/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <stdio.h>
#include <sys/types.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <stropts.h>
#include <ctype.h>
#include <errno.h>
#include <stdlib.h>
#include <door.h>
#include <sys/mman.h>
#include <libscf.h>
#include <libscf_priv.h>
#include <libdllink.h>
#include <libdlbridge.h>
#include <libdladm_impl.h>
#include <stp_in.h>
#include <net/bridge.h>
#include <net/trill.h>
#include <sys/socket.h>
#include <sys/dld_ioc.h>

/*
 * Bridge Administration Library.
 *
 * This library is used by administration tools such as dladm(8) to configure
 * bridges, and by the bridge daemon to retrieve configuration information.
 */

#define	BRIDGE_SVC_NAME	"network/bridge"
#define	TRILL_SVC_NAME	"network/routing/trill"

#define	DEFAULT_TIMEOUT	60000000
#define	INIT_WAIT_USECS	50000
#define	MAXPORTS	256

typedef struct scf_state {
	scf_handle_t *ss_handle;
	scf_instance_t *ss_inst;
	scf_service_t *ss_svc;
	scf_snapshot_t *ss_snap;
	scf_propertygroup_t *ss_pg;
	scf_property_t *ss_prop;
} scf_state_t;

static void
shut_down_scf(scf_state_t *sstate)
{
	scf_instance_destroy(sstate->ss_inst);
	(void) scf_handle_unbind(sstate->ss_handle);
	scf_handle_destroy(sstate->ss_handle);
}

static char *
alloc_fmri(const char *service, const char *instance_name)
{
	ssize_t max_fmri;
	char *fmri;

	/* If the limit is unknown, then use an arbitrary value */
	if ((max_fmri = scf_limit(SCF_LIMIT_MAX_FMRI_LENGTH)) == -1)
		max_fmri = 1024;
	if ((fmri = malloc(max_fmri)) != NULL) {
		(void) snprintf(fmri, max_fmri, "svc:/%s:%s", service,
		    instance_name);
	}
	return (fmri);
}

/*
 * Start up SCF and bind the requested instance alone.
 */
static int
bind_instance(const char *service, const char *instance_name,
    scf_state_t *sstate)
{
	char *fmri = NULL;

	(void) memset(sstate, 0, sizeof (*sstate));

	if ((sstate->ss_handle = scf_handle_create(SCF_VERSION)) == NULL)
		return (-1);

	if (scf_handle_bind(sstate->ss_handle) != 0)
		goto failure;
	sstate->ss_inst = scf_instance_create(sstate->ss_handle);
	if (sstate->ss_inst == NULL)
		goto failure;

	fmri = alloc_fmri(service, instance_name);

	if (scf_handle_decode_fmri(sstate->ss_handle, fmri, NULL, NULL,
	    sstate->ss_inst, NULL, NULL,
	    SCF_DECODE_FMRI_REQUIRE_INSTANCE) != 0)
		goto failure;
	free(fmri);
	return (0);

failure:
	free(fmri);
	shut_down_scf(sstate);
	return (-1);
}

/*
 * Start up SCF and an exact FMRI.  This is used for creating new instances and
 * enable/disable actions.
 */
static dladm_status_t
exact_instance(const char *fmri, scf_state_t *sstate)
{
	dladm_status_t status;

	(void) memset(sstate, 0, sizeof (*sstate));

	if ((sstate->ss_handle = scf_handle_create(SCF_VERSION)) == NULL)
		return (DLADM_STATUS_NOMEM);

	status = DLADM_STATUS_FAILED;
	if (scf_handle_bind(sstate->ss_handle) != 0)
		goto failure;
	sstate->ss_svc = scf_service_create(sstate->ss_handle);
	if (sstate->ss_svc == NULL)
		goto failure;
	if (scf_handle_decode_fmri(sstate->ss_handle, fmri, NULL,
	    sstate->ss_svc, NULL, NULL, NULL, SCF_DECODE_FMRI_EXACT) != 0) {
		if (scf_error() == SCF_ERROR_NOT_FOUND)
			status = DLADM_STATUS_OPTMISSING;
		goto failure;
	}
	sstate->ss_inst = scf_instance_create(sstate->ss_handle);
	if (sstate->ss_inst == NULL)
		goto failure;
	return (DLADM_STATUS_OK);

failure:
	shut_down_scf(sstate);
	return (status);
}

static void
drop_composed(scf_state_t *sstate)
{
	scf_property_destroy(sstate->ss_prop);
	scf_pg_destroy(sstate->ss_pg);
	scf_snapshot_destroy(sstate->ss_snap);
}

/*
 * This function sets up a composed view of the configuration information for
 * the specified instance.  When this is done, the get_property() function
 * should be able to return individual parameters.
 */
static int
get_composed_properties(const char *lpg, boolean_t snap, scf_state_t *sstate)
{
	sstate->ss_snap = NULL;
	sstate->ss_pg = NULL;
	sstate->ss_prop = NULL;

	if (snap) {
		sstate->ss_snap = scf_snapshot_create(sstate->ss_handle);
		if (sstate->ss_snap == NULL)
			goto failure;
		if (scf_instance_get_snapshot(sstate->ss_inst, "running",
		    sstate->ss_snap) != 0)
			goto failure;
	}
	if ((sstate->ss_pg = scf_pg_create(sstate->ss_handle)) == NULL)
		goto failure;
	if (scf_instance_get_pg_composed(sstate->ss_inst, sstate->ss_snap, lpg,
	    sstate->ss_pg) != 0)
		goto failure;
	if ((sstate->ss_prop = scf_property_create(sstate->ss_handle)) ==
	    NULL)
		goto failure;
	return (0);

failure:
	drop_composed(sstate);
	return (-1);
}

static int
get_count(const char *lprop, scf_state_t *sstate, uint64_t *answer)
{
	scf_value_t *val;
	int retv;

	if (scf_pg_get_property(sstate->ss_pg, lprop, sstate->ss_prop) != 0)
		return (-1);
	if ((val = scf_value_create(sstate->ss_handle)) == NULL)
		return (-1);

	if (scf_property_get_value(sstate->ss_prop, val) == 0 &&
	    scf_value_get_count(val, answer) == 0)
		retv = 0;
	else
		retv = -1;
	scf_value_destroy(val);
	return (retv);
}

static int
get_boolean(const char *lprop, scf_state_t *sstate, boolean_t *answer)
{
	scf_value_t *val;
	int retv;
	uint8_t bval;

	if (scf_pg_get_property(sstate->ss_pg, lprop, sstate->ss_prop) != 0)
		return (-1);
	if ((val = scf_value_create(sstate->ss_handle)) == NULL)
		return (-1);

	if (scf_property_get_value(sstate->ss_prop, val) == 0 &&
	    scf_value_get_boolean(val, &bval) == 0) {
		retv = 0;
		*answer = bval != 0;
	} else {
		retv = -1;
	}
	scf_value_destroy(val);
	return (retv);
}

static dladm_status_t
bridge_door_call(const char *instname, bridge_door_type_t dtype,
    datalink_id_t linkid, void **bufp, size_t inlen, size_t *buflenp,
    boolean_t is_list)
{
	char doorname[MAXPATHLEN];
	int did, retv, etmp;
	bridge_door_cmd_t *bdc;
	door_arg_t arg;

	(void) snprintf(doorname, sizeof (doorname), "%s/%s", DOOR_DIRNAME,
	    instname);

	/* Knock on the door */
	did = open(doorname, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
	if (did == -1)
		return (dladm_errno2status(errno));

	if ((bdc = malloc(sizeof (*bdc) + inlen)) == NULL) {
		(void) close(did);
		return (DLADM_STATUS_NOMEM);
	}
	bdc->bdc_type = dtype;
	bdc->bdc_linkid = linkid;
	if (inlen != 0)
		(void) memcpy(bdc + 1, *bufp, inlen);

	(void) memset(&arg, 0, sizeof (arg));
	arg.data_ptr = (char *)bdc;
	arg.data_size = sizeof (*bdc) + inlen;
	arg.rbuf = *bufp;
	arg.rsize = *buflenp;

	/* The door_call function doesn't restart, so take care of that */
	do {
		errno = 0;
		if ((retv = door_call(did, &arg)) == 0)
			break;
	} while (errno == EINTR);

	/* If we get an unexpected response, then return an error */
	if (retv == 0) {
		/* The daemon returns a single int for errors */
		/* LINTED: pointer alignment */
		if (arg.data_size == sizeof (int) && *(int *)arg.rbuf != 0) {
			retv = -1;
			/* LINTED: pointer alignment */
			errno = *(int *)arg.rbuf;
		}
		/* Terminated daemon returns with zero data */
		if (arg.data_size == 0) {
			retv = -1;
			errno = EBADF;
		}
	}

	if (retv == 0) {
		if (arg.rbuf != *bufp) {
			if (is_list) {
				void *newp;

				newp = realloc(*bufp, arg.data_size);
				if (newp == NULL) {
					retv = -1;
				} else {
					*bufp = newp;
					(void) memcpy(*bufp, arg.rbuf,
					    arg.data_size);
				}
			}
			(void) munmap(arg.rbuf, arg.rsize);
		}
		if (is_list) {
			*buflenp = arg.data_size;
		} else if (arg.data_size != *buflenp || arg.rbuf != *bufp) {
			errno = EINVAL;
			retv = -1;
		}
	}

	etmp = errno;
	(void) close(did);

	/* Revoked door is the same as no door at all */
	if (etmp == EBADF)
		etmp = ENOENT;

	return (retv == 0 ? DLADM_STATUS_OK : dladm_errno2status(etmp));
}

/*
 * Wrapper function for making per-port calls.
 */
static dladm_status_t
port_door_call(dladm_handle_t handle, datalink_id_t linkid,
    bridge_door_type_t dtype, void *buf, size_t inlen, size_t buflen)
{
	char bridge[MAXLINKNAMELEN];
	dladm_status_t status;

	status = dladm_bridge_getlink(handle, linkid, bridge, sizeof (bridge));
	if (status != DLADM_STATUS_OK)
		return (status);
	return (bridge_door_call(bridge, dtype, linkid, &buf, inlen, &buflen,
	    B_FALSE));
}

static dladm_status_t
bridge_refresh(const char *bridge)
{
	dladm_status_t status;
	int twoints[2];
	void *bdptr;
	size_t buflen;
	char *fmri;
	int refresh_count;

	buflen = sizeof (twoints);
	bdptr = twoints;
	status = bridge_door_call(bridge, bdcBridgeGetRefreshCount,
	    DATALINK_INVALID_LINKID, &bdptr, 0, &buflen, B_FALSE);
	if (status == DLADM_STATUS_NOTFOUND)
		return (DLADM_STATUS_OK);
	if (status != DLADM_STATUS_OK)
		return (status);
	refresh_count = twoints[0];
	if ((fmri = alloc_fmri(BRIDGE_SVC_NAME, bridge)) == NULL)
		return (DLADM_STATUS_NOMEM);
	status = smf_refresh_instance(fmri) == 0 ?
	    DLADM_STATUS_OK : DLADM_STATUS_FAILED;
	free(fmri);
	if (status == DLADM_STATUS_OK) {
		int i = 0;

		/*
		 * SMF doesn't give any synchronous behavior or dependency
		 * ordering for refresh operations, so we have to invent our
		 * own mechanism here.  Get the refresh counter from the
		 * daemon, and wait for it to change.  It's not pretty, but
		 * it's sufficient.
		 */
		while (++i <= 10) {
			buflen = sizeof (twoints);
			bdptr = twoints;
			status = bridge_door_call(bridge,
			    bdcBridgeGetRefreshCount, DATALINK_INVALID_LINKID,
			    &bdptr, 0, &buflen, B_FALSE);
			if (status != DLADM_STATUS_OK)
				break;
			if (twoints[0] != refresh_count)
				break;
			(void) usleep(100000);
		}
		fmri = alloc_fmri(TRILL_SVC_NAME, bridge);
		if (fmri == NULL)
			return (DLADM_STATUS_NOMEM);
		status = smf_refresh_instance(fmri) == 0 ||
		    scf_error() == SCF_ERROR_NOT_FOUND ?
		    DLADM_STATUS_OK : DLADM_STATUS_FAILED;
		free(fmri);
	}
	return (status);
}

/*
 * Look up bridge property values from SCF and return them.
 */
dladm_status_t
dladm_bridge_get_properties(const char *instance_name, UID_STP_CFG_T *cfg,
    dladm_bridge_prot_t *brprotp)
{
	scf_state_t sstate;
	uint64_t value;
	boolean_t trill_enabled;

	cfg->field_mask = 0;
	cfg->bridge_priority = DEF_BR_PRIO;
	cfg->max_age = DEF_BR_MAXAGE;
	cfg->hello_time = DEF_BR_HELLOT;
	cfg->forward_delay = DEF_BR_FWDELAY;
	cfg->force_version = DEF_FORCE_VERS;

	(void) strlcpy(cfg->vlan_name, instance_name, sizeof (cfg->vlan_name));

	*brprotp = DLADM_BRIDGE_PROT_STP;

	/* It's ok for this to be missing; it's installed separately */
	if (bind_instance(TRILL_SVC_NAME, instance_name, &sstate) == 0) {
		trill_enabled = B_FALSE;
		if (get_composed_properties(SCF_PG_GENERAL, B_FALSE, &sstate) ==
		    0) {
			(void) get_boolean(SCF_PROPERTY_ENABLED, &sstate,
			    &trill_enabled);
			if (trill_enabled)
				*brprotp = DLADM_BRIDGE_PROT_TRILL;
			drop_composed(&sstate);
		}
		if (get_composed_properties(SCF_PG_GENERAL_OVR, B_FALSE,
		    &sstate) == 0) {
			(void) get_boolean(SCF_PROPERTY_ENABLED, &sstate,
			    &trill_enabled);
			if (trill_enabled)
				*brprotp = DLADM_BRIDGE_PROT_TRILL;
			drop_composed(&sstate);
		}
		shut_down_scf(&sstate);
	}

	cfg->stp_enabled = (*brprotp == DLADM_BRIDGE_PROT_STP) ?
	    STP_ENABLED : STP_DISABLED;
	cfg->field_mask |= BR_CFG_STATE;

	if (bind_instance(BRIDGE_SVC_NAME, instance_name, &sstate) != 0)
		return (DLADM_STATUS_REPOSITORYINVAL);

	if (get_composed_properties("config", B_TRUE, &sstate) != 0) {
		shut_down_scf(&sstate);
		return (DLADM_STATUS_REPOSITORYINVAL);
	}

	if (get_count("priority", &sstate, &value) == 0) {
		cfg->bridge_priority = value;
		cfg->field_mask |= BR_CFG_PRIO;
	}
	if (get_count("max-age", &sstate, &value) == 0) {
		cfg->max_age = value / IEEE_TIMER_SCALE;
		cfg->field_mask |= BR_CFG_AGE;
	}
	if (get_count("hello-time", &sstate, &value) == 0) {
		cfg->hello_time = value / IEEE_TIMER_SCALE;
		cfg->field_mask |= BR_CFG_HELLO;
	}
	if (get_count("forward-delay", &sstate, &value) == 0) {
		cfg->forward_delay = value / IEEE_TIMER_SCALE;
		cfg->field_mask |= BR_CFG_DELAY;
	}
	if (get_count("force-protocol", &sstate, &value) == 0) {
		cfg->force_version = value;
		cfg->field_mask |= BR_CFG_FORCE_VER;
	}

	drop_composed(&sstate);
	shut_down_scf(&sstate);
	return (DLADM_STATUS_OK);
}

/*
 * Retrieve special non-settable and undocumented parameters.
 */
dladm_status_t
dladm_bridge_get_privprop(const char *instance_name, boolean_t *debugp,
    uint32_t *tablemaxp)
{
	scf_state_t sstate;
	uint64_t value;

	*debugp = B_FALSE;
	*tablemaxp = 10000;

	if (bind_instance(BRIDGE_SVC_NAME, instance_name, &sstate) != 0)
		return (DLADM_STATUS_REPOSITORYINVAL);

	if (get_composed_properties("config", B_TRUE, &sstate) != 0) {
		shut_down_scf(&sstate);
		return (DLADM_STATUS_REPOSITORYINVAL);
	}

	(void) get_boolean("debug", &sstate, debugp);
	if (get_count("table-maximum", &sstate, &value) == 0)
		*tablemaxp = (uint32_t)value;

	drop_composed(&sstate);
	shut_down_scf(&sstate);
	return (DLADM_STATUS_OK);
}

static boolean_t
set_count_property(scf_handle_t *handle, scf_transaction_t *tran,
    const char *propname, uint64_t propval)
{
	scf_transaction_entry_t *entry;
	scf_value_t *value = NULL;

	if ((entry = scf_entry_create(handle)) == NULL)
		return (B_FALSE);

	if ((value = scf_value_create(handle)) == NULL)
		goto out;
	if (scf_transaction_property_new(tran, entry, propname,
	    SCF_TYPE_COUNT) != 0 &&
	    scf_transaction_property_change(tran, entry, propname,
	    SCF_TYPE_COUNT) != 0)
		goto out;
	scf_value_set_count(value, propval);
	if (scf_entry_add_value(entry, value) == 0)
		return (B_TRUE);

out:
	if (value != NULL)
		scf_value_destroy(value);

	scf_entry_destroy_children(entry);
	scf_entry_destroy(entry);

	return (B_FALSE);
}

static boolean_t
set_string_property(scf_handle_t *handle, scf_transaction_t *tran,
    const char *propname, const char *propval)
{
	scf_transaction_entry_t *entry;
	scf_value_t *value = NULL;

	if ((entry = scf_entry_create(handle)) == NULL)
		return (B_FALSE);

	if ((value = scf_value_create(handle)) == NULL)
		goto out;
	if (scf_transaction_property_new(tran, entry, propname,
	    SCF_TYPE_ASTRING) != 0 &&
	    scf_transaction_property_change(tran, entry, propname,
	    SCF_TYPE_ASTRING) != 0)
		goto out;
	if (scf_value_set_astring(value, propval) != 0)
		goto out;
	if (scf_entry_add_value(entry, value) == 0)
		return (B_TRUE);

out:
	if (value != NULL)
		scf_value_destroy(value);

	scf_entry_destroy_children(entry);
	scf_entry_destroy(entry);

	return (B_FALSE);
}

static boolean_t
set_fmri_property(scf_handle_t *handle, scf_transaction_t *tran,
    const char *propname, const char *propval)
{
	scf_transaction_entry_t *entry;
	scf_value_t *value = NULL;

	if ((entry = scf_entry_create(handle)) == NULL)
		return (B_FALSE);

	if ((value = scf_value_create(handle)) == NULL)
		goto out;
	if (scf_transaction_property_new(tran, entry, propname,
	    SCF_TYPE_FMRI) != 0 &&
	    scf_transaction_property_change(tran, entry, propname,
	    SCF_TYPE_FMRI) != 0)
		goto out;
	if (scf_value_set_from_string(value, SCF_TYPE_FMRI, propval) != 0)
		goto out;
	if (scf_entry_add_value(entry, value) == 0)
		return (B_TRUE);

out:
	if (value != NULL)
		scf_value_destroy(value);

	scf_entry_destroy_children(entry);
	scf_entry_destroy(entry);

	return (B_FALSE);
}

static dladm_status_t
dladm_bridge_persist_conf(dladm_handle_t handle, const char *link,
    datalink_id_t linkid)
{
	dladm_conf_t conf;
	dladm_status_t status;

	status = dladm_create_conf(handle, link, linkid, DATALINK_CLASS_BRIDGE,
	    DL_ETHER, &conf);
	if (status == DLADM_STATUS_OK) {
		/*
		 * Create the datalink entry for the bridge.  Note that all of
		 * the real configuration information is in SMF.
		 */
		status = dladm_write_conf(handle, conf);
		dladm_destroy_conf(handle, conf);
	}
	return (status);
}

/* Convert bridge protection option string to dladm_bridge_prot_t */
dladm_status_t
dladm_bridge_str2prot(const char *str, dladm_bridge_prot_t *brprotp)
{
	if (strcmp(str, "stp") == 0)
		*brprotp = DLADM_BRIDGE_PROT_STP;
	else if (strcmp(str, "trill") == 0)
		*brprotp = DLADM_BRIDGE_PROT_TRILL;
	else
		return (DLADM_STATUS_BADARG);
	return (DLADM_STATUS_OK);
}

/* Convert bridge protection option from dladm_bridge_prot_t to string */
const char *
dladm_bridge_prot2str(dladm_bridge_prot_t brprot)
{
	switch (brprot) {
	case DLADM_BRIDGE_PROT_STP:
		return ("stp");
	case DLADM_BRIDGE_PROT_TRILL:
		return ("trill");
	default:
		return ("unknown");
	}
}

static dladm_status_t
enable_instance(const char *service_name, const char *instance)
{
	dladm_status_t status;
	char *fmri = alloc_fmri(service_name, instance);

	if (fmri == NULL)
		return (DLADM_STATUS_NOMEM);
	status = smf_enable_instance(fmri, 0) == 0 ?
	    DLADM_STATUS_OK : DLADM_STATUS_FAILED;
	free(fmri);
	return (status);
}

/*
 * Shut down a possibly-running service instance.  If this is a permanent
 * change, then delete it from the system.
 */
static dladm_status_t
shut_down_instance(const char *service_name, const char *instance,
    uint32_t flags)
{
	dladm_status_t status;
	char *fmri = alloc_fmri(service_name, instance);
	char *state;
	scf_state_t sstate;

	if (fmri == NULL)
		return (DLADM_STATUS_NOMEM);

	if (smf_disable_instance(fmri,
	    flags & DLADM_OPT_PERSIST ? 0 : SMF_TEMPORARY) == 0) {
		useconds_t usecs, umax;

		/* If we can disable, then wait for it to happen. */
		umax = DEFAULT_TIMEOUT;
		for (usecs = INIT_WAIT_USECS; umax != 0; umax -= usecs) {
			state = smf_get_state(fmri);
			if (state != NULL &&
			    strcmp(state, SCF_STATE_STRING_DISABLED) == 0)
				break;
			free(state);
			usecs *= 2;
			if (usecs > umax)
				usecs = umax;
			(void) usleep(usecs);
		}
		if (umax == 0) {
			state = smf_get_state(fmri);
			if (state != NULL &&
			    strcmp(state, SCF_STATE_STRING_DISABLED) == 0)
				umax = 1;
		}
		free(state);
		status = umax != 0 ? DLADM_STATUS_OK : DLADM_STATUS_FAILED;
	} else if (scf_error() == SCF_ERROR_NOT_FOUND) {
		free(fmri);
		return (DLADM_STATUS_OK);
	} else {
		status = DLADM_STATUS_FAILED;
	}

	free(fmri);
	if (status == DLADM_STATUS_OK && (flags & DLADM_OPT_PERSIST) &&
	    bind_instance(service_name, instance, &sstate) == 0) {
		(void) scf_instance_delete(sstate.ss_inst);
		shut_down_scf(&sstate);
	}

	return (status);
}

static dladm_status_t
disable_trill(const char *instance, uint32_t flags)
{
	return (shut_down_instance(TRILL_SVC_NAME, instance, flags));
}

/*
 * To enable TRILL, we must create a new instance of the TRILL service, then
 * add proper dependencies to it, and finally mark it as enabled.  The
 * dependencies will keep it from going on-line until the bridge is running.
 */
static dladm_status_t
enable_trill(const char *instance)
{
	dladm_status_t status = DLADM_STATUS_FAILED;
	char *fmri = NULL;
	scf_state_t sstate;
	scf_transaction_t *tran = NULL;
	boolean_t new_instance = B_FALSE;
	boolean_t new_pg = B_FALSE;
	int rv;

	/*
	 * This check is here in case the user has installed and then removed
	 * the package.  SMF should remove the manifest, but currently does
	 * not.
	 */
	if (access("/usr/sbin/trilld", F_OK) != 0)
		return (DLADM_STATUS_OPTMISSING);

	if ((status = exact_instance(TRILL_SVC_NAME, &sstate)) !=
	    DLADM_STATUS_OK)
		goto out;

	status = DLADM_STATUS_FAILED;
	if (scf_service_get_instance(sstate.ss_svc, instance, sstate.ss_inst) !=
	    0) {
		if (scf_service_add_instance(sstate.ss_svc, instance,
		    sstate.ss_inst) != 0)
			goto out;
		new_instance = B_TRUE;
	}

	if ((tran = scf_transaction_create(sstate.ss_handle)) == NULL)
		goto out;

	if ((sstate.ss_pg = scf_pg_create(sstate.ss_handle)) == NULL)
		goto out;

	if (scf_instance_get_pg(sstate.ss_inst, "bridging",
	    sstate.ss_pg) == 0) {
		status = DLADM_STATUS_OK;
		goto out;
	}

	if ((fmri = alloc_fmri(BRIDGE_SVC_NAME, instance)) == NULL)
		goto out;

	if (scf_instance_add_pg(sstate.ss_inst, "bridging",
	    SCF_GROUP_DEPENDENCY, 0, sstate.ss_pg) != 0)
		goto out;

	new_pg = B_TRUE;
	do {
		if (scf_transaction_start(tran, sstate.ss_pg) != 0)
			goto out;

		if (!set_string_property(sstate.ss_handle, tran,
		    SCF_PROPERTY_GROUPING, SCF_DEP_REQUIRE_ALL))
			goto out;
		if (!set_string_property(sstate.ss_handle, tran,
		    SCF_PROPERTY_RESTART_ON, SCF_DEP_RESET_ON_RESTART))
			goto out;
		if (!set_string_property(sstate.ss_handle, tran,
		    SCF_PROPERTY_TYPE, "service"))
			goto out;
		if (!set_fmri_property(sstate.ss_handle, tran,
		    SCF_PROPERTY_ENTITIES, fmri))
			goto out;

		rv = scf_transaction_commit(tran);
		scf_transaction_reset(tran);
		if (rv == 0 && scf_pg_update(sstate.ss_pg) == -1)
			goto out;
	} while (rv == 0);
	if (rv != 1)
		goto out;

	status = DLADM_STATUS_OK;

out:
	free(fmri);
	if (tran != NULL) {
		scf_transaction_destroy_children(tran);
		scf_transaction_destroy(tran);
	}

	if (status != DLADM_STATUS_OK && new_pg)
		(void) scf_pg_delete(sstate.ss_pg);

	drop_composed(&sstate);

	/*
	 * If we created an instance and then failed, then remove the instance
	 * from the system.
	 */
	if (status != DLADM_STATUS_OK && new_instance)
		(void) scf_instance_delete(sstate.ss_inst);

	shut_down_scf(&sstate);

	if (status == DLADM_STATUS_OK)
		status = enable_instance(TRILL_SVC_NAME, instance);

	return (status);
}

/*
 * Create a new bridge or modify an existing one.  Update the SMF configuration
 * and add links.
 *
 * Input timer values are in IEEE scaled (* 256) format.
 */
dladm_status_t
dladm_bridge_configure(dladm_handle_t handle, const char *name,
    const UID_STP_CFG_T *cfg, dladm_bridge_prot_t brprot, uint32_t flags)
{
	dladm_status_t status;
	scf_state_t sstate;
	scf_transaction_t *tran = NULL;
	boolean_t new_instance = B_FALSE;
	boolean_t new_pg = B_FALSE;
	datalink_id_t linkid = DATALINK_INVALID_LINKID;
	char linkname[MAXLINKNAMELEN];
	int rv;

	if (!dladm_valid_bridgename(name))
		return (DLADM_STATUS_FAILED);

	if (flags & DLADM_OPT_CREATE) {
		/*
		 * This check is here in case the user has installed and then
		 * removed the package.  SMF should remove the manifest, but
		 * currently does not.
		 */
		if (access("/usr/lib/bridged", F_OK) != 0)
			return (DLADM_STATUS_OPTMISSING);

		(void) snprintf(linkname, sizeof (linkname), "%s0", name);
		status = dladm_create_datalink_id(handle, linkname,
		    DATALINK_CLASS_BRIDGE, DL_ETHER,
		    flags & (DLADM_OPT_ACTIVE | DLADM_OPT_PERSIST), &linkid);
		if (status != DLADM_STATUS_OK)
			return (status);

		if ((flags & DLADM_OPT_PERSIST) &&
		    (status = dladm_bridge_persist_conf(handle, linkname,
		    linkid) != DLADM_STATUS_OK))
			goto dladm_fail;
	}

	if (brprot == DLADM_BRIDGE_PROT_TRILL)
		status = enable_trill(name);
	else
		status = disable_trill(name, flags);
	if (status != DLADM_STATUS_OK)
		goto dladm_fail;

	if ((status = exact_instance(BRIDGE_SVC_NAME, &sstate)) !=
	    DLADM_STATUS_OK)
		goto out;

	/* set up for a series of scf calls */
	status = DLADM_STATUS_FAILED;

	if (scf_service_get_instance(sstate.ss_svc, name, sstate.ss_inst) ==
	    0) {
		if (flags & DLADM_OPT_CREATE) {
			status = DLADM_STATUS_EXIST;
			goto out;
		}
	} else {
		if (!(flags & DLADM_OPT_CREATE)) {
			status = DLADM_STATUS_NOTFOUND;
			goto out;
		}
		if (scf_service_add_instance(sstate.ss_svc, name,
		    sstate.ss_inst) != 0)
			goto out;
		new_instance = B_TRUE;
	}

	if ((tran = scf_transaction_create(sstate.ss_handle)) == NULL)
		goto out;

	if (cfg->field_mask & BR_CFG_ALL) {
		if ((sstate.ss_pg = scf_pg_create(sstate.ss_handle)) == NULL)
			goto out;
		if (scf_instance_add_pg(sstate.ss_inst, "config",
		    SCF_GROUP_APPLICATION, 0, sstate.ss_pg) == 0) {
			new_pg = B_TRUE;
		} else if (scf_instance_get_pg(sstate.ss_inst, "config",
		    sstate.ss_pg) != 0) {
			goto out;
		}
		do {
			if (scf_transaction_start(tran, sstate.ss_pg) != 0)
				goto out;

			if ((cfg->field_mask & BR_CFG_PRIO) &&
			    !set_count_property(sstate.ss_handle, tran,
			    "priority", cfg->bridge_priority))
				goto out;
			if ((cfg->field_mask & BR_CFG_AGE) &&
			    !set_count_property(sstate.ss_handle, tran,
			    "max-age", cfg->max_age * IEEE_TIMER_SCALE))
				goto out;
			if ((cfg->field_mask & BR_CFG_HELLO) &&
			    !set_count_property(sstate.ss_handle, tran,
			    "hello-time", cfg->hello_time * IEEE_TIMER_SCALE))
				goto out;
			if ((cfg->field_mask & BR_CFG_DELAY) &&
			    !set_count_property(sstate.ss_handle, tran,
			    "forward-delay",
			    cfg->forward_delay * IEEE_TIMER_SCALE))
				goto out;
			if ((cfg->field_mask & BR_CFG_FORCE_VER) &&
			    !set_count_property(sstate.ss_handle, tran,
			    "force-protocol", cfg->force_version))
				goto out;

			rv = scf_transaction_commit(tran);
			scf_transaction_reset(tran);
			if (rv == 0 && scf_pg_update(sstate.ss_pg) == -1)
				goto out;
		} while (rv == 0);
		if (rv != 1)
			goto out;
	}

	/*
	 * If we're modifying an existing and running bridge, then tell the
	 * daemon to update the requested values.
	 */
	if ((flags & DLADM_OPT_ACTIVE) && !(flags & DLADM_OPT_CREATE))
		status = bridge_refresh(name);
	else
		status = DLADM_STATUS_OK;

out:
	if (tran != NULL) {
		scf_transaction_destroy_children(tran);
		scf_transaction_destroy(tran);
	}

	if (status != DLADM_STATUS_OK && new_pg)
		(void) scf_pg_delete(sstate.ss_pg);

	drop_composed(&sstate);

	/*
	 * If we created an instance and then failed, then remove the instance
	 * from the system.
	 */
	if (status != DLADM_STATUS_OK && new_instance)
		(void) scf_instance_delete(sstate.ss_inst);

	shut_down_scf(&sstate);

	/*
	 * Remove the bridge linkid if we've allocated one in this function but
	 * we've failed to set up the SMF properties.
	 */
dladm_fail:
	if (status != DLADM_STATUS_OK && linkid != DATALINK_INVALID_LINKID) {
		(void) dladm_remove_conf(handle, linkid);
		(void) dladm_destroy_datalink_id(handle, linkid, flags);
	}

	return (status);
}

/*
 * Enable a newly-created bridge in SMF by creating "general/enabled" and
 * deleting any "general_ovr/enabled" (used for temporary services).
 */
dladm_status_t
dladm_bridge_enable(const char *name)
{
	return (enable_instance(BRIDGE_SVC_NAME, name));
}

/*
 * Set a link as a member of a bridge, or remove bridge membership.  If the
 * DLADM_OPT_CREATE flag is set, then we assume that the daemon isn't running.
 * In all other cases, we must tell the daemon to add or delete the link in
 * order to stay in sync.
 */
dladm_status_t
dladm_bridge_setlink(dladm_handle_t handle, datalink_id_t linkid,
    const char *bridge)
{
	dladm_status_t status;
	dladm_conf_t conf;
	char oldbridge[MAXLINKNAMELEN];
	boolean_t has_oldbridge;
	boolean_t changed = B_FALSE;

	if (*bridge != '\0' && !dladm_valid_bridgename(bridge))
		return (DLADM_STATUS_FAILED);

	status = dladm_open_conf(handle, linkid, &conf);
	if (status != DLADM_STATUS_OK)
		return (status);

	has_oldbridge = B_FALSE;
	status = dladm_get_conf_field(handle, conf, FBRIDGE, oldbridge,
	    sizeof (oldbridge));
	if (status == DLADM_STATUS_OK) {
		/*
		 * Don't allow a link to be reassigned directly from one bridge
		 * to another.  It must be removed first.
		 */
		if (*oldbridge != '\0' && *bridge != '\0') {
			status = DLADM_STATUS_EXIST;
			goto out;
		}
		has_oldbridge = B_TRUE;
	} else if (status != DLADM_STATUS_NOTFOUND) {
		goto out;
	}

	if (*bridge != '\0') {
		status = dladm_set_conf_field(handle, conf, FBRIDGE,
		    DLADM_TYPE_STR, bridge);
		changed = B_TRUE;
	} else if (has_oldbridge) {
		status = dladm_unset_conf_field(handle, conf, FBRIDGE);
		changed = B_TRUE;
	} else {
		status = DLADM_STATUS_OK;
		goto out;
	}
	if (status == DLADM_STATUS_OK)
		status = dladm_write_conf(handle, conf);

out:
	dladm_destroy_conf(handle, conf);
	if (changed && status == DLADM_STATUS_OK) {
		if (bridge[0] == '\0')
			bridge = oldbridge;
		status = bridge_refresh(bridge);
	}
	return (status);
}

/*
 * Get the name of the bridge of which the given linkid is a member.
 */
dladm_status_t
dladm_bridge_getlink(dladm_handle_t handle, datalink_id_t linkid, char *bridge,
    size_t bridgelen)
{
	dladm_status_t status;
	dladm_conf_t conf;

	if ((status = dladm_getsnap_conf(handle, linkid, &conf)) !=
	    DLADM_STATUS_OK)
		return (status);

	*bridge = '\0';
	status = dladm_get_conf_field(handle, conf, FBRIDGE, bridge, bridgelen);
	if (status == DLADM_STATUS_OK && *bridge == '\0')
		status = DLADM_STATUS_NOTFOUND;

	dladm_destroy_conf(handle, conf);
	return (status);
}

dladm_status_t
dladm_bridge_refresh(dladm_handle_t handle, datalink_id_t linkid)
{
	char bridge[MAXLINKNAMELEN];
	dladm_status_t status;

	status = dladm_bridge_getlink(handle, linkid, bridge, sizeof (bridge));
	if (status == DLADM_STATUS_NOTFOUND)
		return (DLADM_STATUS_OK);
	if (status == DLADM_STATUS_OK)
		status = bridge_refresh(bridge);
	return (status);
}

typedef struct bridge_held_arg_s {
	const char	*bha_bridge;
	boolean_t	bha_isheld;
} bridge_held_arg_t;

static int
i_dladm_bridge_is_held(dladm_handle_t handle, datalink_id_t linkid, void *arg)
{
	dladm_status_t status = DLADM_STATUS_FAILED;
	dladm_conf_t conf;
	char bridge[MAXLINKNAMELEN];
	bridge_held_arg_t *bha = arg;

	if ((status = dladm_getsnap_conf(handle, linkid, &conf)) !=
	    DLADM_STATUS_OK)
		return (DLADM_WALK_CONTINUE);
	status = dladm_get_conf_field(handle, conf, FBRIDGE, bridge,
	    sizeof (bridge));
	if (status == DLADM_STATUS_OK && strcmp(bha->bha_bridge, bridge) == 0) {
		bha->bha_isheld = B_TRUE;
		dladm_destroy_conf(handle, conf);
		return (DLADM_WALK_TERMINATE);
	} else {
		dladm_destroy_conf(handle, conf);
		return (DLADM_WALK_CONTINUE);
	}
}

/*
 * Delete a previously created bridge.
 */
dladm_status_t
dladm_bridge_delete(dladm_handle_t handle, const char *bridge, uint32_t flags)
{
	datalink_id_t linkid;
	datalink_class_t class;
	dladm_status_t status;
	char linkname[MAXLINKNAMELEN];

	if (!dladm_valid_bridgename(bridge))
		return (DLADM_STATUS_LINKINVAL);

	/* Get the datalink ID for this bridge */
	(void) snprintf(linkname, sizeof (linkname), "%s0", bridge);
	if (dladm_name2info(handle, linkname, &linkid, NULL, NULL, NULL) !=
	    DLADM_STATUS_OK)
		linkid = DATALINK_INVALID_LINKID;
	else if (dladm_datalink_id2info(handle, linkid, NULL, &class, NULL,
	    NULL, 0) != DLADM_STATUS_OK)
		linkid = DATALINK_INVALID_LINKID;
	else if (class != DATALINK_CLASS_BRIDGE)
		return (DLADM_STATUS_BADARG);

	if ((flags & DLADM_OPT_ACTIVE) && linkid == DATALINK_INVALID_LINKID)
		return (DLADM_STATUS_BADARG);

	if (flags & DLADM_OPT_PERSIST) {
		bridge_held_arg_t arg;

		arg.bha_bridge = bridge;
		arg.bha_isheld = B_FALSE;

		/*
		 * See whether there are any persistent links using this
		 * bridge.  If so, we fail the operation.
		 */
		(void) dladm_walk_datalink_id(i_dladm_bridge_is_held, handle,
		    &arg, DATALINK_CLASS_PHYS | DATALINK_CLASS_AGGR |
		    DATALINK_CLASS_ETHERSTUB | DATALINK_CLASS_SIMNET,
		    DATALINK_ANY_MEDIATYPE, DLADM_OPT_PERSIST);
		if (arg.bha_isheld)
			return (DLADM_STATUS_LINKBUSY);
	}

	if ((status = disable_trill(bridge, flags)) != DLADM_STATUS_OK)
		goto out;

	/* Disable or remove the SMF instance */
	status = shut_down_instance(BRIDGE_SVC_NAME, bridge, flags);
	if (status != DLADM_STATUS_OK)
		goto out;

	if (flags & DLADM_OPT_ACTIVE) {
		/*
		 * Delete ACTIVE linkprop now that daemon is gone.
		 */
		(void) dladm_set_linkprop(handle, linkid, NULL, NULL, 0,
		    DLADM_OPT_ACTIVE);
		(void) dladm_destroy_datalink_id(handle, linkid,
		    DLADM_OPT_ACTIVE);
	}

	if (flags & DLADM_OPT_PERSIST) {
		(void) dladm_remove_conf(handle, linkid);
		(void) dladm_destroy_datalink_id(handle, linkid,
		    DLADM_OPT_PERSIST);
	}

out:

	return (status);
}

/* Check if given name is valid for bridges */
boolean_t
dladm_valid_bridgename(const char *bridge)
{
	size_t		len = strnlen(bridge, MAXLINKNAMELEN);
	const char	*cp;

	if (len == MAXLINKNAMELEN)
		return (B_FALSE);

	/*
	 * The bridge name cannot start or end with a digit.
	 */
	if (isdigit(bridge[0]) || isdigit(bridge[len - 1]))
		return (B_FALSE);

	/*
	 * The legal characters within a bridge name are:
	 * alphanumeric (a-z,  A-Z,  0-9), and the underscore ('_').
	 */
	for (cp = bridge; *cp != '\0'; cp++) {
		if (!isalnum(*cp) && *cp != '_')
			return (B_FALSE);
	}

	return (B_TRUE);
}

/*
 * Convert a bridge-related observability node name back into the name of the
 * bridge.  Returns B_FALSE without making changes if the input name is not in
 * a legal format.
 */
boolean_t
dladm_observe_to_bridge(char *link)
{
	int llen;

	llen = strnlen(link, MAXLINKNAMELEN);
	if (llen < 2 || link[llen - 1] != '0' || isdigit(link[llen - 2]))
		return (B_FALSE);
	link[llen - 1] = '\0';
	return (B_TRUE);
}

/*
 * Get bridge property values from the running daemon and return them in a
 * common structure.
 */
dladm_status_t
dladm_bridge_run_properties(const char *instname, UID_STP_CFG_T *smcfg,
    dladm_bridge_prot_t *brprotp)
{
	dladm_status_t status;
	bridge_door_cfg_t bdcf;
	bridge_door_cfg_t *bdcfp = &bdcf;
	size_t buflen = sizeof (bdcf);

	status = bridge_door_call(instname, bdcBridgeGetConfig,
	    DATALINK_INVALID_LINKID, (void **)&bdcfp, 0, &buflen, B_FALSE);
	if (status == DLADM_STATUS_OK) {
		*smcfg = bdcfp->bdcf_cfg;
		*brprotp = bdcfp->bdcf_prot;
	} else {
		smcfg->field_mask = 0;
		*brprotp = DLADM_BRIDGE_PROT_STP;
	}
	return (status);
}

/*
 * Get bridge state from the running daemon and return in structure borrowed
 * from librstp.
 */
dladm_status_t
dladm_bridge_state(const char *instname, UID_STP_STATE_T *statep)
{
	size_t buflen = sizeof (*statep);

	return (bridge_door_call(instname, bdcBridgeGetState,
	    DATALINK_INVALID_LINKID, (void **)&statep, 0, &buflen, B_FALSE));
}

/* Returns list of ports (datalink_id_t values) assigned to a bridge instance */
datalink_id_t *
dladm_bridge_get_portlist(const char *instname, uint_t *nports)
{
	size_t buflen = sizeof (int) + MAXPORTS * sizeof (datalink_id_t);
	int *rbuf;

	if ((rbuf = malloc(buflen)) == NULL)
		return (NULL);
	if (bridge_door_call(instname, bdcBridgeGetPorts,
	    DATALINK_INVALID_LINKID, (void **)&rbuf, 0, &buflen, B_TRUE) !=
	    DLADM_STATUS_OK) {
		free(rbuf);
		return (NULL);
	} else {
		/*
		 * Returns an array of datalink_id_t values for all the ports
		 * part of the bridge instance. First entry in the array is the
		 * number of ports.
		 */
		*nports = *rbuf;
		return ((datalink_id_t *)(rbuf + 1));
	}
}

void
dladm_bridge_free_portlist(datalink_id_t *dlp)
{
	free((int *)dlp - 1);
}

/* Retrieve Bridge port configuration values */
dladm_status_t
dladm_bridge_get_port_cfg(dladm_handle_t handle, datalink_id_t linkid,
    int field, int *valuep)
{
	UID_STP_PORT_CFG_T portcfg;
	dladm_status_t status;

	status = port_door_call(handle, linkid, bdcPortGetConfig, &portcfg,
	    0, sizeof (portcfg));
	if (status != DLADM_STATUS_OK)
		return (status);

	switch (field) {
	case PT_CFG_COST:
		*valuep = portcfg.admin_port_path_cost;
		break;
	case PT_CFG_PRIO:
		*valuep = portcfg.port_priority;
		break;
	case PT_CFG_P2P:
		*valuep = portcfg.admin_point2point;
		break;
	case PT_CFG_EDGE:
		*valuep = portcfg.admin_edge;
		break;
	case PT_CFG_NON_STP:
		*valuep = !portcfg.admin_non_stp;
		break;
	case PT_CFG_MCHECK:
		*valuep = (portcfg.field_mask & PT_CFG_MCHECK) ? 1 : 0;
		break;
	}
	return (status);
}

/* Retreive Bridge port status (disabled, bad SDU etc.) */
dladm_status_t
dladm_bridge_link_state(dladm_handle_t handle, datalink_id_t linkid,
    UID_STP_PORT_STATE_T *spsp)
{
	return (port_door_call(handle, linkid, bdcPortGetState, spsp, 0,
	    sizeof (*spsp)));
}

/* Retrieve Bridge forwarding status of the given link */
dladm_status_t
dladm_bridge_get_forwarding(dladm_handle_t handle, datalink_id_t linkid,
    uint_t *valuep)
{
	int twoints[2];
	dladm_status_t status;

	status = port_door_call(handle, linkid, bdcPortGetForwarding, twoints,
	    0, sizeof (twoints));
	if (status == DLADM_STATUS_OK)
		*valuep = twoints[0];
	return (status);
}

/* Retrieve Bridge forwarding table entries */
bridge_listfwd_t *
dladm_bridge_get_fwdtable(dladm_handle_t handle, const char *bridge,
    uint_t *nfwd)
{
	bridge_listfwd_t *blf = NULL, *newblf, blfread;
	uint_t nblf = 0, maxblf = 0;
	static uint8_t zero_addr[ETHERADDRL];
	int rc;

	(void) memset(&blfread, 0, sizeof (blfread));
	(void) snprintf(blfread.blf_name, sizeof (blfread.blf_name),
	    "%s0", bridge);
	for (;;) {
		if (nblf >= maxblf) {
			maxblf = maxblf == 0 ? 64 : (maxblf << 1);
			newblf = realloc(blf, maxblf * sizeof (*blf));
			if (newblf == NULL) {
				free(blf);
				blf = NULL;
				break;
			}
			blf = newblf;
		}
		rc = ioctl(dladm_dld_fd(handle), BRIDGE_IOC_LISTFWD, &blfread);
		if (rc != 0) {
			free(blf);
			blf = NULL;
			break;
		}
		if (memcmp(blfread.blf_dest, zero_addr, ETHERADDRL) == 0)
			break;
		blf[nblf++] = blfread;
	}
	if (blf != NULL)
		*nfwd = nblf;
	return (blf);
}

void
dladm_bridge_free_fwdtable(bridge_listfwd_t *blf)
{
	free(blf);
}

/* Retrieve list of TRILL nicknames from the TRILL module */
trill_listnick_t *
dladm_bridge_get_trillnick(const char *bridge, uint_t *nnick)
{
	int fd;
	char brcopy[MAXLINKNAMELEN];
	trill_listnick_t *tln = NULL, *newtln, tlnread;
	uint_t ntln = 0, maxtln = 0;

	if ((fd = socket(PF_TRILL, SOCK_DGRAM, 0)) == -1)
		return (NULL);
	(void) strlcpy(brcopy, bridge, sizeof (brcopy));
	if (ioctl(fd, TRILL_GETBRIDGE, &brcopy) < 0) {
		(void) close(fd);
		return (NULL);
	}
	(void) memset(&tlnread, 0, sizeof (tlnread));
	for (;;) {
		if (ntln >= maxtln) {
			maxtln = maxtln == 0 ? 64 : (maxtln << 1);
			newtln = realloc(tln, maxtln * sizeof (*tln));
			if (newtln == NULL) {
				free(tln);
				tln = NULL;
				break;
			}
			tln = newtln;
		}
		if (ioctl(fd, TRILL_LISTNICK, &tlnread) == -1) {
			free(tln);
			tln = NULL;
			break;
		}
		if (tlnread.tln_nick == 0)
			break;
		tln[ntln++] = tlnread;
	}
	(void) close(fd);
	if (tln != NULL)
		*nnick = ntln;
	return (tln);
}

void
dladm_bridge_free_trillnick(trill_listnick_t *tln)
{
	free(tln);
}

/* Retrieve any stored TRILL nickname from TRILL SMF service */
uint16_t
dladm_bridge_get_nick(const char *bridge)
{
	scf_state_t sstate;
	uint64_t value;
	uint16_t nickname = RBRIDGE_NICKNAME_NONE;

	if (bind_instance(TRILL_SVC_NAME, bridge, &sstate) != 0)
		return (nickname);

	if (get_composed_properties("config", B_TRUE, &sstate) == 0 &&
	    get_count("nickname", &sstate, &value) == 0)
		nickname = value;
	shut_down_scf(&sstate);
	return (nickname);
}

/* Stores TRILL nickname in SMF configuraiton for the TRILL service */
void
dladm_bridge_set_nick(const char *bridge, uint16_t nick)
{
	scf_state_t sstate;
	scf_transaction_t *tran = NULL;
	boolean_t new_pg = B_FALSE;
	int rv = 0;
	char *fmri;

	if (exact_instance(TRILL_SVC_NAME, &sstate) != DLADM_STATUS_OK)
		return;

	if (scf_service_get_instance(sstate.ss_svc, bridge, sstate.ss_inst) !=
	    0)
		goto out;
	if ((tran = scf_transaction_create(sstate.ss_handle)) == NULL)
		goto out;
	if ((sstate.ss_pg = scf_pg_create(sstate.ss_handle)) == NULL)
		goto out;
	if (scf_instance_add_pg(sstate.ss_inst, "config",
	    SCF_GROUP_APPLICATION, 0, sstate.ss_pg) == 0) {
		new_pg = B_TRUE;
	} else if (scf_instance_get_pg(sstate.ss_inst, "config",
	    sstate.ss_pg) != 0) {
		goto out;
	}
	do {
		if (scf_transaction_start(tran, sstate.ss_pg) != 0)
			goto out;
		if (!set_count_property(sstate.ss_handle, tran, "nickname",
		    nick))
			goto out;
		rv = scf_transaction_commit(tran);
		scf_transaction_reset(tran);
		if (rv == 0 && scf_pg_update(sstate.ss_pg) == -1)
			goto out;
	} while (rv == 0);

out:
	if (tran != NULL) {
		scf_transaction_destroy_children(tran);
		scf_transaction_destroy(tran);
	}

	if (rv != 1 && new_pg)
		(void) scf_pg_delete(sstate.ss_pg);

	drop_composed(&sstate);
	shut_down_scf(&sstate);
	if (rv == 1 && (fmri = alloc_fmri(TRILL_SVC_NAME, bridge)) != NULL) {
		(void) smf_refresh_instance(fmri);
		free(fmri);
	}
}
