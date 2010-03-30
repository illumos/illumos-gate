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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * util.c contains a set of miscellaneous utility functions which,
 * among other things:
 * - start a child process
 * - look up the zone name
 * - look up/set SMF properties
 * - drop/escalate privs
 */

#include <assert.h>
#include <errno.h>
#include <inetcfg.h>
#include <libdllink.h>
#include <limits.h>
#include <libscf.h>
#include <net/if.h>
#include <pthread.h>
#include <pwd.h>
#include <spawn.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <stropts.h>
#include <sys/socket.h>
#include <sys/sockio.h>
#include <sys/types.h>
#include <unistd.h>
#include <wait.h>
#include <zone.h>

#include "util.h"
#include "llp.h"

extern char **environ;
extern sigset_t original_sigmask;

/*
 * A holder for all the resources needed to get a property value
 * using libscf.
 */
typedef struct scf_resources {
	scf_handle_t *sr_handle;
	scf_instance_t *sr_inst;
	scf_snapshot_t *sr_snap;
	scf_propertygroup_t *sr_pg;
	scf_property_t *sr_prop;
	scf_value_t *sr_val;
	scf_transaction_t *sr_tx;
	scf_transaction_entry_t *sr_ent;
} scf_resources_t;

static pthread_mutex_t uid_mutex = PTHREAD_MUTEX_INITIALIZER;
static uid_t uid;
static int uid_cnt;

void
nwamd_escalate(void) {
	priv_set_t *priv_set;
	priv_set = priv_str_to_set("zone", ",", NULL);

	if (priv_set == NULL)
		pfail("creating privilege set: %s", strerror(errno));

	(void) pthread_mutex_lock(&uid_mutex);
	if (uid == 0)
		uid = getuid();
	if (uid_cnt++ == 0) {
		if (setppriv(PRIV_SET, PRIV_EFFECTIVE, priv_set) == -1) {
			priv_freeset(priv_set);
			pfail("setppriv effective: %s", strerror(errno));
		}
	}
	(void) pthread_mutex_unlock(&uid_mutex);

	priv_freeset(priv_set);
}

void
nwamd_deescalate(void) {
	(void) pthread_mutex_lock(&uid_mutex);

	assert(uid_cnt > 0);
	if (--uid_cnt == 0) {
		priv_set_t *priv_set, *allpriv_set;

		/* build up our minimal set of privs. */
		priv_set = priv_str_to_set("basic", ",", NULL);
		allpriv_set = priv_str_to_set("zone", ",", NULL);
		if (priv_set == NULL || allpriv_set == NULL)
			pfail("converting privilege sets: %s", strerror(errno));

		(void) priv_addset(priv_set, PRIV_FILE_CHOWN_SELF);
		(void) priv_addset(priv_set, PRIV_FILE_DAC_READ);
		(void) priv_addset(priv_set, PRIV_FILE_DAC_WRITE);
		(void) priv_addset(priv_set, PRIV_NET_RAWACCESS);
		(void) priv_addset(priv_set, PRIV_NET_PRIVADDR);
		(void) priv_addset(priv_set, PRIV_PROC_AUDIT);
		(void) priv_addset(priv_set, PRIV_PROC_OWNER);
		(void) priv_addset(priv_set, PRIV_PROC_SETID);
		(void) priv_addset(priv_set, PRIV_SYS_CONFIG);
		(void) priv_addset(priv_set, PRIV_SYS_IP_CONFIG);
		(void) priv_addset(priv_set, PRIV_SYS_IPC_CONFIG);
		(void) priv_addset(priv_set, PRIV_SYS_MOUNT);
		(void) priv_addset(priv_set, PRIV_SYS_NET_CONFIG);
		(void) priv_addset(priv_set, PRIV_SYS_RES_CONFIG);
		(void) priv_addset(priv_set, PRIV_SYS_RESOURCE);

		/*
		 * Since our zone might not have all these privs,
		 * just ask for those that are available.
		 */
		priv_intersect(allpriv_set, priv_set);

		if (setppriv(PRIV_SET, PRIV_INHERITABLE, priv_set) == -1) {
			priv_freeset(allpriv_set);
			priv_freeset(priv_set);
			pfail("setppriv inheritable: %s", strerror(errno));
		}
		/*
		 * Need to ensure permitted set contains all privs so we can
		 * escalate later.
		 */
		if (setppriv(PRIV_SET, PRIV_PERMITTED, allpriv_set) == -1) {
			priv_freeset(allpriv_set);
			priv_freeset(priv_set);
			pfail("setppriv permitted: %s", strerror(errno));
		}
		/*
		 * We need to find a smaller set of privs that are important to
		 * us.  Otherwise we really are not gaining much by doing this.
		 */
		if (setppriv(PRIV_SET, PRIV_EFFECTIVE, priv_set) == -1) {
			priv_freeset(allpriv_set);
			priv_freeset(priv_set);
			pfail("setppriv effective: %s", strerror(errno));
		}

		priv_freeset(priv_set);
		priv_freeset(allpriv_set);
	}
	(void) pthread_mutex_unlock(&uid_mutex);
}

/*
 *
 * This starts a child process determined by command.  If command contains a
 * slash then it is assumed to be a full path; otherwise the path is searched
 * for an executable file with the name command.  Command is also used as
 * argv[0] of the new process.  The rest of the arguments of the function
 * up to the first NULL make up pointers to arguments of the new process.
 *
 * This function returns child exit status on success and -1 on failure.
 *
 * NOTE: original_sigmask must be set before this function is called.
 */
int
nwamd_start_childv(const char *command, char const * const *argv)
{
	posix_spawnattr_t attr;
	sigset_t fullset;
	int i, rc, status, n;
	pid_t pid;
	char vbuf[1024];

	vbuf[0] = 0;
	n = sizeof (vbuf);
	for (i = 1; argv[i] != NULL && n > 2; i++) {
		n -= strlcat(vbuf, " ", n);
		n -= strlcat(vbuf, argv[i], n);
	}
	if (argv[i] != NULL || n < 0)
		nlog(LOG_ERR, "nwamd_start_childv can't log full arg vector");

	if ((rc = posix_spawnattr_init(&attr)) != 0) {
		nlog(LOG_DEBUG, "posix_spawnattr_init %d %s\n",
		    rc, strerror(rc));
		return (-1);
	}
	(void) sigfillset(&fullset);
	if ((rc = posix_spawnattr_setsigdefault(&attr, &fullset)) != 0) {
		nlog(LOG_DEBUG, "setsigdefault %d %s\n", rc, strerror(rc));
		return (-1);
	}
	if ((rc = posix_spawnattr_setsigmask(&attr, &original_sigmask)) != 0) {
		nlog(LOG_DEBUG, "setsigmask %d %s\n", rc, strerror(rc));
		return (-1);
	}
	if ((rc = posix_spawnattr_setflags(&attr,
	    POSIX_SPAWN_SETSIGDEF|POSIX_SPAWN_SETSIGMASK)) != 0) {
		nlog(LOG_DEBUG, "setflags %d %s\n", rc, strerror(rc));
		return (-1);
	}

	if ((rc = posix_spawnp(&pid, command, NULL, &attr, (char * const *)argv,
	    environ)) > 0) {
		nlog(LOG_DEBUG, "posix_spawnp failed errno %d", rc);
		return (-1);
	}

	if ((rc = posix_spawnattr_destroy(&attr)) != 0) {
		nlog(LOG_DEBUG, "posix_spawn_attr_destroy %d %s\n",
		    rc, strerror(rc));
		return (-1);
	}

	(void) waitpid(pid, &status, 0);
	if (WIFSIGNALED(status) || WIFSTOPPED(status)) {
		i = WIFSIGNALED(status) ? WTERMSIG(status) : WSTOPSIG(status);
		nlog(LOG_ERR, "'%s%s' %s with signal %d (%s)", command, vbuf,
		    (WIFSIGNALED(status) ? "terminated" : "stopped"), i,
		    strsignal(i));
		return (-2);
	} else {
		nlog(LOG_INFO, "'%s%s' completed normally: %d", command, vbuf,
		    WEXITSTATUS(status));
		return (WEXITSTATUS(status));
	}
}

/*
 * For global zone, check if the link is used by a non-global
 * zone, note that the non-global zones doesn't need this check,
 * because zoneadm has taken care of this when the zone boots.
 * In the global zone, we ignore events for local-zone-owned links
 * since these are taken care of by the local zone's network
 * configuration services.
 */
boolean_t
nwamd_link_belongs_to_this_zone(const char *linkname)
{
	zoneid_t zoneid;
	char zonename[ZONENAME_MAX];
	int ret;

	zoneid = getzoneid();
	if (zoneid == GLOBAL_ZONEID) {
		datalink_id_t linkid;
		dladm_status_t status;
		char errstr[DLADM_STRSIZE];

		if ((status = dladm_name2info(dld_handle, linkname, &linkid,
		    NULL, NULL, NULL)) != DLADM_STATUS_OK) {
			nlog(LOG_DEBUG, "nwamd_link_belongs_to_this_zone: "
			    "could not get linkid for %s: %s",
			    linkname, dladm_status2str(status, errstr));
			return (B_FALSE);
		}
		zoneid = ALL_ZONES;
		ret = zone_check_datalink(&zoneid, linkid);
		if (ret == 0) {
			(void) getzonenamebyid(zoneid, zonename, ZONENAME_MAX);
			nlog(LOG_DEBUG, "nwamd_link_belongs_to_this_zone: "
			    "%s is used by non-global zone: %s",
			    linkname, zonename);
			return (B_FALSE);
		}
	}
	return (B_TRUE);
}

/*
 * Inputs:
 *   res is a pointer to the scf_resources_t to be released.
 */
static void
release_scf_resources(scf_resources_t *res)
{
	scf_entry_destroy(res->sr_ent);
	scf_transaction_destroy(res->sr_tx);
	scf_value_destroy(res->sr_val);
	scf_property_destroy(res->sr_prop);
	scf_pg_destroy(res->sr_pg);
	scf_snapshot_destroy(res->sr_snap);
	scf_instance_destroy(res->sr_inst);
	(void) scf_handle_unbind(res->sr_handle);
	scf_handle_destroy(res->sr_handle);
}

/*
 * Inputs:
 *   fmri is the instance to look up
 * Outputs:
 *   res is a pointer to an scf_resources_t.  This is an internal
 *   structure that holds all the handles needed to get a specific
 *   property from the running snapshot; on a successful return it
 *   contains the scf_value_t that should be passed to the desired
 *   scf_value_get_foo() function, and must be freed after use by
 *   calling release_scf_resources().  On a failure return, any
 *   resources that may have been assigned to res are released, so
 *   the caller does not need to do any cleanup in the failure case.
 * Returns:
 *    0 on success
 *   -1 on failure
 */

static int
create_scf_resources(const char *fmri, scf_resources_t *res)
{
	res->sr_tx = NULL;
	res->sr_ent = NULL;
	res->sr_inst = NULL;
	res->sr_snap = NULL;
	res->sr_pg = NULL;
	res->sr_prop = NULL;
	res->sr_val = NULL;

	if ((res->sr_handle = scf_handle_create(SCF_VERSION)) == NULL) {
		return (-1);
	}

	if (scf_handle_bind(res->sr_handle) != 0) {
		scf_handle_destroy(res->sr_handle);
		return (-1);
	}
	if ((res->sr_inst = scf_instance_create(res->sr_handle)) == NULL) {
		goto failure;
	}
	if (scf_handle_decode_fmri(res->sr_handle, fmri, NULL, NULL,
	    res->sr_inst, NULL, NULL, SCF_DECODE_FMRI_REQUIRE_INSTANCE) != 0) {
		goto failure;
	}
	if ((res->sr_snap = scf_snapshot_create(res->sr_handle)) == NULL) {
		goto failure;
	}
	if (scf_instance_get_snapshot(res->sr_inst, "running",
	    res->sr_snap) != 0) {
		goto failure;
	}
	if ((res->sr_pg = scf_pg_create(res->sr_handle)) == NULL) {
		goto failure;
	}
	if ((res->sr_prop = scf_property_create(res->sr_handle)) == NULL) {
		goto failure;
	}
	if ((res->sr_val = scf_value_create(res->sr_handle)) == NULL) {
		goto failure;
	}
	if ((res->sr_tx = scf_transaction_create(res->sr_handle)) == NULL) {
		goto failure;
	}
	if ((res->sr_ent = scf_entry_create(res->sr_handle)) == NULL) {
		goto failure;
	}
	return (0);

failure:
	nlog(LOG_ERR, "create_scf_resources failed: %s",
	    scf_strerror(scf_error()));
	release_scf_resources(res);
	return (-1);
}

/*
 * Inputs:
 *   fmri is the instance to look up
 *   pg is the property group to look up
 *   prop is the property within that group to look up
 *   running specifies if running snapshot is to be used
 * Outputs:
 *   res is a pointer to an scf_resources_t.  This is an internal
 *   structure that holds all the handles needed to get a specific
 *   property from the running snapshot; on a successful return it
 *   contains the scf_value_t that should be passed to the desired
 *   scf_value_get_foo() function, and must be freed after use by
 *   calling release_scf_resources().  On a failure return, any
 *   resources that may have been assigned to res are released, so
 *   the caller does not need to do any cleanup in the failure case.
 * Returns:
 *    0 on success
 *   -1 on failure
 */
static int
get_property_value(const char *fmri, const char *pg, const char *prop,
    boolean_t running, scf_resources_t *res)
{
	if (create_scf_resources(fmri, res) != 0)
		return (-1);

	if (scf_instance_get_pg_composed(res->sr_inst,
	    running ? res->sr_snap : NULL, pg, res->sr_pg) != 0) {
		goto failure;
	}
	if (scf_pg_get_property(res->sr_pg, prop, res->sr_prop) != 0) {
		goto failure;
	}
	if (scf_property_get_value(res->sr_prop, res->sr_val) != 0) {
		goto failure;
	}
	return (0);

failure:
	release_scf_resources(res);
	return (-1);
}

/*
 * Inputs:
 *   lfmri is the instance fmri to look up
 *   lpg is the property group to look up
 *   lprop is the property within that group to look up
 * Outputs:
 *   answer is a pointer to the property value
 * Returns:
 *    0 on success
 *   -1 on failure
 * If successful, the property value is retured in *answer.
 * Otherwise, *answer is undefined, and it is up to the caller to decide
 * how to handle that case.
 */
int
nwamd_lookup_boolean_property(const char *lfmri, const char *lpg,
    const char *lprop, boolean_t *answer)
{
	int result = -1;
	scf_resources_t res;
	uint8_t prop_val;

	if (get_property_value(lfmri, lpg, lprop, B_TRUE, &res) != 0) {

		/*
		 * an error was already logged by get_property_value,
		 * and it released any resources assigned to res before
		 * returning.
		 */
		return (result);
	}
	if (scf_value_get_boolean(res.sr_val, &prop_val) != 0) {
		goto cleanup;
	}
	*answer = (boolean_t)prop_val;
	result = 0;
cleanup:
	release_scf_resources(&res);
	return (result);
}

/*
 * Inputs:
 *   lfmri is the instance fmri to look up
 *   lpg is the property group to look up
 *   lprop is the property within that group to look up
 *   buf is the place to put the answer
 *   bufsz is the size of buf
 * Outputs:
 *
 * Returns:
 *    0 on success
 *   -1 on failure
 * If successful, the property value is retured in buf.
 * Otherwise, buf is undefined, and it is up to the caller to decide
 * how to handle that case.
 */
int
nwamd_lookup_string_property(const char *lfmri, const char *lpg,
    const char *lprop, char *buf, size_t bufsz)
{
	int result = -1;
	scf_resources_t res;

	if (get_property_value(lfmri, lpg, lprop, B_TRUE, &res) != 0) {
		/*
		 * The above function fails when trying to get a
		 * non-persistent property group from the running snapshot.
		 * Try going for the non-running snapshot.
		 */
		if (get_property_value(lfmri, lpg, lprop, B_FALSE, &res) != 0) {
			/*
			 * an error was already logged by get_property_value,
			 * and it released any resources assigned to res before
			 * returning.
			 */
			return (result);
		}
	}
	if (scf_value_get_astring(res.sr_val, buf, bufsz) == 0)
		goto cleanup;

	result = 0;
cleanup:
	release_scf_resources(&res);
	return (result);
}

/*
 * Inputs:
 *   lfmri is the instance fmri to look up
 *   lpg is the property group to look up
 *   lprop is the property within that group to look up
 * Outputs:
 *   answer is a pointer to the property value
 * Returns:
 *    0 on success
 *   -1 on failure
 * If successful, the property value is retured in *answer.
 * Otherwise, *answer is undefined, and it is up to the caller to decide
 * how to handle that case.
 */
int
nwamd_lookup_count_property(const char *lfmri, const char *lpg,
    const char *lprop, uint64_t *answer)
{
	int result = -1;
	scf_resources_t res;

	if (get_property_value(lfmri, lpg, lprop, B_TRUE, &res) != 0) {

		/*
		 * an error was already logged by get_property_value,
		 * and it released any resources assigned to res before
		 * returning.
		 */
		return (result);
	}
	if (scf_value_get_count(res.sr_val, answer) != 0) {
		goto cleanup;
	}
	result = 0;
cleanup:
	release_scf_resources(&res);
	return (result);
}

static int
set_property_value(scf_resources_t *res, const char *propname,
    scf_type_t proptype)
{
	int result = -1;
	boolean_t new;

retry:
	new = (scf_pg_get_property(res->sr_pg, propname, res->sr_prop) != 0);

	if (scf_transaction_start(res->sr_tx, res->sr_pg) == -1) {
		goto failure;
	}
	if (new) {
		if (scf_transaction_property_new(res->sr_tx, res->sr_ent,
		    propname, proptype) == -1) {
			goto failure;
		}
	} else {
		if (scf_transaction_property_change(res->sr_tx, res->sr_ent,
		    propname, proptype) == -1) {
			goto failure;
		}
	}

	if (scf_entry_add_value(res->sr_ent, res->sr_val) != 0) {
		goto failure;
	}

	result = scf_transaction_commit(res->sr_tx);
	if (result == 0) {
		scf_transaction_reset(res->sr_tx);
		if (scf_pg_update(res->sr_pg) == -1) {
			goto failure;
		}
		nlog(LOG_INFO, "set_property_value: transaction commit failed "
		    "for %s; retrying", propname);
		goto retry;
	}
	if (result == -1)
		goto failure;
	return (0);

failure:
	return (-1);
}

int
nwamd_set_count_property(const char *fmri, const char *pg, const char *prop,
    uint64_t count)
{
	scf_resources_t res;

	if (create_scf_resources(fmri, &res) != 0)
		return (-1);

	if (scf_instance_add_pg(res.sr_inst, pg, SCF_GROUP_APPLICATION,
	    SCF_PG_FLAG_NONPERSISTENT, res.sr_pg) != 0) {
		if (scf_error() != SCF_ERROR_EXISTS)
			goto failure;
		if (scf_instance_get_pg_composed(res.sr_inst, NULL, pg,
		    res.sr_pg) != 0)
			goto failure;
	}

	scf_value_set_count(res.sr_val, (uint64_t)count);

	if (set_property_value(&res, prop, SCF_TYPE_COUNT) != 0)
		goto failure;

	release_scf_resources(&res);
	return (0);

failure:
	nlog(LOG_INFO, "nwamd_set_count_property: scf failure %s while "
	    "setting %s", scf_strerror(scf_error()), prop);
	release_scf_resources(&res);
	return (-1);
}

int
nwamd_set_string_property(const char *fmri, const char *pg, const char *prop,
    const char *str)
{
	scf_resources_t res;

	if (create_scf_resources(fmri, &res) != 0)
		return (-1);

	if (scf_instance_add_pg(res.sr_inst, pg, SCF_GROUP_APPLICATION,
	    SCF_PG_FLAG_NONPERSISTENT, res.sr_pg) != 0) {
		if (scf_error() != SCF_ERROR_EXISTS)
			goto failure;
		if (scf_instance_get_pg_composed(res.sr_inst, NULL, pg,
		    res.sr_pg) != 0)
			goto failure;
	}

	if (scf_value_set_astring(res.sr_val, str) != 0)
		goto failure;

	if (set_property_value(&res, prop, SCF_TYPE_ASTRING) != 0)
		goto failure;

	release_scf_resources(&res);
	return (0);

failure:
	nlog(LOG_INFO, "nwamd_set_string_property: scf failure %s while "
	    "setting %s", scf_strerror(scf_error()), prop);
	release_scf_resources(&res);
	return (-1);
}

/*
 * Deletes property prop from property group pg in SMF instance fmri.
 * Returns 0 on success, -1 on failure.
 */
int
nwamd_delete_scf_property(const char *fmri, const char *pg, const char *prop)
{
	scf_resources_t res;
	int result = -1;

	if (create_scf_resources(fmri, &res) != 0)
		return (-1);

	if (scf_instance_add_pg(res.sr_inst, pg, SCF_GROUP_APPLICATION,
	    SCF_PG_FLAG_NONPERSISTENT, res.sr_pg) != 0) {
		if (scf_error() != SCF_ERROR_EXISTS)
			goto failure;
		if (scf_instance_get_pg_composed(res.sr_inst, NULL, pg,
		    res.sr_pg) != 0)
			goto failure;
	}

	if (scf_pg_get_property(res.sr_pg, prop, res.sr_prop) != 0)
		goto failure;
retry:
	if (scf_transaction_start(res.sr_tx, res.sr_pg) == -1)
		goto failure;

	if (scf_transaction_property_delete(res.sr_tx, res.sr_ent, prop) == -1)
		goto failure;

	result = scf_transaction_commit(res.sr_tx);
	if (result == 0) {
		scf_transaction_reset(res.sr_tx);
		if (scf_pg_update(res.sr_pg) == -1)
			goto failure;
		goto retry;
	}
	if (result == -1)
		goto failure;

	release_scf_resources(&res);
	return (0);
failure:
	release_scf_resources(&res);
	return (-1);
}
