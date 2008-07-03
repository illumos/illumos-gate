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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Config routines common to idmap(1M) and idmapd(1M)
 */

#include <stdlib.h>
#include <strings.h>
#include <libintl.h>
#include <ctype.h>
#include <errno.h>
#include "idmapd.h"
#include <stdio.h>
#include <stdarg.h>
#include <uuid/uuid.h>
#include <pthread.h>
#include <port.h>
#include <net/route.h>
#include "addisc.h"

#define	MACHINE_SID_LEN		(9 + 3 * 11)
#define	FMRI_BASE		"svc:/system/idmap"
#define	CONFIG_PG		"config"
#define	GENERAL_PG		"general"
#define	RECONFIGURE		1
#define	POKE_AUTO_DISCOVERY	2

/*LINTLIBRARY*/


static pthread_t update_thread_handle = 0;

static int idmapd_ev_port = -1;
static int rt_sock = -1;

static int
generate_machine_sid(char **machine_sid)
{
	char *p;
	uuid_t uu;
	int i, j, len, rlen;
	uint32_t rid;

	/*
	 * Generate and split 128-bit UUID into three 32-bit RIDs The
	 * machine_sid will be of the form S-1-5-21-N1-N2-N3 (that's
	 * four RIDs altogether).
	 *
	 * Technically we could use upto 14 random RIDs here, but it
	 * turns out that with some versions of Windows using SIDs with
	 * more than  five RIDs in security descriptors causes problems.
	 */

	*machine_sid = calloc(1, MACHINE_SID_LEN);
	if (*machine_sid == NULL) {
		idmapdlog(LOG_ERR, "Out of memory");
		return (-1);
	}
	(void) strcpy(*machine_sid, "S-1-5-21");
	p = *machine_sid + strlen("S-1-5-21");
	len = MACHINE_SID_LEN - strlen("S-1-5-21");

	uuid_clear(uu);
	uuid_generate_random(uu);

#if UUID_LEN != 16
#error UUID size is not 16!
#endif

	for (i = 0; i < 3; i++) {
		j = i * 4;
		rid = (uu[j] << 24) | (uu[j + 1] << 16) |
		    (uu[j + 2] << 8) | (uu[j + 3]);
		rlen = snprintf(p, len, "-%u", rid);
		p += rlen;
		len -= rlen;
	}

	return (0);
}


/* In the case of error, exists is set to FALSE anyway */
static int
prop_exists(idmap_cfg_handles_t *handles, char *name, bool_t *exists)
{

	scf_property_t *scf_prop;
	scf_value_t *value;

	*exists = FALSE;

	scf_prop = scf_property_create(handles->main);
	if (scf_prop == NULL) {
		idmapdlog(LOG_ERR, "scf_property_create() failed: %s",
		    scf_strerror(scf_error()));
		return (-1);
	}
	value = scf_value_create(handles->main);
	if (value == NULL) {
		idmapdlog(LOG_ERR, "scf_value_create() failed: %s",
		    scf_strerror(scf_error()));
		scf_property_destroy(scf_prop);
		return (-1);
	}

	if (scf_pg_get_property(handles->config_pg, name, scf_prop) == 0)
		*exists = TRUE;

	scf_value_destroy(value);
	scf_property_destroy(scf_prop);

	return (0);
}

/* Check if in the case of failure the original value of *val is preserved */
static int
get_val_int(idmap_cfg_handles_t *handles, char *name,
	void *val, scf_type_t type)
{
	int rc = 0;

	scf_property_t *scf_prop;
	scf_value_t *value;

	switch (type) {
	case SCF_TYPE_BOOLEAN:
		*(uint8_t *)val = 0;
		break;
	case SCF_TYPE_COUNT:
		*(uint64_t *)val = 0;
		break;
	case SCF_TYPE_INTEGER:
		*(int64_t *)val = 0;
		break;
	default:
		idmapdlog(LOG_ERR, "Invalid scf integer type (%d)",
		    type);
		abort();
	}

	scf_prop = scf_property_create(handles->main);
	if (scf_prop == NULL) {
		idmapdlog(LOG_ERR, "scf_property_create() failed: %s",
		    scf_strerror(scf_error()));
		return (-1);
	}
	value = scf_value_create(handles->main);
	if (value == NULL) {
		idmapdlog(LOG_ERR, "scf_value_create() failed: %s",
		    scf_strerror(scf_error()));
		scf_property_destroy(scf_prop);
		return (-1);
	}

	if (scf_pg_get_property(handles->config_pg, name, scf_prop) < 0)
	/* this is OK: the property is just undefined */
		goto destruction;


	if (scf_property_get_value(scf_prop, value) < 0)
	/* It is still OK when a property doesn't have any value */
		goto destruction;

	switch (type) {
	case SCF_TYPE_BOOLEAN:
		rc = scf_value_get_boolean(value, val);
		break;
	case SCF_TYPE_COUNT:
		rc = scf_value_get_count(value, val);
		break;
	case SCF_TYPE_INTEGER:
		rc = scf_value_get_integer(value, val);
		break;
	}


destruction:
	scf_value_destroy(value);
	scf_property_destroy(scf_prop);

	return (rc);
}

static char *
scf_value2string(scf_value_t *value)
{
	int rc = -1;
	char buf_size = 127;
	int length;
	char *buf = NULL;
	buf = (char *) malloc(sizeof (char) * buf_size);

	for (;;) {
		length = scf_value_get_astring(value, buf, buf_size);
		if (length < 0) {
			rc = -1;
			goto destruction;
		}

		if (length == buf_size - 1) {
			buf_size *= 2;
			buf = (char *)realloc(buf, buf_size * sizeof (char));
			if (!buf) {
				idmapdlog(LOG_ERR, "Out of memory");
				rc = -1;
				goto destruction;
			}
		} else {
			rc = 0;
			break;
		}
	}

destruction:
	if (rc < 0) {
		if (buf)
			free(buf);
		buf = NULL;
	}

	return (buf);
}

static int
get_val_ds(idmap_cfg_handles_t *handles, const char *name, int defport,
		idmap_ad_disc_ds_t **val)
{
	idmap_ad_disc_ds_t *servers = NULL;
	scf_property_t *scf_prop;
	scf_value_t *value;
	scf_iter_t *iter;
	char *host, *portstr;
	int len, i;
	int count = 0;
	int rc = -1;

	*val = NULL;

restart:
	scf_prop = scf_property_create(handles->main);
	if (scf_prop == NULL) {
		idmapdlog(LOG_ERR, "scf_property_create() failed: %s",
		    scf_strerror(scf_error()));
		return (-1);
	}

	value = scf_value_create(handles->main);
	if (value == NULL) {
		idmapdlog(LOG_ERR, "scf_value_create() failed: %s",
		    scf_strerror(scf_error()));
		scf_property_destroy(scf_prop);
		return (-1);
	}

	iter = scf_iter_create(handles->main);
	if (iter == NULL) {
		idmapdlog(LOG_ERR, "scf_iter_create() failed: %s",
		    scf_strerror(scf_error()));
		scf_value_destroy(value);
		scf_property_destroy(scf_prop);
		return (-1);
	}

	if (scf_pg_get_property(handles->config_pg, name, scf_prop) < 0) {
		/* this is OK: the property is just undefined */
		rc = 0;
		goto destruction;
	}

	if (scf_iter_property_values(iter, scf_prop) < 0) {
		idmapdlog(LOG_ERR,
		    "scf_iter_property_values(%s) failed: %s",
		    name, scf_strerror(scf_error()));
		goto destruction;
	}

	/* Workaround scf bugs -- can't reset an iteration */
	if (count == 0) {
		while (scf_iter_next_value(iter, value) > 0)
			count++;

		if (count == 0) {
			/* no values */
			rc = 0;
			goto destruction;
		}

		scf_value_destroy(value);
		scf_iter_destroy(iter);
		scf_property_destroy(scf_prop);
		goto restart;
	}

	if ((servers = calloc(count + 1, sizeof (*servers))) == NULL) {
		idmapdlog(LOG_ERR, "Out of memory");
		goto destruction;
	}

	i = 0;
	while (i < count && scf_iter_next_value(iter, value) > 0) {
		servers[i].priority = 0;
		servers[i].weight = 100;
		servers[i].port = defport;
		if ((host = scf_value2string(value)) == NULL) {
			goto destruction;
		}
		if ((portstr = strchr(host, ':')) != NULL) {
			*portstr++ = '\0';
			servers[i].port = strtol(portstr,
			    (char **)NULL, 10);
			if (servers[i].port == 0)
				servers[i].port = defport;
		}
		len = strlcpy(servers[i].host, host,
		    sizeof (servers->host));

		free(host);

		/* Ignore this server if the hostname is too long */
		if (len < sizeof (servers->host))
			i++;
	}

	*val = servers;

	rc = 0;

destruction:
	scf_value_destroy(value);
	scf_iter_destroy(iter);
	scf_property_destroy(scf_prop);

	if (rc < 0) {
		if (servers)
			free(servers);
		*val = NULL;
	}

	return (rc);
}


static int
get_val_astring(idmap_cfg_handles_t *handles, char *name, char **val)
{
	int rc = 0;

	scf_property_t *scf_prop;
	scf_value_t *value;

	scf_prop = scf_property_create(handles->main);
	if (scf_prop == NULL) {
		idmapdlog(LOG_ERR, "scf_property_create() failed: %s",
		    scf_strerror(scf_error()));
		return (-1);
	}
	value = scf_value_create(handles->main);
	if (value == NULL) {
		idmapdlog(LOG_ERR, "scf_value_create() failed: %s",
		    scf_strerror(scf_error()));
		scf_property_destroy(scf_prop);
		return (-1);
	}

	*val = NULL;

	if (scf_pg_get_property(handles->config_pg, name, scf_prop) < 0)
	/* this is OK: the property is just undefined */
		goto destruction;

	if (scf_property_get_value(scf_prop, value) < 0) {
		idmapdlog(LOG_ERR,
		    "scf_property_get_value(%s) failed: %s",
		    name, scf_strerror(scf_error()));
		rc = -1;
		goto destruction;
	}

	if (!(*val = scf_value2string(value)))
		rc = -1;

destruction:
	scf_value_destroy(value);
	scf_property_destroy(scf_prop);

	if (rc < 0) {
		if (*val)
			free(*val);
		*val = NULL;
	}

	return (rc);
}


static int
set_val_astring(idmap_cfg_handles_t *handles, char *name, const char *val)
{
	int			rc = -1;
	int			ret = -2;
	int			i;
	scf_property_t		*scf_prop = NULL;
	scf_value_t		*value = NULL;
	scf_transaction_t	*tx = NULL;
	scf_transaction_entry_t	*ent = NULL;

	if ((scf_prop = scf_property_create(handles->main)) == NULL ||
	    (value = scf_value_create(handles->main)) == NULL ||
	    (tx = scf_transaction_create(handles->main)) == NULL ||
	    (ent = scf_entry_create(handles->main)) == NULL) {
		idmapdlog(LOG_ERR, "Unable to set property %s",
		    name, scf_strerror(scf_error()));
		goto destruction;
	}

	for (i = 0; i < MAX_TRIES && (ret == -2 || ret == 0); i++) {
		if (scf_transaction_start(tx, handles->config_pg) == -1) {
			idmapdlog(LOG_ERR,
			    "scf_transaction_start(%s) failed: %s",
			    name, scf_strerror(scf_error()));
			goto destruction;
		}

		if (scf_transaction_property_new(tx, ent, name,
		    SCF_TYPE_ASTRING) < 0) {
			idmapdlog(LOG_ERR,
			    "scf_transaction_property_new() failed: %s",
			    scf_strerror(scf_error()));
			goto destruction;
		}

		if (scf_value_set_astring(value, val) == -1) {
			idmapdlog(LOG_ERR,
			    "scf_value_set_astring() failed: %s",
			    scf_strerror(scf_error()));
			goto destruction;
		}

		if (scf_entry_add_value(ent, value) == -1) {
			idmapdlog(LOG_ERR,
			    "scf_entry_add_value() failed: %s",
			    scf_strerror(scf_error()));
			goto destruction;
		}

		if ((ret = scf_transaction_commit(tx)) == 1)
			break;

		if (ret == 0 && i < MAX_TRIES - 1) {
			/*
			 * Property group set in scf_transaction_start()
			 * is not the most recent. Update pg, reset tx and
			 * retry tx.
			 */
			idmapdlog(LOG_WARNING,
			    "scf_transaction_commit(%s) failed - Retry: %s",
			    name, scf_strerror(scf_error()));
			if (scf_pg_update(handles->config_pg) == -1) {
				idmapdlog(LOG_ERR,
				    "scf_pg_update() failed: %s",
				    scf_strerror(scf_error()));
				goto destruction;
			}
			scf_transaction_reset(tx);
		}
	}


	if (ret == 1)
		rc = 0;
	else if (ret != -2)
		idmapdlog(LOG_ERR,
		    "scf_transaction_commit(%s) failed: %s",
		    name, scf_strerror(scf_error()));

destruction:
	scf_value_destroy(value);
	scf_entry_destroy(ent);
	scf_transaction_destroy(tx);
	scf_property_destroy(scf_prop);
	return (rc);
}

static int
update_bool(bool_t *value, bool_t *new, char *name)
{
	if (*value == *new)
		return (0);

	idmapdlog(LOG_INFO, "change %s=%s", name, *new ? "true" : "false");
	*value = *new;
	return (1);
}

static int
update_string(char **value, char **new, char *name)
{
	if (*new == NULL)
		return (0);

	if (*value != NULL && strcmp(*new, *value) == 0) {
		free(*new);
		*new = NULL;
		return (0);
	}

	idmapdlog(LOG_INFO, "change %s=%s", name, CHECK_NULL(*new));
	if (*value != NULL)
		free(*value);
	*value = *new;
	*new = NULL;
	return (1);
}

static int
update_dirs(idmap_ad_disc_ds_t **value, idmap_ad_disc_ds_t **new, char *name)
{
	int i;

	if (*value == *new)
		/* Nothing to do */
		return (0);

	if (*value != NULL && *new != NULL &&
	    ad_disc_compare_ds(*value, *new) == 0) {
		free(*new);
		*new = NULL;
		return (0);
	}

	if (*value)
		free(*value);

	*value = *new;
	*new = NULL;

	if (*value == NULL) {
		/* We're unsetting this DS property */
		idmapdlog(LOG_INFO, "change %s=<none>", name);
		return (1);
	}

	/* List all the new DSs */
	for (i = 0; (*value)[i].host[0] != '\0'; i++)
		idmapdlog(LOG_INFO, "change %s=%s port=%d", name,
		    (*value)[i].host, (*value)[i].port);
	return (1);
}


#define	MAX_CHECK_TIME		(20 * 60)

/*
 * Returns 1 if the PF_ROUTE socket event indicates that we should rescan the
 * interfaces.
 *
 * Shamelessly based on smb_nics_changed() and other PF_ROUTE uses in ON.
 */
static
int
pfroute_event_is_interesting(int rt_sock)
{
	int nbytes;
	int64_t msg[2048 / 8];
	struct rt_msghdr *rtm;
	int is_interesting = FALSE;

	for (;;) {
		if ((nbytes = read(rt_sock, msg, sizeof (msg))) <= 0)
			break;
		rtm = (struct rt_msghdr *)msg;
		if (rtm->rtm_version != RTM_VERSION)
			continue;
		if (nbytes < rtm->rtm_msglen)
			continue;
		switch (rtm->rtm_type) {
		case RTM_NEWADDR:
		case RTM_DELADDR:
		case RTM_IFINFO:
			is_interesting = TRUE;
			break;
		default:
			break;
		}
	}
	return (is_interesting);
}

/*
 * Returns 1 if SIGHUP has been received (see hup_handler() elsewhere) or if an
 * interface address was added or removed; otherwise it returns 0.
 *
 * Note that port_get() does not update its timeout argument when EINTR, unlike
 * nanosleep().  We probably don't care very much here, but if we did care then
 * we could always use a timer event and associate it with the same event port,
 * then we could get accurate waiting regardless of EINTRs.
 */
static
int
wait_for_event(int poke_is_interesting, struct timespec *timeoutp)
{
	port_event_t pe;

retry:
	memset(&pe, 0, sizeof (pe));
	if (port_get(idmapd_ev_port, &pe, timeoutp) != 0) {
		switch (errno) {
		case EINTR:
			goto retry;
		case ETIME:
			/* Timeout */
			return (FALSE);
		default:
			/* EBADF, EBADFD, EFAULT, EINVAL (end of time?)? */
			idmapdlog(LOG_ERR, "Event port failed: %s",
			    strerror(errno));
			exit(1);
			/* NOTREACHED */
			break;
		}
	}

	if (pe.portev_source == PORT_SOURCE_USER &&
	    pe.portev_events == POKE_AUTO_DISCOVERY)
		return (poke_is_interesting ? TRUE : FALSE);

	if (pe.portev_source == PORT_SOURCE_FD && pe.portev_object == rt_sock) {
		/* PF_ROUTE socket read event, re-associate fd, handle event */
		if (port_associate(idmapd_ev_port, PORT_SOURCE_FD, rt_sock,
		    POLLIN, NULL) != 0) {
			idmapdlog(LOG_ERR, "Failed to re-associate the "
			    "routing socket with the event port: %s",
			    strerror(errno));
			exit(1);
		}
		/*
		 * The network configuration may still be in flux.  No matter,
		 * the resolver will re-transmit and timout if need be.
		 */
		return (pfroute_event_is_interesting(rt_sock));
	}

	if (pe.portev_source == PORT_SOURCE_USER &&
	    pe.portev_events == RECONFIGURE) {
		int rc;

		/*
		 * Blow away the ccache, we might have re-joined the
		 * domain or joined a new one
		 */
		(void) unlink(IDMAP_CACHEDIR "/ccache");
		/* HUP is the refresh method, so re-read SMF config */
		(void) idmapdlog(LOG_INFO, "SMF refresh");
		rc = idmap_cfg_load(_idmapdstate.cfg, CFG_DISCOVER|CFG_LOG);
		if (rc < -1) {
			(void) idmapdlog(LOG_ERR, "Fatal errors while reading "
			    "SMF properties");
			exit(1);
		} else if (rc == -1) {
			(void) idmapdlog(LOG_WARNING, "Various errors "
			    "re-loading configuration may cause AD lookups "
			    "to fail");
		}
		return (FALSE);
	}

	return (FALSE);
}

void *
idmap_cfg_update_thread(void *arg)
{

	int			ttl, changed, poke_is_interesting;
	idmap_cfg_handles_t	*handles = &_idmapdstate.cfg->handles;
	ad_disc_t		ad_ctx = handles->ad_ctx;
	struct timespec		timeout, *timeoutp;

	poke_is_interesting = 1;
	for (ttl = 0, changed = TRUE; ; ttl = ad_disc_get_TTL(ad_ctx)) {
		/*
		 * If ttl < 0 then we can wait for an event without timing out.
		 * If idmapd needs to notice that the system has been joined to
		 * a Windows domain then idmapd needs to be refreshed.
		 */
		timeoutp = (ttl < 0) ? NULL : &timeout;
		if (ttl > MAX_CHECK_TIME)
			ttl = MAX_CHECK_TIME;
		timeout.tv_sec = ttl;
		timeout.tv_nsec = 0;
		changed = wait_for_event(poke_is_interesting, timeoutp);

		/*
		 * If there are no interesting events, and this is not the first
		 * time through the loop, and we haven't waited the most that
		 * we're willing to wait, so do nothing but wait some more.
		 */
		if (changed == FALSE && ttl > 0 && ttl < MAX_CHECK_TIME)
			continue;

		(void) ad_disc_SubnetChanged(ad_ctx);

		if (idmap_cfg_load(_idmapdstate.cfg, CFG_DISCOVER) < -1) {
			(void) idmapdlog(LOG_ERR, "Fatal errors while reading "
			    "SMF properties");
			exit(1);
		}

		if (_idmapdstate.cfg->pgcfg.global_catalog == NULL ||
		    _idmapdstate.cfg->pgcfg.global_catalog[0].host[0] == '\0')
			poke_is_interesting = 1;
		else
			poke_is_interesting = 0;
	}
	/*NOTREACHED*/
	return (NULL);
}

int
idmap_cfg_start_updates(void)
{
	if ((idmapd_ev_port = port_create()) < 0) {
		idmapdlog(LOG_ERR, "Failed to create event port: %s",
		    strerror(errno));
		return (-1);
	}

	if ((rt_sock = socket(PF_ROUTE, SOCK_RAW, 0)) < 0) {
		idmapdlog(LOG_ERR, "Failed to open routing socket: %s",
		    strerror(errno));
		(void) close(idmapd_ev_port);
		return (-1);
	}

	if (fcntl(rt_sock, F_SETFL, O_NDELAY|O_NONBLOCK) < 0) {
		idmapdlog(LOG_ERR, "Failed to set routing socket flags: %s",
		    strerror(errno));
		(void) close(rt_sock);
		(void) close(idmapd_ev_port);
		return (-1);
	}

	if (port_associate(idmapd_ev_port, PORT_SOURCE_FD,
	    rt_sock, POLLIN, NULL) != 0) {
		idmapdlog(LOG_ERR, "Failed to associate the routing "
		    "socket with the event port: %s", strerror(errno));
		(void) close(rt_sock);
		(void) close(idmapd_ev_port);
		return (-1);
	}

	if ((errno = pthread_create(&update_thread_handle, NULL,
	    idmap_cfg_update_thread, NULL)) != 0) {
		idmapdlog(LOG_ERR, "Failed to start update thread: %s",
		    strerror(errno));
		(void) port_dissociate(idmapd_ev_port, PORT_SOURCE_FD, rt_sock);
		(void) close(rt_sock);
		(void) close(idmapd_ev_port);
		return (-1);
	}

	return (0);
}

/*
 * Reject attribute names with invalid characters.
 */
static
int
valid_ldap_attr(const char *attr) {
	for (; *attr; attr++) {
		if (!isalnum(*attr) && *attr != '-' &&
		    *attr != '_' && *attr != '.' && *attr != ';')
			return (0);
	}
	return (1);
}

/*
 * This is the half of idmap_cfg_load() that loads property values from
 * SMF (using the config/ property group of the idmap FMRI).
 *
 * Return values: 0 -> success, -1 -> failure, -2 -> hard failures
 *               -3 -> hard smf config failures
 * reading from SMF.
 */
static
int
idmap_cfg_load_smf(idmap_cfg_handles_t *handles, idmap_pg_config_t *pgcfg,
	int *errors)
{
	int rc;
	uint8_t bool_val;
	char *str = NULL;
	bool_t new_debug_mode;

	if (scf_pg_update(handles->config_pg) < 0) {
		idmapdlog(LOG_ERR, "scf_pg_update() failed: %s",
		    scf_strerror(scf_error()));
		return (-2);
	}

	if (scf_pg_update(handles->general_pg) < 0) {
		idmapdlog(LOG_ERR, "scf_pg_update() failed: %s",
		    scf_strerror(scf_error()));
		return (-2);
	}


	rc = prop_exists(handles, "debug", &new_debug_mode);
	if (rc != 0)
		errors++;

	if (_idmapdstate.debug_mode != new_debug_mode) {
		if (_idmapdstate.debug_mode == FALSE) {
			_idmapdstate.debug_mode = new_debug_mode;
			idmap_log_stderr(LOG_DEBUG);
			idmapdlog(LOG_DEBUG, "debug mode enabled");
		} else {
			idmapdlog(LOG_DEBUG, "debug mode disabled");
			idmap_log_stderr(-1);
			_idmapdstate.debug_mode = new_debug_mode;
		}
	}

	rc = get_val_int(handles, "unresolvable_sid_mapping",
	    &pgcfg->eph_map_unres_sids, SCF_TYPE_BOOLEAN);
	if (rc != 0)
		errors++;

	rc = get_val_int(handles, "list_size_limit",
	    &pgcfg->list_size_limit, SCF_TYPE_COUNT);
	if (rc != 0)
		errors++;

	rc = get_val_astring(handles, "domain_name",
	    &pgcfg->domain_name);
	if (rc != 0)
		errors++;
	else
		(void) ad_disc_set_DomainName(handles->ad_ctx,
		    pgcfg->domain_name);

	rc = get_val_astring(handles, "default_domain",
	    &pgcfg->default_domain);
	if (rc != 0) {
		/*
		 * SCF failures fetching config/default_domain we treat
		 * as fatal as they may leave ID mapping rules that
		 * match unqualified winnames flapping in the wind.
		 */
		return (-2);
	}

	rc = get_val_astring(handles, "mapping_domain", &str);
	if (rc != 0)
		errors++;

	/*
	 * We treat default_domain as having been specified in SMF IFF
	 * either (the config/default_domain property was set) or (the
	 * old, obsolete, never documented config/mapping_domain
	 * property was set and the new config/domain_name property was
	 * not set).
	 */
	pgcfg->dflt_dom_set_in_smf = TRUE;
	if (pgcfg->default_domain == NULL) {

		pgcfg->dflt_dom_set_in_smf = FALSE;

		if (pgcfg->domain_name != NULL) {
			pgcfg->default_domain = strdup(pgcfg->domain_name);
			if (str != NULL) {
				idmapdlog(LOG_WARNING,
				    "Ignoring obsolete, undocumented "
				    "config/mapping_domain property");
			}
		} else if (str != NULL) {
			pgcfg->default_domain = strdup(str);
			pgcfg->dflt_dom_set_in_smf = TRUE;
			idmapdlog(LOG_WARNING,
			    "The config/mapping_domain property is "
			    "obsolete; support for it will be removed, "
			    "please use config/default_domain instead");
		}
	}

	if (str != NULL)
		free(str);

	rc = get_val_astring(handles, "machine_sid", &pgcfg->machine_sid);
	if (rc != 0)
		errors++;
	if (pgcfg->machine_sid == NULL) {
		/* If machine_sid not configured, generate one */
		if (generate_machine_sid(&pgcfg->machine_sid) < 0)
			return (-2);
		rc = set_val_astring(handles, "machine_sid",
		    pgcfg->machine_sid);
		if (rc != 0)
			errors++;
	}

	str = NULL;
	rc = get_val_ds(handles, "domain_controller", 389,
	    &pgcfg->domain_controller);
	if (rc != 0)
		errors++;
	else
		(void) ad_disc_set_DomainController(handles->ad_ctx,
		    pgcfg->domain_controller);

	rc = get_val_astring(handles, "forest_name", &pgcfg->forest_name);
	if (rc != 0)
		errors++;
	else
		(void) ad_disc_set_ForestName(handles->ad_ctx,
		    pgcfg->forest_name);

	rc = get_val_astring(handles, "site_name", &pgcfg->site_name);
	if (rc != 0)
		errors++;
	else
		(void) ad_disc_set_SiteName(handles->ad_ctx, pgcfg->site_name);

	str = NULL;
	rc = get_val_ds(handles, "global_catalog", 3268,
	    &pgcfg->global_catalog);
	if (rc != 0)
		errors++;
	else
		(void) ad_disc_set_GlobalCatalog(handles->ad_ctx,
		    pgcfg->global_catalog);

	/*
	 * Read directory-based name mappings related SMF properties
	 */
	rc = get_val_int(handles, "ds_name_mapping_enabled",
	    &bool_val, SCF_TYPE_BOOLEAN);
	if (rc != 0)
		return (-2);

	if (!bool_val)
		return (rc);

	pgcfg->ds_name_mapping_enabled = TRUE;
	rc = get_val_astring(handles, "ad_unixuser_attr",
	    &pgcfg->ad_unixuser_attr);
	if (rc != 0)
		return (-2);
	if (pgcfg->ad_unixuser_attr != NULL &&
	    !valid_ldap_attr(pgcfg->ad_unixuser_attr)) {
		idmapdlog(LOG_ERR, "config/ad_unixuser_attr=%s is not a "
		    "valid LDAP attribute name", pgcfg->ad_unixuser_attr);
		return (-3);
	}

	rc = get_val_astring(handles, "ad_unixgroup_attr",
	    &pgcfg->ad_unixgroup_attr);
	if (rc != 0)
		return (-2);
	if (pgcfg->ad_unixgroup_attr != NULL &&
	    !valid_ldap_attr(pgcfg->ad_unixgroup_attr)) {
		idmapdlog(LOG_ERR, "config/ad_unixgroup_attr=%s is not a "
		    "valid LDAP attribute name", pgcfg->ad_unixgroup_attr);
		return (-3);
	}

	rc = get_val_astring(handles, "nldap_winname_attr",
	    &pgcfg->nldap_winname_attr);
	if (rc != 0)
		return (-2);
	if (pgcfg->nldap_winname_attr != NULL &&
	    !valid_ldap_attr(pgcfg->nldap_winname_attr)) {
		idmapdlog(LOG_ERR, "config/nldap_winname_attr=%s is not a "
		    "valid LDAP attribute name", pgcfg->nldap_winname_attr);
		return (-3);
	}
	if (pgcfg->ad_unixuser_attr == NULL &&
	    pgcfg->ad_unixgroup_attr == NULL &&
	    pgcfg->nldap_winname_attr == NULL) {
		idmapdlog(LOG_ERR,
		    "If config/ds_name_mapping_enabled property is set to "
		    "true then atleast one of the following name mapping "
		    "attributes must be specified. (config/ad_unixuser_attr OR "
		    "config/ad_unixgroup_attr OR config/nldap_winname_attr)");
		return (-3);
	}

	return (rc);

}

/*
 * This is the half of idmap_cfg_load() that auto-discovers values of
 * discoverable properties that weren't already set via SMF properties.
 *
 * idmap_cfg_discover() is called *after* idmap_cfg_load_smf(), so it
 * needs to be careful not to overwrite any properties set in SMF.
 */
static
void
idmap_cfg_discover(idmap_cfg_handles_t *handles, idmap_pg_config_t *pgcfg)
{
	ad_disc_t ad_ctx = handles->ad_ctx;

	ad_disc_refresh(ad_ctx);

	if (pgcfg->default_domain == NULL)
		pgcfg->default_domain = ad_disc_get_DomainName(ad_ctx);

	if (pgcfg->domain_name == NULL)
		pgcfg->domain_name = ad_disc_get_DomainName(ad_ctx);

	if (pgcfg->domain_controller == NULL)
		pgcfg->domain_controller =
		    ad_disc_get_DomainController(ad_ctx, AD_DISC_PREFER_SITE);

	if (pgcfg->forest_name == NULL)
		pgcfg->forest_name = ad_disc_get_ForestName(ad_ctx);

	if (pgcfg->site_name == NULL)
		pgcfg->site_name = ad_disc_get_SiteName(ad_ctx);

	if (pgcfg->global_catalog == NULL)
		pgcfg->global_catalog =
		    ad_disc_get_GlobalCatalog(ad_ctx, AD_DISC_PREFER_SITE);

	if (pgcfg->domain_name == NULL)
		idmapdlog(LOG_DEBUG, "unable to discover Domain Name");
	if (pgcfg->domain_controller == NULL)
		idmapdlog(LOG_DEBUG, "unable to discover Domain Controller");
	if (pgcfg->forest_name == NULL)
		idmapdlog(LOG_DEBUG, "unable to discover Forest Name");
	if (pgcfg->site_name == NULL)
		idmapdlog(LOG_DEBUG, "unable to discover Site Name");
	if (pgcfg->global_catalog == NULL)
		idmapdlog(LOG_DEBUG, "unable to discover Global Catalog");
}

/*
 * idmap_cfg_load() is called at startup, and periodically via the
 * update thread when the auto-discovery TTLs expire, as well as part of
 * the refresh method, to update the current configuration.  It always
 * reads from SMF, but you still have to refresh the service after
 * changing the config pg in order for the changes to take effect.
 *
 * There are two flags:
 *
 *  - CFG_DISCOVER
 *  - CFG_LOG
 *
 * If CFG_DISCOVER is set then idmap_cfg_load() calls
 * idmap_cfg_discover() to discover, via DNS and LDAP lookups, property
 * values that weren't set in SMF.
 *
 * If CFG_LOG is set then idmap_cfg_load() will log (to LOG_NOTICE)
 * whether the configuration changed.  This should be used only from the
 * refresh method.
 *
 * Return values: 0 -> success, -1 -> failure, -2 -> hard failures
 * reading from SMF.
 */
int
idmap_cfg_load(idmap_cfg_t *cfg, int flags)
{
	int rc = 0;
	int errors = 0;
	int changed = 0;
	idmap_pg_config_t new_pgcfg, *live_pgcfg;

	live_pgcfg = &cfg->pgcfg;
	(void) memset(&new_pgcfg, 0, sizeof (new_pgcfg));

	pthread_mutex_lock(&cfg->handles.mutex);

	if ((rc = idmap_cfg_load_smf(&cfg->handles, &new_pgcfg, &errors)) < -1)
		goto err;

	if (flags & CFG_DISCOVER)
		idmap_cfg_discover(&cfg->handles, &new_pgcfg);

	WRLOCK_CONFIG();
	if (live_pgcfg->list_size_limit != new_pgcfg.list_size_limit) {
		idmapdlog(LOG_INFO, "change list_size=%d",
		    new_pgcfg.list_size_limit);
		live_pgcfg->list_size_limit = new_pgcfg.list_size_limit;
	}

	/* Non-discoverable props updated here */
	changed += update_string(&live_pgcfg->machine_sid,
	    &new_pgcfg.machine_sid, "machine_sid");

	changed += update_bool(&live_pgcfg->eph_map_unres_sids,
	    &new_pgcfg.eph_map_unres_sids, "unresolvable_sid_mapping");

	changed += live_pgcfg->ds_name_mapping_enabled !=
	    new_pgcfg.ds_name_mapping_enabled;
	live_pgcfg->ds_name_mapping_enabled =
	    new_pgcfg.ds_name_mapping_enabled;

	changed += update_string(&live_pgcfg->ad_unixuser_attr,
	    &new_pgcfg.ad_unixuser_attr, "ad_unixuser_attr");

	changed += update_string(&live_pgcfg->ad_unixgroup_attr,
	    &new_pgcfg.ad_unixgroup_attr, "ad_unixgroup_attr");

	changed += update_string(&live_pgcfg->nldap_winname_attr,
	    &new_pgcfg.nldap_winname_attr, "nldap_winname_attr");

	/* Props that can be discovered and set in SMF updated here */
	if (live_pgcfg->dflt_dom_set_in_smf == FALSE)
		changed += update_string(&live_pgcfg->default_domain,
		    &new_pgcfg.default_domain, "default_domain");

	changed += update_string(&live_pgcfg->domain_name,
	    &new_pgcfg.domain_name, "domain_name");

	changed += update_dirs(&live_pgcfg->domain_controller,
	    &new_pgcfg.domain_controller, "domain_controller");

	changed += update_string(&live_pgcfg->forest_name,
	    &new_pgcfg.forest_name, "forest_name");

	changed += update_string(&live_pgcfg->site_name,
	    &new_pgcfg.site_name, "site_name");

	if (update_dirs(&live_pgcfg->global_catalog,
	    &new_pgcfg.global_catalog, "global_catalog")) {
		changed++;
		/*
		 * Right now we only update the ad_t used for AD lookups
		 * when the GC list is updated.  When we add mixed
		 * ds-based mapping we'll also need to update the ad_t
		 * used to talk to the domain, not just the one used to
		 * talk to the GC.
		 */
		if (live_pgcfg->global_catalog != NULL &&
		    live_pgcfg->global_catalog[0].host[0] != '\0')
			reload_ad();
	}

	idmap_cfg_unload(&new_pgcfg);

	if (flags & CFG_LOG) {
		/*
		 * If the config changes as a result of a refresh of the
		 * service, then logging about it can provide useful
		 * feedback to the sysadmin.
		 */
		idmapdlog(LOG_NOTICE, "Configuration %schanged",
		    changed ? "" : "un");
	}

	UNLOCK_CONFIG();

err:
	pthread_mutex_unlock(&cfg->handles.mutex);

	if (rc < -1)
		return (rc);

	return ((errors == 0) ? 0 : -1);
}

/*
 * Initialize 'cfg'.
 */
idmap_cfg_t *
idmap_cfg_init()
{
	idmap_cfg_handles_t *handles;

	/* First the smf repository handles: */
	idmap_cfg_t *cfg = calloc(1, sizeof (idmap_cfg_t));
	if (!cfg) {
		idmapdlog(LOG_ERR, "Out of memory");
		return (NULL);
	}
	handles = &cfg->handles;

	(void) pthread_mutex_init(&handles->mutex, NULL);

	if (!(handles->main = scf_handle_create(SCF_VERSION))) {
		idmapdlog(LOG_ERR, "scf_handle_create() failed: %s",
		    scf_strerror(scf_error()));
		goto error;
	}

	if (scf_handle_bind(handles->main) < 0) {
		idmapdlog(LOG_ERR, "scf_handle_bind() failed: %s",
		    scf_strerror(scf_error()));
		goto error;
	}

	if (!(handles->service = scf_service_create(handles->main)) ||
	    !(handles->instance = scf_instance_create(handles->main)) ||
	    !(handles->config_pg = scf_pg_create(handles->main)) ||
	    !(handles->general_pg = scf_pg_create(handles->main))) {
		idmapdlog(LOG_ERR, "scf handle creation failed: %s",
		    scf_strerror(scf_error()));
		goto error;
	}

	if (scf_handle_decode_fmri(handles->main,
	    FMRI_BASE "/:properties/" CONFIG_PG,
	    NULL,				/* scope */
	    handles->service,		/* service */
	    handles->instance,		/* instance */
	    handles->config_pg,		/* pg */
	    NULL,				/* prop */
	    SCF_DECODE_FMRI_EXACT) < 0) {
		idmapdlog(LOG_ERR, "scf_handle_decode_fmri() failed: %s",
		    scf_strerror(scf_error()));
		goto error;
	}

	if (scf_service_get_pg(handles->service,
	    GENERAL_PG, handles->general_pg) < 0) {
		idmapdlog(LOG_ERR, "scf_service_get_pg() failed: %s",
		    scf_strerror(scf_error()));
		goto error;
	}

	/* Initialize AD Auto Discovery context */
	handles->ad_ctx = ad_disc_init();
	if (handles->ad_ctx == NULL)
		goto error;

	return (cfg);

error:
	(void) idmap_cfg_fini(cfg);
	return (NULL);
}

void
idmap_cfg_unload(idmap_pg_config_t *pgcfg)
{

	if (pgcfg->default_domain) {
		free(pgcfg->default_domain);
		pgcfg->default_domain = NULL;
	}
	if (pgcfg->domain_name) {
		free(pgcfg->domain_name);
		pgcfg->domain_name = NULL;
	}
	if (pgcfg->machine_sid) {
		free(pgcfg->machine_sid);
		pgcfg->machine_sid = NULL;
	}
	if (pgcfg->domain_controller) {
		free(pgcfg->domain_controller);
		pgcfg->domain_controller = NULL;
	}
	if (pgcfg->forest_name) {
		free(pgcfg->forest_name);
		pgcfg->forest_name = NULL;
	}
	if (pgcfg->site_name) {
		free(pgcfg->site_name);
		pgcfg->site_name = NULL;
	}
	if (pgcfg->global_catalog) {
		free(pgcfg->global_catalog);
		pgcfg->global_catalog = NULL;
	}
	if (pgcfg->ad_unixuser_attr) {
		free(pgcfg->ad_unixuser_attr);
		pgcfg->ad_unixuser_attr = NULL;
	}
	if (pgcfg->ad_unixgroup_attr) {
		free(pgcfg->ad_unixgroup_attr);
		pgcfg->ad_unixgroup_attr = NULL;
	}
	if (pgcfg->nldap_winname_attr) {
		free(pgcfg->nldap_winname_attr);
		pgcfg->nldap_winname_attr = NULL;
	}
}

int
idmap_cfg_fini(idmap_cfg_t *cfg)
{
	idmap_cfg_handles_t *handles = &cfg->handles;
	idmap_cfg_unload(&cfg->pgcfg);

	(void) pthread_mutex_destroy(&handles->mutex);
	scf_pg_destroy(handles->config_pg);
	scf_pg_destroy(handles->general_pg);
	scf_instance_destroy(handles->instance);
	scf_service_destroy(handles->service);
	scf_handle_destroy(handles->main);
	if (handles->ad_ctx != NULL)
		ad_disc_fini(handles->ad_ctx);
	free(cfg);

	return (0);
}

void
idmap_cfg_poke_updates(void)
{
	if (idmapd_ev_port != -1)
		(void) port_send(idmapd_ev_port, POKE_AUTO_DISCOVERY, NULL);
}

/*ARGSUSED*/
void
idmap_cfg_hup_handler(int sig)
{
	if (idmapd_ev_port >= 0)
		(void) port_send(idmapd_ev_port, RECONFIGURE, NULL);
}
