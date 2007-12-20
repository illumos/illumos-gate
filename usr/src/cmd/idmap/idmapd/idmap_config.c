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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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
#include "addisc.h"

#define	MACHINE_SID_LEN	(9 + UUID_LEN/4 * 11)
#define	FMRI_BASE "svc:/system/idmap"
#define	CONFIG_PG "config"
#define	GENERAL_PG "general"
/* initial length of the array for policy options/attributes: */
#define	DEF_ARRAY_LENGTH 16

/*LINTLIBRARY*/


static const char *me = "idmapd";


static pthread_t update_thread_handle = 0;

int hup_ev_port = -1;
extern int hupped;

static int
generate_machine_sid(char **machine_sid) {
	char *p;
	uuid_t uu;
	int i, j, len, rlen;
	uint32_t rid;

	/*
	 * Generate and split 128-bit UUID into four 32-bit RIDs
	 * The machine_sid will be of the form S-1-5-N1-N2-N3-N4
	 * We depart from Windows here, which instead of 128
	 * bits worth of random numbers uses 96 bits.
	 */

	*machine_sid = calloc(1, MACHINE_SID_LEN);
	if (*machine_sid == NULL) {
		idmapdlog(LOG_ERR, "%s: Out of memory", me);
		return (-1);
	}
	(void) strcpy(*machine_sid, "S-1-5-21");
	p = *machine_sid + strlen("S-1-5-21");
	len = MACHINE_SID_LEN - strlen("S-1-5-21");

	uuid_clear(uu);
	uuid_generate_random(uu);

	for (i = 0; i < UUID_LEN/4; i++) {
		j = i * 4;
		rid = (uu[j] << 24) | (uu[j + 1] << 16) |
			(uu[j + 2] << 8) | (uu[j + 3]);
		rlen = snprintf(p, len, "-%u", rid);
		p += rlen;
		len -= rlen;
	}

	return (0);
}

/* Check if in the case of failure the original value of *val is preserved */
static int
get_val_int(idmap_cfg_handles_t *handles, char *name,
	void *val, scf_type_t type)
{
	int rc = 0;

	scf_property_t *scf_prop = scf_property_create(handles->main);
	scf_value_t *value = scf_value_create(handles->main);

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
	default:
		idmapdlog(LOG_ERR, "%s: Invalid scf integer type (%d)",
		    me, type);
		rc = -1;
		break;
	}


destruction:
	scf_value_destroy(value);
	scf_property_destroy(scf_prop);

	return (rc);
}

static char *
scf_value2string(scf_value_t *value) {
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
				idmapdlog(LOG_ERR, "%s: Out of memory", me);
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
		ad_disc_ds_t **val)
{
	ad_disc_ds_t *servers = NULL;
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
	value = scf_value_create(handles->main);
	iter = scf_iter_create(handles->main);

	if (scf_pg_get_property(handles->config_pg, name, scf_prop) < 0) {
		/* this is OK: the property is just undefined */
		rc = 0;
		goto destruction;
	}

	if (scf_iter_property_values(iter, scf_prop) < 0) {
		idmapdlog(LOG_ERR,
		    "%s: scf_iter_property_values(%s) failed: %s",
		    me, name, scf_strerror(scf_error()));
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
		idmapdlog(LOG_ERR, "%s: Out of memory", me);
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

	scf_property_t *scf_prop = scf_property_create(handles->main);
	scf_value_t *value = scf_value_create(handles->main);

	*val = NULL;

	if (scf_pg_get_property(handles->config_pg, name, scf_prop) < 0)
	/* this is OK: the property is just undefined */
		goto destruction;

	if (scf_property_get_value(scf_prop, value) < 0) {
		idmapdlog(LOG_ERR,
		    "%s: scf_property_get_value(%s) failed: %s",
		    me, name, scf_strerror(scf_error()));
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
		idmapdlog(LOG_ERR, "%s: Unable to set property %s: %s",
		    me, name, scf_strerror(scf_error()));
		goto destruction;
	}

	for (i = 0; i < MAX_TRIES && (ret == -2 || ret == 0); i++) {
		if (scf_transaction_start(tx, handles->config_pg) == -1) {
			idmapdlog(LOG_ERR,
			    "%s: scf_transaction_start(%s) failed: %s",
			    me, name, scf_strerror(scf_error()));
			goto destruction;
		}

		if (scf_transaction_property_new(tx, ent, name,
		    SCF_TYPE_ASTRING) < 0) {
			idmapdlog(LOG_ERR,
			    "%s: scf_transaction_property_new() failed: %s",
			    me, scf_strerror(scf_error()));
			goto destruction;
		}

		if (scf_value_set_astring(value, val) == -1) {
			idmapdlog(LOG_ERR,
			    "%s: scf_value_set_astring() failed: %s",
			    me, scf_strerror(scf_error()));
			goto destruction;
		}

		if (scf_entry_add_value(ent, value) == -1) {
			idmapdlog(LOG_ERR,
			    "%s: scf_entry_add_value() failed: %s",
			    me, scf_strerror(scf_error()));
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
			    "%s: scf_transaction_commit(%s) failed - Retry: %s",
			    me, name, scf_strerror(scf_error()));
			if (scf_pg_update(handles->config_pg) == -1) {
				idmapdlog(LOG_ERR,
				    "%s: scf_pg_update() failed: %s",
				    me, scf_strerror(scf_error()));
				goto destruction;
			}
			scf_transaction_reset(tx);
		}
	}


	if (ret == 1)
		rc = 0;
	else if (ret != -2)
		idmapdlog(LOG_ERR,
		    "%s: scf_transaction_commit(%s) failed: %s",
		    me, name, scf_strerror(scf_error()));

destruction:
	scf_value_destroy(value);
	scf_entry_destroy(ent);
	scf_transaction_destroy(tx);
	scf_property_destroy(scf_prop);
	return (rc);
}

static int
update_value(char **value, char **new, char *name)
{
	if (*new == NULL)
		return (FALSE);

	if (*value != NULL && strcmp(*new, *value) == 0) {
		free(*new);
		*new = NULL;
		return (FALSE);
	}

	idmapdlog(LOG_INFO, "%s: change %s=%s", me, name, CHECK_NULL(*new));
	if (*value != NULL)
		free(*value);
	*value = *new;
	*new = NULL;
	return (TRUE);
}

static int
update_dirs(ad_disc_ds_t **value, ad_disc_ds_t **new, char *name)
{
	int i;

	if (*new == NULL)
		return (FALSE);

	if (*value != NULL && ad_disc_compare_ds(*value, *new) == 0) {
		free(*new);
		*new = NULL;
		return (FALSE);
	}

	if (*value)
		free(*value);

	for (i = 0; (*new)[i].host[0] != '\0'; i++)
		idmapdlog(LOG_INFO, "%s: change %s=%s port=%d", me, name,
		    (*new)[i].host, (*new)[i].port);
	*value = *new;
	*new = NULL;
	return (TRUE);
}


#define	SUBNET_CHECK_TIME	(2 * 60)
#define	MAX_CHECK_TIME		(10 * 60)

/*
 * Returns 1 if SIGHUP has been received (see hup_handler elsewhere), 0
 * otherwise.  Uses an event port and a user-defined event.
 *
 * Note that port_get() does not update its timeout argument when EINTR,
 * unlike nanosleep().  We probably don't care very much here because
 * the only signals we expect are ones that will lead to idmapd dying or
 * SIGHUP, and we intend for the latter to cause this function to
 * return.  But if we did care then we could always use a timer event
 * (see timer_create(3RT)) and associate it with the same event port,
 * then we could get accurate waiting regardless of EINTRs.
 */
static
int
wait_for_ttl(struct timespec *timeout)
{
	port_event_t pe;
	int retries = 1;

	/*
	 * If event port creation failed earlier and fails now then we
	 * simply don't learn about SIGHUPs in a timely fashion.  No big
	 * deal
	 */
	if (hup_ev_port == -1 && (hup_ev_port = port_create()) < 0) {
		(void) nanosleep(timeout, NULL);
		return (0);
	}

retry:
	if (port_get(hup_ev_port, &pe, timeout) != 0) {
		switch (errno) {
		case EBADF:
		case EBADFD:
			hup_ev_port = -1;
			(void) nanosleep(timeout, NULL);
			break;
		case EINVAL:
			/*
			 * Shouldn't happen, except, perhaps, near the
			 * end of time
			 */
			timeout->tv_nsec = 0;
			timeout->tv_sec = MAX_CHECK_TIME;
			if (retries-- > 0)
				goto retry;
			/* NOTREACHED */
			break;
		case EINTR:
			if (!hupped)
				goto retry;
			break;
		case ETIME:
			/* Timeout */
			break;
		default:
			/* EFAULT */
			(void) nanosleep(timeout, NULL);
			break;
		}
	}

	/*
	 * We only have one event that we care about, a user event, so
	 * there's nothing to check or clean up about pe.
	 *
	 * If we get here it's either because we had a SIGHUP and a user
	 * event was sent to our port, or because the port_get() timed
	 * out (or even both!).
	 */

	if (hupped) {
		int rc;

		hupped = 0;
		/*
		 * Blow away the ccache, we might have re-joined the
		 * domain or joined a new one
		 */
		(void) unlink(IDMAP_CACHEDIR "/ccache");
		/* HUP is the refresh method, so re-read SMF config */
		(void) idmapdlog(LOG_INFO, "idmapd: SMF refresh");
		WRLOCK_CONFIG();
		(void) idmap_cfg_unload(&_idmapdstate.cfg->pgcfg);
		rc = idmap_cfg_load(&_idmapdstate.cfg->handles,
		    &_idmapdstate.cfg->pgcfg, 1);
		if (rc < -1)
			(void) idmapdlog(LOG_ERR,
			    "idmapd: Various errors re-loading configuration "
			    "will cause AD lookups to fail");
		else if (rc == -1)
			(void) idmapdlog(LOG_WARNING,
			    "idmapd: Various errors re-loading configuration "
			    "may cause AD lookups to fail");
		UNLOCK_CONFIG();
		return (1);
	}

	return (0);
}

void *
idmap_cfg_update_thread(void *arg)
{

	idmap_pg_config_t	new_cfg;
	int			ttl, changed;
	idmap_cfg_handles_t	*handles = &_idmapdstate.cfg->handles;
	idmap_pg_config_t	*live_cfg = &_idmapdstate.cfg->pgcfg;
	ad_disc_t		ad_ctx = handles->ad_ctx;
	struct timespec		delay;
	int			first = 1;

	(void) memset(&new_cfg, 0, sizeof (new_cfg));

	for (;;) {
		changed = FALSE;

		if (first) {
			ttl = 1;
			first = 0;
		} else {
			ttl = ad_disc_get_TTL(ad_ctx);
		}

		if (ttl > MAX_CHECK_TIME)
			ttl = MAX_CHECK_TIME;
		while (ttl > 0 || ttl == -1) {
			if (ttl == -1) {
				wait_for_ttl(NULL);
			} else if (ttl > SUBNET_CHECK_TIME) {
				/*
				 * We really ought to just monitor
				 * network interfaces with a PF_ROUTE
				 * socket...  This crude method of
				 * discovering subnet changes will do
				 * for now.  Though might even not want
				 * to bother: subnet changes leading to
				 * sitename changes ought never happen,
				 * and requiring a refresh when they do
				 * should be no problem (SMF/NWAM ought
				 * to be able to refresh us).
				 */
				delay.tv_sec = SUBNET_CHECK_TIME;
				delay.tv_nsec = 0;
				if (wait_for_ttl(&delay)) {
					/* Got SIGHUP, re-discover */
					ttl = 0;
					changed = TRUE;
					break;
				}
				ttl -= SUBNET_CHECK_TIME;
				if (ad_disc_SubnetChanged(ad_ctx))
					break;
			} else {
				delay.tv_sec = ttl;
				delay.tv_nsec = 0;
				if (wait_for_ttl(&delay))
					changed = TRUE;
				ttl = 0;
			}
		}

		/*
		 * Load configuration data into a private copy.
		 *
		 * The fixed values (i.e., from SMF) have already been
		 * set in AD auto discovery, so if all values have been
		 * set in SMF and they haven't been changed or the
		 * service been refreshed then the rest of this loop's
		 * body is one big no-op.
		 */
		pthread_mutex_lock(&handles->mutex);

		new_cfg.default_domain = ad_disc_get_DomainName(ad_ctx);
		if (new_cfg.default_domain == NULL) {
			idmapdlog(LOG_INFO,
			    "%s: unable to discover Default Domain", me);
		}

		new_cfg.domain_name = ad_disc_get_DomainName(ad_ctx);
		if (new_cfg.domain_name == NULL) {
			idmapdlog(LOG_INFO,
			    "%s: unable to discover Domain Name", me);
		}

		new_cfg.domain_controller =
		    ad_disc_get_DomainController(ad_ctx, AD_DISC_PREFER_SITE);
		if (new_cfg.domain_controller == NULL) {
			idmapdlog(LOG_INFO,
			    "%s: unable to discover Domain Controller", me);
		}

		new_cfg.forest_name = ad_disc_get_ForestName(ad_ctx);
		if (new_cfg.forest_name == NULL) {
			idmapdlog(LOG_INFO,
			    "%s: unable to discover Forest Name", me);
		}

		new_cfg.site_name = ad_disc_get_SiteName(ad_ctx);
		if (new_cfg.site_name == NULL) {
			idmapdlog(LOG_INFO,
			    "%s: unable to discover Site Name", me);
		}

		new_cfg.global_catalog =
		    ad_disc_get_GlobalCatalog(ad_ctx, AD_DISC_PREFER_SITE);
		if (new_cfg.global_catalog == NULL) {
			idmapdlog(LOG_INFO,
			    "%s: unable to discover Global Catalog", me);
		}

		pthread_mutex_unlock(&handles->mutex);

		if (new_cfg.default_domain == NULL &&
		    new_cfg.domain_name == NULL &&
		    new_cfg.domain_controller == NULL &&
		    new_cfg.forest_name == NULL &&
		    new_cfg.global_catalog == NULL) {
			idmapdlog(LOG_NOTICE, "%s: Could not auto-discover AD "
			    "domain and forest names nor domain controllers "
			    "and global catalog servers", me);
			idmap_cfg_unload(&new_cfg);
			continue;
		}

		/*
		 * Update the live configuration
		 */
		WRLOCK_CONFIG();

		if (live_cfg->list_size_limit != new_cfg.list_size_limit) {
			idmapdlog(LOG_INFO, "%s: change list_size=%d", me,
			    new_cfg.list_size_limit);
			live_cfg->list_size_limit = new_cfg.list_size_limit;
		}

		/*
		 * If default_domain came from SMF then we must not
		 * auto-discover it.
		 */
		if (live_cfg->dflt_dom_set_in_smf == FALSE &&
		    update_value(&live_cfg->default_domain,
		    &new_cfg.default_domain, "default_domain") == TRUE)
			changed = TRUE;

		(void) update_value(&live_cfg->domain_name,
		    &new_cfg.domain_name, "domain_name");

		(void) update_dirs(&live_cfg->domain_controller,
		    &new_cfg.domain_controller, "domain_controller");

		(void) update_value(&live_cfg->forest_name,
		    &new_cfg.forest_name, "forest_name");

		(void) update_value(&live_cfg->site_name,
		    &new_cfg.site_name, "site_name");

		if (update_dirs(&live_cfg->global_catalog,
		    &new_cfg.global_catalog, "global_catalog") == TRUE)
			changed = TRUE;
		UNLOCK_CONFIG();

		idmap_cfg_unload(&new_cfg);


		/*
		 * Re-create the ad_t/ad_host_t objects if
		 * either the default domain or the global
		 * catalog server list changed.
		 */

		if (changed) {
			RDLOCK_CONFIG();
			(void) reload_ad();
			UNLOCK_CONFIG();
			print_idmapdstate();
		}
	}
	/*NOTREACHED*/
	return (NULL);
}


int
idmap_cfg_start_updates(idmap_cfg_t *cfg)
{
	/* Don't check for failure -- see wait_for_ttl() */
	hup_ev_port = port_create();

	errno = pthread_create(&update_thread_handle, NULL,
	    idmap_cfg_update_thread, NULL);
	if (errno == 0)
		return (0);
	else
		return (-1);
}


int
idmap_cfg_load(idmap_cfg_handles_t *handles, idmap_pg_config_t *pgcfg,
	int discover)
{
	int rc;
	int errors = 0;
	uint8_t bool_val;
	char *str = NULL;
	ad_disc_t ad_ctx = handles->ad_ctx;

	pgcfg->list_size_limit = 0;
	pgcfg->default_domain = NULL;
	pgcfg->domain_name = NULL;
	pgcfg->machine_sid = NULL;
	pgcfg->domain_controller = NULL;
	pgcfg->forest_name = NULL;
	pgcfg->site_name = NULL;
	pgcfg->global_catalog = NULL;
	pgcfg->ad_unixuser_attr = NULL;
	pgcfg->ad_unixgroup_attr = NULL;
	pgcfg->nldap_winname_attr = NULL;
	pgcfg->ds_name_mapping_enabled = FALSE;

	pthread_mutex_lock(&handles->mutex);

	ad_disc_refresh(handles->ad_ctx);

	if (scf_pg_update(handles->config_pg) < 0) {
		idmapdlog(LOG_ERR, "%s: scf_pg_update() failed: %s",
		    me, scf_strerror(scf_error()));
		rc = -2;
		goto exit;
	}

	if (scf_pg_update(handles->general_pg) < 0) {
		idmapdlog(LOG_ERR, "%s: scf_pg_update() failed: %s",
		    me, scf_strerror(scf_error()));
		rc = -2;
		goto exit;
	}

	rc = get_val_int(handles, "list_size_limit",
	    &pgcfg->list_size_limit, SCF_TYPE_COUNT);
	if (rc != 0) {
		pgcfg->list_size_limit = 0;
		errors++;
	}

	rc = get_val_astring(handles, "domain_name",
	    &pgcfg->domain_name);
	if (rc != 0)
		errors++;
	else
		(void) ad_disc_set_DomainName(ad_ctx, pgcfg->domain_name);

	rc = get_val_astring(handles, "default_domain",
	    &pgcfg->default_domain);
	if (rc != 0) {
		/*
		 * SCF failures fetching config/default_domain we treat
		 * as fatal as they may leave ID mapping rules that
		 * match unqualified winnames flapping in the wind.
		 */
		rc = -2;
		goto exit;
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
				    "%s: Ignoring obsolete, undocumented "
				    "config/mapping_domain property", me);
			}
		} else if (str != NULL) {
			pgcfg->default_domain = strdup(str);
			pgcfg->dflt_dom_set_in_smf = TRUE;
			idmapdlog(LOG_WARNING,
			    "%s: The config/mapping_domain property is "
			    "obsolete; support for it will be removed, "
			    "please use config/default_domain instead",
			    me);
		}
	}

	if (str != NULL)
		free(str);

	rc = get_val_astring(handles, "machine_sid", &pgcfg->machine_sid);
	if (rc != 0)
		errors++;
	if (pgcfg->machine_sid == NULL) {
		/* If machine_sid not configured, generate one */
		if (generate_machine_sid(&pgcfg->machine_sid) < 0) {
			rc =  -2;
			goto exit;
		}
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
		(void) ad_disc_set_DomainController(ad_ctx,
		    pgcfg->domain_controller);

	rc = get_val_astring(handles, "forest_name", &pgcfg->forest_name);
	if (rc != 0)
		errors++;
	else
		(void) ad_disc_set_ForestName(ad_ctx, pgcfg->forest_name);

	rc = get_val_astring(handles, "site_name", &pgcfg->site_name);
	if (rc != 0)
		errors++;
	else
		(void) ad_disc_set_SiteName(ad_ctx, pgcfg->site_name);

	str = NULL;
	rc = get_val_ds(handles, "global_catalog", 3268,
	    &pgcfg->global_catalog);
	if (rc != 0)
		errors++;
	else
		(void) ad_disc_set_GlobalCatalog(ad_ctx, pgcfg->global_catalog);

	/*
	 * Read directory-based name mappings related SMF properties
	 */
	bool_val = 0;
	rc = get_val_int(handles, "ds_name_mapping_enabled",
	    &bool_val, SCF_TYPE_BOOLEAN);
	if (rc != 0) {
		rc = -2;
		goto exit;
	} else if (bool_val) {
		pgcfg->ds_name_mapping_enabled = TRUE;
		rc = get_val_astring(handles, "ad_unixuser_attr",
		    &pgcfg->ad_unixuser_attr);
		if (rc != 0) {
			rc = -2;
			goto exit;
		}

		rc = get_val_astring(handles, "ad_unixgroup_attr",
		    &pgcfg->ad_unixgroup_attr);
		if (rc != 0) {
			rc = -2;
			goto exit;
		}

		rc = get_val_astring(handles, "nldap_winname_attr",
		    &pgcfg->nldap_winname_attr);
		if (rc != 0) {
			rc = -2;
			goto exit;
		}

		if (pgcfg->nldap_winname_attr != NULL) {
			idmapdlog(LOG_ERR,
			    "%s: native LDAP based name mapping not supported "
			    "at this time. Please unset "
			    "config/nldap_winname_attr and restart idmapd.",
			    me);
			rc = -3;
			goto exit;
		}

		if (pgcfg->ad_unixuser_attr == NULL &&
		    pgcfg->ad_unixgroup_attr == NULL) {
			idmapdlog(LOG_ERR,
			    "%s: If config/ds_name_mapping_enabled property "
			    "is set to true then atleast one of the following "
			    "name mapping attributes must be specified. "
			    "(config/ad_unixuser_attr OR "
			    "config/ad_unixgroup_attr)", me);
			rc = -3;
			goto exit;
		}
	}


	if (!discover)
		goto exit;

	/*
	 * Auto Discover the rest
	 */
	if (pgcfg->default_domain == NULL) {
		pgcfg->default_domain = ad_disc_get_DomainName(ad_ctx);
		if (pgcfg->default_domain == NULL) {
			idmapdlog(LOG_INFO,
			    "%s: unable to discover Default Domain", me);
		}
	}

	if (pgcfg->domain_name == NULL) {
		pgcfg->domain_name = ad_disc_get_DomainName(ad_ctx);
		if (pgcfg->domain_name == NULL) {
			idmapdlog(LOG_INFO,
			    "%s: unable to discover Domain Name", me);
		}
	}

	if (pgcfg->domain_controller == NULL) {
		pgcfg->domain_controller =
		    ad_disc_get_DomainController(ad_ctx, AD_DISC_PREFER_SITE);
		if (pgcfg->domain_controller == NULL) {
			idmapdlog(LOG_INFO,
			    "%s: unable to discover Domain Controller", me);
		}
	}

	if (pgcfg->forest_name == NULL) {
		pgcfg->forest_name = ad_disc_get_ForestName(ad_ctx);
		if (pgcfg->forest_name == NULL) {
			idmapdlog(LOG_INFO,
			    "%s: unable to discover Forest Name", me);
		}
	}

	if (pgcfg->site_name == NULL) {
		pgcfg->site_name = ad_disc_get_SiteName(ad_ctx);
		if (pgcfg->site_name == NULL) {
			idmapdlog(LOG_INFO,
			    "%s: unable to discover Site Name", me);
		}
	}

	if (pgcfg->global_catalog == NULL) {
		pgcfg->global_catalog =
		    ad_disc_get_GlobalCatalog(ad_ctx, AD_DISC_PREFER_SITE);
		if (pgcfg->global_catalog == NULL) {
			idmapdlog(LOG_INFO,
			    "%s: unable to discover Global Catalog", me);
		}
	}

exit:
	pthread_mutex_unlock(&handles->mutex);

	if (rc < -1)
		return (rc);

	return ((errors == 0) ? 0 : -1);
}

/*
 * Initialize 'cfg'.
 */
idmap_cfg_t *
idmap_cfg_init() {
	idmap_cfg_handles_t *handles;

	/* First the smf repository handles: */
	idmap_cfg_t *cfg = calloc(1, sizeof (idmap_cfg_t));
	if (!cfg) {
		idmapdlog(LOG_ERR, "%s: Out of memory", me);
		return (NULL);
	}
	handles = &cfg->handles;

	(void) pthread_mutex_init(&handles->mutex, NULL);

	if (!(handles->main = scf_handle_create(SCF_VERSION))) {
		idmapdlog(LOG_ERR, "%s: scf_handle_create() failed: %s",
		    me, scf_strerror(scf_error()));
		goto error;
	}

	if (scf_handle_bind(handles->main) < 0) {
		idmapdlog(LOG_ERR, "%s: scf_handle_bind() failed: %s",
		    me, scf_strerror(scf_error()));
		goto error;
	}

	if (!(handles->service = scf_service_create(handles->main)) ||
	    !(handles->instance = scf_instance_create(handles->main)) ||
	    !(handles->config_pg = scf_pg_create(handles->main)) ||
	    !(handles->general_pg = scf_pg_create(handles->main))) {
		idmapdlog(LOG_ERR, "%s: scf handle creation failed: %s",
		    me, scf_strerror(scf_error()));
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
		idmapdlog(LOG_ERR, "%s: scf_handle_decode_fmri() failed: %s",
		    me, scf_strerror(scf_error()));
		goto error;

	}

	if (scf_service_get_pg(handles->service,
		GENERAL_PG, handles->general_pg) < 0) {
		idmapdlog(LOG_ERR, "%s: scf_service_get_pg() failed: %s",
		    me, scf_strerror(scf_error()));
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
idmap_cfg_unload(idmap_pg_config_t *pgcfg) {

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
