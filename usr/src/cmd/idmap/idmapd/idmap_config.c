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
#include <synch.h>
#include <assert.h>
#include <sys/varargs.h>
#include <sys/systeminfo.h>
#include <strings.h>
#include <libintl.h>
#include <ctype.h>
#include <errno.h>
#include "idmapd.h"
#include <stdio.h>
#include <stdarg.h>
#include <uuid/uuid.h>

#define	MACHINE_SID_LEN	(9 + UUID_LEN/4 * 11)
#define	FMRI_BASE "svc:/system/idmap"
#define	CONFIG_PG "config"
#define	GENERAL_PG "general"
/* initial length of the array for policy options/attributes: */
#define	DEF_ARRAY_LENGTH 16

static const char *me = "idmapd";

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
get_val_int(idmap_cfg_t *cfg, char *name, void *val, scf_type_t type)
{
	int rc = 0;

	scf_property_t *scf_prop = scf_property_create(cfg->handles.main);
	scf_value_t *value = scf_value_create(cfg->handles.main);


	if (0 > scf_pg_get_property(cfg->handles.config_pg, name, scf_prop))
	/* this is OK: the property is just undefined */
		goto destruction;


	if (0 > scf_property_get_value(scf_prop, value))
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
get_val_astring(idmap_cfg_t *cfg, char *name, char **val)
{
	int rc = 0;

	scf_property_t *scf_prop = scf_property_create(cfg->handles.main);
	scf_value_t *value = scf_value_create(cfg->handles.main);


	if (0 > scf_pg_get_property(cfg->handles.config_pg, name, scf_prop))
	/* this is OK: the property is just undefined */
		goto destruction;

	if (0 > scf_property_get_value(scf_prop, value)) {
		idmapdlog(LOG_ERR,
		    "%s: scf_property_get_value(%s) failed: %s",
		    me, name, scf_strerror(scf_error()));
		rc = -1;
		goto destruction;
	}

	if (!(*val = scf_value2string(value))) {
		rc = -1;
		idmapdlog(LOG_ERR,
		    "%s: scf_value2string(%s) failed: %s",
		    me, name, scf_strerror(scf_error()));
	}

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
set_val_astring(idmap_cfg_t *cfg, char *name, const char *val)
{
	int			rc = 0, i;
	scf_property_t		*scf_prop = NULL;
	scf_value_t		*value = NULL;
	scf_transaction_t	*tx = NULL;
	scf_transaction_entry_t	*ent = NULL;

	if ((scf_prop = scf_property_create(cfg->handles.main)) == NULL ||
	    (value = scf_value_create(cfg->handles.main)) == NULL ||
	    (tx = scf_transaction_create(cfg->handles.main)) == NULL ||
	    (ent = scf_entry_create(cfg->handles.main)) == NULL) {
		idmapdlog(LOG_ERR, "%s: Unable to set property %s: %s",
		    me, name, scf_strerror(scf_error()));
		rc = -1;
		goto destruction;
	}

	for (i = 0; i < MAX_TRIES && rc == 0; i++) {
		if (scf_transaction_start(tx, cfg->handles.config_pg) == -1) {
			idmapdlog(LOG_ERR,
			    "%s: scf_transaction_start(%s) failed: %s",
			    me, name, scf_strerror(scf_error()));
			rc = -1;
			goto destruction;
		}

		rc = scf_transaction_property_new(tx, ent, name,
		    SCF_TYPE_ASTRING);
		if (rc == -1) {
			idmapdlog(LOG_ERR,
			    "%s: scf_transaction_property_new() failed: %s",
			    me, scf_strerror(scf_error()));
			goto destruction;
		}

		if (scf_value_set_astring(value, val) == -1) {
			idmapdlog(LOG_ERR,
			    "%s: scf_value_set_astring() failed: %s",
			    me, scf_strerror(scf_error()));
			rc = -1;
			goto destruction;
		}

		if (scf_entry_add_value(ent, value) == -1) {
			idmapdlog(LOG_ERR,
			    "%s: scf_entry_add_value() failed: %s",
			    me, scf_strerror(scf_error()));
			rc = -1;
			goto destruction;
		}

		rc = scf_transaction_commit(tx);
		if (rc == 0 && i < MAX_TRIES - 1) {
			/*
			 * Property group set in scf_transaction_start()
			 * is not the most recent. Update pg, reset tx and
			 * retry tx.
			 */
			idmapdlog(LOG_WARNING,
			    "%s: scf_transaction_commit(%s) failed - Retry: %s",
			    me, name, scf_strerror(scf_error()));
			if (scf_pg_update(cfg->handles.config_pg) == -1) {
				idmapdlog(LOG_ERR,
				    "%s: scf_pg_update() failed: %s",
				    me, scf_strerror(scf_error()));
				rc = -1;
				goto destruction;
			}
			scf_transaction_reset(tx);
		}
	}

	/* Log failure message if all retries failed */
	if (rc == 0) {
		idmapdlog(LOG_ERR,
		    "%s: scf_transaction_commit(%s) failed: %s",
		    me, name, scf_strerror(scf_error()));
		rc = -1;
	}

destruction:
	scf_value_destroy(value);
	scf_entry_destroy(ent);
	scf_transaction_destroy(tx);
	scf_property_destroy(scf_prop);
	return (rc);
}

int
idmap_cfg_load(idmap_cfg_t *cfg)
{
	int rc = 0;

	cfg->pgcfg.list_size_limit = 0;
	cfg->pgcfg.mapping_domain = NULL;
	cfg->pgcfg.machine_sid = NULL;
	cfg->pgcfg.domain_controller = NULL;
	cfg->pgcfg.global_catalog = NULL;

	if (0 > scf_pg_update(cfg->handles.config_pg)) {
		idmapdlog(LOG_ERR, "%s: scf_pg_update() failed: %s",
		    me, scf_strerror(scf_error()));
		return (-1);
	}

	if (0 > scf_pg_update(cfg->handles.general_pg)) {
		idmapdlog(LOG_ERR, "%s: scf_pg_update() failed: %s",
		    me, scf_strerror(scf_error()));
		return (-1);
	}

	rc = get_val_int(cfg, "list_size_limit",
	    &cfg->pgcfg.list_size_limit, SCF_TYPE_COUNT);
	if (rc != 0)
		return (-1);

	rc = get_val_astring(cfg, "mapping_domain",
	    &cfg->pgcfg.mapping_domain);
	if (rc != 0)
		return (-1);

	/*
	 * If there is no mapping_domain in idmap's smf config then
	 * set it to the joined domain.
	 * Till domain join is implemented, temporarily set it to
	 * the system domain for testing purposes.
	 */
	if (!cfg->pgcfg.mapping_domain) 	{
		char test[1];
		long dname_size = sysinfo(SI_SRPC_DOMAIN, test, 1);
		if (dname_size > 0) {
			cfg->pgcfg.mapping_domain =
			    (char *)malloc(dname_size * sizeof (char));
			dname_size = sysinfo(SI_SRPC_DOMAIN,
			    cfg->pgcfg.mapping_domain, dname_size);
		}
		if (dname_size <= 0) {
			idmapdlog(LOG_ERR,
			    "%s: unable to get name service domain", me);
			if (cfg->pgcfg.mapping_domain)
				free(cfg->pgcfg.mapping_domain);
			cfg->pgcfg.mapping_domain = NULL;
		}
	}

	rc = get_val_astring(cfg, "machine_sid", &cfg->pgcfg.machine_sid);
	if (rc != 0)
		return (-1);
	if (cfg->pgcfg.machine_sid == NULL) {
		/* If machine_sid not configured, generate one */
		if (generate_machine_sid(&cfg->pgcfg.machine_sid) < 0)
			return (-1);
		rc = set_val_astring(cfg, "machine_sid",
		    cfg->pgcfg.machine_sid);
		if (rc < 0) {
			free(cfg->pgcfg.machine_sid);
			cfg->pgcfg.machine_sid = NULL;
			return (-1);
		}
	}

	rc = get_val_astring(cfg, "global_catalog", &cfg->pgcfg.global_catalog);
	if (rc != 0)
		return (-1);

	rc = get_val_astring(cfg, "domain_controller",
	    &cfg->pgcfg.domain_controller);
	if (rc != 0)
		return (-1);

	return (rc);
}

/*
 * Initialize 'cfg'.
 */
idmap_cfg_t *
idmap_cfg_init() {

	/* First the smf repository handles: */
	idmap_cfg_t *cfg = calloc(1, sizeof (idmap_cfg_t));
	if (!cfg) {
		idmapdlog(LOG_ERR, "%s: Out of memory", me);
		return (NULL);
	}

	if (!(cfg->handles.main = scf_handle_create(SCF_VERSION))) {
		idmapdlog(LOG_ERR, "%s: scf_handle_create() failed: %s",
		    me, scf_strerror(scf_error()));
		goto error;
	}

	if (0 > scf_handle_bind(cfg->handles.main)) {
		idmapdlog(LOG_ERR, "%s: scf_handle_bind() failed: %s",
		    me, scf_strerror(scf_error()));
		goto error;
	}

	if (!(cfg->handles.service = scf_service_create(cfg->handles.main)) ||
	    !(cfg->handles.instance = scf_instance_create(cfg->handles.main)) ||
	    !(cfg->handles.config_pg = scf_pg_create(cfg->handles.main)) ||
	    !(cfg->handles.general_pg = scf_pg_create(cfg->handles.main))) {
		idmapdlog(LOG_ERR, "%s: scf handle creation failed: %s",
		    me, scf_strerror(scf_error()));
		goto error;
	}

	if (0 > scf_handle_decode_fmri(cfg->handles.main,
		FMRI_BASE "/:properties/" CONFIG_PG,
		NULL,				/* scope */
		cfg->handles.service,		/* service */
		cfg->handles.instance,		/* instance */
		cfg->handles.config_pg,		/* pg */
		NULL,				/* prop */
		SCF_DECODE_FMRI_EXACT)) {
		idmapdlog(LOG_ERR, "%s: scf_handle_decode_fmri() failed: %s",
		    me, scf_strerror(scf_error()));
		goto error;

	}

	if (0 > scf_service_get_pg(cfg->handles.service,
		GENERAL_PG, cfg->handles.general_pg)) {
		idmapdlog(LOG_ERR, "%s: scf_service_get_pg() failed: %s",
		    me, scf_strerror(scf_error()));
		goto error;
	}

	return (cfg);

error:
	(void) idmap_cfg_fini(cfg);
	return (NULL);
}

/* ARGSUSED */
static void
idmap_pgcfg_fini(idmap_pg_config_t *pgcfg) {
	if (pgcfg->mapping_domain)
		free(pgcfg->mapping_domain);
	if (pgcfg->machine_sid)
		free(pgcfg->mapping_domain);
	if (pgcfg->global_catalog)
		free(pgcfg->global_catalog);
	if (pgcfg->domain_controller)
		free(pgcfg->domain_controller);
}

int
idmap_cfg_fini(idmap_cfg_t *cfg)
{
	idmap_pgcfg_fini(&cfg->pgcfg);

	scf_pg_destroy(cfg->handles.config_pg);
	scf_pg_destroy(cfg->handles.general_pg);
	scf_instance_destroy(cfg->handles.instance);
	scf_service_destroy(cfg->handles.service);
	scf_handle_destroy(cfg->handles.main);
	free(cfg);

	return (0);
}
