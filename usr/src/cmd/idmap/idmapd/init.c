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
 * Initialization routines
 */

#include "idmapd.h"
#include <signal.h>
#include <thread.h>
#include <string.h>
#include <errno.h>
#include <assert.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <rpcsvc/daemon_utils.h>


int
init_mapping_system()
{
	int rc = 0;

	if (rwlock_init(&_idmapdstate.rwlk_cfg, USYNC_THREAD, NULL) != 0)
		return (-1);
	if ((rc = load_config()) < 0)
		return (rc);

	(void) setegid(DAEMON_GID);
	(void) seteuid(DAEMON_UID);
	if (init_dbs() < 0) {
		rc = -1;
		fini_mapping_system();
	}
	(void) seteuid(0);
	(void) setegid(0);

	return (rc);
}

void
fini_mapping_system()
{
	fini_dbs();
}

int
load_config()
{
	int rc;
	idmap_pg_config_t *pgcfg;
	if ((_idmapdstate.cfg = idmap_cfg_init()) == NULL) {
		degrade_svc("failed to initialize config");
		return (-1);
	}
	pgcfg = &_idmapdstate.cfg->pgcfg;

	rc = idmap_cfg_load(&_idmapdstate.cfg->handles,
	    &_idmapdstate.cfg->pgcfg, 0);
	if (rc < -1) {
		/* Total failure */
		degrade_svc("fatal error while loading configuration");
		return (rc);
	}

	if (rc != 0)
		/* Partial failure */
		idmapdlog(LOG_ERR, "Various errors occurred while loading "
		    "the configuration; check the logs");

	if (pgcfg->global_catalog == NULL ||
	    pgcfg->global_catalog[0].host[0] == '\0') {
		degrade_svc(
		    "global catalog server is not configured; AD lookup "
		    "will fail until one or more global catalog server names "
		    "are configured or discovered; auto-discovery will begin "
		    "shortly");
	} else {
		restore_svc();
	}

	(void) reload_ad();

	if ((rc = idmap_cfg_start_updates()) < 0) {
		/* Total failure */
		degrade_svc("could not start config updater");
		return (rc);
	}

	idmapdlog(LOG_DEBUG, "Initial configuration loaded");

	return (0);
}


int
reload_ad()
{
	int	i;
	ad_t	*old;
	ad_t	*new;

	idmap_pg_config_t *pgcfg = &_idmapdstate.cfg->pgcfg;

	if (pgcfg->default_domain == NULL ||
	    pgcfg->global_catalog == NULL) {
		if (_idmapdstate.ad == NULL)
			idmapdlog(LOG_ERR, "AD lookup disabled");
		else
			idmapdlog(LOG_ERR, "cannot update AD context");
		return (-1);
	}

	old = _idmapdstate.ad;

	if (idmap_ad_alloc(&new, pgcfg->default_domain,
	    IDMAP_AD_GLOBAL_CATALOG) != 0) {
		degrade_svc("could not initialize AD context");
		return (-1);
	}

	for (i = 0; pgcfg->global_catalog[i].host[0] != '\0'; i++) {
		if (idmap_add_ds(new,
		    pgcfg->global_catalog[i].host,
		    pgcfg->global_catalog[i].port) != 0) {
			idmap_ad_free(&new);
			degrade_svc("could not initialize AD GC context");
			return (-1);
		}
	}

	_idmapdstate.ad = new;

	if (old != NULL)
		idmap_ad_free(&old);

	return (0);
}


void
print_idmapdstate()
{
	int i;
	idmap_pg_config_t *pgcfg;

	RDLOCK_CONFIG();

	if (_idmapdstate.cfg == NULL) {
		idmapdlog(LOG_INFO, "Null configuration");
		UNLOCK_CONFIG();
		return;
	}

	pgcfg = &_idmapdstate.cfg->pgcfg;

	idmapdlog(LOG_DEBUG, "list_size_limit=%llu", pgcfg->list_size_limit);
	idmapdlog(LOG_DEBUG, "default_domain=%s",
	    CHECK_NULL(pgcfg->default_domain));
	idmapdlog(LOG_DEBUG, "domain_name=%s", CHECK_NULL(pgcfg->domain_name));
	idmapdlog(LOG_DEBUG, "machine_sid=%s", CHECK_NULL(pgcfg->machine_sid));
	if (pgcfg->domain_controller == NULL ||
	    pgcfg->domain_controller[0].host[0] == '\0') {
		idmapdlog(LOG_DEBUG, "No domain controllers known");
	} else {
		for (i = 0; pgcfg->domain_controller[i].host[0] != '\0'; i++)
			idmapdlog(LOG_DEBUG, "domain_controller=%s port=%d",
			    pgcfg->domain_controller[i].host,
			    pgcfg->domain_controller[i].port);
	}
	idmapdlog(LOG_DEBUG, "forest_name=%s", CHECK_NULL(pgcfg->forest_name));
	idmapdlog(LOG_DEBUG, "site_name=%s", CHECK_NULL(pgcfg->site_name));
	if (pgcfg->global_catalog == NULL ||
	    pgcfg->global_catalog[0].host[0] == '\0') {
		idmapdlog(LOG_DEBUG, "No global catalog servers known");
	} else {
		for (i = 0; pgcfg->global_catalog[i].host[0] != '\0'; i++)
			idmapdlog(LOG_DEBUG, "global_catalog=%s port=%d",
			    pgcfg->global_catalog[i].host,
			    pgcfg->global_catalog[i].port);
	}
	idmapdlog(LOG_DEBUG, "ds_name_mapping_enabled=%s",
	    (pgcfg->ds_name_mapping_enabled == TRUE) ? "true" : "false");
	idmapdlog(LOG_DEBUG, "ad_unixuser_attr=%s",
	    CHECK_NULL(pgcfg->ad_unixuser_attr));
	idmapdlog(LOG_DEBUG, "ad_unixgroup_attr=%s",
	    CHECK_NULL(pgcfg->ad_unixgroup_attr));
	idmapdlog(LOG_DEBUG, "nldap_winname_attr=%s",
	    CHECK_NULL(pgcfg->nldap_winname_attr));

	UNLOCK_CONFIG();
}

int
create_directory(const char *path, uid_t uid, gid_t gid)
{
	int	rc;

	if ((rc = mkdir(path, 0700)) < 0 && errno != EEXIST) {
		idmapdlog(LOG_ERR, "Error creating directory %s (%s)",
		    path, strerror(errno));
		return (-1);
	}

	if (lchown(path, uid, gid) < 0) {
		idmapdlog(LOG_ERR, "Error creating directory %s (%s)",
		    path, strerror(errno));
		if (rc == 0)
			(void) rmdir(path);
		return (-1);
	}
	return (0);
}
