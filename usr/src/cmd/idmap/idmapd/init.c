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

static const char *me = "idmapd";

int
init_mapping_system() {
	int rc = 0;

	if (rwlock_init(&_idmapdstate.rwlk_cfg, USYNC_THREAD, NULL) != 0)
		return (-1);
	if (load_config() < 0)
		return (-1);

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
fini_mapping_system() {
	fini_dbs();
}

int
load_config() {
	int rc;
	idmap_pg_config_t *pgcfg;
	if ((_idmapdstate.cfg = idmap_cfg_init()) == NULL) {
		idmapdlog(LOG_ERR, "%s: failed to initialize config", me);
		degrade_svc();
		return (-1);
	}
	pgcfg = &_idmapdstate.cfg->pgcfg;

	rc = idmap_cfg_load(&_idmapdstate.cfg->handles,
	    &_idmapdstate.cfg->pgcfg, 0);
	if (rc < -1) {
		/* Total failure */
		degrade_svc();
		idmapdlog(LOG_ERR, "%s: Fatal error while loading "
		    "configuration", me);
		return (-1);
	}

	if (rc != 0)
		/* Partial failure */
		idmapdlog(LOG_ERR, "%s: Various errors occurred while loading "
			"the configuration; check the logs", me);

	if (pgcfg->global_catalog == NULL ||
	    pgcfg->global_catalog[0].host[0] == '\0') {
		degrade_svc();
		idmapdlog(LOG_INFO,
		    "%s: Global catalog server is not configured; AD lookup "
		    "will fail until one or more global catalog server names "
		    "are configured or discovered; auto-discovery will begin "
		    "shortly", me);
	} else {
		restore_svc();
	}

	(void) reload_ad();

	if (idmap_cfg_start_updates(_idmapdstate.cfg) < 0)
		idmapdlog(LOG_ERR, "%s: could not start config updater",
			me);

	idmapdlog(LOG_DEBUG, "%s: initial configuration loaded", me);

	return (0);
}


int
reload_ad() {
	int	i;
	ad_t	*old;
	ad_t	*new;

	idmap_pg_config_t *pgcfg = &_idmapdstate.cfg->pgcfg;

	if (pgcfg->default_domain == NULL ||
	    pgcfg->global_catalog == NULL) {
		if (_idmapdstate.ad == NULL)
			idmapdlog(LOG_ERR, "%s: AD lookup disabled", me);
		else
			idmapdlog(LOG_ERR, "%s: cannot update AD context", me);
		return (-1);
	}

	old = _idmapdstate.ad;

	if (idmap_ad_alloc(&new, pgcfg->default_domain,
	    IDMAP_AD_GLOBAL_CATALOG) != 0) {
		if (old == NULL)
			degrade_svc();
		idmapdlog(LOG_ERR, "%s: could not initialize AD context", me);
		return (-1);
	}

	for (i = 0; pgcfg->global_catalog[i].host[0] != '\0'; i++) {
		if (idmap_add_ds(new,
		    pgcfg->global_catalog[i].host,
		    pgcfg->global_catalog[i].port) != 0) {
			idmap_ad_free(&new);
			if (old == NULL)
				degrade_svc();
			idmapdlog(LOG_ERR,
			    "%s: could not initialize AD DS context", me);
			return (-1);
		}
	}

	_idmapdstate.ad = new;

	if (old != NULL)
		idmap_ad_free(&old);

	return (0);
}


void
print_idmapdstate() {
	int i;
	idmap_pg_config_t *pgcfg = &_idmapdstate.cfg->pgcfg;

	RDLOCK_CONFIG();

	if (_idmapdstate.cfg == NULL) {
		idmapdlog(LOG_INFO, "%s: Null configuration", me);
		UNLOCK_CONFIG();
		return;
	}

	idmapdlog(LOG_DEBUG, "%s: list_size_limit=%llu", me,
	    pgcfg->list_size_limit);
	idmapdlog(LOG_DEBUG, "%s: default_domain=%s", me,
	    CHECK_NULL(pgcfg->default_domain));
	idmapdlog(LOG_DEBUG, "%s: domain_name=%s", me,
	    CHECK_NULL(pgcfg->domain_name));
	idmapdlog(LOG_DEBUG, "%s: machine_sid=%s", me,
	    CHECK_NULL(pgcfg->machine_sid));
	if (pgcfg->domain_controller == NULL ||
	    pgcfg->domain_controller[0].host[0] == '\0') {
		idmapdlog(LOG_DEBUG, "%s: No domain controllers known", me);
	} else {
		for (i = 0; pgcfg->domain_controller[i].host[0] != '\0'; i++)
			idmapdlog(LOG_DEBUG, "%s: domain_controller=%s port=%d",
			    me, pgcfg->domain_controller[i].host,
			    pgcfg->domain_controller[i].port);
	}
	idmapdlog(LOG_DEBUG, "%s: forest_name=%s", me,
	    CHECK_NULL(pgcfg->forest_name));
	idmapdlog(LOG_DEBUG, "%s: site_name=%s", me,
	    CHECK_NULL(pgcfg->site_name));
	if (pgcfg->global_catalog == NULL ||
	    pgcfg->global_catalog[0].host[0] == '\0') {
		idmapdlog(LOG_DEBUG, "%s: No global catalog servers known", me);
	} else {
		for (i = 0; pgcfg->global_catalog[i].host[0] != '\0'; i++)
			idmapdlog(LOG_DEBUG, "%s: global_catalog=%s port=%d",
			    me,
			    pgcfg->global_catalog[i].host,
			    pgcfg->global_catalog[i].port);
	}

	UNLOCK_CONFIG();
}

int
create_directory(const char *path, uid_t uid, gid_t gid) {
	int	rc;

	if ((rc = mkdir(path, 0700)) < 0 && errno != EEXIST) {
		idmapdlog(LOG_ERR,
			"%s: Error creating directory %s (%s)",
			me, path, strerror(errno));
		return (-1);
	}

	if (lchown(path, uid, gid) < 0) {
		idmapdlog(LOG_ERR,
			"%s: Error creating directory %s (%s)",
			me, path, strerror(errno));
		if (rc == 0)
			(void) rmdir(path);
		return (-1);
	}
	return (0);
}
