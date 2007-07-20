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
	if ((_idmapdstate.cfg = idmap_cfg_init()) == NULL) {
		idmapdlog(LOG_ERR, "%s: failed to initialize config", me);
		return (-1);
	}
	if (_idmapdstate.ad != NULL)
		idmap_ad_free(&_idmapdstate.ad);
	if (idmap_cfg_load(_idmapdstate.cfg) < 0) {
		idmapdlog(LOG_ERR, "%s: failed to load config", me);
		return (-1);
	}
	if (_idmapdstate.cfg->pgcfg.mapping_domain == NULL ||
	    _idmapdstate.cfg->pgcfg.mapping_domain[0] == '\0') {
		idmapdlog(LOG_ERR, "%s: Joined AD domain not configured; name "
			"based and ephemeral mapping will not function", me);
	} else if (idmap_ad_alloc(&_idmapdstate.ad,
		    _idmapdstate.cfg->pgcfg.mapping_domain,
		    IDMAP_AD_GLOBAL_CATALOG) != 0) {
		idmapdlog(LOG_ERR, "%s: could not initialize AD context",
			me);
		return (-1);
	}
	if (_idmapdstate.cfg->pgcfg.global_catalog == NULL ||
	    _idmapdstate.cfg->pgcfg.global_catalog[0] == '\0') {
		idmapdlog(LOG_ERR, "%s: Global catalog DSnot configured; name "
			"based and ephemeral mapping will not function", me);
	} else if (idmap_add_ds(_idmapdstate.ad,
		    _idmapdstate.cfg->pgcfg.global_catalog, 0) != 0) {
		idmapdlog(LOG_ERR, "%s: could not initialize AD DS context",
			me);
		return (-1);
	}
	return (0);
}

void
print_idmapdstate() {
	RDLOCK_CONFIG();

	if (_idmapdstate.daemon_mode == FALSE) {
		(void) fprintf(stderr, "%s: daemon_mode=%s\n",
			me, _idmapdstate.daemon_mode == TRUE?"true":"false");
		(void) fprintf(stderr, "%s: hostname=%s\n",
			me, _idmapdstate.hostname);
		(void) fprintf(stderr, "%s; name service domain=%s\n", me,
			_idmapdstate.domainname);

		(void) fprintf(stderr, "%s: config=%s\n", me,
			_idmapdstate.cfg?"not null":"null");
	}
	if (_idmapdstate.cfg == NULL || _idmapdstate.daemon_mode == TRUE)
		goto out;
	(void) fprintf(stderr, "%s: list_size_limit=%llu\n", me,
		_idmapdstate.cfg->pgcfg.list_size_limit);
	(void) fprintf(stderr, "%s: mapping_domain=%s\n", me,
		CHECK_NULL(_idmapdstate.cfg->pgcfg.mapping_domain));
	(void) fprintf(stderr, "%s: machine_sid=%s\n", me,
		CHECK_NULL(_idmapdstate.cfg->pgcfg.machine_sid));
	(void) fprintf(stderr, "%s: global_catalog=%s\n", me,
		CHECK_NULL(_idmapdstate.cfg->pgcfg.global_catalog));
	(void) fprintf(stderr, "%s: domain_controller=%s\n", me,
		CHECK_NULL(_idmapdstate.cfg->pgcfg.domain_controller));
out:
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
