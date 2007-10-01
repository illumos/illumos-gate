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

#include <locale.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include "nscd_common.h"
#include "nscd_config.h"
#include "nscd_log.h"
#include "nscd_switch.h"
#include "nscd_frontend.h"

static char	*cfgfile_save = NULL;
static mutex_t	time_mutex = DEFAULTMUTEX;
static time_t	start_time = 0;

void
_nscd_set_start_time(int reset)
{
	(void) mutex_lock(&time_mutex);
	if (start_time == 0 || reset == 1)
		start_time = time(NULL);
	(void) mutex_unlock(&time_mutex);
}

time_t
_nscd_get_start_time()
{
	return (start_time);
}

nscd_rc_t
_nscd_init(
	char			*cfgfile)
{
	char			*me = "nscd_init";
	nscd_rc_t		rc;
	nscd_cfg_error_t	*err;

	/*
	 * remember when main or forker nscd starts.
	 */
	_nscd_set_start_time(0);

	/*
	 * allocate the space for tables
	 */
	if ((rc = _nscd_alloc_nsw_config()) != NSCD_SUCCESS ||
	    (rc = _nscd_alloc_service_state_table()) != NSCD_SUCCESS ||
	    (rc = _nscd_alloc_nsw_state_base()) != NSCD_SUCCESS ||
	    (rc = _nscd_alloc_nsw_be_info_db()) != NSCD_SUCCESS ||
	    (rc = _nscd_alloc_getent_ctx_base()) != NSCD_SUCCESS)
		return (rc);

	/*
	 * allocate the space for local configuration
	 * and statistics
	 */
	if ((rc = _nscd_alloc_switch_cfg()) != NSCD_SUCCESS ||
	    (rc = _nscd_alloc_frontend_cfg()) != NSCD_SUCCESS ||
	    (rc = _nscd_alloc_switch_stats()) != NSCD_SUCCESS)
		return (rc);

	/*
	 * Create and init the internal address database to keep
	 * track of the memory allocated by _nscd_alloc
	 */
	if (_nscd_create_int_addrDB() == NULL) {
		_NSCD_LOG(NSCD_LOG_INT_ADDR, NSCD_LOG_LEVEL_ERROR)
		(me, "_nscd_create_int_addrDB failed\n");
		return (NSCD_NO_MEMORY);
	}

	/*
	 * Create and init the internal context database to keep
	 * track of the getent context currently being used
	 */
	if (_nscd_create_getent_ctxDB() == NULL) {
		_NSCD_LOG(NSCD_LOG_GETENT_CTX, NSCD_LOG_LEVEL_ERROR)
		(me, "_nscd_create_getent_ctx_addrDB failed\n");
		return (NSCD_NO_MEMORY);
	}

	/*
	 * Create the backend info database for each possible source
	 */
	if ((rc = _nscd_init_all_nsw_be_info_db()) != NSCD_SUCCESS) {
		_NSCD_LOG(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_ERROR)
		(me, "_nscd_init_all_nsw_be_info_db failed (rc = %d)\n",
		    rc);
		return (rc);
	}

	/*
	 * Create the nscd_nsw_config_t for each possible nss database
	 */
	if ((rc = _nscd_init_all_nsw_config()) != NSCD_SUCCESS) {
		_NSCD_LOG(NSCD_LOG_NSW_STATE, NSCD_LOG_LEVEL_ERROR)
		(me, "_nscd_init_all_nsw_config failed (rc = %d)\n", rc);
		return (rc);
	}

	/*
	 * initialize config/stats management
	 */
	rc = _nscd_cfg_init(&err);
	if (rc != NSCD_SUCCESS) {
		if (err != NULL)
			_nscd_cfg_free_error(err);
		return (rc);
	}

	/*
	 * read in the nsswitch configuration
	 */
	rc = _nscd_cfg_read_nsswitch_file("/etc/nsswitch.conf", &err);
	if (rc != NSCD_SUCCESS) {
		(void) printf(
		gettext("reading config file %s failed with rc = %d, %s\n"),
		    "/etc/nsswitch.conf", rc, NSCD_ERR2MSG(err));
		if (err != NULL)
			_nscd_cfg_free_error(err);

		_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_ERROR)
	(me, "unable to read /etc/nsswitch.conf (rc = %d)\n", rc);
		return (rc);
	}
	/*
	 * remember which version of /etc/nsswitch.conf that was read
	 */
	_nscd_restart_if_cfgfile_changed();

	/*
	 * read in the nscd configuration
	 */
	if (cfgfile == NULL) {
		cfgfile = "/etc/nscd.conf";
		if (access(cfgfile, R_OK) != 0) {
			_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_ERROR)
		(me, "unable to read /etc/nscd.conf (rc = %d)\n", rc);

			return (NSCD_CFG_FILE_ACCESS_ERROR);
		}
	}
	rc = _nscd_cfg_read_file(cfgfile, &err);
	if (rc != NSCD_SUCCESS) {
		(void) printf(
		gettext("reading config file %s failed with rc = %d, %s\n"),
		    cfgfile, rc, NSCD_ERR2MSG(err));
		if (err != NULL)
			_nscd_cfg_free_error(err);

		_NSCD_LOG(NSCD_LOG_FRONT_END, NSCD_LOG_LEVEL_ERROR)
		(me, "unable to read configuration from %s (rc = %d)\n",
		    cfgfile, rc);

		return (rc);
	}
	/*
	 * remember the name of the config file
	 * in case refresh is requested later
	 */
	if (cfgfile != NULL) {
		cfgfile_save = strdup(cfgfile);
		if (cfgfile_save == NULL)
			return (NSCD_NO_MEMORY);
	}

	return (NSCD_SUCCESS);
}

nscd_rc_t
_nscd_refresh()
{
	char			*me = "nscd_refresh";
	char			*cfgfile;
	nscd_rc_t		rc;
	nscd_cfg_error_t	*err;
	char			errmsg[1024];

	/*
	 * re-read the nsswitch configuration
	 */
	rc = _nscd_cfg_read_nsswitch_file("/etc/nsswitch.conf", &err);
	if (rc != NSCD_SUCCESS) {
		(void) snprintf(errmsg, sizeof (errmsg),
		"unable to parse the config file %s (rc = %d), %s\n",
		"/etc/nsswitch.conf", rc, NSCD_ERR2MSG(err));
		goto error_exit;
	}

	/*
	 * re-read the nscd configuration
	 */
	if (cfgfile_save == NULL)
		cfgfile = "/etc/nscd.conf";
	else
		cfgfile = cfgfile_save;

	if (access(cfgfile, R_OK) != 0) {
		(void) snprintf(errmsg, sizeof (errmsg),
		"unable to read the config file %s (rc = %d), %s\n",
		    cfgfile, NSCD_CFG_FILE_ACCESS_ERROR,
		    strerror(errno));

		goto error_exit;
	}

	rc = _nscd_cfg_read_file(cfgfile, &err);
	if (rc != NSCD_SUCCESS) {
		(void) snprintf(errmsg, sizeof (errmsg),
		    "unable to parse the config file %s (rc = %d), %s\n",
		    cfgfile, rc, NSCD_ERR2MSG(err));

		goto error_exit;
	}

	_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ALL)
	(me, "nsswitch/nscd configuration refreshed successfully\n");

	return (NSCD_SUCCESS);

	error_exit:

	if (err != NULL)
		_nscd_cfg_free_error(err);

	_NSCD_LOG(NSCD_LOG_CONFIG, NSCD_LOG_LEVEL_ERROR)
	(me, "%s\n", errmsg);

	return (rc);
}
