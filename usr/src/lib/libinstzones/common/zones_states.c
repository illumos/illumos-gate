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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


/*
 * Module:	zones_states.c
 * Group:	libinstzones
 * Description:	Provide "zones" state interfaces for install consolidation code
 *
 * Public Methods:
 *
 *  z_make_zone_running - change state of non-global zone to "running"
 * _z_make_zone_ready - change state of non-global zone to "ready"
 * _z_make_zone_down - change state of non-global zone to "down"
 */

/*
 * System includes
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/param.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <stdarg.h>
#include <limits.h>
#include <errno.h>
#include <stropts.h>
#include <libintl.h>
#include <locale.h>
#include <assert.h>

/*
 * local includes
 */

#include "instzones_lib.h"
#include "zones_strings.h"

/*
 * Private structures
 */

/*
 * Library Function Prototypes
 */

/*
 * Local Function Prototypes
 */

/*
 * global internal (private) declarations
 */

/*
 * *****************************************************************************
 * global external (public) functions
 * *****************************************************************************
 */

/*
 * Name:	_z_make_zone_running
 * Description:	Given a zone element entry for the non-global zone to affect,
 *		change the state of that non-global zone to "running"
 * Arguments:	a_zlem - [RO, *RW] - (zoneListElement_t)
 *			Zone list element describing the non-global zone to
 *			make running
 * Returns:	boolean_t
 *			B_TRUE - non-global zone state changed successfully
 *			B_FALSE - failed to make the non-global zone run
 */

boolean_t
_z_make_zone_running(zoneListElement_t *a_zlem)
{
	FILE		*fp;
	argArray_t	*args;
	char		 zonename[ZONENAME_MAX];
	char		*results = (char *)NULL;
	int		ret;
	int		status = 0;

	/* entry assertions */

	assert(a_zlem != NULL);

	/* act based on the zone's current kernel state */

	switch (a_zlem->_zlCurrKernelStatus) {
	case ZONE_STATE_RUNNING:
	case ZONE_STATE_MOUNTED:
		/* already running */
		return (B_TRUE);

	case ZONE_STATE_READY:
		/* This should never happen */
		if (zonecfg_in_alt_root())
			return (B_FALSE);

		/*
		 * We're going to upset the zone anyway, so might as well just
		 * halt it now and fall through to normal mounting.
		 */

		_z_echoDebug(DBG_TO_ZONEHALT, a_zlem->_zlName);

		args = _z_new_args(5);		/* generate new arg list */
		(void) _z_add_arg(args, ZONEADM_CMD);
		(void) _z_add_arg(args, "-z");
		(void) _z_add_arg(args, a_zlem->_zlName);
		(void) _z_add_arg(args, "halt");

		ret = z_ExecCmdArray(&status, &results, (char *)NULL,
		    ZONEADM_CMD, _z_get_argv(args));

		/* free generated argument list */

		_z_free_args(args);

		if (ret != 0) {
			_z_program_error(ERR_ZONEHALT_EXEC, ZONEADM_CMD,
			    strerror(errno));
			free(results);
			return (B_FALSE);
		}
		if (status != 0) {
			if (status == -1) {
				_z_program_error(ERR_ZONEBOOT_CMD_SIGNAL,
				    ZONEADM_CMD, a_zlem->_zlName);
			} else {
				_z_program_error(ERR_ZONEBOOT_CMD_ERROR,
				    ZONEADM_CMD, a_zlem->_zlName, status,
				    results == NULL ? "" : "\n",
				    results == NULL ? "" : results);
			}
			free(results);
			return (B_FALSE);
		}

		free(results);

		a_zlem->_zlCurrKernelStatus = ZONE_STATE_INSTALLED;
		/* FALLTHROUGH */

	case ZONE_STATE_INSTALLED:
	case ZONE_STATE_DOWN:
		/* return false if the zone cannot be booted */

		if (a_zlem->_zlStatus & ZST_NOT_BOOTABLE) {
			return (B_FALSE);
		}

		_z_echoDebug(DBG_TO_ZONERUNNING, a_zlem->_zlName);

		/* these states can be booted - do so */

		args = _z_new_args(10);		/* generate new arg list */
		(void) _z_add_arg(args, ZONEADM_CMD);
		if (zonecfg_in_alt_root()) {
			(void) _z_add_arg(args, "-R");
			(void) _z_add_arg(args, "%s",
			    (char *)zonecfg_get_root());
		}

		(void) _z_add_arg(args, "-z");
		(void) _z_add_arg(args, "%s", a_zlem->_zlName);
		(void) _z_add_arg(args, "mount");

		ret = z_ExecCmdArray(&status, &results, (char *)NULL,
		    ZONEADM_CMD, _z_get_argv(args));

		/* free generated argument list */

		_z_free_args(args);

		if (ret != 0) {
			_z_program_error(ERR_ZONEBOOT_EXEC, ZONEADM_CMD,
			    strerror(errno));
			free(results);
			return (B_FALSE);
		}

		if (status != 0) {
			if (status == -1) {
				_z_program_error(ERR_ZONEBOOT_CMD_SIGNAL,
				    ZONEADM_CMD, a_zlem->_zlName);
			} else {
				_z_program_error(ERR_ZONEBOOT_CMD_ERROR,
				    ZONEADM_CMD, a_zlem->_zlName, status,
				    results == NULL ? "" : "\n",
				    results == NULL ? "" : results);
			}
			free(results);

			/* remember this zone cannot be booted */

			a_zlem->_zlStatus |= ZST_NOT_BOOTABLE;

			return (B_FALSE);
		}
		free(results);

		if (zonecfg_in_alt_root()) {
			if ((fp = zonecfg_open_scratch("", B_FALSE)) == NULL ||
			    zonecfg_find_scratch(fp, a_zlem->_zlName,
			    zonecfg_get_root(), zonename,
			    sizeof (zonename)) == -1) {
				_z_program_error(ERR_ZONEBOOT_DIDNT_BOOT,
				    a_zlem->_zlName);
				if (fp != NULL)
					zonecfg_close_scratch(fp);
				return (B_FALSE);
			}
			zonecfg_close_scratch(fp);
			free(a_zlem->_zlScratchName);
			a_zlem->_zlScratchName = _z_strdup(zonename);
		}
		a_zlem->_zlCurrKernelStatus = ZONE_STATE_MOUNTED;
		return (B_TRUE);

	case ZONE_STATE_CONFIGURED:
	case ZONE_STATE_INCOMPLETE:
	case ZONE_STATE_SHUTTING_DOWN:
	default:
		/* cannot transition (boot) these states */
		return (B_FALSE);
	}
}

/*
 * Name:	_z_make_zone_ready
 * Description:	Given a zone element entry for the non-global zone to affect,
 *		restore the ready state of the zone when the zone is currently
 *		in the running state.
 * Arguments:	a_zlem - [RO, *RW] - (zoneListElement_t)
 *			Zone list element describing the non-global zone to
 *			make ready
 * Returns:	boolean_t
 *			B_TRUE - non-global zone state changed successfully
 *			B_FALSE - failed to make the non-global zone ready
 */

boolean_t
_z_make_zone_ready(zoneListElement_t *a_zlem)
{
	argArray_t	*args;
	char		*results = (char *)NULL;
	int		status = 0;
	int		i;
	int		ret;
	zone_state_t	st;

	/* entry assertions */

	assert(a_zlem != (zoneListElement_t *)NULL);

	/* act based on the zone's current kernel state */

	switch (a_zlem->_zlCurrKernelStatus) {
	case ZONE_STATE_DOWN:
	case ZONE_STATE_READY:
		/* already down */
		return (B_TRUE);

	case ZONE_STATE_MOUNTED:
		_z_echoDebug(DBG_TO_ZONEUNMOUNT, a_zlem->_zlName);

		args = _z_new_args(10);		/* generate new arg list */
		(void) _z_add_arg(args, ZONEADM_CMD);
		(void) _z_add_arg(args, "-z");
		(void) _z_add_arg(args, "%s", a_zlem->_zlName);
		(void) _z_add_arg(args, "unmount");
		ret = z_ExecCmdArray(&status, &results, NULL,
		    ZONEADM_CMD, _z_get_argv(args));
		if (ret != 0) {
			_z_program_error(ERR_ZONEUNMOUNT_EXEC,
			    ZONEADM_CMD, strerror(errno));
			free(results);
			_z_free_args(args);
			return (B_FALSE);
		}
		if (status != 0) {
			if (status == -1) {
				_z_program_error(ERR_ZONEUNMOUNT_CMD_SIGNAL,
				    ZONEADM_CMD, a_zlem->_zlName);
			} else {
				_z_program_error(ERR_ZONEUNMOUNT_CMD_ERROR,
				    ZONEADM_CMD, a_zlem->_zlName, status,
				    results == NULL ? "" : "\n",
				    results == NULL ? "" : results);
			}
			if (results != NULL) {
				free(results);
			}
			_z_free_args(args);
			return (B_FALSE);
		}
		if (results != NULL) {
			free(results);
		}
		_z_free_args(args);
		a_zlem->_zlCurrKernelStatus = ZONE_STATE_INSTALLED;
		_z_echoDebug(DBG_TO_ZONEREADY, a_zlem->_zlName);

		args = _z_new_args(10);		/* generate new arg list */
		(void) _z_add_arg(args, ZONEADM_CMD);
		(void) _z_add_arg(args, "-z");
		(void) _z_add_arg(args, "%s", a_zlem->_zlName);
		(void) _z_add_arg(args, "ready");

		ret = z_ExecCmdArray(&status, &results, NULL,
		    ZONEADM_CMD, _z_get_argv(args));
		if (ret != 0) {
			_z_program_error(ERR_ZONEREADY_EXEC, ZONEADM_CMD,
			    strerror(errno));
			free(results);
			_z_free_args(args);
			return (B_FALSE);
		}
		if (status != 0) {
			_z_program_error(ERR_ZONEREADY_CMDFAIL, ZONEADM_CMD,
			    a_zlem->_zlName, strerror(errno),
			    results == NULL ? "" : "\n",
			    results == NULL ? "" : results);
			if (results != NULL) {
				free(results);
			}
			_z_free_args(args);
			return (B_FALSE);
		}
		if (results != NULL) {
			free(results);
		}
		/* success - zone is now in the ready state */
		a_zlem->_zlCurrKernelStatus = ZONE_STATE_READY;
		return (B_TRUE);

	case ZONE_STATE_RUNNING:

		_z_echoDebug(DBG_TO_ZONEREADY, a_zlem->_zlName);

		args = _z_new_args(10);		/* generate new arg list */
		(void) _z_add_arg(args, ZONEADM_CMD);
		(void) _z_add_arg(args, "-z");
		(void) _z_add_arg(args, "%s", a_zlem->_zlName);
		(void) _z_add_arg(args, "ready");

		ret = z_ExecCmdArray(&status, &results, (char *)NULL,
		    ZONEADM_CMD, _z_get_argv(args));

		/* free generated argument list */

		_z_free_args(args);

		if (ret != 0) {
			_z_program_error(ERR_ZONEREADY_EXEC, ZONEADM_CMD,
			    strerror(errno));
			free(results);
			_z_free_args(args);
			return (B_FALSE);
		}
		if (status != 0) {
			_z_program_error(ERR_ZONEREADY_CMDFAIL, ZONEADM_CMD,
			    a_zlem->_zlName, strerror(errno),
			    results == (char *)NULL ? "" : "\n",
			    results == (char *)NULL ? "" : results);
			if (results != (char *)NULL) {
				(void) free(results);
			}
			return (B_FALSE);
		}

		if (results != (char *)NULL) {
			(void) free(results);
		}

		for (i = 0; i < MAX_RETRIES; i++) {
			if (zone_get_state(a_zlem->_zlName, &st) != Z_OK) {
				break;
			}
			if ((st == ZONE_STATE_DOWN) ||
			    (st == ZONE_STATE_INSTALLED)||
			    (st == ZONE_STATE_READY)) {
				break;
			}
			(void) sleep(RETRY_DELAY_SECS);
		}

		/* failure if maximum retries reached */

		if (i >= MAX_RETRIES) {
			_z_program_error(ERR_ZONEREADY_DIDNT_READY,
			    a_zlem->_zlName);
			a_zlem->_zlCurrKernelStatus = st;
			return (B_FALSE);
		}

		/* success - zone is now in the ready state  */

		a_zlem->_zlCurrKernelStatus = ZONE_STATE_READY;

		return (B_TRUE);

	case ZONE_STATE_INSTALLED:
	case ZONE_STATE_CONFIGURED:
	case ZONE_STATE_INCOMPLETE:
	case ZONE_STATE_SHUTTING_DOWN:
	default:
		return (B_FALSE);
	}
}

/*
 * Name:	_z_make_zone_down
 * Description:	Given a zone element entry for the non-global zone to affect,
 *		change the state of that non-global zone to "down"
 * Arguments:	a_zlem - [RO, *RW] - (zoneListElement_t)
 *			Zone list element describing the non-global zone to
 *			make down
 * Returns:	boolean_t
 *			B_TRUE - non-global zone state changed successfully
 *			B_FALSE - failed to make the non-global zone down
 */

boolean_t
_z_make_zone_down(zoneListElement_t *a_zlem)
{
	argArray_t	*args;
	char		*results = (char *)NULL;
	int		status = 0;
	int		ret;

	/* entry assertions */

	assert(a_zlem != NULL);

	/* act based on the zone's current kernel state */

	switch (a_zlem->_zlCurrKernelStatus) {
	case ZONE_STATE_DOWN:
	case ZONE_STATE_READY:
	case ZONE_STATE_RUNNING:
		/* shouldn't be touched */
		return (B_TRUE);

	case ZONE_STATE_MOUNTED:

		_z_echoDebug(DBG_TO_ZONEHALT, a_zlem->_zlName);

		/* these states can be halted - do so */

		args = _z_new_args(10);		/* generate new arg list */
		(void) _z_add_arg(args, ZONEADM_CMD);

		if (zonecfg_in_alt_root()) {
			(void) _z_add_arg(args, "-R");
			(void) _z_add_arg(args, "%s",
			    (char *)zonecfg_get_root());
		}

		(void) _z_add_arg(args, "-z");
		(void) _z_add_arg(args, "%s", a_zlem->_zlName);
		(void) _z_add_arg(args, "unmount");

		ret = z_ExecCmdArray(&status, &results, (char *)NULL,
		    ZONEADM_CMD, _z_get_argv(args));

		/* free generated argument list */

		_z_free_args(args);

		if (ret != 0) {
			_z_program_error(ERR_ZONEHALT_EXEC, ZONEADM_CMD,
			    strerror(errno));
			free(results);
			return (B_FALSE);
		}
		if (status != 0) {
			if (status == -1) {
				_z_program_error(ERR_ZONEBOOT_CMD_SIGNAL,
				    ZONEADM_CMD, a_zlem->_zlName);
			} else {
				_z_program_error(ERR_ZONEBOOT_CMD_ERROR,
				    ZONEADM_CMD, a_zlem->_zlName, status,
				    results == NULL ? "" : "\n",
				    results == NULL ? "" : results);
			}
			free(results);
			return (B_FALSE);
		}

		free(results);

		a_zlem->_zlCurrKernelStatus = ZONE_STATE_INSTALLED;
		/*
		 * Leave the scratch name in place because the upper level
		 * software may have used it to construct file names and the
		 * like.
		 */
		return (B_TRUE);

	case ZONE_STATE_INSTALLED:
	case ZONE_STATE_CONFIGURED:
	case ZONE_STATE_INCOMPLETE:
	case ZONE_STATE_SHUTTING_DOWN:
	default:
		return (B_FALSE);
	}
}

/*
 * Function:    UmountAllZones
 * Description: Unmount all mounted zones under a specified directory.
 *
 * Scope:   public
 * Parameters:  mntpnt  [RO, *RO]
 *          Non-NULL pointer to name of directory to be unmounted.
 * Return:   0  - successfull
 *      -1  - unmount failed; see errno for reason
 */
int
UmountAllZones(char *mntpnt) {

	zoneList_t  zlst;
	int	 k;
	int  ret = 0;

	if (z_zones_are_implemented()) {

		z_set_zone_root(mntpnt);

		zlst = z_get_nonglobal_zone_list();
		if (zlst == (zoneList_t)NULL) {
			return (0);
		}

		for (k = 0; z_zlist_get_zonename(zlst, k) != (char *)NULL;
		    k++) {
			if (z_zlist_get_current_state(zlst, k) >
			    ZONE_STATE_INSTALLED) {
				if (!z_zlist_change_zone_state(zlst, k,
				    ZONE_STATE_INSTALLED)) {
					ret = -1;
					break;
				}
			}
		}

		/* Free zlst */
		z_free_zone_list(zlst);
	}

	return (ret);

}
