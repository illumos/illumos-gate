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
 * RCM module for managing the OS Quiesce event (SUNW_OS) in a
 * clustered environment.
 */

#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <thread.h>
#include <synch.h>
#include <assert.h>
#include <errno.h>
#include <libintl.h>
#include <sys/param.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/cladm.h>
#include "rcm_module.h"

#define	SUNW_OS		"SUNW_OS"
#define	OS_USAGE	gettext("Sun Cluster")
#define	OS_SUSPEND_ERR	gettext("OS cannot be quiesced on clustered nodes")
#define	OS_OFFLINE_ERR	gettext("Invalid operation: OS cannot be offlined")
#define	OS_REMOVE_ERR	gettext("Invalid operation: OS cannot be removed")

static int		cluster_register(rcm_handle_t *);
static int		cluster_unregister(rcm_handle_t *);
static int		cluster_getinfo(rcm_handle_t *, char *, id_t, uint_t,
			    char **, char **, nvlist_t *, rcm_info_t **);
static int		cluster_suspend(rcm_handle_t *, char *, id_t,
			    timespec_t *, uint_t, char **, rcm_info_t **);
static int		cluster_resume(rcm_handle_t *, char *, id_t, uint_t,
			    char **, rcm_info_t **);
static int		cluster_offline(rcm_handle_t *, char *, id_t, uint_t,
			    char **, rcm_info_t **);
static int		cluster_online(rcm_handle_t *, char *, id_t, uint_t,
			    char **, rcm_info_t **);
static int		cluster_remove(rcm_handle_t *, char *, id_t, uint_t,
			    char **, rcm_info_t **);

static int		cluster_SUNW_os_registered = 0;

static struct rcm_mod_ops cluster_ops =
{
	RCM_MOD_OPS_VERSION,
	cluster_register,
	cluster_unregister,
	cluster_getinfo,
	cluster_suspend,
	cluster_resume,
	cluster_offline,
	cluster_online,
	cluster_remove,
	NULL,
	NULL,
	NULL
};

struct rcm_mod_ops *
rcm_mod_init()
{
	return (&cluster_ops);
}

const char *
rcm_mod_info()
{
	return (gettext("RCM Cluster module 1.3"));
}

int
rcm_mod_fini()
{
	return (RCM_SUCCESS);
}

static int
cluster_register(rcm_handle_t *hdl)
{
	int bootflags;

	if (cluster_SUNW_os_registered)
		return (RCM_SUCCESS);

	if (_cladm(CL_INITIALIZE, CL_GET_BOOTFLAG, &bootflags) != 0) {
		rcm_log_message(RCM_ERROR,
			gettext("unable to check cluster status\n"));
		return (RCM_FAILURE);
	}

	/* attempt to determine if we are in cluster mode */

	if (bootflags & CLUSTER_BOOTED) {
		if (rcm_register_interest(hdl, SUNW_OS, 0, NULL) !=
		    RCM_SUCCESS) {
			rcm_log_message(RCM_ERROR,
			    gettext("failed to register\n"));
			return (RCM_FAILURE);
		} else {
			cluster_SUNW_os_registered = 1;
			rcm_log_message(RCM_DEBUG, "registered " SUNW_OS
					"\n");
		}
	}

	return (RCM_SUCCESS);
}

static int
cluster_unregister(rcm_handle_t *hdl)
{

	if (cluster_SUNW_os_registered) {
		if (rcm_unregister_interest(hdl, SUNW_OS, 0) !=
		    RCM_SUCCESS) {
			rcm_log_message(RCM_ERROR,
			    gettext("failed to unregister"));
		}
		cluster_SUNW_os_registered = 0;
	}
	return (RCM_SUCCESS);
}

/*ARGSUSED*/
static int
cluster_getinfo(rcm_handle_t *hdl, char *rsrcname, id_t id, uint_t flags,
    char **infostr, char **errstr, nvlist_t *props, rcm_info_t **dependent)
{

	assert(rsrcname != NULL && infostr != NULL);

	if ((*infostr = strdup(OS_USAGE)) == NULL)
		rcm_log_message(RCM_ERROR, gettext("strdup failure\n"));

	return (RCM_SUCCESS);
}

/*ARGSUSED*/
static int
cluster_suspend(rcm_handle_t *hdl, char *rsrcname, id_t id,
    timespec_t *interval, uint_t flags, char **errstr,
    rcm_info_t **dependent)
{
	if ((*errstr = strdup(OS_SUSPEND_ERR)) == NULL)
		rcm_log_message(RCM_ERROR, gettext("strdup failure\n"));

	return (RCM_FAILURE);
}

/*ARGSUSED*/
static int
cluster_resume(rcm_handle_t *hdl, char *rsrcname, id_t id, uint_t flags,
    char **errstr, rcm_info_t **dependent)
{
	return (RCM_SUCCESS);
}

/*
 * By default, reject offline. If offline request is
 * forced, attempt to relocate the cluster device.
 */
/*ARGSUSED*/
static int
cluster_offline(rcm_handle_t *hdl, char *rsrcname, id_t id, uint_t flags,
    char **errstr, rcm_info_t **dependent)
{
	if ((*errstr = strdup(OS_OFFLINE_ERR)) == NULL)
		rcm_log_message(RCM_ERROR, gettext("strdup failure\n"));

	return (RCM_FAILURE);
}

/*ARGSUSED*/
static int
cluster_online(rcm_handle_t *hdl, char *rsrcname, id_t id, uint_t flags,
    char  **errstr, rcm_info_t **dependent)
{
	return (RCM_SUCCESS);
}

/*ARGSUSED*/
static int
cluster_remove(rcm_handle_t *hdl, char *rsrcname, id_t id, uint_t flags,
    char **errstr, rcm_info_t **dependent)
{
	if ((*errstr = strdup(OS_REMOVE_ERR)) == NULL)
		rcm_log_message(RCM_ERROR, gettext("strdup failure\n"));

	return (RCM_FAILURE);
}
