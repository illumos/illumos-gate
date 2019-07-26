/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * PICL plug-in that listens to sysevent and posts picl events
 */

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <stdlib.h>
#include <assert.h>
#include <alloca.h>
#include <unistd.h>
#include <stropts.h>
#include <syslog.h>
#include <libdevinfo.h>
#include <sys/time.h>
#include <fcntl.h>
#include <picl.h>
#include <picltree.h>
#include <sys/types.h>
#include <sys/sysinfo.h>
#include <dirent.h>
#include <libintl.h>
#include <sys/sunddi.h>
#include <sys/stat.h>
#include <libsysevent.h>
#include <libnvpair.h>
#include "piclevent.h"

/*
 * Plugin registration entry points
 */
static void	eventplugin_register(void);
static void	eventplugin_init(void);
static void	eventplugin_fini(void);

#pragma	init(eventplugin_register)

static picld_plugin_reg_t  my_reg_info = {
	PICLD_PLUGIN_VERSION_1,
	PICLD_PLUGIN_CRITICAL,
	"SUNW_piclevent plugin for sysevents",
	eventplugin_init,
	eventplugin_fini
};

/*
 * Log message texts
 */
#define	EVT_THR_FAILED		gettext("Event thread create failed!\n")
#define	EVT_OPEN_FAILED		gettext("PICL SLM door create failed\n")

static	int		door_id = -1;
#define	SUNW_PICLEVENT_PLUGIN_DEBUG	"SUNW_PICLEVENT_PLUGIN_DEBUG"
static	int		piclevent_debug = 0;


/*
 * completion handler for the posted picl event
 */
/*ARGSUSED*/
static void
piclevent_completion_handler(char *ename, void *earg, size_t size)
{
	free(earg);
	free(ename);
}

/*
 * This function posts the incoming piclevent
 * It packs the nvlist and posts it to PICL
 */
static void
parse_piclevent(nvlist_t *nvlp)
{
	char		*enval;
	char		*ename;
	size_t		nvl_size;
	char		*packed_nvl;
	int		err;

	if (nvlist_lookup_string(nvlp, PICLEVENTARG_EVENT_NAME, &enval))
		return;

	packed_nvl = NULL;
	if (nvlist_pack(nvlp, &packed_nvl, &nvl_size, NV_ENCODE_NATIVE, 0))
		return;

	ename = strdup(enval);
	if (ename == NULL) {
		free(packed_nvl);
		return;
	}

	if (piclevent_debug) {
		syslog(LOG_INFO, "piclevent: posting ename:%s packed_nvl:%p "
		    "nvl_size:0x%x\n", ename, packed_nvl, nvl_size);
	}
	err = ptree_post_event(ename, packed_nvl, nvl_size,
	    piclevent_completion_handler);

	if (err != PICL_SUCCESS) {
		if (piclevent_debug)
			syslog(LOG_INFO,
			    "piclevent: posting ename:%s failed err:%d\n",
			    ename, err);
		free(ename);
		free(packed_nvl);
	}
}

/*
 * This is the PICL SLM door handler. It parses the event tuple received
 * and posts an event to refresh the PICL tree.
 */
/*ARGSUSED*/
static void
event_handler(void *cookie, char *argp, size_t asize,
    door_desc_t *dp, uint_t n_desc)
{
	door_cred_t		cred;
	nvlist_t		*nvlp;
	char			*dtype;

	if (piclevent_debug)
		syslog(LOG_INFO,
		    "piclevent: got SLM event cookie:%p evarg:%p size:0x%x\n",
		    cookie, argp, asize);
	if ((door_id < 0) || (argp == NULL) || (door_cred(&cred) < 0) ||
	    (cred.dc_euid != 0))
		(void) door_return(argp, 0, NULL, 0);

	if (nvlist_unpack(argp, asize, &nvlp, 0))
		(void) door_return(argp, 0, NULL, 0);

	if (nvlist_lookup_string(nvlp, PICLEVENTARG_DATA_TYPE, &dtype)) {
		nvlist_free(nvlp);
		(void) door_return(argp, 0, NULL, 0);
	}

	if (strcmp(dtype, PICLEVENTARG_PICLEVENT_DATA) == 0)
		parse_piclevent(nvlp);
	/*
	 * ignore other event data types
	 */
	nvlist_free(nvlp);
	(void) door_return(argp, 0, NULL, 0);
}

/*
 * Create the slm to picl plugin door
 */
static int
setup_door(void)
{
	struct stat	stbuf;

	/*
	 * Create the door
	 */
	door_id = door_create(event_handler, PICLEVENT_DOOR_COOKIE,
	    DOOR_REFUSE_DESC | DOOR_NO_CANCEL);

	if (door_id < 0)
		return (-1);

	if (stat(PICLEVENT_DOOR, &stbuf) < 0) {
		int newfd;
		if ((newfd = creat(PICLEVENT_DOOR, 0444)) < 0) {
			(void) door_revoke(door_id);
			door_id = -1;
			return (-1);
		}
		(void) close(newfd);
	}

	if (fattach(door_id, PICLEVENT_DOOR) < 0) {
		if ((errno != EBUSY) || (fdetach(PICLEVENT_DOOR) < 0) ||
		    (fattach(door_id, PICLEVENT_DOOR) < 0)) {
			(void) door_revoke(door_id);
			door_id = -1;
			return (-1);
		}
	}

	return (0);
}


/*
 * This function is executed as part of .init when the plugin is
 * dlopen()ed
 */
static void
eventplugin_register(void)
{
	if (getenv(SUNW_PICLEVENT_PLUGIN_DEBUG))
		piclevent_debug = 1;
	(void) picld_plugin_register(&my_reg_info);
}

/*
 * This function is the init entry point of the plugin.
 * It creates the slm to picl plugin door.
 */
static void
eventplugin_init(void)
{
	if (setup_door() < 0) {
		syslog(LOG_ERR, EVT_OPEN_FAILED);
	}
}

/*
 * This function is the fini entry point of the plugin
 */
static void
eventplugin_fini(void)
{
	if (door_id >= 0) {
		(void) door_revoke(door_id);
		door_id = -1;
	}
}
