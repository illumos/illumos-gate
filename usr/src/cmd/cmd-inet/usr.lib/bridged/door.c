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
 * bridged - bridging control daemon.  This module provides the door-based
 * interface used by user applications to gather bridge status information.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <syslog.h>
#include <door.h>
#include <errno.h>
#include <alloca.h>
#include <libdlpi.h>
#include <libdlbridge.h>
#include <stp_in.h>
#include <net/bridge.h>

#include "global.h"

#define	DOOR_DIRMODE	0755
#define	DOOR_FILEMODE	0444

static int door_fd = -1;
static char doorname[MAXPATHLEN];

/*ARGSUSED*/
static void
bridge_door_server(void *cookie, char *argp, size_t arg_size, door_desc_t *dp,
    uint_t ndesc)
{
	/* LINTED: alignment */
	bridge_door_cmd_t *bdc = (bridge_door_cmd_t *)argp;
	int retv = EINVAL;
	bridge_door_cfg_t bdcf;
	UID_STP_STATE_T smstate;
	UID_STP_PORT_CFG_T portcfg;
	UID_STP_PORT_STATE_T portstate;
	struct portdata *pdp;
	int twoints[2];

	if (arg_size < sizeof (*bdc) || lock_engine() != 0) {
		(void) door_return((char *)&retv, sizeof (retv), NULL, 0);
		return;
	}

	switch (bdc->bdc_type) {
	case bdcBridgeGetConfig:
		if ((retv = STP_IN_stpm_get_cfg(0, &bdcf.bdcf_cfg)) != 0)
			break;
		bdcf.bdcf_prot = protect;
		unlock_engine();
		(void) door_return((char *)&bdcf, sizeof (bdcf), NULL, 0);
		return;

	case bdcBridgeGetState:
		if ((retv = STP_IN_stpm_get_state(0, &smstate)) != 0)
			break;
		unlock_engine();
		(void) door_return((char *)&smstate, sizeof (smstate), NULL, 0);
		return;

	case bdcBridgeGetPorts: {
		datalink_id_t *dlp;
		int *rbuf;
		size_t rlen;
		int i, nports;

		if (nextport == 0) {
			twoints[0] = 0;
			rbuf = twoints;
			rlen = sizeof (twoints);
		} else {
			rlen = sizeof (int) + nextport * sizeof (datalink_id_t);
			rbuf = alloca(rlen);
			dlp = (datalink_id_t *)(rbuf + 1);
			for (i = nports = 0; i < nextport; i++) {
				if (allports[i]->kern_added)
					dlp[nports++] = allports[i]->linkid;
			}
			rbuf[0] = nports;
			rlen = sizeof (int) + nports * sizeof (datalink_id_t);
		}
		unlock_engine();
		(void) door_return((char *)rbuf, rlen, NULL, 0);
		return;
	}

	case bdcBridgeGetRefreshCount:
		twoints[0] = refresh_count;
		twoints[1] = 0;
		unlock_engine();
		(void) door_return((char *)twoints, sizeof (twoints), NULL, 0);
		return;

	case bdcPortGetConfig:
		if ((pdp = find_by_linkid(bdc->bdc_linkid)) == NULL)
			break;
		retv = STP_IN_port_get_cfg(0, pdp->port_index, &portcfg);
		if (retv != 0)
			break;
		unlock_engine();
		(void) door_return((char *)&portcfg, sizeof (portcfg), NULL, 0);
		return;

	case bdcPortGetState:
		if ((pdp = find_by_linkid(bdc->bdc_linkid)) == NULL)
			break;
		portstate.port_no = pdp->port_index;
		if ((retv = STP_IN_port_get_state(0, &portstate)) != 0)
			break;
		if (pdp->sdu_failed)
			portstate.state = UID_PORT_BADSDU;
		else if (protect != DLADM_BRIDGE_PROT_STP)
			portstate.state = UID_PORT_NON_STP;
		else if (pdp->admin_non_stp && pdp->bpdu_protect)
			portstate.state = UID_PORT_DISABLED;
		unlock_engine();
		(void) door_return((char *)&portstate, sizeof (portstate),
		    NULL, 0);
		return;

	case bdcPortGetForwarding:
		if ((pdp = find_by_linkid(bdc->bdc_linkid)) == NULL)
			break;
		twoints[0] = pdp->admin_status ? 1 : 0;
		twoints[1] = 0;
		unlock_engine();
		(void) door_return((char *)twoints, sizeof (twoints), NULL, 0);
		return;
	}
	unlock_engine();
	(void) door_return((char *)&retv, sizeof (retv), NULL, 0);
}

static void
cleanup_door(void)
{
	if (door_fd != -1) {
		(void) door_revoke(door_fd);
		door_fd = -1;
	}
	if (doorname[0] != '\0') {
		(void) unlink(doorname);
		doorname[0] = '\0';
	}
}

void
init_door(void)
{
	int fd;

	/* Make sure that the control directory exists */
	(void) mkdir(DOOR_DIRNAME, DOOR_DIRMODE);

	/* Each instance gets a separate door. */
	(void) snprintf(doorname, sizeof (doorname), "%s/%s", DOOR_DIRNAME,
	    instance_name);

	/* Do a low-overhead "touch" on the file that will be the door node. */
	fd = open(doorname,
	    O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_NONBLOCK,
	    DOOR_FILEMODE);
	if (fd != -1) {
		(void) close(fd);
	} else if (errno != EEXIST) {
		syslog(LOG_ERR, "unable to create control door node: %m");
		exit(EXIT_FAILURE);
	}

	(void) atexit(cleanup_door);

	/* Create the door. */
	door_fd = door_create(bridge_door_server, NULL,
	    DOOR_REFUSE_DESC | DOOR_NO_CANCEL);
	if (door_fd == -1) {
		syslog(LOG_ERR, "unable to create control door: %m");
		exit(EXIT_FAILURE);
	}

	/* Attach the door to the file. */
	(void) fdetach(doorname);
	if (fattach(door_fd, doorname) == -1) {
		syslog(LOG_ERR, "unable to attach control door: %m");
		exit(EXIT_FAILURE);
	}
}
