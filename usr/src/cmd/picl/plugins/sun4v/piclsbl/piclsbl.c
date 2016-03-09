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

/*
 *  PICL Ontario platform plug-in to message the SC to light
 *  or extinguish the hdd 'OK2RM' ready-to-service light in
 *  the event of a soft unconfigure or configure, respectively.
 *
 *  Erie platforms (T1000) do not have ok-to-remove LEDs
 *  so they do not need handlers for the SBL events.
 */

#include <picl.h>
#include <picltree.h>
#include <picldefs.h>
#include <stdio.h>
#include <umem.h>
#include <unistd.h>
#include <libnvpair.h>
#include <strings.h>
#include <syslog.h>
#include <dlfcn.h>
#include <link.h>
#include <signal.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/param.h>
#include <sys/raidioctl.h>
#include <sys/utsname.h>
#include <sys/systeminfo.h>
#include <libpcp.h>
#include "piclsbl.h"

#include "errno.h"

#pragma init(piclsbl_register)

static void *pcp_handle;

static char hba_devctl[MAXPATHLEN];

static int (* pcp_init_ptr)();
static int (* pcp_send_recv_ptr)();
static int (* pcp_close_ptr)();

static int load_pcp_libs(void);
static void piclsbl_init(void);
static void piclsbl_fini(void);
static void piclsbl_register(void);
static void piclsbl_handler(const char *ename, const void *earg,
				size_t size, void *cookie);

static picld_plugin_reg_t piclsbl_reg = {
	PICLD_PLUGIN_VERSION_1,
	PICLD_PLUGIN_CRITICAL,
	"piclsbl",
	piclsbl_init,
	piclsbl_fini
};

/*
 * called from init to load the pcp library
 */
static int
load_pcp_libs()
{
	char pcp_dl_lib[80];

	(void) snprintf(pcp_dl_lib, sizeof (pcp_dl_lib), "%s%s",
	    LIB_PCP_PATH, PCPLIB);

	/* load the library and set up function pointers */
	if ((pcp_handle = dlopen(pcp_dl_lib, RTLD_NOW)) == (void *) NULL)
		return (1);

	pcp_init_ptr = (int(*)())dlsym(pcp_handle, "pcp_init");
	pcp_close_ptr = (int(*)())dlsym(pcp_handle, "pcp_close");
	pcp_send_recv_ptr = (int(*)())dlsym(pcp_handle, "pcp_send_recv");

	if (pcp_init_ptr == NULL || pcp_send_recv_ptr == NULL ||
	    pcp_close_ptr == NULL)
		return (1);

	return (0);
}

/*
 * callback routine for ptree_walk_tree_by_class()
 */
static int
cb_find_disk(picl_nodehdl_t node, void *args)
{
	disk_lookup_t *lookup  = (disk_lookup_t *)args;
	int status = -1;
	char *n;
	char path[PICL_PROPNAMELEN_MAX];

	status = ptree_get_propval_by_name(node, "Path", (void *)&path,
	    PICL_PROPNAMELEN_MAX);
	if (status != PICL_SUCCESS) {
		return (PICL_WALK_CONTINUE);
	}

	if (strcmp(path, lookup->path) == 0) {
		lookup->disk = node;
		lookup->result = DISK_FOUND;

		/* store the HBA's device path for use in check_raid() */
		n = strstr(path, "/sd");
		strncpy(n, "\0", 1);
		(void) snprintf(hba_devctl, MAXPATHLEN, "/devices%s:devctl",
		    path);

		return (PICL_WALK_TERMINATE);
	}

	return (PICL_WALK_CONTINUE);
}

/*
 * check a target for RAID membership
 */
static int
check_raid(int target)
{
	raid_config_t config;
	int fd;
	int numvols;
	int i;
	int j;

	/*
	 * hba_devctl is set to the onboard hba, so it will
	 * always house any onboard RAID volumes
	 */
	if ((fd = open(hba_devctl, O_RDONLY)) < 0) {
		syslog(LOG_ERR, "%s", strerror(errno));
		return (0);
	}

	/*
	 * look up the RAID configurations for the onboard
	 * HBA and check target against all member targets
	 */
	if (ioctl(fd, RAID_NUMVOLUMES, &numvols)) {
		syslog(LOG_ERR, "%s", strerror(errno));
		(void) close(fd);
		return (0);
	}

	for (i = 0; i < numvols; i++) {
		config.unitid = i;
		if (ioctl(fd, RAID_GETCONFIG, &config)) {
			syslog(LOG_ERR, "%s", strerror(errno));
			(void) close(fd);
			return (0);
		}

		for (j = 0; j < config.ndisks; j++) {
			if (config.disk[j] == target) {
				(void) close(fd);
				return (1);
			}
		}
	}
	(void) close(fd);
	return (0);
}

/*
 * Ontario SBL event handler, subscribed to:
 * 	PICLEVENT_SYSEVENT_DEVICE_ADDED
 * 	PICLEVENT_SYSEVENT_DEVICE_REMOVED
 */
static void
piclsbl_handler(const char *ename, const void *earg, size_t size,
		void *cookie)
{
	char		*devfs_path;
	char		hdd_location[PICL_PROPNAMELEN_MAX];
	nvlist_t	*nvlp = NULL;
	pcp_msg_t	send_msg;
	pcp_msg_t	recv_msg;
	pcp_sbl_req_t	*req_ptr = NULL;
	pcp_sbl_resp_t	*resp_ptr = NULL;
	int		status = -1;
	int		target;
	disk_lookup_t	lookup;
	int		channel_fd;

	/*
	 * setup the request data to attach to the libpcp msg
	 */
	if ((req_ptr = (pcp_sbl_req_t *)umem_zalloc(sizeof (pcp_sbl_req_t),
	    UMEM_DEFAULT)) == NULL)
		goto sbl_return;

	/*
	 * This plugin serves to enable or disable the blue RAS
	 * 'ok-to-remove' LED that is on each of the 4 disks on the
	 * Ontario.  We catch the event via the picl handler, and
	 * if the event is DEVICE_ADDED for one of our onboard disks,
	 * then we'll be turning off the LED. Otherwise, if the event
	 * is DEVICE_REMOVED, then we turn it on.
	 */
	if (strcmp(ename, PICLEVENT_SYSEVENT_DEVICE_ADDED) == 0)
		req_ptr->sbl_action = PCP_SBL_DISABLE;
	else if (strcmp(ename, PICLEVENT_SYSEVENT_DEVICE_REMOVED) == 0)
		req_ptr->sbl_action = PCP_SBL_ENABLE;
	else
		goto sbl_return;

	/*
	 * retrieve the device's physical path from the event payload
	 */
	if (nvlist_unpack((char *)earg, size, &nvlp, NULL))
		goto sbl_return;
	if (nvlist_lookup_string(nvlp, "devfs-path", &devfs_path))
		goto sbl_return;

	/*
	 * look for this disk in the picl tree, and if it's
	 * location indicates that it's one of our internal
	 * disks, then set sbl_id to incdicate which one.
	 * otherwise, return as it is not one of our disks.
	 */
	lookup.path = strdup(devfs_path);
	lookup.disk = NULL;
	lookup.result = DISK_NOT_FOUND;

	/* first, find the disk */
	status = ptree_walk_tree_by_class(root_node, "disk", (void *)&lookup,
	    cb_find_disk);
	if (status != PICL_SUCCESS)
		goto sbl_return;

	if (lookup.result == DISK_FOUND) {
		/* now, lookup it's location in the node */
		status = ptree_get_propval_by_name(lookup.disk, "Location",
		    (void *)&hdd_location, PICL_PROPNAMELEN_MAX);
		if (status != PICL_SUCCESS) {
			syslog(LOG_ERR, "piclsbl: failed hdd discovery");
			goto sbl_return;
		}
	}

	/*
	 * Strip off the target from the NAC name.
	 * The disk NAC will always be HDD#
	 */
	if (strncmp(hdd_location, NAC_DISK_PREFIX,
	    strlen(NAC_DISK_PREFIX)) == 0) {
		(void) sscanf(hdd_location, "%*3s%d", &req_ptr->sbl_id);
		target = (int)req_ptr->sbl_id;
	} else {
		/* this is not one of the onboard disks */
		goto sbl_return;
	}

	/*
	 * check the onboard RAID configuration for this disk. if it is
	 * a member of a RAID and is not the RAID itself, ignore the event
	 */
	if (check_raid(target))
		goto sbl_return;

	/*
	 * we have the information we need, init the platform channel.
	 * the platform channel driver will only allow one connection
	 * at a time on this socket. on the offchance that more than
	 * one event comes in, we'll retry to initialize this connection
	 * up to 3 times
	 */
	if ((channel_fd = (*pcp_init_ptr)(LED_CHANNEL)) < 0) {
		/* failed to init; wait and retry up to 3 times */
		int s = PCPINIT_TIMEOUT;
		int retries = 0;
		while (++retries) {
			(void) sleep(s);
			if ((channel_fd = (*pcp_init_ptr)(LED_CHANNEL)) >= 0)
				break;
			else if (retries == 3) {
				syslog(LOG_ERR, "piclsbl: ",
				    "SC channel initialization failed");
				goto sbl_return;
			}
			/* continue */
		}
	}

	/*
	 * populate the message for libpcp
	 */
	send_msg.msg_type = PCP_SBL_CONTROL;
	send_msg.sub_type = NULL;
	send_msg.msg_len = sizeof (pcp_sbl_req_t);
	send_msg.msg_data = (uint8_t *)req_ptr;

	/*
	 * send the request, receive the response
	 */
	if ((*pcp_send_recv_ptr)(channel_fd, &send_msg, &recv_msg,
	    PCPCOMM_TIMEOUT) < 0) {
		/* we either timed out or erred; either way try again */
		int s = PCPCOMM_TIMEOUT;
		(void) sleep(s);
		if ((*pcp_send_recv_ptr)(channel_fd, &send_msg, &recv_msg,
		    PCPCOMM_TIMEOUT) < 0) {
			syslog(LOG_ERR, "piclsbl: communication failure");
			goto sbl_return;
		}
	}

	/*
	 * validate that this data was meant for us
	 */
	if (recv_msg.msg_type != PCP_SBL_CONTROL_R) {
		syslog(LOG_ERR, "piclsbl: unbound packet received");
		goto sbl_return;
	}

	/*
	 * verify that the LED action has taken place
	 */
	resp_ptr = (pcp_sbl_resp_t *)recv_msg.msg_data;
	if (resp_ptr->status == PCP_SBL_ERROR) {
		syslog(LOG_ERR, "piclsbl: OK2RM LED action error");
		goto sbl_return;
	}

	/*
	 * ensure the LED action taken is the one requested
	 */
	if ((req_ptr->sbl_action == PCP_SBL_DISABLE) &&
	    (resp_ptr->sbl_state != SBL_STATE_OFF))
		syslog(LOG_ERR, "piclsbl: OK2RM LED not OFF after disk "
		    "configuration");
	else if ((req_ptr->sbl_action == PCP_SBL_ENABLE) &&
	    (resp_ptr->sbl_state != SBL_STATE_ON))
		syslog(LOG_ERR, "piclsbl: OK2RM LED not ON after disk "
		    "unconfiguration");
	else if (resp_ptr->sbl_state == SBL_STATE_UNKNOWN)
		syslog(LOG_ERR, "piclsbl: OK2RM LED set to unknown state");

sbl_return:

	(*pcp_close_ptr)(channel_fd);
	if (req_ptr != NULL)
		umem_free(req_ptr, sizeof (pcp_sbl_req_t));
	if (resp_ptr != NULL)
		free(resp_ptr);
	nvlist_free(nvlp);
}

static void
piclsbl_init(void)
{
	char	platbuf[SYS_NMLN];

	/* check for Erie platform name */
	if ((sysinfo(SI_PLATFORM, platbuf, SYS_NMLN) != -1) &&
	    ((strcmp(platbuf, ERIE_PLATFORM) == 0) ||
	    (strcmp(platbuf, ERIE_PLATFORM2) == 0)))
		return;

	/* retrieve the root node for lookups in the event handler */
	if ((ptree_get_root(&root_node)) != NULL)
		return;

	/* load libpcp */
	if (load_pcp_libs()) {
		syslog(LOG_ERR, "piclsbl: failed to load libpcp");
		syslog(LOG_ERR, "piclsbl: aborting");
		return;
	}

	/*
	 * register piclsbl_handler for both "sysevent-device-added" and
	 * and for "sysevent-device-removed" PICL events
	 */
	(void) ptree_register_handler(PICLEVENT_SYSEVENT_DEVICE_ADDED,
	    piclsbl_handler, NULL);
	(void) ptree_register_handler(PICLEVENT_SYSEVENT_DEVICE_REMOVED,
	    piclsbl_handler, NULL);
}

static void
piclsbl_fini(void)
{
	/* unregister the event handler */
	(void) ptree_unregister_handler(PICLEVENT_SYSEVENT_DEVICE_ADDED,
	    piclsbl_handler, NULL);
	(void) ptree_unregister_handler(PICLEVENT_SYSEVENT_DEVICE_REMOVED,
	    piclsbl_handler, NULL);
}

static void
piclsbl_register(void)
{
	picld_plugin_register(&piclsbl_reg);
}
