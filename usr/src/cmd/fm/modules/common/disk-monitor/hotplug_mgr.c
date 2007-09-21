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

#include <sys/types.h>
#include <sys/sysevent/dr.h>
#include <sys/sysevent/eventdefs.h>
#include <sys/sunddi.h>	/* for the EC's for DEVFS */

#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdio.h>
#include <unistd.h>
#include <time.h>
#include <pthread.h>

#include <libsysevent.h>
#include <sys/sysevent_impl.h>

#include <libnvpair.h>
#include <config_admin.h>

#include "disk_monitor.h"
#include "hotplug_mgr.h"
#include "schg_mgr.h"
#include "dm_platform.h"

typedef struct sysevent_event {
	sysevent_t	*evp;
} sysevent_event_t;

/* Lock guarantees the ordering of the incoming sysevents */
static pthread_t g_sysev_tid;
static pthread_mutex_t g_event_handler_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t g_event_handler_cond = PTHREAD_COND_INITIALIZER;
static qu_t *g_sysev_queue = NULL;
static thread_state_t g_sysev_thread_state = TS_NOT_RUNNING;
/*
 * The sysevent handle is bound to the main sysevent handler
 * (event_handler), for each of the hotplug sysevents.
 */
static sysevent_handle_t *sysevent_handle = NULL;

static void free_sysevent_event(void *p);

static int
nsleep(int seconds)
{
	struct timespec tspec;

	tspec.tv_sec = seconds;
	tspec.tv_nsec = 0;

	return (nanosleep(&tspec, NULL));
}

static int
config_list_ext_poll(int num, char * const *path,
    cfga_list_data_t **list_array, int *nlist, int flag)
{
	boolean_t done = B_FALSE;
	boolean_t timedout = B_FALSE;
	boolean_t interrupted = B_FALSE;
	int timeout = 0;
	int e;
#define	TIMEOUT_MAX 60

	do {
		switch ((e = config_list_ext(num, path, list_array,
		    nlist, NULL, NULL, NULL, flag))) {

		case CFGA_OK:

			return (CFGA_OK);

		case CFGA_BUSY:
		case CFGA_SYSTEM_BUSY:

			if (timeout++ >= TIMEOUT_MAX)
				timedout = B_TRUE;
			else {
				if (nsleep(1) < 0)
					interrupted = (errno == EINTR);
			}
			break;

		default:
			done = B_TRUE;
			break;

		}
	} while (!done && !timedout && !interrupted);

	return (e);
}

/*
 * Given a physical attachment point with a dynamic component
 * (as in the case of SCSI APs), ensure the 'controller'
 * portion of the dynamic component matches the physical portion.
 * Argument 'adjusted' must point to a buffer of at least
 * MAXPATHLEN bytes.
 */
void
adjust_dynamic_ap(const char *apid, char *adjusted)
{
	cfga_list_data_t *list_array = NULL;
	int nlist;
	char *ap_path[1];
	char phys[MAXPATHLEN];
	char dev_phys[MAXPATHLEN];
	char *dyn;
	int c, t, d;

	dm_assert((strlen(apid) + 8 /* strlen("/devices") */) < MAXPATHLEN);

	/* In the case of any error, return the unadjusted APID */
	(void) strcpy(adjusted, apid);

	/* if AP is not dynamic or not a disk node, no need to adjust it */
	dyn = strstr(apid, "::");
	if ((dyn == NULL) || (dyn == apid) ||
	    (sscanf(dyn, "::dsk/c%dt%dd%d", &c, &t, &d) != 3))
		return;

	/*
	 * Copy the AP_ID and terminate it at the '::' that we know
	 * for a fact it contains.  Pre-pend '/devices' for the sake
	 * of cfgadm_scsi, and get the cfgadm data for the controller.
	 */
	(void) strcpy(phys, apid);
	*strstr(phys, "::") = '\0';
	(void) snprintf(dev_phys, MAXPATHLEN, "/devices%s", phys);
	ap_path[0] = dev_phys;

	if (config_list_ext_poll(1, ap_path, &list_array, &nlist, 0)
	    != CFGA_OK)
		return;

	dm_assert(nlist == 1);

	if (sscanf(list_array[0].ap_log_id, "c%d", &c) == 1)
		(void) snprintf(adjusted, MAXPATHLEN, "%s::dsk/c%dt%dd%d",
		    phys, c, t, d);

	free(list_array);
}

static int
disk_ap_is_scsi(const char *ap_path)
{
	return (strstr(ap_path, ":scsi:") != NULL);
}

/*
 * Looks up the attachment point's state and returns it in one of
 * the hotplug states that the state change manager understands.
 */
hotplug_state_t
disk_ap_state_to_hotplug_state(diskmon_t *diskp)
{
	hotplug_state_t state = HPS_UNKNOWN;
	cfga_list_data_t *list_array = NULL;
	int rv, nlist;
	char *app = (char *)dm_prop_lookup(diskp->app_props,
	    DISK_AP_PROP_APID);
	char adj_app[MAXPATHLEN];
	char *ap_path[1];
	char *devices_app;
	int len;
	boolean_t list_valid = B_FALSE;

	dm_assert(app != NULL);

	adjust_dynamic_ap(app, adj_app);
	ap_path[0] = adj_app;
	devices_app = NULL;

	rv = config_list_ext_poll(1, ap_path, &list_array, &nlist,
	    CFGA_FLAG_LIST_ALL);

	if (rv != CFGA_OK) {
		/*
		 * The SATA and SCSI libcfgadm plugins add a
		 * /devices to the phys id; to use it, we must
		 * prepend this string before the call.
		 */
		len = 8 /* strlen("/devices") */ + strlen(adj_app) + 1;
		devices_app = dmalloc(len);
		(void) snprintf(devices_app, len, "/devices%s",
		    adj_app);
		ap_path[0] = devices_app;

		rv = config_list_ext_poll(1, ap_path, &list_array, &nlist,
		    CFGA_FLAG_LIST_ALL);
	}

	/*
	 * cfgadm_scsi will return an error for an absent target,
	 * so treat an error as "absent"; otherwise, make sure
	 * cfgadm_xxx has returned a list of 1 item
	 */
	if (rv == CFGA_OK) {
		dm_assert(nlist == 1);
		list_valid = B_TRUE;
	} else if (disk_ap_is_scsi(ap_path[0]))
		state = HPS_ABSENT;

	if (devices_app != NULL)
		dfree(devices_app, len);

	if (list_valid) {
		/*
		 * The following truth table defines how each state is
		 * computed:
		 *
		 * +----------------------------------------------+
		 * |		  | o_state | r_state | condition |
		 * |		  +---------+---------+-----------|
		 * | Absent	  |Don'tCare|Disc/Empt|	Don'tCare |
		 * | Present	  |Unconfgrd|Connected|	 unknown  |
		 * | Configured	  |Configred|Connected|	Don'tCare |
		 * | Unconfigured |Unconfgrd|Connected|	   OK	  |
		 * +--------------+---------+---------+-----------+
		 */

		if (list_array[0].ap_r_state == CFGA_STAT_EMPTY ||
		    list_array[0].ap_r_state == CFGA_STAT_DISCONNECTED)
			state = HPS_ABSENT;
		else if (list_array[0].ap_r_state == CFGA_STAT_CONNECTED &&
		    list_array[0].ap_o_state == CFGA_STAT_UNCONFIGURED &&
		    list_array[0].ap_cond == CFGA_COND_UNKNOWN)
			state = HPS_PRESENT;
		else if (list_array[0].ap_r_state == CFGA_STAT_CONNECTED &&
		    list_array[0].ap_o_state == CFGA_STAT_UNCONFIGURED &&
		    list_array[0].ap_cond != CFGA_COND_UNKNOWN)
			state = HPS_UNCONFIGURED;
		else if (list_array[0].ap_r_state == CFGA_STAT_CONNECTED &&
		    list_array[0].ap_o_state == CFGA_STAT_CONFIGURED)
			state = HPS_CONFIGURED;

		free(list_array);
	}

	return (state);
}

/*
 * Examine the sysevent passed in and returns the hotplug state that
 * the sysevent states (or implies, in the case of attachment point
 * events).
 */
static hotplug_state_t
disk_sysev_to_state(diskmon_t *diskp, sysevent_t *evp)
{
	const char *class_name, *subclass;
	hotplug_state_t state = HPS_UNKNOWN;
	sysevent_value_t se_val;

	/*
	 * The state mapping is as follows:
	 *
	 * Sysevent				State
	 * --------------------------------------------------------
	 * EC_DEVFS/ESC_DEVFS_DEVI_ADD		Configured
	 * EC_DEVFS/ESC_DEVFS_DEVI_REMOVE	Unconfigured
	 * EC_DR/ESC_DR_AP_STATE_CHANGE		*[Absent/Present]
	 *
	 * (The EC_DR event requires a probe of the attachment point
	 * to determine the AP's state if there is no usable HINT)
	 *
	 */

	class_name = sysevent_get_class_name(evp);
	subclass = sysevent_get_subclass_name(evp);

	if (strcmp(class_name, EC_DEVFS) == 0) {
		if (strcmp(subclass, ESC_DEVFS_DEVI_ADD) == 0) {

			state = HPS_CONFIGURED;

		} else if (strcmp(subclass, ESC_DEVFS_DEVI_REMOVE) == 0) {

			state = HPS_UNCONFIGURED;

		}

	} else if (strcmp(class_name, EC_DR) == 0 &&
	    ((strcmp(subclass, ESC_DR_AP_STATE_CHANGE) == 0) ||
	    (strcmp(subclass, ESC_DR_TARGET_STATE_CHANGE) == 0))) {

		if (sysevent_lookup_attr(evp, DR_HINT, SE_DATA_TYPE_STRING,
		    &se_val) == 0 && se_val.value.sv_string != NULL) {

			if (strcmp(se_val.value.sv_string, DR_HINT_INSERT)
			    == 0) {

				state = HPS_PRESENT;

			} else if (strcmp(se_val.value.sv_string,
			    DR_HINT_REMOVE) == 0) {

				state = HPS_ABSENT;
			}

		}

		/*
		 * If the state could not be determined by the hint
		 * (or there was no hint), ask the AP directly.
		 * SCSI HBAs may send an insertion sysevent
		 * *after* configuring the target node, so double-
		 * check HPS_PRESENT
		 */
		if ((state == HPS_UNKNOWN) || (state = HPS_PRESENT))
			state = disk_ap_state_to_hotplug_state(diskp);
	}

	return (state);
}

static void
disk_split_ap_path_sata(const char *ap_path, char *device, int *target)
{
	char *p;
	int n;

	/*
	 *  /devices/rootnode/.../device:target
	 */
	(void) strncpy(device, ap_path, MAXPATHLEN);
	p = strrchr(device, ':');
	dm_assert(p != NULL);
	n = sscanf(p, ":%d", target);
	dm_assert(n == 1);
	*p = '\0';
}

static void
disk_split_ap_path_scsi(const char *ap_path, char *device, int *target)
{
	char *p;
	int n;

	/*
	 *  /devices/rootnode/.../device:scsi::dsk/cXtXdX
	 */

	(void) strncpy(device, ap_path, MAXPATHLEN);
	p = strrchr(device, ':');
	dm_assert(p != NULL);

	n = sscanf(p, ":dsk/c%*dt%dd%*d", target);
	dm_assert(n == 1);

	*strchr(device, ':') = '\0';
}

static void
disk_split_ap_path(const char *ap_path, char *device, int *target)
{
	/*
	 * The AP path comes in two forms; for SATA devices,
	 * is is of the form:
	 *   /devices/rootnode/.../device:portnum
	 * and for SCSI devices, it is of the form:
	 *  /devices/rootnode/.../device:scsi::dsk/cXtXdX
	 */

	if (disk_ap_is_scsi(ap_path))
		disk_split_ap_path_scsi(ap_path, device, target);
	else
		disk_split_ap_path_sata(ap_path, device, target);
}

static void
disk_split_device_path(const char *dev_path, char *device, int *target)
{
	char *t, *p, *e;

	/*
	 * The disk device path is of the form:
	 * /rootnode/.../device/target@tgtid,tgtlun
	 */

	(void) strncpy(device, dev_path, MAXPATHLEN);
	e = t = strrchr(device, '/');
	dm_assert(t != NULL);

	t = strchr(t, '@');
	dm_assert(t != NULL);
	t += 1;

	if ((p = strchr(t, ',')) != NULL)
		*p = '\0';

	*target = strtol(t, 0, 16);
	*e = '\0';
}

/*
 * Returns the diskmon that corresponds to the physical disk path
 * passed in.
 */
static diskmon_t *
disk_match_by_device_path(diskmon_t *disklistp, const char *dev_path)
{
	char dev_device[MAXPATHLEN];
	int dev_target;
	char ap_device[MAXPATHLEN];
	int ap_target;

	dm_assert(disklistp != NULL);
	dm_assert(dev_path != NULL);

	if (strncmp(dev_path, DEVICES_PREFIX, 8) == 0)
		dev_path += 8;

	/* pare dev_path into device and target components */
	disk_split_device_path(dev_path, (char *)&dev_device, &dev_target);

	/*
	 * The AP path specified in the configuration properties is
	 * the path to an attachment point minor node whose port number is
	 * equal to the target number on the disk "major" node sent by the
	 * sysevent.  To match them, we need to extract the target id and
	 * construct an AP string to compare to the AP path in the diskmon.
	 */
	while (disklistp != NULL) {
		char *app = (char *)dm_prop_lookup(disklistp->app_props,
		    DISK_AP_PROP_APID);
		dm_assert(app != NULL);

		/* Not necessary to adjust the APID here */
		if (strncmp(app, DEVICES_PREFIX, 8) == 0)
			app += 8;

		disk_split_ap_path(app, (char *)&ap_device, &ap_target);

		if ((strcmp(dev_device, ap_device) == 0) &&
		    (dev_target == ap_target))
			return (disklistp);

		disklistp = disklistp->next;
	}
	return (NULL);
}

static diskmon_t *
disk_match_by_ap_id(diskmon_t *disklistp, const char *ap_id)
{
	const char *disk_ap_id;
	dm_assert(disklistp != NULL);
	dm_assert(ap_id != NULL);

	/* Match only the device-tree portion of the name */
	if (strncmp(ap_id, DEVICES_PREFIX, 8 /* strlen("/devices") */) == 0)
		ap_id += 8;

	while (disklistp != NULL) {
		disk_ap_id = dm_prop_lookup(disklistp->app_props,
		    DISK_AP_PROP_APID);

		dm_assert(disk_ap_id != NULL);

		if (strcmp(disk_ap_id, ap_id) == 0)
			return (disklistp);

		disklistp = disklistp->next;
	}
	return (NULL);
}

static diskmon_t *
disk_match_by_target_id(diskmon_t *disklistp, const char *target_path)
{
	const char *disk_ap_id;

	char match_device[MAXPATHLEN];
	int match_target;

	char ap_device[MAXPATHLEN];
	int ap_target;


	/* Match only the device-tree portion of the name */
	if (strncmp(target_path, DEVICES_PREFIX, 8) == 0)
		target_path += 8;
	disk_split_ap_path(target_path, (char *)&match_device, &match_target);

	while (disklistp != NULL) {

		disk_ap_id = dm_prop_lookup(disklistp->app_props,
		    DISK_AP_PROP_APID);
		dm_assert(disk_ap_id != NULL);

		disk_split_ap_path(disk_ap_id, (char *)&ap_device, &ap_target);
		if ((match_target == ap_target) &&
		    (strcmp(match_device, ap_device) == 0))
			return (disklistp);

		disklistp = disklistp->next;
	}
	return (NULL);
}

static diskmon_t *
match_sysevent_to_disk(diskmon_t *disklistp, sysevent_t *evp)
{
	diskmon_t *dmp = NULL;
	sysevent_value_t se_val;
	char *class_name = sysevent_get_class_name(evp);
	char *subclass = sysevent_get_subclass_name(evp);

	se_val.value.sv_string = NULL;

	if (strcmp(class_name, EC_DEVFS) == 0) {
		/* EC_DEVFS-class events have a `DEVFS_PATHNAME' property */
		if (sysevent_lookup_attr(evp, DEVFS_PATHNAME,
		    SE_DATA_TYPE_STRING, &se_val) == 0 &&
		    se_val.value.sv_string != NULL) {

			dmp = disk_match_by_device_path(disklistp,
			    se_val.value.sv_string);

		}

	} else if (strcmp(class_name, EC_DR) == 0 &&
	    strcmp(subclass, ESC_DR_AP_STATE_CHANGE) == 0) {

		/* EC_DR-class events have a `DR_AP_ID' property */
		if (sysevent_lookup_attr(evp, DR_AP_ID, SE_DATA_TYPE_STRING,
		    &se_val) == 0 && se_val.value.sv_string != NULL) {

			dmp = disk_match_by_ap_id(disklistp,
			    se_val.value.sv_string);
		}
	} else if (strcmp(class_name, EC_DR) == 0 &&
	    strcmp(subclass, ESC_DR_TARGET_STATE_CHANGE) == 0) {
		/* get DR_TARGET_ID */
		if (sysevent_lookup_attr(evp, DR_TARGET_ID,
		    SE_DATA_TYPE_STRING, &se_val) == 0 &&
		    se_val.value.sv_string != NULL) {
			dmp = disk_match_by_target_id(disklistp,
			    se_val.value.sv_string);
		}
	}

	if (se_val.value.sv_string)
		log_msg(MM_HPMGR, "match_sysevent_to_disk: device/ap: %s\n",
		    se_val.value.sv_string);

	return (dmp);
}


/*
 * The disk hotplug monitor (DHPM) listens for disk hotplug events and calls the
 * state-change functionality when a disk's state changes.  The DHPM listens for
 * hotplug events via sysevent subscriptions to the following sysevent
 * classes/subclasses: { EC_DEVFS/ESC_DEVFS_BRANCH_ADD,
 * EC_DEVFS/ESC_DEVFS_BRANCH_REMOVE, EC_DEVFS/ESC_DEVFS_DEVI_ADD,
 * EC_DEVFS/ESC_DEVFS_DEVI_REMOVE, EC_DR/ESC_DR_AP_STATE_CHANGE }.  Once the
 * event is received, the device path sent as part of the event is matched
 * to one of the disks described by the configuration data structures.
 */
static void
dm_process_sysevent(sysevent_t *dupev)
{
	char		*class_name;
	char		*pub;
	char		*subclass = sysevent_get_subclass_name(dupev);
	diskmon_t	*diskp;

	class_name = sysevent_get_class_name(dupev);
	log_msg(MM_HPMGR, "****EVENT: %s %s (by %s)\n", class_name,
	    subclass,
	    ((pub = sysevent_get_pub_name(dupev)) != NULL) ? pub : "UNKNOWN");

	if (pub)
		free(pub);

	if (strcmp(class_name, EC_PLATFORM) == 0 &&
	    strcmp(subclass, ESC_PLATFORM_SP_RESET) == 0) {
		if (dm_platform_resync() != 0)
			log_warn("failed to resync SP platform\n");
		return;
	}

	/*
	 * We will handle this event if the event's target matches one of the
	 * disks we're monitoring
	 */
	if ((diskp = match_sysevent_to_disk(config_data->disk_list, dupev))
	    != NULL) {

		dm_state_change(diskp, disk_sysev_to_state(diskp, dupev));
	}

	sysevent_free(dupev);
}

static void
dm_fmd_sysevent_thread(void *queuep)
{
	qu_t			*qp = (qu_t *)queuep;
	sysevent_event_t	*sevevp;

	/* Signal the thread spawner that we're running */
	dm_assert(pthread_mutex_lock(&g_event_handler_lock) == 0);
	if (g_sysev_thread_state != TS_EXIT_REQUESTED)
		g_sysev_thread_state = TS_RUNNING;
	(void) pthread_cond_broadcast(&g_event_handler_cond);
	dm_assert(pthread_mutex_unlock(&g_event_handler_lock) == 0);

	while (g_sysev_thread_state != TS_EXIT_REQUESTED) {
		if ((sevevp = (sysevent_event_t *)queue_remove(qp)) == NULL)
			continue;

		dm_process_sysevent(sevevp->evp);

		free_sysevent_event(sevevp);
	}

	/* Signal the thread spawner that we've exited */
	dm_assert(pthread_mutex_lock(&g_event_handler_lock) == 0);
	g_sysev_thread_state = TS_EXITED;
	(void) pthread_cond_broadcast(&g_event_handler_cond);
	dm_assert(pthread_mutex_unlock(&g_event_handler_lock) == 0);

	log_msg(MM_HPMGR, "FMD sysevent handler thread exiting...");
}

static sysevent_event_t *
new_sysevent_event(sysevent_t *ev)
{
	/*
	 * Cannot use dmalloc for this because the thread isn't a FMD-created
	 * thread!
	 */
	sysevent_event_t *sevevp = malloc(sizeof (sysevent_event_t));
	sevevp->evp = ev;
	return (sevevp);
}

static void
free_sysevent_event(void *p)
{
	/* the sysevent_event was allocated with malloc(): */
	free(p);
}

static void
event_handler(sysevent_t *ev)
{
	/* The duplicated sysevent will be freed in the child thread */
	sysevent_t	*dupev = sysevent_dup(ev);

	/*
	 * Add this sysevent to the work queue of our FMA thread so we can
	 * handle the sysevent and use the FMA API (e.g. for memory
	 * allocation, etc.) in the sysevent handler.
	 */
	queue_add(g_sysev_queue, new_sysevent_event(dupev));
}

static void
fini_sysevents(void)
{
	sysevent_unsubscribe_event(sysevent_handle, EC_ALL);
}

static int
init_sysevents(void)
{
	int rv = 0;
	const char *devfs_subclasses[] = {
		ESC_DEVFS_DEVI_ADD,
		ESC_DEVFS_DEVI_REMOVE
	};
	const char *dr_subclasses[] = {
		ESC_DR_AP_STATE_CHANGE,
		ESC_DR_TARGET_STATE_CHANGE
	};
	const char *platform_subclasses[] = {
		ESC_PLATFORM_SP_RESET
	};

	if ((sysevent_handle = sysevent_bind_handle(event_handler)) == NULL) {
		rv = errno;
		log_err("Could not initialize the hotplug manager ("
		    "sysevent_bind_handle failure");
	}

	if (sysevent_subscribe_event(sysevent_handle, EC_DEVFS,
	    devfs_subclasses,
	    sizeof (devfs_subclasses)/sizeof (devfs_subclasses[0])) != 0) {

		log_err("Could not initialize the hotplug manager "
		    "sysevent_subscribe_event(event class = EC_DEVFS) "
		    "failure");

		rv = -1;

	} else if (sysevent_subscribe_event(sysevent_handle, EC_DR,
	    dr_subclasses,
	    sizeof (dr_subclasses)/sizeof (dr_subclasses[0])) != 0) {

		log_err("Could not initialize the hotplug manager "
		    "sysevent_subscribe_event(event class = EC_DR) "
		    "failure");

		/* Unsubscribe from all sysevents in the event of a failure */
		fini_sysevents();

		rv = -1;
	} else if (sysevent_subscribe_event(sysevent_handle, EC_PLATFORM,
	    platform_subclasses,
	    sizeof (platform_subclasses)/sizeof (platform_subclasses[0]))
	    != 0) {

		log_err("Could not initialize the hotplug manager "
		    "sysevent_subscribe_event(event class = EC_PLATFORM) "
		    "failure");

		/* Unsubscribe from all sysevents in the event of a failure */
		fini_sysevents();

		rv = -1;
	}


	return (rv);
}

/*ARGSUSED*/
static void
stdfree(void *p, size_t sz)
{
	free(p);
}

/*
 * Assumptions: Each disk's current state was determined and stored in
 * its diskmon_t.
 */
hotplug_mgr_init_err_t
init_hotplug_manager()
{
	/* Create the queue to which we'll add sysevents */
	g_sysev_queue = new_queue(B_TRUE, malloc, stdfree, free_sysevent_event);

	/*
	 * Grab the event handler lock before spawning the thread so we can
	 * wait for the thread to transition to the running state.
	 */
	dm_assert(pthread_mutex_lock(&g_event_handler_lock) == 0);

	/* Create the sysevent handling thread */
	g_sysev_tid = fmd_thr_create(g_fm_hdl, dm_fmd_sysevent_thread,
	    g_sysev_queue);

	/* Wait for the thread's acknowledgement */
	while (g_sysev_thread_state != TS_RUNNING)
		(void) pthread_cond_wait(&g_event_handler_cond,
		    &g_event_handler_lock);
	dm_assert(pthread_mutex_unlock(&g_event_handler_lock) == 0);

	if (init_sysevents() != 0) {
		log_warn_e("Error initializing sysevents");
		return (HPM_ERR_SYSEVENT_INIT);
	}

	return (0);
}

void
cleanup_hotplug_manager()
{
	/* Unsubscribe from the sysevents */
	fini_sysevents();

	/*
	 * Wait for the thread to exit before we can destroy
	 * the event queue.
	 */
	dm_assert(pthread_mutex_lock(&g_event_handler_lock) == 0);
	g_sysev_thread_state = TS_EXIT_REQUESTED;
	queue_add(g_sysev_queue, NULL);
	while (g_sysev_thread_state != TS_EXITED)
		(void) pthread_cond_wait(&g_event_handler_cond,
		    &g_event_handler_lock);
	dm_assert(pthread_mutex_unlock(&g_event_handler_lock) == 0);
	(void) pthread_join(g_sysev_tid, NULL);
	fmd_thr_destroy(g_fm_hdl, g_sysev_tid);

	/* Finally, destroy the event queue and reset the thread state */
	queue_free(&g_sysev_queue);
	g_sysev_thread_state = TS_NOT_RUNNING;
}
