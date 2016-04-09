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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2012 by Delphix. All rights reserved.
 * Copyright 2015 Nexenta Systems, Inc. All rights reserved.
 */

/*
 * ZFS syseventd module.
 *
 * The purpose of this module is to identify when devices are added to the
 * system, and appropriately online or replace the affected vdevs.
 *
 * When a device is added to the system:
 *
 * 	1. Search for any vdevs whose devid matches that of the newly added
 *	   device.
 *
 * 	2. If no vdevs are found, then search for any vdevs whose devfs path
 *	   matches that of the new device.
 *
 *	3. If no vdevs match by either method, then ignore the event.
 *
 * 	4. Attempt to online the device with a flag to indicate that it should
 *	   be unspared when resilvering completes.  If this succeeds, then the
 *	   same device was inserted and we should continue normally.
 *
 *	5. If the pool does not have the 'autoreplace' property set, attempt to
 *	   online the device again without the unspare flag, which will
 *	   generate a FMA fault.
 *
 *	6. If the pool has the 'autoreplace' property set, and the matching vdev
 *	   is a whole disk, then label the new disk and attempt a 'zpool
 *	   replace'.
 *
 * The module responds to EC_DEV_ADD events for both disks and lofi devices,
 * with the latter used for testing.  The special ESC_ZFS_VDEV_CHECK event
 * indicates that a device failed to open during pool load, but the autoreplace
 * property was set.  In this case, we deferred the associated FMA fault until
 * our module had a chance to process the autoreplace logic.  If the device
 * could not be replaced, then the second online attempt will trigger the FMA
 * fault that we skipped earlier.
 */

#include <alloca.h>
#include <devid.h>
#include <fcntl.h>
#include <libnvpair.h>
#include <libsysevent.h>
#include <libzfs.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <sys/list.h>
#include <sys/sunddi.h>
#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/dev.h>
#include <thread_pool.h>
#include <unistd.h>
#include "syseventd.h"

#if defined(__i386) || defined(__amd64)
#define	PHYS_PATH	":q"
#define	RAW_SLICE	"p0"
#elif defined(__sparc)
#define	PHYS_PATH	":c"
#define	RAW_SLICE	"s2"
#else
#error Unknown architecture
#endif

typedef void (*zfs_process_func_t)(zpool_handle_t *, nvlist_t *, boolean_t);

libzfs_handle_t *g_zfshdl;
list_t g_pool_list;
tpool_t *g_tpool;
boolean_t g_enumeration_done;
thread_t g_zfs_tid;

typedef struct unavailpool {
	zpool_handle_t	*uap_zhp;
	list_node_t	uap_node;
} unavailpool_t;

int
zfs_toplevel_state(zpool_handle_t *zhp)
{
	nvlist_t *nvroot;
	vdev_stat_t *vs;
	unsigned int c;

	verify(nvlist_lookup_nvlist(zpool_get_config(zhp, NULL),
	    ZPOOL_CONFIG_VDEV_TREE, &nvroot) == 0);
	verify(nvlist_lookup_uint64_array(nvroot, ZPOOL_CONFIG_VDEV_STATS,
	    (uint64_t **)&vs, &c) == 0);
	return (vs->vs_state);
}

static int
zfs_unavail_pool(zpool_handle_t *zhp, void *data)
{
	if (zfs_toplevel_state(zhp) < VDEV_STATE_DEGRADED) {
		unavailpool_t *uap;
		uap = malloc(sizeof (unavailpool_t));
		uap->uap_zhp = zhp;
		list_insert_tail((list_t *)data, uap);
	} else {
		zpool_close(zhp);
	}
	return (0);
}

/*
 * The device associated with the given vdev (either by devid or physical path)
 * has been added to the system.  If 'isdisk' is set, then we only attempt a
 * replacement if it's a whole disk.  This also implies that we should label the
 * disk first.
 *
 * First, we attempt to online the device (making sure to undo any spare
 * operation when finished).  If this succeeds, then we're done.  If it fails,
 * and the new state is VDEV_CANT_OPEN, it indicates that the device was opened,
 * but that the label was not what we expected.  If the 'autoreplace' property
 * is not set, then we relabel the disk (if specified), and attempt a 'zpool
 * replace'.  If the online is successful, but the new state is something else
 * (REMOVED or FAULTED), it indicates that we're out of sync or in some sort of
 * race, and we should avoid attempting to relabel the disk.
 */
static void
zfs_process_add(zpool_handle_t *zhp, nvlist_t *vdev, boolean_t isdisk)
{
	char *path;
	vdev_state_t newstate;
	nvlist_t *nvroot, *newvd;
	uint64_t wholedisk = 0ULL;
	uint64_t offline = 0ULL;
	char *physpath = NULL;
	char rawpath[PATH_MAX], fullpath[PATH_MAX];
	size_t len;

	if (nvlist_lookup_string(vdev, ZPOOL_CONFIG_PATH, &path) != 0)
		return;

	(void) nvlist_lookup_string(vdev, ZPOOL_CONFIG_PHYS_PATH, &physpath);
	(void) nvlist_lookup_uint64(vdev, ZPOOL_CONFIG_WHOLE_DISK, &wholedisk);
	(void) nvlist_lookup_uint64(vdev, ZPOOL_CONFIG_OFFLINE, &offline);

	/*
	 * We should have a way to online a device by guid.  With the current
	 * interface, we are forced to chop off the 's0' for whole disks.
	 */
	(void) strlcpy(fullpath, path, sizeof (fullpath));
	if (wholedisk)
		fullpath[strlen(fullpath) - 2] = '\0';

	/*
	 * Attempt to online the device.  It would be nice to online this by
	 * GUID, but the current interface only supports lookup by path.
	 */
	if (offline ||
	    (zpool_vdev_online(zhp, fullpath,
	    ZFS_ONLINE_CHECKREMOVE | ZFS_ONLINE_UNSPARE, &newstate) == 0 &&
	    (newstate == VDEV_STATE_HEALTHY ||
	    newstate == VDEV_STATE_DEGRADED)))
		return;

	/*
	 * If the pool doesn't have the autoreplace property set, then attempt a
	 * true online (without the unspare flag), which will trigger a FMA
	 * fault.
	 */
	if (!zpool_get_prop_int(zhp, ZPOOL_PROP_AUTOREPLACE, NULL) ||
	    (isdisk && !wholedisk)) {
		(void) zpool_vdev_online(zhp, fullpath, ZFS_ONLINE_FORCEFAULT,
		    &newstate);
		return;
	}

	if (isdisk) {
		/*
		 * If this is a request to label a whole disk, then attempt to
		 * write out the label.  Before we can label the disk, we need
		 * access to a raw node.  Ideally, we'd like to walk the devinfo
		 * tree and find a raw node from the corresponding parent node.
		 * This is overly complicated, and since we know how we labeled
		 * this device in the first place, we know it's save to switch
		 * from /dev/dsk to /dev/rdsk and append the backup slice.
		 *
		 * If any part of this process fails, then do a force online to
		 * trigger a ZFS fault for the device (and any hot spare
		 * replacement).
		 */
		if (strncmp(path, ZFS_DISK_ROOTD,
		    strlen(ZFS_DISK_ROOTD)) != 0) {
			(void) zpool_vdev_online(zhp, fullpath,
			    ZFS_ONLINE_FORCEFAULT, &newstate);
			return;
		}

		(void) strlcpy(rawpath, path + 9, sizeof (rawpath));
		len = strlen(rawpath);
		rawpath[len - 2] = '\0';

		if (zpool_label_disk(g_zfshdl, zhp, rawpath) != 0) {
			(void) zpool_vdev_online(zhp, fullpath,
			    ZFS_ONLINE_FORCEFAULT, &newstate);
			return;
		}
	}

	/*
	 * Cosntruct the root vdev to pass to zpool_vdev_attach().  While adding
	 * the entire vdev structure is harmless, we construct a reduced set of
	 * path/physpath/wholedisk to keep it simple.
	 */
	if (nvlist_alloc(&nvroot, NV_UNIQUE_NAME, 0) != 0)
		return;

	if (nvlist_alloc(&newvd, NV_UNIQUE_NAME, 0) != 0) {
		nvlist_free(nvroot);
		return;
	}

	if (nvlist_add_string(newvd, ZPOOL_CONFIG_TYPE, VDEV_TYPE_DISK) != 0 ||
	    nvlist_add_string(newvd, ZPOOL_CONFIG_PATH, path) != 0 ||
	    (physpath != NULL && nvlist_add_string(newvd,
	    ZPOOL_CONFIG_PHYS_PATH, physpath) != 0) ||
	    nvlist_add_uint64(newvd, ZPOOL_CONFIG_WHOLE_DISK, wholedisk) != 0 ||
	    nvlist_add_string(nvroot, ZPOOL_CONFIG_TYPE, VDEV_TYPE_ROOT) != 0 ||
	    nvlist_add_nvlist_array(nvroot, ZPOOL_CONFIG_CHILDREN, &newvd,
	    1) != 0) {
		nvlist_free(newvd);
		nvlist_free(nvroot);
		return;
	}

	nvlist_free(newvd);

	(void) zpool_vdev_attach(zhp, fullpath, path, nvroot, B_TRUE);

	nvlist_free(nvroot);

}

/*
 * Utility functions to find a vdev matching given criteria.
 */
typedef struct dev_data {
	const char		*dd_compare;
	const char		*dd_prop;
	zfs_process_func_t	dd_func;
	boolean_t		dd_found;
	boolean_t		dd_isdisk;
	uint64_t		dd_pool_guid;
	uint64_t		dd_vdev_guid;
} dev_data_t;

static void
zfs_iter_vdev(zpool_handle_t *zhp, nvlist_t *nvl, void *data)
{
	dev_data_t *dp = data;
	char *path;
	uint_t c, children;
	nvlist_t **child;
	size_t len;
	uint64_t guid;

	/*
	 * First iterate over any children.
	 */
	if (nvlist_lookup_nvlist_array(nvl, ZPOOL_CONFIG_CHILDREN,
	    &child, &children) == 0) {
		for (c = 0; c < children; c++)
			zfs_iter_vdev(zhp, child[c], data);
		return;
	}

	if (dp->dd_vdev_guid != 0) {
		if (nvlist_lookup_uint64(nvl, ZPOOL_CONFIG_GUID,
		    &guid) != 0 || guid != dp->dd_vdev_guid)
			return;
	} else if (dp->dd_compare != NULL) {
		len = strlen(dp->dd_compare);

		if (nvlist_lookup_string(nvl, dp->dd_prop, &path) != 0 ||
		    strncmp(dp->dd_compare, path, len) != 0)
			return;

		/*
		 * Normally, we want to have an exact match for the comparison
		 * string.  However, we allow substring matches in the following
		 * cases:
		 *
		 * 	<path>:		This is a devpath, and the target is one
		 * 			of its children.
		 *
		 * 	<path/>		This is a devid for a whole disk, and
		 * 			the target is one of its children.
		 */
		if (path[len] != '\0' && path[len] != ':' &&
		    path[len - 1] != '/')
			return;
	}

	(dp->dd_func)(zhp, nvl, dp->dd_isdisk);
}

void
zfs_enable_ds(void *arg)
{
	unavailpool_t *pool = (unavailpool_t *)arg;

	(void) zpool_enable_datasets(pool->uap_zhp, NULL, 0);
	zpool_close(pool->uap_zhp);
	free(pool);
}

static int
zfs_iter_pool(zpool_handle_t *zhp, void *data)
{
	nvlist_t *config, *nvl;
	dev_data_t *dp = data;
	uint64_t pool_guid;
	unavailpool_t *pool;

	if ((config = zpool_get_config(zhp, NULL)) != NULL) {
		if (dp->dd_pool_guid == 0 ||
		    (nvlist_lookup_uint64(config, ZPOOL_CONFIG_POOL_GUID,
		    &pool_guid) == 0 && pool_guid == dp->dd_pool_guid)) {
			(void) nvlist_lookup_nvlist(config,
			    ZPOOL_CONFIG_VDEV_TREE, &nvl);
			zfs_iter_vdev(zhp, nvl, data);
		}
	}
	if (g_enumeration_done)  {
		for (pool = list_head(&g_pool_list); pool != NULL;
		    pool = list_next(&g_pool_list, pool)) {

			if (strcmp(zpool_get_name(zhp),
			    zpool_get_name(pool->uap_zhp)))
				continue;
			if (zfs_toplevel_state(zhp) >= VDEV_STATE_DEGRADED) {
				list_remove(&g_pool_list, pool);
				(void) tpool_dispatch(g_tpool, zfs_enable_ds,
				    pool);
				break;
			}
		}
	}

	zpool_close(zhp);
	return (0);
}

/*
 * Given a physical device path, iterate over all (pool, vdev) pairs which
 * correspond to the given path.
 */
static boolean_t
devpath_iter(const char *devpath, zfs_process_func_t func, boolean_t wholedisk)
{
	dev_data_t data = { 0 };

	data.dd_compare = devpath;
	data.dd_func = func;
	data.dd_prop = ZPOOL_CONFIG_PHYS_PATH;
	data.dd_found = B_FALSE;
	data.dd_isdisk = wholedisk;

	(void) zpool_iter(g_zfshdl, zfs_iter_pool, &data);

	return (data.dd_found);
}

/*
 * Given a /devices path, lookup the corresponding devid for each minor node,
 * and find any vdevs with matching devids.  Doing this straight up would be
 * rather inefficient, O(minor nodes * vdevs in system), so we take advantage of
 * the fact that each devid ends with "/<minornode>".  Once we find any valid
 * minor node, we chop off the portion after the last slash, and then search for
 * matching vdevs, which is O(vdevs in system).
 */
static boolean_t
devid_iter(const char *devpath, zfs_process_func_t func, boolean_t wholedisk)
{
	size_t len = strlen(devpath) + sizeof ("/devices") +
	    sizeof (PHYS_PATH) - 1;
	char *fullpath;
	int fd;
	ddi_devid_t devid;
	char *devidstr, *fulldevid;
	dev_data_t data = { 0 };

	/*
	 * Try to open a known minor node.
	 */
	fullpath = alloca(len);
	(void) snprintf(fullpath, len, "/devices%s%s", devpath, PHYS_PATH);
	if ((fd = open(fullpath, O_RDONLY)) < 0)
		return (B_FALSE);

	/*
	 * Determine the devid as a string, with no trailing slash for the minor
	 * node.
	 */
	if (devid_get(fd, &devid) != 0) {
		(void) close(fd);
		return (B_FALSE);
	}
	(void) close(fd);

	if ((devidstr = devid_str_encode(devid, NULL)) == NULL) {
		devid_free(devid);
		return (B_FALSE);
	}

	len = strlen(devidstr) + 2;
	fulldevid = alloca(len);
	(void) snprintf(fulldevid, len, "%s/", devidstr);

	data.dd_compare = fulldevid;
	data.dd_func = func;
	data.dd_prop = ZPOOL_CONFIG_DEVID;
	data.dd_found = B_FALSE;
	data.dd_isdisk = wholedisk;

	(void) zpool_iter(g_zfshdl, zfs_iter_pool, &data);

	devid_str_free(devidstr);
	devid_free(devid);

	return (data.dd_found);
}

/*
 * This function is called when we receive a devfs add event.  This can be
 * either a disk event or a lofi event, and the behavior is slightly different
 * depending on which it is.
 */
static int
zfs_deliver_add(nvlist_t *nvl, boolean_t is_lofi)
{
	char *devpath, *devname;
	char path[PATH_MAX], realpath[PATH_MAX];
	char *colon, *raw;
	int ret;

	/*
	 * The main unit of operation is the physical device path.  For disks,
	 * this is the device node, as all minor nodes are affected.  For lofi
	 * devices, this includes the minor path.  Unfortunately, this isn't
	 * represented in the DEV_PHYS_PATH for various reasons.
	 */
	if (nvlist_lookup_string(nvl, DEV_PHYS_PATH, &devpath) != 0)
		return (-1);

	/*
	 * If this is a lofi device, then also get the minor instance name.
	 * Unfortunately, the current payload doesn't include an easy way to get
	 * this information.  So we cheat by resolving the 'dev_name' (which
	 * refers to the raw device) and taking the portion between ':(*),raw'.
	 */
	(void) strlcpy(realpath, devpath, sizeof (realpath));
	if (is_lofi) {
		if (nvlist_lookup_string(nvl, DEV_NAME,
		    &devname) == 0 &&
		    (ret = resolvepath(devname, path,
		    sizeof (path))) > 0) {
			path[ret] = '\0';
			colon = strchr(path, ':');
			if (colon != NULL)
				raw = strstr(colon + 1, ",raw");
			if (colon != NULL && raw != NULL) {
				*raw = '\0';
				(void) snprintf(realpath,
				    sizeof (realpath), "%s%s",
				    devpath, colon);
				*raw = ',';
			}
		}
	}

	/*
	 * Iterate over all vdevs with a matching devid, and then those with a
	 * matching /devices path.  For disks, we only want to pay attention to
	 * vdevs marked as whole disks.  For lofi, we don't care (because we're
	 * matching an exact minor name).
	 */
	if (!devid_iter(realpath, zfs_process_add, !is_lofi))
		(void) devpath_iter(realpath, zfs_process_add, !is_lofi);

	return (0);
}

/*
 * Called when we receive a VDEV_CHECK event, which indicates a device could not
 * be opened during initial pool open, but the autoreplace property was set on
 * the pool.  In this case, we treat it as if it were an add event.
 */
static int
zfs_deliver_check(nvlist_t *nvl)
{
	dev_data_t data = { 0 };

	if (nvlist_lookup_uint64(nvl, ZFS_EV_POOL_GUID,
	    &data.dd_pool_guid) != 0 ||
	    nvlist_lookup_uint64(nvl, ZFS_EV_VDEV_GUID,
	    &data.dd_vdev_guid) != 0 ||
	    data.dd_vdev_guid == 0)
		return (0);

	data.dd_isdisk = B_TRUE;
	data.dd_func = zfs_process_add;

	(void) zpool_iter(g_zfshdl, zfs_iter_pool, &data);

	return (0);
}

#define	DEVICE_PREFIX	"/devices"

static int
zfsdle_vdev_online(zpool_handle_t *zhp, void *data)
{
	char *devname = data;
	boolean_t avail_spare, l2cache;
	vdev_state_t newstate;
	nvlist_t *tgt;

	syseventd_print(9, "zfsdle_vdev_online: searching for %s in pool %s\n",
	    devname, zpool_get_name(zhp));

	if ((tgt = zpool_find_vdev_by_physpath(zhp, devname,
	    &avail_spare, &l2cache, NULL)) != NULL) {
		char *path, fullpath[MAXPATHLEN];
		uint64_t wholedisk = 0ULL;

		verify(nvlist_lookup_string(tgt, ZPOOL_CONFIG_PATH,
		    &path) == 0);
		verify(nvlist_lookup_uint64(tgt, ZPOOL_CONFIG_WHOLE_DISK,
		    &wholedisk) == 0);

		(void) strlcpy(fullpath, path, sizeof (fullpath));
		if (wholedisk) {
			fullpath[strlen(fullpath) - 2] = '\0';

			/*
			 * We need to reopen the pool associated with this
			 * device so that the kernel can update the size
			 * of the expanded device.
			 */
			(void) zpool_reopen(zhp);
		}

		if (zpool_get_prop_int(zhp, ZPOOL_PROP_AUTOEXPAND, NULL)) {
			syseventd_print(9, "zfsdle_vdev_online: setting device"
			    " device %s to ONLINE state in pool %s.\n",
			    fullpath, zpool_get_name(zhp));
			if (zpool_get_state(zhp) != POOL_STATE_UNAVAIL)
				(void) zpool_vdev_online(zhp, fullpath, 0,
				    &newstate);
		}
		zpool_close(zhp);
		return (1);
	}
	zpool_close(zhp);
	return (0);
}

/*
 * This function is called for each vdev of a pool for which any of the
 * following events was recieved:
 *  - ESC_ZFS_vdev_add
 *  - ESC_ZFS_vdev_attach
 *  - ESC_ZFS_vdev_clear
 *  - ESC_ZFS_vdev_online
 *  - ESC_ZFS_pool_create
 *  - ESC_ZFS_pool_import
 * It will update the vdevs FRU property if it is out of date.
 */
/*ARGSUSED2*/
static void
zfs_update_vdev_fru(zpool_handle_t *zhp, nvlist_t *vdev, boolean_t isdisk)
{
	char *devpath, *cptr, *oldfru = NULL;
	const char *newfru;
	uint64_t vdev_guid;

	(void) nvlist_lookup_uint64(vdev, ZPOOL_CONFIG_GUID, &vdev_guid);
	(void) nvlist_lookup_string(vdev, ZPOOL_CONFIG_PHYS_PATH, &devpath);
	(void) nvlist_lookup_string(vdev, ZPOOL_CONFIG_FRU, &oldfru);

	/* remove :<slice> from devpath */
	cptr = strrchr(devpath, ':');
	if (cptr != NULL)
		*cptr = '\0';

	newfru = libzfs_fru_lookup(g_zfshdl, devpath);
	if (newfru == NULL) {
		syseventd_print(9, "zfs_update_vdev_fru: no FRU for %s\n",
		    devpath);
		return;
	}

	/* do nothing if the FRU hasn't changed */
	if (oldfru != NULL && libzfs_fru_compare(g_zfshdl, oldfru, newfru)) {
		syseventd_print(9, "zfs_update_vdev_fru: FRU unchanged\n");
		return;
	}

	syseventd_print(9, "zfs_update_vdev_fru: devpath = %s\n", devpath);
	syseventd_print(9, "zfs_update_vdev_fru: FRU = %s\n", newfru);

	(void) zpool_fru_set(zhp, vdev_guid, newfru);
}

/*
 * This function handles the following events:
 *  - ESC_ZFS_vdev_add
 *  - ESC_ZFS_vdev_attach
 *  - ESC_ZFS_vdev_clear
 *  - ESC_ZFS_vdev_online
 *  - ESC_ZFS_pool_create
 *  - ESC_ZFS_pool_import
 * It will iterate over the pool vdevs to update the FRU property.
 */
int
zfs_deliver_update(nvlist_t *nvl)
{
	dev_data_t dd = { 0 };
	char *pname;
	zpool_handle_t *zhp;
	nvlist_t *config, *vdev;

	if (nvlist_lookup_string(nvl, "pool_name", &pname) != 0) {
		syseventd_print(9, "zfs_deliver_update: no pool name\n");
		return (-1);
	}

	/*
	 * If this event was triggered by a pool export or destroy we cannot
	 * open the pool. This is not an error, just return 0 as we don't care
	 * about these events.
	 */
	zhp = zpool_open_canfail(g_zfshdl, pname);
	if (zhp == NULL)
		return (0);

	config = zpool_get_config(zhp, NULL);
	if (config == NULL) {
		syseventd_print(9, "zfs_deliver_update: "
		    "failed to get pool config for %s\n", pname);
		zpool_close(zhp);
		return (-1);
	}

	if (nvlist_lookup_nvlist(config, ZPOOL_CONFIG_VDEV_TREE, &vdev) != 0) {
		syseventd_print(0, "zfs_deliver_update: "
		    "failed to get vdev tree for %s\n", pname);
		zpool_close(zhp);
		return (-1);
	}

	libzfs_fru_refresh(g_zfshdl);

	dd.dd_func = zfs_update_vdev_fru;
	zfs_iter_vdev(zhp, vdev, &dd);

	zpool_close(zhp);
	return (0);
}

int
zfs_deliver_dle(nvlist_t *nvl)
{
	char *devname;
	if (nvlist_lookup_string(nvl, DEV_PHYS_PATH, &devname) != 0) {
		syseventd_print(9, "zfs_deliver_event: no physpath\n");
		return (-1);
	}
	if (strncmp(devname, DEVICE_PREFIX, strlen(DEVICE_PREFIX)) != 0) {
		syseventd_print(9, "zfs_deliver_event: invalid "
		    "device '%s'", devname);
		return (-1);
	}

	/*
	 * We try to find the device using the physical
	 * path that has been supplied. We need to strip off
	 * the /devices prefix before starting our search.
	 */
	devname += strlen(DEVICE_PREFIX);
	if (zpool_iter(g_zfshdl, zfsdle_vdev_online, devname) != 1) {
		syseventd_print(9, "zfs_deliver_event: device '%s' not"
		    " found\n", devname);
		return (1);
	}
	return (0);
}


/*ARGSUSED*/
static int
zfs_deliver_event(sysevent_t *ev, int unused)
{
	const char *class = sysevent_get_class_name(ev);
	const char *subclass = sysevent_get_subclass_name(ev);
	nvlist_t *nvl;
	int ret;
	boolean_t is_lofi = B_FALSE, is_check = B_FALSE;
	boolean_t is_dle = B_FALSE, is_update = B_FALSE;

	if (strcmp(class, EC_DEV_ADD) == 0) {
		/*
		 * We're mainly interested in disk additions, but we also listen
		 * for new lofi devices, to allow for simplified testing.
		 */
		if (strcmp(subclass, ESC_DISK) == 0)
			is_lofi = B_FALSE;
		else if (strcmp(subclass, ESC_LOFI) == 0)
			is_lofi = B_TRUE;
		else
			return (0);

		is_check = B_FALSE;
	} else if (strcmp(class, EC_ZFS) == 0) {
		if (strcmp(subclass, ESC_ZFS_VDEV_CHECK) == 0) {
			/*
			 * This event signifies that a device failed to open
			 * during pool load, but the 'autoreplace' property was
			 * set, so we should pretend it's just been added.
			 */
			is_check = B_TRUE;
		} else if ((strcmp(subclass, ESC_ZFS_VDEV_ADD) == 0) ||
		    (strcmp(subclass, ESC_ZFS_VDEV_ATTACH) == 0) ||
		    (strcmp(subclass, ESC_ZFS_VDEV_CLEAR) == 0) ||
		    (strcmp(subclass, ESC_ZFS_VDEV_ONLINE) == 0) ||
		    (strcmp(subclass, ESC_ZFS_POOL_CREATE) == 0) ||
		    (strcmp(subclass, ESC_ZFS_POOL_IMPORT) == 0)) {
			/*
			 * When we receive these events we check the pool
			 * configuration and update the vdev FRUs if necessary.
			 */
			is_update = B_TRUE;
		}
	} else if (strcmp(class, EC_DEV_STATUS) == 0 &&
	    strcmp(subclass, ESC_DEV_DLE) == 0) {
		is_dle = B_TRUE;
	} else {
		return (0);
	}

	if (sysevent_get_attr_list(ev, &nvl) != 0)
		return (-1);

	if (is_dle)
		ret = zfs_deliver_dle(nvl);
	else if (is_update)
		ret = zfs_deliver_update(nvl);
	else if (is_check)
		ret = zfs_deliver_check(nvl);
	else
		ret = zfs_deliver_add(nvl, is_lofi);

	nvlist_free(nvl);
	return (ret);
}

/*ARGSUSED*/
void *
zfs_enum_pools(void *arg)
{
	(void) zpool_iter(g_zfshdl, zfs_unavail_pool, (void *)&g_pool_list);
	if (!list_is_empty(&g_pool_list))
		g_tpool = tpool_create(1, sysconf(_SC_NPROCESSORS_ONLN),
		    0, NULL);
	g_enumeration_done = B_TRUE;
	return (NULL);
}

static struct slm_mod_ops zfs_mod_ops = {
	SE_MAJOR_VERSION, SE_MINOR_VERSION, 10, zfs_deliver_event
};

struct slm_mod_ops *
slm_init()
{
	if ((g_zfshdl = libzfs_init()) == NULL)
		return (NULL);
	/*
	 * collect a list of unavailable pools (asynchronously,
	 * since this can take a while)
	 */
	list_create(&g_pool_list, sizeof (struct unavailpool),
	    offsetof(struct unavailpool, uap_node));
	if (thr_create(NULL, 0, zfs_enum_pools, NULL, 0, &g_zfs_tid) != 0)
		return (NULL);
	return (&zfs_mod_ops);
}

void
slm_fini()
{
	unavailpool_t *pool;

	if (g_tpool != NULL) {
		tpool_wait(g_tpool);
		tpool_destroy(g_tpool);
	}
	while ((pool = (list_head(&g_pool_list))) != NULL) {
		list_remove(&g_pool_list, pool);
		zpool_close(pool->uap_zhp);
		free(pool);
	}
	(void) thr_join(g_zfs_tid, NULL, NULL);
	list_destroy(&g_pool_list);
	libzfs_fini(g_zfshdl);
}
