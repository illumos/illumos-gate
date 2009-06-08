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

#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>
#include <libintl.h>
#include <libnvpair.h>
#include <libzfs.h>

libzfs_handle_t *g_zfs;

int debug = 0;

#define	DEVICE_PREFIX	"/devices"

static int
zfsdle_vdev_online(zpool_handle_t *zhp, void *data)
{
	char *devname = data;
	boolean_t avail_spare, l2cache;
	vdev_state_t newstate;
	nvlist_t *tgt;

	if (debug) {
		syslog(LOG_ERR, "Searching for %s in pool %s\n",
		    devname, zpool_get_name(zhp));
	}

	if ((tgt = zpool_find_vdev_by_physpath(zhp, devname,
	    &avail_spare, &l2cache, NULL)) != NULL) {
		char *path, fullpath[MAXPATHLEN];
		uint64_t wholedisk = 0ULL;

		verify(nvlist_lookup_string(tgt, ZPOOL_CONFIG_PATH,
		    &path) == 0);
		verify(nvlist_lookup_uint64(tgt, ZPOOL_CONFIG_WHOLE_DISK,
		    &wholedisk) == 0);

		(void) strlcpy(fullpath, path, sizeof (fullpath));
		if (wholedisk)
			fullpath[strlen(fullpath) - 2] = '\0';

		if (zpool_get_prop_int(zhp, ZPOOL_PROP_AUTOEXPAND, NULL)) {
			if (debug) {
				syslog(LOG_ERR, "Setting device %s to ONLINE "
				    "state in pool %s.\n", fullpath,
				    zpool_get_name(zhp));
			}
			(void) zpool_vdev_online(zhp, fullpath, 0, &newstate);
		}

		return (1);
	}
	return (0);
}

int
main(int argc, char *argv[])
{
	char *devname;

	if ((g_zfs = libzfs_init()) == NULL) {
		(void) fprintf(stderr, gettext("internal error: failed to "
		    "initialize ZFS library\n"));
		return (1);
	}
	libzfs_print_on_error(g_zfs, B_TRUE);

	if (argc < 2) {
		(void) fprintf(stderr, gettext("missing argument\n"));
		libzfs_fini(g_zfs);
		return (1);
	}

	if (argc > 2) {
		(void) fprintf(stderr, gettext("too many arguments\n"));
		libzfs_fini(g_zfs);
		return (1);
	}
	devname = argv[1];
	if (strncmp(devname, DEVICE_PREFIX, strlen(DEVICE_PREFIX)) != 0) {
		(void) fprintf(stderr, gettext("invalid device name '%s'\n"),
		    devname);
		libzfs_fini(g_zfs);
		return (1);
	}

	/*
	 * We try to find the device using the physical
	 * path that has been supplied. We need to strip off
	 * the /devices prefix before starting our search.
	 */
	devname += strlen(DEVICE_PREFIX);
	if (zpool_iter(g_zfs, zfsdle_vdev_online, devname) != 1) {
		if (debug)
			syslog(LOG_ERR, "device '%s': not found\n", argv[1]);
	}
	libzfs_fini(g_zfs);
	return (0);
}
