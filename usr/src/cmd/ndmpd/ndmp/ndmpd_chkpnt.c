/*
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2013, 2015 by Delphix. All rights reserved.
 * Copyright (c) 2013 Steven Hartland. All rights reserved.
 * Copyright (c) 2016 Martin Matuska. All rights reserved.
 */

/*
 * BSD 3 Clause License
 *
 * Copyright (c) 2007, The Storage Networking Industry Association.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 	- Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *
 * 	- Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in
 *	  the documentation and/or other materials provided with the
 *	  distribution.
 *
 *	- Neither the name of The Storage Networking Industry Association (SNIA)
 *	  nor the names of its contributors may be used to endorse or promote
 *	  products derived from this software without specific prior written
 *	  permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <stdio.h>
#include <string.h>
#include "ndmpd.h"
#include <libzfs.h>

typedef struct snap_param {
	char *snp_name;
	boolean_t snp_found;
} snap_param_t;

static int cleanup_fd = -1;

/*
 * ndmp_has_backup
 *
 * Call backup function which looks for backup snapshot.
 * This is a callback function used with zfs_iter_snapshots.
 *
 * Parameters:
 *   zhp (input) - ZFS handle pointer
 *   data (output) - 0 - no backup snapshot
 *		     1 - has backup snapshot
 *
 * Returns:
 *   0: on success
 *  -1: otherwise
 */
static int
ndmp_has_backup(zfs_handle_t *zhp, void *data)
{
	const char *name;
	snap_param_t *chp = (snap_param_t *)data;

	name = zfs_get_name(zhp);
	if (name == NULL ||
	    strstr(name, chp->snp_name) == NULL) {
		zfs_close(zhp);
		return (-1);
	}

	chp->snp_found = 1;
	zfs_close(zhp);

	return (0);
}

/*
 * ndmp_has_backup_snapshot
 *
 * Returns TRUE if the volume has an active backup snapshot, otherwise,
 * returns FALSE.
 *
 * Parameters:
 *   volname (input) - name of the volume
 *
 * Returns:
 *   0: on success
 *  -1: otherwise
 */
static int
ndmp_has_backup_snapshot(char *volname, char *jobname)
{
	zfs_handle_t *zhp;
	snap_param_t snp;
	char chname[ZFS_MAX_DATASET_NAME_LEN];

	(void) mutex_lock(&zlib_mtx);
	if ((zhp = zfs_open(zlibh, volname, ZFS_TYPE_DATASET)) == 0) {
		NDMP_LOG(LOG_ERR, "Cannot open snapshot %s.", volname);
		(void) mutex_unlock(&zlib_mtx);
		return (-1);
	}

	snp.snp_found = 0;
	(void) snprintf(chname, ZFS_MAX_DATASET_NAME_LEN, "@%s", jobname);
	snp.snp_name = chname;

	(void) zfs_iter_snapshots(zhp, B_FALSE, ndmp_has_backup, &snp);
	zfs_close(zhp);
	(void) mutex_unlock(&zlib_mtx);

	return (snp.snp_found);
}

/*
 * ndmp_create_snapshot
 *
 * This function will parse the path to get the real volume name.
 * It will then create a snapshot based on volume and job name.
 * This function should be called before the NDMP backup is started.
 *
 * Parameters:
 *   vol_name (input) - name of the volume
 *
 * Returns:
 *   0: on success
 *   -1: otherwise
 */
int
ndmp_create_snapshot(char *vol_name, char *jname)
{
	char vol[ZFS_MAX_DATASET_NAME_LEN];

	if (vol_name == 0 ||
	    get_zfsvolname(vol, sizeof (vol), vol_name) == -1)
		return (0);

	/*
	 * If there is an old snapshot left from the previous
	 * backup it could be stale one and it must be
	 * removed before using it.
	 */
	if (ndmp_has_backup_snapshot(vol, jname))
		(void) snapshot_destroy(vol, jname, B_FALSE, B_TRUE, NULL);

	return (snapshot_create(vol, jname, B_FALSE, B_TRUE));
}

/*
 * ndmp_remove_snapshot
 *
 * This function will parse the path to get the real volume name.
 * It will then remove the snapshot for that volume and job name.
 * This function should be called after NDMP backup is finished.
 *
 * Parameters:
 *   vol_name (input) - name of the volume
 *
 * Returns:
 *   0: on success
 *   -1: otherwise
 */
int
ndmp_remove_snapshot(char *vol_name, char *jname)
{
	char vol[ZFS_MAX_DATASET_NAME_LEN];

	if (vol_name == 0 ||
	    get_zfsvolname(vol, sizeof (vol), vol_name) == -1)
		return (0);

	return (snapshot_destroy(vol, jname, B_FALSE, B_TRUE, NULL));
}

/*
 * Put a hold on snapshot
 */
int
snapshot_hold(char *volname, char *snapname, char *jname, boolean_t recursive)
{
	zfs_handle_t *zhp;
	char *p;

	if ((zhp = zfs_open(zlibh, volname, ZFS_TYPE_DATASET)) == 0) {
		NDMP_LOG(LOG_ERR, "Cannot open volume %s.", volname);
		return (-1);
	}

	if (cleanup_fd == -1 && (cleanup_fd = open(ZFS_DEV,
	    O_RDWR|O_EXCL)) < 0) {
		NDMP_LOG(LOG_ERR, "Cannot open dev %d", errno);
		zfs_close(zhp);
		return (-1);
	}

	p = strchr(snapname, '@') + 1;
	if (zfs_hold(zhp, p, jname, recursive, cleanup_fd) != 0) {
		NDMP_LOG(LOG_ERR, "Cannot hold snapshot %s", p);
		zfs_close(zhp);
		return (-1);
	}
	zfs_close(zhp);
	return (0);
}

int
snapshot_release(char *volname, char *snapname, char *jname,
    boolean_t recursive)
{
	zfs_handle_t *zhp;
	char *p;
	int rv = 0;

	if ((zhp = zfs_open(zlibh, volname, ZFS_TYPE_DATASET)) == 0) {
		NDMP_LOG(LOG_ERR, "Cannot open volume %s", volname);
		return (-1);
	}

	p = strchr(snapname, '@') + 1;
	if (zfs_release(zhp, p, jname, recursive) != 0) {
		NDMP_LOG(LOG_DEBUG, "Cannot release snapshot %s", p);
		rv = -1;
	}
	if (cleanup_fd != -1) {
		(void) close(cleanup_fd);
		cleanup_fd = -1;
	}
	zfs_close(zhp);
	return (rv);
}

/*
 * Create a snapshot on the volume
 */
int
snapshot_create(char *volname, char *jname, boolean_t recursive,
    boolean_t hold)
{
	char snapname[ZFS_MAX_DATASET_NAME_LEN];
	int rv;

	if (!volname || !*volname)
		return (-1);

	(void) snprintf(snapname, ZFS_MAX_DATASET_NAME_LEN,
	    "%s@%s", volname, jname);

	(void) mutex_lock(&zlib_mtx);
	if ((rv = zfs_snapshot(zlibh, snapname, recursive, NULL))
	    == -1) {
		if (errno == EEXIST) {
			(void) mutex_unlock(&zlib_mtx);
			return (0);
		}
		NDMP_LOG(LOG_DEBUG,
		    "snapshot_create: %s failed (err=%d): %s",
		    snapname, errno, libzfs_error_description(zlibh));
		(void) mutex_unlock(&zlib_mtx);
		return (rv);
	}
	if (hold && snapshot_hold(volname, snapname, jname, recursive) != 0) {
		NDMP_LOG(LOG_DEBUG,
		    "snapshot_create: %s hold failed (err=%d): %s",
		    snapname, errno, libzfs_error_description(zlibh));
		(void) mutex_unlock(&zlib_mtx);
		return (-1);
	}

	(void) mutex_unlock(&zlib_mtx);
	return (0);
}

/*
 * Remove and release the backup snapshot
 */
int
snapshot_destroy(char *volname, char *jname, boolean_t recursive,
    boolean_t hold, int *zfs_err)
{
	char snapname[ZFS_MAX_DATASET_NAME_LEN];
	zfs_handle_t *zhp;
	zfs_type_t ztype;
	char *namep;
	int err;

	if (zfs_err)
		*zfs_err = 0;

	if (!volname || !*volname)
		return (-1);

	if (recursive) {
		ztype = ZFS_TYPE_VOLUME | ZFS_TYPE_FILESYSTEM;
		namep = volname;
	} else {
		(void) snprintf(snapname, ZFS_MAX_DATASET_NAME_LEN,
		    "%s@%s", volname, jname);
		namep = snapname;
		ztype = ZFS_TYPE_SNAPSHOT;
	}

	(void) mutex_lock(&zlib_mtx);
	if (hold &&
	    snapshot_release(volname, namep, jname, recursive) != 0) {
		NDMP_LOG(LOG_DEBUG,
		    "snapshot_destroy: %s release failed (err=%d): %s",
		    namep, errno, libzfs_error_description(zlibh));
		(void) mutex_unlock(&zlib_mtx);
		return (-1);
	}

	if ((zhp = zfs_open(zlibh, namep, ztype)) == NULL) {
		NDMP_LOG(LOG_DEBUG, "snapshot_destroy: open %s failed",
		    namep);
		(void) mutex_unlock(&zlib_mtx);
		return (-1);
	}

	if (recursive) {
		err = zfs_destroy_snaps(zhp, jname, B_TRUE);
	} else {
		err = zfs_destroy(zhp, B_TRUE);
	}

	if (err) {
		NDMP_LOG(LOG_ERR, "%s (recursive destroy: %d): %d; %s; %s",
		    namep,
		    recursive,
		    libzfs_errno(zlibh),
		    libzfs_error_action(zlibh),
		    libzfs_error_description(zlibh));

		if (zfs_err)
			*zfs_err = err;
	}

	zfs_close(zhp);
	(void) mutex_unlock(&zlib_mtx);

	return (0);
}
