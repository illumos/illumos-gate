/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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

ndmp_chkpnt_vol_t *chkpnt_vols = NULL;

typedef struct chkpnt_param {
	char *chp_name;
	boolean_t chp_found;
} chkpnt_param_t;

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
	chkpnt_param_t *chp = (chkpnt_param_t *)data;

	name = zfs_get_name(zhp);
	if (name == NULL ||
	    strstr(name, chp->chp_name) == NULL) {
		zfs_close(zhp);
		return (-1);
	}

	chp->chp_found = 1;
	zfs_close(zhp);

	return (0);
}

/*
 * ndmp_has_backup_chkpnt
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
ndmp_has_backup_chkpnt(char *volname, char *jobname)
{
	zfs_handle_t *zhp;
	chkpnt_param_t chkp;
	char chname[ZFS_MAXNAMELEN];

	(void) mutex_lock(&zlib_mtx);
	if ((zhp = zfs_open(zlibh, volname, ZFS_TYPE_DATASET)) == 0) {
		NDMP_LOG(LOG_ERR, "Cannot open checkpoint %s.", volname);
		(void) mutex_unlock(&zlib_mtx);
		return (-1);
	}

	chkp.chp_found = 0;
	(void) snprintf(chname, ZFS_MAXNAMELEN, "@bk-%s", jobname);
	chkp.chp_name = chname;

	(void) zfs_iter_snapshots(zhp, ndmp_has_backup, &chkp);
	zfs_close(zhp);
	(void) mutex_unlock(&zlib_mtx);

	return (chkp.chp_found);
}


/*
 * ndmp_add_chk_pnt_vol
 *
 * This function keep track of check points created by NDMP. Whenever the
 * NDMP check points need to be created, this function should be called.
 * If the value returned is bigger than 1, it indicates that the check point
 * has already exists and should not be created.
 *
 * Parameters:
 *   vol_name (input) - name of the volume
 *
 * Returns:
 *   The number of existing snapshots
 */
static unsigned int
ndmp_add_chk_pnt_vol(char *vol_name)
{
	ndmp_chkpnt_vol_t *new_chkpnt_vol;

	for (new_chkpnt_vol = chkpnt_vols; new_chkpnt_vol != NULL;
	    new_chkpnt_vol = new_chkpnt_vol->cv_next) {
		if (strcmp(new_chkpnt_vol->cv_vol_name, vol_name) == 0) {
			new_chkpnt_vol->cv_count++;
			return (new_chkpnt_vol->cv_count);
		}
	}

	new_chkpnt_vol = ndmp_malloc(sizeof (ndmp_chkpnt_vol_t));
	if (new_chkpnt_vol == NULL)
		return (0);

	(void) memset(new_chkpnt_vol, 0, sizeof (ndmp_chkpnt_vol_t));
	(void) strlcpy(new_chkpnt_vol->cv_vol_name, vol_name,
	    sizeof (new_chkpnt_vol->cv_vol_name));

	new_chkpnt_vol->cv_count++;

	if (chkpnt_vols == NULL) {
		chkpnt_vols = new_chkpnt_vol;
	} else {
		new_chkpnt_vol->cv_next = chkpnt_vols;
		chkpnt_vols = new_chkpnt_vol;
	}

	return (new_chkpnt_vol->cv_count);
}


/*
 * ndmp_remove_chk_pnt_vol
 *
 * This function will decrement the usage counter belongs to the check point.
 * Whenever a check point needs to be removed, this function should be
 * called. When the return value is greater than zero, it indicates someone
 * else is still using the check point and the check point should not be
 * removed.
 *
 * Parameters:
 *   vol_name (input) - name of the volume
 *
 * Returns:
 *   The number of existing snapshots
 */
static unsigned int
ndmp_remove_chk_pnt_vol(char *vol_name)
{
	ndmp_chkpnt_vol_t *new_chkpnt_vol, *pre_chkpnt_vol;

	pre_chkpnt_vol = chkpnt_vols;
	for (new_chkpnt_vol = chkpnt_vols; new_chkpnt_vol != NULL;
	    new_chkpnt_vol = new_chkpnt_vol->cv_next) {
		if (strcmp(new_chkpnt_vol->cv_vol_name, vol_name) == 0) {
			new_chkpnt_vol->cv_count--;

			if (new_chkpnt_vol->cv_count == 0) {
				if (pre_chkpnt_vol == new_chkpnt_vol &&
				    new_chkpnt_vol->cv_next == NULL)
					chkpnt_vols = NULL;
				else if (pre_chkpnt_vol == new_chkpnt_vol)
					chkpnt_vols = new_chkpnt_vol->cv_next;
				else
					pre_chkpnt_vol->cv_next =
					    new_chkpnt_vol->cv_next;

				free(new_chkpnt_vol);
				return (0);
			}
			return (new_chkpnt_vol->cv_count);
		}
		if (new_chkpnt_vol != chkpnt_vols)
			pre_chkpnt_vol = pre_chkpnt_vol->cv_next;
	}

	return (0);
}




/*
 * ndmp_start_check_point
 *
 * This function will parse the path, vol_name, to get the real volume name.
 * It will then check via ndmp_add_chk_pnt_vol to see if creating a check point
 * for the volume is necessary. If it is, a checkpoint is created.
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
ndmp_start_check_point(char *vol_name, char *jname)
{
	int erc = 0;
	char vol[ZFS_MAXNAMELEN];

	if (vol_name == 0 ||
	    get_zfsvolname(vol, sizeof (vol), vol_name) == -1)
		return (0);

	if (ndmp_add_chk_pnt_vol(vol) > 0) {
		/*
		 * If there is an old checkpoint left from the previous
		 * backup and the reference count of backup checkpoint of
		 * the volume is 1 after increasing it, it shows that the
		 * checkpoint on file system is a stale one and it must be
		 * removed before using it.
		 */
		if (ndmp_has_backup_chkpnt(vol, jname))
			(void) chkpnt_backup_successful(vol, jname);
		if ((erc = chkpnt_backup_prepare(vol, jname)) < 0)
			(void) ndmp_remove_chk_pnt_vol(vol);
	}

	return (erc);
}

/*
 * ndmp_release_check_point
 *
 * This function will parse the path, vol_name, to get the real volume name.
 * It will then check via ndmp_remove_chk_pnt_vol to see if removing a check
 * point for the volume is necessary. If it is, a checkpoint is removed.
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
ndmp_release_check_point(char *vol_name, char *jname)
{
	int erc = 0;
	char vol[ZFS_MAXNAMELEN];

	if (vol_name == 0 ||
	    get_zfsvolname(vol, sizeof (vol), vol_name))
		return (0);

	if (ndmp_remove_chk_pnt_vol(vol) == 0)
		erc = chkpnt_backup_successful(vol, jname);

	return (erc);
}
