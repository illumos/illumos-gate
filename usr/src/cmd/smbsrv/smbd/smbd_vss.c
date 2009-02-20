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

#include <synch.h>
#include <pthread.h>
#include <unistd.h>
#include <string.h>
#include <strings.h>
#include <sys/errno.h>
#include <libzfs.h>

#include <smbsrv/libsmb.h>
#include <smbsrv/libsmbrdr.h>
#include <smbsrv/libsmbns.h>
#include <smbsrv/libmlsvc.h>
#include <smbsrv/smbinfo.h>
#include <smbsrv/ntstatus.h>
#include "smbd.h"

/*
 * This file supports three basic functions that all use the
 * the zfs_iter_snapshots function to get the snapshot info
 * from ZFS.  If the filesystem is not ZFS, the an error is sent
 * to the caller (door functions in this case) with the count of
 * zero in the case of smbd_vss_get_count.  Each function
 * is expecting a path that is the root of the dataset.
 * The basic idea is to define a structure for the data and
 * an iterator function that will be called for every snapshot
 * in the dataset that was opened.  The iterator function gets
 * a zfs_handle_t(that needs to be closed) for the snapshot
 * and a pointer to the structure of data defined passed to it.
 * If the iterator function returns a non-zero value, no more
 * snapshots will be processed.  There is no guarantee in the
 * order in which the snapshots are processed.
 *
 * The structure of this file is:
 * Three structures that are used between the iterator functions
 * and "main" functions
 * The 3 "main" functions
 * Support functions
 * The 3 iterator functions
 */

static void smbd_vss_time2gmttoken(time_t time, char *gmttoken);
static int smbd_vss_cmp_time(const void *a, const void *b);
static int smbd_vss_iterate_count(zfs_handle_t *zhp, void *data);
static int smbd_vss_iterate_get_uint64_date(zfs_handle_t *zhp, void *data);
static int smbd_vss_iterate_map_gmttoken(zfs_handle_t *zhp, void *data);

typedef struct smbd_vss_count {
	int vc_count;
} smbd_vss_count_t;

/*
 * gd_count how many @GMT tokens are expected
 * gd_return_count how many @GMT tokens are being returned
 * gd_gmt_array array of the @GMT token with max size of gd_count
 */
typedef struct smbd_vss_get_uint64_date {
	int gd_count;
	int gd_return_count;
	uint64_t *gd_gmt_array;
} smbd_vss_get_uint64_date_t;

typedef struct smbd_vss_map_gmttoken {
	char *mg_gmttoken;
	char *mg_snapname;
} smbd_vss_map_gmttoken_t;


/*
 * path - path of the dataset
 * count - return value of the number of snapshots for the dataset
 */
int
smbd_vss_get_count(const char *path, uint32_t *count)
{
	char dataset[MAXPATHLEN];
	libzfs_handle_t *libhd;
	zfs_handle_t *zfshd;
	smbd_vss_count_t vss_count;

	bzero(&vss_count, sizeof (smbd_vss_count_t));
	*count = 0;

	if (smb_getdataset(path, dataset, MAXPATHLEN) != 0)
		return (-1);

	if ((libhd = libzfs_init()) == NULL)
		return (-1);

	if ((zfshd = zfs_open(libhd, dataset, ZFS_TYPE_DATASET)) == NULL) {
		libzfs_fini(libhd);
		return (-1);
	}

	(void) zfs_iter_snapshots(zfshd, smbd_vss_iterate_count,
	    (void *)&vss_count);

	*count = vss_count.vc_count;
	zfs_close(zfshd);
	libzfs_fini(libhd);
	return (0);
}

/*
 * path - is the path of the dataset
 * count - is the maxium number of GMT tokens allowed to be returned
 * return_count - is how many should be returned
 * num_gmttokens - how many gmttokens in gmttokenp (0 if error)
 * gmttokenp - array of @GMT tokens (even if zero, elements still need
 * to be freed)
 */

void
smbd_vss_get_snapshots(const char *path, uint32_t count,
    uint32_t *return_count, uint32_t *num_gmttokens, char **gmttokenp)
{
	char dataset[MAXPATHLEN];
	libzfs_handle_t *libhd;
	zfs_handle_t *zfshd;
	smbd_vss_get_uint64_date_t vss_uint64_date;
	int i;
	uint64_t *timep;

	*return_count = 0;
	*num_gmttokens = 0;

	if (smb_getdataset(path, dataset, MAXPATHLEN) != 0)
		return;

	if ((libhd = libzfs_init()) == NULL)
		return;

	if ((zfshd = zfs_open(libhd, dataset, ZFS_TYPE_DATASET)) == NULL) {
		libzfs_fini(libhd);
		return;
	}

	vss_uint64_date.gd_count = count;
	vss_uint64_date.gd_return_count = 0;
	vss_uint64_date.gd_gmt_array = malloc(count * sizeof (uint64_t));

	if (vss_uint64_date.gd_gmt_array != NULL) {
		(void) zfs_iter_snapshots(zfshd,
		    smbd_vss_iterate_get_uint64_date,
		    (void *)&vss_uint64_date);

		*num_gmttokens = vss_uint64_date.gd_return_count;
		*return_count = vss_uint64_date.gd_return_count;

		if (vss_uint64_date.gd_return_count <= count) {
			/*
			 * Sort the list since neither
			 * zfs nor the client sorts it.
			 */
			qsort((char *)vss_uint64_date.gd_gmt_array,
			    vss_uint64_date.gd_return_count,
			    sizeof (uint64_t), smbd_vss_cmp_time);

			timep = vss_uint64_date.gd_gmt_array;

			for (i = 0; i < vss_uint64_date.gd_return_count; i++) {
				*gmttokenp = malloc(SMB_VSS_GMT_SIZE);

				if (*gmttokenp) {
					smbd_vss_time2gmttoken(*timep,
					    *gmttokenp);
				} else {
					vss_uint64_date.gd_return_count = 0;
				}

				timep++;
				gmttokenp++;
			}
		}

		free(vss_uint64_date.gd_gmt_array);
	}

	zfs_close(zfshd);
	libzfs_fini(libhd);
}

/*
 * path - path of the dataset for the operation
 * gmttoken - the @GMT token to be looked up
 * snapname - the snapshot name to be returned
 *
 * Here we are going to get the snapshot name from the @GMT token
 * The snapname returned by ZFS is : <dataset name>@<snapshot name>
 * So we are going to make sure there is the @ symbol in
 * the right place and then just return the snapshot name
 */
int
smbd_vss_map_gmttoken(const char *path, char *gmttoken, char *snapname)
{
	char dataset[MAXPATHLEN];
	libzfs_handle_t *libhd;
	zfs_handle_t *zfshd;
	smbd_vss_map_gmttoken_t vss_map_gmttoken;
	char *zsnap;
	const char *lsnap;

	vss_map_gmttoken.mg_gmttoken = gmttoken;
	vss_map_gmttoken.mg_snapname = snapname;
	*snapname = '\0';

	if (smb_getdataset(path, dataset, MAXPATHLEN) != 0)
		return (-1);

	if ((libhd = libzfs_init()) == NULL)
		return (-1);

	if ((zfshd = zfs_open(libhd, dataset, ZFS_TYPE_DATASET)) == NULL) {
		libzfs_fini(libhd);
		return (-1);
	}

	(void) zfs_iter_snapshots(zfshd, smbd_vss_iterate_map_gmttoken,
	    (void *)&vss_map_gmttoken);

	/* compare the zfs snapshot name and the local snap name */
	zsnap = snapname;
	lsnap = dataset;
	while ((*lsnap != '\0') && (*zsnap != '\0') && (*lsnap == *zsnap)) {
		zsnap++;
		lsnap++;
	}

	/* Now we should be passed the dataset name */
	if ((*zsnap == '@') && (*lsnap == '\0')) {
		zsnap++;
		(void) strlcpy(snapname, zsnap, MAXPATHLEN);
	} else {
		*snapname = '\0';
	}

	zfs_close(zfshd);
	libzfs_fini(libhd);
	return (0);
}

static void
smbd_vss_time2gmttoken(time_t time, char *gmttoken)
{
	struct tm t;

	(void) gmtime_r(&time, &t);

	(void) strftime(gmttoken, SMB_VSS_GMT_SIZE,
	    "@GMT-%Y.%m.%d-%H.%M.%S", &t);
}

static int
smbd_vss_cmp_time(const void *a, const void *b)
{
	if (*(uint64_t *)a < *(uint64_t *)b)
		return (1);
	if (*(uint64_t *)a == *(uint64_t *)b)
		return (0);
	return (-1);
}

static int
smbd_vss_iterate_count(zfs_handle_t *zhp, void *data)
{
	smbd_vss_count_t *vss_data;
	vss_data = data;
	vss_data->vc_count++;
	/* libzfs expects us to close the handle */
	zfs_close(zhp);
	return (0);
}

static int
smbd_vss_iterate_get_uint64_date(zfs_handle_t *zhp, void *data)
{
	smbd_vss_get_uint64_date_t *vss_data;

	vss_data = data;

	if (vss_data->gd_return_count < vss_data->gd_count) {
		vss_data->gd_gmt_array[vss_data->gd_return_count] =
		    zfs_prop_get_int(zhp, ZFS_PROP_CREATION);
	}

	vss_data->gd_return_count += 1;
	/* libzfs expects us to close the handle */
	zfs_close(zhp);
	return (0);
}

static int
smbd_vss_iterate_map_gmttoken(zfs_handle_t *zhp, void *data)
{
	smbd_vss_map_gmttoken_t *vss_data;
	time_t time;
	char gmttoken[SMB_VSS_GMT_SIZE];

	vss_data = data;

	time = (time_t)zfs_prop_get_int(zhp, ZFS_PROP_CREATION);
	smbd_vss_time2gmttoken(time, gmttoken);

	if (strncmp(gmttoken, vss_data->mg_gmttoken, SMB_VSS_GMT_SIZE) == 0) {
		(void) strlcpy(vss_data->mg_snapname, zfs_get_name(zhp),
		    MAXPATHLEN);

		/* libzfs expects us to close the handle */
		zfs_close(zhp);

		/* we found a match, do not process anymore snapshots */
		return (-1);
	}

	/* libzfs expects us to close the handle */
	zfs_close(zhp);
	return (0);
}
