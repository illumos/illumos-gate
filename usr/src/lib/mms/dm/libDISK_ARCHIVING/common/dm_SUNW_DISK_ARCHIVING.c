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
 *
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */


#include <note.h>
#include <sys/types.h>
#include <syslog.h>
#include <sys/scsi/impl/uscsi.h>
#include <sys/scsi/generic/sense.h>
#include <sys/scsi/generic/status.h>
#include <sys/scsi/generic/commands.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/stat.h>
#include <sys/mntio.h>
#include <sys/mnttab.h>
#include <dlfcn.h>
#include <errno.h>
#include <pthread.h>
#include <string.h>
#include <unistd.h>
#include <stropts.h>
#include <sys/ioctl.h>
#include <sys/siginfo.h>
#include <sys/mtio.h>
#include <time.h>
#include <mms_dmd.h>
#include <mms_trace.h>
#include <dmd_impl.h>
#include <dm_impl.h>
#include <dm_drive.h>
#include <dm_msg.h>
#include <dm_proto.h>
#include <dda.h>
#include <mms_strapp.h>

static	char *_SrcFile = __FILE__;

/*
 * Specify whether the persistent reserve out command is supported or not.
 * 0 - not supported
 * 1 - supported
 *
 * If the persistent reserve out command is supported, then it will be used
 * to reserve the drive.
 * If the persistent reserve out command is not supported, then the reserve
 * command will be used to reserve the drive.
 */
int	drv_prsv_supported = 1;		/* persistent reserve out supported */

/*
 * specify timeouts for this drive. Time is specified in seconds.
 */
drv_timeout_t	drv_timeout = {
	(151 *60),			/* For really long commands */
	(20 *60),			/* Normal commands */
	(1 *60),			/* short commands */
};

/*
 * Specify the drive type.
 * Drive type must begin with "dt_"
 */
char	drv_drive_type[] = "dt_disk";

/*
 * Specify the directory in which this device can be found.
 * e.g. /dev/rmt
 *
 * The DM will open each device in this directory and look for a device
 * whose serial number matches the serial number specified in
 * DRIVE.'DriveSerialNum'.
 * If this is a null string, then the full pathname of the device is specified
 * in DM.'DMTargetPath'.
 */
char	drv_dev_dir[] = "";

/*
 * drv_density[]
 * - Specify density names with their density codes supported by this DM.
 * - Densities must be specified in the order of their selection priority.
 *   The ones at the beginning of the list will be selected before those
 *   at the end of the list.
 * - Density names must start with "den_" to avoid conflict with other names.
 */

mms_sym_t	drv_density[] = {
	"den_DISK", 0,
	NULL
};

/*
 * drv_shape[]
 * - Specify shape names of cartridge types supported by this DM.
 * - Shape names must be specified in the order of their selection priority.
 *   The ones at the beginning of the list will be selected before those
 *   at the end of the list.
 * - Shape name must be a well known and published name.
 */

char	*drv_shape[] = {
	"DISK",
	NULL
};

/*
 * drv_shape_den[]
 * Specify the shape of a cartridge and the density on it that can be
 * written over by a readwrite density.
 * All shape names and density names must have been specified in
 * drv_density[] and drv_shape[].
 * Each entry of the array consists of:
 * {shapename, density on cart, readwrite density}.
 * If the density on cartridge is the same as the readwrite density, then
 * the drive can read and write with that density.
 * If the density on cartridge is read only, then the readwrite density
 * is NULL.
 * If the readwrite density is not NULL and it is different from the density
 * on cartridge, then the drive is able to write over the existing data
 * starting from the beginning of medium.
 */

drv_shape_density_t	drv_shape_den[] = {
	"DISK", "den_DISK", "den_DISK",
	NULL
};

/*
 * Specify SCSI commands that a client may not issue using USCSI
 */
int	drv_disallowed_cmds[] = {
	SCMD_PROUT,			/* persistent reserve out */
	SCMD_RESERVE,			/* reserve */
	SCMD_RELEASE,			/* release */
};
int	drv_num_disallowed_cmds =
    sizeof (drv_disallowed_cmds) / sizeof (int);

/*
 * Specify ioctl's that a client may not issue
 */
int	drv_disallowed_ioctls[] = {
	MTIOCRESERVE,
	MTIOCRELEASE,
	MTIOCFORCERESERVE,
};
int	drv_num_disallowed_ioctls =
    sizeof (drv_disallowed_ioctls) / sizeof (int);


typedef	struct	drv_cart_mountpt	{
	int	drv_state;
	char	*drv_mpoint;
	pthread_t drv_tid;
}	drv_cart_mountpt_t;

/*
 * drv_state flags
 */
#define	DRV_MOUNTED		1
#define	DRV_MOUNT_THREAD_ACTIVE	2

static	char	**drv_mounted = NULL;
static	int	drv_mounted_size = 0;
static	drv_cart_mountpt_t	*drv_cart_mountpt = NULL;
static	int	drv_cart_mountpt_size = 0;
static	char	**drv_mnttab = NULL;
static	int	drv_mnttab_size = 0;
static	int	drv_mount_initialized = 0;
static	int	drv_mount_cnt;
static	pthread_cond_t	drv_mount_cv;
static	pthread_mutex_t	drv_mount_mutex;

#define	DRV_MOUNTTAB_SIZE	20

/*
 * Since there is no library to unload a dda tape drive, it has to be
 * initialized by unload any loaded tape when the drive is activate enabled.
 */
void
drv_init_dev(void)
{
	DRV_CALL(drv_unload, ());
}

int64_t
drv_get_avail_capacity(void)
{
	mms_capacity_t	cap;

	if (DRV_CALL(drv_get_capacity, (&cap)) < 0) {
		return (-1);
	}
	return (cap.mms_avail);
}

int
drv_get_capacity(mms_capacity_t *cap)
{
	dda_capacity_t	dda_cap;

	if (ioctl(drv->drv_fd, DDA_CMD_CAPACITY, &dda_cap) < 0) {
		return (-1);
	}

	TRACE((MMS_DEBUG, "dda_capacity = %lld, dda_space = %lld",
	    dda_cap.dda_capacity, dda_cap.dda_space));

	cap->mms_max = dda_cap.dda_capacity / (1024 * 1024);
	cap->mms_avail = dda_cap.dda_space / (1024 * 1024);
	cap->mms_pc_avail =
	    (dda_cap.dda_space * 100) / dda_cap.dda_capacity;
	return (0);
}


/*
 * drv_mode_sense - issue mode sense
 * - page - page code
 * - len - allocation length
 *
 * - always return block descriptor block
 * - always get current value
 */

/*ARGSUSED0*/
int
drv_mode_sense(int page, int pc, int len)
{
	errno = ENOTSUP;
	return (-1);
}

/*
 * drv_mode_select - issue mode select
 * - pf - page format - 0, no page data, or 1, send page data
 * - len - allocation length
 */
/*ARGSUSED0*/
int
drv_mode_select(int pf, int len)
{
	errno = ENOTSUP;
	return (-1);
}

int
drv_inquiry(void)
{
	errno = ENOTSUP;
	return (-1);
}

int
drv_clrerr(void)
{
	errno = ENOTSUP;
	return (-1);
}

int
drv_tur(void)
{
	struct	mtget	mtget;

	if (ioctl(drv->drv_fd, MTIOCGET, &mtget) < 0) {
		return (-1);
	}
	if (mtget.mt_fileno < 0) {
		return (-1);
	}
	return (0);
}

int
drv_load(void)
{
	char	*path;
	struct	stat	statbuf;
	int	err;

	TRACE((MMS_DEBUG, "Load/Retension"));

	path = dm_show_virt_cart_path();
	if (path == NULL) {
		return (-1);
	}

	/*
	 * If path does not exist
	 */
	while (stat(path, &statbuf) < 0) {
		if (errno == EINTR) {
			continue;
		}
		DM_MSG_ADD((MMS_EXIST, MMS_DM_E_NOCART,
		    "cartridge %s does not exist", path));

		TRACE((MMS_DEBUG, "path %s does not exist", path));
		free(path);
		return (-1);
	}

	drv->drv_flags &= ~DRV_MOVE_FLAGS;
	if (ioctl(drv->drv_fd, DDA_CMD_LOAD, path) < 0) {
		err = errno;
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_IO,
		    "load error: %s", strerror(err)));

		TRACE((MMS_DEBUG, "load error: %s", strerror(err)));
		free(path);
		return (-1);
	}

	drv->drv_flags |= DRV_BOM;
	TRACE((MMS_DEBUG, "Cartridge \"%s\" loaded, path = %s",
	    mnt->mnt_pcl, path));
	free(path);
	return (0);
}

int
drv_get_pos(tapepos_t *pos)
{
	if (ioctl(drv->drv_fd, MTIOCGETPOS, pos) != 0) {
		return (-1);
	}
	TRACE((MMS_DEBUG, "Read position %lld", pos->lgclblkno));
	return (0);
}

/*ARGSUSED0*/
int
drv_log_sense(uchar_t *buf, int len, int page_control, int page_code)
{
	errno = ENOTSUP;
	return (-1);
}

int
drv_blk_limit(mms_blk_limit_t *lmt)
{
	dda_blklmt_t	dda_blklmt;

	if (ioctl(drv->drv_fd, DDA_CMD_BLKLMT, &dda_blklmt) < 0) {
		return (-1);
	}
	lmt->mms_max = dda_blklmt.dda_blkmax;
	lmt->mms_min = dda_blklmt.dda_blkmin;
	lmt->mms_gran = 0;
	TRACE((MMS_DEBUG, "Read block limits max %d min %d",
	    lmt->mms_max, lmt->mms_min));
	return (0);
}

int
drv_release(void)
{
	return (0);
}

int
drv_prsv_register(void)
{
	return (0);
}

int
drv_prsv_reserve(void)
{
	return (0);
}

int
drv_prsv_release(void)
{
	return (0);
}

/*ARGSUSED0*/
int
drv_prsv_preempt(char *curkey)
{
	return (0);
}

int
drv_prsv_clear(void)
{
	return (0);
}

/*ARGSUSED0*/
int
drv_prsv_read_keys(char *buf, int bufsize)
{
	errno = ENOTSUP;
	return (-1);
}

/*ARGSUSED0*/
int
drv_prsv_read_rsv(char *buf, int bufsize)
{
	errno = ENOTSUP;
	return (-1);
}


int
drv_reserve(void)
{
	return (0);
}

int
drv_get_serial_num(char *ser)
{
	dda_serial_t	serial;

	if (ioctl(drv->drv_fd, DDA_CMD_SERIAL, serial) < 0) {
		return (-1);
	}
	(void) memset(ser, 0, MMS_SER_NUM_LEN);
	(void) strncpy(ser, serial, MMS_SER_NUM_LEN);
	TRACE((MMS_DEBUG, "Drive serial number %s", ser));
	return (0);
}

int
drv_get_write_protect(int *wp)
{
	*wp = !ioctl(drv->drv_fd, DDA_CMD_WPROTECT, NULL);
	TRACE((MMS_DEBUG, "Cartridge write protected is %s",
	    *wp ? "yes" : "no"));
	return (0);
}

/*ARGSUSED0*/
int
drv_set_compression(int comp)
{
	return (0);
}

/*ARGSUSED0*/
void
drv_pthread_cleanup(void *arg)
{
	(void) pthread_mutex_unlock(&drv_mount_mutex);
}

/*
 * A thread to do stat
 */
void *
drv_stat_mount_point(void *mntpt)
{
	struct	stat	statbuf;
	char		*path;
	drv_cart_mountpt_t	*mp = mntpt;

	pthread_cleanup_push(drv_pthread_cleanup, NULL);
	(void) pthread_mutex_lock(&drv_mount_mutex);
	pthread_testcancel();
	mp->drv_state = DRV_MOUNT_THREAD_ACTIVE;
	path = mms_strnew("%s/x", mp->drv_mpoint);
	(void) pthread_mutex_unlock(&drv_mount_mutex);

	TRACE((MMS_DEBUG, "stat %s", mp->drv_mpoint));
	(void) stat(path, &statbuf);
	free(path);
	(void) pthread_mutex_lock(&drv_mount_mutex);
	mp->drv_tid = (pthread_t)(-1);
	pthread_testcancel();
	mp->drv_state = 0;
	drv_mount_cnt--;
	if (drv_mount_cnt == 0) {
		(void) pthread_cond_broadcast(&drv_mount_cv);
	}
	pthread_cleanup_pop(0);
	(void) pthread_mutex_unlock(&drv_mount_mutex);
	pthread_exit(0);
	return (NULL);
}

int
drv_bld_mounted(void)
{
	int	i;
	int	j;
	int	k;
	char	**newpt;
	int	newsize;
	int	size;

	if (drv_mounted == NULL) {
		drv_mounted_size = DRV_MOUNTTAB_SIZE;
		size = drv_mounted_size * sizeof (char *);
		drv_mounted = (char **)malloc(size);
		if (drv_mounted == NULL) {
			DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
			    "out of memory"));
			return (-1);
		}
		drv_mounted[0] = NULL;
	}

	/*
	 * Find where to add to drv_mounted
	 */
	for (k = 0; drv_mounted[k] != NULL; k++)
		;

	(void) pthread_mutex_lock(&drv_mount_mutex);
	for (i = 0; drv_cart_mountpt[i].drv_mpoint != NULL; i++) {
		if (drv_cart_mountpt[i].drv_state != DRV_MOUNTED) {
			/* Not mounted, skip */
			continue;
		}
		/* Check if already in drv_mounted */
		for (j = 0; drv_mounted[j] != NULL; j++) {
			if (strcmp(drv_cart_mountpt[i].drv_mpoint,
			    drv_mounted[j]) == 0) {
				break;
			}
		}
		if (drv_mounted[j] == NULL) {
			/* mount point not in mounted */
			if (k == drv_mounted_size - 1) {
				newsize = drv_mounted_size << 1;
				size = sizeof (char *) * newsize;
				newpt = (char **)
				    realloc(drv_mounted, newsize);
				if (newpt == NULL) {
					DM_MSG_ADD((MMS_INTERNAL,
					    MMS_DM_E_INTERNAL,
					    "out of memory"));
					(void) pthread_mutex_unlock(
					    &drv_mount_mutex);
					return (-1);
				}
				drv_mounted = newpt;
				drv_mounted_size = newsize;
			}
			drv_mounted[k] = strdup(drv_cart_mountpt[i].drv_mpoint);
			if (drv_mounted[k] == NULL) {
				DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
				    "out of memory"));
				(void) pthread_mutex_unlock(&drv_mount_mutex);
				return (-1);
			}
			k++;
			drv_mounted[k] = NULL;
		}
	}

	(void) pthread_mutex_unlock(&drv_mount_mutex);
	/*
	 * If no mount point return -1
	 */
	if (drv_mounted[0] == NULL) {
		dm_msg_destroy();		/* Remove unreleated msgs */
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "No mount point accessible by this DM"));
		return (-1);
	}
	return (0);
}

int
drv_add_mounted(void)
{
	int	i;
	int	j;

	(void) pthread_mutex_lock(&drv_mount_mutex);
	for (i = 0; drv_cart_mountpt[i].drv_mpoint != NULL; i++) {
		if (drv_cart_mountpt[i].drv_state == DRV_MOUNTED ||
		    drv_cart_mountpt[i].drv_state == DRV_MOUNT_THREAD_ACTIVE) {
			/* already mounted or unknown */
			continue;
		}
		for (j = 0; drv_mnttab[j] != NULL; j++) {
			if (strcmp(drv_cart_mountpt[i].drv_mpoint,
			    drv_mnttab[j]) == 0) {
				drv_cart_mountpt[i].drv_state = DRV_MOUNTED;
				break;
			}
		}
	}
	(void) pthread_mutex_unlock(&drv_mount_mutex);

	return (0);
}



int
drv_force_mount(void)
{
	int		rc = ~0;
	int		i;
	struct timespec	ts;

	if (drv_mount_initialized == 0) {
		(void) pthread_cond_init(&drv_mount_cv, NULL);
		(void) pthread_mutex_init(&drv_mount_mutex, NULL);
		drv_mount_cnt = 0;
		drv_mount_initialized = 1;
	}

	(void) pthread_mutex_lock(&drv_mount_mutex);
	drv_mount_cnt = 0;
	for (i = 0; drv_cart_mountpt[i].drv_mpoint != NULL; i++) {
		/* Create a thread to stat a file in cart_mountpt[i] */
		drv_cart_mountpt[i].drv_tid = (pthread_t)(-1);
		if (pthread_create(&drv_cart_mountpt[i].drv_tid, NULL,
		    drv_stat_mount_point,
		    (void *)(&drv_cart_mountpt[i])) != 0) {
			DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
			    "pthread_create error: %s", strerror(errno)));
			(void) pthread_mutex_unlock(&drv_mount_mutex);
			return (-1);
		}
		(void) pthread_detach(drv_cart_mountpt[i].drv_tid);
		drv_mount_cnt++;
	}

	/*
	 * Wait for mounts
	 */
	ts.tv_sec = drv->drv_disk_mount_timeout;
	ts.tv_nsec = 0;
	for (;;) {
		rc = pthread_cond_timedwait(&drv_mount_cv, &drv_mount_mutex,
		    &ts);
		if (drv_mount_cnt == 0 ||
		    (rc != 0 && errno == ETIMEDOUT)) {
			break;
		}
	}

	for (i = 0; drv_cart_mountpt[i].drv_mpoint != NULL; i++) {
		if (drv_cart_mountpt[i].drv_tid != (pthread_t)(-1)) {
			(void) pthread_cancel(drv_cart_mountpt[i].drv_tid);
			drv_cart_mountpt[i].drv_tid = (pthread_t)(-1);
		}
	}
	drv_mount_cnt = 0;
	(void) pthread_mutex_unlock(&drv_mount_mutex);
	return (0);
}

int
drv_get_mnttab(void)
{
	FILE		*mnttab;
	struct mnttab	mp;
	int		newsize;
	char		**newpt;
	int		i;
	int		k;
	int		size;

	if (drv_mnttab == NULL) {
		drv_mnttab_size = DRV_MOUNTTAB_SIZE;
		size = drv_mnttab_size * sizeof (char *);
		drv_mnttab = (char **)malloc(size);
		if (drv_mnttab == NULL) {
			DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
			    "out of memory"));
			return (-1);
		}
		drv_mnttab[0] = NULL;
	}

	/*
	 * Find offset to add new entries
	 */
	for (k = 0; drv_mnttab[k] != NULL; k++)
		;

	/*
	 * Read /etc/mnttab and get mounted mount points
	 */
	mnttab = fopen("/etc/mnttab", "r");
	if (mnttab == NULL) {
		DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
		    "cannot open /etc/mnttab: %s", strerror(errno)));
		return (-1);
	}

	while (getmntent(mnttab, &mp) == 0) {
		if (mp.mnt_mountp != NULL) {
			for (i = 0; drv_mnttab[i] != NULL; i++) {
				if (strcmp(drv_mnttab[i], mp.mnt_mountp) == 0) {
					break;
				}
			}
			if (drv_mnttab[i] != NULL) {
				/* Already in mnttab */
				continue;
			}
			if (k == drv_mnttab_size - 1) {
				newsize = drv_mnttab_size << 1;
				size = newsize * sizeof (char *);
				newpt = (char **)realloc(drv_mnttab, size);
				if (newpt == NULL) {
					DM_MSG_ADD((MMS_INTERNAL,
					    MMS_DM_E_INTERNAL,
					    "out of memory"));
					return (-1);
				}
				drv_mnttab = newpt;
				drv_mnttab_size = newsize;
			}
			drv_mnttab[k] = strdup(mp.mnt_mountp);
			if (drv_mnttab[k] == NULL) {
				DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
				    "out of memory"));
				return (-1);
			}
			TRACE((MMS_DEBUG, "added mount point from mnttab: %s",
			    drv_mnttab[k]));
			k++;
			drv_mnttab[k] = NULL;
		}
	}
	(void) fclose(mnttab);
	return (0);
}

int
drv_get_mount_points(void)
{
	mms_par_node_t	*root;
	mms_par_node_t	*text;
	char		*val;
	mms_par_node_t	*work = NULL;
	drv_cart_mountpt_t	*newpt;
	int		newsize;
	int		size;
	int		i;
	int		k;

	if (dm_show_mount_point(&root) != 0) {
		return (-1);
	}

	if (drv_cart_mountpt == NULL) {
		drv_cart_mountpt_size = DRV_MOUNTTAB_SIZE;
		size = drv_cart_mountpt_size * sizeof (drv_cart_mountpt_t);
		drv_cart_mountpt = (drv_cart_mountpt_t *)malloc(size);
		if (drv_cart_mountpt == NULL) {
			DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
			    "out of memory"));
			mms_pn_destroy(root);
			return (-1);
		}
		drv_cart_mountpt[0].drv_state = 0;
		drv_cart_mountpt[0].drv_mpoint = NULL;
	}

	(void) pthread_mutex_lock(&drv_mount_mutex);
	for (k = 0; drv_cart_mountpt[k].drv_mpoint != NULL; k++)
		;
	while (text =
	    mms_pn_lookup_arg(root, "text", MMS_PN_CLAUSE, &work)) {
		val = dm_get_attr_value(text, "CARTRIDGE",
		    "CartridgeMountPoint");
		if (val == NULL) {
			DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
			    "no DISK cartridge"));
			break;
		}
		/*
		 * Discard if already in mp
		 */
		for (i = 0; i < k; i++) {
			if (strcmp(val, drv_cart_mountpt[i].drv_mpoint) == 0) {
				/* Already in mp */
				break;
			}
		}
		if (i < k) {
			/* already in mp */
			continue;			/* discard */
		}

		/*
		 * A new mount point
		 */
		if (k == drv_cart_mountpt_size - 1) {
			newsize = drv_cart_mountpt_size << 1;
			size = newsize * sizeof (drv_cart_mountpt_t);
			newpt = (drv_cart_mountpt_t *)
			    realloc(drv_cart_mountpt, size);
			if (newpt == NULL) {
				DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
				    "out of memory"));
				(void) pthread_mutex_unlock(&drv_mount_mutex);
				mms_pn_destroy(root);
				return (-1);
			}
			drv_cart_mountpt = newpt;
			drv_cart_mountpt_size = newsize;
		}

		drv_cart_mountpt[k].drv_mpoint = strdup(val);
		if (drv_cart_mountpt[k].drv_mpoint == NULL) {
			DM_MSG_ADD((MMS_INTERNAL, MMS_DM_E_INTERNAL,
			    "out of memory"));
			(void) pthread_mutex_unlock(&drv_mount_mutex);
			mms_pn_destroy(root);
			return (-1);
		}
		TRACE((MMS_DEBUG, "added mount point from cartridge: %s",
		    drv_cart_mountpt[k].drv_mpoint));
		k++;
		drv_cart_mountpt[k].drv_state = 0;
		drv_cart_mountpt[k].drv_mpoint = NULL;
	}
	(void) pthread_mutex_unlock(&drv_mount_mutex);

	/*
	 * Done
	 */
	mms_pn_destroy(root);
	return (0);
}

char **
drv_get_mounted(void)
{
	int	i;

	/*
	 * Show mount points in DISK cartridges
	 */
	if (drv_get_mount_points() != 0) {
		return (NULL);
	}

	/*
	 * Stat a file on the mount points to force mount if necessary
	 */
	if (drv_force_mount() != 0) {
		goto out1;
	}

	/*
	 * Get mounted FS from /etc/mnttab
	 */
	if (drv_get_mnttab() != 0) {
		goto out1;
	}

	/*
	 * Add to the mounted table
	 */
	if (drv_add_mounted() != 0) {
		goto out2;
	}

	/*
	 * Add to the mounted table
	 */
	if (drv_bld_mounted() != 0) {
		goto out3;
	}

	return (drv_mounted);

out3:
	for (i = 0; drv_mounted[i] != NULL; i++) {
		free(drv_mounted[i]);
	}
	free(drv_mounted);
	drv_mounted = NULL;

out2:
	for (i = 0; drv_mnttab[i] != NULL; i++) {
		free(drv_mnttab[i]);
	}
	free(drv_mnttab);
	drv_mnttab = NULL;

out1:
	(void) pthread_mutex_lock(&drv_mount_mutex);
	if (drv_mount_cnt != 0) {
		for (i = 0; drv_cart_mountpt[i].drv_mpoint != NULL; i++) {
			if (drv_cart_mountpt[i].drv_state ==
			    DRV_MOUNT_THREAD_ACTIVE) {
				(void) pthread_cancel(drv_cart_mountpt[i].
				    drv_tid);
			}
		}
	}
	for (i = 0; drv_cart_mountpt[i].drv_mpoint != NULL; i++) {
		free(drv_cart_mountpt[i].drv_mpoint);
	}
	free(drv_cart_mountpt);
	drv_cart_mountpt = NULL;
	(void) pthread_mutex_unlock(&drv_mount_mutex);

	return (NULL);
}

void
drv_disallowed(void)
{
}

void
drv_mk_prsv_key(void)
{
}

int
drv_rebind_target(void)
{
	/*
	 * Target is already bound.
	 */
	return (0);
}

/*ARGSUSED0*/
int
drv_bind_raw_dev(int oflags)
{
	return (0);
}

int
drv_get_statistics(void)
{
	return (-1);
}

int
drv_get_density(int *den, int *comp)
{
	*den = 0;				/* DISK density */
	if (comp) {
		*comp = 0;
	}
	return (0);
}

int
/* ARGSUSED */
drv_set_density(int den)
{
	return (0);
}
