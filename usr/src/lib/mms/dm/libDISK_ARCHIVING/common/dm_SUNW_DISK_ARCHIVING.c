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
 * Function name
 *	drv_init_dev(void)
 *
 * Parameters:
 *	none
 *
 * Description:
 *	initialize a DISK cartridge by getting opening the DISK library
 *	and unload the drive.
 *
 * Return code:
 *	none
 *
 * Note:
 *
 *
 */

int
drv_init_dev(void)
{
	/*
	 * Get the library path
	 */

	/*
	 * Read LIBRARYACCESS to get HostPath.
	 * If HostPath is set, then it is the path to access the
	 * library.
	 * If HostPath is not set, then read the default path
	 * in the LIBRARY and use it to access the library.
	 */
	if (dm_get_hostpath() != 0) {
		TRACE((MMS_DEBUG, "Can't get hostpath"));
		return (-1);
	}

	if (drv->drv_disk_libpath == NULL) {
		/*
		 * Host path is not set.
		 * Read the default lib path from LIBRARY
		 */
		if (dm_get_default_lib_path() != 0) {
			TRACE((MMS_DEBUG, "Can't get default lib path"));
			return (-1);
		}
	}

	/*
	 * Since there is no library to unload a dda tape drive, it has
	 * to be initialized by unload any loaded tape when the drive is
	 * activate enabled.
	 */

	DRV_CALL(drv_unload, ());
	return (0);
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

	/*
	 * Get path to cartridge.
	 * It is library-path/pcl
	 */
	path = mms_strnew("%s/%s", drv->drv_disk_libpath, mnt->mnt_pcl);

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
