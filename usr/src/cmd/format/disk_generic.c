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
 * This file contains functions that implement the fdisk menu commands.
 */
#include "global.h"
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <signal.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/stat.h>

#include <sys/dklabel.h>
#include <errno.h>


#include "main.h"
#include "analyze.h"
#include "menu.h"
#include "menu_command.h"
#include "menu_defect.h"
#include "menu_partition.h"
#if defined(_FIRMWARE_NEEDS_FDISK)
#include "menu_fdisk.h"
#endif	/* defined(_FIRMWARE_NEEDS_FDISK) */
#include "param.h"
#include "misc.h"
#include "label.h"
#include "startup.h"
#include "partition.h"
#include "prompts.h"
#include "checkdev.h"
#include "io.h"
#include "ctlr_scsi.h"
#include "auto_sense.h"

#ifdef	__STDC__
/*
 *	Local prototypes for ANSI C compilers
 */
static int	generic_ck_format(void);
static int	generic_rdwr(int dir, int fd, diskaddr_t blkno, int secnt,
			caddr_t bufaddr, int flags, int *xfercntp);
#else	/* __STDC__ */

static int	generic_ck_format();
static int	generic_rdwr();

#endif	/* __STDC__ */

struct  ctlr_ops genericops = {
	generic_rdwr,
	generic_ck_format,
	0,
	0,
	0,
	0,
	0,
};


/*
 * Check to see if the disk has been formatted.
 * If we are able to read the first track, we conclude that
 * the disk has been formatted.
 */
static int
generic_ck_format()
{
	int	status;

	/*
	 * Try to read the first four blocks.
	 */
	status = generic_rdwr(DIR_READ, cur_file, 0, 4, (caddr_t)cur_buf,
	    F_SILENT, NULL);
	return (!status);
}

/*
 * Read or write the disk.
 * Temporary interface until IOCTL interface finished.
 */
/*ARGSUSED*/
static int
generic_rdwr(dir, fd, blkno, secnt, bufaddr, flags, xfercntp)
	int	dir;
	int	fd;
	diskaddr_t	blkno;
	int	secnt;
	caddr_t	bufaddr;
	int	flags;
	int	*xfercntp;
{

	offset_t	tmpsec, status, tmpblk;
	int		ret;

	tmpsec = (offset_t)secnt * UBSIZE;
	tmpblk = (offset_t)blkno * UBSIZE;

#if defined(_FIRMWARE_NEEDS_FDISK)
	/* Use "p0" file to seek/read the data  */
	(void) open_cur_file(FD_USE_P0_PATH);
#endif
	if (dir == DIR_READ) {
		status = llseek(fd, tmpblk, SEEK_SET);
		if (status != tmpblk) {
			ret = (int)status;
			goto out;
		}

		status = read(fd, bufaddr, (size_t)tmpsec);
		if (status != tmpsec)
			ret = (int)tmpsec;
		else
			ret = 0;
	} else {
		status = llseek(fd, tmpblk, SEEK_SET);
		if (status != tmpblk) {
			ret = (int)status;
			goto out;
		}

		status = write(fd, bufaddr, (size_t)tmpsec);
		if (status != tmpsec)
			ret = (int)tmpsec;
		else
			ret = 0;
	}
out:
#if defined(_FIRMWARE_NEEDS_FDISK)
	/* Restore cur_file with cur_disk->disk_path */
	(void) open_cur_file(FD_USE_CUR_DISK_PATH);
#endif
	return (ret);
}
