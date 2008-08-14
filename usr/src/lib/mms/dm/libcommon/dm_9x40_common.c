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


#include <sys/types.h>
#include <syslog.h>
#include <sys/scsi/impl/uscsi.h>
#include <sys/scsi/generic/sense.h>
#include <sys/scsi/generic/status.h>
#include <sys/scsi/generic/commands.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <ctype.h>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/stat.h>
#include <dlfcn.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <stropts.h>
#include <sys/ioctl.h>
#include <sys/mtio.h>
#include <mms_dmd.h>
#include <mms_trace.h>
#include <dmd_impl.h>
#include <dm_drive.h>
#include <mms_sym.h>

static	char *_SrcFile = __FILE__;
static	uint64_t	drv_max_cap = (uint64_t)(-1);	/* Cart max capacity */

int64_t
drv_get_avail_capacity(void)
{
	uchar_t		iobuf[120];
	uchar_t		*buf = iobuf;
	uint64_t	val;
	int		page_control = 1;	/* return current value */

	if (DRV_CALL(drv_log_sense,
	    (buf, sizeof (iobuf), page_control, 0x0c)) != 0) {
		return (-1);
	}
	if (dm_get_log_sense_parm(buf, 0x8000, &val) != 0) {
		return (-1);
	}
	/* Avail capacity in mega unit */
	return ((val * 4096) / (1024 * 1024));
}

int
drv_get_capacity(mms_capacity_t *cap)
{
	int64_t		avail;
	tapepos_t	pos;

	if (DRV_CALL(drv_get_pos, (&pos)) != 0) {
		return (-1);
	}
	if (DRV_CALL(drv_eom, ()) != 0) {
		DRV_CALL(drv_locate, (&pos));
		return (-1);
	}
	avail = DRV_CALL(drv_get_avail_capacity, ());
	if (DRV_CALL(drv_locate, (&pos)) != 0 || avail < 0) {
		return (-1);
	}

	cap->mms_max = drv_max_cap;
	cap->mms_avail = avail;
	cap->mms_pc_avail = (avail * 100) / drv_max_cap;

	TRACE((MMS_INFO, "Capacity: max %lld, avail %lld, avail %d%%",
	    cap->mms_max, cap->mms_avail, cap->mms_pc_avail));

	return (0);
}

int
drv_load(void)
{
	struct		uscsi_cmd us;
	char		cdb[6] = { 0x1b, 0x00, 0x00, 0x00, 0x03, 0x00 };
	int		i;

	TRACE((MMS_DEBUG, "9840 Load/Retension"));

	for (i = 0; i < DRV_LOAD_TUR; i++) {
		if (DRV_CALL(drv_tur, ()) != 0) {
			(void) sleep(1);
			continue;
		}
		(void) memset(&us, 0, sizeof (us));
		us.uscsi_cdb = cdb;
		us.uscsi_cdblen = 6;
		us.uscsi_timeout = drv->drv_timeout->drv_short_timeout;
		us.uscsi_bufaddr = NULL;
		us.uscsi_buflen = 0;
		TRACE((MMS_DEBUG, "Do LOAD"));
		if (DRV_CALL(drv_rewind, ()) == 0 &&
		    serr->se_dsreg == STATUS_GOOD) {
			break;
		} else {
			/* Error doing load */
			return (-1);
		}
	}
	if (i == DRV_LOAD_TUR) {
		return (-1);
	}
	drv->drv_flags &= ~DRV_MOVE_FLAGS;
	drv->drv_flags |= DRV_BOM;
	/*
	 * You can only get max capacity of tape at BOM
	 */
	if (drv_max_cap == -1) {
		drv_max_cap = DRV_CALL(drv_get_avail_capacity, ());
	}
	drv->drv_capacity = drv_max_cap;
	TRACE((MMS_DEBUG, "Cartridge \"%s\" loaded", mnt->mnt_pcl));
	return (0);
}
