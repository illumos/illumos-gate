/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <libintl.h>

#include "transport.h"
#include "toshiba.h"
#include "device.h"
#include "misc_scsi.h"
#include "util.h"
#include "main.h"
#include "msgs.h"
#include "mmc.h"

static int speed_tbl[4] = 		{ 1, 2, 12, 4 };
static uchar_t rev_speed_tbl[16] = 	{ 0, 0, 1, 0, 3, 0, 0, 0, 0,
					    0, 0, 0, 2, 0, 0, 0 };

/*
 * These are commands for using older Sun Toshiba drives. These
 * commands are needed for reading CD TOC and audio extraction
 * and changing speeds (used for audio extraction).
 */

int
read_toc_as_per_8020(int fd, int format, int trackno, int buflen, uchar_t *buf)
{
	struct uscsi_cmd *scmd;

	scmd = get_uscsi_cmd();
	scmd->uscsi_flags = USCSI_READ|USCSI_SILENT;
	scmd->uscsi_timeout = 60;
	scmd->uscsi_cdb[0] = READ_TOC_CMD;
	scmd->uscsi_cdb[6] = trackno;
	scmd->uscsi_cdb[8] = buflen & 0xff;
	scmd->uscsi_cdb[7] = (buflen >> 8) & 0xff;
	scmd->uscsi_cdb[9] = (format << 6) & 0xc0;
	scmd->uscsi_cdblen = 10;
	scmd->uscsi_bufaddr = (char *)buf;
	scmd->uscsi_buflen = buflen;
	if (uscsi(fd, scmd) < 0)
		return (0);
	return (1);
}

int
toshiba_read_audio(cd_device *target, uint_t start_blk, uint_t nblk,
    uchar_t *buf)
{
	struct uscsi_cmd *scmd;
	int ret, retry;

	scmd = get_uscsi_cmd();
	scmd->uscsi_flags = USCSI_READ|USCSI_SILENT;
	scmd->uscsi_timeout = 60;
	((uchar_t *)scmd->uscsi_cdb)[0] = READ_AUDIO_CMD;
	scmd->uscsi_cdb[5] = start_blk & 0xff;
	scmd->uscsi_cdb[4] = (start_blk >> 8) & 0xff;
	scmd->uscsi_cdb[3] = (start_blk >> 16) & 0xff;
	scmd->uscsi_cdb[2] = (start_blk >> 24) & 0xff;
	scmd->uscsi_cdb[9] = nblk & 0xff;
	scmd->uscsi_cdb[8] = (nblk >> 8) & 0xff;
	scmd->uscsi_cdb[7] = (nblk >> 16) & 0xff;
	scmd->uscsi_cdb[6] = (nblk >> 24) & 0xff;
	scmd->uscsi_cdblen = 12;
	scmd->uscsi_bufaddr = (char *)buf;
	scmd->uscsi_buflen = nblk*2352;

	for (retry = 0; retry < 3; retry++) {
		ret = uscsi(target->d_fd, scmd);
		if (ret >= 0)
			break;
	}

	if (ret < 0)
		return (0);
	return (1);
}

int
toshiba_speed_ctrl(cd_device *dev, int cmd, int speed)
{
	uchar_t *mpage;
	struct uscsi_cmd *scmd;
	int ret;

	if ((cmd == GET_WRITE_SPEED) || (cmd == SET_WRITE_SPEED)) {
		if (debug) {
			(void) printf("toshiba_speed_ctrl: WRONG CMD %d\n",
			    cmd);
		}
		return (0);
	}

	if (cmd == SET_READ_SPEED) {
		if (dev->d_cap & DEV_CAP_SETTING_SPEED_NOT_ALLOWED) {
			if (verbose)
				err_msg(gettext(
				    "Cannot set speed on this device.\n"));
			return (0);
		}
		if (speed == 32) {
			if (strncmp("SUN32XCD",
			    (const char *)&dev->d_inq[24], 8) == 0)
				return (1);
		}
		if ((speed != 1) && (speed != 2) && (speed != 4) &&
		    (speed != 12)) {
			if (verbose)
				err_msg(gettext(
				"%dx speed is not supported by the device.\n"));
			return (0);
		}
	}

	ret = 0;
	mpage = (uchar_t *)my_zalloc(16);
	scmd = get_uscsi_cmd();
	scmd->uscsi_flags = USCSI_READ|USCSI_SILENT;
	scmd->uscsi_timeout = 60;
	scmd->uscsi_cdblen = 6;
	scmd->uscsi_bufaddr = (char *)mpage;
	scmd->uscsi_buflen = 16;
	/* 6 byte mode sense for older drives */
	scmd->uscsi_cdb[0] = MODE_SENSE_6_CMD;
	scmd->uscsi_cdb[2] = 0x31;
	scmd->uscsi_cdb[4] = 16;
	if (uscsi(dev->d_fd, scmd) < 0)
		goto end_speed_ctrl;
	if (cmd == GET_READ_SPEED) {
		ret = speed_tbl[mpage[14] & 0x3];
		goto end_speed_ctrl;
	}
	if (cmd == SET_READ_SPEED) {
		(void) memset(mpage, 0, 9);
		mpage[3] = 8;
		mpage[12] = 0x31;
		mpage[13] = 2;
		mpage[14] = rev_speed_tbl[speed];
		scmd = get_uscsi_cmd();
		scmd->uscsi_flags = USCSI_WRITE|USCSI_SILENT;
		scmd->uscsi_timeout = 60;
		scmd->uscsi_cdblen = 6;
		scmd->uscsi_bufaddr = (char *)mpage;
		scmd->uscsi_buflen = 16;
		/* 6 byte mode sense command for older drives */
		scmd->uscsi_cdb[0] = MODE_SELECT_6_CMD;
		scmd->uscsi_cdb[1] = 0x10;
		scmd->uscsi_cdb[4] = 16;
		if (uscsi(dev->d_fd, scmd) < 0)
			goto end_speed_ctrl;
		ret = 1;
	}
end_speed_ctrl:
	free(mpage);
	return (ret);
}
