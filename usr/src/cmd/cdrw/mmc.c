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

#include <sys/types.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "transport.h"
#include "mmc.h"
#include "util.h"
#include "main.h"

int uscsi_error;

int
test_unit_ready(int fd)
{
	struct uscsi_cmd *scmd;

	scmd = get_uscsi_cmd();
	scmd->uscsi_flags = USCSI_SILENT;
	scmd->uscsi_timeout = DEFAULT_SCSI_TIMEOUT;
	/* give length of cdb structure */
	scmd->uscsi_cdblen = 6;
	if ((uscsi_error = uscsi(fd, scmd)) < 0)
		return (0);
	return (1);
}

int
inquiry(int fd, uchar_t *inq)
{
	struct uscsi_cmd *scmd;

	scmd = get_uscsi_cmd();
	scmd->uscsi_flags = USCSI_READ|USCSI_SILENT;
	scmd->uscsi_timeout = DEFAULT_SCSI_TIMEOUT;
	scmd->uscsi_cdb[0] = INQUIRY_CMD;
	scmd->uscsi_cdb[4] = INQUIRY_DATA_LENGTH;
	scmd->uscsi_cdblen = 6;
	scmd->uscsi_bufaddr = (char *)inq;
	scmd->uscsi_buflen = INQUIRY_DATA_LENGTH;
	if ((uscsi_error = uscsi(fd, scmd)) < 0)
		return (0);
	return (1);
}

int
read_capacity(int fd, uchar_t *capbuf)
{
	struct uscsi_cmd *scmd;

	scmd = get_uscsi_cmd();
	scmd->uscsi_flags = USCSI_READ|USCSI_SILENT;
	scmd->uscsi_timeout = DEFAULT_SCSI_TIMEOUT;
	scmd->uscsi_cdb[0] = READ_CAP_CMD;
	scmd->uscsi_cdblen = 10;
	scmd->uscsi_bufaddr = (char *)capbuf;
	scmd->uscsi_buflen = 8;
	if ((uscsi_error = uscsi(fd, scmd)) < 0)
		return (0);
	return (1);
}

int
mode_sense(int fd, uchar_t pc, int dbd, int page_len, uchar_t *buffer)
{
	struct uscsi_cmd *scmd;

	scmd = get_uscsi_cmd();
	scmd->uscsi_flags = USCSI_READ|USCSI_SILENT;
	scmd->uscsi_buflen = page_len;
	scmd->uscsi_bufaddr = (char *)buffer;
	scmd->uscsi_timeout = DEFAULT_SCSI_TIMEOUT;
	scmd->uscsi_cdblen = 0xa;
	scmd->uscsi_cdb[0] = MODE_SENSE_10_CMD;
	if (dbd) {
		/* don't return any block descriptors */
		scmd->uscsi_cdb[1] = 0x8;
	}
	/* the page code we want */
	scmd->uscsi_cdb[2] = pc;
	/* allocation length */
	scmd->uscsi_cdb[7] = (page_len >> 8) & 0xff;
	scmd->uscsi_cdb[8] = page_len & 0xff;

	if ((uscsi_error = uscsi(fd, scmd)) < 0)
		return (0);
	return (1);
}

int
mode_select(int fd, int page_len, uchar_t *buffer)
{
	struct uscsi_cmd *scmd;

	scmd = get_uscsi_cmd();
	scmd->uscsi_flags = USCSI_WRITE|USCSI_SILENT;
	scmd->uscsi_buflen = page_len;
	scmd->uscsi_bufaddr = (char *)buffer;
	scmd->uscsi_timeout = DEFAULT_SCSI_TIMEOUT;
	scmd->uscsi_cdblen = 0xa;

	/* mode select (10) command */
	scmd->uscsi_cdb[0] = MODE_SELECT_10_CMD;
	scmd->uscsi_cdb[1] = 0x10;

	/* parameter list length */
	scmd->uscsi_cdb[7] = (page_len >> 8) & 0xff;
	scmd->uscsi_cdb[8] = page_len & 0xff;

	if ((uscsi_error = uscsi(fd, scmd)) < 0)
		return (0);
	return (1);
}

int
read_track_info(int fd, int trackno, uchar_t *ti)
{
	struct uscsi_cmd *scmd;

	scmd = get_uscsi_cmd();
	scmd->uscsi_flags = USCSI_READ|USCSI_SILENT;
	scmd->uscsi_timeout = DEFAULT_SCSI_TIMEOUT;
	scmd->uscsi_cdb[0] = READ_TRACK_CMD;

	/* tell device we are giving it a track number */
	scmd->uscsi_cdb[1] = 1;

	/* track number to read */
	if (trackno == -1)
		if (device_type == CD_RW) {
			((uchar_t *)scmd->uscsi_cdb)[5] = 0xff;
		} else {
			/* only 1 track is allowed on DVD media */
			scmd->uscsi_cdb[1] = 0;
			((uchar_t *)scmd->uscsi_cdb)[5] = 0;
		}
	else
		scmd->uscsi_cdb[5] = (uchar_t)trackno;

	scmd->uscsi_cdb[8] = TRACK_INFO_SIZE;
	scmd->uscsi_cdblen = 10;
	scmd->uscsi_bufaddr = (char *)ti;
	scmd->uscsi_buflen = TRACK_INFO_SIZE;
	if ((uscsi_error = uscsi(fd, scmd)) < 0)
		return (0);
	return (1);
}

int
read_toc(int fd, int format, int trackno, int buflen, uchar_t *buf)
{
	struct uscsi_cmd *scmd;

	scmd = get_uscsi_cmd();
	scmd->uscsi_flags = USCSI_READ|USCSI_SILENT;
	scmd->uscsi_timeout = DEFAULT_SCSI_TIMEOUT;
	scmd->uscsi_cdb[0] = READ_TOC_CMD;
	scmd->uscsi_cdb[2] = format & 0xf;
	scmd->uscsi_cdb[6] = trackno;
	scmd->uscsi_cdb[8] = buflen & 0xff;
	scmd->uscsi_cdb[7] = (buflen >> 8) & 0xff;
	scmd->uscsi_cdblen = 10;
	scmd->uscsi_bufaddr = (char *)buf;
	scmd->uscsi_buflen = buflen;
	if ((uscsi_error = uscsi(fd, scmd)) < 0)
		return (0);

	/* Fix for old SONY drives */
	if ((format == 0) && (buflen == 4) && (buf[0] == 0) && (buf[1] == 2)) {
		uint16_t toc_size;

		toc_size = (((uint16_t)(buf[3] + 1)) * 8) + 2;
		load_scsi16(buf, toc_size);
	}
	return (1);
}

int
read_header(int fd, uint32_t lba, uchar_t *buf)
{
	struct uscsi_cmd *scmd;

	scmd = get_uscsi_cmd();
	scmd->uscsi_flags = USCSI_READ|USCSI_SILENT;
	scmd->uscsi_timeout = DEFAULT_SCSI_TIMEOUT;
	scmd->uscsi_cdb[0] = READ_HDR_CMD;

	/* Logical block address */
	load_scsi32(&scmd->uscsi_cdb[2], lba);

	/* allocation length */
	scmd->uscsi_cdb[8] = 8;
	scmd->uscsi_cdblen = 10;
	scmd->uscsi_bufaddr = (char *)buf;
	scmd->uscsi_buflen = 8;
	if ((uscsi_error = uscsi(fd, scmd)) < 0)
		return (0);
	return (1);
}

int
read_disc_info(int fd, uchar_t *di)
{
	struct uscsi_cmd *scmd;

	scmd = get_uscsi_cmd();
	scmd->uscsi_flags = USCSI_READ|USCSI_SILENT;
	scmd->uscsi_timeout = DEFAULT_SCSI_TIMEOUT;
	scmd->uscsi_cdb[0] = READ_INFO_CMD;
	scmd->uscsi_cdb[8] = DISC_INFO_BLOCK_SIZE;
	scmd->uscsi_cdblen = 10;
	scmd->uscsi_bufaddr = (char *)di;
	scmd->uscsi_buflen = DISC_INFO_BLOCK_SIZE;
	if ((uscsi_error = uscsi(fd, scmd)) < 0)
		return (0);
	return (1);
}

/* Get information about the Logical Unit's capabilities */
int
get_configuration(int fd, uint16_t feature, int bufsize, uchar_t *buf)
{
	struct uscsi_cmd *scmd;

	scmd = get_uscsi_cmd();
	scmd->uscsi_flags = USCSI_READ|USCSI_SILENT;
	scmd->uscsi_timeout = DEFAULT_SCSI_TIMEOUT;

	/* Set OPERATION CODE in CDB */
	scmd->uscsi_cdb[0] = GET_CONFIG_CMD;

	/*
	 * Set RT field in CDB, currently need at most one
	 * Feature Descriptor
	 */
	scmd->uscsi_cdb[1] = 0x2;

	/* Set Starting Feature Number in CDB */
	scmd->uscsi_cdb[2] = (feature >> 8) & 0xff;
	scmd->uscsi_cdb[3] = feature & 0xff;

	/* Set Allocation Length in CDB */
	scmd->uscsi_cdb[7] = (bufsize >> 8) & 0xff;
	scmd->uscsi_cdb[8] = bufsize & 0xff;

	scmd->uscsi_cdblen = 10;
	scmd->uscsi_bufaddr = (char *)buf;
	scmd->uscsi_buflen = bufsize;
	if ((uscsi_error = uscsi(fd, scmd)) < 0)
		return (0);
	return (1);
}

int
read10(int fd, uint32_t start_blk, uint16_t nblk, uchar_t *buf,
    uint32_t bufsize)
{
	struct uscsi_cmd *scmd;

	scmd = get_uscsi_cmd();
	scmd->uscsi_flags = USCSI_READ|USCSI_SILENT;
	scmd->uscsi_timeout = DEFAULT_SCSI_TIMEOUT;
	scmd->uscsi_cdb[0] = READ_10_CMD;
	load_scsi32(&scmd->uscsi_cdb[2], start_blk);
	scmd->uscsi_cdb[8] = nblk & 0xff;
	scmd->uscsi_cdb[7] = (nblk >> 8) & 0xff;
	scmd->uscsi_cdblen = 10;
	scmd->uscsi_bufaddr = (char *)buf;
	scmd->uscsi_buflen = bufsize;
	if ((uscsi_error = uscsi(fd, scmd)) < 0)
		return (0);
	return (1);
}

int
write10(int fd, uint32_t start_blk, uint16_t nblk, uchar_t *buf,
    uint32_t bufsize)
{
	struct uscsi_cmd *scmd;

	scmd = get_uscsi_cmd();
	scmd->uscsi_flags = USCSI_WRITE|USCSI_SILENT;
	/*
	 * Some DVD drives take longer to write than
	 * the standard time, since they tend to generate
	 * the media TOC on the fly when the cache is full
	 */
	scmd->uscsi_timeout = DEFAULT_SCSI_TIMEOUT * 3;
	scmd->uscsi_cdb[0] = WRITE_10_CMD;
	load_scsi32(&scmd->uscsi_cdb[2], start_blk);
	scmd->uscsi_cdb[8] = nblk & 0xff;
	scmd->uscsi_cdb[7] = (nblk >> 8) & 0xff;
	scmd->uscsi_cdblen = 10;
	scmd->uscsi_bufaddr = (char *)buf;
	scmd->uscsi_buflen = bufsize;
	if ((uscsi_error = uscsi(fd, scmd)) < 0)
		return (0);
	return (1);
}

int
close_track(int fd, int trackno, int close_session, int immediate)
{
	struct uscsi_cmd *scmd;

	scmd = get_uscsi_cmd();
	scmd->uscsi_flags = USCSI_SILENT;
	scmd->uscsi_cdb[0] = CLOSE_TRACK_CMD;
	if (immediate) {
		scmd->uscsi_timeout = DEFAULT_SCSI_TIMEOUT;
		scmd->uscsi_cdb[1] = 1;
	} else {
		scmd->uscsi_timeout = 240;
	}
	if ((close_session) || (device_type == DVD_PLUS) ||
	    (device_type == DVD_PLUS_W)) {
		/* close the session */
		scmd->uscsi_cdb[2] = 2;

	} else {
		/* Close the track but leave session open */
		scmd->uscsi_cdb[2] = 1;
		scmd->uscsi_cdb[5] = trackno & 0xff;
	}

	/*
	 * DVD+R media are already formatted, we are using
	 * a special case to notify that drive to close
	 * track/session and null-fill the remaining space.
	 */
	if (device_type == DVD_PLUS) {
		scmd->uscsi_cdb[5] = 1; /* only 1 track */

		if (close_session) {
			scmd->uscsi_cdb[2] = 6; /* session */
		} else {
			scmd->uscsi_cdb[2] = 1; /* track */
		}
	}

	scmd->uscsi_cdblen = 10;
	if ((uscsi_error = uscsi(fd, scmd)) < 0)
		return (0);
	return (1);
}

int
blank_disc(int fd, int type, int immediate)
{
	struct uscsi_cmd *scmd;

	scmd = get_uscsi_cmd();
	scmd->uscsi_flags = USCSI_SILENT;

	if (immediate) {
		scmd->uscsi_timeout = DEFAULT_SCSI_TIMEOUT;
		scmd->uscsi_cdb[1] = 0x10;
	} else {
		scmd->uscsi_timeout = 0x12c0;
	}
	((uchar_t *)scmd->uscsi_cdb)[0] = BLANK_CMD;

	/* tell it to blank the last session or all of the disk */
	scmd->uscsi_cdb[1] |= type & 0x07;
	scmd->uscsi_cdblen = 12;

	if ((uscsi_error = uscsi(fd, scmd)) < 0)
		return (0);
	return (1);
}

int
read_cd(int fd, uint32_t start_blk, uint16_t nblk, uchar_t sector_type,
    uchar_t *buf, uint32_t bufsize)
{
	struct uscsi_cmd *scmd;

	scmd = get_uscsi_cmd();
	scmd->uscsi_flags = USCSI_READ|USCSI_SILENT;
	scmd->uscsi_timeout = DEFAULT_SCSI_TIMEOUT;
	((uchar_t *)scmd->uscsi_cdb)[0] = READ_CD_CMD;
	scmd->uscsi_cdb[1] = (sector_type & 0x7) << 2;
	scmd->uscsi_cdb[5] = start_blk & 0xff;
	scmd->uscsi_cdb[4] = (start_blk >> 8) & 0xff;
	scmd->uscsi_cdb[3] = (start_blk >> 16) & 0xff;
	scmd->uscsi_cdb[2] = (start_blk >> 24) & 0xff;
	scmd->uscsi_cdb[8] = nblk & 0xff;
	scmd->uscsi_cdb[7] = (nblk >> 8) & 0xff;
	scmd->uscsi_cdb[9] = 0x10;
	scmd->uscsi_cdblen = 12;
	scmd->uscsi_bufaddr = (char *)buf;
	scmd->uscsi_buflen = bufsize;
	if ((uscsi_error = uscsi(fd, scmd)) < 0)
		return (0);
	return (1);
}

int
load_unload(int fd, int load)
{
	struct uscsi_cmd *scmd;

	scmd = get_uscsi_cmd();
	scmd->uscsi_flags = USCSI_SILENT;
	scmd->uscsi_timeout = DEFAULT_SCSI_TIMEOUT;
	scmd->uscsi_cdb[0] = START_STOP_CMD;
	if (load == 0) {
		/* unload medium */
		scmd->uscsi_cdb[4] = 2;
	} else {
		/* load medium */
		scmd->uscsi_cdb[4] = 3;
	}
	scmd->uscsi_cdblen = 6;

	if ((uscsi_error = uscsi(fd, scmd)) < 0)
		return (0);
	return (1);
}

int
prevent_allow_mr(int fd, int op)
{
	struct uscsi_cmd *scmd;

	scmd = get_uscsi_cmd();
	scmd->uscsi_flags = USCSI_SILENT;
	scmd->uscsi_timeout = DEFAULT_SCSI_TIMEOUT;
	scmd->uscsi_cdb[0] = PREVENT_ALLOW_CMD;
	if (!op) {	/* prevent */
		scmd->uscsi_cdb[4] = 1;
	}
	scmd->uscsi_cdblen = 6;
	if ((uscsi_error = uscsi(fd, scmd)) < 0)
		return (0);
	return (1);
}

int
set_cd_speed(int fd, uint16_t read_speed, uint16_t write_speed)
{
	struct uscsi_cmd *scmd;

	scmd = get_uscsi_cmd();
	scmd->uscsi_flags = USCSI_SILENT;
	scmd->uscsi_timeout = DEFAULT_SCSI_TIMEOUT;
	scmd->uscsi_cdblen = 0xc;
	((uchar_t *)scmd->uscsi_cdb)[0] = SET_CD_SPEED;
	scmd->uscsi_cdb[2] = (read_speed >> 8) & 0xff;
	scmd->uscsi_cdb[3] = read_speed & 0xff;
	scmd->uscsi_cdb[4] = (write_speed >> 8) & 0xff;
	scmd->uscsi_cdb[5] = write_speed & 0xff;

	if ((uscsi_error = uscsi(fd, scmd)) < 0)
		return (0);
	return (1);
}

int
get_performance(int fd, int get_write_performance, uchar_t *perf)
{
	struct uscsi_cmd *scmd;

	scmd = get_uscsi_cmd();
	scmd->uscsi_flags = USCSI_READ|USCSI_SILENT;
	scmd->uscsi_buflen = GET_PERF_DATA_LEN;
	scmd->uscsi_bufaddr = (char *)perf;
	scmd->uscsi_timeout = DEFAULT_SCSI_TIMEOUT;
	scmd->uscsi_cdblen = 0xc;
	((uchar_t *)scmd->uscsi_cdb)[0] = GET_PERFORMANCE_CMD;
	scmd->uscsi_cdb[1] = 0x10;
	if (get_write_performance)
		scmd->uscsi_cdb[1] |= 4;
	scmd->uscsi_cdb[9] = 2;
	if ((uscsi_error = uscsi(fd, scmd)) < 0)
		return (0);
	return (1);
}

int
set_streaming(int fd, uchar_t *buf)
{
	struct uscsi_cmd *scmd;

	scmd = get_uscsi_cmd();
	scmd->uscsi_flags = USCSI_WRITE|USCSI_SILENT;
	scmd->uscsi_buflen = SET_STREAM_DATA_LEN;
	scmd->uscsi_bufaddr = (char *)buf;
	scmd->uscsi_timeout = DEFAULT_SCSI_TIMEOUT;
	scmd->uscsi_cdblen = 0xc;
	((uchar_t *)scmd->uscsi_cdb)[0] = STREAM_CMD;
	scmd->uscsi_cdb[10] = SET_STREAM_DATA_LEN;
	if ((uscsi_error = uscsi(fd, scmd)) < 0)
		return (0);
	return (1);
}

int
rezero_unit(int fd)
{
	struct uscsi_cmd *scmd;

	scmd = get_uscsi_cmd();
	scmd->uscsi_flags = USCSI_SILENT;
	scmd->uscsi_timeout = DEFAULT_SCSI_TIMEOUT;
	scmd->uscsi_cdblen = 0x6;
	scmd->uscsi_cdb[0] = REZERO_UNIT_CMD;
	if ((uscsi_error = uscsi(fd, scmd)) < 0)
		return (0);
	return (1);
}

int
start_stop(int fd, int start)
{
	struct uscsi_cmd *scmd;

	scmd = get_uscsi_cmd();
	scmd->uscsi_flags = USCSI_SILENT;
	scmd->uscsi_timeout = DEFAULT_SCSI_TIMEOUT;
	scmd->uscsi_cdblen = 0x6;
	scmd->uscsi_cdb[0] = START_STOP_CMD;
	if (start) {
		scmd->uscsi_cdb[4] = 1;
	}
	if ((uscsi_error = uscsi(fd, scmd)) < 0)
		return (0);
	return (1);
}

int
flush_cache(int fd)
{
	struct uscsi_cmd *scmd;

	scmd = get_uscsi_cmd();
	scmd->uscsi_flags = USCSI_SILENT;
	scmd->uscsi_timeout = DEFAULT_SCSI_TIMEOUT;
	scmd->uscsi_cdblen = 10;
	scmd->uscsi_cdb[0] = SYNC_CACHE_CMD;
	if (device_type != CD_RW) {
		scmd->uscsi_cdb[1] = 0x2; /* Immediate */
	}

	if ((uscsi_error = uscsi(fd, scmd)) < 0)
		return (0);
	return (1);
}

/*
 * used for DVD- to reserve the size we want to write.
 * This is used by the drive to generate a TOC.
 */
int
set_reservation(int fd, ulong_t size)
{
	struct uscsi_cmd *scmd;

	scmd = get_uscsi_cmd();
	scmd->uscsi_flags = USCSI_READ|USCSI_SILENT;
	scmd->uscsi_timeout = DEFAULT_SCSI_TIMEOUT;
	scmd->uscsi_cdb[0] = SET_RESERVATION_CMD;
	scmd->uscsi_cdblen = 10;
	scmd->uscsi_cdb[5] = (uchar_t)(size >> 24);
	scmd->uscsi_cdb[6] = (uchar_t)(size >> 16);
	scmd->uscsi_cdb[7] = (uchar_t)(size >> 8);
	scmd->uscsi_cdb[8] = (uchar_t)size;
	if ((uscsi_error = uscsi(fd, scmd)) < 0)
		return (0);
	return (1);
}

/*
 * Used for DVD+RW media to prepare the disk to write.
 * It will also be used for packet mode writing when
 * it becomes supported.
 */
int
format_media(int fd)
{
	struct uscsi_cmd *scmd;
	uchar_t buf[20];

	(void) memset(buf, 0, 20);
	scmd = get_uscsi_cmd();
	scmd->uscsi_flags = USCSI_READ|USCSI_SILENT;
	scmd->uscsi_timeout = DEFAULT_SCSI_TIMEOUT;

	scmd->uscsi_cdblen = 12;
	scmd->uscsi_cdb[0] = READ_FORMAT_CAP_CMD;
	scmd->uscsi_cdb[8] = 0x14; /* buffer length */
	scmd->uscsi_buflen = 20;
	scmd->uscsi_bufaddr = (char *)buf;

	if ((uscsi_error = uscsi(fd, scmd)) < 0)
		return (0);

	/* RE-use cap structure */

	scmd->uscsi_flags = USCSI_WRITE|USCSI_SILENT;
	scmd->uscsi_timeout = DEFAULT_SCSI_TIMEOUT;
	scmd->uscsi_cdblen = 6;
	scmd->uscsi_cdb[0] = FORMAT_UNIT_CMD;
	/* full format */
	scmd->uscsi_cdb[1] = 0x11;
	scmd->uscsi_buflen = 12;
	buf[1] = 0x82; /* immediate and FOV */
	buf[3] = 8;	/* descriptor length */
	buf[8] = 0x98;	/* type = 26 DVD+RW format */
	buf[10] = 0;

	if ((uscsi_error = uscsi(fd, scmd)) < 0)
		return (0);
	return (1);
}


/*
 * Prefered method of reading the media size. This is
 * the only supported method on several newer drives.
 */
uint32_t
read_format_capacity(int fd, uint_t *bsize)
{
	struct uscsi_cmd *scmd;
	uint32_t filesize;
	char buf[20];

	scmd = get_uscsi_cmd();
	scmd->uscsi_flags = USCSI_READ|USCSI_SILENT;
	scmd->uscsi_timeout = DEFAULT_SCSI_TIMEOUT;
	scmd->uscsi_cdblen = 12;
	scmd->uscsi_cdb[0] = READ_FORMAT_CAP_CMD;
	scmd->uscsi_cdb[8] = 0x14;
	scmd->uscsi_buflen = 20;
	scmd->uscsi_bufaddr = buf;

	if ((uscsi_error = uscsi(fd, scmd)) < 0)
		return (0);

	filesize =  (uint32_t)(((uchar_t)buf[4] << 24) +
	    ((uchar_t)buf[5] << 16) + ((uchar_t)buf[6] << 8) + (uchar_t)buf[7]);

	*bsize = (uint16_t)(((uchar_t)buf[10] << 8) + (uchar_t)buf[11]);

	return (filesize);
}

/*
 * Used to reset the device. Since, sd(4D) requires a
 * command to be issued when resetting a device we will
 * issue an innocuous command. The command chosen for this
 * purpose is the TEST UNIT READY (TUR) command. We also do
 * not care about the sucess of the TUR so we will not return
 * a value.
 */
void
reset_dev(int fd)
{
	struct uscsi_cmd *scmd;

	/*
	 * Since a TUR has SCSI operation code of 0, we
	 * can make use of the fact that get_uscsi_cmd()
	 * initializes a CDB to all zeros to generate
	 * the TUR command.
	 */
	scmd = get_uscsi_cmd();

	/* Tell sd(4D) to do a silent reset of the device. */
	scmd->uscsi_flags = USCSI_SILENT | USCSI_RESET;

	scmd->uscsi_timeout = DEFAULT_SCSI_TIMEOUT;
	scmd->uscsi_cdblen = 6;

	/* Issue the TUR command. */
	uscsi_error = uscsi(fd, scmd);
}


/*
 * Function:    ftr_supported
 *
 * Description: Check to see if a device supports a Feature
 *
 * Arguments:   fd      - file descriptor
 *              feature - the MMC Feature for which we'd like to know
 *                        if there's support
 *
 * Return Code: 1       - Feature is supported
 *		0	- Feature is not supported
 *
 */
int
ftr_supported(int fd, uint16_t feature)
{
	size_t response_len;
	uchar_t *bufp;
	int ret;

	response_len = MMC_FTR_HDR_LEN + MMC_FTR_DSCRPTR_BASE_LEN;
	bufp = (uchar_t *)my_zalloc(response_len);

	/*
	 * If a Feature is supported, a device will return a Feature Descriptor
	 * for that Feature, and its Current Bit will be set.
	 */
	if (get_configuration(fd, feature, response_len, bufp) == 1) {
		/*
		 * To check that a Feature Descriptor was returned, we
		 * check to see if the Data Length field of the Feature
		 * Header holds a value greater than four.  To check if
		 * the Current Bit is set, we check bit 1 of byte 10.
		 */
		if (read_scsi32(bufp) > 4 && bufp[10] & 1)
			ret = 1;
		else
			ret = 0;
	} else {
		/* get_configuration failed */
		ret = 0;
	}
	free(bufp);
	return (ret);
}

/*
 * Function:    print_profile_name
 *
 * Description: Prints a list of the Profiles the device supports
 *
 * Parameters:  num     - hexadecimal representation of Profile
 *              current - 1 if the Profile is Current, otherwise 0
 *		abbr	- 1 if printing abbreviated name, otherwise 0
 */
void
print_profile_name(uint16_t num, uchar_t current, uchar_t abbr)
{
	if (abbr != 1)
		(void) printf(" 0x%04x: ", num);

	switch (num) {
	case 0x0000:
		(void) printf("No Current Profile");
		break;
	case 0x0001:
		(void) printf("Non-Removable Disk");
		break;
	case 0x0002:
		(void) printf("Removable Disk");
		break;
	case 0x0003:
		(void) printf("Magneto-Optical Erasable");
		break;
	case 0x0004:
		(void) printf("Optical Write Once");
		break;
	case 0x0005:
		(void) printf("AS-MO");
		break;
	case 0x0008:
		(void) printf("CD-ROM");
		break;
	case 0x0009:
		(void) printf("CD-R");
		break;
	case 0x000A:
		(void) printf("CD-RW");
		break;
	case 0x0010:
		(void) printf("DVD-ROM");
		break;
	case 0x0011:
		(void) printf("DVD-R");
		if (abbr != 1)
			(void) printf(" Sequential Recording");
		break;
	case 0x0012:
		(void) printf("DVD-RAM");
		break;
	case 0x0013:
		(void) printf("DVD-RW");
		if (abbr != 1)
			(void) printf(" Restricted Overwrite");
		break;
	case 0x0014:
		(void) printf("DVD-RW");
		if (abbr != 1)
			(void) printf(" Sequential Recording");
		break;
	case 0x0015:
		(void) printf("DVD-R");
		if (abbr != 1)
			(void) printf(" Dual Layer Sequential Recording");
		else
			(void) printf(" DL");
		break;
	case 0x0016:
		(void) printf("DVD-R");
		if (abbr != 1)
			(void) printf(" Dual Layer Jump Recording");
		else
			(void) printf(" DL");
		break;
	case 0x0017:
		(void) printf("DVD-RW");
		if (abbr != 1)
			(void) printf(" Dual Layer");
		else
			(void) printf(" DL");
		break;
	case 0x001A:
		(void) printf("DVD+RW");
		break;
	case 0x001B:
		(void) printf("DVD+R");
		break;
	case 0x0020:
		(void) printf("DDCD-ROM");
		break;
	case 0x0021:
		(void) printf("DDCD-R");
		break;
	case 0x0022:
		(void) printf("DDCD-RW");
		break;
	case 0x002A:
		(void) printf("DVD+RW");
		if (abbr != 1)
			(void) printf(" Dual Layer");
		else
			(void) printf(" DL");
		break;
	case 0x002B:
		(void) printf("DVD+R");
		if (abbr != 1)
			(void) printf(" Dual Layer");
		else
			(void) printf(" DL");
		break;
	case 0x0040:
		(void) printf("BD-ROM");
		break;
	case 0x0041:
		(void) printf("BD-R Sequential Recording (SRM) Profile");
		break;
	case 0x0042:
		(void) printf("BD-R Random Recording (RRM) Profile");
		break;
	case 0x0043:
		(void) printf("BD-RE");
		break;
	case 0xFFFF:
		(void) printf("Nonstandard Profile");
		break;
	default:
		break;
	}
	if (current == 1)
		(void) printf(" (Current Profile)");
	(void) printf("\n");
}

/*
 * Function: print_profile_list
 *
 * Description: Print a list of Profiles supported by the Logical Unit.
 *
 * Parameters:	fd	- file descriptor for device whose list of
 *			  profiles we wish to print
 */
void
print_profile_list(int fd)
{
	size_t i;
	size_t buflen;
	uint16_t current;
	uint16_t other;
	uchar_t *bufp = (uchar_t *)my_zalloc(MMC_FTR_HDR_LEN);

	/*
	 * First get_configuration call is used to determine amount of memory
	 * needed to hold all the Profiles.  The first four bytes of bufp
	 * concatenated tell us the number of bytes of memory we need but do
	 * not take themselves into account.  Therefore, add four, and
	 * allocate that number of bytes.
	 */
	if (get_configuration(fd, MMC_FTR_PRFL_LIST, MMC_FTR_HDR_LEN,
	    bufp)) {
		buflen = read_scsi32(bufp) + 4;
		free(bufp);
		bufp = (uchar_t *)my_zalloc(buflen);

		/*
		 * Now get all the Profiles
		 */
		if (get_configuration(fd, MMC_FTR_PRFL_LIST, buflen, bufp)) {
			(void) printf("\nProfile List\n");
			(void) printf("---------------------------------\n");

			/*
			 * Find out the Logical Unit's Current Profile
			 */
			current = read_scsi16(&bufp[6]);

			/*
			 * Print out the Profile List and indicate which
			 * Profile is Current
			 */
			for (i = MMC_FTR_HDR_LEN + MMC_FTR_DSCRPTR_BASE_LEN;
			    i < buflen; i += MMC_PRFL_DSCRPTR_LEN) {
				other = read_scsi16(&bufp[i]);
				if (other == current)
					print_profile_name(other, 1, 0);
				else
					print_profile_name(other, 0, 0);
			}
			(void) printf("\n");
		}
	}
	free(bufp);
}
