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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/dkio.h>
#include <unistd.h>
#include <errno.h>
#include <libintl.h>
#include <sys/time.h>

#include "mmc.h"
#include "util.h"
#include "misc_scsi.h"
#include "transport.h"
#include "main.h"
#include "toshiba.h"
#include "msgs.h"
#include "device.h"

static int check_track_size(cd_device *dev, int trk_num,
    struct track_info *tip);
static int rtoc_get_trk_sess_num(uchar_t *rtoc, size_t rtoc_len, int trk_num,
    int *sess_nump);
static int rtoc_get_sess_last_trk_num(uchar_t *rtoc, size_t rtoc_len,
    int sess_num, int *last_trk_nump);
static int rtoc_get_sess_leadout_lba(uchar_t *rtoc, size_t rtoc_len,
    int sess_num, uint32_t *leadout_lba);
static rtoc_td_t *get_rtoc_td(rtoc_td_t *begin_tdp, rtoc_td_t *end_tdp,
    uchar_t adr, uchar_t point);

uint32_t
read_scsi32(void *addr)
{
	uchar_t *ad = (uchar_t *)addr;
	uint32_t ret;

	ret = ((((uint32_t)ad[0]) << 24) | (((uint32_t)ad[1]) << 16) |
	    (((uint32_t)ad[2]) << 8) | ad[3]);
	return (ret);
}

uint16_t
read_scsi16(void *addr)
{
	uchar_t *ad = (uchar_t *)addr;
	uint16_t ret;

	ret = ((((uint16_t)ad[0]) << 8) | ad[1]);
	return (ret);
}

void
load_scsi32(void *addr, uint32_t v)
{
	uchar_t *ad = (uchar_t *)addr;

	ad[0] = (uchar_t)(v >> 24);
	ad[1] = (uchar_t)(v >> 16);
	ad[2] = (uchar_t)(v >> 8);
	ad[3] = (uchar_t)v;
}

void
load_scsi16(void *addr, uint16_t v)
{
	uchar_t *ad = (uchar_t *)addr;
	ad[0] = (uchar_t)(v >> 8);
	ad[1] = (uchar_t)v;
}
/*
 * will get the mode page only i.e. will strip off the header.
 */
int
get_mode_page(int fd, int page_no, int pc, int buf_len, uchar_t *buffer)
{
	int ret;
	uchar_t byte2, *buf;
	uint_t header_len, page_len, copy_cnt;

	byte2 = (uchar_t)(((pc << 6) & 0xC0) | (page_no & 0x3f));
	buf = (uchar_t *)my_zalloc(256);

	/* Ask 254 bytes only to make our IDE driver happy */
	ret = mode_sense(fd, byte2, 1, 254, buf);
	if (ret == 0) {
		free(buf);
		return (0);
	}

	header_len = 8 + read_scsi16(&buf[6]);
	page_len = buf[header_len + 1] + 2;

	copy_cnt = (page_len > buf_len) ? buf_len : page_len;
	(void) memcpy(buffer, &buf[header_len], copy_cnt);
	free(buf);

	return (1);
}

/*
 * will take care of adding mode header and any extra bytes at the end.
 */
int
set_mode_page(int fd, uchar_t *buffer)
{
	int ret;
	uchar_t *buf;
	uint_t total, p_len;

	p_len = buffer[1] + 2;
	total = p_len + 8;
	buf = (uchar_t *)my_zalloc(total);

	(void) memcpy(&buf[8], buffer, p_len);
	if (debug) {
		int i;

		(void) printf("MODE: [");
		for (i = 0; i < p_len; i++) {
			(void) printf("0x%02x ", (uchar_t)buffer[i]);
		}

		(void) printf("]\n");
	}
	ret = mode_select(fd, total, buf);
	free(buf);

	return (ret);
}

/*
 * Builds track information database for track trackno. If trackno is
 * -1, builds the database for next blank track.
 */
int
build_track_info(cd_device *dev, int trackno, struct track_info *t_info)
{
	uchar_t *ti;
	uchar_t toc[20];		/* 2 entries + 4 byte header */
	int ret;

	(void) memset(t_info, 0, sizeof (*t_info));
	/* 1st try READ TRACK INFORMATION */
	ti = (uchar_t *)my_zalloc(TRACK_INFO_SIZE);
	t_info->ti_track_no = trackno;

	/* Gererate faked information for writing to DVD */
	if (device_type != CD_RW) {
		uint_t bsize;

		t_info->ti_flags = 0x3000;
		t_info->ti_track_no = 1;
		t_info->ti_session_no = 1;
		t_info->ti_track_mode = 0x4;
		t_info->ti_data_mode = 1;
		t_info->ti_start_address = 0;

		/* only 1 track on DVD make it max size */
		t_info->ti_track_size = read_format_capacity(target->d_fd,
		    &bsize);
		if (t_info->ti_track_size < MAX_CD_BLKS) {
			t_info->ti_track_size = MAX_DVD_BLKS;
		}

		t_info->ti_nwa = 0;
		t_info->ti_lra = 0;
		t_info->ti_packet_size = 0x10;
		t_info->ti_free_blocks = 0;
	}

	if (read_track_info(dev->d_fd, trackno, ti)) {

		if (debug)
			(void) printf("using read_track_info for TOC \n");

		t_info->ti_track_no = ti[2];
		t_info->ti_session_no = ti[3];
		t_info->ti_flags = (ti[6] >> 4) & 0xf;
		t_info->ti_flags |= (uint32_t)(ti[5] & 0xf0);
		t_info->ti_flags |= (uint32_t)(ti[7]) << 8;
		t_info->ti_flags |= TI_SESSION_NO_VALID | TI_FREE_BLOCKS_VALID;
		t_info->ti_track_mode = ti[5] & 0xf;
		if ((ti[6] & 0xf) == 0xf)
			t_info->ti_data_mode = 0xff;
		else
			t_info->ti_data_mode = ti[6] & 0xf;
		t_info->ti_start_address = read_scsi32(&ti[8]);
		t_info->ti_nwa = read_scsi32(&ti[12]);
		t_info->ti_free_blocks = read_scsi32(&ti[16]);
		t_info->ti_packet_size = read_scsi32(&ti[20]);
		t_info->ti_track_size = read_scsi32(&ti[24]);
		t_info->ti_lra = read_scsi32(&ti[28]);
		free(ti);
		return (1);
	}
	/* READ TRACK INFORMATION not supported, try other options */
	free(ti);
	/*
	 * We can get info for next blank track if READ TRACK INFO is not
	 * supported.
	 */
	if (trackno == -1)
		return (0);

	if (debug)
		(void) printf("using READ_TOC for TOC\n");

	/* Try Read TOC */
	if (!read_toc(dev->d_fd, 0, trackno, 20, toc)) {
		return (0);
	}
	t_info->ti_start_address = read_scsi32(&toc[8]);
	t_info->ti_track_mode = toc[5] & 0xf;
	t_info->ti_track_size = read_scsi32(&toc[16]) - read_scsi32(&toc[8]);
	t_info->ti_data_mode = get_data_mode(dev->d_fd, read_scsi32(&toc[8]));

	/* Numbers for audio tracks are always in 2K chunks */
	if ((dev->d_blksize == 512) && ((t_info->ti_track_mode & 4) == 0)) {
		t_info->ti_start_address /= 4;
		t_info->ti_track_size /= 4;
	}

	/* Now find out the session thing */
	ret = read_toc(dev->d_fd, 1, trackno, 12, toc);

	/*
	 * Make sure that the call succeeds and returns the requested
	 * TOC size correctly.
	 */

	if ((ret == 0) || (toc[1] != 0x0a)) {

		/* For ATAPI drives or old Toshiba drives */
		ret = read_toc_as_per_8020(dev->d_fd, 1, trackno, 12, toc);
	}
	/* If this goes through well TOC length will always be 0x0a */
	if (ret && (toc[1] == 0x0a)) {
		if (trackno >= toc[6]) {
			t_info->ti_session_no = toc[3];
			t_info->ti_flags |= TI_SESSION_NO_VALID;
		}
		/*
		 * This might be the last track of this session. If so,
		 * exclude the leadout and next lead in.
		 */
		if (trackno == (toc[6] - 1)) {
			/*
			 * 1.5 Min leadout + 1 min. leadin + 2 sec. pre-gap.
			 * For 2nd+ leadout it will be 0.5 min. But currently
			 * there is no direct way. And it will not happen
			 * for any normal case.
			 *
			 * 75 frames/sec, 60 sec/min, so leadin gap is
			 * ((1.5 +1)*60 + 2)*75 = 11400 frames (blocks)
			 */
			t_info->ti_track_size -= 11400;
		}
	} else {
		if (check_track_size(dev, trackno, t_info) != 1)
			return (0);
	}

	return (1);
}

/*
 * The size of the last track in one of the first N - 1 sessions of an
 * N-session (N > 1) disc is reported incorrectly by some drives and calculated
 * incorrectly for others, because a pre-gap/lead-out/lead-in section that ends
 * a session is erroneously considered part of that track. This function checks
 * for this corner case, and adjusts the track size if necessary.
 */
static int
check_track_size(cd_device *dev, int trk_num, struct track_info *tip)
{
	size_t raw_toc_len;
	uchar_t *raw_toc;
	rtoc_hdr_t hdr;
	uint32_t sess_leadout_lba;
	int sess_last_trk_num;
	int trk_sess_num;
	uint32_t trk_size;

	/* Request Raw TOC Header for session count. */
	if (read_toc(dev->d_fd, FORMAT_RAW_TOC, 1,
	    sizeof (rtoc_hdr_t), (uchar_t *)&hdr) != 1)
		return (0);

	/* Is this a multi-session medium? */
	if (hdr.rh_last_sess_num > hdr.rh_first_sess_num) {
		/* Yes; request entire Raw TOC. */
		raw_toc_len = read_scsi16(&hdr.rh_data_len1) + RTOC_DATA_LEN_SZ;
		raw_toc = (uchar_t *)my_zalloc(raw_toc_len);

		if (read_toc(dev->d_fd, FORMAT_RAW_TOC, 1, raw_toc_len, raw_toc)
		    != 1)
			goto fail;

		if (rtoc_get_trk_sess_num(raw_toc, raw_toc_len, trk_num,
		    &trk_sess_num) != 1)
			goto fail;

		tip->ti_session_no = trk_sess_num;
		tip->ti_flags |= TI_SESSION_NO_VALID;

		/* Is the track in one of the first N - 1 sessions? */
		if (trk_sess_num < hdr.rh_last_sess_num) {
			if (rtoc_get_sess_last_trk_num(raw_toc, raw_toc_len,
			    trk_sess_num, &sess_last_trk_num) != 1)
				goto fail;

			/* Is the track the last track in the session? */
			if (trk_num == sess_last_trk_num) {
				if (rtoc_get_sess_leadout_lba(raw_toc,
				    raw_toc_len, trk_sess_num,
				    &sess_leadout_lba) != 1)
					goto fail;

				trk_size = sess_leadout_lba -
				    tip->ti_start_address;

				/* Fix track size if it was too big. */
				if (tip->ti_track_size > trk_size)
					tip->ti_track_size = trk_size;
			}
		}
		free(raw_toc);
	}
	return (1);

fail:
	free(raw_toc);
	return (0);
}

/*
 * Determine what session number a track is in by parsing the Raw TOC format of
 * the the READ TOC/PMA/ATIP command response data.
 */
static int
rtoc_get_trk_sess_num(uchar_t *rtoc, size_t rtoc_len, int trk_num,
    int *sess_nump)
{
	rtoc_td_t *tdp = (rtoc_td_t *)(rtoc + sizeof (rtoc_hdr_t));
	rtoc_td_t *last_tdp = (rtoc_td_t *)(rtoc + rtoc_len -
	    sizeof (rtoc_td_t));

	if ((tdp = get_rtoc_td(tdp, last_tdp, Q_MODE_1, (uchar_t)trk_num)) !=
	    NULL) {
		*sess_nump = tdp->rt_session_num;
		return (1);
	} else
		return (0);
}

/*
 * Determine the last track number in a specified session number by parsing the
 * Raw TOC format of the READ TOC/PMA/ATIP command response data.
 */
static int
rtoc_get_sess_last_trk_num(uchar_t *rtoc, size_t rtoc_len, int sess_num,
    int *last_trk_nump)
{
	rtoc_td_t *tdp = (rtoc_td_t *)(rtoc + sizeof (rtoc_hdr_t));
	rtoc_td_t *last_tdp = (rtoc_td_t *)(rtoc + rtoc_len -
	    sizeof (rtoc_td_t));

	while ((tdp = get_rtoc_td(tdp, last_tdp, Q_MODE_1,
	    POINT_SESS_LAST_TRK)) != NULL) {
		if (tdp->rt_session_num == sess_num) {
			*last_trk_nump = tdp->rt_pmin;
			return (1);
		} else {
			++tdp;
		}
	}

	return (0);
}

/*
 * Determine the starting LBA of the the session leadout by parsing the Raw TOC
 * format of the READ TOC/PMA/ATIP command response data.
 */
static int
rtoc_get_sess_leadout_lba(uchar_t *rtoc, size_t rtoc_len, int sess_num,
    uint32_t *leadout_lba)
{
	rtoc_td_t *tdp = (rtoc_td_t *)(rtoc + sizeof (rtoc_hdr_t));
	rtoc_td_t *last_tdp = (rtoc_td_t *)(rtoc + rtoc_len -
	    sizeof (rtoc_td_t));

	while ((tdp = get_rtoc_td(tdp, last_tdp, Q_MODE_1,
	    POINT_LEADOUT_ADDR)) != NULL) {
		if (tdp->rt_session_num == sess_num) {
			*leadout_lba = MSF2LBA(tdp->rt_pmin, tdp->rt_psec,
			    tdp->rt_pframe);
			return (1);
		} else {
			++tdp;
		}
	}

	return (0);
}

/*
 * Search a set of Raw TOC Track Descriptors using <'adr', 'point'> as the
 * search key. Return a pointer to the first Track Descriptor that matches.
 */
static rtoc_td_t *
get_rtoc_td(rtoc_td_t *begin_tdp, rtoc_td_t *end_tdp, uchar_t adr,
    uchar_t point)
{
	rtoc_td_t *cur_tdp = begin_tdp;

	while (cur_tdp <= end_tdp) {
		if ((cur_tdp->rt_adr == adr) && (cur_tdp->rt_point == point))
			return (cur_tdp);
		else
			cur_tdp++;
	}

	return (NULL);
}

uchar_t
get_data_mode(int fd, uint32_t lba)
{
	int ret;
	uchar_t *buf;
	uchar_t mode;

	buf = (uchar_t *)my_zalloc(8);
	ret = read_header(fd, lba, buf);
	if (ret == 0)
		mode = 0xff;
	else
		mode = buf[0];
	free(buf);
	return (mode);
}

/*
 * Set page code 5 for TAO mode.
 */
int
prepare_for_write(cd_device *dev, int track_mode, int test_write,
    int keep_disc_open)
{
	uchar_t *buf;
	int no_err;
	int reset_device;

	if ((write_mode == DAO_MODE) && keep_disc_open) {
		(void) printf(gettext(
		    "Multi-session is not supported on DVD media\n"));
		exit(1);
	}

	if ((write_mode == DAO_MODE) && debug) {
		(void) printf("Preparing to write in DAO\n");
	}

	(void) start_stop(dev->d_fd, 1);
	/* Some drives do not support this command but still do it */
	(void) rezero_unit(dev->d_fd);

	buf = (uchar_t *)my_zalloc(64);

	no_err = get_mode_page(dev->d_fd, 5, 0, 64, buf);
	if (no_err)
		no_err = ((buf[1] + 2) > 64) ? 0 : 1;
	/*
	 * If the device is already in simulation mode and again a
	 * simulation is requested, then set the device in non-simulation
	 * 1st and then take it to simulation mode. This will flush any
	 * previous fake state in the drive.
	 */
	if (no_err && test_write && (buf[2] & 0x10)) {
		reset_device = 1;
	} else {
		reset_device = 0;
	}
	if (no_err != 0) {
		buf[0] &= 0x3f;

		/* set TAO or DAO writing mode */
		buf[2] = (write_mode == TAO_MODE)?1:2;

		/* set simulation flag */
		if (test_write && (!reset_device)) {
			buf[2] |= 0x10;
		} else {
			buf[2] &= ~0x10;
		}

		/* Turn on HW buffer underrun protection (BUFE) */
		if (!test_write) {
			buf[2] |= 0x40;
		}

		/* set track mode type */
		if (device_type == CD_RW) {
			buf[3] = track_mode & 0x0f;	/* ctrl nibble */
		}

		if (keep_disc_open) {
			buf[3] |= 0xc0;		/* Allow more sessions */
		}

		/* Select track type (audio or data) */
		if (track_mode == TRACK_MODE_DATA) {
			buf[4] = 8;		/* 2048 byte sector */
		} else {
			buf[4] = 0;		/* 2352 byte sector */
		}
		buf[7] = buf[8] = 0;

		/* Need to clear these fields for setting into DAO */
		if (write_mode == DAO_MODE)
			buf[5] = buf[15] = 0;

		/* print out mode for detailed log */
		if (debug && verbose) {
			int i;

			(void) printf("setting = [ ");
			for (i = 0; i < 15; i++)
				(void) printf("0x%x ", buf[i]);
			(void) printf("]\n");
		}

		no_err = set_mode_page(dev->d_fd, buf);

		if (no_err && reset_device) {
			/* Turn the test write bit back on */
			buf[2] |= 0x10;
			no_err = set_mode_page(dev->d_fd, buf);
		}

		/*
		 * Since BUFE is the only optional flag we are
		 * setting we will try to turn it off if the command
		 * fails.
		 */
		if (!no_err) {
			/*
			 * Some old drives may not support HW
			 * buffer underrun protection, try again
			 * after turning it off.
			 */
			if (debug)
				(void) printf("Turning off BUFE\n");
			buf[2] &= ~0x40;
			no_err = set_mode_page(dev->d_fd, buf);
		}
	}

	free(buf);
	return (no_err);
}

/*
 * Close session. This will write TOC.
 */
int
finalize(cd_device *dev)
{
	uchar_t *di;
	int count, ret, err;
	int immediate;
	int finalize_max;

	/*
	 * For ATAPI devices we will use the immediate mode and will
	 * poll the command for completion so that this command may
	 * not hog the channel. But for SCSI, we will use the treditional
	 * way of issuing the command with a large enough timeout. This
	 * is done because immediate mode was designed for ATAPI and some
	 * SCSI RW drives might not be even tested with it.
	 */
	if ((dev->d_inq[2] & 7) != 0) {
		/* SCSI device */
		immediate = 0;
	} else {
		/* non-SCSI (e.g ATAPI) device */
		immediate = 1;
	}

	/* We need to close track before close session */
	if (device_type == DVD_PLUS) {
		if (!close_track(dev->d_fd, 0, 0, immediate))
			return (0);
	}

	if (!close_track(dev->d_fd, 0, 1, immediate)) {
		/*
		 * For DAO mode which we use for DVD-RW, the latest MMC
		 * specification does not mention close_track. Some
		 * newer drives will return an ILLEGAL INSTRUCTION
		 * which we will ignore. We have also found a Panasonic
		 * drive which will return a MEDIA ERROR. It is safe
		 * to ignore both errors as this is not needed for
		 * these drives.
		 * This is kept for older drives which had needed
		 * us to issue close_track to flush the cache fully.
		 * once we are certain these drives have cleared the
		 * market, this can be removed.
		 */
		if (device_type == DVD_MINUS) {
			return (0);
		}
	} else {
		if (!immediate)
			return (1);
	}
	if (immediate) {
		(void) sleep(10);

		di = (uchar_t *)my_zalloc(DISC_INFO_BLOCK_SIZE);
		err = 0;

		if (device_type == CD_RW) {
			/* Finalization should not take more than 6 minutes */
			finalize_max = FINALIZE_TIMEOUT;
		} else {
			/* some DVD-RW drives take longer than 6 minutes */
			finalize_max = FINALIZE_TIMEOUT*2;
		}

		for (count = 0; count < finalize_max; count++) {
			ret = read_disc_info(dev->d_fd, di);
			if (ret != 0)
				break;
			if (uscsi_status != 2)
				err = 1;
			if (SENSE_KEY(rqbuf) == 2) {
				/* not ready but not becoming ready */
				if (ASC(rqbuf) != 4)
					err = 1;
			} else if (SENSE_KEY(rqbuf) == 5) {
				/* illegal mode for this track */
				if (ASC(rqbuf) != 0x64)
					err = 1;
			} else {
				err = 1;
			}
			if (err == 1) {
				if (debug) {
					(void) printf("Finalization failed\n");
					(void) printf("%x %x %x %x\n",
					    uscsi_status, SENSE_KEY(rqbuf),
					    ASC(rqbuf), ASCQ(rqbuf));
				}
				free(di);
				return (0);
			}
			if (uscsi_status == 2) {
				int i;
				/* illegal field in command packet */
				if (ASC(rqbuf) == 0x24) {
					/* print it out! */
					(void) printf("\n");
					for (i = 0; i < 18; i++)
						(void) printf("%x ",
						    (unsigned)(rqbuf[i]));
					(void) printf("\n");
				}
			}
			(void) sleep(5);
		}
		free(di);
	}
	return (ret);
}

/*
 * Find out media capacity.
 */
uint32_t
get_last_possible_lba(cd_device *dev)
{
	uchar_t *di;
	uint32_t cap;

	di = (uchar_t *)my_zalloc(DISC_INFO_BLOCK_SIZE);
	if (!read_disc_info(dev->d_fd, di)) {
		free(di);
		return (0);
	}

	/*
	 * If we have a DVD+R this field is an LBA. If the media is
	 * a CD-R/W the field is MSF formatted. Otherwise this field
	 * is not valid and will be zero.
	 */
	if (device_type == DVD_PLUS) {
		if (read_scsi32(&di[20]) != 0xffffffff) {
			cap = read_scsi32(&di[20]);
		} else {
			cap = 0;
		}
	} else {
		if ((di[21] != 0) && (di[21] != 0xff)) {
			cap = MSF2LBA(di[21], di[22], di[23]);
		} else {
			cap = 0;
		}
	}

	free(di);
	return (cap);
}

int
read_audio_through_read_cd(cd_device *dev, uint_t start_lba, uint_t nblks,
    uchar_t *buf)
{
	int retry;
	int ret;

	for (retry = 0; retry < 3; retry++) {
		ret = read_cd(dev->d_fd, (uint32_t)start_lba, (uint16_t)nblks,
		    1, buf, (uint32_t)(nblks * 2352));
		if (ret)
			break;
	}
	return (ret);
}

int
eject_media(cd_device *dev)
{
	if (vol_running) {
		/* If there is a media, try using DKIOCEJECT 1st */
		if (check_device(dev, CHECK_NO_MEDIA) == 0) {
			/*
			 * The check_device() call will issue
			 * a TEST UNIT READY (TUR) and retry many
			 * times when a DVD-R is present. The DKIOCEJECT
			 * ioctl will subsequently fail causing us to
			 * issue the LOAD/UNLOAD SCSI command to the device
			 * with out ejecting the media. Insted of letting
			 * this happen, issue a reset to the device before
			 * issuing the DKIOCEJCET ioctl.
			 */
			if (device_type == DVD_MINUS)
				reset_dev(dev->d_fd);

			if (ioctl(dev->d_fd, DKIOCEJECT, 0) == 0) {
				return (1);
			}
		}
	}
	if (load_unload(dev->d_fd, 0) == 0) {
		/* if eject fails */
		if ((uscsi_status == 2) && (ASC(rqbuf) == 0x53)) {
			/*
			 * check that eject is not blocked on the device
			 */
			if (!prevent_allow_mr(dev->d_fd, 1))
				return (0);
			return (load_unload(dev->d_fd, 0));
		}
		return (0);
	}
	return (1);
}

/*
 * Get current Read or Write Speed from Mode Page 0x2a.
 *
 * Use the size of the Page to determine which Multimedia Command
 * set (MMC) is present.  Based on the MMC version, get the
 * specified Read/Write Speed.
 *
 * Note that some MMC versions do not necessarily support a
 * (current) Read or Write Speed.  As a result, this function
 * _can_ return a value of zero.
 *
 * The newer standards (reserve and) mark the field(s) as Obsolete,
 * yet many vendors populate the Obsolete fields with valid values
 * (assumedly for backward compatibility).  This is important, as
 * a command like GET PERFORMANCE cannot return _the_ speed; it can
 * only return a Logical-Block-Address-dependent (LBA) speed.  Such
 * values can vary widely between the innermost and outermost Track.
 * Mode Page 0x2a is the best solution identifying "the current
 * (nominal) speed".
 */
static uint16_t
cd_speed_get(cd_device *dev, int cmd)
{
	uchar_t		*mp2a;
	uint16_t	rate = 0;
	int		offset;
	uint_t		buflen = 254;

	/*
	 * Allocate a buffer acceptably larger than any nominal
	 * Page for Page Code 0x2A.
	 */
	mp2a = (uchar_t *)my_zalloc(buflen);
	if (get_mode_page(dev->d_fd, 0x2A, 0, buflen, mp2a) == 0)
		goto end;

	/* Determine MMC version based on 'Page Length' field */
	switch (mp2a[1]) {
	case 0x14:  /* MMC-1 */
		if (debug)
			(void) printf("Mode Page 2A: MMC-1\n");

		offset = (cmd == GET_READ_SPEED) ? 14 : 20;
		rate = read_scsi16(&mp2a[offset]);
		break;


	case 0x18: /* MMC-2 */
		if (debug)
			(void) printf("Mode Page 2A: MMC-2;"
			    " Read and Write Speeds are "
			    "obsolete\n");

		/* see if "Obsolete" values are valid: */
		offset = (cmd == GET_READ_SPEED) ? 14 : 20;
		rate = read_scsi16(&mp2a[offset]);
		break;

	default: /* MMC-3 or newer */
		if (debug)
			(void) printf("Mode Page 2A: MMC-3 or"
			    " newer; Read Speed is obsolete.\n");

		if (cmd == GET_READ_SPEED) {
			/* this is Obsolete, but try it */
			offset = 14;
			rate = read_scsi16(&mp2a[offset]);
		} else {
			/* Write Speed is not obsolete */
			offset = 28;
			rate = read_scsi16(&mp2a[offset]);

			if (rate == 0) {
				/*
				 * then try an Obsolete field
				 * (but this shouldn't happen!)
				 */
				offset = 20;
				rate = read_scsi16(&mp2a[offset]);
			}
		}
		break;
	}
end:
	free(mp2a);

	if (debug)
		(void) printf("cd_speed_get: %s Speed is "
		    "%uX\n", (cmd == GET_READ_SPEED) ?
		    "Read" : "Write", cdrw_bandwidth_to_x(rate));
	return (rate);
}

/*
 * CD speed related functions (ioctl style) for drives which do not support
 * real time streaming.
 *
 * For the SET operations, the SET CD SPEED command needs
 * both the Read Speed and the Write Speed.  Eg, if
 * we're trying to set the Write Speed (SET_WRITE_SPEED),
 * then we first need to obtain the current Read Speed.
 * That speed is specified along with the chosen_speed (the
 * Write Speed in this case) in the SET CD SPEED command.
 */
int
cd_speed_ctrl(cd_device *dev, int cmd, int speed)
{
	uint16_t rate;

	switch (cmd) {
	case GET_READ_SPEED:
		rate = cd_speed_get(dev, GET_READ_SPEED);
		return (cdrw_bandwidth_to_x(rate));

	case GET_WRITE_SPEED:
		rate = cd_speed_get(dev, GET_WRITE_SPEED);
		return (cdrw_bandwidth_to_x(rate));

	case SET_READ_SPEED:
		rate = cd_speed_get(dev, GET_WRITE_SPEED);
		return (set_cd_speed(dev->d_fd,
		    cdrw_x_to_bandwidth(speed), rate));

	case SET_WRITE_SPEED:
		rate = cd_speed_get(dev, GET_READ_SPEED);
		return (set_cd_speed(dev->d_fd, rate,
		    cdrw_x_to_bandwidth(speed)));

	default:
		return (0);
	}
}

/*
 * Manage sending of SET STREAMING command using the specified
 * read_speed and write_speed.
 *
 * This function allocates and initializes a Performance
 * Descriptor, which is sent as part of the SET STREAMING
 * command.  The descriptor is deallocated before function
 * exit.
 */
static int
do_set_streaming(cd_device *dev, uint_t read_speed,
	uint_t write_speed)
{
	int ret;
	uchar_t *str;

	/* Allocate and initialize the Performance Descriptor */
	str = (uchar_t *)my_zalloc(SET_STREAM_DATA_LEN);

	/* Read Time (in milliseconds) */
	load_scsi32(&str[16], 1000);
	/* Write Time (in milliseconds) */
	load_scsi32(&str[24], 1000);

	/* Read Speed */
	load_scsi32(&str[12], (uint32_t)read_speed);
	/* Write Speed */
	load_scsi32(&str[20], (uint32_t)write_speed);

	/* issue SET STREAMING command */
	ret = set_streaming(dev->d_fd, str);
	free(str);

	return (ret);
}

/*
 * cd speed related functions for drives which support
 * Real-Time Streaming Feature.
 *
 * For the SET operations, the SET STREAMING command needs
 * both the Read Speed and the Write Speed.  Eg, if
 * we're trying to set the Write Speed (SET_WRITE_SPEED),
 * then we first need to obtain the current Read Speed.
 * That speed is specified along with the chosen_speed (the
 * Write Speed in this case) in the SET STREAMING command.
 */
int
rt_streaming_ctrl(cd_device *dev, int cmd, int speed)
{
	int ret = 0;
	uint_t rate;

	switch (cmd) {
	case GET_WRITE_SPEED:
		rate = cd_speed_get(dev, GET_WRITE_SPEED);
		ret = (int)cdrw_bandwidth_to_x(rate);
		break;

	case GET_READ_SPEED:
		rate = cd_speed_get(dev, GET_READ_SPEED);
		ret = (int)cdrw_bandwidth_to_x(rate);
		break;

	case SET_READ_SPEED: {
		uint_t write_speed = cd_speed_get(dev, GET_WRITE_SPEED);

		/* set Read Speed using SET STREAMING */
		ret = do_set_streaming(dev,
		    cdrw_x_to_bandwidth(speed), write_speed);

		/* If rt_speed_ctrl fails for any reason use cd_speed_ctrl */
		if (ret == 0) {
			if (debug)
				(void) printf(" real time speed control"
				    " failed, using CD speed control\n");

			dev->d_speed_ctrl = cd_speed_ctrl;
			ret = dev->d_speed_ctrl(dev, cmd, speed);
		}
		break;
	}

	case SET_WRITE_SPEED: {
		uint_t read_speed = cd_speed_get(dev, GET_READ_SPEED);

		/* set Write Speed using SET STREAMING */
		ret = do_set_streaming(dev, read_speed,
		    cdrw_x_to_bandwidth(speed));

		/* If rt_speed_ctrl fails for any reason use cd_speed_ctrl */
		if (ret == 0) {
			if (debug)
				(void) printf(" real time speed control"
				    " failed, using CD speed control\n");

			dev->d_speed_ctrl = cd_speed_ctrl;
			ret = dev->d_speed_ctrl(dev, cmd, speed);
		}
		break;
	}

	default:
		break;
	}

	return (ret);
}

/*
 * Initialize device for track-at-once mode of writing. All of the data will
 * need to be written to the track without interruption.
 * This initialized TAO by setting page code 5 and speed.
 */
void
write_init(int mode)
{
	(void) printf(gettext("Initializing device"));
	if (simulation)
		(void) printf(gettext("(Simulation mode)"));
	print_n_flush("...");

	get_media_type(target->d_fd);

	/* DVD- requires DAO mode */
	if (device_type == DVD_MINUS) {
		write_mode = DAO_MODE;
	}

	/* DVD+ and DVD- have no support for AUDIO, bail out */
	if ((mode == TRACK_MODE_AUDIO) && (device_type != CD_RW)) {
		err_msg(gettext("Audio mode is only supported for CD media\n"));
		exit(1);
	}
	if (simulation &&
	    check_device(target, CHECK_MEDIA_IS_NOT_BLANK) &&
	    !check_device(target, CHECK_MEDIA_IS_NOT_ERASABLE) &&
	    device_type != DVD_PLUS_W) {
		/*
		 * If we were in simulation mode, and media wasn't blank,
		 * but medium was erasable, then cdrw goes to erase the
		 * contents of the media after the simulation writing in order
		 * to cleanup the ghost TOC (see write_fini() calls blank()).
		 * This is bad because it removes existing data if media was
		 * multi-session. Therefore, we no longer allow simulation
		 * writing if such condition is met. we don't blank the DVD+RW
		 * media, so DVD+RWs are fine.
		 */
		err_msg(gettext(
		    "Cannot perform simulation for non-blank media\n"));
		exit(1);
	}

	if (!prepare_for_write(target, mode, simulation, keep_disc_open)) {
		/* l10n_NOTE : 'failed' as in Initializing device...failed  */
		(void) printf(gettext("failed.\n"));
		err_msg(gettext("Cannot initialize device for write\n"));
		exit(1);
	}
	/* l10n_NOTE : 'done' as in "Initializing device...done"  */
	(void) printf(gettext("done.\n"));

	/* if speed change option was used (-p) then try to set the speed */
	if (requested_speed != 0) {
		if (verbose)
			(void) printf(gettext("Trying to set speed to %dX.\n"),
			    requested_speed);
		if (target->d_speed_ctrl(target, SET_WRITE_SPEED,
		    requested_speed) == 0) {
			err_msg(gettext("Unable to set speed.\n"));
			exit(1);
		}
		if (verbose) {
			int speed;
			speed = target->d_speed_ctrl(target,
			    GET_WRITE_SPEED, 0);
			if (speed == requested_speed) {
				(void) printf(gettext("Speed set to %dX.\n"),
				    speed);
			} else if (speed == 0) {
				(void) printf(gettext("Could not obtain "
				    "current Write Speed.\n"));
			} else {
				(void) printf(
				gettext("Speed set to closest approximation "
				    "of %dX allowed by device (%dX).\n"),
				    requested_speed, speed);
			}
		}
	}
}

void
write_fini(void)
{
	print_n_flush(gettext("Finalizing (Can take several minutes)..."));
	/* Some drives don't like this while in test write mode */
	if (!simulation) {
		if (!finalize(target)) {
			/*
			 * It is possible that the drive is busy writing the
			 * buffered portion. So do not get upset yet.
			 */
			(void) sleep(10);
			if (!finalize(target)) {
				if (debug) {
					(void) printf("status %x, %x/%x/%x\n",
					    uscsi_status, SENSE_KEY(rqbuf),
					    ASC(rqbuf), ASCQ(rqbuf));
				}

				/*
				 * Different vendor drives return different
				 * sense error info for CLOSE SESSION command.
				 * The Panasonic drive that we are using is
				 * one such drive.
				 */
				if (device_type == DVD_MINUS) {
					if (verbose) {
						(void) printf(
						    "skipping finalizing\n");
					}
				} else {

			/* l10n_NOTE : 'failed' as in finishing up...failed  */
					(void) printf(gettext("failed.\n"));

					err_msg(gettext(
					    "Could not finalize the disc.\n"));
					exit(1);
				}


			}
		}
		if (vol_running) {
			(void) eject_media(target);
		}
	} else if (check_device(target, CHECK_MEDIA_IS_NOT_BLANK)) {
		/*
		 * Some drives such as the pioneer A04 will retain a
		 * ghost TOC after a simulation write is done. The
		 * media will actually be blank, but the drive will
		 * report a TOC. There is currently no other way to
		 * re-initialize the media other than ejecting or
		 * to ask the drive to clear the leadout. The laser
		 * is currently off so nothing is written to the
		 * media (on a good behaving drive).
		 * NOTE that a device reset does not work to make
		 * the drive re-initialize the media.
		 */

		blanking_type = "clear_ghost";
		blank();

	}
	/* l10n_NOTE : 'done' as in "Finishing up...done"  */
	(void) printf(gettext("done.\n"));
}
