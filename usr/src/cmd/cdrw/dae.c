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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <string.h>
#include <stdlib.h>
#include <libintl.h>
#include <signal.h>

#include "bstream.h"
#include "util.h"
#include "misc_scsi.h"
#include "device.h"
#include "main.h"
#include "msgs.h"

#define	BLOCK_SIZE		2352
#define	READ_BURST_SIZE		200
#define	SMALL_READ_BURST_SIZE	24	/* < 64K in all cases */
#define	READ_OVERLAP		7
#define	BLOCKS_COMPARE		3

static int			abort_read;

/*
 * These are routines for extracting audio from a cd. During
 * extraction we will also convert the audio type from the
 * CD to the audio type specified on the command line. This
 * handles both newer CD drives which support the MMC2 standard
 * and older Sun Toshiba drives which need jitter correction.
 */

static bstreamhandle
open_audio_for_extraction(char *fname)
{
	int at;
	char *ext;

	if (audio_type == AUDIO_TYPE_NONE) {
		ext = (char *)(strrchr(fname, '.'));
		if (ext) {
			ext++;
		}
		if ((ext == NULL) || ((at = get_audio_type(ext)) == -1)) {
			err_msg(gettext(
			    "Cannot understand file extension for %s\n"),
			    fname);
			exit(1);
		}
	} else {
		at = audio_type;
	}
	if (at == AUDIO_TYPE_SUN)
		return (open_au_write_stream(fname));
	if (at == AUDIO_TYPE_WAV)
		return (open_wav_write_stream(fname));
	if (at == AUDIO_TYPE_CDA)
		return (open_file_write_stream(fname));
	if (at == AUDIO_TYPE_AUR)
		return (open_aur_write_stream(fname));
	return (NULL);
}

/* ARGSUSED */
static void
extract_signal_handler(int sig, siginfo_t *info, void *context)
{
	abort_read = 1;
}

/*
 * Older drives use different data buffer and m:s:f channels to transmit audio
 * information. These channels may not be in sync with each other with the
 * maximum disparity being the size of the data buffer. So handling is needed
 * to keep these two channels in sync.
 */

static int
handle_jitter(uchar_t *buf, uchar_t *last_end)
{
	int i;
	for (i = BLOCK_SIZE*(READ_OVERLAP - BLOCKS_COMPARE); i >= 0; i -= 4) {
		if (memcmp(last_end - BLOCK_SIZE * BLOCKS_COMPARE, buf + i,
		    BLOCK_SIZE * BLOCKS_COMPARE) == 0) {
			return (i + (BLOCK_SIZE * BLOCKS_COMPARE));
		}
	}
	for (i = BLOCK_SIZE*(READ_OVERLAP - BLOCKS_COMPARE);
	    i < 2*READ_OVERLAP*BLOCK_SIZE; i += 4) {
		if (memcmp(last_end - BLOCK_SIZE * BLOCKS_COMPARE, buf + i,
		    BLOCK_SIZE * BLOCKS_COMPARE) == 0) {
			return (i + (BLOCK_SIZE * BLOCKS_COMPARE));
		}
	}
	return (-1);
}

int
read_audio_track(cd_device *dev, struct track_info *ti, bstreamhandle h)
{
	uint32_t	blocks_to_write, blocks_to_read, blks_to_overlap;
	uint32_t	start_blk, end_blk, c_blk;
	uint32_t	read_burst_size;
	uchar_t		*tmp, *buf, *prev, *previous_end;
	int		ret, off;
	struct sigaction	sv;
	struct sigaction	oldsv;

	ret = 0;
	abort_read = 0;

	/*
	 * It is good to do small sized I/Os as we have seen many devices
	 * choke with large I/Os. But if the device does not support
	 * reading accurate CDDA then we have to do overlapped I/Os
	 * and reducing size might affect performance. So use small
	 * I/O size if device supports accurate CDDA.
	 */
	if (dev->d_cap & DEV_CAP_ACCURATE_CDDA) {
		read_burst_size = SMALL_READ_BURST_SIZE;
	} else {
		read_burst_size = READ_BURST_SIZE;
	}
	buf = (uchar_t *)my_zalloc(BLOCK_SIZE * read_burst_size);
	prev = (uchar_t *)my_zalloc(BLOCK_SIZE * read_burst_size);
	start_blk = ti->ti_start_address;
	end_blk = ti->ti_start_address + ti->ti_track_size - 1;

	/* Even when we need jitter correction, this will be 0 1st time */
	blks_to_overlap = 0;
	off = 0;

	/* set up signal handler to write audio TOC if ^C is pressed */
	sv.sa_sigaction = extract_signal_handler;
	(void) sigemptyset(&sv.sa_mask);
	sv.sa_flags = 0;
	(void) sigaction(SIGINT, &sv, &oldsv);

	if ((dev->d_cap & DEV_CAP_EXTRACT_CDDA) == 0) {
		err_msg(gettext("Audio extraction method unknown for %s\n"),
		    dev->d_name ? dev->d_name : gettext("CD drive"));
		exit(1);
	}

	/* if the speed option given, try to change the speed */
	if ((requested_speed != 0) && !cflag) {
		if (verbose)
			(void) printf(gettext("Trying to set speed to %dX.\n"),
			    requested_speed);
		if (dev->d_speed_ctrl(dev, SET_READ_SPEED,
		    requested_speed) == 0) {

			err_msg(gettext("Unable to set speed.\n"));
			exit(1);
		}
		if (verbose) {
			int speed;
			speed = dev->d_speed_ctrl(dev, GET_READ_SPEED, 0);
			if (speed == requested_speed) {
				(void) printf(gettext("Speed set to %dX.\n"),
				    speed);
			} else if (speed == 0) {
				(void) printf(gettext("Could not obtain "
				    "current Read Speed.\n"));
			} else {
				(void) printf(gettext("Speed set to "
				    "closest approximation of %dX allowed "
				    "by device (%dX).\n"),
				    requested_speed, speed);
			}
		}
	}

	print_n_flush(
	    gettext("Extracting audio from track %d..."), ti->ti_track_no);
	init_progress();

	if (debug)
		(void) printf("\nStarting: %d Ending: %d\n",
		    start_blk, end_blk);

	blocks_to_write = 0;

	for (c_blk = start_blk; c_blk < end_blk; c_blk += blocks_to_write) {
		/* update progress indicator */
		(void) progress((end_blk - start_blk),
		    (int64_t)(c_blk - start_blk));
		blocks_to_read =  end_blk - c_blk + blks_to_overlap;

		/*
		 * Make sure we don't read more blocks than the maximum
		 * burst size.
		 */

		if (blocks_to_read > read_burst_size)
			blocks_to_read = read_burst_size;

		if (dev->d_read_audio(dev, c_blk - blks_to_overlap,
		    blocks_to_read, buf) == 0)
			goto read_audio_track_done;

		/*
		 * This drive supports accurate audio extraction don't
		 * do jitter correction.
		 */
		if ((c_blk == start_blk) ||
		    (dev->d_cap & DEV_CAP_ACCURATE_CDDA)) {
			blocks_to_write = blocks_to_read;
			previous_end = buf + (blocks_to_write * BLOCK_SIZE);
			goto skip_jitter_correction;
		}

		if (c_blk == start_blk)
			blks_to_overlap = 0;
		else
			blks_to_overlap = READ_OVERLAP;
		off = handle_jitter(buf, previous_end);
		if (off == -1) {
			if (debug)
				(void) printf(
				    "jitter control failed\n");

			/* recover if jitter correction failed */
			off = BLOCK_SIZE * BLOCKS_COMPARE;
		}

		blocks_to_write = blocks_to_read - blks_to_overlap;

		while ((off + (blocks_to_write*BLOCK_SIZE)) >
		    (blocks_to_read * BLOCK_SIZE)) {
			blocks_to_write--;
		}

		if ((blocks_to_write + c_blk) > end_blk) {
			blocks_to_write = end_blk - c_blk;
		}

		if (blocks_to_write == 0) {
			c_blk = end_blk - 1;
			blocks_to_write = 1;
			(void) memset(&buf[off], 0, off % BLOCK_SIZE);
		}

		previous_end = buf + off + blocks_to_write * BLOCK_SIZE;
skip_jitter_correction:
		(void) memcpy(prev, buf, read_burst_size * BLOCK_SIZE);
		if (h->bstr_write(h, &buf[off], blocks_to_write*BLOCK_SIZE)
		    < 0)
			goto read_audio_track_done;
		tmp = buf;
		buf = prev;
		prev = tmp;

		if (abort_read == 1)
			goto read_audio_track_done;
	}

	ret = 1;
	(void) str_print(gettext("done.\n"), progress_pos);

read_audio_track_done:
	(void) sigaction(SIGINT, &oldsv, (struct sigaction *)0);

	free(buf);
	free(prev);
	return (ret);
}

void
extract_audio(void)
{
	bstreamhandle h;
	struct track_info *ti;

	(void) check_device(target, CHECK_NO_MEDIA | CHECK_DEVICE_NOT_READY |
	    EXIT_IF_CHECK_FAILED);

	ti = (struct track_info *)my_zalloc(sizeof (*ti));
	if (!build_track_info(target, extract_track_no, ti)) {
		err_msg(gettext("Cannot get track information for track %d\n"),
		    extract_track_no);
		exit(1);
	}

	/* Verify track */
	if ((ti->ti_track_size == 0) || ((ti->ti_flags & TI_NWA_VALID) &&
	    (ti->ti_start_address == ti->ti_nwa))) {
		err_msg(gettext("Track %d is empty\n"), extract_track_no);
		exit(1);
	}
	if (ti->ti_track_mode & 4) {
		err_msg(gettext("Track %d is not an audio track\n"),
		    extract_track_no);
		exit(1);
	}
	if (ti->ti_data_mode == 2) {
		err_msg(gettext("Track format is not supported\n"));
		exit(1);
	}

	h = open_audio_for_extraction(extract_file);
	if (h == NULL) {
		err_msg(gettext("Cannot open %s:%s\n"), extract_file,
		    get_err_str());
		exit(1);
	}
	if (read_audio_track(target, ti, h) == 0) {
		err_msg(gettext("Extract audio failed\n"));
		h->bstr_close(h);
		exit(1);
	}
	if (h->bstr_close(h) != 0) {
		err_msg(gettext("Error closing audio stream : %s\n"),
		    get_err_str());
		exit(1);
	}
	exit(0);
}
