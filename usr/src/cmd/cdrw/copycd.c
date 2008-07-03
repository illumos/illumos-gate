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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <errno.h>
#include <limits.h>
#include <unistd.h>
#include <libintl.h>
#include <string.h>

#include "main.h"
#include "util.h"
#include "misc_scsi.h"
#include "mmc.h"
#include "bstream.h"
#include "device.h"
#include "msgs.h"
#include "transport.h"

struct t_data {
	bstreamhandle h;
	struct track_info ti;
};

int read_audio_track(cd_device *dev, struct track_info *ti, bstreamhandle h);

#define	READ_BURST	24	/* < 64K in all cases */

/*
 * This reads the data off of a cd while updating the progress indicator.
 * We want to do this in smaller chunks since some CD drives have
 * problems with larger reads.
 */
static int
read_data_track(cd_device *dev, struct track_info *ti, bstreamhandle h)
{
	int blksize;
	uint32_t blks_read, cblk, read_chunk, read_size;
	uchar_t *buf;
	int ret, sav;
	int link_blks_count;

	buf = NULL;
	ret = 0;

	/*
	 * the last link_blks_count blocks may not exist or be completely
	 * filled. We need to record the amount to avoid bailing out if
	 * they cannot be read.
	 */

	if (dev->d_blksize == 512) {
		blksize = 512;
		link_blks_count = 8;
	} else {
		blksize = 2048;
		link_blks_count = 2;
	}

	buf = (uchar_t *)my_zalloc(READ_BURST * blksize);

	print_n_flush(gettext("Reading track %d..."), ti->ti_track_no);

	if (verbose)
		print_n_flush("Track size is %u...", ti->ti_track_size);

	init_progress();
	cblk = ti->ti_start_address;
	blks_read = 0;
	while (blks_read < ti->ti_track_size) {
		/* Last few are special */
		read_chunk = ti->ti_track_size - blks_read - link_blks_count;
		read_chunk = (read_chunk > READ_BURST) ? READ_BURST :
		    read_chunk;
		if (read_chunk == 0) {
			/* Time for last link blocks */
			read_chunk = link_blks_count;
		}
		read_size = read_chunk * blksize;
		if (read10(dev->d_fd, cblk, read_chunk, buf, read_size)) {
			if (h->bstr_write(h, buf, read_size) != read_size) {
				goto read_data_track_failed;
			}
		} else {
			if (blks_read !=
			    (ti->ti_track_size - link_blks_count)) {
				goto read_data_track_failed;
			} else {
			/* Read can fail for last link sectors */
				errno = 0;
			}
		}
		blks_read += read_chunk;
		cblk += read_chunk;
		(void) progress((ti->ti_track_size), blks_read);
	}
	/* l10n_NOTE : 'done' as in "Reading track 1...done"  */
	(void) str_print(gettext("done.\n"), progress_pos);
	ret = 1;
read_data_track_failed:
	sav = errno;

	free(buf);
	errno = sav;
	return (ret);
}

static void
ensure_media_space(uint32_t total_nblks, uchar_t end_tno)
{
	uint32_t nblks_avail;
	uint_t bsize;
	uint_t leadin_size = 0;

	get_media_type(target->d_fd);

	if (device_type == CD_RW) {
		nblks_avail = get_last_possible_lba(target);

		if (nblks_avail == 0) {

			/* most newer drives use READ FORMAT CAPACITY */
			nblks_avail = read_format_capacity(target->d_fd,
			    &bsize);

			/* if both methods fail, fall back on defaults */
			if (nblks_avail == 0) {
				err_msg(gettext("Unable to determine media "
				    "capacity. Defaulting to 650 MB (74 minute)"
				    " disc.\n"));
				nblks_avail = MAX_CD_BLKS;
			}
		leadin_size = end_tno*300;
		}
	} else {
		/*
		 * For DVD drives use read_format_capacity as default
		 * retrieve the media size, it can be 3.6, 3.9, 4.2,
		 * 4.7, or 9.2 GB
		 */
		nblks_avail = read_format_capacity(target->d_fd, &bsize);

		/* sanity check. if not reasonable default to 4.7 GB */
		if (nblks_avail < MAX_CD_BLKS) {
			nblks_avail = MAX_DVD_BLKS;
		}
	}

	if ((total_nblks + leadin_size) > nblks_avail) {
		err_msg(gettext("Not enough space on the media.\n"));
		if (debug) {
			(void) printf("Need %u  only found %u \n",
			    (total_nblks + leadin_size),
			    (uint32_t)nblks_avail);
		}

		exit(1);
	}
}

/*
 * This copies both audio and data CDs. It first reads the TOC of the source CD
 * and creates a temp file with the CD image. After this is completed it creates
 * the target CD using TAO mode.
 */
void
copy_cd(void)
{
	cd_device *src;
	char *p;
	uchar_t *toc, end_tno;
	int blksize, i;
	int audio_cd, data_cd;
	uint32_t total_nblks;
	int ret;
	struct t_data *tlist;

	print_n_flush(gettext("Analyzing source CD..."));
	(void) check_device(target,
	    CHECK_DEVICE_NOT_WRITABLE|EXIT_IF_CHECK_FAILED);

	/* if source drive is specified on the command line */

	if (copy_src) {
		p = my_zalloc(PATH_MAX);
		if (lookup_device(copy_src, p) == 0) {
			err_msg(gettext("Cannot find device %s"), copy_src);
			err_msg(gettext(" or no media in the drive\n"));
			exit(1);
		}
		src = get_device(copy_src, p);
		if (src == NULL) {
			err_msg(gettext("Unable to open %s\n"), copy_src);
			exit(1);
		}
		free(p);
	} else {
		/* source is same as target drive */
		src = target;
	}

	(void) check_device(src, CHECK_TYPE_NOT_CDROM | CHECK_NO_MEDIA |
	    CHECK_DEVICE_NOT_READY | EXIT_IF_CHECK_FAILED);

	/* What type of media are we working with? */
	get_media_type(src->d_fd);

	toc = (uchar_t *)my_zalloc(4);
	if (!read_toc(src->d_fd, 0, 0, 4, toc)) {
		err_msg(gettext("Cannot read table of contents\n"));
		exit(1);
	}
	end_tno = toc[3];
	free(toc);
	tlist = (struct t_data *)my_zalloc(end_tno * sizeof (struct t_data));

	audio_cd = data_cd = 0;
	total_nblks = 0;

	/* build track information so we can copy it over */
	for (i = 1; i <= end_tno; i++) {
		struct track_info *ti;

		ti = &tlist[i - 1].ti;
		if (!build_track_info(src, i, ti)) {
			err_msg(gettext(
			    "Cannot get information for track %d\n"), i);
			exit(1);
		}
		total_nblks += ti->ti_track_size;
		if (ti->ti_track_mode & 4)
			data_cd = 1;
		else
			audio_cd = 1;

		/* Now some sanity checks on the track information */
		if ((ti->ti_flags & TI_SESSION_NO_VALID) &&
		    (ti->ti_session_no != 1)) {
			err_msg(
			gettext("Copying multisession CD is not supported\n"));
			exit(1);
		}
		if ((ti->ti_flags & TI_BLANK_TRACK) ||
		    (ti->ti_flags & TI_DAMAGED_TRACK) ||
		    (data_cd && audio_cd) || (ti->ti_data_mode == 2)) {

			err_msg(gettext("CD format is not supported\n"));
			exit(1);
		}
		if ((ti->ti_flags & TI_NWA_VALID) &&
		    (ti->ti_nwa != 0xffffffff)) {
			err_msg(gettext("Cannot copy incomplete discs\n"));
			exit(1);
		}
	}
	/* l10n_NOTE : 'done' as in "Analyzing source CD...done"  */
	(void) printf(gettext("done.\n"));

	if (data_cd) {
		blksize = 2048;
	} else {
		/* audio cd */
		blksize = 2352;
	}

	/* In case of audio CDs, build_track_info() returns 2352 sized nblks */
	if (src->d_blksize == 512 && data_cd) {
		total_nblks /= 4;
	}
	(void) printf(gettext("\nCopying %d %s track%s : %ld kbytes\n\n"),
	    end_tno, (audio_cd == 1) ? gettext("audio") : gettext("data"),
	    (end_tno > 1) ? "s" : "", (long)((total_nblks*blksize)/1024));

	if ((ret = check_avail_temp_space(total_nblks*blksize)) != 0) {
		err_msg(gettext("Cannot use temporary directory : %s\n"),
		    strerror(ret));
		err_msg(gettext("Use -m to specify alternate"
		    " temporary directory\n"));
		exit(1);
	}

	/*
	 * If we can check available space on the target media at this
	 * Stage, then it is always better. We cannot check DVD+R(W)
	 * as this media may be formatted and not blank.
	 */
	if (target && (src != target) && (device_type != DVD_PLUS) &&
	    (device_type != DVD_PLUS_W) && (!check_device(target,
	    CHECK_NO_MEDIA|CHECK_MEDIA_IS_NOT_BLANK))) {
		ensure_media_space(total_nblks, end_tno);
	}

	/* for each track */
	for (i = 1; i <= end_tno; i++) {
		tlist[i - 1].h = open_temp_file_stream();
		if (tlist[i - 1].h == NULL) {
			err_msg(gettext("Cannot create temporary file : %s\n"),
			    get_err_str());
			exit(1);
		}

		if (audio_cd)
			ret = read_audio_track(src, &tlist[i - 1].ti,
			    tlist[i - 1].h);
		else
			ret = read_data_track(src, &tlist[i - 1].ti,
			    tlist[i - 1].h);
		if (ret == 0) {
			err_msg(gettext("Error reading track %d : %s\n"), i,
			    get_err_str());
			if (debug)
				(void) printf("%x %x %x %x\n", uscsi_status,
				    SENSE_KEY(rqbuf), ASC(rqbuf), ASCQ(rqbuf));
			exit(1);
		}
	}

	/*
	 * We've finished copying the CD. If source and destination are the same
	 * or they where not specified then eject the disk and wait for a new
	 * disk to be inserted.
	 *
	 * Since, DVD+RWs are not blanked just reformated, allow the insertion
	 * of a DVD+RW to be the only condition necessary to complete copying.
	 */

	do {
		if (target != NULL) {
			(void) eject_media(target);
		}

		(void) printf("\n");
		print_n_flush(
		gettext("Insert a blank media in the drive and press Enter."));
		(void) fflush(stdin);
		if (target) {
			fini_device(target);
			target = NULL;
		}
		(void) getchar();
		(void) sleep(4);
		(void) setup_target(SCAN_WRITERS);
		if (target)
			get_media_type(target->d_fd);
	} while ((target == NULL) ||
	    ((device_type == DVD_PLUS_W)? check_device(target, CHECK_NO_MEDIA):
	    check_device(target, CHECK_NO_MEDIA|CHECK_MEDIA_IS_NOT_BLANK)));

	(void) printf("\n");
	(void) setreuid(ruid, 0);

	if ((device_type != DVD_PLUS) && (device_type != DVD_PLUS_W)) {
		ensure_media_space(total_nblks, end_tno);
		write_init(audio_cd ? TRACK_MODE_AUDIO : TRACK_MODE_DATA);
	}

	/*
	 * Simulation writing can't happen on DVD+RW's
	 * or DVD+R's. According to the MMC spec this
	 * operation is not supported. So we should
	 * bail out if the user tries to do a simulation
	 * write.
	 */
	if (simulation && (device_type == DVD_PLUS_W ||
	    device_type == DVD_PLUS)) {
		err_msg(gettext("Media does not support simulated writing.\n"));
		exit(1);
	}

	if (device_type == DVD_PLUS_W) {
		/*
		 * DVD+RW requires that we format the media before
		 * writing.
		 */
		(void) print_n_flush(gettext("Formatting media..."));
		if (!format_media(target->d_fd)) {
			(void) printf(gettext(
			    "Could not format media\n"));
			exit(1);
		} else {
			int counter;
			uchar_t *di;

			/* poll until format is done */
			di = (uchar_t *)my_zalloc(DISC_INFO_BLOCK_SIZE);
			(void) sleep(10);
			for (counter = 0; counter < 200; counter++) {
				ret = read_disc_info(target->d_fd, di);
				if ((SENSE_KEY(rqbuf) == 2) &&
				    (ASC(rqbuf) == 4)) {
					(void) print_n_flush(".");
					(void) sleep(5);
				} else {
					break;
				}
			}
		}
	}

	/* for each track */
	for (i = 0; i < end_tno; i++) {
		/*
		 * DVD's dont contain tracks and need to be written in DAO
		 * mode.
		 */
		if (device_type != CD_RW) {
			if (end_tno > 1) {
				err_msg(gettext(
				    "Media state is not suitable for this"
				    " write mode.\n"));
			}
			write_mode = DAO_MODE;

			/*
			 * DVD-R(W) and DVD+R needs to have space reserved
			 * prior to writing.
			 */
			if ((device_type == DVD_MINUS) ||
			    (device_type == DVD_PLUS)) {
				if (!set_reservation(target->d_fd,
				    total_nblks + 1)) {
					(void) printf(gettext(
					    "Setting reservation failed\n"));
					exit(1);
				}
			}
		}

		write_next_track(audio_cd ? TRACK_MODE_AUDIO : TRACK_MODE_DATA,
		    tlist[i].h);

		/*
		 * Running in simulation mode and writing several tracks is
		 * useless so bail after the first track is done.
		 */

		if (simulation && (end_tno != 1)) {
			(void) printf(gettext(
			"Simulation mode : skipping remaining tracks\n"));
			break;
		}
	}

	write_fini();
	/* close the temp file handles */
	for (i = 0; i < end_tno; i++)
		(tlist[i].h)->bstr_close(tlist[i].h);
	free(tlist);
	fini_device(target);
	exit(0);
}
