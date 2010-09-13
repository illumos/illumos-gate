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

#include <sys/types.h>
#include <stdlib.h>
#include <libintl.h>
#include <unistd.h>
#include "trackio.h"
#include "main.h"
#include "util.h"
#include "bstream.h"
#include "misc_scsi.h"
#include "msgs.h"
#include "device.h"
#include "mmc.h"
#include "transport.h"

void
write_image(void)
{
	bstreamhandle h;
	off_t size;
	int no_size, ret;

	get_media_type(target->d_fd);

	/* DVD+RW does not have blanking and can be overwritten */
	if (device_type != DVD_PLUS_W) {
	(void) check_device(target, CHECK_DEVICE_NOT_READY |
	    CHECK_DEVICE_NOT_WRITABLE | CHECK_MEDIA_IS_NOT_WRITABLE |
	    EXIT_IF_CHECK_FAILED);
	} else {
		(void) check_device(target, CHECK_DEVICE_NOT_READY |
		    EXIT_IF_CHECK_FAILED);
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

	write_init(TRACK_MODE_DATA);

	if (image_file) {
		h = open_iso_read_stream(image_file);
	} else {
		h = open_stdin_read_stream();
	}

	if (h == NULL) {
		err_msg(gettext("Cannot open %s: %s\n"),
		    image_file ? image_file : "stdin", get_err_str());
		exit(1);
	}
	no_size = 0;
	ret = h->bstr_size(h, &size);
	if (ret == 0) {
		if ((str_errno == STR_ERR_NO_REG_FILE)) {
			no_size = 1;
		} else {
			err_msg(gettext("Cannot stat input file: %s\n"),
			    get_err_str());
			exit(1);
		}
	}
	if ((no_size == 0) && (size == 0)) {
		err_msg(gettext("Input size(0) not valid\n"));
		exit(1);
	}
	if (no_size == 0) {
		off_t cap;
		struct track_info *ti;
		uint_t bsize;

		ti = (struct track_info *)my_zalloc(sizeof (*ti));
		if (write_mode == TAO_MODE)
			if (!build_track_info(target, -1, ti)) {
				err_msg(
				    gettext("Unable to find out writable "
				    "address\n"));
				exit(1);
			}
		if (device_type == CD_RW) {
			if ((cap = get_last_possible_lba(target)) <= 0) {
				if ((cap = read_format_capacity(target->d_fd,
				    &bsize)) <= 0) {
					err_msg(gettext("Unable to determine "
					    "media capacity.  Defaulting to "
					    "650 MB (74 minute) disc.\n"));
					cap = MAX_CD_BLKS;
				}
			}
		} else {
			/*
			 * For DVD drives use read_format_capacity to
			 * find media size, it can be 3.6, 3.9, 4.2,
			 * 4.7, 9.2
			 */
			cap = read_format_capacity(target->d_fd,
			    &bsize);
			/*
			 * Sanity check; Default to 4.7 GB if cap unreasonable
			 */
			if (cap < MAX_CD_BLKS)
				cap = MAX_DVD_BLKS;
		}

		if (device_type == CD_RW)
			cap = (cap + 1 - ti->ti_start_address) * 2048;
		else
			cap *= 2048 + 1;

		if (size > cap) {
			err_msg(gettext("Size required (%lld bytes) is greater "
			    "than available space (%lld bytes).\n"), size, cap);
			exit(1);
		}

		if (device_type == DVD_MINUS) {
			(void) printf(gettext("Preparing to write DVD\n"));

			/* streamed file, we dont know the size to reserve */
			if (no_size == 1) {
				size = cap - 1;
			}

			/* DAO requires that we reserve the size to write */
			if (debug)
				(void) printf(
				    "DAO_MODE:reserving track size of = 0x%x\n",
				    (uint32_t)(size/2048));

			if (!set_reservation(target->d_fd, size/2048)) {
				(void) printf(gettext(
				    "Setting reservation failed\n"));
				exit(1);
			}
		} else if (device_type == DVD_PLUS_W) {
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

			(void) printf(gettext("done\n"));
		}


		free(ti);
	}

	write_next_track(TRACK_MODE_DATA, h);

	h->bstr_close(h);
	write_fini();
	fini_device(target);
	exit(0);
}
