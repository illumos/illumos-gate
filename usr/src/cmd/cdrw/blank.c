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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <stdlib.h>
#include <string.h>
#include <libintl.h>
#include <unistd.h>

#include "msgs.h"
#include "mmc.h"
#include "util.h"
#include "transport.h"
#include "main.h"
#include "misc_scsi.h"

/*
 * This is called recursively once, if an ALL blank succeeds but the
 * media is not blank we call blank() again to perform a fast blank.
 * This is a workaround for some drives such as older Toshiba DVD-RW
 * which has this problem with ALL blanking.
 */
void
blank(void)
{
	int type, invalid;
	int count, ret;
	uchar_t *di, *buf;
	int immediate, err;
	int silent_pass = 0;
	/*
	 * silent_pass is set to 1 whenever we do not want to print
	 * information messages. This is the case where blank() function
	 * is called within the blank() function or the blank() function
	 * is called from other functions within cdrw to blank the media
	 * as part of other operations (clearing ghost TOC, closing the media
	 * after a write operation, etc). In all those cases we need not print
	 * or duplicate information messages. We should also return from the
	 * blank() function to the calling function in those cases.
	 */
	int ignore_error = 0;
	/*
	 * ignore_error is set to 1 whenever we do not want to report any
	 * error messages to the user and make things transparent to the
	 * user (For eg: Clearing ghost TOC during write simulation).
	 */

	invalid = 0;
	err = 0;

	(void) check_device(target, CHECK_TYPE_NOT_CDROM | CHECK_NO_MEDIA |
	    EXIT_IF_CHECK_FAILED);
	(void) check_device(target, CHECK_DEVICE_NOT_READY |
	    CHECK_DEVICE_NOT_WRITABLE | EXIT_IF_CHECK_FAILED);

	if (blanking_type == NULL) {
		invalid = 1;
	}

	get_media_type(target->d_fd);

	if (strcmp(blanking_type, "all") == 0) {
		/* erase the whole disk */
		type = ALL;
	} else if (strcmp(blanking_type, "session") == 0) {
		/* only erase the last session */
		type = SESSION;
	} else if (strcmp(blanking_type, "fast") == 0) {
		/* quick blank the TOC on the media */
		type = FAST;
	} else if (strcmp(blanking_type, "leadout") == 0) {
		/* erase the track tail to unclose the media */
		type = LEADOUT;
		silent_pass = 1;
	} else if (strcmp(blanking_type, "clear") == 0) {
		/*
		 * used for drives where "all" blanking fails,
		 * if it fails we follow up with a quick erase of TOC.
		 * This is only called from within this function to do
		 * a second blanking pass.
		 */
		type = CLEAR;
		silent_pass = 1;
	} else if (strcmp(blanking_type, "clear_ghost") == 0) {
		/*
		 * used for drives in simulation mode to blank ghost
		 * TOC after simulation write is complete.
		 */
		type = CLEAR;
		silent_pass = 1;
		ignore_error = 1;
	} else {
		/* invalid blank type was passed on the command line */
		invalid = 1;
	}

	if (invalid) {
		err_msg(gettext("Invalid blanking type specified\n"));
		exit(1);
	}

	/*
	 * many DVD+RW drives do not allow blanking the media, it is also
	 * not included in the spec, we would just reformat the media prior
	 * to writing. This is not the equivelent to blanking as the media
	 * contains a TOC when formatted.
	 */
	if (device_type == DVD_PLUS_W) {
		if (ignore_error)
			return;
		err_msg(gettext("Blanking cannot be done on DVD+RW media\n"));
		exit(1);
	}

	if ((target->d_inq[2] & 7) != 0) {
		/* SCSI device */
		immediate = 0;
	} else {
		/* non-SCSI (e.g ATAPI) device */
		immediate = 1;
	}

	/* we are doing a second pass. We don't want to re-print messsages */
	if (!silent_pass)
		print_n_flush(gettext("Initializing device..."));

	/* Make sure that test write is off */
	buf = (uchar_t *)my_zalloc(64);

	/* get mode page for test writing if it fails we cannot turn it off */
	if (!get_mode_page(target->d_fd, 5, 0, 64, buf)) {
		if (ignore_error)
			return;
		err_msg(gettext("Device not supported\n"));
		exit(1);
	}

	buf[2] &= 0xef;

	/* turn laser on */
	if (!set_mode_page(target->d_fd, buf)) {
		if (ignore_error)
			return;
		err_msg(gettext("Unable to configure device\n"));
		exit(1);
	}
	free(buf);

	/* we are doing a second pass. We don't want to re-print messsages */
	if (!silent_pass) {
		/* l10n_NOTE : 'done' as in "Initializing device...done"  */
		(void) printf(gettext("done.\n"));

		print_n_flush(gettext(
		    "Blanking the media (Can take several minutes)..."));
	}
	if (!blank_disc(target->d_fd, type, immediate)) {
		if (ignore_error)
			return;
		err_msg(gettext("Blank command failed\n"));
		if (debug)
			(void) printf("%x %x %x %x\n", uscsi_status,
			    SENSE_KEY(rqbuf), ASC(rqbuf), ASCQ(rqbuf));
		goto blank_failed;
	}
	/* Allow the blanking to start */
	(void) sleep(10);

	/*
	 * set ATAPI devices to immediately return from the command and poll
	 * so that we don't hog the channel.
	 */

	if (immediate) {
		di = (uchar_t *)my_zalloc(DISC_INFO_BLOCK_SIZE);
		/* Blanking should not take more than 75 minutes */
		for (count = 0; count < (16*60); count++) {
			ret = read_disc_info(target->d_fd, di);
			if (ret != 0)
				break;
			if (uscsi_status != 2)
				err = 1;
			/* not ready but not becoming ready */
			if (SENSE_KEY(rqbuf) == 2) {
				if (ASC(rqbuf) != 4)
					err = 1;
			/* illegal mode for this track */
			} else if (SENSE_KEY(rqbuf) == 5) {
				if (ASC(rqbuf) != 0x64)
					err = 1;
			} else {
				err = 1;
			}
			if (err == 1) {
				if (ignore_error)
					break;
				err_msg(gettext("Blanking operation failed\n"));
				if (debug) {
					(void) printf("%x %x %x %x\n",
					    uscsi_status, SENSE_KEY(rqbuf),
					    ASC(rqbuf), ASCQ(rqbuf));
				}
				free(di);
				goto blank_failed;
			}
			(void) sleep(5);
		}
		free(di);
		if (count == (16*60)) {
			if (!silent_pass) {
				(void) printf(gettext(
				    "Blank command timed out.\n"));
			}
			goto blank_failed;
		}
	}
	/* we are doing a second pass. We don't want to re-print messsages */
	if (!silent_pass) {
		/* l10n_NOTE : 'done' as in "Erasing track 1...done"  */
		(void) printf(gettext("done.\n"));
	}

	/*
	 * some cruft left from all blanking, this has been seen on some
	 * newer drives including Toshiba SD-6112 DVD-RW and Sony 510A.
	 * we will do a second pass with a recursive call to blank the
	 * lead-in.
	 */
	if (type == ALL) {
		if (check_device(target,  CHECK_MEDIA_IS_NOT_BLANK)) {
			blanking_type = "clear";
			blank();
			if (silent_pass)
				return;
			exit(0);
		}
	}

	/*
	 * We erased part of the leadout for the media to unclose
	 * the disk, we still need to generate an appendable leadout
	 * so that the next track can be written. so do not eject or exit.
	 */
	if (silent_pass)
		return;

	if (vol_running)
		(void) eject_media(target);
	exit(0);
blank_failed:
	if ((type != ALL) && !silent_pass) {
		(void) printf("Try using blanking type 'all'\n");
	}
	if (silent_pass)
		return;
	if (vol_running)
		(void) eject_media(target);
	exit(1);
}
