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

#include <sys/types.h>
#include <stdlib.h>
#include <libintl.h>

#include "msgs.h"
#include "mmc.h"
#include "misc_scsi.h"
#include "device.h"
#include "main.h"
#include "util.h"
#include "toshiba.h"

void
info(void)
{
	uchar_t *toc, *p;
	int ret, toc_size;
	char *msg;
	struct track_info *ti;

	msg = gettext("Cannot read Table of contents\n");

	get_media_type(target->d_fd);

	(void) printf(gettext("\nDevice : %.8s %.16s\n"),
	    &target->d_inq[8], &target->d_inq[16]);
	(void) printf(gettext("Firmware : Rev. %.4s (%.12s)\n"),
	    &target->d_inq[32], &target->d_inq[36]);

	if (check_device(target, CHECK_DEVICE_NOT_READY)) {
		(void) check_device(target, CHECK_NO_MEDIA |
		    EXIT_IF_CHECK_FAILED);
		(void) check_device(target, CHECK_DEVICE_NOT_READY |
		    EXIT_IF_CHECK_FAILED);
	}
	if (!check_device(target, CHECK_MEDIA_IS_NOT_BLANK)) {
		(void) printf(gettext("Media is blank\n"));
		exit(0);
	}

	/*  Find out the number of entries in the toc */
	toc = (uchar_t *)my_zalloc(12);
	if (!read_toc(target->d_fd, 0, 1, 4, toc)) {
		err_msg(msg);
	} else {
		toc_size = 256*toc[0] + toc[1] + 2;
		free(toc);

		/* allocate enough space for each track entry */
		toc = (uchar_t *)my_zalloc(toc_size);

		if (!read_toc(target->d_fd, 0, 1, toc_size, toc)) {
			err_msg(msg);
			exit(1);
		}
		(void) printf("\n");

		/* l10n_NOTE : Preserve column numbers of '|' character */
		(void) printf(gettext("Track No. |Type    |Start address\n"));
		(void) printf("----------+--------+-------------\n");


		/* look at each track and display it's type. */

		for (p = &toc[4]; p < (toc + toc_size); p += 8) {
			if (p[2] != 0xAA)
				(void) printf(" %-3d      |", p[2]);
			else
				(void) printf("Leadout   |");
			(void) printf("%s   |", (p[1] & 4) ? gettext("Data ") :
			    gettext("Audio"));
			(void) printf("%u\n", read_scsi32(&p[4]));
		}
	}
	(void) printf("\n");
	ret = read_toc(target->d_fd, 1, 0, 12, toc);
	if ((ret == 0) || (toc[1] != 0x0a))
		/* For ATAPI drives or old Toshiba drives */
		ret = read_toc_as_per_8020(target->d_fd, 1, 0, 12, toc);

	if (ret && (toc[1] == 0x0a)) {
		(void) printf(gettext("Last session start address: %u\n"),
		    read_scsi32(&toc[8]));
	}
	free(toc);
	ti = (struct track_info *)my_zalloc(sizeof (struct track_info));

	if (build_track_info(target, -1, ti) && (ti->ti_flags & TI_NWA_VALID)) {
		(void) printf(gettext("Next writable address: %u\n"),
		    ti->ti_nwa);
	}
	free(ti);
	exit(0);
}
