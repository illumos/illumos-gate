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

#include <string.h>
#include <stdlib.h>
#include <libintl.h>

#include "bstream.h"
#include "trackio.h"
#include "misc_scsi.h"
#include "util.h"
#include "msgs.h"
#include "main.h"
#include "trackio.h"
#include "mmc.h"

static  bstreamhandle
open_audio(char *fname)
{
	int at;
	char *ext;

	/* No audio type specified, look at extension */
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
		return (open_au_read_stream(fname));
	if (at == AUDIO_TYPE_WAV)
		return (open_wav_read_stream(fname));
	if (at == AUDIO_TYPE_CDA)
		return (open_file_read_stream(fname));
	if (at == AUDIO_TYPE_AUR)
		return (open_aur_read_stream(fname));
	return (NULL);
}

void
write_audio(char **argv, int start_argc, int argc)
{
	bstreamhandle *h_ptr;
	int i, nfiles;
	struct track_info *ti;
	uint32_t blks_req, blks_avail;
	off_t fsize;

	/* number of tracks to write */
	nfiles = argc - start_argc;
	h_ptr = (bstreamhandle *)my_zalloc(nfiles * sizeof (bstreamhandle));
	blks_req = 0;
	for (i = 0; i < nfiles; i++) {
		h_ptr[i] = open_audio(argv[start_argc + i]);
		if (h_ptr[i] == NULL) {
			err_msg(gettext("Cannot open %s: %s\n"),
			    argv[start_argc + i], get_err_str());
			exit(1);
		}
		(void) (h_ptr[i])->bstr_size(h_ptr[i], &fsize);

		/* 2352 bytes per block, 75 blocks per second */
		blks_req += 150 + fsize/2352; /* 2 sec gap per track */
		if (fsize % 2352)
			blks_req++;
	}
	(void) check_device(target, CHECK_DEVICE_NOT_READY |
	    CHECK_DEVICE_NOT_WRITABLE | CHECK_MEDIA_IS_NOT_WRITABLE |
	    EXIT_IF_CHECK_FAILED);

	/* Put the device in track-at-once mode */
	write_init(TRACK_MODE_AUDIO);
	ti = (struct track_info *)my_zalloc(sizeof (*ti));

	/* Build information for next invisible track, -1 */
	if ((build_track_info(target, -1, ti) == 0) ||
	    ((ti->ti_flags & TI_NWA_VALID) == 0)) {
		err_msg(gettext(
		    "Cannot get writable address for the media.\n"));
		exit(1);
	}
	if ((blks_avail = get_last_possible_lba(target)) == 0) {
		err_msg(gettext("Unable to determine media capacity. "
		    "Defaulting to 650 MB (74 minute) disc.\n"));
		blks_avail = MAX_CD_BLKS;
	} else {
		/* LBA is always one less */
		blks_avail++;
	}
	/*
	 * Actual number of blocks available based on nwa (next writable
	 * address) since there may already be information on the disc.
	 */

	blks_avail -= ti->ti_nwa;
	if (blks_avail < blks_req) {
		err_msg(gettext("Insufficient space on the media.\n"));
		exit(1);
	}
	for (i = 0; i < nfiles; i++) {
		write_next_track(TRACK_MODE_AUDIO, h_ptr[i]);
		if (simulation && (nfiles != 1)) {
			(void) printf(gettext(
			    "Simulation mode : skipping remaining tracks\n"));
			break;
		}
	}
	for (i = 0; i < nfiles; i++)
		(h_ptr[i])->bstr_close(h_ptr[i]);
	free(ti);
	free(h_ptr);

	write_fini();

	fini_device(target);
	exit(0);
}
