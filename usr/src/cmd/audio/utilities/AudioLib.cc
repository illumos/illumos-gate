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
 * Copyright (c) 1990-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <Audio.h>
#include <AudioFile.h>
#include <AudioList.h>
#include <AudioLib.h>

// Generic Audio functions


// Open an audio file readonly, and return an AudioList referencing it.
AudioError
Audio_OpenInputFile(
	const char	*path,		// input filename
	Audio*&		ap)		// returned AudioList pointer
{
	AudioFile*	inf;
	AudioList*	lp;
	AudioError	err;

	// Open file and decode the header
	inf = new AudioFile(path, (FileAccess)ReadOnly);
	if (inf == 0)
		return (AUDIO_UNIXERROR);
	err = inf->Open();
	if (err) {
		delete inf;
		return (err);
	}

	// Create a list object and set it up to reference the file
	lp = new AudioList;
	if (lp == 0) {
		delete inf;
		return (AUDIO_UNIXERROR);
	}
	lp->Insert(inf);
	ap = lp;
	return (AUDIO_SUCCESS);
}


// Create an output file and copy an input stream to it.
// If an error occurs during output, leave a partially written file.
AudioError
Audio_WriteOutputFile(
	const char	*path,		// output filename
	const AudioHdr&	hdr,		// output data header
	Audio*		input)		// input data stream
{
	AudioFile*	outf;
	AudioError	err;

	// Create output file object
	outf = new AudioFile(path, (FileAccess)WriteOnly);
	if (outf == 0)
		return (AUDIO_UNIXERROR);

	// Set audio file header and create file
	if ((err = outf->SetHeader(hdr)) || (err = outf->Create())) {
		delete outf;
		return (err);
	}

	// Copy data to file
	err = AudioCopy(input, outf);

	// Close output file and clean up.  If error, leave partial file.
	delete outf;
	return (err);
}
