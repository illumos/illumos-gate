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
 * Copyright 1991-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>

#include <AudioRawPipe.h>
#include <libaudio.h>
#include <audio_hdr.h>

// class AudioPipe methods

// Constructor with file descriptor, mode, and optional name
AudioRawPipe::
AudioRawPipe(
	const int		desc,		// file descriptor
	const FileAccess	acc,		// access mode
	const AudioHdr&		hdr_local,	// header
	const char		*name_local,	// name
	const off_t		off		// offset
):AudioPipe(desc, acc, name_local), offset(off)
{
	isopened = FALSE;
	setfd(desc);
	SetHeader(hdr_local);
}

// The create routine for pipes writes a file header
AudioError AudioRawPipe::
Create()
{
	AudioError	err;

	// Was the header properly set?
	err = GetHeader().Validate();
	if (err != AUDIO_SUCCESS)
		return (RaiseError(err));

	// Open fd supplied by constructor
	if (!isfdset() || opened()) {
		return (RaiseError(AUDIO_ERR_NOEFFECT, Warning));
	}

	// set flag for opened() test
	isopened = TRUE;

	// Set the actual output length to zero
	setlength(0.);

	return (AUDIO_SUCCESS);
}

// The open routine for raw pipes validates the header and
// init's the read pos to offset and sets the opened flag.
AudioError AudioRawPipe::
Open()
{
	AudioError	err;
	struct stat	st;

	// The constructor should have supplied a valid fd
	// If fd is not open, or file header already decoded, skip it
	if (!isfdset() || opened())
		return (RaiseError(AUDIO_ERR_NOEFFECT, Warning));

	// Stat the file, to see if it is a regular file
	if (fstat(getfd(), &st) < 0)
		return (RaiseError(AUDIO_UNIXERROR));

	// check validity of file header
	err = GetHeader().Validate();
	if (err != AUDIO_SUCCESS) {
		(void) close(getfd());
		setfd(-1);
		return (err);
	}

	// Only trust the file size for regular files
	if (S_ISREG(st.st_mode)) {
		// for raw files - no hdr, so it's the whole file minus
		// the offset.
		setlength(GetHeader().Bytes_to_Time(st.st_size - offset));
	} else {
		// don't know ...
		setlength(AUDIO_UNKNOWN_TIME);
	}

	// set flag for opened() test
	isopened = TRUE;

	err = SetOffset(offset);

	// reset logical position to 0.0, since this is, in effect,
	// the beginning of the file.
	SetReadPosition(0.0, Absolute);

	return (err);
}

Boolean AudioRawPipe::
opened() const
{
	return (isopened);
}

AudioError AudioRawPipe::
SetOffset(off_t val)
{
	off_t		setting = 0;
	AudioError	err;

	// only read only files for now
	if (GetAccess().Writeable()) {
		return (AUDIO_ERR_NOEFFECT);
	}

	// only allow this if we haven't read anything yet (i.e. current
	// position is 0).
	if (ReadPosition() != 0.) {
		return (AUDIO_ERR_NOEFFECT);
	}

	if ((err = seekread(GetHeader().Bytes_to_Time(val), setting))
	    != AUDIO_SUCCESS) {
		return (err);
	}

	// this should *never* happen 'cause seekread just sets setting
	// to GetHeader().Time_to_Bytes....
	if (setting != val) {
		// don't really know what error is apropos for this.
		return (AUDIO_ERR_BADFRAME);
	}

	offset = val;
	return (AUDIO_SUCCESS);
}

off_t AudioRawPipe::
GetOffset() const
{
	return (offset);
}
