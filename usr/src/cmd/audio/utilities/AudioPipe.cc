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

#include <stdlib.h>
#include <unistd.h>
#include <AudioPipe.h>

// class AudioPipe methods


// Constructor with file descriptor, mode, and optional name
AudioPipe::
AudioPipe(
	const int		desc,		// file descriptor
	const FileAccess	acc,		// access mode
	const char		*name_local):	// name
	AudioUnixfile(name_local, acc)
{
	setfd(desc);
}

// The create routine for pipes writes a file header
AudioError AudioPipe::
Create()
{
	AudioError	err;

	// Was the header properly set?
	err = GetHeader().Validate();
	if (err != AUDIO_SUCCESS)
		return (RaiseError(err));

	// Open fd supplied by constructor
	if (!isfdset())
		return (RaiseError(AUDIO_ERR_NOEFFECT));

	// Write the file header with current (usually unknown) size
	err = encode_filehdr();
	if (err != AUDIO_SUCCESS) {
		(void) close(getfd());		// If error, remove file
		setfd(-1);
		return (err);
	}

	// Set the actual output length to zero
	setlength(0.);

	return (AUDIO_SUCCESS);
}

// The open routine for pipes decodes the header
AudioError AudioPipe::
Open()
{
	AudioError		err;

	// The constructor should have supplied a valid fd
	if (!isfdset())
		return (RaiseError(AUDIO_ERR_NOEFFECT));

	// Decode a file header
	err = decode_filehdr();
	if (err != AUDIO_SUCCESS) {
		(void) close(getfd());
		setfd(-1);
		return (err);
	}

	return (AUDIO_SUCCESS);
}

// Read data from underlying pipe into specified buffer.
// No data format translation takes place.
// Since there's no going back, the object's read position pointer is updated.
AudioError AudioPipe::
ReadData(
	void*		buf,		// destination buffer address
	size_t&		len,		// buffer length (updated)
	Double&		pos)		// start position (updated)
{
	AudioError	err;
	char		*tbuf;		// current buffer pointer
	size_t		remain;		// number of bytes remaining
	size_t		cnt;		// accumulated number of bytes read

	tbuf = (char *)buf;
	remain = len;
	cnt = 0;

	// Pipes return short reads.  If non-blocking i/o, try to read all.
	do {
		// Call the real routine
		err = AudioUnixfile::ReadData((void*)tbuf, remain, pos);

		// Update the object's read position
		if (!err) {
			(void) SetReadPosition(pos, Absolute);
			if (remain == 0)
				break;
			cnt += remain;
			tbuf += remain;
			remain = len - cnt;
		}
	} while (!err && (remain > 0) && GetBlocking());
	len = cnt;
	if (len > 0)
		return (AUDIO_SUCCESS);
	return (err);
}

// Write data to underlying file from specified buffer.
// No data format translation takes place.
// Since there's no going back, the object's write position pointer is updated.
AudioError AudioPipe::
WriteData(
	void*		buf,		// source buffer address
	size_t&		len,		// buffer length (updated)
	Double&		pos)		// start position (updated)
{
	AudioError	err;

	// Call the real routine
	err = AudioUnixfile::WriteData(buf, len, pos);

	// Update the object's write position
	if (err == AUDIO_SUCCESS)
		(void) SetWritePosition(pos, Absolute);
	return (err);
}
