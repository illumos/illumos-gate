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

#include <AudioStream.h>
#include <string.h>

// class AudioStream methods


// Constructor
AudioStream::
AudioStream(
	const char	*path):			// pathname
	Audio(path), length(AUDIO_UNKNOWN_TIME)
{
}

// Set the header structure, even if it is already set
AudioError AudioStream::
updateheader(
	const AudioHdr&	h)			// new header to set
{
	AudioError	err;

	// Validate the header before stuffing it in
	err = h.Validate();
	if (err != AUDIO_SUCCESS)
		return (RaiseError(err));

	// Copy in the new header
	hdr = h;
	return (AUDIO_SUCCESS);
}

// Set the header structure
AudioError AudioStream::
SetHeader(
	const AudioHdr&	h)			// new header to set
{
	// Once the header is set and the file is open, it cannot be changed
	// XXX - hdrset test might be redundant?
	if (hdrset() && opened())
		return (RaiseError(AUDIO_ERR_NOEFFECT));

	return (updateheader(h));
}

// Check the endian nature of the data, and change if necessary.
AudioError AudioStream::
coerceEndian(unsigned char *buf, size_t len,
		    AudioEndian endian)
{
	// If the stream isn't endian sensitive, don't bother.
	if (! isEndianSensitive())
		return (AUDIO_SUCCESS);

	if (hdr.endian == endian) {
#ifdef DEBUG
		AUDIO_DEBUG((1, "AudioStream: endian swap not needed, byte"
		    "order OK.\n"));
#endif
		return (AUDIO_SUCCESS);
	}

	// The endians don't match, lets swap bytes.
	unsigned char chTemp;
	for (int i = 0; i < len - 1; i += 2) {
		chTemp = buf[i];
		buf[i] = buf[i + 1];
		buf[i+1] = chTemp;
	}

#ifdef DEBUG
	AUDIO_DEBUG((1, "AudioStream: converting endian.\n"));
	// printf("AudioStream: converting endian.\n");
#endif
	return (AUDIO_SUCCESS);
}

// This routine knows if the current format is endian sensitive.
Boolean AudioStream::isEndianSensitive() const
{

	// Only these encodings have endian problems.
	if (hdr.encoding == LINEAR || hdr.encoding == FLOAT)
		return (TRUE);

	return (FALSE);
}
