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

#ifndef _MULTIMEDIA_AUDIOSTREAM_INLINE_H
#define	_MULTIMEDIA_AUDIOSTREAM_INLINE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

// Inline routines for class AudioStream

// Return TRUE if the current AudioHdr is valid
inline Boolean AudioStream::
hdrset() const
{
	return (hdr.Validate() == AUDIO_SUCCESS);
}

// Return the current AudioHdr
inline AudioHdr AudioStream::
GetHeader()
{
	return (hdr);
}

// Set the length parameter
inline void AudioStream::
setlength(
	Double len)		// new length, in secs
{
	length = len;
}

// Set the length parameter, if possible
inline void AudioStream::
SetLength(
	Double len)		// new length, in secs
{
	// This may be used to set the expected length of a write-only stream
	if (!opened())
		length = len;
}

inline Double AudioStream::
GetLength() const
{
	return (length);
}

inline size_t AudioStream::
GetByteCount() const
{
	return (hdr.Time_to_Bytes(length));
}

#ifdef __cplusplus
}
#endif

#endif /* !_MULTIMEDIA_AUDIOSTREAM_INLINE_H */
