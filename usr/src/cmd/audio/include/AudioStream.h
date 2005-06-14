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

#ifndef _MULTIMEDIA_AUDIOSTREAM_H
#define	_MULTIMEDIA_AUDIOSTREAM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <Audio.h>
#include <AudioHdr.h>
#include <stdlib.h>
#include <AudioDebug.h>

#ifdef __cplusplus
extern "C" {
#endif

// This is the abstract base class for all audio data sources/sinks.
// It is invalid to create an object of type AudioStream.

class AudioStream : public Audio {
private:
	AudioHdr	hdr;			// data encoding info
	Double		length;			// length of data, in secs

protected:

	Boolean hdrset() const;			// TRUE if header valid

	// Set header (always)
	AudioError updateheader(
	    const AudioHdr& h);			// header to copy

	// Set data length
	void setlength(
	    Double len);			// new length, in secs

	virtual Boolean opened() const = 0;	// TRUE if stream 'open'

public:
	AudioStream(const char *path = "");	// Constructor

	// Set header
	virtual AudioError SetHeader(
	    const AudioHdr& h);			// header to copy

	// Set data length
	virtual void SetLength(
	    Double len);			// new length, in secs

	// XXX - is this needed?  do we need time->sample frames?
	virtual size_t GetByteCount() const;		// Get length, in bytes

	// class Audio methods specialized here
	virtual AudioHdr GetHeader();			// Get header

	virtual Double GetLength() const;		// Get length, in secs

	// Make sure endian of the data matches the current processor.
	AudioError coerceEndian(unsigned char *buf, size_t len,
	    AudioEndian en);

	virtual Boolean isEndianSensitive() const;
	AudioEndian localByteOrder() const
	{
		return (hdr.localByteOrder());
	}
};

#include <AudioStream_inline.h>

#ifdef __cplusplus
}
#endif

#endif /* !_MULTIMEDIA_AUDIOSTREAM_H */
