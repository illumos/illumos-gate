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
 * Copyright (c) 1992-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _MULTIMEDIA_AUDIOBUFFER_H
#define	_MULTIMEDIA_AUDIOBUFFER_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <AudioStream.h>

#ifdef __cplusplus
extern "C" {
#endif

// This is the class describing a mapped buffer of audio data.
// In addition to the standard Read and Write methods, the address
// of the buffer may be obtained and the data accessed directly.

class AudioBuffer : public AudioStream {
private:
	Double		buflen;			// buffer size, in seconds
	int		zflag;			// malloc'd with zmalloc?
protected:
	size_t		bufsize;		// buffer size, in bytes
	void*		bufaddr;		// buffer address

	// class AudioStream methods specialized here
	virtual Boolean opened() const;			// TRUE, if open
	virtual AudioError alloc();			// Allocate buffer

public:
	// Constructor
	AudioBuffer(
	    double len = 0.,			// buffer size, in seconds
	    const char *name = "(buffer)");	// name
	~AudioBuffer();					// Destructor

	virtual void* GetAddress() const;		// Get buffer address
	virtual void* GetAddress(Double) const;		// Get address at offset
	virtual AudioError SetSize(Double len);		// Change buffer size
	virtual Double GetSize() const;			// Get buffer size
	virtual size_t GetByteCount() const;		// Get size, in bytes

	// class AudioStream methods specialized here
	// Set header
	virtual AudioError SetHeader(
	    const AudioHdr& h);			// header to copy

	// Set data length
	virtual void SetLength(
	    Double len);			// new length, in secs

	// class Audio methods specialized here

	// Read from position
	virtual AudioError ReadData(
	    void* buf,				// buffer to fill
	    size_t& len,			// buffer length (updated)
	    Double& pos);			// start position (updated)

	// Write at position
	virtual AudioError WriteData(
	    void* buf,				// buffer to copy
	    size_t& len,			// buffer length (updated)
	    Double& pos);			// start position (updated)

	// Append at position
	virtual AudioError AppendData(
	    void* buf,				// buffer to copy
	    size_t& len,			// buffer length (updated)
	    Double& pos);			// start position (updated)

	// copy to another audio obj.
	virtual AudioError AsyncCopy(
	    Audio* to,				// dest audio object
	    Double& frompos,
	    Double& topos,
	    Double& limit);

	virtual Boolean isBuffer() const { return (TRUE); }
};

#ifdef __cplusplus
}
#endif

#endif /* !_MULTIMEDIA_AUDIOBUFFER_H */
