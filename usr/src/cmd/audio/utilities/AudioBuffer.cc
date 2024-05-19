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

#include <stdlib.h>
#include <memory.h>
#include "../include/AudioDebug.h"
#include "../include/AudioBuffer.h"
#include "../include/zmalloc.h"

// class AudioBuffer methods

// Constructor with optional hdr, size, and name arguments
AudioBuffer::
AudioBuffer(
	double		len,			// buffer length, in seconds
	const char	*local_name):			// name
	AudioStream(local_name), buflen(len), zflag(0), bufsize(0), bufaddr(0)
{
}

// Destructor
AudioBuffer::
~AudioBuffer()
{
	(void) SetSize(0.);		// deallocate the buffer
}

// XXX - the following functions are good candidates for inlining

// Return TRUE if the stream is 'open'
Boolean AudioBuffer::
opened() const
{
	// A buffer is open if it is allocated and has a valid header
	return (hdrset() && (GetAddress() != 0));
}

#define	MIN_ZBUFFER	(8192 * 10)	// only for large buffers

// Allocate buffer.  Size and header must be set.
AudioError AudioBuffer::
alloc()
{
	long		size;
	size_t		cnt;
	unsigned int	ncpy;
	void*		tmpbuf;

	// this is going to be the size we're setting the buffer
	// to (buflen field). it's set by calling SetSize().
	size = GetHeader().Time_to_Bytes(GetSize());

	// this is actual current size, in bytes, of the allocated
	// buffer (the bufsize field).
	cnt = GetByteCount();

	AUDIO_DEBUG((5, "%d: AudioBuffer::alloc - change from %d to %d bytes\n",
	    getid(), cnt, size));

	bufsize = 0;

	if (size == 0) {
		// Zero size deletes the buffer
		if (bufaddr != 0) {
			if (zflag != 0) {
				AUDIO_DEBUG((5,
			    "%d: AudioBuffer::alloc - zfree mmapped buffer\n",
				    getid()));
				(void) zfree((char *)bufaddr);
			} else {
				AUDIO_DEBUG((5,
			    "%d: AudioBuffer::alloc - free malloc'd buffer\n",
				    getid()));
				(void) free((char *)bufaddr);
			}
			zflag = 0;
		}
		bufaddr = 0;

	} else if (size < 0) {
		// Ridiculous size
		AUDIO_DEBUG((5, "%d: AudioBuffer::alloc - bad size\n",
		    getid()));
		return (RaiseError(AUDIO_ERR_BADARG));

	} else if (bufaddr == 0) {
		// Allocate a new buffer
		if (size > MIN_ZBUFFER) {
			AUDIO_DEBUG((5,
			    "%d: AudioBuffer::alloc - zmalloc new buffer\n",
			    getid()));
			bufaddr = (void*) zmalloc((unsigned int)size);
			zflag = 1;
		} else {
			AUDIO_DEBUG((5,
			    "%d: AudioBuffer::alloc - malloc new buffer\n",
			    getid()));
			bufaddr = (void*) malloc((unsigned int)size);
			zflag = 0;
		}
		if (bufaddr == 0) {
			AUDIO_DEBUG((5,
			    "%d: AudioBuffer::alloc - buffer alloc failed\n",
			    getid()));
			return (RaiseError(AUDIO_UNIXERROR));
		}
	} else {
		// A buffer was already allocated.
		// Change its size, preserving as much data as possible.
		if ((cnt <= MIN_ZBUFFER) && (size <= MIN_ZBUFFER) &&
		    (zflag == 0)) {
			AUDIO_DEBUG((5,
			    "%d: AudioBuffer::alloc - realloc to change size\n",
			    getid()));
			bufaddr = (void*)
			    realloc((char *)bufaddr, (unsigned int)size);
		} else {
			AUDIO_DEBUG((5,
			    "%d: AudioBuffer::alloc - zmalloc new buffer\n",
			    getid()));
			tmpbuf = bufaddr;
			bufaddr = (void*) zmalloc((unsigned int)size);

			// copy over as much of the old data as will fit
			if (bufaddr != 0) {
				ncpy = (cnt < size) ? (unsigned int)cnt :
					(unsigned int)size;

				AUDIO_DEBUG((5,
			    "%d: AudioBuffer::alloc - trasnfer %d bytes\n",
				    getid(), ncpy));
				(void) memcpy(bufaddr, tmpbuf, ncpy);
			}
			if ((cnt > MIN_ZBUFFER) && (zflag != 0)) {
				AUDIO_DEBUG((5,
			    "%d: AudioBuffer::alloc - zfree old buffer\n",
				    getid()));
				(void) zfree((char *)tmpbuf);
			} else {
				AUDIO_DEBUG((5,
			    "%d: AudioBuffer::alloc - free old buffer\n",
				    getid()));
				(void) free((char *)tmpbuf);
			}
			zflag = 1;
		}
		if (bufaddr == 0) {
			return (RaiseError(AUDIO_UNIXERROR));
		}
	}
	bufsize = (size_t)size;
	return (AUDIO_SUCCESS);
}


// Return the buffer address
void* AudioBuffer::
GetAddress() const
{
	return (GetAddress(0.));
}

// Return the buffer address at a given time offset
// Returns NULL if no buffer, or the position is not within the buffer.
void* AudioBuffer::
GetAddress(
	Double		pos) const
{
	char		*addr;
	AudioHdr	hdr_local;
	AudioHdr(AudioBuffer::*hfunc)()const;

	addr = (char *)bufaddr;
	if ((addr == 0) || (pos < 0.) || (pos >= buflen))
		return (NULL);

	// If no offset, it's ok if the header hasn't been set yet
	if (pos == 0.)
		return ((void*) addr);

	// Get the header and make sure it's valid
	// This convoluted hfunc works around non-const function problems
	hfunc = (AudioHdr(AudioBuffer::*)() const)&AudioBuffer::GetHeader;
	hdr_local = (this->*hfunc)();
	if (hdr_local.Validate())
		return (NULL);
	addr += hdr_local.Time_to_Bytes(pos);

	// One more validation, to be paranoid before handing out this address
	if (addr >= ((char *)bufaddr + bufsize))
		return (NULL);
	return ((void*) addr);
}

// Return the buffer size, in bytes
// (as opposed to 'length' which indicates how much data is in the buffer)
size_t AudioBuffer::
GetByteCount() const
{
	return (bufsize);
}

// Return the buffer size, in seconds
// (as opposed to 'length' which indicates how much data is in the buffer)
Double AudioBuffer::
GetSize() const
{
	return (buflen);
}

// Set the buffer size, allocating the buffer as necessary
AudioError AudioBuffer::
SetSize(
	Double		len)			// new size, in seconds
{
	// If no change in size, do nothing
	if (len == buflen)
		return (AUDIO_SUCCESS);

	// If header not set, store the size for later
	buflen = len;
	if (!hdrset()) {
		return (AUDIO_SUCCESS);
	}

	// If shrinking buffer, note this
	if (buflen < GetLength())
		SetLength(buflen);
	return (alloc());
}

// Set the data header
// If no buffer allocated, allocate one now (if size is set).
// If buffer allocated, fiddle the sizes to account for new header type.
AudioError AudioBuffer::
SetHeader(
	const AudioHdr& h)			// header to copy
{
	AudioError	err;

	// Validate, then update the header
	err = h.Validate();
	if (err)
		return (RaiseError(err));
	(void) AudioStream::updateheader(h);

	// If no size set, done for now
	if (buflen == 0.)
		return (AUDIO_SUCCESS);

	// If no buffer allocated, allocate one now
	if (GetAddress() == 0)
		return (alloc());

	// If buffer allocated, change size to match new header
	buflen = h.Bytes_to_Time(GetByteCount());
	return (AUDIO_SUCCESS);
}

// Set the buffer length (ie, the amount of data written to the buffer)
void AudioBuffer::
SetLength(
	Double		len)			// new length
{
	if (!hdrset() || (len < 0.))		// no-op if not ready
		return;
	if (!opened() && (len > 0.))
		return;

	if (Undefined(len) || (len > GetSize())) {
		// Limit to the size of the buffer
		setlength(GetSize());
	} else {
		setlength(len);
	}
}

// Copy data from local buffer into specified buffer.
// No data format translation takes place.
// The object's read position is not updated.
AudioError AudioBuffer::
ReadData(
	void*		buf,		// destination buffer address
	size_t&		len,		// buffer length (updated)
	Double&		pos)		// start position (updated)
{
	off_t		resid;
	off_t		cnt;
	off_t		offset;
	AudioError	err;

	// Copy length, zero return value
	cnt = (off_t)len;
	len = 0;

	// Cannot read if buffer or header not valid
	if (!opened())
		return (RaiseError(AUDIO_ERR_NOEFFECT));

	// Position must be valid
	if ((pos < 0.) || (cnt < 0))
		return (RaiseError(AUDIO_ERR_BADARG));

	// If the starting offset is at or beyond EOF, return eof flag
	if (pos >= GetLength()) {
		err = AUDIO_EOF;
		err.sys = AUDIO_COPY_INPUT_EOF;
		return (err);
	}

	// Limit transfer to remaining room in buffer
	offset = GetHeader().Time_to_Bytes(pos);
	resid = GetHeader().Time_to_Bytes(GetLength()) - offset;
	if (resid <= 0) {
		err = AUDIO_EOF;
		err.sys = AUDIO_COPY_INPUT_EOF;
		return (err);
	}
	if (cnt > resid)
		cnt = resid;

	// Fix the alignment to make sure we're not splitting frames
	err = AUDIO_SUCCESS;
	if (GetHeader().Bytes_to_Bytes(cnt) > 0) {
		// Copy as much data as possible
		memcpy((char *)buf, (char *)((off_t)GetAddress() + offset),
		    (int)cnt);
	} else {
		err.sys = AUDIO_COPY_ZERO_LIMIT;
	}

	// Return the updated transfer size and position
	len = (size_t)cnt;
	pos = GetHeader().Bytes_to_Time(offset + cnt);


	// Check to see if the endian is right.
	coerceEndian((unsigned char *)buf, len, localByteOrder());

	return (err);
}

// Copy data to local buffer from specified buffer.
// No data format translation takes place.
// The object's write position is not updated.
AudioError AudioBuffer::
WriteData(
	void*		buf,		// source buffer address
	size_t&		len,		// buffer length (updated)
	Double&		pos)		// start position (updated)
{
	off_t		resid;
	off_t		cnt;
	off_t		offset;
	AudioError	err;

	// Copy length, zero return value
	cnt = (off_t)len;
	len = 0;

	// Cannot write if buffer or header not valid
	if (!opened())
		return (RaiseError(AUDIO_ERR_NOEFFECT));

	// Position must be valid
	if ((pos < 0.) || (cnt < 0))
		return (RaiseError(AUDIO_ERR_BADARG));

	// If the starting offset beyond end of buffer, return short write flag
	if (pos >= GetSize()) {
		err = AUDIO_EOF;
		err.sys = AUDIO_COPY_OUTPUT_EOF;
		return (err);
	}

	// Limit transfer to remaining room in buffer
	offset = GetHeader().Time_to_Bytes(pos);
	resid = (off_t)bufsize - offset;
	if (resid <= 0) {
		err = AUDIO_EOF;
		err.sys = AUDIO_COPY_OUTPUT_EOF;
		return (err);
	}
	if (cnt > resid)
		cnt = resid;

	// Fix the alignment to make sure we're not splitting frames
	err = AUDIO_SUCCESS;
	if (GetHeader().Bytes_to_Bytes(cnt) > 0) {
		// Copy as much data as possible
		memcpy((char *)((off_t)GetAddress() + offset), (char *)buf,
		    (int)cnt);
	} else {
		err.sys = AUDIO_COPY_ZERO_LIMIT;
	}

	// Return the updated transfer size and position
	len = (size_t)cnt;
	pos = GetHeader().Bytes_to_Time(offset + cnt);

	// The end of a write to a buffer always becomes the buffer EOF
	setlength(pos);
	return (err);
}

// AppendData is just like WriteData, except that it guarantees to extend
// the buffer if it is not big enough.
// The object's write position is not updated.
AudioError AudioBuffer::
AppendData(
	void*		buf,		// source buffer address
	size_t&		len,		// buffer length (updated)
	Double&		pos)		// start position (updated)
{
	Double		local_length;
	AudioError	err;

	// Cannot write if header not valid
	if (!hdrset())
		return (RaiseError(AUDIO_ERR_NOEFFECT));

	// Position must be valid
	if (pos < 0.)
		return (RaiseError(AUDIO_ERR_BADARG));

	// If the ending offset is beyond end of buffer, extend it
	local_length = pos + GetHeader().Bytes_to_Time(len);
	if (local_length > GetSize()) {
		if (err = SetSize(local_length))
			return (err);
	}
	return (WriteData(buf, len, pos));
}

// Copy routine to copy direct to destination
AudioError AudioBuffer::
AsyncCopy(
	Audio*		to,			// audio object to copy to
	Double&		frompos,
	Double&		topos,
	Double&		limit)
{
	caddr_t		bptr;
	size_t		cnt;
	size_t		svcnt;
	Double		svfrom;
	Double		svto;
	Double		lim;
	AudioHdr	tohdr;
	AudioError	err;

	// Cannot write if buffer or header not valid
	if (!opened())
		return (RaiseError(AUDIO_ERR_NOEFFECT));

	tohdr = to->GetHeader();
	if (limit < 0.)
		return (RaiseError(AUDIO_ERR_BADARG));

	// Get maximum possible copy length
	svfrom = GetLength();
	if (frompos >= svfrom) {
		limit = 0.;
		err = AUDIO_EOF;
		err.sys = AUDIO_COPY_INPUT_EOF;
		return (err);
	}
	lim = svfrom - frompos;
	if (!Undefined(limit) && (limit < lim))
		lim = limit;

	limit = 0.;

	bptr = (caddr_t)GetAddress(frompos);
	if (bptr == 0) {
		err = AUDIO_EOF;
		err.sys = AUDIO_COPY_INPUT_EOF;
		return (err);
	}
	cnt = (size_t)GetHeader().Time_to_Bytes(lim);
	if (cnt == 0) {
		err = AUDIO_SUCCESS;
		err.sys = AUDIO_COPY_ZERO_LIMIT;
		return (err);
	}

	// Add a bunch of paranoid checks
	svcnt = (size_t)GetAddress() + (size_t)GetByteCount();
	if ((bptr + cnt) > (caddr_t)svcnt) {
		// re-adjust cnt so it reads up to the end of file
		cnt = (size_t)((caddr_t)svcnt - bptr);
	}
	if (GetHeader().Bytes_to_Bytes(cnt) == 0) {
		err = AUDIO_EOF;
		err.sys = AUDIO_COPY_INPUT_EOF;
		return (err);
	}

	// Write the data to the destination and update pointers/ctrs
	svfrom = frompos;
	svto = topos;
	svcnt = cnt;
	err = to->WriteData(bptr, cnt, topos);
	limit = topos - svto;
	frompos = svfrom + limit;

	// Report short writes
	if (!err && (cnt < svcnt)) {
		err.sys = AUDIO_COPY_SHORT_OUTPUT;
	}
	return (err);
}
