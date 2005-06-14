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
 * Copyright (c) 1993-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <AudioExtent.h>
#include <stdio.h>

// class AudioExtent methods


// class AudioExtent Constructor
AudioExtent::
AudioExtent(
	Audio*		obj,		// audio object to point to
	double		s,		// start time
	double		e):		// end time
	Audio("[extent]"), ref(obj)
{
	ref->Reference();		// reference audio object
	SetStart(s);			// set start/end times
	SetEnd(e);
}

// class AudioExtent Destructor
AudioExtent::
~AudioExtent()
{
	ref->Dereference();		// clear audio object reference
}

// Get referenced object
Audio* AudioExtent::
GetRef() const
{
	return (ref);
}

// Set referenced object
void AudioExtent::
SetRef(
	Audio*		r)		// new audio object
{
	if (ref == r)			// object is not changing
		return;
	ref->Dereference();		// dereference previous object
	if (r != 0) {
		ref = r;
		ref->Reference();	// reference new object
	} else {
		PrintMsg(_MGET_("AudioExtent:...NULL Audio object reference"),
		    Fatal);
	}
}

// Get start time
Double AudioExtent::
GetStart() const
{
	return (start);
}

// Set start time
void AudioExtent::
SetStart(
	Double		s)		// start time, in seconds
{
	if (Undefined(s) || (s < 0.))
		start = 0.;
	else
		start = s;
}

// Get end time
Double AudioExtent::
GetEnd() const
{
	// If determinate endpoint, return it
	if (!Undefined(end))
		return (end);
	// Otherwise, return the endpoint of the underlying object
	return (ref->GetLength());
}

// Set end time
void AudioExtent::
SetEnd(
	Double		e)		// end time, in seconds
{
	Double		len;

	// If known endpoint and object has known size, do not exceed size
	if (!Undefined(e)) {
		len = ref->GetLength();
		if (!Undefined(len) && (e > len))
			e = len;
	}
	end = e;
}

// Get the length of an audio extent
Double AudioExtent::
GetLength() const
{
	Double		x;

	// If extent end is indeterminate, use the end of the target object
	x = GetEnd();
	// If the object length is indeterminate, then the length is
	if (Undefined(x))
		return (x);
	return (x - start);
}

// Construct a name for the list
char *AudioExtent::
GetName() const
{
	// XXX - construct a better name
	return (ref->GetName());
}

// Get the audio header for the current read position
AudioHdr AudioExtent::
GetHeader()
{
	return (ref->GetDHeader(ReadPosition() + start));
}

// Get the audio header for the given position
AudioHdr AudioExtent::
GetHeader(
	Double		pos)		// position
{
	return (ref->GetDHeader(pos + start));
}

// Copy data from extent into specified buffer.
// No data format translation takes place.
// The object's read position is not updated.
//
// Since the extent could refer to a list of extents of differing encodings,
// clients should always use GetHeader() in combination with ReadData()
AudioError AudioExtent::
ReadData(
	void*		buf,		// destination buffer address
	size_t&		len,		// buffer size (updated)
	Double&		pos)		// start position (updated)
{
	size_t		cnt;
	off_t		buflen;
	Double		off;
	Double		newpos;
	AudioError	err;

	// Save buffer size and zero transfer count
	cnt = len;
	len = 0;

	// Position must be valid
	if (Undefined(pos) || (pos < 0.) || ((int)cnt < 0))
		return (RaiseError(AUDIO_ERR_BADARG));

	// If the end is determinate, check start position and length
	off = pos + start;
	newpos = GetEnd();
	if (!Undefined(newpos)) {
		// If starting beyond eof, give up now
		if (off >= newpos) {
			err = AUDIO_EOF;
			err.sys = AUDIO_COPY_INPUT_EOF;
			return (err);
		}

		// If the read would extend beyond end-of-extent, shorten it
		buflen = GetHeader(pos).Time_to_Bytes((Double)(newpos - off));
		if (buflen == 0) {
			err = AUDIO_EOF;
			err.sys = AUDIO_COPY_INPUT_EOF;
			return (err);
		}
		if (buflen < cnt)
			cnt = (size_t)buflen;
	}
	// Zero-length reads are easy
	if (cnt == 0) {
		err = AUDIO_SUCCESS;
		err.sys = AUDIO_COPY_ZERO_LIMIT;
		return (err);
	}

	// Save the offset, read data, and update the returned position
	newpos = off;
	len = cnt;
	err = ref->ReadData(buf, len, newpos);
	pos = (newpos - start);		// XXX - calculate bytes and convert?
	return (err);
}

// Write to AudioExtent is (currently) prohibited
AudioError AudioExtent::
WriteData(
	void*,				// destination buffer address
	size_t&		len,		// buffer size (updated)
	Double&)			// start position (updated)
{
	len = 0;
	return (RaiseError(AUDIO_ERR_NOEFFECT));
}
