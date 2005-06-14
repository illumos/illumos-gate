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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <AudioHdr.h>

// class AudioHdr basic methods

// This routine uses the byteorder network utilities to tell whether the
// current process uses network byte order or not.
AudioEndian AudioHdr::localByteOrder() const
{
	short sTestHost;
	short sTestNetwork;
	static AudioEndian ae = UNDEFINED_ENDIAN;

	if (ae == UNDEFINED_ENDIAN) {
		sTestHost = MAXSHORT;
		sTestNetwork = htons(sTestHost);
		if (sTestNetwork != sTestHost) {
			ae = LITTLE_ENDIAN;
		} else {
			ae = BIG_ENDIAN;
		}
	}
	return (ae);
}

// Clear a header structure
void AudioHdr::
Clear()
{
	sample_rate = 0;
	samples_per_unit = 0;
	bytes_per_unit = 0;
	channels = 0;
	encoding = NONE;
}

// Return error code (TRUE) if header is inconsistent or unrecognizable
// XXX - how do we support extensions?
AudioError AudioHdr::
Validate() const
{
	// Check for uninitialized fields
	if ((bytes_per_unit < 1) || (samples_per_unit < 1) ||
	    (sample_rate < 1) || (channels < 1))
		return (AUDIO_ERR_BADHDR);

	switch (encoding) {
	case NONE:
		return (AUDIO_ERR_BADHDR);

	case LINEAR:
		if (bytes_per_unit > 4)
			return (AUDIO_ERR_PRECISION);
		if (samples_per_unit != 1)
			return (AUDIO_ERR_HDRINVAL);
		break;

	case FLOAT:
		if ((bytes_per_unit != 4) && (bytes_per_unit != 8))
			return (AUDIO_ERR_PRECISION);
		if (samples_per_unit != 1)
			return (AUDIO_ERR_HDRINVAL);
		break;

	case ULAW:
	case ALAW:
	case G722:
		if (bytes_per_unit != 1)
			return (AUDIO_ERR_PRECISION);
		if (samples_per_unit != 1)
			return (AUDIO_ERR_HDRINVAL);
		break;

	case G721:
	case DVI:
		// G.721 is a 4-bit encoding
		if ((bytes_per_unit != 1) || (samples_per_unit != 2))
			return (AUDIO_ERR_PRECISION);
		break;

	case G723:
		// G.723 has 3-bit and 5-bit flavors
		// 5-bit is currently unsupported
		if ((bytes_per_unit != 3) || (samples_per_unit != 8))
			return (AUDIO_ERR_PRECISION);
		break;
	}
	return (AUDIO_SUCCESS);
}


// Convert a byte count into a floating-point time value, in seconds,
// using the encoding specified in the audio header.
Double AudioHdr::
Bytes_to_Time(
	off_t	cnt) const			// byte count
{
	if ((cnt == AUDIO_UNKNOWN_SIZE) || (Validate() != AUDIO_SUCCESS))
		return (AUDIO_UNKNOWN_TIME);

	// round off to nearest sample frame!
	cnt -= (cnt % (bytes_per_unit * channels));

	return (Double) ((double)cnt /
	    ((double)(channels * bytes_per_unit * sample_rate) /
	    (double)samples_per_unit));
}

// Convert a floating-point time value, in seconds, to a byte count for
// the audio encoding in the audio header.  Make sure that the byte count
// or offset does not span a sample frame.
off_t AudioHdr::
Time_to_Bytes(
	Double	sec) const			// time, in seconds
{
	off_t	offset;

	if (Undefined(sec) || (Validate() != AUDIO_SUCCESS))
		return (AUDIO_UNKNOWN_SIZE);

	offset = (off_t)(0.5 + (sec *
	    ((double)(channels * bytes_per_unit * sample_rate) /
	    (double)samples_per_unit)));

	// Round down to the start of the nearest sample frame
	offset -= (offset % (bytes_per_unit * channels));
	return (offset);
}

// Round a byte count down to a sample frame boundary.
off_t AudioHdr::
Bytes_to_Bytes(
	off_t&	cnt) const
{
	if (Validate() != AUDIO_SUCCESS)
		return (AUDIO_UNKNOWN_SIZE);

	// Round down to the start of the nearest sample frame
	cnt -= (cnt % (bytes_per_unit * channels));
	return (cnt);
}

// Round a byte count down to a sample frame boundary.
size_t AudioHdr::
Bytes_to_Bytes(
	size_t&	cnt) const
{
	if (Validate() != AUDIO_SUCCESS)
		return (AUDIO_UNKNOWN_SIZE);

	// Round down to the start of the nearest sample frame
	cnt -= (cnt % (bytes_per_unit * channels));
	return (cnt);
}

// Convert a count of sample frames into a floating-point time value,
// in seconds, using the encoding specified in the audio header.
Double AudioHdr::
Samples_to_Time(
	unsigned long	cnt) const		// sample frame count
{
	if ((cnt == AUDIO_UNKNOWN_SIZE) || (Validate() != AUDIO_SUCCESS))
		return (AUDIO_UNKNOWN_TIME);

	return ((Double)(((double)cnt * (double)samples_per_unit) /
	    (double)sample_rate));
}

// Convert a floating-point time value, in seconds, to a count of sample frames
// for the audio encoding in the audio header.
unsigned long AudioHdr::
Time_to_Samples(
	Double	sec) const			// time, in seconds
{
	if (Undefined(sec) || (Validate() != AUDIO_SUCCESS))
		return (AUDIO_UNKNOWN_SIZE);

	// Round down to sample frame boundary
	return ((unsigned long) (AUDIO_MINFLOAT +
	    (((double)sec * (double)sample_rate) / (double)samples_per_unit)));
}

// Return the number of bytes in a sample frame for the audio encoding.
unsigned int AudioHdr::
FrameLength() const
{
	return (bytes_per_unit * channels);
}
