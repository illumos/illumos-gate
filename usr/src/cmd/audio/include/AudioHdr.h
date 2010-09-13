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

#ifndef _MULTIMEDIA_AUDIOHDR_H
#define	_MULTIMEDIA_AUDIOHDR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef NO_EXTERN_C

#ifdef __cplusplus
extern "C" {
#endif

#endif /* NO_EXTERN_C */

#include <AudioTypes.h>
#include <AudioError.h>
#include <audio_hdr.h>

// Required for the use of MAXSHORT
#include <values.h>

// Required by htons() and other network services.
#include <sys/types.h>
#include <netinet/in.h>

// Define an in-core audio data header.
//
// This is different than the on-disk file header.
//
//
// The audio header contains the following fields:
//
//	sample_rate		Number of samples per second (per channel).
//
//	samples_per_unit	This field describes the number of samples
//				  represented by each sample unit (which, by
//				  definition, are aligned on byte boundaries).
//				  Audio samples may be stored individually
//				  or, in the case of compressed formats
//				  (e.g., ADPCM), grouped in algorithm-
//				  specific ways.  If the data is bit-packed,
//				  this field tells the number of samples
//				  needed to get to a byte boundary.
//
//	bytes_per_unit		Number of bytes stored for each sample unit
//
//	channels		Number of interleaved sample units.
//				   For any given time quantum, the set
//				   consisting of 'channels' sample units
//				   is called a sample frame.  Seeks in
//				   the data should be aligned to the start
//				   of the nearest sample frame.
//
//	encoding		Data encoding format.
//
//
// The first four values are used to compute the byte offset given a
// particular time, and vice versa.  Specifically:
//
//	seconds = offset / C
//	offset = seconds * C
// where:
//	C = (channels * bytes_per_unit * sample_rate) / samples_per_unit


// Define the possible encoding types.
// XXX - As long as audio_hdr.h exists, these values should match the
//	 corresponding fields in audio_hdr.h since the cast operator
//	 copies them blindly.  This implies that the values should
//	 match any of the encodings that appear in <sys/audioio.h> also.
// XXX - How can encoding types be added dynamically?
enum AudioEncoding {
	NONE = 0,	// no encoding type set
	ULAW = 1,	// ISDN u-law
	ALAW = 2,	// ISDN A-law
	LINEAR = 3,	// PCM 2's-complement (0-center)
	FLOAT = 100,	// IEEE float (-1. <-> +1.)
	G721 = 101,	// CCITT G.721 ADPCM
	G722 = 102,	// CCITT G.722 ADPCM
	G723 = 103,	// CCITT G.723 ADPCM
	DVI = 104 	// DVI ADPCM
};

// The byte order of the data.  This is only applicable if the data
// is 16-bit.  All variables of this type will have the prefix "endian".
enum AudioEndian {
	BIG_ENDIAN = 0,	// Sun and network byte order
	LITTLE_ENDIAN = 1,  // Intel byte order
	SWITCH_ENDIAN = 2,  // Flag to switch to the opposite endian, used
			    // by coerceEndian().
	UNDEFINED_ENDIAN = -1
};

// Define a public data header structure.
// Clients must be able to modify multiple fields inbetween validity checking.
class AudioHdr {
public:
	unsigned int	sample_rate;		// samples per second
	unsigned int	samples_per_unit;	// samples per unit
	unsigned int	bytes_per_unit;		// bytes per sample unit
	unsigned int	channels;		// # of interleaved channels
	AudioEncoding	encoding;		// data encoding format
	AudioEndian	endian;			// byte order

	AudioHdr():					// Constructor
	    sample_rate(0), samples_per_unit(0), bytes_per_unit(0),
	    channels(0), encoding(NONE)
	    {
		// The default for files is BIG, but this is
		// set in the AudioUnixfile class.
		endian = localByteOrder();
	    }

	AudioHdr(Audio_hdr hdr):		// Constructor from C struct
	    sample_rate(hdr.sample_rate),
	    samples_per_unit(hdr.samples_per_unit),
	    bytes_per_unit(hdr.bytes_per_unit),
	    channels(hdr.channels),
	    encoding((AudioEncoding)hdr.encoding)
	    {
		// The default for files is BIG, but this is
		// set in the AudioUnixfile class.
		endian = localByteOrder();
	    }

	// Determines the local byte order, otherwise know as the endian
	// nature of the current machine.
	AudioEndian localByteOrder() const;

	virtual void Clear();				// Init header
	virtual AudioError Validate() const;		// Check hdr validity

	// Conversion between time (in seconds) and byte offsets
	virtual Double Bytes_to_Time(off_t cnt) const;
	virtual off_t Time_to_Bytes(Double sec) const;

	// Round down a byte count to a sample frame boundary
	virtual off_t Bytes_to_Bytes(off_t& cnt) const;
	virtual size_t Bytes_to_Bytes(size_t& cnt) const;

	// Conversion between time (in seconds) and sample frames
	virtual Double Samples_to_Time(unsigned long cnt) const;
	virtual unsigned long Time_to_Samples(Double sec) const;

	// Return the number of bytes in a sample frame for the audio encoding.
	virtual unsigned int FrameLength() const;

	// Return some meaningful strings.  The returned char pointers
	// must be deleted when the caller is through with them.
	virtual char *RateString() const;	// eg "44.1kHz"
	virtual char *ChannelString() const;	// eg "stereo"
	virtual char *EncodingString() const;	// eg "3-bit G.723"
	virtual char *FormatString() const;	// eg "4-bit G.721, 8 kHz, mono"

	// Parse strings and set corresponding header fields.
	virtual AudioError RateParse(char *);
	virtual AudioError ChannelParse(char *);
	virtual AudioError EncodingParse(char *);
	virtual AudioError FormatParse(char *);

	// for casting to C Audio_hdr struct
	operator Audio_hdr() {
		Audio_hdr hdr;

		hdr.sample_rate = sample_rate;
		hdr.samples_per_unit = samples_per_unit;
		hdr.bytes_per_unit = bytes_per_unit;
		hdr.channels = channels;
		hdr.encoding = encoding;
		hdr.endian = endian;
		return (hdr);
	};

	// compare two AudioHdr objects
	int operator == (const AudioHdr& tst)
	{
		return ((sample_rate == tst.sample_rate) &&
		    (samples_per_unit == tst.samples_per_unit) &&
		    (bytes_per_unit == tst.bytes_per_unit) &&
		    (channels == tst.channels) &&
// Audioconvert uses this method to see if a conversion should take
// place, but doesn't know how to convert between endian formats.
// This makes it ignore endian differences.
//		    (endian = tst.endian) &&
		    (encoding == tst.encoding));
	}
	int operator != (const AudioHdr& tst)
	{
		return (! (*this == tst));
	}
};

#ifdef NO_EXTERN_C

#ifdef __cplusplus
}
#endif

#endif /* NO_EXTERN_C */

#endif /* !_MULTIMEDIA_AUDIOHDR_H */
