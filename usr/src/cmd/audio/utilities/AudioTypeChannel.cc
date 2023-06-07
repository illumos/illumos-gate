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

#include <stdlib.h>
#include <memory.h>
#include <math.h>

#include <AudioTypeChannel.h>

// This is a conversion class for channel conversions
// It handles mono->multi-channel and multi-channel->mono (mixing)

// class AudioTypeChannel methods

// Constructor
AudioTypeChannel::
AudioTypeChannel()
{
}

// Destructor
AudioTypeChannel::
~AudioTypeChannel()
{
}

// Test conversion possibilities.
// Return TRUE if conversion to/from the specified type is possible.
Boolean AudioTypeChannel::
CanConvert(
	AudioHdr	/* h */) const		// target header
{
	// XXX - This is misleading.  Multi-channel->mono conversions
	//	 must be linear format, but mono->multi-channel is
	//	 ok in any format.
	return (TRUE);
}

// Convert buffer to the specified type
// May replace the buffer with a new one, if necessary
AudioError AudioTypeChannel::
Convert(
	AudioBuffer*&	inbuf,			// data buffer to process
	AudioHdr	outhdr)			// target header
{
	AudioBuffer*	outbuf;
	AudioHdr	inhdr;
	AudioHdr	newhdr;
	Double		length;
	size_t		nsamps;
	size_t		nbytes;
	int		i;
	int		j;
	int		k;
	int		chans;
	char		*cin;
	char		*cout;
	short		*sin;
	short		*sout;
	AudioError	err;
	long		smix;

	inhdr = inbuf->GetHeader();
	length = inbuf->GetLength();

	// Make sure we're not being asked to do the impossible or trivial
	if ((err = inhdr.Validate()))
		return (err);
	if ((inhdr.sample_rate != outhdr.sample_rate) ||
	    (inhdr.encoding != outhdr.encoding) ||
	    (inhdr.samples_per_unit != outhdr.samples_per_unit) ||
	    (inhdr.bytes_per_unit != outhdr.bytes_per_unit))
		return (AUDIO_ERR_HDRINVAL);
	if (inhdr.channels == outhdr.channels)
		return (AUDIO_SUCCESS);
	if ((inhdr.channels != 1) && (outhdr.channels != 1))
		return (AUDIO_ERR_HDRINVAL);
	if (Undefined(length))
		return (AUDIO_ERR_BADARG);

	// setup header for output buffer
	newhdr = inhdr;
	newhdr.channels = outhdr.channels;

	// XXX - If multi-channel -> mono, must be linear to mix
	// We need to test for this before trying the conversion!
	if ((inhdr.channels > 1) && (newhdr.channels == 1)) {
		if ((inhdr.encoding != LINEAR) ||
		    (inhdr.bytes_per_unit > 2))
			return (AUDIO_ERR_HDRINVAL);
	}

	// Allocate a new buffer
	outbuf = new AudioBuffer(length, "(Channel conversion buffer)");
	if (outbuf == 0)
		return (AUDIO_UNIXERROR);
	err = outbuf->SetHeader(newhdr);
	if (err != AUDIO_SUCCESS) {
		delete outbuf;
		return (err);
	}

	// Get the number of sample frames and the size of each
	nsamps = (size_t)inhdr.Time_to_Samples(length);
	nbytes = (size_t)inhdr.FrameLength();
	chans = inhdr.channels;

	// multi-channel -> mono conversion
	if ((chans > 1) && (newhdr.channels == 1)) {
		switch (inhdr.bytes_per_unit) {
		case 1:
			cin = (char *)inbuf->GetAddress();
			cout = (char *)outbuf->GetAddress();

			for (i = 0; i < nsamps; i++) {
				smix = 0;
				for (j = 0; j < chans; j++) {
					smix += *cin++;
				}
				if (smix < -0x7f) {
					smix = -0x7f;
				} else if (smix > 0x7f) {
					smix = 0x7f;
				}
				*cout++ = (char)smix;
			}
			break;
		case 2:
			sin = (short *)inbuf->GetAddress();
			sout = (short *)outbuf->GetAddress();

			for (i = 0; i < nsamps; i++) {
				smix = 0;
				for (j = 0; j < chans; j++) {
					smix += *sin++;
				}
				if (smix < -0x7fff) {
					smix = -0x7fff;
				} else if (smix > 0x7fff) {
					smix = 0x7fff;
				}
				*sout++ = (short)smix;
			}
			break;
		default:
			err = AUDIO_ERR_HDRINVAL;
		}

	} else if ((chans == 1) && (newhdr.channels > 1)) {
		// mono -> multi-channel
		chans = newhdr.channels;
		cin = (char *)inbuf->GetAddress();
		cout = (char *)outbuf->GetAddress();

		// XXX - this could be optimized by special-casing stuff
		for (i = 0; i < nsamps; i++) {
			for (j = 0; j < chans; j++) {
				for (k = 0; k < nbytes; k++)
					*cout++ = cin[k];
			}
			cin += nbytes;
		}
	}

	if (err) {
		if (outbuf != inbuf)
			delete outbuf;
		return (err);
	}

	// This will delete the buffer
	inbuf->Reference();
	inbuf->Dereference();

	// Set the valid data length
	outbuf->SetLength(length);
	inbuf = outbuf;
	return (AUDIO_SUCCESS);
}

AudioError AudioTypeChannel::
Flush(
	AudioBuffer*&	/* buf */)
{
	return (AUDIO_SUCCESS);
}
