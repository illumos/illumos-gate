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
#include <math.h>

#include <AudioTypeG72X.h>

// class AudioTypeG72X methods
// G.721 & G.723 compress/decompress

// Constructor
AudioTypeG72X::
AudioTypeG72X()
{
	initialized = FALSE;
}

// Destructor
AudioTypeG72X::
~AudioTypeG72X()
{
}

// Test conversion possibilities.
// Return TRUE if conversion to/from the specified type is possible.
Boolean AudioTypeG72X::
CanConvert(
	AudioHdr	h) const		// target header
{
	// g72x conversion code handles mono 16-bit pcm, ulaw, alaw
	if (h.channels != 1)
		return (FALSE);

	switch (h.encoding) {
	case LINEAR:
		if ((h.samples_per_unit != 1) ||
		    (h.bytes_per_unit != 2))
			return (FALSE);
		break;
	case ALAW:
	case ULAW:
		if ((h.samples_per_unit != 1) ||
		    (h.bytes_per_unit != 1))
			return (FALSE);
		break;
	case G721:
		if ((h.samples_per_unit != 2) ||
		    (h.bytes_per_unit != 1))
			return (FALSE);
		break;
	case G723:
		if (h.samples_per_unit != 8)
			return (FALSE);

		// XXX - 5-bit G.722 not supported yet
		if (h.bytes_per_unit != 3)
			return (FALSE);
		break;
	case FLOAT:
	default:
		return (FALSE);
	}
	return (TRUE);
}

// Convert buffer to the specified type
// May replace the buffer with a new one, if necessary
AudioError AudioTypeG72X::
Convert(
	AudioBuffer*&	inbuf,			// data buffer to process
	AudioHdr	outhdr)			// target header
{
	AudioBuffer*	outbuf;
	AudioHdr	inhdr;
	Audio_hdr	chdr;	// C struct for g72x convert code
	Double		length;
	Double		pad;
	size_t		nbytes;
	int		cnt;
	unsigned char	*inptr;
	unsigned char	*outptr;
	AudioError	err;

	inhdr = inbuf->GetHeader();
	length = inbuf->GetLength();

	if (Undefined(length)) {
		return (AUDIO_ERR_BADARG);
	}

	// Make sure we're not being asked to do the impossible
	if ((err = inhdr.Validate()) || (err = outhdr.Validate())) {
		return (err);
	}

	if (!CanConvert(inhdr) || !CanConvert(outhdr) ||
	    (inhdr.sample_rate != outhdr.sample_rate) ||
	    (inhdr.channels != outhdr.channels))
		return (AUDIO_ERR_HDRINVAL);

	// if conversion is a no-op, just return success
	if ((inhdr.encoding == outhdr.encoding) &&
	    (inhdr.bytes_per_unit == outhdr.bytes_per_unit)) {
		return (AUDIO_SUCCESS);
	}

	// Add some padding to the output buffer
	pad = outhdr.Samples_to_Time(
	    4 * outhdr.bytes_per_unit * outhdr.channels);

	// Allocate a new buffer
	outbuf = new AudioBuffer(length + pad, "(G72x conversion buffer)");
	if (outbuf == 0)
		return (AUDIO_UNIXERROR);
	err = outbuf->SetHeader(outhdr);
	if (err != AUDIO_SUCCESS) {
		delete outbuf;
		return (err);
	}

	// Convert from the input type to the output type
	inptr = (unsigned char *)inbuf->GetAddress();
	outptr = (unsigned char *)outbuf->GetAddress();
	nbytes = (size_t)inhdr.Time_to_Bytes(length);
	if (nbytes == 0)
		goto cleanup;

	switch (inhdr.encoding) {
	case ALAW:
	case ULAW:
	case LINEAR:
		switch (outhdr.encoding) {
		case G721:
			chdr = (Audio_hdr)inhdr;
			if (!initialized) {
				g721_init_state(&g72x_state);
				initialized = TRUE;
			}
			err = g721_encode((void*)inptr, nbytes, &chdr,
			    outptr, &cnt, &g72x_state);
			length = outhdr.Bytes_to_Time(cnt);
			break;
		case G723:
			chdr = (Audio_hdr)inhdr;
			if (!initialized) {
				g723_init_state(&g72x_state);
				initialized = TRUE;
			}
			err = g723_encode((void*)inptr, nbytes, &chdr,
			    outptr, &cnt, &g72x_state);
			length = outhdr.Bytes_to_Time(cnt);
			break;
		default:
			err = AUDIO_ERR_HDRINVAL; break;
		}
		break;
	case G721:
		switch (outhdr.encoding) {
		case ALAW:
		case ULAW:
		case LINEAR:
			chdr = (Audio_hdr)outhdr;
			if (!initialized) {
				g721_init_state(&g72x_state);
				initialized = TRUE;
			}
			err = g721_decode(inptr, nbytes, &chdr,
			    (void*)outptr, &cnt, &g72x_state);
			length = outhdr.Samples_to_Time(cnt);
			break;
		default:
			err = AUDIO_ERR_HDRINVAL; break;
		}
		break;
	case G723:
		switch (outhdr.encoding) {
		case ALAW:
		case ULAW:
		case LINEAR:
			chdr = (Audio_hdr)outhdr;
			if (!initialized) {
				g723_init_state(&g72x_state);
				initialized = TRUE;
			}
			err = g723_decode(inptr, nbytes, &chdr,
			    (void*)outptr, &cnt, &g72x_state);
			length = outhdr.Samples_to_Time(cnt);
			break;
		default:
			err = AUDIO_ERR_HDRINVAL; break;
		}
		break;
	default:
		err = AUDIO_ERR_HDRINVAL; break;
	}
	if (err) {
		if (outbuf != inbuf)
			delete outbuf;
		return (err);
	}
cleanup:
	// This will delete the buffer
	inbuf->Reference();
	inbuf->Dereference();

	// Set the valid data length
	outbuf->SetLength(length);
	inbuf = outbuf;

	return (AUDIO_SUCCESS);
}

// Flush out any leftover state, appending to supplied buffer
AudioError AudioTypeG72X::
Flush(
	AudioBuffer*&	outbuf)
{
	AudioHdr	h;
	Double		pos;
	size_t		cnt;
	AudioError	err;
	unsigned char	tmpbuf[32];

	if (!initialized)
		return (AUDIO_SUCCESS);
	initialized = FALSE;
	if (outbuf == NULL)
		return (AUDIO_SUCCESS);

	h = outbuf->GetHeader();

	switch (h.encoding) {
	case G721:
	case G723:
		switch (h.encoding) {
		case G721:
			err = g721_encode(NULL, 0, NULL,
			    tmpbuf, (int *)&cnt, &g72x_state);
			break;
		case G723:
			err = g723_encode(NULL, 0, NULL,
			    tmpbuf, (int *)&cnt, &g72x_state);
			break;
		}
		// Copy to the supplied buffer
		if (cnt > 0) {
			pos = outbuf->GetLength();
			err = outbuf->AppendData(tmpbuf, cnt, pos);
			if (err)
				return (err);
		}
		break;
	default:
		break;
	}
	return (AUDIO_SUCCESS);
}
