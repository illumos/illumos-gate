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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/param.h>
#include <Audio.h>
#include <AudioFile.h>
#include <AudioPipe.h>
#include <AudioRawPipe.h>
#include <AudioLib.h>
#include <AudioTypePcm.h>
#include <AudioTypeG72X.h>
#include <AudioTypeChannel.h>
#include <AudioTypeMux.h>
#include <AudioTypeSampleRate.h>

#include <convert.h>


// Maximum sizes of buffer to convert, in seconds and bytes
#define	CVTMAXTIME	((double)5.0)
#define	CVTMAXBUF	(64 * 1024)

// maintain a list of conversions
struct conv_list {
	struct conv_list	*next;	// next conversion in chain
	unsigned		bufcnt;	// number of buffers to process
	AudioTypeConvert*	conv;	// conversion class
	AudioHdr		hdr;	// what to convert to
	char			*desc;	// describe conversion (for errs)
};


// check if this is a valid conversion. return -1 if not, 0 if OK.
int
verify_conversion(
	AudioHdr	ihdr,
	AudioHdr	ohdr)
{
	char		*enc1;
	char		*enc2;

	if (((ihdr.encoding != ULAW) &&
	    (ihdr.encoding != ALAW) &&
	    (ihdr.encoding != LINEAR) &&
	    (ihdr.encoding != FLOAT) &&
	    (ihdr.encoding != G721) &&
	    (ihdr.encoding != G723)) ||
	    ((ohdr.encoding != ULAW) &&
	    (ohdr.encoding != ALAW) &&
	    (ohdr.encoding != LINEAR) &&
	    (ohdr.encoding != FLOAT) &&
	    (ohdr.encoding != G721) &&
	    (ohdr.encoding != G723))) {
		enc1 = ihdr.EncodingString();
		enc2 = ohdr.EncodingString();
		Err(MGET("can't convert from %s to %s\n"), enc1, enc2);
		delete enc1;
		delete enc2;
		return (-1);
	}
	return (0);
}

// check if this conversion is a no-op
int
noop_conversion(
	AudioHdr	ihdr,
	AudioHdr	ohdr,
	format_type	i_fmt,
	format_type	o_fmt,
	off_t		i_offset,
	off_t		/* o_offset */)
{
	if ((ihdr == ohdr) &&
	    (i_fmt == o_fmt) &&
	    (i_offset == 0)) {
		return (1);
	}
	return (0);
}


// Conversion list maintenance routines

// Return a pointer to the last conversion entry in the list
struct conv_list
*get_last_conv(
	struct conv_list	*list)
{
	struct conv_list	*lp;

	for (lp = list; lp != NULL; lp = lp->next) {
		if (lp->next == NULL)
			break;
	}
	return (lp);
}

// Release the conversion list
void
free_conv_list(
	struct conv_list	*&list)
{
	unsigned int		i;
	unsigned int		bufs;
	struct conv_list	*tlp;
	AudioTypeConvert*	conv;

	while (list != NULL) {
		bufs = list->bufcnt;
		conv = list->conv;
		for (i = 0; i < bufs; i++) {
			// Delete the conversion string
			if (list[i].desc != NULL)
				free(list[i].desc);

			// Delete the conversion class if unique
			if ((list[i].conv != NULL) &&
			    ((i == 0) || (list[i].conv != conv)))
				delete(list[i].conv);
		}
		tlp = list->next;
		free((char *)list);
		list = tlp;
	}
}

// Append a new entry on the end of the conversion list
void
append_conv_list(
	struct conv_list	*&list,	// list to modify
	AudioHdr		tohdr,	// target format
	unsigned int		bufs,	// number of buffers involved
	AudioTypeConvert*	conv,	// NULL, if multiple buffers
	char			*desc)	// string describing the transform
{
	unsigned int		i;
	struct conv_list	*lp;
	struct conv_list	*nlp;
	Boolean			B;

	nlp = new struct conv_list[bufs];
	if (nlp == NULL) {
		Err(MGET("out of memory\n"));
		exit(1);
	}
	B = tohdr.Validate();
	// Initialize a conversion entry for each expected buffer
	for (i = 0; i < bufs; i++) {
		nlp[i].next = NULL;
		nlp[i].hdr = tohdr;
		B = nlp[i].hdr.Validate();
		nlp[i].bufcnt = bufs;
		nlp[i].conv = conv;
		if (desc && *desc) {
			nlp[i].desc = strdup(desc);
		} else {
			nlp[i].desc = NULL;
		}
	}

	// Link in the new entry
	if (list == NULL) {
		list = nlp;
	} else {
		lp = get_last_conv(list);
		lp->next = nlp;
	}
}


// Routines to establish specific conversions.
// These routines append the proper conversion to the list, and update
// the audio header structure to reflect the resulting data format.

// Multiplex/Demultiplex interleaved data
// If the data is multi-channel, demultiplex into multiple buffer streams.
// If there are multiple buffers, multiplex back into one interleaved stream.
AudioError
add_mux_convert(
	struct conv_list	*&list,
	AudioHdr&		ihdr,
	unsigned int&		bufs)
{
	AudioTypeConvert*	conv;
	unsigned int		n;
	char			*msg;

	conv = new AudioTypeMux;

	// Verify conversion
	if (!conv->CanConvert(ihdr)) {
error:		delete conv;
		return (AUDIO_ERR_FORMATLOCK);
	}

	if (bufs == 1) {
		// Demultiplex multi-channel data
		n = ihdr.channels;	// save the target number of buffers
		ihdr.channels = 1;	// each output buffer will be mono
		msg = MGET("Split multi-channel data");
	} else {
		// Multiplex multiple buffers
		ihdr.channels = bufs;	// set the target interleave
		n = 1;
		bufs = 1;		// just one conversion necessary
		msg = MGET("Interleave multi-channel data");
	}
	if (!conv->CanConvert(ihdr))
		goto error;

	append_conv_list(list, ihdr, bufs, conv, msg);
	bufs = n;
	return (AUDIO_SUCCESS);
}

// Convert to PCM (linear, ulaw, alaw)
AudioError
add_pcm_convert(
	struct conv_list	*&list,
	AudioHdr&		ihdr,
	AudioEncoding		tofmt,
	unsigned int		unitsz,
	unsigned int&		bufs)
{
	AudioTypeConvert*	conv;
	char			msg[BUFSIZ];
	char			*infmt;
	char			*outfmt;
	AudioError		err;

	conv = new AudioTypePcm;

	// Verify conversion
	if (!conv->CanConvert(ihdr)) {
error:		delete conv;
		return (AUDIO_ERR_FORMATLOCK);
	}

	// Set up conversion, get encoding strings
	infmt = ihdr.EncodingString();
	ihdr.encoding = tofmt;
	ihdr.bytes_per_unit = unitsz;
	ihdr.samples_per_unit = 1;
	if (!conv->CanConvert(ihdr))
		goto error;
	outfmt = ihdr.EncodingString();

	sprintf(msg, MGET("Convert %s to %s"), infmt, outfmt);
	delete infmt;
	delete outfmt;

	append_conv_list(list, ihdr, bufs, conv, msg);
	return (AUDIO_SUCCESS);
}

// Convert multi-channel data to mono, or vice versa
AudioError
add_channel_convert(
	struct conv_list	*&list,
	AudioHdr&		ihdr,
	unsigned int		tochans,
	unsigned int&		bufs)
{
	AudioTypeConvert*	conv;
	char			msg[BUFSIZ];
	char			*inchans;
	char			*outchans;
	AudioError		err;

	// Make sure we're converting to/from mono with an interleaved buffer
	if (((ihdr.channels != 1) && (tochans != 1)) || (bufs != 1))
		return (AUDIO_ERR_FORMATLOCK);

	conv = new AudioTypeChannel;

	// Verify conversion; if no good, try converting to 16-bit pcm first
	if (!conv->CanConvert(ihdr) || (ihdr.channels != 1)) {
		if (err = add_pcm_convert(list, ihdr, LINEAR, 2, bufs)) {
			delete conv;
			return (err);
		}
		if (!conv->CanConvert(ihdr)) {
error:			delete conv;
			return (AUDIO_ERR_FORMATLOCK);
		}
	}

	// Set up conversion, get channel strings
	inchans = ihdr.ChannelString();
	ihdr.channels = tochans;
	if (!conv->CanConvert(ihdr))
		goto error;
	outchans = ihdr.ChannelString();

	sprintf(msg, MGET("Convert %s to %s"), inchans, outchans);
	delete inchans;
	delete outchans;

	append_conv_list(list, ihdr, bufs, conv, msg);
	return (AUDIO_SUCCESS);
}

// Compress data
AudioError
add_compress(
	struct conv_list	*&list,
	AudioHdr&		ihdr,
	AudioEncoding		tofmt,
	unsigned int		unitsz,
	unsigned int&		bufs)
{
	AudioTypeConvert*	conv;
	char			msg[BUFSIZ];
	char			*infmt;
	char			*outfmt;
	struct conv_list	*lp;
	int			i;
	AudioError		err;

	// Make sure we're converting something we understand
	if ((tofmt != G721) && (tofmt != G723))
		return (AUDIO_ERR_FORMATLOCK);

	conv = new AudioTypeG72X;

	// Verify conversion; if no good, try converting to 16-bit pcm first
	if (!conv->CanConvert(ihdr)) {
		if (err = add_pcm_convert(list, ihdr, LINEAR, 2, bufs)) {
			delete conv;
			return (err);
		}
		if (!conv->CanConvert(ihdr)) {
error:			delete conv;
			return (AUDIO_ERR_FORMATLOCK);
		}
	}

	// Set up conversion, get encoding strings
	infmt = ihdr.EncodingString();
	ihdr.encoding = tofmt;
	switch (tofmt) {
	case G721:
		ihdr.bytes_per_unit = unitsz;
		ihdr.samples_per_unit = 2;
		break;
	case G723:
		ihdr.bytes_per_unit = unitsz;
		ihdr.samples_per_unit = 8;
		break;
	}
	if (!conv->CanConvert(ihdr))
		goto error;
	outfmt = ihdr.EncodingString();

	sprintf(msg, MGET("Convert %s to %s"), infmt, outfmt);
	delete infmt;
	delete outfmt;

	append_conv_list(list, ihdr, bufs, NULL, msg);

	// Need a separate converter instantiation for each channel
	lp = get_last_conv(list);
	for (i = 0; i < bufs; i++) {
		if (i == 0)
			lp[i].conv = conv;
		else
			lp[i].conv = new AudioTypeG72X;
	}
	return (AUDIO_SUCCESS);
}

// Decompress data
AudioError
add_decompress(
	struct conv_list	*&list,
	AudioHdr&		ihdr,
	AudioEncoding		tofmt,
	unsigned int		unitsz,
	unsigned int&		bufs)
{
	AudioTypeConvert*	conv;
	char			msg[BUFSIZ];
	char			*infmt;
	char			*outfmt;
	struct conv_list	*lp;
	int			i;
	AudioError		err;

	// Make sure we're converting something we understand
	if ((ihdr.encoding != G721) && (ihdr.encoding != G723))
		return (AUDIO_ERR_FORMATLOCK);

	conv = new AudioTypeG72X;

	// Verify conversion
	if (!conv->CanConvert(ihdr)) {
error:		delete conv;
		return (AUDIO_ERR_FORMATLOCK);
	}

	// Set up conversion, get encoding strings
	infmt = ihdr.EncodingString();
	ihdr.encoding = tofmt;
	ihdr.bytes_per_unit = unitsz;
	ihdr.samples_per_unit = 1;
	if (!conv->CanConvert(ihdr)) {
		// Try converting to 16-bit linear
		ihdr.encoding = LINEAR;
		ihdr.bytes_per_unit = 2;
		if (!conv->CanConvert(ihdr))
			goto error;
	}
	outfmt = ihdr.EncodingString();

	sprintf(msg, MGET("Convert %s to %s"), infmt, outfmt);
	delete infmt;
	delete outfmt;

	append_conv_list(list, ihdr, bufs, NULL, msg);

	// Need a separate converter instantiation for each channel
	lp = get_last_conv(list);
	for (i = 0; i < bufs; i++) {
		if (i == 0)
			lp[i].conv = conv;
		else
			lp[i].conv = new AudioTypeG72X;
	}
	return (AUDIO_SUCCESS);
}

// Sample rate conversion
AudioError
add_rate_convert(
	struct conv_list	*&list,
	AudioHdr&		ihdr,
	unsigned int		torate,
	unsigned int&		bufs)
{
	AudioTypeConvert*	conv;
	unsigned int		fromrate;
	char			msg[BUFSIZ];
	char			*inrate;
	char			*outrate;
	struct conv_list	*lp;
	int			i;
	AudioError		err;

	fromrate = ihdr.sample_rate;
	conv = new AudioTypeSampleRate(fromrate, torate);

	// Verify conversion; if no good, try converting to 16-bit pcm first
	if (!conv->CanConvert(ihdr)) {
		if (err = add_pcm_convert(list, ihdr, LINEAR, 2, bufs)) {
			delete conv;
			return (err);
		}
		if (!conv->CanConvert(ihdr)) {
error:			delete conv;
			return (AUDIO_ERR_FORMATLOCK);
		}
	}

	// Set up conversion, get encoding strings
	inrate = ihdr.RateString();
	ihdr.sample_rate = torate;
	if (!conv->CanConvert(ihdr))
		goto error;
	outrate = ihdr.RateString();

	sprintf(msg, MGET("Convert %s to %s"), inrate, outrate);
	delete inrate;
	delete outrate;

	append_conv_list(list, ihdr, bufs, NULL, msg);

	// Need a separate converter instantiation for each channel
	lp = get_last_conv(list);
	for (i = 0; i < bufs; i++) {
		if (i == 0)
			lp[i].conv = conv;
		else
			lp[i].conv = new AudioTypeSampleRate(fromrate, torate);
	}
	return (AUDIO_SUCCESS);
}

// Returns TRUE if the specified header has a pcm type encoding
Boolean
pcmtype(
	AudioHdr&	hdr)
{
	if (hdr.samples_per_unit != 1)
		return (FALSE);
	switch (hdr.encoding) {
	case LINEAR:
	case FLOAT:
	case ULAW:
	case ALAW:
		return (TRUE);
	}
	return (FALSE);
}

#define	IS_PCM(ihp)		(pcmtype(ihp))
#define	IS_MONO(ihp)		(ihp.channels == 1)
#define	RATE_CONV(ihp, ohp)	(ihp.sample_rate != ohp.sample_rate)
#define	ENC_CONV(ihp, ohp)	((ihp.encoding != ohp.encoding) ||	\
				    (ihp.samples_per_unit !=		\
				    ohp.samples_per_unit) ||		\
				    (ihp.bytes_per_unit != ohp.bytes_per_unit))
#define	CHAN_CONV(ihp, ohp)	(ihp.channels != ohp.channels)


// Build the conversion list to get from input to output format
AudioError
build_conversion_list(
	struct conv_list	*&list,
	AudioStream*		ifp,
	AudioStream*		ofp)
{
	AudioHdr		ihdr;
	AudioHdr		ohdr;
	unsigned int		bufs;
	AudioError		err;

	ihdr = ifp->GetHeader();
	ohdr = ofp->GetHeader();
	bufs = 1;

	// Each pass, add another conversion, until there's no more to do
	while (((ihdr != ohdr) || (bufs != 1)) && !err) {

		// First off, if the target is mono, convert the source to mono
		// before doing harder stuff, like sample rate conversion.
		if (IS_MONO(ohdr)) {
			if (!IS_MONO(ihdr)) {
				if (IS_PCM(ihdr)) {
					// If multi-channel pcm,
					// mix the channels down to one
					err = add_channel_convert(list,
					    ihdr, 1, bufs);
				} else {
					// If not pcm, demultiplex in order
					// to decompress
					err = add_mux_convert(list, ihdr, bufs);
				}
				continue;
			} else if (bufs != 1) {
				// Multi-channel data was demultiplexed
				if (IS_PCM(ihdr)) {
					// If multi-channel pcm, recombine them
					// for mixing down to one
					err = add_mux_convert(list, ihdr, bufs);
				} else {
					// If not pcm, decompress it
					err = add_decompress(list, ihdr,
					    ohdr.encoding, ohdr.bytes_per_unit,
					    bufs);
				}
				continue;
			}
			// At this point, input and output are both mono

		} else if (ihdr.channels != 1) {
			// Here if input and output are both multi-channel.
			// If sample rate conversion or compression,
			// split into multiple streams
			if (RATE_CONV(ihdr, ohdr) ||
			    (ENC_CONV(ihdr, ohdr) &&
			    (!IS_PCM(ihdr) || !IS_PCM(ohdr)))) {
				err = add_mux_convert(list, ihdr, bufs);
				continue;
			}
		}

		// Input is either mono, split into multiple buffers, or
		// this is a conversion that can be handled multi-channel.
		if (RATE_CONV(ihdr, ohdr)) {
			// Decompress before sample-rate conversion
			if (!IS_PCM(ihdr)) {
				err = add_decompress(list, ihdr,
				    ohdr.encoding, ohdr.bytes_per_unit,
				    bufs);
			} else {
				err = add_rate_convert(list, ihdr,
				    ohdr.sample_rate, bufs);
			}
			continue;
		}

		if (ENC_CONV(ihdr, ohdr)) {
			// Encoding is changing:
			if (!IS_PCM(ihdr)) {
				// if we start compressed, decompress
				err = add_decompress(list, ihdr,
				    ohdr.encoding, ohdr.bytes_per_unit,
				    bufs);
			} else if (IS_PCM(ohdr)) {
				// we should be able to convert to PCM now
				err = add_pcm_convert(list, ihdr,
				    ohdr.encoding, ohdr.bytes_per_unit,
				    bufs);
			} else {
				// we should be able to compress now
				err = add_compress(list, ihdr,
				    ohdr.encoding, ohdr.bytes_per_unit,
				    bufs);
			}
			continue;
		}

		// The sample rate and encoding match.
		// All that's left to do is get the channels right
		if (bufs > 1) {
			// Combine channels back into an interleaved stream
			err = add_mux_convert(list, ihdr, bufs);
			continue;
		}
		if (!IS_MONO(ohdr)) {
			// If multi-channel output, try to accomodate
			err = add_channel_convert(list,
			    ihdr, ohdr.channels, bufs);
			continue;
		}

		// Everything should be done at this point.
		// XXX - this should never be reached
		return (AUDIO_ERR_FORMATLOCK);
	}
	return (err);
}

// Set up the conversion list and execute it
int
do_convert(
	AudioStream*	ifp,
	AudioStream*	ofp)
{
	struct conv_list *list = NULL;
	struct conv_list *lp;
	AudioBuffer* 	obuf;
	AudioBuffer** 	multibuf;
	AudioError	err;
	AudioHdr	ihdr;
	AudioHdr	ohdr;
	Double		pos = 0.0;
	size_t		len;
	unsigned int	i;
	Double		cvtlen;
	char		*msg1;
	char		*msg2;

	ihdr = ifp->GetHeader();
	ohdr = ofp->GetHeader();

	// create conversion list
	if ((err = build_conversion_list(list, ifp, ofp)) != AUDIO_SUCCESS) {
		free_conv_list(list);
		msg1 = ohdr.FormatString();
		Err(MGET("Cannot convert %s to %s\n"), ifp->GetName(), msg1);
		delete msg1;
		return (-1);
	}

	// Print warnings for exceptional conditions
	if ((ohdr.sample_rate < 8000) || (ohdr.sample_rate > 48000)) {
		msg1 = ohdr.RateString();
		Err(MGET("Warning: converting %s to %s\n"),
		    ifp->GetName(), msg1);
		delete msg1;
	}
	if (ohdr.channels > 2) {
		msg1 = ohdr.ChannelString();
		Err(MGET("Warning: converting %s to %s\n"),
		    ifp->GetName(), msg1);
		delete msg1;
	}

	if (Debug) {
		msg1 = ihdr.FormatString();
		msg2 = ohdr.FormatString();
		Err(MGET("Converting %s:\n\t\tfrom: %s\n\t\tto: %s\n"),
		    ifp->GetName(), msg1, msg2);
		delete msg1;
		delete msg2;

		// Print each entry in the conversion list
		for (lp = list; lp; lp = lp->next) {
			(void) fprintf(stderr, MGET("\t%s  %s\n"), lp->desc,
			    (lp->bufcnt == 1) ? "" : MGET("(multi-channel)"));
		}
	}

	// Calculate buffer size, obeying maximums
	cvtlen = ihdr.Bytes_to_Time(CVTMAXBUF);
	if (cvtlen > CVTMAXTIME)
		cvtlen = CVTMAXTIME;
	if (cvtlen > ohdr.Bytes_to_Time(CVTMAXBUF * 4))
		cvtlen = ohdr.Bytes_to_Time(CVTMAXBUF * 4);

	// create output buf
	if (!(obuf = new AudioBuffer(cvtlen, MGET("Audio Convert Buffer")))) {
		Err(MGET("Can't create conversion buffer\n"));
		exit(1);
	}

	while (1) {
		// Reset length
		len = (size_t)ihdr.Time_to_Bytes(cvtlen);
		if ((err = obuf->SetHeader(ihdr)) != AUDIO_SUCCESS) {
			Err(MGET("Can't set buffer header: %s\n"), err.msg());
			return (-1);
		}
		// If growing buffer, free the old one rather than copy data
		if (obuf->GetSize() < cvtlen)
			obuf->SetSize(0.);
		obuf->SetSize(cvtlen);

		// Read a chunk of input and set the real length of buffer
		// XXX - Use Copy() method??  Check for errors?
		if (err = ifp->ReadData(obuf->GetAddress(), len, pos))
			break;
		obuf->SetLength(ihdr.Bytes_to_Time(len));

		// Process each entry in the conversion list
		for (lp = list; lp; lp = lp->next) {
			if (lp->conv) {
				// If multiple buffers, make multiple calls
				if (lp->bufcnt == 1) {
					err = lp->conv->Convert(obuf, lp->hdr);
				} else {
					multibuf = (AudioBuffer**)obuf;
					for (i = 0; i < lp->bufcnt; i++) {
						err = lp[i].conv->Convert(
						    multibuf[i], lp[i].hdr);
						if (err)
							break;
					}
				}
				if (err) {
					Err(MGET(
					    "Conversion failed: %s (%s)\n"),
					    lp->desc ? lp->desc : MGET("???"),
					    err.msg());
					return (-1);
				}
			}
		}

		if ((err = write_output(obuf, ofp)) != AUDIO_SUCCESS) {
			Err(MGET("Error writing to output file %s (%s)\n"),
			    ofp->GetName(), err.msg());
			return (-1);
		}
	}

	// Now flush any left overs from conversions w/state
	obuf->SetLength(0.0);
	for (lp = list; lp; lp = lp->next) {
		if (lp->conv) {
			// First check if there's any residual to convert.
			// If not, just set the header to this type.
			// If multiple buffers, make multiple calls
			if (lp->bufcnt == 1) {
				err = lp->conv->Convert(obuf, lp->hdr);
				if (!err)
					err = lp->conv->Flush(obuf);
			} else {
				multibuf = (AudioBuffer**)obuf;
				for (i = 0; i < lp->bufcnt; i++) {
					err = lp[i].conv->Convert(
					    multibuf[i], lp[i].hdr);
					if (!err) {
						err = lp[i].conv->Flush(
						    multibuf[i]);
					}
					if (err)
						break;
				}
			}
			if (err) {
				Err(MGET(
				    "Warning: Flush of final bytes failed: "
				    "%s (%s)\n"),
				    lp->desc ? lp->desc : MGET("???"),
				    err.msg());

				/* return (-1); ignore errors for now */
				break;
			}
		}
	}

	if (obuf->GetLength() > 0.0) {
		if ((err = write_output(obuf, ofp)) != AUDIO_SUCCESS) {
			Err(MGET("Warning: Final write to %s failed (%s)\n"),
			    ofp->GetName(), err.msg());
			/* return (-1); ignore errors for now */
		}
	}

	delete obuf;
	free_conv_list(list);
	return (0);
}
