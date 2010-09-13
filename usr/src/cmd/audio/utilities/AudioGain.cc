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
#include <malloc.h>
#include <math.h>
#include <errno.h>
#include <memory.h>
#include <sys/param.h>
#include <sys/types.h>
#include <sys/ioctl.h>

#include <AudioGain.h>
#include <AudioTypePcm.h>

#define	irint(d)	((int)d)


// initialize constants for instananeous gain normalization
const double	AudioGain::LoSigInstantRange	= .008;
const double	AudioGain::HiSigInstantRange	= .48;

// initialize constants for weighted gain normalization
const double	AudioGain::NoSigWeight		= .0000;
const double	AudioGain::LoSigWeightRange	= .001;
const double	AudioGain::HiSigWeightRange	= .050;

// u-law max value converted to floating point
const double	AudioGain::PeakSig		= .9803765;

// XXX - patchable dc time constant:  TC = 1 / (sample rate / DCfreq)
int DCfreq = 500;
const double	AudioGain::DCtimeconstant	= .1;

// patchable debugging flag
int debug_agc = 0;


// Constructor
AudioGain::
AudioGain():
	clipcnt(0), DCaverage(0.), instant_gain(0.),
	weighted_peaksum(0.), weighted_sum(0.),
	weighted_avgsum(0.), weighted_cnt(0),
	gain_cache(NULL)
{
}

// Destructor
AudioGain::
~AudioGain()
{
	if (gain_cache != NULL) {
		delete gain_cache;
	}
}

// Return TRUE if we can handle this data type
Boolean AudioGain::
CanConvert(
	const AudioHdr&	hdr) const
{
	return (float_convert.CanConvert(hdr));
}

// Return latest instantaneous gain
double AudioGain::
InstantGain()
{
	return ((double)instant_gain);
}

// Return latest weighted gain
double AudioGain::
WeightedGain()
{
	double		g;

	// Accumulated sum is averaged by the cache size and number of sums
	if ((weighted_cnt > 0) && (gain_cache_size > 0.)) {
		g = weighted_avgsum / gain_cache_size;
		g /=  weighted_cnt;
		g -= NoSigWeight;
		if (g > HiSigWeightRange) {
			g = 1.;
		} else if (g < 0.) {
			g = 0.;
		} else {
			g /= HiSigWeightRange;
		}
	} else {
		g = 0.;
	}
	return (g);
}

// Return latest weighted peak
// Clears the weighted peak for next calculation.
double AudioGain::
WeightedPeak()
{
	double		g;

	// Peak sum is averaged by the cache size
	if (gain_cache_size > 0.) {
		g = weighted_peaksum / gain_cache_size;
		g -= NoSigWeight;
		if (g > HiSigWeightRange) {
			g = 1.;
		} else if (g < 0.) {
			g = 0.;
		} else {
			g /= HiSigWeightRange;
		}
	} else {
		g = 0.;
	}
	weighted_peaksum = 0.;
	return (g);
}

// Return TRUE if signal clipped during last processed buffer
Boolean AudioGain::
Clipped()
{
	Boolean		clipped;

	clipped = (clipcnt > 0);
	return (clipped);
}

// Flush gain state
void AudioGain::
Flush()
{
	clipcnt = 0;
	DCaverage = 0.;
	instant_gain = 0.;
	weighted_peaksum = 0.;
	weighted_sum = 0.;
	weighted_avgsum = 0.;
	weighted_cnt = 0;
	if (gain_cache != NULL) {
		delete gain_cache;
		gain_cache = NULL;
	}
}

// Process an input buffer according to the specified flags
// The input buffer is consumed if the reference count is zero!
AudioError AudioGain::
Process(
	AudioBuffer*	inbuf,
	int		type)
{
	AudioHdr	newhdr;
	AudioError	err;

	if (inbuf == NULL)
		return (AUDIO_ERR_BADARG);

	if (Undefined(inbuf->GetLength())) {
		err = AUDIO_ERR_BADARG;
process_error:
		// report error and toss the buffer if it is not referenced
		inbuf->RaiseError(err);
		inbuf->Reference();
		inbuf->Dereference();
		return (err);
	}

	// Set up to convert to floating point; verify all header formats
	newhdr = inbuf->GetHeader();
	if (!float_convert.CanConvert(newhdr)) {
		err = AUDIO_ERR_HDRINVAL;
		goto process_error;
	}
	newhdr.encoding = FLOAT;
	newhdr.bytes_per_unit = 8;
	if ((err = newhdr.Validate()) || !float_convert.CanConvert(newhdr)) {
		err = AUDIO_ERR_HDRINVAL;
		goto process_error;
	}

	// Convert to floating-point up front, if necessary
	if (inbuf->GetHeader() != newhdr) {
		err = float_convert.Convert(inbuf, newhdr);
		if (err)
			goto process_error;
	}

	// Reference the resulting buffer to make sure it gets ditched later
	inbuf->Reference();

	// run through highpass filter to reject DC
	process_dcfilter(inbuf);

	if (type & AUDIO_GAIN_INSTANT)
		process_instant(inbuf);

	if (type & AUDIO_GAIN_WEIGHTED)
		process_weighted(inbuf);

	inbuf->Dereference();
	return (AUDIO_SUCCESS);
}

// Run the buffer through a simple, dc filter.
// Buffer is assumed to be floating-point double PCM
void AudioGain::
process_dcfilter(
	AudioBuffer*	inbuf)
{
	int		i;
	Boolean		lastpeak;
	double		val;
	double		dcweight;
	double		timeconstant;
	AudioHdr	inhdr;
	double		*inptr;
	size_t		frames;

	inhdr = inbuf->GetHeader();
	inptr = (double *)inbuf->GetAddress();
	frames = (size_t)inhdr.Time_to_Samples(inbuf->GetLength());
	clipcnt = 0;
	lastpeak = FALSE;

	// Time constant corresponds to the number of samples for 500Hz
	timeconstant = 1. / (inhdr.sample_rate / (double)DCfreq);
	dcweight = 1. - timeconstant;

	// loop through the input buffer, rewriting with weighted data
	// XXX - should deal with multi-channel data!
	// XXX - for now, check first channel only
	for (i = 0; i < frames; i++, inptr += inhdr.channels) {
		val = *inptr;

		// Two max values in a row constitutes clipping
		if ((val >= PeakSig) || (val <= -PeakSig)) {
			if (lastpeak) {
				clipcnt++;
			} else {
				lastpeak = TRUE;
			}
		} else {
			lastpeak = FALSE;
		}

		// Add in this value to weighted average
		DCaverage = (DCaverage * dcweight) + (val * timeconstant);
		val -= DCaverage;
		if (val > 1.)
			val = 1.;
		else if (val < -1.)
			val = -1.;
		*inptr = val;
	}
}

// Calculate a single energy value averaged from the input buffer
// Buffer is assumed to be floating-point double PCM
void AudioGain::
process_instant(
	AudioBuffer*	inbuf)
{
	int		i;
	double		val;
	double		sum;
	double		sv;
	AudioHdr	inhdr;
	double		*inptr;
	size_t		frames;

	inhdr = inbuf->GetHeader();
	inptr = (double *)inbuf->GetAddress();
	frames = (size_t)inhdr.Time_to_Samples(inbuf->GetLength());

	// loop through the input buffer, calculating gain
	// XXX - should deal with multi-channel data!
	// XXX - for now, check first channel only
	sum = 0.;
	for (i = 0; i < frames; i++, inptr += inhdr.channels) {
		// Get absolute value
		sum += fabs(*inptr);
	}
	sum /= (double)frames;

	// calculate level meter value (between 0 & 1)
	val = log10(1. + (9. * sum));
	sv = val;

	// Normalize to within a reasonable range
	val -= LoSigInstantRange;
	if (val > HiSigInstantRange) {
		val = 1.;
	} else if (val < 0.) {
		val = 0.;
	} else {
		val /= HiSigInstantRange;
	}
	instant_gain = val;

	if (debug_agc != 0) {
		printf("audio_amplitude: avg = %7.5f  log value = %7.5f, "
		    "adjusted = %7.5f\n", sum, sv, val);
	}
}

// Calculate a weighted gain for agc computations
// Buffer is assumed to be floating-point double PCM
void AudioGain::
process_weighted(
	AudioBuffer*	inbuf)
{
	int		i;
	double		val;
	double		nosig;
	AudioHdr	inhdr;
	double		*inptr;
	size_t		frames;
	Double		sz;

	inhdr = inbuf->GetHeader();
	inptr = (double *)inbuf->GetAddress();
	frames = (size_t)inhdr.Time_to_Samples(inbuf->GetLength());
	sz = (Double) frames;

	// Allocate gain cache...all calls will hopefully be the same length
	if (gain_cache == NULL) {
		gain_cache = new double[frames];
		for (i = 0; i < frames; i++) {
			gain_cache[i] = 0.;
		}
		gain_cache_size = sz;
	} else if (sz > gain_cache_size) {
		frames = (size_t)irint(gain_cache_size);
	}
	// Scale up the 'no signal' level to avoid a divide in the inner loop
	nosig = NoSigWeight * gain_cache_size;

	// For each sample:
	//   calculate the sum of squares for a window around the sample;
	//   save the peak sum of squares;
	//   keep a running average of the sum of squares
	//
	// XXX - should deal with multi-channel data!
	// XXX - for now, check first channel only

	for (i = 0; i < frames; i++, inptr += inhdr.channels) {
		val = *inptr;
		val *= val;
		weighted_sum += val;
		weighted_sum -= gain_cache[i];
		gain_cache[i] = val;		// save value to subtract later
		if (weighted_sum > weighted_peaksum)
			weighted_peaksum = weighted_sum;	// save peak

		// Only count this sample towards the average if it is
		// above threshold (this attempts to keep the volume
		// from pumping up when there is no input signal).
		if (weighted_sum > nosig) {
			weighted_avgsum += weighted_sum;
			weighted_cnt++;
		}
	}
}
