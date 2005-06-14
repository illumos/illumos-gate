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

#ifndef _MULTIMEDIA_AUDIOGAIN_H
#define	_MULTIMEDIA_AUDIOGAIN_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <AudioTypePcm.h>

#ifdef __cplusplus
extern "C" {
#endif

// Class to handle gain calculations

// Define bits for AudioGain::Process() type argument
#define	AUDIO_GAIN_INSTANT	(1)		// Gain for level meter
#define	AUDIO_GAIN_WEIGHTED	(2)		// Gain for agc


class AudioGain {
protected:

static const double	LoSigInstantRange;	// normalization constants
static const double	HiSigInstantRange;
static const double	NoSigWeight;
static const double	LoSigWeightRange;
static const double	HiSigWeightRange;
static const double	PeakSig;
static const double	DCtimeconstant;		// DC offset time constant

	AudioTypePcm	float_convert;		// used in signal processing
	unsigned	clipcnt;		// clip counter
	Double		DCaverage;		// weighted DC offset
	Double		instant_gain;		// current (instantaneous) gain
	Double		weighted_peaksum;	// peak weighted sum
	Double		weighted_sum;		// running sum of squares
	Double		weighted_avgsum;	// accumulated sums to averages
	unsigned	weighted_cnt;		// number of sums to average
	double		*gain_cache;		// weighted gains
	Double		gain_cache_size;	// number of cached gains

protected:
	// Internal processing methods

	// filter DC bias
	virtual void process_dcfilter(
	    AudioBuffer*);
	// calculate instant gain
	virtual void process_instant(
	    AudioBuffer*);
	// calculate weighted gain
	virtual void process_weighted(
	    AudioBuffer*);

public:
		AudioGain();			// Constructor
	virtual	~AudioGain();			// Destructor

	// TRUE if conversion ok
	virtual Boolean CanConvert(
	    const AudioHdr&) const;	// type to check against

	// Process new audio data
	virtual AudioError Process(
	    AudioBuffer*, int);		// buffer destroyed if not referenced!
	virtual double InstantGain();	// Get most recent gain
	virtual double WeightedGain();	// Get current weighted gain
	virtual double WeightedPeak();	// Get peak weighted gain
	virtual Boolean Clipped();	// TRUE if peak since last check
	virtual void Flush();		// Reset state
};

#ifdef __cplusplus
}
#endif

#endif /* !_MULTIMEDIA_AUDIOGAIN_H */
