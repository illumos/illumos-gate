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
 * Copyright (c) 1990-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _MULTIMEDIA_AUDIODETECT_H
#define	_MULTIMEDIA_AUDIODETECT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <Audio.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Audio sound/silence detection structures and routines */

/*
 * An array of AudioDetectPts is returned by the detection algorithms.
 * 'Pos' gives the start time of a region.  'Type' give the type of data
 * detected in that particular region.  The end time of the region is equal
 * to the start time of the next region.
 * The last entry in the array has type DETECT_EOF.
 */

enum AudioDetectType {
    DETECT_EOF,			/* end of file marker */
    DETECT_SILENCE,		/* region of silence */
    DETECT_SOUND		/* region of detected sound */
			/* XXX - may be extended to include */
			/* touch-tone and speech detection. */
};
struct AudioDetectPts {
	double			pos;	/* start time of audio region */
	enum AudioDetectType	type;	/* type of audio region */
};

/* Audio detection algorithm tuning parameters */
enum AudioDetectConfig {
	DETECT_MINIMUM_SILENCE,		/* (double) minimum pause time */
	DETECT_MINIMUM_SOUND,		/* (double) minimum sound time */
	DETECT_THRESHOLD_SCALE,		/* (double) 0.(low) - 4.(hi) */
	DETECT_NOISE_RATIO		/* (double) 0.(low) - 1.(hi) */
};

// Array of detection points
class AudioDetectArray {
private:
	unsigned int	count;		// number of valid points in array
	unsigned int	size;		// number of entries in array

	void operator=(AudioDetectArray);	// Assignment is illegal
public:
	AudioDetectPts*	pts;		// array ptr

	AudioDetectArray(unsigned int cnt = 0);		// Constructor
	~AudioDetectArray();				// Destructor

	// Append points
	AudioError appendpts(
	    AudioDetectPts* newpts,		// array to append
	    unsigned int cnt = -1);		// number of points to append
	void reduce();				// Eliminate redundancy
	AudioError duparray(AudioDetectPts*& cp);	// Copy array
};


// Audio detection state structure
class AudioDetect {
private:
	void*		state;		// detection algorithm state
	Double		min_silence;	// length of minimum silence segment
	Double		min_sound;	// length of minimum sound segment
	Double		thresh_scale;	// silence threshold scale
	Double		noise_ratio;	// silence threshold noise ratio

	void operator=(AudioDetect);			// Assignment is illegal

	// Analyze main loop
	AudioError analyzeappend(
	    AudioDetectArray*& aptr,		// value array to modify
	    Audio* obj,				// AudioList, or whatever
	    Double from,			// starting offset
	    Double to,				// ending offset
	    Double mintime);			// minimum analysis buffer size
public:
	AudioDetect();				// Constructor
	~AudioDetect();				// Destructor

	// Get detection params
	AudioError GetParam(
	    AudioDetectConfig type,		// type flag
	    Double& val);			// return value

	// Set detection params
	AudioError SetParam(
	    AudioDetectConfig type,		// type flag
	    Double val);			// value

	// Analyze silence
	AudioError SetNoiseFloor(
	    Audio* obj);			// AudioExtent, or whatever

	// Analyze gain level
	AudioError AnalyzeGain(
	    Audio* obj,				// AudioExtent, or whatever
	    Double& val);			// return value

	// Process data
	AudioError Analyze(
	    AudioDetectPts*& pts,		// value array to modify
	    Audio* obj);			// AudioList, or whatever

	// Process data
	AudioError Analyze(
	    AudioDetectPts*& pts,		// value array to modify
	    Audio* obj,				// AudioList, or whatever
	    Double from);			// starting offset

	// Process data
	AudioError Analyze(
	    AudioDetectPts*& pts,		// value array to modify
	    Audio* obj,				// AudioList, or whatever
	    Double from,			// starting offset
	    Double to);				// ending offset
};

#ifdef __cplusplus
}
#endif

#endif /* !_MULTIMEDIA_AUDIODETECT_H */
