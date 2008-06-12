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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <malloc.h>
#include <stdlib.h>
#include <memory.h>
#include <AudioBuffer.h>
#include <AudioLib.h>
#include <AudioDetect.h>
#include <silence_detect.h>

// XXX - temporary: manual data conversion
#include <AudioTypePcm.h>

// class AudioDetectArray methods

// Allocation increment for array
static const unsigned int	ARRAY_INCR = 50;

// Minimum time for detection algorithm is 250 milliseconds
static const double		MIN_DURATION = .250;
// The detection algorithm needs at least 20 msecs more than silence duration
static const double		DURATION_INCR = .022;
// Minimum silence for detection algorithm is fine grain
// XXX - not used for now
static const double		MIN_SILENCE = .05;

// Constructor
AudioDetectArray::
AudioDetectArray(
	unsigned int	cnt):		// start size of array
	count(0)
{
	size = cnt;
	if (size == 0)
		size = ARRAY_INCR;	// set default size
	pts = (AudioDetectPts*)malloc(size * sizeof (*pts));
}

// Destructor
AudioDetectArray::
~AudioDetectArray()
{
	if (pts != NULL)
		(void) free((char *)pts);
}

// Append a list of detection points to the array
AudioError AudioDetectArray::
appendpts(
	AudioDetectPts*	newpts,		// new array to append
	unsigned int	cnt)		// number of points to append
{
	// If cnt == -1, append until eof
	if (cnt == -1) {
		AudioDetectPts*	cp;

		cnt = 1;
		cp = newpts;
		while (cp->type != DETECT_EOF) {
			cnt++;
			cp++;
		}
	}

	// Loop through, appending each new point in turn
	while (cnt-- > 0) {
		if (count == size) {
			// Time to allocate more space in array
			size += ARRAY_INCR;
			pts = (AudioDetectPts*)
			    realloc((char *)pts, (size * sizeof (*pts)));
			if (pts == NULL)
				return (AUDIO_UNIXERROR);
		}
		pts[count++] = *newpts++;
	}
	return (AUDIO_SUCCESS);
}

// Process the detection array, eliminating eofs and collapsing adjacent entries
void AudioDetectArray::
reduce()
{
	AudioDetectPts*		ip;	// input pointer
	AudioDetectPts*		op;	// output pointer
	unsigned int		ocnt;	// output counter

	// Start input and output pointers together
	ip = pts;
	op = pts;
	ocnt = 0;

	// If no entries in the array, make at least one
	if (count == 0) {
		op->pos = 0.;
		op->type = DETECT_EOF;
		count = 1;
		return;
	}

	// Get a legitimate starting point
	while ((ip->type == DETECT_EOF) && (count-- > 0)) {
		*op = *ip++;	// copy eof, in case it's the last
	}
	if (count <= 0) {
		count = 1;	// already copied final eof
		return;
	}

	// Copy first entry
	*op++ = *ip++;
	ocnt++;
	count--;

	// Collapse the array
	while (count-- > 0) {
		if (ip->type == op[-1].type) {
			// Eliminate adjacent entries of same type
			ip++;
		} else if ((ip->type == DETECT_EOF) && (count > 0)) {
			// Remove non-final eofs
			ip++;
		} else {
			*op++ = *ip++;
			ocnt++;
		}
	}
	count = ocnt;		// set final count
}

// Copy the detection array to a new array
AudioError AudioDetectArray::
duparray(
	AudioDetectPts*&	cp)	// set pointer to new array
{
	// Allocate new array of adequate size
	cp = (AudioDetectPts*)malloc(count * sizeof (*pts));
	if (cp == NULL)
		return (AUDIO_UNIXERROR);

	// Copy array
	(void) memcpy((char *)cp, (char *)pts, (count * sizeof (*pts)));
	return (AUDIO_SUCCESS);
}


// class AudioDetect methods


// Constructor
AudioDetect::
AudioDetect()
{
	min_sound = .3;
	min_silence = .2;
	state = (void*)silence_create_state(8000, min_silence);
	thresh_scale = silence_get_thr_scale((SIL_STATE*)state);
	noise_ratio = silence_get_noise_ratio((SIL_STATE*)state);
}

// Destructor
AudioDetect::
~AudioDetect()
{
	silence_destroy_state((SIL_STATE*)state);
}


// Get parameters for the audio detection algorithm.
// Each call retrieves one parameter.  The parameter is identified
// by the 'type' argument.  'Valp' is a pointer to the new value.
AudioError AudioDetect::
GetParam(
	AudioDetectConfig type,		// type flag
	Double&		val)		// address of value
{
	switch (type) {
	case DETECT_MINIMUM_SILENCE:
		val = min_silence;
		break;
	case DETECT_MINIMUM_SOUND:
		val = min_sound;
		break;
	case DETECT_THRESHOLD_SCALE:
		val = thresh_scale;
		break;
	case DETECT_NOISE_RATIO:
		val = noise_ratio;
		break;
	default:
		return (AUDIO_ERR_BADARG);
	}
	return (AUDIO_SUCCESS);
}

// Set parameters for the audio detection algorithm.
// Each call adjusts one parameter.  The parameter is identified
// by the 'type' argument.  'Valp' is a pointer to the new value.
AudioError AudioDetect::
SetParam(
	AudioDetectConfig type,		// type flag
	Double		val)		// value
{
	if (val < 0.)
		return (AUDIO_ERR_BADARG);

	switch (type) {
	case DETECT_MINIMUM_SILENCE:
		min_silence = val;
		break;
	case DETECT_MINIMUM_SOUND:
		min_sound = val;
		break;
	case DETECT_THRESHOLD_SCALE:
		thresh_scale = val;
		break;
	case DETECT_NOISE_RATIO:
		if (val > 1.)
			return (AUDIO_ERR_BADARG);
		noise_ratio = val;
		break;
	default:
		return (AUDIO_ERR_BADARG);
	}
	return (AUDIO_SUCCESS);
}

// Entry stubs for invocations with missing arguments
AudioError AudioDetect::
Analyze(
	AudioDetectPts*& pts,		// value array to modify
	Audio*		obj)		// AudioList, or whatever
{
	Double		from;		// starting offset
	Double		to;		// ending offset

	return (Analyze(pts, obj, from = 0., to = AUDIO_UNKNOWN_TIME));
}

AudioError AudioDetect::
Analyze(
	AudioDetectPts*& pts,		// value array to modify
	Audio*		obj,		// AudioList, or whatever
	Double		from)		// starting offset
{
	Double		to;		// ending offset

	return (Analyze(pts, obj, from, to = AUDIO_UNKNOWN_TIME));
}

// Process data from a given Audio object, filling in the 'vals' structure.
// If from and to identify a subset region for which there are
// already valid markers in the 'vals' structure, 'vals' is updated.
// For instance, suppose a 60 second file has already been mapped out.
// Now a PASTE operation inserts 10 seconds right in the middle.
// Step through the vals structure, adding 10 (the insert length) to
// every time greater than 30 (the insert point).  Then call this routine
// with (from, to) set to (30, 40).  The vals structure will be
// updated by reading the minimum required amount of data (which will,
// however, be a little longer than 10 seconds in order to get the
// transitions right).
// Returns audio error code or AUDIO_SUCCESS.
// This routine deallocates the input copy of 'pts', so make sure
// it is a copy of non-volatile storage, if necessary.
AudioError AudioDetect::
Analyze(
	AudioDetectPts*& pts,		// value array to modify
	Audio*		obj,		// AudioList, or whatever
	Double		from,		// starting offset [0.]
	Double		to)		// ending offset [AUDIO_UNKNOWN_TIME]
{
	Double		maxdur;		// length of minimum sample interval
	AudioDetectArray* ap;		// new value array
	AudioDetectPts*	oldpts;		// saved input array
	AudioDetectPts*	list;
	AudioDetectPts*	aptr;
	unsigned int	cnt;
	AudioError	err;

	ap = new AudioDetectArray;
	if (ap == NULL)
		return (AUDIO_UNIXERROR);
	oldpts = pts;
	pts = NULL;

	// Get largest of the minimum time parameters
	maxdur = min_silence;
	if (min_sound > maxdur)
		maxdur = min_sound;
	maxdur += DURATION_INCR;
	if (maxdur < MIN_DURATION)
		maxdur =  MIN_DURATION;

	// Adjust starting time
	from -= maxdur;
	if (from < 0.)
		from = 0.;

	// Adjust ending time
	if (!Undefined(to))
		to += maxdur;

	// If replacing virtually the whole array, skip trying to update
	if ((oldpts != NULL) &&
	    ((oldpts->type == DETECT_EOF) ||
	    ((from < MIN_DURATION) && (Undefined(to))))) {
		(void) free((char *)oldpts);
		oldpts = NULL;
		from = 0.;
	}

	// If time is a subset of an existing list, copy out the first entries
	list = oldpts;
	if ((list != NULL) && (from > 0.)) {
		cnt = 0;
		while ((list->type != DETECT_EOF) && (from > list->pos)) {
			cnt++;
			list++;
		}
		if (err = ap->appendpts(oldpts, cnt))
			goto error_ret;
	}

	// Analyze the specified region of data
	if (err = analyzeappend(ap, obj, from, to, maxdur))
		goto error_ret;

	// If time is a subset of an existing list, copy out the last entries
	if ((list != NULL) && (!Undefined(to))) {
		while (list->type != DETECT_EOF) {
			if (list->pos >= to) {
				ap->appendpts(list, 1);
				list++;
			}
		}
	}

	// Compress and copy the list
	ap->reduce();


	// Eliminate silence segments that are under their length threshold
	for (aptr = ap->pts; aptr->type != DETECT_EOF; aptr++) {
		if ((aptr->type == DETECT_SILENCE) &&
		    ((aptr[1].pos - aptr->pos) < min_silence))
			aptr->type = DETECT_SOUND;
	}
	ap->reduce();

	// Eliminate sound segments that are under their length threshold
	for (aptr = ap->pts; aptr->type != DETECT_EOF; aptr++) {
		if ((aptr->type == DETECT_SOUND) &&
		    ((aptr[1].pos - aptr->pos) < min_sound))
			aptr->type = DETECT_SILENCE;
	}
	ap->reduce();

	// Caller must free the returned array
	// XXX - maybe can arrange for caller to dup it instead
	err = ap->duparray(pts);

error_ret:
	// Throw away interim structures
	if (oldpts != NULL)
		(void) free((char *)oldpts);
	delete ap;
	return (err);
}

// Audio detection main anaylze loop
AudioError AudioDetect::
analyzeappend(
	AudioDetectArray*& aptr,		// value array to modify
	Audio*		obj,			// AudioList, or whatever
	Double		from,			// starting offset
	Double		to,			// ending offset
	Double		mintime)		// minimum analysis buffer size
{
	AudioBuffer*	buf;
	AudioBuffer*	abp;
	AudioHdr	hdr;
	Double		start;
	Double		len;
	Double		minbuf;
	Double		tmpend = 0.;
	unsigned int	bufsiz;
	off_t		offset;
	unsigned int	npts;
	int		i;
	int		valid;
	END_POINTS*	ep;
	AudioDetectPts	apt;
	AudioError	err;

	buf = NULL;
	abp = NULL;
	offset = 0;
	start = from;
	minbuf = mintime * 10.;			// Process buffer length

	// Start out assuming non-silence
	apt.type = DETECT_SOUND;
	apt.pos = from;
	if (err = aptr->appendpts(&apt, 1))
		return (err);

	// If eof, set an eof marker
	if (!Undefined(obj->GetLength()) && (from >= obj->GetLength())) {
		goto no_data;
	}

	hdr = obj->GetDHeader(from);
	hdr.sample_rate = 0;		// dummy value for now

	// Init detection state
	silence_set_min_sil_dur(min_silence, (SIL_STATE*)state);
	silence_set_thr_scale(thresh_scale, (SIL_STATE*)state);
	silence_set_noise_ratio(noise_ratio, (SIL_STATE*)state);
	silence_init_state((SIL_STATE*)state);

	// Loop while there is data to read
	do {
		// If eof, we're done
		if (!Undefined(obj->GetLength()) &&
		    (from >= obj->GetLength())) {
			break;
		}

		// If the current sample rate does not match the old, re-init
		if (obj->GetDHeader(from).sample_rate != hdr.sample_rate) {
			hdr.sample_rate = obj->GetDHeader(from).sample_rate;
			if (buf != NULL)
				buf->Dereference();

			// Allocate a new holding buffer
			buf = new AudioBuffer(minbuf);
			if (buf == NULL)
				return (AUDIO_UNIXERROR);
			buf->Reference();
			if (err = buf->SetHeader(hdr))
				goto error_ret;

			// Update algorithm state
			silence_set_rate(hdr.sample_rate, (SIL_STATE*)state);
		}

		// Limit the copy to the buffer length or remaining data time
		len = minbuf;
		if (!Undefined(to)) {
			if (len > (to - from)) {
				len = to - from;
			}
		}

		// Copy one region of data
		// XXX - Duplicate bufptr to hold onto it (for now)
		//    tmpend should = 0. from initialization area

		// tmpend should be cleared each time before calling.
		// Bug ID 4034048	DPT 24-Feb-97
		tmpend = 0.;
		err = AudioAsyncCopy(obj, buf, from, tmpend, len);

		// XXX - Temporary: Convert to linear manually
		if (!err) {
			AudioTypePcm	conv;		// XXX - temporary
			AudioHdr	newhdr = hdr;

			abp = buf;
			// only convert if not LINEAR pcm
			if (buf->GetHeader().encoding != LINEAR) {
				newhdr.bytes_per_unit = 2;
				newhdr.encoding = LINEAR;
				err = conv.Convert(abp, newhdr);
				if (!err)
					abp->Reference();
			} else {
				abp->Reference();
			}
		}

		if (!err) {
			// Process data through signal detection routine
			bufsiz = (unsigned int) hdr.Time_to_Samples(len);
			npts = bufsiz;
			i = silence_detect((short *)abp->GetAddress(), &ep,
			    &npts, &valid, (SIL_STATE*)state);
			abp->Dereference();		// XXX - temporary
			if (i == SILENCE_ERR_BUFFER_TOO_SMALL) {
				// If buffer too small, go on
				err = AUDIO_SUCCESS;
			} else if (i == SILENCE_ERR_REALLOC_FAILED) {
				err = AUDIO_UNIXERROR;
			}

			// Convert endpoints to AudioDetectPts
			if (!err) {
				// First, add byte offset to all 'times'
				// Then, create entries for silence regions
				for (i = 0; i < npts; i++) {
					ep[i].ep_start += (int)offset;
					apt.pos = start +
					    hdr.Samples_to_Time(ep[i].ep_start);
					apt.type = DETECT_SILENCE;
					if (err = aptr->appendpts(&apt, 1))
						goto error_ret;

					// If the end of silence is the same
					// as the end of processed data,
					// don't start sound yet
					if (ep[i].ep_end == valid)
						break;
					ep[i].ep_end += (int)offset;
					apt.pos = start +
					    hdr.Samples_to_Time(ep[i].ep_end);
					apt.type = DETECT_SOUND;
					if (err = aptr->appendpts(&apt, 1))
						goto error_ret;
				}
				offset += bufsiz;
			}
		}
	} while (!err);

no_data:
	// Set end-of-file marker to latest position
	if (!err || (err == AUDIO_EOF)) {
		apt.type = DETECT_EOF;
		apt.pos = from;
		err = aptr->appendpts(&apt, 1);
	}

error_ret:
	if (buf != NULL)
		buf->Dereference();
	return (err);
}
