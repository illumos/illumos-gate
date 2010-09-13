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

#ifndef _MULTIMEDIA_AUDIOEXTENT_H
#define	_MULTIMEDIA_AUDIOEXTENT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <values.h>
#include <Audio.h>

#ifdef __cplusplus
extern "C" {
#endif

// This class defines an extent of a referenced audio class
class AudioExtent : public Audio {
private:
	Audio*			ref;		// reference to audio object
	Double			start;		// start time
	Double			end;		// end time

	AudioExtent operator=(AudioExtent);	// Assignment is illegal

public:
	// Constructor
	AudioExtent(
	    Audio* obj,				// audio object
	    double s = 0.,			// start time
	    double e = AUDIO_UNKNOWN_TIME);	// end time
	virtual ~AudioExtent();				// Destructor

	Audio* GetRef() const;				// Get audio obj
	void SetRef(Audio* r);				// Set audio obj
	Double GetStart() const;			// Get start time
	void SetStart(Double s);			// Set start time
	Double GetEnd() const;				// Get end time
	void SetEnd(Double e);				// Set end time

	// class Audio methods specialized here
	virtual Double GetLength() const;		// Get length, in secs
	virtual char *GetName() const;			// Get name string
	virtual AudioHdr GetHeader();			// Get header
	virtual AudioHdr GetHeader(Double pos);		// Get header at pos

	// Read from position
	virtual AudioError ReadData(
	    void* buf,				// buffer to fill
	    size_t& len,			// buffer length (updated)
	    Double& pos);			// start position (updated)

	// Write is prohibited
	virtual AudioError WriteData(
	    void* buf,				// buffer to copy
	    size_t& len,			// buffer length (updated)
	    Double& pos);			// start position (updated)

	virtual Boolean isExtent() const { return (TRUE); }
};

#ifdef __cplusplus
}
#endif

#endif /* !_MULTIMEDIA_AUDIOEXTENT_H */
