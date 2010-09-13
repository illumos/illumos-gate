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

#ifndef _MULTIMEDIA_AUDIOTYPECONVERT_H
#define	_MULTIMEDIA_AUDIOTYPECONVERT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <AudioBuffer.h>

#ifdef __cplusplus
extern "C" {
#endif

// This is the abstract base class for an audio type conversion module

class AudioTypeConvert {
protected:
	AudioHdr	hdr;		// contains type information

public:
	AudioTypeConvert() {};				// Constructor
	virtual ~AudioTypeConvert() {};			// Destructor
	virtual AudioHdr DataType() const		// Return type
	    { return (hdr); }

	// class methods specialized by subclasses

	// TRUE if conversion ok
	virtual Boolean CanConvert(
	    AudioHdr h) const = 0;		// type to check against

	// Convert buffer to the specified type
	// Either the input or output type must be handled by this class

	// Convert to new type
	virtual AudioError Convert(
	    AudioBuffer*& inbuf,		// data buffer to process
	    AudioHdr outhdr) = 0;		// target header

	virtual AudioError Flush(AudioBuffer*& buf) = 0; // flush any remaining
							// data that may exist
};

#ifdef __cplusplus
}
#endif

#endif /* !_MULTIMEDIA_AUDIOTYPECONVERT_H */
