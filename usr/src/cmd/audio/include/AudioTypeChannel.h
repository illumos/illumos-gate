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

#ifndef _MULTIMEDIA_AUDIOTYPECHANNEL_H
#define	_MULTIMEDIA_AUDIOTYPECHANNEL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <AudioTypeConvert.h>
#include <audio_encode.h>

#ifdef __cplusplus
extern "C" {
#endif

// This is the class doing channel (mono->stereo) conversion

class AudioTypeChannel : public AudioTypeConvert {

protected:

public:
	AudioTypeChannel();	// Constructor
	~AudioTypeChannel();	// Destructor

	// Class AudioTypeConvert methods specialized here

	// TRUE if conversion ok
	virtual Boolean CanConvert(
	    AudioHdr h) const;			// type to check against

	// Convert buffer to the specified type
	// Either the input or output type must be handled by this class

	// Convert to new type
	virtual AudioError Convert(
	    AudioBuffer*& inbuf,		// data buffer to process
	    AudioHdr outhdr);			// target header

	virtual AudioError Flush(AudioBuffer*& buf);
};

#ifdef __cplusplus
}
#endif

#endif /* !_MULTIMEDIA_AUDIOTYPECHANNEL_H */
