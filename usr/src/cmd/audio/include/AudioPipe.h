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

#ifndef _MULTIMEDIA_AUDIOPIPE_H
#define	_MULTIMEDIA_AUDIOPIPE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <AudioUnixfile.h>

#ifdef __cplusplus
extern "C" {
#endif

// This is the 'base' class for pipes (such as stdin) containing audio data
class AudioPipe : public AudioUnixfile {
private:
	AudioPipe();					// Constructor w/no args
	AudioPipe operator=(AudioPipe);			// Assignment is illegal

public:
	// Constructor with path
	AudioPipe(
	    const int		desc,		// file descriptor
	    const FileAccess	acc,		// access mode
	    const char		*name = "(pipe)");	// name

	// class AudioUnixfile methods specialized here
	virtual AudioError Create();			// Create file
	virtual AudioError Open();			// Open file

	// Read from position
	virtual AudioError ReadData(
	    void* buf,				// buffer to fill
	    size_t& len,			// buffer length (updated)
	    Double& pos);			// start position (updated)

	// Write at position
	virtual AudioError WriteData(
	    void* buf,				// buffer to copy
	    size_t& len,			// buffer length (updated)
	    Double& pos);			// start position (updated)

	// class Audio methods specialized here
	virtual Boolean isPipe() const { return (TRUE); }
};

#ifdef __cplusplus
}
#endif

#endif /* !_MULTIMEDIA_AUDIOPIPE_H */
