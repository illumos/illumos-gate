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

#ifndef _MULTIMEDIA_AUDIODEVICECTL_H
#define	_MULTIMEDIA_AUDIODEVICECTL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <AudioDevice.h>

#ifdef __cplusplus
extern "C" {
#endif

// This is the audio control device class
//
// The audio control device cannot be read or written.

class AudioDevicectl : public AudioDevice {
private:
	AudioDevicectl operator=(AudioDevicectl);	// Assignment is illegal

protected:

public:
	// Constructor with path
	AudioDevicectl(
	    const char	*path = "");		// default device
	virtual ~AudioDevicectl() {}		// Destructor

	// class AudioDevice methods specialized here
	virtual AudioError tryopen(
	    const char *, int);		// open with a given pathname

	// class Audio methods specialized here
	virtual AudioHdr GetReadHeader();	// Get header

	// Device control and status functions
	// Turn SIGPOLL on/off
	virtual AudioError SetSignal(
	    Boolean on);


	// No-op methods
	virtual AudioError Create()
	    { return (RaiseError(AUDIO_ERR_NOEFFECT)); }
	virtual AudioError ReadData(void*, size_t&, Double&)
	    { return (RaiseError(AUDIO_ERR_NOEFFECT)); }
	virtual AudioError WriteData(void*, size_t&, Double&)
	    { return (RaiseError(AUDIO_ERR_NOEFFECT)); }
	virtual AudioError SetHeader(const AudioHdr&)
	    { return (RaiseError(AUDIO_ERR_NOEFFECT)); }
	virtual AudioError SetReadHeader(AudioHdr&)
	    { return (RaiseError(AUDIO_ERR_NOEFFECT)); }
	virtual AudioError SetWriteHeader(AudioHdr&)
	    { return (RaiseError(AUDIO_ERR_NOEFFECT)); }
	virtual AudioError WriteEof()
	    { return (RaiseError(AUDIO_ERR_NOEFFECT)); }
	virtual AudioError Flush(const FileAccess)
	    { return (RaiseError(AUDIO_ERR_NOEFFECT)); }
	virtual AudioError DrainOutput()
	    { return (RaiseError(AUDIO_ERR_NOEFFECT)); }

	virtual Boolean isDevice() const { return (TRUE); } // XXX ??
	virtual Boolean isDevicectl() const { return (TRUE); }
};

#ifdef __cplusplus
}
#endif

#endif /* !_MULTIMEDIA_AUDIODEVICECTL_H */
