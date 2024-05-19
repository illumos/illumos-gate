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

#ifndef _MULTIMEDIA_AUDIOUNIXFILE_H
#define	_MULTIMEDIA_AUDIOUNIXFILE_H

#include <AudioStream.h>

#ifdef __cplusplus
extern "C" {
#endif

// This is the abstract base class for all file descriptor based audio i/o.
// It is invalid to create an object of type AudioUnixfile.

class AudioUnixfile : public AudioStream {
private:
	FileAccess	mode;			// access mode
	Boolean		block;			// FALSE if fd set non-blocking
	Boolean		filehdrset;		// TRUE if file hdr read/written
	int		fd;			// file descriptor
	char		*infostring;		// Info string from header
	unsigned int	infolength;		// Info string length

	AudioUnixfile() {}			// Constructor w/no args

protected:
	// Constructor
	AudioUnixfile(
	    const char *path,		// pathname
	    const FileAccess acc);	// access mode

	int getfd() const;			// Return descriptor
	void setfd(int d);			// Set descriptor

	virtual AudioError decode_filehdr();	// Get header from file
	virtual AudioError encode_filehdr();	// Write file header

	// Seek in input stream
	virtual AudioError seekread(
	    Double pos,				// position to seek to
	    off_t& offset);			// returned byte offset

	// Seek in output stream
	virtual AudioError seekwrite(
	    Double pos,				// position to seek to
	    off_t& offset);			// returned byte offset

	virtual Boolean isfdset() const;		// TRUE if fd is valid
	virtual Boolean isfilehdrset() const;		// TRUE if file hdr r/w

	// class AudioStream methods specialized here
	virtual Boolean opened() const;			// TRUE, if open

public:
	virtual ~AudioUnixfile();			// Destructor

	virtual FileAccess GetAccess() const;		// Get mode
	virtual Boolean GetBlocking() const;		// TRUE, if blocking i/o
	virtual void SetBlocking(Boolean b);		// Set block/non-block

	virtual AudioError Create() = 0;		// Create file
	virtual AudioError Open() = 0;			// Open file

	// ... with search path
	virtual AudioError OpenPath(
	    const char *path = 0);
	virtual AudioError Close();			// Close file

	// Methods specific to the audio file format
	// Get info string
	virtual char *GetInfostring(
	    int& len) const;			// return length

	// Set info string
	virtual void SetInfostring(
	    const char	*str,			// ptr to info data
	    int		len = -1);		// optional length

	// class Audio methods specialized here
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
};

#include <AudioUnixfile_inline.h>

#ifdef __cplusplus
}
#endif

#endif /* !_MULTIMEDIA_AUDIOUNIXFILE_H */
