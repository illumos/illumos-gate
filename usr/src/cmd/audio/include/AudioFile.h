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

#ifndef _MULTIMEDIA_AUDIOFILE_H
#define	_MULTIMEDIA_AUDIOFILE_H

#ifdef NO_EXTERN_C

#ifdef __cplusplus
extern "C" {
#endif

#endif /* NO_EXTERN_C */

#include <AudioUnixfile.h>
#include <sys/types.h>
#include <sys/mman.h>

// A 'primitive type' for memory mapped file access types
enum vmaccess_t {
    NormalAccess = 0, RandomAccess = 1, SequentialAccess = 2
};

class VMAccess {
private:
	vmaccess_t	type;		// combined mode
public:
	VMAccess(vmaccess_t x = NormalAccess): type(x) { }	// Constructor
	inline operator vmaccess_t()			// Cast to enum
	    { return (type); }
	inline operator int() {				// Cast to integer
	    switch (type) {
	    case RandomAccess: return (MADV_RANDOM);
	    case SequentialAccess: return (MADV_SEQUENTIAL);
	    case NormalAccess:
	    default:
		return (MADV_NORMAL);
	    }
	}
};


// This is the 'base' class for regular files containing audio data
class AudioFile : public AudioUnixfile {
private:
	static const FileAccess	defmode;	// Default access mode
	static const char	*AUDIO_PATH;	// Default path env name

	off_t			hdrsize;	// length of file header
	off_t			seekpos;	// current system file pointer
	Double			origlen;	// initial length of file

	caddr_t			mapaddr;	// for mmaping RO files
	off_t			maplen;		// length of mmaped region
	VMAccess		vmaccess;	// vm (mmap) access type

	AudioFile operator=(AudioFile);			// Assignment is illegal

protected:
	// Open named file
	virtual AudioError tryopen(
	    const char *, int);
	// Create named file
	virtual AudioError createfile(
	    const char *path);			// filename

	// class AudioUnixfile methods specialized here
	// Seek in input stream
	virtual AudioError seekread(
	    Double pos,				// position to seek to
	    off_t& offset);			// returned byte offset
	// Seek in output stream
	virtual AudioError seekwrite(
	    Double pos,				// position to seek to
	    off_t& offset);			// returned byte offset

public:
	AudioFile();				// Constructor w/no args

	// Constructor with path
	AudioFile(
	    const char *path,			// filename
	    const FileAccess acc = defmode);	// access mode
	virtual ~AudioFile();			// Destructor

	// Set tmpfile location
	static AudioError SetTempPath(
	    const char *path);			// directory path

	// class AudioUnixfile methods specialized here
	virtual void SetBlocking(Boolean) { }	// No-op for files

	// front end to madvise
	AudioError SetAccessType(
	    VMAccess vmacc);			// (normal, random, seq access)

	inline VMAccess GetAccessType()	const {	// get vm access type
		return (vmaccess);
	}

	virtual AudioError Create();		// Create file
	virtual AudioError Open();		// Open file

	// ... with search path
	virtual AudioError OpenPath(
	    const char *path = AUDIO_PATH);
	virtual AudioError Close();		// Close file

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

	// copy to another audio obj.
	virtual AudioError AsyncCopy(
	    Audio* ap,				// dest audio object
	    Double& frompos,
	    Double& topos,
	    Double& limit);

	// class Audio methods specialized here
	virtual Boolean isFile() const { return (TRUE); }
};

#ifdef NO_EXTERN_C

#ifdef __cplusplus
}
#endif

#endif /* NO_EXTERN_C */

#endif /* !_MULTIMEDIA_AUDIOFILE_H */
