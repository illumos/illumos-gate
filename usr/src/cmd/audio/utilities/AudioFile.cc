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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <malloc.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>

#include <AudioFile.h>
#include <AudioLib.h>
#include <AudioDebug.h>
#include <libaudio.h>
#include <audio_hdr.h>

// class AudioFile methods


// Initialize temporary file params
#define	TMPDIR		"/tmp"
#define	TMPFILE		"/audiotoolXXXXXX"
static char		*tmpdir = NULL;
static const char	*tmpname = "(temporary file)";
static const FileAccess	tmpmode = ReadWrite;
static const VMAccess	defaccess = SequentialAccess;

// Initialize default access mode, used when a filename is supplied
const FileAccess	AudioFile::defmode = ReadOnly;

// Default audio file path prefix environment variable
const char *AudioFile::AUDIO_PATH = "AUDIOPATH";


// Constructor with no arguments opens a read/write temporary file
AudioFile::
AudioFile():
	AudioUnixfile(tmpname, tmpmode),
	hdrsize(0), seekpos(0), origlen(0.), mapaddr(0), maplen(0),
	vmaccess(defaccess)
{
}

// Constructor with pathname and optional mode arg
AudioFile::
AudioFile(
	const char		*path,		// filename
	const FileAccess	acc):		// access mode
	AudioUnixfile(path, acc),
	hdrsize(0), seekpos(0), origlen(0.), mapaddr(0), maplen(0),
	vmaccess(defaccess)
{
}

// Destructor must call the local Close() routine
AudioFile::
~AudioFile()
{
	// If the file was open, close it
	if (opened())
		(void) Close();
}

// Set a default temporary file directory
AudioError AudioFile::
SetTempPath(
	const char	*path)
{
	struct stat	st;

	// Verify intended path
	if ((stat(path, &st) < 0) ||
	    !S_ISDIR(st.st_mode) ||
	    (access(path, W_OK) < 0)) {
		errno = ENOTDIR;
		return (AUDIO_UNIXERROR);
	}

	if (tmpdir != NULL)
		(void) free(tmpdir);
	tmpdir = (char *)malloc(strlen(path) + 1);
	(void) strcpy(tmpdir, path);
	return (AUDIO_SUCCESS);
}


// Create a named file according to the current mode setting
AudioError AudioFile::
createfile(
	const char	*path)			// pathname or 0
{
	char		*tmpf;
	char		*tmpstr;
	int		openmode;
	int		desc;
	AudioError	err;

	// Convert the open mode to an int argument for open()
	openmode = GetAccess();

	// Was the header properly set?
	if (!hdrset())
		return (RaiseError(AUDIO_ERR_BADHDR));

	// Can't create if already opened or if mode or name not set
	if ((openmode == -1) || opened() || (strlen(path) == 0))
		return (RaiseError(AUDIO_ERR_NOEFFECT));

	// If temporary file, create and unlink it.
	if (strcmp(path, tmpname) == 0) {
		// Construct the temporary file path
		tmpstr = (char *)malloc(1 + strlen(TMPFILE) +
		    strlen((tmpdir == NULL) ? TMPDIR : tmpdir));
		(void) sprintf(tmpstr, "%s%s",
		    (tmpdir == NULL) ? TMPDIR : tmpdir, TMPFILE);
		tmpf = mktemp(tmpstr);

		// Open the temp file and unlink it
		err = createfile(tmpf);
		if ((err == AUDIO_SUCCESS) && (unlink(tmpf) < 0)) {
			(void) Close();
			err = RaiseError(AUDIO_UNIXERROR, Warning);
		}
		(void) free(tmpstr);
		return (err);
	}

	// Create the file
	desc = open(path, openmode | O_CREAT | O_TRUNC, 0666);
	if ((desc < 0) && (errno == EOVERFLOW)) {
		return (RaiseError(AUDIO_UNIXERROR, Fatal,
		    (char *)"Large File"));
	} else if (desc < 0) {
		return (RaiseError(AUDIO_UNIXERROR));
	}

	// Set the file descriptor (this marks the file open)
	setfd(desc);

	// Write the file header with current (usually unknown) size
	err = encode_filehdr();
	if (err != AUDIO_SUCCESS) {
		setfd(-1);
		(void) close(desc);		// If error, remove file
		(void) unlink(path);
		return (err);
	}

	// Save the length that got written, then set it to zero
	origlen = GetLength();
	setlength(0.);

	// Set the size of the file header
	hdrsize = lseek(desc, (off_t)0, SEEK_CUR);
	if (hdrsize < 0) {
		setfd(-1);
		(void) close(desc);		// If error, remove file
		(void) unlink(path);
		return (err);
	}
	seekpos = 0;

	return (AUDIO_SUCCESS);
}

// Create a file whose name is already set, according to the mode setting
AudioError AudioFile::
Create()
{
	return (createfile(GetName()));
}

// Open a file whose name is set
AudioError AudioFile::
Open()
{
	return (OpenPath(NULL));
}

// Open a file, using the specified path prefixes
AudioError AudioFile::
OpenPath(
	const char	*path)
{
	char		*filename;
	int		flen;
	char		*prefix;
	char		*str;
	char		*wrk;
	char		*pathname;
	int		openmode;
	AudioError	err;

	// Convert the open mode to an int argument for open()
	openmode = GetAccess();
	filename = GetName();
	flen = strlen(filename);

	// Can't open if already opened or if mode or name not set
	if ((openmode == -1) || opened() || (strlen(filename) == 0))
		return (RaiseError(AUDIO_ERR_NOEFFECT));

	// Search path:
	//	1) try name: if not found and not readonly:
	//		if Append mode, try creating it
	//	2) if name is a relative pathname, and 'path' is not NULL:
	//		try every path prefix in 'path'

	err = tryopen(filename, openmode);
	if (!err)
		return (AUDIO_SUCCESS);
	if (GetAccess().Writeable() || (filename[0] == '/')) {
		// If file is non-existent and Append mode, try creating it.
		if ((err == AUDIO_UNIXERROR) && (err.sys == ENOENT) &&
		    GetAccess().Append() && hdrset()) {
			return (Create());
		}
		return (RaiseError(err));
	}

	// Try path as an environment variable name, else assume it is a path
	str = (path == NULL) ? NULL : getenv(path);
	if (str == NULL)
		str = (char *)path;

	if (str != NULL) {
		// Make a copy of the path, to parse it
		wrk = new char[strlen(str) + 1];
		(void) strcpy(wrk, str);
		str = wrk;

		// Try each component as a path prefix
		for (prefix = str;
		    (prefix != NULL) && (prefix[0] != '\0');
		    prefix = str) {
			str = strchr(str, ':');
			if (str != NULL)
				*str++ = '\0';
			pathname = new char[strlen(prefix) + flen + 2];
			(void) sprintf(pathname, "%s/%s", prefix, filename);
			err = tryopen(pathname, openmode);
			delete[] pathname;
			switch (err) {
			case AUDIO_SUCCESS:	// found the file
				delete[] wrk;
				return (RaiseError(err));
			// XXX - if file found but not audio, stop looking??
			}
		}
		delete[] wrk;
	}
	// Can't find file.  Return the original error condition.
	return (RaiseError(tryopen(filename, openmode)));
}

// Attempt to open the given audio file
AudioError AudioFile::
tryopen(
	const char	*pathname,
	int		openmode)
{
	struct stat	st;
	int		desc;
	AudioError	err;

	// If the name is changing, set the new one
	if (pathname != GetName())
		SetName(pathname);

	// Does the file exist?
	if (stat(pathname, &st) < 0)
		return (AUDIO_UNIXERROR);

	// If not a regular file, stop right there
	if (!S_ISREG(st.st_mode))
		return (AUDIO_ERR_BADFILEHDR);

	// Open the file and check that it's an audio file
	desc = open(GetName(), openmode);
	if ((desc < 0) && (errno == EOVERFLOW)) {
		return (RaiseError(AUDIO_UNIXERROR, Fatal,
		    (char *)"Large File"));
	} else if (desc < 0) {
		return (AUDIO_UNIXERROR);
	}

	// Set the file descriptor (this marks the file open)
	setfd(desc);

	err = decode_filehdr();
	if (err != AUDIO_SUCCESS) {
		(void) close(desc);
		setfd(-1);
		return (err);
	}

	// Save the length of the data and the size of the file header
	origlen = GetLength();
	hdrsize = (off_t)lseek(desc, (off_t)0, SEEK_CUR);
	if (hdrsize < 0) {
		(void) close(desc);
		setfd(-1);
		return (err);
	}
	seekpos = 0;

	// If this is ReadOnly file, mmap() it.  Don't worry if mmap() fails.
	if (!GetAccess().Writeable()) {
		maplen = st.st_size;

		/*
		 * Can't mmap LITTLE_ENDIAN as they are converted in
		 * place.
		 */
		if (localByteOrder() == BIG_ENDIAN) {
			if ((mapaddr = (caddr_t)mmap(0, (int)maplen, PROT_READ,
				MAP_SHARED, desc, 0)) != (caddr_t)-1) {
				// set default access method
				(void) madvise(mapaddr, (unsigned int)maplen,
				    (int)GetAccessType());
			} else {
				(void) RaiseError(AUDIO_UNIXERROR, Warning,
				    (char *)"Could not mmap() file");
				mapaddr = 0;
				maplen = 0;
			}
		} else {
			mapaddr = 0;
			maplen = 0;
		}
	}
	return (AUDIO_SUCCESS);
}

// set VM access hint for mmapped files
AudioError AudioFile::
SetAccessType(VMAccess vmacc)
{
	if (!opened()) {
		return (AUDIO_ERR_NOEFFECT);
	}

	if (mapaddr == 0) {
		return (AUDIO_ERR_NOEFFECT);
	}

	(void) madvise(mapaddr, (unsigned int)maplen, (int)vmacc);
	vmaccess = vmacc;

	return (AUDIO_SUCCESS);
}

// Close the file
AudioError AudioFile::
Close()
{
	AudioError	err;

	if (!opened())
		return (RaiseError(AUDIO_ERR_NOEFFECT, Warning));

	// Rewind the file and rewrite the header with the correct length
	if (GetAccess().Writeable() && (origlen != GetLength())) {

		// sanity check
		if (GetHeader().Time_to_Bytes(GetLength()) !=
		    (lseek(getfd(), (off_t)0, SEEK_END) - hdrsize)) {
			PrintMsg(_MGET_(
			    "AudioFile:Close()...inconsistent length\n"),
			    Fatal);
		}

		// XXX - should be rewritten in C++
		err = (AudioError) audio_rewrite_filesize(getfd(), FILE_AU,
		    (uint_t)GetHeader().Time_to_Bytes(GetLength()), 0, 0);
	}

	// Call the generic file close routine
	err = AudioUnixfile::Close();

	if (mapaddr) {
		munmap(mapaddr, (int)maplen);
		mapaddr = 0;
		maplen = 0;
	}

	// Init important values, in case the file is reopened
	hdrsize = 0;
	seekpos = 0;
	return (RaiseError(err));
}

// Read data from underlying file into specified buffer.
// No data format translation takes place.
// The object's read position pointer is unaffected.
AudioError AudioFile::
ReadData(
	void*		buf,		// destination buffer address
	size_t&		len,		// buffer length (updated)
	Double&		pos)		// start position (updated)
{
	off_t		offset;
	size_t		cnt;
	caddr_t		cp;
	AudioError	err;

	// If the file is not mapped, call parent ReadData() and return
	if (mapaddr == 0) {
		// Call the real routine
		err = AudioUnixfile::ReadData(buf, len, pos);
		// Update the cached seek pointer
		seekpos += len;
		return (err);
	}

	// If the file is mmapped, do a memcpy() from the mapaddr

	// Save buffer size and zero transfer count
	cnt = (size_t)len;
	len = 0;

	// Cannot read if file is not open
	if (!opened() || !GetAccess().Readable())
		return (RaiseError(AUDIO_ERR_NOEFFECT));

	// Position must be valid
	if (Undefined(pos) || (pos < 0.) || ((int)cnt < 0))
		return (RaiseError(AUDIO_ERR_BADARG));

	// Make sure we don't read off the end of file
	offset = GetHeader().Time_to_Bytes(pos);

	if ((offset + hdrsize) >= maplen) {
		// trying to read past EOF
		err = AUDIO_EOF;
		err.sys = AUDIO_COPY_INPUT_EOF;
		return (err);
	} else if ((offset + hdrsize + cnt) > maplen) {
		// re-adjust cnt so it reads up to the end of file
		cnt = (size_t)(maplen - (offset + hdrsize));
	}

	// Zero-length reads are finished
	if (GetHeader().Bytes_to_Bytes(cnt) == 0) {
		err = AUDIO_SUCCESS;
		err.sys = AUDIO_COPY_ZERO_LIMIT;
		return (err);
	} else {
		cp = mapaddr + offset + hdrsize;
		memcpy((void*)buf, (void*)cp, cnt);
	}

	// Return the updated byte count and position
	len = cnt;
	pos = GetHeader().Bytes_to_Time(offset + len);

	// Check to see if the endian is right. Note that special care
	// doesn't need to be taken because of the mmap, since the data
	// is copied into a separate buffer anyway.
	coerceEndian((unsigned char *)buf, len, localByteOrder());

	return (AUDIO_SUCCESS);
}

// Write data to underlying file from specified buffer.
// No data format translation takes place.
// The object's write position pointer is unaffected.
AudioError AudioFile::
WriteData(
	void*		buf, // source buffer address
	size_t&		len, // buffer length (updated)
	Double&		pos) // start position (updated)
{
	AudioError	err;

	// Call the real routine
	err = AudioUnixfile::WriteData(buf, len, pos);

	// Update the cached seek pointer
	seekpos += len;
	return (err);
}

// Set the Unix file pointer to match a given file position.
AudioError AudioFile::
seekread(
	Double		pos,	// position to seek to
	off_t&		offset)	// returned byte offset
{
	offset = GetHeader().Time_to_Bytes(pos);
	if (offset != seekpos) {
		if (lseek(getfd(), (off_t)(hdrsize + offset), SEEK_SET) < 0)
			return (RaiseError(AUDIO_UNIXERROR, Warning));
		seekpos = offset;
	}
	return (AUDIO_SUCCESS);
}

// Set the Unix file pointer to match a given file position.
// If seek beyond end-of-file, NULL out intervening data.
AudioError AudioFile::
seekwrite(
	Double		pos,	// position to seek to
	off_t&		offset)	// returned byte offset
{
	// If append-only, can't seek backwards into file
	if (GetAccess().Append() && (pos < GetLength()))
		return (RaiseError(AUDIO_ERR_NOEFFECT, Warning));

	// If seek beyond eof, fill data
	if (pos > GetLength()) {
		seekwrite(GetLength(), offset);	// seek to eof

		// XXX - not implemented yet

		return (AUDIO_SUCCESS);
	}

	offset = GetHeader().Time_to_Bytes(pos);
	if (offset != seekpos) {
		if (lseek(getfd(), (off_t)(hdrsize + offset), SEEK_SET) < 0)
			return (RaiseError(AUDIO_UNIXERROR, Warning));
		seekpos = offset;
	}
	return (AUDIO_SUCCESS);
}

// Copy routine that handles mapped files
AudioError AudioFile::
AsyncCopy(
	Audio*		to,			// audio object to copy to
	Double&		frompos,
	Double&		topos,
	Double&		limit)
{
	caddr_t		bptr;
	size_t		offset;
	size_t		cnt;
	size_t		svlim;
	Double		svfrom;
	Double		svto;
	AudioHdr	tohdr;
	AudioError	err;

	// If this is NOT mmapped, or the destination is an AudioBuffer,
	// use the default routine
	if ((mapaddr == 0) || to->isBuffer()) {
		return (Audio::AsyncCopy(to, frompos, topos, limit));
	}

	tohdr = to->GetHeader();
	if (err = tohdr.Validate())
		return (err);
	if (limit < 0.)
		return (RaiseError(AUDIO_ERR_BADARG));
	svlim = (size_t)tohdr.Time_to_Bytes(limit);

	// Get maximum possible copy length
	svfrom = GetLength();
	if ((frompos >= svfrom) || ((cnt = (size_t)
	    GetHeader().Time_to_Bytes(svfrom - frompos)) == 0)) {
		limit = 0.;
		err = AUDIO_EOF;
		err.sys = AUDIO_COPY_INPUT_EOF;
		return (err);
	}
	if (!Undefined(limit) && (svlim < cnt))
		cnt = svlim;

	limit = 0.;

	offset = (size_t)GetHeader().Time_to_Bytes(frompos);
	if ((offset + hdrsize) >= maplen) {
		// trying to read past EOF
		err = AUDIO_EOF;
		err.sys = AUDIO_COPY_INPUT_EOF;
		return (err);
	} else if ((offset + hdrsize + cnt) > maplen) {
		// re-adjust cnt so it reads up to the end of file
		cnt = (size_t)(maplen - (offset + hdrsize));
	}

	// Zero-length reads are done
	if (GetHeader().Bytes_to_Bytes(cnt) == 0) {
		err = AUDIO_SUCCESS;
		err.sys = AUDIO_COPY_ZERO_LIMIT;
		return (err);
	}

	// Write the data to the destination and update pointers/ctrs
	svfrom = frompos;
	svto = topos;
	svlim = cnt;
	bptr = mapaddr + hdrsize + offset;
	err = to->WriteData(bptr, cnt, topos);
	limit = topos - svto;
	frompos = svfrom + limit;

	// Report short writes
	if (!err && (cnt < svlim))
		err.sys = AUDIO_COPY_SHORT_OUTPUT;
	return (err);
}
