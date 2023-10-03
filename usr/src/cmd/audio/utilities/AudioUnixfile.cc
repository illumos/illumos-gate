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
 * Copyright 1993-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/t_lock.h>

#include <AudioDebug.h>
#include <AudioUnixfile.h>
#include <libaudio.h>
#include <audio_hdr.h>
#include <audio/au.h>

// class AudioUnixfile methods

// Constructor with pathname and mode arg
AudioUnixfile::
AudioUnixfile(
	const char		*path,		// pathname
	const FileAccess	acc):		// access mode
	AudioStream(path), fd(-1), block(TRUE), mode(acc),
	infostring(new char[1]), infolength(1)
{
	infostring[0] = '\0';
}

// Destructor
AudioUnixfile::
~AudioUnixfile()
{
	// If the file is open, close it
	if (opened())
		(void) Close();

	// Deallocate the dynamic storage
	delete infostring;
}

// Generic open with search path routine just calls default Open()
AudioError AudioUnixfile::
OpenPath(
	const char *)
{
	return (Open());
}

// Decode an audio file header
// This routine reads the audio file header and decodes it.
//
// This method should be specialized by subclasses that are not files,
// like devices for instance.
//
// XXX - this routine should be rewritten for C++
AudioError AudioUnixfile::
decode_filehdr()
{
	Boolean		saveblock;	// saved state of the blocking i/o flag
	AudioHdr	hdr_local;	// local copy of header
	Audio_hdr	ohdr;		// XXX - old libaudio hdr
	au_filehdr_t	fhdr;
	char		*ibuf;
	int		file_type;
	int		infosize;
	int		cnt;
	struct stat	st;
	AudioError	err;

	// If fd is not open, or file header already decoded, skip it
	if (!isfdset() || opened())
		return (RaiseError(AUDIO_ERR_NOEFFECT, Warning));

	// Stat the file, to see if it is a regular file
	if (fstat(getfd(), &st) < 0)
		return (RaiseError(AUDIO_UNIXERROR));

	// Make sure the file is not set for blocking i/o
	saveblock = GetBlocking();
	if (!saveblock)
		SetBlocking(TRUE);

	// Read the file header, but not the info field
	// XXX - Should use C++ input method
	cnt = read(getfd(), (char *)&fhdr, sizeof (fhdr));
	if (cnt != sizeof (fhdr)) {
		return (RaiseError(AUDIO_UNIXERROR));
	}

	// Check the validity of the header and get the size of the info field
	err = (AudioError) audio_decode_filehdr(getfd(), (unsigned char *)&fhdr,
	    &file_type, &ohdr, &infosize);
	if (err != AUDIO_SUCCESS)
		return (RaiseError(err));

	// Allocate and read in the info field
	ibuf = new char[infosize];
	cnt = read(getfd(), ibuf, infosize);
	if (cnt != infosize) {
		delete[] ibuf;
		return (RaiseError(AUDIO_UNIXERROR));
	}
	SetBlocking(saveblock);		// Restore the saved blocking i/o state

	// XXX - convert from libaudio header
	hdr_local = GetHeader();
	hdr_local.sample_rate = ohdr.sample_rate;
	hdr_local.samples_per_unit = ohdr.samples_per_unit;
	hdr_local.bytes_per_unit = ohdr.bytes_per_unit;
	hdr_local.channels = ohdr.channels;
	hdr_local.encoding = (AudioEncoding) ohdr.encoding;
	hdr_local.endian = BIG_ENDIAN; // Files are always written in
					// big endian.

	err = SetHeader(hdr_local);
	if (err != AUDIO_SUCCESS) {
		delete[] ibuf;
		return (RaiseError(err));
	}
	SetInfostring(ibuf, infosize);
	delete[] ibuf;

	// Only trust the file size for regular files
	if (S_ISREG(st.st_mode)) {
		setlength(GetHeader().Bytes_to_Time(
		    st.st_size - infosize - sizeof (au_filehdr_t)));

		// Sanity check
		if ((ohdr.data_size != AUDIO_UNKNOWN_SIZE) &&
		    (GetLength() != GetHeader().Bytes_to_Time(ohdr.data_size)))
			PrintMsg(_MGET_(
			    "AudioUnixfile: header/file size mismatch"));

		// always consider it to be unknown if not reading a real file
		// since there's no real way to verify if the header is
		// correct.
	} else {
		setlength(AUDIO_UNKNOWN_TIME);
	}

	// set flag for opened() test
	filehdrset = TRUE;

	return (AUDIO_SUCCESS);
}

// Write an audio file header
// This routine encodes the audio file header and writes it out.
// XXX - It assumes that the file pointer is set to the start of the file.
//
// This method should be specialized by subclasses that are not files,
// like devices for instance.
//
// XXX - this routine should be rewritten for C++
AudioError AudioUnixfile::
encode_filehdr()
{
	Boolean		saveblock;	// saved state of the blocking i/o flag
	AudioHdr	hdr_local;	// local copy of header
	Audio_hdr	ohdr;		// XXX - old libaudio hdr
	AudioError	err;

	// If fd is not open, or file header already written, skip it
	if (!isfdset() || opened())
		return (RaiseError(AUDIO_ERR_NOEFFECT, Warning));

	// XXX - Set up the libaudio hdr
	hdr_local = GetHeader();
	hdr_local.endian = BIG_ENDIAN; // Files are always written big endian.
	err = SetHeader(hdr_local);
	if (err != AUDIO_SUCCESS) {
		return (RaiseError(err));
	}

	ohdr.sample_rate = hdr_local.sample_rate;
	ohdr.samples_per_unit = hdr_local.samples_per_unit;
	ohdr.bytes_per_unit = hdr_local.bytes_per_unit;
	ohdr.channels = hdr_local.channels;
	ohdr.encoding = hdr_local.encoding;
	if (Undefined(GetLength()))
		ohdr.data_size = AUDIO_UNKNOWN_SIZE;
	else
		ohdr.data_size = (uint_t)GetHeader().Time_to_Bytes(GetLength());

	/* Make sure the file is not set for blocking i/o */
	saveblock = GetBlocking();
	if (!saveblock)
		SetBlocking(TRUE);

	// XXX - Should use C++ output method
	err = (AudioError) audio_write_filehdr(getfd(), &ohdr, FILE_AU,
	    infostring, infolength);

	// set flag for opened() test
	if (err == AUDIO_SUCCESS)
		filehdrset = TRUE;

	SetBlocking(saveblock);		// Restore the saved blocking i/o state
	return (RaiseError(err));
}

// Set a file blocking/non-blocking
// This method should be subclassed by objects that always block (eg, files)
void AudioUnixfile::
SetBlocking(
	Boolean		b)			// FALSE to set non-blocking
{
	int		flag;

	// If the file is open, set blocking/non-blocking now
	if (isfdset()) {
		flag = fcntl(getfd(), F_GETFL, 0);
		if ((flag < 0) && (errno == EOVERFLOW || errno == EINVAL)) {
			RaiseError(AUDIO_UNIXERROR, Fatal,
			    (char *)"Large File");
		} else if (b) {
			flag &= ~(O_NDELAY | O_NONBLOCK);	// set blocking
		} else {
			flag |= O_NONBLOCK;		// set non-blocking
		}
		if (fcntl(getfd(), F_SETFL, flag) < 0) {
			RaiseError(AUDIO_UNIXERROR, Warning);
		}
	}
	// Set the blocking flag (this may affect the Open() behavior)
	block = b;
}

// Return a pointer to the info string
// XXX - returns a pointer to the string stored in the object
// XXX - assumes ASCII data
char *const AudioUnixfile::
GetInfostring(
	int&		len) const		// returned length of string
{
	len = infolength;
	return (infostring);
}

// Set the info string
void AudioUnixfile::
SetInfostring(
	const char	*str,			// new info string
	int		len)			// length of string
{
	// If length defaulted, assume an ASCII string
	if (len == -1)
		len = strlen(str) + 1;
	delete infostring;
	infostring = new char[len];
	infolength = len;
	(void) memcpy(infostring, str, len);
}

// Close file
AudioError AudioUnixfile::
Close()
{
	// If the file is open, close it
	if (isfdset()) {
		if (close(getfd()) < 0)
			return (RaiseError(AUDIO_UNIXERROR));
	} else {
		return (RaiseError(AUDIO_ERR_NOEFFECT, Warning));
	}

	// Init important values, in case the file is reopened
	setfd(-1);
	filehdrset = FALSE;
	(void) SetReadPosition((Double)0., Absolute);
	(void) SetWritePosition((Double)0., Absolute);
	return (AUDIO_SUCCESS);
}

// Read data from underlying file into specified buffer.
// No data format translation takes place.
// The object's read position is not updated (subclasses can change this)
AudioError AudioUnixfile::
ReadData(
	void*		buf,		// destination buffer address
	size_t&		len,		// buffer length (updated)
	Double&		pos)		// start position (updated)
{
	off_t		offset;
	off_t		cnt;
	AudioError	err;

	// Save buffer size and zero transfer count
	cnt = (off_t)len;
	len = 0;

	// Cannot read if file is not open
	if (!opened() || !mode.Readable())
		return (RaiseError(AUDIO_ERR_NOEFFECT));

	// Position must be valid
	if (Undefined(pos) || (pos < 0.) || (cnt < 0))
		return (RaiseError(AUDIO_ERR_BADARG));

	// Position the file pointer to the right place
	err = seekread(pos, offset);
	if (err != AUDIO_SUCCESS)
		return (err);

	// Check for EOF
	if (pos >= GetLength()) {
		err = AUDIO_EOF;
		err.sys = AUDIO_COPY_INPUT_EOF;
		return (err);
	}

	// Zero-length reads are finished
	if (GetHeader().Bytes_to_Bytes(cnt) == 0) {
		err = AUDIO_SUCCESS;
		err.sys = AUDIO_COPY_ZERO_LIMIT;
		return (err);
	}

	// Read as much data as possible
	cnt = read(fd, (char *)buf, (int)cnt);
	if (cnt < 0) {
		if (errno == EOVERFLOW) {
			perror("read");
			exit(1);
		} else if ((errno == EINTR) ||
		    (((errno == EWOULDBLOCK) || (errno == EAGAIN)) &&
		    !GetBlocking())) {
		// Is this an interrupted or failed non-blocking request?
			err = AUDIO_SUCCESS;
			err.sys = AUDIO_COPY_SHORT_INPUT;
			return (err);
		}
		return (RaiseError(AUDIO_UNIXERROR));
	}

	// End-of-file?
	if ((cnt == 0) && GetBlocking()) {
		if (isDevice() || isPipe()) {
			AUDIO_DEBUG((1,
			    "Zero-length blocking device/pipe read?!\n"));
		}
		err = AUDIO_EOF;
		err.sys = AUDIO_COPY_INPUT_EOF;
		return (err);
	}
	err = AUDIO_SUCCESS;
	if (cnt == 0) {
		err.sys = AUDIO_COPY_SHORT_INPUT;
	}

	// Return the updated byte count and position
	len = (size_t)cnt;
	if (GetHeader().Bytes_to_Bytes(cnt) != len) {
		AUDIO_DEBUG((1,
		    "Read returned a partial sample frame?!\n"));
	}
	pos = GetHeader().Bytes_to_Time(offset + len);

	// Check to see if the endian is right.
	coerceEndian((unsigned char *)buf, len, localByteOrder());

	return (err);
}

// Write data to underlying file from specified buffer.
// No data format translation takes place.
// The object's write position is not updated (subclasses can change this)
AudioError AudioUnixfile::
WriteData(
	void*		buf,		// source buffer address
	size_t&		len,		// buffer length (updated)
	Double&		pos)		// start position (updated)
{
	off_t		offset;
	off_t		cnt;
	AudioError	err;

	// Save buffer size and zero transfer count
	cnt = (off_t)len;
	len = 0;

	// Cannot write if file is not open
	if (!opened() || !mode.Writeable())
		return (RaiseError(AUDIO_ERR_NOEFFECT));

	// Position must be valid
	if (Undefined(pos) || (pos < 0.) || (cnt < 0))
		return (RaiseError(AUDIO_ERR_BADARG));

	// Zero-length writes are easy
	if (GetHeader().Bytes_to_Bytes(cnt) == 0) {
		err = AUDIO_SUCCESS;
		err.sys = AUDIO_COPY_ZERO_LIMIT;
		return (err);
	}

	// Position the file pointer to the right place
	err = seekwrite(pos, offset);
	if (err != AUDIO_SUCCESS)
		return (err);

	// Make sure data is in target's endian format before writing.
	// This conversion is done inplace so we need to change back.
	// We assume that the data in buf is in localByteOrder.
	// Only files should have order issues.
	if (localByteOrder() != GetHeader().endian)
		coerceEndian((unsigned char *)buf, (size_t)cnt, SWITCH_ENDIAN);

	// Write as much data as possible
	err = AUDIO_SUCCESS;
	cnt = write(fd, (char *)buf, (int)cnt);
	if (cnt < 0) {
		if (errno == EFBIG) {
			perror("write");
			exit(1);
		} else if ((errno == EWOULDBLOCK) || (errno == EAGAIN)) {
			// Is this a failed non-blocking request?
			err.sys = AUDIO_COPY_SHORT_OUTPUT;
			return (err);
		}
		return (RaiseError(AUDIO_UNIXERROR));
	}
	if (cnt == 0)
		err.sys = AUDIO_COPY_SHORT_OUTPUT;

	// Switch the endian back if local order doesn't match target order.
	if (localByteOrder() != GetHeader().endian)
		coerceEndian((unsigned char *)buf, (size_t)cnt, SWITCH_ENDIAN);

	// Return the updated byte count and position
	len = (size_t)cnt;
	pos = GetHeader().Bytes_to_Time(offset + len);

	// If the current position is beyond old EOF, update the size
	if (!Undefined(GetLength()) && (pos > GetLength())) {
		setlength(pos);
	}

	return (AUDIO_SUCCESS);
}

// Seek in input stream
// Ordinary streams (ie, pipes and devices) cannot be rewound.
// A forward seek in them consumes data by reading it.
//
// This method should be specialized by subclasses that can actually seek,
// like regular files for instance.
//
AudioError AudioUnixfile::
seekread(
	Double		pos,		// position to seek to
	off_t&		offset)		// returned byte offset
{
	char		*bufp;		// temporary input buffer
	size_t		bufl;		// input buffer size
	size_t		cnt;		// input byte count
	long		icnt;		// read size
	Boolean		saveblock;	// saved state of the blocking i/o flag
	Double		buflen;
	AudioError	err;

	offset = GetHeader().Time_to_Bytes(pos);
	pos -= ReadPosition();

	// If the seek is backwards, do nothing
	if (pos < 0.)
		return (RaiseError(AUDIO_ERR_NOEFFECT, Warning));

	// If the seek is to the current position, then do nothing.
	icnt = GetHeader().Time_to_Bytes(pos);
	if (icnt == 0)
		return (AUDIO_SUCCESS);

	// The seek is determinate and forward.
	// We'll have to consume data to get there.
	// First allocate a buffer to stuff the data into.
	// Then set the stream for blocking i/o (saving the old state).
	buflen = max(pos, 1.);
	bufl = (size_t)GetHeader().Time_to_Bytes(buflen);
	bufp = new char[bufl];
	if (bufp == 0) {		// allocation error, try a smaller buf
		bufl = (size_t)sysconf(_SC_PAGESIZE);
		bufp = new char[bufl];
		if (bufp == 0)
			return (RaiseError(AUDIO_UNIXERROR));
	}
	// XXX - May have to realign to partial frame count!

	saveblock = GetBlocking();
	if (!saveblock)
		SetBlocking(TRUE);

	// Loop until the seek is satisfied (or an error occurs).
	do {
		// Limit the read to keep from going too far
		cnt = (icnt >= (long)bufl) ? bufl : (size_t)icnt;
		err = Read(bufp, cnt);
		if (err != AUDIO_SUCCESS)
			break;
		icnt -= (long)cnt;
	} while (icnt > 0);

	SetBlocking(saveblock);		// Restore the saved blocking i/o state
	delete[] bufp;			// Free the temporary buffer
	return (RaiseError(err));
}

// Seek in output stream
// Ordinary streams (ie, pipes and devices) cannot be rewound.
// A forward seek in them writes NULL data.
//
// This method should be specialized by subclasses that can actually seek,
// like regular files for instance.
//
AudioError AudioUnixfile::
seekwrite(
	Double		pos,		// position to seek to
	off_t&		offset)		// returned byte offset
{
	char		*bufp;		// temporary output buffer
	size_t		bufl;		// output buffer size
	size_t		cnt;		// output byte count
	long		ocnt;		// write size
	Boolean		saveblock;	// saved state of the blocking i/o flag
	Double		buflen;
	AudioError	err;

	offset = GetHeader().Time_to_Bytes(pos);
	pos -= WritePosition();

	// If the seek is backwards, do nothing
	if (pos < 0.)
		return (RaiseError(AUDIO_ERR_NOEFFECT, Warning));

	// If the seek is to the current position, then do nothing.
	ocnt = GetHeader().Time_to_Bytes(pos);
	if (ocnt == 0)
		return (AUDIO_SUCCESS);

	// The seek is determinate and forward.
	// We'll have to produce NULL data to get there.
	// XXX - not implemented correctly yet
	buflen = max(pos, 1.);
	bufl = (size_t)GetHeader().Time_to_Bytes(buflen);
	bufp = new char[bufl];
	if (bufp == 0) {		// allocation error, try a smaller buf
		bufl = (size_t)sysconf(_SC_PAGESIZE);
		bufp = new char[bufl];
		if (bufp == 0)
			return (RaiseError(AUDIO_UNIXERROR));
	}

	// XXX - May have to realign to partial frame count!
	saveblock = GetBlocking();
	if (!saveblock)
		SetBlocking(TRUE);

	// Loop until the seek is satisfied (or an error occurs).
	do {
		// Limit the write to keep from going too far
		cnt = (ocnt >= (long)bufl) ? bufl : (size_t)ocnt;
		err = Write(bufp, cnt);
		if (err != AUDIO_SUCCESS)
			break;
		ocnt -= (long)cnt;
	} while (ocnt > 0);

	SetBlocking(saveblock);		// Restore the saved blocking i/o state
	delete[] bufp;			// Free the temporary buffer
	return (RaiseError(err));
}
