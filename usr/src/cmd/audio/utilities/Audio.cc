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
 * Copyright (c) 1993-2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <Audio.h>
#include <AudioDebug.h>
#include <AudioBuffer.h>

// class Audio methods


// Initialize monotonically increasing id counter
int
Audio::idctr = 0;

// Constructor
Audio::
Audio(
	const char	*str):				// name
	id(++idctr), refcnt(0), readpos(0.), writepos(0.), errorfunc(0)
{
	char		*s;

	s = (char *)((str == NULL) ? "" : str);
	name = new char[strlen(s) + 1];
	(void) strcpy(name, s);

#ifndef DEBUG
	// errorfunc is always set if compiling DEBUG;
	// otherwise, only if requested
	if (GetDebug() > 0)
#endif
		errorfunc = AudioStderrMsg;
	PrintMsg(_MGET_("Audio object create"), InitMessage);
}

// Destructor
Audio::
~Audio()
{
	// If there are outstanding references, there is a programming error
	if (refcnt < 0) {
		PrintMsg(_MGET_("Audio object multiple destroy"), InitFatal);
	} else if (refcnt > 0) {
		PrintMsg(_MGET_("Referenced Audio object destroyed"),
		    InitFatal);
	} else {
		refcnt = -1;
		PrintMsg(_MGET_("Audio object destroy"), InitMessage);
	}
	delete name;
}

// Raise error code
AudioError Audio::
RaiseError(
	AudioError	code,			// error code
	AudioSeverity	sev,			// error severity
	const char	*msg) const		// additional message
{
	if (code == AUDIO_SUCCESS)
		return (code);

	if (errorfunc != 0) {
		// XXX - Userfunc return value ignored for now
		(void) (*errorfunc)(this, code, sev, msg);
	}
	if ((sev == Fatal) || (sev == InitFatal))
		abort();
	return (code);
}

// Print out messages
void Audio::
PrintMsg(
	char		*msg,			// error message
	AudioSeverity	sev) const		// error severity
{
	if (errorfunc != 0) {
		// XXX - Userfunc return value ignored for now
		(void) (*errorfunc)(this, AUDIO_NOERROR, sev, msg);
	}

	if ((sev == Fatal) || (sev == InitFatal)) {
		fprintf(stderr, _MGET_("** Fatal Error: %s\n"), msg);
		abort();
	}
}

// Increment reference count
void Audio::
Reference()
{
	if (refcnt < 0) {
		PrintMsg(_MGET_("Reference to destroyed Audio object"), Fatal);
	} else {
		refcnt++;
	}
}

// Decrement reference count
void Audio::
Dereference()
{
	if (refcnt < 0) {
		PrintMsg(_MGET_("Dereference of destroyed Audio object"),
		    Fatal);
	} else if (refcnt == 0) {
		PrintMsg(_MGET_("Audio object dereference underflow"), Fatal);
	} else if (--refcnt == 0) {	// If this was the last reference,
		delete this;		//  blow the object away
	}
}

// Reset the stored name
void Audio::
SetName(
	const char	*str)		// new name string
{
	delete name;
	name = new char[strlen(str) + 1];
	(void) strcpy(name, str);
}


// Set the current read/write position pointer
Double Audio::
setpos(
	Double&	pos,			// field to update
	Double	newpos,			// new position
	Whence	w)			// Absolute || Relative || Relative_eof
{
	if (w == Relative)			// offset from current position
		newpos += pos;
	else if (w == Relative_eof) {		// offset from end-of-file
		if (!Undefined(GetLength()))
			newpos += GetLength();
		else
			return (AUDIO_UNKNOWN_TIME);
	}

	// If seek before start of file, set to start of file
	if (newpos < 0.)
		newpos = 0.;
	pos = newpos;
	return (pos);
}

// Set a new read position
Double Audio::
SetReadPosition(
	Double		pos,		// new position or offset
	Whence		w)		// Absolute | Relative
{
	return (setpos(readpos, pos, w));
}

// Set a new write position
Double Audio::
SetWritePosition(
	Double		pos,		// new position or offset
	Whence		w)		// Absolute | Relative
{
	return (setpos(writepos, pos, w));
}

// Default read routine reads from the current position
AudioError Audio::
Read(
	void*		buf,			// buffer address
	size_t&		len)			// buffer length (updated)
{
	// ReadData updates the position argument
	return (ReadData(buf, len, readpos));
}

// Default write routine writes to the current position
AudioError Audio::
Write(
	void*		buf,			// buffer address
	size_t&		len)			// buffer length (updated)
{
	// WriteData updates the position argument
	return (WriteData(buf, len, writepos));
}

// Default append routine should be specialized, if the object is fixed-length
AudioError Audio::
AppendData(
	void*		buf,			// buffer address
	size_t&		len,			// buffer length (updated)
	Double&		pos)			// write position (updated)
{
	// The default action is just to write the data.
	// Subclasses, like AudioBuffer, should specialize this method
	// to extend the object, if necessary.
	return (WriteData(buf, len, pos));
}

// Copy out to the specified audio object.
// Input and output positions default to the 'current' positions.
AudioError Audio::
Copy(
	Audio*		to)			// audio object to copy to
{
	Double		frompos = AUDIO_UNKNOWN_TIME;
	Double		topos = AUDIO_UNKNOWN_TIME;
	Double		limit = AUDIO_UNKNOWN_TIME;

	return (Copy(to, frompos, topos, limit));
}

// Default Copy out routine. Specify the destination audio object,
// and src/dest start offsets.  limit is either the time to copy or
// AUDIO_UNKNOWN_TIME to copy to eof or error.
// frompos and topos are updated with the final positions.
// limit is updated with the amount of data actually copied.
AudioError Audio::
Copy(
	Audio*		to,			// audio object to copy to
	Double&		frompos,
	Double&		topos,
	Double&		limit)
{
	Double		len;
	Double		svpos;
	AudioError	err;

	// If positions are Undefined, try to set them properly
	if (Undefined(frompos))
		frompos = ReadPosition();
	if (Undefined(topos))
		topos = to->WritePosition();

	svpos = frompos;
	do {
		// Calculate remaining copy size
		if (Undefined(limit)) {
			len = limit;
		} else {
			len = limit - (frompos - svpos);
			if (len < 0.)
				len = 0.;
		}
		// Copy one segment
		err = AsyncCopy(to, frompos, topos, len);
		if (!err) {
			switch (err.sys) {
			default:
			case 0:
				break;

			// XXX - What do we do with short writes?
			//	 This routine is meant to block until all the
			//	 data has been copied.  So copies to a pipe or
			//	 device should continue.  However, copies to a
			//	 buffer (or extent or list?) will never go any
			//	further.
			// For now, punt and return immediately.
			case AUDIO_COPY_SHORT_OUTPUT:
				goto outofloop;

			// If a zero-length transfer was requested, we're done
			case AUDIO_COPY_ZERO_LIMIT:
				goto outofloop;

			// If the input would block, we're done
			case AUDIO_COPY_SHORT_INPUT:
				goto outofloop;
			}
		}
	} while (err == AUDIO_SUCCESS);
outofloop:
	// Calculate total transfer count
	limit = frompos - svpos;

	// Declare victory if anything was copied
	if (limit > 0.)
		return (AUDIO_SUCCESS);
	return (err);
}

// Default Data Copy out routine. Like Copy(), but only does one segment.
// If either src or dest are set non-blocking, a partial transfer may occur.
// Returns AUDIO_SUCCESS on normal completion, regardless of how much data
// was actually transferred (err.sys: AUDIO_COPY_SHORT_INPUT if input would
// block;  AUDIO_COPY_ZERO_LIMIT if a zero-length copy was requested).
// Returns AUDIO_SUCCESS (err.sys: AUDIO_COPY_SHORT_OUTPUT) if more data was
// read than could be copied out (eg, if there was a short write to a
// non-blocking output).  Short writes result in the input pointer being
// backed up to the right place in the input stream.
// Returns AUDIO_EOF if input or output position beyond end-of-file.
//
// XXX - If the input cannot seek backwards, this routine will spin trying
//	 to finish writing all input data to the output.  We need to keep
//	 partial data in a state structure.
AudioError Audio::
AsyncCopy(
	Audio*		to,			// audio object to copy to
	Double&		frompos,
	Double&		topos,
	Double&		limit)
{
	caddr_t		bptr;
	size_t		bufsiz;
	size_t		lim;
	Double		svfrom;
	Double		svto;
	AudioBuffer*	tob;
	AudioHdr	tohdr;
	AudioError	err;

	// Validate basic arguments and state
	tohdr = to->GetHeader();
	if (err = tohdr.Validate())
		return (err);
	if (limit < 0.)
		return (RaiseError(AUDIO_ERR_BADARG));
	lim = (size_t)tohdr.Time_to_Bytes(limit);

	// If the destination is an AudioBuffer, we can copy more directly
	if (to->isBuffer()) {
		tob = (AudioBuffer*) to;

		// Get the buffer address at the starting offset
		bptr = (caddr_t)tob->GetAddress(topos);
		bufsiz = bptr - (caddr_t)tob->GetAddress();
		if ((bptr == NULL) || (tob->GetByteCount() <= bufsiz)) {
			limit = 0.;
			err = AUDIO_EOF;
			err.sys = AUDIO_COPY_OUTPUT_EOF;
			return (err);
		}
		bufsiz = tob->GetByteCount() - bufsiz;

		// Limit the data transfer by the limit argument
		if (!Undefined(limit) && (lim < bufsiz))
			bufsiz = lim;

		// Read the data directly into buffer
		(void) tohdr.Bytes_to_Bytes(bufsiz);
		err = ReadData((void*) bptr, bufsiz, frompos);
		limit = tohdr.Bytes_to_Time(bufsiz);
		topos += limit;
		tob->SetLength(topos);
		return (err);
	}

	// XXX - temporary bogus implementation
	// XXX - max transfer buf will be 2 seconds of data (1 sec for stereo)
	if (tohdr.channels < 2) {
		bufsiz = (size_t)tohdr.Time_to_Bytes(2.0);
	} else {
		bufsiz = (size_t)tohdr.Time_to_Bytes(1.0);
	}
	if (!Undefined(limit) && (lim < bufsiz))
		bufsiz = lim;

	limit = 0.;
	if ((bptr = new char[bufsiz]) == NULL)
		return (AUDIO_UNIXERROR);

	svfrom = frompos;
	err = ReadData((void*)bptr, bufsiz, frompos);
	if (!err) {
		svto = topos;
		lim = bufsiz;
		if (tohdr.Bytes_to_Bytes(bufsiz) != lim) {
			AUDIO_DEBUG((1,
			    "Read returned a fraction of a sample frame?!\n"));
			lim = bufsiz;
		}
		if (bufsiz > 0) {
			err = to->WriteData(bptr, bufsiz, topos);
			limit = topos - svto;

			// If the write was short, back up the input pointer
			if (bufsiz < lim) {
				lim = bufsiz;
				if (tohdr.Bytes_to_Bytes(bufsiz) != lim) {
					AUDIO_DEBUG((1,
		    "Write returned a fraction of a sample frame?!\n"));
				}
				frompos = svfrom + limit;
				if (!err)
					err.sys = AUDIO_COPY_SHORT_OUTPUT;
			}
		}
	}
	delete bptr;
	return (err);
}
