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
 * Copyright 1992-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _MULTIMEDIA_AUDIO_H
#define	_MULTIMEDIA_AUDIO_H

#include <AudioTypes.h>
#include <AudioError.h>
#include <AudioHdr.h>

#ifdef __cplusplus
extern "C" {
#endif

// Error-handling function declaration
class Audio;
typedef Boolean	(*AudioErrfunc)(const Audio*, AudioError, AudioSeverity,
    const char *);


// Data transfer subcodes.
// Returned from ReadData(), WriteData(), AsyncCopy(), Copy() in err.sys
enum AudioCopyFlag {
    AUDIO_COPY_SHORT_INPUT = 100,	// AUDIO_SUCCESS: input would block
    AUDIO_COPY_ZERO_LIMIT = 101,	// AUDIO_SUCCESS: length was zero
    AUDIO_COPY_SHORT_OUTPUT = 102,	// AUDIO_SUCCESS: only partial output
    AUDIO_COPY_INPUT_EOF = 103,		// AUDIO_EOF: eof on input
    AUDIO_COPY_OUTPUT_EOF = 104		// AUDIO_EOF: eof on output
};



// This is the abstract base class from which all audio data types derive.
// It is invalid to create an object of type Audio.

class Audio {
private:
	static int	idctr;			// id seed value

	int		id;			// object id number
	int		refcnt;			// reference count
	char		*name;			// name
	Double		readpos;		// current read position ptr
	Double		writepos;		// current write position ptr
	AudioErrfunc	errorfunc;		// address of error function

protected:
	void SetName(const char *str);		// Set name string

	// Set position
	Double setpos(
	    Double& pos,			// position field to update
	    Double newpos,			// new position
	    Whence w = Absolute);		// Absolute || Relative

// XXX - should these be protected?
public:
	int getid() const;			// Get id value

	// Raise error code
	virtual AudioError RaiseError(
	    AudioError code,			// error code
	    AudioSeverity sev = Error,		// error severity
	    const char *msg = "unknown error") const;		// error message

	// Raise error msg
	virtual void PrintMsg(
	    char *msg,				// error code
	    AudioSeverity sev = Message) const;	// error severity

public:
	Audio(const char *str = "");		// Constructor
	virtual ~Audio();			// Destructor

	void Reference();			// Increment ref count
	void Dereference();			// Decrement ref count
	Boolean isReferenced() const;		// TRUE if referenced

	virtual char *GetName() const;		// Get name string

	// Set user error func
	virtual void SetErrorFunction(
	    AudioErrfunc func);			// return TRUE if non-fatal

	virtual Double ReadPosition() const;	// Get read position
	virtual Double WritePosition() const;	// Get write position

	// Set read position
	virtual Double SetReadPosition(
	    Double pos,				// new position
	    Whence w = Absolute);		// Absolute || Relative

	// Set write position
	virtual Double SetWritePosition(
	    Double pos,				// new position
	    Whence w = Absolute);		// Absolute || Relative

	// Read from current pos
	virtual AudioError Read(
	    void* buf,				// buffer to fill
	    size_t& len);			// buffer length (updated)

	// Write to current pos
	virtual AudioError Write(
	    void* buf,				// buffer to copy
	    size_t& len);			// buffer length (updated)

	// XXX - no Append() method for now because of name clashes

	// methods specialized by inherited classes
	virtual AudioHdr GetHeader() = 0;	// Get header
	virtual AudioHdr GetDHeader(Double);	// Get header at pos
	virtual Double GetLength() const = 0;	// Get length, in secs

	// Read from position
	virtual AudioError ReadData(
	    void* buf,				// buffer to fill
	    size_t& len,			// buffer length (updated)
	    Double& pos) = 0;			// start position (updated)

	// Write at position
	virtual AudioError WriteData(
	    void* buf,				// buffer to copy
	    size_t& len,			// buffer length (updated)
	    Double& pos) = 0;			// start position (updated)

	// Write and extend
	virtual AudioError AppendData(
	    void* buf,				// buffer to copy
	    size_t& len,			// buffer length (updated)
	    Double& pos);			// start position (updated)

	// copy to another audio obj.
	virtual AudioError Copy(
	    Audio* ap);				// dest audio object

	// copy to another audio obj.
	virtual AudioError Copy(
	    Audio* ap,				// dest audio object
	    Double& frompos,
	    Double& topos,
	    Double& limit);

	// copy to another audio obj.
	virtual AudioError AsyncCopy(
	    Audio* ap,				// dest audio object
	    Double& frompos,
	    Double& topos,
	    Double& limit);

	// Define default classification routines
	// The appropriate routine should be specialized by each leaf class.
	virtual Boolean isFile() const { return (FALSE); }
	virtual Boolean isDevice() const { return (FALSE); }
	virtual Boolean isDevicectl() const { return (FALSE); }
	virtual Boolean isPipe() const { return (FALSE); }
	virtual Boolean isBuffer() const { return (FALSE); }
	virtual Boolean isExtent() const { return (FALSE); }
	virtual Boolean isList() const { return (FALSE); }
};

#include <Audio_inline.h>

#ifdef __cplusplus
}
#endif

#endif /* !_MULTIMEDIA_AUDIO_H */
