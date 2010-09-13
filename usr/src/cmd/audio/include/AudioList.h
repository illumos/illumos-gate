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

#ifndef _MULTIMEDIA_AUDIOLIST_H
#define	_MULTIMEDIA_AUDIOLIST_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <Audio.h>

#ifdef __cplusplus
extern "C" {
#endif

// This is the 'base' class for a list of extents of audio objects
class AudioList : public Audio {

	// Define a linked list nested class
	class AudioListEntry {
	private:
		void operator=(AudioListEntry);	// Assignment is illegal
	public:
		Audio*		aptr;		// pointer to audio object
		AudioListEntry*	next;		// pointer to next in list
		AudioListEntry*	prev;		// pointer to previous

		// Constructor w/obj
		AudioListEntry(
		    Audio* obj);		// referenced audio object
		~AudioListEntry();		// Destructor

		void newptr(Audio* newa);	// Reset extent

		// Link in new extent
		void link(
		    AudioListEntry* after);	// link after this one

		// Split an extent
		void split(
		    Double pos);		// split at offset
	};

private:
	AudioListEntry		head;		// list head

	AudioListEntry* first() const;		// Return first extent

	// Locate extent/offset
	virtual Boolean getposition(
	    Double& pos,			// target position (updated)
	    AudioListEntry*& ep) const;		// returned entry pointer

	AudioList operator=(AudioList);		// Assignment is illegal

public:
	AudioList(const char *name = "[list]");	// Constructor
	virtual ~AudioList();			// Destructor

	// class Audio methods specialized here
	virtual Double GetLength() const;	// Get length, in secs
	virtual char *GetName() const;		// Get name string
	virtual AudioHdr GetHeader();		// Get header
	virtual AudioHdr GetHeader(Double pos);	// Get header at pos

	// Read from position
	virtual AudioError ReadData(
	    void* buf,				// buffer to fill
	    size_t& len,			// buffer length (updated)
	    Double& pos);			// start position (updated)

	// Write is prohibited
	virtual AudioError WriteData(
	    void* buf,				// buffer to copy
	    size_t& len,			// buffer length (updated)
	    Double& pos);			// start position (updated)

	virtual Boolean isList() const { return (TRUE); }

	// list manipulation methods
	// Insert an entry
	virtual AudioError Insert(
	    Audio* obj);			// object to insert

	// Insert an entry
	virtual AudioError Insert(
	    Audio* obj,				// object to insert
	    Double pos);			// insertion offset, in seconds

	// Append an entry
	virtual AudioError Append(
	    Audio* obj);			// object to append

	// copy to another audio obj.
	virtual AudioError AsyncCopy(
	    Audio* ap,				// dest audio object
	    Double& frompos,
	    Double& topos,
	    Double& limit);
};

#ifdef __cplusplus
}
#endif

#endif /* !_MULTIMEDIA_AUDIOLIST_H */
