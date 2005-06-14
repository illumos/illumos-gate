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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <AudioExtent.h>
#include <AudioList.h>
#include <AudioDebug.h>

// class AudioList methods


// class AudioListEntry Constructor
AudioList::AudioListEntry::
AudioListEntry(
	Audio*		obj):			// audio object to point to
	aptr(0), next(0), prev(0)
{
	// A NULL object is only valid in dummy entries, such as list heads
	newptr(obj);
}

// class AudioListEntry Destructor
AudioList::AudioListEntry::
~AudioListEntry()
{
	newptr(0);
	if (next != 0) {
		next->prev = prev;
	}
	if (prev != 0) {
		prev->next = next;
	}
}

// Set a new extent pointer in an AudioListEntry
void AudioList::AudioListEntry::
newptr(
	Audio*		newa)		// new object
{
	if (aptr != 0)
		aptr->Dereference();
	aptr = newa;
	if (aptr != 0)
		aptr->Reference();
}

	// Link object into list
// Link in a new AudioListEntry
void AudioList::AudioListEntry::
link(
	AudioListEntry*	after)		// link after this one
{
	// Link object into list
	prev = after;
	next = after->next;
	after->next = this;
	if (next != 0)
		next->prev = this;
}

// Split an AudioListEntry at the specified offset
void AudioList::AudioListEntry::
split(
	Double		pos)		// split offset
{
	AudioExtent*	e1;
	AudioExtent*	e2;
	AudioListEntry*	newp;

	// Create two extents referencing this object
	e1 = new AudioExtent(aptr, 0., pos);
	e2 = new AudioExtent(aptr, pos, AUDIO_UNKNOWN_TIME);

	// Set the current entry to the first extent and append the second
	newptr(e1);
	newp = new AudioListEntry(e2);
	newp->link(this);
}


// class AudioList Constructor
AudioList::
AudioList(
	const char  *local_name):		// name string
	Audio(local_name), head(0)
{
}

// class AudioList Destructor
AudioList::
~AudioList()
{
	// Delete all entries in the list
	while (first() != 0)
		delete first();
}

// Get the first entry in the list
AudioList::AudioListEntry* AudioList::
first() const
{
	return (head.next);
}

// Get the extent and offset corresponding to a given position
// Return FALSE if no extents in list or position is beyond eof
Boolean AudioList::
getposition(
	Double&			pos,		// target position (updated)
	AudioListEntry*&	ep) const	// returned extent pointer
{
	Double			length;

	// Position must be specified
	if (Undefined(pos))
		return (FALSE);

	// Get the first extent in the list
	ep = first();
	while (ep != 0) {
		// Get length of extent
		length = ep->aptr->GetLength();
		if (Undefined(length)) {
			// Can't determine sizes beyond this
			return (TRUE);
		}
		// If the remaining offset is inside the current extent
		if (length > pos)
			return (TRUE);

		// Move on to the next extent
		pos -= length;
		ep = ep->next;
	}
	return (FALSE);
}

// Get the total length of the audio list
Double AudioList::
GetLength() const
{
	AudioListEntry*	ep;
	Double		sum;
	Double		x;

	for (sum = 0., ep = first(); ep != 0; ep = ep->next) {
		// Accumulate times for each extent
		// Indeterminate extents screw up the calculation
		x = ep->aptr->GetLength();
		if (Undefined(x))
			return (x);
		sum += x;
	}
	return (sum);
}

// Construct a name for the list
char *AudioList::
GetName() const
{
	// XXX - construct a better name
	return (Audio::GetName());
}

// Get the audio header for the current read position
AudioHdr AudioList::
GetHeader()
{
	return (GetHeader(ReadPosition()));
}

// Get the audio header for the given position
AudioHdr AudioList::
GetHeader(
	Double		pos)		// position
{
	AudioListEntry*	ep;

	// Get the extent pointer for the given position
	if (!getposition(pos, ep)) {
		AudioHdr	h;

		if (pos != 0.) {
			PrintMsg(_MGET_(
			    "AudioHdr:GetHeader()...position is beyond eof"),
			    Warning);
			return (h);
		}
		if ((ep = first()) != 0)
			return (ep->aptr->GetHeader());
		return (h);
	}
	// Get the header for the proper offset in the extent
	return (ep->aptr->GetDHeader(pos));
}

// Copy data from list into specified buffer.
// No data format translation takes place.
// The object's read position is not updated.
//
// Since list could contain extents of differing encodings,
// clients should always use GetHeader() in combination with ReadData()
AudioError AudioList::
ReadData(
	void*		buf,		// destination buffer address
	size_t&		len,		// buffer size (updated)
	Double&		pos)		// start position (updated)
{
	AudioListEntry*	ep;
	size_t		cnt;
	Double		off;
	Double		newpos;
	AudioError	err;

	// Save buffer size
	cnt = len;

	// Position must be valid
	if (Undefined(pos) || (pos < 0.) || ((int)cnt < 0))
		return (RaiseError(AUDIO_ERR_BADARG));

	// Loop until data is returned or error
	// XXX - THIS IS WRONG!  THE HEADER COULD CHANGE!
	do {
		// Get the extent/offset for read position; clear return count
		len = 0;
		off = pos;
		if (!getposition(off, ep)) {
			err = AUDIO_EOF;
			err.sys = AUDIO_COPY_INPUT_EOF;
			return (err);
		}

		// Save the offset and read some data
		newpos = off;
		len = cnt;
		err = ep->aptr->ReadData(buf, len, newpos);

		// If no eof on this list entry, or no more data, we're done
		if ((err != AUDIO_EOF) || (err.sys != AUDIO_COPY_INPUT_EOF) ||
		    (ep->next == 0)) {
			break;
		}

		// Advance to next list entry
		// XXX - Is this problemmatic, too?
		pos += ep->aptr->GetLength() - off;
	} while (TRUE);

	// Update the byte count and position
	pos += (newpos - off);		// XXX - recalculate?
	return (err);
}

// Write to AudioList is (currently) prohibited
AudioError AudioList::
WriteData(
	void*,				// destination buffer address
	size_t&		len,		// buffer size (updated)
	Double&)			// start position (updated)
{
	len = 0;
	return (RaiseError(AUDIO_ERR_NOEFFECT));
}

// Insert an entry at the start
AudioError AudioList::
Insert(
	Audio*		obj)		// object to insert
{
	Double		pos;		// insertion offset, in seconds

	return (Insert(obj, pos = 0.));
}

// Insert an entry at a specified position
AudioError AudioList::
Insert(
	Audio*		obj,		// object to insert
	Double		pos)		// insertion offset, in seconds
{
	AudioListEntry	*ep;
	AudioListEntry	*prev;

	// Find the insertion point
	if (first() == 0) {
		prev = &head;		// this is the first extent
	} else {
		if (!getposition(pos, prev)) {
			if (pos == 0.) {
				// Append extent to end of list
				return (Append(obj));
			} else {
				return (RaiseError(AUDIO_ERR_BADARG));
			}
		} else if (pos != 0.) {
			// The insertion is in an extent, split it in two
			prev->split(pos);
		} else {
			// Insert before the current position
			prev = prev->prev;
		}
	}
	// Create object and link into list
	ep = new AudioListEntry(obj);
	ep->link(prev);

	return (AUDIO_SUCCESS);
}

// Append an entry to a list
AudioError AudioList::
Append(
	Audio*		obj)		// object to append
{
	AudioListEntry	*ep;
	AudioListEntry	*prev;

	// Find the last extent in the list
	for (prev = &head; prev->next != 0; prev = prev->next)
		continue;

	// Create object and link into list
	ep = new AudioListEntry(obj);
	ep->link(prev);
	return (AUDIO_SUCCESS);
}

// Copy routine for lists
AudioError AudioList::
AsyncCopy(
	Audio*		to,			// audio object to copy to
	Double&		frompos,		// input pos (updated)
	Double&		topos,			// output pos (updated)
	Double&		limit)			// amt to copy (updated)
{
	AudioListEntry*	ep;
	Double		svlim;
	Double		newpos;
	Double		off;
	AudioError	err;

	svlim = limit;
	// Loop until data is returned or error
	// XXX - THIS IS WRONG!  THE HEADER COULD CHANGE!
	do {
		// Get the extent and offset for the read position
		off = frompos;
		if (!getposition(off, ep)) {
			// nothing written, limit should reflect this
			limit = 0.0;
			err = AUDIO_EOF;
			err.sys = AUDIO_COPY_INPUT_EOF;
			return (err);
		}

		// Save the offset and do a copy
		newpos = off;
		limit = svlim;
		err = ep->aptr->AsyncCopy(to, newpos, topos, limit);

		// If no eof on this list entry, or no more data, we're done
		if ((err != AUDIO_EOF) || (err.sys != AUDIO_COPY_INPUT_EOF) ||
		    (ep->next == 0)) {
			break;
		}

		// Advance to next list entry
		// XXX - Is this problemmatic, too?
		frompos += ep->aptr->GetLength() - off;
	} while (TRUE);

	// Update the byte count and  position
	frompos += (newpos - off); // XXX - recalculate?
	return (err);
}
