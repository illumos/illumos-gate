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

#ifndef _MULTIMEDIA_AUDIO_INLINE_H
#define	_MULTIMEDIA_AUDIO_INLINE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

// Inline routines for class Audio

// Return object id
inline int Audio::
getid() const
{
	return (id);
}

// Return TRUE if the object is referenced
inline Boolean Audio::
isReferenced() const
{
	return (refcnt > 0);
}

// Access routine for retrieving the current read position pointer
inline Double Audio::
ReadPosition() const
{
	return (readpos);
}

// Access routine for retrieving the current write position pointer
inline Double Audio::
WritePosition() const
{
	return (writepos);
}

// Return the name of an audio object
inline char *Audio::
GetName() const
{
	return (name);
}

// Set the error function callback address
inline void Audio::
SetErrorFunction(
	AudioErrfunc	func)			// function address
{
	errorfunc = func;
}

// Default get header at position routine does a normal GetHeader
inline AudioHdr Audio::
GetDHeader(
	Double)
{
	return (GetHeader());
}

#ifdef __cplusplus
}
#endif

#endif /* !_MULTIMEDIA_AUDIO_INLINE_H */
