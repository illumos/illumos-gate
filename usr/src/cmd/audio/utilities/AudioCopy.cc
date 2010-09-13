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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdlib.h>
#include <errno.h>
#include <Audio.h>
#include <AudioBuffer.h>
#include <AudioLib.h>

// Generic Audio functions


// Data format translation occurs transparently
AudioError
AudioCopy(
	Audio*		from,		// input source
	Audio*		to)		// output sink
{
	Double		frompos = 0.;
	Double		topos   = 0.;
	Double		limit   = AUDIO_UNKNOWN_TIME;

	return (AudioCopy(from, to, frompos, topos, limit));
}

// Copy a data stream
// Data format translation occurs transparently
AudioError
AudioCopy(
	Audio*		from,		// input source
	Audio*		to,		// output sink
	Double&		frompos,	// input position (updated)
	Double&		topos,		// output position (updated)
	Double&		limit)		// amount to copy (updated)
{
	return (from->Copy(to, frompos, topos, limit));
}

// Copy one segment of a data stream
// Data format translation occurs transparently
AudioError
AudioAsyncCopy(
	Audio*		from,		// input source
	Audio*		to,		// output sink
	Double&		frompos,	// input position (updated)
	Double&		topos,		// output position (updated)
	Double&		limit)		// amount to copy (updated)
{
	return (from->AsyncCopy(to, frompos, topos, limit));
}
