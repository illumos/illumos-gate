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

#ifndef _MULTIMEDIA_AUDIOLIB_H
#define	_MULTIMEDIA_AUDIOLIB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef NO_EXTERN_C

#ifdef __cplusplus
extern "C" {
#endif

#endif /* NO_EXTERN_C */

#include <Audio.h>

// Declarations for global functions
// Copy entire stream
AudioError AudioCopy(
    Audio*	from,				// input source
    Audio*	to);				// output sink

// Copy data
AudioError AudioCopy(
    Audio*	from,				// input source
    Audio*	to,				// output sink
    Double&	frompos,			// input position (updated)
    Double&	topos,				// output position (updated)
    Double&	limit);				// amount to copy (updated)

// Copy one data segment
AudioError AudioAsyncCopy(
    Audio*	from,				// input source
    Audio*	to,				// output sink
    Double&	frompos,			// input position (updated)
    Double&	topos,				// output position (updated)
    Double&	limit);				// amount to copy (updated)

// Filename->AudioList
AudioError Audio_OpenInputFile(
    const char *path,				// input filename
    Audio*&	ap);				// returned AudioList ptr

// Copy to output file
AudioError Audio_WriteOutputFile(
    const char *path,				// output filename
    const AudioHdr&	hdr,			// output data header
    Audio*	input);				// input data stream

#ifdef NO_EXTERN_C

#ifdef __cplusplus
}
#endif

#endif /* NO_EXTERN_C */

#endif /* !_MULTIMEDIA_AUDIOLIB_H */
