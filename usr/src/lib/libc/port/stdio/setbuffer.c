/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Compatibility wrappers for setbuffer and setlinebuf
 */

#include "lint.h"
#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>

/*
 * Associate a buffer with an "unused" stream.
 * If the buffer is NULL, then make the stream completely unbuffered.
 */
void
setbuffer(FILE *iop, char *abuf, size_t asize)
{
	if (abuf == NULL)
		(void) setvbuf(iop, NULL, _IONBF, 0);
	else
		(void) setvbuf(iop, abuf, _IOFBF, asize);
}

/*
 * Convert a block buffered or line buffered stream to be line buffered
 * Allowed while the stream is still active; relies on the implementation
 * not the interface!
 */

int
setlinebuf(FILE *iop)
{
	(void) fflush(iop);
	(void) setvbuf(iop, NULL, _IOLBF, 128);
	return (0);
}
