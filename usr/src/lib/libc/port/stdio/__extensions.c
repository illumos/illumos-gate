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

#include "lint.h"
#include "file64.h"
#include <sys/types.h>
#include <stdio.h>
#include <mtlib.h>
#include "stdiom.h"
#include <stdio_ext.h>

/*
 * Returns non-zero if the file is open readonly, or if the last operation
 * on the stream was a read e.g. fread() or fgetc().  Otherwise returns 0.
 */
int
__freading(FILE *stream)
{
	return (stream->_flag & _IOREAD);
}

/*
 * Returns non-zero if the file is open write-only or append-only, or if
 * the last operation on the stream was a write e.g. fwrite() or fputc().
 * Otherwise returns 0.
 */
int
__fwriting(FILE *stream)
{
	return (stream->_flag & _IOWRT);
}

/*
 * Returns non-zero if it is possible to read from a stream.
 */
int
__freadable(FILE *stream)
{
	return (stream->_flag & (_IOREAD|_IORW));
}

/*
 * Returns non-zero if it is possible to write on a stream.
 */
int
__fwritable(FILE *stream)
{
	return (stream->_flag & (_IOWRT|_IORW));
}

/*
 * Returns non-zero if the stream is line buffered.
 */
int
__flbf(FILE *stream)
{
	return (stream->_flag & _IOLBF);
}

/*
 * Discard any pending buffered I/O.
 */
void
__fpurge(FILE *stream)
{
	rmutex_t *lk;

	FLOCKFILE(lk, stream);
	if ((stream->_ptr = stream->_base) != NULL)
		stream->_cnt = 0;
	FUNLOCKFILE(lk);
}

/*
 * Return the amount of output pending on a stream (in bytes).
 */
size_t
__fpending(FILE *stream)
{
	size_t amount;
	rmutex_t *lk;

	FLOCKFILE(lk, stream);
	amount = stream->_ptr - stream->_base;
	FUNLOCKFILE(lk);
	return (amount);
}

/*
 * Returns the buffer size (in bytes) currently in use by the given stream.
 */
size_t
__fbufsize(FILE *stream)
{
	size_t size;
	rmutex_t *lk;

	FLOCKFILE(lk, stream);
	size = _bufend(stream) - stream->_base;
	FUNLOCKFILE(lk);
	return (size);
}
