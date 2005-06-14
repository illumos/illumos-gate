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
 * Copyright (c) 1996-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* LINTLIBRARY */

/*
 * wio_put.c
 *
 * Wide I/O Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/wide/rcs/wio_put.c 1.1 "
"1995/07/26 17:51:21 ant Exp $";
#endif
#endif

#include <mks.h>
#include <errno.h>
#include <m_wio.h>

/*
 * Return the number of bytes written.  Errno will be set for errors.
 *
 * The function referenced by "put" is passed a byte value and the
 * pointer "object", and returns the byte value or EOF if no further
 * data can be written.
 */
int
m_wio_put(wint_t wc, t_wide_io *wio)
{
	int	count, mb_len;
	unsigned char	*ptr;

	if (wio == NULL || wio->put == (int (*)(int, void *)) NULL) {
		errno = EINVAL;
		return (-1);
	}

	/* Force shift-in state at end-of-file. */
	if (wc == WEOF)
		wc = L'\0';

	if ((mb_len = wctomb((char *) wio->_mb, wc)) < 0)
		/* Note errno will have been set by wcrtomb(). */
		return (-1);

	/*
	 * When shift-in state has been forced don't write '\0' byte.
	 * The "stream" object is considered to be in "text" mode, in
	 * which case file I/O produces undefined results for systems
	 * using locking-shift character sets.
	 */
	if (wc == '\0')
		--mb_len;

	/* Write multibyte character sequence. */
	for (ptr = wio->_mb, count = 0; count < mb_len; ++ptr, ++count)
		if ((*wio->put)(*ptr, wio->object) == EOF)
			break;

	/* Remember just in case some one needs it. */
	wio->_size = mb_len;
	wio->_next = count;

	return (count);
}
