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
 * wio_get.c
 *
 * Wide I/O Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] =
"$Header: /team/ps/sun_xcurses/archive/local_changes/xcurses/src/lib/"
"libxcurses/src/libc/wide/rcs/wio_get.c 1.3 1998/05/22 17:56:47 "
"cbates Exp $";
#endif
#endif

#include <mks.h>
#include <errno.h>
#include <m_wio.h>

/*
 * Return a wide character or WEOF for EOF or error.
 *
 * The function referenced by "get" is passed the pointer "object"
 * and returns an input byte or EOF if no further data available.
 *
 * This mechanism is used to do conversions of byte strings or
 * streams into wide characters without loss of information in the
 * case of a bad multibyte character conversion.  The bad multibyte
 * sequence is passed through as individual bytes.
 */
wint_t
m_wio_get(t_wide_io *wio)
{
	int	ch;
	wchar_t	wc;

	if (wio == NULL || wio->get == (int (*)(void *)) NULL) {
		errno = EINVAL;
		return (-1);
	}

	/* Do still have bytes available? */
	if (wio->_next < wio->_size) {
		return ((wint_t)wio->_mb[wio->_next++]);
	}

	/* Read in enough bytes to convert a multibyte character. */
	wio->_size = 0;
	for (wio->_next = 0; wio->_next < (int)MB_CUR_MAX; ) {
		if ((ch = (*wio->get)(wio->object)) == EOF) {
			break;
		}

		wio->_mb[wio->_next] = (unsigned char)ch;

		wio->_size = mbtowc(&wc, (char *)wio->_mb, wio->_next + 1);

		++wio->_next;

		if (0 <= wio->_size) {
			/* Remember the number of bytes converted. */
			wio->_size = wio->_next;

			return ((wint_t) wc);
		}
	}

	/*
	 * If we fill the multibyte character buffer or receive an
	 * EOF without recognising a multibyte character, then we
	 * will return individual bytes from the buffer.  The buffer
	 * is restored to its state before the bogus byte sequence
	 * was read.
	 */
	wio->_size = wio->_next;
	wio->_next = 0;

	return (0 < wio->_size ? (wint_t) wio->_mb[wio->_next++] : WEOF);
}
