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
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * key_name.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/key_name.c 1.1 1995/06/07 13:57:49 ant Exp $";
#endif
#endif

#include <private.h>
#include <string.h>

/*f
 *
 */
const char *
key_name(wchar_t wc)
{
	size_t len;
	cchar_t cc;
	wchar_t *ws;
	static char mbs[MB_LEN_MAX+1];

#ifdef M_CURSES_TRACE
	__m_trace("key_name(%ld)", wc);
#endif

	(void) __m_wc_cc(wc, &cc);

	ws = (wchar_t *) wunctrl(&cc);

	if ((len = wcstombs(mbs, ws, MB_LEN_MAX)) == (size_t) -1)
		return __m_return_pointer("key_name", (const char *) 0);

	mbs[len] = '\0';

#ifdef M_CURSES_TRACE
	__m_trace("key_name returned %p = \"%s\".", mbs, mbs);
#endif
	return mbs;
}
