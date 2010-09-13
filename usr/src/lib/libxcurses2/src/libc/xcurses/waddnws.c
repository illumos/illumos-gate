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
 * Copyright (c) 1995-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* LINTLIBRARY */

/*
 * waddnws.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] =
"$Header: /team/ps/sun_xcurses/archive/local_changes/xcurses/src/lib/"
"libxcurses/src/libc/xcurses/rcs/waddnws.c 1.5 1998/05/26 20:00:57 "
"cbates Exp $";
#endif
#endif

#include <private.h>
#include <limits.h>

int
waddnwstr(WINDOW *w, const wchar_t *wcs, int n)
{
	cchar_t	cc;
	short	oflags;

	if (n < 0)
		n = INT_MAX;

	/*
	 * Disable window flushing until the entire string has
	 * been written into the window.
	 */
	oflags = w->_flags & (W_FLUSH | W_SYNC_UP);
	w->_flags &= ~(W_FLUSH | W_SYNC_UP);

	for (; *wcs != '\0' && 0 < n; wcs++, n--) {
		if (__m_wc_cc(*wcs, &cc) < 0)
			return (ERR);
		cc._at = w->_bg._at;
		if (__m_wadd_wch(w, &cc) == ERR)
			return (ERR);
	}
	w->_flags |= oflags;

	WSYNC(w);

	return (WFLUSH(w));
}
