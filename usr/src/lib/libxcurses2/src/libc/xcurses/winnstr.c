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
 * Copyright (c) 1995-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* LINTLIBRARY */

/*
 * winnstr.c
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
"libxcurses/src/libc/xcurses/rcs/winnstr.c 1.2 1998/04/30 20:30:40 "
"cbates Exp $";
#endif
#endif

#include <private.h>
#include <string.h>

int
winnstr(WINDOW *w, char *mbs, int n)
{
	int	y, x;

	y = w->_cury;
	x = w->_curx;

	if (n < 0)
		n = w->_maxx + 1;

	/* Write first character as a multibyte string. */
	(void) __m_cc_mbs(&w->_line[y][x], mbs, n);

	/* Write additional characters without colour and attributes. */
	for (; ; ) {
		x = __m_cc_next(w, y, x);
		if (w->_maxx <= x)
			break;
		if (__m_cc_mbs(&w->_line[y][x], NULL, 0) < 0)
			break;
	}

	/* Return to initial shift state and terminate string. */
	(void) __m_cc_mbs(NULL, NULL, 0);

	return ((int)strlen(mbs));
}
