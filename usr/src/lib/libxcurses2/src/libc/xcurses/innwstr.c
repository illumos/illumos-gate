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
 * innwwstr.c
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
"libxcurses/src/libc/xcurses/rcs/innwstr.c 1.2 1998/04/30 20:30:23 "
"cbates Exp $";
#endif
#endif

#include <private.h>

#undef innwstr

int
innwstr(wchar_t *wcs, int n)
{
	int code;

	code = winnwstr(stdscr, wcs, n);

	return (code);
}

#undef mvinnwstr

int
mvinnwstr(int y, int x, wchar_t *wcs, int n)
{
	int code;

	if ((code = wmove(stdscr, y, x)) == OK)
		code = winnwstr(stdscr, wcs, n);

	return (code);
}

#undef mvwinnwstr

int
mvwinnwstr(WINDOW *w, int y, int x, wchar_t *wcs, int n)
{
	int code;

	if ((code = wmove(w, y, x)) == OK)
		code = winnwstr(w, wcs, n);

	return (code);
}

#undef inwstr

int
inwstr(wchar_t *wcs)
{
	int code;

	code = winnwstr(stdscr, wcs, -1);

	return ((code == ERR) ? ERR : OK);
}

#undef mvinwstr

int
mvinwstr(int y, int x, wchar_t *wcs)
{
	int code;

	if ((code = wmove(stdscr, y, x)) == OK)
		code = winnwstr(stdscr, wcs, -1);

	return ((code == ERR) ? ERR : OK);
}

#undef mvwinwstr

int
mvwinwstr(WINDOW *w, int y, int x, wchar_t *wcs)
{
	int code;

	if ((code = wmove(w, y, x)) == OK)
		code = winnwstr(w, wcs, -1);

	return ((code == ERR) ? ERR : OK);
}

#undef winwstr

int
winwstr(WINDOW *w, wchar_t *wcs)
{
	int	code;

	code = winnwstr(w, wcs, -1);

	return ((code == ERR) ? ERR : OK);
}
