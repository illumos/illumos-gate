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
 * ins_nws.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/ins_nws.c 1.1 "
"1995/06/15 15:15:08 ant Exp $";
#endif
#endif

#include <private.h>

#undef ins_nwstr

int
ins_nwstr(const wchar_t *wcs, int n)
{
	int code;

	code = wins_nwstr(stdscr, wcs, n);

	return (code);
}

#undef mvins_nwstr

int
mvins_nwstr(int y, int x, const wchar_t *wcs, int n)
{
	int code;

	if ((code = wmove(stdscr, y, x)) == OK)
		code = wins_nwstr(stdscr, wcs, n);

	return (code);
}

#undef mvwins_nwstr

int
mvwins_nwstr(WINDOW *w, int y, int x, const wchar_t *wcs, int n)
{
	int code;

	if ((code = wmove(w, y, x)) == OK)
		code = wins_nwstr(w, wcs, n);

	return (code);
}

#undef ins_wstr

int
ins_wstr(const wchar_t *wcs)
{
	int code;

	code = wins_nwstr(stdscr, wcs, -1);

	return (code);
}

#undef mvins_wstr

int
mvins_wstr(int y, int x, const wchar_t *wcs)
{
	int code;

	if ((code = wmove(stdscr, y, x)) == OK)
		code = wins_nwstr(stdscr, wcs, -1);

	return (code);
}

#undef mvwins_wstr

int
mvwins_wstr(WINDOW *w, int y, int x, const wchar_t *wcs)
{
	int code;

	if ((code = wmove(w, y, x)) == OK)
		code = wins_nwstr(w, wcs, -1);

	return (code);
}

#undef wins_wstr

int
wins_wstr(WINDOW *w, const wchar_t *wcs)
{
	int code;

	code = wins_nwstr(w, wcs, -1);

	return (code);
}
