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
 * inchn.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/inchn.c 1.1 "
"1995/06/13 21:05:53 ant Exp $";
#endif
#endif

#include <private.h>

#undef inchnstr

int
inchnstr(chtype *chs, int n)
{
	int code;

	code = winchnstr(stdscr, chs, n);

	return (code);
}

#undef mvinchnstr

int
mvinchnstr(int y, int x, chtype *chs, int n)
{
	int code;

	if ((code = wmove(stdscr, y, x)) == OK)
		code = winchnstr(stdscr, chs, n);

	return (code);
}

#undef mvwinchnstr

int
mvwinchnstr(WINDOW *w, int y, int x, chtype *chs, int n)
{
	int code;

	if ((code = wmove(w, y, x)) == OK)
		code = winchnstr(w, chs, n);

	return (code);
}

#undef inchstr

int
inchstr(chtype *chs)
{
	int code;

	code = winchnstr(stdscr, chs, -1);

	return (code);
}

#undef mvinchstr

int
mvinchstr(int y, int x, chtype *chs)
{
	int code;

	if ((code = wmove(stdscr, y, x)) == OK)
		code = winchnstr(stdscr, chs, -1);

	return (code);
}

#undef mvwinchstr

int
mvwinchstr(WINDOW *w, int y, int x, chtype *chs)
{
	int code;

	if ((code = wmove(w, y, x)) == OK)
		code = winchnstr(w, chs, -1);

	return (code);
}

#undef winchstr

int
winchstr(WINDOW *w, chtype *chs)
{
	int code;

	code = winchnstr(w, chs, -1);

	return (code);
}
