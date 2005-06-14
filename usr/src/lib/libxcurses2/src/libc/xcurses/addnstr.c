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
 * addnstr.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/addnstr.c 1.3 "
"1995/07/07 17:59:11 ant Exp $";
#endif
#endif

#include <private.h>

#undef addnstr

int
addnstr(const char *str, int n)
{
	int code;

	code = waddnstr(stdscr, str, n);

	return (code);
}

#undef mvaddnstr

int
mvaddnstr(int y, int x, const char *str, int n)
{
	int code;

	if ((code = wmove(stdscr, y, x)) == OK)
		code = waddnstr(stdscr, str, n);

	return (code);
}

#undef mvwaddnstr

int
mvwaddnstr(WINDOW *w, int y, int x, const char *str, int n)
{
	int code;

	if ((code = wmove(w, y, x)) == OK)
		code = waddnstr(w, str, n);

	return (code);
}

#undef addstr

int
addstr(const char *str)
{
	int code;

	code = waddnstr(stdscr, str, -1);

	return (code);
}

#undef mvaddstr

int
mvaddstr(int y, int x, const char *str)
{
	int code;

	if ((code = wmove(stdscr, y, x)) == OK)
		code = waddnstr(stdscr, str, -1);

	return (code);
}

#undef mvwaddstr

int
mvwaddstr(WINDOW *w, int y, int x, const char *str)
{
	int code;

	if ((code = wmove(w, y, x)) == OK)
		code = waddnstr(w, str, -1);

	return (code);
}

#undef waddstr

int
waddstr(WINDOW *w, const char *str)
{
	int code;

	code = waddnstr(w, str, -1);

	return (code);
}
