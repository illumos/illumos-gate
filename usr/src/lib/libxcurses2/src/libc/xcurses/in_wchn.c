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
 * in_wchn.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/in_wchn.c 1.1 "
"1995/06/13 21:14:26 ant Exp $";
#endif
#endif

#include <private.h>

#undef in_wchnstr

int
in_wchnstr(cchar_t *ccs, int n)
{
	int code;

	code = win_wchnstr(stdscr, ccs, n);

	return (code);
}

#undef mvin_wchnstr

int
mvin_wchnstr(int y, int x, cchar_t *ccs, int n)
{
	int code;

	if ((code = wmove(stdscr, y, x)) == OK)
		code = win_wchnstr(stdscr, ccs, n);

	return (code);
}

#undef mvwin_wchnstr

int
mvwin_wchnstr(WINDOW *w, int y, int x, cchar_t *ccs, int n)
{
	int code;

	if ((code = wmove(w, y, x)) == OK)
		code = win_wchnstr(w, ccs, n);

	return (code);
}

#undef in_wchstr

int
in_wchstr(cchar_t *ccs)
{
	int code;

	code = win_wchnstr(stdscr, ccs, -1);

	return (code);
}

#undef mvin_wchstr

int
mvin_wchstr(int y, int x, cchar_t *ccs)
{
	int code;

	if ((code = wmove(stdscr, y, x)) == OK)
		code = win_wchnstr(stdscr, ccs, -1);

	return (code);
}

#undef mvwin_wchstr

int
mvwin_wchstr(WINDOW *w, int y, int x, cchar_t *ccs)
{
	int code;

	if ((code = wmove(w, y, x)) == OK)
		code = win_wchnstr(w, ccs, -1);

	return (code);
}

#undef win_wchstr

int
win_wchstr(WINDOW *w, cchar_t *ccs)
{
	int code;

	code = win_wchnstr(w, ccs, -1);

	return (code);
}
