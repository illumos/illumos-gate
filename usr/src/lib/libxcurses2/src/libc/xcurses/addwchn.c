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
 * addwchn.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/addwchn.c 1.1 "
"1995/05/30 13:39:41 ant Exp $";
#endif
#endif

#include <private.h>

#undef add_wchnstr

int
add_wchnstr(const cchar_t *ccs, int n)
{
	int code;

	code = wadd_wchnstr(stdscr, ccs, n);

	return (code);
}

#undef mvadd_wchnstr

int
mvadd_wchnstr(int y, int x, const cchar_t *ccs, int n)
{
	int code;

	if ((code = wmove(stdscr, y, x)) == OK)
		code = wadd_wchnstr(stdscr, ccs, n);

	return (code);
}

#undef mvwadd_wchnstr

int
mvwadd_wchnstr(WINDOW *w, int y, int x, const cchar_t *ccs, int n)
{
	int code;

	if ((code = wmove(w, y, x)) == OK)
		code = wadd_wchnstr(w, ccs, n);

	return (code);
}

#undef add_wchstr

int
add_wchstr(const cchar_t *ccs)
{
	int code;

	code = wadd_wchnstr(stdscr, ccs, -1);

	return (code);
}

#undef mvadd_wchstr

int
mvadd_wchstr(int y, int x, const cchar_t *ccs)
{
	int code;

	if ((code = wmove(stdscr, y, x)) == OK)
		code = wadd_wchnstr(stdscr, ccs, -1);

	return (code);
}

#undef mvwadd_wchstr

int
mvwadd_wchstr(WINDOW *w, int y, int x, const cchar_t *ccs)
{
	int code;

	if ((code = wmove(w, y, x)) == OK)
		code = wadd_wchnstr(w, ccs, -1);

	return (code);
}

#undef wadd_wchstr

int
wadd_wchstr(WINDOW *w, const cchar_t *ccs)
{
	int code;

	code = wadd_wchnstr(w, ccs, -1);

	return (code);
}
