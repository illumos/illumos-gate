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
 * insnstr.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/insnstr.c 1.1 "
"1995/06/15 17:35:00 ant Exp $";
#endif
#endif

#include <private.h>

#undef insnstr

int
insnstr(const char *mbs, int n)
{
	int code;

	code = winsnstr(stdscr, mbs, n);

	return (code);
}

#undef mvinsnstr

int
mvinsnstr(int y, int x, const char *mbs, int n)
{
	int code;

	if ((code = wmove(stdscr, y, x)) == OK)
		code = winsnstr(stdscr, mbs, n);

	return (code);
}

#undef mvwinsnstr

int
mvwinsnstr(WINDOW *w, int y, int x, const char *mbs, int n)
{
	int code;

	if ((code = wmove(w, y, x)) == OK)
		code = winsnstr(w, mbs, n);

	return (code);
}

#undef insstr

int
insstr(const char *mbs)
{
	int code;

	code = winsnstr(stdscr, mbs, -1);

	return (code);
}

#undef mvinsstr

int
mvinsstr(int y, int x, const char *mbs)
{
	int code;

	if ((code = wmove(stdscr, y, x)) == OK)
		code = winsnstr(stdscr, mbs, -1);

	return (code);
}

#undef mvwinsstr

int
mvwinsstr(WINDOW *w, int y, int x, const char *mbs)
{
	int code;

	if ((code = wmove(w, y, x)) == OK)
		code = winsnstr(w, mbs, -1);

	return (code);
}

#undef winsstr

int
winsstr(WINDOW *w, const char *mbs)
{
	int code;

	code = winsnstr(w, mbs, -1);

	return (code);
}
