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
 * echo_wch.c
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
"libxcurses/src/libc/xcurses/rcs/echo_wch.c 1.2 1998/05/12 19:24:31 "
"cbates Exp $";
#endif
#endif

#include <private.h>

#undef echo_wchar

int
echo_wchar(const cchar_t *ch)
{
	int	code;
	int	code1;

	code1 = wadd_wch(stdscr, ch);
	code = wrefresh(stdscr);

	return ((code1 == OK) ? code : code1);
}

#undef wecho_wchar

int
wecho_wchar(WINDOW *w, const cchar_t *ch)
{
	int code;
	int code1;

	code1 = wadd_wch(w, ch);
	code = wrefresh(w);

	return ((code1 == OK) ? code : code1);
}
