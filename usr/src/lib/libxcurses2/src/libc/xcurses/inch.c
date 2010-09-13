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
 * inch.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/inch.c 1.1 "
"1995/06/12 20:24:39 ant Exp $";
#endif
#endif

#include <private.h>

#undef inch

chtype
inch(void)
{
	chtype ch;

	ch = winch(stdscr);

	return (ch);
}

#undef mvinch

chtype
mvinch(int y, int x)
{
	chtype ch;

	if ((ch = (chtype) wmove(stdscr, y, x)) != (chtype) ERR)
		ch = winch(stdscr);

	return (ch);
}

#undef mvwinch

chtype
mvwinch(WINDOW *w, int y, int x)
{
	chtype ch;

	if ((ch = (chtype) wmove(w, y, x)) != (chtype) ERR)
		ch = winch(w);

	return (ch);
}
