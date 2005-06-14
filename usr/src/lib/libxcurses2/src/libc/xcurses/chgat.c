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
 * chgat.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/chgat.c 1.1 "
"1995/06/05 19:04:08 ant Exp $";
#endif
#endif

#include <private.h>

#undef chgat

int
chgat(int n, attr_t at, short co, const void *opts)
{
	int code;

	code = wchgat(stdscr, n, at, co, opts);

	return (code);
}

#undef mvchgat

int
mvchgat(int y, int x, int n, attr_t at, short co, const void *opts)
{
	int code;

	if ((code = wmove(stdscr, y, x)) == OK)
		code = wchgat(stdscr, n, at, co, opts);

	return (code);
}

#undef mvwchgat

int
mvwchgat(WINDOW *w, int y, int x, int n, attr_t at,
	short co, const void *opts)
{
	int code;

	if ((code = wmove(w, y, x)) == OK)
		code = wchgat(w, n, at, co, opts);

	return (code);
}
