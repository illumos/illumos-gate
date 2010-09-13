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
 * Copyright (c) 1995-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* LINTLIBRARY */

/*
 * wtouchln.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] =
"$Header: /team/ps/sun_xcurses/archive/local_changes/xcurses/src/lib/"
"libxcurses/src/libc/xcurses/rcs/wtouchln.c 1.6 1998/06/03 12:57:09 "
"cbates Exp $";
#endif
#endif

#include <private.h>

/*
 * Given a window, start from line y, and mark n lines either as touched
 * or untouched since the last call to wrefresh().
 */
int
wtouchln(WINDOW *w, int y, int n, int bf)
{
	int	first, last;

	first = bf ? 0 : w->_maxx;
	last = bf ? w->_maxx : -1;

	for (; y < w->_maxy && 0 < n; ++y, --n) {
		w->_first[y] = (short) first;
		w->_last[y] = (short) last;
	}

	return (OK);
}
