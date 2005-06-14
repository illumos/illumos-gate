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
 * wchgat.c
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
"libxcurses/src/libc/xcurses/rcs/wchgat.c 1.3 1998/05/22 19:23:22 "
"cbates Exp $";
#endif
#endif

#include <private.h>

/* ARGSUSED */
int
wchgat(WINDOW *w, int n, attr_t at, short co, const void *opts)
{
	int	i, x;
	cchar_t	*cp;

	if (n < 0)
		n = w->_maxx;

	cp = &w->_line[w->_cury][w->_curx];

	if (!cp->_f)
		return (ERR);

	for (i = 0, x = w->_curx; x < w->_maxx; ++x, ++cp) {
		if (cp->_f && n <= i++)
			break;

		cp->_co = co;
		cp->_at = at;
	}

	if (w->_curx < w->_first[w->_cury])
		w->_first[w->_cury] = w->_curx;
	if (w->_last[w->_cury] < x)
		w->_last[w->_cury] = x;

	WSYNC(w);

	return (WFLUSH(w));
}
