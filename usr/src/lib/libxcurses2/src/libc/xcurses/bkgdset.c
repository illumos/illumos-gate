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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* LINTLIBRARY */

/*
 * bkgdset.c
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
"libxcurses/src/libc/xcurses/rcs/bkgdset.c 1.4 1998/05/28 17:10:12 "
"cbates Exp $";
#endif
#endif

#include <private.h>

#undef bkgdset

void
bkgdset(chtype bg)
{
	wbkgdset(stdscr, bg);
}

#undef wbkgdset

void
wbkgdset(WINDOW *w, chtype bg)
{
	cchar_t	cc;

	(void) __m_chtype_cc(bg, &cc);
	w->_fg._at = (w->_fg._at & ~w->_bg._at) | cc._at;
	w->_bg = cc;
	w->_fg._co = cc._co;
}

#undef getbkgd

chtype
getbkgd(WINDOW *w)
{
	chtype bg;

	bg = __m_cc_chtype(&w->_bg);

	return (bg);
}
