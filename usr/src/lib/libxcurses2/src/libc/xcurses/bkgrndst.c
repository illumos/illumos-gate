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
 * bkgrndst.c
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
"libxcurses/src/libc/xcurses/rcs/bkgrndst.c 1.4 1998/05/28 17:10:13 "
"cbates Exp $";
#endif
#endif

#include <private.h>

#undef bkgrndset

void
bkgrndset(const cchar_t *bg)
{
	wbkgrndset(stdscr, bg);
}

#undef wbkgrndset

void
wbkgrndset(WINDOW *w, const cchar_t *bg)
{
	attr_t	attrs;

	attrs = w->_fg._at;
	w->_fg._at = (attrs & ~w->_bg._at) | bg->_at;
	if (w->_fg._co == w->_bg._co) {
		w->_fg._co = bg->_co;
	}
	w->_bg = *bg;
}

#undef getbkgrnd

int
getbkgrnd(cchar_t *bg)
{
	*bg = stdscr->_bg;

	return (OK);
}

#undef wgetbkgrnd

int
wgetbkgrnd(WINDOW *w, cchar_t *bg)
{
	*bg = w->_bg;

	return (OK);
}
