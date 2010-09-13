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
 * wclear.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/wclear.c 1.2 "
"1995/07/21 12:58:52 ant Exp $";
#endif
#endif

#include <private.h>

/*
 * Erase window and clear screen next update.
 */
#undef wclear

int
wclear(WINDOW *w)
{
	int	value;

	w->_flags |= W_CLEAR_WINDOW;
	value = werase(w);

	return (value == 0 ? OK : ERR);
}

/*
 * Erase window.
 */
#undef werase

int
werase(WINDOW *w)
{
	int	value;

	w->_cury = 0;
	w->_curx = 0;
	value = __m_cc_erase(w, 0, 0, w->_maxy-1, w->_maxx-1);

	return (value == 0 ? OK : ERR);
}
