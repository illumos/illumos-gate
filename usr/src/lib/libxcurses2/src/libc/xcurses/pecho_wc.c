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
 * pecho_wc.c
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
"libxcurses/src/libc/xcurses/rcs/pecho_wc.c 1.4 1998/05/22 15:04:28 "
"cbates Exp $";
#endif
#endif

#include <private.h>

int
pecho_wchar(WINDOW *pad, const cchar_t *cc)
{
	int	code, dy, dx;
	int	code1;

	/* Compute height and width of inclusive region. */
	dy = pad->_smaxy - pad->_sminy;
	dx = pad->_smaxx - pad->_sminx;


	/* Is the logical cursor within the previously displayed region? */
	if (pad->_cury < pad->_refy || pad->_curx < pad->_refx ||
		pad->_refy + dy < pad->_cury || pad->_refx + dx < pad->_curx)
		return (ERR);

	/* Add the character to the pad. */
	code1 = wadd_wch(pad, cc);

	/* Redisplay previous region. */
	code = prefresh(pad, pad->_refy, pad->_refx,
		pad->_sminy, pad->_sminx, pad->_smaxy, pad->_smaxx);

	return ((code1) ? code : code1);
}
