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
 * Copyright 1997 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

/*
 * Set the current screen coordinates (y, x).
 *
 * This routine may be called before doupdate(). It tells doupdate()
 * where to leave the cursor instead of the location of (x, y) of the
 * last window that was wnoutrefreshed or pnoutrefreshed.
 * If x and y are negative, then the cursor will be left wherever
 * curses decides to leave it, as if leaveok() had been TRUE for the
 * last window refreshed.
 */

#include	<sys/types.h>
#include	"curses_inc.h"

int
setsyx(int y, int x)
{
	if (y < 0 && x < 0) {
		SP->virt_scr->_leave = TRUE;
	} else {
		_virtscr->_cury = y + SP->Yabove;
		/* LINTED */
		_virtscr->_curx = (short) x;
		_virtscr->_leave = FALSE;
		_virtscr->_flags |= _WINMOVED;
	}
	return (OK);
}
