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

#include	<sys/types.h>
#include	"curses_inc.h"

/*
 * Get the current screen coordinates (y, x).
 *
 * The current screen coordinates are defined as the last place that
 * the cursor was placed by a wnoutrefresh(), pnoutrefresh() or setsyx()
 * call. If leaveok() was true for the last window refreshed, then
 * return (-1, -1) so that setsyx() can reset the leaveok flag.
 *
 * This function is actually called by the macro getsyx(y, x), which is
 * defined in curses.h as:
 *
 * #define getsyx(y, x)	_getsyx(&y, &x)
 *
 * Note that this macro just adds in the '&'. In this way, getsyx()
 * is parallel with the other getyx() routines which don't require
 * ampersands. The reason that this can't all be a macro is that
 * that we need to access SP, which is normally not available in
 * user-level routines.
 */

int
_getsyx(int *yp, int *xp)
{
	if (SP->virt_scr->_leave)
		*yp = *xp = -1;
	else {
		*yp = _virtscr->_cury - SP->Yabove;
		*xp = _virtscr->_curx;
	}
	return (OK);
}
