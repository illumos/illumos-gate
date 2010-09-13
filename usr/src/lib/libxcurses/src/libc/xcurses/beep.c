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
 * Copyright (c) 1995, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * beep.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/beep.c 1.2 1995/07/14 20:51:19 ant Exp $";
#endif
#endif

#include <private.h>

/*f
 * Sound the current terminal's audible bell if it has one. If 
 * not, flash the screen if possible.
 */
int
beep()
{
#ifdef M_CURSES_TRACE
	__m_trace("beep(void)");
#endif

	if (bell != (char *) 0)
		(void) tputs(bell, 1, __m_outc);
	else if (flash_screen != (char *) 0)
		(void) tputs(flash_screen, 1, __m_outc);

	(void) fflush(__m_screen->_of);

	return __m_return_code("beep", OK);
}

/*f
 * flash() - Flash the current terminal's screen if possible. If not,
 * sound the audible bell if one exists.
 */
int
flash()
{
#ifdef M_CURSES_TRACE
	__m_trace("flash(void)");
#endif

	if (flash_screen != (char *) 0)
		(void) tputs(flash_screen, 1, __m_outc);
	else if (bell != (char *) 0)
		(void) tputs(bell, 1, __m_outc);

	(void) fflush(__m_screen->_of);

	return __m_return_code("flash", OK);
}
