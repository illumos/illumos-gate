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
 * meta.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/meta.c 1.1 1995/05/18 18:20:54 ant Exp $";
#endif
#endif

#include <private.h>

/*f
 * If true, then input will be 8 bits, else 7.
 * NOTE the window parameter is ignored.
 */
int
meta(WINDOW *w, bool bf)
{
#ifdef M_CURSES_TRACE
	__m_trace("meta(%p, %d)", w, bf);
#endif
	cur_term->_prog.c_cflag &= ~CSIZE;
	cur_term->_prog.c_cflag |= bf ? CS8 : CS7; 

	if (__m_tty_set(&cur_term->_prog) == ERR)
		return __m_return_code("meta", ERR); 

	__m_screen->_flags &= ~S_USE_META;

	if (bf) {
		if (meta_on != (char *) 0)
			(void) tputs(meta_on, 1, __m_outc);
		__m_screen->_flags |= S_USE_META;
	} else if (meta_off != (char *) 0) {
		(void) tputs(meta_off, 1, __m_outc);
	}

	return __m_return_code("meta", OK); 
}

