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
 * qiflush.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/qiflush.c 1.1 1995/06/15 18:39:15 ant Exp $";
#endif
#endif

#include <private.h>

void
(qiflush)()
{
#ifdef M_CURSES_TRACE
	__m_trace("qiflush(void)");
#endif

	cur_term->_prog.c_lflag &= ~NOFLSH;
	(void) __m_tty_set(&cur_term->_prog);

	__m_return_void("qiflush");
}

void
(noqiflush)()
{
#ifdef M_CURSES_TRACE
	__m_trace("noqiflush(void)");
#endif

	cur_term->_prog.c_lflag |= NOFLSH;
	(void) __m_tty_set(&cur_term->_prog);

	__m_return_void("noqiflush");
}
