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
 * nonl.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/nonl.c 1.1 1995/05/15 15:12:23 ant Exp $";
#endif
#endif

#include <private.h>

/*
 * Enable mappnig of cr -> nl on input and nl -> crlf on output. 
 */
int
nl()
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("nl(void)");
#endif

	cur_term->_prog.c_iflag |= ICRNL;
	cur_term->_prog.c_oflag |= OPOST;
#ifdef ONLCR
	cur_term->_prog.c_oflag |= ONLCR;
#endif

	if ((code = __m_tty_set(&cur_term->_prog)) == OK)
		cur_term->_flags |= __TERM_NL_IS_CRLF;

	return __m_return_code("nl", code);
}

/*
 * Disable mappnig of cr -> nl on input and nl -> crlf on output. 
 */
int
nonl()
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("nonl(void)");
#endif

	cur_term->_prog.c_iflag &= ~ICRNL;
#if ONLCR
	cur_term->_prog.c_oflag &= ~ONLCR;
#else
	cur_term->_prog.c_oflag &= ~OPOST;
#endif

	if ((code = __m_tty_set(&cur_term->_prog)) == OK)
		cur_term->_flags &= ~__TERM_NL_IS_CRLF;

	return __m_return_code("nonl", code);
}
