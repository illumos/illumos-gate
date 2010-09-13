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
 * flushinp.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/flushinp.c 1.1 1995/06/06 14:13:41 ant Exp $";
#endif
#endif

#include <private.h>

/*f
 * Throw away any typeahead that has been typed by the user 
 * and has not yet been read by the program.
 */
int
flushinp()
{
	int fd;

#ifdef M_CURSES_TRACE
	__m_trace("flushinp(void)");
#endif

	if (!ISEMPTY())
		RESET();

        if (cur_term->_flags & __TERM_ISATTY_IN)
                fd = cur_term->_ifd;
        else if (cur_term->_flags & __TERM_ISATTY_OUT)
                fd = cur_term->_ofd;
	else
		fd = -1;

	if (0 <= fd)
		(void) tcflush(fd, TCIFLUSH);

	return __m_return_code("flushinp", OK);
}
