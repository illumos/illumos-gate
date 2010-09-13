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
 * getcchar.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/getcchar.c 1.1 1995/05/10 13:59:24 ant Exp $";
#endif
#endif

#include <private.h>

int
getcchar(const cchar_t *c, wchar_t *wcs, attr_t *at, short *co, void *opts)
{
	int i;

#ifdef M_CURSES_TRACE
	__m_trace("getcchar(%p, %p, %p, %p, %p)", c, wcs, at, co, opts);
#endif

	if (wcs == (wchar_t *) 0)
		return __m_return_int("getcchar", c->_n + 1);

	*at = c->_at;
	*co = (short) c->_co;
	
	for (i = 0; i < c->_n; ++i)
		*wcs++ = c->_wc[i];
	*wcs = M_MB_L('\0');
		
	return __m_return_code("getcchar", OK);
}
