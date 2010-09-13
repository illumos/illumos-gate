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
 * box_set.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/box_set.c 1.1 1995/05/26 19:11:37 ant Exp $";
#endif
#endif

#include <private.h>

#undef box_set

int
box_set(w, v, h)
WINDOW *w; 
const cchar_t *v, *h;
{
	int code;

#ifdef M_CURSES_TRACE
	__m_trace("box_set(%p, %p, %p)", w, v, h);
#endif

	code = wborder_set(
		w, v, v, h, h, 
		(const cchar_t *) 0, (const cchar_t *) 0, 
		(const cchar_t *) 0, (const cchar_t *) 0
	);

	return __m_return_code("box_set", code);
}
