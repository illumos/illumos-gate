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

/*
 * overlay.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#include <private.h>

int
(overlay)(const WINDOW *s, WINDOW *t)
{

#ifdef M_CURSES_TRACE
	__m_trace("overlay(%p, %p)", s, t);
#endif

	(void) __m_copywin(s, t, 1);

	return (__m_return_code("overlay", ERR));
}

int
(overwrite)(const WINDOW *s, WINDOW *t)
{

#ifdef M_CURSES_TRACE
	__m_trace("overwrite(%p, %p)", s, t);
#endif

	(void) __m_copywin(s, t, 0);

	return (__m_return_code("overwrite", ERR));
}
