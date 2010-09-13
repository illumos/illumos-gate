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
 * vw_scan.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/vw_scanw.c 1.3 1995/07/14 20:48:27 ant Exp $";
#endif
#endif

#include <private.h>
#include <limits.h>
#include <stdarg.h>

int
vw_scanw(w, fmt, ap)
WINDOW *w;
const char *fmt;
#if defined(sun)
va_list ap;
#else
void *ap;
#endif
{
	extern int m_vsscanf();
	int code;
	char buffer[LINE_MAX];

#ifdef M_CURSES_TRACE
	__m_trace("vw_scanw(%p, %p = \"%s\", %p)", w, fmt, fmt, ap);
#endif
	if ((code = wgetnstr(w, buffer, (int) sizeof buffer)) == OK)
#if defined(sun)
		(void) m_vsscanf(buffer, fmt, ap);
#else
		(void) m_vsscanf(buffer, fmt, (va_list) ap);
#endif

	return __m_return_code("vw_scanw", code);
}
