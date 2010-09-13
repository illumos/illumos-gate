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
 * napms.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/napms.c 1.1 1995/06/16 20:35:38 ant Exp $";
#endif
#endif

#include <private.h>
#include <sys/types.h>
#include <unistd.h>

int
napms(ms)
int ms;
{
#ifdef M_CURSES_TRACE
	__m_trace("napms(%d)", ms);
#endif

	if (0 < ms) {
#ifdef M_HAS_USLEEP
		if (1000000L < ms)
			return __m_return_code("napms", ERR);

		(void) usleep((usecond_t) ms);
#else
		(void) sleep((unsigned) (0 < ms / 1000 ? ms / 1000 : 1));
#endif
	}

	return __m_return_code("napms", OK);
}
