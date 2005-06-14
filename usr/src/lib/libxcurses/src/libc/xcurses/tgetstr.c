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
 * tgetstr.c
 *
 * XCurses Library 
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/tgetstr.c 1.2 1995/08/30 19:31:37 danv Exp $";
#endif
#endif

#include <private.h>
#include <string.h>

/*
 * Termcap Emulation
 *
 * Similar to tigetstr() except cap is a termcap code and area is
 * the buffer area used to receive a copy of the string.
 */
char *
tgetstr(cap, area)
const char *cap;
char **area;
{
	char **p, *value = (char *) -1;

#ifdef M_CURSES_TRACE
	__m_trace("tgetstr(%p = \"%.2s\", %p)", cap, cap, area);
#endif

	for (p = __m_strcodes; *p != (char *) 0; ++p) {
		if (strcmp(*p, cap) == 0) {
			value = cur_term->_str[(int)(p - __m_strcodes)];
			if (*area != (char *) 0 && *area != (char *) 0)
				*area += strlen(strcpy(*area, value));
			break;
		}
	}

	return __m_return_pointer("tgetstr", value);
}
