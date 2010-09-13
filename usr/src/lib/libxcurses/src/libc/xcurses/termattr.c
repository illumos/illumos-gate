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
 * termattr.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/termattr.c 1.1 1995/07/10 16:09:34 ant Exp $";
#endif
#endif

#include <private.h>
#include <ctype.h>

chtype
termattrs()
{
	chtype ch;
	cchar_t cc;

#ifdef M_CURSES_TRACE
	__m_trace("termattrs(void)");
#endif

	cc = __m_screen->_newscr->_bg;
	cc._at = term_attrs();
	ch = __m_cc_chtype(&cc) & A_ATTRIBUTES & ~A_COLOR;
	

	return __m_return_chtype("termattrs", ch);
}

attr_t
term_attrs()
{
	char *p;
	attr_t at;

#ifdef M_CURSES_TRACE
	__m_trace("term_attrs(void)");
#endif

	if (set_attributes) {
		for (p = set_attributes; *p != '\0'; ++p) {
			if (p[0] != '%' || p[1] != 'p' || !isdigit(p[2]))
				continue;

			p += 2;
			switch (*p) {
			case 1:
				at |= WA_STANDOUT;
				break;
			case 2:
				at |= WA_UNDERLINE;
				break;
			case 3:
				at |= WA_REVERSE;
				break;
			case 4:
				at |= WA_BLINK;
				break;
			case 5:
				at |= WA_DIM;
				break;
			case 6:
				at |= WA_BOLD;
				break;
			case 7:
				at |= WA_INVIS;
				break;
			case 8:
				at |= WA_PROTECT;
				break;
			case 9:
				at |= WA_ALTCHARSET;
				break;
			}
		}
	}

	if (set_a_attributes) {
		for (p = set_a_attributes; *p != '\0'; ++p) {
			if (p[0] != '%' || p[1] != 'p' || !isdigit(p[2]))
				continue;

			p += 2;
			switch (*p) {
			case 1:
				at |= WA_HORIZONTAL;
				break;
			case 2:
				at |= WA_LEFT;
				break;
			case 3:
				at |= WA_LOW;
				break;
			case 4:
				at |= WA_RIGHT;
				break;
			case 5:
				at |= WA_TOP;
				break;
			case 6:
				at |= WA_VERTICAL;
				break;
			}
		}
	}

	if (enter_alt_charset_mode != (char *) 0)
		at |= WA_ALTCHARSET;

	if (enter_blink_mode != (char *) 0)
		at |= WA_BLINK;

	if (enter_bold_mode != (char *) 0)
		at |= WA_BOLD;

	if (enter_secure_mode != (char *) 0)
		at |= WA_INVIS;

	if (enter_dim_mode != (char *) 0)
		at |= WA_DIM;

	if (enter_protected_mode != (char *) 0)
		at |= WA_PROTECT;

	if (enter_reverse_mode != (char *) 0)
		at |= WA_REVERSE;

	if (enter_standout_mode != (char *) 0)
		at |= WA_STANDOUT;

	if (enter_underline_mode != (char *) 0)
		at |= WA_UNDERLINE;

	if (enter_horizontal_hl_mode != (char *) 0)
		at |= WA_HORIZONTAL;

	if (enter_left_hl_mode != (char *) 0)
		at |= WA_LEFT;

	if (enter_low_hl_mode != (char *) 0)
		at |= WA_LOW;

	if (enter_right_hl_mode != (char *) 0)
		at |= WA_RIGHT;

	if (enter_top_hl_mode != (char *) 0)
		at |= WA_TOP;

	if (enter_vertical_hl_mode != (char *) 0)
		at |= WA_VERTICAL;

	return __m_return_chtype("term_attrs", (chtype) at);
}
