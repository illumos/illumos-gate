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
 * has.c
 * 
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/has.c 1.2 1995/07/19 16:38:02 ant Exp $";
#endif
#endif

#include <private.h>

bool
(has_colors)()
{
	bool value;

#ifdef M_CURSES_TRACE
	__m_trace("has_colors(void)");
#endif

	value = 0 < max_colors;

	return __m_return_int("has_colors", value);
}

bool
(has_ic)()
{
	bool value;

#ifdef M_CURSES_TRACE
	__m_trace("has_ic(void)");
#endif

	value = ((insert_character != (char *) 0 || parm_ich != (char *) 0)
		&& (delete_character != (char *) 0 || parm_dch != (char *) 0))
		|| (enter_insert_mode != (char *) 0 && exit_insert_mode);

	return __m_return_int("has_ic", value);
}

bool
(has_il)()
{
	bool value;

#ifdef M_CURSES_TRACE
	__m_trace("has_il(void)");
#endif

        value = ((insert_line != (char *) 0 || parm_insert_line != (char *) 0)
                && (delete_line != (char *) 0 || parm_delete_line != (char *)0))
                || change_scroll_region != (char *) 0;

	return __m_return_int("has_il", value);
}

bool
(can_change_color)()
{
	bool value;

#ifdef M_CURSES_TRACE
	__m_trace("can_change_color(void)");
#endif

	value = 2 < max_colors && can_change && initialize_color != (char *) 0;

	return __m_return_int("can_change_color", value);
}

