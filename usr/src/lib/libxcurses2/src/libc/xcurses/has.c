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
 * Copyright (c) 1995-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/* LINTLIBRARY */

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
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/has.c 1.2 "
"1995/07/19 16:38:02 ant Exp $";
#endif
#endif

#include <private.h>

#undef has_colors

bool
has_colors(void)
{
	bool value;

	value = 0 < max_colors;

	return (value);
}

#undef has_ic

bool
has_ic(void)
{
	bool value;

	value = ((insert_character != NULL || parm_ich != NULL)	&&
		(delete_character != NULL || parm_dch != NULL)) ||
		(enter_insert_mode != NULL && exit_insert_mode);

	return (value);
}

#undef has_il

bool
has_il(void)
{
	bool value;

	value = ((insert_line != NULL || parm_insert_line != NULL) &&
		(delete_line != NULL || parm_delete_line != NULL)) ||
		change_scroll_region != NULL;

	return (value);
}

#undef can_change_color

bool
can_change_color(void)
{
	bool value;

	value = 2 < max_colors && can_change && initialize_color != NULL;

	return (value);
}
