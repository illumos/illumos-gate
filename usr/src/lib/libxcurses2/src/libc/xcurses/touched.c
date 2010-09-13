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
 * touched.c
 *
 * XCurses Library
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#if M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/touched.c 1.2 "
"1995/06/15 18:42:55 ant Exp $";
#endif
#endif

#include <private.h>

/*
 * Return true if line has been touched.  See wtouchln().
 *
 *	touched 	0 <= _first[y] <= _last[y] <= _maxx
 * 	untouched	_last[y] < 0 < _maxx <= _first[y].
 */
#undef is_linetouched

bool
is_linetouched(WINDOW *w, int y)
{
	return (0 <= w->_last[y]);
}

#undef is_wintouched

bool
is_wintouched(WINDOW *w)
{
	int	y, value;

	for (y = 0; y < w->_maxy; ++y)
		if ((value = (0 <= w->_last[y])) != 0)
			break;

	return (value);
}
