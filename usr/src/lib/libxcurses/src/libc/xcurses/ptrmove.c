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
 * ptrmove.c
 *
 * Copyright 1990, 1995 by Mortice Kern Systems Inc.  All rights reserved.
 *
 */

#ifdef M_RCSID
#ifndef lint
static char rcsID[] = "$Header: /rd/src/libc/xcurses/rcs/ptrmove.c 1.3 1995/05/18 20:55:05 ant Exp $";
#endif
#endif

#include <private.h>

static void reverse(void **, int, int);

/*
 * Move range start..finish inclusive before the given location.
 * Return -1 if the region to move is out of bounds or the target 
 * falls within the region; 0 for success.
 *
 * (See Software Tools chapter 6.)
 */
int
__m_ptr_move(array, length, start, finish, to)
void **array;
unsigned length, start, finish, to;
{
#ifdef M_CURSES_TRACE
	__m_trace(
		"__m_ptr_move(%p, %d, %d, %d, %d)", 
		array, length, start, finish, to
	);
#endif
	if (finish < start || length <= finish)
		return __m_return_int("__m_ptr_move()", -1);

	if (to < start) {
		reverse(array, to, start-1);
		reverse(array, start, finish);
		reverse(array, to, finish);
	} else if (finish < to && to <= length) {
		reverse(array, start, finish);
		reverse(array, finish+1, to-1);
		reverse(array, start, to-1);
	} else {
		return __m_return_int("__m_ptr_move()", -1);
	}

	return __m_return_int("__m_ptr_move()", 0);
}

/*
 * Reverse range a..b inclusive.
 */
static void
reverse(ptr, a, b)
void **ptr;
int a, b;
{
	register void *temp;
	register void **a_ptr = &ptr[a];
	register void **b_ptr = &ptr[b];

	while (a_ptr < b_ptr) {
		temp = *a_ptr;
		*a_ptr++ = *b_ptr;
		*b_ptr-- = temp;
	}
}
