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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * Copyright  (c) 1986 AT&T
 *	All Rights Reserved
 */
#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.2 */

#include	<stdio.h>
#include	"wish.h"
#include	"var_arrays.h"


/*
 * make the v_array bigger by one element, mallocing as needed
 */
struct v_array *
array_grow(array, step)
struct v_array	array[];
unsigned	step;
{
	register struct v_array	*ptr;
	register unsigned	delta;

	ptr = v_header(array);
	if (step > ptr->tot_left) {
		delta = ptr->step_size;
		if (delta < step)
			delta = step;
		if ((ptr = (struct v_array *)realloc(ptr, sizeof(struct v_array) + (ptr->tot_used + ptr->tot_left + delta) * ptr->ele_size)) == NULL)
			return NULL;
		ptr->tot_left += delta;
	}
	ptr->tot_used += step;
	ptr->tot_left -= step;
	return v_body(ptr);
}
