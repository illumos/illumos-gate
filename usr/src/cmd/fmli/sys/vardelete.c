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
#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.1 */

#include	<stdio.h>
#include	"wish.h"
#include	"var_arrays.h"

/*
 * delete an element from a v_array
 * this does not reduce the size of the v_array in-core
 * array_shrink does that
 */
struct v_array *
array_delete(array, position)
struct v_array	array[];
unsigned	position;
{
	register struct v_array	*ptr;

	ptr = v_header(array);
	if (position >= ptr->tot_used)
		return array;
	ptr->tot_used--;
	ptr->tot_left++;
	if (position < ptr->tot_used)
		memshift(ptr_to_ele(ptr, position), ptr_to_ele(ptr, position + 1), ptr->ele_size * (ptr->tot_used - position));
	return v_body(ptr);
}
