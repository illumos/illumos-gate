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
 * create a new v_array with space in it for "num" elements of size "size"
 * (but the array is empty - must use array_grow or array append to fill it)
 */
struct v_array *
array_create(size, num)
unsigned	size;
unsigned	num;
{
	register unsigned	realsize;
	register unsigned	initstep;
	register struct v_array	*ptr;

	realsize = size * num + sizeof(struct v_array);
	initstep = num / 10;
	if (initstep < 2)
		initstep = 2;
	if ((ptr = (struct v_array *)malloc(realsize)) == NULL)
		return NULL;
	ptr->tot_used = 0;
	ptr->tot_left = num;
	ptr->ele_size = size;
	ptr->step_size = initstep;
	return v_body(ptr);
}
