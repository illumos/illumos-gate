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
#ident	"%Z%%M%	%I%	%E% SMI"       /* SVr4.0 1.3 */

#include	<stdio.h>
#include	"wish.h"
#include	"var_arrays.h"

/*
 * shrink the actual space used by a v_array as much as possible
 * note that this requires the process to allocate more space
 * before giving some back, so it may actually INCREASE the data
 * segment size of the process.  If used, array_shrink should be
 * called before adding things to other v_arrays, since perhaps
 * one of them can take advantage of the freed space.
 */
struct v_array *
array_shrink(array)
struct v_array	array[];
{
	register struct v_array	*ptr;
	register struct v_array	*newptr;

	ptr = v_header(array);
	if ((newptr = (struct v_array *)realloc(ptr, sizeof(struct v_array) + ptr->tot_used * ptr->ele_size)) == NULL)
		return NULL;
	return v_body(newptr);	/* chged ptr to newptr. abs k14.2 */
}
