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
 * add string to the end of a var_array string
 */
struct v_array *
array_strappend(array, string)
struct v_array	array[];
char	*string;
{
	register struct v_array	*ptr;

	ptr = v_header(array_grow(array, strlen(string)));
	if (string != NULL)
		strcat(v_body(ptr), string);
	return v_body(ptr);
}

/*
 * do the same with a character
 */
struct v_array *
array_chappend(array, ch)
struct v_array	array[];
char	ch;
{
	register char	*cp;
	register struct v_array	*ptr;

	ptr = v_header(array_grow(array, 1));
	cp = ((char *) v_body(ptr)) + strlen(v_body(ptr));
	*cp++ = ch;
	*cp = '\0';
	return v_body(ptr);
}
