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


#ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.5	*/
/*
	Place the `len' length substring of `as' starting at `as[origin]'
	in `aresult'.
	Return `aresult'.

  Note: The copying of as to aresult stops if either the
	specified number (len) characters have been copied,
	or if the end of as is found.
	A negative len generally guarantees that everything gets copied.
*/

char *substr(as, aresult, origin, len)
char *as, *aresult;
int origin;
register unsigned len;
{
	register char *s, *result;

	s = as + origin;
	result = aresult;
	++len;
	while (--len && (*result++ = *s++)) ;
	if (len == 0)
		*result = 0;
	return(aresult);
}
