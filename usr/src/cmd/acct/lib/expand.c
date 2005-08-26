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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.7	*/

#include <sys/types.h>
#include <sys/param.h>
#include <sys/acct.h>

#ifdef uts
float
#else
/*
 * For as long as ct is of type comp_t, and comp_t is defined to be of type
 * unsigned short, the maximum value of ct will be 2^16-1 ie 65535. Based on
 * this input value, the maximum value that expand() can return will therefore
 * be 4292870144. A return type of ulong_t ensures we don't overflow.
 */
ulong_t
#endif
expand(comp_t ct)
{
	int e;
#ifdef uts
	float f;
#else
	ulong_t f;
#endif
	e = (ct >> 13) & 07;
	f = ct & 017777;

	while (e-- > 0) 
#ifdef uts
		f *= 8.0;		/* can't shift a float */
#else
		f <<=3;
#endif

	return f;
}
