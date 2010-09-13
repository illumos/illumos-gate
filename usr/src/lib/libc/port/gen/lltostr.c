/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	lltostr -- convert long long to decimal string
 *
 *	char *
 *	lltostr(value, ptr)
 *	long long value;
 *	char *ptr;
 *
 *	Ptr is assumed to point to the byte following a storage area
 *	into which the decimal representation of "value" is to be
 *	placed as a string.  Lltostr converts "value" to decimal and
 *	produces the string, and returns a pointer to the beginning
 *	of the string.  No leading zeroes are produced, and no
 *	terminating null is produced.  The low-order digit of the
 *	result always occupies memory position ptr-1.
 *	Lltostr's behavior is undefined if "value" is negative.  A single
 *	zero digit is produced if "value" is zero.
 */

#pragma weak _lltostr = lltostr
#pragma weak _ulltostr = ulltostr

#include "lint.h"
#include <sys/types.h>
#include <stdlib.h>

char *
lltostr(longlong_t value, char *ptr)
{
	longlong_t t;

#ifdef _ILP32
	if (!(0xffffffff00000000ULL & value)) {
		ulong_t t, val = (ulong_t)value;

		do {
			*--ptr = (char)('0' + val - 10 * (t = val / 10));
		} while ((val = t) != 0);

		return (ptr);
	}
#endif

	do {
		*--ptr = (char)('0' + value - 10 * (t = value / 10));
	} while ((value = t) != 0);

	return (ptr);
}

char *
ulltostr(u_longlong_t value, char *ptr)
{
	u_longlong_t t;

#ifdef _ILP32
	if (!(0xffffffff00000000ULL & value)) {
		ulong_t t, val = (ulong_t)value;

		do {
			*--ptr = (char)('0' + val - 10 * (t = val / 10));
		} while ((val = t) != 0);

		return (ptr);
	}
#endif

	do {
		*--ptr = (char)('0' + value - 10 * (t = value / 10));
	} while ((value = t) != 0);

	return (ptr);
}
