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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma weak scalbl = __scalbl

/*
 * scalbl(x,n): return x * 2**n by manipulating exponent.
 */

#include "libm.h"
#include "longdouble.h"

#include <sys/isa_defs.h>

long double
scalbl(long double x, long double fn) {
	int *py = (int *) &fn, n;
	long double z;

	if (isnanl(x) || isnanl(fn))
		return x * fn;

	/* fn is +/-Inf */
#if defined(_BIG_ENDIAN)
	if ((py[0] & 0x7fff0000) == 0x7fff0000) {
		if ((py[0] & 0x80000000) != 0)
#else
	if ((py[2] & 0x7fff) == 0x7fff) {
		if ((py[2] & 0x8000) != 0)
#endif
			return x / (-fn);
		else
			return x * fn;
	}
	if (rintl(fn) != fn)
		return (fn - fn) / (fn - fn);
	if (fn > 65000.0L)
		z = scalbnl(x, 65000);
	else if (-fn > 65000.0L)
		z = scalbnl(x, -65000);
	else {
		n = (int) fn;
		z = scalbnl(x, n);
	}
	return z;
}
