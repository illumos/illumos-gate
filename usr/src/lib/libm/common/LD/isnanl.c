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

#pragma weak __isnanl = isnanl

#include "libm.h"

#if defined(__sparc)
int
isnanl(long double x) {
	int *px = (int *) &x;
	return ((px[0] & ~0x80000000) >= 0x7fff0000 &&
		((px[0] & ~0xffff0000) | px[1] | px[2] | px[3]) != 0);
}
#elif defined(__x86)
int
isnanl(long double x) {
	int *px = (int *) &x, t = px[2] & 0x7fff;
#if defined(HANDLE_UNSUPPORTED)
	return ((t == 0x7fff && ((px[1] & ~0x80000000) | px[0]) != 0) ||
		(t != 0 && (px[1] & 0x80000000) == 0));
#else
	return (t == 0x7fff && ((px[1] & ~0x80000000) | px[0]) != 0);
#endif
}
#endif	/* defined(__sparc) || defined(__x86) */
