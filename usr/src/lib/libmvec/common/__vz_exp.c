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

#ifdef __RESTRICT
#define restrict _Restrict
#else
#define restrict
#endif

extern void __vexp(int, double *, int, double *, int);
extern void __vsincos(int, double *, int, double *, int, double *, int);

void
__vz_exp(int n, double * restrict x, int stridex, double * restrict y,
	int stridey, double * restrict tmp)
{
	int		i, j;

	stridex <<= 1;
	stridey <<= 1;
	__vexp(n, x, stridex, tmp, 1);
	__vsincos(n, x + 1, stridex, y + 1, stridey, y, stridey);
	for (i = j = 0; i < n; i++, j += stridey)
	{
		y[j] *= tmp[i];
		y[j+1] *= tmp[i];
	}
}
