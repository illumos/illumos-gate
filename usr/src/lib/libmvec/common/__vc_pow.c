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

extern void __vc_exp(int, float *, int, float *, int, float *);
extern void __vc_log(int, float *, int, float *, int);

void
__vc_pow(int n, float * restrict x, int stridex, float * restrict y,
	int stridey, float * restrict z, int stridez, float * restrict tmp)
{
	float	r;
	int		i, j, k;

	__vc_log(n, x, stridex, tmp, 1);
	stridey <<= 1;
	for (i = j = 0; i < n; i++, j += stridey)
	{
		k = i << 1;
		r = y[j] * tmp[k] - y[j+1] * tmp[k+1];
		tmp[k+1] = y[j+1] * tmp[k] + y[j] * tmp[k+1];
		tmp[k] = r;
	}
	__vc_exp(n, tmp, 1, z, stridez, tmp + n + n);
}
