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

#include "libm_inlines.h"

#ifdef __RESTRICT
#define	restrict _Restrict
#else
#define	restrict
#endif

extern double sqrt(double);

/*
 * Instead of type punning, use union type.
 */
typedef union h32 {
	float f;
	unsigned u;
} h32;

void
__vhypotf(int n, float *restrict x, int stridex, float *restrict y,
    int stridey, float *restrict z, int stridez)
{
	float		x0, x1, x2, y0, y1, y2, z0, z1, z2, *pz0, *pz1, *pz2;
	h32		hx0, hx1, hx2, hy0, hy1, hy2;
	int		i, j0, j1, j2;

	do {
LOOP0:
		hx0.f = *x;
		hy0.f = *y;
		hx0.u &= ~0x80000000;
		hy0.u &= ~0x80000000;
		x0 = hx0.f;
		y0 = hy0.f;
		if (hy0.u > hx0.u) {
			i = hy0.u - hx0.u;
			j0 = hy0.u & 0x7f800000;
			if (hx0.u == 0)
				i = 0x7f800000;
		} else {
			i = hx0.u - hy0.u;
			j0 = hx0.u & 0x7f800000;
			if (hy0.u == 0)
				i = 0x7f800000;
			else if (hx0.u == 0)
				i = 0x7f800000;
		}
		if (i >= 0x0c800000 || j0 >= 0x7f800000) {
			z0 = x0 + y0;
			if (hx0.u == 0x7f800000)
				z0 = x0;
			else if (hy0.u  == 0x7f800000)
				z0 = y0;
			else if (hx0.u > 0x7f800000 || hy0.u > 0x7f800000)
				z0 = *x + *y;
			*z = z0;
			x += stridex;
			y += stridey;
			z += stridez;
			i = 0;
			if (--n <= 0)
				break;
			goto LOOP0;
		}
		pz0 = z;
		x += stridex;
		y += stridey;
		z += stridez;
		i = 1;
		if (--n <= 0)
			break;

LOOP1:
		hx1.f = *x;
		hy1.f = *y;
		hx1.u &= ~0x80000000;
		hy1.u &= ~0x80000000;
		x1 = hx1.f;
		y1 = hy1.f;
		if (hy1.u > hx1.u) {
			i = hy1.u - hx1.u;
			j1 = hy1.u & 0x7f800000;
			if (hx1.u == 0)
				i = 0x7f800000;
		} else {
			i = hx1.u - hy1.u;
			j1 = hx1.u & 0x7f800000;
			if (hy1.u == 0)
				i = 0x7f800000;
			else if (hx1.u == 0)
				i = 0x7f800000;
		}
		if (i >= 0x0c800000 || j1 >= 0x7f800000) {
			z1 = x1 + y1;
			if (hx1.u == 0x7f800000)
				z1 = x1;
			else if (hy1.u == 0x7f800000)
				z1 = y1;
			else if (hx1.u > 0x7f800000 || hy1.u > 0x7f800000)
				z1 = *x + *y;
			*z = z1;
			x += stridex;
			y += stridey;
			z += stridez;
			i = 1;
			if (--n <= 0)
				break;
			goto LOOP1;
		}
		pz1 = z;
		x += stridex;
		y += stridey;
		z += stridez;
		i = 2;
		if (--n <= 0)
			break;

LOOP2:
		hx2.f = *x;
		hy2.f = *y;
		hx2.u &= ~0x80000000;
		hy2.u &= ~0x80000000;
		x2 = hx2.f;
		y2 = hy2.f;
		if (hy2.u > hx2.u) {
			i = hy2.u - hx2.u;
			j2 = hy2.u & 0x7f800000;
			if (hx2.u == 0)
				i = 0x7f800000;
		} else {
			i = hx2.u - hy2.u;
			j2 = hx2.u & 0x7f800000;
			if (hy2.u == 0)
				i = 0x7f800000;
			else if (hx2.u == 0)
				i = 0x7f800000;
		}
		if (i >= 0x0c800000 || j2 >= 0x7f800000) {
			z2 = x2 + y2;
			if (hx2.u == 0x7f800000)
				z2 = x2;
			else if (hy2.u == 0x7f800000)
				z2 = y2;
			else if (hx2.u > 0x7f800000 || hy2.u > 0x7f800000)
				z2 = *x + *y;
			*z = z2;
			x += stridex;
			y += stridey;
			z += stridez;
			i = 2;
			if (--n <= 0)
				break;
			goto LOOP2;
		}
		pz2 = z;

		z0 = sqrt(x0 * (double)x0 + y0 * (double)y0);
		z1 = sqrt(x1 * (double)x1 + y1 * (double)y1);
		z2 = sqrt(x2 * (double)x2 + y2 * (double)y2);
		*pz0 = z0;
		*pz1 = z1;
		*pz2 = z2;

		x += stridex;
		y += stridey;
		z += stridez;
		i = 0;
	} while (--n > 0);

	if (i > 0) {
		if (i > 1) {
			z1 = sqrt(x1 * (double)x1 + y1 * (double)y1);
			*pz1 = z1;
		}
		z0 = sqrt(x0 * (double)x0 + y0 * (double)y0);
		*pz0 = z0;
	}
}
