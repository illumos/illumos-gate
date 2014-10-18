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

#include "libm_synonyms.h"
#include "libm_inlines.h"

#ifdef __RESTRICT
#define restrict _Restrict
#else
#define restrict
#endif

#define sqrt __sqrt

extern double sqrt(double);

void
__vhypotf(int n, float * restrict x, int stridex, float * restrict y,
	int stridey, float * restrict z, int stridez)
{
	float		x0, x1, x2, y0, y1, y2, z0, z1, z2, *pz0, *pz1, *pz2;
	unsigned	hx0, hx1, hx2, hy0, hy1, hy2;
	int			i, j0, j1, j2;

	do
	{
LOOP0:
		hx0 = *(unsigned*)x & ~0x80000000;
		hy0 = *(unsigned*)y & ~0x80000000;
		*(unsigned*)&x0 = hx0;
		*(unsigned*)&y0 = hy0;
		if (hy0 > hx0)
		{
			i = hy0 - hx0;
			j0 = hy0 & 0x7f800000;
			if (hx0 == 0)
				i = 0x7f800000;
		}
		else
		{
			i = hx0 - hy0;
			j0 = hx0 & 0x7f800000;
			if (hy0 == 0)
				i = 0x7f800000;
			else if (hx0 == 0)
				i = 0x7f800000;
		}
		if (i >= 0x0c800000 || j0 >= 0x7f800000)
		{
			z0 = x0 + y0;
			if (hx0 == 0x7f800000)
				z0 = x0;
			else if (hy0  == 0x7f800000)
				z0 = y0;
			else if (hx0 > 0x7f800000 || hy0 > 0x7f800000)
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
		hx1 = *(unsigned*)x & ~0x80000000;
		hy1 = *(unsigned*)y & ~0x80000000;
		*(unsigned*)&x1 = hx1;
		*(unsigned*)&y1 = hy1;
		if (hy1 > hx1)
		{
			i = hy1 - hx1;
			j1 = hy1 & 0x7f800000;
			if (hx1 == 0)
				i = 0x7f800000;
		}
		else
		{
			i = hx1 - hy1;
			j1 = hx1 & 0x7f800000;
			if (hy1 == 0)
				i = 0x7f800000;
			else if (hx1 == 0)
				i = 0x7f800000;
		}
		if (i >= 0x0c800000 || j1 >= 0x7f800000)
		{
			z1 = x1 + y1;
			if (hx1 == 0x7f800000)
				z1 = x1;
			else if (hy1 == 0x7f800000)
				z1 = y1;
			else if (hx1 > 0x7f800000 || hy1 > 0x7f800000)
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
		hx2 = *(unsigned*)x & ~0x80000000;
		hy2 = *(unsigned*)y & ~0x80000000;
		*(unsigned*)&x2 = hx2;
		*(unsigned*)&y2 = hy2;
		if (hy2 > hx2)
		{
			i = hy2 - hx2;
			j2 = hy2 & 0x7f800000;
			if (hx2 == 0)
				i = 0x7f800000;
		}
		else
		{
			i = hx2 - hy2;
			j2 = hx2 & 0x7f800000;
			if (hy2 == 0)
				i = 0x7f800000;
			else if (hx2 == 0)
				i = 0x7f800000;
		}
		if (i >= 0x0c800000 || j2 >= 0x7f800000)
		{
			z2 = x2 + y2;
			if (hx2 == 0x7f800000)
				z2 = x2;
			else if (hy2 == 0x7f800000)
				z2 = y2;
			else if (hx2 > 0x7f800000 || hy2 > 0x7f800000)
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

	if (i > 0)
	{
		if (i > 1)
		{
			z1 = sqrt(x1 * (double)x1 + y1 * (double)y1);
			*pz1 = z1;
		}
		z0 = sqrt(x0 * (double)x0 + y0 * (double)y0);
		*pz0 = z0;
	}
}
