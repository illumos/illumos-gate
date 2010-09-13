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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if !defined(sparc) && !defined(__sparc)
#error This code is for SPARC only
#endif

/*
 * _Q_scl(x, n) sets *x = *x * 2^n.
 *
 * This routine tacitly assumes the result will be either zero
 * or normal, so there is no need to raise any exceptions.
 */
void
_Q_scl(long double *x, int n)
{
	union {
		unsigned int	i[4];
		long double	q;
	} xx;
	int	hx;

	xx.q = *x;
	hx = xx.i[0] & ~0x80000000;

	if (hx < 0x10000) { /* x is zero or subnormal */
		if ((hx | xx.i[1] | xx.i[2] | xx.i[3]) == 0)
			return;

		/* normalize x */
		while (hx == 0 && xx.i[1] < 0x10000) {
			hx = xx.i[1];
			xx.i[1] = xx.i[2];
			xx.i[2] = xx.i[3];
			xx.i[3] = 0;
			n -= 32;
		}
		while (hx < 0x10000) {
			hx = (hx << 1) | (xx.i[1] >> 31);
			xx.i[1] = (xx.i[1] << 1) | (xx.i[2] >> 31);
			xx.i[2] = (xx.i[2] << 1) | (xx.i[3] >> 31);
			xx.i[3] <<= 1;
			n--;
		}
		xx.i[0] = hx | (xx.i[0] & 0x80000000);
	}

	if ((hx >> 16) + n < 1) {
		/* for subnormal result, just deliver zero */
		xx.i[0] = xx.i[0] & 0x80000000;
		xx.i[1] = xx.i[2] = xx.i[3] = 0;
	} else
		xx.i[0] += (n << 16);
	*x = xx.q;
}

static const union {
	int		i[4];
	long double	q;
} consts[2] = {
	{ 0x7ffe0000, 0, 0, 0 },
	{ 0x00010000, 0, 0, 0 }
};

/*
 * _Q_scle(x, n) sets *x = *x * 2^n, raising overflow or underflow
 * as appropriate.
 *
 * This routine tacitly assumes the argument is either zero or normal.
 */
void
_Q_scle(long double *x, int n)
{
	union {
		unsigned int	i[4];
		long double	q;
	} xx;
	int	hx;

	xx.q = *x;
	hx = (xx.i[0] >> 16) & 0x7fff;

	if (hx == 0) /* x must be zero */
		return;

	hx += n;
	if (hx >= 0x7fff) { /* overflow */
		xx.i[0] = 0x7ffe0000 | (xx.i[0] & 0x80000000);
		xx.i[1] = xx.i[2] = xx.i[3] = 0;
		xx.q *= consts[0].q;
	} else if (hx < 1) { /* possible underflow */
		if (hx < -112) {
			xx.i[0] = 0x00010000 | (xx.i[0] & 0x80000000);
			xx.i[1] = xx.i[2] = xx.i[3] = 0;
		} else {
			xx.i[0] = (0x3ffe0000 + (hx << 16)) |
				(xx.i[0] & 0x8000ffff);
		}
		xx.q *= consts[1].q;
	} else
		xx.i[0] += (n << 16);

	*x = xx.q;
}
