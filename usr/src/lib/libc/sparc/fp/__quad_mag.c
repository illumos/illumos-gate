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
 * Copyright (c) 1994-1997, by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains __quad_mag_add and __quad_mag_sub, the core
 * of the quad precision add and subtract operations.
 */

#include "quad.h"

/*
 * __quad_mag_add(x, y, z, fsr)
 *
 * Sets *z = *x + *y, rounded according to the rounding mode in *fsr,
 * and updates the current exceptions in *fsr.  This routine assumes
 * *x and *y are finite, with the same sign (i.e., an addition of
 * magnitudes), |*x| >= |*y|, and *z already has its sign bit set.
 */
void
__quad_mag_add(const union longdouble *x, const union longdouble *y,
	union longdouble *z, unsigned int *fsr)
{
	unsigned int	lx, ly, ex, ey, frac2, frac3, frac4;
	unsigned int	round, sticky, carry, rm;
	int		e, uflo;

	/* get the leading significand words and exponents */
	ex = (x->l.msw & 0x7fffffff) >> 16;
	lx = x->l.msw & 0xffff;
	if (ex == 0)
		ex = 1;
	else
		lx |= 0x10000;

	ey = (y->l.msw & 0x7fffffff) >> 16;
	ly = y->l.msw & 0xffff;
	if (ey == 0)
		ey = 1;
	else
		ly |= 0x10000;

	/* prenormalize y */
	e = (int) ex - (int) ey;
	round = sticky = 0;
	if (e >= 114) {
		frac2 = x->l.frac2;
		frac3 = x->l.frac3;
		frac4 = x->l.frac4;
		sticky = ly | y->l.frac2 | y->l.frac3 | y->l.frac4;
	} else {
		frac2 = y->l.frac2;
		frac3 = y->l.frac3;
		frac4 = y->l.frac4;
		if (e >= 96) {
			sticky = frac4 | frac3 | (frac2 & 0x7fffffff);
			round = frac2 & 0x80000000;
			frac4 = ly;
			frac3 = frac2 = ly = 0;
			e -= 96;
		} else if (e >= 64) {
			sticky = frac4 | (frac3 & 0x7fffffff);
			round = frac3 & 0x80000000;
			frac4 = frac2;
			frac3 = ly;
			frac2 = ly = 0;
			e -= 64;
		} else if (e >= 32) {
			sticky = frac4 & 0x7fffffff;
			round = frac4 & 0x80000000;
			frac4 = frac3;
			frac3 = frac2;
			frac2 = ly;
			ly = 0;
			e -= 32;
		}
		if (e) {
			sticky |= round | (frac4 & ((1 << (e - 1)) - 1));
			round = frac4 & (1 << (e - 1));
			frac4 = (frac4 >> e) | (frac3 << (32 - e));
			frac3 = (frac3 >> e) | (frac2 << (32 - e));
			frac2 = (frac2 >> e) | (ly << (32 - e));
			ly >>= e;
		}

		/* add, propagating carries */
		frac4 += x->l.frac4;
		carry = (frac4 < x->l.frac4);
		frac3 += x->l.frac3;
		if (carry) {
			frac3++;
			carry = (frac3 <= x->l.frac3);
		} else {
			carry = (frac3 < x->l.frac3);
		}
		frac2 += x->l.frac2;
		if (carry) {
			frac2++;
			carry = (frac2 <= x->l.frac2);
		} else {
			carry = (frac2 < x->l.frac2);
		}
		lx += ly;
		if (carry)
			lx++;

		/* postnormalize */
		if (lx >= 0x20000) {
			sticky |= round;
			round = frac4 & 1;
			frac4 = (frac4 >> 1) | (frac3 << 31);
			frac3 = (frac3 >> 1) | (frac2 << 31);
			frac2 = (frac2 >> 1) | (lx << 31);
			lx >>= 1;
			ex++;
		}
	}

	/* keep track of whether the result before rounding is tiny */
	uflo = (lx < 0x10000);

	/* get the rounding mode, fudging directed rounding modes */
	/* as though the result were positive */
	rm = *fsr >> 30;
	if (z->l.msw)
		rm ^= (rm >> 1);

	/* see if we need to round */
	if (round | sticky) {
		*fsr |= FSR_NXC;

		/* round up if necessary */
		if (rm == FSR_RP || (rm == FSR_RN && round &&
			(sticky || (frac4 & 1)))) {
			if (++frac4 == 0)
				if (++frac3 == 0)
					if (++frac2 == 0)
						if (++lx >= 0x20000) {
							lx >>= 1;
							ex++;
						}
		}
	}

	/* check for overflow */
	if (ex >= 0x7fff) {
		/* store the default overflowed result */
		*fsr |= FSR_OFC | FSR_NXC;
		if (rm == FSR_RN || rm == FSR_RP) {
			z->l.msw |= 0x7fff0000;
			z->l.frac2 = z->l.frac3 = z->l.frac4 = 0;
		} else {
			z->l.msw |= 0x7ffeffff;
			z->l.frac2 = z->l.frac3 = z->l.frac4 = 0xffffffff;
		}
	} else {
		/* store the result */
		if (lx >= 0x10000)
			z->l.msw |= (ex << 16);
		z->l.msw |= (lx & 0xffff);
		z->l.frac2 = frac2;
		z->l.frac3 = frac3;
		z->l.frac4 = frac4;

		/* if the pre-rounded result was tiny and underflow trapping */
		/* is enabled, simulate underflow */
		if (uflo && (*fsr & FSR_UFM))
			*fsr |= FSR_UFC;
	}
}

/*
 * __quad_mag_sub(x, y, z, fsr)
 *
 * Sets *z = *x - *y, rounded according to the rounding mode in *fsr,
 * and updates the current exceptions in *fsr.  This routine assumes
 * *x and *y are finite, with opposite signs (i.e., a subtraction of
 * magnitudes), |*x| >= |*y|, and *z already has its sign bit set.
 */
void
__quad_mag_sub(const union longdouble *x, const union longdouble *y,
	union longdouble *z, unsigned int *fsr)
{
	unsigned int	lx, ly, ex, ey, frac2, frac3, frac4;
	unsigned int	guard, round, sticky, borrow, rm;
	int		e;

	/* get the leading significand words and exponents */
	ex = (x->l.msw & 0x7fffffff) >> 16;
	lx = x->l.msw & 0xffff;
	if (ex == 0)
		ex = 1;
	else
		lx |= 0x10000;

	ey = (y->l.msw & 0x7fffffff) >> 16;
	ly = y->l.msw & 0xffff;
	if (ey == 0)
		ey = 1;
	else
		ly |= 0x10000;

	/* prenormalize y */
	e = (int) ex - (int) ey;
	guard = round = sticky = 0;
	if (e > 114) {
		sticky = ly | y->l.frac2 | y->l.frac3 | y->l.frac4;
		ly = frac2 = frac3 = frac4 = 0;
	} else {
		frac2 = y->l.frac2;
		frac3 = y->l.frac3;
		frac4 = y->l.frac4;
		if (e >= 96) {
			sticky = frac4 | frac3 | (frac2 & 0x3fffffff);
			round = frac2 & 0x40000000;
			guard = frac2 & 0x80000000;
			frac4 = ly;
			frac3 = frac2 = ly = 0;
			e -= 96;
		} else if (e >= 64) {
			sticky = frac4 | (frac3 & 0x3fffffff);
			round = frac3 & 0x40000000;
			guard = frac3 & 0x80000000;
			frac4 = frac2;
			frac3 = ly;
			frac2 = ly = 0;
			e -= 64;
		} else if (e >= 32) {
			sticky = frac4 & 0x3fffffff;
			round = frac4 & 0x40000000;
			guard = frac4 & 0x80000000;
			frac4 = frac3;
			frac3 = frac2;
			frac2 = ly;
			ly = 0;
			e -= 32;
		}
		if (e > 1) {
			sticky |= guard | round |
				(frac4 & ((1 << (e - 2)) - 1));
			round = frac4 & (1 << (e - 2));
			guard = frac4 & (1 << (e - 1));
			frac4 = (frac4 >> e) | (frac3 << (32 - e));
			frac3 = (frac3 >> e) | (frac2 << (32 - e));
			frac2 = (frac2 >> e) | (ly << (32 - e));
			ly >>= e;
		} else if (e == 1) {
			sticky |= round;
			round = guard;
			guard = frac4 & 1;
			frac4 = (frac4 >> 1) | (frac3 << 31);
			frac3 = (frac3 >> 1) | (frac2 << 31);
			frac2 = (frac2 >> 1) | (ly << 31);
			ly >>= 1;
		}
	}

	/* complement guard, round, and sticky as need be */
	if (sticky) {
		round = !round;
		guard = !guard;
	} else if (round) {
		guard = !guard;
	}
	borrow = (guard | round | sticky);

	/* subtract, propagating borrows */
	frac4 = x->l.frac4 - frac4;
	if (borrow) {
		frac4--;
		borrow = (frac4 >= x->l.frac4);
	} else {
		borrow = (frac4 > x->l.frac4);
	}
	frac3 = x->l.frac3 - frac3;
	if (borrow) {
		frac3--;
		borrow = (frac3 >= x->l.frac3);
	} else {
		borrow = (frac3 > x->l.frac3);
	}
	frac2 = x->l.frac2 - frac2;
	if (borrow) {
		frac2--;
		borrow = (frac2 >= x->l.frac2);
	} else {
		borrow = (frac2 > x->l.frac2);
	}
	lx -= ly;
	if (borrow)
		lx--;

	/* get the rounding mode */
	rm = *fsr >> 30;

	/* handle zero result */
	if (!(lx | frac2 | frac3 | frac4 | guard)) {
		z->l.msw = ((rm == FSR_RM)? 0x80000000 : 0);
		z->l.frac2 = z->l.frac3 = z->l.frac4 = 0;
		return;
	}

	/* postnormalize */
	if (lx < 0x10000) {
		/* if cancellation occurred or the exponent is 1, */
		/* the result is exact */
		if (lx < 0x8000 || ex == 1) {
			while ((lx | (frac2 & 0xfffe0000)) == 0 && ex > 32) {
				lx = frac2;
				frac2 = frac3;
				frac3 = frac4;
				frac4 = ((guard)? 0x80000000 : 0);
				guard = 0;
				ex -= 32;
			}
			while (lx < 0x10000 && ex > 1) {
				lx = (lx << 1) | (frac2 >> 31);
				frac2 = (frac2 << 1) | (frac3 >> 31);
				frac3 = (frac3 << 1) | (frac4 >> 31);
				frac4 <<= 1;
				if (guard) {
					frac4 |= 1;
					guard = 0;
				}
				ex--;
			}
			if (lx >= 0x10000)
				z->l.msw |= (ex << 16);
			z->l.msw |= (lx & 0xffff);
			z->l.frac2 = frac2;
			z->l.frac3 = frac3;
			z->l.frac4 = frac4;

			/* if the result is tiny and underflow trapping is */
			/* enabled, simulate underflow */
			if (lx < 0x10000 && (*fsr & FSR_UFM))
				*fsr |= FSR_UFC;
			return;
		}

		/* otherwise we only borrowed one place */
		lx = (lx << 1) | (frac2 >> 31);
		frac2 = (frac2 << 1) | (frac3 >> 31);
		frac3 = (frac3 << 1) | (frac4 >> 31);
		frac4 <<= 1;
		if (guard)
			frac4 |= 1;
		ex--;
	} else {
		sticky |= round;
		round = guard;
	}

	/* fudge directed rounding modes as though the result were positive */
	if (z->l.msw)
		rm ^= (rm >> 1);

	/* see if we need to round */
	if (round | sticky) {
		*fsr |= FSR_NXC;

		/* round up if necessary */
		if (rm == FSR_RP || (rm == FSR_RN && round &&
			(sticky || (frac4 & 1)))) {
			if (++frac4 == 0)
				if (++frac3 == 0)
					if (++frac2 == 0)
						if (++lx >= 0x20000) {
							lx >>= 1;
							ex++;
						}
		}
	}

	/* store the result */
	z->l.msw |= (ex << 16) | (lx & 0xffff);
	z->l.frac2 = frac2;
	z->l.frac3 = frac3;
	z->l.frac4 = frac4;
}
