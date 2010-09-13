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
 * Copyright 1988 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "base_conversion.h"

/*	Fundamental utilities for base conversion that should be recoded as assembly language subprograms or as inline expansion templates. */

/* Converts t < 10000 into four ascii digits at *pc.     */
void
_fourdigitsquick(short unsigned t, char *d)
{
	short  i;

	i = 3;
	do {
		d[i] = '0' + t % 10;
		t = t / 10;
	}
	while (--i != -1);
}

void
_multiply_base_two_vector(short unsigned n, _BIG_FLOAT_DIGIT *px,
    short unsigned *py, _BIG_FLOAT_DIGIT product[3])
{
	/*
	 * Given xi and yi, base 2**16 vectors of length n, computes dot
	 * product
	 * 
	 * sum (i=0,n-1) of x[i]*y[n-1-i]
	 * 
	 * Product may fill as many as three short-unsigned buckets. Product[0]
	 * is least significant, product[2] most.
	 */

	unsigned long   acc, p;
	short unsigned  carry;
	int             i;

	acc = 0;
	carry = 0;
	for (i = 0; i < n; i++) {
	p=_umac(px[i],py[n - 1 - i],acc);
		if (p < acc)
			carry++;
		acc = p;
	}
	product[0] = (_BIG_FLOAT_DIGIT) (acc & 0xffff);
	product[1] = (_BIG_FLOAT_DIGIT) (acc >> 16);
	product[2] = (_BIG_FLOAT_DIGIT) (carry);
}

void
_multiply_base_ten_vector(short unsigned n, _BIG_FLOAT_DIGIT *px,
    short unsigned *py, _BIG_FLOAT_DIGIT product[3])
{
	/*
	 * Given xi and yi, base 10**4 vectors of length n, computes dot
	 * product
	 * 
	 * sum (i=0,n-1) of x[i]*y[n-1-i]
	 * 
	 * Product may fill as many as three short-unsigned buckets. Product[0]
	 * is least significant, product[2] most.
	 */

#define ABASE	3000000000U	/* Base of accumulator. */

	unsigned long   acc;
	short unsigned  carry;
	int             i;

	acc = 0;
	carry = 0;
	for (i = 0; i < n; i++) {
	acc=_umac(px[i],py[n - 1 - i],acc);
		if (acc >= (unsigned long) ABASE) {
			carry++;
			acc -= ABASE;
		}
	}
	/*
	 NOTE: because 
		acc * <= ABASE-1,
		acc/10000 <= 299999
	 which would overflow a short unsigned
	 */
	product[0] = (_BIG_FLOAT_DIGIT) (acc % 10000);
	acc /= 10000;
	product[1] = (_BIG_FLOAT_DIGIT) (acc % 10000);
	acc /= 10000;
	product[2] = (_BIG_FLOAT_DIGIT) (acc + (ABASE / 100000000) * carry);
}
