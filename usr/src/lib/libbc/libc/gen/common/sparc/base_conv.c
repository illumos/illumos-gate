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
#pragma ident	"%Z%%M%	%I%	%E% SMI" 

/*
 * Copyright (c) 1986 by Sun Microsystems, Inc. 
 */

/*
 * Machine-independent versions of base conversion primitives.
 * Routines to multiply buffers by 2**16 or 10**4. Base 10**4 buffers have
 * b[i] < 10000, carry in and out < 65536. Base 2**16 buffers have b[i] <
 * 65536, carry in and out < 10000. If n is positive, b[0]..b[n-1] are
 * processed; if n is negative, b[0]..b[n+1] are processed. 
 */

void 
_fourdigits(t, d)
	unsigned        t;
	char            d[4];

/* Converts t < 10000 into four ascii digits at *pc.	 */

{
	register short  i;

	i = 3;
	do {
		d[i] = '0' + t % 10;
		t = t / 10;
	}
	while (--i != -1);
}

unsigned 
_quorem10000(u, pr)
	unsigned        u;
	unsigned       *pr;
{
	*pr = u % 10000;
	return (u / 10000);
}

void 
_mul_10000(b, n, c)
	unsigned       *b;
	int             n;
	unsigned       *c;
{
	/* Multiply base-2**16 buffer by 10000. */

	register unsigned carry, t;
	register short int i;
	register unsigned *pb;

	carry = *c;
	pb = b;
	if ((i = n) > 0) {
		i--;
		do {
			*pb = (t = (*pb * 10000) + carry) & 0xffff;
			pb++;
			carry = t >> 16;
		}
		while (--i != -1);
	} else {
		i = -i - 1;
		do {
			*pb = (t = (*pb * 10000) + carry) & 0xffff;
			pb--;
			carry = t >> 16;
		}
		while (--i != -1);
	}
	*c = carry;
}

void 
_mul_65536(b, n, c)
	unsigned       *b;
	int             n;
	unsigned       *c;
{
	/* Multiply base-10**4 buffer by 65536. */

	register unsigned carry, t;
	register short int i;
	register unsigned *pb;

	carry = *c;
	pb = b;
	if ((i = n) > 0) {
		i--;
		do {
			*pb = (t = (*pb << 16) | carry) % 10000;
			pb++;
			carry = t / 10000;
		}
		while (--i != -1);
	} else {
		i = -i - 1;
		do {
			*pb = (t = (*pb << 16) | carry) % 10000;
			pb--;
			carry = t / 10000;
		}
		while (--i != -1);
	}
	*c = carry;
}
