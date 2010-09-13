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
 * Copyright 1996 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*      Copyright (c) 1984 AT&T */
/*        All Rights Reserved   */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/
/*
 *	drand48, etc. pseudo-random number generator
 *	This implementation assumes unsigned short integers of at least
 *	16 bits, long integers of at least 32 bits, and ignores
 *	overflows on adding or multiplying two unsigned integers.
 *	Two's-complement representation is assumed in a few places.
 *	Some extra masking is done if unsigneds are exactly 16 bits
 *	or longs are exactly 32 bits, but so what?
 *	An assembly-language implementation would run significantly faster.
 */
#define	N	16
#define	MASK	((unsigned)(1 << (N - 1)) + (1 << (N - 1)) - 1)
#define	LOW(x)	((unsigned)(x) & MASK)
#define	HIGH(x)	LOW((x) >> N)
#define	MUL(x, y, z)	{ long l = (long)(x) * (long)(y); \
		(z)[0] = LOW(l); (z)[1] = HIGH(l); }
#define	CARRY(x, y)	((long)(x) + (long)(y) > MASK)
#define	ADDEQU(x, y, z)	(z = CARRY(x, (y)), x = LOW(x + (y)))
#define	X0	0x330E
#define	X1	0xABCD
#define	X2	0x1234
#define	A0	0xE66D
#define	A1	0xDEEC
#define	A2	0x5
#define	C	0xB
#define	SET3(x, x0, x1, x2)	((x)[0] = (x0), (x)[1] = (x1), (x)[2] = (x2))
#define	SETLOW(x, y, n) SET3(x, LOW((y)[n]), LOW((y)[(n)+1]), LOW((y)[(n)+2]))
#define	SEED(x0, x1, x2) (SET3(x, x0, x1, x2), SET3(a, A0, A1, A2), c = C)
#define	REST(v)							\
	for (i = 0; i < 3; i++) {				\
		xsubi[i] = x[i];				\
		x[i] = temp[i];					\
	}							\
	return (v)

#define	NEST(TYPE, f, F)					\
	TYPE f(xsubi)						\
	register unsigned short *xsubi;				\
	{							\
		register int i;					\
		register TYPE v;				\
		unsigned temp[3];				\
								\
		for (i = 0; i < 3; i++) {			\
			temp[i] = x[i];				\
			x[i] = LOW(xsubi[i]);			\
		}						\
		v = F();					\
		REST(v);					\
	}

static unsigned x[3] = { X0, X1, X2 }, a[3] = { A0, A1, A2 }, c = C;
static unsigned short lastx[3];
static void next();

double
drand48()
{
	static double two16m = 1.0 / (1L << N);

	next();
	return (two16m * (two16m * (two16m * x[0] + x[1]) + x[2]));
}

NEST(double, erand48, drand48)

long
lrand48()
{
	next();
	return (((long)x[2] << (N - 1)) + (x[1] >> 1));
}

long
mrand48()
{
	next();
	return (((long)x[2] << N) + x[1]);
}

static void
next()
{
	unsigned p[2], q[2], r[2], carry0, carry1;

	MUL(a[0], x[0], p);
	ADDEQU(p[0], c, carry0);
	ADDEQU(p[1], carry0, carry1);
	MUL(a[0], x[1], q);
	ADDEQU(p[1], q[0], carry0);
	MUL(a[1], x[0], r);
	x[2] = LOW(carry0 + carry1 + CARRY(p[1], r[0]) + q[1] + r[1] +
		a[0] * x[2] + a[1] * x[1] + a[2] * x[0]);
	x[1] = LOW(p[1] + r[0]);
	x[0] = LOW(p[0]);
}

void
srand48(seedval)
long seedval;
{
	SEED(X0, LOW(seedval), HIGH(seedval));
}

unsigned short *
seed48(seed16v)
unsigned short seed16v[3];
{
	SETLOW(lastx, x, 0);
	SEED(LOW(seed16v[0]), LOW(seed16v[1]), LOW(seed16v[2]));
	return (lastx);
}

void
lcong48(param)
unsigned short param[7];
{
	SETLOW(x, param, 0);
	SETLOW(a, param, 3);
	c = LOW(param[6]);
}

NEST(long, nrand48, lrand48)

NEST(long, jrand48, mrand48)

#ifdef DRIVER
/*
 *	This should print the sequences of integers in Tables 2
 *		and 1 of the TM:
 *	1623, 3442, 1447, 1829, 1305, ...
 *	657EB7255101, D72A0C966378, 5A743C062A23, ...
 */
#include <stdio.h>

main()
{
	int i;

	for (i = 0; i < 80; i++) {
		printf("%4d ", (int)(4096 * drand48()));
		printf("%.4X%.4X%.4X\n", x[2], x[1], x[0]);
	}
}
#endif
