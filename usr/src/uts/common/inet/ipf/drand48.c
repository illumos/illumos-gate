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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved  	*/

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
/*
 *	New assumptions (supercede those stated above) for 64-bit work.
 *	Longs are now 64 bits, and we are bound by standards to return
 *	type long, hovever all internal calculations where long was
 *	previously used (32 bit precision) are now using the int32_t
 *	type (32 bit precision in both ILP32 and LP64 worlds).
 */

#include <sys/mutex.h>

static kmutex_t seed_lock;
static int	init48done = 0;

#define	EXPORT0(TYPE, fn, fnu)	TYPE fn() { \
	TYPE res; \
	mutex_enter(&seed_lock); \
	res = fnu(); \
	mutex_exit(&seed_lock); \
	return (res); }
#define	EXPORT1(TYPE, fn, fnu)	TYPE fn(unsigned short xsubi[3]) { \
	TYPE res; \
	mutex_enter(&seed_lock); \
	res = fnu(xsubi); \
	mutex_exit(&seed_lock); \
	return (res); }

#define	N	16
#define	MASK	((unsigned)(1 << (N - 1)) + (1 << (N - 1)) - 1)
#define	LOW(x)	((unsigned)(x) & MASK)
#define	HIGH(x)	LOW((x) >> N)
#define	MUL(x, y, z)	{ int32_t l = (int32_t)(x) * (int32_t)(y); \
		(z)[0] = LOW(l); (z)[1] = HIGH(l); }
#define	CARRY(x, y)	((int32_t)(x) + (int32_t)(y) > MASK)
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
#define	REST(v)	for (i = 0; i < 3; i++) { xsubi[i] = x[i]; x[i] = temp[i]; } \
		return (v)
#define	NEST(TYPE, f, F) static TYPE f(unsigned short *xsubi) { \
	int i; TYPE v; unsigned temp[3]; \
	for (i = 0; i < 3; i++) { temp[i] = x[i]; x[i] = LOW(xsubi[i]); }  \
	v = F(); REST(v); }

/* Way ugly solution to problem names, but it works */
#define	x	_drand48_x
#define	a	_drand48_a
#define	c	_drand48_c
/* End way ugly */
static unsigned x[3] = { X0, X1, X2 }, a[3] = { A0, A1, A2 }, c = C;
static unsigned short lastx[3];
static void next(void);

static long
ipf_r_lrand48_u(void)
{
	next();
	return ((long)((int32_t)x[2] << (N - 1)) + (x[1] >> 1));
}

static void
init48(void)
{
	mutex_init(&seed_lock, 0L, MUTEX_DRIVER, 0L);
	init48done = 1;
}

static long
ipf_r_mrand48_u(void)
{
	next();
	return ((long)((int32_t)x[2] << N) + x[1]);
}

static void
next(void)
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
ipf_r_srand48(long seedval)
{
	int32_t fixseed = (int32_t)seedval;	/* limit to 32 bits */

	if (init48done == 0)
		init48();
	mutex_enter(&seed_lock);
	SEED(X0, LOW(fixseed), HIGH(fixseed));
	mutex_exit(&seed_lock);
}

EXPORT0(long, ipf_r_lrand48, ipf_r_lrand48_u)

#include <sys/random.h>

unsigned
ipf_random()
{
	static int seeded = 0;

	if (seeded == 0) {
		long seed;

		/*
		 * Keep reseeding until some good randomness comes from the
		 * kernel. One of two things will happen: it will succeed or
		 * it will fail (with poor randomness), thus creating NAT
		 * sessions will be "slow" until enough randomness is gained
		 * to not need to get more. It isn't necessary to initialise
		 * seed as it will just pickup whatever random garbage has
		 * been left on the heap and that's good enough until we
		 * get some good garbage.
		 */
		if (random_get_bytes((uint8_t *)&seed, sizeof (seed)) == 0)
			seeded = 1;
		ipf_r_srand48(seed);
	}

	return (unsigned)ipf_r_lrand48();
}
