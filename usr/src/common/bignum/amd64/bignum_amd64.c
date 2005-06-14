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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains bignum implementation code that
 * is specific to AMD64, but which is still more appropriate
 * to write in C, rather than assembly language.
 * bignum_amd64_asm.s does all the assembly language code
 * for AMD64 specific bignum support.  The assembly language
 * source file has pure code, no data.  Let the C compiler
 * generate what is needed to handle the variations in
 * data representation and addressing, for example,
 * statically linked vs PIC.
 */

#include "bignum.h"

/*
 * The bignum interface deals only with arrays of 32-bit "digits".
 * The 64-bit bignum functions are internal implementation details.
 * If a bignum happens to be aligned on a 64-bit boundary
 * and its length is even, then the pure 64-bit implementation
 * can be used.
 */

#define	ISALIGNED64(p) (((uintptr_t)(p) & 7) == 0)
#define	ISBIGNUM64(p, len) (ISALIGNED64(p) && (((len) & 1) == 0))

#if defined(__lint)

extern uint64_t *P64(uint32_t *addr);

#else /* lint */

#define	P64(addr) ((uint64_t *)addr)

#endif /* lint */

extern uint64_t big_mul_set_vec64(uint64_t *, uint64_t *, int, uint64_t);
extern uint64_t big_mul_add_vec64(uint64_t *, uint64_t *, int, uint64_t);
extern void big_mul_vec64(uint64_t *, uint64_t *, int, uint64_t *, int);
extern void big_sqr_vec64(uint64_t *, uint64_t *, int);

extern uint32_t big_mul_set_vec32(uint32_t *, uint32_t *, int, uint32_t);
extern uint32_t big_mul_add_vec32(uint32_t *, uint32_t *, int, uint32_t);
extern void big_mul_vec32(uint32_t *, uint32_t *, int, uint32_t *, int);
extern void big_sqr_vec32(uint32_t *, uint32_t *, int);

uint32_t big_mul_set_vec(uint32_t *, uint32_t *, int, uint32_t);
uint32_t big_mul_add_vec(uint32_t *, uint32_t *, int, uint32_t);
void big_mul_vec(uint32_t *, uint32_t *, int, uint32_t *, int);
void big_sqr_vec(uint32_t *, uint32_t *, int);


void
big_mul_vec(uint32_t *r, uint32_t *a, int alen, uint32_t *b, int blen)
{
	if (!ISALIGNED64(r) || !ISBIGNUM64(a, alen) || !ISBIGNUM64(b, blen)) {
		big_mul_vec32(r, a, alen, b, blen);
		return;
	}

	big_mul_vec64(P64(r), P64(a), alen / 2, P64(b), blen / 2);
}

void
big_sqr_vec(uint32_t *r, uint32_t *a, int alen)
{
	if (!ISALIGNED64(r) || !ISBIGNUM64(a, alen)) {
		big_mul_vec32(r, a, alen, a, alen);
		return;
	}
	big_sqr_vec64(P64(r), P64(a), alen / 2);
}

/*
 * It is OK to cast the 64-bit carry to 32 bit.
 * There will be no loss, because although we are multiplying the vector, a,
 * by a uint64_t, its value cannot exceedthat of a uint32_t.
 */

uint32_t
big_mul_set_vec(uint32_t *r, uint32_t *a, int alen, uint32_t digit)
{
	if (!ISALIGNED64(r) || !ISBIGNUM64(a, alen))
		return (big_mul_set_vec32(r, a, alen, digit));

	return (big_mul_set_vec64(P64(r), P64(a), alen / 2, digit));
}
uint32_t
big_mul_add_vec(uint32_t *r, uint32_t *a, int alen, uint32_t digit)
{
	if (!ISALIGNED64(r) || !ISBIGNUM64(a, alen))
		return (big_mul_add_vec32(r, a, alen, digit));

	return (big_mul_add_vec64(P64(r), P64(a), alen / 2, digit));
}


void
big_mul_vec64(uint64_t *r, uint64_t *a, int alen, uint64_t *b, int blen)
{
	int i;

	r[alen] = big_mul_set_vec64(r, a, alen, b[0]);
	for (i = 1; i < blen; ++i)
		r[alen + i] = big_mul_add_vec64(r+i, a, alen, b[i]);
}

void
big_mul_vec32(uint32_t *r, uint32_t *a, int alen, uint32_t *b, int blen)
{
	int i;

	r[alen] = big_mul_set_vec32(r, a, alen, b[0]);
	for (i = 1; i < blen; ++i)
		r[alen + i] = big_mul_add_vec32(r+i, a, alen, b[i]);
}

void
big_sqr_vec32(uint32_t *r, uint32_t *a, int alen)
{
	big_mul_vec32(r, a, alen, a, alen);
}


uint32_t
big_mul_set_vec32(uint32_t *r, uint32_t *a, int alen, uint32_t digit)
{
	uint64_t p, d, cy;

	d = (uint64_t)digit;
	cy = 0;
	while (alen != 0) {
		p = (uint64_t)a[0] * d + cy;
		r[0] = (uint32_t)p;
		cy = p >> 32;
		++r;
		++a;
		--alen;
	}
	return ((uint32_t)cy);
}

uint32_t
big_mul_add_vec32(uint32_t *r, uint32_t *a, int alen, uint32_t digit)
{
	uint64_t p, d, cy;

	d = (uint64_t)digit;
	cy = 0;
	while (alen != 0) {
		p = r[0] + (uint64_t)a[0] * d + cy;
		r[0] = (uint32_t)p;
		cy = p >> 32;
		++r;
		++a;
		--alen;
	}
	return ((uint32_t)cy);
}
