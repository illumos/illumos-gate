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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains bignum implementation code that
 * is specific to x86, but which is still more appropriate
 * to write in C, rather than assembly language.
 * bignum_i386_asm.s does all the assembly language code
 * for x86 specific bignum support.  The assembly language
 * source file has pure code, no data.  Let the C compiler
 * generate what is needed to handle the variations in
 * data representation and addressing, for example,
 * statically linked vs PIC.
 */

#include "bignum.h"

#if defined(_KERNEL)
#include <sys/cpuvar.h>
#include <sys/disp.h>
#endif

extern uint32_t big_mul_set_vec_sse2(uint32_t *, uint32_t *, int, uint32_t);
extern uint32_t big_mul_add_vec_sse2(uint32_t *, uint32_t *, int, uint32_t);
extern void big_mul_vec_sse2(uint32_t *, uint32_t *, int, uint32_t *, int);
extern void big_sqr_vec_sse2(uint32_t *, uint32_t *, int);

#if defined(MMX_MANAGE)

extern uint32_t big_mul_set_vec_sse2_nsv(uint32_t *, uint32_t *, int, uint32_t);
extern uint32_t big_mul_add_vec_sse2_nsv(uint32_t *, uint32_t *, int, uint32_t);
extern void big_mul_vec_sse2_nsv(uint32_t *, uint32_t *, int, uint32_t *, int);
extern void big_sqr_vec_sse2_nsv(uint32_t *, uint32_t *, int);

#endif

extern uint32_t big_mul_set_vec_umul(uint32_t *, uint32_t *, int, uint32_t);
extern uint32_t big_mul_add_vec_umul(uint32_t *, uint32_t *, int, uint32_t);
extern void big_mul_vec_umul(uint32_t *, uint32_t *, int, uint32_t *, int);
extern void big_sqr_vec_umul(uint32_t *, uint32_t *, int);

extern uint32_t bignum_use_sse2();

static void bignum_i386_init();

static uint32_t big_mul_set_vec_init(uint32_t *, uint32_t *, int, uint32_t);
static uint32_t big_mul_add_vec_init(uint32_t *, uint32_t *, int, uint32_t);
static void big_mul_vec_init(uint32_t *, uint32_t *, int, uint32_t *, int);
static void big_sqr_vec_init(uint32_t *, uint32_t *, int);

uint32_t
(*big_mul_set_vec_impl)(uint32_t *r, uint32_t *a, int len, uint32_t digit)
	= &big_mul_set_vec_init;

uint32_t
(*big_mul_add_vec_impl)(uint32_t *r, uint32_t *a, int len, uint32_t digit)
	= &big_mul_add_vec_init;

void
(*big_mul_vec_impl)(uint32_t *r, uint32_t *a, int alen, uint32_t *b, int blen)
	= &big_mul_vec_init;
void
(*big_sqr_vec_impl)(uint32_t *r, uint32_t *a, int alen)
	= &big_sqr_vec_init;

static uint32_t
big_mul_set_vec_init(uint32_t *r, uint32_t *a, int len, uint32_t digit)
{
	bignum_i386_init();
	return ((*big_mul_set_vec_impl)(r, a, len, digit));
}

static uint32_t
big_mul_add_vec_init(uint32_t *r, uint32_t *a, int len, uint32_t digit)
{
	bignum_i386_init();
	return ((*big_mul_add_vec_impl)(r, a, len, digit));
}

static void
big_mul_vec_init(uint32_t *r, uint32_t *a, int alen, uint32_t *b, int blen)
{
	bignum_i386_init();
	(*big_mul_vec_impl)(r, a, alen, b, blen);
}

static void
big_sqr_vec_init(uint32_t *r, uint32_t *a, int alen)
{
	bignum_i386_init();
	(*big_sqr_vec_impl)(r, a, alen);
}

static void
bignum_i386_init()
{
	if (bignum_use_sse2() != 0) {
		big_mul_set_vec_impl = &big_mul_set_vec_sse2;
		big_mul_add_vec_impl = &big_mul_add_vec_sse2;
		big_mul_vec_impl = &big_mul_vec_sse2;
		big_sqr_vec_impl = &big_sqr_vec_sse2;
	} else {
		big_mul_set_vec_impl = &big_mul_set_vec_umul;
		big_mul_add_vec_impl = &big_mul_add_vec_umul;
		big_mul_vec_impl = &big_mul_vec_umul;
		big_sqr_vec_impl = &big_sqr_vec_umul;
	}
}

void
big_mul_vec_umul(uint32_t *r, uint32_t *a, int alen, uint32_t *b, int blen)
{
	int i;

	r[alen] = big_mul_set_vec_umul(r, a, alen, b[0]);
	for (i = 1; i < blen; ++i)
		r[alen + i] = big_mul_add_vec_umul(r+i, a, alen, b[i]);
}

void
big_sqr_vec_umul(uint32_t *r, uint32_t *a, int alen)
{
	int i;

	r[alen] = big_mul_set_vec_umul(r, a, alen, a[0]);
	for (i = 1; i < alen; ++i)
		r[alen + i] = big_mul_add_vec_umul(r+i, a, alen, a[i]);
}

#if defined(_KERNEL)

void
kpr_disable()
{
	kpreempt_disable();
}

void
kpr_enable()
{
	kpreempt_enable();
}

#endif
