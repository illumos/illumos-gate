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

#define	big_div_pos_fast big_div_pos

#include "bignum.h"

/*
 * Configuration guide
 * -------------------
 *
 * There are 4 preprocessor symbols used to configure the bignum
 * implementation.  This file contains no logic to configure based on
 * processor; we leave that to the Makefiles to specify.
 *
 * USE_FLOATING_POINT
 *   Meaning: There is support for a fast floating-point implementation of
 *   Montgomery multiply.
 *
 * PSR_MUL
 *   Meaning: There are processor-specific versions of the low level
 *   functions to implement big_mul.  Those functions are: big_mul_set_vec,
 *   big_mul_add_vec, big_mul_vec, and big_sqr_vec.  PSR_MUL implies support
 *   for all 4 functions.  You cannot pick and choose which subset of these
 *   functions to support; that would lead to a rat's nest of #ifdefs.
 *
 * HWCAP
 *   Meaning: Call multiply support functions through a function pointer.
 *   On x86, there are multiple implementations for differnt hardware
 *   capabilities, such as MMX, SSE2, etc.  Tests are made at run-time, when
 *   a function is first used.  So, the support functions are called through
 *   a function pointer.  There is no need for that on Sparc, because there
 *   is only one implementation; support functions are called directly.
 *   Later, if there were some new VIS instruction, or something, and a
 *   run-time test were needed, rather than variant kernel modules and
 *   libraries, then HWCAP would be defined for Sparc, as well.
 *
 * UMUL64
 *   Meaning: It is safe to use generic C code that assumes the existence
 *   of a 32 x 32 --> 64 bit unsigned multiply.  If this is not defined,
 *   then the generic code for big_mul_add_vec() must necessarily be very slow,
 *   because it must fall back to using 16 x 16 --> 32 bit multiplication.
 *
 */


#ifdef	_KERNEL

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/param.h>
#include <sys/sunddi.h>

#define	big_malloc(size)	kmem_alloc(size, KM_NOSLEEP)
#define	big_free(ptr, size)	kmem_free(ptr, size)

void *
big_realloc(void *from, size_t oldsize, size_t newsize)
{
	void *rv;

	rv = kmem_alloc(newsize, KM_NOSLEEP);
	if (rv != NULL)
		bcopy(from, rv, oldsize);
	kmem_free(from, oldsize);
	return (rv);
}

#else	/* _KERNEL */

#include <stdlib.h>
#include <stdio.h>

#ifndef MALLOC_DEBUG

#define	big_malloc(size)	malloc(size)
#define	big_free(ptr, size)	free(ptr)

#else

void
big_free(void *ptr, size_t size)
{
	printf("freed %d bytes at %p\n", size, ptr);
	free(ptr);
}

void *
big_malloc(size_t size)
{
	void *rv;
	rv = malloc(size);
	printf("malloced %d bytes, addr:%p\n", size, rv);
	return (rv);
}
#endif /* MALLOC_DEBUG */

#define	big_realloc(x, y, z) realloc((x), (z))

void
printbignum(char *aname, BIGNUM *a)
{
	int i;

	(void) printf("\n%s\n%d\n", aname, a->sign*a->len);
	for (i = a->len - 1; i >= 0; i--) {
		(void) printf("%08x ", a->value[i]);
		if ((i % 8 == 0) && (i != 0))
		    (void) printf("\n");
	}
	(void) printf("\n");
}

#endif	/* _KERNEL */


/* size in 32-bit words */
BIG_ERR_CODE
big_init(BIGNUM *number, int size)
{
	number->value = big_malloc(sizeof (uint32_t) * size);
	if (number->value == NULL) {
		return (BIG_NO_MEM);
	}
	number->size = size;
	number->len = 0;
	number->sign = 1;
	number->malloced = 1;
	return (BIG_OK);
}

/* size in 32-bit words */
BIG_ERR_CODE
big_init1(BIGNUM *number, int size, uint32_t *buf, int bufsize)
{
	if ((buf == NULL) || (size > bufsize)) {
		number->value = big_malloc(sizeof (uint32_t) * size);
		if (number->value == NULL) {
			return (BIG_NO_MEM);
		}
		number->size = size;
		number->malloced = 1;
	} else {
		number->value = buf;
		number->size = bufsize;
		number->malloced = 0;
	}
		number->len = 0;
		number->sign = 1;

	return (BIG_OK);
}

void
big_finish(BIGNUM *number)
{
	if (number->malloced == 1) {
		big_free(number->value, sizeof (uint32_t) * number->size);
		number->malloced = 0;
	}
}

/*
 *  bn->size should be at least (len + 3) / 4
 * converts from byte-big-endian format to bignum format (words in
 * little endian order, but bytes within the words big endian)
 */
void
bytestring2bignum(BIGNUM *bn, uchar_t *kn, size_t len)
{
	int		i, j, offs;
	uint32_t	word;
	uchar_t		*knwordp;

#ifdef	_LP64
	/* LINTED */
	offs = (uint32_t)len % sizeof (uint32_t);
	/* LINTED */
	bn->len = (uint32_t)len / sizeof (uint32_t);
	/* LINTED */
	for (i = 0; i < (uint32_t)len / sizeof (uint32_t); i++) {
#else	/* !_LP64 */
	offs = len % sizeof (uint32_t);
	bn->len = len / sizeof (uint32_t);
	for (i = 0; i < len / sizeof (uint32_t); i++) {
#endif	/* _LP64 */
		knwordp = &(kn[len - sizeof (uint32_t) * (i + 1)]);
		word = knwordp[0];
		for (j = 1; j < sizeof (uint32_t); j++) {
			word = (word << 8)+ knwordp[j];
		}
		bn->value[i] = word;
	}
	if (offs > 0) {
		word = kn[0];
		for (i = 1; i < offs; i++) word = (word << 8) + kn[i];
		bn->value[bn->len++] = word;
	}
	while ((bn->len > 1) && (bn->value[bn->len-1] == 0)) {
		bn->len --;
	}
}

/*
 * copies the least significant len bytes if
 * len < bn->len * sizeof (uint32_t)
 * converts from bignum format to byte-big-endian format.
 * bignum format is words in little endian order,
 * but bytes within words in native byte order.
 */
void
bignum2bytestring(uchar_t *kn, BIGNUM *bn, size_t len)
{
	int		i, j, offs;
	uint32_t	word;

	if (len < sizeof (uint32_t) * bn->len) {
#ifdef	_LP64
		/* LINTED */
		for (i = 0; i < (uint32_t)len / sizeof (uint32_t); i++) {
#else	/* !_LP64 */
		for (i = 0; i < len / sizeof (uint32_t); i++) {
#endif	/* _LP64 */
			word = bn->value[i];
			for (j = 0; j < sizeof (uint32_t); j++) {
				kn[len - sizeof (uint32_t) * i - j - 1] =
				    word & 0xff;
				word = word >> 8;
			}
		}
#ifdef	_LP64
		/* LINTED */
		offs = (uint32_t)len % sizeof (uint32_t);
#else	/* !_LP64 */
		offs = len % sizeof (uint32_t);
#endif	/* _LP64 */
		if (offs > 0) {
			word = bn->value[len / sizeof (uint32_t)];
#ifdef	_LP64
			    /* LINTED */
			    for (i =  (uint32_t)len % sizeof (uint32_t);
				i > 0; i --) {
#else	/* !_LP64 */
			    for (i = len % sizeof (uint32_t); i > 0; i --) {
#endif	/* _LP64 */
				    kn[i - 1] = word & 0xff;
				    word = word >> 8;
			    }
		}
	} else {
		for (i = 0; i < bn->len; i++) {
			word = bn->value[i];
			for (j = 0; j < sizeof (uint32_t); j++) {
				kn[len - sizeof (uint32_t) * i - j - 1] =
				    word & 0xff;
				word = word >> 8;
			}
		}
#ifdef	_LP64
		/* LINTED */
		for (i = 0; i < (uint32_t)len - sizeof (uint32_t) * bn->len;
		    i++) {
#else	/* !_LP64 */
		for (i = 0; i < len - sizeof (uint32_t) * bn->len; i++) {
#endif	/* _LP64 */
			kn[i] = 0;
		}
	}
}


int
big_bitlength(BIGNUM *a)
{
	int		l, b;
	uint32_t	c;

	l = a->len - 1;
	while ((l > 0) && (a->value[l] == 0)) {
		l--;
	}
	b = sizeof (uint32_t) * 8;
	c = a->value[l];
	while ((b > 1) && ((c & 0x80000000) == 0)) {
		c = c << 1;
		b--;
	}
	return (l * (int)sizeof (uint32_t) * 8 + b);
}


BIG_ERR_CODE
big_copy(BIGNUM *dest, BIGNUM *src)
{
	uint32_t *newptr;
	int i, len;

	len = src->len;
	while ((len > 1) && (src->value[len - 1] == 0))
		len--;
	src->len = len;
	if (dest->size < len) {
		if (dest->malloced == 1) {
			newptr = (uint32_t *)big_realloc(dest->value,
			    sizeof (uint32_t) * dest->size,
			    sizeof (uint32_t) * len);
		} else {
			newptr = (uint32_t *)
			    big_malloc(sizeof (uint32_t) * len);
			if (newptr != NULL) dest->malloced = 1;
		}
		if (newptr == NULL)
			return (BIG_NO_MEM);
		dest->value = newptr;
		dest->size = len;
	}
	dest->len = len;
	dest->sign = src->sign;
	for (i = 0; i < len; i++) dest->value[i] = src->value[i];

	return (BIG_OK);
}


BIG_ERR_CODE
big_extend(BIGNUM *number, int size)
{
	uint32_t	*newptr;
	int		i;

	if (number->size >= size)
		return (BIG_OK);
	if (number->malloced) {
		number->value =
		    big_realloc(number->value,
			sizeof (uint32_t) * number->size,
			sizeof (uint32_t) * size);
	} else {
		newptr = big_malloc(sizeof (uint32_t) * size);
		if (newptr != NULL) {
			for (i = 0; i < number->size; i++) {
				newptr[i] = number->value[i];
			}
		}
		number->value = newptr;
	}

	if (number->value == NULL)
		return (BIG_NO_MEM);

	number->size = size;
	number->malloced = 1;
	return (BIG_OK);
}


int
big_is_zero(BIGNUM *n)
{
	int i, result;

	result = 1;
	for (i = 0; i < n->len; i++)
		if (n->value[i] != 0) result = 0;
	return (result);
}


BIG_ERR_CODE
big_add_abs(BIGNUM *result, BIGNUM *aa, BIGNUM *bb)
{
	int i, shorter, longer;
	uint32_t cy, ai;
	uint32_t *r, *a, *b, *c;
	BIG_ERR_CODE err;

	if (aa->len > bb->len) {
		shorter = bb->len;
		longer = aa->len;
		c = aa->value;
	} else {
		shorter = aa->len;
		longer = bb->len;
		c = bb->value;
	}
	if (result->size < longer + 1) {
		err = big_extend(result, longer + 1);
		if (err != BIG_OK)
			return (err);
	}

	r = result->value;
	a = aa->value;
	b = bb->value;
	cy = 0;
	for (i = 0; i < shorter; i++) {
		ai = a[i];
		r[i] = ai + b[i] + cy;
		if (r[i] > ai) cy = 0;
		else if (r[i] < ai) cy = 1;
	}
	for (; i < longer; i++) {
		ai = c[i];
		r[i] = ai + cy;
		if (r[i] >= ai) cy = 0;
	}
	if (cy == 1) {
		r[i] = cy;
		result->len = longer + 1;
	} else {
		result->len = longer;
	}
	result->sign = 1;
	return (BIG_OK);
}


/* caller must make sure that result has at least len words allocated */
void
big_sub_vec(uint32_t *r, uint32_t *a, uint32_t *b, int len)
{
	int i;
	uint32_t cy, ai;

	cy = 1;
	for (i = 0; i < len; i++) {
		ai = a[i];
		r[i] = ai + (~b[i]) + cy;
		if (r[i] > ai) cy = 0;
		else if (r[i] < ai) cy = 1;
	}
}


/* result=aa-bb  it is assumed that aa>=bb */
BIG_ERR_CODE
big_sub_pos(BIGNUM *result, BIGNUM *aa, BIGNUM *bb)
{
	int i, shorter;
	uint32_t cy, ai;
	uint32_t *r, *a, *b;
	BIG_ERR_CODE err;

	if (aa->len > bb->len) shorter = bb->len;
	else shorter = aa->len;
	if (result->size < aa->len) {
		err = big_extend(result, aa->len);
		if (err != BIG_OK)
			return (err);
	}

	r = result->value;
	a = aa->value;
	b = bb->value;
	result->len = aa->len;
	cy = 1;
	for (i = 0; i < shorter; i++) {
		ai = a[i];
		r[i] = ai + (~b[i]) + cy;
		if (r[i] > ai) cy = 0;
		else if (r[i] < ai) cy = 1;
	}
	for (; i < aa->len; i++) {
		ai = a[i];
		r[i] = ai + (~0) + cy;
		if (r[i] < ai) cy = 1;
	}
	result->sign = 1;
	if (cy == 0)
		return (BIG_INVALID_ARGS);
	else
		return (BIG_OK);
}


/* returns -1 if |aa|<|bb|, 0 if |aa|==|bb| 1 if |aa|>|bb| */
int
big_cmp_abs(BIGNUM *aa, BIGNUM *bb)
{
	int i;

	if (aa->len > bb->len) {
		for (i = aa->len - 1; i > bb->len - 1; i--) {
			if (aa->value[i] > 0)
				return (1);
		}
	} else if (aa->len < bb->len) {
		for (i = bb->len - 1; i > aa->len - 1; i--) {
			if (bb->value[i] > 0)
				return (-1);
		}
	} else i = aa->len-1;
	for (; i >= 0; i--) {
		if (aa->value[i] > bb->value[i])
			return (1);
		else if (aa->value[i] < bb->value[i])
			return (-1);
	}

	return (0);
}


BIG_ERR_CODE
big_sub(BIGNUM *result, BIGNUM *aa, BIGNUM *bb)
{
	BIG_ERR_CODE err;

	if ((bb->sign == -1) && (aa->sign == 1)) {
		if ((err = big_add_abs(result, aa, bb)) != BIG_OK)
			return (err);
		result->sign = 1;
	} else if ((aa->sign == -1) && (bb->sign == 1)) {
		if ((err = big_add_abs(result, aa, bb)) != BIG_OK)
			return (err);
		result->sign = -1;
	} else if ((aa->sign == 1) && (bb->sign == 1)) {
		if (big_cmp_abs(aa, bb) >= 0) {
			if ((err = big_sub_pos(result, aa, bb)) != BIG_OK)
				return (err);
			result->sign = 1;
		} else {
			if ((err = big_sub_pos(result, bb, aa)) != BIG_OK)
				return (err);
			result->sign = -1;
		}
	} else {
		if (big_cmp_abs(aa, bb) >= 0) {
			if ((err = big_sub_pos(result, aa, bb)) != BIG_OK)
				return (err);
			result->sign = -1;
		} else {
			if ((err = big_sub_pos(result, bb, aa)) != BIG_OK)
				return (err);
			result->sign = 1;
		}
	}
	return (BIG_OK);
}



BIG_ERR_CODE
big_add(BIGNUM *result, BIGNUM *aa, BIGNUM *bb)
{
	BIG_ERR_CODE err;

	if ((bb->sign == -1) && (aa->sign == -1)) {
		if ((err = big_add_abs(result, aa, bb)) != BIG_OK)
			return (err);
		result->sign = -1;
	} else if ((aa->sign == 1) && (bb->sign == 1)) {
		if ((err = big_add_abs(result, aa, bb)) != BIG_OK)
			return (err);
		result->sign = 1;
	} else if ((aa->sign == 1) && (bb->sign == -1)) {
		if (big_cmp_abs(aa, bb) >= 0) {
			if ((err = big_sub_pos(result, aa, bb)) != BIG_OK)
				return (err);
			result->sign = 1;
		} else {
			if ((err = big_sub_pos(result, bb, aa)) != BIG_OK)
				return (err);
			result->sign = -1;
		}
	} else {
		if (big_cmp_abs(aa, bb) >= 0) {
			if ((err = big_sub_pos(result, aa, bb)) != BIG_OK)
				return (err);
			result->sign = -1;
		} else {
			if ((err = big_sub_pos(result, bb, aa)) != BIG_OK)
				return (err);
			result->sign = 1;
		}
	}
	return (BIG_OK);
}


/* result = aa/2 aa must be positive */
BIG_ERR_CODE
big_half_pos(BIGNUM *result, BIGNUM *aa)
{
	BIG_ERR_CODE err;
	int i;
	uint32_t cy, cy1;
	uint32_t *a, *r;

	if (result->size < aa->len) {
		err = big_extend(result, aa->len);
		if (err != BIG_OK)
			return (err);
	}

	result->len = aa->len;
	a = aa->value;
	r = result->value;
	cy = 0;
	for (i = aa->len-1; i >= 0; i--) {
		cy1 = a[i] << 31;
		r[i] = (cy|(a[i] >> 1));
		cy = cy1;
	}
	if (r[result->len-1] == 0) result->len--;
	return (BIG_OK);
}

/* result  =  aa*2 aa must be positive */
BIG_ERR_CODE
big_double(BIGNUM *result, BIGNUM *aa)
{
	BIG_ERR_CODE err;
	int i, rsize;
	uint32_t cy, cy1;
	uint32_t *a, *r;

	if ((aa->len > 0) && ((aa->value[aa->len - 1] & 0x80000000) != 0))
		rsize = aa->len + 1;
	else rsize = aa->len;

	if (result->size < rsize) {
		err = big_extend(result, rsize);
		if (err != BIG_OK)
			return (err);
	}

	a = aa->value;
	r = result->value;
	if (rsize == aa->len + 1) r[rsize - 1] = 1;
	cy = 0;
	for (i = 0; i < aa->len; i++) {
		cy1 = a[i] >> 31;
		r[i] = (cy | (a[i] << 1));
		cy = cy1;
	}
	result->len = rsize;
	return (BIG_OK);
}

/* returns aa mod b, aa must be nonneg, b must be a max 16-bit integer */
uint32_t
big_mod16_pos(BIGNUM *aa, uint32_t b)
{
	int i;
	uint32_t rem;

	if (aa->len == 0)
		return (0);
	rem = aa->value[aa->len - 1] % b;
	for (i = aa->len - 2; i >= 0; i--) {
		rem = ((rem << 16) | (aa->value[i] >> 16)) % b;
		rem = ((rem << 16) | (aa->value[i] & 0xffff)) % b;
	}
	return (rem);
}


/*
 * result = aa - (2^32)^lendiff * bb
 * result->size should be at least aa->len at entry
 * aa, bb, and result should be positive
 */
void
big_sub_pos_high(BIGNUM *result, BIGNUM *aa, BIGNUM *bb)
{
	int i, lendiff;
	BIGNUM res1, aa1;

	lendiff = aa->len - bb->len;
	res1.size = result->size - lendiff;
	res1.malloced = 0;
	res1.value = result->value + lendiff;
	aa1.size = aa->size - lendiff;
	aa1.value = aa->value + lendiff;
	aa1.len = bb->len;
	aa1.sign = 1;
	(void) big_sub_pos(&res1, &aa1, bb);
	if (result->value != aa->value) {
		for (i = 0; i < lendiff; i++) {
			result->value[i] = aa->value[i];
		}
	}
	result->len = aa->len;
}


/*
 * returns 1, 0, or -1 depending on whether |aa| > , ==, or <
 *							(2^32)^lendiff * |bb|
 * aa->len should be >= bb->len
 */
int
big_cmp_abs_high(BIGNUM *aa, BIGNUM *bb)
{
	int lendiff;
	BIGNUM aa1;

	lendiff = aa->len - bb->len;
	aa1.len = bb->len;
	aa1.size = aa->size - lendiff;
	aa1.malloced = 0;
	aa1.value = aa->value + lendiff;
	return (big_cmp_abs(&aa1, bb));
}


/*
 * result = aa * b where b is a max. 16-bit positive integer.
 * result should have enough space allocated.
 */
void
big_mul16_low(BIGNUM *result, BIGNUM *aa, uint32_t b)
{
	int i;
	uint32_t t1, t2, ai, cy;
	uint32_t *a, *r;

	a = aa->value;
	r = result->value;
	cy = 0;
	for (i = 0; i < aa->len; i++) {
		ai = a[i];
		t1 = (ai & 0xffff) * b + cy;
		t2 = (ai >> 16) * b + (t1 >> 16);
		r[i] = (t1 & 0xffff) | (t2 << 16);
		cy = t2 >> 16;
	}
	r[i] = cy;
	result->len = aa->len + 1;
	result->sign = aa->sign;
}


/*
 * result = aa * b * 2^16 where b is a max. 16-bit positive integer.
 * result should have enough space allocated.
 */
void
big_mul16_high(BIGNUM *result, BIGNUM *aa, uint32_t b)
{
	int i;
	uint32_t t1, t2, ai, cy, ri;
	uint32_t *a, *r;

	a = aa->value;
	r = result->value;
	cy = 0;
	ri = 0;
	for (i = 0; i < aa->len; i++) {
		ai = a[i];
		t1 = (ai & 0xffff) * b + cy;
		t2 = (ai >> 16) * b + (t1 >> 16);
		r[i] = (t1 << 16) + ri;
		ri = t2 & 0xffff;
		cy = t2 >> 16;
	}
	r[i] = (cy << 16) + ri;
	result->len = aa->len + 1;
	result->sign = aa->sign;
}

/* it is assumed that result->size is big enough */
void
big_shiftleft(BIGNUM *result, BIGNUM *aa, int offs)
{
	int i;
	uint32_t cy, ai;

	if (offs == 0) {
		if (result != aa) {
			(void) big_copy(result, aa);
		}
		return;
	}
	cy = 0;
	for (i = 0; i < aa->len; i++) {
		ai = aa->value[i];
		result->value[i] = (ai << offs) | cy;
		cy = ai >> (32 - offs);
	}
	if (cy != 0) {
		result->len = aa->len + 1;
		result->value[result->len - 1] = cy;
	} else {
		result->len = aa->len;
	}
	result->sign = aa->sign;
}

/* it is assumed that result->size is big enough */
void
big_shiftright(BIGNUM *result, BIGNUM *aa, int offs)
{
	int i;
	uint32_t cy, ai;

	if (offs == 0) {
		if (result != aa) {
			(void) big_copy(result, aa);
		}
		return;
	}
	cy = aa->value[0] >> offs;
	for (i = 1; i < aa->len; i++) {
		ai = aa->value[i];
		result->value[i-1] = (ai << (32 - offs)) | cy;
		cy = ai >> offs;
	}
	result->len = aa->len;
	result->value[result->len - 1] = cy;
	result->sign = aa->sign;
}


/*
 * result = aa/bb   remainder = aa mod bb
 * it is assumed that aa and bb are positive
 */
BIG_ERR_CODE
big_div_pos_fast(BIGNUM *result, BIGNUM *remainder, BIGNUM *aa, BIGNUM *bb)
{
	BIG_ERR_CODE err;
	int i, alen, blen, tlen, rlen, offs;
	uint32_t higha, highb, coeff;
	uint64_t highb64;
	uint32_t *a, *b;
	BIGNUM bbhigh, bblow, tresult, tmp1, tmp2;
	uint32_t tmp1value[BIGTMPSIZE];
	uint32_t tmp2value[BIGTMPSIZE];
	uint32_t tresultvalue[BIGTMPSIZE];
	uint32_t bblowvalue[BIGTMPSIZE];
	uint32_t bbhighvalue[BIGTMPSIZE];

	a = aa->value;
	b = bb->value;
	alen = aa->len;
	blen = bb->len;
	while ((alen > 1) && (a[alen - 1] == 0)) alen = alen - 1;
	aa->len = alen;
	while ((blen > 1) && (b[blen - 1] == 0)) blen = blen - 1;
	bb->len = blen;
	if ((blen == 1) && (b[0] == 0))
		return (BIG_DIV_BY_0);

	if (big_cmp_abs(aa, bb) < 0) {
		if ((remainder != NULL) &&
		    ((err = big_copy(remainder, aa)) != BIG_OK))
			return (err);
		if (result != NULL) {
			result->len = 1;
			result->sign = 1;
			result->value[0] = 0;
		}
		return (BIG_OK);
	}

	if ((err = big_init1(&bblow, blen + 1,
	    bblowvalue, arraysize(bblowvalue))) != BIG_OK)
		return (err);

	if ((err = big_init1(&bbhigh, blen + 1,
	    bbhighvalue, arraysize(bbhighvalue))) != BIG_OK)
		goto ret1;

	if ((err = big_init1(&tmp1, alen + 2,
	    tmp1value, arraysize(tmp1value))) != BIG_OK)
		goto ret2;

	if ((err = big_init1(&tmp2, blen + 2,
	    tmp2value, arraysize(tmp2value))) != BIG_OK)
		goto ret3;

	if ((err = big_init1(&tresult, alen - blen + 2,
	    tresultvalue, arraysize(tresultvalue))) != BIG_OK)
		goto ret4;

	offs = 0;
	if (blen > 1) {
		highb64 = (((uint64_t)(b[blen - 1])) << 32) |
		    ((uint64_t)(b[blen - 2]));
	} else {
		highb64 = (((uint64_t)(b[blen - 1])) << 32);
	}
	if (highb64 >= 0x1000000000000ull) {
		highb64 = highb64 >> 16;
		offs = 16;
	}
	while ((highb64 & 0x800000000000ull) == 0) {
		highb64 = highb64 << 1;
		offs++;
	}
#ifdef	_LP64
	/* LINTED */
	highb = (highb64 >> 32) & 0xffffffff;
#else	/* !_LP64 */
	highb = highb64 >> 32;
#endif	/* _LP64 */

	big_shiftleft(&bblow, bb, offs);
	if (offs <= 15) {
		big_shiftleft(&bbhigh, &bblow, 16);
	} else {
		big_shiftright(&bbhigh, &bblow, 16);
	}
	if (bbhigh.value[bbhigh.len - 1] == 0) {
		bbhigh.len--;
	} else {
		bbhigh.value[bbhigh.len] = 0;
	}

	big_shiftleft(&tmp1, aa, offs);
	rlen = tmp1.len - bblow.len + 1;
	tresult.len = rlen;

	tmp1.len++;
	tlen = tmp1.len;
	tmp1.value[tmp1.len - 1] = 0;
	for (i = 0; i < rlen; i++) {
		higha = (tmp1.value[tlen - 1] << 16) +
		    (tmp1.value[tlen - 2] >> 16);
		coeff = higha / (highb + 1);
		big_mul16_high(&tmp2, &bblow, coeff);
		big_sub_pos_high(&tmp1, &tmp1, &tmp2);
		bbhigh.len++;
		while (tmp1.value[tlen - 1] > 0) {
			big_sub_pos_high(&tmp1, &tmp1, &bbhigh);
			coeff++;
		}
		bbhigh.len--;
		tlen--;
		tmp1.len--;
		while (big_cmp_abs_high(&tmp1, &bbhigh) >= 0) {
			big_sub_pos_high(&tmp1, &tmp1, &bbhigh);
			coeff++;
		}
		tresult.value[rlen - i - 1] = coeff << 16;
		higha = tmp1.value[tlen - 1];
		coeff = higha / (highb + 1);
		big_mul16_low(&tmp2, &bblow, coeff);
		tmp2.len--;
		big_sub_pos_high(&tmp1, &tmp1, &tmp2);
		while (big_cmp_abs_high(&tmp1, &bblow) >= 0) {
			big_sub_pos_high(&tmp1, &tmp1, &bblow);
			coeff++;
		}
		tresult.value[rlen - i - 1] =
		    tresult.value[rlen - i - 1] + coeff;
	}

	big_shiftright(&tmp1, &tmp1, offs);

	err = BIG_OK;

	if ((remainder != NULL) &&
	    ((err = big_copy(remainder, &tmp1)) != BIG_OK))
		goto ret;

	if (result != NULL)
		err = big_copy(result, &tresult);

ret:
	big_finish(&tresult);
ret4:
	big_finish(&tmp1);
ret3:
	big_finish(&tmp2);
ret2:
	big_finish(&bbhigh);
ret1:
	big_finish(&bblow);
	return (err);
}

/*
 * If there is no processor-specific integer implementation of
 * the lower level multiply functions, then this code is provided
 * for big_mul_set_vec(), big_mul_add_vec(), big_mul_vec() and
 * big_sqr_vec().
 *
 * There are two generic implementations.  One that assumes that
 * there is hardware and C compiler support for a 32 x 32 --> 64
 * bit unsigned multiply, but otherwise is not specific to any
 * processor, platform, or ISA.
 *
 * The other makes very few assumptions about hardware capabilities.
 * It does not even assume that there is any implementation of a
 * 32 x 32 --> 64 bit multiply that is accessible to C code and
 * appropriate to use.  It falls constructs 32 x 32 --> 64 bit
 * multiplies from 16 x 16 --> 32 bit multiplies.
 *
 */

#if !defined(PSR_MUL)

#ifdef UMUL64

#define	UNROLL8

#define	MUL_SET_VEC_ROUND_PREFETCH(R) \
	p = pf * d; \
	pf = (uint64_t)a[R+1]; \
	t = p + cy; \
	r[R] = (uint32_t)t; \
	cy = t >> 32

#define	MUL_SET_VEC_ROUND_NOPREFETCH(R) \
	p = pf * d; \
	t = p + cy; \
	r[R] = (uint32_t)t; \
	cy = t >> 32

#define	MUL_ADD_VEC_ROUND_PREFETCH(R) \
	t = (uint64_t)r[R]; \
	p = pf * d; \
	pf = (uint64_t)a[R+1]; \
	t = p + t + cy; \
	r[R] = (uint32_t)t; \
	cy = t >> 32

#define	MUL_ADD_VEC_ROUND_NOPREFETCH(R) \
	t = (uint64_t)r[R]; \
	p = pf * d; \
	t = p + t + cy; \
	r[R] = (uint32_t)t; \
	cy = t >> 32

#ifdef UNROLL8

#define	UNROLL 8

/*
 * r = a * b
 * where r and a are vectors; b is a single 32-bit digit
 */

uint32_t
big_mul_set_vec(uint32_t *r, uint32_t *a, int len, uint32_t b)
{
	uint64_t d, pf, p, t, cy;

	if (len == 0)
		return (0);
	cy = 0;
	d = (uint64_t)b;
	pf = (uint64_t)a[0];
	while (len > UNROLL) {
		MUL_SET_VEC_ROUND_PREFETCH(0);
		MUL_SET_VEC_ROUND_PREFETCH(1);
		MUL_SET_VEC_ROUND_PREFETCH(2);
		MUL_SET_VEC_ROUND_PREFETCH(3);
		MUL_SET_VEC_ROUND_PREFETCH(4);
		MUL_SET_VEC_ROUND_PREFETCH(5);
		MUL_SET_VEC_ROUND_PREFETCH(6);
		MUL_SET_VEC_ROUND_PREFETCH(7);
		r += UNROLL;
		a += UNROLL;
		len -= UNROLL;
	}
	if (len == UNROLL) {
		MUL_SET_VEC_ROUND_PREFETCH(0);
		MUL_SET_VEC_ROUND_PREFETCH(1);
		MUL_SET_VEC_ROUND_PREFETCH(2);
		MUL_SET_VEC_ROUND_PREFETCH(3);
		MUL_SET_VEC_ROUND_PREFETCH(4);
		MUL_SET_VEC_ROUND_PREFETCH(5);
		MUL_SET_VEC_ROUND_PREFETCH(6);
		MUL_SET_VEC_ROUND_NOPREFETCH(7);
		return ((uint32_t)cy);
	}
	while (len > 1) {
		MUL_SET_VEC_ROUND_PREFETCH(0);
		++r;
		++a;
		--len;
	}
	if (len > 0) {
		MUL_SET_VEC_ROUND_NOPREFETCH(0);
	}
	return ((uint32_t)cy);
}

/*
 * r += a * b
 * where r and a are vectors; b is a single 32-bit digit
 */

uint32_t
big_mul_add_vec(uint32_t *r, uint32_t *a, int len, uint32_t b)
{
	uint64_t d, pf, p, t, cy;

	if (len == 0)
		return (0);
	cy = 0;
	d = (uint64_t)b;
	pf = (uint64_t)a[0];
	while (len > 8) {
		MUL_ADD_VEC_ROUND_PREFETCH(0);
		MUL_ADD_VEC_ROUND_PREFETCH(1);
		MUL_ADD_VEC_ROUND_PREFETCH(2);
		MUL_ADD_VEC_ROUND_PREFETCH(3);
		MUL_ADD_VEC_ROUND_PREFETCH(4);
		MUL_ADD_VEC_ROUND_PREFETCH(5);
		MUL_ADD_VEC_ROUND_PREFETCH(6);
		MUL_ADD_VEC_ROUND_PREFETCH(7);
		r += 8;
		a += 8;
		len -= 8;
	}
	if (len == 8) {
		MUL_ADD_VEC_ROUND_PREFETCH(0);
		MUL_ADD_VEC_ROUND_PREFETCH(1);
		MUL_ADD_VEC_ROUND_PREFETCH(2);
		MUL_ADD_VEC_ROUND_PREFETCH(3);
		MUL_ADD_VEC_ROUND_PREFETCH(4);
		MUL_ADD_VEC_ROUND_PREFETCH(5);
		MUL_ADD_VEC_ROUND_PREFETCH(6);
		MUL_ADD_VEC_ROUND_NOPREFETCH(7);
		return ((uint32_t)cy);
	}
	while (len > 1) {
		MUL_ADD_VEC_ROUND_PREFETCH(0);
		++r;
		++a;
		--len;
	}
	if (len > 0) {
		MUL_ADD_VEC_ROUND_NOPREFETCH(0);
	}
	return ((uint32_t)cy);
}
#endif /* UNROLL8 */

void
big_sqr_vec(uint32_t *r, uint32_t *a, int len)
{
	uint32_t *tr, *ta;
	int tlen, row, col;
	uint64_t p, s, t, t2, cy;
	uint32_t d;

	tr = r + 1;
	ta = a;
	tlen = len - 1;
	tr[tlen] = big_mul_set_vec(tr, ta + 1, tlen, ta[0]);
	while (--tlen > 0) {
		tr += 2;
		++ta;
		tr[tlen] = big_mul_add_vec(tr, ta + 1, tlen, ta[0]);
	}
	s = (uint64_t)a[0];
	s = s * s;
	r[0] = (uint32_t)s;
	cy = s >> 32;
	p = ((uint64_t)r[1] << 1) + cy;
	r[1] = (uint32_t)p;
	cy = p >> 32;
	row = 1;
	col = 2;
	while (row < len) {
		s = (uint64_t)a[row];
		s = s * s;
		p = (uint64_t)r[col] << 1;
		t = p + s;
		d = (uint32_t)t;
		t2 = (uint64_t)d + cy;
		r[col] = (uint32_t)t2;
		cy = (t >> 32) + (t2 >> 32);
		if (row == len - 1)
			break;
		p = ((uint64_t)r[col+1] << 1) + cy;
		r[col+1] = (uint32_t)p;
		cy = p >> 32;
		++row;
		col += 2;
	}
	r[col+1] = (uint32_t)cy;
}

#else /* ! UMUL64 */

/*
 * r = r + a * digit, r and a are vectors of length len
 * returns the carry digit
 */
uint32_t
big_mul_add_vec(uint32_t *r, uint32_t *a, int len, uint32_t digit)
{
	uint32_t cy, cy1, retcy, dlow, dhigh;
	int i;

	cy1 = 0;
	dlow = digit & 0xffff;
	dhigh = digit >> 16;
	for (i = 0; i < len; i++) {
		cy = (cy1 >> 16) + dlow * (a[i] & 0xffff) + (r[i] & 0xffff);
		cy1 = (cy >> 16) + dlow * (a[i]>>16) + (r[i] >> 16);
		r[i] = (cy & 0xffff) | (cy1 << 16);
	}
	retcy = cy1 >> 16;

	cy1 = r[0] & 0xffff;
	for (i = 0; i < len - 1; i++) {
		cy = (cy1 >> 16) + dhigh * (a[i] & 0xffff) + (r[i] >> 16);
		r[i] = (cy1 & 0xffff) | (cy << 16);
		cy1 = (cy >> 16) + dhigh * (a[i] >> 16) + (r[i + 1] & 0xffff);
	}
	cy = (cy1 >> 16) + dhigh * (a[len - 1] & 0xffff) + (r[len - 1] >> 16);
	r[len - 1] = (cy1 & 0xffff) | (cy << 16);
	retcy = (cy >> 16) + dhigh * (a[len - 1] >> 16) + retcy;

	return (retcy);
}

/*
 * r = a * digit, r and a are vectors of length len
 * returns the carry digit
 */
uint32_t
big_mul_set_vec(uint32_t *r, uint32_t *a, int len, uint32_t digit)
{
	return (big_mul_add_vec(r, a, len, digit));
}

void
big_sqr_vec(uint32_t *r, uint32_t *a, int len)
{
	int i;

	r[len] = big_mul_set_vec(r, a, len, a[0]);
	for (i = 1; i < len; ++i)
		r[len + i] = big_mul_add_vec(r+i, a, len, a[i]);
}

#endif /* UMUL64 */

void
big_mul_vec(uint32_t *r, uint32_t *a, int alen, uint32_t *b, int blen)
{
	int i;

	r[alen] = big_mul_set_vec(r, a, alen, b[0]);
	for (i = 1; i < blen; ++i)
		r[alen + i] = big_mul_add_vec(r+i, a, alen, b[i]);
}


#endif /* ! PSR_MUL */


/*
 * result = aa * bb  result->value should be big enough to hold the result
 *
 * Implementation: Standard grammar school algorithm
 *
 */

BIG_ERR_CODE
big_mul(BIGNUM *result, BIGNUM *aa, BIGNUM *bb)
{
	BIGNUM tmp1;
	uint32_t tmp1value[BIGTMPSIZE];
	uint32_t *r, *t, *a, *b;
	BIG_ERR_CODE err;
	int i, alen, blen, rsize, sign, diff;

	if (aa == bb) {
		diff = 0;
	} else {
		diff = big_cmp_abs(aa, bb);
		if (diff < 0) {
			BIGNUM *tt;
			tt = aa;
			aa = bb;
			bb = tt;
		}
	}
	a = aa->value;
	b = bb->value;
	alen = aa->len;
	blen = bb->len;
	while ((alen > 1) && (a[alen - 1] == 0)) alen--;
	aa->len = alen;
	while ((blen > 1) && (b[blen - 1] == 0)) blen--;
	bb->len = blen;

	rsize = alen + blen;
	if (result->size < rsize) {
		err = big_extend(result, rsize);
		if (err != BIG_OK)
			return (err);
		/* aa or bb might be an alias to result */
		a = aa->value;
		b = bb->value;
	}
	r = result->value;

	if (((alen == 1) && (a[0] == 0)) || ((blen == 1) && (b[0] == 0))) {
		result->len = 1;
		result->sign = 1;
		r[0] = 0;
		return (BIG_OK);
	}
	sign = aa->sign * bb->sign;
	if ((alen == 1) && (a[0] == 1)) {
		for (i = 0; i < blen; i++) r[i] = b[i];
		result->len = blen;
		result->sign = sign;
		return (BIG_OK);
	}
	if ((blen == 1) && (b[0] == 1)) {
		for (i = 0; i < alen; i++) r[i] = a[i];
		result->len = alen;
		result->sign = sign;
		return (BIG_OK);
	}

	err = big_init1(&tmp1, rsize, tmp1value, arraysize(tmp1value));
	if (err != BIG_OK)
		return (err);
	t = tmp1.value;
	for (i = 0; i < rsize; i++) t[i] = 0;

	if (diff == 0 && alen > 2)
		BIG_SQR_VEC(t, a, alen);
	else if (blen > 0)
		BIG_MUL_VEC(t, a, alen, b, blen);
	if (t[rsize - 1] == 0)
		--rsize;
	tmp1.len = rsize;
	if ((err = big_copy(result, &tmp1)) != BIG_OK)
		return (err);

	result->sign = sign;

	if (tmp1.malloced) big_finish(&tmp1);

	return (BIG_OK);
}


/*
 * caller must ensure that  a < n,  b < n  and  ret->size >=  2 * n->len + 1
 * and that ret is not n
 */
BIG_ERR_CODE
big_mont_mul(BIGNUM *ret, BIGNUM *a, BIGNUM *b, BIGNUM *n, uint32_t n0)
{
	int i, j, nlen, needsubtract;
	uint32_t *nn, *rr;
	uint32_t digit, c;
	BIG_ERR_CODE err;

	nlen = n->len;
	nn = n->value;

	rr = ret->value;

	if ((err = big_mul(ret, a, b)) != BIG_OK)
		return (err);

	rr = ret->value;
	for (i = ret->len; i < 2 * nlen + 1; i++) rr[i] = 0;
	for (i = 0; i < nlen; i++) {
		digit = rr[i];
		digit = digit * n0;

		c = BIG_MUL_ADD_VEC(rr + i, nn, nlen, digit);
		j = i + nlen;
		rr[j] += c;
		while (rr[j] < c) {
			rr[j + 1] += 1;
			j++;
			c = 1;
		}
	}

	needsubtract = 0;
	if ((rr[2 * nlen]  != 0))
		needsubtract = 1;
	else {
		for (i = 2 * nlen - 1; i >= nlen; i--) {
			if (rr[i] > nn[i - nlen]) {
				needsubtract = 1;
				break;
			} else if (rr[i] < nn[i - nlen]) break;
		}
	}
	if (needsubtract)
		big_sub_vec(rr, rr + nlen, nn, nlen);
	else {
		for (i = 0; i < nlen; i++)
			rr[i] = rr[i + nlen];
	}
	for (i = nlen - 1; (i >= 0) && (rr[i] == 0); i--);
	ret->len = i+1;

	return (BIG_OK);
}

uint32_t
big_n0(uint32_t n)
{
	int i;
	uint32_t result, tmp;

	result = 0;
	tmp = 0xffffffff;
	for (i = 0; i < 32; i++) {
		if ((tmp & 1) == 1) {
			result = (result >> 1) | 0x80000000;
			tmp = tmp - n;
		} else  result = (result>>1);
		tmp = tmp >> 1;
	}

	return (result);
}


int
big_numbits(BIGNUM *n)
{
	int i, j;
	uint32_t t;

	for (i = n->len - 1; i > 0; i--)
		if (n->value[i] != 0) break;
	t = n->value[i];
	for (j = 32; j > 0; j--) {
		if ((t & 0x80000000) == 0)
			t = t << 1;
		else
			return (32 * i + j);
	}
	return (0);
}

/* caller must make sure that a < n */
BIG_ERR_CODE
big_mont_rr(BIGNUM *result, BIGNUM *n)
{
	BIGNUM rr;
	uint32_t rrvalue[BIGTMPSIZE];
	int len, i;
	BIG_ERR_CODE err;

	rr.malloced = 0;
	len = n->len;

	if ((err = big_init1(&rr, 2 * len + 1,
	    rrvalue, arraysize(rrvalue))) != BIG_OK)
		return (err);

	for (i = 0; i < 2 * len; i++) rr.value[i] = 0;
	rr.value[2 * len] = 1;
	rr.len = 2 * len + 1;
	if ((err = big_div_pos(NULL, &rr, &rr, n)) != BIG_OK)
		goto ret;
	err = big_copy(result, &rr);
ret:
	if (rr.malloced) big_finish(&rr);
	return (err);
}

/* caller must make sure that a < n */
BIG_ERR_CODE
big_mont_conv(BIGNUM *result, BIGNUM *a, BIGNUM *n, uint32_t n0, BIGNUM *n_rr)
{
	BIGNUM rr;
	uint32_t rrvalue[BIGTMPSIZE];
	int len, i;
	BIG_ERR_CODE err;

	rr.malloced = 0;
	len = n->len;

	if ((err = big_init1(&rr, 2 * len + 1, rrvalue, arraysize(rrvalue)))
	    != BIG_OK)
			return (err);

	if (n_rr == NULL) {
		for (i = 0; i < 2 * len; i++) rr.value[i] = 0;
		rr.value[2 * len] = 1;
		rr.len = 2 * len + 1;
		if ((err = big_div_pos(NULL, &rr, &rr, n)) != BIG_OK)
			goto ret;
		n_rr = &rr;
	}

	if ((err = big_mont_mul(&rr, n_rr, a, n, n0)) != BIG_OK)
		goto ret;
	err = big_copy(result, &rr);
ret:
	if (rr.malloced) big_finish(&rr);
	return (err);
}


#define	MAX_EXP_BIT_GROUP_SIZE 6
#define	APOWERS_MAX_SIZE (1 << (MAX_EXP_BIT_GROUP_SIZE - 1))

#ifdef USE_FLOATING_POINT

/*
 * This version makes use of floating point for performance.
 */
static BIG_ERR_CODE
_big_modexp(BIGNUM *result, BIGNUM *a, BIGNUM *e, BIGNUM *n, BIGNUM *n_rr)
{
	BIGNUM ma, tmp, rr;
	uint32_t mavalue[BIGTMPSIZE];
	uint32_t tmpvalue[BIGTMPSIZE];
	uint32_t rrvalue[BIGTMPSIZE];
	int i, j, k, l, m, p, bit, bitind, bitcount, nlen;
	BIG_ERR_CODE err;
	uint32_t n0;
	double dn0;
	double *dn, *dt, *d16r, *d32r;
	uint32_t *nint, *prod;
	double *apowers[APOWERS_MAX_SIZE];
	int nbits, groupbits, apowerssize;

	nbits = big_numbits(e);
	if (nbits < 50) {
		groupbits = 1;
		apowerssize = 1;
	} else {
		groupbits = MAX_EXP_BIT_GROUP_SIZE;
		apowerssize = 1 << (groupbits - 1);
	}

	if ((err = big_init1(&ma, n->len, mavalue, arraysize(mavalue)))	!=
	    BIG_OK)
		return (err);
	ma.len = 1;
	ma.value[0] = 0;

	if ((err = big_init1(&tmp, 2 * n->len + 1,
	    tmpvalue, arraysize(tmpvalue))) != BIG_OK)
		goto ret1;
	tmp.len = 1;
	tmp.value[0] = 0;

	rr.malloced = 0;
	if (n_rr == NULL) {
		if ((err = big_init1(&rr, 2 * n->len + 1,
		    rrvalue, arraysize(rrvalue))) != BIG_OK)
			goto ret2;
		if (big_mont_rr(&rr, n) != BIG_OK)
			goto ret2;
		n_rr = &rr;
	}

	n0 = big_n0(n->value[0]);

	if (big_cmp_abs(a, n) > 0) {
		if ((err = big_div_pos(NULL, &ma, a, n)) != BIG_OK)
			goto ret2;
		err = big_mont_conv(&ma, &ma, n, n0, n_rr);
	} else {
		err = big_mont_conv(&ma, a, n, n0, n_rr);
	}
	if (err != BIG_OK)
		goto ret3;

	tmp.len = 1;
	tmp.value[0] = 1;
	if ((err = big_mont_conv(&tmp, &tmp, n, n0, n_rr)) != BIG_OK)
		goto ret3;

	nlen = n->len;
	dn0 = (double)(n0 & 0xffff);

	dn = dt = d16r = d32r = NULL;
	nint = prod = NULL;
	for (i = 0; i < apowerssize; i++) {
		apowers[i] = NULL;
	}

	if ((dn = big_malloc(nlen * sizeof (double))) == NULL) {
		err = BIG_NO_MEM;
		goto ret;
	}
	if ((dt = big_malloc((4 * nlen + 2) * sizeof (double))) == NULL) {
		err = BIG_NO_MEM;
		goto ret;
	}
	if ((nint = big_malloc(nlen * sizeof (uint32_t))) == NULL) {
		err = BIG_NO_MEM;
		goto ret;
	}
	if ((prod = big_malloc((nlen + 1) * sizeof (uint32_t))) == NULL) {
		err = BIG_NO_MEM;
		goto ret;
	}
	if ((d16r = big_malloc((2 * nlen + 1) * sizeof (double))) == NULL) {
		err = BIG_NO_MEM;
		goto ret;
	}
	if ((d32r = big_malloc(nlen * sizeof (double))) == NULL) {
		err = BIG_NO_MEM;
		goto ret;
	}
	for (i = 0; i < apowerssize; i++) {
		if ((apowers[i] = big_malloc((2 * nlen + 1) *
		    sizeof (double))) == NULL) {
			err = BIG_NO_MEM;
			goto ret;
		}
	}

	for (i = 0; i < ma.len; i++) nint[i] = ma.value[i];
	for (; i < nlen; i++) nint[i] = 0;
	conv_i32_to_d32_and_d16(d32r, apowers[0], nint, nlen);

	for (i = 0; i < n->len; i++) nint[i] = n->value[i];
	for (; i < nlen; i++) nint[i] = 0;
	conv_i32_to_d32(dn, nint, nlen);

	mont_mulf_noconv(prod, d32r, apowers[0], dt, dn, nint, nlen, dn0);
	conv_i32_to_d32(d32r, prod, nlen);
	for (i = 1; i < apowerssize; i++) {
		mont_mulf_noconv(prod, d32r, apowers[i - 1],
		    dt, dn, nint, nlen, dn0);
		conv_i32_to_d16(apowers[i], prod, nlen);
	}

	for (i = 0; i < tmp.len; i++) prod[i] = tmp.value[i];
	for (; i < nlen + 1; i++) prod[i] = 0;

	bitind = nbits % 32;
	k = 0;
	l = 0;
	p = 0;
	bitcount = 0;
	for (i = nbits / 32; i >= 0; i--) {
		for (j = bitind - 1; j >= 0; j--) {
			bit = (e->value[i] >> j) & 1;
			if ((bitcount == 0) && (bit == 0)) {
				conv_i32_to_d32_and_d16(d32r, d16r,
				    prod, nlen);
				mont_mulf_noconv(prod, d32r, d16r,
				    dt, dn, nint, nlen, dn0);
			} else {
				bitcount++;
				p = p * 2 + bit;
				if (bit == 1) {
					k = k + l + 1;
					l = 0;
				} else {
					l++;
				}
				if (bitcount == groupbits) {
					for (m = 0; m < k; m++) {
						conv_i32_to_d32_and_d16(
							d32r, d16r,
							prod, nlen);
						mont_mulf_noconv(prod, d32r,
						    d16r, dt, dn, nint,
						    nlen, dn0);
					}
					conv_i32_to_d32(d32r, prod, nlen);
					mont_mulf_noconv(prod, d32r,
					    apowers[p >> (l+1)],
					    dt, dn, nint, nlen, dn0);
					for (m = 0; m < l; m++) {
						conv_i32_to_d32_and_d16(
							d32r, d16r,
							prod, nlen);
						mont_mulf_noconv(prod, d32r,
						    d16r, dt, dn, nint,
						    nlen, dn0);
					}
					k = 0;
					l = 0;
					p = 0;
					bitcount = 0;
				}
			}
		}
		bitind = 32;
	}

	for (m = 0; m < k; m++) {
		conv_i32_to_d32_and_d16(d32r, d16r, prod, nlen);
		mont_mulf_noconv(prod, d32r, d16r, dt, dn, nint, nlen, dn0);
	}
	if (p != 0) {
		conv_i32_to_d32(d32r, prod, nlen);
		mont_mulf_noconv(prod, d32r, apowers[p >> (l + 1)],
		    dt, dn, nint, nlen, dn0);
	}
	for (m = 0; m < l; m++) {
		conv_i32_to_d32_and_d16(d32r, d16r, prod, nlen);
		mont_mulf_noconv(prod, d32r, d16r, dt, dn, nint, nlen, dn0);
	}

	ma.value[0] = 1;
	ma.len = 1;
	for (i = 0; i < nlen; i++) tmp.value[i] = prod[i];
	for (i = nlen - 1; (i > 0) && (prod[i] == 0); i--);
	tmp.len = i + 1;
	if ((err = big_mont_mul(&tmp, &tmp, &ma, n, n0)) != BIG_OK)
		goto ret;
	err = big_copy(result, &tmp);
ret:
	for (i = apowerssize - 1; i >= 0; i--) {
		if (apowers[i] != NULL)
			big_free(apowers[i], (2 * nlen + 1) * sizeof (double));
	}
	if (d32r != NULL)
		big_free(d32r, nlen * sizeof (double));
	if (d16r != NULL)
		big_free(d16r, (2 * nlen + 1) * sizeof (double));
	if (prod != NULL)
		big_free(prod, (nlen + 1) * sizeof (uint32_t));
	if (nint != NULL)
		big_free(nint, nlen * sizeof (uint32_t));
	if (dt != NULL)
		big_free(dt, (4 * nlen + 2) * sizeof (double));
	if (dn != NULL)
		big_free(dn, nlen * sizeof (double));

ret3:
	big_finish(&rr);
ret2:
	big_finish(&tmp);
ret1:
	big_finish(&ma);
	return (err);

}

#ifdef _KERNEL

#include <sys/sysmacros.h>
#include <sys/regset.h>
#include <sys/fpu/fpusystm.h>

/* the alignment for block stores to save fp registers */
#define	FPR_ALIGN	(64)

extern void big_savefp(kfpu_t *);
extern void big_restorefp(kfpu_t *);

#endif /* _KERNEL */

BIG_ERR_CODE
big_modexp(BIGNUM *result, BIGNUM *a, BIGNUM *e, BIGNUM *n, BIGNUM *n_rr)
{
#ifdef _KERNEL
	BIG_ERR_CODE rv;
	uint8_t fpua[sizeof (kfpu_t) + FPR_ALIGN];
	kfpu_t *fpu;

#ifdef DEBUG
	if (!fpu_exists)
		return (BIG_GENERAL_ERR);
#endif

	fpu =  (kfpu_t *)P2ROUNDUP((uintptr_t)fpua, FPR_ALIGN);
	big_savefp(fpu);

	rv = _big_modexp(result, a, e, n, n_rr);

	big_restorefp(fpu);

	return (rv);
#else
	return (_big_modexp(result, a, e, n, n_rr));
#endif	/* _KERNEL */
}

#else /* ! USE_FLOATING_POINT */

/*
 * This version uses strictly integer math and is safe in the kernel
 * for all platforms.
 */

/*
 * computes a^e mod n
 * assumes a < n, n odd, result->value at least as long as n->value
 */
BIG_ERR_CODE
big_modexp(BIGNUM *result, BIGNUM *a, BIGNUM *e, BIGNUM *n, BIGNUM *n_rr)
{
	BIGNUM ma, tmp, rr;
	uint32_t mavalue[BIGTMPSIZE];
	uint32_t tmpvalue[BIGTMPSIZE];
	uint32_t rrvalue[BIGTMPSIZE];
	BIGNUM apowers[APOWERS_MAX_SIZE];
	int i, j, k, l, m, p,
	    bit, bitind, bitcount, groupbits, apowerssize;
	BIG_ERR_CODE err;
	uint32_t n0;

	int nbits;

	nbits = big_numbits(e);
	if (nbits < 50) {
		groupbits = 1;
		apowerssize = 1;
	} else {
		groupbits = MAX_EXP_BIT_GROUP_SIZE;
		apowerssize = 1 << (groupbits - 1);
	}

	if ((err = big_init1(&ma, n->len,
	    mavalue, arraysize(mavalue))) != BIG_OK)
		return (err);
	ma.len = 1;
	ma.value[0] = 0;

	if ((err = big_init1(&tmp, 2 * n->len + 1,
	    tmpvalue, arraysize(tmpvalue))) != BIG_OK)
		goto ret1;
	tmp.len = 1;
	tmp.value[0] = 1;

	n0 = big_n0(n->value[0]);

	rr.malloced = 0;
	if (n_rr == NULL) {
		if ((err = big_init1(&rr, 2 * n->len + 1,
		    rrvalue, arraysize(rrvalue))) != BIG_OK)
			goto ret2;

		if (big_mont_rr(&rr, n) != BIG_OK)
			goto ret3;
		n_rr = &rr;
	}

	for (i = 0; i < apowerssize; i++) apowers[i].malloced = 0;
	for (i = 0; i < apowerssize; i++) {
		if ((err = big_init1(&(apowers[i]), n->len, NULL, 0)) !=
		    BIG_OK)
			goto ret;
	}

	if (big_cmp_abs(a, n) > 0) {
		if ((err = big_div_pos(NULL, &ma, a, n)) != BIG_OK)
			goto ret;
		err = big_mont_conv(&ma, &ma, n, n0, n_rr);
	} else {
		err = big_mont_conv(&ma, a, n, n0, n_rr);
	}
	if (err != BIG_OK) goto ret;

	(void) big_copy(&(apowers[0]), &ma);
	if ((err = big_mont_mul(&tmp, &ma, &ma, n, n0)) != BIG_OK)
		goto ret;
	(void) big_copy(&ma, &tmp);

	for (i = 1; i < apowerssize; i++) {
		if ((err = big_mont_mul(&tmp, &ma,
		    &(apowers[i-1]), n, n0)) != BIG_OK)
			goto ret;
		(void) big_copy(&apowers[i], &tmp);
	}

	tmp.len = 1;
	tmp.value[0] = 1;
	if ((err = big_mont_conv(&tmp, &tmp, n, n0, n_rr)) != BIG_OK)
		goto ret;

	bitind = nbits % 32;
	k = 0;
	l = 0;
	p = 0;
	bitcount = 0;
	for (i = nbits / 32; i >= 0; i--) {
		for (j = bitind - 1; j >= 0; j--) {
			bit = (e->value[i] >> j) & 1;
			if ((bitcount == 0) && (bit == 0)) {
				if ((err = big_mont_mul(&tmp,
				    &tmp, &tmp, n, n0)) != BIG_OK)
					goto ret;
			} else {
				bitcount++;
				p = p * 2 + bit;
				if (bit == 1) {
					k = k + l + 1;
					l = 0;
				} else {
					l++;
				}
				if (bitcount == groupbits) {
					for (m = 0; m < k; m++) {
						if ((err = big_mont_mul(&tmp,
						    &tmp, &tmp, n, n0)) !=
						    BIG_OK)
							goto ret;
					}
					if ((err = big_mont_mul(&tmp, &tmp,
					    &(apowers[p >> (l + 1)]),
					    n, n0)) != BIG_OK)
						goto ret;
					for (m = 0; m < l; m++) {
						if ((err = big_mont_mul(&tmp,
						    &tmp, &tmp, n, n0)) !=
						    BIG_OK)
							goto ret;
					}
					k = 0;
					l = 0;
					p = 0;
					bitcount = 0;
				}
			}
		}
		bitind = 32;
	}

	for (m = 0; m < k; m++) {
		if ((err = big_mont_mul(&tmp, &tmp, &tmp, n, n0)) != BIG_OK)
			goto ret;
	}
	if (p != 0) {
		if ((err = big_mont_mul(&tmp, &tmp,
		    &(apowers[p >> (l + 1)]), n, n0)) != BIG_OK)
			goto ret;
	}
	for (m = 0; m < l; m++) {
		if ((err = big_mont_mul(&tmp, &tmp, &tmp, n, n0)) != BIG_OK)
			goto ret;
	}

	ma.value[0] = 1;
	ma.len = 1;
	if ((err = big_mont_mul(&tmp, &tmp, &ma, n, n0)) != BIG_OK)
		goto ret;
	err = big_copy(result, &tmp);
ret:
	for (i = apowerssize - 1; i >= 0; i--) {
		big_finish(&(apowers[i]));
	}
ret3:
	if (rr.malloced) big_finish(&rr);
ret2:
	if (tmp.malloced) big_finish(&tmp);
ret1:
	if (ma.malloced) big_finish(&ma);
	return (err);
}

#endif /* USE_FLOATING_POINT */


BIG_ERR_CODE
big_modexp_crt(BIGNUM *result, BIGNUM *a, BIGNUM *dmodpminus1,
    BIGNUM *dmodqminus1, BIGNUM *p, BIGNUM *q, BIGNUM *pinvmodq,
    BIGNUM *p_rr, BIGNUM *q_rr)
{
	BIGNUM ap, aq, tmp;
	int alen, biglen, sign;
	BIG_ERR_CODE err;

	if (p->len > q->len) biglen = p->len;
	else biglen = q->len;

	if ((err = big_init1(&ap, p->len, NULL, 0)) != BIG_OK)
		return (err);
	if ((err = big_init1(&aq, q->len, NULL, 0)) != BIG_OK)
		goto ret1;
	if ((err = big_init1(&tmp, biglen + q->len + 1, NULL, 0)) != BIG_OK)
		goto ret2;

	/*
	 * check whether a is too short - to avoid timing attacks
	 */
	alen = a->len;
	while ((alen > p->len) && (a->value[alen - 1] == 0)) {
		alen--;
	}
	if (alen < p->len + q->len) {
		/*
		 * a is too short, add p*q to it before
		 * taking it modulo p and q
		 * this will also affect timing, but this difference
		 * does not depend on p or q, only on a
		 * (in "normal" operation, this path will never be
		 * taken, so it is not a performance penalty
		 */
		if ((err = big_mul(&tmp, p, q)) != BIG_OK)
			goto ret;
		if ((err = big_add(&tmp, &tmp, a)) != BIG_OK)
			goto ret;
		if ((err = big_div_pos(NULL, &ap, &tmp, p)) != BIG_OK)
			goto ret;
		if ((err = big_div_pos(NULL, &aq, &tmp, q)) != BIG_OK)
			goto ret;
	} else {
		if ((err = big_div_pos(NULL, &ap, a, p)) != BIG_OK)
			goto ret;
		if ((err = big_div_pos(NULL, &aq, a, q)) != BIG_OK)
			goto ret;
	}

	if ((err = big_modexp(&ap, &ap, dmodpminus1, p, p_rr)) != BIG_OK)
		goto ret;
	if ((err = big_modexp(&aq, &aq, dmodqminus1, q, q_rr)) != BIG_OK)
		goto ret;
	if ((err = big_sub(&tmp, &aq, &ap)) != BIG_OK)
		goto ret;
	if ((err = big_mul(&tmp, &tmp, pinvmodq)) != BIG_OK)
		goto ret;
	sign = tmp.sign;
	tmp.sign = 1;
	if ((err = big_div_pos(NULL, &aq, &tmp, q)) != BIG_OK)
		goto ret;
	if ((sign == -1) && (!big_is_zero(&aq))) {
		(void) big_sub_pos(&aq, q, &aq);
	}
	if ((err = big_mul(&tmp, &aq, p)) != BIG_OK)
		goto ret;
	err = big_add_abs(result, &ap, &tmp);

ret:
	big_finish(&tmp);
ret2:
	big_finish(&aq);
ret1:
	big_finish(&ap);

	return (err);
}


uint32_t onearr[1] = {1};
BIGNUM One = {1, 1, 1, 0, onearr};

uint32_t twoarr[1] = {2};
BIGNUM Two = {1, 1, 1, 0, twoarr};

uint32_t fourarr[1] = {4};
BIGNUM Four = {1, 1, 1, 0, fourarr};

BIG_ERR_CODE
big_sqrt_pos(BIGNUM *result, BIGNUM *n)
{
	BIGNUM *high, *low, *mid, *t;
	BIGNUM t1, t2, t3, prod;
	uint32_t t1value[BIGTMPSIZE];
	uint32_t t2value[BIGTMPSIZE];
	uint32_t t3value[BIGTMPSIZE];
	uint32_t prodvalue[BIGTMPSIZE];
	int i, nbits, diff, nrootbits, highbits;
	BIG_ERR_CODE err;

	nbits = big_numbits(n);

	if ((err = big_init1(&t1, n->len + 1,
	    t1value, arraysize(t1value))) != BIG_OK)
		return (err);
	if ((err = big_init1(&t2, n->len + 1,
	    t2value, arraysize(t2value))) != BIG_OK)
		goto ret1;
	if ((err = big_init1(&t3, n->len + 1,
	    t3value, arraysize(t3value))) != BIG_OK)
		goto ret2;
	if ((err = big_init1(&prod, n->len + 1,
	    prodvalue, arraysize(prodvalue))) != BIG_OK)
		goto ret3;

	nrootbits = (nbits + 1) / 2;
	t1.len = t2.len = t3.len = (nrootbits - 1) / 32 + 1;
	for (i = 0; i < t1.len; i++) {
		t1.value[i] = 0;
		t2.value[i] = 0xffffffff;
	}
	highbits = nrootbits - 32 * (t1.len - 1);
	if (highbits == 32) {
		t1.value[t1.len - 1] = 0x80000000;
		t2.value[t2.len - 1] = 0xffffffff;
	} else {
		t1.value[t1.len - 1] = 1 << (highbits - 1);
		t2.value[t2.len - 1] = 2 * t1.value[t1.len - 1] - 1;
	}
	high = &t2;
	low = &t1;
	mid = &t3;

	if ((err = big_mul(&prod, high, high)) != BIG_OK)
		goto ret;
	diff = big_cmp_abs(&prod, n);
	if (diff <= 0) {
		err = big_copy(result, high);
		goto ret;
	}

	(void) big_sub_pos(mid, high, low);
	while (big_cmp_abs(&One, mid) != 0) {
		(void) big_add_abs(mid, high, low);
		(void) big_half_pos(mid, mid);
		if ((err = big_mul(&prod, mid, mid)) != BIG_OK)
			goto ret;
		diff = big_cmp_abs(&prod, n);
		if (diff > 0) {
			t = high;
			high = mid;
			mid = t;
		} else if (diff < 0) {
			t = low;
			low = mid;
			mid = t;
		} else {
			err = big_copy(result, low);
			goto ret;
		}
		(void) big_sub_pos(mid, high, low);
	}

	err = big_copy(result, low);
ret:
	if (prod.malloced) big_finish(&prod);
ret3:
	if (t3.malloced) big_finish(&t3);
ret2:
	if (t2.malloced) big_finish(&t2);
ret1:
	if (t1.malloced) big_finish(&t1);

	return (err);
}


BIG_ERR_CODE
big_Jacobi_pos(int *jac, BIGNUM *nn, BIGNUM *mm)
{
	BIGNUM *t, *tmp2, *m, *n;
	BIGNUM t1, t2, t3;
	uint32_t t1value[BIGTMPSIZE];
	uint32_t t2value[BIGTMPSIZE];
	uint32_t t3value[BIGTMPSIZE];
	int len, err;

	if (big_is_zero(nn) ||
	    (((nn->value[0] & 1) | (mm->value[0] & 1)) == 0)) {
		*jac = 0;
		return (BIG_OK);
	}

	if (nn->len > mm->len) len = nn->len;
	else len = mm->len;

	if ((err = big_init1(&t1, len,
	    t1value, arraysize(t1value))) != BIG_OK)
		return (err);
	if ((err = big_init1(&t2, len,
	    t2value, arraysize(t2value))) != BIG_OK)
		goto ret1;
	if ((err = big_init1(&t3, len,
	    t3value, arraysize(t3value))) != BIG_OK)
		goto ret2;

	n = &t1;
	m = &t2;
	tmp2 = &t3;

	(void) big_copy(n, nn);
	(void) big_copy(m, mm);

	*jac = 1;
	while (big_cmp_abs(&One, m) != 0) {
		if (big_is_zero(n)) {
			*jac = 0;
			goto ret;
		}
		if ((m->value[0] & 1) == 0) {
			if (((n->value[0] & 7) == 3) ||
			    ((n->value[0] & 7) == 5)) *jac = -*jac;
			(void) big_half_pos(m, m);
		} else if ((n->value[0] & 1) == 0) {
			if (((m->value[0] & 7) == 3) ||
			    ((m->value[0] & 7) == 5)) *jac = -*jac;
			(void) big_half_pos(n, n);
		} else {
			if (((m->value[0] & 3) == 3) &&
			    ((n->value[0] & 3) == 3)) {
				*jac = -*jac;
			}
			if ((err = big_div_pos(NULL, tmp2, m, n)) != BIG_OK)
				goto ret;
			t = tmp2;
			tmp2 = m;
			m = n;
			n = t;
		}
	}
	err = BIG_OK;

ret:
	if (t3.malloced) big_finish(&t3);
ret2:
	if (t2.malloced) big_finish(&t2);
ret1:
	if (t1.malloced) big_finish(&t1);

	return (err);
}


BIG_ERR_CODE
big_Lucas(BIGNUM *Lkminus1, BIGNUM *Lk, BIGNUM *p, BIGNUM *k, BIGNUM *n)
{
	int m, w, i;
	uint32_t bit;
	BIGNUM ki, tmp, tmp2;
	uint32_t kivalue[BIGTMPSIZE];
	uint32_t tmpvalue[BIGTMPSIZE];
	uint32_t tmp2value[BIGTMPSIZE];
	BIG_ERR_CODE err;

	if (big_cmp_abs(k, &One) == 0) {
		(void) big_copy(Lk, p);
		(void) big_copy(Lkminus1, &Two);
		return (BIG_OK);
	}

	if ((err = big_init1(&ki, k->len + 1,
	    kivalue, arraysize(kivalue))) != BIG_OK)
		return (err);

	if ((err = big_init1(&tmp, 2 * n->len +1,
	    tmpvalue, arraysize(tmpvalue))) != BIG_OK)
		goto ret1;

	if ((err = big_init1(&tmp2, n->len,
	    tmp2value, arraysize(tmp2value))) != BIG_OK)
		goto ret2;

	m = big_numbits(k);
	ki.len = (m - 1) / 32 + 1;
	w = (m - 1) / 32;
	bit = 1 << ((m - 1) % 32);
	for (i = 0; i < ki.len; i++) ki.value[i] = 0;
	ki.value[ki.len - 1] = bit;
	if (big_cmp_abs(k, &ki) != 0)
		(void) big_double(&ki, &ki);
	(void) big_sub_pos(&ki, &ki, k);

	(void) big_copy(Lk, p);
	(void) big_copy(Lkminus1, &Two);

	for (i = 0; i < m; i++) {
		if ((err = big_mul(&tmp, Lk, Lkminus1)) != BIG_OK)
			goto ret;
		(void) big_add_abs(&tmp, &tmp, n);
		(void) big_sub_pos(&tmp, &tmp, p);
		if ((err = big_div_pos(NULL, &tmp2, &tmp, n)) != BIG_OK)
			goto ret;

		if ((ki.value[w] & bit) != 0) {
			if ((err = big_mul(&tmp, Lkminus1, Lkminus1)) !=
			    BIG_OK)
				goto ret;
			(void) big_add_abs(&tmp, &tmp, n);
			(void) big_sub_pos(&tmp, &tmp, &Two);
			if ((err = big_div_pos(NULL, Lkminus1, &tmp, n)) !=
			    BIG_OK)
				goto ret;
			(void) big_copy(Lk, &tmp2);
		} else {
			if ((err = big_mul(&tmp, Lk, Lk)) != BIG_OK)
				goto ret;
			(void) big_add_abs(&tmp, &tmp, n);
			(void) big_sub_pos(&tmp, &tmp, &Two);
			if ((err = big_div_pos(NULL, Lk, &tmp, n)) != BIG_OK)
				goto ret;
			(void) big_copy(Lkminus1, &tmp2);
		}
		bit = bit >> 1;
		if (bit == 0) {
			bit = 0x80000000;
			w--;
		}
	}

	err = BIG_OK;

ret:
	if (tmp2.malloced) big_finish(&tmp2);
ret2:
	if (tmp.malloced) big_finish(&tmp);
ret1:
	if (ki.malloced) big_finish(&ki);

	return (err);
}


BIG_ERR_CODE
big_isprime_pos(BIGNUM *n)
{
	BIGNUM o, nminus1, tmp, Lkminus1, Lk;
	uint32_t ovalue[BIGTMPSIZE];
	uint32_t nminus1value[BIGTMPSIZE];
	uint32_t tmpvalue[BIGTMPSIZE];
	uint32_t Lkminus1value[BIGTMPSIZE];
	uint32_t Lkvalue[BIGTMPSIZE];
	BIG_ERR_CODE err;
	int e, i, jac;

	if (big_cmp_abs(n, &One) == 0)
		return (BIG_FALSE);
	if (big_cmp_abs(n, &Two) == 0)
		return (BIG_TRUE);
	if ((n->value[0] & 1) == 0)
		return (BIG_FALSE);

	if ((err = big_init1(&o, n->len, ovalue, arraysize(ovalue))) != BIG_OK)
		return (err);

	if ((err = big_init1(&nminus1, n->len,
	    nminus1value, arraysize(nminus1value))) != BIG_OK)
		goto ret1;

	if ((err = big_init1(&tmp, 2 * n->len,
	    tmpvalue, arraysize(tmpvalue))) != BIG_OK)
		goto ret2;

	if ((err = big_init1(&Lkminus1, n->len,
	    Lkminus1value, arraysize(Lkminus1value))) != BIG_OK)
		goto ret3;

	if ((err = big_init1(&Lk, n->len,
	    Lkvalue, arraysize(Lkvalue))) != BIG_OK)
		goto ret4;

	(void) big_sub_pos(&o, n, &One); 	/* cannot fail */
	(void) big_copy(&nminus1, &o);		/* cannot fail */
	e = 0;
	while ((o.value[0] & 1) == 0) {
		e++;
		(void) big_half_pos(&o, &o);  /* cannot fail */
	}
	if ((err = big_modexp(&tmp, &Two, &o, n, NULL)) != BIG_OK)
		goto ret;
	i = 0;
	while ((i < e) &&
	    (big_cmp_abs(&tmp, &One) != 0) &&
	    (big_cmp_abs(&tmp, &nminus1) != 0)) {
		if ((err = big_modexp(&tmp, &tmp, &Two, n, NULL)) !=  BIG_OK)
			goto ret;
		i++;
	}
	if (!((big_cmp_abs(&tmp, &nminus1) == 0) ||
	    ((i == 0) && (big_cmp_abs(&tmp, &One) == 0)))) {
		err = BIG_FALSE;
		goto ret;
	}

	if ((err = big_sqrt_pos(&tmp, n)) != BIG_OK)
		goto ret;
	if ((err = big_mul(&tmp, &tmp, &tmp)) != BIG_OK)
		goto ret;
	if (big_cmp_abs(&tmp, n) == 0) {
		err = BIG_FALSE;
		goto ret;
	}

	(void) big_copy(&o, &Two);
	do {
		(void) big_add_abs(&o, &o, &One);
		if ((err = big_mul(&tmp, &o, &o)) != BIG_OK)
			goto ret;
		(void) big_sub_pos(&tmp, &tmp, &Four);
		if ((err = big_Jacobi_pos(&jac, &tmp, n)) != BIG_OK)
			goto ret;
	} while (jac != -1);

	(void) big_add_abs(&tmp, n, &One);
	if ((err = big_Lucas(&Lkminus1, &Lk, &o, &tmp, n)) != BIG_OK)
		goto ret;
	if ((big_cmp_abs(&Lkminus1, &o) == 0) && (big_cmp_abs(&Lk, &Two) == 0))
		err = BIG_TRUE;
	else err = BIG_FALSE;

ret:
	if (Lk.malloced) big_finish(&Lk);
ret4:
	if (Lkminus1.malloced) big_finish(&Lkminus1);
ret3:
	if (tmp.malloced) big_finish(&tmp);
ret2:
	if (nminus1.malloced) big_finish(&nminus1);
ret1:
	if (o.malloced) big_finish(&o);

	return (err);
}


#define	SIEVESIZE 1000

uint32_t smallprimes[] =
{
3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47,
51, 53, 59, 61, 67, 71, 73, 79, 83, 89, 91, 97
};


BIG_ERR_CODE
big_nextprime_pos(BIGNUM *result, BIGNUM *n)
{
	BIG_ERR_CODE err;
	int sieve[SIEVESIZE];
	int i;
	uint32_t off, p;

	if ((err = big_copy(result, n)) != BIG_OK)
		return (err);
	result->value[0] |= 1;
	/* CONSTCOND */
	while (1) {
		for (i = 0; i < SIEVESIZE; i++) sieve[i] = 0;
		for (i = 0;
		    i < sizeof (smallprimes) / sizeof (uint32_t); i++) {
			p = smallprimes[i];
			off = big_mod16_pos(result, p);
			off = p - off;
			if ((off % 2) == 1) off = off + p;
			off = off/2;
			while (off < SIEVESIZE) {
				sieve[off] = 1;
				off = off + p;
			}
		}

		for (i = 0; i < SIEVESIZE; i++) {
			if (sieve[i] == 0) {
				err = big_isprime_pos(result);
				if (err != BIG_FALSE) {
					if (err != BIG_TRUE)
						return (err);
					else
						return (BIG_OK);
				}

			}
			if ((err = big_add_abs(result, result, &Two)) !=
			    BIG_OK)
				return (err);
		}
	}
	/* NOTREACHED */
}


BIG_ERR_CODE
big_nextprime_pos_slow(BIGNUM *result, BIGNUM *n)
{
	BIG_ERR_CODE err;


	if ((err = big_copy(result, n)) != BIG_OK)
		return (err);
	result->value[0] |= 1;
	while ((err = big_isprime_pos(result)) != BIG_TRUE) {
		if (err != BIG_FALSE)
			return (err);
		if ((err = big_add_abs(result, result, &Two)) != BIG_OK)
			return (err);
	}
	return (BIG_OK);
}


/*
 * given m and e, computes the rest in the equation
 * gcd(m, e) = cm * m + ce * e
 */
BIG_ERR_CODE
big_ext_gcd_pos(BIGNUM *gcd, BIGNUM *cm, BIGNUM *ce, BIGNUM *m, BIGNUM *e)
{
	BIGNUM *xi, *ri, *riminus1, *riminus2, *t,
	    *vmi, *vei, *vmiminus1, *veiminus1;
	BIGNUM t1, t2, t3, t4, t5, t6, t7, t8, tmp;
	uint32_t t1value[BIGTMPSIZE];
	uint32_t t2value[BIGTMPSIZE];
	uint32_t t3value[BIGTMPSIZE];
	uint32_t t4value[BIGTMPSIZE];
	uint32_t t5value[BIGTMPSIZE];
	uint32_t t6value[BIGTMPSIZE];
	uint32_t t7value[BIGTMPSIZE];
	uint32_t t8value[BIGTMPSIZE];
	uint32_t tmpvalue[BIGTMPSIZE];
	BIG_ERR_CODE err;
	int len;

	if (big_cmp_abs(m, e) >= 0) len = m->len;
	else len = e->len;

	if ((err = big_init1(&t1, len,
	    t1value, arraysize(t1value))) != BIG_OK)
		return (err);
	if ((err = big_init1(&t2, len,
	    t2value, arraysize(t2value))) != BIG_OK)
			goto ret1;
	if ((err = big_init1(&t3, len,
	    t3value, arraysize(t3value))) != BIG_OK)
			goto ret2;
	if ((err = big_init1(&t4, len,
	    t4value, arraysize(t3value))) != BIG_OK)
			goto ret3;
	if ((err = big_init1(&t5, len,
	    t5value, arraysize(t5value))) != BIG_OK)
			goto ret4;
	if ((err = big_init1(&t6, len,
	    t6value, arraysize(t6value))) != BIG_OK)
			goto ret5;
	if ((err = big_init1(&t7, len,
	    t7value, arraysize(t7value))) != BIG_OK)
			goto ret6;
	if ((err = big_init1(&t8, len,
	    t8value, arraysize(t8value))) != BIG_OK)
			goto ret7;

	if ((err = big_init1(&tmp, 2 * len,
	    tmpvalue, arraysize(tmpvalue))) != BIG_OK)
		goto ret8;

	ri = &t1;
	ri->value[0] = 1;
	ri->len = 1;
	xi = &t2;
	riminus1 = &t3;
	riminus2 = &t4;
	vmi = &t5;
	vei = &t6;
	vmiminus1 = &t7;
	veiminus1 = &t8;

	(void) big_copy(vmiminus1, &One);
	(void) big_copy(vmi, &One);
	(void) big_copy(veiminus1, &One);
	(void) big_copy(xi, &One);
	vei->len = 1;
	vei->value[0] = 0;

	(void) big_copy(riminus1, m);
	(void) big_copy(ri, e);

	while (!big_is_zero(ri)) {
		t = riminus2;
		riminus2 = riminus1;
		riminus1 = ri;
		ri = t;
		if ((err = big_mul(&tmp, vmi, xi)) != BIG_OK)
			goto ret;
		if ((err = big_sub(vmiminus1, vmiminus1, &tmp)) != BIG_OK)
			goto ret;
		t = vmiminus1;
		vmiminus1 = vmi;
		vmi = t;
		if ((err = big_mul(&tmp, vei, xi)) != BIG_OK)
			goto ret;
		if ((err = big_sub(veiminus1, veiminus1, &tmp)) != BIG_OK)
			goto ret;
		t = veiminus1;
		veiminus1 = vei;
		vei = t;
		if ((err = big_div_pos(xi, ri, riminus2, riminus1)) != BIG_OK)
			goto ret;
	}
	if ((gcd != NULL) && ((err = big_copy(gcd, riminus1)) != BIG_OK))
		goto ret;
	if ((cm != NULL) && ((err = big_copy(cm, vmi)) != BIG_OK))
		goto ret;
	if (ce != NULL)
		err = big_copy(ce, vei);
ret:
	if (tmp.malloced) big_finish(&tmp);
ret8:
	if (t8.malloced) big_finish(&t8);
ret7:
	if (t7.malloced) big_finish(&t7);
ret6:
	if (t6.malloced) big_finish(&t6);
ret5:
	if (t5.malloced) big_finish(&t5);
ret4:
	if (t4.malloced) big_finish(&t4);
ret3:
	if (t3.malloced) big_finish(&t3);
ret2:
	if (t2.malloced) big_finish(&t2);
ret1:
	if (t1.malloced) big_finish(&t1);

	return (err);
}
