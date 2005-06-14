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

#ifndef _BIGNUM_H
#define	_BIGNUM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>

typedef int BIG_ERR_CODE;


/*
 * leading 0's are permitted
 * 0 should be represented by size>=1, size>=len>=1, sign=1,
 * value[i]=0 for 0<i<len
 */
typedef struct {
	int size; /* the size of memory allocated for value (in words) */
	int len;  /* the number of words that hold valid data in value */
	int sign; /* 1 for nonnegative, -1 for negative   */
	int malloced; /* 1 if value was malloced 0 if not */
	uint32_t *value;
} BIGNUM;

#define	BIGTMPSIZE 65

#define	BIG_TRUE 1
#define	BIG_FALSE 0

/* error codes */
#define	BIG_OK 0
#define	BIG_NO_MEM -1
#define	BIG_INVALID_ARGS -2
#define	BIG_DIV_BY_0 -3
#define	BIG_NO_RANDOM -4
#define	BIG_GENERAL_ERR	-5

#define	arraysize(x) (sizeof (x) / sizeof (x[0]))

#ifdef USE_FLOATING_POINT
void conv_d16_to_i32(uint32_t *i32, double *d16, int64_t *tmp, int ilen);
void conv_i32_to_d32(double *d32, uint32_t *i32, int len);
void conv_i32_to_d16(double *d16, uint32_t *i32, int len);
void conv_i32_to_d32_and_d16(double *d32, double *d16,
    uint32_t *i32, int len);
void mont_mulf_noconv(uint32_t *result, double *dm1, double *dm2, double *dt,
    double *dn, uint32_t *nint, int nlen, double dn0);
#endif /* USE_FLOATING_POINT */

void printbignum(char *aname, BIGNUM *a);

BIG_ERR_CODE big_init(BIGNUM *number, int size);
BIG_ERR_CODE big_extend(BIGNUM *number, int size);
void big_finish(BIGNUM *number);
void bytestring2bignum(BIGNUM *bn, uchar_t *kn, size_t len);
void bignum2bytestring(uchar_t *kn, BIGNUM *bn, size_t len);
BIG_ERR_CODE big_mont_rr(BIGNUM *result, BIGNUM *n);
BIG_ERR_CODE big_modexp(BIGNUM *result, BIGNUM *a, BIGNUM *e,
    BIGNUM *n, BIGNUM *n_rr);
BIG_ERR_CODE big_modexp_crt(BIGNUM *result, BIGNUM *a, BIGNUM *dmodpminus1,
    BIGNUM *dmodqminus1, BIGNUM *p, BIGNUM *q, BIGNUM *pinvmodq,
    BIGNUM *p_rr, BIGNUM *q_rr);
int big_cmp_abs(BIGNUM *a, BIGNUM *b);
BIG_ERR_CODE randombignum(BIGNUM *r, int length);
BIG_ERR_CODE big_div_pos(BIGNUM *result, BIGNUM *remainder,
    BIGNUM *aa, BIGNUM *bb);
BIG_ERR_CODE big_ext_gcd_pos(BIGNUM *gcd, BIGNUM *cm, BIGNUM *ce,
    BIGNUM *m, BIGNUM *e);
BIG_ERR_CODE big_add(BIGNUM *result, BIGNUM *aa, BIGNUM *bb);
BIG_ERR_CODE big_mul(BIGNUM *result, BIGNUM *aa, BIGNUM *bb);
BIG_ERR_CODE big_nextprime_pos(BIGNUM *result, BIGNUM *n);
BIG_ERR_CODE big_sub_pos(BIGNUM *result, BIGNUM *aa, BIGNUM *bb);
BIG_ERR_CODE big_copy(BIGNUM *dest, BIGNUM *src);
BIG_ERR_CODE big_sub(BIGNUM *result, BIGNUM *aa, BIGNUM *bb);
int big_bitlength(BIGNUM *n);
BIG_ERR_CODE big_init1(BIGNUM *number, int size, uint32_t *buf, int bufsize);

#if defined(HWCAP)

#define	BIG_MUL_SET_VEC(r, a, len, digit) \
	(*big_mul_set_vec_impl)(r, a, len, digit)
#define	BIG_MUL_ADD_VEC(r, a, len, digit) \
	(*big_mul_add_vec_impl)(r, a, len, digit)
#define	BIG_MUL_VEC(r, a, alen, b, blen) \
	(*big_mul_vec_impl)(r, a, alen, b, blen)
#define	BIG_SQR_VEC(r, a, len) \
	(*big_sqr_vec_impl)(r, a, len)

extern uint32_t (*big_mul_set_vec_impl)
	(uint32_t *r, uint32_t *a, int len, uint32_t digit);
extern uint32_t (*big_mul_add_vec_impl)
	(uint32_t *r, uint32_t *a, int len, uint32_t digit);
extern void (*big_mul_vec_impl)
	(uint32_t *r, uint32_t *a, int alen, uint32_t *b, int blen);
extern void (*big_sqr_vec_impl)
	(uint32_t *r, uint32_t *a, int len);

#else /* ! HWCAP */

#define	BIG_MUL_SET_VEC(r, a, len, digit) big_mul_set_vec(r, a, len, digit)
#define	BIG_MUL_ADD_VEC(r, a, len, digit) big_mul_add_vec(r, a, len, digit)
#define	BIG_MUL_VEC(r, a, alen, b, blen) big_mul_vec(r, a, alen, b, blen)
#define	BIG_SQR_VEC(r, a, len) big_sqr_vec(r, a, len)

extern uint32_t big_mul_set_vec(uint32_t *r, uint32_t *a, int len, uint32_t d);
extern uint32_t big_mul_add_vec(uint32_t *r, uint32_t *a, int len, uint32_t d);
extern void big_mul_vec(uint32_t *r, uint32_t *a, int alen,
    uint32_t *b, int blen);
extern void big_sqr_vec(uint32_t *r, uint32_t *a, int len);

#endif /* HWCAP */

#ifdef	__cplusplus
}
#endif

#endif	/* _BIGNUM_H */
