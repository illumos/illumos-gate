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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */
/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_M9X_FEX_HANDLER_H
#define	_M9X_FEX_HANDLER_H

/* the following enums must match the bit positions in fenv.h */
enum fex_exception {
	fex_inexact		= 0,
	fex_division	= 1,
	fex_underflow	= 2,
	fex_overflow	= 3,
	fex_inv_zdz		= 4,
	fex_inv_idi		= 5,
	fex_inv_isi		= 6,
	fex_inv_zmi		= 7,
	fex_inv_sqrt	= 8,
	fex_inv_snan	= 9,
	fex_inv_int		= 10,
	fex_inv_cmp		= 11
};


/* auxiliary functions in __fex_hdlr.c */
extern struct fex_handler_data *__fex_get_thr_handlers(void);
extern void __fex_update_te(void);

/* auxiliary functions in __fex_sym.c */
extern void __fex_sym_init(void);
extern char *__fex_sym(char *, char **);

/* auxiliary functions in fex_log.c */
extern void __fex_mklog(ucontext_t *, char *, int, enum fex_exception,
	int, void *);

/* system-dependent auxiliary functions */
extern enum fex_exception __fex_get_invalid_type(siginfo_t *, ucontext_t *);
extern void __fex_get_op(siginfo_t *, ucontext_t *, fex_info_t *);
extern void __fex_st_result(siginfo_t *, ucontext_t *, fex_info_t *);

/* inline templates and macros for accessing fp state */
extern void __fenv_getfsr(unsigned long *);
extern void __fenv_setfsr(const unsigned long *);

#if defined(__sparc)

#define __fenv_get_rd(X)	((X>>30)&0x3)
#define __fenv_set_rd(X,Y)	X=(X&~0xc0000000ul)|((Y)<<30)

#define __fenv_get_te(X)	((X>>23)&0x1f)
#define __fenv_set_te(X,Y)	X=(X&~0x0f800000ul)|((Y)<<23)

#define __fenv_get_ex(X)	((X>>5)&0x1f)
#define __fenv_set_ex(X,Y)	X=(X&~0x000003e0ul)|((Y)<<5)

#elif defined(__x86)

extern void __fenv_getcwsw(unsigned int *);
extern void __fenv_setcwsw(const unsigned int *);

extern void __fenv_getmxcsr(unsigned int *);
extern void __fenv_setmxcsr(const unsigned int *);

#define __fenv_get_rd(X)	((X>>26)&3)
#define __fenv_set_rd(X,Y)	X=(X&~0x0c000000)|((Y)<<26)

#define __fenv_get_rp(X)	((X>>24)&3)
#define __fenv_set_rp(X,Y)	X=(X&~0x03000000)|((Y)<<24)

#define __fenv_get_te(X)	((X>>16)&0x3d)
#define __fenv_set_te(X,Y)	X=(X&~0x003d0000)|((Y)<<16)

#define __fenv_get_ex(X)	(X&0x3d)
#define __fenv_set_ex(X,Y)	X=(X&~0x0000003d)|(Y)

/* 
 * These macros define some useful distinctions between various
 * SSE instructions.  In some cases, distinctions are made for
 * the purpose of simplifying the decoding of instructions, while
 * in other cases, they are made for the purpose of simplying the
 * emulation.  Note that these values serve as bit flags within
 * the enum values in sseinst_t.
 */
#define DOUBLE		0x100
#define SIMD		0x080
#define INTREG		0x040

typedef union {
	double		d[2];
	long long	l[2];
	float		f[4];
	int		i[4];
} sseoperand_t;

/* structure to hold a decoded SSE instruction */
typedef struct {
	enum {
		/* single precision scalar instructions */
		cmpss		= 0,
		minss		= 1,
		maxss		= 2,
		addss		= 3,
		subss		= 4,
		mulss		= 5,
		divss		= 6,
		sqrtss		= 7,
		ucomiss		= 16,
		comiss		= 17,
		cvtss2sd	= 32,
		cvtsi2ss	= INTREG + 0,
		cvttss2si	= INTREG + 1,
		cvtss2si	= INTREG + 2,
		cvtsi2ssq	= INTREG + 8,
		cvttss2siq	= INTREG + 9,
		cvtss2siq	= INTREG + 10,

		/* single precision SIMD instructions */
		cmpps		= SIMD + 0,
		minps		= SIMD + 1,
		maxps		= SIMD + 2,
		addps		= SIMD + 3,
		subps		= SIMD + 4,
		mulps		= SIMD + 5,
		divps		= SIMD + 6,
		sqrtps		= SIMD + 7,
		cvtps2pd	= SIMD + 32,
		cvtdq2ps	= SIMD + 34,
		cvttps2dq	= SIMD + 35,
		cvtps2dq	= SIMD + 36,
		cvtpi2ps	= SIMD + INTREG + 0,
		cvttps2pi	= SIMD + INTREG + 1,
		cvtps2pi	= SIMD + INTREG + 2,

		/* double precision scalar instructions */
		cmpsd		= DOUBLE + 0,
		minsd		= DOUBLE + 1,
		maxsd		= DOUBLE + 2,
		addsd		= DOUBLE + 3,
		subsd		= DOUBLE + 4,
		mulsd		= DOUBLE + 5,
		divsd		= DOUBLE + 6,
		sqrtsd		= DOUBLE + 7,
		ucomisd		= DOUBLE + 16,
		comisd		= DOUBLE + 17,
		cvtsd2ss	= DOUBLE + 32,
		cvtsi2sd	= DOUBLE + INTREG + 0,
		cvttsd2si	= DOUBLE + INTREG + 1,
		cvtsd2si	= DOUBLE + INTREG + 2,
		cvtsi2sdq	= DOUBLE + INTREG + 8,
		cvttsd2siq	= DOUBLE + INTREG + 9,
		cvtsd2siq	= DOUBLE + INTREG + 10,

		/* double precision SIMD instructions */
		cmppd		= DOUBLE + SIMD + 0,
		minpd		= DOUBLE + SIMD + 1,
		maxpd		= DOUBLE + SIMD + 2,
		addpd		= DOUBLE + SIMD + 3,
		subpd		= DOUBLE + SIMD + 4,
		mulpd		= DOUBLE + SIMD + 5,
		divpd		= DOUBLE + SIMD + 6,
		sqrtpd		= DOUBLE + SIMD + 7,
		cvtpd2ps	= DOUBLE + SIMD + 32,
		cvtdq2pd	= DOUBLE + SIMD + 34,
		cvttpd2dq	= DOUBLE + SIMD + 35,
		cvtpd2dq	= DOUBLE + SIMD + 36,
		cvtpi2pd	= DOUBLE + SIMD + INTREG + 0,
		cvttpd2pi	= DOUBLE + SIMD + INTREG + 1,
		cvtpd2pi	= DOUBLE + SIMD + INTREG + 2,
	} op;
	int		imm;
	sseoperand_t	*op1, *op2;
} sseinst_t;

/* x86-specific auxiliary functions */
extern int *__fex_accrued(void);
extern void __fex_get_x86_exc(siginfo_t *, ucontext_t *);
extern int __fex_parse_sse(ucontext_t *, sseinst_t *);
extern enum fex_exception __fex_get_sse_op(ucontext_t *, sseinst_t *,
	fex_info_t *);
extern void __fex_get_simd_op(ucontext_t *, sseinst_t *,
	enum fex_exception *, fex_info_t *);
extern void __fex_st_sse_result(ucontext_t *, sseinst_t *,
	enum fex_exception, fex_info_t *);
extern void __fex_st_simd_result(ucontext_t *, sseinst_t *,
	enum fex_exception *, fex_info_t *);

#else
#error Unknown architecture
#endif

#endif	/* _M9X_FEX_HANDLER_H */
