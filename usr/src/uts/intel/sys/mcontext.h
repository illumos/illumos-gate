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
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 *
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc. */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T		*/
/*	All Rights Reserved	*/

/*
 * Essential struct definitions for mcontext_t needed by ucontext.h
 * These were formerly in regset.h, which now includes this file.
 */

#ifndef	_SYS_MCONTEXT_H
#define	_SYS_MCONTEXT_H

#include <sys/feature_tests.h>

#if !defined(_ASM)
#include <sys/types.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

/*
 * A gregset_t is defined as an array type for compatibility with the reference
 * source. This is important due to differences in the way the C language
 * treats arrays and structures as parameters.
 */
#if defined(__amd64)
#define	_NGREG	28
#else
#define	_NGREG	19
#endif

#if !defined(_ASM)

#if defined(_LP64) || defined(_I32LPx)
typedef long	greg_t;
#else
typedef int	greg_t;
#endif

#if defined(_SYSCALL32)

typedef int32_t greg32_t;
typedef int64_t	greg64_t;

#endif	/* _SYSCALL32 */

typedef greg_t	gregset_t[_NGREG];

#if defined(_SYSCALL32)

#define	_NGREG32	19
#define	_NGREG64	28

typedef greg32_t gregset32_t[_NGREG32];
typedef	greg64_t gregset64_t[_NGREG64];

#endif	/* _SYSCALL32 */

/*
 * Floating point definitions.
 */

#if defined(__amd64)

typedef struct _fpu {
	union {
		struct _fpchip_state {
			uint16_t cw;
			uint16_t sw;
			uint8_t  fctw;
			uint8_t  __fx_rsvd;
			uint16_t fop;
			uint64_t rip;
			uint64_t rdp;
			uint32_t mxcsr;
			uint32_t mxcsr_mask;
			union {
				uint16_t fpr_16[5];
				upad128_t __fpr_pad;
			} st[8];
			upad128_t xmm[16];
			upad128_t __fx_ign2[6];
			uint32_t status;	/* sw at exception */
			uint32_t xstatus;	/* mxcsr at exception */
		} fpchip_state;
		uint32_t	f_fpregs[130];
	} fp_reg_set;
} fpregset_t;

#else	/* __i386 */

/*
 * This definition of the floating point structure is binary
 * compatible with the Intel386 psABI definition, and source
 * compatible with that specification for x87-style floating point.
 * It also allows SSE/SSE2 state to be accessed on machines that
 * possess such hardware capabilities.
 */
typedef struct _fpu {
	union {
		struct _fpchip_state {
			uint32_t state[27];	/* 287/387 saved state */
			uint32_t status;	/* saved at exception */
			uint32_t mxcsr;		/* SSE control and status */
			uint32_t xstatus;	/* SSE mxcsr at exception */
			uint32_t __pad[2];	/* align to 128-bits */
			upad128_t xmm[8];	/* %xmm0-%xmm7 */
		} fpchip_state;
		struct _fp_emul_space {		/* for emulator(s) */
			uint8_t	fp_emul[246];
			uint8_t	fp_epad[2];
		} fp_emul_space;
		uint32_t	f_fpregs[95];	/* union of the above */
	} fp_reg_set;
} fpregset_t;

#endif	/* __i386 */

#if defined(_SYSCALL32)

/* Kernel view of user i386 fpu structure */

typedef struct fpu32 {
	union {
		struct fpchip32_state {
			uint32_t state[27];	/* 287/387 saved state */
			uint32_t status;	/* saved at exception */
			uint32_t mxcsr;		/* SSE control and status */
			uint32_t xstatus;	/* SSE mxcsr at exception */
			uint32_t __pad[2];	/* align to 128-bits */
			uint32_t xmm[8][4];	/* %xmm0-%xmm7 */
		} fpchip_state;
		uint32_t	f_fpregs[95];	/* union of the above */
	} fp_reg_set;
} fpregset32_t;

#endif	/* _SYSCALL32 */

/*
 * Structure mcontext defines the complete hardware machine state.
 * (This structure is specified in the i386 ABI suppl.)
 */
typedef struct {
	gregset_t	gregs;		/* general register set */
	fpregset_t	fpregs;		/* floating point register set */
} mcontext_t;

#if defined(_SYSCALL32)

typedef struct {
	gregset32_t	gregs;		/* general register set */
	fpregset32_t	fpregs;		/* floating point register set */
} mcontext32_t;

#endif	/* _SYSCALL32 */

#endif	/* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MCONTEXT_H */
