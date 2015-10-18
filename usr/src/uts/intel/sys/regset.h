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
 * Copyright (c) 1989, 2010, Oracle and/or its affiliates. All rights reserved.
 */
/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc. */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T		*/
/*	All Rights Reserved	*/

#ifndef	_SYS_REGSET_H
#define	_SYS_REGSET_H

#include <sys/feature_tests.h>

#if !defined(_ASM)
#include <sys/types.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(_XPG4_2) || defined(__EXTENSIONS__)

/*
 * The names and offsets defined here should be specified by the
 * AMD64 ABI suppl.
 *
 * We make fsbase and gsbase part of the lwp context (since they're
 * the only way to access the full 64-bit address range via the segment
 * registers) and thus belong here too.  However we treat them as
 * read-only; if %fs or %gs are updated, the results of the descriptor
 * table lookup that those updates implicitly cause will be reflected
 * in the corresponding fsbase and/or gsbase values the next time the
 * context can be inspected.  However it is NOT possible to override
 * the fsbase/gsbase settings via this interface.
 *
 * Direct modification of the base registers (thus overriding the
 * descriptor table base address) can be achieved with _lwp_setprivate.
 */

#define	REG_GSBASE	27
#define	REG_FSBASE	26
#define	REG_DS		25
#define	REG_ES		24

#define	REG_GS		23
#define	REG_FS		22
#define	REG_SS		21
#define	REG_RSP		20
#define	REG_RFL		19
#define	REG_CS		18
#define	REG_RIP		17
#define	REG_ERR		16
#define	REG_TRAPNO	15
#define	REG_RAX		14
#define	REG_RCX		13
#define	REG_RDX		12
#define	REG_RBX		11
#define	REG_RBP		10
#define	REG_RSI		9
#define	REG_RDI		8
#define	REG_R8		7
#define	REG_R9		6
#define	REG_R10		5
#define	REG_R11		4
#define	REG_R12		3
#define	REG_R13		2
#define	REG_R14		1
#define	REG_R15		0

/*
 * The names and offsets defined here are specified by i386 ABI suppl.
 */

#define	SS		18	/* only stored on a privilege transition */
#define	UESP		17	/* only stored on a privilege transition */
#define	EFL		16
#define	CS		15
#define	EIP		14
#define	ERR		13
#define	TRAPNO		12
#define	EAX		11
#define	ECX		10
#define	EDX		9
#define	EBX		8
#define	ESP		7
#define	EBP		6
#define	ESI		5
#define	EDI		4
#define	DS		3
#define	ES		2
#define	FS		1
#define	GS		0

/* aliases for portability */

#if defined(__amd64)

#define	REG_PC	REG_RIP
#define	REG_FP	REG_RBP
#define	REG_SP	REG_RSP
#define	REG_PS	REG_RFL
#define	REG_R0	REG_RAX
#define	REG_R1	REG_RDX

#else	/* __i386 */

#define	REG_PC	EIP
#define	REG_FP	EBP
#define	REG_SP	UESP
#define	REG_PS	EFL
#define	REG_R0	EAX
#define	REG_R1	EDX

#endif	/* __i386 */

#endif	/* !defined(_XPG4_2) || defined(__EXTENSIONS__) */

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
#if !defined(_XPG4_2) || defined(__EXTENSIONS__)
#define	NGREG	_NGREG
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

#if !defined(_XPG4_2) || defined(__EXTENSIONS__)

/*
 * Floating point definitions.
 */

/*
 * This structure is written to memory by an 'fnsave' instruction
 */
struct fnsave_state {
	uint16_t	f_fcw;
	uint16_t	__f_ign0;
	uint16_t	f_fsw;
	uint16_t	__f_ign1;
	uint16_t	f_ftw;
	uint16_t	__f_ign2;
	uint32_t	f_eip;
	uint16_t	f_cs;
	uint16_t	f_fop;
	uint32_t	f_dp;
	uint16_t	f_ds;
	uint16_t	__f_ign3;
	union {
		uint16_t fpr_16[5];	/* 80-bits of x87 state */
	} f_st[8];
};	/* 108 bytes */

/*
 * This structure is written to memory by an 'fxsave' instruction
 * Note the variant behaviour of this instruction between long mode
 * and legacy environments!
 */
struct fxsave_state {
	uint16_t	fx_fcw;
	uint16_t	fx_fsw;
	uint16_t	fx_fctw;	/* compressed tag word */
	uint16_t	fx_fop;
#if defined(__amd64)
	uint64_t	fx_rip;
	uint64_t	fx_rdp;
#else
	uint32_t	fx_eip;
	uint16_t	fx_cs;
	uint16_t	__fx_ign0;
	uint32_t	fx_dp;
	uint16_t	fx_ds;
	uint16_t	__fx_ign1;
#endif
	uint32_t	fx_mxcsr;
	uint32_t	fx_mxcsr_mask;
	union {
		uint16_t fpr_16[5];	/* 80-bits of x87 state */
		u_longlong_t fpr_mmx;	/* 64-bit mmx register */
		uint32_t __fpr_pad[4];	/* (pad out to 128-bits) */
	} fx_st[8];
#if defined(__amd64)
	upad128_t	fx_xmm[16];	/* 128-bit registers */
	upad128_t	__fx_ign2[6];
#else
	upad128_t	fx_xmm[8];	/* 128-bit registers */
	upad128_t	__fx_ign2[14];
#endif
};	/* 512 bytes */

/*
 * This structure is written to memory by an 'xsave' instruction.
 * First 512 byte is compatible with the format of an 'fxsave' area.
 */
struct xsave_state {
	struct fxsave_state	xs_fxsave;
	uint64_t		xs_xstate_bv;	/* 512 */
	uint64_t		xs_rsv_mbz[2];
	uint64_t		xs_reserved[5];
	upad128_t		xs_ymm[16];	/* avx - 576 */
};	/* 832 bytes, asserted in fpnoextflt() */

#if defined(__amd64)

typedef struct fpu {
	union {
		struct fpchip_state {
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
typedef struct fpu {
	union {
		struct fpchip_state {
			uint32_t state[27];	/* 287/387 saved state */
			uint32_t status;	/* saved at exception */
			uint32_t mxcsr;		/* SSE control and status */
			uint32_t xstatus;	/* SSE mxcsr at exception */
			uint32_t __pad[2];	/* align to 128-bits */
			upad128_t xmm[8];	/* %xmm0-%xmm7 */
		} fpchip_state;
		struct fp_emul_space {		/* for emulator(s) */
			uint8_t	fp_emul[246];
			uint8_t	fp_epad[2];
		} fp_emul_space;
		uint32_t	f_fpregs[95];	/* union of the above */
	} fp_reg_set;
} fpregset_t;

/*
 * (This structure definition is specified in the i386 ABI supplement)
 */
typedef struct __old_fpu {
	union {
		struct __old_fpchip_state	/* fp extension state */
		{
			int 	state[27];	/* 287/387 saved state */
			int 	status;		/* status word saved at */
						/* exception */
		} fpchip_state;
		struct __old_fp_emul_space	/* for emulator(s) */
		{
			char	fp_emul[246];
			char	fp_epad[2];
		} fp_emul_space;
		int 	f_fpregs[62];		/* union of the above */
	} fp_reg_set;
	long    	f_wregs[33];		/* saved weitek state */
} __old_fpregset_t;

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
 * Kernel's FPU save area
 */
typedef struct {
	union _kfpu_u {
		struct fxsave_state kfpu_fx;
#if defined(__i386)
		struct fnsave_state kfpu_fn;
#endif
		struct xsave_state kfpu_xs;
	} kfpu_u;
	uint32_t kfpu_status;		/* saved at #mf exception */
	uint32_t kfpu_xstatus;		/* saved at #xm exception */
} kfpu_t;

#if defined(__amd64)
#define	NDEBUGREG	16
#else
#define	NDEBUGREG	8
#endif

typedef struct dbregset {
	unsigned long	debugreg[NDEBUGREG];
} dbregset_t;

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
#endif /* !defined(_XPG4_2) || defined(__EXTENSIONS__) */

/*
 * The version of privregs.h that is used on implementations that run on
 * processors that support the AMD64 instruction set is deliberately not
 * imported here.
 *
 * The amd64 'struct regs' definition may -not- compatible with either
 * 32-bit or 64-bit core file contents, nor with the ucontext.  As a result,
 * the 'regs' structure cannot be used portably by applications, and should
 * only be used by the kernel implementation.
 *
 * The inclusion of the i386 version of privregs.h allows for some limited
 * source compatibility with 32-bit applications who expect to use
 * 'struct regs' to match the context of a 32-bit core file, or a ucontext_t.
 *
 * Note that the ucontext_t actually describes the general register in terms
 * of the gregset_t data type, as described in this file.  Note also
 * that the core file content is defined by core(4) in terms of data types
 * defined by procfs -- see proc(4).
 */
#if defined(__i386) && \
	(!defined(_KERNEL) && !defined(_XPG4_2) || defined(__EXTENSIONS__))
#include <sys/privregs.h>
#endif	/* __i386 (!_KERNEL && !_XPG4_2 || __EXTENSIONS__) */

/*
 * The following is here for XPG4.2 standards compliance.
 * regset.h is included in ucontext.h for the definition of
 * mcontext_t, all of which breaks XPG4.2 namespace.
 */

#if defined(_XPG4_2) && !defined(__EXTENSIONS__) && !defined(_ASM)

/*
 * The following is here for UNIX 95 compliance (XPG Issue 4, Version 2
 * System Interfaces and Headers). The structures included here are identical
 * to those visible elsewhere in this header except that the structure
 * element names have been changed in accordance with the X/Open namespace
 * rules.  Specifically, depending on the name and scope, the names have
 * been prepended with a single or double underscore (_ or __).  See the
 * structure definitions in the non-X/Open namespace for more detailed
 * comments describing each of these structures.
 */

#if defined(__amd64)

typedef struct __fpu {
	union {
		struct __fpchip_state {
			uint16_t __fx_cw;
			uint16_t __fx_sw;
			uint16_t __fx_ctw;
			uint16_t __fx_op;
			uint64_t __fx_rip;
			uint64_t __fx_rdp;
			uint32_t __fx_mxcsr;
			uint32_t __fx_mxcsr_mask;
			union {
				uint16_t __fpr_16[5];
				upad128_t __fpr_pad;
			} __fx_st[8];
			upad128_t __fx_xmm[16];
			upad128_t __fx_ign2[6];
			uint32_t __status;
			uint32_t __xstatus;
		} __fpchip_state;
		uint32_t	__f_fpregs[130];
	} __fp_reg_set;
} fpregset_t;

#else	/* __i386 */

typedef struct __fpu {
	union {
		struct __fpchip_state {
			uint32_t __state[27];	/* 287/387 saved state */
			uint32_t __status;	/* saved at exception */
			uint32_t __mxcsr;	/* SSE control and status */
			uint32_t __xstatus;	/* SSE mxcsr at exception */
			uint32_t __pad[2];	/* align to 128-bits */
			upad128_t __xmm[8];	/* %xmm0-%xmm7 */
		} __fpchip_state;
		struct __fp_emul_space {	/* for emulator(s) */
			uint8_t	 __fp_emul[246];
			uint8_t	 __fp_epad[2];
		} __fp_emul_space;
		uint32_t	__f_fpregs[95];	/* union of the above */
	} __fp_reg_set;
} fpregset_t;

#endif	/* __i386 */

typedef struct {
	gregset_t	__gregs;	/* general register set */
	fpregset_t	__fpregs;	/* floating point register set */
} mcontext_t;

#endif /* _XPG4_2 && !__EXTENSIONS__ && !_ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_REGSET_H */
