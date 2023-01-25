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

/*
 * Copyright 2023 Oxide Computer Company
 */

#ifndef _SYS_PROCFS_ISA_H
#define	_SYS_PROCFS_ISA_H

/*
 * Instruction Set Architecture specific component of <sys/procfs.h>
 * i386 version
 */

#include <sys/regset.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Possible values of pr_dmodel.
 * This isn't isa-specific, but it needs to be defined here for other reasons.
 */
#define	PR_MODEL_UNKNOWN 0
#define	PR_MODEL_ILP32	1	/* process data model is ILP32 */
#define	PR_MODEL_LP64	2	/* process data model is LP64 */

/*
 * To determine whether application is running native.
 */
#if defined(_LP64)
#define	PR_MODEL_NATIVE	PR_MODEL_LP64
#elif defined(_ILP32)
#define	PR_MODEL_NATIVE	PR_MODEL_ILP32
#else
#error "No DATAMODEL_NATIVE specified"
#endif	/* _LP64 || _ILP32 */

#if defined(__i386) || defined(__amd64)
/*
 * Holds one i386 or amd64 instruction
 */
typedef	uchar_t instr_t;
#endif

#define	NPRGREG		_NGREG
#define	prgreg_t	greg_t
#define	prgregset_t	gregset_t
#define	prfpregset	_fpu
#define	prfpregset_t	fpregset_t

#if defined(_SYSCALL32)
/*
 * kernel view of the ia32 register set
 */
typedef	uchar_t		instr32_t;
#if defined(__amd64)
#define	NPRGREG32	_NGREG32
#define	prgreg32_t	greg32_t
#define	prgregset32_t	gregset32_t
#define	prfpregset32	fpu32
#define	prfpregset32_t	fpregset32_t
#else
#define	NPRGREG32	_NGREG
#define	prgreg32_t	greg_t
#define	prgregset32_t	gregset_t
#define	prfpregset32	_fpu
#define	prfpregset32_t	fpregset_t
#endif
#endif	/* _SYSCALL32 */

#if defined(__amd64)
/*
 * The following defines are for portability (see <sys/regset.h>).
 */
#define	R_PC	REG_RIP
#define	R_PS	REG_RFL
#define	R_SP	REG_RSP
#define	R_FP	REG_RBP
#define	R_R0	REG_RAX
#define	R_R1	REG_RDX
#elif defined(__i386)
/*
 * The following defines are for portability (see <sys/regset.h>).
 */
#define	R_PC	EIP
#define	R_PS	EFL
#define	R_SP	UESP
#define	R_FP	EBP
#define	R_R0	EAX
#define	R_R1	EDX
#endif

/*
 * The x86 xregs structure is a blob of data that contains a header with several
 * descriptors that describe the region of additional data that corresponds to
 * it. Effectively this looks like:
 *
 * 0  +-----------------+
 *    | prxregset_hdr_t |
 *    +-----------------+
 *    | Info 0 (XCR)    |-------+
 *    +-----------------+       |
 *    | Info 1 (XSAVE)  |----------+
 *    +-----------------+       |  |
 *           ...                |  |
 *    +-----------------+       |  |
 *    | Info n (Hi ZMM) |-------------+
 *    +-----------------+       |  |  |
 *    +-----------------+       |  |  |
 *    | prxregset_xcr_t |<------+  |  |
 *    +-----------------+          |  |
 *    +-------------------+        |  |
 *    | prxregset_xsave_t |<-------+  |
 *    |                   |           |
 *    | XMM + xsave       |           |
 *    +-------------------+           |
 *           ...                      |
 *    +---------------------+         |
 *    | prxregset_hi_zmm_t  |<--------+
 *    |                     |
 *    | 1 KiB %zmm16-%zmm31 |
 *    +---------------------+
 *
 * The actual structure size will vary based on the CPU features present. For
 * more information, see proc(5). When adding structures, please make sure all
 * structures are multiples of 16 bytes (0x10) so as to ensure alignment.
 */
typedef struct prxregset prxregset_t;

#define	PRX_INFO_XCR	0x01
#define	PRX_INFO_XSAVE	0x02
#define	PRX_INFO_YMM	0x03
#define	PRX_INFO_OPMASK	0x04
#define	PRX_INFO_ZMM	0x05
#define	PRX_INFO_HI_ZMM	0x06

typedef struct prxregset_info {
	uint32_t pri_type;
	uint32_t pri_flags;
	uint32_t pri_size;
	uint32_t pri_offset;
} prxregset_info_t;

#define	PR_TYPE_XSAVE	0x01

typedef struct prxregset_hdr {
	uint32_t	pr_type;
	uint32_t	pr_size;
	uint32_t	pr_flags;
	uint32_t	pr_pad[4];
	uint32_t	pr_ninfo;
#if defined(_STDC_C99) || defined(__C99FEATURES__)
	prxregset_info_t pr_info[];
#endif
} prxregset_hdr_t;

typedef struct prxregset_xcr {
	uint64_t	prx_xcr_xcr0;
	uint64_t	prx_xcr_xfd;
	uint64_t	prx_xcr_pad[2];
} prxregset_xcr_t;

typedef struct prxregset_xsave {
	uint16_t	prx_fx_fcw;
	uint16_t	prx_fx_fsw;
	uint16_t	prx_fx_fctw;	/* compressed tag word */
	uint16_t	prx_fx_fop;
#if defined(__amd64)
	uint64_t	prx_fx_rip;
	uint64_t	prx_fx_rdp;
#else
	uint32_t	prx_fx_eip;
	uint16_t	prx_fx_cs;
	uint16_t	__prx_fx_ign0;
	uint32_t	prx_fx_dp;
	uint16_t	prx_fx_ds;
	uint16_t	__prx_fx_ign1;
#endif
	uint32_t	prx_fx_mxcsr;
	uint32_t	prx_fx_mxcsr_mask;
	union {
		uint16_t prx_fpr_16[5];	/* 80-bits of x87 state */
		u_longlong_t prx_fpr_mmx;	/* 64-bit mmx register */
		uint32_t _prx__fpr_pad[4];	/* (pad out to 128-bits) */
	} fx_st[8];
#if defined(__amd64)
	upad128_t	prx_fx_xmm[16];	/* 128-bit registers */
	upad128_t	__prx_fx_ign2[6];
#else
	upad128_t	prx_fx_xmm[8];	/* 128-bit registers */
	upad128_t	__prx_fx_ign2[14];
#endif
	uint64_t	prx_xsh_xstate_bv;
	uint64_t	prx_xsh_xcomp_bv;
	uint64_t	prx_xsh_reserved[6];
} prxregset_xsave_t;

typedef struct prxregset_ymm {
#if defined(__amd64)
	upad128_t	prx_ymm[16];
#else
	upad128_t	prx_ymm[8];
	upad128_t	prx_rsvd[8];
#endif
} prxregset_ymm_t;

typedef struct prxregset_opmask {
	uint64_t	prx_opmask[8];
} prxregset_opmask_t;

typedef struct prxregset_zmm {
#if defined(__amd64)
	upad256_t	prx_zmm[16];
#else
	upad256_t	prx_zmm[8];
	upad256_t	prx_rsvd[8];
#endif
} prxregset_zmm_t;

typedef struct prxregset_hi_zmm {
#if defined(__amd64)
	upad512_t	prx_hi_zmm[16];
#else
	upad512_t	prx_rsvd[16];
#endif
} prxregset_hi_zmm_t;

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PROCFS_ISA_H */
