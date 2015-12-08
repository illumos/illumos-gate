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
 * Copyright (c) 1996-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_PROCFS_ISA_H
#define	_SYS_PROCFS_ISA_H

/*
 * Instruction Set Architecture specific component of <sys/procfs.h>
 * sparc v8/v9 version
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

/*
 * Holds one sparc instruction, for both ILP32 and LP64.
 */
typedef	uint32_t	instr_t;

/*
 * General register access (sparc).
 * Don't confuse definitions here with definitions in <sys/regset.h>.
 * Registers are 32 bits for ILP32, 64 bits for LP64.
 */
#define	NPRGREG	38
#if defined(_LP64) || defined(_I32LPx)
typedef	long		prgreg_t;
#else
typedef	int		prgreg_t;
#endif
typedef	prgreg_t	prgregset_t[NPRGREG];

#define	R_G0	0
#define	R_G1	1
#define	R_G2	2
#define	R_G3	3
#define	R_G4	4
#define	R_G5	5
#define	R_G6	6
#define	R_G7	7
#define	R_O0	8
#define	R_O1	9
#define	R_O2	10
#define	R_O3	11
#define	R_O4	12
#define	R_O5	13
#define	R_O6	14
#define	R_O7	15
#define	R_L0	16
#define	R_L1	17
#define	R_L2	18
#define	R_L3	19
#define	R_L4	20
#define	R_L5	21
#define	R_L6	22
#define	R_L7	23
#define	R_I0	24
#define	R_I1	25
#define	R_I2	26
#define	R_I3	27
#define	R_I4	28
#define	R_I5	29
#define	R_I6	30
#define	R_I7	31

#ifdef	__sparcv9
#define	R_CCR	32	/* v9 condition code register */
#else
#define	R_PSR	32	/* v7/v8 processor status register */
#endif

#define	R_PC	33
#define	R_nPC	34
#define	R_Y	35

#ifdef	__sparcv9
#define	R_ASI	36
#define	R_FPRS	37
#else
#define	R_WIM	36
#define	R_TBR	37
#endif

/*
 * The following defines are for portability.
 */
#ifdef	__sparcv9
#define	R_PS	R_CCR
#else
#define	R_PS	R_PSR
#endif
#define	R_SP	R_O6
#define	R_FP	R_I6
#define	R_R0	R_O0
#define	R_R1	R_O1

#if defined(_SYSCALL32)
/*
 * kernel view of the _ILP32 register set
 */
typedef	int32_t		prgreg32_t;
typedef	prgreg32_t	prgregset32_t[NPRGREG];
#define	R_PSR	32
#define	R_WIM	36
#define	R_TBR	37
#endif

/*
 * Floating-point register access (sparc FPU).
 * See <sys/regset.h> for details of interpretation.
 */
#ifdef	__sparcv9
typedef struct prfpregset {
	union {				/* FPU floating point regs */
		uint32_t pr_regs[32];		/* 32 singles */
		double	pr_dregs[32];		/* 32 doubles */
		long double pr_qregs[16];	/* 16 quads */
	} pr_fr;
	uint64_t pr_filler;
	uint64_t pr_fsr;		/* FPU status register */
	uint8_t	pr_qcnt;		/* # of entries in saved FQ */
	uint8_t	pr_q_entrysize;		/* # of bytes per FQ entry */
	uint8_t	pr_en;			/* flag signifying fpu in use */
	char	pr_pad[13];		/* ensure sizeof(prfpregset)%16 == 0 */
	struct _fq pr_q[16];		/* contains the FQ array */
} prfpregset_t;
#else
typedef struct prfpregset {
	union {				/* FPU floating point regs */
		uint32_t pr_regs[32];		/* 32 singles */
		double	pr_dregs[16];		/* 16 doubles */
	} pr_fr;
	uint32_t pr_filler;
	uint32_t pr_fsr;		/* FPU status register */
	uint8_t	pr_qcnt;		/* # of entries in saved FQ */
	uint8_t	pr_q_entrysize;		/* # of bytes per FQ entry */
	uint8_t	pr_en;			/* flag signifying fpu in use */
	struct _fq pr_q[32];		/* contains the FQ array */
} prfpregset_t;
#endif	/* __sparcv9 */

#if defined(_SYSCALL32)
/*
 * kernel view of the _ILP32 floating point register set
 */
typedef struct prfpregset32 {
	union {				/* FPU floating point regs */
		uint32_t pr_regs[32];		/* 32 singles */
		double	pr_dregs[16];		/* 16 doubles */
	} pr_fr;
	uint32_t pr_filler;
	uint32_t pr_fsr;		/* FPU status register */
	uint8_t	pr_qcnt;		/* # of entries in saved FQ */
	uint8_t	pr_q_entrysize;		/* # of bytes per FQ entry */
	uint8_t	pr_en;			/* flag signifying fpu in use */
	struct fq32 pr_q[32];		/* contains the FQ array */
} prfpregset32_t;
#endif	/* _SYSCALL32 */

/*
 * Extra register access
 */

#define	XR_G0		0
#define	XR_G1		1
#define	XR_G2		2
#define	XR_G3		3
#define	XR_G4		4
#define	XR_G5		5
#define	XR_G6		6
#define	XR_G7		7
#define	NPRXGREG	8

#define	XR_O0		0
#define	XR_O1		1
#define	XR_O2		2
#define	XR_O3		3
#define	XR_O4		4
#define	XR_O5		5
#define	XR_O6		6
#define	XR_O7		7
#define	NPRXOREG	8

#define	NPRXFILLER	8

#define	XR_TYPE_V8P	1		/* interpret union as pr_v8p */

typedef struct prxregset {
	uint32_t	pr_type;		/* how to interpret union */
	uint32_t	pr_align;		/* alignment for the union */
	union {
	    struct pr_v8p {
		union {				/* extra FP registers */
			uint32_t	pr_regs[32];
			double		pr_dregs[16];
#ifndef __sparcv9		/* 32-bit alignment problem */
			long double	pr_qregs[8];
#endif
		} pr_xfr;
		uint32_t	pr_xfsr;	/* upper 32bits, FP state reg */
		uint32_t	pr_fprs;	/* FP registers state */
		uint32_t	pr_xg[NPRXGREG]; /* upper 32bits, G registers */
		uint32_t	pr_xo[NPRXOREG]; /* upper 32bits, O registers */
		uint64_t	pr_tstate;	/* TSTATE register */
		uint32_t	pr_filler[NPRXFILLER];
	    } pr_v8p;
	} pr_un;
} prxregset_t;

/*
 * Given a pointer to a prxregset structure, this macro yields the value
 * of the %gsr embedded in the structure.  It is an lvalue, so it can
 * be used to assign the value of the %gsr into the structure.
 * (Please don't ask why this is done this way.)
 */
#define	PRXREG_GSR(xrp)	(*(uint64_t *)((xrp)->pr_un.pr_v8p.pr_filler))

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PROCFS_ISA_H */
