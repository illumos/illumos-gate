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

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PROCFS_ISA_H */
