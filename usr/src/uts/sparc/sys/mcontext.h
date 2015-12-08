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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	All Rights Reserved	*/


/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

/*
 * Essential struct definitions for mcontext_t needed by ucontext.h
 * These were formerly in regset.h, which now includes this file.
 */

#ifndef	_SYS_MCONTEXT_H
#define	_SYS_MCONTEXT_H

#include <sys/feature_tests.h>

#if !defined(_ASM)
#include <sys/int_types.h>
#endif

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * A gregset_t is defined as an array type for compatibility with the reference
 * source. This is important due to differences in the way the C language
 * treats arrays and structures as parameters.
 *
 * Note that NGREG is really (sizeof (struct regs) / sizeof (greg_t)),
 * but that the SPARC V8 ABI defines it absolutely to be 19.
 */
#if defined(__sparcv9)
#define	_NGREG	21
#else	/* __sparcv9 */
#define	_NGREG	19
#endif	/* __sparcv9 */

#ifndef	_ASM

#if defined(_LP64) || defined(_I32LPx)
typedef long	greg_t;
#else
typedef int	greg_t;
#endif

#if defined(_SYSCALL32)

typedef int32_t greg32_t;
typedef int64_t greg64_t;

#endif	/* _SYSCALL32 */

typedef greg_t	gregset_t[_NGREG];

#if defined(_SYSCALL32)

#define	_NGREG32	19
#define	_NGREG64	21

typedef	greg32_t gregset32_t[_NGREG32];
typedef greg64_t gregset64_t[_NGREG64];

#endif	/* _SYSCALL32 */

/*
 * Floating point definitions.
 */

#define	_MAXFPQ	16	/* max # of fpu queue entries currently supported */

/*
 * struct _fq defines the minimal format of a floating point instruction queue
 * entry. The size of entries in the floating point queue are implementation
 * dependent. The union FQu is guarenteed to be the first field in any ABI
 * conformant system implementation. Any additional fields provided by an
 * implementation should not be used applications designed to be ABI conformant.
 */

struct _fpq {
	unsigned int *fpq_addr;		/* address */
	unsigned int fpq_instr;		/* instruction */
};

struct _fq {
	union {				/* FPU inst/addr queue */
		double whole;
		struct _fpq fpq;
	} FQu;
};

#if defined(_SYSCALL32)

struct fpq32 {
	caddr32_t	fpq_addr;	/* address */
	uint32_t	fpq_instr;	/* instruction */
};

struct fq32 {
	union {				/* FPU inst/addr queue */
		double whole;
		struct fpq32 fpq;
	} FQu;
};

#endif	/* _SYSCALL32 */

/*
 * struct fpu is the floating point processor state. struct fpu is the sum
 * total of all possible floating point state which includes the state of
 * external floating point hardware, fpa registers, etc..., if it exists.
 *
 * A floating point instuction queue may or may not be associated with
 * the floating point processor state. If a queue does exist, the field
 * fpu_q will point to an array of fpu_qcnt entries where each entry is
 * fpu_q_entrysize long. fpu_q_entry has a lower bound of sizeof (union FQu)
 * and no upper bound. If no floating point queue entries are associated
 * with the processor state, fpu_qcnt will be zeo and fpu_q will be NULL.
 */

#if defined(__sparcv9)

struct _fpu {
	union {					/* FPU floating point regs */
		uint32_t	fpu_regs[32];	/* 32 singles */
		double		fpu_dregs[32];	/* 32 doubles */
		long double	fpu_qregs[16];	/* 16 quads */
	} fpu_fr;
	struct _fq	*fpu_q;			/* ptr to array of FQ entries */
	uint64_t	fpu_fsr;		/* FPU status register */
	uint8_t		fpu_qcnt;		/* # of entries in saved FQ */
	uint8_t		fpu_q_entrysize;	/* # of bytes per FQ entry */
	uint8_t		fpu_en;			/* flag specifying fpu in use */
};

#else	/* __sparcv9 */

struct _fpu {
	union {					/* FPU floating point regs */
		uint32_t	fpu_regs[32];	/* 32 singles */
		double		fpu_dregs[16];	/* 16 doubles */
	} fpu_fr;
	struct _fq	*fpu_q;			/* ptr to array of FQ entries */
	uint32_t	fpu_fsr;		/* FPU status register */
	uint8_t		fpu_qcnt;		/* # of entries in saved FQ */
	uint8_t		fpu_q_entrysize;	/* # of bytes per FQ entry */
	uint8_t		fpu_en;			/* flag signifying fpu in use */
};

#endif	/* __sparcv9 */

typedef struct _fpu	fpregset_t;

#if defined(_SYSCALL32)

/* Kernel view of user sparcv7/v8 fpu structure */

struct fpu32 {
	union {					/* FPU floating point regs */
		uint32_t	fpu_regs[32];	/* 32 singles */
		double		fpu_dregs[16];	/* 16 doubles */
	} fpu_fr;
	caddr32_t	fpu_q;			/* ptr to array of FQ entries */
	uint32_t	fpu_fsr;		/* FPU status register */
	uint8_t		fpu_qcnt;		/* # of entries in saved FQ */
	uint8_t		fpu_q_entrysize;	/* # of bytes per FQ entry */
	uint8_t		fpu_en;			/* flag signifying fpu in use */
};

typedef struct fpu32	fpregset32_t;

#endif	/* _SYSCALL32 */

#if defined(_KERNEL) || defined(_KMDB)
/*
 * The ABI uses struct fpu, so we use this to describe the kernel's view of the
 * fpu.
 */
typedef struct {
	union _fpu_fr {				/* V9 FPU floating point regs */
		uint32_t	fpu_regs[32];	/* 32 singles */
		uint64_t	fpu_dregs[32];	/* 32 doubles */
		long double	fpu_qregs[16];	/* 16 quads */
	} fpu_fr;
	uint64_t	fpu_fsr;		/* FPU status register */
	uint32_t	 fpu_fprs;		/* fprs register */
	struct _fq	*fpu_q;
	uint8_t		fpu_qcnt;
	uint8_t		fpu_q_entrysize;
	uint8_t		fpu_en;			/* flag signifying fpu in use */
} kfpu_t;
#endif /* _KERNEL || _KMDB */

/*
 * The following structure is for associating extra register state with
 * the ucontext structure and is kept within the uc_mcontext filler area.
 *
 * If (xrs_id == XRS_ID) then the xrs_ptr field is a valid pointer to
 * extra register state. The exact format of the extra register state
 * pointed to by xrs_ptr is platform-dependent.
 *
 * Note: a platform may or may not manage extra register state.
 */
typedef struct {
	unsigned int	xrs_id;		/* indicates xrs_ptr validity */
	caddr_t		xrs_ptr;	/* ptr to extra reg state */
} xrs_t;

#define	_XRS_ID			0x78727300	/* the string "xrs" */

#if defined(_SYSCALL32)

typedef	struct {
	uint32_t	xrs_id;		/* indicates xrs_ptr validity */
	caddr32_t	xrs_ptr;	/* ptr to extra reg state */
} xrs32_t;

#endif	/* _SYSCALL32 */

#if defined(__sparcv9)

/*
 * Ancillary State Registers
 *
 * The SPARC V9 architecture defines 25 ASRs, numbered from 7 through 31.
 * ASRs 16 through 31 are available to user programs, though the meaning
 * and content of these registers is implementation dependent.
 */
typedef	int64_t	asrset_t[16];	/* %asr16 - > %asr31 */

#endif	/* __sparcv9 */

/*
 * Structure mcontext defines the complete hardware machine state. If
 * the field `gwins' is non NULL, it points to a save area for register
 * window frames. If `gwins' is NULL, the register windows were saved
 * on the user's stack.
 *
 * The filler of 21 longs is historical (now filler[19] plus the xrs_t
 * field). The value was selected to provide binary compatibility with
 * statically linked ICL binaries. It is in the ABI (do not change). It
 * actually appears in the ABI as a single filler of 44 is in the field
 * uc_filler of struct ucontext. It is split here so that ucontext.h can
 * (hopefully) remain architecture independent.
 *
 * Note that 2 longs of the filler are used to hold extra register state info.
 */
typedef struct {
	gregset_t	gregs;	/* general register set */
	struct _gwindows *gwins; /* POSSIBLE pointer to register windows */
	fpregset_t	fpregs;	/* floating point register set */
	xrs_t		xrs;	/* POSSIBLE extra register state association */
#if defined(__sparcv9)
	asrset_t	asrs;		/* ancillary registers */
	long		filler[4];	/* room for expansion */
#else	/* __sparcv9 */
	long		filler[19];
#endif	/* __sparcv9 */
} mcontext_t;

#if defined(_SYSCALL32)

typedef struct {
	gregset32_t	gregs;	/* general register set */
	caddr32_t	gwins;	/* POSSIBLE pointer to register windows */
	fpregset32_t	fpregs;	/* floating point register set */
	xrs32_t		xrs;	/* POSSIBLE extra register state association */
	int32_t		filler[19];
} mcontext32_t;

#endif /* _SYSCALL32 */

#endif	/* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_MCONTEXT_H */
