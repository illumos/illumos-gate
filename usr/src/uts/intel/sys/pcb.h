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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2018, Joyent, Inc.
 */

#ifndef _SYS_PCB_H
#define	_SYS_PCB_H

#include <sys/regset.h>
#include <sys/segments.h>
#ifndef _ASM
#include <sys/fp.h>	/* kfpu_t */
#endif

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef _ASM
typedef struct fpu_ctx {
	kfpu_t		fpu_regs;	/* kernel save area for FPU */
	uint64_t	fpu_xsave_mask;	/* xsave mask for FPU/SSE/AVX */
#if defined(__i386)
	uint64_t	fpu_padding;	/* fix 32bit libmicro regression */
#endif
	uint_t		fpu_flags;	/* FPU state flags */
} fpu_ctx_t;

typedef struct pcb {
	fpu_ctx_t	pcb_fpu;	/* fpu state */
	uint_t		pcb_flags;	/* state flags; cleared on fork */
	greg_t		pcb_drstat;	/* status debug register (%dr6) */
	unsigned char	pcb_instr;	/* /proc: instruction at stop */
	unsigned char	pcb_rupdate;	/* new register values in pcb -> regs */
	uintptr_t	pcb_fsbase;
	uintptr_t	pcb_gsbase;
	selector_t	pcb_ds;
	selector_t	pcb_es;
	selector_t	pcb_fs;
	selector_t	pcb_gs;
	user_desc_t	pcb_fsdesc;	/* private per-lwp %fs descriptors */
	user_desc_t	pcb_gsdesc;	/* private per-lwp %gs descriptors */
} pcb_t;

#endif /* ! _ASM */

/* pcb_flags */
#define	DEBUG_PENDING	0x02	/* single-step of lcall for a sys call */
#define	PRSTOP_CALLED	0x04	/* prstop() has been called for this lwp */
#define	INSTR_VALID	0x08	/* value in pcb_instr is valid (/proc) */
#define	NORMAL_STEP	0x10	/* normal debugger-requested single-step */
#define	WATCH_STEP	0x20	/* single-stepping in watchpoint emulation */
#define	CPC_OVERFLOW	0x40	/* performance counters overflowed */
#define	REQUEST_STEP	0x100	/* request pending to single-step this lwp */
#define	REQUEST_NOSTEP	0x200	/* request pending to disable single-step */
#define	ASYNC_HWERR	0x400	/* hardware error has corrupted context  */

/* pcb_rupdate values */
#define	PCB_UPDATE_SEGS	0x01	/* Update segment registers */
#define	PCB_UPDATE_FPU	0x02	/* Update FPU registers */

#define	PCB_SET_UPDATE_SEGS(pcb)	((pcb)->pcb_rupdate |= PCB_UPDATE_SEGS)
#define	PCB_SET_UPDATE_FPU(pcb)		((pcb)->pcb_rupdate |= PCB_UPDATE_FPU)
#define	PCB_NEED_UPDATE_SEGS(pcb)	\
	(((pcb)->pcb_rupdate & PCB_UPDATE_SEGS) != 0)
#define	PCB_NEED_UPDATE_FPU(pcb)	\
	(((pcb)->pcb_rupdate & PCB_UPDATE_FPU) != 0)
#define	PCB_NEED_UPDATE(pcb)		\
	(PCB_NEED_UPDATE_FPU(pcb) || PCB_NEED_UPDATE_SEGS(pcb))
#define	PCB_CLEAR_UPDATE_SEGS(pcb)	((pcb)->pcb_rupdate &= ~PCB_UPDATE_SEGS)
#define	PCB_CLEAR_UPDATE_FPU(pcb)	((pcb)->pcb_rupdate &= ~PCB_UPDATE_FPU)

/* fpu_flags */
#define	FPU_EN		0x1	/* flag signifying fpu in use */
#define	FPU_VALID	0x2	/* fpu_regs has valid fpu state */
#define	FPU_MODIFIED	0x4	/* fpu_regs is modified (/proc) */

#define	FPU_INVALID	0x0	/* fpu context is not in use */

/* fpu_flags */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PCB_H */
