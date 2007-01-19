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

#ifndef _KAIF_ASMUTIL_H
#define	_KAIF_ASMUTIL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/segments.h>

#include <kmdb/kaif_regs.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _ASM

/*
 * Multiple CPUs won't be present until a) we're on the kernel's %gs and
 * b) cross-call initialization has completed.  Until that time, we just assume
 * we're CPU zero.
 *
 * This macro returns the CPUID in %eax, and doesn't clobber any other
 * registers.
 */
#define	GET_CPUID \
	call	kmdb_kdi_xc_initialized;	\
	cmpl	$0, %eax;			\
	je	1f;				\
	movw	%gs, %ax;			\
	cmpw	$KGS_SEL, %ax;			\
	jne	1f;				\
	verr	%ax;				\
	jnz	1f;				\
	;					\
	movzbl	%gs:CPU_ID, %eax;		\
	jmp	2f;				\
1:						\
	clr	%eax;				\
2:

/* clobbers %edx, %ecx, returns addr in %eax, cpu id in %ebx */
#define	GET_CPUSAVE_ADDR \
	GET_CPUID;				\
	movl	%eax, %ebx;			\
	movl	$KRS_SIZE, %ecx;		\
	mull	%ecx;				\
	movl	$kaif_cpusave, %edx;		\
	/*CSTYLED*/				\
	addl	(%edx), %eax

/*
 * Save copies of the IDT and GDT descriptors.  Note that we only save the IDT
 * and GDT if the IDT isn't ours, as we may be legitimately re-entering the
 * debugger through the trap handler.  We don't want to clobber the saved IDT
 * in the process, as we'd end up resuming the world on our IDT.
 *
 * assumes cpusave in %eax, clobbers %ecx
 */
#define	SAVE_IDTGDT \
	sidt	KRS_TMPDESC(%eax);		\
	movl	KRS_TMPDESC+2(%eax), %ecx;	\
	cmpl	$kaif_idt, %ecx;		\
	je	1f;				\
	sidt	KRS_IDTR(%eax);			\
	sgdt	KRS_GDTR(%eax);			\
1:

/*
 * Each cpusave buffer has an area set aside for a ring buffer of breadcrumbs.
 * The following macros manage the buffer.
 */

/* Advance the ring buffer */
#define	ADVANCE_CRUMB_POINTER(cpusave, tmp1, tmp2) \
	movl	KRS_CURCRUMBIDX(cpusave), tmp1;	\
	cmpl	$[KAIF_NCRUMBS - 1], tmp1;	\
	jge	1f;				\
	/* Advance the pointer and index */	\
	addl	$1, tmp1;			\
	movl	tmp1, KRS_CURCRUMBIDX(cpusave);	\
	movl	KRS_CURCRUMB(cpusave), tmp1;	\
	addl	$KRM_SIZE, tmp1;		\
	jmp	2f;				\
1:	/* Reset the pointer and index */	\
	movw	$0, KRS_CURCRUMBIDX(cpusave);	\
	leal	KRS_CRUMBS(cpusave), tmp1;	\
2:	movl	tmp1, KRS_CURCRUMB(cpusave);	\
	/* Clear the new crumb */		\
	movl	$KAIF_NCRUMBS, tmp2;		\
3:	movl	$0, -4(tmp1, tmp2, 4);		\
	decl	tmp2;				\
	jnz	3b

/* Set a value in the current breadcrumb buffer */
#define	ADD_CRUMB(cpusave, offset, value, tmp) \
	movl	KRS_CURCRUMB(cpusave), tmp;	\
	movl	value, offset(tmp)

/* Patch point for MSR clearing. */
#define	KAIF_MSR_PATCH \
	nop; nop; nop; nop; \
	nop; nop; nop; nop; \
	nop; nop; nop; nop; \
	nop

#endif	/* _ASM */

#define	KAIF_MSR_PATCHSZ	13	/* bytes in KAIF_MSR_PATCH, above */
#define	KAIF_MSR_PATCHOFF	8	/* bytes of code before patch point */

#ifdef __cplusplus
}
#endif

#endif /* _KAIF_ASMUTIL_H */
