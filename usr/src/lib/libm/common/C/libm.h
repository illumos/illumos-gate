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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_LIBM_H
#define	_LIBM_H

#include <sys/isa_defs.h>

#ifdef _ASM
/* BEGIN CSTYLED */

/*
 * Disable amd64 assembly code profiling for now.
 */
#if defined(__amd64)
#undef PROF
#endif

#include <sys/asm_linkage.h>

#define	NAME(x) x
#define	TEXT	.section	".text"
#define	DATA	.section	".data"
#define	RO_DATA	.section	".rodata"
#define	IDENT(x)	.ident	x

#if defined(__sparc)

#define	LIBM_ANSI_PRAGMA_WEAK(sym,stype) \
	.weak sym; \
	.type sym,#stype; \
sym	= __/**/sym

#ifndef SET_FILE
#define	SET_FILE(x) \
	.file	x
#endif	/* !defined(SET_FILE) */

#ifdef PIC
/*
 * One should *never* pass o7 to PIC_SETUP.
 */
#define	PIC_SETUP(via) \
9:	call	8f; \
	sethi	%hi(NAME(_GLOBAL_OFFSET_TABLE_)-(9b-.)),%via; \
8:	or	%via,%lo(NAME(_GLOBAL_OFFSET_TABLE_)-(9b-.)),%via; \
	add	%via,%o7,%via
/*
 * Must save/restore %o7 in leaf routines; may *not* use jmpl!
 */
#define	PIC_LEAF_SETUP(via) \
	or	%g0,%o7,%g1; \
9:	call	8f; \
	sethi	%hi(NAME(_GLOBAL_OFFSET_TABLE_)-(9b-.)),%via; \
8:	or	%via,%lo(NAME(_GLOBAL_OFFSET_TABLE_)-(9b-.)),%via; \
	add	%via,%o7,%via; \
	or	%g0,%g1,%o7
#ifdef __sparcv9
#define	PIC_SET(via,sym,dst)	ldx	[%via+sym],%dst
#else	/* defined(__sparcv9) */
#define	PIC_SET(via,sym,dst)	ld	[%via+sym],%dst
#endif	/* defined(__sparcv9) */
#else	/* defined(PIC) */
#define	PIC_SETUP(via)
#define	PIC_LEAF_SETUP(via)
#ifdef __sparcv9
/*
 * g1 is used as scratch register in V9 mode
 */
#define	PIC_SET(via,sym,dst)	setx	sym,%g1,%dst
#else	/* defined(__sparcv9) */
#define	PIC_SET(via,sym,dst)	set	sym,%dst
#endif	/* defined(__sparcv9) */
#endif	/* defined(PIC) */

/*
 * Workaround for 4337025: MCOUNT in asm_linkage.h does not support __sparcv9
 */
#if defined(PROF) && defined(__sparcv9)

#undef MCOUNT_SIZE
#undef MCOUNT

#if !defined(PIC)
#define	MCOUNT_SIZE	(9*4)	/* 9 instructions */
#define	MCOUNT(x) \
	save	%sp, -SA(MINFRAME), %sp; \
	sethi	%hh(.L_/**/x/**/1), %o0; \
	sethi	%lm(.L_/**/x/**/1), %o1; \
	or	%o0, %hm(.L_/**/x/**/1), %o0; \
	or	%o1, %lo(.L_/**/x/**/1), %o1; \
	sllx	%o0, 32, %o0; \
	call	_mcount; \
	or	%o0, %o1, %o0; \
	restore; \
	.common .L_/**/x/**/1, 8, 8
#elif defined(PIC32)
#define	MCOUNT_SIZE	(10*4)	/* 10 instructions */
#define	MCOUNT(x) \
	save	%sp,-SA(MINFRAME),%sp; \
1:	call	.+8; \
	sethi	%hi(_GLOBAL_OFFSET_TABLE_-(1b-.)),%o0; \
	sethi	%hi(.L_/**/x/**/1),%o1; \
	add	%o0,%lo(_GLOBAL_OFFSET_TABLE_-(1b-.)),%o0; \
	add	%o1,%lo(.L_/**/x/**/1),%o1; \
	add	%o0,%o7,%o0; \
	call	_mcount; \
	ldx	[%o0+%o1],%o0; \
	restore; \
	.common .L_/**/x/**/1,8,8
#else	/* PIC13 */
#define	MCOUNT_SIZE	(8*4)	/* 8 instructions */
#define	MCOUNT(x) \
	save	%sp,-SA(MINFRAME),%sp; \
1:	call	.+8; \
	sethi	%hi(_GLOBAL_OFFSET_TABLE_-(1b-.)),%o0; \
	add	%o0,%lo(_GLOBAL_OFFSET_TABLE_-(1b-.)),%o0; \
	add	%o0,%o7,%o0; \
	call	_mcount; \
	ldx	[%o0+%lo(.L_/**/x/**/1)],%o0; \
	restore; \
	.common .L_/**/x/**/1,8,8
#endif	/* !defined(PIC) */
#endif /* defined(PROF) && defined(__sparcv9) */

#elif defined(__x86)

#define	LIBM_ANSI_PRAGMA_WEAK(sym,stype) \
	.weak sym; \
	.type sym,@stype; \
sym	= __/**/sym

#ifdef PIC
#if defined(__amd64)
#define	PIC_SETUP(x)
#define	PIC_WRAPUP
#define	PIC_F(x)	x@PLT
#define	PIC_G(x)	x@GOTPCREL(%rip)
#define	PIC_L(x)	x(%rip)
#define	PIC_G_LOAD(insn,sym,dst) \
	movq	PIC_G(sym),%dst; \
	insn	(%dst),%dst
#else
#define	PIC_SETUP(label) \
	pushl	%ebx; \
	call	.label; \
.label:	popl	%ebx; \
	addl	$_GLOBAL_OFFSET_TABLE_+[.-.label],%ebx
#define	PIC_WRAPUP	popl	%ebx
#define	PIC_F(x)	x@PLT
#define	PIC_G(x)	x@GOT(%ebx)
#define	PIC_L(x)	x@GOTOFF(%ebx)
#define	PIC_G_LOAD(insn,sym,dst) \
	mov	PIC_G(sym),%dst; \
	insn	(%dst),%dst
#endif
#else	/* defined(PIC) */
#define	PIC_SETUP(x)
#define	PIC_WRAPUP
#define	PIC_F(x)	x
#define	PIC_G(x)	x
#define	PIC_L(x)	x
#define	PIC_G_LOAD(insn,sym,dst)	insn	sym,%dst
#endif	/* defined(PIC) */

#else
#error Unknown architecture
#endif

/* END CSTYLED */
#else	/* defined(_ASM) */

#include "libm_macros.h"
#include "libm_synonyms.h"
#include "libm_protos.h"
#include "libm_inlines.h"
#include <math.h>
#if defined(__SUNPRO_C)
#include <sunmath.h>
#endif

#endif	/* defined(_ASM) */

#endif	/* _LIBM_H */
