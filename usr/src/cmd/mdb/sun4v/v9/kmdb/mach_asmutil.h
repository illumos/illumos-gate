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

#ifndef _MACH_ASMUTIL_H
#define	_MACH_ASMUTIL_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef _ASM

#define	GET_NWIN(scr1, reg1)	\
	rdpr	%cwp, scr1;	/* save current %cwp */	\
	wrpr	%g0, 0x1f, %cwp;	\
	rdpr	%cwp, reg1;		\
	wrpr	%g0, scr1, %cwp	/* restore current %cwp */

#define	SET_GL(x)	\
	wrpr	%g0, x, %gl

#define	SWITCH_TO_NORMAL_GLOBALS()	\
	/* tempararily save %o5 and %o4 and %o3 */; \
	stx	%o5, [%g5 + KREG_OFF(KREG_O5)]; \
	stx	%o4, [%g5 + KREG_OFF(KREG_O4)]; \
	stx	%o3, [%g5 + KREG_OFF(KREG_O3)]; \
	/* now save %g5, %g4 and %g7 cause we are going to gl 0 */; \
	mov	%g5, %o5	/* %o5 is gregs pointer now */; \
	mov	%g4, %o4	/* %o4 is %pstate value now */; \
	mov	%g7, %o3	/* %o3 is return pc now */; \
	SET_GL(0);	/* normal globals */

#define	SWITCH_TO_TL1_GLOBALS_AND_RET()	\
	SET_GL(1)	/* use TL1 globals, set %pstate from %o4 */;\
	mov	%o4, %g4		/* restore %g4 as %pstate */; \
	mov	%o5, %g5		/* restore %g5 as gregs pointer */; \
	mov	%o3, %g7		/* retore %g7 as return pc */; \
	ldx	[%g5 + KREG_OFF(KREG_O5)], %o5 /* restore saved %o5 */; \
	ldx	[%g5 + KREG_OFF(KREG_O4)], %o4 /* restore saved %o4 */; \
	jmp	%g7; \
	ldx	[%g5 + KREG_OFF(KREG_O3)], %o3 /* restore saved %o3 */

#define	KAIF_SAVE_TL1_STATE()	\
	ba	kaif_save_tl1_state;\
	mov	PTSTATE_KERN_COMMON, %g4

#define	KAIF_SAVE_TL1_STATE_SLAVE()	KAIF_SAVE_TL1_STATE()

#define	SET_PSTATE_COMMON_AG(reg1)	\
	or	%g0, PTSTATE_KERN_COMMON, reg1;\
	wrpr	reg1, %pstate

#define	KAIF_DEMAP_TLB_ALL(scr)

#endif

#ifdef __cplusplus
}
#endif

#endif /* _MACH_ASMUTIL_H */
