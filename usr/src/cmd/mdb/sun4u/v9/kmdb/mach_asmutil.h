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
	rdpr	%ver, reg1;\
	and	reg1, VER_MAXWIN, reg1

#define	SET_GL(x)

#define	SWITCH_TO_NORMAL_GLOBALS()	\
	mov	%o5, %g3	/* save %o5 in %g3 */;\
	mov	%o4, %g2	/* save %o4 in %g2 */;\
	mov	%g5, %o5	/* set %o5 = gregs pointer */;\
	mov	%g4, %o4	/* set %o4 = return %pstate value */;\
	wrpr	%g0, PTSTATE_KERN_COMMON, %pstate	/* AG = 0 */

#define	SWITCH_TO_TL1_GLOBALS_AND_RET()	\
	wrpr	%o4, %pstate	/* use TL1 globals, set %pstate from %o4 */;\
	mov	%g3, %o5	/* restore saved %o5 from %g3 */;\
	jmp	%g7;\
	mov	%g2, %o4	/* restore saved %o4 from %g2 */

#define	KAIF_SAVE_TL1_STATE()	\
	ba	kaif_save_tl1_state;\
	mov	PTSTATE_KERN_COMMON|PSTATE_AG, %g4

#define	KAIF_SAVE_TL1_STATE_SLAVE()	\
	ba	kaif_save_tl1_state;\
	mov	PTSTATE_KERN_COMMON|PSTATE_IG, %g4

#define	SET_PSTATE_COMMON_AG(reg1)	\
	or	%g0, PTSTATE_KERN_COMMON | PSTATE_AG, reg1;\
	wrpr	reg1, %pstate

#define	KAIF_DEMAP_TLB_ALL(scr)			\
	mov	DEMAP_ALL_TYPE, scr;		\
	stxa	%g0, [scr]ASI_DTLB_DEMAP;	\
	sethi	%hi(FLUSH_ADDR), scr;		\
	flush	scr

#endif

#ifdef __cplusplus
}
#endif

#endif /* _MACH_ASMUTIL_H */
