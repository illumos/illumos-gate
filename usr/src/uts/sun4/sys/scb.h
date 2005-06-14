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
 * Copyright (c) 1991, by Sun Microsystems, Inc.
 */

#ifndef _SYS_SCB_H
#define	_SYS_SCB_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	VEC_MIN 0
#define	VEC_MAX 255
#define	AUTOBASE	16		/* base for autovectored ints */

#ifndef _ASM

typedef	struct trapvec {
	int	instr[8];
} trapvec;

/*
 * Sparc9 System control block layout
 */
struct scb {
	trapvec	tl0_hwtraps[256];	/* 0 - 255 tl0 hw traps */
	trapvec	tl0_swtraps[256];	/* 256 - 511 tl0 sw traps */
	trapvec	tl1_hwtraps[256];	/* 512 - 767 tl>0 hw traps */
	/* we don't use tl>0 sw traps */
};

#ifdef _KERNEL
extern	struct scb scb;
#endif /* _KERNEL */

#endif /* _ASM */

/*
 * These defines are used by the TL1 tlb miss handlers to calculate
 * the pc to jump to in the case the entry was not found in the TSB.
 */
#define	WTRAP_ALIGN	0x7f	/* window handlers are 128 byte align */
#define	WTRAP_FAULTOFF	124	/* last instruction in handler */

/* use the following defines to determine if trap was a fill or a spill */
#define	WTRAP_TTMASK	0x180
#define	WTRAP_TYPE	0x080


#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SCB_H */
