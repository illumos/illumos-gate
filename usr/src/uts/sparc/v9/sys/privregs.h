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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_PRIVREGS_H
#define	_SYS_PRIVREGS_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * This file is kernel isa dependent.
 */

#include <sys/fsr.h>
#include <v9/sys/asi.h>

/*
 * This file describes the cpu's privileged register set, and
 * how the machine state is saved on the stack when a trap occurs.
 */

#ifndef	_ASM

struct regs {
	long long	r_tstate;
	long long	r_g1;		/* user global regs */
	long long	r_g2;
	long long	r_g3;
	long long	r_g4;
	long long	r_g5;
	long long	r_g6;
	long long	r_g7;
	long long	r_o0;
	long long	r_o1;
	long long	r_o2;
	long long	r_o3;
	long long	r_o4;
	long long	r_o5;
	long long	r_o6;
	long long	r_o7;
	/*
	 * These are still 32b in 4u's v8/v9 hybrid
	 */
	long	r_pc;		/* program counter */
	long	r_npc;		/* next program counter */
	int	r_y;		/* the y register */
};

#define	r_ps	r_tstate
#define	r_sp	r_o6

#endif	/* _ASM */

#ifdef _KERNEL

#define	lwptoregs(lwp)	((struct regs *)((lwp)->lwp_regs))
#define	lwptofpu(lwp)	((kfpu_t *)((lwp)->lwp_fpu))

/*
 * Macros for saving/restoring registers.
 */

#define	SAVE_GLOBALS(RP) \
	stx	%g1, [RP + G1_OFF]; \
	stx	%g2, [RP + G2_OFF]; \
	stx	%g3, [RP + G3_OFF]; \
	stx	%g4, [RP + G4_OFF]; \
	stx	%g5, [RP + G5_OFF]; \
	stx	%g6, [RP + G6_OFF]; \
	stx	%g7, [RP + G7_OFF]; \
	mov	%y, %g1; \
	st	%g1, [RP + Y_OFF];

#define	RESTORE_GLOBALS(RP) \
	ld	[RP + Y_OFF], %g1; \
	mov	%g1, %y; \
	ldx	[RP + G1_OFF], %g1; \
	ldx	[RP + G2_OFF], %g2; \
	ldx	[RP + G3_OFF], %g3; \
	ldx	[RP + G4_OFF], %g4; \
	ldx	[RP + G5_OFF], %g5; \
	ldx	[RP + G6_OFF], %g6; \
	ldx	[RP + G7_OFF], %g7;

#define	SAVE_OUTS(RP) \
	stx	%i0, [RP + O0_OFF]; \
	stx	%i1, [RP + O1_OFF]; \
	stx	%i2, [RP + O2_OFF]; \
	stx	%i3, [RP + O3_OFF]; \
	stx	%i4, [RP + O4_OFF]; \
	stx	%i5, [RP + O5_OFF]; \
	stx	%i6, [RP + O6_OFF]; \
	stx	%i7, [RP + O7_OFF];

#define	RESTORE_OUTS(RP) \
	ldx	[RP + O0_OFF], %i0; \
	ldx	[RP + O1_OFF], %i1; \
	ldx	[RP + O2_OFF], %i2; \
	ldx	[RP + O3_OFF], %i3; \
	ldx	[RP + O4_OFF], %i4; \
	ldx	[RP + O5_OFF], %i5; \
	ldx	[RP + O6_OFF], %i6; \
	ldx	[RP + O7_OFF], %i7;

#define	SAVE_V8WINDOW(SBP) \
	st	%l0, [SBP + (0*4)]; \
	st	%l1, [SBP + (1*4)]; \
	st	%l2, [SBP + (2*4)]; \
	st	%l3, [SBP + (3*4)]; \
	st	%l4, [SBP + (4*4)]; \
	st	%l5, [SBP + (5*4)]; \
	st	%l6, [SBP + (6*4)]; \
	st	%l7, [SBP + (7*4)]; \
	st	%i0, [SBP + (8*4)]; \
	st	%i1, [SBP + (9*4)]; \
	st	%i2, [SBP + (10*4)]; \
	st	%i3, [SBP + (11*4)]; \
	st	%i4, [SBP + (12*4)]; \
	st	%i5, [SBP + (13*4)]; \
	st	%i6, [SBP + (14*4)]; \
	st	%i7, [SBP + (15*4)];

#define	SAVE_V8WINDOW_ASI(SBP) \
	sta	%l0, [SBP + (0*4)]%asi; \
	sta	%l1, [SBP + (1*4)]%asi; \
	sta	%l2, [SBP + (2*4)]%asi; \
	sta	%l3, [SBP + (3*4)]%asi; \
	sta	%l4, [SBP + (4*4)]%asi; \
	sta	%l5, [SBP + (5*4)]%asi; \
	sta	%l6, [SBP + (6*4)]%asi; \
	sta	%l7, [SBP + (7*4)]%asi; \
	sta	%i0, [SBP + (8*4)]%asi; \
	sta	%i1, [SBP + (9*4)]%asi; \
	sta	%i2, [SBP + (10*4)]%asi; \
	sta	%i3, [SBP + (11*4)]%asi; \
	sta	%i4, [SBP + (12*4)]%asi; \
	sta	%i5, [SBP + (13*4)]%asi; \
	sta	%i6, [SBP + (14*4)]%asi; \
	sta	%i7, [SBP + (15*4)]%asi;

#define	RESTORE_V8WINDOW(SBP) \
	ld	[SBP + (0*4)], %l0; \
	ld	[SBP + (1*4)], %l1; \
	ld	[SBP + (2*4)], %l2; \
	ld	[SBP + (3*4)], %l3; \
	ld	[SBP + (4*4)], %l4; \
	ld	[SBP + (5*4)], %l5; \
	ld	[SBP + (6*4)], %l6; \
	ld	[SBP + (7*4)], %l7; \
	ld	[SBP + (8*4)], %i0; \
	ld	[SBP + (9*4)], %i1; \
	ld	[SBP + (10*4)], %i2; \
	ld	[SBP + (11*4)], %i3; \
	ld	[SBP + (12*4)], %i4; \
	ld	[SBP + (13*4)], %i5; \
	ld	[SBP + (14*4)], %i6; \
	ld	[SBP + (15*4)], %i7;

#define	SAVE_V9WINDOW(SBP) \
	stx	%l0, [SBP + (0*8)]; \
	stx	%l1, [SBP + (1*8)]; \
	stx	%l2, [SBP + (2*8)]; \
	stx	%l3, [SBP + (3*8)]; \
	stx	%l4, [SBP + (4*8)]; \
	stx	%l5, [SBP + (5*8)]; \
	stx	%l6, [SBP + (6*8)]; \
	stx	%l7, [SBP + (7*8)]; \
	stx	%i0, [SBP + (8*8)]; \
	stx	%i1, [SBP + (9*8)]; \
	stx	%i2, [SBP + (10*8)]; \
	stx	%i3, [SBP + (11*8)]; \
	stx	%i4, [SBP + (12*8)]; \
	stx	%i5, [SBP + (13*8)]; \
	stx	%i6, [SBP + (14*8)]; \
	stx	%i7, [SBP + (15*8)];

#define	SAVE_V9WINDOW_ASI(SBP) \
	stxa	%l0, [SBP + (0*8)]%asi; \
	stxa	%l1, [SBP + (1*8)]%asi; \
	stxa	%l2, [SBP + (2*8)]%asi; \
	stxa	%l3, [SBP + (3*8)]%asi; \
	stxa	%l4, [SBP + (4*8)]%asi; \
	stxa	%l5, [SBP + (5*8)]%asi; \
	stxa	%l6, [SBP + (6*8)]%asi; \
	stxa	%l7, [SBP + (7*8)]%asi; \
	stxa	%i0, [SBP + (8*8)]%asi; \
	stxa	%i1, [SBP + (9*8)]%asi; \
	stxa	%i2, [SBP + (10*8)]%asi; \
	stxa	%i3, [SBP + (11*8)]%asi; \
	stxa	%i4, [SBP + (12*8)]%asi; \
	stxa	%i5, [SBP + (13*8)]%asi; \
	stxa	%i6, [SBP + (14*8)]%asi; \
	stxa	%i7, [SBP + (15*8)]%asi;

#define	RESTORE_V9WINDOW(SBP) \
	ldx	[SBP + (0*8)], %l0; \
	ldx	[SBP + (1*8)], %l1; \
	ldx	[SBP + (2*8)], %l2; \
	ldx	[SBP + (3*8)], %l3; \
	ldx	[SBP + (4*8)], %l4; \
	ldx	[SBP + (5*8)], %l5; \
	ldx	[SBP + (6*8)], %l6; \
	ldx	[SBP + (7*8)], %l7; \
	ldx	[SBP + (8*8)], %i0; \
	ldx	[SBP + (9*8)], %i1; \
	ldx	[SBP + (10*8)], %i2; \
	ldx	[SBP + (11*8)], %i3; \
	ldx	[SBP + (12*8)], %i4; \
	ldx	[SBP + (13*8)], %i5; \
	ldx	[SBP + (14*8)], %i6; \
	ldx	[SBP + (15*8)], %i7;

#define	STORE_FPREGS(FP) \
	std	%f0, [FP]; \
	std	%f2, [FP + 8]; \
	std	%f4, [FP + 16]; \
	std	%f6, [FP + 24]; \
	std	%f8, [FP + 32]; \
	std	%f10, [FP + 40]; \
	std	%f12, [FP + 48]; \
	std	%f14, [FP + 56]; \
	std	%f16, [FP + 64]; \
	std	%f18, [FP + 72]; \
	std	%f20, [FP + 80]; \
	std	%f22, [FP + 88]; \
	std	%f24, [FP + 96]; \
	std	%f26, [FP + 104]; \
	std	%f28, [FP + 112]; \
	std	%f30, [FP + 120]; \
	std	%d32, [FP + 128]; \
	std	%d34, [FP + 136]; \
	std	%d36, [FP + 144]; \
	std	%d38, [FP + 152]; \
	std	%d40, [FP + 160]; \
	std	%d42, [FP + 168]; \
	std	%d44, [FP + 176]; \
	std	%d46, [FP + 184]; \
	std	%d48, [FP + 192]; \
	std	%d50, [FP + 200]; \
	std	%d52, [FP + 208]; \
	std	%d54, [FP + 216]; \
	std	%d56, [FP + 224]; \
	std	%d58, [FP + 232]; \
	std	%d60, [FP + 240]; \
	std	%d62, [FP + 248];

#define	LOAD_FPREGS(FP) \
	ldd	[FP], %f0; \
	ldd	[FP + 8], %f2; \
	ldd	[FP + 16], %f4; \
	ldd	[FP + 24], %f6; \
	ldd	[FP + 32], %f8; \
	ldd	[FP + 40], %f10; \
	ldd	[FP + 48], %f12; \
	ldd	[FP + 56], %f14; \
	ldd	[FP + 64], %f16; \
	ldd	[FP + 72], %f18; \
	ldd	[FP + 80], %f20; \
	ldd	[FP + 88], %f22; \
	ldd	[FP + 96], %f24; \
	ldd	[FP + 104], %f26; \
	ldd	[FP + 112], %f28; \
	ldd	[FP + 120], %f30; \
	ldd	[FP + 128], %d32; \
	ldd	[FP + 136], %d34; \
	ldd	[FP + 144], %d36; \
	ldd	[FP + 152], %d38; \
	ldd	[FP + 160], %d40; \
	ldd	[FP + 168], %d42; \
	ldd	[FP + 176], %d44; \
	ldd	[FP + 184], %d46; \
	ldd	[FP + 192], %d48; \
	ldd	[FP + 200], %d50; \
	ldd	[FP + 208], %d52; \
	ldd	[FP + 216], %d54; \
	ldd	[FP + 224], %d56; \
	ldd	[FP + 232], %d58; \
	ldd	[FP + 240], %d60; \
	ldd	[FP + 248], %d62;

#define	STORE_DL_FPREGS(FP) \
	std	%f0, [FP]; \
	std	%f2, [FP + 8]; \
	std	%f4, [FP + 16]; \
	std	%f6, [FP + 24]; \
	std	%f8, [FP + 32]; \
	std	%f10, [FP + 40]; \
	std	%f12, [FP + 48]; \
	std	%f14, [FP + 56]; \
	std	%f16, [FP + 64]; \
	std	%f18, [FP + 72]; \
	std	%f20, [FP + 80]; \
	std	%f22, [FP + 88]; \
	std	%f24, [FP + 96]; \
	std	%f26, [FP + 104]; \
	std	%f28, [FP + 112]; \
	std	%f30, [FP + 120];

#define	STORE_DU_FPREGS(FP) \
	std	%d32, [FP + 128]; \
	std	%d34, [FP + 136]; \
	std	%d36, [FP + 144]; \
	std	%d38, [FP + 152]; \
	std	%d40, [FP + 160]; \
	std	%d42, [FP + 168]; \
	std	%d44, [FP + 176]; \
	std	%d46, [FP + 184]; \
	std	%d48, [FP + 192]; \
	std	%d50, [FP + 200]; \
	std	%d52, [FP + 208]; \
	std	%d54, [FP + 216]; \
	std	%d56, [FP + 224]; \
	std	%d58, [FP + 232]; \
	std	%d60, [FP + 240]; \
	std	%d62, [FP + 248];

#define	LOAD_DL_FPREGS(FP) \
	ldd	[FP], %f0; \
	ldd	[FP + 8], %f2; \
	ldd	[FP + 16], %f4; \
	ldd	[FP + 24], %f6; \
	ldd	[FP + 32], %f8; \
	ldd	[FP + 40], %f10; \
	ldd	[FP + 48], %f12; \
	ldd	[FP + 56], %f14; \
	ldd	[FP + 64], %f16; \
	ldd	[FP + 72], %f18; \
	ldd	[FP + 80], %f20; \
	ldd	[FP + 88], %f22; \
	ldd	[FP + 96], %f24; \
	ldd	[FP + 104], %f26; \
	ldd	[FP + 112], %f28; \
	ldd	[FP + 120], %f30;

#define	LOAD_DU_FPREGS(FP) \
	ldd	[FP + 128], %d32; \
	ldd	[FP + 136], %d34; \
	ldd	[FP + 144], %d36; \
	ldd	[FP + 152], %d38; \
	ldd	[FP + 160], %d40; \
	ldd	[FP + 168], %d42; \
	ldd	[FP + 176], %d44; \
	ldd	[FP + 184], %d46; \
	ldd	[FP + 192], %d48; \
	ldd	[FP + 200], %d50; \
	ldd	[FP + 208], %d52; \
	ldd	[FP + 216], %d54; \
	ldd	[FP + 224], %d56; \
	ldd	[FP + 232], %d58; \
	ldd	[FP + 240], %d60; \
	ldd	[FP + 248], %d62;

#endif /* _KERNEL */

/*
 * V9 privileged registers
 */

/*
 * Condition Codes Register (CCR)
 *
 *	|-------------------------------|
 *	|	XCC	|	ICC	|
 *	| N | Z | V | C | N | Z | V | C |
 *	|---|---|---|---|---|---|---|---|
 *	7   6   5   4   3   2   1   0
 */
#define	CCR_IC		0x01	/* 32b carry */
#define	CCR_IV		0x02	/* 32b overflow */
#define	CCR_IZ		0x04	/* 32b zero */
#define	CCR_IN		0x08	/* 32b negative */
#define	CCR_XC		0x10	/* 64b carry */
#define	CCR_XV		0x20	/* 64b overflow */
#define	CCR_XZ		0x40	/* 64b zero */
#define	CCR_XN		0x80	/* 64b negative */
#define	CCR_ICC		0x0F
#define	CCR_XCC		0xF0


/*
 * Processor State Register (PSTATE)
 *
 *   |-------------------------------------------------------------|
 *   |  IG | MG | CLE | TLE | MM | RED | PEF | AM | PRIV | IE | AG |
 *   |-----|----|-----|-----|----|-----|-----|----|------|----|----|
 *	11   10    9     8   7  6   5     4     3     2     1    0
 *
 * Note that the IG, MG, RED and AG fields are not applicable to sun4v
 * compliant processors.
 */
#ifndef GLREG
#define	PSTATE_AG	0x001		/* alternate globals */
#endif /* GLREG */

#define	PSTATE_IE	0x002		/* interrupt enable */
#define	PSTATE_PRIV	0x004		/* privileged mode */
#define	PSTATE_AM	0x008		/* use 32b address mask */
#define	PSTATE_PEF	0x010		/* fp enable */

#ifndef GLREG
#define	PSTATE_RED	0x020		/* red mode */
#endif /* GLREG */

#define	PSTATE_MM	0x0C0		/* memory model */
#define	PSTATE_TLE	0x100		/* trap little endian */
#define	PSTATE_CLE	0x200		/* current little endian */

#ifndef GLREG
#define	PSTATE_MG	0x400		/* MMU globals */
#define	PSTATE_IG	0x800		/* interrupt globals */
#endif /* GLREG */

#define	PSTATE_BITS \
"\020\014IG\013MG\012CLE\011TLE\010MM-RMO\
\07MM-PSO\06RED\05PEF\04AM\03PRIV\02IE\01AG"

/*
 * Definition of MM (Memory Mode) bit field of pstate.
 */
#define	PSTATE_MM_TSO	0x00		/* total store odering */
#define	PSTATE_MM_PSO	0x40		/* partial store odering */
#define	PSTATE_MM_RMO	0x80		/* relaxed memory ordering */


/*
 * Trap State Register (TSTATE)
 *
 *	|------------------------------------------|
 *	| GL | CCR | ASI | --- | PSTATE | -- | CWP |
 *	|----|-----|-----|-----|--------|----|-----|
 *	42 40 39 32 31 24 23 20 19	  8 7  5 4   0
 *
 * Note that the GL field is applicable to sun4v compliant processors only.
 */
#define	TSTATE_CWP_MASK		0x01F
#define	TSTATE_CWP_SHIFT	0
#define	TSTATE_PSTATE_MASK	0xFFF
#define	TSTATE_PSTATE_SHIFT	8
#define	TSTATE_ASI_MASK		0x0FF
#define	TSTATE_ASI_SHIFT	24
#define	TSTATE_CCR_MASK		0x0FF
#define	TSTATE_CCR_SHIFT	32

#ifdef GLREG
#define	TSTATE_GL_MASK		0x7
#define	TSTATE_GL_SHIFT		40
#endif /* GLREG */

/*
 * Some handy tstate macros
 */
#define	TSTATE_AG	(PSTATE_AG << TSTATE_PSTATE_SHIFT)
#define	TSTATE_IE	(PSTATE_IE << TSTATE_PSTATE_SHIFT)
#define	TSTATE_PRIV	(PSTATE_PRIV << TSTATE_PSTATE_SHIFT)
#define	TSTATE_AM	(PSTATE_AM << TSTATE_PSTATE_SHIFT)
#define	TSTATE_PEF	(PSTATE_PEF << TSTATE_PSTATE_SHIFT)
#define	TSTATE_MG	(PSTATE_MG << TSTATE_PSTATE_SHIFT)
#define	TSTATE_IG	(PSTATE_IG << TSTATE_PSTATE_SHIFT)
#define	TSTATE_CWP	TSTATE_CWP_MASK

/*
 * as is 64b, but cc is 32b, so we need this hack.
 */
#ifndef _ASM
#define	TSTATE_ICC	((long long)CCR_ICC << TSTATE_CCR_SHIFT)
#define	TSTATE_XCC	((long long)CCR_XCC << TSTATE_CCR_SHIFT)
#define	TSTATE_IC	((long long)CCR_IC << TSTATE_CCR_SHIFT)
#define	TSTATE_IV	((long long)CCR_IV << TSTATE_CCR_SHIFT)
#define	TSTATE_IN	((long long)CCR_IN << TSTATE_CCR_SHIFT)
#define	TSTATE_XV	((long long)CCR_XV << TSTATE_CCR_SHIFT)
#define	TSTATE_XZ	((long long)CCR_XZ << TSTATE_CCR_SHIFT)
#else
#define	TSTATE_ICC	(CCR_ICC << TSTATE_CCR_SHIFT)
#define	TSTATE_XCC	(CCR_XCC << TSTATE_CCR_SHIFT)
#define	TSTATE_IC	(CCR_IC << TSTATE_CCR_SHIFT)
#define	TSTATE_IV	(CCR_IV << TSTATE_CCR_SHIFT)
#define	TSTATE_IN	(CCR_IN << TSTATE_CCR_SHIFT)
#define	TSTATE_XV	(CCR_XV << TSTATE_CCR_SHIFT)
#define	TSTATE_XZ	(CCR_XZ << TSTATE_CCR_SHIFT)
#endif
#define	TSTATE_V8_UBITS (TSTATE_ICC | TSTATE_PEF)

/*
 * Initial kernel and user %tstate.
 */
#define	PTSTATE_KERN_COMMON \
	(PSTATE_PRIV | PSTATE_PEF | PSTATE_MM_TSO)

#define	TSTATE_USER_COMMON \
	(PSTATE_IE | PSTATE_PEF | PSTATE_MM_TSO)

#define	TSTATE_KERN	\
	(PTSTATE_KERN_COMMON << TSTATE_PSTATE_SHIFT)

#define	PSTATE_KERN	\
	(PTSTATE_KERN_COMMON | PSTATE_PRIV | PSTATE_IE)

#define	TSTATE_USER32	\
	(((TSTATE_USER_COMMON | PSTATE_AM) << TSTATE_PSTATE_SHIFT) | \
	    ((long long)ASI_PNF << TSTATE_ASI_SHIFT))

#define	TSTATE_USER64	\
	((TSTATE_USER_COMMON << TSTATE_PSTATE_SHIFT) | \
	    ((long long)ASI_PNF << TSTATE_ASI_SHIFT))

#define	USERMODE(x)	(!((x) & TSTATE_PRIV))

/*
 * Window State Register (WSTATE)
 *
 *   |------------|
 *   |OTHER|NORMAL|
 *   |-----|------|
 *    5	  3 2    0
 */
#define	WSTATE_BAD	0	/* unused */
#define	WSTATE_U32	1	/* 32b stack */
#define	WSTATE_U64	2	/* 64b stack */
#define	WSTATE_CLEAN32	3	/* cleanwin workaround, 32b stack */
#define	WSTATE_CLEAN64	4	/* cleanwin workaround, 64b stack */
#define	WSTATE_K32	5	/* priv 32b stack */
#define	WSTATE_K64	6	/* priv 64b stack */
#define	WSTATE_KMIX	7	/* priv mixed stack */

#define	WSTATE_CLEAN_OFFSET	2
#define	WSTATE_SHIFT	3	/* normal-to-other shift */
#define	WSTATE_MASK	7	/* mask for each set */
#define	WSTATE(o, n)	(((o) << WSTATE_SHIFT) | (n))

#define	WSTATE_USER32	WSTATE(WSTATE_BAD, WSTATE_U32)
#define	WSTATE_USER64	WSTATE(WSTATE_BAD, WSTATE_U64)
#define	WSTATE_KERN	WSTATE(WSTATE_U32, WSTATE_K64)

/*
 * Processor Interrupt Level Register (PIL)
 *
 *   |-----|
 *   | PIL |
 *   |-----|
 *    3   0
 */

/*
 * Version Register (VER)
 *
 *   |-------------------------------------------------|
 *   | manuf | impl | mask | ---- | maxtl | - | maxwin |
 *   |-------|------|------|------|-------|---|--------|
 *    63   48 47  32 31  24 23  16 15	8  7 5	4    0
 */
#define	VER_MANUF	0xFFFF000000000000
#define	VER_IMPL	0x0000FFFF00000000
#define	VER_MASK	0x00000000FF000000
#define	VER_MAXTL	0x000000000000FF00
#define	VER_MAXWIN	0x000000000000001F
#define	VER_MAXTL_SHIFT	8
#define	VER_MAXTL_MASK	(VER_MAXTL >> VER_MAXTL_SHIFT)

/*
 * Tick Register (TICK)
 *
 *   |---------------|
 *   | npt | counter |
 *   |-----|---------|
 *     63   62      0
 *
 * Note: UltraSparc III Stick register has the same layout. When
 * present, we clear it too.
 */

#define	TICK_NPT	0x8000000000000000
#define	TICK_COUNTER	0x7FFFFFFFFFFFFFFF

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PRIVREGS_H */
