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
 * Copyright (c) 1986 by Sun Microsystems, Inc.
 */

#ifndef _SYS_FSR_H
#define	_SYS_FSR_H

#pragma ident	"%Z%%M%	%I%	%E% SMI" /* from SunOS psl.h 1.2 */

#ifdef	__cplusplus
extern "C" {
#endif


/*
 * Floating Point State Register (FSR)
 *
 * Notes:
 *	On v9 cpus, the fsr is 64b.
 *	On v7 and v8 cpus, it is 32b.
 *
 *	FCC1 thru FCC3 are v9 only.
 *	RP is v7 only (v8 dropped extended precision).
 *	PR was dropped before v7.
 *
 *   |------------------------------------------------------------------------|
 *   |				---			 | FCC3 | FCC2 | FCC1 |
 *   |---------------------------------------------------|------|------|------|
 *    63						38 37  36 35  34 33  32
 *
 *   |------------------------------------------------------------------------|
 *   |  RD |  RP | TEM | NS | --- | VER | FTT | QNE | PR | FCC0 | AEXC | CEXC |
 *   |-----|-----|-----|----|-----|-----|-----|-----|----|------|------|------|
 *    31 30 29 28 27 23  22  21 20 19 17 16 14  13    12  11  10 9    5 4    0
 */
#define	FSR_CEXC	0x0000001f	/* Current Exception */
#define	FSR_AEXC	0x000003e0	/* ieee accrued exceptions */
#define	FSR_FCC		0x00000c00	/* Floating-point Condition Codes */
#define	FSR_PR		0x00001000	/* Partial Remainder */
#define	FSR_QNE		0x00002000	/* Queue not empty */
#define	FSR_FTT		0x0001c000	/* Floating-point Trap Type */
#define	FSR_VER		0x000e0000	/* fpu version */
#define	FSR_TEM		0x0f800000	/* ieee Trap Enable Mask */
#define	FSR_RP		0x30000000	/* Rounding Precision */
#define	FSR_RD		0xc0000000	/* Rounding Direction */
#define	FSR_VER_SHIFT	17		/* version shift */
#define	FSR_FCC1	0x00000003	/* fp condition codes set #1 */
#define	FSR_FCC2	0x0000000C	/* fp condition codes set #2 */
#define	FSR_FCC3	0x00000030	/* fp condition codes set #3 */

/*
 * Definition of CEXC (Current EXCeption) bit field of fsr
 */
#define	FSR_CEXC_NX	0x00000001	/* inexact */
#define	FSR_CEXC_DZ	0x00000002	/* divide-by-zero */
#define	FSR_CEXC_UF	0x00000004	/* underflow */
#define	FSR_CEXC_OF	0x00000008	/* overflow */
#define	FSR_CEXC_NV	0x00000010	/* invalid */

/*
 * Definition of AEXC (Accrued EXCeption) bit field of fsr
 */
#define	FSR_AEXC_NX	(0x1 << 5)	/* inexact */
#define	FSR_AEXC_DZ	(0x2 << 5)	/* divide-by-zero */
#define	FSR_AEXC_UF	(0x4 << 5)	/* underflow */
#define	FSR_AEXC_OF	(0x8 << 5)	/* overflow */
#define	FSR_AEXC_NV	(0x10 << 5)	/* invalid */

/*
 * Definition of FTT (Floating-point Trap Type) field within the FSR
 */
#define	FTT_NONE	0		/* no exceptions */
#define	FTT_IEEE	1		/* IEEE exception */
#define	FTT_UNFIN	2		/* unfinished fpop */
#define	FTT_UNIMP	3		/* unimplemented fpop */
#define	FTT_SEQ		4		/* sequence error */
#define	FTT_ALIGN	5	/* alignment, by software convention */
#define	FTT_DFAULT	6	/* data fault, by software convention */
#define	FSR_FTT_SHIFT	14	/* shift needed to justify ftt field */
#define	FSR_FTT_IEEE	(FTT_IEEE   << FSR_FTT_SHIFT)
#define	FSR_FTT_UNFIN	(FTT_UNFIN  << FSR_FTT_SHIFT)
#define	FSR_FTT_UNIMP	(FTT_UNIMP  << FSR_FTT_SHIFT)
#define	FSR_FTT_SEQ	(FTT_SEQ    << FSR_FTT_SHIFT)
#define	FSR_FTT_ALIGN	(FTT_ALIGN  << FSR_FTT_SHIFT)
#define	FSR_FTT_DFAULT	(FTT_DFAULT << FSR_FTT_SHIFT)

/*
 * Definition of TEM (Trap Enable Mask) bit field of fsr
 */
#define	FSR_TEM_NX	(0x1 << 23)	/* inexact */
#define	FSR_TEM_DZ	(0x2 << 23)	/* divide-by-zero */
#define	FSR_TEM_UF	(0x4 << 23)	/* underflow */
#define	FSR_TEM_OF	(0x8 << 23)	/* overflow */
#define	FSR_TEM_NV	(0x10 << 23)	/* invalid */

/*
 * Definition of RP (Rounding Precision) field of fsr
 */
#define	RP_DBLEXT	0		/* double-extended */
#define	RP_SINGLE	1		/* single */
#define	RP_DOUBLE	2		/* double */
#define	RP_RESERVED	3		/* unused and reserved */

/*
 * Definition of RD (Rounding Direction) field of fsr
 */
#define	RD_NEAR		0		/* nearest or even if tie */
#define	RD_ZER0		1		/* to zero */
#define	RD_POSINF	2		/* positive infinity */
#define	RD_NEGINF	3		/* negative infinity */


/*
 * Floating Point Registers State (FPRS)
 *	(For V9 only)
 *
 *   |---------------|
 *   | FEF | DU | DL |
 *   |-----|----|----|
 *      2    1     0
 */
#define	FPRS_DL		0x1	/* dirty lower */
#define	FPRS_DU		0x2	/* dirty upper */
#define	FPRS_FEF	0x4	/* enable fp */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_FSR_H */
