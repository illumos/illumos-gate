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
/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc. */
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T   */
/*	  All Rights Reserved   */

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _IA32_SYS_PSW_H
#define	_IA32_SYS_PSW_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifndef _ASM

/* Flags Register */

typedef struct flags {
	uint_t	fl_cf	:  1,		/* carry/borrow */
			:  1,		/* reserved */
		fl_pf	:  1,		/* parity */
			:  1,		/* reserved */
		fl_af	:  1,		/* carry/borrow */
			:  1,		/* reserved */
		fl_zf	:  1,		/* zero */
		fl_sf	:  1,		/* sign */
		fl_tf	:  1,		/* trace */
		fl_if	:  1,		/* interrupt enable */
		fl_df	:  1,		/* direction */
		fl_of	:  1,		/* overflow */
		fl_iopl :  2,		/* I/O privilege level */
		fl_nt	:  1,		/* nested task */
			:  1,		/* reserved */
		fl_rf	:  1,		/* reset */
		fl_vm	:  1,		/* virtual 86 mode */
		fl_res	: 14;		/* reserved */
} flags_t;

#endif		/* !_ASM */

#define	PS_C		0x0001		/* carry bit			*/
#define	PS_MB1		0x0002		/* unused; must be 1.		*/
#define	PS_P		0x0004		/* parity bit			*/
#define	PS_AC		0x0010		/* auxiliary carry bit		*/
#define	PS_Z		0x0040		/* zero bit			*/
#define	PS_N		0x0080		/* negative bit			*/
#define	PS_T		0x0100		/* trace enable bit		*/
#define	PS_IE		0x0200		/* interrupt enable bit		*/
#define	PS_D		0x0400		/* direction bit		*/
#define	PS_V		0x0800		/* overflow bit			*/
#define	PS_IOPL		0x3000		/* I/O privilege level		*/
#define	PS_NT		0x4000		/* nested task flag		*/
#define	PS_RF		0x10000		/* restore flag			*/
#define	PS_VM		0x20000		/* virtual 86 mode flag		*/
#define	PS_ACHK		0x40000		/* alignment check enable (486) */
#define	PS_VINT		0x80000		/* virtual interrupt flag	*/
#define	PS_VINTP	0x100000	/* virtual interrupt pending	*/
#define	PS_ID		0x200000	/* ID flag			*/

#define	PS_ICC		(PS_C|PS_AC|PS_Z|PS_N)	   /* integer condition codes */

#define	FMT_FLAGS_REG				\
	"\20\26id\25vip\24vif\23ac\22vm\21rf"	\
	"\17nt\14of\13df\12if\11tf\10sf\7zf\5af\3pf\1cf"

#define	PSL_USER	0x202		/* initial user FLAGS */

/* user variable PS bits */
#define	PSL_USERMASK	(PS_ICC|PS_D|PS_T|PS_V|PS_P|PS_ACHK|PS_NT)

/* PS bits changeable by the sahf instruction */
#define	PSL_LSAHFMASK	(PS_ICC|PS_P)

/*
 * kernel flags settings
 *
 * Note that the kernel's SMAP protection relies on PS_ACHK not being present in
 * the following two definitions. See uts/intel/ia32/ml/copy.s for more
 * information on SMAP.
 */
#define	F_OFF		0x2		/* interrupts off */
#define	F_ON		0x202		/* interrupts on */

#ifndef _ASM
typedef int	psw_t;
#endif

#include <sys/tss.h>
#include <sys/segments.h>			/* selector definitions */

#define	USERMODE(cs)	((uint16_t)(cs) != KCS_SEL)

#include <sys/spl.h>

#ifdef	__cplusplus
}
#endif

#endif	/* _IA32_SYS_PSW_H */
