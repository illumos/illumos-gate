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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_PFMOD_H
#define	_SYS_PFMOD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Ioctls.
 */
#define	PFIOC		('P' << 8)
#define	PFIOCSETF	(PFIOC|1)	/* replace current packet filter */

#define	ENMAXFILTERS	255		/* maximum filter short words */
#define	PF_MAXFILTERS	2047		/* max short words for newpacketfilt */

/*
 * filter structure for SETF
 */
struct packetfilt {
	uchar_t	Pf_Priority;			/* priority of filter */
	uchar_t Pf_FilterLen;			/* length of filter cmd list */
	ushort_t Pf_Filter[ENMAXFILTERS];	/* filter command list */
};

/*
 * The extended packet filter structure
 */
struct Pf_ext_packetfilt {
	uchar_t	Pf_Priority;			/* priority of filter */
	unsigned int Pf_FilterLen;		/* length of filter cmd list */
	ushort_t Pf_Filter[PF_MAXFILTERS];	/* filter command list */
};

/*
 * We now allow specification of up to MAXFILTERS (short) words of a filter
 * command list to be applied to incoming packets to determine if
 * those packets should be given to a particular open ethernet file.
 * Alternatively, PF_MAXFILTERS and Pf_ext_packetfilt structure can be
 * used in case even bigger filter command list is needed.
 *
 * In this context, "word" means a short (16-bit) integer.
 *
 * The filter command list is specified using ioctl().  Each filter command
 * list specifies a sequence of actions that leaves a boolean value on the
 * top of an internal stack.  There is also an offset register which is
 * initialized to zero.  Each word of the command list specifies an action
 * from the set {PUSHLIT, PUSHZERO, PUSHWORD+N, LOAD_OFFSET, BRTR, BRFL, POP}
 * (see #defines below for definitions), and a binary operator from the set
 * {EQ, LT, LE, GT, GE, AND, OR, XOR} which operates on the top two elements
 * of the stack and replaces them with its result.  The special action NOPUSH
 * and the special operator NOP can be used to only perform the binary
 * operation or to only push a value on the stack.
 *
 * If the final value of the filter operation is true, then the packet is
 * accepted for the open file which specified the filter.
 */

/* these must sum to sizeof (ushort_t)! */
#define	ENF_NBPA	10			/* # bits / action */
#define	ENF_NBPO	 6			/* # bits / operator */

/* binary operators */
#define	ENF_NOP		(0 << ENF_NBPA)
#define	ENF_EQ		(1 << ENF_NBPA)
#define	ENF_LT		(2 << ENF_NBPA)
#define	ENF_LE		(3 << ENF_NBPA)
#define	ENF_GT		(4 << ENF_NBPA)
#define	ENF_GE		(5 << ENF_NBPA)
#define	ENF_AND		(6 << ENF_NBPA)
#define	ENF_OR		(7 << ENF_NBPA)
#define	ENF_XOR		(8 << ENF_NBPA)
#define	ENF_COR		(9 << ENF_NBPA)
#define	ENF_CAND	(10 << ENF_NBPA)
#define	ENF_CNOR	(11 << ENF_NBPA)
#define	ENF_CNAND	(12 << ENF_NBPA)
#define	ENF_NEQ		(13 << ENF_NBPA)

/* stack actions */
#define	ENF_NOPUSH	0
#define	ENF_PUSHLIT	1  /* Push the next word on the stack */
#define	ENF_PUSHZERO	2  /* Push 0 on the stack */
#define	ENF_PUSHONE	3  /* Push 1 on the stack */
#define	ENF_PUSHFFFF	4  /* Push 0xffff on the stack */
#define	ENF_PUSHFF00	5  /* Push 0xff00 on the stack */
#define	ENF_PUSH00FF	6  /* Push 0x00ff on the stack */
#define	ENF_LOAD_OFFSET	7  /* Load the next word into the offset register */
#define	ENF_BRTR	8  /* Branch if the stack's top element is true */
#define	ENF_BRFL	9  /* Branch if the stack's top element is false */
#define	ENF_POP		10 /* Pop the top element from the stack */
#define	ENF_PUSHWORD	16

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PFMOD_H */
