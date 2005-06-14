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

/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	  All Rights Reserved  	*/

#ifndef _SYS_PIC_H
#define	_SYS_PIC_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/avintr.h>

#ifdef	__cplusplus
extern "C" {
#endif

/* Definitions for 8259 Programmable Interrupt Controller */

#define	PIC_NEEDICW4	0x01		/* ICW4 needed */
#define	PIC_ICW1BASE	0x10		/* base for ICW1 */
#define	PIC_LTIM	0x08		/* level-triggered mode */
#define	PIC_86MODE	0x01		/* MCS 86 mode */
#define	PIC_AUTOEOI	0x02		/* do auto eoi's */
#define	PIC_SLAVEBUF	0x08		/* put slave in buffered mode */
#define	PIC_MASTERBUF	0x0C		/* put master in buffered mode */
#define	PIC_SPFMODE	0x10		/* special fully nested mode */
#define	PIC_READISR	0x0B		/* Read the ISR */
#define	PIC_READIRR	0x0A		/* Read the IRR */
#define	PIC_NSEOI	0x20		/* Non-specific EOI command */
#define	PIC_SEOI	0x60		/* specific EOI command */
#define	PIC_SEOI_LVL7	(PIC_SEOI | 0x7)	/* specific EOI for level 7 */

#if defined(__i386) || defined(__amd64)
#define	PIC_VECTBASE	0x20		/* Vectors for external interrupts */
					/* start at 32. */
#endif	/* __i386 || __amd64 */

/*
 * Interrupt configuration information specific to a particular computer.
 * These constants are used to initialize tables in modules/pic/space.c.
 * NOTE: The master pic must always be pic zero.
 */

#define	NPIC		2		/* 2 PICs */
/* Port addresses */
#define	MCMD_PORT	0x20		/* master command port */
#define	MIMR_PORT	0x21		/* master intr mask register port */
#define	SCMD_PORT	0xA0		/* slave command port */
#define	SIMR_PORT	0xA1		/* slave intr mask register port */
#define	MASTERLINE	0x02		/* slave on IR2 of master PIC */
#define	SLAVEBASE	8		/* slave IR0 interrupt number */
#define	PICBUFFERED	0		/* PICs not in buffered mode */

struct standard_pic {
	short c_npic;
	uchar_t c_curmask[NPIC];
	uchar_t c_iplmask[MAXIPL*NPIC];
};

#define	CLOCK_VECTOR	0 	/* line at which clock interrupt comes */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_PIC_H */
