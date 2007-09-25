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
/*	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.	*/
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989, 1990 AT&T	*/
/*	All Rights Reserved	*/

/*
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_PIT_H
#define	_SYS_PIT_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

/* Definitions for 8254 Programmable Interrupt Timer ports on AT 386 */
#define	PITCTR0_PORT	0x40		/* counter 0 port */
#define	PITCTR1_PORT	0x41		/* counter 1 port */
#define	PITCTR2_PORT	0x42		/* counter 2 port */
#define	PITCTL_PORT	0x43		/* PIT control port */
#define	PITAUX_PORT	0x61		/* PIT auxiliary port */
#define	SANITY_CTR0	0x48		/* sanity timer counter */
#define	SANITY_CTL	0x4B		/* sanity control word */
#define	SANITY_CHECK	0x461		/* bit 7 set if sanity timer went off */
#define	FAILSAFE_NMI	0x80		/* to test if sanity timer went off */
#define	ENABLE_SANITY	0x04		/* Enables sanity clock NMI ints */
#define	RESET_SANITY	0x00		/* resets sanity NMI interrupt */

/* PIT Status Byte */

#define	PITSTAT_OUTPUT	7		/* OUTPUT status bit */
#define	PITSTAT_NULLCNT	6		/* NULL COUNT status bit */

/* Definitions for 8254 commands */

#define	PIT_READBACK	0xc0		/* read-back command */
#define	PIT_READBACKC0	0x02		/* enable read-back for counter 0 */

/* Following are used for Timer 0 */
#define	PIT_C0		0x00		/* select counter 0 */
#define	PIT_LOADMODE	0x30		/* load least significant byte */
					/* followed by most significant byte */
#define	PIT_NDIVMODE	0x04		/* divide by N counter */
#define	PIT_SQUAREMODE	0x06		/* square-wave mode */
#define	PIT_ENDSIGMODE	0x00		/* assert OUT at end-of-count mode */

/* Used for Timer 1. Used for delay calculations in countdown mode */
#define	PIT_C1		0x40		/* select counter 1 */
#define	PIT_READMODE	0x30		/* read or load least significant */
					/* byte followed by most significant */
#define	PIT_RATEMODE	0x06		/* square-wave mode for USART */

#define	PIT_C2		0x80		/* select counter 2 */

#define	SANITY_NUM	0xFFFF		/* Sanity timer fires every .2 secs */
/* bits used in auxiliary control port for timer 2 */
#define	PITAUX_GATE2	0x01		/* aux port, PIT gate 2 input */
#define	PITAUX_OUT2	0x02		/* aux port, PIT clock out 2 enable */
#define	PIT_HZ		1193182		/* 8254's cycles per second */

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_PIT_H */
