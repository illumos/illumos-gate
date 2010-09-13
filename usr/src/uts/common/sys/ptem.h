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
/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#ifndef _SYS_PTEM_H
#define	_SYS_PTEM_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 11.7	*/

#include <sys/termios.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * The ptem data structure used to define the global data
 * for the psuedo terminal emulation streams module
 */
struct ptem {
	tcflag_t cflags;	/* copy of c_cflags */
	mblk_t *dack_ptr;	/* preallocated mblk used to ACK disconnect */
	queue_t *q_ptr;		/* ptem read queue */
	struct winsize wsz;	/* struct to hold the windowing info. */
	unsigned short state;	/* state of ptem entry: see below */
};

/*
 * state flags
 */
#define	REMOTEMODE	0x1	/* Pty in remote mode */
#define	OFLOW_CTL	0x2	/* Outflow control on */
#define	IS_PTSTTY	0x4	/* is x/open terminal */

/*
 * Constants used to distinguish between a common function invoked
 * from the read or write side put procedures
 */
#define	RDSIDE	1
#define	WRSIDE	2

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_PTEM_H */
