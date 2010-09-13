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
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Terminal definitions related to underlying hardware.
 */

#ifndef	__sys_ttydev_h
#define	__sys_ttydev_h

/*
 * Speeds
 */
#define	B0	0
#define	B50	1
#define	B75	2
#define	B110	3
#define	B134	4
#define	B150	5
#define	B200	6
#define	B300	7
#define	B600	8
#define	B1200	9
#define	B1800	10
#define	B2400	11
#define	B4800	12
#define	B9600	13
#define	B19200	14
#define	B38400	15
#ifndef	_POSIX_SOURCE
#define	EXTA	14
#define	EXTB	15
#endif

#ifdef	KERNEL
/*
 * Hardware bits.
 * SHOULD NOT BE HERE.
 */
#define	DONE	0200
#define	IENABLE	0100

/*
 * Modem control commands.
 */
#define	DMSET		0
#define	DMBIS		1
#define	DMBIC		2
#define	DMGET		3
#endif	/* KERNEL */

#endif	/* !__sys_ttydev_h */
