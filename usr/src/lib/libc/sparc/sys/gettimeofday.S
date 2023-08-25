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

/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/

	.file	"gettimeofday.s"

/*
 * C library -- gettimeofday
 * int gettimeofday (struct timeval *tp);
 */

#include "SYS.h"

	ANSI_PRAGMA_WEAK(gettimeofday,function)

/*
 * The interface below calls the trap (0x27) to get the timestamp in
 * secs and nsecs. It than converts the nsecs value into usecs before
 * it returns.
 *
 * The algorithm used to perform the division by 1000 is based upon
 * algorithms for division based upon multiplication by invariant
 * integers.  Relevant sources for these algorithms are:
 *
 * Granlund, T.; Montgomery, P.L.: "Division by Invariant Integers using
 * Multiplication". SIGPLAN Notices, Vol. 29, June 1994, page 61.
 *
 * Magenheimer, D.J.; et al: "Integer Multiplication and Division on the HP
 * Precision Architecture". IEEE Transactions on Computers, Vol 37, No. 8,
 * August 1988, page 980.
 *
 * Steele G.; Warren H.: Hacker's Delight. 2002 Pearson Education, Ch 10
 *
 */

	ENTRY(gettimeofday)
	brz,pn	%o0, 1f
	mov	%o0, %o5
	SYSFASTTRAP(GETHRESTIME)
	stn	%o0, [%o5]
	sethi	%hi(0x10624DD3), %o2
	or	%o2, %lo(0x10624DD3), %o2
	mulx	%o1, %o2, %o2
	srlx	%o2, 38, %o2
	stn	%o2, [%o5 + CLONGSIZE]
1:	RETC
	SET_SIZE(gettimeofday)
