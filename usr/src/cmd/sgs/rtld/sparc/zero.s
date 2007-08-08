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
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Routine to zero out a section of memory (the tail end of the data segment
 * up to a page boundary).  First nibble off any bytes up to the first double
 * aligned word, and then clear doubles until the byte count is zero.  Note,
 * this assumes the count specified has been rounded to end on a double word
 * boundary.
 *
 *	%o0 = addr, %o1 = len
 */
#if	defined(lint)

#include	<sys/types.h>

void
zero(caddr_t addr, size_t len)
{
	while (len-- > 0)
		*addr++ = 0;
}

#else

#include	<sys/asm_linkage.h>

	.file	"zero.s"

	ENTRY(zero)
	tst	%o1		! Have we any count at all?
	ba	3f		! Go find out,
	clr	%g1		!   but prepare for long loop

! Byte clearing loop

0:
	inc	%o0		! Bump address
	deccc	%o1		! Decrement count
3:
	bz	1f		! If no count left, exit
	andcc	%o0, 7, %g0	! Is the address less than double-word aligned?
	bnz,a	0b		! Branch if so
	clrb	[%o0]		!   but clear the current byte anyway

! Double clearing loop

2:
	std	%g0, [%o0]	! Clear next 8 bytes
	subcc	%o1, 8, %o1	! Decrement count
	bnz	2b		! Branch if any left
	inc	8, %o0		!   but always increment address by 8
1:
	retl			! Go home
	nop
	SET_SIZE(zero)
#endif
