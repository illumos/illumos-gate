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
 * Copyright 1992 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

!	.seg	"data"
!	.asciz ident	"%Z%%M%	%I%	%E% SMI"
	.seg	".text"

	.file	"ffs.s"

#include <sun4/asm_linkage.h>

	ENTRY(ffs)
	tst	%o0		! if zero, done
	bz	2f
	clr	%o1		! delay slot, return zero if no bit set
1:
	inc	%o1		! bit that will get checked
	btst	1, %o0
	be	1b		! if bit is zero, keep checking
	srl	%o0, 1, %o0	! shift input right until we hit a 1 bit
2:
	retl
	mov	%o1, %o0	! return value is in o1
	SET_SIZE(ffs)
