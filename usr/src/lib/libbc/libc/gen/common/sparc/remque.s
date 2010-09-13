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
 * Copyright 1990 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

!	.seg	"data"
!	.asciz ident	"%Z%%M%	%I%	%E% SMI"
!	.seg	"text"

	.file	"remque.s"

#include <sun4/asm_linkage.h>

/*
 * remque(entryp)
 *
 * Remove entryp from a doubly linked list
 */
	ENTRY(remque)
	ld	[%o0], %g1		! entryp->forw
	ld	[%o0 + 4], %g2		! entryp->back
	st	%g1, [%g2]		! entryp->back = entryp->forw
	retl
	st	%g2, [%g1 + 4]		! entryp->forw = entryp->back
	SET_SIZE(remque)
