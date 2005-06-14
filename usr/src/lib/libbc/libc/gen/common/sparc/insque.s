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

	.file	"insque.s"

#include <sun4/asm_linkage.h>

/*
 * insque(entryp, predp)
 *
 * Insert entryp after predp in a doubly linked list.
 */
	ENTRY(insque)
	ld	[%o1], %g1		! predp->forw
	st	%o1, [%o0 + 4]		! entryp->back = predp
	st	%g1, [%o0]		! entryp->forw =  predp->forw
	st	%o0, [%o1]		! predp->forw = entryp
	retl
	st	%o0, [%g1 + 4]		! predp->forw->back = entryp
	SET_SIZE(insque)
