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
/*	Copyright (c) 1988 AT&T	*/
/*	  All Rights Reserved	*/


/*	Copyright (c) 1989 by Sun Microsystems, Inc.		*/

.ident	"%Z%%M%	%I%	%E% SMI"	/* SVr4.0 1.11	*/

	.file	"fpgetrnd.s"

#include <sys/asm_linkage.h>

	ANSI_PRAGMA_WEAK(fpgetround,function)

#include "synonyms.h"

	ENTRY(fpgetround)
	add	%sp, -SA(MINFRAME), %sp	! get an additional word of storage
	st	%fsr, [%sp+STACK_BIAS+ARGPUSH]	! get fsr value
	ld	[%sp+STACK_BIAS+ARGPUSH], %o0	! load into register
	srl	%o0, 30, %o0		! return round control value
	retl
	add	%sp, SA(MINFRAME), %sp	! reclaim stack space

	SET_SIZE(fpgetround)
