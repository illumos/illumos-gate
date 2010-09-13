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

	.file	"fpgetsticky.s"

#include "SYS.h"

	ANSI_PRAGMA_WEAK(fpgetsticky,function)

	ENTRY(fpgetsticky)
	add	%sp, -SA(MINFRAME), %sp	! get an additional word of storage
	set	0x000003e0, %o4		! mask of accrued exception bits
	st	%fsr, [%sp+STACK_BIAS+ARGPUSH]	! get fsr value
	ld	[%sp+STACK_BIAS+ARGPUSH], %o0	! load into register
	and	%o0, %o4, %o0		! mask off bits of interest
	srl	%o0, 5, %o0		! return accrued exception value
	retl
	add	%sp, SA(MINFRAME), %sp	! reclaim stack space

	SET_SIZE(fpgetsticky)
