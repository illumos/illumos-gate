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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * These are functions corresponding to some which used to be inline, with Sun
 * Studio.  Someone may want to make them into gcc inline asm.
 */

#include <sys/asm_linkage.h>

	ENTRY_NP(__quad_getfsrp)
	retl
	st	%fsr,[%o0]
	SET_SIZE(__quad_getfsrp)

	ENTRY_NP(__quad_setfsrp)
	retl
	ld	[%o0],%fsr
	SET_SIZE(__quad_setfsrp)

	ENTRY_NP(__quad_dp_sqrt)
	ldd	[%o0],%f0
	fsqrtd	%f0,%f0
	retl
	nop
	SET_SIZE(__quad_dp_sqrt)

	ENTRY_NP(__quad_faddq)
	ldd	[%o0],%f0
	ldd	[%o0+8],%f2
	ldd	[%o1],%f4
	ldd	[%o1+8],%f6
	faddq	%f0,%f4,%f8
	std	%f8,[%o2]
	retl
	std	%f10,[%o2+8]
	SET_SIZE(__quad_faddq)

	ENTRY_NP(__quad_fsubq)
	ldd	[%o0],%f0
	ldd	[%o0+8],%f2
	ldd	[%o1],%f4
	ldd	[%o1+8],%f6
	fsubq	%f0,%f4,%f8
	std	%f8,[%o2]
	retl
	std	%f10,[%o2+8]
	SET_SIZE(__quad_fsubq)

	ENTRY_NP(__quad_fmulq)
	ldd	[%o0],%f0
	ldd	[%o0+8],%f2
	ldd	[%o1],%f4
	ldd	[%o1+8],%f6
	fmulq	%f0,%f4,%f8
	std	%f8,[%o2]
	retl
	std	%f10,[%o2+8]
	SET_SIZE(__quad_fmulq)

	ENTRY_NP(__quad_fdivq)
	ldd	[%o0],%f0
	ldd	[%o0+8],%f2
	ldd	[%o1],%f4
	ldd	[%o1+8],%f6
	fdivq	%f0,%f4,%f8
	std	%f8,[%o2]
	retl
	std	%f10,[%o2+8]
	SET_SIZE(__quad_fdivq)

	ENTRY_NP(__quad_fsqrtq)
	ldd	[%o0],%f0
	ldd	[%o0+8],%f2
	fsqrtq	%f0,%f4
	std	%f4,[%o1]
	retl
	std	%f6,[%o1+8]
	SET_SIZE(__quad_fsqrtq)

	ENTRY_NP(__quad_fcmpq)
	ldd	[%o0],%f0
	ldd	[%o0+8],%f2
	ldd	[%o1],%f4
	ldd	[%o1+8],%f6
	fcmpq	%f0,%f4
	retl
	st	%fsr,[%o2]
	SET_SIZE(__quad_fcmpq)

	ENTRY_NP(__quad_fcmpeq)
	ldd	[%o0],%f0
	ldd	[%o0+8],%f2
	ldd	[%o1],%f4
	ldd	[%o1+8],%f6
	fcmpeq	%f0,%f4
	retl
	st	%fsr,[%o2]
	SET_SIZE(__quad_fcmpeq)

	ENTRY_NP(__quad_fstoq)
	ld	[%o0],%f0
	fstoq	%f0,%f4
	std	%f4,[%o1]
	retl
	std	%f6,[%o1+8]
	SET_SIZE(__quad_fstoq)

	ENTRY_NP(__quad_fdtoq)
	ldd	[%o0],%f0
	fdtoq	%f0,%f4
	std	%f4,[%o1]
	retl
	std	%f6,[%o1+8]
	SET_SIZE(__quad_fdtoq)

	ENTRY_NP(__quad_fqtoi)
	ldd	[%o0],%f0
	ldd	[%o0+8],%f2
	fqtoi	%f0,%f4
	retl
	st	%f4,[%o1]
	SET_SIZE(__quad_fqtoi)

	ENTRY_NP(__quad_fqtos)
	ldd	[%o0],%f0
	ldd	[%o0+8],%f2
	fqtos	%f0,%f4
	retl
	st	%f4,[%o1]
	SET_SIZE(__quad_fqtos)

	ENTRY_NP(__quad_fqtod)
	ldd	[%o0],%f0
	ldd	[%o0+8],%f2
	fqtod	%f0,%f4
	retl
	std	%f4,[%o1]
	SET_SIZE(__quad_fqtod)

#if defined(__sparcv9)
	ENTRY_NP(__quad_fqtox)
	ldd	[%o0],%f0
	ldd	[%o0+8],%f2
	fqtox	%f0,%f4
	retl
	std	%f4,[%o1]
	SET_SIZE(__quad_fqtox)
#endif
