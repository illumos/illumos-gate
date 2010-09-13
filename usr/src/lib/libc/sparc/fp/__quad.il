!
! Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
! Use is subject to license terms.
!
! CDDL HEADER START
!
! The contents of this file are subject to the terms of the
! Common Development and Distribution License, Version 1.0 only
! (the "License").  You may not use this file except in compliance
! with the License.
!
! You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
! or http://www.opensolaris.org/os/licensing.
! See the License for the specific language governing permissions
! and limitations under the License.
!
! When distributing Covered Code, include this CDDL HEADER in each
! file and include the License file at usr/src/OPENSOLARIS.LICENSE.
! If applicable, add the following below this CDDL HEADER, with the
! fields enclosed by brackets "[]" replaced with your own identifying
! information: Portions Copyright [yyyy] [name of copyright owner]
!
! CDDL HEADER END
!
! 
! .ident	"%Z%%M%	%I%	%E% SMI"
!
! This file contains inline templates for the internal routines used
! by the quad precision emulation code for SPARC.  It should be used
! in preference to __quad.s whenever possible.

	.inline	__quad_getfsrp,1
	st	%fsr,[%o0]
	.end

	.inline	__quad_setfsrp,1
	ld	[%o0],%fsr
	.end

	.inline __quad_dp_sqrt,1
	ldd	[%o0],%f0
	fsqrtd	%f0,%f0
	.end

	.inline	__quad_faddq,3
	ldd	[%o0],%f0
	ldd	[%o0+8],%f2
	ldd	[%o1],%f4
	ldd	[%o1+8],%f6
	faddq	%f0,%f4,%f8
	std	%f8,[%o2]
	std	%f10,[%o2+8]
	.end

	.inline	__quad_fsubq,3
	ldd	[%o0],%f0
	ldd	[%o0+8],%f2
	ldd	[%o1],%f4
	ldd	[%o1+8],%f6
	fsubq	%f0,%f4,%f8
	std	%f8,[%o2]
	std	%f10,[%o2+8]
	.end

	.inline	__quad_fmulq,3
	ldd	[%o0],%f0
	ldd	[%o0+8],%f2
	ldd	[%o1],%f4
	ldd	[%o1+8],%f6
	fmulq	%f0,%f4,%f8
	std	%f8,[%o2]
	std	%f10,[%o2+8]
	.end

	.inline	__quad_fdivq,3
	ldd	[%o0],%f0
	ldd	[%o0+8],%f2
	ldd	[%o1],%f4
	ldd	[%o1+8],%f6
	fdivq	%f0,%f4,%f8
	std	%f8,[%o2]
	std	%f10,[%o2+8]
	.end

	.inline	__quad_fsqrtq,2
	ldd	[%o0],%f0
	ldd	[%o0+8],%f2
	fsqrtq	%f0,%f4
	std	%f4,[%o1]
	std	%f6,[%o1+8]
	.end

	.inline	__quad_fcmpq,3
	ldd	[%o0],%f0
	ldd	[%o0+8],%f2
	ldd	[%o1],%f4
	ldd	[%o1+8],%f6
	.volatile
	fcmpq	%f0,%f4
	st	%fsr,[%o2]
	.nonvolatile
	.end

	.inline	__quad_fcmpeq,3
	ldd	[%o0],%f0
	ldd	[%o0+8],%f2
	ldd	[%o1],%f4
	ldd	[%o1+8],%f6
	.volatile
	fcmpeq	%f0,%f4
	st	%fsr,[%o2]
	.nonvolatile
	.end

	.inline	__quad_fstoq,2
	ld	[%o0],%f0
	fstoq	%f0,%f4
	std	%f4,[%o1]
	std	%f6,[%o1+8]
	.end

	.inline	__quad_fdtoq,2
	ldd	[%o0],%f0
	fdtoq	%f0,%f4
	std	%f4,[%o1]
	std	%f6,[%o1+8]
	.end

	.inline	__quad_fqtoi,2
	ldd	[%o0],%f0
	ldd	[%o0+8],%f2
	fqtoi	%f0,%f4
	st	%f4,[%o1]
	.end

	.inline	__quad_fqtos,2
	ldd	[%o0],%f0
	ldd	[%o0+8],%f2
	fqtos	%f0,%f4
	st	%f4,[%o1]
	.end

	.inline	__quad_fqtod,2
	ldd	[%o0],%f0
	ldd	[%o0+8],%f2
	fqtod	%f0,%f4
	std	%f4,[%o1]
	.end

!	only used in V9 code
	.inline	__quad_fqtox,2
	ldd	[%o0],%f0
	ldd	[%o0+8],%f2
	fqtox	%f0,%f4
	std	%f4,[%o1]
	.end
