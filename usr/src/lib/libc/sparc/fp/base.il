! .ident	"%Z%%M%	%I%	%E% SMI"
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

	.inline	__mul_set,3
	std	%o0,[%sp+0x48]		! save x
	ldd	[%sp+0x48],%f0
	std	%o2,[%sp+0x50]		! save y
	ldd	[%sp+0x50],%f2
	.volatile
	fmuld	%f0,%f2,%f0		! compute result and leave it for return
	st	%fsr,[%sp+0x44]
	.nonvolatile
	ld	[%sp+0x44],%o0
	and	%o0,1,%o0
	st	%o0,[%o4]		! store eround
	.end

	.inline	__div_set,3
	std	%o0,[%sp+0x48]		! save x
	ldd	[%sp+0x48],%f0
	std	%o2,[%sp+0x50]		! save y
	ldd	[%sp+0x50],%f2
	.volatile
	fdivd	%f0,%f2,%f0		! compute result and leave it for return
	st	%fsr,[%sp+0x44]
	.nonvolatile
	ld	[%sp+0x44],%o0
	and	%o0,1,%o0
	st	%o0,[%o4]		! store eround
	.end

        .inline __dabs,2
	ld	[%o0],%f0
	ld	[%o0+4],%f1
	fabss	%f0,%f0
        .end

	.inline	__get_ieee_flags,1
	.volatile
	st	%fsr,[%o0]
	st	%g0,[%sp+0x44]
	ld	[%sp+0x44],%fsr
	.nonvolatile
	.end

	.inline	__set_ieee_flags,1
	ld	[%o0],%fsr
	.end
