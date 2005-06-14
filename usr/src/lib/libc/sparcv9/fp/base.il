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

	.inline	__mul_set,0
	.volatile
	fmuld	%f0,%f2,%f0		! compute result and leave it for return
	st	%fsr,[%sp+0x87f]
	.nonvolatile
	ld	[%sp+0x87f],%o0
	and	%o0,1,%o0
	st	%o0,[%o2]		! store eround
	.end

	.inline	__div_set,0
	.volatile
	fdivd	%f0,%f2,%f0
	st	%fsr,[%sp+0x87f]
	.nonvolatile
	ld	[%sp+0x87f],%o0
	and	%o0,1,%o0
	st	%o0,[%o2]		! store eround
	.end

	.inline	__dabs,0
	ldd	[%o0],%f0
	fabsd	%f0,%f0
	.end

	.inline	__get_ieee_flags,0
	.volatile
	st	%fsr,[%o0]
	st	%g0,[%sp+0x87f]
	ld	[%sp+0x87f],%fsr
	.nonvolatile
	.end

	.inline	__set_ieee_flags,0
	ld	[%o0],%fsr
	.end
