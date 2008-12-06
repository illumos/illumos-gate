!
! Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
! Use is subject to license terms.
!
! CDDL HEADER START
!
! The contents of this file are subject to the terms of the
! Common Development and Distribution License (the "License").
! You may not use this file except in compliance with the License.
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
! In-line functions for sparc kernels.
!

! return current thread pointer

	.inline	threadp,0
	.register %g7, #scratch
	mov	%g7, %o0
	.end

! return caller

	.inline	caller,0
	mov	%i7, %o0
	.end

! return callee

	.inline	callee,0
	mov	%o7, %o0
	.end

! needed by krtld

	.inline doflush,0
	andn	%o0, 3, %o0
	flush	%o0
	.end

! prefetch 64 bytes into L2-cache

	.inline	prefetch64,8
	prefetch [%o0], #n_writes
	.end
