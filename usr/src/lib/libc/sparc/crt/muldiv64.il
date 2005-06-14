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
!	ident	"%Z%%M%	%I%	%E% SMI"

! Reorder args from .umul to put them into 'long long' ordering

	.inline	__umul32x32to64,8
	call	.umul,2
	nop
	mov	%o0, %o2
	mov	%o1, %o0
	mov	%o2, %o1
	.end

! Generates divide-by-zero trap from C

	.inline	__raise_divide_by_zero,8
	ta	2
	clr	%o0
	clr	%o1
	.end
