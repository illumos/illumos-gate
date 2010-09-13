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
!	"%Z%%M%	%I%	%E% SMI"
!	Copyright (c) 1986 by Sun Microsystems, Inc.
!
!	.seg	"text"

	.file	"sbrk.s"

#include "SYS.h"
#include <sys/syscall.h>

#define ALIGNSIZE	8

	.global	.curbrk
	.type   .curbrk,#object
	.size	.curbrk,4

	.global end
	.section ".data"
	.align	4
.curbrk:	
	.word	end

	ENTRY(sbrk)
	add	%o0, (ALIGNSIZE-1), %o0	! round up request to align size
	andn	%o0, (ALIGNSIZE-1), %o0
#ifdef PIC
	PIC_SETUP(o5)
	ld	[%o5 + .curbrk], %g1
	ld	[%g1], %o3
#else
	sethi	%hi(.curbrk), %o2
	ld	[%o2 + %lo(.curbrk)], %o3
#endif
	add	%o3, (ALIGNSIZE-1), %o3	! round up .curbrk to align size
	andn	%o3, (ALIGNSIZE-1), %o3
	add	%o3, %o0, %o0		! new break setting = request + .curbrk
	mov	%o0, %o4		! save it
	mov	SYS_brk, %g1
	t	8
	CERROR(o5)
#ifdef PIC
	PIC_SETUP(o5)
	ld	[%o5 + .curbrk], %g1
	st	%o4, [%g1]
#else
	st	%o4, [%o2 + %lo(.curbrk)] ! store new break in .curbrk
#endif
	retl
	mov	%o3, %o0		! return old break
	SET_SIZE(sbrk)
