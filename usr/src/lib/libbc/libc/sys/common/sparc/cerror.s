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
!	Note this routine used to be called cerror, the
!	file name will not change for now. We might go
!	back to the old name.

!	.seg	"text"

#include "SYS.h"

!	.seg	"text"
	.global .cerror
	.global errno

	ENTRY(.cerror)
#ifdef PIC
	PIC_SETUP(o5)
	ld	[%o5 + errno], %g1
	st	%o0, [%g1]
#else
	sethi	%hi(errno), %g1
	st	%o0, [%g1 + %lo(errno)]
#endif
	save	%sp, -SA(MINFRAME), %sp
	call	maperror,0
	nop
	ret
	restore	%g0, -1, %o0

	SET_SIZE(.cerror)
