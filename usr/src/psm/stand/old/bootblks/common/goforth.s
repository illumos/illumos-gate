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
! Copyright 2000 Sun Microsystems, Inc.  All rights reserved.
! Use is subject to license terms.
!
! #ident	"%Z%%M%	%I%	%E% SMI"
!

#include <sys/asm_linkage.h>

#if	defined(lint)
void
goforth(struct sunromvec *romp, caddr_t start, caddr_t end)
{ return; }
#endif

	.text
!
! goforth(struct sunromvec *romp,
!	char *start, char *end)
!
	ENTRY(goforth)
	save	%sp, -SA(MINFRAME), %sp
	ld	[%i0 + 0x7c], %l2	! Address of romp->v_interpret
	set	byteload, %i1
	sethi	%hi(forthblock), %i2
	or	%i2, %lo(forthblock), %i2
v2:
	!
	! op_interpret(cmd, 1, forthblock);
	!
	mov	%i1, %o0
	mov	%i2, %o2

	call	%l2
	mov	1, %o1
/*NOTREACHED*/

byteload:
	.asciz	"byte-load"
	.align	4
