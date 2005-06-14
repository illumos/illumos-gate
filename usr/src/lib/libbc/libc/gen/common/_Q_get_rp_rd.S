!
! #ident	"%Z%%M%	%I%	%E% SMI"
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

#include "SYS.h"

        ENTRY(_Q_get_rp_rd)
	.global fp_precision, fp_direction
__Q_get_rp_rd:
#ifdef PIC
	PIC_SETUP(o5)
	ld     [%o5+fp_direction],%o3
#else
	set     fp_direction,%o3
#endif
	set     0xc0000000,%o4          ! mask of rounding direction bits
        st      %fsr,[%sp+0x44]
        ld      [%sp+0x44],%o0          ! o0 = fsr
        and     %o0,%o4,%o1
        srl     %o1,30,%o1
	st	%o1,[%o3]
#ifdef PIC
	ld     [%o5+fp_precision],%o3
#else
	set     fp_precision,%o3
#endif
	set     0x30000000,%o4
	and     %o0,%o4,%o1
	srl     %o1,28,%o1
        retl
	st	%o1,[%o3]
        SET_SIZE(_Q_get_rp_rd)
