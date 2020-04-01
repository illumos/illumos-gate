/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
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
 * Copyright 1998 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/param.h>
#include <sys/errno.h>
#include <sys/asm_linkage.h>
#include <sys/vtrace.h>
#include <sys/machthread.h>
#include <sys/clock.h>
#include <sys/asi.h>
#include <sys/fsr.h>
#include <sys/privregs.h>
#include <sys/pte.h>
#include <sys/mmu.h>
#include <sys/spitregs.h>

#include "assym.h"

#define	TT_HSM	0x99

!
! Move a single cache line of data.  Survive UE and CE on the read
!
! i0 = src va
! i1 = dst va
! i2 = line count
! i3 = line size
! i4 = cache of fpu state
!
	ENTRY(ac_blkcopy)

	! TODO: can we safely SAVE here
	save	%sp, -SA(MINFRAME + 2*64), %sp

	! XXX do we need to save the state of the fpu?
	rd	%fprs, %i4
	btst	(FPRS_DU|FPRS_DL|FPRS_FEF), %i4

	! always enable FPU
	wr	%g0, FPRS_FEF, %fprs

	bz,a	1f
	 nop

	! save in-use fpregs on stack
	membar	#Sync
	add	%fp, STACK_BIAS - 81, %o2
	and	%o2, -64, %o2
	stda	%d0, [%o2]ASI_BLK_P
	membar	#Sync

1:
	brz,pn	%i2, 2f				! while (linecount) {
	 nop
	ldda	[%i0]ASI_BLK_P, %d0		! *dst = *src;
	membar	#Sync
	stda	%d0, [%i1]ASI_BLK_COMMIT_P
	membar	#Sync

	add	%i0, %i3, %i0			! dst++, src++;
	add	%i1, %i3, %i1

	ba	1b				! linecount-- }
	 dec	%i2

2:
	membar	#Sync

	! restore fp to the way we got it
	btst	(FPRS_DU|FPRS_DL|FPRS_FEF), %i4
	bz,a	3f
	 nop

	! restore fpregs from stack
	add	%fp, STACK_BIAS - 81, %o2
	and	%o2, -64, %o2
	ldda	[%o2]ASI_BLK_P, %d0
	membar	#Sync

3:
	wr	%g0, %i4, %fprs			! fpu back to the way it was
	ret
	 restore
	SET_SIZE(ac_blkcopy)
