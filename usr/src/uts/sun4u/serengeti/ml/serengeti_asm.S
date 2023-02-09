/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "assym.h"

#include <sys/asm_linkage.h>
#include <sys/param.h>
#include <sys/privregs.h>
#include <sys/machasi.h>
#include <sys/mmu.h>
#include <sys/machthread.h>
#include <sys/pte.h>
#include <sys/stack.h>
#include <sys/vis.h>
#include <sys/param.h>
#include <sys/errno.h>
#include <sys/vtrace.h>
#include <sys/clock.h>
#include <sys/asi.h>
#include <sys/fsr.h>
#include <sys/cheetahregs.h>

!
! Load the safari address for a specific cpu
!
!
	ENTRY(lddsafaddr)
	rdpr	%pstate, %o4
	andn	%o4, PSTATE_IE | PSTATE_AM, %o5
	wrpr	%o5, 0, %pstate	! clear IE, AM bits
	ldxa	[%o0]ASI_SAFARI_CONFIG, %o0
	retl
	wrpr	%g0, %o4, %pstate	! restore earlier pstate register value
	SET_SIZE(lddsafaddr)

!
! Load the mc_decode reg for this cpu.
!
!
	ENTRY(lddmcdecode)
	rdpr	%pstate, %o4
	andn	%o4, PSTATE_IE | PSTATE_AM, %o5
	wrpr	%o5, 0, %pstate	! clear IE, AM bits
	ldxa	[%o0]ASI_MC_DECODE, %o0
	retl
	wrpr	%g0, %o4, %pstate	! restore earlier pstate register value
	SET_SIZE(lddmcdecode)

