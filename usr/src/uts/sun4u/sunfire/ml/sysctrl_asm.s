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
 * Copyright 2001 Sun Microsystems, Inc.  All rights reserved.
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

/*
 * This routine quiets a cpu and has it spin on a barrier.
 * It is used during memory sparing so that no memory operation
 * occurs during the memory copy.
 *
 *	Entry:
 *		%g1    - gate array base address
 *		%g2    - barrier base address
 *		%g3    - arg2
 *		%g4    - arg3
 *
 * 	Register Usage:
 *		%g3    - saved pstate
 *		%g4    - temporary
 *		%g5    - check for panicstr
 */
	ENTRY_NP(sysctrl_freeze)
	CPU_INDEX(%g4, %g5)
	sll	%g4, 2, %g4
	add	%g4, %g1, %g4			! compute address of gate id

	st	%g4, [%g4]			! indicate we are ready
	membar	#Sync
1:
	sethi	%hi(panicstr), %g5
	ldn	[%g5 + %lo(panicstr)], %g5
	brnz	%g5, 2f				! exit if in panic
	 nop
	ld	[%g2], %g4
	brz,pt	%g4, 1b				! spin until barrier true
	 nop

2:
	retry
	membar	#Sync
	SET_SIZE(sysctrl_freeze)

