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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 *	Copyright (c) 1990, 1991 UNIX System Laboratories, Inc.
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Establish the default settings for the floating-point state for a C language
 * program:
 *	rounding mode		-- round to nearest default by OS,
 *	exceptions enabled	-- all masked
 *	sticky bits		-- all clear by default by OS.
 *      precision control       -- double extended
 * Set _fp_hw according to what floating-point hardware is available.
 * Set _sse_hw according to what SSE hardware is available.
 * Set __flt_rounds according to the rounding mode.
 */

#pragma weak _fpstart = __fpstart

#include	"synonyms.h"
#include	<sys/types.h>
#include	<sys/sysi86.h>	/* for SI86FPHW/SI86FPSTART definitions */
#include	<sys/fp.h>	/* for FPU_CW_INIT and SSE_MXCSR_INIT */

extern int	__fltrounds();

int	_fp_hw;			/* default: bss: 0 == no hardware */
int	_sse_hw;		/* default: bss: 0 == no sse */
int	__flt_rounds;		/* ANSI rounding mode */

void
__fpstart()
{
	/*
	 * query OS for HW status and ensure the x87 and (optional)
	 * SSE control words are (will be) set correctly.
	 */
	if ((_sse_hw = sysi86(SI86FPSTART,
	    &_fp_hw, FPU_CW_INIT, SSE_MXCSR_INIT)) == -1) {
		extern void _putcw();

		/*
		 * (fallback to old syscall on old kernels)
		 */
		_sse_hw = 0;
		(void) sysi86(SI86FPHW, &_fp_hw);
		_putcw(0x133f);
	}

	/*
	 * At this point the x87 fp environment that has been (or more
	 * hopefully, will be) established by the kernel is:
	 *
	 * affine infinity	0x1000
	 * round to nearest	0x0000
	 * 64-bit doubles	0x0300
	 * precision, underflow, overflow, zero-divide, denorm, invalid masked
	 *			0x003f
	 *
	 * which conforms to the 4th edition i386 ABI definition.
	 *
	 * Additionally, if we have SSE hardware, we've also masked all
	 * the same traps, and have round to nearest.
	 */

	__flt_rounds = 1;	/* ANSI way of saying round-to-nearest */
}
