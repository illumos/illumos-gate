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

#include <sys/param.h>
#include <sys/asm_linkage.h>
#include <sys/errno.h>
#include <sys/intreg.h>
#include <sys/intr.h>
#include <sys/x_call.h>
#include <sys/privregs.h>
#include <sys/machthread.h>
#include <sys/machtrap.h>
#include <sys/xc_impl.h>
#include <sys/bitmap.h>

#ifdef TRAPTRACE
#include <sys/traptrace.h>
#endif /* TRAPTRACE */


/*
 * For a x-trap request to the same processor, just send a fast trap.
 * Does not accept inums.
 */
	ENTRY_NP(send_self_xcall)
	ta	 ST_SELFXCALL
	retl
	nop
	SET_SIZE(send_self_xcall)

/*
 * idle or stop xcall handler.
 *
 * Called in response to an xt_some initiated by idle_other_cpus
 * and stop_other_cpus.
 *
 *	Entry:
 *		%g1 - handler at TL==0
 *
 * 	Register Usage:
 *		%g1 - preserved
 *		%g4 - pil
 *
 * %g1 will either be cpu_idle_self or cpu_stop_self and is
 * passed to sys_trap, to run at TL=0. No need to worry about
 * the regp passed to cpu_idle_self/cpu_stop_self, since
 * neither require arguments.
 */
	ENTRY_NP(idle_stop_xcall)
	rdpr	%pil, %g4
	cmp	%g4, XCALL_PIL
	ba,pt	%xcc, sys_trap
	  movl	%xcc, XCALL_PIL, %g4
	SET_SIZE(idle_stop_xcall)

