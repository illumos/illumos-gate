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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/asm_linkage.h>
#include <sys/privregs.h>

#if defined(__lint)
#include <kmdb/kmdb_start.h>
#endif

#include <kmdb/kaif_asmutil.h>

/*
 * This routine is called for the initial trip into the debugger.  We need
 * to switch over to the debugger stack (which we also need to initialize)
 * before entering the debugger.  Subsequent re-entries will longjmp their
 * way in.
 */
#if defined(__lint)
void
kmdb_first_start(void)
{
}
#else	/* __lint */

	ENTRY(kmdb_first_start)

	GET_NWIN(%g1, %g2);	/* %g1 is scratch, %g2 set to nwin-1 */
	sub	%g2, 1, %g2

	wrpr	%g2, %cansave
	wrpr	%g0, %canrestore

	set	kmdb_main_stack, %g1
	ldx	[%g1], %g1

	set	kmdb_main_stack_size, %g2
	ldx	[%g2], %g2

	add	%g1, %g2, %g1
	sub	%g1, 1, %g1
	and	%g1, -STACK_ALIGN64, %g1
	sub	%g1, SA64(MINFRAME) + V9BIAS64, %sp

	mov	0, %fp
	save	%sp, -SA64(MINFRAME64), %sp

	/* start the debugger */	
	call	kmdb_main
	nop

	SET_SIZE(kmdb_first_start)
#endif

