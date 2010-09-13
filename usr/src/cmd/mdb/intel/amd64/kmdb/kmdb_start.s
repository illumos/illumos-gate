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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#if defined(__lint)
#include <kmdb/kmdb_start.h>
#endif

#include <sys/asm_linkage.h>

/*
 * This routine is called for the initial trip into the debugger.  We need
 * to switch over to the debugger stack before entering the debugger.
 * Subsequent re-entries will longjmp their way in.
 */
#if defined(__lint)
void
kmdb_first_start(void)
{
}
#else

	ENTRY(kmdb_first_start)
	movq	kmdb_main_stack, %rsp
	movq	kmdb_main_stack_size, %rbx

	addq	%rbx, %rsp
	subq	$1, %rsp
	andq	$_BITNOT(STACK_ALIGN-1), %rsp

	call	kmdb_main	

	ret
	SET_SIZE(kmdb_first_start)

#endif
