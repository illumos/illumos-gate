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

#include <sys/asm_linkage.h>
#include <sys/trap.h>

#include <kmdb/kaif_asmutil.h>

#if defined(__lint)
void
kaif_enter(void)
{
}
#else

	ENTRY(kaif_enter)
	pushq	%rbp
	movq	%rsp, %rbp

	pushfq
	cli

	int	$T_DBGENTR

	popfq

	leave
	ret	
	SET_SIZE(kaif_enter)

#endif

#if defined(__lint)
/*ARGSUSED*/
void
get_idt(desctbr_t *idt)
{
}
#else

	ENTRY(get_idt)
	sidt	(%rdi)
	ret
	SET_SIZE(get_idt)

#endif

#if defined(__lint)
/*ARGSUSED*/
void
set_idt(desctbr_t *idt)
{
}
#else

	ENTRY(set_idt)
	lidt	(%rdi)
	ret
	SET_SIZE(set_idt)

#endif
