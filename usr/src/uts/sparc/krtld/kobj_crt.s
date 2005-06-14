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
#include <sys/stack.h>
#include <sys/trap.h>
#include <sys/reboot.h>

/* XXX No sharing here -- make this into two files */

/*
 * Exit routine from linker/loader to kernel.
 */

#if defined(lint) || defined(__lint)

/* ARGSUSED */
void
exitto(caddr_t entrypoint)
{}

#else	/* lint */

	ENTRY_NP(exitto)
	save	%sp, -SA(MINFRAME64), %sp

	set	boothowto, %o3
	ld	[%o3], %o3
	set	RB_DEBUGENTER, %o2
	andcc	%o3, %o2, %g0
	bz	1f
	nop
	t	ST_KMDB_TRAP
	nop
1:
	set	romp, %o0			! pass the romp to the callee
	set	ops, %o1			! pass the bootops
	ldx	[%o1], %o1
	jmpl	%i0, %o7
	ldx	[%o0], %o0
	/*  there is no return from here */
	SET_SIZE(exitto)

#endif	/* lint */
