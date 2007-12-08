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
 * Copyright (c) 1986-1994, by Sun Microsystems, Inc.
 */

#pragma	ident	"%Z%%M%	%I%	%E% SMI"

/*
 * simple standalone startup code
 */

#include <sys/asm_linkage.h>

#if defined(lint)

#include "cbootblk.h"

/*ARGSUSED*/
void
start(void *romp)
{}

#else	/* lint */

	ENTRY(start)
	.global	end
	.global	edata
	.global	main
	!
	! OBP gives us control right here ..
	!
	! On entry, %o0 contains the romp.
	!
	sethi	%hi(start), %o1		! Top of stack
	or	%o1, %lo(start), %o1
	save	%o1, -SA(MINFRAME), %sp
	!
	! zero the bss
	!
	sethi	%hi(edata), %o0		! Beginning of bss
	or	%o0, %lo(edata), %o0
	sethi	%hi(end), %o2		! End of the whole wad
	or	%o2, %lo(end), %o2	
	call	bzero
	sub	%o2, %o0, %o1		! end - edata = size of bss
	call	main
	mov	%i0, %o0		! romvec pointer
	call	exit
	mov	0, %o0
	ret				! ret to prom
	restore
	SET_SIZE(start)

#endif	/* lint */
