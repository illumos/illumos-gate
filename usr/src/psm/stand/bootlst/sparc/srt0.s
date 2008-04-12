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

#ident	"%Z%%M%	%I%	%E% SMI"

/*
 * srt0.s - bootlst startup code
 */
#include <sys/asm_linkage.h>
#include <sys/machparam.h>

#define	STKSIZE	0x1000

#if defined(lint)
void *estack;
caddr_t _end;
#endif

#if defined(lint)

/* ARGSUSED */
void
_start(void *a, ...)
{}

#else	/* !lint */

	.seg	".bss"
	.align	MMU_PAGESIZE
	.skip	STKSIZE
estack:					! top of cprboot stack
	.global	estack

	.seg	".data"
	.align	8
local_cif:
	.xword	0			! space for prom cookie

	.seg	".text"
	.align	8

	!
	! regs on entry:
	! %o4 = prom cookie
	!
	ENTRY(_start)
	set	estack - STACK_BIAS, %o5
	save	%o5, -SA(MINFRAME), %sp

	!
	! clear the bss
	!
	set	_edata, %o0
	set	_end, %g2
	call	bzero
	sub	%g2, %o0, %o1		! bss size = (_end - _edata)

	set	local_cif, %g2
	stx	%i4, [%g2]
	call	main
	mov	%i4, %o0		! SPARCV9/CIF

	call	prom_exit_to_mon
	nop
	SET_SIZE(_start)

#endif	/* lint */


#if defined(lint)

/* ARGSUSED */
int
client_handler(void *cif_handler, void *arg_array)
{ return (0); }

#else

	!
	! 64/64 client interface for ieee1275 prom
	!
	ENTRY(client_handler)
	mov	%o7, %g1
	mov	%o0, %g5
	mov	%o1, %o0
	jmp	%g5
	mov	%g1, %o7
	SET_SIZE(client_handler)

#endif	/* lint */

