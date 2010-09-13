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
 * Copyright (c) 1986-1997, Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * standalone startup code for sun4u LP64 secondary booters.
 */

#include <sys/asm_linkage.h>
#include <sys/privregs.h>
#include <sys/stack.h>

#if defined(lint)

/*ARGSUSED*/
void
_start(void *a, ...)
{}

#else
	.seg	".text"
	.align	8
	.global	end
	.global	edata
	.global	main

	.seg	".bss"
	.align	8

_local_p1275cif:
	.skip	8

!
! Create a stack just below _start.
!
#define	STACK_SIZE	0x14000

	.skip	STACK_SIZE
.ebootstack:			! end --top-- of boot stack

!
! Enter here for all disk/secondary booters loaded by a bootblk program or
! inetboot loaded by OBP.
! Careful: don't touch %o4 until the save, since it contains the
! address of the IEEE 1275 SPARC v9 CIF handler; the linkage to the prom.
!
	.seg	".text"
	.global	prom_exit_to_mon
	.type	prom_exit_to_mon, #function

	ENTRY(_start)

	!
	! The stacks in bss now; use the stack we came in on (prom is supposed
	! to call us with a minimum of an 8k stack, bzero bss (and thus our
	! new stack), then switch to the new stack. Do all this without losing
	! track of the p1275cif address cached in %o4.
	!

	save	%sp, -SA(MINFRAME), %sp

	!
	! Zero the bss [edata to end]
	!
	setn	edata, %g1, %o0
	setn	end, %g1, %i2
	call	bzero
	sub	%i2, %o0, %o1			! size

	restore %g0, %g0, %g0	! Trivial restore

	!
	! Switch to our new stack.
	!
	setn    (.ebootstack - STACK_BIAS), %g1, %o1
	save	%o1, -SA(MINFRAME), %sp

	!
	! Set supervisor mode, interrupt level >= 13, traps enabled
	! We don't set PSTATE_AM even though all our addresses are under 4G.
	!
	wrpr	%g0, PSTATE_PEF+PSTATE_PRIV+PSTATE_IE, %pstate

	sethi	%hi(_local_p1275cif), %o1
	stx	%i4, [%o1 + %lo(_local_p1275cif)]
	call	main			! main(prom-cookie)
	mov	%i4, %o0		! SPARCV9/CIF

	! print stupid error message here!

	call	prom_enter_mon		! can't happen .. :-)
	nop
	SET_SIZE(_start)

#endif	/* lint */

#if defined(lint)

/* ARGSUSED */
void
exitto(int (*entrypoint)(void *romvec, void *dvec, void *bootops,
    void *bootvec))
{}

/* ARGSUSED */
void
exitto64(int (*entrypoint)(void *romvec, void *dvec, void *bootops,
    void *bootvec), void *bootvec)
{}

#else	/* lint */

	ENTRY(exitto)
	!
	! Setup args for client.
	!
	! 32 bit frame, 64 bit sized
	sub	%g0, SA(MINFRAME) - STACK_BIAS, %g1
	save	%sp, %g1, %sp
	sethi	%hi(_local_p1275cif), %o0 ! 1275 CIF handler for callee.
	ldx	[%o0 + %lo(_local_p1275cif)], %o0
	clr	%o1			! boot passes no dvec
	setn	bootops, %g1, %o2
	sethi	%hi(elfbootvec), %o3	! pass elf bootstrap vector
	ldx	[%o3 + %lo(elfbootvec)], %o3
	rdpr	%pstate, %l1		! Get the present pstate value
	wrpr    %l1, PSTATE_AM, %pstate ! Set PSTATE_AM = 1
	jmpl	%i0, %o7		! call thru register to the standalone
	mov	%o0, %o4		! 1210378: Pass cif in both %o0 & %o4

	! eek - we returned -- switch back to a 64-bit frame
	! then panic in a slightly informative way.

	restore	%g0, %g0, %g0
	save	%sp, -SA(MINFRAME), %sp
	sethi	%hi(.msg), %o0
	call	prom_panic
	or	%o0, %lo(.msg), %o0
.msg:	.asciz	"exitto returned from client program"
	SET_SIZE(exitto)

	ENTRY(exitto64)
	!
	! Setup args for client.
	!
	save	%sp, -SA(MINFRAME), %sp
	sethi	%hi(_local_p1275cif), %o0 ! 1275 CIF handler for callee.
	ldx	[%o0 + %lo(_local_p1275cif)], %o0
	mov	%i1, %o3		! bootvec
	clr	%o1			! boot passes no dvec
	setn	bootops, %g1, %o2
	jmpl	%i0, %o7		! call thru register to the standalone
	mov	%o0, %o4		! 1210378: Pass cif in both %o0 & %o4

	! eek - we returned -- panic in a slightly informative way.

	sethi	%hi(.msg64), %o0
	call	prom_panic
	or	%o0, %lo(.msg64), %o0
.msg64:	.asciz	"exitto64 returned from client program"
	SET_SIZE(exitto64)

#endif	/* lint */

#if defined(lint)

/*
 * The interface for our 64-bit client program
 * calling the 64-bit romvec OBP.
 */

#include <sys/promif.h>
#include <sys/prom_isa.h>

/* ARGSUSED */
int
client_handler(void *cif_handler, void *arg_array)
{ return (0); }

#else	/* lint */

	ENTRY(client_handler)
	mov	%o7, %g1
	mov	%o0, %g5
	mov	%o1, %o0
	jmp	%g5
	mov	%g1, %o7
	SET_SIZE(client_handler)

#endif	/* lint */
