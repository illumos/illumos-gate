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

/*
 * Assembly language support for px driver
 */
 
#include <sys/asm_linkage.h>
#include <sys/machthread.h>
#include <sys/privregs.h>

/*LINTLIBRARY*/

! px_phys_peek_4u: Do physical address read.
!
! %o0 is size in bytes - Must be 8, 4, 2 or 1.  Invalid sizes default to 1.
! %o1 is address to read
! %o2 is address to save value into
! %o3 is 0 for little endian, non-zero for big endian
!
! To be called from an on_trap environment.
! Interrupts will be disabled for the duration of the read, to prevent
! an interrupt from raising the trap level to 1 and then a possible
! data access exception being delivered while the trap level > 0.
!
! Always returns success (0) in %o0
!
! Assumes alignment is correct and that on_trap handling has been installed

	ENTRY(px_phys_peek_4u)

	rdpr	%pstate, %o4		! Disable interrupts if not already
	andcc	%o4, PSTATE_IE, %g2	! Save original state first
	bz	.peek_ints_disabled
	nop
	wrpr	%o4, PSTATE_IE, %pstate
.peek_ints_disabled:

	tst	%o3			! Set up %asi with modifier for
	movz	%xcc, ASI_IOL, %g1	! Big/little endian physical space
	movnz	%xcc, ASI_IO, %g1
	mov	%g1, %asi

	cmp	%o0, 8			! 64-bit?
	bne	.peek_int
	cmp	%o0, 4			! 32-bit?
	ldxa	[%o1]%asi, %g1
	ba	.peekdone
	stx	%g1, [%o2]

.peek_int:
	bne	.peek_half
	cmp	%o0, 2			! 16-bit?
	lduwa	[%o1]%asi, %g1
	ba	.peekdone
	stuw	%g1, [%o2]
	
.peek_half:
	bne	.peek_byte
	nop
	lduha	[%o1]%asi, %g1
	ba	.peekdone
	stuh	%g1, [%o2]

.peek_byte:
	lduba	[%o1]%asi, %g1	! 8-bit!
	stub	%g1, [%o2]
 
.peekdone:
	membar	#Sync			! Make sure the loads take
	tst	%g2			! No need to reenable interrupts
	bz	.peek_ints_done		! 	if not enabled at entry
	rdpr	%pstate, %o4
	wrpr	%o4, PSTATE_IE, %pstate
.peek_ints_done:
	mov     %g0, %o0
	retl
	nop
	SET_SIZE(px_phys_peek_4u)


! px_phys_poke_4u: Do physical address write.
!
! %o0 is size in bytes - Must be 8, 4, 2 or 1.  Invalid sizes default to 1.
! %o1 is address to write to
! %o2 is address to read from
! %o3 is 0 for little endian, non-zero for big endian
!
! Always returns success (0) in %o0
!
! Assumes alignment is correct and that on_trap handling has been installed

	ENTRY(px_phys_poke_4u)

	tst	%o3
	movz	%xcc, ASI_IOL, %g1	! Big/little endian physical space
	movnz	%xcc, ASI_IO, %g1
	mov	%g1, %asi

	cmp	%o0, 8			! 64 bit?
	bne	.poke_int
	cmp	%o0, 4			! 32-bit?
	ldx	[%o2], %g1
	ba	.pokedone
	stxa	%g1, [%o1]%asi

.poke_int:
	bne	.poke_half
	cmp	%o0, 2			! 16-bit?
	lduw	[%o2], %g1
	ba	.pokedone
	stuwa	%g1, [%o1]%asi

.poke_half:
	bne	.poke_byte
	nop
	lduh	[%o2], %g1
	ba	.pokedone
	stuha	%g1, [%o1]%asi

.poke_byte:
	ldub	[%o2], %g1		! 8-bit!
	stuba	%g1, [%o1]%asi

.pokedone:
	membar	#Sync
	retl
	mov	%g0, %o0
	SET_SIZE(px_phys_poke_4u)
 
