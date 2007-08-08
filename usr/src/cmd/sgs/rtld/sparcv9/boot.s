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
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 *
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Bootstrap routine for ld.so.  Control arrives here directly from
 * exec() upon invocation of a dynamically linked program specifying ld.so
 * as its interpreter. 
 *
 * On entry, the stack appears as:
 *
 *	!_______________________!  high addresses
 *	!	0 word		!
 *	!_______________________!
 *	!			!
 *	!	Information	!
 *	!	Block		!
 *	!	(size varies)	!
 *	!_______________________!
 *	!	Auxiliary	!
 *	!	vector		!
 *	!	2 word entries	!
 *	!			!
 *	!_______________________!
 *	!	0 word		!
 *	!_______________________!
 *	!	Environment	!
 *	!	pointers	!
 *	!	...		!
 *	!	(one word each)	!
 *	!_______________________!
 *	!	0 word		!
 *	!_______________________!
 *	!	Argument	! low addresses
 *	!	pointers	!
 *	!	Argc words	!
 *	!_______________________!
 *	!			!
 *	!	Argc		!
 *	!_______________________! <- %sp + STACK_BIAS + WINDOWSIZE
 *	!			!
 *	!   Window save area	!
 *	!_______________________! <- %sp + STACK_BIAS
 */

#if	defined(lint)

extern	unsigned long	_setup();
extern	void		atexit_fini();

void
main()
{
	(void) _setup();
	atexit_fini();
}

#else

#include <sys/asm_linkage.h>
#include <sys/param.h>
#include <link.h>

	.file	"boot.s"
	.seg	".text"
	.global	_rt_boot, _setup, atexit_fini
	.type	_rt_boot, #function
	.align	4

! Entry vector
!	+0: normal start
!	+4: normal start
!	+8: alias start (frame exists)		XX64 what's this for?

_rt_boot:
	nop
	ba,a	_elf_start
	ba,a	_alias_start

! Start up routines

_elf_start:

! Create a stack frame, perform PIC set up.  We have
! to determine a bunch of things from our "environment" and
! construct an Elf64_Boot attribute value vector.

	save	%sp, -SA(MINFRAME + (EB_MAX * 16)), %sp
	
_alias_start:

1:					! PIC prologue
	call	2f
	sethi	%hh(_GLOBAL_OFFSET_TABLE_ + (. - 1b)), %g1
2:	or	%g1, %hm(_GLOBAL_OFFSET_TABLE_ + (. - 1b)), %g1
	sllx	%g1, 32, %g5
	sethi	%lm(_GLOBAL_OFFSET_TABLE_ + (. - 1b)), %l7
	or	%l7, %lo(_GLOBAL_OFFSET_TABLE_ + (. - 1b)), %l7
	or	%g5, %l7, %l7
	add	%l7, %o7, %l7		! finish PIC prologue

! %fp points to the root of our ELF bootstrap vector, use it to construct
! the vector and send it to _setup.
! 
! The resulting Elf64_Boot vector looks like this:
! 
!	Offset		Contents
!	+0x0		EB_ARGV
!	+0x8		argv[]
!	+0x10		EB_ENVP
! 	+0x18		envp[]
!	+0x20		EB_AUXV
!	+0x28		auxv[]
!	+0x30		EB_NULL

	add	%sp, STACK_BIAS + SA(MINFRAME), %o0
					! &eb[0] == %sp + frame size
	mov	EB_ARGV, %l0		! code for this entry
	stx	%l0, [%o0]		!   store it
	add	%fp, WINDOWSIZE + 8 + STACK_BIAS, %l0
					! argument vector
	stx	%l0, [%o0 + 0x8]	!   store that
	ldx	[%fp + WINDOWSIZE + STACK_BIAS], %l1
					! get argument count (argc)
	inc	%l1			! account for last element of 0
	sllx	%l1, 3, %l1		! multiply by 8
	add	%l0, %l1, %l0		!   and get address of first env ptr
	stx	%l0, [%o0 + 0x18]	! store it in the vector
	mov	EB_ENVP, %l1		! code for environment base
	stx	%l1, [%o0 + 0x10]	!   store it
	mov	EB_AUXV, %l1		! get code for auxiliary vector
	stx	%l1, [%o0 + 0x20]	!   store it

3:	ldx	[%l0], %l1		! get an entry
	brnz,pt	%l1, 3b			! if not at end, go back and look again
	add	%l0, 8, %l0		!	incrementing pointer in delay
	stx	%l0, [%o0 + 0x28]	! store aux vector pointer
	
	mov	EB_NULL, %l0		! set up for the last pointer
	stx	%l0, [%o0 + 0x30]	!   and store it
	mov	%g0, %g2		! clear globals
	mov	%g0, %g3

! Call _setup.  Two arguments, the ELF bootstrap vector and our (unrelocated)
! _DYNAMIC address.  The _DYNAMIC address is located in entry 0 of the GOT


	call	_setup			! call it
	ldx	[%l7], %o1

! On return, give callee the exit function in %g1, and jump to the
! target program, clearing out the reserved globals as we go.
	
	ldx	[%l7 + atexit_fini], %g1! get function address
	restore	%o0, %g0, %l1		! release frame
	jmpl	%l1, %g0		! call main program
	mov	%g0, %g4		!   clear one last global in delay

	.size	_rt_boot, . - _rt_boot
#endif
