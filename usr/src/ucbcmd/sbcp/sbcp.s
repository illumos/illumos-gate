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

	.file	"sbcp.s"

#include <sys/asm_linkage.h>
#include <sys/link.h>
#include <sys/syscall.h>

#define	PIC_SETUP(r)						\
	mov	%o7, %g1;					\
9:	call	8f;						\
	sethi	%hi(_GLOBAL_OFFSET_TABLE_ - (9b - .)), %r;	\
8:	or	%r, %lo(_GLOBAL_OFFSET_TABLE_ - (9b - .)), %r;	\
	add	%r, %o7, %r;					\
	mov	%g1, %o7

#define	FUNC(x) \
	.section	".text"; \
	.align	4; \
	.type	x, #function; \
x:

#define	ENOSYS	90		/* 4.x ENOSYS */

/* derived from <sys/exechdr.h>, which we can't include */
#define	A_MAGIC	0x02	/* offset of a_magic field */
#define	A_ENTRY	0x14	/* offset of a_entry field */
#define	ZMAGIC	0413	/* magic number for demand paged executable */

	.global	atexit, errno

!
!	_start - execution starts here (after the runtime linker runs)
!
!	The SPARC ABI defines our "environment" at this point, see page 3-34.
!	Register the exit handler, register the trap0 handler, find the
!	entry point, and jump to it.  We depend on the stack (argv, envp)
!	being compatible between 4.x and 5.x.  We also depend on the
!	runtime linker to set up ``environ''.
!

ENTRY_NP(_start)
	tst	%g1			! is there a handler to register?
	bz	1f			! no
	nop
	mov	%g1, %o0
	call	atexit			! yes, register it with atexit()
	nop
1:

	!
	! Aside from a value in %g1, there were no arguments explicitly
	! passed to this routine, but we do know how our initial stack has
	! been setup by the kernel.  The stack format is documented in:
	!	usr/src/cmd/sgs/rtld/sparc/boot.s
	!	usr/src/cmd/sgs/rtld/sparcv9/boot.s
	!
	! Since we want to invoke the following c initalization routine:
	!	sbcp_init(int argc, char *argv[], char *envp[]))
	! we need to troll through the stack to setup it's argument values.
	!
	save	%sp, -SA(MINFRAME + EB_MAX_SIZE32), %sp

	ldn	[%fp + WINDOWSIZE + STACK_BIAS], %o0		! get argc
	add	%fp, + WINDOWSIZE + CPTRSIZE + STACK_BIAS, %o1	! get argv

	add	%o0, 1, %l0		! add 1 to argc for last element of 0
	sll	%l0, CPTRSHIFT, %l0	! multiply argc by pointer size
	add	%o1, %l0, %o2		!  and add to argv to get envp

	call	sbcp_init		! Call our c initalization routine
	nop
	restore

	PIC_SETUP(g2)
	ld	[%g2+trap0], %g1
	ta	9

	! jump to the main program's entry point

	sethi   %hi(0x2000), %o0
	lduh    [%o0 + A_MAGIC], %g1
	cmp     %g1, ZMAGIC		! is it a ZMAGIC executable?
	be,a    1f			! yes,
	ld      [%o0 + A_ENTRY], %o0	!   get entry point
1:					! else, assume entry point is 0x2000
	jmp	%o0
	nop
	SET_SIZE(_start)

!
!	trap0 - glue between 4.x syscall trap and 5.x BCP routine
!
!	enter with:
!		%g1	syscall number
!		%g6	return address (after trap instruction)
!
!	We used to use %g7, but that conflicts with threading code
!	which uses %g7 as the curthread pointer.  That is why we
!	changed to using %g6 instead.
!
!	We use an extra window to save the %o registers we're entered
!	with (which the 4.x system call stubs depend on) and to allow
!	recursive traps (e.g., from a signal handler).
!

FUNC(trap0)
	save	%sp, -SA(MINFRAME), %sp
	tst	%g1
	be	1f
	nop
	mov	%i0, %o0
	mov	%i1, %o1
	mov	%i2, %o2
	mov	%i3, %o3
	mov	%i4, %o4
	mov	%i5, %o5
	ba,a	2f
1:
	! indir syscall
	mov	%i0, %g1
	mov	%i1, %o0
	mov	%i2, %o1
	mov	%i3, %o2
	mov	%i4, %o3
	mov	%i5, %o4
	ld	[%fp + MINFRAME], %o5
2:
	sll	%g1, 4, %l1
	PIC_SETUP(l0)
	ld	[%l0+sysent], %l0
	add	%l1, %l0, %l1
	jmp	%l1			! jump into branch table
	nop
	SET_SIZE(trap0)

FUNC(trap0rtn)
	cmp	%o0, -1
	bne	1f
	addcc	%g0, %g0, %g0		! psr &= ~C
	PIC_SETUP(o1)
	ld	[%o1+errno], %o1
	ld	[%o1], %o0
	subcc	%g0, 1, %g0		! psr |= C
1:
	mov	%o0, %i0
	restore
	jmp	%g6
	nop
	SET_SIZE(trap0rtn)

!
!	nullsys
!
FUNC(nullsys)
	clr	%o0
	b,a	trap0rtn
	SET_SIZE(nullsys)

!
!	nosys
!
FUNC(nosys)
	set	ENOSYS, %o1
	PIC_SETUP(g2)
	ld	[%g2+errno], %g2
	st	%o1, [%g2]
	set	-1, %o0
	b,a	trap0rtn
	SET_SIZE(nosys)

!
!	Have to #include the sysent table and stubs so that all
!	symbols referenced between here and there are "static"
!	to this module so the assembler can resolve them without
!	the linker needing to deal with them at run time.
!
#include "sysent.s"
