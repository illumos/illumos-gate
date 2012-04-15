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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

	.file	"_rtboot.s"

! Bootstrap routine for alias ld.so.  Control arrives here either directly
! from exec() upon invocation of a dynamically linked program specifying our
! alias as its interpreter.
!
! On entry, the stack appears as:
!
!_______________________!  high addresses
!			!  
!	Information	!  
!	Block		!  
!	(size varies)	!  
!_______________________!
!	0 word		!
!_______________________!
!	Auxiliary	!
!	vector		!
!	2 word entries	!
!			!
!_______________________!
!	0 word		!
!_______________________!
!	Environment	!
!	pointers	!
!	...		!
!	(one word each)	!
!_______________________!
!	0 word		!
!_______________________!
!	Argument	! low addresses
!	pointers	!
!	Argc words	!
!_______________________!
!			!
!	Argc		!
!_______________________!<- %sp +64
!			!
!   Window save area	! 
!_______________________! <- %sp

#include <sys/asm_linkage.h>
#include <sys/param.h>
#include <sys/syscall.h>
#include <link.h>
#include "alias_boot.h"

	.section ".text"
	.volatile
	.global	__rtboot
	.global	__rtld
	.local	s.LDSO, s.ZERO
	.local	f.PANIC, f.OPENAT, f.MMAP, f.FSTATAT, f.SYSCONFIG
	.local	f.CLOSE, f.EXIT, f.MUNMAP
	.type	__rtboot, #function
	.align	4

! Create a stack frame, perform PIC set up.  If we're a "normal" start, we have
! to determine a bunch of things from our "environment" and construct an ELF
! boot attribute value vector.  Otherwise, it's already been done and we can
! skip it.

__rtboot:
	save	%sp, -SA(MINFRAME + (EB_MAX * 8) + ((S_MAX + F_MAX) * 4)), %sp
1:					! PIC prologue
	call	2f			! get PIC for PIC work

! Set up pointers to __rtld parameters.  eb[], strings[] and funcs[] are on
! the stack.  Note that we will call ld.so with an entry vector that causes
! it to use the stack frame we have.

	add	%sp, MINFRAME, %o0	! &eb[0]
2:
	add	%o0, (EB_MAX * 8), %o1	! &strings[0] == &eb[EB_MAX]
	add	%o1, (S_MAX * 4), %o2	! &funcs[0] == &strings[S_MAX]
	set	EB_ARGV, %l0		! code for this entry
	st	%l0, [%o0]		!   store it
	add	%fp, 68, %l0		! argument vector is at %fp+68
	st	%l0, [%o0 + 4]		!   store that
	ld	[%fp + 64], %l1		! get argument count
	inc	%l1			! account for last element of 0
	sll	%l1, 2, %l1		! multiply by 4
	add	%l0, %l1, %l0		!   and get address of first env ptr
	st	%l0, [%o0 + 12]		! store it in the vector
	set	EB_ENVP, %l1		! code for environment base
	st	%l1, [%o0 + 8]		!   store it
	set	EB_AUXV, %l1		! get code for auxiliary vector
	st	%l1, [%o0 + 16]		!   store it
2:
	ld	[%l0], %l1		! get an entry
	tst	%l1			! are we at a "0" entry in environment?
	bne	2b			!   no, go back and look again
	add	%l0, 4, %l0		!     incrementing pointer in delay
	st	%l0, [%o0 + 20]		! store aux vector pointer
	set	EB_NULL, %l0		! set up for the last pointer
	st	%l0, [%o0 + 24]		!   and store it

! Initialize strings and functions as appropriate

#define	SI(n) \
	set	(s./**/n  - 1b), %l0; \
	add	%o7, %l0, %l0; \
	st	%l0, [%o1 + (n/**/_S * 4)]
#define	FI(n) \
	set	(f./**/n - 1b), %l0; \
	add	%o7, %l0, %l0; \
	st	%l0, [%o2 + (n/**/_F * 4)]

	SI(LDSO)
	SI(ZERO)
	SI(EMPTY)
	FI(PANIC)
	FI(OPENAT)
	FI(MMAP)
	FI(FSTATAT)
	FI(SYSCONFIG)
	FI(CLOSE)
	FI(MUNMAP)

! Call the startup function to get the real loader in here.

	call	__rtld			! call it
	mov	%o0, %l0		!   and save &eb[0] for later

! On return, jump to the function in %o0, passing &eb[0] in %o0

	jmpl	%o0, %g0		! call main program
	mov	%l0, %i0		! set up parameter

! Functions

f.PANIC:
	save	%sp, -SA(MINFRAME), %sp	! make a frame
	mov	%i0, %o1		! set up pointer
	clr	%o2			! set up character counter
1:					! loop over all characters
	ldub	[%i0 + %o2], %o0	! get byte
	tst	%o0			! end of string?
	bne,a	1b			!   no,
	inc	%o2			!     increment count
	call	f.WRITE			! write(2, buf, %o2)
	mov	2, %o0
2:
	call	1f			! get PC
	mov	l.ERROR, %o2		! same with constant message
1:
	set	(s.ERROR - 2b), %o1	! get PC-relative address 
	add	%o7, %o1, %o1		!   and now make it absolute
	call	f.WRITE			! write it out
	mov	2, %o0			!   to standard error
	ba	f.EXIT			! leave
	nop

f.OPENAT:
	ba	__syscall
	mov	SYS_openat, %g1

f.MMAP:
	sethi	%hi(0x80000000), %g1	! MAP_NEW
	or	%g1, %o3, %o3
	ba	__syscall
	mov	SYS_mmap, %g1

f.MUNMAP:
	ba	__syscall
	mov	SYS_munmap, %g1

f.READ:
	ba	__syscall
	mov	SYS_read, %g1

f.WRITE:
	ba	__syscall
	mov	SYS_write, %g1

f.LSEEK:
	ba	__syscall
	mov	SYS_lseek, %g1

f.CLOSE:
	ba	__syscall
	mov	SYS_close, %g1

f.FSTATAT:
	ba	__syscall
	mov	SYS_fstatat, %g1

f.SYSCONFIG:
	ba	__syscall
	mov	SYS_sysconfig, %g1

f.EXIT:
	mov	SYS_exit, %g1

__syscall:
	t	0x8			! call the system call
	bcs	__err_exit		! test for error
	nop
	retl				! return
	nop

__err_exit:
	retl				! return
	mov	-1, %o0

! String constants

s.LDSO:	.asciz	"/usr/lib/ld.so.1"
s.ZERO:	.asciz	"/dev/zero"
s.EMPTY:.asciz	"(null)"
s.ERROR:.asciz	": no (or bad) /usr/lib/ld.so.1\n"
l.ERROR= . - s.ERROR
	.align	4
	.size	__rtboot, . - __rtboot

! During construction -- the assembly output of _rtld.c2s is placed here.

	.section ".text"
	.nonvolatile
