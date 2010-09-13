! CDDL HEADER START
!
! The contents of this file are subject to the terms of the
! Common Development and Distribution License (the "License").
! You may not use this file except in compliance with the License.
!
! You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
! or http://www.opensolaris.org/os/licensing.
! See the License for the specific language governing permissions
! and limitations under the License.
!
! When distributing Covered Code, include this CDDL HEADER in each
! file and include the License file at usr/src/OPENSOLARIS.LICENSE.
! If applicable, add the following below this CDDL HEADER, with the
! fields enclosed by brackets "[]" replaced with your own identifying
! information: Portions Copyright [yyyy] [name of copyright owner]
!
! CDDL HEADER END
!
! Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
! Use is subject to license terms.
!
!	SPARC support routines for 4.x compatibility dynamic linker.

#include <sys/asm_linkage.h>		! N.B.: although this is the 4.x
#include <sys/syscall.h>		! compatibility stuff, it actually
					! runs only on the SVR4 base, and
					! is compiled in an SVR4 .h environment

#define	AT_FDCWD	0xffd19553

! ld.so bootstrap.  Called from crt0 of a dynamically linked program with:
!	%i0:	version number (always 1)
!	%i1:	address of crt0 structure, which contains:
!		+0	base address of where we are mapped
!		+4	open file descriptor for /dev/zero
!		+8	open file descriptor for ld.so
!		+c	a.out _DYNAMIC address
!		+10	environment strings
!		+14	break address for adb/dbx

start_rtld:
	save	%sp,-SA(MINFRAME),%sp	! build frame
L1:
	call    1f			! get absolute address of _GOT_
        nop
1:
        sethi	%hi(__GLOBAL_OFFSET_TABLE_ - (L1 - 1b)), %l7
L2:
	or	%l7, %lo(__GLOBAL_OFFSET_TABLE_ - (L1 - L2)), %l7
	add	%l7, %o7, %l7
	mov	%i0, %o0		! pass version through
	add	%fp, %i1, %l0		! get interface pointer
	mov	%l0, %o1		! ptr to interface structure
	ld	[%l0], %l2		! address where ld.so is mapped in
	ld	[%l7], %l1		! ptr to ld.so first entry in globtable
	add	%l2, %l1, %o2		! relocate ld.so _DYNAMIC
	add	%fp, 0xd8, %o3		! point to arg count (is it safe?)
	ld	[%l7 + _rtld], %g1	! manually fix pic reference to rtld
	add	%g1, %l2, %g1		!   by adding offset to GOT entry
	jmpl	%g1, %o7		! go there
	nop				! delay
	mov	0,%o0
	mov	%o0,%i0
	ret
	restore


!
! aout_reloc_write
!	Update a relocation offset, the value replaces any original
!	value in the relocation offset.
!
 
	.global _aout_reloc_write
 
_aout_reloc_write:
	st	%o1, [%o0]		! Store value in the offset
	retl
	iflush	%o0			! Flush instruction memory


! Special system call stubs to save system call overhead

	.global	_open, _mmap, _munmap, _read, _write, _lseek, _close
	.global	_fstat, _sysconfig, __exit
_open:				! open(path, oflags, mode) =>
	mov	%o2, %o3	! openat(AT_FDCWD, path, oflag, mode)
	mov	%o1, %o2
	mov	%o0, %o1
	sethi	%hi(AT_FDCWD), %o0
	or	%o0, %lo(AT_FDCWD), %o0
	ba	__syscall
	mov	SYS_openat, %g1

_mmap:
	sethi	%hi(0x80000000), %g1	! MAP_NEW
	or	%g1, %o3, %o3
	ba	__syscall
	mov	SYS_mmap, %g1

_munmap:
	ba	__syscall
	mov	SYS_munmap, %g1

_read:
	ba	__syscall
	mov	SYS_read, %g1

_write:
	ba	__syscall
	mov	SYS_write, %g1

_lseek:
	ba	__syscall
	mov	SYS_lseek, %g1

_close:
	ba	__syscall
	mov	SYS_close, %g1

_fstat:				! fstat(fd, statb) =>
	mov	%g0, %o3	! fstatat(fd, NULL, statb, 0)
	mov	%o1, %o2
	mov	%g0, %o1
	ba	__syscall
	mov	SYS_fstatat, %g1

_sysconfig:
	ba	__syscall
	mov	SYS_sysconfig, %g1

__exit:
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
