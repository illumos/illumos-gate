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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * This crt1.o module is provided as the bare minimum required to build
 * a 32-bit executable with gcc.  It is installed in /usr/lib
 * where it will be picked up by gcc, along with crti.o and crtn.o
 */

	.file	"crt1.s"

	.globl	_start

/* global entities defined elsewhere but used here */
	.globl	main
	.globl	__fpstart
	.globl	exit
	.globl	_exit
	.weak	_DYNAMIC

	.section	.data

	.weak	environ
	.set	environ,_environ
	.globl	_environ
	.type	_environ,@object
	.size	_environ,4
	.align	4
_environ:
	.4byte	0x0

	.globl	__environ_lock
	.type	__environ_lock,@object
	.size	__environ_lock,24
	.align	8
__environ_lock:
	.zero	24

	.globl	___Argv
	.type	___Argv,@object
	.size	___Argv,4
	.align	4
___Argv:
	.4byte	0x0

	.section	.text
	.align	4

/*
 * C language startup routine.
 * Assume that exec code has cleared the direction flag in the TSS.
 * Assume that %esp is set to the addr after the last word pushed.
 * The stack contains (in order): argc, argv[],envp[],...
 * Assume that all of the segment registers are initialized.
 *
 * Allocate a NULL return address and a NULL previous %ebp as if
 * there was a genuine call to _start.
 * sdb stack trace shows _start(argc,argv[0],argv[1],...,envp[0],...)
 */
	.type	_start,@function
_start:
	pushl	$0
	pushl	$0
	movl	%esp,%ebp		/* The first stack frame */

	movl	$_DYNAMIC,%eax
	testl	%eax,%eax
	jz	1f
	pushl	%edx			/* register rt_do_exit */
	call	atexit
	addl	$4,%esp
1:
	pushl	$_fini
	call	atexit
	addl	$4,%esp

/*
 * The following code provides almost standard static destructor handling
 * for systems that do not have the modified atexit processing in their
 * system libraries.  It checks for the existence of the new routine
 * "_get_exit_frame_monitor()", which is in libc.so when the new exit-handling
 * code is there.  It then check for the existence of "__Crun::do_exit_code()"
 * which will be in libCrun.so whenever the code was linked with the C++
 * compiler.  If there is no enhanced atexit, and we do have do_exit_code,
 * we register the latter with atexit.  There are 5 extra slots in
 * atexit, so this will still be standard conforming.  Since the code
 * is registered after the .fini section, it runs before the library
 * cleanup code, leaving nothing for the calls to _do_exit_code_in_range
 * to handle.
 *
 * Remove this code and the associated code in libCrun when the earliest
 * system to be supported is Solaris 8.
 */
	.weak	_get_exit_frame_monitor
	.weak	__1cG__CrunMdo_exit_code6F_v_

	.section	.data
	.align	4
__get_exit_frame_monitor_ptr:
	.4byte	_get_exit_frame_monitor
	.type	__get_exit_frame_monitor_ptr,@object
	.size	__get_exit_frame_monitor_ptr,4

	.align	4
__do_exit_code_ptr:
	.4byte	__1cG__CrunMdo_exit_code6F_v_
	.type	__do_exit_code_ptr,@object
	.size	__do_exit_code_ptr,4

	.section	.text

	lea	__get_exit_frame_monitor_ptr, %eax
	movl	(%eax), %eax
	testl	%eax,%eax
	jz	1f
	lea	__do_exit_code_ptr, %eax
	movl	(%eax), %eax
	testl	%eax, %eax
	jz	1f
	pushl	%eax
	call	atexit		/* atexit(__Crun::do_exit_code()) */
	addl	$4,%esp
1:

/*
 * End of destructor handling code
 */

/*
 * Calculate the location of the envp array by adding the size of
 * the argv array to the start of the argv array.
 */

	movl	8(%ebp),%eax		/* argc */
	movl	_environ, %edx		/* fixed bug 4302802 */
	testl	%edx, %edx		/* check if _enviorn==0 */
	jne	1f			/* fixed bug 4203802 */
	leal	16(%ebp,%eax,4),%edx	/* envp */
	movl	%edx,_environ		/* copy to _environ */
1:
	/*
	 * The stack needs to be 16-byte aligned with a 4-byte bias.  See
	 * comment in lib/libc/i386/gen/makectxt.c.
	 *
	 * Note: If you change it, you need to change it in the following
	 * files as well:
	 *
	 *  - lib/libc/i386/threads/machdep.c
	 *  - lib/libc/i386/gen/makectxt.c
	 *  - lib/common/i386/crti.s
	 */
	andl	$-16,%esp	/* make main() and exit() be called with */
	subl	$4,%esp		/* a properly aligned stack pointer */
	pushl	%edx
	leal	12(%ebp),%edx	/* argv */
	movl	%edx,___Argv
	pushl	%edx
	pushl	%eax		/* argc */
	call	__fpstart
	call	__fsr		/* support for ftrap/fround/fprecision  */
	call	_init
	call	main		/* main(argc,argv,envp) */
	movl	%eax,(%esp)	/* return value from main, for exit() */
	movl	%eax,4(%esp)	/* remember it for _exit(), below */
	call	exit
	movl	4(%esp),%eax	/* if user redefined exit, call _exit */
	movl	%eax,(%esp)
	call	_exit
	hlt
	.size	_start, .-_start

#include "fsr.s"

/*
 * The following is here in case any object module compiled with cc -p
 *	was linked into this module.
 */
	.section	.text
	.align	4
	.globl	_mcount
	.type	_mcount,@function
_mcount:
	ret
	.size	_mcount, .-_mcount

	.section	.data

	.globl	__longdouble_used
	.type	__longdouble_used,@object
	.size	__longdouble_used,4
	.align	4
__longdouble_used:
	.4byte	0x0
