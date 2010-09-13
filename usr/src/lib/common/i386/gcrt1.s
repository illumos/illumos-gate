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

/*
 * This gcrt1.o module is provided as the bare minimum required to build a
 * 32-bit profile executable with gcc -pg.  It is installed in /usr/lib
 * where it will be picked up by gcc, along with crti.o and crtn.o
 */

	.ident	"%Z%%M%	%I%	%E% SMI"

	.file	"gcrt1.s"

	.globl	_start
	.globl	_etext

/* global entities defined elsewhere but used here */
	.globl	main
	.globl	__fpstart
	.globl	_init
	.globl	_fini
	.globl	exit
	.globl	_exit
	.globl	monstartup
	.weak	_mcleanup
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

/*
 * Check to see if there is an _mcleanup() function linked in, and if so,
 * register it with atexit() as the last thing to be run by exit().
 */
	pushl	%edx			/* save rt_do_exit for later atexit */

	movl	$_mcleanup,%eax
	testl	%eax,%eax
	jz	1f
	pushl	%eax
	call	atexit
	addl	$4,%esp
1:

	movl	$_DYNAMIC,%eax
	testl	%eax,%eax
	jz	1f
	call	atexit			/* register rt_do_exit */
1:
	addl	$4,%esp

	pushl	$_fini
	call	atexit
	addl	$4,%esp

/* start profiling */
	pushl	%ebp
	movl	%esp,%ebp
	pushl	$_etext
	pushl	$_start
	call	monstartup
	addl	$8,%esp
	popl	%ebp

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
	andl	$-16,%esp	/* align the stack */
	subl	$4,%esp

	pushl	%edx
	leal	12(%ebp),%edx	/* argv */
	movl	%edx,___Argv
	pushl	%edx
	pushl	%eax		/* argc */
	call	__fpstart
	call	_init
	call	main		/* main(argc,argv,envp) */
	addl	$12,%esp
	pushl	%eax		/* return value from main */
	pushl	%eax		/* push it again (for _exit(), below) */
	call	exit
	addl	$4,%esp
	call	_exit		/* if user redefined exit, call _exit */
	addl	$4,%esp
	hlt
	.size	_start, .-_start
