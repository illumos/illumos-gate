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
#include <sys/asm_linkage.h>

	.file	"mach-crt1.s"

/* global entities defined elsewhere but used here */
	.globl	_start_crt

/*
 * C language startup routine.
 * Assume that exec code has cleared the direction flag in the TSS.
 * Assume that %esp is set to the addr after the last word pushed.
 * The stack contains (in order): argc, argv[],envp[],...
 * Assume that all of the segment registers are initialized.
 *
 * Allocate a NULL return address and a NULL previous %ebp as if
 * there was a genuine call to _start.
 * debugger stack trace shows _start(argc,argv[0],argv[1],...,envp[0],...)
 */
ENTRY_NP(_start)
	pushl	$0
	pushl	$0
	movl	%esp,%ebp		/* The first stack frame */

	/*
	 * The stack needs to be 16-byte aligned with a 4-byte bias.  See
	 * comment in lib/libc/i386/gen/makectxt.c.
	 *
	 * Note: If you change it, you need to change it in the following
	 * files as well:
	 *
	 *  - lib/libc/i386/threads/machdep.c
	 *  - lib/libc/i386/gen/makectxt.c
	 *  - lib/crt/i386/crti.s
	 */
	andl	$-16,%esp	/* make main() and exit() be called with */
	subl	$4,%esp		/* a properly aligned stack pointer */
	pushl	%edx		/* possible atexit handler */
	leal	12(%ebp),%edx	/* argv */
	movl	8(%ebp),%eax	/* argc */
	pushl	%edx
	pushl	%eax
	call	_start_crt
	hlt
SET_SIZE(_start)

#include "fsr.s"

/*
 * The following is here in case any object module compiled with cc -p
 * was linked into this module.
 */
ENTRY_NP(_mcount)
	.weak	_mcount
	ret
SET_SIZE(_mcount)
