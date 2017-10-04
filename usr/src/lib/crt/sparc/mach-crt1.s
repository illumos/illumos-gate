/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
	
/* Copyright 2016, Richard Lowe. */

#include <sys/asm_linkage.h>
#include <sys/stack.h>

	.file	"mach-crt1.s"

	.global	_start_crt

#if defined(__sparcv9)
#define	EB_MAX_SIZE	128
#else
#define	EB_MAX_SIZE	64
#endif

ENTRY_NP(_start)
	/*
	 * On entry, the stack is:
	 *
	 * .-----------------------.   <--- %sp
	 * |			   |
	 * |	    Window	   |
	 * |			   |
	 * |-----------------------|
	 * |	    argc	   |
	 * |-----------------------|
	 * |	    argv[0]	   |
	 * |	    argv[1]	   |
	 * |	    argv[2]	   |
	 * |	    argv[3]	   |
	 * |	    ...		   |
	 * |	 argv[argc - 1]	   |
	 * |-----------------------|
	 * |	      NULL	   |
	 * |-----------------------|
	 * |	    envp[0]	   |
	 * |	    envp[1]	   |
	 * |	    envp[2]	   |
	 * |	    envp[3]	   |
	 * |	     ...	   |
	 * |	    envp[N]	   |
	 * |-----------------------|
	 * |	      NULL	   |
	 * .-----------------------.
	 *
	 * and an exit handler from the linker is in %g1
	 */
	clr	%fp		! don't trace the stack past this point 

	add	%sp, WINDOWSIZE + STACK_BIAS, %l0	! address of argc

	! allocate a minimally sized frame, and align ourselves
	add	%sp, -SA(MINFRAME - EB_MAX_SIZE), %sp

	ldn	[%l0], %o0			! argc
	add	%l0, CPTRSIZE, %o1	! argv
	call	_start_crt
	    mov %g1, %o2			! exit_handler in delay slot
SET_SIZE(_start)
