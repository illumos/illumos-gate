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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2015 Joyent, Inc.
 */

#include <sys/asm_linkage.h>
#include <sys/regset.h>
#include <sys/segments.h>
#include <sys/syscall.h>
#include <sys/lx_brand.h>

#if defined(_ASM)
#include <sys/lx_signal.h>
#include <sys/lx_syscall.h>
#endif	/* _ASM */

#include "assym.h"

/* 64-bit signal syscall numbers */
#define	LX_SYS_rt_sigreturn	15

#if defined(lint)

#include <sys/types.h>
#include <sys/regset.h>
#include <sys/signal.h>

void
lx_rt_sigreturn_tramp(void)
{}

#else	/* lint */

	/*
	 * Trampoline code is called by the return at the end of a Linux
	 * signal handler to return control to the interrupted application
	 * via the lx_rt_sigreturn() syscall.
	 */
	ENTRY_NP(lx_rt_sigreturn_tramp)
	movq	$LX_SYS_rt_sigreturn, %rax
	syscall
	SET_SIZE(lx_rt_sigreturn_tramp)

#endif	/* lint */
