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
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

#ifndef _SYS_LX_SIGSTACK_H
#define	_SYS_LX_SIGSTACK_H

#if !defined(_ASM)
#include <sys/lx_types.h>
#include <sys/ucontext.h>
#include <sys/lx_signal.h>
#include <lx_signum.h>

#endif	/* !defined(_ASM) */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Two flavors of Linux signal stacks:
 *
 * lx_sigstack - used for "modern" signal handlers, in practice those
 *               that have the sigaction(2) flag SA_SIGINFO set
 *
 * lx_oldsigstack - used for legacy signal handlers, those that do not have
 *		    the sigaction(2) flag SA_SIGINFO set or that were setup via
 *		    the signal(2) call.
 *
 * NOTE: Since these structures will be placed on the stack and stack math will
 *	 be done with their sizes, for the 32-bit code they must be word
 *	 aligned in size (4 bytes) so the stack remains word aligned per the
 *	 i386 ABI, or, for 64-bit code they must be 16 byte aligned as per the
 *	 AMD64 ABI.
 */
#if defined(_LP64)
typedef struct lx_sigstack {
	void (*retaddr)();	/* address of real lx_rt_sigreturn code */
	lx_siginfo_t si;	/* saved signal information */
	lx_ucontext_t uc;	/* saved user context */
	lx_fpstate_t fpstate;	/* saved FP state */
	char pad[2];		/* stack alignment */
} lx_sigstack_t;
#else
struct lx_sigstack {
	void (*retaddr)();	/* address of real lx_rt_sigreturn code */
	int sig;		/* signal number */
	lx_siginfo_t *sip;	/* points to "si" if valid, NULL if not */
	lx_ucontext_t *ucp;	/* points to "uc" */
	lx_siginfo_t si;	/* saved signal information */
	lx_ucontext_t uc;	/* saved user context */
	lx_fpstate_t fpstate;	/* saved FP state */
	char trampoline[8];	/* code for trampoline to lx_rt_sigreturn() */
};
#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_LX_SIGSTACK_H */
