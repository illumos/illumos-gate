/*
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Copyright (c) 1980 Regents of the University of California.
 * All rights reserved. The Berkeley Software License Agreement
 * specifies the terms and conditions for redistribution.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * 4.3BSD signal compatibility functions
 *
 * the implementation interprets signal masks equal to -1 as "all of the
 * signals in the signal set", thereby allowing signals with numbers
 * above 32 to be blocked when referenced in code such as:
 *
 *	for (i = 0; i < NSIG; i++)
 *		mask |= sigmask(i)
 */

#include <sys/types.h>
#include <sys/siginfo.h>
#include <sys/ucontext.h>
#include <signal.h>
#include "signal.h"
#include <errno.h>
#include <stdio.h>

#define set2mask(setp) ((setp)->__sigbits[0])
#define mask2set(mask, setp) \
	((mask) == -1 ? sigfillset(setp) : sigemptyset(setp), (((setp)->__sigbits[0]) = (mask)))

void (*_siguhandler[NSIG])() = { 0 };

/*
 * sigstack is emulated with sigaltstack by guessing an appropriate
 * value for the stack size - on machines that have stacks that grow 
 * upwards, the ss_sp arguments for both functions mean the same thing, 
 * (the initial stack pointer sigstack() is also the stack base 
 * sigaltstack()), so a "very large" value should be chosen for the 
 * stack size - on machines that have stacks that grow downwards, the
 * ss_sp arguments mean opposite things, so 0 should be used (hopefully
 * these machines don't have hardware stack bounds registers that pay
 * attention to sigaltstack()'s size argument.
 */

#ifdef sun
#define SIGSTACKSIZE	0
#endif


/*
 * sigvechandler is the real signal handler installed for all
 * signals handled in the 4.3BSD compatibility interface - it translates
 * SVR4 signal hander arguments into 4.3BSD signal handler arguments
 * and then calls the real handler
 */

static void
sigvechandler(int sig, siginfo_t *sip, ucontext_t *ucp) 
{
	struct sigcontext sc;
	int code;
	char *addr;
	int i, j;
	int gwinswitch = 0;
	
	sc.sc_onstack = ((ucp->uc_stack.ss_flags & SS_ONSTACK) != 0);
	sc.sc_mask = set2mask(&ucp->uc_sigmask);

	/* 
	 * Machine dependent code begins
	 */
	sc.sc_sp = (int) ucp->uc_mcontext.gregs[UESP];
	sc.sc_pc = (int) ucp->uc_mcontext.gregs[EIP];
	sc.sc_ps = (int) ucp->uc_mcontext.gregs[EFL];
	sc.sc_eax = (int) ucp->uc_mcontext.gregs[EAX];
	sc.sc_edx = (int) ucp->uc_mcontext.gregs[EDX];

	/*
	 * Machine dependent code ends
	 */

	if (sip != NULL)
		if ((code = sip->si_code) == BUS_OBJERR)
			code = SEGV_MAKE_ERR(sip->si_errno);

	if (sig == SIGILL || sig == SIGFPE || sig == SIGSEGV || sig == SIGBUS)
		if (sip != NULL)
			addr = (char *)sip->si_addr;
	else
		addr = SIG_NOADDR;
	
	(*_siguhandler[sig])(sig, code, &sc, addr);

	if (sc.sc_onstack)
		ucp->uc_stack.ss_flags |= SS_ONSTACK;
	else
		ucp->uc_stack.ss_flags &= ~SS_ONSTACK;
	mask2set(sc.sc_mask, &ucp->uc_sigmask);

	/* 
	 * Machine dependent code begins
	 */
	ucp->uc_mcontext.gregs[UESP] = (int) sc.sc_sp;
	ucp->uc_mcontext.gregs[EIP] = (int) sc.sc_pc;
	ucp->uc_mcontext.gregs[EFL] = (int) sc.sc_ps;
	ucp->uc_mcontext.gregs[EAX] = (int) sc.sc_eax;
	ucp->uc_mcontext.gregs[EDX] = (int) sc.sc_edx;
	/*
	 * Machine dependent code ends
	 */

	setcontext (ucp);
}

int
sigsetmask(int mask)
{
	sigset_t oset;
	sigset_t nset;

	(void) sigprocmask(0, (sigset_t *)0, &nset);
	mask2set(mask, &nset);
	(void) sigprocmask(SIG_SETMASK, &nset, &oset);
	return set2mask(&oset);
}

int
sigblock(int mask)
{
	sigset_t oset;
	sigset_t nset;

	(void) sigprocmask(0, (sigset_t *)0, &nset);
	mask2set(mask, &nset);
	(void) sigprocmask(SIG_BLOCK, &nset, &oset);
	return set2mask(&oset);
}

int
sigpause(int mask)
{
	sigset_t set;

	(void) sigprocmask(0, (sigset_t *)0, &set);
	mask2set(mask, &set);
	return (sigsuspend(&set));
}

int
sigvec(int sig, struct sigvec *nvec, struct sigvec *ovec)
{
        struct sigaction nact;
        struct sigaction oact;
        struct sigaction *nactp;
        void (*ohandler)(), (*nhandler)();

        if (sig <= 0 || sig >= NSIG) {
                errno = EINVAL;
                return -1;
        }

        ohandler = _siguhandler[sig];

        if (nvec) {
		_sigaction(sig, (struct sigaction *)0, &nact);
                nhandler = nvec->sv_handler; 
                _siguhandler[sig] = nhandler;
                if (nhandler != SIG_DFL && nhandler != SIG_IGN)
                        nact.sa_handler = (void (*)())sigvechandler;
		else
			nact.sa_handler = nhandler;
		mask2set(nvec->sv_mask, &nact.sa_mask);
		/*
		if ( sig == SIGTSTP || sig == SIGSTOP )
			nact.sa_handler = SIG_DFL; 	*/
		nact.sa_flags = SA_SIGINFO;
		if (!(nvec->sv_flags & SV_INTERRUPT))
			nact.sa_flags |= SA_RESTART;
		if (nvec->sv_flags & SV_RESETHAND)
			nact.sa_flags |= SA_RESETHAND;
		if (nvec->sv_flags & SV_ONSTACK)
			nact.sa_flags |= SA_ONSTACK;
		nactp = &nact;
        } else
		nactp = (struct sigaction *)0;

        if (_sigaction(sig, nactp, &oact) < 0) {
                _siguhandler[sig] = ohandler;
                return -1;
        }

        if (ovec) {
		if (oact.sa_handler == SIG_DFL || oact.sa_handler == SIG_IGN)
			ovec->sv_handler = oact.sa_handler;
		else
			ovec->sv_handler = ohandler;
		ovec->sv_mask = set2mask(&oact.sa_mask);
		ovec->sv_flags = 0;
		if (oact.sa_flags & SA_ONSTACK)
			ovec->sv_flags |= SV_ONSTACK;
		if (oact.sa_flags & SA_RESETHAND)
			ovec->sv_flags |= SV_RESETHAND;
		if (!(oact.sa_flags & SA_RESTART))
			ovec->sv_flags |= SV_INTERRUPT;
	}
			
        return 0;
}


void (*
signal(int s, void (*a)()))()
{
        struct sigvec osv;
	struct sigvec nsv;
        static int mask[NSIG];
        static int flags[NSIG];

	nsv.sv_handler = a;
	nsv.sv_mask = mask[s];
	nsv.sv_flags = flags[s];
        if (sigvec(s, &nsv, &osv) < 0)
                return (SIG_ERR);
        if (nsv.sv_mask != osv.sv_mask || nsv.sv_flags != osv.sv_flags) {
                mask[s] = nsv.sv_mask = osv.sv_mask;
                flags[s] = nsv.sv_flags = osv.sv_flags & ~SV_RESETHAND;
                if (sigvec(s, &nsv, (struct sigvec *)0) < 0)
                        return (SIG_ERR);
        }
        return (osv.sv_handler);
}
