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

/*	Copyright (c) 1983, 1984, 1985, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * Portions of this source code were derived from Berkeley 4.3 BSD
 * under license from the Regents of the University of California.
 */

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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <ucontext.h>
#include <signal.h>
#include <errno.h>

#undef	BUS_OBJERR	/* namespace conflict */
#include <sys/siginfo.h>
#include "libc.h"

#pragma weak sigvechandler = _sigvechandler
#pragma weak sigsetmask = _sigsetmask
#pragma weak sigblock = _sigblock
#pragma weak sigpause = usigpause
#pragma weak sigvec = _sigvec
#pragma weak sigstack = _sigstack
#pragma weak signal = usignal
#pragma weak siginterrupt = _siginterrupt

#define	set2mask(setp) ((setp)->__sigbits[0])
#define	mask2set(mask, setp) \
	((mask) == -1 ? sigfillset(setp) : \
	    (sigemptyset(setp), (((setp)->__sigbits[0]) = (int)(mask))))

void (*_siguhandler[NSIG])() = { 0 };

/* forward declarations */
int ucbsigsetmask(int);
int ucbsigblock(int);
int ucbsigvec(int, struct sigvec *, struct sigvec *);
int ucbsigpause(int);
int ucbsiginterrupt(int, int);

/*
 * sigvechandler is the real signal handler installed for all
 * signals handled in the 4.3BSD compatibility interface - it translates
 * SVR4 signal hander arguments into 4.3BSD signal handler arguments
 * and then calls the real handler
 */

void
_sigvechandler(int sig, siginfo_t *sip, ucontext_t *ucp)
{
	static void ucbsigvechandler();

	ucbsigvechandler(sig, sip, ucp);
}

static void
ucbsigvechandler(int sig, siginfo_t *sip, ucontext_t *ucp)
{
	struct sigcontext sc;
	int code;
	char *addr;
	int i, j;
	int gwinswitch = 0;

	sc.sc_onstack = ((ucp->uc_stack.ss_flags & SS_ONSTACK) != 0);
	sc.sc_mask = set2mask(&ucp->uc_sigmask);

#if defined(__amd64)
	sc.sc_sp = (long)ucp->uc_mcontext.gregs[REG_RSP];
	sc.sc_pc = (long)ucp->uc_mcontext.gregs[REG_RIP];
	sc.sc_ps = (long)ucp->uc_mcontext.gregs[REG_RFL];
	sc.sc_r0 = (long)ucp->uc_mcontext.gregs[REG_RAX];
	sc.sc_r1 = (long)ucp->uc_mcontext.gregs[REG_RDX];
#else
	sc.sc_sp = (int)ucp->uc_mcontext.gregs[UESP];
	sc.sc_pc = (int)ucp->uc_mcontext.gregs[EIP];
	sc.sc_ps = (int)ucp->uc_mcontext.gregs[EFL];
	sc.sc_r0 = (int)ucp->uc_mcontext.gregs[EAX];
	sc.sc_r1 = (int)ucp->uc_mcontext.gregs[EDX];
#endif

	/*
	 * Translate signal codes from new to old.
	 * /usr/include/sys/siginfo.h contains new codes.
	 * /usr/ucbinclude/sys/signal.h contains old codes.
	 */
	code = 0;
	addr = SIG_NOADDR;
	if (sip != NULL && SI_FROMKERNEL(sip)) {
		addr = sip->si_addr;

		switch (sig) {
		case SIGILL:
		case SIGFPE:
			code = ILL_ILLINSTR_FAULT;
			break;

		case SIGBUS:
			switch (sip->si_code) {
			case BUS_ADRALN:
				code = BUS_ALIGN;
				break;
			case BUS_ADRERR:
				code = BUS_HWERR;
				break;
			default:	/* BUS_OBJERR */
				code = FC_MAKE_ERR(sip->si_errno);
				break;
			}
			break;

		case SIGSEGV:
			switch (sip->si_code) {
			case SEGV_MAPERR:
				code = SEGV_NOMAP;
				break;
			case SEGV_ACCERR:
				code = SEGV_PROT;
				break;
			default:
				code = FC_MAKE_ERR(sip->si_errno);
				break;
			}
			break;

		default:
			addr = SIG_NOADDR;
			break;
		}
	}

	(*_siguhandler[sig])(sig, code, &sc, addr);

	if (sc.sc_onstack)
		ucp->uc_stack.ss_flags |= SS_ONSTACK;
	else
		ucp->uc_stack.ss_flags &= ~SS_ONSTACK;
	mask2set(sc.sc_mask, &ucp->uc_sigmask);

#if defined(__amd64)
	ucp->uc_mcontext.gregs[REG_RSP] = (long)sc.sc_sp;
	ucp->uc_mcontext.gregs[REG_RIP] = (long)sc.sc_pc;
	ucp->uc_mcontext.gregs[REG_RFL] = (long)sc.sc_ps;
	ucp->uc_mcontext.gregs[REG_RAX] = (long)sc.sc_r0;
	ucp->uc_mcontext.gregs[REG_RDX] = (long)sc.sc_r1;
#else
	ucp->uc_mcontext.gregs[UESP] = (int)sc.sc_sp;
	ucp->uc_mcontext.gregs[EIP] = (int)sc.sc_pc;
	ucp->uc_mcontext.gregs[EFL] = (int)sc.sc_ps;
	ucp->uc_mcontext.gregs[EAX] = (int)sc.sc_r0;
	ucp->uc_mcontext.gregs[EDX] = (int)sc.sc_r1;
#endif

	setcontext(ucp);
}

int
_sigsetmask(int mask)
{
	return (ucbsigsetmask(mask));
}

int
ucbsigsetmask(int mask)
{
	sigset_t oset;
	sigset_t nset;

	(void) sigprocmask(0, (sigset_t *)0, &nset);
	mask2set(mask, &nset);
	(void) sigprocmask(SIG_SETMASK, &nset, &oset);
	return (set2mask(&oset));
}

int
_sigblock(int mask)
{
	return (ucbsigblock(mask));
}

int
ucbsigblock(int mask)
{
	sigset_t oset;
	sigset_t nset;

	(void) sigprocmask(0, (sigset_t *)0, &nset);
	mask2set(mask, &nset);
	(void) sigprocmask(SIG_BLOCK, &nset, &oset);
	return (set2mask(&oset));
}

int
usigpause(int mask)
{
	return (ucbsigpause(mask));
}

int
ucbsigpause(int mask)
{
	sigset_t set, oset;
	int ret;

	(void) sigprocmask(0, (sigset_t *)0, &set);
	oset = set;
	mask2set(mask, &set);
	ret = sigsuspend(&set);
	(void) sigprocmask(SIG_SETMASK, &oset, (sigset_t *)0);
	return (ret);
}

int
_sigvec(int sig, struct sigvec *nvec, struct sigvec *ovec)
{
	return (ucbsigvec(sig, nvec, ovec));
}

int
ucbsigvec(int sig, struct sigvec *nvec, struct sigvec *ovec)
{
	struct sigaction nact;
	struct sigaction oact;
	struct sigaction *nactp;
	void (*ohandler)(), (*nhandler)();

	if (sig <= 0 || sig >= NSIG) {
		errno = EINVAL;
		return (-1);
	}

	if ((intptr_t)ovec == -1 || (intptr_t)nvec == -1) {
		errno = EFAULT;
		return (-1);
	}

	ohandler = _siguhandler[sig];

	if (nvec) {
		_sigaction(sig, (struct sigaction *)0, &nact);
		nhandler = nvec->sv_handler;
		/*
		 * To be compatible with the behavior of SunOS 4.x:
		 * If the new signal handler is SIG_IGN or SIG_DFL,
		 * do not change the signal's entry in the handler array.
		 * This allows a child of vfork(2) to set signal handlers
		 * to SIG_IGN or SIG_DFL without affecting the parent.
		 */
		if (nhandler != SIG_DFL && nhandler != SIG_IGN) {
			_siguhandler[sig] = nhandler;
			nact.sa_handler = (void (*)())ucbsigvechandler;
		} else {
			nact.sa_handler = nhandler;
		}
		mask2set(nvec->sv_mask, &nact.sa_mask);
		if (sig == SIGKILL || sig == SIGSTOP)
			nact.sa_handler = SIG_DFL;
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
		return (-1);
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

	return (0);
}

int
_sigstack(struct sigstack *nss, struct sigstack *oss)
{
	struct sigaltstack nalt;
	struct sigaltstack oalt;
	struct sigaltstack *naltp;

	if (nss) {
		/*
		 * assumes stack growth is down (like sparc and x86)
		 */
		nalt.ss_sp = nss->ss_sp - SIGSTKSZ;
		nalt.ss_size = SIGSTKSZ;
		nalt.ss_flags = 0;
		naltp = &nalt;
	} else
		naltp = (struct sigaltstack *)0;

	if (sigaltstack(naltp, &oalt) < 0)
		return (-1);

	if (oss) {
		/*
		 * assumes stack growth is down (like sparc and x86)
		 */
		oss->ss_sp = oalt.ss_sp + oalt.ss_size;
		oss->ss_onstack = ((oalt.ss_flags & SS_ONSTACK) != 0);
	}

	return (0);
}

void (*
ucbsignal(int s, void (*a)()))()
{
	struct sigvec osv;
	struct sigvec nsv;
	static int mask[NSIG];
	static int flags[NSIG];

	nsv.sv_handler = a;
	nsv.sv_mask = mask[s];
	nsv.sv_flags = flags[s];
	if (ucbsigvec(s, &nsv, &osv) < 0)
		return (SIG_ERR);
	if (nsv.sv_mask != osv.sv_mask || nsv.sv_flags != osv.sv_flags) {
		mask[s] = nsv.sv_mask = osv.sv_mask;
		flags[s] = nsv.sv_flags =
			osv.sv_flags & ~(SV_RESETHAND|SV_INTERRUPT);
		if (ucbsigvec(s, &nsv, (struct sigvec *)0) < 0)
			return (SIG_ERR);
	}
	return (osv.sv_handler);
}

void (*
usignal(int s, void (*a)()))()
{
	return (ucbsignal(s, a));
}

/*
 * Set signal state to prevent restart of system calls
 * after an instance of the indicated signal.
 */
int
_siginterrupt(int sig, int flag)
{
	return (ucbsiginterrupt(sig, flag));
}

int
ucbsiginterrupt(int sig, int flag)
{
	struct sigvec sv;
	int ret;

	if ((ret = ucbsigvec(sig, 0, &sv)) < 0)
		return (ret);
	if (flag)
		sv.sv_flags |= SV_INTERRUPT;
	else
		sv.sv_flags &= ~SV_INTERRUPT;
	return (ucbsigvec(sig, &sv, 0));
}
