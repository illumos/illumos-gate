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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

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

/*
 * DO NOT remove the _ from these 3 functions or the subsequent
 * calls to them below.  The non _ versions of these functions
 * are the wrong functions to call.  This is BCP.  Extra
 * care should be taken when modifying this code.
 */
extern int _sigfillset(sigset_t *);
extern int _sigemptyset(sigset_t *);
extern int _sigprocmask(int, const sigset_t *, sigset_t *);

#define	set2mask(setp) ((setp)->__sigbits[0])
#define	mask2set(mask, setp) \
	((mask) == -1 ? _sigfillset(setp) : \
	    ((void) _sigemptyset(setp), (((setp)->__sigbits[0]) = (int)(mask))))

void (*_siguhandler[NSIG])() = { 0 };

/*
 * forward declarations
 */
int ucbsiginterrupt(int, int);
int ucbsigvec(int, struct sigvec *, struct sigvec *);
int ucbsigpause(int);
int ucbsigblock(int);
int ucbsigsetmask(int);
static void ucbsigvechandler(int, siginfo_t *, ucontext_t *);

/*
 * sigvechandler is the real signal handler installed for all
 * signals handled in the 4.3BSD compatibility interface - it translates
 * SVR4 signal hander arguments into 4.3BSD signal handler arguments
 * and then calls the real handler
 */

int
_sigvechandler(int sig, siginfo_t *sip, ucontext_t *ucp)
{
	ucbsigvechandler(sig, sip, ucp);
	return (0);	/* keep the same as the original prototype */
}

static void
ucbsigvechandler(int sig, siginfo_t *sip, ucontext_t *ucp)
{
	struct sigcontext sc;
	int code;
	char *addr;
#ifdef NEVER
	int gwinswitch = 0;
#endif

	sc.sc_onstack = ((ucp->uc_stack.ss_flags & SS_ONSTACK) != 0);
	sc.sc_mask = set2mask(&ucp->uc_sigmask);

#if defined(__sparc)
	if (sig == SIGFPE && sip != NULL && SI_FROMKERNEL(sip) &&
	    (sip->si_code == FPE_INTDIV || sip->si_code == FPE_INTOVF)) {
		/*
		 * Hack to emulate the 4.x kernel behavior of incrementing
		 * the PC on integer divide by zero and integer overflow
		 * on sparc machines.  (5.x does not increment the PC.)
		 */
		ucp->uc_mcontext.gregs[REG_PC] =
		    ucp->uc_mcontext.gregs[REG_nPC];
		ucp->uc_mcontext.gregs[REG_nPC] += 4;
	}
	sc.sc_sp = ucp->uc_mcontext.gregs[REG_SP];
	sc.sc_pc = ucp->uc_mcontext.gregs[REG_PC];
	sc.sc_npc = ucp->uc_mcontext.gregs[REG_nPC];

	/* XX64 There is no REG_PSR for sparcv9, we map in REG_CCR for now */
#if defined(__sparcv9)
	sc.sc_psr = ucp->uc_mcontext.gregs[REG_CCR];
#else
	sc.sc_psr = ucp->uc_mcontext.gregs[REG_PSR];
#endif

	sc.sc_g1 = ucp->uc_mcontext.gregs[REG_G1];
	sc.sc_o0 = ucp->uc_mcontext.gregs[REG_O0];

	/*
	 * XXX - What a kludge!
	 * Store a pointer to the original ucontext_t in the sigcontext
	 * so that it's available to the sigcleanup call that needs to
	 * return from the signal handler.  Otherwise, vital information
	 * (e.g., the "out" registers) that's only saved in the
	 * ucontext_t isn't available to sigcleanup.
	 */
	sc.sc_wbcnt = (int)(sizeof (*ucp));
	sc.sc_spbuf[0] = (char *)(uintptr_t)sig;
	sc.sc_spbuf[1] = (char *)ucp;
#ifdef NEVER
	/*
	 * XXX - Sorry, we can never pass the saved register windows
	 * on in the sigcontext because we use that space to save the
	 * ucontext_t.
	 */
	if (ucp->uc_mcontext.gwins != (gwindows_t *)0) {
		int i, j;

		gwinswitch = 1;
		sc.sc_wbcnt = ucp->uc_mcontext.gwins->wbcnt;
		/* XXX - should use bcopy to move this in bulk */
		for (i = 0; i < ucp->uc_mcontext.gwins; i++) {
			sc.sc_spbuf[i] = ucp->uc_mcontext.gwins->spbuf[i];
			for (j = 0; j < 8; j++)
				sc.sc_wbuf[i][j] =
				    ucp->uc_mcontext.gwins->wbuf[i].rw_local[j];
			for (j = 0; j < 8; j++)
				sc.sc_wbuf[i][j+8] =
				    ucp->uc_mcontext.gwins->wbuf[i].rw_in[j];
		}
	}
#endif
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
			switch (sip->si_code) {
			case ILL_PRVOPC:
				code = ILL_PRIVINSTR_FAULT;
				break;
			case ILL_BADSTK:
				code = ILL_STACK;
				break;
			case ILL_ILLTRP:
				code = ILL_TRAP_FAULT(sip->si_trapno);
				break;
			default:
				code = ILL_ILLINSTR_FAULT;
				break;
			}
			break;

		case SIGEMT:
			code = EMT_TAG;
			break;

		case SIGFPE:
			switch (sip->si_code) {
			case FPE_INTDIV:
				code = FPE_INTDIV_TRAP;
				break;
			case FPE_INTOVF:
				code = FPE_INTOVF_TRAP;
				break;
			case FPE_FLTDIV:
				code = FPE_FLTDIV_TRAP;
				break;
			case FPE_FLTOVF:
				code = FPE_FLTOVF_TRAP;
				break;
			case FPE_FLTUND:
				code = FPE_FLTUND_TRAP;
				break;
			case FPE_FLTRES:
				code = FPE_FLTINEX_TRAP;
				break;
			default:
				code = FPE_FLTOPERR_TRAP;
				break;
			}
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

#if defined(__sparc)
	ucp->uc_mcontext.gregs[REG_SP] = sc.sc_sp;
	ucp->uc_mcontext.gregs[REG_PC] = sc.sc_pc;
	ucp->uc_mcontext.gregs[REG_nPC] = sc.sc_npc;
#if defined(__sparcv9)
	ucp->uc_mcontext.gregs[REG_CCR] = sc.sc_psr;
#else
	ucp->uc_mcontext.gregs[REG_PSR] = sc.sc_psr;
#endif
	ucp->uc_mcontext.gregs[REG_G1] = sc.sc_g1;
	ucp->uc_mcontext.gregs[REG_O0] = sc.sc_o0;
#ifdef NEVER
	if (gwinswitch == 1) {
		int i, j;

		ucp->uc_mcontext.gwins->wbcnt = sc.sc_wbcnt;
		/* XXX - should use bcopy to move this in bulk */
		for (i = 0; i < sc.sc_wbcnt; i++) {
			ucp->uc_mcontext.gwins->spbuf[i] = sc.sc_spbuf[i];
			for (j = 0; j < 8; j++)
				ucp->uc_mcontext.gwins->wbuf[i].rw_local[j] =
				    sc.sc_wbuf[i][j];
			for (j = 0; j < 8; j++)
				ucp->uc_mcontext.gwins->wbuf[i].rw_in[j] =
				    sc.sc_wbuf[i][j+8];
		}
	}
#endif

	if (sig == SIGFPE) {
		if (ucp->uc_mcontext.fpregs.fpu_qcnt > 0) {
			ucp->uc_mcontext.fpregs.fpu_qcnt--;
			ucp->uc_mcontext.fpregs.fpu_q++;
		}
	}
#endif

	(void) setcontext(ucp);
}

#if defined(__sparc)
/*
 * Emulate the special sigcleanup trap.
 * This is only used by statically linked 4.x applications
 * and thus is only called by the static BCP support.
 * It lives here because of its close relationship with
 * the ucbsigvechandler code above.
 *
 * It's used by 4.x applications to:
 *	1. return from a signal handler (in __sigtramp)
 *	2. [sig]longjmp
 *	3. context switch, in the old 4.x liblwp
 */

void
__sigcleanup(struct sigcontext *scp)
{
	ucontext_t uc, *ucp;
	int sig;

	/*
	 * If there's a pointer to a ucontext_t hiding in the sigcontext,
	 * we *must* use that to return, since it contains important data
	 * such as the original "out" registers when the signal occurred.
	 */
	if (scp->sc_wbcnt == sizeof (*ucp)) {
		sig = (int)(uintptr_t)scp->sc_spbuf[0];
		ucp = (ucontext_t *)scp->sc_spbuf[1];
	} else {
		/*
		 * Otherwise, use a local ucontext_t and
		 * initialize it with getcontext.
		 */
		sig = 0;
		ucp = &uc;
		(void) getcontext(ucp);
	}

	if (scp->sc_onstack) {
		ucp->uc_stack.ss_flags |= SS_ONSTACK;
	} else
		ucp->uc_stack.ss_flags &= ~SS_ONSTACK;
	mask2set(scp->sc_mask, &ucp->uc_sigmask);

	ucp->uc_mcontext.gregs[REG_SP] = scp->sc_sp;
	ucp->uc_mcontext.gregs[REG_PC] = scp->sc_pc;
	ucp->uc_mcontext.gregs[REG_nPC] = scp->sc_npc;
#if defined(__sparcv9)
	ucp->uc_mcontext.gregs[REG_CCR] = scp->sc_psr;
#else
	ucp->uc_mcontext.gregs[REG_PSR] = scp->sc_psr;
#endif
	ucp->uc_mcontext.gregs[REG_G1] = scp->sc_g1;
	ucp->uc_mcontext.gregs[REG_O0] = scp->sc_o0;

	if (sig == SIGFPE) {
		if (ucp->uc_mcontext.fpregs.fpu_qcnt > 0) {
			ucp->uc_mcontext.fpregs.fpu_qcnt--;
			ucp->uc_mcontext.fpregs.fpu_q++;
		}
	}
	(void) setcontext(ucp);
	/* NOTREACHED */
}
#endif

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

	(void) _sigprocmask(0, (sigset_t *)0, &nset);
	mask2set(mask, &nset);
	(void) _sigprocmask(SIG_SETMASK, &nset, &oset);
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

	(void) _sigprocmask(0, (sigset_t *)0, &nset);
	mask2set(mask, &nset);
	(void) _sigprocmask(SIG_BLOCK, &nset, &oset);
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

	(void) _sigprocmask(0, (sigset_t *)0, &set);
	oset = set;
	mask2set(mask, &set);
	ret = sigsuspend(&set);
	(void) _sigprocmask(SIG_SETMASK, &oset, (sigset_t *)0);
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
	void (*ohandler)(int, int, struct sigcontext *, char *);
	void (*nhandler)(int, int, struct sigcontext *, char *);

	if (sig <= 0 || sig >= NSIG) {
		errno = EINVAL;
		return (-1);
	}

	if ((long)ovec == -1L || (long)nvec == -1L) {
		errno = EFAULT;
		return (-1);
	}

	ohandler = _siguhandler[sig];

	if (nvec) {
		(void) _sigaction(sig, (struct sigaction *)0, &nact);
		nhandler = nvec->sv_handler;
		/*
		 * To be compatible with the behavior of SunOS 4.x:
		 * If the new signal handler is SIG_IGN or SIG_DFL,
		 * do not change the signal's entry in the handler array.
		 * This allows a child of vfork(2) to set signal handlers
		 * to SIG_IGN or SIG_DFL without affecting the parent.
		 */
		if ((void (*)(int))nhandler != SIG_DFL &&
		    (void (*)(int))nhandler != SIG_IGN) {
			_siguhandler[sig] = nhandler;
			nact.sa_handler = (void (*)(int))ucbsigvechandler;
		} else {
			nact.sa_handler = (void (*)(int))nhandler;
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
			ovec->sv_handler =
			    (void (*) (int, int, struct sigcontext *, char *))
			    oact.sa_handler;
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
		 * XXX: assumes stack growth is down (like sparc)
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
		 * XXX: assumes stack growth is down (like sparc)
		 */
		oss->ss_sp = oalt.ss_sp + oalt.ss_size;
		oss->ss_onstack = ((oalt.ss_flags & SS_ONSTACK) != 0);
	}

	return (0);
}

void (*
ucbsignal(int s, void (*a)(int)))(int)
{
	struct sigvec osv;
	struct sigvec nsv;
	static int mask[NSIG];
	static int flags[NSIG];

	nsv.sv_handler = (void (*) (int, int, struct sigcontext *, char *)) a;
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
	return ((void (*) (int)) osv.sv_handler);
}

void (*
usignal(int s, void (*a) (int)))(int)
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
