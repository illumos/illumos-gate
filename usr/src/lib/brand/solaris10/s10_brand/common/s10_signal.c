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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/types.h>
#include <sys/brand.h>
#include <sys/errno.h>
#include <sys/sysconfig.h>
#include <sys/ucontext.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <strings.h>
#include <signal.h>

#include <s10_brand.h>
#include <brand_misc.h>
#include <s10_misc.h>
#include <s10_signal.h>

s10_sighandler_t s10_handlers[S10_NSIG - 1];

/*
 * Theory of operation:
 *
 * As of now, Solaris 10 and solaris_nevada signal numbers match all the
 * way through SIGJVM2 (1 - 40) and the first 8 realtime signals (41 - 48).
 * However, solaris_nevada provides 32 realtime signals rather than 8 for S10.
 *
 * We do not assume that the current range of realtime signals is
 * _SIGRTMIN - _SIGRTMAX.  As a hedge against future changes,
 * we obtain the realtime signal range via SIGRTMIN and SIGRTMAX.
 *
 * Therefore, we must interpose on the various signal calls to translate
 * signal masks and signal handlers that deal with SIGRTMIN - SIGRTMAX to
 * refer to a potentially different range and to intercenpt any "illegal"
 * signals that might otherwise be sent to an S10 process.
 *
 * Important exception:
 * We cannot interpose on the SYS_context system call in order to deal with the
 * sigset_t contained within the ucontext_t structure because the getcontext()
 * part of this system call trap would then return an incorrect set of machine
 * registers.  See the getcontext() functions in libc to get the gory details.
 * The kernel code for getcontext() and setcontext() has been made brand-aware
 * in order to deal with this.
 *
 * Simple translation is all that is required to handle most system calls,
 * but signal handlers also must be interposed upon so that a user signal
 * handler sees proper signal numbers in its arguments, any passed siginfo_t
 * and in the signal mask reported in its ucontext_t.
 *
 * libc adds its own signal handler to handled signals such that the
 * signal delivery mechanism looks like:
 *
 * signal ->
 *     libc sigacthandler() ->
 *         user signal handler()
 *
 * With interposition, this will instead look like:
 *
 * signal ->
 *     s10_sigacthandler() ->
 *         libc sigacthandler() ->
 *             user signal handler()
 */

/*
 * A little exposition on SIGRTMIN and SIGRTMAX:
 *
 * For configurability reasons, in Solaris SIGRTMIN and SIGRTMAX are actually
 * #defined to be routines:
 *
 *    #define SIGRTMIN ((int)_sysconf(_SC_SIGRT_MIN))
 *    #define SIGRTMAX ((int)_sysconf(_SC_SIGRT_MAX))
 *
 * This means we need routines that will call the native sysconfig() system
 * call to find out what the native values for SIGRTMIN and SIGRTMAX are, and
 * those are native_sigrtmin() and native_sigrtmax(), respectively.
 *
 * To try and mitigate confusion this might cause, rather than use SIGRTMIN and
 * SIGRTMAX directly, mnemonic convenience macros are #defined to clarify the
 * matter:
 *
 *     S10_SIGRTMIN
 *     S10_SIGRTMAX
 *     NATIVE_SIGRTMIN
 *     NATIVE_SIGRTMAX
 */

static int
native_sigrtmin()
{
	static int sigrtmin;
	sysret_t rval;

	if (sigrtmin)
		return (sigrtmin);
	sigrtmin = __systemcall(&rval, SYS_sysconfig + 1024, _CONFIG_SIGRT_MIN)?
	    _SIGRTMIN : (int)rval.sys_rval1;
	return (sigrtmin);
}

static int
native_sigrtmax()
{
	static int sigrtmax;
	sysret_t rval;

	if (sigrtmax)
		return (sigrtmax);
	sigrtmax = __systemcall(&rval, SYS_sysconfig + 1024, _CONFIG_SIGRT_MAX)?
	    _SIGRTMAX : (int)rval.sys_rval1;
	return (sigrtmax);
}

#define	NATIVE_SIGRTMIN		(native_sigrtmin())
#define	NATIVE_SIGRTMAX		(native_sigrtmax())

/*
 * These #defines are setup to create the SIGADDSET and SIGISMEMBER macros,
 * needed because the sigaddset(3C) and sigismember(3C) calls make function
 * calls that end up being recursive in an interpositioned system call
 * environment.
 */
#define	MAXBITNO	(NBPW*8)
#define	SIGWORD(n)	((n-1)/MAXBITNO)
#define	BITMASK(n)	(1L<<((n-1)%MAXBITNO))

#define	SIGADDSET(sigset, sig) \
	((sigset)->__sigbits[SIGWORD(sig)] |= BITMASK(sig))

#define	SIGISMEMBER(sigset, sig) \
	(((sigset)->__sigbits[SIGWORD(sig)] & BITMASK(sig)) != 0)

/*
 * Convert an S10 signal number to its native value.
 */
static int
s10sig_to_native(int sig)
{
	/* signals 1 .. SIGJVM2 are the same between S10 and native */
	if (sig <= SIGJVM2)
		return (sig);

	/*
	 * If a signal is > SIGJVM2 but is < S10_SIGRTMIN, it's being used
	 * for some private purpose we likely wouldn't emulate properly.
	 */
	if (sig < S10_SIGRTMIN)		/* can't happen */
		return (-1);

	/*
	 * If an app passes in a signal that is out of range, it
	 * expects to get back EINVAL.
	 */
	if (sig > S10_MAXSIG)
		return (-1);

	/*
	 * Map S10 RT signals to their native counterparts to the degree
	 * possible.  If the signal would be out of the native RT signal
	 * range, return an error to the caller.
	 */
	sig -= S10_SIGRTMIN;

	if (sig > (NATIVE_SIGRTMAX - NATIVE_SIGRTMIN))
		return (-1);

	return (NATIVE_SIGRTMIN + sig);
}

/*
 * Convert an S10 sigset_t to its native version.
 */
int
s10sigset_to_native(const sigset_t *s10_set, sigset_t *native_set)
{
	int sig;
	int nativesig;
	sigset_t srcset, newset;

	if (brand_uucopy(s10_set, &srcset, sizeof (sigset_t)) != 0)
		return (EFAULT);

	(void) sigemptyset(&newset);

	/*
	 * Shortcut: we know the first 32 signals are the same in both
	 * s10 and native Solaris.  Just assign the first word.
	 */
	newset.__sigbits[0] = srcset.__sigbits[0];

	/*
	 * Copy the remainder of the initial set of common signals.
	 */
	for (sig = 33; sig <= SIGJVM2; sig++)
		if (SIGISMEMBER(&srcset, sig))
			SIGADDSET(&newset, sig);

	/* convert any S10 RT signals to their native equivalents */
	for (sig = S10_SIGRTMIN; sig <= S10_SIGRTMAX; sig++) {
		if (SIGISMEMBER(&srcset, sig) &&
		    (nativesig = s10sig_to_native(sig)) > 0)
			SIGADDSET(&newset, nativesig);
	}

	if (brand_uucopy(&newset, native_set, sizeof (sigset_t)) != 0)
		return (EFAULT);

	return (0);
}

/*
 * Convert a native signal number to its S10 value.
 */
int
nativesig_to_s10(int sig)
{
	/* signals 1 .. SIGJVM2 are the same between native and S10 */
	if (sig <= SIGJVM2)
		return (sig);

	/*
	 * We have no way to emulate native signals between (SIGJVM2 + 1) and
	 * NATIVE_SIGRTMIN, so return an error to the caller.
	 */
	if (sig < NATIVE_SIGRTMIN)	/* can't happen */
		return (-1);

	/*
	 * Map native RT signals to their S10 counterparts to the degree
	 * possible.  If the signal would be out of range for S10, return
	 * an error to the caller.
	 */
	sig -= NATIVE_SIGRTMIN;

	if (sig > (S10_SIGRTMAX - S10_SIGRTMIN))
		return (-1);

	return (S10_SIGRTMIN + sig);
}

/*
 * Convert a native sigset_t to its S10 version.
 */
int
nativesigset_to_s10(const sigset_t *native_set, sigset_t *s10_set)
{
	int sig;
	int s10sig;
	sigset_t srcset, newset;

	if (brand_uucopy(native_set, &srcset, sizeof (sigset_t)) != 0)
		return (EFAULT);

	(void) sigemptyset(&newset);

	/*
	 * Shortcut: we know the first 32 signals are the same in both
	 * s10 and native Solaris.  Just assign the first word.
	 */
	newset.__sigbits[0] = srcset.__sigbits[0];

	/*
	 * Copy the remainder of the initial set of common signals.
	 */
	for (sig = 33; sig <= SIGJVM2; sig++)
		if (SIGISMEMBER(&srcset, sig))
			SIGADDSET(&newset, sig);

	/* convert any RT signals to their S10 values */
	for (sig = NATIVE_SIGRTMIN; sig <= NATIVE_SIGRTMAX; sig++) {
		if (SIGISMEMBER(&srcset, sig) &&
		    (s10sig = nativesig_to_s10(sig)) > 0)
			SIGADDSET(&newset, s10sig);
	}

	if (brand_uucopy(&newset, s10_set, sizeof (sigset_t)) != 0)
		return (EFAULT);

	return (0);
}

/*
 * This is our interposed signal handler.
 * Fix up the arguments received from the kernel and jump
 * to the s10 signal handler, normally libc's sigacthandler().
 */
static void
s10_sigacthandler(int sig, siginfo_t *sip, void *uvp)
{
	int s10_sig;
	ucontext_t *ucp;

	s10_sig = nativesig_to_s10(sig);
	if (s10_sig <= 0)	/* can't happen? */
		brand_abort(sig, "Received an impossible signal");
	if (sip != NULL) {
		/*
		 * All we really have to do is map the signal number,
		 * which changes only for the realtime signals,
		 * so all the rest of the siginfo structure is the
		 * same between s10 and native.
		 */
		if (sip->si_signo != sig)	/* can't happen? */
			brand_abort(sig, "Received an impossible siginfo");
		sip->si_signo = s10_sig;
	}
	if ((ucp = uvp) != NULL &&
	    (ucp->uc_flags & UC_SIGMASK))
		(void) nativesigset_to_s10(&ucp->uc_sigmask, &ucp->uc_sigmask);

	s10_handlers[s10_sig - 1](s10_sig, sip, uvp);
}

/*
 * Interposition upon SYS_lwp_sigmask
 */
int
s10_lwp_sigmask(sysret_t *rval, int how, uint_t bits0, uint_t bits1)
{
	sigset_t s10_blockset;
	sigset_t native_blockset;
	int err;

	s10_blockset.__sigbits[0] = bits0;
	s10_blockset.__sigbits[1] = bits1;
	s10_blockset.__sigbits[2] = 0;
	s10_blockset.__sigbits[3] = 0;

	(void) s10sigset_to_native(&s10_blockset, &native_blockset);

	err = __systemcall(rval, SYS_lwp_sigmask + 1024,
	    how,
	    native_blockset.__sigbits[0],
	    native_blockset.__sigbits[1],
	    native_blockset.__sigbits[2],
	    native_blockset.__sigbits[3]);

	if (err != 0)
		return (err);

	native_blockset.__sigbits[0] = (int)rval->sys_rval1;
	native_blockset.__sigbits[1] = (int)rval->sys_rval2;
	native_blockset.__sigbits[2] = 0;
	native_blockset.__sigbits[3] = 0;

	(void) nativesigset_to_s10(&native_blockset, &s10_blockset);

	rval->sys_rval1 = s10_blockset.__sigbits[0];
	rval->sys_rval2 = s10_blockset.__sigbits[1];

	return (0);
}

/*
 * Interposition upon SYS_sigprocmask
 */
int
s10_sigprocmask(sysret_t *rval, int how, const sigset_t *set, sigset_t *oset)
{
	sigset_t sigset_set, sigset_oset;
	sigset_t *set_ptr, *oset_ptr;
	int err;

	oset_ptr = (oset == NULL) ? NULL : &sigset_oset;
	set_ptr = (set == NULL) ? NULL : &sigset_set;

	if (set_ptr != NULL &&
	    (err = s10sigset_to_native(set, set_ptr)) != 0)
		return (err);

	if ((err = __systemcall(rval, SYS_sigprocmask + 1024,
	    how, set_ptr, oset_ptr)) != 0)
		return (err);

	if (oset_ptr != NULL &&
	    (err = nativesigset_to_s10(oset_ptr, oset)) != 0)
		return (err);

	return (0);
}

/*
 * Interposition upon SYS_sigsuspend
 */
int
s10_sigsuspend(sysret_t *rval, const sigset_t *set)
{
	sigset_t sigset_set;
	int err;

	if ((err = s10sigset_to_native(set, &sigset_set)) != 0) {
		(void) B_TRUSS_POINT_1(rval, SYS_sigsuspend, err, set);
		return (err);
	}

	return (__systemcall(rval, SYS_sigsuspend + 1024, &sigset_set));
}

/*
 * Interposition upon SYS_sigaction
 *
 * There is a fair amount of complexity here due to the need to interpose
 * on any registered user signal handler.
 *
 * The idea is that if a user signal handler is installed, we must install
 * our own signal handler between the system and the signal handler being
 * registered.  If the signal handler to be registered is SIG_DFL or SIG_IGN,
 * we should remove our interpositioned handler as it's no longer needed.
 *
 * The way we do this is we set the signal handler to call s10_sigacthandler(),
 * and then store the address of the passed signal handler in a global
 * per-process array, s10_handlers[].
 *
 * We rely on the fact that the s10 libc blocks all signals during
 * its call to the sigaction() system call to guarantee atomicity.
 */
int
s10_sigaction(sysret_t *rval,
    int sig, const struct sigaction *act, struct sigaction *oact)
{
	struct sigaction sigact, osigact;
	struct sigaction *sigactp, *osigactp;
	int err, nativesig;
	void (*handler)();

	if ((nativesig = s10sig_to_native(sig)) < 0) {
		(void) B_TRUSS_POINT_3(rval, SYS_sigaction, EINVAL,
		    sig, act, oact);
		return (EINVAL);
	}

	if (act == NULL) {
		sigactp = NULL;
	} else {
		sigactp = &sigact;

		if (brand_uucopy(act, sigactp, sizeof (struct sigaction)) != 0)
			return (EFAULT);

		if ((err = s10sigset_to_native(&sigactp->sa_mask,
		    &sigactp->sa_mask)) != 0) {
			(void) B_TRUSS_POINT_3(rval, SYS_sigaction, err,
			    sig, act, oact);
			return (err);
		}
	}

	osigactp = ((oact == NULL) ? NULL : &osigact);

	if (sigactp != NULL) {
		handler = sigactp->sa_handler;
		if (handler != SIG_DFL && handler != SIG_IGN)
			sigactp->sa_sigaction = s10_sigacthandler;
	}

	if ((err = __systemcall(rval, SYS_sigaction + 1024,
	    nativesig, sigactp, osigactp)) != 0)
		return (err);

	/*
	 * Translate the old signal mask if we are supposed to return the old
	 * struct sigaction.
	 *
	 * Note that we may have set the signal handler, but may return EFAULT
	 * here if the oact parameter is bad.
	 *
	 * That's OK, because the direct system call acts the same way.
	 */
	if (osigactp != NULL) {
		err = nativesigset_to_s10(&osigactp->sa_mask,
		    &osigactp->sa_mask);

		if (osigactp->sa_sigaction == s10_sigacthandler)
			osigactp->sa_sigaction = s10_handlers[sig - 1];

		if (err == 0 && brand_uucopy(osigactp, oact,
		    sizeof (struct sigaction)) != 0)
			err = EFAULT;
	}

	/*
	 * Do not store SIG_DFL or SIG_IGN into the array of remembered
	 * signal handlers.  Only store bona-fide function addresses.
	 * This is to avoid a race condition in which some thread
	 * sets the signal handler to SIG_DFL or SIG_IGN while some
	 * other thread is fielding the signal but has not yet reached
	 * s10_sigacthandler().  s10_sigacthandler() will unconditionally
	 * call the remembered signal handler and it it calls SIG_DFL or
	 * SIG_IGN, the process will incur a SIGSEGV or SIGBUS signal.
	 * This also allows a vfork() child to set signal handlers
	 * to SIG_DFL or SIG_IGN without corrupting the parent's
	 * address space.
	 */
	if (sigactp != NULL &&
	    handler != SIG_DFL && handler != SIG_IGN)
		s10_handlers[sig - 1] = handler;

	return (err);
}

/*
 * Interposition upon SYS_sigpending
 */
int
s10_sigpending(sysret_t *rval, int flag, sigset_t *set)
{
	sigset_t sigset_set;
	int err;

	if ((err = __systemcall(rval, SYS_sigpending + 1024,
	    flag, &sigset_set)) != 0)
		return (err);

	if ((err = nativesigset_to_s10(&sigset_set, set)) != 0)
		return (err);

	return (0);
}

/*
 * Interposition upon SYS_sigsendsys
 */
int
s10_sigsendsys(sysret_t *rval, procset_t *psp, int sig)
{
	int nativesig;

	if ((nativesig = s10sig_to_native(sig)) < 0) {
		(void) B_TRUSS_POINT_2(rval, SYS_sigsendsys, EINVAL,
		    psp, sig);
		return (EINVAL);
	}

	return (__systemcall(rval, SYS_sigsendsys + 1024, psp, nativesig));
}

/*
 * Convert the siginfo_t code and status fields to an old style
 * wait status for s10_wait(), below.
 */
static int
wstat(int code, int status)
{
	int stat = (status & 0377);

	switch (code) {
	case CLD_EXITED:
		stat <<= 8;
		break;
	case CLD_DUMPED:
		stat |= WCOREFLG;
		break;
	case CLD_KILLED:
		break;
	case CLD_TRAPPED:
	case CLD_STOPPED:
		stat <<= 8;
		stat |= WSTOPFLG;
		break;
	case CLD_CONTINUED:
		stat = WCONTFLG;
		break;
	}
	return (stat);
}

/*
 * Interposition upon SYS_wait
 */
int
s10_wait(sysret_t *rval)
{
	int err;
	siginfo_t info;

	err = s10_waitid(rval, P_ALL, 0, &info, WEXITED | WTRAPPED);
	if (err != 0)
		return (err);

	rval->sys_rval1 = info.si_pid;
	rval->sys_rval2 = wstat(info.si_code, info.si_status);

	return (0);
}

/*
 * Interposition upon SYS_waitid
 */
int
s10_waitid(sysret_t *rval,
    idtype_t idtype, id_t id, siginfo_t *infop, int options)
{
	int err, sig;

	err = __systemcall(rval, SYS_waitid + 1024, idtype, id, infop, options);
	if (err != 0)
		return (err);

	/*
	 * If the process being waited for terminated or stopped due to a
	 * signal, translate the signal number from its native value to its
	 * S10 equivalent.
	 *
	 * If we can't legally translate the signal number, just sort of punt
	 * and leave it untranslated.
	 *
	 * We shouldn't return EINVAL as the syscall didn't technically fail.
	 */
	if (infop->si_signo == SIGCLD && infop->si_code != CLD_EXITED &&
	    (sig = nativesig_to_s10(infop->si_status)) > 0)
		infop->si_status = sig;

	return (0);
}

/*
 * Interposition upon SYS_sigtimedwait
 */
int
s10_sigtimedwait(sysret_t *rval,
    const sigset_t *set, siginfo_t *info, const timespec_t *timeout)
{
	sigset_t sigset_set;
	int err, sig;

	if ((err = s10sigset_to_native(set, &sigset_set)) != 0) {
		(void) B_TRUSS_POINT_3(rval, SYS_sigtimedwait, err,
		    set, info, timeout);
		return (err);
	}

	if ((err = __systemcall(rval, SYS_sigtimedwait + 1024,
	    &sigset_set, info, timeout)) != 0)
		return (err);

	if (info != NULL) {
		/*
		 * If we can't legally translate the signal number in the
		 * siginfo_t, just sort of punt and leave it untranslated.
		 *
		 * We shouldn't return EINVAL as the syscall didn't technically
		 * fail.
		 */
		if ((sig = nativesig_to_s10(info->si_signo)) > 0)
			info->si_signo = sig;
	}

	/*
	 * If we can't legally translate the signal number returned by the
	 * sigtimedwait syscall, just sort of punt and leave it untranslated.
	 *
	 * We shouldn't return EINVAL as the syscall didn't technically
	 * fail.
	 */
	if ((sig = nativesig_to_s10((int)rval->sys_rval1)) > 0)
		rval->sys_rval1 = sig;

	return (0);
}

/*
 * Interposition upon SYS_sigqueue
 */
int
s10_sigqueue(sysret_t *rval, pid_t pid, int signo, void *value, int si_code)
{
	int nativesig;

	if ((nativesig = s10sig_to_native(signo)) < 0) {
		(void) B_TRUSS_POINT_4(rval, SYS_sigqueue, EINVAL,
		    pid, signo, value, si_code);
		return (EINVAL);
	}

	if (pid == 1)
		pid = zone_init_pid;

	/*
	 * The native version of this syscall takes an extra argument.
	 * The new last arg "block" flag should be zero.  The block flag
	 * is used by the Opensolaris AIO implementation, which is now
	 * part of libc.
	 */
	return (__systemcall(rval, SYS_sigqueue + 1024,
	    pid, nativesig, value, si_code, 0));
}

/*
 * Interposition upon SYS_signotify
 */
int
s10_signotify(sysret_t *rval,
    int cmd, siginfo_t *siginfo, signotify_id_t *sn_id)
{
	siginfo_t *infop, info;

	infop = siginfo;

	/* only check for a valid siginfo pointer in the case of SN_PROC */
	if (cmd == SN_PROC) {
		int nativesig;

		if (brand_uucopy(infop, &info, sizeof (siginfo_t)) != 0)
			return (EFAULT);

		if ((nativesig = s10sig_to_native(info.si_signo)) < 0) {
			(void) B_TRUSS_POINT_3(rval, SYS_signotify, EINVAL,
			    cmd, siginfo, sn_id);
			return (EINVAL);
		}

		info.si_signo = nativesig;
		infop = &info;
	}

	return (__systemcall(rval, SYS_signotify + 1024, cmd, infop, sn_id));
}

/*
 * Interposition upon SYS_kill
 */
int
s10_kill(sysret_t *rval, pid_t pid, int sig)
{
	int nativesig;

	if ((nativesig = s10sig_to_native(sig)) < 0) {
		(void) B_TRUSS_POINT_2(rval, SYS_kill, EINVAL, pid, sig);
		return (EINVAL);
	}

	if (pid == 1)
		pid = zone_init_pid;

	return (__systemcall(rval, SYS_kill + 1024, pid, nativesig));
}

/*
 * Interposition upon SYS_lwp_create
 *
 * See also the s10_lwp_create_correct_fs() function in s10_brand.c
 * for the special case of creating an lwp in a 64-bit x86 process.
 */
int
s10_lwp_create(sysret_t *rval, ucontext_t *ucp, int flags, id_t *new_lwp)
{
	ucontext_t s10_uc;

	if (brand_uucopy(ucp, &s10_uc, sizeof (ucontext_t)) != 0)
		return (EFAULT);

	if (s10_uc.uc_flags & UC_SIGMASK)
		(void) s10sigset_to_native(&s10_uc.uc_sigmask,
		    &s10_uc.uc_sigmask);

	return (__systemcall(rval, SYS_lwp_create + 1024,
	    &s10_uc, flags, new_lwp));
}

/*
 * Interposition upon SYS_lwp_kill
 */
int
s10_lwp_kill(sysret_t *rval, id_t lwpid, int sig)
{
	int nativesig;

	if ((nativesig = s10sig_to_native(sig)) < 0) {
		(void) B_TRUSS_POINT_2(rval, SYS_lwp_kill, EINVAL,
		    lwpid, sig);
		return (EINVAL);
	}

	return (__systemcall(rval, SYS_lwp_kill + 1024, lwpid, nativesig));
}
