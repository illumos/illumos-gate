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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * Copyright (c) 2014, Joyent, Inc. All rights reserved.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/segments.h>
#include <sys/lx_types.h>
#include <sys/lx_brand.h>
#include <sys/lx_misc.h>
#include <sys/lx_debug.h>
#include <sys/lx_signal.h>
#include <sys/lx_syscall.h>
#include <sys/lx_thread.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <thread.h>
#include <ucontext.h>
#include <unistd.h>
#include <stdio.h>
#include <libintl.h>
#include <ieeefp.h>

extern int pselect_large_fdset(int nfds, fd_set *in0, fd_set *out0, fd_set *ex0,
	const timespec_t *tsp, const sigset_t *sp);

/*
 * Delivering signals to a Linux process is complicated by differences in
 * signal numbering, stack structure and contents, and the action taken when a
 * signal handler exits.  In addition, many signal-related structures, such as
 * sigset_ts, vary between Solaris and Linux.
 *
 * To support user-level signal handlers, the brand uses a double layer of
 * indirection to process and deliver signals to branded threads.
 *
 * When a Linux process sends a signal using the kill(2) system call, we must
 * translate the signal into the Solaris equivalent before handing control off
 * to the standard signalling mechanism.  When a signal is delivered to a Linux
 * process, we translate the signal number from Solaris to back to Linux.
 * Translating signals both at generation and delivery time ensures both that
 * Solaris signals are sent properly to Linux applications and that signals'
 * default behavior works as expected.
 *
 * In a normal Solaris process, signal delivery is interposed on for any thread
 * registering a signal handler by libc. Libc needs to do various bits of magic
 * to provide thread-safe critical regions, so it registers its own handler,
 * named sigacthandler(), using the sigaction(2) system call. When a signal is
 * received, sigacthandler() is called, and after some processing, libc turns
 * around and calls the user's signal handler via a routine named
 * call_user_handler().
 *
 * Adding a Linux branded thread to the mix complicates things somewhat.
 *
 * First, when a thread receives a signal, it may be running with a Linux value
 * in the x86 %gs segment register as opposed to the value Solaris threads
 * expect; if control were passed directly to Solaris code, such as libc's
 * sigacthandler(), that code would experience a segmentation fault the first
 * time it tried to dereference a memory location using %gs.
 *
 * Second, the signal number translation referenced above must take place.
 * Further, as was the case with Solaris libc, before the Linux signal handler
 * is called, the value of the %gs segment register MUST be restored to the
 * value Linux code expects.
 *
 * This need to translate signal numbers and manipulate the %gs register means
 * that while with standard Solaris libc, following a signal from generation to
 * delivery looks something like:
 *
 * 	kernel ->
 *	    sigacthandler() ->
 *		call_user_handler() ->
 *		    user signal handler
 *
 * while for the brand's Linux threads, this would look like:
 *
 *	kernel ->
 *	    lx_sigacthandler() ->
 *		sigacthandler() ->
 *		    call_user_handler() ->
 *			lx_call_user_handler() ->
 *			    Linux user signal handler
 *
 * The new addtions are:
 *
 * 	lx_sigacthandler
 *	================
 *	This routine is responsible for setting the %gs segment register to the
 *	value Solaris code expects, and jumping to Solaris' libc signal
 *	interposition handler, sigacthandler().
 *
 * 	lx_call_user_handler
 *	====================
 *	This routine is responsible for translating Solaris signal numbers to
 *	their Linux equivalents, building a Linux signal stack based on the
 * 	information Solaris has provided, and passing the stack to the
 *	registered Linux signal handler. It is, in effect, the Linux thread
 *	equivalent to libc's call_user_handler().
 *
 * Installing lx_sigacthandler() is a bit tricky, as normally libc's
 * sigacthandler() routine is hidden from user programs. To facilitate this, a
 * new private function was added to libc, setsigaction():
 *
 *	void setsigacthandler(void (*new_handler)(int, siginfo_t *, void *),
 *	    void (**old_handler)(int, siginfo_t *, void *))
 *
 * The routine works by modifying the per-thread data structure libc already
 * keeps that keeps track of the address of its own interposition handler with
 * the address passed in; the old handler's address is set in the pointer
 * pointed to by the second argument, if it is non-NULL, mimicking the behavior
 * of sigaction() itself.  Once setsigacthandler() has been executed, all
 * future branded threads this thread may create will automatically have the
 * proper interposition handler installed as the result of a normal
 * sigaction() call.
 *
 * Note that none of this interposition is necessary unless a Linux thread
 * registers a user signal handler, as the default action for all signals is the
 * same between Solaris and Linux save for one signal, SIGPWR.  For this reason,
 * the brand ALWAYS installs its own internal signal handler for SIGPWR that
 * translates the action to the Linux default, to terminate the process.
 * (Solaris' default action is to ignore SIGPWR.)
 *
 * It is also important to note that when signals are not translated, the brand
 * relies upon code interposing upon the wait(2) system call to translate
 * signals to their proper values for any Linux threads retrieving the status
 * of others.  So while the Solaris signal number for a particular signal is set
 * in a process' data structures (and would be returned as the result of say,
 * WTERMSIG()), the brand's interposiiton upon wait(2) is responsible for
 * translating the value WTERMSIG() would return from a Solaris signal number
 * to the appropriate Linux value.
 *
 * The process of returning to an interrupted thread of execution from a user
 * signal handler is entirely different between Solaris and Linux.  While
 * Solaris generally expects to set the context to the interrupted one on a
 * normal return from a signal handler, in the normal case Linux instead calls
 * code that calls a specific Linux system call, sigreturn(2).  Thus when a
 * Linux signal handler completes execution, instead of returning through what
 * would in libc be a call to setcontext(2), the sigreturn(2) Linux system call
 * is responsible for accomplishing much the same thing.
 *
 * This trampoline code looks something like this:
 *
 *	pop	%eax
 *	mov	LX_SYS_rt_sigreturn, %eax
 *	int	$0x80
 *
 * so when the Linux user signal handler is eventually called, the stack looks
 * like this (in the case of an "lx_sigstack" stack:
 *
 *	=========================================================
 *	| Pointer to actual trampoline code (in code segment)	|
 *	=========================================================
 *	| Linux signal number					|
 *	=========================================================
 *	| Pointer to Linux siginfo_t (or NULL)			|
 *	=========================================================
 *	| Pointer to Linux ucontext_t (or NULL)			|
 *	=========================================================
 *	| Linux siginfo_t					|
 *	=========================================================
 *	| Linux ucontext_t					|
 *	=========================================================
 *	| Linux struct _fpstate					|
 *	=========================================================
 *	| Trampoline code (marker for gdb, not really executed)	|
 *	=========================================================
 *
 * The brand takes the approach of intercepting the Linux sigreturn(2) system
 * call in order to turn it into the return through the libc call stack that
 * Solaris expects. This is done by the lx_sigreturn() and lx_rt_sigreturn()
 * routines, which remove the Linux signal frame from the stack and pass the
 * resulting stack pointer to another routine, lx_sigreturn_tolibc(), which
 * makes libc believe the user signal handler it had called returned.
 *
 * (Note that the trampoline code actually lives in a proper executable segment
 * and not on the stack, but gdb checks for the exact code sequence of the
 * trampoline code on the stack to determine whether it is in a signal stack
 * frame or not.  Really.)
 *
 * When control then returns to libc's call_user_handler() routine, a
 * setcontext(2) will be done that (in most cases) returns the thread executing
 * the code back to the location originally interrupted by receipt of the
 * signal.
 */

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
 *       be done with their sizes, they must be word aligned in size (32 bits)
 *	 so the stack remains word aligned per the i386 ABI.
 */
struct lx_sigstack {
	void (*retaddr)();	/* address of real lx_rt_sigreturn code */
	int sig;		/* signal number */
	lx_siginfo_t *sip;	/* points to "si" if valid, NULL if not */
	lx_ucontext_t *ucp;	/* points to "uc" if valid, NULL if not */
	lx_siginfo_t si;	/* saved signal information */
	lx_ucontext_t uc;	/* saved user context */
	lx_fpstate_t fpstate;	/* saved FP state */
	char trampoline[8];	/* code for trampoline to lx_rt_sigreturn() */
};

struct lx_oldsigstack {
	void (*retaddr)();	/* address of real lx_sigreturn code */
	int sig;		/* signal number */
	lx_sigcontext_t sigc;	/* saved user context */
	lx_fpstate_t fpstate;	/* saved FP state */
	int sig_extra;		/* signal mask for signals [32 .. NSIG - 1] */
	char trampoline[8];	/* code for trampoline to lx_sigreturn() */
};

/*
 * libc_sigacthandler is set to the address of the libc signal interposition
 * routine, sigacthandler().
 */
void (*libc_sigacthandler)(int, siginfo_t *, void*);

/*
 * The lx_sighandlers structure needs to be a global due to the semantics of
 * clone().
 *
 * If CLONE_SIGHAND is set, the calling process and child share signal
 * handlers, and if either calls sigaction(2) it should change the behavior
 * in the other thread.  Each thread does, however, have its own signal mask
 * and set of pending signals.
 *
 * If CLONE_SIGHAND is not set, the child process should inherit a copy of
 * the signal handlers at the time of the clone() but later calls to
 * sigaction(2) should only affect the individual thread calling it.
 *
 * This maps perfectly to a thr_create(3C) thread semantic in the first
 * case and a fork(2)-type semantic in the second case.  By making
 * lx_sighandlers global, we automatically get the correct behavior.
 */
static lx_sighandlers_t lx_sighandlers;

/*
 * stol_stack() and ltos_stack() convert between Solaris and Linux stack_t
 * structures.
 *
 * These routines are needed because although the two structures have the same
 * contents, their contents are declared in a different order, so the content
 * of the structures cannot be copied with a simple bcopy().
 */
static void
stol_stack(stack_t *fr, lx_stack_t *to)
{
	to->ss_sp = fr->ss_sp;
	to->ss_flags = fr->ss_flags;
	to->ss_size = fr->ss_size;
}

static void
ltos_stack(lx_stack_t *fr, stack_t *to)
{
	to->ss_sp = fr->ss_sp;
	to->ss_flags = fr->ss_flags;
	to->ss_size = fr->ss_size;
}

static int
ltos_sigset(lx_sigset_t *lx_sigsetp, sigset_t *s_sigsetp)
{
	lx_sigset_t l;
	int lx_sig, sig;

	if (uucopy(lx_sigsetp, &l, sizeof (lx_sigset_t)) != 0)
		return (-errno);

	(void) sigemptyset(s_sigsetp);

	for (lx_sig = 1; lx_sig < LX_NSIG; lx_sig++) {
		if (lx_sigismember(&l, lx_sig) &&
		    ((sig = ltos_signo[lx_sig]) > 0))
			(void) sigaddset(s_sigsetp, sig);
	}

	return (0);
}

static int
stol_sigset(sigset_t *s_sigsetp, lx_sigset_t *lx_sigsetp)
{
	lx_sigset_t l;
	int sig, lx_sig;

	bzero(&l, sizeof (lx_sigset_t));

	for (sig = 1; sig < NSIG; sig++) {
		if (sigismember(s_sigsetp, sig) &&
		    ((lx_sig = stol_signo[sig]) > 0))
			lx_sigaddset(&l, lx_sig);
	}

	return ((uucopy(&l, lx_sigsetp, sizeof (lx_sigset_t)) != 0)
	    ? -errno : 0);
}

static int
ltos_osigset(lx_osigset_t *lx_osigsetp, sigset_t *s_sigsetp)
{
	lx_osigset_t lo;
	int lx_sig, sig;

	if (uucopy(lx_osigsetp, &lo, sizeof (lx_osigset_t)) != 0)
		return (-errno);

	(void) sigemptyset(s_sigsetp);

	for (lx_sig = 1; lx_sig <= OSIGSET_NBITS; lx_sig++)
		if ((lo & OSIGSET_BITSET(lx_sig)) &&
		    ((sig = ltos_signo[lx_sig]) > 0))
			(void) sigaddset(s_sigsetp, sig);

	return (0);
}

static int
stol_osigset(sigset_t *s_sigsetp, lx_osigset_t *lx_osigsetp)
{
	lx_osigset_t lo = 0;
	int lx_sig, sig;

	/*
	 * Note that an lx_osigset_t can only represent the signals from
	 * [1 .. OSIGSET_NBITS], so even though a signal may be present in the
	 * Solaris sigset_t, it may not be representable as a bit in the
	 * lx_osigset_t.
	 */
	for (sig = 1; sig < NSIG; sig++)
		if (sigismember(s_sigsetp, sig) &&
		    ((lx_sig = stol_signo[sig]) > 0) &&
		    (lx_sig <= OSIGSET_NBITS))
			lo |= OSIGSET_BITSET(lx_sig);

	return ((uucopy(&lo, lx_osigsetp, sizeof (lx_osigset_t)) != 0)
	    ? -errno : 0);
}

static int
stol_sigcode(int si_code)
{
	switch (si_code) {
		case SI_USER:
			return (LX_SI_USER);
		case SI_LWP:
			return (LX_SI_TKILL);
		case SI_QUEUE:
			return (LX_SI_QUEUE);
		case SI_TIMER:
			return (LX_SI_TIMER);
		case SI_ASYNCIO:
			return (LX_SI_ASYNCIO);
		case SI_MESGQ:
			return (LX_SI_MESGQ);
		default:
			return (si_code);
	}
}

int
stol_siginfo(siginfo_t *siginfop, lx_siginfo_t *lx_siginfop)
{
	lx_siginfo_t lx_siginfo;

	bzero(&lx_siginfo, sizeof (*lx_siginfop));

	if ((lx_siginfo.lsi_signo = stol_signo[siginfop->si_signo]) <= 0) {
		errno = EINVAL;
		return (-1);
	}

	lx_siginfo.lsi_code = stol_sigcode(siginfop->si_code);
	lx_siginfo.lsi_errno = siginfop->si_errno;

	switch (lx_siginfo.lsi_signo) {
		/*
		 * Semantics ARE defined for SIGKILL, but since
		 * we can't catch it, we can't translate it. :-(
		 */
		case LX_SIGPOLL:
			lx_siginfo.lsi_band = siginfop->si_band;
			lx_siginfo.lsi_fd = siginfop->si_fd;
			break;

		case LX_SIGCHLD:
			lx_siginfo.lsi_pid = siginfop->si_pid;
			lx_siginfo.lsi_status = siginfop->si_status;
			lx_siginfo.lsi_utime = siginfop->si_utime;
			lx_siginfo.lsi_stime = siginfop->si_stime;

			break;

		case LX_SIGILL:
		case LX_SIGBUS:
		case LX_SIGFPE:
			lx_siginfo.lsi_addr = siginfop->si_addr;
			break;

		default:
			lx_siginfo.lsi_pid = siginfop->si_pid;
			lx_siginfo.lsi_uid =
			    LX_UID32_TO_UID16(siginfop->si_uid);
			break;
	}

	return ((uucopy(&lx_siginfo, lx_siginfop, sizeof (lx_siginfo_t)) != 0)
	    ? -errno : 0);
}

static void
stol_fpstate(fpregset_t *fpr, lx_fpstate_t *lfpr)
{
	struct _fpstate *fpsp = (struct _fpstate *)fpr;
	size_t copy_len;

	/*
	 * The Solaris struct _fpstate and lx_fpstate_t are identical from the
	 * beginning of the structure to the lx_fpstate_t "magic" field, so
	 * just bcopy() those entries.
	 */
	copy_len = (size_t)&(((lx_fpstate_t *)0)->magic);
	bcopy(fpsp, lfpr, copy_len);

	/*
	 * These fields are all only significant for the first 16 bits.
	 */
	lfpr->cw &= 0xffff;		/* x87 control word */
	lfpr->tag &= 0xffff;		/* x87 tag word */
	lfpr->cssel &= 0xffff;		/* cs selector */
	lfpr->datasel &= 0xffff;	/* ds selector */

	/*
	 * Linux wants the x87 status word field to contain the value of the
	 * x87 saved exception status word.
	 */
	lfpr->sw = lfpr->status & 0xffff;	/* x87 status word */

	lfpr->mxcsr = fpsp->mxcsr;

	if (fpsp->mxcsr != 0) {
		/*
		 * Linux uses the "magic" field to denote whether the XMM
		 * registers contain legal data or not.  Since we can't get to
		 * %cr4 from userland to check the status of the OSFXSR bit,
		 * check the mxcsr field to see if it's 0, which it should
		 * never be on a system with the OXFXSR bit enabled.
		 */
		lfpr->magic = LX_X86_FXSR_MAGIC;
		bcopy(fpsp->xmm, lfpr->_xmm, sizeof (lfpr->_xmm));
	} else {
		lfpr->magic = LX_X86_FXSR_NONE;
	}
}

static void
ltos_fpstate(lx_fpstate_t *lfpr, fpregset_t *fpr)
{
	struct _fpstate *fpsp = (struct _fpstate *)fpr;
	size_t copy_len;

	/*
	 * The lx_fpstate_t and Solaris struct _fpstate are identical from the
	 * beginning of the structure to the struct _fpstate "mxcsr" field, so
	 * just bcopy() those entries.
	 *
	 * Note that we do NOT have to propogate changes the user may have made
	 * to the "status" word back to the "sw" word, unlike the way we have
	 * to deal with processing the ESP and UESP register values on return
	 * from a signal handler.
	 */
	copy_len = (size_t)&(((struct _fpstate *)0)->mxcsr);
	bcopy(lfpr, fpsp, copy_len);

	/*
	 * These fields are all only significant for the first 16 bits.
	 */
	fpsp->cw &= 0xffff;		/* x87 control word */
	fpsp->sw &= 0xffff;		/* x87 status word */
	fpsp->tag &= 0xffff;		/* x87 tag word */
	fpsp->cssel &= 0xffff;		/* cs selector */
	fpsp->datasel &= 0xffff;	/* ds selector */
	fpsp->status &= 0xffff;		/* saved status */

	fpsp->mxcsr = lfpr->mxcsr;

	if (lfpr->magic == LX_X86_FXSR_MAGIC)
		bcopy(lfpr->_xmm, fpsp->xmm, sizeof (fpsp->xmm));
}

/*
 * The brand needs a lx version of this because the format of the lx stack_t
 * differs from the Solaris stack_t not really in content but in ORDER,
 * so we can't simply pass pointers and expect things to work (sigh...)
 */
int
lx_sigaltstack(uintptr_t nsp, uintptr_t osp)
{
	lx_stack_t ls;
	stack_t newsstack, oldsstack;
	stack_t *nssp = (nsp ? &newsstack : NULL);
	stack_t *ossp = (osp ? &oldsstack : NULL);

	if (nsp) {
		if (uucopy((void *)nsp, &ls, sizeof (lx_stack_t)) != 0)
			return (-errno);

		if ((ls.ss_flags & LX_SS_DISABLE) == 0 &&
		    ls.ss_size < LX_MINSIGSTKSZ)
			return (-ENOMEM);

		newsstack.ss_sp = (int *)ls.ss_sp;
		newsstack.ss_size = (long)ls.ss_size;
		newsstack.ss_flags = ls.ss_flags;
	}

	if (sigaltstack(nssp, ossp) != 0)
		return (-errno);

	if (osp) {
		ls.ss_sp = (void *)oldsstack.ss_sp;
		ls.ss_size = (size_t)oldsstack.ss_size;
		ls.ss_flags = oldsstack.ss_flags;

		if (uucopy(&ls, (void *)osp, sizeof (lx_stack_t)) != 0)
			return (-errno);
	}

	return (0);
}

/*
 * The following routines are needed because sigset_ts and siginfo_ts are
 * different in format between Linux and Solaris.
 *
 * Note that there are two different lx_sigset structures, lx_sigset_ts and
 * lx_osigset_ts:
 *
 *    + An lx_sigset_t is the equivalent of a Solaris sigset_t and supports
 *	more than 32 signals.
 *
 *    + An lx_osigset_t is simply a uint32_t, so it by definition only supports
 *	32 signals.
 *
 * When there are two versions of a routine, one prefixed with lx_rt_ and
 * one prefixed with lx_ alone, in GENERAL the lx_rt_ routines deal with
 * lx_sigset_ts while the lx_ routines deal with lx_osigset_ts.  Unfortunately,
 * this is not always the case (e.g. lx_sigreturn() vs. lx_rt_sigreturn())
 */
int
lx_sigpending(uintptr_t sigpend)
{
	sigset_t sigpendset;

	if (sigpending(&sigpendset) != 0)
		return (-errno);

	return (stol_osigset(&sigpendset, (lx_osigset_t *)sigpend));
}

int
lx_rt_sigpending(uintptr_t sigpend, uintptr_t setsize)
{
	sigset_t sigpendset;

	if ((size_t)setsize != sizeof (lx_sigset_t))
		return (-EINVAL);

	if (sigpending(&sigpendset) != 0)
		return (-errno);

	return (stol_sigset(&sigpendset, (lx_sigset_t *)sigpend));
}

/*
 * Create a common routine to encapsulate all of the sigprocmask code,
 * as the only difference between lx_sigprocmask() and lx_rt_sigprocmask()
 * is the usage of lx_osigset_ts vs. lx_sigset_ts, as toggled in the code by
 * the setting of the "sigset_type" flag.
 */
static int
lx_sigprocmask_common(uintptr_t how, uintptr_t l_setp, uintptr_t l_osetp,
    uintptr_t sigset_type)
{
	int err;
	sigset_t set, oset;
	sigset_t *s_setp = NULL;
	sigset_t *s_osetp;

	if (l_setp) {
		switch (how) {
			case LX_SIG_BLOCK:
				how = SIG_BLOCK;
				break;

			case LX_SIG_UNBLOCK:
				how = SIG_UNBLOCK;
				break;

			case LX_SIG_SETMASK:
				how = SIG_SETMASK;
				break;

			default:
				return (-EINVAL);
		}

		s_setp = &set;

		if (sigset_type == USE_SIGSET)
			err = ltos_sigset((lx_sigset_t *)l_setp, s_setp);
		else
			err = ltos_osigset((lx_osigset_t *)l_setp, s_setp);

		if (err != 0)
			return (err);
	}

	s_osetp = (l_osetp ? &oset : NULL);

	/*
	 * In a multithreaded environment, a call to sigprocmask(2) should
	 * only affect the current thread's signal mask so we don't need to
	 * explicitly call thr_sigsetmask(3C) here.
	 */
	if (sigprocmask(how, s_setp, s_osetp) != 0)
		return (-errno);

	if (l_osetp) {
		if (sigset_type == USE_SIGSET)
			err = stol_sigset(s_osetp, (lx_sigset_t *)l_osetp);
		else
			err = stol_osigset(s_osetp, (lx_osigset_t *)l_osetp);

		if (err != 0) {
			/*
			 * Encountered a fault while writing to the old signal
			 * mask buffer, so unwind the signal mask change made
			 * above.
			 */
			(void) sigprocmask(how, s_osetp, (sigset_t *)NULL);
			return (err);
		}
	}

	return (0);
}

int
lx_sigprocmask(uintptr_t how, uintptr_t setp, uintptr_t osetp)
{
	return (lx_sigprocmask_common(how, setp, osetp, USE_OSIGSET));
}

int
lx_sgetmask(void)
{
	lx_osigset_t oldmask;

	return ((lx_sigprocmask_common(SIG_SETMASK, NULL, (uintptr_t)&oldmask,
	    USE_OSIGSET) != 0) ? -errno : (int)oldmask);
}

int
lx_ssetmask(uintptr_t sigmask)
{
	lx_osigset_t newmask, oldmask;

	newmask = (lx_osigset_t)sigmask;

	return ((lx_sigprocmask_common(SIG_SETMASK, (uintptr_t)&newmask,
	    (uintptr_t)&oldmask, USE_OSIGSET) != 0) ? -errno : (int)oldmask);
}

int
lx_rt_sigprocmask(uintptr_t how, uintptr_t setp, uintptr_t osetp,
    uintptr_t setsize)
{
	if ((size_t)setsize != sizeof (lx_sigset_t))
		return (-EINVAL);

	return (lx_sigprocmask_common(how, setp, osetp, USE_SIGSET));
}

int
lx_sigsuspend(uintptr_t set)
{
	sigset_t s_set;

	if (ltos_osigset((lx_osigset_t *)set, &s_set) != 0)
		return (-errno);

	return ((sigsuspend(&s_set) == -1) ? -errno : 0);
}

int
lx_rt_sigsuspend(uintptr_t set, uintptr_t setsize)
{
	sigset_t s_set;

	if ((size_t)setsize != sizeof (lx_sigset_t))
		return (-EINVAL);

	if (ltos_sigset((lx_sigset_t *)set, &s_set) != 0)
		return (-errno);

	return ((sigsuspend(&s_set) == -1) ? -errno : 0);
}

int
lx_sigwaitinfo(uintptr_t set, uintptr_t sinfo)
{
	lx_osigset_t *setp = (lx_osigset_t *)set;
	lx_siginfo_t *sinfop = (lx_siginfo_t *)sinfo;

	sigset_t s_set;
	siginfo_t s_sinfo, *s_sinfop;
	int rc;

	if (ltos_osigset(setp, &s_set) != 0)
		return (-errno);

	s_sinfop = (sinfop == NULL) ? NULL : &s_sinfo;

	if ((rc = sigwaitinfo(&s_set, s_sinfop)) == -1)
		return (-errno);

	if (s_sinfop == NULL)
		return (rc);

	return ((stol_siginfo(s_sinfop, sinfop) != 0) ? -errno : rc);
}

int
lx_rt_sigwaitinfo(uintptr_t set, uintptr_t sinfo, uintptr_t setsize)
{
	sigset_t s_set;
	siginfo_t s_sinfo, *s_sinfop;
	int rc;

	lx_sigset_t *setp = (lx_sigset_t *)set;
	lx_siginfo_t *sinfop = (lx_siginfo_t *)sinfo;

	if ((size_t)setsize != sizeof (lx_sigset_t))
		return (-EINVAL);

	if (ltos_sigset(setp, &s_set) != 0)
		return (-errno);

	s_sinfop = (sinfop == NULL) ? NULL : &s_sinfo;

	if ((rc = sigwaitinfo(&s_set, s_sinfop)) == -1)
		return (-errno);

	if (s_sinfop == NULL)
		return (rc);

	return ((stol_siginfo(s_sinfop, sinfop) != 0) ? -errno : rc);
}

int
lx_sigtimedwait(uintptr_t set, uintptr_t sinfo, uintptr_t toutp)
{
	sigset_t s_set;
	siginfo_t s_sinfo, *s_sinfop;
	int rc;

	lx_osigset_t *setp = (lx_osigset_t *)set;
	lx_siginfo_t *sinfop = (lx_siginfo_t *)sinfo;

	if (ltos_osigset(setp, &s_set) != 0)
		return (-errno);

	s_sinfop = (sinfop == NULL) ? NULL : &s_sinfo;

	if ((rc = sigtimedwait(&s_set, s_sinfop,
	    (struct timespec *)toutp)) == -1)
		return (-errno);

	if (s_sinfop == NULL)
		return (rc);

	return ((stol_siginfo(s_sinfop, sinfop) != 0) ? -errno : rc);
}

int
lx_rt_sigtimedwait(uintptr_t set, uintptr_t sinfo, uintptr_t toutp,
    uintptr_t setsize)
{
	sigset_t s_set;
	siginfo_t s_sinfo, *s_sinfop;
	int rc;

	lx_sigset_t *setp = (lx_sigset_t *)set;
	lx_siginfo_t *sinfop = (lx_siginfo_t *)sinfo;

	if ((size_t)setsize != sizeof (lx_sigset_t))
		return (-EINVAL);

	if (ltos_sigset(setp, &s_set) != 0)
		return (-errno);

	s_sinfop = (sinfop == NULL) ? NULL : &s_sinfo;

	if ((rc = sigtimedwait(&s_set, s_sinfop,
	    (struct timespec *)toutp)) == -1)
		return (-errno);

	if (s_sinfop == NULL)
		return (rc);

	return ((stol_siginfo(s_sinfop, sinfop) != 0) ? -errno : rc);
}

/*
 * Intercept the Linux sigreturn() syscall to turn it into the return through
 * the libc call stack that Solaris expects.
 *
 * When control returns to libc's call_user_handler() routine, a setcontext(2)
 * will be done that returns thread execution to the point originally
 * interrupted by receipt of the signal.
 */
int
lx_sigreturn(void)
{
	struct lx_oldsigstack *lx_ossp;
	lx_sigset_t lx_sigset;
	lx_regs_t *rp;
	ucontext_t *ucp;
	uintptr_t sp;

	rp = lx_syscall_regs();

	/*
	 * NOTE:  The sp saved in the context is eight bytes off of where we
	 *	  need it to be.
	 */
	sp = (uintptr_t)rp->lxr_esp - 8;

	/*
	 * At this point, the stack pointer should point to the struct
	 * lx_oldsigstack that lx_build_old_signal_frame() constructed and
	 * placed on the stack.  We need to reference it a bit later, so
	 * save a pointer to it before incrementing our copy of the sp.
	 */
	lx_ossp = (struct lx_oldsigstack *)sp;
	sp += sizeof (struct lx_oldsigstack);

	/*
	 * lx_sigdeliver() pushes LX_SIGRT_MAGIC on the stack before it
	 * creates the struct lx_oldsigstack.
	 *
	 * If we don't find it here, the stack's been corrupted and we need to
	 * kill ourselves.
	 */
	if (*(uint32_t *)sp != LX_SIGRT_MAGIC)
		lx_err_fatal(gettext(
		    "sp @ 0x%p, expected 0x%x, found 0x%x!"),
		    sp, LX_SIGRT_MAGIC, *(uint32_t *)sp);

	sp += sizeof (uint32_t);

	/*
	 * For signal mask handling to be done properly, this call needs to
	 * return to the libc routine that originally called the signal handler
	 * rather than directly set the context back to the place the signal
	 * interrupted execution as the original Linux code would do.
	 *
	 * Here *sp points to the Solaris ucontext_t, so we need to copy
	 * machine registers the Linux signal handler may have modified
	 * back to the Solaris version.
	 */
	ucp = (ucontext_t *)(*(uint32_t *)sp);

	/*
	 * General registers copy across as-is, except Linux expects that
	 * changes made to uc_mcontext.gregs[ESP] will be reflected when the
	 * interrupted thread resumes execution after the signal handler. To
	 * emulate this behavior, we must modify uc_mcontext.gregs[UESP] to
	 * match uc_mcontext.gregs[ESP] as Solaris will restore the UESP
	 * value to ESP.
	 */
	lx_ossp->sigc.sc_esp_at_signal = lx_ossp->sigc.sc_esp;
	bcopy(&lx_ossp->sigc, &ucp->uc_mcontext, sizeof (gregset_t));

	/* copy back FP regs if present */
	if (lx_ossp->sigc.sc_fpstate != NULL)
		ltos_fpstate(&lx_ossp->fpstate, &ucp->uc_mcontext.fpregs);

	/* convert Linux signal mask back to its Solaris equivalent */
	bzero(&lx_sigset, sizeof (lx_sigset_t));
	lx_sigset.__bits[0] = lx_ossp->sigc.sc_mask;
	lx_sigset.__bits[1] = lx_ossp->sig_extra;
	(void) ltos_sigset(&lx_sigset, &ucp->uc_sigmask);

	/*
	 * At this point sp contains the value of the stack pointer when
	 * lx_call_user_handler() was called.
	 *
	 * Pop one more value off the stack and pass the new sp to
	 * lx_sigreturn_tolibc(), which will in turn manipulate the x86
	 * registers to make it appear to libc's call_user_handler() as if the
	 * handler it had called returned.
	 */
	sp += sizeof (uint32_t);
	lx_debug("calling lx_sigreturn_tolibc(0x%p)", sp);
	lx_sigreturn_tolibc(sp);

	/*NOTREACHED*/
	return (0);
}

int
lx_rt_sigreturn(void)
{
	struct lx_sigstack *lx_ssp;
	lx_regs_t *rp;
	lx_ucontext_t *lx_ucp;
	ucontext_t *ucp;
	uintptr_t sp;

	rp = lx_syscall_regs();

	/*
	 * NOTE:  Because of some silly compatibility measures done in the
	 *	  signal trampoline code to make sure it uses the _exact same_
	 *	  instruction sequence Linux does, we have to manually "pop"
	 *	  one extra four byte instruction off the stack here before
	 *	  passing the stack address to the syscall because the
	 *	  trampoline code isn't allowed to do it.
	 *
	 *	  No, I'm not kidding.
	 *
	 *	  The sp saved in the context is eight bytes off of where we
	 *	  need it to be, so the need to pop the extra four byte
	 *	  instruction means we need to subtract a net four bytes from
	 *	  the sp before "popping" the struct lx_sigstack off the stack.
	 *	  This will yield the value the stack pointer had before
	 *	  lx_sigdeliver() created the stack frame for the Linux signal
	 *	  handler.
	 */
	sp = (uintptr_t)rp->lxr_esp - 4;

	/*
	 * At this point, the stack pointer should point to the struct
	 * lx_sigstack that lx_build_signal_frame() constructed and
	 * placed on the stack.  We need to reference it a bit later, so
	 * save a pointer to it before incrementing our copy of the sp.
	 */
	lx_ssp = (struct lx_sigstack *)sp;
	sp += sizeof (struct lx_sigstack);

	/*
	 * lx_sigdeliver() pushes LX_SIGRT_MAGIC on the stack before it
	 * creates the struct lx_sigstack (and possibly struct lx_fpstate_t).
	 *
	 * If we don't find it here, the stack's been corrupted and we need to
	 * kill ourselves.
	 */
	if (*(uint32_t *)sp != LX_SIGRT_MAGIC)
		lx_err_fatal(gettext("sp @ 0x%p, expected 0x%x, found 0x%x!"),
		    sp, LX_SIGRT_MAGIC, *(uint32_t *)sp);

	sp += sizeof (uint32_t);

	/*
	 * For signal mask handling to be done properly, this call needs to
	 * return to the libc routine that originally called the signal handler
	 * rather than directly set the context back to the place the signal
	 * interrupted execution as the original Linux code would do.
	 *
	 * Here *sp points to the Solaris ucontext_t, so we need to copy
	 * machine registers the Linux signal handler may have modified
	 * back to the Solaris version.
	 */
	ucp = (ucontext_t *)(*(uint32_t *)sp);

	lx_ucp = lx_ssp->ucp;

	if (lx_ucp != NULL) {
		/*
		 * General registers copy across as-is, except Linux expects
		 * that changes made to uc_mcontext.gregs[ESP] will be reflected
		 * when the interrupted thread resumes execution after the
		 * signal handler. To emulate this behavior, we must modify
		 * uc_mcontext.gregs[UESP] to match uc_mcontext.gregs[ESP] as
		 * Solaris will restore the UESP value to ESP.
		 */
		lx_ucp->uc_sigcontext.sc_esp_at_signal =
		    lx_ucp->uc_sigcontext.sc_esp;
		bcopy(&lx_ucp->uc_sigcontext, &ucp->uc_mcontext.gregs,
		    sizeof (gregset_t));

		if (lx_ucp->uc_sigcontext.sc_fpstate != NULL)
			ltos_fpstate(lx_ucp->uc_sigcontext.sc_fpstate,
			    &ucp->uc_mcontext.fpregs);

		/*
		 * Convert the Linux signal mask and stack back to their
		 * Solaris equivalents.
		 */
		(void) ltos_sigset(&lx_ucp->uc_sigmask, &ucp->uc_sigmask);
		ltos_stack(&lx_ucp->uc_stack, &ucp->uc_stack);
	}

	/*
	 * At this point sp contains the value of the stack pointer when
	 * lx_call_user_handler() was called.
	 *
	 * Pop one more value off the stack and pass the new sp to
	 * lx_sigreturn_tolibc(), which will in turn manipulate the x86
	 * registers to make it appear to libc's call_user_handler() as if the
	 * handler it had called returned.
	 */
	sp += sizeof (uint32_t);
	lx_debug("calling lx_sigreturn_tolibc(0x%p)", sp);
	lx_sigreturn_tolibc(sp);

	/*NOTREACHED*/
	return (0);
}

/*
 * Build signal frame for processing for "old" (legacy) Linux signals
 */
static void
lx_build_old_signal_frame(int lx_sig, siginfo_t *sip, void *p, void *sp)
{
	extern void lx_sigreturn_tramp();

	lx_sigset_t lx_sigset;
	ucontext_t *ucp = (ucontext_t *)p;
	struct lx_sigaction *lxsap;
	struct lx_oldsigstack *lx_ossp = sp;

	lx_debug("building old signal frame for lx sig %d at 0x%p", lx_sig, sp);

	lx_ossp->sig = lx_sig;
	lxsap = &lx_sighandlers.lx_sa[lx_sig];
	lx_debug("lxsap @ 0x%p", lxsap);

	if (lxsap && (lxsap->lxsa_flags & LX_SA_RESTORER) &&
	    lxsap->lxsa_restorer) {
		lx_ossp->retaddr = lxsap->lxsa_restorer;
		lx_debug("lxsa_restorer exists @ 0x%p", lx_ossp->retaddr);
	} else {
		lx_ossp->retaddr = lx_sigreturn_tramp;
		lx_debug("lx_ossp->retaddr set to 0x%p", lx_sigreturn_tramp);
	}

	lx_debug("osf retaddr = 0x%p", lx_ossp->retaddr);

	/* convert Solaris signal mask and stack to their Linux equivalents */
	(void) stol_sigset(&ucp->uc_sigmask, &lx_sigset);
	lx_ossp->sigc.sc_mask = lx_sigset.__bits[0];
	lx_ossp->sig_extra = lx_sigset.__bits[1];

	/*
	 * General registers copy across as-is, except Linux expects that
	 * uc_mcontext.gregs[ESP] == uc_mcontext.gregs[UESP] on receipt of a
	 * signal.
	 */
	bcopy(&ucp->uc_mcontext, &lx_ossp->sigc, sizeof (gregset_t));
	lx_ossp->sigc.sc_esp = lx_ossp->sigc.sc_esp_at_signal;

	/*
	 * cr2 contains the faulting address, and Linux only sets cr2 for a
	 * a segmentation fault.
	 */
	lx_ossp->sigc.sc_cr2 = (((lx_sig == LX_SIGSEGV) && (sip)) ?
	    (uintptr_t)sip->si_addr : 0);

	/* convert FP regs if present */
	if (ucp->uc_flags & UC_FPU) {
		stol_fpstate(&ucp->uc_mcontext.fpregs, &lx_ossp->fpstate);
		lx_ossp->sigc.sc_fpstate = &lx_ossp->fpstate;
	} else {
		lx_ossp->sigc.sc_fpstate = NULL;
	}

	/*
	 * Believe it or not, gdb wants to SEE the trampoline code on the
	 * bottom of the stack to determine whether the stack frame belongs to
	 * a signal handler, even though this code is no longer actually
	 * called.
	 *
	 * You can't make this stuff up.
	 */
	bcopy((void *)lx_sigreturn_tramp, lx_ossp->trampoline,
	    sizeof (lx_ossp->trampoline));
}

/*
 * Build signal frame for processing for modern Linux signals
 */
static void
lx_build_signal_frame(int lx_sig, siginfo_t *sip, void *p, void *sp)
{
	extern void lx_rt_sigreturn_tramp();

	lx_ucontext_t *lx_ucp;
	ucontext_t *ucp = (ucontext_t *)p;
	struct lx_sigstack *lx_ssp = sp;
	struct lx_sigaction *lxsap;

	lx_debug("building signal frame for lx sig %d at 0x%p", lx_sig, sp);

	lx_ucp = &lx_ssp->uc;
	lx_ssp->ucp = lx_ucp;
	lx_ssp->sig = lx_sig;

	lxsap = &lx_sighandlers.lx_sa[lx_sig];
	lx_debug("lxsap @ 0x%p", lxsap);

	if (lxsap && (lxsap->lxsa_flags & LX_SA_RESTORER) &&
	    lxsap->lxsa_restorer) {
		lx_ssp->retaddr = lxsap->lxsa_restorer;
		lx_debug("lxsa_restorer exists @ 0x%p", lx_ssp->retaddr);
	} else {
		lx_ssp->retaddr = lx_rt_sigreturn_tramp;
		lx_debug("lx_ssp->retaddr set to 0x%p", lx_rt_sigreturn_tramp);
	}

	/* Linux has these fields but always clears them to 0 */
	lx_ucp->uc_flags = 0;
	lx_ucp->uc_link = NULL;

	/* convert Solaris signal mask and stack to their Linux equivalents */
	(void) stol_sigset(&ucp->uc_sigmask, &lx_ucp->uc_sigmask);
	stol_stack(&ucp->uc_stack, &lx_ucp->uc_stack);

	/*
	 * General registers copy across as-is, except Linux expects that
	 * uc_mcontext.gregs[ESP] == uc_mcontext.gregs[UESP] on receipt of a
	 * signal.
	 */
	bcopy(&ucp->uc_mcontext, &lx_ucp->uc_sigcontext, sizeof (gregset_t));
	lx_ucp->uc_sigcontext.sc_esp = lx_ucp->uc_sigcontext.sc_esp_at_signal;

	/*
	 * cr2 contains the faulting address, which Linux only sets for a
	 * a segmentation fault.
	 */
	lx_ucp->uc_sigcontext.sc_cr2 = ((lx_sig == LX_SIGSEGV) && (sip)) ?
	    (uintptr_t)sip->si_addr : 0;

	/*
	 * Point the lx_siginfo_t pointer to the signal stack's lx_siginfo_t
	 * if there was a Solaris siginfo_t to convert, otherwise set it to
	 * NULL.
	 */
	if ((sip) && (stol_siginfo(sip, &lx_ssp->si) == 0))
		lx_ssp->sip = &lx_ssp->si;
	else
		lx_ssp->sip = NULL;

	/* convert FP regs if present */
	if (ucp->uc_flags & UC_FPU) {
		/*
		 * Copy FP regs to the appropriate place in the the lx_sigstack
		 * structure.
		 */
		stol_fpstate(&ucp->uc_mcontext.fpregs, &lx_ssp->fpstate);
		lx_ucp->uc_sigcontext.sc_fpstate = &lx_ssp->fpstate;
	} else
		lx_ucp->uc_sigcontext.sc_fpstate = NULL;

	/*
	 * Believe it or not, gdb wants to SEE the trampoline code on the
	 * bottom of the stack to determine whether the stack frame belongs to
	 * a signal handler, even though this code is no longer actually
	 * called.
	 *
	 * You can't make this stuff up.
	 */
	bcopy((void *)lx_rt_sigreturn_tramp, lx_ssp->trampoline,
	    sizeof (lx_ssp->trampoline));
}

/*
 * This is the second level interposition handler for Linux signals.
 */
static void
lx_call_user_handler(int sig, siginfo_t *sip, void *p)
{
	void (*user_handler)();
	void (*stk_builder)();

	lx_tsd_t *lx_tsd;
	struct lx_sigaction *lxsap;
	ucontext_t *ucp = (ucontext_t *)p;
	uintptr_t gs;
	size_t stksize;
	int err, lx_sig;

	/*
	 * If Solaris signal has no Linux equivalent, effectively
	 * ignore it.
	 */
	if ((lx_sig = stol_signo[sig]) == -1) {
		lx_debug("caught solaris signal %d, no Linux equivalent", sig);
		return;
	}

	lx_debug("interpose caught solaris signal %d, translating to Linux "
	    "signal %d", sig, lx_sig);

	lxsap = &lx_sighandlers.lx_sa[lx_sig];
	lx_debug("lxsap @ 0x%p", lxsap);

	if ((sig == SIGPWR) && (lxsap->lxsa_handler == SIG_DFL)) {
		/* Linux SIG_DFL for SIGPWR is to terminate */
		exit(LX_SIGPWR | 0x80);
	}

	if ((lxsap->lxsa_handler == SIG_DFL) ||
	    (lxsap->lxsa_handler == SIG_IGN))
		lx_err_fatal(gettext("%s set to %s?  How?!?!?"),
		    "lxsa_handler",
		    ((lxsap->lxsa_handler == SIG_DFL) ? "SIG_DFL" : "SIG_IGN"),
		    lxsap->lxsa_handler);

	if ((err = thr_getspecific(lx_tsd_key, (void **)&lx_tsd)) != 0)
		lx_err_fatal(gettext(
		    "%s: unable to read thread-specific data: %s"),
		    "lx_call_user_handler", strerror(err));

	assert(lx_tsd != 0);

	gs = lx_tsd->lxtsd_gs & 0xffff;		/* gs is only 16 bits */

	/*
	 * Any zero %gs value should be caught when a save is attempted in
	 * lx_emulate(), but this extra check will catch any zero values due to
	 * bugs in the library.
	 */
	assert(gs != 0);

	if (lxsap->lxsa_flags & LX_SA_SIGINFO) {
		stksize = sizeof (struct lx_sigstack);
		stk_builder = lx_build_signal_frame;
	} else  {
		stksize = sizeof (struct lx_oldsigstack);
		stk_builder = lx_build_old_signal_frame;
	}

	user_handler = lxsap->lxsa_handler;

	lx_debug("delivering %d (lx %d) to handler at 0x%p with gs 0x%x", sig,
	    lx_sig, lxsap->lxsa_handler, gs);

	if (lxsap->lxsa_flags & LX_SA_RESETHAND)
		lxsap->lxsa_handler = SIG_DFL;

	/*
	 * lx_sigdeliver() doesn't return, so it relies on the Linux
	 * signal handlers to clean up the stack, reset the current
	 * signal mask and return to the code interrupted by the signal.
	 */
	lx_sigdeliver(lx_sig, sip, ucp, stksize, stk_builder, user_handler, gs);
}

/*
 * Common routine to modify sigaction characteristics of a thread.
 *
 * We shouldn't need any special locking code here as we actually use
 * libc's sigaction() to do all the real work, so its thread locking should
 * take care of any issues for us.
 */
static int
lx_sigaction_common(int lx_sig, struct lx_sigaction *lxsp,
    struct lx_sigaction *olxsp)
{
	struct lx_sigaction *lxsap;
	struct sigaction sa;

	if (lx_sig <= 0 || lx_sig >= LX_NSIG)
		return (-EINVAL);

	lxsap = &lx_sighandlers.lx_sa[lx_sig];
	lx_debug("&lx_sighandlers.lx_sa[%d] = 0x%p", lx_sig, lxsap);

	if ((olxsp != NULL) &&
	    ((uucopy(lxsap, olxsp, sizeof (struct lx_sigaction))) != 0))
		return (-errno);

	if (lxsp != NULL) {
		int err, sig;
		struct lx_sigaction lxsa;
		sigset_t new_set, oset;

		if (uucopy(lxsp, &lxsa, sizeof (struct lx_sigaction)) != 0)
			return (-errno);

		if ((sig = ltos_signo[lx_sig]) != -1) {
			/*
			 * Block this signal while messing with its dispostion
			 */
			(void) sigemptyset(&new_set);
			(void) sigaddset(&new_set, sig);

			if (sigprocmask(SIG_BLOCK, &new_set, &oset) < 0) {
				err = errno;
				lx_debug("unable to block signal %d: %s", sig,
				    strerror(err));
				return (-err);
			}

			/*
			 * We don't really need the old signal disposition at
			 * this point, but this weeds out signals that would
			 * cause sigaction() to return an error before we change
			 * anything other than the current signal mask.
			 */
			if (sigaction(sig, NULL, &sa) < 0) {
				err = errno;
				lx_debug("sigaction() to get old "
				    "disposition for signal %d failed: "
				    "%s", sig, strerror(err));
				(void) sigprocmask(SIG_SETMASK, &oset, NULL);
				return (-err);
			}

			if ((lxsa.lxsa_handler != SIG_DFL) &&
			    (lxsa.lxsa_handler != SIG_IGN)) {
				sa.sa_handler = lx_call_user_handler;

				/*
				 * The interposition signal handler needs the
				 * information provided via the SA_SIGINFO flag.
				 */
				sa.sa_flags = SA_SIGINFO;

				if (lxsa.lxsa_flags & LX_SA_NOCLDSTOP)
					sa.sa_flags |= SA_NOCLDSTOP;
				if (lxsa.lxsa_flags & LX_SA_NOCLDWAIT)
					sa.sa_flags |= SA_NOCLDWAIT;
				if (lxsa.lxsa_flags & LX_SA_ONSTACK)
					sa.sa_flags |= SA_ONSTACK;
				if (lxsa.lxsa_flags & LX_SA_RESTART)
					sa.sa_flags |= SA_RESTART;
				if (lxsa.lxsa_flags & LX_SA_NODEFER)
					sa.sa_flags |= SA_NODEFER;

				/*
				 * Can't use RESETHAND with SIGPWR due to
				 * different default actions between Linux
				 * and Solaris.
				 */
				if ((sig != SIGPWR) &&
				    (lxsa.lxsa_flags & LX_SA_RESETHAND))
					sa.sa_flags |= SA_RESETHAND;

				if (ltos_sigset(&lxsa.lxsa_mask,
				    &sa.sa_mask) != 0) {
					err = errno;
					(void) sigprocmask(SIG_SETMASK, &oset,
					    NULL);
					return (-err);
				}

				lx_debug("interposing handler @ 0x%p for "
				    "signal %d (lx %d), flags 0x%x",
				    lxsa.lxsa_handler, sig, lx_sig,
				    lxsa.lxsa_flags);

				if (sigaction(sig, &sa, NULL) < 0) {
					err = errno;
					lx_debug("sigaction() to set new "
					    "disposition for signal %d failed: "
					    "%s", sig, strerror(err));
					(void) sigprocmask(SIG_SETMASK, &oset,
					    NULL);
					return (-err);
				}
			} else if ((sig != SIGPWR) ||
			    ((sig == SIGPWR) &&
			    (lxsa.lxsa_handler == SIG_IGN))) {
				/*
				 * There's no need to interpose for SIG_DFL or
				 * SIG_IGN so just call libc's sigaction(), but
				 * don't allow SIG_DFL for SIGPWR due to
				 * differing default actions between Linux and
				 * Solaris.
				 *
				 * Get the previous disposition first so things
				 * like sa_mask and sa_flags are preserved over
				 * a transition to SIG_DFL or SIG_IGN, which is
				 * what Linux expects.
				 */

				sa.sa_handler = lxsa.lxsa_handler;

				if (sigaction(sig, &sa, NULL) < 0) {
					err = errno;
					lx_debug("sigaction(%d, %s) failed: %s",
					    sig, ((sa.sa_handler == SIG_DFL) ?
					    "SIG_DFL" : "SIG_IGN"),
					    strerror(err));
					(void) sigprocmask(SIG_SETMASK, &oset,
					    NULL);
					return (-err);
				}
			}
		} else {
			lx_debug("Linux signal with no kill support "
			    "specified: %d", lx_sig);
		}

		/*
		 * Save the new disposition for the signal in the global
		 * lx_sighandlers structure.
		 */
		bcopy(&lxsa, lxsap, sizeof (struct lx_sigaction));

		/*
		 * Reset the signal mask to what we came in with if
		 * we were modifying a kill-supported signal.
		 */
		if (sig != -1)
			(void) sigprocmask(SIG_SETMASK, &oset, NULL);
	}

	return (0);
}

int
lx_sigaction(uintptr_t lx_sig, uintptr_t actp, uintptr_t oactp)
{
	int val;
	struct lx_sigaction sa, osa;
	struct lx_sigaction *sap, *osap;
	struct lx_osigaction *osp;

	sap = (actp ? &sa : NULL);
	osap = (oactp ? &osa : NULL);

	/*
	 * If we have a source pointer, convert source lxsa_mask from
	 * lx_osigset_t to lx_sigset_t format.
	 */
	if (sap) {
		osp = (struct lx_osigaction *)actp;
		sap->lxsa_handler = osp->lxsa_handler;

		bzero(&sap->lxsa_mask, sizeof (lx_sigset_t));

		for (val = 1; val <= OSIGSET_NBITS; val++)
			if (osp->lxsa_mask & OSIGSET_BITSET(val))
				(void) lx_sigaddset(&sap->lxsa_mask, val);

		sap->lxsa_flags = osp->lxsa_flags;
		sap->lxsa_restorer = osp->lxsa_restorer;
	}

	if ((val = lx_sigaction_common(lx_sig, sap, osap)))
		return (val);

	/*
	 * If we have a save pointer, convert the old lxsa_mask from
	 * lx_sigset_t to lx_osigset_t format.
	 */
	if (osap) {
		osp = (struct lx_osigaction *)oactp;

		osp->lxsa_handler = osap->lxsa_handler;

		bzero(&osp->lxsa_mask, sizeof (osp->lxsa_mask));
		for (val = 1; val <= OSIGSET_NBITS; val++)
			if (lx_sigismember(&osap->lxsa_mask, val))
				osp->lxsa_mask |= OSIGSET_BITSET(val);

		osp->lxsa_flags = osap->lxsa_flags;
		osp->lxsa_restorer = osap->lxsa_restorer;
	}

	return (0);
}

int
lx_rt_sigaction(uintptr_t lx_sig, uintptr_t actp, uintptr_t oactp,
    uintptr_t setsize)
{
	/*
	 * The "new" rt_sigaction call checks the setsize
	 * parameter.
	 */
	if ((size_t)setsize != sizeof (lx_sigset_t))
		return (-EINVAL);

	return (lx_sigaction_common(lx_sig, (struct lx_sigaction *)actp,
	    (struct lx_sigaction *)oactp));
}

/*
 * Convert signal syscall to a call to the lx_sigaction() syscall
 */
int
lx_signal(uintptr_t lx_sig, uintptr_t handler)
{
	struct sigaction act;
	struct sigaction oact;
	int rc;

	/*
	 * Use sigaction to mimic SYSV signal() behavior; glibc will
	 * actually call sigaction(2) itself, so we're really reaching
	 * back for signal(2) semantics here.
	 */
	bzero(&act, sizeof (act));
	act.sa_handler = (void (*)())handler;
	act.sa_flags = SA_RESETHAND | SA_NODEFER;

	rc = lx_sigaction(lx_sig, (uintptr_t)&act, (uintptr_t)&oact);
	return ((rc == 0) ? ((int)oact.sa_handler) : rc);
}

int
lx_tgkill(uintptr_t tgid, uintptr_t pid, uintptr_t sig)
{
	if (((pid_t)tgid <= 0) || ((pid_t)pid <= 0))
		return (-EINVAL);

	if (tgid != pid) {
		lx_unsupported("tgkill does not support gid != pid");
		return (-ENOTSUP);
	}

	/*
	 * Pad the lx_tkill() call with NULLs to match the IN_KERNEL_SYSCALL
	 * prototype generated for it by IN_KERNEL_SYSCALL in lx_brand.c.
	 */
	return (lx_tkill(pid, sig, NULL, NULL, NULL, NULL));
}

/*
 * This C routine to save the passed %gs value into the thread-specific save
 * area is called by the assembly routine lx_sigacthandler.
 */
void
lx_sigsavegs(uintptr_t signalled_gs)
{
	lx_tsd_t *lx_tsd;
	int err;

	signalled_gs &= 0xffff;		/* gs is only 16 bits */

	/*
	 * While a %gs of 0 is technically legal (as long as the application
	 * never dereferences memory using %gs), Solaris has its own ideas as
	 * to how a zero %gs should be handled in _update_sregs(), such that
	 * any 32-bit user process with a %gs of zero running on a system with
	 * a 64-bit kernel will have its %gs hidden base register stomped on on
	 * return from a system call, leaving an incorrect base address in
	 * place until the next time %gs is actually reloaded (forcing a reload
	 * of the base address from the appropriate descriptor table.)
	 *
	 * Of course the kernel will once again stomp on THAT base address when
	 * returning from a system call, resulting in an application
	 * segmentation fault.
	 *
	 * To avoid this situation, disallow a save of a zero %gs here in order
	 * to try and capture any Linux process that takes a signal with a zero
	 * %gs installed.
	 */
	assert(signalled_gs != 0);

	if (signalled_gs != LWPGS_SEL) {
		if ((err = thr_getspecific(lx_tsd_key,
		    (void **)&lx_tsd)) != 0)
			lx_err_fatal(gettext(
			    "%s: unable to read thread-specific data: %s"),
			    "sigsavegs", strerror(err));

		assert(lx_tsd != 0);

		lx_tsd->lxtsd_gs = signalled_gs;

		lx_debug("lx_sigsavegs(): gsp 0x%p, saved gs: 0x%x\n",
		    lx_tsd, signalled_gs);
	}
}

int
lx_siginit(void)
{
	extern void set_setcontext_enforcement(int);
	extern void lx_sigacthandler(int, siginfo_t *, void *);

	struct sigaction sa;
	sigset_t new_set, oset;
	int lx_sig, sig;

	/*
	 * Block all signals possible while setting up the signal imposition
	 * mechanism.
	 */
	(void) sigfillset(&new_set);

	if (sigprocmask(SIG_BLOCK, &new_set, &oset) < 0)
		lx_err_fatal(gettext("unable to block signals while setting up "
		    "imposition mechanism: %s"), strerror(errno));

	/*
	 * Ignore any signals that have no Linux analog so that those
	 * signals cannot be sent to Linux processes from the global zone
	 */
	for (sig = 1; sig < NSIG; sig++)
		if (stol_signo[sig] < 0)
			(void) sigignore(sig);

	/*
	 * As mentioned previously, when a user signal handler is installed
	 * via sigaction(), libc interposes on the mechanism by actually
	 * installing an internal routine sigacthandler() as the signal
	 * handler.  On receipt of the signal, libc does some thread-related
	 * processing via sigacthandler(), then calls the registered user
	 * signal handler on behalf of the user.
	 *
	 * We need to interpose on that mechanism to make sure the correct
	 * %gs segment register value is installed before the libc routine
	 * is called, otherwise the libc code will die with a segmentation
	 * fault.
	 *
	 * The private libc routine setsigacthandler() will set our
	 * interposition routine, lx_sigacthandler(), as the default
	 * "sigacthandler" routine for all new signal handlers for this
	 * thread.
	 */
	setsigacthandler(lx_sigacthandler, &libc_sigacthandler);
	lx_debug("lx_sigacthandler installed, libc_sigacthandler = 0x%p",
	    libc_sigacthandler);

	/*
	 * Mark any signals that are ignored as ignored in our interposition
	 * handler array
	 */
	for (lx_sig = 1; lx_sig < LX_NSIG; lx_sig++) {
		if (((sig = ltos_signo[lx_sig]) != -1) &&
		    (sigaction(sig, NULL, &sa) < 0))
			lx_err_fatal(gettext("unable to determine previous "
			    "disposition for signal %d: %s"),
			    sig, strerror(errno));

		if (sa.sa_handler == SIG_IGN) {
			lx_debug("marking signal %d (lx %d) as SIG_IGN",
			    sig, lx_sig);
			lx_sighandlers.lx_sa[lx_sig].lxsa_handler = SIG_IGN;
		}
	}

	/*
	 * Have our interposition handler handle SIGPWR to start with,
	 * as it has a default action of terminating the process in Linux
	 * but its default is to be ignored in Solaris.
	 */
	(void) sigemptyset(&sa.sa_mask);
	sa.sa_sigaction = lx_call_user_handler;
	sa.sa_flags = SA_SIGINFO;

	if (sigaction(SIGPWR, &sa, NULL) < 0)
		lx_err_fatal(gettext("%s failed: %s"), "sigaction(SIGPWR)",
		    strerror(errno));

	/*
	 * Solaris' libc forces certain register values in the ucontext_t
	 * used to restore a post-signal user context to be those Solaris
	 * expects; however that is not what we want to happen if the signal
	 * was taken while branded code was executing, so we must disable
	 * that behavior.
	 */
	set_setcontext_enforcement(0);

	/*
	 * Reset the signal mask to what we came in with
	 */
	(void) sigprocmask(SIG_SETMASK, &oset, NULL);

	lx_debug("interposition handler setup for SIGPWR");
	return (0);
}

/*
 * This code stongly resemebles lx_select(), but is here to be able to take
 * advantage of the Linux signal helper routines.
 */
int
lx_pselect6(uintptr_t p1, uintptr_t p2, uintptr_t p3, uintptr_t p4,
	uintptr_t p5, uintptr_t p6)
{
	int nfds = (int)p1;
	fd_set *rfdsp = NULL;
	fd_set *wfdsp = NULL;
	fd_set *efdsp = NULL;
	timespec_t ts, *tsp = NULL;
	int fd_set_len = howmany(nfds, 8);
	int r;
	sigset_t sigset, *sp = NULL;

	lx_debug("\tpselect6(%d, 0x%p, 0x%p, 0x%p, 0x%p, 0x%p)",
	    p1, p2, p3, p4, p4, p6);

	if (nfds > 0) {
		if (p2 != NULL) {
			rfdsp = SAFE_ALLOCA(fd_set_len);
			if (rfdsp == NULL)
				return (-ENOMEM);
			if (uucopy((void *)p2, rfdsp, fd_set_len) != 0)
				return (-errno);
		}
		if (p3 != NULL) {
			wfdsp = SAFE_ALLOCA(fd_set_len);
			if (wfdsp == NULL)
				return (-ENOMEM);
			if (uucopy((void *)p3, wfdsp, fd_set_len) != 0)
				return (-errno);
		}
		if (p4 != NULL) {
			efdsp = SAFE_ALLOCA(fd_set_len);
			if (efdsp == NULL)
				return (-ENOMEM);
			if (uucopy((void *)p4, efdsp, fd_set_len) != 0)
				return (-errno);
		}
	}

	if (p5 != NULL) {
		if (uucopy((void *)p5, &ts, sizeof (ts)) != 0)
			return (-errno);

		tsp = &ts;
	}

	if (p6 != NULL) {
		/*
		 * To force the number of arguments to be no more than six,
		 * Linux bundles both the sigset and the size into a structure
		 * that becomes the sixth argument.
		 */
		struct {
			lx_sigset_t *addr;
			size_t size;
		} lx_sigset;

		if (uucopy((void *)p6, &lx_sigset, sizeof (lx_sigset)) != 0)
			return (-errno);

		/*
		 * Yes, that's right:  Linux forces a size to be passed only
		 * so it can check that it's the size of a sigset_t.
		 */
		if (lx_sigset.size != sizeof (lx_sigset_t))
			return (-EINVAL);

		if ((r = ltos_sigset(lx_sigset.addr, &sigset)) != 0)
			return (r);

		sp = &sigset;
	}

	if (nfds >= FD_SETSIZE)
		r = pselect_large_fdset(nfds, rfdsp, wfdsp, efdsp, tsp, sp);
	else
		r = pselect(nfds, rfdsp, wfdsp, efdsp, tsp, sp);

	if (r < 0)
		return (-errno);

	/*
	 * For pselect6(), we don't honor the strange Linux select() semantics
	 * with respect to the timestruc parameter because glibc ignores it
	 * anyway -- just copy out the fd pointers and return.
	 */
	if ((rfdsp != NULL) && (uucopy(rfdsp, (void *)p2, fd_set_len) != 0))
		return (-errno);
	if ((wfdsp != NULL) && (uucopy(wfdsp, (void *)p3, fd_set_len) != 0))
		return (-errno);
	if ((efdsp != NULL) && (uucopy(efdsp, (void *)p4, fd_set_len) != 0))
		return (-errno);

	return (r);
}
