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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2015 Joyent, Inc.
 */

#include <sys/signal.h>
#include <sys/lx_siginfo.h>
#include <lx_signum.h>
#include <sys/debug.h>

/*
 * Delivering signals to a Linux process is complicated by differences in
 * signal numbering, stack structure and contents, and the action taken when a
 * signal handler exits.  In addition, many signal-related structures, such as
 * sigset_ts, vary between Solaris and Linux.
 *
 * The simplest transformation that must be done when sending signals is to
 * translate between Linux and Solaris signal numbers.
 *
 * These are the major signal number differences between Linux and Solaris:
 *
 * 	====================================
 * 	| Number |   Linux    |  Solaris   |
 * 	| ====== | =========  | ========== |
 *	|    7   | SIGBUS     | SIGEMT     |
 *	|   10   | SIGUSR1    | SIGBUS     |
 *	|   12   | SIGUSR2    | SIGSYS     |
 *	|   16   | SIGSTKFLT  | SIGUSR1    |
 *	|   17   | SIGCHLD    | SIGUSR2    |
 * 	|   18   | SIGCONT    | SIGCHLD    |
 *	|   19   | SIGSTOP    | SIGPWR     |
 * 	|   20   | SIGTSTP    | SIGWINCH   |
 * 	|   21   | SIGTTIN    | SIGURG     |
 * 	|   22   | SIGTTOU    | SIGPOLL    |
 *	|   23   | SIGURG     | SIGSTOP    |
 * 	|   24   | SIGXCPU    | SIGTSTP    |
 *	|   25   | SIGXFSZ    | SIGCONT    |
 *	|   26   | SIGVTALARM | SIGTTIN    |
 *	|   27   | SIGPROF    | SIGTTOU    |
 *	|   28   | SIGWINCH   | SIGVTALARM |
 *	|   29   | SIGPOLL    | SIGPROF    |
 *	|   30   | SIGPWR     | SIGXCPU    |
 *	|   31   | SIGSYS     | SIGXFSZ    |
 * 	====================================
 *
 * Not every Linux signal maps to a Solaris signal, nor does every Solaris
 * signal map to a Linux counterpart. However, when signals do map, the
 * mapping is unique.
 *
 * One mapping issue is that Linux supports 33 real time signals, with SIGRTMIN
 * typically starting at or near 32 (SIGRTMIN) and proceeding to 64 (SIGRTMAX)
 * (SIGRTMIN is "at or near" 32 because glibc usually "steals" one ore more of
 * these signals for its own internal use, adjusting SIGRTMIN and SIGRTMAX as
 * needed.)  Conversely, Solaris actively uses signals 32-40 for other purposes
 * and supports exactly 32 real time signals, in the range 41 (SIGRTMIN)
 * to 72 (SIGRTMAX).
 *
 * At present, attempting to translate a Linux signal equal to 63
 * will generate an error (we allow SIGRTMAX because a program
 * should be able to send SIGRTMAX without getting an EINVAL, though obviously
 * anything that loops through the signals from SIGRTMIN to SIGRTMAX will
 * fail.)
 *
 * Similarly, attempting to translate a native Solaris signal in the range
 * 32-40 will also generate an error as we don't want to support the receipt of
 * those signals from the Solaris global zone.
 */

/*
 * Linux to Solaris signal map
 *
 * Usage:  solaris_signal = ltos_signum[lx_signal];
 */
const int
ltos_signo[LX_NSIG + 1] = {
	0,
	SIGHUP,
	SIGINT,
	SIGQUIT,
	SIGILL,
	SIGTRAP,
	SIGABRT,
	SIGBUS,
	SIGFPE,
	SIGKILL,
	SIGUSR1,
	SIGSEGV,
	SIGUSR2,
	SIGPIPE,
	SIGALRM,
	SIGTERM,
	SIGEMT,			/* 16:  Linux SIGSTKFLT; use Solaris SIGEMT */
	SIGCHLD,
	SIGCONT,
	SIGSTOP,
	SIGTSTP,
	SIGTTIN,
	SIGTTOU,
	SIGURG,
	SIGXCPU,
	SIGXFSZ,
	SIGVTALRM,
	SIGPROF,
	SIGWINCH,
	SIGPOLL,
	SIGPWR,
	SIGSYS,
	_SIGRTMIN,		/* 32:  Linux SIGRTMIN */
	_SIGRTMIN + 1,
	_SIGRTMIN + 2,
	_SIGRTMIN + 3,
	_SIGRTMIN + 4,
	_SIGRTMIN + 5,
	_SIGRTMIN + 6,
	_SIGRTMIN + 7,
	_SIGRTMIN + 8,
	_SIGRTMIN + 9,
	_SIGRTMIN + 10,
	_SIGRTMIN + 11,
	_SIGRTMIN + 12,
	_SIGRTMIN + 13,
	_SIGRTMIN + 14,
	_SIGRTMIN + 15,
	_SIGRTMIN + 16,
	_SIGRTMIN + 17,
	_SIGRTMIN + 18,
	_SIGRTMIN + 19,
	_SIGRTMIN + 20,
	_SIGRTMIN + 21,
	_SIGRTMIN + 22,
	_SIGRTMIN + 23,
	_SIGRTMIN + 24,
	_SIGRTMIN + 25,
	_SIGRTMIN + 26,
	_SIGRTMIN + 27,
	_SIGRTMIN + 28,
	_SIGRTMIN + 29,
	_SIGRTMIN + 30,
	_SIGRTMIN + 31,
	_SIGRTMAX,		/* 64:  Linux SIGRTMAX */
};

/*
 * Solaris to Linux signal map
 *
 * Usage:  lx_signal = stol_signo[solaris_signal];
 */
const int
stol_signo[NSIG] = {
	0,
	LX_SIGHUP,
	LX_SIGINT,
	LX_SIGQUIT,
	LX_SIGILL,
	LX_SIGTRAP,
	LX_SIGABRT,
	LX_SIGSTKFLT,		/* 7:  Solaris SIGEMT; use for LX_SIGSTKFLT */
	LX_SIGFPE,
	LX_SIGKILL,
	LX_SIGBUS,
	LX_SIGSEGV,
	LX_SIGSYS,
	LX_SIGPIPE,
	LX_SIGALRM,
	LX_SIGTERM,
	LX_SIGUSR1,
	LX_SIGUSR2,
	LX_SIGCHLD,
	LX_SIGPWR,
	LX_SIGWINCH,
	LX_SIGURG,
	LX_SIGPOLL,
	LX_SIGSTOP,
	LX_SIGTSTP,
	LX_SIGCONT,
	LX_SIGTTIN,
	LX_SIGTTOU,
	LX_SIGVTALRM,
	LX_SIGPROF,
	LX_SIGXCPU,
	LX_SIGXFSZ,
	-1,			/* 32:  Solaris SIGWAITING */
	-1,			/* 33:  Solaris SIGLWP */
	-1,			/* 34:  Solaris SIGFREEZE */
	-1,			/* 35:  Solaris SIGTHAW */
	-1,			/* 36:  Solaris SIGCANCEL */
	-1,			/* 37:  Solaris SIGLOST */
	-1,			/* 38:  Solaris SIGXRES */
	-1,			/* 39:  Solaris SIGJVM1 */
	-1,			/* 40:  Solaris SIGJVM2 */
	-1,			/* 41:  Solaris SIGINFO */
	LX_SIGRTMIN,		/* 42:  Solaris _SIGRTMIN */
	LX_SIGRTMIN + 1,
	LX_SIGRTMIN + 2,
	LX_SIGRTMIN + 3,
	LX_SIGRTMIN + 4,
	LX_SIGRTMIN + 5,
	LX_SIGRTMIN + 6,
	LX_SIGRTMIN + 7,
	LX_SIGRTMIN + 8,
	LX_SIGRTMIN + 9,
	LX_SIGRTMIN + 10,
	LX_SIGRTMIN + 11,
	LX_SIGRTMIN + 12,
	LX_SIGRTMIN + 13,
	LX_SIGRTMIN + 14,
	LX_SIGRTMIN + 15,
	LX_SIGRTMIN + 16,
	LX_SIGRTMIN + 17,
	LX_SIGRTMIN + 18,
	LX_SIGRTMIN + 19,
	LX_SIGRTMIN + 20,
	LX_SIGRTMIN + 21,
	LX_SIGRTMIN + 22,
	LX_SIGRTMIN + 23,
	LX_SIGRTMIN + 24,
	LX_SIGRTMIN + 25,
	LX_SIGRTMIN + 26,
	LX_SIGRTMIN + 27,
	LX_SIGRTMIN + 28,
	LX_SIGRTMIN + 29,
	LX_SIGRTMIN + 30,
	LX_SIGRTMIN + 31,
	LX_SIGRTMAX,		/* 74: Solaris _SIGRTMAX */
};

/*
 * Convert an illumos native signal number to a Linux signal number and return
 * it.  If no valid conversion is possible, the function fails back to the
 * value of "defsig".  In userland, passing a default signal number of "-1"
 * will abort the program if the signal number could not be converted.
 */
int
lx_stol_signo(int signo, int defsig)
{
	int rval;

#ifdef	_KERNEL
	VERIFY3S(defsig, >=, 0);
#endif

	if (signo < 0 || signo >= NSIG || (rval = stol_signo[signo]) < 1) {
#ifndef	_KERNEL
		VERIFY3S(defsig, >=, 0);
#endif
		return (defsig);
	}

	return (rval);
}


/*
 * Convert a Linux signal number to an illumos signal number and return it.
 * Error behavior is identical to lx_stol_signo.
 */
int
lx_ltos_signo(int signo, int defsig)
{
#ifdef	_KERNEL
	VERIFY3S(defsig, >=, 0);
#endif

	if (signo < 1 || signo >= NSIG) {
#ifndef	_KERNEL
		VERIFY3S(defsig, >=, 0);
#endif
		return (defsig);
	}

	return (ltos_signo[signo]);
}

/*
 * Convert the "status" field of a SIGCLD siginfo_t.  We need to extract the
 * illumos signal number and convert it to a Linux signal number while leaving
 * the ptrace(2) event bits intact.  In userland, passing a default signal
 * number of "-1" will abort the program if the signal number could not be
 * converted, as for lx_stol_signo().
 */
int
lx_stol_status(int s, int defsig)
{
	/*
	 * We mask out the top bit here in case PTRACE_O_TRACESYSGOOD
	 * is in use and 0x80 has been ORed with the signal number.
	 */
	int stat = lx_stol_signo(s & 0x7f, defsig);

	/*
	 * We must mix in the ptrace(2) event which may be stored in
	 * the second byte of the status code.  We also re-include the
	 * PTRACE_O_TRACESYSGOOD bit.
	 */
	return ((s & 0xff80) | stat);
}

int
lx_stol_sigcode(int code)
{
	switch (code) {
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
		return (code);
	}
}
