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

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


/*
 * UNIX shell
 */

#include	"defs.h"
#include	<sys/procset.h>
#include	<siginfo.h>
#include	<ucontext.h>
#include	<errno.h>
#include	<string.h>

extern void hupforegnd(void);

/* previous signal handler for signal 0 */
static	void (*psig0_func)() = SIG_ERR;
static	char sigsegv_stack[SIGSTKSZ];

static void sigsegv(int sig, siginfo_t *sip, ucontext_t *uap);
static void fault();
static BOOL sleeping = 0;
static unsigned char *trapcom[MAXTRAP]; /* array of actions, one per signal */
static BOOL trapflg[MAXTRAP] =
{
	0,
	0,	/* hangup */
	0,	/* interrupt */
	0,	/* quit */
	0,	/* illegal instr */
	0,	/* trace trap */
	0,	/* IOT */
	0,	/* EMT */
	0,	/* float pt. exp */
	0,	/* kill */
	0, 	/* bus error */
	0,	/* memory faults */
	0,	/* bad sys call */
	0,	/* bad pipe call */
	0,	/* alarm */
	0, 	/* software termination */
	0,	/* unassigned */
	0,	/* unassigned */
	0,	/* death of child */
	0,	/* power fail */
	0,	/* window size change */
	0,	/* urgent IO condition */
	0,	/* pollable event occured */
	0,	/* stopped by signal */
	0,	/* stopped by user */
	0,	/* continued */
	0,	/* stopped by tty input */
	0,	/* stopped by tty output */
	0,	/* virtual timer expired */
	0,	/* profiling timer expired */
	0,	/* exceeded cpu limit */
	0,	/* exceeded file size limit */
	0, 	/* process's lwps are blocked */
	0,	/* special signal used by thread library */
	0, 	/* check point freeze */
	0,	/* check point thaw */
};

static void (*(
sigval[MAXTRAP]))() =
{
	0,
	done, 	/* hangup */
	fault,	/* interrupt */
	fault,	/* quit */
	done,	/* illegal instr */
	done,	/* trace trap */
	done,	/* IOT */
	done,	/* EMT */
	done,	/* floating pt. exp */
	0,	/* kill */
	done, 	/* bus error */
	sigsegv,	/* memory faults */
	done, 	/* bad sys call */
	done,	/* bad pipe call */
	done,	/* alarm */
	fault,	/* software termination */
	done,	/* unassigned */
	done,	/* unassigned */
	0,	/* death of child */
	done,	/* power fail */
	0,	/* window size change */
	done,	/* urgent IO condition */
	done,	/* pollable event occured */
	0,	/* uncatchable stop */
	0,	/* foreground stop */
	0,	/* stopped process continued */
	0,	/* background tty read */
	0,	/* background tty write */
	done,	/* virtual timer expired */
	done,	/* profiling timer expired */
	done,	/* exceeded cpu limit */
	done,	/* exceeded file size limit */
	0, 	/* process's lwps are blocked */
	0,	/* special signal used by thread library */
	0, 	/* check point freeze */
	0,	/* check point thaw */
};

static int
ignoring(int i)
{
	struct sigaction act;
	if (trapflg[i] & SIGIGN)
		return (1);
	sigaction(i, 0, &act);
	if (act.sa_handler == SIG_IGN) {
		trapflg[i] |= SIGIGN;
		return (1);
	}
	return (0);
}

static void
clrsig(i)
int	i;
{
	if (trapcom[i] != 0) {
		free(trapcom[i]);
		trapcom[i] = 0;
	}


	if (trapflg[i] & SIGMOD) {
		/*
		 * If the signal has been set to SIGIGN and we are now
		 * clearing the disposition of the signal (restoring it
		 * back to its default value) then we need to clear this
		 * bit as well
		 *
		 */
		if (trapflg[i] & SIGIGN)
			trapflg[i] &= ~SIGIGN;

		trapflg[i] &= ~SIGMOD;
		handle(i, sigval[i]);
	}
}

void
done(int sig)
{
	unsigned char	*t;
	int	savxit;

	if (t = trapcom[0]) {
		trapcom[0] = 0;
		/* Save exit value so trap handler will not change its val */
		savxit = exitval;
		execexp(t, 0);
		exitval = savxit;		/* Restore exit value */
		free(t);
	}
	else
		chktrap();

	rmtemp(0);
	rmfunctmp();

#ifdef ACCT
	doacct();
#endif
	if (flags & subsh) {
		/* in a subshell, need to wait on foreground job */
		collect_fg_job();
	}

	(void) endjobs(0);
	if (sig) {
		sigset_t set;

		/*
		 * If the signal is SIGHUP, then it should be delivered
		 * to the process group leader of the foreground job.
		 */
		if (sig == SIGHUP)
			hupforegnd();

		sigemptyset(&set);
		sigaddset(&set, sig);
		sigprocmask(SIG_UNBLOCK, &set, 0);
		handle(sig, SIG_DFL);
		kill(mypid, sig);
	}
	exit(exitval);
}

static void
fault(int sig)
{
	int flag;

	switch (sig) {
		case SIGALRM:
			if (sleeping)
				return;
			break;
	}

	if (trapcom[sig])
		flag = TRAPSET;
	else if (flags & subsh)
		done(sig);
	else
		flag = SIGSET;

	trapnote |= flag;
	trapflg[sig] |= flag;
}

int
handle(sig, func)
	int sig;
	void (*func)();
{
	int	ret;
	struct sigaction act, oact;

	if (func == SIG_IGN && (trapflg[sig] & SIGIGN))
		return (0);

	/*
	 * Ensure that sigaction is only called with valid signal numbers,
	 * we can get random values back for oact.sa_handler if the signal
	 * number is invalid
	 *
	 */
	if (sig > MINTRAP && sig < MAXTRAP) {
		sigemptyset(&act.sa_mask);
		act.sa_flags = (sig == SIGSEGV) ? (SA_ONSTACK | SA_SIGINFO) : 0;
		act.sa_handler = func;
		sigaction(sig, &act, &oact);
	}

	if (func == SIG_IGN)
		trapflg[sig] |= SIGIGN;

	/*
	 * Special case for signal zero, we can not obtain the previos
	 * action by calling sigaction, instead we save it in the variable
	 * psig0_func, so we can test it next time through this code
	 *
	 */
	if (sig == 0) {
		ret = (psig0_func != func);
		psig0_func = func;
	} else {
		ret = (func != oact.sa_handler);
	}

	return (ret);
}

void
stdsigs()
{
	int	i;
	stack_t	ss;
	int rtmin = (int)SIGRTMIN;
	int rtmax = (int)SIGRTMAX;

	ss.ss_size = SIGSTKSZ;
	ss.ss_sp = sigsegv_stack;
	ss.ss_flags = 0;
	if (sigaltstack(&ss, NULL) == -1) {
		error("sigaltstack(2) failed");
	}

	for (i = 1; i < MAXTRAP; i++) {
		if (i == rtmin) {
			i = rtmax;
			continue;
		}
		if (sigval[i] == 0)
			continue;
		if (i != SIGSEGV && ignoring(i))
			continue;
		handle(i, sigval[i]);
	}

	/*
	 * handle all the realtime signals
	 *
	 */
	for (i = rtmin; i <= rtmax; i++) {
		handle(i, done);
	}
}

void
oldsigs()
{
	int	i;
	unsigned char	*t;

	i = MAXTRAP;
	while (i--) {
		t = trapcom[i];
		if (t == 0 || *t)
			clrsig(i);
		trapflg[i] = 0;
	}
	trapnote = 0;
}

/*
 * check for traps
 */

void
chktrap()
{
	int	i = MAXTRAP;
	unsigned char	*t;

	trapnote &= ~TRAPSET;
	while (--i) {
		if (trapflg[i] & TRAPSET) {
			trapflg[i] &= ~TRAPSET;
			if (t = trapcom[i]) {
				int	savxit = exitval;

				execexp(t, 0);
				exitval = savxit;
				exitset();
			}
		}
	}
}

void
systrap(int argc, char **argv)
{
	int sig;

	if (argc == 1) {
		/*
		 * print out the current action associated with each signal
		 * handled by the shell
		 *
		 */
		for (sig = 0; sig < MAXTRAP; sig++) {
			if (trapcom[sig]) {
				prn_buff(sig);
				prs_buff(colon);
				prs_buff(trapcom[sig]);
				prc_buff(NL);
			}
		}
	} else {
		/*
		 * set the action for the list of signals
		 *
		 */
		char *cmd = *argv, *a1 = *(argv+1);
		BOOL noa1;
		noa1 = (str2sig(a1, &sig) == 0);
		if (noa1 == 0)
			++argv;
		while (*++argv) {
			if (str2sig(*argv, &sig) < 0 ||
			    sig >= MAXTRAP || sig < MINTRAP ||
			    sig == SIGSEGV) {
				failure(cmd, badtrap);
			} else if (noa1) {
				/*
				 * no action specifed so reset the siganl
				 * to its default disposition
				 *
				 */
				clrsig(sig);
			} else if (*a1) {
				/*
				 * set the action associated with the signal
				 * to a1
				 *
				 */
				if (trapflg[sig] & SIGMOD || sig == 0 ||
				    !ignoring(sig)) {
					handle(sig, fault);
					trapflg[sig] |= SIGMOD;
					replace(&trapcom[sig], a1);
				}
			} else if (handle(sig, SIG_IGN)) {
				/*
				 * set the action associated with the signal
				 * to SIG_IGN
				 *
				 */
				trapflg[sig] |= SIGMOD;
				replace(&trapcom[sig], a1);
			}
		}
	}
}

void
sh_sleep(unsigned int ticks)
{
	sigset_t set, oset;
	struct sigaction act, oact;


	/*
	 * add SIGALRM to mask
	 */

	sigemptyset(&set);
	sigaddset(&set, SIGALRM);
	sigprocmask(SIG_BLOCK, &set, &oset);

	/*
	 * catch SIGALRM
	 */

	sigemptyset(&act.sa_mask);
	act.sa_flags = 0;
	act.sa_handler = fault;
	sigaction(SIGALRM, &act, &oact);

	/*
	 * start alarm and wait for signal
	 */

	alarm(ticks);
	sleeping = 1;
	sigsuspend(&oset);
	sleeping = 0;

	/*
	 * reset alarm, catcher and mask
	 */

	alarm(0);
	sigaction(SIGALRM, &oact, NULL);
	sigprocmask(SIG_SETMASK, &oset, 0);

}

void
sigsegv(int sig, siginfo_t *sip, ucontext_t *uap)
{
	if (sip == (siginfo_t *)NULL) {
		/*
		 * This should never happen, but if it does this is all we
		 * can do. It can only happen if sigaction(2) for SIGSEGV
		 * has been called without SA_SIGINFO being set.
		 *
		 */

		exit(ERROR);
	} else {
		if (sip->si_code <= 0) {
			/*
			 * If we are here then SIGSEGV must have been sent to
			 * us from a user process NOT as a result of an
			 * internal error within the shell eg
			 * kill -SEGV $$
			 * will bring us here. So do the normal thing.
			 *
			 */
			fault(sig);
		} else {
			/*
			 * If we are here then there must have been an internal
			 * error within the shell to generate SIGSEGV eg
			 * the stack is full and we cannot call any more
			 * functions (Remeber this signal handler is running
			 * on an alternate stack). So we just exit cleanly
			 * with an error status (no core file).
			 */
			exit(ERROR);
		}
	}
}
