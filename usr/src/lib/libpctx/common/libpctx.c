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
 */

/*
 * This file contains a set of generic routines for periodically
 * sampling the state of another process, or tree of processes.
 *
 * It is built upon the infrastructure provided by libproc.
 */

#include <sys/wait.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <libproc.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <ctype.h>
#include <libintl.h>
#include <libcpc.h>
#include <sys/cpc_impl.h>

#include "libpctx.h"

struct __pctx {
	pctx_errfn_t *errfn;
	struct ps_prochandle *Pr;
	void *uarg;
	pctx_sysc_execfn_t *exec;
	pctx_sysc_forkfn_t *fork;
	pctx_sysc_exitfn_t *exit;
	pctx_sysc_lwp_createfn_t *lwp_create;
	pctx_init_lwpfn_t *init_lwp;
	pctx_fini_lwpfn_t *fini_lwp;
	pctx_sysc_lwp_exitfn_t *lwp_exit;
	int verbose;
	int created;
	int sigblocked;
	int terminate;
	sigset_t savedset;
	cpc_t *cpc;
};

static void (*pctx_cpc_callback)(cpc_t *cpc, struct __pctx *pctx);

static void
pctx_default_errfn(const char *fn, const char *fmt, va_list ap)
{
	(void) fprintf(stderr, "libpctx: pctx_%s: ", fn);
	(void) vfprintf(stderr, fmt, ap);
}

/*PRINTFLIKE3*/
static void
pctx_error(pctx_t *pctx, const char *fn, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	pctx->errfn(fn, fmt, ap);
	va_end(ap);
}

/*
 * Create a new process and bind the user args for it
 */
pctx_t *
pctx_create(
    const char *filename,
    char *const *argv,
    void *arg,
    int verbose,
    pctx_errfn_t *errfn)
{
	static const char fn[] = "create";
	int err;
	pctx_t *pctx;

	pctx = calloc(1, sizeof (*pctx));
	pctx->uarg = arg;
	pctx->verbose = verbose;
	pctx->terminate = 0;
	pctx->errfn = errfn ? errfn : pctx_default_errfn;

	if ((pctx->Pr = Pcreate(filename, argv, &err, 0, 0)) == NULL) {
		switch (err) {
		case C_PERM:
			pctx_error(pctx, fn, gettext("cannot trace set-id or "
			    "unreadable program '%s'\n"), filename);
			break;
		case C_LP64:
			pctx_error(pctx, fn, gettext("cannot control LP64 "
			    "program '%s'\n"), filename);
			break;
		case C_NOEXEC:
			pctx_error(pctx, fn, gettext("cannot execute "
			    "program '%s'\n"), filename);
			break;
		case C_NOENT:
			pctx_error(pctx, fn, gettext("cannot find"
			    "program '%s'\n"), filename);
			break;
		case C_FORK:
			pctx_error(pctx, fn, gettext("cannot fork, "
			    "program '%s'\n"), filename);
			break;
		default:
			pctx_error(pctx, fn, gettext("%s, program '%s'\n"),
			    Pcreate_error(err), filename);
			break;
		}
		free(pctx);
		return (NULL);
	}

	if (Psysentry(pctx->Pr, SYS_exit, 1) == -1) {
		pctx_error(pctx, fn,
		    gettext("can't stop-on-exit() program '%s'\n"), filename);
		Prelease(pctx->Pr, PRELEASE_KILL);
		free(pctx);
		return (NULL);
	}
	/*
	 * Set kill-on-last-close so the controlled process
	 * dies if we die.
	 */
	pctx->created = 1;
	(void) Psetflags(pctx->Pr, PR_KLC);
	(void) pctx_set_events(pctx, PCTX_NULL_EVENT);

	return (pctx);
}

/*
 * Capture an existing process and bind the user args for it
 */
pctx_t *
pctx_capture(pid_t pid, void *arg, int verbose, pctx_errfn_t *errfn)
{
	static const char fn[] = "capture";
	int err;
	pctx_t *pctx;

	pctx = calloc(1, sizeof (*pctx));
	pctx->uarg = arg;
	pctx->verbose = verbose;
	pctx->errfn = errfn ? errfn : pctx_default_errfn;

	if ((pctx->Pr = Pgrab(pid, 0, &err)) == NULL) {
		switch (err) {
		case G_NOPROC:
			pctx_error(pctx, fn,
			    gettext("pid %d doesn't exist\n"), (int)pid);
			break;
		case G_ZOMB:
			pctx_error(pctx, fn,
			    gettext("pid %d is a zombie\n"), (int)pid);
			break;
		case G_PERM:
			pctx_error(pctx, fn,
			    gettext("pid %d: permission denied\n"), (int)pid);
			break;
		case G_BUSY:
			pctx_error(pctx, fn,
			    gettext("pid %d is already being traced\n"),
			    (int)pid);
			break;
		case G_SYS:
			pctx_error(pctx, fn,
			    gettext("pid %d is a system process\n"), (int)pid);
			break;
		case G_SELF:
			pctx_error(pctx, fn,
			    gettext("cannot capture self!\n"));
			break;
		case G_LP64:
			pctx_error(pctx, fn, gettext("cannot control LP64 "
			    "process, pid %d\n"), (int)pid);
			break;
		default:
			pctx_error(pctx, fn, gettext("%s: pid %d\n"),
			    Pgrab_error(err), (int)pid);
			break;
		}
		free(pctx);
		return (NULL);
	}

	if (Psysentry(pctx->Pr, SYS_exit, 1) == -1) {
		pctx_error(pctx, fn,
		    gettext("can't stop-on-exit() pid %d\n"), (int)pid);
		Prelease(pctx->Pr, PRELEASE_CLEAR);
		free(pctx);
		return (NULL);
	}

	/*
	 * Set run-on-last-close so the controlled process
	 * runs even if we die on a signal.  This is because
	 * we grabbed an existing process - it would be impolite
	 * to cause it to die if we exit prematurely.
	 */
	pctx->created = 0;
	(void) Psetflags(pctx->Pr, PR_RLC);
	(void) pctx_set_events(pctx, PCTX_NULL_EVENT);

	return (pctx);
}

/*ARGSUSED*/
static void
default_void(pctx_t *pctx)
{}

/*ARGSUSED*/
static int
default_int(pctx_t *pctx)
{
	return (0);
}

int
pctx_set_events(pctx_t *pctx, ...)
{
	static const char fn[] = "set_events";
	va_list pvar;
	int error = 0;
	pctx_event_t event;

	va_start(pvar, pctx);
	do {
		switch (event = (pctx_event_t)va_arg(pvar, pctx_event_t)) {
		case PCTX_NULL_EVENT:
			break;
		case PCTX_SYSC_EXEC_EVENT:
			pctx->exec = (pctx_sysc_execfn_t *)
			    va_arg(pvar, pctx_sysc_execfn_t *);
			break;
		case PCTX_SYSC_FORK_EVENT:
			pctx->fork = (pctx_sysc_forkfn_t *)
			    va_arg(pvar, pctx_sysc_forkfn_t *);
			break;
		case PCTX_SYSC_EXIT_EVENT:	/* always intercepted */
			pctx->exit = (pctx_sysc_exitfn_t *)
			    va_arg(pvar, pctx_sysc_exitfn_t *);
			break;
		case PCTX_SYSC_LWP_CREATE_EVENT:
			pctx->lwp_create = (pctx_sysc_lwp_createfn_t *)
			    va_arg(pvar, pctx_sysc_lwp_createfn_t *);
			break;
		case PCTX_INIT_LWP_EVENT:
			pctx->init_lwp = (pctx_init_lwpfn_t *)
			    va_arg(pvar, pctx_init_lwpfn_t *);
			break;
		case PCTX_FINI_LWP_EVENT:
			pctx->fini_lwp = (pctx_fini_lwpfn_t *)
			    va_arg(pvar, pctx_fini_lwpfn_t *);
			break;
		case PCTX_SYSC_LWP_EXIT_EVENT:
			pctx->lwp_exit = (pctx_sysc_lwp_exitfn_t *)
			    va_arg(pvar, pctx_sysc_lwp_exitfn_t *);
			break;
		default:
			pctx_error(pctx, fn,
			    gettext("unknown event type %x\n"), event);
			error = -1;
			break;
		}
	} while (event != PCTX_NULL_EVENT && error == 0);
	va_end(pvar);

	if (error != 0)
		return (error);

	if (pctx->exec == NULL)
		pctx->exec = (pctx_sysc_execfn_t *)(uintptr_t)default_int;
	if (pctx->fork == NULL)
		pctx->fork = (pctx_sysc_forkfn_t *)(uintptr_t)default_void;
	if (pctx->exit == NULL)
		pctx->exit = (pctx_sysc_exitfn_t *)(uintptr_t)default_void;
	if (pctx->lwp_create == NULL)
		pctx->lwp_create = (pctx_sysc_lwp_createfn_t *)
		    (uintptr_t)default_int;
	if (pctx->init_lwp == NULL)
		pctx->init_lwp = (pctx_init_lwpfn_t *)(uintptr_t)default_int;
	if (pctx->fini_lwp == NULL)
		pctx->fini_lwp = (pctx_fini_lwpfn_t *)(uintptr_t)default_int;
	if (pctx->lwp_exit == NULL)
		pctx->lwp_exit = (pctx_sysc_lwp_exitfn_t *)
		    (uintptr_t)default_int;

	if ((uintptr_t)pctx->fork != (uintptr_t)default_void) {
		(void) Psysexit(pctx->Pr, SYS_vfork, 1);
		(void) Psysexit(pctx->Pr, SYS_forksys, 1);
		if (Psetflags(pctx->Pr, PR_FORK) == -1)
			error = -1;
	} else {
		(void) Psysexit(pctx->Pr, SYS_vfork, 0);
		(void) Psysexit(pctx->Pr, SYS_forksys, 0);
		if (Punsetflags(pctx->Pr, PR_FORK) == -1)
			error = -1;
	}

	/*
	 * exec causes termination of all but the exec-ing lwp,
	 * and resets the lwpid to one in the new address space.
	 */
	if ((uintptr_t)pctx->exec != (uintptr_t)default_int ||
	    (uintptr_t)pctx->fini_lwp != (uintptr_t)default_int ||
	    (uintptr_t)pctx->init_lwp != (uintptr_t)default_int) {
		(void) Psysexit(pctx->Pr, SYS_execve, 1);
		(void) Psysentry(pctx->Pr, SYS_execve, 1);
	} else {
		(void) Psysexit(pctx->Pr, SYS_execve, 0);
		(void) Psysentry(pctx->Pr, SYS_execve, 0);
	}

	(void) Psysexit(pctx->Pr, SYS_lwp_create,
	    (uintptr_t)pctx->lwp_create != (uintptr_t)default_int ||
	    (uintptr_t)pctx->init_lwp != (uintptr_t)default_int);

	(void) Psysentry(pctx->Pr, SYS_lwp_exit,
	    (uintptr_t)pctx->lwp_exit != (uintptr_t)default_int ||
	    (uintptr_t)pctx->fini_lwp != (uintptr_t)default_int);

	return (0);
}

static sigset_t termsig;

static void
__libpctx_init(void)
{
	/*
	 * Initialize the signal set used to shield ourselves from
	 * death-by-terminal-signal while the agent lwp is running.
	 */
	(void) sigemptyset(&termsig);
	(void) sigaddset(&termsig, SIGHUP);
	(void) sigaddset(&termsig, SIGTERM);
	(void) sigaddset(&termsig, SIGINT);
	(void) sigaddset(&termsig, SIGQUIT);
}

#pragma init(__libpctx_init)

static void
pctx_begin_syscalls(pctx_t *pctx)
{
	if (pctx->Pr == NULL)
		return;
	if (pctx->sigblocked++ == 0) {
		(void) sigprocmask(SIG_BLOCK, &termsig, &pctx->savedset);
		(void) Pcreate_agent(pctx->Pr);
	}
}

static void
pctx_end_syscalls(pctx_t *pctx)
{
	if (pctx->Pr == NULL)
		return;
	if (--pctx->sigblocked == 0) {
		(void) Pdestroy_agent(pctx->Pr);
		(void) sigprocmask(SIG_SETMASK, &pctx->savedset, NULL);
	}
}

/*
 * Iterate over the valid lwpids in the process, invoking the
 * action function on each one.
 */
static int
pctx_lwpiterate(pctx_t *pctx, int (*action)(pctx_t *, pid_t, id_t, void *))
{
	const pstatus_t *pstatus;
	char lstatus[64];
	struct stat statb;
	lwpstatus_t *lwps;
	prheader_t *prh;
	int fd, nlwp;
	int ret = 0;

	if ((uintptr_t)action == (uintptr_t)default_int)
		return (0);

	pstatus = Pstatus(pctx->Pr);
	if (pstatus->pr_nlwp <= 1) {
		pctx_begin_syscalls(pctx);
		ret = action(pctx, pstatus->pr_pid, 1, pctx->uarg);
		pctx_end_syscalls(pctx);
		return (ret);
	}

	(void) snprintf(lstatus, sizeof (lstatus),
	    "/proc/%d/lstatus", (int)pstatus->pr_pid);

	if ((fd = open(lstatus, O_RDONLY)) < 0 ||
	    fstat(fd, &statb) != 0) {
		if (fd >= 0)
			(void) close(fd);
		return (-1);
	}

	prh = malloc(statb.st_size);
	if (read(fd, prh, statb.st_size) <
	    sizeof (prheader_t) + sizeof (lwpstatus_t)) {
		(void) close(fd);
		free(prh);
		return (-1);
	}
	(void) close(fd);

	/* LINTED pointer cast may result in improper alignment */
	lwps = (lwpstatus_t *)(prh + 1);
	pctx_begin_syscalls(pctx);
	for (nlwp = prh->pr_nent; nlwp > 0; nlwp--) {
		if (action(pctx,
		    pstatus->pr_pid, lwps->pr_lwpid, pctx->uarg) != 0)
			ret = -1;
		/* LINTED pointer cast may result in improper alignment */
		lwps = (lwpstatus_t *)((char *)lwps + prh->pr_entsize);
	}
	pctx_end_syscalls(pctx);
	free(prh);
	return (ret);
}

/*
 * Free any associated state, but leave the process stopped if it
 * is still under our control.  (If it isn't under our control,
 * it should just run to completion when we do our last close)
 */
static void
pctx_free(pctx_t *pctx)
{
	if (pctx->cpc != NULL && pctx_cpc_callback != NULL)
		(*pctx_cpc_callback)(pctx->cpc, pctx);
	if (pctx->Pr) {
		Pfree(pctx->Pr);
		pctx->Pr = NULL;
	}
	pctx->errfn = pctx_default_errfn;
}

/*
 * Completely release the process from our control and discard all our state
 */
void
pctx_release(pctx_t *pctx)
{
	if (pctx->Pr) {
		Prelease(pctx->Pr, PRELEASE_CLEAR);
		pctx->Pr = NULL;
	}

	pctx_free(pctx);
	bzero(pctx, sizeof (*pctx));
	free(pctx);
}

static void
msincr(struct timeval *tv, uint_t msec)
{
	tv->tv_sec += msec / MILLISEC;
	tv->tv_usec += (msec % MILLISEC) * MILLISEC;
	if (tv->tv_usec > MICROSEC) {
		tv->tv_sec++;
		tv->tv_usec -= MICROSEC;
	}
}

static uint_t
msdiff(struct timeval *tva, struct timeval *tvb)
{
	time_t sdiff = tva->tv_sec - tvb->tv_sec;
	suseconds_t udiff = tva->tv_usec - tvb->tv_usec;

	if (sdiff < 0)
		return (0);
	if (udiff < 0) {
		udiff += MICROSEC;
		sdiff--;
	}
	if (sdiff < 0)
		return (0);
	if (sdiff >= (INT_MAX / MILLISEC))
		return ((uint_t)INT_MAX);
	return ((uint_t)(sdiff * MILLISEC + udiff / MILLISEC));
}

int
pctx_run(
	pctx_t *pctx,
	uint_t msec,
	uint_t nsamples,
	int (*tick)(pctx_t *, pid_t, id_t, void *))
{
	static const char fn[] = "run";
	struct timeval tvgoal, tvnow;
	uint_t mswait = 0;
	int running = 1;
	const pstatus_t *pstatus;
	psinfo_t psinfo;
	void (*sigsaved)();
	id_t lwpid;
	pid_t pid = Pstatus(pctx->Pr)->pr_pid;
	int pstate;

	if (msec == 0)
		nsamples = 0;
	if (nsamples == 0)
		nsamples = UINT_MAX;

	/*
	 * Casually discard any knowledge of the children we create
	 */
	sigsaved = signal(SIGCHLD, SIG_IGN);

	/*
	 * Since we've just "discovered" this process which might have
	 * been running for weeks, deliver some init_lwp events so
	 * that our caller gets a handle on the process.
	 */
	if (pctx_lwpiterate(pctx, pctx->init_lwp) != 0) {
		if (pctx->verbose)
			pctx_error(pctx, fn,
			    gettext("%d: lwp discovery failed\n"), (int)pid);
		goto bailout;
	}

	if (msec != 0) {
		/*
		 * tvgoal represents the time at which the sample
		 * should next be taken.
		 */
		(void) gettimeofday(&tvgoal, 0);
		msincr(&tvgoal, msec);
	}

	/*
	 * The event handling loop continues while running is 1.
	 * running becomes 0 when either the controlled process has
	 * exited successfully or the number of time samples has expired.
	 * Otherwise, if an error has occurred, running becomes -1.
	 */
	while (running == 1 && !pctx->terminate) {

		if (Psetrun(pctx->Pr, 0, 0) != 0) {
			if (pctx->verbose)
				pctx_error(pctx, fn,
				    gettext("%d: Psetrun\n"), (int)pid);
			break;
		}

		if (msec != 0) {
			/*
			 * This timing loop attempts to estimate the number
			 * of milliseconds between our "goal" time (when
			 * we should stop the process and run the tick
			 * routine) and the current time.
			 *
			 * If we ever find ourselves running behind i.e. we
			 * missed our goal, then we skip ahead to the next
			 * goal instead.
			 */
			do {
				(void) gettimeofday(&tvnow, 0);
				if ((mswait = msdiff(&tvgoal, &tvnow)) == 0) {
					msincr(&tvgoal, msec);
					/*
					 * Skip ahead to the next goal, unless
					 * there is only one more sample left
					 * to take.
					 */
					if (nsamples != 1)
						nsamples--;
				}
			} while (mswait == 0 && !pctx->terminate);
		}

		if (pctx->terminate)
			goto bailout;
		else
			(void) Pwait(pctx->Pr, mswait);

checkstate:
		switch (pstate = Pstate(pctx->Pr)) {
		case PS_RUN:
			/*
			 * Try again, but wait for up to 5 seconds.
			 */
			if (Pstop(pctx->Pr, 5 * MILLISEC) == -1 ||
			    (pstate = Pstate(pctx->Pr)) != PS_STOP) {
				pctx_error(pctx, fn,
				    gettext("%d: won't stop\n"), (int)pid);
			}
			break;
		case PS_STOP:
			break;
		case PS_LOST:
			/*
			 * Lost control - probably execed a setuid/setgid
			 * executable.  Try and get control back again,
			 * else bail ..
			 */
			(void) Preopen(pctx->Pr);
			if ((pstate = Pstate(pctx->Pr)) != PS_LOST)
				goto checkstate;
			pctx_error(pctx, fn,
			    gettext("%d: execed a program that cannot "
			    "be tracked\n"), (int)pid);
			running = -1;
			break;
		case PS_UNDEAD:
		case PS_DEAD:
			if (pctx->verbose)
				pctx_error(pctx, fn,
				    gettext("%d: process terminated\n"),
				    (int)pid);
			running = -1;
			break;
		default:
			if (pctx->verbose)
				pctx_error(pctx, fn,
				    gettext("%d: process state 0x%x?\n"),
				    (int)pid, pstate);
			break;
		}

		if (pstate != PS_STOP)
			break;

		pstatus = Pstatus(pctx->Pr);
		lwpid = pstatus->pr_lwp.pr_lwpid;
		switch (pstatus->pr_lwp.pr_why) {
		case PR_REQUESTED:
			msincr(&tvgoal, msec);
			if (pstatus->pr_flags & PR_VFORKP) {
				/*
				 * The process is in a vfork stupor until
				 * its child releases it via an exec.
				 * Don't sample it while it's in this state
				 * - we won't be able to create the agent.
				 */
				break;
			}
			if (pctx_lwpiterate(pctx, tick) != 0)
				running = -1;
			if (running == 1 && --nsamples == 0)
				running = 0;
			break;
		case PR_SYSENTRY:
			switch (pstatus->pr_lwp.pr_what) {
			case SYS_lwp_exit:
				pctx_begin_syscalls(pctx);
				(void) pctx->fini_lwp(pctx,
				    pid, lwpid, pctx->uarg);
				(void) pctx->lwp_exit(pctx,
				    pid, lwpid, pctx->uarg);
				pctx_end_syscalls(pctx);
				break;
			case SYS_exit:
				if (pctx_lwpiterate(pctx, pctx->fini_lwp)
				    != 0)
					running = -1;
				pctx->exit(pctx, pid, lwpid,
				    (int)pstatus->pr_lwp.pr_sysarg[0],
				    pctx->uarg);
				if (running == 1)
					running = 0;
				break;
			case SYS_execve:
				(void) pctx_lwpiterate(pctx, pctx->fini_lwp);
				break;
			default:
				pctx_error(pctx, fn,
				    "warning - pid %d sysentry(%d)\n",
				    (int)pid, pstatus->pr_lwp.pr_what);
				break;
			}
			break;
		case PR_SYSEXIT:
			switch (pstatus->pr_lwp.pr_what) {
			case SYS_execve:
				if (pstatus->pr_lwp.pr_errno) {
					/*
					 * The exec failed completely.
					 * Reinstate the lwps we fini'd
					 * at exec entrance
					 */
					if (pctx_lwpiterate(pctx,
					    pctx->init_lwp) == 0)
						running = 1;
					else
						running = -1;
					break;
				}
				if ((uintptr_t)pctx->exec ==
				    (uintptr_t)default_int) {
					running = 0;
					break;
				}
				(void) memcpy(&psinfo,
				    Ppsinfo(pctx->Pr), sizeof (psinfo));
				proc_unctrl_psinfo(&psinfo);
				pctx_begin_syscalls(pctx);
				if (pctx->exec(pctx, pid, lwpid,
				    psinfo.pr_psargs, pctx->uarg) != 0)
					running = -1;
				if (running == 1 && pctx->init_lwp(pctx,
				    pid, 1, pctx->uarg) != 0)
					running = -1;
				pctx_end_syscalls(pctx);
				break;
			case SYS_lwp_create:
				if (pstatus->pr_lwp.pr_errno ||
				    pstatus->pr_lwp.pr_rval1)
					break;
				pctx_begin_syscalls(pctx);
				if (pctx->init_lwp(pctx, pid, lwpid,
				    pctx->uarg) != 0)
					running = -1;
				if (running == 1 && pctx->lwp_create(pctx,
				    pid, lwpid, pctx->uarg) != 0)
					running = -1;
				pctx_end_syscalls(pctx);
				break;
			case SYS_vfork:
			case SYS_forksys:
				if (pstatus->pr_lwp.pr_errno)
					break;
				(void) fflush(NULL);
				switch (fork1()) {
					pid_t ppid;
					int wascreated;
					pctx_sysc_forkfn_t *forkfn;
				case 0:
					ppid = pid;
					pid = pstatus->pr_lwp.pr_rval1;
					wascreated = pctx->created;
					forkfn = pctx->fork;
					pctx_free(pctx);
					pctx = pctx_capture(pid, pctx->uarg,
					    pctx->verbose, pctx->errfn);
					if (pctx != NULL) {
						if (wascreated) {
							/*
							 * Set kill on last
							 * close so -all-
							 * children die.
							 */
							pctx->created = 1;
							(void) Psetflags(
							    pctx->Pr, PR_KLC);
						}
						(*forkfn)(pctx, ppid, pid,
						    lwpid, pctx->uarg);
						pctx_release(pctx);
						_exit(0);
					} else {
						_exit(1);
					}
					/*NOTREACHED*/
				case -1:
					pctx_error(pctx, fn,
					    "cannot follow pid %d: %s\n",
					    (int)pstatus->pr_lwp.pr_rval1,
					    strerror(errno));
					break;
				default:
					break;
				}
				break;
			default:
				pctx_error(pctx, fn, gettext(
				    "warning - pid %d sysexit(%d)\n"),
				    (int)pid, pstatus->pr_lwp.pr_what);
				break;
			}
			break;
		case PR_SIGNALLED:
			if (pctx->verbose)
				pctx_error(pctx, fn,
				    gettext("pid %d - signalled\n"), (int)pid);
			break;
		case PR_JOBCONTROL:
			if (pctx->verbose)
				pctx_error(pctx, fn,
				    gettext("pid %d - job control stop\n"),
				    (int)pid);
			running = -1;
			break;
		case PR_FAULTED:
			if (pctx->verbose)
				pctx_error(pctx, fn,
				    gettext("pid %d - faulted\n"), (int)pid);
			break;
		case PR_SUSPENDED:
			if (pctx->verbose)
				pctx_error(pctx, fn,
				    gettext("pid %d - suspended\n"), (int)pid);
			break;
		case PR_CHECKPOINT:
			if (pctx->verbose)
				pctx_error(pctx, fn,
				    gettext("pid %d - checkpoint\n"),
				    (int)pid);
			break;
		default:
			if (pctx->verbose)
				pctx_error(pctx, fn,
				    gettext("pid %d - reason %d\n"),
				    (int)pid, pstatus->pr_lwp.pr_why);
			running = -1;
			break;
		}
	}

bailout:
	(void) signal(SIGCHLD, sigsaved);

	if (pctx->terminate)
		return (0);

	switch (running) {
	case 0:
		return (0);
	case -1:
		return (-1);
	default:
		pctx_error(pctx, fn, gettext("lost control of pid %d\n"),
		    (int)pid);
		pctx_free(pctx);
		return (-1);
	}
}

/*
 * Execute the private 'cpc' system call in the context of the
 * controlled process.
 */
int
__pctx_cpc(pctx_t *pctx, cpc_t *cpc,
    int cmd, id_t lwpid, void *data1, void *data2, void *data3, int bufsize)
{
	sysret_t rval;
	argdes_t argd[5];
	argdes_t *adp = &argd[0];
	int error;

	/*
	 * Keep track of the relationship between cpc_t and pctx_t here.
	 * We store the last cpc_t used by libpctx, so that when this pctx is
	 * destroyed, libpctx can notify libcpc.
	 */

	if (pctx->cpc != NULL && pctx->cpc != cpc && pctx_cpc_callback != NULL)
		(*pctx_cpc_callback)(pctx->cpc, pctx);
	pctx->cpc = cpc;

	/*
	 * cmd and lwpid are passed in by value no matter what the command is.
	 */
	adp->arg_value = cmd;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;
	adp++;

	adp->arg_value = lwpid;
	adp->arg_object = NULL;
	adp->arg_type = AT_BYVAL;
	adp->arg_inout = AI_INPUT;
	adp->arg_size = 0;
	adp++;

	switch (cmd) {
	case CPC_BIND:
		adp->arg_value = 0;
		adp->arg_object = data1;
		adp->arg_type = AT_BYREF;
		adp->arg_inout = AI_INPUT;
		adp->arg_size = (size_t)data2;
		adp++;

		adp->arg_value = (size_t)data2;
		adp->arg_object = NULL;
		adp->arg_type = AT_BYVAL;
		adp->arg_inout = AI_INPUT;
		adp->arg_size = 0;
		adp++;

		adp->arg_value = 0;
		adp->arg_object = data3;
		adp->arg_type = AT_BYREF;
		adp->arg_inout = AI_INOUT;
		adp->arg_size = sizeof (int);

		break;
	case CPC_SAMPLE:
		adp->arg_value = 0;
		adp->arg_object = data1;
		adp->arg_type = AT_BYREF;
		adp->arg_inout = AI_OUTPUT;
		adp->arg_size = bufsize;
		adp++;

		adp->arg_value = 0;
		adp->arg_object = data2;
		adp->arg_type = AT_BYREF;
		adp->arg_inout = AI_OUTPUT;
		adp->arg_size = sizeof (hrtime_t);
		adp++;

		adp->arg_value = 0;
		adp->arg_object = data3;
		adp->arg_type = AT_BYREF;
		adp->arg_inout = AI_OUTPUT;
		adp->arg_size = sizeof (uint64_t);

		break;
	default:
		adp->arg_value = 0;
		adp->arg_object = 0;
		adp->arg_type = AT_BYVAL;
		adp->arg_inout = AI_INPUT;
		adp->arg_size = 0;
		adp++;

		adp->arg_value = 0;
		adp->arg_object = 0;
		adp->arg_type = AT_BYVAL;
		adp->arg_inout = AI_INPUT;
		adp->arg_size = 0;
		adp++;

		adp->arg_value = 0;
		adp->arg_object = 0;
		adp->arg_type = AT_BYVAL;
		adp->arg_inout = AI_INPUT;
		adp->arg_size = 0;

		break;
	}

	error = Psyscall(pctx->Pr, &rval, SYS_cpc, 5, &argd[0]);

	if (error) {
		errno = error > 0 ? error : ENOSYS;
		return (-1);
	}
	return (rval.sys_rval1);
}

/*
 * libcpc-private hook used to register a callback. The callback is used to
 * notify libcpc when a pctx handle is invalidated.
 */
void
__pctx_cpc_register_callback(void (*arg)(struct __cpc *, struct __pctx *))
{
	pctx_cpc_callback = arg;
}

/*
 * Tell pctx_run to bail out immediately
 */
void
pctx_terminate(struct __pctx *pctx)
{
	pctx->terminate = 1;
}
