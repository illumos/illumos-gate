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
 * Copyright (c) 1994-1999 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains interfaces that are wrappers over the basic
 * /proc ioctls
 */

#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/uio.h>
#include <sys/types.h>
#include <sys/param.h>
#include <sys/fault.h>
#include <sys/procfs.h>

#include "prb_proc_int.h"
#include "dbg.h"

/*
 * Declarations
 */

#define	PROCFORMAT	"/proc/%d"

static prb_status_t
prb_proc_open_general(pid_t pid, prb_proc_ctl_t **proc_pp, int oflg);

/*
 * prb_proc_open_general() - function to open the process file
 * system entry for the supplied process. Opens with different
 * options based on the 'oflg'.
 * Returns a pointer to an opaque structure that contains the fd
 * needed for /proc control.
 */

prb_status_t
prb_proc_open_general(pid_t pid, prb_proc_ctl_t **proc_pp, int oflg)
{
	prb_proc_ctl_t		*proc_p;
	char			path[MAXPATHLEN];
	int			retval;

	(void) sprintf(path, PROCFORMAT, (int)pid);

	DBG_TNF_PROBE_1(prb_proc_open_1, "libtnfctl", "sunw%verbosity 2",
		tnf_string, opening_proc_on, path);

	retval = open(path, oflg);
	if (retval == -1) {
		DBG((void) fprintf(stderr,
			"proc_open: open of \"%s\" failed: %s\n",
			path, strerror(errno)));
		return (prb_status_map(errno));
	}
	/* allocate proc_p and zero fill */
	proc_p = calloc(1, sizeof (*proc_p));
	if (proc_p == NULL)
		return (PRB_STATUS_ALLOCFAIL);
	proc_p->procfd = retval;
	proc_p->pid = pid;
	*proc_pp = proc_p;
	return (PRB_STATUS_OK);
}


/*
 * prb_proc_open() - a wrapper which opens the process file system
 * entry for the supplied process.  Returns a pointer to an opaque
 * structure that contains the fd needed for /proc control.
 */

prb_status_t
prb_proc_open(pid_t pid, prb_proc_ctl_t **proc_pp)
{

	return (prb_proc_open_general(pid,
				proc_pp, O_RDWR | O_EXCL));

}

/*
 * prb_proc_reopen() - re-opens the process, mainly for setuid/setgid files.
 * Read the last section of /proc man page for details.
 * re-open should not use O_EXCL flag.
 */

prb_status_t
prb_proc_reopen(pid_t pid, prb_proc_ctl_t **proc_pp)
{

	return (prb_proc_open_general(pid,
				proc_pp, O_RDWR));

}

/*
 * prob_proc_close() - close the proc fd and free the memory taken up
 *	by proc_p
 */
prb_status_t
prb_proc_close(prb_proc_ctl_t *proc_p)
{
	DBG_TNF_PROBE_0(prb_proc_close_1, "libtnfctl", "sunw%verbosity 2");

	if (proc_p == NULL)
		return (PRB_STATUS_OK);

	if (close(proc_p->procfd) == -1) {
		DBG((void) fprintf(stderr,
			"proc_close: close failed: %s\n", strerror(errno)));
		return (prb_status_map(errno));
	}
	free(proc_p);
	return (PRB_STATUS_OK);
}

/*
 * prb_proc_pid_get() - gets the pid of the proc
 */
pid_t
prb_proc_pid_get(prb_proc_ctl_t *proc_p)
{
	return (proc_p->pid);
}

/*
 * prb_proc_stop() - stops the target process
 */
prb_status_t
prb_proc_stop(prb_proc_ctl_t *proc_p)
{
	int			 retval;

	DBG_TNF_PROBE_0(prb_proc_stop_1, "libtnfctl",
		"sunw%verbosity 2; sunw%debug 'stopping the target process'");

again:
	retval = ioctl(proc_p->procfd, PIOCSTOP, NULL);
	if (retval == -1) {
		if (errno == EINTR)
			goto again;
		DBG((void) fprintf(stderr,
			"prb_proc_stop: PIOCSTOP failed: %s\n",
			strerror(errno)));
		return (prb_status_map(errno));
	}
	return (PRB_STATUS_OK);
}


/*
 * prb_proc_prstop() - runs and stops the process, used to clear a target
 * process out of a system call state.
 */
prb_status_t
prb_proc_prstop(prb_proc_ctl_t *proc_p)
{
	int		procfd;
	int		retval;
	prrun_t		prrun;
	prstatus_t	prstat;

	DBG_TNF_PROBE_0(prb_proc_prstop_1, "libtnfctl",
		"sunw%verbosity 2; sunw%debug 'stepping the target process'");

	procfd = proc_p->procfd;
	(void) memset((char *)&prrun, 0, sizeof (prrun));
	(void) memset((char *)&prstat, 0, sizeof (prstat));

again1:
	prrun.pr_flags = PRSTOP;
	retval = ioctl(procfd, PIOCRUN, &prrun);
	if (retval == -1) {
		if (errno == EINTR)
			goto again1;
		DBG((void) fprintf(stderr,
			"prb_proc_prstop: PIOCRUN failed: %s\n",
			strerror(errno)));
		return (prb_status_map(errno));
	}
again2:
	retval = ioctl(procfd, PIOCWSTOP, &prstat);
	if (retval == -1) {
		if (errno == EINTR)
			goto again2;
		DBG((void) fprintf(stderr,
			"prb_proc_prstop: PIOCWSTOP failed: %s\n",
			strerror(errno)));
		return (prb_status_map(errno));
	}
	/*
	 * if we didn't stop because we requested it (eg. if there was a
	 * signal in the target ?), we might need to try again
	 */
	if (prstat.pr_why != PR_REQUESTED)
		goto again1;

	return (PRB_STATUS_OK);
}


/*
 * prb_proc_state() - returns the status pf the process
 */
prb_status_t
prb_proc_state(prb_proc_ctl_t *proc_p, prb_proc_state_t *state_p)
{
	int		procfd;
	int		retval;
	prstatus_t	prstatus;

	DBG_TNF_PROBE_0(prb_proc_state_1, "libtnfctl",
		"sunw%verbosity 2; sunw%debug 'getting the status'");

	procfd = proc_p->procfd;

	(void) memset(&prstatus, 0, sizeof (prstatus));

again:
	retval = ioctl(procfd, PIOCSTATUS, &prstatus);
	if (retval == -1) {
		if (errno == EINTR)
			goto again;
		DBG((void) fprintf(stderr,
			"prb_proc_status: PIOCSTATUS failed: %s\n",
			strerror(errno)));
		return (prb_status_map(errno));
	}
	state_p->ps_isbptfault = (prstatus.pr_flags & PR_FAULTED &&
		prstatus.pr_what == FLTBPT);
	state_p->ps_isstopped = ((prstatus.pr_flags & PR_STOPPED) != 0);
	state_p->ps_isinsys = ((prstatus.pr_flags & PR_ASLEEP) != 0);
	state_p->ps_isrequested = ((prstatus.pr_why & PR_REQUESTED) != 0);
	state_p->ps_issysexit = ((prstatus.pr_why & PR_SYSEXIT) != 0);
	state_p->ps_issysentry = ((prstatus.pr_why & PR_SYSENTRY) != 0);
	state_p->ps_syscallnum = prstatus.pr_what;
	return (PRB_STATUS_OK);
}


/*
 * prb_proc_wait() - waits for the target process to stop
 */
prb_status_t
prb_proc_wait(prb_proc_ctl_t *proc_p, boolean_t use_sigmask, sigset_t *oldmask)
{
	int		procfd;
	int		retval;
	prstatus_t	prstat;
	sigset_t	pendmask;
	int		i, mask_size;
	boolean_t	pending_signal = B_FALSE;

	DBG_TNF_PROBE_0(prb_proc_wait_1, "libtnfctl",
		"sunw%verbosity 2;"
		"sunw%debug 'waiting for the target process to stop'");

	procfd = proc_p->procfd;

	/*
	 * This one of the places where we do not resubmit the ioctl if
	 * if it is terminated by an EINTR (interrupted system call). In
	 * this case, the caller knows best ...
	 */
	(void) memset(&prstat, 0, sizeof (prstat));

	/* if we blocked signals... */
	if (use_sigmask) {
		if (sigemptyset(&pendmask) == -1)
			return (prb_status_map(errno));
		if (sigpending(&pendmask) == -1)
			return (prb_status_map(errno));
		/*
		 * check if there were any signals pending -
		 * XXXX libc should provide this interface
		 */
		mask_size = sizeof (pendmask) / sizeof (pendmask.__sigbits[0]);
		for (i = 0; i < mask_size; i++) {
			if (pendmask.__sigbits[i] != 0)
				pending_signal = B_TRUE;
		}

		/* return to original signal mask */
		if (sigprocmask(SIG_SETMASK, oldmask, NULL) == -1)
			return (prb_status_map(errno));

		/* if there was a pending signal, don't call PIOCWSTOP ioctl */
		if (pending_signal)
			return (prb_status_map(EINTR));

		/*
		 * XXXX - there is a a race between now and when we call
		 * the PIOCWSTOP ioctl.  One solution, is for the user to
		 * call an interface in libtnfctl from their signal handler.
		 * This interface will do a longjmp such that it never
		 * calls the ioctl (the setjmp would be before we restore
		 * the signal mask above)
		 */
	}

	retval = ioctl(procfd, PIOCWSTOP, &prstat);

	DBG_TNF_PROBE_2(prb_proc_wait_2, "libtnfctl", "sunw%verbosity 2;",
			tnf_opaque, pc, prstat.pr_reg[R_PC],
			tnf_opaque, instr, prstat.pr_instr);

	if (retval == -1) {
#ifdef DEBUG
		if (errno != EINTR && errno != ENOENT)
			(void) fprintf(stderr,
				"prb_proc_wait: PIOCWSTOP failed: %s\n",
				strerror(errno));

#endif
		return (prb_status_map(errno));
	}

	return (PRB_STATUS_OK);
}


/*
 * prb_proc_cont() - continues the target process
 */
prb_status_t
prb_proc_cont(prb_proc_ctl_t *proc_p)
{
	int		procfd;
	int		retval;
	prrun_t		prrun;

	DBG_TNF_PROBE_0(prb_proc_cont_1, "libtnfctl",
		"sunw%verbosity 2; sunw%debug 'starting the target process'");
	procfd = proc_p->procfd;

	(void) memset((char *)&prrun, 0, sizeof (prrun));

again:
	prrun.pr_flags = PRCFAULT;
	retval = ioctl(procfd, PIOCRUN, &prrun);
	if (retval == -1) {
		if (errno == EINTR)
			goto again;
		DBG((void) fprintf(stderr,
			"prb_proc_cont: PIOCRUN failed: %s\n",
			strerror(errno)));
		return (prb_status_map(errno));
	}
	return (PRB_STATUS_OK);
}


/*
 * prb_proc_istepbpt() - step the target process one instruction
 *
 * CAUTION!!!! - this routine is specialized to only be able to single
 * step over the breakpoint location.
 */
prb_status_t
prb_proc_istepbpt(prb_proc_ctl_t *proc_p)
{
	int		procfd;
	int		retval;
	prrun_t		run;
	fltset_t	faults;
	prstatus_t	prstat;

	DBG_TNF_PROBE_0(prb_proc_istepbpt_1, "libtnfctl",
		"sunw%verbosity 2; "
		"sunw%debug 'single stepping over breakpoint'");

	procfd = proc_p->procfd;

	(void) memset((char *)&run, 0, sizeof (run));

	/* add trace fault to the list of current traced faults */
again1:
	retval = ioctl(procfd, PIOCGFAULT, &faults);
	if (retval == -1) {
		if (errno == EINTR)
			goto again1;
		DBG((void) fprintf(stderr,
			"prb_proc_istepbpt: PIOCGFAULT failed: %s\n",
			strerror(errno)));
		return (prb_status_map(errno));
	}
	praddset(&faults, FLTTRACE);

	/* issue the run command with the single-step option */
	run.pr_flags = PRCFAULT | PRSFAULT | PRSTEP;
	run.pr_fault = faults;

	/* load the location of the breakpoint */
	run.pr_vaddr = (caddr_t)proc_p->bptaddr;
	run.pr_flags |= PRSVADDR;

again2:
	retval = ioctl(procfd, PIOCRUN, &run);
	if (retval == -1) {
		if (errno == EINTR)
			goto again2;
		DBG((void) fprintf(stderr,
			"prb_proc_istepbpt: PIOCRUN failed: %s\n",
			strerror(errno)));
		return (prb_status_map(errno));
	}
again3:
	retval = ioctl(procfd, PIOCWSTOP, &prstat);
	if (retval == -1) {
		if (errno == EINTR)
			goto again3;
		DBG((void) fprintf(stderr,
				"prb_proc_istepbpt: PIOCWSTOP failed: %s\n",
				strerror(errno)));
		return (prb_status_map(errno));
	}

	DBG_TNF_PROBE_2(prb_proc_istepbpt_2, "libtnfctl", "sunw%verbosity 2;",
			tnf_opaque, pc, prstat.pr_reg[R_PC],
			tnf_opaque, instr, prstat.pr_instr);


	/* clear any current faults */
again4:
	retval = ioctl(procfd, PIOCCFAULT, NULL);
	if (retval == -1) {
		if (errno == EINTR)
			goto again4;
		DBG((void) fprintf(stderr,
			"prb_proc_clrbptflt: PIOCCFAULT failed: %s\n",
			strerror(errno)));
		return (prb_status_map(errno));
	}
	/* remove the trace fault from the current traced faults */
	prdelset(&faults, FLTTRACE);
again5:
	retval = ioctl(procfd, PIOCSFAULT, &faults);
	if (retval == -1) {
		if (errno == EINTR)
			goto again5;
		DBG((void) fprintf(stderr,
			"prb_proc_istepbpt: PIOCSFAULT failed: %s\n",
			strerror(errno)));
		return (prb_status_map(errno));
	}
	return (PRB_STATUS_OK);
}


/*
 * prb_proc_clrbptflt() - clear an encountered breakpoint fault
 */
prb_status_t
prb_proc_clrbptflt(prb_proc_ctl_t *proc_p)
{
	int	retval;
	int	procfd;

	DBG_TNF_PROBE_0(prb_proc_clrbptflt_1, "libtnfctl", "sunw%verbosity 2");

	procfd = proc_p->procfd;

	/* clear any current faults */
again:
	retval = ioctl(procfd, PIOCCFAULT, NULL);
	if (retval == -1) {
		if (errno == EINTR)
			goto again;
		DBG((void) fprintf(stderr,
			"prb_proc_clrbptflt: PIOCCFAULT failed: %s\n",
			strerror(errno)));
		return (prb_status_map(errno));
	}
	return (PRB_STATUS_OK);
}


/*
 * prb_proc_tracebpt() - sets the bpt tracing state.
 */
prb_status_t
prb_proc_tracebpt(prb_proc_ctl_t *proc_p, boolean_t bpt)
{
	int		procfd;
	int		retval;
	fltset_t	faults;

	DBG_TNF_PROBE_1(prb_proc_tracebpt_1, "libtnfctl", "sunw%verbosity 2;",
		tnf_string, bpt_state, (bpt) ? "enabled" : "disabled");

	procfd = proc_p->procfd;
	/* get the current set of traced faults */
again1:
	retval = ioctl(procfd, PIOCGFAULT, &faults);
	if (retval == -1) {
		if (errno == EINTR)
			goto again1;
		DBG((void) fprintf(stderr,
			"prb_proc_tracebpt: PIOCGFAULT failed: %s\n",
			strerror(errno)));
		return (prb_status_map(errno));
	}
	/* set or clear the breakpoint flag */
	if (bpt)
		praddset(&faults, FLTBPT);
	else
		prdelset(&faults, FLTBPT);

	/* write the fault set back */
again2:
	retval = ioctl(procfd, PIOCSFAULT, &faults);
	if (retval == -1) {
		if (errno == EINTR)
			goto again2;
		DBG((void) fprintf(stderr,
			"prb_proc_tracebpt: PIOCSFAULT failed: %s\n",
			strerror(errno)));
		return (prb_status_map(errno));
	}
	return (PRB_STATUS_OK);
}

/* Note - the following 3 functions should be combined */

/*
 * prb_proc_setrlc() - sets or clears the run-on-last-close flag.
 */
prb_status_t
prb_proc_setrlc(prb_proc_ctl_t *proc_p, boolean_t rlc)
{
	int			procfd;
	long			mode;
	int			retval;

	DBG_TNF_PROBE_1(prb_proc_setrlc_1, "libtnfctl", "sunw%verbosity 2;",
		tnf_string, run_on_last_close, (rlc) ? "setting" : "clearing");

	procfd = proc_p->procfd;
	mode = PR_RLC;

	if (rlc) {
again1:
		retval = ioctl(procfd, PIOCSET, &mode);
		if (retval == -1) {
			if (errno == EINTR)
				goto again1;
			DBG((void) fprintf(stderr,
				"prb_proc_setrlc: PIOCSET failed: %s\n",
				strerror(errno)));
			return (prb_status_map(errno));
		}
	} else {
again2:
		retval = ioctl(procfd, PIOCRESET, &mode);
		if (retval == -1) {
			if (errno == EINTR)
				goto again2;
			DBG((void) fprintf(stderr,
				"prb_proc_setrlc: PIOCRESET failed: %s\n",
				strerror(errno)));
			return (prb_status_map(errno));
		}
	}

	return (PRB_STATUS_OK);


}				/* end prb_proc_setrlc */


/*
 * prb_proc_setklc() - sets or clears the kill-on-last-close flag.
 */
prb_status_t
prb_proc_setklc(prb_proc_ctl_t *proc_p, boolean_t klc)
{
	int			procfd;
	long			mode;
	int			retval;

	DBG_TNF_PROBE_1(prb_proc_setklc_1, "libtnfctl", "sunw%verbosity 2;",
		tnf_string, kill_on_last_close, (klc) ? "setting" : "clearing");

	procfd = proc_p->procfd;
	mode = PR_KLC;

	if (klc) {
again1:
		retval = ioctl(procfd, PIOCSET, &mode);
		if (retval == -1) {
			if (errno == EINTR)
				goto again1;
			DBG((void) fprintf(stderr,
				"prb_proc_setklc: PIOCSET failed: %s\n",
				strerror(errno)));
			return (prb_status_map(errno));
		}
	} else {
again2:
		retval = ioctl(procfd, PIOCRESET, &mode);
		if (retval == -1) {
			if (errno == EINTR)
				goto again2;
			DBG((void) fprintf(stderr,
				"prb_proc_setklc: PIOCRESET failed: %s\n",
				strerror(errno)));
			return (prb_status_map(errno));
		}
	}

	return (PRB_STATUS_OK);

}				/* end prb_proc_setklc */

/*
 * prb_proc_setfork() - sets or clears the inherit-on-fork flag
 */
prb_status_t
prb_proc_setfork(prb_proc_ctl_t *proc_p, boolean_t inhfork)
{
	int			procfd;
	long			mode;
	int			retval;

	DBG_TNF_PROBE_1(prb_proc_setfork_1, "libtnfctl", "sunw%verbosity 2;",
		tnf_string, kill_on_last_close,
		(inhfork) ? "setting" : "clearing");

	procfd = proc_p->procfd;
	mode = PR_FORK;

	if (inhfork) {
again1:
		retval = ioctl(procfd, PIOCSET, &mode);
		if (retval == -1) {
			if (errno == EINTR)
				goto again1;
			DBG((void) fprintf(stderr,
				"prb_proc_setfork: PIOCSET failed: %s\n",
				strerror(errno)));
			return (prb_status_map(errno));
		}
	} else {
again2:
		retval = ioctl(procfd, PIOCRESET, &mode);
		if (retval == -1) {
			if (errno == EINTR)
				goto again2;
			DBG((void) fprintf(stderr,
				"prb_proc_setfork: PIOCRESET failed: %s\n",
				strerror(errno)));
			return (prb_status_map(errno));
		}
	}

	return (PRB_STATUS_OK);

}				/* end prb_proc_setfork */

/*
 * prb_proc_exit() - if op is PRB_SYS_ALL, sets up the target process to stop
 * on exit from all system calls.  If op is PRB_SYS_NONE, sets up the target
 * process so that it will not stop on exit from any system call.
 * PRB_SYS_ADD and PRB_SYS_DEL adds or deletes a particular system call from
 * the mask of "interested" system calls respectively. This function can be
 * called multiple times to build up the mask.
 */
prb_status_t
prb_proc_exit(prb_proc_ctl_t *proc_p,
	uint_t syscall,
	prb_syscall_op_t op)
{
	int		procfd;
	int		retval;
	sysset_t	sysmask;

	DBG_TNF_PROBE_0(prb_proc_exit_1, "libtnfctl",
		"sunw%verbosity 2; "
		"sunw%debug 'setting up target to stop on exit of syscall'");

	procfd = proc_p->procfd;

	switch (op) {
	case PRB_SYS_ALL:
		prfillset(&sysmask);
		break;
	case PRB_SYS_NONE:
		premptyset(&sysmask);
		break;
	case PRB_SYS_ADD:
again1:
		retval = ioctl(procfd, PIOCGEXIT, &sysmask);
		if (retval == -1) {
			if (errno == EINTR)
				goto again1;
			DBG((void) fprintf(stderr,
				"prb_proc_exit: PIOCGEXIT failed: %s\n",
				strerror(errno)));
			return (prb_status_map(errno));
		}
		praddset(&sysmask, syscall);
		break;
	case PRB_SYS_DEL:
again2:
		retval = ioctl(procfd, PIOCGEXIT, &sysmask);
		if (retval == -1) {
			if (errno == EINTR)
				goto again2;
			DBG((void) fprintf(stderr,
				"prb_proc_exit: PIOCGEXIT failed: %s\n",
				strerror(errno)));
			return (prb_status_map(errno));
		}
		prdelset(&sysmask, syscall);
		break;
	default:
		DBG((void) fprintf(stderr, "prb_proc_exit: bad input arg\n"));
		return (PRB_STATUS_BADARG);
	}
again3:
	retval = ioctl(procfd, PIOCSEXIT, &sysmask);
	if (retval == -1) {
		if (errno == EINTR)
			goto again3;
		DBG((void) fprintf(stderr,
			"prb_proc_exit: PIOCSEXIT failed: %s\n",
			strerror(errno)));
		return (prb_status_map(errno));
	}
	return (PRB_STATUS_OK);

}				/* end prb_proc_exit */

/*
 * prb_proc_entry() - if op is PRB_SYS_ALL, sets up the target process to
 * stop on entry from all system calls.  If op is PRB_SYS_NONE, sets up the
 * target process so that it will not stop on entry from any system call.
 * PRB_SYS_ADD and PRB_SYS_DEL adds or deletes a particular system call from
 * the mask of "interested" system calls respectively. This function can be
 * called multiple times to build up the mask.
 */
prb_status_t
prb_proc_entry(prb_proc_ctl_t *proc_p,
	uint_t syscall,
	prb_syscall_op_t op)
{
	int		procfd;
	int		retval;
	sysset_t	sysmask;

	DBG_TNF_PROBE_0(prb_proc_entry_1, "libtnfctl",
		"sunw%verbosity 2; "
		"sunw%debug 'setting up target to stop on entry of syscall'");

	procfd = proc_p->procfd;

	switch (op) {
	case PRB_SYS_ALL:
		prfillset(&sysmask);
		break;
	case PRB_SYS_NONE:
		premptyset(&sysmask);
		break;
	case PRB_SYS_ADD:
again1:
		retval = ioctl(procfd, PIOCGENTRY, &sysmask);
		if (retval == -1) {
			if (errno == EINTR)
				goto again1;
			DBG((void) fprintf(stderr,
				"prb_proc_entry: PIOCGENTRY failed: %s\n",
				strerror(errno)));
			return (prb_status_map(errno));
		}
		praddset(&sysmask, syscall);
		break;
	case PRB_SYS_DEL:
again2:
		retval = ioctl(procfd, PIOCGENTRY, &sysmask);
		if (retval == -1) {
			if (errno == EINTR)
				goto again2;
			DBG((void) fprintf(stderr,
				"prb_proc_entry: PIOCGENTRY failed: %s\n",
				strerror(errno)));
			return (prb_status_map(errno));
		}
		prdelset(&sysmask, syscall);
		break;
	default:
		DBG((void) fprintf(stderr, "prb_proc_entry: bad input arg\n"));
		return (PRB_STATUS_BADARG);
	}
again3:
	retval = ioctl(procfd, PIOCSENTRY, &sysmask);
	if (retval == -1) {
		if (errno == EINTR)
			goto again3;
		DBG((void) fprintf(stderr,
			"prb_proc_entry: PIOCSENTRY failed: %s\n",
			strerror(errno)));
		return (prb_status_map(errno));
	}
	return (PRB_STATUS_OK);
}

/*
 * prb_proc_read() - reads a block of memory from a processes address space.
 */
prb_status_t
prb_proc_read(prb_proc_ctl_t *proc_p, uintptr_t addr, void *buf, size_t size)
{
	int		procfd;
	ssize_t		sz;
	off_t		offset;

	DBG_TNF_PROBE_2(prb_proc_read_1, "libtnfctl", "sunw%verbosity 3;",
		tnf_long, num_bytes, size,
		tnf_opaque, from_address, addr);

	procfd = proc_p->procfd;
	offset = lseek(procfd, (off_t)addr, SEEK_SET);
	if (offset != (off_t)addr) {
		DBG(perror("prb_proc_read: lseek failed"));
		return (prb_status_map(errno));
	}
	sz = read(procfd, buf, size);
	if (sz != size) {
		DBG(perror("prb_proc_read: read failed"));
		return (prb_status_map(errno));
	}
	return (PRB_STATUS_OK);
}


/*
 * prb_proc_write() - writes a block of memory from a processes address
 * space.
 */
prb_status_t
prb_proc_write(prb_proc_ctl_t *proc_p, uintptr_t addr, void *buf, size_t size)
{
	int		procfd;
	ssize_t		sz;
	off_t		offset;

	DBG_TNF_PROBE_2(prb_proc_write_1, "libtnfctl", "sunw%verbosity 3;",
		tnf_long, num_bytes, size,
		tnf_opaque, to_address, addr);

	procfd = proc_p->procfd;
	offset = lseek(procfd, (off_t)addr, SEEK_SET);
	if (offset != (off_t)addr) {
		DBG(perror("prb_proc_write: lseek failed"));
		return (prb_status_map(errno));
	}
	sz = write(procfd, buf, size);
	if (sz != size) {
		DBG(perror("prb_proc_write: write failed"));
		return (prb_status_map(errno));
	}
	return (PRB_STATUS_OK);
}


/*
 * prb_proc_readstr() - dereferences a string in the target
 * 	NOTE: There is a similar routine called _tnfctl_readstr_targ()
 *	      used by tnfctl layer.  It would be better if there was only
 *	      one of these functions defined.
 */

#define	BUFSZ	256

prb_status_t
prb_proc_readstr(prb_proc_ctl_t *proc_p, uintptr_t addr, const char **outstr_pp)
{
	prb_status_t	prbstat;
	int		bufsz = BUFSZ;
	char		buffer[BUFSZ + 1];
	offset_t	offset;
	char		*ptr, *orig_ptr;

	*outstr_pp = NULL;
	offset = 0;

	/* allocate an inital return buffer */
	ptr = (char *)malloc(BUFSZ);
	if (!ptr) {
		DBG((void) fprintf(stderr,
			"prb_proc_readstr: malloc failed\n"));
		return (PRB_STATUS_ALLOCFAIL);
	}
	/*LINTED constant in conditional context*/
	while (1) {
		int			 i;

		/* read a chunk into our buffer */
		prbstat = prb_proc_read(proc_p, addr + offset, buffer, bufsz);
		if (prbstat) {

			/*
			 * if we get into trouble with a large read, try again
			 * with a single byte.  Subsequent failure is real ...
			 */
			if (bufsz > 1) {
				bufsz = 1;
				continue;
			}

			DBG((void) fprintf(stderr,
				"prb_proc_readstr: prb_proc_read failed: %s\n",
				prb_status_str(prbstat)));
			free(ptr);
			return (prbstat);
		}
		/* copy the chracters into the return buffer */
		for (i = 0; i < bufsz; i++) {
			char			c = buffer[i];

			ptr[offset + i] = c;
			if (c == '\0') {
				/* hooray! we saw the end of the string */
				*outstr_pp = ptr;
				return (PRB_STATUS_OK);
			}
		}

		/* bummer, need to grab another bufsz characters */
		offset += bufsz;
		orig_ptr = ptr;
		ptr = (char *)realloc(ptr, offset + bufsz);
		if (!ptr) {
			free(orig_ptr);
			DBG((void) fprintf(stderr,
				"prb_proc_readstr: realloc failed\n"));
			return (PRB_STATUS_ALLOCFAIL);
		}
	}

#if defined(lint)
	return (PRB_STATUS_OK);
#endif
}

prb_status_t
prb_proc_get_r0_r1(prb_proc_ctl_t *proc_p, prgreg_t *r0, prgreg_t *r1)
{
	int retval;
	int procfd;
	prstatus_t  prstatus;

	procfd = proc_p->procfd;
again:
	retval = ioctl(procfd, PIOCSTATUS, &prstatus);
	if (retval == -1) {
		if (errno == EINTR)
			goto again;
		return (prb_status_map(errno));
	}

	/*
	 *  Use R_Rn register definitions for some uniformity
	 *	   sparc: 	define R_R0  R_O0
	 *			define R_R1  R_O1
	 *	   x86:   	define R_R0  EAX
	 *			define R_R1  EDX
	 */
	*r0 = prstatus.pr_reg[R_R0];
	*r1 = prstatus.pr_reg[R_R1];
	DBG((void) fprintf
	    (stderr, "prb_proc_get_r0_r1: R_R0 = %d, R_R1 = %d\n", *r0, *r1));
	return (PRB_STATUS_OK);
}
