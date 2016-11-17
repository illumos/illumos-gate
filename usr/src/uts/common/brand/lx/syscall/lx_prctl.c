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
 * Copyright 2016 Joyent, Inc.
 */

#include <sys/systm.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/priv.h>
#include <sys/brand.h>
#include <sys/cmn_err.h>
#include <sys/lx_brand.h>
#include <sys/lx_impl.h>
#include <lx_signum.h>

#define	LX_PR_SET_PDEATHSIG		1
#define	LX_PR_GET_PDEATHSIG		2
#define	LX_PR_GET_DUMPABLE		3
#define	LX_PR_SET_DUMPABLE		4
#define	LX_PR_GET_UNALIGN		5
#define	LX_PR_SET_UNALIGN		6
#define	LX_PR_GET_KEEPCAPS		7
#define	LX_PR_SET_KEEPCAPS		8
#define	LX_PR_GET_FPEMU			9
#define	LX_PR_SET_FPEMU			10
#define	LX_PR_GET_FPEXC			11
#define	LX_PR_SET_FPEXC			12
#define	LX_PR_GET_TIMING		13
#define	LX_PR_SET_TIMING		14
#define	LX_PR_SET_NAME			15
#define	LX_PR_GET_NAME			16
#define	LX_PR_GET_ENDIAN		19
#define	LX_PR_SET_ENDIAN		20
#define	LX_PR_GET_SECCOMP		21
#define	LX_PR_SET_SECCOMP		22
#define	LX_PR_CAPBSET_READ		23
#define	LX_PR_CAPBSET_DROP		24
#define	LX_PR_GET_TSC			25
#define	LX_PR_SET_TSC			26
#define	LX_PR_GET_SECUREBITS		27
#define	LX_PR_SET_SECUREBITS		28
#define	LX_PR_SET_TIMERSLACK		29
#define	LX_PR_GET_TIMERSLACK		30
#define	LX_PR_TASK_PERF_EVENTS_DISABLE	31
#define	LX_PR_TASK_PERF_EVENTS_ENABLE	32
#define	LX_PR_MCE_KILL			33
#define	LX_PR_MCE_KILL_GET		34
#define	LX_PR_SET_MM			35
#define	LX_PR_SET_CHILD_SUBREAPER	36
#define	LX_PR_GET_CHILD_SUBREAPER	37
#define	LX_PR_SET_NO_NEW_PRIVS		38
#define	LX_PR_GET_NO_NEW_PRIVS		39
#define	LX_PR_GET_TID_ADDRESS		40
#define	LX_PR_SET_THP_DISABLE		41
#define	LX_PR_GET_THP_DISABLE		42

#define	LX_PR_SET_NAME_NAMELEN	16

long
lx_prctl(int opt, uintptr_t data)
{
	long err;
	char ebuf[64];

	switch (opt) {
	case LX_PR_GET_DUMPABLE: {
		/* Only track in brand data - could hook into SNOCD later */
		lx_proc_data_t *lxpd;
		int val;

		mutex_enter(&curproc->p_lock);
		VERIFY((lxpd = ptolxproc(curproc)) != NULL);
		val = lxpd->l_flags & LX_PROC_NO_DUMP;
		mutex_exit(&curproc->p_lock);

		return (val == 0);
	}

	case LX_PR_SET_DUMPABLE: {
		lx_proc_data_t *lxpd;

		if (data != 0 && data != 1) {
			return (set_errno(EINVAL));
		}

		mutex_enter(&curproc->p_lock);
		VERIFY((lxpd = ptolxproc(curproc)) != NULL);
		if (data == 0) {
			lxpd->l_flags |= LX_PROC_NO_DUMP;
		} else {
			lxpd->l_flags &= ~LX_PROC_NO_DUMP;
		}
		mutex_exit(&curproc->p_lock);

		return (0);
	}

	case LX_PR_GET_SECUREBITS: {
		/* Our bits are always 0 */
		return (0);
	}

	case LX_PR_SET_SECUREBITS: {
		/* Ignore setting any bits from arg2 */
		return (0);
	}

	case LX_PR_SET_KEEPCAPS: {
		/*
		 * The closest illumos analog to SET_KEEPCAPS is the PRIV_AWARE
		 * flag.  There are probably some cases where it's not exactly
		 * the same, but this will do for a first try.
		 */
		if (data == 0) {
			err = setpflags(PRIV_AWARE_RESET, 1, NULL);
		} else {
			err = setpflags(PRIV_AWARE, 1, NULL);
		}

		if (err != 0) {
			return (set_errno(err));
		}
		return (0);
	}

	case LX_PR_SET_NAME: {
		char name[LX_PR_SET_NAME_NAMELEN + 1];
		proc_t *p = curproc;
		/*
		 * In Linux, PR_SET_NAME sets the name of the thread, not the
		 * process.  Due to the historical quirks of Linux's asinine
		 * thread model, this name is effectively the name of the
		 * process (as visible via ps(1)) if the thread is the first of
		 * its task group.  The first thread is therefore special, and
		 * to best mimic Linux semantics (and absent a notion of
		 * per-LWP names), we do nothing (but return success) on LWPs
		 * other than LWP 1.
		 */
		if (curthread->t_tid != 1) {
			return (0);
		}
		if (copyin((void *)data, name, LX_PR_SET_NAME_NAMELEN) != 0) {
			return (set_errno(EFAULT));
		}
		name[LX_PR_SET_NAME_NAMELEN] = '\0';
		mutex_enter(&p->p_lock);
		(void) strncpy(p->p_user.u_comm, name, MAXCOMLEN + 1);
		(void) strncpy(p->p_user.u_psargs, name, PSARGSZ);
		mutex_exit(&p->p_lock);
		return (0);
	}

	case LX_PR_GET_PDEATHSIG: {
		int sig;
		lx_proc_data_t *lxpd;

		mutex_enter(&curproc->p_lock);
		VERIFY((lxpd = ptolxproc(curproc)) != NULL);
		sig = lxpd->l_parent_deathsig;
		mutex_exit(&curproc->p_lock);

		return (sig);
	}

	case LX_PR_SET_PDEATHSIG: {
		int sig = lx_ltos_signo((int)data, 0);
		proc_t *pp = NULL;
		lx_proc_data_t *lxpd;

		if (sig == 0 && data != 0) {
			return (set_errno(EINVAL));
		}

		mutex_enter(&pidlock);
		/* Set signal on our self */
		mutex_enter(&curproc->p_lock);
		VERIFY((lxpd = ptolxproc(curproc)) != NULL);
		lxpd->l_parent_deathsig = sig;
		pp = curproc->p_parent;
		mutex_exit(&curproc->p_lock);

		/* Configure parent to potentially signal children on death */
		mutex_enter(&pp->p_lock);
		if (PROC_IS_BRANDED(pp)) {
			VERIFY((lxpd = ptolxproc(pp)) != NULL);
			/*
			 * Mark the parent as having children which wish to be
			 * signaled on death of parent.
			 */
			lxpd->l_flags |= LX_PROC_CHILD_DEATHSIG;
		} else {
			/*
			 * If the parent is not a branded process, the needed
			 * hooks to facilitate this mechanism will not fire
			 * when it dies. We lie about success in this case.
			 */
			/* EMPTY */
		}
		mutex_exit(&pp->p_lock);
		mutex_exit(&pidlock);
		return (0);
	}

	case LX_PR_CAPBSET_DROP: {
		/*
		 * On recent versions of Linux the login svc drops capabilities
		 * and if that fails the svc dies and is restarted by systemd.
		 * For now we pretend dropping capabilities succeeded.
		 */
		return (0);
	}

	default:
		break;
	}

	(void) snprintf(ebuf, 64, "prctl option %d", opt);
	lx_unsupported(ebuf);
	return (set_errno(EINVAL));
}
