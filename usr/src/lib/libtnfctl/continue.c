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
 * interface to continue a target process (DIRECT_MODE) and helper
 * functions needed by this routine.
 */

#include "tnfctl_int.h"
#include "prb_proc.h"
#include "dbg.h"


#include <stdlib.h>
#include <errno.h>

static tnfctl_errcode_t _tnfctl_continue(tnfctl_handle_t *hndl,
    tnfctl_event_t *evt, sigset_t *oldmask, boolean_t watch_forks);
static tnfctl_errcode_t enable_target_state(tnfctl_handle_t *hndl,
    boolean_t watch_forks);
static tnfctl_errcode_t disable_target_state(tnfctl_handle_t *hndl);

/*
 * continue the target process and return the evt it stopped on.
 * If child_hndl is set and we see a fork, return a handle on child
 * process.
 */
tnfctl_errcode_t
tnfctl_continue(tnfctl_handle_t *hndl, tnfctl_event_t *evt,
		tnfctl_handle_t **child_hndl)
{
	tnfctl_errcode_t	prexstat;
	prb_status_t		prbstat;
	boolean_t		lmapok = B_FALSE;
	boolean_t		watch_forks;
	/* set my_evt to something other than TNFCTL_EVENT_TARGGONE */
	tnfctl_event_t		my_evt = TNFCTL_EVENT_EINTR;
	enum event_op_t		dl_evt;
	sigset_t		newmask, oldmask;
	prb_proc_ctl_t		*proc_p;
	prgreg_t		reg0, reg1;

	/* this interface only works for DIRECT_MODE clients */
	if (hndl->mode != DIRECT_MODE)
		return (TNFCTL_ERR_BADARG);

	proc_p = hndl->proc_p;

	if (sigfillset(&newmask) == -1)
		return (tnfctl_status_map(errno));

	watch_forks = (child_hndl != NULL);

	/*
	 * XXXX block all signals.  Synchronous signals like SEGV that
	 * the user could catch and handle will now result in a core dump.
	 * But, this is very unlikely for 2 reasons - most users don't try
	 * to handle synchronous signals - it usually just aborts the process.
	 * And, secondly, the code until we return the original mask is the
	 * place where this synchronous signal would be generated - and, it
	 * is not very much code.
	 */
	if (sigprocmask(SIG_BLOCK, &newmask, &oldmask) == -1)
		return (tnfctl_status_map(errno));

	/*
	 * Target is stopped on entry because tnfctl_continue()
	 * only returns with a stopped target.
	 */

	/* target process shouldn't be stopped when link maps are incosistent */
	while (lmapok == B_FALSE) {
		prexstat = _tnfctl_continue(hndl, &my_evt, &oldmask,
		    watch_forks);
		if (prexstat) {
			if (my_evt == TNFCTL_EVENT_TARGGONE ||
			    my_evt == TNFCTL_EVENT_EXIT) {
				/*
				 * target exited - free obj list and probe
				 * list so that we keep our internal state
				 * correct, else probe control interfaces will
				 * have wrong information.
				 */
			    DBG(fprintf(stderr, "target is gone\n"));
				_tnfctl_free_objs_and_probes(hndl);
				*evt = my_evt;
				return (TNFCTL_ERR_NONE);
			} else if (my_evt == TNFCTL_EVENT_EXEC) {
				*evt = my_evt;
				return (TNFCTL_ERR_NONE);
			} else if (prexstat == TNFCTL_ERR_FILENOTFOUND) {
				return (TNFCTL_ERR_NOPROCESS);
			} else {
				return (prexstat);
			}
		}
		if (my_evt == TNFCTL_EVENT_FORK) {
	/*
	 * sanity check.  we should only get here if child_hndl is set
	 */
		    if (child_hndl) {
			    *evt = my_evt;
			    prbstat = prb_proc_get_r0_r1(proc_p,
				&reg0, &reg1);
			    if (prbstat) {
				prexstat = _tnfctl_map_to_errcode(prbstat);
				return (prexstat);
			    }
			    prexstat = tnfctl_pid_open((pid_t)reg0,
						child_hndl);
			    disable_target_state(*child_hndl);
			    return (prexstat);
			}
			return (TNFCTL_ERR_NONE);
		}

		/*
		 * update state in handle
		 * REMIND: Only need to call _tnfctl_refresh_process on
		 * dlopen or dlclose.  Need to take out other functionality
		 * of refresh_process into a separate function that should
		 * be called here.
		 */
		prexstat = _tnfctl_refresh_process(hndl, &lmapok, &dl_evt);
		if (prexstat && (lmapok == B_TRUE))
			return (prexstat);
		prexstat = TNFCTL_ERR_NONE;
	}
	*evt = my_evt;
	/* see if we have more detail about the event */
	if (dl_evt == EVT_OPEN)
		*evt = TNFCTL_EVENT_DLOPEN;
	else if (dl_evt == EVT_CLOSE)
		*evt = TNFCTL_EVENT_DLCLOSE;

	return (TNFCTL_ERR_NONE);
}

/*
 * Continues target and waits for it to stop.
 *	warning: This routine returns TNFCTL_EVENT_DLOPEN for any kind of
 *	dl activity.  Up to the caller to determine the actual DL event.
 */
static tnfctl_errcode_t
_tnfctl_continue(tnfctl_handle_t *hndl, tnfctl_event_t *evt, sigset_t *oldmask,
    boolean_t watch_forks)
{
	tnfctl_errcode_t	prexstat;
	tnfctl_errcode_t	ret_prexstat = TNFCTL_ERR_NONE;
	prb_status_t		prbstat, prbstat2;
	prb_proc_ctl_t		*proc_p;
	prb_proc_state_t 	state;

	proc_p = hndl->proc_p;

	/* set up state before we run process */
	prexstat = enable_target_state(hndl, watch_forks);
	if (prexstat)
		return (prexstat);

again:

	/* resume target */
	prbstat = prb_proc_cont(proc_p);
	if (prbstat) {
		ret_prexstat = _tnfctl_map_to_errcode(prbstat);
		goto end_of_func;
	}

	/* wait on target to stop (standby) */
	prbstat = prb_proc_wait(proc_p, B_TRUE, oldmask);
	if (prbstat) {
		if (prbstat == EINTR) {
			*evt = TNFCTL_EVENT_EINTR;
			prbstat2 = prb_proc_stop(proc_p);
			if (prbstat2) {
				ret_prexstat = _tnfctl_map_to_errcode(prbstat2);
				goto end_of_func;
			}
		} else if (prbstat == ENOENT) {
			/* target process finished */
			if (hndl->called_exit)
				*evt = TNFCTL_EVENT_EXIT;
			else
				*evt = TNFCTL_EVENT_TARGGONE;
			/* return directly - process no longer around */
			return (TNFCTL_ERR_INTERNAL);
		} else {
			ret_prexstat = _tnfctl_map_to_errcode(prbstat);
			goto end_of_func;
		}
	}

	prbstat = prb_proc_state(proc_p, &state);
	if (prbstat) {
		ret_prexstat = _tnfctl_map_to_errcode(prbstat);
		goto end_of_func;
	}
	if (state.ps_isbptfault) {
		/* dlopen or dlclose */
		prbstat = prb_rtld_advance(proc_p);
		if (prbstat) {
			ret_prexstat = _tnfctl_map_to_errcode(prbstat);
			goto end_of_func;
		}
		/*
		 * actually don't know if it is a dlopen or dlclose yet.
		 * But, we return dlopen here.  Up to the caller to determine
		 * which one it actually is.
		 */
		*evt = TNFCTL_EVENT_DLOPEN;
	} else
	    if (state.ps_issysentry) {
		switch (state.ps_syscallnum) {
		case SYS_execve:
		    *evt = TNFCTL_EVENT_EXEC;
		    ret_prexstat = TNFCTL_ERR_INTERNAL;
		    break;
		case SYS_exit:
		    hndl->called_exit = B_TRUE;
		    goto again;
		default:
		    break;
		}
	    } else if (state.ps_issysexit) {
		    switch (state.ps_syscallnum) {
		    case SYS_vfork:
		    case SYS_forksys:
			*evt = TNFCTL_EVENT_FORK;
			break;
		    default:
			break;
		    }
		}
end_of_func:
	/*
	 * disable all our sycall tracing and bpt setup in process when it
	 * is stopped, so that even if the controlling process aborts,
	 * the target could continue running
	 */
	prexstat = disable_target_state(hndl);
	if (prexstat)
		return (prexstat);
	return (ret_prexstat);
}

/*
 * enable the system call tracing and dl activity tracing
 */
static tnfctl_errcode_t
enable_target_state(tnfctl_handle_t *hndl, boolean_t watch_forks)
{
	prb_status_t	prbstat;
	prb_proc_ctl_t	*proc_p;

	proc_p = hndl->proc_p;

	/* trace exec */
	prbstat = prb_proc_entry(proc_p, SYS_execve, PRB_SYS_ADD);
	if (prbstat)
		return (_tnfctl_map_to_errcode(prbstat));
	/* trace exit */
	prbstat = prb_proc_entry(proc_p, SYS_exit, PRB_SYS_ADD);
	if (prbstat)
		return (_tnfctl_map_to_errcode(prbstat));
	/* trace fork if the caller requests */
	if (watch_forks) {
		prbstat = prb_proc_exit(proc_p, SYS_vfork, PRB_SYS_ADD);
		if (prbstat)
			return (_tnfctl_map_to_errcode(prbstat));

		prbstat = prb_proc_exit(proc_p, SYS_forksys, PRB_SYS_ADD);
		if (prbstat)
			return (_tnfctl_map_to_errcode(prbstat));

		prbstat = prb_proc_setfork(proc_p, B_TRUE);
		if (prbstat)
			return (_tnfctl_map_to_errcode(prbstat));
	}
	/*
	 * tracing flags for fork and exec will get unset when
	 * process stops. see disable_target_state()
	 */

	/* setup process to stop during dlopen() or dlclose() */
	prbstat = prb_rtld_stalk(proc_p);
	return (_tnfctl_map_to_errcode(prbstat));
}

/*
 * disable the system call tracing and dl activity tracing
 */
static tnfctl_errcode_t
disable_target_state(tnfctl_handle_t *hndl)
{
	prb_status_t	prbstat;
	prb_proc_ctl_t	*proc_p;

	proc_p = hndl->proc_p;

	/* remove the stalking breakpoint while the process is stopped */
	prbstat = prb_rtld_unstalk(proc_p);
	if (prbstat)
		return (_tnfctl_map_to_errcode(prbstat));

	/* remove the exec, exit and fork tracing while stopped */
	prbstat = prb_proc_entry(proc_p, SYS_execve, PRB_SYS_DEL);
	if (prbstat)
		return (_tnfctl_map_to_errcode(prbstat));
	prbstat = prb_proc_entry(proc_p, SYS_exit, PRB_SYS_DEL);
	if (prbstat)
		return (_tnfctl_map_to_errcode(prbstat));
	prbstat = prb_proc_exit(proc_p, SYS_vfork, PRB_SYS_DEL);
	if (prbstat)
	    return (_tnfctl_map_to_errcode(prbstat));
	prbstat = prb_proc_exit(proc_p, SYS_forksys, PRB_SYS_DEL);
	if (prbstat)
	    return (_tnfctl_map_to_errcode(prbstat));
	prbstat = prb_proc_setfork(proc_p, B_FALSE);
	if (prbstat)
	    return (_tnfctl_map_to_errcode(prbstat));

	return (TNFCTL_ERR_NONE);
}
