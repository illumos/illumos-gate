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
#include <sys/procset.h>
#include <sys/resource.h>
#include <sys/priocntl.h>
#include <sys/param.h>
#include <sys/policy.h>
#include <sys/brand.h>
#include <sys/lx_brand.h>

/* From uts/common/disp/priocntl.c */
extern int donice(procset_t *, pcnice_t *);

/*
 * The Linux syscall returns priorities in the range (highest) 40-1 (lowest)
 * and then glibc adjusts these to the range -20 - 19.
 */
long
lx_getpriority(int which, id_t who)
{
	int rval;
	idtype_t idtype;
	id_t id, lid;
	pcnice_t pcnice;
	procset_t procset;

	switch (which) {
	case PRIO_PROCESS:
		idtype = P_PID;
		if (who > 0 && lx_lpid_to_spair(who, &who, &lid) < 0)
			return (set_errno(ESRCH));
		break;
	case PRIO_PGRP:
		idtype = P_PGID;
		break;
	case PRIO_USER:
		idtype = P_UID;
		break;
	default:
		return (set_errno(EINVAL));
	}

	/* Linux fails with a different errno on a negative id */
	if (who < 0)
		return (set_errno(ESRCH));

	id = (who == 0 ? P_MYID : who);

	pcnice.pc_val = 0;
	pcnice.pc_op = PC_GETNICE;

	setprocset(&procset, POP_AND, idtype, id, P_ALL, 0);

	rval = donice(&procset, &pcnice);
	if (rval != 0) {
		if (which == PRIO_PROCESS &&
		    (who == curproc->p_pid || who == 0) &&
		    strcmp(sclass[curthread->t_cid].cl_name, "RT") == 0) {
			/*
			 * donice() will always return EINVAL if we're in the
			 * RT class. The zone won't be able to put itself or any
			 * of its processes into RT, but if we put the whole
			 * zone into RT via the scheduling-class property, then
			 * getpriority would always fail. This breaks pam and
			 * prevents any login. Just pretend to be the highest
			 * priority.
			 */
			return (40);
		}

		/*
		 * Linux does not return EINVAL for invalid 'who' values, it
		 * returns ESRCH instead. We already validated 'which' above.
		 */
		if (rval == EINVAL)
			rval = ESRCH;
		return (set_errno(rval));
	}

	/*
	 * The return value of the getpriority syscall is biased by 20 to avoid
	 * returning negative values when successful (-20 internally is our
	 * highest priority and 19 is our lowest).
	 */
	return (20 - pcnice.pc_val);
}

/*
 * Return EPERM if the current process is not allowed to operate on the target
 * process (which is part of the procset for setpriority).
 */
/* ARGSUSED */
static int
lx_chk_pripriv(proc_t *pp, char *dummy)
{
	ASSERT(MUTEX_HELD(&pidlock));
	mutex_enter(&pp->p_lock);
	if (!prochasprocperm(pp, curproc, CRED())) {
		mutex_exit(&pp->p_lock);
		return (EPERM);
	}
	mutex_exit(&pp->p_lock);
	return (0);
}

long
lx_setpriority(int which, id_t who, int prio)
{
	int rval;
	idtype_t idtype;
	id_t id, lid;
	pcnice_t pcnice;
	procset_t procset;

	switch (which) {
	case PRIO_PROCESS:
		idtype = P_PID;
		if (who > 0 && lx_lpid_to_spair(who, &who, &lid) < 0)
			return (set_errno(ESRCH));
		break;
	case PRIO_PGRP:
		idtype = P_PGID;
		break;
	case PRIO_USER:
		idtype = P_UID;
		break;
	default:
		return (set_errno(EINVAL));
	}

	/* Linux fails with a different errno on a negative id */
	if (who < 0)
		return (set_errno(ESRCH));

	id = (who == 0 ? P_MYID : who);

	if (prio > NZERO - 1) {
		prio = NZERO - 1;
	} else if (prio < -NZERO) {
		prio = -NZERO;
	}

	pcnice.pc_val = prio;
	pcnice.pc_op = PC_SETNICE;

	setprocset(&procset, POP_AND, idtype, id, P_ALL, 0);

	rval = donice(&procset, &pcnice);
	if (rval != 0) {
		/*
		 * Once we fully support Linux capabilities, we should update
		 * the following check to look at the CAP_SYS_NICE capability.
		 */
		if (rval == EPERM && crgetuid(CRED()) != 0) {
			/*
			 * donice() returns EPERM under two conditions:
			 * 1) if either the real or eff. uid don't match
			 * 2) we lack the privileges to raise the priority
			 *
			 * However, setpriority() must return a different errno
			 * based on the following:
			 * EPERM  - real or eff. uid did not match
			 * EACCES - trying to increase priority
			 *
			 * We use lx_chk_pripriv to determine which case we hit.
			 *
			 * Note that the native setpriority(3C) code has the
			 * same race on re-checking.
			 */
			if (dotoprocs(&procset, lx_chk_pripriv, NULL) != EPERM)
				rval = EACCES;
		}

		return (set_errno(rval));
	}

	return (0);
}
