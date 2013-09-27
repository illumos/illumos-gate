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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T */

#include <sys/param.h>
#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/proc.h>
#include <sys/procset.h>
#include <sys/fault.h>
#include <sys/signal.h>
#include <sys/siginfo.h>
#include <sys/debug.h>

extern rctl_hndl_t rc_process_sigqueue;

static int
sigqkill(pid_t pid, sigsend_t *sigsend)
{
	proc_t *p;
	int error;

	if ((uint_t)sigsend->sig >= NSIG)
		return (EINVAL);

	if (pid == -1) {
		procset_t set;

		setprocset(&set, POP_AND, P_ALL, P_MYID, P_ALL, P_MYID);
		error = sigsendset(&set, sigsend);
	} else if (pid > 0) {
		mutex_enter(&pidlock);
		if ((p = prfind(pid)) == NULL || p->p_stat == SIDL)
			error = ESRCH;
		else {
			error = sigsendproc(p, sigsend);
			if (error == 0 && sigsend->perm == 0)
				error = EPERM;
		}
		mutex_exit(&pidlock);
	} else {
		int nfound = 0;
		pid_t pgid;

		if (pid == 0)
			pgid = ttoproc(curthread)->p_pgrp;
		else
			pgid = -pid;

		error = 0;
		mutex_enter(&pidlock);
		for (p = pgfind(pgid); p && !error; p = p->p_pglink) {
			if (p->p_stat != SIDL) {
				nfound++;
				error = sigsendproc(p, sigsend);
			}
		}
		mutex_exit(&pidlock);
		if (nfound == 0)
			error = ESRCH;
		else if (error == 0 && sigsend->perm == 0)
			error = EPERM;
	}

	return (error);
}


/*
 * for implementations that don't require binary compatibility,
 * the kill system call may be made into a library call to the
 * sigsend system call
 */
int
kill(pid_t pid, int sig)
{
	int error;
	sigsend_t v;

	bzero(&v, sizeof (v));
	v.sig = sig;
	v.checkperm = 1;
	v.sicode = SI_USER;
	if ((error = sigqkill(pid, &v)) != 0)
		return (set_errno(error));
	return (0);
}

/*
 * The handling of small unions, like the sigval argument to sigqueue,
 * is architecture dependent.  We have adopted the convention that the
 * value itself is passed in the storage which crosses the kernel
 * protection boundary.  This procedure will accept a scalar argument,
 * and store it in the appropriate value member of the sigsend_t structure.
 */
int
sigqueue(pid_t pid, int sig, /* union sigval */ void *value,
    int si_code, int block)
{
	int error;
	sigsend_t v;
	sigqhdr_t *sqh;
	proc_t *p = curproc;

	/* The si_code value must indicate the signal will be queued */
	if (pid <= 0 || !sigwillqueue(sig, si_code))
		return (set_errno(EINVAL));

	if ((sqh = p->p_sigqhdr) == NULL) {
		rlim64_t sigqsz_max;

		mutex_enter(&p->p_lock);
		sigqsz_max = rctl_enforced_value(rc_process_sigqueue,
		    p->p_rctls, p);
		mutex_exit(&p->p_lock);

		/* Allocate sigqueue pool first time */
		sqh = sigqhdralloc(sizeof (sigqueue_t), (uint_t)sigqsz_max);
		mutex_enter(&p->p_lock);
		if (p->p_sigqhdr == NULL) {
			/* hang the pool head on proc */
			p->p_sigqhdr = sqh;
		} else {
			/* another lwp allocated the pool, free ours */
			sigqhdrfree(sqh);
			sqh = p->p_sigqhdr;
		}
		mutex_exit(&p->p_lock);
	}

	do {
		bzero(&v, sizeof (v));
		v.sig = sig;
		v.checkperm = 1;
		v.sicode = si_code;
		v.value.sival_ptr = value;
		if ((error = sigqkill(pid, &v)) != EAGAIN || !block)
			break;
		/* block waiting for another chance to allocate a sigqueue_t */
		mutex_enter(&sqh->sqb_lock);
		while (sqh->sqb_count == 0) {
			if (!cv_wait_sig(&sqh->sqb_cv, &sqh->sqb_lock)) {
				error = EINTR;
				break;
			}
		}
		mutex_exit(&sqh->sqb_lock);
	} while (error == EAGAIN);

	if (error)
		return (set_errno(error));
	return (0);
}

#ifdef _SYSCALL32_IMPL
/*
 * sigqueue32 - System call entry point for 32-bit callers on LP64 kernel,
 * needed to handle the 32-bit sigvals as correctly as we can.  We always
 * assume that a 32-bit caller is passing an int. A 64-bit recipient
 * that expects an int will therefore get it correctly.  A 32-bit
 * recipient will also get it correctly since siginfo_kto32() uses
 * sival_int in the conversion.  Since a 32-bit pointer has the same
 * size and address in the sigval, it also converts correctly so that
 * two 32-bit apps can exchange a pointer value.  However, this means
 * that a pointer sent by a 32-bit caller will be seen in the upper half
 * by a 64-bit recipient, and only the upper half of a 64-bit pointer will
 * be seen by a 32-bit recipient.  This is the best solution that does
 * not require severe hacking of the sigval union.  Anyways, what it
 * means to be sending pointers between processes with dissimilar
 * models is unclear.
 */
int
sigqueue32(pid_t pid, int sig, /* union sigval32 */ caddr32_t value,
	int si_code, int block)
{
	union sigval sv;

	bzero(&sv, sizeof (sv));
	sv.sival_int = (int)value;
	return (sigqueue(pid, sig, sv.sival_ptr, si_code, block));
}
#endif
