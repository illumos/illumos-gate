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
#include <sys/schedctl.h>
#include <vm/as.h>
#include <sys/debug.h>
#include <sys/contract/process_impl.h>

/*ARGSUSED*/
static int
copyin_siginfo(model_t datamodel, void *uaddr, k_siginfo_t *ksip)
{
#ifdef _SYSCALL32_IMPL
	int ret;

	if (datamodel == DATAMODEL_NATIVE) {
#endif
		return (copyin(uaddr, ksip, sizeof (k_siginfo_t)));
#ifdef _SYSCALL32_IMPL
	} else {
		siginfo32_t si32;

		if (ret = copyin(uaddr, &si32, sizeof (si32)))
			return (ret);

		siginfo_32tok(&si32, ksip);
	}

	return (0);
#endif
}

/*
 * To find secured 64 bit id for signotify() call
 * This depends upon as_getmemid() which returns
 * unique vnode/offset for a user virtual address.
 */
static u_longlong_t
get_sigid(proc_t *p, caddr_t addr)
{
	u_longlong_t snid = 0;
	memid_t memid;
	quad_t *tquad = (quad_t *)&snid;

	if (!as_getmemid(p->p_as, addr, &memid)) {
		tquad->val[0] = (int)memid.val[0];
		tquad->val[1] = (int)memid.val[1];
	}
	return (snid);
}

#define	SIGN_PTR(p, n)	&((signotifyq_t *)(&p->p_signhdr[1]))[n];

int
signotify(int cmd, siginfo_t *siginfo, signotify_id_t *sn_id)
{
	k_siginfo_t	info;
	signotify_id_t	id;
	proc_t		*p;
	proc_t		*cp = curproc;
	signotifyq_t	*snqp;
	struct cred	*cr;
	sigqueue_t	*sqp;
	sigqhdr_t	*sqh;
	u_longlong_t	sid;
	model_t 	datamodel = get_udatamodel();

	if (copyin(sn_id, &id, sizeof (signotify_id_t)))
		return (set_errno(EFAULT));

	if (id.sn_index >= _SIGNOTIFY_MAX || id.sn_index < 0)
		return (set_errno(EINVAL));

	switch (cmd) {
	case SN_PROC:
		/* get snid for the given user address of signotifyid_t */
		sid = get_sigid(cp, (caddr_t)sn_id);

		if (id.sn_pid > 0) {
			mutex_enter(&pidlock);
			if ((p = prfind(id.sn_pid)) != NULL) {
				mutex_enter(&p->p_lock);
				if (p->p_signhdr != NULL) {
					snqp = SIGN_PTR(p, id.sn_index);
					if (snqp->sn_snid == sid) {
						mutex_exit(&p->p_lock);
						mutex_exit(&pidlock);
						return (set_errno(EBUSY));
					}
				}
				mutex_exit(&p->p_lock);
			}
			mutex_exit(&pidlock);
		}

		if (copyin_siginfo(datamodel, siginfo, &info))
			return (set_errno(EFAULT));

		/* The si_code value must indicate the signal will be queued */
		if (!sigwillqueue(info.si_signo, info.si_code))
			return (set_errno(EINVAL));

		if (cp->p_signhdr == NULL) {
			/* Allocate signotify pool first time */
			sqh = sigqhdralloc(sizeof (signotifyq_t),
			    _SIGNOTIFY_MAX);
			mutex_enter(&cp->p_lock);
			if (cp->p_signhdr == NULL) {
				/* hang the pool head on proc */
				cp->p_signhdr = sqh;
			} else {
				/* another lwp allocated the pool, free ours */
				sigqhdrfree(sqh);
			}
		} else {
			mutex_enter(&cp->p_lock);
		}

		sqp = sigqalloc(cp->p_signhdr);
		if (sqp == NULL) {
			mutex_exit(&cp->p_lock);
			return (set_errno(EAGAIN));
		}
		cr = CRED();
		sqp->sq_info = info;
		sqp->sq_info.si_pid = cp->p_pid;
		sqp->sq_info.si_ctid = PRCTID(cp);
		sqp->sq_info.si_zoneid = getzoneid();
		sqp->sq_info.si_uid = crgetruid(cr);

		/* fill the signotifyq_t fields */
		((signotifyq_t *)sqp)->sn_snid = sid;

		mutex_exit(&cp->p_lock);

		/* complete the signotify_id_t fields */
		id.sn_index = (signotifyq_t *)sqp - SIGN_PTR(cp, 0);
		id.sn_pid = cp->p_pid;

		break;

	case SN_CANCEL:
	case SN_SEND:

		sid =  get_sigid(cp, (caddr_t)sn_id);
		mutex_enter(&pidlock);
		if ((id.sn_pid <= 0) || ((p = prfind(id.sn_pid)) == NULL)) {
			mutex_exit(&pidlock);
			return (set_errno(EINVAL));
		}
		mutex_enter(&p->p_lock);
		mutex_exit(&pidlock);

		if (p->p_signhdr == NULL) {
			mutex_exit(&p->p_lock);
			return (set_errno(EINVAL));
		}

		snqp = SIGN_PTR(p, id.sn_index);

		if (snqp->sn_snid == 0) {
			mutex_exit(&p->p_lock);
			return (set_errno(EINVAL));
		}

		if (snqp->sn_snid != sid) {
			mutex_exit(&p->p_lock);
			return (set_errno(EINVAL));
		}

		snqp->sn_snid = 0;

		/* cmd == SN_CANCEL or signo == 0 (SIGEV_NONE) */
		if (((sigqueue_t *)snqp)->sq_info.si_signo <= 0)
			cmd = SN_CANCEL;

		sigqsend(cmd, p, 0, (sigqueue_t *)snqp);
		mutex_exit(&p->p_lock);

		id.sn_pid = 0;
		id.sn_index = 0;

		break;

	default :
		return (set_errno(EINVAL));
	}

	if (copyout(&id, sn_id, sizeof (signotify_id_t)))
		return (set_errno(EFAULT));

	return (0);
}

int
sigresend(int sig, siginfo_t *siginfo, sigset_t *mask)
{
	kthread_t *t = curthread;
	klwp_t *lwp = ttolwp(t);
	sigqueue_t *sqp = kmem_zalloc(sizeof (*sqp), KM_SLEEP);
	sigset_t set;
	k_sigset_t kset;
	int error;

	if (sig <= 0 || sig >= NSIG || sigismember(&cantmask, sig)) {
		error = EINVAL;
		goto bad;
	}

	if (siginfo == NULL) {
		sqp->sq_info.si_signo = sig;
		sqp->sq_info.si_code = SI_NOINFO;
	} else {
		if (copyin_siginfo(get_udatamodel(), siginfo, &sqp->sq_info)) {
			error = EFAULT;
			goto bad;
		}
		if (sqp->sq_info.si_signo != sig) {
			error = EINVAL;
			goto bad;
		}
	}

	if (copyin(mask, &set, sizeof (set))) {
		error = EFAULT;
		goto bad;
	}
	sigutok(&set, &kset);

	/*
	 * We don't need to acquire p->p_lock here;
	 * we are manipulating thread-private data.
	 */
	if (lwp->lwp_cursig || lwp->lwp_curinfo) {
		t->t_sig_check = 1;
		error = EAGAIN;
		goto bad;
	}
	lwp->lwp_cursig = sig;
	lwp->lwp_curinfo = sqp;
	schedctl_finish_sigblock(t);
	t->t_hold = kset;
	t->t_sig_check = 1;
	return (0);
bad:
	kmem_free(sqp, sizeof (*sqp));
	return (set_errno(error));
}
