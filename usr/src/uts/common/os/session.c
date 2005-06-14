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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/file.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/errno.h>
#include <sys/signal.h>
#include <sys/pcb.h>
#include <sys/cred.h>
#include <sys/policy.h>
#include <sys/user.h>
#include <sys/buf.h>
#include <sys/var.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/proc.h>
#include <sys/session.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/strsubr.h>

sess_t session0 = {
	1,	/* s_ref   */
	0555,	/* s_mode  */
	0,	/* s_uid   */
	0,	/* s_gid   */
	0,	/* s_ctime */
	NODEV,	/* s_dev   */
	NULL,	/* s_vp    */
	&pid0,	/* s_sidp  */
	NULL	/* s_cred  */
};

void
sess_rele(sess_t *sp)
{
	ASSERT(MUTEX_HELD(&pidlock));

	ASSERT(sp->s_ref != 0);
	if (--sp->s_ref == 0) {
		if (sp == &session0)
			panic("sp == &session0");
		PID_RELE(sp->s_sidp);
		mutex_destroy(&sp->s_lock);
		cv_destroy(&sp->s_wait_cv);
		kmem_free(sp, sizeof (sess_t));
	}
}

void
sess_create(void)
{
	proc_t *pp;
	sess_t *sp;

	pp = ttoproc(curthread);

	sp = kmem_zalloc(sizeof (sess_t), KM_SLEEP);

	mutex_init(&sp->s_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&sp->s_wait_cv, NULL, CV_DEFAULT, NULL);

	mutex_enter(&pidlock);

	/*
	 * We need to protect p_pgidp with p_lock because
	 * /proc looks at it while holding only p_lock.
	 */
	mutex_enter(&pp->p_lock);
	pgexit(pp);
	SESS_RELE(pp->p_sessp);

	sp->s_sidp = pp->p_pidp;
	sp->s_ref = 1;
	sp->s_dev = NODEV;

	pp->p_sessp = sp;

	pgjoin(pp, pp->p_pidp);
	mutex_exit(&pp->p_lock);

	PID_HOLD(sp->s_sidp);
	mutex_exit(&pidlock);
}

void
freectty(sess_t *sp)
{
	vnode_t *vp;
	cred_t *cred;

	vp = sp->s_vp;

	strfreectty(vp->v_stream);

	mutex_enter(&sp->s_lock);
	while (sp->s_cnt > 0) {
		cv_wait(&sp->s_wait_cv, &sp->s_lock);
	}
	ASSERT(sp->s_cnt == 0);
	ASSERT(vp->v_count >= 1);
	sp->s_vp = NULL;
	cred = sp->s_cred;

	/*
	 * It is possible for the VOP_CLOSE below to call strctty
	 * and reallocate a new tty vnode.  To prevent that the
	 * session is marked as closing here.
	 */

	sp->s_flag = SESS_CLOSE;
	sp->s_cred = NULL;
	mutex_exit(&sp->s_lock);

	/*
	 * This will be the only thread with access to
	 * this vnode, from this point on.
	 */

	(void) VOP_CLOSE(vp, 0, 1, (offset_t)0, cred);
	VN_RELE(vp);

	crfree(cred);
}

/*
 *	++++++++++++++++++++++++
 *	++  SunOS4.1 Buyback  ++
 *	++++++++++++++++++++++++
 *
 * vhangup: Revoke access of the current tty by all processes
 * Used by privileged users to give a "clean" terminal at login
 */
int
vhangup()
{
	if (secpolicy_sys_config(CRED(), B_FALSE) != 0)
		return (set_errno(EPERM));
	/*
	 * This routine used to call freectty() under a condition that
	 * could never happen.  So this code has never actually done
	 * anything, and evidently nobody has ever noticed.  4098399.
	 */
	return (0);
}

dev_t
cttydev(proc_t *pp)
{
	sess_t *sp = pp->p_sessp;
	if (sp->s_vp == NULL)
		return (NODEV);
	return (sp->s_dev);
}

void
alloctty(proc_t *pp, vnode_t *vp)
{
	sess_t *sp = pp->p_sessp;
	cred_t *crp;

	sp->s_vp = vp;
	sp->s_dev = vp->v_rdev;

	mutex_enter(&pp->p_crlock);
	crhold(crp = pp->p_cred);
	mutex_exit(&pp->p_crlock);
	sp->s_cred = crp;
	sp->s_uid = crgetuid(crp);
	sp->s_ctime = gethrestime_sec();
	if (session0.s_mode & VSGID)
		sp->s_gid = session0.s_gid;
	else
		sp->s_gid = crgetgid(crp);
	sp->s_mode = (0666 & ~(PTOU(pp)->u_cmask));
}

int
hascttyperm(sess_t *sp, cred_t *cr, mode_t mode)
{
	int shift = 0;

	if (crgetuid(cr) != sp->s_uid) {
		shift += 3;
		if (!groupmember(sp->s_gid, cr))
			shift += 3;
	}

	mode &= ~(sp->s_mode << shift);

	if (mode == 0)
		return (1);

	return (secpolicy_vnode_access(cr, sp->s_vp, sp->s_uid, mode) == 0);
}
