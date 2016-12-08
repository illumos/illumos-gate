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
 * Copyright 2016 Joyent, Inc.
 */

/*
 * [This comment omits the 'LX_' prefix on the clone flag names.]
 *
 * The vast majority of clone calls result in the creation of a new process or
 * a new thread. Both of these map easily from Linux to our native code. For
 * these calls, the user-level brand library uses a brand call to hook into the
 * lx_helper_clone function for the required in-kernel support.
 *
 * A fork will typically provide these clone flags:
 *    CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID
 *
 * A new thread will use our SHARED_AS macro which has the flags:
 *     CLONE_FILES | CLONE_FS | CLONE_SIGHAND | CLONE_THREAD |  CLONE_VM
 *
 * In rare cases an application will attempt to use a subset of the SHARED_AS
 * flags in order to implement some sharing between two processes without using
 * a true thread. Because we do not have native support for this concept, the
 * lx brand implements the notion of a 'clone-group'. This is a set of
 * processes which share a subset of the allowed SHARED_AS flags. The lx brand
 * syscalls implement the appropriate sharing for each flag. A clone-group is
 * only instantiated in the rare case that a subset of the SHARED_AS flags are
 * used with clone.
 *
 * The following set of flags could theoretically be supported, although most
 * are not implemented at this time. The user-level brand library will validate
 * that a supported subset of the flags are being used, or error if not. We
 * also re-validate in the kernel.
 *
 * CLONE_FILES:	share the file descriptor table
 * CLONE_FS:	share the filesystem information (root of the filesystem, the
 *		CWD, and the umask)
 * CLONE_SIGHAND: share the table of signal handlers
 * CLONE_THREAD: share the thread group
 * CLONE_VM:	share the address space
 *
 * At this time, only those flags defined in CLONE_GRP_SUBSET (CLONE_FS) are
 * implemented.
 *
 * When a clone-group is in use, the lx_proc_data_t`l_clone_grps array will
 * hold groups of processes sharing the attributes relevant to the clone flag.
 * Each supported flag can have an associated group list in the array.
 *
 * On the first clone, a new lx_clone_grp_t struct will be created. This struct
 * holds a pointer to each process in the group. A reference to that group is
 * held in the appropriate slot in l_clone_grps. The struct is created for
 * the parent process by lx_clone_grp_create() and then the child process will
 * associate itself with the group(s) using lx_clone_grp_enter().
 *
 * Each syscall acting upon attributes relevant to a clone-group must include
 * logic to do so properly. The syscalls will use lx_clone_grp_member() to
 * determine if clone-group handling is required, and use lx_clone_grp_walk()
 * to walk the list of processes in the group and apply the provided callback
 * to each process.
 *
 * The following example illustrates how a common clone group would be used,
 * as processes clone with the same set of CLONE_* flags.
 *	A clones B with CLONE_FS
 *	B clones C with CLONE_FS
 * When A clones B, a new clone group is created and saved in the LX_CLGRP_FS
 * slot in the l_clone_grps array on both A and B. When B clones, since a group
 * already exists, C is added to the group and the group is saved in the
 * LX_CLGRP_FS slot on C.
 *
 * The following example illustrates how two common clone groups would be used,
 * as processes clone with the same set of CLONE_* flags.
 *	A clones B with CLONE_FS|CLONE_THREAD
 * A new clone group is created and saved in the LX_CLGRP_FS slot in the
 * l_clone_grps array on both A and B. A second clone group is created and
 * saved in the LX_CLGRP_THREAD slot on both A and B (note that LX_CLGRP_THREAD
 * is not implemented at this time).
 *
 * The following example illustrates how different clone groups would be used,
 * as processes clone with different sets of CLONE_* flags.
 *	A clones B with CLONE_FS
 *	B clones C with CLONE_THREAD
 *	C clones D with CLONE_FS
 * In this example, only A&B and C&D should share their FS information. B&C
 * have to be in two clone groups. When A clones, a new clone group is created
 * and saved in the LX_CLGRP_FS slot in the l_clone_grps array on both A and B.
 * When B clones, a new clone group is created and saved in the LX_CLGRP_THREAD
 * slot on both B and C (note that LX_CLGRP_THREAD is not implemented at this
 * time). When C clones, a new clone group is created and saved in the
 * LX_CLGRP_FS slot on both C and D.
 *
 * When a process exits, it removes itself from any groups to which it belongs.
 * When the last process exits a group, it is cleaned up.
 *
 * If clone-groups were commonly used, this implementation would be inefficient
 * and unwieldy, but since they are so rare a straightforward list-based
 * approach is adequate.
 *
 * During group creation, the l_clone_grp_lock is first taken to ensure only
 * one group is created, otherwise, only the group's lx_clgrp_lock protects the
 * list.
 *
 * Note: Despite the locking, there is still a subtle race that can occur in
 * this code. This occurs if a process has two threads and one of them is about
 * to execute a clone-group aware syscall (e.g. chdir), while the other thread
 * is forking to create a new clone-group. In theory the child process could be
 * created, but not yet in the group. The syscall in the first thread could
 * thus miss the new process. For example, the first thread might chdir the
 * parent, but since the child process was alrady created, but not yet in the
 * clone-group, it would not be chdir-ed.
 */


#include <sys/types.h>
#include <sys/systm.h>
#include <sys/errno.h>
#include <sys/brand.h>
#include <sys/lx_brand.h>
#include <sys/lx_ldt.h>
#include <sys/lx_misc.h>
#include <lx_signum.h>
#include <lx_syscall.h>
#include <sys/x86_archext.h>
#include <sys/controlregs.h>

/*
 * We currently only support a single clone-group (CLONE_FS) but the design
 * allows for future expansion by expanding the lx_proc_data+t`l_clone_grps
 * array.
 */
static int
lx_clone_flag2grp(uint_t flag)
{
	if (flag & LX_CLONE_FS)
		return (LX_CLGRP_FS);

	return (-1);
}

/*
 * Note: this function has the side effect of clearing the flags.
 */
static int
lx_clone_flags_iter(uint_t *fp)
{
	if (*fp & LX_CLONE_FS) {
		*fp &= ~LX_CLONE_FS;
		return (LX_CLGRP_FS);
	}

	return (-1);
}

/*
 * Setup the current process in the proper clone-group(s) and record the
 * clone-group flags on the lwp so that we can join the child process to the
 * group during lx_forklwp().
 */
void
lx_clone_grp_create(uint_t flags)
{
	int offset;
	lx_proc_data_t *plproc = ttolxproc(curthread);
	lx_lwp_data_t *ldp = (lx_lwp_data_t *)ttolwp(curthread)->lwp_brand;
	lx_clone_grp_t **cgps;
	lx_clone_grp_t *cgp;
	lx_clone_grp_member_t *mp;

	if (!LX_IS_CLONE_GRP(flags))
		return;

	ldp->br_clone_grp_flags = flags & LX_CLONE_GRP_SUBSET;

	cgps = plproc->l_clone_grps;
	/*
	 * We take the top-level mutex during create to ensure we only create
	 * one group per flag.
	 */
	mutex_enter(&plproc->l_clone_grp_lock);
	while ((offset = lx_clone_flags_iter(&flags)) != -1) {
		cgp = cgps[offset];

		/*
		 * If we already havae a clone-group list for this flag then
		 * nothing to do.
		 */
		if (cgp != NULL)
			continue;

		/*
		 * Create a new clone-group. If it ever becomes an issue, we
		 * could preallocate this memory before taking
		 * l_clone_grp_lock.
		 */
		cgp = kmem_alloc(sizeof (lx_clone_grp_t), KM_SLEEP);
		mutex_init(&cgp->lx_clgrp_lock, NULL, MUTEX_DEFAULT, NULL);
		cgp->lx_clgrp_cnt = 1;
		list_create(&cgp->lx_clgrp_members,
		    sizeof (lx_clone_grp_member_t),
		    offsetof(lx_clone_grp_member_t, lx_clgrpm_link));

		mp = kmem_zalloc(sizeof (lx_clone_grp_member_t), KM_SLEEP);
		mp->lx_clgrpm_pp = curproc;
		list_insert_tail(&cgp->lx_clgrp_members, mp);

		/* Attach group to our proc */
		plproc->l_clone_grps[offset] = cgp;
	}
	mutex_exit(&plproc->l_clone_grp_lock);
}

/*
 * Add the child process to the proper parent clone-group(s).
 *
 * Called from lx_forklwp, thus there is no need to have any locking for the
 * destination proc. This is always run in the thread context of the source
 * thread, and the destination thread is always newly created and not referred
 * to from anywhere else. The source process should have already created the
 * clone group(s) that we need to place the child into via lx_clone_grp_create.
 */
void
lx_clone_grp_enter(uint_t flags, proc_t *srcp, proc_t *dstp)
{
	int offset;
	lx_proc_data_t *plproc = ptolxproc(srcp);
	lx_proc_data_t *clproc = ptolxproc(dstp);
	lx_clone_grp_t **cgps;
	lx_clone_grp_t *cgp;
	lx_clone_grp_member_t *mp;

	cgps = plproc->l_clone_grps;
	while ((offset = lx_clone_flags_iter(&flags)) != -1) {
		cgp = cgps[offset];

		/*
		 * Parent should already have a clone-group list for this flag.
		 * The child joins that group.
		 */
		VERIFY(cgp != NULL);

		mp = kmem_zalloc(sizeof (lx_clone_grp_member_t), KM_SLEEP);
		mp->lx_clgrpm_pp = dstp;

		mutex_enter(&cgp->lx_clgrp_lock);
		list_insert_tail(&cgp->lx_clgrp_members, mp);
		cgp->lx_clgrp_cnt++;
		clproc->l_clone_grps[offset] = cgp;
		mutex_exit(&cgp->lx_clgrp_lock);
	}
}

/*
 * The process is exiting or we're exec-ing a native app. In the unlikely event
 * it is in a clone-group, remove it from the group and perform any necessary
 * cleanup. Normally we're called from lx_proc_exit(), so we know we're the
 * last lwp in the process, but we can also be called from lx_clearbrand() when
 * exec-ing a native application. In this case we know the lwp(s) are stopped
 * (It is possible to have multiple lwps if we branded the process but the
 * exec failed. Those lwps were just branded as part of the exec, and will
 * be de-branded).
 */
void
lx_clone_grp_exit(proc_t *p, boolean_t lwps_ok)
{
	int i;
	lx_proc_data_t *plproc = ptolxproc(p);
	lx_clone_grp_t **cgps;

	ASSERT(!MUTEX_HELD(&p->p_lock));
	ASSERT(plproc != NULL);

	if (!lwps_ok)
		VERIFY(p->p_lwpcnt <= 1);

	cgps = plproc->l_clone_grps;
	for (i = 0; i < LX_CLGRP_MAX; i++) {
		lx_clone_grp_t *cgp;
		lx_clone_grp_member_t *mp;
		boolean_t found;

		cgp = cgps[i];
		if (cgp == NULL)
			continue;

		/*
		 * The rare case when this process belongs to a clone-group.
		 */

		mutex_enter(&cgp->lx_clgrp_lock);

		/* First remove ourselves from the group. */
		found = B_FALSE;
		mp = list_head(&cgp->lx_clgrp_members);
		while (mp != NULL) {
			if (mp->lx_clgrpm_pp == p) {
				found = B_TRUE;
				list_remove(&cgp->lx_clgrp_members, mp);
				kmem_free(mp, sizeof (lx_clone_grp_member_t));
				ASSERT(cgp->lx_clgrp_cnt > 0);
				cgp->lx_clgrp_cnt--;
				plproc->l_clone_grps[i] = NULL;
				break;
			}
			mp = list_next(&cgp->lx_clgrp_members, mp);
		}
		VERIFY(found);

		if (cgp->lx_clgrp_cnt > 0) {
			mutex_exit(&cgp->lx_clgrp_lock);
			continue;
		}

		/*
		 * cgp->lx_clgrp_cnt == 0
		 *
		 * We're the sole remaining member; finish cleanup now.
		 */
		ASSERT(plproc->l_clone_grps[i] == NULL);
		mutex_exit(&cgp->lx_clgrp_lock);

		/* Delete the group since there are no more references to it. */
		VERIFY(list_is_empty(&cgp->lx_clgrp_members));

		list_destroy(&cgp->lx_clgrp_members);
		mutex_destroy(&cgp->lx_clgrp_lock);
		kmem_free(cgp, sizeof (lx_clone_grp_t));
	}
}

/*
 * Return true in the rare case that the process is a member of a clone group
 * with the specific flag set. Clone groups are only added to the array
 * atomically until this process exits, so we don't need to take
 * l_clone_grp_lock.
 */
boolean_t
lx_clone_grp_member(lx_proc_data_t *dp, uint_t flag)
{
	int offset;

	if ((offset = lx_clone_flag2grp(flag)) == -1)
		return (B_FALSE);

	if (dp->l_clone_grps[offset] != NULL) {
		return (B_TRUE);
	}

	return (B_FALSE);
}

/*
 * Walk all of the processes in the clone-group list and apply the callback
 * to each. Because we're holding the group list lock (lx_clgrp_lock) none of
 * the processes can exit, but that is the only locking guarantee made by this
 * function itself.
 */
int
lx_clone_grp_walk(lx_proc_data_t *dp, uint_t flag, int (*cb)(proc_t *, void *),
    void *arg)
{
	int offset;
	lx_clone_grp_t *cgp;
	lx_clone_grp_member_t *mp;
	int res, rv = 0;


	ASSERT(dp != NULL);
	/* We should not be called unless we belong to a group */
	VERIFY((offset = lx_clone_flag2grp(flag)) != -1);
	VERIFY(dp->l_clone_grps[offset] != NULL);

	cgp = dp->l_clone_grps[offset];
	mutex_enter(&cgp->lx_clgrp_lock);

	mp = list_head(&cgp->lx_clgrp_members);
	while (mp != NULL) {
		res = cb(mp->lx_clgrpm_pp, arg);
		/* return the first error we see, but try all procs */
		if (res != 0 && rv == 0)
			rv = res;
		mp = list_next(&cgp->lx_clgrp_members, mp);
	}

	mutex_exit(&cgp->lx_clgrp_lock);

	return (rv);
}


/*
 * Our lwp has already been created at this point, so this routine is
 * responsible for setting up all the state needed to track this as a
 * linux cloned thread.
 */
/* ARGSUSED */
int
lx_helper_clone(int64_t *rval, int flags, void *ptidp, void *tls, void *ctidp)
{
	struct lx_lwp_data *lwpd = ttolxlwp(curthread);
	struct lx_proc_data *lproc = ttolxproc(curthread);
	struct ldt_info info;
	struct user_desc descr;
	int tls_index;
	int entry = -1;
	int signo;

	signo = flags & LX_CSIGNAL;
	if (signo < 0 || signo > LX_NSIG)
		return (set_errno(EINVAL));

	if (!(flags & LX_CLONE_THREAD)) {
		lproc->l_signal = signo;
	} else {
		if (flags & LX_CLONE_SETTLS) {
			if (get_udatamodel() == DATAMODEL_ILP32) {
				if (copyin((caddr_t)tls, &info, sizeof (info)))
					return (set_errno(EFAULT));

				if (LDT_INFO_EMPTY(&info))
					return (set_errno(EINVAL));

				entry = info.entry_number;
				if (entry < GDT_TLSMIN || entry > GDT_TLSMAX)
					return (set_errno(EINVAL));

				tls_index = entry - GDT_TLSMIN;

				/*
				 * Convert the user-space structure into a real
				 * x86 descriptor and copy it into this LWP's
				 * TLS array.  We also load it into the GDT.
				 */
				LDT_INFO_TO_DESC(&info, &descr);
				bcopy(&descr, &lwpd->br_tls[tls_index],
				    sizeof (descr));
				lx_set_gdt(entry, &lwpd->br_tls[tls_index]);
			} else {
				/*
				 * Set the Linux %fsbase for this LWP.  We will
				 * restore it the next time we return to Linux
				 * via setcontext()/lx_restorecontext().
				 */
				lwpd->br_lx_fsbase = (uintptr_t)tls;
			}
		}

		lwpd->br_clear_ctidp =
		    (flags & LX_CLONE_CHILD_CLEARTID) ?  ctidp : NULL;

		if (signo && ! (flags & LX_CLONE_DETACH))
			lwpd->br_signal = signo;
		else
			lwpd->br_signal = 0;

		if (flags & LX_CLONE_THREAD)
			lwpd->br_tgid = curthread->t_procp->p_pid;

		if (flags & LX_CLONE_PARENT)
			lwpd->br_ppid = 0;

		if ((flags & LX_CLONE_CHILD_SETTID) && (ctidp != NULL) &&
		    (suword32(ctidp, lwpd->br_pid) != 0)) {
			if (entry >= 0)
				lx_clear_gdt(entry);
			return (set_errno(EFAULT));
		}
		if ((flags & LX_CLONE_PARENT_SETTID) && (ptidp != NULL) &&
		    (suword32(ptidp, lwpd->br_pid) != 0)) {
			if (entry >= 0)
				lx_clear_gdt(entry);
			return (set_errno(EFAULT));
		}
	}

	*rval = lwpd->br_pid;
	return (0);
}

long
lx_set_tid_address(int *tidp)
{
	struct lx_lwp_data *lwpd = ttolxlwp(curthread);
	long rv;

	lwpd->br_clear_ctidp = tidp;

	if (curproc->p_pid == curproc->p_zone->zone_proc_initpid) {
		rv = 1;
	} else {
		rv = lwpd->br_pid;
	}

	return (rv);
}
