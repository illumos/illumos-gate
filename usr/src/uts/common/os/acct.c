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
 * Copyright (c) 1992, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/


#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/acct.h>
#include <sys/cred.h>
#include <sys/user.h>
#include <sys/errno.h>
#include <sys/file.h>
#include <sys/vnode.h>
#include <sys/debug.h>
#include <sys/proc.h>
#include <sys/resource.h>
#include <sys/session.h>
#include <sys/modctl.h>
#include <sys/syscall.h>
#include <sys/policy.h>
#include <sys/list.h>
#include <sys/time.h>
#include <sys/msacct.h>
#include <sys/zone.h>

/*
 * Each zone has its own accounting settings (on or off) and associated
 * file.  The global zone is not special in this aspect; it will only
 * generate records for processes that ran in the global zone.  We could
 * allow the global zone to record all activity on the system, but there
 * would be no way of knowing the zone in which the processes executed.
 * sysacct() is thus virtualized to only act on the caller's zone.
 */
struct acct_globals {
	struct acct	acctbuf;
	kmutex_t	aclock;
	struct vnode	*acctvp;
	list_node_t	aclink;
};

/*
 * We need a list of all accounting settings for all zones, so we can
 * accurately determine if a file is in use for accounting (possibly by
 * another zone).
 */
static zone_key_t acct_zone_key;
static list_t acct_list;
kmutex_t acct_list_lock;

static struct sysent acctsysent = {
	1,
	SE_NOUNLOAD | SE_ARGC | SE_32RVAL1,
	sysacct
};

static struct modlsys modlsys = {
	&mod_syscallops, "acct(2) syscall", &acctsysent
};

#ifdef _SYSCALL32_IMPL
static struct modlsys modlsys32 = {
	&mod_syscallops32, "32-bit acct(2) syscall", &acctsysent
};
#endif

static struct modlinkage modlinkage = {
	MODREV_1,
	&modlsys,
#ifdef _SYSCALL32_IMPL
	&modlsys32,
#endif
	NULL
};

/*ARGSUSED*/
static void *
acct_init(zoneid_t zoneid)
{
	struct acct_globals *ag;

	ag = kmem_alloc(sizeof (*ag), KM_SLEEP);
	bzero(&ag->acctbuf, sizeof (ag->acctbuf));
	mutex_init(&ag->aclock, NULL, MUTEX_DEFAULT, NULL);
	ag->acctvp = NULL;

	mutex_enter(&acct_list_lock);
	list_insert_tail(&acct_list, ag);
	mutex_exit(&acct_list_lock);
	return (ag);
}

/* ARGSUSED */
static void
acct_shutdown(zoneid_t zoneid, void *arg)
{
	struct acct_globals *ag = arg;

	mutex_enter(&ag->aclock);
	if (ag->acctvp) {
		/*
		 * This needs to be done as a shutdown callback, otherwise this
		 * held vnode may cause filesystems to be busy, and the zone
		 * shutdown operation to fail.
		 */
		(void) VOP_CLOSE(ag->acctvp, FWRITE, 1, (offset_t)0, kcred,
		    NULL);
		VN_RELE(ag->acctvp);
	}
	ag->acctvp = NULL;
	mutex_exit(&ag->aclock);
}

/*ARGSUSED*/
static void
acct_fini(zoneid_t zoneid, void *arg)
{
	struct acct_globals *ag = arg;

	mutex_enter(&acct_list_lock);
	list_remove(&acct_list, ag);
	mutex_exit(&acct_list_lock);

	mutex_destroy(&ag->aclock);
	kmem_free(ag, sizeof (*ag));
}

int
_init(void)
{
	int error;

	mutex_init(&acct_list_lock, NULL, MUTEX_DEFAULT, NULL);
	list_create(&acct_list, sizeof (struct acct_globals),
	    offsetof(struct acct_globals, aclink));
	/*
	 * Using an initializer here wastes a bit of memory for zones that
	 * don't use accounting, but vastly simplifies the locking.
	 */
	zone_key_create(&acct_zone_key, acct_init, acct_shutdown, acct_fini);
	if ((error = mod_install(&modlinkage)) != 0) {
		(void) zone_key_delete(acct_zone_key);
		list_destroy(&acct_list);
		mutex_destroy(&acct_list_lock);
	}
	return (error);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * acct() is a "weak stub" routine called from exit().
 * Once this module has been loaded, we refuse to allow
 * it to unload - otherwise accounting would quietly
 * cease.  See 1211661.  It's possible to make this module
 * unloadable but it's substantially safer not to bother.
 */
int
_fini(void)
{
	return (EBUSY);
}

/*
 * See if vp is in use by the accounting system on any zone.  This does a deep
 * comparison of vnodes such that a file and a lofs "shadow" node of it will
 * appear to be the same.
 *
 * If 'compare_vfs' is true, the function will do a comparison of vfs_t's
 * instead (ie, is the vfs_t on which the vnode resides in use by the
 * accounting system in any zone).
 *
 * Returns 1 if found (in use), 0 otherwise.
 */
static int
acct_find(vnode_t *vp, boolean_t compare_vfs)
{
	struct acct_globals *ag;
	vnode_t *realvp;

	ASSERT(MUTEX_HELD(&acct_list_lock));
	ASSERT(vp != NULL);

	if (VOP_REALVP(vp, &realvp, NULL))
		realvp = vp;
	for (ag = list_head(&acct_list); ag != NULL;
	    ag = list_next(&acct_list, ag)) {
		vnode_t *racctvp;
		boolean_t found = B_FALSE;

		mutex_enter(&ag->aclock);
		if (ag->acctvp == NULL) {
			mutex_exit(&ag->aclock);
			continue;
		}
		if (VOP_REALVP(ag->acctvp, &racctvp, NULL))
			racctvp = ag->acctvp;
		if (compare_vfs) {
			if (racctvp->v_vfsp == realvp->v_vfsp)
				found = B_TRUE;
		} else {
			if (VN_CMP(realvp, racctvp))
				found = B_TRUE;
		}
		mutex_exit(&ag->aclock);
		if (found)
			return (1);
	}
	return (0);
}

/*
 * Returns 1 if the vfs that vnode resides on is in use for the accounting
 * subsystem, 0 otherwise.
 */
int
acct_fs_in_use(vnode_t *vp)
{
	int found;

	if (vp == NULL)
		return (0);
	mutex_enter(&acct_list_lock);
	found = acct_find(vp, B_TRUE);
	mutex_exit(&acct_list_lock);
	return (found);
}

/*
 * Perform process accounting functions.
 */
int
sysacct(char *fname)
{
	struct acct_globals *ag;
	struct vnode *vp;
	int error = 0;

	if (secpolicy_acct(CRED()) != 0)
		return (set_errno(EPERM));

	ag = zone_getspecific(acct_zone_key, curproc->p_zone);
	ASSERT(ag != NULL);

	if (fname == NULL) {
		/*
		 * Close the file and stop accounting.
		 */
		mutex_enter(&ag->aclock);
		vp = ag->acctvp;
		ag->acctvp = NULL;
		mutex_exit(&ag->aclock);
		if (vp) {
			error = VOP_CLOSE(vp, FWRITE, 1, (offset_t)0, CRED(),
			    NULL);
			VN_RELE(vp);
		}
		return (error == 0 ? 0 : set_errno(error));
	}

	/*
	 * Either (a) open a new file and begin accounting -or- (b)
	 * switch accounting from an old to a new file.
	 *
	 * (Open the file without holding aclock in case it
	 * sleeps (holding the lock prevents process exit).)
	 */
	if ((error = vn_open(fname, UIO_USERSPACE, FWRITE,
	    0, &vp, (enum create)0, 0)) != 0) {
		/* SVID  compliance */
		if (error == EISDIR)
			error = EACCES;
		return (set_errno(error));
	}

	if (vp->v_type != VREG) {
		error = EACCES;
	} else {
		mutex_enter(&acct_list_lock);
		if (acct_find(vp, B_FALSE)) {
			error = EBUSY;
		} else {
			mutex_enter(&ag->aclock);
			if (ag->acctvp) {
				vnode_t *oldvp;

				/*
				 * close old acctvp, and point acct()
				 * at new file by swapping vp and acctvp
				 */
				oldvp = ag->acctvp;
				ag->acctvp = vp;
				vp = oldvp;
			} else {
				/*
				 * no existing file, start accounting ..
				 */
				ag->acctvp = vp;
				vp = NULL;
			}
			mutex_exit(&ag->aclock);
		}
		mutex_exit(&acct_list_lock);
	}

	if (vp) {
		(void) VOP_CLOSE(vp, FWRITE, 1, (offset_t)0, CRED(), NULL);
		VN_RELE(vp);
	}
	return (error == 0 ? 0 : set_errno(error));
}

/*
 * Produce a pseudo-floating point representation
 * with 3 bits base-8 exponent, 13 bits fraction.
 */
static comp_t
acct_compress(ulong_t t)
{
	int exp = 0, round = 0;

	while (t >= 8192) {
		exp++;
		round = t & 04;
		t >>= 3;
	}
	if (round) {
		t++;
		if (t >= 8192) {
			t >>= 3;
			exp++;
		}
	}
#ifdef _LP64
	if (exp > 7) {
		/* prevent wraparound */
		t = 8191;
		exp = 7;
	}
#endif
	return ((exp << 13) + t);
}

/*
 * On exit, write a record on the accounting file.
 */
void
acct(char st)
{
	struct vnode *vp;
	struct cred *cr;
	struct proc *p;
	user_t *ua;
	struct vattr va;
	ssize_t resid = 0;
	int error;
	struct acct_globals *ag;

	/*
	 * If sysacct module is loaded when zone is in down state then
	 * the following function can return NULL.
	 */
	ag = zone_getspecific(acct_zone_key, curproc->p_zone);
	if (ag == NULL)
		return;

	mutex_enter(&ag->aclock);
	if ((vp = ag->acctvp) == NULL) {
		mutex_exit(&ag->aclock);
		return;
	}

	/*
	 * This only gets called from exit after all lwp's have exited so no
	 * cred locking is needed.
	 */
	p = curproc;
	ua = PTOU(p);
	bcopy(ua->u_comm, ag->acctbuf.ac_comm, sizeof (ag->acctbuf.ac_comm));
	ag->acctbuf.ac_btime = ua->u_start.tv_sec;
	ag->acctbuf.ac_utime = acct_compress(NSEC_TO_TICK(p->p_acct[LMS_USER]));
	ag->acctbuf.ac_stime = acct_compress(
	    NSEC_TO_TICK(p->p_acct[LMS_SYSTEM] + p->p_acct[LMS_TRAP]));
	ag->acctbuf.ac_etime = acct_compress(ddi_get_lbolt() - ua->u_ticks);
	ag->acctbuf.ac_mem = acct_compress((ulong_t)ua->u_mem);
	ag->acctbuf.ac_io = acct_compress((ulong_t)p->p_ru.ioch);
	ag->acctbuf.ac_rw = acct_compress((ulong_t)(p->p_ru.inblock +
	    p->p_ru.oublock));
	cr = CRED();
	ag->acctbuf.ac_uid = crgetruid(cr);
	ag->acctbuf.ac_gid = crgetrgid(cr);
	(void) cmpldev(&ag->acctbuf.ac_tty, cttydev(p));
	ag->acctbuf.ac_stat = st;
	ag->acctbuf.ac_flag = (ua->u_acflag | AEXPND);

	/*
	 * Save the size. If the write fails, reset the size to avoid
	 * corrupted acct files.
	 *
	 * Large Files: We deliberately prevent accounting files from
	 * exceeding the 2GB limit as none of the accounting commands are
	 * currently large file aware.
	 */
	va.va_mask = AT_SIZE;
	if (VOP_GETATTR(vp, &va, 0, kcred, NULL) == 0) {
		error = vn_rdwr(UIO_WRITE, vp, (caddr_t)&ag->acctbuf,
		    sizeof (ag->acctbuf), 0LL, UIO_SYSSPACE, FAPPEND,
		    (rlim64_t)MAXOFF32_T, kcred, &resid);
		if (error || resid)
			(void) VOP_SETATTR(vp, &va, 0, kcred, NULL);
	}
	mutex_exit(&ag->aclock);
}
