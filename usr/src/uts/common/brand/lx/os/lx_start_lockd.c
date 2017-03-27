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
 * Copyright 2017 Joyent, Inc.
 */

/*
 * Start an NFS lockd (lx_lockd) process inside the zone. This uses the same
 * technique as used in our lx cgroupfs to launch a release agent process.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/sysmacros.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/systm.h>
#include <sys/policy.h>
#include <sys/vmparam.h>
#include <sys/contract_impl.h>
#include <sys/pool.h>
#include <sys/stack.h>
#include <sys/var.h>
#include <sys/rt.h>
#include <sys/fx.h>
#include <sys/brand.h>
#include <sys/lx_brand.h>
#include <sys/pathname.h>

#define	LX_LOCKD_PATH	"/native/usr/lib/brand/lx/lx_lockd"

/*
 * Check if the current lockd is still running.
 */
static boolean_t
lx_lockd_alive(pid_t lockd_pid)
{
	boolean_t ret = B_FALSE;
	proc_t *p;
	vnode_t *vp;
	char path[MAXPATHLEN];

	mutex_enter(&pidlock);
	p = prfind(lockd_pid);
	if (p == NULL) {
		mutex_exit(&pidlock);
		return (B_FALSE);
	}

	mutex_enter(&p->p_lock);
	vp = p->p_exec;
	VN_HOLD(vp);
	mutex_exit(&p->p_lock);
	mutex_exit(&pidlock);

	if (vnodetopath(NULL, vp, path, sizeof (path), CRED()) == 0 &&
	    strcmp(path, LX_LOCKD_PATH) == 0) {
		ret = B_TRUE;
	}

	VN_RELE(vp);
	return (ret);
}

/* ARGSUSED */
static void
lx_run_lockd(void *a)
{
	proc_t *p = curproc;
	zone_t *z = curzone;
	struct core_globals *cg;
	lx_zone_data_t *lxzd = ztolxzd(z);
	int res;

	ASSERT(!INGLOBALZONE(p));
	VERIFY(lxzd != NULL);

	/* The following block is derived from start_init_common */
	ASSERT_STACK_ALIGNED();

	p->p_cstime = p->p_stime = p->p_cutime = p->p_utime = 0;
	p->p_usrstack = (caddr_t)USRSTACK32;
	p->p_model = DATAMODEL_ILP32;
	p->p_stkprot = PROT_ZFOD & ~PROT_EXEC;
	p->p_datprot = PROT_ZFOD & ~PROT_EXEC;
	p->p_stk_ctl = INT32_MAX;

	p->p_as = as_alloc();
	p->p_as->a_proc = p;
	p->p_as->a_userlimit = (caddr_t)USERLIMIT32;
	(void) hat_setup(p->p_as->a_hat, HAT_INIT);

	VERIFY((cg = zone_getspecific(core_zone_key, z)) != NULL);

	corectl_path_hold(cg->core_default_path);
	corectl_content_hold(cg->core_default_content);

	p->p_corefile = cg->core_default_path;
	p->p_content = cg->core_default_content;

	init_mstate(curthread, LMS_SYSTEM);
	res = exec_init(LX_LOCKD_PATH, NULL);

	/* End of code derived from start_init_common */

	/* The following is derived from zone_start_init - see comments there */
	if (res != 0 || zone_status_get(global_zone) >= ZONE_IS_SHUTTING_DOWN) {
		if (proc_exit(CLD_EXITED, res) != 0) {
			mutex_enter(&p->p_lock);
			ASSERT(p->p_flag & SEXITLWPS);
			lwp_exit();
		}
	} else {
		id_t cid = curthread->t_cid;

		mutex_enter(&class_lock);
		ASSERT(cid < loaded_classes);
		if (strcmp(sclass[cid].cl_name, "FX") == 0 &&
		    z->zone_fixed_hipri) {
			pcparms_t pcparms;

			pcparms.pc_cid = cid;
			((fxkparms_t *)pcparms.pc_clparms)->fx_upri = FXMAXUPRI;
			((fxkparms_t *)pcparms.pc_clparms)->fx_uprilim =
			    FXMAXUPRI;
			((fxkparms_t *)pcparms.pc_clparms)->fx_cflags =
			    FX_DOUPRILIM | FX_DOUPRI;

			mutex_enter(&pidlock);
			mutex_enter(&p->p_lock);
			(void) parmsset(&pcparms, curthread);
			mutex_exit(&p->p_lock);
			mutex_exit(&pidlock);
		} else if (strcmp(sclass[cid].cl_name, "RT") == 0) {
			curthread->t_pri = RTGPPRIO0;
		}
		mutex_exit(&class_lock);

		/*
		 * Set our pid as the lockd pid in the zone data, or exit
		 * if another process raced and already did so.
		 */
		mutex_enter(&lxzd->lxzd_lock);
		if (lxzd->lxzd_lockd_pid != 0) {
			/* another mount raced and created a new lockd */
			mutex_exit(&lxzd->lxzd_lock);
			if (proc_exit(CLD_EXITED, 0) != 0) {
				mutex_enter(&p->p_lock);
				ASSERT(p->p_flag & SEXITLWPS);
				lwp_exit();
			}
			return;
		}
		lxzd->lxzd_lockd_pid = p->p_pid;
		mutex_exit(&lxzd->lxzd_lock);

		/* cause the process to return to userland. */
		lwp_rtt();
	}
}

/*
 * Launch the user-level, native, lx_lockd process.
 */
int
lx_start_nfs_lockd()
{
	id_t cid;
	proc_t *p = ttoproc(curthread);
	zone_t *z = p->p_zone;
	lx_zone_data_t *lxzd = ztolxzd(z);

	ASSERT(!INGLOBALZONE(p));
	ASSERT(lxzd != NULL);

	/*
	 * This should only be called by the mount emulation, which must have
	 * 'root' privileges in order to have performed a mount, but
	 * double-check.
	 */
	if (crgetuid(CRED()) != 0)
		return (EPERM);

	mutex_enter(&lxzd->lxzd_lock);
	if (lxzd->lxzd_lockd_pid != 0) {
		/* verify lockd is still alive */
		pid_t lockd_pid;

		lockd_pid = lxzd->lxzd_lockd_pid;
		mutex_exit(&lxzd->lxzd_lock);

		if (lx_lockd_alive(lockd_pid))
			return (EEXIST);

		mutex_enter(&lxzd->lxzd_lock);
		if (lxzd->lxzd_lockd_pid != lockd_pid) {
			/* another mount raced and created a new lockd */
			mutex_exit(&lxzd->lxzd_lock);
			return (EEXIST);
		}

		/* old lockd is dead, launch a new one */
		lxzd->lxzd_lockd_pid = 0;
	}
	mutex_exit(&lxzd->lxzd_lock);

	if (z->zone_defaultcid > 0) {
		cid = z->zone_defaultcid;
	} else {
		pool_lock();
		cid = pool_get_class(z->zone_pool);
		pool_unlock();
	}
	if (cid == -1)
		cid = defaultcid;

	/*
	 * There's nothing to do here if creating the proc fails, but we
	 * return the result to make it obvious while DTracing.
	 */
	return (newproc(lx_run_lockd, NULL, cid, minclsyspri - 1, NULL, -1));
}
