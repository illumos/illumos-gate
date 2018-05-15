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
 * Copyright 2018 Joyent, Inc.
 */

/*
 * lx_start_nfs_lockd() starts an NFS lockd (lx_lockd) process inside the zone.
 * This uses the same technique as used in our lx cgroupfs to launch a release
 * agent process. This is called implicitly when an NFS mount syscall occurs
 * within the zone. See the user-level lx_lockd source for the "big theory"
 * comment behind this.
 *
 * lx_upcall_statd() is a brand hook that interposes on the rpc.statd RPC
 * handling so that we can interface to a Linux rpc.statd that must run
 * when NFSv3 locking is in use. The rpc.statd handles server or client reboots
 * and interacts with the lockd to reclaim locks after the server reboots. The
 * rcp.statd also informs the server when we reboot, so the server can release
 * the locks we held.
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
#include <rpcsvc/nlm_prot.h>
#include <rpcsvc/sm_inter.h>
#include <klm/nlm_impl.h>

#define	LX_LOCKD_PATH	"/native/usr/lib/brand/lx/lx_lockd"

/* Linux lockd RPC called by statd when it detects an NFS server reboot */
#define	LX_NLMPROC_NSM_NOTIFY	16

/* From uts/common/klm/nlm_impl.c */
extern void nlm_netbuf_to_netobj(struct netbuf *, int *, netobj *);
extern void nlm_nsm_clnt_init(CLIENT *, struct nlm_nsm *);

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
	if (p->p_stat == SZOMB || (p->p_flag & SEXITING) != 0) {
		mutex_exit(&p->p_lock);
		mutex_exit(&pidlock);
		return (B_FALSE);
	}
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

void
lx_upcall_statd(int op, struct nlm_globals *g, struct nlm_host *host)
{
	struct nlm_nsm *nsm;
	struct mon args;
	struct mon_id *mip = &args.mon_id;
	int family;
	netobj obj;
	enum clnt_stat stat;

	/*
	 * For Linux rpc.statd monitor registration, the Linux NSMPROC_MON and
	 * NSMPROC_UNMON RPC upcalls correspond almost directly to the native
	 * SM_MON and SM_UNMON RPC upcalls. The key differences with the native
	 * registration is that in our nlm_host_monitor function we make two
	 * RPC calls:
	 *    - the first RPC (nsmaddrproc1_reg_1) uses our private 'nsm_addr'
	 *	RPC protocol to register the lockd RPC information that statd
	 *	should call when it detects that the remote server rebooted
	 *    - the second RPC (sm_mon_1) tells statd the information about the
	 *	remote server to be monitored
	 * For Linux, there is only a single RPC from the kernel to the local
	 * statd. This RPC is equivalent to our sm_mon_1 code, but it uses the
	 * Linux-private NLMPROC_NSM_NOTIFY lockd procedure in the 'my_proc'
	 * RPC parameter. This corresponds to our private 'nsm_addr' code, and
	 * tells statd which lockd RPC to call when it detects a server reboot.
	 *
	 * Because our sm_mon_1 RPC is so similar to the Linux RPC, we can use
	 * that directly and simply set the expected value in the 'my_proc'
	 * argument.
	 *
	 * Within the kernel lockd RPC handling, the nlm_prog_3_dtable dispatch
	 * table has an entry for each lockd RPC function. Thus, this table also
	 * contains an entry for the Linux NLMPROC_NSM_NOTIFY procedure. That
	 * procedure number is unused by the native lockd code, so there is no
	 * conflict with dispatching that procedure. The implementation of the
	 * procedure corresponds to the native, private NLM_SM_NOTIFY1
	 * procedure which is called by the native rpc.statd.
	 *
	 * The Linux RPC call to "unmonitor" a host expects the same arguments
	 * as we pass to monitor, so that is also handled here by this same
	 * brand hook.
	 */
	nlm_netbuf_to_netobj(&host->nh_addr, &family, &obj);
	nsm = &g->nlm_nsm;

	bzero(&args, sizeof (args));

	mip->mon_name = host->nh_name;
	mip->my_id.my_name = uts_nodename();
	mip->my_id.my_prog = NLM_PROG;
	mip->my_id.my_vers = NLM_SM;
	mip->my_id.my_proc = LX_NLMPROC_NSM_NOTIFY;
	if (op == SM_MON) {
		bcopy(&host->nh_sysid, args.priv, sizeof (uint16_t));
	}

	sema_p(&nsm->ns_sem);
	nlm_nsm_clnt_init(nsm->ns_handle, nsm);
	if (op == SM_MON) {
		struct sm_stat_res mres;

		bzero(&mres, sizeof (mres));
		stat = sm_mon_1(&args, &mres, nsm->ns_handle);
	} else {
		struct sm_stat ures;

		ASSERT(op == SM_UNMON);
		bzero(&ures, sizeof (ures));
		stat = sm_unmon_1(mip, &ures, nsm->ns_handle);
	}
	sema_v(&nsm->ns_sem);

	if (stat != RPC_SUCCESS) {
		NLM_WARN("Failed to contact local statd, stat=%d", stat);
		if (op == SM_MON) {
			mutex_enter(&g->lock);
			host->nh_flags &= ~NLM_NH_MONITORED;
			mutex_exit(&g->lock);
		}
	}
}
