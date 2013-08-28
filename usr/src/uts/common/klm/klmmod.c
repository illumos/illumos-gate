/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy is of the CDDL is also available via the Internet
 * at http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2012 by Delphix. All rights reserved.
 */

/*
 * NFS Lock Manager, server-side and common.
 *
 * This file contains all the external entry points of klmmod.
 * Basically, this is the "glue" to the BSD nlm code.
 */

#include <sys/types.h>
#include <sys/errno.h>
#include <sys/modctl.h>
#include <sys/flock.h>

#include <nfs/nfs.h>
#include <nfs/nfssys.h>
#include <nfs/lm.h>
#include <rpcsvc/nlm_prot.h>
#include "nlm_impl.h"

static struct modlmisc modlmisc = {
	&mod_miscops, "lock mgr common module"
};

static struct modlinkage modlinkage = {
	MODREV_1, &modlmisc, NULL
};

/*
 * Cluster node ID.  Zero unless we're part of a cluster.
 * Set by lm_set_nlmid_flk.  Pass to lm_set_nlm_status.
 * We're not yet doing "clustered" NLM stuff.
 */
int lm_global_nlmid = 0;

/*
 * Call-back hook for clusters: Set lock manager status.
 * If this hook is set, call this instead of the ususal
 * flk_set_lockmgr_status(FLK_LOCKMGR_UP / DOWN);
 */
void (*lm_set_nlm_status)(int nlm_id, flk_nlm_status_t) = NULL;

/*
 * Call-back hook for clusters: Delete all locks held by sysid.
 * Call from code that drops all client locks (for which we're
 * the server) i.e. after the SM tells us a client has crashed.
 */
void (*lm_remove_file_locks)(int) = NULL;

krwlock_t		lm_lck;
zone_key_t		nlm_zone_key;

/*
 * Init/fini per-zone stuff for klm
 */
/* ARGSUSED */
void *
lm_zone_init(zoneid_t zoneid)
{
	struct nlm_globals *g;

	g = kmem_zalloc(sizeof (*g), KM_SLEEP);

	avl_create(&g->nlm_hosts_tree, nlm_host_cmp,
	    sizeof (struct nlm_host),
	    offsetof(struct nlm_host, nh_by_addr));

	g->nlm_hosts_hash = mod_hash_create_idhash("nlm_host_by_sysid",
	    64, mod_hash_null_valdtor);

	TAILQ_INIT(&g->nlm_idle_hosts);
	TAILQ_INIT(&g->nlm_slocks);

	mutex_init(&g->lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&g->nlm_gc_sched_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&g->nlm_gc_finish_cv, NULL, CV_DEFAULT, NULL);
	mutex_init(&g->clean_lock, NULL, MUTEX_DEFAULT, NULL);

	g->lockd_pid = 0;
	g->run_status = NLM_ST_DOWN;

	nlm_globals_register(g);
	return (g);
}

/* ARGSUSED */
void
lm_zone_fini(zoneid_t zoneid, void *data)
{
	struct nlm_globals *g = data;

	ASSERT(avl_is_empty(&g->nlm_hosts_tree));
	avl_destroy(&g->nlm_hosts_tree);
	mod_hash_destroy_idhash(g->nlm_hosts_hash);

	ASSERT(g->nlm_gc_thread == NULL);
	mutex_destroy(&g->lock);
	cv_destroy(&g->nlm_gc_sched_cv);
	cv_destroy(&g->nlm_gc_finish_cv);
	mutex_destroy(&g->clean_lock);

	nlm_globals_unregister(g);
	kmem_free(g, sizeof (*g));
}



/*
 * ****************************************************************
 * module init, fini, info
 */
int
_init()
{
	int retval;

	rw_init(&lm_lck, NULL, RW_DEFAULT, NULL);
	nlm_init();

	zone_key_create(&nlm_zone_key, lm_zone_init, NULL, lm_zone_fini);
	/* Per-zone lockmgr data.  See: os/flock.c */
	zone_key_create(&flock_zone_key, flk_zone_init, NULL, flk_zone_fini);

	retval = mod_install(&modlinkage);
	if (retval == 0)
		return (0);

	/*
	 * mod_install failed! undo above, reverse order
	 */

	(void) zone_key_delete(flock_zone_key);
	flock_zone_key = ZONE_KEY_UNINITIALIZED;
	(void) zone_key_delete(nlm_zone_key);
	rw_destroy(&lm_lck);

	return (retval);
}

int
_fini()
{
	/* Don't unload. */
	return (EBUSY);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}



/*
 * ****************************************************************
 * Stubs listed in modstubs.s
 */

/*
 * klm system calls.  Start service on some endpoint.
 * Called by nfssys() LM_SVC, from lockd.
 */
int
lm_svc(struct lm_svc_args *args)
{
	struct knetconfig knc;
	const char *netid;
	struct nlm_globals *g;
	struct file *fp = NULL;
	int err = 0;

	/* Get our "globals" */
	g = zone_getspecific(nlm_zone_key, curzone);

	/*
	 * Check version of lockd calling.
	 */
	if (args->version != LM_SVC_CUR_VERS) {
		NLM_ERR("lm_svc: Version mismatch "
		    "(given 0x%x, expected 0x%x)\n",
		    args->version, LM_SVC_CUR_VERS);
		return (EINVAL);
	}

	/*
	 * Build knetconfig, checking arg values.
	 * Also come up with the "netid" string.
	 * (With some knowledge of /etc/netconfig)
	 */
	bzero(&knc, sizeof (knc));
	switch (args->n_proto) {
	case LM_TCP:
		knc.knc_semantics = NC_TPI_COTS_ORD;
		knc.knc_proto = NC_TCP;
		break;
	case LM_UDP:
		knc.knc_semantics = NC_TPI_CLTS;
		knc.knc_proto = NC_UDP;
		break;
	default:
		NLM_ERR("nlm_build_knetconfig: Unknown "
		    "lm_proto=0x%x\n", args->n_proto);
		return (EINVAL);
	}

	switch (args->n_fmly) {
	case LM_INET:
		knc.knc_protofmly = NC_INET;
		break;
	case LM_INET6:
		knc.knc_protofmly = NC_INET6;
		break;
	case LM_LOOPBACK:
		knc.knc_protofmly = NC_LOOPBACK;
		/* Override what we set above. */
		knc.knc_proto = NC_NOPROTO;
		break;
	default:
		NLM_ERR("nlm_build_knetconfig: Unknown "
		    "lm_fmly=0x%x\n", args->n_fmly);
		return (EINVAL);
	}

	knc.knc_rdev = args->n_rdev;
	netid = nlm_knc_to_netid(&knc);
	if (!netid)
		return (EINVAL);

	/*
	 * Setup service on the passed transport.
	 * NB: must releasef(fp) after this.
	 */
	if ((fp = getf(args->fd)) == NULL)
		return (EBADF);

	mutex_enter(&g->lock);
	/*
	 * Don't try to start while still shutting down,
	 * or lots of things will fail...
	 */
	if (g->run_status == NLM_ST_STOPPING) {
		err = EAGAIN;
		goto out;
	}

	/*
	 * There is no separate "initialize" sub-call for nfssys,
	 * and we want to do some one-time work when the first
	 * binding comes in from lockd.
	 */
	if (g->run_status == NLM_ST_DOWN) {
		g->run_status = NLM_ST_STARTING;
		g->lockd_pid = curproc->p_pid;

		/* Save the options. */
		g->cn_idle_tmo = args->timout;
		g->grace_period = args->grace;
		g->retrans_tmo = args->retransmittimeout;

		/* See nfs_sys.c (not yet per-zone) */
		if (INGLOBALZONE(curproc)) {
			rfs4_grace_period = args->grace;
			rfs4_lease_time   = args->grace;
		}

		mutex_exit(&g->lock);
		err = nlm_svc_starting(g, fp, netid, &knc);
		mutex_enter(&g->lock);
	} else {
		/*
		 * If KLM is not started and the very first endpoint lockd
		 * tries to add is not a loopback device, report an error.
		 */
		if (g->run_status != NLM_ST_UP) {
			err = ENOTACTIVE;
			goto out;
		}
		if (g->lockd_pid != curproc->p_pid) {
			/* Check if caller has the same PID lockd does */
			err = EPERM;
			goto out;
		}

		err = nlm_svc_add_ep(fp, netid, &knc);
	}

out:
	mutex_exit(&g->lock);
	if (fp != NULL)
		releasef(args->fd);

	return (err);
}

/*
 * klm system calls.  Kill the lock manager.
 * Called by nfssys() KILL_LOCKMGR,
 * liblm:lm_shutdown() <- unused?
 */
int
lm_shutdown(void)
{
	struct nlm_globals *g;
	proc_t *p;
	pid_t pid;

	/* Get our "globals" */
	g = zone_getspecific(nlm_zone_key, curzone);

	mutex_enter(&g->lock);
	if (g->run_status != NLM_ST_UP) {
		mutex_exit(&g->lock);
		return (EBUSY);
	}

	g->run_status = NLM_ST_STOPPING;
	pid = g->lockd_pid;
	mutex_exit(&g->lock);
	nlm_svc_stopping(g);

	mutex_enter(&pidlock);
	p = prfind(pid);
	if (p != NULL)
		psignal(p, SIGTERM);

	mutex_exit(&pidlock);
	return (0);
}

/*
 * Cleanup remote locks on FS un-export.
 *
 * NOTE: called from nfs_export.c:unexport()
 * right before the share is going to
 * be unexported.
 */
void
lm_unexport(struct exportinfo *exi)
{
	nlm_unexport(exi);
}

/*
 * CPR suspend/resume hooks.
 * See:cpr_suspend, cpr_resume
 *
 * Before suspend, get current state from "statd" on
 * all remote systems for which we have locks.
 *
 * After resume, check with those systems again,
 * and either reclaim locks, or do SIGLOST.
 */
void
lm_cprsuspend(void)
{
	nlm_cprsuspend();
}

void
lm_cprresume(void)
{
	nlm_cprresume();
}

/*
 * Add the nlm_id bits to the sysid (by ref).
 */
void
lm_set_nlmid_flk(int *new_sysid)
{
	if (lm_global_nlmid != 0)
		*new_sysid |= (lm_global_nlmid << BITS_IN_SYSID);
}

/*
 * It seems that closed source klmmod used
 * this function to release knetconfig stored
 * in mntinfo structure (see mntinfo's mi_klmconfig
 * field).
 * We store knetconfigs differently, thus we don't
 * need this function.
 */
void
lm_free_config(struct knetconfig *knc)
{
	_NOTE(ARGUNUSED(knc));
}

/*
 * Called by NFS4 delegation code to check if there are any
 * NFSv2/v3 locks for the file, so it should not delegate.
 *
 * NOTE: called from NFSv4 code
 * (see nfs4_srv_deleg.c:rfs4_bgrant_delegation())
 */
int
lm_vp_active(const vnode_t *vp)
{
	return (nlm_vp_active(vp));
}

/*
 * Find or create a "sysid" for given knc+addr.
 * name is optional.  Sets nc_changed if the
 * found knc_proto is different from passed.
 * Increments the reference count.
 *
 * Called internally, and in nfs4_find_sysid()
 */
struct lm_sysid *
lm_get_sysid(struct knetconfig *knc, struct netbuf *addr,
    char *name, bool_t *nc_changed)
{
	struct nlm_globals *g;
	const char *netid;
	struct nlm_host *hostp;

	_NOTE(ARGUNUSED(nc_changed));
	netid = nlm_knc_to_netid(knc);
	if (netid == NULL)
		return (NULL);

	g = zone_getspecific(nlm_zone_key, curzone);

	hostp = nlm_host_findcreate(g, name, netid, addr);
	if (hostp == NULL)
		return (NULL);

	return ((struct lm_sysid *)hostp);
}

/*
 * Release a reference on a "sysid".
 */
void
lm_rel_sysid(struct lm_sysid *sysid)
{
	struct nlm_globals *g;

	g = zone_getspecific(nlm_zone_key, curzone);
	nlm_host_release(g, (struct nlm_host *)sysid);
}

/*
 * Alloc/free a sysid_t (a unique number between
 * LM_SYSID and LM_SYSID_MAX).
 *
 * Used by NFSv4 rfs4_op_lockt and smbsrv/smb_fsop_frlock,
 * both to represent non-local locks outside of klm.
 *
 * NOTE: called from NFSv4 and SMBFS to allocate unique
 * sysid.
 */
sysid_t
lm_alloc_sysidt(void)
{
	return (nlm_sysid_alloc());
}

void
lm_free_sysidt(sysid_t sysid)
{
	nlm_sysid_free(sysid);
}

/* Access private member lms->sysid */
sysid_t
lm_sysidt(struct lm_sysid *lms)
{
	return (((struct nlm_host *)lms)->nh_sysid);
}

/*
 * Called by nfs_frlock to check lock constraints.
 * Return non-zero if the lock request is "safe", i.e.
 * the range is not mapped, not MANDLOCK, etc.
 *
 * NOTE: callde from NFSv3/NFSv2 frlock() functions to
 * determine whether it's safe to add new lock.
 */
int
lm_safelock(vnode_t *vp, const struct flock64 *fl, cred_t *cr)
{
	return (nlm_safelock(vp, fl, cr));
}

/*
 * Called by nfs_lockcompletion to check whether it's "safe"
 * to map the file (and cache it's data).  Walks the list of
 * file locks looking for any that are not "whole file".
 *
 * NOTE: called from nfs_client.c:nfs_lockcompletion()
 */
int
lm_safemap(const vnode_t *vp)
{
	return (nlm_safemap(vp));
}

/*
 * Called by nfs_map() for the MANDLOCK case.
 * Return non-zero if the file has any locks with a
 * blocked request (sleep).
 *
 * NOTE: called from NFSv3/NFSv2 map() functions in
 * order to determine whether it's safe to add new
 * mapping.
 */
int
lm_has_sleep(const vnode_t *vp)
{
	return (nlm_has_sleep(vp));
}

/*
 * ****************************************************************
 * Stuff needed by klmops?
 */
