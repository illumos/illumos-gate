/*
 * Copyright (c) 2008 Isilon Inc http://www.isilon.com/
 * Authors: Doug Rabson <dfr@rabson.org>
 * Developed with Red Inc: Alfred Perlstein <alfred@freebsd.org>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

/*
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2012 by Delphix. All rights reserved.
 */

/*
 * NFS LockManager, start/stop, support functions, etc.
 * Most of the interesting code is here.
 *
 * Source code derived from FreeBSD nlm_prot_impl.c
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/thread.h>
#include <sys/fcntl.h>
#include <sys/flock.h>
#include <sys/mount.h>
#include <sys/priv.h>
#include <sys/proc.h>
#include <sys/share.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/syslog.h>
#include <sys/systm.h>
#include <sys/class.h>
#include <sys/unistd.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/queue.h>
#include <sys/bitmap.h>
#include <sys/sdt.h>
#include <netinet/in.h>

#include <rpc/rpc.h>
#include <rpc/xdr.h>
#include <rpc/pmap_prot.h>
#include <rpc/pmap_clnt.h>
#include <rpc/rpcb_prot.h>

#include <rpcsvc/nlm_prot.h>
#include <rpcsvc/sm_inter.h>
#include <rpcsvc/nsm_addr.h>

#include <nfs/nfs.h>
#include <nfs/nfs_clnt.h>
#include <nfs/export.h>
#include <nfs/rnode.h>
#include <nfs/lm.h>

#include "nlm_impl.h"

struct nlm_knc {
	struct knetconfig	n_knc;
	const char		*n_netid;
};

/*
 * Number of attempts NLM tries to obtain RPC binding
 * of local statd.
 */
#define	NLM_NSM_RPCBIND_RETRIES 10

/*
 * Timeout (in seconds) NLM waits before making another
 * attempt to obtain RPC binding of local statd.
 */
#define	NLM_NSM_RPCBIND_TIMEOUT 5

/*
 * Total number of sysids in NLM sysid bitmap
 */
#define	NLM_BMAP_NITEMS	(LM_SYSID_MAX + 1)

/*
 * Number of ulong_t words in bitmap that is used
 * for allocation of sysid numbers.
 */
#define	NLM_BMAP_WORDS  (NLM_BMAP_NITEMS / BT_NBIPUL)

/*
 * Given an integer x, the macro returns
 * -1 if x is negative,
 *  0 if x is zero
 *  1 if x is positive
 */
#define	SIGN(x) (((x) > 0) - ((x) < 0))

#define	ARRSIZE(arr)	(sizeof (arr) / sizeof ((arr)[0]))
#define	NLM_KNCS	ARRSIZE(nlm_netconfigs)

krwlock_t lm_lck;

/*
 * Zero timeout for asynchronous NLM RPC operations
 */
static const struct timeval nlm_rpctv_zero = { 0,  0 };

/*
 * List of all Zone globals nlm_globals instences
 * linked together.
 */
static struct nlm_globals_list nlm_zones_list; /* (g) */

/*
 * NLM kmem caches
 */
static struct kmem_cache *nlm_hosts_cache = NULL;
static struct kmem_cache *nlm_vhold_cache = NULL;

/*
 * A bitmap for allocation of new sysids.
 * Sysid is a unique number between LM_SYSID
 * and LM_SYSID_MAX. Sysid represents unique remote
 * host that does file locks on the given host.
 */
static ulong_t	nlm_sysid_bmap[NLM_BMAP_WORDS];	/* (g) */
static int	nlm_sysid_nidx;			/* (g) */

/*
 * RPC service registration for all transports
 */
static SVC_CALLOUT nlm_svcs[] = {
	{ NLM_PROG, 4, 4, nlm_prog_4 },	/* NLM4_VERS */
	{ NLM_PROG, 1, 3, nlm_prog_3 }	/* NLM_VERS - NLM_VERSX */
};

static SVC_CALLOUT_TABLE nlm_sct = {
	ARRSIZE(nlm_svcs),
	FALSE,
	nlm_svcs
};

/*
 * Static table of all netid/knetconfig network
 * lock manager can work with. nlm_netconfigs table
 * is used when we need to get valid knetconfig by
 * netid and vice versa.
 *
 * Knetconfigs are activated either by the call from
 * user-space lockd daemon (server side) or by taking
 * knetconfig from NFS mountinfo (client side)
 */
static struct nlm_knc nlm_netconfigs[] = { /* (g) */
	/* UDP */
	{
		{ NC_TPI_CLTS, NC_INET, NC_UDP, NODEV },
		"udp",
	},
	/* TCP */
	{
		{ NC_TPI_COTS_ORD, NC_INET, NC_TCP, NODEV },
		"tcp",
	},
	/* UDP over IPv6 */
	{
		{ NC_TPI_CLTS, NC_INET6, NC_UDP, NODEV },
		"udp6",
	},
	/* TCP over IPv6 */
	{
		{ NC_TPI_COTS_ORD, NC_INET6, NC_TCP, NODEV },
		"tcp6",
	},
	/* ticlts (loopback over UDP) */
	{
		{ NC_TPI_CLTS, NC_LOOPBACK, NC_NOPROTO, NODEV },
		"ticlts",
	},
	/* ticotsord (loopback over TCP) */
	{
		{ NC_TPI_COTS_ORD, NC_LOOPBACK, NC_NOPROTO, NODEV },
		"ticotsord",
	},
};

/*
 * NLM misc. function
 */
static void nlm_copy_netbuf(struct netbuf *, struct netbuf *);
static int nlm_netbuf_addrs_cmp(struct netbuf *, struct netbuf *);
static void nlm_kmem_reclaim(void *);
static void nlm_pool_shutdown(void);
static void nlm_suspend_zone(struct nlm_globals *);
static void nlm_resume_zone(struct nlm_globals *);
static void nlm_nsm_clnt_init(CLIENT *, struct nlm_nsm *);
static void nlm_netbuf_to_netobj(struct netbuf *, int *, netobj *);

/*
 * NLM thread functions
 */
static void nlm_gc(struct nlm_globals *);
static void nlm_reclaimer(struct nlm_host *);

/*
 * NLM NSM functions
 */
static int nlm_init_local_knc(struct knetconfig *);
static int nlm_nsm_init_local(struct nlm_nsm *);
static int nlm_nsm_init(struct nlm_nsm *, struct knetconfig *, struct netbuf *);
static void nlm_nsm_fini(struct nlm_nsm *);
static enum clnt_stat nlm_nsm_simu_crash(struct nlm_nsm *);
static enum clnt_stat nlm_nsm_stat(struct nlm_nsm *, int32_t *);
static enum clnt_stat nlm_nsm_mon(struct nlm_nsm *, char *, uint16_t);
static enum clnt_stat nlm_nsm_unmon(struct nlm_nsm *, char *);

/*
 * NLM host functions
 */
static int nlm_host_ctor(void *, void *, int);
static void nlm_host_dtor(void *, void *);
static void nlm_host_destroy(struct nlm_host *);
static struct nlm_host *nlm_host_create(char *, const char *,
    struct knetconfig *, struct netbuf *);
static struct nlm_host *nlm_host_find_locked(struct nlm_globals *,
    const char *, struct netbuf *, avl_index_t *);
static void nlm_host_unregister(struct nlm_globals *, struct nlm_host *);
static void nlm_host_gc_vholds(struct nlm_host *);
static bool_t nlm_host_has_srv_locks(struct nlm_host *);
static bool_t nlm_host_has_cli_locks(struct nlm_host *);
static bool_t nlm_host_has_locks(struct nlm_host *);

/*
 * NLM vhold functions
 */
static int nlm_vhold_ctor(void *, void *, int);
static void nlm_vhold_dtor(void *, void *);
static void nlm_vhold_destroy(struct nlm_host *,
    struct nlm_vhold *);
static bool_t nlm_vhold_busy(struct nlm_host *, struct nlm_vhold *);
static void nlm_vhold_clean(struct nlm_vhold *, int);

/*
 * NLM client/server sleeping locks/share reservation functions
 */
struct nlm_slreq *nlm_slreq_find_locked(struct nlm_host *,
    struct nlm_vhold *, struct flock64 *);
static struct nlm_shres *nlm_shres_create_item(struct shrlock *, vnode_t *);
static void nlm_shres_destroy_item(struct nlm_shres *);
static bool_t nlm_shres_equal(struct shrlock *, struct shrlock *);

/*
 * NLM initialization functions.
 */
void
nlm_init(void)
{
	nlm_hosts_cache = kmem_cache_create("nlm_host_cache",
	    sizeof (struct nlm_host), 0, nlm_host_ctor, nlm_host_dtor,
	    nlm_kmem_reclaim, NULL, NULL, 0);

	nlm_vhold_cache = kmem_cache_create("nlm_vhold_cache",
	    sizeof (struct nlm_vhold), 0, nlm_vhold_ctor, nlm_vhold_dtor,
	    NULL, NULL, NULL, 0);

	nlm_rpc_init();
	TAILQ_INIT(&nlm_zones_list);

	/* initialize sysids bitmap */
	bzero(nlm_sysid_bmap, sizeof (nlm_sysid_bmap));
	nlm_sysid_nidx = 1;

	/*
	 * Reserv the sysid #0, because it's associated
	 * with local locks only. Don't let to allocate
	 * it for remote locks.
	 */
	BT_SET(nlm_sysid_bmap, 0);
}

void
nlm_globals_register(struct nlm_globals *g)
{
	rw_enter(&lm_lck, RW_WRITER);
	TAILQ_INSERT_TAIL(&nlm_zones_list, g, nlm_link);
	rw_exit(&lm_lck);
}

void
nlm_globals_unregister(struct nlm_globals *g)
{
	rw_enter(&lm_lck, RW_WRITER);
	TAILQ_REMOVE(&nlm_zones_list, g, nlm_link);
	rw_exit(&lm_lck);
}

/* ARGSUSED */
static void
nlm_kmem_reclaim(void *cdrarg)
{
	struct nlm_globals *g;

	rw_enter(&lm_lck, RW_READER);
	TAILQ_FOREACH(g, &nlm_zones_list, nlm_link)
		cv_broadcast(&g->nlm_gc_sched_cv);

	rw_exit(&lm_lck);
}

/*
 * NLM garbage collector thread (GC).
 *
 * NLM GC periodically checks whether there're any host objects
 * that can be cleaned up. It also releases stale vnodes that
 * live on the server side (under protection of vhold objects).
 *
 * NLM host objects are cleaned up from GC thread because
 * operations helping us to determine whether given host has
 * any locks can be quite expensive and it's not good to call
 * them every time the very last reference to the host is dropped.
 * Thus we use "lazy" approach for hosts cleanup.
 *
 * The work of GC is to release stale vnodes on the server side
 * and destroy hosts that haven't any locks and any activity for
 * some time (i.e. idle hosts).
 */
static void
nlm_gc(struct nlm_globals *g)
{
	struct nlm_host *hostp;
	clock_t now, idle_period;

	idle_period = SEC_TO_TICK(g->cn_idle_tmo);
	mutex_enter(&g->lock);
	for (;;) {
		/*
		 * GC thread can be explicitly scheduled from
		 * memory reclamation function.
		 */
		(void) cv_timedwait(&g->nlm_gc_sched_cv, &g->lock,
		    ddi_get_lbolt() + idle_period);

		/*
		 * NLM is shutting down, time to die.
		 */
		if (g->run_status == NLM_ST_STOPPING)
			break;

		now = ddi_get_lbolt();
		DTRACE_PROBE2(gc__start, struct nlm_globals *, g,
		    clock_t, now);

		/*
		 * Find all obviously unused vholds and destroy them.
		 */
		for (hostp = avl_first(&g->nlm_hosts_tree); hostp != NULL;
		    hostp = AVL_NEXT(&g->nlm_hosts_tree, hostp)) {
			struct nlm_vhold *nvp;

			mutex_enter(&hostp->nh_lock);

			nvp = TAILQ_FIRST(&hostp->nh_vholds_list);
			while (nvp != NULL) {
				struct nlm_vhold *new_nvp;

				new_nvp = TAILQ_NEXT(nvp, nv_link);

				/*
				 * If these conditions are met, the vhold is
				 * obviously unused and we will destroy it.  In
				 * a case either v_filocks and/or v_shrlocks is
				 * non-NULL the vhold might still be unused by
				 * the host, but it is expensive to check that.
				 * We defer such check until the host is idle.
				 * The expensive check is done below without
				 * the global lock held.
				 */
				if (nvp->nv_refcnt == 0 &&
				    nvp->nv_vp->v_filocks == NULL &&
				    nvp->nv_vp->v_shrlocks == NULL) {
					nlm_vhold_destroy(hostp, nvp);
				}

				nvp = new_nvp;
			}

			mutex_exit(&hostp->nh_lock);
		}

		/*
		 * Handle all hosts that are unused at the moment
		 * until we meet one with idle timeout in future.
		 */
		while ((hostp = TAILQ_FIRST(&g->nlm_idle_hosts)) != NULL) {
			bool_t has_locks;

			if (hostp->nh_idle_timeout > now)
				break;

			/*
			 * Drop global lock while doing expensive work
			 * on this host. We'll re-check any conditions
			 * that might change after retaking the global
			 * lock.
			 */
			mutex_exit(&g->lock);
			mutex_enter(&hostp->nh_lock);

			/*
			 * nlm_globals lock was dropped earlier because
			 * garbage collecting of vholds and checking whether
			 * host has any locks/shares are expensive operations.
			 */
			nlm_host_gc_vholds(hostp);
			has_locks = nlm_host_has_locks(hostp);

			mutex_exit(&hostp->nh_lock);
			mutex_enter(&g->lock);

			/*
			 * While we were doing expensive operations
			 * outside of nlm_globals critical section,
			 * somebody could take the host and remove it
			 * from the idle list.  Whether its been
			 * reinserted or not, our information about
			 * the host is outdated, and we should take no
			 * further action.
			 */
			if ((hostp->nh_flags & NLM_NH_INIDLE) == 0 ||
			    hostp->nh_idle_timeout > now)
				continue;

			/*
			 * If the host has locks we have to renew the
			 * host's timeout and put it at the end of LRU
			 * list.
			 */
			if (has_locks) {
				TAILQ_REMOVE(&g->nlm_idle_hosts,
				    hostp, nh_link);
				hostp->nh_idle_timeout = now + idle_period;
				TAILQ_INSERT_TAIL(&g->nlm_idle_hosts,
				    hostp, nh_link);
				continue;
			}

			/*
			 * We're here if all the following conditions hold:
			 * 1) Host hasn't any locks or share reservations
			 * 2) Host is unused
			 * 3) Host wasn't touched by anyone at least for
			 *    g->cn_idle_tmo seconds.
			 *
			 * So, now we can destroy it.
			 */
			nlm_host_unregister(g, hostp);
			mutex_exit(&g->lock);

			nlm_host_unmonitor(g, hostp);
			nlm_host_destroy(hostp);
			mutex_enter(&g->lock);
			if (g->run_status == NLM_ST_STOPPING)
				break;

		}

		DTRACE_PROBE(gc__end);
	}

	DTRACE_PROBE1(gc__exit, struct nlm_globals *, g);

	/* Let others know that GC has died */
	g->nlm_gc_thread = NULL;
	mutex_exit(&g->lock);

	cv_broadcast(&g->nlm_gc_finish_cv);
	zthread_exit();
}

/*
 * Thread reclaim locks/shares acquired by the client side
 * on the given server represented by hostp.
 */
static void
nlm_reclaimer(struct nlm_host *hostp)
{
	struct nlm_globals *g;

	mutex_enter(&hostp->nh_lock);
	hostp->nh_reclaimer = curthread;
	mutex_exit(&hostp->nh_lock);

	g = zone_getspecific(nlm_zone_key, curzone);
	nlm_reclaim_client(g, hostp);

	mutex_enter(&hostp->nh_lock);
	hostp->nh_flags &= ~NLM_NH_RECLAIM;
	hostp->nh_reclaimer = NULL;
	cv_broadcast(&hostp->nh_recl_cv);
	mutex_exit(&hostp->nh_lock);

	/*
	 * Host was explicitly referenced before
	 * nlm_reclaim() was called, release it
	 * here.
	 */
	nlm_host_release(g, hostp);
	zthread_exit();
}

/*
 * Copy a struct netobj.  (see xdr.h)
 */
void
nlm_copy_netobj(struct netobj *dst, struct netobj *src)
{
	dst->n_len = src->n_len;
	dst->n_bytes = kmem_alloc(src->n_len, KM_SLEEP);
	bcopy(src->n_bytes, dst->n_bytes, src->n_len);
}

/*
 * An NLM specificw replacement for clnt_call().
 * nlm_clnt_call() is used by all RPC functions generated
 * from nlm_prot.x specification. The function is aware
 * about some pitfalls of NLM RPC procedures and has a logic
 * that handles them properly.
 */
enum clnt_stat
nlm_clnt_call(CLIENT *clnt, rpcproc_t procnum, xdrproc_t xdr_args,
    caddr_t argsp, xdrproc_t xdr_result, caddr_t resultp, struct timeval wait)
{
	k_sigset_t oldmask;
	enum clnt_stat stat;
	bool_t sig_blocked = FALSE;

	/*
	 * If NLM RPC procnum is one of the NLM _RES procedures
	 * that are used to reply to asynchronous NLM RPC
	 * (MSG calls), explicitly set RPC timeout to zero.
	 * Client doesn't send a reply to RES procedures, so
	 * we don't need to wait anything.
	 *
	 * NOTE: we ignore NLM4_*_RES procnums because they are
	 * equal to NLM_*_RES numbers.
	 */
	if (procnum >= NLM_TEST_RES && procnum <= NLM_GRANTED_RES)
		wait = nlm_rpctv_zero;

	/*
	 * We need to block signals in case of NLM_CANCEL RPC
	 * in order to prevent interruption of network RPC
	 * calls.
	 */
	if (procnum == NLM_CANCEL) {
		k_sigset_t newmask;

		sigfillset(&newmask);
		sigreplace(&newmask, &oldmask);
		sig_blocked = TRUE;
	}

	stat = clnt_call(clnt, procnum, xdr_args,
	    argsp, xdr_result, resultp, wait);

	/*
	 * Restore signal mask back if signals were blocked
	 */
	if (sig_blocked)
		sigreplace(&oldmask, (k_sigset_t *)NULL);

	return (stat);
}

/*
 * Suspend NLM client/server in the given zone.
 *
 * During suspend operation we mark those hosts
 * that have any locks with NLM_NH_SUSPEND flags,
 * so that they can be checked later, when resume
 * operation occurs.
 */
static void
nlm_suspend_zone(struct nlm_globals *g)
{
	struct nlm_host *hostp;
	struct nlm_host_list all_hosts;

	/*
	 * Note that while we're doing suspend, GC thread is active
	 * and it can destroy some hosts while we're walking through
	 * the hosts tree. To prevent that and make suspend logic
	 * a bit more simple we put all hosts to local "all_hosts"
	 * list and increment reference counter of each host.
	 * This guaranties that no hosts will be released while
	 * we're doing suspend.
	 * NOTE: reference of each host must be dropped during
	 * resume operation.
	 */
	TAILQ_INIT(&all_hosts);
	mutex_enter(&g->lock);
	for (hostp = avl_first(&g->nlm_hosts_tree); hostp != NULL;
	    hostp = AVL_NEXT(&g->nlm_hosts_tree, hostp)) {
		/*
		 * If host is idle, remove it from idle list and
		 * clear idle flag. That is done to prevent GC
		 * from touching this host.
		 */
		if (hostp->nh_flags & NLM_NH_INIDLE) {
			TAILQ_REMOVE(&g->nlm_idle_hosts, hostp, nh_link);
			hostp->nh_flags &= ~NLM_NH_INIDLE;
		}

		hostp->nh_refs++;
		TAILQ_INSERT_TAIL(&all_hosts, hostp, nh_link);
	}

	/*
	 * Now we can walk through all hosts on the system
	 * with zone globals lock released. The fact the
	 * we have taken a reference to each host guaranties
	 * that no hosts can be destroyed during that process.
	 */
	mutex_exit(&g->lock);
	while ((hostp = TAILQ_FIRST(&all_hosts)) != NULL) {
		mutex_enter(&hostp->nh_lock);
		if (nlm_host_has_locks(hostp))
			hostp->nh_flags |= NLM_NH_SUSPEND;

		mutex_exit(&hostp->nh_lock);
		TAILQ_REMOVE(&all_hosts, hostp, nh_link);
	}
}

/*
 * Resume NLM hosts for the given zone.
 *
 * nlm_resume_zone() is called after hosts were suspended
 * (see nlm_suspend_zone) and its main purpose to check
 * whether remote locks owned by hosts are still in consistent
 * state. If they aren't, resume function tries to reclaim
 * locks (for client side hosts) and clean locks (for
 * server side hosts).
 */
static void
nlm_resume_zone(struct nlm_globals *g)
{
	struct nlm_host *hostp, *h_next;

	mutex_enter(&g->lock);
	hostp = avl_first(&g->nlm_hosts_tree);

	/*
	 * In nlm_suspend_zone() the reference counter of each
	 * host was incremented, so we can safely iterate through
	 * all hosts without worrying that any host we touch will
	 * be removed at the moment.
	 */
	while (hostp != NULL) {
		struct nlm_nsm nsm;
		enum clnt_stat stat;
		int32_t sm_state;
		int error;
		bool_t resume_failed = FALSE;

		h_next = AVL_NEXT(&g->nlm_hosts_tree, hostp);
		mutex_exit(&g->lock);

		DTRACE_PROBE1(resume__host, struct nlm_host *, hostp);

		/*
		 * Suspend operation marked that the host doesn't
		 * have any locks. Skip it.
		 */
		if (!(hostp->nh_flags & NLM_NH_SUSPEND))
			goto cycle_end;

		error = nlm_nsm_init(&nsm, &hostp->nh_knc, &hostp->nh_addr);
		if (error != 0) {
			NLM_ERR("Resume: Failed to contact to NSM of host %s "
			    "[error=%d]\n", hostp->nh_name, error);
			resume_failed = TRUE;
			goto cycle_end;
		}

		stat = nlm_nsm_stat(&nsm, &sm_state);
		if (stat != RPC_SUCCESS) {
			NLM_ERR("Resume: Failed to call SM_STAT operation for "
			    "host %s [stat=%d]\n", hostp->nh_name, stat);
			resume_failed = TRUE;
			nlm_nsm_fini(&nsm);
			goto cycle_end;
		}

		if (sm_state != hostp->nh_state) {
			/*
			 * Current SM state of the host isn't equal
			 * to the one host had when it was suspended.
			 * Probably it was rebooted. Try to reclaim
			 * locks if the host has any on its client side.
			 * Also try to clean up its server side locks
			 * (if the host has any).
			 */
			nlm_host_notify_client(hostp, sm_state);
			nlm_host_notify_server(hostp, sm_state);
		}

		nlm_nsm_fini(&nsm);

cycle_end:
		if (resume_failed) {
			/*
			 * Resume failed for the given host.
			 * Just clean up all resources it owns.
			 */
			nlm_host_notify_server(hostp, 0);
			nlm_client_cancel_all(g, hostp);
		}

		hostp->nh_flags &= ~NLM_NH_SUSPEND;
		nlm_host_release(g, hostp);
		hostp = h_next;
		mutex_enter(&g->lock);
	}

	mutex_exit(&g->lock);
}

/*
 * NLM functions responsible for operations on NSM handle.
 */

/*
 * Initialize knetconfig that is used for communication
 * with local statd via loopback interface.
 */
static int
nlm_init_local_knc(struct knetconfig *knc)
{
	int error;
	vnode_t *vp;

	bzero(knc, sizeof (*knc));
	error = lookupname("/dev/tcp", UIO_SYSSPACE,
	    FOLLOW, NULLVPP, &vp);
	if (error != 0)
		return (error);

	knc->knc_semantics = NC_TPI_COTS;
	knc->knc_protofmly = NC_INET;
	knc->knc_proto = NC_TCP;
	knc->knc_rdev = vp->v_rdev;
	VN_RELE(vp);


	return (0);
}

/*
 * Initialize NSM handle that will be used to talk
 * to local statd via loopback interface.
 */
static int
nlm_nsm_init_local(struct nlm_nsm *nsm)
{
	int error;
	struct knetconfig knc;
	struct sockaddr_in sin;
	struct netbuf nb;

	error = nlm_init_local_knc(&knc);
	if (error != 0)
		return (error);

	bzero(&sin, sizeof (sin));
	sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sin.sin_family = AF_INET;

	nb.buf = (char *)&sin;
	nb.len = nb.maxlen = sizeof (sin);

	return (nlm_nsm_init(nsm, &knc, &nb));
}

/*
 * Initialize NSM handle used for talking to statd
 */
static int
nlm_nsm_init(struct nlm_nsm *nsm, struct knetconfig *knc, struct netbuf *nb)
{
	enum clnt_stat stat;
	int error, retries;

	bzero(nsm, sizeof (*nsm));
	nsm->ns_knc = *knc;
	nlm_copy_netbuf(&nsm->ns_addr, nb);

	/*
	 * Try several times to get the port of statd service,
	 * If rpcbind_getaddr returns  RPC_PROGNOTREGISTERED,
	 * retry an attempt, but wait for NLM_NSM_RPCBIND_TIMEOUT
	 * seconds berofore.
	 */
	for (retries = 0; retries < NLM_NSM_RPCBIND_RETRIES; retries++) {
		stat = rpcbind_getaddr(&nsm->ns_knc, SM_PROG,
		    SM_VERS, &nsm->ns_addr);
		if (stat != RPC_SUCCESS) {
			if (stat == RPC_PROGNOTREGISTERED) {
				delay(SEC_TO_TICK(NLM_NSM_RPCBIND_TIMEOUT));
				continue;
			}
		}

		break;
	}

	if (stat != RPC_SUCCESS) {
		DTRACE_PROBE2(rpcbind__error, enum clnt_stat, stat,
		    int, retries);
		error = ENOENT;
		goto error;
	}

	/*
	 * Create an RPC handle that'll be used for communication with local
	 * statd using the status monitor protocol.
	 */
	error = clnt_tli_kcreate(&nsm->ns_knc, &nsm->ns_addr, SM_PROG, SM_VERS,
	    0, NLM_RPC_RETRIES, kcred, &nsm->ns_handle);
	if (error != 0)
		goto error;

	/*
	 * Create an RPC handle that'll be used for communication with the
	 * local statd using the address registration protocol.
	 */
	error = clnt_tli_kcreate(&nsm->ns_knc, &nsm->ns_addr, NSM_ADDR_PROGRAM,
	    NSM_ADDR_V1, 0, NLM_RPC_RETRIES, kcred, &nsm->ns_addr_handle);
	if (error != 0)
		goto error;

	sema_init(&nsm->ns_sem, 1, NULL, SEMA_DEFAULT, NULL);
	return (0);

error:
	kmem_free(nsm->ns_addr.buf, nsm->ns_addr.maxlen);
	if (nsm->ns_handle)
		CLNT_DESTROY(nsm->ns_handle);

	return (error);
}

static void
nlm_nsm_fini(struct nlm_nsm *nsm)
{
	kmem_free(nsm->ns_addr.buf, nsm->ns_addr.maxlen);
	CLNT_DESTROY(nsm->ns_addr_handle);
	nsm->ns_addr_handle = NULL;
	CLNT_DESTROY(nsm->ns_handle);
	nsm->ns_handle = NULL;
	sema_destroy(&nsm->ns_sem);
}

static enum clnt_stat
nlm_nsm_simu_crash(struct nlm_nsm *nsm)
{
	enum clnt_stat stat;

	sema_p(&nsm->ns_sem);
	nlm_nsm_clnt_init(nsm->ns_handle, nsm);
	stat = sm_simu_crash_1(NULL, NULL, nsm->ns_handle);
	sema_v(&nsm->ns_sem);

	return (stat);
}

static enum clnt_stat
nlm_nsm_stat(struct nlm_nsm *nsm, int32_t *out_stat)
{
	struct sm_name args;
	struct sm_stat_res res;
	enum clnt_stat stat;

	args.mon_name = uts_nodename();
	bzero(&res, sizeof (res));

	sema_p(&nsm->ns_sem);
	nlm_nsm_clnt_init(nsm->ns_handle, nsm);
	stat = sm_stat_1(&args, &res, nsm->ns_handle);
	sema_v(&nsm->ns_sem);

	if (stat == RPC_SUCCESS)
		*out_stat = res.state;

	return (stat);
}

static enum clnt_stat
nlm_nsm_mon(struct nlm_nsm *nsm, char *hostname, uint16_t priv)
{
	struct mon args;
	struct sm_stat_res res;
	enum clnt_stat stat;

	bzero(&args, sizeof (args));
	bzero(&res, sizeof (res));

	args.mon_id.mon_name = hostname;
	args.mon_id.my_id.my_name = uts_nodename();
	args.mon_id.my_id.my_prog = NLM_PROG;
	args.mon_id.my_id.my_vers = NLM_SM;
	args.mon_id.my_id.my_proc = NLM_SM_NOTIFY1;
	bcopy(&priv, args.priv, sizeof (priv));

	sema_p(&nsm->ns_sem);
	nlm_nsm_clnt_init(nsm->ns_handle, nsm);
	stat = sm_mon_1(&args, &res, nsm->ns_handle);
	sema_v(&nsm->ns_sem);

	return (stat);
}

static enum clnt_stat
nlm_nsm_unmon(struct nlm_nsm *nsm, char *hostname)
{
	struct mon_id args;
	struct sm_stat res;
	enum clnt_stat stat;

	bzero(&args, sizeof (args));
	bzero(&res, sizeof (res));

	args.mon_name = hostname;
	args.my_id.my_name = uts_nodename();
	args.my_id.my_prog = NLM_PROG;
	args.my_id.my_vers = NLM_SM;
	args.my_id.my_proc = NLM_SM_NOTIFY1;

	sema_p(&nsm->ns_sem);
	nlm_nsm_clnt_init(nsm->ns_handle, nsm);
	stat = sm_unmon_1(&args, &res, nsm->ns_handle);
	sema_v(&nsm->ns_sem);

	return (stat);
}

static enum clnt_stat
nlm_nsmaddr_reg(struct nlm_nsm *nsm, char *name, int family, netobj *address)
{
	struct reg1args args = { 0 };
	struct reg1res res = { 0 };
	enum clnt_stat stat;

	args.family = family;
	args.name = name;
	args.address = *address;

	sema_p(&nsm->ns_sem);
	nlm_nsm_clnt_init(nsm->ns_addr_handle, nsm);
	stat = nsmaddrproc1_reg_1(&args, &res, nsm->ns_addr_handle);
	sema_v(&nsm->ns_sem);

	return (stat);
}

/*
 * Get NLM vhold object corresponding to vnode "vp".
 * If no such object was found, create a new one.
 *
 * The purpose of this function is to associate vhold
 * object with given vnode, so that:
 * 1) vnode is hold (VN_HOLD) while vhold object is alive.
 * 2) host has a track of all vnodes it touched by lock
 *    or share operations. These vnodes are accessible
 *    via collection of vhold objects.
 */
struct nlm_vhold *
nlm_vhold_get(struct nlm_host *hostp, vnode_t *vp)
{
	struct nlm_vhold *nvp, *new_nvp = NULL;

	mutex_enter(&hostp->nh_lock);
	nvp = nlm_vhold_find_locked(hostp, vp);
	if (nvp != NULL)
		goto out;

	/* nlm_vhold wasn't found, then create a new one */
	mutex_exit(&hostp->nh_lock);
	new_nvp = kmem_cache_alloc(nlm_vhold_cache, KM_SLEEP);

	/*
	 * Check if another thread has already
	 * created the same nlm_vhold.
	 */
	mutex_enter(&hostp->nh_lock);
	nvp = nlm_vhold_find_locked(hostp, vp);
	if (nvp == NULL) {
		nvp = new_nvp;
		new_nvp = NULL;

		TAILQ_INIT(&nvp->nv_slreqs);
		nvp->nv_vp = vp;
		nvp->nv_refcnt = 1;
		VN_HOLD(nvp->nv_vp);

		VERIFY(mod_hash_insert(hostp->nh_vholds_by_vp,
		    (mod_hash_key_t)vp, (mod_hash_val_t)nvp) == 0);
		TAILQ_INSERT_TAIL(&hostp->nh_vholds_list, nvp, nv_link);
	}

out:
	mutex_exit(&hostp->nh_lock);
	if (new_nvp != NULL)
		kmem_cache_free(nlm_vhold_cache, new_nvp);

	return (nvp);
}

/*
 * Drop a reference to vhold object nvp.
 */
void
nlm_vhold_release(struct nlm_host *hostp, struct nlm_vhold *nvp)
{
	if (nvp == NULL)
		return;

	mutex_enter(&hostp->nh_lock);
	ASSERT(nvp->nv_refcnt > 0);
	nvp->nv_refcnt--;

	/*
	 * If these conditions are met, the vhold is obviously unused and we
	 * will destroy it.  In a case either v_filocks and/or v_shrlocks is
	 * non-NULL the vhold might still be unused by the host, but it is
	 * expensive to check that.  We defer such check until the host is
	 * idle.  The expensive check is done in the NLM garbage collector.
	 */
	if (nvp->nv_refcnt == 0 &&
	    nvp->nv_vp->v_filocks == NULL &&
	    nvp->nv_vp->v_shrlocks == NULL) {
		nlm_vhold_destroy(hostp, nvp);
	}

	mutex_exit(&hostp->nh_lock);
}

/*
 * Clean all locks and share reservations on the
 * given vhold object that were acquired by the
 * given sysid
 */
static void
nlm_vhold_clean(struct nlm_vhold *nvp, int sysid)
{
	cleanlocks(nvp->nv_vp, IGN_PID, sysid);
	cleanshares_by_sysid(nvp->nv_vp, sysid);
}

static void
nlm_vhold_destroy(struct nlm_host *hostp, struct nlm_vhold *nvp)
{
	ASSERT(MUTEX_HELD(&hostp->nh_lock));

	ASSERT(nvp->nv_refcnt == 0);
	ASSERT(TAILQ_EMPTY(&nvp->nv_slreqs));

	VERIFY(mod_hash_remove(hostp->nh_vholds_by_vp,
	    (mod_hash_key_t)nvp->nv_vp,
	    (mod_hash_val_t)&nvp) == 0);

	TAILQ_REMOVE(&hostp->nh_vholds_list, nvp, nv_link);
	VN_RELE(nvp->nv_vp);
	nvp->nv_vp = NULL;

	kmem_cache_free(nlm_vhold_cache, nvp);
}

/*
 * Return TRUE if the given vhold is busy.
 * Vhold object is considered to be "busy" when
 * all the following conditions hold:
 * 1) No one uses it at the moment;
 * 2) It hasn't any locks;
 * 3) It hasn't any share reservations;
 */
static bool_t
nlm_vhold_busy(struct nlm_host *hostp, struct nlm_vhold *nvp)
{
	vnode_t *vp;
	int sysid;

	ASSERT(MUTEX_HELD(&hostp->nh_lock));

	if (nvp->nv_refcnt > 0)
		return (TRUE);

	vp = nvp->nv_vp;
	sysid = hostp->nh_sysid;
	if (flk_has_remote_locks_for_sysid(vp, sysid) ||
	    shr_has_remote_shares(vp, sysid))
		return (TRUE);

	return (FALSE);
}

/* ARGSUSED */
static int
nlm_vhold_ctor(void *datap, void *cdrarg, int kmflags)
{
	struct nlm_vhold *nvp = (struct nlm_vhold *)datap;

	bzero(nvp, sizeof (*nvp));
	return (0);
}

/* ARGSUSED */
static void
nlm_vhold_dtor(void *datap, void *cdrarg)
{
	struct nlm_vhold *nvp = (struct nlm_vhold *)datap;

	ASSERT(nvp->nv_refcnt == 0);
	ASSERT(TAILQ_EMPTY(&nvp->nv_slreqs));
	ASSERT(nvp->nv_vp == NULL);
}

struct nlm_vhold *
nlm_vhold_find_locked(struct nlm_host *hostp, const vnode_t *vp)
{
	struct nlm_vhold *nvp = NULL;

	ASSERT(MUTEX_HELD(&hostp->nh_lock));
	(void) mod_hash_find(hostp->nh_vholds_by_vp,
	    (mod_hash_key_t)vp,
	    (mod_hash_val_t)&nvp);

	if (nvp != NULL)
		nvp->nv_refcnt++;

	return (nvp);
}

/*
 * NLM host functions
 */
static void
nlm_copy_netbuf(struct netbuf *dst, struct netbuf *src)
{
	ASSERT(src->len <= src->maxlen);

	dst->maxlen = src->maxlen;
	dst->len = src->len;
	dst->buf = kmem_zalloc(src->maxlen, KM_SLEEP);
	bcopy(src->buf, dst->buf, src->len);
}

/* ARGSUSED */
static int
nlm_host_ctor(void *datap, void *cdrarg, int kmflags)
{
	struct nlm_host *hostp = (struct nlm_host *)datap;

	bzero(hostp, sizeof (*hostp));
	return (0);
}

/* ARGSUSED */
static void
nlm_host_dtor(void *datap, void *cdrarg)
{
	struct nlm_host *hostp = (struct nlm_host *)datap;
	ASSERT(hostp->nh_refs == 0);
}

static void
nlm_host_unregister(struct nlm_globals *g, struct nlm_host *hostp)
{
	ASSERT(hostp->nh_refs == 0);
	ASSERT(hostp->nh_flags & NLM_NH_INIDLE);

	avl_remove(&g->nlm_hosts_tree, hostp);
	VERIFY(mod_hash_remove(g->nlm_hosts_hash,
	    (mod_hash_key_t)(uintptr_t)hostp->nh_sysid,
	    (mod_hash_val_t)&hostp) == 0);
	TAILQ_REMOVE(&g->nlm_idle_hosts, hostp, nh_link);
	hostp->nh_flags &= ~NLM_NH_INIDLE;
}

/*
 * Free resources used by a host. This is called after the reference
 * count has reached zero so it doesn't need to worry about locks.
 */
static void
nlm_host_destroy(struct nlm_host *hostp)
{
	ASSERT(hostp->nh_name != NULL);
	ASSERT(hostp->nh_netid != NULL);
	ASSERT(TAILQ_EMPTY(&hostp->nh_vholds_list));

	strfree(hostp->nh_name);
	strfree(hostp->nh_netid);
	kmem_free(hostp->nh_addr.buf, hostp->nh_addr.maxlen);

	if (hostp->nh_sysid != LM_NOSYSID)
		nlm_sysid_free(hostp->nh_sysid);

	nlm_rpc_cache_destroy(hostp);

	ASSERT(TAILQ_EMPTY(&hostp->nh_vholds_list));
	mod_hash_destroy_ptrhash(hostp->nh_vholds_by_vp);

	mutex_destroy(&hostp->nh_lock);
	cv_destroy(&hostp->nh_rpcb_cv);
	cv_destroy(&hostp->nh_recl_cv);

	kmem_cache_free(nlm_hosts_cache, hostp);
}

/*
 * Cleanup SERVER-side state after a client restarts,
 * or becomes unresponsive, or whatever.
 *
 * We unlock any active locks owned by the host.
 * When rpc.lockd is shutting down,
 * this function is called with newstate set to zero
 * which allows us to cancel any pending async locks
 * and clear the locking state.
 *
 * When "state" is 0, we don't update host's state,
 * but cleanup all remote locks on the host.
 * It's useful to call this function for resources
 * cleanup.
 */
void
nlm_host_notify_server(struct nlm_host *hostp, int32_t state)
{
	struct nlm_vhold *nvp;
	struct nlm_slreq *slr;
	struct nlm_slreq_list slreqs2free;

	TAILQ_INIT(&slreqs2free);
	mutex_enter(&hostp->nh_lock);
	if (state != 0)
		hostp->nh_state = state;

	TAILQ_FOREACH(nvp, &hostp->nh_vholds_list, nv_link) {

		/* cleanup sleeping requests at first */
		while ((slr = TAILQ_FIRST(&nvp->nv_slreqs)) != NULL) {
			TAILQ_REMOVE(&nvp->nv_slreqs, slr, nsr_link);

			/*
			 * Instead of freeing cancelled sleeping request
			 * here, we add it to the linked list created
			 * on the stack in order to do all frees outside
			 * the critical section.
			 */
			TAILQ_INSERT_TAIL(&slreqs2free, slr, nsr_link);
		}

		nvp->nv_refcnt++;
		mutex_exit(&hostp->nh_lock);

		nlm_vhold_clean(nvp, hostp->nh_sysid);

		mutex_enter(&hostp->nh_lock);
		nvp->nv_refcnt--;
	}

	mutex_exit(&hostp->nh_lock);
	while ((slr = TAILQ_FIRST(&slreqs2free)) != NULL) {
		TAILQ_REMOVE(&slreqs2free, slr, nsr_link);
		kmem_free(slr, sizeof (*slr));
	}
}

/*
 * Cleanup CLIENT-side state after a server restarts,
 * or becomes unresponsive, or whatever.
 *
 * This is called by the local NFS statd when we receive a
 * host state change notification.  (also nlm_svc_stopping)
 *
 * Deal with a server restart.  If we are stopping the
 * NLM service, we'll have newstate == 0, and will just
 * cancel all our client-side lock requests.  Otherwise,
 * start the "recovery" process to reclaim any locks
 * we hold on this server.
 */
void
nlm_host_notify_client(struct nlm_host *hostp, int32_t state)
{
	mutex_enter(&hostp->nh_lock);
	hostp->nh_state = state;
	if (hostp->nh_flags & NLM_NH_RECLAIM) {
		/*
		 * Either host's state is up to date or
		 * host is already in recovery.
		 */
		mutex_exit(&hostp->nh_lock);
		return;
	}

	hostp->nh_flags |= NLM_NH_RECLAIM;

	/*
	 * Host will be released by the recovery thread,
	 * thus we need to increment refcount.
	 */
	hostp->nh_refs++;
	mutex_exit(&hostp->nh_lock);

	(void) zthread_create(NULL, 0, nlm_reclaimer,
	    hostp, 0, minclsyspri);
}

/*
 * The function is called when NLM client detects that
 * server has entered in grace period and client needs
 * to wait until reclamation process (if any) does
 * its job.
 */
int
nlm_host_wait_grace(struct nlm_host *hostp)
{
	struct nlm_globals *g;
	int error = 0;

	g = zone_getspecific(nlm_zone_key, curzone);
	mutex_enter(&hostp->nh_lock);

	do {
		int rc;

		rc = cv_timedwait_sig(&hostp->nh_recl_cv,
		    &hostp->nh_lock, ddi_get_lbolt() +
		    SEC_TO_TICK(g->retrans_tmo));

		if (rc == 0) {
			error = EINTR;
			break;
		}
	} while (hostp->nh_flags & NLM_NH_RECLAIM);

	mutex_exit(&hostp->nh_lock);
	return (error);
}

/*
 * Create a new NLM host.
 *
 * NOTE: The in-kernel RPC (kRPC) subsystem uses TLI/XTI,
 * which needs both a knetconfig and an address when creating
 * endpoints. Thus host object stores both knetconfig and
 * netid.
 */
static struct nlm_host *
nlm_host_create(char *name, const char *netid,
    struct knetconfig *knc, struct netbuf *naddr)
{
	struct nlm_host *host;

	host = kmem_cache_alloc(nlm_hosts_cache, KM_SLEEP);

	mutex_init(&host->nh_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&host->nh_rpcb_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&host->nh_recl_cv, NULL, CV_DEFAULT, NULL);

	host->nh_sysid = LM_NOSYSID;
	host->nh_refs = 1;
	host->nh_name = strdup(name);
	host->nh_netid = strdup(netid);
	host->nh_knc = *knc;
	nlm_copy_netbuf(&host->nh_addr, naddr);

	host->nh_state = 0;
	host->nh_rpcb_state = NRPCB_NEED_UPDATE;
	host->nh_flags = 0;

	host->nh_vholds_by_vp = mod_hash_create_ptrhash("nlm vholds hash",
	    32, mod_hash_null_valdtor, sizeof (vnode_t));

	TAILQ_INIT(&host->nh_vholds_list);
	TAILQ_INIT(&host->nh_rpchc);

	return (host);
}

/*
 * Cancel all client side sleeping locks owned by given host.
 */
void
nlm_host_cancel_slocks(struct nlm_globals *g, struct nlm_host *hostp)
{
	struct nlm_slock *nslp;

	mutex_enter(&g->lock);
	TAILQ_FOREACH(nslp, &g->nlm_slocks, nsl_link) {
		if (nslp->nsl_host == hostp) {
			nslp->nsl_state = NLM_SL_CANCELLED;
			cv_broadcast(&nslp->nsl_cond);
		}
	}

	mutex_exit(&g->lock);
}

/*
 * Garbage collect stale vhold objects.
 *
 * In other words check whether vnodes that are
 * held by vhold objects still have any locks
 * or shares or still in use. If they aren't,
 * just destroy them.
 */
static void
nlm_host_gc_vholds(struct nlm_host *hostp)
{
	struct nlm_vhold *nvp;

	ASSERT(MUTEX_HELD(&hostp->nh_lock));

	nvp = TAILQ_FIRST(&hostp->nh_vholds_list);
	while (nvp != NULL) {
		struct nlm_vhold *nvp_tmp;

		if (nlm_vhold_busy(hostp, nvp)) {
			nvp = TAILQ_NEXT(nvp, nv_link);
			continue;
		}

		nvp_tmp = TAILQ_NEXT(nvp, nv_link);
		nlm_vhold_destroy(hostp, nvp);
		nvp = nvp_tmp;
	}
}

/*
 * Check whether the given host has any
 * server side locks or share reservations.
 */
static bool_t
nlm_host_has_srv_locks(struct nlm_host *hostp)
{
	/*
	 * It's cheap and simple: if server has
	 * any locks/shares there must be vhold
	 * object storing the affected vnode.
	 *
	 * NOTE: We don't need to check sleeping
	 * locks on the server side, because if
	 * server side sleeping lock is alive,
	 * there must be a vhold object corresponding
	 * to target vnode.
	 */
	ASSERT(MUTEX_HELD(&hostp->nh_lock));
	if (!TAILQ_EMPTY(&hostp->nh_vholds_list))
		return (TRUE);

	return (FALSE);
}

/*
 * Check whether the given host has any client side
 * locks or share reservations.
 */
static bool_t
nlm_host_has_cli_locks(struct nlm_host *hostp)
{
	ASSERT(MUTEX_HELD(&hostp->nh_lock));

	/*
	 * XXX: It's not the way I'd like to do the check,
	 * because flk_sysid_has_locks() can be very
	 * expensive by design. Unfortunatelly it iterates
	 * through all locks on the system, doesn't matter
	 * were they made on remote system via NLM or
	 * on local system via reclock. To understand the
	 * problem, consider that there're dozens of thousands
	 * of locks that are made on some ZFS dataset. And there's
	 * another dataset shared by NFS where NLM client had locks
	 * some time ago, but doesn't have them now.
	 * In this case flk_sysid_has_locks() will iterate
	 * thrught dozens of thousands locks until it returns us
	 * FALSE.
	 * Oh, I hope that in shiny future somebody will make
	 * local lock manager (os/flock.c) better, so that
	 * it'd be more friedly to remote locks and
	 * flk_sysid_has_locks() wouldn't be so expensive.
	 */
	if (flk_sysid_has_locks(hostp->nh_sysid |
	    LM_SYSID_CLIENT, FLK_QUERY_ACTIVE))
		return (TRUE);

	/*
	 * Check whether host has any share reservations
	 * registered on the client side.
	 */
	if (hostp->nh_shrlist != NULL)
		return (TRUE);

	return (FALSE);
}

/*
 * Determine whether the given host owns any
 * locks or share reservations.
 */
static bool_t
nlm_host_has_locks(struct nlm_host *hostp)
{
	if (nlm_host_has_srv_locks(hostp))
		return (TRUE);

	return (nlm_host_has_cli_locks(hostp));
}

/*
 * This function compares only addresses of two netbufs
 * that belong to NC_TCP[6] or NC_UDP[6] protofamily.
 * Port part of netbuf is ignored.
 *
 * Return values:
 *  -1: nb1's address is "smaller" than nb2's
 *   0: addresses are equal
 *   1: nb1's address is "greater" than nb2's
 */
static int
nlm_netbuf_addrs_cmp(struct netbuf *nb1, struct netbuf *nb2)
{
	union nlm_addr {
		struct sockaddr sa;
		struct sockaddr_in sin;
		struct sockaddr_in6 sin6;
	} *na1, *na2;
	int res;

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	na1 = (union nlm_addr *)nb1->buf;
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	na2 = (union nlm_addr *)nb2->buf;

	if (na1->sa.sa_family < na2->sa.sa_family)
		return (-1);
	if (na1->sa.sa_family > na2->sa.sa_family)
		return (1);

	switch (na1->sa.sa_family) {
	case AF_INET:
		res = memcmp(&na1->sin.sin_addr, &na2->sin.sin_addr,
		    sizeof (na1->sin.sin_addr));
		break;
	case AF_INET6:
		res = memcmp(&na1->sin6.sin6_addr, &na2->sin6.sin6_addr,
		    sizeof (na1->sin6.sin6_addr));
		break;
	default:
		VERIFY(0);
		return (0);
	}

	return (SIGN(res));
}

/*
 * Compare two nlm hosts.
 * Return values:
 * -1: host1 is "smaller" than host2
 *  0: host1 is equal to host2
 *  1: host1 is "greater" than host2
 */
int
nlm_host_cmp(const void *p1, const void *p2)
{
	struct nlm_host *h1 = (struct nlm_host *)p1;
	struct nlm_host *h2 = (struct nlm_host *)p2;
	int res;

	res = strcmp(h1->nh_netid, h2->nh_netid);
	if (res != 0)
		return (SIGN(res));

	res = nlm_netbuf_addrs_cmp(&h1->nh_addr, &h2->nh_addr);
	return (res);
}

/*
 * Find the host specified by...  (see below)
 * If found, increment the ref count.
 */
static struct nlm_host *
nlm_host_find_locked(struct nlm_globals *g, const char *netid,
    struct netbuf *naddr, avl_index_t *wherep)
{
	struct nlm_host *hostp, key;
	avl_index_t pos;

	ASSERT(MUTEX_HELD(&g->lock));

	key.nh_netid = (char *)netid;
	key.nh_addr.buf = naddr->buf;
	key.nh_addr.len = naddr->len;
	key.nh_addr.maxlen = naddr->maxlen;

	hostp = avl_find(&g->nlm_hosts_tree, &key, &pos);

	if (hostp != NULL) {
		/*
		 * Host is inuse now. Remove it from idle
		 * hosts list if needed.
		 */
		if (hostp->nh_flags & NLM_NH_INIDLE) {
			TAILQ_REMOVE(&g->nlm_idle_hosts, hostp, nh_link);
			hostp->nh_flags &= ~NLM_NH_INIDLE;
		}

		hostp->nh_refs++;
	}
	if (wherep != NULL)
		*wherep = pos;

	return (hostp);
}

/*
 * Find NLM host for the given name and address.
 */
struct nlm_host *
nlm_host_find(struct nlm_globals *g, const char *netid,
    struct netbuf *addr)
{
	struct nlm_host *hostp = NULL;

	mutex_enter(&g->lock);
	if (g->run_status != NLM_ST_UP)
		goto out;

	hostp = nlm_host_find_locked(g, netid, addr, NULL);

out:
	mutex_exit(&g->lock);
	return (hostp);
}


/*
 * Find or create an NLM host for the given name and address.
 *
 * The remote host is determined by all of: name, netid, address.
 * Note that the netid is whatever nlm_svc_add_ep() gave to
 * svc_tli_kcreate() for the service binding.  If any of these
 * are different, allocate a new host (new sysid).
 */
struct nlm_host *
nlm_host_findcreate(struct nlm_globals *g, char *name,
    const char *netid, struct netbuf *addr)
{
	int err;
	struct nlm_host *host, *newhost = NULL;
	struct knetconfig knc;
	avl_index_t where;

	mutex_enter(&g->lock);
	if (g->run_status != NLM_ST_UP) {
		mutex_exit(&g->lock);
		return (NULL);
	}

	host = nlm_host_find_locked(g, netid, addr, NULL);
	mutex_exit(&g->lock);
	if (host != NULL)
		return (host);

	err = nlm_knc_from_netid(netid, &knc);
	if (err != 0)
		return (NULL);
	/*
	 * Do allocations (etc.) outside of mutex,
	 * and then check again before inserting.
	 */
	newhost = nlm_host_create(name, netid, &knc, addr);
	newhost->nh_sysid = nlm_sysid_alloc();
	if (newhost->nh_sysid == LM_NOSYSID)
		goto out;

	mutex_enter(&g->lock);
	host = nlm_host_find_locked(g, netid, addr, &where);
	if (host == NULL) {
		host = newhost;
		newhost = NULL;

		/*
		 * Insert host to the hosts AVL tree that is
		 * used to lookup by <netid, address> pair.
		 */
		avl_insert(&g->nlm_hosts_tree, host, where);

		/*
		 * Insert host to the hosts hash table that is
		 * used to lookup host by sysid.
		 */
		VERIFY(mod_hash_insert(g->nlm_hosts_hash,
		    (mod_hash_key_t)(uintptr_t)host->nh_sysid,
		    (mod_hash_val_t)host) == 0);
	}

	mutex_exit(&g->lock);

out:
	if (newhost != NULL) {
		/*
		 * We do not need the preallocated nlm_host
		 * so decrement the reference counter
		 * and destroy it.
		 */
		newhost->nh_refs--;
		nlm_host_destroy(newhost);
	}

	return (host);
}

/*
 * Find the NLM host that matches the value of 'sysid'.
 * If found, return it with a new ref,
 * else return NULL.
 */
struct nlm_host *
nlm_host_find_by_sysid(struct nlm_globals *g, sysid_t sysid)
{
	struct nlm_host *hostp = NULL;

	mutex_enter(&g->lock);
	if (g->run_status != NLM_ST_UP)
		goto out;

	(void) mod_hash_find(g->nlm_hosts_hash,
	    (mod_hash_key_t)(uintptr_t)sysid,
	    (mod_hash_val_t)&hostp);

	if (hostp == NULL)
		goto out;

	/*
	 * Host is inuse now. Remove it
	 * from idle hosts list if needed.
	 */
	if (hostp->nh_flags & NLM_NH_INIDLE) {
		TAILQ_REMOVE(&g->nlm_idle_hosts, hostp, nh_link);
		hostp->nh_flags &= ~NLM_NH_INIDLE;
	}

	hostp->nh_refs++;

out:
	mutex_exit(&g->lock);
	return (hostp);
}

/*
 * Release the given host.
 * I.e. drop a reference that was taken earlier by one of
 * the following functions: nlm_host_findcreate(), nlm_host_find(),
 * nlm_host_find_by_sysid().
 *
 * When the very last reference is dropped, host is moved to
 * so-called "idle state". All hosts that are in idle state
 * have an idle timeout. If timeout is expired, GC thread
 * checks whether hosts have any locks and if they heven't
 * any, it removes them.
 * NOTE: only unused hosts can be in idle state.
 */
void
nlm_host_release(struct nlm_globals *g, struct nlm_host *hostp)
{
	if (hostp == NULL)
		return;

	mutex_enter(&g->lock);
	ASSERT(hostp->nh_refs > 0);

	hostp->nh_refs--;
	if (hostp->nh_refs != 0) {
		mutex_exit(&g->lock);
		return;
	}

	/*
	 * The very last reference to the host was dropped,
	 * thus host is unused now. Set its idle timeout
	 * and move it to the idle hosts LRU list.
	 */
	hostp->nh_idle_timeout = ddi_get_lbolt() +
	    SEC_TO_TICK(g->cn_idle_tmo);

	ASSERT((hostp->nh_flags & NLM_NH_INIDLE) == 0);
	TAILQ_INSERT_TAIL(&g->nlm_idle_hosts, hostp, nh_link);
	hostp->nh_flags |= NLM_NH_INIDLE;
	mutex_exit(&g->lock);
}

/*
 * Unregister this NLM host (NFS client) with the local statd
 * due to idleness (no locks held for a while).
 */
void
nlm_host_unmonitor(struct nlm_globals *g, struct nlm_host *host)
{
	enum clnt_stat stat;

	VERIFY(host->nh_refs == 0);
	if (!(host->nh_flags & NLM_NH_MONITORED))
		return;

	host->nh_flags &= ~NLM_NH_MONITORED;
	stat = nlm_nsm_unmon(&g->nlm_nsm, host->nh_name);
	if (stat != RPC_SUCCESS) {
		NLM_WARN("NLM: Failed to contact statd, stat=%d\n", stat);
		return;
	}
}

/*
 * Ask the local NFS statd to begin monitoring this host.
 * It will call us back when that host restarts, using the
 * prog,vers,proc specified below, i.e. NLM_SM_NOTIFY1,
 * which is handled in nlm_do_notify1().
 */
void
nlm_host_monitor(struct nlm_globals *g, struct nlm_host *host, int state)
{
	int family;
	netobj obj;
	enum clnt_stat stat;

	if (state != 0 && host->nh_state == 0) {
		/*
		 * This is the first time we have seen an NSM state
		 * Value for this host. We record it here to help
		 * detect host reboots.
		 */
		host->nh_state = state;
	}

	mutex_enter(&host->nh_lock);
	if (host->nh_flags & NLM_NH_MONITORED) {
		mutex_exit(&host->nh_lock);
		return;
	}

	host->nh_flags |= NLM_NH_MONITORED;
	mutex_exit(&host->nh_lock);

	/*
	 * Before we begin monitoring the host register the network address
	 * associated with this hostname.
	 */
	nlm_netbuf_to_netobj(&host->nh_addr, &family, &obj);
	stat = nlm_nsmaddr_reg(&g->nlm_nsm, host->nh_name, family, &obj);
	if (stat != RPC_SUCCESS) {
		NLM_WARN("Failed to register address, stat=%d\n", stat);
		mutex_enter(&g->lock);
		host->nh_flags &= ~NLM_NH_MONITORED;
		mutex_exit(&g->lock);

		return;
	}

	/*
	 * Tell statd how to call us with status updates for
	 * this host. Updates arrive via nlm_do_notify1().
	 *
	 * We put our assigned system ID value in the priv field to
	 * make it simpler to find the host if we are notified of a
	 * host restart.
	 */
	stat = nlm_nsm_mon(&g->nlm_nsm, host->nh_name, host->nh_sysid);
	if (stat != RPC_SUCCESS) {
		NLM_WARN("Failed to contact local NSM, stat=%d\n", stat);
		mutex_enter(&g->lock);
		host->nh_flags &= ~NLM_NH_MONITORED;
		mutex_exit(&g->lock);

		return;
	}
}

int
nlm_host_get_state(struct nlm_host *hostp)
{

	return (hostp->nh_state);
}

/*
 * NLM client/server sleeping locks
 */

/*
 * Register client side sleeping lock.
 *
 * Our client code calls this to keep information
 * about sleeping lock somewhere. When it receives
 * grant callback from server or when it just
 * needs to remove all sleeping locks from vnode,
 * it uses this information for remove/apply lock
 * properly.
 */
struct nlm_slock *
nlm_slock_register(
	struct nlm_globals *g,
	struct nlm_host *host,
	struct nlm4_lock *lock,
	struct vnode *vp)
{
	struct nlm_slock *nslp;

	nslp = kmem_zalloc(sizeof (*nslp), KM_SLEEP);
	cv_init(&nslp->nsl_cond, NULL, CV_DEFAULT, NULL);
	nslp->nsl_lock = *lock;
	nlm_copy_netobj(&nslp->nsl_fh, &nslp->nsl_lock.fh);
	nslp->nsl_state = NLM_SL_BLOCKED;
	nslp->nsl_host = host;
	nslp->nsl_vp = vp;

	mutex_enter(&g->lock);
	TAILQ_INSERT_TAIL(&g->nlm_slocks, nslp, nsl_link);
	mutex_exit(&g->lock);

	return (nslp);
}

/*
 * Remove this lock from the wait list and destroy it.
 */
void
nlm_slock_unregister(struct nlm_globals *g, struct nlm_slock *nslp)
{
	mutex_enter(&g->lock);
	TAILQ_REMOVE(&g->nlm_slocks, nslp, nsl_link);
	mutex_exit(&g->lock);

	kmem_free(nslp->nsl_fh.n_bytes, nslp->nsl_fh.n_len);
	cv_destroy(&nslp->nsl_cond);
	kmem_free(nslp, sizeof (*nslp));
}

/*
 * Wait for a granted callback or cancellation event
 * for a sleeping lock.
 *
 * If a signal interrupted the wait or if the lock
 * was cancelled, return EINTR - the caller must arrange to send
 * a cancellation to the server.
 *
 * If timeout occurred, return ETIMEDOUT - the caller must
 * resend the lock request to the server.
 *
 * On success return 0.
 */
int
nlm_slock_wait(struct nlm_globals *g,
    struct nlm_slock *nslp, uint_t timeo_secs)
{
	clock_t timeo_ticks;
	int cv_res, error;

	/*
	 * If the granted message arrived before we got here,
	 * nslp->nsl_state will be NLM_SL_GRANTED - in that case don't sleep.
	 */
	cv_res = 1;
	timeo_ticks = ddi_get_lbolt() + SEC_TO_TICK(timeo_secs);

	mutex_enter(&g->lock);
	while (nslp->nsl_state == NLM_SL_BLOCKED && cv_res > 0) {
		cv_res = cv_timedwait_sig(&nslp->nsl_cond,
		    &g->lock, timeo_ticks);
	}

	/*
	 * No matter why we wake up, if the lock was
	 * cancelled, let the function caller to know
	 * about it by returning EINTR.
	 */
	if (nslp->nsl_state == NLM_SL_CANCELLED) {
		error = EINTR;
		goto out;
	}

	if (cv_res <= 0) {
		/* We were woken up either by timeout or by interrupt */
		error = (cv_res < 0) ? ETIMEDOUT : EINTR;

		/*
		 * The granted message may arrive after the
		 * interrupt/timeout but before we manage to lock the
		 * mutex. Detect this by examining nslp.
		 */
		if (nslp->nsl_state == NLM_SL_GRANTED)
			error = 0;
	} else { /* Awaken via cv_signal()/cv_broadcast() or didn't block */
		error = 0;
		VERIFY(nslp->nsl_state == NLM_SL_GRANTED);
	}

out:
	mutex_exit(&g->lock);
	return (error);
}

/*
 * Mark client side sleeping lock as granted
 * and wake up a process blocked on the lock.
 * Called from server side NLM_GRANT handler.
 *
 * If sleeping lock is found return 0, otherwise
 * return ENOENT.
 */
int
nlm_slock_grant(struct nlm_globals *g,
    struct nlm_host *hostp, struct nlm4_lock *alock)
{
	struct nlm_slock *nslp;
	int error = ENOENT;

	mutex_enter(&g->lock);
	TAILQ_FOREACH(nslp, &g->nlm_slocks, nsl_link) {
		if ((nslp->nsl_state != NLM_SL_BLOCKED) ||
		    (nslp->nsl_host != hostp))
			continue;

		if (alock->svid		== nslp->nsl_lock.svid &&
		    alock->l_offset	== nslp->nsl_lock.l_offset &&
		    alock->l_len	== nslp->nsl_lock.l_len &&
		    alock->fh.n_len	== nslp->nsl_lock.fh.n_len &&
		    bcmp(alock->fh.n_bytes, nslp->nsl_lock.fh.n_bytes,
		    nslp->nsl_lock.fh.n_len) == 0) {
			nslp->nsl_state = NLM_SL_GRANTED;
			cv_broadcast(&nslp->nsl_cond);
			error = 0;
			break;
		}
	}

	mutex_exit(&g->lock);
	return (error);
}

/*
 * Register sleeping lock request corresponding to
 * flp on the given vhold object.
 * On success function returns 0, otherwise (if
 * lock request with the same flp is already
 * registered) function returns EEXIST.
 */
int
nlm_slreq_register(struct nlm_host *hostp, struct nlm_vhold *nvp,
	struct flock64 *flp)
{
	struct nlm_slreq *slr, *new_slr = NULL;
	int ret = EEXIST;

	mutex_enter(&hostp->nh_lock);
	slr = nlm_slreq_find_locked(hostp, nvp, flp);
	if (slr != NULL)
		goto out;

	mutex_exit(&hostp->nh_lock);
	new_slr = kmem_zalloc(sizeof (*slr), KM_SLEEP);
	bcopy(flp, &new_slr->nsr_fl, sizeof (*flp));

	mutex_enter(&hostp->nh_lock);
	slr = nlm_slreq_find_locked(hostp, nvp, flp);
	if (slr == NULL) {
		slr = new_slr;
		new_slr = NULL;
		ret = 0;

		TAILQ_INSERT_TAIL(&nvp->nv_slreqs, slr, nsr_link);
	}

out:
	mutex_exit(&hostp->nh_lock);
	if (new_slr != NULL)
		kmem_free(new_slr, sizeof (*new_slr));

	return (ret);
}

/*
 * Unregister sleeping lock request corresponding
 * to flp from the given vhold object.
 * On success function returns 0, otherwise (if
 * lock request corresponding to flp isn't found
 * on the given vhold) function returns ENOENT.
 */
int
nlm_slreq_unregister(struct nlm_host *hostp, struct nlm_vhold *nvp,
	struct flock64 *flp)
{
	struct nlm_slreq *slr;

	mutex_enter(&hostp->nh_lock);
	slr = nlm_slreq_find_locked(hostp, nvp, flp);
	if (slr == NULL) {
		mutex_exit(&hostp->nh_lock);
		return (ENOENT);
	}

	TAILQ_REMOVE(&nvp->nv_slreqs, slr, nsr_link);
	mutex_exit(&hostp->nh_lock);

	kmem_free(slr, sizeof (*slr));
	return (0);
}

/*
 * Find sleeping lock request on the given vhold object by flp.
 */
struct nlm_slreq *
nlm_slreq_find_locked(struct nlm_host *hostp, struct nlm_vhold *nvp,
    struct flock64 *flp)
{
	struct nlm_slreq *slr = NULL;

	ASSERT(MUTEX_HELD(&hostp->nh_lock));
	TAILQ_FOREACH(slr, &nvp->nv_slreqs, nsr_link) {
		if (slr->nsr_fl.l_start		== flp->l_start	&&
		    slr->nsr_fl.l_len		== flp->l_len	&&
		    slr->nsr_fl.l_pid		== flp->l_pid	&&
		    slr->nsr_fl.l_type		== flp->l_type)
			break;
	}

	return (slr);
}

/*
 * NLM tracks active share reservations made on the client side.
 * It needs to have a track of share reservations for two purposes
 * 1) to determine if nlm_host is busy (if it has active locks and/or
 *    share reservations, it is)
 * 2) to recover active share reservations when NLM server reports
 *    that it has rebooted.
 *
 * Unfortunately Illumos local share reservations manager (see os/share.c)
 * doesn't have an ability to lookup all reservations on the system
 * by sysid (like local lock manager) or get all reservations by sysid.
 * It tracks reservations per vnode and is able to get/looup them
 * on particular vnode. It's not what NLM needs. Thus it has that ugly
 * share reservations tracking scheme.
 */

void
nlm_shres_track(struct nlm_host *hostp, vnode_t *vp, struct shrlock *shrp)
{
	struct nlm_shres *nsp, *nsp_new;

	/*
	 * NFS code must fill the s_owner, so that
	 * s_own_len is never 0.
	 */
	ASSERT(shrp->s_own_len > 0);
	nsp_new = nlm_shres_create_item(shrp, vp);

	mutex_enter(&hostp->nh_lock);
	for (nsp = hostp->nh_shrlist; nsp != NULL; nsp = nsp->ns_next)
		if (nsp->ns_vp == vp && nlm_shres_equal(shrp, nsp->ns_shr))
			break;

	if (nsp != NULL) {
		/*
		 * Found a duplicate. Do nothing.
		 */

		goto out;
	}

	nsp = nsp_new;
	nsp_new = NULL;
	nsp->ns_next = hostp->nh_shrlist;
	hostp->nh_shrlist = nsp;

out:
	mutex_exit(&hostp->nh_lock);
	if (nsp_new != NULL)
		nlm_shres_destroy_item(nsp_new);
}

void
nlm_shres_untrack(struct nlm_host *hostp, vnode_t *vp, struct shrlock *shrp)
{
	struct nlm_shres *nsp, *nsp_prev = NULL;

	mutex_enter(&hostp->nh_lock);
	nsp = hostp->nh_shrlist;
	while (nsp != NULL) {
		if (nsp->ns_vp == vp && nlm_shres_equal(shrp, nsp->ns_shr)) {
			struct nlm_shres *nsp_del;

			nsp_del = nsp;
			nsp = nsp->ns_next;
			if (nsp_prev != NULL)
				nsp_prev->ns_next = nsp;
			else
				hostp->nh_shrlist = nsp;

			nlm_shres_destroy_item(nsp_del);
			continue;
		}

		nsp_prev = nsp;
		nsp = nsp->ns_next;
	}

	mutex_exit(&hostp->nh_lock);
}

/*
 * Get a _copy_ of the list of all active share reservations
 * made by the given host.
 * NOTE: the list function returns _must_ be released using
 *       nlm_free_shrlist().
 */
struct nlm_shres *
nlm_get_active_shres(struct nlm_host *hostp)
{
	struct nlm_shres *nsp, *nslist = NULL;

	mutex_enter(&hostp->nh_lock);
	for (nsp = hostp->nh_shrlist; nsp != NULL; nsp = nsp->ns_next) {
		struct nlm_shres *nsp_new;

		nsp_new = nlm_shres_create_item(nsp->ns_shr, nsp->ns_vp);
		nsp_new->ns_next = nslist;
		nslist = nsp_new;
	}

	mutex_exit(&hostp->nh_lock);
	return (nslist);
}

/*
 * Free memory allocated for the active share reservations
 * list created by nlm_get_active_shres() function.
 */
void
nlm_free_shrlist(struct nlm_shres *nslist)
{
	struct nlm_shres *nsp;

	while (nslist != NULL) {
		nsp =  nslist;
		nslist = nslist->ns_next;

		nlm_shres_destroy_item(nsp);
	}
}

static bool_t
nlm_shres_equal(struct shrlock *shrp1, struct shrlock *shrp2)
{
	if (shrp1->s_sysid	== shrp2->s_sysid	&&
	    shrp1->s_pid	== shrp2->s_pid		&&
	    shrp1->s_own_len	== shrp2->s_own_len	&&
	    bcmp(shrp1->s_owner, shrp2->s_owner,
	    shrp1->s_own_len) == 0)
		return (TRUE);

	return (FALSE);
}

static struct nlm_shres *
nlm_shres_create_item(struct shrlock *shrp, vnode_t *vp)
{
	struct nlm_shres *nsp;

	nsp = kmem_alloc(sizeof (*nsp), KM_SLEEP);
	nsp->ns_shr = kmem_alloc(sizeof (*shrp), KM_SLEEP);
	bcopy(shrp, nsp->ns_shr, sizeof (*shrp));
	nsp->ns_shr->s_owner = kmem_alloc(shrp->s_own_len, KM_SLEEP);
	bcopy(shrp->s_owner, nsp->ns_shr->s_owner, shrp->s_own_len);
	nsp->ns_vp = vp;

	return (nsp);
}

static void
nlm_shres_destroy_item(struct nlm_shres *nsp)
{
	kmem_free(nsp->ns_shr->s_owner,
	    nsp->ns_shr->s_own_len);
	kmem_free(nsp->ns_shr, sizeof (struct shrlock));
	kmem_free(nsp, sizeof (*nsp));
}

/*
 * Called by klmmod.c when lockd adds a network endpoint
 * on which we should begin RPC services.
 */
int
nlm_svc_add_ep(struct file *fp, const char *netid, struct knetconfig *knc)
{
	SVCMASTERXPRT *xprt = NULL;
	int error;

	error = svc_tli_kcreate(fp, 0, (char *)netid, NULL, &xprt,
	    &nlm_sct, NULL, NLM_SVCPOOL_ID, FALSE);
	if (error != 0)
		return (error);

	(void) nlm_knc_to_netid(knc);
	return (0);
}

/*
 * Start NLM service.
 */
int
nlm_svc_starting(struct nlm_globals *g, struct file *fp,
    const char *netid, struct knetconfig *knc)
{
	int error;
	enum clnt_stat stat;

	VERIFY(g->run_status == NLM_ST_STARTING);
	VERIFY(g->nlm_gc_thread == NULL);

	error = nlm_nsm_init_local(&g->nlm_nsm);
	if (error != 0) {
		NLM_ERR("Failed to initialize NSM handler "
		    "(error=%d)\n", error);
		g->run_status = NLM_ST_DOWN;
		return (error);
	}

	error = EIO;

	/*
	 * Create an NLM garbage collector thread that will
	 * clean up stale vholds and hosts objects.
	 */
	g->nlm_gc_thread = zthread_create(NULL, 0, nlm_gc,
	    g, 0, minclsyspri);

	/*
	 * Send SIMU_CRASH to local statd to report that
	 * NLM started, so that statd can report other hosts
	 * about NLM state change.
	 */

	stat = nlm_nsm_simu_crash(&g->nlm_nsm);
	if (stat != RPC_SUCCESS) {
		NLM_ERR("Failed to connect to local statd "
		    "(rpcerr=%d)\n", stat);
		goto shutdown_lm;
	}

	stat = nlm_nsm_stat(&g->nlm_nsm, &g->nsm_state);
	if (stat != RPC_SUCCESS) {
		NLM_ERR("Failed to get the status of local statd "
		    "(rpcerr=%d)\n", stat);
		goto shutdown_lm;
	}

	g->grace_threshold = ddi_get_lbolt() +
	    SEC_TO_TICK(g->grace_period);

	/* Register endpoint used for communications with local NLM */
	error = nlm_svc_add_ep(fp, netid, knc);
	if (error != 0)
		goto shutdown_lm;

	(void) svc_pool_control(NLM_SVCPOOL_ID,
	    SVCPSET_SHUTDOWN_PROC, (void *)nlm_pool_shutdown);
	g->run_status = NLM_ST_UP;
	return (0);

shutdown_lm:
	mutex_enter(&g->lock);
	g->run_status = NLM_ST_STOPPING;
	mutex_exit(&g->lock);

	nlm_svc_stopping(g);
	return (error);
}

/*
 * Called when the server pool is destroyed, so that
 * all transports are closed and no any server threads
 * exist.
 *
 * Just call lm_shutdown() to shut NLM down properly.
 */
static void
nlm_pool_shutdown(void)
{
	(void) lm_shutdown();
}

/*
 * Stop NLM service, cleanup all resources
 * NLM owns at the moment.
 *
 * NOTE: NFS code can call NLM while it's
 * stopping or even if it's shut down. Any attempt
 * to lock file either on client or on the server
 * will fail if NLM isn't in NLM_ST_UP state.
 */
void
nlm_svc_stopping(struct nlm_globals *g)
{
	mutex_enter(&g->lock);
	ASSERT(g->run_status == NLM_ST_STOPPING);

	/*
	 * Ask NLM GC thread to exit and wait until it dies.
	 */
	cv_signal(&g->nlm_gc_sched_cv);
	while (g->nlm_gc_thread != NULL)
		cv_wait(&g->nlm_gc_finish_cv, &g->lock);

	mutex_exit(&g->lock);

	/*
	 * Cleanup locks owned by NLM hosts.
	 * NOTE: New hosts won't be created while
	 * NLM is stopping.
	 */
	while (!avl_is_empty(&g->nlm_hosts_tree)) {
		struct nlm_host *hostp;
		int busy_hosts = 0;

		/*
		 * Iterate through all NLM hosts in the system
		 * and drop the locks they own by force.
		 */
		hostp = avl_first(&g->nlm_hosts_tree);
		while (hostp != NULL) {
			/* Cleanup all client and server side locks */
			nlm_client_cancel_all(g, hostp);
			nlm_host_notify_server(hostp, 0);

			mutex_enter(&hostp->nh_lock);
			nlm_host_gc_vholds(hostp);
			if (hostp->nh_refs > 0 || nlm_host_has_locks(hostp)) {
				/*
				 * Oh, it seems the host is still busy, let
				 * it some time to release and go to the
				 * next one.
				 */

				mutex_exit(&hostp->nh_lock);
				hostp = AVL_NEXT(&g->nlm_hosts_tree, hostp);
				busy_hosts++;
				continue;
			}

			mutex_exit(&hostp->nh_lock);
			hostp = AVL_NEXT(&g->nlm_hosts_tree, hostp);
		}

		/*
		 * All hosts go to nlm_idle_hosts list after
		 * all locks they own are cleaned up and last refereces
		 * were dropped. Just destroy all hosts in nlm_idle_hosts
		 * list, they can not be removed from there while we're
		 * in stopping state.
		 */
		while ((hostp = TAILQ_FIRST(&g->nlm_idle_hosts)) != NULL) {
			nlm_host_unregister(g, hostp);
			nlm_host_destroy(hostp);
		}

		if (busy_hosts > 0) {
			/*
			 * There're some hosts that weren't cleaned
			 * up. Probably they're in resource cleanup
			 * process. Give them some time to do drop
			 * references.
			 */
			delay(MSEC_TO_TICK(500));
		}
	}

	ASSERT(TAILQ_EMPTY(&g->nlm_slocks));

	nlm_nsm_fini(&g->nlm_nsm);
	g->lockd_pid = 0;
	g->run_status = NLM_ST_DOWN;
}

/*
 * Returns TRUE if the given vnode has
 * any active or sleeping locks.
 */
int
nlm_vp_active(const vnode_t *vp)
{
	struct nlm_globals *g;
	struct nlm_host *hostp;
	struct nlm_vhold *nvp;
	int active = 0;

	g = zone_getspecific(nlm_zone_key, curzone);

	/*
	 * Server side NLM has locks on the given vnode
	 * if there exist a vhold object that holds
	 * the given vnode "vp" in one of NLM hosts.
	 */
	mutex_enter(&g->lock);
	hostp = avl_first(&g->nlm_hosts_tree);
	while (hostp != NULL) {
		mutex_enter(&hostp->nh_lock);
		nvp = nlm_vhold_find_locked(hostp, vp);
		mutex_exit(&hostp->nh_lock);
		if (nvp != NULL) {
			active = 1;
			break;
		}

		hostp = AVL_NEXT(&g->nlm_hosts_tree, hostp);
	}

	mutex_exit(&g->lock);
	return (active);
}

/*
 * Called right before NFS export is going to
 * dissapear. The function finds all vnodes
 * belonging to the given export and cleans
 * all remote locks and share reservations
 * on them.
 */
void
nlm_unexport(struct exportinfo *exi)
{
	struct nlm_globals *g;
	struct nlm_host *hostp;

	g = zone_getspecific(nlm_zone_key, curzone);

	mutex_enter(&g->lock);
	hostp = avl_first(&g->nlm_hosts_tree);
	while (hostp != NULL) {
		struct nlm_vhold *nvp;

		mutex_enter(&hostp->nh_lock);
		TAILQ_FOREACH(nvp, &hostp->nh_vholds_list, nv_link) {
			vnode_t *vp;

			nvp->nv_refcnt++;
			mutex_exit(&hostp->nh_lock);

			vp = nvp->nv_vp;

			if (!EQFSID(&exi->exi_fsid, &vp->v_vfsp->vfs_fsid))
				goto next_iter;

			/*
			 * Ok, it we found out that vnode vp is under
			 * control by the exportinfo exi, now we need
			 * to drop all locks from this vnode, let's
			 * do it.
			 */
			nlm_vhold_clean(nvp, hostp->nh_sysid);

		next_iter:
			mutex_enter(&hostp->nh_lock);
			nvp->nv_refcnt--;
		}

		mutex_exit(&hostp->nh_lock);
		hostp = AVL_NEXT(&g->nlm_hosts_tree, hostp);
	}

	mutex_exit(&g->lock);
}

/*
 * Allocate new unique sysid.
 * In case of failure (no available sysids)
 * return LM_NOSYSID.
 */
sysid_t
nlm_sysid_alloc(void)
{
	sysid_t ret_sysid = LM_NOSYSID;

	rw_enter(&lm_lck, RW_WRITER);
	if (nlm_sysid_nidx > LM_SYSID_MAX)
		nlm_sysid_nidx = LM_SYSID;

	if (!BT_TEST(nlm_sysid_bmap, nlm_sysid_nidx)) {
		BT_SET(nlm_sysid_bmap, nlm_sysid_nidx);
		ret_sysid = nlm_sysid_nidx++;
	} else {
		index_t id;

		id = bt_availbit(nlm_sysid_bmap, NLM_BMAP_NITEMS);
		if (id > 0) {
			nlm_sysid_nidx = id + 1;
			ret_sysid = id;
			BT_SET(nlm_sysid_bmap, id);
		}
	}

	rw_exit(&lm_lck);
	return (ret_sysid);
}

void
nlm_sysid_free(sysid_t sysid)
{
	ASSERT(sysid >= LM_SYSID && sysid <= LM_SYSID_MAX);

	rw_enter(&lm_lck, RW_WRITER);
	ASSERT(BT_TEST(nlm_sysid_bmap, sysid));
	BT_CLEAR(nlm_sysid_bmap, sysid);
	rw_exit(&lm_lck);
}

/*
 * Return true if the request came from a local caller.
 * By necessity, this "knows" the netid names invented
 * in lm_svc() and nlm_netid_from_knetconfig().
 */
bool_t
nlm_caller_is_local(SVCXPRT *transp)
{
	char *netid;
	struct netbuf *rtaddr;

	netid = svc_getnetid(transp);
	rtaddr = svc_getrpccaller(transp);

	if (netid == NULL)
		return (FALSE);

	if (strcmp(netid, "ticlts") == 0 ||
	    strcmp(netid, "ticotsord") == 0)
		return (TRUE);

	if (strcmp(netid, "tcp") == 0 || strcmp(netid, "udp") == 0) {
		struct sockaddr_in *sin = (void *)rtaddr->buf;
		if (sin->sin_addr.s_addr == htonl(INADDR_LOOPBACK))
			return (TRUE);
	}
	if (strcmp(netid, "tcp6") == 0 || strcmp(netid, "udp6") == 0) {
		struct sockaddr_in6 *sin6 = (void *)rtaddr->buf;
		if (IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr))
			return (TRUE);
	}

	return (FALSE); /* unknown transport */
}

/*
 * Get netid string correspondig to the given knetconfig.
 * If not done already, save knc->knc_rdev in our table.
 */
const char *
nlm_knc_to_netid(struct knetconfig *knc)
{
	int i;
	dev_t rdev;
	struct nlm_knc *nc;
	const char *netid = NULL;

	rw_enter(&lm_lck, RW_READER);
	for (i = 0; i < NLM_KNCS; i++) {
		nc = &nlm_netconfigs[i];

		if (nc->n_knc.knc_semantics == knc->knc_semantics &&
		    strcmp(nc->n_knc.knc_protofmly,
		    knc->knc_protofmly) == 0) {
			netid = nc->n_netid;
			rdev = nc->n_knc.knc_rdev;
			break;
		}
	}
	rw_exit(&lm_lck);

	if (netid != NULL && rdev == NODEV) {
		rw_enter(&lm_lck, RW_WRITER);
		if (nc->n_knc.knc_rdev == NODEV)
			nc->n_knc.knc_rdev = knc->knc_rdev;
		rw_exit(&lm_lck);
	}

	return (netid);
}

/*
 * Get a knetconfig corresponding to the given netid.
 * If there's no knetconfig for this netid, ENOENT
 * is returned.
 */
int
nlm_knc_from_netid(const char *netid, struct knetconfig *knc)
{
	int i, ret;

	ret = ENOENT;
	for (i = 0; i < NLM_KNCS; i++) {
		struct nlm_knc *nknc;

		nknc = &nlm_netconfigs[i];
		if (strcmp(netid, nknc->n_netid) == 0 &&
		    nknc->n_knc.knc_rdev != NODEV) {
			*knc = nknc->n_knc;
			ret = 0;
			break;
		}
	}

	return (ret);
}

void
nlm_cprsuspend(void)
{
	struct nlm_globals *g;

	rw_enter(&lm_lck, RW_READER);
	TAILQ_FOREACH(g, &nlm_zones_list, nlm_link)
		nlm_suspend_zone(g);

	rw_exit(&lm_lck);
}

void
nlm_cprresume(void)
{
	struct nlm_globals *g;

	rw_enter(&lm_lck, RW_READER);
	TAILQ_FOREACH(g, &nlm_zones_list, nlm_link)
		nlm_resume_zone(g);

	rw_exit(&lm_lck);
}

static void
nlm_nsm_clnt_init(CLIENT *clnt, struct nlm_nsm *nsm)
{
	(void) clnt_tli_kinit(clnt, &nsm->ns_knc, &nsm->ns_addr, 0,
	    NLM_RPC_RETRIES, kcred);
}

static void
nlm_netbuf_to_netobj(struct netbuf *addr, int *family, netobj *obj)
{
	/* LINTED pointer alignment */
	struct sockaddr *sa = (struct sockaddr *)addr->buf;

	*family = sa->sa_family;

	switch (sa->sa_family) {
	case AF_INET: {
		/* LINTED pointer alignment */
		struct sockaddr_in *sin = (struct sockaddr_in *)sa;

		obj->n_len = sizeof (sin->sin_addr);
		obj->n_bytes = (char *)&sin->sin_addr;
		break;
	}

	case AF_INET6: {
		/* LINTED pointer alignment */
		struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)sa;

		obj->n_len = sizeof (sin6->sin6_addr);
		obj->n_bytes = (char *)&sin6->sin6_addr;
		break;
	}

	default:
		VERIFY(0);
		break;
	}
}
