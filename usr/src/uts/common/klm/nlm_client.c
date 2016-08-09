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
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 * Copyright (c) 2012 by Delphix. All rights reserved.
 * Copyright (c) 2014, Joyent, Inc. All rights reserved.
 */

/*
 * Client-side support for (NFS) VOP_FRLOCK, VOP_SHRLOCK.
 * (called via klmops.c: lm_frlock, lm4_frlock)
 *
 * Source code derived from FreeBSD nlm_advlock.c
 */

#include <sys/param.h>
#include <sys/fcntl.h>
#include <sys/lock.h>
#include <sys/flock.h>
#include <sys/mount.h>
#include <sys/mutex.h>
#include <sys/proc.h>
#include <sys/share.h>
#include <sys/syslog.h>
#include <sys/systm.h>
#include <sys/unistd.h>
#include <sys/vnode.h>
#include <sys/queue.h>
#include <sys/sdt.h>
#include <netinet/in.h>

#include <fs/fs_subr.h>
#include <rpcsvc/nlm_prot.h>

#include <nfs/nfs.h>
#include <nfs/nfs_clnt.h>
#include <nfs/export.h>
#include <nfs/rnode.h>
#include <nfs/lm.h>

#include "nlm_impl.h"

/* Extra flags for nlm_call_lock() - xflags */
#define	NLM_X_RECLAIM	1
#define	NLM_X_BLOCKING	2

/*
 * Max. number of retries nlm_call_cancel() does
 * when NLM server is in grace period or doesn't
 * respond correctly.
 */
#define	NLM_CANCEL_NRETRS 5

/*
 * Determines wether given lock "flp" is safe.
 * The lock is considered to be safe when it
 * acquires the whole file (i.e. its start
 * and len are zeroes).
 */
#define	NLM_FLOCK_IS_SAFE(flp) \
	((flp)->l_start == 0 && (flp)->l_len == 0)

static volatile uint32_t nlm_xid = 1;

static int nlm_init_fh_by_vp(vnode_t *, struct netobj *, rpcvers_t *);
static int nlm_map_status(nlm4_stats);
static int nlm_map_clnt_stat(enum clnt_stat);
static void nlm_send_siglost(pid_t);

static int nlm_frlock_getlk(struct nlm_host *, vnode_t *,
    struct flock64 *, int, u_offset_t, struct netobj *, int);

static int nlm_frlock_setlk(struct nlm_host *, vnode_t *,
    struct flock64 *, int, u_offset_t, struct netobj *,
    struct flk_callback *, int, bool_t);

static int nlm_reclaim_lock(struct nlm_host *, vnode_t *,
    struct flock64 *, int32_t);

static void nlm_init_lock(struct nlm4_lock *,
    const struct flock64 *, struct netobj *,
    struct nlm_owner_handle *);

static int nlm_call_lock(vnode_t *, struct flock64 *,
    struct nlm_host *, struct netobj *,
    struct flk_callback *, int, int);
static int nlm_call_unlock(struct flock64 *, struct nlm_host *,
    struct netobj *, int);
static int nlm_call_test(struct flock64 *, struct nlm_host *,
    struct netobj *, int);
static int nlm_call_cancel(struct nlm4_lockargs *,
    struct nlm_host *, int);

static int nlm_local_getlk(vnode_t *, struct flock64 *, int);
static int nlm_local_setlk(vnode_t *, struct flock64 *, int);
static void nlm_local_cancelk(vnode_t *, struct flock64 *);

static void nlm_init_share(struct nlm4_share *,
    const struct shrlock *, struct netobj *);

static int nlm_call_share(struct shrlock *, struct nlm_host *,
    struct netobj *, int, int);
static int nlm_call_unshare(struct shrlock *, struct nlm_host *,
    struct netobj *, int);
static int nlm_reclaim_share(struct nlm_host *, vnode_t *,
    struct shrlock *, uint32_t);
static int nlm_local_shrlock(vnode_t *, struct shrlock *, int, int);
static void nlm_local_shrcancel(vnode_t *, struct shrlock *);

/*
 * Reclaim locks/shares acquired by the client side
 * on the given server represented by hostp.
 * The function is called from a dedicated thread
 * when server reports us that it's entered grace
 * period.
 */
void
nlm_reclaim_client(struct nlm_globals *g, struct nlm_host *hostp)
{
	int32_t state;
	int error, sysid;
	struct locklist *llp_head, *llp;
	struct nlm_shres *nsp_head, *nsp;
	bool_t restart;

	sysid = hostp->nh_sysid | LM_SYSID_CLIENT;
	do {
		error = 0;
		restart = FALSE;
		state = nlm_host_get_state(hostp);

		DTRACE_PROBE3(reclaim__iter, struct nlm_globals *, g,
		    struct nlm_host *, hostp, int, state);

		/*
		 * We cancel all sleeping locks that were
		 * done by the host, because we don't allow
		 * reclamation of sleeping locks. The reason
		 * we do this is that allowing of sleeping locks
		 * reclamation can potentially break locks recovery
		 * order.
		 *
		 * Imagine that we have two client machines A and B
		 * and an NLM server machine. A adds a non sleeping
		 * lock to the file F and aquires this file. Machine
		 * B in its turn adds sleeping lock to the file
		 * F and blocks because F is already aquired by
		 * the machine A. Then server crashes and after the
		 * reboot it notifies its clients about the crash.
		 * If we would allow sleeping locks reclamation,
		 * there would be possible that machine B recovers
		 * its lock faster than machine A (by some reason).
		 * So that B aquires the file F after server crash and
		 * machine A (that by some reason recovers slower) fails
		 * to recover its non sleeping lock. Thus the original
		 * locks order becames broken.
		 */
		nlm_host_cancel_slocks(g, hostp);

		/*
		 * Try to reclaim all active locks we have
		 */
		llp_head = llp = flk_get_active_locks(sysid, NOPID);
		while (llp != NULL) {
			error = nlm_reclaim_lock(hostp, llp->ll_vp,
			    &llp->ll_flock, state);

			if (error == 0) {
				llp = llp->ll_next;
				continue;
			} else if (error == ERESTART) {
				restart = TRUE;
				break;
			} else {
				/*
				 * Critical error occurred, the lock
				 * can not be recovered, just take it away.
				 */
				nlm_local_cancelk(llp->ll_vp, &llp->ll_flock);
			}

			llp = llp->ll_next;
		}

		flk_free_locklist(llp_head);
		if (restart) {
			/*
			 * Lock reclamation fucntion reported us that
			 * the server state was changed (again), so
			 * try to repeat the whole reclamation process.
			 */
			continue;
		}

		nsp_head = nsp = nlm_get_active_shres(hostp);
		while (nsp != NULL) {
			error = nlm_reclaim_share(hostp, nsp->ns_vp,
			    nsp->ns_shr, state);

			if (error == 0) {
				nsp = nsp->ns_next;
				continue;
			} else if (error == ERESTART) {
				break;
			} else {
				/* Failed to reclaim share */
				nlm_shres_untrack(hostp, nsp->ns_vp,
				    nsp->ns_shr);
				nlm_local_shrcancel(nsp->ns_vp,
				    nsp->ns_shr);
			}

			nsp = nsp->ns_next;
		}

		nlm_free_shrlist(nsp_head);
	} while (state != nlm_host_get_state(hostp));
}

/*
 * nlm_frlock --
 *      NFS advisory byte-range locks.
 *	Called in klmops.c
 *
 * Note that the local locking code (os/flock.c) is used to
 * keep track of remote locks granted by some server, so we
 * can reclaim those locks after a server restarts.  We can
 * also sometimes use this as a cache of lock information.
 *
 * Was: nlm_advlock()
 */
/* ARGSUSED */
int
nlm_frlock(struct vnode *vp, int cmd, struct flock64 *flkp,
    int flags, u_offset_t offset, struct cred *crp,
    struct netobj *fhp, struct flk_callback *flcb, int vers)
{
	mntinfo_t *mi;
	servinfo_t *sv;
	const char *netid;
	struct nlm_host *hostp;
	int error;
	struct nlm_globals *g;

	mi = VTOMI(vp);
	sv = mi->mi_curr_serv;

	netid = nlm_knc_to_netid(sv->sv_knconf);
	if (netid == NULL) {
		NLM_ERR("nlm_frlock: unknown NFS netid");
		return (ENOSYS);
	}

	g = zone_getspecific(nlm_zone_key, curzone);
	hostp = nlm_host_findcreate(g, sv->sv_hostname, netid, &sv->sv_addr);
	if (hostp == NULL)
		return (ENOSYS);

	/*
	 * Purge cached attributes in order to make sure that
	 * future calls of convoff()/VOP_GETATTR() will get the
	 * latest data.
	 */
	if (flkp->l_whence == SEEK_END)
		PURGE_ATTRCACHE(vp);

	/* Now flk0 is the zero-based lock request. */
	switch (cmd) {
	case F_GETLK:
		error = nlm_frlock_getlk(hostp, vp, flkp, flags,
		    offset, fhp, vers);
		break;

	case F_SETLK:
	case F_SETLKW:
		error = nlm_frlock_setlk(hostp, vp, flkp, flags,
		    offset, fhp, flcb, vers, (cmd == F_SETLKW));
		if (error == 0)
			nlm_host_monitor(g, hostp, 0);
		break;

	default:
		error = EINVAL;
		break;
	}

	nlm_host_release(g, hostp);
	return (error);
}

static int
nlm_frlock_getlk(struct nlm_host *hostp, vnode_t *vp,
    struct flock64 *flkp, int flags, u_offset_t offset,
    struct netobj *fhp, int vers)
{
	struct flock64 flk0;
	int error;

	/*
	 * Check local (cached) locks first.
	 * If we find one, no need for RPC.
	 */
	flk0 = *flkp;
	flk0.l_pid = curproc->p_pid;
	error = nlm_local_getlk(vp, &flk0, flags);
	if (error != 0)
		return (error);
	if (flk0.l_type != F_UNLCK) {
		*flkp = flk0;
		return (0);
	}

	/* Not found locally.  Try remote. */
	flk0 = *flkp;
	flk0.l_pid = curproc->p_pid;
	error = convoff(vp, &flk0, 0, (offset_t)offset);
	if (error != 0)
		return (error);

	error = nlm_call_test(&flk0, hostp, fhp, vers);
	if (error != 0)
		return (error);

	if (flk0.l_type == F_UNLCK) {
		/*
		 * Update the caller's *flkp with information
		 * on the conflicting lock (or lack thereof).
		 */
		flkp->l_type = F_UNLCK;
	} else {
		/*
		 * Found a conflicting lock.  Set the
		 * caller's *flkp with the info, first
		 * converting to the caller's whence.
		 */
		(void) convoff(vp, &flk0, flkp->l_whence, (offset_t)offset);
		*flkp = flk0;
	}

	return (0);
}

static int
nlm_frlock_setlk(struct nlm_host *hostp, vnode_t *vp,
    struct flock64 *flkp, int flags, u_offset_t offset,
    struct netobj *fhp, struct flk_callback *flcb,
    int vers, bool_t do_block)
{
	int error, xflags;

	error = convoff(vp, flkp, 0, (offset_t)offset);
	if (error != 0)
		return (error);

	/*
	 * NFS v2 clients should not request locks where any part
	 * of the lock range is beyond 0xffffffff.  The NFS code
	 * checks that (see nfs_frlock, flk_check_lock_data), but
	 * as that's outside this module, let's check here too.
	 * This check ensures that we will be able to convert this
	 * lock request into 32-bit form without change, and that
	 * (more importantly) when the granted call back arrives,
	 * it's unchanged when converted back into 64-bit form.
	 * If this lock range were to change in any way during
	 * either of those conversions, the "granted" call back
	 * from the NLM server would not find our sleeping lock.
	 */
	if (vers < NLM4_VERS) {
		if (flkp->l_start > MAX_UOFF32 ||
		    flkp->l_start + flkp->l_len > MAX_UOFF32 + 1)
			return (EINVAL);
	}

	/*
	 * Fill in l_sysid for the local locking calls.
	 * Also, let's not trust the caller's l_pid.
	 */
	flkp->l_sysid = hostp->nh_sysid | LM_SYSID_CLIENT;
	flkp->l_pid = curproc->p_pid;

	if (flkp->l_type == F_UNLCK) {
		/*
		 * Purge local (cached) lock information first,
		 * then clear the remote lock.
		 */
		(void) nlm_local_setlk(vp, flkp, flags);
		error = nlm_call_unlock(flkp, hostp, fhp, vers);

		return (error);
	}

	if (!do_block) {
		/*
		 * This is a non-blocking "set" request,
		 * so we can check locally first, and
		 * sometimes avoid an RPC call.
		 */
		struct flock64 flk0;

		flk0 = *flkp;
		error = nlm_local_getlk(vp, &flk0, flags);
		if (error != 0 && flk0.l_type != F_UNLCK) {
			/* Found a conflicting lock. */
			return (EAGAIN);
		}

		xflags = 0;
	} else {
		xflags = NLM_X_BLOCKING;
	}

	nfs_add_locking_id(vp, curproc->p_pid, RLMPL_PID,
	    (char *)&curproc->p_pid, sizeof (pid_t));

	error = nlm_call_lock(vp, flkp, hostp, fhp, flcb, vers, xflags);
	if (error != 0)
		return (error);

	/*
	 * Save the lock locally.  This should not fail,
	 * because the server is authoritative about locks
	 * and it just told us we have the lock!
	 */
	error = nlm_local_setlk(vp, flkp, flags);
	if (error != 0) {
		/*
		 * That's unexpected situation. Just ignore the error.
		 */
		NLM_WARN("nlm_frlock_setlk: Failed to set local lock. "
		    "[err=%d]\n", error);
		error = 0;
	}

	return (error);
}

/*
 * Cancel all client side remote locks/shares on the
 * given host. Report to the processes that own
 * cancelled locks that they are removed by force
 * by sending SIGLOST.
 */
void
nlm_client_cancel_all(struct nlm_globals *g, struct nlm_host *hostp)
{
	struct locklist *llp_head, *llp;
	struct nlm_shres *nsp_head, *nsp;
	struct netobj lm_fh;
	rpcvers_t vers;
	int error, sysid;

	sysid = hostp->nh_sysid | LM_SYSID_CLIENT;
	nlm_host_cancel_slocks(g, hostp);

	/*
	 * Destroy all active locks
	 */
	llp_head = llp = flk_get_active_locks(sysid, NOPID);
	while (llp != NULL) {
		llp->ll_flock.l_type = F_UNLCK;

		error = nlm_init_fh_by_vp(llp->ll_vp, &lm_fh, &vers);
		if (error == 0)
			(void) nlm_call_unlock(&llp->ll_flock, hostp,
			    &lm_fh, vers);

		nlm_local_cancelk(llp->ll_vp, &llp->ll_flock);
		llp = llp->ll_next;
	}

	flk_free_locklist(llp_head);

	/*
	 * Destroy all active share reservations
	 */
	nsp_head = nsp = nlm_get_active_shres(hostp);
	while (nsp != NULL) {
		error = nlm_init_fh_by_vp(nsp->ns_vp, &lm_fh, &vers);
		if (error == 0)
			(void) nlm_call_unshare(nsp->ns_shr, hostp,
			    &lm_fh, vers);

		nlm_local_shrcancel(nsp->ns_vp, nsp->ns_shr);
		nlm_shres_untrack(hostp, nsp->ns_vp, nsp->ns_shr);
		nsp = nsp->ns_next;
	}

	nlm_free_shrlist(nsp_head);
}

/*
 * The function determines whether the lock "fl" can
 * be safely applied to the file vnode "vp" corresponds to.
 * The lock can be "safely" applied if all the conditions
 * above are held:
 *  - It's not a mandatory lock
 *  - The vnode wasn't mapped by anyone
 *  - The vnode was mapped, but it hasn't any locks on it.
 *  - The vnode was mapped and all locks it has occupies
 *    the whole file.
 */
int
nlm_safelock(vnode_t *vp, const struct flock64 *fl, cred_t *cr)
{
	rnode_t *rp = VTOR(vp);
	struct vattr va;
	int err;

	if ((rp->r_mapcnt > 0) && (fl->l_start != 0 || fl->l_len != 0))
		return (0);

	va.va_mask = AT_MODE;
	err = VOP_GETATTR(vp, &va, 0, cr, NULL);
	if (err != 0)
		return (0);

	/* NLM4 doesn't allow mandatory file locking */
	if (MANDLOCK(vp, va.va_mode))
		return (0);

	return (1);
}

/*
 * The function determines whether it's safe to map
 * a file correspoding to vnode vp.
 * The mapping is considered to be "safe" if file
 * either has no any locks on it or all locks it
 * has occupy the whole file.
 */
int
nlm_safemap(const vnode_t *vp)
{
	struct locklist *llp, *llp_next;
	struct nlm_slock *nslp;
	struct nlm_globals *g;
	int safe = 1;

	/* Check active locks at first */
	llp = flk_active_locks_for_vp(vp);
	while (llp != NULL) {
		if ((llp->ll_vp == vp) &&
		    !NLM_FLOCK_IS_SAFE(&llp->ll_flock))
			safe = 0;

		llp_next = llp->ll_next;
		VN_RELE(llp->ll_vp);
		kmem_free(llp, sizeof (*llp));
		llp = llp_next;
	}
	if (!safe)
		return (safe);

	/* Then check sleeping locks if any */
	g = zone_getspecific(nlm_zone_key, curzone);
	mutex_enter(&g->lock);
	TAILQ_FOREACH(nslp, &g->nlm_slocks, nsl_link) {
		if (nslp->nsl_state == NLM_SL_BLOCKED &&
		    nslp->nsl_vp == vp &&
		    (nslp->nsl_lock.l_offset != 0 ||
		    nslp->nsl_lock.l_len != 0)) {
			safe = 0;
			break;
		}
	}

	mutex_exit(&g->lock);
	return (safe);
}

int
nlm_has_sleep(const vnode_t *vp)
{
	struct nlm_globals *g;
	struct nlm_slock *nslp;
	int has_slocks = FALSE;

	g = zone_getspecific(nlm_zone_key, curzone);
	mutex_enter(&g->lock);
	TAILQ_FOREACH(nslp, &g->nlm_slocks, nsl_link) {
		if (nslp->nsl_state == NLM_SL_BLOCKED &&
		    nslp->nsl_vp == vp) {
			has_slocks = TRUE;
			break;
		}
	}

	mutex_exit(&g->lock);
	return (has_slocks);
}

void
nlm_register_lock_locally(struct vnode *vp, struct nlm_host *hostp,
    struct flock64 *flk, int flags, u_offset_t offset)
{
	struct nlm_globals *g = NULL;
	int sysid = 0;

	if (hostp == NULL) {
		mntinfo_t *mi;
		servinfo_t *sv;
		const char *netid;

		mi = VTOMI(vp);
		sv = mi->mi_curr_serv;
		netid = nlm_knc_to_netid(sv->sv_knconf);

		if (netid != NULL) {
			g = zone_getspecific(nlm_zone_key, curzone);
			hostp = nlm_host_findcreate(g, sv->sv_hostname,
			    netid, &sv->sv_addr);
		}
	}

	if (hostp != NULL) {
		sysid = hostp->nh_sysid | LM_SYSID_CLIENT;

		if (g != NULL)
			nlm_host_release(g, hostp);
	}

	flk->l_sysid = sysid;
	(void) convoff(vp, flk, 0, (offset_t)offset);
	(void) nlm_local_setlk(vp, flk, flags);
}


/*
 * The BSD code had functions here to "reclaim" (destroy)
 * remote locks when a vnode is being forcibly destroyed.
 * We just keep vnodes around until statd tells us the
 * client has gone away.
 */

static int
nlm_reclaim_lock(struct nlm_host *hostp, vnode_t *vp,
    struct flock64 *flp, int32_t orig_state)
{
	struct netobj lm_fh;
	int error, state;
	rpcvers_t vers;

	/*
	 * If the remote NSM state changes during recovery, the host
	 * must have rebooted a second time. In that case, we must
	 * restart the recovery.
	 */
	state = nlm_host_get_state(hostp);
	if (state != orig_state)
		return (ERESTART);

	error = nlm_init_fh_by_vp(vp, &lm_fh, &vers);
	if (error != 0)
		return (error);

	return (nlm_call_lock(vp, flp, hostp, &lm_fh,
	    NULL, vers, NLM_X_RECLAIM));
}

/*
 * Get local lock information for some NFS server.
 *
 * This gets (checks for) a local conflicting lock.
 * Note: Modifies passed flock, if a conflict is found,
 * but the caller expects that.
 */
static int
nlm_local_getlk(vnode_t *vp, struct flock64 *fl, int flags)
{
	VERIFY(fl->l_whence == SEEK_SET);
	return (reclock(vp, fl, 0, flags, 0, NULL));
}

/*
 * Set local lock information for some NFS server.
 *
 * Called after a lock request (set or clear) succeeded. We record the
 * details in the local lock manager. Note that since the remote
 * server has granted the lock, we can be sure that it doesn't
 * conflict with any other locks we have in the local lock manager.
 *
 * Since it is possible that host may also make NLM client requests to
 * our NLM server, we use a different sysid value to record our own
 * client locks.
 *
 * Note that since it is possible for us to receive replies from the
 * server in a different order than the locks were granted (e.g. if
 * many local threads are contending for the same lock), we must use a
 * blocking operation when registering with the local lock manager.
 * We expect that any actual wait will be rare and short hence we
 * ignore signals for this.
 */
static int
nlm_local_setlk(vnode_t *vp, struct flock64 *fl, int flags)
{
	VERIFY(fl->l_whence == SEEK_SET);
	return (reclock(vp, fl, SETFLCK, flags, 0, NULL));
}

/*
 * Cancel local lock and send send SIGLOST signal
 * to the lock owner.
 *
 * NOTE: modifies flp
 */
static void
nlm_local_cancelk(vnode_t *vp, struct flock64 *flp)
{
	flp->l_type = F_UNLCK;
	(void) nlm_local_setlk(vp, flp, FREAD | FWRITE);
	nlm_send_siglost(flp->l_pid);
}

/*
 * Do NLM_LOCK call.
 * Was: nlm_setlock()
 *
 * NOTE: nlm_call_lock() function should care about locking/unlocking
 * of rnode->r_lkserlock which should be released before nlm_call_lock()
 * sleeps on waiting lock and acquired when it wakes up.
 */
static int
nlm_call_lock(vnode_t *vp, struct flock64 *flp,
    struct nlm_host *hostp, struct netobj *fhp,
    struct flk_callback *flcb, int vers, int xflags)
{
	struct nlm4_lockargs args;
	struct nlm_owner_handle oh;
	struct nlm_globals *g;
	rnode_t *rnp = VTOR(vp);
	struct nlm_slock *nslp = NULL;
	uint32_t xid;
	int error = 0;

	bzero(&args, sizeof (args));
	g = zone_getspecific(nlm_zone_key, curzone);
	nlm_init_lock(&args.alock, flp, fhp, &oh);

	args.exclusive = (flp->l_type == F_WRLCK);
	args.reclaim = xflags & NLM_X_RECLAIM;
	args.state = g->nsm_state;
	args.cookie.n_len = sizeof (xid);
	args.cookie.n_bytes = (char *)&xid;

	oh.oh_sysid = hostp->nh_sysid;
	xid = atomic_inc_32_nv(&nlm_xid);

	if (xflags & NLM_X_BLOCKING) {
		args.block = TRUE;
		nslp = nlm_slock_register(g, hostp, &args.alock, vp);
	}

	for (;;) {
		nlm_rpc_t *rpcp;
		enum clnt_stat stat;
		struct nlm4_res res;
		enum nlm4_stats nlm_err;

		error = nlm_host_get_rpc(hostp, vers, &rpcp);
		if (error != 0) {
			error = ENOLCK;
			goto out;
		}

		bzero(&res, sizeof (res));
		stat = nlm_lock_rpc(&args, &res, rpcp->nr_handle, vers);
		nlm_host_rele_rpc(hostp, rpcp);

		error = nlm_map_clnt_stat(stat);
		if (error != 0) {
			if (error == EAGAIN)
				continue;

			goto out;
		}

		DTRACE_PROBE1(lock__res, enum nlm4_stats, res.stat.stat);
		nlm_err = res.stat.stat;
		xdr_free((xdrproc_t)xdr_nlm4_res, (void *)&res);
		if (nlm_err == nlm4_denied_grace_period) {
			if (args.reclaim) {
				error = ENOLCK;
				goto out;
			}

			error = nlm_host_wait_grace(hostp);
			if (error != 0)
				goto out;

			continue;
		}

		switch (nlm_err) {
		case nlm4_granted:
		case nlm4_blocked:
			error = 0;
			break;

		case nlm4_denied:
			if (nslp != NULL) {
				NLM_WARN("nlm_call_lock: got nlm4_denied for "
				    "blocking lock\n");
			}

			error = EAGAIN;
			break;

		default:
			error = nlm_map_status(nlm_err);
		}

		/*
		 * If we deal with either non-blocking lock or
		 * with a blocking locks that wasn't blocked on
		 * the server side (by some reason), our work
		 * is finished.
		 */
		if (nslp == NULL			||
		    nlm_err != nlm4_blocked		||
		    error != 0)
			goto out;

		/*
		 * Before releasing the r_lkserlock of rnode, we should
		 * check whether the new lock is "safe". If it's not
		 * safe, disable caching for the given vnode. That is done
		 * for sleeping locks only that are waiting for a GRANT reply
		 * from the NLM server.
		 *
		 * NOTE: the vnode cache can be enabled back later if an
		 * unsafe lock will be merged with existent locks so that
		 * it will become safe. This condition is checked in the
		 * NFSv3 code (see nfs_lockcompletion).
		 */
		if (!NLM_FLOCK_IS_SAFE(flp)) {
			mutex_enter(&vp->v_lock);
			vp->v_flag &= ~VNOCACHE;
			mutex_exit(&vp->v_lock);
		}

		/*
		 * The server should call us back with a
		 * granted message when the lock succeeds.
		 * In order to deal with broken servers,
		 * lost granted messages, or server reboots,
		 * we will also re-try every few seconds.
		 *
		 * Note: We're supposed to call these
		 * flk_invoke_callbacks when blocking.
		 * Take care on rnode->r_lkserlock, we should
		 * release it before going to sleep.
		 */
		(void) flk_invoke_callbacks(flcb, FLK_BEFORE_SLEEP);
		nfs_rw_exit(&rnp->r_lkserlock);

		error = nlm_slock_wait(g, nslp, g->retrans_tmo);

		/*
		 * NFS expects that we return with rnode->r_lkserlock
		 * locked on write, lock it back.
		 *
		 * NOTE: nfs_rw_enter_sig() can be either interruptible
		 * or not. It depends on options of NFS mount. Here
		 * we're _always_ uninterruptible (independently of mount
		 * options), because nfs_frlock/nfs3_frlock expects that
		 * we return with rnode->r_lkserlock acquired. So we don't
		 * want our lock attempt to be interrupted by a signal.
		 */
		(void) nfs_rw_enter_sig(&rnp->r_lkserlock, RW_WRITER, 0);
		(void) flk_invoke_callbacks(flcb, FLK_AFTER_SLEEP);

		if (error == 0) {
			break;
		} else if (error == EINTR) {
			/*
			 * We need to call the server to cancel our
			 * lock request.
			 */
			DTRACE_PROBE1(cancel__lock, int, error);
			(void) nlm_call_cancel(&args, hostp, vers);
			break;
		} else {
			/*
			 * Timeout happened, resend the lock request to
			 * the server. Well, we're a bit paranoid here,
			 * but keep in mind previous request could lost
			 * (especially with conectionless transport).
			 */

			ASSERT(error == ETIMEDOUT);
			continue;
		}
	}

	/*
	 * We could disable the vnode cache for the given _sleeping_
	 * (codition: nslp != NULL) lock if it was unsafe. Normally,
	 * nfs_lockcompletion() function can enable the vnode cache
	 * back if the lock becomes safe after activativation. But it
	 * will not happen if any error occurs on the locking path.
	 *
	 * Here we enable the vnode cache back if the error occurred
	 * and if there aren't any unsafe locks on the given vnode.
	 * Note that if error happened, sleeping lock was derigistered.
	 */
	if (error != 0 && nslp != NULL && nlm_safemap(vp)) {
		mutex_enter(&vp->v_lock);
		vp->v_flag |= VNOCACHE;
		mutex_exit(&vp->v_lock);
	}

out:
	if (nslp != NULL)
		nlm_slock_unregister(g, nslp);

	return (error);
}

/*
 * Do NLM_CANCEL call.
 * Helper for nlm_call_lock() error recovery.
 */
static int
nlm_call_cancel(struct nlm4_lockargs *largs,
    struct nlm_host *hostp, int vers)
{
	nlm4_cancargs cargs;
	uint32_t xid;
	int error, retries;

	bzero(&cargs, sizeof (cargs));

	xid = atomic_inc_32_nv(&nlm_xid);
	cargs.cookie.n_len = sizeof (xid);
	cargs.cookie.n_bytes = (char *)&xid;
	cargs.block	= largs->block;
	cargs.exclusive	= largs->exclusive;
	cargs.alock	= largs->alock;

	/*
	 * Unlike all other nlm_call_* functions, nlm_call_cancel
	 * doesn't spin forever until it gets reasonable response
	 * from NLM server. It makes limited number of retries and
	 * if server doesn't send a reasonable reply, it returns an
	 * error. It behaves like that because it's called from nlm_call_lock
	 * with blocked signals and thus it can not be interrupted from
	 * user space.
	 */
	for (retries = 0; retries < NLM_CANCEL_NRETRS; retries++) {
		nlm_rpc_t *rpcp;
		enum clnt_stat stat;
		struct nlm4_res res;

		error = nlm_host_get_rpc(hostp, vers, &rpcp);
		if (error != 0)
			return (ENOLCK);

		bzero(&res, sizeof (res));
		stat = nlm_cancel_rpc(&cargs, &res, rpcp->nr_handle, vers);
		nlm_host_rele_rpc(hostp, rpcp);

		DTRACE_PROBE1(cancel__rloop_end, enum clnt_stat, stat);
		error = nlm_map_clnt_stat(stat);
		if (error != 0) {
			if (error == EAGAIN)
				continue;

			return (error);
		}

		DTRACE_PROBE1(cancel__res, enum nlm4_stats, res.stat.stat);
		switch (res.stat.stat) {
			/*
			 * There was nothing to cancel. We are going to go ahead
			 * and assume we got the lock.
			 */
		case nlm_denied:
			/*
			 * The server has recently rebooted.  Treat this as a
			 * successful cancellation.
			 */
		case nlm4_denied_grace_period:
			/*
			 * We managed to cancel.
			 */
		case nlm4_granted:
			error = 0;
			break;

		default:
			/*
			 * Broken server implementation.  Can't really do
			 * anything here.
			 */
			error = EIO;
			break;
		}

		xdr_free((xdrproc_t)xdr_nlm4_res, (void *)&res);
		break;
	}

	return (error);
}

/*
 * Do NLM_UNLOCK call.
 * Was: nlm_clearlock
 */
static int
nlm_call_unlock(struct flock64 *flp, struct nlm_host *hostp,
    struct netobj *fhp, int vers)
{
	struct nlm4_unlockargs args;
	struct nlm_owner_handle oh;
	enum nlm4_stats nlm_err;
	uint32_t xid;
	int error;

	bzero(&args, sizeof (args));
	nlm_init_lock(&args.alock, flp, fhp, &oh);

	oh.oh_sysid = hostp->nh_sysid;
	xid = atomic_inc_32_nv(&nlm_xid);
	args.cookie.n_len = sizeof (xid);
	args.cookie.n_bytes = (char *)&xid;

	for (;;) {
		nlm_rpc_t *rpcp;
		struct nlm4_res res;
		enum clnt_stat stat;

		error = nlm_host_get_rpc(hostp, vers, &rpcp);
		if (error != 0)
			return (ENOLCK);

		bzero(&res, sizeof (res));
		stat = nlm_unlock_rpc(&args, &res, rpcp->nr_handle, vers);
		nlm_host_rele_rpc(hostp, rpcp);

		error = nlm_map_clnt_stat(stat);
		if (error != 0) {
			if (error == EAGAIN)
				continue;

			return (error);
		}

		DTRACE_PROBE1(unlock__res, enum nlm4_stats, res.stat.stat);
		nlm_err = res.stat.stat;
		xdr_free((xdrproc_t)xdr_nlm4_res, (void *)&res);
		if (nlm_err == nlm4_denied_grace_period) {
			error = nlm_host_wait_grace(hostp);
			if (error != 0)
				return (error);

			continue;
		}

		break;
	}

	/* special cases */
	switch (nlm_err) {
	case nlm4_denied:
		error = EINVAL;
		break;
	default:
		error = nlm_map_status(nlm_err);
		break;
	}

	return (error);
}

/*
 * Do NLM_TEST call.
 * Was: nlm_getlock()
 */
static int
nlm_call_test(struct flock64 *flp, struct nlm_host *hostp,
    struct netobj *fhp, int vers)
{
	struct nlm4_testargs args;
	struct nlm4_holder h;
	struct nlm_owner_handle oh;
	enum nlm4_stats nlm_err;
	uint32_t xid;
	int error;

	bzero(&args, sizeof (args));
	nlm_init_lock(&args.alock, flp, fhp, &oh);

	args.exclusive = (flp->l_type == F_WRLCK);
	oh.oh_sysid = hostp->nh_sysid;
	xid = atomic_inc_32_nv(&nlm_xid);
	args.cookie.n_len = sizeof (xid);
	args.cookie.n_bytes = (char *)&xid;

	for (;;) {
		nlm_rpc_t *rpcp;
		struct nlm4_testres res;
		enum clnt_stat stat;

		error = nlm_host_get_rpc(hostp, vers, &rpcp);
		if (error != 0)
			return (ENOLCK);

		bzero(&res, sizeof (res));
		stat = nlm_test_rpc(&args, &res, rpcp->nr_handle, vers);
		nlm_host_rele_rpc(hostp, rpcp);

		error = nlm_map_clnt_stat(stat);
		if (error != 0) {
			if (error == EAGAIN)
				continue;

			return (error);
		}

		DTRACE_PROBE1(test__res, enum nlm4_stats, res.stat.stat);
		nlm_err = res.stat.stat;
		bcopy(&res.stat.nlm4_testrply_u.holder, &h, sizeof (h));
		xdr_free((xdrproc_t)xdr_nlm4_testres, (void *)&res);
		if (nlm_err == nlm4_denied_grace_period) {
			error = nlm_host_wait_grace(hostp);
			if (error != 0)
				return (error);

			continue;
		}

		break;
	}

	switch (nlm_err) {
	case nlm4_granted:
		flp->l_type = F_UNLCK;
		error = 0;
		break;

	case nlm4_denied:
		flp->l_start = h.l_offset;
		flp->l_len = h.l_len;
		flp->l_pid = h.svid;
		flp->l_type = (h.exclusive) ? F_WRLCK : F_RDLCK;
		flp->l_whence = SEEK_SET;
		flp->l_sysid = 0;
		error = 0;
		break;

	default:
		error = nlm_map_status(nlm_err);
		break;
	}

	return (error);
}


static void
nlm_init_lock(struct nlm4_lock *lock,
    const struct flock64 *fl, struct netobj *fh,
    struct nlm_owner_handle *oh)
{

	/* Caller converts to zero-base. */
	VERIFY(fl->l_whence == SEEK_SET);
	bzero(lock, sizeof (*lock));
	bzero(oh, sizeof (*oh));

	lock->caller_name = uts_nodename();
	lock->fh.n_len = fh->n_len;
	lock->fh.n_bytes = fh->n_bytes;
	lock->oh.n_len = sizeof (*oh);
	lock->oh.n_bytes = (void *)oh;
	lock->svid = fl->l_pid;
	lock->l_offset = fl->l_start;
	lock->l_len = fl->l_len;
}

/* ************************************************************** */

int
nlm_shrlock(struct vnode *vp, int cmd, struct shrlock *shr,
    int flags, struct netobj *fh, int vers)
{
	struct shrlock shlk;
	mntinfo_t *mi;
	servinfo_t *sv;
	const char *netid;
	struct nlm_host *host = NULL;
	int error;
	struct nlm_globals *g;

	mi = VTOMI(vp);
	sv = mi->mi_curr_serv;

	netid = nlm_knc_to_netid(sv->sv_knconf);
	if (netid == NULL) {
		NLM_ERR("nlm_shrlock: unknown NFS netid\n");
		return (ENOSYS);
	}

	g = zone_getspecific(nlm_zone_key, curzone);
	host = nlm_host_findcreate(g, sv->sv_hostname, netid, &sv->sv_addr);
	if (host == NULL)
		return (ENOSYS);

	/*
	 * Fill in s_sysid for the local locking calls.
	 * Also, let's not trust the caller's l_pid.
	 */
	shlk = *shr;
	shlk.s_sysid = host->nh_sysid | LM_SYSID_CLIENT;
	shlk.s_pid = curproc->p_pid;

	if (cmd == F_UNSHARE) {
		/*
		 * Purge local (cached) share information first,
		 * then clear the remote share.
		 */
		(void) nlm_local_shrlock(vp, &shlk, cmd, flags);
		nlm_shres_untrack(host, vp, &shlk);
		error = nlm_call_unshare(&shlk, host, fh, vers);
		goto out;
	}

	nfs_add_locking_id(vp, curproc->p_pid, RLMPL_OWNER,
	    shr->s_owner, shr->s_own_len);

	error = nlm_call_share(&shlk, host, fh, vers, FALSE);
	if (error != 0)
		goto out;

	/*
	 * Save the share locally.  This should not fail,
	 * because the server is authoritative about shares
	 * and it just told us we have the share reservation!
	 */
	error = nlm_local_shrlock(vp, shr, cmd, flags);
	if (error != 0) {
		/*
		 * Oh oh, we really don't expect an error here.
		 */
		NLM_WARN("nlm_shrlock: set locally, err %d\n", error);
		error = 0;
	}

	nlm_shres_track(host, vp, &shlk);
	nlm_host_monitor(g, host, 0);

out:
	nlm_host_release(g, host);

	return (error);
}

static int
nlm_reclaim_share(struct nlm_host *hostp, vnode_t *vp,
    struct shrlock *shr, uint32_t orig_state)
{
	struct netobj lm_fh;
	int error, state;
	rpcvers_t vers;

	state = nlm_host_get_state(hostp);
	if (state != orig_state) {
		/*
		 * It seems that NLM server rebooted while
		 * we were busy with recovery.
		 */
		return (ERESTART);
	}

	error = nlm_init_fh_by_vp(vp, &lm_fh, &vers);
	if (error != 0)
		return (error);

	return (nlm_call_share(shr, hostp, &lm_fh, vers, 1));
}

/*
 * Set local share information for some NFS server.
 *
 * Called after a share request (set or clear) succeeded. We record
 * the details in the local lock manager. Note that since the remote
 * server has granted the share, we can be sure that it doesn't
 * conflict with any other shares we have in the local lock manager.
 *
 * Since it is possible that host may also make NLM client requests to
 * our NLM server, we use a different sysid value to record our own
 * client shares.
 */
int
nlm_local_shrlock(vnode_t *vp, struct shrlock *shr, int cmd, int flags)
{
	return (fs_shrlock(vp, cmd, shr, flags, CRED(), NULL));
}

static void
nlm_local_shrcancel(vnode_t *vp, struct shrlock *shr)
{
	(void) nlm_local_shrlock(vp, shr, F_UNSHARE, FREAD | FWRITE);
	nlm_send_siglost(shr->s_pid);
}

/*
 * Do NLM_SHARE call.
 * Was: nlm_setshare()
 */
static int
nlm_call_share(struct shrlock *shr, struct nlm_host *host,
    struct netobj *fh, int vers, int reclaim)
{
	struct nlm4_shareargs args;
	enum nlm4_stats nlm_err;
	uint32_t xid;
	int error;

	bzero(&args, sizeof (args));
	nlm_init_share(&args.share, shr, fh);

	args.reclaim = reclaim;
	xid = atomic_inc_32_nv(&nlm_xid);
	args.cookie.n_len = sizeof (xid);
	args.cookie.n_bytes = (char *)&xid;


	for (;;) {
		nlm_rpc_t *rpcp;
		struct nlm4_shareres res;
		enum clnt_stat stat;

		error = nlm_host_get_rpc(host, vers, &rpcp);
		if (error != 0)
			return (ENOLCK);

		bzero(&res, sizeof (res));
		stat = nlm_share_rpc(&args, &res, rpcp->nr_handle, vers);
		nlm_host_rele_rpc(host, rpcp);

		error = nlm_map_clnt_stat(stat);
		if (error != 0) {
			if (error == EAGAIN)
				continue;

			return (error);
		}

		DTRACE_PROBE1(share__res, enum nlm4_stats, res.stat);
		nlm_err = res.stat;
		xdr_free((xdrproc_t)xdr_nlm4_shareres, (void *)&res);
		if (nlm_err == nlm4_denied_grace_period) {
			if (args.reclaim)
				return (ENOLCK);

			error = nlm_host_wait_grace(host);
			if (error != 0)
				return (error);

			continue;
		}

		break;
	}

	switch (nlm_err) {
	case nlm4_granted:
		error = 0;
		break;
	case nlm4_blocked:
	case nlm4_denied:
		error = EAGAIN;
		break;
	case nlm4_denied_nolocks:
	case nlm4_deadlck:
		error = ENOLCK;
		break;
	default:
		error = EINVAL;
		break;
	}

	return (error);
}

/*
 * Do NLM_UNSHARE call.
 */
static int
nlm_call_unshare(struct shrlock *shr, struct nlm_host *host,
    struct netobj *fh, int vers)
{
	struct nlm4_shareargs args;
	enum nlm4_stats nlm_err;
	uint32_t xid;
	int error;

	bzero(&args, sizeof (args));
	nlm_init_share(&args.share, shr, fh);

	xid = atomic_inc_32_nv(&nlm_xid);
	args.cookie.n_len = sizeof (xid);
	args.cookie.n_bytes = (char *)&xid;

	for (;;) {
		nlm_rpc_t *rpcp;
		struct nlm4_shareres res;
		enum clnt_stat stat;

		error = nlm_host_get_rpc(host, vers, &rpcp);
		if (error != 0)
			return (ENOLCK);

		bzero(&res, sizeof (res));
		stat = nlm_unshare_rpc(&args, &res, rpcp->nr_handle, vers);
		nlm_host_rele_rpc(host, rpcp);

		error = nlm_map_clnt_stat(stat);
		if (error != 0) {
			if (error == EAGAIN)
				continue;

			return (error);
		}

		DTRACE_PROBE1(unshare__res, enum nlm4_stats, res.stat);
		nlm_err = res.stat;
		xdr_free((xdrproc_t)xdr_nlm4_res, (void *)&res);
		if (nlm_err == nlm4_denied_grace_period) {
			error = nlm_host_wait_grace(host);
			if (error != 0)
				return (error);

			continue;
		}

		break;
	}

	switch (nlm_err) {
	case nlm4_granted:
		error = 0;
		break;
	case nlm4_denied:
		error = EAGAIN;
		break;
	case nlm4_denied_nolocks:
		error = ENOLCK;
		break;
	default:
		error = EINVAL;
		break;
	}

	return (error);
}

static void
nlm_init_share(struct nlm4_share *args,
    const struct shrlock *shr, struct netobj *fh)
{

	bzero(args, sizeof (*args));

	args->caller_name = uts_nodename();
	args->fh.n_len = fh->n_len;
	args->fh.n_bytes = fh->n_bytes;
	args->oh.n_len = shr->s_own_len;
	args->oh.n_bytes = (void *)shr->s_owner;

	switch (shr->s_deny) {
	default:
	case F_NODNY:
		args->mode = fsm_DN;
		break;
	case F_RDDNY:
		args->mode = fsm_DR;
		break;
	case F_WRDNY:
		args->mode = fsm_DW;
		break;
	case F_RWDNY:
		args->mode = fsm_DRW;
		break;
	}

	switch (shr->s_access) {
	default:
	case 0:	/* seen with F_UNSHARE */
		args->access = fsa_NONE;
		break;
	case F_RDACC:
		args->access = fsa_R;
		break;
	case F_WRACC:
		args->access = fsa_W;
		break;
	case F_RWACC:
		args->access = fsa_RW;
		break;
	}
}

/*
 * Initialize filehandle according to the version
 * of NFS vnode was created on. The version of
 * NLM that can be used with given NFS version
 * is saved to lm_vers.
 */
static int
nlm_init_fh_by_vp(vnode_t *vp, struct netobj *fh, rpcvers_t *lm_vers)
{
	mntinfo_t *mi = VTOMI(vp);

	/*
	 * Too bad the NFS code doesn't just carry the FH
	 * in a netobj or a netbuf.
	 */
	switch (mi->mi_vers) {
	case NFS_V3:
		/* See nfs3_frlock() */
		*lm_vers = NLM4_VERS;
		fh->n_len = VTOFH3(vp)->fh3_length;
		fh->n_bytes = (char *)&(VTOFH3(vp)->fh3_u.data);
		break;

	case NFS_VERSION:
		/* See nfs_frlock() */
		*lm_vers = NLM_VERS;
		fh->n_len = sizeof (fhandle_t);
		/* LINTED E_BAD_PTR_CAST_ALIGN */
		fh->n_bytes = (char *)VTOFH(vp);
		break;
	default:
		return (ENOSYS);
	}

	return (0);
}

/*
 * Send SIGLOST to the process identified by pid.
 * NOTE: called when NLM decides to remove lock
 * or share reservation ownder by the process
 * by force.
 */
static void
nlm_send_siglost(pid_t pid)
{
	proc_t *p;

	mutex_enter(&pidlock);
	p = prfind(pid);
	if (p != NULL)
		psignal(p, SIGLOST);

	mutex_exit(&pidlock);
}

static int
nlm_map_clnt_stat(enum clnt_stat stat)
{
	switch (stat) {
	case RPC_SUCCESS:
		return (0);

	case RPC_TIMEDOUT:
	case RPC_PROGUNAVAIL:
		return (EAGAIN);

	case RPC_INTR:
		return (EINTR);

	default:
		return (EINVAL);
	}
}

static int
nlm_map_status(enum nlm4_stats stat)
{
	switch (stat) {
	case nlm4_granted:
		return (0);

	case nlm4_denied:
		return (EAGAIN);

	case nlm4_denied_nolocks:
		return (ENOLCK);

	case nlm4_blocked:
		return (EAGAIN);

	case nlm4_denied_grace_period:
		return (EAGAIN);

	case nlm4_deadlck:
		return (EDEADLK);

	case nlm4_rofs:
		return (EROFS);

	case nlm4_stale_fh:
		return (ESTALE);

	case nlm4_fbig:
		return (EFBIG);

	case nlm4_failed:
		return (EACCES);

	default:
		return (EINVAL);
	}
}
