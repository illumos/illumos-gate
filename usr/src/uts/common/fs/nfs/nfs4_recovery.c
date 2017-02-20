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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * NFS Version 4 state recovery code.
 */

#include <nfs/nfs4_clnt.h>
#include <nfs/nfs4.h>
#include <nfs/rnode4.h>
#include <sys/cmn_err.h>
#include <sys/cred.h>
#include <sys/systm.h>
#include <sys/flock.h>
#include <sys/dnlc.h>
#include <sys/ddi.h>
#include <sys/disp.h>
#include <sys/list.h>
#include <sys/sdt.h>
#include <sys/mount.h>
#include <sys/door.h>
#include <nfs/nfssys.h>
#include <nfs/nfsid_map.h>
#include <nfs/nfs4_idmap_impl.h>

extern r4hashq_t *rtable4;

/*
 * Information that describes what needs to be done for recovery.  It is
 * passed to a client recovery thread as well as passed to various recovery
 * routines.  rc_mi, rc_vp1, and rc_vp2 refer to the filesystem and
 * vnode(s) affected by recovery.  rc_vp1 and rc_vp2 are references (use
 * VN_HOLD) or NULL.  rc_lost_rqst contains information about the lost
 * lock or open/close request, and it holds reference counts for the
 * various objects (vnode, etc.).  The recovery thread also uses flags set
 * in the mntinfo4_t or vnode_t to tell it what to do.  rc_error is used
 * to save the error that originally triggered the recovery event -- will
 * later be used to set mi_error if recovery doesn't work.  rc_bseqid_rqst
 * contains information about the request that got NFS4ERR_BAD_SEQID, and
 * it holds reference count for the various objects (vnode, open owner,
 * open stream, lock owner).
 */

typedef struct {
	mntinfo4_t *rc_mi;
	vnode_t *rc_vp1;
	vnode_t *rc_vp2;
	nfs4_recov_t rc_action;
	stateid4 rc_stateid;
	bool_t rc_srv_reboot;		/* server has rebooted */
	nfs4_lost_rqst_t *rc_lost_rqst;
	nfs4_error_t rc_orig_errors;	/* original errors causing recovery */
	int rc_error;
	nfs4_bseqid_entry_t *rc_bseqid_rqst;
	vnode_t *rc_moved_vp;
	char *rc_moved_nm;
} recov_info_t;

/*
 * How long to wait before trying again if there is an error doing
 * recovery, in seconds.
 */

static int recov_err_delay = 1;

/*
 * How long to wait when processing NFS4ERR_GRACE or NFS4ERR_DELAY
 * errors.  Expressed in seconds.  Default is defined as
 * NFS4ERR_DELAY_TIME and this variable is initialized in nfs4_subr_init()
 */
time_t nfs4err_delay_time = 0;

/*
 * Tuneable to limit how many time "exempt" ops go OTW
 * after a recovery error.  Exempt op hints are OH_CLOSE,
 * OH_LOCKU, OH_DELEGRETURN.  These previously always went
 * OTW even after rnode was "dead" due to recovery errors.
 *
 * The tuneable below limits the number of times a start_fop
 * invocation will retry the exempt hints.  After the limit
 * is reached, nfs4_start_fop will return an error just like
 * it would for non-exempt op hints.
 */
int nfs4_max_recov_error_retry = 3;

/*
 * Number of seconds the recovery thread should pause before retry when the
 * filesystem has been forcibly unmounted.
 */

int nfs4_unmount_delay = 1;

#ifdef DEBUG

/*
 * How long to wait (in seconds) between recovery operations on a given
 * file.  Normally zero, but could be set longer for testing purposes.
 */
static int nfs4_recovdelay = 0;

/*
 * Switch that controls whether to go into the debugger when recovery
 * fails.
 */
static int nfs4_fail_recov_stop = 0;

/*
 * Tuneables to debug client namespace interaction with server
 * mount points:
 *
 *	nfs4_srvmnt_fail_cnt:
 *		number of times EACCES returned because client
 *		attempted to cross server mountpoint
 *
 *	nfs4_srvmnt_debug:
 *		trigger console printf whenever client attempts
 *		to cross server mountpoint
 */
int nfs4_srvmnt_fail_cnt = 0;
int nfs4_srvmnt_debug = 0;
#endif

extern zone_key_t	nfs4clnt_zone_key;

/* forward references, in alphabetic order */
static void close_after_open_resend(vnode_t *, cred_t *, uint32_t,
	nfs4_error_t *);
static void errs_to_action(recov_info_t *,
	nfs4_server_t *, mntinfo4_t *, stateid4 *, nfs4_lost_rqst_t *, int,
	nfs_opnum4, nfs4_bseqid_entry_t *);
static void flush_reinstate(nfs4_lost_rqst_t *);
static void free_milist(mntinfo4_t **, int);
static mntinfo4_t **make_milist(nfs4_server_t *, int *);
static int nfs4_check_recov_err(vnode_t *, nfs4_op_hint_t,
	nfs4_recov_state_t *, int, char *);
static char *nfs4_getsrvnames(mntinfo4_t *, size_t *);
static void nfs4_recov_fh_fail(vnode_t *, int, nfsstat4);
static void nfs4_recov_thread(recov_info_t *);
static void nfs4_remove_lost_rqsts(mntinfo4_t *, nfs4_server_t *);
static void nfs4_resend_lost_rqsts(recov_info_t *, nfs4_server_t *);
static cred_t *pid_to_cr(pid_t);
static void reclaim_one_lock(vnode_t *, flock64_t *, nfs4_error_t *, int *);
static void recov_bad_seqid(recov_info_t *);
static void recov_badstate(recov_info_t *, vnode_t *, nfsstat4);
static void recov_clientid(recov_info_t *, nfs4_server_t *);
static void recov_done(mntinfo4_t *, recov_info_t *);
static void recov_filehandle(nfs4_recov_t, mntinfo4_t *, vnode_t *);
static void recov_newserver(recov_info_t *, nfs4_server_t **, bool_t *);
static void recov_openfiles(recov_info_t *, nfs4_server_t *);
static void recov_stale(mntinfo4_t *, vnode_t *);
static void nfs4_free_lost_rqst(nfs4_lost_rqst_t *, nfs4_server_t *);
static void recov_throttle(recov_info_t *, vnode_t *);
static void relock_skip_pid(vnode_t *, locklist_t *, pid_t);
static void resend_lock(nfs4_lost_rqst_t *, nfs4_error_t *);
static void resend_one_op(nfs4_lost_rqst_t *, nfs4_error_t *, mntinfo4_t *,
	nfs4_server_t *);
static void save_bseqid_rqst(nfs4_bseqid_entry_t *, recov_info_t *);
static void start_recovery(recov_info_t *, mntinfo4_t *, vnode_t *, vnode_t *,
	nfs4_server_t *, vnode_t *, char *);
static void start_recovery_action(nfs4_recov_t, bool_t, mntinfo4_t *, vnode_t *,
	vnode_t *);
static int wait_for_recovery(mntinfo4_t *, nfs4_op_hint_t);

/*
 * Return non-zero if the given errno, status, and rpc status codes
 * in the nfs4_error_t indicate that client recovery is needed.
 * "stateful" indicates whether the call that got the error establishes or
 * removes state on the server (open, close, lock, unlock, delegreturn).
 */

int
nfs4_needs_recovery(nfs4_error_t *ep, bool_t stateful, vfs_t *vfsp)
{
	int recov = 0;
	mntinfo4_t *mi;

	/*
	 * Try failover if the error values justify it and if
	 * it's a failover mount.  Don't try if the mount is in
	 * progress, failures are handled explicitly by nfs4rootvp.
	 */
	if (nfs4_try_failover(ep)) {
		mi = VFTOMI4(vfsp);
		mutex_enter(&mi->mi_lock);
		recov = FAILOVER_MOUNT4(mi) && !(mi->mi_flags & MI4_MOUNTING);
		mutex_exit(&mi->mi_lock);
		if (recov)
			return (recov);
	}

	if (ep->error == EINTR || NFS4_FRC_UNMT_ERR(ep->error, vfsp)) {
		/*
		 * The server may have gotten the request, so for stateful
		 * ops we need to resynchronize and possibly back out the
		 * op.
		 */
		return (stateful);
	}
	if (ep->error != 0)
		return (0);

	/* stat values are listed alphabetically */
	/*
	 * There are two lists here: the errors for which we have code, and
	 * the errors for which we plan to have code before FCS.  For the
	 * second list, print a warning message but don't attempt recovery.
	 */
	switch (ep->stat) {
	case NFS4ERR_BADHANDLE:
	case NFS4ERR_BAD_SEQID:
	case NFS4ERR_BAD_STATEID:
	case NFS4ERR_DELAY:
	case NFS4ERR_EXPIRED:
	case NFS4ERR_FHEXPIRED:
	case NFS4ERR_GRACE:
	case NFS4ERR_OLD_STATEID:
	case NFS4ERR_RESOURCE:
	case NFS4ERR_STALE_CLIENTID:
	case NFS4ERR_STALE_STATEID:
	case NFS4ERR_WRONGSEC:
	case NFS4ERR_STALE:
		recov = 1;
		break;
#ifdef DEBUG
	case NFS4ERR_LEASE_MOVED:
	case NFS4ERR_MOVED:
		zcmn_err(VFTOMI4(vfsp)->mi_zone->zone_id,
		    CE_WARN, "!Can't yet recover from NFS status %d",
		    ep->stat);
		break;
#endif
	}

	return (recov);
}

/*
 * Some operations such as DELEGRETURN want to avoid invoking
 * recovery actions that will only mark the file dead.  If
 * better handlers are invoked for any of these errors, this
 * routine should be modified.
 */
int
nfs4_recov_marks_dead(nfsstat4 status)
{
	if (status == NFS4ERR_BAD_SEQID ||
	    status == NFS4ERR_EXPIRED ||
	    status == NFS4ERR_BAD_STATEID ||
	    status == NFS4ERR_OLD_STATEID)
		return (1);
	return (0);
}

/*
 * Transfer the state recovery information in recovp to mi's resend queue,
 * and mark mi as having a lost state request.
 */
static void
nfs4_enqueue_lost_rqst(recov_info_t *recovp, mntinfo4_t *mi)
{
	nfs4_lost_rqst_t *lrp = recovp->rc_lost_rqst;

	ASSERT(nfs_rw_lock_held(&mi->mi_recovlock, RW_READER) ||
	    nfs_rw_lock_held(&mi->mi_recovlock, RW_WRITER));

	ASSERT(lrp != NULL && lrp->lr_op != 0);

	NFS4_DEBUG(nfs4_lost_rqst_debug, (CE_NOTE,
	    "nfs4_enqueue_lost_rqst %p, op %d",
	    (void *)lrp, lrp->lr_op));

	mutex_enter(&mi->mi_lock);
	mi->mi_recovflags |= MI4R_LOST_STATE;
	if (lrp->lr_putfirst)
		list_insert_head(&mi->mi_lost_state, lrp);
	else
		list_insert_tail(&mi->mi_lost_state, lrp);
	recovp->rc_lost_rqst = NULL;
	mutex_exit(&mi->mi_lock);

	nfs4_queue_event(RE_LOST_STATE, mi, NULL, lrp->lr_op, lrp->lr_vp,
	    lrp->lr_dvp, 0, NULL, 0, TAG_NONE, TAG_NONE, 0, 0);
}

/*
 * Transfer the bad seqid recovery information in recovp to mi's
 * bad seqid queue, and mark mi as having a bad seqid request.
 */
void
enqueue_bseqid_rqst(recov_info_t *recovp, mntinfo4_t *mi)
{
	ASSERT(nfs_rw_lock_held(&mi->mi_recovlock, RW_READER) ||
	    nfs_rw_lock_held(&mi->mi_recovlock, RW_WRITER));
	ASSERT(recovp->rc_bseqid_rqst != NULL);

	mutex_enter(&mi->mi_lock);
	mi->mi_recovflags |= MI4R_BAD_SEQID;
	list_insert_tail(&mi->mi_bseqid_list, recovp->rc_bseqid_rqst);
	recovp->rc_bseqid_rqst = NULL;
	mutex_exit(&mi->mi_lock);
}

/*
 * Initiate recovery.
 *
 * The nfs4_error_t contains the return codes that triggered a recovery
 * attempt.  mi, vp1, and vp2 refer to the filesystem and files that were
 * being operated on.  vp1 and vp2 may be NULL.
 *
 * Multiple calls are okay.  If recovery is already underway, the call
 * updates the information about what state needs recovery but does not
 * start a new thread.  The caller should hold mi->mi_recovlock as a reader
 * for proper synchronization with any recovery thread.
 *
 * This will return TRUE if recovery was aborted, and FALSE otherwise.
 */
bool_t
nfs4_start_recovery(nfs4_error_t *ep, mntinfo4_t *mi, vnode_t *vp1,
    vnode_t *vp2, stateid4 *sid, nfs4_lost_rqst_t *lost_rqstp, nfs_opnum4 op,
    nfs4_bseqid_entry_t *bsep, vnode_t *moved_vp, char *moved_nm)
{
	recov_info_t *recovp;
	nfs4_server_t *sp;
	bool_t abort = FALSE;
	bool_t gone = FALSE;

	ASSERT(nfs_zone() == mi->mi_zone);
	mutex_enter(&mi->mi_lock);
	/*
	 * If there is lost state, we need to kick off recovery even if the
	 * filesystem has been unmounted or the zone is shutting down.
	 */
	gone = FS_OR_ZONE_GONE4(mi->mi_vfsp);
	if (gone) {
		ASSERT(ep->error != EINTR || lost_rqstp != NULL);
		if (ep->error == EIO && lost_rqstp == NULL) {
			/* failed due to forced unmount, no new lost state */
			abort = TRUE;
		}
		if ((ep->error == 0 || ep->error == ETIMEDOUT) &&
		    !(mi->mi_recovflags & MI4R_LOST_STATE)) {
			/* some other failure, no existing lost state */
			abort = TRUE;
		}
		if (abort) {
			mutex_exit(&mi->mi_lock);
			NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
			    "nfs4_start_recovery: fs unmounted"));
			return (TRUE);
		}
	}
	mi->mi_in_recovery++;
	mutex_exit(&mi->mi_lock);

	recovp = kmem_alloc(sizeof (recov_info_t), KM_SLEEP);
	recovp->rc_orig_errors = *ep;
	sp = find_nfs4_server(mi);
	errs_to_action(recovp, sp, mi, sid, lost_rqstp, gone, op, bsep);
	if (sp != NULL)
		mutex_exit(&sp->s_lock);
	start_recovery(recovp, mi, vp1, vp2, sp, moved_vp, moved_nm);
	if (sp != NULL)
		nfs4_server_rele(sp);
	return (FALSE);
}

/*
 * Internal version of nfs4_start_recovery.  The difference is that the
 * caller specifies the recovery action, rather than the errors leading to
 * recovery.
 */
static void
start_recovery_action(nfs4_recov_t what, bool_t reboot, mntinfo4_t *mi,
    vnode_t *vp1, vnode_t *vp2)
{
	recov_info_t *recovp;

	ASSERT(nfs_zone() == mi->mi_zone);
	mutex_enter(&mi->mi_lock);
	mi->mi_in_recovery++;
	mutex_exit(&mi->mi_lock);

	recovp = kmem_zalloc(sizeof (recov_info_t), KM_SLEEP);
	recovp->rc_action = what;
	recovp->rc_srv_reboot = reboot;
	recovp->rc_error = EIO;
	start_recovery(recovp, mi, vp1, vp2, NULL, NULL, NULL);
}

static void
start_recovery(recov_info_t *recovp, mntinfo4_t *mi,
    vnode_t *vp1, vnode_t *vp2, nfs4_server_t *sp,
    vnode_t *moved_vp, char *moved_nm)
{
	NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
	    "start_recovery: mi %p, what %s", (void*)mi,
	    nfs4_recov_action_to_str(recovp->rc_action)));

	/*
	 * Bump the reference on the vfs so that we can pass it to the
	 * recovery thread.
	 */
	VFS_HOLD(mi->mi_vfsp);
	MI4_HOLD(mi);
again:
	switch (recovp->rc_action) {
	case NR_FAILOVER:
		ASSERT(nfs_rw_lock_held(&mi->mi_recovlock, RW_READER) ||
		    nfs_rw_lock_held(&mi->mi_recovlock, RW_WRITER));
		if (mi->mi_servers->sv_next == NULL)
			goto out_no_thread;
		mutex_enter(&mi->mi_lock);
		mi->mi_recovflags |= MI4R_NEED_NEW_SERVER;
		mutex_exit(&mi->mi_lock);

		if (recovp->rc_lost_rqst != NULL)
			nfs4_enqueue_lost_rqst(recovp, mi);
		break;

	case NR_CLIENTID:
		/*
		 * If the filesystem has been unmounted, punt.
		 */
		if (sp == NULL)
			goto out_no_thread;

		/*
		 * If nobody else is working on the clientid, mark the
		 * clientid as being no longer set.  Then mark the specific
		 * filesystem being worked on.
		 */
		if (!nfs4_server_in_recovery(sp)) {
			mutex_enter(&sp->s_lock);
			sp->s_flags &= ~N4S_CLIENTID_SET;
			mutex_exit(&sp->s_lock);
		}
		ASSERT(nfs_rw_lock_held(&mi->mi_recovlock, RW_READER) ||
		    nfs_rw_lock_held(&mi->mi_recovlock, RW_WRITER));
		mutex_enter(&mi->mi_lock);
		mi->mi_recovflags |= MI4R_NEED_CLIENTID;
		if (recovp->rc_srv_reboot)
			mi->mi_recovflags |= MI4R_SRV_REBOOT;
		mutex_exit(&mi->mi_lock);
		break;

	case NR_OPENFILES:
		ASSERT(nfs_rw_lock_held(&mi->mi_recovlock, RW_READER) ||
		    nfs_rw_lock_held(&mi->mi_recovlock, RW_WRITER));
		mutex_enter(&mi->mi_lock);
		mi->mi_recovflags |= MI4R_REOPEN_FILES;
		if (recovp->rc_srv_reboot)
			mi->mi_recovflags |= MI4R_SRV_REBOOT;
		mutex_exit(&mi->mi_lock);
		break;

	case NR_WRONGSEC:
		ASSERT(nfs_rw_lock_held(&mi->mi_recovlock, RW_READER) ||
		    nfs_rw_lock_held(&mi->mi_recovlock, RW_WRITER));
		mutex_enter(&mi->mi_lock);
		mi->mi_recovflags |= MI4R_NEED_SECINFO;
		mutex_exit(&mi->mi_lock);
		break;

	case NR_EXPIRED:
		if (vp1 != NULL)
			recov_badstate(recovp, vp1, NFS4ERR_EXPIRED);
		if (vp2 != NULL)
			recov_badstate(recovp, vp2, NFS4ERR_EXPIRED);
		goto out_no_thread;	/* no further recovery possible */

	case NR_BAD_STATEID:
		if (vp1 != NULL)
			recov_badstate(recovp, vp1, NFS4ERR_BAD_STATEID);
		if (vp2 != NULL)
			recov_badstate(recovp, vp2, NFS4ERR_BAD_STATEID);
		goto out_no_thread;	/* no further recovery possible */

	case NR_FHEXPIRED:
	case NR_BADHANDLE:
		if (vp1 != NULL)
			recov_throttle(recovp, vp1);
		if (vp2 != NULL)
			recov_throttle(recovp, vp2);
		/*
		 * Recover the filehandle now, rather than using a
		 * separate thread.  We can do this because filehandle
		 * recovery is independent of any other state, and because
		 * we know that we are not competing with the recovery
		 * thread at this time.  recov_filehandle will deal with
		 * threads that are competing to recover this filehandle.
		 */
		ASSERT(nfs_rw_lock_held(&mi->mi_recovlock, RW_READER) ||
		    nfs_rw_lock_held(&mi->mi_recovlock, RW_WRITER));
		if (vp1 != NULL)
			recov_filehandle(recovp->rc_action, mi, vp1);
		if (vp2 != NULL)
			recov_filehandle(recovp->rc_action, mi, vp2);
		goto out_no_thread;	/* no further recovery needed */

	case NR_STALE:
		/*
		 * NFS4ERR_STALE handling
		 * recov_stale() could set MI4R_NEED_NEW_SERVER to
		 * indicate that we can and should failover.
		 */
		ASSERT(nfs_rw_lock_held(&mi->mi_recovlock, RW_READER) ||
		    nfs_rw_lock_held(&mi->mi_recovlock, RW_WRITER));

		if (vp1 != NULL)
			recov_stale(mi, vp1);
		if (vp2 != NULL)
			recov_stale(mi, vp2);
		mutex_enter(&mi->mi_lock);
		if ((mi->mi_recovflags & MI4R_NEED_NEW_SERVER) == 0) {
			mutex_exit(&mi->mi_lock);
			goto out_no_thread;
		}
		mutex_exit(&mi->mi_lock);
		recovp->rc_action = NR_FAILOVER;
		goto again;

	case NR_BAD_SEQID:
		if (recovp->rc_bseqid_rqst) {
			enqueue_bseqid_rqst(recovp, mi);
			break;
		}

		if (vp1 != NULL)
			recov_badstate(recovp, vp1, NFS4ERR_BAD_SEQID);
		if (vp2 != NULL)
			recov_badstate(recovp, vp2, NFS4ERR_BAD_SEQID);
		goto out_no_thread; /* no further recovery possible */

	case NR_OLDSTATEID:
		if (vp1 != NULL)
			recov_badstate(recovp, vp1, NFS4ERR_OLD_STATEID);
		if (vp2 != NULL)
			recov_badstate(recovp, vp2, NFS4ERR_OLD_STATEID);
		goto out_no_thread;	/* no further recovery possible */

	case NR_GRACE:
		nfs4_set_grace_wait(mi);
		goto out_no_thread; /* no further action required for GRACE */

	case NR_DELAY:
		if (vp1)
			nfs4_set_delay_wait(vp1);
		goto out_no_thread; /* no further action required for DELAY */

	case NR_LOST_STATE_RQST:
	case NR_LOST_LOCK:
		nfs4_enqueue_lost_rqst(recovp, mi);
		break;
	default:
		nfs4_queue_event(RE_UNEXPECTED_ACTION, mi, NULL,
		    recovp->rc_action, NULL, NULL, 0, NULL, 0, TAG_NONE,
		    TAG_NONE, 0, 0);
		goto out_no_thread;
	}

	/*
	 * If either file recently went through the same recovery, wait
	 * awhile.  This is in case there is some sort of bug; we might not
	 * be able to recover properly, but at least we won't bombard the
	 * server with calls, and we won't tie up the client.
	 */
	if (vp1 != NULL)
		recov_throttle(recovp, vp1);
	if (vp2 != NULL)
		recov_throttle(recovp, vp2);

	/*
	 * If there's already a recovery thread, don't start another one.
	 */

	mutex_enter(&mi->mi_lock);
	if (mi->mi_flags & MI4_RECOV_ACTIV) {
		mutex_exit(&mi->mi_lock);
		goto out_no_thread;
	}
	mi->mi_flags |= MI4_RECOV_ACTIV;
	mutex_exit(&mi->mi_lock);
	NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
	    "start_recovery: starting new thread for mi %p", (void*)mi));

	recovp->rc_mi = mi;
	recovp->rc_vp1 = vp1;
	if (vp1 != NULL) {
		ASSERT(VTOMI4(vp1) == mi);
		VN_HOLD(recovp->rc_vp1);
	}
	recovp->rc_vp2 = vp2;
	if (vp2 != NULL) {
		ASSERT(VTOMI4(vp2) == mi);
		VN_HOLD(recovp->rc_vp2);
	}
	recovp->rc_moved_vp = moved_vp;
	recovp->rc_moved_nm = moved_nm;

	(void) zthread_create(NULL, 0, nfs4_recov_thread, recovp, 0,
	    minclsyspri);
	return;

	/* not reached by thread creating call */
out_no_thread:
	mutex_enter(&mi->mi_lock);
	mi->mi_in_recovery--;
	if (mi->mi_in_recovery == 0)
		cv_broadcast(&mi->mi_cv_in_recov);
	mutex_exit(&mi->mi_lock);

	VFS_RELE(mi->mi_vfsp);
	MI4_RELE(mi);
	/*
	 * Free up resources that were allocated for us.
	 */
	kmem_free(recovp, sizeof (recov_info_t));
}

static int
nfs4_check_recov_err(vnode_t *vp, nfs4_op_hint_t op,
    nfs4_recov_state_t *rsp, int retry_err_cnt, char *str)
{
	rnode4_t *rp;
	int error = 0;
	int exempt;

	if (vp == NULL)
		return (0);

	exempt = (op == OH_CLOSE || op == OH_LOCKU || op == OH_DELEGRETURN);
	rp = VTOR4(vp);
	mutex_enter(&rp->r_statelock);

	/*
	 * If there was a recovery error, then allow op hints "exempt" from
	 * recov errors to retry (currently 3 times).  Either r_error or
	 * EIO is returned for non-exempt op hints.
	 */
	if (rp->r_flags & R4RECOVERR) {
		if (exempt && rsp->rs_num_retry_despite_err <=
		    nfs4_max_recov_error_retry) {

			/*
			 * Check to make sure that we haven't already inc'd
			 * rs_num_retry_despite_err for current nfs4_start_fop
			 * instance.  We don't want to double inc (if we were
			 * called with vp2, then the vp1 call could have
			 * already incremented.
			 */
			if (retry_err_cnt == rsp->rs_num_retry_despite_err)
				rsp->rs_num_retry_despite_err++;

			NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
			    "nfs4_start_fop: %s %p DEAD, cnt=%d", str,
			    (void *)vp, rsp->rs_num_retry_despite_err));
		} else {
			error = (rp->r_error ? rp->r_error : EIO);
			/*
			 * An ESTALE error on a non-regular file is not
			 * "sticky".  Return the ESTALE error once, but
			 * clear the condition to allow future operations
			 * to go OTW.  This will allow the client to
			 * recover if the server has merely unshared then
			 * re-shared the file system.  For regular files,
			 * the unshare has destroyed the open state at the
			 * server and we aren't willing to do a reopen (yet).
			 */
			if (error == ESTALE && vp->v_type != VREG) {
				rp->r_flags &=
				    ~(R4RECOVERR|R4RECOVERRP|R4STALE);
				rp->r_error = 0;
				error = ESTALE;
			}
			NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
			    "nfs4_start_fop: %s %p DEAD, cnt=%d error=%d",
			    str, (void *)vp,
			    rsp->rs_num_retry_despite_err, error));
		}
	}

	mutex_exit(&rp->r_statelock);
	return (error);
}

/*
 * Initial setup code that every operation should call if it might invoke
 * client recovery.  Can block waiting for recovery to finish on a
 * filesystem.  Either vnode ptr can be NULL.
 *
 * Returns 0 if there are no outstanding errors.  Can return an
 * errno value under various circumstances (e.g., failed recovery, or
 * interrupted while waiting for recovery to finish).
 *
 * There must be a corresponding call to nfs4_end_op() to free up any locks
 * or resources allocated by this call (assuming this call succeeded),
 * using the same rsp that's passed in here.
 *
 * The open and lock seqid synchronization must be stopped before calling this
 * function, as it could lead to deadlock when trying to reopen a file or
 * reclaim a lock.  The synchronization is obtained with calls to:
 *   nfs4_start_open_seqid_sync()
 *   nfs4_start_lock_seqid_sync()
 *
 * *startrecovp is set TRUE if the caller should not bother with the
 * over-the-wire call, and just initiate recovery for the given request.
 * This is typically used for state-releasing ops if the filesystem has
 * been forcibly unmounted.  startrecovp may be NULL for
 * non-state-releasing ops.
 */

int
nfs4_start_fop(mntinfo4_t *mi, vnode_t *vp1, vnode_t *vp2, nfs4_op_hint_t op,
    nfs4_recov_state_t *rsp, bool_t *startrecovp)
{
	int error = 0, rerr_cnt;
	nfs4_server_t *sp = NULL;
	nfs4_server_t *tsp;
	nfs4_error_t e = { 0, NFS4_OK, RPC_SUCCESS };
	uint_t droplock_cnt;
#ifdef DEBUG
	void *fop_caller;
#endif

	ASSERT(vp1 == NULL || vp1->v_vfsp == mi->mi_vfsp);
	ASSERT(vp2 == NULL || vp2->v_vfsp == mi->mi_vfsp);

#ifdef	DEBUG
	if ((fop_caller = tsd_get(nfs4_tsd_key)) != NULL) {
		cmn_err(CE_PANIC, "Missing nfs4_end_fop: last caller %p",
		    fop_caller);
	}
	(void) tsd_set(nfs4_tsd_key, caller());
#endif

	rsp->rs_sp = NULL;
	rsp->rs_flags &= ~NFS4_RS_RENAME_HELD;
	rerr_cnt = rsp->rs_num_retry_despite_err;

	/*
	 * Process the items that may delay() based on server response
	 */
	error = nfs4_wait_for_grace(mi, rsp);
	if (error)
		goto out;

	if (vp1 != NULL) {
		error = nfs4_wait_for_delay(vp1, rsp);
		if (error)
			goto out;
	}

	/* Wait for a delegation recall to complete. */

	error = wait_for_recall(vp1, vp2, op, rsp);
	if (error)
		goto out;

	/*
	 * Wait for any current recovery actions to finish.  Note that a
	 * recovery thread can still start up after wait_for_recovery()
	 * finishes.  We don't block out recovery operations until we
	 * acquire s_recovlock and mi_recovlock.
	 */
	error = wait_for_recovery(mi, op);
	if (error)
		goto out;

	/*
	 * Check to see if the rnode is already marked with a
	 * recovery error.  If so, return it immediately.  But
	 * always pass CLOSE, LOCKU, and DELEGRETURN so we can
	 * clean up state on the server.
	 */

	if (vp1 != NULL) {
		if (error = nfs4_check_recov_err(vp1, op, rsp, rerr_cnt, "vp1"))
			goto out;
		nfs4_check_remap(mi, vp1, NFS4_REMAP_CKATTRS, &e);
	}

	if (vp2 != NULL) {
		if (error = nfs4_check_recov_err(vp2, op, rsp, rerr_cnt, "vp2"))
			goto out;
		nfs4_check_remap(mi, vp2, NFS4_REMAP_CKATTRS, &e);
	}

	/*
	 * The lock order calls for us to acquire s_recovlock before
	 * mi_recovlock, but we have to hold mi_recovlock to look up sp (to
	 * prevent races with the failover/migration code).  So acquire
	 * mi_recovlock, look up sp, drop mi_recovlock, acquire
	 * s_recovlock and mi_recovlock, then verify that sp is still the
	 * right object.  XXX Can we find a simpler way to deal with this?
	 */
	if (nfs_rw_enter_sig(&mi->mi_recovlock, RW_READER,
	    mi->mi_flags & MI4_INT)) {
		error = EINTR;
		goto out;
	}
get_sp:
	sp = find_nfs4_server(mi);
	if (sp != NULL) {
		sp->s_otw_call_count++;
		mutex_exit(&sp->s_lock);
		droplock_cnt = mi->mi_srvset_cnt;
	}
	nfs_rw_exit(&mi->mi_recovlock);

	if (sp != NULL) {
		if (nfs_rw_enter_sig(&sp->s_recovlock, RW_READER,
		    mi->mi_flags & MI4_INT)) {
			error = EINTR;
			goto out;
		}
	}
	if (nfs_rw_enter_sig(&mi->mi_recovlock, RW_READER,
	    mi->mi_flags & MI4_INT)) {
		if (sp != NULL)
			nfs_rw_exit(&sp->s_recovlock);
		error = EINTR;
		goto out;
	}
	/*
	 * If the mntinfo4_t hasn't changed nfs4_sever_ts then
	 * there's no point in double checking to make sure it
	 * has switched.
	 */
	if (sp == NULL || droplock_cnt != mi->mi_srvset_cnt) {
		tsp = find_nfs4_server(mi);
		if (tsp != sp) {
			/* try again */
			if (tsp != NULL) {
				mutex_exit(&tsp->s_lock);
				nfs4_server_rele(tsp);
				tsp = NULL;
			}
			if (sp != NULL) {
				nfs_rw_exit(&sp->s_recovlock);
				mutex_enter(&sp->s_lock);
				sp->s_otw_call_count--;
				mutex_exit(&sp->s_lock);
				nfs4_server_rele(sp);
				sp = NULL;
			}
			goto get_sp;
		} else {
			if (tsp != NULL) {
				mutex_exit(&tsp->s_lock);
				nfs4_server_rele(tsp);
				tsp = NULL;
			}
		}
	}

	if (sp != NULL) {
		rsp->rs_sp = sp;
	}

	/*
	 * If the fileystem uses volatile filehandles, obtain a lock so
	 * that we synchronize with renames.  Exception: mount operations
	 * can change mi_fh_expire_type, which could be a problem, since
	 * the end_op code needs to be consistent with the start_op code
	 * about mi_rename_lock.  Since mounts don't compete with renames,
	 * it's simpler to just not acquire the rename lock for mounts.
	 */
	if (NFS4_VOLATILE_FH(mi) && op != OH_MOUNT) {
		if (nfs_rw_enter_sig(&mi->mi_rename_lock,
		    op == OH_VFH_RENAME ? RW_WRITER : RW_READER,
		    mi->mi_flags & MI4_INT)) {
			nfs_rw_exit(&mi->mi_recovlock);
			if (sp != NULL)
				nfs_rw_exit(&sp->s_recovlock);
			error = EINTR;
			goto out;
		}
		rsp->rs_flags |= NFS4_RS_RENAME_HELD;
	}

	if (OH_IS_STATE_RELE(op)) {
		/*
		 * For forced unmount, letting the request proceed will
		 * almost always delay response to the user, so hand it off
		 * to the recovery thread.  For exiting lwp's, we don't
		 * have a good way to tell if the request will hang.  We
		 * generally want processes to handle their own requests so
		 * that they can be done in parallel, but if there is
		 * already a recovery thread, hand the request off to it.
		 * This will improve user response at no cost to overall
		 * system throughput.  For zone shutdown, we'd prefer
		 * the recovery thread to handle this as well.
		 */
		ASSERT(startrecovp != NULL);
		mutex_enter(&mi->mi_lock);
		if (FS_OR_ZONE_GONE4(mi->mi_vfsp))
			*startrecovp = TRUE;
		else if ((curthread->t_proc_flag & TP_LWPEXIT) &&
		    (mi->mi_flags & MI4_RECOV_ACTIV))
			*startrecovp = TRUE;
		else
			*startrecovp = FALSE;
		mutex_exit(&mi->mi_lock);
	} else
		if (startrecovp != NULL)
			*startrecovp = FALSE;

	ASSERT(error == 0);
	return (error);

out:
	ASSERT(error != 0);
	if (sp != NULL) {
		mutex_enter(&sp->s_lock);
		sp->s_otw_call_count--;
		mutex_exit(&sp->s_lock);
		nfs4_server_rele(sp);
		rsp->rs_sp = NULL;
	}
	nfs4_end_op_recall(vp1, vp2, rsp);

#ifdef	DEBUG
	(void) tsd_set(nfs4_tsd_key, NULL);
#endif
	return (error);
}

/*
 * It is up to the caller to determine if rsp->rs_sp being NULL
 * is detrimental or not.
 */
int
nfs4_start_op(mntinfo4_t *mi, vnode_t *vp1, vnode_t *vp2,
    nfs4_recov_state_t *rsp)
{
	ASSERT(rsp->rs_num_retry_despite_err == 0);
	rsp->rs_num_retry_despite_err = 0;
	return (nfs4_start_fop(mi, vp1, vp2, OH_OTHER, rsp, NULL));
}

/*
 * Release any resources acquired by nfs4_start_op().
 * 'sp' should be the nfs4_server pointer returned by nfs4_start_op().
 *
 * The operation hint is used to avoid a deadlock by bypassing delegation
 * return logic for writes, which are done while returning a delegation.
 */

void
nfs4_end_fop(mntinfo4_t *mi, vnode_t *vp1, vnode_t *vp2, nfs4_op_hint_t op,
    nfs4_recov_state_t *rsp, bool_t needs_recov)
{
	nfs4_server_t *sp = rsp->rs_sp;
	rnode4_t *rp = NULL;

#ifdef	lint
	/*
	 * The op hint isn't used any more, but might be in
	 * the future.
	 */
	op = op;
#endif

#ifdef	DEBUG
	ASSERT(tsd_get(nfs4_tsd_key) != NULL);
	(void) tsd_set(nfs4_tsd_key, NULL);
#endif

	nfs4_end_op_recall(vp1, vp2, rsp);

	if (rsp->rs_flags & NFS4_RS_RENAME_HELD)
		nfs_rw_exit(&mi->mi_rename_lock);

	if (!needs_recov) {
		if (rsp->rs_flags & NFS4_RS_DELAY_MSG) {
			/* may need to clear the delay interval */
			if (vp1 != NULL) {
				rp = VTOR4(vp1);
				mutex_enter(&rp->r_statelock);
				rp->r_delay_interval = 0;
				mutex_exit(&rp->r_statelock);
			}
		}
		rsp->rs_flags &= ~(NFS4_RS_GRACE_MSG|NFS4_RS_DELAY_MSG);
	}

	/*
	 * If the corresponding nfs4_start_op() found a sp,
	 * then there must still be a sp.
	 */
	if (sp != NULL) {
		nfs_rw_exit(&mi->mi_recovlock);
		nfs_rw_exit(&sp->s_recovlock);
		mutex_enter(&sp->s_lock);
		sp->s_otw_call_count--;
		cv_broadcast(&sp->s_cv_otw_count);
		mutex_exit(&sp->s_lock);
		nfs4_server_rele(sp);
	} else {
		nfs_rw_exit(&mi->mi_recovlock);
	}
}

void
nfs4_end_op(mntinfo4_t *mi, vnode_t *vp1, vnode_t *vp2,
    nfs4_recov_state_t *rsp, bool_t needrecov)
{
	nfs4_end_fop(mi, vp1, vp2, OH_OTHER, rsp, needrecov);
}

/*
 * If the filesystem is going through client recovery, block until
 * finished.
 * Exceptions:
 * - state-releasing ops (CLOSE, LOCKU, DELEGRETURN) are allowed to proceed
 *   if the filesystem has been forcibly unmounted or the lwp is exiting.
 *
 * Return value:
 * - 0 if no errors
 * - EINTR if the call was interrupted
 * - EIO if the filesystem has been forcibly unmounted (non-state-releasing
 *   op)
 * - the errno value from the recovery thread, if recovery failed
 */

static int
wait_for_recovery(mntinfo4_t *mi, nfs4_op_hint_t op_hint)
{
	int error = 0;

	mutex_enter(&mi->mi_lock);

	while (mi->mi_recovflags != 0) {
		klwp_t *lwp = ttolwp(curthread);

		if ((mi->mi_vfsp->vfs_flag & VFS_UNMOUNTED) ||
		    (mi->mi_flags & MI4_RECOV_FAIL))
			break;
		if (OH_IS_STATE_RELE(op_hint) &&
		    (curthread->t_proc_flag & TP_LWPEXIT))
			break;

		if (lwp != NULL)
			lwp->lwp_nostop++;
		/* XXX - use different cv? */
		if (cv_wait_sig(&mi->mi_failover_cv, &mi->mi_lock) == 0) {
			error = EINTR;
			if (lwp != NULL)
				lwp->lwp_nostop--;
			break;
		}
		if (lwp != NULL)
			lwp->lwp_nostop--;
	}

	if ((mi->mi_vfsp->vfs_flag & VFS_UNMOUNTED) &&
	    !OH_IS_STATE_RELE(op_hint)) {
		NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
		    "wait_for_recovery: forced unmount"));
		error = EIO;
	} else if (mi->mi_flags & MI4_RECOV_FAIL) {
		NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
		    "wait_for_recovery: fail since RECOV FAIL"));
		error = mi->mi_error;
	}

	mutex_exit(&mi->mi_lock);

	return (error);
}

/*
 * If the client received NFS4ERR_GRACE for this particular mount,
 * the client blocks here until it is time to try again.
 *
 * Return value:
 * - 0 if wait was successful
 * - EINTR if the call was interrupted
 */

int
nfs4_wait_for_grace(mntinfo4_t *mi, nfs4_recov_state_t *rsp)
{
	int error = 0;
	time_t curtime, time_to_wait;

	/* do a unprotected check to reduce mi_lock contention */
	if (mi->mi_grace_wait != 0) {
		mutex_enter(&mi->mi_lock);

		if (mi->mi_grace_wait != 0) {
			if (!(rsp->rs_flags & NFS4_RS_GRACE_MSG))
				rsp->rs_flags |= NFS4_RS_GRACE_MSG;

			curtime = gethrestime_sec();

			if (curtime < mi->mi_grace_wait) {

				time_to_wait = mi->mi_grace_wait - curtime;

				mutex_exit(&mi->mi_lock);

				delay(SEC_TO_TICK(time_to_wait));

				curtime = gethrestime_sec();

				mutex_enter(&mi->mi_lock);

				if (curtime >= mi->mi_grace_wait)
					mi->mi_grace_wait = 0;
			} else {
				mi->mi_grace_wait = 0;
			}
		}
		mutex_exit(&mi->mi_lock);
	}

	return (error);
}

/*
 * If the client received NFS4ERR_DELAY for an operation on a vnode,
 * the client blocks here until it is time to try again.
 *
 * Return value:
 * - 0 if wait was successful
 * - EINTR if the call was interrupted
 */

int
nfs4_wait_for_delay(vnode_t *vp, nfs4_recov_state_t *rsp)
{
	int error = 0;
	time_t curtime, time_to_wait;
	rnode4_t *rp;

	ASSERT(vp != NULL);

	rp = VTOR4(vp);

	/* do a unprotected check to reduce r_statelock contention */
	if (rp->r_delay_wait != 0) {
		mutex_enter(&rp->r_statelock);

		if (rp->r_delay_wait != 0) {

			if (!(rsp->rs_flags & NFS4_RS_DELAY_MSG)) {
				rsp->rs_flags |= NFS4_RS_DELAY_MSG;
				nfs4_mi_kstat_inc_delay(VTOMI4(vp));
			}

			curtime = gethrestime_sec();

			if (curtime < rp->r_delay_wait) {

				time_to_wait = rp->r_delay_wait - curtime;

				mutex_exit(&rp->r_statelock);

				delay(SEC_TO_TICK(time_to_wait));

				curtime = gethrestime_sec();

				mutex_enter(&rp->r_statelock);

				if (curtime >= rp->r_delay_wait)
					rp->r_delay_wait = 0;
			} else {
				rp->r_delay_wait = 0;
			}
		}
		mutex_exit(&rp->r_statelock);
	}

	return (error);
}

/*
 * The recovery thread.
 */

static void
nfs4_recov_thread(recov_info_t *recovp)
{
	mntinfo4_t *mi = recovp->rc_mi;
	nfs4_server_t *sp;
	int done = 0, error = 0;
	bool_t recov_fail = FALSE;
	callb_cpr_t cpr_info;
	kmutex_t cpr_lock;

	nfs4_queue_event(RE_START, mi, NULL, mi->mi_recovflags,
	    recovp->rc_vp1, recovp->rc_vp2, 0, NULL, 0, TAG_NONE, TAG_NONE,
	    0, 0);

	mutex_init(&cpr_lock, NULL, MUTEX_DEFAULT, NULL);
	CALLB_CPR_INIT(&cpr_info, &cpr_lock, callb_generic_cpr, "nfsv4Recov");

	mutex_enter(&mi->mi_lock);
	mi->mi_recovthread = curthread;
	mutex_exit(&mi->mi_lock);

	/*
	 * We don't really need protection here against failover or
	 * migration, since the current thread is the one that would make
	 * any changes, but hold mi_recovlock anyway for completeness (and
	 * to satisfy any ASSERTs).
	 */
	(void) nfs_rw_enter_sig(&mi->mi_recovlock, RW_READER, 0);
	sp = find_nfs4_server(mi);
	if (sp != NULL)
		mutex_exit(&sp->s_lock);
	nfs_rw_exit(&mi->mi_recovlock);

	/*
	 * Do any necessary recovery, based on the information in recovp
	 * and any recovery flags.
	 */

	do {
		mutex_enter(&mi->mi_lock);
		if (FS_OR_ZONE_GONE4(mi->mi_vfsp)) {
			bool_t activesrv;

			NFS4_DEBUG(nfs4_client_recov_debug &&
			    mi->mi_vfsp->vfs_flag & VFS_UNMOUNTED, (CE_NOTE,
			    "nfs4_recov_thread: file system has been "
			    "unmounted"));
			NFS4_DEBUG(nfs4_client_recov_debug &&
			    zone_status_get(curproc->p_zone) >=
			    ZONE_IS_SHUTTING_DOWN, (CE_NOTE,
			    "nfs4_recov_thread: zone shutting down"));
			/*
			 * If the server has lost its state for us and
			 * the filesystem is unmounted, then the filesystem
			 * can be tossed, even if there are lost lock or
			 * lost state calls in the recovery queue.
			 */
			if (mi->mi_recovflags &
			    (MI4R_NEED_CLIENTID | MI4R_REOPEN_FILES)) {
				NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
				"nfs4_recov_thread: bailing out"));
				mi->mi_flags |= MI4_RECOV_FAIL;
				mi->mi_error = recovp->rc_error;
				recov_fail = TRUE;
			}
			/*
			 * We don't know if the server has any state for
			 * us, and the filesystem has been unmounted.  If
			 * there are "lost state" recovery items, keep
			 * trying to process them until there are no more
			 * mounted filesystems for the server.  Otherwise,
			 * bail out.  The reason we don't mark the
			 * filesystem as failing recovery is in case we
			 * have to do "lost state" recovery later (e.g., a
			 * user process exits).
			 */
			if (!(mi->mi_recovflags & MI4R_LOST_STATE)) {
				done = 1;
				mutex_exit(&mi->mi_lock);
				break;
			}
			mutex_exit(&mi->mi_lock);

			if (sp == NULL)
				activesrv = FALSE;
			else {
				mutex_enter(&sp->s_lock);
				activesrv = nfs4_fs_active(sp);
			}
			if (!activesrv) {
				NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
				    "no active fs for server %p",
				    (void *)sp));
				mutex_enter(&mi->mi_lock);
				mi->mi_flags |= MI4_RECOV_FAIL;
				mi->mi_error = recovp->rc_error;
				mutex_exit(&mi->mi_lock);
				recov_fail = TRUE;
				if (sp != NULL) {
					/*
					 * Mark the server instance as
					 * dead, so that nobody will attach
					 * a new filesystem.
					 */
					nfs4_mark_srv_dead(sp);
				}
			}
			if (sp != NULL)
				mutex_exit(&sp->s_lock);
		} else {
			mutex_exit(&mi->mi_lock);
		}

		/*
		 * Check if we need to select a new server for a
		 * failover.  Choosing a new server will force at
		 * least a check of the clientid.
		 */
		mutex_enter(&mi->mi_lock);
		if (!recov_fail &&
		    (mi->mi_recovflags & MI4R_NEED_NEW_SERVER)) {
			mutex_exit(&mi->mi_lock);
			recov_newserver(recovp, &sp, &recov_fail);
		} else
			mutex_exit(&mi->mi_lock);

		/*
		 * Check if we need to recover the clientid.  This
		 * must be done before file and lock recovery, and it
		 * potentially affects the recovery threads for other
		 * filesystems, so it gets special treatment.
		 */
		if (sp != NULL && recov_fail == FALSE) {
			mutex_enter(&sp->s_lock);
			if (!(sp->s_flags & N4S_CLIENTID_SET)) {
				mutex_exit(&sp->s_lock);
				recov_clientid(recovp, sp);
			} else {
				/*
				 * Unset this flag in case another recovery
				 * thread successfully recovered the clientid
				 * for us already.
				 */
				mutex_enter(&mi->mi_lock);
				mi->mi_recovflags &= ~MI4R_NEED_CLIENTID;
				mutex_exit(&mi->mi_lock);
				mutex_exit(&sp->s_lock);
			}
		}

		/*
		 * Check if we need to get the security information.
		 */
		mutex_enter(&mi->mi_lock);
		if ((mi->mi_recovflags & MI4R_NEED_SECINFO) &&
		    !(mi->mi_flags & MI4_RECOV_FAIL)) {
			mutex_exit(&mi->mi_lock);
			(void) nfs_rw_enter_sig(&mi->mi_recovlock,
			    RW_WRITER, 0);
			error = nfs4_secinfo_recov(recovp->rc_mi,
			    recovp->rc_vp1, recovp->rc_vp2);
			/*
			 * If error, nothing more can be done, stop
			 * the recovery.
			 */
			if (error) {
				mutex_enter(&mi->mi_lock);
				mi->mi_flags |= MI4_RECOV_FAIL;
				mi->mi_error = recovp->rc_error;
				mutex_exit(&mi->mi_lock);
				nfs4_queue_event(RE_WRONGSEC, mi, NULL,
				    error, recovp->rc_vp1, recovp->rc_vp2,
				    0, NULL, 0, TAG_NONE, TAG_NONE, 0, 0);
			}
			nfs_rw_exit(&mi->mi_recovlock);
		} else
			mutex_exit(&mi->mi_lock);

		/*
		 * Check if there's a bad seqid to recover.
		 */
		mutex_enter(&mi->mi_lock);
		if ((mi->mi_recovflags & MI4R_BAD_SEQID) &&
		    !(mi->mi_flags & MI4_RECOV_FAIL)) {
			mutex_exit(&mi->mi_lock);
			(void) nfs_rw_enter_sig(&mi->mi_recovlock,
			    RW_WRITER, 0);
			recov_bad_seqid(recovp);
			nfs_rw_exit(&mi->mi_recovlock);
		} else
			mutex_exit(&mi->mi_lock);

		/*
		 * Next check for recovery that affects the entire
		 * filesystem.
		 */
		if (sp != NULL) {
			mutex_enter(&mi->mi_lock);
			if ((mi->mi_recovflags & MI4R_REOPEN_FILES) &&
			    !(mi->mi_flags & MI4_RECOV_FAIL)) {
				mutex_exit(&mi->mi_lock);
				recov_openfiles(recovp, sp);
			} else
				mutex_exit(&mi->mi_lock);
		}

		/*
		 * Send any queued state recovery requests.
		 */
		mutex_enter(&mi->mi_lock);
		if (sp != NULL &&
		    (mi->mi_recovflags & MI4R_LOST_STATE) &&
		    !(mi->mi_flags & MI4_RECOV_FAIL)) {
			mutex_exit(&mi->mi_lock);
			(void) nfs_rw_enter_sig(&mi->mi_recovlock,
			    RW_WRITER, 0);
			nfs4_resend_lost_rqsts(recovp, sp);
			if (list_head(&mi->mi_lost_state) == NULL) {
				/* done */
				mutex_enter(&mi->mi_lock);
				mi->mi_recovflags &= ~MI4R_LOST_STATE;
				mutex_exit(&mi->mi_lock);
			}
			nfs_rw_exit(&mi->mi_recovlock);
		} else {
			mutex_exit(&mi->mi_lock);
		}

		/*
		 * See if there is anything more to do.  If not, announce
		 * that we are done and exit.
		 *
		 * Need mi_recovlock to keep 'sp' valid.  Must grab
		 * mi_recovlock before mi_lock to preserve lock ordering.
		 */
		(void) nfs_rw_enter_sig(&mi->mi_recovlock, RW_READER, 0);
		mutex_enter(&mi->mi_lock);
		if ((mi->mi_recovflags & ~MI4R_SRV_REBOOT) == 0 ||
		    (mi->mi_flags & MI4_RECOV_FAIL)) {
			list_t local_lost_state;
			nfs4_lost_rqst_t *lrp;

			/*
			 * We need to remove the lost requests before we
			 * unmark the mi as no longer doing recovery to
			 * avoid a race with a new thread putting new lost
			 * requests on the same mi (and the going away
			 * thread would remove the new lost requests).
			 *
			 * Move the lost requests to a local list since
			 * nfs4_remove_lost_rqst() drops mi_lock, and
			 * dropping the mi_lock would make our check to
			 * see if recovery is done no longer valid.
			 */
			list_create(&local_lost_state,
			    sizeof (nfs4_lost_rqst_t),
			    offsetof(nfs4_lost_rqst_t, lr_node));
			list_move_tail(&local_lost_state, &mi->mi_lost_state);

			done = 1;
			mutex_exit(&mi->mi_lock);
			/*
			 * Now officially free the "moved"
			 * lost requests.
			 */
			while ((lrp = list_head(&local_lost_state)) != NULL) {
				list_remove(&local_lost_state, lrp);
				nfs4_free_lost_rqst(lrp, sp);
			}
			list_destroy(&local_lost_state);
		} else
			mutex_exit(&mi->mi_lock);
		nfs_rw_exit(&mi->mi_recovlock);

		/*
		 * If the filesystem has been forcibly unmounted, there is
		 * probably no point in retrying immediately.  Furthermore,
		 * there might be user processes waiting for a chance to
		 * queue up "lost state" requests, so that they can exit.
		 * So pause here for a moment.  Same logic for zone shutdown.
		 */
		if (!done && FS_OR_ZONE_GONE4(mi->mi_vfsp)) {
			mutex_enter(&mi->mi_lock);
			cv_broadcast(&mi->mi_failover_cv);
			mutex_exit(&mi->mi_lock);
			delay(SEC_TO_TICK(nfs4_unmount_delay));
		}

	} while (!done);

	if (sp != NULL)
		nfs4_server_rele(sp);

	/*
	 * Return all recalled delegations
	 */
	nfs4_dlistclean();

	mutex_enter(&mi->mi_lock);
	recov_done(mi, recovp);
	mutex_exit(&mi->mi_lock);

	/*
	 * Free up resources that were allocated for us.
	 */
	if (recovp->rc_vp1 != NULL)
		VN_RELE(recovp->rc_vp1);
	if (recovp->rc_vp2 != NULL)
		VN_RELE(recovp->rc_vp2);

	/* now we are done using the mi struct, signal the waiters */
	mutex_enter(&mi->mi_lock);
	mi->mi_in_recovery--;
	if (mi->mi_in_recovery == 0)
		cv_broadcast(&mi->mi_cv_in_recov);
	mutex_exit(&mi->mi_lock);

	VFS_RELE(mi->mi_vfsp);
	MI4_RELE(mi);
	kmem_free(recovp, sizeof (recov_info_t));
	mutex_enter(&cpr_lock);
	CALLB_CPR_EXIT(&cpr_info);
	mutex_destroy(&cpr_lock);
	zthread_exit();
}

/*
 * Log the end of recovery and notify any waiting threads.
 */

static void
recov_done(mntinfo4_t *mi, recov_info_t *recovp)
{

	ASSERT(MUTEX_HELD(&mi->mi_lock));

	nfs4_queue_event(RE_END, mi, NULL, 0, recovp->rc_vp1,
	    recovp->rc_vp2, 0, NULL, 0, TAG_NONE, TAG_NONE, 0, 0);
	mi->mi_recovthread = NULL;
	mi->mi_flags &= ~MI4_RECOV_ACTIV;
	mi->mi_recovflags &= ~MI4R_SRV_REBOOT;
	cv_broadcast(&mi->mi_failover_cv);
}

/*
 * State-specific recovery routines, by state.
 */

/*
 * Failover.
 *
 * Replaces *spp with a reference to the new server, which must
 * eventually be freed.
 */

static void
recov_newserver(recov_info_t *recovp, nfs4_server_t **spp, bool_t *recov_fail)
{
	mntinfo4_t *mi = recovp->rc_mi;
	servinfo4_t *svp = NULL;
	nfs4_server_t *osp = *spp;
	CLIENT *cl;
	enum clnt_stat status;
	struct timeval tv;
	int error;
	int oncethru = 0;
	rnode4_t *rp;
	int index;
	nfs_fh4 fh;
	char *snames;
	size_t len;

	(void) nfs_rw_enter_sig(&mi->mi_recovlock, RW_WRITER, 0);

	tv.tv_sec = 2;
	tv.tv_usec = 0;

#ifdef lint
	/*
	 * Lint can't follow the logic, so thinks that snames and len
	 * can be used before being set.  They can't, but lint can't
	 * figure it out.  To address the lint warning, initialize
	 * snames and len for lint.
	 */
	snames = NULL;
	len = 0;
#endif

	/*
	 * Ping the null NFS procedure of every server in
	 * the list until one responds.  We always start
	 * at the head of the list and always skip the one
	 * that is current, since it's caused us a problem.
	 */
	while (svp == NULL) {
		for (svp = mi->mi_servers; svp; svp = svp->sv_next) {

			mutex_enter(&mi->mi_lock);
			if (FS_OR_ZONE_GONE4(mi->mi_vfsp)) {
				mi->mi_flags |= MI4_RECOV_FAIL;
				mutex_exit(&mi->mi_lock);
				(void) nfs_rw_exit(&mi->mi_recovlock);
				*recov_fail = TRUE;
				if (oncethru)
					kmem_free(snames, len);
				return;
			}
			mutex_exit(&mi->mi_lock);

			(void) nfs_rw_enter_sig(&svp->sv_lock, RW_READER, 0);
			if (svp->sv_flags & SV4_NOTINUSE) {
				nfs_rw_exit(&svp->sv_lock);
				continue;
			}
			nfs_rw_exit(&svp->sv_lock);

			if (!oncethru && svp == mi->mi_curr_serv)
				continue;

			error = clnt_tli_kcreate(svp->sv_knconf, &svp->sv_addr,
			    NFS_PROGRAM, NFS_V4, 0, 1, CRED(), &cl);
			if (error)
				continue;

			if (!(mi->mi_flags & MI4_INT))
				cl->cl_nosignal = TRUE;
			status = CLNT_CALL(cl, RFS_NULL, xdr_void, NULL,
			    xdr_void, NULL, tv);
			if (!(mi->mi_flags & MI4_INT))
				cl->cl_nosignal = FALSE;
			AUTH_DESTROY(cl->cl_auth);
			CLNT_DESTROY(cl);
			if (status == RPC_SUCCESS) {
				nfs4_queue_event(RE_FAILOVER, mi,
				    svp == mi->mi_curr_serv ? NULL :
				    svp->sv_hostname, 0, NULL, NULL, 0,
				    NULL, 0, TAG_NONE, TAG_NONE, 0, 0);
				break;
			}
		}

		if (svp == NULL) {
			if (!oncethru) {
				snames = nfs4_getsrvnames(mi, &len);
				nfs4_queue_fact(RF_SRVS_NOT_RESPOND, mi,
				    0, 0, 0, FALSE, snames, 0, NULL);
				oncethru = 1;
			}
			delay(hz);
		}
	}

	if (oncethru) {
		nfs4_queue_fact(RF_SRVS_OK, mi, 0, 0, 0, FALSE, snames,
		    0, NULL);
		kmem_free(snames, len);
	}

#if DEBUG
	(void) nfs_rw_enter_sig(&svp->sv_lock, RW_READER, 0);
	ASSERT((svp->sv_flags & SV4_NOTINUSE) == 0);
	nfs_rw_exit(&svp->sv_lock);
#endif

	mutex_enter(&mi->mi_lock);
	mi->mi_recovflags &= ~MI4R_NEED_NEW_SERVER;
	if (svp != mi->mi_curr_serv) {
		servinfo4_t *osvp = mi->mi_curr_serv;

		mutex_exit(&mi->mi_lock);

		/*
		 * Update server-dependent fields in the root vnode.
		 */
		index = rtable4hash(mi->mi_rootfh);
		rw_enter(&rtable4[index].r_lock, RW_WRITER);

		rp = r4find(&rtable4[index], mi->mi_rootfh, mi->mi_vfsp);
		if (rp != NULL) {
			NFS4_DEBUG(nfs4_client_failover_debug, (CE_NOTE,
			    "recov_newserver: remapping %s", rnode4info(rp)));
			mutex_enter(&rp->r_statelock);
			rp->r_server = svp;
			PURGE_ATTRCACHE4_LOCKED(rp);
			mutex_exit(&rp->r_statelock);
			(void) nfs4_free_data_reclaim(rp);
			nfs4_purge_rddir_cache(RTOV4(rp));
			rw_exit(&rtable4[index].r_lock);
			NFS4_DEBUG(nfs4_client_failover_debug, (CE_NOTE,
			    "recov_newserver: done with %s",
			    rnode4info(rp)));
			VN_RELE(RTOV4(rp));
		} else
			rw_exit(&rtable4[index].r_lock);
		(void) dnlc_purge_vfsp(mi->mi_vfsp, 0);

		mutex_enter(&mi->mi_lock);
		mi->mi_recovflags |= MI4R_REOPEN_FILES | MI4R_REMAP_FILES;
		if (recovp->rc_srv_reboot)
			mi->mi_recovflags |= MI4R_SRV_REBOOT;
		mi->mi_curr_serv = svp;
		mi->mi_failover++;
		mi->mi_flags &= ~MI4_BADOWNER_DEBUG;
		mutex_exit(&mi->mi_lock);

		(void) nfs_rw_enter_sig(&svp->sv_lock, RW_READER, 0);
		fh.nfs_fh4_len = svp->sv_fhandle.fh_len;
		fh.nfs_fh4_val = svp->sv_fhandle.fh_buf;
		sfh4_update(mi->mi_rootfh, &fh);
		fh.nfs_fh4_len = svp->sv_pfhandle.fh_len;
		fh.nfs_fh4_val = svp->sv_pfhandle.fh_buf;
		sfh4_update(mi->mi_srvparentfh, &fh);
		nfs_rw_exit(&svp->sv_lock);

		*spp = nfs4_move_mi(mi, osvp, svp);
		if (osp != NULL)
			nfs4_server_rele(osp);
	} else
		mutex_exit(&mi->mi_lock);
	(void) nfs_rw_exit(&mi->mi_recovlock);
}

/*
 * Clientid.
 */

static void
recov_clientid(recov_info_t *recovp, nfs4_server_t *sp)
{
	mntinfo4_t *mi = recovp->rc_mi;
	int error = 0;
	int still_stale;
	int need_new_s;

	ASSERT(sp != NULL);

	/*
	 * Acquire the recovery lock and then verify that the clientid
	 * still needs to be recovered.  (Note that s_recovlock is supposed
	 * to be acquired before s_lock.)  Since the thread holds the
	 * recovery lock, no other thread will recover the clientid.
	 */
	(void) nfs_rw_enter_sig(&sp->s_recovlock, RW_WRITER, 0);
	(void) nfs_rw_enter_sig(&mi->mi_recovlock, RW_WRITER, 0);
	mutex_enter(&sp->s_lock);
	still_stale = ((sp->s_flags & N4S_CLIENTID_SET) == 0);
	mutex_exit(&sp->s_lock);

	if (still_stale) {
		nfs4_error_t n4e;

		nfs4_error_zinit(&n4e);
		nfs4setclientid(mi, kcred, TRUE, &n4e);
		error = n4e.error;
		if (error != 0) {

			/*
			 * nfs4setclientid may have set MI4R_NEED_NEW_SERVER,
			 * if so, just return and let recov_thread drive
			 * failover.
			 */
			mutex_enter(&mi->mi_lock);
			need_new_s = mi->mi_recovflags & MI4R_NEED_NEW_SERVER;
			mutex_exit(&mi->mi_lock);

			if (need_new_s) {
				nfs_rw_exit(&mi->mi_recovlock);
				nfs_rw_exit(&sp->s_recovlock);
				return;
			}

			nfs4_queue_event(RE_CLIENTID, mi, NULL, n4e.error, NULL,
			    NULL, n4e.stat, NULL, 0, TAG_NONE, TAG_NONE, 0, 0);
			mutex_enter(&mi->mi_lock);
			mi->mi_flags |= MI4_RECOV_FAIL;
			mi->mi_error = recovp->rc_error;
			mutex_exit(&mi->mi_lock);
			/* don't destroy the nfs4_server, let umount do it */
		}
	}

	if (error == 0) {
		mutex_enter(&mi->mi_lock);
		mi->mi_recovflags &= ~MI4R_NEED_CLIENTID;
		/*
		 * If still_stale isn't true, then another thread already
		 * recovered the clientid.  And that thread that set the
		 * clientid will have initiated reopening files on all the
		 * filesystems for the server, so we should not initiate
		 * reopening for this filesystem here.
		 */
		if (still_stale) {
			mi->mi_recovflags |= MI4R_REOPEN_FILES;
			if (recovp->rc_srv_reboot)
				mi->mi_recovflags |= MI4R_SRV_REBOOT;
		}
		mutex_exit(&mi->mi_lock);
	}

	nfs_rw_exit(&mi->mi_recovlock);

	if (error != 0) {
		nfs_rw_exit(&sp->s_recovlock);
		mutex_enter(&mi->mi_lock);
		if ((mi->mi_flags & MI4_RECOV_FAIL) == 0)
			delay(SEC_TO_TICK(recov_err_delay));
		mutex_exit(&mi->mi_lock);
	} else {
		mntinfo4_t **milist;
		mntinfo4_t *tmi;
		int nummi, i;

		/*
		 * Initiate recovery of open files for other filesystems.
		 * We create an array of filesystems, rather than just
		 * walking the filesystem list, to avoid deadlock issues
		 * with s_lock and mi_recovlock.
		 */
		milist = make_milist(sp, &nummi);
		for (i = 0; i < nummi; i++) {
			tmi = milist[i];
			if (tmi != mi) {
				(void) nfs_rw_enter_sig(&tmi->mi_recovlock,
				    RW_READER, 0);
				start_recovery_action(NR_OPENFILES, TRUE, tmi,
				    NULL, NULL);
				nfs_rw_exit(&tmi->mi_recovlock);
			}
		}
		free_milist(milist, nummi);

		nfs_rw_exit(&sp->s_recovlock);
	}
}

/*
 * Return an array of filesystems associated with the given server.  The
 * caller should call free_milist() to free the references and memory.
 */

static mntinfo4_t **
make_milist(nfs4_server_t *sp, int *nummip)
{
	int nummi, i;
	mntinfo4_t **milist;
	mntinfo4_t *tmi;

	mutex_enter(&sp->s_lock);
	nummi = 0;
	for (tmi = sp->mntinfo4_list; tmi != NULL; tmi = tmi->mi_clientid_next)
		nummi++;

	milist = kmem_alloc(nummi * sizeof (mntinfo4_t *), KM_SLEEP);

	for (i = 0, tmi = sp->mntinfo4_list; tmi != NULL; i++,
	    tmi = tmi->mi_clientid_next) {
		milist[i] = tmi;
		VFS_HOLD(tmi->mi_vfsp);
	}
	mutex_exit(&sp->s_lock);

	*nummip = nummi;
	return (milist);
}

/*
 * Free the filesystem list created by make_milist().
 */

static void
free_milist(mntinfo4_t **milist, int nummi)
{
	mntinfo4_t *tmi;
	int i;

	for (i = 0; i < nummi; i++) {
		tmi = milist[i];
		VFS_RELE(tmi->mi_vfsp);
	}
	kmem_free(milist, nummi * sizeof (mntinfo4_t *));
}

/*
 * Filehandle
 */

/*
 * Lookup the filehandle for the given vnode and update the rnode if it has
 * changed.
 *
 * Errors:
 * - if the filehandle could not be updated because of an error that
 *   requires further recovery, initiate that recovery and return.
 * - if the filehandle could not be updated because of a signal, pretend we
 *   succeeded and let someone else deal with it.
 * - if the filehandle could not be updated and the filesystem has been
 *   forcibly unmounted, pretend we succeeded, and let the caller deal with
 *   the forced unmount (to retry or not to retry, that is the question).
 * - if the filehandle could not be updated because of some other error,
 *   mark the rnode bad and return.
 */
static void
recov_filehandle(nfs4_recov_t action, mntinfo4_t *mi, vnode_t *vp)
{
	rnode4_t *rp = VTOR4(vp);
	nfs4_error_t e = { 0, NFS4_OK, RPC_SUCCESS };
	bool_t needrecov;

	mutex_enter(&rp->r_statelock);

	if (rp->r_flags & R4RECOVERR) {
		mutex_exit(&rp->r_statelock);
		return;
	}

	/*
	 * If someone else is updating the filehandle, wait for them to
	 * finish and then let our caller retry.
	 */
	if (rp->r_flags & R4RECEXPFH) {
		while (rp->r_flags & R4RECEXPFH) {
			cv_wait(&rp->r_cv, &rp->r_statelock);
		}
		mutex_exit(&rp->r_statelock);
		return;
	}
	rp->r_flags |= R4RECEXPFH;
	mutex_exit(&rp->r_statelock);

	if (action == NR_BADHANDLE) {
		/* shouldn't happen */
		nfs4_queue_event(RE_BADHANDLE, mi, NULL, 0,
		    vp, NULL, 0, NULL, 0, TAG_NONE, TAG_NONE, 0, 0);
	}

	nfs4_remap_file(mi, vp, 0, &e);
	needrecov = nfs4_needs_recovery(&e, FALSE, mi->mi_vfsp);

	/*
	 * If we get BADHANDLE, FHEXPIRED or STALE in their handler,
	 * something is broken. Don't try to recover, just mark the
	 * file dead.
	 */
	DTRACE_PROBE2(recov__filehandle, nfs4_error_t, &e, vnode_t, vp);
	if (needrecov) {
		if (e.error == 0) {
			switch (e.stat) {
			case NFS4ERR_BADHANDLE:
			case NFS4ERR_FHEXPIRED:
			case NFS4ERR_STALE:
				goto norec;	/* Unrecoverable errors */
			default:
				break;
			}
		}
		(void) nfs4_start_recovery(&e, mi, vp, NULL,
		    NULL, NULL, OP_LOOKUP, NULL, NULL, NULL);

	} else if (e.error != EINTR &&
	    !NFS4_FRC_UNMT_ERR(e.error, mi->mi_vfsp) &&
	    (e.error != 0 || e.stat != NFS4_OK)) {
		nfs4_recov_fh_fail(vp, e.error, e.stat);
		/*
		 * Don't set r_error to ESTALE. Higher-level code (e.g.,
		 * cstatat_getvp()) retries on ESTALE, which would cause
		 * an infinite loop.
		 */
	}
norec:
	mutex_enter(&rp->r_statelock);
	rp->r_flags &= ~R4RECEXPFH;
	cv_broadcast(&rp->r_cv);
	mutex_exit(&rp->r_statelock);
}

/*
 * Stale Filehandle
 */

/*
 * A stale filehandle can happen when an individual file has
 * been removed, or when an entire filesystem has been taken
 * offline.  To distinguish these cases, we do this:
 * - if a GETATTR with the current filehandle is okay, we do
 *   nothing (this can happen with two-filehandle ops)
 * - if the GETATTR fails, but a GETATTR of the root filehandle
 *   succeeds, mark the rnode with R4STALE, which will stop use
 * - if the GETATTR fails, and a GETATTR of the root filehandle
 *   also fails, we consider the problem filesystem-wide, so:
 *   - if we can failover, we should
 *   - if we can't failover, we should mark both the original
 *     vnode and the root bad
 */
static void
recov_stale(mntinfo4_t *mi, vnode_t *vp)
{
	rnode4_t *rp = VTOR4(vp);
	vnode_t *rootvp = NULL;
	nfs4_error_t e = { 0, NFS4_OK, RPC_SUCCESS };
	nfs4_ga_res_t gar;
	char *fail_msg = "failed to recover from NFS4ERR_STALE";
	bool_t needrecov;

	mutex_enter(&rp->r_statelock);

	if (rp->r_flags & R4RECOVERR) {
		mutex_exit(&rp->r_statelock);
		NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
		    "recov_stale: already marked dead, rp %s",
		    rnode4info(rp)));
		return;
	}

	if (rp->r_flags & R4STALE) {
		mutex_exit(&rp->r_statelock);
		NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
		    "recov_stale: already marked stale, rp %s",
		    rnode4info(rp)));
		return;
	}

	mutex_exit(&rp->r_statelock);

	/* Try a GETATTR on this vnode */
	nfs4_getattr_otw_norecovery(vp, &gar, &e, CRED(), 0);

	/*
	 * Handle non-STALE recoverable errors
	 */
	needrecov = nfs4_needs_recovery(&e, FALSE, vp->v_vfsp);
	if (needrecov) {
		if (e.error == 0) {
			switch (e.stat) {
			case NFS4ERR_STALE:
			case NFS4ERR_BADHANDLE:
				goto norec;	/* Unrecoverable */
			default:
				break;
			}
		}
		(void) nfs4_start_recovery(&e, mi, vp, NULL,
		    NULL, NULL, OP_GETATTR, NULL, NULL, NULL);
		goto out;
	}
norec:
	/* Are things OK for this vnode? */
	if (!e.error && e.stat == NFS4_OK) {
		NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
		    "recov_stale: file appears fine, rp %s",
		    rnode4info(rp)));
		goto out;
	}

	/* Did we get an unrelated non-recoverable error? */
	if (e.error || e.stat != NFS4ERR_STALE) {
		nfs4_fail_recov(vp, fail_msg, e.error, e.stat);
		NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
		    "recov_stale: unrelated fatal error, rp %s",
		    rnode4info(rp)));
		goto out;
	}

	/*
	 * If we don't appear to be dealing with the root node, find it.
	 */
	if ((vp->v_flag & VROOT) == 0) {
		nfs4_error_zinit(&e);
		e.error = VFS_ROOT(vp->v_vfsp, &rootvp);
		if (e.error) {
			nfs4_fail_recov(vp, fail_msg, 0, NFS4ERR_STALE);
			NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
			    "recov_stale: can't find root node for rp %s",
			    rnode4info(rp)));
			goto out;
		}
	}

	/* Try a GETATTR on the root vnode */
	if (rootvp != NULL) {
		nfs4_error_zinit(&e);
		nfs4_getattr_otw_norecovery(rootvp, &gar, &e, CRED(), 0);

		needrecov = nfs4_needs_recovery(&e, FALSE, vp->v_vfsp);
		if (needrecov) {
			if (e.error == 0) {
				switch (e.stat) {
				case NFS4ERR_STALE:
				case NFS4ERR_BADHANDLE:
					goto unrec;	/* Unrecoverable */
				default:
					break;
				}
			}
			(void) nfs4_start_recovery(&e, mi, rootvp, NULL,
			    NULL, NULL, OP_GETATTR, NULL, NULL, NULL);
		}
unrec:
		/*
		 * Check to see if a failover attempt is warranted
		 * NB: nfs4_try_failover doesn't check for STALE
		 * because recov_stale gets a shot first.  Now that
		 * recov_stale has failed, go ahead and try failover.
		 *
		 * If the getattr on the root filehandle was successful,
		 * then mark recovery as failed for 'vp' and exit.
		 */
		if (nfs4_try_failover(&e) == 0 && e.stat != NFS4ERR_STALE) {
			/*
			 * pass the original error to fail_recov, not
			 * the one from trying the root vnode.
			 */
			nfs4_fail_recov(vp, fail_msg, 0, NFS4ERR_STALE);
			NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
			    "recov_stale: root node OK, marking "
			    "dead rp %s", rnode4info(rp)));
			goto out;
		}
	}

	/*
	 * Here, we know that both the original file and the
	 * root filehandle (which may be the same) are stale.
	 * We want to fail over if we can, and if we can't, we
	 * want to mark everything in sight bad.
	 */
	if (FAILOVER_MOUNT4(mi)) {
		mutex_enter(&mi->mi_lock);
		mi->mi_recovflags |= MI4R_NEED_NEW_SERVER;
		NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
		    "recov_stale: failing over due to rp %s",
		    rnode4info(rp)));
		mutex_exit(&mi->mi_lock);
	} else {
		rnode4_t *rootrp;
		servinfo4_t *svp;

		/*
		 * Can't fail over, so mark things dead.
		 *
		 * If rootvp is set, we know we have a distinct
		 * non-root vnode which can be marked dead in
		 * the usual way.
		 *
		 * Then we want to mark the root vnode dead.
		 * Note that if rootvp wasn't set, our vp is
		 * actually the root vnode.
		 */
		if (rootvp != NULL) {
			NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
			    "recov_stale: can't fail over, marking dead rp %s",
			    rnode4info(rp)));
			nfs4_fail_recov(vp, fail_msg, 0, NFS4ERR_STALE);
		} else {
			rootvp = vp;
			VN_HOLD(rootvp);
		}

		/*
		 * Mark root dead, but quietly - since
		 * the root rnode is frequently recreated,
		 * we can encounter this at every access.
		 * Also mark recovery as failed on this VFS.
		 */
		rootrp = VTOR4(rootvp);
		NFS4_DEBUG(nfs4_client_recov_debug, (CE_CONT,
		    "recov_stale: marking dead root rp %s",
		    rnode4info(rootrp)));
		mutex_enter(&rootrp->r_statelock);
		rootrp->r_flags |= (R4RECOVERR | R4STALE);
		rootrp->r_error = ESTALE;
		mutex_exit(&rootrp->r_statelock);
		mutex_enter(&mi->mi_lock);
		mi->mi_error = ESTALE;
		mutex_exit(&mi->mi_lock);

		svp = mi->mi_curr_serv;
		(void) nfs_rw_enter_sig(&svp->sv_lock, RW_WRITER, 0);
		svp->sv_flags |= SV4_ROOT_STALE;
		nfs_rw_exit(&svp->sv_lock);
	}

out:
	if (rootvp)
		VN_RELE(rootvp);
}

/*
 * Locks.
 */

/*
 * Reclaim all the active (acquired) locks for the given file.
 * If a process lost a lock, the process is sent a SIGLOST.  This is not
 * considered an error.
 *
 * Return values:
 * Errors and status are returned via the nfs4_error_t parameter
 * If an error indicates that recovery is needed, the caller is responsible
 * for dealing with it.
 */

static void
relock_file(vnode_t *vp, mntinfo4_t *mi, nfs4_error_t *ep,
    fattr4_change pre_change)
{
	locklist_t *locks, *llp;
	rnode4_t *rp;

	ASSERT(ep != NULL);
	nfs4_error_zinit(ep);

	if (VTOMI4(vp)->mi_flags & MI4_LLOCK)
		return;

	nfs4_flush_lock_owners(VTOR4(vp));

	/*
	 * If we get an error that requires recovery actions, just bail out
	 * and let the top-level recovery code handle it.
	 *
	 * If we get some other error, kill the process that owned the lock
	 * and mark its remaining locks (if any) as belonging to NOPID, so
	 * that we don't make any more reclaim requests for that process.
	 */

	rp = VTOR4(vp);
	locks = flk_active_locks_for_vp(vp);
	for (llp = locks; llp != NULL; llp = llp->ll_next) {
		int did_reclaim = 1;

		ASSERT(llp->ll_vp == vp);
		if (llp->ll_flock.l_pid == NOPID)
			continue;
		reclaim_one_lock(vp, &llp->ll_flock, ep, &did_reclaim);
		/*
		 * If we need to restart recovery, stop processing the
		 * list.  Some errors would be recoverable under other
		 * circumstances, but if they happen here we just give up
		 * on the lock.
		 */
		if (nfs4_needs_recovery(ep, TRUE, vp->v_vfsp)) {
			if (ep->error != 0)
				break;
			if (!nfs4_recov_marks_dead(ep->stat))
				break;
		}
		/*
		 *   In case the server isn't offering us a grace period, or
		 * if we missed it, we might have opened & locked from scratch,
		 * rather than reopened/reclaimed.
		 *   We need to ensure that the object hadn't been otherwise
		 * changed during this time, by comparing the changeinfo.
		 *   We get passed the changeinfo from before the reopen by our
		 * caller, in pre_change.
		 *   The changeinfo from after the reopen is in rp->r_change,
		 * courtesy of the GETATTR in the reopen.
		 *   If they're different, then the file has changed, and we
		 * have to SIGLOST the app.
		 */
		if (ep->error == 0 && ep->stat == NFS4_OK && !did_reclaim) {
			mutex_enter(&rp->r_statelock);
			if (pre_change != rp->r_change)
				ep->stat = NFS4ERR_NO_GRACE;
			mutex_exit(&rp->r_statelock);
		}
		if (ep->error != 0 || ep->stat != NFS4_OK) {
			if (ep->error != 0)
				nfs4_queue_event(RE_FAIL_RELOCK, mi,
				    NULL, ep->error, vp, NULL, 0, NULL,
				    llp->ll_flock.l_pid, TAG_NONE, TAG_NONE,
				    0, 0);
			else
				nfs4_queue_event(RE_FAIL_RELOCK, mi,
				    NULL, 0, vp, NULL, ep->stat, NULL,
				    llp->ll_flock.l_pid, TAG_NONE, TAG_NONE,
				    0, 0);
			nfs4_send_siglost(llp->ll_flock.l_pid, mi, vp, TRUE,
			    ep->error, ep->stat);
			relock_skip_pid(vp, llp, llp->ll_flock.l_pid);

			/* Reinitialize the nfs4_error and continue */
			nfs4_error_zinit(ep);
		}
	}

	if (locks != NULL)
		flk_free_locklist(locks);
}

/*
 * Reclaim the given lock.
 *
 * Errors are returned via the nfs4_error_t parameter.
 */
static void
reclaim_one_lock(vnode_t *vp, flock64_t *flk, nfs4_error_t *ep,
    int *did_reclaimp)
{
	cred_t *cr;
	rnode4_t *rp = VTOR4(vp);

	cr = pid_to_cr(flk->l_pid);
	if (cr == NULL) {
		nfs4_error_init(ep, ESRCH);
		return;
	}

	do {
		mutex_enter(&rp->r_statelock);
		if (rp->r_flags & R4RECOVERR) {
			mutex_exit(&rp->r_statelock);
			nfs4_error_init(ep, ESTALE);
			break;
		}
		mutex_exit(&rp->r_statelock);

		nfs4frlock(NFS4_LCK_CTYPE_RECLAIM, vp, F_SETLK, flk,
		    FREAD|FWRITE, 0, cr, ep, NULL, did_reclaimp);
		if (ep->error == 0 && ep->stat == NFS4ERR_FHEXPIRED)
			start_recovery_action(NR_FHEXPIRED, TRUE, VTOMI4(vp),
			    vp, NULL);
	} while (ep->error == 0 && ep->stat == NFS4ERR_FHEXPIRED);

	crfree(cr);
}

/*
 * Open files.
 */

/*
 * Verifies if the nfsstat4 is a valid error for marking this vnode dead.
 * Returns 1 if the error is valid; 0 otherwise.
 */
static int
nfs4_valid_recov_err_for_vp(vnode_t *vp, nfsstat4 stat)
{
	/*
	 * We should not be marking non-regular files as dead,
	 * except in very rare cases (eg: BADHANDLE or NFS4ERR_BADNAME).
	 */
	if (vp->v_type != VREG && stat != NFS4ERR_BADHANDLE &&
	    stat != NFS4ERR_BADNAME)
		return (0);

	return (1);
}

/*
 * Failed attempting to recover a filehandle.  If 'stat' is valid for 'vp',
 * then mark the object dead.  Since we've had to do a lookup for
 * filehandle recovery, we will mark the object dead if we got NOENT.
 */
static void
nfs4_recov_fh_fail(vnode_t *vp, int error, nfsstat4 stat)
{
	ASSERT(vp != NULL);

	if ((error == 0) && (stat != NFS4ERR_NOENT) &&
	    (!nfs4_valid_recov_err_for_vp(vp, stat)))
		return;

	nfs4_fail_recov(vp, "can't recover filehandle", error, stat);
}

/*
 * Recovery from a "shouldn't happen" error.  In the long term, we'd like
 * to mark only the data structure(s) that provided the bad value as being
 * bad.  But for now we'll just mark the entire file.
 */

static void
recov_badstate(recov_info_t *recovp, vnode_t *vp, nfsstat4 stat)
{
	ASSERT(vp != NULL);
	recov_throttle(recovp, vp);

	if (!nfs4_valid_recov_err_for_vp(vp, stat))
		return;

	nfs4_fail_recov(vp, "", 0, stat);
}

/*
 * Free up the information saved for a lost state request.
 */
static void
nfs4_free_lost_rqst(nfs4_lost_rqst_t *lrp, nfs4_server_t *sp)
{
	component4 *filep;
	nfs4_open_stream_t *osp;
	int have_sync_lock;

	NFS4_DEBUG(nfs4_lost_rqst_debug,
	    (CE_NOTE, "nfs4_free_lost_rqst:"));

	switch (lrp->lr_op) {
	case OP_OPEN:
		filep = &lrp->lr_ofile;
		if (filep->utf8string_val) {
			kmem_free(filep->utf8string_val, filep->utf8string_len);
			filep->utf8string_val = NULL;
		}
		break;
	case OP_DELEGRETURN:
		nfs4delegreturn_cleanup(VTOR4(lrp->lr_vp), sp);
		break;
	case OP_CLOSE:
		osp = lrp->lr_osp;
		ASSERT(osp != NULL);
		mutex_enter(&osp->os_sync_lock);
		have_sync_lock = 1;
		if (osp->os_pending_close) {
			/* clean up the open file state. */
			osp->os_pending_close = 0;
			nfs4close_notw(lrp->lr_vp, osp, &have_sync_lock);
		}
		if (have_sync_lock)
			mutex_exit(&osp->os_sync_lock);
		break;
	}

	lrp->lr_op = 0;
	if (lrp->lr_oop != NULL) {
		open_owner_rele(lrp->lr_oop);
		lrp->lr_oop = NULL;
	}
	if (lrp->lr_osp != NULL) {
		open_stream_rele(lrp->lr_osp, VTOR4(lrp->lr_vp));
		lrp->lr_osp = NULL;
	}
	if (lrp->lr_lop != NULL) {
		lock_owner_rele(lrp->lr_lop);
		lrp->lr_lop = NULL;
	}
	if (lrp->lr_flk != NULL) {
		kmem_free(lrp->lr_flk, sizeof (flock64_t));
		lrp->lr_flk = NULL;
	}
	if (lrp->lr_vp != NULL) {
		VN_RELE(lrp->lr_vp);
		lrp->lr_vp = NULL;
	}
	if (lrp->lr_dvp != NULL) {
		VN_RELE(lrp->lr_dvp);
		lrp->lr_dvp = NULL;
	}
	if (lrp->lr_cr != NULL) {
		crfree(lrp->lr_cr);
		lrp->lr_cr = NULL;
	}

	kmem_free(lrp, sizeof (nfs4_lost_rqst_t));
}

/*
 * Remove any lost state requests and free them.
 */
static void
nfs4_remove_lost_rqsts(mntinfo4_t *mi, nfs4_server_t *sp)
{
	nfs4_lost_rqst_t *lrp;

	mutex_enter(&mi->mi_lock);
	while ((lrp = list_head(&mi->mi_lost_state)) != NULL) {
		list_remove(&mi->mi_lost_state, lrp);
		mutex_exit(&mi->mi_lock);
		nfs4_free_lost_rqst(lrp, sp);
		mutex_enter(&mi->mi_lock);
	}
	mutex_exit(&mi->mi_lock);
}

/*
 * Reopen all the files for the given filesystem and reclaim any locks.
 */

static void
recov_openfiles(recov_info_t *recovp, nfs4_server_t *sp)
{
	mntinfo4_t *mi = recovp->rc_mi;
	nfs4_opinst_t *reopenlist = NULL, *rep;
	nfs4_error_t e = { 0, NFS4_OK, RPC_SUCCESS };
	open_claim_type4 claim;
	int remap;
	char *fail_msg = "No such file or directory on replica";
	rnode4_t *rp;
	fattr4_change pre_change;

	ASSERT(sp != NULL);

	/*
	 * This check is to allow a 10ms pause before we reopen files
	 * it should allow the server time to have received the CB_NULL
	 * reply and update its internal structures such that (if
	 * applicable) we are granted a delegation on reopened files.
	 */
	mutex_enter(&sp->s_lock);
	if ((sp->s_flags & (N4S_CB_PINGED | N4S_CB_WAITER)) == 0) {
		sp->s_flags |= N4S_CB_WAITER;
		(void) cv_reltimedwait(&sp->wait_cb_null, &sp->s_lock,
		    drv_usectohz(N4S_CB_PAUSE_TIME), TR_CLOCK_TICK);
	}
	mutex_exit(&sp->s_lock);

	(void) nfs_rw_enter_sig(&sp->s_recovlock, RW_READER, 0);
	(void) nfs_rw_enter_sig(&mi->mi_recovlock, RW_WRITER, 0);

	if (NFS4_VOLATILE_FH(mi)) {
		nfs4_remap_root(mi, &e, 0);
		if (nfs4_needs_recovery(&e, FALSE, mi->mi_vfsp)) {
			(void) nfs4_start_recovery(&e, mi, NULL,
			    NULL, NULL, NULL, OP_LOOKUP, NULL, NULL, NULL);
		}
	}

	mutex_enter(&mi->mi_lock);
	if (recovp->rc_srv_reboot || (mi->mi_recovflags & MI4R_SRV_REBOOT))
		claim = CLAIM_PREVIOUS;
	else
		claim = CLAIM_NULL;
	mutex_exit(&mi->mi_lock);

	if (e.error == 0 && e.stat == NFS4_OK) {
		/*
		 * Get a snapshot of open files in the filesystem.  Note
		 * that new opens will stall until the server's grace
		 * period is done.
		 */
		reopenlist = r4mkopenlist(mi);

		mutex_enter(&mi->mi_lock);
		remap = mi->mi_recovflags & MI4R_REMAP_FILES;
		mutex_exit(&mi->mi_lock);
		/*
		 * Since we are re-establishing state on the
		 * server, its ok to blow away the saved lost
		 * requests since we don't need to reissue it.
		 */
		nfs4_remove_lost_rqsts(mi, sp);

		for (rep = reopenlist; rep; rep = rep->re_next) {

			if (remap) {
				nfs4_remap_file(mi, rep->re_vp,
				    NFS4_REMAP_CKATTRS, &e);
			}
			DTRACE_PROBE2(recov__openfiles, nfs4_error_t, &e,
			    vnode_t, rep->re_vp);
			if (e.error == ENOENT || e.stat == NFS4ERR_NOENT) {
				/*
				 * The current server does not have the file
				 * that is to be remapped.  This is most
				 * likely due to an improperly maintained
				 * replica.   The files that are missing from
				 * the server will be marked dead and logged
				 * in order to make sys admins aware of the
				 * problem.
				 */
				nfs4_fail_recov(rep->re_vp,
				    fail_msg, e.error, e.stat);
				/*
				 * We've already handled the error so clear it.
				 */
				nfs4_error_zinit(&e);
				continue;
			} else if (e.error == 0 && e.stat == NFS4_OK) {
				int j;

				rp = VTOR4(rep->re_vp);
				mutex_enter(&rp->r_statelock);
				pre_change = rp->r_change;
				mutex_exit(&rp->r_statelock);

				for (j = 0; j < rep->re_numosp; j++) {
					nfs4_reopen(rep->re_vp, rep->re_osp[j],
					    &e, claim, FALSE, TRUE);
					if (e.error != 0 || e.stat != NFS4_OK)
						break;
				}
				if (nfs4_needs_recovery(&e, TRUE,
				    mi->mi_vfsp)) {
					(void) nfs4_start_recovery(&e, mi,
					    rep->re_vp, NULL, NULL, NULL,
					    OP_OPEN, NULL, NULL, NULL);
					break;
				}
			}
#ifdef DEBUG
			if (nfs4_recovdelay > 0)
				delay(MSEC_TO_TICK(nfs4_recovdelay * 1000));
#endif
			if (e.error == 0 && e.stat == NFS4_OK) {
				relock_file(rep->re_vp, mi, &e, pre_change);

				if (nfs4_needs_recovery(&e, TRUE, mi->mi_vfsp))
					(void) nfs4_start_recovery(&e, mi,
					    rep->re_vp, NULL, NULL, NULL,
					    OP_LOCK, NULL, NULL, NULL);
			}

			if (e.error != 0 || e.stat != NFS4_OK)
				break;
		}

		/*
		 * Check to see if we need to remap files passed in
		 * via the recovery arguments; this will have been
		 * done for open files.  A failure here is not fatal.
		 */
		if (remap) {
			nfs4_error_t ignore;
			nfs4_check_remap(mi, recovp->rc_vp1, NFS4_REMAP_CKATTRS,
			    &ignore);
			nfs4_check_remap(mi, recovp->rc_vp2, NFS4_REMAP_CKATTRS,
			    &ignore);
		}
	}

	if (e.error == 0 && e.stat == NFS4_OK) {
		mutex_enter(&mi->mi_lock);
		mi->mi_recovflags &= ~(MI4R_REOPEN_FILES | MI4R_REMAP_FILES);
		mutex_exit(&mi->mi_lock);
	}

	nfs_rw_exit(&mi->mi_recovlock);
	nfs_rw_exit(&sp->s_recovlock);

	if (reopenlist != NULL)
		r4releopenlist(reopenlist);
}

/*
 * Resend the queued state recovery requests in "rqsts".
 */

static void
nfs4_resend_lost_rqsts(recov_info_t *recovp, nfs4_server_t *sp)
{
	nfs4_lost_rqst_t	*lrp, *tlrp;
	mntinfo4_t		*mi = recovp->rc_mi;
	nfs4_error_t		n4e;
#ifdef NOTYET
	uint32_t		deny_bits = 0;
#endif

	NFS4_DEBUG(nfs4_lost_rqst_debug, (CE_NOTE, "nfs4_resend_lost_rqsts"));

	ASSERT(mi != NULL);
	ASSERT(nfs_rw_lock_held(&mi->mi_recovlock, RW_WRITER));

	mutex_enter(&mi->mi_lock);
	lrp = list_head(&mi->mi_lost_state);
	mutex_exit(&mi->mi_lock);
	while (lrp != NULL) {
		nfs4_error_zinit(&n4e);
		resend_one_op(lrp, &n4e, mi, sp);
		NFS4_DEBUG(nfs4_lost_rqst_debug, (CE_NOTE,
		    "nfs4_resend_lost_rqsts: resend request: for vp %p got "
		    "error %d stat %d", (void *)lrp->lr_vp, n4e.error,
		    n4e.stat));

		/*
		 * If we get a recovery error that we can actually
		 * recover from (such as ETIMEDOUT, FHEXPIRED), we
		 * return and let the recovery thread redrive the call.
		 * Don't requeue unless the zone is still healthy.
		 */
		if (zone_status_get(curproc->p_zone) < ZONE_IS_SHUTTING_DOWN &&
		    nfs4_needs_recovery(&n4e, TRUE, mi->mi_vfsp) &&
		    (nfs4_try_failover(&n4e) ||
		    NFS4_FRC_UNMT_ERR(n4e.error, mi->mi_vfsp) ||
		    (n4e.error == 0 && n4e.stat != NFS4ERR_BADHANDLE &&
		    !nfs4_recov_marks_dead(n4e.stat)))) {
			/*
			 * For these three errors, we want to delay a bit
			 * instead of pounding the server into submission.
			 * We have to do this manually; the normal
			 * processing for these errors only works for
			 * non-recovery requests.
			 */
			if ((n4e.error == 0 && n4e.stat == NFS4ERR_DELAY) ||
			    (n4e.error == 0 && n4e.stat == NFS4ERR_GRACE) ||
			    (n4e.error == 0 && n4e.stat == NFS4ERR_RESOURCE) ||
			    NFS4_FRC_UNMT_ERR(n4e.error, mi->mi_vfsp)) {
				delay(SEC_TO_TICK(nfs4err_delay_time));
			} else {
				(void) nfs4_start_recovery(&n4e,
				    mi, lrp->lr_dvp, lrp->lr_vp, NULL, NULL,
				    lrp->lr_op, NULL, NULL, NULL);
			}
			return;
		}

		mutex_enter(&mi->mi_lock);
		list_remove(&mi->mi_lost_state, lrp);
		tlrp = lrp;
		lrp = list_head(&mi->mi_lost_state);
		mutex_exit(&mi->mi_lock);
		nfs4_free_lost_rqst(tlrp, sp);
	}
}

/*
 * Resend the given op, and issue any necessary undo call.
 * errors are returned via the nfs4_error_t parameter.
 */

static void
resend_one_op(nfs4_lost_rqst_t *lrp, nfs4_error_t *ep,
    mntinfo4_t *mi, nfs4_server_t *sp)
{
	vnode_t *vp;
	nfs4_open_stream_t *osp;
	cred_t *cr;
	uint32_t acc_bits;

	vp = lrp->lr_vp;
	NFS4_DEBUG(nfs4_lost_rqst_debug, (CE_NOTE, "resend_one_op: "
	    "have a lost open/close request for vp %p", (void *)vp));

	switch (lrp->lr_op) {
	case OP_OPEN:
		nfs4_resend_open_otw(&vp, lrp, ep);
		break;
	case OP_OPEN_DOWNGRADE:
		ASSERT(lrp->lr_oop != NULL);
		ep->error = nfs4_start_open_seqid_sync(lrp->lr_oop, mi);
		ASSERT(!ep->error);	/* recov thread always succeeds */
		ASSERT(lrp->lr_osp != NULL);
		mutex_enter(&lrp->lr_osp->os_sync_lock);
		nfs4_open_downgrade(lrp->lr_dg_acc, lrp->lr_dg_deny,
		    lrp->lr_oop, lrp->lr_osp, vp, lrp->lr_cr, lrp,
		    ep, NULL, NULL);
		mutex_exit(&lrp->lr_osp->os_sync_lock);
		nfs4_end_open_seqid_sync(lrp->lr_oop);
		break;
	case OP_CLOSE:
		osp = lrp->lr_osp;
		cr = lrp->lr_cr;
		acc_bits = 0;
		mutex_enter(&osp->os_sync_lock);
		if (osp->os_share_acc_read)
			acc_bits |= OPEN4_SHARE_ACCESS_READ;
		if (osp->os_share_acc_write)
			acc_bits |= OPEN4_SHARE_ACCESS_WRITE;
		mutex_exit(&osp->os_sync_lock);
		nfs4close_one(vp, osp, cr, acc_bits, lrp, ep,
		    CLOSE_RESEND, 0, 0, 0);
		break;
	case OP_LOCK:
	case OP_LOCKU:
		resend_lock(lrp, ep);
		goto done;
	case OP_DELEGRETURN:
		nfs4_resend_delegreturn(lrp, ep, sp);
		goto done;
	default:
#ifdef DEBUG
		cmn_err(CE_PANIC, "resend_one_op: unexpected op: %d",
		    lrp->lr_op);
#endif
		nfs4_queue_event(RE_LOST_STATE_BAD_OP, mi, NULL,
		    lrp->lr_op, lrp->lr_vp, lrp->lr_dvp, NFS4_OK, NULL, 0,
		    TAG_NONE, TAG_NONE, 0, 0);
		nfs4_error_init(ep, EINVAL);
		return;
	}

	/*
	 * No need to retry nor send an "undo" CLOSE in the
	 * event the server rebooted.
	 */
	if (ep->error == 0 && (ep->stat == NFS4ERR_STALE_CLIENTID ||
	    ep->stat == NFS4ERR_STALE_STATEID || ep->stat == NFS4ERR_EXPIRED))
		goto done;

	/*
	 * If we resent a CLOSE or OPEN_DOWNGRADE, there's nothing
	 * to undo.  Undoing locking operations was handled by
	 * resend_lock().
	 */
	if (lrp->lr_op == OP_OPEN_DOWNGRADE || lrp->lr_op == OP_CLOSE)
		goto done;

	/*
	 * If we get any other error for OPEN, then don't attempt
	 * to undo the resend of the open (since it was never
	 * successful!).
	 */
	ASSERT(lrp->lr_op == OP_OPEN);
	if (ep->error || ep->stat != NFS4_OK)
		goto done;

	/*
	 * Now let's undo our OPEN.
	 */
	nfs4_error_zinit(ep);
	close_after_open_resend(vp, lrp->lr_cr, lrp->lr_oacc, ep);
	NFS4_DEBUG(nfs4_lost_rqst_debug, (CE_NOTE, "resend_one_op: "
	    "nfs4close_one: for vp %p got error %d stat %d",
	    (void *)vp, ep->error, ep->stat));

done:
	if (vp != lrp->lr_vp)
		VN_RELE(vp);
}

/*
 * Close a file that was opened via a resent OPEN.
 * Most errors are passed back to the caller (via the return value and
 * *statp), except for FHEXPIRED, which is retried.
 *
 * It might be conceptually cleaner to push the CLOSE request onto the
 * front of the resend queue, rather than sending it here.  That would
 * match the way we undo lost lock requests.  On the other
 * hand, we've already got something that works, and there's no reason to
 * change it at this time.
 */

static void
close_after_open_resend(vnode_t *vp, cred_t *cr, uint32_t acc_bits,
    nfs4_error_t *ep)
{

	for (;;) {
		nfs4close_one(vp, NULL, cr, acc_bits, NULL, ep,
		    CLOSE_AFTER_RESEND, 0, 0, 0);
		if (ep->error == 0 && ep->stat == NFS4_OK)
			break;		/* success; done */
		if (ep->error != 0 || ep->stat != NFS4ERR_FHEXPIRED)
			break;
		/* else retry FHEXPIRED */
	}

}

/*
 * Resend the given lost lock request.  Return an errno value.  If zero,
 * *statp is set to the NFS status code for the call.
 *
 * Issue a SIGLOST and mark the rnode dead if we get a non-recovery error or
 * a recovery error that we don't actually recover from yet (eg: BAD_SEQID).
 * Let the recovery thread redrive the call if we get a recovery error that
 * we can actually recover from.
 */
static void
resend_lock(nfs4_lost_rqst_t *lrp, nfs4_error_t *ep)
{
	bool_t		send_siglost = FALSE;
	vnode_t		*vp = lrp->lr_vp;

	NFS4_DEBUG(nfs4_lost_rqst_debug, (CE_NOTE, "resend_lock:"));
	ASSERT(lrp->lr_ctype == NFS4_LCK_CTYPE_REINSTATE ||
	    lrp->lr_ctype == NFS4_LCK_CTYPE_RESEND);

	nfs4frlock(lrp->lr_ctype, vp, F_SETLK,
	    lrp->lr_flk, FREAD|FWRITE, 0, lrp->lr_cr, ep, lrp, NULL);

	NFS4_DEBUG(nfs4_lost_rqst_debug, (CE_NOTE, "resend_lock: "
	    "nfs4frlock for vp %p returned error %d, stat %d",
	    (void *)vp, ep->error, ep->stat));

	if (ep->error == 0 && ep->stat == 0)
		goto done;
	if (ep->error == 0 && ep->stat == NFS4ERR_DENIED &&
	    lrp->lr_ctype == NFS4_LCK_CTYPE_RESEND)
		goto done;

	/*
	 * If we failed with a non-recovery error, send SIGLOST and
	 * mark the file dead.
	 */
	if (!nfs4_needs_recovery(ep, TRUE, vp->v_vfsp))
		send_siglost = TRUE;
	else {
		/*
		 * Done with recovering LOST LOCK in the event the
		 * server rebooted or we've lost the lease.
		 */
		if (ep->error == 0 && (ep->stat == NFS4ERR_STALE_CLIENTID ||
		    ep->stat == NFS4ERR_STALE_STATEID ||
		    ep->stat == NFS4ERR_EXPIRED)) {
			goto done;
		}

		/*
		 * BAD_STATEID on an unlock indicates that the server has
		 * forgotten about the lock anyway, so act like the call
		 * was successful.
		 */
		if (ep->error == 0 && ep->stat == NFS4ERR_BAD_STATEID &&
		    lrp->lr_op == OP_LOCKU)
			goto done;

		/*
		 * If we got a recovery error that we don't actually
		 * recover from, send SIGLOST.  If the filesystem was
		 * forcibly unmounted, we skip the SIGLOST because (a) it's
		 * unnecessary noise, and (b) there could be a new process
		 * with the same pid as the one that had generated the lost
		 * state request.
		 */
		if (ep->error == 0 && (ep->stat == NFS4ERR_BADHANDLE ||
		    nfs4_recov_marks_dead(ep->stat))) {
			if (!(vp->v_vfsp->vfs_flag & VFS_UNMOUNTED))
				send_siglost = TRUE;
			goto done;
		}

		/*
		 * If the filesystem was forcibly unmounted, we
		 * still need to synchronize with the server and
		 * release state.  Try again later.
		 */
		if (NFS4_FRC_UNMT_ERR(ep->error, vp->v_vfsp))
			goto done;

		/*
		 * If we get a recovery error that we can actually
		 * recover from (such as ETIMEDOUT, FHEXPIRED),
		 * return and let the recovery thread redrive the call.
		 *
		 * For the three errors below, we want to delay a bit
		 * instead of pounding the server into submission.
		 */
		if ((ep->error == 0 && ep->stat == NFS4ERR_DELAY) ||
		    (ep->error == 0 && ep->stat == NFS4ERR_GRACE) ||
		    (ep->error == 0 && ep->stat == NFS4ERR_RESOURCE))
			delay(SEC_TO_TICK(recov_err_delay));
		goto done;
	}

done:
	if (send_siglost) {
		cred_t *sv_cred;

		/*
		 * Must be root or the actual thread being issued the
		 * SIGLOST for this to work, so just become root.
		 */
		sv_cred = curthread->t_cred;
		curthread->t_cred = kcred;
		nfs4_send_siglost(lrp->lr_flk->l_pid, VTOMI4(vp), vp, FALSE,
		    ep->error, ep->stat);
		curthread->t_cred = sv_cred;

		/*
		 * Flush any additional reinstantiation requests for
		 * this operation.  Sending multiple SIGLOSTs to the user
		 * process is unlikely to help and may cause trouble.
		 */
		if (lrp->lr_ctype == NFS4_LCK_CTYPE_REINSTATE)
			flush_reinstate(lrp);
	}
}

/*
 * Remove any lock reinstantiation requests that correspond to the given
 * lost request.  We only remove items that follow lrp in the queue,
 * assuming that lrp will be removed by the generic lost state code.
 */

static void
flush_reinstate(nfs4_lost_rqst_t *lrp)
{
	vnode_t *vp;
	pid_t pid;
	mntinfo4_t *mi;
	nfs4_lost_rqst_t *nlrp;

	vp = lrp->lr_vp;
	mi = VTOMI4(vp);
	pid = lrp->lr_flk->l_pid;

	/*
	 * If there are any more reinstantation requests to get rid of,
	 * they should all be clustered at the front of the lost state
	 * queue.
	 */
	mutex_enter(&mi->mi_lock);
	for (lrp = list_next(&mi->mi_lost_state, lrp); lrp != NULL;
	    lrp = nlrp) {
		nlrp = list_next(&mi->mi_lost_state, lrp);
		if (lrp->lr_op != OP_LOCK && lrp->lr_op != OP_LOCKU)
			break;
		if (lrp->lr_ctype != NFS4_LCK_CTYPE_REINSTATE)
			break;
		ASSERT(lrp->lr_vp == vp);
		ASSERT(lrp->lr_flk->l_pid == pid);
		NFS4_DEBUG(nfs4_lost_rqst_debug, (CE_NOTE,
		    "remove reinstantiation %p", (void *)lrp));
		list_remove(&mi->mi_lost_state, lrp);
		nfs4_free_lost_rqst(lrp, NULL);
	}
	mutex_exit(&mi->mi_lock);
}

/*
 * End of state-specific recovery routines.
 */

/*
 * Allocate a lost request struct, initialize it from lost_rqstp (including
 * bumping the reference counts for the referenced vnode, etc.), and hang
 * it off of recovp.
 */

static void
nfs4_save_lost_rqst(nfs4_lost_rqst_t *lost_rqstp, recov_info_t *recovp,
    nfs4_recov_t *action, mntinfo4_t *mi)
{
	nfs4_lost_rqst_t *destp;

	ASSERT(recovp->rc_lost_rqst == NULL);

	destp = kmem_alloc(sizeof (nfs4_lost_rqst_t), KM_SLEEP);
	recovp->rc_lost_rqst = destp;

	if (lost_rqstp->lr_op == OP_LOCK ||
	    lost_rqstp->lr_op == OP_LOCKU) {
		ASSERT(lost_rqstp->lr_lop);
		*action = NR_LOST_LOCK;
		destp->lr_ctype = lost_rqstp->lr_ctype;
		destp->lr_locktype = lost_rqstp->lr_locktype;
	} else if (lost_rqstp->lr_op == OP_OPEN) {
		component4 *srcfp, *destfp;

		destp->lr_oacc = lost_rqstp->lr_oacc;
		destp->lr_odeny = lost_rqstp->lr_odeny;
		destp->lr_oclaim = lost_rqstp->lr_oclaim;
		if (lost_rqstp->lr_oclaim == CLAIM_DELEGATE_CUR)
			destp->lr_ostateid = lost_rqstp->lr_ostateid;

		srcfp = &lost_rqstp->lr_ofile;
		destfp = &destp->lr_ofile;
		/*
		 * Consume caller's utf8string
		 */
		destfp->utf8string_len = srcfp->utf8string_len;
		destfp->utf8string_val = srcfp->utf8string_val;
		srcfp->utf8string_len = 0;
		srcfp->utf8string_val = NULL;	/* make sure not reused */

		*action = NR_LOST_STATE_RQST;
	} else if (lost_rqstp->lr_op == OP_OPEN_DOWNGRADE) {
		destp->lr_dg_acc = lost_rqstp->lr_dg_acc;
		destp->lr_dg_deny = lost_rqstp->lr_dg_deny;

		*action = NR_LOST_STATE_RQST;
	} else if (lost_rqstp->lr_op == OP_CLOSE) {
		ASSERT(lost_rqstp->lr_oop);
		*action = NR_LOST_STATE_RQST;
	} else if (lost_rqstp->lr_op == OP_DELEGRETURN) {
		*action = NR_LOST_STATE_RQST;
	} else {
#ifdef DEBUG
		cmn_err(CE_PANIC, "nfs4_save_lost_rqst: bad op %d",
		    lost_rqstp->lr_op);
#endif
		nfs4_queue_event(RE_LOST_STATE_BAD_OP, mi, NULL,
		    lost_rqstp->lr_op, lost_rqstp->lr_vp, lost_rqstp->lr_dvp,
		    NFS4_OK, NULL, curproc->p_pid, TAG_NONE, TAG_NONE, 0, 0);
		*action = NR_UNUSED;
		recovp->rc_lost_rqst = NULL;
		kmem_free(destp, sizeof (nfs4_lost_rqst_t));
		return;
	}

	destp->lr_op = lost_rqstp->lr_op;
	destp->lr_vp = lost_rqstp->lr_vp;
	if (destp->lr_vp)
		VN_HOLD(destp->lr_vp);
	destp->lr_dvp = lost_rqstp->lr_dvp;
	if (destp->lr_dvp)
		VN_HOLD(destp->lr_dvp);
	destp->lr_oop = lost_rqstp->lr_oop;
	if (destp->lr_oop)
		open_owner_hold(destp->lr_oop);
	destp->lr_osp = lost_rqstp->lr_osp;
	if (destp->lr_osp)
		open_stream_hold(destp->lr_osp);
	destp->lr_lop = lost_rqstp->lr_lop;
	if (destp->lr_lop)
		lock_owner_hold(destp->lr_lop);
	destp->lr_cr = lost_rqstp->lr_cr;
	if (destp->lr_cr)
		crhold(destp->lr_cr);
	if (lost_rqstp->lr_flk == NULL)
		destp->lr_flk = NULL;
	else {
		destp->lr_flk = kmem_alloc(sizeof (flock64_t), KM_SLEEP);
		*destp->lr_flk = *lost_rqstp->lr_flk;
	}
	destp->lr_putfirst = lost_rqstp->lr_putfirst;
}

/*
 * Map the given return values (errno and nfs4 status code) to a recovery
 * action and fill in the following fields of recovp: rc_action,
 * rc_srv_reboot, rc_stateid, rc_lost_rqst.
 */

void
errs_to_action(recov_info_t *recovp,
    nfs4_server_t *sp, mntinfo4_t *mi, stateid4 *sidp,
    nfs4_lost_rqst_t *lost_rqstp, int unmounted, nfs_opnum4 op,
    nfs4_bseqid_entry_t *bsep)
{
	nfs4_recov_t action = NR_UNUSED;
	bool_t reboot = FALSE;
	int try_f;
	int error = recovp->rc_orig_errors.error;
	nfsstat4 stat = recovp->rc_orig_errors.stat;

	bzero(&recovp->rc_stateid, sizeof (stateid4));
	recovp->rc_lost_rqst = NULL;
	recovp->rc_bseqid_rqst = NULL;

	try_f = nfs4_try_failover(&recovp->rc_orig_errors) &&
	    FAILOVER_MOUNT4(mi);

	/*
	 * We start recovery for EINTR only in the lost lock
	 * or lost open/close case.
	 */

	if (try_f || error == EINTR || (error == EIO && unmounted)) {
		recovp->rc_error = (error != 0 ? error : geterrno4(stat));
		if (lost_rqstp) {
			ASSERT(lost_rqstp->lr_op != 0);
			nfs4_save_lost_rqst(lost_rqstp, recovp, &action, mi);
		}
		if (try_f)
			action = NR_FAILOVER;
	} else if (error != 0) {
		recovp->rc_error = error;
		nfs4_queue_event(RE_UNEXPECTED_ERRNO, mi, NULL, error, NULL,
		    NULL, 0, NULL, 0, TAG_NONE, TAG_NONE, 0, 0);
		action = NR_CLIENTID;
	} else {
		recovp->rc_error = geterrno4(stat);
		switch (stat) {
#ifdef notyet
		case NFS4ERR_LEASE_MOVED:
			action = xxx;
			break;
#endif
		case NFS4ERR_MOVED:
			action = NR_MOVED;
			break;
		case NFS4ERR_BADHANDLE:
			action = NR_BADHANDLE;
			break;
		case NFS4ERR_BAD_SEQID:
			if (bsep)
				save_bseqid_rqst(bsep, recovp);
			action = NR_BAD_SEQID;
			break;
		case NFS4ERR_OLD_STATEID:
			action = NR_OLDSTATEID;
			break;
		case NFS4ERR_WRONGSEC:
			action = NR_WRONGSEC;
			break;
		case NFS4ERR_FHEXPIRED:
			action = NR_FHEXPIRED;
			break;
		case NFS4ERR_BAD_STATEID:
			if (sp == NULL || (sp != NULL && inlease(sp))) {

				action = NR_BAD_STATEID;
				if (sidp)
					recovp->rc_stateid = *sidp;
			} else
				action = NR_CLIENTID;
			break;
		case NFS4ERR_EXPIRED:
			/*
			 * The client's lease has expired, either due
			 * to a network partition or perhaps a client
			 * error.  In either case, try an NR_CLIENTID
			 * style recovery.  reboot remains false, since
			 * there is no evidence the server has rebooted.
			 * This will cause CLAIM_NULL opens and lock
			 * requests without the reclaim bit.
			 */
			action = NR_CLIENTID;

			DTRACE_PROBE4(nfs4__expired,
			    nfs4_server_t *, sp,
			    mntinfo4_t *, mi,
			    stateid4 *, sidp, int, op);

			break;
		case NFS4ERR_STALE_CLIENTID:
		case NFS4ERR_STALE_STATEID:
			action = NR_CLIENTID;
			reboot = TRUE;
			break;
		case NFS4ERR_RESOURCE:
			/*
			 * If this had been a FAILOVER mount, then
			 * we'd have tried failover.  Since it's not,
			 * just delay a while and retry.
			 */
			action = NR_DELAY;
			break;
		case NFS4ERR_GRACE:
			action = NR_GRACE;
			break;
		case NFS4ERR_DELAY:
			action = NR_DELAY;
			break;
		case NFS4ERR_STALE:
			action = NR_STALE;
			break;
		default:
			nfs4_queue_event(RE_UNEXPECTED_STATUS, mi, NULL, 0,
			    NULL, NULL, stat, NULL, 0, TAG_NONE, TAG_NONE,
			    0, 0);
			action = NR_CLIENTID;
			break;
		}
	}

	/* make sure action got set */
	ASSERT(action != NR_UNUSED);
	recovp->rc_srv_reboot = reboot;
	recovp->rc_action = action;
	nfs4_queue_fact(RF_ERR, mi, stat, action, op, reboot, NULL, error,
	    NULL);
}

/*
 * Return the (held) credential for the process with the given pid.
 * May return NULL (e.g., process not found).
 */

static cred_t *
pid_to_cr(pid_t pid)
{
	proc_t *p;
	cred_t *cr;

	mutex_enter(&pidlock);
	if ((p = prfind(pid)) == NULL) {
		mutex_exit(&pidlock);
		return (NULL);
	}

	mutex_enter(&p->p_crlock);
	crhold(cr = p->p_cred);
	mutex_exit(&p->p_crlock);
	mutex_exit(&pidlock);

	return (cr);
}

/*
 * Send SIGLOST to the given process and queue the event.
 *
 * The 'dump' boolean tells us whether this action should dump the
 * in-kernel queue of recovery messages or not.
 */

void
nfs4_send_siglost(pid_t pid, mntinfo4_t *mi, vnode_t *vp, bool_t dump,
    int error, nfsstat4 stat)
{
	proc_t *p;

	mutex_enter(&pidlock);
	p = prfind(pid);
	if (p)
		psignal(p, SIGLOST);
	mutex_exit(&pidlock);
	nfs4_queue_event(dump ? RE_SIGLOST : RE_SIGLOST_NO_DUMP, mi,
	    NULL, error, vp, NULL, stat, NULL, pid, TAG_NONE, TAG_NONE, 0, 0);
}

/*
 * Scan the lock list for entries that match the given pid.  Unregister those
 * locks that do and change their pid to NOPID.
 */

static void
relock_skip_pid(vnode_t *vp, locklist_t *llp, pid_t pid)
{
	for (; llp != NULL; llp = llp->ll_next) {
		if (llp->ll_flock.l_pid == pid) {
			int r;

			/*
			 * Unregister the lost lock.
			 */
			llp->ll_flock.l_type = F_UNLCK;
			r = reclock(vp, &llp->ll_flock, SETFLCK, FREAD | FWRITE,
			    0, NULL);
			/* The unlock cannot fail */
			ASSERT(r == 0);

			llp->ll_flock.l_pid = NOPID;
		}
	}
}

/*
 * Mark a file as having failed recovery, after making a last-ditch effort
 * to return any delegation.
 *
 * Sets r_error to EIO or ESTALE for the given vnode.
 */
void
nfs4_fail_recov(vnode_t *vp, char *why, int error, nfsstat4 stat)
{
	rnode4_t *rp = VTOR4(vp);

#ifdef DEBUG
	if (nfs4_fail_recov_stop)
		debug_enter("nfs4_fail_recov");
#endif

	mutex_enter(&rp->r_statelock);
	if (rp->r_flags & (R4RECOVERR|R4RECOVERRP)) {
		mutex_exit(&rp->r_statelock);
		return;
	}

	/*
	 * Set R4RECOVERRP to indicate that a recovery error is in
	 * progress.  This will shut down reads and writes at the top
	 * half.  Don't set R4RECOVERR until after we've returned the
	 * delegation, otherwise it will fail.
	 */

	rp->r_flags |= R4RECOVERRP;
	mutex_exit(&rp->r_statelock);

	nfs4delegabandon(rp);

	mutex_enter(&rp->r_statelock);
	rp->r_flags |= (R4RECOVERR | R4STALE);
	rp->r_error = (error == 0 && stat == NFS4ERR_STALE) ? ESTALE : EIO;
	PURGE_ATTRCACHE4_LOCKED(rp);
	if (!(vp->v_vfsp->vfs_flag & VFS_UNMOUNTED))
		nfs4_queue_event(RE_DEAD_FILE, VTOMI4(vp), NULL, error,
		    vp, NULL, stat, why, 0, TAG_NONE, TAG_NONE, 0, 0);
	mutex_exit(&rp->r_statelock);

	dnlc_purge_vp(vp);
}

/*
 * recov_throttle: if the file had the same recovery action within the
 * throttle interval, wait for the throttle interval to finish before
 * proceeding.
 *
 * Side effects: updates the rnode with the current recovery information.
 */

static void
recov_throttle(recov_info_t *recovp, vnode_t *vp)
{
	time_t curtime, time_to_wait;
	rnode4_t *rp = VTOR4(vp);

	curtime = gethrestime_sec();

	mutex_enter(&rp->r_statelock);
	NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
	    "recov_throttle: now: (%d, %ld), last: (%d, %ld)",
	    recovp->rc_action, curtime,
	    rp->r_recov_act, rp->r_last_recov));
	if (recovp->rc_action == rp->r_recov_act &&
	    rp->r_last_recov + recov_err_delay > curtime) {
		time_to_wait = rp->r_last_recov + recov_err_delay - curtime;
		mutex_exit(&rp->r_statelock);
		delay(SEC_TO_TICK(time_to_wait));
		curtime = gethrestime_sec();
		mutex_enter(&rp->r_statelock);
	}

	rp->r_last_recov = curtime;
	rp->r_recov_act = recovp->rc_action;
	mutex_exit(&rp->r_statelock);
}

/*
 * React to NFS4ERR_GRACE by setting the time we'll permit
 * the next call to this filesystem.
 */
void
nfs4_set_grace_wait(mntinfo4_t *mi)
{
	mutex_enter(&mi->mi_lock);
	/* Mark the time for the future */
	mi->mi_grace_wait = gethrestime_sec() + nfs4err_delay_time;
	mutex_exit(&mi->mi_lock);
}

/*
 * React to MFS4ERR_DELAY by setting the time we'll permit
 * the next call to this vnode.
 */
void
nfs4_set_delay_wait(vnode_t *vp)
{
	rnode4_t *rp = VTOR4(vp);

	mutex_enter(&rp->r_statelock);
	/*
	 * Calculate amount we should delay, initial
	 * delay will be short and then we will back off.
	 */
	if (rp->r_delay_interval == 0)
		rp->r_delay_interval = NFS4_INITIAL_DELAY_INTERVAL;
	else
		/* calculate next interval value */
		rp->r_delay_interval =
		    MIN(NFS4_MAX_DELAY_INTERVAL, (rp->r_delay_interval << 1));
	rp->r_delay_wait = gethrestime_sec() + rp->r_delay_interval;
	mutex_exit(&rp->r_statelock);
}

/*
 * The caller is responsible for freeing the returned string.
 */
static char *
nfs4_getsrvnames(mntinfo4_t *mi, size_t *len)
{
	servinfo4_t *svp;
	char *srvnames;
	char *namep;
	size_t length;

	/*
	 * Calculate the length of the string required to hold all
	 * of the server names plus either a comma or a null
	 * character following each individual one.
	 */
	length = 0;
	for (svp = mi->mi_servers; svp != NULL; svp = svp->sv_next) {
		(void) nfs_rw_enter_sig(&svp->sv_lock, RW_READER, 0);
		if (svp->sv_flags & SV4_NOTINUSE) {
			nfs_rw_exit(&svp->sv_lock);
			continue;
		}
		nfs_rw_exit(&svp->sv_lock);
		length += svp->sv_hostnamelen;
	}

	srvnames = kmem_alloc(length, KM_SLEEP);

	namep = srvnames;
	for (svp = mi->mi_servers; svp != NULL; svp = svp->sv_next) {
		(void) nfs_rw_enter_sig(&svp->sv_lock, RW_READER, 0);
		if (svp->sv_flags & SV4_NOTINUSE) {
			nfs_rw_exit(&svp->sv_lock);
			continue;
		}
		nfs_rw_exit(&svp->sv_lock);
		(void) strcpy(namep, svp->sv_hostname);
		namep += svp->sv_hostnamelen - 1;
		*namep++ = ',';
	}
	*--namep = '\0';

	*len = length;

	return (srvnames);
}

static void
save_bseqid_rqst(nfs4_bseqid_entry_t *bsep, recov_info_t *recovp)
{
	nfs4_bseqid_entry_t *destp;

	destp = kmem_alloc(sizeof (nfs4_bseqid_entry_t), KM_SLEEP);
	recovp->rc_bseqid_rqst = destp;

	if (bsep->bs_oop)
		open_owner_hold(bsep->bs_oop);
	destp->bs_oop = bsep->bs_oop;
	if (bsep->bs_lop)
		lock_owner_hold(bsep->bs_lop);
	destp->bs_lop = bsep->bs_lop;
	if (bsep->bs_vp)
		VN_HOLD(bsep->bs_vp);
	destp->bs_vp = bsep->bs_vp;
	destp->bs_pid = bsep->bs_pid;
	destp->bs_tag = bsep->bs_tag;
	destp->bs_seqid = bsep->bs_seqid;
}

static void
free_bseqid_rqst(nfs4_bseqid_entry_t *bsep)
{
	if (bsep->bs_oop)
		open_owner_rele(bsep->bs_oop);
	if (bsep->bs_lop)
		lock_owner_rele(bsep->bs_lop);
	if (bsep->bs_vp)
		VN_RELE(bsep->bs_vp);
	kmem_free(bsep, sizeof (nfs4_bseqid_entry_t));
}

/*
 * We don't actually fully recover from NFS4ERR_BAD_SEQID.  We
 * simply mark the open owner and open stream (if provided) as "bad".
 * Then future uses of these data structures will be limited to basically
 * just cleaning up the internal client state (no going OTW).
 *
 * The result of this is to return errors back to the app/usr when
 * we receive NFS4ERR_BAD_SEQID, but also allow future/new calls to
 * succeed so progress can be made.
 */
void
recov_bad_seqid(recov_info_t *recovp)
{
	mntinfo4_t		*mi = recovp->rc_mi;
	nfs4_open_owner_t	*bad_oop;
	nfs4_lock_owner_t	*bad_lop;
	vnode_t			*vp;
	rnode4_t		*rp = NULL;
	pid_t			pid;
	nfs4_bseqid_entry_t	*bsep, *tbsep;
	int			error;

	ASSERT(mi != NULL);
	ASSERT(nfs_rw_lock_held(&mi->mi_recovlock, RW_WRITER));

	mutex_enter(&mi->mi_lock);
	bsep = list_head(&mi->mi_bseqid_list);
	mutex_exit(&mi->mi_lock);

	/*
	 * Handle all the bad seqid entries on mi's list.
	 */
	while (bsep != NULL) {
		bad_oop = bsep->bs_oop;
		bad_lop = bsep->bs_lop;
		vp = bsep->bs_vp;
		pid = bsep->bs_pid;

		NFS4_DEBUG(nfs4_client_recov_debug, (CE_NOTE,
		    "recov_bad_seqid: mark oop %p lop %p as bad for "
		    "vp %p tag %s pid %d: last good seqid %d for tag %s",
		    (void *)bad_oop, (void *)bad_lop, (void *)vp,
		    nfs4_ctags[bsep->bs_tag].ct_str, pid,
		    bad_oop ?  bad_oop->oo_last_good_seqid : 0,
		    bad_oop ? nfs4_ctags[bad_oop->oo_last_good_op].ct_str :
		    nfs4_ctags[TAG_NONE].ct_str));

		nfs4_queue_event(RE_BAD_SEQID, mi, NULL,
		    0, vp, NULL, NFS4ERR_BAD_SEQID, NULL, pid, bsep->bs_tag,
		    bad_oop ? bad_oop->oo_last_good_op : TAG_NONE,
		    bsep->bs_seqid, bad_oop ? bad_oop->oo_last_good_seqid : 0);

		if (bad_oop) {
			/* essentially reset the open owner */
			error = nfs4_start_open_seqid_sync(bad_oop, mi);
			ASSERT(!error);	/* recov thread always succeeds */
			bad_oop->oo_name = nfs4_get_new_oo_name();
			bad_oop->oo_seqid = 0;
			nfs4_end_open_seqid_sync(bad_oop);
		}

		if (bad_lop) {
			mutex_enter(&bad_lop->lo_lock);
			bad_lop->lo_flags |= NFS4_BAD_SEQID_LOCK;
			mutex_exit(&bad_lop->lo_lock);

			ASSERT(vp != NULL);
			rp = VTOR4(vp);
			mutex_enter(&rp->r_statelock);
			rp->r_flags |= R4LODANGLERS;
			mutex_exit(&rp->r_statelock);

			nfs4_send_siglost(pid, mi, vp, TRUE,
			    0, NFS4ERR_BAD_SEQID);
		}

		mutex_enter(&mi->mi_lock);
		list_remove(&mi->mi_bseqid_list, bsep);
		tbsep = bsep;
		bsep = list_head(&mi->mi_bseqid_list);
		mutex_exit(&mi->mi_lock);
		free_bseqid_rqst(tbsep);
	}

	mutex_enter(&mi->mi_lock);
	mi->mi_recovflags &= ~MI4R_BAD_SEQID;
	mutex_exit(&mi->mi_lock);
}
