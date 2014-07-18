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
 * Copyright (c) 2012 by Delphix. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2014 Joyent, Inc.  All rights reserved.
 */

/*
 * NFS Lock Manager service functions (nlm_do_...)
 * Called from nlm_rpc_svc.c wrappers.
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
#include <sys/taskq.h>
#include <sys/unistd.h>
#include <sys/vnode.h>
#include <sys/vfs.h>
#include <sys/queue.h>
#include <sys/sdt.h>
#include <netinet/in.h>

#include <rpc/rpc.h>
#include <rpc/xdr.h>
#include <rpc/pmap_prot.h>
#include <rpc/pmap_clnt.h>
#include <rpc/rpcb_prot.h>

#include <rpcsvc/nlm_prot.h>
#include <rpcsvc/sm_inter.h>

#include <nfs/nfs.h>
#include <nfs/nfs_clnt.h>
#include <nfs/export.h>
#include <nfs/rnode.h>

#include "nlm_impl.h"

#define	NLM_IN_GRACE(g) (ddi_get_lbolt() < (g)->grace_threshold)

struct nlm_block_cb_data {
	struct nlm_host		*hostp;
	struct nlm_vhold	*nvp;
	struct flock64		*flp;
};

/*
 * Invoke an asyncronous RPC callbeck
 * (used when NLM server needs to reply to MSG NLM procedure).
 */
#define	NLM_INVOKE_CALLBACK(descr, rpcp, resp, callb)			\
	do {								\
		enum clnt_stat _stat;					\
									\
		_stat = (*(callb))(resp, NULL, (rpcp)->nr_handle);	\
		if (_stat != RPC_SUCCESS && _stat != RPC_TIMEDOUT) {	\
			struct rpc_err _err;				\
									\
			CLNT_GETERR((rpcp)->nr_handle, &_err);		\
			NLM_ERR("NLM: %s callback failed: "		\
			    "stat %d, err %d\n", descr, _stat,		\
			    _err.re_errno);				\
		}							\
									\
	_NOTE(CONSTCOND) } while (0)

static void nlm_block(
	nlm4_lockargs *lockargs,
	struct nlm_host *host,
	struct nlm_vhold *nvp,
	nlm_rpc_t *rpcp,
	struct flock64 *fl,
	nlm_testargs_cb grant_cb);

static vnode_t *nlm_fh_to_vp(struct netobj *);
static struct nlm_vhold *nlm_fh_to_vhold(struct nlm_host *, struct netobj *);
static void nlm_init_shrlock(struct shrlock *, nlm4_share *, struct nlm_host *);
static callb_cpr_t *nlm_block_callback(flk_cb_when_t, void *);
static int nlm_vop_frlock(vnode_t *, int, flock64_t *, int, offset_t,
    struct flk_callback *, cred_t *, caller_context_t *);

/*
 * Convert a lock from network to local form, and
 * check for valid range (no overflow).
 */
static int
nlm_init_flock(struct flock64 *fl, struct nlm4_lock *nl,
	struct nlm_host *host, rpcvers_t vers, short type)
{
	uint64_t off, len;

	bzero(fl, sizeof (*fl));
	off = nl->l_offset;
	len = nl->l_len;

	if (vers < NLM4_VERS) {
		if (off > MAX_UOFF32 || len > MAX_UOFF32)
			return (EINVAL);
		if (off + len > MAX_UOFF32 + 1)
			return (EINVAL);
	} else {
		/*
		 * Check range for 64-bit client (no overflow).
		 * Again allow len == ~0 to mean lock to EOF.
		 */
		if (len == MAX_U_OFFSET_T)
			len = 0;
		if (len != 0 && off + (len - 1) < off)
			return (EINVAL);
	}

	fl->l_type = type;
	fl->l_whence = SEEK_SET;
	fl->l_start = off;
	fl->l_len = len;
	fl->l_sysid = host->nh_sysid;
	fl->l_pid = nl->svid;
	/* l_pad */

	return (0);
}

/*
 * Convert an fhandle into a vnode.
 * Uses the file id (fh_len + fh_data) in the fhandle to get the vnode.
 * WARNING: users of this routine must do a VN_RELE on the vnode when they
 * are done with it.
 * This is just like nfs_fhtovp() but without the exportinfo argument.
 */
static vnode_t *
lm_fhtovp(fhandle3_t *fh)
{
	vfs_t *vfsp;
	vnode_t *vp;
	int error;

	vfsp = getvfs(&fh->_fh3_fsid);
	if (vfsp == NULL)
		return (NULL);

	/* LINTED E_BAD_PTR_CAST_ALIGN */
	error = VFS_VGET(vfsp, &vp, (fid_t *)&(fh->_fh3_len));
	VFS_RELE(vfsp);
	if (error || vp == NULL)
		return (NULL);

	return (vp);
}

/*
 * Gets vnode from client's filehandle
 * NOTE: Holds vnode, it _must_ be explicitly
 * released by VN_RELE().
 */
static vnode_t *
nlm_fh_to_vp(struct netobj *fh)
{
	fhandle3_t *fhp;

	/*
	 * Get a vnode pointer for the given NFS file handle.
	 * Note that it could be an NFSv2 or NFSv3 handle,
	 * which means the size might vary.  (don't copy)
	 */
	if (fh->n_len < sizeof (fhandle_t))
		return (NULL);

	/* We know this is aligned (kmem_alloc) */
	/* LINTED E_BAD_PTR_CAST_ALIGN */
	fhp = (fhandle3_t *)fh->n_bytes;

	/*
	 * See the comment for NFS_FH3MAXDATA in uts/common/nfs/nfs.h for
	 * converting fhandles. Check the NFSv3 file handle size. The lockmgr
	 * is not used for NFS v4.
	 */
	if (fhp->_fh3_len > NFS_FH3MAXDATA || fhp->_fh3_len == 0)
		return (NULL);

	return (lm_fhtovp(fhp));
}

/*
 * Get vhold from client's filehandle, but in contrast to
 * The function tries to check some access rights as well.
 *
 * NOTE: vhold object _must_ be explicitly released by
 * nlm_vhold_release().
 */
static struct nlm_vhold *
nlm_fh_to_vhold(struct nlm_host *hostp, struct netobj *fh)
{
	vnode_t *vp;
	struct nlm_vhold *nvp;

	vp = nlm_fh_to_vp(fh);
	if (vp == NULL)
		return (NULL);


	nvp = nlm_vhold_get(hostp, vp);

	/*
	 * Both nlm_fh_to_vp() and nlm_vhold_get()
	 * do VN_HOLD(), so we need to drop one
	 * reference on vnode.
	 */
	VN_RELE(vp);
	return (nvp);
}

/* ******************************************************************* */

/*
 * NLM implementation details, called from the RPC svc code.
 */

/*
 * Call-back from NFS statd, used to notify that one of our
 * hosts had a status change. The host can be either an
 * NFS client, NFS server or both.
 * According to NSM protocol description, the state is a
 * number that is increases monotonically each time the
 * state of host changes. An even number indicates that
 * the host is down, while an odd number indicates that
 * the host is up.
 *
 * Here we ignore this even/odd difference of status number
 * reported by the NSM, we launch notification handlers
 * every time the state is changed. The reason we why do so
 * is that client and server can talk to each other using
 * connectionless transport and it's easy to lose packet
 * containing NSM notification with status number update.
 *
 * In nlm_host_monitor(), we put the sysid in the private data
 * that statd carries in this callback, so we can easliy find
 * the host this call applies to.
 */
/* ARGSUSED */
void
nlm_do_notify1(nlm_sm_status *argp, void *res, struct svc_req *sr)
{
	struct nlm_globals *g;
	struct nlm_host *host;
	uint16_t sysid;

	g = zone_getspecific(nlm_zone_key, curzone);
	bcopy(&argp->priv, &sysid, sizeof (sysid));

	DTRACE_PROBE2(nsm__notify, uint16_t, sysid,
	    int, argp->state);

	host = nlm_host_find_by_sysid(g, (sysid_t)sysid);
	if (host == NULL)
		return;

	nlm_host_notify_server(host, argp->state);
	nlm_host_notify_client(host, argp->state);
	nlm_host_release(g, host);
}

/*
 * Another available call-back for NFS statd.
 * Not currently used.
 */
/* ARGSUSED */
void
nlm_do_notify2(nlm_sm_status *argp, void *res, struct svc_req *sr)
{
	ASSERT(0);
}


/*
 * NLM_TEST, NLM_TEST_MSG,
 * NLM4_TEST, NLM4_TEST_MSG,
 * Client inquiry about locks, non-blocking.
 */
void
nlm_do_test(nlm4_testargs *argp, nlm4_testres *resp,
    struct svc_req *sr, nlm_testres_cb cb)
{
	struct nlm_globals *g;
	struct nlm_host *host;
	struct nlm4_holder *lh;
	struct nlm_owner_handle *oh;
	nlm_rpc_t *rpcp = NULL;
	vnode_t *vp = NULL;
	struct netbuf *addr;
	char *netid;
	char *name;
	int error;
	struct flock64 fl;

	nlm_copy_netobj(&resp->cookie, &argp->cookie);

	name = argp->alock.caller_name;
	netid = svc_getnetid(sr->rq_xprt);
	addr = svc_getrpccaller(sr->rq_xprt);

	g = zone_getspecific(nlm_zone_key, curzone);
	host = nlm_host_findcreate(g, name, netid, addr);
	if (host == NULL) {
		resp->stat.stat = nlm4_denied_nolocks;
		return;
	}
	if (cb != NULL) {
		error = nlm_host_get_rpc(host, sr->rq_vers, &rpcp);
		if (error != 0) {
			resp->stat.stat = nlm4_denied_nolocks;
			goto out;
		}
	}

	vp = nlm_fh_to_vp(&argp->alock.fh);
	if (vp == NULL) {
		resp->stat.stat = nlm4_stale_fh;
		goto out;
	}

	if (NLM_IN_GRACE(g)) {
		resp->stat.stat = nlm4_denied_grace_period;
		goto out;
	}

	/* Convert to local form. */
	error = nlm_init_flock(&fl, &argp->alock, host, sr->rq_vers,
	    (argp->exclusive) ? F_WRLCK : F_RDLCK);
	if (error) {
		resp->stat.stat = nlm4_failed;
		goto out;
	}

	/* BSD: VOP_ADVLOCK(nv->nv_vp, NULL, F_GETLK, &fl, F_REMOTE); */
	error = nlm_vop_frlock(vp, F_GETLK, &fl,
	    F_REMOTELOCK | FREAD | FWRITE,
	    (u_offset_t)0, NULL, CRED(), NULL);
	if (error) {
		resp->stat.stat = nlm4_failed;
		goto out;
	}

	if (fl.l_type == F_UNLCK) {
		resp->stat.stat = nlm4_granted;
		goto out;
	}
	resp->stat.stat = nlm4_denied;

	/*
	 * This lock "test" fails due to a conflicting lock.
	 *
	 * If this is a v1 client, make sure the conflicting
	 * lock range we report can be expressed with 32-bit
	 * offsets.  The lock range requested was expressed
	 * as 32-bit offset and length, so at least part of
	 * the conflicting lock should lie below MAX_UOFF32.
	 * If the conflicting lock extends past that, we'll
	 * trim the range to end at MAX_UOFF32 so this lock
	 * can be represented in a 32-bit response.  Check
	 * the start also (paranoid, but a low cost check).
	 */
	if (sr->rq_vers < NLM4_VERS) {
		uint64 maxlen;
		if (fl.l_start > MAX_UOFF32)
			fl.l_start = MAX_UOFF32;
		maxlen = MAX_UOFF32 + 1 - fl.l_start;
		if (fl.l_len > maxlen)
			fl.l_len = maxlen;
	}

	/*
	 * Build the nlm4_holder result structure.
	 *
	 * Note that lh->oh is freed via xdr_free,
	 * xdr_nlm4_holder, xdr_netobj, xdr_bytes.
	 */
	oh = kmem_zalloc(sizeof (*oh), KM_SLEEP);
	oh->oh_sysid = (sysid_t)fl.l_sysid;
	lh = &resp->stat.nlm4_testrply_u.holder;
	lh->exclusive = (fl.l_type == F_WRLCK);
	lh->svid = fl.l_pid;
	lh->oh.n_len = sizeof (*oh);
	lh->oh.n_bytes = (void *)oh;
	lh->l_offset = fl.l_start;
	lh->l_len = fl.l_len;

out:
	/*
	 * If we have a callback function, use that to
	 * deliver the response via another RPC call.
	 */
	if (cb != NULL && rpcp != NULL)
		NLM_INVOKE_CALLBACK("test", rpcp, resp, cb);

	if (vp != NULL)
		VN_RELE(vp);
	if (rpcp != NULL)
		nlm_host_rele_rpc(host, rpcp);

	nlm_host_release(g, host);
}

/*
 * NLM_LOCK, NLM_LOCK_MSG, NLM_NM_LOCK
 * NLM4_LOCK, NLM4_LOCK_MSG, NLM4_NM_LOCK
 *
 * Client request to set a lock, possibly blocking.
 *
 * If the lock needs to block, we return status blocked to
 * this RPC call, and then later call back the client with
 * a "granted" callback.  Tricky aspects of this include:
 * sending a reply before this function returns, and then
 * borrowing this thread from the RPC service pool for the
 * wait on the lock and doing the later granted callback.
 *
 * We also have to keep a list of locks (pending + granted)
 * both to handle retransmitted requests, and to keep the
 * vnodes for those locks active.
 */
void
nlm_do_lock(nlm4_lockargs *argp, nlm4_res *resp, struct svc_req *sr,
    nlm_reply_cb reply_cb, nlm_res_cb res_cb, nlm_testargs_cb grant_cb)
{
	struct nlm_globals *g;
	struct flock64 fl;
	struct nlm_host *host = NULL;
	struct netbuf *addr;
	struct nlm_vhold *nvp = NULL;
	nlm_rpc_t *rpcp = NULL;
	char *netid;
	char *name;
	int error, flags;
	bool_t do_blocking = FALSE;
	bool_t do_mon_req = FALSE;
	enum nlm4_stats status;

	nlm_copy_netobj(&resp->cookie, &argp->cookie);

	name = argp->alock.caller_name;
	netid = svc_getnetid(sr->rq_xprt);
	addr = svc_getrpccaller(sr->rq_xprt);

	g = zone_getspecific(nlm_zone_key, curzone);
	host = nlm_host_findcreate(g, name, netid, addr);
	if (host == NULL) {
		DTRACE_PROBE4(no__host, struct nlm_globals *, g,
		    char *, name, char *, netid, struct netbuf *, addr);
		status = nlm4_denied_nolocks;
		goto doreply;
	}

	DTRACE_PROBE3(start, struct nlm_globals *, g,
	    struct nlm_host *, host, nlm4_lockargs *, argp);

	/*
	 * If we may need to do _msg_ call needing an RPC
	 * callback, get the RPC client handle now,
	 * so we know if we can bind to the NLM service on
	 * this client.
	 *
	 * Note: host object carries transport type.
	 * One client using multiple transports gets
	 * separate sysids for each of its transports.
	 */
	if (res_cb != NULL || (grant_cb != NULL && argp->block == TRUE)) {
		error = nlm_host_get_rpc(host, sr->rq_vers, &rpcp);
		if (error != 0) {
			status = nlm4_denied_nolocks;
			goto doreply;
		}
	}

	/*
	 * During the "grace period", only allow reclaim.
	 */
	if (argp->reclaim == 0 && NLM_IN_GRACE(g)) {
		status = nlm4_denied_grace_period;
		goto doreply;
	}

	/*
	 * Check whether we missed host shutdown event
	 */
	if (nlm_host_get_state(host) != argp->state)
		nlm_host_notify_server(host, argp->state);

	/*
	 * Get a hold on the vnode for a lock operation.
	 * Only lock() and share() need vhold objects.
	 */
	nvp = nlm_fh_to_vhold(host, &argp->alock.fh);
	if (nvp == NULL) {
		status = nlm4_stale_fh;
		goto doreply;
	}

	/* Convert to local form. */
	error = nlm_init_flock(&fl, &argp->alock, host, sr->rq_vers,
	    (argp->exclusive) ? F_WRLCK : F_RDLCK);
	if (error) {
		status = nlm4_failed;
		goto doreply;
	}

	/*
	 * Try to lock non-blocking first.  If we succeed
	 * getting the lock, we can reply with the granted
	 * status directly and avoid the complications of
	 * making the "granted" RPC callback later.
	 *
	 * This also let's us find out now about some
	 * possible errors like EROFS, etc.
	 */
	flags = F_REMOTELOCK | FREAD | FWRITE;
	error = nlm_vop_frlock(nvp->nv_vp, F_SETLK, &fl, flags,
	    (u_offset_t)0, NULL, CRED(), NULL);

	DTRACE_PROBE3(setlk__res, struct flock64 *, &fl,
	    int, flags, int, error);

	switch (error) {
	case 0:
		/* Got it without waiting! */
		status = nlm4_granted;
		do_mon_req = TRUE;
		break;

	/* EINPROGRESS too? */
	case EAGAIN:
		/* We did not get the lock. Should we block? */
		if (argp->block == FALSE || grant_cb == NULL) {
			status = nlm4_denied;
			break;
		}
		/*
		 * Should block.  Try to reserve this thread
		 * so we can use it to wait for the lock and
		 * later send the granted message.  If this
		 * reservation fails, say "no resources".
		 */
		if (!svc_reserve_thread(sr->rq_xprt)) {
			status = nlm4_denied_nolocks;
			break;
		}
		/*
		 * OK, can detach this thread, so this call
		 * will block below (after we reply).
		 */
		status = nlm4_blocked;
		do_blocking = TRUE;
		do_mon_req = TRUE;
		break;

	case ENOLCK:
		/* Failed for lack of resources. */
		status = nlm4_denied_nolocks;
		break;

	case EROFS:
		/* read-only file system */
		status = nlm4_rofs;
		break;

	case EFBIG:
		/* file too big */
		status = nlm4_fbig;
		break;

	case EDEADLK:
		/* dead lock condition */
		status = nlm4_deadlck;
		break;

	default:
		status = nlm4_denied;
		break;
	}

doreply:
	resp->stat.stat = status;

	/*
	 * We get one of two function pointers; one for a
	 * normal RPC reply, and another for doing an RPC
	 * "callback" _res reply for a _msg function.
	 * Use either of those to send the reply now.
	 *
	 * If sending this reply fails, just leave the
	 * lock in the list for retransmitted requests.
	 * Cleanup is via unlock or host rele (statmon).
	 */
	if (reply_cb != NULL) {
		/* i.e. nlm_lock_1_reply */
		if (!(*reply_cb)(sr->rq_xprt, resp))
			svcerr_systemerr(sr->rq_xprt);
	}
	if (res_cb != NULL && rpcp != NULL)
		NLM_INVOKE_CALLBACK("lock", rpcp, resp, res_cb);

	/*
	 * The reply has been sent to the client.
	 * Start monitoring this client (maybe).
	 *
	 * Note that the non-monitored (NM) calls pass grant_cb=NULL
	 * indicating that the client doesn't support RPC callbacks.
	 * No monitoring for these (lame) clients.
	 */
	if (do_mon_req && grant_cb != NULL)
		nlm_host_monitor(g, host, argp->state);

	if (do_blocking) {
		/*
		 * We need to block on this lock, and when that
		 * completes, do the granted RPC call. Note that
		 * we "reserved" this thread above, so we can now
		 * "detach" it from the RPC SVC pool, allowing it
		 * to block indefinitely if needed.
		 */
		ASSERT(rpcp != NULL);
		(void) svc_detach_thread(sr->rq_xprt);
		nlm_block(argp, host, nvp, rpcp, &fl, grant_cb);
	}

	DTRACE_PROBE3(lock__end, struct nlm_globals *, g,
	    struct nlm_host *, host, nlm4_res *, resp);

	if (rpcp != NULL)
		nlm_host_rele_rpc(host, rpcp);

	nlm_vhold_release(host, nvp);
	nlm_host_release(g, host);
}

/*
 * Helper for nlm_do_lock(), partly for observability,
 * (we'll see a call blocked in this function) and
 * because nlm_do_lock() was getting quite long.
 */
static void
nlm_block(nlm4_lockargs *lockargs,
    struct nlm_host *host,
    struct nlm_vhold *nvp,
    nlm_rpc_t *rpcp,
    struct flock64 *flp,
    nlm_testargs_cb grant_cb)
{
	nlm4_testargs args;
	int error;
	flk_callback_t flk_cb;
	struct nlm_block_cb_data cb_data;

	/*
	 * Keep a list of blocked locks on nh_pending, and use it
	 * to cancel these threads in nlm_destroy_client_pending.
	 *
	 * Check to see if this lock is already in the list
	 * and if not, add an entry for it.  Allocate first,
	 * then if we don't insert, free the new one.
	 * Caller already has vp held.
	 */

	error = nlm_slreq_register(host, nvp, flp);
	if (error != 0) {
		/*
		 * Sleeping lock request with given fl is already
		 * registered by someone else. This means that
		 * some other thread is handling the request, let
		 * him to do its work.
		 */
		ASSERT(error == EEXIST);
		return;
	}

	cb_data.hostp = host;
	cb_data.nvp = nvp;
	cb_data.flp = flp;
	flk_init_callback(&flk_cb, nlm_block_callback, &cb_data);

	/* BSD: VOP_ADVLOCK(vp, NULL, F_SETLK, fl, F_REMOTE); */
	error = nlm_vop_frlock(nvp->nv_vp, F_SETLKW, flp,
	    F_REMOTELOCK | FREAD | FWRITE,
	    (u_offset_t)0, &flk_cb, CRED(), NULL);

	if (error != 0) {
		/*
		 * We failed getting the lock, but have no way to
		 * tell the client about that.  Let 'em time out.
		 */
		(void) nlm_slreq_unregister(host, nvp, flp);
		return;
	}

	/*
	 * Do the "granted" call-back to the client.
	 */
	args.cookie	= lockargs->cookie;
	args.exclusive	= lockargs->exclusive;
	args.alock	= lockargs->alock;

	NLM_INVOKE_CALLBACK("grant", rpcp, &args, grant_cb);
}

/*
 * The function that is used as flk callback when NLM server
 * sets new sleeping lock. The function unregisters NLM
 * sleeping lock request (nlm_slreq) associated with the
 * sleeping lock _before_ lock becomes active. It prevents
 * potential race condition between nlm_block() and
 * nlm_do_cancel().
 */
static callb_cpr_t *
nlm_block_callback(flk_cb_when_t when, void *data)
{
	struct nlm_block_cb_data *cb_data;

	cb_data = (struct nlm_block_cb_data *)data;
	if (when == FLK_AFTER_SLEEP) {
		(void) nlm_slreq_unregister(cb_data->hostp,
		    cb_data->nvp, cb_data->flp);
	}

	return (0);
}

/*
 * NLM_CANCEL, NLM_CANCEL_MSG,
 * NLM4_CANCEL, NLM4_CANCEL_MSG,
 * Client gives up waiting for a blocking lock.
 */
void
nlm_do_cancel(nlm4_cancargs *argp, nlm4_res *resp,
    struct svc_req *sr, nlm_res_cb cb)
{
	struct nlm_globals *g;
	struct nlm_host *host;
	struct netbuf *addr;
	struct nlm_vhold *nvp = NULL;
	nlm_rpc_t *rpcp = NULL;
	char *netid;
	char *name;
	int error;
	struct flock64 fl;

	nlm_copy_netobj(&resp->cookie, &argp->cookie);
	netid = svc_getnetid(sr->rq_xprt);
	addr = svc_getrpccaller(sr->rq_xprt);
	name = argp->alock.caller_name;

	g = zone_getspecific(nlm_zone_key, curzone);
	host = nlm_host_findcreate(g, name, netid, addr);
	if (host == NULL) {
		resp->stat.stat = nlm4_denied_nolocks;
		return;
	}
	if (cb != NULL) {
		error = nlm_host_get_rpc(host, sr->rq_vers, &rpcp);
		if (error != 0) {
			resp->stat.stat = nlm4_denied_nolocks;
			return;
		}
	}

	DTRACE_PROBE3(start, struct nlm_globals *, g,
	    struct nlm_host *, host, nlm4_cancargs *, argp);

	if (NLM_IN_GRACE(g)) {
		resp->stat.stat = nlm4_denied_grace_period;
		goto out;
	}

	nvp = nlm_fh_to_vhold(host, &argp->alock.fh);
	if (nvp == NULL) {
		resp->stat.stat = nlm4_stale_fh;
		goto out;
	}

	/* Convert to local form. */
	error = nlm_init_flock(&fl, &argp->alock, host, sr->rq_vers,
	    (argp->exclusive) ? F_WRLCK : F_RDLCK);
	if (error) {
		resp->stat.stat = nlm4_failed;
		goto out;
	}

	error = nlm_slreq_unregister(host, nvp, &fl);
	if (error != 0) {
		/*
		 * There's no sleeping lock request corresponding
		 * to the lock. Then requested sleeping lock
		 * doesn't exist.
		 */
		resp->stat.stat = nlm4_denied;
		goto out;
	}

	fl.l_type = F_UNLCK;
	error = nlm_vop_frlock(nvp->nv_vp, F_SETLK, &fl,
	    F_REMOTELOCK | FREAD | FWRITE,
	    (u_offset_t)0, NULL, CRED(), NULL);

	resp->stat.stat = (error == 0) ?
	    nlm4_granted : nlm4_denied;

out:
	/*
	 * If we have a callback function, use that to
	 * deliver the response via another RPC call.
	 */
	if (cb != NULL && rpcp != NULL)
		NLM_INVOKE_CALLBACK("cancel", rpcp, resp, cb);

	DTRACE_PROBE3(cancel__end, struct nlm_globals *, g,
	    struct nlm_host *, host, nlm4_res *, resp);

	if (rpcp != NULL)
		nlm_host_rele_rpc(host, rpcp);

	nlm_vhold_release(host, nvp);
	nlm_host_release(g, host);
}

/*
 * NLM_UNLOCK, NLM_UNLOCK_MSG,
 * NLM4_UNLOCK, NLM4_UNLOCK_MSG,
 * Client removes one of their locks.
 */
void
nlm_do_unlock(nlm4_unlockargs *argp, nlm4_res *resp,
    struct svc_req *sr, nlm_res_cb cb)
{
	struct nlm_globals *g;
	struct nlm_host *host;
	struct netbuf *addr;
	nlm_rpc_t *rpcp = NULL;
	vnode_t *vp = NULL;
	char *netid;
	char *name;
	int error;
	struct flock64 fl;

	nlm_copy_netobj(&resp->cookie, &argp->cookie);

	netid = svc_getnetid(sr->rq_xprt);
	addr = svc_getrpccaller(sr->rq_xprt);
	name = argp->alock.caller_name;

	/*
	 * NLM_UNLOCK operation doesn't have an error code
	 * denoting that operation failed, so we always
	 * return nlm4_granted except when the server is
	 * in a grace period.
	 */
	resp->stat.stat = nlm4_granted;

	g = zone_getspecific(nlm_zone_key, curzone);
	host = nlm_host_findcreate(g, name, netid, addr);
	if (host == NULL)
		return;

	if (cb != NULL) {
		error = nlm_host_get_rpc(host, sr->rq_vers, &rpcp);
		if (error != 0)
			goto out;
	}

	DTRACE_PROBE3(start, struct nlm_globals *, g,
	    struct nlm_host *, host, nlm4_unlockargs *, argp);

	if (NLM_IN_GRACE(g)) {
		resp->stat.stat = nlm4_denied_grace_period;
		goto out;
	}

	vp = nlm_fh_to_vp(&argp->alock.fh);
	if (vp == NULL)
		goto out;

	/* Convert to local form. */
	error = nlm_init_flock(&fl, &argp->alock, host, sr->rq_vers, F_UNLCK);
	if (error)
		goto out;

	/* BSD: VOP_ADVLOCK(nv->nv_vp, NULL, F_UNLCK, &fl, F_REMOTE); */
	error = nlm_vop_frlock(vp, F_SETLK, &fl,
	    F_REMOTELOCK | FREAD | FWRITE,
	    (u_offset_t)0, NULL, CRED(), NULL);

	DTRACE_PROBE1(unlock__res, int, error);
out:
	/*
	 * If we have a callback function, use that to
	 * deliver the response via another RPC call.
	 */
	if (cb != NULL && rpcp != NULL)
		NLM_INVOKE_CALLBACK("unlock", rpcp, resp, cb);

	DTRACE_PROBE3(unlock__end, struct nlm_globals *, g,
	    struct nlm_host *, host, nlm4_res *, resp);

	if (vp != NULL)
		VN_RELE(vp);
	if (rpcp != NULL)
		nlm_host_rele_rpc(host, rpcp);

	nlm_host_release(g, host);
}

/*
 * NLM_GRANTED, NLM_GRANTED_MSG,
 * NLM4_GRANTED, NLM4_GRANTED_MSG,
 *
 * This service routine is special.  It's the only one that's
 * really part of our NLM _client_ support, used by _servers_
 * to "call back" when a blocking lock from this NLM client
 * is granted by the server.  In this case, we _know_ there is
 * already an nlm_host allocated and held by the client code.
 * We want to find that nlm_host here.
 *
 * Over in nlm_call_lock(), the client encoded the sysid for this
 * server in the "owner handle" netbuf sent with our lock request.
 * We can now use that to find the nlm_host object we used there.
 * (NB: The owner handle is opaque to the server.)
 */
void
nlm_do_granted(nlm4_testargs *argp, nlm4_res *resp,
    struct svc_req *sr, nlm_res_cb cb)
{
	struct nlm_globals *g;
	struct nlm_owner_handle *oh;
	struct nlm_host *host;
	nlm_rpc_t *rpcp = NULL;
	int error;

	nlm_copy_netobj(&resp->cookie, &argp->cookie);
	resp->stat.stat = nlm4_denied;

	g = zone_getspecific(nlm_zone_key, curzone);
	oh = (void *) argp->alock.oh.n_bytes;
	if (oh == NULL)
		return;

	host = nlm_host_find_by_sysid(g, oh->oh_sysid);
	if (host == NULL)
		return;

	if (cb != NULL) {
		error = nlm_host_get_rpc(host, sr->rq_vers, &rpcp);
		if (error != 0)
			goto out;
	}

	if (NLM_IN_GRACE(g)) {
		resp->stat.stat = nlm4_denied_grace_period;
		goto out;
	}

	error = nlm_slock_grant(g, host, &argp->alock);
	if (error == 0)
		resp->stat.stat = nlm4_granted;

out:
	/*
	 * If we have a callback function, use that to
	 * deliver the response via another RPC call.
	 */
	if (cb != NULL && rpcp != NULL)
		NLM_INVOKE_CALLBACK("do_granted", rpcp, resp, cb);

	if (rpcp != NULL)
		nlm_host_rele_rpc(host, rpcp);

	nlm_host_release(g, host);
}

/*
 * NLM_FREE_ALL, NLM4_FREE_ALL
 *
 * Destroy all lock state for the calling client.
 */
void
nlm_do_free_all(nlm4_notify *argp, void *res, struct svc_req *sr)
{
	struct nlm_globals *g;
	struct nlm_host_list host_list;
	struct nlm_host *hostp;

	TAILQ_INIT(&host_list);
	g = zone_getspecific(nlm_zone_key, curzone);

	/* Serialize calls to clean locks. */
	mutex_enter(&g->clean_lock);

	/*
	 * Find all hosts that have the given node name and put them on a
	 * local list.
	 */
	mutex_enter(&g->lock);
	for (hostp = avl_first(&g->nlm_hosts_tree); hostp != NULL;
	    hostp = AVL_NEXT(&g->nlm_hosts_tree, hostp)) {
		if (strcasecmp(hostp->nh_name, argp->name) == 0) {
			/*
			 * If needed take the host out of the idle list since
			 * we are taking a reference.
			 */
			if (hostp->nh_flags & NLM_NH_INIDLE) {
				TAILQ_REMOVE(&g->nlm_idle_hosts, hostp,
				    nh_link);
				hostp->nh_flags &= ~NLM_NH_INIDLE;
			}
			hostp->nh_refs++;

			TAILQ_INSERT_TAIL(&host_list, hostp, nh_link);
		}
	}
	mutex_exit(&g->lock);

	/* Free locks for all hosts on the local list. */
	while (!TAILQ_EMPTY(&host_list)) {
		hostp = TAILQ_FIRST(&host_list);
		TAILQ_REMOVE(&host_list, hostp, nh_link);

		/*
		 * Note that this does not do client-side cleanup.
		 * We want to do that ONLY if statd tells us the
		 * server has restarted.
		 */
		nlm_host_notify_server(hostp, argp->state);
		nlm_host_release(g, hostp);
	}

	mutex_exit(&g->clean_lock);

	(void) res;
	(void) sr;
}

static void
nlm_init_shrlock(struct shrlock *shr,
    nlm4_share *nshare, struct nlm_host *host)
{

	switch (nshare->access) {
	default:
	case fsa_NONE:
		shr->s_access = 0;
		break;
	case fsa_R:
		shr->s_access = F_RDACC;
		break;
	case fsa_W:
		shr->s_access = F_WRACC;
		break;
	case fsa_RW:
		shr->s_access = F_RWACC;
		break;
	}

	switch (nshare->mode) {
	default:
	case fsm_DN:
		shr->s_deny = F_NODNY;
		break;
	case fsm_DR:
		shr->s_deny = F_RDDNY;
		break;
	case fsm_DW:
		shr->s_deny = F_WRDNY;
		break;
	case fsm_DRW:
		shr->s_deny = F_RWDNY;
		break;
	}

	shr->s_sysid = host->nh_sysid;
	shr->s_pid = 0;
	shr->s_own_len = nshare->oh.n_len;
	shr->s_owner   = nshare->oh.n_bytes;
}

/*
 * NLM_SHARE, NLM4_SHARE
 *
 * Request a DOS-style share reservation
 */
void
nlm_do_share(nlm4_shareargs *argp, nlm4_shareres *resp, struct svc_req *sr)
{
	struct nlm_globals *g;
	struct nlm_host *host;
	struct netbuf *addr;
	struct nlm_vhold *nvp = NULL;
	char *netid;
	char *name;
	int error;
	struct shrlock shr;

	nlm_copy_netobj(&resp->cookie, &argp->cookie);

	name = argp->share.caller_name;
	netid = svc_getnetid(sr->rq_xprt);
	addr = svc_getrpccaller(sr->rq_xprt);

	g = zone_getspecific(nlm_zone_key, curzone);
	host = nlm_host_findcreate(g, name, netid, addr);
	if (host == NULL) {
		resp->stat = nlm4_denied_nolocks;
		return;
	}

	DTRACE_PROBE3(share__start, struct nlm_globals *, g,
	    struct nlm_host *, host, nlm4_shareargs *, argp);

	if (argp->reclaim == 0 && NLM_IN_GRACE(g)) {
		resp->stat = nlm4_denied_grace_period;
		goto out;
	}

	/*
	 * Get holded vnode when on lock operation.
	 * Only lock() and share() need vhold objects.
	 */
	nvp = nlm_fh_to_vhold(host, &argp->share.fh);
	if (nvp == NULL) {
		resp->stat = nlm4_stale_fh;
		goto out;
	}

	/* Convert to local form. */
	nlm_init_shrlock(&shr, &argp->share, host);
	error = VOP_SHRLOCK(nvp->nv_vp, F_SHARE, &shr,
	    FREAD | FWRITE, CRED(), NULL);

	if (error == 0) {
		resp->stat = nlm4_granted;
		nlm_host_monitor(g, host, 0);
	} else {
		resp->stat = nlm4_denied;
	}

out:
	DTRACE_PROBE3(share__end, struct nlm_globals *, g,
	    struct nlm_host *, host, nlm4_shareres *, resp);

	nlm_vhold_release(host, nvp);
	nlm_host_release(g, host);
}

/*
 * NLM_UNSHARE, NLM4_UNSHARE
 *
 * Release a DOS-style share reservation
 */
void
nlm_do_unshare(nlm4_shareargs *argp, nlm4_shareres *resp, struct svc_req *sr)
{
	struct nlm_globals *g;
	struct nlm_host *host;
	struct netbuf *addr;
	vnode_t *vp = NULL;
	char *netid;
	int error;
	struct shrlock shr;

	nlm_copy_netobj(&resp->cookie, &argp->cookie);

	netid = svc_getnetid(sr->rq_xprt);
	addr = svc_getrpccaller(sr->rq_xprt);

	g = zone_getspecific(nlm_zone_key, curzone);
	host = nlm_host_find(g, netid, addr);
	if (host == NULL) {
		resp->stat = nlm4_denied_nolocks;
		return;
	}

	DTRACE_PROBE3(unshare__start, struct nlm_globals *, g,
	    struct nlm_host *, host, nlm4_shareargs *, argp);

	if (NLM_IN_GRACE(g)) {
		resp->stat = nlm4_denied_grace_period;
		goto out;
	}

	vp = nlm_fh_to_vp(&argp->share.fh);
	if (vp == NULL) {
		resp->stat = nlm4_stale_fh;
		goto out;
	}

	/* Convert to local form. */
	nlm_init_shrlock(&shr, &argp->share, host);
	error = VOP_SHRLOCK(vp, F_UNSHARE, &shr,
	    FREAD | FWRITE, CRED(), NULL);

	(void) error;
	resp->stat = nlm4_granted;

out:
	DTRACE_PROBE3(unshare__end, struct nlm_globals *, g,
	    struct nlm_host *, host, nlm4_shareres *, resp);

	if (vp != NULL)
		VN_RELE(vp);

	nlm_host_release(g, host);
}

/*
 * NLM wrapper to VOP_FRLOCK that checks the validity of the lock before
 * invoking the vnode operation.
 */
static int
nlm_vop_frlock(vnode_t *vp, int cmd, flock64_t *bfp, int flag, offset_t offset,
	struct flk_callback *flk_cbp, cred_t *cr, caller_context_t *ct)
{
	if (bfp->l_len != 0 && bfp->l_start + (bfp->l_len - 1) < bfp->l_start) {
		return (EOVERFLOW);
	}

	return (VOP_FRLOCK(vp, cmd, bfp, flag, offset, flk_cbp, cr, ct));
}
