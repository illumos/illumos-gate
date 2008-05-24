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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/vfs.h>
#include <sys/vfs_opreg.h>
#include <sys/vnode.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/stropts.h>
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>

#include <sys/project.h>
#include <sys/tihdr.h>
#include <sys/strsubr.h>

#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/strsun.h>

#include <sys/tsol/label.h>

#include <inet/sdp_itf.h>
#include "socksdp.h"

/*
 * SDP sockfs sonode operations
 */
static int sosdp_accept(struct sonode *, int, struct sonode **);
static int sosdp_listen(struct sonode *, int);
static int sosdp_connect(struct sonode *, const struct sockaddr *, socklen_t,
    int, int);
static int sosdp_sendmsg(struct sonode *, struct nmsghdr *, struct uio *);
static int sosdp_getpeername(struct sonode *);
static int sosdp_getsockname(struct sonode *);
static int sosdp_shutdown(struct sonode *, int);
static int sosdp_getsockopt(struct sonode *, int, int, void *, socklen_t *,
    int);
static int sosdp_setsockopt(struct sonode *, int, int, const void *,
    socklen_t);


/*
 * Socket upcalls
 */
static void *sdp_sock_newconn(void *parenthandle, void *connind);
static void sdp_sock_connected(void *handle);
static void sdp_sock_disconnected(void *handle, int error);
static void sdp_sock_connfail(void *handle, int error);
static int sdp_sock_recv(void *handle, mblk_t *mp, int flags);
static void sdp_sock_xmitted(void *handle, int txqueued);
static void sdp_sock_urgdata(void *handle);
static void sdp_sock_ordrel(void *handle);

static kmem_cache_t *sosdp_sockcache;

sonodeops_t sosdp_sonodeops = {
	sosdp_accept,		/* sop_accept	*/
	sosdp_bind,		/* sop_bind	*/
	sosdp_listen,		/* sop_listen	*/
	sosdp_connect,		/* sop_connect	*/
	sosdp_recvmsg,		/* sop_recvmsg	*/
	sosdp_sendmsg,		/* sop_sendmsg	*/
	sosdp_getpeername,	/* sop_getpeername */
	sosdp_getsockname,	/* sop_getsockname */
	sosdp_shutdown,	/* sop_shutdown */
	sosdp_getsockopt,	/* sop_getsockopt */
	sosdp_setsockopt	/* sop_setsockopt */
};

sdp_upcalls_t sosdp_sock_upcalls = {
	sdp_sock_newconn,
	sdp_sock_connected,
	sdp_sock_disconnected,
	sdp_sock_connfail,
	sdp_sock_recv,
	sdp_sock_xmitted,
	sdp_sock_urgdata,
	sdp_sock_ordrel,
};


/*ARGSUSED*/
static int
sosdp_sock_constructor(void *buf, void *cdrarg, int kmflags)
{
	struct sdp_sonode *ss = buf;
	struct sonode *so = &ss->ss_so;
	struct vnode *vp;

	ss->ss_type		= SOSDP_SOCKET;
	so->so_oobmsg		= NULL;
	so->so_ack_mp		= NULL;
	so->so_conn_ind_head	= NULL;
	so->so_conn_ind_tail	= NULL;
	so->so_discon_ind_mp	= NULL;
	so->so_ux_bound_vp	= NULL;
	so->so_unbind_mp	= NULL;
	so->so_accessvp		= NULL;
	so->so_priv = NULL;

	so->so_nl7c_flags	= 0;
	so->so_nl7c_uri		= NULL;
	so->so_nl7c_rcv_mp	= NULL;

	so->so_direct		= NULL;

	vp = vn_alloc(kmflags);
	if (vp == NULL) {
		return (-1);
	}
	so->so_vnode = vp;

	vn_setops(vp, socksdp_vnodeops);
	vp->v_data = (caddr_t)so;

	mutex_init(&so->so_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&so->so_plumb_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&so->so_state_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&so->so_ack_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&so->so_connind_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&so->so_want_cv, NULL, CV_DEFAULT, NULL);
	return (0);
}

/*ARGSUSED*/
static void
sosdp_sock_destructor(void *buf, void *cdrarg)
{
	struct sdp_sonode *ss = buf;
	struct sonode *so = &ss->ss_so;
	struct vnode *vp = SOTOV(so);

	ASSERT(so->so_direct == NULL);

	ASSERT(so->so_nl7c_flags == 0);
	ASSERT(so->so_nl7c_uri == NULL);
	ASSERT(so->so_nl7c_rcv_mp == NULL);

	ASSERT(so->so_oobmsg == NULL);
	ASSERT(so->so_ack_mp == NULL);
	ASSERT(so->so_conn_ind_head == NULL);
	ASSERT(so->so_conn_ind_tail == NULL);
	ASSERT(so->so_discon_ind_mp == NULL);
	ASSERT(so->so_ux_bound_vp == NULL);
	ASSERT(so->so_unbind_mp == NULL);
	ASSERT(so->so_ops == &sosdp_sonodeops);

	ASSERT(vn_matchops(vp, socksdp_vnodeops));
	ASSERT(vp->v_data == (caddr_t)so);

	vn_free(vp);

	mutex_destroy(&so->so_lock);
	mutex_destroy(&so->so_plumb_lock);
	cv_destroy(&so->so_state_cv);
	cv_destroy(&so->so_ack_cv);
	cv_destroy(&so->so_connind_cv);
	cv_destroy(&so->so_want_cv);
}


int
sosdp_init(void)
{
	int error;

	error = vn_make_ops("socksdp", socksdp_vnodeops_template,
	    &socksdp_vnodeops);
	if (error != 0) {
		cmn_err(CE_WARN, "sosdp_init: bad vnode ops template");
		return (error);
	}

	sosdp_sockcache = kmem_cache_create("sdpsock",
	    sizeof (struct sdp_sonode), 0, sosdp_sock_constructor,
	    sosdp_sock_destructor, NULL, NULL, NULL, 0);
	return (0);
}

static struct vnode *
sosdp_makevp(struct vnode *accessvp, int domain, int type, int protocol,
    int kmflags)
{
	struct sdp_sonode *ss;
	struct sonode *so;
	struct vnode *vp;
	time_t now;

	ss = kmem_cache_alloc(sosdp_sockcache, kmflags);
	if (ss == NULL) {
		return (NULL);
	}
	so = &ss->ss_so;
	so->so_cache = sosdp_sockcache;
	so->so_obj = ss;
	vp = SOTOV(so);
	now = gethrestime_sec();

	so->so_flag	= 0;
	so->so_accessvp = accessvp;
	so->so_dev = accessvp->v_rdev;

	so->so_state	= 0;
	so->so_mode	= 0;

	so->so_fsid	= sockdev;
	so->so_atime	= now;
	so->so_mtime	= now;
	so->so_ctime	= now;
	so->so_count	= 0;

	so->so_family	= domain;
	so->so_type	= type;
	so->so_protocol	= protocol;
	so->so_pushcnt	= 0;

	so->so_options	= 0;
	so->so_linger.l_onoff   = 0;
	so->so_linger.l_linger = 0;
	so->so_sndbuf	= 0;
	so->so_rcvbuf	= 0;
	so->so_error	= 0;
	so->so_delayed_error = 0;

	ASSERT(so->so_oobmsg == NULL);
	so->so_oobcnt	= 0;
	so->so_oobsigcnt = 0;
	so->so_pgrp	= 0;
	so->so_provinfo = NULL;

	so->so_laddr_sa	= (struct sockaddr *)&ss->ss_laddr;
	so->so_faddr_sa	= (struct sockaddr *)&ss->ss_faddr;
	so->so_laddr_maxlen = so->so_faddr_maxlen = sizeof (ss->ss_laddr);
	so->so_laddr_len = so->so_faddr_len = 0;
	so->so_eaddr_mp = NULL;
	so->so_delayed_error = 0;

	so->so_peercred = NULL;

	ASSERT(so->so_ack_mp == NULL);
	ASSERT(so->so_conn_ind_head == NULL);
	ASSERT(so->so_conn_ind_tail == NULL);
	ASSERT(so->so_ux_bound_vp == NULL);
	ASSERT(so->so_unbind_mp == NULL);

	vn_reinit(vp);
	vp->v_vfsp	= rootvfs;
	vp->v_type	= VSOCK;
	vp->v_rdev	= so->so_dev;

	so->so_ops	= &sosdp_sonodeops;

	ss->ss_rxqueued = 0;
	bzero(&ss->ss_poll_list, sizeof (ss->ss_poll_list));

	vn_exists(vp);
	return (vp);
}

/*
 * Creates a sdp socket data structure.
 * tso is non-NULL if it's passive open.
 */
struct sonode *
sosdp_create(vnode_t *accessvp, int domain, int type, int protocol,
    int version, struct sonode *tso, int *errorp)
{
	struct sonode *so;
	vnode_t *vp;
	int error;
	int soflags;
	cred_t *cr;

	dprint(4, ("Inside sosdp_create: domain:%d proto:%d type:%d",
		domain, protocol, type));

	if (is_system_labeled()) {
		*errorp = EOPNOTSUPP;
		return (NULL);
	}

	if (version == SOV_STREAM) {
		*errorp = EINVAL;
		return (NULL);
	}
	ASSERT(accessvp != NULL);

	/*
	 * We only support one type of SDP socket.  Let sotpi_create()
	 * handle all other cases, such as raw socket.
	 */
	if (!(domain == AF_INET || domain == AF_INET6) ||
	    !(type == SOCK_STREAM)) {
		return (sotpi_create(accessvp, domain, type, protocol, version,
		    NULL, errorp));
	}

	if (tso == NULL) {
		vp = sosdp_makevp(accessvp, domain, type, protocol, KM_SLEEP);
		ASSERT(vp != NULL);

		soflags = FREAD | FWRITE;
	} else {
		vp = sosdp_makevp(accessvp, domain, type, protocol,
		    KM_NOSLEEP);
		if (vp == NULL) {
			/*
			 * sosdp_makevp() only fails when there is no memory.
			 */
			*errorp = ENOMEM;
			return (NULL);
		}
		soflags = FREAD | FWRITE | SO_ACCEPTOR;
	}
	/*
	 * This function may be called in interrupt context, and CRED()
	 * will be NULL.  In this case, pass in kcred to VOP_OPEN().
	 */
	if ((cr = CRED()) == NULL)
		cr = kcred;
	if ((error = VOP_OPEN(&vp, soflags, cr, NULL)) != 0) {
		VN_RELE(vp);
		*errorp = error;
		return (NULL);
	}
	so = VTOSO(vp);

	dprint(2, ("sosdp_create: %p domain %d type %d\n", so, domain, type));

	if (version == SOV_DEFAULT) {
		version = so_default_version;
	}
	so->so_version = (short)version;

	return (so);
}

/*
 * Free SDP socket data structure.
 * Closes incoming connections which were never accepted, frees
 * resources.
 */
void
sosdp_free(struct sonode *so)
{
	struct sonode *nso;
	mblk_t *mp;

	dprint(3, ("sosdp_free: so:%p priv:%p", (void *)so, so->so_priv));

	mutex_enter(&so->so_lock);

	/*
	 * Need to clear these out so that sockfree() doesn't think that
	 * there's memory in need of free'ing.
	 */
	so->so_laddr_sa = so->so_faddr_sa = NULL;
	so->so_laddr_len = so->so_laddr_maxlen = 0;
	so->so_faddr_len = so->so_faddr_maxlen = 0;

	while ((mp = so->so_conn_ind_head) != NULL) {
		so->so_conn_ind_head = mp->b_next;
		mutex_exit(&so->so_lock);
		mp->b_next = NULL;
		nso = *(struct sonode **)mp->b_rptr;

		(void) VOP_CLOSE(SOTOV(nso), 0, 1, 0, CRED(), NULL);
		vn_invalid(SOTOV(nso));
		VN_RELE(SOTOV(nso));

		freeb(mp);
		mutex_enter(&so->so_lock);
	}
	so->so_conn_ind_tail = NULL;
	so->so_state &= ~SS_HASCONNIND;
	mutex_exit(&so->so_lock);

	sockfree(so);
}

/*
 * Accept incoming connection.
 */
static int
sosdp_accept(struct sonode *lso, int fflag, struct sonode **nsop)
{
	int error = 0;
	mblk_t *mp;
	struct sonode *nso;

	dprint(3, ("sosdp_accept: so:%p priv:%p", (void *)lso,
	    lso->so_priv));

	if (!(lso->so_state & SS_ACCEPTCONN)) {
		/*
		 * Not a listen socket.
		 */
		eprintsoline(lso, EINVAL);
		return (EINVAL);
	}

	/*
	 * Returns right away if socket is nonblocking.
	 */
	error = sowaitconnind(lso, fflag, &mp);
	if (error != 0) {
		eprintsoline(lso, error);
		dprint(4, ("sosdp_accept: failed <%d>:lso:%p prv:%p",
		    error, (void *)lso, lso->so_priv));
		return (error);
	}
	nso = *(struct sonode **)mp->b_rptr;
	freeb(mp);

	mutex_enter(&lso->so_lock);
	ASSERT(SOTOSDO(lso)->ss_rxqueued > 0);
	--SOTOSDO(lso)->ss_rxqueued;
	mutex_exit(&lso->so_lock);


	/*
	 * accept() needs remote address right away.
	 */
	(void) sosdp_getpeername(nso);

	dprint(2, ("sosdp_accept: new %p\n", nso));

	*nsop = nso;
	return (0);
}

/*
 * Bind local endpoint.
 */
int
sosdp_bind(struct sonode *so, struct sockaddr *name, socklen_t namelen,
    int flags)
{
	int error = 0;

	if (!(flags & _SOBIND_LOCK_HELD)) {
		mutex_enter(&so->so_lock);
		so_lock_single(so);	/* Set SOLOCKED */
		/* LINTED - statement has no conseq */
	} else {
		ASSERT(MUTEX_HELD(&so->so_lock));
		ASSERT(so->so_flag & SOLOCKED);
	}

	if ((so->so_state & SS_ISBOUND) || name == NULL || namelen == 0) {
		/*
		 * Multiple binds not allowed for any SDP socket.
		 * Also binding with null address is not supported.
		 */
		error = EINVAL;
		eprintsoline(so, error);
		goto done;
	}
	/*
	 * X/Open requires this check
	 */
	if (so->so_state & SS_CANTSENDMORE) {
		error = EINVAL;
		goto done;
	}

	/*
	 * Protocol module does address family checks.
	 */
	mutex_exit(&so->so_lock);

	error = sdp_bind(so->so_priv, name, namelen);

	mutex_enter(&so->so_lock);
	if (error == 0) {
		so->so_state |= SS_ISBOUND;
		/* LINTED - statement has no conseq */
	} else {
		eprintsoline(so, error);
	}
done:
	if (!(flags & _SOBIND_LOCK_HELD)) {
		so_unlock_single(so, SOLOCKED);
		mutex_exit(&so->so_lock);
		/* LINTED - statement has no conseq */
	} else {
		/* If the caller held the lock don't release it here */
		ASSERT(MUTEX_HELD(&so->so_lock));
		ASSERT(so->so_flag & SOLOCKED);
	}
	return (error);
}

/*
 * Turn socket into a listen socket.
 */
static int
sosdp_listen(struct sonode *so, int backlog)
{
	int error = 0;


	mutex_enter(&so->so_lock);
	so_lock_single(so);

	/*
	 * If this socket is trying to do connect, or if it has
	 * been connected, disallow.
	 */
	if (so->so_state & (SS_ISCONNECTING | SS_ISCONNECTED |
	    SS_ISDISCONNECTING | SS_CANTRCVMORE | SS_CANTSENDMORE)) {
		error = EINVAL;
		eprintsoline(so, error);
		goto done;
	}

	if (backlog < 0) {
		backlog = 0;
	}

	/*
	 * Use the same qlimit as in BSD. BSD checks the qlimit
	 * before queuing the next connection implying that a
	 * listen(sock, 0) allows one connection to be queued.
	 * BSD also uses 1.5 times the requested backlog.
	 *
	 * XNS Issue 4 required a strict interpretation of the backlog.
	 * This has been waived subsequently for Issue 4 and the change
	 * incorporated in XNS Issue 5. So we aren't required to do
	 * anything special for XPG apps.
	 */
	if (backlog >= (INT_MAX - 1) / 3)
		backlog = INT_MAX;
	else
		backlog = backlog * 3 / 2 + 1;

	/*
	 * If listen() is only called to change backlog, we don't
	 * need to notify protocol module.
	 */
	if (so->so_state & SS_ACCEPTCONN) {
		so->so_backlog = backlog;
		goto done;
	}

	mutex_exit(&so->so_lock);

	error = sdp_listen(so->so_priv, backlog);

	mutex_enter(&so->so_lock);
	if (error == 0) {
		so->so_state |= (SS_ACCEPTCONN|SS_ISBOUND);
		so->so_backlog = backlog;
		/* LINTED - statement has no conseq */
	} else {
		eprintsoline(so, error);
	}
done:
	so_unlock_single(so, SOLOCKED);
	mutex_exit(&so->so_lock);

	return (error);
}

/*
 * Active open.
 */
/*ARGSUSED*/
static int
sosdp_connect(struct sonode *so, const struct sockaddr *name,
    socklen_t namelen, int fflag, int flags)
{
	int error;

	ASSERT(so->so_type == SOCK_STREAM);
	dprint(3, ("sosdp_connect: so:%p priv:%p", (void *)so,
	    so->so_priv));

	mutex_enter(&so->so_lock);
	so_lock_single(so);

	/*
	 * Can't connect() after listen(), or if the socket is already
	 * connected.
	 */
	if (so->so_state & (SS_ACCEPTCONN|SS_ISCONNECTED|SS_ISCONNECTING)) {
		if (so->so_state & SS_ISCONNECTED) {
			error = EISCONN;
		} else if (so->so_state & SS_ISCONNECTING) {
			error = EALREADY;
		} else {
			error = EOPNOTSUPP;
		}
		eprintsoline(so, error);
		goto done;
	}

	/*
	 * Check for failure of an earlier call
	 */
	if (so->so_error != 0) {
		error = sogeterr(so);
		eprintsoline(so, error);
		goto done;
	}

	/*
	 * Connection is closing, or closed, don't allow reconnect.
	 * TCP allows this to proceed, but the socket remains unwriteable.
	 * BSD returns EINVAL.
	 */
	if (so->so_state & (SS_ISDISCONNECTING|SS_CANTRCVMORE|
	    SS_CANTSENDMORE)) {
		error = EINVAL;
		eprintsoline(so, error);
		goto done;
	}
	if (name == NULL || namelen == 0) {
		error = EINVAL;
		eprintsoline(so, error);
		goto done;
	}
	soisconnecting(so);

	mutex_exit(&so->so_lock);

	error = sdp_connect(so->so_priv, name, namelen);
	mutex_enter(&so->so_lock);
	if (error == 0) {
		/*
		 * Allow other threads to access the socket
		 */
		error = sosdp_waitconnected(so, fflag);
		dprint(4, ("sosdp_connect: wait on so:%p priv:%p failed:%d",
		    (void *)so,	so->so_priv, error));
	}
	switch (error) {
	case 0:
	case EINPROGRESS:
	case EALREADY:
	case EINTR:
		/* Non-fatal errors */
		so->so_state |= SS_ISBOUND;
		break;
	default:
		/* clear SS_ISCONNECTING in case it was set */
		so->so_state &= ~SS_ISCONNECTING;
		break;
	}
done:
	so_unlock_single(so, SOLOCKED);
	mutex_exit(&so->so_lock);
	return (error);
}


/*
 * Receive data.
 */
int
sosdp_recvmsg(struct sonode *so, struct nmsghdr *msg, struct uio *uiop)
{
	int flags, error = 0;
	int size;

	flags = msg->msg_flags;
	msg->msg_flags = 0;


	if (!(so->so_state & (SS_ISCONNECTED|SS_ISCONNECTING|
	    SS_CANTRCVMORE))) {
		return (ENOTCONN);
	}

	/*
	 * flag possibilities:
	 *
	 * MSG_PEEK	Don't consume data
	 * MSG_WAITALL	Wait for full quantity of data (ignored if MSG_PEEK)
	 * MSG_DONTWAIT Non-blocking (same as FNDELAY | FNONBLOCK)
	 *
	 * MSG_WAITALL can return less than the full buffer if either
	 *
	 * 1. we would block and we are non-blocking
	 * 2. a full message cannot be delivered
	 *
	 */

	mutex_enter(&so->so_lock);

	/*
	 * Allow just one reader at a time.
	 */
	error = so_lock_read_intr(so,
	    uiop->uio_fmode | ((flags & MSG_DONTWAIT) ? FNONBLOCK : 0));
	if (error != 0) {
		mutex_exit(&so->so_lock);
		return (error);
	}
	size = uiop->uio_resid;
	mutex_exit(&so->so_lock);

	if (!(so->so_state & SS_CANTRCVMORE)) {
		if (uiop->uio_fmode & (FNDELAY|FNONBLOCK)) {
			flags |= MSG_DONTWAIT;
		}
		error = sdp_recv(so->so_priv, msg, size, flags, uiop);
	} else {
		msg->msg_controllen = 0;
		msg->msg_namelen = 0;
	}
done:
	mutex_enter(&so->so_lock);
	so_unlock_read(so);
	mutex_exit(&so->so_lock);
	return (error);
}

/*
 * Send message.
 */
static int
sosdp_sendmsg(struct sonode *so, struct nmsghdr *msg, struct uio *uiop)
{
	int flags;
	ssize_t count;
	int error;

	ASSERT(so->so_type == SOCK_STREAM);

	dprint(4, ("sosdp_sendmsg: so:%p priv:%p",
	    (void *)so, so->so_priv));

	flags = msg->msg_flags;

	if (msg->msg_controllen != 0) {
		return (EOPNOTSUPP);
	}

	mutex_enter(&so->so_lock);
	if (so->so_state & SS_CANTSENDMORE) {
		mutex_exit(&so->so_lock);
		tsignal(curthread, SIGPIPE);
		return (EPIPE);
	}

	if (so->so_error != 0) {
		error = sogeterr(so);
		mutex_exit(&so->so_lock);
		return (error);
	}

	if (uiop->uio_fmode & (FNDELAY|FNONBLOCK))
	    flags |= MSG_DONTWAIT;

	count = uiop->uio_resid;

	if (!(so->so_state & (SS_ISCONNECTING | SS_ISCONNECTED))) {
		dprint(4, ("sosdp_sendmsg: invalid state: <%x>",
		    so->so_state));
		mutex_exit(&so->so_lock);
		return (ENOTCONN);
	}

	mutex_exit(&so->so_lock);
	error = sdp_send(so->so_priv, msg, count, flags, uiop);
	if (error == 0)
		return (0);

	mutex_enter(&so->so_lock);
	if ((error == EPIPE) && (so->so_state & SS_CANTSENDMORE)) {
		/*
		 * We received shutdown between the time lock was
		 * lifted and call to sdp_sendmsg().
		 */
		mutex_exit(&so->so_lock);
		tsignal(curthread, SIGPIPE);
		return (EPIPE);
	}
	mutex_exit(&so->so_lock);
	return (error);
}


/*
 * Get address of remote node.
 */
static int
sosdp_getpeername(struct sonode *so)
{
	int error;


	if (!(so->so_state & SS_ISCONNECTED)) {
		error = ENOTCONN;
	} else {
		error = sdp_getpeername(so->so_priv, so->so_faddr_sa,
		    &so->so_faddr_len);
	}
	return (error);
}

/*
 * Get local address.
 */
static int
sosdp_getsockname(struct sonode *so)
{
	int error;

	mutex_enter(&so->so_lock);
	if (!(so->so_state & SS_ISBOUND)) {
		/*
		 * Zero address, except for address family
		 */
		bzero(so->so_laddr_sa, so->so_laddr_maxlen);

		so->so_laddr_len = (so->so_family == AF_INET6) ?
		    sizeof (struct sockaddr_in6) : sizeof (struct sockaddr_in);
		so->so_laddr_sa->sa_family = so->so_family;
		error = 0;
		mutex_exit(&so->so_lock);
	} else {
		mutex_exit(&so->so_lock);

		error = sdp_getsockname(so->so_priv, so->so_laddr_sa,
		    &so->so_laddr_len);
	}

	return (error);
}

/*
 * Called from shutdown().
 */
static int
sosdp_shutdown(struct sonode *so, int how)
{
	struct sdp_sonode *ss = SOTOSDO(so);
	uint_t state_change;
	int error = 0;
	short wakesig = 0;

	mutex_enter(&so->so_lock);
	so_lock_single(so);

	/*
	 * Record the current state and then perform any state changes.
	 * Then use the difference between the old and new states to
	 * determine which needs to be done.
	 */
	state_change = so->so_state;

	switch (how) {
	case SHUT_RD:
		socantrcvmore(so);
		break;
	case SHUT_WR:
		socantsendmore(so);
		break;
	case SHUT_RDWR:
		socantsendmore(so);
		socantrcvmore(so);
		break;
	default:
		error = EINVAL;
		goto done;
	}

	state_change = so->so_state & ~state_change;

	if (state_change & SS_CANTRCVMORE) {
		wakesig = POLLIN|POLLRDNORM;
		sosdp_sendsig(ss, SDPSIG_READ);
	}
	if (state_change & SS_CANTSENDMORE) {
		wakesig |= POLLOUT;
		so->so_state |= SS_ISDISCONNECTING;
	}
	mutex_exit(&so->so_lock);

	pollwakeup(&ss->ss_poll_list, wakesig);

	if (state_change & SS_CANTSENDMORE) {
		error = sdp_shutdown(so->so_priv, how);
	}
	mutex_enter(&so->so_lock);
done:
	so_unlock_single(so, SOLOCKED);
	mutex_exit(&so->so_lock);

	/*
	 * HACK: sdp_disconnect() may return EWOULDBLOCK.  But this error is
	 * not documented in standard socket API.  Catch it here.
	 */
	if (error == EWOULDBLOCK)
		error = 0;
	return (error);
}

/*
 * Get socket options.
 */
/*ARGSUSED*/
static int
sosdp_getsockopt(struct sonode *so, int level, int option_name,
    void *optval, socklen_t *optlenp, int flags)
{
	int error = 0;
	void *option = NULL;
	socklen_t maxlen = *optlenp, len, optlen;
	uint32_t value;
	uint8_t buffer[4];
	void *optbuf = &buffer;


	mutex_enter(&so->so_lock);

	if (level == SOL_SOCKET) {
		switch (option_name) {
		case SO_TYPE:
		case SO_ERROR:
		case SO_DEBUG:
		case SO_ACCEPTCONN:
		case SO_REUSEADDR:
		case SO_KEEPALIVE:
		case SO_DONTROUTE:
		case SO_BROADCAST:
		case SO_USELOOPBACK:
		case SO_OOBINLINE:
		case SO_SNDBUF:
		case SO_RCVBUF:
		case SO_SNDLOWAT:
		case SO_RCVLOWAT:
		case SO_DGRAM_ERRIND:
			if (maxlen < (t_uscalar_t)sizeof (int32_t)) {
				error = EINVAL;
				eprintsoline(so, error);
				goto done;
			}
			break;
		case SO_LINGER:
			if (maxlen < (t_uscalar_t)sizeof (struct linger)) {
				error = EINVAL;
				eprintsoline(so, error);
				goto done;
			}
			break;
		}
		len = (t_uscalar_t)sizeof (uint32_t);   /* Default */
		option = &value;

		switch (option_name) {
		case SO_TYPE:
			value = so->so_type;
			goto copyout;

		case SO_ERROR:
			value = sogeterr(so);
			goto copyout;

		case SO_ACCEPTCONN:
			value = (so->so_state & SS_ACCEPTCONN) ?
			    SO_ACCEPTCONN : 0;
			goto copyout;

		case SO_DEBUG:
		case SO_REUSEADDR:
		case SO_KEEPALIVE:
		case SO_DONTROUTE:
		case SO_BROADCAST:
		case SO_USELOOPBACK:
		case SO_OOBINLINE:
		case SO_DGRAM_ERRIND:
			value = (so->so_options & option_name);
			goto copyout;

			/*
			 * The following options are only returned by sockfs
			 * when sdp_get_opt() fails.
			 */

		case SO_LINGER:
			option = &so->so_linger;
			len = (t_uscalar_t)sizeof (struct linger);
			break;
		case SO_SNDBUF:
			value = so->so_sndbuf;
			len = (t_uscalar_t)sizeof (int);
			goto copyout;

		case SO_RCVBUF:
			value = so->so_rcvbuf;
			len = (t_uscalar_t)sizeof (int);
			goto copyout;

		case SO_SNDLOWAT:
			value = so->so_sndlowat;
			len = (t_uscalar_t)sizeof (int);
			goto copyout;

		case SO_RCVLOWAT:
			value = so->so_rcvlowat;
			len = (t_uscalar_t)sizeof (int);
			goto copyout;

		default:
			option = NULL;
			break;
		}
	}
	if (maxlen > sizeof (buffer)) {
		optbuf = kmem_alloc(maxlen, KM_SLEEP);
	}
	optlen = maxlen;
	mutex_exit(&so->so_lock);
	error = sdp_get_opt(so->so_priv, level, option_name, optbuf, &optlen);
	mutex_enter(&so->so_lock);
	ASSERT(optlen <= maxlen);
	if (error != 0) {
		if (option == NULL) {
			/* We have no fallback value */
			eprintsoline(so, error);
			goto free;
		}
		error = 0;
		goto copyout;
	}

	option = optbuf;
	len = optlen;

copyout:
	len = MIN(len, maxlen);
	bcopy(option, optval, len);
	*optlenp = len;

free:
	if (optbuf != &buffer) {
		kmem_free(optbuf, maxlen);
	}
done:
	mutex_exit(&so->so_lock);
	return (error);
}

/*
 * Set socket options
 */
static int
sosdp_setsockopt(struct sonode *so, int level, int option_name,
    const void *optval, t_uscalar_t optlen)
{
	int error;
	void *conn = NULL;


	/* X/Open requires this check */
	if (so->so_state & SS_CANTSENDMORE) {
		return (EINVAL);
	}

	/* Caller allocates aligned optval, or passes null */
	ASSERT(((uintptr_t)optval & (sizeof (t_scalar_t) - 1)) == 0);

	/* No SDP options should be zero-length */
	if (optlen == 0) {
		error = EINVAL;
		eprintsoline(so, error);
		return (error);
	}

	mutex_enter(&so->so_lock);
	so_lock_single(so);

	if (so->so_type == SOCK_STREAM) {
		conn = so->so_priv;
	}

	dprint(2, ("sosdp_setsockopt (%d) - conn %p %d %d \n",
		so->so_type, conn, level, option_name));
	if (conn != NULL) {
		mutex_exit(&so->so_lock);
		error = sdp_set_opt(conn, level, option_name, optval, optlen);
		mutex_enter(&so->so_lock);
	}
	/*
	 * Check for SOL_SOCKET options and record their values.
	 * If we know about a SOL_SOCKET parameter and the transport
	 * failed it with TBADOPT or TOUTSTATE (i.e. ENOPROTOOPT or
	 * EPROTO) we let the setsockopt succeed.
	 */
	if (level == SOL_SOCKET) {
		boolean_t handled = B_FALSE;

		/* Check parameters */
		switch (option_name) {
		case SO_DEBUG:
		case SO_REUSEADDR:
		case SO_KEEPALIVE:
		case SO_DONTROUTE:
		case SO_BROADCAST:
		case SO_USELOOPBACK:
		case SO_OOBINLINE:
		case SO_SNDBUF:
		case SO_RCVBUF:
		case SO_SNDLOWAT:
		case SO_RCVLOWAT:
		case SO_DGRAM_ERRIND:
			if (optlen != (t_uscalar_t)sizeof (int32_t)) {
				error = EINVAL;
				eprintsoline(so, error);
				goto done;
			}
			ASSERT(optval);
			handled = B_TRUE;
			break;
		case SO_LINGER:
			if (optlen != (t_uscalar_t)sizeof (struct linger)) {
				error = EINVAL;
				eprintsoline(so, error);
				goto done;
			}
			ASSERT(optval);
			handled = B_TRUE;
			break;
		}

#define	intvalue (*(int32_t *)optval)

		switch (option_name) {
		case SO_TYPE:
		case SO_ERROR:
		case SO_ACCEPTCONN:
			/* Can't be set */
			error = ENOPROTOOPT;
			goto done;
		case SO_LINGER: {
			struct linger *l = (struct linger *)optval;

			so->so_linger.l_linger = l->l_linger;
			if (l->l_onoff) {
				so->so_linger.l_onoff = SO_LINGER;
				so->so_options |= SO_LINGER;
			} else {
				so->so_linger.l_onoff = 0;
				so->so_options &= ~SO_LINGER;
			}
			break;
		}

		case SO_DEBUG:
		case SO_REUSEADDR:
		case SO_KEEPALIVE:
		case SO_DONTROUTE:
		case SO_BROADCAST:
		case SO_USELOOPBACK:
		case SO_OOBINLINE:
		case SO_DGRAM_ERRIND:
			if (intvalue != 0) {
				dprintso(so, 1,
				    ("sosdp_setsockopt: setting 0x%x\n",
					option_name));
				so->so_options |= option_name;
			} else {
				dprintso(so, 1,
				    ("sosdp_setsockopt: clearing 0x%x\n",
					option_name));
				so->so_options &= ~option_name;
			}
			break;

		case SO_SNDBUF:
			so->so_sndbuf = intvalue;
			if (so->so_sndlowat > so->so_sndbuf) {
				so->so_sndlowat = so->so_sndbuf;
			}
			break;
		case SO_RCVBUF:
			so->so_rcvbuf = intvalue;
			if (so->so_rcvlowat > so->so_rcvbuf) {
				so->so_rcvlowat = so->so_rcvbuf;
			}
			break;
		case SO_SNDLOWAT:
			if (so->so_sndlowat > so->so_sndbuf) {
				so->so_sndlowat = so->so_sndbuf;
			}
			break;
		case SO_RCVLOWAT:
			if (so->so_rcvlowat > so->so_rcvbuf) {
				so->so_rcvlowat = so->so_rcvbuf;
			}
			break;
		}
#undef  intvalue

		if (error != 0) {
			if ((error == ENOPROTOOPT || error == EPROTO ||
			    error == EINVAL) && handled) {
				dprintso(so, 1,
				    ("sosdp_setsockopt: ignoring error %d "
					"for 0x%x\n", error, option_name));
				error = 0;
			}
		}
	}

done:
	so_unlock_single(so, SOLOCKED);
	mutex_exit(&so->so_lock);

	return (error);
}

/*
 * Upcalls from SDP
 */

/*
 * Incoming connection on listen socket.
 */
static void *
sdp_sock_newconn(void *parenthandle, void *connind)
{
	struct sdp_sonode *lss = parenthandle;
	struct sonode *lso = &lss->ss_so;
	struct sonode *nso;
	struct sdp_sonode *nss;
	mblk_t *mp;
	int error;

	ASSERT(lso->so_state & SS_ACCEPTCONN);
	ASSERT(lso->so_priv != NULL); /* closed conn */
	ASSERT(lso->so_type == SOCK_STREAM);

	dprint(3, ("sosdp_newconn A: so:%p priv:%p", (void *)lso,
	    lso->so_priv));

	/*
	 * Check current # of queued conns against backlog
	 */
	if (lss->ss_rxqueued >= lso->so_backlog) {
		return (NULL);
	}

	/*
	 * Need to create a new socket.
	 */
	mp = allocb(sizeof (connind), BPRI_MED);
	if (mp == NULL) {
		eprintsoline(lso, ENOMEM);
		return (NULL);
	}
	DB_TYPE(mp) = M_PROTO;

	VN_HOLD(lso->so_accessvp);
	nso = sosdp_create(lso->so_accessvp, lso->so_family, lso->so_type,
	    lso->so_protocol, lso->so_version, lso, &error);
	if (nso == NULL) {
		VN_RELE(lso->so_accessvp);
		freeb(mp);
		eprintsoline(lso, error);
		return (NULL);
	}

	dprint(2, ("sdp_stream_newconn: new %p\n", nso));
	nss = SOTOSDO(nso);

	/*
	 * Inherit socket properties
	 */
	mutex_enter(&lso->so_lock);
	mutex_enter(&nso->so_lock);

	nso->so_state |= (SS_ISBOUND | SS_ISCONNECTED |
	    (lso->so_state & SS_ASYNC));
	sosdp_so_inherit(lss, nss);
	nso->so_priv = connind;

	mutex_exit(&nso->so_lock);

	++lss->ss_rxqueued;
	mutex_exit(&lso->so_lock);

	/*
	 * Copy pointer to new socket to connind queue message
	 */
	*(struct sonode **)mp->b_wptr = nso;
	mp->b_wptr += sizeof (nso);

	/*
	 * Wake people who're waiting incoming conns. Note that
	 * soqueueconnind gets so_lock.
	 */
	soqueueconnind(lso, mp);
	pollwakeup(&lss->ss_poll_list, POLLIN|POLLRDNORM);

	mutex_enter(&lso->so_lock);
	sosdp_sendsig(lss, SDPSIG_READ);
	mutex_exit(&lso->so_lock);
	return (nss);
}

/*
 * For outgoing connections, the connection has been established.
 */
static void
sdp_sock_connected(void *handle)
{
	struct sdp_sonode *ss = handle;
	struct sonode *so = &ss->ss_so;

	ASSERT(so->so_type == SOCK_STREAM);
	dprint(3, ("sosdp_connected C: so:%p priv:%p", (void *)so,
	    so->so_priv));

	mutex_enter(&so->so_lock);
	ASSERT(so->so_priv); /* closed conn */

	ASSERT(!(so->so_state & SS_ACCEPTCONN));
	soisconnected(so);

	sosdp_sendsig(ss, SDPSIG_WRITE);
	mutex_exit(&so->so_lock);

	/*
	 * Wake ones who're waiting for conn to become established.
	 */
	pollwakeup(&ss->ss_poll_list, POLLOUT);
}

/*
 * Connection got disconnected. Either with an error, or through
 * normal handshake.
 */
static void
sdp_sock_disconnected(void *handle, int error)
{
	int event = 0;
	struct sdp_sonode *ss = handle;
	struct sonode *so = &ss->ss_so;

	ASSERT(so->so_type == SOCK_STREAM);
	dprint(2, ("sosdp_disconnected C: so:%p priv:%p error:%d",
	    (void *)so, so->so_priv, error));

	mutex_enter(&so->so_lock);
	ASSERT(so->so_priv != NULL); /* closed conn */

	/*
	 * If socket is already disconnected/disconnecting,
	 * don't (re)send signal.
	 */
	if (!(so->so_state & SS_CANTRCVMORE))
		event |= SDPSIG_READ;
	if (!(so->so_state & SS_CANTSENDMORE))
		event |= SDPSIG_WRITE;
	if (event != 0)
		sosdp_sendsig(ss, event);

	soisdisconnected(so, error);
	mutex_exit(&so->so_lock);

	pollwakeup(&ss->ss_poll_list, POLLIN|POLLRDNORM|POLLOUT);
}

/*
 * Incoming data.
 */
/*ARGSUSED*/
static int
sdp_sock_recv(void *handle, mblk_t *mp, int flags)
{
	struct sdp_sonode *ss = handle;
	struct sonode *so = &ss->ss_so;

	ASSERT(so->so_type == SOCK_STREAM);

	mutex_enter(&so->so_lock);
	sosdp_sendsig(ss, SDPSIG_READ);
	mutex_exit(&so->so_lock);
	pollwakeup(&ss->ss_poll_list, POLLIN|POLLRDNORM);

	return (so->so_rcvbuf);
}

/*
 * TX queued data got acknowledged.
 */
static void
sdp_sock_xmitted(void *handle, int writeable)
{
	struct sdp_sonode *ss = handle;
	struct sonode *so = &ss->ss_so;

	dprint(4, ("sosdp_sock_xmitted: so:%p priv:%p txq:%d",
		(void *)so, so->so_priv, writeable));
	mutex_enter(&so->so_lock);
	ASSERT(so->so_priv != NULL); /* closed conn */


	/*
	 * Only do pollwakeup if the amount of queued data is less than
	 * watermark.
	 */
	if (!writeable) {
		sosdp_sendsig(ss, SDPSIG_WRITE);
		mutex_exit(&so->so_lock);
		pollwakeup(&ss->ss_poll_list, POLLOUT);
	} else {
		mutex_exit(&so->so_lock);
	}
}


/*
 * SDP notifies socket for presence of urgent data.
 */
static void
sdp_sock_urgdata(void *handle)
{
	struct sdp_sonode *ss = handle;

	ASSERT(ss->ss_so.so_type == SOCK_STREAM);

	mutex_enter(&ss->ss_so.so_lock);

	ASSERT(ss->ss_so.so_priv != NULL); /* closed conn */
	sosdp_sendsig(ss, SDPSIG_URG);

	mutex_exit(&ss->ss_so.so_lock);
}

/*
 * SDP notifies socket about receiving of conn close request from peer side.
 */
static void
sdp_sock_ordrel(void *handle)
{
	struct sdp_sonode *ss = handle;
	/* LINTED */
	struct sonode *so = &ss->ss_so;

	ASSERT(ss->ss_so.so_type == SOCK_STREAM);

	dprint(4, ("sdp_sock_ordrel : so:%p, priv:%p",
	    (void *)so, so->so_priv));
	mutex_enter(&ss->ss_so.so_lock);
	socantrcvmore(&ss->ss_so);
	mutex_exit(&ss->ss_so.so_lock);
	pollwakeup(&ss->ss_poll_list, POLLIN|POLLRDNORM);
}

static void
sdp_sock_connfail(void *handle, int error)
{

	struct sdp_sonode *ss = handle;
	struct sonode *so = &ss->ss_so;

	dprint(3, ("sosdp_conn Failed: so:%p priv:%p", (void *)so,
		so->so_priv));
	mutex_enter(&so->so_lock);
	ASSERT(so->so_priv != NULL); /* closed conn */
	so->so_state &= ~(SS_ISCONNECTING|SS_ISCONNECTED|SS_ISDISCONNECTING);
	so->so_error = (ushort_t)error;
	mutex_exit(&so->so_lock);
	cv_broadcast(&so->so_state_cv);
}
