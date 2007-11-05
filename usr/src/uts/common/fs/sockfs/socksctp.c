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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
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

#include <netinet/sctp.h>
#include <inet/sctp_itf.h>
#include "socksctp.h"

/*
 * SCTP sockfs sonode operations, 1-1 socket
 */
static int sosctp_accept(struct sonode *, int, struct sonode **);
static int sosctp_listen(struct sonode *, int);
static int sosctp_connect(struct sonode *, const struct sockaddr *, socklen_t,
    int, int);
static int sosctp_sendmsg(struct sonode *, struct nmsghdr *, struct uio *);
static int sosctp_getpeername(struct sonode *);
static int sosctp_getsockname(struct sonode *);
static int sosctp_shutdown(struct sonode *, int);
static int sosctp_getsockopt(struct sonode *, int, int, void *, socklen_t *,
    int);
static int sosctp_setsockopt(struct sonode *, int, int, const void *,
    socklen_t);

/*
 * SCTP sockfs sonode operations, 1-N socket
 */
static int sosctp_seq_connect(struct sonode *, const struct sockaddr *,
    socklen_t, int, int);
static int sosctp_seq_sendmsg(struct sonode *, struct nmsghdr *, struct uio *);

/*
 * Socket upcalls, 1-1 socket connection
 */
static void *sctp_sock_newconn(void *parenthandle, void *connind);
static void sctp_sock_connected(void *handle);
static int sctp_sock_disconnected(void *handle, int error);
static void sctp_sock_disconnecting(void *handle);
static int sctp_sock_recv(void *handle, mblk_t *mp, int flags);
static void sctp_sock_xmitted(void *handle, int txqueued);
static void sctp_sock_properties(void *handle, int wroff, size_t maxblk);

/*
 * Socket association upcalls, 1-N socket connection
 */
static void *sctp_assoc_newconn(void *parenthandle, void *connind);
static void sctp_assoc_connected(void *handle);
static int sctp_assoc_disconnected(void *handle, int error);
static void sctp_assoc_disconnecting(void *handle);
static int sctp_assoc_recv(void *handle, mblk_t *mp, int flags);
static void sctp_assoc_xmitted(void *handle, int txqueued);
static void sctp_assoc_properties(void *handle, int wroff, size_t maxblk);

static kmem_cache_t *sosctp_sockcache;
kmem_cache_t *sosctp_assoccache;

sonodeops_t sosctp_sonodeops = {
	sosctp_accept,		/* sop_accept	*/
	sosctp_bind,		/* sop_bind	*/
	sosctp_listen,		/* sop_listen	*/
	sosctp_connect,		/* sop_connect	*/
	sosctp_recvmsg,		/* sop_recvmsg	*/
	sosctp_sendmsg,		/* sop_sendmsg	*/
	sosctp_getpeername,	/* sop_getpeername */
	sosctp_getsockname,	/* sop_getsockname */
	sosctp_shutdown,	/* sop_shutdown */
	sosctp_getsockopt,	/* sop_getsockopt */
	sosctp_setsockopt	/* sop_setsockopt */
};

sonodeops_t sosctp_seq_sonodeops = {
	sosctp_accept,		/* sop_accept	*/
	sosctp_bind,		/* sop_bind	*/
	sosctp_listen,		/* sop_listen	*/
	sosctp_seq_connect,	/* sop_connect	*/
	sosctp_recvmsg,		/* sop_recvmsg	*/
	sosctp_seq_sendmsg,	/* sop_sendmsg	*/
	sosctp_getpeername,	/* sop_getpeername */
	sosctp_getsockname,	/* sop_getsockname */
	sosctp_shutdown,	/* sop_shutdown */
	sosctp_getsockopt,	/* sop_getsockopt */
	sosctp_setsockopt	/* sop_setsockopt */
};

sctp_upcalls_t sosctp_sock_upcalls = {
	sctp_sock_newconn,
	sctp_sock_connected,
	sctp_sock_disconnected,
	sctp_sock_disconnecting,
	sctp_sock_recv,
	sctp_sock_xmitted,
	sctp_sock_properties
};

sctp_upcalls_t sosctp_assoc_upcalls = {
	sctp_assoc_newconn,
	sctp_assoc_connected,
	sctp_assoc_disconnected,
	sctp_assoc_disconnecting,
	sctp_assoc_recv,
	sctp_assoc_xmitted,
	sctp_assoc_properties
};

/*ARGSUSED*/
static int
sosctp_sock_constructor(void *buf, void *cdrarg, int kmflags)
{
	struct sctp_sonode *ss = buf;
	struct sonode *so = &ss->ss_so;
	struct vnode *vp;

	ss->ss_type		= SOSCTP_SOCKET;
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

	vp = vn_alloc(kmflags);
	if (vp == NULL) {
		return (-1);
	}
	so->so_vnode = vp;

	vn_setops(vp, socksctp_vnodeops);
	vp->v_data = (caddr_t)so;

	ss->ss_rxdata = NULL;
	ss->ss_rxtail = &ss->ss_rxdata;

	mutex_init(&so->so_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&so->so_plumb_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&so->so_state_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&so->so_ack_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&so->so_connind_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&so->so_want_cv, NULL, CV_DEFAULT, NULL);

	cv_init(&ss->ss_txdata_cv, NULL, CV_DEFAULT, NULL);
	cv_init(&ss->ss_rxdata_cv, NULL, CV_DEFAULT, NULL);

	return (0);
}

/*ARGSUSED*/
static void
sosctp_sock_destructor(void *buf, void *cdrarg)
{
	struct sctp_sonode *ss = buf;
	struct sonode *so = &ss->ss_so;
	struct vnode *vp = SOTOV(so);

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
	ASSERT(so->so_ops == &sosctp_sonodeops ||
	    so->so_ops == &sosctp_seq_sonodeops);

	ASSERT(ss->ss_rxdata == NULL);

	ASSERT(vn_matchops(vp, socksctp_vnodeops));
	ASSERT(vp->v_data == (caddr_t)so);

	vn_free(vp);

	mutex_destroy(&so->so_lock);
	mutex_destroy(&so->so_plumb_lock);
	cv_destroy(&so->so_state_cv);
	cv_destroy(&so->so_ack_cv);
	cv_destroy(&so->so_connind_cv);
	cv_destroy(&so->so_want_cv);
	cv_destroy(&ss->ss_txdata_cv);
	cv_destroy(&ss->ss_rxdata_cv);
}

int
sosctp_init(void)
{
	int error;

	error = vn_make_ops("socksctp", socksctp_vnodeops_template,
	    &socksctp_vnodeops);
	if (error != 0) {
		zcmn_err(GLOBAL_ZONEID, CE_WARN,
		    "sosctp_init: bad vnode ops template");
		return (error);
	}

	sosctp_sockcache = kmem_cache_create("sctpsock",
	    sizeof (struct sctp_sonode), 0, sosctp_sock_constructor,
	    sosctp_sock_destructor, NULL, NULL, NULL, 0);
	sosctp_assoccache = kmem_cache_create("sctp_assoc",
	    sizeof (struct sctp_soassoc), 0, NULL, NULL, NULL, NULL, NULL, 0);
	return (0);
}

static struct vnode *
sosctp_makevp(struct vnode *accessvp, int domain, int type, int protocol,
    int kmflags)
{
	struct sctp_sonode *ss;
	struct sonode *so;
	struct vnode *vp;
	time_t now;

	ss = kmem_cache_alloc(sosctp_sockcache, kmflags);
	if (ss == NULL) {
		return (NULL);
	}
	so = &ss->ss_so;
	so->so_cache = sosctp_sockcache;
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

	ss->ss_maxassoc	= 0;
	ss->ss_assoccnt	= 0;
	ss->ss_assocs	= NULL;

	if (type == SOCK_STREAM) {
		so->so_ops	= &sosctp_sonodeops;
	} else {
		ASSERT(type == SOCK_SEQPACKET);
		so->so_ops	= &sosctp_seq_sonodeops;
		mutex_enter(&so->so_lock);
		(void) sosctp_aid_grow(ss, 1, kmflags);
		mutex_exit(&so->so_lock);
	}
	ss->ss_rxqueued = 0;
	ss->ss_txqueued = 0;
	ss->ss_wroff = 0;
	ss->ss_wrsize = strmsgsz;
	bzero(&ss->ss_poll_list, sizeof (ss->ss_poll_list));

	vn_exists(vp);
	return (vp);
}

/*
 * Creates a sctp socket data structure.
 * tso is non-NULL if it's passive open.
 */
struct sonode *
sosctp_create(vnode_t *accessvp, int domain, int type, int protocol,
    int version, struct sonode *tso, int *errorp)
{
	struct sonode *so;
	vnode_t *vp;
	int error;
	int soflags;
	cred_t *cr;

	if (version == SOV_STREAM) {
		*errorp = EINVAL;
		return (NULL);
	}
	ASSERT(accessvp != NULL);

	/*
	 * We only support two types of SCTP socket.  Let sotpi_create()
	 * handle all other cases, such as raw socket.
	 */
	if (!(domain == AF_INET || domain == AF_INET6) ||
	    !(type == SOCK_STREAM || type == SOCK_SEQPACKET)) {
		return (sotpi_create(accessvp, domain, type, protocol, version,
		    NULL, errorp));
	}

	if (tso == NULL) {
		vp = sosctp_makevp(accessvp, domain, type, protocol, KM_SLEEP);
		ASSERT(vp != NULL);

		soflags = FREAD | FWRITE;
	} else {
		vp = sosctp_makevp(accessvp, domain, type, protocol,
		    KM_NOSLEEP);
		if (vp == NULL) {
			/*
			 * sosctp_makevp() only fails when there is no memory.
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

	dprint(2, ("sosctp_create: %p domain %d type %d\n", so, domain, type));

	if (version == SOV_DEFAULT) {
		version = so_default_version;
	}
	so->so_version = (short)version;

	return (so);
}

/*
 * Free SCTP socket data structure.
 * Closes incoming connections which were never accepted, frees
 * resources.
 */
void
sosctp_free(struct sonode *so)
{
	struct sctp_sonode *ss = SOTOSSO(so);
	struct sonode *nso;
	mblk_t *mp;

	mutex_enter(&so->so_lock);

	/*
	 * Need to clear these out so that sockfree() doesn't think that
	 * there's memory in need of free'ing.
	 */
	so->so_laddr_sa = so->so_faddr_sa = NULL;
	so->so_laddr_len = so->so_laddr_maxlen = 0;
	so->so_faddr_len = so->so_faddr_maxlen = 0;

	while ((mp = ss->ss_rxdata) != NULL) {
		ss->ss_rxdata = mp->b_next;
		mp->b_next = NULL;
		freemsg(mp);
		mp = ss->ss_rxdata;
	}
	ss->ss_rxtail = &ss->ss_rxdata;


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

	if (ss->ss_assocs != NULL) {
		ASSERT(ss->ss_assoccnt == 0);
		kmem_free(ss->ss_assocs,
		    ss->ss_maxassoc * sizeof (struct sctp_sa_id));
	}
	mutex_exit(&so->so_lock);

	sockfree(so);
}

/*
 * Accept incoming connection.
 */
static int
sosctp_accept(struct sonode *lso, int fflag, struct sonode **nsop)
{
	int error = 0;
	mblk_t *mp;
	struct sonode *nso;

	if (!(lso->so_state & SS_ACCEPTCONN)) {
		/*
		 * Not a listen socket.
		 */
		eprintsoline(lso, EINVAL);
		return (EINVAL);
	}
	if (lso->so_type != SOCK_STREAM) {
		/*
		 * Cannot accept() connections from SOCK_SEQPACKET type
		 * socket.
		 */
		eprintsoline(lso, EOPNOTSUPP);
		return (EOPNOTSUPP);
	}

	/*
	 * Returns right away if socket is nonblocking.
	 */
	error = sowaitconnind(lso, fflag, &mp);
	if (error != 0) {
		eprintsoline(lso, error);
		return (error);
	}
	nso = *(struct sonode **)mp->b_rptr;
	freeb(mp);

	mutex_enter(&lso->so_lock);
	ASSERT(SOTOSSO(lso)->ss_rxqueued > 0);
	--SOTOSSO(lso)->ss_rxqueued;
	mutex_exit(&lso->so_lock);

	/*
	 * accept() needs remote address right away.
	 * since sosctp_getpeername() is called with
	 * socket lock released, the connection may
	 * get aborted before we return from the
	 * routine. So, we need to to handle aborted
	 * socket connection here.
	 */
	error = sosctp_getpeername(nso);
	if (error != 0) {
		vnode_t *nvp;
		nvp = SOTOV(nso);
		(void) VOP_CLOSE(nvp, 0, 1, 0, CRED(), NULL);
		VN_RELE(nvp);

		/*
		 * We can't return ENOTCONN to accept. accept
		 * either returns connected socket in case no error
		 * has occured or the connection which is getting
		 * accepted is being aborted. This is the reason we
		 * return ECONNABORTED in case sosctp_getpeername()
		 * returns ENOTCONN.
		 */
		return ((error == ENOTCONN) ? ECONNABORTED : error);
	}

	dprint(2, ("sosctp_accept: new %p\n", nso));

	*nsop = nso;
	return (0);
}

/*
 * Bind local endpoint.
 */
int
sosctp_bind(struct sonode *so, struct sockaddr *name, socklen_t namelen,
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
		 * Multiple binds not allowed for any SCTP socket.
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

	error = sctp_bind(so->so_priv, name, namelen);

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
sosctp_listen(struct sonode *so, int backlog)
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
	 * If listen() is only called to change backlog, we don't
	 * need to notify protocol module.
	 */
	if (so->so_state & SS_ACCEPTCONN) {
		so->so_backlog = backlog;
		goto done;
	}

	mutex_exit(&so->so_lock);

	error = sctp_listen(so->so_priv);

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
static int
sosctp_connect(struct sonode *so, const struct sockaddr *name,
    socklen_t namelen, int fflag, int flags)
{
	int error;

	ASSERT(so->so_type == SOCK_STREAM);

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

	error = sctp_connect(so->so_priv, name, namelen);

	mutex_enter(&so->so_lock);
	if (error == 0) {
		/*
		 * Allow other threads to access the socket
		 */
		error = sosctp_waitconnected(so, fflag);
	}
	switch (error) {
	case 0:
	case EINPROGRESS:
	case EALREADY:
	case EINTR:
		/* Non-fatal errors */
		so->so_state |= SS_ISBOUND;
		break;
	case EHOSTUNREACH:
		if (flags & _SOCONNECT_XPG4_2) {
			/*
			 * X/Open specification contains a requirement that
			 * ENETUNREACH be returned but does not require
			 * EHOSTUNREACH. In order to keep the test suite
			 * happy we mess with the errno here.
			 */
			error = ENETUNREACH;
		}
		/* FALLTHRU */

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
 * Active open for 1-N sockets, create a new association and
 * call connect on that.
 * If there parent hasn't been bound yet (this is the first association),
 * make it so.
 */
static int
sosctp_seq_connect(struct sonode *so, const struct sockaddr *name,
    socklen_t namelen, int fflag, int flags)
{
	struct sctp_soassoc *ssa;
	struct sctp_sonode *ss;
	int error;

	ASSERT(so->so_type == SOCK_SEQPACKET);

	mutex_enter(&so->so_lock);
	so_lock_single(so);

	if (name == NULL || namelen == 0) {
		error = EINVAL;
		eprintsoline(so, error);
		goto done;
	}

	ss = SOTOSSO(so);

	error = sosctp_assoc_createconn(ss, name, namelen, NULL, 0, fflag,
	    &ssa);
	if (error != 0) {
		if ((error == EHOSTUNREACH) && (flags & _SOCONNECT_XPG4_2)) {
			error = ENETUNREACH;
		}
	}
	if (ssa != NULL) {
		SSA_REFRELE(ss, ssa);
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
sosctp_recvmsg(struct sonode *so, struct nmsghdr *msg, struct uio *uiop)
{
	struct sctp_sonode *ss = SOTOSSO(so);
	struct sctp_soassoc *ssa = NULL;
	int flags, error = 0;
	struct T_unitdata_ind *tind;
	int len, count, readcnt = 0, rxqueued;
	boolean_t consumed = B_FALSE;
	void *opt;
	mblk_t *mp, *mdata;

	flags = msg->msg_flags;
	msg->msg_flags = 0;

	if (so->so_type == SOCK_STREAM) {
		if (!(so->so_state & (SS_ISCONNECTED|SS_ISCONNECTING|
		    SS_CANTRCVMORE))) {
			return (ENOTCONN);
		}
	} else {
		/* For 1-N socket, recv() cannot be used. */
		if (msg->msg_namelen == 0)
			return (EOPNOTSUPP);
		/*
		 * If there are no associations, and no new connections are
		 * coming in, there's not going to be new messages coming
		 * in either.
		 */
		if (ss->ss_rxdata == NULL && ss->ss_assoccnt == 0 &&
		    !(so->so_state & SS_ACCEPTCONN)) {
			return (ENOTCONN);
		}
	}

	/*
	 * out-of-band data not supported.
	 */
	if (flags & MSG_OOB) {
		return (EOPNOTSUPP);
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
	 * Given that we always get a full message from proto below,
	 * MSG_WAITALL is not meaningful.
	 */

	mutex_enter(&so->so_lock);

	/*
	 * Allow just one reader at a time.
	 */
	error = so_lock_read_intr(so,
	    uiop->uio_fmode | ((flags & MSG_DONTWAIT) ? FNONBLOCK : 0));
	if (error) {
		mutex_exit(&so->so_lock);
		return (error);
	}
again:
	mp = ss->ss_rxdata;
	if (mp != NULL) {
		if (so->so_type == SOCK_SEQPACKET) {
			ssa = *(struct sctp_soassoc **)DB_BASE(mp);
		}
		mutex_exit(&so->so_lock);

		tind = (struct T_unitdata_ind *)mp->b_rptr;

		len = tind->SRC_length;

		if (msg->msg_namelen > 0 && len > 0) {

			opt = sogetoff(mp, tind->SRC_offset, len, 1);

			ASSERT(opt != NULL);

			msg->msg_name = kmem_alloc(len, KM_SLEEP);
			msg->msg_namelen = len;

			bcopy(opt, msg->msg_name, len);
		} else {
			msg->msg_namelen = 0;
		}

		len = tind->OPT_length;
		if (msg->msg_controllen == 0) {
			if (len > 0) {
				msg->msg_flags |= MSG_CTRUNC;
			}
		} else if (len > 0) {
			opt = sogetoff(mp, tind->OPT_offset, len,
			    __TPI_ALIGN_SIZE);

			ASSERT(opt != NULL);
			sosctp_pack_cmsg(opt, msg, len);
		} else {
			msg->msg_controllen = 0;
		}

		if (mp->b_flag & SCTP_NOTIFICATION) {
			msg->msg_flags |= MSG_NOTIFICATION;
		}

		mdata = mp->b_cont;
		while (mdata != NULL) {
			len = MBLKL(mdata);
			count = MIN(uiop->uio_resid, len);

			error = uiomove(mdata->b_rptr, count, UIO_READ, uiop);
			/*
			 * We will re-read this message the next time.
			 */
			if (error != 0) {
				if (msg->msg_namelen > 0) {
					kmem_free(msg->msg_name,
					    msg->msg_namelen);
				}
				if (msg->msg_controllen > 0) {
					kmem_free(msg->msg_control,
					    msg->msg_controllen);
				}
				mutex_enter(&so->so_lock);
				so_unlock_read(so);
				mutex_exit(&so->so_lock);
				return (error);
			}
			if (!(flags & MSG_PEEK))
				readcnt += count;
			if (uiop->uio_resid == 0) {
				mblk_t	*mp1 = ss->ss_rxdata;
				mblk_t	*mp2 = mp1->b_cont;
#ifdef	DEBUG
				int	rcnt = readcnt;
#endif

				/* Finished with this message? */
				if (count == len && mdata->b_cont == NULL)
					break;
				/*
				 * Remove the bits that have been read, the
				 * next read will start from where we left
				 * off.
				 */
				while (mp1->b_cont != mdata) {
#ifdef	DEBUG
					ASSERT(rcnt > MBLKL(mp1->b_cont));
					rcnt -= MBLKL(mp1->b_cont);
#endif
					mp1 = mp1->b_cont;
				}
#ifdef	DEBUG
				ASSERT(rcnt == count);
#endif
				if (len > count)
					mp1->b_cont->b_rptr += count;
				else
					mp1 = mp1->b_cont;
				mutex_enter(&so->so_lock);
				if (mp2 != mp1->b_cont) {
					ss->ss_rxdata->b_cont = mp1->b_cont;
					mp1->b_cont = NULL;
					freemsg(mp2);
				}
				goto done;
			}
			mdata = mdata->b_cont;
		}
		if (!(mp->b_flag & SCTP_PARTIAL_DATA))
			msg->msg_flags |= MSG_EOR;
		/*
		 * Consume this message
		 */
consume:
		mutex_enter(&so->so_lock);
		if (!(flags & MSG_PEEK)) {
			ss->ss_rxdata = mp->b_next;
			if (ss->ss_rxtail == &mp->b_next) {
				ss->ss_rxtail = &ss->ss_rxdata;
			}
			mp->b_next = NULL;
			freemsg(mp);
			consumed = B_TRUE;
		}
	} else {
		/*
		 * No pending data. Return right away for nonblocking
		 * socket, otherwise sleep waiting for data.
		 */
		if (!(so->so_state & SS_CANTRCVMORE)) {
			if ((uiop->uio_fmode & (FNDELAY|FNONBLOCK)) ||
			    (flags & MSG_DONTWAIT)) {
				error = EWOULDBLOCK;
			} else {
				if (!cv_wait_sig(&ss->ss_rxdata_cv,
				    &so->so_lock)) {
					error = EINTR;
				} else {
					goto again;
				}
			}
		} else {
			msg->msg_controllen = 0;
			msg->msg_namelen = 0;
		}
	}
done:
	/*
	 * Determine if we need to update SCTP about the buffer
	 * space.  For performance reason, we cannot update SCTP
	 * every time a message is read.  The socket buffer low
	 * watermark is used as the threshold.
	 */
	if (ssa == NULL) {
		rxqueued = ss->ss_rxqueued;

		ss->ss_rxqueued = rxqueued - readcnt;
		count = so->so_rcvbuf - ss->ss_rxqueued;

		ASSERT(ss->ss_rxdata != NULL || ss->ss_rxqueued == 0);

		so_unlock_read(so);
		mutex_exit(&so->so_lock);

		if (readcnt > 0 && (((count > 0) &&
		    (rxqueued >= so->so_rcvlowat)) ||
		    (ss->ss_rxqueued == 0))) {
			/*
			 * If amount of queued data is higher than watermark,
			 * updata SCTP's idea of available buffer space.
			 */
			sctp_recvd(so->so_priv, count);
		}
	} else {
		rxqueued = ssa->ssa_rxqueued;

		ssa->ssa_rxqueued = rxqueued - readcnt;
		count = so->so_rcvbuf - ssa->ssa_rxqueued;

		so_unlock_read(so);

		if (readcnt > 0 &&
		    (((count > 0) && (rxqueued >= so->so_rcvlowat)) ||
		    (ssa->ssa_rxqueued == 0))) {
			/*
			 * If amount of queued data is higher than watermark,
			 * updata SCTP's idea of available buffer space.
			 */
			mutex_exit(&so->so_lock);

			sctp_recvd(ssa->ssa_conn, count);

			mutex_enter(&so->so_lock);
		}
		if (consumed) {
			SSA_REFRELE(ss, ssa);
		}
		mutex_exit(&so->so_lock);
	}

	return (error);
}

int
sosctp_uiomove(mblk_t *hdr_mp, ssize_t count, ssize_t blk_size, int wroff,
    struct uio *uiop, int flags, cred_t *cr)
{
	ssize_t size;
	int error;
	mblk_t *mp;
	dblk_t *dp;

	/*
	 * Loop until we have all data copied into mblk's.
	 */
	while (count > 0) {
		size = MIN(count, blk_size);

		/*
		 * As a message can be splitted up and sent in different
		 * packets, each mblk will have the extra space before
		 * data to accommodate what SCTP wants to put in there.
		 */
		while ((mp = allocb_cred(size + wroff, cr)) == NULL) {
			if ((uiop->uio_fmode & (FNDELAY|FNONBLOCK)) ||
			    (flags & MSG_DONTWAIT)) {
				return (EAGAIN);
			}
			if ((error = strwaitbuf(size + wroff, BPRI_MED))) {
				return (error);
			}
		}

		dp = mp->b_datap;
		dp->db_cpid = curproc->p_pid;
		ASSERT(wroff <= dp->db_lim - mp->b_wptr);
		mp->b_rptr += wroff;
		error = uiomove(mp->b_rptr, size, UIO_WRITE, uiop);
		if (error != 0) {
			freeb(mp);
			return (error);
		}
		mp->b_wptr = mp->b_rptr + size;
		count -= size;
		hdr_mp->b_cont = mp;
		hdr_mp = mp;
	}
	return (0);
}

/*
 * Send message.
 */
static int
sosctp_sendmsg(struct sonode *so, struct nmsghdr *msg, struct uio *uiop)
{
	struct sctp_sonode *ss = SOTOSSO(so);
	mblk_t *mctl;
	struct cmsghdr *cmsg;
	struct sctp_sndrcvinfo *sinfo;
	int optlen, flags, fflag;
	ssize_t count, msglen;
	int error;

	ASSERT(so->so_type == SOCK_STREAM);

	flags = msg->msg_flags;
	if (flags & MSG_OOB) {
		/*
		 * No out-of-band data support.
		 */
		return (EOPNOTSUPP);
	}

	if (msg->msg_controllen != 0) {
		optlen = msg->msg_controllen;
		cmsg = sosctp_find_cmsg(msg->msg_control, optlen, SCTP_SNDRCV);
		if (cmsg != NULL) {
			if (cmsg->cmsg_len <
			    (sizeof (*sinfo) + sizeof (*cmsg))) {
				eprintsoline(so, EINVAL);
				return (EINVAL);
			}
			sinfo = (struct sctp_sndrcvinfo *)(cmsg + 1);

			/* Both flags should not be set together. */
			if ((sinfo->sinfo_flags & MSG_EOF) &&
			    (sinfo->sinfo_flags & MSG_ABORT)) {
				eprintsoline(so, EINVAL);
				return (EINVAL);
			}

			/* Initiate a graceful shutdown. */
			if (sinfo->sinfo_flags & MSG_EOF) {
				/* Can't include data in MSG_EOF message. */
				if (uiop->uio_resid != 0) {
					eprintsoline(so, EINVAL);
					return (EINVAL);
				}

				/*
				 * This is the same sequence as done in
				 * shutdown(SHUT_WR).
				 */
				mutex_enter(&so->so_lock);
				so_lock_single(so);
				socantsendmore(so);
				cv_broadcast(&ss->ss_txdata_cv);
				so->so_state |= SS_ISDISCONNECTING;
				mutex_exit(&so->so_lock);

				pollwakeup(&ss->ss_poll_list, POLLOUT);
				sctp_recvd(so->so_priv, so->so_rcvbuf);
				error = sctp_disconnect(so->so_priv);

				mutex_enter(&so->so_lock);
				so_unlock_single(so, SOLOCKED);
				mutex_exit(&so->so_lock);
				return (error);
			}
		}
	} else {
		optlen = 0;
	}

	mutex_enter(&so->so_lock);
	for (;;) {
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

		if (ss->ss_txqueued < so->so_sndbuf)
			break;

		/*
		 * Xmit window full in a blocking socket.
		 */
		if ((uiop->uio_fmode & (FNDELAY|FNONBLOCK)) ||
		    (flags & MSG_DONTWAIT)) {
			mutex_exit(&so->so_lock);
			return (EAGAIN);
		} else {
			/*
			 * Wait for space to become available and try again.
			 */
			error = cv_wait_sig(&ss->ss_txdata_cv, &so->so_lock);
			if (!error) { /* signal */
				mutex_exit(&so->so_lock);
				return (EINTR);
			}
		}
	}
	msglen = count = uiop->uio_resid;

	/* Don't allow sending a message larger than the send buffer size. */
	if (msglen > so->so_sndbuf) {
		mutex_exit(&so->so_lock);
		return (EMSGSIZE);
	}

	/*
	 * Update TX buffer usage here so that we can lift the socket lock.
	 */
	ss->ss_txqueued += msglen;

	/*
	 * Allow piggybacking data on handshake messages (SS_ISCONNECTING).
	 */
	if (!(so->so_state & (SS_ISCONNECTING | SS_ISCONNECTED))) {
		/*
		 * We need to check here for listener so that the
		 * same error will be returned as with a TCP socket.
		 * In this case, sosctp_connect() returns EOPNOTSUPP
		 * while a TCP socket returns ENOTCONN instead.  Catch it
		 * here to have the same behavior as a TCP socket.
		 *
		 * We also need to make sure that the peer address is
		 * provided before we attempt to do the connect.
		 */
		if ((so->so_state & SS_ACCEPTCONN) ||
		    msg->msg_name == NULL) {
			mutex_exit(&so->so_lock);
			error = ENOTCONN;
			goto error_nofree;
		}
		mutex_exit(&so->so_lock);
		fflag = uiop->uio_fmode;
		if (flags & MSG_DONTWAIT) {
			fflag |= FNDELAY;
		}
		error = sosctp_connect(so, msg->msg_name, msg->msg_namelen,
		    fflag, (so->so_version == SOV_XPG4_2) * _SOCONNECT_XPG4_2);
		if (error) {
			/*
			 * Check for non-fatal errors, socket connected
			 * while the lock had been lifted.
			 */
			if (error != EISCONN && error != EALREADY) {
				goto error_nofree;
			}
			error = 0;
		}
	} else {
		mutex_exit(&so->so_lock);
	}

	mctl = sctp_alloc_hdr(msg->msg_name, msg->msg_namelen,
	    msg->msg_control, optlen, SCTP_CAN_BLOCK);
	if (mctl == NULL) {
		error = EINTR;
		goto error_nofree;
	}

	/* Copy in the message. */
	if ((error = sosctp_uiomove(mctl, count, ss->ss_wrsize, ss->ss_wroff,
	    uiop, flags, CRED())) != 0) {
		goto error_ret;
	}
	error = sctp_sendmsg(so->so_priv, mctl, 0);
	if (error == 0)
		return (0);

error_ret:
	freemsg(mctl);
error_nofree:
	mutex_enter(&so->so_lock);
	ss->ss_txqueued -= msglen;
	cv_broadcast(&ss->ss_txdata_cv);
	if ((error == EPIPE) && (so->so_state & SS_CANTSENDMORE)) {
		/*
		 * We received shutdown between the time lock was
		 * lifted and call to sctp_sendmsg().
		 */
		mutex_exit(&so->so_lock);
		tsignal(curthread, SIGPIPE);
		return (EPIPE);
	}
	mutex_exit(&so->so_lock);
	return (error);
}

/*
 * Send message on 1-N socket. Connects automatically if there is
 * no association.
 */
static int
sosctp_seq_sendmsg(struct sonode *so, struct nmsghdr *msg, struct uio *uiop)
{
	struct sctp_sonode *ss;
	struct sctp_soassoc *ssa;
	struct cmsghdr *cmsg;
	struct sctp_sndrcvinfo *sinfo;
	int aid = 0;
	mblk_t *mctl;
	int namelen, optlen, flags;
	ssize_t count, msglen;
	int error;
	uint16_t s_flags = 0;

	ASSERT(so->so_type == SOCK_SEQPACKET);

	/*
	 * There shouldn't be problems with alignment, as the memory for
	 * msg_control was alloced with kmem_alloc.
	 */
	cmsg = sosctp_find_cmsg(msg->msg_control, msg->msg_controllen,
	    SCTP_SNDRCV);
	if (cmsg != NULL) {
		if (cmsg->cmsg_len < (sizeof (*sinfo) + sizeof (*cmsg))) {
			eprintsoline(so, EINVAL);
			return (EINVAL);
		}
		sinfo = (struct sctp_sndrcvinfo *)(cmsg + 1);
		s_flags = sinfo->sinfo_flags;
		aid = sinfo->sinfo_assoc_id;
	}

	ss = SOTOSSO(so);
	namelen = msg->msg_namelen;

	if (msg->msg_controllen > 0) {
		optlen = msg->msg_controllen;
	} else {
		optlen = 0;
	}

	mutex_enter(&so->so_lock);

	/*
	 * If there is no association id, connect to address specified
	 * in msg_name.  Otherwise look up the association using the id.
	 */
	if (aid == 0) {
		/*
		 * Connect and shutdown cannot be done together, so check for
		 * MSG_EOF.
		 */
		if (msg->msg_name == NULL || namelen == 0 ||
		    (s_flags & MSG_EOF)) {
			error = EINVAL;
			eprintsoline(so, error);
			goto done;
		}
		flags = uiop->uio_fmode;
		if (msg->msg_flags & MSG_DONTWAIT) {
			flags |= FNDELAY;
		}
		so_lock_single(so);
		error = sosctp_assoc_createconn(ss, msg->msg_name, namelen,
		    msg->msg_control, optlen, flags, &ssa);
		if (error) {
			if ((so->so_version == SOV_XPG4_2) &&
			    (error == EHOSTUNREACH)) {
				error = ENETUNREACH;
			}
			if (ssa == NULL) {
				/*
				 * Fatal error during connect(). Bail out.
				 * If ssa exists, it means that the handshake
				 * is in progress.
				 */
				eprintsoline(so, error);
				so_unlock_single(so, SOLOCKED);
				goto done;
			}
			/*
			 * All the errors are non-fatal ones, don't return
			 * e.g. EINPROGRESS from sendmsg().
			 */
			error = 0;
		}
		so_unlock_single(so, SOLOCKED);
	} else {
		if ((error = sosctp_assoc(ss, aid, &ssa)) != 0) {
			eprintsoline(so, error);
			goto done;
		}
	}

	/*
	 * Now we have an association.
	 */
	flags = msg->msg_flags;

	/*
	 * MSG_EOF initiates graceful shutdown.
	 */
	if (s_flags & MSG_EOF) {
		if (uiop->uio_resid) {
			/*
			 * Can't include data in MSG_EOF message.
			 */
			error = EINVAL;
		} else {
			mutex_exit(&so->so_lock);
			ssa->ssa_state |= SS_ISDISCONNECTING;
			sctp_recvd(ssa->ssa_conn, so->so_rcvbuf);
			error = sctp_disconnect(ssa->ssa_conn);
			mutex_enter(&so->so_lock);
		}
		goto refrele;
	}

	for (;;) {
		if (ssa->ssa_state & SS_CANTSENDMORE) {
			SSA_REFRELE(ss, ssa);
			mutex_exit(&so->so_lock);
			tsignal(curthread, SIGPIPE);
			return (EPIPE);
		}

		if (ssa->ssa_error != 0) {
			error = ssa->ssa_error;
			ssa->ssa_error = 0;
			goto refrele;
		}

		if (ssa->ssa_txqueued < so->so_sndbuf)
			break;

		if ((uiop->uio_fmode & (FNDELAY|FNONBLOCK)) ||
		    (flags & MSG_DONTWAIT)) {
			error = EAGAIN;
			goto refrele;
		} else {
			/*
			 * Wait for space to become available and try again.
			 */
			error = cv_wait_sig(&ss->ss_txdata_cv, &so->so_lock);
			if (!error) { /* signal */
				error = EINTR;
				goto refrele;
			}
		}
	}

	msglen = count = uiop->uio_resid;

	/* Don't allow sending a message larger than the send buffer size. */
	if (msglen > so->so_sndbuf) {
		error = EMSGSIZE;
		goto refrele;
	}

	/*
	 * Update TX buffer usage here so that we can lift the socket lock.
	 */
	ssa->ssa_txqueued += msglen;

	mutex_exit(&so->so_lock);

	mctl = sctp_alloc_hdr(msg->msg_name, namelen, msg->msg_control,
	    optlen, SCTP_CAN_BLOCK);
	if (mctl == NULL) {
		error = EINTR;
		goto lock_rele;
	}

	/* Copy in the message. */
	if ((error = sosctp_uiomove(mctl, count, ssa->ssa_wrsize,
	    ssa->ssa_wroff, uiop, flags, CRED())) != 0) {
		goto lock_rele;
	}
	error = sctp_sendmsg(ssa->ssa_conn, mctl, 0);
lock_rele:
	mutex_enter(&so->so_lock);
	if (error != 0) {
		freemsg(mctl);
		ssa->ssa_txqueued -= msglen;
		cv_broadcast(&ss->ss_txdata_cv);
		if ((error == EPIPE) && (ssa->ssa_state & SS_CANTSENDMORE)) {
			/*
			 * We received shutdown between the time lock was
			 * lifted and call to sctp_sendmsg().
			 */
			SSA_REFRELE(ss, ssa);
			mutex_exit(&so->so_lock);
			tsignal(curthread, SIGPIPE);
			return (EPIPE);
		}
	}

refrele:
	SSA_REFRELE(ss, ssa);
done:
	mutex_exit(&so->so_lock);
	return (error);
}

/*
 * Get address of remote node.
 */
static int
sosctp_getpeername(struct sonode *so)
{
	int error;

	if (so->so_type != SOCK_STREAM) {
		/*
		 * SEQPACKET can have multiple end-points.
		 */
		return (EOPNOTSUPP);
	}

	if (!(so->so_state & SS_ISCONNECTED)) {
		error = ENOTCONN;
	} else {
		error = sctp_getpeername(so->so_priv, so->so_faddr_sa,
		    &so->so_faddr_len);
	}
	return (error);
}

/*
 * Get local address.
 */
static int
sosctp_getsockname(struct sonode *so)
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

		error = sctp_getsockname(so->so_priv, so->so_laddr_sa,
		    &so->so_laddr_len);
	}

	return (error);
}

/*
 * Called from shutdown().
 */
static int
sosctp_shutdown(struct sonode *so, int how)
{
	struct sctp_sonode *ss = SOTOSSO(so);
	uint_t state_change;
	int error = 0;
	short wakesig = 0;

	if (so->so_type == SOCK_SEQPACKET) {
		return (EOPNOTSUPP);
	}
	mutex_enter(&so->so_lock);
	so_lock_single(so);

	/*
	 * SunOS 4.X has no check for datagram sockets.
	 * 5.X checks that it is connected (ENOTCONN)
	 * X/Open requires that we check the connected state.
	 */
	if (!(so->so_state & SS_ISCONNECTED)) {
		error = ENOTCONN;
		goto done;
	}

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
		if (ss->ss_rxdata == NULL) {
			cv_signal(&ss->ss_rxdata_cv);
		}
		wakesig = POLLIN|POLLRDNORM;

		sosctp_sendsig(ss, SCTPSIG_READ);
	}
	if (state_change & SS_CANTSENDMORE) {
		cv_broadcast(&ss->ss_txdata_cv);
		wakesig |= POLLOUT;

		so->so_state |= SS_ISDISCONNECTING;
	}
	mutex_exit(&so->so_lock);

	pollwakeup(&ss->ss_poll_list, wakesig);

	if (state_change & SS_CANTSENDMORE) {
		sctp_recvd(so->so_priv, so->so_rcvbuf);
		error = sctp_disconnect(so->so_priv);
	}
	mutex_enter(&so->so_lock);
done:
	so_unlock_single(so, SOLOCKED);
	mutex_exit(&so->so_lock);

	/*
	 * HACK: sctp_disconnect() may return EWOULDBLOCK.  But this error is
	 * not documented in standard socket API.  Catch it here.
	 */
	if (error == EWOULDBLOCK)
		error = 0;
	return (error);
}

/*
 * Get socket options.
 */
/*ARGSUSED5*/
static int
sosctp_getsockopt(struct sonode *so, int level, int option_name,
    void *optval, socklen_t *optlenp, int flags)
{
	int		error = 0;
	void		*option = NULL;
	socklen_t	maxlen = *optlenp;
	socklen_t	len;
	socklen_t	optlen;
	uint32_t	value;
	uint8_t		buffer[4];
	void		*optbuf = &buffer;

	mutex_enter(&so->so_lock);

	if (level == SOL_SOCKET) {
		switch (option_name) {
		/* Not supported options */
		case SO_SNDTIMEO:
		case SO_RCVTIMEO:
		case SO_EXCLBIND:
			error = ENOPROTOOPT;
			eprintsoline(so, error);
			goto done;

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
		case SO_PROTOTYPE:
		case SO_DOMAIN:
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

		/*
		 * Most of the SOL_SOCKET level option values are also
		 * recorded in sockfs.  So we can return the recorded value
		 * here without calling into SCTP.
		 */
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

		case SO_SNDBUF:
			value = so->so_sndbuf;
			goto copyout;

		case SO_RCVBUF:
			value = so->so_rcvbuf;
			goto copyout;

		case SO_SNDLOWAT:
			value = so->so_sndlowat;
			goto copyout;

		case SO_RCVLOWAT:
			value = so->so_rcvlowat;
			goto copyout;

		case SO_PROTOTYPE:
			value = IPPROTO_SCTP;
			goto copyout;

		case SO_DOMAIN:
			value = so->so_family;
			goto copyout;

		case SO_LINGER:
			option = &so->so_linger;
			len = (t_uscalar_t)sizeof (struct linger);
			break;

		default:
			option = NULL;
			break;
		}
	}
	if (level == IPPROTO_SCTP) {
		/*
		 * Should go through ioctl().
		 */
		error = EINVAL;
		goto done;
	}
	if (maxlen > sizeof (buffer)) {
		optbuf = kmem_alloc(maxlen, KM_SLEEP);
	}
	optlen = maxlen;
	mutex_exit(&so->so_lock);
	/*
	 * If the resulting optlen is greater than the provided maxlen, then
	 * we sliently trucate.
	 */
	error = sctp_get_opt(so->so_priv, level, option_name, optbuf, &optlen);
	mutex_enter(&so->so_lock);
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
sosctp_setsockopt(struct sonode *so, int level, int option_name,
    const void *optval, t_uscalar_t optlen)
{
	struct sctp_sonode *ss = SOTOSSO(so);
	struct sctp_soassoc *ssa = NULL;
	sctp_assoc_t id;
	int error, rc;
	void *conn = NULL;

	/* X/Open requires this check */
	if (so->so_state & SS_CANTSENDMORE) {
		return (EINVAL);
	}
	if ((option_name == SCTP_UC_SWAP) && (level == IPPROTO_SCTP)) {
		error = EOPNOTSUPP;
		eprintsoline(so, error);
		return (error);
	}

	/* Caller allocates aligned optval, or passes null */
	ASSERT(((uintptr_t)optval & (sizeof (t_scalar_t) - 1)) == 0);

	/* No SCTP options should be zero-length */
	if (optlen == 0) {
		error = EINVAL;
		eprintsoline(so, error);
		return (error);
	}

	mutex_enter(&so->so_lock);
	so_lock_single(so);

	/*
	 * For some SCTP level options, one can select the association this
	 * applies to.
	 */
	if (so->so_type == SOCK_STREAM) {
		conn = so->so_priv;
	} else {
		/*
		 * SOCK_SEQPACKET only
		 */
		id = 0;
		if (level == IPPROTO_SCTP) {
			switch (option_name) {
			case SCTP_RTOINFO:
			case SCTP_ASSOCINFO:
			case SCTP_SET_PEER_PRIMARY_ADDR:
			case SCTP_PRIMARY_ADDR:
			case SCTP_PEER_ADDR_PARAMS:
				/*
				 * Association ID is the first element
				 * params struct
				 */
				if (optlen < sizeof (sctp_assoc_t)) {
					error = EINVAL;
					eprintsoline(so, error);
					goto done;
				}
				id = *(sctp_assoc_t *)optval;
				break;
			case SCTP_DEFAULT_SEND_PARAM:
				if (optlen != sizeof (struct sctp_sndrcvinfo)) {
					error = EINVAL;
					eprintsoline(so, error);
					goto done;
				}
				id = ((struct sctp_sndrcvinfo *)
				    optval)->sinfo_assoc_id;
				break;
			case SCTP_INITMSG:
				/*
				 * Only applies to future associations
				 */
				conn = so->so_priv;
				break;
			default:
				break;
			}
		} else if (level == SOL_SOCKET) {
			if (option_name == SO_LINGER) {
				error = EOPNOTSUPP;
				eprintsoline(so, error);
				goto done;
			}
			/*
			 * These 2 options are applied to all associations.
			 * The other socket level options are only applied
			 * to the socket (not associations).
			 */
			if ((option_name != SO_RCVBUF) &&
			    (option_name != SO_SNDBUF)) {
				conn = so->so_priv;
			}
		} else {
			conn = NULL;
		}

		/*
		 * If association ID was specified, do op on that assoc.
		 * Otherwise set the default setting of a socket.
		 */
		if (id != 0) {
			if ((error = sosctp_assoc(ss, id, &ssa)) != 0) {
				eprintsoline(so, error);
				goto done;
			}
			conn = ssa->ssa_conn;
		}
	}
	dprint(2, ("sosctp_setsockopt %p (%d) - conn %p %d %d id:%d\n",
	    ss, so->so_type, conn, level, option_name, id));

	ASSERT(ssa == NULL || (ssa != NULL && conn != NULL));
	if (conn != NULL) {
		mutex_exit(&so->so_lock);
		error = sctp_set_opt(conn, level, option_name, optval, optlen);
		mutex_enter(&so->so_lock);
		if (ssa != NULL)
			SSA_REFRELE(ss, ssa);
	} else {
		/*
		 * 1-N socket, and we have to apply the operation to ALL
		 * associations. Like with anything of this sort, the
		 * problem is what to do if the operation fails.
		 * Just try to apply the setting to everyone, but store
		 * error number if someone returns such.  And since we are
		 * looping through all possible aids, some of them can be
		 * invalid.  We just ignore this kind (sosctp_assoc()) of
		 * errors.
		 */
		sctp_assoc_t aid;

		mutex_exit(&so->so_lock);
		error = sctp_set_opt(so->so_priv, level, option_name, optval,
		    optlen);
		mutex_enter(&so->so_lock);
		for (aid = 1; aid < ss->ss_maxassoc; aid++) {
			if (sosctp_assoc(ss, aid, &ssa) != 0)
				continue;
			mutex_exit(&so->so_lock);
			rc = sctp_set_opt(ssa->ssa_conn, level, option_name,
			    optval, optlen);
			mutex_enter(&so->so_lock);
			SSA_REFRELE(ss, ssa);
			if (error == 0) {
				error = rc;
			}
		}
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
		case SO_SNDTIMEO:
		case SO_RCVTIMEO:
		case SO_EXCLBIND:
		case SO_TYPE:
		case SO_ERROR:
		case SO_ACCEPTCONN:
		case SO_PROTOTYPE:
		case SO_DOMAIN:
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
				    ("sosctp_setsockopt: setting 0x%x\n",
				    option_name));
				so->so_options |= option_name;
			} else {
				dprintso(so, 1,
				    ("sosctp_setsockopt: clearing 0x%x\n",
				    option_name));
				so->so_options &= ~option_name;
			}
			break;
			/*
			 * The following options are only returned by us when
			 * the sctp_set_opt fails.
			 * XXX XPG 4.2 applications retrieve SO_RCVBUF from
			 * sockfs since the transport might adjust the value
			 * and not return exactly what was set by the
			 * application.
			 */
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
			so->so_sndlowat = intvalue;
			if (so->so_sndlowat > so->so_sndbuf) {
				so->so_sndlowat = so->so_sndbuf;
			}
			break;
		case SO_RCVLOWAT:
			so->so_rcvlowat = intvalue;
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
				    ("sosctp_setsockopt: ignoring error %d "
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
 * Upcalls from SCTP
 */

/*
 * Incoming connection on listen socket.
 */
static void *
sctp_sock_newconn(void *parenthandle, void *connind)
{
	struct sctp_sonode *lss = parenthandle;
	struct sonode *lso = &lss->ss_so;
	struct sonode *nso;
	struct sctp_sonode *nss;
	mblk_t *mp;
	int error;

	ASSERT(lso->so_state & SS_ACCEPTCONN);
	ASSERT(lso->so_priv != NULL); /* closed conn */
	ASSERT(lso->so_type == SOCK_STREAM);

	/*
	 * Check current # of queued conns against backlog
	 */
	if (lss->ss_rxqueued >= lso->so_backlog) {
		return (NULL);
	}

	/*
	 * Need to create a new socket.
	 */
	mp = allocb(sizeof (nso), BPRI_MED);
	if (mp == NULL) {
		eprintsoline(lso, ENOMEM);
		return (NULL);
	}
	DB_TYPE(mp) = M_PROTO;

	VN_HOLD(lso->so_accessvp);
	nso = sosctp_create(lso->so_accessvp, lso->so_family, lso->so_type,
	    lso->so_protocol, lso->so_version, lso, &error);
	if (nso == NULL) {
		VN_RELE(lso->so_accessvp);
		freeb(mp);
		eprintsoline(lso, error);
		return (NULL);
	}

	dprint(2, ("sctp_stream_newconn: new %p\n", nso));

	nss = SOTOSSO(nso);

	/*
	 * Inherit socket properties
	 */
	mutex_enter(&lso->so_lock);
	mutex_enter(&nso->so_lock);

	nso->so_state |= (SS_ISBOUND | SS_ISCONNECTED |
	    (lso->so_state & SS_ASYNC));
	sosctp_so_inherit(lss, nss);
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
	sosctp_sendsig(lss, SCTPSIG_READ);
	mutex_exit(&lso->so_lock);

	return (nss);
}

/*
 * This is the upcall function for 1-N (SOCK_SEQPACKET) socket when a new
 * association is created.  Note that the first argument (handle) is of type
 * sctp_sonode *, which is the one changed to a listener for new
 * associations.  All the other upcalls for 1-N socket take sctp_soassoc *
 * as handle.  The only exception is the su_properties upcall, which
 * can take both types as handle.
 */
static void *
sctp_assoc_newconn(void *parenthandle, void *connind)
{
	struct sctp_sonode *lss = (struct sctp_sonode *)parenthandle;
	struct sonode *lso = &lss->ss_so;
	struct sctp_soassoc *ssa;
	sctp_assoc_t id;

	ASSERT(lss->ss_type == SOSCTP_SOCKET);
	ASSERT(lso->so_state & SS_ACCEPTCONN);
	ASSERT(lso->so_priv != NULL); /* closed conn */
	ASSERT(lso->so_type == SOCK_SEQPACKET);

	mutex_enter(&lso->so_lock);

	if ((id = sosctp_aid_get(lss)) == -1) {
		/*
		 * Array not large enough; increase size.
		 */
		if (sosctp_aid_grow(lss, lss->ss_maxassoc, KM_NOSLEEP) < 0) {
			mutex_exit(&lso->so_lock);
			return (NULL);
		}
		id = sosctp_aid_get(lss);
		ASSERT(id != -1);
	}

	/*
	 * Create soassoc for this connection
	 */
	ssa = sosctp_assoc_create(lss, KM_NOSLEEP);
	if (ssa == NULL) {
		mutex_exit(&lso->so_lock);
		return (NULL);
	}
	sosctp_aid_reserve(lss, id, 1);
	lss->ss_assocs[id].ssi_assoc = ssa;
	++lss->ss_assoccnt;
	ssa->ssa_id = id;
	ssa->ssa_conn = connind;
	ssa->ssa_state = (SS_ISBOUND | SS_ISCONNECTED);
	ssa->ssa_wroff = lss->ss_wroff;
	ssa->ssa_wrsize = lss->ss_wrsize;

	mutex_exit(&lso->so_lock);

	return (ssa);
}

/*
 * For outgoing connections, the connection has been established.
 */
static void
sctp_sock_connected(void *handle)
{
	struct sctp_sonode *ss = handle;
	struct sonode *so = &ss->ss_so;

	ASSERT(so->so_type == SOCK_STREAM);

	mutex_enter(&so->so_lock);
	ASSERT(so->so_priv); /* closed conn */

	ASSERT(!(so->so_state & SS_ACCEPTCONN));
	soisconnected(so);

	sosctp_sendsig(ss, SCTPSIG_WRITE);

	mutex_exit(&so->so_lock);

	/*
	 * Wake ones who're waiting for conn to become established.
	 */
	pollwakeup(&ss->ss_poll_list, POLLOUT);
}

static void
sctp_assoc_connected(void *handle)
{
	struct sctp_soassoc *ssa = handle;
	struct sonode *so = &ssa->ssa_sonode->ss_so;

	ASSERT(so->so_type == SOCK_SEQPACKET);
	ASSERT(ssa->ssa_conn);

	mutex_enter(&so->so_lock);
	sosctp_assoc_isconnected(ssa);
	mutex_exit(&so->so_lock);
}

/*
 * Connection got disconnected. Either with an error, or through
 * normal handshake.
 * Note that there is no half-closed conn, like TCP.
 */
static int
sctp_sock_disconnected(void *handle, int error)
{
	struct sctp_sonode *ss = handle;
	struct sonode *so = &ss->ss_so;
	int event = 0;

	ASSERT(so->so_type == SOCK_STREAM);

	mutex_enter(&so->so_lock);
	ASSERT(so->so_priv != NULL); /* closed conn */

	/*
	 * Connection is gone, wake everybody.
	 */
	if (ss->ss_rxdata == NULL) {
		cv_signal(&ss->ss_rxdata_cv);
	}
	cv_broadcast(&ss->ss_txdata_cv);

	/*
	 * If socket is already disconnected/disconnecting,
	 * don't (re)send signal.
	 */
	if (!(so->so_state & SS_CANTRCVMORE))
		event |= SCTPSIG_READ;
	if (!(so->so_state & SS_CANTSENDMORE))
		event |= SCTPSIG_WRITE;
	if (event != 0)
		sosctp_sendsig(ss, event);

	soisdisconnected(so, error);
	mutex_exit(&so->so_lock);

	pollwakeup(&ss->ss_poll_list, POLLIN|POLLRDNORM|POLLOUT);

	return (0);
}

static int
sctp_assoc_disconnected(void *handle, int error)
{
	struct sctp_soassoc *ssa = handle;
	struct sctp_sonode *ss = ssa->ssa_sonode;
	struct sonode *so = &ssa->ssa_sonode->ss_so;
	int ret;

	ASSERT(so->so_type == SOCK_SEQPACKET);
	ASSERT(ssa->ssa_conn != NULL);

	mutex_enter(&so->so_lock);
	sosctp_assoc_isdisconnected(ssa, error);
	if (ssa->ssa_refcnt == 1) {
		ret = 1;
		ssa->ssa_conn = NULL;
	} else {
		ret = 0;
	}
	SSA_REFRELE(SOTOSSO(so), ssa);

	cv_broadcast(&ss->ss_txdata_cv);

	mutex_exit(&so->so_lock);

	return (ret);
}

/*
 * Peer sent a shutdown. After this point writes are not allowed
 * to this socket, but one might still receive notifications
 * (e.g. for data which never got sent).
 */
static void
sctp_sock_disconnecting(void *handle)
{
	struct sctp_sonode *ss = handle;
	struct sonode *so = &ss->ss_so;

	ASSERT(so->so_type == SOCK_STREAM);

	mutex_enter(&so->so_lock);
	ASSERT(so->so_priv != NULL); /* closed conn */

	/*
	 * Socket not writeable anymore. Wake writers, and ones
	 * who're waiting on socket state change
	 */
	cv_broadcast(&ss->ss_txdata_cv);

	if (!(so->so_state & SS_CANTSENDMORE)) {
		/*
		 * If socket already un-writeable, don't (re)send signal.
		 */
		sosctp_sendsig(ss, SCTPSIG_WRITE);
	}
	so->so_state &= ~(SS_ISCONNECTING);
	so->so_state |= SS_CANTSENDMORE;
	cv_broadcast(&so->so_state_cv);
	mutex_exit(&so->so_lock);

	pollwakeup(&ss->ss_poll_list, POLLOUT);
}

static void
sctp_assoc_disconnecting(void *handle)
{
	struct sctp_soassoc *ssa = handle;
	struct sonode *so = &ssa->ssa_sonode->ss_so;

	ASSERT(so->so_type == SOCK_SEQPACKET);
	ASSERT(ssa->ssa_conn != NULL);

	mutex_enter(&so->so_lock);
	sosctp_assoc_isdisconnecting(ssa);
	mutex_exit(&so->so_lock);
}

/*
 * Incoming data.
 */
static int
sctp_sock_recv(void *handle, mblk_t *mp, int flags)
{
	struct sctp_sonode *ss = handle;
	struct sonode *so = &ss->ss_so;
	int msglen;
#if defined(DEBUG) && !defined(lint)
	union T_primitives *tpr;
#endif

	ASSERT(so->so_type == SOCK_STREAM);
	ASSERT(mp != NULL);
	ASSERT(!(so->so_state & SS_ACCEPTCONN));

	/*
	 * Should be getting T_unitdata_req's only.
	 * Must have address as part of packet.
	 */
#if defined(DEBUG) && !defined(lint)
	tpr = (union T_primitives *)mp->b_rptr;
	ASSERT((DB_TYPE(mp) == M_PROTO) &&
	    (tpr->type == T_UNITDATA_IND));
	ASSERT((tpr->unitdata_ind.SRC_length));
#endif

	/*
	 * First mblk has only unitdata_req
	 */
	msglen = msgsize(mp->b_cont);

	mutex_enter(&so->so_lock);
	ASSERT(so->so_priv); /* closed conn */

	if (so->so_state & SS_CANTRCVMORE) {
		mutex_exit(&so->so_lock);
		freemsg(mp);
		return (so->so_rcvbuf);
	}
	if (ss->ss_rxdata == NULL) {
		cv_signal(&ss->ss_rxdata_cv);
	}
	*ss->ss_rxtail = mp;
	ss->ss_rxtail = &mp->b_next;
	ss->ss_rxqueued += msglen;

	sosctp_sendsig(ss, SCTPSIG_READ);

	/*
	 * Override b_flag for SCTP sockfs internal use
	 */
	mp->b_flag = (short)flags;

	mutex_exit(&so->so_lock);

	pollwakeup(&ss->ss_poll_list, POLLIN|POLLRDNORM);

	return (so->so_rcvbuf - ss->ss_rxqueued);
}

static int
sctp_assoc_recv(void *handle, mblk_t *mp, int flags)
{
	struct sctp_soassoc *ssa = handle;
	struct sctp_sonode *ss = ssa->ssa_sonode;
	struct sonode *so = &ss->ss_so;
	struct T_unitdata_ind *tind;
	int msglen;
	mblk_t *mp2;
	union sctp_notification *sn;
	struct sctp_sndrcvinfo *sinfo;

	ASSERT(ssa->ssa_type == SOSCTP_ASSOC);
	ASSERT(so->so_type == SOCK_SEQPACKET);
	ASSERT(ssa->ssa_conn != NULL); /* closed conn */
	ASSERT(mp != NULL);

	/*
	 * Should be getting T_unitdata_req's only.
	 * Must have address as part of packet.
	 */
	tind = (struct T_unitdata_ind *)mp->b_rptr;
	ASSERT((DB_TYPE(mp) == M_PROTO) &&
	    (tind->PRIM_type == T_UNITDATA_IND));
	ASSERT(tind->SRC_length);

	/*
	 * First mblk has only unitdata_req
	 */
	msglen = msgsize(mp->b_cont);

	mutex_enter(&so->so_lock);

	/*
	 * Override b_flag for SCTP sockfs internal use
	 */
	mp->b_flag = (short)flags;

	/*
	 * For notify messages, need to fill in association id.
	 * For data messages, sndrcvinfo could be in ancillary data.
	 */
	if (flags & SCTP_NOTIFICATION) {
		mp2 = mp->b_cont;
		sn = (union sctp_notification *)mp2->b_rptr;
		switch (sn->sn_header.sn_type) {
		case SCTP_ASSOC_CHANGE:
			sn->sn_assoc_change.sac_assoc_id = ssa->ssa_id;
			break;
		case SCTP_PEER_ADDR_CHANGE:
			sn->sn_paddr_change.spc_assoc_id = ssa->ssa_id;
			break;
		case SCTP_REMOTE_ERROR:
			sn->sn_remote_error.sre_assoc_id = ssa->ssa_id;
			break;
		case SCTP_SEND_FAILED:
			sn->sn_send_failed.ssf_assoc_id = ssa->ssa_id;
			break;
		case SCTP_SHUTDOWN_EVENT:
			sn->sn_shutdown_event.sse_assoc_id = ssa->ssa_id;
			break;
		case SCTP_ADAPTION_INDICATION:
			sn->sn_adaption_event.sai_assoc_id = ssa->ssa_id;
			break;
		case SCTP_PARTIAL_DELIVERY_EVENT:
			sn->sn_pdapi_event.pdapi_assoc_id = ssa->ssa_id;
			break;
		default:
			ASSERT(0);
			break;
		}
	} else {
		if (tind->OPT_length > 0) {
			struct cmsghdr	*cmsg;
			char		*cend;

			cmsg = (struct cmsghdr *)
			    ((uchar_t *)mp->b_rptr + tind->OPT_offset);
			cend = (char *)cmsg + tind->OPT_length;
			for (;;) {
				if ((char *)(cmsg + 1) > cend ||
				    ((char *)cmsg + cmsg->cmsg_len) > cend) {
					break;
				}
				if ((cmsg->cmsg_level == IPPROTO_SCTP) &&
				    (cmsg->cmsg_type == SCTP_SNDRCV)) {
					sinfo = (struct sctp_sndrcvinfo *)
					    (cmsg + 1);
					sinfo->sinfo_assoc_id = ssa->ssa_id;
					break;
				}
				if (cmsg->cmsg_len > 0) {
					cmsg = (struct cmsghdr *)
					    ((uchar_t *)cmsg + cmsg->cmsg_len);
				} else {
					break;
				}
			}
		}
	}

	/*
	 * SCTP has reserved space in the header for storing a pointer.
	 * Put the pointer to assocation there, and queue the data.
	 */
	SSA_REFHOLD(ssa);
	ASSERT((mp->b_rptr - DB_BASE(mp)) >= sizeof (ssa));
	*(struct sctp_soassoc **)DB_BASE(mp) = ssa;

	if (ss->ss_rxdata == NULL) {
		cv_signal(&ss->ss_rxdata_cv);
	}
	*ss->ss_rxtail = mp;
	ss->ss_rxtail = &mp->b_next;
	ssa->ssa_rxqueued += msglen;

	sosctp_sendsig(ss, SCTPSIG_READ);

	mutex_exit(&so->so_lock);

	pollwakeup(&ss->ss_poll_list, POLLIN|POLLRDNORM);

	return (so->so_rcvbuf - ssa->ssa_rxqueued);
}

/*
 * TX queued data got acknowledged. Frees up space in TX queue.
 */
static void
sctp_sock_xmitted(void *handle, int txqueued)
{
	struct sctp_sonode *ss = handle;
	struct sonode *so = &ss->ss_so;
	boolean_t writeable;

	mutex_enter(&so->so_lock);
	ASSERT(so->so_priv != NULL); /* closed conn */

	if (ss->ss_txqueued < so->so_sndlowat) {
		writeable = B_TRUE;
	} else {
		writeable = B_FALSE;
	}
	ss->ss_txqueued = txqueued;

	/*
	 * Wake blocked writers.
	 */
	cv_broadcast(&ss->ss_txdata_cv);

	/*
	 * Only do pollwakeup if the amount of queued data is less than
	 * watermark, and the socket wasn't writeable before.
	 */
	if (!writeable && (ss->ss_txqueued < so->so_sndlowat)) {
		sosctp_sendsig(ss, SCTPSIG_WRITE);
		mutex_exit(&so->so_lock);
		pollwakeup(&ss->ss_poll_list, POLLOUT);
	} else {
		mutex_exit(&so->so_lock);
	}
}

static void
sctp_assoc_xmitted(void *handle, int txqueued)
{
	struct sctp_soassoc *ssa = handle;
	struct sctp_sonode *ss = ssa->ssa_sonode;

	ASSERT(ssa->ssa_type == SOSCTP_ASSOC);
	ASSERT(ss->ss_so.so_type == SOCK_SEQPACKET);
	ASSERT(ssa->ssa_conn != NULL);

	mutex_enter(&ss->ss_so.so_lock);

	ssa->ssa_txqueued = txqueued;

	/*
	 * Wake blocked writers.
	 */
	cv_broadcast(&ss->ss_txdata_cv);

	mutex_exit(&ss->ss_so.so_lock);
}

/*
 * SCTP notifies socket about write offset and amount of TX data per mblk.
 */
static void
sctp_sock_properties(void *handle, int wroff, size_t maxblk)
{
	struct sctp_sonode *ss = handle;

	ASSERT(ss->ss_so.so_type == SOCK_STREAM);

	mutex_enter(&ss->ss_so.so_lock);

	ASSERT(ss->ss_so.so_priv != NULL); /* closed conn */

	/*
	 * Only change them if they're set.
	 */
	if (wroff != 0) {
		ss->ss_wroff = wroff;
	}
	if (maxblk != 0) {
		ss->ss_wrsize = maxblk;
	}
	mutex_exit(&ss->ss_so.so_lock);
}

static void
sctp_assoc_properties(void *handle, int wroff, size_t maxblk)
{
	struct sctp_soassoc *ssa = handle;
	struct sctp_sonode *ss;

	if (ssa->ssa_type == SOSCTP_ASSOC) {
		ss = ssa->ssa_sonode;
		mutex_enter(&ss->ss_so.so_lock);

		/*
		 * Only change them if they're set.
		 */
		if (wroff != 0) {
			ssa->ssa_wroff = wroff;
		}
		if (maxblk != 0) {
			ssa->ssa_wrsize = maxblk;
		}
	} else {
		ss = (struct sctp_sonode *)handle;
		mutex_enter(&ss->ss_so.so_lock);

		if (wroff != 0) {
			ss->ss_wroff = wroff;
		}
		if (maxblk != 0) {
			ss->ss_wrsize = maxblk;
		}
	}

	mutex_exit(&ss->ss_so.so_lock);
}
