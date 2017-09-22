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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2017 Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/buf.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/stropts.h>
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>
#include <sys/policy.h>

#include <sys/filio.h>
#include <sys/sockio.h>

#include <sys/project.h>
#include <sys/tihdr.h>
#include <sys/strsubr.h>

#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/strsun.h>

#include <sys/tsol/label.h>

#include <inet/sdp_itf.h>
#include "socksdp.h"
#include <fs/sockfs/sockcommon.h>

/*
 * SDP sockfs sonode operations
 */
static int sosdp_init(struct sonode *, struct sonode *, struct cred *, int);
static int sosdp_accept(struct sonode *, int, struct cred *, struct sonode **);
static int sosdp_bind(struct sonode *, struct sockaddr *, socklen_t, int,
    struct cred *);
static int sosdp_listen(struct sonode *, int, struct cred *);
static int sosdp_connect(struct sonode *, struct sockaddr *, socklen_t,
    int, int, struct cred *);
static int sosdp_recvmsg(struct sonode *, struct nmsghdr *, struct uio *,
    struct cred *);
static int sosdp_sendmsg(struct sonode *, struct nmsghdr *, struct uio *,
    struct cred *);
static int sosdp_getpeername(struct sonode *, struct sockaddr *, socklen_t *,
    boolean_t, struct cred *);
static int sosdp_getsockname(struct sonode *, struct sockaddr *, socklen_t *,
    struct cred *);
static int sosdp_shutdown(struct sonode *, int, struct cred *);
static int sosdp_getsockopt(struct sonode *, int, int, void *, socklen_t *,
    int, struct cred *);
static int sosdp_setsockopt(struct sonode *, int, int, const void *,
    socklen_t, struct cred *);
static int sosdp_ioctl(struct sonode *, int, intptr_t, int, struct cred *,
    int32_t *);
static int sosdp_poll(struct sonode *, short, int, short *,
    struct pollhead **);
static int sosdp_close(struct sonode *, int, struct cred *);
void sosdp_fini(struct sonode *, struct cred *);


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

sonodeops_t sosdp_sonodeops = {
	sosdp_init,			/* sop_init	*/
	sosdp_accept,			/* sop_accept	*/
	sosdp_bind,			/* sop_bind	*/
	sosdp_listen,			/* sop_listen	*/
	sosdp_connect,			/* sop_connect	*/
	sosdp_recvmsg,			/* sop_recvmsg	*/
	sosdp_sendmsg,			/* sop_sendmsg	*/
	so_sendmblk_notsupp,		/* sop_sendmblk */
	sosdp_getpeername,		/* sop_getpeername */
	sosdp_getsockname,		/* sop_getsockname */
	sosdp_shutdown,			/* sop_shutdown */
	sosdp_getsockopt,		/* sop_getsockopt */
	sosdp_setsockopt,		/* sop_setsockopt */
	sosdp_ioctl,			/* sop_ioctl	*/
	sosdp_poll,			/* sop_poll	*/
	sosdp_close,			/* sop_close	*/
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

/* ARGSUSED */
static int
sosdp_init(struct sonode *so, struct sonode *pso, struct cred *cr, int flags)
{
	int error = 0;
	sdp_sockbuf_limits_t sbl;
	sdp_upcalls_t *upcalls;

	if (pso != NULL) {
		/* passive open, just inherit settings from parent */

		mutex_enter(&so->so_lock);

		so->so_state |= (SS_ISBOUND | SS_ISCONNECTED |
		    (pso->so_state & SS_ASYNC));
		sosdp_so_inherit(pso, so);
		so->so_proto_props = pso->so_proto_props;

		mutex_exit(&so->so_lock);

		return (0);
	}

	if ((error = secpolicy_basic_net_access(cr)) != 0)
		return (error);

	upcalls = &sosdp_sock_upcalls;

	so->so_proto_handle = (sock_lower_handle_t)sdp_create(so, NULL,
	    so->so_family, SDP_CAN_BLOCK, upcalls, &sbl, cr, &error);
	if (so->so_proto_handle == NULL)
		return (ENOMEM);

	so->so_rcvbuf = sbl.sbl_rxbuf;
	so->so_rcvlowat = sbl.sbl_rxlowat;
	so->so_sndbuf = sbl.sbl_txbuf;
	so->so_sndlowat = sbl.sbl_txlowat;

	return (error);
}

/*
 * Accept incoming connection.
 */
/* ARGSUSED */
static int
sosdp_accept(struct sonode *lso, int fflag, struct cred *cr,
    struct sonode **nsop)
{
	int error = 0;
	struct sonode *nso;

	dprint(3, ("sosdp_accept: so:%p so_proto_handle:%p", (void *)lso,
	    (void *)lso->so_proto_handle));

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
	error = so_acceptq_dequeue(lso, (fflag & (FNONBLOCK|FNDELAY)), &nso);
	if (error != 0) {
		eprintsoline(lso, error);
		dprint(4, ("sosdp_accept: failed %d:lso:%p so_proto_handle:%p",
		    error, (void *)lso, (void *)lso->so_proto_handle));
		return (error);
	}

	dprint(2, ("sosdp_accept: new %p\n", (void *)nso));
	*nsop = nso;

	return (0);
}

/*
 * Bind local endpoint.
 */
/* ARGSUSED */
int
sosdp_bind(struct sonode *so, struct sockaddr *name, socklen_t namelen,
    int flags, struct cred *cr)
{
	int	error = 0;

	if (!(flags & _SOBIND_LOCK_HELD)) {
		mutex_enter(&so->so_lock);
		so_lock_single(so);	/* Set SOLOCKED */
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
	 * Protocol module does address family checks
	 */
	mutex_exit(&so->so_lock);

	error = sdp_bind((struct sdp_conn_struct_t *)so->so_proto_handle,
	    name, namelen);

	mutex_enter(&so->so_lock);

	if (error == 0) {
		so->so_state |= SS_ISBOUND;
	} else {
		eprintsoline(so, error);
	}
done:
	if (!(flags & _SOBIND_LOCK_HELD)) {
		so_unlock_single(so, SOLOCKED);
		mutex_exit(&so->so_lock);
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
/* ARGSUSED */
static int
sosdp_listen(struct sonode *so, int backlog, struct cred *cr)
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
		eprintsoline(so, EINVAL);
		goto done;
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

	error = sdp_listen((struct sdp_conn_struct_t *)so->so_proto_handle,
	    backlog);

	mutex_enter(&so->so_lock);
	if (error == 0) {
		so->so_state |= (SS_ACCEPTCONN | SS_ISBOUND);
		so->so_backlog = backlog;
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
sosdp_connect(struct sonode *so, struct sockaddr *name,
    socklen_t namelen, int fflag, int flags, struct cred *cr)
{
	int error = 0;

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
	 * check for failure of an earlier call
	 */
	if (so->so_error != 0) {
		error = sogeterr(so, B_TRUE);
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
		eprintsoline(so, EINVAL);
		goto done;
	}
	soisconnecting(so);
	mutex_exit(&so->so_lock);

	error = sdp_connect((struct sdp_conn_struct_t *)so->so_proto_handle,
	    name, namelen);

	mutex_enter(&so->so_lock);
	if (error == 0) {
		/*
		 * Allow other threads to access the socket
		 */
		error = sowaitconnected(so, fflag, 0);
		dprint(4,
		    ("sosdp_connect: wait on so:%p "
		    "so_proto_handle:%p failed:%d",
		    (void *)so,	(void *)so->so_proto_handle, error));
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
/* ARGSUSED */
int
sosdp_recvmsg(struct sonode *so, struct nmsghdr *msg, struct uio *uiop,
    struct cred *cr)
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
		error = sdp_recv(
		    (struct sdp_conn_struct_t *)so->so_proto_handle, msg,
		    size, flags, uiop);
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
/* ARGSUSED */
static int
sosdp_sendmsg(struct sonode *so, struct nmsghdr *msg, struct uio *uiop,
    struct cred *cr)
{
	int flags;
	ssize_t count;
	int error;

	ASSERT(so->so_type == SOCK_STREAM);

	dprint(4, ("sosdp_sendmsg: so:%p so_proto_handle:%p",
	    (void *)so, (void *)so->so_proto_handle));

	flags = msg->msg_flags;

	if (msg->msg_controllen != 0) {
		return (EOPNOTSUPP);
	}

	mutex_enter(&so->so_lock);
	if (so->so_state & SS_CANTSENDMORE) {
		mutex_exit(&so->so_lock);
		return (EPIPE);
	}

	if (so->so_error != 0) {
		error = sogeterr(so, B_TRUE);
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
	error = sdp_send((struct sdp_conn_struct_t *)so->so_proto_handle,
	    msg, count, flags, uiop);

	return (error);
}

/*
 * Get address of remote node.
 */
/* ARGSUSED */
static int
sosdp_getpeername(struct sonode *so, struct sockaddr *addr, socklen_t *addrlen,
    boolean_t accept, struct cred *cr)
{

	if (!accept && !(so->so_state & SS_ISCONNECTED)) {
		return (ENOTCONN);
	} else {
		return (sdp_getpeername(
		    (struct sdp_conn_struct_t *)so->so_proto_handle,
		    addr, addrlen));
	}
}

/*
 * Get local address.
 */
/* ARGSUSED */
static int
sosdp_getsockname(struct sonode *so, struct sockaddr *addr, socklen_t *addrlen,
    struct cred *cr)
{
	mutex_enter(&so->so_lock);

	if (!(so->so_state & SS_ISBOUND)) {
		/*
		 * Zero address, except for address family
		 */
		if (so->so_family == AF_INET || so->so_family == AF_INET6) {
			bzero(addr, *addrlen);
			*addrlen = (so->so_family == AF_INET6) ?
			    sizeof (struct sockaddr_in6) :
			    sizeof (struct sockaddr_in);
			addr->sa_family = so->so_family;
		}
		mutex_exit(&so->so_lock);
		return (0);
	} else {
		mutex_exit(&so->so_lock);
		return (sdp_getsockname(
		    (struct sdp_conn_struct_t *)so->so_proto_handle,
		    addr, addrlen));
	}
}

/*
 * Called from shutdown().
 */
/* ARGSUSED */
static int
sosdp_shutdown(struct sonode *so, int how, struct cred *cr)
{
	uint_t state_change;
	int error = 0;

	mutex_enter(&so->so_lock);
	so_lock_single(so);
	/*
	 * Record the current state and then perform any state changes.
	 * Then use the difference between the old and new states to
	 * determine which needs to be done.
	 */
	state_change = so->so_state;
	if (!(state_change & SS_ISCONNECTED)) {
		error = ENOTCONN;
		goto done;
	}

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

	if (state_change & SS_CANTSENDMORE) {
		so->so_state |= SS_ISDISCONNECTING;
	}
	so_notify_shutdown(so);

	if (state_change & SS_CANTSENDMORE) {
		error = sdp_shutdown(
		    (struct sdp_conn_struct_t *)so->so_proto_handle, how);
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
    void *optval, socklen_t *optlenp, int flags, struct cred *cr)
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
			value = sogeterr(so, B_TRUE);
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
	error = sdp_get_opt((struct sdp_conn_struct_t *)so->so_proto_handle,
	    level, option_name, optbuf, &optlen);
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
/* ARGSUSED */
static int
sosdp_setsockopt(struct sonode *so, int level, int option_name,
    const void *optval, t_uscalar_t optlen, struct cred *cr)
{
	void *conn = NULL;
	int error = 0;

	if (so->so_state & SS_CANTSENDMORE) {
		return (EINVAL);
	}

	mutex_enter(&so->so_lock);
	so_lock_single(so);

	if (so->so_type == SOCK_STREAM) {
		conn = (void *)so->so_proto_handle;
	}

	dprint(2, ("sosdp_setsockopt (%d) - conn %p %d %d \n",
	    so->so_type, conn, level, option_name));

	if (conn != NULL) {
		mutex_exit(&so->so_lock);
		error = sdp_set_opt((struct sdp_conn_struct_t *)conn, level,
		    option_name, optval, optlen);
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

/* ARGSUSED */
static int
sosdp_ioctl(struct sonode *so, int cmd, intptr_t arg, int mode,
    struct cred *cr, int32_t *rvalp)
{
	int32_t value;
	int error, intval;
	pid_t pid;

	/* handle socket specific ioctls */
	switch (cmd) {
	case FIONBIO:
		if (so_copyin((void *)arg, &value, sizeof (int32_t),
		    (mode & (int)FKIOCTL))) {
			return (EFAULT);
		}
		mutex_enter(&so->so_lock);
		if (value != 0) {
			so->so_state |= SS_NDELAY;
		} else {
			so->so_state &= ~SS_NDELAY;
		}
		mutex_exit(&so->so_lock);
		return (0);

	case FIOASYNC:
		if (so_copyin((void *)arg, &value, sizeof (int32_t),
		    (mode & (int)FKIOCTL))) {
			return (EFAULT);
		}
		mutex_enter(&so->so_lock);

		if (value) {
			/* Turn on SIGIO */
			so->so_state |= SS_ASYNC;
		} else {
			/* Turn off SIGIO */
			so->so_state &= ~SS_ASYNC;
		}
		mutex_exit(&so->so_lock);
		return (0);

	case SIOCSPGRP:
	case FIOSETOWN:
		if (so_copyin((void *)arg, &pid, sizeof (pid_t),
		    (mode & (int)FKIOCTL))) {
			return (EFAULT);
		}
		mutex_enter(&so->so_lock);

		error = (pid != so->so_pgrp) ? socket_chgpgrp(so, pid) : 0;
		mutex_exit(&so->so_lock);
		return (error);

	case SIOCGPGRP:
	case FIOGETOWN:
		if (so_copyout(&so->so_pgrp, (void *)arg,
		    sizeof (pid_t), (mode & (int)FKIOCTL)))
			return (EFAULT);
		return (0);

	case SIOCATMARK:
		intval = 0;
		error = sdp_ioctl(
		    (struct sdp_conn_struct_t *)so->so_proto_handle, cmd,
		    &intval, cr);
		if (so_copyout(&intval, (void *)arg, sizeof (int),
		    (mode & (int)FKIOCTL)))
			return (EFAULT);
		return (0);


	case SIOCSENABLESDP: {
		int32_t enable;

		/*
		 * System wide enable SDP
		 */

		if (so_copyin((void *)arg, &enable, sizeof (int32_t),
		    mode & (int)FKIOCTL))
			return (EFAULT);

		error = sdp_ioctl(
		    (struct sdp_conn_struct_t *)so->so_proto_handle, cmd,
		    &enable, cr);
		if (so_copyout(&enable, (void *)arg,
		    sizeof (int32_t), (mode & (int)FKIOCTL)))
			return (EFAULT);
		return (0);
	}
		/* from strioctl */
	case FIONREAD:
		/*
		 * Return number of bytes of data in all data messages
		 * in queue in "arg".
		 * For stream socket, amount of available data.
		 */
		if (so->so_state & SS_ACCEPTCONN) {
			intval = 0;
		} else {
			mutex_enter(&so->so_lock);
			intval = sdp_polldata(
			    (struct sdp_conn_struct_t *)so->so_proto_handle,
			    SDP_READ);
			mutex_exit(&so->so_lock);
		}
		if (so_copyout(&intval, (void *)arg, sizeof (intval),
		    (mode & (int)FKIOCTL)))
			return (EFAULT);
		return (0);
	default:
		return (EINVAL);
	}
}

/*
 * Check socktpi_poll() on why so_lock is not held in this function.
 */
static int
sosdp_poll(struct sonode *so, short events, int anyyet, short *reventsp,
    struct pollhead **phpp)
{
	short origevents = events;
	int so_state;

	so_state = so->so_state;

	ASSERT(so->so_version != SOV_STREAM);

	if (!(so_state & SS_ISCONNECTED) && (so->so_type == SOCK_STREAM)) {
		/*
		 * Not connected yet - turn off write side events
		 */
		events &= ~(POLLOUT|POLLWRBAND);
	}

	/*
	 * Check for errors
	 */
	if (so->so_error != 0 &&
	    ((POLLIN|POLLRDNORM|POLLOUT) & origevents) != 0) {
		*reventsp = (POLLIN|POLLRDNORM|POLLOUT) & origevents;
		goto done;
	}

	*reventsp = 0;
	if (so->so_type != SOCK_STREAM) {
		goto done;
	}

	/*
	 * Don't mark socket writable until TX queued data is below watermark.
	 */
	if (sdp_polldata((struct sdp_conn_struct_t *)so->so_proto_handle,
	    SDP_XMIT)) {
		*reventsp |= POLLOUT & events;
	}

	if (sdp_polldata((struct sdp_conn_struct_t *)so->so_proto_handle,
	    SDP_READ)) {
		*reventsp |= (POLLIN|POLLRDNORM) & events;
	}

	if ((so_state & SS_CANTRCVMORE) || (so->so_acceptq_len > 0)) {
		*reventsp |= (POLLIN|POLLRDNORM) & events;
	}

done:
	if ((*reventsp == 0 && !anyyet) || (events & POLLET)) {
		*phpp = &so->so_poll_list;
	}

	return (0);
}

/* ARGSUSED */
static int
sosdp_close(struct sonode *so, int flag, struct cred *cr)
{
	int error = 0;

	mutex_enter(&so->so_lock);
	so_lock_single(so);
	/*
	 * Need to set flags as there might be ops in progress on
	 * this socket.
	 *
	 * If socket already disconnected/disconnecting,
	 * don't send signal (again).
	 */
	soisdisconnected(so, 0);
	mutex_exit(&so->so_lock);

	/*
	 * Initiate connection shutdown.
	 */
	error = sdp_disconnect((struct sdp_conn_struct_t *)so->so_proto_handle,
	    flag);

	mutex_enter(&so->so_lock);
	so_unlock_single(so, SOLOCKED);
	so_notify_disconnected(so, B_FALSE, error);

	return (error);
}

/* ARGSUSED */
void
sosdp_fini(struct sonode *so, struct cred *cr)
{
	dprint(3, ("sosdp_fini: so:%p so_proto_handle:%p", (void *)so,
	    (void *)so->so_proto_handle));

	ASSERT(so->so_ops == &sosdp_sonodeops);

	if (so->so_proto_handle != NULL)
		sdp_close((struct sdp_conn_struct_t *)so->so_proto_handle);
	so->so_proto_handle = NULL;

	mutex_enter(&so->so_lock);

	so_acceptq_flush(so, B_TRUE);

	mutex_exit(&so->so_lock);

	sonode_fini(so);
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
	struct sonode *lso = parenthandle;
	struct sonode *nso;
	int error;

	ASSERT(lso->so_state & SS_ACCEPTCONN);
	ASSERT(lso->so_proto_handle != NULL); /* closed conn */
	ASSERT(lso->so_type == SOCK_STREAM);

	dprint(3, ("sosdp_newconn A: so:%p so_proto_handle:%p", (void *)lso,
	    (void *)lso->so_proto_handle));

	/*
	 * Check current # of queued conns against backlog
	 */
	if (lso->so_rcv_queued >= lso->so_backlog) {
		return (NULL);
	}

	nso = socket_newconn(lso, connind, NULL, SOCKET_NOSLEEP, &error);
	if (nso == NULL) {
		eprintsoline(lso, error);
		return (NULL);
	}

	dprint(2, ("sdp_stream_newconn: new %p\n", (void *)nso));

	(void) so_acceptq_enqueue(lso, nso);

	mutex_enter(&lso->so_lock);
	so_notify_newconn(lso);
	return (nso);
}

/*
 * For outgoing connections, the connection has been established.
 */
static void
sdp_sock_connected(void *handle)
{
	struct sonode *so = handle;

	ASSERT(so->so_type == SOCK_STREAM);
	dprint(3, ("sosdp_connected C: so:%p so_proto_handle:%p", (void *)so,
	    (void *)so->so_proto_handle));

	mutex_enter(&so->so_lock);
	ASSERT(so->so_proto_handle); /* closed conn */

	ASSERT(!(so->so_state & SS_ACCEPTCONN));
	soisconnected(so);

	so_notify_connected(so);
}

/*
 * Connection got disconnected. Either with an error, or through
 * normal handshake.
 */
static void
sdp_sock_disconnected(void *handle, int error)
{
	struct sonode *so = handle;

	ASSERT(so->so_type == SOCK_STREAM);
	dprint(2, ("sosdp_disconnected C: so:%p so_proto_handle:%p error:%d",
	    (void *)so, (void *)so->so_proto_handle, error));

	mutex_enter(&so->so_lock);
	ASSERT(so->so_proto_handle != NULL); /* closed conn */

	soisdisconnected(so, error);
	so_notify_disconnected(so, B_FALSE, error);
}

/*
 * Incoming data.
 */
/*ARGSUSED*/
static int
sdp_sock_recv(void *handle, mblk_t *mp, int flags)
{
	struct sonode *so = handle;

	ASSERT(so->so_type == SOCK_STREAM);

	mutex_enter(&so->so_lock);
	so_notify_data(so, 0);

	return (so->so_rcvbuf);
}

/*
 * TX queued data got acknowledged.
 */
static void
sdp_sock_xmitted(void *handle, int writeable)
{
	struct sonode *so = handle;

	dprint(4, ("sosdp_sock_xmitted: so:%p so_proto_handle:%p txq:%d",
	    (void *)so, (void *)so->so_proto_handle, writeable));
	mutex_enter(&so->so_lock);
	ASSERT(so->so_proto_handle != NULL); /* closed conn */


	/*
	 * Only do pollwakeup if the amount of queued data is less than
	 * watermark.
	 */
	if (!writeable) {
		so_notify_writable(so);
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
	struct sonode *so = handle;

	ASSERT(so->so_type == SOCK_STREAM);

	mutex_enter(&so->so_lock);

	ASSERT(so->so_proto_handle != NULL); /* closed conn */
	so_notify_oobsig(so);
}

/*
 * SDP notifies socket about receiving of conn close request from peer side.
 */
static void
sdp_sock_ordrel(void *handle)
{
	struct sonode *so = handle;

	ASSERT(so->so_type == SOCK_STREAM);

	dprint(4, ("sdp_sock_ordrel : so:%p, so_proto_handle:%p",
	    (void *)so, (void *)so->so_proto_handle));
	mutex_enter(&so->so_lock);
	socantrcvmore(so);
	so_notify_eof(so);
}

static void
sdp_sock_connfail(void *handle, int error)
{
	struct sonode *so = handle;

	dprint(3, ("sosdp_conn Failed: so:%p so_proto_handle:%p", (void *)so,
	    (void *)so->so_proto_handle));
	mutex_enter(&so->so_lock);
	ASSERT(so->so_proto_handle != NULL); /* closed conn */
	so->so_state &= ~(SS_ISCONNECTING|SS_ISCONNECTED|SS_ISDISCONNECTING);
	so->so_error = (ushort_t)error;
	mutex_exit(&so->so_lock);
	cv_broadcast(&so->so_state_cv);
}
