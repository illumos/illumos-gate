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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/* This file contains all TCP kernel socket related functions. */

#include <sys/types.h>
#include <sys/strlog.h>
#include <sys/policy.h>
#include <sys/sockio.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/squeue_impl.h>
#include <sys/squeue.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/timod.h>
#include <sys/tpicommon.h>
#include <sys/socketvar.h>

#include <inet/common.h>
#include <inet/proto_set.h>
#include <inet/ip.h>
#include <inet/tcp.h>
#include <inet/tcp_impl.h>

static void	tcp_activate(sock_lower_handle_t, sock_upper_handle_t,
		    sock_upcalls_t *, int, cred_t *);
static int	tcp_accept(sock_lower_handle_t, sock_lower_handle_t,
		    sock_upper_handle_t, cred_t *);
static int	tcp_bind(sock_lower_handle_t, struct sockaddr *,
		    socklen_t, cred_t *);
static int	tcp_listen(sock_lower_handle_t, int, cred_t *);
static int	tcp_connect(sock_lower_handle_t, const struct sockaddr *,
		    socklen_t, sock_connid_t *, cred_t *);
static int	tcp_getpeername(sock_lower_handle_t, struct sockaddr *,
		    socklen_t *, cred_t *);
static int	tcp_getsockname(sock_lower_handle_t, struct sockaddr *,
		    socklen_t *, cred_t *);
static int	tcp_getsockopt(sock_lower_handle_t, int, int, void *,
		    socklen_t *, cred_t *);
static int	tcp_setsockopt(sock_lower_handle_t, int, int, const void *,
		    socklen_t, cred_t *);
static int	tcp_sendmsg(sock_lower_handle_t, mblk_t *, struct nmsghdr *,
		    cred_t *);
static int	tcp_shutdown(sock_lower_handle_t, int, cred_t *);
static void	tcp_clr_flowctrl(sock_lower_handle_t);
static int	tcp_ioctl(sock_lower_handle_t, int, intptr_t, int, int32_t *,
		    cred_t *);
static int	tcp_close(sock_lower_handle_t, int, cred_t *);

sock_downcalls_t sock_tcp_downcalls = {
	tcp_activate,
	tcp_accept,
	tcp_bind,
	tcp_listen,
	tcp_connect,
	tcp_getpeername,
	tcp_getsockname,
	tcp_getsockopt,
	tcp_setsockopt,
	tcp_sendmsg,
	NULL,
	NULL,
	NULL,
	tcp_shutdown,
	tcp_clr_flowctrl,
	tcp_ioctl,
	tcp_close,
};

/* ARGSUSED */
static void
tcp_activate(sock_lower_handle_t proto_handle, sock_upper_handle_t sock_handle,
    sock_upcalls_t *sock_upcalls, int flags, cred_t *cr)
{
	conn_t *connp = (conn_t *)proto_handle;
	struct sock_proto_props sopp;
	extern struct module_info tcp_rinfo;

	ASSERT(connp->conn_upper_handle == NULL);

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	sopp.sopp_flags = SOCKOPT_RCVHIWAT | SOCKOPT_RCVLOWAT |
	    SOCKOPT_MAXPSZ | SOCKOPT_MAXBLK | SOCKOPT_RCVTIMER |
	    SOCKOPT_RCVTHRESH | SOCKOPT_MAXADDRLEN | SOCKOPT_MINPSZ;

	sopp.sopp_rxhiwat = SOCKET_RECVHIWATER;
	sopp.sopp_rxlowat = SOCKET_RECVLOWATER;
	sopp.sopp_maxpsz = INFPSZ;
	sopp.sopp_maxblk = INFPSZ;
	sopp.sopp_rcvtimer = SOCKET_TIMER_INTERVAL;
	sopp.sopp_rcvthresh = SOCKET_RECVHIWATER >> 3;
	sopp.sopp_maxaddrlen = sizeof (sin6_t);
	sopp.sopp_minpsz = (tcp_rinfo.mi_minpsz == 1) ? 0 :
	    tcp_rinfo.mi_minpsz;

	connp->conn_upcalls = sock_upcalls;
	connp->conn_upper_handle = sock_handle;

	ASSERT(connp->conn_rcvbuf != 0 &&
	    connp->conn_rcvbuf == connp->conn_tcp->tcp_rwnd);
	(*sock_upcalls->su_set_proto_props)(sock_handle, &sopp);
}

/*ARGSUSED*/
static int
tcp_accept(sock_lower_handle_t lproto_handle,
    sock_lower_handle_t eproto_handle, sock_upper_handle_t sock_handle,
    cred_t *cr)
{
	conn_t *lconnp, *econnp;
	tcp_t *listener, *eager;

	/*
	 * KSSL can move a socket from one listener to another, in which
	 * case `lproto_handle' points to the new listener. To ensure that
	 * the original listener is used the information is obtained from
	 * the eager.
	 */
	econnp = (conn_t *)eproto_handle;
	eager = econnp->conn_tcp;
	ASSERT(IPCL_IS_NONSTR(econnp));
	ASSERT(eager->tcp_listener != NULL);
	listener = eager->tcp_listener;
	lconnp = (conn_t *)listener->tcp_connp;
	ASSERT(listener->tcp_state == TCPS_LISTEN);
	ASSERT(lconnp->conn_upper_handle != NULL);

	/*
	 * It is possible for the accept thread to race with the thread that
	 * made the su_newconn upcall in tcp_newconn_notify. Both
	 * tcp_newconn_notify and tcp_accept require that conn_upper_handle
	 * and conn_upcalls be set before returning, so they both write to
	 * them. However, we're guaranteed that the value written is the same
	 * for both threads.
	 */
	ASSERT(econnp->conn_upper_handle == NULL ||
	    econnp->conn_upper_handle == sock_handle);
	ASSERT(econnp->conn_upcalls == NULL ||
	    econnp->conn_upcalls == lconnp->conn_upcalls);
	econnp->conn_upper_handle = sock_handle;
	econnp->conn_upcalls = lconnp->conn_upcalls;

	ASSERT(econnp->conn_netstack ==
	    listener->tcp_connp->conn_netstack);
	ASSERT(eager->tcp_tcps == listener->tcp_tcps);

	/*
	 * We should have a minimum of 2 references on the conn at this
	 * point. One for TCP and one for the newconn notification
	 * (which is now taken over by IP). In the normal case we would
	 * also have another reference (making a total of 3) for the conn
	 * being in the classifier hash list. However the eager could have
	 * received an RST subsequently and tcp_closei_local could have
	 * removed the eager from the classifier hash list, hence we can't
	 * assert that reference.
	 */
	ASSERT(econnp->conn_ref >= 2);

	mutex_enter(&listener->tcp_eager_lock);
	/*
	 * Non-STREAMS listeners never defer the notification of new
	 * connections.
	 */
	ASSERT(!listener->tcp_eager_prev_q0->tcp_conn_def_q0);
	tcp_eager_unlink(eager);
	mutex_exit(&listener->tcp_eager_lock);
	CONN_DEC_REF(listener->tcp_connp);

	return ((eager->tcp_state < TCPS_ESTABLISHED) ? ECONNABORTED : 0);
}

static int
tcp_bind(sock_lower_handle_t proto_handle, struct sockaddr *sa,
    socklen_t len, cred_t *cr)
{
	int 		error;
	conn_t		*connp = (conn_t *)proto_handle;

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);
	ASSERT(connp->conn_upper_handle != NULL);

	error = squeue_synch_enter(connp, NULL);
	if (error != 0) {
		/* failed to enter */
		return (ENOSR);
	}

	/* binding to a NULL address really means unbind */
	if (sa == NULL) {
		if (connp->conn_tcp->tcp_state < TCPS_LISTEN)
			error = tcp_do_unbind(connp);
		else
			error = EINVAL;
	} else {
		error = tcp_do_bind(connp, sa, len, cr, B_TRUE);
	}

	squeue_synch_exit(connp);

	if (error < 0) {
		if (error == -TOUTSTATE)
			error = EINVAL;
		else
			error = proto_tlitosyserr(-error);
	}

	return (error);
}

/* ARGSUSED */
static int
tcp_listen(sock_lower_handle_t proto_handle, int backlog, cred_t *cr)
{
	conn_t	*connp = (conn_t *)proto_handle;
	tcp_t	*tcp = connp->conn_tcp;
	int 	error;

	ASSERT(connp->conn_upper_handle != NULL);

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	error = squeue_synch_enter(connp, NULL);
	if (error != 0) {
		/* failed to enter */
		return (ENOBUFS);
	}

	error = tcp_do_listen(connp, NULL, 0, backlog, cr, B_FALSE);
	if (error == 0) {
		/*
		 * sockfs needs to know what's the maximum number of socket
		 * that can be queued on the listener.
		 */
		(*connp->conn_upcalls->su_opctl)(connp->conn_upper_handle,
		    SOCK_OPCTL_ENAB_ACCEPT,
		    (uintptr_t)(tcp->tcp_conn_req_max +
		    tcp->tcp_tcps->tcps_conn_req_max_q0));
	} else if (error < 0) {
		if (error == -TOUTSTATE)
			error = EINVAL;
		else
			error = proto_tlitosyserr(-error);
	}
	squeue_synch_exit(connp);
	return (error);
}

static int
tcp_connect(sock_lower_handle_t proto_handle, const struct sockaddr *sa,
    socklen_t len, sock_connid_t *id, cred_t *cr)
{
	conn_t		*connp = (conn_t *)proto_handle;
	int		error;

	ASSERT(connp->conn_upper_handle != NULL);

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	error = proto_verify_ip_addr(connp->conn_family, sa, len);
	if (error != 0) {
		return (error);
	}

	error = squeue_synch_enter(connp, NULL);
	if (error != 0) {
		/* failed to enter */
		return (ENOSR);
	}

	/*
	 * TCP supports quick connect, so no need to do an implicit bind
	 */
	error = tcp_do_connect(connp, sa, len, cr, curproc->p_pid);
	if (error == 0) {
		*id = connp->conn_tcp->tcp_connid;
	} else if (error < 0) {
		if (error == -TOUTSTATE) {
			switch (connp->conn_tcp->tcp_state) {
			case TCPS_SYN_SENT:
				error = EALREADY;
				break;
			case TCPS_ESTABLISHED:
				error = EISCONN;
				break;
			case TCPS_LISTEN:
				error = EOPNOTSUPP;
				break;
			default:
				error = EINVAL;
				break;
			}
		} else {
			error = proto_tlitosyserr(-error);
		}
	}

	if (connp->conn_tcp->tcp_loopback) {
		struct sock_proto_props sopp;

		sopp.sopp_flags = SOCKOPT_LOOPBACK;
		sopp.sopp_loopback = B_TRUE;

		(*connp->conn_upcalls->su_set_proto_props)(
		    connp->conn_upper_handle, &sopp);
	}
done:
	squeue_synch_exit(connp);

	return ((error == 0) ? EINPROGRESS : error);
}

/* ARGSUSED3 */
static int
tcp_getpeername(sock_lower_handle_t proto_handle, struct sockaddr *addr,
    socklen_t *addrlenp, cred_t *cr)
{
	conn_t	*connp = (conn_t *)proto_handle;
	tcp_t	*tcp = connp->conn_tcp;

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	ASSERT(tcp != NULL);
	if (tcp->tcp_state < TCPS_SYN_RCVD)
		return (ENOTCONN);

	return (conn_getpeername(connp, addr, addrlenp));
}

/* ARGSUSED3 */
static int
tcp_getsockname(sock_lower_handle_t proto_handle, struct sockaddr *addr,
    socklen_t *addrlenp, cred_t *cr)
{
	conn_t	*connp = (conn_t *)proto_handle;

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	return (conn_getsockname(connp, addr, addrlenp));
}

/* returns UNIX error, the optlen is a value-result arg */
static int
tcp_getsockopt(sock_lower_handle_t proto_handle, int level, int option_name,
    void *optvalp, socklen_t *optlen, cred_t *cr)
{
	conn_t		*connp = (conn_t *)proto_handle;
	int		error;
	t_uscalar_t	max_optbuf_len;
	void		*optvalp_buf;
	int		len;

	ASSERT(connp->conn_upper_handle != NULL);

	error = proto_opt_check(level, option_name, *optlen, &max_optbuf_len,
	    tcp_opt_obj.odb_opt_des_arr,
	    tcp_opt_obj.odb_opt_arr_cnt,
	    B_FALSE, B_TRUE, cr);
	if (error != 0) {
		if (error < 0) {
			error = proto_tlitosyserr(-error);
		}
		return (error);
	}

	optvalp_buf = kmem_alloc(max_optbuf_len, KM_SLEEP);

	error = squeue_synch_enter(connp, NULL);
	if (error == ENOMEM) {
		kmem_free(optvalp_buf, max_optbuf_len);
		return (ENOMEM);
	}

	len = tcp_opt_get(connp, level, option_name, optvalp_buf);
	squeue_synch_exit(connp);

	if (len == -1) {
		kmem_free(optvalp_buf, max_optbuf_len);
		return (EINVAL);
	}

	/*
	 * update optlen and copy option value
	 */
	t_uscalar_t size = MIN(len, *optlen);

	bcopy(optvalp_buf, optvalp, size);
	bcopy(&size, optlen, sizeof (size));

	kmem_free(optvalp_buf, max_optbuf_len);
	return (0);
}

static int
tcp_setsockopt(sock_lower_handle_t proto_handle, int level, int option_name,
    const void *optvalp, socklen_t optlen, cred_t *cr)
{
	conn_t		*connp = (conn_t *)proto_handle;
	int		error;

	ASSERT(connp->conn_upper_handle != NULL);
	/*
	 * Entering the squeue synchronously can result in a context switch,
	 * which can cause a rather sever performance degradation. So we try to
	 * handle whatever options we can without entering the squeue.
	 */
	if (level == IPPROTO_TCP) {
		switch (option_name) {
		case TCP_NODELAY:
			if (optlen != sizeof (int32_t))
				return (EINVAL);
			mutex_enter(&connp->conn_tcp->tcp_non_sq_lock);
			connp->conn_tcp->tcp_naglim = *(int *)optvalp ? 1 :
			    connp->conn_tcp->tcp_mss;
			mutex_exit(&connp->conn_tcp->tcp_non_sq_lock);
			return (0);
		default:
			break;
		}
	}

	error = squeue_synch_enter(connp, NULL);
	if (error == ENOMEM) {
		return (ENOMEM);
	}

	error = proto_opt_check(level, option_name, optlen, NULL,
	    tcp_opt_obj.odb_opt_des_arr,
	    tcp_opt_obj.odb_opt_arr_cnt,
	    B_TRUE, B_FALSE, cr);

	if (error != 0) {
		if (error < 0) {
			error = proto_tlitosyserr(-error);
		}
		squeue_synch_exit(connp);
		return (error);
	}

	error = tcp_opt_set(connp, SETFN_OPTCOM_NEGOTIATE, level, option_name,
	    optlen, (uchar_t *)optvalp, (uint_t *)&optlen, (uchar_t *)optvalp,
	    NULL, cr);
	squeue_synch_exit(connp);

	ASSERT(error >= 0);

	return (error);
}

/* ARGSUSED */
static int
tcp_sendmsg(sock_lower_handle_t proto_handle, mblk_t *mp, struct nmsghdr *msg,
    cred_t *cr)
{
	tcp_t		*tcp;
	uint32_t	msize;
	conn_t *connp = (conn_t *)proto_handle;
	int32_t		tcpstate;

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	ASSERT(connp->conn_ref >= 2);
	ASSERT(connp->conn_upper_handle != NULL);

	if (msg->msg_controllen != 0) {
		freemsg(mp);
		return (EOPNOTSUPP);
	}

	switch (DB_TYPE(mp)) {
	case M_DATA:
		tcp = connp->conn_tcp;
		ASSERT(tcp != NULL);

		tcpstate = tcp->tcp_state;
		if (tcpstate < TCPS_ESTABLISHED) {
			freemsg(mp);
			/*
			 * We return ENOTCONN if the endpoint is trying to
			 * connect or has never been connected, and EPIPE if it
			 * has been disconnected. The connection id helps us
			 * distinguish between the last two cases.
			 */
			return ((tcpstate == TCPS_SYN_SENT) ? ENOTCONN :
			    ((tcp->tcp_connid > 0) ? EPIPE : ENOTCONN));
		} else if (tcpstate > TCPS_CLOSE_WAIT) {
			freemsg(mp);
			return (EPIPE);
		}

		msize = msgdsize(mp);

		mutex_enter(&tcp->tcp_non_sq_lock);
		tcp->tcp_squeue_bytes += msize;
		/*
		 * Squeue Flow Control
		 */
		if (TCP_UNSENT_BYTES(tcp) > connp->conn_sndbuf) {
			tcp_setqfull(tcp);
		}
		mutex_exit(&tcp->tcp_non_sq_lock);

		/*
		 * The application may pass in an address in the msghdr, but
		 * we ignore the address on connection-oriented sockets.
		 * Just like BSD this code does not generate an error for
		 * TCP (a CONNREQUIRED socket) when sending to an address
		 * passed in with sendto/sendmsg. Instead the data is
		 * delivered on the connection as if no address had been
		 * supplied.
		 */
		CONN_INC_REF(connp);

		if (msg->msg_flags & MSG_OOB) {
			SQUEUE_ENTER_ONE(connp->conn_sqp, mp, tcp_output_urgent,
			    connp, NULL, tcp_squeue_flag, SQTAG_TCP_OUTPUT);
		} else {
			SQUEUE_ENTER_ONE(connp->conn_sqp, mp, tcp_output,
			    connp, NULL, tcp_squeue_flag, SQTAG_TCP_OUTPUT);
		}

		return (0);

	default:
		ASSERT(0);
	}

	freemsg(mp);
	return (0);
}

/* ARGSUSED */
static int
tcp_shutdown(sock_lower_handle_t proto_handle, int how, cred_t *cr)
{
	conn_t  *connp = (conn_t *)proto_handle;
	tcp_t   *tcp = connp->conn_tcp;

	ASSERT(connp->conn_upper_handle != NULL);

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	/*
	 * X/Open requires that we check the connected state.
	 */
	if (tcp->tcp_state < TCPS_SYN_SENT)
		return (ENOTCONN);

	/* shutdown the send side */
	if (how != SHUT_RD) {
		mblk_t *bp;

		bp = allocb_wait(0, BPRI_HI, STR_NOSIG, NULL);
		CONN_INC_REF(connp);
		SQUEUE_ENTER_ONE(connp->conn_sqp, bp, tcp_shutdown_output,
		    connp, NULL, SQ_NODRAIN, SQTAG_TCP_SHUTDOWN_OUTPUT);

		(*connp->conn_upcalls->su_opctl)(connp->conn_upper_handle,
		    SOCK_OPCTL_SHUT_SEND, 0);
	}

	/* shutdown the recv side */
	if (how != SHUT_WR)
		(*connp->conn_upcalls->su_opctl)(connp->conn_upper_handle,
		    SOCK_OPCTL_SHUT_RECV, 0);

	return (0);
}

static void
tcp_clr_flowctrl(sock_lower_handle_t proto_handle)
{
	conn_t  *connp = (conn_t *)proto_handle;
	tcp_t	*tcp = connp->conn_tcp;
	mblk_t *mp;
	int error;

	ASSERT(connp->conn_upper_handle != NULL);

	/*
	 * If tcp->tcp_rsrv_mp == NULL, it means that tcp_clr_flowctrl()
	 * is currently running.
	 */
	mutex_enter(&tcp->tcp_rsrv_mp_lock);
	if ((mp = tcp->tcp_rsrv_mp) == NULL) {
		mutex_exit(&tcp->tcp_rsrv_mp_lock);
		return;
	}
	tcp->tcp_rsrv_mp = NULL;
	mutex_exit(&tcp->tcp_rsrv_mp_lock);

	error = squeue_synch_enter(connp, mp);
	ASSERT(error == 0);

	mutex_enter(&tcp->tcp_rsrv_mp_lock);
	tcp->tcp_rsrv_mp = mp;
	mutex_exit(&tcp->tcp_rsrv_mp_lock);

	if (tcp->tcp_fused) {
		tcp_fuse_backenable(tcp);
	} else {
		tcp->tcp_rwnd = connp->conn_rcvbuf;
		/*
		 * Send back a window update immediately if TCP is above
		 * ESTABLISHED state and the increase of the rcv window
		 * that the other side knows is at least 1 MSS after flow
		 * control is lifted.
		 */
		if (tcp->tcp_state >= TCPS_ESTABLISHED &&
		    tcp_rwnd_reopen(tcp) == TH_ACK_NEEDED) {
			tcp_xmit_ctl(NULL, tcp,
			    (tcp->tcp_swnd == 0) ? tcp->tcp_suna :
			    tcp->tcp_snxt, tcp->tcp_rnxt, TH_ACK);
		}
	}

	squeue_synch_exit(connp);
}

/* ARGSUSED */
static int
tcp_ioctl(sock_lower_handle_t proto_handle, int cmd, intptr_t arg,
    int mode, int32_t *rvalp, cred_t *cr)
{
	conn_t  	*connp = (conn_t *)proto_handle;
	int		error;

	ASSERT(connp->conn_upper_handle != NULL);

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	/*
	 * If we don't have a helper stream then create one.
	 * ip_create_helper_stream takes care of locking the conn_t,
	 * so this check for NULL is just a performance optimization.
	 */
	if (connp->conn_helper_info == NULL) {
		tcp_stack_t *tcps = connp->conn_tcp->tcp_tcps;

		/*
		 * Create a helper stream for non-STREAMS socket.
		 */
		error = ip_create_helper_stream(connp, tcps->tcps_ldi_ident);
		if (error != 0) {
			ip0dbg(("tcp_ioctl: create of IP helper stream "
			    "failed %d\n", error));
			return (error);
		}
	}

	switch (cmd) {
		case ND_SET:
		case ND_GET:
		case _SIOCSOCKFALLBACK:
		case TCP_IOC_ABORT_CONN:
		case TI_GETPEERNAME:
		case TI_GETMYNAME:
			ip1dbg(("tcp_ioctl: cmd 0x%x on non streams socket",
			    cmd));
			error = EINVAL;
			break;
		default:
			/*
			 * If the conn is not closing, pass on to IP using
			 * helper stream. Bump the ioctlref to prevent tcp_close
			 * from closing the rq/wq out from underneath the ioctl
			 * if it ends up queued or aborted/interrupted.
			 */
			mutex_enter(&connp->conn_lock);
			if (connp->conn_state_flags & (CONN_CLOSING)) {
				mutex_exit(&connp->conn_lock);
				error = EINVAL;
				break;
			}
			CONN_INC_IOCTLREF_LOCKED(connp);
			error = ldi_ioctl(connp->conn_helper_info->iphs_handle,
			    cmd, arg, mode, cr, rvalp);
			CONN_DEC_IOCTLREF(connp);
			break;
	}
	return (error);
}

/* ARGSUSED */
static int
tcp_close(sock_lower_handle_t proto_handle, int flags, cred_t *cr)
{
	conn_t *connp = (conn_t *)proto_handle;

	ASSERT(connp->conn_upper_handle != NULL);

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	tcp_close_common(connp, flags);

	ip_free_helper_stream(connp);

	/*
	 * Drop IP's reference on the conn. This is the last reference
	 * on the connp if the state was less than established. If the
	 * connection has gone into timewait state, then we will have
	 * one ref for the TCP and one more ref (total of two) for the
	 * classifier connected hash list (a timewait connections stays
	 * in connected hash till closed).
	 *
	 * We can't assert the references because there might be other
	 * transient reference places because of some walkers or queued
	 * packets in squeue for the timewait state.
	 */
	CONN_DEC_REF(connp);

	/*
	 * EINPROGRESS tells sockfs to wait for a 'closed' upcall before
	 * freeing the socket.
	 */
	return (EINPROGRESS);
}

/* ARGSUSED */
sock_lower_handle_t
tcp_create(int family, int type, int proto, sock_downcalls_t **sock_downcalls,
    uint_t *smodep, int *errorp, int flags, cred_t *credp)
{
	conn_t		*connp;
	boolean_t	isv6 = family == AF_INET6;

	if (type != SOCK_STREAM || (family != AF_INET && family != AF_INET6) ||
	    (proto != 0 && proto != IPPROTO_TCP)) {
		*errorp = EPROTONOSUPPORT;
		return (NULL);
	}

	connp = tcp_create_common(credp, isv6, B_TRUE, errorp);
	if (connp == NULL) {
		return (NULL);
	}

	/*
	 * Put the ref for TCP. Ref for IP was already put
	 * by ipcl_conn_create. Also make the conn_t globally
	 * visible to walkers
	 */
	mutex_enter(&connp->conn_lock);
	CONN_INC_REF_LOCKED(connp);
	ASSERT(connp->conn_ref == 2);
	connp->conn_state_flags &= ~CONN_INCIPIENT;

	connp->conn_flags |= IPCL_NONSTR;
	mutex_exit(&connp->conn_lock);

	ASSERT(errorp != NULL);
	*errorp = 0;
	*sock_downcalls = &sock_tcp_downcalls;
	*smodep = SM_CONNREQUIRED | SM_EXDATA | SM_ACCEPTSUPP |
	    SM_SENDFILESUPP;

	return ((sock_lower_handle_t)connp);
}

/*
 * tcp_fallback
 *
 * A direct socket is falling back to using STREAMS. The queue
 * that is being passed down was created using tcp_open() with
 * the SO_FALLBACK flag set. As a result, the queue is not
 * associated with a conn, and the q_ptrs instead contain the
 * dev and minor area that should be used.
 *
 * The 'issocket' flag indicates whether the FireEngine
 * optimizations should be used. The common case would be that
 * optimizations are enabled, and they might be subsequently
 * disabled using the _SIOCSOCKFALLBACK ioctl.
 */

/*
 * An active connection is falling back to TPI. Gather all the information
 * required by the STREAM head and TPI sonode and send it up.
 */
static void
tcp_fallback_noneager(tcp_t *tcp, mblk_t *stropt_mp, queue_t *q,
    boolean_t issocket, so_proto_quiesced_cb_t quiesced_cb,
    sock_quiesce_arg_t *arg)
{
	conn_t			*connp = tcp->tcp_connp;
	struct stroptions	*stropt;
	struct T_capability_ack tca;
	struct sockaddr_in6	laddr, faddr;
	socklen_t 		laddrlen, faddrlen;
	short			opts;
	int			error;
	mblk_t			*mp, *mpnext;

	connp->conn_dev = (dev_t)RD(q)->q_ptr;
	connp->conn_minor_arena = WR(q)->q_ptr;

	RD(q)->q_ptr = WR(q)->q_ptr = connp;

	connp->conn_rq = RD(q);
	connp->conn_wq = WR(q);

	WR(q)->q_qinfo = &tcp_sock_winit;

	if (!issocket)
		tcp_use_pure_tpi(tcp);

	/*
	 * free the helper stream
	 */
	ip_free_helper_stream(connp);

	/*
	 * Notify the STREAM head about options
	 */
	DB_TYPE(stropt_mp) = M_SETOPTS;
	stropt = (struct stroptions *)stropt_mp->b_rptr;
	stropt_mp->b_wptr += sizeof (struct stroptions);
	stropt->so_flags = SO_HIWAT | SO_WROFF | SO_MAXBLK;

	stropt->so_wroff = connp->conn_ht_iphc_len + (tcp->tcp_loopback ? 0 :
	    tcp->tcp_tcps->tcps_wroff_xtra);
	if (tcp->tcp_snd_sack_ok)
		stropt->so_wroff += TCPOPT_MAX_SACK_LEN;
	stropt->so_hiwat = connp->conn_rcvbuf;
	stropt->so_maxblk = tcp_maxpsz_set(tcp, B_FALSE);

	putnext(RD(q), stropt_mp);

	/*
	 * Collect the information needed to sync with the sonode
	 */
	tcp_do_capability_ack(tcp, &tca, TC1_INFO|TC1_ACCEPTOR_ID);

	laddrlen = faddrlen = sizeof (sin6_t);
	(void) tcp_getsockname((sock_lower_handle_t)connp,
	    (struct sockaddr *)&laddr, &laddrlen, CRED());
	error = tcp_getpeername((sock_lower_handle_t)connp,
	    (struct sockaddr *)&faddr, &faddrlen, CRED());
	if (error != 0)
		faddrlen = 0;

	opts = 0;
	if (connp->conn_oobinline)
		opts |= SO_OOBINLINE;
	if (connp->conn_ixa->ixa_flags & IXAF_DONTROUTE)
		opts |= SO_DONTROUTE;

	/*
	 * Notify the socket that the protocol is now quiescent,
	 * and it's therefore safe move data from the socket
	 * to the stream head.
	 */
	mp = (*quiesced_cb)(connp->conn_upper_handle, arg, &tca,
	    (struct sockaddr *)&laddr, laddrlen,
	    (struct sockaddr *)&faddr, faddrlen, opts);

	while (mp != NULL) {
		mpnext = mp->b_next;
		tcp->tcp_rcv_list = mp->b_next;
		mp->b_next = NULL;
		putnext(q, mp);
		mp = mpnext;
	}
	ASSERT(tcp->tcp_rcv_last_head == NULL);
	ASSERT(tcp->tcp_rcv_last_tail == NULL);
	ASSERT(tcp->tcp_rcv_cnt == 0);

	/*
	 * All eagers in q0 are marked as being non-STREAM, so they will
	 * make su_newconn upcalls when the handshake completes, which
	 * will fail (resulting in the conn being closed). So we just blow
	 * off everything in q0 instead of waiting for the inevitable.
	 */
	if (tcp->tcp_conn_req_cnt_q0 != 0)
		tcp_eager_cleanup(tcp, B_TRUE);
}

/*
 * An eager is falling back to TPI. All we have to do is send
 * up a T_CONN_IND.
 */
static void
tcp_fallback_eager(tcp_t *eager, boolean_t issocket,
    so_proto_quiesced_cb_t quiesced_cb, sock_quiesce_arg_t *arg)
{
	conn_t *connp = eager->tcp_connp;
	tcp_t *listener = eager->tcp_listener;
	mblk_t *mp;

	ASSERT(listener != NULL);

	/*
	 * Notify the socket that the protocol is now quiescent,
	 * and it's therefore safe move data from the socket
	 * to tcp's rcv queue.
	 */
	mp = (*quiesced_cb)(connp->conn_upper_handle, arg, NULL, NULL, 0,
	    NULL, 0, 0);

	if (mp != NULL) {
		ASSERT(eager->tcp_rcv_cnt == 0);

		eager->tcp_rcv_list = mp;
		eager->tcp_rcv_cnt = msgdsize(mp);
		while (mp->b_next != NULL) {
			mp = mp->b_next;
			eager->tcp_rcv_cnt += msgdsize(mp);
		}
		eager->tcp_rcv_last_head = mp;
		while (mp->b_cont)
			mp = mp->b_cont;
		eager->tcp_rcv_last_tail = mp;
		if (eager->tcp_rcv_cnt > eager->tcp_rwnd)
			eager->tcp_rwnd = 0;
		else
			eager->tcp_rwnd -= eager->tcp_rcv_cnt;
	}

	if (!issocket)
		eager->tcp_issocket = B_FALSE;
	/*
	 * The stream for this eager does not yet exist, so mark it as
	 * being detached.
	 */
	eager->tcp_detached = B_TRUE;
	eager->tcp_hard_binding = B_TRUE;
	connp->conn_rq = listener->tcp_connp->conn_rq;
	connp->conn_wq = listener->tcp_connp->conn_wq;

	/* Send up the connection indication */
	mp = eager->tcp_conn.tcp_eager_conn_ind;
	ASSERT(mp != NULL);
	eager->tcp_conn.tcp_eager_conn_ind = NULL;

	/*
	 * TLI/XTI applications will get confused by
	 * sending eager as an option since it violates
	 * the option semantics. So remove the eager as
	 * option since TLI/XTI app doesn't need it anyway.
	 */
	if (!issocket) {
		struct T_conn_ind *conn_ind;

		conn_ind = (struct T_conn_ind *)mp->b_rptr;
		conn_ind->OPT_length = 0;
		conn_ind->OPT_offset = 0;
	}

	/*
	 * Sockfs guarantees that the listener will not be closed
	 * during fallback. So we can safely use the listener's queue.
	 */
	putnext(listener->tcp_connp->conn_rq, mp);
}


int
tcp_fallback(sock_lower_handle_t proto_handle, queue_t *q,
    boolean_t direct_sockfs, so_proto_quiesced_cb_t quiesced_cb,
    sock_quiesce_arg_t *arg)
{
	tcp_t			*tcp;
	conn_t 			*connp = (conn_t *)proto_handle;
	int			error;
	mblk_t			*stropt_mp;
	mblk_t			*ordrel_mp;

	tcp = connp->conn_tcp;

	stropt_mp = allocb_wait(sizeof (struct stroptions), BPRI_HI, STR_NOSIG,
	    NULL);

	/* Pre-allocate the T_ordrel_ind mblk. */
	ASSERT(tcp->tcp_ordrel_mp == NULL);
	ordrel_mp = allocb_wait(sizeof (struct T_ordrel_ind), BPRI_HI,
	    STR_NOSIG, NULL);
	ordrel_mp->b_datap->db_type = M_PROTO;
	((struct T_ordrel_ind *)ordrel_mp->b_rptr)->PRIM_type = T_ORDREL_IND;
	ordrel_mp->b_wptr += sizeof (struct T_ordrel_ind);

	/*
	 * Enter the squeue so that no new packets can come in
	 */
	error = squeue_synch_enter(connp, NULL);
	if (error != 0) {
		/* failed to enter, free all the pre-allocated messages. */
		freeb(stropt_mp);
		freeb(ordrel_mp);
		return (ENOMEM);
	}

	/*
	 * Both endpoints must be of the same type (either STREAMS or
	 * non-STREAMS) for fusion to be enabled. So if we are fused,
	 * we have to unfuse.
	 */
	if (tcp->tcp_fused)
		tcp_unfuse(tcp);

	if (tcp->tcp_listener != NULL) {
		/* The eager will deal with opts when accept() is called */
		freeb(stropt_mp);
		tcp_fallback_eager(tcp, direct_sockfs, quiesced_cb, arg);
	} else {
		tcp_fallback_noneager(tcp, stropt_mp, q, direct_sockfs,
		    quiesced_cb, arg);
	}

	/*
	 * No longer a direct socket
	 *
	 * Note that we intentionally leave the upper_handle and upcalls
	 * intact, since eagers may still be using them.
	 */
	connp->conn_flags &= ~IPCL_NONSTR;
	tcp->tcp_ordrel_mp = ordrel_mp;

	/*
	 * There should be atleast two ref's (IP + TCP)
	 */
	ASSERT(connp->conn_ref >= 2);
	squeue_synch_exit(connp);

	return (0);
}

/*
 * Notifies a non-STREAMS based listener about a new connection. This
 * function is executed on the *eager*'s squeue once the 3 way handshake
 * has completed. Note that the behavior differs from STREAMS, where the
 * T_CONN_IND is sent up by tcp_send_conn_ind() while on the *listener*'s
 * squeue.
 *
 * Returns B_TRUE if the notification succeeded and an upper handle was
 * obtained. `tcp' should be closed on failure.
 */
boolean_t
tcp_newconn_notify(tcp_t *tcp, ip_recv_attr_t *ira)
{
	tcp_t *listener = tcp->tcp_listener;
	conn_t *lconnp = listener->tcp_connp;
	conn_t *econnp = tcp->tcp_connp;
	tcp_t *tail;
	ipaddr_t *addr_cache;
	sock_upper_handle_t upper;
	struct sock_proto_props sopp;

	mutex_enter(&listener->tcp_eager_lock);
	/*
	 * Take the eager out, if it is in the list of droppable eagers
	 * as we are here because the 3W handshake is over.
	 */
	MAKE_UNDROPPABLE(tcp);
	/*
	 * The eager already has an extra ref put in tcp_input_data
	 * so that it stays till accept comes back even though it
	 * might get into TCPS_CLOSED as a result of a TH_RST etc.
	 */
	ASSERT(listener->tcp_conn_req_cnt_q0 > 0);
	listener->tcp_conn_req_cnt_q0--;
	listener->tcp_conn_req_cnt_q++;

	/* Move from SYN_RCVD to ESTABLISHED list  */
	tcp->tcp_eager_next_q0->tcp_eager_prev_q0 = tcp->tcp_eager_prev_q0;
	tcp->tcp_eager_prev_q0->tcp_eager_next_q0 = tcp->tcp_eager_next_q0;
	tcp->tcp_eager_prev_q0 = NULL;
	tcp->tcp_eager_next_q0 = NULL;

	/*
	 * Insert at end of the queue because connections are accepted
	 * in chronological order. Leaving the older connections at front
	 * of the queue helps reducing search time.
	 */
	tail = listener->tcp_eager_last_q;
	if (tail != NULL)
		tail->tcp_eager_next_q = tcp;
	else
		listener->tcp_eager_next_q = tcp;
	listener->tcp_eager_last_q = tcp;
	tcp->tcp_eager_next_q = NULL;

	/* we have timed out before */
	if (tcp->tcp_syn_rcvd_timeout != 0) {
		tcp->tcp_syn_rcvd_timeout = 0;
		listener->tcp_syn_rcvd_timeout--;
		if (listener->tcp_syn_defense &&
		    listener->tcp_syn_rcvd_timeout <=
		    (listener->tcp_tcps->tcps_conn_req_max_q0 >> 5) &&
		    10*MINUTES < TICK_TO_MSEC(ddi_get_lbolt64() -
		    listener->tcp_last_rcv_lbolt)) {
			/*
			 * Turn off the defense mode if we
			 * believe the SYN attack is over.
			 */
			listener->tcp_syn_defense = B_FALSE;
			if (listener->tcp_ip_addr_cache) {
				kmem_free((void *)listener->tcp_ip_addr_cache,
				    IP_ADDR_CACHE_SIZE * sizeof (ipaddr_t));
				listener->tcp_ip_addr_cache = NULL;
			}
		}
	}
	addr_cache = (ipaddr_t *)(listener->tcp_ip_addr_cache);
	if (addr_cache != NULL) {
		/*
		 * We have finished a 3-way handshake with this
		 * remote host. This proves the IP addr is good.
		 * Cache it!
		 */
		addr_cache[IP_ADDR_CACHE_HASH(tcp->tcp_connp->conn_faddr_v4)] =
		    tcp->tcp_connp->conn_faddr_v4;
	}
	mutex_exit(&listener->tcp_eager_lock);

	/*
	 * Notify the ULP about the newconn. It is guaranteed that no
	 * tcp_accept() call will be made for the eager if the
	 * notification fails.
	 */
	if ((upper = (*lconnp->conn_upcalls->su_newconn)
	    (lconnp->conn_upper_handle, (sock_lower_handle_t)econnp,
	    &sock_tcp_downcalls, ira->ira_cred, ira->ira_cpid,
	    &econnp->conn_upcalls)) == NULL) {
		return (B_FALSE);
	}
	econnp->conn_upper_handle = upper;

	tcp->tcp_detached = B_FALSE;
	tcp->tcp_hard_binding = B_FALSE;
	tcp->tcp_tconnind_started = B_TRUE;

	if (econnp->conn_keepalive) {
		tcp->tcp_ka_last_intrvl = 0;
		tcp->tcp_ka_tid = TCP_TIMER(tcp, tcp_keepalive_timer,
		    tcp->tcp_ka_interval);
	}

	/* Update the necessary parameters */
	tcp_get_proto_props(tcp, &sopp);

	(*econnp->conn_upcalls->su_set_proto_props)
	    (econnp->conn_upper_handle, &sopp);

	return (B_TRUE);
}
