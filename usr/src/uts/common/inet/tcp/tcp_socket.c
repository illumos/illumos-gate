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

/* This file contains all TCP kernel socket related functions. */

#include <sys/types.h>
#include <sys/strlog.h>
#include <sys/policy.h>
#include <sys/sockio.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/squeue_impl.h>
#include <sys/squeue.h>
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
static int	tcp_getsockopt(sock_lower_handle_t, int, int, void *,
		    socklen_t *, cred_t *);
static int	tcp_setsockopt(sock_lower_handle_t, int, int, const void *,
		    socklen_t, cred_t *);
static int	tcp_sendmsg(sock_lower_handle_t, mblk_t *, struct nmsghdr *,
		    cred_t *cr);
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

static int
tcp_accept(sock_lower_handle_t lproto_handle,
    sock_lower_handle_t eproto_handle, sock_upper_handle_t sock_handle,
    cred_t *cr)
{
	conn_t *lconnp, *econnp;
	tcp_t *listener, *eager;

	lconnp = (conn_t *)lproto_handle;
	listener = lconnp->conn_tcp;
	ASSERT(listener->tcp_state == TCPS_LISTEN);
	econnp = (conn_t *)eproto_handle;
	eager = econnp->conn_tcp;
	ASSERT(eager->tcp_listener != NULL);

	/*
	 * It is OK to manipulate these fields outside the eager's squeue
	 * because they will not start being used until tcp_accept_finish
	 * has been called.
	 */
	ASSERT(lconnp->conn_upper_handle != NULL);
	ASSERT(econnp->conn_upper_handle == NULL);
	econnp->conn_upper_handle = sock_handle;
	econnp->conn_upcalls = lconnp->conn_upcalls;
	ASSERT(IPCL_IS_NONSTR(econnp));
	return (tcp_accept_common(lconnp, econnp, cr));
}

static int
tcp_bind(sock_lower_handle_t proto_handle, struct sockaddr *sa,
    socklen_t len, cred_t *cr)
{
	int 		error;
	conn_t		*connp = (conn_t *)proto_handle;
	squeue_t	*sqp = connp->conn_sqp;

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	ASSERT(sqp != NULL);
	ASSERT(connp->conn_upper_handle != NULL);

	error = squeue_synch_enter(sqp, connp, NULL);
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

	squeue_synch_exit(sqp, connp);

	if (error < 0) {
		if (error == -TOUTSTATE)
			error = EINVAL;
		else
			error = proto_tlitosyserr(-error);
	}

	return (error);
}

/*
 * SOP_LISTEN() calls into tcp_listen().
 */
/* ARGSUSED */
static int
tcp_listen(sock_lower_handle_t proto_handle, int backlog, cred_t *cr)
{
	conn_t	*connp = (conn_t *)proto_handle;
	int 	error;
	squeue_t *sqp = connp->conn_sqp;

	ASSERT(connp->conn_upper_handle != NULL);

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	error = squeue_synch_enter(sqp, connp, NULL);
	if (error != 0) {
		/* failed to enter */
		return (ENOBUFS);
	}

	error = tcp_do_listen(connp, NULL, 0, backlog, cr, B_FALSE);
	if (error == 0) {
		(*connp->conn_upcalls->su_opctl)(connp->conn_upper_handle,
		    SOCK_OPCTL_ENAB_ACCEPT, (uintptr_t)backlog);
	} else if (error < 0) {
		if (error == -TOUTSTATE)
			error = EINVAL;
		else
			error = proto_tlitosyserr(-error);
	}
	squeue_synch_exit(sqp, connp);
	return (error);
}

static int
tcp_connect(sock_lower_handle_t proto_handle, const struct sockaddr *sa,
    socklen_t len, sock_connid_t *id, cred_t *cr)
{
	conn_t		*connp = (conn_t *)proto_handle;
	squeue_t	*sqp = connp->conn_sqp;
	int		error;

	ASSERT(connp->conn_upper_handle != NULL);

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	error = proto_verify_ip_addr(connp->conn_family, sa, len);
	if (error != 0) {
		return (error);
	}

	error = squeue_synch_enter(sqp, connp, NULL);
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
	squeue_synch_exit(sqp, connp);

	return ((error == 0) ? EINPROGRESS : error);
}

/* ARGSUSED3 */
int
tcp_getpeername(sock_lower_handle_t proto_handle, struct sockaddr *addr,
    socklen_t *addrlenp, cred_t *cr)
{
	conn_t	*connp = (conn_t *)proto_handle;
	tcp_t	*tcp = connp->conn_tcp;

	ASSERT(connp->conn_upper_handle != NULL);
	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	ASSERT(tcp != NULL);
	if (tcp->tcp_state < TCPS_SYN_RCVD)
		return (ENOTCONN);

	return (conn_getpeername(connp, addr, addrlenp));
}

/* ARGSUSED3 */
int
tcp_getsockname(sock_lower_handle_t proto_handle, struct sockaddr *addr,
    socklen_t *addrlenp, cred_t *cr)
{
	conn_t	*connp = (conn_t *)proto_handle;

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	ASSERT(connp->conn_upper_handle != NULL);
	return (conn_getsockname(connp, addr, addrlenp));
}

/* returns UNIX error, the optlen is a value-result arg */
static int
tcp_getsockopt(sock_lower_handle_t proto_handle, int level, int option_name,
    void *optvalp, socklen_t *optlen, cred_t *cr)
{
	conn_t		*connp = (conn_t *)proto_handle;
	squeue_t	*sqp = connp->conn_sqp;
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

	error = squeue_synch_enter(sqp, connp, NULL);
	if (error == ENOMEM) {
		kmem_free(optvalp_buf, max_optbuf_len);
		return (ENOMEM);
	}

	len = tcp_opt_get(connp, level, option_name, optvalp_buf);
	squeue_synch_exit(sqp, connp);

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
	squeue_t	*sqp = connp->conn_sqp;
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

	error = squeue_synch_enter(sqp, connp, NULL);
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
		squeue_synch_exit(sqp, connp);
		return (error);
	}

	error = tcp_opt_set(connp, SETFN_OPTCOM_NEGOTIATE, level, option_name,
	    optlen, (uchar_t *)optvalp, (uint_t *)&optlen, (uchar_t *)optvalp,
	    NULL, cr);
	squeue_synch_exit(sqp, connp);

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

	error = squeue_synch_enter(connp->conn_sqp, connp, mp);
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

	squeue_synch_exit(connp->conn_sqp, connp);
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
	return (0);
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
	 * by ipcl_conn_create. Also Make the conn_t globally
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

int
tcp_fallback(sock_lower_handle_t proto_handle, queue_t *q,
    boolean_t direct_sockfs, so_proto_quiesced_cb_t quiesced_cb)
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
	error = squeue_synch_enter(connp->conn_sqp, connp, NULL);
	if (error != 0) {
		/* failed to enter, free all the pre-allocated messages. */
		freeb(stropt_mp);
		freeb(ordrel_mp);
		/*
		 * We cannot process the eager, so at least send out a
		 * RST so the peer can reconnect.
		 */
		if (tcp->tcp_listener != NULL) {
			(void) tcp_eager_blowoff(tcp->tcp_listener,
			    tcp->tcp_conn_req_seqnum);
		}
		return (ENOMEM);
	}

	/*
	 * Both endpoints must be of the same type (either STREAMS or
	 * non-STREAMS) for fusion to be enabled. So if we are fused,
	 * we have to unfuse.
	 */
	if (tcp->tcp_fused)
		tcp_unfuse(tcp);

	/*
	 * No longer a direct socket
	 */
	connp->conn_flags &= ~IPCL_NONSTR;
	tcp->tcp_ordrel_mp = ordrel_mp;

	if (tcp->tcp_listener != NULL) {
		/* The eager will deal with opts when accept() is called */
		freeb(stropt_mp);
		tcp_fallback_eager(tcp, direct_sockfs);
	} else {
		tcp_fallback_noneager(tcp, stropt_mp, q, direct_sockfs,
		    quiesced_cb);
	}

	/*
	 * There should be atleast two ref's (IP + TCP)
	 */
	ASSERT(connp->conn_ref >= 2);
	squeue_synch_exit(connp->conn_sqp, connp);

	return (0);
}
