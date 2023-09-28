/*
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This file contains code imported from the OFED rds source file af_rds.c
 * Oracle elects to have and use the contents of af_rds.c under and governed
 * by the OpenIB.org BSD license (see below for full license text). However,
 * the following notice accompanied the original version of this file:
 */

/*
 * Copyright (c) 2006 Oracle.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/rds.h>
#include <sys/stropts.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>
#include <sys/sysmacros.h>

#include <inet/ip.h>
#include <net/if_types.h>

#include <sys/ib/clients/rdsv3/rdsv3.h>
#include <sys/ib/clients/rdsv3/rdma.h>
#include <sys/ib/clients/rdsv3/rdma_transport.h>
#include <sys/ib/clients/rdsv3/rdsv3_debug.h>

extern void rdsv3_remove_bound(struct rdsv3_sock *rds);
extern int rdsv3_verify_bind_address(ipaddr_t addr);

extern ddi_taskq_t	*rdsv3_taskq;
extern struct rdma_cm_id *rdsv3_rdma_listen_id;

/* this is just used for stats gathering :/ */
kmutex_t rdsv3_sock_lock;
static unsigned long rdsv3_sock_count;
list_t rdsv3_sock_list;

/*
 * This is called as the final descriptor referencing this socket is closed.
 * We have to unbind the socket so that another socket can be bound to the
 * address it was using.
 *
 * We have to be careful about racing with the incoming path.  sock_orphan()
 * sets SOCK_DEAD and we use that as an indicator to the rx path that new
 * messages shouldn't be queued.
 */
/* ARGSUSED */
static int
rdsv3_release(sock_lower_handle_t proto_handle, int flgs, cred_t *cr)
{
	struct rsock *sk = (struct rsock *)proto_handle;
	struct rdsv3_sock *rs;

	if (!sk)
		goto out;

	rs = rdsv3_sk_to_rs(sk);
	RDSV3_DPRINTF4("rdsv3_release", "Enter(rs: %p, sk: %p)", rs, sk);

	rdsv3_sk_sock_orphan(sk);
	rdsv3_cong_remove_socket(rs);
	rdsv3_remove_bound(rs);

	/*
	 * Note - rdsv3_clear_recv_queue grabs rs_recv_lock, so
	 * that ensures the recv path has completed messing
	 * with the socket.
	 *
	 * Note2 - rdsv3_clear_recv_queue(rs) should be called first
	 * to prevent some race conditions, which is different from
	 * the Linux code.
	 */
	rdsv3_clear_recv_queue(rs);
	rdsv3_send_drop_to(rs, NULL);
	rdsv3_rdma_drop_keys(rs);
	(void) rdsv3_notify_queue_get(rs, NULL);

	mutex_enter(&rdsv3_sock_lock);
	list_remove_node(&rs->rs_item);
	rdsv3_sock_count--;
	mutex_exit(&rdsv3_sock_lock);

	while (sk->sk_refcount > 1) {
		/* wait for 1 sec and try again */
		delay(drv_usectohz(1000000));
	}

	/* this will free the rs and sk */
	rdsv3_sk_sock_put(sk);

	RDSV3_DPRINTF4("rdsv3_release", "Return (rds: %p)", rs);
out:
	return (0);
}

void
__rdsv3_wake_sk_sleep(struct rsock *sk)
{
	/* wakup anyone waiting in recvmsg */
	if (!rdsv3_sk_sock_flag(sk, SOCK_DEAD) && sk->sk_sleep)
		rdsv3_wake_up(sk->sk_sleep);
}

/*
 * Careful not to race with rdsv3_release -> sock_orphan which clears sk_sleep.
 * _bh() isn't OK here, we're called from interrupt handlers.  It's probably OK
 * to wake the waitqueue after sk_sleep is clear as we hold a sock ref, but
 * this seems more conservative.
 * NB - normally, one would use sk_callback_lock for this, but we can
 * get here from interrupts, whereas the network code grabs sk_callback_lock
 * with _lock_bh only - so relying on sk_callback_lock introduces livelocks.
 */
void
rdsv3_wake_sk_sleep(struct rdsv3_sock *rs)
{
	RDSV3_DPRINTF4("rdsv3_wake_sk_sleep", "Enter(rs: %p)", rs);

	rw_enter(&rs->rs_recv_lock, RW_READER);
	__rdsv3_wake_sk_sleep(rdsv3_rs_to_sk(rs));
	rw_exit(&rs->rs_recv_lock);
}

/*ARGSUSED*/
static int
rdsv3_getname(sock_lower_handle_t proto_handle, struct sockaddr *addr,
    socklen_t *addr_len, cred_t *cr)
{
	struct rsock *sk = (struct rsock *)proto_handle;
	struct sockaddr_in *sin = (struct sockaddr_in *)addr;
	struct rdsv3_sock *rs = rdsv3_sk_to_rs(sk);

	RDSV3_DPRINTF4("rdsv3_getname", "Enter(rs: %p, port: %d)", rs,
	    rs->rs_bound_port);

	sin->sin_port = rs->rs_bound_port;
	sin->sin_addr.s_addr = rs->rs_bound_addr;

	sin->sin_family = AF_INET_OFFLOAD;

	*addr_len = sizeof (*sin);
	return (0);
}

/*
 * RDS' poll is without a doubt the least intuitive part of the interface,
 * as POLLIN and POLLOUT do not behave entirely as you would expect from
 * a network protocol.
 *
 * POLLIN is asserted if
 *  -	there is data on the receive queue.
 *  -	to signal that a previously congested destination may have become
 *	uncongested
 *  -	A notification has been queued to the socket (this can be a congestion
 *	update, or a RDMA completion).
 *
 * POLLOUT is asserted if there is room on the send queue. This does not mean
 * however, that the next sendmsg() call will succeed. If the application tries
 * to send to a congested destination, the system call may still fail (and
 * return ENOBUFS).
 */
/* ARGSUSED */
static short
rdsv3_poll(sock_lower_handle_t proto_handle, short events, int anyyet,
    cred_t *cr)
{
	struct rsock	*sk = (struct rsock *)proto_handle;
	struct rdsv3_sock	*rs = rdsv3_sk_to_rs(sk);
	unsigned short mask = 0;

#if 0
	RDSV3_DPRINTF4("rdsv3_poll", "enter(%p %x %d)", rs, events, anyyet);
#endif

	/*
	 * If rs_seen_congestion is on, wait until it's off.
	 * This is implemented for the following OFED code.
	 * 	if (rs->rs_seen_congestion)
	 *		poll_wait(file, &rds_poll_waitq, wait);
	 */
	mutex_enter(&rs->rs_congested_lock);
	while (rs->rs_seen_congestion) {
		cv_wait(&rs->rs_congested_cv,
		    &rs->rs_congested_lock);
	}
	mutex_exit(&rs->rs_congested_lock);

	rw_enter(&rs->rs_recv_lock, RW_READER);
	if (!rs->rs_cong_monitor) {
		/*
		 * When a congestion map was updated, we signal POLLIN for
		 * "historical" reasons. Applications can also poll for
		 * WRBAND instead.
		 */
		if (rdsv3_cong_updated_since(&rs->rs_cong_track))
			mask |= (POLLIN | POLLRDNORM | POLLWRBAND);
	} else {
		mutex_enter(&rs->rs_lock);
		if (rs->rs_cong_notify)
			mask |= (POLLIN | POLLRDNORM);
		mutex_exit(&rs->rs_lock);
	}
	if (!list_is_empty(&rs->rs_recv_queue) ||
	    !list_is_empty(&rs->rs_notify_queue))
		mask |= (POLLIN | POLLRDNORM);
	if (rs->rs_snd_bytes < rdsv3_sk_sndbuf(rs))
		mask |= (POLLOUT | POLLWRNORM);

	/* clear state any time we wake a seen-congested socket */
	if (mask) {
		mutex_enter(&rs->rs_congested_lock);
		rs->rs_seen_congestion = 0;
		mutex_exit(&rs->rs_congested_lock);
	}

	rw_exit(&rs->rs_recv_lock);

#if 0
	RDSV3_DPRINTF4("rdsv3_poll", "return(%p %x)", rs, mask);
#endif

	return (mask);
}

/* ARGSUSED */
static int
rdsv3_ioctl(sock_lower_handle_t proto_handle, int cmd, intptr_t arg,
    int mode, int32_t *rvalp, cred_t *cr)
{
	ksocket_t	so4;
	struct lifconf	lifc;
	struct lifreq	lifr, *lifrp;
	struct ifconf	ifc;
	struct ifreq	ifr;
	int		rval = 0, rc, len;
	int		numifs;
	int		bufsize;
	void		*buf;

	RDSV3_DPRINTF4("rdsv3_ioctl", "enter: cmd: %d", cmd);

	/* Only ipv4 for now */
	rval = ksocket_socket(&so4, PF_INET, SOCK_DGRAM, 0, KSOCKET_NOSLEEP,
	    CRED());
	if (rval != 0) {
		RDSV3_DPRINTF2("rdsv3_ioctl", "ksocket_socket returned %d",
		    rval);
		return (rval);
	}

	switch (cmd) {
	case SIOCGLIFNUM :
	case SIOCGIFNUM :
		rval = rdsv3_do_ip_ioctl(so4, &buf, &bufsize, &numifs);
		if (rval != 0) break;
		if (cmd == SIOCGLIFNUM) {
			struct lifnum	lifn;
			lifn.lifn_family = AF_INET_OFFLOAD;
			lifn.lifn_flags = 0;
			lifn.lifn_count = numifs;
			(void) ddi_copyout(&lifn, (void *)arg,
			    sizeof (struct lifnum), 0);
		} else {
			len = 0;
			for (lifrp = (struct lifreq *)buf, rc = 0; rc < numifs;
			    rc++, lifrp++) {
				if (strlen(lifrp->lifr_name) <= IFNAMSIZ) {
					len++;
				}
			}
			(void) ddi_copyout(&len, (void *)arg,
			    sizeof (int), 0);
		}
		kmem_free(buf, bufsize);
		break;

	case SIOCGLIFCONF :
		if (ddi_copyin((void *)arg, &lifc, sizeof (struct lifconf), 0)
		    != 0) {
			RDSV3_DPRINTF2("rdsv3_ioctl", "ddi_copyin failed lifc");
			rval = EFAULT;
			break;
		}

		rval = rdsv3_do_ip_ioctl(so4, &buf, &bufsize, &numifs);
		if (rval != 0) {
			RDSV3_DPRINTF2("rdsv3_ioctl",
			    "rdsv3_do_ip_ioctl failed: %d", rval);
			break;
		}

		if ((lifc.lifc_len > 0) && (numifs > 0)) {
			if (ddi_copyout(buf, (void *)lifc.lifc_req,
			    (lifc.lifc_len < bufsize) ? lifc.lifc_len :
			    bufsize, 0) != 0) {
				RDSV3_DPRINTF2("rdsv3_ioctl",
				    "copyout of records failed");
				rval = EFAULT;
			}

		}

		lifc.lifc_len = bufsize;
		if (ddi_copyout(&lifc, (void *)arg, sizeof (struct lifconf),
		    0) != 0) {
			RDSV3_DPRINTF2("rdsv3_ioctl",
			    "copyout of lifconf failed");
			rval = EFAULT;
		}

		kmem_free(buf, bufsize);
		break;

	case SIOCGIFCONF :
	case O_SIOCGIFCONF :
		if (ddi_copyin((void *)arg, &ifc, sizeof (struct ifconf), 0)
		    != 0) {
			RDSV3_DPRINTF2("rdsv3_ioctl", "ddi_copyin failed ifc");
			rval = EFAULT;
			break;
		}

		RDSV3_DPRINTF2("rdsv3_ioctl",
		    "O_SIOCGIFCONF: ifc_len: %d, req: %p",
		    ifc.ifc_len, ifc.ifc_req);

		rval = rdsv3_do_ip_ioctl_old(so4, &buf, &bufsize, &numifs);
		if (rval != 0) {
			RDSV3_DPRINTF2("rdsv3_ioctl",
			    "rdsv3_do_ip_ioctl_old failed: %d", rval);
			break;
		}

		if ((ifc.ifc_len > 0) && (numifs > 0)) {
			if (ddi_copyout(buf, (void *)ifc.ifc_req,
			    (ifc.ifc_len < bufsize) ? ifc.ifc_len :
			    bufsize, 0) != 0) {
				RDSV3_DPRINTF2("rdsv3_ioctl",
				    "copyout of records failed");
				rval = EFAULT;
			}

		}

		ifc.ifc_len = bufsize;
		if (ddi_copyout(&ifc, (void *)arg, sizeof (struct ifconf),
		    0) != 0) {
			RDSV3_DPRINTF2("rdsv3_ioctl",
			    "copyout of ifconf failed");
			rval = EFAULT;
		}

		kmem_free(buf, bufsize);
		break;

	case SIOCGLIFFLAGS :
	case SIOCSLIFFLAGS :
	case SIOCGLIFMTU :
	case SIOCGLIFNETMASK :
	case SIOCGLIFINDEX :
		if (ddi_copyin((void *)arg, &lifr, sizeof (struct lifreq), 0)
		    != 0) {
			RDSV3_DPRINTF2("rdsv3_ioctl", "ddi_copyin failed lifr");
			rval = EFAULT;
			break;
		}

		rc = ksocket_ioctl(so4, cmd, (intptr_t)&lifr, &rval, CRED());
		if (rc != 0) {
			RDSV3_DPRINTF2("rdsv3_ioctl",
			    "ksocket_ioctl failed: %d, name: %s cmd: 0x%x",
			    rc, lifr.lifr_name, cmd);
			break;
		}

		(void) ddi_copyout(&lifr, (void *)arg,
		    sizeof (struct lifreq), 0);
		break;

	case SIOCGIFFLAGS :
	case SIOCSIFFLAGS :
	case SIOCGIFMTU :
	case SIOCGIFNETMASK :
	case SIOCGIFINDEX :
		if (ddi_copyin((void *)arg, &ifr, sizeof (struct ifreq), 0)
		    != 0) {
			RDSV3_DPRINTF2("rdsv3_ioctl", "ddi_copyin failed ifr");
			rval = EFAULT;
			break;
		}

		RDSV3_DPRINTF2("rdsv3_ioctl", "1. name: %s", ifr.ifr_name);

		rc = ksocket_ioctl(so4, cmd, (intptr_t)&ifr, &rval, CRED());
		if (rc != 0) {
			RDSV3_DPRINTF2("rdsv3_ioctl",
			    "ksocket_ioctl failed: %d, name: %s cmd: 0x%x",
			    rc, ifr.ifr_name, cmd);

			break;
		}

		RDSV3_DPRINTF2("rdsv3_ioctl", "2. name: %s", ifr.ifr_name);

		(void) ddi_copyout(&ifr, (void *)arg,
		    sizeof (struct ifreq), 0);
		break;

	default:
		if ((cmd >= RDS_INFO_FIRST) &&
		    (cmd <= RDS_INFO_LAST)) {
			return (rdsv3_info_ioctl((struct rsock *)proto_handle,
			    cmd, (char *)arg, rvalp));
		}
		RDSV3_DPRINTF2("rdsv3_ioctl", "Unknown ioctl cmd: %d",  cmd);
		cmn_err(CE_CONT, "unsupported IOCTL cmd: %d \n", cmd);
		rval = EOPNOTSUPP;
	}

	(void) ksocket_close(so4, CRED());

	RDSV3_DPRINTF4("rdsv3_ioctl", "return: %d cmd: %d", rval, cmd);

	*rvalp = rval;
	return (rval);
}

static int
rdsv3_cancel_sent_to(struct rdsv3_sock *rs, char *optval, int len)
{
	struct sockaddr_in sin;

	/* racing with another thread binding seems ok here */
	if (rs->rs_bound_addr == 0)
		return (-ENOTCONN); /* XXX not a great errno */

	if (len < sizeof (struct sockaddr_in))
		return (-EINVAL);

	if (ddi_copyin((void *)optval, &sin, sizeof (struct sockaddr_in),
	    0) != 0) {
		RDSV3_DPRINTF2("rdsv3_cancel_sent_to", "ddi_copyin failed sin");
		return (-EFAULT);
	}

	rdsv3_send_drop_to(rs, &sin);

	return (0);
}

static int
rdsv3_set_bool_option(unsigned char *optvar, char *optval, int optlen)
{
	int value = *optval;

	if (optlen < sizeof (int))
		return (-EINVAL);
	*optvar = !!value;
	return (0);
}

static int
rdsv3_cong_monitor(struct rdsv3_sock *rs, char *optval, int optlen)
{
	int ret;

	ret = rdsv3_set_bool_option(&rs->rs_cong_monitor, optval, optlen);
	if (ret == 0) {
		if (rs->rs_cong_monitor) {
			rdsv3_cong_add_socket(rs);
		} else {
			rdsv3_cong_remove_socket(rs);
			rs->rs_cong_mask = 0;
			rs->rs_cong_notify = 0;
		}
	}
	return (ret);
}

/*ARGSUSED*/
static int
rdsv3_setsockopt(sock_lower_handle_t proto_handle, int level,
    int optname, const void *optval, socklen_t optlen, cred_t *cr)
{
	struct rsock *sk = (struct rsock *)proto_handle;
	struct rdsv3_sock	*rs = rdsv3_sk_to_rs(sk);
	int	ret = 0;

	RDSV3_DPRINTF4("rdsv3_setsockopt", "enter(%p %d %d)",
	    rs, level, optname);

	switch (optname) {
	case RDS_CANCEL_SENT_TO:
		ret = rdsv3_cancel_sent_to(rs, (char *)optval, optlen);
		break;
	case RDS_GET_MR:
		ret = rdsv3_get_mr(rs, optval, optlen);
		break;
	case RDS_GET_MR_FOR_DEST:
		ret = rdsv3_get_mr_for_dest(rs, optval, optlen);
		break;
	case RDS_FREE_MR:
		ret = rdsv3_free_mr(rs, optval, optlen);
		break;
	case RDS_RECVERR:
		ret = rdsv3_set_bool_option(&rs->rs_recverr,
		    (char *)optval, optlen);
		break;
	case RDS_CONG_MONITOR:
		ret = rdsv3_cong_monitor(rs, (char *)optval, optlen);
		break;
	case SO_SNDBUF:
		sk->sk_sndbuf = *(uint_t *)optval;
		return (ret);
	case SO_RCVBUF:
		sk->sk_rcvbuf = *(uint_t *)optval;
		return (ret);
	default:
#if 1
		break;
#else
		ret = -ENOPROTOOPT;
#endif
	}
	return (ret);
}

/* XXX */
/*ARGSUSED*/
static int
rdsv3_getsockopt(sock_lower_handle_t proto_handle, int level,
    int optname, void *optval, socklen_t *optlen, cred_t *cr)
{
	struct rsock *sk = (struct rsock *)proto_handle;
	struct rdsv3_sock	*rs = rdsv3_sk_to_rs(sk);
	int ret = 0;

	RDSV3_DPRINTF4("rdsv3_getsockopt", "enter(%p %d %d)",
	    rs, optname, *optlen);

	switch (optname) {
	case SO_SNDBUF:
		RDSV3_DPRINTF4("rdsv3_getsockopt", "SO_SNDBUF(%d)",
		    sk->sk_sndbuf);
		if (*optlen != 0) {
			*((int *)optval) = sk->sk_sndbuf;
			*optlen = sizeof (uint_t);
		}
		return (ret);
	case SO_RCVBUF:
		RDSV3_DPRINTF4("rdsv3_getsockopt", "SO_RCVBUF(%d)",
		    sk->sk_rcvbuf);
		if (*optlen != 0) {
			*((int *)optval) = sk->sk_rcvbuf;
			*optlen = sizeof (uint_t);
		}
		return (ret);
	case RDS_RECVERR:
		RDSV3_DPRINTF4("rdsv3_getsockopt", "RDSV3_RECVERR(%d)",
		    rs->rs_recverr);
		if (*optlen < sizeof (int))
			return (-EINVAL);
		else {
			*(int *)optval = rs->rs_recverr;
			*optlen = sizeof (int);
		}
		return (0);
	default:
		RDSV3_DPRINTF2("rdsv3_getsockopt",
		    "Unknown: level: %d optname: %d", level, optname);
		ret = -ENOPROTOOPT;
	}

	RDSV3_DPRINTF4("rdsv3_getsockopt", "return(%p %d %d)",
	    rs, optname, ret);
	return (ret);
}

/*ARGSUSED*/
static int rdsv3_connect(sock_lower_handle_t proto_handle,
    const struct sockaddr *addr, socklen_t addr_len, sock_connid_t *conn,
    cred_t *cr)
{
	struct rsock *sk = (struct rsock *)proto_handle;
	struct sockaddr_in *sin = (struct sockaddr_in *)addr;
	struct rdsv3_sock	*rs = rdsv3_sk_to_rs(sk);
	int ret = 0;

	RDSV3_DPRINTF4("rdsv3_connect", "Enter(rs: %p)", rs);

	mutex_enter(&sk->sk_lock);

	if (addr_len != sizeof (struct sockaddr_in)) {
		ret = -EINVAL;
		goto out;
	}

	if (sin->sin_family != AF_INET_OFFLOAD) {
		ret = -EAFNOSUPPORT;
		goto out;
	}

	if (sin->sin_addr.s_addr == htonl(INADDR_ANY)) {
		ret = -EDESTADDRREQ;
		goto out;
	}

	rs->rs_conn_addr = sin->sin_addr.s_addr;
	rs->rs_conn_port = sin->sin_port;

	sk->sk_upcalls->su_connected(sk->sk_upper_handle, 0, NULL, -1);

	RDSV3_DPRINTF4("rdsv3_connect", "Return(rs: %p)", rs);

out:
	mutex_exit(&sk->sk_lock);
	return (ret);
}

/*ARGSUSED*/
static int
rdsv3_shutdown(sock_lower_handle_t proto_handle, int how, cred_t *cr)
{
	struct rsock *sk = (struct rsock *)proto_handle;
	struct rdsv3_sock *rs = rdsv3_sk_to_rs(sk);

	RDSV3_DPRINTF4("rdsv3_shutdown", "Enter(rs: %p)", rs);

	return (0);
}

/*ARGSUSED*/
void
rdsv3_activate(sock_lower_handle_t proto_handle,
    sock_upper_handle_t sock_handle, sock_upcalls_t *sock_upcalls,
    int flags, cred_t *cr)
{
	struct rsock *sk = (struct rsock *)proto_handle;
	struct rdsv3_sock *rs = rdsv3_sk_to_rs(sk);

	RDSV3_DPRINTF4("rdsv3_activate", "Enter(rs: %p)", rs);

	sk->sk_upcalls = sock_upcalls;
	sk->sk_upper_handle = sock_handle;

	RDSV3_DPRINTF4("rdsv3_activate", "Return (rs: %p)", rs);
}


/* ARGSUSED */
int
rdsv3_send_uio(sock_lower_handle_t proto_handle, uio_t *uio,
    struct nmsghdr *msg, cred_t *cr)
{
	struct rsock *sk = (struct rsock *)proto_handle;
	struct rdsv3_sock *rs = rdsv3_sk_to_rs(sk);
	int ret;

	RDSV3_DPRINTF4("rdsv3_send_uio", "Enter(rs: %p)", rs);
	ret = rdsv3_sendmsg(rs, uio, msg, uio->uio_resid);

	RDSV3_DPRINTF4("rdsv3_send_uio", "Return(rs: %p ret %d)", rs, ret);
	if (ret < 0) {
		return (-ret);
	}

	return (0);
}

/* ARGSUSED */
int
rdsv3_recv_uio(sock_lower_handle_t proto_handle, uio_t *uio,
    struct nmsghdr *msg, cred_t *cr)
{
	struct rsock *sk = (struct rsock *)proto_handle;
	struct rdsv3_sock *rs = rdsv3_sk_to_rs(sk);
	int ret;

	RDSV3_DPRINTF4("rdsv3_recv_uio", "Enter (rs: %p)", rs);
	ret = rdsv3_recvmsg(rs, uio, msg, uio->uio_resid, msg->msg_flags);

	RDSV3_DPRINTF4("rdsv3_recv_uio", "Return(rs: %p ret %d)", rs, ret);

	if (ret < 0) {
		return (-ret);
	}

	return (0);
}

/*ARGSUSED*/
int
rdsv3_getpeername(sock_lower_handle_t  proto_handle, struct sockaddr *addr,
    socklen_t *addr_len, cred_t *cr)
{
	struct sockaddr_in *sin = (struct sockaddr_in *)addr;
	struct rsock *sk = (struct rsock *)proto_handle;
	struct rdsv3_sock *rs = rdsv3_sk_to_rs(sk);

	RDSV3_DPRINTF2("rdsv3_getpeername", "enter(rs: %p)", rs);

	(void) memset(sin->sin_zero, 0, sizeof (sin->sin_zero));

	/* racey, don't care */
	if (!rs->rs_conn_addr)
		return (-ENOTCONN);

	sin->sin_port = rs->rs_conn_port;
	sin->sin_addr.s_addr = rs->rs_conn_addr;

	sin->sin_family = AF_INET_OFFLOAD;

	*addr_len = sizeof (*sin);
	return (0);
}

void
rdsv3_clrflowctrl(sock_lower_handle_t proto_handle)
{
	struct rsock *sk = (struct rsock *)proto_handle;
	struct rdsv3_sock *rs = rdsv3_sk_to_rs(sk);

	RDSV3_DPRINTF2("rdsv3_clrflowctrl", "enter(rs: %p)", rs);
}

#ifndef __lock_lint
static struct sock_downcalls_s rdsv3_sock_downcalls = {
	.sd_close =		rdsv3_release,
	.sd_bind =		rdsv3_bind,
	.sd_connect =		rdsv3_connect,
	.sd_accept =		NULL,
	.sd_getsockname =	rdsv3_getname,
	.sd_poll =		rdsv3_poll,
	.sd_ioctl =		rdsv3_ioctl,
	.sd_listen =		NULL,
	.sd_shutdown =		rdsv3_shutdown,
	.sd_setsockopt =	rdsv3_setsockopt,
	.sd_getsockopt =	rdsv3_getsockopt,
	.sd_send_uio =		rdsv3_send_uio,
	.sd_recv_uio =		rdsv3_recv_uio,
	.sd_activate =		rdsv3_activate,
	.sd_getpeername =	rdsv3_getpeername,
	.sd_send =		NULL,
	.sd_clr_flowctrl =	NULL
};
#else
static struct sock_downcalls_s rdsv3_sock_downcalls = {
	rdsv3_activate,
	NULL,
	rdsv3_bind,
	NULL,
	rdsv3_connect,
	rdsv3_getpeername,
	rdsv3_getname,
	rdsv3_getsockopt,
	rdsv3_setsockopt,
	NULL,
	rdsv3_send_uio,
	rdsv3_recv_uio,
	rdsv3_poll,
	rdsv3_shutdown,
	NULL,
	rdsv3_ioctl,
	rdsv3_release
};
#endif

sock_lower_handle_t
rdsv3_create(int family, int type, int proto, sock_downcalls_t **sock_downcalls,
    uint_t *smodep, int *errorp, int flags, cred_t *credp)
{
	struct rdsv3_sock	*rs;
	struct rsock		*sk;

	RDSV3_DPRINTF4("rdsv3_create", "Enter (family: %d type: %d, proto: %d "
	    "flags: %d", family, type, proto, flags);

	sk = rdsv3_sk_alloc();
	if (sk == NULL)
		return (NULL);
	rdsv3_sock_init_data(sk);

	rs = rdsv3_sk_to_rs(sk);
	rs->rs_sk = sk;
	mutex_init(&rs->rs_lock, NULL, MUTEX_DRIVER, NULL);
	rw_init(&rs->rs_recv_lock, NULL, RW_DRIVER, NULL);
	list_create(&rs->rs_send_queue, sizeof (struct rdsv3_message),
	    offsetof(struct rdsv3_message, m_sock_item));
	list_create(&rs->rs_recv_queue, sizeof (struct rdsv3_incoming),
	    offsetof(struct rdsv3_incoming, i_item));
	list_create(&rs->rs_notify_queue, sizeof (struct rdsv3_notifier),
	    offsetof(struct rdsv3_notifier, n_list));
	mutex_init(&rs->rs_rdma_lock, NULL, MUTEX_DRIVER, NULL);
	avl_create(&rs->rs_rdma_keys, rdsv3_mr_compare,
	    sizeof (struct rdsv3_mr), offsetof(struct rdsv3_mr, r_rb_node));
	mutex_init(&rs->rs_conn_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&rs->rs_congested_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&rs->rs_congested_cv, NULL, CV_DRIVER, NULL);
	rs->rs_cred = credp;
	rs->rs_zoneid = getzoneid();
	crhold(credp);

	mutex_enter(&rdsv3_sock_lock);
	list_insert_tail(&rdsv3_sock_list, rs);
	rdsv3_sock_count++;
	/* Initialize RDMA/IB on the 1st socket if not done at attach */
	if (rdsv3_sock_count == 1) {
		rdsv3_rdma_init();
	}
	mutex_exit(&rdsv3_sock_lock);

	*errorp = 0;
	*smodep = SM_ATOMIC;
	*sock_downcalls = &rdsv3_sock_downcalls;

	RDSV3_DPRINTF4("rdsv3_create", "Return: %p", rs);

	return ((sock_lower_handle_t)rdsv3_rs_to_sk(rs));
}

void
rdsv3_sock_addref(struct rdsv3_sock *rs)
{
	RDSV3_DPRINTF4("rdsv3_sock_addref", "Enter(rs: %p)", rs);
	rdsv3_sk_sock_hold(rdsv3_rs_to_sk(rs));
}

void
rdsv3_sock_put(struct rdsv3_sock *rs)
{
	RDSV3_DPRINTF4("rdsv3_sock_put", "Enter(rs: %p)", rs);
	rdsv3_sk_sock_put(rdsv3_rs_to_sk(rs));
}

static void
rdsv3_sock_inc_info(struct rsock *sock, unsigned int len,
    struct rdsv3_info_iterator *iter, struct rdsv3_info_lengths *lens)
{
	struct rdsv3_sock *rs;
	struct rdsv3_incoming *inc;
	unsigned int total = 0;

	RDSV3_DPRINTF4("rdsv3_sock_inc_info", "Enter(rs: %p)",
	    rdsv3_sk_to_rs(sock));

	len /= sizeof (struct rds_info_message);

	mutex_enter(&rdsv3_sock_lock);

	RDSV3_FOR_EACH_LIST_NODE(rs, &rdsv3_sock_list, rs_item) {
		rw_enter(&rs->rs_recv_lock, RW_READER);

		/* XXX too lazy to maintain counts.. */
		RDSV3_FOR_EACH_LIST_NODE(inc, &rs->rs_recv_queue, i_item) {
			total++;
			if (total <= len)
				rdsv3_inc_info_copy(inc, iter, inc->i_saddr,
				    rs->rs_bound_addr, 1);
		}

		rw_exit(&rs->rs_recv_lock);
	}

	mutex_exit(&rdsv3_sock_lock);

	lens->nr = total;
	lens->each = sizeof (struct rds_info_message);

	RDSV3_DPRINTF4("rdsv3_sock_inc_info", "return(rs: %p)",
	    rdsv3_sk_to_rs(sock));
}

static void
rdsv3_sock_info(struct rsock *sock, unsigned int len,
    struct rdsv3_info_iterator *iter, struct rdsv3_info_lengths *lens)
{
	struct rds_info_socket sinfo;
	struct rdsv3_sock *rs;
	unsigned long bytes;

	RDSV3_DPRINTF4("rdsv3_sock_info", "Enter(rs: %p)",
	    rdsv3_sk_to_rs(sock));

	len /= sizeof (struct rds_info_socket);

	mutex_enter(&rdsv3_sock_lock);

	if ((len < rdsv3_sock_count) || (iter->addr == NULL))
		goto out;

	bytes = sizeof (struct rds_info_socket);
	RDSV3_FOR_EACH_LIST_NODE(rs, &rdsv3_sock_list, rs_item) {
		sinfo.sndbuf = rdsv3_sk_sndbuf(rs);
		sinfo.rcvbuf = rdsv3_sk_rcvbuf(rs);
		sinfo.bound_addr = rs->rs_bound_addr;
		sinfo.connected_addr = rs->rs_conn_addr;
		sinfo.bound_port = rs->rs_bound_port;
		sinfo.connected_port = rs->rs_conn_port;

		rdsv3_info_copy(iter, &sinfo, bytes);
	}

	RDSV3_DPRINTF4("rdsv3_sock_info", "Return(rs: %p)",
	    rdsv3_sk_to_rs(sock));

out:
	lens->nr = rdsv3_sock_count;
	lens->each = sizeof (struct rds_info_socket);

	mutex_exit(&rdsv3_sock_lock);
}

rdsv3_delayed_work_t	*rdsv3_rdma_dwp = NULL;
uint_t			rdsv3_rdma_init_delay = 5; /* secs */
extern void rdsv3_rdma_init_worker(struct rdsv3_work_s *work);

void
rdsv3_exit(void)
{
	RDSV3_DPRINTF4("rdsv3_exit", "Enter");

	if (rdsv3_rdma_dwp) {
		rdsv3_cancel_delayed_work(rdsv3_rdma_dwp);
	}

	(void) ddi_taskq_dispatch(rdsv3_taskq, rdsv3_rdma_exit,
	    NULL, DDI_SLEEP);
	while (rdsv3_rdma_listen_id != NULL) {
#ifndef __lock_lint
		RDSV3_DPRINTF5("rdsv3", "%s-%d Waiting for rdsv3_rdma_exit",
		    __func__, __LINE__);
#endif
		delay(drv_usectohz(1000));
	}

	rdsv3_conn_exit();
	rdsv3_cong_exit();
	rdsv3_sysctl_exit();
	rdsv3_threads_exit();
	rdsv3_stats_exit();
	rdsv3_info_deregister_func(RDS_INFO_SOCKETS, rdsv3_sock_info);
	rdsv3_info_deregister_func(RDS_INFO_RECV_MESSAGES,
	    rdsv3_sock_inc_info);

	if (rdsv3_rdma_dwp) {
		kmem_free(rdsv3_rdma_dwp, sizeof (rdsv3_delayed_work_t));
		rdsv3_rdma_dwp = NULL;
	}

	RDSV3_DPRINTF4("rdsv3_exit", "Return");
}

/*ARGSUSED*/
int
rdsv3_init()
{
	int ret;

	RDSV3_DPRINTF4("rdsv3_init", "Enter");

	rdsv3_cong_init();

	ret = rdsv3_conn_init();
	if (ret)
		goto out;
	ret = rdsv3_threads_init();
	if (ret)
		goto out_conn;
	ret = rdsv3_sysctl_init();
	if (ret)
		goto out_threads;
	ret = rdsv3_stats_init();
	if (ret)
		goto out_sysctl;

	rdsv3_info_register_func(RDS_INFO_SOCKETS, rdsv3_sock_info);
	rdsv3_info_register_func(RDS_INFO_RECV_MESSAGES, rdsv3_sock_inc_info);

	/* rdsv3_rdma_init need to be called with a little delay */
	rdsv3_rdma_dwp = kmem_zalloc(sizeof (rdsv3_delayed_work_t), KM_SLEEP);
	RDSV3_INIT_DELAYED_WORK(rdsv3_rdma_dwp, rdsv3_rdma_init_worker);
	rdsv3_queue_delayed_work(rdsv3_wq, rdsv3_rdma_dwp,
	    rdsv3_rdma_init_delay);

	RDSV3_DPRINTF4("rdsv3_init", "Return");

	goto out;

out_sysctl:
	rdsv3_sysctl_exit();
out_threads:
	rdsv3_threads_exit();
out_conn:
	rdsv3_conn_exit();
	rdsv3_cong_exit();
out:
	return (ret);
}
