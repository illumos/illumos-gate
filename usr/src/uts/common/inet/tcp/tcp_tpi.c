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

/* This files contains all TCP TLI/TPI related functions */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/stropts.h>
#include <sys/strlog.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/suntpi.h>
#include <sys/xti_inet.h>
#include <sys/squeue_impl.h>
#include <sys/squeue.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/tcp.h>
#include <inet/tcp_impl.h>
#include <inet/proto_set.h>

static void	tcp_accept_swap(tcp_t *, tcp_t *, tcp_t *);
static int	tcp_conprim_opt_process(tcp_t *, mblk_t *, int *, int *, int *);

void
tcp_use_pure_tpi(tcp_t *tcp)
{
	conn_t		*connp = tcp->tcp_connp;

#ifdef	_ILP32
	tcp->tcp_acceptor_id = (t_uscalar_t)connp->conn_rq;
#else
	tcp->tcp_acceptor_id = connp->conn_dev;
#endif
	/*
	 * Insert this socket into the acceptor hash.
	 * We might need it for T_CONN_RES message
	 */
	tcp_acceptor_hash_insert(tcp->tcp_acceptor_id, tcp);

	tcp->tcp_issocket = B_FALSE;
	TCP_STAT(tcp->tcp_tcps, tcp_sock_fallback);
}

/* Shorthand to generate and send TPI error acks to our client */
void
tcp_err_ack(tcp_t *tcp, mblk_t *mp, int t_error, int sys_error)
{
	if ((mp = mi_tpi_err_ack_alloc(mp, t_error, sys_error)) != NULL)
		putnext(tcp->tcp_connp->conn_rq, mp);
}

/* Shorthand to generate and send TPI error acks to our client */
void
tcp_err_ack_prim(tcp_t *tcp, mblk_t *mp, int primitive,
    int t_error, int sys_error)
{
	struct T_error_ack	*teackp;

	if ((mp = tpi_ack_alloc(mp, sizeof (struct T_error_ack),
	    M_PCPROTO, T_ERROR_ACK)) != NULL) {
		teackp = (struct T_error_ack *)mp->b_rptr;
		teackp->ERROR_prim = primitive;
		teackp->TLI_error = t_error;
		teackp->UNIX_error = sys_error;
		putnext(tcp->tcp_connp->conn_rq, mp);
	}
}

/*
 * TCP routine to get the values of options.
 */
int
tcp_tpi_opt_get(queue_t *q, int level, int name, uchar_t *ptr)
{
	return (tcp_opt_get(Q_TO_CONN(q), level, name, ptr));
}

/* ARGSUSED */
int
tcp_tpi_opt_set(queue_t *q, uint_t optset_context, int level, int name,
    uint_t inlen, uchar_t *invalp, uint_t *outlenp, uchar_t *outvalp,
    void *thisdg_attrs, cred_t *cr)
{
	conn_t	*connp =  Q_TO_CONN(q);

	return (tcp_opt_set(connp, optset_context, level, name, inlen, invalp,
	    outlenp, outvalp, thisdg_attrs, cr));
}

static int
tcp_conprim_opt_process(tcp_t *tcp, mblk_t *mp, int *do_disconnectp,
    int *t_errorp, int *sys_errorp)
{
	int error;
	int is_absreq_failure;
	t_scalar_t *opt_lenp;
	t_scalar_t opt_offset;
	int prim_type;
	struct T_conn_req *tcreqp;
	struct T_conn_res *tcresp;
	cred_t *cr;

	/*
	 * All Solaris components should pass a db_credp
	 * for this TPI message, hence we ASSERT.
	 * But in case there is some other M_PROTO that looks
	 * like a TPI message sent by some other kernel
	 * component, we check and return an error.
	 */
	cr = msg_getcred(mp, NULL);
	ASSERT(cr != NULL);
	if (cr == NULL)
		return (-1);

	prim_type = ((union T_primitives *)mp->b_rptr)->type;
	ASSERT(prim_type == T_CONN_REQ || prim_type == O_T_CONN_RES ||
	    prim_type == T_CONN_RES);

	switch (prim_type) {
	case T_CONN_REQ:
		tcreqp = (struct T_conn_req *)mp->b_rptr;
		opt_offset = tcreqp->OPT_offset;
		opt_lenp = (t_scalar_t *)&tcreqp->OPT_length;
		break;
	case O_T_CONN_RES:
	case T_CONN_RES:
		tcresp = (struct T_conn_res *)mp->b_rptr;
		opt_offset = tcresp->OPT_offset;
		opt_lenp = (t_scalar_t *)&tcresp->OPT_length;
		break;
	}

	*t_errorp = 0;
	*sys_errorp = 0;
	*do_disconnectp = 0;

	error = tpi_optcom_buf(tcp->tcp_connp->conn_wq, mp, opt_lenp,
	    opt_offset, cr, &tcp_opt_obj,
	    NULL, &is_absreq_failure);

	switch (error) {
	case  0:		/* no error */
		ASSERT(is_absreq_failure == 0);
		return (0);
	case ENOPROTOOPT:
		*t_errorp = TBADOPT;
		break;
	case EACCES:
		*t_errorp = TACCES;
		break;
	default:
		*t_errorp = TSYSERR; *sys_errorp = error;
		break;
	}
	if (is_absreq_failure != 0) {
		/*
		 * The connection request should get the local ack
		 * T_OK_ACK and then a T_DISCON_IND.
		 */
		*do_disconnectp = 1;
	}
	return (-1);
}

void
tcp_tpi_bind(tcp_t *tcp, mblk_t *mp)
{
	int	error;
	conn_t	*connp = tcp->tcp_connp;
	struct sockaddr	*sa;
	mblk_t  *mp1;
	struct T_bind_req *tbr;
	int	backlog;
	socklen_t	len;
	sin_t	*sin;
	sin6_t	*sin6;
	cred_t		*cr;

	/*
	 * All Solaris components should pass a db_credp
	 * for this TPI message, hence we ASSERT.
	 * But in case there is some other M_PROTO that looks
	 * like a TPI message sent by some other kernel
	 * component, we check and return an error.
	 */
	cr = msg_getcred(mp, NULL);
	ASSERT(cr != NULL);
	if (cr == NULL) {
		tcp_err_ack(tcp, mp, TSYSERR, EINVAL);
		return;
	}

	ASSERT((uintptr_t)(mp->b_wptr - mp->b_rptr) <= (uintptr_t)INT_MAX);
	if ((mp->b_wptr - mp->b_rptr) < sizeof (*tbr)) {
		if (connp->conn_debug) {
			(void) strlog(TCP_MOD_ID, 0, 1, SL_ERROR|SL_TRACE,
			    "tcp_tpi_bind: bad req, len %u",
			    (uint_t)(mp->b_wptr - mp->b_rptr));
		}
		tcp_err_ack(tcp, mp, TPROTO, 0);
		return;
	}
	/* Make sure the largest address fits */
	mp1 = reallocb(mp, sizeof (struct T_bind_ack) + sizeof (sin6_t), 1);
	if (mp1 == NULL) {
		tcp_err_ack(tcp, mp, TSYSERR, ENOMEM);
		return;
	}
	mp = mp1;
	tbr = (struct T_bind_req *)mp->b_rptr;

	backlog = tbr->CONIND_number;
	len = tbr->ADDR_length;

	switch (len) {
	case 0:		/* request for a generic port */
		tbr->ADDR_offset = sizeof (struct T_bind_req);
		if (connp->conn_family == AF_INET) {
			tbr->ADDR_length = sizeof (sin_t);
			sin = (sin_t *)&tbr[1];
			*sin = sin_null;
			sin->sin_family = AF_INET;
			sa = (struct sockaddr *)sin;
			len = sizeof (sin_t);
			mp->b_wptr = (uchar_t *)&sin[1];
		} else {
			ASSERT(connp->conn_family == AF_INET6);
			tbr->ADDR_length = sizeof (sin6_t);
			sin6 = (sin6_t *)&tbr[1];
			*sin6 = sin6_null;
			sin6->sin6_family = AF_INET6;
			sa = (struct sockaddr *)sin6;
			len = sizeof (sin6_t);
			mp->b_wptr = (uchar_t *)&sin6[1];
		}
		break;

	case sizeof (sin_t):    /* Complete IPv4 address */
		sa = (struct sockaddr *)mi_offset_param(mp, tbr->ADDR_offset,
		    sizeof (sin_t));
		break;

	case sizeof (sin6_t): /* Complete IPv6 address */
		sa = (struct sockaddr *)mi_offset_param(mp,
		    tbr->ADDR_offset, sizeof (sin6_t));
		break;

	default:
		if (connp->conn_debug) {
			(void) strlog(TCP_MOD_ID, 0, 1, SL_ERROR|SL_TRACE,
			    "tcp_tpi_bind: bad address length, %d",
			    tbr->ADDR_length);
		}
		tcp_err_ack(tcp, mp, TBADADDR, 0);
		return;
	}

	if (backlog > 0) {
		error = tcp_do_listen(connp, sa, len, backlog, DB_CRED(mp),
		    tbr->PRIM_type != O_T_BIND_REQ);
	} else {
		error = tcp_do_bind(connp, sa, len, DB_CRED(mp),
		    tbr->PRIM_type != O_T_BIND_REQ);
	}
done:
	if (error > 0) {
		tcp_err_ack(tcp, mp, TSYSERR, error);
	} else if (error < 0) {
		tcp_err_ack(tcp, mp, -error, 0);
	} else {
		/*
		 * Update port information as sockfs/tpi needs it for checking
		 */
		if (connp->conn_family == AF_INET) {
			sin = (sin_t *)sa;
			sin->sin_port = connp->conn_lport;
		} else {
			sin6 = (sin6_t *)sa;
			sin6->sin6_port = connp->conn_lport;
		}
		mp->b_datap->db_type = M_PCPROTO;
		tbr->PRIM_type = T_BIND_ACK;
		putnext(connp->conn_rq, mp);
	}
}

/* tcp_unbind is called by tcp_wput_proto to handle T_UNBIND_REQ messages. */
void
tcp_tpi_unbind(tcp_t *tcp, mblk_t *mp)
{
	conn_t *connp = tcp->tcp_connp;
	int error;

	error = tcp_do_unbind(connp);
	if (error > 0) {
		tcp_err_ack(tcp, mp, TSYSERR, error);
	} else if (error < 0) {
		tcp_err_ack(tcp, mp, -error, 0);
	} else {
		/* Send M_FLUSH according to TPI */
		(void) putnextctl1(connp->conn_rq, M_FLUSH, FLUSHRW);

		mp = mi_tpi_ok_ack_alloc(mp);
		if (mp != NULL)
			putnext(connp->conn_rq, mp);
	}
}

int
tcp_tpi_close(queue_t *q, int flags)
{
	conn_t		*connp;

	ASSERT(WR(q)->q_next == NULL);

	if (flags & SO_FALLBACK) {
		/*
		 * stream is being closed while in fallback
		 * simply free the resources that were allocated
		 */
		inet_minor_free(WR(q)->q_ptr, (dev_t)(RD(q)->q_ptr));
		qprocsoff(q);
		goto done;
	}

	connp = Q_TO_CONN(q);
	/*
	 * We are being closed as /dev/tcp or /dev/tcp6.
	 */
	tcp_close_common(connp, flags);

	qprocsoff(q);
	inet_minor_free(connp->conn_minor_arena, connp->conn_dev);

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
done:
	q->q_ptr = WR(q)->q_ptr = NULL;
	return (0);
}

int
tcp_tpi_close_accept(queue_t *q)
{
	vmem_t	*minor_arena;
	dev_t	conn_dev;
	extern struct qinit tcp_acceptor_winit;

	ASSERT(WR(q)->q_qinfo == &tcp_acceptor_winit);

	/*
	 * We had opened an acceptor STREAM for sockfs which is
	 * now being closed due to some error.
	 */
	qprocsoff(q);

	minor_arena = (vmem_t *)WR(q)->q_ptr;
	conn_dev = (dev_t)RD(q)->q_ptr;
	ASSERT(minor_arena != NULL);
	ASSERT(conn_dev != 0);
	inet_minor_free(minor_arena, conn_dev);
	q->q_ptr = WR(q)->q_ptr = NULL;
	return (0);
}

/*
 * Put a connection confirmation message upstream built from the
 * address/flowid information with the conn and iph. Report our success or
 * failure.
 */
boolean_t
tcp_conn_con(tcp_t *tcp, uchar_t *iphdr, mblk_t *idmp,
    mblk_t **defermp, ip_recv_attr_t *ira)
{
	sin_t	sin;
	sin6_t	sin6;
	mblk_t	*mp;
	char	*optp = NULL;
	int	optlen = 0;
	conn_t	*connp = tcp->tcp_connp;

	if (defermp != NULL)
		*defermp = NULL;

	if (tcp->tcp_conn.tcp_opts_conn_req != NULL) {
		/*
		 * Return in T_CONN_CON results of option negotiation through
		 * the T_CONN_REQ. Note: If there is an real end-to-end option
		 * negotiation, then what is received from remote end needs
		 * to be taken into account but there is no such thing (yet?)
		 * in our TCP/IP.
		 * Note: We do not use mi_offset_param() here as
		 * tcp_opts_conn_req contents do not directly come from
		 * an application and are either generated in kernel or
		 * from user input that was already verified.
		 */
		mp = tcp->tcp_conn.tcp_opts_conn_req;
		optp = (char *)(mp->b_rptr +
		    ((struct T_conn_req *)mp->b_rptr)->OPT_offset);
		optlen = (int)
		    ((struct T_conn_req *)mp->b_rptr)->OPT_length;
	}

	if (IPH_HDR_VERSION(iphdr) == IPV4_VERSION) {

		/* packet is IPv4 */
		if (connp->conn_family == AF_INET) {
			sin = sin_null;
			sin.sin_addr.s_addr = connp->conn_faddr_v4;
			sin.sin_port = connp->conn_fport;
			sin.sin_family = AF_INET;
			mp = mi_tpi_conn_con(NULL, (char *)&sin,
			    (int)sizeof (sin_t), optp, optlen);
		} else {
			sin6 = sin6_null;
			sin6.sin6_addr = connp->conn_faddr_v6;
			sin6.sin6_port = connp->conn_fport;
			sin6.sin6_family = AF_INET6;
			mp = mi_tpi_conn_con(NULL, (char *)&sin6,
			    (int)sizeof (sin6_t), optp, optlen);

		}
	} else {
		ip6_t	*ip6h = (ip6_t *)iphdr;

		ASSERT(IPH_HDR_VERSION(iphdr) == IPV6_VERSION);
		ASSERT(connp->conn_family == AF_INET6);
		sin6 = sin6_null;
		sin6.sin6_addr = connp->conn_faddr_v6;
		sin6.sin6_port = connp->conn_fport;
		sin6.sin6_family = AF_INET6;
		sin6.sin6_flowinfo = ip6h->ip6_vcf & ~IPV6_VERS_AND_FLOW_MASK;
		mp = mi_tpi_conn_con(NULL, (char *)&sin6,
		    (int)sizeof (sin6_t), optp, optlen);
	}

	if (!mp)
		return (B_FALSE);

	mblk_copycred(mp, idmp);

	if (defermp == NULL) {
		conn_t *connp = tcp->tcp_connp;
		if (IPCL_IS_NONSTR(connp)) {
			(*connp->conn_upcalls->su_connected)
			    (connp->conn_upper_handle, tcp->tcp_connid,
			    ira->ira_cred, ira->ira_cpid);
			freemsg(mp);
		} else {
			if (ira->ira_cred != NULL) {
				/* So that getpeerucred works for TPI sockfs */
				mblk_setcred(mp, ira->ira_cred, ira->ira_cpid);
			}
			putnext(connp->conn_rq, mp);
		}
	} else {
		*defermp = mp;
	}

	if (tcp->tcp_conn.tcp_opts_conn_req != NULL)
		tcp_close_mpp(&tcp->tcp_conn.tcp_opts_conn_req);
	return (B_TRUE);
}

/*
 * Successful connect request processing begins when our client passes
 * a T_CONN_REQ message into tcp_wput(), which performs function calls into
 * IP and the passes a T_OK_ACK (or T_ERROR_ACK upstream).
 *
 * After various error checks are completed, tcp_tpi_connect() lays
 * the target address and port into the composite header template.
 * Then we ask IP for information, including a source address if we didn't
 * already have one. Finally we prepare to send the SYN packet, and then
 * send up the T_OK_ACK reply message.
 */
void
tcp_tpi_connect(tcp_t *tcp, mblk_t *mp)
{
	sin_t		*sin;
	struct T_conn_req	*tcr;
	struct sockaddr	*sa;
	socklen_t	len;
	int		error;
	cred_t		*cr;
	pid_t		cpid;
	conn_t		*connp = tcp->tcp_connp;
	queue_t		*q = connp->conn_wq;

	/*
	 * All Solaris components should pass a db_credp
	 * for this TPI message, hence we ASSERT.
	 * But in case there is some other M_PROTO that looks
	 * like a TPI message sent by some other kernel
	 * component, we check and return an error.
	 */
	cr = msg_getcred(mp, &cpid);
	ASSERT(cr != NULL);
	if (cr == NULL) {
		tcp_err_ack(tcp, mp, TSYSERR, EINVAL);
		return;
	}

	tcr = (struct T_conn_req *)mp->b_rptr;

	ASSERT((uintptr_t)(mp->b_wptr - mp->b_rptr) <= (uintptr_t)INT_MAX);
	if ((mp->b_wptr - mp->b_rptr) < sizeof (*tcr)) {
		tcp_err_ack(tcp, mp, TPROTO, 0);
		return;
	}

	/*
	 * Pre-allocate the T_ordrel_ind mblk so that at close time, we
	 * will always have that to send up.  Otherwise, we need to do
	 * special handling in case the allocation fails at that time.
	 * If the end point is TPI, the tcp_t can be reused and the
	 * tcp_ordrel_mp may be allocated already.
	 */
	if (tcp->tcp_ordrel_mp == NULL) {
		if ((tcp->tcp_ordrel_mp = mi_tpi_ordrel_ind()) == NULL) {
			tcp_err_ack(tcp, mp, TSYSERR, ENOMEM);
			return;
		}
	}

	/*
	 * Determine packet type based on type of address passed in
	 * the request should contain an IPv4 or IPv6 address.
	 * Make sure that address family matches the type of
	 * family of the address passed down.
	 */
	switch (tcr->DEST_length) {
	default:
		tcp_err_ack(tcp, mp, TBADADDR, 0);
		return;

	case (sizeof (sin_t) - sizeof (sin->sin_zero)): {
		/*
		 * XXX: The check for valid DEST_length was not there
		 * in earlier releases and some buggy
		 * TLI apps (e.g Sybase) got away with not feeding
		 * in sin_zero part of address.
		 * We allow that bug to keep those buggy apps humming.
		 * Test suites require the check on DEST_length.
		 * We construct a new mblk with valid DEST_length
		 * free the original so the rest of the code does
		 * not have to keep track of this special shorter
		 * length address case.
		 */
		mblk_t *nmp;
		struct T_conn_req *ntcr;
		sin_t *nsin;

		nmp = allocb(sizeof (struct T_conn_req) + sizeof (sin_t) +
		    tcr->OPT_length, BPRI_HI);
		if (nmp == NULL) {
			tcp_err_ack(tcp, mp, TSYSERR, ENOMEM);
			return;
		}
		ntcr = (struct T_conn_req *)nmp->b_rptr;
		bzero(ntcr, sizeof (struct T_conn_req)); /* zero fill */
		ntcr->PRIM_type = T_CONN_REQ;
		ntcr->DEST_length = sizeof (sin_t);
		ntcr->DEST_offset = sizeof (struct T_conn_req);

		nsin = (sin_t *)((uchar_t *)ntcr + ntcr->DEST_offset);
		*nsin = sin_null;
		/* Get pointer to shorter address to copy from original mp */
		sin = (sin_t *)mi_offset_param(mp, tcr->DEST_offset,
		    tcr->DEST_length); /* extract DEST_length worth of sin_t */
		if (sin == NULL || !OK_32PTR((char *)sin)) {
			freemsg(nmp);
			tcp_err_ack(tcp, mp, TSYSERR, EINVAL);
			return;
		}
		nsin->sin_family = sin->sin_family;
		nsin->sin_port = sin->sin_port;
		nsin->sin_addr = sin->sin_addr;
		/* Note:nsin->sin_zero zero-fill with sin_null assign above */
		nmp->b_wptr = (uchar_t *)&nsin[1];
		if (tcr->OPT_length != 0) {
			ntcr->OPT_length = tcr->OPT_length;
			ntcr->OPT_offset = nmp->b_wptr - nmp->b_rptr;
			bcopy((uchar_t *)tcr + tcr->OPT_offset,
			    (uchar_t *)ntcr + ntcr->OPT_offset,
			    tcr->OPT_length);
			nmp->b_wptr += tcr->OPT_length;
		}
		freemsg(mp);	/* original mp freed */
		mp = nmp;	/* re-initialize original variables */
		tcr = ntcr;
	}
	/* FALLTHRU */

	case sizeof (sin_t):
		sa = (struct sockaddr *)mi_offset_param(mp, tcr->DEST_offset,
		    sizeof (sin_t));
		len = sizeof (sin_t);
		break;

	case sizeof (sin6_t):
		sa = (struct sockaddr *)mi_offset_param(mp, tcr->DEST_offset,
		    sizeof (sin6_t));
		len = sizeof (sin6_t);
		break;
	}

	error = proto_verify_ip_addr(connp->conn_family, sa, len);
	if (error != 0) {
		tcp_err_ack(tcp, mp, TSYSERR, error);
		return;
	}

	/*
	 * TODO: If someone in TCPS_TIME_WAIT has this dst/port we
	 * should key on their sequence number and cut them loose.
	 */

	/*
	 * If options passed in, feed it for verification and handling
	 */
	if (tcr->OPT_length != 0) {
		mblk_t	*ok_mp;
		mblk_t	*discon_mp;
		mblk_t  *conn_opts_mp;
		int t_error, sys_error, do_disconnect;

		conn_opts_mp = NULL;

		if (tcp_conprim_opt_process(tcp, mp,
		    &do_disconnect, &t_error, &sys_error) < 0) {
			if (do_disconnect) {
				ASSERT(t_error == 0 && sys_error == 0);
				discon_mp = mi_tpi_discon_ind(NULL,
				    ECONNREFUSED, 0);
				if (!discon_mp) {
					tcp_err_ack_prim(tcp, mp, T_CONN_REQ,
					    TSYSERR, ENOMEM);
					return;
				}
				ok_mp = mi_tpi_ok_ack_alloc(mp);
				if (!ok_mp) {
					tcp_err_ack_prim(tcp, NULL, T_CONN_REQ,
					    TSYSERR, ENOMEM);
					return;
				}
				qreply(q, ok_mp);
				qreply(q, discon_mp); /* no flush! */
			} else {
				ASSERT(t_error != 0);
				tcp_err_ack_prim(tcp, mp, T_CONN_REQ, t_error,
				    sys_error);
			}
			return;
		}
		/*
		 * Success in setting options, the mp option buffer represented
		 * by OPT_length/offset has been potentially modified and
		 * contains results of option processing. We copy it in
		 * another mp to save it for potentially influencing returning
		 * it in T_CONN_CONN.
		 */
		if (tcr->OPT_length != 0) { /* there are resulting options */
			conn_opts_mp = copyb(mp);
			if (!conn_opts_mp) {
				tcp_err_ack_prim(tcp, mp, T_CONN_REQ,
				    TSYSERR, ENOMEM);
				return;
			}
			ASSERT(tcp->tcp_conn.tcp_opts_conn_req == NULL);
			tcp->tcp_conn.tcp_opts_conn_req = conn_opts_mp;
			/*
			 * Note:
			 * These resulting option negotiation can include any
			 * end-to-end negotiation options but there no such
			 * thing (yet?) in our TCP/IP.
			 */
		}
	}

	/* call the non-TPI version */
	error = tcp_do_connect(tcp->tcp_connp, sa, len, cr, cpid);
	if (error < 0) {
		mp = mi_tpi_err_ack_alloc(mp, -error, 0);
	} else if (error > 0) {
		mp = mi_tpi_err_ack_alloc(mp, TSYSERR, error);
	} else {
		mp = mi_tpi_ok_ack_alloc(mp);
	}

	/*
	 * Note: Code below is the "failure" case
	 */
	/* return error ack and blow away saved option results if any */
connect_failed:
	if (mp != NULL)
		putnext(connp->conn_rq, mp);
	else {
		tcp_err_ack_prim(tcp, NULL, T_CONN_REQ,
		    TSYSERR, ENOMEM);
	}
}

/* Return the TPI/TLI equivalent of our current tcp_state */
static int
tcp_tpistate(tcp_t *tcp)
{
	switch (tcp->tcp_state) {
	case TCPS_IDLE:
		return (TS_UNBND);
	case TCPS_LISTEN:
		/*
		 * Return whether there are outstanding T_CONN_IND waiting
		 * for the matching T_CONN_RES. Therefore don't count q0.
		 */
		if (tcp->tcp_conn_req_cnt_q > 0)
			return (TS_WRES_CIND);
		else
			return (TS_IDLE);
	case TCPS_BOUND:
		return (TS_IDLE);
	case TCPS_SYN_SENT:
		return (TS_WCON_CREQ);
	case TCPS_SYN_RCVD:
		/*
		 * Note: assumption: this has to the active open SYN_RCVD.
		 * The passive instance is detached in SYN_RCVD stage of
		 * incoming connection processing so we cannot get request
		 * for T_info_ack on it.
		 */
		return (TS_WACK_CRES);
	case TCPS_ESTABLISHED:
		return (TS_DATA_XFER);
	case TCPS_CLOSE_WAIT:
		return (TS_WREQ_ORDREL);
	case TCPS_FIN_WAIT_1:
		return (TS_WIND_ORDREL);
	case TCPS_FIN_WAIT_2:
		return (TS_WIND_ORDREL);

	case TCPS_CLOSING:
	case TCPS_LAST_ACK:
	case TCPS_TIME_WAIT:
	case TCPS_CLOSED:
		/*
		 * Following TS_WACK_DREQ7 is a rendition of "not
		 * yet TS_IDLE" TPI state. There is no best match to any
		 * TPI state for TCPS_{CLOSING, LAST_ACK, TIME_WAIT} but we
		 * choose a value chosen that will map to TLI/XTI level
		 * state of TSTATECHNG (state is process of changing) which
		 * captures what this dummy state represents.
		 */
		return (TS_WACK_DREQ7);
	default:
		cmn_err(CE_WARN, "tcp_tpistate: strange state (%d) %s",
		    tcp->tcp_state, tcp_display(tcp, NULL,
		    DISP_PORT_ONLY));
		return (TS_UNBND);
	}
}

static void
tcp_copy_info(struct T_info_ack *tia, tcp_t *tcp)
{
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	conn_t		*connp = tcp->tcp_connp;
	extern struct T_info_ack tcp_g_t_info_ack;
	extern struct T_info_ack tcp_g_t_info_ack_v6;

	if (connp->conn_family == AF_INET6)
		*tia = tcp_g_t_info_ack_v6;
	else
		*tia = tcp_g_t_info_ack;
	tia->CURRENT_state = tcp_tpistate(tcp);
	tia->OPT_size = tcp_max_optsize;
	if (tcp->tcp_mss == 0) {
		/* Not yet set - tcp_open does not set mss */
		if (connp->conn_ipversion == IPV4_VERSION)
			tia->TIDU_size = tcps->tcps_mss_def_ipv4;
		else
			tia->TIDU_size = tcps->tcps_mss_def_ipv6;
	} else {
		tia->TIDU_size = tcp->tcp_mss;
	}
	/* TODO: Default ETSDU is 1.  Is that correct for tcp? */
}

void
tcp_do_capability_ack(tcp_t *tcp, struct T_capability_ack *tcap,
    t_uscalar_t cap_bits1)
{
	tcap->CAP_bits1 = 0;

	if (cap_bits1 & TC1_INFO) {
		tcp_copy_info(&tcap->INFO_ack, tcp);
		tcap->CAP_bits1 |= TC1_INFO;
	}

	if (cap_bits1 & TC1_ACCEPTOR_ID) {
		tcap->ACCEPTOR_id = tcp->tcp_acceptor_id;
		tcap->CAP_bits1 |= TC1_ACCEPTOR_ID;
	}

}

/*
 * This routine responds to T_CAPABILITY_REQ messages.  It is called by
 * tcp_wput.  Much of the T_CAPABILITY_ACK information is copied from
 * tcp_g_t_info_ack.  The current state of the stream is copied from
 * tcp_state.
 */
void
tcp_capability_req(tcp_t *tcp, mblk_t *mp)
{
	t_uscalar_t		cap_bits1;
	struct T_capability_ack	*tcap;

	if (MBLKL(mp) < sizeof (struct T_capability_req)) {
		freemsg(mp);
		return;
	}

	cap_bits1 = ((struct T_capability_req *)mp->b_rptr)->CAP_bits1;

	mp = tpi_ack_alloc(mp, sizeof (struct T_capability_ack),
	    mp->b_datap->db_type, T_CAPABILITY_ACK);
	if (mp == NULL)
		return;

	tcap = (struct T_capability_ack *)mp->b_rptr;
	tcp_do_capability_ack(tcp, tcap, cap_bits1);

	putnext(tcp->tcp_connp->conn_rq, mp);
}

/*
 * This routine responds to T_INFO_REQ messages.  It is called by tcp_wput.
 * Most of the T_INFO_ACK information is copied from tcp_g_t_info_ack.
 * The current state of the stream is copied from tcp_state.
 */
void
tcp_info_req(tcp_t *tcp, mblk_t *mp)
{
	mp = tpi_ack_alloc(mp, sizeof (struct T_info_ack), M_PCPROTO,
	    T_INFO_ACK);
	if (!mp) {
		tcp_err_ack(tcp, mp, TSYSERR, ENOMEM);
		return;
	}
	tcp_copy_info((struct T_info_ack *)mp->b_rptr, tcp);
	putnext(tcp->tcp_connp->conn_rq, mp);
}

/* Respond to the TPI addr request */
void
tcp_addr_req(tcp_t *tcp, mblk_t *mp)
{
	struct sockaddr *sa;
	mblk_t	*ackmp;
	struct T_addr_ack *taa;
	conn_t	*connp = tcp->tcp_connp;
	uint_t	addrlen;

	/* Make it large enough for worst case */
	ackmp = reallocb(mp, sizeof (struct T_addr_ack) +
	    2 * sizeof (sin6_t), 1);
	if (ackmp == NULL) {
		tcp_err_ack(tcp, mp, TSYSERR, ENOMEM);
		return;
	}

	taa = (struct T_addr_ack *)ackmp->b_rptr;

	bzero(taa, sizeof (struct T_addr_ack));
	ackmp->b_wptr = (uchar_t *)&taa[1];

	taa->PRIM_type = T_ADDR_ACK;
	ackmp->b_datap->db_type = M_PCPROTO;

	if (connp->conn_family == AF_INET)
		addrlen = sizeof (sin_t);
	else
		addrlen = sizeof (sin6_t);

	/*
	 * Note: Following code assumes 32 bit alignment of basic
	 * data structures like sin_t and struct T_addr_ack.
	 */
	if (tcp->tcp_state >= TCPS_BOUND) {
		/*
		 * Fill in local address first
		 */
		taa->LOCADDR_offset = sizeof (*taa);
		taa->LOCADDR_length = addrlen;
		sa = (struct sockaddr *)&taa[1];
		(void) conn_getsockname(connp, sa, &addrlen);
		ackmp->b_wptr += addrlen;
	}
	if (tcp->tcp_state >= TCPS_SYN_RCVD) {
		/*
		 * Fill in Remote address
		 */
		taa->REMADDR_length = addrlen;
		/* assumed 32-bit alignment */
		taa->REMADDR_offset = taa->LOCADDR_offset + taa->LOCADDR_length;
		sa = (struct sockaddr *)(ackmp->b_rptr + taa->REMADDR_offset);
		(void) conn_getpeername(connp, sa, &addrlen);
		ackmp->b_wptr += addrlen;
	}
	ASSERT(ackmp->b_wptr <= ackmp->b_datap->db_lim);
	putnext(tcp->tcp_connp->conn_rq, ackmp);
}

/*
 * Swap information between the eager and acceptor for a TLI/XTI client.
 * The sockfs accept is done on the acceptor stream and control goes
 * through tcp_tli_accept() and tcp_accept()/tcp_accept_swap() is not
 * called. In either case, both the eager and listener are in their own
 * perimeter (squeue) and the code has to deal with potential race.
 *
 * See the block comment on top of tcp_accept() and tcp_tli_accept().
 */
static void
tcp_accept_swap(tcp_t *listener, tcp_t *acceptor, tcp_t *eager)
{
	conn_t	*econnp, *aconnp;

	ASSERT(eager->tcp_connp->conn_rq == listener->tcp_connp->conn_rq);
	ASSERT(eager->tcp_detached && !acceptor->tcp_detached);
	ASSERT(!TCP_IS_SOCKET(acceptor));
	ASSERT(!TCP_IS_SOCKET(eager));
	ASSERT(!TCP_IS_SOCKET(listener));

	/*
	 * Trusted Extensions may need to use a security label that is
	 * different from the acceptor's label on MLP and MAC-Exempt
	 * sockets. If this is the case, the required security label
	 * already exists in econnp->conn_ixa->ixa_tsl. Since we make the
	 * acceptor stream refer to econnp we atomatically get that label.
	 */

	acceptor->tcp_detached = B_TRUE;
	/*
	 * To permit stream re-use by TLI/XTI, the eager needs a copy of
	 * the acceptor id.
	 */
	eager->tcp_acceptor_id = acceptor->tcp_acceptor_id;

	/* remove eager from listen list... */
	mutex_enter(&listener->tcp_eager_lock);
	tcp_eager_unlink(eager);
	ASSERT(eager->tcp_eager_next_q == NULL &&
	    eager->tcp_eager_last_q == NULL);
	ASSERT(eager->tcp_eager_next_q0 == NULL &&
	    eager->tcp_eager_prev_q0 == NULL);
	mutex_exit(&listener->tcp_eager_lock);

	econnp = eager->tcp_connp;
	aconnp = acceptor->tcp_connp;
	econnp->conn_rq = aconnp->conn_rq;
	econnp->conn_wq = aconnp->conn_wq;
	econnp->conn_rq->q_ptr = econnp;
	econnp->conn_wq->q_ptr = econnp;

	/*
	 * In the TLI/XTI loopback case, we are inside the listener's squeue,
	 * which might be a different squeue from our peer TCP instance.
	 * For TCP Fusion, the peer expects that whenever tcp_detached is
	 * clear, our TCP queues point to the acceptor's queues.  Thus, use
	 * membar_producer() to ensure that the assignments of conn_rq/conn_wq
	 * above reach global visibility prior to the clearing of tcp_detached.
	 */
	membar_producer();
	eager->tcp_detached = B_FALSE;

	ASSERT(eager->tcp_ack_tid == 0);

	econnp->conn_dev = aconnp->conn_dev;
	econnp->conn_minor_arena = aconnp->conn_minor_arena;

	ASSERT(econnp->conn_minor_arena != NULL);
	if (econnp->conn_cred != NULL)
		crfree(econnp->conn_cred);
	econnp->conn_cred = aconnp->conn_cred;
	ASSERT(!(econnp->conn_ixa->ixa_free_flags & IXA_FREE_CRED));
	econnp->conn_ixa->ixa_cred = econnp->conn_cred;
	aconnp->conn_cred = NULL;
	econnp->conn_cpid = aconnp->conn_cpid;
	ASSERT(econnp->conn_netstack == aconnp->conn_netstack);
	ASSERT(eager->tcp_tcps == acceptor->tcp_tcps);

	econnp->conn_zoneid = aconnp->conn_zoneid;
	econnp->conn_allzones = aconnp->conn_allzones;
	econnp->conn_ixa->ixa_zoneid = aconnp->conn_ixa->ixa_zoneid;

	econnp->conn_mac_mode = aconnp->conn_mac_mode;
	econnp->conn_zone_is_global = aconnp->conn_zone_is_global;
	aconnp->conn_mac_mode = CONN_MAC_DEFAULT;

	/* Do the IPC initialization */
	CONN_INC_REF(econnp);

	/* Done with old IPC. Drop its ref on its connp */
	CONN_DEC_REF(aconnp);
}

/*
 * This runs at the tail end of accept processing on the squeue of the
 * new connection.
 */
/* ARGSUSED */
static void
tcp_accept_finish(void *arg, mblk_t *mp, void *arg2, ip_recv_attr_t *dummy)
{
	conn_t			*connp = (conn_t *)arg;
	tcp_t			*tcp = connp->conn_tcp;
	queue_t			*q = connp->conn_rq;
	tcp_stack_t		*tcps = tcp->tcp_tcps;
	struct stroptions 	*stropt;
	struct sock_proto_props sopp;

	/* Should never be called for non-STREAMS sockets */
	ASSERT(!IPCL_IS_NONSTR(connp));

	/* We should just receive a single mblk that fits a T_discon_ind */
	ASSERT(mp->b_cont == NULL);

	/*
	 * Drop the eager's ref on the listener, that was placed when
	 * this eager began life in tcp_input_listener.
	 */
	CONN_DEC_REF(tcp->tcp_saved_listener->tcp_connp);

	tcp->tcp_detached = B_FALSE;

	if (tcp->tcp_state <= TCPS_BOUND || tcp->tcp_accept_error) {
		/*
		 * Someone blewoff the eager before we could finish
		 * the accept.
		 *
		 * The only reason eager exists it because we put in
		 * a ref on it when conn ind went up. We need to send
		 * a disconnect indication up while the last reference
		 * on the eager will be dropped by the squeue when we
		 * return.
		 */
		ASSERT(tcp->tcp_listener == NULL);
		if (tcp->tcp_issocket || tcp->tcp_send_discon_ind) {
			struct	T_discon_ind	*tdi;

			(void) putnextctl1(q, M_FLUSH, FLUSHRW);
			/*
			 * Let us reuse the incoming mblk to avoid
			 * memory allocation failure problems. We know
			 * that the size of the incoming mblk i.e.
			 * stroptions is greater than sizeof
			 * T_discon_ind.
			 */
			ASSERT(DB_REF(mp) == 1);
			ASSERT(MBLKSIZE(mp) >=
			    sizeof (struct T_discon_ind));

			DB_TYPE(mp) = M_PROTO;
			((union T_primitives *)mp->b_rptr)->type =
			    T_DISCON_IND;
			tdi = (struct T_discon_ind *)mp->b_rptr;
			if (tcp->tcp_issocket) {
				tdi->DISCON_reason = ECONNREFUSED;
				tdi->SEQ_number = 0;
			} else {
				tdi->DISCON_reason = ENOPROTOOPT;
				tdi->SEQ_number =
				    tcp->tcp_conn_req_seqnum;
			}
			mp->b_wptr = mp->b_rptr +
			    sizeof (struct T_discon_ind);
			putnext(q, mp);
		}
		tcp->tcp_hard_binding = B_FALSE;
		return;
	}

	/*
	 * This is the first time we run on the correct
	 * queue after tcp_accept. So fix all the q parameters
	 * here.
	 *
	 * Let us reuse the incoming mblk to avoid
	 * memory allocation failure problems. We know
	 * that the size of the incoming mblk is at least
	 * stroptions
	 */
	tcp_get_proto_props(tcp, &sopp);

	ASSERT(DB_REF(mp) == 1);
	ASSERT(MBLKSIZE(mp) >= sizeof (struct stroptions));

	DB_TYPE(mp) = M_SETOPTS;
	stropt = (struct stroptions *)mp->b_rptr;
	mp->b_wptr = mp->b_rptr + sizeof (struct stroptions);
	stropt = (struct stroptions *)mp->b_rptr;
	ASSERT(sopp.sopp_flags & (SO_HIWAT|SO_WROFF|SO_MAXBLK));
	stropt->so_flags = SO_HIWAT | SO_WROFF | SO_MAXBLK;
	stropt->so_hiwat = sopp.sopp_rxhiwat;
	stropt->so_wroff = sopp.sopp_wroff;
	stropt->so_maxblk = sopp.sopp_maxblk;

	/* Send the options up */
	putnext(q, mp);

	/*
	 * Pass up any data and/or a fin that has been received.
	 *
	 * Adjust receive window in case it had decreased
	 * (because there is data <=> tcp_rcv_list != NULL)
	 * while the connection was detached. Note that
	 * in case the eager was flow-controlled, w/o this
	 * code, the rwnd may never open up again!
	 */
	if (tcp->tcp_rcv_list != NULL) {
		/* We drain directly in case of fused tcp loopback */

		if (!tcp->tcp_fused && canputnext(q)) {
			tcp->tcp_rwnd = connp->conn_rcvbuf;
			if (tcp->tcp_state >= TCPS_ESTABLISHED &&
			    tcp_rwnd_reopen(tcp) == TH_ACK_NEEDED) {
				tcp_xmit_ctl(NULL,
				    tcp, (tcp->tcp_swnd == 0) ?
				    tcp->tcp_suna : tcp->tcp_snxt,
				    tcp->tcp_rnxt, TH_ACK);
			}
		}

		(void) tcp_rcv_drain(tcp);

		/*
		 * For fused tcp loopback, back-enable peer endpoint
		 * if it's currently flow-controlled.
		 */
		if (tcp->tcp_fused) {
			tcp_t *peer_tcp = tcp->tcp_loopback_peer;

			ASSERT(peer_tcp != NULL);
			ASSERT(peer_tcp->tcp_fused);

			mutex_enter(&peer_tcp->tcp_non_sq_lock);
			if (peer_tcp->tcp_flow_stopped) {
				tcp_clrqfull(peer_tcp);
				TCP_STAT(tcps, tcp_fusion_backenabled);
			}
			mutex_exit(&peer_tcp->tcp_non_sq_lock);
		}
	}
	ASSERT(tcp->tcp_rcv_list == NULL || tcp->tcp_fused_sigurg);
	if (tcp->tcp_fin_rcvd && !tcp->tcp_ordrel_done) {
		tcp->tcp_ordrel_done = B_TRUE;
		mp = tcp->tcp_ordrel_mp;
		tcp->tcp_ordrel_mp = NULL;
		putnext(q, mp);
	}
	tcp->tcp_hard_binding = B_FALSE;

	if (connp->conn_keepalive) {
		tcp->tcp_ka_last_intrvl = 0;
		tcp->tcp_ka_tid = TCP_TIMER(tcp, tcp_keepalive_timer,
		    tcp->tcp_ka_interval);
	}

	/*
	 * At this point, eager is fully established and will
	 * have the following references -
	 *
	 * 2 references for connection to exist (1 for TCP and 1 for IP).
	 * 1 reference for the squeue which will be dropped by the squeue as
	 *	soon as this function returns.
	 * There will be 1 additonal reference for being in classifier
	 *	hash list provided something bad hasn't happened.
	 */
	ASSERT((connp->conn_fanout != NULL && connp->conn_ref >= 4) ||
	    (connp->conn_fanout == NULL && connp->conn_ref >= 3));
}

/*
 * Pull a deferred connection indication off of the listener. The caller
 * must verify that there is a deferred conn ind under eager_lock before
 * calling this function.
 */
static mblk_t *
tcp_get_def_conn_ind(tcp_t *listener)
{
	tcp_t *tail;
	tcp_t *tcp;
	mblk_t *conn_ind;

	ASSERT(MUTEX_HELD(&listener->tcp_eager_lock));
	ASSERT(listener->tcp_eager_prev_q0->tcp_conn_def_q0);

	tcp = listener->tcp_eager_prev_q0;
	/*
	 * listener->tcp_eager_prev_q0 points to the TAIL of the
	 * deferred T_conn_ind queue. We need to get to the head
	 * of the queue in order to send up T_conn_ind the same
	 * order as how the 3WHS is completed.
	 */
	while (tcp != listener) {
		if (!tcp->tcp_eager_prev_q0->tcp_conn_def_q0)
			break;
		else
			tcp = tcp->tcp_eager_prev_q0;
	}

	conn_ind = tcp->tcp_conn.tcp_eager_conn_ind;
	tcp->tcp_conn.tcp_eager_conn_ind = NULL;
	/* Move from q0 to q */
	ASSERT(listener->tcp_conn_req_cnt_q0 > 0);
	listener->tcp_conn_req_cnt_q0--;
	listener->tcp_conn_req_cnt_q++;
	tcp->tcp_eager_next_q0->tcp_eager_prev_q0 =
	    tcp->tcp_eager_prev_q0;
	tcp->tcp_eager_prev_q0->tcp_eager_next_q0 =
	    tcp->tcp_eager_next_q0;
	tcp->tcp_eager_prev_q0 = NULL;
	tcp->tcp_eager_next_q0 = NULL;
	tcp->tcp_conn_def_q0 = B_FALSE;

	/* Make sure the tcp isn't in the list of droppables */
	ASSERT(tcp->tcp_eager_next_drop_q0 == NULL &&
	    tcp->tcp_eager_prev_drop_q0 == NULL);

	/*
	 * Insert at end of the queue because sockfs sends
	 * down T_CONN_RES in chronological order. Leaving
	 * the older conn indications at front of the queue
	 * helps reducing search time.
	 */
	tail = listener->tcp_eager_last_q;
	if (tail != NULL) {
		tail->tcp_eager_next_q = tcp;
	} else {
		listener->tcp_eager_next_q = tcp;
	}
	listener->tcp_eager_last_q = tcp;
	tcp->tcp_eager_next_q = NULL;

	return (conn_ind);
}


/*
 * Reply to a clients T_CONN_RES TPI message. This function
 * is used only for TLI/XTI listener. Sockfs sends T_CONN_RES
 * on the acceptor STREAM and processed in tcp_accept_common().
 * Read the block comment on top of tcp_input_listener().
 */
void
tcp_tli_accept(tcp_t *listener, mblk_t *mp)
{
	tcp_t		*acceptor;
	tcp_t		*eager;
	struct T_conn_res	*tcr;
	t_uscalar_t	acceptor_id;
	t_scalar_t	seqnum;
	mblk_t		*discon_mp = NULL;
	mblk_t		*ok_mp;
	mblk_t		*mp1;
	tcp_stack_t	*tcps = listener->tcp_tcps;
	conn_t		*econnp;

	if ((mp->b_wptr - mp->b_rptr) < sizeof (*tcr)) {
		tcp_err_ack(listener, mp, TPROTO, 0);
		return;
	}
	tcr = (struct T_conn_res *)mp->b_rptr;

	/*
	 * Under ILP32 the stream head points tcr->ACCEPTOR_id at the
	 * read side queue of the streams device underneath us i.e. the
	 * read side queue of 'ip'. Since we can't deference QUEUE_ptr we
	 * look it up in the queue_hash.  Under LP64 it sends down the
	 * minor_t of the accepting endpoint.
	 *
	 * Once the acceptor/eager are modified (in tcp_accept_swap) the
	 * fanout hash lock is held.
	 * This prevents any thread from entering the acceptor queue from
	 * below (since it has not been hard bound yet i.e. any inbound
	 * packets will arrive on the listener conn_t and
	 * go through the classifier).
	 * The CONN_INC_REF will prevent the acceptor from closing.
	 *
	 * XXX It is still possible for a tli application to send down data
	 * on the accepting stream while another thread calls t_accept.
	 * This should not be a problem for well-behaved applications since
	 * the T_OK_ACK is sent after the queue swapping is completed.
	 *
	 * If the accepting fd is the same as the listening fd, avoid
	 * queue hash lookup since that will return an eager listener in a
	 * already established state.
	 */
	acceptor_id = tcr->ACCEPTOR_id;
	mutex_enter(&listener->tcp_eager_lock);
	if (listener->tcp_acceptor_id == acceptor_id) {
		eager = listener->tcp_eager_next_q;
		/* only count how many T_CONN_INDs so don't count q0 */
		if ((listener->tcp_conn_req_cnt_q != 1) ||
		    (eager->tcp_conn_req_seqnum != tcr->SEQ_number)) {
			mutex_exit(&listener->tcp_eager_lock);
			tcp_err_ack(listener, mp, TBADF, 0);
			return;
		}
		if (listener->tcp_conn_req_cnt_q0 != 0) {
			/* Throw away all the eagers on q0. */
			tcp_eager_cleanup(listener, 1);
		}
		if (listener->tcp_syn_defense) {
			listener->tcp_syn_defense = B_FALSE;
			if (listener->tcp_ip_addr_cache != NULL) {
				kmem_free(listener->tcp_ip_addr_cache,
				    IP_ADDR_CACHE_SIZE * sizeof (ipaddr_t));
				listener->tcp_ip_addr_cache = NULL;
			}
		}
		/*
		 * Transfer tcp_conn_req_max to the eager so that when
		 * a disconnect occurs we can revert the endpoint to the
		 * listen state.
		 */
		eager->tcp_conn_req_max = listener->tcp_conn_req_max;
		ASSERT(listener->tcp_conn_req_cnt_q0 == 0);
		/*
		 * Get a reference on the acceptor just like the
		 * tcp_acceptor_hash_lookup below.
		 */
		acceptor = listener;
		CONN_INC_REF(acceptor->tcp_connp);
	} else {
		acceptor = tcp_acceptor_hash_lookup(acceptor_id, tcps);
		if (acceptor == NULL) {
			if (listener->tcp_connp->conn_debug) {
				(void) strlog(TCP_MOD_ID, 0, 1,
				    SL_ERROR|SL_TRACE,
				    "tcp_accept: did not find acceptor 0x%x\n",
				    acceptor_id);
			}
			mutex_exit(&listener->tcp_eager_lock);
			tcp_err_ack(listener, mp, TPROVMISMATCH, 0);
			return;
		}
		/*
		 * Verify acceptor state. The acceptable states for an acceptor
		 * include TCPS_IDLE and TCPS_BOUND.
		 */
		switch (acceptor->tcp_state) {
		case TCPS_IDLE:
			/* FALLTHRU */
		case TCPS_BOUND:
			break;
		default:
			CONN_DEC_REF(acceptor->tcp_connp);
			mutex_exit(&listener->tcp_eager_lock);
			tcp_err_ack(listener, mp, TOUTSTATE, 0);
			return;
		}
	}

	/* The listener must be in TCPS_LISTEN */
	if (listener->tcp_state != TCPS_LISTEN) {
		CONN_DEC_REF(acceptor->tcp_connp);
		mutex_exit(&listener->tcp_eager_lock);
		tcp_err_ack(listener, mp, TOUTSTATE, 0);
		return;
	}

	/*
	 * Rendezvous with an eager connection request packet hanging off
	 * 'tcp' that has the 'seqnum' tag.  We tagged the detached open
	 * tcp structure when the connection packet arrived in
	 * tcp_input_listener().
	 */
	seqnum = tcr->SEQ_number;
	eager = listener;
	do {
		eager = eager->tcp_eager_next_q;
		if (eager == NULL) {
			CONN_DEC_REF(acceptor->tcp_connp);
			mutex_exit(&listener->tcp_eager_lock);
			tcp_err_ack(listener, mp, TBADSEQ, 0);
			return;
		}
	} while (eager->tcp_conn_req_seqnum != seqnum);
	mutex_exit(&listener->tcp_eager_lock);

	/*
	 * At this point, both acceptor and listener have 2 ref
	 * that they begin with. Acceptor has one additional ref
	 * we placed in lookup while listener has 3 additional
	 * ref for being behind the squeue (tcp_accept() is
	 * done on listener's squeue); being in classifier hash;
	 * and eager's ref on listener.
	 */
	ASSERT(listener->tcp_connp->conn_ref >= 5);
	ASSERT(acceptor->tcp_connp->conn_ref >= 3);

	/*
	 * The eager at this point is set in its own squeue and
	 * could easily have been killed (tcp_accept_finish will
	 * deal with that) because of a TH_RST so we can only
	 * ASSERT for a single ref.
	 */
	ASSERT(eager->tcp_connp->conn_ref >= 1);

	/*
	 * Pre allocate the discon_ind mblk also. tcp_accept_finish will
	 * use it if something failed.
	 */
	discon_mp = allocb(MAX(sizeof (struct T_discon_ind),
	    sizeof (struct stroptions)), BPRI_HI);
	if (discon_mp == NULL) {
		CONN_DEC_REF(acceptor->tcp_connp);
		CONN_DEC_REF(eager->tcp_connp);
		tcp_err_ack(listener, mp, TSYSERR, ENOMEM);
		return;
	}

	econnp = eager->tcp_connp;

	/* Hold a copy of mp, in case reallocb fails */
	if ((mp1 = copymsg(mp)) == NULL) {
		CONN_DEC_REF(acceptor->tcp_connp);
		CONN_DEC_REF(eager->tcp_connp);
		freemsg(discon_mp);
		tcp_err_ack(listener, mp, TSYSERR, ENOMEM);
		return;
	}

	tcr = (struct T_conn_res *)mp1->b_rptr;

	/*
	 * This is an expanded version of mi_tpi_ok_ack_alloc()
	 * which allocates a larger mblk and appends the new
	 * local address to the ok_ack.  The address is copied by
	 * soaccept() for getsockname().
	 */
	{
		int extra;

		extra = (econnp->conn_family == AF_INET) ?
		    sizeof (sin_t) : sizeof (sin6_t);

		/*
		 * Try to re-use mp, if possible.  Otherwise, allocate
		 * an mblk and return it as ok_mp.  In any case, mp
		 * is no longer usable upon return.
		 */
		if ((ok_mp = mi_tpi_ok_ack_alloc_extra(mp, extra)) == NULL) {
			CONN_DEC_REF(acceptor->tcp_connp);
			CONN_DEC_REF(eager->tcp_connp);
			freemsg(discon_mp);
			/* Original mp has been freed by now, so use mp1 */
			tcp_err_ack(listener, mp1, TSYSERR, ENOMEM);
			return;
		}

		mp = NULL;	/* We should never use mp after this point */

		switch (extra) {
		case sizeof (sin_t): {
			sin_t *sin = (sin_t *)ok_mp->b_wptr;

			ok_mp->b_wptr += extra;
			sin->sin_family = AF_INET;
			sin->sin_port = econnp->conn_lport;
			sin->sin_addr.s_addr = econnp->conn_laddr_v4;
			break;
		}
		case sizeof (sin6_t): {
			sin6_t *sin6 = (sin6_t *)ok_mp->b_wptr;

			ok_mp->b_wptr += extra;
			sin6->sin6_family = AF_INET6;
			sin6->sin6_port = econnp->conn_lport;
			sin6->sin6_addr = econnp->conn_laddr_v6;
			sin6->sin6_flowinfo = econnp->conn_flowinfo;
			if (IN6_IS_ADDR_LINKSCOPE(&econnp->conn_laddr_v6) &&
			    (econnp->conn_ixa->ixa_flags & IXAF_SCOPEID_SET)) {
				sin6->sin6_scope_id =
				    econnp->conn_ixa->ixa_scopeid;
			} else {
				sin6->sin6_scope_id = 0;
			}
			sin6->__sin6_src_id = 0;
			break;
		}
		default:
			break;
		}
		ASSERT(ok_mp->b_wptr <= ok_mp->b_datap->db_lim);
	}

	/*
	 * If there are no options we know that the T_CONN_RES will
	 * succeed. However, we can't send the T_OK_ACK upstream until
	 * the tcp_accept_swap is done since it would be dangerous to
	 * let the application start using the new fd prior to the swap.
	 */
	tcp_accept_swap(listener, acceptor, eager);

	/*
	 * tcp_accept_swap unlinks eager from listener but does not drop
	 * the eager's reference on the listener.
	 */
	ASSERT(eager->tcp_listener == NULL);
	ASSERT(listener->tcp_connp->conn_ref >= 5);

	/*
	 * The eager is now associated with its own queue. Insert in
	 * the hash so that the connection can be reused for a future
	 * T_CONN_RES.
	 */
	tcp_acceptor_hash_insert(acceptor_id, eager);

	/*
	 * We now do the processing of options with T_CONN_RES.
	 * We delay till now since we wanted to have queue to pass to
	 * option processing routines that points back to the right
	 * instance structure which does not happen until after
	 * tcp_accept_swap().
	 *
	 * Note:
	 * The sanity of the logic here assumes that whatever options
	 * are appropriate to inherit from listner=>eager are done
	 * before this point, and whatever were to be overridden (or not)
	 * in transfer logic from eager=>acceptor in tcp_accept_swap().
	 * [ Warning: acceptor endpoint can have T_OPTMGMT_REQ done to it
	 *   before its ACCEPTOR_id comes down in T_CONN_RES ]
	 * This may not be true at this point in time but can be fixed
	 * independently. This option processing code starts with
	 * the instantiated acceptor instance and the final queue at
	 * this point.
	 */

	if (tcr->OPT_length != 0) {
		/* Options to process */
		int t_error = 0;
		int sys_error = 0;
		int do_disconnect = 0;

		if (tcp_conprim_opt_process(eager, mp1,
		    &do_disconnect, &t_error, &sys_error) < 0) {
			eager->tcp_accept_error = 1;
			if (do_disconnect) {
				/*
				 * An option failed which does not allow
				 * connection to be accepted.
				 *
				 * We allow T_CONN_RES to succeed and
				 * put a T_DISCON_IND on the eager queue.
				 */
				ASSERT(t_error == 0 && sys_error == 0);
				eager->tcp_send_discon_ind = 1;
			} else {
				ASSERT(t_error != 0);
				freemsg(ok_mp);
				/*
				 * Original mp was either freed or set
				 * to ok_mp above, so use mp1 instead.
				 */
				tcp_err_ack(listener, mp1, t_error, sys_error);
				goto finish;
			}
		}
		/*
		 * Most likely success in setting options (except if
		 * eager->tcp_send_discon_ind set).
		 * mp1 option buffer represented by OPT_length/offset
		 * potentially modified and contains results of setting
		 * options at this point
		 */
	}

	/* We no longer need mp1, since all options processing has passed */
	freemsg(mp1);

	putnext(listener->tcp_connp->conn_rq, ok_mp);

	mutex_enter(&listener->tcp_eager_lock);
	if (listener->tcp_eager_prev_q0->tcp_conn_def_q0) {
		mblk_t	*conn_ind;

		/*
		 * This path should not be executed if listener and
		 * acceptor streams are the same.
		 */
		ASSERT(listener != acceptor);
		conn_ind = tcp_get_def_conn_ind(listener);
		mutex_exit(&listener->tcp_eager_lock);
		putnext(listener->tcp_connp->conn_rq, conn_ind);
	} else {
		mutex_exit(&listener->tcp_eager_lock);
	}

	/*
	 * Done with the acceptor - free it
	 *
	 * Note: from this point on, no access to listener should be made
	 * as listener can be equal to acceptor.
	 */
finish:
	ASSERT(acceptor->tcp_detached);
	acceptor->tcp_connp->conn_rq = NULL;
	ASSERT(!IPCL_IS_NONSTR(acceptor->tcp_connp));
	acceptor->tcp_connp->conn_wq = NULL;
	(void) tcp_clean_death(acceptor, 0);
	CONN_DEC_REF(acceptor->tcp_connp);

	/*
	 * We pass discon_mp to tcp_accept_finish to get on the right squeue.
	 *
	 * It will update the setting for sockfs/stream head and also take
	 * care of any data that arrived before accept() wad called.
	 * In case we already received a FIN then tcp_accept_finish will send up
	 * the ordrel. It will also send up a window update if the window
	 * has opened up.
	 */

	/*
	 * XXX: we currently have a problem if XTI application closes the
	 * acceptor stream in between. This problem exists in on10-gate also
	 * and is well know but nothing can be done short of major rewrite
	 * to fix it. Now it is possible to take care of it by assigning TLI/XTI
	 * eager same squeue as listener (we can distinguish non socket
	 * listeners at the time of handling a SYN in tcp_input_listener)
	 * and do most of the work that tcp_accept_finish does here itself
	 * and then get behind the acceptor squeue to access the acceptor
	 * queue.
	 */
	/*
	 * We already have a ref on tcp so no need to do one before squeue_enter
	 */
	SQUEUE_ENTER_ONE(eager->tcp_connp->conn_sqp, discon_mp,
	    tcp_accept_finish, eager->tcp_connp, NULL, SQ_FILL,
	    SQTAG_TCP_ACCEPT_FINISH);
}


/*
 * This is the STREAMS entry point for T_CONN_RES coming down on
 * Acceptor STREAM when  sockfs listener does accept processing.
 * Read the block comment on top of tcp_input_listener().
 */
void
tcp_tpi_accept(queue_t *q, mblk_t *mp)
{
	queue_t *rq = RD(q);
	struct T_conn_res *conn_res;
	tcp_t *eager;
	tcp_t *listener;
	struct T_ok_ack *ok;
	t_scalar_t PRIM_type;
	mblk_t *discon_mp;
	conn_t *econnp;
	cred_t *cr;

	ASSERT(DB_TYPE(mp) == M_PROTO);

	/*
	 * All Solaris components should pass a db_credp
	 * for this TPI message, hence we ASSERT.
	 * But in case there is some other M_PROTO that looks
	 * like a TPI message sent by some other kernel
	 * component, we check and return an error.
	 */
	cr = msg_getcred(mp, NULL);
	ASSERT(cr != NULL);
	if (cr == NULL) {
		mp = mi_tpi_err_ack_alloc(mp, TSYSERR, EINVAL);
		if (mp != NULL)
			putnext(rq, mp);
		return;
	}
	conn_res = (struct T_conn_res *)mp->b_rptr;
	ASSERT((uintptr_t)(mp->b_wptr - mp->b_rptr) <= (uintptr_t)INT_MAX);
	if ((mp->b_wptr - mp->b_rptr) < sizeof (struct T_conn_res)) {
		mp = mi_tpi_err_ack_alloc(mp, TPROTO, 0);
		if (mp != NULL)
			putnext(rq, mp);
		return;
	}
	switch (conn_res->PRIM_type) {
	case O_T_CONN_RES:
	case T_CONN_RES:
		/*
		 * We pass up an err ack if allocb fails. This will
		 * cause sockfs to issue a T_DISCON_REQ which will cause
		 * tcp_eager_blowoff to be called. sockfs will then call
		 * rq->q_qinfo->qi_qclose to cleanup the acceptor stream.
		 * we need to do the allocb up here because we have to
		 * make sure rq->q_qinfo->qi_qclose still points to the
		 * correct function (tcp_tpi_close_accept) in case allocb
		 * fails.
		 */
		bcopy(mp->b_rptr + conn_res->OPT_offset,
		    &eager, conn_res->OPT_length);
		PRIM_type = conn_res->PRIM_type;
		mp->b_datap->db_type = M_PCPROTO;
		mp->b_wptr = mp->b_rptr + sizeof (struct T_ok_ack);
		ok = (struct T_ok_ack *)mp->b_rptr;
		ok->PRIM_type = T_OK_ACK;
		ok->CORRECT_prim = PRIM_type;
		econnp = eager->tcp_connp;
		econnp->conn_dev = (dev_t)RD(q)->q_ptr;
		econnp->conn_minor_arena = (vmem_t *)(WR(q)->q_ptr);
		econnp->conn_rq = rq;
		econnp->conn_wq = q;
		rq->q_ptr = econnp;
		rq->q_qinfo = &tcp_rinitv4;	/* No open - same as rinitv6 */
		q->q_ptr = econnp;
		q->q_qinfo = &tcp_winit;
		listener = eager->tcp_listener;

		/*
		 * Pre allocate the discon_ind mblk also. tcp_accept_finish will
		 * use it if something failed.
		 */
		discon_mp = allocb(MAX(sizeof (struct T_discon_ind),
		    sizeof (struct stroptions)), BPRI_HI);

		if (discon_mp == NULL) {
			mp = mi_tpi_err_ack_alloc(mp, TPROTO, 0);
			if (mp != NULL)
				putnext(rq, mp);
			return;
		}

		eager->tcp_issocket = B_TRUE;

		ASSERT(econnp->conn_netstack ==
		    listener->tcp_connp->conn_netstack);
		ASSERT(eager->tcp_tcps == listener->tcp_tcps);

		/* Put the ref for IP */
		CONN_INC_REF(econnp);

		/*
		 * We should have minimum of 3 references on the conn
		 * at this point. One each for TCP and IP and one for
		 * the T_conn_ind that was sent up when the 3-way handshake
		 * completed. In the normal case we would also have another
		 * reference (making a total of 4) for the conn being in the
		 * classifier hash list. However the eager could have received
		 * an RST subsequently and tcp_closei_local could have removed
		 * the eager from the classifier hash list, hence we can't
		 * assert that reference.
		 */
		ASSERT(econnp->conn_ref >= 3);

		mutex_enter(&listener->tcp_eager_lock);
		if (listener->tcp_eager_prev_q0->tcp_conn_def_q0) {
			mblk_t *conn_ind = tcp_get_def_conn_ind(listener);

			/* Need to get inside the listener perimeter */
			CONN_INC_REF(listener->tcp_connp);
			SQUEUE_ENTER_ONE(listener->tcp_connp->conn_sqp,
			    conn_ind, tcp_send_pending, listener->tcp_connp,
			    NULL, SQ_FILL, SQTAG_TCP_SEND_PENDING);
		}
		tcp_eager_unlink(eager);
		mutex_exit(&listener->tcp_eager_lock);

		/*
		 * At this point, the eager is detached from the listener
		 * but we still have an extra refs on eager (apart from the
		 * usual tcp references). The ref was placed in tcp_input_data
		 * before sending the conn_ind in tcp_send_conn_ind.
		 * The ref will be dropped in tcp_accept_finish().
		 */
		SQUEUE_ENTER_ONE(econnp->conn_sqp, discon_mp, tcp_accept_finish,
		    econnp, NULL, SQ_NODRAIN, SQTAG_TCP_ACCEPT_FINISH_Q0);

		/*
		 * Send the new local address also up to sockfs. There
		 * should already be enough space in the mp that came
		 * down from soaccept().
		 */
		if (econnp->conn_family == AF_INET) {
			sin_t *sin;

			ASSERT((mp->b_datap->db_lim - mp->b_datap->db_base) >=
			    (sizeof (struct T_ok_ack) + sizeof (sin_t)));
			sin = (sin_t *)mp->b_wptr;
			mp->b_wptr += sizeof (sin_t);
			sin->sin_family = AF_INET;
			sin->sin_port = econnp->conn_lport;
			sin->sin_addr.s_addr = econnp->conn_laddr_v4;
		} else {
			sin6_t *sin6;

			ASSERT((mp->b_datap->db_lim - mp->b_datap->db_base) >=
			    sizeof (struct T_ok_ack) + sizeof (sin6_t));
			sin6 = (sin6_t *)mp->b_wptr;
			mp->b_wptr += sizeof (sin6_t);
			sin6->sin6_family = AF_INET6;
			sin6->sin6_port = econnp->conn_lport;
			sin6->sin6_addr = econnp->conn_laddr_v6;
			if (econnp->conn_ipversion == IPV4_VERSION)
				sin6->sin6_flowinfo = 0;
			else
				sin6->sin6_flowinfo = econnp->conn_flowinfo;
			if (IN6_IS_ADDR_LINKSCOPE(&econnp->conn_laddr_v6) &&
			    (econnp->conn_ixa->ixa_flags & IXAF_SCOPEID_SET)) {
				sin6->sin6_scope_id =
				    econnp->conn_ixa->ixa_scopeid;
			} else {
				sin6->sin6_scope_id = 0;
			}
			sin6->__sin6_src_id = 0;
		}

		putnext(rq, mp);
		return;
	default:
		mp = mi_tpi_err_ack_alloc(mp, TNOTSUPPORT, 0);
		if (mp != NULL)
			putnext(rq, mp);
		return;
	}
}

/*
 * The function called through squeue to get behind listener's perimeter to
 * send a deferred conn_ind.
 */
/* ARGSUSED */
void
tcp_send_pending(void *arg, mblk_t *mp, void *arg2, ip_recv_attr_t *dummy)
{
	conn_t	*lconnp = (conn_t *)arg;
	tcp_t *listener = lconnp->conn_tcp;
	struct T_conn_ind *conn_ind;
	tcp_t *tcp;

	conn_ind = (struct T_conn_ind *)mp->b_rptr;
	bcopy(mp->b_rptr + conn_ind->OPT_offset, &tcp,
	    conn_ind->OPT_length);

	if (listener->tcp_state != TCPS_LISTEN) {
		/*
		 * If listener has closed, it would have caused a
		 * a cleanup/blowoff to happen for the eager, so
		 * we don't need to do anything more.
		 */
		freemsg(mp);
		return;
	}

	putnext(lconnp->conn_rq, mp);
}

/*
 * Sends the T_CONN_IND to the listener. The caller calls this
 * functions via squeue to get inside the listener's perimeter
 * once the 3 way hand shake is done a T_CONN_IND needs to be
 * sent. As an optimization, the caller can call this directly
 * if listener's perimeter is same as eager's.
 */
/* ARGSUSED */
void
tcp_send_conn_ind(void *arg, mblk_t *mp, void *arg2)
{
	conn_t			*lconnp = (conn_t *)arg;
	tcp_t			*listener = lconnp->conn_tcp;
	tcp_t			*tcp;
	struct T_conn_ind	*conn_ind;
	ipaddr_t 		*addr_cache;
	boolean_t		need_send_conn_ind = B_FALSE;
	tcp_stack_t		*tcps = listener->tcp_tcps;

	/* retrieve the eager */
	conn_ind = (struct T_conn_ind *)mp->b_rptr;
	ASSERT(conn_ind->OPT_offset != 0 &&
	    conn_ind->OPT_length == sizeof (intptr_t));
	bcopy(mp->b_rptr + conn_ind->OPT_offset, &tcp,
	    conn_ind->OPT_length);

	/*
	 * TLI/XTI applications will get confused by
	 * sending eager as an option since it violates
	 * the option semantics. So remove the eager as
	 * option since TLI/XTI app doesn't need it anyway.
	 */
	if (!TCP_IS_SOCKET(listener)) {
		conn_ind->OPT_length = 0;
		conn_ind->OPT_offset = 0;
	}
	if (listener->tcp_state != TCPS_LISTEN) {
		/*
		 * If listener has closed, it would have caused a
		 * a cleanup/blowoff to happen for the eager. We
		 * just need to return.
		 */
		freemsg(mp);
		return;
	}


	/*
	 * if the conn_req_q is full defer passing up the
	 * T_CONN_IND until space is availabe after t_accept()
	 * processing
	 */
	mutex_enter(&listener->tcp_eager_lock);

	/*
	 * Take the eager out, if it is in the list of droppable eagers
	 * as we are here because the 3W handshake is over.
	 */
	MAKE_UNDROPPABLE(tcp);

	if (listener->tcp_conn_req_cnt_q < listener->tcp_conn_req_max) {
		tcp_t *tail;

		/*
		 * The eager already has an extra ref put in tcp_input_data
		 * so that it stays till accept comes back even though it
		 * might get into TCPS_CLOSED as a result of a TH_RST etc.
		 */
		ASSERT(listener->tcp_conn_req_cnt_q0 > 0);
		listener->tcp_conn_req_cnt_q0--;
		listener->tcp_conn_req_cnt_q++;

		/* Move from SYN_RCVD to ESTABLISHED list  */
		tcp->tcp_eager_next_q0->tcp_eager_prev_q0 =
		    tcp->tcp_eager_prev_q0;
		tcp->tcp_eager_prev_q0->tcp_eager_next_q0 =
		    tcp->tcp_eager_next_q0;
		tcp->tcp_eager_prev_q0 = NULL;
		tcp->tcp_eager_next_q0 = NULL;

		/*
		 * Insert at end of the queue because sockfs
		 * sends down T_CONN_RES in chronological
		 * order. Leaving the older conn indications
		 * at front of the queue helps reducing search
		 * time.
		 */
		tail = listener->tcp_eager_last_q;
		if (tail != NULL)
			tail->tcp_eager_next_q = tcp;
		else
			listener->tcp_eager_next_q = tcp;
		listener->tcp_eager_last_q = tcp;
		tcp->tcp_eager_next_q = NULL;
		/*
		 * Delay sending up the T_conn_ind until we are
		 * done with the eager. Once we have have sent up
		 * the T_conn_ind, the accept can potentially complete
		 * any time and release the refhold we have on the eager.
		 */
		need_send_conn_ind = B_TRUE;
	} else {
		/*
		 * Defer connection on q0 and set deferred
		 * connection bit true
		 */
		tcp->tcp_conn_def_q0 = B_TRUE;

		/* take tcp out of q0 ... */
		tcp->tcp_eager_prev_q0->tcp_eager_next_q0 =
		    tcp->tcp_eager_next_q0;
		tcp->tcp_eager_next_q0->tcp_eager_prev_q0 =
		    tcp->tcp_eager_prev_q0;

		/* ... and place it at the end of q0 */
		tcp->tcp_eager_prev_q0 = listener->tcp_eager_prev_q0;
		tcp->tcp_eager_next_q0 = listener;
		listener->tcp_eager_prev_q0->tcp_eager_next_q0 = tcp;
		listener->tcp_eager_prev_q0 = tcp;
		tcp->tcp_conn.tcp_eager_conn_ind = mp;
	}

	/* we have timed out before */
	if (tcp->tcp_syn_rcvd_timeout != 0) {
		tcp->tcp_syn_rcvd_timeout = 0;
		listener->tcp_syn_rcvd_timeout--;
		if (listener->tcp_syn_defense &&
		    listener->tcp_syn_rcvd_timeout <=
		    (tcps->tcps_conn_req_max_q0 >> 5) &&
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
	if (need_send_conn_ind)
		putnext(lconnp->conn_rq, mp);
}
