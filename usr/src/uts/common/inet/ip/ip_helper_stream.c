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

#include <sys/types.h>
#include <inet/ip.h>
#include <inet/ip_impl.h>
#include <inet/ipclassifier.h>
#include <inet/proto_set.h>
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/strsun.h>
#include <sys/cmn_err.h>
#include <sys/t_kuser.h>
#include <sys/tihdr.h>
#include <sys/pathname.h>
#include <sys/sockio.h>
#include <sys/vmem.h>
#include <sys/disp.h>

void ip_helper_wput(queue_t *q, mblk_t *mp);

static int ip_helper_stream_close(queue_t *, int);

static struct module_info ip_helper_stream_info =  {
	0, "iphelper", IP_MOD_MINPSZ, IP_MOD_MAXPSZ, IP_MOD_HIWAT, IP_MOD_LOWAT
};

static struct qinit ip_helper_stream_rinit = {
	NULL, NULL, NULL, ip_helper_stream_close, NULL,
	&ip_helper_stream_info, NULL
};

static struct qinit ip_helper_stream_winit = {
	(pfi_t)ip_helper_wput, (pfi_t)ip_wsrv, NULL, NULL, NULL,
	&ip_helper_stream_info, NULL, NULL, NULL, STRUIOT_NONE
};

#define	IP_USE_HELPER_CACHE	(ip_helper_stream_cache != NULL)

/*
 * set the q_ptr of the 'q' to the conn_t pointer passed in
 */
static void
ip_helper_share_conn(queue_t *q, mblk_t *mp)
{
	if (IP_USE_HELPER_CACHE) {
		ip_helper_stream_info_t	*ip_helper_info;

		ip_helper_info = *((ip_helper_stream_info_t **)
		    mp->b_cont->b_rptr);
		ip_helper_info->iphs_minfo = q->q_ptr;
		ip_helper_info->iphs_rq = RD(q);
		ip_helper_info->iphs_wq = WR(q);
	} else {
		conn_t *connp = *((conn_t **)mp->b_cont->b_rptr);

		connp->conn_helper_info->iphs_minfo = q->q_ptr;
		connp->conn_helper_info->iphs_rq = RD(q);
		connp->conn_helper_info->iphs_wq = WR(q);
		WR(q)->q_ptr = RD(q)->q_ptr = (void *)connp;
		connp->conn_rq = RD(q);
		connp->conn_wq = WR(q);
	}
	miocack(q, mp, 0, 0);
}

void
ip_helper_wput(queue_t *q, mblk_t *mp)
{
	struct iocblk *iocp = (struct iocblk *)mp->b_rptr;
	if (DB_TYPE(mp) == M_IOCTL &&
	    iocp->ioc_cmd == SIOCSQPTR) {
		ip_helper_share_conn(q, mp);
	} else {
		conn_t *connp = (conn_t *)q->q_ptr;

		if (connp->conn_af_isv6) {
			ip_wput_v6(q, mp);
		} else {
			ip_wput(q, mp);
		}
	}
}

/* ARGSUSED */
int
ip_helper_stream_setup(queue_t *q, dev_t *devp, int flag, int sflag,
    cred_t *credp, boolean_t isv6)
{
	major_t			maj;
	ip_helper_minfo_t	*ip_minfop;

	ASSERT((flag & ~(FKLYR)) == IP_HELPER_STR);

	ASSERT(RD(q) == q);

	ip_minfop = kmem_alloc(sizeof (ip_helper_minfo_t), KM_NOSLEEP);
	if (ip_minfop == NULL) {
		return (ENOMEM);
	}

	ip_minfop->ip_minfo_dev = 0;
	ip_minfop->ip_minfo_arena = NULL;

	/*
	 * Clone the device, allocate minor device number
	 */
	if (ip_minor_arena_la != NULL)
		ip_minfop->ip_minfo_dev = inet_minor_alloc(ip_minor_arena_la);

	if (ip_minfop->ip_minfo_dev == 0) {
		/*
		 * numbers in the large arena are exhausted
		 * Try small arena.
		 * Or this is a 32 bit system, 32 bit systems do not have
		 * ip_minor_arena_la
		 */
		ip_minfop->ip_minfo_dev = inet_minor_alloc(ip_minor_arena_sa);
		if (ip_minfop->ip_minfo_dev == 0) {
			return (EBUSY);
		}
		ip_minfop->ip_minfo_arena = ip_minor_arena_sa;
	} else {
		ip_minfop->ip_minfo_arena = ip_minor_arena_la;
	}


	ASSERT(ip_minfop->ip_minfo_dev != 0);
	ASSERT(ip_minfop->ip_minfo_arena != NULL);

	RD(q)->q_ptr = WR(q)->q_ptr = ip_minfop;

	maj = getemajor(*devp);
	*devp = makedevice(maj, (ulong_t)(ip_minfop->ip_minfo_dev));

	q->q_qinfo = &ip_helper_stream_rinit;
	WR(q)->q_qinfo = &ip_helper_stream_winit;
	qprocson(q);
	return (0);
}

/* ARGSUSED */
static int
ip_helper_stream_close(queue_t *q, int flag)
{
	ip_helper_minfo_t *ip_minfop;

	qprocsoff(q);
	ip_minfop = (q)->q_ptr;
	inet_minor_free(ip_minfop->ip_minfo_arena,
	    ip_minfop->ip_minfo_dev);
	kmem_free(ip_minfop, sizeof (ip_helper_minfo_t));
	RD(q)->q_ptr = NULL;
	WR(q)->q_ptr = NULL;
	return (0);
}

/*
 * Public interface for creating an IP stream with shared conn_t
 */
/* ARGSUSED */
int
ip_create_helper_stream(conn_t *connp, ldi_ident_t li)
{
	int	error;
	int	ret;

	ASSERT(!servicing_interrupt());

	error = 0;
	if (IP_USE_HELPER_CACHE) {
		queue_t	*rq, *wq;

		connp->conn_helper_info = kmem_cache_alloc(
		    ip_helper_stream_cache, KM_NOSLEEP);
		if (connp->conn_helper_info == NULL)
			return (EAGAIN);
		rq = connp->conn_helper_info->iphs_rq;
		wq = connp->conn_helper_info->iphs_wq;
		/*
		 * Doesn't need to hold the QLOCK for there is no one else
		 * should have a pointer to this queue.
		 */
		rq->q_flag |= QWANTR;
		wq->q_flag |= QWANTR;

		connp->conn_rq = rq;
		connp->conn_wq = wq;
		rq->q_ptr = (void *)connp;
		wq->q_ptr = (void *)connp;
	} else {
		ASSERT(connp->conn_helper_info == NULL);
		connp->conn_helper_info = kmem_alloc(
		    sizeof (ip_helper_stream_info_t), KM_SLEEP);
		/*
		 * open ip device via the layered interface.
		 * pass in kcred as some threads do not have the
		 * priviledge to open /dev/ip and the check in
		 * secpolicy_spec_open() will fail the open
		 */
		error = ldi_open_by_name(connp->conn_af_isv6 ?
		    DEV_IP6 : DEV_IP, IP_HELPER_STR,
		    kcred, &connp->conn_helper_info->iphs_handle, li);

		if (error != 0) {
			kmem_free(connp->conn_helper_info,
			    (sizeof (ip_helper_stream_info_t)));
			connp->conn_helper_info = NULL;
			return (error);
		}
		/*
		 * Share connp with the helper stream
		 */
		error = ldi_ioctl(connp->conn_helper_info->iphs_handle,
		    SIOCSQPTR, (intptr_t)connp, FKIOCTL, kcred, &ret);

		if (error != 0) {
			/*
			 * Passing in a zero flag indicates that an error
			 * occured and stream was not shared
			 */
			(void) ldi_close(connp->conn_helper_info->iphs_handle,
			    0, kcred);
			kmem_free(connp->conn_helper_info,
			    (sizeof (ip_helper_stream_info_t)));
			connp->conn_helper_info = NULL;
		}
	}
	return (error);
}

/*
 * Public interface for closing the shared IP stream
 */
/* ARGSUSED */
void
ip_close_helper_stream(conn_t *connp)
{
	ASSERT(!servicing_interrupt());
	if (IP_USE_HELPER_CACHE) {

		if (connp->conn_helper_info == NULL)
			return;
		ASSERT(connp->conn_helper_info->iphs_rq != NULL);
		ASSERT(connp->conn_helper_info->iphs_wq != NULL);

		/* Prevent service procedures from being called */
		disable_svc(connp->conn_helper_info->iphs_rq);

		/* Wait until service procedure of each queue is run */
		wait_svc(connp->conn_helper_info->iphs_rq);

		/* Cleanup any pending ioctls */
		conn_ioctl_cleanup(connp);

		/* Allow service procedures to be called again */
		enable_svc(connp->conn_helper_info->iphs_rq);

		/* Flush the queues */
		flushq(connp->conn_helper_info->iphs_rq, FLUSHALL);
		flushq(connp->conn_helper_info->iphs_wq, FLUSHALL);

		connp->conn_helper_info->iphs_rq->q_ptr = NULL;
		connp->conn_helper_info->iphs_wq->q_ptr = NULL;

		kmem_cache_free(ip_helper_stream_cache,
		    connp->conn_helper_info);
	} else {
		ASSERT(
		    connp->conn_helper_info->iphs_handle != NULL);

		connp->conn_helper_info->iphs_rq->q_ptr =
		    connp->conn_helper_info->iphs_wq->q_ptr =
		    connp->conn_helper_info->iphs_minfo;
		(void) ldi_close(connp->conn_helper_info->iphs_handle,
		    IP_HELPER_STR, kcred);
		kmem_free(connp->conn_helper_info,
		    sizeof (ip_helper_stream_info_t));
	}
	connp->conn_helper_info = NULL;
}

/*
 * create a T_SVR4_OPTMGMT_REQ TPI message and send down the IP stream
 */
static int
ip_send_option_request(conn_t *connp, uint_t optset_context, int level,
    int option_name, const void *optval, t_uscalar_t optlen, cred_t *cr)
{
	struct T_optmgmt_req	*optmgmt_reqp;
	struct opthdr		*ohp;
	ssize_t			size;
	mblk_t			*mp;

	size = sizeof (struct T_optmgmt_req) + sizeof (struct opthdr) + optlen;
	mp = allocb_cred(size, cr);
	if (mp == NULL)
		return (ENOMEM);

	mp->b_datap->db_type = M_PROTO;
	optmgmt_reqp = (struct T_optmgmt_req *)mp->b_wptr;

	optmgmt_reqp->PRIM_type = T_SVR4_OPTMGMT_REQ;
	optmgmt_reqp->MGMT_flags = optset_context;
	optmgmt_reqp->OPT_length = (t_scalar_t)sizeof (struct opthdr) + optlen;
	optmgmt_reqp->OPT_offset = (t_scalar_t)sizeof (struct T_optmgmt_req);

	mp->b_wptr += sizeof (struct T_optmgmt_req);

	ohp = (struct opthdr *)mp->b_wptr;

	ohp->level = level;
	ohp->name = option_name;
	ohp->len = optlen;

	mp->b_wptr += sizeof (struct opthdr);

	if (optval != NULL) {
		bcopy(optval, mp->b_wptr, optlen);
	} else {
		bzero(mp->b_wptr, optlen);
	}
	mp->b_wptr += optlen;

	/*
	 * Send down the primitive
	 */
	return (ldi_putmsg(connp->conn_helper_info->iphs_handle, mp));
}

/*
 * wait/process the response to T_SVR4_OPTMGMT_REQ TPI message
 */
static int
ip_get_option_response(conn_t *connp, uint_t optset_context, void *optval,
    t_uscalar_t *optlenp)
{
	union T_primitives	*tpr;
	int			error;
	mblk_t			*mp;

	mp = NULL;

	ASSERT(optset_context == T_CHECK || optset_context == T_NEGOTIATE);
	error = ldi_getmsg(connp->conn_helper_info->iphs_handle, &mp, NULL);
	if (error != 0) {
		return (error);
	}

	if (DB_TYPE(mp) != M_PCPROTO || MBLKL(mp) < sizeof (tpr->type)) {
		error = EPROTO;
		goto done;
	}

	tpr = (union T_primitives *)mp->b_rptr;

	switch (tpr->type) {
	case T_OPTMGMT_ACK:
		if (MBLKL(mp) < TOPTMGMTACKSZ)
			error = EPROTO;
		break;
	case T_ERROR_ACK:
		if (MBLKL(mp) < TERRORACKSZ) {
			error = EPROTO;
			break;
		}

		if (tpr->error_ack.TLI_error == TSYSERR)
			error = tpr->error_ack.UNIX_error;
		else
			error = proto_tlitosyserr(tpr->error_ack.TLI_error);
		break;
	default:
		error = EPROTO;
		break;
	}

	if ((optset_context == T_CHECK) && (error == 0)) {
		struct opthdr		*opt_res;
		t_uscalar_t		len;
		t_uscalar_t		size;
		t_uscalar_t		maxlen = *optlenp;
		void			*option;
		struct T_optmgmt_ack	*optmgmt_ack;

		optmgmt_ack = (struct T_optmgmt_ack *)mp->b_rptr;
		opt_res = (struct opthdr *)
		    ((uintptr_t)mp->b_rptr +  optmgmt_ack->OPT_offset);
		/*
		 * Check mblk boundary
		 */
		if (!MBLKIN(mp, optmgmt_ack->OPT_offset,
		    optmgmt_ack->OPT_length)) {
			error = EPROTO;
			goto done;
		}

		/*
		 * Check alignment
		 */
		if ((((uintptr_t)opt_res) & (__TPI_ALIGN_SIZE - 1)) != 0) {
			error = EPROTO;
			goto done;
		}

		option = &opt_res[1];

		/* check to ensure that the option is within bounds */
		if ((((uintptr_t)option + opt_res->len) < (uintptr_t)option) ||
		    !MBLKIN(mp, sizeof (struct opthdr), opt_res->len)) {
			error = EPROTO;
			goto done;
		}

		len = opt_res->len;
		size = MIN(len, maxlen);

		/*
		 * Copy data
		 */
		bcopy(option, optval, size);
		bcopy(&size, optlenp, sizeof (size));
	}

done:
	freemsg(mp);
	return (error);
}

/*
 * Public interface to get socketoptions via the ip helper stream.
 */
int
ip_get_options(conn_t *connp, int level, int option_name, void *optval,
    t_uscalar_t *optlenp, cred_t *cr)
{
	int			error;

	error = ip_send_option_request(connp, T_CHECK, level, option_name, NULL,
	    *optlenp, cr);
	if (error)
		return (error);

	return (ip_get_option_response(connp, T_CHECK, optval, optlenp));
}

/*
 * Public interface to set socket options via the ip helper stream.
 */
int
ip_set_options(conn_t *connp, int level, int option_name, const void *optval,
    t_uscalar_t optlen, cred_t *cr)
{

	int	error;

	error = ip_send_option_request(connp, T_NEGOTIATE, level, option_name,
	    optval, optlen, cr);
	if (error)
		return (error);

	return (ip_get_option_response(connp, T_NEGOTIATE, (void *)optval,
	    &optlen));
}
