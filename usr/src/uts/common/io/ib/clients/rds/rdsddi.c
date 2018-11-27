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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/priv_names.h>
#include <inet/common.h>

#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/timod.h>
#include <sys/tiuser.h>
#include <sys/suntpi.h>
#include <inet/common.h>
#include <inet/ip.h>
#include <inet/mi.h>
#include <inet/proto_set.h>
#include <sys/ib/clients/rds/rds.h>
#include <sys/policy.h>
#include <inet/ipclassifier.h>
#include <sys/ib/clients/rds/rds_kstat.h>
#include "sys/random.h"
#include <sys/ib/clients/rds/rds_transport.h>
#include <sys/ib/ibtl/ibti.h>


#define	RDS_NAME	"rds"
#define	RDS_STRTAB	rdsinfo
#define	RDS_DEVDESC	"RDS STREAMS driver"
#define	RDS_DEVMINOR	0
#define	RDS_DEVMTFLAGS D_MP | D_SYNCSTR
#define	RDS_DEFAULT_PRIV_MODE	0666

#define	rds_smallest_port	1
#define	rds_largest_port	65535

#define	RDS_RECV_HIWATER	(56 * 1024)
#define	RDS_RECV_LOWATER	128
#define	RDS_XMIT_HIWATER	(56 * 1024)
#define	RDS_XMIT_LOWATER	1024

#define	RDS_DPRINTF2	0 &&
#define	LABEL	"RDS"

typedef struct rdsahdr_s {
	in_port_t	uha_src_port;	/* Source port */
	in_port_t	uha_dst_port;	/* Destination port */
} rdsha_t;

#define	RDSH_SIZE	4

int rds_recv_hiwat = RDS_RECV_HIWATER;
int rds_recv_lowat = RDS_RECV_LOWATER;
int rds_xmit_hiwat = RDS_XMIT_HIWATER;
int rds_xmit_lowat = RDS_XMIT_LOWATER;

int rdsdebug;

static dev_info_t *rds_dev_info;

/* Hint not protected by any lock */
static	in_port_t	rds_next_port_to_try;

ldi_ident_t rds_li;
static int loopmax = rds_largest_port - rds_smallest_port + 1;

/* global configuration variables */
uint_t  UserBufferSize;
uint_t  rds_rx_pkts_pending_hwm;

extern void rds_ioctl(queue_t *, mblk_t *);
extern void rds_ioctl_copyin_done(queue_t *q, mblk_t *mp);

int rds_open_transport_driver();
int rds_close_transport_driver();

#define	RDS_CURRENT_PORT_QUOTA()					\
	(rds_rx_pkts_pending_hwm/RDS_GET_NPORT())

krwlock_t	rds_transport_lock;
ldi_handle_t	rds_transport_handle = NULL;
rds_transport_ops_t *rds_transport_ops = NULL;

static int
rds_attach(dev_info_t *devi, ddi_attach_cmd_t cmd)
{
	int	ret;

	if (cmd != DDI_ATTACH)
		return (DDI_FAILURE);

	rds_dev_info = devi;

	ret = ddi_create_minor_node(devi, RDS_NAME, S_IFCHR,
	    RDS_DEVMINOR, DDI_PSEUDO, 0);
	if (ret != DDI_SUCCESS) {
		return (ret);
	}

	return (DDI_SUCCESS);
}

static int
rds_detach(dev_info_t *devi, ddi_detach_cmd_t cmd)
{
	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	ASSERT(devi == rds_dev_info);

	ddi_remove_minor_node(devi, NULL);

	return (DDI_SUCCESS);
}

/* ARGSUSED */
static int
rds_info(dev_info_t *dip, ddi_info_cmd_t cmd, void *arg, void **result)
{
	int error = DDI_FAILURE;

	switch (cmd) {
	case DDI_INFO_DEVT2DEVINFO:
		if (rds_dev_info != NULL) {
			*result = (void *)rds_dev_info;
			error = DDI_SUCCESS;
		}
		break;

	case DDI_INFO_DEVT2INSTANCE:
		*result = NULL;
		error = DDI_SUCCESS;
		break;

	default:
		break;
	}

	return (error);
}


/*ARGSUSED*/
static int
rds_open(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	rds_t	*rds;
	int	ret;

	if (is_system_labeled()) {
		/*
		 * RDS socket is not supported on labeled systems
		 */
		return (ESOCKTNOSUPPORT);
	}

	/* Open the transport driver if IB HW is present */
	rw_enter(&rds_transport_lock, RW_READER);
	if (rds_transport_handle == NULL) {
		rw_exit(&rds_transport_lock);
		ret = rds_open_transport_driver();
		rw_enter(&rds_transport_lock, RW_READER);

		if (ret != 0) {
			/* Transport driver failed to load */
			rw_exit(&rds_transport_lock);
			return (ret);
		}
	}
	rw_exit(&rds_transport_lock);

	if (sflag == MODOPEN) {
		return (EINVAL);
	}

	/* Reopen not supported */
	if (q->q_ptr != NULL) {
		dprint(2, ("%s: Reopen is not supported: %p", LABEL, q->q_ptr));
		return (0);
	}

	rds = rds_create(q, credp);
	if (rds == NULL) {
		dprint(2, ("%s: rds_create failed", LABEL));
		return (0);
	}

	q->q_ptr = WR(q)->q_ptr = rds;
	rds->rds_state = TS_UNBND;
	rds->rds_family = AF_INET_OFFLOAD;

	q->q_hiwat = rds_recv_hiwat;
	q->q_lowat = rds_recv_lowat;

	qprocson(q);

	WR(q)->q_hiwat = rds_xmit_hiwat;
	WR(q)->q_lowat = rds_xmit_lowat;

	/* Set the Stream head watermarks */
	(void) proto_set_rx_hiwat(q, NULL, rds_recv_hiwat);
	(void) proto_set_rx_lowat(q, NULL, rds_recv_lowat);

	return (0);
}

/* ARGSUSED */
static int
rds_close(queue_t *q, int flags __unused, cred_t *credp __unused)
{
	rds_t *rdsp = (rds_t *)q->q_ptr;

	qprocsoff(q);

	/*
	 * NPORT should be decremented only if this socket was previously
	 * bound to an RDS port.
	 */
	if (rdsp->rds_state >= TS_IDLE) {
		RDS_DECR_NPORT();
		RDS_SET_PORT_QUOTA(RDS_CURRENT_PORT_QUOTA());
		rds_transport_ops->
		    rds_transport_resume_port(ntohs(rdsp->rds_port));
	}

	/* close the transport driver if this is the last socket */
	if (RDS_GET_NPORT() == 1) {
		(void) rds_close_transport_driver();
	}

	/*
	 * We set the flags without holding a lock as this is
	 * just a hint for the fanout lookup to skip this rds.
	 * We dont free the struct until it's out of the hash and
	 * the ref count goes down.
	 */
	rdsp->rds_flags |= RDS_CLOSING;
	rds_bind_hash_remove(rdsp, B_FALSE);
	mutex_enter(&rdsp->rds_lock);
	ASSERT(rdsp->rds_refcnt > 0);
	if (rdsp->rds_refcnt != 1) {
		cv_wait(&rdsp->rds_refcv, &rdsp->rds_lock);
	}
	mutex_exit(&rdsp->rds_lock);
	RDS_DEC_REF_CNT(rdsp);
	RD(q)->q_ptr = NULL;
	WR(q)->q_ptr = NULL;
	return (0);
}

/*
 * Add a new message to the socket
 */
int
rds_deliver_new_msg(mblk_t *mp, ipaddr_t local_addr, ipaddr_t rem_addr,
    in_port_t local_port, in_port_t rem_port, zoneid_t zoneid)
{
	rds_t *rds;
	struct  T_unitdata_ind  *tudi;
	int	udi_size;	/* Size of T_unitdata_ind */
	mblk_t *mp1;
	sin_t	*sin;
	int error = 0;

	local_port = htons(local_port);
	rem_port = htons(rem_port);

	ASSERT(mp->b_datap->db_type == M_DATA);
	rds = rds_fanout(local_addr, rem_addr, local_port, rem_port, zoneid);
	if (rds == NULL) {
		dprint(2, ("%s: rds_fanout failed: (0x%x 0x%x %d %d)", LABEL,
		    local_addr, rem_addr, ntohs(local_port), ntohs(rem_port)));
		freemsg(mp);
		return (error);
	}

	udi_size = sizeof (struct T_unitdata_ind) + sizeof (sin_t);

	/* Allocate a message block for the T_UNITDATA_IND structure. */
	mp1 = allocb(udi_size, BPRI_MED);
	if (mp1 == NULL) {
		dprint(2, ("%s: allocb failed", LABEL));
		freemsg(mp);
		return (ENOMEM);
	}

	mp1->b_cont = mp;
	mp = mp1;
	mp->b_datap->db_type = M_PROTO;
	tudi = (struct T_unitdata_ind *)(uintptr_t)mp->b_rptr;
	mp->b_wptr = (uchar_t *)tudi + udi_size;
	tudi->PRIM_type = T_UNITDATA_IND;
	tudi->SRC_length = sizeof (sin_t);
	tudi->SRC_offset = sizeof (struct T_unitdata_ind);
	tudi->OPT_offset = sizeof (struct T_unitdata_ind) + sizeof (sin_t);
	udi_size -= (sizeof (struct T_unitdata_ind) + sizeof (sin_t));
	tudi->OPT_length = udi_size;
	sin = (sin_t *)&tudi[1];
	sin->sin_addr.s_addr = rem_addr;
	sin->sin_port = ntohs(rem_port);
	sin->sin_family = rds->rds_family;
	*(uint32_t *)(uintptr_t)&sin->sin_zero[0] = 0;
	*(uint32_t *)(uintptr_t)&sin->sin_zero[4] = 0;

	putnext(rds->rds_ulpd, mp);

	/* check port quota */
	if (RDS_GET_RXPKTS_PEND() > rds_rx_pkts_pending_hwm) {
		ulong_t current_port_quota = RDS_GET_PORT_QUOTA();
		if (rds->rds_port_quota > current_port_quota) {
			/* this may result in stalling the port */
			rds->rds_port_quota = current_port_quota;
			(void) proto_set_rx_hiwat(rds->rds_ulpd, NULL,
			    rds->rds_port_quota * UserBufferSize);
			RDS_INCR_PORT_QUOTA_ADJUSTED();
		}
	}

	/*
	 * canputnext() check is done after putnext as the protocol does
	 * not allow dropping any received packet.
	 */
	if (!canputnext(rds->rds_ulpd)) {
		error = ENOSPC;
	}

	RDS_DEC_REF_CNT(rds);
	return (error);
}


/* Default structure copied into T_INFO_ACK messages */
static struct T_info_ack rds_g_t_info_ack_ipv4 = {
	T_INFO_ACK,
	65535,	/* TSDU_size. Excl. headers */
	T_INVALID,	/* ETSU_size.  rds does not support expedited data. */
	T_INVALID,	/* CDATA_size. rds does not support connect data. */
	T_INVALID,	/* DDATA_size. rds does not support disconnect data. */
	sizeof (sin_t),	/* ADDR_size. */
	0,		/* OPT_size - not initialized here */
	65535,		/* TIDU_size.  Excl. headers */
	T_CLTS,		/* SERV_type.  rds supports connection-less. */
	TS_UNBND,	/* CURRENT_state.  This is set from rds_state. */
	(XPG4_1|SENDZERO) /* PROVIDER_flag */
};

static in_port_t
rds_update_next_port(in_port_t port)
{
	(void) random_get_pseudo_bytes((uint8_t *)&port, sizeof (in_port_t));
	if (port < rds_smallest_port)
		port = rds_smallest_port;
	return (port);
}

/* This routine creates a T_ERROR_ACK message and passes it upstream. */
static void
rds_err_ack(queue_t *q, mblk_t *mp, t_scalar_t t_error, int sys_error)
{
	if ((mp = mi_tpi_err_ack_alloc(mp, t_error, sys_error)) != NULL)
		qreply(q, mp);
}

static void
rds_capability_req(queue_t *q, mblk_t *mp)
{
	t_uscalar_t	cap_bits1;
	struct T_capability_ack *tcap;

	cap_bits1 =
	    ((struct T_capability_req *)(uintptr_t)mp->b_rptr)->CAP_bits1;

	mp = tpi_ack_alloc(mp, sizeof (struct T_capability_ack),
	    mp->b_datap->db_type, T_CAPABILITY_ACK);
	if (mp == NULL)
		return;
	tcap = (struct T_capability_ack *)(uintptr_t)mp->b_rptr;
	tcap->CAP_bits1 = 0;

	if (cap_bits1 & TC1_INFO) {
		tcap->CAP_bits1 |= TC1_INFO;
		*(&tcap->INFO_ack) = rds_g_t_info_ack_ipv4;
	}

	qreply(q, mp);
}

static void
rds_info_req(queue_t *q, mblk_t *omp)
{
	rds_t *rds = (rds_t *)q->q_ptr;
	struct T_info_ack *tap;
	mblk_t *mp;

	/* Create a T_INFO_ACK message. */
	mp = tpi_ack_alloc(omp, sizeof (struct T_info_ack), M_PCPROTO,
	    T_INFO_ACK);
	if (mp == NULL)
		return;
	tap = (struct T_info_ack *)(uintptr_t)mp->b_rptr;
	*tap = rds_g_t_info_ack_ipv4;
	tap->CURRENT_state = rds->rds_state;
	tap->OPT_size = 128;
	qreply(q, mp);
}

/*
 * NO locking protection here as sockfs will only send down
 * one bind operation at a time.
 */
static void
rds_bind(queue_t *q, mblk_t *mp)
{
	sin_t		*sin;
	rds_t *rds;
	struct T_bind_req *tbr;
	in_port_t	port;	/* Host byte order */
	in_port_t	requested_port; /* Host byte order */
	struct T_bind_ack *tba;
	int		count;
	rds_bf_t	*rdsbf;
	in_port_t	lport;	/* Network byte order */

	rds = (rds_t *)q->q_ptr;
	if (((uintptr_t)mp->b_wptr - (uintptr_t)mp->b_rptr) < sizeof (*tbr)) {
		rds_err_ack(q, mp, TPROTO, 0);
		return;
	}

	/*
	 * We don't allow multiple binds
	 */
	if (rds->rds_state != TS_UNBND) {
		rds_err_ack(q, mp, TOUTSTATE, 0);
		return;
	}

	tbr = (struct T_bind_req *)(uintptr_t)mp->b_rptr;
	switch (tbr->ADDR_length) {
	case sizeof (sin_t):    /* Complete IPv4 address */
		sin = (sin_t *)(uintptr_t)mi_offset_param(mp, tbr->ADDR_offset,
		    sizeof (sin_t));
		if (sin == NULL || !OK_32PTR((char *)sin)) {
			rds_err_ack(q, mp, TSYSERR, EINVAL);
			return;
		}
		if (rds->rds_family != AF_INET_OFFLOAD ||
		    sin->sin_family != AF_INET_OFFLOAD) {
			rds_err_ack(q, mp, TSYSERR, EAFNOSUPPORT);
			return;
		}
		if (sin->sin_addr.s_addr == INADDR_ANY) {
			rds_err_ack(q, mp, TBADADDR, 0);
			return;
		}

		/*
		 * verify that the address is hosted on IB
		 * only exception is the loopback address.
		 */
		if ((sin->sin_addr.s_addr != INADDR_LOOPBACK) &&
		    !rds_verify_bind_address(sin->sin_addr.s_addr)) {
			rds_err_ack(q, mp, TBADADDR, 0);
			return;
		}

		port = ntohs(sin->sin_port);
		break;
	default:	/* Invalid request */
		rds_err_ack(q, mp, TBADADDR, 0);
		return;
	}

	requested_port = port;

	/*
	 * TPI only sends down T_BIND_REQ for AF_INET and AF_INET6
	 * since RDS socket is of type AF_INET_OFFLOAD a O_T_BIND_REQ
	 * will be sent down. Treat O_T_BIND_REQ as T_BIND_REQ
	 */

	if (requested_port == 0) {
		/*
		 * If the application passed in zero for the port number, it
		 * doesn't care which port number we bind to. Get one in the
		 * valid range.
		 */
		port = rds_update_next_port(rds_next_port_to_try);
	}

	ASSERT(port != 0);
	count = 0;
	for (;;) {
		rds_t		*rds1;
		ASSERT(sin->sin_addr.s_addr != INADDR_ANY);
		/*
		 * Walk through the list of rds streams bound to
		 * requested port with the same IP address.
		 */
		lport = htons(port);
		rdsbf = &rds_bind_fanout[RDS_BIND_HASH(lport)];
		mutex_enter(&rdsbf->rds_bf_lock);
		for (rds1 = rdsbf->rds_bf_rds; rds1 != NULL;
		    rds1 = rds1->rds_bind_hash) {
			if (lport != rds1->rds_port ||
			    rds1->rds_src != sin->sin_addr.s_addr ||
			    rds1->rds_zoneid != rds->rds_zoneid)

				continue;
			break;
		}

		if (rds1 == NULL) {
			/*
			 * No other stream has this IP address
			 * and port number. We can use it.
			 */
			break;
		}
		mutex_exit(&rdsbf->rds_bf_lock);
		if (requested_port != 0) {
			/*
			 * We get here only when requested port
			 * is bound (and only first  of the for()
			 * loop iteration).
			 *
			 * The semantics of this bind request
			 * require it to fail so we return from
			 * the routine (and exit the loop).
			 *
			 */
			rds_err_ack(q, mp, TADDRBUSY, 0);
			return;
		}

		port = rds_update_next_port(port + 1);

		if (++count >= loopmax) {
			/*
			 * We've tried every possible port number and
			 * there are none available, so send an error
			 * to the user.
			 */
			rds_err_ack(q, mp, TNOADDR, 0);
			return;
		}
	}

	/*
	 * Copy the source address into our rds structure.
	 */
	rds->rds_src = sin->sin_addr.s_addr;
	rds->rds_port = lport;

	/*
	 * reset the next port if we choose the port
	 */
	if (requested_port == 0) {
		rds_next_port_to_try = port + 1;
	}

	rds->rds_state = TS_IDLE;
	rds_bind_hash_insert(rdsbf, rds);
	mutex_exit(&rdsbf->rds_bf_lock);

	/* Reset the message type in preparation for shipping it back. */
	mp->b_datap->db_type = M_PCPROTO;
	tba = (struct T_bind_ack *)(uintptr_t)mp->b_rptr;
	tba->PRIM_type = T_BIND_ACK;

	/* Increment the number of ports and set the port quota */
	RDS_INCR_NPORT();
	rds->rds_port_quota = RDS_CURRENT_PORT_QUOTA();
	RDS_SET_PORT_QUOTA(rds->rds_port_quota);
	(void) proto_set_rx_hiwat(RD(q), NULL,
	    rds->rds_port_quota * UserBufferSize);

	qreply(q, mp);
}

static void
rds_wput_other(queue_t *q, mblk_t *mp)
{
	uchar_t *rptr = mp->b_rptr;
	struct datab *db;
	cred_t *cr;

	db = mp->b_datap;
	switch (db->db_type) {
	case M_DATA:
		/* Not connected */
		freemsg(mp);
		return;
	case M_PROTO:
	case M_PCPROTO:
		if ((uintptr_t)mp->b_wptr - (uintptr_t)rptr <
		    sizeof (t_scalar_t)) {
			freemsg(mp);
			return;
		}
		switch (((union T_primitives *)(uintptr_t)rptr)->type) {
		case T_CAPABILITY_REQ:
			rds_capability_req(q, mp);
			return;

		case T_INFO_REQ:
			rds_info_req(q, mp);
			return;
		case O_T_BIND_REQ:
		case T_BIND_REQ:
			rds_bind(q, mp);
			return;
		case T_SVR4_OPTMGMT_REQ:
		case T_OPTMGMT_REQ:
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
				rds_err_ack(q, mp, TSYSERR, EINVAL);
				return;
			}
			if (((union T_primitives *)(uintptr_t)rptr)->type ==
			    T_SVR4_OPTMGMT_REQ) {
				svr4_optcom_req(q, mp, cr, &rds_opt_obj);
			} else {
				tpi_optcom_req(q, mp, cr, &rds_opt_obj);
			}
			return;
		case T_CONN_REQ:
			/*
			 * We should not receive T_CONN_REQ as sockfs only
			 * sends down T_CONN_REQ if family == AF_INET/AF_INET6
			 * and type == SOCK_DGRAM/SOCK_RAW. For all others
			 * it simply calls soisconnected. see sotpi_connect()
			 * for details.
			 */
		/* FALLTHRU */
		default:
			cmn_err(CE_PANIC, "type %d \n",
			    ((union T_primitives *)(uintptr_t)rptr)->type);
		}
		break;
	case M_FLUSH:
		if (*rptr & FLUSHW)
			flushq(q, FLUSHDATA);
		break;
	case M_IOCTL:
		rds_ioctl(q, mp);
		break;
	case M_IOCDATA:
		/* IOCTL continuation following copyin or copyout. */
		if (mi_copy_state(q, mp, NULL) == -1) {
			/*
			 * The copy operation failed.  mi_copy_state already
			 * cleaned up, so we're out of here.
			 */
			return;
		}
		/*
		 * If we just completed a copy in, continue processing
		 * in rds_ioctl_copyin_done. If it was a copy out, we call
		 * mi_copyout again.  If there is nothing more to copy out,
		 * it will complete the IOCTL.
		 */

		if (MI_COPY_DIRECTION(mp) == MI_COPY_IN)
			rds_ioctl_copyin_done(q, mp);
		else
			mi_copyout(q, mp);
		return;

	default:
		cmn_err(CE_PANIC, "types %d \n", db->db_type);
	}
}

static int
rds_wput(queue_t *q, mblk_t *mp)
{
	struct	datab	*db;
	uchar_t	*rptr = mp->b_rptr;

	db = mp->b_datap;
	switch (db->db_type) {
	case M_PROTO:
	case M_PCPROTO:
		ASSERT(((uintptr_t)mp->b_wptr - (uintptr_t)rptr) <=
		    (uintptr_t)INT_MAX);
		if ((uintptr_t)mp->b_wptr - (uintptr_t)rptr >=
		    sizeof (struct T_unitdata_req)) {
			if (((union T_primitives *)(uintptr_t)rptr)->type
			    == T_UNITDATA_REQ) {
				/*
				 *  We should never come here for T_UNITDATA_REQ
				 */
				cmn_err(CE_PANIC, "rds_wput T_UNITDATA_REQ \n");
			}
		}
		/* FALLTHRU */
	default:
		rds_wput_other(q, mp);
		return (0);
	}
}

static int
rds_wput_data(queue_t *q, mblk_t *mp, uio_t *uiop)
{
	uchar_t	*rptr = mp->b_rptr;
	rds_t	*rds;
	mblk_t	*mp1;
	sin_t	*sin;
	ipaddr_t dst;
	uint16_t port;
	int ret = 0;

#define	tudr	((struct T_unitdata_req *)(uintptr_t)rptr)

	rds = (rds_t *)q->q_ptr;
	/* Handle UNITDATA_REQ messages here */
	if (rds->rds_state == TS_UNBND) {
		/* If a port has not been bound to the stream, fail. */
		dprint(2, ("%s: socket is not bound to a port", LABEL));
		freemsg(mp);
		return (EPROTO);
	}

	mp1 = mp->b_cont;
	mp->b_cont = NULL;
	if (mp1 == NULL) {
		dprint(2, ("%s: No message to send", LABEL));
		freemsg(mp);
		return (EPROTO);
	}

	/*
	 * No options allowed
	 */
	if (tudr->OPT_length != 0) {
		ret = EINVAL;
		goto done;
	}

	ASSERT(mp1->b_datap->db_ref == 1);

	if ((rptr + tudr->DEST_offset + tudr->DEST_length) >
	    mp->b_wptr) {
		ret = EDESTADDRREQ;
		goto done;
	}

	sin = (sin_t *)(uintptr_t)&rptr[tudr->DEST_offset];
	if (!OK_32PTR((char *)sin) || tudr->DEST_length !=
	    sizeof (sin_t) || sin->sin_family != AF_INET_OFFLOAD) {
		ret = EDESTADDRREQ;
		goto done;
	}
	/* Extract port and ipaddr */
	port = sin->sin_port;
	dst = sin->sin_addr.s_addr;

	if (port == 0 || dst == INADDR_ANY) {
		ret = EDESTADDRREQ;
		goto done;
	}

	ASSERT(rds_transport_ops != NULL);
	ret = rds_transport_ops->rds_transport_sendmsg(uiop, rds->rds_src, dst,
	    ntohs(rds->rds_port), ntohs(port), rds->rds_zoneid);
	if (ret != 0) {
		if ((ret != ENOBUFS) && (ret != ENOMEM)) {
			/* ENOMEM is actually EWOULDBLOCK */
			dprint(2, ("%s: rds_sendmsg returned %d", LABEL, ret));
			goto done;
		}
	}
done:
	freemsg(mp1);
	freemsg(mp);
	return (ret);
}

/*
 * Make sure we dont return EINVAL and EWOULDBLOCK as it has
 * special meanings for the synchronous streams (rwnext()).
 * We should return ENOMEM which is changed to EWOULDBLOCK by kstrputmsg()
 */
static int
rds_wrw(queue_t *q, struiod_t *dp)
{
	mblk_t  *mp = dp->d_mp;
	int error = 0;
	struct  datab   *db;
	uchar_t *rptr;

	db = mp->b_datap;
	rptr = mp->b_rptr;
	switch (db->db_type) {
	case M_PROTO:
	case M_PCPROTO:
		ASSERT(((uintptr_t)mp->b_wptr - (uintptr_t)rptr) <=
		    (uintptr_t)INT_MAX);
		if ((uintptr_t)mp->b_wptr - (uintptr_t)rptr >=
		    sizeof (struct T_unitdata_req)) {
			/* Detect valid T_UNITDATA_REQ here */
			if (((union T_primitives *)(uintptr_t)rptr)->type
			    == T_UNITDATA_REQ)
			break;
		}
		/* FALLTHRU */
	default:

		if (isuioq(q) && (error = struioget(q, mp, dp, 0))) {
		/*
		 * Uio error of some sort, so just return the error.
		 */
			goto done;
		}
		dp->d_mp = 0;
		rds_wput_other(q, mp);
		return (0);
	}

	dp->d_mp = 0;
	error = rds_wput_data(q, mp, &dp->d_uio);
done:
	if (error == EWOULDBLOCK || error == EINVAL)
		error = EIO;

	return (error);
}

static void
rds_rsrv(queue_t *q)
{
	rds_t	*rds = (rds_t *)q->q_ptr;
	ulong_t current_port_quota;

	/* update the port quota to the current level */
	current_port_quota = RDS_GET_PORT_QUOTA();
	if (rds->rds_port_quota != current_port_quota) {
		rds->rds_port_quota = current_port_quota;
		(void) proto_set_rx_hiwat(q, NULL,
		    rds->rds_port_quota * UserBufferSize);
	}

	/* No more messages in the q, unstall the socket */
	rds_transport_ops->rds_transport_resume_port(ntohs(rds->rds_port));
}

int
rds_close_transport_driver()
{
	ASSERT(rds_transport_ops != NULL);

	rw_enter(&rds_transport_lock, RW_WRITER);
	if (rds_transport_handle != NULL) {
		rds_transport_ops->rds_transport_close_ib();
		(void) ldi_close(rds_transport_handle, FNDELAY, kcred);
		rds_transport_handle = NULL;
	}
	rw_exit(&rds_transport_lock);

	return (0);
}


int
rds_open_transport_driver()
{
	int ret = 0;

	rw_enter(&rds_transport_lock, RW_WRITER);
	if (rds_transport_handle != NULL) {
		/*
		 * Someone beat us to it.
		 */
		goto done;
	}

	if (ibt_hw_is_present() == 0) {
		ret = ENODEV;
		goto done;
	}

	if (rds_li == NULL) {
		ret = EPROTONOSUPPORT;
		goto done;
	}

	ret = ldi_open_by_name("/devices/ib/rdsib@0:rdsib",
	    FREAD | FWRITE, kcred, &rds_transport_handle, rds_li);
	if (ret != 0) {
		ret = EPROTONOSUPPORT;
		rds_transport_handle = NULL;
		goto done;
	}

	ret = rds_transport_ops->rds_transport_open_ib();
	if (ret != 0) {
		(void) ldi_close(rds_transport_handle, FNDELAY, kcred);
		rds_transport_handle = NULL;
	}
done:
	rw_exit(&rds_transport_lock);
	return (ret);
}

static struct module_info info = {
	0, "rds", 1, INFPSZ, 65536, 1024
};

static struct qinit rinit = {
	NULL, (pfi_t)rds_rsrv, rds_open, rds_close, NULL, &info
};

static struct qinit winit = {
	(pfi_t)rds_wput, NULL, rds_open, rds_close, NULL, &info,
	NULL, rds_wrw, NULL, STRUIOT_STANDARD
};

struct streamtab rdsinfo = {
	&rinit, &winit, NULL, NULL
};

DDI_DEFINE_STREAM_OPS(rds_devops, nulldev, nulldev, rds_attach, rds_detach,
    nulldev, rds_info, RDS_DEVMTFLAGS, &RDS_STRTAB, ddi_quiesce_not_supported);

/*
 * Module linkage information for the kernel.
 */
static struct modldrv modldrv = {
	&mod_driverops,
	RDS_DEVDESC,
	&rds_devops
};

static struct modlinkage modlinkage = {
	MODREV_1,
	&modldrv,
	NULL
};

int
_init(void)
{
	int	ret;

	rds_init();

	ret = mod_install(&modlinkage);
	if (ret != 0)
		goto done;
	ret = ldi_ident_from_mod(&modlinkage, &rds_li);
	if (ret != 0)
		rds_li = NULL;
done:
	return (ret);
}

int
_fini(void)
{
	int	ret;

	ret = mod_remove(&modlinkage);
	if (ret != 0) {
		return (ret);
	}

	rds_fini();

	ldi_ident_release(rds_li);
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}
