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
#include <sys/stream.h>
#include <sys/strsubr.h>
#include <sys/stropts.h>
#include <sys/strsun.h>
#include <sys/strlog.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/timod.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/proc.h>
#include <sys/suntpi.h>
#include <sys/policy.h>
#include <sys/zone.h>

#include <sys/socket.h>
#include <netinet/in.h>

#include <inet/common.h>
#include <netinet/ip6.h>
#include <inet/ip.h>
#include <inet/ipclassifier.h>
#include <inet/mi.h>
#include <inet/nd.h>
#include <inet/optcom.h>
#include <netinet/ip_mroute.h>
#include <sys/isa_defs.h>
#include <net/route.h>

#include <inet/rts_impl.h>
#include <inet/ip_rts.h>

/*
 * This is a transport provider for routing sockets.  Downstream messages are
 * wrapped with a IP_IOCTL header, and ip_wput_ioctl calls the appropriate entry
 * in the ip_ioctl_ftbl callout table to pass the routing socket data into IP.
 * Upstream messages are generated for listeners of the routing socket as well
 * as the message sender (unless they have turned off their end using
 * SO_USELOOPBACK or shutdown(3n)).  Upstream messages may also be generated
 * asynchronously when:
 *
 *	Interfaces are brought up or down.
 *	Addresses are assigned to interfaces.
 *	ICMP redirects are processed and a IRE_HOST/RTF_DYNAMIC is installed.
 *	No route is found while sending a packet.
 *	When TCP requests IP to remove an IRE_CACHE of a troubled destination.
 *
 * Since all we do is reformat the messages between routing socket and
 * ioctl forms, no synchronization is necessary in this module; all
 * the dirty work is done down in ip.
 */

/* Default structure copied into T_INFO_ACK messages */
static struct T_info_ack rts_g_t_info_ack = {
	T_INFO_ACK,
	T_INFINITE,	/* TSDU_size. Maximum size messages. */
	T_INVALID,	/* ETSDU_size. No expedited data. */
	T_INVALID,	/* CDATA_size. No connect data. */
	T_INVALID,	/* DDATA_size. No disconnect data. */
	0,		/* ADDR_size. */
	0,		/* OPT_size - not initialized here */
	64 * 1024,	/* TIDU_size. rts allows maximum size messages. */
	T_COTS,		/* SERV_type. rts supports connection oriented. */
	TS_UNBND,	/* CURRENT_state. This is set from rts_state. */
	(XPG4_1)	/* PROVIDER_flag */
};

/*
 * Table of ND variables supported by rts. These are loaded into rts_g_nd
 * in rts_open.
 * All of these are alterable, within the min/max values given, at run time.
 */
static rtsparam_t	lcl_param_arr[] = {
	/* min		max		value		name */
	{ 4096,		65536,		8192,		"rts_xmit_hiwat"},
	{ 0,		65536,		1024,		"rts_xmit_lowat"},
	{ 4096,		65536,		8192,		"rts_recv_hiwat"},
	{ 65536,	1024*1024*1024, 256*1024,	"rts_max_buf"},
};
#define	rtss_xmit_hiwat		rtss_params[0].rts_param_value
#define	rtss_xmit_lowat		rtss_params[1].rts_param_value
#define	rtss_recv_hiwat		rtss_params[2].rts_param_value
#define	rtss_max_buf		rtss_params[3].rts_param_value

static int	rts_close(queue_t *q);
static void 	rts_err_ack(queue_t *q, mblk_t *mp, t_scalar_t t_error,
    int sys_error);
static void	rts_input(void *, mblk_t *, void *);
static mblk_t	*rts_ioctl_alloc(mblk_t *data, cred_t *cr);
static int	rts_open(queue_t *q, dev_t *devp, int flag, int sflag,
    cred_t *credp);
int		rts_opt_default(queue_t *q, t_scalar_t level, t_scalar_t name,
    uchar_t *ptr);
int		rts_opt_get(queue_t *q, t_scalar_t level, t_scalar_t name,
    uchar_t *ptr);
int		rts_opt_set(queue_t *q, uint_t optset_context, int level,
    int name, uint_t inlen, uchar_t *invalp, uint_t *outlenp,
    uchar_t *outvalp, void *thisdg_attrs, cred_t *cr, mblk_t *mblk);
static int	rts_param_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *cr);
static boolean_t rts_param_register(IDP *ndp, rtsparam_t *rtspa, int cnt);
static int	rts_param_set(queue_t *q, mblk_t *mp, char *value, caddr_t cp,
    cred_t *cr);
static void	rts_rsrv(queue_t *q);
static void	*rts_stack_init(netstackid_t stackid, netstack_t *ns);
static void	rts_stack_fini(netstackid_t stackid, void *arg);
static void	rts_wput(queue_t *q, mblk_t *mp);
static void	rts_wput_iocdata(queue_t *q, mblk_t *mp);
static void 	rts_wput_other(queue_t *q, mblk_t *mp);
static int	rts_wrw(queue_t *q, struiod_t *dp);

static struct module_info rts_mod_info = {
	129, "rts", 1, INFPSZ, 512, 128
};

static struct qinit rtsrinit = {
	NULL, (pfi_t)rts_rsrv, rts_open, rts_close, NULL, &rts_mod_info
};

static struct qinit rtswinit = {
	(pfi_t)rts_wput, NULL, NULL, NULL, NULL, &rts_mod_info,
	NULL, (pfi_t)rts_wrw, NULL, STRUIOT_STANDARD
};

struct streamtab rtsinfo = {
	&rtsrinit, &rtswinit
};

/*
 * This routine allocates the necessary
 * message blocks for IOCTL wrapping the
 * user data.
 */
static mblk_t *
rts_ioctl_alloc(mblk_t *data, cred_t *cr)
{
	mblk_t	*mp = NULL;
	mblk_t	*mp1 = NULL;
	ipllc_t	*ipllc;
	struct iocblk	*ioc;

	mp = allocb_cred(sizeof (ipllc_t), cr);
	if (mp == NULL)
		return (NULL);
	mp1 = allocb_cred(sizeof (struct iocblk), cr);
	if (mp1 == NULL) {
		freeb(mp);
		return (NULL);
	}

	ipllc = (ipllc_t *)mp->b_rptr;
	ipllc->ipllc_cmd = IP_IOC_RTS_REQUEST;
	ipllc->ipllc_name_offset = 0;
	ipllc->ipllc_name_length = 0;
	mp->b_wptr += sizeof (ipllc_t);
	mp->b_cont = data;

	ioc = (struct iocblk *)mp1->b_rptr;
	ioc->ioc_cmd = IP_IOCTL;
	ioc->ioc_error = 0;
	ioc->ioc_cr = NULL;
	ioc->ioc_count = msgdsize(mp);
	mp1->b_wptr += sizeof (struct iocblk);
	mp1->b_datap->db_type = M_IOCTL;
	mp1->b_cont = mp;

	return (mp1);
}

/*
 * This routine closes rts stream, by disabling
 * put/srv routines and freeing the this module
 * internal datastructure.
 */
static int
rts_close(queue_t *q)
{
	conn_t	*connp = Q_TO_CONN(q);

	ASSERT(connp != NULL && IPCL_IS_RTS(connp));

	ip_rts_unregister(connp);

	ip_quiesce_conn(connp);

	qprocsoff(q);

	/*
	 * Now we are truly single threaded on this stream, and can
	 * delete the things hanging off the connp, and finally the connp.
	 * We removed this connp from the fanout list, it cannot be
	 * accessed thru the fanouts, and we already waited for the
	 * conn_ref to drop to 0. We are already in close, so
	 * there cannot be any other thread from the top. qprocsoff
	 * has completed, and service has completed or won't run in
	 * future.
	 */
	ASSERT(connp->conn_ref == 1);

	inet_minor_free(connp->conn_minor_arena, connp->conn_dev);

	connp->conn_ref--;
	ipcl_conn_destroy(connp);

	q->q_ptr = WR(q)->q_ptr = NULL;
	return (0);
}

/*
 * This is the open routine for routing socket. It allocates
 * rts_t structure for the stream and tells IP that it is a routing socket.
 */
/* ARGSUSED */
static int
rts_open(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	rts_t	*rts;
	conn_t *connp;
	dev_t	conn_dev;
	zoneid_t zoneid;
	netstack_t *ns;
	rts_stack_t *rtss;

	/* If the stream is already open, return immediately. */
	if (q->q_ptr != NULL)
		return (0);

	if (sflag == MODOPEN)
		return (EINVAL);

	ns = netstack_find_by_cred(credp);
	ASSERT(ns != NULL);
	rtss = ns->netstack_rts;
	ASSERT(rtss != NULL);

	/*
	 * For exclusive stacks we set the zoneid to zero
	 * to make RTS operate as if in the global zone.
	 */
	if (ns->netstack_stackid != GLOBAL_NETSTACKID)
		zoneid = GLOBAL_ZONEID;
	else
		zoneid = crgetzoneid(credp);

	/*
	 * Since RTS is not used so heavily, allocating from the small
	 * arena should be sufficient.
	 */
	if ((conn_dev = inet_minor_alloc(ip_minor_arena_sa)) == 0) {
		netstack_rele(ns);
		return (EBUSY);
	}
	*devp = makedevice(getemajor(*devp), (minor_t)conn_dev);

	connp = ipcl_conn_create(IPCL_RTSCONN, KM_SLEEP, ns);
	connp->conn_dev = conn_dev;
	connp->conn_minor_arena = ip_minor_arena_sa;
	rts = connp->conn_rts;

	/*
	 * ipcl_conn_create did a netstack_hold. Undo the hold that was
	 * done by netstack_find_by_cred()
	 */
	netstack_rele(ns);

	/*
	 * Initialize the rts_t structure for this stream.
	 */
	q->q_ptr = connp;
	WR(q)->q_ptr = connp;
	connp->conn_rq = q;
	connp->conn_wq = WR(q);

	rw_enter(&rts->rts_rwlock, RW_WRITER);
	ASSERT(connp->conn_rts == rts);
	ASSERT(rts->rts_connp == connp);

	/* Set the initial state of the stream and the privilege status. */
	rts->rts_state = TS_UNBND;
	connp->conn_zoneid = zoneid;

	connp->conn_ulp_labeled = is_system_labeled();

	rts->rts_rtss = rtss;

	q->q_hiwat = rtss->rtss_recv_hiwat;
	WR(q)->q_hiwat = rtss->rtss_xmit_hiwat;
	WR(q)->q_lowat = rtss->rtss_xmit_lowat;

	connp->conn_recv = rts_input;
	crhold(credp);
	connp->conn_cred = credp;

	mutex_enter(&connp->conn_lock);
	connp->conn_state_flags &= ~CONN_INCIPIENT;
	mutex_exit(&connp->conn_lock);

	qprocson(q);
	rw_exit(&rts->rts_rwlock);

	/*
	 * Indicate the down IP module that this is a routing socket
	 * client by sending an RTS IOCTL without any user data. Although
	 * this is just a notification message (without any real routing
	 * request), we pass in any credential for correctness sake.
	 */
	ip_rts_register(connp);

	return (0);

}

/*
 * This routine creates a T_ERROR_ACK message and passes it upstream.
 */
static void
rts_err_ack(queue_t *q, mblk_t *mp, t_scalar_t t_error, int sys_error)
{
	if ((mp = mi_tpi_err_ack_alloc(mp, t_error, sys_error)) != NULL)
		qreply(q, mp);
}

/*
 * This routine creates a T_OK_ACK message and passes it upstream.
 */
static void
rts_ok_ack(queue_t *q, mblk_t *mp)
{
	if ((mp = mi_tpi_ok_ack_alloc(mp)) != NULL)
		qreply(q, mp);
}

/*
 * This routine is called by rts_wput to handle T_UNBIND_REQ messages.
 */
static void
rts_unbind(queue_t *q, mblk_t *mp)
{
	conn_t	*connp = Q_TO_CONN(q);
	rts_t	*rts = connp->conn_rts;

	/* If a bind has not been done, we can't unbind. */
	if (rts->rts_state != TS_IDLE) {
		rts_err_ack(q, mp, TOUTSTATE, 0);
		return;
	}
	rts->rts_state = TS_UNBND;
	rts_ok_ack(q, mp);
}

/*
 * This routine is called to handle each
 * O_T_BIND_REQ/T_BIND_REQ message passed to
 * rts_wput. Note: This routine works with both
 * O_T_BIND_REQ and T_BIND_REQ semantics.
 */
static void
rts_bind(queue_t *q, mblk_t *mp)
{
	conn_t	*connp = Q_TO_CONN(q);
	rts_t	*rts = connp->conn_rts;
	mblk_t	*mp1;
	struct T_bind_req *tbr;

	if ((mp->b_wptr - mp->b_rptr) < sizeof (*tbr)) {
		(void) mi_strlog(q, 1, SL_ERROR|SL_TRACE,
		    "rts_bind: bad data, %d", rts->rts_state);
		rts_err_ack(q, mp, TBADADDR, 0);
		return;
	}
	if (rts->rts_state != TS_UNBND) {
		(void) mi_strlog(q, 1, SL_ERROR|SL_TRACE,
		    "rts_bind: bad state, %d", rts->rts_state);
		rts_err_ack(q, mp, TOUTSTATE, 0);
		return;
	}
	/*
	 * Reallocate the message to make sure we have enough room for an
	 * address and the protocol type.
	 */
	mp1 = reallocb(mp, sizeof (struct T_bind_ack) + sizeof (sin_t), 1);
	if (mp1 == NULL) {
		rts_err_ack(q, mp, TSYSERR, ENOMEM);
		return;
	}
	mp = mp1;
	tbr = (struct T_bind_req *)mp->b_rptr;
	if (tbr->ADDR_length != 0) {
		(void) mi_strlog(q, 1, SL_ERROR|SL_TRACE,
		    "rts_bind: bad ADDR_length %d", tbr->ADDR_length);
		rts_err_ack(q, mp, TBADADDR, 0);
		return;
	}
	/* Generic request */
	tbr->ADDR_offset = (t_scalar_t)sizeof (struct T_bind_req);
	tbr->ADDR_length = 0;
	tbr->PRIM_type = T_BIND_ACK;
	rts->rts_state = TS_IDLE;
	qreply(q, mp);
}

static void
rts_copy_info(struct T_info_ack *tap, rts_t *rts)
{
	*tap = rts_g_t_info_ack;
	tap->CURRENT_state = rts->rts_state;
	tap->OPT_size = rts_max_optsize;
}

/*
 * This routine responds to T_CAPABILITY_REQ messages.  It is called by
 * rts_wput.  Much of the T_CAPABILITY_ACK information is copied from
 * rts_g_t_info_ack.  The current state of the stream is copied from
 * rts_state.
 */
static void
rts_capability_req(queue_t *q, mblk_t *mp)
{
	conn_t	*connp = Q_TO_CONN(q);
	rts_t	*rts = connp->conn_rts;
	t_uscalar_t		cap_bits1;
	struct T_capability_ack	*tcap;

	cap_bits1 = ((struct T_capability_req *)mp->b_rptr)->CAP_bits1;

	mp = tpi_ack_alloc(mp, sizeof (struct T_capability_ack),
	    mp->b_datap->db_type, T_CAPABILITY_ACK);
	if (mp == NULL)
		return;

	tcap = (struct T_capability_ack *)mp->b_rptr;
	tcap->CAP_bits1 = 0;

	if (cap_bits1 & TC1_INFO) {
		rts_copy_info(&tcap->INFO_ack, rts);
		tcap->CAP_bits1 |= TC1_INFO;
	}

	qreply(q, mp);
}

/*
 * This routine responds to T_INFO_REQ messages.  It is called by rts_wput.
 * Most of the T_INFO_ACK information is copied from rts_g_t_info_ack.
 * The current state of the stream is copied from rts_state.
 */
static void
rts_info_req(queue_t *q, mblk_t *mp)
{
	conn_t	*connp = Q_TO_CONN(q);
	rts_t	*rts = connp->conn_rts;

	mp = tpi_ack_alloc(mp, sizeof (rts_g_t_info_ack), M_PCPROTO,
	    T_INFO_ACK);
	if (mp == NULL)
		return;
	rts_copy_info((struct T_info_ack *)mp->b_rptr, rts);
	qreply(q, mp);
}

/*
 * This routine gets default values of certain options whose default
 * values are maintained by protcol specific code
 */
/* ARGSUSED */
int
rts_opt_default(queue_t *q, t_scalar_t level, t_scalar_t name, uchar_t *ptr)
{
	/* no default value processed by protocol specific code currently */
	return (-1);
}

/*
 * This routine retrieves the current status of socket options.
 * It returns the size of the option retrieved.
 */
int
rts_opt_get(queue_t *q, t_scalar_t level, t_scalar_t name, uchar_t *ptr)
{
	int	*i1 = (int *)ptr;
	conn_t	*connp = Q_TO_CONN(q);
	rts_t	*rts = connp->conn_rts;

	switch (level) {
	case SOL_SOCKET:
		switch (name) {
		case SO_DEBUG:
			*i1 = rts->rts_debug;
			break;
		case SO_REUSEADDR:
			*i1 = rts->rts_reuseaddr;
			break;
		case SO_TYPE:
			*i1 = SOCK_RAW;
			break;

		/*
		 * The following three items are available here,
		 * but are only meaningful to IP.
		 */
		case SO_DONTROUTE:
			*i1 = rts->rts_dontroute;
			break;
		case SO_USELOOPBACK:
			*i1 = rts->rts_useloopback;
			break;
		case SO_BROADCAST:
			*i1 = rts->rts_broadcast;
			break;
		case SO_PROTOTYPE:
			*i1 = rts->rts_proto;
			break;
		/*
		 * The following two items can be manipulated,
		 * but changing them should do nothing.
		 */
		case SO_SNDBUF:
			ASSERT(q->q_hiwat <= INT_MAX);
			*i1 = (int)(q->q_hiwat);
			break;
		case SO_RCVBUF:
			ASSERT(q->q_hiwat <= INT_MAX);
			*i1 = (int)(RD(q)->q_hiwat);
			break;
		case SO_DOMAIN:
			*i1 = PF_ROUTE;
			break;
		default:
			return (-1);
		}
		break;
	default:
		return (-1);
	}
	return ((int)sizeof (int));
}


/*
 * This routine sets socket options.
 */
/*ARGSUSED*/
int
rts_opt_set(queue_t *q, uint_t optset_context, int level,
    int name, uint_t inlen, uchar_t *invalp, uint_t *outlenp,
    uchar_t *outvalp, void *thisdg_attrs, cred_t *cr, mblk_t *mblk)
{
	int	*i1 = (int *)invalp;
	conn_t	*connp = Q_TO_CONN(q);
	rts_t	*rts = connp->conn_rts;
	boolean_t checkonly;
	rts_stack_t	*rtss = rts->rts_rtss;

	switch (optset_context) {
	case SETFN_OPTCOM_CHECKONLY:
		checkonly = B_TRUE;
		/*
		 * Note: Implies T_CHECK semantics for T_OPTCOM_REQ
		 * inlen != 0 implies value supplied and
		 * 	we have to "pretend" to set it.
		 * inlen == 0 implies that there is no
		 * 	value part in T_CHECK request and just validation
		 * done elsewhere should be enough, we just return here.
		 */
		if (inlen == 0) {
			*outlenp = 0;
			return (0);
		}
		break;
	case SETFN_OPTCOM_NEGOTIATE:
		checkonly = B_FALSE;
		break;
	case SETFN_UD_NEGOTIATE:
	case SETFN_CONN_NEGOTIATE:
		checkonly = B_FALSE;
		/*
		 * Negotiating local and "association-related" options
		 * through T_UNITDATA_REQ or T_CONN_{REQ,CON}
		 * Not allowed in this module.
		 */
		return (EINVAL);
	default:
		/*
		 * We should never get here
		 */
		*outlenp = 0;
		return (EINVAL);
	}

	ASSERT((optset_context != SETFN_OPTCOM_CHECKONLY) ||
	    (optset_context == SETFN_OPTCOM_CHECKONLY && inlen != 0));

	/*
	 * For rts, we should have no ancillary data sent down
	 * (rts_wput doesn't handle options).
	 */
	ASSERT(thisdg_attrs == NULL);

	/*
	 * For fixed length options, no sanity check
	 * of passed in length is done. It is assumed *_optcom_req()
	 * routines do the right thing.
	 */

	switch (level) {
	case SOL_SOCKET:
		switch (name) {
		case SO_REUSEADDR:
			if (!checkonly)
				rts->rts_reuseaddr = *i1;
			break;	/* goto sizeof (int) option return */
		case SO_DEBUG:
			if (!checkonly)
				rts->rts_debug = *i1;
			break;	/* goto sizeof (int) option return */
		/*
		 * The following three items are available here,
		 * but are only meaningful to IP.
		 */
		case SO_DONTROUTE:
			if (!checkonly)
				rts->rts_dontroute = *i1;
			break;	/* goto sizeof (int) option return */
		case SO_USELOOPBACK:
			if (!checkonly)
				rts->rts_useloopback = *i1;
			break;	/* goto sizeof (int) option return */
		case SO_BROADCAST:
			if (!checkonly)
				rts->rts_broadcast = *i1;
			break;	/* goto sizeof (int) option return */
		case SO_PROTOTYPE:
			/*
			 * Routing socket applications that call socket() with
			 * a third argument can filter which messages will be
			 * sent upstream thanks to sockfs.  so_socket() sends
			 * down the SO_PROTOTYPE and rts_queue_input()
			 * implements the filtering.
			 */
			if (*i1 != AF_INET && *i1 != AF_INET6)
				return (EPROTONOSUPPORT);
			if (!checkonly)
				rts->rts_proto = *i1;
			break;	/* goto sizeof (int) option return */
		/*
		 * The following two items can be manipulated,
		 * but changing them should do nothing.
		 */
		case SO_SNDBUF:
			if (*i1 > rtss->rtss_max_buf) {
				*outlenp = 0;
				return (ENOBUFS);
			}
			if (!checkonly) {
				q->q_hiwat = *i1;
			}
			break;	/* goto sizeof (int) option return */
		case SO_RCVBUF:
			if (*i1 > rtss->rtss_max_buf) {
				*outlenp = 0;
				return (ENOBUFS);
			}
			if (!checkonly) {
				RD(q)->q_hiwat = *i1;
				(void) mi_set_sth_hiwat(RD(q), *i1);
			}
			break;	/* goto sizeof (int) option return */
		default:
			*outlenp = 0;
			return (EINVAL);
		}
		break;
	default:
		*outlenp = 0;
		return (EINVAL);
	}
	/*
	 * Common case of return from an option that is sizeof (int)
	 */
	*(int *)outvalp = *i1;
	*outlenp = (t_uscalar_t)sizeof (int);
	return (0);
}

/*
 * This routine retrieves the value of an ND variable in a rtsparam_t
 * structure. It is called through nd_getset when a user reads the
 * variable.
 */
/* ARGSUSED */
static int
rts_param_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *cr)
{
	rtsparam_t	*rtspa = (rtsparam_t *)cp;

	(void) mi_mpprintf(mp, "%u", rtspa->rts_param_value);
	return (0);
}

/*
 * Walk through the param array specified registering each element with the
 * named dispatch (ND) handler.
 */
static boolean_t
rts_param_register(IDP *ndp, rtsparam_t *rtspa, int cnt)
{
	for (; cnt-- > 0; rtspa++) {
		if (rtspa->rts_param_name != NULL && rtspa->rts_param_name[0]) {
			if (!nd_load(ndp, rtspa->rts_param_name,
			    rts_param_get, rts_param_set, (caddr_t)rtspa)) {
				nd_free(ndp);
				return (B_FALSE);
			}
		}
	}
	return (B_TRUE);
}

/* This routine sets an ND variable in a rtsparam_t structure. */
/* ARGSUSED */
static int
rts_param_set(queue_t *q, mblk_t *mp, char *value, caddr_t cp, cred_t *cr)
{
	ulong_t	new_value;
	rtsparam_t	*rtspa = (rtsparam_t *)cp;

	/*
	 * Fail the request if the new value does not lie within the
	 * required bounds.
	 */
	if (ddi_strtoul(value, NULL, 10, &new_value) != 0 ||
	    new_value < rtspa->rts_param_min ||
	    new_value > rtspa->rts_param_max) {
		return (EINVAL);
	}

	/* Set the new value */
	rtspa->rts_param_value = new_value;
	return (0);
}

/*
 * Empty rsrv routine which is used by rts_input to cause a wakeup
 * of a thread in qwait.
 */
/*ARGSUSED*/
static void
rts_rsrv(queue_t *q)
{
}

/*
 * This routine handles synchronous messages passed downstream. It either
 * consumes the message or passes it downstream; it never queues a
 * a message. The data messages that go down are wrapped in an IOCTL
 * message.
 *
 * Since it is synchronous, it waits for the M_IOCACK/M_IOCNAK so that
 * it can return an immediate error (such as ENETUNREACH when adding a route).
 * It uses the RTS_WRW_PENDING to ensure that each rts instance has only
 * one M_IOCTL outstanding at any given time.
 */
static int
rts_wrw(queue_t *q, struiod_t *dp)
{
	mblk_t	*mp = dp->d_mp;
	mblk_t	*mp1;
	int	error;
	rt_msghdr_t	*rtm;
	conn_t	*connp = Q_TO_CONN(q);
	rts_t	*rts = connp->conn_rts;

	while (rts->rts_flag & RTS_WRW_PENDING) {
		if (qwait_rw(q)) {
			rts->rts_error = EINTR;
			goto err_ret;
		}
		}
	rts->rts_flag |= RTS_WRW_PENDING;

	if (isuioq(q) && (error = struioget(q, mp, dp, 0))) {
		/*
		 * Uio error of some sort, so just return the error.
		 */
		rts->rts_error = error;
		goto err_ret;
	}
	/*
	 * Pass the mblk (chain) onto wput().
	 */
	dp->d_mp = 0;

	switch (mp->b_datap->db_type) {
	case M_PROTO:
	case M_PCPROTO:
		/* Expedite other than T_DATA_REQ to below the switch */
		if (((mp->b_wptr - mp->b_rptr) !=
		    sizeof (struct T_data_req)) ||
		    (((union T_primitives *)mp->b_rptr)->type != T_DATA_REQ))
			break;
		if ((mp1 = mp->b_cont) == NULL) {
			rts->rts_error = EINVAL;
			goto err_ret;
		}
		freeb(mp);
		mp = mp1;
		/* FALLTHRU */
	case M_DATA:
		/*
		 * The semantics of the routing socket is such that the rtm_pid
		 * field is automatically filled in during requests with the
		 * current process' pid.  We do this here (where we still have
		 * user context) after checking we have at least a message the
		 * size of a routing message header.
		 */
		if ((mp->b_wptr - mp->b_rptr) < sizeof (rt_msghdr_t)) {
			if (!pullupmsg(mp, sizeof (rt_msghdr_t))) {
				rts->rts_error = EINVAL;
				goto err_ret;
			}
		}
		rtm = (rt_msghdr_t *)mp->b_rptr;
		rtm->rtm_pid = curproc->p_pid;
		break;
	default:
		break;
	}
	rts->rts_flag |= RTS_WPUT_PENDING;
	rts_wput(q, mp);
	while (rts->rts_flag & RTS_WPUT_PENDING)
		if (qwait_rw(q)) {
			/* RTS_WPUT_PENDING will be cleared below */
			rts->rts_error = EINTR;
			break;
		}
err_ret:
	rts->rts_flag &= ~(RTS_WPUT_PENDING | RTS_WRW_PENDING);
	return (rts->rts_error);
}

/*
 * This routine handles all messages passed downstream. It either
 * consumes the message or passes it downstream; it never queues a
 * a message. The data messages that go down are wrapped in an IOCTL
 * message.
 *
 * FIXME? Should we call IP rts_request directly? Could punt on returning
 * errno in the case when it defers processing due to
 * IPIF_CHANGING/ILL_CHANGING???
 */
static void
rts_wput(queue_t *q, mblk_t *mp)
{
	uchar_t	*rptr = mp->b_rptr;
	mblk_t	*mp1;
	conn_t	*connp = Q_TO_CONN(q);
	rts_t	*rts = connp->conn_rts;

	switch (mp->b_datap->db_type) {
	case M_DATA:
		break;
	case M_PROTO:
	case M_PCPROTO:
		if ((mp->b_wptr - rptr) == sizeof (struct T_data_req)) {
			/* Expedite valid T_DATA_REQ to below the switch */
			if (((union T_primitives *)rptr)->type == T_DATA_REQ) {
				mp1 = mp->b_cont;
				freeb(mp);
				if (mp1 == NULL)
					return;
				mp = mp1;
				break;
			}
		}
		/* FALLTHRU */
	default:
		rts_wput_other(q, mp);
		return;
	}


	mp1 = rts_ioctl_alloc(mp, DB_CRED(mp));
	if (mp1 == NULL) {
		ASSERT(rts != NULL);
		freemsg(mp);
		if (rts->rts_flag & RTS_WPUT_PENDING) {
			rts->rts_error = ENOMEM;
			rts->rts_flag &= ~RTS_WPUT_PENDING;
		}
		return;
	}
	ip_output(connp, mp1, q, IP_WPUT);
}


/*
 * Handles all the control message, if it
 * can not understand it, it will
 * pass down stream.
 */
static void
rts_wput_other(queue_t *q, mblk_t *mp)
{
	conn_t	*connp = Q_TO_CONN(q);
	rts_t	*rts = connp->conn_rts;
	uchar_t	*rptr = mp->b_rptr;
	struct iocblk	*iocp;
	cred_t	*cr;
	rts_stack_t	*rtss;

	rtss = rts->rts_rtss;

	cr = DB_CREDDEF(mp, connp->conn_cred);

	switch (mp->b_datap->db_type) {
	case M_PROTO:
	case M_PCPROTO:
		if ((mp->b_wptr - rptr) < sizeof (t_scalar_t)) {
			/*
			 * If the message does not contain a PRIM_type,
			 * throw it away.
			 */
			freemsg(mp);
			return;
		}
		switch (((union T_primitives *)rptr)->type) {
		case T_BIND_REQ:
		case O_T_BIND_REQ:
			rts_bind(q, mp);
			return;
		case T_UNBIND_REQ:
			rts_unbind(q, mp);
			return;
		case T_CAPABILITY_REQ:
			rts_capability_req(q, mp);
			return;
		case T_INFO_REQ:
			rts_info_req(q, mp);
			return;
		case T_SVR4_OPTMGMT_REQ:
			(void) svr4_optcom_req(q, mp, cr, &rts_opt_obj,
			    B_TRUE);
			return;
		case T_OPTMGMT_REQ:
			(void) tpi_optcom_req(q, mp, cr, &rts_opt_obj, B_TRUE);
			return;
		case O_T_CONN_RES:
		case T_CONN_RES:
		case T_DISCON_REQ:
			/* Not supported by rts. */
			rts_err_ack(q, mp, TNOTSUPPORT, 0);
			return;
		case T_DATA_REQ:
		case T_EXDATA_REQ:
		case T_ORDREL_REQ:
			/* Illegal for rts. */
			freemsg(mp);
			(void) putnextctl1(RD(q), M_ERROR, EPROTO);
			return;
		default:
			break;
		}
		break;
	case M_IOCTL:
		iocp = (struct iocblk *)mp->b_rptr;
		switch (iocp->ioc_cmd) {
		case ND_SET:
		case ND_GET:
			if (nd_getset(q, rtss->rtss_g_nd, mp)) {
				qreply(q, mp);
				return;
			}
			break;
		case TI_GETPEERNAME:
			mi_copyin(q, mp, NULL,
			    SIZEOF_STRUCT(strbuf, iocp->ioc_flag));
			return;
		default:
			break;
		}
	case M_IOCDATA:
		rts_wput_iocdata(q, mp);
		return;
	default:
		break;
	}
	ip_output(connp, mp, q, IP_WPUT);
}

/*
 * Called by rts_wput_other to handle all M_IOCDATA messages.
 */
static void
rts_wput_iocdata(queue_t *q, mblk_t *mp)
{
	conn_t *connp = Q_TO_CONN(q);
	struct sockaddr	*rtsaddr;
	mblk_t	*mp1;
	STRUCT_HANDLE(strbuf, sb);
	struct iocblk	*iocp	= (struct iocblk *)mp->b_rptr;

	/* Make sure it is one of ours. */
	switch (iocp->ioc_cmd) {
	case TI_GETPEERNAME:
		break;
	default:
		ip_output(connp, mp, q, IP_WPUT);
		return;
	}
	switch (mi_copy_state(q, mp, &mp1)) {
	case -1:
		return;
	case MI_COPY_CASE(MI_COPY_IN, 1):
		break;
	case MI_COPY_CASE(MI_COPY_OUT, 1):
		/* Copy out the strbuf. */
		mi_copyout(q, mp);
		return;
	case MI_COPY_CASE(MI_COPY_OUT, 2):
		/* All done. */
		mi_copy_done(q, mp, 0);
		return;
	default:
		mi_copy_done(q, mp, EPROTO);
		return;
	}
	STRUCT_SET_HANDLE(sb, iocp->ioc_flag, (void *)mp1->b_rptr);
	if (STRUCT_FGET(sb, maxlen) < (int)sizeof (sin_t)) {
		mi_copy_done(q, mp, EINVAL);
		return;
	}
	switch (iocp->ioc_cmd) {
	case TI_GETPEERNAME:
		break;
	default:
		mi_copy_done(q, mp, EPROTO);
		return;
	}
	mp1 = mi_copyout_alloc(q, mp, STRUCT_FGETP(sb, buf), sizeof (sin_t),
	    B_TRUE);
	if (mp1 == NULL)
		return;
	STRUCT_FSET(sb, len, (int)sizeof (sin_t));
	rtsaddr = (struct sockaddr *)mp1->b_rptr;
	mp1->b_wptr = (uchar_t *)&rtsaddr[1];
	bzero(rtsaddr, sizeof (struct sockaddr));
	rtsaddr->sa_family = AF_ROUTE;
	/* Copy out the address */
	mi_copyout(q, mp);
}

/*ARGSUSED2*/
static void
rts_input(void *arg1, mblk_t *mp, void *arg2)
{
	conn_t *connp = (conn_t *)arg1;
	rts_t	*rts = connp->conn_rts;
	struct iocblk	*iocp;
	mblk_t *mp1;
	struct T_data_ind *tdi;

	switch (mp->b_datap->db_type) {
	case M_IOCACK:
	case M_IOCNAK:
		iocp = (struct iocblk *)mp->b_rptr;
		if (rts->rts_flag & (RTS_WPUT_PENDING)) {
			rts->rts_flag &= ~RTS_WPUT_PENDING;
			rts->rts_error = iocp->ioc_error;
			/*
			 * Tell rts_wvw/qwait that we are done.
			 * Note: there is no qwait_wakeup() we can use.
			 */
			qenable(connp->conn_rq);
			freemsg(mp);
			return;
		}
		break;
	case M_DATA:
		/*
		 * Prepend T_DATA_IND to prevent the stream head from
		 * consolidating multiple messages together.
		 * If the allocation fails just send up the M_DATA.
		 */
		mp1 = allocb(sizeof (*tdi), BPRI_MED);
		if (mp1 != NULL) {
			mp1->b_cont = mp;
			mp = mp1;

			mp->b_datap->db_type = M_PROTO;
			mp->b_wptr += sizeof (*tdi);
			tdi = (struct T_data_ind *)mp->b_rptr;
			tdi->PRIM_type = T_DATA_IND;
			tdi->MORE_flag = 0;
		}
		break;
	default:
		break;
	}
	putnext(connp->conn_rq, mp);
}


void
rts_ddi_init(void)
{
	rts_max_optsize = optcom_max_optsize(rts_opt_obj.odb_opt_des_arr,
	    rts_opt_obj.odb_opt_arr_cnt);

	/*
	 * We want to be informed each time a stack is created or
	 * destroyed in the kernel, so we can maintain the
	 * set of rts_stack_t's.
	 */
	netstack_register(NS_RTS, rts_stack_init, NULL, rts_stack_fini);
}

void
rts_ddi_destroy(void)
{
	netstack_unregister(NS_RTS);
}

/*
 * Initialize the RTS stack instance.
 */
/* ARGSUSED */
static void *
rts_stack_init(netstackid_t stackid, netstack_t *ns)
{
	rts_stack_t	*rtss;
	rtsparam_t	*pa;

	rtss = (rts_stack_t *)kmem_zalloc(sizeof (*rtss), KM_SLEEP);
	rtss->rtss_netstack = ns;

	pa = (rtsparam_t *)kmem_alloc(sizeof (lcl_param_arr), KM_SLEEP);
	rtss->rtss_params = pa;
	bcopy(lcl_param_arr, rtss->rtss_params, sizeof (lcl_param_arr));

	(void) rts_param_register(&rtss->rtss_g_nd,
	    rtss->rtss_params, A_CNT(lcl_param_arr));
	return (rtss);
}

/*
 * Free the RTS stack instance.
 */
/* ARGSUSED */
static void
rts_stack_fini(netstackid_t stackid, void *arg)
{
	rts_stack_t *rtss = (rts_stack_t *)arg;

	nd_free(&rtss->rtss_g_nd);
	kmem_free(rtss->rtss_params, sizeof (lcl_param_arr));
	rtss->rtss_params = NULL;
	kmem_free(rtss, sizeof (*rtss));
}
