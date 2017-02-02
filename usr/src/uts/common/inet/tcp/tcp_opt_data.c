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
 * Copyright (c) 2011 Nexenta Systems, Inc. All rights reserved.
 */

#include <sys/types.h>
#include <sys/stream.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/socket.h>
#include <sys/xti_xtiopt.h>
#include <sys/xti_inet.h>
#include <sys/policy.h>

#include <inet/common.h>
#include <netinet/ip6.h>
#include <inet/ip.h>

#include <netinet/in.h>
#include <netinet/tcp.h>
#include <inet/optcom.h>
#include <inet/proto_set.h>
#include <inet/tcp_impl.h>

static int	tcp_opt_default(queue_t *, int, int, uchar_t *);

/*
 * Table of all known options handled on a TCP protocol stack.
 *
 * Note: This table contains options processed by both TCP and IP levels
 *       and is the superset of options that can be performed on a TCP over IP
 *       stack.
 */
opdes_t	tcp_opt_arr[] = {

{ SO_LINGER,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0,
	sizeof (struct linger), 0 },

{ SO_DEBUG,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_KEEPALIVE,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_DONTROUTE,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_USELOOPBACK, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0
	},
{ SO_BROADCAST,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_REUSEADDR, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_OOBINLINE, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_TYPE,	SOL_SOCKET, OA_R, OA_R, OP_NP, 0, sizeof (int), 0 },
{ SO_SNDBUF,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_RCVBUF,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_SNDTIMEO,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0,
	sizeof (struct timeval), 0 },
{ SO_RCVTIMEO,	SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0,
	sizeof (struct timeval), 0 },
{ SO_DGRAM_ERRIND, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0
	},
{ SO_SND_COPYAVOID, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ SO_ANON_MLP, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int),
	0 },
{ SO_MAC_EXEMPT, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int),
	0 },
{ SO_MAC_IMPLICIT, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int),
	0 },
{ SO_ALLZONES, SOL_SOCKET, OA_R, OA_RW, OP_CONFIG, 0, sizeof (int),
	0 },
{ SO_EXCLBIND, SOL_SOCKET, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },

{ SO_DOMAIN,	SOL_SOCKET, OA_R, OA_R, OP_NP, 0, sizeof (int), 0 },

{ SO_PROTOTYPE,	SOL_SOCKET, OA_R, OA_R, OP_NP, 0, sizeof (int), 0 },

{ TCP_NODELAY,	IPPROTO_TCP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0
	},
{ TCP_MAXSEG,	IPPROTO_TCP, OA_R, OA_R, OP_NP, 0, sizeof (uint_t),
	536 },

{ TCP_NOTIFY_THRESHOLD, IPPROTO_TCP, OA_RW, OA_RW, OP_NP,
	OP_DEF_FN, sizeof (int), -1 /* not initialized */ },

{ TCP_ABORT_THRESHOLD, IPPROTO_TCP, OA_RW, OA_RW, OP_NP,
	OP_DEF_FN, sizeof (int), -1 /* not initialized */ },

{ TCP_CONN_NOTIFY_THRESHOLD, IPPROTO_TCP, OA_RW, OA_RW, OP_NP,
	OP_DEF_FN, sizeof (int), -1 /* not initialized */ },

{ TCP_CONN_ABORT_THRESHOLD, IPPROTO_TCP, OA_RW, OA_RW, OP_NP,
	OP_DEF_FN, sizeof (int), -1 /* not initialized */ },

{ TCP_RECVDSTADDR, IPPROTO_TCP, OA_RW, OA_RW, OP_NP, 0, sizeof (int),
	0 },

{ TCP_ANONPRIVBIND, IPPROTO_TCP, OA_R, OA_RW, OP_PRIVPORT, 0,
	sizeof (int), 0 },

{ TCP_EXCLBIND, IPPROTO_TCP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0
	},

{ TCP_INIT_CWND, IPPROTO_TCP, OA_RW, OA_RW, OP_CONFIG, 0,
	sizeof (int), 0 },

{ TCP_KEEPALIVE_THRESHOLD, IPPROTO_TCP, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0	},

{ TCP_KEEPIDLE, IPPROTO_TCP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },

{ TCP_KEEPCNT, IPPROTO_TCP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },

{ TCP_KEEPINTVL, IPPROTO_TCP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },

{ TCP_KEEPALIVE_ABORT_THRESHOLD, IPPROTO_TCP, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0	},

{ TCP_CORK, IPPROTO_TCP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },

{ TCP_RTO_INITIAL, IPPROTO_TCP, OA_RW, OA_RW, OP_NP, 0, sizeof (uint32_t), 0 },

{ TCP_RTO_MIN, IPPROTO_TCP, OA_RW, OA_RW, OP_NP, 0, sizeof (uint32_t), 0 },

{ TCP_RTO_MAX, IPPROTO_TCP, OA_RW, OA_RW, OP_NP, 0, sizeof (uint32_t), 0 },

{ TCP_LINGER2, IPPROTO_TCP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },

{ IP_OPTIONS,	IPPROTO_IP, OA_RW, OA_RW, OP_NP,
	(OP_VARLEN|OP_NODEFAULT),
	IP_MAX_OPT_LENGTH + IP_ADDR_LEN, -1 /* not initialized */ },
{ T_IP_OPTIONS,	IPPROTO_IP, OA_RW, OA_RW, OP_NP,
	(OP_VARLEN|OP_NODEFAULT),
	IP_MAX_OPT_LENGTH + IP_ADDR_LEN, -1 /* not initialized */ },

{ IP_TOS,	IPPROTO_IP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ T_IP_TOS,	IPPROTO_IP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },
{ IP_TTL,	IPPROTO_IP, OA_RW, OA_RW, OP_NP, OP_DEF_FN,
	sizeof (int), -1 /* not initialized */ },

{ IP_SEC_OPT, IPPROTO_IP, OA_RW, OA_RW, OP_NP, OP_NODEFAULT,
	sizeof (ipsec_req_t), -1 /* not initialized */ },

{ IP_BOUND_IF, IPPROTO_IP, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int),	0 /* no ifindex */ },

{ IP_UNSPEC_SRC, IPPROTO_IP, OA_R, OA_RW, OP_RAW, 0,
	sizeof (int), 0 },

{ IPV6_UNICAST_HOPS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, OP_DEF_FN,
	sizeof (int), -1 /* not initialized */ },

{ IPV6_BOUND_IF, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int),	0 /* no ifindex */ },

{ IP_DONTFRAG, IPPROTO_IP, OA_RW, OA_RW, OP_NP, 0, sizeof (int), 0 },

{ IP_NEXTHOP, IPPROTO_IP, OA_R, OA_RW, OP_CONFIG, 0,
	sizeof (in_addr_t),	-1 /* not initialized  */ },

{ IPV6_UNSPEC_SRC, IPPROTO_IPV6, OA_R, OA_RW, OP_RAW, 0,
	sizeof (int), 0 },

{ IPV6_PKTINFO, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	(OP_NODEFAULT|OP_VARLEN),
	sizeof (struct in6_pktinfo), -1 /* not initialized */ },
{ IPV6_NEXTHOP, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	OP_NODEFAULT,
	sizeof (sin6_t), -1 /* not initialized */ },
{ IPV6_HOPOPTS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	(OP_VARLEN|OP_NODEFAULT), 255*8,
	-1 /* not initialized */ },
{ IPV6_DSTOPTS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	(OP_VARLEN|OP_NODEFAULT), 255*8,
	-1 /* not initialized */ },
{ IPV6_RTHDRDSTOPTS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	(OP_VARLEN|OP_NODEFAULT), 255*8,
	-1 /* not initialized */ },
{ IPV6_RTHDR, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	(OP_VARLEN|OP_NODEFAULT), 255*8,
	-1 /* not initialized */ },
{ IPV6_TCLASS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	OP_NODEFAULT,
	sizeof (int), -1 /* not initialized */ },
{ IPV6_PATHMTU, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP,
	OP_NODEFAULT,
	sizeof (struct ip6_mtuinfo), -1 /* not initialized */ },
{ IPV6_DONTFRAG, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },
{ IPV6_USE_MIN_MTU, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },
{ IPV6_V6ONLY, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },

/* Enable receipt of ancillary data */
{ IPV6_RECVPKTINFO, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },
{ IPV6_RECVHOPLIMIT, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },
{ IPV6_RECVHOPOPTS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },
{ _OLD_IPV6_RECVDSTOPTS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },
{ IPV6_RECVDSTOPTS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },
{ IPV6_RECVRTHDR, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },
{ IPV6_RECVRTHDRDSTOPTS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },
{ IPV6_RECVTCLASS, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (int), 0 },

{ IPV6_SEC_OPT, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, OP_NODEFAULT,
	sizeof (ipsec_req_t), -1 /* not initialized */ },
{ IPV6_SRC_PREFERENCES, IPPROTO_IPV6, OA_RW, OA_RW, OP_NP, 0,
	sizeof (uint32_t), IPV6_PREFER_SRC_DEFAULT },
};

/*
 * Table of all supported levels
 * Note: Some levels (e.g. XTI_GENERIC) may be valid but may not have
 * any supported options so we need this info separately.
 *
 * This is needed only for topmost tpi providers and is used only by
 * XTI interfaces.
 */
optlevel_t	tcp_valid_levels_arr[] = {
	XTI_GENERIC,
	SOL_SOCKET,
	IPPROTO_TCP,
	IPPROTO_IP,
	IPPROTO_IPV6
};


#define	TCP_OPT_ARR_CNT		A_CNT(tcp_opt_arr)
#define	TCP_VALID_LEVELS_CNT	A_CNT(tcp_valid_levels_arr)

uint_t tcp_max_optsize; /* initialized when TCP driver is loaded */

/*
 * Initialize option database object for TCP
 *
 * This object represents database of options to search passed to
 * {sock,tpi}optcom_req() interface routine to take care of option
 * management and associated methods.
 */

optdb_obj_t tcp_opt_obj = {
	tcp_opt_default,	/* TCP default value function pointer */
	tcp_tpi_opt_get,	/* TCP get function pointer */
	tcp_tpi_opt_set,	/* TCP set function pointer */
	TCP_OPT_ARR_CNT,	/* TCP option database count of entries */
	tcp_opt_arr,		/* TCP option database */
	TCP_VALID_LEVELS_CNT,	/* TCP valid level count of entries */
	tcp_valid_levels_arr	/* TCP valid level array */
};

static int tcp_max_init_cwnd = TCP_MAX_INIT_CWND;

/*
 * Some TCP options can be "set" by requesting them in the option
 * buffer. This is needed for XTI feature test though we do not
 * allow it in general. We interpret that this mechanism is more
 * applicable to OSI protocols and need not be allowed in general.
 * This routine filters out options for which it is not allowed (most)
 * and lets through those (few) for which it is. [ The XTI interface
 * test suite specifics will imply that any XTI_GENERIC level XTI_* if
 * ever implemented will have to be allowed here ].
 */
static boolean_t
tcp_allow_connopt_set(int level, int name)
{

	switch (level) {
	case IPPROTO_TCP:
		switch (name) {
		case TCP_NODELAY:
			return (B_TRUE);
		default:
			return (B_FALSE);
		}
		/*NOTREACHED*/
	default:
		return (B_FALSE);
	}
	/*NOTREACHED*/
}

/*
 * This routine gets default values of certain options whose default
 * values are maintained by protocol specific code
 */
/* ARGSUSED */
static int
tcp_opt_default(queue_t *q, int level, int name, uchar_t *ptr)
{
	int32_t	*i1 = (int32_t *)ptr;
	tcp_stack_t	*tcps = Q_TO_TCP(q)->tcp_tcps;

	switch (level) {
	case IPPROTO_TCP:
		switch (name) {
		case TCP_NOTIFY_THRESHOLD:
			*i1 = tcps->tcps_ip_notify_interval;
			break;
		case TCP_ABORT_THRESHOLD:
			*i1 = tcps->tcps_ip_abort_interval;
			break;
		case TCP_CONN_NOTIFY_THRESHOLD:
			*i1 = tcps->tcps_ip_notify_cinterval;
			break;
		case TCP_CONN_ABORT_THRESHOLD:
			*i1 = tcps->tcps_ip_abort_cinterval;
			break;
		default:
			return (-1);
		}
		break;
	case IPPROTO_IP:
		switch (name) {
		case IP_TTL:
			*i1 = tcps->tcps_ipv4_ttl;
			break;
		default:
			return (-1);
		}
		break;
	case IPPROTO_IPV6:
		switch (name) {
		case IPV6_UNICAST_HOPS:
			*i1 = tcps->tcps_ipv6_hoplimit;
			break;
		default:
			return (-1);
		}
		break;
	default:
		return (-1);
	}
	return (sizeof (int));
}

/*
 * TCP routine to get the values of options.
 */
int
tcp_opt_get(conn_t *connp, int level, int name, uchar_t *ptr)
{
	int		*i1 = (int *)ptr;
	tcp_t		*tcp = connp->conn_tcp;
	conn_opt_arg_t	coas;
	int		retval;

	coas.coa_connp = connp;
	coas.coa_ixa = connp->conn_ixa;
	coas.coa_ipp = &connp->conn_xmit_ipp;
	coas.coa_ancillary = B_FALSE;
	coas.coa_changed = 0;

	switch (level) {
	case SOL_SOCKET:
		switch (name) {
		case SO_SND_COPYAVOID:
			*i1 = tcp->tcp_snd_zcopy_on ?
			    SO_SND_COPYAVOID : 0;
			return (sizeof (int));
		case SO_ACCEPTCONN:
			*i1 = (tcp->tcp_state == TCPS_LISTEN);
			return (sizeof (int));
		}
		break;
	case IPPROTO_TCP:
		switch (name) {
		case TCP_NODELAY:
			*i1 = (tcp->tcp_naglim == 1) ? TCP_NODELAY : 0;
			return (sizeof (int));
		case TCP_MAXSEG:
			*i1 = tcp->tcp_mss;
			return (sizeof (int));
		case TCP_NOTIFY_THRESHOLD:
			*i1 = (int)tcp->tcp_first_timer_threshold;
			return (sizeof (int));
		case TCP_ABORT_THRESHOLD:
			*i1 = tcp->tcp_second_timer_threshold;
			return (sizeof (int));
		case TCP_CONN_NOTIFY_THRESHOLD:
			*i1 = tcp->tcp_first_ctimer_threshold;
			return (sizeof (int));
		case TCP_CONN_ABORT_THRESHOLD:
			*i1 = tcp->tcp_second_ctimer_threshold;
			return (sizeof (int));
		case TCP_INIT_CWND:
			*i1 = tcp->tcp_init_cwnd;
			return (sizeof (int));
		case TCP_KEEPALIVE_THRESHOLD:
			*i1 = tcp->tcp_ka_interval;
			return (sizeof (int));

		/*
		 * TCP_KEEPIDLE expects value in seconds, but
		 * tcp_ka_interval is in milliseconds.
		 */
		case TCP_KEEPIDLE:
			*i1 = tcp->tcp_ka_interval / 1000;
			return (sizeof (int));
		case TCP_KEEPCNT:
			*i1 = tcp->tcp_ka_cnt;
			return (sizeof (int));

		/*
		 * TCP_KEEPINTVL expects value in seconds, but
		 * tcp_ka_rinterval is in milliseconds.
		 */
		case TCP_KEEPINTVL:
			*i1 = tcp->tcp_ka_rinterval / 1000;
			return (sizeof (int));
		case TCP_KEEPALIVE_ABORT_THRESHOLD:
			*i1 = tcp->tcp_ka_abort_thres;
			return (sizeof (int));
		case TCP_CORK:
			*i1 = tcp->tcp_cork;
			return (sizeof (int));
		case TCP_RTO_INITIAL:
			*i1 = tcp->tcp_rto_initial;
			return (sizeof (uint32_t));
		case TCP_RTO_MIN:
			*i1 = tcp->tcp_rto_min;
			return (sizeof (uint32_t));
		case TCP_RTO_MAX:
			*i1 = tcp->tcp_rto_max;
			return (sizeof (uint32_t));
		case TCP_LINGER2:
			*i1 = tcp->tcp_fin_wait_2_flush_interval / SECONDS;
			return (sizeof (int));
		}
		break;
	case IPPROTO_IP:
		if (connp->conn_family != AF_INET)
			return (-1);
		switch (name) {
		case IP_OPTIONS:
		case T_IP_OPTIONS:
			/* Caller ensures enough space */
			return (ip_opt_get_user(connp, ptr));
		default:
			break;
		}
		break;

	case IPPROTO_IPV6:
		/*
		 * IPPROTO_IPV6 options are only supported for sockets
		 * that are using IPv6 on the wire.
		 */
		if (connp->conn_ipversion != IPV6_VERSION) {
			return (-1);
		}
		switch (name) {
		case IPV6_PATHMTU:
			if (tcp->tcp_state < TCPS_ESTABLISHED)
				return (-1);
			break;
		}
		break;
	}
	mutex_enter(&connp->conn_lock);
	retval = conn_opt_get(&coas, level, name, ptr);
	mutex_exit(&connp->conn_lock);
	return (retval);
}

/*
 * We declare as 'int' rather than 'void' to satisfy pfi_t arg requirements.
 * Parameters are assumed to be verified by the caller.
 */
/* ARGSUSED */
int
tcp_opt_set(conn_t *connp, uint_t optset_context, int level, int name,
    uint_t inlen, uchar_t *invalp, uint_t *outlenp, uchar_t *outvalp,
    void *thisdg_attrs, cred_t *cr)
{
	tcp_t	*tcp = connp->conn_tcp;
	int	*i1 = (int *)invalp;
	boolean_t onoff = (*i1 == 0) ? 0 : 1;
	boolean_t checkonly;
	int	reterr;
	tcp_stack_t	*tcps = tcp->tcp_tcps;
	conn_opt_arg_t	coas;
	uint32_t	val = *((uint32_t *)invalp);

	coas.coa_connp = connp;
	coas.coa_ixa = connp->conn_ixa;
	coas.coa_ipp = &connp->conn_xmit_ipp;
	coas.coa_ancillary = B_FALSE;
	coas.coa_changed = 0;

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
	case SETFN_UD_NEGOTIATE: /* error on conn-oriented transports ? */
	case SETFN_CONN_NEGOTIATE:
		checkonly = B_FALSE;
		/*
		 * Negotiating local and "association-related" options
		 * from other (T_CONN_REQ, T_CONN_RES,T_UNITDATA_REQ)
		 * primitives is allowed by XTI, but we choose
		 * to not implement this style negotiation for Internet
		 * protocols (We interpret it is a must for OSI world but
		 * optional for Internet protocols) for all options.
		 * [ Will do only for the few options that enable test
		 * suites that our XTI implementation of this feature
		 * works for transports that do allow it ]
		 */
		if (!tcp_allow_connopt_set(level, name)) {
			*outlenp = 0;
			return (EINVAL);
		}
		break;
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
	 * For TCP, we should have no ancillary data sent down
	 * (sendmsg isn't supported for SOCK_STREAM), so thisdg_attrs
	 * has to be zero.
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
		case SO_KEEPALIVE:
			if (checkonly) {
				/* check only case */
				break;
			}

			if (!onoff) {
				if (connp->conn_keepalive) {
					if (tcp->tcp_ka_tid != 0) {
						(void) TCP_TIMER_CANCEL(tcp,
						    tcp->tcp_ka_tid);
						tcp->tcp_ka_tid = 0;
					}
					connp->conn_keepalive = 0;
				}
				break;
			}
			if (!connp->conn_keepalive) {
				/* Crank up the keepalive timer */
				tcp->tcp_ka_last_intrvl = 0;
				tcp->tcp_ka_tid = TCP_TIMER(tcp,
				    tcp_keepalive_timer, tcp->tcp_ka_interval);
				connp->conn_keepalive = 1;
			}
			break;
		case SO_SNDBUF: {
			if (*i1 > tcps->tcps_max_buf) {
				*outlenp = 0;
				return (ENOBUFS);
			}
			if (checkonly)
				break;

			connp->conn_sndbuf = *i1;
			if (tcps->tcps_snd_lowat_fraction != 0) {
				connp->conn_sndlowat = connp->conn_sndbuf /
				    tcps->tcps_snd_lowat_fraction;
			}
			(void) tcp_maxpsz_set(tcp, B_TRUE);
			/*
			 * If we are flow-controlled, recheck the condition.
			 * There are apps that increase SO_SNDBUF size when
			 * flow-controlled (EWOULDBLOCK), and expect the flow
			 * control condition to be lifted right away.
			 */
			mutex_enter(&tcp->tcp_non_sq_lock);
			if (tcp->tcp_flow_stopped &&
			    TCP_UNSENT_BYTES(tcp) < connp->conn_sndbuf) {
				tcp_clrqfull(tcp);
			}
			mutex_exit(&tcp->tcp_non_sq_lock);
			*outlenp = inlen;
			return (0);
		}
		case SO_RCVBUF:
			if (*i1 > tcps->tcps_max_buf) {
				*outlenp = 0;
				return (ENOBUFS);
			}
			/* Silently ignore zero */
			if (!checkonly && *i1 != 0) {
				*i1 = MSS_ROUNDUP(*i1, tcp->tcp_mss);
				(void) tcp_rwnd_set(tcp, *i1);
			}
			/*
			 * XXX should we return the rwnd here
			 * and tcp_opt_get ?
			 */
			*outlenp = inlen;
			return (0);
		case SO_SND_COPYAVOID:
			if (!checkonly) {
				if (tcp->tcp_loopback ||
				    (onoff != 1) || !tcp_zcopy_check(tcp)) {
					*outlenp = 0;
					return (EOPNOTSUPP);
				}
				tcp->tcp_snd_zcopy_aware = 1;
			}
			*outlenp = inlen;
			return (0);
		}
		break;
	case IPPROTO_TCP:
		switch (name) {
		case TCP_NODELAY:
			if (!checkonly)
				tcp->tcp_naglim = *i1 ? 1 : tcp->tcp_mss;
			break;
		case TCP_NOTIFY_THRESHOLD:
			if (!checkonly)
				tcp->tcp_first_timer_threshold = *i1;
			break;
		case TCP_ABORT_THRESHOLD:
			if (!checkonly)
				tcp->tcp_second_timer_threshold = *i1;
			break;
		case TCP_CONN_NOTIFY_THRESHOLD:
			if (!checkonly)
				tcp->tcp_first_ctimer_threshold = *i1;
			break;
		case TCP_CONN_ABORT_THRESHOLD:
			if (!checkonly)
				tcp->tcp_second_ctimer_threshold = *i1;
			break;
		case TCP_RECVDSTADDR:
			if (tcp->tcp_state > TCPS_LISTEN) {
				*outlenp = 0;
				return (EOPNOTSUPP);
			}
			/* Setting done in conn_opt_set */
			break;
		case TCP_INIT_CWND:
			if (checkonly)
				break;

			/*
			 * Only allow socket with network configuration
			 * privilege to set the initial cwnd to be larger
			 * than allowed by RFC 3390.
			 */
			if (val > MIN(4, MAX(2, 4380 / tcp->tcp_mss))) {
				if ((reterr = secpolicy_ip_config(cr, B_TRUE))
				    != 0) {
					*outlenp = 0;
					return (reterr);
				}
				if (val > tcp_max_init_cwnd) {
					*outlenp = 0;
					return (EINVAL);
				}
			}

			tcp->tcp_init_cwnd = val;

			/*
			 * If the socket is connected, AND no outbound data
			 * has been sent, reset the actual cwnd values.
			 */
			if (tcp->tcp_state == TCPS_ESTABLISHED &&
			    tcp->tcp_iss == tcp->tcp_snxt - 1) {
				tcp->tcp_cwnd =
				    MIN(tcp->tcp_rwnd, val * tcp->tcp_mss);
			}
			break;

		/*
		 * TCP_KEEPIDLE is in seconds but TCP_KEEPALIVE_THRESHOLD
		 * is in milliseconds. TCP_KEEPIDLE is introduced for
		 * compatibility with other Unix flavors.
		 * We can fall through TCP_KEEPALIVE_THRESHOLD logic after
		 * converting the input to milliseconds.
		 */
		case TCP_KEEPIDLE:
			*i1 *= 1000;
			/* FALLTHRU */

		case TCP_KEEPALIVE_THRESHOLD:
			if (checkonly)
				break;

			if (*i1 < tcps->tcps_keepalive_interval_low ||
			    *i1 > tcps->tcps_keepalive_interval_high) {
				*outlenp = 0;
				return (EINVAL);
			}
			if (*i1 != tcp->tcp_ka_interval) {
				tcp->tcp_ka_interval = *i1;
				/*
				 * Check if we need to restart the
				 * keepalive timer.
				 */
				if (tcp->tcp_ka_tid != 0) {
					ASSERT(connp->conn_keepalive);
					(void) TCP_TIMER_CANCEL(tcp,
					    tcp->tcp_ka_tid);
					tcp->tcp_ka_last_intrvl = 0;
					tcp->tcp_ka_tid = TCP_TIMER(tcp,
					    tcp_keepalive_timer,
					    tcp->tcp_ka_interval);
				}
			}
			break;

		/*
		 * tcp_ka_abort_thres = tcp_ka_rinterval * tcp_ka_cnt.
		 * So setting TCP_KEEPCNT or TCP_KEEPINTVL can affect all the
		 * three members - tcp_ka_abort_thres, tcp_ka_rinterval and
		 * tcp_ka_cnt.
		 */
		case TCP_KEEPCNT:
			if (checkonly)
				break;

			if (*i1 == 0) {
				return (EINVAL);
			} else if (tcp->tcp_ka_rinterval == 0) {
				/*
				 * When TCP_KEEPCNT is specified without first
				 * specifying a TCP_KEEPINTVL, we infer an
				 * interval based on a tunable specific to our
				 * stack: the tcp_keepalive_abort_interval.
				 * (Or the TCP_KEEPALIVE_ABORT_THRESHOLD, in
				 * the unlikely event that that has been set.)
				 * Given the abort interval's default value of
				 * 480 seconds, low TCP_KEEPCNT values can
				 * result in intervals that exceed the default
				 * maximum RTO of 60 seconds.  Rather than
				 * fail in these cases, we (implicitly) clamp
				 * the interval at the maximum RTO; if the
				 * TCP_KEEPCNT is shortly followed by a
				 * TCP_KEEPINTVL (as we expect), the abort
				 * threshold will be recalculated correctly --
				 * and if a TCP_KEEPINTVL is not forthcoming,
				 * keep-alive will at least operate reasonably
				 * given the underconfigured state.
				 */
				uint32_t interval;

				interval = tcp->tcp_ka_abort_thres / *i1;

				if (interval < tcp->tcp_rto_min)
					interval = tcp->tcp_rto_min;

				if (interval > tcp->tcp_rto_max)
					interval = tcp->tcp_rto_max;

				tcp->tcp_ka_rinterval = interval;
			} else {
				if ((*i1 * tcp->tcp_ka_rinterval) <
				    tcps->tcps_keepalive_abort_interval_low ||
				    (*i1 * tcp->tcp_ka_rinterval) >
				    tcps->tcps_keepalive_abort_interval_high)
					return (EINVAL);
				tcp->tcp_ka_abort_thres =
				    (*i1 * tcp->tcp_ka_rinterval);
			}
			tcp->tcp_ka_cnt = *i1;
			break;
		case TCP_KEEPINTVL:
			/*
			 * TCP_KEEPINTVL is specified in seconds, but
			 * tcp_ka_rinterval is in milliseconds.
			 */

			if (checkonly)
				break;

			if ((*i1 * 1000) < tcp->tcp_rto_min ||
			    (*i1 * 1000) > tcp->tcp_rto_max)
				return (EINVAL);

			if (tcp->tcp_ka_cnt == 0) {
				tcp->tcp_ka_cnt =
				    tcp->tcp_ka_abort_thres / (*i1 * 1000);
			} else {
				if ((*i1 * tcp->tcp_ka_cnt * 1000) <
				    tcps->tcps_keepalive_abort_interval_low ||
				    (*i1 * tcp->tcp_ka_cnt * 1000) >
				    tcps->tcps_keepalive_abort_interval_high)
					return (EINVAL);
				tcp->tcp_ka_abort_thres =
				    (*i1 * tcp->tcp_ka_cnt * 1000);
			}
			tcp->tcp_ka_rinterval = *i1 * 1000;
			break;
		case TCP_KEEPALIVE_ABORT_THRESHOLD:
			if (!checkonly) {
				if (*i1 <
				    tcps->tcps_keepalive_abort_interval_low ||
				    *i1 >
				    tcps->tcps_keepalive_abort_interval_high) {
					*outlenp = 0;
					return (EINVAL);
				}
				tcp->tcp_ka_abort_thres = *i1;
				tcp->tcp_ka_cnt = 0;
				tcp->tcp_ka_rinterval = 0;
			}
			break;
		case TCP_CORK:
			if (!checkonly) {
				/*
				 * if tcp->tcp_cork was set and is now
				 * being unset, we have to make sure that
				 * the remaining data gets sent out. Also
				 * unset tcp->tcp_cork so that tcp_wput_data()
				 * can send data even if it is less than mss
				 */
				if (tcp->tcp_cork && onoff == 0 &&
				    tcp->tcp_unsent > 0) {
					tcp->tcp_cork = B_FALSE;
					tcp_wput_data(tcp, NULL, B_FALSE);
				}
				tcp->tcp_cork = onoff;
			}
			break;
		case TCP_RTO_INITIAL: {
			clock_t rto;

			if (checkonly || val == 0)
				break;

			/*
			 * Sanity checks
			 *
			 * The initial RTO should be bounded by the minimum
			 * and maximum RTO.  And it should also be smaller
			 * than the connect attempt abort timeout.  Otherwise,
			 * the connection won't be aborted in a period
			 * reasonably close to that timeout.
			 */
			if (val < tcp->tcp_rto_min || val > tcp->tcp_rto_max ||
			    val > tcp->tcp_second_ctimer_threshold ||
			    val < tcps->tcps_rexmit_interval_initial_low ||
			    val > tcps->tcps_rexmit_interval_initial_high) {
				*outlenp = 0;
				return (EINVAL);
			}
			tcp->tcp_rto_initial = val;

			/*
			 * If TCP has not sent anything, need to re-calculate
			 * tcp_rto.  Otherwise, this option change does not
			 * really affect anything.
			 */
			if (tcp->tcp_state >= TCPS_SYN_SENT)
				break;

			tcp->tcp_rtt_sa = tcp->tcp_rto_initial << 2;
			tcp->tcp_rtt_sd = tcp->tcp_rto_initial >> 1;
			rto = (tcp->tcp_rtt_sa >> 3) + tcp->tcp_rtt_sd +
			    tcps->tcps_rexmit_interval_extra +
			    (tcp->tcp_rtt_sa >> 5) +
			    tcps->tcps_conn_grace_period;
			TCP_SET_RTO(tcp, rto);
			break;
		}
		case TCP_RTO_MIN:
			if (checkonly || val == 0)
				break;

			if (val < tcps->tcps_rexmit_interval_min_low ||
			    val > tcps->tcps_rexmit_interval_min_high ||
			    val > tcp->tcp_rto_max) {
				*outlenp = 0;
				return (EINVAL);
			}
			tcp->tcp_rto_min = val;
			if (tcp->tcp_rto < val)
				tcp->tcp_rto = val;
			break;
		case TCP_RTO_MAX:
			if (checkonly || val == 0)
				break;

			/*
			 * Sanity checks
			 *
			 * The maximum RTO should not be larger than the
			 * connection abort timeout.  Otherwise, the
			 * connection won't be aborted in a period reasonably
			 * close to that timeout.
			 */
			if (val < tcps->tcps_rexmit_interval_max_low ||
			    val > tcps->tcps_rexmit_interval_max_high ||
			    val < tcp->tcp_rto_min ||
			    val > tcp->tcp_second_timer_threshold) {
				*outlenp = 0;
				return (EINVAL);
			}
			tcp->tcp_rto_max = val;
			if (tcp->tcp_rto > val)
				tcp->tcp_rto = val;
			break;
		case TCP_LINGER2:
			if (checkonly || *i1 == 0)
				break;

			/*
			 * Note that the option value's unit is second.  And
			 * the value should be bigger than the private
			 * parameter tcp_fin_wait_2_flush_interval's lower
			 * bound and smaller than the current value of that
			 * parameter.  It should be smaller than the current
			 * value to avoid an app setting TCP_LINGER2 to a big
			 * value, causing resource to be held up too long in
			 * FIN-WAIT-2 state.
			 */
			if (*i1 < 0 ||
			    tcps->tcps_fin_wait_2_flush_interval_low/SECONDS >
			    *i1 ||
			    tcps->tcps_fin_wait_2_flush_interval/SECONDS <
			    *i1) {
				*outlenp = 0;
				return (EINVAL);
			}
			tcp->tcp_fin_wait_2_flush_interval = *i1 * SECONDS;
			break;
		default:
			break;
		}
		break;
	case IPPROTO_IP:
		if (connp->conn_family != AF_INET) {
			*outlenp = 0;
			return (EINVAL);
		}
		switch (name) {
		case IP_SEC_OPT:
			/*
			 * We should not allow policy setting after
			 * we start listening for connections.
			 */
			if (tcp->tcp_state == TCPS_LISTEN) {
				return (EINVAL);
			}
			break;
		}
		break;
	case IPPROTO_IPV6:
		/*
		 * IPPROTO_IPV6 options are only supported for sockets
		 * that are using IPv6 on the wire.
		 */
		if (connp->conn_ipversion != IPV6_VERSION) {
			*outlenp = 0;
			return (EINVAL);
		}

		switch (name) {
		case IPV6_RECVPKTINFO:
			if (!checkonly) {
				/* Force it to be sent up with the next msg */
				tcp->tcp_recvifindex = 0;
			}
			break;
		case IPV6_RECVTCLASS:
			if (!checkonly) {
				/* Force it to be sent up with the next msg */
				tcp->tcp_recvtclass = 0xffffffffU;
			}
			break;
		case IPV6_RECVHOPLIMIT:
			if (!checkonly) {
				/* Force it to be sent up with the next msg */
				tcp->tcp_recvhops = 0xffffffffU;
			}
			break;
		case IPV6_PKTINFO:
			/* This is an extra check for TCP */
			if (inlen == sizeof (struct in6_pktinfo)) {
				struct in6_pktinfo *pkti;

				pkti = (struct in6_pktinfo *)invalp;
				/*
				 * RFC 3542 states that ipi6_addr must be
				 * the unspecified address when setting the
				 * IPV6_PKTINFO sticky socket option on a
				 * TCP socket.
				 */
				if (!IN6_IS_ADDR_UNSPECIFIED(&pkti->ipi6_addr))
					return (EINVAL);
			}
			break;
		case IPV6_SEC_OPT:
			/*
			 * We should not allow policy setting after
			 * we start listening for connections.
			 */
			if (tcp->tcp_state == TCPS_LISTEN) {
				return (EINVAL);
			}
			break;
		}
		break;
	}
	reterr = conn_opt_set(&coas, level, name, inlen, invalp,
	    checkonly, cr);
	if (reterr != 0) {
		*outlenp = 0;
		return (reterr);
	}

	/*
	 * Common case of OK return with outval same as inval
	 */
	if (invalp != outvalp) {
		/* don't trust bcopy for identical src/dst */
		(void) bcopy(invalp, outvalp, inlen);
	}
	*outlenp = inlen;

	if (coas.coa_changed & COA_HEADER_CHANGED) {
		/* If we are connected we rebuilt the headers */
		if (!IN6_IS_ADDR_UNSPECIFIED(&connp->conn_faddr_v6) &&
		    !IN6_IS_ADDR_V4MAPPED_ANY(&connp->conn_faddr_v6)) {
			reterr = tcp_build_hdrs(tcp);
			if (reterr != 0)
				return (reterr);
		}
	}
	if (coas.coa_changed & COA_ROUTE_CHANGED) {
		in6_addr_t nexthop;

		/*
		 * If we are connected we re-cache the information.
		 * We ignore errors to preserve BSD behavior.
		 * Note that we don't redo IPsec policy lookup here
		 * since the final destination (or source) didn't change.
		 */
		ip_attr_nexthop(&connp->conn_xmit_ipp, connp->conn_ixa,
		    &connp->conn_faddr_v6, &nexthop);

		if (!IN6_IS_ADDR_UNSPECIFIED(&connp->conn_faddr_v6) &&
		    !IN6_IS_ADDR_V4MAPPED_ANY(&connp->conn_faddr_v6)) {
			(void) ip_attr_connect(connp, connp->conn_ixa,
			    &connp->conn_laddr_v6, &connp->conn_faddr_v6,
			    &nexthop, connp->conn_fport, NULL, NULL,
			    IPDF_VERIFY_DST);
		}
	}
	if ((coas.coa_changed & COA_SNDBUF_CHANGED) && !IPCL_IS_NONSTR(connp)) {
		connp->conn_wq->q_hiwat = connp->conn_sndbuf;
	}
	if (coas.coa_changed & COA_WROFF_CHANGED) {
		connp->conn_wroff = connp->conn_ht_iphc_allocated +
		    tcps->tcps_wroff_xtra;
		(void) proto_set_tx_wroff(connp->conn_rq, connp,
		    connp->conn_wroff);
	}
	if (coas.coa_changed & COA_OOBINLINE_CHANGED) {
		if (IPCL_IS_NONSTR(connp))
			proto_set_rx_oob_opt(connp, onoff);
	}
	return (0);
}
