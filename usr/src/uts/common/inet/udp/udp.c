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
 * Copyright (c) 1991, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2013 Nexenta Systems, Inc.  All rights reserved.
 * Copyright 2014, OmniTI Computer Consulting, Inc. All rights reserved.
 */
/* Copyright (c) 1990 Mentat Inc. */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/strlog.h>
#include <sys/strsun.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/timod.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/strsubr.h>
#include <sys/suntpi.h>
#include <sys/xti_inet.h>
#include <sys/kmem.h>
#include <sys/cred_impl.h>
#include <sys/policy.h>
#include <sys/priv.h>
#include <sys/ucred.h>
#include <sys/zone.h>

#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/sockio.h>
#include <sys/vtrace.h>
#include <sys/sdt.h>
#include <sys/debug.h>
#include <sys/isa_defs.h>
#include <sys/random.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <netinet/udp.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip_impl.h>
#include <inet/ipsec_impl.h>
#include <inet/ip6.h>
#include <inet/ip_ire.h>
#include <inet/ip_if.h>
#include <inet/ip_multi.h>
#include <inet/ip_ndp.h>
#include <inet/proto_set.h>
#include <inet/mib2.h>
#include <inet/optcom.h>
#include <inet/snmpcom.h>
#include <inet/kstatcom.h>
#include <inet/ipclassifier.h>
#include <sys/squeue_impl.h>
#include <inet/ipnet.h>
#include <sys/ethernet.h>

#include <sys/tsol/label.h>
#include <sys/tsol/tnet.h>
#include <rpc/pmap_prot.h>

#include <inet/udp_impl.h>

/*
 * Synchronization notes:
 *
 * UDP is MT and uses the usual kernel synchronization primitives. There are 2
 * locks, the fanout lock (uf_lock) and conn_lock. conn_lock
 * protects the contents of the udp_t. uf_lock protects the address and the
 * fanout information.
 * The lock order is conn_lock -> uf_lock.
 *
 * The fanout lock uf_lock:
 * When a UDP endpoint is bound to a local port, it is inserted into
 * a bind hash list.  The list consists of an array of udp_fanout_t buckets.
 * The size of the array is controlled by the udp_bind_fanout_size variable.
 * This variable can be changed in /etc/system if the default value is
 * not large enough.  Each bind hash bucket is protected by a per bucket
 * lock.  It protects the udp_bind_hash and udp_ptpbhn fields in the udp_t
 * structure and a few other fields in the udp_t. A UDP endpoint is removed
 * from the bind hash list only when it is being unbound or being closed.
 * The per bucket lock also protects a UDP endpoint's state changes.
 *
 * Plumbing notes:
 * UDP is always a device driver. For compatibility with mibopen() code
 * it is possible to I_PUSH "udp", but that results in pushing a passthrough
 * dummy module.
 *
 * The above implies that we don't support any intermediate module to
 * reside in between /dev/ip and udp -- in fact, we never supported such
 * scenario in the past as the inter-layer communication semantics have
 * always been private.
 */

/* For /etc/system control */
uint_t udp_bind_fanout_size = UDP_BIND_FANOUT_SIZE;

static void	udp_addr_req(queue_t *q, mblk_t *mp);
static void	udp_tpi_bind(queue_t *q, mblk_t *mp);
static void	udp_bind_hash_insert(udp_fanout_t *uf, udp_t *udp);
static void	udp_bind_hash_remove(udp_t *udp, boolean_t caller_holds_lock);
static int	udp_build_hdr_template(conn_t *, const in6_addr_t *,
    const in6_addr_t *, in_port_t, uint32_t);
static void	udp_capability_req(queue_t *q, mblk_t *mp);
static int	udp_tpi_close(queue_t *q, int flags);
static void	udp_close_free(conn_t *);
static void	udp_tpi_connect(queue_t *q, mblk_t *mp);
static void	udp_tpi_disconnect(queue_t *q, mblk_t *mp);
static void	udp_err_ack(queue_t *q, mblk_t *mp, t_scalar_t t_error,
    int sys_error);
static void	udp_err_ack_prim(queue_t *q, mblk_t *mp, t_scalar_t primitive,
    t_scalar_t tlierr, int sys_error);
static int	udp_extra_priv_ports_get(queue_t *q, mblk_t *mp, caddr_t cp,
		    cred_t *cr);
static int	udp_extra_priv_ports_add(queue_t *q, mblk_t *mp,
		    char *value, caddr_t cp, cred_t *cr);
static int	udp_extra_priv_ports_del(queue_t *q, mblk_t *mp,
		    char *value, caddr_t cp, cred_t *cr);
static void	udp_icmp_input(void *, mblk_t *, void *, ip_recv_attr_t *);
static void	udp_icmp_error_ipv6(conn_t *connp, mblk_t *mp,
    ip_recv_attr_t *ira);
static void	udp_info_req(queue_t *q, mblk_t *mp);
static void	udp_input(void *, mblk_t *, void *, ip_recv_attr_t *);
static void	udp_lrput(queue_t *, mblk_t *);
static void	udp_lwput(queue_t *, mblk_t *);
static int	udp_open(queue_t *q, dev_t *devp, int flag, int sflag,
		    cred_t *credp, boolean_t isv6);
static int	udp_openv4(queue_t *q, dev_t *devp, int flag, int sflag,
		    cred_t *credp);
static int	udp_openv6(queue_t *q, dev_t *devp, int flag, int sflag,
		    cred_t *credp);
static boolean_t udp_opt_allow_udr_set(t_scalar_t level, t_scalar_t name);
int		udp_opt_set(conn_t *connp, uint_t optset_context,
		    int level, int name, uint_t inlen,
		    uchar_t *invalp, uint_t *outlenp, uchar_t *outvalp,
		    void *thisdg_attrs, cred_t *cr);
int		udp_opt_get(conn_t *connp, int level, int name,
		    uchar_t *ptr);
static int	udp_output_connected(conn_t *connp, mblk_t *mp, cred_t *cr,
		    pid_t pid);
static int	udp_output_lastdst(conn_t *connp, mblk_t *mp, cred_t *cr,
    pid_t pid, ip_xmit_attr_t *ixa);
static int	udp_output_newdst(conn_t *connp, mblk_t *data_mp, sin_t *sin,
		    sin6_t *sin6, ushort_t ipversion, cred_t *cr, pid_t,
		    ip_xmit_attr_t *ixa);
static mblk_t	*udp_prepend_hdr(conn_t *, ip_xmit_attr_t *, const ip_pkt_t *,
    const in6_addr_t *, const in6_addr_t *, in_port_t, uint32_t, mblk_t *,
    int *);
static mblk_t	*udp_prepend_header_template(conn_t *, ip_xmit_attr_t *,
    mblk_t *, const in6_addr_t *, in_port_t, uint32_t, int *);
static void	udp_ud_err(queue_t *q, mblk_t *mp, t_scalar_t err);
static void	udp_ud_err_connected(conn_t *, t_scalar_t);
static void	udp_tpi_unbind(queue_t *q, mblk_t *mp);
static in_port_t udp_update_next_port(udp_t *udp, in_port_t port,
    boolean_t random);
static void	udp_wput_other(queue_t *q, mblk_t *mp);
static void	udp_wput_iocdata(queue_t *q, mblk_t *mp);
static void	udp_wput_fallback(queue_t *q, mblk_t *mp);
static size_t	udp_set_rcv_hiwat(udp_t *udp, size_t size);

static void	*udp_stack_init(netstackid_t stackid, netstack_t *ns);
static void	udp_stack_fini(netstackid_t stackid, void *arg);

/* Common routines for TPI and socket module */
static void	udp_ulp_recv(conn_t *, mblk_t *, uint_t, ip_recv_attr_t *);

/* Common routine for TPI and socket module */
static conn_t	*udp_do_open(cred_t *, boolean_t, int, int *);
static void	udp_do_close(conn_t *);
static int	udp_do_bind(conn_t *, struct sockaddr *, socklen_t, cred_t *,
    boolean_t);
static int	udp_do_unbind(conn_t *);

int		udp_getsockname(sock_lower_handle_t,
    struct sockaddr *, socklen_t *, cred_t *);
int		udp_getpeername(sock_lower_handle_t,
    struct sockaddr *, socklen_t *, cred_t *);
static int	udp_do_connect(conn_t *, const struct sockaddr *, socklen_t,
    cred_t *, pid_t);

#pragma inline(udp_output_connected, udp_output_newdst, udp_output_lastdst)

/*
 * Checks if the given destination addr/port is allowed out.
 * If allowed, registers the (dest_addr/port, node_ID) mapping at Cluster.
 * Called for each connect() and for sendto()/sendmsg() to a different
 * destination.
 * For connect(), called in udp_connect().
 * For sendto()/sendmsg(), called in udp_output_newdst().
 *
 * This macro assumes that the cl_inet_connect2 hook is not NULL.
 * Please check this before calling this macro.
 *
 * void
 * CL_INET_UDP_CONNECT(conn_t cp, udp_t *udp, boolean_t is_outgoing,
 *     in6_addr_t *faddrp, in_port_t (or uint16_t) fport, int err);
 */
#define	CL_INET_UDP_CONNECT(cp, is_outgoing, faddrp, fport, err) {	\
	(err) = 0;							\
	/*								\
	 * Running in cluster mode - check and register active		\
	 * "connection" information					\
	 */								\
	if ((cp)->conn_ipversion == IPV4_VERSION)			\
		(err) = (*cl_inet_connect2)(				\
		    (cp)->conn_netstack->netstack_stackid,		\
		    IPPROTO_UDP, is_outgoing, AF_INET,			\
		    (uint8_t *)&((cp)->conn_laddr_v4),			\
		    (cp)->conn_lport,					\
		    (uint8_t *)&(V4_PART_OF_V6(*faddrp)),		\
		    (in_port_t)(fport), NULL);				\
	else								\
		(err) = (*cl_inet_connect2)(				\
		    (cp)->conn_netstack->netstack_stackid,		\
		    IPPROTO_UDP, is_outgoing, AF_INET6,			\
		    (uint8_t *)&((cp)->conn_laddr_v6),			\
		    (cp)->conn_lport,					\
		    (uint8_t *)(faddrp), (in_port_t)(fport), NULL);	\
}

static struct module_info udp_mod_info =  {
	UDP_MOD_ID, UDP_MOD_NAME, 1, INFPSZ, UDP_RECV_HIWATER, UDP_RECV_LOWATER
};

/*
 * Entry points for UDP as a device.
 * We have separate open functions for the /dev/udp and /dev/udp6 devices.
 */
static struct qinit udp_rinitv4 = {
	NULL, NULL, udp_openv4, udp_tpi_close, NULL, &udp_mod_info, NULL
};

static struct qinit udp_rinitv6 = {
	NULL, NULL, udp_openv6, udp_tpi_close, NULL, &udp_mod_info, NULL
};

static struct qinit udp_winit = {
	(pfi_t)udp_wput, (pfi_t)ip_wsrv, NULL, NULL, NULL, &udp_mod_info
};

/* UDP entry point during fallback */
struct qinit udp_fallback_sock_winit = {
	(pfi_t)udp_wput_fallback, NULL, NULL, NULL, NULL, &udp_mod_info
};

/*
 * UDP needs to handle I_LINK and I_PLINK since ifconfig
 * likes to use it as a place to hang the various streams.
 */
static struct qinit udp_lrinit = {
	(pfi_t)udp_lrput, NULL, udp_openv4, udp_tpi_close, NULL, &udp_mod_info
};

static struct qinit udp_lwinit = {
	(pfi_t)udp_lwput, NULL, udp_openv4, udp_tpi_close, NULL, &udp_mod_info
};

/* For AF_INET aka /dev/udp */
struct streamtab udpinfov4 = {
	&udp_rinitv4, &udp_winit, &udp_lrinit, &udp_lwinit
};

/* For AF_INET6 aka /dev/udp6 */
struct streamtab udpinfov6 = {
	&udp_rinitv6, &udp_winit, &udp_lrinit, &udp_lwinit
};

#define	UDP_MAXPACKET_IPV4 (IP_MAXPACKET - UDPH_SIZE - IP_SIMPLE_HDR_LENGTH)

/* Default structure copied into T_INFO_ACK messages */
static struct T_info_ack udp_g_t_info_ack_ipv4 = {
	T_INFO_ACK,
	UDP_MAXPACKET_IPV4,	/* TSDU_size. Excl. headers */
	T_INVALID,	/* ETSU_size.  udp does not support expedited data. */
	T_INVALID,	/* CDATA_size. udp does not support connect data. */
	T_INVALID,	/* DDATA_size. udp does not support disconnect data. */
	sizeof (sin_t),	/* ADDR_size. */
	0,		/* OPT_size - not initialized here */
	UDP_MAXPACKET_IPV4,	/* TIDU_size.  Excl. headers */
	T_CLTS,		/* SERV_type.  udp supports connection-less. */
	TS_UNBND,	/* CURRENT_state.  This is set from udp_state. */
	(XPG4_1|SENDZERO) /* PROVIDER_flag */
};

#define	UDP_MAXPACKET_IPV6 (IP_MAXPACKET - UDPH_SIZE - IPV6_HDR_LEN)

static	struct T_info_ack udp_g_t_info_ack_ipv6 = {
	T_INFO_ACK,
	UDP_MAXPACKET_IPV6,	/* TSDU_size.  Excl. headers */
	T_INVALID,	/* ETSU_size.  udp does not support expedited data. */
	T_INVALID,	/* CDATA_size. udp does not support connect data. */
	T_INVALID,	/* DDATA_size. udp does not support disconnect data. */
	sizeof (sin6_t), /* ADDR_size. */
	0,		/* OPT_size - not initialized here */
	UDP_MAXPACKET_IPV6,	/* TIDU_size. Excl. headers */
	T_CLTS,		/* SERV_type.  udp supports connection-less. */
	TS_UNBND,	/* CURRENT_state.  This is set from udp_state. */
	(XPG4_1|SENDZERO) /* PROVIDER_flag */
};

/*
 * UDP tunables related declarations. Definitions are in udp_tunables.c
 */
extern mod_prop_info_t udp_propinfo_tbl[];
extern int udp_propinfo_count;

/* Setable in /etc/system */
/* If set to 0, pick ephemeral port sequentially; otherwise randomly. */
uint32_t udp_random_anon_port = 1;

/*
 * Hook functions to enable cluster networking.
 * On non-clustered systems these vectors must always be NULL
 */

void (*cl_inet_bind)(netstackid_t stack_id, uchar_t protocol,
    sa_family_t addr_family, uint8_t *laddrp, in_port_t lport,
    void *args) = NULL;
void (*cl_inet_unbind)(netstackid_t stack_id, uint8_t protocol,
    sa_family_t addr_family, uint8_t *laddrp, in_port_t lport,
    void *args) = NULL;

typedef union T_primitives *t_primp_t;

/*
 * Return the next anonymous port in the privileged port range for
 * bind checking.
 *
 * Trusted Extension (TX) notes: TX allows administrator to mark or
 * reserve ports as Multilevel ports (MLP). MLP has special function
 * on TX systems. Once a port is made MLP, it's not available as
 * ordinary port. This creates "holes" in the port name space. It
 * may be necessary to skip the "holes" find a suitable anon port.
 */
static in_port_t
udp_get_next_priv_port(udp_t *udp)
{
	static in_port_t next_priv_port = IPPORT_RESERVED - 1;
	in_port_t nextport;
	boolean_t restart = B_FALSE;
	udp_stack_t *us = udp->udp_us;

retry:
	if (next_priv_port < us->us_min_anonpriv_port ||
	    next_priv_port >= IPPORT_RESERVED) {
		next_priv_port = IPPORT_RESERVED - 1;
		if (restart)
			return (0);
		restart = B_TRUE;
	}

	if (is_system_labeled() &&
	    (nextport = tsol_next_port(crgetzone(udp->udp_connp->conn_cred),
	    next_priv_port, IPPROTO_UDP, B_FALSE)) != 0) {
		next_priv_port = nextport;
		goto retry;
	}

	return (next_priv_port--);
}

/*
 * Hash list removal routine for udp_t structures.
 */
static void
udp_bind_hash_remove(udp_t *udp, boolean_t caller_holds_lock)
{
	udp_t		*udpnext;
	kmutex_t	*lockp;
	udp_stack_t	*us = udp->udp_us;
	conn_t		*connp = udp->udp_connp;

	if (udp->udp_ptpbhn == NULL)
		return;

	/*
	 * Extract the lock pointer in case there are concurrent
	 * hash_remove's for this instance.
	 */
	ASSERT(connp->conn_lport != 0);
	if (!caller_holds_lock) {
		lockp = &us->us_bind_fanout[UDP_BIND_HASH(connp->conn_lport,
		    us->us_bind_fanout_size)].uf_lock;
		ASSERT(lockp != NULL);
		mutex_enter(lockp);
	}
	if (udp->udp_ptpbhn != NULL) {
		udpnext = udp->udp_bind_hash;
		if (udpnext != NULL) {
			udpnext->udp_ptpbhn = udp->udp_ptpbhn;
			udp->udp_bind_hash = NULL;
		}
		*udp->udp_ptpbhn = udpnext;
		udp->udp_ptpbhn = NULL;
	}
	if (!caller_holds_lock) {
		mutex_exit(lockp);
	}
}

static void
udp_bind_hash_insert(udp_fanout_t *uf, udp_t *udp)
{
	conn_t	*connp = udp->udp_connp;
	udp_t	**udpp;
	udp_t	*udpnext;
	conn_t	*connext;

	ASSERT(MUTEX_HELD(&uf->uf_lock));
	ASSERT(udp->udp_ptpbhn == NULL);
	udpp = &uf->uf_udp;
	udpnext = udpp[0];
	if (udpnext != NULL) {
		/*
		 * If the new udp bound to the INADDR_ANY address
		 * and the first one in the list is not bound to
		 * INADDR_ANY we skip all entries until we find the
		 * first one bound to INADDR_ANY.
		 * This makes sure that applications binding to a
		 * specific address get preference over those binding to
		 * INADDR_ANY.
		 */
		connext = udpnext->udp_connp;
		if (V6_OR_V4_INADDR_ANY(connp->conn_bound_addr_v6) &&
		    !V6_OR_V4_INADDR_ANY(connext->conn_bound_addr_v6)) {
			while ((udpnext = udpp[0]) != NULL &&
			    !V6_OR_V4_INADDR_ANY(connext->conn_bound_addr_v6)) {
				udpp = &(udpnext->udp_bind_hash);
			}
			if (udpnext != NULL)
				udpnext->udp_ptpbhn = &udp->udp_bind_hash;
		} else {
			udpnext->udp_ptpbhn = &udp->udp_bind_hash;
		}
	}
	udp->udp_bind_hash = udpnext;
	udp->udp_ptpbhn = udpp;
	udpp[0] = udp;
}

/*
 * This routine is called to handle each O_T_BIND_REQ/T_BIND_REQ message
 * passed to udp_wput.
 * It associates a port number and local address with the stream.
 * It calls IP to verify the local IP address, and calls IP to insert
 * the conn_t in the fanout table.
 * If everything is ok it then sends the T_BIND_ACK back up.
 *
 * Note that UDP over IPv4 and IPv6 sockets can use the same port number
 * without setting SO_REUSEADDR. This is needed so that they
 * can be viewed as two independent transport protocols.
 * However, anonymouns ports are allocated from the same range to avoid
 * duplicating the us->us_next_port_to_try.
 */
static void
udp_tpi_bind(queue_t *q, mblk_t *mp)
{
	sin_t		*sin;
	sin6_t		*sin6;
	mblk_t		*mp1;
	struct T_bind_req *tbr;
	conn_t		*connp;
	udp_t		*udp;
	int		error;
	struct sockaddr	*sa;
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
		udp_err_ack(q, mp, TSYSERR, EINVAL);
		return;
	}

	connp = Q_TO_CONN(q);
	udp = connp->conn_udp;
	if ((mp->b_wptr - mp->b_rptr) < sizeof (*tbr)) {
		(void) mi_strlog(q, 1, SL_ERROR|SL_TRACE,
		    "udp_bind: bad req, len %u",
		    (uint_t)(mp->b_wptr - mp->b_rptr));
		udp_err_ack(q, mp, TPROTO, 0);
		return;
	}
	if (udp->udp_state != TS_UNBND) {
		(void) mi_strlog(q, 1, SL_ERROR|SL_TRACE,
		    "udp_bind: bad state, %u", udp->udp_state);
		udp_err_ack(q, mp, TOUTSTATE, 0);
		return;
	}
	/*
	 * Reallocate the message to make sure we have enough room for an
	 * address.
	 */
	mp1 = reallocb(mp, sizeof (struct T_bind_ack) + sizeof (sin6_t), 1);
	if (mp1 == NULL) {
		udp_err_ack(q, mp, TSYSERR, ENOMEM);
		return;
	}

	mp = mp1;

	/* Reset the message type in preparation for shipping it back. */
	DB_TYPE(mp) = M_PCPROTO;

	tbr = (struct T_bind_req *)mp->b_rptr;
	switch (tbr->ADDR_length) {
	case 0:			/* Request for a generic port */
		tbr->ADDR_offset = sizeof (struct T_bind_req);
		if (connp->conn_family == AF_INET) {
			tbr->ADDR_length = sizeof (sin_t);
			sin = (sin_t *)&tbr[1];
			*sin = sin_null;
			sin->sin_family = AF_INET;
			mp->b_wptr = (uchar_t *)&sin[1];
			sa = (struct sockaddr *)sin;
		} else {
			ASSERT(connp->conn_family == AF_INET6);
			tbr->ADDR_length = sizeof (sin6_t);
			sin6 = (sin6_t *)&tbr[1];
			*sin6 = sin6_null;
			sin6->sin6_family = AF_INET6;
			mp->b_wptr = (uchar_t *)&sin6[1];
			sa = (struct sockaddr *)sin6;
		}
		break;

	case sizeof (sin_t):	/* Complete IPv4 address */
		sa = (struct sockaddr *)mi_offset_param(mp, tbr->ADDR_offset,
		    sizeof (sin_t));
		if (sa == NULL || !OK_32PTR((char *)sa)) {
			udp_err_ack(q, mp, TSYSERR, EINVAL);
			return;
		}
		if (connp->conn_family != AF_INET ||
		    sa->sa_family != AF_INET) {
			udp_err_ack(q, mp, TSYSERR, EAFNOSUPPORT);
			return;
		}
		break;

	case sizeof (sin6_t):	/* complete IPv6 address */
		sa = (struct sockaddr *)mi_offset_param(mp, tbr->ADDR_offset,
		    sizeof (sin6_t));
		if (sa == NULL || !OK_32PTR((char *)sa)) {
			udp_err_ack(q, mp, TSYSERR, EINVAL);
			return;
		}
		if (connp->conn_family != AF_INET6 ||
		    sa->sa_family != AF_INET6) {
			udp_err_ack(q, mp, TSYSERR, EAFNOSUPPORT);
			return;
		}
		break;

	default:		/* Invalid request */
		(void) mi_strlog(q, 1, SL_ERROR|SL_TRACE,
		    "udp_bind: bad ADDR_length length %u", tbr->ADDR_length);
		udp_err_ack(q, mp, TBADADDR, 0);
		return;
	}

	error = udp_do_bind(connp, sa, tbr->ADDR_length, cr,
	    tbr->PRIM_type != O_T_BIND_REQ);

	if (error != 0) {
		if (error > 0) {
			udp_err_ack(q, mp, TSYSERR, error);
		} else {
			udp_err_ack(q, mp, -error, 0);
		}
	} else {
		tbr->PRIM_type = T_BIND_ACK;
		qreply(q, mp);
	}
}

/*
 * This routine handles each T_CONN_REQ message passed to udp.  It
 * associates a default destination address with the stream.
 *
 * After various error checks are completed, udp_connect() lays
 * the target address and port into the composite header template.
 * Then we ask IP for information, including a source address if we didn't
 * already have one. Finally we send up the T_OK_ACK reply message.
 */
static void
udp_tpi_connect(queue_t *q, mblk_t *mp)
{
	conn_t	*connp = Q_TO_CONN(q);
	int	error;
	socklen_t	len;
	struct sockaddr		*sa;
	struct T_conn_req	*tcr;
	cred_t		*cr;
	pid_t		pid;
	/*
	 * All Solaris components should pass a db_credp
	 * for this TPI message, hence we ASSERT.
	 * But in case there is some other M_PROTO that looks
	 * like a TPI message sent by some other kernel
	 * component, we check and return an error.
	 */
	cr = msg_getcred(mp, &pid);
	ASSERT(cr != NULL);
	if (cr == NULL) {
		udp_err_ack(q, mp, TSYSERR, EINVAL);
		return;
	}

	tcr = (struct T_conn_req *)mp->b_rptr;

	/* A bit of sanity checking */
	if ((mp->b_wptr - mp->b_rptr) < sizeof (struct T_conn_req)) {
		udp_err_ack(q, mp, TPROTO, 0);
		return;
	}

	if (tcr->OPT_length != 0) {
		udp_err_ack(q, mp, TBADOPT, 0);
		return;
	}

	/*
	 * Determine packet type based on type of address passed in
	 * the request should contain an IPv4 or IPv6 address.
	 * Make sure that address family matches the type of
	 * family of the address passed down.
	 */
	len = tcr->DEST_length;
	switch (tcr->DEST_length) {
	default:
		udp_err_ack(q, mp, TBADADDR, 0);
		return;

	case sizeof (sin_t):
		sa = (struct sockaddr *)mi_offset_param(mp, tcr->DEST_offset,
		    sizeof (sin_t));
		break;

	case sizeof (sin6_t):
		sa = (struct sockaddr *)mi_offset_param(mp, tcr->DEST_offset,
		    sizeof (sin6_t));
		break;
	}

	error = proto_verify_ip_addr(connp->conn_family, sa, len);
	if (error != 0) {
		udp_err_ack(q, mp, TSYSERR, error);
		return;
	}

	error = udp_do_connect(connp, sa, len, cr, pid);
	if (error != 0) {
		if (error < 0)
			udp_err_ack(q, mp, -error, 0);
		else
			udp_err_ack(q, mp, TSYSERR, error);
	} else {
		mblk_t	*mp1;
		/*
		 * We have to send a connection confirmation to
		 * keep TLI happy.
		 */
		if (connp->conn_family == AF_INET) {
			mp1 = mi_tpi_conn_con(NULL, (char *)sa,
			    sizeof (sin_t), NULL, 0);
		} else {
			mp1 = mi_tpi_conn_con(NULL, (char *)sa,
			    sizeof (sin6_t), NULL, 0);
		}
		if (mp1 == NULL) {
			udp_err_ack(q, mp, TSYSERR, ENOMEM);
			return;
		}

		/*
		 * Send ok_ack for T_CONN_REQ
		 */
		mp = mi_tpi_ok_ack_alloc(mp);
		if (mp == NULL) {
			/* Unable to reuse the T_CONN_REQ for the ack. */
			udp_err_ack_prim(q, mp1, T_CONN_REQ, TSYSERR, ENOMEM);
			return;
		}

		putnext(connp->conn_rq, mp);
		putnext(connp->conn_rq, mp1);
	}
}

static int
udp_tpi_close(queue_t *q, int flags)
{
	conn_t	*connp;

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
	udp_do_close(connp);
done:
	q->q_ptr = WR(q)->q_ptr = NULL;
	return (0);
}

static void
udp_close_free(conn_t *connp)
{
	udp_t *udp = connp->conn_udp;

	/* If there are any options associated with the stream, free them. */
	if (udp->udp_recv_ipp.ipp_fields != 0)
		ip_pkt_free(&udp->udp_recv_ipp);

	/*
	 * Clear any fields which the kmem_cache constructor clears.
	 * Only udp_connp needs to be preserved.
	 * TBD: We should make this more efficient to avoid clearing
	 * everything.
	 */
	ASSERT(udp->udp_connp == connp);
	bzero(udp, sizeof (udp_t));
	udp->udp_connp = connp;
}

static int
udp_do_disconnect(conn_t *connp)
{
	udp_t	*udp;
	udp_fanout_t *udpf;
	udp_stack_t *us;
	int	error;

	udp = connp->conn_udp;
	us = udp->udp_us;
	mutex_enter(&connp->conn_lock);
	if (udp->udp_state != TS_DATA_XFER) {
		mutex_exit(&connp->conn_lock);
		return (-TOUTSTATE);
	}
	udpf = &us->us_bind_fanout[UDP_BIND_HASH(connp->conn_lport,
	    us->us_bind_fanout_size)];
	mutex_enter(&udpf->uf_lock);
	if (connp->conn_mcbc_bind)
		connp->conn_saddr_v6 = ipv6_all_zeros;
	else
		connp->conn_saddr_v6 = connp->conn_bound_addr_v6;
	connp->conn_laddr_v6 = connp->conn_bound_addr_v6;
	connp->conn_faddr_v6 = ipv6_all_zeros;
	connp->conn_fport = 0;
	udp->udp_state = TS_IDLE;
	mutex_exit(&udpf->uf_lock);

	/* Remove any remnants of mapped address binding */
	if (connp->conn_family == AF_INET6)
		connp->conn_ipversion = IPV6_VERSION;

	connp->conn_v6lastdst = ipv6_all_zeros;
	error = udp_build_hdr_template(connp, &connp->conn_saddr_v6,
	    &connp->conn_faddr_v6, connp->conn_fport, connp->conn_flowinfo);
	mutex_exit(&connp->conn_lock);
	if (error != 0)
		return (error);

	/*
	 * Tell IP to remove the full binding and revert
	 * to the local address binding.
	 */
	return (ip_laddr_fanout_insert(connp));
}

static void
udp_tpi_disconnect(queue_t *q, mblk_t *mp)
{
	conn_t	*connp = Q_TO_CONN(q);
	int	error;

	/*
	 * Allocate the largest primitive we need to send back
	 * T_error_ack is > than T_ok_ack
	 */
	mp = reallocb(mp, sizeof (struct T_error_ack), 1);
	if (mp == NULL) {
		/* Unable to reuse the T_DISCON_REQ for the ack. */
		udp_err_ack_prim(q, mp, T_DISCON_REQ, TSYSERR, ENOMEM);
		return;
	}

	error = udp_do_disconnect(connp);

	if (error != 0) {
		if (error < 0) {
			udp_err_ack(q, mp, -error, 0);
		} else {
			udp_err_ack(q, mp, TSYSERR, error);
		}
	} else {
		mp = mi_tpi_ok_ack_alloc(mp);
		ASSERT(mp != NULL);
		qreply(q, mp);
	}
}

int
udp_disconnect(conn_t *connp)
{
	int error;

	connp->conn_dgram_errind = B_FALSE;
	error = udp_do_disconnect(connp);
	if (error < 0)
		error = proto_tlitosyserr(-error);

	return (error);
}

/* This routine creates a T_ERROR_ACK message and passes it upstream. */
static void
udp_err_ack(queue_t *q, mblk_t *mp, t_scalar_t t_error, int sys_error)
{
	if ((mp = mi_tpi_err_ack_alloc(mp, t_error, sys_error)) != NULL)
		qreply(q, mp);
}

/* Shorthand to generate and send TPI error acks to our client */
static void
udp_err_ack_prim(queue_t *q, mblk_t *mp, t_scalar_t primitive,
    t_scalar_t t_error, int sys_error)
{
	struct T_error_ack	*teackp;

	if ((mp = tpi_ack_alloc(mp, sizeof (struct T_error_ack),
	    M_PCPROTO, T_ERROR_ACK)) != NULL) {
		teackp = (struct T_error_ack *)mp->b_rptr;
		teackp->ERROR_prim = primitive;
		teackp->TLI_error = t_error;
		teackp->UNIX_error = sys_error;
		qreply(q, mp);
	}
}

/* At minimum we need 4 bytes of UDP header */
#define	ICMP_MIN_UDP_HDR	4

/*
 * udp_icmp_input is called as conn_recvicmp to process ICMP messages.
 * Generates the appropriate T_UDERROR_IND for permanent (non-transient) errors.
 * Assumes that IP has pulled up everything up to and including the ICMP header.
 */
/* ARGSUSED2 */
static void
udp_icmp_input(void *arg1, mblk_t *mp, void *arg2, ip_recv_attr_t *ira)
{
	conn_t		*connp = (conn_t *)arg1;
	icmph_t		*icmph;
	ipha_t		*ipha;
	int		iph_hdr_length;
	udpha_t		*udpha;
	sin_t		sin;
	sin6_t		sin6;
	mblk_t		*mp1;
	int		error = 0;
	udp_t		*udp = connp->conn_udp;

	ipha = (ipha_t *)mp->b_rptr;

	ASSERT(OK_32PTR(mp->b_rptr));

	if (IPH_HDR_VERSION(ipha) != IPV4_VERSION) {
		ASSERT(IPH_HDR_VERSION(ipha) == IPV6_VERSION);
		udp_icmp_error_ipv6(connp, mp, ira);
		return;
	}
	ASSERT(IPH_HDR_VERSION(ipha) == IPV4_VERSION);

	/* Skip past the outer IP and ICMP headers */
	ASSERT(IPH_HDR_LENGTH(ipha) == ira->ira_ip_hdr_length);
	iph_hdr_length = ira->ira_ip_hdr_length;
	icmph = (icmph_t *)&mp->b_rptr[iph_hdr_length];
	ipha = (ipha_t *)&icmph[1];	/* Inner IP header */

	/* Skip past the inner IP and find the ULP header */
	iph_hdr_length = IPH_HDR_LENGTH(ipha);
	udpha = (udpha_t *)((char *)ipha + iph_hdr_length);

	switch (icmph->icmph_type) {
	case ICMP_DEST_UNREACHABLE:
		switch (icmph->icmph_code) {
		case ICMP_FRAGMENTATION_NEEDED: {
			ipha_t		*ipha;
			ip_xmit_attr_t	*ixa;
			/*
			 * IP has already adjusted the path MTU.
			 * But we need to adjust DF for IPv4.
			 */
			if (connp->conn_ipversion != IPV4_VERSION)
				break;

			ixa = conn_get_ixa(connp, B_FALSE);
			if (ixa == NULL || ixa->ixa_ire == NULL) {
				/*
				 * Some other thread holds conn_ixa. We will
				 * redo this on the next ICMP too big.
				 */
				if (ixa != NULL)
					ixa_refrele(ixa);
				break;
			}
			(void) ip_get_pmtu(ixa);

			mutex_enter(&connp->conn_lock);
			ipha = (ipha_t *)connp->conn_ht_iphc;
			if (ixa->ixa_flags & IXAF_PMTU_IPV4_DF) {
				ipha->ipha_fragment_offset_and_flags |=
				    IPH_DF_HTONS;
			} else {
				ipha->ipha_fragment_offset_and_flags &=
				    ~IPH_DF_HTONS;
			}
			mutex_exit(&connp->conn_lock);
			ixa_refrele(ixa);
			break;
		}
		case ICMP_PORT_UNREACHABLE:
		case ICMP_PROTOCOL_UNREACHABLE:
			error = ECONNREFUSED;
			break;
		default:
			/* Transient errors */
			break;
		}
		break;
	default:
		/* Transient errors */
		break;
	}
	if (error == 0) {
		freemsg(mp);
		return;
	}

	/*
	 * Deliver T_UDERROR_IND when the application has asked for it.
	 * The socket layer enables this automatically when connected.
	 */
	if (!connp->conn_dgram_errind) {
		freemsg(mp);
		return;
	}

	switch (connp->conn_family) {
	case AF_INET:
		sin = sin_null;
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = ipha->ipha_dst;
		sin.sin_port = udpha->uha_dst_port;
		if (IPCL_IS_NONSTR(connp)) {
			mutex_enter(&connp->conn_lock);
			if (udp->udp_state == TS_DATA_XFER) {
				if (sin.sin_port == connp->conn_fport &&
				    sin.sin_addr.s_addr ==
				    connp->conn_faddr_v4) {
					mutex_exit(&connp->conn_lock);
					(*connp->conn_upcalls->su_set_error)
					    (connp->conn_upper_handle, error);
					goto done;
				}
			} else {
				udp->udp_delayed_error = error;
				*((sin_t *)&udp->udp_delayed_addr) = sin;
			}
			mutex_exit(&connp->conn_lock);
		} else {
			mp1 = mi_tpi_uderror_ind((char *)&sin, sizeof (sin_t),
			    NULL, 0, error);
			if (mp1 != NULL)
				putnext(connp->conn_rq, mp1);
		}
		break;
	case AF_INET6:
		sin6 = sin6_null;
		sin6.sin6_family = AF_INET6;
		IN6_IPADDR_TO_V4MAPPED(ipha->ipha_dst, &sin6.sin6_addr);
		sin6.sin6_port = udpha->uha_dst_port;
		if (IPCL_IS_NONSTR(connp)) {
			mutex_enter(&connp->conn_lock);
			if (udp->udp_state == TS_DATA_XFER) {
				if (sin6.sin6_port == connp->conn_fport &&
				    IN6_ARE_ADDR_EQUAL(&sin6.sin6_addr,
				    &connp->conn_faddr_v6)) {
					mutex_exit(&connp->conn_lock);
					(*connp->conn_upcalls->su_set_error)
					    (connp->conn_upper_handle, error);
					goto done;
				}
			} else {
				udp->udp_delayed_error = error;
				*((sin6_t *)&udp->udp_delayed_addr) = sin6;
			}
			mutex_exit(&connp->conn_lock);
		} else {
			mp1 = mi_tpi_uderror_ind((char *)&sin6, sizeof (sin6_t),
			    NULL, 0, error);
			if (mp1 != NULL)
				putnext(connp->conn_rq, mp1);
		}
		break;
	}
done:
	freemsg(mp);
}

/*
 * udp_icmp_error_ipv6 is called by udp_icmp_error to process ICMP for IPv6.
 * Generates the appropriate T_UDERROR_IND for permanent (non-transient) errors.
 * Assumes that IP has pulled up all the extension headers as well as the
 * ICMPv6 header.
 */
static void
udp_icmp_error_ipv6(conn_t *connp, mblk_t *mp, ip_recv_attr_t *ira)
{
	icmp6_t		*icmp6;
	ip6_t		*ip6h, *outer_ip6h;
	uint16_t	iph_hdr_length;
	uint8_t		*nexthdrp;
	udpha_t		*udpha;
	sin6_t		sin6;
	mblk_t		*mp1;
	int		error = 0;
	udp_t		*udp = connp->conn_udp;
	udp_stack_t	*us = udp->udp_us;

	outer_ip6h = (ip6_t *)mp->b_rptr;
#ifdef DEBUG
	if (outer_ip6h->ip6_nxt != IPPROTO_ICMPV6)
		iph_hdr_length = ip_hdr_length_v6(mp, outer_ip6h);
	else
		iph_hdr_length = IPV6_HDR_LEN;
	ASSERT(iph_hdr_length == ira->ira_ip_hdr_length);
#endif
	/* Skip past the outer IP and ICMP headers */
	iph_hdr_length = ira->ira_ip_hdr_length;
	icmp6 = (icmp6_t *)&mp->b_rptr[iph_hdr_length];

	/* Skip past the inner IP and find the ULP header */
	ip6h = (ip6_t *)&icmp6[1];	/* Inner IP header */
	if (!ip_hdr_length_nexthdr_v6(mp, ip6h, &iph_hdr_length, &nexthdrp)) {
		freemsg(mp);
		return;
	}
	udpha = (udpha_t *)((char *)ip6h + iph_hdr_length);

	switch (icmp6->icmp6_type) {
	case ICMP6_DST_UNREACH:
		switch (icmp6->icmp6_code) {
		case ICMP6_DST_UNREACH_NOPORT:
			error = ECONNREFUSED;
			break;
		case ICMP6_DST_UNREACH_ADMIN:
		case ICMP6_DST_UNREACH_NOROUTE:
		case ICMP6_DST_UNREACH_BEYONDSCOPE:
		case ICMP6_DST_UNREACH_ADDR:
			/* Transient errors */
			break;
		default:
			break;
		}
		break;
	case ICMP6_PACKET_TOO_BIG: {
		struct T_unitdata_ind	*tudi;
		struct T_opthdr		*toh;
		size_t			udi_size;
		mblk_t			*newmp;
		t_scalar_t		opt_length = sizeof (struct T_opthdr) +
		    sizeof (struct ip6_mtuinfo);
		sin6_t			*sin6;
		struct ip6_mtuinfo	*mtuinfo;

		/*
		 * If the application has requested to receive path mtu
		 * information, send up an empty message containing an
		 * IPV6_PATHMTU ancillary data item.
		 */
		if (!connp->conn_ipv6_recvpathmtu)
			break;

		udi_size = sizeof (struct T_unitdata_ind) + sizeof (sin6_t) +
		    opt_length;
		if ((newmp = allocb(udi_size, BPRI_MED)) == NULL) {
			UDPS_BUMP_MIB(us, udpInErrors);
			break;
		}

		/*
		 * newmp->b_cont is left to NULL on purpose.  This is an
		 * empty message containing only ancillary data.
		 */
		newmp->b_datap->db_type = M_PROTO;
		tudi = (struct T_unitdata_ind *)newmp->b_rptr;
		newmp->b_wptr = (uchar_t *)tudi + udi_size;
		tudi->PRIM_type = T_UNITDATA_IND;
		tudi->SRC_length = sizeof (sin6_t);
		tudi->SRC_offset = sizeof (struct T_unitdata_ind);
		tudi->OPT_offset = tudi->SRC_offset + sizeof (sin6_t);
		tudi->OPT_length = opt_length;

		sin6 = (sin6_t *)&tudi[1];
		bzero(sin6, sizeof (sin6_t));
		sin6->sin6_family = AF_INET6;
		sin6->sin6_addr = connp->conn_faddr_v6;

		toh = (struct T_opthdr *)&sin6[1];
		toh->level = IPPROTO_IPV6;
		toh->name = IPV6_PATHMTU;
		toh->len = opt_length;
		toh->status = 0;

		mtuinfo = (struct ip6_mtuinfo *)&toh[1];
		bzero(mtuinfo, sizeof (struct ip6_mtuinfo));
		mtuinfo->ip6m_addr.sin6_family = AF_INET6;
		mtuinfo->ip6m_addr.sin6_addr = ip6h->ip6_dst;
		mtuinfo->ip6m_mtu = icmp6->icmp6_mtu;
		/*
		 * We've consumed everything we need from the original
		 * message.  Free it, then send our empty message.
		 */
		freemsg(mp);
		udp_ulp_recv(connp, newmp, msgdsize(newmp), ira);
		return;
	}
	case ICMP6_TIME_EXCEEDED:
		/* Transient errors */
		break;
	case ICMP6_PARAM_PROB:
		/* If this corresponds to an ICMP_PROTOCOL_UNREACHABLE */
		if (icmp6->icmp6_code == ICMP6_PARAMPROB_NEXTHEADER &&
		    (uchar_t *)ip6h + icmp6->icmp6_pptr ==
		    (uchar_t *)nexthdrp) {
			error = ECONNREFUSED;
			break;
		}
		break;
	}
	if (error == 0) {
		freemsg(mp);
		return;
	}

	/*
	 * Deliver T_UDERROR_IND when the application has asked for it.
	 * The socket layer enables this automatically when connected.
	 */
	if (!connp->conn_dgram_errind) {
		freemsg(mp);
		return;
	}

	sin6 = sin6_null;
	sin6.sin6_family = AF_INET6;
	sin6.sin6_addr = ip6h->ip6_dst;
	sin6.sin6_port = udpha->uha_dst_port;
	sin6.sin6_flowinfo = ip6h->ip6_vcf & ~IPV6_VERS_AND_FLOW_MASK;

	if (IPCL_IS_NONSTR(connp)) {
		mutex_enter(&connp->conn_lock);
		if (udp->udp_state == TS_DATA_XFER) {
			if (sin6.sin6_port == connp->conn_fport &&
			    IN6_ARE_ADDR_EQUAL(&sin6.sin6_addr,
			    &connp->conn_faddr_v6)) {
				mutex_exit(&connp->conn_lock);
				(*connp->conn_upcalls->su_set_error)
				    (connp->conn_upper_handle, error);
				goto done;
			}
		} else {
			udp->udp_delayed_error = error;
			*((sin6_t *)&udp->udp_delayed_addr) = sin6;
		}
		mutex_exit(&connp->conn_lock);
	} else {
		mp1 = mi_tpi_uderror_ind((char *)&sin6, sizeof (sin6_t),
		    NULL, 0, error);
		if (mp1 != NULL)
			putnext(connp->conn_rq, mp1);
	}
done:
	freemsg(mp);
}

/*
 * This routine responds to T_ADDR_REQ messages.  It is called by udp_wput.
 * The local address is filled in if endpoint is bound. The remote address
 * is filled in if remote address has been precified ("connected endpoint")
 * (The concept of connected CLTS sockets is alien to published TPI
 *  but we support it anyway).
 */
static void
udp_addr_req(queue_t *q, mblk_t *mp)
{
	struct sockaddr *sa;
	mblk_t	*ackmp;
	struct T_addr_ack *taa;
	udp_t	*udp = Q_TO_UDP(q);
	conn_t	*connp = udp->udp_connp;
	uint_t	addrlen;

	/* Make it large enough for worst case */
	ackmp = reallocb(mp, sizeof (struct T_addr_ack) +
	    2 * sizeof (sin6_t), 1);
	if (ackmp == NULL) {
		udp_err_ack(q, mp, TSYSERR, ENOMEM);
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

	mutex_enter(&connp->conn_lock);
	/*
	 * Note: Following code assumes 32 bit alignment of basic
	 * data structures like sin_t and struct T_addr_ack.
	 */
	if (udp->udp_state != TS_UNBND) {
		/*
		 * Fill in local address first
		 */
		taa->LOCADDR_offset = sizeof (*taa);
		taa->LOCADDR_length = addrlen;
		sa = (struct sockaddr *)&taa[1];
		(void) conn_getsockname(connp, sa, &addrlen);
		ackmp->b_wptr += addrlen;
	}
	if (udp->udp_state == TS_DATA_XFER) {
		/*
		 * connected, fill remote address too
		 */
		taa->REMADDR_length = addrlen;
		/* assumed 32-bit alignment */
		taa->REMADDR_offset = taa->LOCADDR_offset + taa->LOCADDR_length;
		sa = (struct sockaddr *)(ackmp->b_rptr + taa->REMADDR_offset);
		(void) conn_getpeername(connp, sa, &addrlen);
		ackmp->b_wptr += addrlen;
	}
	mutex_exit(&connp->conn_lock);
	ASSERT(ackmp->b_wptr <= ackmp->b_datap->db_lim);
	qreply(q, ackmp);
}

static void
udp_copy_info(struct T_info_ack *tap, udp_t *udp)
{
	conn_t		*connp = udp->udp_connp;

	if (connp->conn_family == AF_INET) {
		*tap = udp_g_t_info_ack_ipv4;
	} else {
		*tap = udp_g_t_info_ack_ipv6;
	}
	tap->CURRENT_state = udp->udp_state;
	tap->OPT_size = udp_max_optsize;
}

static void
udp_do_capability_ack(udp_t *udp, struct T_capability_ack *tcap,
    t_uscalar_t cap_bits1)
{
	tcap->CAP_bits1 = 0;

	if (cap_bits1 & TC1_INFO) {
		udp_copy_info(&tcap->INFO_ack, udp);
		tcap->CAP_bits1 |= TC1_INFO;
	}
}

/*
 * This routine responds to T_CAPABILITY_REQ messages.  It is called by
 * udp_wput.  Much of the T_CAPABILITY_ACK information is copied from
 * udp_g_t_info_ack.  The current state of the stream is copied from
 * udp_state.
 */
static void
udp_capability_req(queue_t *q, mblk_t *mp)
{
	t_uscalar_t		cap_bits1;
	struct T_capability_ack	*tcap;
	udp_t	*udp = Q_TO_UDP(q);

	cap_bits1 = ((struct T_capability_req *)mp->b_rptr)->CAP_bits1;

	mp = tpi_ack_alloc(mp, sizeof (struct T_capability_ack),
	    mp->b_datap->db_type, T_CAPABILITY_ACK);
	if (!mp)
		return;

	tcap = (struct T_capability_ack *)mp->b_rptr;
	udp_do_capability_ack(udp, tcap, cap_bits1);

	qreply(q, mp);
}

/*
 * This routine responds to T_INFO_REQ messages.  It is called by udp_wput.
 * Most of the T_INFO_ACK information is copied from udp_g_t_info_ack.
 * The current state of the stream is copied from udp_state.
 */
static void
udp_info_req(queue_t *q, mblk_t *mp)
{
	udp_t *udp = Q_TO_UDP(q);

	/* Create a T_INFO_ACK message. */
	mp = tpi_ack_alloc(mp, sizeof (struct T_info_ack), M_PCPROTO,
	    T_INFO_ACK);
	if (!mp)
		return;
	udp_copy_info((struct T_info_ack *)mp->b_rptr, udp);
	qreply(q, mp);
}

/* For /dev/udp aka AF_INET open */
static int
udp_openv4(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	return (udp_open(q, devp, flag, sflag, credp, B_FALSE));
}

/* For /dev/udp6 aka AF_INET6 open */
static int
udp_openv6(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	return (udp_open(q, devp, flag, sflag, credp, B_TRUE));
}

/*
 * This is the open routine for udp.  It allocates a udp_t structure for
 * the stream and, on the first open of the module, creates an ND table.
 */
static int
udp_open(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp,
    boolean_t isv6)
{
	udp_t		*udp;
	conn_t		*connp;
	dev_t		conn_dev;
	vmem_t		*minor_arena;
	int		err;

	/* If the stream is already open, return immediately. */
	if (q->q_ptr != NULL)
		return (0);

	if (sflag == MODOPEN)
		return (EINVAL);

	if ((ip_minor_arena_la != NULL) && (flag & SO_SOCKSTR) &&
	    ((conn_dev = inet_minor_alloc(ip_minor_arena_la)) != 0)) {
		minor_arena = ip_minor_arena_la;
	} else {
		/*
		 * Either minor numbers in the large arena were exhausted
		 * or a non socket application is doing the open.
		 * Try to allocate from the small arena.
		 */
		if ((conn_dev = inet_minor_alloc(ip_minor_arena_sa)) == 0)
			return (EBUSY);

		minor_arena = ip_minor_arena_sa;
	}

	if (flag & SO_FALLBACK) {
		/*
		 * Non streams socket needs a stream to fallback to
		 */
		RD(q)->q_ptr = (void *)conn_dev;
		WR(q)->q_qinfo = &udp_fallback_sock_winit;
		WR(q)->q_ptr = (void *)minor_arena;
		qprocson(q);
		return (0);
	}

	connp = udp_do_open(credp, isv6, KM_SLEEP, &err);
	if (connp == NULL) {
		inet_minor_free(minor_arena, conn_dev);
		return (err);
	}
	udp = connp->conn_udp;

	*devp = makedevice(getemajor(*devp), (minor_t)conn_dev);
	connp->conn_dev = conn_dev;
	connp->conn_minor_arena = minor_arena;

	/*
	 * Initialize the udp_t structure for this stream.
	 */
	q->q_ptr = connp;
	WR(q)->q_ptr = connp;
	connp->conn_rq = q;
	connp->conn_wq = WR(q);

	/*
	 * Since this conn_t/udp_t is not yet visible to anybody else we don't
	 * need to lock anything.
	 */
	ASSERT(connp->conn_proto == IPPROTO_UDP);
	ASSERT(connp->conn_udp == udp);
	ASSERT(udp->udp_connp == connp);

	if (flag & SO_SOCKSTR) {
		udp->udp_issocket = B_TRUE;
	}

	WR(q)->q_hiwat = connp->conn_sndbuf;
	WR(q)->q_lowat = connp->conn_sndlowat;

	qprocson(q);

	/* Set the Stream head write offset and high watermark. */
	(void) proto_set_tx_wroff(q, connp, connp->conn_wroff);
	(void) proto_set_rx_hiwat(q, connp,
	    udp_set_rcv_hiwat(udp, connp->conn_rcvbuf));

	mutex_enter(&connp->conn_lock);
	connp->conn_state_flags &= ~CONN_INCIPIENT;
	mutex_exit(&connp->conn_lock);
	return (0);
}

/*
 * Which UDP options OK to set through T_UNITDATA_REQ...
 */
/* ARGSUSED */
static boolean_t
udp_opt_allow_udr_set(t_scalar_t level, t_scalar_t name)
{
	return (B_TRUE);
}

/*
 * This routine gets default values of certain options whose default
 * values are maintained by protcol specific code
 */
int
udp_opt_default(queue_t *q, t_scalar_t level, t_scalar_t name, uchar_t *ptr)
{
	udp_t		*udp = Q_TO_UDP(q);
	udp_stack_t *us = udp->udp_us;
	int *i1 = (int *)ptr;

	switch (level) {
	case IPPROTO_IP:
		switch (name) {
		case IP_MULTICAST_TTL:
			*ptr = (uchar_t)IP_DEFAULT_MULTICAST_TTL;
			return (sizeof (uchar_t));
		case IP_MULTICAST_LOOP:
			*ptr = (uchar_t)IP_DEFAULT_MULTICAST_LOOP;
			return (sizeof (uchar_t));
		}
		break;
	case IPPROTO_IPV6:
		switch (name) {
		case IPV6_MULTICAST_HOPS:
			*i1 = IP_DEFAULT_MULTICAST_TTL;
			return (sizeof (int));
		case IPV6_MULTICAST_LOOP:
			*i1 = IP_DEFAULT_MULTICAST_LOOP;
			return (sizeof (int));
		case IPV6_UNICAST_HOPS:
			*i1 = us->us_ipv6_hoplimit;
			return (sizeof (int));
		}
		break;
	}
	return (-1);
}

/*
 * This routine retrieves the current status of socket options.
 * It returns the size of the option retrieved, or -1.
 */
int
udp_opt_get(conn_t *connp, t_scalar_t level, t_scalar_t name,
    uchar_t *ptr)
{
	int		*i1 = (int *)ptr;
	udp_t		*udp = connp->conn_udp;
	int		len;
	conn_opt_arg_t	coas;
	int		retval;

	coas.coa_connp = connp;
	coas.coa_ixa = connp->conn_ixa;
	coas.coa_ipp = &connp->conn_xmit_ipp;
	coas.coa_ancillary = B_FALSE;
	coas.coa_changed = 0;

	/*
	 * We assume that the optcom framework has checked for the set
	 * of levels and names that are supported, hence we don't worry
	 * about rejecting based on that.
	 * First check for UDP specific handling, then pass to common routine.
	 */
	switch (level) {
	case IPPROTO_IP:
		/*
		 * Only allow IPv4 option processing on IPv4 sockets.
		 */
		if (connp->conn_family != AF_INET)
			return (-1);

		switch (name) {
		case IP_OPTIONS:
		case T_IP_OPTIONS:
			mutex_enter(&connp->conn_lock);
			if (!(udp->udp_recv_ipp.ipp_fields &
			    IPPF_IPV4_OPTIONS)) {
				mutex_exit(&connp->conn_lock);
				return (0);
			}

			len = udp->udp_recv_ipp.ipp_ipv4_options_len;
			ASSERT(len != 0);
			bcopy(udp->udp_recv_ipp.ipp_ipv4_options, ptr, len);
			mutex_exit(&connp->conn_lock);
			return (len);
		}
		break;
	case IPPROTO_UDP:
		switch (name) {
		case UDP_NAT_T_ENDPOINT:
			mutex_enter(&connp->conn_lock);
			*i1 = udp->udp_nat_t_endpoint;
			mutex_exit(&connp->conn_lock);
			return (sizeof (int));
		case UDP_RCVHDR:
			mutex_enter(&connp->conn_lock);
			*i1 = udp->udp_rcvhdr ? 1 : 0;
			mutex_exit(&connp->conn_lock);
			return (sizeof (int));
		}
	}
	mutex_enter(&connp->conn_lock);
	retval = conn_opt_get(&coas, level, name, ptr);
	mutex_exit(&connp->conn_lock);
	return (retval);
}

/*
 * This routine retrieves the current status of socket options.
 * It returns the size of the option retrieved, or -1.
 */
int
udp_tpi_opt_get(queue_t *q, t_scalar_t level, t_scalar_t name, uchar_t *ptr)
{
	conn_t		*connp = Q_TO_CONN(q);
	int		err;

	err = udp_opt_get(connp, level, name, ptr);
	return (err);
}

/*
 * This routine sets socket options.
 */
int
udp_do_opt_set(conn_opt_arg_t *coa, int level, int name,
    uint_t inlen, uchar_t *invalp, cred_t *cr, boolean_t checkonly)
{
	conn_t		*connp = coa->coa_connp;
	ip_xmit_attr_t	*ixa = coa->coa_ixa;
	udp_t		*udp = connp->conn_udp;
	udp_stack_t	*us = udp->udp_us;
	int		*i1 = (int *)invalp;
	boolean_t 	onoff = (*i1 == 0) ? 0 : 1;
	int		error;

	ASSERT(MUTEX_NOT_HELD(&coa->coa_connp->conn_lock));
	/*
	 * First do UDP specific sanity checks and handle UDP specific
	 * options. Note that some IPPROTO_UDP options are handled
	 * by conn_opt_set.
	 */
	switch (level) {
	case SOL_SOCKET:
		switch (name) {
		case SO_SNDBUF:
			if (*i1 > us->us_max_buf) {
				return (ENOBUFS);
			}
			break;
		case SO_RCVBUF:
			if (*i1 > us->us_max_buf) {
				return (ENOBUFS);
			}
			break;

		case SCM_UCRED: {
			struct ucred_s *ucr;
			cred_t *newcr;
			ts_label_t *tsl;

			/*
			 * Only sockets that have proper privileges and are
			 * bound to MLPs will have any other value here, so
			 * this implicitly tests for privilege to set label.
			 */
			if (connp->conn_mlp_type == mlptSingle)
				break;

			ucr = (struct ucred_s *)invalp;
			if (inlen < sizeof (*ucr) + sizeof (bslabel_t) ||
			    ucr->uc_labeloff < sizeof (*ucr) ||
			    ucr->uc_labeloff + sizeof (bslabel_t) > inlen)
				return (EINVAL);
			if (!checkonly) {
				/*
				 * Set ixa_tsl to the new label.
				 * We assume that crgetzoneid doesn't change
				 * as part of the SCM_UCRED.
				 */
				ASSERT(cr != NULL);
				if ((tsl = crgetlabel(cr)) == NULL)
					return (EINVAL);
				newcr = copycred_from_bslabel(cr, UCLABEL(ucr),
				    tsl->tsl_doi, KM_NOSLEEP);
				if (newcr == NULL)
					return (ENOSR);
				ASSERT(newcr->cr_label != NULL);
				/*
				 * Move the hold on the cr_label to ixa_tsl by
				 * setting cr_label to NULL. Then release newcr.
				 */
				ip_xmit_attr_replace_tsl(ixa, newcr->cr_label);
				ixa->ixa_flags |= IXAF_UCRED_TSL;
				newcr->cr_label = NULL;
				crfree(newcr);
				coa->coa_changed |= COA_HEADER_CHANGED;
				coa->coa_changed |= COA_WROFF_CHANGED;
			}
			/* Fully handled this option. */
			return (0);
		}
		}
		break;
	case IPPROTO_UDP:
		switch (name) {
		case UDP_NAT_T_ENDPOINT:
			if ((error = secpolicy_ip_config(cr, B_FALSE)) != 0) {
				return (error);
			}

			/*
			 * Use conn_family instead so we can avoid ambiguitites
			 * with AF_INET6 sockets that may switch from IPv4
			 * to IPv6.
			 */
			if (connp->conn_family != AF_INET) {
				return (EAFNOSUPPORT);
			}

			if (!checkonly) {
				mutex_enter(&connp->conn_lock);
				udp->udp_nat_t_endpoint = onoff;
				mutex_exit(&connp->conn_lock);
				coa->coa_changed |= COA_HEADER_CHANGED;
				coa->coa_changed |= COA_WROFF_CHANGED;
			}
			/* Fully handled this option. */
			return (0);
		case UDP_RCVHDR:
			mutex_enter(&connp->conn_lock);
			udp->udp_rcvhdr = onoff;
			mutex_exit(&connp->conn_lock);
			return (0);
		}
		break;
	}
	error = conn_opt_set(coa, level, name, inlen, invalp,
	    checkonly, cr);
	return (error);
}

/*
 * This routine sets socket options.
 */
int
udp_opt_set(conn_t *connp, uint_t optset_context, int level,
    int name, uint_t inlen, uchar_t *invalp, uint_t *outlenp,
    uchar_t *outvalp, void *thisdg_attrs, cred_t *cr)
{
	udp_t		*udp = connp->conn_udp;
	int		err;
	conn_opt_arg_t	coas, *coa;
	boolean_t	checkonly;
	udp_stack_t	*us = udp->udp_us;

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
		 * through T_UNITDATA_REQ.
		 *
		 * Following routine can filter out ones we do not
		 * want to be "set" this way.
		 */
		if (!udp_opt_allow_udr_set(level, name)) {
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

	if (thisdg_attrs != NULL) {
		/* Options from T_UNITDATA_REQ */
		coa = (conn_opt_arg_t *)thisdg_attrs;
		ASSERT(coa->coa_connp == connp);
		ASSERT(coa->coa_ixa != NULL);
		ASSERT(coa->coa_ipp != NULL);
		ASSERT(coa->coa_ancillary);
	} else {
		coa = &coas;
		coas.coa_connp = connp;
		/* Get a reference on conn_ixa to prevent concurrent mods */
		coas.coa_ixa = conn_get_ixa(connp, B_TRUE);
		if (coas.coa_ixa == NULL) {
			*outlenp = 0;
			return (ENOMEM);
		}
		coas.coa_ipp = &connp->conn_xmit_ipp;
		coas.coa_ancillary = B_FALSE;
		coas.coa_changed = 0;
	}

	err = udp_do_opt_set(coa, level, name, inlen, invalp,
	    cr, checkonly);
	if (err != 0) {
errout:
		if (!coa->coa_ancillary)
			ixa_refrele(coa->coa_ixa);
		*outlenp = 0;
		return (err);
	}
	/* Handle DHCPINIT here outside of lock */
	if (level == IPPROTO_IP && name == IP_DHCPINIT_IF) {
		uint_t	ifindex;
		ill_t	*ill;

		ifindex = *(uint_t *)invalp;
		if (ifindex == 0) {
			ill = NULL;
		} else {
			ill = ill_lookup_on_ifindex(ifindex, B_FALSE,
			    coa->coa_ixa->ixa_ipst);
			if (ill == NULL) {
				err = ENXIO;
				goto errout;
			}

			mutex_enter(&ill->ill_lock);
			if (ill->ill_state_flags & ILL_CONDEMNED) {
				mutex_exit(&ill->ill_lock);
				ill_refrele(ill);
				err = ENXIO;
				goto errout;
			}
			if (IS_VNI(ill)) {
				mutex_exit(&ill->ill_lock);
				ill_refrele(ill);
				err = EINVAL;
				goto errout;
			}
		}
		mutex_enter(&connp->conn_lock);

		if (connp->conn_dhcpinit_ill != NULL) {
			/*
			 * We've locked the conn so conn_cleanup_ill()
			 * cannot clear conn_dhcpinit_ill -- so it's
			 * safe to access the ill.
			 */
			ill_t *oill = connp->conn_dhcpinit_ill;

			ASSERT(oill->ill_dhcpinit != 0);
			atomic_dec_32(&oill->ill_dhcpinit);
			ill_set_inputfn(connp->conn_dhcpinit_ill);
			connp->conn_dhcpinit_ill = NULL;
		}

		if (ill != NULL) {
			connp->conn_dhcpinit_ill = ill;
			atomic_inc_32(&ill->ill_dhcpinit);
			ill_set_inputfn(ill);
			mutex_exit(&connp->conn_lock);
			mutex_exit(&ill->ill_lock);
			ill_refrele(ill);
		} else {
			mutex_exit(&connp->conn_lock);
		}
	}

	/*
	 * Common case of OK return with outval same as inval.
	 */
	if (invalp != outvalp) {
		/* don't trust bcopy for identical src/dst */
		(void) bcopy(invalp, outvalp, inlen);
	}
	*outlenp = inlen;

	/*
	 * If this was not ancillary data, then we rebuild the headers,
	 * update the IRE/NCE, and IPsec as needed.
	 * Since the label depends on the destination we go through
	 * ip_set_destination first.
	 */
	if (coa->coa_ancillary) {
		return (0);
	}

	if (coa->coa_changed & COA_ROUTE_CHANGED) {
		in6_addr_t saddr, faddr, nexthop;
		in_port_t fport;

		/*
		 * We clear lastdst to make sure we pick up the change
		 * next time sending.
		 * If we are connected we re-cache the information.
		 * We ignore errors to preserve BSD behavior.
		 * Note that we don't redo IPsec policy lookup here
		 * since the final destination (or source) didn't change.
		 */
		mutex_enter(&connp->conn_lock);
		connp->conn_v6lastdst = ipv6_all_zeros;

		ip_attr_nexthop(coa->coa_ipp, coa->coa_ixa,
		    &connp->conn_faddr_v6, &nexthop);
		saddr = connp->conn_saddr_v6;
		faddr = connp->conn_faddr_v6;
		fport = connp->conn_fport;
		mutex_exit(&connp->conn_lock);

		if (!IN6_IS_ADDR_UNSPECIFIED(&faddr) &&
		    !IN6_IS_ADDR_V4MAPPED_ANY(&faddr)) {
			(void) ip_attr_connect(connp, coa->coa_ixa,
			    &saddr, &faddr, &nexthop, fport, NULL, NULL,
			    IPDF_ALLOW_MCBC | IPDF_VERIFY_DST);
		}
	}

	ixa_refrele(coa->coa_ixa);

	if (coa->coa_changed & COA_HEADER_CHANGED) {
		/*
		 * Rebuild the header template if we are connected.
		 * Otherwise clear conn_v6lastdst so we rebuild the header
		 * in the data path.
		 */
		mutex_enter(&connp->conn_lock);
		if (!IN6_IS_ADDR_UNSPECIFIED(&connp->conn_faddr_v6) &&
		    !IN6_IS_ADDR_V4MAPPED_ANY(&connp->conn_faddr_v6)) {
			err = udp_build_hdr_template(connp,
			    &connp->conn_saddr_v6, &connp->conn_faddr_v6,
			    connp->conn_fport, connp->conn_flowinfo);
			if (err != 0) {
				mutex_exit(&connp->conn_lock);
				return (err);
			}
		} else {
			connp->conn_v6lastdst = ipv6_all_zeros;
		}
		mutex_exit(&connp->conn_lock);
	}
	if (coa->coa_changed & COA_RCVBUF_CHANGED) {
		(void) proto_set_rx_hiwat(connp->conn_rq, connp,
		    connp->conn_rcvbuf);
	}
	if ((coa->coa_changed & COA_SNDBUF_CHANGED) && !IPCL_IS_NONSTR(connp)) {
		connp->conn_wq->q_hiwat = connp->conn_sndbuf;
	}
	if (coa->coa_changed & COA_WROFF_CHANGED) {
		/* Increase wroff if needed */
		uint_t wroff;

		mutex_enter(&connp->conn_lock);
		wroff = connp->conn_ht_iphc_allocated + us->us_wroff_extra;
		if (udp->udp_nat_t_endpoint)
			wroff += sizeof (uint32_t);
		if (wroff > connp->conn_wroff) {
			connp->conn_wroff = wroff;
			mutex_exit(&connp->conn_lock);
			(void) proto_set_tx_wroff(connp->conn_rq, connp, wroff);
		} else {
			mutex_exit(&connp->conn_lock);
		}
	}
	return (err);
}

/* This routine sets socket options. */
int
udp_tpi_opt_set(queue_t *q, uint_t optset_context, int level, int name,
    uint_t inlen, uchar_t *invalp, uint_t *outlenp, uchar_t *outvalp,
    void *thisdg_attrs, cred_t *cr)
{
	conn_t	*connp = Q_TO_CONN(q);
	int error;

	error = udp_opt_set(connp, optset_context, level, name, inlen, invalp,
	    outlenp, outvalp, thisdg_attrs, cr);
	return (error);
}

/*
 * Setup IP and UDP headers.
 * Returns NULL on allocation failure, in which case data_mp is freed.
 */
mblk_t *
udp_prepend_hdr(conn_t *connp, ip_xmit_attr_t *ixa, const ip_pkt_t *ipp,
    const in6_addr_t *v6src, const in6_addr_t *v6dst, in_port_t dstport,
    uint32_t flowinfo, mblk_t *data_mp, int *errorp)
{
	mblk_t		*mp;
	udpha_t		*udpha;
	udp_stack_t	*us = connp->conn_netstack->netstack_udp;
	uint_t		data_len;
	uint32_t	cksum;
	udp_t		*udp = connp->conn_udp;
	boolean_t	insert_spi = udp->udp_nat_t_endpoint;
	uint_t		ulp_hdr_len;

	data_len = msgdsize(data_mp);
	ulp_hdr_len = UDPH_SIZE;
	if (insert_spi)
		ulp_hdr_len += sizeof (uint32_t);

	mp = conn_prepend_hdr(ixa, ipp, v6src, v6dst, IPPROTO_UDP, flowinfo,
	    ulp_hdr_len, data_mp, data_len, us->us_wroff_extra, &cksum, errorp);
	if (mp == NULL) {
		ASSERT(*errorp != 0);
		return (NULL);
	}

	data_len += ulp_hdr_len;
	ixa->ixa_pktlen = data_len + ixa->ixa_ip_hdr_length;

	udpha = (udpha_t *)(mp->b_rptr + ixa->ixa_ip_hdr_length);
	udpha->uha_src_port = connp->conn_lport;
	udpha->uha_dst_port = dstport;
	udpha->uha_checksum = 0;
	udpha->uha_length = htons(data_len);

	/*
	 * If there was a routing option/header then conn_prepend_hdr
	 * has massaged it and placed the pseudo-header checksum difference
	 * in the cksum argument.
	 *
	 * Setup header length and prepare for ULP checksum done in IP.
	 *
	 * We make it easy for IP to include our pseudo header
	 * by putting our length in uha_checksum.
	 * The IP source, destination, and length have already been set by
	 * conn_prepend_hdr.
	 */
	cksum += data_len;
	cksum = (cksum >> 16) + (cksum & 0xFFFF);
	ASSERT(cksum < 0x10000);

	if (ixa->ixa_flags & IXAF_IS_IPV4) {
		ipha_t	*ipha = (ipha_t *)mp->b_rptr;

		ASSERT(ntohs(ipha->ipha_length) == ixa->ixa_pktlen);

		/* IP does the checksum if uha_checksum is non-zero */
		if (us->us_do_checksum) {
			if (cksum == 0)
				udpha->uha_checksum = 0xffff;
			else
				udpha->uha_checksum = htons(cksum);
		} else {
			udpha->uha_checksum = 0;
		}
	} else {
		ip6_t *ip6h = (ip6_t *)mp->b_rptr;

		ASSERT(ntohs(ip6h->ip6_plen) + IPV6_HDR_LEN == ixa->ixa_pktlen);
		if (cksum == 0)
			udpha->uha_checksum = 0xffff;
		else
			udpha->uha_checksum = htons(cksum);
	}

	/* Insert all-0s SPI now. */
	if (insert_spi)
		*((uint32_t *)(udpha + 1)) = 0;

	return (mp);
}

static int
udp_build_hdr_template(conn_t *connp, const in6_addr_t *v6src,
    const in6_addr_t *v6dst, in_port_t dstport, uint32_t flowinfo)
{
	udpha_t		*udpha;
	int		error;

	ASSERT(MUTEX_HELD(&connp->conn_lock));
	/*
	 * We clear lastdst to make sure we don't use the lastdst path
	 * next time sending since we might not have set v6dst yet.
	 */
	connp->conn_v6lastdst = ipv6_all_zeros;

	error = conn_build_hdr_template(connp, UDPH_SIZE, 0, v6src, v6dst,
	    flowinfo);
	if (error != 0)
		return (error);

	/*
	 * Any routing header/option has been massaged. The checksum difference
	 * is stored in conn_sum.
	 */
	udpha = (udpha_t *)connp->conn_ht_ulp;
	udpha->uha_src_port = connp->conn_lport;
	udpha->uha_dst_port = dstport;
	udpha->uha_checksum = 0;
	udpha->uha_length = htons(UDPH_SIZE);	/* Filled in later */
	return (0);
}

static mblk_t *
udp_queue_fallback(udp_t *udp, mblk_t *mp)
{
	ASSERT(MUTEX_HELD(&udp->udp_recv_lock));
	if (IPCL_IS_NONSTR(udp->udp_connp)) {
		/*
		 * fallback has started but messages have not been moved yet
		 */
		if (udp->udp_fallback_queue_head == NULL) {
			ASSERT(udp->udp_fallback_queue_tail == NULL);
			udp->udp_fallback_queue_head = mp;
			udp->udp_fallback_queue_tail = mp;
		} else {
			ASSERT(udp->udp_fallback_queue_tail != NULL);
			udp->udp_fallback_queue_tail->b_next = mp;
			udp->udp_fallback_queue_tail = mp;
		}
		return (NULL);
	} else {
		/*
		 * Fallback completed, let the caller putnext() the mblk.
		 */
		return (mp);
	}
}

/*
 * Deliver data to ULP. In case we have a socket, and it's falling back to
 * TPI, then we'll queue the mp for later processing.
 */
static void
udp_ulp_recv(conn_t *connp, mblk_t *mp, uint_t len, ip_recv_attr_t *ira)
{
	if (IPCL_IS_NONSTR(connp)) {
		udp_t *udp = connp->conn_udp;
		int error;

		ASSERT(len == msgdsize(mp));
		if ((*connp->conn_upcalls->su_recv)
		    (connp->conn_upper_handle, mp, len, 0, &error, NULL) < 0) {
			mutex_enter(&udp->udp_recv_lock);
			if (error == ENOSPC) {
				/*
				 * let's confirm while holding the lock
				 */
				if ((*connp->conn_upcalls->su_recv)
				    (connp->conn_upper_handle, NULL, 0, 0,
				    &error, NULL) < 0) {
					ASSERT(error == ENOSPC);
					if (error == ENOSPC) {
						connp->conn_flow_cntrld =
						    B_TRUE;
					}
				}
				mutex_exit(&udp->udp_recv_lock);
			} else {
				ASSERT(error == EOPNOTSUPP);
				mp = udp_queue_fallback(udp, mp);
				mutex_exit(&udp->udp_recv_lock);
				if (mp != NULL)
					putnext(connp->conn_rq, mp);
			}
		}
		ASSERT(MUTEX_NOT_HELD(&udp->udp_recv_lock));
	} else {
		if (is_system_labeled()) {
			ASSERT(ira->ira_cred != NULL);
			/*
			 * Provide for protocols above UDP such as RPC
			 * NOPID leaves db_cpid unchanged.
			 */
			mblk_setcred(mp, ira->ira_cred, NOPID);
		}

		putnext(connp->conn_rq, mp);
	}
}

/*
 * This is the inbound data path.
 * IP has already pulled up the IP plus UDP headers and verified alignment
 * etc.
 */
/* ARGSUSED2 */
static void
udp_input(void *arg1, mblk_t *mp, void *arg2, ip_recv_attr_t *ira)
{
	conn_t			*connp = (conn_t *)arg1;
	struct T_unitdata_ind	*tudi;
	uchar_t			*rptr;		/* Pointer to IP header */
	int			hdr_length;	/* Length of IP+UDP headers */
	int			udi_size;	/* Size of T_unitdata_ind */
	int			pkt_len;
	udp_t			*udp;
	udpha_t			*udpha;
	ip_pkt_t		ipps;
	ip6_t			*ip6h;
	mblk_t			*mp1;
	uint32_t		udp_ipv4_options_len;
	crb_t			recv_ancillary;
	udp_stack_t		*us;

	ASSERT(connp->conn_flags & IPCL_UDPCONN);

	udp = connp->conn_udp;
	us = udp->udp_us;
	rptr = mp->b_rptr;

	ASSERT(DB_TYPE(mp) == M_DATA);
	ASSERT(OK_32PTR(rptr));
	ASSERT(ira->ira_pktlen == msgdsize(mp));
	pkt_len = ira->ira_pktlen;

	/*
	 * Get a snapshot of these and allow other threads to change
	 * them after that. We need the same recv_ancillary when determining
	 * the size as when adding the ancillary data items.
	 */
	mutex_enter(&connp->conn_lock);
	udp_ipv4_options_len = udp->udp_recv_ipp.ipp_ipv4_options_len;
	recv_ancillary = connp->conn_recv_ancillary;
	mutex_exit(&connp->conn_lock);

	hdr_length = ira->ira_ip_hdr_length;

	/*
	 * IP inspected the UDP header thus all of it must be in the mblk.
	 * UDP length check is performed for IPv6 packets and IPv4 packets
	 * to check if the size of the packet as specified
	 * by the UDP header is the same as the length derived from the IP
	 * header.
	 */
	udpha = (udpha_t *)(rptr + hdr_length);
	if (pkt_len != ntohs(udpha->uha_length) + hdr_length)
		goto tossit;

	hdr_length += UDPH_SIZE;
	ASSERT(MBLKL(mp) >= hdr_length);	/* IP did a pullup */

	/* Initialize regardless of IP version */
	ipps.ipp_fields = 0;

	if (((ira->ira_flags & IRAF_IPV4_OPTIONS) ||
	    udp_ipv4_options_len > 0) &&
	    connp->conn_family == AF_INET) {
		int	err;

		/*
		 * Record/update udp_recv_ipp with the lock
		 * held. Not needed for AF_INET6 sockets
		 * since they don't support a getsockopt of IP_OPTIONS.
		 */
		mutex_enter(&connp->conn_lock);
		err = ip_find_hdr_v4((ipha_t *)rptr, &udp->udp_recv_ipp,
		    B_TRUE);
		if (err != 0) {
			/* Allocation failed. Drop packet */
			mutex_exit(&connp->conn_lock);
			freemsg(mp);
			UDPS_BUMP_MIB(us, udpInErrors);
			return;
		}
		mutex_exit(&connp->conn_lock);
	}

	if (recv_ancillary.crb_all != 0) {
		/*
		 * Record packet information in the ip_pkt_t
		 */
		if (ira->ira_flags & IRAF_IS_IPV4) {
			ASSERT(IPH_HDR_VERSION(rptr) == IPV4_VERSION);
			ASSERT(MBLKL(mp) >= sizeof (ipha_t));
			ASSERT(((ipha_t *)rptr)->ipha_protocol == IPPROTO_UDP);
			ASSERT(ira->ira_ip_hdr_length == IPH_HDR_LENGTH(rptr));

			(void) ip_find_hdr_v4((ipha_t *)rptr, &ipps, B_FALSE);
		} else {
			uint8_t nexthdrp;

			ASSERT(IPH_HDR_VERSION(rptr) == IPV6_VERSION);
			/*
			 * IPv6 packets can only be received by applications
			 * that are prepared to receive IPv6 addresses.
			 * The IP fanout must ensure this.
			 */
			ASSERT(connp->conn_family == AF_INET6);

			ip6h = (ip6_t *)rptr;

			/* We don't care about the length, but need the ipp */
			hdr_length = ip_find_hdr_v6(mp, ip6h, B_TRUE, &ipps,
			    &nexthdrp);
			ASSERT(hdr_length == ira->ira_ip_hdr_length);
			/* Restore */
			hdr_length = ira->ira_ip_hdr_length + UDPH_SIZE;
			ASSERT(nexthdrp == IPPROTO_UDP);
		}
	}

	/*
	 * This is the inbound data path.  Packets are passed upstream as
	 * T_UNITDATA_IND messages.
	 */
	if (connp->conn_family == AF_INET) {
		sin_t *sin;

		ASSERT(IPH_HDR_VERSION((ipha_t *)rptr) == IPV4_VERSION);

		/*
		 * Normally only send up the source address.
		 * If any ancillary data items are wanted we add those.
		 */
		udi_size = sizeof (struct T_unitdata_ind) + sizeof (sin_t);
		if (recv_ancillary.crb_all != 0) {
			udi_size += conn_recvancillary_size(connp,
			    recv_ancillary, ira, mp, &ipps);
		}

		/* Allocate a message block for the T_UNITDATA_IND structure. */
		mp1 = allocb(udi_size, BPRI_MED);
		if (mp1 == NULL) {
			freemsg(mp);
			UDPS_BUMP_MIB(us, udpInErrors);
			return;
		}
		mp1->b_cont = mp;
		mp1->b_datap->db_type = M_PROTO;
		tudi = (struct T_unitdata_ind *)mp1->b_rptr;
		mp1->b_wptr = (uchar_t *)tudi + udi_size;
		tudi->PRIM_type = T_UNITDATA_IND;
		tudi->SRC_length = sizeof (sin_t);
		tudi->SRC_offset = sizeof (struct T_unitdata_ind);
		tudi->OPT_offset = sizeof (struct T_unitdata_ind) +
		    sizeof (sin_t);
		udi_size -= (sizeof (struct T_unitdata_ind) + sizeof (sin_t));
		tudi->OPT_length = udi_size;
		sin = (sin_t *)&tudi[1];
		sin->sin_addr.s_addr = ((ipha_t *)rptr)->ipha_src;
		sin->sin_port =	udpha->uha_src_port;
		sin->sin_family = connp->conn_family;
		*(uint32_t *)&sin->sin_zero[0] = 0;
		*(uint32_t *)&sin->sin_zero[4] = 0;

		/*
		 * Add options if IP_RECVDSTADDR, IP_RECVIF, IP_RECVSLLA or
		 * IP_RECVTTL has been set.
		 */
		if (udi_size != 0) {
			conn_recvancillary_add(connp, recv_ancillary, ira,
			    &ipps, (uchar_t *)&sin[1], udi_size);
		}
	} else {
		sin6_t *sin6;

		/*
		 * Handle both IPv4 and IPv6 packets for IPv6 sockets.
		 *
		 * Normally we only send up the address. If receiving of any
		 * optional receive side information is enabled, we also send
		 * that up as options.
		 */
		udi_size = sizeof (struct T_unitdata_ind) + sizeof (sin6_t);

		if (recv_ancillary.crb_all != 0) {
			udi_size += conn_recvancillary_size(connp,
			    recv_ancillary, ira, mp, &ipps);
		}

		mp1 = allocb(udi_size, BPRI_MED);
		if (mp1 == NULL) {
			freemsg(mp);
			UDPS_BUMP_MIB(us, udpInErrors);
			return;
		}
		mp1->b_cont = mp;
		mp1->b_datap->db_type = M_PROTO;
		tudi = (struct T_unitdata_ind *)mp1->b_rptr;
		mp1->b_wptr = (uchar_t *)tudi + udi_size;
		tudi->PRIM_type = T_UNITDATA_IND;
		tudi->SRC_length = sizeof (sin6_t);
		tudi->SRC_offset = sizeof (struct T_unitdata_ind);
		tudi->OPT_offset = sizeof (struct T_unitdata_ind) +
		    sizeof (sin6_t);
		udi_size -= (sizeof (struct T_unitdata_ind) + sizeof (sin6_t));
		tudi->OPT_length = udi_size;
		sin6 = (sin6_t *)&tudi[1];
		if (ira->ira_flags & IRAF_IS_IPV4) {
			in6_addr_t v6dst;

			IN6_IPADDR_TO_V4MAPPED(((ipha_t *)rptr)->ipha_src,
			    &sin6->sin6_addr);
			IN6_IPADDR_TO_V4MAPPED(((ipha_t *)rptr)->ipha_dst,
			    &v6dst);
			sin6->sin6_flowinfo = 0;
			sin6->sin6_scope_id = 0;
			sin6->__sin6_src_id = ip_srcid_find_addr(&v6dst,
			    IPCL_ZONEID(connp), us->us_netstack);
		} else {
			ip6h = (ip6_t *)rptr;

			sin6->sin6_addr = ip6h->ip6_src;
			/* No sin6_flowinfo per API */
			sin6->sin6_flowinfo = 0;
			/* For link-scope pass up scope id */
			if (IN6_IS_ADDR_LINKSCOPE(&ip6h->ip6_src))
				sin6->sin6_scope_id = ira->ira_ruifindex;
			else
				sin6->sin6_scope_id = 0;
			sin6->__sin6_src_id = ip_srcid_find_addr(
			    &ip6h->ip6_dst, IPCL_ZONEID(connp),
			    us->us_netstack);
		}
		sin6->sin6_port = udpha->uha_src_port;
		sin6->sin6_family = connp->conn_family;

		if (udi_size != 0) {
			conn_recvancillary_add(connp, recv_ancillary, ira,
			    &ipps, (uchar_t *)&sin6[1], udi_size);
		}
	}

	/*
	 * DTrace this UDP input as udp:::receive (this is for IPv4, IPv6 and
	 * loopback traffic).
	 */
	DTRACE_UDP5(receive, mblk_t *, NULL, ip_xmit_attr_t *, connp->conn_ixa,
	    void_ip_t *, rptr, udp_t *, udp, udpha_t *, udpha);

	/* Walk past the headers unless IP_RECVHDR was set. */
	if (!udp->udp_rcvhdr) {
		mp->b_rptr = rptr + hdr_length;
		pkt_len -= hdr_length;
	}

	UDPS_BUMP_MIB(us, udpHCInDatagrams);
	udp_ulp_recv(connp, mp1, pkt_len, ira);
	return;

tossit:
	freemsg(mp);
	UDPS_BUMP_MIB(us, udpInErrors);
}

/*
 * This routine creates a T_UDERROR_IND message and passes it upstream.
 * The address and options are copied from the T_UNITDATA_REQ message
 * passed in mp.  This message is freed.
 */
static void
udp_ud_err(queue_t *q, mblk_t *mp, t_scalar_t err)
{
	struct T_unitdata_req *tudr;
	mblk_t	*mp1;
	uchar_t *destaddr;
	t_scalar_t destlen;
	uchar_t	*optaddr;
	t_scalar_t optlen;

	if ((mp->b_wptr < mp->b_rptr) ||
	    (MBLKL(mp)) < sizeof (struct T_unitdata_req)) {
		goto done;
	}
	tudr = (struct T_unitdata_req *)mp->b_rptr;
	destaddr = mp->b_rptr + tudr->DEST_offset;
	if (destaddr < mp->b_rptr || destaddr >= mp->b_wptr ||
	    destaddr + tudr->DEST_length < mp->b_rptr ||
	    destaddr + tudr->DEST_length > mp->b_wptr) {
		goto done;
	}
	optaddr = mp->b_rptr + tudr->OPT_offset;
	if (optaddr < mp->b_rptr || optaddr >= mp->b_wptr ||
	    optaddr + tudr->OPT_length < mp->b_rptr ||
	    optaddr + tudr->OPT_length > mp->b_wptr) {
		goto done;
	}
	destlen = tudr->DEST_length;
	optlen = tudr->OPT_length;

	mp1 = mi_tpi_uderror_ind((char *)destaddr, destlen,
	    (char *)optaddr, optlen, err);
	if (mp1 != NULL)
		qreply(q, mp1);

done:
	freemsg(mp);
}

/*
 * This routine removes a port number association from a stream.  It
 * is called by udp_wput to handle T_UNBIND_REQ messages.
 */
static void
udp_tpi_unbind(queue_t *q, mblk_t *mp)
{
	conn_t	*connp = Q_TO_CONN(q);
	int	error;

	error = udp_do_unbind(connp);
	if (error) {
		if (error < 0)
			udp_err_ack(q, mp, -error, 0);
		else
			udp_err_ack(q, mp, TSYSERR, error);
		return;
	}

	mp = mi_tpi_ok_ack_alloc(mp);
	ASSERT(mp != NULL);
	ASSERT(((struct T_ok_ack *)mp->b_rptr)->PRIM_type == T_OK_ACK);
	qreply(q, mp);
}

/*
 * Don't let port fall into the privileged range.
 * Since the extra privileged ports can be arbitrary we also
 * ensure that we exclude those from consideration.
 * us->us_epriv_ports is not sorted thus we loop over it until
 * there are no changes.
 */
static in_port_t
udp_update_next_port(udp_t *udp, in_port_t port, boolean_t random)
{
	int i, bump;
	in_port_t nextport;
	boolean_t restart = B_FALSE;
	udp_stack_t *us = udp->udp_us;

	if (random && udp_random_anon_port != 0) {
		(void) random_get_pseudo_bytes((uint8_t *)&port,
		    sizeof (in_port_t));
		/*
		 * Unless changed by a sys admin, the smallest anon port
		 * is 32768 and the largest anon port is 65535.  It is
		 * very likely (50%) for the random port to be smaller
		 * than the smallest anon port.  When that happens,
		 * add port % (anon port range) to the smallest anon
		 * port to get the random port.  It should fall into the
		 * valid anon port range.
		 */
		if ((port < us->us_smallest_anon_port) ||
		    (port > us->us_largest_anon_port)) {
			if (us->us_smallest_anon_port ==
			    us->us_largest_anon_port) {
				bump = 0;
			} else {
				bump = port % (us->us_largest_anon_port -
				    us->us_smallest_anon_port);
			}

			port = us->us_smallest_anon_port + bump;
		}
	}

retry:
	if (port < us->us_smallest_anon_port)
		port = us->us_smallest_anon_port;

	if (port > us->us_largest_anon_port) {
		port = us->us_smallest_anon_port;
		if (restart)
			return (0);
		restart = B_TRUE;
	}

	if (port < us->us_smallest_nonpriv_port)
		port = us->us_smallest_nonpriv_port;

	for (i = 0; i < us->us_num_epriv_ports; i++) {
		if (port == us->us_epriv_ports[i]) {
			port++;
			/*
			 * Make sure that the port is in the
			 * valid range.
			 */
			goto retry;
		}
	}

	if (is_system_labeled() &&
	    (nextport = tsol_next_port(crgetzone(udp->udp_connp->conn_cred),
	    port, IPPROTO_UDP, B_TRUE)) != 0) {
		port = nextport;
		goto retry;
	}

	return (port);
}

/*
 * Handle T_UNITDATA_REQ with options. Both IPv4 and IPv6
 * Either tudr_mp or msg is set. If tudr_mp we take ancillary data from
 * the TPI options, otherwise we take them from msg_control.
 * If both sin and sin6 is set it is a connected socket and we use conn_faddr.
 * Always consumes mp; never consumes tudr_mp.
 */
static int
udp_output_ancillary(conn_t *connp, sin_t *sin, sin6_t *sin6, mblk_t *mp,
    mblk_t *tudr_mp, struct nmsghdr *msg, cred_t *cr, pid_t pid)
{
	udp_t		*udp = connp->conn_udp;
	udp_stack_t	*us = udp->udp_us;
	int		error;
	ip_xmit_attr_t	*ixa;
	ip_pkt_t	*ipp;
	in6_addr_t	v6src;
	in6_addr_t	v6dst;
	in6_addr_t	v6nexthop;
	in_port_t	dstport;
	uint32_t	flowinfo;
	uint_t		srcid;
	int		is_absreq_failure = 0;
	conn_opt_arg_t	coas, *coa;

	ASSERT(tudr_mp != NULL || msg != NULL);

	/*
	 * Get ixa before checking state to handle a disconnect race.
	 *
	 * We need an exclusive copy of conn_ixa since the ancillary data
	 * options might modify it. That copy has no pointers hence we
	 * need to set them up once we've parsed the ancillary data.
	 */
	ixa = conn_get_ixa_exclusive(connp);
	if (ixa == NULL) {
		UDPS_BUMP_MIB(us, udpOutErrors);
		freemsg(mp);
		return (ENOMEM);
	}
	ASSERT(cr != NULL);
	ASSERT(!(ixa->ixa_free_flags & IXA_FREE_CRED));
	ixa->ixa_cred = cr;
	ixa->ixa_cpid = pid;
	if (is_system_labeled()) {
		/* We need to restart with a label based on the cred */
		ip_xmit_attr_restore_tsl(ixa, ixa->ixa_cred);
	}

	/* In case previous destination was multicast or multirt */
	ip_attr_newdst(ixa);

	/* Get a copy of conn_xmit_ipp since the options might change it */
	ipp = kmem_zalloc(sizeof (*ipp), KM_NOSLEEP);
	if (ipp == NULL) {
		ASSERT(!(ixa->ixa_free_flags & IXA_FREE_CRED));
		ixa->ixa_cred = connp->conn_cred;	/* Restore */
		ixa->ixa_cpid = connp->conn_cpid;
		ixa_refrele(ixa);
		UDPS_BUMP_MIB(us, udpOutErrors);
		freemsg(mp);
		return (ENOMEM);
	}
	mutex_enter(&connp->conn_lock);
	error = ip_pkt_copy(&connp->conn_xmit_ipp, ipp, KM_NOSLEEP);
	mutex_exit(&connp->conn_lock);
	if (error != 0) {
		UDPS_BUMP_MIB(us, udpOutErrors);
		freemsg(mp);
		goto done;
	}

	/*
	 * Parse the options and update ixa and ipp as a result.
	 * Note that ixa_tsl can be updated if SCM_UCRED.
	 * ixa_refrele/ixa_inactivate will release any reference on ixa_tsl.
	 */

	coa = &coas;
	coa->coa_connp = connp;
	coa->coa_ixa = ixa;
	coa->coa_ipp = ipp;
	coa->coa_ancillary = B_TRUE;
	coa->coa_changed = 0;

	if (msg != NULL) {
		error = process_auxiliary_options(connp, msg->msg_control,
		    msg->msg_controllen, coa, &udp_opt_obj, udp_opt_set, cr);
	} else {
		struct T_unitdata_req *tudr;

		tudr = (struct T_unitdata_req *)tudr_mp->b_rptr;
		ASSERT(tudr->PRIM_type == T_UNITDATA_REQ);
		error = tpi_optcom_buf(connp->conn_wq, tudr_mp,
		    &tudr->OPT_length, tudr->OPT_offset, cr, &udp_opt_obj,
		    coa, &is_absreq_failure);
	}
	if (error != 0) {
		/*
		 * Note: No special action needed in this
		 * module for "is_absreq_failure"
		 */
		freemsg(mp);
		UDPS_BUMP_MIB(us, udpOutErrors);
		goto done;
	}
	ASSERT(is_absreq_failure == 0);

	mutex_enter(&connp->conn_lock);
	/*
	 * If laddr is unspecified then we look at sin6_src_id.
	 * We will give precedence to a source address set with IPV6_PKTINFO
	 * (aka IPPF_ADDR) but that is handled in build_hdrs. However, we don't
	 * want ip_attr_connect to select a source (since it can fail) when
	 * IPV6_PKTINFO is specified.
	 * If this doesn't result in a source address then we get a source
	 * from ip_attr_connect() below.
	 */
	v6src = connp->conn_saddr_v6;
	if (sin != NULL) {
		IN6_IPADDR_TO_V4MAPPED(sin->sin_addr.s_addr, &v6dst);
		dstport = sin->sin_port;
		flowinfo = 0;
		ixa->ixa_flags &= ~IXAF_SCOPEID_SET;
		ixa->ixa_flags |= IXAF_IS_IPV4;
	} else if (sin6 != NULL) {
		boolean_t v4mapped;

		v6dst = sin6->sin6_addr;
		dstport = sin6->sin6_port;
		flowinfo = sin6->sin6_flowinfo;
		srcid = sin6->__sin6_src_id;
		if (IN6_IS_ADDR_LINKSCOPE(&v6dst) && sin6->sin6_scope_id != 0) {
			ixa->ixa_scopeid = sin6->sin6_scope_id;
			ixa->ixa_flags |= IXAF_SCOPEID_SET;
		} else {
			ixa->ixa_flags &= ~IXAF_SCOPEID_SET;
		}
		v4mapped = IN6_IS_ADDR_V4MAPPED(&v6dst);
		if (v4mapped)
			ixa->ixa_flags |= IXAF_IS_IPV4;
		else
			ixa->ixa_flags &= ~IXAF_IS_IPV4;
		if (srcid != 0 && IN6_IS_ADDR_UNSPECIFIED(&v6src)) {
			if (!ip_srcid_find_id(srcid, &v6src, IPCL_ZONEID(connp),
			    v4mapped, connp->conn_netstack)) {
				/* Mismatch - v4mapped/v6 specified by srcid. */
				mutex_exit(&connp->conn_lock);
				error = EADDRNOTAVAIL;
				goto failed;	/* Does freemsg() and mib. */
			}
		}
	} else {
		/* Connected case */
		v6dst = connp->conn_faddr_v6;
		dstport = connp->conn_fport;
		flowinfo = connp->conn_flowinfo;
	}
	mutex_exit(&connp->conn_lock);

	/* Handle IP_PKTINFO/IPV6_PKTINFO setting source address. */
	if (ipp->ipp_fields & IPPF_ADDR) {
		if (ixa->ixa_flags & IXAF_IS_IPV4) {
			if (IN6_IS_ADDR_V4MAPPED(&ipp->ipp_addr))
				v6src = ipp->ipp_addr;
		} else {
			if (!IN6_IS_ADDR_V4MAPPED(&ipp->ipp_addr))
				v6src = ipp->ipp_addr;
		}
	}

	ip_attr_nexthop(ipp, ixa, &v6dst, &v6nexthop);
	error = ip_attr_connect(connp, ixa, &v6src, &v6dst, &v6nexthop, dstport,
	    &v6src, NULL, IPDF_ALLOW_MCBC | IPDF_VERIFY_DST | IPDF_IPSEC);

	switch (error) {
	case 0:
		break;
	case EADDRNOTAVAIL:
		/*
		 * IXAF_VERIFY_SOURCE tells us to pick a better source.
		 * Don't have the application see that errno
		 */
		error = ENETUNREACH;
		goto failed;
	case ENETDOWN:
		/*
		 * Have !ipif_addr_ready address; drop packet silently
		 * until we can get applications to not send until we
		 * are ready.
		 */
		error = 0;
		goto failed;
	case EHOSTUNREACH:
	case ENETUNREACH:
		if (ixa->ixa_ire != NULL) {
			/*
			 * Let conn_ip_output/ire_send_noroute return
			 * the error and send any local ICMP error.
			 */
			error = 0;
			break;
		}
		/* FALLTHRU */
	default:
	failed:
		freemsg(mp);
		UDPS_BUMP_MIB(us, udpOutErrors);
		goto done;
	}

	/*
	 * We might be going to a different destination than last time,
	 * thus check that TX allows the communication and compute any
	 * needed label.
	 *
	 * TSOL Note: We have an exclusive ipp and ixa for this thread so we
	 * don't have to worry about concurrent threads.
	 */
	if (is_system_labeled()) {
		/* Using UDP MLP requires SCM_UCRED from user */
		if (connp->conn_mlp_type != mlptSingle &&
		    !((ixa->ixa_flags & IXAF_UCRED_TSL))) {
			UDPS_BUMP_MIB(us, udpOutErrors);
			error = ECONNREFUSED;
			freemsg(mp);
			goto done;
		}
		/*
		 * Check whether Trusted Solaris policy allows communication
		 * with this host, and pretend that the destination is
		 * unreachable if not.
		 * Compute any needed label and place it in ipp_label_v4/v6.
		 *
		 * Later conn_build_hdr_template/conn_prepend_hdr takes
		 * ipp_label_v4/v6 to form the packet.
		 *
		 * Tsol note: We have ipp structure local to this thread so
		 * no locking is needed.
		 */
		error = conn_update_label(connp, ixa, &v6dst, ipp);
		if (error != 0) {
			freemsg(mp);
			UDPS_BUMP_MIB(us, udpOutErrors);
			goto done;
		}
	}
	mp = udp_prepend_hdr(connp, ixa, ipp, &v6src, &v6dst, dstport,
	    flowinfo, mp, &error);
	if (mp == NULL) {
		ASSERT(error != 0);
		UDPS_BUMP_MIB(us, udpOutErrors);
		goto done;
	}
	if (ixa->ixa_pktlen > IP_MAXPACKET) {
		error = EMSGSIZE;
		UDPS_BUMP_MIB(us, udpOutErrors);
		freemsg(mp);
		goto done;
	}
	/* We're done.  Pass the packet to ip. */
	UDPS_BUMP_MIB(us, udpHCOutDatagrams);

	DTRACE_UDP5(send, mblk_t *, NULL, ip_xmit_attr_t *, ixa,
	    void_ip_t *, mp->b_rptr, udp_t *, udp, udpha_t *,
	    &mp->b_rptr[ixa->ixa_ip_hdr_length]);

	error = conn_ip_output(mp, ixa);
	/* No udpOutErrors if an error since IP increases its error counter */
	switch (error) {
	case 0:
		break;
	case EWOULDBLOCK:
		(void) ixa_check_drain_insert(connp, ixa);
		error = 0;
		break;
	case EADDRNOTAVAIL:
		/*
		 * IXAF_VERIFY_SOURCE tells us to pick a better source.
		 * Don't have the application see that errno
		 */
		error = ENETUNREACH;
		/* FALLTHRU */
	default:
		mutex_enter(&connp->conn_lock);
		/*
		 * Clear the source and v6lastdst so we call ip_attr_connect
		 * for the next packet and try to pick a better source.
		 */
		if (connp->conn_mcbc_bind)
			connp->conn_saddr_v6 = ipv6_all_zeros;
		else
			connp->conn_saddr_v6 = connp->conn_bound_addr_v6;
		connp->conn_v6lastdst = ipv6_all_zeros;
		mutex_exit(&connp->conn_lock);
		break;
	}
done:
	ASSERT(!(ixa->ixa_free_flags & IXA_FREE_CRED));
	ixa->ixa_cred = connp->conn_cred;	/* Restore */
	ixa->ixa_cpid = connp->conn_cpid;
	ixa_refrele(ixa);
	ip_pkt_free(ipp);
	kmem_free(ipp, sizeof (*ipp));
	return (error);
}

/*
 * Handle sending an M_DATA for a connected socket.
 * Handles both IPv4 and IPv6.
 */
static int
udp_output_connected(conn_t *connp, mblk_t *mp, cred_t *cr, pid_t pid)
{
	udp_t		*udp = connp->conn_udp;
	udp_stack_t	*us = udp->udp_us;
	int		error;
	ip_xmit_attr_t	*ixa;

	/*
	 * If no other thread is using conn_ixa this just gets a reference to
	 * conn_ixa. Otherwise we get a safe copy of conn_ixa.
	 */
	ixa = conn_get_ixa(connp, B_FALSE);
	if (ixa == NULL) {
		UDPS_BUMP_MIB(us, udpOutErrors);
		freemsg(mp);
		return (ENOMEM);
	}

	ASSERT(cr != NULL);
	ASSERT(!(ixa->ixa_free_flags & IXA_FREE_CRED));
	ixa->ixa_cred = cr;
	ixa->ixa_cpid = pid;

	mutex_enter(&connp->conn_lock);
	mp = udp_prepend_header_template(connp, ixa, mp, &connp->conn_saddr_v6,
	    connp->conn_fport, connp->conn_flowinfo, &error);

	if (mp == NULL) {
		ASSERT(error != 0);
		mutex_exit(&connp->conn_lock);
		ASSERT(!(ixa->ixa_free_flags & IXA_FREE_CRED));
		ixa->ixa_cred = connp->conn_cred;	/* Restore */
		ixa->ixa_cpid = connp->conn_cpid;
		ixa_refrele(ixa);
		UDPS_BUMP_MIB(us, udpOutErrors);
		freemsg(mp);
		return (error);
	}

	/*
	 * In case we got a safe copy of conn_ixa, or if opt_set made us a new
	 * safe copy, then we need to fill in any pointers in it.
	 */
	if (ixa->ixa_ire == NULL) {
		in6_addr_t	faddr, saddr;
		in6_addr_t	nexthop;
		in_port_t	fport;

		saddr = connp->conn_saddr_v6;
		faddr = connp->conn_faddr_v6;
		fport = connp->conn_fport;
		ip_attr_nexthop(&connp->conn_xmit_ipp, ixa, &faddr, &nexthop);
		mutex_exit(&connp->conn_lock);

		error = ip_attr_connect(connp, ixa, &saddr, &faddr, &nexthop,
		    fport, NULL, NULL, IPDF_ALLOW_MCBC | IPDF_VERIFY_DST |
		    IPDF_IPSEC);
		switch (error) {
		case 0:
			break;
		case EADDRNOTAVAIL:
			/*
			 * IXAF_VERIFY_SOURCE tells us to pick a better source.
			 * Don't have the application see that errno
			 */
			error = ENETUNREACH;
			goto failed;
		case ENETDOWN:
			/*
			 * Have !ipif_addr_ready address; drop packet silently
			 * until we can get applications to not send until we
			 * are ready.
			 */
			error = 0;
			goto failed;
		case EHOSTUNREACH:
		case ENETUNREACH:
			if (ixa->ixa_ire != NULL) {
				/*
				 * Let conn_ip_output/ire_send_noroute return
				 * the error and send any local ICMP error.
				 */
				error = 0;
				break;
			}
			/* FALLTHRU */
		default:
		failed:
			ASSERT(!(ixa->ixa_free_flags & IXA_FREE_CRED));
			ixa->ixa_cred = connp->conn_cred;	/* Restore */
			ixa->ixa_cpid = connp->conn_cpid;
			ixa_refrele(ixa);
			freemsg(mp);
			UDPS_BUMP_MIB(us, udpOutErrors);
			return (error);
		}
	} else {
		/* Done with conn_t */
		mutex_exit(&connp->conn_lock);
	}
	ASSERT(ixa->ixa_ire != NULL);

	/* We're done.  Pass the packet to ip. */
	UDPS_BUMP_MIB(us, udpHCOutDatagrams);

	DTRACE_UDP5(send, mblk_t *, NULL, ip_xmit_attr_t *, ixa,
	    void_ip_t *, mp->b_rptr, udp_t *, udp, udpha_t *,
	    &mp->b_rptr[ixa->ixa_ip_hdr_length]);

	error = conn_ip_output(mp, ixa);
	/* No udpOutErrors if an error since IP increases its error counter */
	switch (error) {
	case 0:
		break;
	case EWOULDBLOCK:
		(void) ixa_check_drain_insert(connp, ixa);
		error = 0;
		break;
	case EADDRNOTAVAIL:
		/*
		 * IXAF_VERIFY_SOURCE tells us to pick a better source.
		 * Don't have the application see that errno
		 */
		error = ENETUNREACH;
		break;
	}
	ASSERT(!(ixa->ixa_free_flags & IXA_FREE_CRED));
	ixa->ixa_cred = connp->conn_cred;	/* Restore */
	ixa->ixa_cpid = connp->conn_cpid;
	ixa_refrele(ixa);
	return (error);
}

/*
 * Handle sending an M_DATA to the last destination.
 * Handles both IPv4 and IPv6.
 *
 * NOTE: The caller must hold conn_lock and we drop it here.
 */
static int
udp_output_lastdst(conn_t *connp, mblk_t *mp, cred_t *cr, pid_t pid,
    ip_xmit_attr_t *ixa)
{
	udp_t		*udp = connp->conn_udp;
	udp_stack_t	*us = udp->udp_us;
	int		error;

	ASSERT(MUTEX_HELD(&connp->conn_lock));
	ASSERT(ixa != NULL);

	ASSERT(cr != NULL);
	ASSERT(!(ixa->ixa_free_flags & IXA_FREE_CRED));
	ixa->ixa_cred = cr;
	ixa->ixa_cpid = pid;

	mp = udp_prepend_header_template(connp, ixa, mp, &connp->conn_v6lastsrc,
	    connp->conn_lastdstport, connp->conn_lastflowinfo, &error);

	if (mp == NULL) {
		ASSERT(error != 0);
		mutex_exit(&connp->conn_lock);
		ASSERT(!(ixa->ixa_free_flags & IXA_FREE_CRED));
		ixa->ixa_cred = connp->conn_cred;	/* Restore */
		ixa->ixa_cpid = connp->conn_cpid;
		ixa_refrele(ixa);
		UDPS_BUMP_MIB(us, udpOutErrors);
		freemsg(mp);
		return (error);
	}

	/*
	 * In case we got a safe copy of conn_ixa, or if opt_set made us a new
	 * safe copy, then we need to fill in any pointers in it.
	 */
	if (ixa->ixa_ire == NULL) {
		in6_addr_t	lastdst, lastsrc;
		in6_addr_t	nexthop;
		in_port_t	lastport;

		lastsrc = connp->conn_v6lastsrc;
		lastdst = connp->conn_v6lastdst;
		lastport = connp->conn_lastdstport;
		ip_attr_nexthop(&connp->conn_xmit_ipp, ixa, &lastdst, &nexthop);
		mutex_exit(&connp->conn_lock);

		error = ip_attr_connect(connp, ixa, &lastsrc, &lastdst,
		    &nexthop, lastport, NULL, NULL, IPDF_ALLOW_MCBC |
		    IPDF_VERIFY_DST | IPDF_IPSEC);
		switch (error) {
		case 0:
			break;
		case EADDRNOTAVAIL:
			/*
			 * IXAF_VERIFY_SOURCE tells us to pick a better source.
			 * Don't have the application see that errno
			 */
			error = ENETUNREACH;
			goto failed;
		case ENETDOWN:
			/*
			 * Have !ipif_addr_ready address; drop packet silently
			 * until we can get applications to not send until we
			 * are ready.
			 */
			error = 0;
			goto failed;
		case EHOSTUNREACH:
		case ENETUNREACH:
			if (ixa->ixa_ire != NULL) {
				/*
				 * Let conn_ip_output/ire_send_noroute return
				 * the error and send any local ICMP error.
				 */
				error = 0;
				break;
			}
			/* FALLTHRU */
		default:
		failed:
			ASSERT(!(ixa->ixa_free_flags & IXA_FREE_CRED));
			ixa->ixa_cred = connp->conn_cred;	/* Restore */
			ixa->ixa_cpid = connp->conn_cpid;
			ixa_refrele(ixa);
			freemsg(mp);
			UDPS_BUMP_MIB(us, udpOutErrors);
			return (error);
		}
	} else {
		/* Done with conn_t */
		mutex_exit(&connp->conn_lock);
	}

	/* We're done.  Pass the packet to ip. */
	UDPS_BUMP_MIB(us, udpHCOutDatagrams);

	DTRACE_UDP5(send, mblk_t *, NULL, ip_xmit_attr_t *, ixa,
	    void_ip_t *, mp->b_rptr, udp_t *, udp, udpha_t *,
	    &mp->b_rptr[ixa->ixa_ip_hdr_length]);

	error = conn_ip_output(mp, ixa);
	/* No udpOutErrors if an error since IP increases its error counter */
	switch (error) {
	case 0:
		break;
	case EWOULDBLOCK:
		(void) ixa_check_drain_insert(connp, ixa);
		error = 0;
		break;
	case EADDRNOTAVAIL:
		/*
		 * IXAF_VERIFY_SOURCE tells us to pick a better source.
		 * Don't have the application see that errno
		 */
		error = ENETUNREACH;
		/* FALLTHRU */
	default:
		mutex_enter(&connp->conn_lock);
		/*
		 * Clear the source and v6lastdst so we call ip_attr_connect
		 * for the next packet and try to pick a better source.
		 */
		if (connp->conn_mcbc_bind)
			connp->conn_saddr_v6 = ipv6_all_zeros;
		else
			connp->conn_saddr_v6 = connp->conn_bound_addr_v6;
		connp->conn_v6lastdst = ipv6_all_zeros;
		mutex_exit(&connp->conn_lock);
		break;
	}
	ASSERT(!(ixa->ixa_free_flags & IXA_FREE_CRED));
	ixa->ixa_cred = connp->conn_cred;	/* Restore */
	ixa->ixa_cpid = connp->conn_cpid;
	ixa_refrele(ixa);
	return (error);
}


/*
 * Prepend the header template and then fill in the source and
 * flowinfo. The caller needs to handle the destination address since
 * it's setting is different if rthdr or source route.
 *
 * Returns NULL is allocation failed or if the packet would exceed IP_MAXPACKET.
 * When it returns NULL it sets errorp.
 */
static mblk_t *
udp_prepend_header_template(conn_t *connp, ip_xmit_attr_t *ixa, mblk_t *mp,
    const in6_addr_t *v6src, in_port_t dstport, uint32_t flowinfo, int *errorp)
{
	udp_t		*udp = connp->conn_udp;
	udp_stack_t	*us = udp->udp_us;
	boolean_t	insert_spi = udp->udp_nat_t_endpoint;
	uint_t		pktlen;
	uint_t		alloclen;
	uint_t		copylen;
	uint8_t		*iph;
	uint_t		ip_hdr_length;
	udpha_t		*udpha;
	uint32_t	cksum;
	ip_pkt_t	*ipp;

	ASSERT(MUTEX_HELD(&connp->conn_lock));

	/*
	 * Copy the header template and leave space for an SPI
	 */
	copylen = connp->conn_ht_iphc_len;
	alloclen = copylen + (insert_spi ? sizeof (uint32_t) : 0);
	pktlen = alloclen + msgdsize(mp);
	if (pktlen > IP_MAXPACKET) {
		freemsg(mp);
		*errorp = EMSGSIZE;
		return (NULL);
	}
	ixa->ixa_pktlen = pktlen;

	/* check/fix buffer config, setup pointers into it */
	iph = mp->b_rptr - alloclen;
	if (DB_REF(mp) != 1 || iph < DB_BASE(mp) || !OK_32PTR(iph)) {
		mblk_t *mp1;

		mp1 = allocb(alloclen + us->us_wroff_extra, BPRI_MED);
		if (mp1 == NULL) {
			freemsg(mp);
			*errorp = ENOMEM;
			return (NULL);
		}
		mp1->b_wptr = DB_LIM(mp1);
		mp1->b_cont = mp;
		mp = mp1;
		iph = (mp->b_wptr - alloclen);
	}
	mp->b_rptr = iph;
	bcopy(connp->conn_ht_iphc, iph, copylen);
	ip_hdr_length = (uint_t)(connp->conn_ht_ulp - connp->conn_ht_iphc);

	ixa->ixa_ip_hdr_length = ip_hdr_length;
	udpha = (udpha_t *)(iph + ip_hdr_length);

	/*
	 * Setup header length and prepare for ULP checksum done in IP.
	 * udp_build_hdr_template has already massaged any routing header
	 * and placed the result in conn_sum.
	 *
	 * We make it easy for IP to include our pseudo header
	 * by putting our length in uha_checksum.
	 */
	cksum = pktlen - ip_hdr_length;
	udpha->uha_length = htons(cksum);

	cksum += connp->conn_sum;
	cksum = (cksum >> 16) + (cksum & 0xFFFF);
	ASSERT(cksum < 0x10000);

	ipp = &connp->conn_xmit_ipp;
	if (ixa->ixa_flags & IXAF_IS_IPV4) {
		ipha_t	*ipha = (ipha_t *)iph;

		ipha->ipha_length = htons((uint16_t)pktlen);

		/* IP does the checksum if uha_checksum is non-zero */
		if (us->us_do_checksum)
			udpha->uha_checksum = htons(cksum);

		/* if IP_PKTINFO specified an addres it wins over bind() */
		if ((ipp->ipp_fields & IPPF_ADDR) &&
		    IN6_IS_ADDR_V4MAPPED(&ipp->ipp_addr)) {
			ASSERT(ipp->ipp_addr_v4 != INADDR_ANY);
			ipha->ipha_src = ipp->ipp_addr_v4;
		} else {
			IN6_V4MAPPED_TO_IPADDR(v6src, ipha->ipha_src);
		}
	} else {
		ip6_t *ip6h = (ip6_t *)iph;

		ip6h->ip6_plen =  htons((uint16_t)(pktlen - IPV6_HDR_LEN));
		udpha->uha_checksum = htons(cksum);

		/* if IP_PKTINFO specified an addres it wins over bind() */
		if ((ipp->ipp_fields & IPPF_ADDR) &&
		    !IN6_IS_ADDR_V4MAPPED(&ipp->ipp_addr)) {
			ASSERT(!IN6_IS_ADDR_UNSPECIFIED(&ipp->ipp_addr));
			ip6h->ip6_src = ipp->ipp_addr;
		} else {
			ip6h->ip6_src = *v6src;
		}
		ip6h->ip6_vcf =
		    (IPV6_DEFAULT_VERS_AND_FLOW & IPV6_VERS_AND_FLOW_MASK) |
		    (flowinfo & ~IPV6_VERS_AND_FLOW_MASK);
		if (ipp->ipp_fields & IPPF_TCLASS) {
			/* Overrides the class part of flowinfo */
			ip6h->ip6_vcf = IPV6_TCLASS_FLOW(ip6h->ip6_vcf,
			    ipp->ipp_tclass);
		}
	}

	/* Insert all-0s SPI now. */
	if (insert_spi)
		*((uint32_t *)(udpha + 1)) = 0;

	udpha->uha_dst_port = dstport;
	return (mp);
}

/*
 * Send a T_UDERR_IND in response to an M_DATA
 */
static void
udp_ud_err_connected(conn_t *connp, t_scalar_t error)
{
	struct sockaddr_storage ss;
	sin_t		*sin;
	sin6_t		*sin6;
	struct sockaddr	*addr;
	socklen_t	addrlen;
	mblk_t		*mp1;

	mutex_enter(&connp->conn_lock);
	/* Initialize addr and addrlen as if they're passed in */
	if (connp->conn_family == AF_INET) {
		sin = (sin_t *)&ss;
		*sin = sin_null;
		sin->sin_family = AF_INET;
		sin->sin_port = connp->conn_fport;
		sin->sin_addr.s_addr = connp->conn_faddr_v4;
		addr = (struct sockaddr *)sin;
		addrlen = sizeof (*sin);
	} else {
		sin6 = (sin6_t *)&ss;
		*sin6 = sin6_null;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_port = connp->conn_fport;
		sin6->sin6_flowinfo = connp->conn_flowinfo;
		sin6->sin6_addr = connp->conn_faddr_v6;
		if (IN6_IS_ADDR_LINKSCOPE(&connp->conn_faddr_v6) &&
		    (connp->conn_ixa->ixa_flags & IXAF_SCOPEID_SET)) {
			sin6->sin6_scope_id = connp->conn_ixa->ixa_scopeid;
		} else {
			sin6->sin6_scope_id = 0;
		}
		sin6->__sin6_src_id = 0;
		addr = (struct sockaddr *)sin6;
		addrlen = sizeof (*sin6);
	}
	mutex_exit(&connp->conn_lock);

	mp1 = mi_tpi_uderror_ind((char *)addr, addrlen, NULL, 0, error);
	if (mp1 != NULL)
		putnext(connp->conn_rq, mp1);
}

/*
 * This routine handles all messages passed downstream.  It either
 * consumes the message or passes it downstream; it never queues a
 * a message.
 *
 * Also entry point for sockfs when udp is in "direct sockfs" mode.  This mode
 * is valid when we are directly beneath the stream head, and thus sockfs
 * is able to bypass STREAMS and directly call us, passing along the sockaddr
 * structure without the cumbersome T_UNITDATA_REQ interface for the case of
 * connected endpoints.
 */
void
udp_wput(queue_t *q, mblk_t *mp)
{
	sin6_t		*sin6;
	sin_t		*sin = NULL;
	uint_t		srcid;
	conn_t		*connp = Q_TO_CONN(q);
	udp_t		*udp = connp->conn_udp;
	int		error = 0;
	struct sockaddr	*addr = NULL;
	socklen_t	addrlen;
	udp_stack_t	*us = udp->udp_us;
	struct T_unitdata_req *tudr;
	mblk_t		*data_mp;
	ushort_t	ipversion;
	cred_t		*cr;
	pid_t		pid;

	/*
	 * We directly handle several cases here: T_UNITDATA_REQ message
	 * coming down as M_PROTO/M_PCPROTO and M_DATA messages for connected
	 * socket.
	 */
	switch (DB_TYPE(mp)) {
	case M_DATA:
		if (!udp->udp_issocket || udp->udp_state != TS_DATA_XFER) {
			/* Not connected; address is required */
			UDPS_BUMP_MIB(us, udpOutErrors);
			UDP_DBGSTAT(us, udp_data_notconn);
			UDP_STAT(us, udp_out_err_notconn);
			freemsg(mp);
			return;
		}
		/*
		 * All Solaris components should pass a db_credp
		 * for this message, hence we ASSERT.
		 * On production kernels we return an error to be robust against
		 * random streams modules sitting on top of us.
		 */
		cr = msg_getcred(mp, &pid);
		ASSERT(cr != NULL);
		if (cr == NULL) {
			UDPS_BUMP_MIB(us, udpOutErrors);
			freemsg(mp);
			return;
		}
		ASSERT(udp->udp_issocket);
		UDP_DBGSTAT(us, udp_data_conn);
		error = udp_output_connected(connp, mp, cr, pid);
		if (error != 0) {
			UDP_STAT(us, udp_out_err_output);
			if (connp->conn_rq != NULL)
				udp_ud_err_connected(connp, (t_scalar_t)error);
#ifdef DEBUG
			printf("udp_output_connected returned %d\n", error);
#endif
		}
		return;

	case M_PROTO:
	case M_PCPROTO:
		tudr = (struct T_unitdata_req *)mp->b_rptr;
		if (MBLKL(mp) < sizeof (*tudr) ||
		    ((t_primp_t)mp->b_rptr)->type != T_UNITDATA_REQ) {
			udp_wput_other(q, mp);
			return;
		}
		break;

	default:
		udp_wput_other(q, mp);
		return;
	}

	/* Handle valid T_UNITDATA_REQ here */
	data_mp = mp->b_cont;
	if (data_mp == NULL) {
		error = EPROTO;
		goto ud_error2;
	}
	mp->b_cont = NULL;

	if (!MBLKIN(mp, 0, tudr->DEST_offset + tudr->DEST_length)) {
		error = EADDRNOTAVAIL;
		goto ud_error2;
	}

	/*
	 * All Solaris components should pass a db_credp
	 * for this TPI message, hence we should ASSERT.
	 * However, RPC (svc_clts_ksend) does this odd thing where it
	 * passes the options from a T_UNITDATA_IND unchanged in a
	 * T_UNITDATA_REQ. While that is the right thing to do for
	 * some options, SCM_UCRED being the key one, this also makes it
	 * pass down IP_RECVDSTADDR. Hence we can't ASSERT here.
	 */
	cr = msg_getcred(mp, &pid);
	if (cr == NULL) {
		cr = connp->conn_cred;
		pid = connp->conn_cpid;
	}

	/*
	 * If a port has not been bound to the stream, fail.
	 * This is not a problem when sockfs is directly
	 * above us, because it will ensure that the socket
	 * is first bound before allowing data to be sent.
	 */
	if (udp->udp_state == TS_UNBND) {
		error = EPROTO;
		goto ud_error2;
	}
	addr = (struct sockaddr *)&mp->b_rptr[tudr->DEST_offset];
	addrlen = tudr->DEST_length;

	switch (connp->conn_family) {
	case AF_INET6:
		sin6 = (sin6_t *)addr;
		if (!OK_32PTR((char *)sin6) || (addrlen != sizeof (sin6_t)) ||
		    (sin6->sin6_family != AF_INET6)) {
			error = EADDRNOTAVAIL;
			goto ud_error2;
		}

		srcid = sin6->__sin6_src_id;
		if (!IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
			/*
			 * Destination is a non-IPv4-compatible IPv6 address.
			 * Send out an IPv6 format packet.
			 */

			/*
			 * If the local address is a mapped address return
			 * an error.
			 * It would be possible to send an IPv6 packet but the
			 * response would never make it back to the application
			 * since it is bound to a mapped address.
			 */
			if (IN6_IS_ADDR_V4MAPPED(&connp->conn_saddr_v6)) {
				error = EADDRNOTAVAIL;
				goto ud_error2;
			}

			UDP_DBGSTAT(us, udp_out_ipv6);

			if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr))
				sin6->sin6_addr = ipv6_loopback;
			ipversion = IPV6_VERSION;
		} else {
			if (connp->conn_ipv6_v6only) {
				error = EADDRNOTAVAIL;
				goto ud_error2;
			}

			/*
			 * If the local address is not zero or a mapped address
			 * return an error.  It would be possible to send an
			 * IPv4 packet but the response would never make it
			 * back to the application since it is bound to a
			 * non-mapped address.
			 */
			if (!IN6_IS_ADDR_V4MAPPED(&connp->conn_saddr_v6) &&
			    !IN6_IS_ADDR_UNSPECIFIED(&connp->conn_saddr_v6)) {
				error = EADDRNOTAVAIL;
				goto ud_error2;
			}
			UDP_DBGSTAT(us, udp_out_mapped);

			if (V4_PART_OF_V6(sin6->sin6_addr) == INADDR_ANY) {
				V4_PART_OF_V6(sin6->sin6_addr) =
				    htonl(INADDR_LOOPBACK);
			}
			ipversion = IPV4_VERSION;
		}

		if (tudr->OPT_length != 0) {
			/*
			 * If we are connected then the destination needs to be
			 * the same as the connected one.
			 */
			if (udp->udp_state == TS_DATA_XFER &&
			    !conn_same_as_last_v6(connp, sin6)) {
				error = EISCONN;
				goto ud_error2;
			}
			UDP_STAT(us, udp_out_opt);
			error = udp_output_ancillary(connp, NULL, sin6,
			    data_mp, mp, NULL, cr, pid);
		} else {
			ip_xmit_attr_t *ixa;

			/*
			 * We have to allocate an ip_xmit_attr_t before we grab
			 * conn_lock and we need to hold conn_lock once we've
			 * checked conn_same_as_last_v6 to handle concurrent
			 * send* calls on a socket.
			 */
			ixa = conn_get_ixa(connp, B_FALSE);
			if (ixa == NULL) {
				error = ENOMEM;
				goto ud_error2;
			}
			mutex_enter(&connp->conn_lock);

			if (conn_same_as_last_v6(connp, sin6) &&
			    connp->conn_lastsrcid == srcid &&
			    ipsec_outbound_policy_current(ixa)) {
				UDP_DBGSTAT(us, udp_out_lastdst);
				/* udp_output_lastdst drops conn_lock */
				error = udp_output_lastdst(connp, data_mp, cr,
				    pid, ixa);
			} else {
				UDP_DBGSTAT(us, udp_out_diffdst);
				/* udp_output_newdst drops conn_lock */
				error = udp_output_newdst(connp, data_mp, NULL,
				    sin6, ipversion, cr, pid, ixa);
			}
			ASSERT(MUTEX_NOT_HELD(&connp->conn_lock));
		}
		if (error == 0) {
			freeb(mp);
			return;
		}
		break;

	case AF_INET:
		sin = (sin_t *)addr;
		if ((!OK_32PTR((char *)sin) || addrlen != sizeof (sin_t)) ||
		    (sin->sin_family != AF_INET)) {
			error = EADDRNOTAVAIL;
			goto ud_error2;
		}
		UDP_DBGSTAT(us, udp_out_ipv4);
		if (sin->sin_addr.s_addr == INADDR_ANY)
			sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
		ipversion = IPV4_VERSION;

		srcid = 0;
		if (tudr->OPT_length != 0) {
			/*
			 * If we are connected then the destination needs to be
			 * the same as the connected one.
			 */
			if (udp->udp_state == TS_DATA_XFER &&
			    !conn_same_as_last_v4(connp, sin)) {
				error = EISCONN;
				goto ud_error2;
			}
			UDP_STAT(us, udp_out_opt);
			error = udp_output_ancillary(connp, sin, NULL,
			    data_mp, mp, NULL, cr, pid);
		} else {
			ip_xmit_attr_t *ixa;

			/*
			 * We have to allocate an ip_xmit_attr_t before we grab
			 * conn_lock and we need to hold conn_lock once we've
			 * checked conn_same_as_last_v4 to handle concurrent
			 * send* calls on a socket.
			 */
			ixa = conn_get_ixa(connp, B_FALSE);
			if (ixa == NULL) {
				error = ENOMEM;
				goto ud_error2;
			}
			mutex_enter(&connp->conn_lock);

			if (conn_same_as_last_v4(connp, sin) &&
			    ipsec_outbound_policy_current(ixa)) {
				UDP_DBGSTAT(us, udp_out_lastdst);
				/* udp_output_lastdst drops conn_lock */
				error = udp_output_lastdst(connp, data_mp, cr,
				    pid, ixa);
			} else {
				UDP_DBGSTAT(us, udp_out_diffdst);
				/* udp_output_newdst drops conn_lock */
				error = udp_output_newdst(connp, data_mp, sin,
				    NULL, ipversion, cr, pid, ixa);
			}
			ASSERT(MUTEX_NOT_HELD(&connp->conn_lock));
		}
		if (error == 0) {
			freeb(mp);
			return;
		}
		break;
	}
	UDP_STAT(us, udp_out_err_output);
	ASSERT(mp != NULL);
	/* mp is freed by the following routine */
	udp_ud_err(q, mp, (t_scalar_t)error);
	return;

ud_error2:
	UDPS_BUMP_MIB(us, udpOutErrors);
	freemsg(data_mp);
	UDP_STAT(us, udp_out_err_output);
	ASSERT(mp != NULL);
	/* mp is freed by the following routine */
	udp_ud_err(q, mp, (t_scalar_t)error);
}

/*
 * Handle the case of the IP address, port, flow label being different
 * for both IPv4 and IPv6.
 *
 * NOTE: The caller must hold conn_lock and we drop it here.
 */
static int
udp_output_newdst(conn_t *connp, mblk_t *data_mp, sin_t *sin, sin6_t *sin6,
    ushort_t ipversion, cred_t *cr, pid_t pid, ip_xmit_attr_t *ixa)
{
	uint_t		srcid;
	uint32_t	flowinfo;
	udp_t		*udp = connp->conn_udp;
	int		error = 0;
	ip_xmit_attr_t	*oldixa;
	udp_stack_t	*us = udp->udp_us;
	in6_addr_t	v6src;
	in6_addr_t	v6dst;
	in6_addr_t	v6nexthop;
	in_port_t	dstport;

	ASSERT(MUTEX_HELD(&connp->conn_lock));
	ASSERT(ixa != NULL);
	/*
	 * We hold conn_lock across all the use and modifications of
	 * the conn_lastdst, conn_ixa, and conn_xmit_ipp to ensure that they
	 * stay consistent.
	 */

	ASSERT(cr != NULL);
	ASSERT(!(ixa->ixa_free_flags & IXA_FREE_CRED));
	ixa->ixa_cred = cr;
	ixa->ixa_cpid = pid;
	if (is_system_labeled()) {
		/* We need to restart with a label based on the cred */
		ip_xmit_attr_restore_tsl(ixa, ixa->ixa_cred);
	}

	/*
	 * If we are connected then the destination needs to be the
	 * same as the connected one, which is not the case here since we
	 * checked for that above.
	 */
	if (udp->udp_state == TS_DATA_XFER) {
		mutex_exit(&connp->conn_lock);
		error = EISCONN;
		goto ud_error;
	}

	/* In case previous destination was multicast or multirt */
	ip_attr_newdst(ixa);

	/*
	 * If laddr is unspecified then we look at sin6_src_id.
	 * We will give precedence to a source address set with IPV6_PKTINFO
	 * (aka IPPF_ADDR) but that is handled in build_hdrs. However, we don't
	 * want ip_attr_connect to select a source (since it can fail) when
	 * IPV6_PKTINFO is specified.
	 * If this doesn't result in a source address then we get a source
	 * from ip_attr_connect() below.
	 */
	v6src = connp->conn_saddr_v6;
	if (sin != NULL) {
		IN6_IPADDR_TO_V4MAPPED(sin->sin_addr.s_addr, &v6dst);
		dstport = sin->sin_port;
		flowinfo = 0;
		/* Don't bother with ip_srcid_find_id(), but indicate anyway. */
		srcid = 0;
		ixa->ixa_flags &= ~IXAF_SCOPEID_SET;
		ixa->ixa_flags |= IXAF_IS_IPV4;
	} else {
		boolean_t v4mapped;

		v6dst = sin6->sin6_addr;
		dstport = sin6->sin6_port;
		flowinfo = sin6->sin6_flowinfo;
		srcid = sin6->__sin6_src_id;
		if (IN6_IS_ADDR_LINKSCOPE(&v6dst) && sin6->sin6_scope_id != 0) {
			ixa->ixa_scopeid = sin6->sin6_scope_id;
			ixa->ixa_flags |= IXAF_SCOPEID_SET;
		} else {
			ixa->ixa_flags &= ~IXAF_SCOPEID_SET;
		}
		v4mapped = IN6_IS_ADDR_V4MAPPED(&v6dst);
		if (v4mapped)
			ixa->ixa_flags |= IXAF_IS_IPV4;
		else
			ixa->ixa_flags &= ~IXAF_IS_IPV4;
		if (srcid != 0 && IN6_IS_ADDR_UNSPECIFIED(&v6src)) {
			if (!ip_srcid_find_id(srcid, &v6src, IPCL_ZONEID(connp),
			    v4mapped, connp->conn_netstack)) {
				/* Mismatched v4mapped/v6 specified by srcid. */
				mutex_exit(&connp->conn_lock);
				error = EADDRNOTAVAIL;
				goto ud_error;
			}
		}
	}
	/* Handle IP_PKTINFO/IPV6_PKTINFO setting source address. */
	if (connp->conn_xmit_ipp.ipp_fields & IPPF_ADDR) {
		ip_pkt_t *ipp = &connp->conn_xmit_ipp;

		if (ixa->ixa_flags & IXAF_IS_IPV4) {
			if (IN6_IS_ADDR_V4MAPPED(&ipp->ipp_addr))
				v6src = ipp->ipp_addr;
		} else {
			if (!IN6_IS_ADDR_V4MAPPED(&ipp->ipp_addr))
				v6src = ipp->ipp_addr;
		}
	}

	ip_attr_nexthop(&connp->conn_xmit_ipp, ixa, &v6dst, &v6nexthop);
	mutex_exit(&connp->conn_lock);

	error = ip_attr_connect(connp, ixa, &v6src, &v6dst, &v6nexthop, dstport,
	    &v6src, NULL, IPDF_ALLOW_MCBC | IPDF_VERIFY_DST | IPDF_IPSEC);
	switch (error) {
	case 0:
		break;
	case EADDRNOTAVAIL:
		/*
		 * IXAF_VERIFY_SOURCE tells us to pick a better source.
		 * Don't have the application see that errno
		 */
		error = ENETUNREACH;
		goto failed;
	case ENETDOWN:
		/*
		 * Have !ipif_addr_ready address; drop packet silently
		 * until we can get applications to not send until we
		 * are ready.
		 */
		error = 0;
		goto failed;
	case EHOSTUNREACH:
	case ENETUNREACH:
		if (ixa->ixa_ire != NULL) {
			/*
			 * Let conn_ip_output/ire_send_noroute return
			 * the error and send any local ICMP error.
			 */
			error = 0;
			break;
		}
		/* FALLTHRU */
	failed:
	default:
		goto ud_error;
	}


	/*
	 * Cluster note: we let the cluster hook know that we are sending to a
	 * new address and/or port.
	 */
	if (cl_inet_connect2 != NULL) {
		CL_INET_UDP_CONNECT(connp, B_TRUE, &v6dst, dstport, error);
		if (error != 0) {
			error = EHOSTUNREACH;
			goto ud_error;
		}
	}

	mutex_enter(&connp->conn_lock);
	/*
	 * While we dropped the lock some other thread might have connected
	 * this socket. If so we bail out with EISCONN to ensure that the
	 * connecting thread is the one that updates conn_ixa, conn_ht_*
	 * and conn_*last*.
	 */
	if (udp->udp_state == TS_DATA_XFER) {
		mutex_exit(&connp->conn_lock);
		error = EISCONN;
		goto ud_error;
	}

	/*
	 * We need to rebuild the headers if
	 *  - we are labeling packets (could be different for different
	 *    destinations)
	 *  - we have a source route (or routing header) since we need to
	 *    massage that to get the pseudo-header checksum
	 *  - the IP version is different than the last time
	 *  - a socket option with COA_HEADER_CHANGED has been set which
	 *    set conn_v6lastdst to zero.
	 *
	 * Otherwise the prepend function will just update the src, dst,
	 * dstport, and flow label.
	 */
	if (is_system_labeled()) {
		/* TX MLP requires SCM_UCRED and don't have that here */
		if (connp->conn_mlp_type != mlptSingle) {
			mutex_exit(&connp->conn_lock);
			error = ECONNREFUSED;
			goto ud_error;
		}
		/*
		 * Check whether Trusted Solaris policy allows communication
		 * with this host, and pretend that the destination is
		 * unreachable if not.
		 * Compute any needed label and place it in ipp_label_v4/v6.
		 *
		 * Later conn_build_hdr_template/conn_prepend_hdr takes
		 * ipp_label_v4/v6 to form the packet.
		 *
		 * Tsol note: Since we hold conn_lock we know no other
		 * thread manipulates conn_xmit_ipp.
		 */
		error = conn_update_label(connp, ixa, &v6dst,
		    &connp->conn_xmit_ipp);
		if (error != 0) {
			mutex_exit(&connp->conn_lock);
			goto ud_error;
		}
		/* Rebuild the header template */
		error = udp_build_hdr_template(connp, &v6src, &v6dst, dstport,
		    flowinfo);
		if (error != 0) {
			mutex_exit(&connp->conn_lock);
			goto ud_error;
		}
	} else if ((connp->conn_xmit_ipp.ipp_fields &
	    (IPPF_IPV4_OPTIONS|IPPF_RTHDR)) ||
	    ipversion != connp->conn_lastipversion ||
	    IN6_IS_ADDR_UNSPECIFIED(&connp->conn_v6lastdst)) {
		/* Rebuild the header template */
		error = udp_build_hdr_template(connp, &v6src, &v6dst, dstport,
		    flowinfo);
		if (error != 0) {
			mutex_exit(&connp->conn_lock);
			goto ud_error;
		}
	} else {
		/* Simply update the destination address if no source route */
		if (ixa->ixa_flags & IXAF_IS_IPV4) {
			ipha_t	*ipha = (ipha_t *)connp->conn_ht_iphc;

			IN6_V4MAPPED_TO_IPADDR(&v6dst, ipha->ipha_dst);
			if (ixa->ixa_flags & IXAF_PMTU_IPV4_DF) {
				ipha->ipha_fragment_offset_and_flags |=
				    IPH_DF_HTONS;
			} else {
				ipha->ipha_fragment_offset_and_flags &=
				    ~IPH_DF_HTONS;
			}
		} else {
			ip6_t *ip6h = (ip6_t *)connp->conn_ht_iphc;
			ip6h->ip6_dst = v6dst;
		}
	}

	/*
	 * Remember the dst/dstport etc which corresponds to the built header
	 * template and conn_ixa.
	 */
	oldixa = conn_replace_ixa(connp, ixa);
	connp->conn_v6lastdst = v6dst;
	connp->conn_lastipversion = ipversion;
	connp->conn_lastdstport = dstport;
	connp->conn_lastflowinfo = flowinfo;
	connp->conn_lastscopeid = ixa->ixa_scopeid;
	connp->conn_lastsrcid = srcid;
	/* Also remember a source to use together with lastdst */
	connp->conn_v6lastsrc = v6src;

	data_mp = udp_prepend_header_template(connp, ixa, data_mp, &v6src,
	    dstport, flowinfo, &error);

	/* Done with conn_t */
	mutex_exit(&connp->conn_lock);
	ixa_refrele(oldixa);

	if (data_mp == NULL) {
		ASSERT(error != 0);
		goto ud_error;
	}

	/* We're done.  Pass the packet to ip. */
	UDPS_BUMP_MIB(us, udpHCOutDatagrams);

	DTRACE_UDP5(send, mblk_t *, NULL, ip_xmit_attr_t *, ixa,
	    void_ip_t *, data_mp->b_rptr, udp_t *, udp, udpha_t *,
	    &data_mp->b_rptr[ixa->ixa_ip_hdr_length]);

	error = conn_ip_output(data_mp, ixa);
	/* No udpOutErrors if an error since IP increases its error counter */
	switch (error) {
	case 0:
		break;
	case EWOULDBLOCK:
		(void) ixa_check_drain_insert(connp, ixa);
		error = 0;
		break;
	case EADDRNOTAVAIL:
		/*
		 * IXAF_VERIFY_SOURCE tells us to pick a better source.
		 * Don't have the application see that errno
		 */
		error = ENETUNREACH;
		/* FALLTHRU */
	default:
		mutex_enter(&connp->conn_lock);
		/*
		 * Clear the source and v6lastdst so we call ip_attr_connect
		 * for the next packet and try to pick a better source.
		 */
		if (connp->conn_mcbc_bind)
			connp->conn_saddr_v6 = ipv6_all_zeros;
		else
			connp->conn_saddr_v6 = connp->conn_bound_addr_v6;
		connp->conn_v6lastdst = ipv6_all_zeros;
		mutex_exit(&connp->conn_lock);
		break;
	}
	ASSERT(!(ixa->ixa_free_flags & IXA_FREE_CRED));
	ixa->ixa_cred = connp->conn_cred;	/* Restore */
	ixa->ixa_cpid = connp->conn_cpid;
	ixa_refrele(ixa);
	return (error);

ud_error:
	ASSERT(!(ixa->ixa_free_flags & IXA_FREE_CRED));
	ixa->ixa_cred = connp->conn_cred;	/* Restore */
	ixa->ixa_cpid = connp->conn_cpid;
	ixa_refrele(ixa);

	freemsg(data_mp);
	UDPS_BUMP_MIB(us, udpOutErrors);
	UDP_STAT(us, udp_out_err_output);
	return (error);
}

/* ARGSUSED */
static void
udp_wput_fallback(queue_t *wq, mblk_t *mp)
{
#ifdef DEBUG
	cmn_err(CE_CONT, "udp_wput_fallback: Message in fallback \n");
#endif
	freemsg(mp);
}


/*
 * Handle special out-of-band ioctl requests (see PSARC/2008/265).
 */
static void
udp_wput_cmdblk(queue_t *q, mblk_t *mp)
{
	void	*data;
	mblk_t	*datamp = mp->b_cont;
	conn_t	*connp = Q_TO_CONN(q);
	udp_t	*udp = connp->conn_udp;
	cmdblk_t *cmdp = (cmdblk_t *)mp->b_rptr;

	if (datamp == NULL || MBLKL(datamp) < cmdp->cb_len) {
		cmdp->cb_error = EPROTO;
		qreply(q, mp);
		return;
	}
	data = datamp->b_rptr;

	mutex_enter(&connp->conn_lock);
	switch (cmdp->cb_cmd) {
	case TI_GETPEERNAME:
		if (udp->udp_state != TS_DATA_XFER)
			cmdp->cb_error = ENOTCONN;
		else
			cmdp->cb_error = conn_getpeername(connp, data,
			    &cmdp->cb_len);
		break;
	case TI_GETMYNAME:
		cmdp->cb_error = conn_getsockname(connp, data, &cmdp->cb_len);
		break;
	default:
		cmdp->cb_error = EINVAL;
		break;
	}
	mutex_exit(&connp->conn_lock);

	qreply(q, mp);
}

static void
udp_use_pure_tpi(udp_t *udp)
{
	conn_t	*connp = udp->udp_connp;

	mutex_enter(&connp->conn_lock);
	udp->udp_issocket = B_FALSE;
	mutex_exit(&connp->conn_lock);
	UDP_STAT(udp->udp_us, udp_sock_fallback);
}

static void
udp_wput_other(queue_t *q, mblk_t *mp)
{
	uchar_t	*rptr = mp->b_rptr;
	struct iocblk *iocp;
	conn_t	*connp = Q_TO_CONN(q);
	udp_t	*udp = connp->conn_udp;
	cred_t	*cr;

	switch (mp->b_datap->db_type) {
	case M_CMD:
		udp_wput_cmdblk(q, mp);
		return;

	case M_PROTO:
	case M_PCPROTO:
		if (mp->b_wptr - rptr < sizeof (t_scalar_t)) {
			/*
			 * If the message does not contain a PRIM_type,
			 * throw it away.
			 */
			freemsg(mp);
			return;
		}
		switch (((t_primp_t)rptr)->type) {
		case T_ADDR_REQ:
			udp_addr_req(q, mp);
			return;
		case O_T_BIND_REQ:
		case T_BIND_REQ:
			udp_tpi_bind(q, mp);
			return;
		case T_CONN_REQ:
			udp_tpi_connect(q, mp);
			return;
		case T_CAPABILITY_REQ:
			udp_capability_req(q, mp);
			return;
		case T_INFO_REQ:
			udp_info_req(q, mp);
			return;
		case T_UNITDATA_REQ:
			/*
			 * If a T_UNITDATA_REQ gets here, the address must
			 * be bad.  Valid T_UNITDATA_REQs are handled
			 * in udp_wput.
			 */
			udp_ud_err(q, mp, EADDRNOTAVAIL);
			return;
		case T_UNBIND_REQ:
			udp_tpi_unbind(q, mp);
			return;
		case T_SVR4_OPTMGMT_REQ:
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
				udp_err_ack(q, mp, TSYSERR, EINVAL);
				return;
			}
			if (!snmpcom_req(q, mp, udp_snmp_set, ip_snmp_get,
			    cr)) {
				svr4_optcom_req(q, mp, cr, &udp_opt_obj);
			}
			return;

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
				udp_err_ack(q, mp, TSYSERR, EINVAL);
				return;
			}
			tpi_optcom_req(q, mp, cr, &udp_opt_obj);
			return;

		case T_DISCON_REQ:
			udp_tpi_disconnect(q, mp);
			return;

		/* The following TPI message is not supported by udp. */
		case O_T_CONN_RES:
		case T_CONN_RES:
			udp_err_ack(q, mp, TNOTSUPPORT, 0);
			return;

		/* The following 3 TPI requests are illegal for udp. */
		case T_DATA_REQ:
		case T_EXDATA_REQ:
		case T_ORDREL_REQ:
			udp_err_ack(q, mp, TNOTSUPPORT, 0);
			return;
		default:
			break;
		}
		break;
	case M_FLUSH:
		if (*rptr & FLUSHW)
			flushq(q, FLUSHDATA);
		break;
	case M_IOCTL:
		iocp = (struct iocblk *)mp->b_rptr;
		switch (iocp->ioc_cmd) {
		case TI_GETPEERNAME:
			if (udp->udp_state != TS_DATA_XFER) {
				/*
				 * If a default destination address has not
				 * been associated with the stream, then we
				 * don't know the peer's name.
				 */
				iocp->ioc_error = ENOTCONN;
				iocp->ioc_count = 0;
				mp->b_datap->db_type = M_IOCACK;
				qreply(q, mp);
				return;
			}
			/* FALLTHRU */
		case TI_GETMYNAME:
			/*
			 * For TI_GETPEERNAME and TI_GETMYNAME, we first
			 * need to copyin the user's strbuf structure.
			 * Processing will continue in the M_IOCDATA case
			 * below.
			 */
			mi_copyin(q, mp, NULL,
			    SIZEOF_STRUCT(strbuf, iocp->ioc_flag));
			return;
		case _SIOCSOCKFALLBACK:
			/*
			 * Either sockmod is about to be popped and the
			 * socket would now be treated as a plain stream,
			 * or a module is about to be pushed so we have
			 * to follow pure TPI semantics.
			 */
			if (!udp->udp_issocket) {
				DB_TYPE(mp) = M_IOCNAK;
				iocp->ioc_error = EINVAL;
			} else {
				udp_use_pure_tpi(udp);

				DB_TYPE(mp) = M_IOCACK;
				iocp->ioc_error = 0;
			}
			iocp->ioc_count = 0;
			iocp->ioc_rval = 0;
			qreply(q, mp);
			return;
		default:
			break;
		}
		break;
	case M_IOCDATA:
		udp_wput_iocdata(q, mp);
		return;
	default:
		/* Unrecognized messages are passed through without change. */
		break;
	}
	ip_wput_nondata(q, mp);
}

/*
 * udp_wput_iocdata is called by udp_wput_other to handle all M_IOCDATA
 * messages.
 */
static void
udp_wput_iocdata(queue_t *q, mblk_t *mp)
{
	mblk_t		*mp1;
	struct	iocblk *iocp = (struct iocblk *)mp->b_rptr;
	STRUCT_HANDLE(strbuf, sb);
	uint_t		addrlen;
	conn_t		*connp = Q_TO_CONN(q);
	udp_t		*udp = connp->conn_udp;

	/* Make sure it is one of ours. */
	switch (iocp->ioc_cmd) {
	case TI_GETMYNAME:
	case TI_GETPEERNAME:
		break;
	default:
		ip_wput_nondata(q, mp);
		return;
	}

	switch (mi_copy_state(q, mp, &mp1)) {
	case -1:
		return;
	case MI_COPY_CASE(MI_COPY_IN, 1):
		break;
	case MI_COPY_CASE(MI_COPY_OUT, 1):
		/*
		 * The address has been copied out, so now
		 * copyout the strbuf.
		 */
		mi_copyout(q, mp);
		return;
	case MI_COPY_CASE(MI_COPY_OUT, 2):
		/*
		 * The address and strbuf have been copied out.
		 * We're done, so just acknowledge the original
		 * M_IOCTL.
		 */
		mi_copy_done(q, mp, 0);
		return;
	default:
		/*
		 * Something strange has happened, so acknowledge
		 * the original M_IOCTL with an EPROTO error.
		 */
		mi_copy_done(q, mp, EPROTO);
		return;
	}

	/*
	 * Now we have the strbuf structure for TI_GETMYNAME
	 * and TI_GETPEERNAME.  Next we copyout the requested
	 * address and then we'll copyout the strbuf.
	 */
	STRUCT_SET_HANDLE(sb, iocp->ioc_flag, (void *)mp1->b_rptr);

	if (connp->conn_family == AF_INET)
		addrlen = sizeof (sin_t);
	else
		addrlen = sizeof (sin6_t);

	if (STRUCT_FGET(sb, maxlen) < addrlen) {
		mi_copy_done(q, mp, EINVAL);
		return;
	}

	switch (iocp->ioc_cmd) {
	case TI_GETMYNAME:
		break;
	case TI_GETPEERNAME:
		if (udp->udp_state != TS_DATA_XFER) {
			mi_copy_done(q, mp, ENOTCONN);
			return;
		}
		break;
	}
	mp1 = mi_copyout_alloc(q, mp, STRUCT_FGETP(sb, buf), addrlen, B_TRUE);
	if (!mp1)
		return;

	STRUCT_FSET(sb, len, addrlen);
	switch (((struct iocblk *)mp->b_rptr)->ioc_cmd) {
	case TI_GETMYNAME:
		(void) conn_getsockname(connp, (struct sockaddr *)mp1->b_wptr,
		    &addrlen);
		break;
	case TI_GETPEERNAME:
		(void) conn_getpeername(connp, (struct sockaddr *)mp1->b_wptr,
		    &addrlen);
		break;
	}
	mp1->b_wptr += addrlen;
	/* Copy out the address */
	mi_copyout(q, mp);
}

void
udp_ddi_g_init(void)
{
	udp_max_optsize = optcom_max_optsize(udp_opt_obj.odb_opt_des_arr,
	    udp_opt_obj.odb_opt_arr_cnt);

	/*
	 * We want to be informed each time a stack is created or
	 * destroyed in the kernel, so we can maintain the
	 * set of udp_stack_t's.
	 */
	netstack_register(NS_UDP, udp_stack_init, NULL, udp_stack_fini);
}

void
udp_ddi_g_destroy(void)
{
	netstack_unregister(NS_UDP);
}

#define	INET_NAME	"ip"

/*
 * Initialize the UDP stack instance.
 */
static void *
udp_stack_init(netstackid_t stackid, netstack_t *ns)
{
	udp_stack_t	*us;
	int		i;
	int		error = 0;
	major_t		major;
	size_t		arrsz;

	us = (udp_stack_t *)kmem_zalloc(sizeof (*us), KM_SLEEP);
	us->us_netstack = ns;

	mutex_init(&us->us_epriv_port_lock, NULL, MUTEX_DEFAULT, NULL);
	us->us_num_epriv_ports = UDP_NUM_EPRIV_PORTS;
	us->us_epriv_ports[0] = ULP_DEF_EPRIV_PORT1;
	us->us_epriv_ports[1] = ULP_DEF_EPRIV_PORT2;

	/*
	 * The smallest anonymous port in the priviledged port range which UDP
	 * looks for free port.  Use in the option UDP_ANONPRIVBIND.
	 */
	us->us_min_anonpriv_port = 512;

	us->us_bind_fanout_size = udp_bind_fanout_size;

	/* Roundup variable that might have been modified in /etc/system */
	if (us->us_bind_fanout_size & (us->us_bind_fanout_size - 1)) {
		/* Not a power of two. Round up to nearest power of two */
		for (i = 0; i < 31; i++) {
			if (us->us_bind_fanout_size < (1 << i))
				break;
		}
		us->us_bind_fanout_size = 1 << i;
	}
	us->us_bind_fanout = kmem_zalloc(us->us_bind_fanout_size *
	    sizeof (udp_fanout_t), KM_SLEEP);
	for (i = 0; i < us->us_bind_fanout_size; i++) {
		mutex_init(&us->us_bind_fanout[i].uf_lock, NULL, MUTEX_DEFAULT,
		    NULL);
	}

	arrsz = udp_propinfo_count * sizeof (mod_prop_info_t);
	us->us_propinfo_tbl = (mod_prop_info_t *)kmem_alloc(arrsz,
	    KM_SLEEP);
	bcopy(udp_propinfo_tbl, us->us_propinfo_tbl, arrsz);

	/* Allocate the per netstack stats */
	mutex_enter(&cpu_lock);
	us->us_sc_cnt = MAX(ncpus, boot_ncpus);
	mutex_exit(&cpu_lock);
	us->us_sc = kmem_zalloc(max_ncpus  * sizeof (udp_stats_cpu_t *),
	    KM_SLEEP);
	for (i = 0; i < us->us_sc_cnt; i++) {
		us->us_sc[i] = kmem_zalloc(sizeof (udp_stats_cpu_t),
		    KM_SLEEP);
	}

	us->us_kstat = udp_kstat2_init(stackid);
	us->us_mibkp = udp_kstat_init(stackid);

	major = mod_name_to_major(INET_NAME);
	error = ldi_ident_from_major(major, &us->us_ldi_ident);
	ASSERT(error == 0);
	return (us);
}

/*
 * Free the UDP stack instance.
 */
static void
udp_stack_fini(netstackid_t stackid, void *arg)
{
	udp_stack_t *us = (udp_stack_t *)arg;
	int i;

	for (i = 0; i < us->us_bind_fanout_size; i++) {
		mutex_destroy(&us->us_bind_fanout[i].uf_lock);
	}

	kmem_free(us->us_bind_fanout, us->us_bind_fanout_size *
	    sizeof (udp_fanout_t));

	us->us_bind_fanout = NULL;

	for (i = 0; i < us->us_sc_cnt; i++)
		kmem_free(us->us_sc[i], sizeof (udp_stats_cpu_t));
	kmem_free(us->us_sc, max_ncpus * sizeof (udp_stats_cpu_t *));

	kmem_free(us->us_propinfo_tbl,
	    udp_propinfo_count * sizeof (mod_prop_info_t));
	us->us_propinfo_tbl = NULL;

	udp_kstat_fini(stackid, us->us_mibkp);
	us->us_mibkp = NULL;

	udp_kstat2_fini(stackid, us->us_kstat);
	us->us_kstat = NULL;

	mutex_destroy(&us->us_epriv_port_lock);
	ldi_ident_release(us->us_ldi_ident);
	kmem_free(us, sizeof (*us));
}

static size_t
udp_set_rcv_hiwat(udp_t *udp, size_t size)
{
	udp_stack_t *us = udp->udp_us;

	/* We add a bit of extra buffering */
	size += size >> 1;
	if (size > us->us_max_buf)
		size = us->us_max_buf;

	udp->udp_rcv_hiwat = size;
	return (size);
}

/*
 * For the lower queue so that UDP can be a dummy mux.
 * Nobody should be sending
 * packets up this stream
 */
static void
udp_lrput(queue_t *q, mblk_t *mp)
{
	switch (mp->b_datap->db_type) {
	case M_FLUSH:
		/* Turn around */
		if (*mp->b_rptr & FLUSHW) {
			*mp->b_rptr &= ~FLUSHR;
			qreply(q, mp);
			return;
		}
		break;
	}
	freemsg(mp);
}

/*
 * For the lower queue so that UDP can be a dummy mux.
 * Nobody should be sending packets down this stream.
 */
/* ARGSUSED */
void
udp_lwput(queue_t *q, mblk_t *mp)
{
	freemsg(mp);
}

/*
 * When a CPU is added, we need to allocate the per CPU stats struct.
 */
void
udp_stack_cpu_add(udp_stack_t *us, processorid_t cpu_seqid)
{
	int i;

	if (cpu_seqid < us->us_sc_cnt)
		return;
	for (i = us->us_sc_cnt; i <= cpu_seqid; i++) {
		ASSERT(us->us_sc[i] == NULL);
		us->us_sc[i] = kmem_zalloc(sizeof (udp_stats_cpu_t),
		    KM_SLEEP);
	}
	membar_producer();
	us->us_sc_cnt = cpu_seqid + 1;
}

/*
 * Below routines for UDP socket module.
 */

static conn_t *
udp_do_open(cred_t *credp, boolean_t isv6, int flags, int *errorp)
{
	udp_t		*udp;
	conn_t		*connp;
	zoneid_t 	zoneid;
	netstack_t 	*ns;
	udp_stack_t 	*us;
	int		len;

	ASSERT(errorp != NULL);

	if ((*errorp = secpolicy_basic_net_access(credp)) != 0)
		return (NULL);

	ns = netstack_find_by_cred(credp);
	ASSERT(ns != NULL);
	us = ns->netstack_udp;
	ASSERT(us != NULL);

	/*
	 * For exclusive stacks we set the zoneid to zero
	 * to make UDP operate as if in the global zone.
	 */
	if (ns->netstack_stackid != GLOBAL_NETSTACKID)
		zoneid = GLOBAL_ZONEID;
	else
		zoneid = crgetzoneid(credp);

	ASSERT(flags == KM_SLEEP || flags == KM_NOSLEEP);

	connp = ipcl_conn_create(IPCL_UDPCONN, flags, ns);
	if (connp == NULL) {
		netstack_rele(ns);
		*errorp = ENOMEM;
		return (NULL);
	}
	udp = connp->conn_udp;

	/*
	 * ipcl_conn_create did a netstack_hold. Undo the hold that was
	 * done by netstack_find_by_cred()
	 */
	netstack_rele(ns);

	/*
	 * Since this conn_t/udp_t is not yet visible to anybody else we don't
	 * need to lock anything.
	 */
	ASSERT(connp->conn_proto == IPPROTO_UDP);
	ASSERT(connp->conn_udp == udp);
	ASSERT(udp->udp_connp == connp);

	/* Set the initial state of the stream and the privilege status. */
	udp->udp_state = TS_UNBND;
	connp->conn_ixa->ixa_flags |= IXAF_VERIFY_SOURCE;
	if (isv6) {
		connp->conn_family = AF_INET6;
		connp->conn_ipversion = IPV6_VERSION;
		connp->conn_ixa->ixa_flags &= ~IXAF_IS_IPV4;
		connp->conn_default_ttl = us->us_ipv6_hoplimit;
		len = sizeof (ip6_t) + UDPH_SIZE;
	} else {
		connp->conn_family = AF_INET;
		connp->conn_ipversion = IPV4_VERSION;
		connp->conn_ixa->ixa_flags |= IXAF_IS_IPV4;
		connp->conn_default_ttl = us->us_ipv4_ttl;
		len = sizeof (ipha_t) + UDPH_SIZE;
	}

	ASSERT(connp->conn_ixa->ixa_protocol == connp->conn_proto);
	connp->conn_xmit_ipp.ipp_unicast_hops = connp->conn_default_ttl;

	connp->conn_ixa->ixa_multicast_ttl = IP_DEFAULT_MULTICAST_TTL;
	connp->conn_ixa->ixa_flags |= IXAF_MULTICAST_LOOP | IXAF_SET_ULP_CKSUM;
	/* conn_allzones can not be set this early, hence no IPCL_ZONEID */
	connp->conn_ixa->ixa_zoneid = zoneid;

	connp->conn_zoneid = zoneid;

	/*
	 * If the caller has the process-wide flag set, then default to MAC
	 * exempt mode.  This allows read-down to unlabeled hosts.
	 */
	if (getpflags(NET_MAC_AWARE, credp) != 0)
		connp->conn_mac_mode = CONN_MAC_AWARE;

	connp->conn_zone_is_global = (crgetzoneid(credp) == GLOBAL_ZONEID);

	udp->udp_us = us;

	connp->conn_rcvbuf = us->us_recv_hiwat;
	connp->conn_sndbuf = us->us_xmit_hiwat;
	connp->conn_sndlowat = us->us_xmit_lowat;
	connp->conn_rcvlowat = udp_mod_info.mi_lowat;

	connp->conn_wroff = len + us->us_wroff_extra;
	connp->conn_so_type = SOCK_DGRAM;

	connp->conn_recv = udp_input;
	connp->conn_recvicmp = udp_icmp_input;
	crhold(credp);
	connp->conn_cred = credp;
	connp->conn_cpid = curproc->p_pid;
	connp->conn_open_time = ddi_get_lbolt64();
	/* Cache things in ixa without an extra refhold */
	ASSERT(!(connp->conn_ixa->ixa_free_flags & IXA_FREE_CRED));
	connp->conn_ixa->ixa_cred = connp->conn_cred;
	connp->conn_ixa->ixa_cpid = connp->conn_cpid;
	if (is_system_labeled())
		connp->conn_ixa->ixa_tsl = crgetlabel(connp->conn_cred);

	*((sin6_t *)&udp->udp_delayed_addr) = sin6_null;

	if (us->us_pmtu_discovery)
		connp->conn_ixa->ixa_flags |= IXAF_PMTU_DISCOVERY;

	return (connp);
}

sock_lower_handle_t
udp_create(int family, int type, int proto, sock_downcalls_t **sock_downcalls,
    uint_t *smodep, int *errorp, int flags, cred_t *credp)
{
	udp_t		*udp = NULL;
	udp_stack_t	*us;
	conn_t		*connp;
	boolean_t	isv6;

	if (type != SOCK_DGRAM || (family != AF_INET && family != AF_INET6) ||
	    (proto != 0 && proto != IPPROTO_UDP)) {
		*errorp = EPROTONOSUPPORT;
		return (NULL);
	}

	if (family == AF_INET6)
		isv6 = B_TRUE;
	else
		isv6 = B_FALSE;

	connp = udp_do_open(credp, isv6, flags, errorp);
	if (connp == NULL)
		return (NULL);

	udp = connp->conn_udp;
	ASSERT(udp != NULL);
	us = udp->udp_us;
	ASSERT(us != NULL);

	udp->udp_issocket = B_TRUE;
	connp->conn_flags |= IPCL_NONSTR;

	/*
	 * Set flow control
	 * Since this conn_t/udp_t is not yet visible to anybody else we don't
	 * need to lock anything.
	 */
	(void) udp_set_rcv_hiwat(udp, connp->conn_rcvbuf);
	udp->udp_rcv_disply_hiwat = connp->conn_rcvbuf;

	connp->conn_flow_cntrld = B_FALSE;

	mutex_enter(&connp->conn_lock);
	connp->conn_state_flags &= ~CONN_INCIPIENT;
	mutex_exit(&connp->conn_lock);

	*errorp = 0;
	*smodep = SM_ATOMIC;
	*sock_downcalls = &sock_udp_downcalls;
	return ((sock_lower_handle_t)connp);
}

/* ARGSUSED3 */
void
udp_activate(sock_lower_handle_t proto_handle, sock_upper_handle_t sock_handle,
    sock_upcalls_t *sock_upcalls, int flags, cred_t *cr)
{
	conn_t 		*connp = (conn_t *)proto_handle;
	struct sock_proto_props sopp;

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	connp->conn_upcalls = sock_upcalls;
	connp->conn_upper_handle = sock_handle;

	sopp.sopp_flags = SOCKOPT_WROFF | SOCKOPT_RCVHIWAT | SOCKOPT_RCVLOWAT |
	    SOCKOPT_MAXBLK | SOCKOPT_MAXPSZ | SOCKOPT_MINPSZ;
	sopp.sopp_wroff = connp->conn_wroff;
	sopp.sopp_maxblk = INFPSZ;
	sopp.sopp_rxhiwat = connp->conn_rcvbuf;
	sopp.sopp_rxlowat = connp->conn_rcvlowat;
	sopp.sopp_maxaddrlen = sizeof (sin6_t);
	sopp.sopp_maxpsz =
	    (connp->conn_family == AF_INET) ? UDP_MAXPACKET_IPV4 :
	    UDP_MAXPACKET_IPV6;
	sopp.sopp_minpsz = (udp_mod_info.mi_minpsz == 1) ? 0 :
	    udp_mod_info.mi_minpsz;

	(*connp->conn_upcalls->su_set_proto_props)(connp->conn_upper_handle,
	    &sopp);
}

static void
udp_do_close(conn_t *connp)
{
	udp_t	*udp;

	ASSERT(connp != NULL && IPCL_IS_UDP(connp));
	udp = connp->conn_udp;

	if (cl_inet_unbind != NULL && udp->udp_state == TS_IDLE) {
		/*
		 * Running in cluster mode - register unbind information
		 */
		if (connp->conn_ipversion == IPV4_VERSION) {
			(*cl_inet_unbind)(
			    connp->conn_netstack->netstack_stackid,
			    IPPROTO_UDP, AF_INET,
			    (uint8_t *)(&V4_PART_OF_V6(connp->conn_laddr_v6)),
			    (in_port_t)connp->conn_lport, NULL);
		} else {
			(*cl_inet_unbind)(
			    connp->conn_netstack->netstack_stackid,
			    IPPROTO_UDP, AF_INET6,
			    (uint8_t *)&(connp->conn_laddr_v6),
			    (in_port_t)connp->conn_lport, NULL);
		}
	}

	udp_bind_hash_remove(udp, B_FALSE);

	ip_quiesce_conn(connp);

	if (!IPCL_IS_NONSTR(connp)) {
		ASSERT(connp->conn_wq != NULL);
		ASSERT(connp->conn_rq != NULL);
		qprocsoff(connp->conn_rq);
	}

	udp_close_free(connp);

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

	if (!IPCL_IS_NONSTR(connp)) {
		inet_minor_free(connp->conn_minor_arena, connp->conn_dev);
	} else {
		ip_free_helper_stream(connp);
	}

	connp->conn_ref--;
	ipcl_conn_destroy(connp);
}

/* ARGSUSED1 */
int
udp_close(sock_lower_handle_t proto_handle, int flags, cred_t *cr)
{
	conn_t	*connp = (conn_t *)proto_handle;

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	udp_do_close(connp);
	return (0);
}

static int
udp_do_bind(conn_t *connp, struct sockaddr *sa, socklen_t len, cred_t *cr,
    boolean_t bind_to_req_port_only)
{
	sin_t		*sin;
	sin6_t		*sin6;
	udp_t		*udp = connp->conn_udp;
	int		error = 0;
	ip_laddr_t	laddr_type = IPVL_UNICAST_UP;	/* INADDR_ANY */
	in_port_t	port;		/* Host byte order */
	in_port_t	requested_port;	/* Host byte order */
	int		count;
	ipaddr_t	v4src;		/* Set if AF_INET */
	in6_addr_t	v6src;
	int		loopmax;
	udp_fanout_t	*udpf;
	in_port_t	lport;		/* Network byte order */
	uint_t		scopeid = 0;
	zoneid_t	zoneid = IPCL_ZONEID(connp);
	ip_stack_t	*ipst = connp->conn_netstack->netstack_ip;
	boolean_t	is_inaddr_any;
	mlp_type_t	addrtype, mlptype;
	udp_stack_t	*us = udp->udp_us;

	switch (len) {
	case sizeof (sin_t):	/* Complete IPv4 address */
		sin = (sin_t *)sa;

		if (sin == NULL || !OK_32PTR((char *)sin))
			return (EINVAL);

		if (connp->conn_family != AF_INET ||
		    sin->sin_family != AF_INET) {
			return (EAFNOSUPPORT);
		}
		v4src = sin->sin_addr.s_addr;
		IN6_IPADDR_TO_V4MAPPED(v4src, &v6src);
		if (v4src != INADDR_ANY) {
			laddr_type = ip_laddr_verify_v4(v4src, zoneid, ipst,
			    B_TRUE);
		}
		port = ntohs(sin->sin_port);
		break;

	case sizeof (sin6_t):	/* complete IPv6 address */
		sin6 = (sin6_t *)sa;

		if (sin6 == NULL || !OK_32PTR((char *)sin6))
			return (EINVAL);

		if (connp->conn_family != AF_INET6 ||
		    sin6->sin6_family != AF_INET6) {
			return (EAFNOSUPPORT);
		}
		v6src = sin6->sin6_addr;
		if (IN6_IS_ADDR_V4MAPPED(&v6src)) {
			if (connp->conn_ipv6_v6only)
				return (EADDRNOTAVAIL);

			IN6_V4MAPPED_TO_IPADDR(&v6src, v4src);
			if (v4src != INADDR_ANY) {
				laddr_type = ip_laddr_verify_v4(v4src,
				    zoneid, ipst, B_FALSE);
			}
		} else {
			if (!IN6_IS_ADDR_UNSPECIFIED(&v6src)) {
				if (IN6_IS_ADDR_LINKSCOPE(&v6src))
					scopeid = sin6->sin6_scope_id;
				laddr_type = ip_laddr_verify_v6(&v6src,
				    zoneid, ipst, B_TRUE, scopeid);
			}
		}
		port = ntohs(sin6->sin6_port);
		break;

	default:		/* Invalid request */
		(void) strlog(UDP_MOD_ID, 0, 1, SL_ERROR|SL_TRACE,
		    "udp_bind: bad ADDR_length length %u", len);
		return (-TBADADDR);
	}

	/* Is the local address a valid unicast, multicast, or broadcast? */
	if (laddr_type == IPVL_BAD)
		return (EADDRNOTAVAIL);

	requested_port = port;

	if (requested_port == 0 || !bind_to_req_port_only)
		bind_to_req_port_only = B_FALSE;
	else		/* T_BIND_REQ and requested_port != 0 */
		bind_to_req_port_only = B_TRUE;

	if (requested_port == 0) {
		/*
		 * If the application passed in zero for the port number, it
		 * doesn't care which port number we bind to. Get one in the
		 * valid range.
		 */
		if (connp->conn_anon_priv_bind) {
			port = udp_get_next_priv_port(udp);
		} else {
			port = udp_update_next_port(udp,
			    us->us_next_port_to_try, B_TRUE);
		}
	} else {
		/*
		 * If the port is in the well-known privileged range,
		 * make sure the caller was privileged.
		 */
		int i;
		boolean_t priv = B_FALSE;

		if (port < us->us_smallest_nonpriv_port) {
			priv = B_TRUE;
		} else {
			for (i = 0; i < us->us_num_epriv_ports; i++) {
				if (port == us->us_epriv_ports[i]) {
					priv = B_TRUE;
					break;
				}
			}
		}

		if (priv) {
			if (secpolicy_net_privaddr(cr, port, IPPROTO_UDP) != 0)
				return (-TACCES);
		}
	}

	if (port == 0)
		return (-TNOADDR);

	/*
	 * The state must be TS_UNBND. TPI mandates that users must send
	 * TPI primitives only 1 at a time and wait for the response before
	 * sending the next primitive.
	 */
	mutex_enter(&connp->conn_lock);
	if (udp->udp_state != TS_UNBND) {
		mutex_exit(&connp->conn_lock);
		(void) strlog(UDP_MOD_ID, 0, 1, SL_ERROR|SL_TRACE,
		    "udp_bind: bad state, %u", udp->udp_state);
		return (-TOUTSTATE);
	}
	/*
	 * Copy the source address into our udp structure. This address
	 * may still be zero; if so, IP will fill in the correct address
	 * each time an outbound packet is passed to it. Since the udp is
	 * not yet in the bind hash list, we don't grab the uf_lock to
	 * change conn_ipversion
	 */
	if (connp->conn_family == AF_INET) {
		ASSERT(sin != NULL);
		ASSERT(connp->conn_ixa->ixa_flags & IXAF_IS_IPV4);
	} else {
		if (IN6_IS_ADDR_V4MAPPED(&v6src)) {
			/*
			 * no need to hold the uf_lock to set the conn_ipversion
			 * since we are not yet in the fanout list
			 */
			connp->conn_ipversion = IPV4_VERSION;
			connp->conn_ixa->ixa_flags |= IXAF_IS_IPV4;
		} else {
			connp->conn_ipversion = IPV6_VERSION;
			connp->conn_ixa->ixa_flags &= ~IXAF_IS_IPV4;
		}
	}

	/*
	 * If conn_reuseaddr is not set, then we have to make sure that
	 * the IP address and port number the application requested
	 * (or we selected for the application) is not being used by
	 * another stream.  If another stream is already using the
	 * requested IP address and port, the behavior depends on
	 * "bind_to_req_port_only". If set the bind fails; otherwise we
	 * search for any an unused port to bind to the stream.
	 *
	 * As per the BSD semantics, as modified by the Deering multicast
	 * changes, if udp_reuseaddr is set, then we allow multiple binds
	 * to the same port independent of the local IP address.
	 *
	 * This is slightly different than in SunOS 4.X which did not
	 * support IP multicast. Note that the change implemented by the
	 * Deering multicast code effects all binds - not only binding
	 * to IP multicast addresses.
	 *
	 * Note that when binding to port zero we ignore SO_REUSEADDR in
	 * order to guarantee a unique port.
	 */

	count = 0;
	if (connp->conn_anon_priv_bind) {
		/*
		 * loopmax = (IPPORT_RESERVED-1) -
		 *    us->us_min_anonpriv_port + 1
		 */
		loopmax = IPPORT_RESERVED - us->us_min_anonpriv_port;
	} else {
		loopmax = us->us_largest_anon_port -
		    us->us_smallest_anon_port + 1;
	}

	is_inaddr_any = V6_OR_V4_INADDR_ANY(v6src);

	for (;;) {
		udp_t		*udp1;
		boolean_t	found_exclbind = B_FALSE;
		conn_t		*connp1;

		/*
		 * Walk through the list of udp streams bound to
		 * requested port with the same IP address.
		 */
		lport = htons(port);
		udpf = &us->us_bind_fanout[UDP_BIND_HASH(lport,
		    us->us_bind_fanout_size)];
		mutex_enter(&udpf->uf_lock);
		for (udp1 = udpf->uf_udp; udp1 != NULL;
		    udp1 = udp1->udp_bind_hash) {
			connp1 = udp1->udp_connp;

			if (lport != connp1->conn_lport)
				continue;

			/*
			 * On a labeled system, we must treat bindings to ports
			 * on shared IP addresses by sockets with MAC exemption
			 * privilege as being in all zones, as there's
			 * otherwise no way to identify the right receiver.
			 */
			if (!IPCL_BIND_ZONE_MATCH(connp1, connp))
				continue;

			/*
			 * If UDP_EXCLBIND is set for either the bound or
			 * binding endpoint, the semantics of bind
			 * is changed according to the following chart.
			 *
			 * spec = specified address (v4 or v6)
			 * unspec = unspecified address (v4 or v6)
			 * A = specified addresses are different for endpoints
			 *
			 * bound	bind to		allowed?
			 * -------------------------------------
			 * unspec	unspec		no
			 * unspec	spec		no
			 * spec		unspec		no
			 * spec		spec		yes if A
			 *
			 * For labeled systems, SO_MAC_EXEMPT behaves the same
			 * as UDP_EXCLBIND, except that zoneid is ignored.
			 */
			if (connp1->conn_exclbind || connp->conn_exclbind ||
			    IPCL_CONNS_MAC(udp1->udp_connp, connp)) {
				if (V6_OR_V4_INADDR_ANY(
				    connp1->conn_bound_addr_v6) ||
				    is_inaddr_any ||
				    IN6_ARE_ADDR_EQUAL(
				    &connp1->conn_bound_addr_v6,
				    &v6src)) {
					found_exclbind = B_TRUE;
					break;
				}
				continue;
			}

			/*
			 * Check ipversion to allow IPv4 and IPv6 sockets to
			 * have disjoint port number spaces.
			 */
			if (connp->conn_ipversion != connp1->conn_ipversion) {

				/*
				 * On the first time through the loop, if the
				 * the user intentionally specified a
				 * particular port number, then ignore any
				 * bindings of the other protocol that may
				 * conflict. This allows the user to bind IPv6
				 * alone and get both v4 and v6, or bind both
				 * both and get each seperately. On subsequent
				 * times through the loop, we're checking a
				 * port that we chose (not the user) and thus
				 * we do not allow casual duplicate bindings.
				 */
				if (count == 0 && requested_port != 0)
					continue;
			}

			/*
			 * No difference depending on SO_REUSEADDR.
			 *
			 * If existing port is bound to a
			 * non-wildcard IP address and
			 * the requesting stream is bound to
			 * a distinct different IP addresses
			 * (non-wildcard, also), keep going.
			 */
			if (!is_inaddr_any &&
			    !V6_OR_V4_INADDR_ANY(connp1->conn_bound_addr_v6) &&
			    !IN6_ARE_ADDR_EQUAL(&connp1->conn_laddr_v6,
			    &v6src)) {
				continue;
			}
			break;
		}

		if (!found_exclbind &&
		    (connp->conn_reuseaddr && requested_port != 0)) {
			break;
		}

		if (udp1 == NULL) {
			/*
			 * No other stream has this IP address
			 * and port number. We can use it.
			 */
			break;
		}
		mutex_exit(&udpf->uf_lock);
		if (bind_to_req_port_only) {
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
			mutex_exit(&connp->conn_lock);
			return (-TADDRBUSY);
		}

		if (connp->conn_anon_priv_bind) {
			port = udp_get_next_priv_port(udp);
		} else {
			if ((count == 0) && (requested_port != 0)) {
				/*
				 * If the application wants us to find
				 * a port, get one to start with. Set
				 * requested_port to 0, so that we will
				 * update us->us_next_port_to_try below.
				 */
				port = udp_update_next_port(udp,
				    us->us_next_port_to_try, B_TRUE);
				requested_port = 0;
			} else {
				port = udp_update_next_port(udp, port + 1,
				    B_FALSE);
			}
		}

		if (port == 0 || ++count >= loopmax) {
			/*
			 * We've tried every possible port number and
			 * there are none available, so send an error
			 * to the user.
			 */
			mutex_exit(&connp->conn_lock);
			return (-TNOADDR);
		}
	}

	/*
	 * Copy the source address into our udp structure.  This address
	 * may still be zero; if so, ip_attr_connect will fill in the correct
	 * address when a packet is about to be sent.
	 * If we are binding to a broadcast or multicast address then
	 * we just set the conn_bound_addr since we don't want to use
	 * that as the source address when sending.
	 */
	connp->conn_bound_addr_v6 = v6src;
	connp->conn_laddr_v6 = v6src;
	if (scopeid != 0) {
		connp->conn_ixa->ixa_flags |= IXAF_SCOPEID_SET;
		connp->conn_ixa->ixa_scopeid = scopeid;
		connp->conn_incoming_ifindex = scopeid;
	} else {
		connp->conn_ixa->ixa_flags &= ~IXAF_SCOPEID_SET;
		connp->conn_incoming_ifindex = connp->conn_bound_if;
	}

	switch (laddr_type) {
	case IPVL_UNICAST_UP:
	case IPVL_UNICAST_DOWN:
		connp->conn_saddr_v6 = v6src;
		connp->conn_mcbc_bind = B_FALSE;
		break;
	case IPVL_MCAST:
	case IPVL_BCAST:
		/* ip_set_destination will pick a source address later */
		connp->conn_saddr_v6 = ipv6_all_zeros;
		connp->conn_mcbc_bind = B_TRUE;
		break;
	}

	/* Any errors after this point should use late_error */
	connp->conn_lport = lport;

	/*
	 * Now reset the next anonymous port if the application requested
	 * an anonymous port, or we handed out the next anonymous port.
	 */
	if ((requested_port == 0) && (!connp->conn_anon_priv_bind)) {
		us->us_next_port_to_try = port + 1;
	}

	/* Initialize the T_BIND_ACK. */
	if (connp->conn_family == AF_INET) {
		sin->sin_port = connp->conn_lport;
	} else {
		sin6->sin6_port = connp->conn_lport;
	}
	udp->udp_state = TS_IDLE;
	udp_bind_hash_insert(udpf, udp);
	mutex_exit(&udpf->uf_lock);
	mutex_exit(&connp->conn_lock);

	if (cl_inet_bind) {
		/*
		 * Running in cluster mode - register bind information
		 */
		if (connp->conn_ipversion == IPV4_VERSION) {
			(*cl_inet_bind)(connp->conn_netstack->netstack_stackid,
			    IPPROTO_UDP, AF_INET, (uint8_t *)&v4src,
			    (in_port_t)connp->conn_lport, NULL);
		} else {
			(*cl_inet_bind)(connp->conn_netstack->netstack_stackid,
			    IPPROTO_UDP, AF_INET6, (uint8_t *)&v6src,
			    (in_port_t)connp->conn_lport, NULL);
		}
	}

	mutex_enter(&connp->conn_lock);
	connp->conn_anon_port = (is_system_labeled() && requested_port == 0);
	if (is_system_labeled() && (!connp->conn_anon_port ||
	    connp->conn_anon_mlp)) {
		uint16_t mlpport;
		zone_t *zone;

		zone = crgetzone(cr);
		connp->conn_mlp_type =
		    connp->conn_recv_ancillary.crb_recvucred ? mlptBoth :
		    mlptSingle;
		addrtype = tsol_mlp_addr_type(
		    connp->conn_allzones ? ALL_ZONES : zone->zone_id,
		    IPV6_VERSION, &v6src, us->us_netstack->netstack_ip);
		if (addrtype == mlptSingle) {
			error = -TNOADDR;
			mutex_exit(&connp->conn_lock);
			goto late_error;
		}
		mlpport = connp->conn_anon_port ? PMAPPORT : port;
		mlptype = tsol_mlp_port_type(zone, IPPROTO_UDP, mlpport,
		    addrtype);

		/*
		 * It is a coding error to attempt to bind an MLP port
		 * without first setting SOL_SOCKET/SCM_UCRED.
		 */
		if (mlptype != mlptSingle &&
		    connp->conn_mlp_type == mlptSingle) {
			error = EINVAL;
			mutex_exit(&connp->conn_lock);
			goto late_error;
		}

		/*
		 * It is an access violation to attempt to bind an MLP port
		 * without NET_BINDMLP privilege.
		 */
		if (mlptype != mlptSingle &&
		    secpolicy_net_bindmlp(cr) != 0) {
			if (connp->conn_debug) {
				(void) strlog(UDP_MOD_ID, 0, 1,
				    SL_ERROR|SL_TRACE,
				    "udp_bind: no priv for multilevel port %d",
				    mlpport);
			}
			error = -TACCES;
			mutex_exit(&connp->conn_lock);
			goto late_error;
		}

		/*
		 * If we're specifically binding a shared IP address and the
		 * port is MLP on shared addresses, then check to see if this
		 * zone actually owns the MLP.  Reject if not.
		 */
		if (mlptype == mlptShared && addrtype == mlptShared) {
			/*
			 * No need to handle exclusive-stack zones since
			 * ALL_ZONES only applies to the shared stack.
			 */
			zoneid_t mlpzone;

			mlpzone = tsol_mlp_findzone(IPPROTO_UDP,
			    htons(mlpport));
			if (connp->conn_zoneid != mlpzone) {
				if (connp->conn_debug) {
					(void) strlog(UDP_MOD_ID, 0, 1,
					    SL_ERROR|SL_TRACE,
					    "udp_bind: attempt to bind port "
					    "%d on shared addr in zone %d "
					    "(should be %d)",
					    mlpport, connp->conn_zoneid,
					    mlpzone);
				}
				error = -TACCES;
				mutex_exit(&connp->conn_lock);
				goto late_error;
			}
		}
		if (connp->conn_anon_port) {
			error = tsol_mlp_anon(zone, mlptype, connp->conn_proto,
			    port, B_TRUE);
			if (error != 0) {
				if (connp->conn_debug) {
					(void) strlog(UDP_MOD_ID, 0, 1,
					    SL_ERROR|SL_TRACE,
					    "udp_bind: cannot establish anon "
					    "MLP for port %d", port);
				}
				error = -TACCES;
				mutex_exit(&connp->conn_lock);
				goto late_error;
			}
		}
		connp->conn_mlp_type = mlptype;
	}

	/*
	 * We create an initial header template here to make a subsequent
	 * sendto have a starting point. Since conn_last_dst is zero the
	 * first sendto will always follow the 'dst changed' code path.
	 * Note that we defer massaging options and the related checksum
	 * adjustment until we have a destination address.
	 */
	error = udp_build_hdr_template(connp, &connp->conn_saddr_v6,
	    &connp->conn_faddr_v6, connp->conn_fport, connp->conn_flowinfo);
	if (error != 0) {
		mutex_exit(&connp->conn_lock);
		goto late_error;
	}
	/* Just in case */
	connp->conn_faddr_v6 = ipv6_all_zeros;
	connp->conn_fport = 0;
	connp->conn_v6lastdst = ipv6_all_zeros;
	mutex_exit(&connp->conn_lock);

	error = ip_laddr_fanout_insert(connp);
	if (error != 0)
		goto late_error;

	/* Bind succeeded */
	return (0);

late_error:
	/* We had already picked the port number, and then the bind failed */
	mutex_enter(&connp->conn_lock);
	udpf = &us->us_bind_fanout[
	    UDP_BIND_HASH(connp->conn_lport,
	    us->us_bind_fanout_size)];
	mutex_enter(&udpf->uf_lock);
	connp->conn_saddr_v6 = ipv6_all_zeros;
	connp->conn_bound_addr_v6 = ipv6_all_zeros;
	connp->conn_laddr_v6 = ipv6_all_zeros;
	if (scopeid != 0) {
		connp->conn_ixa->ixa_flags &= ~IXAF_SCOPEID_SET;
		connp->conn_incoming_ifindex = connp->conn_bound_if;
	}
	udp->udp_state = TS_UNBND;
	udp_bind_hash_remove(udp, B_TRUE);
	connp->conn_lport = 0;
	mutex_exit(&udpf->uf_lock);
	connp->conn_anon_port = B_FALSE;
	connp->conn_mlp_type = mlptSingle;

	connp->conn_v6lastdst = ipv6_all_zeros;

	/* Restore the header that was built above - different source address */
	(void) udp_build_hdr_template(connp, &connp->conn_saddr_v6,
	    &connp->conn_faddr_v6, connp->conn_fport, connp->conn_flowinfo);
	mutex_exit(&connp->conn_lock);
	return (error);
}

int
udp_bind(sock_lower_handle_t proto_handle, struct sockaddr *sa,
    socklen_t len, cred_t *cr)
{
	int		error;
	conn_t		*connp;

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	connp = (conn_t *)proto_handle;

	if (sa == NULL)
		error = udp_do_unbind(connp);
	else
		error = udp_do_bind(connp, sa, len, cr, B_TRUE);

	if (error < 0) {
		if (error == -TOUTSTATE)
			error = EINVAL;
		else
			error = proto_tlitosyserr(-error);
	}

	return (error);
}

static int
udp_implicit_bind(conn_t *connp, cred_t *cr)
{
	sin6_t sin6addr;
	sin_t *sin;
	sin6_t *sin6;
	socklen_t len;
	int error;

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	if (connp->conn_family == AF_INET) {
		len = sizeof (struct sockaddr_in);
		sin = (sin_t *)&sin6addr;
		*sin = sin_null;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = INADDR_ANY;
	} else {
		ASSERT(connp->conn_family == AF_INET6);
		len = sizeof (sin6_t);
		sin6 = (sin6_t *)&sin6addr;
		*sin6 = sin6_null;
		sin6->sin6_family = AF_INET6;
		V6_SET_ZERO(sin6->sin6_addr);
	}

	error = udp_do_bind(connp, (struct sockaddr *)&sin6addr, len,
	    cr, B_FALSE);
	return ((error < 0) ? proto_tlitosyserr(-error) : error);
}

/*
 * This routine removes a port number association from a stream. It
 * is called by udp_unbind and udp_tpi_unbind.
 */
static int
udp_do_unbind(conn_t *connp)
{
	udp_t 		*udp = connp->conn_udp;
	udp_fanout_t	*udpf;
	udp_stack_t	*us = udp->udp_us;

	if (cl_inet_unbind != NULL) {
		/*
		 * Running in cluster mode - register unbind information
		 */
		if (connp->conn_ipversion == IPV4_VERSION) {
			(*cl_inet_unbind)(
			    connp->conn_netstack->netstack_stackid,
			    IPPROTO_UDP, AF_INET,
			    (uint8_t *)(&V4_PART_OF_V6(connp->conn_laddr_v6)),
			    (in_port_t)connp->conn_lport, NULL);
		} else {
			(*cl_inet_unbind)(
			    connp->conn_netstack->netstack_stackid,
			    IPPROTO_UDP, AF_INET6,
			    (uint8_t *)&(connp->conn_laddr_v6),
			    (in_port_t)connp->conn_lport, NULL);
		}
	}

	mutex_enter(&connp->conn_lock);
	/* If a bind has not been done, we can't unbind. */
	if (udp->udp_state == TS_UNBND) {
		mutex_exit(&connp->conn_lock);
		return (-TOUTSTATE);
	}
	udpf = &us->us_bind_fanout[UDP_BIND_HASH(connp->conn_lport,
	    us->us_bind_fanout_size)];
	mutex_enter(&udpf->uf_lock);
	udp_bind_hash_remove(udp, B_TRUE);
	connp->conn_saddr_v6 = ipv6_all_zeros;
	connp->conn_bound_addr_v6 = ipv6_all_zeros;
	connp->conn_laddr_v6 = ipv6_all_zeros;
	connp->conn_mcbc_bind = B_FALSE;
	connp->conn_lport = 0;
	/* In case we were also connected */
	connp->conn_faddr_v6 = ipv6_all_zeros;
	connp->conn_fport = 0;
	mutex_exit(&udpf->uf_lock);

	connp->conn_v6lastdst = ipv6_all_zeros;
	udp->udp_state = TS_UNBND;

	(void) udp_build_hdr_template(connp, &connp->conn_saddr_v6,
	    &connp->conn_faddr_v6, connp->conn_fport, connp->conn_flowinfo);
	mutex_exit(&connp->conn_lock);

	ip_unbind(connp);

	return (0);
}

/*
 * It associates a default destination address with the stream.
 */
static int
udp_do_connect(conn_t *connp, const struct sockaddr *sa, socklen_t len,
    cred_t *cr, pid_t pid)
{
	sin6_t		*sin6;
	sin_t		*sin;
	in6_addr_t 	v6dst;
	ipaddr_t 	v4dst;
	uint16_t 	dstport;
	uint32_t 	flowinfo;
	udp_fanout_t	*udpf;
	udp_t		*udp, *udp1;
	ushort_t	ipversion;
	udp_stack_t	*us;
	int		error;
	conn_t		*connp1;
	ip_xmit_attr_t	*ixa;
	ip_xmit_attr_t	*oldixa;
	uint_t		scopeid = 0;
	uint_t		srcid = 0;
	in6_addr_t	v6src = connp->conn_saddr_v6;
	boolean_t	v4mapped;

	udp = connp->conn_udp;
	us = udp->udp_us;

	/*
	 * Address has been verified by the caller
	 */
	switch (len) {
	default:
		/*
		 * Should never happen
		 */
		return (EINVAL);

	case sizeof (sin_t):
		sin = (sin_t *)sa;
		v4dst = sin->sin_addr.s_addr;
		dstport = sin->sin_port;
		IN6_IPADDR_TO_V4MAPPED(v4dst, &v6dst);
		ASSERT(connp->conn_ipversion == IPV4_VERSION);
		ipversion = IPV4_VERSION;
		break;

	case sizeof (sin6_t):
		sin6 = (sin6_t *)sa;
		v6dst = sin6->sin6_addr;
		dstport = sin6->sin6_port;
		srcid = sin6->__sin6_src_id;
		v4mapped = IN6_IS_ADDR_V4MAPPED(&v6dst);
		if (srcid != 0 && IN6_IS_ADDR_UNSPECIFIED(&v6src)) {
			if (!ip_srcid_find_id(srcid, &v6src, IPCL_ZONEID(connp),
			    v4mapped, connp->conn_netstack)) {
				/* Mismatch v4mapped/v6 specified by srcid. */
				return (EADDRNOTAVAIL);
			}
		}
		if (v4mapped) {
			if (connp->conn_ipv6_v6only)
				return (EADDRNOTAVAIL);

			/*
			 * Destination adress is mapped IPv6 address.
			 * Source bound address should be unspecified or
			 * IPv6 mapped address as well.
			 */
			if (!IN6_IS_ADDR_UNSPECIFIED(
			    &connp->conn_bound_addr_v6) &&
			    !IN6_IS_ADDR_V4MAPPED(&connp->conn_bound_addr_v6)) {
				return (EADDRNOTAVAIL);
			}
			IN6_V4MAPPED_TO_IPADDR(&v6dst, v4dst);
			ipversion = IPV4_VERSION;
			flowinfo = 0;
		} else {
			ipversion = IPV6_VERSION;
			flowinfo = sin6->sin6_flowinfo;
			if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr))
				scopeid = sin6->sin6_scope_id;
		}
		break;
	}

	if (dstport == 0)
		return (-TBADADDR);

	/*
	 * If there is a different thread using conn_ixa then we get a new
	 * copy and cut the old one loose from conn_ixa. Otherwise we use
	 * conn_ixa and prevent any other thread from using/changing it.
	 * Once connect() is done other threads can use conn_ixa since the
	 * refcnt will be back at one.
	 * We defer updating conn_ixa until later to handle any concurrent
	 * conn_ixa_cleanup thread.
	 */
	ixa = conn_get_ixa(connp, B_FALSE);
	if (ixa == NULL)
		return (ENOMEM);

	mutex_enter(&connp->conn_lock);
	/*
	 * This udp_t must have bound to a port already before doing a connect.
	 * Reject if a connect is in progress (we drop conn_lock during
	 * udp_do_connect).
	 */
	if (udp->udp_state == TS_UNBND || udp->udp_state == TS_WCON_CREQ) {
		mutex_exit(&connp->conn_lock);
		(void) strlog(UDP_MOD_ID, 0, 1, SL_ERROR|SL_TRACE,
		    "udp_connect: bad state, %u", udp->udp_state);
		ixa_refrele(ixa);
		return (-TOUTSTATE);
	}
	ASSERT(connp->conn_lport != 0 && udp->udp_ptpbhn != NULL);

	udpf = &us->us_bind_fanout[UDP_BIND_HASH(connp->conn_lport,
	    us->us_bind_fanout_size)];

	mutex_enter(&udpf->uf_lock);
	if (udp->udp_state == TS_DATA_XFER) {
		/* Already connected - clear out state */
		if (connp->conn_mcbc_bind)
			connp->conn_saddr_v6 = ipv6_all_zeros;
		else
			connp->conn_saddr_v6 = connp->conn_bound_addr_v6;
		connp->conn_laddr_v6 = connp->conn_bound_addr_v6;
		connp->conn_faddr_v6 = ipv6_all_zeros;
		connp->conn_fport = 0;
		udp->udp_state = TS_IDLE;
	}

	connp->conn_fport = dstport;
	connp->conn_ipversion = ipversion;
	if (ipversion == IPV4_VERSION) {
		/*
		 * Interpret a zero destination to mean loopback.
		 * Update the T_CONN_REQ (sin/sin6) since it is used to
		 * generate the T_CONN_CON.
		 */
		if (v4dst == INADDR_ANY) {
			v4dst = htonl(INADDR_LOOPBACK);
			IN6_IPADDR_TO_V4MAPPED(v4dst, &v6dst);
			if (connp->conn_family == AF_INET) {
				sin->sin_addr.s_addr = v4dst;
			} else {
				sin6->sin6_addr = v6dst;
			}
		}
		connp->conn_faddr_v6 = v6dst;
		connp->conn_flowinfo = 0;
	} else {
		ASSERT(connp->conn_ipversion == IPV6_VERSION);
		/*
		 * Interpret a zero destination to mean loopback.
		 * Update the T_CONN_REQ (sin/sin6) since it is used to
		 * generate the T_CONN_CON.
		 */
		if (IN6_IS_ADDR_UNSPECIFIED(&v6dst)) {
			v6dst = ipv6_loopback;
			sin6->sin6_addr = v6dst;
		}
		connp->conn_faddr_v6 = v6dst;
		connp->conn_flowinfo = flowinfo;
	}
	mutex_exit(&udpf->uf_lock);

	/*
	 * We update our cred/cpid based on the caller of connect
	 */
	if (connp->conn_cred != cr) {
		crhold(cr);
		crfree(connp->conn_cred);
		connp->conn_cred = cr;
	}
	connp->conn_cpid = pid;
	ASSERT(!(ixa->ixa_free_flags & IXA_FREE_CRED));
	ixa->ixa_cred = cr;
	ixa->ixa_cpid = pid;
	if (is_system_labeled()) {
		/* We need to restart with a label based on the cred */
		ip_xmit_attr_restore_tsl(ixa, ixa->ixa_cred);
	}

	if (scopeid != 0) {
		ixa->ixa_flags |= IXAF_SCOPEID_SET;
		ixa->ixa_scopeid = scopeid;
		connp->conn_incoming_ifindex = scopeid;
	} else {
		ixa->ixa_flags &= ~IXAF_SCOPEID_SET;
		connp->conn_incoming_ifindex = connp->conn_bound_if;
	}
	/*
	 * conn_connect will drop conn_lock and reacquire it.
	 * To prevent a send* from messing with this udp_t while the lock
	 * is dropped we set udp_state and clear conn_v6lastdst.
	 * That will make all send* fail with EISCONN.
	 */
	connp->conn_v6lastdst = ipv6_all_zeros;
	udp->udp_state = TS_WCON_CREQ;

	error = conn_connect(connp, NULL, IPDF_ALLOW_MCBC);
	mutex_exit(&connp->conn_lock);
	if (error != 0)
		goto connect_failed;

	/*
	 * The addresses have been verified. Time to insert in
	 * the correct fanout list.
	 */
	error = ipcl_conn_insert(connp);
	if (error != 0)
		goto connect_failed;

	mutex_enter(&connp->conn_lock);
	error = udp_build_hdr_template(connp, &connp->conn_saddr_v6,
	    &connp->conn_faddr_v6, connp->conn_fport, connp->conn_flowinfo);
	if (error != 0) {
		mutex_exit(&connp->conn_lock);
		goto connect_failed;
	}

	udp->udp_state = TS_DATA_XFER;
	/* Record this as the "last" send even though we haven't sent any */
	connp->conn_v6lastdst = connp->conn_faddr_v6;
	connp->conn_lastipversion = connp->conn_ipversion;
	connp->conn_lastdstport = connp->conn_fport;
	connp->conn_lastflowinfo = connp->conn_flowinfo;
	connp->conn_lastscopeid = scopeid;
	connp->conn_lastsrcid = srcid;
	/* Also remember a source to use together with lastdst */
	connp->conn_v6lastsrc = v6src;

	oldixa = conn_replace_ixa(connp, ixa);
	mutex_exit(&connp->conn_lock);
	ixa_refrele(oldixa);

	/*
	 * We've picked a source address above. Now we can
	 * verify that the src/port/dst/port is unique for all
	 * connections in TS_DATA_XFER, skipping ourselves.
	 */
	mutex_enter(&udpf->uf_lock);
	for (udp1 = udpf->uf_udp; udp1 != NULL; udp1 = udp1->udp_bind_hash) {
		if (udp1->udp_state != TS_DATA_XFER)
			continue;

		if (udp1 == udp)
			continue;

		connp1 = udp1->udp_connp;
		if (connp->conn_lport != connp1->conn_lport ||
		    connp->conn_ipversion != connp1->conn_ipversion ||
		    dstport != connp1->conn_fport ||
		    !IN6_ARE_ADDR_EQUAL(&connp->conn_laddr_v6,
		    &connp1->conn_laddr_v6) ||
		    !IN6_ARE_ADDR_EQUAL(&v6dst, &connp1->conn_faddr_v6) ||
		    !(IPCL_ZONE_MATCH(connp, connp1->conn_zoneid) ||
		    IPCL_ZONE_MATCH(connp1, connp->conn_zoneid)))
			continue;
		mutex_exit(&udpf->uf_lock);
		error = -TBADADDR;
		goto connect_failed;
	}
	if (cl_inet_connect2 != NULL) {
		CL_INET_UDP_CONNECT(connp, B_TRUE, &v6dst, dstport, error);
		if (error != 0) {
			mutex_exit(&udpf->uf_lock);
			error = -TBADADDR;
			goto connect_failed;
		}
	}
	mutex_exit(&udpf->uf_lock);

	ixa_refrele(ixa);
	return (0);

connect_failed:
	if (ixa != NULL)
		ixa_refrele(ixa);
	mutex_enter(&connp->conn_lock);
	mutex_enter(&udpf->uf_lock);
	udp->udp_state = TS_IDLE;
	connp->conn_faddr_v6 = ipv6_all_zeros;
	connp->conn_fport = 0;
	/* In case the source address was set above */
	if (connp->conn_mcbc_bind)
		connp->conn_saddr_v6 = ipv6_all_zeros;
	else
		connp->conn_saddr_v6 = connp->conn_bound_addr_v6;
	connp->conn_laddr_v6 = connp->conn_bound_addr_v6;
	mutex_exit(&udpf->uf_lock);

	connp->conn_v6lastdst = ipv6_all_zeros;
	connp->conn_flowinfo = 0;

	(void) udp_build_hdr_template(connp, &connp->conn_saddr_v6,
	    &connp->conn_faddr_v6, connp->conn_fport, connp->conn_flowinfo);
	mutex_exit(&connp->conn_lock);
	return (error);
}

static int
udp_connect(sock_lower_handle_t proto_handle, const struct sockaddr *sa,
    socklen_t len, sock_connid_t *id, cred_t *cr)
{
	conn_t	*connp = (conn_t *)proto_handle;
	udp_t	*udp = connp->conn_udp;
	int	error;
	boolean_t did_bind = B_FALSE;
	pid_t	pid = curproc->p_pid;

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	if (sa == NULL) {
		/*
		 * Disconnect
		 * Make sure we are connected
		 */
		if (udp->udp_state != TS_DATA_XFER)
			return (EINVAL);

		error = udp_disconnect(connp);
		return (error);
	}

	error = proto_verify_ip_addr(connp->conn_family, sa, len);
	if (error != 0)
		goto done;

	/* do an implicit bind if necessary */
	if (udp->udp_state == TS_UNBND) {
		error = udp_implicit_bind(connp, cr);
		/*
		 * We could be racing with an actual bind, in which case
		 * we would see EPROTO. We cross our fingers and try
		 * to connect.
		 */
		if (!(error == 0 || error == EPROTO))
			goto done;
		did_bind = B_TRUE;
	}
	/*
	 * set SO_DGRAM_ERRIND
	 */
	connp->conn_dgram_errind = B_TRUE;

	error = udp_do_connect(connp, sa, len, cr, pid);

	if (error != 0 && did_bind) {
		int unbind_err;

		unbind_err = udp_do_unbind(connp);
		ASSERT(unbind_err == 0);
	}

	if (error == 0) {
		*id = 0;
		(*connp->conn_upcalls->su_connected)
		    (connp->conn_upper_handle, 0, NULL, -1);
	} else if (error < 0) {
		error = proto_tlitosyserr(-error);
	}

done:
	if (error != 0 && udp->udp_state == TS_DATA_XFER) {
		/*
		 * No need to hold locks to set state
		 * after connect failure socket state is undefined
		 * We set the state only to imitate old sockfs behavior
		 */
		udp->udp_state = TS_IDLE;
	}
	return (error);
}

int
udp_send(sock_lower_handle_t proto_handle, mblk_t *mp, struct nmsghdr *msg,
    cred_t *cr)
{
	sin6_t		*sin6;
	sin_t		*sin = NULL;
	uint_t		srcid;
	conn_t		*connp = (conn_t *)proto_handle;
	udp_t		*udp = connp->conn_udp;
	int		error = 0;
	udp_stack_t	*us = udp->udp_us;
	ushort_t	ipversion;
	pid_t		pid = curproc->p_pid;
	ip_xmit_attr_t	*ixa;

	ASSERT(DB_TYPE(mp) == M_DATA);

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	/* do an implicit bind if necessary */
	if (udp->udp_state == TS_UNBND) {
		error = udp_implicit_bind(connp, cr);
		/*
		 * We could be racing with an actual bind, in which case
		 * we would see EPROTO. We cross our fingers and try
		 * to connect.
		 */
		if (!(error == 0 || error == EPROTO)) {
			freemsg(mp);
			return (error);
		}
	}

	/* Connected? */
	if (msg->msg_name == NULL) {
		if (udp->udp_state != TS_DATA_XFER) {
			UDPS_BUMP_MIB(us, udpOutErrors);
			return (EDESTADDRREQ);
		}
		if (msg->msg_controllen != 0) {
			error = udp_output_ancillary(connp, NULL, NULL, mp,
			    NULL, msg, cr, pid);
		} else {
			error = udp_output_connected(connp, mp, cr, pid);
		}
		if (us->us_sendto_ignerr)
			return (0);
		else
			return (error);
	}
	if (udp->udp_state == TS_DATA_XFER) {
		UDPS_BUMP_MIB(us, udpOutErrors);
		return (EISCONN);
	}
	error = proto_verify_ip_addr(connp->conn_family,
	    (struct sockaddr *)msg->msg_name, msg->msg_namelen);
	if (error != 0) {
		UDPS_BUMP_MIB(us, udpOutErrors);
		return (error);
	}
	switch (connp->conn_family) {
	case AF_INET6:
		sin6 = (sin6_t *)msg->msg_name;

		srcid = sin6->__sin6_src_id;

		if (!IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
			/*
			 * Destination is a non-IPv4-compatible IPv6 address.
			 * Send out an IPv6 format packet.
			 */

			/*
			 * If the local address is a mapped address return
			 * an error.
			 * It would be possible to send an IPv6 packet but the
			 * response would never make it back to the application
			 * since it is bound to a mapped address.
			 */
			if (IN6_IS_ADDR_V4MAPPED(&connp->conn_saddr_v6)) {
				UDPS_BUMP_MIB(us, udpOutErrors);
				return (EADDRNOTAVAIL);
			}
			if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr))
				sin6->sin6_addr = ipv6_loopback;
			ipversion = IPV6_VERSION;
		} else {
			if (connp->conn_ipv6_v6only) {
				UDPS_BUMP_MIB(us, udpOutErrors);
				return (EADDRNOTAVAIL);
			}

			/*
			 * If the local address is not zero or a mapped address
			 * return an error.  It would be possible to send an
			 * IPv4 packet but the response would never make it
			 * back to the application since it is bound to a
			 * non-mapped address.
			 */
			if (!IN6_IS_ADDR_V4MAPPED(&connp->conn_saddr_v6) &&
			    !IN6_IS_ADDR_UNSPECIFIED(&connp->conn_saddr_v6)) {
				UDPS_BUMP_MIB(us, udpOutErrors);
				return (EADDRNOTAVAIL);
			}

			if (V4_PART_OF_V6(sin6->sin6_addr) == INADDR_ANY) {
				V4_PART_OF_V6(sin6->sin6_addr) =
				    htonl(INADDR_LOOPBACK);
			}
			ipversion = IPV4_VERSION;
		}

		/*
		 * We have to allocate an ip_xmit_attr_t before we grab
		 * conn_lock and we need to hold conn_lock once we've check
		 * conn_same_as_last_v6 to handle concurrent send* calls on a
		 * socket.
		 */
		if (msg->msg_controllen == 0) {
			ixa = conn_get_ixa(connp, B_FALSE);
			if (ixa == NULL) {
				UDPS_BUMP_MIB(us, udpOutErrors);
				return (ENOMEM);
			}
		} else {
			ixa = NULL;
		}
		mutex_enter(&connp->conn_lock);
		if (udp->udp_delayed_error != 0) {
			sin6_t  *sin2 = (sin6_t *)&udp->udp_delayed_addr;

			error = udp->udp_delayed_error;
			udp->udp_delayed_error = 0;

			/* Compare IP address, port, and family */

			if (sin6->sin6_port == sin2->sin6_port &&
			    IN6_ARE_ADDR_EQUAL(&sin6->sin6_addr,
			    &sin2->sin6_addr) &&
			    sin6->sin6_family == sin2->sin6_family) {
				mutex_exit(&connp->conn_lock);
				UDPS_BUMP_MIB(us, udpOutErrors);
				if (ixa != NULL)
					ixa_refrele(ixa);
				return (error);
			}
		}

		if (msg->msg_controllen != 0) {
			mutex_exit(&connp->conn_lock);
			ASSERT(ixa == NULL);
			error = udp_output_ancillary(connp, NULL, sin6, mp,
			    NULL, msg, cr, pid);
		} else if (conn_same_as_last_v6(connp, sin6) &&
		    connp->conn_lastsrcid == srcid &&
		    ipsec_outbound_policy_current(ixa)) {
			/* udp_output_lastdst drops conn_lock */
			error = udp_output_lastdst(connp, mp, cr, pid, ixa);
		} else {
			/* udp_output_newdst drops conn_lock */
			error = udp_output_newdst(connp, mp, NULL, sin6,
			    ipversion, cr, pid, ixa);
		}
		ASSERT(MUTEX_NOT_HELD(&connp->conn_lock));
		if (us->us_sendto_ignerr)
			return (0);
		else
			return (error);
	case AF_INET:
		sin = (sin_t *)msg->msg_name;

		ipversion = IPV4_VERSION;

		if (sin->sin_addr.s_addr == INADDR_ANY)
			sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);

		/*
		 * We have to allocate an ip_xmit_attr_t before we grab
		 * conn_lock and we need to hold conn_lock once we've check
		 * conn_same_as_last_v6 to handle concurrent send* on a socket.
		 */
		if (msg->msg_controllen == 0) {
			ixa = conn_get_ixa(connp, B_FALSE);
			if (ixa == NULL) {
				UDPS_BUMP_MIB(us, udpOutErrors);
				return (ENOMEM);
			}
		} else {
			ixa = NULL;
		}
		mutex_enter(&connp->conn_lock);
		if (udp->udp_delayed_error != 0) {
			sin_t  *sin2 = (sin_t *)&udp->udp_delayed_addr;

			error = udp->udp_delayed_error;
			udp->udp_delayed_error = 0;

			/* Compare IP address and port */

			if (sin->sin_port == sin2->sin_port &&
			    sin->sin_addr.s_addr == sin2->sin_addr.s_addr) {
				mutex_exit(&connp->conn_lock);
				UDPS_BUMP_MIB(us, udpOutErrors);
				if (ixa != NULL)
					ixa_refrele(ixa);
				return (error);
			}
		}
		if (msg->msg_controllen != 0) {
			mutex_exit(&connp->conn_lock);
			ASSERT(ixa == NULL);
			error = udp_output_ancillary(connp, sin, NULL, mp,
			    NULL, msg, cr, pid);
		} else if (conn_same_as_last_v4(connp, sin) &&
		    ipsec_outbound_policy_current(ixa)) {
			/* udp_output_lastdst drops conn_lock */
			error = udp_output_lastdst(connp, mp, cr, pid, ixa);
		} else {
			/* udp_output_newdst drops conn_lock */
			error = udp_output_newdst(connp, mp, sin, NULL,
			    ipversion, cr, pid, ixa);
		}
		ASSERT(MUTEX_NOT_HELD(&connp->conn_lock));
		if (us->us_sendto_ignerr)
			return (0);
		else
			return (error);
	default:
		return (EINVAL);
	}
}

int
udp_fallback(sock_lower_handle_t proto_handle, queue_t *q,
    boolean_t issocket, so_proto_quiesced_cb_t quiesced_cb,
    sock_quiesce_arg_t *arg)
{
	conn_t 	*connp = (conn_t *)proto_handle;
	udp_t	*udp;
	struct T_capability_ack tca;
	struct sockaddr_in6 laddr, faddr;
	socklen_t laddrlen, faddrlen;
	short opts;
	struct stroptions *stropt;
	mblk_t *mp, *stropt_mp;
	int error;

	udp = connp->conn_udp;

	stropt_mp = allocb_wait(sizeof (*stropt), BPRI_HI, STR_NOSIG, NULL);

	/*
	 * setup the fallback stream that was allocated
	 */
	connp->conn_dev = (dev_t)RD(q)->q_ptr;
	connp->conn_minor_arena = WR(q)->q_ptr;

	RD(q)->q_ptr = WR(q)->q_ptr = connp;

	WR(q)->q_qinfo = &udp_winit;

	connp->conn_rq = RD(q);
	connp->conn_wq = WR(q);

	/* Notify stream head about options before sending up data */
	stropt_mp->b_datap->db_type = M_SETOPTS;
	stropt_mp->b_wptr += sizeof (*stropt);
	stropt = (struct stroptions *)stropt_mp->b_rptr;
	stropt->so_flags = SO_WROFF | SO_HIWAT;
	stropt->so_wroff = connp->conn_wroff;
	stropt->so_hiwat = udp->udp_rcv_disply_hiwat;
	putnext(RD(q), stropt_mp);

	/*
	 * Free the helper stream
	 */
	ip_free_helper_stream(connp);

	if (!issocket)
		udp_use_pure_tpi(udp);

	/*
	 * Collect the information needed to sync with the sonode
	 */
	udp_do_capability_ack(udp, &tca, TC1_INFO);

	laddrlen = faddrlen = sizeof (sin6_t);
	(void) udp_getsockname((sock_lower_handle_t)connp,
	    (struct sockaddr *)&laddr, &laddrlen, CRED());
	error = udp_getpeername((sock_lower_handle_t)connp,
	    (struct sockaddr *)&faddr, &faddrlen, CRED());
	if (error != 0)
		faddrlen = 0;

	opts = 0;
	if (connp->conn_dgram_errind)
		opts |= SO_DGRAM_ERRIND;
	if (connp->conn_ixa->ixa_flags & IXAF_DONTROUTE)
		opts |= SO_DONTROUTE;

	mp = (*quiesced_cb)(connp->conn_upper_handle, arg, &tca,
	    (struct sockaddr *)&laddr, laddrlen,
	    (struct sockaddr *)&faddr, faddrlen, opts);

	mutex_enter(&udp->udp_recv_lock);
	/*
	 * Attempts to send data up during fallback will result in it being
	 * queued in udp_t. First push up the datagrams obtained from the
	 * socket, then any packets queued in udp_t.
	 */
	if (mp != NULL) {
		mp->b_next = udp->udp_fallback_queue_head;
		udp->udp_fallback_queue_head = mp;
	}
	while (udp->udp_fallback_queue_head != NULL) {
		mp = udp->udp_fallback_queue_head;
		udp->udp_fallback_queue_head = mp->b_next;
		mutex_exit(&udp->udp_recv_lock);
		mp->b_next = NULL;
		putnext(RD(q), mp);
		mutex_enter(&udp->udp_recv_lock);
	}
	udp->udp_fallback_queue_tail = udp->udp_fallback_queue_head;
	/*
	 * No longer a streams less socket
	 */
	mutex_enter(&connp->conn_lock);
	connp->conn_flags &= ~IPCL_NONSTR;
	mutex_exit(&connp->conn_lock);

	mutex_exit(&udp->udp_recv_lock);

	ASSERT(connp->conn_ref >= 1);

	return (0);
}

/* ARGSUSED3 */
int
udp_getpeername(sock_lower_handle_t proto_handle, struct sockaddr *sa,
    socklen_t *salenp, cred_t *cr)
{
	conn_t	*connp = (conn_t *)proto_handle;
	udp_t	*udp = connp->conn_udp;
	int error;

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	mutex_enter(&connp->conn_lock);
	if (udp->udp_state != TS_DATA_XFER)
		error = ENOTCONN;
	else
		error = conn_getpeername(connp, sa, salenp);
	mutex_exit(&connp->conn_lock);
	return (error);
}

/* ARGSUSED3 */
int
udp_getsockname(sock_lower_handle_t proto_handle, struct sockaddr *sa,
    socklen_t *salenp, cred_t *cr)
{
	conn_t	*connp = (conn_t *)proto_handle;
	int error;

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	mutex_enter(&connp->conn_lock);
	error = conn_getsockname(connp, sa, salenp);
	mutex_exit(&connp->conn_lock);
	return (error);
}

int
udp_getsockopt(sock_lower_handle_t proto_handle, int level, int option_name,
    void *optvalp, socklen_t *optlen, cred_t *cr)
{
	conn_t		*connp = (conn_t *)proto_handle;
	int		error;
	t_uscalar_t	max_optbuf_len;
	void		*optvalp_buf;
	int		len;

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	error = proto_opt_check(level, option_name, *optlen, &max_optbuf_len,
	    udp_opt_obj.odb_opt_des_arr,
	    udp_opt_obj.odb_opt_arr_cnt,
	    B_FALSE, B_TRUE, cr);
	if (error != 0) {
		if (error < 0)
			error = proto_tlitosyserr(-error);
		return (error);
	}

	optvalp_buf = kmem_alloc(max_optbuf_len, KM_SLEEP);
	len = udp_opt_get(connp, level, option_name, optvalp_buf);
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

int
udp_setsockopt(sock_lower_handle_t proto_handle, int level, int option_name,
    const void *optvalp, socklen_t optlen, cred_t *cr)
{
	conn_t		*connp = (conn_t *)proto_handle;
	int		error;

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	error = proto_opt_check(level, option_name, optlen, NULL,
	    udp_opt_obj.odb_opt_des_arr,
	    udp_opt_obj.odb_opt_arr_cnt,
	    B_TRUE, B_FALSE, cr);

	if (error != 0) {
		if (error < 0)
			error = proto_tlitosyserr(-error);
		return (error);
	}

	error = udp_opt_set(connp, SETFN_OPTCOM_NEGOTIATE, level, option_name,
	    optlen, (uchar_t *)optvalp, (uint_t *)&optlen, (uchar_t *)optvalp,
	    NULL, cr);

	ASSERT(error >= 0);

	return (error);
}

void
udp_clr_flowctrl(sock_lower_handle_t proto_handle)
{
	conn_t	*connp = (conn_t *)proto_handle;
	udp_t	*udp = connp->conn_udp;

	mutex_enter(&udp->udp_recv_lock);
	connp->conn_flow_cntrld = B_FALSE;
	mutex_exit(&udp->udp_recv_lock);
}

/* ARGSUSED2 */
int
udp_shutdown(sock_lower_handle_t proto_handle, int how, cred_t *cr)
{
	conn_t	*connp = (conn_t *)proto_handle;

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	/* shut down the send side */
	if (how != SHUT_RD)
		(*connp->conn_upcalls->su_opctl)(connp->conn_upper_handle,
		    SOCK_OPCTL_SHUT_SEND, 0);
	/* shut down the recv side */
	if (how != SHUT_WR)
		(*connp->conn_upcalls->su_opctl)(connp->conn_upper_handle,
		    SOCK_OPCTL_SHUT_RECV, 0);
	return (0);
}

int
udp_ioctl(sock_lower_handle_t proto_handle, int cmd, intptr_t arg,
    int mode, int32_t *rvalp, cred_t *cr)
{
	conn_t  	*connp = (conn_t *)proto_handle;
	int		error;

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	/*
	 * If we don't have a helper stream then create one.
	 * ip_create_helper_stream takes care of locking the conn_t,
	 * so this check for NULL is just a performance optimization.
	 */
	if (connp->conn_helper_info == NULL) {
		udp_stack_t *us = connp->conn_udp->udp_us;

		ASSERT(us->us_ldi_ident != NULL);

		/*
		 * Create a helper stream for non-STREAMS socket.
		 */
		error = ip_create_helper_stream(connp, us->us_ldi_ident);
		if (error != 0) {
			ip0dbg(("tcp_ioctl: create of IP helper stream "
			    "failed %d\n", error));
			return (error);
		}
	}

	switch (cmd) {
		case _SIOCSOCKFALLBACK:
		case TI_GETPEERNAME:
		case TI_GETMYNAME:
			ip1dbg(("udp_ioctl: cmd 0x%x on non streams socket",
			    cmd));
			error = EINVAL;
			break;
		default:
			/*
			 * Pass on to IP using helper stream
			 */
			error = ldi_ioctl(connp->conn_helper_info->iphs_handle,
			    cmd, arg, mode, cr, rvalp);
			break;
	}
	return (error);
}

/* ARGSUSED */
int
udp_accept(sock_lower_handle_t lproto_handle,
    sock_lower_handle_t eproto_handle, sock_upper_handle_t sock_handle,
    cred_t *cr)
{
	return (EOPNOTSUPP);
}

/* ARGSUSED */
int
udp_listen(sock_lower_handle_t proto_handle, int backlog, cred_t *cr)
{
	return (EOPNOTSUPP);
}

sock_downcalls_t sock_udp_downcalls = {
	udp_activate,		/* sd_activate */
	udp_accept,		/* sd_accept */
	udp_bind,		/* sd_bind */
	udp_listen,		/* sd_listen */
	udp_connect,		/* sd_connect */
	udp_getpeername,	/* sd_getpeername */
	udp_getsockname,	/* sd_getsockname */
	udp_getsockopt,		/* sd_getsockopt */
	udp_setsockopt,		/* sd_setsockopt */
	udp_send,		/* sd_send */
	NULL,			/* sd_send_uio */
	NULL,			/* sd_recv_uio */
	NULL,			/* sd_poll */
	udp_shutdown,		/* sd_shutdown */
	udp_clr_flowctrl,	/* sd_setflowctrl */
	udp_ioctl,		/* sd_ioctl */
	udp_close		/* sd_close */
};
