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
 * Copyright (c) 2013 by Delphix. All rights reserved.
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
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/cred.h>
#include <sys/policy.h>
#include <sys/priv.h>
#include <sys/ucred.h>
#include <sys/zone.h>

#include <sys/sockio.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
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
#include <inet/nd.h>
#include <inet/optcom.h>
#include <inet/snmpcom.h>
#include <inet/kstatcom.h>
#include <inet/ipclassifier.h>

#include <sys/tsol/label.h>
#include <sys/tsol/tnet.h>

#include <inet/rawip_impl.h>

#include <sys/disp.h>

/*
 * Synchronization notes:
 *
 * RAWIP is MT and uses the usual kernel synchronization primitives. We use
 * conn_lock to protect the icmp_t.
 *
 * Plumbing notes:
 * ICMP is always a device driver. For compatibility with mibopen() code
 * it is possible to I_PUSH "icmp", but that results in pushing a passthrough
 * dummy module.
 */
static void	icmp_addr_req(queue_t *q, mblk_t *mp);
static void	icmp_tpi_bind(queue_t *q, mblk_t *mp);
static void	icmp_bind_proto(icmp_t *icmp);
static int	icmp_build_hdr_template(conn_t *, const in6_addr_t *,
    const in6_addr_t *, uint32_t);
static void	icmp_capability_req(queue_t *q, mblk_t *mp);
static int	icmp_close(queue_t *q, int flags);
static void	icmp_close_free(conn_t *);
static void	icmp_tpi_connect(queue_t *q, mblk_t *mp);
static void	icmp_tpi_disconnect(queue_t *q, mblk_t *mp);
static void	icmp_err_ack(queue_t *q, mblk_t *mp, t_scalar_t t_error,
    int sys_error);
static void	icmp_err_ack_prim(queue_t *q, mblk_t *mp, t_scalar_t primitive,
    t_scalar_t tlierr, int sys_error);
static void	icmp_icmp_input(void *arg1, mblk_t *mp, void *arg2,
    ip_recv_attr_t *);
static void	icmp_icmp_error_ipv6(conn_t *connp, mblk_t *mp,
    ip_recv_attr_t *);
static void	icmp_info_req(queue_t *q, mblk_t *mp);
static void	icmp_input(void *, mblk_t *, void *, ip_recv_attr_t *);
static conn_t 	*icmp_open(int family, cred_t *credp, int *err, int flags);
static int	icmp_openv4(queue_t *q, dev_t *devp, int flag, int sflag,
		    cred_t *credp);
static int	icmp_openv6(queue_t *q, dev_t *devp, int flag, int sflag,
		    cred_t *credp);
static boolean_t icmp_opt_allow_udr_set(t_scalar_t level, t_scalar_t name);
int		icmp_opt_set(conn_t *connp, uint_t optset_context,
		    int level, int name, uint_t inlen,
		    uchar_t *invalp, uint_t *outlenp, uchar_t *outvalp,
		    void *thisdg_attrs, cred_t *cr);
int		icmp_opt_get(conn_t *connp, int level, int name,
		    uchar_t *ptr);
static int	icmp_output_newdst(conn_t *connp, mblk_t *data_mp, sin_t *sin,
		    sin6_t *sin6, cred_t *cr, pid_t pid, ip_xmit_attr_t *ixa);
static mblk_t	*icmp_prepend_hdr(conn_t *, ip_xmit_attr_t *, const ip_pkt_t *,
    const in6_addr_t *, const in6_addr_t *, uint32_t, mblk_t *, int *);
static mblk_t	*icmp_prepend_header_template(conn_t *, ip_xmit_attr_t *,
    mblk_t *, const in6_addr_t *, uint32_t, int *);
static int	icmp_snmp_set(queue_t *q, t_scalar_t level, t_scalar_t name,
		    uchar_t *ptr, int len);
static void	icmp_ud_err(queue_t *q, mblk_t *mp, t_scalar_t err);
static void	icmp_tpi_unbind(queue_t *q, mblk_t *mp);
static void	icmp_wput(queue_t *q, mblk_t *mp);
static void	icmp_wput_fallback(queue_t *q, mblk_t *mp);
static void	icmp_wput_other(queue_t *q, mblk_t *mp);
static void	icmp_wput_iocdata(queue_t *q, mblk_t *mp);
static void	icmp_wput_restricted(queue_t *q, mblk_t *mp);
static void	icmp_ulp_recv(conn_t *, mblk_t *, uint_t);

static void	*rawip_stack_init(netstackid_t stackid, netstack_t *ns);
static void	rawip_stack_fini(netstackid_t stackid, void *arg);

static void	*rawip_kstat_init(netstackid_t stackid);
static void	rawip_kstat_fini(netstackid_t stackid, kstat_t *ksp);
static int	rawip_kstat_update(kstat_t *kp, int rw);
static void	rawip_stack_shutdown(netstackid_t stackid, void *arg);

/* Common routines for TPI and socket module */
static conn_t	*rawip_do_open(int, cred_t *, int *, int);
static void	rawip_do_close(conn_t *);
static int	rawip_do_bind(conn_t *, struct sockaddr *, socklen_t);
static int	rawip_do_unbind(conn_t *);
static int	rawip_do_connect(conn_t *, const struct sockaddr *, socklen_t,
    cred_t *, pid_t);

int		rawip_getsockname(sock_lower_handle_t, struct sockaddr *,
		    socklen_t *, cred_t *);
int		rawip_getpeername(sock_lower_handle_t, struct sockaddr *,
		    socklen_t *, cred_t *);

static struct module_info icmp_mod_info =  {
	5707, "icmp", 1, INFPSZ, 512, 128
};

/*
 * Entry points for ICMP as a device.
 * We have separate open functions for the /dev/icmp and /dev/icmp6 devices.
 */
static struct qinit icmprinitv4 = {
	NULL, NULL, icmp_openv4, icmp_close, NULL, &icmp_mod_info
};

static struct qinit icmprinitv6 = {
	NULL, NULL, icmp_openv6, icmp_close, NULL, &icmp_mod_info
};

static struct qinit icmpwinit = {
	(pfi_t)icmp_wput, (pfi_t)ip_wsrv, NULL, NULL, NULL, &icmp_mod_info
};

/* ICMP entry point during fallback */
static struct qinit icmp_fallback_sock_winit = {
	(pfi_t)icmp_wput_fallback, NULL, NULL, NULL, NULL, &icmp_mod_info
};

/* For AF_INET aka /dev/icmp */
struct streamtab icmpinfov4 = {
	&icmprinitv4, &icmpwinit
};

/* For AF_INET6 aka /dev/icmp6 */
struct streamtab icmpinfov6 = {
	&icmprinitv6, &icmpwinit
};

/* Default structure copied into T_INFO_ACK messages */
static struct T_info_ack icmp_g_t_info_ack = {
	T_INFO_ACK,
	IP_MAXPACKET,	 /* TSDU_size.  icmp allows maximum size messages. */
	T_INVALID,	/* ETSDU_size.  icmp does not support expedited data. */
	T_INVALID,	/* CDATA_size. icmp does not support connect data. */
	T_INVALID,	/* DDATA_size. icmp does not support disconnect data. */
	0,		/* ADDR_size - filled in later. */
	0,		/* OPT_size - not initialized here */
	IP_MAXPACKET,	/* TIDU_size.  icmp allows maximum size messages. */
	T_CLTS,		/* SERV_type.  icmp supports connection-less. */
	TS_UNBND,	/* CURRENT_state.  This is set from icmp_state. */
	(XPG4_1|SENDZERO) /* PROVIDER_flag */
};

static int
icmp_set_buf_prop(netstack_t *stack, cred_t *cr, mod_prop_info_t *pinfo,
    const char *ifname, const void *pval, uint_t flags)
{
	return (mod_set_buf_prop(stack->netstack_icmp->is_propinfo_tbl,
	    stack, cr, pinfo, ifname, pval, flags));
}

static int
icmp_get_buf_prop(netstack_t *stack, mod_prop_info_t *pinfo, const char *ifname,
    void *val, uint_t psize, uint_t flags)
{
	return (mod_get_buf_prop(stack->netstack_icmp->is_propinfo_tbl, stack,
	    pinfo, ifname, val, psize, flags));
}

/*
 * All of these are alterable, within the min/max values given, at run time.
 *
 * Note: All those tunables which do not start with "icmp_" are Committed and
 * therefore are public. See PSARC 2010/080.
 */
static mod_prop_info_t icmp_propinfo_tbl[] = {
	/* tunable - 0 */
	{ "_wroff_extra", MOD_PROTO_RAWIP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 128, 32}, {32} },

	{ "_ipv4_ttl", MOD_PROTO_RAWIP,
	    mod_set_uint32, mod_get_uint32,
	    {1, 255, 255}, {255} },

	{ "_ipv6_hoplimit", MOD_PROTO_RAWIP,
	    mod_set_uint32, mod_get_uint32,
	    {0, IPV6_MAX_HOPS, IPV6_DEFAULT_HOPS},
	    {IPV6_DEFAULT_HOPS} },

	{ "_bsd_compat", MOD_PROTO_RAWIP,
	    mod_set_boolean, mod_get_boolean,
	    {B_TRUE}, {B_TRUE} },

	{ "send_buf", MOD_PROTO_RAWIP,
	    icmp_set_buf_prop, icmp_get_buf_prop,
	    {4096, 65536, 8192}, {8192} },

	{ "_xmit_lowat", MOD_PROTO_RAWIP,
	    mod_set_uint32, mod_get_uint32,
	    {0, 65536, 1024}, {1024} },

	{ "recv_buf", MOD_PROTO_RAWIP,
	    icmp_set_buf_prop, icmp_get_buf_prop,
	    {4096, 65536, 8192}, {8192} },

	{ "max_buf", MOD_PROTO_RAWIP,
	    mod_set_uint32, mod_get_uint32,
	    {65536, ULP_MAX_BUF, 256*1024}, {256*1024} },

	{ "_pmtu_discovery", MOD_PROTO_RAWIP,
	    mod_set_boolean, mod_get_boolean,
	    {B_FALSE}, {B_FALSE} },

	{ "_sendto_ignerr", MOD_PROTO_RAWIP,
	    mod_set_boolean, mod_get_boolean,
	    {B_FALSE}, {B_FALSE} },

	{ "?", MOD_PROTO_RAWIP, NULL, mod_get_allprop, {0}, {0} },

	{ NULL, 0, NULL, NULL, {0}, {0} }
};

#define	is_wroff_extra			is_propinfo_tbl[0].prop_cur_uval
#define	is_ipv4_ttl			is_propinfo_tbl[1].prop_cur_uval
#define	is_ipv6_hoplimit		is_propinfo_tbl[2].prop_cur_uval
#define	is_bsd_compat			is_propinfo_tbl[3].prop_cur_bval
#define	is_xmit_hiwat			is_propinfo_tbl[4].prop_cur_uval
#define	is_xmit_lowat			is_propinfo_tbl[5].prop_cur_uval
#define	is_recv_hiwat			is_propinfo_tbl[6].prop_cur_uval
#define	is_max_buf			is_propinfo_tbl[7].prop_cur_uval
#define	is_pmtu_discovery		is_propinfo_tbl[8].prop_cur_bval
#define	is_sendto_ignerr		is_propinfo_tbl[9].prop_cur_bval

typedef union T_primitives *t_primp_t;

/*
 * This routine is called to handle each O_T_BIND_REQ/T_BIND_REQ message
 * passed to icmp_wput.
 * It calls IP to verify the local IP address, and calls IP to insert
 * the conn_t in the fanout table.
 * If everything is ok it then sends the T_BIND_ACK back up.
 */
static void
icmp_tpi_bind(queue_t *q, mblk_t *mp)
{
	int	error;
	struct sockaddr *sa;
	struct T_bind_req *tbr;
	socklen_t	len;
	sin_t	*sin;
	sin6_t	*sin6;
	icmp_t		*icmp;
	conn_t	*connp = Q_TO_CONN(q);
	mblk_t *mp1;
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
	if (cr == NULL) {
		icmp_err_ack(q, mp, TSYSERR, EINVAL);
		return;
	}

	icmp = connp->conn_icmp;
	if ((mp->b_wptr - mp->b_rptr) < sizeof (*tbr)) {
		(void) mi_strlog(q, 1, SL_ERROR|SL_TRACE,
		    "icmp_bind: bad req, len %u",
		    (uint_t)(mp->b_wptr - mp->b_rptr));
		icmp_err_ack(q, mp, TPROTO, 0);
		return;
	}

	if (icmp->icmp_state != TS_UNBND) {
		(void) mi_strlog(q, 1, SL_ERROR|SL_TRACE,
		    "icmp_bind: bad state, %u", icmp->icmp_state);
		icmp_err_ack(q, mp, TOUTSTATE, 0);
		return;
	}

	/*
	 * Reallocate the message to make sure we have enough room for an
	 * address.
	 */
	mp1 = reallocb(mp, sizeof (struct T_bind_ack) + sizeof (sin6_t), 1);
	if (mp1 == NULL) {
		icmp_err_ack(q, mp, TSYSERR, ENOMEM);
		return;
	}
	mp = mp1;

	/* Reset the message type in preparation for shipping it back. */
	DB_TYPE(mp) = M_PCPROTO;
	tbr = (struct T_bind_req *)mp->b_rptr;
	len = tbr->ADDR_length;
	switch (len) {
	case 0:	/* request for a generic port */
		tbr->ADDR_offset = sizeof (struct T_bind_req);
		if (connp->conn_family == AF_INET) {
			tbr->ADDR_length = sizeof (sin_t);
			sin = (sin_t *)&tbr[1];
			*sin = sin_null;
			sin->sin_family = AF_INET;
			mp->b_wptr = (uchar_t *)&sin[1];
			sa = (struct sockaddr *)sin;
			len = sizeof (sin_t);
		} else {
			ASSERT(connp->conn_family == AF_INET6);
			tbr->ADDR_length = sizeof (sin6_t);
			sin6 = (sin6_t *)&tbr[1];
			*sin6 = sin6_null;
			sin6->sin6_family = AF_INET6;
			mp->b_wptr = (uchar_t *)&sin6[1];
			sa = (struct sockaddr *)sin6;
			len = sizeof (sin6_t);
		}
		break;

	case sizeof (sin_t):	/* Complete IPv4 address */
		sa = (struct sockaddr *)mi_offset_param(mp, tbr->ADDR_offset,
		    sizeof (sin_t));
		break;

	case sizeof (sin6_t):	/* Complete IPv6 address */
		sa = (struct sockaddr *)mi_offset_param(mp,
		    tbr->ADDR_offset, sizeof (sin6_t));
		break;

	default:
		(void) mi_strlog(q, 1, SL_ERROR|SL_TRACE,
		    "icmp_bind: bad ADDR_length %u", tbr->ADDR_length);
		icmp_err_ack(q, mp, TBADADDR, 0);
		return;
	}

	error = rawip_do_bind(connp, sa, len);
	if (error != 0) {
		if (error > 0) {
			icmp_err_ack(q, mp, TSYSERR, error);
		} else {
			icmp_err_ack(q, mp, -error, 0);
		}
	} else {
		tbr->PRIM_type = T_BIND_ACK;
		qreply(q, mp);
	}
}

static int
rawip_do_bind(conn_t *connp, struct sockaddr *sa, socklen_t len)
{
	sin_t		*sin;
	sin6_t		*sin6;
	icmp_t		*icmp = connp->conn_icmp;
	int		error = 0;
	ip_laddr_t	laddr_type = IPVL_UNICAST_UP;	/* INADDR_ANY */
	in_port_t	lport;		/* Network byte order */
	ipaddr_t	v4src;		/* Set if AF_INET */
	in6_addr_t	v6src;
	uint_t		scopeid = 0;
	zoneid_t	zoneid = IPCL_ZONEID(connp);
	ip_stack_t	*ipst = connp->conn_netstack->netstack_ip;

	if (sa == NULL || !OK_32PTR((char *)sa)) {
		return (EINVAL);
	}

	switch (len) {
	case sizeof (sin_t):    /* Complete IPv4 address */
		sin = (sin_t *)sa;
		if (sin->sin_family != AF_INET ||
		    connp->conn_family != AF_INET) {
			/* TSYSERR, EAFNOSUPPORT */
			return (EAFNOSUPPORT);
		}
		v4src = sin->sin_addr.s_addr;
		IN6_IPADDR_TO_V4MAPPED(v4src, &v6src);
		if (v4src != INADDR_ANY) {
			laddr_type = ip_laddr_verify_v4(v4src, zoneid, ipst,
			    B_TRUE);
		}
		lport = sin->sin_port;
		break;
	case sizeof (sin6_t): /* Complete IPv6 address */
		sin6 = (sin6_t *)sa;
		if (sin6->sin6_family != AF_INET6 ||
		    connp->conn_family != AF_INET6) {
			/* TSYSERR, EAFNOSUPPORT */
			return (EAFNOSUPPORT);
		}
		/* No support for mapped addresses on raw sockets */
		if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
			/* TSYSERR, EADDRNOTAVAIL */
			return (EADDRNOTAVAIL);
		}
		v6src = sin6->sin6_addr;
		if (!IN6_IS_ADDR_UNSPECIFIED(&v6src)) {
			if (IN6_IS_ADDR_LINKSCOPE(&v6src))
				scopeid = sin6->sin6_scope_id;
			laddr_type = ip_laddr_verify_v6(&v6src, zoneid, ipst,
			    B_TRUE, scopeid);
		}
		lport = sin6->sin6_port;
		break;

	default:
		/* TBADADDR */
		return (EADDRNOTAVAIL);
	}

	/* Is the local address a valid unicast, multicast, or broadcast? */
	if (laddr_type == IPVL_BAD)
		return (EADDRNOTAVAIL);

	/*
	 * The state must be TS_UNBND.
	 */
	mutex_enter(&connp->conn_lock);
	if (icmp->icmp_state != TS_UNBND) {
		mutex_exit(&connp->conn_lock);
		return (-TOUTSTATE);
	}

	/*
	 * Copy the source address into our icmp structure.  This address
	 * may still be zero; if so, ip will fill in the correct address
	 * each time an outbound packet is passed to it.
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

	/*
	 * Use sin_port/sin6_port since applications like psh use SOCK_RAW
	 * with IPPROTO_TCP.
	 */
	connp->conn_lport = lport;
	connp->conn_fport = 0;

	if (connp->conn_family == AF_INET) {
		ASSERT(connp->conn_ipversion == IPV4_VERSION);
	} else {
		ASSERT(connp->conn_ipversion == IPV6_VERSION);
	}

	icmp->icmp_state = TS_IDLE;

	/*
	 * We create an initial header template here to make a subsequent
	 * sendto have a starting point. Since conn_last_dst is zero the
	 * first sendto will always follow the 'dst changed' code path.
	 * Note that we defer massaging options and the related checksum
	 * adjustment until we have a destination address.
	 */
	error = icmp_build_hdr_template(connp, &connp->conn_saddr_v6,
	    &connp->conn_faddr_v6, connp->conn_flowinfo);
	if (error != 0) {
		mutex_exit(&connp->conn_lock);
		goto late_error;
	}
	/* Just in case */
	connp->conn_faddr_v6 = ipv6_all_zeros;
	connp->conn_v6lastdst = ipv6_all_zeros;
	mutex_exit(&connp->conn_lock);

	error = ip_laddr_fanout_insert(connp);
	if (error != 0)
		goto late_error;

	/* Bind succeeded */
	return (0);

late_error:
	mutex_enter(&connp->conn_lock);
	connp->conn_saddr_v6 = ipv6_all_zeros;
	connp->conn_bound_addr_v6 = ipv6_all_zeros;
	connp->conn_laddr_v6 = ipv6_all_zeros;
	if (scopeid != 0) {
		connp->conn_ixa->ixa_flags &= ~IXAF_SCOPEID_SET;
		connp->conn_incoming_ifindex = connp->conn_bound_if;
	}
	icmp->icmp_state = TS_UNBND;
	connp->conn_v6lastdst = ipv6_all_zeros;
	connp->conn_lport = 0;

	/* Restore the header that was built above - different source address */
	(void) icmp_build_hdr_template(connp, &connp->conn_saddr_v6,
	    &connp->conn_faddr_v6, connp->conn_flowinfo);
	mutex_exit(&connp->conn_lock);
	return (error);
}

/*
 * Tell IP to just bind to the protocol.
 */
static void
icmp_bind_proto(icmp_t *icmp)
{
	conn_t	*connp = icmp->icmp_connp;

	mutex_enter(&connp->conn_lock);
	connp->conn_saddr_v6 = ipv6_all_zeros;
	connp->conn_laddr_v6 = ipv6_all_zeros;
	connp->conn_faddr_v6 = ipv6_all_zeros;
	connp->conn_v6lastdst = ipv6_all_zeros;
	mutex_exit(&connp->conn_lock);

	(void) ip_laddr_fanout_insert(connp);
}

/*
 * This routine handles each T_CONN_REQ message passed to icmp.  It
 * associates a default destination address with the stream.
 *
 * After various error checks are completed, icmp_connect() lays
 * the target address and port into the composite header template.
 * Then we ask IP for information, including a source address if we didn't
 * already have one. Finally we send up the T_OK_ACK reply message.
 */
static void
icmp_tpi_connect(queue_t *q, mblk_t *mp)
{
	conn_t	*connp = Q_TO_CONN(q);
	struct T_conn_req	*tcr;
	struct sockaddr *sa;
	socklen_t len;
	int error;
	cred_t *cr;
	pid_t pid;
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
		icmp_err_ack(q, mp, TSYSERR, EINVAL);
		return;
	}

	tcr = (struct T_conn_req *)mp->b_rptr;
	/* Sanity checks */
	if ((mp->b_wptr - mp->b_rptr) < sizeof (struct T_conn_req)) {
		icmp_err_ack(q, mp, TPROTO, 0);
		return;
	}

	if (tcr->OPT_length != 0) {
		icmp_err_ack(q, mp, TBADOPT, 0);
		return;
	}

	len = tcr->DEST_length;

	switch (len) {
	default:
		icmp_err_ack(q, mp, TBADADDR, 0);
		return;
	case sizeof (sin_t):
		sa = (struct sockaddr *)mi_offset_param(mp, tcr->DEST_offset,
		    sizeof (sin_t));
		break;
	case sizeof (sin6_t):
		sa = (struct sockaddr *)mi_offset_param(mp,
		    tcr->DEST_offset, sizeof (sin6_t));
		break;
	}

	error = proto_verify_ip_addr(connp->conn_family, sa, len);
	if (error != 0) {
		icmp_err_ack(q, mp, TSYSERR, error);
		return;
	}

	error = rawip_do_connect(connp, sa, len, cr, pid);
	if (error != 0) {
		if (error < 0) {
			icmp_err_ack(q, mp, -error, 0);
		} else {
			icmp_err_ack(q, mp, 0, error);
		}
	} else {
		mblk_t *mp1;

		/*
		 * We have to send a connection confirmation to
		 * keep TLI happy.
		 */
		if (connp->conn_family == AF_INET) {
			mp1 = mi_tpi_conn_con(NULL, (char *)sa,
			    sizeof (sin_t), NULL, 0);
		} else {
			ASSERT(connp->conn_family == AF_INET6);
			mp1 = mi_tpi_conn_con(NULL, (char *)sa,
			    sizeof (sin6_t), NULL, 0);
		}
		if (mp1 == NULL) {
			icmp_err_ack(q, mp, TSYSERR, ENOMEM);
			return;
		}

		/*
		 * Send ok_ack for T_CONN_REQ
		 */
		mp = mi_tpi_ok_ack_alloc(mp);
		if (mp == NULL) {
			/* Unable to reuse the T_CONN_REQ for the ack. */
			icmp_err_ack_prim(q, mp1, T_CONN_REQ, TSYSERR, ENOMEM);
			return;
		}
		putnext(connp->conn_rq, mp);
		putnext(connp->conn_rq, mp1);
	}
}

static int
rawip_do_connect(conn_t *connp, const struct sockaddr *sa, socklen_t len,
    cred_t *cr, pid_t pid)
{
	icmp_t		*icmp;
	sin_t		*sin;
	sin6_t		*sin6;
	int		error;
	uint16_t 	dstport;
	ipaddr_t	v4dst;
	in6_addr_t	v6dst;
	uint32_t	flowinfo;
	ip_xmit_attr_t	*ixa;
	ip_xmit_attr_t	*oldixa;
	uint_t		scopeid = 0;
	uint_t		srcid = 0;
	in6_addr_t	v6src = connp->conn_saddr_v6;

	icmp = connp->conn_icmp;

	if (sa == NULL || !OK_32PTR((char *)sa)) {
		return (EINVAL);
	}

	ASSERT(sa != NULL && len != 0);

	/*
	 * Determine packet type based on type of address passed in
	 * the request should contain an IPv4 or IPv6 address.
	 * Make sure that address family matches the type of
	 * family of the address passed down.
	 */
	switch (len) {
	case sizeof (sin_t):
		sin = (sin_t *)sa;

		v4dst = sin->sin_addr.s_addr;
		dstport = sin->sin_port;
		IN6_IPADDR_TO_V4MAPPED(v4dst, &v6dst);
		ASSERT(connp->conn_ipversion == IPV4_VERSION);
		break;

	case sizeof (sin6_t):
		sin6 = (sin6_t *)sa;

		/* No support for mapped addresses on raw sockets */
		if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
			return (EADDRNOTAVAIL);
		}
		v6dst = sin6->sin6_addr;
		dstport = sin6->sin6_port;
		ASSERT(connp->conn_ipversion == IPV6_VERSION);
		flowinfo = sin6->sin6_flowinfo;
		if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr))
			scopeid = sin6->sin6_scope_id;
		srcid = sin6->__sin6_src_id;
		if (srcid != 0 && IN6_IS_ADDR_UNSPECIFIED(&v6src)) {
			ip_srcid_find_id(srcid, &v6src, IPCL_ZONEID(connp),
			    connp->conn_netstack);
		}
		break;
	}

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
	 * This icmp_t must have bound already before doing a connect.
	 * Reject if a connect is in progress (we drop conn_lock during
	 * rawip_do_connect).
	 */
	if (icmp->icmp_state == TS_UNBND || icmp->icmp_state == TS_WCON_CREQ) {
		mutex_exit(&connp->conn_lock);
		ixa_refrele(ixa);
		return (-TOUTSTATE);
	}

	if (icmp->icmp_state == TS_DATA_XFER) {
		/* Already connected - clear out state */
		if (connp->conn_mcbc_bind)
			connp->conn_saddr_v6 = ipv6_all_zeros;
		else
			connp->conn_saddr_v6 = connp->conn_bound_addr_v6;
		connp->conn_laddr_v6 = connp->conn_bound_addr_v6;
		connp->conn_faddr_v6 = ipv6_all_zeros;
		icmp->icmp_state = TS_IDLE;
	}

	/*
	 * Use sin_port/sin6_port since applications like psh use SOCK_RAW
	 * with IPPROTO_TCP.
	 */
	connp->conn_fport = dstport;
	if (connp->conn_ipversion == IPV4_VERSION) {
		/*
		 * Interpret a zero destination to mean loopback.
		 * Update the T_CONN_REQ (sin/sin6) since it is used to
		 * generate the T_CONN_CON.
		 */
		if (v4dst == INADDR_ANY) {
			v4dst = htonl(INADDR_LOOPBACK);
			IN6_IPADDR_TO_V4MAPPED(v4dst, &v6dst);
			ASSERT(connp->conn_family == AF_INET);
			sin->sin_addr.s_addr = v4dst;
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
	 * To prevent a send* from messing with this icmp_t while the lock
	 * is dropped we set icmp_state and clear conn_v6lastdst.
	 * That will make all send* fail with EISCONN.
	 */
	connp->conn_v6lastdst = ipv6_all_zeros;
	icmp->icmp_state = TS_WCON_CREQ;

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
	error = icmp_build_hdr_template(connp, &connp->conn_saddr_v6,
	    &connp->conn_faddr_v6, connp->conn_flowinfo);
	if (error != 0) {
		mutex_exit(&connp->conn_lock);
		goto connect_failed;
	}

	icmp->icmp_state = TS_DATA_XFER;
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

	ixa_refrele(ixa);
	return (0);

connect_failed:
	if (ixa != NULL)
		ixa_refrele(ixa);
	mutex_enter(&connp->conn_lock);
	icmp->icmp_state = TS_IDLE;
	/* In case the source address was set above */
	if (connp->conn_mcbc_bind)
		connp->conn_saddr_v6 = ipv6_all_zeros;
	else
		connp->conn_saddr_v6 = connp->conn_bound_addr_v6;
	connp->conn_laddr_v6 = connp->conn_bound_addr_v6;
	connp->conn_faddr_v6 = ipv6_all_zeros;
	connp->conn_v6lastdst = ipv6_all_zeros;
	connp->conn_flowinfo = 0;

	(void) icmp_build_hdr_template(connp, &connp->conn_saddr_v6,
	    &connp->conn_faddr_v6, connp->conn_flowinfo);
	mutex_exit(&connp->conn_lock);
	return (error);
}

static void
rawip_do_close(conn_t *connp)
{
	ASSERT(connp != NULL && IPCL_IS_RAWIP(connp));

	ip_quiesce_conn(connp);

	if (!IPCL_IS_NONSTR(connp)) {
		qprocsoff(connp->conn_rq);
	}

	icmp_close_free(connp);

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

static int
icmp_close(queue_t *q, int flags)
{
	conn_t  *connp;

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
	(void) rawip_do_close(connp);
done:
	q->q_ptr = WR(q)->q_ptr = NULL;
	return (0);
}

static void
icmp_close_free(conn_t *connp)
{
	icmp_t *icmp = connp->conn_icmp;

	if (icmp->icmp_filter != NULL) {
		kmem_free(icmp->icmp_filter, sizeof (icmp6_filter_t));
		icmp->icmp_filter = NULL;
	}

	/*
	 * Clear any fields which the kmem_cache constructor clears.
	 * Only icmp_connp needs to be preserved.
	 * TBD: We should make this more efficient to avoid clearing
	 * everything.
	 */
	ASSERT(icmp->icmp_connp == connp);
	bzero(icmp, sizeof (icmp_t));
	icmp->icmp_connp = connp;
}

/*
 * This routine handles each T_DISCON_REQ message passed to icmp
 * as an indicating that ICMP is no longer connected. This results
 * in telling IP to restore the binding to just the local address.
 */
static int
icmp_do_disconnect(conn_t *connp)
{
	icmp_t	*icmp = connp->conn_icmp;
	int	error;

	mutex_enter(&connp->conn_lock);
	if (icmp->icmp_state != TS_DATA_XFER) {
		mutex_exit(&connp->conn_lock);
		return (-TOUTSTATE);
	}
	if (connp->conn_mcbc_bind)
		connp->conn_saddr_v6 = ipv6_all_zeros;
	else
		connp->conn_saddr_v6 = connp->conn_bound_addr_v6;
	connp->conn_laddr_v6 = connp->conn_bound_addr_v6;
	connp->conn_faddr_v6 = ipv6_all_zeros;
	icmp->icmp_state = TS_IDLE;

	connp->conn_v6lastdst = ipv6_all_zeros;
	error = icmp_build_hdr_template(connp, &connp->conn_saddr_v6,
	    &connp->conn_faddr_v6, connp->conn_flowinfo);
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
icmp_tpi_disconnect(queue_t *q, mblk_t *mp)
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
		icmp_err_ack_prim(q, mp, T_DISCON_REQ, TSYSERR, ENOMEM);
		return;
	}

	error = icmp_do_disconnect(connp);

	if (error != 0) {
		if (error > 0) {
			icmp_err_ack(q, mp, 0, error);
		} else {
			icmp_err_ack(q, mp, -error, 0);
		}
	} else {
		mp = mi_tpi_ok_ack_alloc(mp);
		ASSERT(mp != NULL);
		qreply(q, mp);
	}
}

static int
icmp_disconnect(conn_t *connp)
{
	int	error;

	connp->conn_dgram_errind = B_FALSE;

	error = icmp_do_disconnect(connp);

	if (error < 0)
		error = proto_tlitosyserr(-error);
	return (error);
}

/* This routine creates a T_ERROR_ACK message and passes it upstream. */
static void
icmp_err_ack(queue_t *q, mblk_t *mp, t_scalar_t t_error, int sys_error)
{
	if ((mp = mi_tpi_err_ack_alloc(mp, t_error, sys_error)) != NULL)
		qreply(q, mp);
}

/* Shorthand to generate and send TPI error acks to our client */
static void
icmp_err_ack_prim(queue_t *q, mblk_t *mp, t_scalar_t primitive,
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

/*
 * icmp_icmp_input is called as conn_recvicmp to process ICMP messages.
 * Generates the appropriate T_UDERROR_IND for permanent (non-transient) errors.
 * Assumes that IP has pulled up everything up to and including the ICMP header.
 */
/* ARGSUSED2 */
static void
icmp_icmp_input(void *arg1, mblk_t *mp, void *arg2, ip_recv_attr_t *ira)
{
	conn_t		*connp = (conn_t *)arg1;
	icmp_t		*icmp = connp->conn_icmp;
	icmph_t		*icmph;
	ipha_t		*ipha;
	int		iph_hdr_length;
	sin_t		sin;
	mblk_t		*mp1;
	int		error = 0;

	ipha = (ipha_t *)mp->b_rptr;

	ASSERT(OK_32PTR(mp->b_rptr));

	if (IPH_HDR_VERSION(ipha) != IPV4_VERSION) {
		ASSERT(IPH_HDR_VERSION(ipha) == IPV6_VERSION);
		icmp_icmp_error_ipv6(connp, mp, ira);
		return;
	}
	ASSERT(IPH_HDR_VERSION(ipha) == IPV4_VERSION);

	/* Skip past the outer IP and ICMP headers */
	ASSERT(IPH_HDR_LENGTH(ipha) == ira->ira_ip_hdr_length);
	iph_hdr_length = ira->ira_ip_hdr_length;
	icmph = (icmph_t *)&mp->b_rptr[iph_hdr_length];
	ipha = (ipha_t *)&icmph[1];	/* Inner IP header */

	iph_hdr_length = IPH_HDR_LENGTH(ipha);

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

	sin = sin_null;
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = ipha->ipha_dst;

	if (IPCL_IS_NONSTR(connp)) {
		mutex_enter(&connp->conn_lock);
		if (icmp->icmp_state == TS_DATA_XFER) {
			if (sin.sin_addr.s_addr == connp->conn_faddr_v4) {
				mutex_exit(&connp->conn_lock);
				(*connp->conn_upcalls->su_set_error)
				    (connp->conn_upper_handle, error);
				goto done;
			}
		} else {
			icmp->icmp_delayed_error = error;
			*((sin_t *)&icmp->icmp_delayed_addr) = sin;
		}
		mutex_exit(&connp->conn_lock);
	} else {
		mp1 = mi_tpi_uderror_ind((char *)&sin, sizeof (sin_t), NULL, 0,
		    error);
		if (mp1 != NULL)
			putnext(connp->conn_rq, mp1);
	}
done:
	freemsg(mp);
}

/*
 * icmp_icmp_error_ipv6 is called by icmp_icmp_error to process ICMP for IPv6.
 * Generates the appropriate T_UDERROR_IND for permanent (non-transient) errors.
 * Assumes that IP has pulled up all the extension headers as well as the
 * ICMPv6 header.
 */
static void
icmp_icmp_error_ipv6(conn_t *connp, mblk_t *mp, ip_recv_attr_t *ira)
{
	icmp6_t		*icmp6;
	ip6_t		*ip6h, *outer_ip6h;
	uint16_t	iph_hdr_length;
	uint8_t		*nexthdrp;
	sin6_t		sin6;
	mblk_t		*mp1;
	int		error = 0;
	icmp_t		*icmp = connp->conn_icmp;

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

	ip6h = (ip6_t *)&icmp6[1];	/* Inner IP header */
	if (!ip_hdr_length_nexthdr_v6(mp, ip6h, &iph_hdr_length, &nexthdrp)) {
		freemsg(mp);
		return;
	}

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
			BUMP_MIB(&icmp->icmp_is->is_rawip_mib, rawipInErrors);
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
		icmp_ulp_recv(connp, newmp, msgdsize(newmp));
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
	sin6.sin6_flowinfo = ip6h->ip6_vcf & ~IPV6_VERS_AND_FLOW_MASK;
	if (IPCL_IS_NONSTR(connp)) {
		mutex_enter(&connp->conn_lock);
		if (icmp->icmp_state == TS_DATA_XFER) {
			if (IN6_ARE_ADDR_EQUAL(&sin6.sin6_addr,
			    &connp->conn_faddr_v6)) {
				mutex_exit(&connp->conn_lock);
				(*connp->conn_upcalls->su_set_error)
				    (connp->conn_upper_handle, error);
				goto done;
			}
		} else {
			icmp->icmp_delayed_error = error;
			*((sin6_t *)&icmp->icmp_delayed_addr) = sin6;
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
 * This routine responds to T_ADDR_REQ messages.  It is called by icmp_wput.
 * The local address is filled in if endpoint is bound. The remote address
 * is filled in if remote address has been precified ("connected endpoint")
 * (The concept of connected CLTS sockets is alien to published TPI
 *  but we support it anyway).
 */
static void
icmp_addr_req(queue_t *q, mblk_t *mp)
{
	struct sockaddr *sa;
	mblk_t	*ackmp;
	struct T_addr_ack *taa;
	icmp_t	*icmp = Q_TO_ICMP(q);
	conn_t	*connp = icmp->icmp_connp;
	uint_t	addrlen;

	/* Make it large enough for worst case */
	ackmp = reallocb(mp, sizeof (struct T_addr_ack) +
	    2 * sizeof (sin6_t), 1);
	if (ackmp == NULL) {
		icmp_err_ack(q, mp, TSYSERR, ENOMEM);
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
	if (icmp->icmp_state != TS_UNBND) {
		/*
		 * Fill in local address first
		 */
		taa->LOCADDR_offset = sizeof (*taa);
		taa->LOCADDR_length = addrlen;
		sa = (struct sockaddr *)&taa[1];
		(void) conn_getsockname(connp, sa, &addrlen);
		ackmp->b_wptr += addrlen;
	}
	if (icmp->icmp_state == TS_DATA_XFER) {
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
icmp_copy_info(struct T_info_ack *tap, icmp_t *icmp)
{
	conn_t		*connp = icmp->icmp_connp;

	*tap = icmp_g_t_info_ack;

	if (connp->conn_family == AF_INET6)
		tap->ADDR_size = sizeof (sin6_t);
	else
		tap->ADDR_size = sizeof (sin_t);
	tap->CURRENT_state = icmp->icmp_state;
	tap->OPT_size = icmp_max_optsize;
}

static void
icmp_do_capability_ack(icmp_t *icmp, struct T_capability_ack *tcap,
    t_uscalar_t cap_bits1)
{
	tcap->CAP_bits1 = 0;

	if (cap_bits1 & TC1_INFO) {
		icmp_copy_info(&tcap->INFO_ack, icmp);
		tcap->CAP_bits1 |= TC1_INFO;
	}
}

/*
 * This routine responds to T_CAPABILITY_REQ messages.  It is called by
 * icmp_wput.  Much of the T_CAPABILITY_ACK information is copied from
 * icmp_g_t_info_ack.  The current state of the stream is copied from
 * icmp_state.
 */
static void
icmp_capability_req(queue_t *q, mblk_t *mp)
{
	icmp_t			*icmp = Q_TO_ICMP(q);
	t_uscalar_t		cap_bits1;
	struct T_capability_ack	*tcap;

	cap_bits1 = ((struct T_capability_req *)mp->b_rptr)->CAP_bits1;

	mp = tpi_ack_alloc(mp, sizeof (struct T_capability_ack),
	    mp->b_datap->db_type, T_CAPABILITY_ACK);
	if (!mp)
		return;

	tcap = (struct T_capability_ack *)mp->b_rptr;

	icmp_do_capability_ack(icmp, tcap, cap_bits1);

	qreply(q, mp);
}

/*
 * This routine responds to T_INFO_REQ messages.  It is called by icmp_wput.
 * Most of the T_INFO_ACK information is copied from icmp_g_t_info_ack.
 * The current state of the stream is copied from icmp_state.
 */
static void
icmp_info_req(queue_t *q, mblk_t *mp)
{
	icmp_t	*icmp = Q_TO_ICMP(q);

	/* Create a T_INFO_ACK message. */
	mp = tpi_ack_alloc(mp, sizeof (struct T_info_ack), M_PCPROTO,
	    T_INFO_ACK);
	if (!mp)
		return;
	icmp_copy_info((struct T_info_ack *)mp->b_rptr, icmp);
	qreply(q, mp);
}

static int
icmp_tpi_open(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp,
    int family)
{
	conn_t *connp;
	dev_t	conn_dev;
	int	error;

	/* If the stream is already open, return immediately. */
	if (q->q_ptr != NULL)
		return (0);

	if (sflag == MODOPEN)
		return (EINVAL);

	/*
	 * Since ICMP is not used so heavily, allocating from the small
	 * arena should be sufficient.
	 */
	if ((conn_dev = inet_minor_alloc(ip_minor_arena_sa)) == 0) {
		return (EBUSY);
	}

	if (flag & SO_FALLBACK) {
		/*
		 * Non streams socket needs a stream to fallback to
		 */
		RD(q)->q_ptr = (void *)conn_dev;
		WR(q)->q_qinfo = &icmp_fallback_sock_winit;
		WR(q)->q_ptr = (void *)ip_minor_arena_sa;
		qprocson(q);
		return (0);
	}

	connp = rawip_do_open(family, credp, &error, KM_SLEEP);
	if (connp == NULL) {
		ASSERT(error != 0);
		inet_minor_free(ip_minor_arena_sa, conn_dev);
		return (error);
	}

	*devp = makedevice(getemajor(*devp), (minor_t)conn_dev);
	connp->conn_dev = conn_dev;
	connp->conn_minor_arena = ip_minor_arena_sa;

	/*
	 * Initialize the icmp_t structure for this stream.
	 */
	q->q_ptr = connp;
	WR(q)->q_ptr = connp;
	connp->conn_rq = q;
	connp->conn_wq = WR(q);

	WR(q)->q_hiwat = connp->conn_sndbuf;
	WR(q)->q_lowat = connp->conn_sndlowat;

	qprocson(q);

	/* Set the Stream head write offset. */
	(void) proto_set_tx_wroff(q, connp, connp->conn_wroff);
	(void) proto_set_rx_hiwat(connp->conn_rq, connp, connp->conn_rcvbuf);

	mutex_enter(&connp->conn_lock);
	connp->conn_state_flags &= ~CONN_INCIPIENT;
	mutex_exit(&connp->conn_lock);

	icmp_bind_proto(connp->conn_icmp);

	return (0);
}

/* For /dev/icmp aka AF_INET open */
static int
icmp_openv4(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	return (icmp_tpi_open(q, devp, flag, sflag, credp, AF_INET));
}

/* For /dev/icmp6 aka AF_INET6 open */
static int
icmp_openv6(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	return (icmp_tpi_open(q, devp, flag, sflag, credp, AF_INET6));
}

/*
 * This is the open routine for icmp.  It allocates a icmp_t structure for
 * the stream and, on the first open of the module, creates an ND table.
 */
static conn_t *
rawip_do_open(int family, cred_t *credp, int *err, int flags)
{
	icmp_t	*icmp;
	conn_t *connp;
	zoneid_t zoneid;
	netstack_t *ns;
	icmp_stack_t *is;
	int len;
	boolean_t isv6 = B_FALSE;

	*err = secpolicy_net_icmpaccess(credp);
	if (*err != 0)
		return (NULL);

	if (family == AF_INET6)
		isv6 = B_TRUE;

	ns = netstack_find_by_cred(credp);
	ASSERT(ns != NULL);
	is = ns->netstack_icmp;
	ASSERT(is != NULL);

	/*
	 * For exclusive stacks we set the zoneid to zero
	 * to make ICMP operate as if in the global zone.
	 */
	if (ns->netstack_stackid != GLOBAL_NETSTACKID)
		zoneid = GLOBAL_ZONEID;
	else
		zoneid = crgetzoneid(credp);

	ASSERT(flags == KM_SLEEP || flags == KM_NOSLEEP);

	connp = ipcl_conn_create(IPCL_RAWIPCONN, flags, ns);
	icmp = connp->conn_icmp;

	/*
	 * ipcl_conn_create did a netstack_hold. Undo the hold that was
	 * done by netstack_find_by_cred()
	 */
	netstack_rele(ns);

	/*
	 * Since this conn_t/icmp_t is not yet visible to anybody else we don't
	 * need to lock anything.
	 */
	ASSERT(connp->conn_proto == IPPROTO_ICMP);
	ASSERT(connp->conn_icmp == icmp);
	ASSERT(icmp->icmp_connp == connp);

	/* Set the initial state of the stream and the privilege status. */
	icmp->icmp_state = TS_UNBND;
	connp->conn_ixa->ixa_flags |= IXAF_VERIFY_SOURCE;
	if (isv6) {
		connp->conn_family = AF_INET6;
		connp->conn_ipversion = IPV6_VERSION;
		connp->conn_ixa->ixa_flags &= ~IXAF_IS_IPV4;
		connp->conn_proto = IPPROTO_ICMPV6;
		/* May be changed by a SO_PROTOTYPE socket option. */
		connp->conn_proto = IPPROTO_ICMPV6;
		connp->conn_ixa->ixa_protocol = connp->conn_proto;
		connp->conn_ixa->ixa_raw_cksum_offset = 2;
		connp->conn_default_ttl = is->is_ipv6_hoplimit;
		len = sizeof (ip6_t);
	} else {
		connp->conn_family = AF_INET;
		connp->conn_ipversion = IPV4_VERSION;
		connp->conn_ixa->ixa_flags |= IXAF_IS_IPV4;
		/* May be changed by a SO_PROTOTYPE socket option. */
		connp->conn_proto = IPPROTO_ICMP;
		connp->conn_ixa->ixa_protocol = connp->conn_proto;
		connp->conn_default_ttl = is->is_ipv4_ttl;
		len = sizeof (ipha_t);
	}
	connp->conn_xmit_ipp.ipp_unicast_hops = connp->conn_default_ttl;

	connp->conn_ixa->ixa_multicast_ttl = IP_DEFAULT_MULTICAST_TTL;

	/*
	 * For the socket of protocol IPPROTO_RAW or when IP_HDRINCL is set,
	 * the checksum is provided in the pre-built packet. We clear
	 * IXAF_SET_ULP_CKSUM to tell IP that the application has sent a
	 * complete IP header and not to compute the transport checksum.
	 */
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

	icmp->icmp_is = is;

	connp->conn_rcvbuf = is->is_recv_hiwat;
	connp->conn_sndbuf = is->is_xmit_hiwat;
	connp->conn_sndlowat = is->is_xmit_lowat;
	connp->conn_rcvlowat = icmp_mod_info.mi_lowat;

	connp->conn_wroff = len + is->is_wroff_extra;
	connp->conn_so_type = SOCK_RAW;

	connp->conn_recv = icmp_input;
	connp->conn_recvicmp = icmp_icmp_input;
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

	connp->conn_flow_cntrld = B_FALSE;

	if (is->is_pmtu_discovery)
		connp->conn_ixa->ixa_flags |= IXAF_PMTU_DISCOVERY;

	return (connp);
}

/*
 * Which ICMP options OK to set through T_UNITDATA_REQ...
 */
/* ARGSUSED */
static boolean_t
icmp_opt_allow_udr_set(t_scalar_t level, t_scalar_t name)
{
	return (B_TRUE);
}

/*
 * This routine gets default values of certain options whose default
 * values are maintained by protcol specific code
 */
int
icmp_opt_default(queue_t *q, t_scalar_t level, t_scalar_t name, uchar_t *ptr)
{
	icmp_t *icmp = Q_TO_ICMP(q);
	icmp_stack_t *is = icmp->icmp_is;
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
			*i1 = is->is_ipv6_hoplimit;
			return (sizeof (int));
		}
		break;
	case IPPROTO_ICMPV6:
		switch (name) {
		case ICMP6_FILTER:
			/* Make it look like "pass all" */
			ICMP6_FILTER_SETPASSALL((icmp6_filter_t *)ptr);
			return (sizeof (icmp6_filter_t));
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
icmp_opt_get(conn_t *connp, int level, int name, uchar_t *ptr)
{
	icmp_t		*icmp = connp->conn_icmp;
	int		*i1 = (int *)ptr;
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
	 * First check for ICMP specific handling, then pass to common routine.
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
			/* Options are passed up with each packet */
			return (0);
		case IP_HDRINCL:
			mutex_enter(&connp->conn_lock);
			*i1 = (int)icmp->icmp_hdrincl;
			mutex_exit(&connp->conn_lock);
			return (sizeof (int));
		}
		break;

	case IPPROTO_IPV6:
		/*
		 * Only allow IPv6 option processing on native IPv6 sockets.
		 */
		if (connp->conn_family != AF_INET6)
			return (-1);

		switch (name) {
		case IPV6_CHECKSUM:
			/*
			 * Return offset or -1 if no checksum offset.
			 * Does not apply to IPPROTO_ICMPV6
			 */
			if (connp->conn_proto == IPPROTO_ICMPV6)
				return (-1);

			mutex_enter(&connp->conn_lock);
			if (connp->conn_ixa->ixa_flags & IXAF_SET_RAW_CKSUM)
				*i1 = connp->conn_ixa->ixa_raw_cksum_offset;
			else
				*i1 = -1;
			mutex_exit(&connp->conn_lock);
			return (sizeof (int));
		}
		break;

	case IPPROTO_ICMPV6:
		/*
		 * Only allow IPv6 option processing on native IPv6 sockets.
		 */
		if (connp->conn_family != AF_INET6)
			return (-1);

		if (connp->conn_proto != IPPROTO_ICMPV6)
			return (-1);

		switch (name) {
		case ICMP6_FILTER:
			mutex_enter(&connp->conn_lock);
			if (icmp->icmp_filter == NULL) {
				/* Make it look like "pass all" */
				ICMP6_FILTER_SETPASSALL((icmp6_filter_t *)ptr);
			} else {
				(void) bcopy(icmp->icmp_filter, ptr,
				    sizeof (icmp6_filter_t));
			}
			mutex_exit(&connp->conn_lock);
			return (sizeof (icmp6_filter_t));
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
icmp_tpi_opt_get(queue_t *q, int level, int name, uchar_t *ptr)
{
	conn_t		*connp = Q_TO_CONN(q);
	int 		err;

	err = icmp_opt_get(connp, level, name, ptr);
	return (err);
}

/*
 * This routine sets socket options.
 */
int
icmp_do_opt_set(conn_opt_arg_t *coa, int level, int name,
    uint_t inlen, uchar_t *invalp, cred_t *cr, boolean_t checkonly)
{
	conn_t		*connp = coa->coa_connp;
	ip_xmit_attr_t	*ixa = coa->coa_ixa;
	icmp_t		*icmp = connp->conn_icmp;
	icmp_stack_t	*is = icmp->icmp_is;
	int		*i1 = (int *)invalp;
	boolean_t	onoff = (*i1 == 0) ? 0 : 1;
	int		error;

	ASSERT(MUTEX_NOT_HELD(&coa->coa_connp->conn_lock));

	/*
	 * For fixed length options, no sanity check
	 * of passed in length is done. It is assumed *_optcom_req()
	 * routines do the right thing.
	 */

	switch (level) {
	case SOL_SOCKET:
		switch (name) {
		case SO_PROTOTYPE:
			if ((*i1 & 0xFF) != IPPROTO_ICMP &&
			    (*i1 & 0xFF) != IPPROTO_ICMPV6 &&
			    secpolicy_net_rawaccess(cr) != 0) {
				return (EACCES);
			}
			if (checkonly)
				break;

			mutex_enter(&connp->conn_lock);
			connp->conn_proto = *i1 & 0xFF;
			ixa->ixa_protocol = connp->conn_proto;
			if ((connp->conn_proto == IPPROTO_RAW ||
			    connp->conn_proto == IPPROTO_IGMP) &&
			    connp->conn_family == AF_INET) {
				icmp->icmp_hdrincl = 1;
				ixa->ixa_flags &= ~IXAF_SET_ULP_CKSUM;
			} else if (connp->conn_proto == IPPROTO_UDP ||
			    connp->conn_proto == IPPROTO_TCP ||
			    connp->conn_proto == IPPROTO_SCTP) {
				/* Used by test applications like psh */
				icmp->icmp_hdrincl = 0;
				ixa->ixa_flags &= ~IXAF_SET_ULP_CKSUM;
			} else {
				icmp->icmp_hdrincl = 0;
				ixa->ixa_flags |= IXAF_SET_ULP_CKSUM;
			}

			if (connp->conn_family == AF_INET6 &&
			    connp->conn_proto == IPPROTO_ICMPV6) {
				/* Set offset for icmp6_cksum */
				ixa->ixa_flags &= ~IXAF_SET_RAW_CKSUM;
				ixa->ixa_raw_cksum_offset = 2;
			}
			if (icmp->icmp_filter != NULL &&
			    connp->conn_proto != IPPROTO_ICMPV6) {
				kmem_free(icmp->icmp_filter,
				    sizeof (icmp6_filter_t));
				icmp->icmp_filter = NULL;
			}
			mutex_exit(&connp->conn_lock);

			coa->coa_changed |= COA_HEADER_CHANGED;
			/*
			 * For SCTP, we don't use icmp_bind_proto() for
			 * raw socket binding.
			 */
			if (connp->conn_proto == IPPROTO_SCTP)
				return (0);

			coa->coa_changed |= COA_ICMP_BIND_NEEDED;
			return (0);

		case SO_SNDBUF:
			if (*i1 > is->is_max_buf) {
				return (ENOBUFS);
			}
			break;
		case SO_RCVBUF:
			if (*i1 > is->is_max_buf) {
				return (ENOBUFS);
			}
			break;
		}
		break;

	case IPPROTO_IP:
		/*
		 * Only allow IPv4 option processing on IPv4 sockets.
		 */
		if (connp->conn_family != AF_INET)
			return (EINVAL);

		switch (name) {
		case IP_HDRINCL:
			if (!checkonly) {
				mutex_enter(&connp->conn_lock);
				icmp->icmp_hdrincl = onoff;
				if (onoff)
					ixa->ixa_flags &= ~IXAF_SET_ULP_CKSUM;
				else
					ixa->ixa_flags |= IXAF_SET_ULP_CKSUM;
				mutex_exit(&connp->conn_lock);
			}
			break;
		}
		break;

	case IPPROTO_IPV6:
		if (connp->conn_family != AF_INET6)
			return (EINVAL);

		switch (name) {
		case IPV6_CHECKSUM:
			/*
			 * Integer offset into the user data of where the
			 * checksum is located.
			 * Offset of -1 disables option.
			 * Does not apply to IPPROTO_ICMPV6.
			 */
			if (connp->conn_proto == IPPROTO_ICMPV6 ||
			    coa->coa_ancillary) {
				return (EINVAL);
			}
			if ((*i1 != -1) && ((*i1 < 0) || (*i1 & 0x1) != 0)) {
				/* Negative or not 16 bit aligned offset */
				return (EINVAL);
			}
			if (checkonly)
				break;

			mutex_enter(&connp->conn_lock);
			if (*i1 == -1) {
				ixa->ixa_flags &= ~IXAF_SET_RAW_CKSUM;
				ixa->ixa_raw_cksum_offset = 0;
				ixa->ixa_flags &= ~IXAF_SET_ULP_CKSUM;
			} else {
				ixa->ixa_flags |= IXAF_SET_RAW_CKSUM;
				ixa->ixa_raw_cksum_offset = *i1;
				ixa->ixa_flags |= IXAF_SET_ULP_CKSUM;
			}
			mutex_exit(&connp->conn_lock);
			break;
		}
		break;

	case IPPROTO_ICMPV6:
		/*
		 * Only allow IPv6 option processing on IPv6 sockets.
		 */
		if (connp->conn_family != AF_INET6)
			return (EINVAL);
		if (connp->conn_proto != IPPROTO_ICMPV6)
			return (EINVAL);

		switch (name) {
		case ICMP6_FILTER:
			if (checkonly)
				break;

			if ((inlen != 0) &&
			    (inlen != sizeof (icmp6_filter_t)))
				return (EINVAL);

			mutex_enter(&connp->conn_lock);
			if (inlen == 0) {
				if (icmp->icmp_filter != NULL) {
					kmem_free(icmp->icmp_filter,
					    sizeof (icmp6_filter_t));
					icmp->icmp_filter = NULL;
				}
			} else {
				if (icmp->icmp_filter == NULL) {
					icmp->icmp_filter = kmem_alloc(
					    sizeof (icmp6_filter_t),
					    KM_NOSLEEP);
					if (icmp->icmp_filter == NULL) {
						mutex_exit(&connp->conn_lock);
						return (ENOBUFS);
					}
				}
				(void) bcopy(invalp, icmp->icmp_filter, inlen);
			}
			mutex_exit(&connp->conn_lock);
			break;
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
icmp_opt_set(conn_t *connp, uint_t optset_context, int level, int name,
    uint_t inlen, uchar_t *invalp, uint_t *outlenp, uchar_t *outvalp,
    void *thisdg_attrs, cred_t *cr)
{
	icmp_t		*icmp = connp->conn_icmp;
	int		err;
	conn_opt_arg_t	coas, *coa;
	boolean_t	checkonly;
	icmp_stack_t	*is = icmp->icmp_is;

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
		if (!icmp_opt_allow_udr_set(level, name)) {
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

	err = icmp_do_opt_set(coa, level, name, inlen, invalp,
	    cr, checkonly);
	if (err != 0) {
errout:
		if (!coa->coa_ancillary)
			ixa_refrele(coa->coa_ixa);
		*outlenp = 0;
		return (err);
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
			err = icmp_build_hdr_template(connp,
			    &connp->conn_saddr_v6, &connp->conn_faddr_v6,
			    connp->conn_flowinfo);
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
		wroff = connp->conn_ht_iphc_allocated + is->is_wroff_extra;
		if (wroff > connp->conn_wroff) {
			connp->conn_wroff = wroff;
			mutex_exit(&connp->conn_lock);
			(void) proto_set_tx_wroff(connp->conn_rq, connp, wroff);
		} else {
			mutex_exit(&connp->conn_lock);
		}
	}
	if (coa->coa_changed & COA_ICMP_BIND_NEEDED) {
		icmp_bind_proto(icmp);
	}
	return (err);
}

/* This routine sets socket options. */
int
icmp_tpi_opt_set(queue_t *q, uint_t optset_context, int level, int name,
    uint_t inlen, uchar_t *invalp, uint_t *outlenp, uchar_t *outvalp,
    void *thisdg_attrs, cred_t *cr)
{
	conn_t	*connp = Q_TO_CONN(q);
	int error;

	error = icmp_opt_set(connp, optset_context, level, name, inlen, invalp,
	    outlenp, outvalp, thisdg_attrs, cr);
	return (error);
}

/*
 * Setup IP headers.
 *
 * Note that IP_HDRINCL has ipha_protocol that is different than conn_proto,
 * but icmp_output_hdrincl restores ipha_protocol once we return.
 */
mblk_t *
icmp_prepend_hdr(conn_t *connp, ip_xmit_attr_t *ixa, const ip_pkt_t *ipp,
    const in6_addr_t *v6src, const in6_addr_t *v6dst, uint32_t flowinfo,
    mblk_t *data_mp, int *errorp)
{
	mblk_t		*mp;
	icmp_stack_t	*is = connp->conn_netstack->netstack_icmp;
	uint_t		data_len;
	uint32_t	cksum;

	data_len = msgdsize(data_mp);
	mp = conn_prepend_hdr(ixa, ipp, v6src, v6dst, connp->conn_proto,
	    flowinfo, 0, data_mp, data_len, is->is_wroff_extra, &cksum, errorp);
	if (mp == NULL) {
		ASSERT(*errorp != 0);
		return (NULL);
	}

	ixa->ixa_pktlen = data_len + ixa->ixa_ip_hdr_length;

	/*
	 * If there was a routing option/header then conn_prepend_hdr
	 * has massaged it and placed the pseudo-header checksum difference
	 * in the cksum argument.
	 *
	 * Prepare for ICMPv6 checksum done in IP.
	 *
	 * We make it easy for IP to include our pseudo header
	 * by putting our length (and any routing header adjustment)
	 * in the ICMPv6 checksum field.
	 * The IP source, destination, and length have already been set by
	 * conn_prepend_hdr.
	 */
	cksum += data_len;
	cksum = (cksum >> 16) + (cksum & 0xFFFF);
	ASSERT(cksum < 0x10000);

	if (ixa->ixa_flags & IXAF_IS_IPV4) {
		ipha_t	*ipha = (ipha_t *)mp->b_rptr;

		ASSERT(ntohs(ipha->ipha_length) == ixa->ixa_pktlen);
	} else {
		ip6_t	*ip6h = (ip6_t *)mp->b_rptr;
		uint_t	cksum_offset = 0;

		ASSERT(ntohs(ip6h->ip6_plen) + IPV6_HDR_LEN == ixa->ixa_pktlen);

		if (ixa->ixa_flags & IXAF_SET_ULP_CKSUM) {
			if (connp->conn_proto == IPPROTO_ICMPV6) {
				cksum_offset = ixa->ixa_ip_hdr_length +
				    offsetof(icmp6_t, icmp6_cksum);
			} else if (ixa->ixa_flags & IXAF_SET_RAW_CKSUM) {
				cksum_offset = ixa->ixa_ip_hdr_length +
				    ixa->ixa_raw_cksum_offset;
			}
		}
		if (cksum_offset != 0) {
			uint16_t *ptr;

			/* Make sure the checksum fits in the first mblk */
			if (cksum_offset + sizeof (short) > MBLKL(mp)) {
				mblk_t *mp1;

				mp1 = msgpullup(mp,
				    cksum_offset + sizeof (short));
				freemsg(mp);
				if (mp1 == NULL) {
					*errorp = ENOMEM;
					return (NULL);
				}
				mp = mp1;
				ip6h = (ip6_t *)mp->b_rptr;
			}
			ptr = (uint16_t *)(mp->b_rptr + cksum_offset);
			*ptr = htons(cksum);
		}
	}

	/* Note that we don't try to update wroff due to ancillary data */
	return (mp);
}

static int
icmp_build_hdr_template(conn_t *connp, const in6_addr_t *v6src,
    const in6_addr_t *v6dst, uint32_t flowinfo)
{
	int		error;

	ASSERT(MUTEX_HELD(&connp->conn_lock));
	/*
	 * We clear lastdst to make sure we don't use the lastdst path
	 * next time sending since we might not have set v6dst yet.
	 */
	connp->conn_v6lastdst = ipv6_all_zeros;

	error = conn_build_hdr_template(connp, 0, 0, v6src, v6dst, flowinfo);
	if (error != 0)
		return (error);

	/*
	 * Any routing header/option has been massaged. The checksum difference
	 * is stored in conn_sum.
	 */
	return (0);
}

static mblk_t *
icmp_queue_fallback(icmp_t *icmp, mblk_t *mp)
{
	ASSERT(MUTEX_HELD(&icmp->icmp_recv_lock));
	if (IPCL_IS_NONSTR(icmp->icmp_connp)) {
		/*
		 * fallback has started but messages have not been moved yet
		 */
		if (icmp->icmp_fallback_queue_head == NULL) {
			ASSERT(icmp->icmp_fallback_queue_tail == NULL);
			icmp->icmp_fallback_queue_head = mp;
			icmp->icmp_fallback_queue_tail = mp;
		} else {
			ASSERT(icmp->icmp_fallback_queue_tail != NULL);
			icmp->icmp_fallback_queue_tail->b_next = mp;
			icmp->icmp_fallback_queue_tail = mp;
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
icmp_ulp_recv(conn_t *connp, mblk_t *mp, uint_t len)
{
	if (IPCL_IS_NONSTR(connp)) {
		icmp_t *icmp = connp->conn_icmp;
		int error;

		ASSERT(len == msgdsize(mp));
		if ((*connp->conn_upcalls->su_recv)
		    (connp->conn_upper_handle, mp, len, 0, &error, NULL) < 0) {
			mutex_enter(&icmp->icmp_recv_lock);
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
				mutex_exit(&icmp->icmp_recv_lock);
			} else {
				ASSERT(error == EOPNOTSUPP);
				mp = icmp_queue_fallback(icmp, mp);
				mutex_exit(&icmp->icmp_recv_lock);
				if (mp != NULL)
					putnext(connp->conn_rq, mp);
			}
		}
		ASSERT(MUTEX_NOT_HELD(&icmp->icmp_recv_lock));
	} else {
		putnext(connp->conn_rq, mp);
	}
}

/*
 * This is the inbound data path.
 * IP has already pulled up the IP headers and verified alignment
 * etc.
 */
/* ARGSUSED2 */
static void
icmp_input(void *arg1, mblk_t *mp, void *arg2, ip_recv_attr_t *ira)
{
	conn_t			*connp = (conn_t *)arg1;
	struct T_unitdata_ind	*tudi;
	uchar_t			*rptr;		/* Pointer to IP header */
	int			ip_hdr_length;
	int			udi_size;	/* Size of T_unitdata_ind */
	int			pkt_len;
	icmp_t			*icmp;
	ip_pkt_t		ipps;
	ip6_t			*ip6h;
	mblk_t			*mp1;
	crb_t			recv_ancillary;
	icmp_stack_t		*is;
	sin_t			*sin;
	sin6_t			*sin6;
	ipha_t			*ipha;

	ASSERT(connp->conn_flags & IPCL_RAWIPCONN);

	icmp = connp->conn_icmp;
	is = icmp->icmp_is;
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
	recv_ancillary = connp->conn_recv_ancillary;
	mutex_exit(&connp->conn_lock);

	ip_hdr_length = ira->ira_ip_hdr_length;
	ASSERT(MBLKL(mp) >= ip_hdr_length);	/* IP did a pullup */

	/* Initialize regardless of IP version */
	ipps.ipp_fields = 0;

	if (ira->ira_flags & IRAF_IS_IPV4) {
		ASSERT(IPH_HDR_VERSION(rptr) == IPV4_VERSION);
		ASSERT(MBLKL(mp) >= sizeof (ipha_t));
		ASSERT(ira->ira_ip_hdr_length == IPH_HDR_LENGTH(rptr));

		ipha = (ipha_t *)mp->b_rptr;
		if (recv_ancillary.crb_all != 0)
			(void) ip_find_hdr_v4(ipha, &ipps, B_FALSE);

		/*
		 * BSD for some reason adjusts ipha_length to exclude the
		 * IP header length. We do the same.
		 */
		if (is->is_bsd_compat) {
			ushort_t len;

			len = ntohs(ipha->ipha_length);
			if (mp->b_datap->db_ref > 1) {
				/*
				 * Allocate a new IP header so that we can
				 * modify ipha_length.
				 */
				mblk_t	*mp1;

				mp1 = allocb(ip_hdr_length, BPRI_MED);
				if (mp1 == NULL) {
					freemsg(mp);
					BUMP_MIB(&is->is_rawip_mib,
					    rawipInErrors);
					return;
				}
				bcopy(rptr, mp1->b_rptr, ip_hdr_length);
				mp->b_rptr = rptr + ip_hdr_length;
				rptr = mp1->b_rptr;
				ipha = (ipha_t *)rptr;
				mp1->b_cont = mp;
				mp1->b_wptr = rptr + ip_hdr_length;
				mp = mp1;
			}
			len -= ip_hdr_length;
			ipha->ipha_length = htons(len);
		}

		/*
		 * For RAW sockets we not pass ICMP/IPv4 packets to AF_INET6
		 * sockets. This is ensured by icmp_bind and the IP fanout code.
		 */
		ASSERT(connp->conn_family == AF_INET);

		/*
		 * This is the inbound data path.  Packets are passed upstream
		 * as T_UNITDATA_IND messages with full IPv4 headers still
		 * attached.
		 */

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
			BUMP_MIB(&is->is_rawip_mib, rawipInErrors);
			return;
		}
		mp1->b_cont = mp;
		tudi = (struct T_unitdata_ind *)mp1->b_rptr;
		mp1->b_datap->db_type = M_PROTO;
		mp1->b_wptr = (uchar_t *)tudi + udi_size;
		tudi->PRIM_type = T_UNITDATA_IND;
		tudi->SRC_length = sizeof (sin_t);
		tudi->SRC_offset = sizeof (struct T_unitdata_ind);
		sin = (sin_t *)&tudi[1];
		*sin = sin_null;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = ipha->ipha_src;
		*(uint32_t *)&sin->sin_zero[0] = 0;
		*(uint32_t *)&sin->sin_zero[4] = 0;
		tudi->OPT_offset =  sizeof (struct T_unitdata_ind) +
		    sizeof (sin_t);
		udi_size -= (sizeof (struct T_unitdata_ind) + sizeof (sin_t));
		tudi->OPT_length = udi_size;

		/*
		 * Add options if IP_RECVIF etc is set
		 */
		if (udi_size != 0) {
			conn_recvancillary_add(connp, recv_ancillary, ira,
			    &ipps, (uchar_t *)&sin[1], udi_size);
		}
		goto deliver;
	}

	ASSERT(IPH_HDR_VERSION(rptr) == IPV6_VERSION);
	/*
	 * IPv6 packets can only be received by applications
	 * that are prepared to receive IPv6 addresses.
	 * The IP fanout must ensure this.
	 */
	ASSERT(connp->conn_family == AF_INET6);

	/*
	 * Handle IPv6 packets. We don't pass up the IP headers with the
	 * payload for IPv6.
	 */

	ip6h = (ip6_t *)rptr;
	if (recv_ancillary.crb_all != 0) {
		/*
		 * Call on ip_find_hdr_v6 which gets individual lenghts of
		 * extension headers (and pointers to them).
		 */
		uint8_t		nexthdr;

		/* We don't care about the length or nextheader. */
		(void) ip_find_hdr_v6(mp, ip6h, B_TRUE, &ipps, &nexthdr);

		/*
		 * We do not pass up hop-by-hop options or any other
		 * extension header as part of the packet. Applications
		 * that want to see them have to specify IPV6_RECV* socket
		 * options. And conn_recvancillary_size/add explicitly
		 * drops the TX option from IPV6_HOPOPTS as it does for UDP.
		 *
		 * If we had multilevel ICMP sockets, then we'd want to
		 * modify conn_recvancillary_size/add to
		 * allow the user to see the label.
		 */
	}

	/*
	 * Check a filter for ICMPv6 types if needed.
	 * Verify raw checksums if needed.
	 */
	mutex_enter(&connp->conn_lock);
	if (icmp->icmp_filter != NULL) {
		int type;

		/* Assumes that IP has done the pullupmsg */
		type = mp->b_rptr[ip_hdr_length];

		ASSERT(mp->b_rptr + ip_hdr_length <= mp->b_wptr);
		if (ICMP6_FILTER_WILLBLOCK(type, icmp->icmp_filter)) {
			mutex_exit(&connp->conn_lock);
			freemsg(mp);
			return;
		}
	}
	if (connp->conn_ixa->ixa_flags & IXAF_SET_RAW_CKSUM) {
		/* Checksum */
		uint16_t	*up;
		uint32_t	sum;
		int		remlen;

		up = (uint16_t *)&ip6h->ip6_src;

		remlen = msgdsize(mp) - ip_hdr_length;
		sum = htons(connp->conn_proto + remlen)
		    + up[0] + up[1] + up[2] + up[3]
		    + up[4] + up[5] + up[6] + up[7]
		    + up[8] + up[9] + up[10] + up[11]
		    + up[12] + up[13] + up[14] + up[15];
		sum = (sum & 0xffff) + (sum >> 16);
		sum = IP_CSUM(mp, ip_hdr_length, sum);
		if (sum != 0) {
			/* IPv6 RAW checksum failed */
			ip0dbg(("icmp_rput: RAW checksum failed %x\n", sum));
			mutex_exit(&connp->conn_lock);
			freemsg(mp);
			BUMP_MIB(&is->is_rawip_mib, rawipInCksumErrs);
			return;
		}
	}
	mutex_exit(&connp->conn_lock);

	udi_size = sizeof (struct T_unitdata_ind) + sizeof (sin6_t);

	if (recv_ancillary.crb_all != 0) {
		udi_size += conn_recvancillary_size(connp,
		    recv_ancillary, ira, mp, &ipps);
	}

	mp1 = allocb(udi_size, BPRI_MED);
	if (mp1 == NULL) {
		freemsg(mp);
		BUMP_MIB(&is->is_rawip_mib, rawipInErrors);
		return;
	}
	mp1->b_cont = mp;
	mp1->b_datap->db_type = M_PROTO;
	tudi = (struct T_unitdata_ind *)mp1->b_rptr;
	mp1->b_wptr = (uchar_t *)tudi + udi_size;
	tudi->PRIM_type = T_UNITDATA_IND;
	tudi->SRC_length = sizeof (sin6_t);
	tudi->SRC_offset = sizeof (struct T_unitdata_ind);
	tudi->OPT_offset = sizeof (struct T_unitdata_ind) + sizeof (sin6_t);
	udi_size -= (sizeof (struct T_unitdata_ind) + sizeof (sin6_t));
	tudi->OPT_length = udi_size;
	sin6 = (sin6_t *)&tudi[1];
	*sin6 = sin6_null;
	sin6->sin6_port = 0;
	sin6->sin6_family = AF_INET6;

	sin6->sin6_addr = ip6h->ip6_src;
	/* No sin6_flowinfo per API */
	sin6->sin6_flowinfo = 0;
	/* For link-scope pass up scope id */
	if (IN6_IS_ADDR_LINKSCOPE(&ip6h->ip6_src))
		sin6->sin6_scope_id = ira->ira_ruifindex;
	else
		sin6->sin6_scope_id = 0;
	sin6->__sin6_src_id = ip_srcid_find_addr(&ip6h->ip6_dst,
	    IPCL_ZONEID(connp), is->is_netstack);

	if (udi_size != 0) {
		conn_recvancillary_add(connp, recv_ancillary, ira,
		    &ipps, (uchar_t *)&sin6[1], udi_size);
	}

	/* Skip all the IPv6 headers per API */
	mp->b_rptr += ip_hdr_length;
	pkt_len -= ip_hdr_length;

deliver:
	BUMP_MIB(&is->is_rawip_mib, rawipInDatagrams);
	icmp_ulp_recv(connp, mp1, pkt_len);
}

/*
 * return SNMP stuff in buffer in mpdata. We don't hold any lock and report
 * information that can be changing beneath us.
 */
mblk_t *
icmp_snmp_get(queue_t *q, mblk_t *mpctl)
{
	mblk_t			*mpdata;
	struct opthdr		*optp;
	conn_t			*connp = Q_TO_CONN(q);
	icmp_stack_t		*is = connp->conn_netstack->netstack_icmp;
	mblk_t			*mp2ctl;

	/*
	 * make a copy of the original message
	 */
	mp2ctl = copymsg(mpctl);

	if (mpctl == NULL ||
	    (mpdata = mpctl->b_cont) == NULL) {
		freemsg(mpctl);
		freemsg(mp2ctl);
		return (0);
	}

	/* fixed length structure for IPv4 and IPv6 counters */
	optp = (struct opthdr *)&mpctl->b_rptr[sizeof (struct T_optmgmt_ack)];
	optp->level = EXPER_RAWIP;
	optp->name = 0;
	(void) snmp_append_data(mpdata, (char *)&is->is_rawip_mib,
	    sizeof (is->is_rawip_mib));
	optp->len = msgdsize(mpdata);
	qreply(q, mpctl);

	return (mp2ctl);
}

/*
 * Return 0 if invalid set request, 1 otherwise, including non-rawip requests.
 * TODO:  If this ever actually tries to set anything, it needs to be
 * to do the appropriate locking.
 */
/* ARGSUSED */
int
icmp_snmp_set(queue_t *q, t_scalar_t level, t_scalar_t name,
    uchar_t *ptr, int len)
{
	switch (level) {
	case EXPER_RAWIP:
		return (0);
	default:
		return (1);
	}
}

/*
 * This routine creates a T_UDERROR_IND message and passes it upstream.
 * The address and options are copied from the T_UNITDATA_REQ message
 * passed in mp.  This message is freed.
 */
static void
icmp_ud_err(queue_t *q, mblk_t *mp, t_scalar_t err)
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

static int
rawip_do_unbind(conn_t *connp)
{
	icmp_t	*icmp = connp->conn_icmp;

	mutex_enter(&connp->conn_lock);
	/* If a bind has not been done, we can't unbind. */
	if (icmp->icmp_state == TS_UNBND) {
		mutex_exit(&connp->conn_lock);
		return (-TOUTSTATE);
	}
	connp->conn_saddr_v6 = ipv6_all_zeros;
	connp->conn_bound_addr_v6 = ipv6_all_zeros;
	connp->conn_laddr_v6 = ipv6_all_zeros;
	connp->conn_mcbc_bind = B_FALSE;
	connp->conn_lport = 0;
	connp->conn_fport = 0;
	/* In case we were also connected */
	connp->conn_faddr_v6 = ipv6_all_zeros;
	connp->conn_v6lastdst = ipv6_all_zeros;

	icmp->icmp_state = TS_UNBND;

	(void) icmp_build_hdr_template(connp, &connp->conn_saddr_v6,
	    &connp->conn_faddr_v6, connp->conn_flowinfo);
	mutex_exit(&connp->conn_lock);

	ip_unbind(connp);
	return (0);
}

/*
 * This routine is called by icmp_wput to handle T_UNBIND_REQ messages.
 * After some error checking, the message is passed downstream to ip.
 */
static void
icmp_tpi_unbind(queue_t *q, mblk_t *mp)
{
	conn_t	*connp = Q_TO_CONN(q);
	int	error;

	ASSERT(mp->b_cont == NULL);
	error = rawip_do_unbind(connp);
	if (error) {
		if (error < 0) {
			icmp_err_ack(q, mp, -error, 0);
		} else {
			icmp_err_ack(q, mp, 0, error);
		}
		return;
	}

	/*
	 * Convert mp into a T_OK_ACK
	 */

	mp = mi_tpi_ok_ack_alloc(mp);

	/*
	 * should not happen in practice... T_OK_ACK is smaller than the
	 * original message.
	 */
	ASSERT(mp != NULL);
	ASSERT(((struct T_ok_ack *)mp->b_rptr)->PRIM_type == T_OK_ACK);
	qreply(q, mp);
}

/*
 * Process IPv4 packets that already include an IP header.
 * Used when IP_HDRINCL has been set (implicit for IPPROTO_RAW and
 * IPPROTO_IGMP).
 * In this case we ignore the address and any options in the T_UNITDATA_REQ.
 *
 * The packet is assumed to have a base (20 byte) IP header followed
 * by the upper-layer protocol. We include any IP_OPTIONS including a
 * CIPSO label but otherwise preserve the base IP header.
 */
static int
icmp_output_hdrincl(conn_t *connp, mblk_t *mp, cred_t *cr, pid_t pid)
{
	icmp_t		*icmp = connp->conn_icmp;
	icmp_stack_t	*is = icmp->icmp_is;
	ipha_t		iphas;
	ipha_t		*ipha;
	int		ip_hdr_length;
	int		tp_hdr_len;
	ip_xmit_attr_t	*ixa;
	ip_pkt_t	*ipp;
	in6_addr_t	v6src;
	in6_addr_t	v6dst;
	in6_addr_t	v6nexthop;
	int		error;
	boolean_t	do_ipsec;

	/*
	 * We need an exclusive copy of conn_ixa since the included IP
	 * header could have any destination.
	 * That copy has no pointers hence we
	 * need to set them up once we've parsed the ancillary data.
	 */
	ixa = conn_get_ixa_exclusive(connp);
	if (ixa == NULL) {
		BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
		freemsg(mp);
		return (ENOMEM);
	}
	ASSERT(cr != NULL);
	/*
	 * Caller has a reference on cr; from db_credp or because we
	 * are running in process context.
	 */
	ASSERT(!(ixa->ixa_free_flags & IXA_FREE_CRED));
	ixa->ixa_cred = cr;
	ixa->ixa_cpid = pid;
	if (is_system_labeled()) {
		/* We need to restart with a label based on the cred */
		ip_xmit_attr_restore_tsl(ixa, ixa->ixa_cred);
	}

	/* In case previous destination was multicast or multirt */
	ip_attr_newdst(ixa);

	/* Get a copy of conn_xmit_ipp since the TX label might change it */
	ipp = kmem_zalloc(sizeof (*ipp), KM_NOSLEEP);
	if (ipp == NULL) {
		ASSERT(!(ixa->ixa_free_flags & IXA_FREE_CRED));
		ixa->ixa_cred = connp->conn_cred;	/* Restore */
		ixa->ixa_cpid = connp->conn_cpid;
		ixa_refrele(ixa);
		BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
		freemsg(mp);
		return (ENOMEM);
	}
	mutex_enter(&connp->conn_lock);
	error = ip_pkt_copy(&connp->conn_xmit_ipp, ipp, KM_NOSLEEP);
	mutex_exit(&connp->conn_lock);
	if (error != 0) {
		BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
		freemsg(mp);
		goto done;
	}

	/* Sanity check length of packet */
	ipha = (ipha_t *)mp->b_rptr;

	ip_hdr_length = IP_SIMPLE_HDR_LENGTH;
	if ((mp->b_wptr - mp->b_rptr) < IP_SIMPLE_HDR_LENGTH) {
		if (!pullupmsg(mp, IP_SIMPLE_HDR_LENGTH)) {
			BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
			freemsg(mp);
			goto done;
		}
		ipha = (ipha_t *)mp->b_rptr;
	}
	ipha->ipha_version_and_hdr_length =
	    (IP_VERSION<<4) | (ip_hdr_length>>2);

	/*
	 * We set IXAF_DONTFRAG if the application set DF which makes
	 * IP not fragment.
	 */
	ipha->ipha_fragment_offset_and_flags &= htons(IPH_DF);
	if (ipha->ipha_fragment_offset_and_flags & htons(IPH_DF))
		ixa->ixa_flags |= (IXAF_DONTFRAG | IXAF_PMTU_IPV4_DF);
	else
		ixa->ixa_flags &= ~(IXAF_DONTFRAG | IXAF_PMTU_IPV4_DF);

	/* Even for multicast and broadcast we honor the apps ttl */
	ixa->ixa_flags |= IXAF_NO_TTL_CHANGE;

	/*
	 * No source verification for non-local addresses
	 */
	if (ipha->ipha_src != INADDR_ANY &&
	    ip_laddr_verify_v4(ipha->ipha_src, ixa->ixa_zoneid,
	    is->is_netstack->netstack_ip, B_FALSE)
	    != IPVL_UNICAST_UP) {
		ixa->ixa_flags &= ~IXAF_VERIFY_SOURCE;
	}

	if (ipha->ipha_dst == INADDR_ANY)
		ipha->ipha_dst = htonl(INADDR_LOOPBACK);

	IN6_IPADDR_TO_V4MAPPED(ipha->ipha_src, &v6src);
	IN6_IPADDR_TO_V4MAPPED(ipha->ipha_dst, &v6dst);

	/* Defer IPsec if it might need to look at ICMP type/code */
	do_ipsec = ipha->ipha_protocol != IPPROTO_ICMP;
	ixa->ixa_flags |= IXAF_IS_IPV4;

	ip_attr_nexthop(ipp, ixa, &v6dst, &v6nexthop);
	error = ip_attr_connect(connp, ixa, &v6src, &v6dst, &v6nexthop,
	    connp->conn_fport, &v6src, NULL, IPDF_ALLOW_MCBC | IPDF_VERIFY_DST |
	    (do_ipsec ? IPDF_IPSEC : 0));
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
		BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
		goto done;
	}
	if (ipha->ipha_src == INADDR_ANY)
		IN6_V4MAPPED_TO_IPADDR(&v6src, ipha->ipha_src);

	/*
	 * We might be going to a different destination than last time,
	 * thus check that TX allows the communication and compute any
	 * needed label.
	 *
	 * TSOL Note: We have an exclusive ipp and ixa for this thread so we
	 * don't have to worry about concurrent threads.
	 */
	if (is_system_labeled()) {
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
			BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
			goto done;
		}
	}

	/*
	 * Save away a copy of the IPv4 header the application passed down
	 * and then prepend an IPv4 header complete with any IP options
	 * including label.
	 * We need a struct copy since icmp_prepend_hdr will reuse the available
	 * space in the mblk.
	 */
	iphas = *ipha;
	mp->b_rptr += IP_SIMPLE_HDR_LENGTH;

	mp = icmp_prepend_hdr(connp, ixa, ipp, &v6src, &v6dst, 0, mp, &error);
	if (mp == NULL) {
		BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
		ASSERT(error != 0);
		goto done;
	}
	if (ixa->ixa_pktlen > IP_MAXPACKET) {
		error = EMSGSIZE;
		BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
		freemsg(mp);
		goto done;
	}
	/* Restore key parts of the header that the application passed down */
	ipha = (ipha_t *)mp->b_rptr;
	ipha->ipha_type_of_service = iphas.ipha_type_of_service;
	ipha->ipha_ident = iphas.ipha_ident;
	ipha->ipha_fragment_offset_and_flags =
	    iphas.ipha_fragment_offset_and_flags;
	ipha->ipha_ttl = iphas.ipha_ttl;
	ipha->ipha_protocol = iphas.ipha_protocol;
	ipha->ipha_src = iphas.ipha_src;
	ipha->ipha_dst = iphas.ipha_dst;

	ixa->ixa_protocol = ipha->ipha_protocol;

	/*
	 * Make sure that the IP header plus any transport header that is
	 * checksumed by ip_output is in the first mblk. (ip_output assumes
	 * that at least the checksum field is in the first mblk.)
	 */
	switch (ipha->ipha_protocol) {
	case IPPROTO_UDP:
		tp_hdr_len = 8;
		break;
	case IPPROTO_TCP:
		tp_hdr_len = 20;
		break;
	default:
		tp_hdr_len = 0;
		break;
	}
	ip_hdr_length = IPH_HDR_LENGTH(ipha);
	if (mp->b_wptr - mp->b_rptr < ip_hdr_length + tp_hdr_len) {
		if (!pullupmsg(mp, ip_hdr_length + tp_hdr_len)) {
			BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
			if (mp->b_cont == NULL)
				error = EINVAL;
			else
				error = ENOMEM;
			freemsg(mp);
			goto done;
		}
	}

	if (!do_ipsec) {
		/* Policy might differ for different ICMP type/code */
		if (ixa->ixa_ipsec_policy != NULL) {
			IPPOL_REFRELE(ixa->ixa_ipsec_policy);
			ixa->ixa_ipsec_policy = NULL;
			ixa->ixa_flags &= ~IXAF_IPSEC_SECURE;
		}
		mp = ip_output_attach_policy(mp, ipha, NULL, connp, ixa);
		if (mp == NULL) {
			BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
			error = EHOSTUNREACH;	/* IPsec policy failure */
			goto done;
		}
	}

	/* We're done.  Pass the packet to ip. */
	BUMP_MIB(&is->is_rawip_mib, rawipOutDatagrams);

	error = conn_ip_output(mp, ixa);
	/* No rawipOutErrors if an error since IP increases its error counter */
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
done:
	ASSERT(!(ixa->ixa_free_flags & IXA_FREE_CRED));
	ixa->ixa_cred = connp->conn_cred;	/* Restore */
	ixa->ixa_cpid = connp->conn_cpid;
	ixa_refrele(ixa);
	ip_pkt_free(ipp);
	kmem_free(ipp, sizeof (*ipp));
	return (error);
}

static mblk_t *
icmp_output_attach_policy(mblk_t *mp, conn_t *connp, ip_xmit_attr_t *ixa)
{
	ipha_t	*ipha = NULL;
	ip6_t	*ip6h = NULL;

	if (ixa->ixa_flags & IXAF_IS_IPV4)
		ipha = (ipha_t *)mp->b_rptr;
	else
		ip6h = (ip6_t *)mp->b_rptr;

	if (ixa->ixa_ipsec_policy != NULL) {
		IPPOL_REFRELE(ixa->ixa_ipsec_policy);
		ixa->ixa_ipsec_policy = NULL;
		ixa->ixa_flags &= ~IXAF_IPSEC_SECURE;
	}
	return (ip_output_attach_policy(mp, ipha, ip6h, connp, ixa));
}

/*
 * Handle T_UNITDATA_REQ with options. Both IPv4 and IPv6
 * Either tudr_mp or msg is set. If tudr_mp we take ancillary data from
 * the TPI options, otherwise we take them from msg_control.
 * If both sin and sin6 is set it is a connected socket and we use conn_faddr.
 * Always consumes mp; never consumes tudr_mp.
 */
static int
icmp_output_ancillary(conn_t *connp, sin_t *sin, sin6_t *sin6, mblk_t *mp,
    mblk_t *tudr_mp, struct nmsghdr *msg, cred_t *cr, pid_t pid)
{
	icmp_t		*icmp = connp->conn_icmp;
	icmp_stack_t	*is = icmp->icmp_is;
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
		BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
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
		BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
		freemsg(mp);
		return (ENOMEM);
	}
	mutex_enter(&connp->conn_lock);
	error = ip_pkt_copy(&connp->conn_xmit_ipp, ipp, KM_NOSLEEP);
	mutex_exit(&connp->conn_lock);
	if (error != 0) {
		BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
		freemsg(mp);
		goto done;
	}

	/*
	 * Parse the options and update ixa and ipp as a result.
	 */

	coa = &coas;
	coa->coa_connp = connp;
	coa->coa_ixa = ixa;
	coa->coa_ipp = ipp;
	coa->coa_ancillary = B_TRUE;
	coa->coa_changed = 0;

	if (msg != NULL) {
		error = process_auxiliary_options(connp, msg->msg_control,
		    msg->msg_controllen, coa, &icmp_opt_obj, icmp_opt_set, cr);
	} else {
		struct T_unitdata_req *tudr;

		tudr = (struct T_unitdata_req *)tudr_mp->b_rptr;
		ASSERT(tudr->PRIM_type == T_UNITDATA_REQ);
		error = tpi_optcom_buf(connp->conn_wq, tudr_mp,
		    &tudr->OPT_length, tudr->OPT_offset, cr, &icmp_opt_obj,
		    coa, &is_absreq_failure);
	}
	if (error != 0) {
		/*
		 * Note: No special action needed in this
		 * module for "is_absreq_failure"
		 */
		freemsg(mp);
		BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
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
		if (srcid != 0 && IN6_IS_ADDR_UNSPECIFIED(&v6src)) {
			ip_srcid_find_id(srcid, &v6src, IPCL_ZONEID(connp),
			    connp->conn_netstack);
		}
		if (IN6_IS_ADDR_V4MAPPED(&v6dst))
			ixa->ixa_flags |= IXAF_IS_IPV4;
		else
			ixa->ixa_flags &= ~IXAF_IS_IPV4;
	} else {
		/* Connected case */
		v6dst = connp->conn_faddr_v6;
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
	/*
	 * Allow source not assigned to the system
	 * only if it is not a local addresses
	 */
	if (!V6_OR_V4_INADDR_ANY(v6src)) {
		ip_laddr_t laddr_type;

		if (ixa->ixa_flags & IXAF_IS_IPV4) {
			ipaddr_t v4src;

			IN6_V4MAPPED_TO_IPADDR(&v6src, v4src);
			laddr_type = ip_laddr_verify_v4(v4src, ixa->ixa_zoneid,
			    is->is_netstack->netstack_ip, B_FALSE);
		} else {
			laddr_type = ip_laddr_verify_v6(&v6src, ixa->ixa_zoneid,
			    is->is_netstack->netstack_ip, B_FALSE, B_FALSE);
		}
		if (laddr_type != IPVL_UNICAST_UP)
			ixa->ixa_flags &= ~IXAF_VERIFY_SOURCE;
	}

	ip_attr_nexthop(ipp, ixa, &v6dst, &v6nexthop);
	error = ip_attr_connect(connp, ixa, &v6src, &v6dst, &v6nexthop, dstport,
	    &v6src, NULL, IPDF_ALLOW_MCBC | IPDF_VERIFY_DST);

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
		BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
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
			BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
			goto done;
		}
	}
	mp = icmp_prepend_hdr(connp, ixa, ipp, &v6src, &v6dst, flowinfo, mp,
	    &error);
	if (mp == NULL) {
		BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
		ASSERT(error != 0);
		goto done;
	}
	if (ixa->ixa_pktlen > IP_MAXPACKET) {
		error = EMSGSIZE;
		BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
		freemsg(mp);
		goto done;
	}

	/* Policy might differ for different ICMP type/code */
	mp = icmp_output_attach_policy(mp, connp, ixa);
	if (mp == NULL) {
		BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
		error = EHOSTUNREACH;	/* IPsec policy failure */
		goto done;
	}

	/* We're done.  Pass the packet to ip. */
	BUMP_MIB(&is->is_rawip_mib, rawipOutDatagrams);

	error = conn_ip_output(mp, ixa);
	if (!connp->conn_unspec_src)
		ixa->ixa_flags |= IXAF_VERIFY_SOURCE;
	/* No rawipOutErrors if an error since IP increases its error counter */
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
int
icmp_output_connected(conn_t *connp, mblk_t *mp, cred_t *cr, pid_t pid)
{
	icmp_t		*icmp = connp->conn_icmp;
	icmp_stack_t	*is = icmp->icmp_is;
	int		error;
	ip_xmit_attr_t	*ixa;
	boolean_t	do_ipsec;

	/*
	 * If no other thread is using conn_ixa this just gets a reference to
	 * conn_ixa. Otherwise we get a safe copy of conn_ixa.
	 */
	ixa = conn_get_ixa(connp, B_FALSE);
	if (ixa == NULL) {
		BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
		freemsg(mp);
		return (ENOMEM);
	}

	ASSERT(cr != NULL);
	ASSERT(!(ixa->ixa_free_flags & IXA_FREE_CRED));
	ixa->ixa_cred = cr;
	ixa->ixa_cpid = pid;

	/* Defer IPsec if it might need to look at ICMP type/code */
	switch (ixa->ixa_protocol) {
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		do_ipsec = B_FALSE;
		break;
	default:
		do_ipsec = B_TRUE;
	}

	mutex_enter(&connp->conn_lock);
	mp = icmp_prepend_header_template(connp, ixa, mp,
	    &connp->conn_saddr_v6, connp->conn_flowinfo, &error);

	if (mp == NULL) {
		ASSERT(error != 0);
		mutex_exit(&connp->conn_lock);
		ASSERT(!(ixa->ixa_free_flags & IXA_FREE_CRED));
		ixa->ixa_cred = connp->conn_cred;	/* Restore */
		ixa->ixa_cpid = connp->conn_cpid;
		ixa_refrele(ixa);
		BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
		freemsg(mp);
		return (error);
	}

	if (!do_ipsec) {
		/* Policy might differ for different ICMP type/code */
		mp = icmp_output_attach_policy(mp, connp, ixa);
		if (mp == NULL) {
			mutex_exit(&connp->conn_lock);
			BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
			ASSERT(!(ixa->ixa_free_flags & IXA_FREE_CRED));
			ixa->ixa_cred = connp->conn_cred;	/* Restore */
			ixa->ixa_cpid = connp->conn_cpid;
			ixa_refrele(ixa);
			return (EHOSTUNREACH);	/* IPsec policy failure */
		}
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
		    (do_ipsec ? IPDF_IPSEC : 0));
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
			BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
			freemsg(mp);
			return (error);
		}
	} else {
		/* Done with conn_t */
		mutex_exit(&connp->conn_lock);
	}

	/* We're done.  Pass the packet to ip. */
	BUMP_MIB(&is->is_rawip_mib, rawipOutDatagrams);

	error = conn_ip_output(mp, ixa);
	/* No rawipOutErrors if an error since IP increases its error counter */
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
int
icmp_output_lastdst(conn_t *connp, mblk_t *mp, cred_t *cr, pid_t pid,
    ip_xmit_attr_t *ixa)
{
	icmp_t		*icmp = connp->conn_icmp;
	icmp_stack_t	*is = icmp->icmp_is;
	int		error;
	boolean_t	do_ipsec;

	ASSERT(MUTEX_HELD(&connp->conn_lock));
	ASSERT(ixa != NULL);

	ASSERT(cr != NULL);
	ASSERT(!(ixa->ixa_free_flags & IXA_FREE_CRED));
	ixa->ixa_cred = cr;
	ixa->ixa_cpid = pid;

	/* Defer IPsec if it might need to look at ICMP type/code */
	switch (ixa->ixa_protocol) {
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		do_ipsec = B_FALSE;
		break;
	default:
		do_ipsec = B_TRUE;
	}


	mp = icmp_prepend_header_template(connp, ixa, mp,
	    &connp->conn_v6lastsrc, connp->conn_lastflowinfo, &error);

	if (mp == NULL) {
		ASSERT(error != 0);
		mutex_exit(&connp->conn_lock);
		ASSERT(!(ixa->ixa_free_flags & IXA_FREE_CRED));
		ixa->ixa_cred = connp->conn_cred;	/* Restore */
		ixa->ixa_cpid = connp->conn_cpid;
		ixa_refrele(ixa);
		BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
		freemsg(mp);
		return (error);
	}

	if (!do_ipsec) {
		/* Policy might differ for different ICMP type/code */
		mp = icmp_output_attach_policy(mp, connp, ixa);
		if (mp == NULL) {
			mutex_exit(&connp->conn_lock);
			BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
			ASSERT(!(ixa->ixa_free_flags & IXA_FREE_CRED));
			ixa->ixa_cred = connp->conn_cred;	/* Restore */
			ixa->ixa_cpid = connp->conn_cpid;
			ixa_refrele(ixa);
			return (EHOSTUNREACH);	/* IPsec policy failure */
		}
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
		    IPDF_VERIFY_DST | (do_ipsec ? IPDF_IPSEC : 0));
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
			BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
			freemsg(mp);
			return (error);
		}
	} else {
		/* Done with conn_t */
		mutex_exit(&connp->conn_lock);
	}

	/* We're done.  Pass the packet to ip. */
	BUMP_MIB(&is->is_rawip_mib, rawipOutDatagrams);
	error = conn_ip_output(mp, ixa);
	/* No rawipOutErrors if an error since IP increases its error counter */
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
icmp_prepend_header_template(conn_t *connp, ip_xmit_attr_t *ixa, mblk_t *mp,
    const in6_addr_t *v6src, uint32_t flowinfo, int *errorp)
{
	icmp_t		*icmp = connp->conn_icmp;
	icmp_stack_t	*is = icmp->icmp_is;
	uint_t		pktlen;
	uint_t		copylen;
	uint8_t		*iph;
	uint_t		ip_hdr_length;
	uint32_t	cksum;
	ip_pkt_t	*ipp;

	ASSERT(MUTEX_HELD(&connp->conn_lock));

	/*
	 * Copy the header template.
	 */
	copylen = connp->conn_ht_iphc_len;
	pktlen = copylen + msgdsize(mp);
	if (pktlen > IP_MAXPACKET) {
		freemsg(mp);
		*errorp = EMSGSIZE;
		return (NULL);
	}
	ixa->ixa_pktlen = pktlen;

	/* check/fix buffer config, setup pointers into it */
	iph = mp->b_rptr - copylen;
	if (DB_REF(mp) != 1 || iph < DB_BASE(mp) || !OK_32PTR(iph)) {
		mblk_t *mp1;

		mp1 = allocb(copylen + is->is_wroff_extra, BPRI_MED);
		if (mp1 == NULL) {
			freemsg(mp);
			*errorp = ENOMEM;
			return (NULL);
		}
		mp1->b_wptr = DB_LIM(mp1);
		mp1->b_cont = mp;
		mp = mp1;
		iph = (mp->b_wptr - copylen);
	}
	mp->b_rptr = iph;
	bcopy(connp->conn_ht_iphc, iph, copylen);
	ip_hdr_length = (uint_t)(connp->conn_ht_ulp - connp->conn_ht_iphc);

	ixa->ixa_ip_hdr_length = ip_hdr_length;

	/*
	 * Prepare for ICMPv6 checksum done in IP.
	 *
	 * icmp_build_hdr_template has already massaged any routing header
	 * and placed the result in conn_sum.
	 *
	 * We make it easy for IP to include our pseudo header
	 * by putting our length (and any routing header adjustment)
	 * in the ICMPv6 checksum field.
	 */
	cksum = pktlen - ip_hdr_length;

	cksum += connp->conn_sum;
	cksum = (cksum >> 16) + (cksum & 0xFFFF);
	ASSERT(cksum < 0x10000);

	ipp = &connp->conn_xmit_ipp;
	if (ixa->ixa_flags & IXAF_IS_IPV4) {
		ipha_t	*ipha = (ipha_t *)iph;

		ipha->ipha_length = htons((uint16_t)pktlen);

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
		uint_t	cksum_offset = 0;

		ip6h->ip6_plen =  htons((uint16_t)(pktlen - IPV6_HDR_LEN));

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

		if (ixa->ixa_flags & IXAF_SET_ULP_CKSUM) {
			if (connp->conn_proto == IPPROTO_ICMPV6) {
				cksum_offset = ixa->ixa_ip_hdr_length +
				    offsetof(icmp6_t, icmp6_cksum);
			} else if (ixa->ixa_flags & IXAF_SET_RAW_CKSUM) {
				cksum_offset = ixa->ixa_ip_hdr_length +
				    ixa->ixa_raw_cksum_offset;
			}
		}
		if (cksum_offset != 0) {
			uint16_t *ptr;

			/* Make sure the checksum fits in the first mblk */
			if (cksum_offset + sizeof (short) > MBLKL(mp)) {
				mblk_t *mp1;

				mp1 = msgpullup(mp,
				    cksum_offset + sizeof (short));
				freemsg(mp);
				if (mp1 == NULL) {
					*errorp = ENOMEM;
					return (NULL);
				}
				mp = mp1;
				iph = mp->b_rptr;
				ip6h = (ip6_t *)iph;
			}
			ptr = (uint16_t *)(mp->b_rptr + cksum_offset);
			*ptr = htons(cksum);
		}
	}

	return (mp);
}

/*
 * This routine handles all messages passed downstream.  It either
 * consumes the message or passes it downstream; it never queues a
 * a message.
 */
void
icmp_wput(queue_t *q, mblk_t *mp)
{
	sin6_t		*sin6;
	sin_t		*sin = NULL;
	uint_t		srcid;
	conn_t		*connp = Q_TO_CONN(q);
	icmp_t		*icmp = connp->conn_icmp;
	int		error = 0;
	struct sockaddr	*addr = NULL;
	socklen_t	addrlen;
	icmp_stack_t	*is = icmp->icmp_is;
	struct T_unitdata_req *tudr;
	mblk_t		*data_mp;
	cred_t		*cr;
	pid_t		pid;

	/*
	 * We directly handle several cases here: T_UNITDATA_REQ message
	 * coming down as M_PROTO/M_PCPROTO and M_DATA messages for connected
	 * socket.
	 */
	switch (DB_TYPE(mp)) {
	case M_DATA:
		/* sockfs never sends down M_DATA */
		BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
		freemsg(mp);
		return;

	case M_PROTO:
	case M_PCPROTO:
		tudr = (struct T_unitdata_req *)mp->b_rptr;
		if (MBLKL(mp) < sizeof (*tudr) ||
		    ((t_primp_t)mp->b_rptr)->type != T_UNITDATA_REQ) {
			icmp_wput_other(q, mp);
			return;
		}
		break;

	default:
		icmp_wput_other(q, mp);
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
	 * for this message, hence we ASSERT.
	 * On production kernels we return an error to be robust against
	 * random streams modules sitting on top of us.
	 */
	cr = msg_getcred(mp, &pid);
	ASSERT(cr != NULL);
	if (cr == NULL) {
		error = EINVAL;
		goto ud_error2;
	}

	/*
	 * If a port has not been bound to the stream, fail.
	 * This is not a problem when sockfs is directly
	 * above us, because it will ensure that the socket
	 * is first bound before allowing data to be sent.
	 */
	if (icmp->icmp_state == TS_UNBND) {
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

		/* No support for mapped addresses on raw sockets */
		if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
			error = EADDRNOTAVAIL;
			goto ud_error2;
		}
		srcid = sin6->__sin6_src_id;

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

		if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr))
			sin6->sin6_addr = ipv6_loopback;

		if (tudr->OPT_length != 0) {
			/*
			 * If we are connected then the destination needs to be
			 * the same as the connected one.
			 */
			if (icmp->icmp_state == TS_DATA_XFER &&
			    !conn_same_as_last_v6(connp, sin6)) {
				error = EISCONN;
				goto ud_error2;
			}
			error = icmp_output_ancillary(connp, NULL, sin6,
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
				/* icmp_output_lastdst drops conn_lock */
				error = icmp_output_lastdst(connp, data_mp, cr,
				    pid, ixa);
			} else {
				/* icmp_output_newdst drops conn_lock */
				error = icmp_output_newdst(connp, data_mp, NULL,
				    sin6, cr, pid, ixa);
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
		if (sin->sin_addr.s_addr == INADDR_ANY)
			sin->sin_addr.s_addr = htonl(INADDR_LOOPBACK);

		/* Protocol 255 contains full IP headers */
		/* Read without holding lock */
		if (icmp->icmp_hdrincl) {
			if (MBLKL(data_mp) < IP_SIMPLE_HDR_LENGTH) {
				if (!pullupmsg(data_mp, IP_SIMPLE_HDR_LENGTH)) {
					error = EINVAL;
					goto ud_error2;
				}
			}
			error = icmp_output_hdrincl(connp, data_mp, cr, pid);
			if (error == 0) {
				freeb(mp);
				return;
			}
			/* data_mp consumed above */
			data_mp = NULL;
			goto ud_error2;
		}

		if (tudr->OPT_length != 0) {
			/*
			 * If we are connected then the destination needs to be
			 * the same as the connected one.
			 */
			if (icmp->icmp_state == TS_DATA_XFER &&
			    !conn_same_as_last_v4(connp, sin)) {
				error = EISCONN;
				goto ud_error2;
			}
			error = icmp_output_ancillary(connp, sin, NULL,
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
				/* icmp_output_lastdst drops conn_lock */
				error = icmp_output_lastdst(connp, data_mp, cr,
				    pid, ixa);
			} else {
				/* icmp_output_newdst drops conn_lock */
				error = icmp_output_newdst(connp, data_mp, sin,
				    NULL, cr, pid, ixa);
			}
			ASSERT(MUTEX_NOT_HELD(&connp->conn_lock));
		}
		if (error == 0) {
			freeb(mp);
			return;
		}
		break;
	}
	ASSERT(mp != NULL);
	/* mp is freed by the following routine */
	icmp_ud_err(q, mp, (t_scalar_t)error);
	return;

ud_error2:
	BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
	freemsg(data_mp);
	ASSERT(mp != NULL);
	/* mp is freed by the following routine */
	icmp_ud_err(q, mp, (t_scalar_t)error);
}

/*
 * Handle the case of the IP address or flow label being different
 * for both IPv4 and IPv6.
 *
 * NOTE: The caller must hold conn_lock and we drop it here.
 */
static int
icmp_output_newdst(conn_t *connp, mblk_t *data_mp, sin_t *sin, sin6_t *sin6,
    cred_t *cr, pid_t pid, ip_xmit_attr_t *ixa)
{
	icmp_t		*icmp = connp->conn_icmp;
	icmp_stack_t	*is = icmp->icmp_is;
	int		error;
	ip_xmit_attr_t	*oldixa;
	boolean_t	do_ipsec;
	uint_t		srcid;
	uint32_t	flowinfo;
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
	if (icmp->icmp_state == TS_DATA_XFER) {
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
		srcid = 0;
		ixa->ixa_flags &= ~IXAF_SCOPEID_SET;
		if (srcid != 0 && V4_PART_OF_V6(&v6src) == INADDR_ANY) {
			ip_srcid_find_id(srcid, &v6src, IPCL_ZONEID(connp),
			    connp->conn_netstack);
		}
		ixa->ixa_flags |= IXAF_IS_IPV4;
	} else {
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
		if (srcid != 0 && IN6_IS_ADDR_UNSPECIFIED(&v6src)) {
			ip_srcid_find_id(srcid, &v6src, IPCL_ZONEID(connp),
			    connp->conn_netstack);
		}
		if (IN6_IS_ADDR_V4MAPPED(&v6dst))
			ixa->ixa_flags |= IXAF_IS_IPV4;
		else
			ixa->ixa_flags &= ~IXAF_IS_IPV4;
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

	/* Defer IPsec if it might need to look at ICMP type/code */
	switch (ixa->ixa_protocol) {
	case IPPROTO_ICMP:
	case IPPROTO_ICMPV6:
		do_ipsec = B_FALSE;
		break;
	default:
		do_ipsec = B_TRUE;
	}

	ip_attr_nexthop(&connp->conn_xmit_ipp, ixa, &v6dst, &v6nexthop);
	mutex_exit(&connp->conn_lock);

	error = ip_attr_connect(connp, ixa, &v6src, &v6dst, &v6nexthop, dstport,
	    &v6src, NULL, IPDF_ALLOW_MCBC | IPDF_VERIFY_DST |
	    (do_ipsec ? IPDF_IPSEC : 0));
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
		goto ud_error;
	}

	mutex_enter(&connp->conn_lock);
	/*
	 * While we dropped the lock some other thread might have connected
	 * this socket. If so we bail out with EISCONN to ensure that the
	 * connecting thread is the one that updates conn_ixa, conn_ht_*
	 * and conn_*last*.
	 */
	if (icmp->icmp_state == TS_DATA_XFER) {
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
	 *  - a socket option with COA_HEADER_CHANGED has been set which
	 *    set conn_v6lastdst to zero.
	 *
	 * Otherwise the prepend function will just update the src, dst,
	 * and flow label.
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
		error = icmp_build_hdr_template(connp, &v6src, &v6dst,
		    flowinfo);
		if (error != 0) {
			mutex_exit(&connp->conn_lock);
			goto ud_error;
		}
	} else if (connp->conn_xmit_ipp.ipp_fields &
	    (IPPF_IPV4_OPTIONS|IPPF_RTHDR) ||
	    IN6_IS_ADDR_UNSPECIFIED(&connp->conn_v6lastdst)) {
		/* Rebuild the header template */
		error = icmp_build_hdr_template(connp, &v6src, &v6dst,
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
	 * Remember the dst etc which corresponds to the built header
	 * template and conn_ixa.
	 */
	oldixa = conn_replace_ixa(connp, ixa);
	connp->conn_v6lastdst = v6dst;
	connp->conn_lastflowinfo = flowinfo;
	connp->conn_lastscopeid = ixa->ixa_scopeid;
	connp->conn_lastsrcid = srcid;
	/* Also remember a source to use together with lastdst */
	connp->conn_v6lastsrc = v6src;

	data_mp = icmp_prepend_header_template(connp, ixa, data_mp, &v6src,
	    flowinfo, &error);

	/* Done with conn_t */
	mutex_exit(&connp->conn_lock);
	ixa_refrele(oldixa);

	if (data_mp == NULL) {
		ASSERT(error != 0);
		goto ud_error;
	}

	if (!do_ipsec) {
		/* Policy might differ for different ICMP type/code */
		data_mp = icmp_output_attach_policy(data_mp, connp, ixa);
		if (data_mp == NULL) {
			BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
			error = EHOSTUNREACH;	/* IPsec policy failure */
			goto done;
		}
	}

	/* We're done.  Pass the packet to ip. */
	BUMP_MIB(&is->is_rawip_mib, rawipOutDatagrams);

	error = conn_ip_output(data_mp, ixa);
	/* No rawipOutErrors if an error since IP increases its error counter */
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
	return (error);

ud_error:
	ASSERT(!(ixa->ixa_free_flags & IXA_FREE_CRED));
	ixa->ixa_cred = connp->conn_cred;	/* Restore */
	ixa->ixa_cpid = connp->conn_cpid;
	ixa_refrele(ixa);

	BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
	freemsg(data_mp);
	return (error);
}

/* ARGSUSED */
static void
icmp_wput_fallback(queue_t *q, mblk_t *mp)
{
#ifdef DEBUG
	cmn_err(CE_CONT, "icmp_wput_fallback: Message during fallback \n");
#endif
	freemsg(mp);
}

static void
icmp_wput_other(queue_t *q, mblk_t *mp)
{
	uchar_t	*rptr = mp->b_rptr;
	struct iocblk *iocp;
	conn_t	*connp = Q_TO_CONN(q);
	icmp_t	*icmp = connp->conn_icmp;
	cred_t *cr;

	switch (mp->b_datap->db_type) {
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
			icmp_addr_req(q, mp);
			return;
		case O_T_BIND_REQ:
		case T_BIND_REQ:
			icmp_tpi_bind(q, mp);
			return;
		case T_CONN_REQ:
			icmp_tpi_connect(q, mp);
			return;
		case T_CAPABILITY_REQ:
			icmp_capability_req(q, mp);
			return;
		case T_INFO_REQ:
			icmp_info_req(q, mp);
			return;
		case T_UNITDATA_REQ:
			/*
			 * If a T_UNITDATA_REQ gets here, the address must
			 * be bad.  Valid T_UNITDATA_REQs are handled
			 * in icmp_wput.
			 */
			icmp_ud_err(q, mp, EADDRNOTAVAIL);
			return;
		case T_UNBIND_REQ:
			icmp_tpi_unbind(q, mp);
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
				icmp_err_ack(q, mp, TSYSERR, EINVAL);
				return;
			}

			if (!snmpcom_req(q, mp, icmp_snmp_set, ip_snmp_get,
			    cr)) {
				svr4_optcom_req(q, mp, cr, &icmp_opt_obj);
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
				icmp_err_ack(q, mp, TSYSERR, EINVAL);
				return;
			}
			tpi_optcom_req(q, mp, cr, &icmp_opt_obj);
			return;

		case T_DISCON_REQ:
			icmp_tpi_disconnect(q, mp);
			return;

		/* The following TPI message is not supported by icmp. */
		case O_T_CONN_RES:
		case T_CONN_RES:
			icmp_err_ack(q, mp, TNOTSUPPORT, 0);
			return;

		/* The following 3 TPI requests are illegal for icmp. */
		case T_DATA_REQ:
		case T_EXDATA_REQ:
		case T_ORDREL_REQ:
			icmp_err_ack(q, mp, TNOTSUPPORT, 0);
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
			if (icmp->icmp_state != TS_DATA_XFER) {
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
		default:
			break;
		}
		break;
	case M_IOCDATA:
		icmp_wput_iocdata(q, mp);
		return;
	default:
		/* Unrecognized messages are passed through without change. */
		break;
	}
	ip_wput_nondata(q, mp);
}

/*
 * icmp_wput_iocdata is called by icmp_wput_other to handle all M_IOCDATA
 * messages.
 */
static void
icmp_wput_iocdata(queue_t *q, mblk_t *mp)
{
	mblk_t		*mp1;
	STRUCT_HANDLE(strbuf, sb);
	uint_t		addrlen;
	conn_t		*connp = Q_TO_CONN(q);
	icmp_t		*icmp = connp->conn_icmp;

	/* Make sure it is one of ours. */
	switch (((struct iocblk *)mp->b_rptr)->ioc_cmd) {
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
	STRUCT_SET_HANDLE(sb, ((struct iocblk *)mp->b_rptr)->ioc_flag,
	    (void *)mp1->b_rptr);

	if (connp->conn_family == AF_INET)
		addrlen = sizeof (sin_t);
	else
		addrlen = sizeof (sin6_t);

	if (STRUCT_FGET(sb, maxlen) < addrlen) {
		mi_copy_done(q, mp, EINVAL);
		return;
	}
	switch (((struct iocblk *)mp->b_rptr)->ioc_cmd) {
	case TI_GETMYNAME:
		break;
	case TI_GETPEERNAME:
		if (icmp->icmp_state != TS_DATA_XFER) {
			mi_copy_done(q, mp, ENOTCONN);
			return;
		}
		break;
	default:
		mi_copy_done(q, mp, EPROTO);
		return;
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
icmp_ddi_g_init(void)
{
	icmp_max_optsize = optcom_max_optsize(icmp_opt_obj.odb_opt_des_arr,
	    icmp_opt_obj.odb_opt_arr_cnt);

	/*
	 * We want to be informed each time a stack is created or
	 * destroyed in the kernel, so we can maintain the
	 * set of icmp_stack_t's.
	 */
	netstack_register(NS_ICMP, rawip_stack_init, NULL, rawip_stack_fini);
}

void
icmp_ddi_g_destroy(void)
{
	netstack_unregister(NS_ICMP);
}

#define	INET_NAME	"ip"

/*
 * Initialize the ICMP stack instance.
 */
static void *
rawip_stack_init(netstackid_t stackid, netstack_t *ns)
{
	icmp_stack_t	*is;
	int		error = 0;
	size_t		arrsz;
	major_t		major;

	is = (icmp_stack_t *)kmem_zalloc(sizeof (*is), KM_SLEEP);
	is->is_netstack = ns;

	arrsz = sizeof (icmp_propinfo_tbl);
	is->is_propinfo_tbl = (mod_prop_info_t *)kmem_alloc(arrsz, KM_SLEEP);
	bcopy(icmp_propinfo_tbl, is->is_propinfo_tbl, arrsz);

	is->is_ksp = rawip_kstat_init(stackid);

	major = mod_name_to_major(INET_NAME);
	error = ldi_ident_from_major(major, &is->is_ldi_ident);
	ASSERT(error == 0);
	return (is);
}

/*
 * Free the ICMP stack instance.
 */
static void
rawip_stack_fini(netstackid_t stackid, void *arg)
{
	icmp_stack_t *is = (icmp_stack_t *)arg;

	kmem_free(is->is_propinfo_tbl, sizeof (icmp_propinfo_tbl));
	is->is_propinfo_tbl = NULL;

	rawip_kstat_fini(stackid, is->is_ksp);
	is->is_ksp = NULL;
	ldi_ident_release(is->is_ldi_ident);
	kmem_free(is, sizeof (*is));
}

static void *
rawip_kstat_init(netstackid_t stackid) {
	kstat_t	*ksp;

	rawip_named_kstat_t template = {
		{ "inDatagrams",	KSTAT_DATA_UINT32, 0 },
		{ "inCksumErrs",	KSTAT_DATA_UINT32, 0 },
		{ "inErrors",		KSTAT_DATA_UINT32, 0 },
		{ "outDatagrams",	KSTAT_DATA_UINT32, 0 },
		{ "outErrors",		KSTAT_DATA_UINT32, 0 },
	};

	ksp = kstat_create_netstack("icmp", 0, "rawip", "mib2",
					KSTAT_TYPE_NAMED,
					NUM_OF_FIELDS(rawip_named_kstat_t),
					0, stackid);
	if (ksp == NULL || ksp->ks_data == NULL)
		return (NULL);

	bcopy(&template, ksp->ks_data, sizeof (template));
	ksp->ks_update = rawip_kstat_update;
	ksp->ks_private = (void *)(uintptr_t)stackid;

	kstat_install(ksp);
	return (ksp);
}

static void
rawip_kstat_fini(netstackid_t stackid, kstat_t *ksp)
{
	if (ksp != NULL) {
		ASSERT(stackid == (netstackid_t)(uintptr_t)ksp->ks_private);
		kstat_delete_netstack(ksp, stackid);
	}
}

static int
rawip_kstat_update(kstat_t *ksp, int rw)
{
	rawip_named_kstat_t *rawipkp;
	netstackid_t	stackid = (netstackid_t)(uintptr_t)ksp->ks_private;
	netstack_t	*ns;
	icmp_stack_t	*is;

	if ((ksp == NULL) || (ksp->ks_data == NULL))
		return (EIO);

	if (rw == KSTAT_WRITE)
		return (EACCES);

	rawipkp = (rawip_named_kstat_t *)ksp->ks_data;

	ns = netstack_find_by_stackid(stackid);
	if (ns == NULL)
		return (-1);
	is = ns->netstack_icmp;
	if (is == NULL) {
		netstack_rele(ns);
		return (-1);
	}
	rawipkp->inDatagrams.value.ui32 =  is->is_rawip_mib.rawipInDatagrams;
	rawipkp->inCksumErrs.value.ui32 =  is->is_rawip_mib.rawipInCksumErrs;
	rawipkp->inErrors.value.ui32 =	   is->is_rawip_mib.rawipInErrors;
	rawipkp->outDatagrams.value.ui32 = is->is_rawip_mib.rawipOutDatagrams;
	rawipkp->outErrors.value.ui32 =	   is->is_rawip_mib.rawipOutErrors;
	netstack_rele(ns);
	return (0);
}

/* ARGSUSED */
int
rawip_accept(sock_lower_handle_t lproto_handle,
    sock_lower_handle_t eproto_handle, sock_upper_handle_t sock_handle,
    cred_t *cr)
{
	return (EOPNOTSUPP);
}

/* ARGSUSED */
int
rawip_bind(sock_lower_handle_t proto_handle, struct sockaddr *sa,
    socklen_t len, cred_t *cr)
{
	conn_t  *connp = (conn_t *)proto_handle;
	int	error;

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	/* Binding to a NULL address really means unbind */
	if (sa == NULL)
		error = rawip_do_unbind(connp);
	else
		error = rawip_do_bind(connp, sa, len);

	if (error < 0) {
		if (error == -TOUTSTATE)
			error = EINVAL;
		else
			error = proto_tlitosyserr(-error);
	}
	return (error);
}

static int
rawip_implicit_bind(conn_t *connp)
{
	sin6_t sin6addr;
	sin_t *sin;
	sin6_t *sin6;
	socklen_t len;
	int error;

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

	error = rawip_do_bind(connp, (struct sockaddr *)&sin6addr, len);

	return ((error < 0) ? proto_tlitosyserr(-error) : error);
}

static int
rawip_unbind(conn_t *connp)
{
	int error;

	error = rawip_do_unbind(connp);
	if (error < 0) {
		error = proto_tlitosyserr(-error);
	}
	return (error);
}

/* ARGSUSED */
int
rawip_listen(sock_lower_handle_t proto_handle, int backlog, cred_t *cr)
{
	return (EOPNOTSUPP);
}

int
rawip_connect(sock_lower_handle_t proto_handle, const struct sockaddr *sa,
    socklen_t len, sock_connid_t *id, cred_t *cr)
{
	conn_t	*connp = (conn_t *)proto_handle;
	icmp_t *icmp = connp->conn_icmp;
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
		if (icmp->icmp_state != TS_DATA_XFER)
			return (EINVAL);

		error = icmp_disconnect(connp);
		return (error);
	}

	error = proto_verify_ip_addr(connp->conn_family, sa, len);
	if (error != 0)
		return (error);

	/* do an implicit bind if necessary */
	if (icmp->icmp_state == TS_UNBND) {
		error = rawip_implicit_bind(connp);
		/*
		 * We could be racing with an actual bind, in which case
		 * we would see EPROTO. We cross our fingers and try
		 * to connect.
		 */
		if (!(error == 0 || error == EPROTO))
			return (error);
		did_bind = B_TRUE;
	}

	/*
	 * set SO_DGRAM_ERRIND
	 */
	connp->conn_dgram_errind = B_TRUE;

	error = rawip_do_connect(connp, sa, len, cr, pid);
	if (error != 0 && did_bind) {
		int unbind_err;

		unbind_err = rawip_unbind(connp);
		ASSERT(unbind_err == 0);
	}

	if (error == 0) {
		*id = 0;
		(*connp->conn_upcalls->su_connected)(connp->conn_upper_handle,
		    0, NULL, -1);
	} else if (error < 0) {
		error = proto_tlitosyserr(-error);
	}
	return (error);
}

/* ARGSUSED2 */
int
rawip_fallback(sock_lower_handle_t proto_handle, queue_t *q,
    boolean_t direct_sockfs, so_proto_quiesced_cb_t quiesced_cb,
    sock_quiesce_arg_t *arg)
{
	conn_t  *connp = (conn_t *)proto_handle;
	icmp_t	*icmp;
	struct T_capability_ack tca;
	struct sockaddr_in6 laddr, faddr;
	socklen_t laddrlen, faddrlen;
	short opts;
	struct stroptions *stropt;
	mblk_t *mp, *stropt_mp;
	int error;

	icmp = connp->conn_icmp;

	stropt_mp = allocb_wait(sizeof (*stropt), BPRI_HI, STR_NOSIG, NULL);

	/*
	 * setup the fallback stream that was allocated
	 */
	connp->conn_dev = (dev_t)RD(q)->q_ptr;
	connp->conn_minor_arena = WR(q)->q_ptr;

	RD(q)->q_ptr = WR(q)->q_ptr = connp;

	WR(q)->q_qinfo = &icmpwinit;

	connp->conn_rq = RD(q);
	connp->conn_wq = WR(q);

	/* Notify stream head about options before sending up data */
	stropt_mp->b_datap->db_type = M_SETOPTS;
	stropt_mp->b_wptr += sizeof (*stropt);
	stropt = (struct stroptions *)stropt_mp->b_rptr;
	stropt->so_flags = SO_WROFF | SO_HIWAT;
	stropt->so_wroff = connp->conn_wroff;
	stropt->so_hiwat = connp->conn_rcvbuf;
	putnext(RD(q), stropt_mp);

	/*
	 * free helper stream
	 */
	ip_free_helper_stream(connp);

	/*
	 * Collect the information needed to sync with the sonode
	 */
	icmp_do_capability_ack(icmp, &tca, TC1_INFO);

	laddrlen = faddrlen = sizeof (sin6_t);
	(void) rawip_getsockname((sock_lower_handle_t)connp,
	    (struct sockaddr *)&laddr, &laddrlen, CRED());
	error = rawip_getpeername((sock_lower_handle_t)connp,
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

	/*
	 * Attempts to send data up during fallback will result in it being
	 * queued in icmp_t. Now we push up any queued packets.
	 */
	mutex_enter(&icmp->icmp_recv_lock);
	if (mp != NULL) {
		mp->b_next = icmp->icmp_fallback_queue_head;
		icmp->icmp_fallback_queue_head = mp;
	}
	while (icmp->icmp_fallback_queue_head != NULL) {
		mp = icmp->icmp_fallback_queue_head;
		icmp->icmp_fallback_queue_head = mp->b_next;
		mp->b_next = NULL;
		mutex_exit(&icmp->icmp_recv_lock);
		putnext(RD(q), mp);
		mutex_enter(&icmp->icmp_recv_lock);
	}
	icmp->icmp_fallback_queue_tail = icmp->icmp_fallback_queue_head;

	/*
	 * No longer a streams less socket
	 */
	mutex_enter(&connp->conn_lock);
	connp->conn_flags &= ~IPCL_NONSTR;
	mutex_exit(&connp->conn_lock);

	mutex_exit(&icmp->icmp_recv_lock);

	ASSERT(icmp->icmp_fallback_queue_head == NULL &&
	    icmp->icmp_fallback_queue_tail == NULL);

	ASSERT(connp->conn_ref >= 1);

	return (0);
}

/* ARGSUSED2 */
sock_lower_handle_t
rawip_create(int family, int type, int proto, sock_downcalls_t **sock_downcalls,
    uint_t *smodep, int *errorp, int flags, cred_t *credp)
{
	conn_t *connp;

	if (type != SOCK_RAW || (family != AF_INET && family != AF_INET6)) {
		*errorp = EPROTONOSUPPORT;
		return (NULL);
	}

	connp = rawip_do_open(family, credp, errorp, flags);
	if (connp != NULL) {
		connp->conn_flags |= IPCL_NONSTR;

		mutex_enter(&connp->conn_lock);
		connp->conn_state_flags &= ~CONN_INCIPIENT;
		mutex_exit(&connp->conn_lock);
		*sock_downcalls = &sock_rawip_downcalls;
		*smodep = SM_ATOMIC;
	} else {
		ASSERT(*errorp != 0);
	}

	return ((sock_lower_handle_t)connp);
}

/* ARGSUSED3 */
void
rawip_activate(sock_lower_handle_t proto_handle,
    sock_upper_handle_t sock_handle, sock_upcalls_t *sock_upcalls, int flags,
    cred_t *cr)
{
	conn_t 			*connp = (conn_t *)proto_handle;
	struct sock_proto_props sopp;

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	connp->conn_upcalls = sock_upcalls;
	connp->conn_upper_handle = sock_handle;

	sopp.sopp_flags = SOCKOPT_WROFF | SOCKOPT_RCVHIWAT | SOCKOPT_RCVLOWAT |
	    SOCKOPT_MAXBLK | SOCKOPT_MAXPSZ | SOCKOPT_MINPSZ;
	sopp.sopp_wroff = connp->conn_wroff;
	sopp.sopp_rxhiwat = connp->conn_rcvbuf;
	sopp.sopp_rxlowat = connp->conn_rcvlowat;
	sopp.sopp_maxblk = INFPSZ;
	sopp.sopp_maxpsz = IP_MAXPACKET;
	sopp.sopp_minpsz = (icmp_mod_info.mi_minpsz == 1) ? 0 :
	    icmp_mod_info.mi_minpsz;

	(*connp->conn_upcalls->su_set_proto_props)
	    (connp->conn_upper_handle, &sopp);

	icmp_bind_proto(connp->conn_icmp);
}

/* ARGSUSED3 */
int
rawip_getpeername(sock_lower_handle_t proto_handle, struct sockaddr *sa,
    socklen_t *salenp, cred_t *cr)
{
	conn_t  *connp = (conn_t *)proto_handle;
	icmp_t  *icmp = connp->conn_icmp;
	int	error;

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	mutex_enter(&connp->conn_lock);
	if (icmp->icmp_state != TS_DATA_XFER)
		error = ENOTCONN;
	else
		error = conn_getpeername(connp, sa, salenp);
	mutex_exit(&connp->conn_lock);
	return (error);
}

/* ARGSUSED3 */
int
rawip_getsockname(sock_lower_handle_t proto_handle, struct sockaddr *sa,
    socklen_t *salenp, cred_t *cr)
{
	conn_t  *connp = (conn_t *)proto_handle;
	int	error;

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	mutex_enter(&connp->conn_lock);
	error = conn_getsockname(connp, sa, salenp);
	mutex_exit(&connp->conn_lock);
	return (error);
}

int
rawip_setsockopt(sock_lower_handle_t proto_handle, int level, int option_name,
    const void *optvalp, socklen_t optlen, cred_t *cr)
{
	conn_t	*connp = (conn_t *)proto_handle;
	int error;

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	error = proto_opt_check(level, option_name, optlen, NULL,
	    icmp_opt_obj.odb_opt_des_arr,
	    icmp_opt_obj.odb_opt_arr_cnt,
	    B_TRUE, B_FALSE, cr);

	if (error != 0) {
		/*
		 * option not recognized
		 */
		if (error < 0) {
			error = proto_tlitosyserr(-error);
		}
		return (error);
	}

	error = icmp_opt_set(connp, SETFN_OPTCOM_NEGOTIATE, level,
	    option_name, optlen, (uchar_t *)optvalp, (uint_t *)&optlen,
	    (uchar_t *)optvalp, NULL, cr);

	ASSERT(error >= 0);

	return (error);
}

int
rawip_getsockopt(sock_lower_handle_t proto_handle, int level, int option_name,
    void *optvalp, socklen_t *optlen, cred_t *cr)
{
	int		error;
	conn_t		*connp = (conn_t *)proto_handle;
	t_uscalar_t	max_optbuf_len;
	void		*optvalp_buf;
	int		len;

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	error = proto_opt_check(level, option_name, *optlen, &max_optbuf_len,
	    icmp_opt_obj.odb_opt_des_arr,
	    icmp_opt_obj.odb_opt_arr_cnt,
	    B_FALSE, B_TRUE, cr);

	if (error != 0) {
		if (error < 0) {
			error = proto_tlitosyserr(-error);
		}
		return (error);
	}

	optvalp_buf = kmem_alloc(max_optbuf_len, KM_SLEEP);
	len = icmp_opt_get(connp, level, option_name, optvalp_buf);
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

/* ARGSUSED1 */
int
rawip_close(sock_lower_handle_t proto_handle, int flags, cred_t *cr)
{
	conn_t	*connp = (conn_t *)proto_handle;

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	(void) rawip_do_close(connp);
	return (0);
}

/* ARGSUSED2 */
int
rawip_shutdown(sock_lower_handle_t proto_handle, int how, cred_t *cr)
{
	conn_t  *connp = (conn_t *)proto_handle;

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

void
rawip_clr_flowctrl(sock_lower_handle_t proto_handle)
{
	conn_t  *connp = (conn_t *)proto_handle;
	icmp_t	*icmp = connp->conn_icmp;

	mutex_enter(&icmp->icmp_recv_lock);
	connp->conn_flow_cntrld = B_FALSE;
	mutex_exit(&icmp->icmp_recv_lock);
}

int
rawip_ioctl(sock_lower_handle_t proto_handle, int cmd, intptr_t arg,
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
		icmp_stack_t *is = connp->conn_icmp->icmp_is;

		ASSERT(is->is_ldi_ident != NULL);

		/*
		 * Create a helper stream for non-STREAMS socket.
		 */
		error = ip_create_helper_stream(connp, is->is_ldi_ident);
		if (error != 0) {
			ip0dbg(("rawip_ioctl: create of IP helper stream "
			    "failed %d\n", error));
			return (error);
		}
	}

	switch (cmd) {
	case _SIOCSOCKFALLBACK:
	case TI_GETPEERNAME:
	case TI_GETMYNAME:
#ifdef DEBUG
		cmn_err(CE_CONT, "icmp_ioctl cmd 0x%x on non streams"
		    " socket", cmd);
#endif
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

int
rawip_send(sock_lower_handle_t proto_handle, mblk_t *mp, struct nmsghdr *msg,
    cred_t *cr)
{
	sin6_t		*sin6;
	sin_t		*sin = NULL;
	uint_t		srcid;
	conn_t		*connp = (conn_t *)proto_handle;
	icmp_t		*icmp = connp->conn_icmp;
	int		error = 0;
	icmp_stack_t	*is = icmp->icmp_is;
	pid_t		pid = curproc->p_pid;
	ip_xmit_attr_t	*ixa;

	ASSERT(DB_TYPE(mp) == M_DATA);

	/* All Solaris components should pass a cred for this operation. */
	ASSERT(cr != NULL);

	/* do an implicit bind if necessary */
	if (icmp->icmp_state == TS_UNBND) {
		error = rawip_implicit_bind(connp);
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

	/* Protocol 255 contains full IP headers */
	/* Read without holding lock */
	if (icmp->icmp_hdrincl) {
		ASSERT(connp->conn_ipversion == IPV4_VERSION);
		if (mp->b_wptr - mp->b_rptr < IP_SIMPLE_HDR_LENGTH) {
			if (!pullupmsg(mp, IP_SIMPLE_HDR_LENGTH)) {
				BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
				freemsg(mp);
				return (EINVAL);
			}
		}
		error = icmp_output_hdrincl(connp, mp, cr, pid);
		if (is->is_sendto_ignerr)
			return (0);
		else
			return (error);
	}

	/* Connected? */
	if (msg->msg_name == NULL) {
		if (icmp->icmp_state != TS_DATA_XFER) {
			BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
			return (EDESTADDRREQ);
		}
		if (msg->msg_controllen != 0) {
			error = icmp_output_ancillary(connp, NULL, NULL, mp,
			    NULL, msg, cr, pid);
		} else {
			error = icmp_output_connected(connp, mp, cr, pid);
		}
		if (is->is_sendto_ignerr)
			return (0);
		else
			return (error);
	}
	if (icmp->icmp_state == TS_DATA_XFER) {
		BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
		return (EISCONN);
	}
	error = proto_verify_ip_addr(connp->conn_family,
	    (struct sockaddr *)msg->msg_name, msg->msg_namelen);
	if (error != 0) {
		BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
		return (error);
	}
	switch (connp->conn_family) {
	case AF_INET6:
		sin6 = (sin6_t *)msg->msg_name;

		/* No support for mapped addresses on raw sockets */
		if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
			BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
			return (EADDRNOTAVAIL);
		}
		srcid = sin6->__sin6_src_id;

		/*
		 * If the local address is a mapped address return
		 * an error.
		 * It would be possible to send an IPv6 packet but the
		 * response would never make it back to the application
		 * since it is bound to a mapped address.
		 */
		if (IN6_IS_ADDR_V4MAPPED(&connp->conn_saddr_v6)) {
			BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
			return (EADDRNOTAVAIL);
		}

		if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr))
			sin6->sin6_addr = ipv6_loopback;

		/*
		 * We have to allocate an ip_xmit_attr_t before we grab
		 * conn_lock and we need to hold conn_lock once we've check
		 * conn_same_as_last_v6 to handle concurrent send* calls on a
		 * socket.
		 */
		if (msg->msg_controllen == 0) {
			ixa = conn_get_ixa(connp, B_FALSE);
			if (ixa == NULL) {
				BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
				return (ENOMEM);
			}
		} else {
			ixa = NULL;
		}
		mutex_enter(&connp->conn_lock);
		if (icmp->icmp_delayed_error != 0) {
			sin6_t  *sin2 = (sin6_t *)&icmp->icmp_delayed_addr;

			error = icmp->icmp_delayed_error;
			icmp->icmp_delayed_error = 0;

			/* Compare IP address and family */

			if (IN6_ARE_ADDR_EQUAL(&sin6->sin6_addr,
			    &sin2->sin6_addr) &&
			    sin6->sin6_family == sin2->sin6_family) {
				mutex_exit(&connp->conn_lock);
				BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
				if (ixa != NULL)
					ixa_refrele(ixa);
				return (error);
			}
		}
		if (msg->msg_controllen != 0) {
			mutex_exit(&connp->conn_lock);
			ASSERT(ixa == NULL);
			error = icmp_output_ancillary(connp, NULL, sin6, mp,
			    NULL, msg, cr, pid);
		} else if (conn_same_as_last_v6(connp, sin6) &&
		    connp->conn_lastsrcid == srcid &&
		    ipsec_outbound_policy_current(ixa)) {
			/* icmp_output_lastdst drops conn_lock */
			error = icmp_output_lastdst(connp, mp, cr, pid, ixa);
		} else {
			/* icmp_output_newdst drops conn_lock */
			error = icmp_output_newdst(connp, mp, NULL, sin6, cr,
			    pid, ixa);
		}
		ASSERT(MUTEX_NOT_HELD(&connp->conn_lock));
		if (is->is_sendto_ignerr)
			return (0);
		else
			return (error);
	case AF_INET:
		sin = (sin_t *)msg->msg_name;

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
				BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
				return (ENOMEM);
			}
		} else {
			ixa = NULL;
		}
		mutex_enter(&connp->conn_lock);
		if (icmp->icmp_delayed_error != 0) {
			sin_t  *sin2 = (sin_t *)&icmp->icmp_delayed_addr;

			error = icmp->icmp_delayed_error;
			icmp->icmp_delayed_error = 0;

			/* Compare IP address */

			if (sin->sin_addr.s_addr == sin2->sin_addr.s_addr) {
				mutex_exit(&connp->conn_lock);
				BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
				if (ixa != NULL)
					ixa_refrele(ixa);
				return (error);
			}
		}

		if (msg->msg_controllen != 0) {
			mutex_exit(&connp->conn_lock);
			ASSERT(ixa == NULL);
			error = icmp_output_ancillary(connp, sin, NULL, mp,
			    NULL, msg, cr, pid);
		} else if (conn_same_as_last_v4(connp, sin) &&
		    ipsec_outbound_policy_current(ixa)) {
			/* icmp_output_lastdst drops conn_lock */
			error = icmp_output_lastdst(connp, mp, cr, pid, ixa);
		} else {
			/* icmp_output_newdst drops conn_lock */
			error = icmp_output_newdst(connp, mp, sin, NULL, cr,
			    pid, ixa);
		}
		ASSERT(MUTEX_NOT_HELD(&connp->conn_lock));
		if (is->is_sendto_ignerr)
			return (0);
		else
			return (error);
	default:
		return (EINVAL);
	}
}

sock_downcalls_t sock_rawip_downcalls = {
	rawip_activate,
	rawip_accept,
	rawip_bind,
	rawip_listen,
	rawip_connect,
	rawip_getpeername,
	rawip_getsockname,
	rawip_getsockopt,
	rawip_setsockopt,
	rawip_send,
	NULL,
	NULL,
	NULL,
	rawip_shutdown,
	rawip_clr_flowctrl,
	rawip_ioctl,
	rawip_close
};
