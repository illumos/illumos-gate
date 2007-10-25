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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/* Copyright (c) 1990 Mentat Inc. */


#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/kmem.h>
#include <sys/policy.h>
#include <sys/priv.h>
#include <sys/zone.h>
#include <sys/time.h>

#include <sys/socket.h>
#include <sys/isa_defs.h>
#include <sys/suntpi.h>
#include <sys/xti_inet.h>
#include <sys/netstack.h>

#include <net/route.h>
#include <net/if.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>
#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip6.h>
#include <inet/mi.h>
#include <inet/nd.h>
#include <inet/optcom.h>
#include <inet/snmpcom.h>
#include <inet/kstatcom.h>
#include <inet/rawip_impl.h>

#include <netinet/ip_mroute.h>
#include <inet/tcp.h>
#include <net/pfkeyv2.h>
#include <inet/ipsec_info.h>
#include <inet/ipclassifier.h>

#include <sys/tsol/label.h>
#include <sys/tsol/tnet.h>

#include <inet/ip_ire.h>
#include <inet/ip_if.h>

#include <inet/ip_impl.h>

/*
 * Synchronization notes:
 *
 * RAWIP is MT and uses the usual kernel synchronization primitives. There is
 * locks, which is icmp_rwlock. We also use conn_lock when updating things
 * which affect the IP classifier lookup.
 * The lock order is icmp_rwlock -> conn_lock.
 *
 * The icmp_rwlock:
 * This protects most of the other fields in the icmp_t. The exact list of
 * fields which are protected by each of the above locks is documented in
 * the icmp_t structure definition.
 *
 * Plumbing notes:
 * ICMP is always a device driver. For compatibility with mibopen() code
 * it is possible to I_PUSH "icmp", but that results in pushing a passthrough
 * dummy module.
 */

static void	icmp_addr_req(queue_t *q, mblk_t *mp);
static void	icmp_bind(queue_t *q, mblk_t *mp);
static void	icmp_bind_proto(queue_t *q);
static void	icmp_bind_result(conn_t *, mblk_t *);
static void	icmp_bind_ack(conn_t *, mblk_t *mp);
static void	icmp_bind_error(conn_t *, mblk_t *mp);
static int	icmp_build_hdrs(icmp_t *icmp);
static void	icmp_capability_req(queue_t *q, mblk_t *mp);
static int	icmp_close(queue_t *q);
static void	icmp_connect(queue_t *q, mblk_t *mp);
static void	icmp_disconnect(queue_t *q, mblk_t *mp);
static void	icmp_err_ack(queue_t *q, mblk_t *mp, t_scalar_t t_error,
		    int sys_error);
static void	icmp_err_ack_prim(queue_t *q, mblk_t *mp, t_scalar_t primitive,
		    t_scalar_t t_error, int sys_error);
static void	icmp_icmp_error(queue_t *q, mblk_t *mp);
static void	icmp_icmp_error_ipv6(queue_t *q, mblk_t *mp);
static void	icmp_info_req(queue_t *q, mblk_t *mp);
static void	icmp_input(void *, mblk_t *, void *);
static mblk_t	*icmp_ip_bind_mp(icmp_t *icmp, t_scalar_t bind_prim,
		    t_scalar_t addr_length, in_port_t);
static int	icmp_open(queue_t *q, dev_t *devp, int flag, int sflag,
		    cred_t *credp, boolean_t isv6);
static int	icmp_openv4(queue_t *q, dev_t *devp, int flag, int sflag,
		    cred_t *credp);
static int	icmp_openv6(queue_t *q, dev_t *devp, int flag, int sflag,
		    cred_t *credp);
static void	icmp_output(queue_t *q, mblk_t *mp);
static int	icmp_unitdata_opt_process(queue_t *q, mblk_t *mp,
		    int *errorp, void *thisdg_attrs);
static boolean_t icmp_opt_allow_udr_set(t_scalar_t level, t_scalar_t name);
int		icmp_opt_set(queue_t *q, uint_t optset_context,
		    int level, int name, uint_t inlen,
		    uchar_t *invalp, uint_t *outlenp, uchar_t *outvalp,
		    void *thisdg_attrs, cred_t *cr, mblk_t *mblk);
int		icmp_opt_get(queue_t *q, int level, int name,
		    uchar_t *ptr);
static int	icmp_param_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *cr);
static boolean_t icmp_param_register(IDP *ndp, icmpparam_t *icmppa, int cnt);
static int	icmp_param_set(queue_t *q, mblk_t *mp, char *value,
		    caddr_t cp, cred_t *cr);
static int	icmp_snmp_set(queue_t *q, t_scalar_t level, t_scalar_t name,
		    uchar_t *ptr, int len);
static int	icmp_status_report(queue_t *q, mblk_t *mp, caddr_t cp,
		    cred_t *cr);
static void	icmp_ud_err(queue_t *q, mblk_t *mp, t_scalar_t err);
static void	icmp_unbind(queue_t *q, mblk_t *mp);
static void	icmp_wput(queue_t *q, mblk_t *mp);
static void	icmp_wput_ipv6(queue_t *q, mblk_t *mp, sin6_t *sin6,
		    t_scalar_t tudr_optlen);
static void	icmp_wput_other(queue_t *q, mblk_t *mp);
static void	icmp_wput_iocdata(queue_t *q, mblk_t *mp);
static void	icmp_wput_restricted(queue_t *q, mblk_t *mp);

static void	*rawip_stack_init(netstackid_t stackid, netstack_t *ns);
static void	rawip_stack_fini(netstackid_t stackid, void *arg);

static void	*rawip_kstat_init(netstackid_t stackid);
static void	rawip_kstat_fini(netstackid_t stackid, kstat_t *ksp);
static int	rawip_kstat_update(kstat_t *kp, int rw);


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

/* For AF_INET aka /dev/icmp */
struct streamtab icmpinfov4 = {
	&icmprinitv4, &icmpwinit
};

/* For AF_INET6 aka /dev/icmp6 */
struct streamtab icmpinfov6 = {
	&icmprinitv6, &icmpwinit
};

static sin_t	sin_null;	/* Zero address for quick clears */
static sin6_t	sin6_null;	/* Zero address for quick clears */

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

/*
 * Table of ND variables supported by icmp.  These are loaded into is_nd
 * when the stack instance is created.
 * All of these are alterable, within the min/max values given, at run time.
 */
static icmpparam_t	icmp_param_arr[] = {
	/* min	max	value	name */
	{ 0,	128,	32,	"icmp_wroff_extra" },
	{ 1,	255,	255,	"icmp_ipv4_ttl" },
	{ 0, IPV6_MAX_HOPS, IPV6_DEFAULT_HOPS,	"icmp_ipv6_hoplimit"},
	{ 0,	1,	1,	"icmp_bsd_compat" },
	{ 4096,	65536,	8192,	"icmp_xmit_hiwat"},
	{ 0,	65536,	1024,	"icmp_xmit_lowat"},
	{ 4096,	65536,	8192,	"icmp_recv_hiwat"},
	{ 65536, 1024*1024*1024, 256*1024,	"icmp_max_buf"},
};
#define	is_wroff_extra			is_param_arr[0].icmp_param_value
#define	is_ipv4_ttl			is_param_arr[1].icmp_param_value
#define	is_ipv6_hoplimit		is_param_arr[2].icmp_param_value
#define	is_bsd_compat			is_param_arr[3].icmp_param_value
#define	is_xmit_hiwat			is_param_arr[4].icmp_param_value
#define	is_xmit_lowat			is_param_arr[5].icmp_param_value
#define	is_recv_hiwat			is_param_arr[6].icmp_param_value
#define	is_max_buf			is_param_arr[7].icmp_param_value

/*
 * This routine is called to handle each O_T_BIND_REQ/T_BIND_REQ message
 * passed to icmp_wput.
 * The O_T_BIND_REQ/T_BIND_REQ is passed downstream to ip with the ICMP
 * protocol type placed in the message following the address. A T_BIND_ACK
 * message is returned by ip_bind_v4/v6.
 */
static void
icmp_bind(queue_t *q, mblk_t *mp)
{
	sin_t	*sin;
	sin6_t	*sin6;
	mblk_t	*mp1;
	struct T_bind_req	*tbr;
	icmp_t	*icmp;
	conn_t	*connp = Q_TO_CONN(q);

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
		    "icmp_bind: bad state, %d", icmp->icmp_state);
		icmp_err_ack(q, mp, TOUTSTATE, 0);
		return;
	}
	/*
	 * Reallocate the message to make sure we have enough room for an
	 * address and the protocol type.
	 */
	mp1 = reallocb(mp, sizeof (struct T_bind_ack) + sizeof (sin6_t) + 1, 1);
	if (!mp1) {
		icmp_err_ack(q, mp, TSYSERR, ENOMEM);
		return;
	}
	mp = mp1;
	tbr = (struct T_bind_req *)mp->b_rptr;
	switch (tbr->ADDR_length) {
	case 0:			/* Generic request */
		tbr->ADDR_offset = sizeof (struct T_bind_req);
		if (icmp->icmp_family == AF_INET) {
			tbr->ADDR_length = sizeof (sin_t);
			sin = (sin_t *)&tbr[1];
			*sin = sin_null;
			sin->sin_family = AF_INET;
			mp->b_wptr = (uchar_t *)&sin[1];
		} else {
			ASSERT(icmp->icmp_family == AF_INET6);
			tbr->ADDR_length = sizeof (sin6_t);
			sin6 = (sin6_t *)&tbr[1];
			*sin6 = sin6_null;
			sin6->sin6_family = AF_INET6;
			mp->b_wptr = (uchar_t *)&sin6[1];
		}
		break;
	case sizeof (sin_t):	/* Complete IP address */
		sin = (sin_t *)mi_offset_param(mp, tbr->ADDR_offset,
		    sizeof (sin_t));
		if (sin == NULL || !OK_32PTR((char *)sin)) {
			icmp_err_ack(q, mp, TSYSERR, EINVAL);
			return;
		}
		if (icmp->icmp_family != AF_INET ||
		    sin->sin_family != AF_INET) {
			icmp_err_ack(q, mp, TSYSERR, EAFNOSUPPORT);
			return;
		}
		break;
	case sizeof (sin6_t):	/* Complete IP address */
		sin6 = (sin6_t *)mi_offset_param(mp, tbr->ADDR_offset,
		    sizeof (sin6_t));
		if (sin6 == NULL || !OK_32PTR((char *)sin6)) {
			icmp_err_ack(q, mp, TSYSERR, EINVAL);
			return;
		}
		if (icmp->icmp_family != AF_INET6 ||
		    sin6->sin6_family != AF_INET6) {
			icmp_err_ack(q, mp, TSYSERR, EAFNOSUPPORT);
			return;
		}
		/* No support for mapped addresses on raw sockets */
		if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
			icmp_err_ack(q, mp, TSYSERR, EADDRNOTAVAIL);
			return;
		}
		break;
	default:
		(void) mi_strlog(q, 1, SL_ERROR|SL_TRACE,
		    "icmp_bind: bad ADDR_length %d", tbr->ADDR_length);
		icmp_err_ack(q, mp, TBADADDR, 0);
		return;
	}

	/*
	 * The state must be TS_UNBND. TPI mandates that users must send
	 * TPI primitives only 1 at a time and wait for the response before
	 * sending the next primitive.
	 */
	rw_enter(&icmp->icmp_rwlock, RW_WRITER);
	if (icmp->icmp_state != TS_UNBND || icmp->icmp_pending_op != -1) {
		rw_exit(&icmp->icmp_rwlock);
		(void) mi_strlog(q, 1, SL_ERROR|SL_TRACE,
		    "icmp_bind: bad state, %d", icmp->icmp_state);
		icmp_err_ack(q, mp, TOUTSTATE, 0);
		return;
	}

	icmp->icmp_pending_op = tbr->PRIM_type;

	/*
	 * Copy the source address into our icmp structure.  This address
	 * may still be zero; if so, ip will fill in the correct address
	 * each time an outbound packet is passed to it.
	 * If we are binding to a broadcast or multicast address then
	 * icmp_bind_ack will clear the source address when it receives
	 * the T_BIND_ACK.
	 */
	icmp->icmp_state = TS_IDLE;

	if (icmp->icmp_family == AF_INET) {
		ASSERT(sin != NULL);
		ASSERT(icmp->icmp_ipversion == IPV4_VERSION);
		IN6_IPADDR_TO_V4MAPPED(sin->sin_addr.s_addr,
		    &icmp->icmp_v6src);
		icmp->icmp_max_hdr_len = IP_SIMPLE_HDR_LENGTH +
		    icmp->icmp_ip_snd_options_len;
		icmp->icmp_bound_v6src = icmp->icmp_v6src;
	} else {
		int error;

		ASSERT(sin6 != NULL);
		ASSERT(icmp->icmp_ipversion == IPV6_VERSION);
		icmp->icmp_v6src = sin6->sin6_addr;
		icmp->icmp_max_hdr_len = icmp->icmp_sticky_hdrs_len;
		icmp->icmp_bound_v6src = icmp->icmp_v6src;

		/* Rebuild the header template */
		error = icmp_build_hdrs(icmp);
		if (error != 0) {
			icmp->icmp_pending_op = -1;
			rw_exit(&icmp->icmp_rwlock);
			icmp_err_ack(q, mp, TSYSERR, error);
			return;
		}
	}
	/*
	 * Place protocol type in the O_T_BIND_REQ/T_BIND_REQ following
	 * the address.
	 */
	*mp->b_wptr++ = icmp->icmp_proto;
	if (!(V6_OR_V4_INADDR_ANY(icmp->icmp_v6src))) {
		/*
		 * Append a request for an IRE if src not 0 (INADDR_ANY)
		 */
		mp->b_cont = allocb(sizeof (ire_t), BPRI_HI);
		if (!mp->b_cont) {
			icmp->icmp_pending_op = -1;
			rw_exit(&icmp->icmp_rwlock);
			icmp_err_ack(q, mp, TSYSERR, ENOMEM);
			return;
		}
		mp->b_cont->b_wptr += sizeof (ire_t);
		mp->b_cont->b_datap->db_type = IRE_DB_REQ_TYPE;
	}
	rw_exit(&icmp->icmp_rwlock);

	/* Pass the O_T_BIND_REQ/T_BIND_REQ to ip. */
	if (icmp->icmp_family == AF_INET6)
		mp = ip_bind_v6(q, mp, connp, NULL);
	else
		mp = ip_bind_v4(q, mp, connp);

	/* The above return NULL if the bind needs to be deferred */
	if (mp != NULL)
		icmp_bind_result(connp, mp);
	else
		CONN_INC_REF(connp);
}

/*
 * Send message to IP to just bind to the protocol.
 */
static void
icmp_bind_proto(queue_t *q)
{
	mblk_t	*mp;
	struct T_bind_req	*tbr;
	icmp_t	*icmp;
	conn_t	*connp = Q_TO_CONN(q);

	icmp = connp->conn_icmp;

	mp = allocb(sizeof (struct T_bind_req) + sizeof (sin6_t) + 1,
	    BPRI_MED);
	if (!mp) {
		return;
	}
	mp->b_datap->db_type = M_PROTO;
	tbr = (struct T_bind_req *)mp->b_rptr;
	tbr->PRIM_type = O_T_BIND_REQ; /* change to T_BIND_REQ ? */
	tbr->ADDR_offset = sizeof (struct T_bind_req);

	rw_enter(&icmp->icmp_rwlock, RW_WRITER);
	if (icmp->icmp_ipversion == IPV4_VERSION) {
		sin_t	*sin;

		tbr->ADDR_length = sizeof (sin_t);
		sin = (sin_t *)&tbr[1];
		*sin = sin_null;
		sin->sin_family = AF_INET;
		mp->b_wptr = (uchar_t *)&sin[1];
	} else {
		sin6_t	*sin6;

		ASSERT(icmp->icmp_ipversion == IPV6_VERSION);
		tbr->ADDR_length = sizeof (sin6_t);
		sin6 = (sin6_t *)&tbr[1];
		*sin6 = sin6_null;
		sin6->sin6_family = AF_INET6;
		mp->b_wptr = (uchar_t *)&sin6[1];
	}

	/* Place protocol type in the O_T_BIND_REQ following the address. */
	*mp->b_wptr++ = icmp->icmp_proto;
	rw_exit(&icmp->icmp_rwlock);

	/* Pass the O_T_BIND_REQ to ip. */
	if (icmp->icmp_family == AF_INET6)
		mp = ip_bind_v6(q, mp, connp, NULL);
	else
		mp = ip_bind_v4(q, mp, connp);

	/* The above return NULL if the bind needs to be deferred */
	if (mp != NULL)
		icmp_bind_result(connp, mp);
	else
		CONN_INC_REF(connp);
}

/*
 * This is called from ip_wput_nondata to handle the results of a
 * deferred RAWIP bind.  It is called once the bind has been completed.
 */
void
rawip_resume_bind(conn_t *connp, mblk_t *mp)
{
	ASSERT(connp != NULL && IPCL_IS_RAWIP(connp));

	icmp_bind_result(connp, mp);

	CONN_OPER_PENDING_DONE(connp);
}

/*
 * This routine handles each T_CONN_REQ message passed to icmp.  It
 * associates a default destination address with the stream.
 *
 * This routine sends down a T_BIND_REQ to IP with the following mblks:
 *	T_BIND_REQ	- specifying local and remote address.
 *	IRE_DB_REQ_TYPE	- to get an IRE back containing ire_type and src
 *	T_OK_ACK	- for the T_CONN_REQ
 *	T_CONN_CON	- to keep the TPI user happy
 *
 * The connect completes in icmp_bind_result.
 * When a T_BIND_ACK is received information is extracted from the IRE
 * and the two appended messages are sent to the TPI user.
 * Should icmp_bind_result receive T_ERROR_ACK for the T_BIND_REQ it will
 * convert it to an error ack for the appropriate primitive.
 */
static void
icmp_connect(queue_t *q, mblk_t *mp)
{
	sin_t	*sin;
	sin6_t	*sin6;
	mblk_t	*mp1, *mp2;
	struct T_conn_req	*tcr;
	icmp_t	*icmp;
	ipaddr_t	v4dst;
	in6_addr_t	v6dst;
	uint32_t	flowinfo;
	conn_t	*connp = Q_TO_CONN(q);

	icmp = connp->conn_icmp;
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

	switch (tcr->DEST_length) {
	default:
		icmp_err_ack(q, mp, TBADADDR, 0);
		return;

	case sizeof (sin_t):
		sin = (sin_t *)mi_offset_param(mp, tcr->DEST_offset,
		    sizeof (sin_t));
		if (sin == NULL || !OK_32PTR((char *)sin)) {
			icmp_err_ack(q, mp, TSYSERR, EINVAL);
			return;
		}
		if (icmp->icmp_family != AF_INET ||
		    sin->sin_family != AF_INET) {
			icmp_err_ack(q, mp, TSYSERR, EAFNOSUPPORT);
			return;
		}
		v4dst = sin->sin_addr.s_addr;
		IN6_IPADDR_TO_V4MAPPED(v4dst, &v6dst);
		ASSERT(icmp->icmp_ipversion == IPV4_VERSION);
		icmp->icmp_max_hdr_len = IP_SIMPLE_HDR_LENGTH +
		    icmp->icmp_ip_snd_options_len;
		break;

	case sizeof (sin6_t):
		sin6 = (sin6_t *)mi_offset_param(mp, tcr->DEST_offset,
		    sizeof (sin6_t));
		if (sin6 == NULL || !OK_32PTR((char *)sin6)) {
			icmp_err_ack(q, mp, TSYSERR, EINVAL);
			return;
		}
		if (icmp->icmp_family != AF_INET6 ||
		    sin6->sin6_family != AF_INET6) {
			icmp_err_ack(q, mp, TSYSERR, EAFNOSUPPORT);
			return;
		}
		/* No support for mapped addresses on raw sockets */
		if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
			icmp_err_ack(q, mp, TSYSERR, EADDRNOTAVAIL);
			return;
		}
		v6dst = sin6->sin6_addr;
		ASSERT(icmp->icmp_ipversion == IPV6_VERSION);
		icmp->icmp_max_hdr_len = icmp->icmp_sticky_hdrs_len;
		flowinfo = sin6->sin6_flowinfo;
		break;
	}
	if (icmp->icmp_ipversion == IPV4_VERSION) {
		/*
		 * Interpret a zero destination to mean loopback.
		 * Update the T_CONN_REQ (sin/sin6) since it is used to
		 * generate the T_CONN_CON.
		 */
		if (v4dst == INADDR_ANY) {
			v4dst = htonl(INADDR_LOOPBACK);
			IN6_IPADDR_TO_V4MAPPED(v4dst, &v6dst);
			if (icmp->icmp_family == AF_INET) {
				sin->sin_addr.s_addr = v4dst;
			} else {
				sin6->sin6_addr = v6dst;
			}
		}
		icmp->icmp_v6dst = v6dst;
		icmp->icmp_flowinfo = 0;

		/*
		 * If the destination address is multicast and
		 * an outgoing multicast interface has been set,
		 * use the address of that interface as our
		 * source address if no source address has been set.
		 */
		if (V4_PART_OF_V6(icmp->icmp_v6src) == INADDR_ANY &&
		    CLASSD(v4dst) &&
		    icmp->icmp_multicast_if_addr != INADDR_ANY) {
			IN6_IPADDR_TO_V4MAPPED(icmp->icmp_multicast_if_addr,
			    &icmp->icmp_v6src);
		}
	} else {
		ASSERT(icmp->icmp_ipversion == IPV6_VERSION);
		/*
		 * Interpret a zero destination to mean loopback.
		 * Update the T_CONN_REQ (sin/sin6) since it is used to
		 * generate the T_CONN_CON.
		 */
		if (IN6_IS_ADDR_UNSPECIFIED(&v6dst)) {
			v6dst = ipv6_loopback;
			sin6->sin6_addr = v6dst;
		}
		icmp->icmp_v6dst = v6dst;
		icmp->icmp_flowinfo = flowinfo;
		/*
		 * If the destination address is multicast and
		 * an outgoing multicast interface has been set,
		 * then the ip bind logic will pick the correct source
		 * address (i.e. matching the outgoing multicast interface).
		 */
	}

	rw_enter(&icmp->icmp_rwlock, RW_WRITER);
	if (icmp->icmp_state == TS_UNBND || icmp->icmp_pending_op != -1) {
		rw_exit(&icmp->icmp_rwlock);
		(void) mi_strlog(q, 1, SL_ERROR|SL_TRACE,
		    "icmp_connect: bad state, %d", icmp->icmp_state);
		icmp_err_ack(q, mp, TOUTSTATE, 0);
		return;
	}
	icmp->icmp_pending_op = T_CONN_REQ;

	if (icmp->icmp_state == TS_DATA_XFER) {
		/* Already connected - clear out state */
		icmp->icmp_v6src = icmp->icmp_bound_v6src;
		icmp->icmp_state = TS_IDLE;
	}

	/*
	 * Send down bind to IP to verify that there is a route
	 * and to determine the source address.
	 * This will come back as T_BIND_ACK with an IRE_DB_TYPE in rput.
	 */
	if (icmp->icmp_family == AF_INET) {
		mp1 = icmp_ip_bind_mp(icmp, O_T_BIND_REQ, sizeof (ipa_conn_t),
		    sin->sin_port);
	} else {
		ASSERT(icmp->icmp_family == AF_INET6);
		mp1 = icmp_ip_bind_mp(icmp, O_T_BIND_REQ, sizeof (ipa6_conn_t),
		    sin6->sin6_port);
	}
	if (mp1 == NULL) {
		icmp->icmp_pending_op = -1;
		rw_exit(&icmp->icmp_rwlock);
		icmp_err_ack(q, mp, TSYSERR, ENOMEM);
		return;
	}

	/*
	 * We also have to send a connection confirmation to
	 * keep TLI happy. Prepare it for icmp_bind_result.
	 */
	if (icmp->icmp_family == AF_INET) {
		mp2 = mi_tpi_conn_con(NULL, (char *)sin, sizeof (*sin), NULL,
		    0);
	} else {
		ASSERT(icmp->icmp_family == AF_INET6);
		mp2 = mi_tpi_conn_con(NULL, (char *)sin6, sizeof (*sin6), NULL,
		    0);
	}
	if (mp2 == NULL) {
		freemsg(mp1);
		icmp->icmp_pending_op = -1;
		rw_exit(&icmp->icmp_rwlock);
		icmp_err_ack(q, mp, TSYSERR, ENOMEM);
		return;
	}

	mp = mi_tpi_ok_ack_alloc(mp);
	if (mp == NULL) {
		/* Unable to reuse the T_CONN_REQ for the ack. */
		freemsg(mp2);
		icmp->icmp_pending_op = -1;
		rw_exit(&icmp->icmp_rwlock);
		icmp_err_ack_prim(q, mp1, T_CONN_REQ, TSYSERR, ENOMEM);
		return;
	}

	icmp->icmp_state = TS_DATA_XFER;
	rw_exit(&icmp->icmp_rwlock);

	/* Hang onto the T_OK_ACK and T_CONN_CON for later. */
	linkb(mp1, mp);
	linkb(mp1, mp2);

	mblk_setcred(mp1, connp->conn_cred);
	if (icmp->icmp_family == AF_INET)
		mp1 = ip_bind_v4(q, mp1, connp);
	else
		mp1 = ip_bind_v6(q, mp1, connp, NULL);

	/* The above return NULL if the bind needs to be deferred */
	if (mp1 != NULL)
		icmp_bind_result(connp, mp1);
	else
		CONN_INC_REF(connp);
}

static void
icmp_close_free(conn_t *connp)
{
	icmp_t *icmp = connp->conn_icmp;

	/* If there are any options associated with the stream, free them. */
	if (icmp->icmp_ip_snd_options != NULL) {
		mi_free((char *)icmp->icmp_ip_snd_options);
		icmp->icmp_ip_snd_options = NULL;
		icmp->icmp_ip_snd_options_len = 0;
	}

	if (icmp->icmp_filter != NULL) {
		kmem_free(icmp->icmp_filter, sizeof (icmp6_filter_t));
		icmp->icmp_filter = NULL;
	}
	/* Free memory associated with sticky options */
	if (icmp->icmp_sticky_hdrs_len != 0) {
		kmem_free(icmp->icmp_sticky_hdrs,
		    icmp->icmp_sticky_hdrs_len);
		icmp->icmp_sticky_hdrs = NULL;
		icmp->icmp_sticky_hdrs_len = 0;
	}
	ip6_pkt_free(&icmp->icmp_sticky_ipp);

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

static int
icmp_close(queue_t *q)
{
	conn_t	*connp = (conn_t *)q->q_ptr;

	ASSERT(connp != NULL && IPCL_IS_RAWIP(connp));

	ip_quiesce_conn(connp);

	qprocsoff(connp->conn_rq);

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

	inet_minor_free(ip_minor_arena, connp->conn_dev);

	connp->conn_ref--;
	ipcl_conn_destroy(connp);

	q->q_ptr = WR(q)->q_ptr = NULL;
	return (0);
}

/*
 * This routine handles each T_DISCON_REQ message passed to icmp
 * as an indicating that ICMP is no longer connected. This results
 * in sending a T_BIND_REQ to IP to restore the binding to just
 * the local address.
 *
 * This routine sends down a T_BIND_REQ to IP with the following mblks:
 *	T_BIND_REQ	- specifying just the local address.
 *	T_OK_ACK	- for the T_DISCON_REQ
 *
 * The disconnect completes in icmp_bind_result.
 * When a T_BIND_ACK is received the appended T_OK_ACK is sent to the TPI user.
 * Should icmp_bind_result receive T_ERROR_ACK for the T_BIND_REQ it will
 * convert it to an error ack for the appropriate primitive.
 */
static void
icmp_disconnect(queue_t *q, mblk_t *mp)
{
	icmp_t	*icmp;
	mblk_t	*mp1;
	conn_t	*connp = Q_TO_CONN(q);

	icmp = connp->conn_icmp;
	rw_enter(&icmp->icmp_rwlock, RW_WRITER);
	if (icmp->icmp_state != TS_DATA_XFER || icmp->icmp_pending_op != -1) {
		rw_exit(&icmp->icmp_rwlock);
		(void) mi_strlog(q, 1, SL_ERROR|SL_TRACE,
		    "icmp_disconnect: bad state, %d", icmp->icmp_state);
		icmp_err_ack(q, mp, TOUTSTATE, 0);
		return;
	}
	icmp->icmp_pending_op = T_DISCON_REQ;
	icmp->icmp_v6src = icmp->icmp_bound_v6src;
	icmp->icmp_state = TS_IDLE;

	/*
	 * Send down bind to IP to remove the full binding and revert
	 * to the local address binding.
	 */
	if (icmp->icmp_family == AF_INET) {
		mp1 = icmp_ip_bind_mp(icmp, O_T_BIND_REQ, sizeof (sin_t), 0);
	} else {
		ASSERT(icmp->icmp_family == AF_INET6);
		mp1 = icmp_ip_bind_mp(icmp, O_T_BIND_REQ, sizeof (sin6_t), 0);
	}
	if (mp1 == NULL) {
		icmp->icmp_pending_op = -1;
		rw_exit(&icmp->icmp_rwlock);
		icmp_err_ack(q, mp, TSYSERR, ENOMEM);
		return;
	}
	mp = mi_tpi_ok_ack_alloc(mp);
	if (mp == NULL) {
		/* Unable to reuse the T_DISCON_REQ for the ack. */
		icmp->icmp_pending_op = -1;
		rw_exit(&icmp->icmp_rwlock);
		icmp_err_ack_prim(q, mp1, T_DISCON_REQ, TSYSERR, ENOMEM);
		return;
	}

	if (icmp->icmp_family == AF_INET6) {
		int error;

		/* Rebuild the header template */
		error = icmp_build_hdrs(icmp);
		if (error != 0) {
			icmp->icmp_pending_op = -1;
			rw_exit(&icmp->icmp_rwlock);
			icmp_err_ack_prim(q, mp, T_DISCON_REQ, TSYSERR, error);
			freemsg(mp1);
			return;
		}
	}

	rw_exit(&icmp->icmp_rwlock);
	/* Append the T_OK_ACK to the T_BIND_REQ for icmp_bind_result */
	linkb(mp1, mp);

	if (icmp->icmp_family == AF_INET6)
		mp1 = ip_bind_v6(q, mp1, connp, NULL);
	else
		mp1 = ip_bind_v4(q, mp1, connp);

	/* The above return NULL if the bind needs to be deferred */
	if (mp1 != NULL)
		icmp_bind_result(connp, mp1);
	else
		CONN_INC_REF(connp);
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
 * icmp_icmp_error is called by icmp_input to process ICMP
 * messages passed up by IP.
 * Generates the appropriate T_UDERROR_IND for permanent
 * (non-transient) errors.
 * Assumes that IP has pulled up everything up to and including
 * the ICMP header.
 */
static void
icmp_icmp_error(queue_t *q, mblk_t *mp)
{
	icmph_t *icmph;
	ipha_t	*ipha;
	int	iph_hdr_length;
	sin_t	sin;
	sin6_t	sin6;
	mblk_t	*mp1;
	int	error = 0;
	icmp_t	*icmp = Q_TO_ICMP(q);

	ipha = (ipha_t *)mp->b_rptr;

	ASSERT(OK_32PTR(mp->b_rptr));

	if (IPH_HDR_VERSION(ipha) != IPV4_VERSION) {
		ASSERT(IPH_HDR_VERSION(ipha) == IPV6_VERSION);
		icmp_icmp_error_ipv6(q, mp);
		return;
	}
	ASSERT(IPH_HDR_VERSION(ipha) == IPV4_VERSION);

	/* Skip past the outer IP and ICMP headers */
	iph_hdr_length = IPH_HDR_LENGTH(ipha);
	icmph = (icmph_t *)(&mp->b_rptr[iph_hdr_length]);
	ipha = (ipha_t *)&icmph[1];
	iph_hdr_length = IPH_HDR_LENGTH(ipha);

	switch (icmph->icmph_type) {
	case ICMP_DEST_UNREACHABLE:
		switch (icmph->icmph_code) {
		case ICMP_FRAGMENTATION_NEEDED:
			/*
			 * IP has already adjusted the path MTU.
			 */
			break;
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
	if (!icmp->icmp_dgram_errind) {
		freemsg(mp);
		return;
	}

	switch (icmp->icmp_family) {
	case AF_INET:
		sin = sin_null;
		sin.sin_family = AF_INET;
		sin.sin_addr.s_addr = ipha->ipha_dst;
		mp1 = mi_tpi_uderror_ind((char *)&sin, sizeof (sin_t), NULL, 0,
		    error);
		break;
	case AF_INET6:
		sin6 = sin6_null;
		sin6.sin6_family = AF_INET6;
		IN6_IPADDR_TO_V4MAPPED(ipha->ipha_dst, &sin6.sin6_addr);

		mp1 = mi_tpi_uderror_ind((char *)&sin6, sizeof (sin6_t),
		    NULL, 0, error);
		break;
	}
	if (mp1)
		putnext(q, mp1);
	freemsg(mp);
}

/*
 * icmp_icmp_error_ipv6 is called by icmp_icmp_error to process ICMPv6
 * for IPv6 packets.
 * Send permanent (non-transient) errors upstream.
 * Assumes that IP has pulled up all the extension headers as well
 * as the ICMPv6 header.
 */
static void
icmp_icmp_error_ipv6(queue_t *q, mblk_t *mp)
{
	icmp6_t		*icmp6;
	ip6_t		*ip6h, *outer_ip6h;
	uint16_t	iph_hdr_length;
	uint8_t		*nexthdrp;
	sin6_t		sin6;
	mblk_t		*mp1;
	int		error = 0;
	icmp_t		*icmp = Q_TO_ICMP(q);

	outer_ip6h = (ip6_t *)mp->b_rptr;
	if (outer_ip6h->ip6_nxt != IPPROTO_ICMPV6)
		iph_hdr_length = ip_hdr_length_v6(mp, outer_ip6h);
	else
		iph_hdr_length = IPV6_HDR_LEN;

	icmp6 = (icmp6_t *)&mp->b_rptr[iph_hdr_length];
	ip6h = (ip6_t *)&icmp6[1];
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
		if (!icmp->icmp_ipv6_recvpathmtu)
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
		sin6->sin6_addr = icmp->icmp_v6dst;

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
		putnext(q, newmp);
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
	if (!icmp->icmp_dgram_errind) {
		freemsg(mp);
		return;
	}

	sin6 = sin6_null;
	sin6.sin6_family = AF_INET6;
	sin6.sin6_addr = ip6h->ip6_dst;
	sin6.sin6_flowinfo = ip6h->ip6_vcf & ~IPV6_VERS_AND_FLOW_MASK;

	mp1 = mi_tpi_uderror_ind((char *)&sin6, sizeof (sin6_t), NULL, 0,
	    error);
	if (mp1)
		putnext(q, mp1);
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
	icmp_t	*icmp = Q_TO_ICMP(q);
	mblk_t	*ackmp;
	struct T_addr_ack *taa;

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
	rw_enter(&icmp->icmp_rwlock, RW_READER);
	/*
	 * Note: Following code assumes 32 bit alignment of basic
	 * data structures like sin_t and struct T_addr_ack.
	 */
	if (icmp->icmp_state != TS_UNBND) {
		/*
		 * Fill in local address
		 */
		taa->LOCADDR_offset = sizeof (*taa);
		if (icmp->icmp_family == AF_INET) {
			sin_t	*sin;

			taa->LOCADDR_length = sizeof (sin_t);
			sin = (sin_t *)&taa[1];
			/* Fill zeroes and then intialize non-zero fields */
			*sin = sin_null;
			sin->sin_family = AF_INET;
			if (!IN6_IS_ADDR_V4MAPPED_ANY(&icmp->icmp_v6src) &&
			    !IN6_IS_ADDR_UNSPECIFIED(&icmp->icmp_v6src)) {
				IN6_V4MAPPED_TO_IPADDR(&icmp->icmp_v6src,
				    sin->sin_addr.s_addr);
			} else {
				/*
				 * INADDR_ANY
				 * icmp_v6src is not set, we might be bound to
				 * broadcast/multicast. Use icmp_bound_v6src as
				 * local address instead (that could
				 * also still be INADDR_ANY)
				 */
				IN6_V4MAPPED_TO_IPADDR(&icmp->icmp_bound_v6src,
				    sin->sin_addr.s_addr);
			}
			ackmp->b_wptr = (uchar_t *)&sin[1];
		} else {
			sin6_t	*sin6;

			ASSERT(icmp->icmp_family == AF_INET6);
			taa->LOCADDR_length = sizeof (sin6_t);
			sin6 = (sin6_t *)&taa[1];
			/* Fill zeroes and then intialize non-zero fields */
			*sin6 = sin6_null;
			sin6->sin6_family = AF_INET6;
			if (!IN6_IS_ADDR_UNSPECIFIED(&icmp->icmp_v6src)) {
				sin6->sin6_addr = icmp->icmp_v6src;
			} else {
				/*
				 * UNSPECIFIED
				 * icmp_v6src is not set, we might be bound to
				 * broadcast/multicast. Use icmp_bound_v6src as
				 * local address instead (that could
				 * also still be UNSPECIFIED)
				 */
				sin6->sin6_addr = icmp->icmp_bound_v6src;
			}
			ackmp->b_wptr = (uchar_t *)&sin6[1];
		}
	}
	rw_exit(&icmp->icmp_rwlock);
	ASSERT(ackmp->b_wptr <= ackmp->b_datap->db_lim);
	qreply(q, ackmp);
}

static void
icmp_copy_info(struct T_info_ack *tap, icmp_t *icmp)
{
	*tap = icmp_g_t_info_ack;

	if (icmp->icmp_family == AF_INET6)
		tap->ADDR_size = sizeof (sin6_t);
	else
		tap->ADDR_size = sizeof (sin_t);
	tap->CURRENT_state = icmp->icmp_state;
	tap->OPT_size = icmp_max_optsize;
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
	tcap->CAP_bits1 = 0;

	if (cap_bits1 & TC1_INFO) {
		icmp_copy_info(&tcap->INFO_ack, icmp);
		tcap->CAP_bits1 |= TC1_INFO;
	}

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

	mp = tpi_ack_alloc(mp, sizeof (struct T_info_ack), M_PCPROTO,
	    T_INFO_ACK);
	if (!mp)
		return;
	icmp_copy_info((struct T_info_ack *)mp->b_rptr, icmp);
	qreply(q, mp);
}

/*
 * IP recognizes seven kinds of bind requests:
 *
 * - A zero-length address binds only to the protocol number.
 *
 * - A 4-byte address is treated as a request to
 * validate that the address is a valid local IPv4
 * address, appropriate for an application to bind to.
 * IP does the verification, but does not make any note
 * of the address at this time.
 *
 * - A 16-byte address contains is treated as a request
 * to validate a local IPv6 address, as the 4-byte
 * address case above.
 *
 * - A 16-byte sockaddr_in to validate the local IPv4 address and also
 * use it for the inbound fanout of packets.
 *
 * - A 24-byte sockaddr_in6 to validate the local IPv6 address and also
 * use it for the inbound fanout of packets.
 *
 * - A 12-byte address (ipa_conn_t) containing complete IPv4 fanout
 * information consisting of local and remote addresses
 * and ports (unused for raw sockets).  In this case, the addresses are both
 * validated as appropriate for this operation, and, if
 * so, the information is retained for use in the
 * inbound fanout.
 *
 * - A 36-byte address address (ipa6_conn_t) containing complete IPv6
 * fanout information, like the 12-byte case above.
 *
 * IP will also fill in the IRE request mblk with information
 * regarding our peer.  In all cases, we notify IP of our protocol
 * type by appending a single protocol byte to the bind request.
 */
static mblk_t *
icmp_ip_bind_mp(icmp_t *icmp, t_scalar_t bind_prim, t_scalar_t addr_length,
    in_port_t fport)
{
	char	*cp;
	mblk_t	*mp;
	struct T_bind_req *tbr;
	ipa_conn_t	*ac;
	ipa6_conn_t	*ac6;
	sin_t		*sin;
	sin6_t		*sin6;

	ASSERT(bind_prim == O_T_BIND_REQ || bind_prim == T_BIND_REQ);
	ASSERT(RW_LOCK_HELD(&icmp->icmp_rwlock));
	mp = allocb(sizeof (*tbr) + addr_length + 1, BPRI_HI);
	if (mp == NULL)
		return (NULL);
	mp->b_datap->db_type = M_PROTO;
	tbr = (struct T_bind_req *)mp->b_rptr;
	tbr->PRIM_type = bind_prim;
	tbr->ADDR_offset = sizeof (*tbr);
	tbr->CONIND_number = 0;
	tbr->ADDR_length = addr_length;
	cp = (char *)&tbr[1];
	switch (addr_length) {
	case sizeof (ipa_conn_t):
		ASSERT(icmp->icmp_family == AF_INET);
		/* Append a request for an IRE */
		mp->b_cont = allocb(sizeof (ire_t), BPRI_HI);
		if (mp->b_cont == NULL) {
			freemsg(mp);
			return (NULL);
		}
		mp->b_cont->b_wptr += sizeof (ire_t);
		mp->b_cont->b_datap->db_type = IRE_DB_REQ_TYPE;

		/* cp known to be 32 bit aligned */
		ac = (ipa_conn_t *)cp;
		ac->ac_laddr = V4_PART_OF_V6(icmp->icmp_v6src);
		ac->ac_faddr = V4_PART_OF_V6(icmp->icmp_v6dst);
		ac->ac_fport = fport;
		ac->ac_lport = 0;
		break;

	case sizeof (ipa6_conn_t):
		ASSERT(icmp->icmp_family == AF_INET6);
		/* Append a request for an IRE */
		mp->b_cont = allocb(sizeof (ire_t), BPRI_HI);
		if (mp->b_cont == NULL) {
			freemsg(mp);
			return (NULL);
		}
		mp->b_cont->b_wptr += sizeof (ire_t);
		mp->b_cont->b_datap->db_type = IRE_DB_REQ_TYPE;

		/* cp known to be 32 bit aligned */
		ac6 = (ipa6_conn_t *)cp;
		ac6->ac6_laddr = icmp->icmp_v6src;
		ac6->ac6_faddr = icmp->icmp_v6dst;
		ac6->ac6_fport = fport;
		ac6->ac6_lport = 0;
		break;

	case sizeof (sin_t):
		ASSERT(icmp->icmp_family == AF_INET);
		/* Append a request for an IRE */
		mp->b_cont = allocb(sizeof (ire_t), BPRI_HI);
		if (!mp->b_cont) {
			freemsg(mp);
			return (NULL);
		}
		mp->b_cont->b_wptr += sizeof (ire_t);
		mp->b_cont->b_datap->db_type = IRE_DB_REQ_TYPE;

		sin = (sin_t *)cp;
		*sin = sin_null;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = V4_PART_OF_V6(icmp->icmp_bound_v6src);
		break;

	case sizeof (sin6_t):
		ASSERT(icmp->icmp_family == AF_INET6);
		/* Append a request for an IRE */
		mp->b_cont = allocb(sizeof (ire_t), BPRI_HI);
		if (!mp->b_cont) {
			freemsg(mp);
			return (NULL);
		}
		mp->b_cont->b_wptr += sizeof (ire_t);
		mp->b_cont->b_datap->db_type = IRE_DB_REQ_TYPE;

		sin6 = (sin6_t *)cp;
		*sin6 = sin6_null;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_addr = icmp->icmp_bound_v6src;
		break;
	}
	/* Add protocol number to end */
	cp[addr_length] = icmp->icmp_proto;
	mp->b_wptr = (uchar_t *)&cp[addr_length + 1];
	return (mp);
}

/* For /dev/icmp aka AF_INET open */
static int
icmp_openv4(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	return (icmp_open(q, devp, flag, sflag, credp, B_FALSE));
}

/* For /dev/icmp6 aka AF_INET6 open */
static int
icmp_openv6(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp)
{
	return (icmp_open(q, devp, flag, sflag, credp, B_TRUE));
}

/*
 * This is the open routine for icmp.  It allocates a icmp_t structure for
 * the stream and, on the first open of the module, creates an ND table.
 */
/*ARGSUSED2*/
static int
icmp_open(queue_t *q, dev_t *devp, int flag, int sflag, cred_t *credp,
    boolean_t isv6)
{
	int	err;
	icmp_t	*icmp;
	conn_t *connp;
	dev_t	conn_dev;
	zoneid_t zoneid;
	netstack_t *ns;
	icmp_stack_t *is;

	/* If the stream is already open, return immediately. */
	if (q->q_ptr != NULL)
		return (0);

	if (sflag == MODOPEN)
		return (EINVAL);

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

	if ((conn_dev = inet_minor_alloc(ip_minor_arena)) == 0) {
		netstack_rele(ns);
		return (EBUSY);
	}
	*devp = makedevice(getemajor(*devp), (minor_t)conn_dev);

	connp = ipcl_conn_create(IPCL_RAWIPCONN, KM_SLEEP, ns);
	connp->conn_dev = conn_dev;
	icmp = connp->conn_icmp;

	/*
	 * ipcl_conn_create did a netstack_hold. Undo the hold that was
	 * done by netstack_find_by_cred()
	 */
	netstack_rele(ns);

	/*
	 * Initialize the icmp_t structure for this stream.
	 */
	q->q_ptr = connp;
	WR(q)->q_ptr = connp;
	connp->conn_rq = q;
	connp->conn_wq = WR(q);

	rw_enter(&icmp->icmp_rwlock, RW_WRITER);
	ASSERT(connp->conn_ulp == IPPROTO_ICMP);
	ASSERT(connp->conn_icmp == icmp);
	ASSERT(icmp->icmp_connp == connp);

	/* Set the initial state of the stream and the privilege status. */
	icmp->icmp_state = TS_UNBND;
	if (isv6) {
		icmp->icmp_ipversion = IPV6_VERSION;
		icmp->icmp_family = AF_INET6;
		connp->conn_ulp = IPPROTO_ICMPV6;
		/* May be changed by a SO_PROTOTYPE socket option. */
		icmp->icmp_proto = IPPROTO_ICMPV6;
		icmp->icmp_checksum_off = 2;	/* Offset for icmp6_cksum */
		icmp->icmp_max_hdr_len = IPV6_HDR_LEN;
		icmp->icmp_ttl = (uint8_t)is->is_ipv6_hoplimit;
		connp->conn_af_isv6 = B_TRUE;
		connp->conn_flags |= IPCL_ISV6;
	} else {
		icmp->icmp_ipversion = IPV4_VERSION;
		icmp->icmp_family = AF_INET;
		/* May be changed by a SO_PROTOTYPE socket option. */
		icmp->icmp_proto = IPPROTO_ICMP;
		icmp->icmp_max_hdr_len = IP_SIMPLE_HDR_LENGTH;
		icmp->icmp_ttl = (uint8_t)is->is_ipv4_ttl;
		connp->conn_af_isv6 = B_FALSE;
		connp->conn_flags &= ~IPCL_ISV6;
	}
	icmp->icmp_multicast_ttl = IP_DEFAULT_MULTICAST_TTL;
	icmp->icmp_pending_op = -1;
	connp->conn_multicast_loop = IP_DEFAULT_MULTICAST_LOOP;
	connp->conn_zoneid = zoneid;

	/*
	 * If the caller has the process-wide flag set, then default to MAC
	 * exempt mode.  This allows read-down to unlabeled hosts.
	 */
	if (getpflags(NET_MAC_AWARE, credp) != 0)
		icmp->icmp_mac_exempt = B_TRUE;

	connp->conn_ulp_labeled = is_system_labeled();

	icmp->icmp_is = is;

	q->q_hiwat = is->is_recv_hiwat;
	WR(q)->q_hiwat = is->is_xmit_hiwat;
	WR(q)->q_lowat = is->is_xmit_lowat;

	connp->conn_recv = icmp_input;
	crhold(credp);
	connp->conn_cred = credp;

	mutex_enter(&connp->conn_lock);
	connp->conn_state_flags &= ~CONN_INCIPIENT;
	mutex_exit(&connp->conn_lock);

	qprocson(q);

	if (icmp->icmp_family == AF_INET6) {
		/* Build initial header template for transmit */
		if ((err = icmp_build_hdrs(icmp)) != 0) {
			rw_exit(&icmp->icmp_rwlock);
			qprocsoff(q);
			ipcl_conn_destroy(connp);
			return (err);
		}
	}
	rw_exit(&icmp->icmp_rwlock);

	/* Set the Stream head write offset. */
	(void) mi_set_sth_wroff(q,
	    icmp->icmp_max_hdr_len + is->is_wroff_extra);
	(void) mi_set_sth_hiwat(q, q->q_hiwat);

	return (0);
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
/* ARGSUSED */
int
icmp_opt_default(queue_t *q, int level, int name, uchar_t *ptr)
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
 * It returns the size of the option retrieved.
 */
int
icmp_opt_get_locked(queue_t *q, int level, int name, uchar_t *ptr)
{
	conn_t	*connp = Q_TO_CONN(q);
	icmp_t	*icmp = connp->conn_icmp;
	icmp_stack_t *is = icmp->icmp_is;
	int	*i1 = (int *)ptr;
	ip6_pkt_t	*ipp = &icmp->icmp_sticky_ipp;

	switch (level) {
	case SOL_SOCKET:
		switch (name) {
		case SO_DEBUG:
			*i1 = icmp->icmp_debug;
			break;
		case SO_TYPE:
			*i1 = SOCK_RAW;
			break;
		case SO_PROTOTYPE:
			*i1 = icmp->icmp_proto;
			break;
		case SO_REUSEADDR:
			*i1 = icmp->icmp_reuseaddr;
			break;

		/*
		 * The following three items are available here,
		 * but are only meaningful to IP.
		 */
		case SO_DONTROUTE:
			*i1 = icmp->icmp_dontroute;
			break;
		case SO_USELOOPBACK:
			*i1 = icmp->icmp_useloopback;
			break;
		case SO_BROADCAST:
			*i1 = icmp->icmp_broadcast;
			break;

		case SO_SNDBUF:
			ASSERT(q->q_hiwat <= INT_MAX);
			*i1 = (int)q->q_hiwat;
			break;
		case SO_RCVBUF:
			ASSERT(RD(q)->q_hiwat <= INT_MAX);
			*i1 = (int)RD(q)->q_hiwat;
			break;
		case SO_DGRAM_ERRIND:
			*i1 = icmp->icmp_dgram_errind;
			break;
		case SO_TIMESTAMP:
			*i1 = icmp->icmp_timestamp;
			break;
		case SO_MAC_EXEMPT:
			*i1 = icmp->icmp_mac_exempt;
			break;
		case SO_DOMAIN:
			*i1 = icmp->icmp_family;
			break;

		/*
		 * Following four not meaningful for icmp
		 * Action is same as "default" to which we fallthrough
		 * so we keep them in comments.
		 * case SO_LINGER:
		 * case SO_KEEPALIVE:
		 * case SO_OOBINLINE:
		 * case SO_ALLZONES:
		 */
		default:
			return (-1);
		}
		break;
	case IPPROTO_IP:
		/*
		 * Only allow IPv4 option processing on IPv4 sockets.
		 */
		if (icmp->icmp_family != AF_INET)
			return (-1);

		switch (name) {
		case IP_OPTIONS:
		case T_IP_OPTIONS:
			/* Options are passed up with each packet */
			return (0);
		case IP_HDRINCL:
			*i1 = (int)icmp->icmp_hdrincl;
			break;
		case IP_TOS:
		case T_IP_TOS:
			*i1 = (int)icmp->icmp_type_of_service;
			break;
		case IP_TTL:
			*i1 = (int)icmp->icmp_ttl;
			break;
		case IP_MULTICAST_IF:
			/* 0 address if not set */
			*(ipaddr_t *)ptr = icmp->icmp_multicast_if_addr;
			return (sizeof (ipaddr_t));
		case IP_MULTICAST_TTL:
			*(uchar_t *)ptr = icmp->icmp_multicast_ttl;
			return (sizeof (uchar_t));
		case IP_MULTICAST_LOOP:
			*ptr = connp->conn_multicast_loop;
			return (sizeof (uint8_t));
		case IP_BOUND_IF:
			/* Zero if not set */
			*i1 = icmp->icmp_bound_if;
			break;	/* goto sizeof (int) option return */
		case IP_UNSPEC_SRC:
			*ptr = icmp->icmp_unspec_source;
			break;	/* goto sizeof (int) option return */
		case IP_XMIT_IF:
			*i1 = icmp->icmp_xmit_if;
			break;	/* goto sizeof (int) option return */
		case IP_RECVIF:
			*ptr = icmp->icmp_recvif;
			break;	/* goto sizeof (int) option return */
		case IP_RECVPKTINFO:
			/*
			 * This also handles IP_PKTINFO.
			 * IP_PKTINFO and IP_RECVPKTINFO have the same value.
			 * Differentiation is based on the size of the argument
			 * passed in.
			 * This option is handled in IP which will return an
			 * error for IP_PKTINFO as it's not supported as a
			 * sticky option.
			 */
			return (-EINVAL);
		/*
		 * Cannot "get" the value of following options
		 * at this level. Action is same as "default" to
		 * which we fallthrough so we keep them in comments.
		 *
		 * case IP_ADD_MEMBERSHIP:
		 * case IP_DROP_MEMBERSHIP:
		 * case IP_BLOCK_SOURCE:
		 * case IP_UNBLOCK_SOURCE:
		 * case IP_ADD_SOURCE_MEMBERSHIP:
		 * case IP_DROP_SOURCE_MEMBERSHIP:
		 * case MCAST_JOIN_GROUP:
		 * case MCAST_LEAVE_GROUP:
		 * case MCAST_BLOCK_SOURCE:
		 * case MCAST_UNBLOCK_SOURCE:
		 * case MCAST_JOIN_SOURCE_GROUP:
		 * case MCAST_LEAVE_SOURCE_GROUP:
		 * case MRT_INIT:
		 * case MRT_DONE:
		 * case MRT_ADD_VIF:
		 * case MRT_DEL_VIF:
		 * case MRT_ADD_MFC:
		 * case MRT_DEL_MFC:
		 * case MRT_VERSION:
		 * case MRT_ASSERT:
		 * case IP_SEC_OPT:
		 * case IP_DONTFAILOVER_IF:
		 * case IP_NEXTHOP:
		 */
		default:
			return (-1);
		}
		break;
	case IPPROTO_IPV6:
		/*
		 * Only allow IPv6 option processing on native IPv6 sockets.
		 */
		if (icmp->icmp_family != AF_INET6)
			return (-1);
		switch (name) {
		case IPV6_UNICAST_HOPS:
			*i1 = (unsigned int)icmp->icmp_ttl;
			break;
		case IPV6_MULTICAST_IF:
			/* 0 index if not set */
			*i1 = icmp->icmp_multicast_if_index;
			break;
		case IPV6_MULTICAST_HOPS:
			*i1 = icmp->icmp_multicast_ttl;
			break;
		case IPV6_MULTICAST_LOOP:
			*i1 = connp->conn_multicast_loop;
			break;
		case IPV6_BOUND_IF:
			/* Zero if not set */
			*i1 = icmp->icmp_bound_if;
			break;
		case IPV6_UNSPEC_SRC:
			*i1 = icmp->icmp_unspec_source;
			break;
		case IPV6_CHECKSUM:
			/*
			 * Return offset or -1 if no checksum offset.
			 * Does not apply to IPPROTO_ICMPV6
			 */
			if (icmp->icmp_proto == IPPROTO_ICMPV6)
				return (-1);

			if (icmp->icmp_raw_checksum) {
				*i1 = icmp->icmp_checksum_off;
			} else {
				*i1 = -1;
			}
			break;
		case IPV6_JOIN_GROUP:
		case IPV6_LEAVE_GROUP:
		case MCAST_JOIN_GROUP:
		case MCAST_LEAVE_GROUP:
		case MCAST_BLOCK_SOURCE:
		case MCAST_UNBLOCK_SOURCE:
		case MCAST_JOIN_SOURCE_GROUP:
		case MCAST_LEAVE_SOURCE_GROUP:
			/* cannot "get" the value for these */
			return (-1);
		case IPV6_RECVPKTINFO:
			*i1 = icmp->icmp_ip_recvpktinfo;
			break;
		case IPV6_RECVTCLASS:
			*i1 = icmp->icmp_ipv6_recvtclass;
			break;
		case IPV6_RECVPATHMTU:
			*i1 = icmp->icmp_ipv6_recvpathmtu;
			break;
		case IPV6_V6ONLY:
			*i1 = 1;
			break;
		case IPV6_RECVHOPLIMIT:
			*i1 = icmp->icmp_ipv6_recvhoplimit;
			break;
		case IPV6_RECVHOPOPTS:
			*i1 = icmp->icmp_ipv6_recvhopopts;
			break;
		case IPV6_RECVDSTOPTS:
			*i1 = icmp->icmp_ipv6_recvdstopts;
			break;
		case _OLD_IPV6_RECVDSTOPTS:
			*i1 = icmp->icmp_old_ipv6_recvdstopts;
			break;
		case IPV6_RECVRTHDRDSTOPTS:
			*i1 = icmp->icmp_ipv6_recvrtdstopts;
			break;
		case IPV6_RECVRTHDR:
			*i1 = icmp->icmp_ipv6_recvrthdr;
			break;
		case IPV6_PKTINFO: {
			/* XXX assumes that caller has room for max size! */
			struct in6_pktinfo *pkti;

			pkti = (struct in6_pktinfo *)ptr;
			if (ipp->ipp_fields & IPPF_IFINDEX)
				pkti->ipi6_ifindex = ipp->ipp_ifindex;
			else
				pkti->ipi6_ifindex = 0;
			if (ipp->ipp_fields & IPPF_ADDR)
				pkti->ipi6_addr = ipp->ipp_addr;
			else
				pkti->ipi6_addr = ipv6_all_zeros;
			return (sizeof (struct in6_pktinfo));
		}
		case IPV6_NEXTHOP: {
			sin6_t *sin6 = (sin6_t *)ptr;

			if (!(ipp->ipp_fields & IPPF_NEXTHOP))
				return (0);
			*sin6 = sin6_null;
			sin6->sin6_family = AF_INET6;
			sin6->sin6_addr = ipp->ipp_nexthop;
			return (sizeof (sin6_t));
		}
		case IPV6_HOPOPTS:
			if (!(ipp->ipp_fields & IPPF_HOPOPTS))
				return (0);
			if (ipp->ipp_hopoptslen <= icmp->icmp_label_len_v6)
				return (0);
			bcopy((char *)ipp->ipp_hopopts +
			    icmp->icmp_label_len_v6, ptr,
			    ipp->ipp_hopoptslen - icmp->icmp_label_len_v6);
			if (icmp->icmp_label_len_v6 > 0) {
				ptr[0] = ((char *)ipp->ipp_hopopts)[0];
				ptr[1] = (ipp->ipp_hopoptslen -
				    icmp->icmp_label_len_v6 + 7) / 8 - 1;
			}
			return (ipp->ipp_hopoptslen - icmp->icmp_label_len_v6);
		case IPV6_RTHDRDSTOPTS:
			if (!(ipp->ipp_fields & IPPF_RTDSTOPTS))
				return (0);
			bcopy(ipp->ipp_rtdstopts, ptr, ipp->ipp_rtdstoptslen);
			return (ipp->ipp_rtdstoptslen);
		case IPV6_RTHDR:
			if (!(ipp->ipp_fields & IPPF_RTHDR))
				return (0);
			bcopy(ipp->ipp_rthdr, ptr, ipp->ipp_rthdrlen);
			return (ipp->ipp_rthdrlen);
		case IPV6_DSTOPTS:
			if (!(ipp->ipp_fields & IPPF_DSTOPTS))
				return (0);
			bcopy(ipp->ipp_dstopts, ptr, ipp->ipp_dstoptslen);
			return (ipp->ipp_dstoptslen);
		case IPV6_PATHMTU:
			if (!(ipp->ipp_fields & IPPF_PATHMTU))
				return (0);

			return (ip_fill_mtuinfo(&icmp->icmp_v6dst, 0,
			    (struct ip6_mtuinfo *)ptr,
			    is->is_netstack));
		case IPV6_TCLASS:
			if (ipp->ipp_fields & IPPF_TCLASS)
				*i1 = ipp->ipp_tclass;
			else
				*i1 = IPV6_FLOW_TCLASS(
				    IPV6_DEFAULT_VERS_AND_FLOW);
			break;
		default:
			return (-1);
		}
		break;
	case IPPROTO_ICMPV6:
		/*
		 * Only allow IPv6 option processing on native IPv6 sockets.
		 */
		if (icmp->icmp_family != AF_INET6)
			return (-1);

		if (icmp->icmp_proto != IPPROTO_ICMPV6)
			return (-1);

		switch (name) {
		case ICMP6_FILTER:
			if (icmp->icmp_filter == NULL) {
				/* Make it look like "pass all" */
				ICMP6_FILTER_SETPASSALL((icmp6_filter_t *)ptr);
			} else {
				(void) bcopy(icmp->icmp_filter, ptr,
				    sizeof (icmp6_filter_t));
			}
			return (sizeof (icmp6_filter_t));
		default:
			return (-1);
		}
	default:
		return (-1);
	}
	return (sizeof (int));
}

/*
 * This routine retrieves the current status of socket options.
 * It returns the size of the option retrieved.
 */
int
icmp_opt_get(queue_t *q, int level, int name, uchar_t *ptr)
{
	icmp_t  *icmp = Q_TO_ICMP(q);
	int 	err;

	rw_enter(&icmp->icmp_rwlock, RW_READER);
	err = icmp_opt_get_locked(q, level, name, ptr);
	rw_exit(&icmp->icmp_rwlock);
	return (err);
}


/* This routine sets socket options. */
/* ARGSUSED */
int
icmp_opt_set_locked(queue_t *q, uint_t optset_context, int level, int name,
    uint_t inlen, uchar_t *invalp, uint_t *outlenp, uchar_t *outvalp,
    void *thisdg_attrs, cred_t *cr, mblk_t *mblk)
{
	conn_t	*connp = Q_TO_CONN(q);
	icmp_t	*icmp = connp->conn_icmp;
	icmp_stack_t *is = icmp->icmp_is;
	int	*i1 = (int *)invalp;
	boolean_t onoff = (*i1 == 0) ? 0 : 1;
	boolean_t checkonly;
	int	error;

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

	/*
	 * For fixed length options, no sanity check
	 * of passed in length is done. It is assumed *_optcom_req()
	 * routines do the right thing.
	 */

	switch (level) {
	case SOL_SOCKET:
		switch (name) {
		case SO_DEBUG:
			if (!checkonly)
				icmp->icmp_debug = onoff;
			break;
		case SO_PROTOTYPE:
			if ((*i1 & 0xFF) != IPPROTO_ICMP &&
			    (*i1 & 0xFF) != IPPROTO_ICMPV6 &&
			    secpolicy_net_rawaccess(cr) != 0) {
				*outlenp = 0;
				return (EACCES);
			}
			/* Can't use IPPROTO_RAW with IPv6 */
			if ((*i1 & 0xFF) == IPPROTO_RAW &&
			    icmp->icmp_family == AF_INET6) {
				*outlenp = 0;
				return (EPROTONOSUPPORT);
			}
			if (checkonly) {
				/* T_CHECK case */
				*(int *)outvalp = (*i1 & 0xFF);
				break;
			}
			icmp->icmp_proto = *i1 & 0xFF;
			if ((icmp->icmp_proto == IPPROTO_RAW ||
			    icmp->icmp_proto == IPPROTO_IGMP) &&
			    icmp->icmp_family == AF_INET)
				icmp->icmp_hdrincl = 1;
			else
				icmp->icmp_hdrincl = 0;

			if (icmp->icmp_family == AF_INET6 &&
			    icmp->icmp_proto == IPPROTO_ICMPV6) {
				/* Set offset for icmp6_cksum */
				icmp->icmp_raw_checksum = 0;
				icmp->icmp_checksum_off = 2;
			}
			if (icmp->icmp_proto == IPPROTO_UDP ||
			    icmp->icmp_proto == IPPROTO_TCP ||
			    icmp->icmp_proto == IPPROTO_SCTP) {
				icmp->icmp_no_tp_cksum = 1;
				icmp->icmp_sticky_ipp.ipp_fields |=
				    IPPF_NO_CKSUM;
			} else {
				icmp->icmp_no_tp_cksum = 0;
				icmp->icmp_sticky_ipp.ipp_fields &=
				    ~IPPF_NO_CKSUM;
			}

			if (icmp->icmp_filter != NULL &&
			    icmp->icmp_proto != IPPROTO_ICMPV6) {
				kmem_free(icmp->icmp_filter,
				    sizeof (icmp6_filter_t));
				icmp->icmp_filter = NULL;
			}

			/* Rebuild the header template */
			error = icmp_build_hdrs(icmp);
			if (error != 0) {
				*outlenp = 0;
				return (error);
			}

			/*
			 * For SCTP, we don't use icmp_bind_proto() for
			 * raw socket binding.  Note that we do not need
			 * to set *outlenp.
			 * FIXME: how does SCTP work?
			 */
			if (icmp->icmp_proto == IPPROTO_SCTP)
				return (0);

			*outlenp = sizeof (int);
			*(int *)outvalp = *i1 & 0xFF;

			/* Drop lock across the bind operation */
			rw_exit(&icmp->icmp_rwlock);
			icmp_bind_proto(q);
			rw_enter(&icmp->icmp_rwlock, RW_WRITER);
			return (0);
		case SO_REUSEADDR:
			if (!checkonly)
				icmp->icmp_reuseaddr = onoff;
			break;

		/*
		 * The following three items are available here,
		 * but are only meaningful to IP.
		 */
		case SO_DONTROUTE:
			if (!checkonly)
				icmp->icmp_dontroute = onoff;
			break;
		case SO_USELOOPBACK:
			if (!checkonly)
				icmp->icmp_useloopback = onoff;
			break;
		case SO_BROADCAST:
			if (!checkonly)
				icmp->icmp_broadcast = onoff;
			break;

		case SO_SNDBUF:
			if (*i1 > is->is_max_buf) {
				*outlenp = 0;
				return (ENOBUFS);
			}
			if (!checkonly) {
				q->q_hiwat = *i1;
			}
			break;
		case SO_RCVBUF:
			if (*i1 > is->is_max_buf) {
				*outlenp = 0;
				return (ENOBUFS);
			}
			if (!checkonly) {
				RD(q)->q_hiwat = *i1;
				rw_exit(&icmp->icmp_rwlock);
				(void) mi_set_sth_hiwat(RD(q), *i1);
				rw_enter(&icmp->icmp_rwlock, RW_WRITER);
			}
			break;
		case SO_DGRAM_ERRIND:
			if (!checkonly)
				icmp->icmp_dgram_errind = onoff;
			break;
		case SO_ALLZONES:
			/*
			 * "soft" error (negative)
			 * option not handled at this level
			 * Note: Do not modify *outlenp
			 */
			return (-EINVAL);
		case SO_TIMESTAMP:
			if (!checkonly) {
				icmp->icmp_timestamp = onoff;
			}
			break;
		case SO_MAC_EXEMPT:
			if (secpolicy_net_mac_aware(cr) != 0 ||
			    icmp->icmp_state != TS_UNBND)
				return (EACCES);
			if (!checkonly)
				icmp->icmp_mac_exempt = onoff;
			break;
		/*
		 * Following three not meaningful for icmp
		 * Action is same as "default" so we keep them
		 * in comments.
		 * case SO_LINGER:
		 * case SO_KEEPALIVE:
		 * case SO_OOBINLINE:
		 */
		default:
			*outlenp = 0;
			return (EINVAL);
		}
		break;
	case IPPROTO_IP:
		/*
		 * Only allow IPv4 option processing on IPv4 sockets.
		 */
		if (icmp->icmp_family != AF_INET) {
			*outlenp = 0;
			return (ENOPROTOOPT);
		}
		switch (name) {
		case IP_OPTIONS:
		case T_IP_OPTIONS:
			/* Save options for use by IP. */
			if ((inlen & 0x3) ||
			    inlen + icmp->icmp_label_len > IP_MAX_OPT_LENGTH) {
				*outlenp = 0;
				return (EINVAL);
			}
			if (checkonly)
				break;

			if (!tsol_option_set(&icmp->icmp_ip_snd_options,
			    &icmp->icmp_ip_snd_options_len,
			    icmp->icmp_label_len, invalp, inlen)) {
				*outlenp = 0;
				return (ENOMEM);
			}

			icmp->icmp_max_hdr_len = IP_SIMPLE_HDR_LENGTH +
			    icmp->icmp_ip_snd_options_len;
			rw_exit(&icmp->icmp_rwlock);
			(void) mi_set_sth_wroff(RD(q), icmp->icmp_max_hdr_len +
			    is->is_wroff_extra);
			rw_enter(&icmp->icmp_rwlock, RW_WRITER);
			break;
		case IP_HDRINCL:
			if (!checkonly)
				icmp->icmp_hdrincl = onoff;
			break;
		case IP_TOS:
		case T_IP_TOS:
			if (!checkonly) {
				icmp->icmp_type_of_service = (uint8_t)*i1;
			}
			break;
		case IP_TTL:
			if (!checkonly) {
				icmp->icmp_ttl = (uint8_t)*i1;
			}
			break;
		case IP_MULTICAST_IF:
			/*
			 * TODO should check OPTMGMT reply and undo this if
			 * there is an error.
			 */
			if (!checkonly)
				icmp->icmp_multicast_if_addr = *i1;
			break;
		case IP_MULTICAST_TTL:
			if (!checkonly)
				icmp->icmp_multicast_ttl = *invalp;
			break;
		case IP_MULTICAST_LOOP:
			if (!checkonly) {
				connp->conn_multicast_loop =
				    (*invalp == 0) ? 0 : 1;
			}
			break;
		case IP_BOUND_IF:
			if (!checkonly)
				icmp->icmp_bound_if = *i1;
			break;
		case IP_UNSPEC_SRC:
			if (!checkonly)
				icmp->icmp_unspec_source = onoff;
			break;
		case IP_XMIT_IF:
			if (!checkonly)
				icmp->icmp_xmit_if = *i1;
			break;
		case IP_RECVIF:
			if (!checkonly)
				icmp->icmp_recvif = onoff;
			/*
			 * pass to ip
			 */
			return (-EINVAL);
		case IP_PKTINFO: {
			/*
			 * This also handles IP_RECVPKTINFO.
			 * IP_PKTINFO and IP_RECVPKTINFO have the same value.
			 * Differentiation is based on the size of the argument
			 * passed in.
			 */
			struct in_pktinfo *pktinfop;
			ip4_pkt_t *attr_pktinfop;

			if (checkonly)
				break;

			if (inlen == sizeof (int)) {
				/*
				 * This is IP_RECVPKTINFO option.
				 * Keep a local copy of wether this option is
				 * set or not and pass it down to IP for
				 * processing.
				 */
				icmp->icmp_ip_recvpktinfo = onoff;
				return (-EINVAL);
			}


			if (inlen != sizeof (struct in_pktinfo))
				return (EINVAL);

			if ((attr_pktinfop = (ip4_pkt_t *)thisdg_attrs)
			    == NULL) {
				/*
				 * sticky option is not supported
				 */
				return (EINVAL);
			}

			pktinfop = (struct in_pktinfo *)invalp;

			/*
			 * Atleast one of the values should be specified
			 */
			if (pktinfop->ipi_ifindex == 0 &&
			    pktinfop->ipi_spec_dst.s_addr == INADDR_ANY) {
				return (EINVAL);
			}

			attr_pktinfop->ip4_addr = pktinfop->ipi_spec_dst.s_addr;
			attr_pktinfop->ip4_ill_index = pktinfop->ipi_ifindex;
		}
			break;
		case IP_ADD_MEMBERSHIP:
		case IP_DROP_MEMBERSHIP:
		case IP_BLOCK_SOURCE:
		case IP_UNBLOCK_SOURCE:
		case IP_ADD_SOURCE_MEMBERSHIP:
		case IP_DROP_SOURCE_MEMBERSHIP:
		case MCAST_JOIN_GROUP:
		case MCAST_LEAVE_GROUP:
		case MCAST_BLOCK_SOURCE:
		case MCAST_UNBLOCK_SOURCE:
		case MCAST_JOIN_SOURCE_GROUP:
		case MCAST_LEAVE_SOURCE_GROUP:
		case MRT_INIT:
		case MRT_DONE:
		case MRT_ADD_VIF:
		case MRT_DEL_VIF:
		case MRT_ADD_MFC:
		case MRT_DEL_MFC:
		case MRT_VERSION:
		case MRT_ASSERT:
		case IP_SEC_OPT:
		case IP_DONTFAILOVER_IF:
		case IP_NEXTHOP:
			/*
			 * "soft" error (negative)
			 * option not handled at this level
			 * Note: Do not modify *outlenp
			 */
			return (-EINVAL);
		default:
			*outlenp = 0;
			return (EINVAL);
		}
		break;
	case IPPROTO_IPV6: {
		ip6_pkt_t		*ipp;
		boolean_t		sticky;

		if (icmp->icmp_family != AF_INET6) {
			*outlenp = 0;
			return (ENOPROTOOPT);
		}
		/*
		 * Deal with both sticky options and ancillary data
		 */
		if (thisdg_attrs == NULL) {
			/* sticky options, or none */
			ipp = &icmp->icmp_sticky_ipp;
			sticky = B_TRUE;
		} else {
			/* ancillary data */
			ipp = (ip6_pkt_t *)thisdg_attrs;
			sticky = B_FALSE;
		}

		switch (name) {
		case IPV6_MULTICAST_IF:
			if (!checkonly)
				icmp->icmp_multicast_if_index = *i1;
			break;
		case IPV6_UNICAST_HOPS:
			/* -1 means use default */
			if (*i1 < -1 || *i1 > IPV6_MAX_HOPS) {
				*outlenp = 0;
				return (EINVAL);
			}
			if (!checkonly) {
				if (*i1 == -1) {
					icmp->icmp_ttl = ipp->ipp_unicast_hops =
					    is->is_ipv6_hoplimit;
					ipp->ipp_fields &= ~IPPF_UNICAST_HOPS;
					/* Pass modified value to IP. */
					*i1 = ipp->ipp_hoplimit;
				} else {
					icmp->icmp_ttl = ipp->ipp_unicast_hops =
					    (uint8_t)*i1;
					ipp->ipp_fields |= IPPF_UNICAST_HOPS;
				}
				/* Rebuild the header template */
				error = icmp_build_hdrs(icmp);
				if (error != 0) {
					*outlenp = 0;
					return (error);
				}
			}
			break;
		case IPV6_MULTICAST_HOPS:
			/* -1 means use default */
			if (*i1 < -1 || *i1 > IPV6_MAX_HOPS) {
				*outlenp = 0;
				return (EINVAL);
			}
			if (!checkonly) {
				if (*i1 == -1) {
					icmp->icmp_multicast_ttl =
					    ipp->ipp_multicast_hops =
					    IP_DEFAULT_MULTICAST_TTL;
					ipp->ipp_fields &= ~IPPF_MULTICAST_HOPS;
					/* Pass modified value to IP. */
					*i1 = icmp->icmp_multicast_ttl;
				} else {
					icmp->icmp_multicast_ttl =
					    ipp->ipp_multicast_hops =
					    (uint8_t)*i1;
					ipp->ipp_fields |= IPPF_MULTICAST_HOPS;
				}
			}
			break;
		case IPV6_MULTICAST_LOOP:
			if (*i1 != 0 && *i1 != 1) {
				*outlenp = 0;
				return (EINVAL);
			}
			if (!checkonly)
				connp->conn_multicast_loop = *i1;
			break;
		case IPV6_CHECKSUM:
			/*
			 * Integer offset into the user data of where the
			 * checksum is located.
			 * Offset of -1 disables option.
			 * Does not apply to IPPROTO_ICMPV6.
			 */
			if (icmp->icmp_proto == IPPROTO_ICMPV6 || !sticky) {
				*outlenp = 0;
				return (EINVAL);
			}
			if ((*i1 != -1) && ((*i1 < 0) || (*i1 & 0x1) != 0)) {
				/* Negative or not 16 bit aligned offset */
				*outlenp = 0;
				return (EINVAL);
			}
			if (checkonly)
				break;

			if (*i1 == -1) {
				icmp->icmp_raw_checksum = 0;
				ipp->ipp_fields &= ~IPPF_RAW_CKSUM;
			} else {
				icmp->icmp_raw_checksum = 1;
				icmp->icmp_checksum_off = *i1;
				ipp->ipp_fields |= IPPF_RAW_CKSUM;
			}
			/* Rebuild the header template */
			error = icmp_build_hdrs(icmp);
			if (error != 0) {
				*outlenp = 0;
				return (error);
			}
			break;
		case IPV6_JOIN_GROUP:
		case IPV6_LEAVE_GROUP:
		case MCAST_JOIN_GROUP:
		case MCAST_LEAVE_GROUP:
		case MCAST_BLOCK_SOURCE:
		case MCAST_UNBLOCK_SOURCE:
		case MCAST_JOIN_SOURCE_GROUP:
		case MCAST_LEAVE_SOURCE_GROUP:
			/*
			 * "soft" error (negative)
			 * option not handled at this level
			 * Note: Do not modify *outlenp
			 */
			return (-EINVAL);
		case IPV6_BOUND_IF:
			if (!checkonly)
				icmp->icmp_bound_if = *i1;
			break;
		case IPV6_UNSPEC_SRC:
			if (!checkonly)
				icmp->icmp_unspec_source = onoff;
			break;
		case IPV6_RECVTCLASS:
			if (!checkonly)
				icmp->icmp_ipv6_recvtclass = onoff;
			break;
		/*
		 * Set boolean switches for ancillary data delivery
		 */
		case IPV6_RECVPKTINFO:
			if (!checkonly)
				icmp->icmp_ip_recvpktinfo = onoff;
			break;
		case IPV6_RECVPATHMTU:
			if (!checkonly)
				icmp->icmp_ipv6_recvpathmtu = onoff;
			break;
		case IPV6_RECVHOPLIMIT:
			if (!checkonly)
				icmp->icmp_ipv6_recvhoplimit = onoff;
			break;
		case IPV6_RECVHOPOPTS:
			if (!checkonly)
				icmp->icmp_ipv6_recvhopopts = onoff;
			break;
		case IPV6_RECVDSTOPTS:
			if (!checkonly)
				icmp->icmp_ipv6_recvdstopts = onoff;
			break;
		case _OLD_IPV6_RECVDSTOPTS:
			if (!checkonly)
				icmp->icmp_old_ipv6_recvdstopts = onoff;
			break;
		case IPV6_RECVRTHDRDSTOPTS:
			if (!checkonly)
				icmp->icmp_ipv6_recvrtdstopts = onoff;
			break;
		case IPV6_RECVRTHDR:
			if (!checkonly)
				icmp->icmp_ipv6_recvrthdr = onoff;
			break;
		/*
		 * Set sticky options or ancillary data.
		 * If sticky options, (re)build any extension headers
		 * that might be needed as a result.
		 */
		case IPV6_PKTINFO:
			/*
			 * The source address and ifindex are verified
			 * in ip_opt_set(). For ancillary data the
			 * source address is checked in ip_wput_v6.
			 */
			if (inlen != 0 && inlen != sizeof (struct in6_pktinfo))
				return (EINVAL);
			if (checkonly)
				break;

			if (inlen == 0) {
				ipp->ipp_fields &= ~(IPPF_IFINDEX|IPPF_ADDR);
				ipp->ipp_sticky_ignored |=
				    (IPPF_IFINDEX|IPPF_ADDR);
			} else {
				struct in6_pktinfo *pkti;

				pkti = (struct in6_pktinfo *)invalp;
				ipp->ipp_ifindex = pkti->ipi6_ifindex;
				ipp->ipp_addr = pkti->ipi6_addr;
				if (ipp->ipp_ifindex != 0)
					ipp->ipp_fields |= IPPF_IFINDEX;
				else
					ipp->ipp_fields &= ~IPPF_IFINDEX;
				if (!IN6_IS_ADDR_UNSPECIFIED(
				    &ipp->ipp_addr))
					ipp->ipp_fields |= IPPF_ADDR;
				else
					ipp->ipp_fields &= ~IPPF_ADDR;
			}
			if (sticky) {
				error = icmp_build_hdrs(icmp);
				if (error != 0)
					return (error);
			}
			break;
		case IPV6_HOPLIMIT:
			/* This option can only be used as ancillary data. */
			if (sticky)
				return (EINVAL);
			if (inlen != 0 && inlen != sizeof (int))
				return (EINVAL);
			if (checkonly)
				break;

			if (inlen == 0) {
				ipp->ipp_fields &= ~IPPF_HOPLIMIT;
				ipp->ipp_sticky_ignored |= IPPF_HOPLIMIT;
			} else {
				if (*i1 > 255 || *i1 < -1)
					return (EINVAL);
				if (*i1 == -1)
					ipp->ipp_hoplimit =
					    is->is_ipv6_hoplimit;
				else
					ipp->ipp_hoplimit = *i1;
				ipp->ipp_fields |= IPPF_HOPLIMIT;
			}
			break;
		case IPV6_TCLASS:
			/*
			 * IPV6_RECVTCLASS accepts -1 as use kernel default
			 * and [0, 255] as the actualy traffic class.
			 */
			if (inlen != 0 && inlen != sizeof (int))
				return (EINVAL);
			if (checkonly)
				break;

			if (inlen == 0) {
				ipp->ipp_fields &= ~IPPF_TCLASS;
				ipp->ipp_sticky_ignored |= IPPF_TCLASS;
			} else {
				if (*i1 >= 256 || *i1 < -1)
					return (EINVAL);
				if (*i1 == -1) {
					ipp->ipp_tclass =
					    IPV6_FLOW_TCLASS(
					    IPV6_DEFAULT_VERS_AND_FLOW);
				} else {
					ipp->ipp_tclass = *i1;
				}
				ipp->ipp_fields |= IPPF_TCLASS;
			}
			if (sticky) {
				error = icmp_build_hdrs(icmp);
				if (error != 0)
					return (error);
			}
			break;
		case IPV6_NEXTHOP:
			/*
			 * IP will verify that the nexthop is reachable
			 * and fail for sticky options.
			 */
			if (inlen != 0 && inlen != sizeof (sin6_t))
				return (EINVAL);
			if (checkonly)
				break;

			if (inlen == 0) {
				ipp->ipp_fields &= ~IPPF_NEXTHOP;
				ipp->ipp_sticky_ignored |= IPPF_NEXTHOP;
			} else {
				sin6_t *sin6 = (sin6_t *)invalp;

				if (sin6->sin6_family != AF_INET6)
					return (EAFNOSUPPORT);
				if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr))
					return (EADDRNOTAVAIL);
				ipp->ipp_nexthop = sin6->sin6_addr;
				if (!IN6_IS_ADDR_UNSPECIFIED(
				    &ipp->ipp_nexthop))
					ipp->ipp_fields |= IPPF_NEXTHOP;
				else
					ipp->ipp_fields &= ~IPPF_NEXTHOP;
			}
			if (sticky) {
				error = icmp_build_hdrs(icmp);
				if (error != 0)
					return (error);
			}
			break;
		case IPV6_HOPOPTS: {
			ip6_hbh_t *hopts = (ip6_hbh_t *)invalp;
			/*
			 * Sanity checks - minimum size, size a multiple of
			 * eight bytes, and matching size passed in.
			 */
			if (inlen != 0 &&
			    inlen != (8 * (hopts->ip6h_len + 1)))
				return (EINVAL);

			if (checkonly)
				break;
			error = optcom_pkt_set(invalp, inlen, sticky,
			    (uchar_t **)&ipp->ipp_hopopts,
			    &ipp->ipp_hopoptslen,
			    sticky ? icmp->icmp_label_len_v6 : 0);
			if (error != 0)
				return (error);
			if (ipp->ipp_hopoptslen == 0) {
				ipp->ipp_fields &= ~IPPF_HOPOPTS;
				ipp->ipp_sticky_ignored |= IPPF_HOPOPTS;
			} else {
				ipp->ipp_fields |= IPPF_HOPOPTS;
			}
			if (sticky) {
				error = icmp_build_hdrs(icmp);
				if (error != 0)
					return (error);
			}
			break;
		}
		case IPV6_RTHDRDSTOPTS: {
			ip6_dest_t *dopts = (ip6_dest_t *)invalp;

			/*
			 * Sanity checks - minimum size, size a multiple of
			 * eight bytes, and matching size passed in.
			 */
			if (inlen != 0 &&
			    inlen != (8 * (dopts->ip6d_len + 1)))
				return (EINVAL);

			if (checkonly)
				break;

			if (inlen == 0) {
				if (sticky &&
				    (ipp->ipp_fields & IPPF_RTDSTOPTS) != 0) {
					kmem_free(ipp->ipp_rtdstopts,
					    ipp->ipp_rtdstoptslen);
					ipp->ipp_rtdstopts = NULL;
					ipp->ipp_rtdstoptslen = 0;
				}
				ipp->ipp_fields &= ~IPPF_RTDSTOPTS;
				ipp->ipp_sticky_ignored |= IPPF_RTDSTOPTS;
			} else {
				error = optcom_pkt_set(invalp, inlen, sticky,
				    (uchar_t **)&ipp->ipp_rtdstopts,
				    &ipp->ipp_rtdstoptslen, 0);
				if (error != 0)
					return (error);
				ipp->ipp_fields |= IPPF_RTDSTOPTS;
			}
			if (sticky) {
				error = icmp_build_hdrs(icmp);
				if (error != 0)
					return (error);
			}
			break;
		}
		case IPV6_DSTOPTS: {
			ip6_dest_t *dopts = (ip6_dest_t *)invalp;

			/*
			 * Sanity checks - minimum size, size a multiple of
			 * eight bytes, and matching size passed in.
			 */
			if (inlen != 0 &&
			    inlen != (8 * (dopts->ip6d_len + 1)))
				return (EINVAL);

			if (checkonly)
				break;

			if (inlen == 0) {
				if (sticky &&
				    (ipp->ipp_fields & IPPF_DSTOPTS) != 0) {
					kmem_free(ipp->ipp_dstopts,
					    ipp->ipp_dstoptslen);
					ipp->ipp_dstopts = NULL;
					ipp->ipp_dstoptslen = 0;
				}
				ipp->ipp_fields &= ~IPPF_DSTOPTS;
				ipp->ipp_sticky_ignored |= IPPF_DSTOPTS;
			} else {
				error = optcom_pkt_set(invalp, inlen, sticky,
				    (uchar_t **)&ipp->ipp_dstopts,
				    &ipp->ipp_dstoptslen, 0);
				if (error != 0)
					return (error);
				ipp->ipp_fields |= IPPF_DSTOPTS;
			}
			if (sticky) {
				error = icmp_build_hdrs(icmp);
				if (error != 0)
					return (error);
			}
			break;
		}
		case IPV6_RTHDR: {
			ip6_rthdr_t *rt = (ip6_rthdr_t *)invalp;

			/*
			 * Sanity checks - minimum size, size a multiple of
			 * eight bytes, and matching size passed in.
			 */
			if (inlen != 0 &&
			    inlen != (8 * (rt->ip6r_len + 1)))
				return (EINVAL);

			if (checkonly)
				break;

			if (inlen == 0) {
				if (sticky &&
				    (ipp->ipp_fields & IPPF_RTHDR) != 0) {
					kmem_free(ipp->ipp_rthdr,
					    ipp->ipp_rthdrlen);
					ipp->ipp_rthdr = NULL;
					ipp->ipp_rthdrlen = 0;
				}
				ipp->ipp_fields &= ~IPPF_RTHDR;
				ipp->ipp_sticky_ignored |= IPPF_RTHDR;
			} else {
				error = optcom_pkt_set(invalp, inlen, sticky,
				    (uchar_t **)&ipp->ipp_rthdr,
				    &ipp->ipp_rthdrlen, 0);
				if (error != 0)
					return (error);
				ipp->ipp_fields |= IPPF_RTHDR;
			}
			if (sticky) {
				error = icmp_build_hdrs(icmp);
				if (error != 0)
					return (error);
			}
			break;
		}

		case IPV6_DONTFRAG:
			if (checkonly)
				break;

			if (onoff) {
				ipp->ipp_fields |= IPPF_DONTFRAG;
			} else {
				ipp->ipp_fields &= ~IPPF_DONTFRAG;
			}
			break;

		case IPV6_USE_MIN_MTU:
			if (inlen != sizeof (int))
				return (EINVAL);

			if (*i1 < -1 || *i1 > 1)
				return (EINVAL);

			if (checkonly)
				break;

			ipp->ipp_fields |= IPPF_USE_MIN_MTU;
			ipp->ipp_use_min_mtu = *i1;
			break;

		/*
		 * This option can't be set.  Its only returned via
		 * getsockopt() or ancillary data.
		 */
		case IPV6_PATHMTU:
			return (EINVAL);

		case IPV6_BOUND_PIF:
		case IPV6_SEC_OPT:
		case IPV6_DONTFAILOVER_IF:
		case IPV6_SRC_PREFERENCES:
		case IPV6_V6ONLY:
			/* Handled at IP level */
			return (-EINVAL);
		default:
			*outlenp = 0;
			return (EINVAL);
		}
		break;
	}		/* end IPPROTO_IPV6 */

	case IPPROTO_ICMPV6:
		/*
		 * Only allow IPv6 option processing on IPv6 sockets.
		 */
		if (icmp->icmp_family != AF_INET6) {
			*outlenp = 0;
			return (ENOPROTOOPT);
		}
		if (icmp->icmp_proto != IPPROTO_ICMPV6) {
			*outlenp = 0;
			return (ENOPROTOOPT);
		}
		switch (name) {
		case ICMP6_FILTER:
			if (!checkonly) {
				if ((inlen != 0) &&
				    (inlen != sizeof (icmp6_filter_t)))
					return (EINVAL);

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
							*outlenp = 0;
							return (ENOBUFS);
						}
					}
					(void) bcopy(invalp, icmp->icmp_filter,
					    inlen);
				}
			}
			break;

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
	 * Common case of OK return with outval same as inval.
	 */
	if (invalp != outvalp) {
		/* don't trust bcopy for identical src/dst */
		(void) bcopy(invalp, outvalp, inlen);
	}
	*outlenp = inlen;
	return (0);
}
/* This routine sets socket options. */
/* ARGSUSED */
int
icmp_opt_set(queue_t *q, uint_t optset_context, int level, int name,
    uint_t inlen, uchar_t *invalp, uint_t *outlenp, uchar_t *outvalp,
    void *thisdg_attrs, cred_t *cr, mblk_t *mblk)
{
	icmp_t	*icmp;
	int	err;

	icmp = Q_TO_ICMP(q);

	rw_enter(&icmp->icmp_rwlock, RW_WRITER);
	err = icmp_opt_set_locked(q, optset_context, level, name, inlen, invalp,
	    outlenp, outvalp, thisdg_attrs, cr, mblk);
	rw_exit(&icmp->icmp_rwlock);
	return (err);
}

/*
 * Update icmp_sticky_hdrs based on icmp_sticky_ipp, icmp_v6src, icmp_ttl,
 * icmp_proto, icmp_raw_checksum and icmp_no_tp_cksum.
 * The headers include ip6i_t (if needed), ip6_t, and any sticky extension
 * headers.
 * Returns failure if can't allocate memory.
 */
static int
icmp_build_hdrs(icmp_t *icmp)
{
	icmp_stack_t *is = icmp->icmp_is;
	uchar_t	*hdrs;
	uint_t	hdrs_len;
	ip6_t	*ip6h;
	ip6i_t	*ip6i;
	ip6_pkt_t *ipp = &icmp->icmp_sticky_ipp;

	ASSERT(RW_WRITE_HELD(&icmp->icmp_rwlock));
	hdrs_len = ip_total_hdrs_len_v6(ipp);
	ASSERT(hdrs_len != 0);
	if (hdrs_len != icmp->icmp_sticky_hdrs_len) {
		/* Need to reallocate */
		if (hdrs_len != 0) {
			hdrs = kmem_alloc(hdrs_len, KM_NOSLEEP);
			if (hdrs == NULL)
				return (ENOMEM);
		} else {
			hdrs = NULL;
		}
		if (icmp->icmp_sticky_hdrs_len != 0) {
			kmem_free(icmp->icmp_sticky_hdrs,
			    icmp->icmp_sticky_hdrs_len);
		}
		icmp->icmp_sticky_hdrs = hdrs;
		icmp->icmp_sticky_hdrs_len = hdrs_len;
	}
	ip_build_hdrs_v6(icmp->icmp_sticky_hdrs,
	    icmp->icmp_sticky_hdrs_len, ipp, icmp->icmp_proto);

	/* Set header fields not in ipp */
	if (ipp->ipp_fields & IPPF_HAS_IP6I) {
		ip6i = (ip6i_t *)icmp->icmp_sticky_hdrs;
		ip6h = (ip6_t *)&ip6i[1];

		if (ipp->ipp_fields & IPPF_RAW_CKSUM) {
			ip6i->ip6i_flags |= IP6I_RAW_CHECKSUM;
			ip6i->ip6i_checksum_off = icmp->icmp_checksum_off;
		}
		if (ipp->ipp_fields & IPPF_NO_CKSUM) {
			ip6i->ip6i_flags |= IP6I_NO_ULP_CKSUM;
		}
	} else {
		ip6h = (ip6_t *)icmp->icmp_sticky_hdrs;
	}

	if (!(ipp->ipp_fields & IPPF_ADDR))
		ip6h->ip6_src = icmp->icmp_v6src;

	/* Try to get everything in a single mblk */
	if (hdrs_len > icmp->icmp_max_hdr_len) {
		icmp->icmp_max_hdr_len = hdrs_len;
		rw_exit(&icmp->icmp_rwlock);
		(void) mi_set_sth_wroff(icmp->icmp_connp->conn_rq,
		    icmp->icmp_max_hdr_len + is->is_wroff_extra);
		rw_enter(&icmp->icmp_rwlock, RW_WRITER);
	}
	return (0);
}

/*
 * This routine retrieves the value of an ND variable in a icmpparam_t
 * structure.  It is called through nd_getset when a user reads the
 * variable.
 */
/* ARGSUSED */
static int
icmp_param_get(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *cr)
{
	icmpparam_t	*icmppa = (icmpparam_t *)cp;

	(void) mi_mpprintf(mp, "%d", icmppa->icmp_param_value);
	return (0);
}

/*
 * Walk through the param array specified registering each element with the
 * named dispatch (ND) handler.
 */
static boolean_t
icmp_param_register(IDP *ndp, icmpparam_t *icmppa, int cnt)
{
	for (; cnt-- > 0; icmppa++) {
		if (icmppa->icmp_param_name && icmppa->icmp_param_name[0]) {
			if (!nd_load(ndp, icmppa->icmp_param_name,
			    icmp_param_get, icmp_param_set,
			    (caddr_t)icmppa)) {
				nd_free(ndp);
				return (B_FALSE);
			}
		}
	}
	if (!nd_load(ndp, "icmp_status", icmp_status_report, NULL,
	    NULL)) {
		nd_free(ndp);
		return (B_FALSE);
	}
	return (B_TRUE);
}

/* This routine sets an ND variable in a icmpparam_t structure. */
/* ARGSUSED */
static int
icmp_param_set(queue_t *q, mblk_t *mp, char *value, caddr_t cp, cred_t *cr)
{
	long		new_value;
	icmpparam_t	*icmppa = (icmpparam_t *)cp;

	/*
	 * Fail the request if the new value does not lie within the
	 * required bounds.
	 */
	if (ddi_strtol(value, NULL, 10, &new_value) != 0 ||
	    new_value < icmppa->icmp_param_min ||
	    new_value > icmppa->icmp_param_max) {
		return (EINVAL);
	}
	/* Set the new value */
	icmppa->icmp_param_value = new_value;
	return (0);
}
/*ARGSUSED2*/
static void
icmp_input(void *arg1, mblk_t *mp, void *arg2)
{
	conn_t *connp = (conn_t *)arg1;
	struct T_unitdata_ind	*tudi;
	uchar_t			*rptr;
	icmp_t			*icmp;
	icmp_stack_t		*is;
	sin_t			*sin;
	sin6_t			*sin6;
	ip6_t			*ip6h;
	ip6i_t			*ip6i;
	mblk_t			*mp1;
	int			hdr_len;
	ipha_t			*ipha;
	int			udi_size;	/* Size of T_unitdata_ind */
	uint_t			ipvers;
	ip6_pkt_t		ipp;
	uint8_t			nexthdr;
	ip_pktinfo_t		*pinfo = NULL;
	mblk_t			*options_mp = NULL;
	uint_t			icmp_opt = 0;
	boolean_t		icmp_ipv6_recvhoplimit = B_FALSE;
	uint_t			hopstrip;

	ASSERT(connp->conn_flags & IPCL_RAWIPCONN);

	icmp = connp->conn_icmp;
	is = icmp->icmp_is;
	rptr = mp->b_rptr;
	ASSERT(DB_TYPE(mp) == M_DATA || DB_TYPE(mp) == M_CTL);
	ASSERT(OK_32PTR(rptr));

	/*
	 * IP should have prepended the options data in an M_CTL
	 * Check M_CTL "type" to make sure are not here bcos of
	 * a valid ICMP message
	 */
	if (DB_TYPE(mp) == M_CTL) {
		/*
		 * FIXME: does IP still do this?
		 * IP sends up the IPSEC_IN message for handling IPSEC
		 * policy at the TCP level. We don't need it here.
		 */
		if (*(uint32_t *)(mp->b_rptr) == IPSEC_IN) {
			mp1 = mp->b_cont;
			freeb(mp);
			mp = mp1;
			rptr = mp->b_rptr;
		} else if (MBLKL(mp) == sizeof (ip_pktinfo_t) &&
		    ((ip_pktinfo_t *)mp->b_rptr)->ip_pkt_ulp_type ==
		    IN_PKTINFO) {
			/*
			 * IP_RECVIF or IP_RECVSLLA or IPF_RECVADDR information
			 * has been prepended to the packet by IP. We need to
			 * extract the mblk and adjust the rptr
			 */
			pinfo = (ip_pktinfo_t *)mp->b_rptr;
			options_mp = mp;
			mp = mp->b_cont;
			rptr = mp->b_rptr;
		} else {
			/*
			 * ICMP messages.
			 */
			icmp_icmp_error(connp->conn_rq, mp);
			return;
		}
	}

	/*
	 * Discard message if it is misaligned or smaller than the IP header.
	 */
	if (!OK_32PTR(rptr) || (mp->b_wptr - rptr) < sizeof (ipha_t)) {
		freemsg(mp);
		if (options_mp != NULL)
			freeb(options_mp);
		BUMP_MIB(&is->is_rawip_mib, rawipInErrors);
		return;
	}
	ipvers = IPH_HDR_VERSION((ipha_t *)rptr);

	/* Handle M_DATA messages containing IP packets messages */
	if (ipvers == IPV4_VERSION) {
		/*
		 * Special case where IP attaches
		 * the IRE needs to be handled so that we don't send up
		 * IRE to the user land.
		 */
		ipha = (ipha_t *)rptr;
		hdr_len = IPH_HDR_LENGTH(ipha);

		if (ipha->ipha_protocol == IPPROTO_TCP) {
			tcph_t *tcph = (tcph_t *)&mp->b_rptr[hdr_len];

			if (((tcph->th_flags[0] & (TH_SYN|TH_ACK)) ==
			    TH_SYN) && mp->b_cont != NULL) {
				mp1 = mp->b_cont;
				if (mp1->b_datap->db_type == IRE_DB_TYPE) {
					freeb(mp1);
					mp->b_cont = NULL;
				}
			}
		}
		if (is->is_bsd_compat) {
			ushort_t len;
			len = ntohs(ipha->ipha_length);

			if (mp->b_datap->db_ref > 1) {
				/*
				 * Allocate a new IP header so that we can
				 * modify ipha_length.
				 */
				mblk_t	*mp1;

				mp1 = allocb(hdr_len, BPRI_MED);
				if (!mp1) {
					freemsg(mp);
					if (options_mp != NULL)
						freeb(options_mp);
					BUMP_MIB(&is->is_rawip_mib,
					    rawipInErrors);
					return;
				}
				bcopy(rptr, mp1->b_rptr, hdr_len);
				mp->b_rptr = rptr + hdr_len;
				rptr = mp1->b_rptr;
				ipha = (ipha_t *)rptr;
				mp1->b_cont = mp;
				mp1->b_wptr = rptr + hdr_len;
				mp = mp1;
			}
			len -= hdr_len;
			ipha->ipha_length = htons(len);
		}
	}

	/*
	 * This is the inbound data path.  Packets are passed upstream as
	 * T_UNITDATA_IND messages with full IP headers still attached.
	 */
	if (icmp->icmp_family == AF_INET) {
		ASSERT(ipvers == IPV4_VERSION);
		udi_size =  sizeof (struct T_unitdata_ind) + sizeof (sin_t);
		if (icmp->icmp_recvif && (pinfo != NULL) &&
		    (pinfo->ip_pkt_flags & IPF_RECVIF)) {
			udi_size += sizeof (struct T_opthdr) +
			    sizeof (uint_t);
		}

		if (icmp->icmp_ip_recvpktinfo && (pinfo != NULL) &&
		    (pinfo->ip_pkt_flags & IPF_RECVADDR)) {
			udi_size += sizeof (struct T_opthdr) +
			    sizeof (struct in_pktinfo);
		}

		/*
		 * If SO_TIMESTAMP is set allocate the appropriate sized
		 * buffer. Since gethrestime() expects a pointer aligned
		 * argument, we allocate space necessary for extra
		 * alignment (even though it might not be used).
		 */
		if (icmp->icmp_timestamp) {
			udi_size += sizeof (struct T_opthdr) +
			    sizeof (timestruc_t) + _POINTER_ALIGNMENT;
		}
		mp1 = allocb(udi_size, BPRI_MED);
		if (mp1 == NULL) {
			freemsg(mp);
			if (options_mp != NULL)
				freeb(options_mp);
			BUMP_MIB(&is->is_rawip_mib, rawipInErrors);
			return;
		}
		mp1->b_cont = mp;
		mp = mp1;
		tudi = (struct T_unitdata_ind *)mp->b_rptr;
		mp->b_datap->db_type = M_PROTO;
		mp->b_wptr = (uchar_t *)tudi + udi_size;
		tudi->PRIM_type = T_UNITDATA_IND;
		tudi->SRC_length = sizeof (sin_t);
		tudi->SRC_offset = sizeof (struct T_unitdata_ind);
		sin = (sin_t *)&tudi[1];
		*sin = sin_null;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = ipha->ipha_src;
		tudi->OPT_offset =  sizeof (struct T_unitdata_ind) +
		    sizeof (sin_t);
		udi_size -= (sizeof (struct T_unitdata_ind) + sizeof (sin_t));
		tudi->OPT_length = udi_size;

		/*
		 * Add options if IP_RECVIF is set
		 */
		if (udi_size != 0) {
			char *dstopt;

			dstopt = (char *)&sin[1];
			if (icmp->icmp_recvif && (pinfo != NULL) &&
			    (pinfo->ip_pkt_flags & IPF_RECVIF)) {

				struct T_opthdr *toh;
				uint_t		*dstptr;

				toh = (struct T_opthdr *)dstopt;
				toh->level = IPPROTO_IP;
				toh->name = IP_RECVIF;
				toh->len = sizeof (struct T_opthdr) +
				    sizeof (uint_t);
				toh->status = 0;
				dstopt += sizeof (struct T_opthdr);
				dstptr = (uint_t *)dstopt;
				*dstptr = pinfo->ip_pkt_ifindex;
				dstopt += sizeof (uint_t);
				udi_size -= toh->len;
			}
			if (icmp->icmp_timestamp) {
				struct	T_opthdr *toh;

				toh = (struct T_opthdr *)dstopt;
				toh->level = SOL_SOCKET;
				toh->name = SCM_TIMESTAMP;
				toh->len = sizeof (struct T_opthdr) +
				    sizeof (timestruc_t) + _POINTER_ALIGNMENT;
				toh->status = 0;
				dstopt += sizeof (struct T_opthdr);
				/* Align for gethrestime() */
				dstopt = (char *)P2ROUNDUP((intptr_t)dstopt,
				    sizeof (intptr_t));
				gethrestime((timestruc_t *)dstopt);
				dstopt = (char *)toh + toh->len;
				udi_size -= toh->len;
			}
			if (icmp->icmp_ip_recvpktinfo && (pinfo != NULL) &&
			    (pinfo->ip_pkt_flags & IPF_RECVADDR)) {
				struct	T_opthdr *toh;
				struct	in_pktinfo *pktinfop;

				toh = (struct T_opthdr *)dstopt;
				toh->level = IPPROTO_IP;
				toh->name = IP_PKTINFO;
				toh->len = sizeof (struct T_opthdr) +
				    sizeof (in_pktinfo_t);
				toh->status = 0;
				dstopt += sizeof (struct T_opthdr);
				pktinfop = (struct in_pktinfo *)dstopt;
				pktinfop->ipi_ifindex = pinfo->ip_pkt_ifindex;
				pktinfop->ipi_spec_dst =
				    pinfo->ip_pkt_match_addr;

				pktinfop->ipi_addr.s_addr = ipha->ipha_dst;

				dstopt += sizeof (struct in_pktinfo);
				udi_size -= toh->len;
			}

			/* Consumed all of allocated space */
			ASSERT(udi_size == 0);
		}

		if (options_mp != NULL)
			freeb(options_mp);

		BUMP_MIB(&is->is_rawip_mib, rawipInDatagrams);
		putnext(connp->conn_rq, mp);
		return;
	}

	/*
	 * We don't need options_mp in the IPv6 path.
	 */
	if (options_mp != NULL) {
		freeb(options_mp);
		options_mp = NULL;
	}

	/*
	 * Discard message if it is smaller than the IPv6 header
	 * or if the header is malformed.
	 */
	if ((mp->b_wptr - rptr) < sizeof (ip6_t) ||
	    IPH_HDR_VERSION((ipha_t *)rptr) != IPV6_VERSION ||
	    icmp->icmp_family != AF_INET6) {
		freemsg(mp);
		BUMP_MIB(&is->is_rawip_mib, rawipInErrors);
		return;
	}

	/* Initialize */
	ipp.ipp_fields = 0;
	hopstrip = 0;

	ip6h = (ip6_t *)rptr;
	/*
	 * Call on ip_find_hdr_v6 which gets the total hdr len
	 * as well as individual lenghts of ext hdrs (and ptrs to
	 * them).
	 */
	if (ip6h->ip6_nxt != icmp->icmp_proto) {
		/* Look for ifindex information */
		if (ip6h->ip6_nxt == IPPROTO_RAW) {
			ip6i = (ip6i_t *)ip6h;
			if (ip6i->ip6i_flags & IP6I_IFINDEX) {
				ASSERT(ip6i->ip6i_ifindex != 0);
				ipp.ipp_fields |= IPPF_IFINDEX;
				ipp.ipp_ifindex = ip6i->ip6i_ifindex;
			}
			rptr = (uchar_t *)&ip6i[1];
			mp->b_rptr = rptr;
			if (rptr == mp->b_wptr) {
				mp1 = mp->b_cont;
				freeb(mp);
				mp = mp1;
				rptr = mp->b_rptr;
			}
			ASSERT(mp->b_wptr - rptr >= IPV6_HDR_LEN);
			ip6h = (ip6_t *)rptr;
		}
		hdr_len = ip_find_hdr_v6(mp, ip6h, &ipp, &nexthdr);

		/*
		 * We need to lie a bit to the user because users inside
		 * labeled compartments should not see their own labels.  We
		 * assume that in all other respects IP has checked the label,
		 * and that the label is always first among the options.  (If
		 * it's not first, then this code won't see it, and the option
		 * will be passed along to the user.)
		 *
		 * If we had multilevel ICMP sockets, then the following code
		 * should be skipped for them to allow the user to see the
		 * label.
		 *
		 * Alignment restrictions in the definition of IP options
		 * (namely, the requirement that the 4-octet DOI goes on a
		 * 4-octet boundary) mean that we know exactly where the option
		 * should start, but we're lenient for other hosts.
		 *
		 * Note that there are no multilevel ICMP or raw IP sockets
		 * yet, thus nobody ever sees the IP6OPT_LS option.
		 */
		if ((ipp.ipp_fields & IPPF_HOPOPTS) &&
		    ipp.ipp_hopoptslen > 5 && is_system_labeled()) {
			const uchar_t *ucp =
			    (const uchar_t *)ipp.ipp_hopopts + 2;
			int remlen = ipp.ipp_hopoptslen - 2;

			while (remlen > 0) {
				if (*ucp == IP6OPT_PAD1) {
					remlen--;
					ucp++;
				} else if (*ucp == IP6OPT_PADN) {
					remlen -= ucp[1] + 2;
					ucp += ucp[1] + 2;
				} else if (*ucp == ip6opt_ls) {
					hopstrip = (ucp -
					    (const uchar_t *)ipp.ipp_hopopts) +
					    ucp[1] + 2;
					hopstrip = (hopstrip + 7) & ~7;
					break;
				} else {
					/* label option must be first */
					break;
				}
			}
		}
	} else {
		hdr_len = IPV6_HDR_LEN;
		ip6i = NULL;
		nexthdr = ip6h->ip6_nxt;
	}
	/*
	 * One special case where IP attaches the IRE needs to
	 * be handled so that we don't send up IRE to the user land.
	 */
	if (nexthdr == IPPROTO_TCP) {
		tcph_t *tcph = (tcph_t *)&mp->b_rptr[hdr_len];

		if (((tcph->th_flags[0] & (TH_SYN|TH_ACK)) == TH_SYN) &&
		    mp->b_cont != NULL) {
			mp1 = mp->b_cont;
			if (mp1->b_datap->db_type == IRE_DB_TYPE) {
				freeb(mp1);
				mp->b_cont = NULL;
			}
		}
	}
	/*
	 * Check a filter for ICMPv6 types if needed.
	 * Verify raw checksums if needed.
	 */
	if (icmp->icmp_filter != NULL || icmp->icmp_raw_checksum) {
		if (icmp->icmp_filter != NULL) {
			int type;

			/* Assumes that IP has done the pullupmsg */
			type = mp->b_rptr[hdr_len];

			ASSERT(mp->b_rptr + hdr_len <= mp->b_wptr);
			if (ICMP6_FILTER_WILLBLOCK(type, icmp->icmp_filter)) {
				freemsg(mp);
				return;
			}
		} else {
			/* Checksum */
			uint16_t	*up;
			uint32_t	sum;
			int		remlen;

			up = (uint16_t *)&ip6h->ip6_src;

			remlen = msgdsize(mp) - hdr_len;
			sum = htons(icmp->icmp_proto + remlen)
			    + up[0] + up[1] + up[2] + up[3]
			    + up[4] + up[5] + up[6] + up[7]
			    + up[8] + up[9] + up[10] + up[11]
			    + up[12] + up[13] + up[14] + up[15];
			sum = (sum & 0xffff) + (sum >> 16);
			sum = IP_CSUM(mp, hdr_len, sum);
			if (sum != 0) {
				/* IPv6 RAW checksum failed */
				ip0dbg(("icmp_rput: RAW checksum "
				    "failed %x\n", sum));
				freemsg(mp);
				BUMP_MIB(&is->is_rawip_mib,
				    rawipInCksumErrs);
				return;
			}
		}
	}
	/* Skip all the IPv6 headers per API */
	mp->b_rptr += hdr_len;

	udi_size = sizeof (struct T_unitdata_ind) + sizeof (sin6_t);

	/*
	 * We use local variables icmp_opt and icmp_ipv6_recvhoplimit to
	 * maintain state information, instead of relying on icmp_t
	 * structure, since there arent any locks protecting these members
	 * and there is a window where there might be a race between a
	 * thread setting options on the write side and a thread reading
	 * these options on the read size.
	 */
	if (ipp.ipp_fields & (IPPF_HOPOPTS|IPPF_DSTOPTS|IPPF_RTDSTOPTS|
	    IPPF_RTHDR|IPPF_IFINDEX)) {
		if (icmp->icmp_ipv6_recvhopopts &&
		    (ipp.ipp_fields & IPPF_HOPOPTS) &&
		    ipp.ipp_hopoptslen > hopstrip) {
			udi_size += sizeof (struct T_opthdr) +
			    ipp.ipp_hopoptslen - hopstrip;
			icmp_opt |= IPPF_HOPOPTS;
		}
		if ((icmp->icmp_ipv6_recvdstopts ||
		    icmp->icmp_old_ipv6_recvdstopts) &&
		    (ipp.ipp_fields & IPPF_DSTOPTS)) {
			udi_size += sizeof (struct T_opthdr) +
			    ipp.ipp_dstoptslen;
			icmp_opt |= IPPF_DSTOPTS;
		}
		if (((icmp->icmp_ipv6_recvdstopts &&
		    icmp->icmp_ipv6_recvrthdr &&
		    (ipp.ipp_fields & IPPF_RTHDR)) ||
		    icmp->icmp_ipv6_recvrtdstopts) &&
		    (ipp.ipp_fields & IPPF_RTDSTOPTS)) {
			udi_size += sizeof (struct T_opthdr) +
			    ipp.ipp_rtdstoptslen;
			icmp_opt |= IPPF_RTDSTOPTS;
		}
		if (icmp->icmp_ipv6_recvrthdr &&
		    (ipp.ipp_fields & IPPF_RTHDR)) {
			udi_size += sizeof (struct T_opthdr) +
			    ipp.ipp_rthdrlen;
			icmp_opt |= IPPF_RTHDR;
		}
		if (icmp->icmp_ip_recvpktinfo &&
		    (ipp.ipp_fields & IPPF_IFINDEX)) {
			udi_size += sizeof (struct T_opthdr) +
			    sizeof (struct in6_pktinfo);
			icmp_opt |= IPPF_IFINDEX;
		}
	}
	if (icmp->icmp_ipv6_recvhoplimit) {
		udi_size += sizeof (struct T_opthdr) + sizeof (int);
		icmp_ipv6_recvhoplimit = B_TRUE;
	}

	if (icmp->icmp_ipv6_recvtclass)
		udi_size += sizeof (struct T_opthdr) + sizeof (int);

	mp1 = allocb(udi_size, BPRI_MED);
	if (mp1 == NULL) {
		freemsg(mp);
		BUMP_MIB(&is->is_rawip_mib, rawipInErrors);
		return;
	}
	mp1->b_cont = mp;
	mp = mp1;
	mp->b_datap->db_type = M_PROTO;
	tudi = (struct T_unitdata_ind *)mp->b_rptr;
	mp->b_wptr = (uchar_t *)tudi + udi_size;
	tudi->PRIM_type = T_UNITDATA_IND;
	tudi->SRC_length = sizeof (sin6_t);
	tudi->SRC_offset = sizeof (struct T_unitdata_ind);
	tudi->OPT_offset = sizeof (struct T_unitdata_ind) + sizeof (sin6_t);
	udi_size -= (sizeof (struct T_unitdata_ind) + sizeof (sin6_t));
	tudi->OPT_length = udi_size;
	sin6 = (sin6_t *)&tudi[1];
	sin6->sin6_port = 0;
	sin6->sin6_family = AF_INET6;

	sin6->sin6_addr = ip6h->ip6_src;
	/* No sin6_flowinfo per API */
	sin6->sin6_flowinfo = 0;
	/* For link-scope source pass up scope id */
	if ((ipp.ipp_fields & IPPF_IFINDEX) &&
	    IN6_IS_ADDR_LINKSCOPE(&ip6h->ip6_src))
		sin6->sin6_scope_id = ipp.ipp_ifindex;
	else
		sin6->sin6_scope_id = 0;

	sin6->__sin6_src_id = ip_srcid_find_addr(&ip6h->ip6_dst,
	    icmp->icmp_zoneid, is->is_netstack);

	if (udi_size != 0) {
		uchar_t *dstopt;

		dstopt = (uchar_t *)&sin6[1];
		if (icmp_opt & IPPF_IFINDEX) {
			struct T_opthdr *toh;
			struct in6_pktinfo *pkti;

			toh = (struct T_opthdr *)dstopt;
			toh->level = IPPROTO_IPV6;
			toh->name = IPV6_PKTINFO;
			toh->len = sizeof (struct T_opthdr) +
			    sizeof (*pkti);
			toh->status = 0;
			dstopt += sizeof (struct T_opthdr);
			pkti = (struct in6_pktinfo *)dstopt;
			pkti->ipi6_addr = ip6h->ip6_dst;
			pkti->ipi6_ifindex = ipp.ipp_ifindex;
			dstopt += sizeof (*pkti);
			udi_size -= toh->len;
		}
		if (icmp_ipv6_recvhoplimit) {
			struct T_opthdr *toh;

			toh = (struct T_opthdr *)dstopt;
			toh->level = IPPROTO_IPV6;
			toh->name = IPV6_HOPLIMIT;
			toh->len = sizeof (struct T_opthdr) +
			    sizeof (uint_t);
			toh->status = 0;
			dstopt += sizeof (struct T_opthdr);
			*(uint_t *)dstopt = ip6h->ip6_hops;
			dstopt += sizeof (uint_t);
			udi_size -= toh->len;
		}
		if (icmp->icmp_ipv6_recvtclass) {
			struct T_opthdr *toh;

			toh = (struct T_opthdr *)dstopt;
			toh->level = IPPROTO_IPV6;
			toh->name = IPV6_TCLASS;
			toh->len = sizeof (struct T_opthdr) +
			    sizeof (uint_t);
			toh->status = 0;
			dstopt += sizeof (struct T_opthdr);
			*(uint_t *)dstopt = IPV6_FLOW_TCLASS(ip6h->ip6_flow);
			dstopt += sizeof (uint_t);
			udi_size -= toh->len;
		}
		if (icmp_opt & IPPF_HOPOPTS) {
			struct T_opthdr *toh;

			toh = (struct T_opthdr *)dstopt;
			toh->level = IPPROTO_IPV6;
			toh->name = IPV6_HOPOPTS;
			toh->len = sizeof (struct T_opthdr) +
			    ipp.ipp_hopoptslen - hopstrip;
			toh->status = 0;
			dstopt += sizeof (struct T_opthdr);
			bcopy((char *)ipp.ipp_hopopts + hopstrip, dstopt,
			    ipp.ipp_hopoptslen - hopstrip);
			if (hopstrip > 0) {
				/* copy next header value and fake length */
				dstopt[0] = ((uchar_t *)ipp.ipp_hopopts)[0];
				dstopt[1] = ((uchar_t *)ipp.ipp_hopopts)[1] -
				    hopstrip / 8;
			}
			dstopt += ipp.ipp_hopoptslen - hopstrip;
			udi_size -= toh->len;
		}
		if (icmp_opt & IPPF_RTDSTOPTS) {
			struct T_opthdr *toh;

			toh = (struct T_opthdr *)dstopt;
			toh->level = IPPROTO_IPV6;
			toh->name = IPV6_DSTOPTS;
			toh->len = sizeof (struct T_opthdr) +
			    ipp.ipp_rtdstoptslen;
			toh->status = 0;
			dstopt += sizeof (struct T_opthdr);
			bcopy(ipp.ipp_rtdstopts, dstopt,
			    ipp.ipp_rtdstoptslen);
			dstopt += ipp.ipp_rtdstoptslen;
			udi_size -= toh->len;
		}
		if (icmp_opt & IPPF_RTHDR) {
			struct T_opthdr *toh;

			toh = (struct T_opthdr *)dstopt;
			toh->level = IPPROTO_IPV6;
			toh->name = IPV6_RTHDR;
			toh->len = sizeof (struct T_opthdr) +
			    ipp.ipp_rthdrlen;
			toh->status = 0;
			dstopt += sizeof (struct T_opthdr);
			bcopy(ipp.ipp_rthdr, dstopt, ipp.ipp_rthdrlen);
			dstopt += ipp.ipp_rthdrlen;
			udi_size -= toh->len;
		}
		if (icmp_opt & IPPF_DSTOPTS) {
			struct T_opthdr *toh;

			toh = (struct T_opthdr *)dstopt;
			toh->level = IPPROTO_IPV6;
			toh->name = IPV6_DSTOPTS;
			toh->len = sizeof (struct T_opthdr) +
			    ipp.ipp_dstoptslen;
			toh->status = 0;
			dstopt += sizeof (struct T_opthdr);
			bcopy(ipp.ipp_dstopts, dstopt,
			    ipp.ipp_dstoptslen);
			dstopt += ipp.ipp_dstoptslen;
			udi_size -= toh->len;
		}
		/* Consumed all of allocated space */
		ASSERT(udi_size == 0);
	}
	BUMP_MIB(&is->is_rawip_mib, rawipInDatagrams);
	putnext(connp->conn_rq, mp);
}

/*
 * Handle the results of a T_BIND_REQ whether deferred by IP or handled
 * immediately.
 */
static void
icmp_bind_result(conn_t *connp, mblk_t *mp)
{
	struct T_error_ack	*tea;

	switch (mp->b_datap->db_type) {
	case M_PROTO:
	case M_PCPROTO:
		/* M_PROTO messages contain some type of TPI message. */
		if ((mp->b_wptr - mp->b_rptr) < sizeof (t_scalar_t)) {
			freemsg(mp);
			return;
		}
		tea = (struct T_error_ack *)mp->b_rptr;

		switch (tea->PRIM_type) {
		case T_ERROR_ACK:
			switch (tea->ERROR_prim) {
			case O_T_BIND_REQ:
			case T_BIND_REQ:
				icmp_bind_error(connp, mp);
				return;
			default:
				break;
			}
			ASSERT(0);
			freemsg(mp);
			return;

		case T_BIND_ACK:
			icmp_bind_ack(connp, mp);
			return;

		default:
			break;
		}
		freemsg(mp);
		return;
	default:
		/* FIXME: other cases? */
		ASSERT(0);
		freemsg(mp);
		return;
	}
}

/*
 * Process a T_BIND_ACK
 */
static void
icmp_bind_ack(conn_t *connp, mblk_t *mp)
{
	icmp_t	*icmp = connp->conn_icmp;
	mblk_t	*mp1;
	ire_t	*ire;
	struct T_bind_ack *tba;
	uchar_t *addrp;
	ipa_conn_t	*ac;
	ipa6_conn_t	*ac6;

	rw_enter(&icmp->icmp_rwlock, RW_WRITER);
	/*
	 * We know if headers are included or not so we can
	 * safely do this.
	 */
	if (icmp->icmp_state == TS_UNBND) {
		/*
		 * TPI has not yet bound - bind sent by
		 * icmp_bind_proto.
		 */
		freemsg(mp);
		rw_exit(&icmp->icmp_rwlock);
		return;
	}
	ASSERT(icmp->icmp_pending_op != -1);

	/*
	 * If a broadcast/multicast address was bound set
	 * the source address to 0.
	 * This ensures no datagrams with broadcast address
	 * as source address are emitted (which would violate
	 * RFC1122 - Hosts requirements)
	 *
	 * Note that when connecting the returned IRE is
	 * for the destination address and we only perform
	 * the broadcast check for the source address (it
	 * is OK to connect to a broadcast/multicast address.)
	 */
	mp1 = mp->b_cont;
	if (mp1 != NULL && mp1->b_datap->db_type == IRE_DB_TYPE) {
		ire = (ire_t *)mp1->b_rptr;

		/*
		 * Note: we get IRE_BROADCAST for IPv6 to "mark" a multicast
		 * local address.
		 */
		if (ire->ire_type == IRE_BROADCAST &&
		    icmp->icmp_state != TS_DATA_XFER) {
			ASSERT(icmp->icmp_pending_op == T_BIND_REQ ||
			    icmp->icmp_pending_op == O_T_BIND_REQ);
			/* This was just a local bind to a MC/broadcast addr */
			V6_SET_ZERO(icmp->icmp_v6src);
			if (icmp->icmp_family == AF_INET6)
				(void) icmp_build_hdrs(icmp);
		} else if (V6_OR_V4_INADDR_ANY(icmp->icmp_v6src)) {
			/*
			 * Local address not yet set - pick it from the
			 * T_bind_ack
			 */
			tba = (struct T_bind_ack *)mp->b_rptr;
			addrp = &mp->b_rptr[tba->ADDR_offset];
			switch (icmp->icmp_family) {
			case AF_INET:
				if (tba->ADDR_length == sizeof (ipa_conn_t)) {
					ac = (ipa_conn_t *)addrp;
				} else {
					ASSERT(tba->ADDR_length ==
					    sizeof (ipa_conn_x_t));
					ac = &((ipa_conn_x_t *)addrp)->acx_conn;
				}
				IN6_IPADDR_TO_V4MAPPED(ac->ac_laddr,
				    &icmp->icmp_v6src);
				break;
			case AF_INET6:
				if (tba->ADDR_length == sizeof (ipa6_conn_t)) {
					ac6 = (ipa6_conn_t *)addrp;
				} else {
					ASSERT(tba->ADDR_length ==
					    sizeof (ipa6_conn_x_t));
					ac6 = &((ipa6_conn_x_t *)
					    addrp)->ac6x_conn;
				}
				icmp->icmp_v6src = ac6->ac6_laddr;
				(void) icmp_build_hdrs(icmp);
			}
		}
		mp1 = mp1->b_cont;
	}
	icmp->icmp_pending_op = -1;
	rw_exit(&icmp->icmp_rwlock);
	/*
	 * Look for one or more appended ACK message added by
	 * icmp_connect or icmp_disconnect.
	 * If none found just send up the T_BIND_ACK.
	 * icmp_connect has appended a T_OK_ACK and a
	 * T_CONN_CON.
	 * icmp_disconnect has appended a T_OK_ACK.
	 */
	if (mp1 != NULL) {
		if (mp->b_cont == mp1)
			mp->b_cont = NULL;
		else {
			ASSERT(mp->b_cont->b_cont == mp1);
			mp->b_cont->b_cont = NULL;
		}
		freemsg(mp);
		mp = mp1;
		while (mp != NULL) {
			mp1 = mp->b_cont;
			mp->b_cont = NULL;
			putnext(connp->conn_rq, mp);
			mp = mp1;
		}
		return;
	}
	freemsg(mp->b_cont);
	mp->b_cont = NULL;
	putnext(connp->conn_rq, mp);
}

static void
icmp_bind_error(conn_t *connp, mblk_t *mp)
{
	icmp_t	*icmp = connp->conn_icmp;
	struct T_error_ack *tea;

	tea = (struct T_error_ack *)mp->b_rptr;
	/*
	 * If our O_T_BIND_REQ/T_BIND_REQ fails,
	 * clear out the source address before
	 * passing the message upstream.
	 * If this was caused by a T_CONN_REQ
	 * revert back to bound state.
	 */
	rw_enter(&icmp->icmp_rwlock, RW_WRITER);
	if (icmp->icmp_state == TS_UNBND) {
		/*
		 * TPI has not yet bound - bind sent by icmp_bind_proto.
		 */
		freemsg(mp);
		rw_exit(&icmp->icmp_rwlock);
		return;
	}
	ASSERT(icmp->icmp_pending_op != -1);
	tea->ERROR_prim = icmp->icmp_pending_op;
	icmp->icmp_pending_op = -1;

	switch (tea->ERROR_prim) {
	case T_CONN_REQ:
		ASSERT(icmp->icmp_state == TS_DATA_XFER);
		/* Connect failed */
		/* Revert back to the bound source */
		icmp->icmp_v6src = icmp->icmp_bound_v6src;
		icmp->icmp_state = TS_IDLE;
		if (icmp->icmp_family == AF_INET6)
			(void) icmp_build_hdrs(icmp);
		break;

	case T_DISCON_REQ:
	case T_BIND_REQ:
	case O_T_BIND_REQ:
		V6_SET_ZERO(icmp->icmp_v6src);
		V6_SET_ZERO(icmp->icmp_bound_v6src);
		icmp->icmp_state = TS_UNBND;
		if (icmp->icmp_family == AF_INET6)
			(void) icmp_build_hdrs(icmp);
		break;
	default:
		break;
	}
	rw_exit(&icmp->icmp_rwlock);
	putnext(connp->conn_rq, mp);
}

/*
 * return SNMP stuff in buffer in mpdata
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

/* Report for ndd "icmp_status" */
/* ARGSUSED */
static int
icmp_status_report(queue_t *q, mblk_t *mp, caddr_t cp, cred_t *cr)
{
	conn_t  *connp;
	ip_stack_t *ipst;
	char	laddrbuf[INET6_ADDRSTRLEN];
	char	faddrbuf[INET6_ADDRSTRLEN];
	int	i;

	(void) mi_mpprintf(mp,
	    "RAWIP    " MI_COL_HDRPAD_STR
	/*   01234567[89ABCDEF] */
	    "  src addr        dest addr       state");
	/*   xxx.xxx.xxx.xxx xxx.xxx.xxx.xxx UNBOUND */

	connp = Q_TO_CONN(q);
	ipst = connp->conn_netstack->netstack_ip;
	for (i = 0; i < CONN_G_HASH_SIZE; i++) {
		connf_t *connfp;
		char	*state;

		connfp = &ipst->ips_ipcl_globalhash_fanout[i];
		connp = NULL;

		while ((connp = ipcl_get_next_conn(connfp, connp,
		    IPCL_RAWIPCONN)) != NULL) {
			icmp_t  *icmp;

			mutex_enter(&(connp)->conn_lock);
			icmp = connp->conn_icmp;

			if (icmp->icmp_state == TS_UNBND)
				state = "UNBOUND";
			else if (icmp->icmp_state == TS_IDLE)
				state = "IDLE";
			else if (icmp->icmp_state == TS_DATA_XFER)
				state = "CONNECTED";
			else
				state = "UnkState";

			(void) mi_mpprintf(mp, MI_COL_PTRFMT_STR "%s %s %s",
			    (void *)icmp,
			    inet_ntop(AF_INET6, &icmp->icmp_v6dst, faddrbuf,
			    sizeof (faddrbuf)),
			    inet_ntop(AF_INET6, &icmp->icmp_v6src, laddrbuf,
			    sizeof (laddrbuf)),
			    state);
			mutex_exit(&(connp)->conn_lock);
		}
	}
	return (0);
}

/*
 * This routine creates a T_UDERROR_IND message and passes it upstream.
 * The address and options are copied from the T_UNITDATA_REQ message
 * passed in mp.  This message is freed.
 */
static void
icmp_ud_err(queue_t *q, mblk_t *mp, t_scalar_t err)
{
	mblk_t	*mp1;
	uchar_t	*rptr = mp->b_rptr;
	struct T_unitdata_req *tudr = (struct T_unitdata_req *)rptr;

	mp1 = mi_tpi_uderror_ind((char *)&rptr[tudr->DEST_offset],
	    tudr->DEST_length, (char *)&rptr[tudr->OPT_offset],
	    tudr->OPT_length, err);
	if (mp1)
		qreply(q, mp1);
	freemsg(mp);
}

/*
 * This routine is called by icmp_wput to handle T_UNBIND_REQ messages.
 * After some error checking, the message is passed downstream to ip.
 */
static void
icmp_unbind(queue_t *q, mblk_t *mp)
{
	icmp_t	*icmp = Q_TO_ICMP(q);

	rw_enter(&icmp->icmp_rwlock, RW_WRITER);
	/* If a bind has not been done, we can't unbind. */
	if (icmp->icmp_state == TS_UNBND || icmp->icmp_pending_op != -1) {
		rw_exit(&icmp->icmp_rwlock);
		icmp_err_ack(q, mp, TOUTSTATE, 0);
		return;
	}
	icmp->icmp_pending_op = T_UNBIND_REQ;
	rw_exit(&icmp->icmp_rwlock);

	/*
	 * Pass the unbind to IP; T_UNBIND_REQ is larger than T_OK_ACK
	 * and therefore ip_unbind must never return NULL.
	 */
	mp = ip_unbind(q, mp);
	ASSERT(mp != NULL);
	ASSERT(((struct T_ok_ack *)mp->b_rptr)->PRIM_type == T_OK_ACK);

	/*
	 * Once we're unbound from IP, the pending operation may be cleared
	 * here.
	 */
	rw_enter(&icmp->icmp_rwlock, RW_WRITER);
	V6_SET_ZERO(icmp->icmp_v6src);
	V6_SET_ZERO(icmp->icmp_bound_v6src);
	icmp->icmp_pending_op = -1;
	icmp->icmp_state = TS_UNBND;
	if (icmp->icmp_family == AF_INET6)
		(void) icmp_build_hdrs(icmp);
	rw_exit(&icmp->icmp_rwlock);

	qreply(q, mp);
}

/*
 * Process IPv4 packets that already include an IP header.
 * Used when IP_HDRINCL has been set (implicit for IPPROTO_RAW and
 * IPPROTO_IGMP).
 */
static void
icmp_wput_hdrincl(queue_t *q, mblk_t *mp, icmp_t *icmp, ip4_pkt_t *pktinfop)
{
	icmp_stack_t *is = icmp->icmp_is;
	ipha_t	*ipha;
	int	ip_hdr_length;
	int	tp_hdr_len;
	mblk_t	*mp1;
	uint_t	pkt_len;
	ip_opt_info_t optinfo;
	conn_t	*connp = icmp->icmp_connp;

	optinfo.ip_opt_flags = 0;
	optinfo.ip_opt_ill_index = 0;
	ipha = (ipha_t *)mp->b_rptr;
	ip_hdr_length = IP_SIMPLE_HDR_LENGTH + icmp->icmp_ip_snd_options_len;
	if ((mp->b_wptr - mp->b_rptr) < IP_SIMPLE_HDR_LENGTH) {
		if (!pullupmsg(mp, IP_SIMPLE_HDR_LENGTH)) {
			ASSERT(icmp != NULL);
			BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
			freemsg(mp);
			return;
		}
		ipha = (ipha_t *)mp->b_rptr;
	}
	ipha->ipha_version_and_hdr_length =
	    (IP_VERSION<<4) | (ip_hdr_length>>2);

	/*
	 * For the socket of SOCK_RAW type, the checksum is provided in the
	 * pre-built packet. We set the ipha_ident field to IP_HDR_INCLUDED to
	 * tell IP that the application has sent a complete IP header and not
	 * to compute the transport checksum nor change the DF flag.
	 */
	ipha->ipha_ident = IP_HDR_INCLUDED;
	ipha->ipha_hdr_checksum = 0;
	ipha->ipha_fragment_offset_and_flags &= htons(IPH_DF);
	/* Insert options if any */
	if (ip_hdr_length > IP_SIMPLE_HDR_LENGTH) {
		/*
		 * Put the IP header plus any transport header that is
		 * checksumed by ip_wput into the first mblk. (ip_wput assumes
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
		/*
		 * The code below assumes that IP_SIMPLE_HDR_LENGTH plus
		 * tp_hdr_len bytes will be in a single mblk.
		 */
		if ((mp->b_wptr - mp->b_rptr) < (IP_SIMPLE_HDR_LENGTH +
		    tp_hdr_len)) {
			if (!pullupmsg(mp, IP_SIMPLE_HDR_LENGTH +
			    tp_hdr_len)) {
				BUMP_MIB(&is->is_rawip_mib,
				    rawipOutErrors);
				freemsg(mp);
				return;
			}
			ipha = (ipha_t *)mp->b_rptr;
		}

		/*
		 * if the length is larger then the max allowed IP packet,
		 * then send an error and abort the processing.
		 */
		pkt_len = ntohs(ipha->ipha_length)
		    + icmp->icmp_ip_snd_options_len;
		if (pkt_len > IP_MAXPACKET) {
			icmp_ud_err(q, mp, EMSGSIZE);
			return;
		}
		if (!(mp1 = allocb(ip_hdr_length + is->is_wroff_extra +
		    tp_hdr_len, BPRI_LO))) {
			icmp_ud_err(q, mp, ENOMEM);
			return;
		}
		mp1->b_rptr += is->is_wroff_extra;
		mp1->b_wptr = mp1->b_rptr + ip_hdr_length;

		ipha->ipha_length = htons((uint16_t)pkt_len);
		bcopy(ipha, mp1->b_rptr, IP_SIMPLE_HDR_LENGTH);

		/* Copy transport header if any */
		bcopy(&ipha[1], mp1->b_wptr, tp_hdr_len);
		mp1->b_wptr += tp_hdr_len;

		/* Add options */
		ipha = (ipha_t *)mp1->b_rptr;
		bcopy(icmp->icmp_ip_snd_options, &ipha[1],
		    icmp->icmp_ip_snd_options_len);

		/* Drop IP header and transport header from original */
		(void) adjmsg(mp, IP_SIMPLE_HDR_LENGTH + tp_hdr_len);

		mp1->b_cont = mp;
		mp = mp1;
		/*
		 * Massage source route putting first source
		 * route in ipha_dst.
		 */
		(void) ip_massage_options(ipha, is->is_netstack);
	}

	if (pktinfop != NULL) {
		/*
		 * Over write the source address provided in the header
		 */
		if (pktinfop->ip4_addr != INADDR_ANY) {
			ipha->ipha_src = pktinfop->ip4_addr;
			optinfo.ip_opt_flags = IP_VERIFY_SRC;
		}

		if (pktinfop->ip4_ill_index != 0) {
			optinfo.ip_opt_ill_index = pktinfop->ip4_ill_index;
		}
	}

	mblk_setcred(mp, connp->conn_cred);
	ip_output_options(connp, mp, q, IP_WPUT,
	    &optinfo);
}

static boolean_t
icmp_update_label(queue_t *q, icmp_t *icmp, mblk_t *mp, ipaddr_t dst)
{
	int err;
	uchar_t opt_storage[IP_MAX_OPT_LENGTH];
	icmp_stack_t		*is = icmp->icmp_is;
	conn_t	*connp = icmp->icmp_connp;

	err = tsol_compute_label(DB_CREDDEF(mp, connp->conn_cred), dst,
	    opt_storage, icmp->icmp_mac_exempt,
	    is->is_netstack->netstack_ip);
	if (err == 0) {
		err = tsol_update_options(&icmp->icmp_ip_snd_options,
		    &icmp->icmp_ip_snd_options_len, &icmp->icmp_label_len,
		    opt_storage);
	}
	if (err != 0) {
		BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
		DTRACE_PROBE4(
		    tx__ip__log__drop__updatelabel__icmp,
		    char *, "queue(1) failed to update options(2) on mp(3)",
		    queue_t *, q, char *, opt_storage, mblk_t *, mp);
		icmp_ud_err(q, mp, err);
		return (B_FALSE);
	}
	IN6_IPADDR_TO_V4MAPPED(dst, &icmp->icmp_v6lastdst);
	return (B_TRUE);
}

/*
 * This routine handles all messages passed downstream.  It either
 * consumes the message or passes it downstream; it never queues a
 * a message.
 */
static void
icmp_wput(queue_t *q, mblk_t *mp)
{
	uchar_t	*rptr = mp->b_rptr;
	ipha_t	*ipha;
	mblk_t	*mp1;
	int	ip_hdr_length;
#define	tudr ((struct T_unitdata_req *)rptr)
	size_t	ip_len;
	conn_t	*connp = Q_TO_CONN(q);
	icmp_t	*icmp = connp->conn_icmp;
	icmp_stack_t *is = icmp->icmp_is;
	sin6_t	*sin6;
	sin_t	*sin;
	ipaddr_t	v4dst;
	ip4_pkt_t	pktinfo;
	ip4_pkt_t	*pktinfop = &pktinfo;
	ip_opt_info_t	optinfo;

	switch (mp->b_datap->db_type) {
	case M_DATA:
		if (icmp->icmp_hdrincl) {
			ASSERT(icmp->icmp_ipversion == IPV4_VERSION);
			ipha = (ipha_t *)mp->b_rptr;
			if (mp->b_wptr - mp->b_rptr < IP_SIMPLE_HDR_LENGTH) {
				if (!pullupmsg(mp, IP_SIMPLE_HDR_LENGTH)) {
					BUMP_MIB(&is->is_rawip_mib,
					    rawipOutErrors);
					freemsg(mp);
					return;
				}
				ipha = (ipha_t *)mp->b_rptr;
			}
			/*
			 * If this connection was used for v6 (inconceivable!)
			 * or if we have a new destination, then it's time to
			 * figure a new label.
			 */
			if (is_system_labeled() &&
			    (!IN6_IS_ADDR_V4MAPPED(&icmp->icmp_v6lastdst) ||
			    V4_PART_OF_V6(icmp->icmp_v6lastdst) !=
			    ipha->ipha_dst) &&
			    !icmp_update_label(q, icmp, mp, ipha->ipha_dst)) {
				return;
			}
			icmp_wput_hdrincl(q, mp, icmp, NULL);
			return;
		}
		freemsg(mp);
		return;
	case M_PROTO:
	case M_PCPROTO:
		ip_len = mp->b_wptr - rptr;
		if (ip_len >= sizeof (struct T_unitdata_req)) {
			/* Expedite valid T_UNITDATA_REQ to below the switch */
			if (((union T_primitives *)rptr)->type
			    == T_UNITDATA_REQ)
				break;
		}
		/* FALLTHRU */
	default:
		icmp_wput_other(q, mp);
		return;
	}

	/* Handle T_UNITDATA_REQ messages here. */



	if (icmp->icmp_state == TS_UNBND) {
		/* If a port has not been bound to the stream, fail. */
		BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
		icmp_ud_err(q, mp, EPROTO);
		return;
	}
	mp1 = mp->b_cont;
	if (mp1 == NULL) {
		BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
		icmp_ud_err(q, mp, EPROTO);
		return;
	}

	if ((rptr + tudr->DEST_offset + tudr->DEST_length) > mp->b_wptr) {
		BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
		icmp_ud_err(q, mp, EADDRNOTAVAIL);
		return;
	}

	switch (icmp->icmp_family) {
	case AF_INET6:
		sin6 = (sin6_t *)&rptr[tudr->DEST_offset];
		if (!OK_32PTR((char *)sin6) ||
		    tudr->DEST_length != sizeof (sin6_t) ||
		    sin6->sin6_family != AF_INET6) {
			BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
			icmp_ud_err(q, mp, EADDRNOTAVAIL);
			return;
		}

		/* No support for mapped addresses on raw sockets */
		if (IN6_IS_ADDR_V4MAPPED(&sin6->sin6_addr)) {
			BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
			icmp_ud_err(q, mp, EADDRNOTAVAIL);
			return;
		}

		/*
		 * Destination is a native IPv6 address.
		 * Send out an IPv6 format packet.
		 */
		icmp_wput_ipv6(q, mp, sin6, tudr->OPT_length);
		return;

	case AF_INET:
		sin = (sin_t *)&rptr[tudr->DEST_offset];
		if (!OK_32PTR((char *)sin) ||
		    tudr->DEST_length != sizeof (sin_t) ||
		    sin->sin_family != AF_INET) {
			BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
			icmp_ud_err(q, mp, EADDRNOTAVAIL);
			return;
		}
		/* Extract and ipaddr */
		v4dst = sin->sin_addr.s_addr;
		break;

	default:
		ASSERT(0);
	}

	pktinfop->ip4_ill_index = 0;
	pktinfop->ip4_addr = INADDR_ANY;
	optinfo.ip_opt_flags = 0;
	optinfo.ip_opt_ill_index = 0;


	/*
	 * If options passed in, feed it for verification and handling
	 */
	if (tudr->OPT_length != 0) {
		int error;

		error = 0;
		if (icmp_unitdata_opt_process(q, mp, &error,
		    (void *)pktinfop) < 0) {
			/* failure */
			BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
			icmp_ud_err(q, mp, error);
			return;
		}
		ASSERT(error == 0);
		/*
		 * Note: Success in processing options.
		 * mp option buffer represented by
		 * OPT_length/offset now potentially modified
		 * and contain option setting results
		 */

	}

	if (v4dst == INADDR_ANY)
		v4dst = htonl(INADDR_LOOPBACK);

	/* Check if our saved options are valid; update if not */
	if (is_system_labeled() &&
	    (!IN6_IS_ADDR_V4MAPPED(&icmp->icmp_v6lastdst) ||
	    V4_PART_OF_V6(icmp->icmp_v6lastdst) != v4dst) &&
	    !icmp_update_label(q, icmp, mp, v4dst)) {
		return;
	}

	/* Protocol 255 contains full IP headers */
	if (icmp->icmp_hdrincl) {
		freeb(mp);
		icmp_wput_hdrincl(q, mp1, icmp, pktinfop);
		return;
	}


	/* Add an IP header */
	ip_hdr_length = IP_SIMPLE_HDR_LENGTH + icmp->icmp_ip_snd_options_len;
	ipha = (ipha_t *)&mp1->b_rptr[-ip_hdr_length];
	if ((uchar_t *)ipha < mp1->b_datap->db_base ||
	    mp1->b_datap->db_ref != 1 ||
	    !OK_32PTR(ipha)) {
		if (!(mp1 = allocb(ip_hdr_length + is->is_wroff_extra,
		    BPRI_LO))) {
			BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
			icmp_ud_err(q, mp, ENOMEM);
			return;
		}
		mp1->b_cont = mp->b_cont;
		ipha = (ipha_t *)mp1->b_datap->db_lim;
		mp1->b_wptr = (uchar_t *)ipha;
		ipha = (ipha_t *)((uchar_t *)ipha - ip_hdr_length);
	}
#ifdef	_BIG_ENDIAN
	/* Set version, header length, and tos */
	*(uint16_t *)&ipha->ipha_version_and_hdr_length =
	    ((((IP_VERSION << 4) | (ip_hdr_length>>2)) << 8) |
	    icmp->icmp_type_of_service);
	/* Set ttl and protocol */
	*(uint16_t *)&ipha->ipha_ttl = (icmp->icmp_ttl << 8) | icmp->icmp_proto;
#else
	/* Set version, header length, and tos */
	*(uint16_t *)&ipha->ipha_version_and_hdr_length =
	    ((icmp->icmp_type_of_service << 8) |
	    ((IP_VERSION << 4) | (ip_hdr_length>>2)));
	/* Set ttl and protocol */
	*(uint16_t *)&ipha->ipha_ttl = (icmp->icmp_proto << 8) | icmp->icmp_ttl;
#endif
	if (pktinfop->ip4_addr != INADDR_ANY) {
		ipha->ipha_src = pktinfop->ip4_addr;
		optinfo.ip_opt_flags = IP_VERIFY_SRC;
	} else {

		/*
		 * Copy our address into the packet.  If this is zero,
		 * ip will fill in the real source address.
		 */
		IN6_V4MAPPED_TO_IPADDR(&icmp->icmp_v6src, ipha->ipha_src);
	}

	ipha->ipha_fragment_offset_and_flags = 0;

	if (pktinfop->ip4_ill_index != 0) {
		optinfo.ip_opt_ill_index = pktinfop->ip4_ill_index;
	}


	/*
	 * For the socket of SOCK_RAW type, the checksum is provided in the
	 * pre-built packet. We set the ipha_ident field to IP_HDR_INCLUDED to
	 * tell IP that the application has sent a complete IP header and not
	 * to compute the transport checksum nor change the DF flag.
	 */
	ipha->ipha_ident = IP_HDR_INCLUDED;

	/* Finish common formatting of the packet. */
	mp1->b_rptr = (uchar_t *)ipha;

	ip_len = mp1->b_wptr - (uchar_t *)ipha;
	if (mp1->b_cont != NULL)
		ip_len += msgdsize(mp1->b_cont);

	/*
	 * Set the length into the IP header.
	 * If the length is greater than the maximum allowed by IP,
	 * then free the message and return. Do not try and send it
	 * as this can cause problems in layers below.
	 */
	if (ip_len > IP_MAXPACKET) {
		BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
		icmp_ud_err(q, mp, EMSGSIZE);
		return;
	}
	ipha->ipha_length = htons((uint16_t)ip_len);
	/*
	 * Copy in the destination address from the T_UNITDATA
	 * request
	 */
	ipha->ipha_dst = v4dst;

	/*
	 * Set ttl based on IP_MULTICAST_TTL to match IPv6 logic.
	 */
	if (CLASSD(v4dst))
		ipha->ipha_ttl = icmp->icmp_multicast_ttl;

	/* Copy in options if any */
	if (ip_hdr_length > IP_SIMPLE_HDR_LENGTH) {
		bcopy(icmp->icmp_ip_snd_options,
		    &ipha[1], icmp->icmp_ip_snd_options_len);
		/*
		 * Massage source route putting first source route in ipha_dst.
		 * Ignore the destination in the T_unitdata_req.
		 */
		(void) ip_massage_options(ipha, is->is_netstack);
	}

	freeb(mp);
	BUMP_MIB(&is->is_rawip_mib, rawipOutDatagrams);
	mblk_setcred(mp1, connp->conn_cred);
	ip_output_options(Q_TO_CONN(q), mp1, q, IP_WPUT, &optinfo);
#undef	ipha
#undef tudr
}

static boolean_t
icmp_update_label_v6(queue_t *wq, icmp_t *icmp, mblk_t *mp, in6_addr_t *dst)
{
	int err;
	uchar_t opt_storage[TSOL_MAX_IPV6_OPTION];
	icmp_stack_t		*is = icmp->icmp_is;
	conn_t	*connp = icmp->icmp_connp;

	err = tsol_compute_label_v6(DB_CREDDEF(mp, connp->conn_cred), dst,
	    opt_storage, icmp->icmp_mac_exempt,
	    is->is_netstack->netstack_ip);
	if (err == 0) {
		err = tsol_update_sticky(&icmp->icmp_sticky_ipp,
		    &icmp->icmp_label_len_v6, opt_storage);
	}
	if (err != 0) {
		BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
		DTRACE_PROBE4(
		    tx__ip__log__drop__updatelabel__icmp6,
		    char *, "queue(1) failed to update options(2) on mp(3)",
		    queue_t *, wq, char *, opt_storage, mblk_t *, mp);
		icmp_ud_err(wq, mp, err);
		return (B_FALSE);
	}

	icmp->icmp_v6lastdst = *dst;
	return (B_TRUE);
}

/*
 * icmp_wput_ipv6():
 * Assumes that icmp_wput did some sanity checking on the destination
 * address, but that the label may not yet be correct.
 */
void
icmp_wput_ipv6(queue_t *q, mblk_t *mp, sin6_t *sin6, t_scalar_t tudr_optlen)
{
	ip6_t			*ip6h;
	ip6i_t			*ip6i;	/* mp1->b_rptr even if no ip6i_t */
	mblk_t			*mp1;
	int			ip_hdr_len = IPV6_HDR_LEN;
	size_t			ip_len;
	icmp_t			*icmp = Q_TO_ICMP(q);
	icmp_stack_t		*is = icmp->icmp_is;
	ip6_pkt_t		ipp_s;	/* For ancillary data options */
	ip6_pkt_t		*ipp = &ipp_s;
	ip6_pkt_t		*tipp;
	uint32_t		csum = 0;
	uint_t			ignore = 0;
	uint_t			option_exists = 0, is_sticky = 0;
	uint8_t			*cp;
	uint8_t			*nxthdr_ptr;
	in6_addr_t		ip6_dst;

	/*
	 * If the local address is a mapped address return
	 * an error.
	 * It would be possible to send an IPv6 packet but the
	 * response would never make it back to the application
	 * since it is bound to a mapped address.
	 */
	if (IN6_IS_ADDR_V4MAPPED(&icmp->icmp_v6src)) {
		BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
		icmp_ud_err(q, mp, EADDRNOTAVAIL);
		return;
	}

	ipp->ipp_fields = 0;
	ipp->ipp_sticky_ignored = 0;

	/*
	 * If TPI options passed in, feed it for verification and handling
	 */
	if (tudr_optlen != 0) {
		int error;

		if (icmp_unitdata_opt_process(q, mp, &error,
		    (void *)ipp) < 0) {
			/* failure */
			BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
			icmp_ud_err(q, mp, error);
			return;
		}
		ignore = ipp->ipp_sticky_ignored;
		ASSERT(error == 0);
	}

	if (sin6->sin6_scope_id != 0 &&
	    IN6_IS_ADDR_LINKSCOPE(&sin6->sin6_addr)) {
		/*
		 * IPPF_SCOPE_ID is special.  It's neither a sticky
		 * option nor ancillary data.  It needs to be
		 * explicitly set in options_exists.
		 */
		option_exists |= IPPF_SCOPE_ID;
	}

	/*
	 * Compute the destination address
	 */
	ip6_dst = sin6->sin6_addr;
	if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr))
		ip6_dst = ipv6_loopback;

	/*
	 * If we're not going to the same destination as last time, then
	 * recompute the label required.  This is done in a separate routine to
	 * avoid blowing up our stack here.
	 */
	if (is_system_labeled() &&
	    !IN6_ARE_ADDR_EQUAL(&icmp->icmp_v6lastdst, &ip6_dst) &&
	    !icmp_update_label_v6(q, icmp, mp, &ip6_dst)) {
		return;
	}

	/*
	 * If there's a security label here, then we ignore any options the
	 * user may try to set.  We keep the peer's label as a hidden sticky
	 * option.
	 */
	if (icmp->icmp_label_len_v6 > 0) {
		ignore &= ~IPPF_HOPOPTS;
		ipp->ipp_fields &= ~IPPF_HOPOPTS;
	}

	if ((icmp->icmp_sticky_ipp.ipp_fields == 0) &&
	    (ipp->ipp_fields == 0)) {
		/* No sticky options nor ancillary data. */
		goto no_options;
	}

	/*
	 * Go through the options figuring out where each is going to
	 * come from and build two masks.  The first mask indicates if
	 * the option exists at all.  The second mask indicates if the
	 * option is sticky or ancillary.
	 */
	if (!(ignore & IPPF_HOPOPTS)) {
		if (ipp->ipp_fields & IPPF_HOPOPTS) {
			option_exists |= IPPF_HOPOPTS;
			ip_hdr_len += ipp->ipp_hopoptslen;
		} else if (icmp->icmp_sticky_ipp.ipp_fields & IPPF_HOPOPTS) {
			option_exists |= IPPF_HOPOPTS;
			is_sticky |= IPPF_HOPOPTS;
			ip_hdr_len += icmp->icmp_sticky_ipp.ipp_hopoptslen;
		}
	}

	if (!(ignore & IPPF_RTHDR)) {
		if (ipp->ipp_fields & IPPF_RTHDR) {
			option_exists |= IPPF_RTHDR;
			ip_hdr_len += ipp->ipp_rthdrlen;
		} else if (icmp->icmp_sticky_ipp.ipp_fields & IPPF_RTHDR) {
			option_exists |= IPPF_RTHDR;
			is_sticky |= IPPF_RTHDR;
			ip_hdr_len += icmp->icmp_sticky_ipp.ipp_rthdrlen;
		}
	}

	if (!(ignore & IPPF_RTDSTOPTS) && (option_exists & IPPF_RTHDR)) {
		/*
		 * Need to have a router header to use these.
		 */
		if (ipp->ipp_fields & IPPF_RTDSTOPTS) {
			option_exists |= IPPF_RTDSTOPTS;
			ip_hdr_len += ipp->ipp_rtdstoptslen;
		} else if (icmp->icmp_sticky_ipp.ipp_fields & IPPF_RTDSTOPTS) {
			option_exists |= IPPF_RTDSTOPTS;
			is_sticky |= IPPF_RTDSTOPTS;
			ip_hdr_len +=
			    icmp->icmp_sticky_ipp.ipp_rtdstoptslen;
		}
	}

	if (!(ignore & IPPF_DSTOPTS)) {
		if (ipp->ipp_fields & IPPF_DSTOPTS) {
			option_exists |= IPPF_DSTOPTS;
			ip_hdr_len += ipp->ipp_dstoptslen;
		} else if (icmp->icmp_sticky_ipp.ipp_fields & IPPF_DSTOPTS) {
			option_exists |= IPPF_DSTOPTS;
			is_sticky |= IPPF_DSTOPTS;
			ip_hdr_len += icmp->icmp_sticky_ipp.ipp_dstoptslen;
		}
	}

	if (!(ignore & IPPF_IFINDEX)) {
		if (ipp->ipp_fields & IPPF_IFINDEX) {
			option_exists |= IPPF_IFINDEX;
		} else if (icmp->icmp_sticky_ipp.ipp_fields & IPPF_IFINDEX) {
			option_exists |= IPPF_IFINDEX;
			is_sticky |= IPPF_IFINDEX;
		}
	}

	if (!(ignore & IPPF_ADDR)) {
		if (ipp->ipp_fields & IPPF_ADDR) {
			option_exists |= IPPF_ADDR;
		} else if (icmp->icmp_sticky_ipp.ipp_fields & IPPF_ADDR) {
			option_exists |= IPPF_ADDR;
			is_sticky |= IPPF_ADDR;
		}
	}

	if (!(ignore & IPPF_DONTFRAG)) {
		if (ipp->ipp_fields & IPPF_DONTFRAG) {
			option_exists |= IPPF_DONTFRAG;
		} else if (icmp->icmp_sticky_ipp.ipp_fields & IPPF_DONTFRAG) {
			option_exists |= IPPF_DONTFRAG;
			is_sticky |= IPPF_DONTFRAG;
		}
	}

	if (!(ignore & IPPF_USE_MIN_MTU)) {
		if (ipp->ipp_fields & IPPF_USE_MIN_MTU) {
			option_exists |= IPPF_USE_MIN_MTU;
		} else if (icmp->icmp_sticky_ipp.ipp_fields &
		    IPPF_USE_MIN_MTU) {
			option_exists |= IPPF_USE_MIN_MTU;
			is_sticky |= IPPF_USE_MIN_MTU;
		}
	}

	if (!(ignore & IPPF_NEXTHOP)) {
		if (ipp->ipp_fields & IPPF_NEXTHOP) {
			option_exists |= IPPF_NEXTHOP;
		} else if (icmp->icmp_sticky_ipp.ipp_fields & IPPF_NEXTHOP) {
			option_exists |= IPPF_NEXTHOP;
			is_sticky |= IPPF_NEXTHOP;
		}
	}

	if (!(ignore & IPPF_HOPLIMIT) && (ipp->ipp_fields & IPPF_HOPLIMIT))
		option_exists |= IPPF_HOPLIMIT;
	/* IPV6_HOPLIMIT can never be sticky */
	ASSERT(!(icmp->icmp_sticky_ipp.ipp_fields & IPPF_HOPLIMIT));

	if (!(ignore & IPPF_UNICAST_HOPS) &&
	    (icmp->icmp_sticky_ipp.ipp_fields & IPPF_UNICAST_HOPS)) {
		option_exists |= IPPF_UNICAST_HOPS;
		is_sticky |= IPPF_UNICAST_HOPS;
	}

	if (!(ignore & IPPF_MULTICAST_HOPS) &&
	    (icmp->icmp_sticky_ipp.ipp_fields & IPPF_MULTICAST_HOPS)) {
		option_exists |= IPPF_MULTICAST_HOPS;
		is_sticky |= IPPF_MULTICAST_HOPS;
	}

	if (icmp->icmp_sticky_ipp.ipp_fields & IPPF_NO_CKSUM) {
		/* This is a sticky socket option only */
		option_exists |= IPPF_NO_CKSUM;
		is_sticky |= IPPF_NO_CKSUM;
	}

	if (icmp->icmp_sticky_ipp.ipp_fields & IPPF_RAW_CKSUM) {
		/* This is a sticky socket option only */
		option_exists |= IPPF_RAW_CKSUM;
		is_sticky |= IPPF_RAW_CKSUM;
	}

	if (!(ignore & IPPF_TCLASS)) {
		if (ipp->ipp_fields & IPPF_TCLASS) {
			option_exists |= IPPF_TCLASS;
		} else if (icmp->icmp_sticky_ipp.ipp_fields & IPPF_TCLASS) {
			option_exists |= IPPF_TCLASS;
			is_sticky |= IPPF_TCLASS;
		}
	}

no_options:

	/*
	 * If any options carried in the ip6i_t were specified, we
	 * need to account for the ip6i_t in the data we'll be sending
	 * down.
	 */
	if (option_exists & IPPF_HAS_IP6I)
		ip_hdr_len += sizeof (ip6i_t);

	/* check/fix buffer config, setup pointers into it */
	mp1 = mp->b_cont;
	ip6h = (ip6_t *)&mp1->b_rptr[-ip_hdr_len];
	if ((mp1->b_datap->db_ref != 1) ||
	    ((unsigned char *)ip6h < mp1->b_datap->db_base) ||
	    !OK_32PTR(ip6h)) {
		/* Try to get everything in a single mblk next time */
		if (ip_hdr_len > icmp->icmp_max_hdr_len) {
			icmp->icmp_max_hdr_len = ip_hdr_len;
			(void) mi_set_sth_wroff(RD(q),
			    icmp->icmp_max_hdr_len + is->is_wroff_extra);
		}
		mp1 = allocb(ip_hdr_len + is->is_wroff_extra, BPRI_LO);
		if (!mp1) {
			BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
			icmp_ud_err(q, mp, ENOMEM);
			return;
		}
		mp1->b_cont = mp->b_cont;
		mp1->b_wptr = mp1->b_datap->db_lim;
		ip6h = (ip6_t *)(mp1->b_wptr - ip_hdr_len);
	}
	mp1->b_rptr = (unsigned char *)ip6h;
	ip6i = (ip6i_t *)ip6h;

#define	ANCIL_OR_STICKY_PTR(f) ((is_sticky & f) ? &icmp->icmp_sticky_ipp : ipp)
	if (option_exists & IPPF_HAS_IP6I) {
		ip6h = (ip6_t *)&ip6i[1];
		ip6i->ip6i_flags = 0;
		ip6i->ip6i_vcf = IPV6_DEFAULT_VERS_AND_FLOW;

		/* sin6_scope_id takes precendence over IPPF_IFINDEX */
		if (option_exists & IPPF_SCOPE_ID) {
			ip6i->ip6i_flags |= IP6I_IFINDEX;
			ip6i->ip6i_ifindex = sin6->sin6_scope_id;
		} else if (option_exists & IPPF_IFINDEX) {
			tipp = ANCIL_OR_STICKY_PTR(IPPF_IFINDEX);
			ASSERT(tipp->ipp_ifindex != 0);
			ip6i->ip6i_flags |= IP6I_IFINDEX;
			ip6i->ip6i_ifindex = tipp->ipp_ifindex;
		}

		if (option_exists & IPPF_RAW_CKSUM) {
			ip6i->ip6i_flags |= IP6I_RAW_CHECKSUM;
			ip6i->ip6i_checksum_off = icmp->icmp_checksum_off;
		}

		if (option_exists & IPPF_NO_CKSUM) {
			ip6i->ip6i_flags |= IP6I_NO_ULP_CKSUM;
		}

		if (option_exists & IPPF_ADDR) {
			/*
			 * Enable per-packet source address verification if
			 * IPV6_PKTINFO specified the source address.
			 * ip6_src is set in the transport's _wput function.
			 */
			ip6i->ip6i_flags |= IP6I_VERIFY_SRC;
		}

		if (option_exists & IPPF_DONTFRAG) {
			ip6i->ip6i_flags |= IP6I_DONTFRAG;
		}

		if (option_exists & IPPF_USE_MIN_MTU) {
			ip6i->ip6i_flags = IP6I_API_USE_MIN_MTU(
			    ip6i->ip6i_flags, ipp->ipp_use_min_mtu);
		}

		if (option_exists & IPPF_NEXTHOP) {
			tipp = ANCIL_OR_STICKY_PTR(IPPF_NEXTHOP);
			ASSERT(!IN6_IS_ADDR_UNSPECIFIED(&tipp->ipp_nexthop));
			ip6i->ip6i_flags |= IP6I_NEXTHOP;
			ip6i->ip6i_nexthop = tipp->ipp_nexthop;
		}

		/*
		 * tell IP this is an ip6i_t private header
		 */
		ip6i->ip6i_nxt = IPPROTO_RAW;
	}

	/* Initialize IPv6 header */
	ip6h->ip6_vcf = IPV6_DEFAULT_VERS_AND_FLOW;
	bzero(&ip6h->ip6_src, sizeof (ip6h->ip6_src));

	/* Set the hoplimit of the outgoing packet. */
	if (option_exists & IPPF_HOPLIMIT) {
		/* IPV6_HOPLIMIT ancillary data overrides all other settings. */
		ip6h->ip6_hops = ipp->ipp_hoplimit;
		ip6i->ip6i_flags |= IP6I_HOPLIMIT;
	} else if (IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr)) {
		ip6h->ip6_hops = icmp->icmp_multicast_ttl;
		if (option_exists & IPPF_MULTICAST_HOPS)
			ip6i->ip6i_flags |= IP6I_HOPLIMIT;
	} else {
		ip6h->ip6_hops = icmp->icmp_ttl;
		if (option_exists & IPPF_UNICAST_HOPS)
			ip6i->ip6i_flags |= IP6I_HOPLIMIT;
	}

	if (option_exists & IPPF_ADDR) {
		tipp = ANCIL_OR_STICKY_PTR(IPPF_ADDR);
		ASSERT(!IN6_IS_ADDR_UNSPECIFIED(&tipp->ipp_addr));
		ip6h->ip6_src = tipp->ipp_addr;
	} else {
		/*
		 * The source address was not set using IPV6_PKTINFO.
		 * First look at the bound source.
		 * If unspecified fallback to __sin6_src_id.
		 */
		ip6h->ip6_src = icmp->icmp_v6src;
		if (sin6->__sin6_src_id != 0 &&
		    IN6_IS_ADDR_UNSPECIFIED(&ip6h->ip6_src)) {
			ip_srcid_find_id(sin6->__sin6_src_id,
			    &ip6h->ip6_src, icmp->icmp_zoneid,
			    is->is_netstack);
		}
	}

	nxthdr_ptr = (uint8_t *)&ip6h->ip6_nxt;
	cp = (uint8_t *)&ip6h[1];

	/*
	 * Here's where we have to start stringing together
	 * any extension headers in the right order:
	 * Hop-by-hop, destination, routing, and final destination opts.
	 */
	if (option_exists & IPPF_HOPOPTS) {
		/* Hop-by-hop options */
		ip6_hbh_t *hbh = (ip6_hbh_t *)cp;
		tipp = ANCIL_OR_STICKY_PTR(IPPF_HOPOPTS);

		*nxthdr_ptr = IPPROTO_HOPOPTS;
		nxthdr_ptr = &hbh->ip6h_nxt;

		bcopy(tipp->ipp_hopopts, cp, tipp->ipp_hopoptslen);
		cp += tipp->ipp_hopoptslen;
	}
	/*
	 * En-route destination options
	 * Only do them if there's a routing header as well
	 */
	if (option_exists & IPPF_RTDSTOPTS) {
		ip6_dest_t *dst = (ip6_dest_t *)cp;
		tipp = ANCIL_OR_STICKY_PTR(IPPF_RTDSTOPTS);

		*nxthdr_ptr = IPPROTO_DSTOPTS;
		nxthdr_ptr = &dst->ip6d_nxt;

		bcopy(tipp->ipp_rtdstopts, cp, tipp->ipp_rtdstoptslen);
		cp += tipp->ipp_rtdstoptslen;
	}
	/*
	 * Routing header next
	 */
	if (option_exists & IPPF_RTHDR) {
		ip6_rthdr_t *rt = (ip6_rthdr_t *)cp;
		tipp = ANCIL_OR_STICKY_PTR(IPPF_RTHDR);

		*nxthdr_ptr = IPPROTO_ROUTING;
		nxthdr_ptr = &rt->ip6r_nxt;

		bcopy(tipp->ipp_rthdr, cp, tipp->ipp_rthdrlen);
		cp += tipp->ipp_rthdrlen;
	}
	/*
	 * Do ultimate destination options
	 */
	if (option_exists & IPPF_DSTOPTS) {
		ip6_dest_t *dest = (ip6_dest_t *)cp;
		tipp = ANCIL_OR_STICKY_PTR(IPPF_DSTOPTS);

		*nxthdr_ptr = IPPROTO_DSTOPTS;
		nxthdr_ptr = &dest->ip6d_nxt;

		bcopy(tipp->ipp_dstopts, cp, tipp->ipp_dstoptslen);
		cp += tipp->ipp_dstoptslen;
	}

	/*
	 * Now set the last header pointer to the proto passed in
	 */
	ASSERT((int)(cp - (uint8_t *)ip6i) == ip_hdr_len);
	*nxthdr_ptr = icmp->icmp_proto;

	/*
	 * Copy in the destination address
	 */
	ip6h->ip6_dst = ip6_dst;

	ip6h->ip6_vcf =
	    (IPV6_DEFAULT_VERS_AND_FLOW & IPV6_VERS_AND_FLOW_MASK) |
	    (sin6->sin6_flowinfo & ~IPV6_VERS_AND_FLOW_MASK);

	if (option_exists & IPPF_TCLASS) {
		tipp = ANCIL_OR_STICKY_PTR(IPPF_TCLASS);
		ip6h->ip6_vcf = IPV6_TCLASS_FLOW(ip6h->ip6_vcf,
		    tipp->ipp_tclass);
	}
	if (option_exists & IPPF_RTHDR) {
		ip6_rthdr_t	*rth;

		/*
		 * Perform any processing needed for source routing.
		 * We know that all extension headers will be in the same mblk
		 * as the IPv6 header.
		 */
		rth = ip_find_rthdr_v6(ip6h, mp1->b_wptr);
		if (rth != NULL && rth->ip6r_segleft != 0) {
			if (rth->ip6r_type != IPV6_RTHDR_TYPE_0) {
				/*
				 * Drop packet - only support Type 0 routing.
				 * Notify the application as well.
				 */
				icmp_ud_err(q, mp, EPROTO);
				BUMP_MIB(&is->is_rawip_mib,
				    rawipOutErrors);
				return;
			}
			/*
			 * rth->ip6r_len is twice the number of
			 * addresses in the header
			 */
			if (rth->ip6r_len & 0x1) {
				icmp_ud_err(q, mp, EPROTO);
				BUMP_MIB(&is->is_rawip_mib,
				    rawipOutErrors);
				return;
			}
			/*
			 * Shuffle the routing header and ip6_dst
			 * addresses, and get the checksum difference
			 * between the first hop (in ip6_dst) and
			 * the destination (in the last routing hdr entry).
			 */
			csum = ip_massage_options_v6(ip6h, rth,
			    is->is_netstack);
			/*
			 * Verify that the first hop isn't a mapped address.
			 * Routers along the path need to do this verification
			 * for subsequent hops.
			 */
			if (IN6_IS_ADDR_V4MAPPED(&ip6h->ip6_dst)) {
				icmp_ud_err(q, mp, EADDRNOTAVAIL);
				BUMP_MIB(&is->is_rawip_mib,
				    rawipOutErrors);
				return;
			}
		}
	}

	ip_len = mp1->b_wptr - (uchar_t *)ip6h - IPV6_HDR_LEN;
	if (mp1->b_cont != NULL)
		ip_len += msgdsize(mp1->b_cont);

	/*
	 * Set the length into the IP header.
	 * If the length is greater than the maximum allowed by IP,
	 * then free the message and return. Do not try and send it
	 * as this can cause problems in layers below.
	 */
	if (ip_len > IP_MAXPACKET) {
		BUMP_MIB(&is->is_rawip_mib, rawipOutErrors);
		icmp_ud_err(q, mp, EMSGSIZE);
		return;
	}
	if (icmp->icmp_proto == IPPROTO_ICMPV6 || icmp->icmp_raw_checksum) {
		uint_t	cksum_off;	/* From ip6i == mp1->b_rptr */
		uint16_t *cksum_ptr;
		uint_t	ext_hdrs_len;

		/* ICMPv6 must have an offset matching icmp6_cksum offset */
		ASSERT(icmp->icmp_proto != IPPROTO_ICMPV6 ||
		    icmp->icmp_checksum_off == 2);

		/*
		 * We make it easy for IP to include our pseudo header
		 * by putting our length in uh_checksum, modified (if
		 * we have a routing header) by the checksum difference
		 * between the ultimate destination and first hop addresses.
		 * Note: ICMPv6 must always checksum the packet.
		 */
		cksum_off = ip_hdr_len + icmp->icmp_checksum_off;
		if (cksum_off + sizeof (uint16_t) > mp1->b_wptr - mp1->b_rptr) {
			if (!pullupmsg(mp1, cksum_off + sizeof (uint16_t))) {
				BUMP_MIB(&is->is_rawip_mib,
				    rawipOutErrors);
				freemsg(mp);
				return;
			}
			ip6i = (ip6i_t *)mp1->b_rptr;
			if (ip6i->ip6i_nxt == IPPROTO_RAW)
				ip6h = (ip6_t *)&ip6i[1];
			else
				ip6h = (ip6_t *)ip6i;
		}
		/* Add payload length to checksum */
		ext_hdrs_len = ip_hdr_len - IPV6_HDR_LEN -
		    (int)((uchar_t *)ip6h - (uchar_t *)ip6i);
		csum += htons(ip_len - ext_hdrs_len);

		cksum_ptr = (uint16_t *)((uchar_t *)ip6i + cksum_off);
		csum = (csum & 0xFFFF) + (csum >> 16);
		*cksum_ptr = (uint16_t)csum;
	}

#ifdef _LITTLE_ENDIAN
	ip_len = htons(ip_len);
#endif
	ip6h->ip6_plen = (uint16_t)ip_len;

	freeb(mp);

	/* We're done. Pass the packet to IP */
	BUMP_MIB(&is->is_rawip_mib, rawipOutDatagrams);
	ip_output_v6(icmp->icmp_connp, mp1, q, IP_WPUT);
}

static void
icmp_wput_other(queue_t *q, mblk_t *mp)
{
	uchar_t	*rptr = mp->b_rptr;
	struct iocblk *iocp;
#define	tudr ((struct T_unitdata_req *)rptr)
	conn_t	*connp = Q_TO_CONN(q);
	icmp_t	*icmp = connp->conn_icmp;
	icmp_stack_t *is = icmp->icmp_is;
	cred_t *cr;

	cr = DB_CREDDEF(mp, connp->conn_cred);

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
		switch (((union T_primitives *)rptr)->type) {
		case T_ADDR_REQ:
			icmp_addr_req(q, mp);
			return;
		case O_T_BIND_REQ:
		case T_BIND_REQ:
			icmp_bind(q, mp);
			return;
		case T_CONN_REQ:
			icmp_connect(q, mp);
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
			 * be bad.  Valid T_UNITDATA_REQs are found above
			 * and break to below this switch.
			 */
			icmp_ud_err(q, mp, EADDRNOTAVAIL);
			return;
		case T_UNBIND_REQ:
			icmp_unbind(q, mp);
			return;

		case T_SVR4_OPTMGMT_REQ:
			if (!snmpcom_req(q, mp, icmp_snmp_set, ip_snmp_get,
			    cr)) {
				/* Only IP can return anything meaningful */
				(void) svr4_optcom_req(q, mp, cr,
				    &icmp_opt_obj, B_TRUE);
			}
			return;

		case T_OPTMGMT_REQ:
			/* Only IP can return anything meaningful */
			(void) tpi_optcom_req(q, mp, cr, &icmp_opt_obj, B_TRUE);
			return;

		case T_DISCON_REQ:
			icmp_disconnect(q, mp);
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
			freemsg(mp);
			(void) putctl1(RD(q), M_ERROR, EPROTO);
			return;
		default:
			break;
		}
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
		err_ret:;
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
		case ND_SET:
			/* nd_getset performs the necessary error checking */
		case ND_GET:
			if (nd_getset(q, is->is_nd, mp)) {
				qreply(q, mp);
				return;
			}
			break;
		default:
			break;
		}
		break;
	case M_IOCDATA:
		icmp_wput_iocdata(q, mp);
		return;
	default:
		break;
	}
	ip_wput(q, mp);
}

/*
 * icmp_wput_iocdata is called by icmp_wput_slow to handle all M_IOCDATA
 * messages.
 */
static void
icmp_wput_iocdata(queue_t *q, mblk_t *mp)
{
	mblk_t	*mp1;
	STRUCT_HANDLE(strbuf, sb);
	icmp_t	*icmp;
	in6_addr_t	v6addr;
	ipaddr_t	v4addr;
	uint32_t	flowinfo = 0;
	int		addrlen;

	/* Make sure it is one of ours. */
	switch (((struct iocblk *)mp->b_rptr)->ioc_cmd) {
	case TI_GETMYNAME:
	case TI_GETPEERNAME:
		break;
	default:
		icmp = Q_TO_ICMP(q);
		ip_output(icmp->icmp_connp, mp, q, IP_WPUT);
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
	icmp = Q_TO_ICMP(q);
	if (icmp->icmp_family == AF_INET)
		addrlen = sizeof (sin_t);
	else
		addrlen = sizeof (sin6_t);

	if (STRUCT_FGET(sb, maxlen) < addrlen) {
		mi_copy_done(q, mp, EINVAL);
		return;
	}
	switch (((struct iocblk *)mp->b_rptr)->ioc_cmd) {
	case TI_GETMYNAME:
		if (icmp->icmp_family == AF_INET) {
			ASSERT(icmp->icmp_ipversion == IPV4_VERSION);
			if (!IN6_IS_ADDR_V4MAPPED_ANY(&icmp->icmp_v6src) &&
			    !IN6_IS_ADDR_UNSPECIFIED(&icmp->icmp_v6src)) {
				v4addr = V4_PART_OF_V6(icmp->icmp_v6src);
			} else {
				/*
				 * INADDR_ANY
				 * icmp_v6src is not set, we might be bound to
				 * broadcast/multicast. Use icmp_bound_v6src as
				 * local address instead (that could
				 * also still be INADDR_ANY)
				 */
				v4addr = V4_PART_OF_V6(icmp->icmp_bound_v6src);
			}
		} else {
			/* icmp->icmp_family == AF_INET6 */
			if (!IN6_IS_ADDR_UNSPECIFIED(&icmp->icmp_v6src)) {
				v6addr = icmp->icmp_v6src;
			} else {
				/*
				 * UNSPECIFIED
				 * icmp_v6src is not set, we might be bound to
				 * broadcast/multicast. Use icmp_bound_v6src as
				 * local address instead (that could
				 * also still be UNSPECIFIED)
				 */
				v6addr = icmp->icmp_bound_v6src;
			}
		}
		break;
	case TI_GETPEERNAME:
		if (icmp->icmp_family == AF_INET) {
			ASSERT(icmp->icmp_ipversion == IPV4_VERSION);
			v4addr = V4_PART_OF_V6(icmp->icmp_v6dst);
		} else {
			/* icmp->icmp_family == AF_INET6) */
			v6addr = icmp->icmp_v6dst;
			flowinfo = icmp->icmp_flowinfo;
		}
		break;
	default:
		mi_copy_done(q, mp, EPROTO);
		return;
	}
	mp1 = mi_copyout_alloc(q, mp, STRUCT_FGETP(sb, buf), addrlen, B_TRUE);
	if (!mp1)
		return;

	if (icmp->icmp_family == AF_INET) {
		sin_t *sin;

		STRUCT_FSET(sb, len, (int)sizeof (sin_t));
		sin = (sin_t *)mp1->b_rptr;
		mp1->b_wptr = (uchar_t *)&sin[1];
		*sin = sin_null;
		sin->sin_family = AF_INET;
		sin->sin_addr.s_addr = v4addr;
	} else {
		/* icmp->icmp_family == AF_INET6 */
		sin6_t *sin6;

		ASSERT(icmp->icmp_family == AF_INET6);
		STRUCT_FSET(sb, len, (int)sizeof (sin6_t));
		sin6 = (sin6_t *)mp1->b_rptr;
		mp1->b_wptr = (uchar_t *)&sin6[1];
		*sin6 = sin6_null;
		sin6->sin6_family = AF_INET6;
		sin6->sin6_flowinfo = flowinfo;
		sin6->sin6_addr = v6addr;
	}
	/* Copy out the address */
	mi_copyout(q, mp);
}

static int
icmp_unitdata_opt_process(queue_t *q, mblk_t *mp, int *errorp,
    void *thisdg_attrs)
{
	conn_t	*connp = Q_TO_CONN(q);
	struct T_unitdata_req *udreqp;
	int is_absreq_failure;
	cred_t *cr;

	udreqp = (struct T_unitdata_req *)mp->b_rptr;
	*errorp = 0;

	cr = DB_CREDDEF(mp, connp->conn_cred);

	*errorp = tpi_optcom_buf(q, mp, &udreqp->OPT_length,
	    udreqp->OPT_offset, cr, &icmp_opt_obj,
	    thisdg_attrs, &is_absreq_failure);

	if (*errorp != 0) {
		/*
		 * Note: No special action needed in this
		 * module for "is_absreq_failure"
		 */
		return (-1);		/* failure */
	}
	ASSERT(is_absreq_failure == 0);
	return (0);	/* success */
}

void
icmp_ddi_init(void)
{
	icmp_max_optsize =
	    optcom_max_optsize(icmp_opt_obj.odb_opt_des_arr,
	    icmp_opt_obj.odb_opt_arr_cnt);

	/*
	 * We want to be informed each time a stack is created or
	 * destroyed in the kernel, so we can maintain the
	 * set of icmp_stack_t's.
	 */
	netstack_register(NS_ICMP, rawip_stack_init, NULL, rawip_stack_fini);
}

void
icmp_ddi_destroy(void)
{
	netstack_unregister(NS_ICMP);
}

/*
 * Initialize the ICMP stack instance.
 */
static void *
rawip_stack_init(netstackid_t stackid, netstack_t *ns)
{
	icmp_stack_t	*is;
	icmpparam_t	*pa;

	is = (icmp_stack_t *)kmem_zalloc(sizeof (*is), KM_SLEEP);
	is->is_netstack = ns;

	pa = (icmpparam_t *)kmem_alloc(sizeof (icmp_param_arr), KM_SLEEP);
	is->is_param_arr = pa;
	bcopy(icmp_param_arr, is->is_param_arr, sizeof (icmp_param_arr));

	(void) icmp_param_register(&is->is_nd,
	    is->is_param_arr, A_CNT(icmp_param_arr));
	is->is_ksp = rawip_kstat_init(stackid);
	return (is);
}

/*
 * Free the ICMP stack instance.
 */
static void
rawip_stack_fini(netstackid_t stackid, void *arg)
{
	icmp_stack_t *is = (icmp_stack_t *)arg;

	nd_free(&is->is_nd);
	kmem_free(is->is_param_arr, sizeof (icmp_param_arr));
	is->is_param_arr = NULL;

	rawip_kstat_fini(stackid, is->is_ksp);
	is->is_ksp = NULL;
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
