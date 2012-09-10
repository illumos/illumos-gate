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
 * Copyright (c) 2011, Joyent Inc. All rights reserved.
 */

#include <sys/types.h>
#include <sys/tihdr.h>
#include <sys/policy.h>
#include <sys/tsol/tnet.h>
#include <sys/kstat.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/tcp.h>
#include <inet/tcp_impl.h>
#include <inet/tcp_stats.h>
#include <inet/kstatcom.h>
#include <inet/snmpcom.h>

static int	tcp_kstat_update(kstat_t *, int);
static int	tcp_kstat2_update(kstat_t *, int);
static void	tcp_sum_mib(tcp_stack_t *, mib2_tcp_t *);

static void	tcp_add_mib(mib2_tcp_t *, mib2_tcp_t *);
static void	tcp_add_stats(tcp_stat_counter_t *, tcp_stat_t *);
static void	tcp_clr_stats(tcp_stat_t *);

tcp_g_stat_t	tcp_g_statistics;
kstat_t		*tcp_g_kstat;

/* Translate TCP state to MIB2 TCP state. */
static int
tcp_snmp_state(tcp_t *tcp)
{
	if (tcp == NULL)
		return (0);

	switch (tcp->tcp_state) {
	case TCPS_CLOSED:
	case TCPS_IDLE:	/* RFC1213 doesn't have analogue for IDLE & BOUND */
	case TCPS_BOUND:
		return (MIB2_TCP_closed);
	case TCPS_LISTEN:
		return (MIB2_TCP_listen);
	case TCPS_SYN_SENT:
		return (MIB2_TCP_synSent);
	case TCPS_SYN_RCVD:
		return (MIB2_TCP_synReceived);
	case TCPS_ESTABLISHED:
		return (MIB2_TCP_established);
	case TCPS_CLOSE_WAIT:
		return (MIB2_TCP_closeWait);
	case TCPS_FIN_WAIT_1:
		return (MIB2_TCP_finWait1);
	case TCPS_CLOSING:
		return (MIB2_TCP_closing);
	case TCPS_LAST_ACK:
		return (MIB2_TCP_lastAck);
	case TCPS_FIN_WAIT_2:
		return (MIB2_TCP_finWait2);
	case TCPS_TIME_WAIT:
		return (MIB2_TCP_timeWait);
	default:
		return (0);
	}
}

/*
 * Return SNMP stuff in buffer in mpdata.
 */
mblk_t *
tcp_snmp_get(queue_t *q, mblk_t *mpctl, boolean_t legacy_req)
{
	mblk_t			*mpdata;
	mblk_t			*mp_conn_ctl = NULL;
	mblk_t			*mp_conn_tail;
	mblk_t			*mp_attr_ctl = NULL;
	mblk_t			*mp_attr_tail;
	mblk_t			*mp6_conn_ctl = NULL;
	mblk_t			*mp6_conn_tail;
	mblk_t			*mp6_attr_ctl = NULL;
	mblk_t			*mp6_attr_tail;
	struct opthdr		*optp;
	mib2_tcpConnEntry_t	tce;
	mib2_tcp6ConnEntry_t	tce6;
	mib2_transportMLPEntry_t mlp;
	connf_t			*connfp;
	int			i;
	boolean_t 		ispriv;
	zoneid_t 		zoneid;
	int			v4_conn_idx;
	int			v6_conn_idx;
	conn_t			*connp = Q_TO_CONN(q);
	tcp_stack_t		*tcps;
	ip_stack_t		*ipst;
	mblk_t			*mp2ctl;
	mib2_tcp_t		tcp_mib;
	size_t			tcp_mib_size, tce_size, tce6_size;

	/*
	 * make a copy of the original message
	 */
	mp2ctl = copymsg(mpctl);

	if (mpctl == NULL ||
	    (mpdata = mpctl->b_cont) == NULL ||
	    (mp_conn_ctl = copymsg(mpctl)) == NULL ||
	    (mp_attr_ctl = copymsg(mpctl)) == NULL ||
	    (mp6_conn_ctl = copymsg(mpctl)) == NULL ||
	    (mp6_attr_ctl = copymsg(mpctl)) == NULL) {
		freemsg(mp_conn_ctl);
		freemsg(mp_attr_ctl);
		freemsg(mp6_conn_ctl);
		freemsg(mp6_attr_ctl);
		freemsg(mpctl);
		freemsg(mp2ctl);
		return (NULL);
	}

	ipst = connp->conn_netstack->netstack_ip;
	tcps = connp->conn_netstack->netstack_tcp;

	if (legacy_req) {
		tcp_mib_size = LEGACY_MIB_SIZE(&tcp_mib, mib2_tcp_t);
		tce_size = LEGACY_MIB_SIZE(&tce, mib2_tcpConnEntry_t);
		tce6_size = LEGACY_MIB_SIZE(&tce6, mib2_tcp6ConnEntry_t);
	} else {
		tcp_mib_size = sizeof (mib2_tcp_t);
		tce_size = sizeof (mib2_tcpConnEntry_t);
		tce6_size = sizeof (mib2_tcp6ConnEntry_t);
	}

	bzero(&tcp_mib, sizeof (tcp_mib));

	/* build table of connections -- need count in fixed part */
	SET_MIB(tcp_mib.tcpRtoAlgorithm, 4);   /* vanj */
	SET_MIB(tcp_mib.tcpRtoMin, tcps->tcps_rexmit_interval_min);
	SET_MIB(tcp_mib.tcpRtoMax, tcps->tcps_rexmit_interval_max);
	SET_MIB(tcp_mib.tcpMaxConn, -1);
	SET_MIB(tcp_mib.tcpCurrEstab, 0);

	ispriv =
	    secpolicy_ip_config((Q_TO_CONN(q))->conn_cred, B_TRUE) == 0;
	zoneid = Q_TO_CONN(q)->conn_zoneid;

	v4_conn_idx = v6_conn_idx = 0;
	mp_conn_tail = mp_attr_tail = mp6_conn_tail = mp6_attr_tail = NULL;

	for (i = 0; i < CONN_G_HASH_SIZE; i++) {
		ipst = tcps->tcps_netstack->netstack_ip;

		connfp = &ipst->ips_ipcl_globalhash_fanout[i];

		connp = NULL;

		while ((connp =
		    ipcl_get_next_conn(connfp, connp, IPCL_TCPCONN)) != NULL) {
			tcp_t *tcp;
			boolean_t needattr;

			if (connp->conn_zoneid != zoneid)
				continue;	/* not in this zone */

			tcp = connp->conn_tcp;
			TCPS_UPDATE_MIB(tcps, tcpHCInSegs, tcp->tcp_ibsegs);
			tcp->tcp_ibsegs = 0;
			TCPS_UPDATE_MIB(tcps, tcpHCOutSegs, tcp->tcp_obsegs);
			tcp->tcp_obsegs = 0;

			tce6.tcp6ConnState = tce.tcpConnState =
			    tcp_snmp_state(tcp);
			if (tce.tcpConnState == MIB2_TCP_established ||
			    tce.tcpConnState == MIB2_TCP_closeWait)
				BUMP_MIB(&tcp_mib, tcpCurrEstab);

			needattr = B_FALSE;
			bzero(&mlp, sizeof (mlp));
			if (connp->conn_mlp_type != mlptSingle) {
				if (connp->conn_mlp_type == mlptShared ||
				    connp->conn_mlp_type == mlptBoth)
					mlp.tme_flags |= MIB2_TMEF_SHARED;
				if (connp->conn_mlp_type == mlptPrivate ||
				    connp->conn_mlp_type == mlptBoth)
					mlp.tme_flags |= MIB2_TMEF_PRIVATE;
				needattr = B_TRUE;
			}
			if (connp->conn_anon_mlp) {
				mlp.tme_flags |= MIB2_TMEF_ANONMLP;
				needattr = B_TRUE;
			}
			switch (connp->conn_mac_mode) {
			case CONN_MAC_DEFAULT:
				break;
			case CONN_MAC_AWARE:
				mlp.tme_flags |= MIB2_TMEF_MACEXEMPT;
				needattr = B_TRUE;
				break;
			case CONN_MAC_IMPLICIT:
				mlp.tme_flags |= MIB2_TMEF_MACIMPLICIT;
				needattr = B_TRUE;
				break;
			}
			if (connp->conn_ixa->ixa_tsl != NULL) {
				ts_label_t *tsl;

				tsl = connp->conn_ixa->ixa_tsl;
				mlp.tme_flags |= MIB2_TMEF_IS_LABELED;
				mlp.tme_doi = label2doi(tsl);
				mlp.tme_label = *label2bslabel(tsl);
				needattr = B_TRUE;
			}

			/* Create a message to report on IPv6 entries */
			if (connp->conn_ipversion == IPV6_VERSION) {
			tce6.tcp6ConnLocalAddress = connp->conn_laddr_v6;
			tce6.tcp6ConnRemAddress = connp->conn_faddr_v6;
			tce6.tcp6ConnLocalPort = ntohs(connp->conn_lport);
			tce6.tcp6ConnRemPort = ntohs(connp->conn_fport);
			if (connp->conn_ixa->ixa_flags & IXAF_SCOPEID_SET) {
				tce6.tcp6ConnIfIndex =
				    connp->conn_ixa->ixa_scopeid;
			} else {
				tce6.tcp6ConnIfIndex = connp->conn_bound_if;
			}
			/* Don't want just anybody seeing these... */
			if (ispriv) {
				tce6.tcp6ConnEntryInfo.ce_snxt =
				    tcp->tcp_snxt;
				tce6.tcp6ConnEntryInfo.ce_suna =
				    tcp->tcp_suna;
				tce6.tcp6ConnEntryInfo.ce_rnxt =
				    tcp->tcp_rnxt;
				tce6.tcp6ConnEntryInfo.ce_rack =
				    tcp->tcp_rack;
			} else {
				/*
				 * Netstat, unfortunately, uses this to
				 * get send/receive queue sizes.  How to fix?
				 * Why not compute the difference only?
				 */
				tce6.tcp6ConnEntryInfo.ce_snxt =
				    tcp->tcp_snxt - tcp->tcp_suna;
				tce6.tcp6ConnEntryInfo.ce_suna = 0;
				tce6.tcp6ConnEntryInfo.ce_rnxt =
				    tcp->tcp_rnxt - tcp->tcp_rack;
				tce6.tcp6ConnEntryInfo.ce_rack = 0;
			}

			tce6.tcp6ConnEntryInfo.ce_swnd = tcp->tcp_swnd;
			tce6.tcp6ConnEntryInfo.ce_rwnd = tcp->tcp_rwnd;
			tce6.tcp6ConnEntryInfo.ce_rto =  tcp->tcp_rto;
			tce6.tcp6ConnEntryInfo.ce_mss =  tcp->tcp_mss;
			tce6.tcp6ConnEntryInfo.ce_state = tcp->tcp_state;

			tce6.tcp6ConnCreationProcess =
			    (connp->conn_cpid < 0) ? MIB2_UNKNOWN_PROCESS :
			    connp->conn_cpid;
			tce6.tcp6ConnCreationTime = connp->conn_open_time;

			(void) snmp_append_data2(mp6_conn_ctl->b_cont,
			    &mp6_conn_tail, (char *)&tce6, tce6_size);

			mlp.tme_connidx = v6_conn_idx++;
			if (needattr)
				(void) snmp_append_data2(mp6_attr_ctl->b_cont,
				    &mp6_attr_tail, (char *)&mlp, sizeof (mlp));
			}
			/*
			 * Create an IPv4 table entry for IPv4 entries and also
			 * for IPv6 entries which are bound to in6addr_any
			 * but don't have IPV6_V6ONLY set.
			 * (i.e. anything an IPv4 peer could connect to)
			 */
			if (connp->conn_ipversion == IPV4_VERSION ||
			    (tcp->tcp_state <= TCPS_LISTEN &&
			    !connp->conn_ipv6_v6only &&
			    IN6_IS_ADDR_UNSPECIFIED(&connp->conn_laddr_v6))) {
				if (connp->conn_ipversion == IPV6_VERSION) {
					tce.tcpConnRemAddress = INADDR_ANY;
					tce.tcpConnLocalAddress = INADDR_ANY;
				} else {
					tce.tcpConnRemAddress =
					    connp->conn_faddr_v4;
					tce.tcpConnLocalAddress =
					    connp->conn_laddr_v4;
				}
				tce.tcpConnLocalPort = ntohs(connp->conn_lport);
				tce.tcpConnRemPort = ntohs(connp->conn_fport);
				/* Don't want just anybody seeing these... */
				if (ispriv) {
					tce.tcpConnEntryInfo.ce_snxt =
					    tcp->tcp_snxt;
					tce.tcpConnEntryInfo.ce_suna =
					    tcp->tcp_suna;
					tce.tcpConnEntryInfo.ce_rnxt =
					    tcp->tcp_rnxt;
					tce.tcpConnEntryInfo.ce_rack =
					    tcp->tcp_rack;
				} else {
					/*
					 * Netstat, unfortunately, uses this to
					 * get send/receive queue sizes.  How
					 * to fix?
					 * Why not compute the difference only?
					 */
					tce.tcpConnEntryInfo.ce_snxt =
					    tcp->tcp_snxt - tcp->tcp_suna;
					tce.tcpConnEntryInfo.ce_suna = 0;
					tce.tcpConnEntryInfo.ce_rnxt =
					    tcp->tcp_rnxt - tcp->tcp_rack;
					tce.tcpConnEntryInfo.ce_rack = 0;
				}

				tce.tcpConnEntryInfo.ce_swnd = tcp->tcp_swnd;
				tce.tcpConnEntryInfo.ce_rwnd = tcp->tcp_rwnd;
				tce.tcpConnEntryInfo.ce_rto =  tcp->tcp_rto;
				tce.tcpConnEntryInfo.ce_mss =  tcp->tcp_mss;
				tce.tcpConnEntryInfo.ce_state =
				    tcp->tcp_state;

				tce.tcpConnCreationProcess =
				    (connp->conn_cpid < 0) ?
				    MIB2_UNKNOWN_PROCESS :
				    connp->conn_cpid;
				tce.tcpConnCreationTime = connp->conn_open_time;

				(void) snmp_append_data2(mp_conn_ctl->b_cont,
				    &mp_conn_tail, (char *)&tce, tce_size);

				mlp.tme_connidx = v4_conn_idx++;
				if (needattr)
					(void) snmp_append_data2(
					    mp_attr_ctl->b_cont,
					    &mp_attr_tail, (char *)&mlp,
					    sizeof (mlp));
			}
		}
	}

	tcp_sum_mib(tcps, &tcp_mib);

	/* Fixed length structure for IPv4 and IPv6 counters */
	SET_MIB(tcp_mib.tcpConnTableSize, tce_size);
	SET_MIB(tcp_mib.tcp6ConnTableSize, tce6_size);

	/*
	 * Synchronize 32- and 64-bit counters.  Note that tcpInSegs and
	 * tcpOutSegs are not updated anywhere in TCP.  The new 64 bits
	 * counters are used.  Hence the old counters' values in tcp_sc_mib
	 * are always 0.
	 */
	SYNC32_MIB(&tcp_mib, tcpInSegs, tcpHCInSegs);
	SYNC32_MIB(&tcp_mib, tcpOutSegs, tcpHCOutSegs);

	optp = (struct opthdr *)&mpctl->b_rptr[sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_TCP;
	optp->name = 0;
	(void) snmp_append_data(mpdata, (char *)&tcp_mib, tcp_mib_size);
	optp->len = msgdsize(mpdata);
	qreply(q, mpctl);

	/* table of connections... */
	optp = (struct opthdr *)&mp_conn_ctl->b_rptr[
	    sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_TCP;
	optp->name = MIB2_TCP_CONN;
	optp->len = msgdsize(mp_conn_ctl->b_cont);
	qreply(q, mp_conn_ctl);

	/* table of MLP attributes... */
	optp = (struct opthdr *)&mp_attr_ctl->b_rptr[
	    sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_TCP;
	optp->name = EXPER_XPORT_MLP;
	optp->len = msgdsize(mp_attr_ctl->b_cont);
	if (optp->len == 0)
		freemsg(mp_attr_ctl);
	else
		qreply(q, mp_attr_ctl);

	/* table of IPv6 connections... */
	optp = (struct opthdr *)&mp6_conn_ctl->b_rptr[
	    sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_TCP6;
	optp->name = MIB2_TCP6_CONN;
	optp->len = msgdsize(mp6_conn_ctl->b_cont);
	qreply(q, mp6_conn_ctl);

	/* table of IPv6 MLP attributes... */
	optp = (struct opthdr *)&mp6_attr_ctl->b_rptr[
	    sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_TCP6;
	optp->name = EXPER_XPORT_MLP;
	optp->len = msgdsize(mp6_attr_ctl->b_cont);
	if (optp->len == 0)
		freemsg(mp6_attr_ctl);
	else
		qreply(q, mp6_attr_ctl);
	return (mp2ctl);
}

/* Return 0 if invalid set request, 1 otherwise, including non-tcp requests  */
/* ARGSUSED */
int
tcp_snmp_set(queue_t *q, int level, int name, uchar_t *ptr, int len)
{
	mib2_tcpConnEntry_t	*tce = (mib2_tcpConnEntry_t *)ptr;

	switch (level) {
	case MIB2_TCP:
		switch (name) {
		case 13:
			if (tce->tcpConnState != MIB2_TCP_deleteTCB)
				return (0);
			/* TODO: delete entry defined by tce */
			return (1);
		default:
			return (0);
		}
	default:
		return (1);
	}
}

/*
 * TCP Kstats implementation
 */
void *
tcp_kstat_init(netstackid_t stackid)
{
	kstat_t	*ksp;

	tcp_named_kstat_t template = {
		{ "rtoAlgorithm",	KSTAT_DATA_INT32, 0 },
		{ "rtoMin",		KSTAT_DATA_INT32, 0 },
		{ "rtoMax",		KSTAT_DATA_INT32, 0 },
		{ "maxConn",		KSTAT_DATA_INT32, 0 },
		{ "activeOpens",	KSTAT_DATA_UINT32, 0 },
		{ "passiveOpens",	KSTAT_DATA_UINT32, 0 },
		{ "attemptFails",	KSTAT_DATA_UINT32, 0 },
		{ "estabResets",	KSTAT_DATA_UINT32, 0 },
		{ "currEstab",		KSTAT_DATA_UINT32, 0 },
		{ "inSegs",		KSTAT_DATA_UINT64, 0 },
		{ "outSegs",		KSTAT_DATA_UINT64, 0 },
		{ "retransSegs",	KSTAT_DATA_UINT32, 0 },
		{ "connTableSize",	KSTAT_DATA_INT32, 0 },
		{ "outRsts",		KSTAT_DATA_UINT32, 0 },
		{ "outDataSegs",	KSTAT_DATA_UINT32, 0 },
		{ "outDataBytes",	KSTAT_DATA_UINT32, 0 },
		{ "retransBytes",	KSTAT_DATA_UINT32, 0 },
		{ "outAck",		KSTAT_DATA_UINT32, 0 },
		{ "outAckDelayed",	KSTAT_DATA_UINT32, 0 },
		{ "outUrg",		KSTAT_DATA_UINT32, 0 },
		{ "outWinUpdate",	KSTAT_DATA_UINT32, 0 },
		{ "outWinProbe",	KSTAT_DATA_UINT32, 0 },
		{ "outControl",		KSTAT_DATA_UINT32, 0 },
		{ "outFastRetrans",	KSTAT_DATA_UINT32, 0 },
		{ "inAckSegs",		KSTAT_DATA_UINT32, 0 },
		{ "inAckBytes",		KSTAT_DATA_UINT32, 0 },
		{ "inDupAck",		KSTAT_DATA_UINT32, 0 },
		{ "inAckUnsent",	KSTAT_DATA_UINT32, 0 },
		{ "inDataInorderSegs",	KSTAT_DATA_UINT32, 0 },
		{ "inDataInorderBytes",	KSTAT_DATA_UINT32, 0 },
		{ "inDataUnorderSegs",	KSTAT_DATA_UINT32, 0 },
		{ "inDataUnorderBytes",	KSTAT_DATA_UINT32, 0 },
		{ "inDataDupSegs",	KSTAT_DATA_UINT32, 0 },
		{ "inDataDupBytes",	KSTAT_DATA_UINT32, 0 },
		{ "inDataPartDupSegs",	KSTAT_DATA_UINT32, 0 },
		{ "inDataPartDupBytes",	KSTAT_DATA_UINT32, 0 },
		{ "inDataPastWinSegs",	KSTAT_DATA_UINT32, 0 },
		{ "inDataPastWinBytes",	KSTAT_DATA_UINT32, 0 },
		{ "inWinProbe",		KSTAT_DATA_UINT32, 0 },
		{ "inWinUpdate",	KSTAT_DATA_UINT32, 0 },
		{ "inClosed",		KSTAT_DATA_UINT32, 0 },
		{ "rttUpdate",		KSTAT_DATA_UINT32, 0 },
		{ "rttNoUpdate",	KSTAT_DATA_UINT32, 0 },
		{ "timRetrans",		KSTAT_DATA_UINT32, 0 },
		{ "timRetransDrop",	KSTAT_DATA_UINT32, 0 },
		{ "timKeepalive",	KSTAT_DATA_UINT32, 0 },
		{ "timKeepaliveProbe",	KSTAT_DATA_UINT32, 0 },
		{ "timKeepaliveDrop",	KSTAT_DATA_UINT32, 0 },
		{ "listenDrop",		KSTAT_DATA_UINT32, 0 },
		{ "listenDropQ0",	KSTAT_DATA_UINT32, 0 },
		{ "halfOpenDrop",	KSTAT_DATA_UINT32, 0 },
		{ "outSackRetransSegs",	KSTAT_DATA_UINT32, 0 },
		{ "connTableSize6",	KSTAT_DATA_INT32, 0 }
	};

	ksp = kstat_create_netstack(TCP_MOD_NAME, stackid, TCP_MOD_NAME, "mib2",
	    KSTAT_TYPE_NAMED, NUM_OF_FIELDS(tcp_named_kstat_t), 0, stackid);

	if (ksp == NULL)
		return (NULL);

	template.rtoAlgorithm.value.ui32 = 4;
	template.maxConn.value.i32 = -1;

	bcopy(&template, ksp->ks_data, sizeof (template));
	ksp->ks_update = tcp_kstat_update;
	ksp->ks_private = (void *)(uintptr_t)stackid;

	/*
	 * If this is an exclusive netstack for a local zone, the global zone
	 * should still be able to read the kstat.
	 */
	if (stackid != GLOBAL_NETSTACKID)
		kstat_zone_add(ksp, GLOBAL_ZONEID);

	kstat_install(ksp);
	return (ksp);
}

void
tcp_kstat_fini(netstackid_t stackid, kstat_t *ksp)
{
	if (ksp != NULL) {
		ASSERT(stackid == (netstackid_t)(uintptr_t)ksp->ks_private);
		kstat_delete_netstack(ksp, stackid);
	}
}

static int
tcp_kstat_update(kstat_t *kp, int rw)
{
	tcp_named_kstat_t *tcpkp;
	tcp_t		*tcp;
	connf_t		*connfp;
	conn_t		*connp;
	int 		i;
	netstackid_t	stackid = (netstackid_t)(uintptr_t)kp->ks_private;
	netstack_t	*ns;
	tcp_stack_t	*tcps;
	ip_stack_t	*ipst;
	mib2_tcp_t	tcp_mib;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	ns = netstack_find_by_stackid(stackid);
	if (ns == NULL)
		return (-1);
	tcps = ns->netstack_tcp;
	if (tcps == NULL) {
		netstack_rele(ns);
		return (-1);
	}

	tcpkp = (tcp_named_kstat_t *)kp->ks_data;

	tcpkp->currEstab.value.ui32 = 0;
	tcpkp->rtoMin.value.ui32 = tcps->tcps_rexmit_interval_min;
	tcpkp->rtoMax.value.ui32 = tcps->tcps_rexmit_interval_max;

	ipst = ns->netstack_ip;

	for (i = 0; i < CONN_G_HASH_SIZE; i++) {
		connfp = &ipst->ips_ipcl_globalhash_fanout[i];
		connp = NULL;
		while ((connp =
		    ipcl_get_next_conn(connfp, connp, IPCL_TCPCONN)) != NULL) {
			tcp = connp->conn_tcp;
			switch (tcp_snmp_state(tcp)) {
			case MIB2_TCP_established:
			case MIB2_TCP_closeWait:
				tcpkp->currEstab.value.ui32++;
				break;
			}
		}
	}
	bzero(&tcp_mib, sizeof (tcp_mib));
	tcp_sum_mib(tcps, &tcp_mib);

	/* Fixed length structure for IPv4 and IPv6 counters */
	SET_MIB(tcp_mib.tcpConnTableSize, sizeof (mib2_tcpConnEntry_t));
	SET_MIB(tcp_mib.tcp6ConnTableSize, sizeof (mib2_tcp6ConnEntry_t));

	tcpkp->activeOpens.value.ui32 = tcp_mib.tcpActiveOpens;
	tcpkp->passiveOpens.value.ui32 = tcp_mib.tcpPassiveOpens;
	tcpkp->attemptFails.value.ui32 = tcp_mib.tcpAttemptFails;
	tcpkp->estabResets.value.ui32 = tcp_mib.tcpEstabResets;
	tcpkp->inSegs.value.ui64 = tcp_mib.tcpHCInSegs;
	tcpkp->outSegs.value.ui64 = tcp_mib.tcpHCOutSegs;
	tcpkp->retransSegs.value.ui32 =	tcp_mib.tcpRetransSegs;
	tcpkp->connTableSize.value.i32 = tcp_mib.tcpConnTableSize;
	tcpkp->outRsts.value.ui32 = tcp_mib.tcpOutRsts;
	tcpkp->outDataSegs.value.ui32 = tcp_mib.tcpOutDataSegs;
	tcpkp->outDataBytes.value.ui32 = tcp_mib.tcpOutDataBytes;
	tcpkp->retransBytes.value.ui32 = tcp_mib.tcpRetransBytes;
	tcpkp->outAck.value.ui32 = tcp_mib.tcpOutAck;
	tcpkp->outAckDelayed.value.ui32 = tcp_mib.tcpOutAckDelayed;
	tcpkp->outUrg.value.ui32 = tcp_mib.tcpOutUrg;
	tcpkp->outWinUpdate.value.ui32 = tcp_mib.tcpOutWinUpdate;
	tcpkp->outWinProbe.value.ui32 = tcp_mib.tcpOutWinProbe;
	tcpkp->outControl.value.ui32 = tcp_mib.tcpOutControl;
	tcpkp->outFastRetrans.value.ui32 = tcp_mib.tcpOutFastRetrans;
	tcpkp->inAckSegs.value.ui32 = tcp_mib.tcpInAckSegs;
	tcpkp->inAckBytes.value.ui32 = tcp_mib.tcpInAckBytes;
	tcpkp->inDupAck.value.ui32 = tcp_mib.tcpInDupAck;
	tcpkp->inAckUnsent.value.ui32 = tcp_mib.tcpInAckUnsent;
	tcpkp->inDataInorderSegs.value.ui32 = tcp_mib.tcpInDataInorderSegs;
	tcpkp->inDataInorderBytes.value.ui32 = tcp_mib.tcpInDataInorderBytes;
	tcpkp->inDataUnorderSegs.value.ui32 = tcp_mib.tcpInDataUnorderSegs;
	tcpkp->inDataUnorderBytes.value.ui32 = tcp_mib.tcpInDataUnorderBytes;
	tcpkp->inDataDupSegs.value.ui32 = tcp_mib.tcpInDataDupSegs;
	tcpkp->inDataDupBytes.value.ui32 = tcp_mib.tcpInDataDupBytes;
	tcpkp->inDataPartDupSegs.value.ui32 = tcp_mib.tcpInDataPartDupSegs;
	tcpkp->inDataPartDupBytes.value.ui32 = tcp_mib.tcpInDataPartDupBytes;
	tcpkp->inDataPastWinSegs.value.ui32 = tcp_mib.tcpInDataPastWinSegs;
	tcpkp->inDataPastWinBytes.value.ui32 = tcp_mib.tcpInDataPastWinBytes;
	tcpkp->inWinProbe.value.ui32 = tcp_mib.tcpInWinProbe;
	tcpkp->inWinUpdate.value.ui32 = tcp_mib.tcpInWinUpdate;
	tcpkp->inClosed.value.ui32 = tcp_mib.tcpInClosed;
	tcpkp->rttNoUpdate.value.ui32 = tcp_mib.tcpRttNoUpdate;
	tcpkp->rttUpdate.value.ui32 = tcp_mib.tcpRttUpdate;
	tcpkp->timRetrans.value.ui32 = tcp_mib.tcpTimRetrans;
	tcpkp->timRetransDrop.value.ui32 = tcp_mib.tcpTimRetransDrop;
	tcpkp->timKeepalive.value.ui32 = tcp_mib.tcpTimKeepalive;
	tcpkp->timKeepaliveProbe.value.ui32 = tcp_mib.tcpTimKeepaliveProbe;
	tcpkp->timKeepaliveDrop.value.ui32 = tcp_mib.tcpTimKeepaliveDrop;
	tcpkp->listenDrop.value.ui32 = tcp_mib.tcpListenDrop;
	tcpkp->listenDropQ0.value.ui32 = tcp_mib.tcpListenDropQ0;
	tcpkp->halfOpenDrop.value.ui32 = tcp_mib.tcpHalfOpenDrop;
	tcpkp->outSackRetransSegs.value.ui32 = tcp_mib.tcpOutSackRetransSegs;
	tcpkp->connTableSize6.value.i32 = tcp_mib.tcp6ConnTableSize;

	netstack_rele(ns);
	return (0);
}

/*
 * kstats related to squeues i.e. not per IP instance
 */
void *
tcp_g_kstat_init(tcp_g_stat_t *tcp_g_statp)
{
	kstat_t *ksp;

	tcp_g_stat_t template = {
		{ "tcp_timermp_alloced",	KSTAT_DATA_UINT64 },
		{ "tcp_timermp_allocfail",	KSTAT_DATA_UINT64 },
		{ "tcp_timermp_allocdblfail",	KSTAT_DATA_UINT64 },
		{ "tcp_freelist_cleanup",	KSTAT_DATA_UINT64 },
	};

	ksp = kstat_create(TCP_MOD_NAME, 0, "tcpstat_g", "net",
	    KSTAT_TYPE_NAMED, sizeof (template) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL);

	if (ksp == NULL)
		return (NULL);

	bcopy(&template, tcp_g_statp, sizeof (template));
	ksp->ks_data = (void *)tcp_g_statp;

	kstat_install(ksp);
	return (ksp);
}

void
tcp_g_kstat_fini(kstat_t *ksp)
{
	if (ksp != NULL) {
		kstat_delete(ksp);
	}
}

void *
tcp_kstat2_init(netstackid_t stackid)
{
	kstat_t *ksp;

	tcp_stat_t template = {
		{ "tcp_time_wait_syn_success",	KSTAT_DATA_UINT64, 0 },
		{ "tcp_clean_death_nondetached",	KSTAT_DATA_UINT64, 0 },
		{ "tcp_eager_blowoff_q",	KSTAT_DATA_UINT64, 0 },
		{ "tcp_eager_blowoff_q0",	KSTAT_DATA_UINT64, 0 },
		{ "tcp_no_listener",		KSTAT_DATA_UINT64, 0 },
		{ "tcp_listendrop",		KSTAT_DATA_UINT64, 0 },
		{ "tcp_listendropq0",		KSTAT_DATA_UINT64, 0 },
		{ "tcp_wsrv_called",		KSTAT_DATA_UINT64, 0 },
		{ "tcp_flwctl_on",		KSTAT_DATA_UINT64, 0 },
		{ "tcp_timer_fire_early",	KSTAT_DATA_UINT64, 0 },
		{ "tcp_timer_fire_miss",	KSTAT_DATA_UINT64, 0 },
		{ "tcp_zcopy_on",		KSTAT_DATA_UINT64, 0 },
		{ "tcp_zcopy_off",		KSTAT_DATA_UINT64, 0 },
		{ "tcp_zcopy_backoff",		KSTAT_DATA_UINT64, 0 },
		{ "tcp_fusion_flowctl",		KSTAT_DATA_UINT64, 0 },
		{ "tcp_fusion_backenabled",	KSTAT_DATA_UINT64, 0 },
		{ "tcp_fusion_urg",		KSTAT_DATA_UINT64, 0 },
		{ "tcp_fusion_putnext",		KSTAT_DATA_UINT64, 0 },
		{ "tcp_fusion_unfusable",	KSTAT_DATA_UINT64, 0 },
		{ "tcp_fusion_aborted",		KSTAT_DATA_UINT64, 0 },
		{ "tcp_fusion_unqualified",	KSTAT_DATA_UINT64, 0 },
		{ "tcp_fusion_rrw_busy",	KSTAT_DATA_UINT64, 0 },
		{ "tcp_fusion_rrw_msgcnt",	KSTAT_DATA_UINT64, 0 },
		{ "tcp_fusion_rrw_plugged",	KSTAT_DATA_UINT64, 0 },
		{ "tcp_in_ack_unsent_drop",	KSTAT_DATA_UINT64, 0 },
		{ "tcp_sock_fallback",		KSTAT_DATA_UINT64, 0 },
		{ "tcp_lso_enabled",		KSTAT_DATA_UINT64, 0 },
		{ "tcp_lso_disabled",		KSTAT_DATA_UINT64, 0 },
		{ "tcp_lso_times",		KSTAT_DATA_UINT64, 0 },
		{ "tcp_lso_pkt_out",		KSTAT_DATA_UINT64, 0 },
		{ "tcp_listen_cnt_drop",	KSTAT_DATA_UINT64, 0 },
		{ "tcp_listen_mem_drop",	KSTAT_DATA_UINT64, 0 },
		{ "tcp_zwin_mem_drop",		KSTAT_DATA_UINT64, 0 },
		{ "tcp_zwin_ack_syn",		KSTAT_DATA_UINT64, 0 },
		{ "tcp_rst_unsent",		KSTAT_DATA_UINT64, 0 },
		{ "tcp_reclaim_cnt",		KSTAT_DATA_UINT64, 0 },
		{ "tcp_reass_timeout",		KSTAT_DATA_UINT64, 0 },
#ifdef TCP_DEBUG_COUNTER
		{ "tcp_time_wait",		KSTAT_DATA_UINT64, 0 },
		{ "tcp_rput_time_wait",		KSTAT_DATA_UINT64, 0 },
		{ "tcp_detach_time_wait",	KSTAT_DATA_UINT64, 0 },
		{ "tcp_timeout_calls",		KSTAT_DATA_UINT64, 0 },
		{ "tcp_timeout_cached_alloc",	KSTAT_DATA_UINT64, 0 },
		{ "tcp_timeout_cancel_reqs",	KSTAT_DATA_UINT64, 0 },
		{ "tcp_timeout_canceled",	KSTAT_DATA_UINT64, 0 },
		{ "tcp_timermp_freed",		KSTAT_DATA_UINT64, 0 },
		{ "tcp_push_timer_cnt",		KSTAT_DATA_UINT64, 0 },
		{ "tcp_ack_timer_cnt",		KSTAT_DATA_UINT64, 0 },
#endif
	};

	ksp = kstat_create_netstack(TCP_MOD_NAME, stackid, "tcpstat", "net",
	    KSTAT_TYPE_NAMED, sizeof (template) / sizeof (kstat_named_t), 0,
	    stackid);

	if (ksp == NULL)
		return (NULL);

	bcopy(&template, ksp->ks_data, sizeof (template));
	ksp->ks_private = (void *)(uintptr_t)stackid;
	ksp->ks_update = tcp_kstat2_update;

	/*
	 * If this is an exclusive netstack for a local zone, the global zone
	 * should still be able to read the kstat.
	 */
	if (stackid != GLOBAL_NETSTACKID)
		kstat_zone_add(ksp, GLOBAL_ZONEID);

	kstat_install(ksp);
	return (ksp);
}

void
tcp_kstat2_fini(netstackid_t stackid, kstat_t *ksp)
{
	if (ksp != NULL) {
		ASSERT(stackid == (netstackid_t)(uintptr_t)ksp->ks_private);
		kstat_delete_netstack(ksp, stackid);
	}
}

/*
 * Sum up all per CPU tcp_stat_t kstat counters.
 */
static int
tcp_kstat2_update(kstat_t *kp, int rw)
{
	netstackid_t	stackid = (netstackid_t)(uintptr_t)kp->ks_private;
	netstack_t	*ns;
	tcp_stack_t	*tcps;
	tcp_stat_t	*stats;
	int		i;
	int		cnt;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	ns = netstack_find_by_stackid(stackid);
	if (ns == NULL)
		return (-1);
	tcps = ns->netstack_tcp;
	if (tcps == NULL) {
		netstack_rele(ns);
		return (-1);
	}

	stats = (tcp_stat_t *)kp->ks_data;
	tcp_clr_stats(stats);

	/*
	 * tcps_sc_cnt may change in the middle of the loop.  It is better
	 * to get its value first.
	 */
	cnt = tcps->tcps_sc_cnt;
	for (i = 0; i < cnt; i++)
		tcp_add_stats(&tcps->tcps_sc[i]->tcp_sc_stats, stats);

	netstack_rele(ns);
	return (0);
}

/*
 * To add stats from one mib2_tcp_t to another.  Static fields are not added.
 * The caller should set them up propertly.
 */
static void
tcp_add_mib(mib2_tcp_t *from, mib2_tcp_t *to)
{
	to->tcpActiveOpens += from->tcpActiveOpens;
	to->tcpPassiveOpens += from->tcpPassiveOpens;
	to->tcpAttemptFails += from->tcpAttemptFails;
	to->tcpEstabResets += from->tcpEstabResets;
	to->tcpInSegs += from->tcpInSegs;
	to->tcpOutSegs += from->tcpOutSegs;
	to->tcpRetransSegs += from->tcpRetransSegs;
	to->tcpOutRsts += from->tcpOutRsts;

	to->tcpOutDataSegs += from->tcpOutDataSegs;
	to->tcpOutDataBytes += from->tcpOutDataBytes;
	to->tcpRetransBytes += from->tcpRetransBytes;
	to->tcpOutAck += from->tcpOutAck;
	to->tcpOutAckDelayed += from->tcpOutAckDelayed;
	to->tcpOutUrg += from->tcpOutUrg;
	to->tcpOutWinUpdate += from->tcpOutWinUpdate;
	to->tcpOutWinProbe += from->tcpOutWinProbe;
	to->tcpOutControl += from->tcpOutControl;
	to->tcpOutFastRetrans += from->tcpOutFastRetrans;

	to->tcpInAckBytes += from->tcpInAckBytes;
	to->tcpInDupAck += from->tcpInDupAck;
	to->tcpInAckUnsent += from->tcpInAckUnsent;
	to->tcpInDataInorderSegs += from->tcpInDataInorderSegs;
	to->tcpInDataInorderBytes += from->tcpInDataInorderBytes;
	to->tcpInDataUnorderSegs += from->tcpInDataUnorderSegs;
	to->tcpInDataUnorderBytes += from->tcpInDataUnorderBytes;
	to->tcpInDataDupSegs += from->tcpInDataDupSegs;
	to->tcpInDataDupBytes += from->tcpInDataDupBytes;
	to->tcpInDataPartDupSegs += from->tcpInDataPartDupSegs;
	to->tcpInDataPartDupBytes += from->tcpInDataPartDupBytes;
	to->tcpInDataPastWinSegs += from->tcpInDataPastWinSegs;
	to->tcpInDataPastWinBytes += from->tcpInDataPastWinBytes;
	to->tcpInWinProbe += from->tcpInWinProbe;
	to->tcpInWinUpdate += from->tcpInWinUpdate;
	to->tcpInClosed += from->tcpInClosed;

	to->tcpRttNoUpdate += from->tcpRttNoUpdate;
	to->tcpRttUpdate += from->tcpRttUpdate;
	to->tcpTimRetrans += from->tcpTimRetrans;
	to->tcpTimRetransDrop += from->tcpTimRetransDrop;
	to->tcpTimKeepalive += from->tcpTimKeepalive;
	to->tcpTimKeepaliveProbe += from->tcpTimKeepaliveProbe;
	to->tcpTimKeepaliveDrop += from->tcpTimKeepaliveDrop;
	to->tcpListenDrop += from->tcpListenDrop;
	to->tcpListenDropQ0 += from->tcpListenDropQ0;
	to->tcpHalfOpenDrop += from->tcpHalfOpenDrop;
	to->tcpOutSackRetransSegs += from->tcpOutSackRetransSegs;
	to->tcpHCInSegs += from->tcpHCInSegs;
	to->tcpHCOutSegs += from->tcpHCOutSegs;
}

/*
 * To sum up all MIB2 stats for a tcp_stack_t from all per CPU stats.  The
 * caller should initialize the target mib2_tcp_t properly as this function
 * just adds up all the per CPU stats.
 */
static void
tcp_sum_mib(tcp_stack_t *tcps, mib2_tcp_t *tcp_mib)
{
	int i;
	int cnt;

	/*
	 * tcps_sc_cnt may change in the middle of the loop.  It is better
	 * to get its value first.
	 */
	cnt = tcps->tcps_sc_cnt;
	for (i = 0; i < cnt; i++)
		tcp_add_mib(&tcps->tcps_sc[i]->tcp_sc_mib, tcp_mib);
}

/*
 * To set all tcp_stat_t counters to 0.
 */
static void
tcp_clr_stats(tcp_stat_t *stats)
{
	stats->tcp_time_wait_syn_success.value.ui64 = 0;
	stats->tcp_clean_death_nondetached.value.ui64 = 0;
	stats->tcp_eager_blowoff_q.value.ui64 = 0;
	stats->tcp_eager_blowoff_q0.value.ui64 = 0;
	stats->tcp_no_listener.value.ui64 = 0;
	stats->tcp_listendrop.value.ui64 = 0;
	stats->tcp_listendropq0.value.ui64 = 0;
	stats->tcp_wsrv_called.value.ui64 = 0;
	stats->tcp_flwctl_on.value.ui64 = 0;
	stats->tcp_timer_fire_early.value.ui64 = 0;
	stats->tcp_timer_fire_miss.value.ui64 = 0;
	stats->tcp_zcopy_on.value.ui64 = 0;
	stats->tcp_zcopy_off.value.ui64 = 0;
	stats->tcp_zcopy_backoff.value.ui64 = 0;
	stats->tcp_fusion_flowctl.value.ui64 = 0;
	stats->tcp_fusion_backenabled.value.ui64 = 0;
	stats->tcp_fusion_urg.value.ui64 = 0;
	stats->tcp_fusion_putnext.value.ui64 = 0;
	stats->tcp_fusion_unfusable.value.ui64 = 0;
	stats->tcp_fusion_aborted.value.ui64 = 0;
	stats->tcp_fusion_unqualified.value.ui64 = 0;
	stats->tcp_fusion_rrw_busy.value.ui64 = 0;
	stats->tcp_fusion_rrw_msgcnt.value.ui64 = 0;
	stats->tcp_fusion_rrw_plugged.value.ui64 = 0;
	stats->tcp_in_ack_unsent_drop.value.ui64 = 0;
	stats->tcp_sock_fallback.value.ui64 = 0;
	stats->tcp_lso_enabled.value.ui64 = 0;
	stats->tcp_lso_disabled.value.ui64 = 0;
	stats->tcp_lso_times.value.ui64 = 0;
	stats->tcp_lso_pkt_out.value.ui64 = 0;
	stats->tcp_listen_cnt_drop.value.ui64 = 0;
	stats->tcp_listen_mem_drop.value.ui64 = 0;
	stats->tcp_zwin_mem_drop.value.ui64 = 0;
	stats->tcp_zwin_ack_syn.value.ui64 = 0;
	stats->tcp_rst_unsent.value.ui64 = 0;
	stats->tcp_reclaim_cnt.value.ui64 = 0;
	stats->tcp_reass_timeout.value.ui64 = 0;

#ifdef TCP_DEBUG_COUNTER
	stats->tcp_time_wait.value.ui64 = 0;
	stats->tcp_rput_time_wait.value.ui64 = 0;
	stats->tcp_detach_time_wait.value.ui64 = 0;
	stats->tcp_timeout_calls.value.ui64 = 0;
	stats->tcp_timeout_cached_alloc.value.ui64 = 0;
	stats->tcp_timeout_cancel_reqs.value.ui64 = 0;
	stats->tcp_timeout_canceled.value.ui64 = 0;
	stats->tcp_timermp_freed.value.ui64 = 0;
	stats->tcp_push_timer_cnt.value.ui64 = 0;
	stats->tcp_ack_timer_cnt.value.ui64 = 0;
#endif
}

/*
 * To add counters from the per CPU tcp_stat_counter_t to the stack
 * tcp_stat_t.
 */
static void
tcp_add_stats(tcp_stat_counter_t *from, tcp_stat_t *to)
{
	to->tcp_time_wait_syn_success.value.ui64 +=
	    from->tcp_time_wait_syn_success;
	to->tcp_clean_death_nondetached.value.ui64 +=
	    from->tcp_clean_death_nondetached;
	to->tcp_eager_blowoff_q.value.ui64 +=
	    from->tcp_eager_blowoff_q;
	to->tcp_eager_blowoff_q0.value.ui64 +=
	    from->tcp_eager_blowoff_q0;
	to->tcp_no_listener.value.ui64 +=
	    from->tcp_no_listener;
	to->tcp_listendrop.value.ui64 +=
	    from->tcp_listendrop;
	to->tcp_listendropq0.value.ui64 +=
	    from->tcp_listendropq0;
	to->tcp_wsrv_called.value.ui64 +=
	    from->tcp_wsrv_called;
	to->tcp_flwctl_on.value.ui64 +=
	    from->tcp_flwctl_on;
	to->tcp_timer_fire_early.value.ui64 +=
	    from->tcp_timer_fire_early;
	to->tcp_timer_fire_miss.value.ui64 +=
	    from->tcp_timer_fire_miss;
	to->tcp_zcopy_on.value.ui64 +=
	    from->tcp_zcopy_on;
	to->tcp_zcopy_off.value.ui64 +=
	    from->tcp_zcopy_off;
	to->tcp_zcopy_backoff.value.ui64 +=
	    from->tcp_zcopy_backoff;
	to->tcp_fusion_flowctl.value.ui64 +=
	    from->tcp_fusion_flowctl;
	to->tcp_fusion_backenabled.value.ui64 +=
	    from->tcp_fusion_backenabled;
	to->tcp_fusion_urg.value.ui64 +=
	    from->tcp_fusion_urg;
	to->tcp_fusion_putnext.value.ui64 +=
	    from->tcp_fusion_putnext;
	to->tcp_fusion_unfusable.value.ui64 +=
	    from->tcp_fusion_unfusable;
	to->tcp_fusion_aborted.value.ui64 +=
	    from->tcp_fusion_aborted;
	to->tcp_fusion_unqualified.value.ui64 +=
	    from->tcp_fusion_unqualified;
	to->tcp_fusion_rrw_busy.value.ui64 +=
	    from->tcp_fusion_rrw_busy;
	to->tcp_fusion_rrw_msgcnt.value.ui64 +=
	    from->tcp_fusion_rrw_msgcnt;
	to->tcp_fusion_rrw_plugged.value.ui64 +=
	    from->tcp_fusion_rrw_plugged;
	to->tcp_in_ack_unsent_drop.value.ui64 +=
	    from->tcp_in_ack_unsent_drop;
	to->tcp_sock_fallback.value.ui64 +=
	    from->tcp_sock_fallback;
	to->tcp_lso_enabled.value.ui64 +=
	    from->tcp_lso_enabled;
	to->tcp_lso_disabled.value.ui64 +=
	    from->tcp_lso_disabled;
	to->tcp_lso_times.value.ui64 +=
	    from->tcp_lso_times;
	to->tcp_lso_pkt_out.value.ui64 +=
	    from->tcp_lso_pkt_out;
	to->tcp_listen_cnt_drop.value.ui64 +=
	    from->tcp_listen_cnt_drop;
	to->tcp_listen_mem_drop.value.ui64 +=
	    from->tcp_listen_mem_drop;
	to->tcp_zwin_mem_drop.value.ui64 +=
	    from->tcp_zwin_mem_drop;
	to->tcp_zwin_ack_syn.value.ui64 +=
	    from->tcp_zwin_ack_syn;
	to->tcp_rst_unsent.value.ui64 +=
	    from->tcp_rst_unsent;
	to->tcp_reclaim_cnt.value.ui64 +=
	    from->tcp_reclaim_cnt;
	to->tcp_reass_timeout.value.ui64 +=
	    from->tcp_reass_timeout;

#ifdef TCP_DEBUG_COUNTER
	to->tcp_time_wait.value.ui64 +=
	    from->tcp_time_wait;
	to->tcp_rput_time_wait.value.ui64 +=
	    from->tcp_rput_time_wait;
	to->tcp_detach_time_wait.value.ui64 +=
	    from->tcp_detach_time_wait;
	to->tcp_timeout_calls.value.ui64 +=
	    from->tcp_timeout_calls;
	to->tcp_timeout_cached_alloc.value.ui64 +=
	    from->tcp_timeout_cached_alloc;
	to->tcp_timeout_cancel_reqs.value.ui64 +=
	    from->tcp_timeout_cancel_reqs;
	to->tcp_timeout_canceled.value.ui64 +=
	    from->tcp_timeout_canceled;
	to->tcp_timermp_freed.value.ui64 +=
	    from->tcp_timermp_freed;
	to->tcp_push_timer_cnt.value.ui64 +=
	    from->tcp_push_timer_cnt;
	to->tcp_ack_timer_cnt.value.ui64 +=
	    from->tcp_ack_timer_cnt;
#endif
}
