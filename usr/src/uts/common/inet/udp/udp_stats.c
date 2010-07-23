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

#include <sys/types.h>
#include <sys/tihdr.h>
#include <sys/policy.h>
#include <sys/tsol/tnet.h>

#include <inet/common.h>
#include <inet/kstatcom.h>
#include <inet/snmpcom.h>
#include <inet/mib2.h>
#include <inet/optcom.h>
#include <inet/snmpcom.h>
#include <inet/kstatcom.h>
#include <inet/udp_impl.h>

static int	udp_kstat_update(kstat_t *, int);
static int	udp_kstat2_update(kstat_t *, int);
static void	udp_sum_mib(udp_stack_t *, mib2_udp_t *);
static void	udp_clr_stats(udp_stat_t *);
static void	udp_add_stats(udp_stat_counter_t *, udp_stat_t *);
static void	udp_add_mib(mib2_udp_t *, mib2_udp_t *);
/*
 * return SNMP stuff in buffer in mpdata. We don't hold any lock and report
 * information that can be changing beneath us.
 */
mblk_t *
udp_snmp_get(queue_t *q, mblk_t *mpctl, boolean_t legacy_req)
{
	mblk_t			*mpdata;
	mblk_t			*mp_conn_ctl;
	mblk_t			*mp_attr_ctl;
	mblk_t			*mp6_conn_ctl;
	mblk_t			*mp6_attr_ctl;
	mblk_t			*mp_conn_tail;
	mblk_t			*mp_attr_tail;
	mblk_t			*mp6_conn_tail;
	mblk_t			*mp6_attr_tail;
	struct opthdr		*optp;
	mib2_udpEntry_t		ude;
	mib2_udp6Entry_t	ude6;
	mib2_transportMLPEntry_t mlp;
	int			state;
	zoneid_t		zoneid;
	int			i;
	connf_t			*connfp;
	conn_t			*connp = Q_TO_CONN(q);
	int			v4_conn_idx;
	int			v6_conn_idx;
	boolean_t		needattr;
	udp_t			*udp;
	ip_stack_t		*ipst = connp->conn_netstack->netstack_ip;
	udp_stack_t		*us = connp->conn_netstack->netstack_udp;
	mblk_t			*mp2ctl;
	mib2_udp_t		udp_mib;
	size_t			udp_mib_size, ude_size, ude6_size;


	/*
	 * make a copy of the original message
	 */
	mp2ctl = copymsg(mpctl);

	mp_conn_ctl = mp_attr_ctl = mp6_conn_ctl = NULL;
	if (mpctl == NULL ||
	    (mpdata = mpctl->b_cont) == NULL ||
	    (mp_conn_ctl = copymsg(mpctl)) == NULL ||
	    (mp_attr_ctl = copymsg(mpctl)) == NULL ||
	    (mp6_conn_ctl = copymsg(mpctl)) == NULL ||
	    (mp6_attr_ctl = copymsg(mpctl)) == NULL) {
		freemsg(mp_conn_ctl);
		freemsg(mp_attr_ctl);
		freemsg(mp6_conn_ctl);
		freemsg(mpctl);
		freemsg(mp2ctl);
		return (0);
	}

	zoneid = connp->conn_zoneid;

	if (legacy_req) {
		udp_mib_size = LEGACY_MIB_SIZE(&udp_mib, mib2_udp_t);
		ude_size = LEGACY_MIB_SIZE(&ude, mib2_udpEntry_t);
		ude6_size = LEGACY_MIB_SIZE(&ude6, mib2_udp6Entry_t);
	} else {
		udp_mib_size = sizeof (mib2_udp_t);
		ude_size = sizeof (mib2_udpEntry_t);
		ude6_size = sizeof (mib2_udp6Entry_t);
	}

	bzero(&udp_mib, sizeof (udp_mib));
	/* fixed length structure for IPv4 and IPv6 counters */
	SET_MIB(udp_mib.udpEntrySize, ude_size);
	SET_MIB(udp_mib.udp6EntrySize, ude6_size);

	udp_sum_mib(us, &udp_mib);

	/*
	 * Synchronize 32- and 64-bit counters.  Note that udpInDatagrams and
	 * udpOutDatagrams are not updated anywhere in UDP.  The new 64 bits
	 * counters are used.  Hence the old counters' values in us_sc_mib
	 * are always 0.
	 */
	SYNC32_MIB(&udp_mib, udpInDatagrams, udpHCInDatagrams);
	SYNC32_MIB(&udp_mib, udpOutDatagrams, udpHCOutDatagrams);

	optp = (struct opthdr *)&mpctl->b_rptr[sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_UDP;
	optp->name = 0;
	(void) snmp_append_data(mpdata, (char *)&udp_mib, udp_mib_size);
	optp->len = msgdsize(mpdata);
	qreply(q, mpctl);

	mp_conn_tail = mp_attr_tail = mp6_conn_tail = mp6_attr_tail = NULL;
	v4_conn_idx = v6_conn_idx = 0;

	for (i = 0; i < CONN_G_HASH_SIZE; i++) {
		connfp = &ipst->ips_ipcl_globalhash_fanout[i];
		connp = NULL;

		while ((connp = ipcl_get_next_conn(connfp, connp,
		    IPCL_UDPCONN))) {
			udp = connp->conn_udp;
			if (zoneid != connp->conn_zoneid)
				continue;

			/*
			 * Note that the port numbers are sent in
			 * host byte order
			 */

			if (udp->udp_state == TS_UNBND)
				state = MIB2_UDP_unbound;
			else if (udp->udp_state == TS_IDLE)
				state = MIB2_UDP_idle;
			else if (udp->udp_state == TS_DATA_XFER)
				state = MIB2_UDP_connected;
			else
				state = MIB2_UDP_unknown;

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
			mutex_enter(&connp->conn_lock);
			if (udp->udp_state == TS_DATA_XFER &&
			    connp->conn_ixa->ixa_tsl != NULL) {
				ts_label_t *tsl;

				tsl = connp->conn_ixa->ixa_tsl;
				mlp.tme_flags |= MIB2_TMEF_IS_LABELED;
				mlp.tme_doi = label2doi(tsl);
				mlp.tme_label = *label2bslabel(tsl);
				needattr = B_TRUE;
			}
			mutex_exit(&connp->conn_lock);

			/*
			 * Create an IPv4 table entry for IPv4 entries and also
			 * any IPv6 entries which are bound to in6addr_any
			 * (i.e. anything a IPv4 peer could connect/send to).
			 */
			if (connp->conn_ipversion == IPV4_VERSION ||
			    (udp->udp_state <= TS_IDLE &&
			    IN6_IS_ADDR_UNSPECIFIED(&connp->conn_laddr_v6))) {
				ude.udpEntryInfo.ue_state = state;
				/*
				 * If in6addr_any this will set it to
				 * INADDR_ANY
				 */
				ude.udpLocalAddress = connp->conn_laddr_v4;
				ude.udpLocalPort = ntohs(connp->conn_lport);
				if (udp->udp_state == TS_DATA_XFER) {
					/*
					 * Can potentially get here for
					 * v6 socket if another process
					 * (say, ping) has just done a
					 * sendto(), changing the state
					 * from the TS_IDLE above to
					 * TS_DATA_XFER by the time we hit
					 * this part of the code.
					 */
					ude.udpEntryInfo.ue_RemoteAddress =
					    connp->conn_faddr_v4;
					ude.udpEntryInfo.ue_RemotePort =
					    ntohs(connp->conn_fport);
				} else {
					ude.udpEntryInfo.ue_RemoteAddress = 0;
					ude.udpEntryInfo.ue_RemotePort = 0;
				}

				/*
				 * We make the assumption that all udp_t
				 * structs will be created within an address
				 * region no larger than 32-bits.
				 */
				ude.udpInstance = (uint32_t)(uintptr_t)udp;
				ude.udpCreationProcess =
				    (connp->conn_cpid < 0) ?
				    MIB2_UNKNOWN_PROCESS :
				    connp->conn_cpid;
				ude.udpCreationTime = connp->conn_open_time;

				(void) snmp_append_data2(mp_conn_ctl->b_cont,
				    &mp_conn_tail, (char *)&ude, ude_size);
				mlp.tme_connidx = v4_conn_idx++;
				if (needattr)
					(void) snmp_append_data2(
					    mp_attr_ctl->b_cont, &mp_attr_tail,
					    (char *)&mlp, sizeof (mlp));
			}
			if (connp->conn_ipversion == IPV6_VERSION) {
				ude6.udp6EntryInfo.ue_state  = state;
				ude6.udp6LocalAddress = connp->conn_laddr_v6;
				ude6.udp6LocalPort = ntohs(connp->conn_lport);
				mutex_enter(&connp->conn_lock);
				if (connp->conn_ixa->ixa_flags &
				    IXAF_SCOPEID_SET) {
					ude6.udp6IfIndex =
					    connp->conn_ixa->ixa_scopeid;
				} else {
					ude6.udp6IfIndex = connp->conn_bound_if;
				}
				mutex_exit(&connp->conn_lock);
				if (udp->udp_state == TS_DATA_XFER) {
					ude6.udp6EntryInfo.ue_RemoteAddress =
					    connp->conn_faddr_v6;
					ude6.udp6EntryInfo.ue_RemotePort =
					    ntohs(connp->conn_fport);
				} else {
					ude6.udp6EntryInfo.ue_RemoteAddress =
					    sin6_null.sin6_addr;
					ude6.udp6EntryInfo.ue_RemotePort = 0;
				}
				/*
				 * We make the assumption that all udp_t
				 * structs will be created within an address
				 * region no larger than 32-bits.
				 */
				ude6.udp6Instance = (uint32_t)(uintptr_t)udp;
				ude6.udp6CreationProcess =
				    (connp->conn_cpid < 0) ?
				    MIB2_UNKNOWN_PROCESS :
				    connp->conn_cpid;
				ude6.udp6CreationTime = connp->conn_open_time;

				(void) snmp_append_data2(mp6_conn_ctl->b_cont,
				    &mp6_conn_tail, (char *)&ude6, ude6_size);
				mlp.tme_connidx = v6_conn_idx++;
				if (needattr)
					(void) snmp_append_data2(
					    mp6_attr_ctl->b_cont,
					    &mp6_attr_tail, (char *)&mlp,
					    sizeof (mlp));
			}
		}
	}

	/* IPv4 UDP endpoints */
	optp = (struct opthdr *)&mp_conn_ctl->b_rptr[
	    sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_UDP;
	optp->name = MIB2_UDP_ENTRY;
	optp->len = msgdsize(mp_conn_ctl->b_cont);
	qreply(q, mp_conn_ctl);

	/* table of MLP attributes... */
	optp = (struct opthdr *)&mp_attr_ctl->b_rptr[
	    sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_UDP;
	optp->name = EXPER_XPORT_MLP;
	optp->len = msgdsize(mp_attr_ctl->b_cont);
	if (optp->len == 0)
		freemsg(mp_attr_ctl);
	else
		qreply(q, mp_attr_ctl);

	/* IPv6 UDP endpoints */
	optp = (struct opthdr *)&mp6_conn_ctl->b_rptr[
	    sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_UDP6;
	optp->name = MIB2_UDP6_ENTRY;
	optp->len = msgdsize(mp6_conn_ctl->b_cont);
	qreply(q, mp6_conn_ctl);

	/* table of MLP attributes... */
	optp = (struct opthdr *)&mp6_attr_ctl->b_rptr[
	    sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_UDP6;
	optp->name = EXPER_XPORT_MLP;
	optp->len = msgdsize(mp6_attr_ctl->b_cont);
	if (optp->len == 0)
		freemsg(mp6_attr_ctl);
	else
		qreply(q, mp6_attr_ctl);

	return (mp2ctl);
}

/*
 * Return 0 if invalid set request, 1 otherwise, including non-udp requests.
 * NOTE: Per MIB-II, UDP has no writable data.
 * TODO:  If this ever actually tries to set anything, it needs to be
 * to do the appropriate locking.
 */
/* ARGSUSED */
int
udp_snmp_set(queue_t *q, t_scalar_t level, t_scalar_t name,
    uchar_t *ptr, int len)
{
	switch (level) {
	case MIB2_UDP:
		return (0);
	default:
		return (1);
	}
}

void
udp_kstat_fini(netstackid_t stackid, kstat_t *ksp)
{
	if (ksp != NULL) {
		ASSERT(stackid == (netstackid_t)(uintptr_t)ksp->ks_private);
		kstat_delete_netstack(ksp, stackid);
	}
}

/*
 * To add stats from one mib2_udp_t to another.  Static fields are not added.
 * The caller should set them up propertly.
 */
static void
udp_add_mib(mib2_udp_t *from, mib2_udp_t *to)
{
	to->udpHCInDatagrams += from->udpHCInDatagrams;
	to->udpInErrors += from->udpInErrors;
	to->udpHCOutDatagrams += from->udpHCOutDatagrams;
	to->udpOutErrors += from->udpOutErrors;
}


void *
udp_kstat2_init(netstackid_t stackid)
{
	kstat_t *ksp;

	udp_stat_t template = {
		{ "udp_sock_fallback",		KSTAT_DATA_UINT64 },
		{ "udp_out_opt",		KSTAT_DATA_UINT64 },
		{ "udp_out_err_notconn",	KSTAT_DATA_UINT64 },
		{ "udp_out_err_output",		KSTAT_DATA_UINT64 },
		{ "udp_out_err_tudr",		KSTAT_DATA_UINT64 },
#ifdef DEBUG
		{ "udp_data_conn",		KSTAT_DATA_UINT64 },
		{ "udp_data_notconn",		KSTAT_DATA_UINT64 },
		{ "udp_out_lastdst",		KSTAT_DATA_UINT64 },
		{ "udp_out_diffdst",		KSTAT_DATA_UINT64 },
		{ "udp_out_ipv6",		KSTAT_DATA_UINT64 },
		{ "udp_out_mapped",		KSTAT_DATA_UINT64 },
		{ "udp_out_ipv4",		KSTAT_DATA_UINT64 },
#endif
	};

	ksp = kstat_create_netstack(UDP_MOD_NAME, 0, "udpstat", "net",
	    KSTAT_TYPE_NAMED, sizeof (template) / sizeof (kstat_named_t),
	    0, stackid);

	if (ksp == NULL)
		return (NULL);

	bcopy(&template, ksp->ks_data, sizeof (template));
	ksp->ks_update = udp_kstat2_update;
	ksp->ks_private = (void *)(uintptr_t)stackid;

	kstat_install(ksp);
	return (ksp);
}

void
udp_kstat2_fini(netstackid_t stackid, kstat_t *ksp)
{
	if (ksp != NULL) {
		ASSERT(stackid == (netstackid_t)(uintptr_t)ksp->ks_private);
		kstat_delete_netstack(ksp, stackid);
	}
}

/*
 * To copy counters from the per CPU udpp_stat_counter_t to the stack
 * udp_stat_t.
 */
static void
udp_add_stats(udp_stat_counter_t *from, udp_stat_t *to)
{
	to->udp_sock_fallback.value.ui64 += from->udp_sock_fallback;
	to->udp_out_opt.value.ui64 += from->udp_out_opt;
	to->udp_out_err_notconn.value.ui64 += from->udp_out_err_notconn;
	to->udp_out_err_output.value.ui64 += from->udp_out_err_output;
	to->udp_out_err_tudr.value.ui64 += from->udp_out_err_tudr;
#ifdef DEBUG
	to->udp_data_conn.value.ui64 += from->udp_data_conn;
	to->udp_data_notconn.value.ui64 += from->udp_data_notconn;
	to->udp_out_lastdst.value.ui64 += from->udp_out_lastdst;
	to->udp_out_diffdst.value.ui64 += from->udp_out_diffdst;
	to->udp_out_ipv6.value.ui64 += from->udp_out_ipv6;
	to->udp_out_mapped.value.ui64 += from->udp_out_mapped;
	to->udp_out_ipv4.value.ui64 += from->udp_out_ipv4;
#endif
}

/*
 * To set all udp_stat_t counters to 0.
 */
static void
udp_clr_stats(udp_stat_t *stats)
{
	stats->udp_sock_fallback.value.ui64 = 0;
	stats->udp_out_opt.value.ui64 = 0;
	stats->udp_out_err_notconn.value.ui64 = 0;
	stats->udp_out_err_output.value.ui64 = 0;
	stats->udp_out_err_tudr.value.ui64 = 0;
#ifdef DEBUG
	stats->udp_data_conn.value.ui64 = 0;
	stats->udp_data_notconn.value.ui64 = 0;
	stats->udp_out_lastdst.value.ui64 = 0;
	stats->udp_out_diffdst.value.ui64 = 0;
	stats->udp_out_ipv6.value.ui64 = 0;
	stats->udp_out_mapped.value.ui64 = 0;
	stats->udp_out_ipv4.value.ui64 = 0;
#endif
}

int
udp_kstat2_update(kstat_t *kp, int rw)
{
	udp_stat_t	*stats;
	netstackid_t	stackid = (netstackid_t)(uintptr_t)kp->ks_private;
	netstack_t	*ns;
	udp_stack_t	*us;
	int		i;
	int		cnt;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	ns = netstack_find_by_stackid(stackid);
	if (ns == NULL)
		return (-1);
	us = ns->netstack_udp;
	if (us == NULL) {
		netstack_rele(ns);
		return (-1);
	}
	stats = (udp_stat_t *)kp->ks_data;
	udp_clr_stats(stats);

	cnt = us->us_sc_cnt;
	for (i = 0; i < cnt; i++)
		udp_add_stats(&us->us_sc[i]->udp_sc_stats, stats);

	netstack_rele(ns);
	return (0);
}

void *
udp_kstat_init(netstackid_t stackid)
{
	kstat_t	*ksp;

	udp_named_kstat_t template = {
		{ "inDatagrams",	KSTAT_DATA_UINT64, 0 },
		{ "inErrors",		KSTAT_DATA_UINT32, 0 },
		{ "outDatagrams",	KSTAT_DATA_UINT64, 0 },
		{ "entrySize",		KSTAT_DATA_INT32, 0 },
		{ "entry6Size",		KSTAT_DATA_INT32, 0 },
		{ "outErrors",		KSTAT_DATA_UINT32, 0 },
	};

	ksp = kstat_create_netstack(UDP_MOD_NAME, 0, UDP_MOD_NAME, "mib2",
	    KSTAT_TYPE_NAMED, NUM_OF_FIELDS(udp_named_kstat_t), 0, stackid);

	if (ksp == NULL)
		return (NULL);

	template.entrySize.value.ui32 = sizeof (mib2_udpEntry_t);
	template.entry6Size.value.ui32 = sizeof (mib2_udp6Entry_t);

	bcopy(&template, ksp->ks_data, sizeof (template));
	ksp->ks_update = udp_kstat_update;
	ksp->ks_private = (void *)(uintptr_t)stackid;

	kstat_install(ksp);
	return (ksp);
}

/*
 * To sum up all MIB2 stats for a udp_stack_t from all per CPU stats.  The
 * caller should initialize the target mib2_udp_t properly as this function
 * just adds up all the per CPU stats.
 */
static void
udp_sum_mib(udp_stack_t *us, mib2_udp_t *udp_mib)
{
	int i;
	int cnt;

	cnt = us->us_sc_cnt;
	for (i = 0; i < cnt; i++)
		udp_add_mib(&us->us_sc[i]->udp_sc_mib, udp_mib);
}

static int
udp_kstat_update(kstat_t *kp, int rw)
{
	udp_named_kstat_t *udpkp;
	netstackid_t	stackid = (netstackid_t)(uintptr_t)kp->ks_private;
	netstack_t	*ns;
	udp_stack_t	*us;
	mib2_udp_t	udp_mib;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	ns = netstack_find_by_stackid(stackid);
	if (ns == NULL)
		return (-1);
	us = ns->netstack_udp;
	if (us == NULL) {
		netstack_rele(ns);
		return (-1);
	}
	udpkp = (udp_named_kstat_t *)kp->ks_data;

	bzero(&udp_mib, sizeof (udp_mib));
	udp_sum_mib(us, &udp_mib);

	udpkp->inDatagrams.value.ui64 =	udp_mib.udpHCInDatagrams;
	udpkp->inErrors.value.ui32 =	udp_mib.udpInErrors;
	udpkp->outDatagrams.value.ui64 = udp_mib.udpHCOutDatagrams;
	udpkp->outErrors.value.ui32 =	udp_mib.udpOutErrors;
	netstack_rele(ns);
	return (0);
}
