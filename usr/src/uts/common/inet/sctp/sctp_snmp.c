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
 * Copyright (c) 2004, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright (c) 2018, Joyent, Inc.
 */

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/cmn_err.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/tsol/tndb.h>

#include <netinet/in.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/mib2.h>
#include <inet/snmpcom.h>
#include <inet/kstatcom.h>
#include <inet/ipclassifier.h>
#include "sctp_impl.h"
#include "sctp_addr.h"

static void sctp_clr_kstats2(sctp_kstat_t *);
static void sctp_add_kstats2(sctp_kstat_counter_t *, sctp_kstat_t *);
static int sctp_snmp_state(sctp_t *);
static void sctp_sum_mib(sctp_stack_t *, mib2_sctp_t *);
static void sctp_add_mib(mib2_sctp_t *, mib2_sctp_t *);

static int
sctp_kstat_update(kstat_t *kp, int rw)
{
	sctp_named_kstat_t	*sctpkp;
	sctp_t			*sctp, *sctp_prev;
	zoneid_t	myzoneid;
	netstackid_t	stackid = (netstackid_t)(uintptr_t)kp->ks_private;
	netstack_t	*ns;
	sctp_stack_t	*sctps;
	mib2_sctp_t	sctp_mib;

	if (kp->ks_data == NULL)
		return (EIO);

	if (rw == KSTAT_WRITE)
		return (EACCES);

	ns = netstack_find_by_stackid(stackid);
	if (ns == NULL)
		return (-1);
	sctps = ns->netstack_sctp;
	if (sctps == NULL) {
		netstack_rele(ns);
		return (-1);
	}

	/*
	 * For all exclusive netstacks, the zone ID is always GLOBAL_ZONEID.
	 */
	if (stackid != GLOBAL_NETSTACKID)
		myzoneid = GLOBAL_ZONEID;
	else
		myzoneid = curproc->p_zone->zone_id;

	bzero(&sctp_mib, sizeof (sctp_mib));

	/*
	 * Get the number of current associations and gather their
	 * individual set of statistics.
	 */
	sctp_prev = NULL;
	mutex_enter(&sctps->sctps_g_lock);
	sctp = list_head(&sctps->sctps_g_list);
	while (sctp != NULL) {
		mutex_enter(&sctp->sctp_reflock);
		if (sctp->sctp_condemned) {
			mutex_exit(&sctp->sctp_reflock);
			sctp = list_next(&sctps->sctps_g_list, sctp);
			continue;
		}
		sctp->sctp_refcnt++;
		mutex_exit(&sctp->sctp_reflock);
		mutex_exit(&sctps->sctps_g_lock);
		if (sctp_prev != NULL)
			SCTP_REFRELE(sctp_prev);
		if (sctp->sctp_connp->conn_zoneid != myzoneid)
			goto next_sctp;
		if (sctp->sctp_state == SCTPS_ESTABLISHED ||
		    sctp->sctp_state == SCTPS_SHUTDOWN_PENDING ||
		    sctp->sctp_state == SCTPS_SHUTDOWN_RECEIVED) {
			/*
			 * Just bump the local sctp_mib.  The number of
			 * existing associations is not kept in kernel.
			 */
			BUMP_MIB(&sctp_mib, sctpCurrEstab);
		}

		if (sctp->sctp_opkts) {
			SCTPS_UPDATE_MIB(sctps, sctpOutSCTPPkts,
			    sctp->sctp_opkts);
			sctp->sctp_opkts = 0;
		}

		if (sctp->sctp_obchunks) {
			SCTPS_UPDATE_MIB(sctps, sctpOutCtrlChunks,
			    sctp->sctp_obchunks);
			UPDATE_LOCAL(sctp->sctp_cum_obchunks,
			    sctp->sctp_obchunks);
			sctp->sctp_obchunks = 0;
		}

		if (sctp->sctp_odchunks) {
			SCTPS_UPDATE_MIB(sctps, sctpOutOrderChunks,
			    sctp->sctp_odchunks);
			UPDATE_LOCAL(sctp->sctp_cum_odchunks,
			    sctp->sctp_odchunks);
			sctp->sctp_odchunks = 0;
		}

		if (sctp->sctp_oudchunks) {
			SCTPS_UPDATE_MIB(sctps, sctpOutUnorderChunks,
			    sctp->sctp_oudchunks);
			UPDATE_LOCAL(sctp->sctp_cum_oudchunks,
			    sctp->sctp_oudchunks);
			sctp->sctp_oudchunks = 0;
		}

		if (sctp->sctp_rxtchunks) {
			SCTPS_UPDATE_MIB(sctps, sctpRetransChunks,
			    sctp->sctp_rxtchunks);
			UPDATE_LOCAL(sctp->sctp_cum_rxtchunks,
			    sctp->sctp_rxtchunks);
			sctp->sctp_rxtchunks = 0;
		}

		if (sctp->sctp_ipkts) {
			SCTPS_UPDATE_MIB(sctps, sctpInSCTPPkts,
			    sctp->sctp_ipkts);
			sctp->sctp_ipkts = 0;
		}

		if (sctp->sctp_ibchunks) {
			SCTPS_UPDATE_MIB(sctps, sctpInCtrlChunks,
			    sctp->sctp_ibchunks);
			UPDATE_LOCAL(sctp->sctp_cum_ibchunks,
			    sctp->sctp_ibchunks);
			sctp->sctp_ibchunks = 0;
		}

		if (sctp->sctp_idchunks) {
			SCTPS_UPDATE_MIB(sctps, sctpInOrderChunks,
			    sctp->sctp_idchunks);
			UPDATE_LOCAL(sctp->sctp_cum_idchunks,
			    sctp->sctp_idchunks);
			sctp->sctp_idchunks = 0;
		}

		if (sctp->sctp_iudchunks) {
			SCTPS_UPDATE_MIB(sctps, sctpInUnorderChunks,
			    sctp->sctp_iudchunks);
			UPDATE_LOCAL(sctp->sctp_cum_iudchunks,
			    sctp->sctp_iudchunks);
			sctp->sctp_iudchunks = 0;
		}

		if (sctp->sctp_fragdmsgs) {
			SCTPS_UPDATE_MIB(sctps, sctpFragUsrMsgs,
			    sctp->sctp_fragdmsgs);
			sctp->sctp_fragdmsgs = 0;
		}

		if (sctp->sctp_reassmsgs) {
			SCTPS_UPDATE_MIB(sctps, sctpReasmUsrMsgs,
			    sctp->sctp_reassmsgs);
			sctp->sctp_reassmsgs = 0;
		}

next_sctp:
		sctp_prev = sctp;
		mutex_enter(&sctps->sctps_g_lock);
		sctp = list_next(&sctps->sctps_g_list, sctp);
	}
	mutex_exit(&sctps->sctps_g_lock);
	if (sctp_prev != NULL)
		SCTP_REFRELE(sctp_prev);

	sctp_sum_mib(sctps, &sctp_mib);

	/* Copy data from the SCTP MIB */
	sctpkp = (sctp_named_kstat_t *)kp->ks_data;

	/* These are from global ndd params. */
	sctpkp->sctpRtoMin.value.ui32 = sctps->sctps_rto_ming;
	sctpkp->sctpRtoMax.value.ui32 = sctps->sctps_rto_maxg;
	sctpkp->sctpRtoInitial.value.ui32 = sctps->sctps_rto_initialg;
	sctpkp->sctpValCookieLife.value.ui32 = sctps->sctps_cookie_life;
	sctpkp->sctpMaxInitRetr.value.ui32 = sctps->sctps_max_init_retr;

	/* Copy data from the local sctp_mib to the provided kstat. */
	sctpkp->sctpCurrEstab.value.i32 = sctp_mib.sctpCurrEstab;
	sctpkp->sctpActiveEstab.value.i32 = sctp_mib.sctpActiveEstab;
	sctpkp->sctpPassiveEstab.value.i32 = sctp_mib.sctpPassiveEstab;
	sctpkp->sctpAborted.value.i32 = sctp_mib.sctpAborted;
	sctpkp->sctpShutdowns.value.i32 = sctp_mib.sctpShutdowns;
	sctpkp->sctpOutOfBlue.value.i32 = sctp_mib.sctpOutOfBlue;
	sctpkp->sctpChecksumError.value.i32 = sctp_mib.sctpChecksumError;
	sctpkp->sctpOutCtrlChunks.value.i64 = sctp_mib.sctpOutCtrlChunks;
	sctpkp->sctpOutOrderChunks.value.i64 = sctp_mib.sctpOutOrderChunks;
	sctpkp->sctpOutUnorderChunks.value.i64 = sctp_mib.sctpOutUnorderChunks;
	sctpkp->sctpRetransChunks.value.i64 = sctp_mib.sctpRetransChunks;
	sctpkp->sctpOutAck.value.i32 = sctp_mib.sctpOutAck;
	sctpkp->sctpOutAckDelayed.value.i32 = sctp_mib.sctpOutAckDelayed;
	sctpkp->sctpOutWinUpdate.value.i32 = sctp_mib.sctpOutWinUpdate;
	sctpkp->sctpOutFastRetrans.value.i32 = sctp_mib.sctpOutFastRetrans;
	sctpkp->sctpOutWinProbe.value.i32 = sctp_mib.sctpOutWinProbe;
	sctpkp->sctpInCtrlChunks.value.i64 = sctp_mib.sctpInCtrlChunks;
	sctpkp->sctpInOrderChunks.value.i64 = sctp_mib.sctpInOrderChunks;
	sctpkp->sctpInUnorderChunks.value.i64 = sctp_mib.sctpInUnorderChunks;
	sctpkp->sctpInAck.value.i32 = sctp_mib.sctpInAck;
	sctpkp->sctpInDupAck.value.i32 = sctp_mib.sctpInDupAck;
	sctpkp->sctpInAckUnsent.value.i32 = sctp_mib.sctpInAckUnsent;
	sctpkp->sctpFragUsrMsgs.value.i64 = sctp_mib.sctpFragUsrMsgs;
	sctpkp->sctpReasmUsrMsgs.value.i64 = sctp_mib.sctpReasmUsrMsgs;
	sctpkp->sctpOutSCTPPkts.value.i64 = sctp_mib.sctpOutSCTPPkts;
	sctpkp->sctpInSCTPPkts.value.i64 = sctp_mib.sctpInSCTPPkts;
	sctpkp->sctpInInvalidCookie.value.i32 = sctp_mib.sctpInInvalidCookie;
	sctpkp->sctpTimRetrans.value.i32 = sctp_mib.sctpTimRetrans;
	sctpkp->sctpTimRetransDrop.value.i32 = sctp_mib.sctpTimRetransDrop;
	sctpkp->sctpTimHeartBeatProbe.value.i32 =
	    sctp_mib.sctpTimHeartBeatProbe;
	sctpkp->sctpTimHeartBeatDrop.value.i32 = sctp_mib.sctpTimHeartBeatDrop;
	sctpkp->sctpListenDrop.value.i32 = sctp_mib.sctpListenDrop;
	sctpkp->sctpInClosed.value.i32 = sctp_mib.sctpInClosed;

	netstack_rele(ns);
	return (0);
}

void *
sctp_kstat_init(netstackid_t stackid)
{
	kstat_t	*ksp;

	sctp_named_kstat_t template = {
		{ "sctpRtoAlgorithm",		KSTAT_DATA_INT32, 0 },
		{ "sctpRtoMin",			KSTAT_DATA_UINT32, 0 },
		{ "sctpRtoMax",			KSTAT_DATA_UINT32, 0 },
		{ "sctpRtoInitial",		KSTAT_DATA_UINT32, 0 },
		{ "sctpMaxAssocs",		KSTAT_DATA_INT32, 0 },
		{ "sctpValCookieLife",		KSTAT_DATA_UINT32, 0 },
		{ "sctpMaxInitRetr",		KSTAT_DATA_UINT32, 0 },
		{ "sctpCurrEstab",		KSTAT_DATA_INT32, 0 },
		{ "sctpActiveEstab",		KSTAT_DATA_INT32, 0 },
		{ "sctpPassiveEstab",		KSTAT_DATA_INT32, 0 },
		{ "sctpAborted",		KSTAT_DATA_INT32, 0 },
		{ "sctpShutdowns",		KSTAT_DATA_INT32, 0 },
		{ "sctpOutOfBlue",		KSTAT_DATA_INT32, 0 },
		{ "sctpChecksumError",		KSTAT_DATA_INT32, 0 },
		{ "sctpOutCtrlChunks",		KSTAT_DATA_INT64, 0 },
		{ "sctpOutOrderChunks",		KSTAT_DATA_INT64, 0 },
		{ "sctpOutUnorderChunks",	KSTAT_DATA_INT64, 0 },
		{ "sctpRetransChunks",		KSTAT_DATA_INT64, 0 },
		{ "sctpOutAck",			KSTAT_DATA_INT32, 0 },
		{ "sctpOutAckDelayed",		KSTAT_DATA_INT32, 0 },
		{ "sctpOutWinUpdate",		KSTAT_DATA_INT32, 0 },
		{ "sctpOutFastRetrans",		KSTAT_DATA_INT32, 0 },
		{ "sctpOutWinProbe",		KSTAT_DATA_INT32, 0 },
		{ "sctpInCtrlChunks",		KSTAT_DATA_INT64, 0 },
		{ "sctpInOrderChunks",		KSTAT_DATA_INT64, 0 },
		{ "sctpInUnorderChunks",	KSTAT_DATA_INT64, 0 },
		{ "sctpInAck",			KSTAT_DATA_INT32, 0 },
		{ "sctpInDupAck",		KSTAT_DATA_INT32, 0 },
		{ "sctpInAckUnsent",		KSTAT_DATA_INT32, 0 },
		{ "sctpFragUsrMsgs",		KSTAT_DATA_INT64, 0 },
		{ "sctpReasmUsrMsgs",		KSTAT_DATA_INT64, 0 },
		{ "sctpOutSCTPPkts",		KSTAT_DATA_INT64, 0 },
		{ "sctpInSCTPPkts",		KSTAT_DATA_INT64, 0 },
		{ "sctpInInvalidCookie",	KSTAT_DATA_INT32, 0 },
		{ "sctpTimRetrans",		KSTAT_DATA_INT32, 0 },
		{ "sctpTimRetransDrop",		KSTAT_DATA_INT32, 0 },
		{ "sctpTimHearBeatProbe",	KSTAT_DATA_INT32, 0 },
		{ "sctpTimHearBeatDrop",	KSTAT_DATA_INT32, 0 },
		{ "sctpListenDrop",		KSTAT_DATA_INT32, 0 },
		{ "sctpInClosed",		KSTAT_DATA_INT32, 0 }
	};

	ksp = kstat_create_netstack(SCTP_MOD_NAME, 0, "sctp", "mib2",
	    KSTAT_TYPE_NAMED, NUM_OF_FIELDS(sctp_named_kstat_t), 0, stackid);

	if (ksp == NULL)
		return (NULL);

	/* These won't change. */
	template.sctpRtoAlgorithm.value.i32 = MIB2_SCTP_RTOALGO_VANJ;
	template.sctpMaxAssocs.value.i32 = -1;

	bcopy(&template, ksp->ks_data, sizeof (template));
	ksp->ks_update = sctp_kstat_update;
	ksp->ks_private = (void *)(uintptr_t)stackid;

	kstat_install(ksp);
	return (ksp);
}

/*
 * To set all sctp_stat_t counters to 0.
 */
static void
sctp_clr_kstats2(sctp_kstat_t *stats)
{
	stats->sctp_add_faddr.value.ui64 = 0;
	stats->sctp_add_timer.value.ui64 = 0;
	stats->sctp_conn_create.value.ui64 = 0;
	stats->sctp_find_next_tq.value.ui64 = 0;
	stats->sctp_fr_add_hdr.value.ui64 = 0;
	stats->sctp_fr_not_found.value.ui64 = 0;
	stats->sctp_output_failed.value.ui64 = 0;
	stats->sctp_rexmit_failed.value.ui64 = 0;
	stats->sctp_send_init_failed.value.ui64 = 0;
	stats->sctp_send_cookie_failed.value.ui64 = 0;
	stats->sctp_send_cookie_ack_failed.value.ui64 = 0;
	stats->sctp_send_err_failed.value.ui64 = 0;
	stats->sctp_send_sack_failed.value.ui64 = 0;
	stats->sctp_send_shutdown_failed.value.ui64 = 0;
	stats->sctp_send_shutdown_ack_failed.value.ui64 = 0;
	stats->sctp_send_shutdown_comp_failed.value.ui64 = 0;
	stats->sctp_send_user_abort_failed.value.ui64 = 0;
	stats->sctp_send_asconf_failed.value.ui64 = 0;
	stats->sctp_send_asconf_ack_failed.value.ui64 = 0;
	stats->sctp_send_ftsn_failed.value.ui64 = 0;
	stats->sctp_send_hb_failed.value.ui64 = 0;
	stats->sctp_return_hb_failed.value.ui64 = 0;
	stats->sctp_ss_rexmit_failed.value.ui64 = 0;
	stats->sctp_cl_connect.value.ui64 = 0;
	stats->sctp_cl_assoc_change.value.ui64 = 0;
	stats->sctp_cl_check_addrs.value.ui64 = 0;
	stats->sctp_reclaim_cnt.value.ui64 = 0;
	stats->sctp_listen_cnt_drop.value.ui64 = 0;
}

/*
 * To add counters from the per CPU sctp_kstat_counter_t to the stack
 * sctp_kstat_t.
 */
static void
sctp_add_kstats2(sctp_kstat_counter_t *from, sctp_kstat_t *to)
{
	to->sctp_add_faddr.value.ui64 += from->sctp_add_faddr;
	to->sctp_add_timer.value.ui64 += from->sctp_add_timer;
	to->sctp_conn_create.value.ui64 += from->sctp_conn_create;
	to->sctp_find_next_tq.value.ui64 += from->sctp_find_next_tq;
	to->sctp_fr_add_hdr.value.ui64 += from->sctp_fr_add_hdr;
	to->sctp_fr_not_found.value.ui64 += from->sctp_fr_not_found;
	to->sctp_output_failed.value.ui64 += from->sctp_output_failed;
	to->sctp_rexmit_failed.value.ui64 += from->sctp_rexmit_failed;
	to->sctp_send_init_failed.value.ui64 += from->sctp_send_init_failed;
	to->sctp_send_cookie_failed.value.ui64 += from->sctp_send_cookie_failed;
	to->sctp_send_cookie_ack_failed.value.ui64 +=
	    from->sctp_send_cookie_ack_failed;
	to->sctp_send_err_failed.value.ui64 += from->sctp_send_err_failed;
	to->sctp_send_sack_failed.value.ui64 += from->sctp_send_sack_failed;
	to->sctp_send_shutdown_failed.value.ui64 +=
	    from->sctp_send_shutdown_failed;
	to->sctp_send_shutdown_ack_failed.value.ui64 +=
	    from->sctp_send_shutdown_ack_failed;
	to->sctp_send_shutdown_comp_failed.value.ui64 +=
	    from->sctp_send_shutdown_comp_failed;
	to->sctp_send_user_abort_failed.value.ui64 +=
	    from->sctp_send_user_abort_failed;
	to->sctp_send_asconf_failed.value.ui64 += from->sctp_send_asconf_failed;
	to->sctp_send_asconf_ack_failed.value.ui64 +=
	    from->sctp_send_asconf_ack_failed;
	to->sctp_send_ftsn_failed.value.ui64 += from->sctp_send_ftsn_failed;
	to->sctp_send_hb_failed.value.ui64 += from->sctp_send_hb_failed;
	to->sctp_return_hb_failed.value.ui64 += from->sctp_return_hb_failed;
	to->sctp_ss_rexmit_failed.value.ui64 += from->sctp_ss_rexmit_failed;
	to->sctp_cl_connect.value.ui64 += from->sctp_cl_connect;
	to->sctp_cl_assoc_change.value.ui64 += from->sctp_cl_assoc_change;
	to->sctp_cl_check_addrs.value.ui64 += from->sctp_cl_check_addrs;
}

/*
 * Sum up all per CPU tcp_stat_t kstat counters.
 */
static int
sctp_kstat2_update(kstat_t *kp, int rw)
{
	netstackid_t	stackid = (netstackid_t)(uintptr_t)kp->ks_private;
	netstack_t	*ns;
	sctp_stack_t	*sctps;
	sctp_kstat_t	*stats;
	int		i;
	int		cnt;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	ns = netstack_find_by_stackid(stackid);
	if (ns == NULL)
		return (-1);
	sctps = ns->netstack_sctp;
	if (sctps == NULL) {
		netstack_rele(ns);
		return (-1);
	}

	stats = (sctp_kstat_t *)kp->ks_data;
	sctp_clr_kstats2(stats);

	/*
	 * sctps_sc_cnt may change in the middle of the loop.  It is better
	 * to get its value first.
	 */
	cnt = sctps->sctps_sc_cnt;
	for (i = 0; i < cnt; i++)
		sctp_add_kstats2(&sctps->sctps_sc[i]->sctp_sc_stats, stats);

	netstack_rele(ns);
	return (0);
}

/*
 * The following kstats are for debugging purposes.  They keep
 * track of problems which should not happen normally.  But in
 * those cases which they do happen, these kstats would be handy
 * for engineers to diagnose the problems.  They are not intended
 * to be consumed by customers.
 */
void *
sctp_kstat2_init(netstackid_t stackid)
{
	kstat_t *ksp;

	sctp_kstat_t template = {
		{ "sctp_add_faddr",			KSTAT_DATA_UINT64 },
		{ "sctp_add_timer",			KSTAT_DATA_UINT64 },
		{ "sctp_conn_create",			KSTAT_DATA_UINT64 },
		{ "sctp_find_next_tq",			KSTAT_DATA_UINT64 },
		{ "sctp_fr_add_hdr",			KSTAT_DATA_UINT64 },
		{ "sctp_fr_not_found",			KSTAT_DATA_UINT64 },
		{ "sctp_output_failed",			KSTAT_DATA_UINT64 },
		{ "sctp_rexmit_failed",			KSTAT_DATA_UINT64 },
		{ "sctp_send_init_failed",		KSTAT_DATA_UINT64 },
		{ "sctp_send_cookie_failed",		KSTAT_DATA_UINT64 },
		{ "sctp_send_cookie_ack_failed",	KSTAT_DATA_UINT64 },
		{ "sctp_send_err_failed",		KSTAT_DATA_UINT64 },
		{ "sctp_send_sack_failed",		KSTAT_DATA_UINT64 },
		{ "sctp_send_shutdown_failed",		KSTAT_DATA_UINT64 },
		{ "sctp_send_shutdown_ack_failed",	KSTAT_DATA_UINT64 },
		{ "sctp_send_shutdown_comp_failed",	KSTAT_DATA_UINT64 },
		{ "sctp_send_user_abort_failed",	KSTAT_DATA_UINT64 },
		{ "sctp_send_asconf_failed",		KSTAT_DATA_UINT64 },
		{ "sctp_send_asconf_ack_failed",	KSTAT_DATA_UINT64 },
		{ "sctp_send_ftsn_failed",		KSTAT_DATA_UINT64 },
		{ "sctp_send_hb_failed",		KSTAT_DATA_UINT64 },
		{ "sctp_return_hb_failed",		KSTAT_DATA_UINT64 },
		{ "sctp_ss_rexmit_failed",		KSTAT_DATA_UINT64 },
		{ "sctp_cl_connect",			KSTAT_DATA_UINT64 },
		{ "sctp_cl_assoc_change",		KSTAT_DATA_UINT64 },
		{ "sctp_cl_check_addrs",		KSTAT_DATA_UINT64 },
		{ "sctp_reclaim_drop",			KSTAT_DATA_UINT64 },
		{ "sctp_listen_cnt_drop",		KSTAT_DATA_UINT64 },
	};

	ksp = kstat_create_netstack(SCTP_MOD_NAME, 0, "sctpstat", "net",
	    KSTAT_TYPE_NAMED, NUM_OF_FIELDS(template), 0, stackid);

	if (ksp == NULL)
		return (NULL);

	bcopy(&template, ksp->ks_data, sizeof (template));
	ksp->ks_private = (void *)(uintptr_t)stackid;
	ksp->ks_update = sctp_kstat2_update;

	kstat_install(ksp);
	return (ksp);
}

void
sctp_kstat_fini(netstackid_t stackid, kstat_t *ksp)
{
	if (ksp != NULL) {
		ASSERT(stackid == (netstackid_t)(uintptr_t)ksp->ks_private);
		kstat_delete_netstack(ksp, stackid);
	}
}

void
sctp_kstat2_fini(netstackid_t stackid, kstat_t *ksp)
{
	if (ksp != NULL) {
		ASSERT(stackid == (netstackid_t)(uintptr_t)ksp->ks_private);
		kstat_delete_netstack(ksp, stackid);
	}
}

/*
 * Return SNMP global stats in buffer in mpdata.
 * Return associatiation table in mp_conn_data,
 * local address table in mp_local_data, and
 * remote address table in mp_rem_data.
 */
mblk_t *
sctp_snmp_get_mib2(queue_t *q, mblk_t *mpctl, sctp_stack_t *sctps)
{
	mblk_t			*mpdata, *mp_ret;
	mblk_t			*mp_conn_ctl = NULL;
	mblk_t			*mp_conn_data;
	mblk_t			*mp_conn_tail = NULL;
	mblk_t			*mp_local_ctl = NULL;
	mblk_t			*mp_local_data;
	mblk_t			*mp_local_tail = NULL;
	mblk_t			*mp_rem_ctl = NULL;
	mblk_t			*mp_rem_data;
	mblk_t			*mp_rem_tail = NULL;
	mblk_t			*mp_attr_ctl = NULL;
	mblk_t			*mp_attr_data;
	mblk_t			*mp_attr_tail = NULL;
	struct opthdr		*optp;
	sctp_t			*sctp, *sctp_prev = NULL;
	sctp_faddr_t		*fp;
	mib2_sctpConnEntry_t	sce;
	mib2_sctpConnLocalEntry_t	scle;
	mib2_sctpConnRemoteEntry_t	scre;
	mib2_transportMLPEntry_t	mlp;
	int			i;
	int			l;
	int			scanned = 0;
	zoneid_t		zoneid = Q_TO_CONN(q)->conn_zoneid;
	conn_t			*connp;
	boolean_t		needattr;
	int			idx;
	mib2_sctp_t		sctp_mib;

	/*
	 * Make copies of the original message.
	 * mpctl will hold SCTP counters,
	 * mp_conn_ctl will hold list of connections.
	 */
	mp_ret = copymsg(mpctl);
	mp_conn_ctl = copymsg(mpctl);
	mp_local_ctl = copymsg(mpctl);
	mp_rem_ctl = copymsg(mpctl);
	mp_attr_ctl = copymsg(mpctl);

	mpdata = mpctl->b_cont;

	if (mp_conn_ctl == NULL || mp_local_ctl == NULL ||
	    mp_rem_ctl == NULL || mp_attr_ctl == NULL || mpdata == NULL) {
		freemsg(mp_attr_ctl);
		freemsg(mp_rem_ctl);
		freemsg(mp_local_ctl);
		freemsg(mp_conn_ctl);
		freemsg(mp_ret);
		freemsg(mpctl);
		return (NULL);
	}
	mp_conn_data = mp_conn_ctl->b_cont;
	mp_local_data = mp_local_ctl->b_cont;
	mp_rem_data = mp_rem_ctl->b_cont;
	mp_attr_data = mp_attr_ctl->b_cont;

	bzero(&sctp_mib, sizeof (sctp_mib));

	/* hostname address parameters are not supported in Solaris */
	sce.sctpAssocRemHostName.o_length = 0;
	sce.sctpAssocRemHostName.o_bytes[0] = 0;

	/* build table of connections -- need count in fixed part */

	idx = 0;
	mutex_enter(&sctps->sctps_g_lock);
	sctp = list_head(&sctps->sctps_g_list);
	while (sctp != NULL) {
		mutex_enter(&sctp->sctp_reflock);
		if (sctp->sctp_condemned) {
			mutex_exit(&sctp->sctp_reflock);
			sctp = list_next(&sctps->sctps_g_list, sctp);
			continue;
		}
		sctp->sctp_refcnt++;
		mutex_exit(&sctp->sctp_reflock);
		mutex_exit(&sctps->sctps_g_lock);
		if (sctp_prev != NULL)
			SCTP_REFRELE(sctp_prev);
		if (sctp->sctp_connp->conn_zoneid != zoneid)
			goto next_sctp;
		if (sctp->sctp_state == SCTPS_ESTABLISHED ||
		    sctp->sctp_state == SCTPS_SHUTDOWN_PENDING ||
		    sctp->sctp_state == SCTPS_SHUTDOWN_RECEIVED) {
			/*
			 * Just bump the local sctp_mib.  The number of
			 * existing associations is not kept in kernel.
			 */
			BUMP_MIB(&sctp_mib, sctpCurrEstab);
		}
		SCTPS_UPDATE_MIB(sctps, sctpOutSCTPPkts, sctp->sctp_opkts);
		sctp->sctp_opkts = 0;
		SCTPS_UPDATE_MIB(sctps, sctpOutCtrlChunks, sctp->sctp_obchunks);
		UPDATE_LOCAL(sctp->sctp_cum_obchunks,
		    sctp->sctp_obchunks);
		sctp->sctp_obchunks = 0;
		SCTPS_UPDATE_MIB(sctps, sctpOutOrderChunks,
		    sctp->sctp_odchunks);
		UPDATE_LOCAL(sctp->sctp_cum_odchunks,
		    sctp->sctp_odchunks);
		sctp->sctp_odchunks = 0;
		SCTPS_UPDATE_MIB(sctps, sctpOutUnorderChunks,
		    sctp->sctp_oudchunks);
		UPDATE_LOCAL(sctp->sctp_cum_oudchunks,
		    sctp->sctp_oudchunks);
		sctp->sctp_oudchunks = 0;
		SCTPS_UPDATE_MIB(sctps, sctpRetransChunks,
		    sctp->sctp_rxtchunks);
		UPDATE_LOCAL(sctp->sctp_cum_rxtchunks,
		    sctp->sctp_rxtchunks);
		sctp->sctp_rxtchunks = 0;
		SCTPS_UPDATE_MIB(sctps, sctpInSCTPPkts, sctp->sctp_ipkts);
		sctp->sctp_ipkts = 0;
		SCTPS_UPDATE_MIB(sctps, sctpInCtrlChunks, sctp->sctp_ibchunks);
		UPDATE_LOCAL(sctp->sctp_cum_ibchunks,
		    sctp->sctp_ibchunks);
		sctp->sctp_ibchunks = 0;
		SCTPS_UPDATE_MIB(sctps, sctpInOrderChunks, sctp->sctp_idchunks);
		UPDATE_LOCAL(sctp->sctp_cum_idchunks,
		    sctp->sctp_idchunks);
		sctp->sctp_idchunks = 0;
		SCTPS_UPDATE_MIB(sctps, sctpInUnorderChunks,
		    sctp->sctp_iudchunks);
		UPDATE_LOCAL(sctp->sctp_cum_iudchunks,
		    sctp->sctp_iudchunks);
		sctp->sctp_iudchunks = 0;
		SCTPS_UPDATE_MIB(sctps, sctpFragUsrMsgs, sctp->sctp_fragdmsgs);
		sctp->sctp_fragdmsgs = 0;
		SCTPS_UPDATE_MIB(sctps, sctpReasmUsrMsgs, sctp->sctp_reassmsgs);
		sctp->sctp_reassmsgs = 0;

		sce.sctpAssocId = ntohl(sctp->sctp_lvtag);
		sce.sctpAssocLocalPort = ntohs(sctp->sctp_connp->conn_lport);
		sce.sctpAssocRemPort = ntohs(sctp->sctp_connp->conn_fport);

		RUN_SCTP(sctp);
		if (sctp->sctp_primary != NULL) {
			fp = sctp->sctp_primary;

			if (IN6_IS_ADDR_V4MAPPED(&fp->sf_faddr)) {
				sce.sctpAssocRemPrimAddrType =
				    MIB2_SCTP_ADDR_V4;
			} else {
				sce.sctpAssocRemPrimAddrType =
				    MIB2_SCTP_ADDR_V6;
			}
			sce.sctpAssocRemPrimAddr = fp->sf_faddr;
			sce.sctpAssocLocPrimAddr = fp->sf_saddr;
			sce.sctpAssocHeartBeatInterval = TICK_TO_MSEC(
			    fp->sf_hb_interval);
		} else {
			sce.sctpAssocRemPrimAddrType = MIB2_SCTP_ADDR_V4;
			bzero(&sce.sctpAssocRemPrimAddr,
			    sizeof (sce.sctpAssocRemPrimAddr));
			bzero(&sce.sctpAssocLocPrimAddr,
			    sizeof (sce.sctpAssocLocPrimAddr));
			sce.sctpAssocHeartBeatInterval =
			    sctps->sctps_heartbeat_interval;
		}

		/*
		 * Table for local addresses
		 */
		scanned = 0;
		for (i = 0; i < SCTP_IPIF_HASH; i++) {
			sctp_saddr_ipif_t	*obj;

			if (sctp->sctp_saddrs[i].ipif_count == 0)
				continue;
			obj = list_head(&sctp->sctp_saddrs[i].sctp_ipif_list);
			for (l = 0; l < sctp->sctp_saddrs[i].ipif_count; l++) {
				sctp_ipif_t	*sctp_ipif;
				in6_addr_t	addr;

				sctp_ipif = obj->saddr_ipifp;
				addr = sctp_ipif->sctp_ipif_saddr;
				scanned++;
				scle.sctpAssocId = ntohl(sctp->sctp_lvtag);
				if (IN6_IS_ADDR_V4MAPPED(&addr)) {
					scle.sctpAssocLocalAddrType =
					    MIB2_SCTP_ADDR_V4;
				} else {
					scle.sctpAssocLocalAddrType =
					    MIB2_SCTP_ADDR_V6;
				}
				scle.sctpAssocLocalAddr = addr;
				(void) snmp_append_data2(mp_local_data,
				    &mp_local_tail, (char *)&scle,
				    sizeof (scle));
				if (scanned >= sctp->sctp_nsaddrs)
					goto done;
				obj = list_next(&sctp->
				    sctp_saddrs[i].sctp_ipif_list, obj);
			}
		}
done:
		/*
		 * Table for remote addresses
		 */
		for (fp = sctp->sctp_faddrs; fp; fp = fp->sf_next) {
			scre.sctpAssocId = ntohl(sctp->sctp_lvtag);
			if (IN6_IS_ADDR_V4MAPPED(&fp->sf_faddr)) {
				scre.sctpAssocRemAddrType = MIB2_SCTP_ADDR_V4;
			} else {
				scre.sctpAssocRemAddrType = MIB2_SCTP_ADDR_V6;
			}
			scre.sctpAssocRemAddr = fp->sf_faddr;
			if (fp->sf_state == SCTP_FADDRS_ALIVE) {
				scre.sctpAssocRemAddrActive =
				    scre.sctpAssocRemAddrHBActive =
				    MIB2_SCTP_ACTIVE;
			} else {
				scre.sctpAssocRemAddrActive =
				    scre.sctpAssocRemAddrHBActive =
				    MIB2_SCTP_INACTIVE;
			}
			scre.sctpAssocRemAddrRTO = TICK_TO_MSEC(fp->sf_rto);
			scre.sctpAssocRemAddrMaxPathRtx = fp->sf_max_retr;
			scre.sctpAssocRemAddrRtx = fp->sf_T3expire;
			(void) snmp_append_data2(mp_rem_data, &mp_rem_tail,
			    (char *)&scre, sizeof (scre));
		}
		connp = sctp->sctp_connp;
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
		if (sctp->sctp_connp->conn_ixa->ixa_tsl != NULL) {
			ts_label_t *tsl;

			tsl = sctp->sctp_connp->conn_ixa->ixa_tsl;
			mlp.tme_flags |= MIB2_TMEF_IS_LABELED;
			mlp.tme_doi = label2doi(tsl);
			mlp.tme_label = *label2bslabel(tsl);
			needattr = B_TRUE;
		}
		WAKE_SCTP(sctp);
		sce.sctpAssocState = sctp_snmp_state(sctp);
		sce.sctpAssocInStreams = sctp->sctp_num_istr;
		sce.sctpAssocOutStreams = sctp->sctp_num_ostr;
		sce.sctpAssocMaxRetr = sctp->sctp_pa_max_rxt;
		/* A 0 here indicates that no primary process is known */
		sce.sctpAssocPrimProcess = 0;
		sce.sctpAssocT1expired = sctp->sctp_T1expire;
		sce.sctpAssocT2expired = sctp->sctp_T2expire;
		sce.sctpAssocRtxChunks = sctp->sctp_T3expire;
		sce.sctpAssocStartTime = sctp->sctp_assoc_start_time;
		sce.sctpConnEntryInfo.ce_sendq = sctp->sctp_unacked +
		    sctp->sctp_unsent;
		sce.sctpConnEntryInfo.ce_recvq = sctp->sctp_rxqueued;
		sce.sctpConnEntryInfo.ce_swnd = sctp->sctp_frwnd;
		sce.sctpConnEntryInfo.ce_rwnd = sctp->sctp_rwnd;
		sce.sctpConnEntryInfo.ce_mss = sctp->sctp_mss;
		(void) snmp_append_data2(mp_conn_data, &mp_conn_tail,
		    (char *)&sce, sizeof (sce));
		mlp.tme_connidx = idx++;
		if (needattr)
			(void) snmp_append_data2(mp_attr_ctl->b_cont,
			    &mp_attr_tail, (char *)&mlp, sizeof (mlp));
next_sctp:
		sctp_prev = sctp;
		mutex_enter(&sctps->sctps_g_lock);
		sctp = list_next(&sctps->sctps_g_list, sctp);
	}
	mutex_exit(&sctps->sctps_g_lock);
	if (sctp_prev != NULL)
		SCTP_REFRELE(sctp_prev);

	sctp_sum_mib(sctps, &sctp_mib);

	optp = (struct opthdr *)&mpctl->b_rptr[sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_SCTP;
	optp->name = 0;
	(void) snmp_append_data(mpdata, (char *)&sctp_mib, sizeof (sctp_mib));
	optp->len = msgdsize(mpdata);
	qreply(q, mpctl);

	/* table of connections... */
	optp = (struct opthdr *)&mp_conn_ctl->b_rptr[
	    sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_SCTP;
	optp->name = MIB2_SCTP_CONN;
	optp->len = msgdsize(mp_conn_data);
	qreply(q, mp_conn_ctl);

	/* assoc local address table */
	optp = (struct opthdr *)&mp_local_ctl->b_rptr[
	    sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_SCTP;
	optp->name = MIB2_SCTP_CONN_LOCAL;
	optp->len = msgdsize(mp_local_data);
	qreply(q, mp_local_ctl);

	/* assoc remote address table */
	optp = (struct opthdr *)&mp_rem_ctl->b_rptr[
	    sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_SCTP;
	optp->name = MIB2_SCTP_CONN_REMOTE;
	optp->len = msgdsize(mp_rem_data);
	qreply(q, mp_rem_ctl);

	/* table of MLP attributes */
	optp = (struct opthdr *)&mp_attr_ctl->b_rptr[
	    sizeof (struct T_optmgmt_ack)];
	optp->level = MIB2_SCTP;
	optp->name = EXPER_XPORT_MLP;
	optp->len = msgdsize(mp_attr_data);
	if (optp->len == 0)
		freemsg(mp_attr_ctl);
	else
		qreply(q, mp_attr_ctl);

	return (mp_ret);
}

/* Translate SCTP state to MIB2 SCTP state. */
static int
sctp_snmp_state(sctp_t *sctp)
{
	if (sctp == NULL)
		return (0);

	switch (sctp->sctp_state) {
	case SCTPS_IDLE:
	case SCTPS_BOUND:
		return (MIB2_SCTP_closed);
	case SCTPS_LISTEN:
		return (MIB2_SCTP_listen);
	case SCTPS_COOKIE_WAIT:
		return (MIB2_SCTP_cookieWait);
	case SCTPS_COOKIE_ECHOED:
		return (MIB2_SCTP_cookieEchoed);
	case SCTPS_ESTABLISHED:
		return (MIB2_SCTP_established);
	case SCTPS_SHUTDOWN_PENDING:
		return (MIB2_SCTP_shutdownPending);
	case SCTPS_SHUTDOWN_SENT:
		return (MIB2_SCTP_shutdownSent);
	case SCTPS_SHUTDOWN_RECEIVED:
		return (MIB2_SCTP_shutdownReceived);
	case SCTPS_SHUTDOWN_ACK_SENT:
		return (MIB2_SCTP_shutdownAckSent);
	default:
		return (0);
	}
}

/*
 * To sum up all MIB2 stats for a sctp_stack_t from all per CPU stats.  The
 * caller should initialize the target mib2_sctp_t properly as this function
 * just adds up all the per CPU stats.
 */
static void
sctp_sum_mib(sctp_stack_t *sctps, mib2_sctp_t *sctp_mib)
{
	int i;
	int cnt;

	/* Static componets of mib2_sctp_t. */
	SET_MIB(sctp_mib->sctpRtoAlgorithm, MIB2_SCTP_RTOALGO_VANJ);
	SET_MIB(sctp_mib->sctpRtoMin, sctps->sctps_rto_ming);
	SET_MIB(sctp_mib->sctpRtoMax, sctps->sctps_rto_maxg);
	SET_MIB(sctp_mib->sctpRtoInitial, sctps->sctps_rto_initialg);
	SET_MIB(sctp_mib->sctpMaxAssocs, -1);
	SET_MIB(sctp_mib->sctpValCookieLife, sctps->sctps_cookie_life);
	SET_MIB(sctp_mib->sctpMaxInitRetr, sctps->sctps_max_init_retr);

	/* fixed length structure for IPv4 and IPv6 counters */
	SET_MIB(sctp_mib->sctpEntrySize, sizeof (mib2_sctpConnEntry_t));
	SET_MIB(sctp_mib->sctpLocalEntrySize,
	    sizeof (mib2_sctpConnLocalEntry_t));
	SET_MIB(sctp_mib->sctpRemoteEntrySize,
	    sizeof (mib2_sctpConnRemoteEntry_t));

	/*
	 * sctps_sc_cnt may change in the middle of the loop.  It is better
	 * to get its value first.
	 */
	cnt = sctps->sctps_sc_cnt;
	for (i = 0; i < cnt; i++)
		sctp_add_mib(&sctps->sctps_sc[i]->sctp_sc_mib, sctp_mib);
}

static void
sctp_add_mib(mib2_sctp_t *from, mib2_sctp_t *to)
{
	to->sctpActiveEstab += from->sctpActiveEstab;
	to->sctpPassiveEstab += from->sctpPassiveEstab;
	to->sctpAborted += from->sctpAborted;
	to->sctpShutdowns += from->sctpShutdowns;
	to->sctpOutOfBlue += from->sctpOutOfBlue;
	to->sctpChecksumError += from->sctpChecksumError;
	to->sctpOutCtrlChunks += from->sctpOutCtrlChunks;
	to->sctpOutOrderChunks += from->sctpOutOrderChunks;
	to->sctpOutUnorderChunks += from->sctpOutUnorderChunks;
	to->sctpRetransChunks += from->sctpRetransChunks;
	to->sctpOutAck += from->sctpOutAck;
	to->sctpOutAckDelayed += from->sctpOutAckDelayed;
	to->sctpOutWinUpdate += from->sctpOutWinUpdate;
	to->sctpOutFastRetrans += from->sctpOutFastRetrans;
	to->sctpOutWinProbe += from->sctpOutWinProbe;
	to->sctpInCtrlChunks += from->sctpInCtrlChunks;
	to->sctpInOrderChunks += from->sctpInOrderChunks;
	to->sctpInUnorderChunks += from->sctpInUnorderChunks;
	to->sctpInAck += from->sctpInAck;
	to->sctpInDupAck += from->sctpInDupAck;
	to->sctpInAckUnsent += from->sctpInAckUnsent;
	to->sctpFragUsrMsgs += from->sctpFragUsrMsgs;
	to->sctpReasmUsrMsgs += from->sctpReasmUsrMsgs;
	to->sctpOutSCTPPkts += from->sctpOutSCTPPkts;
	to->sctpInSCTPPkts += from->sctpInSCTPPkts;
	to->sctpInInvalidCookie += from->sctpInInvalidCookie;
	to->sctpTimRetrans += from->sctpTimRetrans;
	to->sctpTimRetransDrop += from->sctpTimRetransDrop;
	to->sctpTimHeartBeatProbe += from->sctpTimHeartBeatProbe;
	to->sctpTimHeartBeatDrop += from->sctpTimHeartBeatDrop;
	to->sctpListenDrop += from->sctpListenDrop;
	to->sctpInClosed += from->sctpInClosed;
}
