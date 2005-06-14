/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/cmn_err.h>
#define	_SUN_TPI_VERSION 2
#include <sys/tihdr.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <netinet/in.h>

#include <inet/common.h>
#include <inet/ip.h>
#include <inet/mib2.h>
#include <inet/snmpcom.h>
#include <inet/kstatcom.h>
#include <inet/ipclassifier.h>
#include "sctp_impl.h"
#include "sctp_addr.h"

mib2_sctp_t	sctp_mib;
kstat_t		*sctp_mibkp;	/* kstat exporting sctp_mib data */

static int sctp_snmp_state(sctp_t *sctp);

static int
sctp_kstat_update(kstat_t *kp, int rw)
{
	sctp_named_kstat_t	*sctpkp;
	sctp_t			*sctp, *sctp_prev;
	zoneid_t		zoneid;

	if (kp == NULL|| kp->ks_data == NULL)
		return (EIO);

	if (rw == KSTAT_WRITE)
		return (EACCES);

	zoneid = getzoneid();

	/*
	 * Get the number of current associations and gather their
	 * individual set of statistics.
	 */
	SET_MIB(sctp_mib.sctpCurrEstab, 0);
	sctp = gsctp;
	sctp_prev = NULL;
	mutex_enter(&sctp_g_lock);
	while (sctp != NULL) {
		mutex_enter(&sctp->sctp_reflock);
		if (sctp->sctp_condemned) {
			mutex_exit(&sctp->sctp_reflock);
			sctp = list_next(&sctp_g_list, sctp);
			continue;
		}
		sctp->sctp_refcnt++;
		mutex_exit(&sctp->sctp_reflock);
		mutex_exit(&sctp_g_lock);
		if (sctp_prev != NULL)
			SCTP_REFRELE(sctp_prev);
		if (sctp->sctp_connp->conn_zoneid != zoneid)
			goto next_sctp;
		if (sctp->sctp_state == SCTPS_ESTABLISHED ||
		    sctp->sctp_state == SCTPS_SHUTDOWN_PENDING ||
		    sctp->sctp_state == SCTPS_SHUTDOWN_RECEIVED) {
			BUMP_MIB(&sctp_mib, sctpCurrEstab);
		}

		if (sctp->sctp_opkts) {
			UPDATE_MIB(&sctp_mib, sctpOutSCTPPkts,
			    sctp->sctp_opkts);
			sctp->sctp_opkts = 0;
		}

		if (sctp->sctp_obchunks) {
			UPDATE_MIB(&sctp_mib, sctpOutCtrlChunks,
			    sctp->sctp_obchunks);
			sctp->sctp_obchunks = 0;
		}

		if (sctp->sctp_odchunks) {
			UPDATE_MIB(&sctp_mib, sctpOutOrderChunks,
			    sctp->sctp_odchunks);
			sctp->sctp_odchunks = 0;
		}

		if (sctp->sctp_oudchunks) {
			UPDATE_MIB(&sctp_mib, sctpOutUnorderChunks,
			    sctp->sctp_oudchunks);
			sctp->sctp_oudchunks = 0;
		}

		if (sctp->sctp_rxtchunks) {
			UPDATE_MIB(&sctp_mib, sctpRetransChunks,
			    sctp->sctp_rxtchunks);
			sctp->sctp_rxtchunks = 0;
		}

		if (sctp->sctp_ipkts) {
			UPDATE_MIB(&sctp_mib, sctpInSCTPPkts, sctp->sctp_ipkts);
			sctp->sctp_ipkts = 0;
		}

		if (sctp->sctp_ibchunks) {
			UPDATE_MIB(&sctp_mib, sctpInCtrlChunks,
			    sctp->sctp_ibchunks);
			sctp->sctp_ibchunks = 0;
		}

		if (sctp->sctp_idchunks) {
			UPDATE_MIB(&sctp_mib, sctpInOrderChunks,
			    sctp->sctp_idchunks);
			sctp->sctp_idchunks = 0;
		}

		if (sctp->sctp_iudchunks) {
			UPDATE_MIB(&sctp_mib, sctpInUnorderChunks,
			    sctp->sctp_iudchunks);
			sctp->sctp_iudchunks = 0;
		}

		if (sctp->sctp_fragdmsgs) {
			UPDATE_MIB(&sctp_mib, sctpFragUsrMsgs,
			    sctp->sctp_fragdmsgs);
			sctp->sctp_fragdmsgs = 0;
		}

		if (sctp->sctp_reassmsgs) {
			UPDATE_MIB(&sctp_mib, sctpReasmUsrMsgs,
			    sctp->sctp_reassmsgs);
			sctp->sctp_reassmsgs = 0;
		}

next_sctp:
		sctp_prev = sctp;
		mutex_enter(&sctp_g_lock);
		sctp = list_next(&sctp_g_list, sctp);
	}
	mutex_exit(&sctp_g_lock);
	if (sctp_prev != NULL)
		SCTP_REFRELE(sctp_prev);

	/* Copy data from the SCTP MIB */
	sctpkp = (sctp_named_kstat_t *)kp->ks_data;

	/* These are from global ndd params. */
	sctpkp->sctpRtoMin.value.ui32 = sctp_rto_ming;
	sctpkp->sctpRtoMax.value.ui32 = sctp_rto_maxg;
	sctpkp->sctpRtoInitial.value.ui32 = sctp_rto_initialg;
	sctpkp->sctpValCookieLife.value.ui32 = sctp_cookie_life;
	sctpkp->sctpMaxInitRetr.value.ui32 = sctp_max_init_retr;

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

	return (0);
}

void
sctp_kstat_init(void)
{
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

	sctp_mibkp = kstat_create("sctp", 0, "sctp", "mib2", KSTAT_TYPE_NAMED,
	    NUM_OF_FIELDS(sctp_named_kstat_t), 0);

	if (sctp_mibkp == NULL)
		return;

	/* These won't change. */
	template.sctpRtoAlgorithm.value.i32 = MIB2_SCTP_RTOALGO_VANJ;
	template.sctpMaxAssocs.value.i32 = -1;

	bcopy(&template, sctp_mibkp->ks_data, sizeof (template));

	sctp_mibkp->ks_update = sctp_kstat_update;

	kstat_install(sctp_mibkp);
}

void
sctp_kstat_fini(void)
{
	if (sctp_mibkp != NULL) {
		kstat_delete(sctp_mibkp);
		sctp_mibkp = NULL;
	}
}

/*
 * Return SNMP global stats in buffer in mpdata.
 * Return associatiation table in mp_conn_data,
 * local address table in mp_local_data, and
 * remote address table in mp_rem_data.
 */
mblk_t *
sctp_snmp_get_mib2(queue_t *q, mblk_t *mpctl)
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
	struct opthdr		*optp;
	sctp_t			*sctp, *sctp_prev = NULL;
	sctp_faddr_t		*fp;
	mib2_sctpConnEntry_t	sce;
	mib2_sctpConnLocalEntry_t	scle;
	mib2_sctpConnRemoteEntry_t	scre;
	int			i;
	int			l;
	int			scanned = 0;
	zoneid_t		zoneid = Q_TO_CONN(q)->conn_zoneid;

	/*
	 * Make copies of the original message.
	 * mpctl will hold SCTP counters,
	 * mp_conn_ctl will hold list of connections.
	 */
	mp_ret = copymsg(mpctl);
	mp_conn_ctl = copymsg(mpctl);
	mp_local_ctl = copymsg(mpctl);
	mp_rem_ctl = copymsg(mpctl);

	mpdata = mpctl->b_cont;

	if (!mp_conn_ctl || !mp_local_ctl || !mp_rem_ctl || !mpdata) {
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

	/* hostname address parameters are not supported in Solaris */
	sce.sctpAssocRemHostName.o_length = 0;
	sce.sctpAssocRemHostName.o_bytes[0] = 0;

	/* build table of connections -- need count in fixed part */
	SET_MIB(sctp_mib.sctpRtoAlgorithm, MIB2_SCTP_RTOALGO_VANJ);
	SET_MIB(sctp_mib.sctpRtoMin, sctp_rto_ming);
	SET_MIB(sctp_mib.sctpRtoMax, sctp_rto_maxg);
	SET_MIB(sctp_mib.sctpRtoInitial, sctp_rto_initialg);
	SET_MIB(sctp_mib.sctpMaxAssocs, -1);
	SET_MIB(sctp_mib.sctpValCookieLife, sctp_cookie_life);
	SET_MIB(sctp_mib.sctpMaxInitRetr, sctp_max_init_retr);
	SET_MIB(sctp_mib.sctpCurrEstab, 0);

	sctp = gsctp;
	mutex_enter(&sctp_g_lock);
	while (sctp != NULL) {
		mutex_enter(&sctp->sctp_reflock);
		if (sctp->sctp_condemned) {
			mutex_exit(&sctp->sctp_reflock);
			sctp = list_next(&sctp_g_list, sctp);
			continue;
		}
		sctp->sctp_refcnt++;
		mutex_exit(&sctp->sctp_reflock);
		mutex_exit(&sctp_g_lock);
		if (sctp_prev != NULL)
			SCTP_REFRELE(sctp_prev);
		if (sctp->sctp_connp->conn_zoneid != zoneid)
			goto next_sctp;
		if (sctp->sctp_state == SCTPS_ESTABLISHED ||
		    sctp->sctp_state == SCTPS_SHUTDOWN_PENDING ||
		    sctp->sctp_state == SCTPS_SHUTDOWN_RECEIVED) {
			BUMP_MIB(&sctp_mib, sctpCurrEstab);
		}
		UPDATE_MIB(&sctp_mib, sctpOutSCTPPkts, sctp->sctp_opkts);
		sctp->sctp_opkts = 0;
		UPDATE_MIB(&sctp_mib, sctpOutCtrlChunks, sctp->sctp_obchunks);
		sctp->sctp_obchunks = 0;
		UPDATE_MIB(&sctp_mib, sctpOutOrderChunks, sctp->sctp_odchunks);
		sctp->sctp_odchunks = 0;
		UPDATE_MIB(&sctp_mib, sctpOutUnorderChunks,
		    sctp->sctp_oudchunks);
		sctp->sctp_oudchunks = 0;
		UPDATE_MIB(&sctp_mib, sctpRetransChunks, sctp->sctp_rxtchunks);
		sctp->sctp_rxtchunks = 0;
		UPDATE_MIB(&sctp_mib, sctpInSCTPPkts, sctp->sctp_ipkts);
		sctp->sctp_ipkts = 0;
		UPDATE_MIB(&sctp_mib, sctpInCtrlChunks, sctp->sctp_ibchunks);
		sctp->sctp_ibchunks = 0;
		UPDATE_MIB(&sctp_mib, sctpInOrderChunks, sctp->sctp_idchunks);
		sctp->sctp_idchunks = 0;
		UPDATE_MIB(&sctp_mib, sctpInUnorderChunks,
		    sctp->sctp_iudchunks);
		sctp->sctp_iudchunks = 0;
		UPDATE_MIB(&sctp_mib, sctpFragUsrMsgs, sctp->sctp_fragdmsgs);
		sctp->sctp_fragdmsgs = 0;
		UPDATE_MIB(&sctp_mib, sctpReasmUsrMsgs, sctp->sctp_reassmsgs);
		sctp->sctp_reassmsgs = 0;

		sce.sctpAssocId = ntohl(sctp->sctp_lvtag);
		sce.sctpAssocLocalPort = ntohs(sctp->sctp_lport);
		sce.sctpAssocRemPort = ntohs(sctp->sctp_fport);

		RUN_SCTP(sctp);
		if (sctp->sctp_primary != NULL) {
			fp = sctp->sctp_primary;

			if (IN6_IS_ADDR_V4MAPPED(&fp->faddr)) {
				sce.sctpAssocRemPrimAddrType =
				    MIB2_SCTP_ADDR_V4;
			} else {
				sce.sctpAssocRemPrimAddrType =
				    MIB2_SCTP_ADDR_V6;
			}
			sce.sctpAssocRemPrimAddr = fp->faddr;
			sce.sctpAssocLocPrimAddr = fp->saddr;
			sce.sctpAssocHeartBeatInterval = TICK_TO_MSEC(
			    fp->hb_interval);
		} else {
			sce.sctpAssocRemPrimAddrType = MIB2_SCTP_ADDR_V4;
			bzero(&sce.sctpAssocRemPrimAddr,
			    sizeof (sce.sctpAssocRemPrimAddr));
			bzero(&sce.sctpAssocLocPrimAddr,
			    sizeof (sce.sctpAssocLocPrimAddr));
			sce.sctpAssocHeartBeatInterval =
			    sctp_heartbeat_interval;
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
		for (fp = sctp->sctp_faddrs; fp; fp = fp->next) {
			scre.sctpAssocId = ntohl(sctp->sctp_lvtag);
			if (IN6_IS_ADDR_V4MAPPED(&fp->faddr)) {
				scre.sctpAssocRemAddrType = MIB2_SCTP_ADDR_V4;
			} else {
				scre.sctpAssocRemAddrType = MIB2_SCTP_ADDR_V6;
			}
			scre.sctpAssocRemAddr = fp->faddr;
			if (fp->state == SCTP_FADDRS_ALIVE) {
				scre.sctpAssocRemAddrActive =
				    scre.sctpAssocRemAddrHBActive =
				    MIB2_SCTP_ACTIVE;
			} else {
				scre.sctpAssocRemAddrActive =
				    scre.sctpAssocRemAddrHBActive =
				    MIB2_SCTP_INACTIVE;
			}
			scre.sctpAssocRemAddrRTO = TICK_TO_MSEC(fp->rto);
			scre.sctpAssocRemAddrMaxPathRtx = fp->max_retr;
			scre.sctpAssocRemAddrRtx = fp->T3expire;
			(void) snmp_append_data2(mp_rem_data, &mp_rem_tail,
			    (char *)&scre, sizeof (scre));
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
next_sctp:
		sctp_prev = sctp;
		mutex_enter(&sctp_g_lock);
		sctp = list_next(&sctp_g_list, sctp);
	}
	mutex_exit(&sctp_g_lock);
	if (sctp_prev != NULL)
		SCTP_REFRELE(sctp_prev);

	/* fixed length structure for IPv4 and IPv6 counters */
	SET_MIB(sctp_mib.sctpEntrySize, sizeof (sce));
	SET_MIB(sctp_mib.sctpLocalEntrySize, sizeof (scle));
	SET_MIB(sctp_mib.sctpRemoteEntrySize, sizeof (scre));
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
