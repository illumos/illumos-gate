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
/* Copyright (c) 1990 Mentat Inc. */

/*
 * An implementation of the IPoIB-CM standard based on PSARC 2009/593.
 */
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/stropts.h>
#include <sys/stream.h>
#include <sys/strsun.h>
#include <sys/strsubr.h>
#include <sys/dlpi.h>
#include <sys/mac_provider.h>

#include <sys/pattr.h>		/* for HCK_FULLCKSUM */
#include <sys/atomic.h>		/* for atomic_add*() */
#include <sys/ethernet.h>	/* for ETHERTYPE_IP */
#include <netinet/in.h>		/* for netinet/ip.h below */
#include <netinet/ip.h>		/* for struct ip */
#include <inet/common.h>	/* for inet/ip.h below */
#include <inet/ip.h>		/* for ipha_t */
#include <inet/ip_if.h>		/* for ETHERTYPE_IPV6 */
#include <inet/ip6.h>		/* for ip6_t */
#include <netinet/icmp6.h>	/* for icmp6_t */

#include <sys/ib/clients/ibd/ibd.h>

extern ibd_global_state_t ibd_gstate;
extern int ibd_rc_conn_timeout;
uint_t ibd_rc_tx_softintr = 1;
/*
 * If the number of WRs in receive queue of each RC connection less than
 * IBD_RC_RX_WR_THRESHOLD, we will post more receive WRs into it.
 */
#define	IBD_RC_RX_WR_THRESHOLD		0x20

/*
 * If the number of free SWQEs (or large Tx buf) is larger than or equal to
 * IBD_RC_TX_FREE_THRESH, we will call mac_tx_update to notify GLD to continue
 * transmitting packets.
 */
#define	IBD_RC_TX_FREE_THRESH		8

#define	IBD_RC_QPN_TO_SID(qpn) \
	((uint64_t)(IBD_RC_SERVICE_ID | ((qpn) & 0xffffff)))

/* For interop with legacy OFED */
#define	IBD_RC_QPN_TO_SID_OFED_INTEROP(qpn) \
	((uint64_t)(IBD_RC_SERVICE_ID_OFED_INTEROP | ((qpn) & 0xffffff)))

/* Internet Header + 64 bits of Data Datagram. Refer to RFC 792 */
#define	IBD_RC_IP_ICMP_RETURN_DATA_BYTES	64


/* Functions for Reliable Connected Mode */
/* Connection Setup/Close Functions */
static ibt_cm_status_t ibd_rc_dispatch_pass_mad(void *,
    ibt_cm_event_t *, ibt_cm_return_args_t *, void *, ibt_priv_data_len_t);
static ibt_cm_status_t ibd_rc_dispatch_actv_mad(void *,
    ibt_cm_event_t *, ibt_cm_return_args_t *, void *, ibt_priv_data_len_t);
static void ibd_rc_act_close(ibd_rc_chan_t *, boolean_t);

static inline void ibd_rc_add_to_chan_list(ibd_rc_chan_list_t *,
    ibd_rc_chan_t *);
static inline ibd_rc_chan_t *ibd_rc_rm_header_chan_list(
    ibd_rc_chan_list_t *);
static inline ibd_rc_chan_t *ibd_rc_rm_from_chan_list(ibd_rc_chan_list_t *,
    ibd_rc_chan_t *);

/* CQ handlers */
static void ibd_rc_rcq_handler(ibt_cq_hdl_t, void *);
static void ibd_rc_scq_handler(ibt_cq_hdl_t, void *);
static void ibd_rc_poll_rcq(ibd_rc_chan_t *, ibt_cq_hdl_t);

/* Receive Functions */
static int ibd_rc_post_srq(ibd_state_t *, ibd_rwqe_t *);
static void ibd_rc_srq_freemsg_cb(char *);
static void ibd_rc_srq_free_rwqe(ibd_state_t *, ibd_rwqe_t *);

static int ibd_rc_post_rwqe(ibd_rc_chan_t *, ibd_rwqe_t *);
static void ibd_rc_freemsg_cb(char *);
static void ibd_rc_process_rx(ibd_rc_chan_t *, ibd_rwqe_t *, ibt_wc_t *);
static void ibd_rc_free_rwqe(ibd_rc_chan_t *, ibd_rwqe_t *);
static void ibd_rc_fini_rxlist(ibd_rc_chan_t *);


/* Send Functions */
static void ibd_rc_release_swqe(ibd_rc_chan_t *, ibd_swqe_t *);
static int ibd_rc_init_txlist(ibd_rc_chan_t *);
static void ibd_rc_fini_txlist(ibd_rc_chan_t *);
static uint_t ibd_rc_tx_recycle(caddr_t);


void
ibd_async_rc_close_act_chan(ibd_state_t *state, ibd_req_t *req)
{
	ibd_rc_chan_t *rc_chan = req->rq_ptr;
	ibd_ace_t *ace;

	while (rc_chan != NULL) {
		ace = rc_chan->ace;
		ASSERT(ace != NULL);
		/* Close old RC channel */
		ibd_rc_act_close(rc_chan, B_TRUE);
		mutex_enter(&state->id_ac_mutex);
		ASSERT(ace->ac_ref != 0);
		atomic_dec_32(&ace->ac_ref);
		ace->ac_chan = NULL;
		if ((ace->ac_ref == 0) || (ace->ac_ref == CYCLEVAL)) {
			IBD_ACACHE_INSERT_FREE(state, ace);
			ace->ac_ref = 0;
		} else {
			ace->ac_ref |= CYCLEVAL;
			state->rc_delay_ace_recycle++;
		}
		mutex_exit(&state->id_ac_mutex);
		rc_chan = ibd_rc_rm_header_chan_list(
		    &state->rc_obs_act_chan_list);
	}
}

void
ibd_async_rc_recycle_ace(ibd_state_t *state, ibd_req_t *req)
{
	ibd_ace_t *ace = req->rq_ptr;
	ibd_rc_chan_t *rc_chan;

	ASSERT(ace != NULL);
	rc_chan = ace->ac_chan;
	ASSERT(rc_chan != NULL);
	/* Close old RC channel */
	ibd_rc_act_close(rc_chan, B_TRUE);
	mutex_enter(&state->id_ac_mutex);
	ASSERT(ace->ac_ref != 0);
	atomic_dec_32(&ace->ac_ref);
	ace->ac_chan = NULL;
	if ((ace->ac_ref == 0) || (ace->ac_ref == CYCLEVAL)) {
		IBD_ACACHE_INSERT_FREE(state, ace);
		ace->ac_ref = 0;
	} else {
		ace->ac_ref |= CYCLEVAL;
		state->rc_delay_ace_recycle++;
	}
	mutex_exit(&state->id_ac_mutex);
	mutex_enter(&state->rc_ace_recycle_lock);
	state->rc_ace_recycle = NULL;
	mutex_exit(&state->rc_ace_recycle_lock);
}

/* Simple ICMP IP Header Template */
static const ipha_t icmp_ipha = {
	IP_SIMPLE_HDR_VERSION, 0, 0, 0, 0, 0, IPPROTO_ICMP
};

/* Packet is too big. Send ICMP packet to GLD to request a smaller MTU */
void
ibd_async_rc_process_too_big(ibd_state_t *state, ibd_req_t *req)
{
	mblk_t *mp = req->rq_ptr;
	ibd_ace_t *ace = req->rq_ptr2;
	uint16_t mtu = state->id_mtu - IPOIB_HDRSIZE;
	uint_t	len_needed;
	size_t	msg_len;
	mblk_t	*pmtu_mp;
	ushort_t	sap;
	ib_header_info_t *ibha;	/* ib header for pmtu_pkt */
	/*
	 * ipha: IP header for pmtu_pkt
	 * old_ipha: IP header for old packet
	 */
	ipha_t *ipha, *old_ipha;
	icmph_t	*icmph;

	sap = ntohs(((ipoib_hdr_t *)mp->b_rptr)->ipoib_type);

	if (!pullupmsg(mp, -1)) {
		DPRINT(40, "ibd_async_rc_process_too_big: pullupmsg fail");
		goto too_big_fail;
	}
	/* move to IP header. */
	mp->b_rptr += IPOIB_HDRSIZE;
	old_ipha = (ipha_t *)mp->b_rptr;

	len_needed = IPH_HDR_LENGTH(old_ipha);
	if (old_ipha->ipha_protocol == IPPROTO_ENCAP) {
		len_needed += IPH_HDR_LENGTH(((uchar_t *)old_ipha +
		    len_needed));
	} else if (old_ipha->ipha_protocol == IPPROTO_IPV6) {
		ip6_t *ip6h = (ip6_t *)((uchar_t *)old_ipha
		    + len_needed);
		len_needed += ip_hdr_length_v6(mp, ip6h);
	}
	len_needed += IBD_RC_IP_ICMP_RETURN_DATA_BYTES;
	msg_len = msgdsize(mp);
	if (msg_len > len_needed) {
		(void) adjmsg(mp, len_needed - msg_len);
		msg_len = len_needed;
	}

	if ((pmtu_mp = allocb(sizeof (ib_header_info_t) + sizeof (ipha_t)
	    + sizeof (icmph_t), BPRI_MED)) == NULL) {
		DPRINT(40, "ibd_async_rc_process_too_big: allocb fail");
		goto too_big_fail;
	}
	pmtu_mp->b_cont = mp;
	pmtu_mp->b_wptr = pmtu_mp->b_rptr + sizeof (ib_header_info_t)
	    + sizeof (ipha_t) + sizeof (icmph_t);

	ibha = (ib_header_info_t *)pmtu_mp->b_rptr;

	/* Fill IB header */
	bcopy(&state->id_macaddr, &ibha->ib_dst, IPOIB_ADDRL);
	/*
	 * If the GRH is not valid, indicate to GLDv3 by setting
	 * the VerTcFlow field to 0.
	 */
	ibha->ib_grh.ipoib_vertcflow = 0;
	ibha->ipib_rhdr.ipoib_type = htons(sap);
	ibha->ipib_rhdr.ipoib_mbz = 0;

	/* Fill IP header */
	ipha = (ipha_t *)&ibha[1];
	*ipha = icmp_ipha;
	ipha->ipha_src = old_ipha->ipha_dst;
	ipha->ipha_dst = old_ipha->ipha_src;
	ipha->ipha_ttl = old_ipha->ipha_ttl;
	msg_len += sizeof (icmp_ipha) + sizeof (icmph_t);
	if (msg_len > IP_MAXPACKET) {
		ibd_print_warn(state, "ibd_rc_process_too_big_pkt: msg_len(%d) "
		    "> IP_MAXPACKET", (uint32_t)msg_len);
		(void) adjmsg(mp, IP_MAXPACKET - msg_len);
		msg_len = IP_MAXPACKET;
	}
	ipha->ipha_length = htons((uint16_t)msg_len);
	ipha->ipha_hdr_checksum = 0;
	ipha->ipha_hdr_checksum = (uint16_t)ip_csum_hdr(ipha);

	/* Fill ICMP body */
	icmph = (icmph_t *)&ipha[1];
	bzero(icmph, sizeof (icmph_t));
	icmph->icmph_type = ICMP_DEST_UNREACHABLE;
	icmph->icmph_code = ICMP_FRAGMENTATION_NEEDED;
	icmph->icmph_du_mtu = htons(mtu);
	icmph->icmph_checksum = 0;
	icmph->icmph_checksum = IP_CSUM(pmtu_mp,
	    (int32_t)sizeof (ib_header_info_t) + (int32_t)sizeof (ipha_t), 0);

	(void) hcksum_assoc(pmtu_mp, NULL, NULL, 0, 0, 0, 0,
	    HCK_FULLCKSUM | HCK_FULLCKSUM_OK, 0);

	DPRINT(30, "ibd_async_rc_process_too_big: sap=0x%x, ip_src=0x%x, "
	    "ip_dst=0x%x, ttl=%d, len_needed=%d, msg_len=%d",
	    sap, ipha->ipha_src, ipha->ipha_dst, ipha->ipha_ttl,
	    len_needed, (uint32_t)msg_len);

	mac_rx(state->id_mh, state->id_rh, pmtu_mp);

	mutex_enter(&ace->tx_too_big_mutex);
	ace->tx_too_big_ongoing = B_FALSE;
	mutex_exit(&ace->tx_too_big_mutex);
	return;

too_big_fail:
	/* Drop packet */
	freemsg(mp);
	mutex_enter(&ace->tx_too_big_mutex);
	ace->tx_too_big_ongoing = B_FALSE;
	mutex_exit(&ace->tx_too_big_mutex);
}

/*
 * Check all active/passive channels. If any ative/passive
 * channel has not been used for a long time, close it.
 */
void
ibd_rc_conn_timeout_call(void *carg)
{
	ibd_state_t *state = carg;
	ibd_ace_t *ace, *pre_ace;
	ibd_rc_chan_t *chan, *pre_chan, *next_chan;
	ibd_req_t *req;

	/* Check all active channels. If chan->is_used == B_FALSE, close it */
	mutex_enter(&state->id_ac_mutex);
	ace = list_head(&state->id_ah_active);
	while ((pre_ace = ace) != NULL) {
		ace = list_next(&state->id_ah_active, ace);
		if (pre_ace->ac_chan != NULL) {
			chan = pre_ace->ac_chan;
			ASSERT(state->id_enable_rc == B_TRUE);
			if (chan->chan_state == IBD_RC_STATE_ACT_ESTAB) {
				if (chan->is_used == B_FALSE) {
					state->rc_timeout_act++;
					INC_REF(pre_ace, 1);
					IBD_ACACHE_PULLOUT_ACTIVE(state,
					    pre_ace);
					chan->chan_state =
					    IBD_RC_STATE_ACT_CLOSING;
					ibd_rc_signal_act_close(state, pre_ace);
				} else {
					chan->is_used = B_FALSE;
				}
			}
		}
	}
	mutex_exit(&state->id_ac_mutex);

	/* Check all passive channels. If chan->is_used == B_FALSE, close it */
	mutex_enter(&state->rc_pass_chan_list.chan_list_mutex);
	next_chan = state->rc_pass_chan_list.chan_list;
	pre_chan = NULL;
	while ((chan = next_chan) != NULL) {
		next_chan = chan->next;
		if (chan->is_used == B_FALSE) {
			req = kmem_cache_alloc(state->id_req_kmc, KM_NOSLEEP);
			if (req != NULL) {
				/* remove it */
				state->rc_timeout_pas++;
				req->rq_ptr = chan;
				ibd_queue_work_slot(state, req,
				    IBD_ASYNC_RC_CLOSE_PAS_CHAN);
			} else {
				ibd_print_warn(state, "ibd_rc_conn_timeout: "
				    "alloc ibd_req_t fail");
				if (pre_chan == NULL) {
					state->rc_pass_chan_list.chan_list =
					    chan;
				} else {
					pre_chan->next = chan;
				}
				pre_chan = chan;
			}
		} else {
			if (pre_chan == NULL) {
				state->rc_pass_chan_list.chan_list = chan;
			} else {
				pre_chan->next = chan;
			}
			pre_chan = chan;
			chan->is_used = B_FALSE;
		}
	}
	if (pre_chan != NULL) {
		pre_chan->next = NULL;
	} else {
		state->rc_pass_chan_list.chan_list = NULL;
	}
	mutex_exit(&state->rc_pass_chan_list.chan_list_mutex);

	mutex_enter(&state->rc_timeout_lock);
	if (state->rc_timeout_start == B_TRUE) {
		state->rc_timeout = timeout(ibd_rc_conn_timeout_call, state,
		    SEC_TO_TICK(ibd_rc_conn_timeout));
	}
	mutex_exit(&state->rc_timeout_lock);
}

#ifdef DEBUG
/*
 * ibd_rc_update_stats - update driver private kstat counters
 *
 * This routine will dump the internal statistics counters for ibd's
 * Reliable Connected Mode. The current stats dump values will
 * be sent to the kernel status area.
 */
static int
ibd_rc_update_stats(kstat_t *ksp, int rw)
{
	ibd_state_t *state;
	ibd_rc_stat_t *ibd_rc_ksp;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	state = (ibd_state_t *)ksp->ks_private;
	ASSERT(state != NULL);
	ibd_rc_ksp = (ibd_rc_stat_t *)ksp->ks_data;

	ibd_rc_ksp->rc_rcv_trans_byte.value.ul = state->rc_rcv_trans_byte;
	ibd_rc_ksp->rc_rcv_trans_pkt.value.ul = state->rc_rcv_trans_pkt;
	ibd_rc_ksp->rc_rcv_copy_byte.value.ul = state->rc_rcv_copy_byte;
	ibd_rc_ksp->rc_rcv_copy_pkt.value.ul = state->rc_rcv_copy_pkt;
	ibd_rc_ksp->rc_rcv_alloc_fail.value.ul = state->rc_rcv_alloc_fail;

	ibd_rc_ksp->rc_rcq_err.value.ul = state->rc_rcq_err;

	ibd_rc_ksp->rc_rwqe_short.value.ul = state->rc_rwqe_short;

	ibd_rc_ksp->rc_xmt_bytes.value.ul = state->rc_xmt_bytes;
	ibd_rc_ksp->rc_xmt_small_pkt.value.ul = state->rc_xmt_small_pkt;
	ibd_rc_ksp->rc_xmt_fragmented_pkt.value.ul =
	    state->rc_xmt_fragmented_pkt;
	ibd_rc_ksp->rc_xmt_map_fail_pkt.value.ul = state->rc_xmt_map_fail_pkt;
	ibd_rc_ksp->rc_xmt_map_succ_pkt.value.ul = state->rc_xmt_map_succ_pkt;
	ibd_rc_ksp->rc_ace_not_found.value.ul = state->rc_ace_not_found;

	ibd_rc_ksp->rc_scq_no_swqe.value.ul = state->rc_scq_no_swqe;
	ibd_rc_ksp->rc_scq_no_largebuf.value.ul = state->rc_scq_no_largebuf;
	ibd_rc_ksp->rc_swqe_short.value.ul = state->rc_swqe_short;
	ibd_rc_ksp->rc_swqe_mac_update.value.ul = state->rc_swqe_mac_update;
	ibd_rc_ksp->rc_xmt_buf_short.value.ul = state->rc_xmt_buf_short;
	ibd_rc_ksp->rc_xmt_buf_mac_update.value.ul =
	    state->rc_xmt_buf_mac_update;

	ibd_rc_ksp->rc_conn_succ.value.ul = state->rc_conn_succ;
	ibd_rc_ksp->rc_conn_fail.value.ul = state->rc_conn_fail;
	ibd_rc_ksp->rc_null_conn.value.ul = state->rc_null_conn;
	ibd_rc_ksp->rc_no_estab_conn.value.ul = state->rc_no_estab_conn;

	ibd_rc_ksp->rc_act_close.value.ul = state->rc_act_close;
	ibd_rc_ksp->rc_pas_close.value.ul = state->rc_pas_close;
	ibd_rc_ksp->rc_delay_ace_recycle.value.ul = state->rc_delay_ace_recycle;
	ibd_rc_ksp->rc_act_close_simultaneous.value.ul =
	    state->rc_act_close_simultaneous;
	ibd_rc_ksp->rc_reset_cnt.value.ul = state->rc_reset_cnt;
	ibd_rc_ksp->rc_timeout_act.value.ul = state->rc_timeout_act;
	ibd_rc_ksp->rc_timeout_pas.value.ul = state->rc_timeout_pas;

	return (0);
}


/*
 * ibd_rc_init_stats - initialize kstat data structures
 *
 * This routine will create and initialize the driver private
 * statistics counters.
 */
int
ibd_rc_init_stats(ibd_state_t *state)
{
	kstat_t *ksp;
	ibd_rc_stat_t *ibd_rc_ksp;
	char stat_name[KSTAT_STRLEN];
	int inst;

	/*
	 * Create and init kstat
	 */
	inst = ddi_get_instance(state->id_dip);
	(void) snprintf(stat_name, KSTAT_STRLEN, "statistics%d_%x_%u", inst,
	    state->id_pkey, state->id_plinkid);
	ksp = kstat_create("ibd", 0, stat_name, "net", KSTAT_TYPE_NAMED,
	    sizeof (ibd_rc_stat_t) / sizeof (kstat_named_t), 0);

	if (ksp == NULL) {
		ibd_print_warn(state, "ibd_rc_init_stats: Could not create "
		    "kernel statistics");
		return (DDI_FAILURE);
	}

	state->rc_ksp = ksp;	/* Fill in the ksp of ibd over RC mode */

	ibd_rc_ksp = (ibd_rc_stat_t *)ksp->ks_data;

	/*
	 * Initialize all the statistics
	 */
	kstat_named_init(&ibd_rc_ksp->rc_rcv_trans_byte, "RC: Rx Bytes, "
	    "transfer mode", KSTAT_DATA_ULONG);
	kstat_named_init(&ibd_rc_ksp->rc_rcv_trans_pkt, "RC: Rx Pkts, "
	    "transfer mode", KSTAT_DATA_ULONG);
	kstat_named_init(&ibd_rc_ksp->rc_rcv_copy_byte, "RC: Rx Bytes, "
	    "copy mode", KSTAT_DATA_ULONG);
	kstat_named_init(&ibd_rc_ksp->rc_rcv_copy_pkt, "RC: Rx Pkts, "
	    "copy mode", KSTAT_DATA_ULONG);
	kstat_named_init(&ibd_rc_ksp->rc_rcv_alloc_fail, "RC: Rx alloc fail",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&ibd_rc_ksp->rc_rcq_err, "RC: fail in Recv CQ handler",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&ibd_rc_ksp->rc_rwqe_short, "RC: Short rwqe",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&ibd_rc_ksp->rc_xmt_bytes, "RC: Sent Bytes",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&ibd_rc_ksp->rc_xmt_small_pkt,
	    "RC: Tx pkt small size", KSTAT_DATA_ULONG);
	kstat_named_init(&ibd_rc_ksp->rc_xmt_fragmented_pkt,
	    "RC: Tx pkt fragmentary", KSTAT_DATA_ULONG);
	kstat_named_init(&ibd_rc_ksp->rc_xmt_map_fail_pkt,
	    "RC: Tx pkt fail ibt_map_mem_iov()", KSTAT_DATA_ULONG);
	kstat_named_init(&ibd_rc_ksp->rc_xmt_map_succ_pkt,
	    "RC: Tx pkt succ ibt_map_mem_iov()", KSTAT_DATA_ULONG);
	kstat_named_init(&ibd_rc_ksp->rc_ace_not_found, "RC: ace not found",
	    KSTAT_DATA_ULONG);

	kstat_named_init(&ibd_rc_ksp->rc_scq_no_swqe, "RC: No swqe after "
	    "recycle", KSTAT_DATA_ULONG);
	kstat_named_init(&ibd_rc_ksp->rc_scq_no_largebuf, "RC: No large tx buf "
	    "after recycle", KSTAT_DATA_ULONG);
	kstat_named_init(&ibd_rc_ksp->rc_swqe_short, "RC: No swqe in ibd_send",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&ibd_rc_ksp->rc_swqe_mac_update, "RC: mac_tx_update "
	    "#, swqe available", KSTAT_DATA_ULONG);
	kstat_named_init(&ibd_rc_ksp->rc_xmt_buf_short, "RC: No buf in "
	    "ibd_send", KSTAT_DATA_ULONG);
	kstat_named_init(&ibd_rc_ksp->rc_xmt_buf_mac_update, "RC: "
	    "mac_tx_update #, buf available", KSTAT_DATA_ULONG);

	kstat_named_init(&ibd_rc_ksp->rc_conn_succ, "RC: succ connected",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&ibd_rc_ksp->rc_conn_fail, "RC: fail connect",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&ibd_rc_ksp->rc_null_conn, "RC: null conn for unicast "
	    "pkt", KSTAT_DATA_ULONG);
	kstat_named_init(&ibd_rc_ksp->rc_no_estab_conn, "RC: not in act estab "
	    "state", KSTAT_DATA_ULONG);

	kstat_named_init(&ibd_rc_ksp->rc_act_close, "RC: call ibd_rc_act_close",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&ibd_rc_ksp->rc_pas_close, "RC: call ibd_rc_pas_close",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&ibd_rc_ksp->rc_delay_ace_recycle, "RC: delay ace "
	    "recycle", KSTAT_DATA_ULONG);
	kstat_named_init(&ibd_rc_ksp->rc_act_close_simultaneous, "RC: "
	    "simultaneous ibd_rc_act_close", KSTAT_DATA_ULONG);
	kstat_named_init(&ibd_rc_ksp->rc_reset_cnt, "RC: Reset RC channel",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&ibd_rc_ksp->rc_act_close, "RC: timeout act side",
	    KSTAT_DATA_ULONG);
	kstat_named_init(&ibd_rc_ksp->rc_pas_close, "RC: timeout pas side",
	    KSTAT_DATA_ULONG);

	/*
	 * Function to provide kernel stat update on demand
	 */
	ksp->ks_update = ibd_rc_update_stats;

	/*
	 * Pointer into provider's raw statistics
	 */
	ksp->ks_private = (void *)state;

	/*
	 * Add kstat to systems kstat chain
	 */
	kstat_install(ksp);

	return (DDI_SUCCESS);
}
#endif

static ibt_status_t
ibd_rc_alloc_chan(ibd_rc_chan_t **ret_chan, ibd_state_t *state,
    boolean_t is_tx_chan)
{
	ibt_status_t result;
	ibd_rc_chan_t *chan;
	ibt_rc_chan_alloc_args_t alloc_args;
	ibt_chan_alloc_flags_t alloc_flags;
	ibt_chan_sizes_t sizes;
	ibt_cq_attr_t cq_atts;
	int rv;

	chan = kmem_zalloc(sizeof (ibd_rc_chan_t), KM_SLEEP);

	chan->state = state;
	mutex_init(&chan->rx_wqe_list.dl_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&chan->rx_free_list.dl_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&chan->tx_wqe_list.dl_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&chan->tx_rel_list.dl_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&chan->tx_post_lock, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&chan->tx_poll_lock, NULL, MUTEX_DRIVER, NULL);

	/* Allocate IB structures for a new RC channel. */
	if (is_tx_chan) {
		chan->scq_size = state->id_rc_num_swqe;
		chan->rcq_size = IBD_RC_MIN_CQ_SIZE;
	} else {
		chan->scq_size = IBD_RC_MIN_CQ_SIZE;
		chan->rcq_size = state->id_rc_num_rwqe;
	}
	cq_atts.cq_size = chan->scq_size;
	cq_atts.cq_sched = NULL;
	cq_atts.cq_flags = IBT_CQ_NO_FLAGS;
	result = ibt_alloc_cq(state->id_hca_hdl, &cq_atts, &chan->scq_hdl,
	    &chan->scq_size);
	if (result != IBT_SUCCESS) {
		DPRINT(40, "ibd_rc_alloc_chan: error <%d>"
		    "create scq completion queue (size <%d>)",
		    result, chan->scq_size);
		goto alloc_scq_err;
	}	/* if failure to alloc cq */

	if (ibt_modify_cq(chan->scq_hdl, state->id_rc_tx_comp_count,
	    state->id_rc_tx_comp_usec, 0) != IBT_SUCCESS) {
		DPRINT(30, "ibd_rc_alloc_chan: Send CQ "
		    "interrupt moderation failed");
	}

	ibt_set_cq_private(chan->scq_hdl, (void *) (uintptr_t)chan);
	ibt_set_cq_handler(chan->scq_hdl, ibd_rc_scq_handler,
	    (void *) (uintptr_t)chan);

	cq_atts.cq_size = chan->rcq_size;
	cq_atts.cq_sched = NULL;
	cq_atts.cq_flags = IBT_CQ_NO_FLAGS;
	result = ibt_alloc_cq(state->id_hca_hdl, &cq_atts, &chan->rcq_hdl,
	    &chan->rcq_size);
	if (result != IBT_SUCCESS) {
		ibd_print_warn(state, "ibd_rc_alloc_chan: error <%d> creating "
		    "rx completion queue (size <%d>)", result, chan->rcq_size);
		goto alloc_rcq_err;
	}	/* if failure to alloc cq */

	if (ibt_modify_cq(chan->rcq_hdl, state->id_rc_rx_comp_count,
	    state->id_rc_rx_comp_usec, 0) != IBT_SUCCESS) {
		DPRINT(30, "ibd_rc_alloc_chan: Receive CQ "
		    "interrupt moderation failed");
	}

	ibt_set_cq_private(chan->rcq_hdl, (void *) (uintptr_t)chan);
	ibt_set_cq_handler(chan->rcq_hdl, ibd_rc_rcq_handler,
	    (void *)(uintptr_t)chan);

	if (is_tx_chan) {
		chan->is_tx_chan = B_TRUE;
		if (ibd_rc_init_txlist(chan) != DDI_SUCCESS) {
			ibd_print_warn(state, "ibd_rc_alloc_chan: "
			    "ibd_rc_init_txlist failed");
			goto init_txlist_err;
		}
		if (ibd_rc_tx_softintr == 1) {
			if ((rv = ddi_add_softintr(state->id_dip,
			    DDI_SOFTINT_LOW, &chan->scq_softintr, NULL, NULL,
			    ibd_rc_tx_recycle, (caddr_t)chan)) !=
			    DDI_SUCCESS) {
				DPRINT(10, "ibd_rc_alloc_chan: failed in "
				    "ddi_add_softintr(scq_softintr), ret=%d",
				    rv);
				goto alloc_softintr_err;
			}
		}
	} else {
		chan->is_tx_chan = B_FALSE;
	}

	/*
	 * enable completions
	 */
	result = ibt_enable_cq_notify(chan->scq_hdl, IBT_NEXT_COMPLETION);
	if (result != IBT_SUCCESS) {
		ibd_print_warn(state, "ibd_rc_alloc_chan: ibt_enable_cq_notify"
		    "(scq) failed: status %d\n", result);
		goto alloc_scq_enable_err;
	}

	/* We will enable chan->rcq_hdl later. */

	/* alloc a RC channel */
	bzero(&alloc_args, sizeof (ibt_rc_chan_alloc_args_t));
	bzero(&sizes, sizeof (ibt_chan_sizes_t));

	alloc_args.rc_flags = IBT_WR_SIGNALED;
	alloc_args.rc_control = IBT_CEP_NO_FLAGS;

	alloc_args.rc_scq = chan->scq_hdl;
	alloc_args.rc_rcq = chan->rcq_hdl;
	alloc_args.rc_pd = state->id_pd_hdl;

	alloc_args.rc_hca_port_num = state->id_port;
	alloc_args.rc_clone_chan = NULL;

	/* scatter/gather */
	alloc_args.rc_sizes.cs_sq_sgl = state->rc_tx_max_sqseg;

	/*
	 * For the number of SGL elements in receive side, I think it
	 * should be 1. Because ibd driver allocates a whole block memory
	 * for each ibt_post_recv().
	 */
	alloc_args.rc_sizes.cs_rq_sgl = 1;

	/* The send queue size and the receive queue size */
	alloc_args.rc_sizes.cs_sq = chan->scq_size;
	alloc_args.rc_sizes.cs_rq = chan->rcq_size;

	if (state->id_hca_res_lkey_capab) {
		alloc_args.rc_flags = IBT_FAST_REG_RES_LKEY;
	} else {
		DPRINT(40, "ibd_rc_alloc_chan: not support reserved lkey");
	}

	if (state->rc_enable_srq) {
		alloc_flags = IBT_ACHAN_USES_SRQ;
		alloc_args.rc_srq = state->rc_srq_hdl;
	} else {
		alloc_flags = IBT_ACHAN_NO_FLAGS;
	}

	result = ibt_alloc_rc_channel(state->id_hca_hdl,
	    alloc_flags, &alloc_args, &chan->chan_hdl, &sizes);
	if (result != IBT_SUCCESS) {
		ibd_print_warn(state, "ibd_rc_alloc_chan: ibd_rc_open_channel"
		    " fail:<%d>", result);
		goto alloc_scq_enable_err;
	}

	if (is_tx_chan)
		atomic_inc_32(&state->rc_num_tx_chan);
	else
		atomic_inc_32(&state->rc_num_rx_chan);

	/* For the connection reaper routine ibd_rc_conn_timeout_call() */
	chan->is_used = B_TRUE;

	*ret_chan = chan;
	return (IBT_SUCCESS);

alloc_scq_enable_err:
	if (is_tx_chan) {
		if (ibd_rc_tx_softintr == 1) {
			ddi_remove_softintr(chan->scq_softintr);
		}
	}
alloc_softintr_err:
	if (is_tx_chan) {
		ibd_rc_fini_txlist(chan);
	}
init_txlist_err:
	(void) ibt_free_cq(chan->rcq_hdl);
alloc_rcq_err:
	(void) ibt_free_cq(chan->scq_hdl);
alloc_scq_err:
	mutex_destroy(&chan->tx_poll_lock);
	mutex_destroy(&chan->tx_post_lock);
	mutex_destroy(&chan->tx_rel_list.dl_mutex);
	mutex_destroy(&chan->tx_wqe_list.dl_mutex);
	mutex_destroy(&chan->rx_free_list.dl_mutex);
	mutex_destroy(&chan->rx_wqe_list.dl_mutex);
	kmem_free(chan, sizeof (ibd_rc_chan_t));
	return (result);
}

static void
ibd_rc_free_chan(ibd_rc_chan_t *chan)
{
	ibt_status_t ret;

	/* DPRINT(30, "ibd_rc_free_chan: chan=%p", chan); */

	if (chan->chan_hdl != NULL) {
		ret = ibt_free_channel(chan->chan_hdl);
		if (ret != IBT_SUCCESS) {
			DPRINT(40, "ib_rc_free_chan: ibt_free_channel failed, "
			    "chan=%p, returned: %d", chan, ret);
			return;
		}
		chan->chan_hdl = NULL;
	}

	if (chan->rcq_hdl != NULL) {
		ret = ibt_free_cq(chan->rcq_hdl);
		if (ret != IBT_SUCCESS) {
			DPRINT(40, "ib_rc_free_chan: ibt_free_cq(rcq) failed, "
			    "chan=%p, returned: %d", chan, ret);
			return;
		}
		chan->rcq_hdl = NULL;
	}

	if (chan->scq_hdl != NULL) {
		ret = ibt_free_cq(chan->scq_hdl);
		if (ret != IBT_SUCCESS) {
			DPRINT(40, "ib_rc_free_chan: ibt_free_cq(scq) failed, "
			    "chan=%p, returned: %d", chan, ret);
			return;
		}
		chan->scq_hdl = NULL;
	}

	/* Free buffers */
	if (chan->is_tx_chan) {
		ibd_rc_fini_txlist(chan);
		if (ibd_rc_tx_softintr == 1) {
			ddi_remove_softintr(chan->scq_softintr);
		}
		atomic_dec_32(&chan->state->rc_num_tx_chan);
	} else {
		if (!chan->state->rc_enable_srq) {
			ibd_rc_fini_rxlist(chan);
		}
		atomic_dec_32(&chan->state->rc_num_rx_chan);
	}

	mutex_destroy(&chan->tx_poll_lock);
	mutex_destroy(&chan->tx_post_lock);
	mutex_destroy(&chan->tx_rel_list.dl_mutex);
	mutex_destroy(&chan->tx_wqe_list.dl_mutex);
	mutex_destroy(&chan->rx_free_list.dl_mutex);
	mutex_destroy(&chan->rx_wqe_list.dl_mutex);

	/*
	 * If it is a passive channel, must make sure it has been removed
	 * from chan->state->rc_pass_chan_list
	 */
	kmem_free(chan, sizeof (ibd_rc_chan_t));
}

/* Add a RC channel */
static inline void
ibd_rc_add_to_chan_list(ibd_rc_chan_list_t *list, ibd_rc_chan_t *chan)
{
	mutex_enter(&list->chan_list_mutex);
	if (list->chan_list == NULL) {
		list->chan_list = chan;
		chan->next = NULL;
	} else {
		chan->next = list->chan_list;
		list->chan_list = chan;
	}
	mutex_exit(&list->chan_list_mutex);
}

static boolean_t
ibd_rc_re_add_to_pas_chan_list(ibd_rc_chan_t *chan)
{
	ibd_state_t *state = chan->state;

	mutex_enter(&state->rc_pass_chan_list.chan_list_mutex);
	if ((state->id_mac_state & IBD_DRV_STARTED) == 0) {
		mutex_exit(&state->rc_pass_chan_list.chan_list_mutex);
		return (B_FALSE);
	} else {
		if (state->rc_pass_chan_list.chan_list == NULL) {
			state->rc_pass_chan_list.chan_list = chan;
			chan->next = NULL;
		} else {
			chan->next = state->rc_pass_chan_list.chan_list;
			state->rc_pass_chan_list.chan_list = chan;
		}
		mutex_exit(&state->rc_pass_chan_list.chan_list_mutex);
		return (B_TRUE);
	}
}

/* Remove a RC channel */
static inline ibd_rc_chan_t *
ibd_rc_rm_from_chan_list(ibd_rc_chan_list_t *list, ibd_rc_chan_t *chan)
{
	ibd_rc_chan_t *pre_chan;

	mutex_enter(&list->chan_list_mutex);
	if (list->chan_list == chan) {
		DPRINT(30, "ibd_rc_rm_from_chan_list(first): found chan(%p)"
		    " in chan_list", chan);
		list->chan_list = chan->next;
	} else {
		pre_chan = list->chan_list;
		while (pre_chan != NULL) {
			if (pre_chan->next == chan) {
				DPRINT(30, "ibd_rc_rm_from_chan_list"
				    "(middle): found chan(%p)", chan);
				pre_chan->next = chan->next;
				break;
			}
			pre_chan = pre_chan->next;
		}
		if (pre_chan == NULL)
			chan = NULL;
	}
	mutex_exit(&list->chan_list_mutex);
	return (chan);
}

static inline ibd_rc_chan_t *
ibd_rc_rm_header_chan_list(ibd_rc_chan_list_t *list)
{
	ibd_rc_chan_t *rc_chan;

	mutex_enter(&list->chan_list_mutex);
	rc_chan = list->chan_list;
	if (rc_chan != NULL) {
		list->chan_list = rc_chan->next;
	}
	mutex_exit(&list->chan_list_mutex);
	return (rc_chan);
}

static int
ibd_rc_alloc_srq_copybufs(ibd_state_t *state)
{
	ibt_mr_attr_t mem_attr;
	uint_t rc_rx_bufs_sz;

	/*
	 * Allocate one big chunk for all regular rx copy bufs
	 */
	rc_rx_bufs_sz =  (state->rc_mtu + IPOIB_GRH_SIZE) * state->rc_srq_size;

	state->rc_srq_rx_bufs = kmem_zalloc(rc_rx_bufs_sz, KM_SLEEP);

	state->rc_srq_rwqes = kmem_zalloc(state->rc_srq_size *
	    sizeof (ibd_rwqe_t), KM_SLEEP);

	/*
	 * Do one memory registration on the entire rxbuf area
	 */
	mem_attr.mr_vaddr = (uint64_t)(uintptr_t)state->rc_srq_rx_bufs;
	mem_attr.mr_len = rc_rx_bufs_sz;
	mem_attr.mr_as = NULL;
	mem_attr.mr_flags = IBT_MR_SLEEP | IBT_MR_ENABLE_LOCAL_WRITE;
	if (ibt_register_mr(state->id_hca_hdl, state->id_pd_hdl, &mem_attr,
	    &state->rc_srq_rx_mr_hdl, &state->rc_srq_rx_mr_desc)
	    != IBT_SUCCESS) {
		DPRINT(40, "ibd_rc_alloc_srq_copybufs: ibt_register_mr() "
		    "failed");
		kmem_free(state->rc_srq_rwqes,
		    state->rc_srq_size * sizeof (ibd_rwqe_t));
		kmem_free(state->rc_srq_rx_bufs, rc_rx_bufs_sz);
		state->rc_srq_rx_bufs = NULL;
		state->rc_srq_rwqes = NULL;
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static void
ibd_rc_free_srq_copybufs(ibd_state_t *state)
{
	uint_t rc_rx_buf_sz;

	/*
	 * Don't change the value of state->rc_mtu at the period from call
	 * ibd_rc_alloc_srq_copybufs() to call ibd_rc_free_srq_copybufs().
	 */
	rc_rx_buf_sz = state->rc_mtu + IPOIB_GRH_SIZE;

	/*
	 * Unregister rxbuf mr
	 */
	if (ibt_deregister_mr(state->id_hca_hdl,
	    state->rc_srq_rx_mr_hdl) != IBT_SUCCESS) {
		DPRINT(40, "ibd_rc_free_srq_copybufs: ibt_deregister_mr()"
		    " failed");
	}
	state->rc_srq_rx_mr_hdl = NULL;

	/*
	 * Free rxbuf memory
	 */
	kmem_free(state->rc_srq_rwqes,
	    state->rc_srq_size * sizeof (ibd_rwqe_t));
	kmem_free(state->rc_srq_rx_bufs, state->rc_srq_size * rc_rx_buf_sz);
	state->rc_srq_rwqes = NULL;
	state->rc_srq_rx_bufs = NULL;
}

/*
 * Allocate and post a certain number of SRQ receive buffers and WRs.
 */
int
ibd_rc_init_srq_list(ibd_state_t *state)
{
	ibd_rwqe_t *rwqe;
	ibt_lkey_t lkey;
	int i;
	uint_t len;
	uint8_t *bufaddr;
	ibt_srq_sizes_t srq_sizes;
	ibt_srq_sizes_t	 srq_real_sizes;
	ibt_status_t ret;

	srq_sizes.srq_sgl_sz = 1;
	srq_sizes.srq_wr_sz = state->id_rc_num_srq;
	ret = ibt_alloc_srq(state->id_hca_hdl, IBT_SRQ_NO_FLAGS,
	    state->id_pd_hdl, &srq_sizes, &state->rc_srq_hdl, &srq_real_sizes);
	if (ret != IBT_SUCCESS) {
		/*
		 * The following code is for CR 6932460 (can't configure ibd
		 * interface on 32 bits x86 systems). 32 bits x86 system has
		 * less memory resource than 64 bits x86 system. If current
		 * resource request can't be satisfied, we request less
		 * resource here.
		 */
		len = state->id_rc_num_srq;
		while ((ret == IBT_HCA_WR_EXCEEDED) &&
		    (len >= 2 * IBD_RC_MIN_CQ_SIZE)) {
			len = len/2;
			srq_sizes.srq_sgl_sz = 1;
			srq_sizes.srq_wr_sz = len;
			ret = ibt_alloc_srq(state->id_hca_hdl,
			    IBT_SRQ_NO_FLAGS, state->id_pd_hdl, &srq_sizes,
			    &state->rc_srq_hdl, &srq_real_sizes);
		}
		if (ret != IBT_SUCCESS) {
			DPRINT(10, "ibd_rc_init_srq_list: ibt_alloc_srq failed."
			    "req_sgl_sz=%d, req_wr_sz=0x%x, final_req_wr_sz="
			    "0x%x, ret=%d", srq_sizes.srq_sgl_sz,
			    srq_sizes.srq_wr_sz, len, ret);
			return (DDI_FAILURE);
		}
		state->id_rc_num_srq = len;
		state->id_rc_num_rwqe = state->id_rc_num_srq + 1;
	}

	state->rc_srq_size = srq_real_sizes.srq_wr_sz;
	if (ibd_rc_alloc_srq_copybufs(state) != DDI_SUCCESS) {
		ret = ibt_free_srq(state->rc_srq_hdl);
		if (ret != IBT_SUCCESS) {
			ibd_print_warn(state, "ibd_rc_init_srq_list: "
			    "ibt_free_srq fail, ret=%d", ret);
		}
		return (DDI_FAILURE);
	}

	/*
	 * Allocate and setup the rwqe list
	 */
	lkey = state->rc_srq_rx_mr_desc.md_lkey;
	rwqe = state->rc_srq_rwqes;
	bufaddr = state->rc_srq_rx_bufs;
	len = state->rc_mtu + IPOIB_GRH_SIZE;
	state->rc_srq_rwqe_list.dl_cnt = 0;
	state->rc_srq_rwqe_list.dl_bufs_outstanding = 0;
	for (i = 0; i < state->rc_srq_size; i++, rwqe++, bufaddr += len) {
		rwqe->w_state = state;
		rwqe->w_freeing_wqe = B_FALSE;
		rwqe->w_freemsg_cb.free_func = ibd_rc_srq_freemsg_cb;
		rwqe->w_freemsg_cb.free_arg = (char *)rwqe;
		rwqe->rwqe_copybuf.ic_bufaddr = bufaddr;

		if ((rwqe->rwqe_im_mblk = desballoc(bufaddr, len, 0,
		    &rwqe->w_freemsg_cb)) == NULL) {
			DPRINT(40, "ibd_rc_init_srq_list : desballoc() failed");
			rwqe->rwqe_copybuf.ic_bufaddr = NULL;
			if (atomic_dec_32_nv(&state->id_running) != 0) {
				cmn_err(CE_WARN, "ibd_rc_init_srq_list: "
				    "id_running was not 1\n");
			}
			ibd_rc_fini_srq_list(state);
			atomic_inc_32(&state->id_running);
			return (DDI_FAILURE);
		}

		rwqe->rwqe_copybuf.ic_sgl.ds_key = lkey;
		/* Leave IPOIB_GRH_SIZE space */
		rwqe->rwqe_copybuf.ic_sgl.ds_va =
		    (ib_vaddr_t)(uintptr_t)(bufaddr + IPOIB_GRH_SIZE);
		rwqe->rwqe_copybuf.ic_sgl.ds_len = state->rc_mtu;
		rwqe->w_rwr.wr_id = (ibt_wrid_t)(uintptr_t)rwqe;
		rwqe->w_rwr.wr_nds = 1;
		rwqe->w_rwr.wr_sgl = &rwqe->rwqe_copybuf.ic_sgl;
		(void) ibd_rc_post_srq(state, rwqe);
	}

	mutex_enter(&state->rc_srq_free_list.dl_mutex);
	state->rc_srq_free_list.dl_head = NULL;
	state->rc_srq_free_list.dl_cnt = 0;
	mutex_exit(&state->rc_srq_free_list.dl_mutex);

	return (DDI_SUCCESS);
}

/*
 * Free the statically allocated Rx buffer list for SRQ.
 */
void
ibd_rc_fini_srq_list(ibd_state_t *state)
{
	ibd_rwqe_t *rwqe;
	int i;
	ibt_status_t ret;

	ASSERT(state->id_running == 0);
	ret = ibt_free_srq(state->rc_srq_hdl);
	if (ret != IBT_SUCCESS) {
		ibd_print_warn(state, "ibd_rc_fini_srq_list: "
		    "ibt_free_srq fail, ret=%d", ret);
	}

	mutex_enter(&state->rc_srq_rwqe_list.dl_mutex);
	rwqe = state->rc_srq_rwqes;
	for (i = 0; i < state->rc_srq_size; i++, rwqe++) {
		if (rwqe->rwqe_im_mblk != NULL) {
			rwqe->w_freeing_wqe = B_TRUE;
			freemsg(rwqe->rwqe_im_mblk);
		}
	}
	mutex_exit(&state->rc_srq_rwqe_list.dl_mutex);

	ibd_rc_free_srq_copybufs(state);
}

/* Repost the elements in state->ib_rc_free_list */
int
ibd_rc_repost_srq_free_list(ibd_state_t *state)
{
	ibd_rwqe_t *rwqe;
	ibd_wqe_t *list;
	uint_t len;

	mutex_enter(&state->rc_srq_free_list.dl_mutex);
	if (state->rc_srq_free_list.dl_head != NULL) {
		/* repost them */
		len = state->rc_mtu + IPOIB_GRH_SIZE;
		list = state->rc_srq_free_list.dl_head;
		state->rc_srq_free_list.dl_head = NULL;
		state->rc_srq_free_list.dl_cnt = 0;
		mutex_exit(&state->rc_srq_free_list.dl_mutex);
		while (list != NULL) {
			rwqe = WQE_TO_RWQE(list);
			if ((rwqe->rwqe_im_mblk == NULL) &&
			    ((rwqe->rwqe_im_mblk = desballoc(
			    rwqe->rwqe_copybuf.ic_bufaddr, len, 0,
			    &rwqe->w_freemsg_cb)) == NULL)) {
				DPRINT(40, "ibd_rc_repost_srq_free_list: "
				    "failed in desballoc()");
				do {
					ibd_rc_srq_free_rwqe(state, rwqe);
					list = list->w_next;
					rwqe = WQE_TO_RWQE(list);
				} while (list != NULL);
				return (DDI_FAILURE);
			}
			if (ibd_rc_post_srq(state, rwqe) == DDI_FAILURE) {
				ibd_rc_srq_free_rwqe(state, rwqe);
			}
			list = list->w_next;
		}
		return (DDI_SUCCESS);
	}
	mutex_exit(&state->rc_srq_free_list.dl_mutex);
	return (DDI_SUCCESS);
}

/*
 * Free an allocated recv wqe.
 */
static void
ibd_rc_srq_free_rwqe(ibd_state_t *state, ibd_rwqe_t *rwqe)
{
	/*
	 * desballoc() failed (no memory) or the posting of rwqe failed.
	 *
	 * This rwqe is placed on a free list so that it
	 * can be reinstated in future.
	 *
	 * NOTE: no code currently exists to reinstate
	 * these "lost" rwqes.
	 */
	mutex_enter(&state->rc_srq_free_list.dl_mutex);
	state->rc_srq_free_list.dl_cnt++;
	rwqe->rwqe_next = state->rc_srq_free_list.dl_head;
	state->rc_srq_free_list.dl_head = RWQE_TO_WQE(rwqe);
	mutex_exit(&state->rc_srq_free_list.dl_mutex);
}

static void
ibd_rc_srq_freemsg_cb(char *arg)
{
	ibd_rwqe_t *rwqe = (ibd_rwqe_t *)arg;
	ibd_state_t *state = rwqe->w_state;

	ASSERT(state->rc_enable_srq);

	/*
	 * If the driver is stopped, just free the rwqe.
	 */
	if (atomic_add_32_nv(&state->id_running, 0) == 0) {
		if (!rwqe->w_freeing_wqe) {
			atomic_dec_32(
			    &state->rc_srq_rwqe_list.dl_bufs_outstanding);
			DPRINT(6, "ibd_rc_srq_freemsg_cb: wqe being freed");
			rwqe->rwqe_im_mblk = NULL;
			ibd_rc_srq_free_rwqe(state, rwqe);
		}
		return;
	}

	atomic_dec_32(&state->rc_srq_rwqe_list.dl_bufs_outstanding);

	ASSERT(state->rc_srq_rwqe_list.dl_cnt < state->rc_srq_size);
	ASSERT(!rwqe->w_freeing_wqe);

	/*
	 * Upper layer has released held mblk, so we have
	 * no more use for keeping the old pointer in
	 * our rwqe.
	 */
	rwqe->rwqe_im_mblk = desballoc(rwqe->rwqe_copybuf.ic_bufaddr,
	    state->rc_mtu + IPOIB_GRH_SIZE, 0, &rwqe->w_freemsg_cb);
	if (rwqe->rwqe_im_mblk == NULL) {
		DPRINT(40, "ibd_rc_srq_freemsg_cb: desballoc failed");
		ibd_rc_srq_free_rwqe(state, rwqe);
		return;
	}

	if (ibd_rc_post_srq(state, rwqe) == DDI_FAILURE) {
		ibd_print_warn(state, "ibd_rc_srq_freemsg_cb: ibd_rc_post_srq"
		    " failed");
		ibd_rc_srq_free_rwqe(state, rwqe);
		return;
	}
}

/*
 * Post a rwqe to the hardware and add it to the Rx list.
 */
static int
ibd_rc_post_srq(ibd_state_t *state, ibd_rwqe_t *rwqe)
{
	/*
	 * Here we should add dl_cnt before post recv, because
	 * we would have to make sure dl_cnt is updated before
	 * the corresponding ibd_rc_process_rx() is called.
	 */
	ASSERT(state->rc_srq_rwqe_list.dl_cnt < state->rc_srq_size);
	atomic_inc_32(&state->rc_srq_rwqe_list.dl_cnt);
	if (ibt_post_srq(state->rc_srq_hdl, &rwqe->w_rwr, 1, NULL) !=
	    IBT_SUCCESS) {
		atomic_dec_32(&state->rc_srq_rwqe_list.dl_cnt);
		DPRINT(40, "ibd_rc_post_srq : ibt_post_srq() failed");
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * Post a rwqe to the hardware and add it to the Rx list.
 */
static int
ibd_rc_post_rwqe(ibd_rc_chan_t *chan, ibd_rwqe_t *rwqe)
{
	/*
	 * Here we should add dl_cnt before post recv, because we would
	 * have to make sure dl_cnt has already updated before
	 * corresponding ibd_rc_process_rx() is called.
	 */
	atomic_inc_32(&chan->rx_wqe_list.dl_cnt);
	if (ibt_post_recv(chan->chan_hdl, &rwqe->w_rwr, 1, NULL) !=
	    IBT_SUCCESS) {
		atomic_dec_32(&chan->rx_wqe_list.dl_cnt);
		DPRINT(40, "ibd_rc_post_rwqe : failed in ibt_post_recv()");
		return (DDI_FAILURE);
	}
	return (DDI_SUCCESS);
}

static int
ibd_rc_alloc_rx_copybufs(ibd_rc_chan_t *chan)
{
	ibd_state_t *state = chan->state;
	ibt_mr_attr_t mem_attr;
	uint_t rc_rx_bufs_sz;

	/*
	 * Allocate one big chunk for all regular rx copy bufs
	 */
	rc_rx_bufs_sz = (state->rc_mtu + IPOIB_GRH_SIZE) * chan->rcq_size;

	chan->rx_bufs = kmem_zalloc(rc_rx_bufs_sz, KM_SLEEP);

	chan->rx_rwqes = kmem_zalloc(chan->rcq_size *
	    sizeof (ibd_rwqe_t), KM_SLEEP);

	/*
	 * Do one memory registration on the entire rxbuf area
	 */
	mem_attr.mr_vaddr = (uint64_t)(uintptr_t)chan->rx_bufs;
	mem_attr.mr_len = rc_rx_bufs_sz;
	mem_attr.mr_as = NULL;
	mem_attr.mr_flags = IBT_MR_SLEEP | IBT_MR_ENABLE_LOCAL_WRITE;
	if (ibt_register_mr(state->id_hca_hdl, state->id_pd_hdl, &mem_attr,
	    &chan->rx_mr_hdl, &chan->rx_mr_desc) != IBT_SUCCESS) {
		DPRINT(40, "ibd_rc_alloc_srq_copybufs: ibt_register_mr failed");
		kmem_free(chan->rx_rwqes, chan->rcq_size * sizeof (ibd_rwqe_t));
		kmem_free(chan->rx_bufs, rc_rx_bufs_sz);
		chan->rx_bufs = NULL;
		chan->rx_rwqes = NULL;
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

static void
ibd_rc_free_rx_copybufs(ibd_rc_chan_t *chan)
{
	ibd_state_t *state = chan->state;
	uint_t rc_rx_buf_sz;

	ASSERT(!state->rc_enable_srq);
	ASSERT(chan->rx_rwqes != NULL);
	ASSERT(chan->rx_bufs != NULL);

	/*
	 * Don't change the value of state->rc_mtu at the period from call
	 * ibd_rc_alloc_rx_copybufs() to call ibd_rc_free_rx_copybufs().
	 */
	rc_rx_buf_sz = state->rc_mtu + IPOIB_GRH_SIZE;

	/*
	 * Unregister rxbuf mr
	 */
	if (ibt_deregister_mr(state->id_hca_hdl,
	    chan->rx_mr_hdl) != IBT_SUCCESS) {
		DPRINT(40, "ibd_rc_free_rx_copybufs: ibt_deregister_mr failed");
	}
	chan->rx_mr_hdl = NULL;

	/*
	 * Free rxbuf memory
	 */
	kmem_free(chan->rx_rwqes, chan->rcq_size * sizeof (ibd_rwqe_t));
	chan->rx_rwqes = NULL;

	kmem_free(chan->rx_bufs, chan->rcq_size * rc_rx_buf_sz);
	chan->rx_bufs = NULL;
}

/*
 * Post a certain number of receive buffers and WRs on a RC channel.
 */
static int
ibd_rc_init_rxlist(ibd_rc_chan_t *chan)
{
	ibd_state_t *state = chan->state;
	ibd_rwqe_t *rwqe;
	ibt_lkey_t lkey;
	int i;
	uint_t len;
	uint8_t *bufaddr;

	ASSERT(!state->rc_enable_srq);
	if (ibd_rc_alloc_rx_copybufs(chan) != DDI_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * Allocate and setup the rwqe list
	 */
	lkey = chan->rx_mr_desc.md_lkey;
	rwqe = chan->rx_rwqes;
	bufaddr = chan->rx_bufs;
	len = state->rc_mtu + IPOIB_GRH_SIZE;
	for (i = 0; i < chan->rcq_size; i++, rwqe++, bufaddr += len) {
		rwqe->w_state = state;
		rwqe->w_chan = chan;
		rwqe->w_freeing_wqe = B_FALSE;
		rwqe->w_freemsg_cb.free_func = ibd_rc_freemsg_cb;
		rwqe->w_freemsg_cb.free_arg = (char *)rwqe;
		rwqe->rwqe_copybuf.ic_bufaddr = bufaddr;

		if ((rwqe->rwqe_im_mblk = desballoc(bufaddr, len, 0,
		    &rwqe->w_freemsg_cb)) == NULL) {
			DPRINT(40, "ibd_rc_init_srq_list: desballoc() failed");
			rwqe->rwqe_copybuf.ic_bufaddr = NULL;
			ibd_rc_fini_rxlist(chan);
			return (DDI_FAILURE);
		}

		rwqe->rwqe_copybuf.ic_sgl.ds_key = lkey;
		rwqe->rwqe_copybuf.ic_sgl.ds_va =
		    (ib_vaddr_t)(uintptr_t)(bufaddr + IPOIB_GRH_SIZE);
		rwqe->rwqe_copybuf.ic_sgl.ds_len = state->rc_mtu;
		rwqe->w_rwr.wr_id = (ibt_wrid_t)(uintptr_t)rwqe;
		rwqe->w_rwr.wr_nds = 1;
		rwqe->w_rwr.wr_sgl = &rwqe->rwqe_copybuf.ic_sgl;
		(void) ibd_rc_post_rwqe(chan, rwqe);
	}

	return (DDI_SUCCESS);
}

/*
 * Free the statically allocated Rx buffer list for SRQ.
 */
static void
ibd_rc_fini_rxlist(ibd_rc_chan_t *chan)
{
	ibd_rwqe_t *rwqe;
	int i;

	if (chan->rx_bufs == NULL) {
		DPRINT(40, "ibd_rc_fini_rxlist: empty chan->rx_bufs, quit");
		return;
	}

	/* bufs_outstanding must be 0 */
	ASSERT((chan->rx_wqe_list.dl_head == NULL) ||
	    (chan->rx_wqe_list.dl_bufs_outstanding == 0));

	mutex_enter(&chan->rx_wqe_list.dl_mutex);
	rwqe = chan->rx_rwqes;
	for (i = 0; i < chan->rcq_size; i++, rwqe++) {
		if (rwqe->rwqe_im_mblk != NULL) {
			rwqe->w_freeing_wqe = B_TRUE;
			freemsg(rwqe->rwqe_im_mblk);
		}
	}
	mutex_exit(&chan->rx_wqe_list.dl_mutex);

	ibd_rc_free_rx_copybufs(chan);
}

/*
 * Free an allocated recv wqe.
 */
static void
ibd_rc_free_rwqe(ibd_rc_chan_t *chan, ibd_rwqe_t *rwqe)
{
	/*
	 * desballoc() failed (no memory) or the posting of rwqe failed.
	 *
	 * This rwqe is placed on a free list so that it
	 * can be reinstated in future.
	 *
	 * NOTE: no code currently exists to reinstate
	 * these "lost" rwqes.
	 */
	mutex_enter(&chan->rx_free_list.dl_mutex);
	chan->rx_free_list.dl_cnt++;
	rwqe->rwqe_next = chan->rx_free_list.dl_head;
	chan->rx_free_list.dl_head = RWQE_TO_WQE(rwqe);
	mutex_exit(&chan->rx_free_list.dl_mutex);
}

/*
 * Processing to be done after receipt of a packet; hand off to GLD
 * in the format expected by GLD.
 */
static void
ibd_rc_process_rx(ibd_rc_chan_t *chan, ibd_rwqe_t *rwqe, ibt_wc_t *wc)
{
	ibd_state_t *state = chan->state;
	ib_header_info_t *phdr;
	ipoib_hdr_t *ipibp;
	mblk_t *mp;
	mblk_t *mpc;
	int rxcnt;
	ip6_t *ip6h;
	int len;

	/*
	 * Track number handed to upper layer, and number still
	 * available to receive packets.
	 */
	if (state->rc_enable_srq) {
		rxcnt = atomic_dec_32_nv(&state->rc_srq_rwqe_list.dl_cnt);
	} else {
		rxcnt = atomic_dec_32_nv(&chan->rx_wqe_list.dl_cnt);
	}

	/*
	 * It can not be a IBA multicast packet.
	 */
	ASSERT(!wc->wc_flags & IBT_WC_GRH_PRESENT);

	/* For the connection reaper routine ibd_rc_conn_timeout_call() */
	chan->is_used = B_TRUE;

#ifdef DEBUG
	if (rxcnt < state->id_rc_rx_rwqe_thresh) {
		state->rc_rwqe_short++;
	}
#endif

	/*
	 * Possibly replenish the Rx pool if needed.
	 */
	if ((rxcnt >= state->id_rc_rx_rwqe_thresh) &&
	    (wc->wc_bytes_xfer > state->id_rc_rx_copy_thresh)) {
		atomic_add_64(&state->rc_rcv_trans_byte, wc->wc_bytes_xfer);
		atomic_inc_64(&state->rc_rcv_trans_pkt);

		/*
		 * Record how many rwqe has been occupied by upper
		 * network layer
		 */
		if (state->rc_enable_srq) {
			atomic_inc_32(
			    &state->rc_srq_rwqe_list.dl_bufs_outstanding);
		} else {
			atomic_inc_32(&chan->rx_wqe_list.dl_bufs_outstanding);
		}
		mp = rwqe->rwqe_im_mblk;
	} else {
		atomic_add_64(&state->rc_rcv_copy_byte, wc->wc_bytes_xfer);
		atomic_inc_64(&state->rc_rcv_copy_pkt);

		if ((mp = allocb(wc->wc_bytes_xfer + IPOIB_GRH_SIZE,
		    BPRI_HI)) == NULL) {	/* no memory */
			DPRINT(40, "ibd_rc_process_rx: allocb() failed");
			state->rc_rcv_alloc_fail++;
			if (state->rc_enable_srq) {
				if (ibd_rc_post_srq(state, rwqe) ==
				    DDI_FAILURE) {
					ibd_rc_srq_free_rwqe(state, rwqe);
				}
			} else {
				if (ibd_rc_post_rwqe(chan, rwqe) ==
				    DDI_FAILURE) {
					ibd_rc_free_rwqe(chan, rwqe);
				}
			}
			return;
		}

		bcopy(rwqe->rwqe_im_mblk->b_rptr + IPOIB_GRH_SIZE,
		    mp->b_wptr + IPOIB_GRH_SIZE, wc->wc_bytes_xfer);

		if (state->rc_enable_srq) {
			if (ibd_rc_post_srq(state, rwqe) == DDI_FAILURE) {
				ibd_rc_srq_free_rwqe(state, rwqe);
			}
		} else {
			if (ibd_rc_post_rwqe(chan, rwqe) == DDI_FAILURE) {
				ibd_rc_free_rwqe(chan, rwqe);
			}
		}
	}

	ipibp = (ipoib_hdr_t *)((uchar_t *)mp->b_rptr + IPOIB_GRH_SIZE);
	if (ntohs(ipibp->ipoib_type) == ETHERTYPE_IPV6) {
		ip6h = (ip6_t *)((uchar_t *)ipibp + sizeof (ipoib_hdr_t));
		len = ntohs(ip6h->ip6_plen);
		if (ip6h->ip6_nxt == IPPROTO_ICMPV6) {
			/* LINTED: E_CONSTANT_CONDITION */
			IBD_PAD_NSNA(ip6h, len, IBD_RECV);
		}
	}

	phdr = (ib_header_info_t *)mp->b_rptr;
	phdr->ib_grh.ipoib_vertcflow = 0;
	ovbcopy(&state->id_macaddr, &phdr->ib_dst,
	    sizeof (ipoib_mac_t));
	mp->b_wptr = mp->b_rptr + wc->wc_bytes_xfer+ IPOIB_GRH_SIZE;

	/*
	 * Can RC mode in IB guarantee its checksum correctness?
	 *
	 *	(void) hcksum_assoc(mp, NULL, NULL, 0, 0, 0, 0,
	 *	    HCK_FULLCKSUM | HCK_FULLCKSUM_OK, 0);
	 */

	/*
	 * Make sure this is NULL or we're in trouble.
	 */
	if (mp->b_next != NULL) {
		ibd_print_warn(state,
		    "ibd_rc_process_rx: got duplicate mp from rcq?");
		mp->b_next = NULL;
	}

	/*
	 * Add this mp to the list of processed mp's to send to
	 * the nw layer
	 */
	if (state->rc_enable_srq) {
		mutex_enter(&state->rc_rx_lock);
		if (state->rc_rx_mp) {
			ASSERT(state->rc_rx_mp_tail != NULL);
			state->rc_rx_mp_tail->b_next = mp;
		} else {
			ASSERT(state->rc_rx_mp_tail == NULL);
			state->rc_rx_mp = mp;
		}

		state->rc_rx_mp_tail = mp;
		state->rc_rx_mp_len++;

		if (state->rc_rx_mp_len  >= IBD_MAX_RX_MP_LEN) {
			mpc = state->rc_rx_mp;

			state->rc_rx_mp = NULL;
			state->rc_rx_mp_tail = NULL;
			state->rc_rx_mp_len = 0;
			mutex_exit(&state->rc_rx_lock);
			mac_rx(state->id_mh, NULL, mpc);
		} else {
			mutex_exit(&state->rc_rx_lock);
		}
	} else {
		mutex_enter(&chan->rx_lock);
		if (chan->rx_mp) {
			ASSERT(chan->rx_mp_tail != NULL);
			chan->rx_mp_tail->b_next = mp;
		} else {
			ASSERT(chan->rx_mp_tail == NULL);
			chan->rx_mp = mp;
		}

		chan->rx_mp_tail = mp;
		chan->rx_mp_len++;

		if (chan->rx_mp_len  >= IBD_MAX_RX_MP_LEN) {
			mpc = chan->rx_mp;

			chan->rx_mp = NULL;
			chan->rx_mp_tail = NULL;
			chan->rx_mp_len = 0;
			mutex_exit(&chan->rx_lock);
			mac_rx(state->id_mh, NULL, mpc);
		} else {
			mutex_exit(&chan->rx_lock);
		}
	}
}

/*
 * Callback code invoked from STREAMs when the recv data buffer is free
 * for recycling.
 */
static void
ibd_rc_freemsg_cb(char *arg)
{
	ibd_rwqe_t *rwqe = (ibd_rwqe_t *)arg;
	ibd_rc_chan_t *chan = rwqe->w_chan;
	ibd_state_t *state = rwqe->w_state;

	/*
	 * If the wqe is being destructed, do not attempt recycling.
	 */
	if (rwqe->w_freeing_wqe == B_TRUE) {
		return;
	}

	ASSERT(!state->rc_enable_srq);
	ASSERT(chan->rx_wqe_list.dl_cnt < chan->rcq_size);

	rwqe->rwqe_im_mblk = desballoc(rwqe->rwqe_copybuf.ic_bufaddr,
	    state->rc_mtu + IPOIB_GRH_SIZE, 0, &rwqe->w_freemsg_cb);
	if (rwqe->rwqe_im_mblk == NULL) {
		DPRINT(40, "ibd_rc_freemsg_cb: desballoc() failed");
		ibd_rc_free_rwqe(chan, rwqe);
		return;
	}

	/*
	 * Post back to h/w. We could actually have more than
	 * id_num_rwqe WQEs on the list if there were multiple
	 * ibd_freemsg_cb() calls outstanding (since the lock is
	 * not held the entire time). This will start getting
	 * corrected over subsequent ibd_freemsg_cb() calls.
	 */
	if (ibd_rc_post_rwqe(chan, rwqe) == DDI_FAILURE) {
		ibd_rc_free_rwqe(chan, rwqe);
		return;
	}
	atomic_dec_32(&chan->rx_wqe_list.dl_bufs_outstanding);
}

/*
 * Common code for interrupt handling as well as for polling
 * for all completed wqe's while detaching.
 */
static void
ibd_rc_poll_rcq(ibd_rc_chan_t *chan, ibt_cq_hdl_t cq_hdl)
{
	ibd_wqe_t *wqe;
	ibt_wc_t *wc, *wcs;
	uint_t numwcs, real_numwcs;
	int i;

	wcs = chan->rx_wc;
	numwcs = IBD_RC_MAX_CQ_WC;

	while (ibt_poll_cq(cq_hdl, wcs, numwcs, &real_numwcs) == IBT_SUCCESS) {
		for (i = 0, wc = wcs; i < real_numwcs; i++, wc++) {
			wqe = (ibd_wqe_t *)(uintptr_t)wc->wc_id;
			if (wc->wc_status != IBT_WC_SUCCESS) {
				chan->state->rc_rcq_err++;
				/*
				 * Channel being torn down.
				 */
				DPRINT(40, "ibd_rc_poll_rcq: wc_status(%d) != "
				    "SUCC, chan=%p", wc->wc_status, chan);
				if (wc->wc_status == IBT_WC_WR_FLUSHED_ERR) {
					/*
					 * Do not invoke Rx handler because
					 * it might add buffers to the Rx pool
					 * when we are trying to deinitialize.
					 */
					continue;
				}
			}
			ibd_rc_process_rx(chan, WQE_TO_RWQE(wqe), wc);
		}
	}
}

/* Receive CQ handler */
/* ARGSUSED */
static void
ibd_rc_rcq_handler(ibt_cq_hdl_t cq_hdl, void *arg)
{
	ibd_rc_chan_t *chan = (ibd_rc_chan_t *)arg;
	ibd_state_t *state = chan->state;

	atomic_inc_32(&chan->rcq_invoking);
	ASSERT(chan->chan_state == IBD_RC_STATE_PAS_ESTAB);

	/*
	 * Poll for completed entries; the CQ will not interrupt any
	 * more for incoming (or transmitted) packets.
	 */
	ibd_rc_poll_rcq(chan, chan->rcq_hdl);

	/*
	 * Now enable CQ notifications; all packets that arrive now
	 * (or complete transmission) will cause new interrupts.
	 */
	if (ibt_enable_cq_notify(chan->rcq_hdl, IBT_NEXT_COMPLETION) !=
	    IBT_SUCCESS) {
		/*
		 * We do not expect a failure here.
		 */
		DPRINT(40, "ibd_rc_rcq_handler: ibt_enable_cq_notify() failed");
	}

	/*
	 * Repoll to catch all packets that might have arrived after
	 * we finished the first poll loop and before interrupts got
	 * armed.
	 */
	ibd_rc_poll_rcq(chan, chan->rcq_hdl);

	if (state->rc_enable_srq) {
		mutex_enter(&state->rc_rx_lock);

		if (state->rc_rx_mp != NULL) {
			mblk_t *mpc;
			mpc = state->rc_rx_mp;

			state->rc_rx_mp = NULL;
			state->rc_rx_mp_tail = NULL;
			state->rc_rx_mp_len = 0;

			mutex_exit(&state->rc_rx_lock);
			mac_rx(state->id_mh, NULL, mpc);
		} else {
			mutex_exit(&state->rc_rx_lock);
		}
	} else {
		mutex_enter(&chan->rx_lock);

		if (chan->rx_mp != NULL) {
			mblk_t *mpc;
			mpc = chan->rx_mp;

			chan->rx_mp = NULL;
			chan->rx_mp_tail = NULL;
			chan->rx_mp_len = 0;

			mutex_exit(&chan->rx_lock);
			mac_rx(state->id_mh, NULL, mpc);
		} else {
			mutex_exit(&chan->rx_lock);
		}
	}
	atomic_dec_32(&chan->rcq_invoking);
}

/*
 * Allocate the statically allocated Tx buffer list.
 */
int
ibd_rc_init_tx_largebuf_list(ibd_state_t *state)
{
	ibd_rc_tx_largebuf_t *lbufp;
	ibd_rc_tx_largebuf_t *tail;
	uint8_t *memp;
	ibt_mr_attr_t mem_attr;
	uint32_t num_swqe;
	size_t  mem_size;
	int i;

	num_swqe = state->id_rc_num_swqe - 1;

	/*
	 * Allocate one big chunk for all Tx large copy bufs
	 */
	/* Don't transfer IPOIB_GRH_SIZE bytes (40 bytes) */
	mem_size = num_swqe * state->rc_mtu;
	state->rc_tx_mr_bufs = kmem_zalloc(mem_size, KM_SLEEP);

	mem_attr.mr_len = mem_size;
	mem_attr.mr_vaddr = (uint64_t)(uintptr_t)state->rc_tx_mr_bufs;
	mem_attr.mr_as = NULL;
	mem_attr.mr_flags = IBT_MR_SLEEP;
	if (ibt_register_mr(state->id_hca_hdl, state->id_pd_hdl, &mem_attr,
	    &state->rc_tx_mr_hdl, &state->rc_tx_mr_desc) != IBT_SUCCESS) {
		DPRINT(40, "ibd_rc_init_tx_largebuf_list: ibt_register_mr "
		    "failed");
		kmem_free(state->rc_tx_mr_bufs, mem_size);
		state->rc_tx_mr_bufs = NULL;
		return (DDI_FAILURE);
	}

	state->rc_tx_largebuf_desc_base = kmem_zalloc(num_swqe *
	    sizeof (ibd_rc_tx_largebuf_t), KM_SLEEP);

	/*
	 * Set up the buf chain
	 */
	memp = state->rc_tx_mr_bufs;
	mutex_enter(&state->rc_tx_large_bufs_lock);
	lbufp = state->rc_tx_largebuf_desc_base;
	for (i = 0; i < num_swqe; i++) {
		lbufp->lb_buf = memp;
		lbufp->lb_next = lbufp + 1;

		tail = lbufp;

		memp += state->rc_mtu;
		lbufp++;
	}
	tail->lb_next = NULL;

	/*
	 * Set up the buffer information in ibd state
	 */
	state->rc_tx_largebuf_free_head = state->rc_tx_largebuf_desc_base;
	state->rc_tx_largebuf_nfree = num_swqe;
	mutex_exit(&state->rc_tx_large_bufs_lock);
	return (DDI_SUCCESS);
}

void
ibd_rc_fini_tx_largebuf_list(ibd_state_t *state)
{
	uint32_t num_swqe;

	num_swqe = state->id_rc_num_swqe - 1;

	if (ibt_deregister_mr(state->id_hca_hdl,
	    state->rc_tx_mr_hdl) != IBT_SUCCESS) {
		DPRINT(40, "ibd_rc_fini_tx_largebuf_list: ibt_deregister_mr() "
		    "failed");
	}
	state->rc_tx_mr_hdl = NULL;

	kmem_free(state->rc_tx_mr_bufs, num_swqe * state->rc_mtu);
	state->rc_tx_mr_bufs = NULL;

	kmem_free(state->rc_tx_largebuf_desc_base,
	    num_swqe * sizeof (ibd_rc_tx_largebuf_t));
	state->rc_tx_largebuf_desc_base = NULL;
}

static int
ibd_rc_alloc_tx_copybufs(ibd_rc_chan_t *chan)
{
	ibt_mr_attr_t mem_attr;
	ibd_state_t *state;

	state = chan->state;
	ASSERT(state != NULL);

	/*
	 * Allocate one big chunk for all regular tx copy bufs
	 */
	mem_attr.mr_len = chan->scq_size * state->id_rc_tx_copy_thresh;

	chan->tx_mr_bufs = kmem_zalloc(mem_attr.mr_len, KM_SLEEP);

	/*
	 * Do one memory registration on the entire txbuf area
	 */
	mem_attr.mr_vaddr = (uint64_t)(uintptr_t)chan->tx_mr_bufs;
	mem_attr.mr_as = NULL;
	mem_attr.mr_flags = IBT_MR_SLEEP;
	if (ibt_register_mr(state->id_hca_hdl, state->id_pd_hdl, &mem_attr,
	    &chan->tx_mr_hdl, &chan->tx_mr_desc) != IBT_SUCCESS) {
		DPRINT(40, "ibd_rc_alloc_tx_copybufs: ibt_register_mr failed");
		ASSERT(mem_attr.mr_len ==
		    chan->scq_size * state->id_rc_tx_copy_thresh);
		kmem_free(chan->tx_mr_bufs, mem_attr.mr_len);
		chan->tx_mr_bufs = NULL;
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * Allocate the statically allocated Tx buffer list.
 */
static int
ibd_rc_init_txlist(ibd_rc_chan_t *chan)
{
	ibd_swqe_t *swqe;
	int i;
	ibt_lkey_t lkey;
	ibd_state_t *state = chan->state;

	if (ibd_rc_alloc_tx_copybufs(chan) != DDI_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * Allocate and setup the swqe list
	 */
	lkey = chan->tx_mr_desc.md_lkey;
	chan->tx_wqes = kmem_zalloc(chan->scq_size *
	    sizeof (ibd_swqe_t), KM_SLEEP);
	swqe = chan->tx_wqes;
	for (i = 0; i < chan->scq_size; i++, swqe++) {
		swqe->swqe_next = NULL;
		swqe->swqe_im_mblk = NULL;

		swqe->swqe_copybuf.ic_sgl.ds_key = lkey;
		swqe->swqe_copybuf.ic_sgl.ds_len = 0; /* set in send */

		swqe->w_swr.wr_id = (ibt_wrid_t)(uintptr_t)swqe;
		swqe->w_swr.wr_flags = IBT_WR_SEND_SIGNAL;
		swqe->swqe_copybuf.ic_sgl.ds_va = (ib_vaddr_t)(uintptr_t)
		    (chan->tx_mr_bufs + i * state->id_rc_tx_copy_thresh);
		swqe->w_swr.wr_trans = IBT_RC_SRV;

		/* Add to list */
		mutex_enter(&chan->tx_wqe_list.dl_mutex);
		chan->tx_wqe_list.dl_cnt++;
		swqe->swqe_next = chan->tx_wqe_list.dl_head;
		chan->tx_wqe_list.dl_head = SWQE_TO_WQE(swqe);
		mutex_exit(&chan->tx_wqe_list.dl_mutex);
	}

	return (DDI_SUCCESS);
}

/*
 * Free the statically allocated Tx buffer list.
 */
static void
ibd_rc_fini_txlist(ibd_rc_chan_t *chan)
{
	ibd_state_t *state = chan->state;
	if (chan->tx_mr_hdl != NULL) {
		if (ibt_deregister_mr(chan->state->id_hca_hdl,
		    chan->tx_mr_hdl) != IBT_SUCCESS) {
			DPRINT(40, "ibd_rc_fini_txlist: ibt_deregister_mr "
			    "failed");
		}
		chan->tx_mr_hdl = NULL;
	}

	if (chan->tx_mr_bufs != NULL) {
		kmem_free(chan->tx_mr_bufs, chan->scq_size *
		    state->id_rc_tx_copy_thresh);
		chan->tx_mr_bufs = NULL;
	}

	if (chan->tx_wqes != NULL) {
		kmem_free(chan->tx_wqes, chan->scq_size *
		    sizeof (ibd_swqe_t));
		chan->tx_wqes = NULL;
	}
}

/*
 * Acquire send wqe from free list.
 * Returns error number and send wqe pointer.
 */
ibd_swqe_t *
ibd_rc_acquire_swqes(ibd_rc_chan_t *chan)
{
	ibd_swqe_t *wqe;

	mutex_enter(&chan->tx_rel_list.dl_mutex);
	if (chan->tx_rel_list.dl_head != NULL) {
		/* transfer id_tx_rel_list to id_tx_list */
		chan->tx_wqe_list.dl_head =
		    chan->tx_rel_list.dl_head;
		chan->tx_wqe_list.dl_cnt =
		    chan->tx_rel_list.dl_cnt;
		chan->tx_wqe_list.dl_pending_sends = B_FALSE;

		/* clear id_tx_rel_list */
		chan->tx_rel_list.dl_head = NULL;
		chan->tx_rel_list.dl_cnt = 0;
		mutex_exit(&chan->tx_rel_list.dl_mutex);

		wqe = WQE_TO_SWQE(chan->tx_wqe_list.dl_head);
		chan->tx_wqe_list.dl_cnt -= 1;
		chan->tx_wqe_list.dl_head = wqe->swqe_next;
	} else {	/* no free swqe */
		mutex_exit(&chan->tx_rel_list.dl_mutex);
		chan->tx_wqe_list.dl_pending_sends = B_TRUE;
		wqe = NULL;
	}
	return (wqe);
}

/*
 * Release send wqe back into free list.
 */
static void
ibd_rc_release_swqe(ibd_rc_chan_t *chan, ibd_swqe_t *swqe)
{
	/*
	 * Add back on Tx list for reuse.
	 */
	swqe->swqe_next = NULL;
	mutex_enter(&chan->tx_rel_list.dl_mutex);
	chan->tx_rel_list.dl_pending_sends = B_FALSE;
	swqe->swqe_next = chan->tx_rel_list.dl_head;
	chan->tx_rel_list.dl_head = SWQE_TO_WQE(swqe);
	chan->tx_rel_list.dl_cnt++;
	mutex_exit(&chan->tx_rel_list.dl_mutex);
}

void
ibd_rc_post_send(ibd_rc_chan_t *chan, ibd_swqe_t *node)
{
	uint_t		i;
	uint_t		num_posted;
	uint_t		n_wrs;
	ibt_status_t	ibt_status;
	ibt_send_wr_t	wrs[IBD_MAX_TX_POST_MULTIPLE];
	ibd_swqe_t	*tx_head, *elem;
	ibd_swqe_t	*nodes[IBD_MAX_TX_POST_MULTIPLE];

	/* post the one request, then check for more */
	ibt_status = ibt_post_send(chan->chan_hdl,
	    &node->w_swr, 1, NULL);
	if (ibt_status != IBT_SUCCESS) {
		ibd_print_warn(chan->state, "ibd_post_send: "
		    "posting one wr failed: ret=%d", ibt_status);
		ibd_rc_tx_cleanup(node);
	}

	tx_head = NULL;
	for (;;) {
		if (tx_head == NULL) {
			mutex_enter(&chan->tx_post_lock);
			tx_head = chan->tx_head;
			if (tx_head == NULL) {
				chan->tx_busy = 0;
				mutex_exit(&chan->tx_post_lock);
				return;
			}
			chan->tx_head = NULL;
			mutex_exit(&chan->tx_post_lock);
		}

		/*
		 * Collect pending requests, IBD_MAX_TX_POST_MULTIPLE wrs
		 * at a time if possible, and keep posting them.
		 */
		for (n_wrs = 0, elem = tx_head;
		    (elem) && (n_wrs < IBD_MAX_TX_POST_MULTIPLE);
		    elem = WQE_TO_SWQE(elem->swqe_next), n_wrs++) {
			nodes[n_wrs] = elem;
			wrs[n_wrs] = elem->w_swr;
		}
		tx_head = elem;

		ASSERT(n_wrs != 0);

		/*
		 * If posting fails for some reason, we'll never receive
		 * completion intimation, so we'll need to cleanup. But
		 * we need to make sure we don't clean up nodes whose
		 * wrs have been successfully posted. We assume that the
		 * hca driver returns on the first failure to post and
		 * therefore the first 'num_posted' entries don't need
		 * cleanup here.
		 */
		num_posted = 0;
		ibt_status = ibt_post_send(chan->chan_hdl,
		    wrs, n_wrs, &num_posted);
		if (ibt_status != IBT_SUCCESS) {
			ibd_print_warn(chan->state, "ibd_post_send: "
			    "posting multiple wrs failed: "
			    "requested=%d, done=%d, ret=%d",
			    n_wrs, num_posted, ibt_status);

			for (i = num_posted; i < n_wrs; i++)
				ibd_rc_tx_cleanup(nodes[i]);
		}
	}
}

/*
 * Common code that deals with clean ups after a successful or
 * erroneous transmission attempt.
 */
void
ibd_rc_tx_cleanup(ibd_swqe_t *swqe)
{
	ibd_ace_t *ace = swqe->w_ahandle;
	ibd_state_t *state;

	ASSERT(ace != NULL);
	ASSERT(ace->ac_chan != NULL);

	state = ace->ac_chan->state;

	/*
	 * If this was a dynamic registration in ibd_send(),
	 * deregister now.
	 */
	if (swqe->swqe_im_mblk != NULL) {
		ASSERT(swqe->w_buftype == IBD_WQE_MAPPED);
		if (swqe->w_buftype == IBD_WQE_MAPPED) {
			ibd_unmap_mem(state, swqe);
		}
		freemsg(swqe->swqe_im_mblk);
		swqe->swqe_im_mblk = NULL;
	} else {
		ASSERT(swqe->w_buftype != IBD_WQE_MAPPED);
	}

	if (swqe->w_buftype == IBD_WQE_RC_COPYBUF) {
		ibd_rc_tx_largebuf_t *lbufp;

		lbufp = swqe->w_rc_tx_largebuf;
		ASSERT(lbufp != NULL);

		mutex_enter(&state->rc_tx_large_bufs_lock);
		lbufp->lb_next = state->rc_tx_largebuf_free_head;
		state->rc_tx_largebuf_free_head = lbufp;
		state->rc_tx_largebuf_nfree ++;
		mutex_exit(&state->rc_tx_large_bufs_lock);
		swqe->w_rc_tx_largebuf = NULL;
	}


	/*
	 * Release the send wqe for reuse.
	 */
	ibd_rc_release_swqe(ace->ac_chan, swqe);

	/*
	 * Drop the reference count on the AH; it can be reused
	 * now for a different destination if there are no more
	 * posted sends that will use it. This can be eliminated
	 * if we can always associate each Tx buffer with an AH.
	 * The ace can be null if we are cleaning up from the
	 * ibd_send() error path.
	 */
	ibd_dec_ref_ace(state, ace);
}

void
ibd_rc_drain_scq(ibd_rc_chan_t *chan, ibt_cq_hdl_t cq_hdl)
{
	ibd_state_t *state = chan->state;
	ibd_wqe_t *wqe;
	ibt_wc_t *wc, *wcs;
	ibd_ace_t *ace;
	uint_t numwcs, real_numwcs;
	int i;
	boolean_t encount_error;

	wcs = chan->tx_wc;
	numwcs = IBD_RC_MAX_CQ_WC;
	encount_error = B_FALSE;

	while (ibt_poll_cq(cq_hdl, wcs, numwcs, &real_numwcs) == IBT_SUCCESS) {
		for (i = 0, wc = wcs; i < real_numwcs; i++, wc++) {
			wqe = (ibd_wqe_t *)(uintptr_t)wc->wc_id;
			if (wc->wc_status != IBT_WC_SUCCESS) {
				if (encount_error == B_FALSE) {
					/*
					 * This RC channle is in error status,
					 * remove it.
					 */
					encount_error = B_TRUE;
					mutex_enter(&state->id_ac_mutex);
					if ((chan->chan_state ==
					    IBD_RC_STATE_ACT_ESTAB) &&
					    (chan->state->id_link_state ==
					    LINK_STATE_UP) &&
					    ((ace = ibd_acache_find(state,
					    &chan->ace->ac_mac, B_FALSE, 0))
					    != NULL) && (ace == chan->ace)) {
						ASSERT(ace->ac_mce == NULL);
						INC_REF(ace, 1);
						IBD_ACACHE_PULLOUT_ACTIVE(
						    state, ace);
						chan->chan_state =
						    IBD_RC_STATE_ACT_CLOSING;
						mutex_exit(&state->id_ac_mutex);
						state->rc_reset_cnt++;
						DPRINT(30, "ibd_rc_drain_scq: "
						    "wc_status(%d) != SUCC, "
						    "chan=%p, ace=%p, "
						    "link_state=%d"
						    "reset RC channel",
						    wc->wc_status, chan,
						    chan->ace, chan->state->
						    id_link_state);
						ibd_rc_signal_act_close(
						    state, ace);
					} else {
						mutex_exit(&state->id_ac_mutex);
						state->
						    rc_act_close_simultaneous++;
						DPRINT(40, "ibd_rc_drain_scq: "
						    "wc_status(%d) != SUCC, "
						    "chan=%p, chan_state=%d,"
						    "ace=%p, link_state=%d."
						    "other thread is closing "
						    "it", wc->wc_status, chan,
						    chan->chan_state, chan->ace,
						    chan->state->id_link_state);
					}
				}
			}
			ibd_rc_tx_cleanup(WQE_TO_SWQE(wqe));
		}

		mutex_enter(&state->id_sched_lock);
		if (state->id_sched_needed == 0) {
			mutex_exit(&state->id_sched_lock);
		} else if (state->id_sched_needed & IBD_RSRC_RC_SWQE) {
			mutex_enter(&chan->tx_wqe_list.dl_mutex);
			mutex_enter(&chan->tx_rel_list.dl_mutex);
			if ((chan->tx_rel_list.dl_cnt +
			    chan->tx_wqe_list.dl_cnt) > IBD_RC_TX_FREE_THRESH) {
				state->id_sched_needed &= ~IBD_RSRC_RC_SWQE;
				mutex_exit(&chan->tx_rel_list.dl_mutex);
				mutex_exit(&chan->tx_wqe_list.dl_mutex);
				mutex_exit(&state->id_sched_lock);
				state->rc_swqe_mac_update++;
				mac_tx_update(state->id_mh);
			} else {
				state->rc_scq_no_swqe++;
				mutex_exit(&chan->tx_rel_list.dl_mutex);
				mutex_exit(&chan->tx_wqe_list.dl_mutex);
				mutex_exit(&state->id_sched_lock);
			}
		} else if (state->id_sched_needed & IBD_RSRC_RC_TX_LARGEBUF) {
			mutex_enter(&state->rc_tx_large_bufs_lock);
			if (state->rc_tx_largebuf_nfree >
			    IBD_RC_TX_FREE_THRESH) {
				ASSERT(state->rc_tx_largebuf_free_head != NULL);
				state->id_sched_needed &=
				    ~IBD_RSRC_RC_TX_LARGEBUF;
				mutex_exit(&state->rc_tx_large_bufs_lock);
				mutex_exit(&state->id_sched_lock);
				state->rc_xmt_buf_mac_update++;
				mac_tx_update(state->id_mh);
			} else {
				state->rc_scq_no_largebuf++;
				mutex_exit(&state->rc_tx_large_bufs_lock);
				mutex_exit(&state->id_sched_lock);
			}
		} else if (state->id_sched_needed & IBD_RSRC_SWQE) {
			mutex_enter(&state->id_tx_list.dl_mutex);
			mutex_enter(&state->id_tx_rel_list.dl_mutex);
			if ((state->id_tx_list.dl_cnt +
			    state->id_tx_rel_list.dl_cnt)
			    > IBD_FREE_SWQES_THRESH) {
				state->id_sched_needed &= ~IBD_RSRC_SWQE;
				state->id_sched_cnt++;
				mutex_exit(&state->id_tx_rel_list.dl_mutex);
				mutex_exit(&state->id_tx_list.dl_mutex);
				mutex_exit(&state->id_sched_lock);
				mac_tx_update(state->id_mh);
			} else {
				mutex_exit(&state->id_tx_rel_list.dl_mutex);
				mutex_exit(&state->id_tx_list.dl_mutex);
				mutex_exit(&state->id_sched_lock);
			}
		} else {
			mutex_exit(&state->id_sched_lock);
		}
	}
}

/* Send CQ handler, call ibd_rx_tx_cleanup to recycle Tx buffers */
/* ARGSUSED */
static void
ibd_rc_scq_handler(ibt_cq_hdl_t cq_hdl, void *arg)
{
	ibd_rc_chan_t *chan = (ibd_rc_chan_t *)arg;

	if (ibd_rc_tx_softintr == 1) {
		mutex_enter(&chan->tx_poll_lock);
		if (chan->tx_poll_busy & IBD_CQ_POLLING) {
			chan->tx_poll_busy |= IBD_REDO_CQ_POLLING;
			mutex_exit(&chan->tx_poll_lock);
			return;
		} else {
			mutex_exit(&chan->tx_poll_lock);
			ddi_trigger_softintr(chan->scq_softintr);
		}
	} else
		(void) ibd_rc_tx_recycle(arg);
}

static uint_t
ibd_rc_tx_recycle(caddr_t arg)
{
	ibd_rc_chan_t *chan = (ibd_rc_chan_t *)arg;
	ibd_state_t *state = chan->state;
	int flag, redo_flag;
	int redo = 1;

	flag = IBD_CQ_POLLING;
	redo_flag = IBD_REDO_CQ_POLLING;

	mutex_enter(&chan->tx_poll_lock);
	if (chan->tx_poll_busy & flag) {
		ibd_print_warn(state, "ibd_rc_tx_recycle: multiple polling "
		    "threads");
		chan->tx_poll_busy |= redo_flag;
		mutex_exit(&chan->tx_poll_lock);
		return (DDI_INTR_CLAIMED);
	}
	chan->tx_poll_busy |= flag;
	mutex_exit(&chan->tx_poll_lock);

	/*
	 * Poll for completed entries; the CQ will not interrupt any
	 * more for completed packets.
	 */
	ibd_rc_drain_scq(chan, chan->scq_hdl);

	/*
	 * Now enable CQ notifications; all completions originating now
	 * will cause new interrupts.
	 */
	do {
		if (ibt_enable_cq_notify(chan->scq_hdl, IBT_NEXT_COMPLETION) !=
		    IBT_SUCCESS) {
			/*
			 * We do not expect a failure here.
			 */
			DPRINT(40, "ibd_rc_scq_handler: ibt_enable_cq_notify()"
			    " failed");
		}

		ibd_rc_drain_scq(chan, chan->scq_hdl);

		mutex_enter(&chan->tx_poll_lock);
		if (chan->tx_poll_busy & redo_flag)
			chan->tx_poll_busy &= ~redo_flag;
		else {
			chan->tx_poll_busy &= ~flag;
			redo = 0;
		}
		mutex_exit(&chan->tx_poll_lock);

	} while (redo);

	return (DDI_INTR_CLAIMED);
}

static ibt_status_t
ibd_register_service(ibt_srv_desc_t *srv, ib_svc_id_t sid,
    int num_sids, ibt_srv_hdl_t *srv_hdl, ib_svc_id_t *ret_sid)
{
	ibd_service_t *p;
	ibt_status_t status;

	mutex_enter(&ibd_gstate.ig_mutex);
	for (p = ibd_gstate.ig_service_list; p != NULL; p = p->is_link) {
		if (p->is_sid == sid) {
			p->is_ref_cnt++;
			*srv_hdl = p->is_srv_hdl;
			*ret_sid = sid;
			mutex_exit(&ibd_gstate.ig_mutex);
			return (IBT_SUCCESS);
		}
	}
	status = ibt_register_service(ibd_gstate.ig_ibt_hdl, srv, sid,
	    num_sids, srv_hdl, ret_sid);
	if (status == IBT_SUCCESS) {
		p = kmem_alloc(sizeof (*p), KM_SLEEP);
		p->is_srv_hdl = *srv_hdl;
		p->is_sid = sid;
		p->is_ref_cnt = 1;
		p->is_link = ibd_gstate.ig_service_list;
		ibd_gstate.ig_service_list = p;
	}
	mutex_exit(&ibd_gstate.ig_mutex);
	return (status);
}

static ibt_status_t
ibd_deregister_service(ibt_srv_hdl_t srv_hdl)
{
	ibd_service_t *p, **pp;
	ibt_status_t status;

	mutex_enter(&ibd_gstate.ig_mutex);
	for (pp = &ibd_gstate.ig_service_list; *pp != NULL;
	    pp = &((*pp)->is_link)) {
		p = *pp;
		if (p->is_srv_hdl == srv_hdl) {	/* Found it */
			if (--p->is_ref_cnt == 0) {
				status = ibt_deregister_service(
				    ibd_gstate.ig_ibt_hdl, srv_hdl);
				*pp = p->is_link; /* link prev to next */
				kmem_free(p, sizeof (*p));
			} else {
				status = IBT_SUCCESS;
			}
			mutex_exit(&ibd_gstate.ig_mutex);
			return (status);
		}
	}
	/* Should not ever get here */
	mutex_exit(&ibd_gstate.ig_mutex);
	return (IBT_FAILURE);
}

/* Listen with corresponding service ID */
ibt_status_t
ibd_rc_listen(ibd_state_t *state)
{
	ibt_srv_desc_t srvdesc;
	ib_svc_id_t ret_sid;
	ibt_status_t status;
	ib_gid_t gid;

	if (state->rc_listen_hdl != NULL) {
		DPRINT(40, "ibd_rc_listen: rc_listen_hdl should be NULL");
		return (IBT_FAILURE);
	}

	bzero(&srvdesc, sizeof (ibt_srv_desc_t));
	srvdesc.sd_handler = ibd_rc_dispatch_pass_mad;
	srvdesc.sd_flags = IBT_SRV_NO_FLAGS;

	/*
	 * Register the service with service id
	 * Incoming connection requests should arrive on this service id.
	 */
	status = ibd_register_service(&srvdesc,
	    IBD_RC_QPN_TO_SID(state->id_qpnum),
	    1, &state->rc_listen_hdl, &ret_sid);
	if (status != IBT_SUCCESS) {
		DPRINT(40, "ibd_rc_listen: Service Registration Failed, "
		    "ret=%d", status);
		return (status);
	}

	gid = state->id_sgid;

	/* pass state as cm_private */
	status = ibt_bind_service(state->rc_listen_hdl,
	    gid, NULL, state, &state->rc_listen_bind);
	if (status != IBT_SUCCESS) {
		DPRINT(40, "ibd_rc_listen:"
		    " fail to bind port: <%d>", status);
		(void) ibd_deregister_service(state->rc_listen_hdl);
		return (status);
	}

	/*
	 * Legacy OFED had used a wrong service ID (one additional zero digit)
	 * for many years. To interop with legacy OFED, we support this wrong
	 * service ID here.
	 */
	ASSERT(state->rc_listen_hdl_OFED_interop == NULL);

	bzero(&srvdesc, sizeof (ibt_srv_desc_t));
	srvdesc.sd_handler = ibd_rc_dispatch_pass_mad;
	srvdesc.sd_flags = IBT_SRV_NO_FLAGS;

	/*
	 * Register the service with service id
	 * Incoming connection requests should arrive on this service id.
	 */
	status = ibd_register_service(&srvdesc,
	    IBD_RC_QPN_TO_SID_OFED_INTEROP(state->id_qpnum),
	    1, &state->rc_listen_hdl_OFED_interop, &ret_sid);
	if (status != IBT_SUCCESS) {
		DPRINT(40,
		    "ibd_rc_listen: Service Registration for Legacy OFED "
		    "Failed %d", status);
		(void) ibt_unbind_service(state->rc_listen_hdl,
		    state->rc_listen_bind);
		(void) ibd_deregister_service(state->rc_listen_hdl);
		return (status);
	}

	gid = state->id_sgid;

	/* pass state as cm_private */
	status = ibt_bind_service(state->rc_listen_hdl_OFED_interop,
	    gid, NULL, state, &state->rc_listen_bind_OFED_interop);
	if (status != IBT_SUCCESS) {
		DPRINT(40, "ibd_rc_listen: fail to bind port: <%d> for "
		    "Legacy OFED listener", status);
		(void) ibd_deregister_service(
		    state->rc_listen_hdl_OFED_interop);
		(void) ibt_unbind_service(state->rc_listen_hdl,
		    state->rc_listen_bind);
		(void) ibd_deregister_service(state->rc_listen_hdl);
		return (status);
	}

	return (IBT_SUCCESS);
}

void
ibd_rc_stop_listen(ibd_state_t *state)
{
	int ret;

	/* Disable incoming connection requests */
	if (state->rc_listen_hdl != NULL) {
		ret = ibt_unbind_all_services(state->rc_listen_hdl);
		if (ret != 0) {
			DPRINT(40, "ibd_rc_stop_listen:"
			    "ibt_unbind_all_services() failed, ret=%d", ret);
		}
		ret = ibd_deregister_service(state->rc_listen_hdl);
		if (ret != 0) {
			DPRINT(40, "ibd_rc_stop_listen:"
			    "ibd_deregister_service() failed, ret=%d", ret);
		} else {
			state->rc_listen_hdl = NULL;
		}
	}

	/* Disable incoming connection requests */
	if (state->rc_listen_hdl_OFED_interop != NULL) {
		ret = ibt_unbind_all_services(
		    state->rc_listen_hdl_OFED_interop);
		if (ret != 0) {
			DPRINT(40, "ibd_rc_stop_listen:"
			    "ibt_unbind_all_services() failed: %d", ret);
		}
		ret = ibd_deregister_service(state->rc_listen_hdl_OFED_interop);
		if (ret != 0) {
			DPRINT(40, "ibd_rc_stop_listen:"
			    "ibd_deregister_service() failed: %d", ret);
		} else {
			state->rc_listen_hdl_OFED_interop = NULL;
		}
	}
}

void
ibd_rc_close_all_chan(ibd_state_t *state)
{
	ibd_rc_chan_t *rc_chan;
	ibd_ace_t *ace, *pre_ace;
	uint_t attempts;

	/* Disable all Rx routines */
	mutex_enter(&state->rc_pass_chan_list.chan_list_mutex);
	rc_chan = state->rc_pass_chan_list.chan_list;
	while (rc_chan != NULL) {
		ibt_set_cq_handler(rc_chan->rcq_hdl, 0, 0);
		rc_chan = rc_chan->next;
	}
	mutex_exit(&state->rc_pass_chan_list.chan_list_mutex);

	if (state->rc_enable_srq) {
		attempts = 10;
		while (state->rc_srq_rwqe_list.dl_bufs_outstanding > 0) {
			DPRINT(30, "ibd_rc_close_all_chan: outstanding > 0");
			delay(drv_usectohz(100000));
			if (--attempts == 0) {
				/*
				 * There are pending bufs with the network
				 * layer and we have no choice but to wait
				 * for them to be done with. Reap all the
				 * Tx/Rx completions that were posted since
				 * we turned off the notification and
				 * return failure.
				 */
				break;
			}
		}
	}

	/* Close all passive RC channels */
	rc_chan = ibd_rc_rm_header_chan_list(&state->rc_pass_chan_list);
	while (rc_chan != NULL) {
		(void) ibd_rc_pas_close(rc_chan, B_TRUE, B_FALSE);
		rc_chan = ibd_rc_rm_header_chan_list(&state->rc_pass_chan_list);
	}

	/* Close all active RC channels */
	mutex_enter(&state->id_ac_mutex);
	state->id_ac_hot_ace = NULL;
	ace = list_head(&state->id_ah_active);
	while ((pre_ace = ace) != NULL) {
		ace = list_next(&state->id_ah_active, ace);
		if (pre_ace->ac_chan != NULL) {
			INC_REF(pre_ace, 1);
			IBD_ACACHE_PULLOUT_ACTIVE(state, pre_ace);
			pre_ace->ac_chan->chan_state = IBD_RC_STATE_ACT_CLOSING;
			ibd_rc_add_to_chan_list(&state->rc_obs_act_chan_list,
			    pre_ace->ac_chan);
		}
	}
	mutex_exit(&state->id_ac_mutex);

	rc_chan = ibd_rc_rm_header_chan_list(&state->rc_obs_act_chan_list);
	while (rc_chan != NULL) {
		ace = rc_chan->ace;
		ibd_rc_act_close(rc_chan, B_TRUE);
		if (ace != NULL) {
			mutex_enter(&state->id_ac_mutex);
			ASSERT(ace->ac_ref != 0);
			atomic_dec_32(&ace->ac_ref);
			ace->ac_chan = NULL;
			if ((ace->ac_ref == 0) || (ace->ac_ref == CYCLEVAL)) {
				IBD_ACACHE_INSERT_FREE(state, ace);
				ace->ac_ref = 0;
			} else {
				ace->ac_ref |= CYCLEVAL;
				state->rc_delay_ace_recycle++;
			}
			mutex_exit(&state->id_ac_mutex);
		}
		rc_chan = ibd_rc_rm_header_chan_list(
		    &state->rc_obs_act_chan_list);
	}

	attempts = 400;
	while (((state->rc_num_tx_chan != 0) ||
	    (state->rc_num_rx_chan != 0)) && (attempts > 0)) {
		/* Other thread is closing CM channel, wait it */
		delay(drv_usectohz(100000));
		attempts--;
	}
}

void
ibd_rc_try_connect(ibd_state_t *state, ibd_ace_t *ace,  ibt_path_info_t *path)
{
	ibt_status_t status;

	if ((state->id_mac_state & IBD_DRV_STARTED) == 0)
		return;

	status = ibd_rc_connect(state, ace, path,
	    IBD_RC_SERVICE_ID_OFED_INTEROP);

	if (status != IBT_SUCCESS) {
		/* wait peer side remove stale channel */
		delay(drv_usectohz(10000));
		if ((state->id_mac_state & IBD_DRV_STARTED) == 0)
			return;
		status = ibd_rc_connect(state, ace, path,
		    IBD_RC_SERVICE_ID_OFED_INTEROP);
	}

	if (status != IBT_SUCCESS) {
		/* wait peer side remove stale channel */
		delay(drv_usectohz(10000));
		if ((state->id_mac_state & IBD_DRV_STARTED) == 0)
			return;
		(void) ibd_rc_connect(state, ace, path,
		    IBD_RC_SERVICE_ID);
	}
}

/*
 * Allocates channel and sets the ace->ac_chan to it.
 * Opens the channel.
 */
ibt_status_t
ibd_rc_connect(ibd_state_t *state, ibd_ace_t *ace,  ibt_path_info_t *path,
    uint64_t ietf_cm_service_id)
{
	ibt_status_t status = 0;
	ibt_rc_returns_t open_returns;
	ibt_chan_open_args_t open_args;
	ibd_rc_msg_hello_t hello_req_msg;
	ibd_rc_msg_hello_t *hello_ack_msg;
	ibd_rc_chan_t *chan;
	ibt_ud_dest_query_attr_t dest_attrs;

	ASSERT(ace != NULL);
	ASSERT(ace->ac_mce == NULL);
	ASSERT(ace->ac_chan == NULL);

	if ((status = ibd_rc_alloc_chan(&chan, state, B_TRUE)) != IBT_SUCCESS) {
		DPRINT(10, "ibd_rc_connect: ibd_rc_alloc_chan() failed");
		return (status);
	}

	ace->ac_chan = chan;
	chan->state = state;
	chan->ace = ace;

	ibt_set_chan_private(chan->chan_hdl, (void *)(uintptr_t)ace);

	hello_ack_msg = kmem_zalloc(sizeof (ibd_rc_msg_hello_t), KM_SLEEP);

	/*
	 * open the channels
	 */
	bzero(&open_args, sizeof (ibt_chan_open_args_t));
	bzero(&open_returns, sizeof (ibt_rc_returns_t));

	open_args.oc_cm_handler = ibd_rc_dispatch_actv_mad;
	open_args.oc_cm_clnt_private = (void *)(uintptr_t)ace;

	/*
	 * update path record with the SID
	 */
	if ((status = ibt_query_ud_dest(ace->ac_dest, &dest_attrs))
	    != IBT_SUCCESS) {
		DPRINT(40, "ibd_rc_connect: ibt_query_ud_dest() failed, "
		    "ret=%d", status);
		return (status);
	}

	path->pi_sid =
	    ietf_cm_service_id | ((dest_attrs.ud_dst_qpn) & 0xffffff);


	/* pre-allocate memory for hello ack message */
	open_returns.rc_priv_data_len = sizeof (ibd_rc_msg_hello_t);
	open_returns.rc_priv_data = hello_ack_msg;

	open_args.oc_path = path;

	open_args.oc_path_rnr_retry_cnt	= 1;
	open_args.oc_path_retry_cnt = 1;

	/* We don't do RDMA */
	open_args.oc_rdma_ra_out = 0;
	open_args.oc_rdma_ra_in	= 0;

	hello_req_msg.reserved_qpn = htonl(state->id_qpnum);
	hello_req_msg.rx_mtu = htonl(state->rc_mtu);
	open_args.oc_priv_data_len = sizeof (ibd_rc_msg_hello_t);
	open_args.oc_priv_data = (void *)(&hello_req_msg);

	ASSERT(open_args.oc_priv_data_len <= IBT_REQ_PRIV_DATA_SZ);
	ASSERT(open_returns.rc_priv_data_len <= IBT_REP_PRIV_DATA_SZ);
	ASSERT(open_args.oc_cm_handler != NULL);

	status = ibt_open_rc_channel(chan->chan_hdl, IBT_OCHAN_NO_FLAGS,
	    IBT_BLOCKING, &open_args, &open_returns);

	if (status == IBT_SUCCESS) {
		/* Success! */
		DPRINT(2, "ibd_rc_connect: call ibt_open_rc_channel succ!");
		state->rc_conn_succ++;
		kmem_free(hello_ack_msg, sizeof (ibd_rc_msg_hello_t));
		return (IBT_SUCCESS);
	}

	/* failure */
	(void) ibt_flush_channel(chan->chan_hdl);
	ibd_rc_free_chan(chan);
	ace->ac_chan = NULL;

	/* check open_returns report error and exit */
	DPRINT(30, "ibd_rc_connect: call ibt_open_rc_chan fail."
	    "ret status = %d, reason=%d, ace=%p, mtu=0x%x, qpn=0x%x,"
	    " peer qpn=0x%x", status, (int)open_returns.rc_status, ace,
	    hello_req_msg.rx_mtu, hello_req_msg.reserved_qpn,
	    dest_attrs.ud_dst_qpn);
	kmem_free(hello_ack_msg, sizeof (ibd_rc_msg_hello_t));
	return (status);
}

void
ibd_rc_signal_act_close(ibd_state_t *state, ibd_ace_t *ace)
{
	ibd_req_t *req;

	req = kmem_cache_alloc(state->id_req_kmc, KM_NOSLEEP);
	if (req == NULL) {
		ibd_print_warn(state, "ibd_rc_signal_act_close: alloc "
		    "ibd_req_t fail");
		mutex_enter(&state->rc_obs_act_chan_list.chan_list_mutex);
		ace->ac_chan->next = state->rc_obs_act_chan_list.chan_list;
		state->rc_obs_act_chan_list.chan_list = ace->ac_chan;
		mutex_exit(&state->rc_obs_act_chan_list.chan_list_mutex);
	} else {
		req->rq_ptr = ace->ac_chan;
		ibd_queue_work_slot(state, req, IBD_ASYNC_RC_CLOSE_ACT_CHAN);
	}
}

void
ibd_rc_signal_ace_recycle(ibd_state_t *state, ibd_ace_t *ace)
{
	ibd_req_t *req;

	mutex_enter(&state->rc_ace_recycle_lock);
	if (state->rc_ace_recycle != NULL) {
		mutex_exit(&state->rc_ace_recycle_lock);
		return;
	}

	req = kmem_cache_alloc(state->id_req_kmc, KM_NOSLEEP);
	if (req == NULL) {
		mutex_exit(&state->rc_ace_recycle_lock);
		return;
	}

	state->rc_ace_recycle = ace;
	mutex_exit(&state->rc_ace_recycle_lock);
	ASSERT(ace->ac_mce == NULL);
	INC_REF(ace, 1);
	IBD_ACACHE_PULLOUT_ACTIVE(state, ace);
	req->rq_ptr = ace;
	ibd_queue_work_slot(state, req, IBD_ASYNC_RC_RECYCLE_ACE);
}

/*
 * Close an active channel
 *
 * is_close_rc_chan: if B_TRUE, we will call ibt_close_rc_channel()
 */
static void
ibd_rc_act_close(ibd_rc_chan_t *chan, boolean_t is_close_rc_chan)
{
	ibd_state_t *state;
	ibd_ace_t *ace;
	uint_t times;
	ibt_status_t ret;

	ASSERT(chan != NULL);

	chan->state->rc_act_close++;
	switch (chan->chan_state) {
	case IBD_RC_STATE_ACT_CLOSING:	/* stale, close it */
	case IBD_RC_STATE_ACT_ESTAB:
		DPRINT(30, "ibd_rc_act_close-1: close and free chan, "
		    "act_state=%d, chan=%p", chan->chan_state, chan);
		chan->chan_state = IBD_RC_STATE_ACT_CLOSED;
		ibt_set_cq_handler(chan->rcq_hdl, 0, 0);
		/*
		 * Wait send queue empty. Its old value is 50 (5 seconds). But
		 * in my experiment, 5 seconds is not enough time to let IBTL
		 * return all buffers and ace->ac_ref. I tried 25 seconds, it
		 * works well. As another evidence, I saw IBTL takes about 17
		 * seconds every time it cleans a stale RC channel.
		 */
		times = 250;
		ace = chan->ace;
		ASSERT(ace != NULL);
		state = chan->state;
		ASSERT(state != NULL);
		mutex_enter(&state->id_ac_mutex);
		mutex_enter(&chan->tx_wqe_list.dl_mutex);
		mutex_enter(&chan->tx_rel_list.dl_mutex);
		while (((chan->tx_wqe_list.dl_cnt + chan->tx_rel_list.dl_cnt)
		    != chan->scq_size) || ((ace->ac_ref != 1) &&
		    (ace->ac_ref != (CYCLEVAL+1)))) {
			mutex_exit(&chan->tx_rel_list.dl_mutex);
			mutex_exit(&chan->tx_wqe_list.dl_mutex);
			mutex_exit(&state->id_ac_mutex);
			times--;
			if (times == 0) {
				state->rc_act_close_not_clean++;
				DPRINT(40, "ibd_rc_act_close: dl_cnt(tx_wqe_"
				    "list=%d, tx_rel_list=%d) != chan->"
				    "scq_size=%d, OR ac_ref(=%d) not clean",
				    chan->tx_wqe_list.dl_cnt,
				    chan->tx_rel_list.dl_cnt,
				    chan->scq_size, ace->ac_ref);
				break;
			}
			mutex_enter(&chan->tx_poll_lock);
			if (chan->tx_poll_busy & IBD_CQ_POLLING) {
				DPRINT(40, "ibd_rc_act_close: multiple "
				    "polling threads");
				mutex_exit(&chan->tx_poll_lock);
			} else {
				chan->tx_poll_busy = IBD_CQ_POLLING;
				mutex_exit(&chan->tx_poll_lock);
				ibd_rc_drain_scq(chan, chan->scq_hdl);
				mutex_enter(&chan->tx_poll_lock);
				chan->tx_poll_busy = 0;
				mutex_exit(&chan->tx_poll_lock);
			}
			delay(drv_usectohz(100000));
			mutex_enter(&state->id_ac_mutex);
			mutex_enter(&chan->tx_wqe_list.dl_mutex);
			mutex_enter(&chan->tx_rel_list.dl_mutex);
		}
		if (times != 0) {
			mutex_exit(&chan->tx_rel_list.dl_mutex);
			mutex_exit(&chan->tx_wqe_list.dl_mutex);
			mutex_exit(&state->id_ac_mutex);
		}

		ibt_set_cq_handler(chan->scq_hdl, 0, 0);
		if (is_close_rc_chan) {
			ret = ibt_close_rc_channel(chan->chan_hdl,
			    IBT_BLOCKING|IBT_NOCALLBACKS, NULL, 0, NULL, NULL,
			    0);
			if (ret != IBT_SUCCESS) {
				DPRINT(40, "ibd_rc_act_close: ibt_close_rc_"
				    "channel fail, chan=%p, ret=%d",
				    chan, ret);
			} else {
				DPRINT(30, "ibd_rc_act_close: ibt_close_rc_"
				    "channel succ, chan=%p", chan);
			}
		}

		ibd_rc_free_chan(chan);
		break;
	case IBD_RC_STATE_ACT_REP_RECV:
		chan->chan_state = IBD_RC_STATE_ACT_CLOSED;
		(void) ibt_flush_channel(chan->chan_hdl);
		ibd_rc_free_chan(chan);
		break;
	case IBD_RC_STATE_ACT_ERROR:
		DPRINT(40, "ibd_rc_act_close: IBD_RC_STATE_ERROR branch");
		break;
	default:
		DPRINT(40, "ibd_rc_act_close: default branch, act_state=%d, "
		    "chan=%p", chan->chan_state, chan);
	}
}

/*
 * Close a passive channel
 *
 * is_close_rc_chan: if B_TRUE, we will call ibt_close_rc_channel()
 *
 * is_timeout_close: if B_TRUE, this function is called by the connection
 * reaper (refer to function ibd_rc_conn_timeout_call). When the connection
 * reaper calls ibd_rc_pas_close(), and if it finds that dl_bufs_outstanding
 * or chan->rcq_invoking is non-zero, then it can simply put that channel back
 * on the passive channels list and move on, since it might be an indication
 * that the channel became active again by the time we started it's cleanup.
 * It is costlier to do the cleanup and then reinitiate the channel
 * establishment and hence it will help to be conservative when we do the
 * cleanup.
 */
int
ibd_rc_pas_close(ibd_rc_chan_t *chan, boolean_t is_close_rc_chan,
    boolean_t is_timeout_close)
{
	uint_t times;
	ibt_status_t ret;

	ASSERT(chan != NULL);
	chan->state->rc_pas_close++;

	switch (chan->chan_state) {
	case IBD_RC_STATE_PAS_ESTAB:
		if (is_timeout_close) {
			if ((chan->rcq_invoking != 0) ||
			    ((!chan->state->rc_enable_srq) &&
			    (chan->rx_wqe_list.dl_bufs_outstanding > 0))) {
				if (ibd_rc_re_add_to_pas_chan_list(chan)) {
					return (DDI_FAILURE);
				}
			}
		}
		/*
		 * First, stop receive interrupts; this stops the
		 * connection from handing up buffers to higher layers.
		 * Wait for receive buffers to be returned; give up
		 * after 5 seconds.
		 */
		ibt_set_cq_handler(chan->rcq_hdl, 0, 0);
		/* Wait 0.01 second to let ibt_set_cq_handler() take effect */
		delay(drv_usectohz(10000));
		if (!chan->state->rc_enable_srq) {
			times = 50;
			while (chan->rx_wqe_list.dl_bufs_outstanding > 0) {
				delay(drv_usectohz(100000));
				if (--times == 0) {
					DPRINT(40, "ibd_rc_pas_close : "
					    "reclaiming failed");
					ibd_rc_poll_rcq(chan, chan->rcq_hdl);
					ibt_set_cq_handler(chan->rcq_hdl,
					    ibd_rc_rcq_handler,
					    (void *)(uintptr_t)chan);
					return (DDI_FAILURE);
				}
			}
		}
		times = 50;
		while (chan->rcq_invoking != 0) {
			delay(drv_usectohz(100000));
			if (--times == 0) {
				DPRINT(40, "ibd_rc_pas_close : "
				    "rcq handler is being invoked");
				chan->state->rc_pas_close_rcq_invoking++;
				break;
			}
		}
		ibt_set_cq_handler(chan->scq_hdl, 0, 0);
		chan->chan_state = IBD_RC_STATE_PAS_CLOSED;
		DPRINT(30, "ibd_rc_pas_close-1: close and free chan, "
		    "chan_state=%d, chan=%p", chan->chan_state, chan);
		if (is_close_rc_chan) {
			ret = ibt_close_rc_channel(chan->chan_hdl,
			    IBT_BLOCKING|IBT_NOCALLBACKS, NULL, 0, NULL, NULL,
			    0);
			if (ret != IBT_SUCCESS) {
				DPRINT(40, "ibd_rc_pas_close: ibt_close_rc_"
				    "channel() fail, chan=%p, ret=%d", chan,
				    ret);
			} else {
				DPRINT(30, "ibd_rc_pas_close: ibt_close_rc_"
				    "channel() succ, chan=%p", chan);
			}
		}
		ibd_rc_free_chan(chan);
		break;
	case IBD_RC_STATE_PAS_REQ_RECV:
		chan->chan_state = IBD_RC_STATE_PAS_CLOSED;
		(void) ibt_flush_channel(chan->chan_hdl);
		ibd_rc_free_chan(chan);
		break;
	default:
		DPRINT(40, "ibd_rc_pas_close: default, chan_state=%d, chan=%p",
		    chan->chan_state, chan);
	}
	return (DDI_SUCCESS);
}

/*
 * Passive Side:
 *	Handle an incoming CM REQ from active side.
 *
 *	If success, this function allocates an ibd_rc_chan_t, then
 * assigns it to "*ret_conn".
 */
static ibt_cm_status_t
ibd_rc_handle_req(void *arg, ibd_rc_chan_t **ret_conn,
    ibt_cm_event_t *ibt_cm_event, ibt_cm_return_args_t *ret_args,
    void *ret_priv_data)
{
	ibd_rc_msg_hello_t *hello_msg;
	ibd_state_t *state = (ibd_state_t *)arg;
	ibd_rc_chan_t *chan;

	if (ibd_rc_alloc_chan(&chan, state, B_FALSE) != IBT_SUCCESS) {
		DPRINT(40, "ibd_rc_handle_req: ibd_rc_alloc_chan() failed");
		return (IBT_CM_REJECT);
	}

	ibd_rc_add_to_chan_list(&state->rc_pass_chan_list, chan);

	ibt_set_chan_private(chan->chan_hdl, (void *)(uintptr_t)chan);

	if (!state->rc_enable_srq) {
		if (ibd_rc_init_rxlist(chan) != DDI_SUCCESS) {
			ibd_rc_free_chan(chan);
			DPRINT(40, "ibd_rc_handle_req: ibd_rc_init_rxlist() "
			    "failed");
			return (IBT_CM_REJECT);
		}
	}

	ret_args->cm_ret.rep.cm_channel = chan->chan_hdl;

	/* We don't do RDMA */
	ret_args->cm_ret.rep.cm_rdma_ra_out = 0;
	ret_args->cm_ret.rep.cm_rdma_ra_in = 0;

	ret_args->cm_ret.rep.cm_rnr_retry_cnt = 7;
	ret_args->cm_ret_len = sizeof (ibd_rc_msg_hello_t);

	hello_msg = (ibd_rc_msg_hello_t *)ibt_cm_event->cm_priv_data;
	DPRINT(30, "ibd_rc_handle_req(): peer qpn=0x%x, peer mtu=0x%x",
	    ntohl(hello_msg->reserved_qpn), ntohl(hello_msg->rx_mtu));

	hello_msg = (ibd_rc_msg_hello_t *)ret_priv_data;
	hello_msg->reserved_qpn = htonl(state->id_qpnum);
	hello_msg->rx_mtu = htonl(state->rc_mtu);

	chan->chan_state = IBD_RC_STATE_PAS_REQ_RECV;	/* ready to receive */
	*ret_conn = chan;

	return (IBT_CM_ACCEPT);
}

/*
 * ibd_rc_handle_act_estab -- handler for connection established completion
 * for active side.
 */
static ibt_cm_status_t
ibd_rc_handle_act_estab(ibd_ace_t *ace)
{
	ibt_status_t result;

	switch (ace->ac_chan->chan_state) {
		case IBD_RC_STATE_ACT_REP_RECV:
			ace->ac_chan->chan_state = IBD_RC_STATE_ACT_ESTAB;
			result = ibt_enable_cq_notify(ace->ac_chan->rcq_hdl,
			    IBT_NEXT_COMPLETION);
			if (result != IBT_SUCCESS) {
				DPRINT(40, "ibd_rc_handle_act_estab: "
				    "ibt_enable_cq_notify(rcq) "
				    "failed: status %d", result);
				return (IBT_CM_REJECT);
			}
			break;
		default:
			DPRINT(40, "ibd_rc_handle_act_estab: default "
			    "branch, act_state=%d", ace->ac_chan->chan_state);
			return (IBT_CM_REJECT);
	}
	return (IBT_CM_ACCEPT);
}

/*
 * ibd_rc_handle_pas_estab -- handler for connection established completion
 * for passive side.
 */
static ibt_cm_status_t
ibd_rc_handle_pas_estab(ibd_rc_chan_t *chan)
{
	ibt_status_t result;

	switch (chan->chan_state) {
		case IBD_RC_STATE_PAS_REQ_RECV:
			chan->chan_state = IBD_RC_STATE_PAS_ESTAB;

			result = ibt_enable_cq_notify(chan->rcq_hdl,
			    IBT_NEXT_COMPLETION);
			if (result != IBT_SUCCESS) {
				DPRINT(40, "ibd_rc_handle_pas_estab: "
				    "ibt_enable_cq_notify(rcq) "
				    "failed: status %d", result);
				return (IBT_CM_REJECT);
			}
			break;
		default:
			DPRINT(40, "ibd_rc_handle_pas_estab: default "
			    "branch, chan_state=%d", chan->chan_state);
			return (IBT_CM_REJECT);
	}
	return (IBT_CM_ACCEPT);
}

/* ARGSUSED */
static ibt_cm_status_t
ibd_rc_dispatch_actv_mad(void *arg, ibt_cm_event_t *ibt_cm_event,
    ibt_cm_return_args_t *ret_args, void *ret_priv_data,
    ibt_priv_data_len_t ret_len_max)
{
	ibt_cm_status_t result = IBT_CM_ACCEPT;
	ibd_ace_t *ace = (ibd_ace_t *)(uintptr_t)arg;
	ibd_rc_chan_t *rc_chan;
	ibd_state_t *state;
	ibd_rc_msg_hello_t *hello_ack;

	switch (ibt_cm_event->cm_type) {
	case IBT_CM_EVENT_REP_RCV:
		ASSERT(ace->ac_chan != NULL);
		ASSERT(ace->ac_chan->chan_state == IBD_RC_STATE_INIT);
		hello_ack = (ibd_rc_msg_hello_t *)ibt_cm_event->cm_priv_data;
		DPRINT(30, "ibd_rc_handle_rep: hello_ack->mtu=0x%x, "
		    "hello_ack->qpn=0x%x", ntohl(hello_ack->rx_mtu),
		    ntohl(hello_ack->reserved_qpn));
		ace->ac_chan->chan_state = IBD_RC_STATE_ACT_REP_RECV;
		break;

	case IBT_CM_EVENT_CONN_EST:
		ASSERT(ace->ac_chan != NULL);
		DPRINT(30, "ibd_rc_dispatch_actv_mad: IBT_CM_EVENT_CONN_EST, "
		    "ace=%p, act_state=%d, chan=%p",
		    ace, ace->ac_chan->chan_state, ace->ac_chan);
		result = ibd_rc_handle_act_estab(ace);
		break;

	case IBT_CM_EVENT_CONN_CLOSED:
		rc_chan = ace->ac_chan;
		if (rc_chan == NULL) {
			DPRINT(40, "ibd_rc_dispatch_actv_mad: "
			    "rc_chan==NULL, IBT_CM_EVENT_CONN_CLOSED");
			return (IBT_CM_ACCEPT);
		}
		state = rc_chan->state;
		mutex_enter(&state->id_ac_mutex);
		if ((rc_chan->chan_state == IBD_RC_STATE_ACT_ESTAB) &&
		    ((ace = ibd_acache_find(state, &ace->ac_mac, B_FALSE, 0))
		    != NULL) && (ace == rc_chan->ace)) {
			rc_chan->chan_state = IBD_RC_STATE_ACT_CLOSING;
			ASSERT(ace->ac_mce == NULL);
			INC_REF(ace, 1);
			IBD_ACACHE_PULLOUT_ACTIVE(state, ace);
			mutex_exit(&state->id_ac_mutex);
			DPRINT(30, "ibd_rc_dispatch_actv_mad: "
			    "IBT_CM_EVENT_CONN_CLOSED, ace=%p, chan=%p, "
			    "reason=%d", ace, rc_chan,
			    ibt_cm_event->cm_event.closed);
		} else {
			mutex_exit(&state->id_ac_mutex);
			state->rc_act_close_simultaneous++;
			DPRINT(40, "ibd_rc_dispatch_actv_mad: other thread "
			    "is closing it, IBT_CM_EVENT_CONN_CLOSED, "
			    "chan_state=%d", rc_chan->chan_state);
			return (IBT_CM_ACCEPT);
		}
		ibd_rc_act_close(rc_chan, B_FALSE);
		mutex_enter(&state->id_ac_mutex);
		ace->ac_chan = NULL;
		ASSERT(ace->ac_ref != 0);
		atomic_dec_32(&ace->ac_ref);
		if ((ace->ac_ref == 0) || (ace->ac_ref == CYCLEVAL)) {
			IBD_ACACHE_INSERT_FREE(state, ace);
			ace->ac_ref = 0;
		} else {
			ace->ac_ref |= CYCLEVAL;
			state->rc_delay_ace_recycle++;
		}
		mutex_exit(&state->id_ac_mutex);
		break;

	case IBT_CM_EVENT_FAILURE:
		DPRINT(30, "ibd_rc_dispatch_actv_mad: IBT_CM_EVENT_FAILURE,"
		    "ace=%p, chan=%p, code: %d, msg: %d, reason=%d",
		    ace, ace->ac_chan,
		    ibt_cm_event->cm_event.failed.cf_code,
		    ibt_cm_event->cm_event.failed.cf_msg,
		    ibt_cm_event->cm_event.failed.cf_reason);
		/*
		 * Don't need free resource here. The resource is freed
		 * at function ibd_rc_connect()
		 */
		break;

	case IBT_CM_EVENT_MRA_RCV:
		DPRINT(40, "ibd_rc_dispatch_actv_mad: IBT_CM_EVENT_MRA_RCV");
		break;
	case IBT_CM_EVENT_LAP_RCV:
		DPRINT(40, "ibd_rc_dispatch_actv_mad: LAP message received");
		break;
	case IBT_CM_EVENT_APR_RCV:
		DPRINT(40, "ibd_rc_dispatch_actv_mad: APR message received");
		break;
	default:
		DPRINT(40, "ibd_rc_dispatch_actv_mad: default branch, "
		    "ibt_cm_event->cm_type=%d", ibt_cm_event->cm_type);
		break;
	}

	return (result);
}

/* ARGSUSED */
static ibt_cm_status_t
ibd_rc_dispatch_pass_mad(void *arg, ibt_cm_event_t *ibt_cm_event,
    ibt_cm_return_args_t *ret_args, void *ret_priv_data,
    ibt_priv_data_len_t ret_len_max)
{
	ibt_cm_status_t result = IBT_CM_ACCEPT;
	ibd_rc_chan_t *chan;

	if (ibt_cm_event->cm_type == IBT_CM_EVENT_REQ_RCV) {
		DPRINT(30, "ibd_rc_dispatch_pass_mad: IBT_CM_EVENT_REQ_RCV,"
		    "req_pkey=%x", ibt_cm_event->cm_event.req.req_pkey);
		/* Receive an incoming CM REQ from active side */
		result = ibd_rc_handle_req(arg, &chan, ibt_cm_event, ret_args,
		    ret_priv_data);
		return (result);
	}

	if (ibt_cm_event->cm_channel == 0) {
		DPRINT(30, "ibd_rc_dispatch_pass_mad: "
		    "ERROR ibt_cm_event->cm_channel == 0");
		return (IBT_CM_REJECT);
	}

	chan =
	    (ibd_rc_chan_t *)ibt_get_chan_private(ibt_cm_event->cm_channel);
	if (chan == NULL) {
		DPRINT(40, "ibd_rc_dispatch_pass_mad: conn == 0");
		return (IBT_CM_REJECT);
	}

	switch (ibt_cm_event->cm_type) {
	case IBT_CM_EVENT_CONN_EST:
		DPRINT(30, "ibd_rc_dispatch_pass_mad: IBT_CM_EVENT_CONN_EST, "
		    "chan=%p", chan);
		result = ibd_rc_handle_pas_estab(chan);
		break;
	case IBT_CM_EVENT_CONN_CLOSED:
		DPRINT(30, "ibd_rc_dispatch_pass_mad: IBT_CM_EVENT_CONN_CLOSED,"
		    " chan=%p, reason=%d", chan, ibt_cm_event->cm_event.closed);
		chan = ibd_rc_rm_from_chan_list(&chan->state->rc_pass_chan_list,
		    chan);
		if (chan != NULL)
			(void) ibd_rc_pas_close(chan, B_FALSE, B_FALSE);
		break;
	case IBT_CM_EVENT_FAILURE:
		DPRINT(30, "ibd_rc_dispatch_pass_mad: IBT_CM_EVENT_FAILURE,"
		    " chan=%p, code: %d, msg: %d, reason=%d", chan,
		    ibt_cm_event->cm_event.failed.cf_code,
		    ibt_cm_event->cm_event.failed.cf_msg,
		    ibt_cm_event->cm_event.failed.cf_reason);
		chan = ibd_rc_rm_from_chan_list(&chan->state->rc_pass_chan_list,
		    chan);
		if (chan != NULL)
			(void) ibd_rc_pas_close(chan, B_FALSE, B_FALSE);
		return (IBT_CM_ACCEPT);
	case IBT_CM_EVENT_MRA_RCV:
		DPRINT(40, "ibd_rc_dispatch_pass_mad: IBT_CM_EVENT_MRA_RCV");
		break;
	case IBT_CM_EVENT_LAP_RCV:
		DPRINT(40, "ibd_rc_dispatch_pass_mad: LAP message received");
		break;
	case IBT_CM_EVENT_APR_RCV:
		DPRINT(40, "ibd_rc_dispatch_pass_mad: APR message received");
		break;
	default:
		DPRINT(40, "ibd_rc_dispatch_pass_mad: default, type=%d, "
		    "chan=%p", ibt_cm_event->cm_type, chan);
		break;
	}

	return (result);
}
