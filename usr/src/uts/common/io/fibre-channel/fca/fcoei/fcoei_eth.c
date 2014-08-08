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
 * The following notice accompanied the original version of this file:
 *
 * BSD LICENSE
 *
 * Copyright(c) 2007 Intel Corporation. All rights reserved.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * This file defines interface functions between fcoe and fcoei driver.
 */

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/stat.h>
#include <sys/pci.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/file.h>
#include <sys/cred.h>
#include <sys/byteorder.h>
#include <sys/atomic.h>
#include <sys/scsi/scsi.h>
#include <sys/mac_client.h>
#include <sys/modhash.h>

/*
 * LEADVILLE header files
 */
#include <sys/fibre-channel/fc.h>
#include <sys/fibre-channel/impl/fc_fcaif.h>

/*
 * COMSTAR header files
 */
#include <sys/stmf_defines.h>

/*
 * FCOE header files
 */
#include <sys/fcoe/fcoe_common.h>

/*
 * Driver's own header files
 */
#include <fcoei.h>

/*
 * Forward declaration of internal functions
 */
static void fcoei_process_unsol_els_req(fcoe_frame_t *frm);
static void fcoei_process_sol_els_rsp(fcoe_frame_t *frm);
static void fcoei_process_unsol_abts_req(fcoe_frame_t *frame);
static void fcoei_process_sol_abts_acc(fcoe_frame_t *frame);
static void fcoei_process_sol_abts_rjt(fcoe_frame_t *frame);
static void fcoei_process_sol_ct_rsp(fcoe_frame_t *frame);
static void fcoei_process_unsol_xfer_rdy(fcoe_frame_t *frame);
static void fcoei_process_sol_fcp_resp(fcoe_frame_t *frm);

static void fcoei_fill_fcp_resp(uint8_t *src, uint8_t *dest, int size);
static void fcoei_fill_els_fpkt_resp(fcoe_frame_t *frm, fcoei_exchange_t *xch,
    int size);

/*
 * fcoei_rx_frame
 *	Unsolicited frame is received
 *
 * Input:
 *	frame = unsolicited frame that is received
 *
 * Return:
 *	N/A
 *
 * Comment:
 *	N/A
 */
static void
fcoei_rx_frame(fcoe_frame_t *frm)
{
	if (!(FRM2SS(frm)->ss_flags & SS_FLAG_LV_BOUND)) {
		/*
		 * Release the frame and netb
		 */
		FCOEI_LOG(__FUNCTION__, "not bound now");
		frm->frm_eport->eport_free_netb(frm->frm_netb);
		frm->frm_eport->eport_release_frame(frm);
		return;
	}

	FRM2IFM(frm)->ifm_ae.ae_type = AE_EVENT_UNSOL_FRAME;
	FRM2IFM(frm)->ifm_ae.ae_obj = frm;

	mutex_enter(&FRM2SS(frm)->ss_watchdog_mutex);
	list_insert_tail(&FRM2SS(frm)->ss_event_list, &FRM2IFM(frm)->ifm_ae);
	if (FRM2SS(frm)->ss_flags & SS_FLAG_WATCHDOG_IDLE) {
		cv_signal(&FRM2SS(frm)->ss_watchdog_cv);
	}
	mutex_exit(&FRM2SS(frm)->ss_watchdog_mutex);
}

/*
 * fcoei_release_sol_frame
 *	Release the solicited frame that has just been sent out
 *
 * Input:
 *	frame = solicited frame that has been sent out
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	After FCOE sends solicited frames out, it will call this to notify
 *	FCOEI of the completion.
 */
static void
fcoei_release_sol_frame(fcoe_frame_t *frm)
{
	/*
	 * For request-type frames, it's safe to be handled out of
	 * watchdog, because it needn't update anything
	 */
	switch (FRM2IFM(frm)->ifm_rctl) {
	case R_CTL_SOLICITED_DATA:
	case R_CTL_COMMAND:
	case R_CTL_ELS_REQ:
	case R_CTL_UNSOL_CONTROL:
	case R_CTL_LS_ABTS:
		FRM2SS(frm)->ss_eport->eport_release_frame(frm);
		break;

	default:
		FRM2IFM(frm)->ifm_ae.ae_type = AE_EVENT_SOL_FRAME;
		FRM2IFM(frm)->ifm_ae.ae_obj = frm;

		mutex_enter(&FRM2SS(frm)->ss_watchdog_mutex);
		list_insert_tail(&FRM2SS(frm)->ss_event_list,
		    &FRM2IFM(frm)->ifm_ae);
		if (FRM2SS(frm)->ss_flags & SS_FLAG_WATCHDOG_IDLE) {
			cv_signal(&FRM2SS(frm)->ss_watchdog_cv);
		}
		mutex_exit(&FRM2SS(frm)->ss_watchdog_mutex);
		break;
	}
}

/*
 * fcoei_process_unsol_xfer_rdy
 *	XFER_RDY is received
 *
 * Input:
 *	frm = XFER_RDY frame
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	N/A
 */
static void
fcoei_process_unsol_xfer_rdy(fcoe_frame_t *frm)
{
	uint16_t		 sol_oxid;
	fcoei_exchange_t	*xch;
	int			 rcv_buf_size;
	int			 offset;
	int			 left_size;
	int			 data_size;
	int			 frm_num;
	int			 idx;
	fcoe_frame_t		*nfrm;

	sol_oxid = FRM_OXID(frm);
	if (mod_hash_find(FRM2SS(frm)->ss_sol_oxid_hash,
	    FMHK(sol_oxid), (mod_hash_val_t *)&xch) != 0) {
		return;
	}

	/*
	 * rcv_buf_size is the total size of data that should be transferred
	 * in this sequence.
	 * offset is based on the exchange not the sequence.
	 */
	xch->xch_rxid = FRM_RXID(frm);
	rcv_buf_size = FCOE_B2V_4(frm->frm_payload + 4);
	offset = FCOE_B2V_4(frm->frm_payload);
	ASSERT(xch->xch_resid >= rcv_buf_size);

	/*
	 * Local variables initialization
	 */
	left_size = rcv_buf_size;
	data_size = FRM2SS(frm)->ss_fcp_data_payload_size;
	frm_num = (rcv_buf_size + data_size - 1) / data_size;

	for (idx = 0; idx < frm_num - 1; idx++) {
		/*
		 * The first (frm_num -1) frames are always full
		 */
		nfrm = FRM2SS(frm)->ss_eport->eport_alloc_frame(
		    FRM2SS(frm)->ss_eport, data_size + FCFH_SIZE, NULL);
		if (nfrm == NULL) {
			FCOEI_LOG(__FUNCTION__, "can't alloc frame");
			return;
		}

		/*
		 * Copy the data payload that will  be transferred
		 */
		bcopy(offset + (uint8_t *)xch->xch_fpkt->pkt_data,
		    nfrm->frm_payload, nfrm->frm_payload_size);

		FFM_R_CTL(R_CTL_SOLICITED_DATA, nfrm);
		FFM_TYPE(FC_TYPE_SCSI_FCP, nfrm);
		FFM_F_CTL(0x010008, nfrm);
		FFM_OXID(xch->xch_oxid, nfrm);
		FFM_RXID(xch->xch_rxid, nfrm);
		FFM_S_ID(FRM_D_ID(frm), nfrm);
		FFM_D_ID(FRM_S_ID(frm), nfrm);
		FFM_SEQ_CNT(idx, nfrm);
		FFM_PARAM(offset, nfrm);
		fcoei_init_ifm(nfrm, xch);

		/*
		 * Submit the frame
		 */
		xch->xch_ss->ss_eport->eport_tx_frame(nfrm);

		/*
		 * Update offset and left_size
		 */
		offset += data_size;
		left_size -= data_size;
	}

	/*
	 * Send the last data frame of this sequence
	 */
	data_size = left_size;
	nfrm = xch->xch_ss->ss_eport->eport_alloc_frame(
	    xch->xch_ss->ss_eport, data_size + FCFH_SIZE, NULL);
	if (nfrm != NULL) {
		fcoei_init_ifm(nfrm, xch);
	} else {
		ASSERT(0);
		return;
	}

	/*
	 * Copy the data payload that will be transferred
	 */
	bcopy(offset + (uint8_t *)xch->xch_fpkt->pkt_data,
	    nfrm->frm_payload, nfrm->frm_payload_size);

	/*
	 * Set ifm_rctl for fcoei_handle_sol_frame_done
	 */
	FRM2IFM(nfrm)->ifm_rctl = R_CTL_SOLICITED_DATA;

	/*
	 * FFM
	 */
	FFM_R_CTL(R_CTL_SOLICITED_DATA, nfrm);
	FFM_TYPE(FC_TYPE_SCSI_FCP, nfrm);
	FFM_F_CTL(0x090008, nfrm);
	FFM_OXID(xch->xch_oxid, nfrm);
	FFM_RXID(xch->xch_rxid, nfrm);
	FFM_S_ID(FRM_D_ID(frm), nfrm);
	FFM_D_ID(FRM_S_ID(frm), nfrm);
	FFM_SEQ_CNT(idx, nfrm);
	FFM_PARAM(offset, nfrm);

	/*
	 * Submit the frame
	 */
	xch->xch_ss->ss_eport->eport_tx_frame(nfrm);

	/*
	 * Sequence is a transaction, so we need only update
	 * xch_remained_bytes in the end.
	 */
	xch->xch_resid -= rcv_buf_size;
}

/*
 * fcoei_process_unsol_els_req
 *	els req frame is received
 *
 * Input:
 *	frm = ELS request frame
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	We will not create exchange data structure at this time,
 *	and we should create unsolicited buffer, which will only
 *	contain the exchange's request payload.
 */
static void
fcoei_process_unsol_els_req(fcoe_frame_t *frm)
{
	fc_unsol_buf_t		*ub;
	fc_rscn_t		*rscn;
	uint32_t		 offset;
	fcoei_exchange_t	*xch_tmp;

	/*
	 * Get the unsol rxid first
	 */
	FCOEI_SET_UNSOL_FRM_RXID(frm, xch_tmp);

	/*
	 * Do proper ub initialization
	 */
	ub = (fc_unsol_buf_t *)kmem_zalloc(sizeof (fc_unsol_buf_t), KM_SLEEP);
	ub->ub_class = FC_TRAN_CLASS3;
	ub->ub_bufsize = frm->frm_payload_size;
	ub->ub_buffer = kmem_alloc(frm->frm_payload_size, KM_SLEEP);
	ub->ub_port_handle = FRM2SS(frm);
	ub->ub_token = (uint64_t)(long)ub;

	/*
	 * header conversion
	 * Caution: ub_buffer is big endian, but ub_frame should be host-format
	 * RSCN is one exception.
	 */
	FCOEI_FRM2FHDR(frm, &ub->ub_frame);

	/*
	 * If it's FLOGI, and our FLOGI failed last time,
	 * then we post online event
	 */
	if ((FRM2SS(frm)->ss_flags & SS_FLAG_FLOGI_FAILED) &&
	    (frm->frm_payload[0] == LA_ELS_FLOGI)) {
		frm->frm_eport->eport_flags |=
		    EPORT_FLAG_IS_DIRECT_P2P;
		FRM2SS(frm)->ss_bind_info.port_statec_cb(FRM2SS(frm)->ss_port,
		    FC_STATE_ONLINE);
	}

	switch (frm->frm_payload[0]) {
	case LA_ELS_RSCN:
		/*
		 * Only RSCN need byte swapping
		 */
		rscn = (fc_rscn_t *)(void *)ub->ub_buffer;
		rscn->rscn_code = frm->frm_payload[0];
		rscn->rscn_len = frm->frm_payload[1];
		rscn->rscn_payload_len =
		    FCOE_B2V_2(frm->frm_payload + 2);

		offset = 4;
		for (int i = 0; i < rscn->rscn_payload_len - 4; i += 4) {
			*(uint32_t *)((intptr_t)(uint8_t *)ub->ub_buffer +
			    offset) = FCOE_B2V_4(frm->frm_payload + offset);
			offset += 4;
		}
		break;

	default:
		bcopy(frm->frm_payload, ub->ub_buffer, frm->frm_payload_size);
		break;
	}

	/*
	 * Pass this unsol ELS up to Leadville
	 */
	FRM2SS(frm)->ss_bind_info.port_unsol_cb(FRM2SS(frm)->ss_port, ub, 0);
}

/*
 * fcoei_search_abort_xch
 *	Find the exchange that should be aborted
 *
 * Input:
 *	key = oxid of the exchange
 *	val = the exchange
 *	arg = the soft state
 *
 * Returns:
 *	MH_WALK_TERMINATE = found it, terminate the walk
 *	MH_WALK_CONTINUE = not found, continue the walk
 *
 * Comments:
 *	N/A
 */
/* ARGSUSED */
static uint32_t
fcoei_search_abort_xch(mod_hash_key_t key, mod_hash_val_t *val, void *arg)
{
	fcoei_walk_arg_t	*wa = (fcoei_walk_arg_t *)arg;
	fcoei_exchange_t	*xch = (fcoei_exchange_t *)val;

	if (xch->xch_oxid == wa->wa_oxid) {
		wa->wa_xch = xch;
		ASSERT(xch->xch_oxid == CMHK(key));
		return (MH_WALK_TERMINATE);
	}

	return (MH_WALK_CONTINUE);
}

/*
 * fcoei_process_unsol_abts_req
 *	ABTS request is received
 *
 * Input:
 *	frm = ABTS request frame
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	The remote side wants to abort one unsolicited exchange.
 */
static void
fcoei_process_unsol_abts_req(fcoe_frame_t *frm)
{
	fcoei_exchange_t	*xch = NULL;
	fcoe_frame_t		*nfrm;
	int			 payload_size;
	fcoei_walk_arg_t	 walk_arg;

	/*
	 * According to spec, the responder could want to ABTS xch too
	 */
	if (FRM_SENDER_IS_XCH_RESPONDER(frm)) {
		uint16_t sol_oxid = FRM_OXID(frm);
		(void) mod_hash_find(FRM2SS(frm)->ss_sol_oxid_hash,
		    FMHK(sol_oxid), (mod_hash_val_t *)&xch);
	} else {
		/*
		 * it's a unsolicited exchange, and we need find it out from
		 * unsolicited hash table. But at this time, RXID in frame could
		 * still be 0xFFFF in most cases, so we need do exaustive search
		 */
		walk_arg.wa_xch = NULL;
		walk_arg.wa_oxid = FRM_OXID(frm);
		mod_hash_walk(FRM2SS(frm)->ss_unsol_rxid_hash,
		    fcoei_search_abort_xch, &walk_arg);
		xch = walk_arg.wa_xch;
	}

	if (xch == NULL) {
		payload_size = 4;
		nfrm = FRM2SS(frm)->ss_eport->eport_alloc_frame(
		    FRM2SS(frm)->ss_eport,
		    payload_size + FCFH_SIZE, NULL);
		if (nfrm == NULL) {
			FCOEI_LOG(__FUNCTION__, "can't alloc frame");
			return;
		}

		bzero(nfrm->frm_payload, nfrm->frm_payload_size);
		nfrm->frm_payload[1] = 0x05;
		nfrm->frm_payload[3] = 0xAA;
		FFM_R_CTL(R_CTL_LS_BA_RJT, nfrm);
		fcoei_init_ifm(nfrm, xch);
	} else {
		/*
		 * We should complete the exchange with frm as NULL,
		 * and we don't care its success or failure
		 */
		fcoei_complete_xch(xch, NULL, FC_PKT_FAILURE, FC_REASON_ABTX);

		/*
		 * Construct ABTS ACC frame
		 */
		payload_size = 12;
		nfrm = FRM2SS(frm)->ss_eport->eport_alloc_frame(
		    FRM2SS(frm)->ss_eport, payload_size + FCFH_SIZE, NULL);
		if (nfrm == NULL) {
			FCOEI_LOG(__FUNCTION__, "can't alloc frame");
			return;
		}

		bzero(nfrm->frm_payload, nfrm->frm_payload_size);
		nfrm->frm_payload[4] = 0xFF & (xch->xch_oxid >> 8);
		nfrm->frm_payload[5] = 0xFF & (xch->xch_oxid);
		nfrm->frm_payload[6] = 0xFF & (xch->xch_rxid >> 8);
		nfrm->frm_payload[7] = 0xFF & (xch->xch_rxid);
		nfrm->frm_payload[10] = 0xFF;
		nfrm->frm_payload[11] = 0xFF;

		FFM_R_CTL(R_CTL_LS_BA_ACC, nfrm);
		fcoei_init_ifm(nfrm, xch);
	}

	FFM_D_ID(FRM_S_ID(frm), nfrm);
	FFM_S_ID(FRM_D_ID(frm), nfrm);
	FFM_TYPE(FRM_TYPE(frm), nfrm);
	FFM_F_CTL(FRM_F_CTL(frm), nfrm);
	FFM_OXID(FRM_OXID(frm), nfrm);
	FFM_RXID(FRM_RXID(frm), nfrm);
	FRM2SS(frm)->ss_eport->eport_tx_frame(nfrm);
}

/*
 * fcoei_process_sol_fcp_resp
 *	FCP response is received
 *
 * Input:
 *	frm = FCP response frame
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	N/A
 */
static void
fcoei_process_sol_fcp_resp(fcoe_frame_t *frm)
{
	uint16_t		 sol_oxid;
	uint32_t		 actual_size;
	fcoei_exchange_t	*xch  = NULL;
	fc_packet_t		*fpkt = NULL;
	mod_hash_val_t		 val;
	uint32_t		 i_fcp_status;

	/*
	 * Firstly, we search the related exchange
	 */
	sol_oxid = FRM_OXID(frm);
	if (mod_hash_find(FRM2SS(frm)->ss_sol_oxid_hash,
	    FMHK(sol_oxid), (mod_hash_val_t *)&xch) != 0) {
		PRT_FRM_HDR(__FUNCTION__, frm);
		FCOEI_LOG(__FUNCTION__, "can't find the corresponding xch: "
		    "oxid/%x %lu - %lu", sol_oxid,
		    CURRENT_CLOCK, frm->frm_clock);
		return;
	} else {
		fpkt = xch->xch_fpkt;
	}

	/*
	 * Decide the actual response length
	 */
	actual_size = fpkt->pkt_rsplen;
	if (actual_size > frm->frm_payload_size) {
		actual_size = frm->frm_payload_size;
	}

	/*
	 * Update the exchange and hash table
	 */
	(void) mod_hash_remove(FRM2SS(frm)->ss_sol_oxid_hash,
	    FMHK(xch->xch_oxid), &val);
	ASSERT((fcoei_exchange_t *)val == xch);
	xch->xch_flags &= ~XCH_FLAG_IN_SOL_HASH;

	/*
	 * Upate fpkt related elements
	 */
	FCOEI_FRM2FHDR(frm, &fpkt->pkt_resp_fhdr);

	/*
	 * we should set pkt_reason and pkt_state carefully
	 */
	fpkt->pkt_state = FC_PKT_SUCCESS;
	fpkt->pkt_reason = 0;

	/*
	 * First we zero the first 12 byte of dest
	 */
	bzero(xch->xch_fpkt->pkt_resp, 12);
	i_fcp_status = BE_IN32(frm->frm_payload + 8);
	if (i_fcp_status != 0) {
		fcoei_fill_fcp_resp(frm->frm_payload,
		    (uint8_t *)xch->xch_fpkt->pkt_resp, actual_size);
	}

	/*
	 * Update pkt_resp_resid
	 */
	fpkt->pkt_data_resid = xch->xch_resid;
	if ((xch->xch_resid != 0) && ((xch->xch_resid % 0x200) == 0) &&
	    ((xch->xch_fpkt->pkt_datalen % 0x200) == 0) &&
	    (i_fcp_status == 0)) {
		FCOEI_LOG(__FUNCTION__, "frame lost no pause ? %x/%x",
		    xch->xch_resid, xch->xch_fpkt->pkt_datalen);
		fpkt->pkt_state = FC_PKT_LOCAL_RJT;
		fpkt->pkt_reason = FC_REASON_UNDERRUN;
	}

	/*
	 * Notify LV it's over
	 */
	if (fpkt->pkt_tran_flags & FC_TRAN_NO_INTR) {
		FCOEI_LOG(__FUNCTION__, "BEFORE WAKEUP: %p-%p", fpkt, xch);
		sema_v(&xch->xch_sema);
		FCOEI_LOG(__FUNCTION__, "AFTERE WAKEUP: %p-%p", fpkt, xch);
	} else {
		xch->xch_fpkt->pkt_comp(xch->xch_fpkt);
	}
}

/*
 * fcoei_process_sol_els_rsp
 *	ELS response is received
 *
 * Input:
 *	frm = ELS response frame
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	N/A
 */
static void
fcoei_process_sol_els_rsp(fcoe_frame_t *frm)
{
	uint16_t		 sol_oxid    = 0;
	uint32_t		 actual_size = 0;
	fcoei_exchange_t	*xch;
	fc_packet_t		*fpkt;

	/*
	 * Look for the related exchange
	 */
	xch = NULL;
	fpkt = NULL;
	sol_oxid = FRM_OXID(frm);
	if (mod_hash_find(FRM2SS(frm)->ss_sol_oxid_hash,
	    FMHK(sol_oxid), (mod_hash_val_t *)&xch) != 0) {
		PRT_FRM_HDR(__FUNCTION__, frm);
		FCOEI_LOG(__FUNCTION__, "can't find the "
		    "corresponding xch: oxid/%x", sol_oxid);
		return;
	}

	xch->xch_rxid = FRM_RXID(frm);
	fpkt = xch->xch_fpkt;

	/*
	 * Decide the actual response length
	 */
	actual_size = frm->frm_payload_size;
	if (actual_size > fpkt->pkt_rsplen) {
		FCOEI_LOG(__FUNCTION__, "pkt_rsplen is smaller"
		    "0x(%x - %x)", actual_size, fpkt->pkt_rsplen);
		actual_size = fpkt->pkt_rsplen;
	}

	/*
	 * Upate fpkt related elements
	 */
	FCOEI_FRM2FHDR(frm, &fpkt->pkt_resp_fhdr);
	fcoei_fill_els_fpkt_resp(frm, xch, actual_size);

	/*
	 * we should set pkt_reason and pkt_state carefully now
	 * Need to analyze pkt_reason according to the response.
	 * Leave it untouched now.
	 */
	if (((ls_code_t *)(void *)xch->xch_fpkt->pkt_resp)->ls_code ==
	    LA_ELS_RJT) {
		fcoei_complete_xch(xch, NULL, FC_PKT_FABRIC_RJT,
		    FC_REASON_INVALID_PARAM);
	} else {
		fcoei_complete_xch(xch, NULL, FC_PKT_SUCCESS, 0);
	}
}

/*
 * fcoei_process_sol_ct_rsp
 *	CT response is received
 *
 * Input:
 *	frm = CT response frame
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	N/A
 */
static void
fcoei_process_sol_ct_rsp(fcoe_frame_t *frm)
{
	uint16_t		 sol_oxid    = 0;
	uint32_t		 actual_size = 0;
	fcoei_exchange_t	*xch;
	fc_packet_t		*fpkt;

	/*
	 * Look for the related exchange
	 */
	xch = NULL;
	fpkt = NULL;
	sol_oxid = FRM_OXID(frm);
	if (mod_hash_find(FRM2SS(frm)->ss_sol_oxid_hash,
	    FMHK(sol_oxid), (mod_hash_val_t *)&xch) != 0) {
		FCOEI_LOG(__FUNCTION__, "can't find the "
		    "corresponding xch: oxid/%x", sol_oxid);
		return;
	}

	xch->xch_rxid = FRM_RXID(frm);
	fpkt = xch->xch_fpkt;

	/*
	 * Decide the actual response length
	 */
	actual_size = fpkt->pkt_rsplen;
	if (actual_size > frm->frm_payload_size) {
		FCOEI_LOG(__FUNCTION__, "payload is smaller"
		    "0x(%x - %x)", actual_size, frm->frm_payload_size);
		actual_size = frm->frm_payload_size;
	}

	/*
	 * Update fpkt related elements
	 * Caution: we needn't do byte swapping for CT response
	 */
	FCOEI_FRM2FHDR(frm, &fpkt->pkt_resp_fhdr);
	bcopy(FPLD, (uint8_t *)xch->xch_fpkt->pkt_resp, actual_size);

	/*
	 * Complete it with frm as NULL
	 */
	fcoei_complete_xch(xch, NULL, FC_PKT_SUCCESS, 0);
}

/*
 * fcoei_process_sol_abts_acc
 *	ABTS accpet is received
 *
 * Input:
 *	frm = ABTS accept frame
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	We will always finish the abortion of solicited exchanges,
 *	so we will not depend on the response from the remote side.
 *	We just log one message.
 */
static void
fcoei_process_sol_abts_acc(fcoe_frame_t *frm)
{
	FCOEI_LOG(__FUNCTION__, "the remote side has agreed to "
	    "abort the exchange: oxid-%x, rxid-%x",
	    FCOE_B2V_2(frm->frm_payload + 4),
	    FCOE_B2V_2(frm->frm_payload + 6));
}

/*
 * fcoei_process_sol_abts_rjt
 *	ABTS reject is received
 *
 * Input:
 *	frm = ABTS reject frame
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	We will alwayas finish the abortion of solicited exchanges,
 *	so we will not depend on the response from the remote side.
 *	We just log one message.
 */
static void
fcoei_process_sol_abts_rjt(fcoe_frame_t *frm)
{
	FCOEI_LOG(__FUNCTION__, "the remote side rejected "
	    "our request to abort one exchange.: %p", frm);
}

/*
 * fcoei_fill_els_fpkt_resp
 *	Fill fpkt ELS response in host format according frm payload
 *
 * Input:
 *	src = frm payload in link format
 *	dest = fpkt ELS response in host format
 *	size = Maximum conversion size
 *	els_op = ELS opcode
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	fpkt->pkt_resp must be mapped to one data structure, and it's
 *	different from the content in the raw frame
 */
static void
fcoei_fill_els_fpkt_resp(fcoe_frame_t *frm, fcoei_exchange_t *xch, int size)
{
	uint8_t			*src	   = frm->frm_payload;
	uint8_t			*dest	   = (uint8_t *)xch->xch_fpkt->pkt_resp;
	ls_code_t		*els_code  = (ls_code_t *)(void *)dest;
	la_els_logi_t		*els_logi  = (la_els_logi_t *)(void *)dest;
	la_els_adisc_t		*els_adisc = (la_els_adisc_t *)(void *)dest;
	la_els_rls_acc_t	*els_rls;
	la_els_rnid_acc_t	*els_rnid;
	struct fcp_prli_acc	*prli_acc;
	int			 offset;

	els_code->ls_code = FCOE_B2V_1(src);
	if (els_code->ls_code == LA_ELS_RJT) {
		FCOEI_LOG(__FUNCTION__, "size :%d", size);
		return;
	}

	switch (((ls_code_t *)(void *)xch->xch_fpkt->pkt_cmd)->ls_code) {
	case LA_ELS_FLOGI:
		bcopy((char *)frm->frm_hdr - 22,
		    frm->frm_eport->eport_efh_dst, ETHERADDRL);
		if (frm->frm_payload[8] & 0x10) {
			/*
			 * We are in fabric p2p mode
			 */
			uint8_t src_addr[ETHERADDRL];
			frm->frm_eport->eport_flags &=
			    ~EPORT_FLAG_IS_DIRECT_P2P;
			FCOE_SET_DEFAULT_OUI(src_addr);
			bcopy(frm->frm_hdr->hdr_d_id, src_addr + 3, 3);
			frm->frm_eport->eport_set_mac_address(
			    frm->frm_eport, src_addr, 1);
		} else {
			/*
			 * We are in direct p2p mode
			 */
			frm->frm_eport->eport_flags |=
			    EPORT_FLAG_IS_DIRECT_P2P;
		}

		if (!(FRM2SS(frm)->ss_eport->eport_flags &
		    EPORT_FLAG_IS_DIRECT_P2P)) {
			FRM2SS(frm)->ss_p2p_info.fca_d_id = FRM_D_ID(frm);
		}

		/* FALLTHROUGH */

	case LA_ELS_PLOGI:
		if (FRM2SS(frm)->ss_eport->eport_flags &
		    EPORT_FLAG_IS_DIRECT_P2P) {
			FRM2SS(frm)->ss_p2p_info.fca_d_id = FRM_D_ID(frm);
			FRM2SS(frm)->ss_p2p_info.d_id = FRM_S_ID(frm);
		}

		offset = offsetof(la_els_logi_t, common_service);
		els_logi->common_service.fcph_version = FCOE_B2V_2(src +
		    offset);
		offset += 2;
		els_logi->common_service.btob_credit = FCOE_B2V_2(src +
		    offset);
		offset += 2;
		els_logi->common_service.cmn_features = FCOE_B2V_2(src +
		    offset);
		offset += 2;
		els_logi->common_service.rx_bufsize = FCOE_B2V_2(src +
		    offset);
		offset += 2;
		els_logi->common_service.conc_sequences = FCOE_B2V_2(src +
		    offset);
		offset += 2;
		els_logi->common_service.relative_offset = FCOE_B2V_2(src +
		    offset);
		offset += 2;
		els_logi->common_service.e_d_tov = FCOE_B2V_4(src +
		    offset);

		/*
		 * port/node WWN
		 */
		offset = offsetof(la_els_logi_t, nport_ww_name);
		bcopy(src + offset, &els_logi->nport_ww_name, 8);
		offset = offsetof(la_els_logi_t, node_ww_name);
		bcopy(src + offset, &els_logi->node_ww_name, 8);

		/*
		 * class_3
		 */
		offset = offsetof(la_els_logi_t, class_3);
		els_logi->class_3.class_opt = FCOE_B2V_2(src + offset);
		offset += 2;
		els_logi->class_3.initiator_ctl = FCOE_B2V_2(src + offset);
		offset += 2;
		els_logi->class_3.recipient_ctl = FCOE_B2V_2(src + offset);
		offset += 2;
		els_logi->class_3.rcv_size = FCOE_B2V_2(src + offset);
		offset += 2;
		els_logi->class_3.conc_sequences = FCOE_B2V_2(src + offset);
		offset += 2;
		els_logi->class_3.n_port_e_to_e_credit = FCOE_B2V_2(src +
		    offset);
		offset += 2;
		els_logi->class_3.open_seq_per_xchng = FCOE_B2V_2(src + offset);

		break;

	case LA_ELS_PRLI:
		/*
		 * PRLI service parameter response page
		 *
		 * fcp_prli_acc doesn't include ls_code, don't use offsetof
		 */
		offset = 4;
		prli_acc = (struct fcp_prli_acc *)(void *)(dest + offset);
		prli_acc->type = FCOE_B2V_1(src + offset);
		/*
		 * Type code extension
		 */
		offset += 1;
		/*
		 * PRLI response flags
		 */
		offset += 1;
		prli_acc->orig_process_assoc_valid =
		    (FCOE_B2V_2(src + offset) & BIT_15) ? 1 : 0;
		prli_acc->resp_process_assoc_valid =
		    (FCOE_B2V_2(src + offset) & BIT_14) ? 1 : 0;
		prli_acc->image_pair_established =
		    (FCOE_B2V_2(src + offset) & BIT_13) ? 1 : 0;
		prli_acc->accept_response_code =
		    (FCOE_B2V_2(src + offset) & 0x0F00) >> 8;
		/*
		 * process associator
		 */
		offset += 2;
		prli_acc->orig_process_associator = FCOE_B2V_4(src + offset);
		offset += 4;
		prli_acc->resp_process_associator = FCOE_B2V_4(src + offset);
		/*
		 * FC-4 type
		 */
		offset += 4;
		prli_acc->initiator_fn =
		    (FCOE_B2V_4(src + offset) & BIT_5) ? 1 : 0;
		prli_acc->target_fn =
		    (FCOE_B2V_4(src + offset) & BIT_4) ? 1 : 0;
		prli_acc->cmd_data_mixed =
		    (FCOE_B2V_4(src + offset) & BIT_3) ? 1 : 0;
		prli_acc->data_resp_mixed =
		    (FCOE_B2V_4(src + offset) & BIT_2) ? 1 : 0;
		prli_acc->read_xfer_rdy_disabled =
		    (FCOE_B2V_4(src + offset) & BIT_1) ? 1 : 0;
		prli_acc->write_xfer_rdy_disabled =
		    (FCOE_B2V_4(src + offset) & BIT_0) ? 1 : 0;

		break;

	case LA_ELS_LOGO:
		/*
		 * could only be LS_ACC, no additional information
		 */
		els_code->ls_code = FCOE_B2V_1(src);
		break;

	case LA_ELS_SCR:
		/*
		 * LS_ACC/LS_RJT, no additional information
		 */
		els_code->ls_code = FCOE_B2V_1(src);
		break;

	case LA_ELS_ADISC:
		offset = 5;
		els_adisc->hard_addr.hard_addr = FCOE_B2V_3(src + offset);
		offset = offsetof(la_els_adisc_t, port_wwn);
		bcopy(src + offset, &els_adisc->port_wwn, 8);
		offset = offsetof(la_els_adisc_t, node_wwn);
		bcopy(src + offset, &els_adisc->node_wwn, 8);
		offset += 9;
		els_adisc->nport_id.port_id = FCOE_B2V_3(src + offset);
		break;
	case LA_ELS_RLS:
		els_rls = (la_els_rls_acc_t *)(void *)dest;
		els_rls->ls_code.ls_code = FCOE_B2V_1(src);
		offset = 4;
		els_rls->rls_link_params.rls_link_fail =
		    FCOE_B2V_4(src + offset);
		offset = 8;
		els_rls->rls_link_params.rls_sync_loss =
		    FCOE_B2V_4(src + offset);
		offset = 12;
		els_rls->rls_link_params.rls_sig_loss =
		    FCOE_B2V_4(src + offset);
		offset = 16;
		els_rls->rls_link_params.rls_prim_seq_err =
		    FCOE_B2V_4(src + offset);
		offset = 20;
		els_rls->rls_link_params.rls_invalid_word =
		    FCOE_B2V_4(src + offset);
		offset = 24;
		els_rls->rls_link_params.rls_invalid_crc =
		    FCOE_B2V_4(src + offset);
		break;
	case LA_ELS_RNID:
		els_rnid = (la_els_rnid_acc_t *)(void *)dest;
		els_rnid->ls_code.ls_code = FCOE_B2V_1(src);
		offset = 4;
		bcopy(src + offset, &els_rnid->hdr.data_format, 1);
		offset = 5;
		bcopy(src + offset, &els_rnid->hdr.cmn_len, 1);
		offset = 7;
		bcopy(src + offset, &els_rnid->hdr.specific_len, 1);
		offset = 8;
		bcopy(src + offset, els_rnid->data, FCIO_RNID_MAX_DATA_LEN);
		break;
	default:
		FCOEI_LOG(__FUNCTION__, "unsupported R_CTL");
		break;
	}
}

/*
 * fcoei_fill_fcp_resp
 *	Fill fpkt FCP response in host format according to frm payload
 *
 * Input:
 *	src - frm payload in link format
 *	dest - fpkt FCP response in host format
 *	size - Maximum conversion size
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	This is called only for SCSI response with non good status
 */
static void
fcoei_fill_fcp_resp(uint8_t *src, uint8_t *dest, int size)
{
	fcp_rsp_t	*fcp_rsp_iu = (fcp_rsp_t *)(void *)dest;
	int		 offset;

	/*
	 * set fcp_status
	 */
	offset = offsetof(fcp_rsp_t, fcp_u);
	offset += 2;
	fcp_rsp_iu->fcp_u.fcp_status.resid_under =
	    (FCOE_B2V_1(src + offset) & BIT_3) ? 1 : 0;
	fcp_rsp_iu->fcp_u.fcp_status.resid_over =
	    (FCOE_B2V_1(src + offset) & BIT_2) ? 1 : 0;
	fcp_rsp_iu->fcp_u.fcp_status.sense_len_set =
	    (FCOE_B2V_1(src + offset) & BIT_1) ? 1 : 0;
	fcp_rsp_iu->fcp_u.fcp_status.rsp_len_set =
	    (FCOE_B2V_1(src + offset) & BIT_0) ? 1 : 0;
	offset += 1;
	fcp_rsp_iu->fcp_u.fcp_status.scsi_status = FCOE_B2V_1(src + offset);
	/*
	 * fcp_resid/fcp_sense_len/fcp_response_len
	 */
	offset = offsetof(fcp_rsp_t, fcp_resid);
	fcp_rsp_iu->fcp_resid = FCOE_B2V_4(src + offset);
	offset = offsetof(fcp_rsp_t, fcp_sense_len);
	fcp_rsp_iu->fcp_sense_len = FCOE_B2V_4(src + offset);
	offset = offsetof(fcp_rsp_t, fcp_response_len);
	fcp_rsp_iu->fcp_response_len = FCOE_B2V_4(src + offset);
	/*
	 * sense or response
	 */
	offset += 4;
	if (fcp_rsp_iu->fcp_sense_len) {
		if ((offset + fcp_rsp_iu->fcp_sense_len) > size) {
			FCOEI_LOG(__FUNCTION__, "buffer too small - sens");
			return;
		}
		bcopy(src + offset, dest + offset, fcp_rsp_iu->fcp_sense_len);
		offset += fcp_rsp_iu->fcp_sense_len;
	}

	if (fcp_rsp_iu->fcp_response_len) {
		if ((offset + fcp_rsp_iu->fcp_response_len) > size) {
			FCOEI_LOG(__FUNCTION__, "buffer too small - resp");
			return;
		}
		bcopy(src + offset, dest + offset,
		    fcp_rsp_iu->fcp_response_len);
	}
}

void
fcoei_init_ect_vectors(fcoe_client_t *ect)
{
	ect->ect_rx_frame	   = fcoei_rx_frame;
	ect->ect_port_event	   = fcoei_port_event;
	ect->ect_release_sol_frame = fcoei_release_sol_frame;
}

/*
 * fcoei_process_unsol_frame
 *	Unsolicited frame is received
 *
 * Input:
 *	frame = unsolicited frame that is received
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	watchdog will call this to process unsolicited frames that we
 *	just received fcoei_process_xx is used to handle different
 *	unsolicited frames
 */
void
fcoei_process_unsol_frame(fcoe_frame_t *frm)
{
	fcoei_exchange_t	*xch;
	uint16_t		 sol_oxid;

	switch (FRM_R_CTL(frm)) {
	case R_CTL_SOLICITED_DATA:
		/*
		 * READ data phase frame
		 * Find the associated exchange
		 */
		sol_oxid = FRM_OXID(frm);
		if (mod_hash_find(FRM2SS(frm)->ss_sol_oxid_hash,
		    FMHK(sol_oxid), (mod_hash_val_t *)&xch) != 0) {
			PRT_FRM_HDR(__FUNCTION__, frm);
			FCOEI_LOG(__FUNCTION__, "associated xch not found: "
			    "oxid/%x %lu - %lu", sol_oxid,
			    CURRENT_CLOCK, frm->frm_clock);
			break;
		}

		/*
		 * Copy data into fpkt data buffer, and update the counter
		 */
		bcopy(frm->frm_payload, (uint8_t *)xch->xch_fpkt->pkt_data +
		    FRM_PARAM(frm), frm->frm_payload_size);
		xch->xch_resid -= frm->frm_payload_size;
		xch->xch_rxid = FRM_RXID(frm);
		break;

	case R_CTL_XFER_RDY:
		fcoei_process_unsol_xfer_rdy(frm);
		break;

	case R_CTL_STATUS:
		fcoei_process_sol_fcp_resp(frm);
		break;

	case R_CTL_ELS_REQ:
		fcoei_process_unsol_els_req(frm);
		break;

	case R_CTL_LS_ABTS:
		fcoei_process_unsol_abts_req(frm);
		break;

	case R_CTL_ELS_RSP:
		fcoei_process_sol_els_rsp(frm);
		break;

	case R_CTL_SOLICITED_CONTROL:
		fcoei_process_sol_ct_rsp(frm);
		break;

	case R_CTL_LS_BA_ACC:
		fcoei_process_sol_abts_acc(frm);
		break;

	case R_CTL_LS_BA_RJT:
		fcoei_process_sol_abts_rjt(frm);
		break;

	default:
		/*
		 * Unsupported frame
		 */
		PRT_FRM_HDR("Unsupported unsol frame: ", frm);
	}

	/*
	 * Release the frame and netb
	 */
	frm->frm_eport->eport_free_netb(frm->frm_netb);
	frm->frm_eport->eport_release_frame(frm);
}

/*
 * fcoei_handle_sol_frame_done
 *	solicited frame is just sent out
 *
 * Input:
 *	frame = solicited frame that has been sent out
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	watchdog will call this to handle solicited frames that FCOEI
 *	has sent out Non-request frame post handling
 */
void
fcoei_handle_sol_frame_done(fcoe_frame_t *frm)
{
	/*
	 * the corresponding xch could be NULL at this time
	 */
	fcoei_exchange_t	*xch  = FRM2IFM(frm)->ifm_xch;

	switch (FRM2IFM(frm)->ifm_rctl) {
	case R_CTL_ELS_RSP:
		/*
		 * Complete it with frm as NULL
		 */
		fcoei_complete_xch(xch, NULL, FC_PKT_SUCCESS, 0);
		break;

	case R_CTL_LS_BA_ACC:
		FCOEI_LOG(__FUNCTION__,  "BA_ACC out: xch-%p, frm-%p",
		    xch, frm);
		PRT_FRM_HDR("LS_BA_ACC", frm);
		break;

	case R_CTL_LS_BA_RJT:
		FCOEI_LOG(__FUNCTION__,  "BA_RJT out: xch-%p, frm-%p",
		    xch, frm);
		PRT_FRM_HDR("LS_BA_RJT", frm);
		break;

	default:
		/*
		 * Unsupported frame
		 */
		PRT_FRM_HDR("Unsupported sol frame: ", frm);
	}

	/*
	 * We should release only the frame, and we don't care its netb
	 */
	FRM2SS(frm)->ss_eport->eport_release_frame(frm);
}

/*
 * fcoei_port_event
 *	link/port state changed
 *
 * Input:
 *	eport = to indicate which port has changed
 *	event = what change
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	refer fctl.h for ss_link_state value
 */
void
fcoei_port_event(fcoe_port_t *eport, uint32_t event)
{
	fcoei_event_t	*ae;

	if (!(EPORT2SS(eport)->ss_flags & SS_FLAG_LV_BOUND)) {
		FCOEI_LOG(__FUNCTION__, "not bound now");
		return;
	}

	mutex_enter(&EPORT2SS(eport)->ss_watchdog_mutex);
	switch (event) {
	case FCOE_NOTIFY_EPORT_LINK_DOWN:
		EPORT2SS(eport)->ss_link_state = FC_STATE_OFFLINE;
		cmn_err(CE_NOTE, "%02x%02x%02x%02x%02x%02x%02x%02x Link down",
		    eport->eport_portwwn[0], eport->eport_portwwn[1],
		    eport->eport_portwwn[2], eport->eport_portwwn[3],
		    eport->eport_portwwn[4], eport->eport_portwwn[5],
		    eport->eport_portwwn[6], eport->eport_portwwn[7]);
		break;

	case FCOE_NOTIFY_EPORT_LINK_UP:
		if (eport->eport_mtu >= 2200) {
			EPORT2SS(eport)->ss_fcp_data_payload_size =
			    FCOE_DEFAULT_FCP_DATA_PAYLOAD_SIZE;
		} else {
			FCOEI_LOG(__FUNCTION__, "fcoei: MTU is not big enough. "
			    "we will use 1K frames in FCP data phase.");
			EPORT2SS(eport)->ss_fcp_data_payload_size =
			    FCOE_MIN_FCP_DATA_PAYLOAD_SIZE;
		}

		cmn_err(CE_NOTE, "%02x%02x%02x%02x%02x%02x%02x%02x Link up",
		    eport->eport_portwwn[0], eport->eport_portwwn[1],
		    eport->eport_portwwn[2], eport->eport_portwwn[3],
		    eport->eport_portwwn[4], eport->eport_portwwn[5],
		    eport->eport_portwwn[6], eport->eport_portwwn[7]);
		EPORT2SS(eport)->ss_link_state = FC_STATE_ONLINE;
		break;

	default:
		FCOEI_LOG(__FUNCTION__, "unsupported event");
		mutex_exit(&EPORT2SS(eport)->ss_watchdog_mutex);

		return;
	}

	EPORT2SS(eport)->ss_port_event_counter++;
	ae = (fcoei_event_t *)kmem_zalloc(sizeof (fcoei_event_t), KM_SLEEP);
	ae->ae_type = AE_EVENT_PORT;
	ae->ae_obj = EPORT2SS(eport);
	ae->ae_specific = EPORT2SS(eport)->ss_link_state;
	list_insert_tail(&EPORT2SS(eport)->ss_event_list, ae);
	mutex_exit(&EPORT2SS(eport)->ss_watchdog_mutex);
}

/*
 * fcoei_process_event_port
 *	link/port state changed
 *
 * Input:
 *	ae = link fcoei_event
 *
 * Returns:
 *	N/A
 *
 * Comments:
 *	asynchronous events from FCOE
 */
void
fcoei_process_event_port(fcoei_event_t *ae)
{
	fcoei_soft_state_t	*ss = (fcoei_soft_state_t *)ae->ae_obj;

	if (ss->ss_eport->eport_link_speed == FCOE_PORT_SPEED_1G) {
		ae->ae_specific |= FC_STATE_1GBIT_SPEED;
	} else if (ss->ss_eport->eport_link_speed ==
	    FCOE_PORT_SPEED_10G) {
		ae->ae_specific |= FC_STATE_10GBIT_SPEED;
	}

	if (ss->ss_flags & SS_FLAG_LV_BOUND) {
		ss->ss_bind_info.port_statec_cb(ss->ss_port,
		    (uint32_t)ae->ae_specific);
	} else {
		FCOEI_LOG(__FUNCTION__, "ss %p not bound now", ss);
	}

	atomic_dec_32(&ss->ss_port_event_counter);
	kmem_free(ae, sizeof (fcoei_event_t));
}
