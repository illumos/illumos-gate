/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at
 * http://www.opensource.org/licenses/cddl1.txt.
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
 * Copyright (c) 2004-2012 Emulex. All rights reserved.
 * Use is subject to license terms.
 */

#include <emlxs.h>


/* Required for EMLXS_CONTEXT in EMLXS_MSGF calls */
EMLXS_MSG_DEF(EMLXS_DIAG_C);

uint32_t emlxs_diag_pattern[256] = {
	/* Walking ones */
	0x80000000, 0x40000000, 0x20000000, 0x10000000,
	0x08000000, 0x04000000, 0x02000000, 0x01000000,
	0x00800000, 0x00400000, 0x00200000, 0x00100000,
	0x00080000, 0x00040000, 0x00020000, 0x00010000,
	0x00008000, 0x00004000, 0x00002000, 0x00001000,
	0x00000800, 0x00000400, 0x00000200, 0x00000100,
	0x00000080, 0x00000040, 0x00000020, 0x00000010,
	0x00000008, 0x00000004, 0x00000002, 0x00000001,

	/* Walking zeros */
	0x7fffffff, 0xbfffffff, 0xdfffffff, 0xefffffff,
	0xf7ffffff, 0xfbffffff, 0xfdffffff, 0xfeffffff,
	0xff7fffff, 0xffbfffff, 0xffdfffff, 0xffefffff,
	0xfff7ffff, 0xfffbffff, 0xfffdffff, 0xfffeffff,
	0xffff7fff, 0xffffbfff, 0xffffdfff, 0xffffefff,
	0xfffff7ff, 0xfffffbff, 0xfffffdff, 0xfffffeff,
	0xffffff7f, 0xffffffbf, 0xffffffdf, 0xffffffef,
	0xfffffff7, 0xfffffffb, 0xfffffffd, 0xfffffffe,

	/* all zeros */
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,
	0x00000000, 0x00000000, 0x00000000, 0x00000000,

	/* all ones */
	0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
	0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
	0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
	0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
	0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
	0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
	0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,
	0xffffffff, 0xffffffff, 0xffffffff, 0xffffffff,

	/* all 5's */
	0x55555555, 0x55555555, 0x55555555, 0x55555555,
	0x55555555, 0x55555555, 0x55555555, 0x55555555,
	0x55555555, 0x55555555, 0x55555555, 0x55555555,
	0x55555555, 0x55555555, 0x55555555, 0x55555555,
	0x55555555, 0x55555555, 0x55555555, 0x55555555,
	0x55555555, 0x55555555, 0x55555555, 0x55555555,
	0x55555555, 0x55555555, 0x55555555, 0x55555555,
	0x55555555, 0x55555555, 0x55555555, 0x55555555,

	/* all a's */
	0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa,
	0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa,
	0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa,
	0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa,
	0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa,
	0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa,
	0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa,
	0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa, 0xaaaaaaaa,

	/* all 5a's */
	0x5a5a5a5a, 0x5a5a5a5a, 0x5a5a5a5a, 0x5a5a5a5a,
	0x5a5a5a5a, 0x5a5a5a5a, 0x5a5a5a5a, 0x5a5a5a5a,
	0x5a5a5a5a, 0x5a5a5a5a, 0x5a5a5a5a, 0x5a5a5a5a,
	0x5a5a5a5a, 0x5a5a5a5a, 0x5a5a5a5a, 0x5a5a5a5a,
	0x5a5a5a5a, 0x5a5a5a5a, 0x5a5a5a5a, 0x5a5a5a5a,
	0x5a5a5a5a, 0x5a5a5a5a, 0x5a5a5a5a, 0x5a5a5a5a,
	0x5a5a5a5a, 0x5a5a5a5a, 0x5a5a5a5a, 0x5a5a5a5a,
	0x5a5a5a5a, 0x5a5a5a5a, 0x5a5a5a5a, 0x5a5a5a5a,

	/* all a5's */
	0xa5a5a5a5, 0xa5a5a5a5, 0xa5a5a5a5, 0xa5a5a5a5,
	0xa5a5a5a5, 0xa5a5a5a5, 0xa5a5a5a5, 0xa5a5a5a5,
	0xa5a5a5a5, 0xa5a5a5a5, 0xa5a5a5a5, 0xa5a5a5a5,
	0xa5a5a5a5, 0xa5a5a5a5, 0xa5a5a5a5, 0xa5a5a5a5,
	0xa5a5a5a5, 0xa5a5a5a5, 0xa5a5a5a5, 0xa5a5a5a5,
	0xa5a5a5a5, 0xa5a5a5a5, 0xa5a5a5a5, 0xa5a5a5a5,
	0xa5a5a5a5, 0xa5a5a5a5, 0xa5a5a5a5, 0xa5a5a5a5,
	0xa5a5a5a5, 0xa5a5a5a5, 0xa5a5a5a5, 0xa5a5a5a5
};


/* Default pkt callback routine */
static void
emlxs_diag_pkt_callback(fc_packet_t *pkt)
{
	emlxs_port_t *port = (emlxs_port_t *)pkt->pkt_ulp_private;

	/* Set the completed flag and wake up sleeping threads */
	mutex_enter(&EMLXS_PKT_LOCK);
	pkt->pkt_tran_flags |= FC_TRAN_COMPLETED;
	cv_broadcast(&EMLXS_PKT_CV);
	mutex_exit(&EMLXS_PKT_LOCK);

	return;

} /* emlxs_diag_pkt_callback() */


extern uint32_t
emlxs_diag_echo_run(emlxs_port_t *port, uint32_t did, uint32_t pattern)
{
	emlxs_hba_t *hba = HBA;
	uint32_t i = 0;
	uint32_t rval = FC_SUCCESS;
	int32_t pkt_ret;
	fc_packet_t *pkt;
	ELS_PKT *els;
	clock_t timeout;
	uint8_t *pkt_resp;
	char *pattern_buffer;
	uint32_t length;
	uint32_t *lptr;
	NODELIST *ndlp;
	uint8_t *pat;

	/* Check did */
	if (did == 0) {
		did = port->did;
	}

	/* Check if device is ready */
	if ((hba->state < FC_LINK_UP) || (port->did == 0)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_diag_error_msg,
		    "ECHO: HBA not ready.");

		return (FC_TRAN_BUSY);
	}

	/* Check for the host node */
	ndlp = emlxs_node_find_did(port, port->did, 1);

	if (!ndlp || !ndlp->nlp_active) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_diag_error_msg,
		    "ECHO: HBA not ready.");

		return (FC_TRAN_BUSY);
	}

	length = 124;

	/* Prepare ECHO pkt */
	if (!(pkt = emlxs_pkt_alloc(port, sizeof (uint32_t) + length,
	    sizeof (uint32_t) + length, 0, KM_NOSLEEP))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_diag_error_msg,
		    "ECHO: Unable to allocate packet. size=%x",
		    sizeof (uint32_t) + length);

		return (FC_NOMEM);
	}

	/* pkt initialization */
	pkt->pkt_tran_type = FC_PKT_EXCHANGE;
	pkt->pkt_timeout = 60;

	/* Build the fc header */
	pkt->pkt_cmd_fhdr.d_id = did;
	pkt->pkt_cmd_fhdr.r_ctl = R_CTL_EXTENDED_SVC | R_CTL_UNSOL_CONTROL;
	pkt->pkt_cmd_fhdr.s_id = port->did;
	pkt->pkt_cmd_fhdr.type = FC_TYPE_EXTENDED_LS;
	pkt->pkt_cmd_fhdr.f_ctl =
	    F_CTL_FIRST_SEQ | F_CTL_SEQ_INITIATIVE | F_CTL_END_SEQ;
	pkt->pkt_cmd_fhdr.seq_id = 0;
	pkt->pkt_cmd_fhdr.df_ctl = 0;
	pkt->pkt_cmd_fhdr.seq_cnt = 0;
	pkt->pkt_cmd_fhdr.ox_id = 0xffff;
	pkt->pkt_cmd_fhdr.rx_id = 0xffff;
	pkt->pkt_cmd_fhdr.ro = 0;
	pkt->pkt_comp = emlxs_diag_pkt_callback;

	/* Build the command */
	els = (ELS_PKT *) pkt->pkt_cmd;
	els->elsCode = 0x10;
	pattern_buffer = (char *)els->un.pad;

	if (pattern) {
		/* Fill the transmit buffer with the pattern */
		lptr = (uint32_t *)pattern_buffer;

		for (i = 0; i < length; i += 4) {
			*lptr++ = pattern;
		}
	} else {
		/* Program the default echo pattern */
		bzero(pattern_buffer, length);
		(void) snprintf(pattern_buffer, length,
		    "Emulex. We network storage. Emulex. We network storage. "
		    "Emulex. We network storage. Emulex. We network storage.");
	}

	/* Send ECHO pkt */
	if ((rval = emlxs_pkt_send(pkt, 1)) != FC_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_diag_error_msg,
		    "ECHO: Packet send failed.");

		goto done;
	}

	/* Wait for ECHO completion */
	mutex_enter(&EMLXS_PKT_LOCK);
	timeout = emlxs_timeout(hba, (pkt->pkt_timeout + 15));
	pkt_ret = 0;
	while ((pkt_ret != -1) && !(pkt->pkt_tran_flags & FC_TRAN_COMPLETED)) {
		pkt_ret =
		    cv_timedwait(&EMLXS_PKT_CV, &EMLXS_PKT_LOCK, timeout);

	}
	mutex_exit(&EMLXS_PKT_LOCK);

	if (pkt_ret == -1) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_echo_failed_msg,
		    "Packet timed out.");

		return (FC_ABORTED);
	}

	if (pkt->pkt_state != FC_PKT_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_echo_failed_msg,
		    "Transport error.");

		rval = FC_TRANSPORT_ERROR;
		goto done;
	}

	/* Check response payload */
	pkt_resp = (uint8_t *)pkt->pkt_resp + 4;
	pat = (uint8_t *)pattern_buffer;
	rval = FC_SUCCESS;

	for (i = 0; i < length; i++, pkt_resp++, pat++) {
		if (*pkt_resp != *pat) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_echo_failed_msg,
			    "Data miscompare. did=%06x length=%d. Offset %d "
			    "value %02x should be %02x.", did, length, i,
			    *pkt_resp, *pat);

			rval = EMLXS_TEST_FAILED;

			break;
		}
	}

	if (rval == FC_SUCCESS) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_echo_complete_msg,
		    "did=%06x  length=%d  pattern=%02x,%02x,%02x,%02x...",
		    did, length, pattern_buffer[0] & 0xff,
		    pattern_buffer[1] & 0xff, pattern_buffer[2] & 0xff,
		    pattern_buffer[3] & 0xff);
	}

done:

	/* Free the echo pkt */
	emlxs_pkt_free(pkt);

	return (rval);

} /* emlxs_diag_echo_run() */


extern uint32_t
emlxs_diag_biu_run(emlxs_hba_t *hba, uint32_t pattern)
{
	emlxs_port_t *port = &PPORT;
	MAILBOXQ *mbq = NULL;
	MATCHMAP *mp = NULL;
	MATCHMAP *mp1 = NULL;
	uint32_t i;
	uint8_t *inptr;
	uint8_t *outptr;
	int32_t rval = FC_SUCCESS;
	uint32_t *lptr;

	/* Check if device is ready */
	if (hba->state < FC_LINK_DOWN) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_diag_error_msg,
		    "BIU: HBA not ready.");

		return (FC_TRAN_BUSY);
	}

	/*
	 * Get a buffer which will be used for the mailbox command
	 */
	if ((mbq = (MAILBOXQ *) emlxs_mem_get(hba, MEM_MBOX)) == 0) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_diag_error_msg,
		    "BIU: Mailbox allocation failed.");

		rval = FC_NOMEM;
		goto done;
	}

	/*
	 * Setup and issue mailbox RUN BIU DIAG command Setup test buffers
	 */
	if (((mp = (MATCHMAP *) emlxs_mem_get(hba, MEM_BUF)) == 0) ||
	    ((mp1 = (MATCHMAP *) emlxs_mem_get(hba, MEM_BUF)) == 0)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_diag_error_msg,
		    "BIU: Buffer allocation failed.");

		rval = FC_NOMEM;
		goto done;
	}

	if (pattern) {
		/* Fill the transmit buffer with the pattern */
		lptr = (uint32_t *)mp->virt;

		for (i = 0; i < MEM_ELSBUF_SIZE; i += 4) {
			*lptr++ = pattern;
		}
	} else {
		/* Copy the default pattern into the trasmit buffer */
		bcopy((caddr_t)&emlxs_diag_pattern[0], (caddr_t)mp->virt,
		    MEM_ELSBUF_SIZE);
	}
	EMLXS_MPDATA_SYNC(mp->dma_handle, 0, MEM_ELSBUF_SIZE,
	    DDI_DMA_SYNC_FORDEV);

	bzero(mp1->virt, MEM_ELSBUF_SIZE);
	EMLXS_MPDATA_SYNC(mp1->dma_handle, 0, MEM_ELSBUF_SIZE,
	    DDI_DMA_SYNC_FORDEV);

	/* Create the biu diag request */
	(void) emlxs_mb_run_biu_diag(hba, mbq, mp->phys, mp1->phys);

	rval = EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, MBX_WAIT, 60);

	if (rval == MBX_TIMEOUT) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_biu_failed_msg,
		    "BUI diagnostic timed out.");

		rval = EMLXS_TEST_FAILED;
		goto done;
	}

	EMLXS_MPDATA_SYNC(mp1->dma_handle, 0, MEM_ELSBUF_SIZE,
	    DDI_DMA_SYNC_FORKERNEL);

	outptr = mp->virt;
	inptr = mp1->virt;

	for (i = 0; i < MEM_ELSBUF_SIZE; i++, outptr++, inptr++) {
		if (*outptr != *inptr) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_biu_failed_msg,
			    "Data miscompare. Offset %d value %02x should "
			    "be %02x.", i, *inptr, *outptr);

			rval = EMLXS_TEST_FAILED;
			goto done;
		}
	}

	/* Wait half second before returning */
	delay(drv_usectohz(500000));
	rval = FC_SUCCESS;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_biu_complete_msg, "Status Good.");

done:

	if (mp) {
#ifdef FMA_SUPPORT
		if (emlxs_fm_check_dma_handle(hba, mp->dma_handle)
		    != DDI_FM_OK) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_invalid_dma_handle_msg,
			    "diag_biu_run: hdl=%p",
			    mp->dma_handle);
			rval = EMLXS_TEST_FAILED;
		}
#endif  /* FMA_SUPPORT */
		emlxs_mem_put(hba, MEM_BUF, (void *)mp);
	}
	if (mp1) {
#ifdef FMA_SUPPORT
		if (emlxs_fm_check_dma_handle(hba, mp1->dma_handle)
		    != DDI_FM_OK) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_invalid_dma_handle_msg,
			    "diag_biu_run: hdl=%p",
			    mp1->dma_handle);
			rval = EMLXS_TEST_FAILED;
		}
#endif  /* FMA_SUPPORT */
		emlxs_mem_put(hba, MEM_BUF, (void *)mp1);
	}
	if (mbq) {
		emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);
	}

	return (rval);

} /* emlxs_diag_biu_run() */


extern uint32_t
emlxs_diag_post_run(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	uint32_t rval = FC_SUCCESS;

	if (hba->flag & (FC_OFFLINE_MODE | FC_OFFLINING_MODE)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_diag_error_msg,
		    "POST: HBA shutdown.");

		return (FC_TRAN_BUSY);
	}

	/* Take board offline */
	if ((rval = emlxs_offline(hba, 0))) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_post_failed_msg,
		    "Unable to take adapter offline.");

		rval = FC_RESETFAIL;
	}

	/* Restart the adapter */
	rval = EMLXS_SLI_HBA_RESET(hba, 1, 1, 0);

	switch (rval) {
	case 0:

		(void) emlxs_online(hba);

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_post_complete_msg,
		    "Status good.");

		rval = FC_SUCCESS;

		break;

	case 1:	/* failed */

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_post_failed_msg,
		    "HBA reset failed.");

		rval = FC_RESETFAIL;

		break;


	case 2:	/* failed */

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_diag_error_msg,
		    "HBA busy. Quiece and retry.");

		rval = FC_STATEC_BUSY;

		break;

	}

	return (rval);

} /* emlxs_diag_post_run() */
