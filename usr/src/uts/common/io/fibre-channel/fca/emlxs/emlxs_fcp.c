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
 * Copyright 2008 Emulex.  All rights reserved.
 * Use is subject to License terms.
 */


#include "emlxs.h"

/* Required for EMLXS_CONTEXT in EMLXS_MSGF calls */
EMLXS_MSG_DEF(EMLXS_FCP_C);

#define	EMLXS_GET_VADDR(hba, rp, icmd) emlxs_mem_get_vaddr(hba, rp, \
	getPaddr(icmd->un.cont64[i].addrHigh, icmd->un.cont64[i].addrLow));

static void emlxs_sbp_abort_add(emlxs_port_t *port, emlxs_buf_t *sbp, Q *abort,
    uint8_t *flag, emlxs_buf_t *fpkt);
static uint32_t emlxs_iotag_flush(emlxs_hba_t *hba);

/*
 * This routine copies data from src then potentially swaps the destination to
 * big endian. Assumes cnt is a multiple of * sizeof(uint32_t).
 */
extern void
emlxs_pcimem_bcopy(uint32_t *src, uint32_t *dest, uint32_t cnt)
{
	uint32_t ldata;
	int32_t i;

	for (i = 0; i < (int)cnt; i += sizeof (uint32_t)) {
		ldata = *src++;
		ldata = PCIMEM_LONG(ldata);
		*dest++ = ldata;
	}
} /* emlxs_pcimem_bcopy */


/*
 * This routine copies data from src then swaps the destination to big endian.
 * Assumes cnt is a multiple of sizeof(uint32_t).
 */
extern void
emlxs_swap_bcopy(uint32_t *src, uint32_t *dest, uint32_t cnt)
{
	uint32_t ldata;
	int32_t i;

	for (i = 0; i < (int)cnt; i += sizeof (uint32_t)) {
		ldata = *src++;
		ldata = SWAP_DATA32(ldata);
		*dest++ = ldata;
	}
} /* End fc_swap_bcopy */


#define	SCSI3_PERSISTENT_RESERVE_IN	0x5e
#define	SCSI_INQUIRY	0x12
#define	SCSI_RX_DIAG    0x1C


/*
 *  emlxs_handle_fcp_event
 *
 *  Description: Process an FCP Rsp Ring completion
 *
 */
/* ARGSUSED */
extern void
emlxs_handle_fcp_event(emlxs_hba_t *hba, RING *rp, IOCBQ *iocbq)
{
	emlxs_port_t *port = &PPORT;
	IOCB *cmd;
	emlxs_buf_t *sbp;
	fc_packet_t *pkt = NULL;
	uint32_t iostat;
	uint8_t localstat;
	fcp_rsp_t *rsp;
	uint32_t rsp_data_resid;
	uint32_t check_underrun;
	uint8_t asc;
	uint8_t ascq;
	uint8_t scsi_status;
	uint8_t sense;
	uint32_t did;
	uint32_t fix_it;
	uint8_t *scsi_cmd;
	uint8_t scsi_opcode;
	uint16_t scsi_dl;
	uint32_t data_rx;

	cmd = &iocbq->iocb;

	/* Initialize the status */
	iostat = cmd->ulpStatus;
	localstat = 0;
	scsi_status = 0;
	asc = 0;
	ascq = 0;
	sense = 0;
	check_underrun = 0;
	fix_it = 0;

	HBASTATS.FcpEvent++;

	sbp = (emlxs_buf_t *)iocbq->sbp;

	if (!sbp) {
		/* completion with missing xmit command */
		HBASTATS.FcpStray++;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_stray_fcp_completion_msg,
		    "cmd=%x iotag=%x",
		    cmd->ulpCommand, cmd->ulpIoTag);

		return;
	}
	HBASTATS.FcpCompleted++;

	pkt = PRIV2PKT(sbp);

	did = SWAP_DATA24_LO(pkt->pkt_cmd_fhdr.d_id);
	scsi_cmd = (uint8_t *)pkt->pkt_cmd;
	scsi_opcode = scsi_cmd[12];
	data_rx = 0;

	/* Sync data in data buffer only on FC_PKT_FCP_READ */
	if (pkt->pkt_datalen && (pkt->pkt_tran_type == FC_PKT_FCP_READ)) {
		emlxs_mpdata_sync(pkt->pkt_data_dma, 0, pkt->pkt_datalen,
		    DDI_DMA_SYNC_FORKERNEL);

#ifdef TEST_SUPPORT
		if (hba->underrun_counter && (iostat == IOSTAT_SUCCESS) &&
		    (pkt->pkt_datalen >= 512)) {
			hba->underrun_counter--;
			iostat = IOSTAT_FCP_RSP_ERROR;

			/* Report 512 bytes missing by adapter */
			cmd->un.fcpi.fcpi_parm = pkt->pkt_datalen - 512;

			/* Corrupt 512 bytes of Data buffer */
			bzero((uint8_t *)pkt->pkt_data, 512);

			/* Set FCP response to STATUS_GOOD */
			bzero((uint8_t *)pkt->pkt_resp, pkt->pkt_rsplen);
		}
#endif	/* TEST_SUPPORT */
	}
	/* Process the pkt */
	mutex_enter(&sbp->mtx);

	/* Check for immediate return */
	if ((iostat == IOSTAT_SUCCESS) &&
	    (pkt->pkt_comp) &&
	    !(sbp->pkt_flags & (PACKET_RETURNED | PACKET_COMPLETED |
	    PACKET_IN_COMPLETION | PACKET_IN_TXQ | PACKET_IN_CHIPQ |
	    PACKET_IN_DONEQ | PACKET_IN_TIMEOUT | PACKET_IN_FLUSH |
	    PACKET_IN_ABORT | PACKET_POLLED))) {
		HBASTATS.FcpGood++;

		sbp->pkt_flags |= (PACKET_STATE_VALID | PACKET_IN_COMPLETION |
		    PACKET_COMPLETED | PACKET_RETURNED);
		mutex_exit(&sbp->mtx);

#if (EMLXS_MODREVX == EMLXS_MODREV2X)
		emlxs_unswap_pkt(sbp);
#endif	/* EMLXS_MODREV2X */

		(*pkt->pkt_comp) (pkt);

		return;
	}
	/*
	 * A response is only placed in the resp buffer if
	 * IOSTAT_FCP_RSP_ERROR is reported
	 */

	/* Check if a response buffer was provided */
	if ((iostat == IOSTAT_FCP_RSP_ERROR) && pkt->pkt_rsplen) {
		emlxs_mpdata_sync(pkt->pkt_resp_dma, 0, pkt->pkt_rsplen,
		    DDI_DMA_SYNC_FORKERNEL);

		/* Get the response buffer pointer */
		rsp = (fcp_rsp_t *)pkt->pkt_resp;

		/* Set the valid response flag */
		sbp->pkt_flags |= PACKET_FCP_RSP_VALID;

		scsi_status = rsp->fcp_u.fcp_status.scsi_status;

		/*
		 * Convert a task abort to a check condition with no data
		 * transferred
		 */
		/*
		 * We saw a data corruption when Solaris received a Task
		 * Abort from a tape
		 */
		if (scsi_status == SCSI_STAT_TASK_ABORT) {
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_fcp_completion_error_msg,
			    "Task Abort. Fixed. "
			    "did=0x%06x sbp=%p cmd=%02x dl=%d",
			    did, sbp, scsi_opcode, pkt->pkt_datalen);

			rsp->fcp_u.fcp_status.scsi_status =
			    SCSI_STAT_CHECK_COND;
			rsp->fcp_u.fcp_status.rsp_len_set = 0;
			rsp->fcp_u.fcp_status.sense_len_set = 0;
			rsp->fcp_u.fcp_status.resid_over = 0;

			if (pkt->pkt_datalen) {
				rsp->fcp_u.fcp_status.resid_under = 1;
				rsp->fcp_resid = SWAP_DATA32(pkt->pkt_datalen);
			} else {
				rsp->fcp_u.fcp_status.resid_under = 0;
				rsp->fcp_resid = 0;
			}

			scsi_status = SCSI_STAT_CHECK_COND;
		}
		/*
		 * We only need to check underrun if data could have been
		 * sent
		 */

		/* Always check underrun if status is good */
		if (scsi_status == SCSI_STAT_GOOD) {
			check_underrun = 1;
		}
		/* Check the sense codes if this is a check condition */
		else if (scsi_status == SCSI_STAT_CHECK_COND) {
			check_underrun = 1;

			/* Check if sense data was provided */
			if (SWAP_DATA32(rsp->fcp_sense_len) >= 14) {
				sense = *((uint8_t *)rsp + 32 + 2);
				asc = *((uint8_t *)rsp + 32 + 12);
				ascq = *((uint8_t *)rsp + 32 + 13);
			}
		}
		/* Status is not good and this is not a check condition */
		/* No data should have been sent */
		else {
			check_underrun = 0;
		}

		/* Get the residual underrun count reported by the SCSI reply */
		rsp_data_resid = (pkt->pkt_datalen &&
		    rsp->fcp_u.fcp_status.resid_under)
		    ? SWAP_DATA32(rsp->fcp_resid) : 0;

		/* Set the pkt resp_resid field */
		pkt->pkt_resp_resid = 0;

		/* Set the pkt data_resid field */
		if (pkt->pkt_datalen &&
		    (pkt->pkt_tran_type == FC_PKT_FCP_READ)) {
			/*
			 * Get the residual underrun count reported by our
			 * adapter
			 */
			pkt->pkt_data_resid = cmd->un.fcpi.fcpi_parm;

			/* Get the actual amount of data transferred */
			data_rx = pkt->pkt_datalen - pkt->pkt_data_resid;

			/*
			 * If the residual being reported by the adapter is
			 * greater than the residual being reported in the
			 * reply, then we have a true underrun.
			 */
			if (check_underrun &&
			    (pkt->pkt_data_resid > rsp_data_resid)) {
				switch (scsi_opcode) {
				case SCSI_INQUIRY:
					scsi_dl = scsi_cmd[16];
					break;

				case SCSI_RX_DIAG:
					scsi_dl = (scsi_cmd[15] * 0x100) +
					    scsi_cmd[16];
					break;

				default:
					scsi_dl = pkt->pkt_datalen;
				}

#ifdef FCP_UNDERRUN_PATCH1
				/*
				 * If status is not good and no data was
				 * actually transferred, then we must fix the
				 * issue
				 */
				if ((scsi_status != SCSI_STAT_GOOD) &&
				    (data_rx == 0)) {
					fix_it = 1;

					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_fcp_completion_error_msg,
					    "Underrun(1). Fixed. did=0x%06x "
					    "sbp=%p cmd=%02x dl=%d,%d rx=%d "
					    "rsp=%d",
					    did, sbp, scsi_opcode,
					    pkt->pkt_datalen, scsi_dl,
					    (pkt->pkt_datalen -
					    cmd->un.fcpi.fcpi_parm),
					    rsp_data_resid);

				}
#endif	/* FCP_UNDERRUN_PATCH1 */


#ifdef FCP_UNDERRUN_PATCH2
				if ((scsi_status == SCSI_STAT_GOOD)) {
					emlxs_msg_t *msg;

					msg = &emlxs_fcp_completion_error_msg;
					/*
					 * If status is good and this is an
					 * inquiry request and the amount of
					 * data
					 */
					/*
					 * requested <= data received, then
					 * we must fix the issue.
					 */

					if ((scsi_opcode == SCSI_INQUIRY) &&
					    (pkt->pkt_datalen >= data_rx) &&
					    (scsi_dl <= data_rx)) {
						fix_it = 1;

						EMLXS_MSGF(EMLXS_CONTEXT,
						    msg,
						    "Underrun(2). Fixed. "
						    "did=0x%06x sbp=%p "
						    "cmd=%02x dl=%d,%d "
						    "rx=%d rsp=%d",
						    did, sbp, scsi_opcode,
						    pkt->pkt_datalen, scsi_dl,
						    data_rx, rsp_data_resid);

					}
					/*
					 * If status is good and this is an
					 * inquiry request and the amount of
					 * data
					 */
					/*
					 * requested >= 128 bytes, but only
					 * 128 bytes were received,
					 */
					/* then we must fix the issue. */
					else if ((scsi_opcode == SCSI_INQUIRY)&&
					    (pkt->pkt_datalen >= 128) &&
					    (scsi_dl >= 128) &&
					    (data_rx == 128)) {
						fix_it = 1;

						EMLXS_MSGF(EMLXS_CONTEXT,
						    msg,
						    "Underrun(3). Fixed. "
						    "did=0x%06x sbp=%p "
						    "cmd=%02x dl=%d,%d rx=%d "
						    "rsp=%d",
						    did, sbp, scsi_opcode,
						    pkt->pkt_datalen, scsi_dl,
						    data_rx, rsp_data_resid);

					}
				}
#endif	/* FCP_UNDERRUN_PATCH2 */

				/*
				 * Check if SCSI response payload should be
				 * fixed or
				 */
				/* if a DATA_UNDERRUN should be reported */
				if (fix_it) {
					/*
					 * Fix the SCSI response payload
					 * itself
					 */
					rsp->fcp_u.fcp_status.resid_under = 1;
					rsp->fcp_resid =
					    SWAP_DATA32(pkt->pkt_data_resid);
				} else {
					/*
					 * Change the status from
					 * IOSTAT_FCP_RSP_ERROR to
					 * IOSTAT_DATA_UNDERRUN
					 */
					iostat = IOSTAT_DATA_UNDERRUN;
					pkt->pkt_data_resid = pkt->pkt_datalen;
				}
			}
			/*
			 * If the residual being reported by the adapter is
			 * less than the residual being reported in the
			 * reply, then we have a true overrun. Since we don't
			 * know where the extra data came from or went to
			 * then we cannot trust anything we received
			 */
			else if (rsp_data_resid > pkt->pkt_data_resid) {
				/*
				 * Change the status from
				 * IOSTAT_FCP_RSP_ERROR to
				 * IOSTAT_DATA_OVERRUN
				 */
				iostat = IOSTAT_DATA_OVERRUN;
				pkt->pkt_data_resid = pkt->pkt_datalen;
			}
		} else {	/* pkt->pkt_datalen==0 or FC_PKT_FCP_WRITE */
			/* Report whatever the target reported */
			pkt->pkt_data_resid = rsp_data_resid;
		}
	}
	/*
	 * If pkt is tagged for timeout then set the return codes
	 * appropriately
	 */
	if (sbp->pkt_flags & PACKET_IN_TIMEOUT) {
		iostat = IOSTAT_LOCAL_REJECT;
		localstat = IOERR_ABORT_TIMEOUT;
		goto done;
	}
	/* If pkt is tagged for abort then set the return codes appropriately */
	if (sbp->pkt_flags & (PACKET_IN_FLUSH | PACKET_IN_ABORT)) {
		iostat = IOSTAT_LOCAL_REJECT;
		localstat = IOERR_ABORT_REQUESTED;
		goto done;
	}
	/* Print completion message */
	switch (iostat) {
	case IOSTAT_SUCCESS:
		/* Build SCSI GOOD status */
		if (pkt->pkt_rsplen) {
			bzero((uint8_t *)pkt->pkt_resp, pkt->pkt_rsplen);
		}
		break;

	case IOSTAT_FCP_RSP_ERROR:
		break;

	case IOSTAT_REMOTE_STOP:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcp_completion_error_msg,
		    "Remote Stop. did=0x%06x sbp=%p cmd=%02x",
		    did, sbp, scsi_opcode);
		break;

	case IOSTAT_LOCAL_REJECT:
		localstat = cmd->un.grsp.perr.statLocalError;

		switch (localstat) {
		case IOERR_SEQUENCE_TIMEOUT:
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_fcp_completion_error_msg,
			    "Local reject. %s did=0x%06x sbp=%p "
			    "cmd=%02x tmo=%d ",
			    emlxs_error_xlate(localstat), did, sbp,
			    scsi_opcode, pkt->pkt_timeout);
			break;

		default:
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_fcp_completion_error_msg,
			    "Local reject. %s did=0x%06x sbp=%p cmd=%02x",
			    emlxs_error_xlate(localstat), did,
			    sbp, scsi_opcode);
		}

		break;

	case IOSTAT_NPORT_RJT:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcp_completion_error_msg,
		    "Nport reject. did=0x%06x sbp=%p cmd=%02x",
		    did, sbp, scsi_opcode);
		break;

	case IOSTAT_FABRIC_RJT:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcp_completion_error_msg,
		    "Fabric reject. did=0x%06x sbp=%p cmd=%02x",
		    did, sbp, scsi_opcode);
		break;

	case IOSTAT_NPORT_BSY:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcp_completion_error_msg,
		    "Nport busy. did=0x%06x sbp=%p cmd=%02x",
		    did, sbp, scsi_opcode);
		break;

	case IOSTAT_FABRIC_BSY:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcp_completion_error_msg,
		    "Fabric busy. did=0x%06x sbp=%p cmd=%02x",
		    did, sbp, scsi_opcode);
		break;

	case IOSTAT_INTERMED_RSP:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcp_completion_error_msg,
		    "Intermediate response. did=0x%06x sbp=%p cmd=%02x",
		    did, sbp, scsi_opcode);
		break;

	case IOSTAT_LS_RJT:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcp_completion_error_msg,
		    "LS Reject. did=0x%06x sbp=%p cmd=%02x",
		    did, sbp, scsi_opcode);
		break;

	case IOSTAT_DATA_UNDERRUN:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcp_completion_error_msg,
		    "Underrun. did=0x%06x sbp=%p cmd=%02x dl=%d,%d rx=%d "
		    "rsp=%d (%02x,%02x,%02x,%02x)",
		    did, sbp, scsi_opcode, pkt->pkt_datalen, scsi_dl,
		    data_rx, rsp_data_resid, scsi_status, sense, asc, ascq);
		break;

	case IOSTAT_DATA_OVERRUN:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcp_completion_error_msg,
		    "Overrun. did=0x%06x sbp=%p cmd=%02x dl=%d,%d rx=%d "
		    "rsp=%d (%02x,%02x,%02x,%02x)",
		    did, sbp, scsi_opcode, pkt->pkt_datalen, scsi_dl,
		    data_rx, rsp_data_resid, scsi_status, sense, asc, ascq);
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcp_completion_error_msg,
		    "Unknown status=%x reason=%x did=0x%06x sbp=%p cmd=%02x",
		    iostat, cmd->un.grsp.perr.statLocalError, did,
		    sbp, scsi_opcode);
		break;
	}

done:

	if (iostat == IOSTAT_SUCCESS) {
		HBASTATS.FcpGood++;
	} else {
		HBASTATS.FcpError++;
	}

	mutex_exit(&sbp->mtx);

	emlxs_pkt_complete(sbp, iostat, localstat, 0);

	return;

} /* emlxs_handle_fcp_event() */



/*
 *  emlxs_post_buffer
 *
 *  This routine will post count buffers to the
 *  ring with the QUE_RING_BUF_CN command. This
 *  allows 2 buffers / command to be posted.
 *  Returns the number of buffers NOT posted.
 */
extern int
emlxs_post_buffer(emlxs_hba_t *hba, RING *rp, int16_t cnt)
{
	emlxs_port_t *port = &PPORT;
	IOCB *icmd;
	IOCBQ *iocbq;
	MATCHMAP *mp;
	uint16_t tag;
	uint32_t maxqbuf;
	int32_t i;
	int32_t j;
	uint32_t seg;
	uint32_t size;

	mp = 0;
	maxqbuf = 2;
	tag = (uint16_t)cnt;
	cnt += rp->fc_missbufcnt;

	if (rp->ringno == FC_ELS_RING) {
		seg = MEM_BUF;
		size = MEM_ELSBUF_SIZE;
	} else if (rp->ringno == FC_IP_RING) {
		seg = MEM_IPBUF;
		size = MEM_IPBUF_SIZE;
	} else if (rp->ringno == FC_CT_RING) {
		seg = MEM_CTBUF;
		size = MEM_CTBUF_SIZE;
	}
#ifdef SFCT_SUPPORT
	else if (rp->ringno == FC_FCT_RING) {
		seg = MEM_FCTBUF;
		size = MEM_FCTBUF_SIZE;
	}
#endif	/* SFCT_SUPPORT */
	else {
		return (0);
	}

	/*
	 * While there are buffers to post
	 */
	while (cnt) {
		if ((iocbq = (IOCBQ *)emlxs_mem_get(hba, MEM_IOCB)) == 0) {
			rp->fc_missbufcnt = cnt;
			return (cnt);
		}
		iocbq->ring = (void *)rp;
		iocbq->port = (void *)port;
		iocbq->flag |= (IOCB_PRIORITY | IOCB_SPECIAL);

		icmd = &iocbq->iocb;

		/*
		 * Max buffers can be posted per command
		 */
		for (i = 0; i < maxqbuf; i++) {
			if (cnt <= 0)
				break;

			/* fill in BDEs for command */
			if ((mp = (MATCHMAP *)emlxs_mem_get(hba, seg)) == 0) {
				uint32_t H;
				uint32_t L;

				icmd->ulpBdeCount = i;
				for (j = 0; j < i; j++) {
					H = icmd->un.cont64[j].addrHigh;
					L = icmd->un.cont64[j].addrLow;
					mp = emlxs_mem_get_vaddr(hba, rp,
					    getPaddr(H, L));
					if (mp) {
						(void) emlxs_mem_put(hba, seg,
						    (uint8_t *)mp);
					}
				}

				rp->fc_missbufcnt = cnt + i;

				(void) emlxs_mem_put(hba, MEM_IOCB,
				    (uint8_t *)iocbq);

				return (cnt + i);
			}
			/*
			 * map that page and save the address pair for lookup
			 * later
			 */
			emlxs_mem_map_vaddr(hba, rp, mp,
			    (uint32_t *)&icmd->un.cont64[i].addrHigh,
			    (uint32_t *)&icmd->un.cont64[i].addrLow);

			icmd->un.cont64[i].tus.f.bdeSize = size;
			icmd->ulpCommand = CMD_QUE_RING_BUF64_CN;

/*
 *			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
 *			    "UB Post: ring=%d addr=%08x%08x size=%d",
 *			    rp->ringno, icmd->un.cont64[i].addrHigh,
 *			    icmd->un.cont64[i].addrLow, size);
 */

			cnt--;
		}

		icmd->ulpIoTag = tag;
		icmd->ulpBdeCount = i;
		icmd->ulpLe = 1;
		icmd->ulpOwner = OWN_CHIP;
		iocbq->bp = (uint8_t *)mp;  /* used for delimiter between */
					    /* commands */

		emlxs_issue_iocb_cmd(hba, rp, iocbq);
	}

	rp->fc_missbufcnt = 0;

	return (0);

} /* emlxs_post_buffer() */


extern int
emlxs_port_offline(emlxs_port_t *port, uint32_t scope)
{
	emlxs_hba_t *hba = HBA;
	emlxs_config_t *cfg;
	NODELIST *nlp;
	fc_affected_id_t *aid;
	uint32_t mask;
	uint32_t aff_d_id;
	uint32_t linkdown;
	uint32_t vlinkdown;
	uint32_t action;
	int i;
	uint32_t unreg_vpi;
	uint32_t update;
	uint32_t adisc_support;

	/* Target mode only uses this routine for linkdowns */
	if (port->tgt_mode && (scope != 0xffffffff) && (scope != 0xfeffffff)) {
		return (0);
	}
	cfg = &CFG;
	aid = (fc_affected_id_t *)&scope;
	linkdown = 0;
	vlinkdown = 0;
	unreg_vpi = 0;
	update = 0;

	if (!(port->flag & EMLXS_PORT_BOUND)) {
		return (0);
	}
	switch (aid->aff_format) {
	case 0:	/* Port */
		mask = 0x00ffffff;
		break;

	case 1:	/* Area */
		mask = 0x00ffff00;
		break;

	case 2:	/* Domain */
		mask = 0x00ff0000;
		break;

	case 3:	/* Network */
		mask = 0x00000000;
		break;

#ifdef DHCHAP_SUPPORT
	case 0xfe:	/* Virtual link down */
		mask = 0x00000000;
		vlinkdown = 1;
		break;
#endif	/* DHCHAP_SUPPORT */

	case 0xff:	/* link is down */
		mask = 0x00000000;
		linkdown = 1;
		break;

	}

	aff_d_id = aid->aff_d_id & mask;


	/* If link is down then this is a hard shutdown and flush */
	/*
	 * If link not down then this is a soft shutdown and flush (e.g.
	 * RSCN)
	 */
	if (linkdown) {
		mutex_enter(&EMLXS_PORT_LOCK);

		port->flag &= EMLXS_PORT_LINKDOWN_MASK;
		port->prev_did = port->did;
		port->did = 0;

		if (port->ulp_statec != FC_STATE_OFFLINE) {
			port->ulp_statec = FC_STATE_OFFLINE;
			update = 1;
		}
		mutex_exit(&EMLXS_PORT_LOCK);

		/* Tell ULP about it */
		if (update) {
			if (port->flag & EMLXS_PORT_BOUND) {
				if (port->vpi == 0) {
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_link_down_msg,
					    NULL);
				}
#ifdef SFCT_SUPPORT
				if (port->tgt_mode) {
					emlxs_fct_link_down(port);

				} else if (port->ini_mode) {
					port->ulp_statec_cb(port->ulp_handle,
					    FC_STATE_OFFLINE);
				}
#else
				port->ulp_statec_cb(port->ulp_handle,
				    FC_STATE_OFFLINE);
#endif	/* SFCT_SUPPORT */
			} else {
				if (port->vpi == 0) {
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_link_down_msg,
					    "*");
				}
			}


		}
		unreg_vpi = 1;

#ifdef DHCHAP_SUPPORT
		/* Stop authentication with all nodes */
		emlxs_dhc_auth_stop(port, NULL);
#endif	/* DHCHAP_SUPPORT */

		/* Flush the base node */
		(void) emlxs_tx_node_flush(port, &port->node_base, 0, 0, 0);
		(void) emlxs_chipq_node_flush(port, 0, &port->node_base, 0);

		/* Flush any pending ub buffers */
		emlxs_ub_flush(port);
	}
#ifdef DHCHAP_SUPPORT
	/* virtual link down */
	else if (vlinkdown) {
		mutex_enter(&EMLXS_PORT_LOCK);

		if (port->ulp_statec != FC_STATE_OFFLINE) {
			port->ulp_statec = FC_STATE_OFFLINE;
			update = 1;
		}
		mutex_exit(&EMLXS_PORT_LOCK);

		/* Tell ULP about it */
		if (update) {
			if (port->flag & EMLXS_PORT_BOUND) {
				if (port->vpi == 0) {
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_link_down_msg,
					    "Switch authentication failed.");
				}
#ifdef SFCT_SUPPORT
				if (port->tgt_mode) {
					emlxs_fct_link_down(port);
				} else if (port->ini_mode) {
					port->ulp_statec_cb(port->ulp_handle,
					    FC_STATE_OFFLINE);
				}
#else
				port->ulp_statec_cb(port->ulp_handle,
				    FC_STATE_OFFLINE);
#endif	/* SFCT_SUPPORT */
			} else {
				if (port->vpi == 0) {
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_link_down_msg,
					    "Switch authentication failed. *");
				}
			}


		}
		/* Flush the base node */
		(void) emlxs_tx_node_flush(port, &port->node_base, 0, 0, 0);
		(void) emlxs_chipq_node_flush(port, 0, &port->node_base, 0);
	}
#endif	/* DHCHAP_SUPPORT */

	if (port->tgt_mode) {
		goto done;
	}
	/* Set the node tags */
	/* We will process all nodes with this tag */
	rw_enter(&port->node_rwlock, RW_READER);
	for (i = 0; i < EMLXS_NUM_HASH_QUES; i++) {
		nlp = port->node_table[i];
		while (nlp != NULL) {
			nlp->nlp_tag = 1;
			nlp = nlp->nlp_list_next;
		}
	}
	rw_exit(&port->node_rwlock);

	if (hba->flag & FC_ONLINE_MODE) {
		adisc_support = cfg[CFG_ADISC_SUPPORT].current;
	} else {
		adisc_support = 0;
	}

	/* Check ADISC support level */
	switch (adisc_support) {
	case 0:	/* No support - Flush all IO to all matching nodes */

		for (; ; ) {
			/*
			 * We need to hold the locks this way because
			 * emlxs_mb_unreg_did and the flush routines enter
			 * the same locks. Also, when we release the lock the
			 * list can change out from under us.
			 */

			/* Find first node */
			rw_enter(&port->node_rwlock, RW_READER);
			action = 0;
			for (i = 0; i < EMLXS_NUM_HASH_QUES; i++) {
				nlp = port->node_table[i];
				while (nlp != NULL) {
					if (!nlp->nlp_tag) {
						nlp = nlp->nlp_list_next;
						continue;
					}
					nlp->nlp_tag = 0;

					/*
					 * Check for any device that matches
					 * our mask
					 */
					if ((nlp->nlp_DID & mask) == aff_d_id) {
						if (linkdown) {
							action = 1;
							break;
						} else {  /* Must be an RCSN */
							action = 2;
							break;
						}
					}
					nlp = nlp->nlp_list_next;
				}

				if (action) {
					break;
				}
			}
			rw_exit(&port->node_rwlock);


			/* Check if nothing was found */
			if (action == 0) {
				break;
			} else if (action == 1) {
				(void) emlxs_mb_unreg_did(port, nlp->nlp_DID,
				    NULL, NULL, NULL);
			} else if (action == 2) {
#ifdef DHCHAP_SUPPORT
				emlxs_dhc_auth_stop(port, nlp);
#endif	/* DHCHAP_SUPPORT */

				/* Close the node for any further normal IO */
				/* A PLOGI with reopen the node */
				emlxs_node_close(port, nlp, FC_FCP_RING, 60);
				emlxs_node_close(port, nlp, FC_IP_RING, 60);

				/* Flush tx queue */
				(void) emlxs_tx_node_flush(port, nlp, 0, 0, 0);

				/* Flush chip queue */
				(void) emlxs_chipq_node_flush(port, 0, nlp, 0);
			}
		}

		break;

	case 1:	/* Partial support - Flush IO for non-FCP2 matching * nodes */

		for (;;) {

			/*
			 * We need to hold the locks this way because
			 * emlxs_mb_unreg_did and the flush routines enter
			 * the same locks. Also, when we release the lock the
			 * list can change out from under us.
			 */
			rw_enter(&port->node_rwlock, RW_READER);
			action = 0;
			for (i = 0; i < EMLXS_NUM_HASH_QUES; i++) {
				nlp = port->node_table[i];
				while (nlp != NULL) {
					if (!nlp->nlp_tag) {
						nlp = nlp->nlp_list_next;
						continue;
					}
					nlp->nlp_tag = 0;

					/*
					 * Check for special FCP2 target
					 * device that matches our mask
					 */
					if ((nlp->nlp_fcp_info &
					    NLP_FCP_TGT_DEVICE) &&
					    (nlp->nlp_fcp_info &
					    NLP_FCP_2_DEVICE) &&
					    (nlp->nlp_DID & mask) == aff_d_id) {
						action = 3;
						break;
					}
					/*
					 * Check for any other device that
					 * matches our mask
					 */
					else if ((nlp->nlp_DID & mask) ==
					    aff_d_id) {
						if (linkdown) {
							action = 1;
							break;
						} else {   /* Must be an RSCN */
							action = 2;
							break;
						}
					}
					nlp = nlp->nlp_list_next;
				}

				if (action) {
					break;
				}
			}
			rw_exit(&port->node_rwlock);

			/* Check if nothing was found */
			if (action == 0) {
				break;
			} else if (action == 1) {
				(void) emlxs_mb_unreg_did(port, nlp->nlp_DID,
				    NULL, NULL, NULL);
			} else if (action == 2) {
#ifdef DHCHAP_SUPPORT
				emlxs_dhc_auth_stop(port, nlp);
#endif	/* DHCHAP_SUPPORT */

				/* Close the node for any further normal IO */
				/* A PLOGI with reopen the node */
				emlxs_node_close(port, nlp, FC_FCP_RING, 60);
				emlxs_node_close(port, nlp, FC_IP_RING, 60);

				/* Flush tx queue */
				(void) emlxs_tx_node_flush(port, nlp, 0, 0, 0);

				/* Flush chip queue */
				(void) emlxs_chipq_node_flush(port, 0, nlp, 0);
			} else if (action == 3) {	/* FCP2 devices */
				unreg_vpi = 0;

#ifdef DHCHAP_SUPPORT
				emlxs_dhc_auth_stop(port, nlp);
#endif	/* DHCHAP_SUPPORT */

				/* Close the node for any further normal IO */
				/* An ADISC or a PLOGI with reopen the node */
				emlxs_node_close(port, nlp, FC_FCP_RING,
				    ((linkdown) ? 0 : 60));
				emlxs_node_close(port, nlp, FC_IP_RING,
				    ((linkdown) ? 0 : 60));

				/* Flush tx queues except for FCP ring */
				(void) emlxs_tx_node_flush(port, nlp,
				    &hba->ring[FC_CT_RING], 0, 0);
				(void) emlxs_tx_node_flush(port, nlp,
				    &hba->ring[FC_ELS_RING], 0, 0);
				(void) emlxs_tx_node_flush(port, nlp,
				    &hba->ring[FC_IP_RING], 0, 0);

				/* Clear IP XRI */
				nlp->nlp_Xri = 0;

				/* Flush chip queues except for FCP ring */
				(void) emlxs_chipq_node_flush(port,
				    &hba->ring[FC_CT_RING], nlp, 0);
				(void) emlxs_chipq_node_flush(port,
				    &hba->ring[FC_ELS_RING], nlp, 0);
				(void) emlxs_chipq_node_flush(port,
				    &hba->ring[FC_IP_RING], nlp, 0);
			}
		}
		break;

	case 2:	/* Full support - Hold FCP IO to FCP target matching nodes */

		if (!linkdown && !vlinkdown) {
			break;
		}
		for (;;) {
			/*
			 * We need to hold the locks this way because
			 * emlxs_mb_unreg_did and the flush routines enter
			 * the same locks. Also, when we release the lock the
			 * list can change out from under us.
			 */
			rw_enter(&port->node_rwlock, RW_READER);
			action = 0;
			for (i = 0; i < EMLXS_NUM_HASH_QUES; i++) {
				nlp = port->node_table[i];
				while (nlp != NULL) {
					if (!nlp->nlp_tag) {
						nlp = nlp->nlp_list_next;
						continue;
					}
					nlp->nlp_tag = 0;

					/*
					 * Check for FCP target device that
					 * matches our mask
					 */
					if ((nlp->nlp_fcp_info &
					    NLP_FCP_TGT_DEVICE) &&
					    (nlp->nlp_DID & mask) == aff_d_id) {
						action = 3;
						break;
					}
					/*
					 * Check for any other device that
					 * matches our mask
					 */
					else if ((nlp->nlp_DID & mask) ==
					    aff_d_id) {
						if (linkdown) {
							action = 1;
							break;
						} else { /* Must be an RSCN */
							action = 2;
							break;
						}
					}
					nlp = nlp->nlp_list_next;
				}
				if (action) {
					break;
				}
			}
			rw_exit(&port->node_rwlock);

			/* Check if nothing was found */
			if (action == 0) {
				break;
			} else if (action == 1) {
				(void) emlxs_mb_unreg_did(port, nlp->nlp_DID,
				    NULL, NULL, NULL);
			} else if (action == 2) {
				/* Close the node for any further normal IO */
				/* A PLOGI with reopen the node */
				emlxs_node_close(port, nlp, FC_FCP_RING, 60);
				emlxs_node_close(port, nlp, FC_IP_RING, 60);

				/* Flush tx queue */
				(void) emlxs_tx_node_flush(port, nlp, 0, 0, 0);

				/* Flush chip queue */
				(void) emlxs_chipq_node_flush(port, 0, nlp, 0);

			} else if (action == 3) {	/* FCP2 devices */
				unreg_vpi = 0;

				/* Close the node for any further normal IO */
				/* An ADISC or a PLOGI with reopen the node */
				emlxs_node_close(port, nlp, FC_FCP_RING,
				    ((linkdown) ? 0 : 60));
				emlxs_node_close(port, nlp, FC_IP_RING,
				    ((linkdown) ? 0 : 60));

				/* Flush tx queues except for FCP ring */
				(void) emlxs_tx_node_flush(port, nlp,
				    &hba->ring[FC_CT_RING], 0, 0);
				(void) emlxs_tx_node_flush(port, nlp,
				    &hba->ring[FC_ELS_RING], 0, 0);
				(void) emlxs_tx_node_flush(port, nlp,
				    &hba->ring[FC_IP_RING], 0, 0);

				/* Clear IP XRI */
				nlp->nlp_Xri = 0;

				/* Flush chip queues except for FCP ring */
				(void) emlxs_chipq_node_flush(port,
				    &hba->ring[FC_CT_RING], nlp, 0);
				(void) emlxs_chipq_node_flush(port,
				    &hba->ring[FC_ELS_RING], nlp, 0);
				(void) emlxs_chipq_node_flush(port,
				    &hba->ring[FC_IP_RING], nlp, 0);
			}
		}

		break;


	}	/* switch() */

done:

	if (unreg_vpi) {
		(void) emlxs_mb_unreg_vpi(port);
	}
	return (0);

} /* emlxs_port_offline() */



extern void
emlxs_port_online(emlxs_port_t *vport)
{
	emlxs_hba_t *hba = vport->hba;
	emlxs_port_t *port = &PPORT;
	uint32_t state;
	uint32_t update;
	uint32_t npiv_linkup;
	char topology[32];
	char linkspeed[32];
	char mode[32];

	/*
	 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_link_up_msg, "linkup_callback.
	 * vpi=%d fc_flag=%x", vport->vpi, hba->flag);
	 */

	if ((vport->vpi > 0) &&
	    (!(hba->flag & FC_NPIV_ENABLED) ||
	    !(hba->flag & FC_NPIV_SUPPORTED))) {
		return;
	}
	if (!(vport->flag & EMLXS_PORT_BOUND) ||
	    !(vport->flag & EMLXS_PORT_ENABLE)) {
		return;
	}
	mutex_enter(&EMLXS_PORT_LOCK);

	/* Check for mode */
	if (port->tgt_mode) {
		(void) strcpy(mode, ", target");
	} else if (port->ini_mode) {
		(void) strcpy(mode, ", initiator");
	} else {
		(void) strcpy(mode, "");
	}

	/* Check for loop topology */
	if (hba->topology == TOPOLOGY_LOOP) {
		state = FC_STATE_LOOP;
		(void) strcpy(topology, ", loop");
	} else {
		state = FC_STATE_ONLINE;
		(void) strcpy(topology, ", fabric");
	}

	/* Set the link speed */
	switch (hba->linkspeed) {
	case 0:
		(void) strcpy(linkspeed, "Gb");
		state |= FC_STATE_1GBIT_SPEED;
		break;

	case LA_1GHZ_LINK:
		(void) strcpy(linkspeed, "1Gb");
		state |= FC_STATE_1GBIT_SPEED;
		break;
	case LA_2GHZ_LINK:
		(void) strcpy(linkspeed, "2Gb");
		state |= FC_STATE_2GBIT_SPEED;
		break;
	case LA_4GHZ_LINK:
		(void) strcpy(linkspeed, "4Gb");
		state |= FC_STATE_4GBIT_SPEED;
		break;
	case LA_8GHZ_LINK:
		(void) strcpy(linkspeed, "8Gb");
		state |= FC_STATE_8GBIT_SPEED;
		break;
	case LA_10GHZ_LINK:
		(void) strcpy(linkspeed, "10Gb");
		state |= FC_STATE_10GBIT_SPEED;
		break;
	default:
		(void) sprintf(linkspeed, "unknown(0x%x)", hba->linkspeed);
		break;
	}

	npiv_linkup = 0;
	update = 0;

	if ((hba->state >= FC_LINK_UP) &&
	    !(hba->flag & FC_LOOPBACK_MODE) &&
	    (vport->ulp_statec != state)) {
		update = 1;
		vport->ulp_statec = state;

		if ((vport->vpi > 0) && !(hba->flag & FC_NPIV_LINKUP)) {
			hba->flag |= FC_NPIV_LINKUP;
			npiv_linkup = 1;
		}
	}
	mutex_exit(&EMLXS_PORT_LOCK);

	/*
	 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_link_up_msg, "linkup_callback:
	 * update=%d vpi=%d flag=%d fc_flag=%x state=%x statec=%x", update,
	 * vport->vpi, npiv_linkup, hba->flag, hba->state,
	 * vport->ulp_statec);
	 */
	if (update) {
		if (vport->flag & EMLXS_PORT_BOUND) {
			if (vport->vpi == 0) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_link_up_msg,
				    "%s%s%s",
				    linkspeed, topology, mode);
			} else if (npiv_linkup) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_npiv_link_up_msg,
				    "%s%s%s",
				    linkspeed, topology, mode);
			}
#ifdef SFCT_SUPPORT
			if (vport->tgt_mode) {
				emlxs_fct_link_up(vport);
			} else if (vport->ini_mode) {
				vport->ulp_statec_cb(vport->ulp_handle, state);
			}
#else
			vport->ulp_statec_cb(vport->ulp_handle, state);
#endif	/* SFCT_SUPPORT */
		} else {
			if (vport->vpi == 0) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_link_up_msg,
				    "%s%s%s *",
				    linkspeed, topology, mode);
			} else if (npiv_linkup) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_npiv_link_up_msg,
				    "%s%s%s *",
				    linkspeed, topology, mode);
			}
		}

		/* Check for waiting threads */
		if (vport->vpi == 0) {
			mutex_enter(&EMLXS_LINKUP_LOCK);
			if (hba->linkup_wait_flag == TRUE) {
				hba->linkup_wait_flag = FALSE;
				cv_broadcast(&EMLXS_LINKUP_CV);
			}
			mutex_exit(&EMLXS_LINKUP_LOCK);
		}
		/* Flush any pending ub buffers */
		emlxs_ub_flush(vport);
	}
	return;

} /* emlxs_port_online() */


extern void
emlxs_linkdown(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	int i;

	mutex_enter(&EMLXS_PORT_LOCK);

	HBASTATS.LinkDown++;
	emlxs_ffstate_change_locked(hba, FC_LINK_DOWN);

	/* Filter hba flags */
	hba->flag &= FC_LINKDOWN_MASK;
	hba->discovery_timer = 0;
	hba->linkup_timer = 0;

	mutex_exit(&EMLXS_PORT_LOCK);

	for (i = 0; i < MAX_VPORTS; i++) {
		port = &VPORT(i);

		if (!(port->flag & EMLXS_PORT_BOUND)) {
			continue;
		}
		(void) emlxs_port_offline(port, 0xffffffff);

	}

	return;

} /* emlxs_linkdown() */


extern void
emlxs_linkup(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	emlxs_config_t *cfg = &CFG;

	mutex_enter(&EMLXS_PORT_LOCK);

	HBASTATS.LinkUp++;
	emlxs_ffstate_change_locked(hba, FC_LINK_UP);

#ifdef MENLO_TEST
	if ((hba->model_info.device_id == PCI_DEVICE_ID_LP21000_M) &&
	    (cfg[CFG_HORNET_FLOGI].current == 0)) {
		hba->flag |= FC_MENLO_MODE;
	}
#endif	/* MENLO_TEST */

#ifdef MENLO_SUPPORT
	if (hba->flag & FC_MENLO_MODE) {
		mutex_exit(&EMLXS_PORT_LOCK);

		/*
		 * Trigger linkup CV and don't start linkup & discovery
		 * timers
		 */
		mutex_enter(&EMLXS_LINKUP_LOCK);
		cv_broadcast(&EMLXS_LINKUP_CV);
		mutex_exit(&EMLXS_LINKUP_LOCK);

		return;
	}
#endif	/* MENLO_SUPPORT */

	/* Set the linkup & discovery timers */
	hba->linkup_timer = hba->timer_tics + cfg[CFG_LINKUP_TIMEOUT].current;
	hba->discovery_timer = hba->timer_tics +
	    cfg[CFG_LINKUP_TIMEOUT].current + cfg[CFG_DISC_TIMEOUT].current;

	mutex_exit(&EMLXS_PORT_LOCK);

	return;

} /* emlxs_linkup() */


/*
 *  emlxs_reset_link
 *
 *  Description:
 *  Called to reset the link with an init_link
 *
 *    Returns:
 *
 */
extern int
emlxs_reset_link(emlxs_hba_t *hba, uint32_t linkup)
{
	emlxs_port_t *port = &PPORT;
	emlxs_config_t *cfg;
	MAILBOX *mb;

	/*
	 * Get a buffer to use for the mailbox command
	 */
	if ((mb = (MAILBOX *)emlxs_mem_get(hba, MEM_MBOX | MEM_PRI)) == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_link_reset_failed_msg,
		    "Unable to allocate mailbox buffer.");

		return (1);
	}
	cfg = &CFG;

	if (linkup) {
		/*
		 * Setup and issue mailbox INITIALIZE LINK command
		 */

		emlxs_mb_init_link(hba, (MAILBOX *)mb,
		    cfg[CFG_TOPOLOGY].current, cfg[CFG_LINK_SPEED].current);

		mb->un.varInitLnk.lipsr_AL_PA = 0;

		/* Clear the loopback mode */
		mutex_enter(&EMLXS_PORT_LOCK);
		hba->flag &= ~FC_LOOPBACK_MODE;
		mutex_exit(&EMLXS_PORT_LOCK);

		if (emlxs_mb_issue_cmd(hba, (MAILBOX *)mb,
		    MBX_NOWAIT, 0) != MBX_BUSY) {
			(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);
		}
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_link_reset_msg, NULL);

	} else {	/* hold link down */
		emlxs_mb_down_link(hba, (MAILBOX *)mb);

		if (emlxs_mb_issue_cmd(hba, (MAILBOX *)mb,
		    MBX_NOWAIT, 0) != MBX_BUSY) {
			(void) emlxs_mem_put(hba, MEM_MBOX, (uint8_t *)mb);
		}
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_link_reset_msg,
		    "Disabling link...");
	}

	return (0);

} /* emlxs_reset_link() */


extern int
emlxs_online(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	int32_t rval = 0;
	uint32_t i = 0;

	/* Make sure adapter is offline or exit trying (30 seconds) */
	for (; ; ) {
		/* Check if adapter is already going online */
		if (hba->flag & (FC_ONLINE_MODE | FC_ONLINING_MODE)) {
			return (0);
		}
		mutex_enter(&EMLXS_PORT_LOCK);

		/* Check again */
		if (hba->flag & (FC_ONLINE_MODE | FC_ONLINING_MODE)) {
			mutex_exit(&EMLXS_PORT_LOCK);
			return (0);
		}
		/* Check if adapter is offline */
		if (hba->flag & FC_OFFLINE_MODE) {
			/* Mark it going online */
			hba->flag &= ~FC_OFFLINE_MODE;
			hba->flag |= FC_ONLINING_MODE;

			/* Currently !FC_ONLINE_MODE and !FC_OFFLINE_MODE */
			mutex_exit(&EMLXS_PORT_LOCK);
			break;
		}
		mutex_exit(&EMLXS_PORT_LOCK);

		if (i++ > 30) {
			/* Return on timeout */
			return (1);
		}
		DELAYMS(1000);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_adapter_trans_msg,
	    "Going online...");

	if (hba->bus_type == SBUS_FC) {
		(void) READ_SBUS_CSR_REG(hba, FC_SHS_REG(hba,
		    hba->sbus_csr_addr));
	}
	if (rval = emlxs_ffinit(hba)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg,
		    "status=%x",
		    rval);
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_offline_msg, NULL);

		/* Set FC_OFFLINE_MODE */
		mutex_enter(&EMLXS_PORT_LOCK);
		emlxs_diag_state = DDI_OFFDI;
		hba->flag |= FC_OFFLINE_MODE;
		hba->flag &= ~FC_ONLINING_MODE;
		mutex_exit(&EMLXS_PORT_LOCK);

		return (rval);
	}
	/* Start the timer */
	emlxs_timer_start(hba);

	/* Set FC_ONLINE_MODE */
	mutex_enter(&EMLXS_PORT_LOCK);
	emlxs_diag_state = DDI_ONDI;
	hba->flag |= FC_ONLINE_MODE;
	hba->flag &= ~FC_ONLINING_MODE;
	mutex_exit(&EMLXS_PORT_LOCK);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_online_msg, NULL);

#ifdef SFCT_SUPPORT
	(void) emlxs_fct_port_initialize(port);
#endif	/* SFCT_SUPPORT */

	return (rval);

} /* emlxs_online() */


extern int
emlxs_offline(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	uint32_t i = 0;
	int rval = 1;

	/* Make sure adapter is online or exit trying (30 seconds) */
	for (; ; ) {
		/* Check if adapter is already going offline */
		if (hba->flag & (FC_OFFLINE_MODE | FC_OFFLINING_MODE)) {
			return (0);
		}
		mutex_enter(&EMLXS_PORT_LOCK);

		/* Check again */
		if (hba->flag & (FC_OFFLINE_MODE | FC_OFFLINING_MODE)) {
			mutex_exit(&EMLXS_PORT_LOCK);
			return (0);
		}
		/* Check if adapter is online */
		if (hba->flag & FC_ONLINE_MODE) {
			/* Mark it going offline */
			hba->flag &= ~FC_ONLINE_MODE;
			hba->flag |= FC_OFFLINING_MODE;

			/* Currently !FC_ONLINE_MODE and !FC_OFFLINE_MODE */
			mutex_exit(&EMLXS_PORT_LOCK);
			break;
		}
		mutex_exit(&EMLXS_PORT_LOCK);

		if (i++ > 30) {
			/* Return on timeout */
			return (1);
		}
		DELAYMS(1000);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_adapter_trans_msg, "Going offline...");

	if (port->ini_mode) {
		/* Flush all IO */
		emlxs_linkdown(hba);

	}
#ifdef SFCT_SUPPORT
	else {
		(void) emlxs_fct_port_shutdown(port);
	}
#endif	/* SFCT_SUPPORT */

	/* Check if adapter was shutdown */
	if (hba->flag & FC_HARDWARE_ERROR) {
		/* Force mailbox cleanup */
		/* This will wake any sleeping or polling threads */
		emlxs_mb_fini(hba, NULL, MBX_HARDWARE_ERROR);
	}
	/* Pause here for the IO to settle */
	delay(drv_usectohz(1000000));	/* 1 sec */

	/* Unregister all nodes */
	emlxs_ffcleanup(hba);


	if (hba->bus_type == SBUS_FC) {
		WRITE_SBUS_CSR_REG(hba,
		    FC_SHS_REG(hba, hba->sbus_csr_addr), 0x9A);
	}
	/* Stop the timer */
	emlxs_timer_stop(hba);

	/* For safety flush every iotag list */
	if (emlxs_iotag_flush(hba)) {
		/* Pause here for the IO to flush */
		delay(drv_usectohz(1000));
	}

	/* Wait for poll command request to settle */
	while (hba->io_poll_count > 0) {
		delay(drv_usectohz(2000000));   /* 2 sec */
	}

	/* Interlock the adapter to take it down */
	(void) emlxs_interlock(hba);

	/* Free all the shared memory */
	(void) emlxs_mem_free_buffer(hba);

	mutex_enter(&EMLXS_PORT_LOCK);
	hba->flag |= FC_OFFLINE_MODE;
	hba->flag &= ~FC_OFFLINING_MODE;
	emlxs_diag_state = DDI_OFFDI;
	mutex_exit(&EMLXS_PORT_LOCK);

	rval = 0;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_offline_msg, NULL);

done:

	return (rval);

} /* emlxs_offline() */



extern int
emlxs_power_down(emlxs_hba_t *hba)
{
	int32_t rval = 0;
	uint32_t *ptr;
	uint32_t i;

	if ((rval = emlxs_offline(hba))) {
		return (rval);
	}
	/* Save pci config space */
	ptr = (uint32_t *)hba->pm_config;
	for (i = 0; i < PCI_CONFIG_SIZE; i += 4, ptr++) {
		*ptr = ddi_get32(hba->pci_acc_handle,
		    (uint32_t *)(hba->pci_addr + i));
	}

	/* Put chip in D3 state */
	(void) ddi_put8(hba->pci_acc_handle,
	    (uint8_t *)(hba->pci_addr + PCI_PM_CONTROL_REGISTER),
	    (uint8_t)PCI_PM_D3_STATE);

	return (0);

} /* End emlxs_power_down */


extern int
emlxs_power_up(emlxs_hba_t *hba)
{
	int32_t rval = 0;
	uint32_t *ptr;
	uint32_t i;


	/* Take chip out of D3 state */
	(void) ddi_put8(hba->pci_acc_handle,
	    (uint8_t *)(hba->pci_addr + PCI_PM_CONTROL_REGISTER),
	    (uint8_t)PCI_PM_D0_STATE);

	/* Must have at least 10 ms delay here */
	DELAYMS(100);

	/* Restore pci config space */
	ptr = (uint32_t *)hba->pm_config;
	for (i = 0; i < PCI_CONFIG_SIZE; i += 4, ptr++) {
		(void) ddi_put32(hba->pci_acc_handle,
		    (uint32_t *)(hba->pci_addr + i), *ptr);
	}

	/* Bring adapter online */
	if ((rval = emlxs_online(hba))) {
		(void) ddi_put8(hba->pci_acc_handle,
		    (uint8_t *)(hba->pci_addr + PCI_PM_CONTROL_REGISTER),
		    (uint8_t)PCI_PM_D3_STATE);

		return (rval);
	}
	return (rval);

} /* End emlxs_power_up */


/*
 * NAME:     emlxs_ffcleanup
 *
 * FUNCTION: Cleanup all the Firefly resources used by configuring the adapter
 *
 * EXECUTION ENVIRONMENT: process only
 *
 * CALLED FROM: CFG_TERM
 *
 * INPUT: hba       - pointer to the dev_ctl area.
 *
 * RETURNS: none
 */
extern void
emlxs_ffcleanup(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	uint32_t j;

	/* Disable all but the mailbox interrupt */
	hba->hc_copy = HC_MBINT_ENA;
	WRITE_CSR_REG(hba, FC_HC_REG(hba, hba->csr_addr), hba->hc_copy);

	/* Make sure all port nodes are destroyed */
	for (j = 0; j < MAX_VPORTS; j++) {
		port = &VPORT(j);

		if (port->node_count) {
			(void) emlxs_mb_unreg_rpi(port, 0xffff, 0, 0, 0);
		}
	}

	/* Clear all interrupt enable conditions */
	hba->hc_copy = 0;
	WRITE_CSR_REG(hba, FC_HC_REG(hba, hba->csr_addr), hba->hc_copy);

	return;

} /* emlxs_ffcleanup() */


extern uint16_t
emlxs_register_pkt(RING *rp, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba;
	emlxs_port_t *port;
	uint16_t iotag;
	uint32_t i;

	hba = rp->hba;

	mutex_enter(&EMLXS_FCTAB_LOCK(rp->ringno));

	if (sbp->iotag != 0) {
		port = &PPORT;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "Pkt already registered! ringo=%d iotag=%d sbp=%p",
		    sbp->ring, sbp->iotag, sbp);
	}
	iotag = 0;
	for (i = 0; i < rp->max_iotag; i++) {
		if (!rp->fc_iotag || rp->fc_iotag >= rp->max_iotag) {
			rp->fc_iotag = 1;
		}
		iotag = rp->fc_iotag++;

		if (rp->fc_table[iotag] == 0 ||
		    rp->fc_table[iotag] == STALE_PACKET) {
			hba->io_count[rp->ringno]++;
			rp->fc_table[iotag] = sbp;

			sbp->iotag = iotag;
			sbp->ring = rp;

			break;
		}
		iotag = 0;
	}

	mutex_exit(&EMLXS_FCTAB_LOCK(rp->ringno));

	/*
	 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	 * "emlxs_register_pkt: ringo=%d iotag=%d sbp=%p", rp->ringno, iotag,
	 * sbp);
	 */

	return (iotag);

} /* emlxs_register_pkt() */



extern emlxs_buf_t *
emlxs_unregister_pkt(RING *rp, uint16_t iotag, uint32_t forced)
{
	emlxs_hba_t *hba;
	emlxs_buf_t *sbp;
	uint32_t ringno;

	/* Check the iotag range */
	if ((iotag == 0) || (iotag >= rp->max_iotag)) {
		return (NULL);
	}
	sbp = NULL;
	hba = rp->hba;
	ringno = rp->ringno;

	/* Remove the sbp from the table */
	mutex_enter(&EMLXS_FCTAB_LOCK(ringno));
	sbp = rp->fc_table[iotag];

	if (!sbp || (sbp == STALE_PACKET)) {
		mutex_exit(&EMLXS_FCTAB_LOCK(ringno));
		return (sbp);
	}
	rp->fc_table[iotag] = ((forced) ? STALE_PACKET : NULL);
	hba->io_count[ringno]--;
	sbp->iotag = 0;

	mutex_exit(&EMLXS_FCTAB_LOCK(ringno));


	/* Clean up the sbp */
	mutex_enter(&sbp->mtx);

	if (sbp->pkt_flags & PACKET_IN_TXQ) {
		sbp->pkt_flags &= ~PACKET_IN_TXQ;
		hba->ring_tx_count[ringno]--;
	}
	if (sbp->pkt_flags & PACKET_IN_CHIPQ) {
		sbp->pkt_flags &= ~PACKET_IN_CHIPQ;
	}
	if (sbp->bmp) {
		(void) emlxs_mem_put(hba, MEM_BPL, (uint8_t *)sbp->bmp);
		sbp->bmp = 0;
	}
	mutex_exit(&sbp->mtx);


	/*
	 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	 * "emlxs_unregister_pkt: ringo=%d iotag=%d sbp=%p", rp->ringno,
	 * iotag, sbp);
	 */

	return (sbp);

} /* emlxs_unregister_pkt() */



/* Flush all IO's to all nodes for a given ring */
extern uint32_t
emlxs_tx_ring_flush(emlxs_hba_t *hba, RING *rp, emlxs_buf_t *fpkt)
{
	emlxs_port_t *port = &PPORT;
	emlxs_buf_t *sbp;
	IOCBQ *iocbq;
	IOCBQ *next;
	IOCB *iocb;
	uint32_t ringno;
	Q abort;
	NODELIST *ndlp;
	IOCB *icmd;
	MATCHMAP *mp;
	uint32_t i;

	ringno = rp->ringno;
	bzero((void *)&abort, sizeof (Q));

	mutex_enter(&EMLXS_RINGTX_LOCK);

	/* While a node needs servicing */
	while (rp->nodeq.q_first) {
		ndlp = (NODELIST *)rp->nodeq.q_first;

		/* Check if priority queue is not empty */
		if (ndlp->nlp_ptx[ringno].q_first) {
			/* Transfer all iocb's to local queue */
			if (abort.q_first == 0) {
				abort.q_first = ndlp->nlp_ptx[ringno].q_first;
				abort.q_last = ndlp->nlp_ptx[ringno].q_last;
			} else {
				((IOCBQ *)abort.q_last)->next =
				    (IOCBQ *)ndlp->nlp_ptx[ringno].q_first;
			}

			abort.q_cnt += ndlp->nlp_ptx[ringno].q_cnt;
		}
		/* Check if tx queue is not empty */
		if (ndlp->nlp_tx[ringno].q_first) {
			/* Transfer all iocb's to local queue */
			if (abort.q_first == 0) {
				abort.q_first = ndlp->nlp_tx[ringno].q_first;
				abort.q_last = ndlp->nlp_tx[ringno].q_last;
			} else {
				((IOCBQ *)abort.q_last)->next =
				    (IOCBQ *)ndlp->nlp_tx[ringno].q_first;
			}

			abort.q_cnt += ndlp->nlp_tx[ringno].q_cnt;

		}
		/* Clear the queue pointers */
		ndlp->nlp_ptx[ringno].q_first = NULL;
		ndlp->nlp_ptx[ringno].q_last = NULL;
		ndlp->nlp_ptx[ringno].q_cnt = 0;

		ndlp->nlp_tx[ringno].q_first = NULL;
		ndlp->nlp_tx[ringno].q_last = NULL;
		ndlp->nlp_tx[ringno].q_cnt = 0;

		/* Remove node from service queue */

		/* If this is the last node on list */
		if (rp->nodeq.q_last == (void *)ndlp) {
			rp->nodeq.q_last = NULL;
			rp->nodeq.q_first = NULL;
			rp->nodeq.q_cnt = 0;
		} else {
			/* Remove node from head */
			rp->nodeq.q_first = ndlp->nlp_next[ringno];
			((NODELIST *)rp->nodeq.q_last)->nlp_next[ringno] =
			    rp->nodeq.q_first;
			rp->nodeq.q_cnt--;
		}

		/* Clear node */
		ndlp->nlp_next[ringno] = NULL;
	}

	/* First cleanup the iocb's while still holding the lock */
	iocbq = (IOCBQ *)abort.q_first;
	while (iocbq) {
		/* Free the IoTag and the bmp */
		iocb = &iocbq->iocb;
		sbp = emlxs_unregister_pkt(iocbq->ring, iocb->ulpIoTag, 0);

		if (sbp && (sbp != STALE_PACKET)) {
			mutex_enter(&sbp->mtx);

			if (sbp->pkt_flags & PACKET_IN_TXQ) {
				sbp->pkt_flags &= ~PACKET_IN_TXQ;
				hba->ring_tx_count[ringno]--;
			}
			sbp->pkt_flags |= PACKET_IN_FLUSH;

			/*
			 * If the fpkt is already set, then we will leave it
			 * alone
			 */
			/*
			 * This ensures that this pkt is only accounted for
			 * on one fpkt->flush_count
			 */
			if (!sbp->fpkt && fpkt) {
				mutex_enter(&fpkt->mtx);
				sbp->fpkt = fpkt;
				fpkt->flush_count++;
				mutex_exit(&fpkt->mtx);
			}
			mutex_exit(&sbp->mtx);
		}
		iocbq = (IOCBQ *)iocbq->next;

	}	/* end of while */

	mutex_exit(&EMLXS_RINGTX_LOCK);

	/* Now abort the iocb's */
	iocbq = (IOCBQ *)abort.q_first;
	while (iocbq) {
		/* Save the next iocbq for now */
		next = (IOCBQ *)iocbq->next;

		/* Unlink this iocbq */
		iocbq->next = NULL;

		/* Get the pkt */
		sbp = (emlxs_buf_t *)iocbq->sbp;

		if (sbp) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_flush_msg,
			    "tx: sbp=%p node=%p",
			    sbp, sbp->node);

			if (hba->state >= FC_LINK_UP) {
				emlxs_pkt_complete(sbp, IOSTAT_LOCAL_REJECT,
				    IOERR_ABORT_REQUESTED, 1);
			} else {
				emlxs_pkt_complete(sbp, IOSTAT_LOCAL_REJECT,
				    IOERR_LINK_DOWN, 1);
			}

		}
		/* Free the iocb and its associated buffers */
		else {
			icmd = &iocbq->iocb;
			if (icmd->ulpCommand == CMD_QUE_RING_BUF64_CN ||
			    icmd->ulpCommand == CMD_QUE_RING_BUF_CN ||
			    icmd->ulpCommand == CMD_QUE_RING_LIST64_CN) {
				if ((hba->flag &
				    (FC_ONLINE_MODE | FC_ONLINING_MODE)) == 0) {
					/* HBA is detaching or offlining */
					if (icmd->ulpCommand !=
					    CMD_QUE_RING_LIST64_CN) {
						uint8_t *tmp;

						for (i = 0;
						    i < icmd->ulpBdeCount;
						    i++) {

							mp = EMLXS_GET_VADDR(
							    hba, rp, icmd);

							tmp = (uint8_t *)mp;
							if (mp) {
	(void) emlxs_mem_put(hba, MEM_BUF, tmp);
							}
						}
					}
					(void) emlxs_mem_put(hba, MEM_IOCB,
					    (uint8_t *)iocbq);
				} else {
					/* repost the unsolicited buffer */
					emlxs_issue_iocb_cmd(hba, rp, iocbq);
				}
			}
		}

		iocbq = next;

	}	/* end of while */

	return (abort.q_cnt);

} /* emlxs_tx_ring_flush() */


/* Flush all IO's on all or a given ring for a given node */
extern uint32_t
emlxs_tx_node_flush(emlxs_port_t *port, NODELIST *ndlp, RING *ring,
    uint32_t shutdown, emlxs_buf_t *fpkt)
{
	emlxs_hba_t *hba = HBA;
	emlxs_buf_t *sbp;
	uint32_t ringno;
	RING *rp;
	IOCB *icmd;
	IOCBQ *iocbq;
	NODELIST *prev;
	IOCBQ *next;
	IOCB *iocb;
	Q abort;
	uint32_t i;
	MATCHMAP *mp;


	bzero((void *)&abort, sizeof (Q));

	/* Flush all I/O's on tx queue to this target */
	mutex_enter(&EMLXS_RINGTX_LOCK);

	if (!ndlp->nlp_base && shutdown) {
		ndlp->nlp_active = 0;
	}
	for (ringno = 0; ringno < hba->ring_count; ringno++) {
		rp = &hba->ring[ringno];

		if (ring && rp != ring) {
			continue;
		}
		if (!ndlp->nlp_base || shutdown) {
			/* Check if priority queue is not empty */
			if (ndlp->nlp_ptx[ringno].q_first) {
				/* Transfer all iocb's to local queue */
				if (abort.q_first == 0) {
					abort.q_first =
					    ndlp->nlp_ptx[ringno].q_first;
					abort.q_last =
					    ndlp->nlp_ptx[ringno].q_last;
				} else {
					emlxs_queue_t *q;

					q = &ndlp->nlp_ptx[ringno];
					((IOCBQ *)abort.q_last)->next =
					    (IOCBQ *)q->q_first;
					/*
					 * ((IOCBQ *)abort.q_last)->next =
					 * (IOCBQ *)
					 * ndlp->nlp_ptx[ringno].q_first;
					 */
				}

				abort.q_cnt += ndlp->nlp_ptx[ringno].q_cnt;
			}
		}
		/* Check if tx queue is not empty */
		if (ndlp->nlp_tx[ringno].q_first) {
			/* Transfer all iocb's to local queue */
			if (abort.q_first == 0) {
				abort.q_first = ndlp->nlp_tx[ringno].q_first;
				abort.q_last = ndlp->nlp_tx[ringno].q_last;
			} else {
				((IOCBQ *)abort.q_last)->next =
				    (IOCBQ *)ndlp->nlp_tx[ringno].q_first;
			}

			abort.q_cnt += ndlp->nlp_tx[ringno].q_cnt;
		}
		/* Clear the queue pointers */
		ndlp->nlp_ptx[ringno].q_first = NULL;
		ndlp->nlp_ptx[ringno].q_last = NULL;
		ndlp->nlp_ptx[ringno].q_cnt = 0;

		ndlp->nlp_tx[ringno].q_first = NULL;
		ndlp->nlp_tx[ringno].q_last = NULL;
		ndlp->nlp_tx[ringno].q_cnt = 0;

		/* If this node was on the ring queue, remove it */
		if (ndlp->nlp_next[ringno]) {
			/* If this is the only node on list */
			if (rp->nodeq.q_first == (void *)ndlp &&
			    rp->nodeq.q_last == (void *)ndlp) {
				rp->nodeq.q_last = NULL;
				rp->nodeq.q_first = NULL;
				rp->nodeq.q_cnt = 0;
			} else if (rp->nodeq.q_first == (void *)ndlp) {
				NODELIST *nd;

				rp->nodeq.q_first = ndlp->nlp_next[ringno];
				nd = (NODELIST *)rp->nodeq.q_last;
				nd->nlp_next[ringno] = rp->nodeq.q_first;
				rp->nodeq.q_cnt--;
			} else {	/* This is a little more difficult */
				/*
				 * Find the previous node in the circular
				 * ring queue
				 */
				prev = ndlp;
				while (prev->nlp_next[ringno] != ndlp) {
					prev = prev->nlp_next[ringno];
				}

				prev->nlp_next[ringno] = ndlp->nlp_next[ringno];

				if (rp->nodeq.q_last == (void *)ndlp) {
					rp->nodeq.q_last = (void *)prev;
				}
				rp->nodeq.q_cnt--;

			}

			/* Clear node */
			ndlp->nlp_next[ringno] = NULL;
		}
	}

	/* First cleanup the iocb's while still holding the lock */
	iocbq = (IOCBQ *)abort.q_first;
	while (iocbq) {
		/* Free the IoTag and the bmp */
		iocb = &iocbq->iocb;
		sbp = emlxs_unregister_pkt(iocbq->ring, iocb->ulpIoTag, 0);

		if (sbp && (sbp != STALE_PACKET)) {
			mutex_enter(&sbp->mtx);
			if (sbp->pkt_flags & PACKET_IN_TXQ) {
				sbp->pkt_flags &= ~PACKET_IN_TXQ;
				hba->ring_tx_count[ring->ringno]--;
			}
			sbp->pkt_flags |= PACKET_IN_FLUSH;

			/*
			 * If the fpkt is already set, then we will leave it
			 * alone
			 */
			/*
			 * This ensures that this pkt is only accounted for
			 * on one fpkt->flush_count
			 */
			if (!sbp->fpkt && fpkt) {
				mutex_enter(&fpkt->mtx);
				sbp->fpkt = fpkt;
				fpkt->flush_count++;
				mutex_exit(&fpkt->mtx);
			}
			mutex_exit(&sbp->mtx);
		}
		iocbq = (IOCBQ *)iocbq->next;

	}	/* end of while */

	mutex_exit(&EMLXS_RINGTX_LOCK);

	/* Now abort the iocb's outside the locks */
	iocbq = (IOCBQ *)abort.q_first;
	while (iocbq) {
		/* Save the next iocbq for now */
		next = (IOCBQ *)iocbq->next;

		/* Unlink this iocbq */
		iocbq->next = NULL;

		/* Get the pkt */
		sbp = (emlxs_buf_t *)iocbq->sbp;

		if (sbp) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_flush_msg,
			    "tx: sbp=%p node=%p",
			    sbp, sbp->node);

			if (hba->state >= FC_LINK_UP) {
				emlxs_pkt_complete(sbp, IOSTAT_LOCAL_REJECT,
				    IOERR_ABORT_REQUESTED, 1);
			} else {
				emlxs_pkt_complete(sbp, IOSTAT_LOCAL_REJECT,
				    IOERR_LINK_DOWN, 1);
			}

		}
		/* Free the iocb and its associated buffers */
		else {
			icmd = &iocbq->iocb;
			if (icmd->ulpCommand == CMD_QUE_RING_BUF64_CN ||
			    icmd->ulpCommand == CMD_QUE_RING_BUF_CN ||
			    icmd->ulpCommand == CMD_QUE_RING_LIST64_CN) {
				if ((hba->flag &
				    (FC_ONLINE_MODE | FC_ONLINING_MODE)) == 0) {
					/* HBA is detaching or offlining */
					if (icmd->ulpCommand !=
					    CMD_QUE_RING_LIST64_CN) {
						uint8_t *tmp;

						for (i = 0;
						    i < icmd->ulpBdeCount;
						    i++) {
							mp = EMLXS_GET_VADDR(
							    hba, rp, icmd);

							tmp = (uint8_t *)mp;
							if (mp) {
	(void) emlxs_mem_put(hba, MEM_BUF, tmp);
							}
						}
					}
					(void) emlxs_mem_put(hba, MEM_IOCB,
					    (uint8_t *)iocbq);
				} else {
					/* repost the unsolicited buffer */
					emlxs_issue_iocb_cmd(hba, rp, iocbq);
				}
			}
		}

		iocbq = next;

	}	/* end of while */

	return (abort.q_cnt);

} /* emlxs_tx_node_flush() */


/* Check for IO's on all or a given ring for a given node */
extern uint32_t
emlxs_tx_node_check(emlxs_port_t *port, NODELIST *ndlp, RING *ring)
{
	emlxs_hba_t *hba = HBA;
	uint32_t ringno;
	RING *rp;
	uint32_t count;

	count = 0;

	/* Flush all I/O's on tx queue to this target */
	mutex_enter(&EMLXS_RINGTX_LOCK);

	for (ringno = 0; ringno < hba->ring_count; ringno++) {
		rp = &hba->ring[ringno];

		if (ring && rp != ring) {
			continue;
		}
		/* Check if priority queue is not empty */
		if (ndlp->nlp_ptx[ringno].q_first) {
			count += ndlp->nlp_ptx[ringno].q_cnt;
		}
		/* Check if tx queue is not empty */
		if (ndlp->nlp_tx[ringno].q_first) {
			count += ndlp->nlp_tx[ringno].q_cnt;
		}
	}

	mutex_exit(&EMLXS_RINGTX_LOCK);

	return (count);

} /* emlxs_tx_node_check() */



/* Flush all IO's on the FCP ring for a given node's lun */
extern uint32_t
emlxs_tx_lun_flush(emlxs_port_t *port, NODELIST *ndlp,
    uint32_t lun, emlxs_buf_t *fpkt)
{
	emlxs_hba_t *hba = HBA;
	emlxs_buf_t *sbp;
	uint32_t ringno;
	IOCBQ *iocbq;
	IOCBQ *prev;
	IOCBQ *next;
	IOCB *iocb;
	IOCB *icmd;
	Q abort;
	uint32_t i;
	MATCHMAP *mp;
	RING *rp;

	ringno = FC_FCP_RING;
	rp = &hba->ring[ringno];

	bzero((void *)&abort, sizeof (Q));

	/* Flush I/O's on txQ to this target's lun */
	mutex_enter(&EMLXS_RINGTX_LOCK);

	/* Scan the priority queue first */
	prev = NULL;
	iocbq = (IOCBQ *)ndlp->nlp_ptx[ringno].q_first;

	while (iocbq) {
		next = (IOCBQ *)iocbq->next;
		iocb = &iocbq->iocb;
		sbp = (emlxs_buf_t *)iocbq->sbp;

		/* Check if this IO is for our lun */
		if (sbp->lun == lun) {
			/* Remove iocb from the node's tx queue */
			if (next == 0) {
				ndlp->nlp_ptx[ringno].q_last = (uint8_t *)prev;
			}
			if (prev == 0) {
				ndlp->nlp_ptx[ringno].q_first = (uint8_t *)next;
			} else {
				prev->next = next;
			}

			iocbq->next = NULL;
			ndlp->nlp_ptx[ringno].q_cnt--;

			/* Add this iocb to our local abort Q */
			/* This way we don't hold the RINGTX lock too long */
			if (abort.q_first) {
				((IOCBQ *) abort.q_last)->next = iocbq;
				abort.q_last = (uint8_t *)iocbq;
				abort.q_cnt++;
			} else {
				abort.q_first = (uint8_t *)iocbq;
				abort.q_last = (uint8_t *)iocbq;
				abort.q_cnt = 1;
			}
			iocbq->next = NULL;
		} else {
			prev = iocbq;
		}

		iocbq = next;

	}	/* while (iocbq) */


	/* Scan the regular queue */
	prev = NULL;
	iocbq = (IOCBQ *)ndlp->nlp_tx[ringno].q_first;

	while (iocbq) {
		next = (IOCBQ *)iocbq->next;
		iocb = &iocbq->iocb;
		sbp = (emlxs_buf_t *)iocbq->sbp;

		/* Check if this IO is for our lun */
		if (sbp->lun == lun) {
			/* Remove iocb from the node's tx queue */
			if (next == 0) {
				ndlp->nlp_tx[ringno].q_last = (uint8_t *)prev;
			}
			if (prev == 0) {
				ndlp->nlp_tx[ringno].q_first = (uint8_t *)next;
			} else {
				prev->next = next;
			}

			iocbq->next = NULL;
			ndlp->nlp_tx[ringno].q_cnt--;

			/* Add this iocb to our local abort Q */
			/* This way we don't hold the RINGTX lock too long */
			if (abort.q_first) {
				((IOCBQ *) abort.q_last)->next = iocbq;
				abort.q_last = (uint8_t *)iocbq;
				abort.q_cnt++;
			} else {
				abort.q_first = (uint8_t *)iocbq;
				abort.q_last = (uint8_t *)iocbq;
				abort.q_cnt = 1;
			}
			iocbq->next = NULL;
		} else {
			prev = iocbq;
		}

		iocbq = next;

	}	/* while (iocbq) */

	/* First cleanup the iocb's while still holding the lock */
	iocbq = (IOCBQ *)abort.q_first;
	while (iocbq) {
		/* Free the IoTag and the bmp */
		iocb = &iocbq->iocb;
		sbp = emlxs_unregister_pkt(iocbq->ring, iocb->ulpIoTag, 0);

		if (sbp && (sbp != STALE_PACKET)) {
			mutex_enter(&sbp->mtx);
			if (sbp->pkt_flags & PACKET_IN_TXQ) {
				sbp->pkt_flags &= ~PACKET_IN_TXQ;
				hba->ring_tx_count[ringno]--;
			}
			sbp->pkt_flags |= PACKET_IN_FLUSH;

			/*
			 * If the fpkt is already set, then we will leave it
			 * alone
			 */
			/*
			 * This ensures that this pkt is only accounted for
			 * on one fpkt->flush_count
			 */
			if (!sbp->fpkt && fpkt) {
				mutex_enter(&fpkt->mtx);
				sbp->fpkt = fpkt;
				fpkt->flush_count++;
				mutex_exit(&fpkt->mtx);
			}
			mutex_exit(&sbp->mtx);
		}
		iocbq = (IOCBQ *)iocbq->next;

	}	/* end of while */

	mutex_exit(&EMLXS_RINGTX_LOCK);

	/* Now abort the iocb's outside the locks */
	iocbq = (IOCBQ *)abort.q_first;
	while (iocbq) {
		/* Save the next iocbq for now */
		next = (IOCBQ *)iocbq->next;

		/* Unlink this iocbq */
		iocbq->next = NULL;

		/* Get the pkt */
		sbp = (emlxs_buf_t *)iocbq->sbp;

		if (sbp) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_flush_msg,
			    "tx: sbp=%p node=%p",
			    sbp, sbp->node);

			if (hba->state >= FC_LINK_UP) {
				emlxs_pkt_complete(sbp, IOSTAT_LOCAL_REJECT,
				    IOERR_ABORT_REQUESTED, 1);
			} else {
				emlxs_pkt_complete(sbp, IOSTAT_LOCAL_REJECT,
				    IOERR_LINK_DOWN, 1);
			}
		}
		/* Free the iocb and its associated buffers */
		else {
			icmd = &iocbq->iocb;

			if (icmd->ulpCommand == CMD_QUE_RING_BUF64_CN ||
			    icmd->ulpCommand == CMD_QUE_RING_BUF_CN ||
			    icmd->ulpCommand == CMD_QUE_RING_LIST64_CN) {
				if ((hba->flag &
				    (FC_ONLINE_MODE | FC_ONLINING_MODE)) == 0) {
					/* HBA is detaching or offlining */
					if (icmd->ulpCommand !=
					    CMD_QUE_RING_LIST64_CN) {
						uint8_t *tmp;

						for (i = 0;
						    i < icmd->ulpBdeCount;
						    i++) {
							mp = EMLXS_GET_VADDR(
							    hba, rp, icmd);

							tmp = (uint8_t *)mp;
							if (mp) {
	(void) emlxs_mem_put(hba, MEM_BUF, tmp);
							}
						}
					}
					(void) emlxs_mem_put(hba, MEM_IOCB,
					    (uint8_t *)iocbq);
				} else {
					/* repost the unsolicited buffer */
					emlxs_issue_iocb_cmd(hba, rp, iocbq);
				}
			}
		}

		iocbq = next;

	}	/* end of while */


	return (abort.q_cnt);

} /* emlxs_tx_lun_flush() */


extern void
emlxs_tx_put(IOCBQ *iocbq, uint32_t lock)
{
	emlxs_hba_t *hba;
	emlxs_port_t *port;
	uint32_t ringno;
	NODELIST *nlp;
	RING *rp;
	emlxs_buf_t *sbp;

	port = (emlxs_port_t *)iocbq->port;
	hba = HBA;
	rp = (RING *)iocbq->ring;
	nlp = (NODELIST *)iocbq->node;
	ringno = rp->ringno;
	sbp = (emlxs_buf_t *)iocbq->sbp;

	if (nlp == NULL) {
		/* Set node to base node by default */
		nlp = &port->node_base;

		iocbq->node = (void *)nlp;

		if (sbp) {
			sbp->node = (void *)nlp;
		}
	}
	if (lock) {
		mutex_enter(&EMLXS_RINGTX_LOCK);
	}
	if (!nlp->nlp_active || (sbp && (sbp->pkt_flags & PACKET_IN_ABORT))) {
		if (sbp) {
			mutex_enter(&sbp->mtx);

			if (sbp->pkt_flags & PACKET_IN_TXQ) {
				sbp->pkt_flags &= ~PACKET_IN_TXQ;
				hba->ring_tx_count[ringno]--;
			}
			sbp->pkt_flags |= PACKET_IN_FLUSH;

			mutex_exit(&sbp->mtx);

			/* Free the ulpIoTag and the bmp */
			(void) emlxs_unregister_pkt(rp, sbp->iotag, 0);

			if (lock) {
				mutex_exit(&EMLXS_RINGTX_LOCK);
			}
			if (hba->state >= FC_LINK_UP) {
				emlxs_pkt_complete(sbp, IOSTAT_LOCAL_REJECT,
				    IOERR_ABORT_REQUESTED, 1);
			} else {
				emlxs_pkt_complete(sbp, IOSTAT_LOCAL_REJECT,
				    IOERR_LINK_DOWN, 1);
			}

			return;
		} else {
			if (lock) {
				mutex_exit(&EMLXS_RINGTX_LOCK);
			}
			(void) emlxs_mem_put(hba, MEM_IOCB, (uint8_t *)iocbq);
		}

		return;
	}
	if (sbp) {

		mutex_enter(&sbp->mtx);

		if (sbp->pkt_flags & (PACKET_IN_COMPLETION | PACKET_IN_CHIPQ |
		    PACKET_IN_TXQ)) {
			mutex_exit(&sbp->mtx);
			if (lock) {
				mutex_exit(&EMLXS_RINGTX_LOCK);
			}
			return;
		}
		sbp->pkt_flags |= PACKET_IN_TXQ;
		hba->ring_tx_count[ringno]++;

		mutex_exit(&sbp->mtx);
	}
	/* Check iocbq priority */
	if (iocbq->flag & IOCB_PRIORITY) {
		/* Add the iocb to the bottom of the node's ptx queue */
		if (nlp->nlp_ptx[ringno].q_first) {
			((IOCBQ *)nlp->nlp_ptx[ringno].q_last)->next = iocbq;
			nlp->nlp_ptx[ringno].q_last = (uint8_t *)iocbq;
			nlp->nlp_ptx[ringno].q_cnt++;
		} else {
			nlp->nlp_ptx[ringno].q_first = (uint8_t *)iocbq;
			nlp->nlp_ptx[ringno].q_last = (uint8_t *)iocbq;
			nlp->nlp_ptx[ringno].q_cnt = 1;
		}

		iocbq->next = NULL;
	} else {	/* Normal priority */

		/* Add the iocb to the bottom of the node's tx queue */
		if (nlp->nlp_tx[ringno].q_first) {
			((IOCBQ *)nlp->nlp_tx[ringno].q_last)->next = iocbq;
			nlp->nlp_tx[ringno].q_last = (uint8_t *)iocbq;
			nlp->nlp_tx[ringno].q_cnt++;
		} else {
			nlp->nlp_tx[ringno].q_first = (uint8_t *)iocbq;
			nlp->nlp_tx[ringno].q_last = (uint8_t *)iocbq;
			nlp->nlp_tx[ringno].q_cnt = 1;
		}

		iocbq->next = NULL;
	}


	/*
	 * Check if the node is not already on ring queue and (is not closed
	 * or  is a priority request)
	 */
	if (!nlp->nlp_next[ringno] && (!(nlp->nlp_flag[ringno] & NLP_CLOSED) ||
	    (iocbq->flag & IOCB_PRIORITY))) {
		/* If so, then add it to the ring queue */
		if (rp->nodeq.q_first) {
			((NODELIST *)rp->nodeq.q_last)->nlp_next[ringno] =
			    (uint8_t *)nlp;
			nlp->nlp_next[ringno] = rp->nodeq.q_first;

			/*
			 * If this is not the base node then add it to the
			 * tail
			 */
			if (!nlp->nlp_base) {
				rp->nodeq.q_last = (uint8_t *)nlp;
			} else {	/* Otherwise, add it to the head */
				/* The command node always gets priority */
				rp->nodeq.q_first = (uint8_t *)nlp;
			}

			rp->nodeq.q_cnt++;
		} else {
			rp->nodeq.q_first = (uint8_t *)nlp;
			rp->nodeq.q_last = (uint8_t *)nlp;
			nlp->nlp_next[ringno] = nlp;
			rp->nodeq.q_cnt = 1;
		}
	}
	HBASTATS.IocbTxPut[ringno]++;

	/* Adjust the ring timeout timer */
	rp->timeout = hba->timer_tics + 5;

	if (lock) {
		mutex_exit(&EMLXS_RINGTX_LOCK);
	}
	return;

} /* emlxs_tx_put() */


extern IOCBQ *
emlxs_tx_get(RING *rp, uint32_t lock)
{
	emlxs_hba_t *hba;
	uint32_t ringno;
	IOCBQ *iocbq;
	NODELIST *nlp;
	emlxs_buf_t *sbp;

	hba = rp->hba;
	ringno = rp->ringno;

	if (lock) {
		mutex_enter(&EMLXS_RINGTX_LOCK);
	}
begin:

	iocbq = NULL;

	/* Check if a node needs servicing */
	if (rp->nodeq.q_first) {
		nlp = (NODELIST *)rp->nodeq.q_first;

		/* Get next iocb from node's priority queue */

		if (nlp->nlp_ptx[ringno].q_first) {
			iocbq = (IOCBQ *)nlp->nlp_ptx[ringno].q_first;

			/* Check if this is last entry */
			if (nlp->nlp_ptx[ringno].q_last == (void *)iocbq) {
				nlp->nlp_ptx[ringno].q_first = NULL;
				nlp->nlp_ptx[ringno].q_last = NULL;
				nlp->nlp_ptx[ringno].q_cnt = 0;
			} else {
				/* Remove iocb from head */
				nlp->nlp_ptx[ringno].q_first =
				    (void *)iocbq->next;
				nlp->nlp_ptx[ringno].q_cnt--;
			}

			iocbq->next = NULL;
		}
		/* Get next iocb from node tx queue if node not closed */
		else if (nlp->nlp_tx[ringno].q_first &&
		    !(nlp->nlp_flag[ringno] & NLP_CLOSED)) {
			iocbq = (IOCBQ *)nlp->nlp_tx[ringno].q_first;

			/* Check if this is last entry */
			if (nlp->nlp_tx[ringno].q_last == (void *)iocbq) {
				nlp->nlp_tx[ringno].q_first = NULL;
				nlp->nlp_tx[ringno].q_last = NULL;
				nlp->nlp_tx[ringno].q_cnt = 0;
			} else {
				/* Remove iocb from head */
				nlp->nlp_tx[ringno].q_first =
				    (void *)iocbq->next;
				nlp->nlp_tx[ringno].q_cnt--;
			}

			iocbq->next = NULL;
		}
		/* Now deal with node itself */

		/* Check if node still needs servicing */
		if ((nlp->nlp_ptx[ringno].q_first) ||
		    (nlp->nlp_tx[ringno].q_first &&
		    !(nlp->nlp_flag[ringno] & NLP_CLOSED))) {

			/*
			 * If this is the base node, then don't shift the
			 * pointers
			 */
			/* We want to drain the base node before moving on */
			if (!nlp->nlp_base) {
				/*
				 * Just shift ring queue pointers to next
				 * node
				 */
				rp->nodeq.q_last = (void *)nlp;
				rp->nodeq.q_first = nlp->nlp_next[ringno];
			}
		} else {
			/* Remove node from ring queue */

			/* If this is the last node on list */
			if (rp->nodeq.q_last == (void *)nlp) {
				rp->nodeq.q_last = NULL;
				rp->nodeq.q_first = NULL;
				rp->nodeq.q_cnt = 0;
			} else {
				NODELIST *nd;

				/* Remove node from head */
				rp->nodeq.q_first = nlp->nlp_next[ringno];
				nd = (NODELIST *)rp->nodeq.q_last;
				nd->nlp_next[ringno] = rp->nodeq.q_first;
				rp->nodeq.q_cnt--;

			}

			/* Clear node */
			nlp->nlp_next[ringno] = NULL;
		}

		/*
		 * If no iocbq was found on this node, then it will have been
		 * removed. So try again.
		 */
		if (!iocbq) {
			goto begin;
		}
		sbp = (emlxs_buf_t *)iocbq->sbp;

		if (sbp) {
			/*
			 * Check flags before we enter mutex in case this has
			 * been flushed and destroyed
			 */
			if ((sbp->pkt_flags &
			    (PACKET_IN_COMPLETION | PACKET_IN_CHIPQ)) ||
			    !(sbp->pkt_flags & PACKET_IN_TXQ)) {
				goto begin;
			}
			mutex_enter(&sbp->mtx);

			if ((sbp->pkt_flags &
			    (PACKET_IN_COMPLETION | PACKET_IN_CHIPQ)) ||
			    !(sbp->pkt_flags & PACKET_IN_TXQ)) {
				mutex_exit(&sbp->mtx);
				goto begin;
			}
			sbp->pkt_flags &= ~PACKET_IN_TXQ;
			hba->ring_tx_count[ringno]--;

			mutex_exit(&sbp->mtx);
		}
	}
	if (iocbq) {
		HBASTATS.IocbTxGet[ringno]++;
	}
	/* Adjust the ring timeout timer */
	rp->timeout = (rp->nodeq.q_first) ? (hba->timer_tics + 5) : 0;

	if (lock) {
		mutex_exit(&EMLXS_RINGTX_LOCK);
	}
	return (iocbq);

} /* emlxs_tx_get() */



extern uint32_t
emlxs_chipq_node_flush(emlxs_port_t *port, RING *ring,
    NODELIST *ndlp, emlxs_buf_t *fpkt)
{
	emlxs_hba_t *hba = HBA;
	emlxs_buf_t *sbp;
	IOCBQ *iocbq;
	IOCBQ *next;
	Q abort;
	RING *rp;
	uint32_t ringno;
	uint8_t flag[MAX_RINGS];
	uint32_t iotag;

	bzero((void *)&abort, sizeof (Q));
	bzero((void *)flag, sizeof (flag));

	for (ringno = 0; ringno < hba->ring_count; ringno++) {
		rp = &hba->ring[ringno];

		if (ring && rp != ring) {
			continue;
		}
		mutex_enter(&EMLXS_FCTAB_LOCK(ringno));

		for (iotag = 1; iotag < rp->max_iotag; iotag++) {
			sbp = rp->fc_table[iotag];

			if (sbp && (sbp != STALE_PACKET) &&
			    (sbp->pkt_flags & PACKET_IN_CHIPQ) &&
			    (sbp->node == ndlp) &&
			    (sbp->ring == rp) &&
			    !(sbp->pkt_flags & PACKET_XRI_CLOSED)) {
				emlxs_sbp_abort_add(port, sbp, &abort,
				    flag, fpkt);
			}
		}
		mutex_exit(&EMLXS_FCTAB_LOCK(ringno));

	}	/* for */

	/* Now put the iocb's on the tx queue */
	iocbq = (IOCBQ *)abort.q_first;
	while (iocbq) {
		/* Save the next iocbq for now */
		next = (IOCBQ *)iocbq->next;

		/* Unlink this iocbq */
		iocbq->next = NULL;

		/* Send this iocbq */
		emlxs_tx_put(iocbq, 1);

		iocbq = next;
	}

	/* Now trigger ring service */
	for (ringno = 0; ringno < hba->ring_count; ringno++) {
		if (!flag[ringno]) {
			continue;
		}
		rp = &hba->ring[ringno];

		emlxs_issue_iocb_cmd(hba, rp, 0);
	}

	return (abort.q_cnt);

} /* emlxs_chipq_node_flush() */


/* Flush all IO's left on all iotag lists */
static uint32_t
emlxs_iotag_flush(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	emlxs_buf_t *sbp;
	IOCBQ *iocbq;
	IOCB *iocb;
	Q abort;
	RING *rp;
	uint32_t ringno;
	uint32_t iotag;
	uint32_t count;

	count = 0;
	for (ringno = 0; ringno < hba->ring_count; ringno++) {
		rp = &hba->ring[ringno];

		bzero((void *)&abort, sizeof (Q));

		mutex_enter(&EMLXS_FCTAB_LOCK(ringno));

		for (iotag = 1; iotag < rp->max_iotag; iotag++) {
			sbp = rp->fc_table[iotag];

			if (!sbp || (sbp == STALE_PACKET)) {
				continue;
			}
			/* Unregister the packet */
			rp->fc_table[iotag] = STALE_PACKET;
			hba->io_count[ringno]--;
			sbp->iotag = 0;

			/* Clean up the sbp */
			mutex_enter(&sbp->mtx);

			/* Set IOCB status */
			iocbq = &sbp->iocbq;
			iocb = &iocbq->iocb;

			iocb->ulpStatus = IOSTAT_LOCAL_REJECT;
			iocb->un.grsp.perr.statLocalError = IOERR_LINK_DOWN;
			iocb->ulpLe = 1;
			iocbq->next = NULL;

			if (sbp->pkt_flags & PACKET_IN_TXQ) {
				sbp->pkt_flags &= ~PACKET_IN_TXQ;
				hba->ring_tx_count[ringno]--;
			}
			if (sbp->pkt_flags & PACKET_IN_CHIPQ) {
				sbp->pkt_flags &= ~PACKET_IN_CHIPQ;
			}
			if (sbp->bmp) {
				(void) emlxs_mem_put(hba, MEM_BPL,
				    (uint8_t *)sbp->bmp);
				sbp->bmp = 0;
			}
			/* At this point all nodes are assumed destroyed */
			sbp->node = 0;

			mutex_exit(&sbp->mtx);

			/* Add this iocb to our local abort Q */
			if (abort.q_first) {
				((IOCBQ *) abort.q_last)->next = iocbq;
				abort.q_last = (uint8_t *)iocbq;
				abort.q_cnt++;
			} else {
				abort.q_first = (uint8_t *)iocbq;
				abort.q_last = (uint8_t *)iocbq;
				abort.q_cnt = 1;
			}
		}

		mutex_exit(&EMLXS_FCTAB_LOCK(ringno));

		/* Trigger deferred completion */
		if (abort.q_first) {
			mutex_enter(&rp->rsp_lock);
			if (rp->rsp_head == NULL) {
				rp->rsp_head = (IOCBQ *)abort.q_first;
				rp->rsp_tail = (IOCBQ *)abort.q_last;
			} else {
				rp->rsp_tail->next = (IOCBQ *)abort.q_first;
				rp->rsp_tail = (IOCBQ *)abort.q_last;
			}
			mutex_exit(&rp->rsp_lock);

			emlxs_thread_trigger2(&rp->intr_thread,
			    emlxs_proc_ring, rp);

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_flush_msg,
			    "Forced iotag completion. ring=%d count=%d",
			    ringno, abort.q_cnt);

			count += abort.q_cnt;
		}
	}

	return (count);

} /* emlxs_iotag_flush() */



/* Checks for IO's on all or a given ring for a given node */
extern uint32_t
emlxs_chipq_node_check(emlxs_port_t *port, RING *ring, NODELIST *ndlp)
{
	emlxs_hba_t *hba = HBA;
	emlxs_buf_t *sbp;
	RING *rp;
	uint32_t ringno;
	uint32_t count;
	uint32_t iotag;

	count = 0;

	for (ringno = 0; ringno < hba->ring_count; ringno++) {
		rp = &hba->ring[ringno];

		if (ring && rp != ring) {
			continue;
		}
		mutex_enter(&EMLXS_FCTAB_LOCK(ringno));

		for (iotag = 1; iotag < rp->max_iotag; iotag++) {
			sbp = rp->fc_table[iotag];

			if (sbp && (sbp != STALE_PACKET) &&
			    (sbp->pkt_flags & PACKET_IN_CHIPQ) &&
			    (sbp->node == ndlp) &&
			    (sbp->ring == rp) &&
			    !(sbp->pkt_flags & PACKET_XRI_CLOSED)) {
				count++;
			}
		}
		mutex_exit(&EMLXS_FCTAB_LOCK(ringno));

	}	/* for */

	return (count);

} /* emlxs_chipq_node_check() */



/* Flush all IO's for a given node's lun (FC_FCP_RING only) */
extern uint32_t
emlxs_chipq_lun_flush(emlxs_port_t *port, NODELIST *ndlp,
    uint32_t lun, emlxs_buf_t *fpkt)
{
	emlxs_hba_t *hba = HBA;
	emlxs_buf_t *sbp;
	RING *rp;
	IOCBQ *iocbq;
	IOCBQ *next;
	Q abort;
	uint32_t iotag;
	uint8_t flag[MAX_RINGS];

	bzero((void *)flag, sizeof (flag));
	bzero((void *)&abort, sizeof (Q));
	rp = &hba->ring[FC_FCP_RING];

	mutex_enter(&EMLXS_FCTAB_LOCK(FC_FCP_RING));
	for (iotag = 1; iotag < rp->max_iotag; iotag++) {
		sbp = rp->fc_table[iotag];

		if (sbp && (sbp != STALE_PACKET) &&
		    sbp->pkt_flags & PACKET_IN_CHIPQ &&
		    sbp->node == ndlp &&
		    sbp->ring == rp &&
		    sbp->lun == lun &&
		    !(sbp->pkt_flags & PACKET_XRI_CLOSED)) {
			emlxs_sbp_abort_add(port, sbp, &abort, flag, fpkt);
		}
	}
	mutex_exit(&EMLXS_FCTAB_LOCK(FC_FCP_RING));

	/* Now put the iocb's on the tx queue */
	iocbq = (IOCBQ *)abort.q_first;
	while (iocbq) {
		/* Save the next iocbq for now */
		next = (IOCBQ *)iocbq->next;

		/* Unlink this iocbq */
		iocbq->next = NULL;

		/* Send this iocbq */
		emlxs_tx_put(iocbq, 1);

		iocbq = next;
	}

	/* Now trigger ring service */
	if (abort.q_cnt) {
		emlxs_issue_iocb_cmd(hba, rp, 0);
	}
	return (abort.q_cnt);

} /* emlxs_chipq_lun_flush() */



/*
 * Issue an ABORT_XRI_CN iocb command to abort an FCP command already issued.
 * This must be called while holding the EMLXS_FCCTAB_LOCK
 */
extern IOCBQ *
emlxs_create_abort_xri_cn(emlxs_port_t *port, NODELIST *ndlp, uint16_t iotag,
    RING *rp, uint8_t class, int32_t flag)
{
	emlxs_hba_t *hba = HBA;
	IOCBQ *iocbq;
	IOCB *iocb;
	uint16_t abort_iotag;

	if ((iocbq = (IOCBQ *)emlxs_mem_get(hba, MEM_IOCB)) == NULL) {
		return (NULL);
	}
	iocbq->ring = (void *)rp;
	iocbq->port = (void *)port;
	iocbq->node = (void *)ndlp;
	iocbq->flag |= (IOCB_PRIORITY | IOCB_SPECIAL);
	iocb = &iocbq->iocb;

	/*
	 * set up an iotag using special Abort iotags
	 */
	if ((rp->fc_abort_iotag < rp->max_iotag)) {
		rp->fc_abort_iotag = rp->max_iotag;
	}
	abort_iotag = rp->fc_abort_iotag++;


	iocb->ulpIoTag = abort_iotag;
	iocb->un.acxri.abortType = flag;
	iocb->un.acxri.abortContextTag = ndlp->nlp_Rpi;
	iocb->un.acxri.abortIoTag = iotag;
	iocb->ulpLe = 1;
	iocb->ulpClass = class;
	iocb->ulpCommand = CMD_ABORT_XRI_CN;
	iocb->ulpOwner = OWN_CHIP;

	return (iocbq);

} /* emlxs_create_abort_xri_cn() */


extern IOCBQ *
emlxs_create_abort_xri_cx(emlxs_port_t *port, NODELIST *ndlp, uint16_t xid,
    RING *rp, uint8_t class, int32_t flag)
{
	emlxs_hba_t *hba = HBA;
	IOCBQ *iocbq;
	IOCB *iocb;
	uint16_t abort_iotag;

	if ((iocbq = (IOCBQ *)emlxs_mem_get(hba, MEM_IOCB)) == NULL) {
		return (NULL);
	}
	iocbq->ring = (void *)rp;
	iocbq->port = (void *)port;
	iocbq->node = (void *)ndlp;
	iocbq->flag |= (IOCB_PRIORITY | IOCB_SPECIAL);
	iocb = &iocbq->iocb;

	/*
	 * set up an iotag using special Abort iotags
	 */
	if ((rp->fc_abort_iotag < rp->max_iotag)) {
		rp->fc_abort_iotag = rp->max_iotag;
	}
	abort_iotag = rp->fc_abort_iotag++;

	iocb->ulpContext = xid;
	iocb->ulpIoTag = abort_iotag;
	iocb->un.acxri.abortType = flag;
	iocb->ulpLe = 1;
	iocb->ulpClass = class;
	iocb->ulpCommand = CMD_ABORT_XRI_CX;
	iocb->ulpOwner = OWN_CHIP;

	return (iocbq);

} /* emlxs_create_abort_xri_cx() */



/* This must be called while holding the EMLXS_FCCTAB_LOCK */
extern IOCBQ *
emlxs_create_close_xri_cn(emlxs_port_t *port, NODELIST *ndlp,
    uint16_t iotag, RING *rp)
{
	emlxs_hba_t *hba = HBA;
	IOCBQ *iocbq;
	IOCB *iocb;
	uint16_t abort_iotag;

	if ((iocbq = (IOCBQ *)emlxs_mem_get(hba, MEM_IOCB)) == NULL) {
		return (NULL);
	}
	iocbq->ring = (void *)rp;
	iocbq->port = (void *)port;
	iocbq->node = (void *)ndlp;
	iocbq->flag |= (IOCB_PRIORITY | IOCB_SPECIAL);
	iocb = &iocbq->iocb;

	/*
	 * set up an iotag using special Abort iotags
	 */
	if ((rp->fc_abort_iotag < rp->max_iotag)) {
		rp->fc_abort_iotag = rp->max_iotag;
	}
	abort_iotag = rp->fc_abort_iotag++;

	iocb->ulpIoTag = abort_iotag;
	iocb->un.acxri.abortType = 0;
	iocb->un.acxri.abortContextTag = ndlp->nlp_Rpi;
	iocb->un.acxri.abortIoTag = iotag;
	iocb->ulpLe = 1;
	iocb->ulpClass = 0;
	iocb->ulpCommand = CMD_CLOSE_XRI_CN;
	iocb->ulpOwner = OWN_CHIP;

	return (iocbq);

} /* emlxs_create_close_xri_cn() */


/* This must be called while holding the EMLXS_FCCTAB_LOCK */
extern IOCBQ *
emlxs_create_close_xri_cx(emlxs_port_t *port, NODELIST *ndlp,
    uint16_t xid, RING *rp)
{
	emlxs_hba_t *hba = HBA;
	IOCBQ *iocbq;
	IOCB *iocb;
	uint16_t abort_iotag;

	if ((iocbq = (IOCBQ *)emlxs_mem_get(hba, MEM_IOCB)) == NULL) {
		return (NULL);
	}
	iocbq->ring = (void *)rp;
	iocbq->port = (void *)port;
	iocbq->node = (void *)ndlp;
	iocbq->flag |= (IOCB_PRIORITY | IOCB_SPECIAL);
	iocb = &iocbq->iocb;

	/*
	 * set up an iotag using special Abort iotags
	 */
	if ((rp->fc_abort_iotag < rp->max_iotag)) {
		rp->fc_abort_iotag = rp->max_iotag;
	}
	abort_iotag = rp->fc_abort_iotag++;

	iocb->ulpContext = xid;
	iocb->ulpIoTag = abort_iotag;
	iocb->ulpLe = 1;
	iocb->ulpClass = 0;
	iocb->ulpCommand = CMD_CLOSE_XRI_CX;
	iocb->ulpOwner = OWN_CHIP;

	return (iocbq);

} /* emlxs_create_close_xri_cx() */


void
emlxs_abort_ct_exchange(emlxs_port_t *port, uint32_t rxid)
{
	emlxs_hba_t *hba = HBA;
	RING *rp;
	IOCBQ *iocbq;

	rp = &hba->ring[FC_CT_RING];

	/* Create the abort IOCB */
	if (hba->state >= FC_LINK_UP) {
		iocbq = emlxs_create_abort_xri_cx(port, NULL, rxid, rp,
		    CLASS3, ABORT_TYPE_ABTS);
	}
	else
	{
		iocbq = emlxs_create_close_xri_cx(port, NULL, rxid, rp);
	}
	iocbq->port = port;
	emlxs_issue_iocb_cmd(hba, rp, iocbq);
}


/* This must be called while holding the EMLXS_FCCTAB_LOCK */
static void
emlxs_sbp_abort_add(emlxs_port_t *port, emlxs_buf_t *sbp, Q *abort,
    uint8_t *flag, emlxs_buf_t *fpkt)
{
	emlxs_hba_t *hba = HBA;
	IOCBQ *iocbq;
	RING *rp;
	NODELIST *ndlp;

	rp = (RING *)sbp->ring;
	ndlp = sbp->node;

	/* Create the close XRI IOCB */
	iocbq = emlxs_create_close_xri_cn(port, ndlp, sbp->iotag, rp);

	/* Add this iocb to our local abort Q */
	/* This way we don't hold the CHIPQ lock too long */
	if (iocbq) {
		if (abort->q_first) {
			((IOCBQ *) abort->q_last)->next = iocbq;
			abort->q_last = (uint8_t *)iocbq;
			abort->q_cnt++;
		} else {
			abort->q_first = (uint8_t *)iocbq;
			abort->q_last = (uint8_t *)iocbq;
			abort->q_cnt = 1;
		}
		iocbq->next = NULL;
	}
	/* set the flags */
	mutex_enter(&sbp->mtx);

	sbp->pkt_flags |= (PACKET_IN_FLUSH | PACKET_XRI_CLOSED);
	sbp->ticks = hba->timer_tics + 10;
	sbp->abort_attempts++;

	flag[rp->ringno] = 1;

	/* If the fpkt is already set, then we will leave it alone */
	/*
	 * This ensures that this pkt is only accounted for on one
	 * fpkt->flush_count
	 */
	if (!sbp->fpkt && fpkt) {
		mutex_enter(&fpkt->mtx);
		sbp->fpkt = fpkt;
		fpkt->flush_count++;
		mutex_exit(&fpkt->mtx);
	}
	mutex_exit(&sbp->mtx);

	return;

} /* emlxs_sbp_abort_add() */
