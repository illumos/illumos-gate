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
EMLXS_MSG_DEF(EMLXS_FCP_C);

#define	EMLXS_GET_VADDR(hba, rp, icmd) emlxs_mem_get_vaddr(hba, rp, \
	PADDR(icmd->un.cont64[i].addrHigh, icmd->un.cont64[i].addrLow));

static void	emlxs_sbp_abort_add(emlxs_port_t *port, emlxs_buf_t *sbp,
    Q *abort, uint8_t *flag, emlxs_buf_t *fpkt);

#define	SCSI3_PERSISTENT_RESERVE_IN	0x5e
#define	SCSI_INQUIRY			0x12
#define	SCSI_RX_DIAG    		0x1C


/*
 *  emlxs_handle_fcp_event
 *
 *  Description: Process an FCP Rsp Ring completion
 *
 */
/* ARGSUSED */
extern void
emlxs_handle_fcp_event(emlxs_hba_t *hba, CHANNEL *cp, IOCBQ *iocbq)
{
	emlxs_port_t *port = &PPORT;
	emlxs_config_t	*cfg = &CFG;
	IOCB *cmd;
	emlxs_buf_t *sbp;
	fc_packet_t *pkt = NULL;
#ifdef SAN_DIAG_SUPPORT
	NODELIST *ndlp;
#endif
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
	uint32_t length;

	cmd = &iocbq->iocb;

	/* Initialize the status */
	iostat = cmd->ULPSTATUS;
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
		    "cmd=%x iotag=%d", cmd->ULPCOMMAND, cmd->ULPIOTAG);

		return;
	}

	HBASTATS.FcpCompleted++;

#ifdef SAN_DIAG_SUPPORT
	emlxs_update_sd_bucket(sbp);
#endif /* SAN_DIAG_SUPPORT */

	pkt = PRIV2PKT(sbp);

	did = LE_SWAP24_LO(pkt->pkt_cmd_fhdr.d_id);
	scsi_cmd = (uint8_t *)pkt->pkt_cmd;
	scsi_opcode = scsi_cmd[12];
	data_rx = 0;

	/* Sync data in data buffer only on FC_PKT_FCP_READ */
	if (pkt->pkt_datalen && (pkt->pkt_tran_type == FC_PKT_FCP_READ)) {
		EMLXS_MPDATA_SYNC(pkt->pkt_data_dma, 0, pkt->pkt_datalen,
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
#endif /* TEST_SUPPORT */
	}

	/* Process the pkt */
	mutex_enter(&sbp->mtx);

	/* Check for immediate return */
	if ((iostat == IOSTAT_SUCCESS) &&
	    (pkt->pkt_comp) &&
	    !(sbp->pkt_flags &
	    (PACKET_ULP_OWNED | PACKET_COMPLETED |
	    PACKET_IN_COMPLETION | PACKET_IN_TXQ | PACKET_IN_CHIPQ |
	    PACKET_IN_DONEQ | PACKET_IN_TIMEOUT | PACKET_IN_FLUSH |
	    PACKET_IN_ABORT | PACKET_POLLED))) {
		HBASTATS.FcpGood++;

		sbp->pkt_flags |=
		    (PACKET_STATE_VALID | PACKET_IN_COMPLETION |
		    PACKET_COMPLETED | PACKET_ULP_OWNED);
		mutex_exit(&sbp->mtx);

#if (EMLXS_MODREVX == EMLXS_MODREV2X)
		emlxs_unswap_pkt(sbp);
#endif /* EMLXS_MODREV2X */

#ifdef FMA_SUPPORT
		emlxs_check_dma(hba, sbp);
#endif  /* FMA_SUPPORT */

		cp->ulpCmplCmd++;
		(*pkt->pkt_comp) (pkt);

#ifdef FMA_SUPPORT
		if (hba->flag & FC_DMA_CHECK_ERROR) {
			emlxs_thread_spawn(hba, emlxs_restart_thread,
			    NULL, NULL);
		}
#endif  /* FMA_SUPPORT */

		return;
	}

	/*
	 * A response is only placed in the resp buffer if IOSTAT_FCP_RSP_ERROR
	 * is reported.
	 */

	/* Check if a response buffer was not provided */
	if ((iostat != IOSTAT_FCP_RSP_ERROR) || (pkt->pkt_rsplen == 0)) {
		goto done;
	}

	EMLXS_MPDATA_SYNC(pkt->pkt_resp_dma, 0, pkt->pkt_rsplen,
	    DDI_DMA_SYNC_FORKERNEL);

	/* Get the response buffer pointer */
	rsp = (fcp_rsp_t *)pkt->pkt_resp;

	/* Validate the response payload */
	if (!rsp->fcp_u.fcp_status.resid_under &&
	    !rsp->fcp_u.fcp_status.resid_over) {
		rsp->fcp_resid = 0;
	}

	if (!rsp->fcp_u.fcp_status.rsp_len_set) {
		rsp->fcp_response_len = 0;
	}

	if (!rsp->fcp_u.fcp_status.sense_len_set) {
		rsp->fcp_sense_len = 0;
	}

	length = sizeof (fcp_rsp_t) + LE_SWAP32(rsp->fcp_response_len) +
	    LE_SWAP32(rsp->fcp_sense_len);

	if (length > pkt->pkt_rsplen) {
		iostat = IOSTAT_RSP_INVALID;
		pkt->pkt_data_resid = pkt->pkt_datalen;
		goto done;
	}

	/* Set the valid response flag */
	sbp->pkt_flags |= PACKET_FCP_RSP_VALID;

	scsi_status = rsp->fcp_u.fcp_status.scsi_status;

#ifdef SAN_DIAG_SUPPORT
	ndlp = (NODELIST *)iocbq->node;
	if (scsi_status == SCSI_STAT_QUE_FULL) {
		emlxs_log_sd_scsi_event(port, SD_SCSI_SUBCATEGORY_QFULL,
		    (HBA_WWN *)&ndlp->nlp_portname, sbp->lun);
	} else if (scsi_status == SCSI_STAT_BUSY) {
		emlxs_log_sd_scsi_event(port,
		    SD_SCSI_SUBCATEGORY_DEVBSY,
		    (HBA_WWN *)&ndlp->nlp_portname, sbp->lun);
	}
#endif

	/*
	 * Convert a task abort to a check condition with no data
	 * transferred. We saw a data corruption when Solaris received
	 * a Task Abort from a tape.
	 */

	if (scsi_status == SCSI_STAT_TASK_ABORT) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_fcp_completion_error_msg,
		    "Task Abort. "
		    "Fixed. did=0x%06x sbp=%p cmd=%02x dl=%d",
		    did, sbp, scsi_opcode, pkt->pkt_datalen);

		rsp->fcp_u.fcp_status.scsi_status =
		    SCSI_STAT_CHECK_COND;
		rsp->fcp_u.fcp_status.rsp_len_set = 0;
		rsp->fcp_u.fcp_status.sense_len_set = 0;
		rsp->fcp_u.fcp_status.resid_over = 0;

		if (pkt->pkt_datalen) {
			rsp->fcp_u.fcp_status.resid_under = 1;
			rsp->fcp_resid =
			    LE_SWAP32(pkt->pkt_datalen);
		} else {
			rsp->fcp_u.fcp_status.resid_under = 0;
			rsp->fcp_resid = 0;
		}

		scsi_status = SCSI_STAT_CHECK_COND;
	}

	/*
	 * We only need to check underrun if data could
	 * have been sent
	 */

	/* Always check underrun if status is good */
	if (scsi_status == SCSI_STAT_GOOD) {
		check_underrun = 1;
	}
	/* Check the sense codes if this is a check condition */
	else if (scsi_status == SCSI_STAT_CHECK_COND) {
		check_underrun = 1;

		/* Check if sense data was provided */
		if (LE_SWAP32(rsp->fcp_sense_len) >= 14) {
			sense = *((uint8_t *)rsp + 32 + 2);
			asc = *((uint8_t *)rsp + 32 + 12);
			ascq = *((uint8_t *)rsp + 32 + 13);
		}

#ifdef SAN_DIAG_SUPPORT
		emlxs_log_sd_scsi_check_event(port,
		    (HBA_WWN *)&ndlp->nlp_portname, sbp->lun,
		    scsi_opcode, sense, asc, ascq);
#endif
	}
	/* Status is not good and this is not a check condition */
	/* No data should have been sent */
	else {
		check_underrun = 0;
	}

	/* Initialize the resids */
	pkt->pkt_resp_resid = 0;
	pkt->pkt_data_resid = 0;

	/* Check if no data was to be transferred */
	if (pkt->pkt_datalen == 0) {
		goto done;
	}

	/* Get the residual underrun count reported by the SCSI reply */
	rsp_data_resid = (rsp->fcp_u.fcp_status.resid_under) ?
	    LE_SWAP32(rsp->fcp_resid) : 0;

	/* Set the pkt_data_resid to what the scsi response resid */
	pkt->pkt_data_resid = rsp_data_resid;

	/* Adjust the pkt_data_resid field if needed */
	if (pkt->pkt_tran_type == FC_PKT_FCP_READ) {
		/*
		 * Get the residual underrun count reported by
		 * our adapter
		 */
		pkt->pkt_data_resid = cmd->un.fcpi.fcpi_parm;

#ifdef SAN_DIAG_SUPPORT
		if ((rsp_data_resid == 0) && (pkt->pkt_data_resid)) {
			emlxs_log_sd_fc_rdchk_event(port,
			    (HBA_WWN *)&ndlp->nlp_portname, sbp->lun,
			    scsi_opcode, pkt->pkt_data_resid);
		}
#endif

		/* Get the actual amount of data transferred */
		data_rx = pkt->pkt_datalen - pkt->pkt_data_resid;

		/*
		 * If the residual being reported by the adapter is
		 * greater than the residual being reported in the
		 * reply, then we have a true underrun.
		 */
		if (check_underrun && (pkt->pkt_data_resid > rsp_data_resid)) {
			switch (scsi_opcode) {
			case SCSI_INQUIRY:
				scsi_dl = scsi_cmd[16];
				break;

			case SCSI_RX_DIAG:
				scsi_dl =
				    (scsi_cmd[15] * 0x100) +
				    scsi_cmd[16];
				break;

			default:
				scsi_dl = pkt->pkt_datalen;
			}

#ifdef FCP_UNDERRUN_PATCH1
if (cfg[CFG_ENABLE_PATCH].current & FCP_UNDERRUN_PATCH1) {
			/*
			 * If status is not good and no data was
			 * actually transferred, then we must fix
			 * the issue
			 */
			if ((scsi_status != SCSI_STAT_GOOD) && (data_rx == 0)) {
				fix_it = 1;

				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_fcp_completion_error_msg,
				    "Underrun(1). Fixed. "
				    "did=0x%06x sbp=%p cmd=%02x "
				    "dl=%d,%d rx=%d rsp=%d",
				    did, sbp, scsi_opcode,
				    pkt->pkt_datalen, scsi_dl,
				    (pkt->pkt_datalen -
				    pkt->pkt_data_resid),
				    rsp_data_resid);

			}
}
#endif /* FCP_UNDERRUN_PATCH1 */


#ifdef FCP_UNDERRUN_PATCH2
if (cfg[CFG_ENABLE_PATCH].current & FCP_UNDERRUN_PATCH2) {
			if (scsi_status == SCSI_STAT_GOOD) {
				emlxs_msg_t	*msg;

				msg = &emlxs_fcp_completion_error_msg;
				/*
				 * If status is good and this is an
				 * inquiry request and the amount of
				 * data
				 */
				/*
				 * requested <= data received, then we
				 * must fix the issue.
				 */

				if ((scsi_opcode == SCSI_INQUIRY) &&
				    (pkt->pkt_datalen >= data_rx) &&
				    (scsi_dl <= data_rx)) {
					fix_it = 1;

					EMLXS_MSGF(EMLXS_CONTEXT, msg,
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
				 * data requested >= 128 bytes, but
				 * only 128 bytes were received,
				 * then we must fix the issue.
				 */
				else if ((scsi_opcode == SCSI_INQUIRY) &&
				    (pkt->pkt_datalen >= 128) &&
				    (scsi_dl >= 128) && (data_rx == 128)) {
					fix_it = 1;

					EMLXS_MSGF(EMLXS_CONTEXT, msg,
					    "Underrun(3). Fixed. "
					    "did=0x%06x sbp=%p "
					    "cmd=%02x dl=%d,%d "
					    "rx=%d rsp=%d",
					    did, sbp, scsi_opcode,
					    pkt->pkt_datalen, scsi_dl,
					    data_rx, rsp_data_resid);

				}
			}
}
#endif /* FCP_UNDERRUN_PATCH2 */

			/*
			 * Check if SCSI response payload should be
			 * fixed or if a DATA_UNDERRUN should be
			 * reported
			 */
			if (fix_it) {
				/*
				 * Fix the SCSI response payload itself
				 */
				rsp->fcp_u.fcp_status.resid_under = 1;
				rsp->fcp_resid =
				    LE_SWAP32(pkt->pkt_data_resid);
			} else {
				/*
				 * Change the status from
				 * IOSTAT_FCP_RSP_ERROR to
				 * IOSTAT_DATA_UNDERRUN
				 */
				iostat = IOSTAT_DATA_UNDERRUN;
				pkt->pkt_data_resid =
				    pkt->pkt_datalen;
			}
		}

		/*
		 * If the residual being reported by the adapter is
		 * less than the residual being reported in the reply,
		 * then we have a true overrun. Since we don't know
		 * where the extra data came from or went to then we
		 * cannot trust anything we received
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

	} else if ((hba->sli_mode == EMLXS_HBA_SLI4_MODE) &&
	    (pkt->pkt_tran_type == FC_PKT_FCP_WRITE)) {
		/*
		 * Get the residual underrun count reported by
		 * our adapter
		 */
		pkt->pkt_data_resid = cmd->un.fcpi.fcpi_parm;

#ifdef SAN_DIAG_SUPPORT
		if ((rsp_data_resid == 0) && (pkt->pkt_data_resid)) {
			emlxs_log_sd_fc_rdchk_event(port,
			    (HBA_WWN *)&ndlp->nlp_portname, sbp->lun,
			    scsi_opcode, pkt->pkt_data_resid);
		}
#endif /* SAN_DIAG_SUPPORT */

		/* Get the actual amount of data transferred */
		data_rx = pkt->pkt_datalen - pkt->pkt_data_resid;

		/*
		 * If the residual being reported by the adapter is
		 * greater than the residual being reported in the
		 * reply, then we have a true underrun.
		 */
		if (check_underrun && (pkt->pkt_data_resid > rsp_data_resid)) {

			scsi_dl = pkt->pkt_datalen;

#ifdef FCP_UNDERRUN_PATCH1
if (cfg[CFG_ENABLE_PATCH].current & FCP_UNDERRUN_PATCH1) {
			/*
			 * If status is not good and no data was
			 * actually transferred, then we must fix
			 * the issue
			 */
			if ((scsi_status != SCSI_STAT_GOOD) && (data_rx == 0)) {
				fix_it = 1;

				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_fcp_completion_error_msg,
				    "Underrun(1). Fixed. "
				    "did=0x%06x sbp=%p cmd=%02x "
				    "dl=%d,%d rx=%d rsp=%d",
				    did, sbp, scsi_opcode,
				    pkt->pkt_datalen, scsi_dl,
				    (pkt->pkt_datalen -
				    pkt->pkt_data_resid),
				    rsp_data_resid);

			}
}
#endif /* FCP_UNDERRUN_PATCH1 */

			/*
			 * Check if SCSI response payload should be
			 * fixed or if a DATA_UNDERRUN should be
			 * reported
			 */
			if (fix_it) {
				/*
				 * Fix the SCSI response payload itself
				 */
				rsp->fcp_u.fcp_status.resid_under = 1;
				rsp->fcp_resid =
				    LE_SWAP32(pkt->pkt_data_resid);
			} else {
				/*
				 * Change the status from
				 * IOSTAT_FCP_RSP_ERROR to
				 * IOSTAT_DATA_UNDERRUN
				 */
				iostat = IOSTAT_DATA_UNDERRUN;
				pkt->pkt_data_resid =
				    pkt->pkt_datalen;
			}
		}

		/*
		 * If the residual being reported by the adapter is
		 * less than the residual being reported in the reply,
		 * then we have a true overrun. Since we don't know
		 * where the extra data came from or went to then we
		 * cannot trust anything we received
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
	}

done:

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
		    "Remote Stop. did=0x%06x sbp=%p cmd=%02x", did, sbp,
		    scsi_opcode);
		break;

	case IOSTAT_LOCAL_REJECT:
		localstat = cmd->un.grsp.perr.statLocalError;

		switch (localstat) {
		case IOERR_SEQUENCE_TIMEOUT:
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_fcp_completion_error_msg,
			    "Local reject. "
			    "%s did=0x%06x sbp=%p cmd=%02x tmo=%d ",
			    emlxs_error_xlate(localstat), did, sbp,
			    scsi_opcode, pkt->pkt_timeout);
			break;

		default:
			EMLXS_MSGF(EMLXS_CONTEXT,
			    &emlxs_fcp_completion_error_msg,
			    "Local reject. %s 0x%06x %p %02x (%x)(%x)",
			    emlxs_error_xlate(localstat), did, sbp,
			    scsi_opcode, (uint16_t)cmd->ULPIOTAG,
			    (uint16_t)cmd->ULPCONTEXT);
		}

		break;

	case IOSTAT_NPORT_RJT:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcp_completion_error_msg,
		    "Nport reject. did=0x%06x sbp=%p cmd=%02x", did, sbp,
		    scsi_opcode);
		break;

	case IOSTAT_FABRIC_RJT:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcp_completion_error_msg,
		    "Fabric reject. did=0x%06x sbp=%p cmd=%02x", did, sbp,
		    scsi_opcode);
		break;

	case IOSTAT_NPORT_BSY:
#ifdef SAN_DIAG_SUPPORT
		ndlp = (NODELIST *)iocbq->node;
		emlxs_log_sd_fc_bsy_event(port, (HBA_WWN *)&ndlp->nlp_portname);
#endif

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcp_completion_error_msg,
		    "Nport busy. did=0x%06x sbp=%p cmd=%02x", did, sbp,
		    scsi_opcode);
		break;

	case IOSTAT_FABRIC_BSY:
#ifdef SAN_DIAG_SUPPORT
		ndlp = (NODELIST *)iocbq->node;
		emlxs_log_sd_fc_bsy_event(port, NULL);
#endif

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcp_completion_error_msg,
		    "Fabric busy. did=0x%06x sbp=%p cmd=%02x", did, sbp,
		    scsi_opcode);
		break;

	case IOSTAT_INTERMED_RSP:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcp_completion_error_msg,
		    "Intermediate response. did=0x%06x sbp=%p cmd=%02x", did,
		    sbp, scsi_opcode);
		break;

	case IOSTAT_LS_RJT:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcp_completion_error_msg,
		    "LS Reject. did=0x%06x sbp=%p cmd=%02x", did, sbp,
		    scsi_opcode);
		break;

	case IOSTAT_DATA_UNDERRUN:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcp_completion_error_msg,
		    "Underrun. did=0x%06x sbp=%p cmd=%02x "
		    "dl=%d,%d rx=%d rsp=%d (%02x,%02x,%02x,%02x)",
		    did, sbp, scsi_opcode, pkt->pkt_datalen, scsi_dl, data_rx,
		    rsp_data_resid, scsi_status, sense, asc, ascq);
		break;

	case IOSTAT_DATA_OVERRUN:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcp_completion_error_msg,
		    "Overrun. did=0x%06x sbp=%p cmd=%02x "
		    "dl=%d,%d rx=%d rsp=%d (%02x,%02x,%02x,%02x)",
		    did, sbp, scsi_opcode, pkt->pkt_datalen, scsi_dl, data_rx,
		    rsp_data_resid, scsi_status, sense, asc, ascq);
		break;

	case IOSTAT_RSP_INVALID:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcp_completion_error_msg,
		    "Rsp Invalid. did=0x%06x sbp=%p cmd=%02x dl=%d rl=%d"
		    "(%d, %d, %d)",
		    did, sbp, scsi_opcode, pkt->pkt_datalen, pkt->pkt_rsplen,
		    LE_SWAP32(rsp->fcp_resid),
		    LE_SWAP32(rsp->fcp_sense_len),
		    LE_SWAP32(rsp->fcp_response_len));
		break;

	default:
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_fcp_completion_error_msg,
		    "Unknown status=%x reason=%x did=0x%06x sbp=%p cmd=%02x",
		    iostat, cmd->un.grsp.perr.statLocalError, did, sbp,
		    scsi_opcode);
		break;
	}

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
/* SLI3 */
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

	if (rp->ringno == hba->channel_els) {
		seg = MEM_BUF;
		size = MEM_ELSBUF_SIZE;
	} else if (rp->ringno == hba->channel_ip) {
		seg = MEM_IPBUF;
		size = MEM_IPBUF_SIZE;
	} else if (rp->ringno == hba->channel_ct) {
		seg = MEM_CTBUF;
		size = MEM_CTBUF_SIZE;
	}
#ifdef SFCT_SUPPORT
	else if (rp->ringno == hba->CHANNEL_FCT) {
		seg = MEM_FCTBUF;
		size = MEM_FCTBUF_SIZE;
	}
#endif /* SFCT_SUPPORT */
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

		iocbq->channel = (void *)&hba->chan[rp->ringno];
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
			if ((mp = (MATCHMAP *)emlxs_mem_get(hba, seg))
			    == 0) {
				icmd->ULPBDECOUNT = i;
				for (j = 0; j < i; j++) {
					mp = EMLXS_GET_VADDR(hba, rp, icmd);
					if (mp) {
						emlxs_mem_put(hba, seg,
						    (void *)mp);
					}
				}

				rp->fc_missbufcnt = cnt + i;

				emlxs_mem_put(hba, MEM_IOCB, (void *)iocbq);

				return (cnt + i);
			}

			/*
			 * map that page and save the address pair for lookup
			 * later
			 */
			emlxs_mem_map_vaddr(hba,
			    rp,
			    mp,
			    (uint32_t *)&icmd->un.cont64[i].addrHigh,
			    (uint32_t *)&icmd->un.cont64[i].addrLow);

			icmd->un.cont64[i].tus.f.bdeSize = size;
			icmd->ULPCOMMAND = CMD_QUE_RING_BUF64_CN;

			/*
			 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
			 *    "UB Post: ring=%d addr=%08x%08x size=%d",
			 *    rp->ringno, icmd->un.cont64[i].addrHigh,
			 *    icmd->un.cont64[i].addrLow, size);
			 */

			cnt--;
		}

		icmd->ULPIOTAG = tag;
		icmd->ULPBDECOUNT = i;
		icmd->ULPLE = 1;
		icmd->ULPOWNER = OWN_CHIP;
		/* used for delimiter between commands */
		iocbq->bp = (void *)mp;

		EMLXS_SLI_ISSUE_IOCB_CMD(hba, &hba->chan[rp->ringno], iocbq);
	}

	rp->fc_missbufcnt = 0;

	return (0);

} /* emlxs_post_buffer() */


static void
emlxs_fcp_tag_nodes(emlxs_port_t *port)
{
	NODELIST *nlp;
	int i;

	/* We will process all nodes with this tag later */
	rw_enter(&port->node_rwlock, RW_READER);
	for (i = 0; i < EMLXS_NUM_HASH_QUES; i++) {
		nlp = port->node_table[i];
		while (nlp != NULL) {
			nlp->nlp_tag = 1;
			nlp = nlp->nlp_list_next;
		}
	}
	rw_exit(&port->node_rwlock);
}


static NODELIST *
emlxs_find_tagged_node(emlxs_port_t *port)
{
	NODELIST *nlp;
	NODELIST *tagged;
	int i;

	/* Find first node */
	rw_enter(&port->node_rwlock, RW_READER);
	tagged = 0;
	for (i = 0; i < EMLXS_NUM_HASH_QUES; i++) {
		nlp = port->node_table[i];
		while (nlp != NULL) {
			if (!nlp->nlp_tag) {
				nlp = nlp->nlp_list_next;
				continue;
			}
			nlp->nlp_tag = 0;

			if (nlp->nlp_Rpi == FABRIC_RPI) {
				nlp = nlp->nlp_list_next;
				continue;
			}
			tagged = nlp;
			break;
		}
		if (tagged) {
			break;
		}
	}
	rw_exit(&port->node_rwlock);
	return (tagged);
}


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
	uint32_t clear_all;
	uint8_t format;

	/* Target mode only uses this routine for linkdowns */
	if ((port->mode == MODE_TARGET) && (scope != 0xffffffff) &&
	    (scope != 0xfeffffff) && (scope != 0xfdffffff)) {
		return (0);
	}

	cfg = &CFG;
	aid = (fc_affected_id_t *)&scope;
	linkdown = 0;
	vlinkdown = 0;
	unreg_vpi = 0;
	update = 0;
	clear_all = 0;

	if (!(port->flag & EMLXS_PORT_BOUND)) {
		return (0);
	}

	format = aid->aff_format;

	switch (format) {
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
#endif /* DHCHAP_SUPPORT */

	case 0xff:	/* link is down */
		mask = 0x00000000;
		linkdown = 1;
		break;

	case 0xfd:	/* New fabric */
	default:
		mask = 0x00000000;
		linkdown = 1;
		clear_all = 1;
		break;
	}

	aff_d_id = aid->aff_d_id & mask;


	/*
	 * If link is down then this is a hard shutdown and flush
	 * If link not down then this is a soft shutdown and flush
	 * (e.g. RSCN)
	 */
	if (linkdown) {
		mutex_enter(&EMLXS_PORT_LOCK);

		port->flag &= EMLXS_PORT_LINKDOWN_MASK;

		if (port->ulp_statec != FC_STATE_OFFLINE) {
			port->ulp_statec = FC_STATE_OFFLINE;

			port->prev_did = port->did;
			port->did = 0;
			port->rdid = 0;

			bcopy(&port->fabric_sparam, &port->prev_fabric_sparam,
			    sizeof (SERV_PARM));
			bzero(&port->fabric_sparam, sizeof (SERV_PARM));

			update = 1;
		}

		mutex_exit(&EMLXS_PORT_LOCK);

		emlxs_timer_cancel_clean_address(port);

		/* Tell ULP about it */
		if (update) {
			if (port->flag & EMLXS_PORT_BOUND) {
				if (port->vpi == 0) {
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_link_down_msg, NULL);
				}

				if (port->mode == MODE_INITIATOR) {
					emlxs_fca_link_down(port);
				}
#ifdef SFCT_SUPPORT
				else if (port->mode == MODE_TARGET) {
					emlxs_fct_link_down(port);
				}
#endif /* SFCT_SUPPORT */

			} else {
				if (port->vpi == 0) {
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_link_down_msg, "*");
				}
			}


		}

		unreg_vpi = 1;

#ifdef DHCHAP_SUPPORT
		/* Stop authentication with all nodes */
		emlxs_dhc_auth_stop(port, NULL);
#endif /* DHCHAP_SUPPORT */

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

		emlxs_timer_cancel_clean_address(port);

		/* Tell ULP about it */
		if (update) {
			if (port->flag & EMLXS_PORT_BOUND) {
				if (port->vpi == 0) {
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_link_down_msg,
					    "Switch authentication failed.");
				}

				if (port->mode == MODE_INITIATOR) {
					emlxs_fca_link_down(port);
				}
#ifdef SFCT_SUPPORT
				else if (port->mode == MODE_TARGET) {
					emlxs_fct_link_down(port);
				}
#endif /* SFCT_SUPPORT */
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
#endif /* DHCHAP_SUPPORT */
	else {
		emlxs_timer_cancel_clean_address(port);
	}

	if (port->mode == MODE_TARGET) {
		if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
			/* Set the node tags */
			emlxs_fcp_tag_nodes(port);
			unreg_vpi = 0;
			while ((nlp = emlxs_find_tagged_node(port))) {
				(void) emlxs_rpi_pause_notify(port,
				    nlp->rpip);
				/*
				 * In port_online we need to resume
				 * these RPIs before we can use them.
				 */
			}
		}
		goto done;
	}

	/* Set the node tags */
	emlxs_fcp_tag_nodes(port);

	if (!clear_all && (hba->flag & FC_ONLINE_MODE)) {
		adisc_support = cfg[CFG_ADISC_SUPPORT].current;
	} else {
		adisc_support = 0;
	}

	/* Check ADISC support level */
	switch (adisc_support) {
	case 0:	/* No support - Flush all IO to all matching nodes */

		for (;;) {
			/*
			 * We need to hold the locks this way because
			 * EMLXS_SLI_UNREG_NODE and the flush routines enter the
			 * same locks. Also, when we release the lock the list
			 * can change out from under us.
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
						} else { /* Must be an RCSN */

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
				(void) EMLXS_SLI_UNREG_NODE(port, nlp,
				    NULL, NULL, NULL);
			} else if (action == 2) {
				EMLXS_SET_DFC_STATE(nlp, NODE_LIMBO);

#ifdef DHCHAP_SUPPORT
				emlxs_dhc_auth_stop(port, nlp);
#endif /* DHCHAP_SUPPORT */

				/*
				 * Close the node for any further normal IO
				 * A PLOGI with reopen the node
				 */
				emlxs_node_close(port, nlp,
				    hba->channel_fcp, 60);
				emlxs_node_close(port, nlp,
				    hba->channel_ip, 60);

				/* Flush tx queue */
				(void) emlxs_tx_node_flush(port, nlp, 0, 0, 0);

				/* Flush chip queue */
				(void) emlxs_chipq_node_flush(port, 0, nlp, 0);
			}

		}

		break;

	case 1:	/* Partial support - Flush IO for non-FCP2 matching nodes */

		for (;;) {

			/*
			 * We need to hold the locks this way because
			 * EMLXS_SLI_UNREG_NODE and the flush routines enter the
			 * same locks. Also, when we release the lock the list
			 * can change out from under us.
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
					 * Check for special FCP2 target device
					 * that matches our mask
					 */
					if ((nlp->nlp_fcp_info &
					    NLP_FCP_TGT_DEVICE) &&
					    (nlp-> nlp_fcp_info &
					    NLP_FCP_2_DEVICE) &&
					    (nlp->nlp_DID & mask) ==
					    aff_d_id) {
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
				(void) EMLXS_SLI_UNREG_NODE(port, nlp,
				    NULL, NULL, NULL);
			} else if (action == 2) {
				EMLXS_SET_DFC_STATE(nlp, NODE_LIMBO);

#ifdef DHCHAP_SUPPORT
				emlxs_dhc_auth_stop(port, nlp);
#endif /* DHCHAP_SUPPORT */

				/*
				 * Close the node for any further normal IO
				 * A PLOGI with reopen the node
				 */
				emlxs_node_close(port, nlp,
				    hba->channel_fcp, 60);
				emlxs_node_close(port, nlp,
				    hba->channel_ip, 60);

				/* Flush tx queue */
				(void) emlxs_tx_node_flush(port, nlp, 0, 0, 0);

				/* Flush chip queue */
				(void) emlxs_chipq_node_flush(port, 0, nlp, 0);

			} else if (action == 3) {	/* FCP2 devices */
				EMLXS_SET_DFC_STATE(nlp, NODE_LIMBO);

				unreg_vpi = 0;

				if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
					(void) emlxs_rpi_pause_notify(port,
					    nlp->rpip);
				}

#ifdef DHCHAP_SUPPORT
				emlxs_dhc_auth_stop(port, nlp);
#endif /* DHCHAP_SUPPORT */

				/*
				 * Close the node for any further normal IO
				 * An ADISC or a PLOGI with reopen the node
				 */
				emlxs_node_close(port, nlp,
				    hba->channel_fcp, -1);
				emlxs_node_close(port, nlp, hba->channel_ip,
				    ((linkdown) ? 0 : 60));

				/* Flush tx queues except for FCP ring */
				(void) emlxs_tx_node_flush(port, nlp,
				    &hba->chan[hba->channel_ct], 0, 0);
				(void) emlxs_tx_node_flush(port, nlp,
				    &hba->chan[hba->channel_els], 0, 0);
				(void) emlxs_tx_node_flush(port, nlp,
				    &hba->chan[hba->channel_ip], 0, 0);

				/* Flush chip queues except for FCP ring */
				(void) emlxs_chipq_node_flush(port,
				    &hba->chan[hba->channel_ct], nlp, 0);
				(void) emlxs_chipq_node_flush(port,
				    &hba->chan[hba->channel_els], nlp, 0);
				(void) emlxs_chipq_node_flush(port,
				    &hba->chan[hba->channel_ip], nlp, 0);
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
			 * EMLXS_SLI_UNREG_NODE and the flush routines enter the
			 * same locks. Also, when we release the lock the list
			 * can change out from under us.
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
					if ((nlp-> nlp_fcp_info &
					    NLP_FCP_TGT_DEVICE) &&
					    (nlp->nlp_DID & mask) ==
					    aff_d_id) {
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
				(void) EMLXS_SLI_UNREG_NODE(port, nlp,
				    NULL, NULL, NULL);
			} else if (action == 2) {
				EMLXS_SET_DFC_STATE(nlp, NODE_LIMBO);

				/*
				 * Close the node for any further normal IO
				 * A PLOGI with reopen the node
				 */
				emlxs_node_close(port, nlp,
				    hba->channel_fcp, 60);
				emlxs_node_close(port, nlp,
				    hba->channel_ip, 60);

				/* Flush tx queue */
				(void) emlxs_tx_node_flush(port, nlp, 0, 0, 0);

				/* Flush chip queue */
				(void) emlxs_chipq_node_flush(port, 0, nlp, 0);

			} else if (action == 3) {	/* FCP2 devices */
				EMLXS_SET_DFC_STATE(nlp, NODE_LIMBO);

				unreg_vpi = 0;

				if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
					(void) emlxs_rpi_pause_notify(port,
					    nlp->rpip);
				}

				/*
				 * Close the node for any further normal IO
				 * An ADISC or a PLOGI with reopen the node
				 */
				emlxs_node_close(port, nlp,
				    hba->channel_fcp, -1);
				emlxs_node_close(port, nlp, hba->channel_ip,
				    ((linkdown) ? 0 : 60));

				/* Flush tx queues except for FCP ring */
				(void) emlxs_tx_node_flush(port, nlp,
				    &hba->chan[hba->channel_ct], 0, 0);
				(void) emlxs_tx_node_flush(port, nlp,
				    &hba->chan[hba->channel_els], 0, 0);
				(void) emlxs_tx_node_flush(port, nlp,
				    &hba->chan[hba->channel_ip], 0, 0);

				/* Flush chip queues except for FCP ring */
				(void) emlxs_chipq_node_flush(port,
				    &hba->chan[hba->channel_ct], nlp, 0);
				(void) emlxs_chipq_node_flush(port,
				    &hba->chan[hba->channel_els], nlp, 0);
				(void) emlxs_chipq_node_flush(port,
				    &hba->chan[hba->channel_ip], nlp, 0);
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
	NODELIST *nlp;
	uint32_t state;
	uint32_t update;
	uint32_t npiv_linkup;
	char topology[32];
	char linkspeed[32];
	char mode[32];

	/*
	 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_link_up_msg,
	 *    "linkup_callback. vpi=%d fc_flag=%x", vport->vpi, hba->flag);
	 */

	if ((vport->vpi > 0) &&
	    (!(hba->flag & FC_NPIV_ENABLED) ||
	    !(hba->flag & FC_NPIV_SUPPORTED))) {
		return;
	}

	if (!(vport->flag & EMLXS_PORT_BOUND) ||
	    !(vport->flag & EMLXS_PORT_ENABLED)) {
		return;
	}

	/* Check for mode */
	if (port->mode == MODE_TARGET) {
		(void) strlcpy(mode, ", target", sizeof (mode));

		if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
			/* Set the node tags */
			emlxs_fcp_tag_nodes(vport);
			while ((nlp = emlxs_find_tagged_node(vport))) {
				/* The RPI was paused in port_offline */
				(void) emlxs_rpi_resume_notify(vport,
				    nlp->rpip, 0);
			}
		}
	} else if (port->mode == MODE_INITIATOR) {
		(void) strlcpy(mode, ", initiator", sizeof (mode));
	} else {
		(void) strlcpy(mode, "unknown", sizeof (mode));
	}
	mutex_enter(&EMLXS_PORT_LOCK);

	/* Check for loop topology */
	if (hba->topology == TOPOLOGY_LOOP) {
		state = FC_STATE_LOOP;
		(void) strlcpy(topology, ", loop", sizeof (topology));
	} else {
		state = FC_STATE_ONLINE;
		(void) strlcpy(topology, ", fabric", sizeof (topology));
	}

	/* Set the link speed */
	switch (hba->linkspeed) {
	case 0:
		(void) strlcpy(linkspeed, "Gb", sizeof (linkspeed));
		state |= FC_STATE_1GBIT_SPEED;
		break;

	case LA_1GHZ_LINK:
		(void) strlcpy(linkspeed, "1Gb", sizeof (linkspeed));
		state |= FC_STATE_1GBIT_SPEED;
		break;
	case LA_2GHZ_LINK:
		(void) strlcpy(linkspeed, "2Gb", sizeof (linkspeed));
		state |= FC_STATE_2GBIT_SPEED;
		break;
	case LA_4GHZ_LINK:
		(void) strlcpy(linkspeed, "4Gb", sizeof (linkspeed));
		state |= FC_STATE_4GBIT_SPEED;
		break;
	case LA_8GHZ_LINK:
		(void) strlcpy(linkspeed, "8Gb", sizeof (linkspeed));
		state |= FC_STATE_8GBIT_SPEED;
		break;
	case LA_10GHZ_LINK:
		(void) strlcpy(linkspeed, "10Gb", sizeof (linkspeed));
		state |= FC_STATE_10GBIT_SPEED;
		break;
	case LA_16GHZ_LINK:
		(void) strlcpy(linkspeed, "16Gb", sizeof (linkspeed));
		state |= FC_STATE_16GBIT_SPEED;
		break;
	default:
		(void) snprintf(linkspeed, sizeof (linkspeed), "unknown(0x%x)",
		    hba->linkspeed);
		break;
	}

	npiv_linkup = 0;
	update = 0;

	if ((hba->state >= FC_LINK_UP) &&
	    !(hba->flag & FC_LOOPBACK_MODE) && (vport->ulp_statec != state)) {
		update = 1;
		vport->ulp_statec = state;

		if ((vport->vpi > 0) && !(hba->flag & FC_NPIV_LINKUP)) {
			hba->flag |= FC_NPIV_LINKUP;
			npiv_linkup = 1;
		}
	}

	mutex_exit(&EMLXS_PORT_LOCK);

	if (update) {
		if (vport->flag & EMLXS_PORT_BOUND) {
			if (vport->vpi == 0) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_link_up_msg,
				    "%s%s%s", linkspeed, topology, mode);

			} else if (npiv_linkup) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_npiv_link_up_msg, "%s%s%s",
				    linkspeed, topology, mode);
			}

			if (vport->mode == MODE_INITIATOR) {
				emlxs_fca_link_up(vport);
			}
#ifdef SFCT_SUPPORT
			else if (vport->mode == MODE_TARGET) {
				emlxs_fct_link_up(vport);
			}
#endif /* SFCT_SUPPORT */
		} else {
			if (vport->vpi == 0) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_link_up_msg,
				    "%s%s%s *", linkspeed, topology, mode);

			} else if (npiv_linkup) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_npiv_link_up_msg, "%s%s%s *",
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


/* SLI3 */
extern void
emlxs_linkdown(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	int i;
	uint32_t scope;

	mutex_enter(&EMLXS_PORT_LOCK);

	if (hba->state > FC_LINK_DOWN) {
		HBASTATS.LinkDown++;
		EMLXS_STATE_CHANGE_LOCKED(hba, FC_LINK_DOWN);
	}

	/* Set scope */
	scope = (hba->flag & FC_NEW_FABRIC)? 0xFDFFFFFF:0xFFFFFFFF;

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

		(void) emlxs_port_offline(port, scope);

	}

	emlxs_log_link_event(port);

	return;

} /* emlxs_linkdown() */


/* SLI3 */
extern void
emlxs_linkup(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	emlxs_config_t *cfg = &CFG;

	mutex_enter(&EMLXS_PORT_LOCK);

	/* Check for any mode changes */
	emlxs_mode_set(hba);

	HBASTATS.LinkUp++;
	EMLXS_STATE_CHANGE_LOCKED(hba, FC_LINK_UP);

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

		emlxs_log_link_event(port);

		return;
	}
#endif /* MENLO_SUPPORT */

	/* Set the linkup & discovery timers */
	hba->linkup_timer = hba->timer_tics + cfg[CFG_LINKUP_TIMEOUT].current;
	hba->discovery_timer =
	    hba->timer_tics + cfg[CFG_LINKUP_TIMEOUT].current +
	    cfg[CFG_DISC_TIMEOUT].current;

	mutex_exit(&EMLXS_PORT_LOCK);

	emlxs_log_link_event(port);

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
emlxs_reset_link(emlxs_hba_t *hba, uint32_t linkup, uint32_t wait)
{
	emlxs_port_t *port = &PPORT;
	emlxs_config_t *cfg;
	MAILBOXQ *mbq = NULL;
	MAILBOX *mb = NULL;
	int rval = 0;
	int tmo;
	int rc;

	/*
	 * Get a buffer to use for the mailbox command
	 */
	if ((mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX))
	    == NULL) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_link_reset_failed_msg,
		    "Unable to allocate mailbox buffer.");
		rval = 1;
		goto reset_link_fail;
	}

	if (linkup) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_link_reset_msg,
		    "Resetting link...");
	} else {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_link_reset_msg,
		    "Disabling link...");
	}

	mb = (MAILBOX *)mbq;

	/* Bring link down first */
	emlxs_mb_down_link(hba, mbq);

#define	MBXERR_LINK_DOWN	0x33

	if (wait) {
		wait = MBX_WAIT;
	} else {
		wait = MBX_NOWAIT;
	}
	rc =  EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, wait, 0);
	if ((rc != MBX_BUSY) && (rc != MBX_SUCCESS) &&
	    (rc != MBXERR_LINK_DOWN)) {
		rval = 1;
		goto reset_link_fail;
	}

	tmo = 120;
	do {
		delay(drv_usectohz(500000));
		tmo--;

		if (!tmo)   {
			rval = 1;

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_link_reset_msg,
			    "Linkdown timeout.");

			goto reset_link_fail;
		}
	} while ((hba->state >= FC_LINK_UP) && (hba->state != FC_ERROR));

	if (linkup) {
		/*
		 * Setup and issue mailbox INITIALIZE LINK command
		 */

		if (wait == MBX_NOWAIT) {
			if ((mbq = (MAILBOXQ *)emlxs_mem_get(hba, MEM_MBOX))
			    == NULL) {
				EMLXS_MSGF(EMLXS_CONTEXT,
				    &emlxs_link_reset_failed_msg,
				    "Unable to allocate mailbox buffer.");
				rval = 1;
				goto reset_link_fail;
			}
			mb = (MAILBOX *)mbq;
		} else {
			/* Reuse mbq from previous mbox */
			mb = (MAILBOX *)mbq;
		}
		cfg = &CFG;

		emlxs_mb_init_link(hba, mbq,
		    cfg[CFG_TOPOLOGY].current, cfg[CFG_LINK_SPEED].current);

		mb->un.varInitLnk.lipsr_AL_PA = 0;

		/* Clear the loopback mode */
		mutex_enter(&EMLXS_PORT_LOCK);
		hba->flag &= ~FC_LOOPBACK_MODE;
		hba->loopback_tics = 0;
		mutex_exit(&EMLXS_PORT_LOCK);

		rc =  EMLXS_SLI_ISSUE_MBOX_CMD(hba, mbq, wait, 0);
		if ((rc != MBX_BUSY) && (rc != MBX_SUCCESS)) {
			rval = 1;
			goto reset_link_fail;
		}

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_link_reset_msg, NULL);
	}

reset_link_fail:

	if ((wait == MBX_WAIT) && mbq) {
		emlxs_mem_put(hba, MEM_MBOX, (void *)mbq);
	}

	return (rval);
} /* emlxs_reset_link() */


extern int
emlxs_online(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	int32_t rval = 0;
	uint32_t i = 0;

	/* Make sure adapter is offline or exit trying (30 seconds) */
	while (i++ < 30) {
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

		BUSYWAIT_MS(1000);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_adapter_trans_msg,
	    "Going online...");

	if (rval = EMLXS_SLI_ONLINE(hba)) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_init_failed_msg, "status=%x",
		    rval);
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_offline_msg, NULL);

		/* Set FC_OFFLINE_MODE */
		mutex_enter(&EMLXS_PORT_LOCK);
		hba->flag |= FC_OFFLINE_MODE;
		hba->flag &= ~FC_ONLINING_MODE;
		mutex_exit(&EMLXS_PORT_LOCK);

		return (rval);
	}

	/* Start the timer */
	emlxs_timer_start(hba);

	/* Set FC_ONLINE_MODE */
	mutex_enter(&EMLXS_PORT_LOCK);
	hba->flag |= FC_ONLINE_MODE;
	hba->flag &= ~FC_ONLINING_MODE;
	mutex_exit(&EMLXS_PORT_LOCK);

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_online_msg, NULL);

#ifdef SFCT_SUPPORT
	if (port->flag & EMLXS_TGT_ENABLED) {
		(void) emlxs_fct_port_initialize(port);
	}
#endif /* SFCT_SUPPORT */

	return (rval);

} /* emlxs_online() */


extern int
emlxs_offline(emlxs_hba_t *hba, uint32_t reset_requested)
{
	emlxs_port_t *port = &PPORT;
	uint32_t i = 0;
	int rval = 1;

	/* Make sure adapter is online or exit trying (30 seconds) */
	while (i++ < 30) {
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

		BUSYWAIT_MS(1000);
	}

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_adapter_trans_msg,
	    "Going offline...");

	/* Declare link down */
	if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
		(void) emlxs_fcf_shutdown_notify(port, 1);
	} else {
		emlxs_linkdown(hba);
	}

#ifdef SFCT_SUPPORT
	if (port->flag & EMLXS_TGT_ENABLED) {
		(void) emlxs_fct_port_shutdown(port);
	}
#endif /* SFCT_SUPPORT */

	/* Check if adapter was shutdown */
	if (hba->flag & FC_HARDWARE_ERROR) {
		/*
		 * Force mailbox cleanup
		 * This will wake any sleeping or polling threads
		 */
		emlxs_mb_fini(hba, NULL, MBX_HARDWARE_ERROR);
	}

	/* Pause here for the IO to settle */
	delay(drv_usectohz(1000000));	/* 1 sec */

	/* Unregister all nodes */
	emlxs_ffcleanup(hba);

	if (hba->bus_type == SBUS_FC) {
		WRITE_SBUS_CSR_REG(hba, FC_SHS_REG(hba), 0x9A);
#ifdef FMA_SUPPORT
		/* Access handle validation */
		EMLXS_CHK_ACC_HANDLE(hba, hba->sli.sli3.sbus_csr_handle);
#endif  /* FMA_SUPPORT */
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

	/* Shutdown the adapter interface */
	EMLXS_SLI_OFFLINE(hba, reset_requested);

	mutex_enter(&EMLXS_PORT_LOCK);
	hba->flag |= FC_OFFLINE_MODE;
	hba->flag &= ~FC_OFFLINING_MODE;
	mutex_exit(&EMLXS_PORT_LOCK);

	rval = 0;

	EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_offline_msg, NULL);

done:

	return (rval);

} /* emlxs_offline() */



extern int
emlxs_power_down(emlxs_hba_t *hba)
{
#ifdef FMA_SUPPORT
	emlxs_port_t *port = &PPORT;
#endif  /* FMA_SUPPORT */
	int32_t rval = 0;

	if ((rval = emlxs_offline(hba, 0))) {
		return (rval);
	}
	EMLXS_SLI_HBA_RESET(hba, 1, 1, 0);


#ifdef FMA_SUPPORT
	if (emlxs_fm_check_acc_handle(hba, hba->pci_acc_handle)
	    != DDI_FM_OK) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_invalid_access_handle_msg, NULL);
		return (1);
	}
#endif  /* FMA_SUPPORT */

	return (0);

} /* End emlxs_power_down */


extern int
emlxs_power_up(emlxs_hba_t *hba)
{
#ifdef FMA_SUPPORT
	emlxs_port_t *port = &PPORT;
#endif  /* FMA_SUPPORT */
	int32_t rval = 0;


#ifdef FMA_SUPPORT
	if (emlxs_fm_check_acc_handle(hba, hba->pci_acc_handle)
	    != DDI_FM_OK) {
		EMLXS_MSGF(EMLXS_CONTEXT,
		    &emlxs_invalid_access_handle_msg, NULL);
		return (1);
	}
#endif  /* FMA_SUPPORT */

	/* Bring adapter online */
	if ((rval = emlxs_online(hba))) {
		if (hba->pci_cap_offset[PCI_CAP_ID_PM]) {
			/* Put chip in D3 state */
			(void) ddi_put8(hba->pci_acc_handle,
			    (uint8_t *)(hba->pci_addr +
			    hba->pci_cap_offset[PCI_CAP_ID_PM] +
			    PCI_PMCSR),
			    (uint8_t)PCI_PMCSR_D3HOT);
		}
		return (rval);
	}

	return (rval);

} /* emlxs_power_up() */


/*
 *
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
	uint32_t i;

	/* Disable all but the mailbox interrupt */
	EMLXS_SLI_DISABLE_INTR(hba, HC_MBINT_ENA);

	/* Make sure all port nodes are destroyed */
	for (i = 0; i < MAX_VPORTS; i++) {
		port = &VPORT(i);

		if (port->node_count) {
			(void) EMLXS_SLI_UNREG_NODE(port, 0, 0, 0, 0);
		}
	}

	/* Clear all interrupt enable conditions */
	EMLXS_SLI_DISABLE_INTR(hba, 0);

	return;

} /* emlxs_ffcleanup() */


extern uint16_t
emlxs_register_pkt(CHANNEL *cp, emlxs_buf_t *sbp)
{
	emlxs_hba_t *hba;
	emlxs_port_t *port;
	uint16_t iotag;
	uint32_t i;

	hba = cp->hba;

	mutex_enter(&EMLXS_FCTAB_LOCK);

	if (sbp->iotag != 0) {
		port = &PPORT;

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
		    "Pkt already registered! channel=%d iotag=%d sbp=%p",
		    sbp->channel, sbp->iotag, sbp);
	}

	iotag = 0;
	for (i = 0; i < hba->max_iotag; i++) {
		if (!hba->fc_iotag || hba->fc_iotag >= hba->max_iotag) {
			hba->fc_iotag = 1;
		}
		iotag = hba->fc_iotag++;

		if (hba->fc_table[iotag] == 0 ||
		    hba->fc_table[iotag] == STALE_PACKET) {
			hba->io_count++;
			hba->fc_table[iotag] = sbp;

			sbp->iotag = iotag;
			sbp->channel = cp;

			break;
		}
		iotag = 0;
	}

	mutex_exit(&EMLXS_FCTAB_LOCK);

	/*
	 * EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_detail_msg,
	 *    "register_pkt: channel=%d iotag=%d sbp=%p",
	 *    cp->channelno, iotag, sbp);
	 */

	return (iotag);

} /* emlxs_register_pkt() */



extern emlxs_buf_t *
emlxs_unregister_pkt(CHANNEL *cp, uint16_t iotag, uint32_t forced)
{
	emlxs_hba_t *hba;
	emlxs_buf_t *sbp;

	sbp = NULL;
	hba = cp->hba;

	/* Check the iotag range */
	if ((iotag == 0) || (iotag >= hba->max_iotag)) {
		return (NULL);
	}

	/* Remove the sbp from the table */
	mutex_enter(&EMLXS_FCTAB_LOCK);
	sbp = hba->fc_table[iotag];

	if (!sbp || (sbp == STALE_PACKET)) {
		mutex_exit(&EMLXS_FCTAB_LOCK);
		return (sbp);
	}

	hba->fc_table[iotag] = ((forced) ? STALE_PACKET : NULL);
	hba->io_count--;
	sbp->iotag = 0;

	mutex_exit(&EMLXS_FCTAB_LOCK);


	/* Clean up the sbp */
	mutex_enter(&sbp->mtx);

	if (sbp->pkt_flags & PACKET_IN_TXQ) {
		sbp->pkt_flags &= ~PACKET_IN_TXQ;
		hba->channel_tx_count--;
	}

	if (sbp->pkt_flags & PACKET_IN_CHIPQ) {
		sbp->pkt_flags &= ~PACKET_IN_CHIPQ;
	}

	if (sbp->bmp) {
		emlxs_mem_put(hba, MEM_BPL, (void *)sbp->bmp);
		sbp->bmp = 0;
	}

	mutex_exit(&sbp->mtx);

	return (sbp);

} /* emlxs_unregister_pkt() */



/* Flush all IO's to all nodes for a given IO Channel */
extern uint32_t
emlxs_tx_channel_flush(emlxs_hba_t *hba, CHANNEL *cp, emlxs_buf_t *fpkt)
{
	emlxs_port_t *port = &PPORT;
	emlxs_buf_t *sbp;
	IOCBQ *iocbq;
	IOCBQ *next;
	IOCB *iocb;
	uint32_t channelno;
	Q abort;
	NODELIST *ndlp;
	IOCB *icmd;
	MATCHMAP *mp;
	uint32_t i;
	uint8_t flag[MAX_CHANNEL];

	channelno = cp->channelno;
	bzero((void *)&abort, sizeof (Q));
	bzero((void *)flag, MAX_CHANNEL * sizeof (uint8_t));

	mutex_enter(&EMLXS_TX_CHANNEL_LOCK);

	/* While a node needs servicing */
	while (cp->nodeq.q_first) {
		ndlp = (NODELIST *) cp->nodeq.q_first;

		/* Check if priority queue is not empty */
		if (ndlp->nlp_ptx[channelno].q_first) {
			/* Transfer all iocb's to local queue */
			if (abort.q_first == 0) {
				abort.q_first =
				    ndlp->nlp_ptx[channelno].q_first;
			} else {
				((IOCBQ *)abort.q_last)->next =
				    (IOCBQ *)ndlp->nlp_ptx[channelno].q_first;
			}
			flag[channelno] = 1;

			abort.q_last = ndlp->nlp_ptx[channelno].q_last;
			abort.q_cnt += ndlp->nlp_ptx[channelno].q_cnt;
		}

		/* Check if tx queue is not empty */
		if (ndlp->nlp_tx[channelno].q_first) {
			/* Transfer all iocb's to local queue */
			if (abort.q_first == 0) {
				abort.q_first = ndlp->nlp_tx[channelno].q_first;
			} else {
				((IOCBQ *)abort.q_last)->next =
				    (IOCBQ *)ndlp->nlp_tx[channelno].q_first;
			}

			abort.q_last = ndlp->nlp_tx[channelno].q_last;
			abort.q_cnt += ndlp->nlp_tx[channelno].q_cnt;
		}

		/* Clear the queue pointers */
		ndlp->nlp_ptx[channelno].q_first = NULL;
		ndlp->nlp_ptx[channelno].q_last = NULL;
		ndlp->nlp_ptx[channelno].q_cnt = 0;

		ndlp->nlp_tx[channelno].q_first = NULL;
		ndlp->nlp_tx[channelno].q_last = NULL;
		ndlp->nlp_tx[channelno].q_cnt = 0;

		/* Remove node from service queue */

		/* If this is the last node on list */
		if (cp->nodeq.q_last == (void *)ndlp) {
			cp->nodeq.q_last = NULL;
			cp->nodeq.q_first = NULL;
			cp->nodeq.q_cnt = 0;
		} else {
			/* Remove node from head */
			cp->nodeq.q_first = ndlp->nlp_next[channelno];
			((NODELIST *)cp->nodeq.q_last)->nlp_next[channelno] =
			    cp->nodeq.q_first;
			cp->nodeq.q_cnt--;
		}

		/* Clear node */
		ndlp->nlp_next[channelno] = NULL;
	}

	/* First cleanup the iocb's while still holding the lock */
	iocbq = (IOCBQ *) abort.q_first;
	while (iocbq) {
		/* Free the IoTag and the bmp */
		iocb = &iocbq->iocb;

		if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
			sbp = iocbq->sbp;
			if (sbp) {
				emlxs_sli4_free_xri(port, sbp, sbp->xrip, 1);
			}
		} else {
			sbp = emlxs_unregister_pkt((CHANNEL *)iocbq->channel,
			    iocb->ULPIOTAG, 0);
		}

		if (sbp && (sbp != STALE_PACKET)) {
			mutex_enter(&sbp->mtx);

			sbp->pkt_flags |= PACKET_IN_FLUSH;
			/*
			 * If the fpkt is already set, then we will leave it
			 * alone. This ensures that this pkt is only accounted
			 * for on one fpkt->flush_count
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

	mutex_exit(&EMLXS_TX_CHANNEL_LOCK);

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
			    "tx: sbp=%p node=%p", sbp, sbp->node);

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

			/* SLI3 */
			if (icmd->ULPCOMMAND == CMD_QUE_RING_BUF64_CN ||
			    icmd->ULPCOMMAND == CMD_QUE_RING_BUF_CN ||
			    icmd->ULPCOMMAND == CMD_QUE_RING_LIST64_CN) {
				if ((hba->flag &
				    (FC_ONLINE_MODE | FC_ONLINING_MODE)) == 0) {
					/* HBA is detaching or offlining */
					if (icmd->ULPCOMMAND !=
					    CMD_QUE_RING_LIST64_CN) {
						void	*tmp;
						RING *rp;

						rp = &hba->sli.sli3.
						    ring[channelno];
						for (i = 0;
						    i < icmd->ULPBDECOUNT;
						    i++) {
							mp = EMLXS_GET_VADDR(
							    hba, rp, icmd);

							tmp = (void *)mp;
							if (mp) {
							emlxs_mem_put(
							    hba, MEM_BUF, tmp);
							}
						}
					}

					emlxs_mem_put(hba, MEM_IOCB,
					    (void *)iocbq);
				} else {
					/* repost the unsolicited buffer */
					EMLXS_SLI_ISSUE_IOCB_CMD(hba, cp,
					    iocbq);
				}
			} else if (icmd->ULPCOMMAND == CMD_CLOSE_XRI_CN ||
			    icmd->ULPCOMMAND == CMD_CLOSE_XRI_CX) {

				emlxs_tx_put(iocbq, 1);
			}
		}

		iocbq = next;

	}	/* end of while */

	/* Now trigger channel service */
	for (channelno = 0; channelno < hba->chan_count; channelno++) {
		if (!flag[channelno]) {
			continue;
		}

		EMLXS_SLI_ISSUE_IOCB_CMD(hba, &hba->chan[channelno], 0);
	}

	return (abort.q_cnt);

} /* emlxs_tx_channel_flush() */


/* Flush all IO's on all or a given ring for a given node */
extern uint32_t
emlxs_tx_node_flush(emlxs_port_t *port, NODELIST *ndlp, CHANNEL *chan,
    uint32_t shutdown, emlxs_buf_t *fpkt)
{
	emlxs_hba_t *hba = HBA;
	emlxs_buf_t *sbp;
	uint32_t channelno;
	CHANNEL *cp;
	IOCB *icmd;
	IOCBQ *iocbq;
	NODELIST *prev;
	IOCBQ *next;
	IOCB *iocb;
	Q abort;
	uint32_t i;
	MATCHMAP *mp;
	uint8_t flag[MAX_CHANNEL];

	bzero((void *)&abort, sizeof (Q));

	/* Flush all I/O's on tx queue to this target */
	mutex_enter(&EMLXS_TX_CHANNEL_LOCK);

	if (!ndlp->nlp_base && shutdown) {
		ndlp->nlp_active = 0;
	}

	for (channelno = 0; channelno < hba->chan_count; channelno++) {
		cp = &hba->chan[channelno];

		if (chan && cp != chan) {
			continue;
		}

		if (!ndlp->nlp_base || shutdown) {
			/* Check if priority queue is not empty */
			if (ndlp->nlp_ptx[channelno].q_first) {
				/* Transfer all iocb's to local queue */
				if (abort.q_first == 0) {
					abort.q_first =
					    ndlp->nlp_ptx[channelno].q_first;
				} else {
					((IOCBQ *)(abort.q_last))->next =
					    (IOCBQ *)ndlp->nlp_ptx[channelno].
					    q_first;
				}

				flag[channelno] = 1;

				abort.q_last = ndlp->nlp_ptx[channelno].q_last;
				abort.q_cnt += ndlp->nlp_ptx[channelno].q_cnt;
			}
		}

		/* Check if tx queue is not empty */
		if (ndlp->nlp_tx[channelno].q_first) {

			/* Transfer all iocb's to local queue */
			if (abort.q_first == 0) {
				abort.q_first = ndlp->nlp_tx[channelno].q_first;
			} else {
				((IOCBQ *)abort.q_last)->next =
				    (IOCBQ *)ndlp->nlp_tx[channelno].q_first;
			}

			abort.q_last = ndlp->nlp_tx[channelno].q_last;
			abort.q_cnt += ndlp->nlp_tx[channelno].q_cnt;
		}

		/* Clear the queue pointers */
		ndlp->nlp_ptx[channelno].q_first = NULL;
		ndlp->nlp_ptx[channelno].q_last = NULL;
		ndlp->nlp_ptx[channelno].q_cnt = 0;

		ndlp->nlp_tx[channelno].q_first = NULL;
		ndlp->nlp_tx[channelno].q_last = NULL;
		ndlp->nlp_tx[channelno].q_cnt = 0;

		/* If this node was on the channel queue, remove it */
		if (ndlp->nlp_next[channelno]) {
			/* If this is the only node on list */
			if (cp->nodeq.q_first == (void *)ndlp &&
			    cp->nodeq.q_last == (void *)ndlp) {
				cp->nodeq.q_last = NULL;
				cp->nodeq.q_first = NULL;
				cp->nodeq.q_cnt = 0;
			} else if (cp->nodeq.q_first == (void *)ndlp) {
				cp->nodeq.q_first = ndlp->nlp_next[channelno];
				((NODELIST *) cp->nodeq.q_last)->
				    nlp_next[channelno] = cp->nodeq.q_first;
				cp->nodeq.q_cnt--;
			} else {
				/*
				 * This is a little more difficult find the
				 * previous node in the circular channel queue
				 */
				prev = ndlp;
				while (prev->nlp_next[channelno] != ndlp) {
					prev = prev->nlp_next[channelno];
				}

				prev->nlp_next[channelno] =
				    ndlp->nlp_next[channelno];

				if (cp->nodeq.q_last == (void *)ndlp) {
					cp->nodeq.q_last = (void *)prev;
				}
				cp->nodeq.q_cnt--;

			}

			/* Clear node */
			ndlp->nlp_next[channelno] = NULL;
		}

	}

	/* First cleanup the iocb's while still holding the lock */
	iocbq = (IOCBQ *) abort.q_first;
	while (iocbq) {
		/* Free the IoTag and the bmp */
		iocb = &iocbq->iocb;

		if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
			sbp = iocbq->sbp;
			if (sbp) {
				emlxs_sli4_free_xri(port, sbp, sbp->xrip, 1);
			}
		} else {
			sbp = emlxs_unregister_pkt((CHANNEL *)iocbq->channel,
			    iocb->ULPIOTAG, 0);
		}

		if (sbp && (sbp != STALE_PACKET)) {
			mutex_enter(&sbp->mtx);
			sbp->pkt_flags |= PACKET_IN_FLUSH;
			/*
			 * If the fpkt is already set, then we will leave it
			 * alone. This ensures that this pkt is only accounted
			 * for on one fpkt->flush_count
			 */
			if (!sbp->fpkt && fpkt) {
				mutex_enter(&fpkt->mtx);
				sbp->fpkt = fpkt;
				fpkt->flush_count++;
				mutex_exit(&fpkt->mtx);
			}

			mutex_exit(&sbp->mtx);
		}

		iocbq = (IOCBQ *) iocbq->next;

	}	/* end of while */

	mutex_exit(&EMLXS_TX_CHANNEL_LOCK);

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
			    "tx: sbp=%p node=%p", sbp, sbp->node);

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
			/* CMD_CLOSE_XRI_CN should also free the memory */
			icmd = &iocbq->iocb;

			/* SLI3 */
			if (icmd->ULPCOMMAND == CMD_QUE_RING_BUF64_CN ||
			    icmd->ULPCOMMAND == CMD_QUE_RING_BUF_CN ||
			    icmd->ULPCOMMAND == CMD_QUE_RING_LIST64_CN) {
				if ((hba->flag &
				    (FC_ONLINE_MODE | FC_ONLINING_MODE)) == 0) {
					/* HBA is detaching or offlining */
					if (icmd->ULPCOMMAND !=
					    CMD_QUE_RING_LIST64_CN) {
						void	*tmp;
						RING *rp;
						int ch;

						ch = ((CHANNEL *)
						    iocbq->channel)->channelno;
						rp = &hba->sli.sli3.ring[ch];
						for (i = 0;
						    i < icmd->ULPBDECOUNT;
						    i++) {
							mp = EMLXS_GET_VADDR(
							    hba, rp, icmd);

							tmp = (void *)mp;
							if (mp) {
							emlxs_mem_put(
							    hba, MEM_BUF, tmp);
							}
						}
					}

					emlxs_mem_put(hba, MEM_IOCB,
					    (void *)iocbq);
				} else {
					/* repost the unsolicited buffer */
					EMLXS_SLI_ISSUE_IOCB_CMD(hba,
					    (CHANNEL *)iocbq->channel, iocbq);
				}
			} else if (icmd->ULPCOMMAND == CMD_CLOSE_XRI_CN ||
			    icmd->ULPCOMMAND == CMD_CLOSE_XRI_CX) {
				/*
				 * Resend the abort iocbq if any
				 */
				emlxs_tx_put(iocbq, 1);
			}
		}

		iocbq = next;

	}	/* end of while */

	/* Now trigger channel service */
	for (channelno = 0; channelno < hba->chan_count; channelno++) {
		if (!flag[channelno]) {
			continue;
		}

		EMLXS_SLI_ISSUE_IOCB_CMD(hba, &hba->chan[channelno], 0);
	}

	return (abort.q_cnt);

} /* emlxs_tx_node_flush() */


/* Check for IO's on all or a given ring for a given node */
extern uint32_t
emlxs_tx_node_check(emlxs_port_t *port, NODELIST *ndlp, CHANNEL *chan)
{
	emlxs_hba_t *hba = HBA;
	uint32_t channelno;
	CHANNEL *cp;
	uint32_t count;

	count = 0;

	/* Flush all I/O's on tx queue to this target */
	mutex_enter(&EMLXS_TX_CHANNEL_LOCK);

	for (channelno = 0; channelno < hba->chan_count; channelno++) {
		cp = &hba->chan[channelno];

		if (chan && cp != chan) {
			continue;
		}

		/* Check if priority queue is not empty */
		if (ndlp->nlp_ptx[channelno].q_first) {
			count += ndlp->nlp_ptx[channelno].q_cnt;
		}

		/* Check if tx queue is not empty */
		if (ndlp->nlp_tx[channelno].q_first) {
			count += ndlp->nlp_tx[channelno].q_cnt;
		}

	}

	mutex_exit(&EMLXS_TX_CHANNEL_LOCK);

	return (count);

} /* emlxs_tx_node_check() */



/* Flush all IO's on the any ring for a given node's lun */
extern uint32_t
emlxs_tx_lun_flush(emlxs_port_t *port, NODELIST *ndlp, uint32_t lun,
    emlxs_buf_t *fpkt)
{
	emlxs_hba_t *hba = HBA;
	emlxs_buf_t *sbp;
	uint32_t channelno;
	IOCBQ *iocbq;
	IOCBQ *prev;
	IOCBQ *next;
	IOCB *iocb;
	IOCB *icmd;
	Q abort;
	uint32_t i;
	MATCHMAP *mp;
	uint8_t flag[MAX_CHANNEL];

	if (lun == EMLXS_LUN_NONE) {
		return (0);
	}

	bzero((void *)&abort, sizeof (Q));

	/* Flush I/O's on txQ to this target's lun */
	mutex_enter(&EMLXS_TX_CHANNEL_LOCK);

	for (channelno = 0; channelno < hba->chan_count; channelno++) {

		/* Scan the priority queue first */
		prev = NULL;
		iocbq = (IOCBQ *) ndlp->nlp_ptx[channelno].q_first;

		while (iocbq) {
			next = (IOCBQ *)iocbq->next;
			iocb = &iocbq->iocb;
			sbp = (emlxs_buf_t *)iocbq->sbp;

			/* Check if this IO is for our lun */
			if (sbp && (sbp->lun == lun)) {
				/* Remove iocb from the node's ptx queue */
				if (next == 0) {
					ndlp->nlp_ptx[channelno].q_last =
					    (uint8_t *)prev;
				}

				if (prev == 0) {
					ndlp->nlp_ptx[channelno].q_first =
					    (uint8_t *)next;
				} else {
					prev->next = next;
				}

				iocbq->next = NULL;
				ndlp->nlp_ptx[channelno].q_cnt--;

				/*
				 * Add this iocb to our local abort Q
				 */
				if (abort.q_first) {
					((IOCBQ *)abort.q_last)->next = iocbq;
					abort.q_last = (uint8_t *)iocbq;
					abort.q_cnt++;
				} else {
					abort.q_first = (uint8_t *)iocbq;
					abort.q_last = (uint8_t *)iocbq;
					abort.q_cnt = 1;
				}
				iocbq->next = NULL;
				flag[channelno] = 1;

			} else {
				prev = iocbq;
			}

			iocbq = next;

		}	/* while (iocbq) */


		/* Scan the regular queue */
		prev = NULL;
		iocbq = (IOCBQ *)ndlp->nlp_tx[channelno].q_first;

		while (iocbq) {
			next = (IOCBQ *)iocbq->next;
			iocb = &iocbq->iocb;
			sbp = (emlxs_buf_t *)iocbq->sbp;

			/* Check if this IO is for our lun */
			if (sbp && (sbp->lun == lun)) {
				/* Remove iocb from the node's tx queue */
				if (next == 0) {
					ndlp->nlp_tx[channelno].q_last =
					    (uint8_t *)prev;
				}

				if (prev == 0) {
					ndlp->nlp_tx[channelno].q_first =
					    (uint8_t *)next;
				} else {
					prev->next = next;
				}

				iocbq->next = NULL;
				ndlp->nlp_tx[channelno].q_cnt--;

				/*
				 * Add this iocb to our local abort Q
				 */
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
	}	/* for loop */

	/* First cleanup the iocb's while still holding the lock */
	iocbq = (IOCBQ *)abort.q_first;
	while (iocbq) {
		/* Free the IoTag and the bmp */
		iocb = &iocbq->iocb;

		if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
			sbp = iocbq->sbp;
			if (sbp) {
				emlxs_sli4_free_xri(port, sbp, sbp->xrip, 1);
			}
		} else {
			sbp = emlxs_unregister_pkt((CHANNEL *)iocbq->channel,
			    iocb->ULPIOTAG, 0);
		}

		if (sbp && (sbp != STALE_PACKET)) {
			mutex_enter(&sbp->mtx);
			sbp->pkt_flags |= PACKET_IN_FLUSH;
			/*
			 * If the fpkt is already set, then we will leave it
			 * alone. This ensures that this pkt is only accounted
			 * for on one fpkt->flush_count
			 */
			if (!sbp->fpkt && fpkt) {
				mutex_enter(&fpkt->mtx);
				sbp->fpkt = fpkt;
				fpkt->flush_count++;
				mutex_exit(&fpkt->mtx);
			}

			mutex_exit(&sbp->mtx);
		}

		iocbq = (IOCBQ *) iocbq->next;

	}	/* end of while */

	mutex_exit(&EMLXS_TX_CHANNEL_LOCK);

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
			    "tx: sbp=%p node=%p", sbp, sbp->node);

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
			/* Should never happen! */
			icmd = &iocbq->iocb;

			/* SLI3 */
			if (icmd->ULPCOMMAND == CMD_QUE_RING_BUF64_CN ||
			    icmd->ULPCOMMAND == CMD_QUE_RING_BUF_CN ||
			    icmd->ULPCOMMAND == CMD_QUE_RING_LIST64_CN) {
				if ((hba->flag &
				    (FC_ONLINE_MODE | FC_ONLINING_MODE)) == 0) {
					/* HBA is detaching or offlining */
					if (icmd->ULPCOMMAND !=
					    CMD_QUE_RING_LIST64_CN) {
						void	*tmp;
						RING *rp;
						int ch;

						ch = ((CHANNEL *)
						    iocbq->channel)->channelno;
						rp = &hba->sli.sli3.ring[ch];
						for (i = 0;
						    i < icmd->ULPBDECOUNT;
						    i++) {
							mp = EMLXS_GET_VADDR(
							    hba, rp, icmd);

							tmp = (void *)mp;
							if (mp) {
							emlxs_mem_put(
							    hba, MEM_BUF, tmp);
							}
						}
					}

					emlxs_mem_put(hba, MEM_IOCB,
					    (void *)iocbq);
				} else {
					/* repost the unsolicited buffer */
					EMLXS_SLI_ISSUE_IOCB_CMD(hba,
					    (CHANNEL *)iocbq->channel, iocbq);
				}
			} else if (icmd->ULPCOMMAND == CMD_CLOSE_XRI_CN ||
			    icmd->ULPCOMMAND == CMD_CLOSE_XRI_CX) {
				/*
				 * Resend the abort iocbq if any
				 */
				emlxs_tx_put(iocbq, 1);
			}
		}

		iocbq = next;

	}	/* end of while */

	/* Now trigger channel service */
	for (channelno = 0; channelno < hba->chan_count; channelno++) {
		if (!flag[channelno]) {
			continue;
		}

		EMLXS_SLI_ISSUE_IOCB_CMD(hba, &hba->chan[channelno], 0);
	}

	return (abort.q_cnt);

} /* emlxs_tx_lun_flush() */


extern void
emlxs_tx_put(IOCBQ *iocbq, uint32_t lock)
{
	emlxs_hba_t *hba;
	emlxs_port_t *port;
	uint32_t channelno;
	NODELIST *nlp;
	CHANNEL *cp;
	emlxs_buf_t *sbp;

	port = (emlxs_port_t *)iocbq->port;
	hba = HBA;
	cp = (CHANNEL *)iocbq->channel;
	nlp = (NODELIST *)iocbq->node;
	channelno = cp->channelno;
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
		mutex_enter(&EMLXS_TX_CHANNEL_LOCK);
	}

	if (!nlp->nlp_active || (sbp && (sbp->pkt_flags & PACKET_IN_ABORT))) {
		if (sbp) {
			mutex_enter(&sbp->mtx);
			sbp->pkt_flags |= PACKET_IN_FLUSH;
			mutex_exit(&sbp->mtx);

			if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
				emlxs_sli4_free_xri(port, sbp, sbp->xrip, 1);
			} else {
				(void) emlxs_unregister_pkt(cp, sbp->iotag, 0);
			}

			if (lock) {
				mutex_exit(&EMLXS_TX_CHANNEL_LOCK);
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
				mutex_exit(&EMLXS_TX_CHANNEL_LOCK);
			}

			emlxs_mem_put(hba, MEM_IOCB, (void *)iocbq);
		}

		return;
	}

	if (sbp) {

		mutex_enter(&sbp->mtx);

		if (sbp->pkt_flags &
		    (PACKET_IN_COMPLETION | PACKET_IN_CHIPQ | PACKET_IN_TXQ)) {
			mutex_exit(&sbp->mtx);
			if (lock) {
				mutex_exit(&EMLXS_TX_CHANNEL_LOCK);
			}
			return;
		}

		sbp->pkt_flags |= PACKET_IN_TXQ;
		hba->channel_tx_count++;

		mutex_exit(&sbp->mtx);
	}


	/* Check iocbq priority */
	/* Some IOCB has the high priority like reset/close xri etc */
	if (iocbq->flag & IOCB_PRIORITY) {
		/* Add the iocb to the bottom of the node's ptx queue */
		if (nlp->nlp_ptx[channelno].q_first) {
			((IOCBQ *)nlp->nlp_ptx[channelno].q_last)->next = iocbq;
			nlp->nlp_ptx[channelno].q_last = (uint8_t *)iocbq;
			nlp->nlp_ptx[channelno].q_cnt++;
		} else {
			nlp->nlp_ptx[channelno].q_first = (uint8_t *)iocbq;
			nlp->nlp_ptx[channelno].q_last = (uint8_t *)iocbq;
			nlp->nlp_ptx[channelno].q_cnt = 1;
		}

		iocbq->next = NULL;
	} else {	/* Normal priority */


		/* Add the iocb to the bottom of the node's tx queue */
		if (nlp->nlp_tx[channelno].q_first) {
			((IOCBQ *)nlp->nlp_tx[channelno].q_last)->next = iocbq;
			nlp->nlp_tx[channelno].q_last = (uint8_t *)iocbq;
			nlp->nlp_tx[channelno].q_cnt++;
		} else {
			nlp->nlp_tx[channelno].q_first = (uint8_t *)iocbq;
			nlp->nlp_tx[channelno].q_last = (uint8_t *)iocbq;
			nlp->nlp_tx[channelno].q_cnt = 1;
		}

		iocbq->next = NULL;
	}


	/*
	 * Check if the node is not already on channel queue and
	 * (is not closed or  is a priority request)
	 */
	if (!nlp->nlp_next[channelno] &&
	    (!(nlp->nlp_flag[channelno] & NLP_CLOSED) ||
	    (iocbq->flag & IOCB_PRIORITY))) {
		/* If so, then add it to the channel queue */
		if (cp->nodeq.q_first) {
			((NODELIST *)cp->nodeq.q_last)->nlp_next[channelno] =
			    (uint8_t *)nlp;
			nlp->nlp_next[channelno] = cp->nodeq.q_first;

			/*
			 * If this is not the base node then add it
			 * to the tail
			 */
			if (!nlp->nlp_base) {
				cp->nodeq.q_last = (uint8_t *)nlp;
			} else {	/* Otherwise, add it to the head */

				/* The command node always gets priority */
				cp->nodeq.q_first = (uint8_t *)nlp;
			}

			cp->nodeq.q_cnt++;
		} else {
			cp->nodeq.q_first = (uint8_t *)nlp;
			cp->nodeq.q_last = (uint8_t *)nlp;
			nlp->nlp_next[channelno] = nlp;
			cp->nodeq.q_cnt = 1;
		}
	}

	HBASTATS.IocbTxPut[channelno]++;

	/* Adjust the channel timeout timer */
	cp->timeout = hba->timer_tics + 5;

	if (lock) {
		mutex_exit(&EMLXS_TX_CHANNEL_LOCK);
	}

	return;

} /* emlxs_tx_put() */


extern IOCBQ *
emlxs_tx_get(CHANNEL *cp, uint32_t lock)
{
	emlxs_hba_t *hba;
	uint32_t channelno;
	IOCBQ *iocbq;
	NODELIST *nlp;
	emlxs_buf_t *sbp;

	hba = cp->hba;
	channelno = cp->channelno;

	if (lock) {
		mutex_enter(&EMLXS_TX_CHANNEL_LOCK);
	}

begin:

	iocbq = NULL;

	/* Check if a node needs servicing */
	if (cp->nodeq.q_first) {
		nlp = (NODELIST *)cp->nodeq.q_first;

		/* Get next iocb from node's priority queue */

		if (nlp->nlp_ptx[channelno].q_first) {
			iocbq = (IOCBQ *)nlp->nlp_ptx[channelno].q_first;

			/* Check if this is last entry */
			if (nlp->nlp_ptx[channelno].q_last == (void *)iocbq) {
				nlp->nlp_ptx[channelno].q_first = NULL;
				nlp->nlp_ptx[channelno].q_last = NULL;
				nlp->nlp_ptx[channelno].q_cnt = 0;
			} else {
				/* Remove iocb from head */
				nlp->nlp_ptx[channelno].q_first =
				    (void *)iocbq->next;
				nlp->nlp_ptx[channelno].q_cnt--;
			}

			iocbq->next = NULL;
		}

		/* Get next iocb from node tx queue if node not closed */
		else if (nlp->nlp_tx[channelno].q_first &&
		    !(nlp->nlp_flag[channelno] & NLP_CLOSED)) {
			iocbq = (IOCBQ *)nlp->nlp_tx[channelno].q_first;

			/* Check if this is last entry */
			if (nlp->nlp_tx[channelno].q_last == (void *)iocbq) {
				nlp->nlp_tx[channelno].q_first = NULL;
				nlp->nlp_tx[channelno].q_last = NULL;
				nlp->nlp_tx[channelno].q_cnt = 0;
			} else {
				/* Remove iocb from head */
				nlp->nlp_tx[channelno].q_first =
				    (void *)iocbq->next;
				nlp->nlp_tx[channelno].q_cnt--;
			}

			iocbq->next = NULL;
		}

		/* Now deal with node itself */

		/* Check if node still needs servicing */
		if ((nlp->nlp_ptx[channelno].q_first) ||
		    (nlp->nlp_tx[channelno].q_first &&
		    !(nlp->nlp_flag[channelno] & NLP_CLOSED))) {

			/*
			 * If this is the base node, then don't shift the
			 * pointers. We want to drain the base node before
			 * moving on
			 */
			if (!nlp->nlp_base) {
				/*
				 * Just shift channel queue pointers to next
				 * node
				 */
				cp->nodeq.q_last = (void *)nlp;
				cp->nodeq.q_first = nlp->nlp_next[channelno];
			}
		} else {
			/* Remove node from channel queue */

			/* If this is the last node on list */
			if (cp->nodeq.q_last == (void *)nlp) {
				cp->nodeq.q_last = NULL;
				cp->nodeq.q_first = NULL;
				cp->nodeq.q_cnt = 0;
			} else {
				/* Remove node from head */
				cp->nodeq.q_first = nlp->nlp_next[channelno];
				((NODELIST *)cp->nodeq.q_last)->
				    nlp_next[channelno] = cp->nodeq.q_first;
				cp->nodeq.q_cnt--;

			}

			/* Clear node */
			nlp->nlp_next[channelno] = NULL;
		}

		/*
		 * If no iocbq was found on this node, then it will have
		 * been removed. So try again.
		 */
		if (!iocbq) {
			goto begin;
		}

		sbp = (emlxs_buf_t *)iocbq->sbp;

		if (sbp) {
			/*
			 * Check flags before we enter mutex in case this
			 * has been flushed and destroyed
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
			hba->channel_tx_count--;

			mutex_exit(&sbp->mtx);
		}
	}

	if (iocbq) {
		HBASTATS.IocbTxGet[channelno]++;
	}

	/* Adjust the ring timeout timer */
	cp->timeout = (cp->nodeq.q_first) ? (hba->timer_tics + 5) : 0;

	if (lock) {
		mutex_exit(&EMLXS_TX_CHANNEL_LOCK);
	}

	return (iocbq);

} /* emlxs_tx_get() */


/*
 * Remove all cmd from from_rp's txq to to_rp's txq for ndlp.
 * The old IoTag has to be released, the new one has to be
 * allocated.  Others no change
 * TX_CHANNEL lock is held
 */
extern void
emlxs_tx_move(NODELIST *ndlp, CHANNEL *from_chan, CHANNEL *to_chan,
    uint32_t cmd, emlxs_buf_t *fpkt, uint32_t lock)
{
	emlxs_hba_t *hba;
	emlxs_port_t *port;
	uint32_t fchanno, tchanno, i;

	IOCBQ *iocbq;
	IOCBQ *prev;
	IOCBQ *next;
	IOCB *iocb, *icmd;
	Q tbm;		/* To Be Moved Q */
	MATCHMAP *mp;

	NODELIST *nlp = ndlp;
	emlxs_buf_t *sbp;

	NODELIST *n_prev = NULL;
	NODELIST *n_next = NULL;
	uint16_t count = 0;

	hba = from_chan->hba;
	port = &PPORT;
	cmd = cmd; /* To pass lint */

	fchanno = from_chan->channelno;
	tchanno = to_chan->channelno;

	if (lock) {
		mutex_enter(&EMLXS_TX_CHANNEL_LOCK);
	}

	bzero((void *)&tbm, sizeof (Q));

	/* Scan the ndlp's fchanno txq to get the iocb of fcp cmd */
	prev = NULL;
	iocbq = (IOCBQ *)nlp->nlp_tx[fchanno].q_first;

	while (iocbq) {
		next = (IOCBQ *)iocbq->next;
		/* Check if this iocb is fcp cmd */
		iocb = &iocbq->iocb;

		switch (iocb->ULPCOMMAND) {
		/* FCP commands */
		case CMD_FCP_ICMND_CR:
		case CMD_FCP_ICMND_CX:
		case CMD_FCP_IREAD_CR:
		case CMD_FCP_IREAD_CX:
		case CMD_FCP_IWRITE_CR:
		case CMD_FCP_IWRITE_CX:
		case CMD_FCP_ICMND64_CR:
		case CMD_FCP_ICMND64_CX:
		case CMD_FCP_IREAD64_CR:
		case CMD_FCP_IREAD64_CX:
		case CMD_FCP_IWRITE64_CR:
		case CMD_FCP_IWRITE64_CX:
			/* We found a fcp cmd */
			break;
		default:
			/* this is not fcp cmd continue */
			prev = iocbq;
			iocbq = next;
			continue;
		}

		/* found a fcp cmd iocb in fchanno txq, now deque it */
		if (next == NULL) {
			/* This is the last iocbq */
			nlp->nlp_tx[fchanno].q_last =
			    (uint8_t *)prev;
		}

		if (prev == NULL) {
			/* This is the first one then remove it from head */
			nlp->nlp_tx[fchanno].q_first =
			    (uint8_t *)next;
		} else {
			prev->next = next;
		}

		iocbq->next = NULL;
		nlp->nlp_tx[fchanno].q_cnt--;

		/* Add this iocb to our local toberemovedq */
		/* This way we donot hold the TX_CHANNEL lock too long */

		if (tbm.q_first) {
			((IOCBQ *)tbm.q_last)->next = iocbq;
			tbm.q_last = (uint8_t *)iocbq;
			tbm.q_cnt++;
		} else {
			tbm.q_first = (uint8_t *)iocbq;
			tbm.q_last = (uint8_t *)iocbq;
			tbm.q_cnt = 1;
		}

		iocbq = next;

	}	/* While (iocbq) */

	if ((tchanno == hba->channel_fcp) && (tbm.q_cnt != 0)) {

		/* from_chan->nodeq.q_first must be non NULL */
		if (from_chan->nodeq.q_first) {

			/* nodeq is not empty, now deal with the node itself */
			if ((nlp->nlp_tx[fchanno].q_first)) {

				if (!nlp->nlp_base) {
					from_chan->nodeq.q_last =
					    (void *)nlp;
					from_chan->nodeq.q_first =
					    nlp->nlp_next[fchanno];
				}

			} else {
				n_prev = (NODELIST *)from_chan->nodeq.q_first;
				count = from_chan->nodeq.q_cnt;

				if (n_prev == nlp) {

					/* If this is the only node on list */
					if (from_chan->nodeq.q_last ==
					    (void *)nlp) {
						from_chan->nodeq.q_last =
						    NULL;
						from_chan->nodeq.q_first =
						    NULL;
						from_chan->nodeq.q_cnt = 0;
					} else {
						from_chan->nodeq.q_first =
						    nlp->nlp_next[fchanno];
						((NODELIST *)from_chan->
						    nodeq.q_last)->
						    nlp_next[fchanno] =
						    from_chan->nodeq.q_first;
						from_chan->nodeq.q_cnt--;
					}
					/* Clear node */
					nlp->nlp_next[fchanno] = NULL;
				} else {
					count--;
					do {
						n_next =
						    n_prev->nlp_next[fchanno];
						if (n_next == nlp) {
							break;
						}
						n_prev = n_next;
					} while (count--);

					if (count != 0) {

						if (n_next ==
						    (NODELIST *)from_chan->
						    nodeq.q_last) {
							n_prev->
							    nlp_next[fchanno]
							    =
							    ((NODELIST *)
							    from_chan->
							    nodeq.q_last)->
							    nlp_next
							    [fchanno];
							from_chan->nodeq.q_last
							    = (uint8_t *)n_prev;
						} else {

							n_prev->
							    nlp_next[fchanno]
							    =
							    n_next-> nlp_next
							    [fchanno];
						}
						from_chan->nodeq.q_cnt--;
						/* Clear node */
						nlp->nlp_next[fchanno] =
						    NULL;
					}
				}
			}
		}
	}

	/* Now cleanup the iocb's */
	prev = NULL;
	iocbq = (IOCBQ *)tbm.q_first;

	while (iocbq) {

		next = (IOCBQ *)iocbq->next;

		/* Free the IoTag and the bmp */
		iocb = &iocbq->iocb;

		if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
			sbp = iocbq->sbp;
			if (sbp) {
				emlxs_sli4_free_xri(port, sbp, sbp->xrip, 1);
			}
		} else {
			sbp = emlxs_unregister_pkt((CHANNEL *)iocbq->channel,
			    iocb->ULPIOTAG, 0);
		}

		if (sbp && (sbp != STALE_PACKET)) {
			mutex_enter(&sbp->mtx);
			sbp->pkt_flags |= PACKET_IN_FLUSH;

			/*
			 * If the fpkt is already set, then we will leave it
			 * alone. This ensures that this pkt is only accounted
			 * for on one fpkt->flush_count
			 */
			if (!sbp->fpkt && fpkt) {
				mutex_enter(&fpkt->mtx);
				sbp->fpkt = fpkt;
				fpkt->flush_count++;
				mutex_exit(&fpkt->mtx);
			}
			mutex_exit(&sbp->mtx);
		}
		iocbq = next;

	}	/* end of while */

	iocbq = (IOCBQ *)tbm.q_first;
	while (iocbq) {
		/* Save the next iocbq for now */
		next = (IOCBQ *)iocbq->next;

		/* Unlink this iocbq */
		iocbq->next = NULL;

		/* Get the pkt */
		sbp = (emlxs_buf_t *)iocbq->sbp;

		if (sbp) {
			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_pkt_flush_msg,
			"tx: sbp=%p node=%p", sbp, sbp->node);

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

			/* SLI3 */
			if (icmd->ULPCOMMAND == CMD_QUE_RING_BUF64_CN ||
			    icmd->ULPCOMMAND == CMD_QUE_RING_BUF_CN ||
			    icmd->ULPCOMMAND == CMD_QUE_RING_LIST64_CN) {
				if ((hba->flag &
				    (FC_ONLINE_MODE | FC_ONLINING_MODE)) == 0) {
					/* HBA is detaching or offlining */
					if (icmd->ULPCOMMAND !=
					    CMD_QUE_RING_LIST64_CN) {
						void *tmp;
						RING *rp;
						int ch;

						ch = from_chan->channelno;
						rp = &hba->sli.sli3.ring[ch];

						for (i = 0;
						    i < icmd->ULPBDECOUNT;
						    i++) {
							mp = EMLXS_GET_VADDR(
							    hba, rp, icmd);

							tmp = (void *)mp;
							if (mp) {
							emlxs_mem_put(
							    hba,
							    MEM_BUF,
							    tmp);
							}
						}

					}

					emlxs_mem_put(hba, MEM_IOCB,
					    (void *)iocbq);
				} else {
					/* repost the unsolicited buffer */
					EMLXS_SLI_ISSUE_IOCB_CMD(hba,
					    from_chan, iocbq);
				}
			}
		}

		iocbq = next;

	}	/* end of while */

	/* Now flush the chipq if any */
	if (!(nlp->nlp_flag[fchanno] & NLP_CLOSED)) {

		mutex_exit(&EMLXS_TX_CHANNEL_LOCK);

		(void) emlxs_chipq_node_flush(port, from_chan, nlp, 0);

		mutex_enter(&EMLXS_TX_CHANNEL_LOCK);
	}

	if (lock) {
		mutex_exit(&EMLXS_TX_CHANNEL_LOCK);
	}

	return;

} /* emlxs_tx_move */


extern uint32_t
emlxs_chipq_node_flush(emlxs_port_t *port, CHANNEL *chan, NODELIST *ndlp,
    emlxs_buf_t *fpkt)
{
	emlxs_hba_t *hba = HBA;
	emlxs_buf_t *sbp;
	IOCBQ *iocbq;
	IOCBQ *next;
	Q abort;
	CHANNEL *cp;
	uint32_t channelno;
	uint8_t flag[MAX_CHANNEL];
	uint32_t iotag;

	bzero((void *)&abort, sizeof (Q));
	bzero((void *)flag, sizeof (flag));

	for (channelno = 0; channelno < hba->chan_count; channelno++) {
		cp = &hba->chan[channelno];

		if (chan && cp != chan) {
			continue;
		}

		mutex_enter(&EMLXS_FCTAB_LOCK);

		for (iotag = 1; iotag < hba->max_iotag; iotag++) {
			sbp = hba->fc_table[iotag];

			if (sbp && (sbp != STALE_PACKET) &&
			    (sbp->pkt_flags & PACKET_IN_CHIPQ) &&
			    (sbp->node == ndlp) &&
			    (sbp->channel == cp) &&
			    !(sbp->pkt_flags & PACKET_XRI_CLOSED)) {
				emlxs_sbp_abort_add(port, sbp, &abort, flag,
				    fpkt);
			}

		}
		mutex_exit(&EMLXS_FCTAB_LOCK);

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

	/* Now trigger channel service */
	for (channelno = 0; channelno < hba->chan_count; channelno++) {
		if (!flag[channelno]) {
			continue;
		}

		EMLXS_SLI_ISSUE_IOCB_CMD(hba, &hba->chan[channelno], 0);
	}

	return (abort.q_cnt);

} /* emlxs_chipq_node_flush() */


/* Flush all IO's left on all iotag lists */
extern uint32_t
emlxs_iotag_flush(emlxs_hba_t *hba)
{
	emlxs_port_t *port = &PPORT;
	emlxs_buf_t *sbp;
	IOCBQ *iocbq;
	IOCB *iocb;
	Q abort;
	CHANNEL *cp;
	uint32_t channelno;
	uint32_t iotag;
	uint32_t count;

	count = 0;
	for (channelno = 0; channelno < hba->chan_count; channelno++) {
		cp = &hba->chan[channelno];

		bzero((void *)&abort, sizeof (Q));

		mutex_enter(&EMLXS_FCTAB_LOCK);

		for (iotag = 1; iotag < hba->max_iotag; iotag++) {
			sbp = hba->fc_table[iotag];

			/* Check if the slot is empty */
			if (!sbp || (sbp == STALE_PACKET)) {
				continue;
			}

			/* We are building an abort list per channel */
			if (sbp->channel != cp) {
				continue;
			}

			hba->fc_table[iotag] = STALE_PACKET;
			hba->io_count--;

			/* Check if IO is valid */
			if (!(sbp->pkt_flags & PACKET_VALID) ||
			    (sbp->pkt_flags & (PACKET_ULP_OWNED|
			    PACKET_COMPLETED|PACKET_IN_COMPLETION))) {
				EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_debug_msg,
				    "iotag_flush: Invalid IO found. iotag=%d",
				    iotag);

				continue;
			}

			sbp->iotag = 0;

			/* Set IOCB status */
			iocbq = &sbp->iocbq;
			iocb = &iocbq->iocb;

			iocb->ULPSTATUS = IOSTAT_LOCAL_REJECT;
			iocb->un.grsp.perr.statLocalError = IOERR_LINK_DOWN;
			iocb->ULPLE = 1;
			iocbq->next = NULL;

			if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
				if (sbp->xrip) {
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_sli_debug_msg,
					    "iotag_flush: iotag=%d sbp=%p "
					    "xrip=%p state=%x flag=%x",
					    iotag, sbp, sbp->xrip,
					    sbp->xrip->state, sbp->xrip->flag);
				} else {
					EMLXS_MSGF(EMLXS_CONTEXT,
					    &emlxs_sli_debug_msg,
					    "iotag_flush: iotag=%d sbp=%p "
					    "xrip=NULL", iotag, sbp);
				}

				emlxs_sli4_free_xri(port, sbp, sbp->xrip, 0);
			} else {
				/* Clean up the sbp */
				mutex_enter(&sbp->mtx);

				if (sbp->pkt_flags & PACKET_IN_TXQ) {
					sbp->pkt_flags &= ~PACKET_IN_TXQ;
					hba->channel_tx_count --;
				}

				if (sbp->pkt_flags & PACKET_IN_CHIPQ) {
					sbp->pkt_flags &= ~PACKET_IN_CHIPQ;
				}

				if (sbp->bmp) {
					emlxs_mem_put(hba, MEM_BPL,
					    (void *)sbp->bmp);
					sbp->bmp = 0;
				}

				mutex_exit(&sbp->mtx);
			}

			/* At this point all nodes are assumed destroyed */
			mutex_enter(&sbp->mtx);
			sbp->node = 0;
			mutex_exit(&sbp->mtx);

			/* Add this iocb to our local abort Q */
			if (abort.q_first) {
				((IOCBQ *)abort.q_last)->next = iocbq;
				abort.q_last = (uint8_t *)iocbq;
				abort.q_cnt++;
			} else {
				abort.q_first = (uint8_t *)iocbq;
				abort.q_last = (uint8_t *)iocbq;
				abort.q_cnt = 1;
			}
		}

		mutex_exit(&EMLXS_FCTAB_LOCK);

		/* Trigger deferred completion */
		if (abort.q_first) {
			mutex_enter(&cp->rsp_lock);
			if (cp->rsp_head == NULL) {
				cp->rsp_head = (IOCBQ *)abort.q_first;
				cp->rsp_tail = (IOCBQ *)abort.q_last;
			} else {
				cp->rsp_tail->next = (IOCBQ *)abort.q_first;
				cp->rsp_tail = (IOCBQ *)abort.q_last;
			}
			mutex_exit(&cp->rsp_lock);

			emlxs_thread_trigger2(&cp->intr_thread,
			    emlxs_proc_channel, cp);

			EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_sli_debug_msg,
			    "iotag_flush: channel=%d count=%d",
			    channelno, abort.q_cnt);

			count += abort.q_cnt;
		}
	}

	return (count);

} /* emlxs_iotag_flush() */



/* Checks for IO's on all or a given channel for a given node */
extern uint32_t
emlxs_chipq_node_check(emlxs_port_t *port, CHANNEL *chan, NODELIST *ndlp)
{
	emlxs_hba_t *hba = HBA;
	emlxs_buf_t *sbp;
	CHANNEL *cp;
	uint32_t channelno;
	uint32_t count;
	uint32_t iotag;

	count = 0;

	for (channelno = 0; channelno < hba->chan_count; channelno++) {
		cp = &hba->chan[channelno];

		if (chan && cp != chan) {
			continue;
		}

		mutex_enter(&EMLXS_FCTAB_LOCK);

		for (iotag = 1; iotag < hba->max_iotag; iotag++) {
			sbp = hba->fc_table[iotag];

			if (sbp && (sbp != STALE_PACKET) &&
			    (sbp->pkt_flags & PACKET_IN_CHIPQ) &&
			    (sbp->node == ndlp) &&
			    (sbp->channel == cp) &&
			    !(sbp->pkt_flags & PACKET_XRI_CLOSED)) {
				count++;
			}

		}
		mutex_exit(&EMLXS_FCTAB_LOCK);

	}	/* for */

	return (count);

} /* emlxs_chipq_node_check() */



/* Flush all IO's for a given node's lun (on any channel) */
extern uint32_t
emlxs_chipq_lun_flush(emlxs_port_t *port, NODELIST *ndlp,
    uint32_t lun, emlxs_buf_t *fpkt)
{
	emlxs_hba_t *hba = HBA;
	emlxs_buf_t *sbp;
	IOCBQ *iocbq;
	IOCBQ *next;
	Q abort;
	uint32_t iotag;
	uint8_t flag[MAX_CHANNEL];
	uint32_t channelno;

	if (lun == EMLXS_LUN_NONE) {
		return (0);
	}

	bzero((void *)flag, sizeof (flag));
	bzero((void *)&abort, sizeof (Q));

	mutex_enter(&EMLXS_FCTAB_LOCK);
	for (iotag = 1; iotag < hba->max_iotag; iotag++) {
		sbp = hba->fc_table[iotag];

		if (sbp && (sbp != STALE_PACKET) &&
		    sbp->pkt_flags & PACKET_IN_CHIPQ &&
		    sbp->node == ndlp &&
		    sbp->lun == lun &&
		    !(sbp->pkt_flags & PACKET_XRI_CLOSED)) {
			emlxs_sbp_abort_add(port, sbp,
			    &abort, flag, fpkt);
		}
	}
	mutex_exit(&EMLXS_FCTAB_LOCK);

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

	/* Now trigger channel service */
	for (channelno = 0; channelno < hba->chan_count; channelno++) {
		if (!flag[channelno]) {
			continue;
		}

		EMLXS_SLI_ISSUE_IOCB_CMD(hba, &hba->chan[channelno], 0);
	}

	return (abort.q_cnt);

} /* emlxs_chipq_lun_flush() */



/*
 * Issue an ABORT_XRI_CN iocb command to abort an FCP command already issued.
 * This must be called while holding the EMLXS_FCTAB_LOCK
 */
extern IOCBQ *
emlxs_create_abort_xri_cn(emlxs_port_t *port, NODELIST *ndlp,
    uint16_t iotag, CHANNEL *cp, uint8_t class, int32_t flag)
{
	emlxs_hba_t *hba = HBA;
	IOCBQ *iocbq;
	IOCB *iocb;
	emlxs_wqe_t *wqe;
	emlxs_buf_t *sbp;
	uint16_t abort_iotag;

	if ((iocbq = (IOCBQ *)emlxs_mem_get(hba, MEM_IOCB)) == NULL) {
		return (NULL);
	}

	iocbq->channel = (void *)cp;
	iocbq->port = (void *)port;
	iocbq->node = (void *)ndlp;
	iocbq->flag |= (IOCB_PRIORITY | IOCB_SPECIAL);

	/*
	 * set up an iotag using special Abort iotags
	 */
	if ((hba->fc_oor_iotag >= EMLXS_MAX_ABORT_TAG)) {
		hba->fc_oor_iotag = hba->max_iotag;
	}
	abort_iotag = hba->fc_oor_iotag++;


	if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
		wqe = &iocbq->wqe;
		sbp = hba->fc_table[iotag];

		/* Try to issue abort by XRI if possible */
		if (sbp == NULL || sbp == STALE_PACKET || sbp->xrip == NULL) {
			wqe->un.Abort.Criteria = ABORT_REQ_TAG;
			wqe->AbortTag = iotag;
		} else {
			wqe->un.Abort.Criteria = ABORT_XRI_TAG;
			wqe->AbortTag = sbp->xrip->XRI;
		}
		wqe->un.Abort.IA = 0;
		wqe->RequestTag = abort_iotag;
		wqe->Command = CMD_ABORT_XRI_CX;
		wqe->Class = CLASS3;
		wqe->CQId = (uint16_t)0xffff;  /* default CQ for response */
		wqe->CmdType = WQE_TYPE_ABORT;
	} else {
		iocb = &iocbq->iocb;
		iocb->ULPIOTAG = abort_iotag;
		iocb->un.acxri.abortType = flag;
		iocb->un.acxri.abortContextTag = ndlp->nlp_Rpi;
		iocb->un.acxri.abortIoTag = iotag;
		iocb->ULPLE = 1;
		iocb->ULPCLASS = class;
		iocb->ULPCOMMAND = CMD_ABORT_XRI_CN;
		iocb->ULPOWNER = OWN_CHIP;
	}

	return (iocbq);

} /* emlxs_create_abort_xri_cn() */


/* This must be called while holding the EMLXS_FCTAB_LOCK */
extern IOCBQ *
emlxs_create_abort_xri_cx(emlxs_port_t *port, NODELIST *ndlp, uint16_t xid,
    CHANNEL *cp, uint8_t class, int32_t flag)
{
	emlxs_hba_t *hba = HBA;
	IOCBQ *iocbq;
	IOCB *iocb;
	emlxs_wqe_t *wqe;
	uint16_t abort_iotag;

	if ((iocbq = (IOCBQ *)emlxs_mem_get(hba, MEM_IOCB)) == NULL) {
		return (NULL);
	}

	iocbq->channel = (void *)cp;
	iocbq->port = (void *)port;
	iocbq->node = (void *)ndlp;
	iocbq->flag |= (IOCB_PRIORITY | IOCB_SPECIAL);

	/*
	 * set up an iotag using special Abort iotags
	 */
	if ((hba->fc_oor_iotag >= EMLXS_MAX_ABORT_TAG)) {
		hba->fc_oor_iotag = hba->max_iotag;
	}
	abort_iotag = hba->fc_oor_iotag++;

	if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
		wqe = &iocbq->wqe;
		wqe->un.Abort.Criteria = ABORT_XRI_TAG;
		wqe->un.Abort.IA = 0;
		wqe->RequestTag = abort_iotag;
		wqe->AbortTag = xid;
		wqe->Command = CMD_ABORT_XRI_CX;
		wqe->Class = CLASS3;
		wqe->CQId = (uint16_t)0xffff;  /* default CQ for response */
		wqe->CmdType = WQE_TYPE_ABORT;
	} else {
		iocb = &iocbq->iocb;
		iocb->ULPCONTEXT = xid;
		iocb->ULPIOTAG = abort_iotag;
		iocb->un.acxri.abortType = flag;
		iocb->ULPLE = 1;
		iocb->ULPCLASS = class;
		iocb->ULPCOMMAND = CMD_ABORT_XRI_CX;
		iocb->ULPOWNER = OWN_CHIP;
	}

	return (iocbq);

} /* emlxs_create_abort_xri_cx() */



/* This must be called while holding the EMLXS_FCTAB_LOCK */
extern IOCBQ *
emlxs_create_close_xri_cn(emlxs_port_t *port, NODELIST *ndlp,
    uint16_t iotag, CHANNEL *cp)
{
	emlxs_hba_t *hba = HBA;
	IOCBQ *iocbq;
	IOCB *iocb;
	emlxs_wqe_t *wqe;
	emlxs_buf_t *sbp;
	uint16_t abort_iotag;

	if ((iocbq = (IOCBQ *)emlxs_mem_get(hba, MEM_IOCB)) == NULL) {
		return (NULL);
	}

	iocbq->channel = (void *)cp;
	iocbq->port = (void *)port;
	iocbq->node = (void *)ndlp;
	iocbq->flag |= (IOCB_PRIORITY | IOCB_SPECIAL);

	/*
	 * set up an iotag using special Abort iotags
	 */
	if ((hba->fc_oor_iotag >= EMLXS_MAX_ABORT_TAG)) {
		hba->fc_oor_iotag = hba->max_iotag;
	}
	abort_iotag = hba->fc_oor_iotag++;

	if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
		wqe = &iocbq->wqe;
		sbp = hba->fc_table[iotag];

		/* Try to issue close by XRI if possible */
		if (sbp == NULL || sbp == STALE_PACKET || sbp->xrip == NULL) {
			wqe->un.Abort.Criteria = ABORT_REQ_TAG;
			wqe->AbortTag = iotag;
		} else {
			wqe->un.Abort.Criteria = ABORT_XRI_TAG;
			wqe->AbortTag = sbp->xrip->XRI;
		}
		wqe->un.Abort.IA = 1;
		wqe->RequestTag = abort_iotag;
		wqe->Command = CMD_ABORT_XRI_CX;
		wqe->Class = CLASS3;
		wqe->CQId = (uint16_t)0xffff;  /* default CQ for response */
		wqe->CmdType = WQE_TYPE_ABORT;
	} else {
		iocb = &iocbq->iocb;
		iocb->ULPIOTAG = abort_iotag;
		iocb->un.acxri.abortType = 0;
		iocb->un.acxri.abortContextTag = ndlp->nlp_Rpi;
		iocb->un.acxri.abortIoTag = iotag;
		iocb->ULPLE = 1;
		iocb->ULPCLASS = 0;
		iocb->ULPCOMMAND = CMD_CLOSE_XRI_CN;
		iocb->ULPOWNER = OWN_CHIP;
	}

	return (iocbq);

} /* emlxs_create_close_xri_cn() */


/* This must be called while holding the EMLXS_FCTAB_LOCK */
extern IOCBQ *
emlxs_create_close_xri_cx(emlxs_port_t *port, NODELIST *ndlp, uint16_t xid,
    CHANNEL *cp)
{
	emlxs_hba_t *hba = HBA;
	IOCBQ *iocbq;
	IOCB *iocb;
	emlxs_wqe_t *wqe;
	uint16_t abort_iotag;

	if ((iocbq = (IOCBQ *)emlxs_mem_get(hba, MEM_IOCB)) == NULL) {
		return (NULL);
	}

	iocbq->channel = (void *)cp;
	iocbq->port = (void *)port;
	iocbq->node = (void *)ndlp;
	iocbq->flag |= (IOCB_PRIORITY | IOCB_SPECIAL);

	/*
	 * set up an iotag using special Abort iotags
	 */
	if ((hba->fc_oor_iotag >= EMLXS_MAX_ABORT_TAG)) {
		hba->fc_oor_iotag = hba->max_iotag;
	}
	abort_iotag = hba->fc_oor_iotag++;

	if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
		wqe = &iocbq->wqe;
		wqe->un.Abort.Criteria = ABORT_XRI_TAG;
		wqe->un.Abort.IA = 1;
		wqe->RequestTag = abort_iotag;
		wqe->AbortTag = xid;
		wqe->Command = CMD_ABORT_XRI_CX;
		wqe->Class = CLASS3;
		wqe->CQId = (uint16_t)0xffff;  /* default CQ for response */
		wqe->CmdType = WQE_TYPE_ABORT;
	} else {
		iocb = &iocbq->iocb;
		iocb->ULPCONTEXT = xid;
		iocb->ULPIOTAG = abort_iotag;
		iocb->ULPLE = 1;
		iocb->ULPCLASS = 0;
		iocb->ULPCOMMAND = CMD_CLOSE_XRI_CX;
		iocb->ULPOWNER = OWN_CHIP;
	}

	return (iocbq);

} /* emlxs_create_close_xri_cx() */


void
emlxs_close_els_exchange(emlxs_hba_t *hba, emlxs_port_t *port, uint32_t rxid)
{
	CHANNEL *cp;
	IOCBQ *iocbq;
	IOCB *iocb;

	if (rxid == 0 || rxid == 0xFFFF) {
		return;
	}

	if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
		    "Closing ELS exchange: xid=%x", rxid);

		if (emlxs_sli4_unreserve_xri(port, rxid, 1) == 0) {
			return;
		}
	}

	cp = &hba->chan[hba->channel_els];

	mutex_enter(&EMLXS_FCTAB_LOCK);

	/* Create the abort IOCB */
	iocbq = emlxs_create_close_xri_cx(port, NULL, rxid, cp);

	mutex_exit(&EMLXS_FCTAB_LOCK);

	if (iocbq) {
		iocb = &iocbq->iocb;
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
		    "Closing ELS exchange: xid=%x iotag=%d", rxid,
		    iocb->ULPIOTAG);

		EMLXS_SLI_ISSUE_IOCB_CMD(hba, cp, iocbq);
	}

} /* emlxs_close_els_exchange() */


void
emlxs_abort_els_exchange(emlxs_hba_t *hba, emlxs_port_t *port, uint32_t rxid)
{
	CHANNEL *cp;
	IOCBQ *iocbq;
	IOCB *iocb;

	if (rxid == 0 || rxid == 0xFFFF) {
		return;
	}

	if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {

		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
		    "Aborting ELS exchange: xid=%x", rxid);

		if (emlxs_sli4_unreserve_xri(port, rxid, 1) == 0) {
			/* We have no way to abort unsolicited exchanges */
			/* that we have not responded to at this time */
			/* So we will return for now */
			return;
		}
	}

	cp = &hba->chan[hba->channel_els];

	mutex_enter(&EMLXS_FCTAB_LOCK);

	/* Create the abort IOCB */
	if (hba->state >= FC_LINK_UP) {
		iocbq = emlxs_create_abort_xri_cx(port, NULL, rxid, cp,
		    CLASS3, ABORT_TYPE_ABTS);
	} else {
		iocbq = emlxs_create_close_xri_cx(port, NULL, rxid, cp);
	}

	mutex_exit(&EMLXS_FCTAB_LOCK);

	if (iocbq) {
		iocb = &iocbq->iocb;
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
		    "Aborting ELS exchange: xid=%x iotag=%d", rxid,
		    iocb->ULPIOTAG);

		EMLXS_SLI_ISSUE_IOCB_CMD(hba, cp, iocbq);
	}

} /* emlxs_abort_els_exchange() */


void
emlxs_abort_ct_exchange(emlxs_hba_t *hba, emlxs_port_t *port, uint32_t rxid)
{
	CHANNEL *cp;
	IOCBQ *iocbq;
	IOCB *iocb;

	if (rxid == 0 || rxid == 0xFFFF) {
		return;
	}

	if (hba->sli_mode == EMLXS_HBA_SLI4_MODE) {
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_ct_msg,
		    "Aborting CT exchange: xid=%x", rxid);

		if (emlxs_sli4_unreserve_xri(port, rxid, 1) == 0) {
			/* We have no way to abort unsolicited exchanges */
			/* that we have not responded to at this time */
			/* So we will return for now */
			return;
		}
	}

	cp = &hba->chan[hba->channel_ct];

	mutex_enter(&EMLXS_FCTAB_LOCK);

	/* Create the abort IOCB */
	if (hba->state >= FC_LINK_UP) {
		iocbq = emlxs_create_abort_xri_cx(port, NULL, rxid, cp,
		    CLASS3, ABORT_TYPE_ABTS);
	} else {
		iocbq = emlxs_create_close_xri_cx(port, NULL, rxid, cp);
	}

	mutex_exit(&EMLXS_FCTAB_LOCK);

	if (iocbq) {
		iocb = &iocbq->iocb;
		EMLXS_MSGF(EMLXS_CONTEXT, &emlxs_unsol_els_msg,
		    "Aborting CT exchange: xid=%x iotag=%d", rxid,
		    iocb->ULPIOTAG);

		EMLXS_SLI_ISSUE_IOCB_CMD(hba, cp, iocbq);
	}

} /* emlxs_abort_ct_exchange() */


/* This must be called while holding the EMLXS_FCTAB_LOCK */
static void
emlxs_sbp_abort_add(emlxs_port_t *port, emlxs_buf_t *sbp, Q *abort,
    uint8_t *flag, emlxs_buf_t *fpkt)
{
	emlxs_hba_t *hba = HBA;
	IOCBQ *iocbq;
	CHANNEL *cp;
	NODELIST *ndlp;

	cp = (CHANNEL *)sbp->channel;
	ndlp = sbp->node;

	/* Create the close XRI IOCB */
	if (hba->state >= FC_LINK_UP) {
		iocbq = emlxs_create_abort_xri_cn(port, ndlp, sbp->iotag, cp,
		    CLASS3, ABORT_TYPE_ABTS);
	} else {
		iocbq = emlxs_create_close_xri_cn(port, ndlp, sbp->iotag, cp);
	}
	/*
	 * Add this iocb to our local abort Q
	 * This way we don't hold the CHIPQ lock too long
	 */
	if (iocbq) {
		if (abort->q_first) {
			((IOCBQ *)abort->q_last)->next = iocbq;
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

	flag[cp->channelno] = 1;

	/*
	 * If the fpkt is already set, then we will leave it alone
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

}	/* emlxs_sbp_abort_add() */
