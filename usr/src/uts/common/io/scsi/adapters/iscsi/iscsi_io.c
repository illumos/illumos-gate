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
 * Copyright 2000 by Cisco Systems, Inc.  All rights reserved.
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2011 Nexenta Systems, Inc. All rights reserved.
 *
 * iSCSI Pseudo HBA Driver
 */

#include <sys/socket.h>		/* networking stuff */
#include <sys/t_kuser.h>	/* networking stuff */
#include <sys/tihdr.h>		/* networking stuff */
#include <sys/strsubr.h>	/* networking stuff */
#include <netinet/tcp.h>	/* TCP_NODELAY */
#include <sys/socketvar.h>	/* _ALLOC_SLEEP */
#include <sys/strsun.h>		/* DB_TYPE() */
#include <sys/scsi/generic/sense.h>

#include "iscsi.h"		/* iscsi driver */
#include <sys/iscsi_protocol.h>	/* iscsi protocol */

#define	ISCSI_INI_TASK_TTT	0xffffffff
#define	ISCSI_CONN_TIEMOUT_DETECT	20

boolean_t iscsi_io_logging = B_FALSE;

#define	ISCSI_CHECK_SCSI_READ(ICHK_CMD, ICHK_HDR, ICHK_LEN, ICHK_TYPE)	\
	if (idm_pattern_checking)  {					\
		struct scsi_pkt *pkt = (ICHK_CMD)->cmd_un.scsi.pkt;	\
		if (((ICHK_HDR)->response == 0) &&			\
		    ((ICHK_HDR)->cmd_status == 0) &&			\
		    ((pkt->pkt_cdbp[0] == SCMD_READ_G1) ||		\
		    (pkt->pkt_cdbp[0] == SCMD_READ_G4) ||		\
		    (pkt->pkt_cdbp[0] == SCMD_READ) ||			\
		    (pkt->pkt_cdbp[0] == SCMD_READ_G5))) {		\
			idm_buf_t *idb = (ICHK_CMD)->cmd_un.scsi.ibp_ibuf; \
			IDM_BUFPAT_CHECK(idb, ICHK_LEN, ICHK_TYPE); \
		}						\
	}

/* Size of structure scsi_arq_status without sense data. */
#define	ISCSI_ARQ_STATUS_NOSENSE_LEN	(sizeof (struct scsi_arq_status) - \
    sizeof (struct scsi_extended_sense))

/* generic io helpers */
static uint32_t n2h24(uchar_t *ptr);
static int iscsi_sna_lt(uint32_t n1, uint32_t n2);
void iscsi_update_flow_control(iscsi_sess_t *isp,
    uint32_t max, uint32_t exp);
static iscsi_status_t iscsi_rx_process_scsi_itt_to_icmdp(iscsi_sess_t *isp,
    idm_conn_t *ic, iscsi_scsi_rsp_hdr_t *ihp, iscsi_cmd_t **icmdp);
static iscsi_status_t iscsi_rx_process_itt_to_icmdp(iscsi_sess_t *isp,
    iscsi_hdr_t *ihp, iscsi_cmd_t **icmdp);
static void iscsi_process_rsp_status(iscsi_sess_t *isp, iscsi_conn_t *icp,
    idm_status_t status);
static void iscsi_drop_conn_cleanup(iscsi_conn_t *icp);
static boolean_t iscsi_nop_timeout_checks(iscsi_cmd_t *icmdp);
/* callbacks from idm */
static idm_pdu_cb_t iscsi_tx_done;

/* receivers */
static idm_status_t iscsi_rx_process_nop(idm_conn_t *ic, idm_pdu_t *pdu);
static idm_status_t iscsi_rx_process_data_rsp(idm_conn_t *ic,
    idm_pdu_t *pdu);
static idm_status_t iscsi_rx_process_cmd_rsp(idm_conn_t *ic, idm_pdu_t *pdu);
static idm_status_t iscsi_rx_process_reject_rsp(idm_conn_t *ic,
    idm_pdu_t *pdu);

static idm_status_t iscsi_rx_process_rejected_tsk_mgt(idm_conn_t *ic,
    iscsi_hdr_t *old_ihp);
static idm_status_t iscsi_rx_process_task_mgt_rsp(idm_conn_t *ic,
    idm_pdu_t *pdu);
static idm_status_t iscsi_rx_process_logout_rsp(idm_conn_t *ic,
    idm_pdu_t *pdu);
static idm_status_t iscsi_rx_process_async_rsp(idm_conn_t *ic,
    idm_pdu_t *pdu);
static idm_status_t iscsi_rx_process_text_rsp(idm_conn_t *ic,
    idm_pdu_t *pdu);

/* senders */
static iscsi_status_t iscsi_tx_scsi(iscsi_sess_t *isp, iscsi_cmd_t *icmdp);
static iscsi_status_t iscsi_tx_nop(iscsi_sess_t *isp, iscsi_cmd_t *icmdp);
static iscsi_status_t iscsi_tx_abort(iscsi_sess_t *isp, iscsi_cmd_t *icmdp);
static iscsi_status_t iscsi_tx_reset(iscsi_sess_t *isp, iscsi_cmd_t *icmdp);
static iscsi_status_t iscsi_tx_logout(iscsi_sess_t *isp, iscsi_cmd_t *icmdp);
static iscsi_status_t iscsi_tx_text(iscsi_sess_t *isp, iscsi_cmd_t *icmdp);


/* helpers */
static void iscsi_logout_start(void *arg);
static void iscsi_handle_passthru_callback(struct scsi_pkt *pkt);
static void iscsi_handle_nop(iscsi_conn_t *icp, uint32_t itt, uint32_t ttt);

static void iscsi_timeout_checks(iscsi_sess_t *isp);
static void iscsi_nop_checks(iscsi_sess_t *isp);
static boolean_t iscsi_decode_sense(uint8_t *sense_data, iscsi_cmd_t *icmdp);
static void iscsi_flush_cmd_after_reset(uint32_t cmd_sn, uint16_t lun_num,
    iscsi_conn_t *icp);

/*
 * This file contains the main guts of the iSCSI protocol layer.
 * It's broken into 5 sections; Basic helper functions, RX IO path,
 * TX IO path, Completion (IC) IO path, and watchdog (WD) routines.
 *
 * The IO flow model is similiar to the below diagram.  The
 * iscsi session, connection and command state machines are used
 * to drive IO through this flow diagram.  Reference those files
 * to get a detailed description of their respective state models
 * prior to their xxx_state_machine_function().
 *
 * tran_start() -> CMD_E1     TX_THREAD                   RX_THREAD
 *                   |            T                           T
 *                   V            T                           T
 *                PENDING_Q  --CMD_E2--> ACTIVE_Q -      --CMD_E3--+
 *                                T                \ C        T    |
 *                                T                 \M        T    |
 *                                                   D        T    |
 *                                       WD_THREAD TT|TT      T    |
 *                                                  /E        T    |
 *                                                 / 6        T    |
 *                                     ABORTING_Q<-      --CMD_E3--+
 *                                                            T    |
 *                                T                           T    |
 *                                T                                |
 *               callback()  <--CMD_E#-- COMPLETION_Q <------------+
 *                                T
 *                                T
 *                            IC_THREAD
 *
 * External and internal command are ran thru this same state
 * machine.  All commands enter the state machine by receiving an
 * ISCSI_CMD_EVENT_E1.  This event places the command into the
 * PENDING_Q.  Next when resources are available the TX_THREAD
 * issues a E2 event on the command.  This sends the command
 * to the TCP stack and places the command on the ACTIVE_Q.  While
 * on the PENDIING_Q and ACTIVE_Q, the command is monitored via the
 * WD_THREAD to ensure the pkt_time has not elapsed.  If elapsed the
 * command is issued an E6(timeout) event which moves either (if pending)
 * completed the command or (if active) moves the command to the
 * aborting queue and issues a SCSI TASK MANAGEMENT ABORT command
 * to cancel the IO request.  If the original command is completed
 * or the TASK MANAGEMENT command completes the command is moved
 * to the COMPLETION_Q via a E3 event.  The IC_THREAD then processes
 * the COMPLETION_Q and issues the scsi_pkt callback.  This
 * callback can not be processed directly from the RX_THREAD
 * because the callback might call back into the iscsi driver
 * causing a deadlock condition.
 *
 * For more details on the complete CMD state machine reference
 * the state machine diagram in iscsi_cmd.c.  The connection state
 * machine is driven via IO events in this file.  Then session
 * events are driven by the connection events.  For complete
 * details on these state machines reference iscsi_sess.c and
 * iscsi_conn.c
 */


/*
 * +--------------------------------------------------------------------+
 * | io helper routines							|
 * +--------------------------------------------------------------------+
 */

/*
 * n2h24 - native to host 24 bit integer translation.
 */
static uint32_t
n2h24(uchar_t *ptr)
{
	uint32_t idx;
	bcopy(ptr, &idx, 3);
	return (ntohl(idx) >> 8);
}

/*
 * iscsi_sna_lt - Serial Number Arithmetic, 32 bits, less than, RFC1982
 */
static int
iscsi_sna_lt(uint32_t n1, uint32_t n2)
{
	return ((n1 != n2) &&
	    (((n1 < n2) && ((n2 - n1) < ISCSI_SNA32_CHECK)) ||
	    ((n1 > n2) && ((n1 - n2) > ISCSI_SNA32_CHECK))));
}

/*
 * iscsi_sna_lte - Serial Number Arithmetic, 32 bits, less than or equal,
 * RFC1982
 */
int
iscsi_sna_lte(uint32_t n1, uint32_t n2)
{
	return ((n1 == n2) ||
	    (((n1 < n2) && ((n2 - n1) < ISCSI_SNA32_CHECK)) ||
	    ((n1 > n2) && ((n1 - n2) > ISCSI_SNA32_CHECK))));
}

/*
 * iscsi_update_flow_control - Update expcmdsn and maxcmdsn iSCSI
 * flow control information for a session
 */
void
iscsi_update_flow_control(iscsi_sess_t *isp, uint32_t max, uint32_t exp)
{
	ASSERT(isp != NULL);
	ASSERT(mutex_owned(&isp->sess_cmdsn_mutex));

	if (!iscsi_sna_lt(max, (exp - 1))) {

		if (!iscsi_sna_lte(exp, isp->sess_expcmdsn)) {
			isp->sess_expcmdsn = exp;
		}

		if (!iscsi_sna_lte(max, isp->sess_maxcmdsn)) {
			isp->sess_maxcmdsn = max;
			if (iscsi_sna_lte(isp->sess_cmdsn,
			    isp->sess_maxcmdsn)) {
				/*
				 * the window is open again - schedule
				 * to send any held tasks soon
				 */
				iscsi_sess_redrive_io(isp);
			}
		}
	}
}


/*
 * +--------------------------------------------------------------------+
 * | io receive and processing routines					|
 * +--------------------------------------------------------------------+
 */

/*
 * iscsi_rx_scsi_rsp - called from idm
 * For each opcode type fan out the processing.
 */
void
iscsi_rx_scsi_rsp(idm_conn_t *ic, idm_pdu_t *pdu)
{
	iscsi_conn_t	*icp;
	iscsi_sess_t	*isp;
	iscsi_hdr_t	*ihp;
	idm_status_t	status;

	ASSERT(ic != NULL);
	ASSERT(pdu != NULL);
	icp		= ic->ic_handle;
	ASSERT(icp != NULL);
	ihp		= (iscsi_hdr_t *)pdu->isp_hdr;
	ASSERT(ihp != NULL);
	isp		= icp->conn_sess;
	ASSERT(isp != NULL);

	/* reset the session timer when we receive the response */
	isp->sess_rx_lbolt = icp->conn_rx_lbolt = ddi_get_lbolt();

	/* fan out the hdr processing */
	switch (ihp->opcode & ISCSI_OPCODE_MASK) {
	case ISCSI_OP_SCSI_DATA_RSP:
		status = iscsi_rx_process_data_rsp(ic, pdu);
		break;
	case ISCSI_OP_SCSI_RSP:
		status = iscsi_rx_process_cmd_rsp(ic, pdu);
		idm_pdu_complete(pdu, status);
		break;
	default:
		cmn_err(CE_WARN, "iscsi connection(%u) protocol error - "
		    "received pdu with unsupported opcode 0x%02x",
		    icp->conn_oid, ihp->opcode);
		status = IDM_STATUS_PROTOCOL_ERROR;
	}
	iscsi_process_rsp_status(isp, icp, status);
}

void
iscsi_task_cleanup(int opcode, iscsi_cmd_t *icmdp)
{
	struct buf	*bp;
	idm_buf_t	*ibp, *obp;
	idm_task_t	*itp;

	itp = icmdp->cmd_itp;
	ASSERT(itp != NULL);
	ASSERT((opcode == ISCSI_OP_SCSI_DATA_RSP) ||
	    (opcode == ISCSI_OP_SCSI_RSP));

	bp = icmdp->cmd_un.scsi.bp;
	ibp = icmdp->cmd_un.scsi.ibp_ibuf;
	obp = icmdp->cmd_un.scsi.ibp_obuf;
	ISCSI_IO_LOG(CE_NOTE, "DEBUG: task_cleanup: itp: %p opcode: %d "
	    "icmdp: %p bp: %p ibp: %p", (void *)itp, opcode,
	    (void *)icmdp, (void *)bp, (void *)ibp);
	if (bp && bp->b_bcount) {
		if (ibp != NULL && bp->b_flags & B_READ) {
			idm_buf_unbind_in(itp, ibp);
			idm_buf_free(ibp);
			icmdp->cmd_un.scsi.ibp_ibuf = NULL;
		} else if (obp != NULL && !(bp->b_flags & B_READ)) {
			idm_buf_unbind_out(itp, obp);
			idm_buf_free(obp);
			icmdp->cmd_un.scsi.ibp_obuf = NULL;
		}
	}

	idm_task_done(itp);
}

idm_status_t
iscsi_rx_chk(iscsi_conn_t *icp, iscsi_sess_t *isp,
    iscsi_scsi_rsp_hdr_t *irhp, iscsi_cmd_t **icmdp)
{
	iscsi_status_t rval;

	mutex_enter(&isp->sess_cmdsn_mutex);

	if (icp->conn_expstatsn == ntohl(irhp->statsn)) {
		icp->conn_expstatsn++;
	} else {
		cmn_err(CE_WARN, "iscsi connection(%u/%x) protocol error - "
		    "received status out of order itt:0x%x statsn:0x%x "
		    "expstatsn:0x%x", icp->conn_oid, irhp->opcode,
		    irhp->itt, ntohl(irhp->statsn), icp->conn_expstatsn);
		mutex_exit(&isp->sess_cmdsn_mutex);
		return (IDM_STATUS_PROTOCOL_ERROR);
	}

	/* get icmdp so we can cleanup on error */
	if ((irhp->opcode == ISCSI_OP_SCSI_DATA_RSP) ||
	    (irhp->opcode == ISCSI_OP_SCSI_RSP)) {
		rval = iscsi_rx_process_scsi_itt_to_icmdp(isp, icp->conn_ic,
		    irhp, icmdp);
	} else {
		rval = iscsi_rx_process_itt_to_icmdp(isp,
		    (iscsi_hdr_t *)irhp, icmdp);
	}

	if (!ISCSI_SUCCESS(rval)) {
		mutex_exit(&isp->sess_cmdsn_mutex);
		return (IDM_STATUS_PROTOCOL_ERROR);
	}

	/* update expcmdsn and maxcmdsn */
	iscsi_update_flow_control(isp, ntohl(irhp->maxcmdsn),
	    ntohl(irhp->expcmdsn));
	mutex_exit(&isp->sess_cmdsn_mutex);
	return (IDM_STATUS_SUCCESS);
}

static void
iscsi_cmd_rsp_chk(iscsi_cmd_t *icmdp, iscsi_scsi_rsp_hdr_t *issrhp)
{
	struct scsi_pkt *pkt;
	size_t data_transferred;

	pkt = icmdp->cmd_un.scsi.pkt;
	pkt->pkt_resid = 0;
	data_transferred = icmdp->cmd_un.scsi.data_transferred;
	/* Check the residual count */
	if ((icmdp->cmd_un.scsi.bp) &&
	    (data_transferred != icmdp->cmd_un.scsi.bp->b_bcount)) {
		/*
		 * We didn't xfer the expected amount of data -
		 * the residual_count in the header is only
		 * valid if the underflow flag is set.
		 */
		if (issrhp->flags & ISCSI_FLAG_CMD_UNDERFLOW) {
			pkt->pkt_resid = ntohl(issrhp->residual_count);
		} else {
			if (icmdp->cmd_un.scsi.bp->b_bcount >
			    data_transferred) {
				/*
				 * Some data fell on the floor
				 * somehow - probably a CRC error
				 */
				pkt->pkt_resid =
				    icmdp->cmd_un.scsi.bp->b_bcount -
				    data_transferred;
			}
		}
		ISCSI_IO_LOG(CE_NOTE,
		    "DEBUG: iscsi_rx_cmd_rsp_chk: itt: %u"
		    "data_trans != b_count data_transferred: %lu "
		    "b_count: %lu cmd_status: %d flags: %d resid: %lu",
		    issrhp->itt, data_transferred,
		    icmdp->cmd_un.scsi.bp->b_bcount,
		    issrhp->cmd_status & STATUS_MASK,
		    issrhp->flags, pkt->pkt_resid);
	}
	/* set flags that tell SCSA that the command is complete */
	if (icmdp->cmd_crc_error_seen == B_FALSE) {
		/* Set successful completion */
		pkt->pkt_reason = CMD_CMPLT;
		if (icmdp->cmd_un.scsi.bp) {
			pkt->pkt_state |= (STATE_XFERRED_DATA |
			    STATE_GOT_STATUS);
		} else {
			pkt->pkt_state |= STATE_GOT_STATUS;
		}
	} else {
		/*
		 * Some of the data was found to have an incorrect
		 * error at the protocol error.
		 */
		pkt->pkt_reason = CMD_PER_FAIL;
		pkt->pkt_statistics |= STAT_PERR;
		if (icmdp->cmd_un.scsi.bp) {
			pkt->pkt_resid =
			    icmdp->cmd_un.scsi.bp->b_bcount;
		} else {
			pkt->pkt_resid = 0;
		}
	}
}

static boolean_t
iscsi_cmd_rsp_cmd_status(iscsi_cmd_t *icmdp, iscsi_scsi_rsp_hdr_t *issrhp,
    uint8_t *data)
{
	int32_t			dlength;
	struct scsi_arq_status	*arqstat;
	size_t			senselen;
	int32_t			statuslen;
	int32_t			sensebuf_len;
	struct scsi_pkt		*pkt;
	boolean_t		affect = B_FALSE;
	int32_t			senselen_to_copy;

	pkt = icmdp->cmd_un.scsi.pkt;
	dlength = n2h24(issrhp->dlength);

	/*
	 * Process iSCSI Cmd Response Status
	 * RFC 3720 Sectionn 10.4.2.
	 */
	switch (issrhp->cmd_status & STATUS_MASK) {
	case STATUS_GOOD:
		/* pass SCSI status up stack */
		if (pkt->pkt_scbp) {
			pkt->pkt_scbp[0] = issrhp->cmd_status;
		}
		break;
	case STATUS_CHECK:
		/*
		 * Verify we received a sense buffer and
		 * that there is the correct amount of
		 * request sense space to copy it to.
		 */
		if ((dlength > 1) &&
		    (pkt->pkt_scbp != NULL) &&
		    (icmdp->cmd_un.scsi.statuslen >=
		    sizeof (struct scsi_arq_status))) {
			/*
			 * If a bad command status is received we
			 * need to reset the pkt_resid to zero.
			 * The target driver compares its value
			 * before checking other error flags.
			 * (ex. check conditions)
			 */
			pkt->pkt_resid = 0;

			/* get sense length from first 2 bytes */
			senselen = ((data[0] << 8) | data[1]) &
			    (size_t)0xFFFF;
			ISCSI_IO_LOG(CE_NOTE,
			    "DEBUG: iscsi_rx_cmd_rsp_cmd_status status_check: "
			    "dlen: %d scbp: %p statuslen: %d arq: %d senselen:"
			    " %lu", dlength, (void *)pkt->pkt_scbp,
			    icmdp->cmd_un.scsi.statuslen,
			    (int)sizeof (struct scsi_arq_status),
			    senselen);

			/* Sanity-check on the sense length */
			if ((senselen + 2) > dlength) {
				senselen = dlength - 2;
			}

			/*
			 * If there was a Data Digest error then
			 * the sense data cannot be trusted.
			 */
			if (icmdp->cmd_crc_error_seen) {
				senselen = 0;
			}

			/* automatic request sense */
			arqstat =
			    (struct scsi_arq_status *)pkt->pkt_scbp;

			/* pass SCSI status up stack */
			*((uchar_t *)&arqstat->sts_status) =
			    issrhp->cmd_status;

			/*
			 * Set the status for the automatic
			 * request sense command
			 */
			arqstat->sts_rqpkt_state = (STATE_GOT_BUS |
			    STATE_GOT_TARGET | STATE_SENT_CMD |
			    STATE_XFERRED_DATA | STATE_GOT_STATUS |
			    STATE_ARQ_DONE);

			*((uchar_t *)&arqstat->sts_rqpkt_status) =
			    STATUS_GOOD;

			arqstat->sts_rqpkt_reason = CMD_CMPLT;
			statuslen = icmdp->cmd_un.scsi.statuslen;

			if (senselen == 0) {
				/* auto request sense failed */
				arqstat->sts_rqpkt_status.sts_chk = 1;
				arqstat->sts_rqpkt_resid = statuslen;
			} else if (senselen < statuslen) {
				/* auto request sense short */
				arqstat->sts_rqpkt_resid = statuslen - senselen;
			} else {
				/* auto request sense complete */
				arqstat->sts_rqpkt_resid = 0;
			}
			arqstat->sts_rqpkt_statistics = 0;
			pkt->pkt_state |= STATE_ARQ_DONE;

			if (icmdp->cmd_misc_flags & ISCSI_CMD_MISCFLAG_XARQ) {
				pkt->pkt_state |= STATE_XARQ_DONE;
			}

			/*
			 * Calculate size of space reserved for sense data in
			 * pkt->pkt_scbp.
			 */
			sensebuf_len = statuslen - ISCSI_ARQ_STATUS_NOSENSE_LEN;

			/* copy auto request sense */
			senselen_to_copy = min(senselen, sensebuf_len);
			if (senselen_to_copy > 0) {
				bcopy(&data[2], (uchar_t *)&arqstat->
				    sts_sensedata, senselen_to_copy);

				affect = iscsi_decode_sense(
				    (uint8_t *)&arqstat->sts_sensedata, icmdp);
			}
			arqstat->sts_rqpkt_resid = sensebuf_len -
			    senselen_to_copy;
			ISCSI_IO_LOG(CE_NOTE, "DEBUG: iscsi_cmd_rsp_cmd_status:"
			    " sts_rqpkt_resid: %d pkt_scblen: %d senselen: %lu"
			    " sensebuf_len: %d senselen_to_copy: %d affect: %d",
			    arqstat->sts_rqpkt_resid, pkt->pkt_scblen, senselen,
			    sensebuf_len, senselen_to_copy, affect);
			break;
		}
		/* FALLTHRU */
	case STATUS_BUSY:
	case STATUS_RESERVATION_CONFLICT:
	case STATUS_QFULL:
	case STATUS_ACA_ACTIVE:
	default:
		/*
		 * If a bad command status is received we need to
		 * reset the pkt_resid to zero.  The target driver
		 * compares its value before checking other error
		 * flags. (ex. check conditions)
		 */
		ISCSI_IO_LOG(CE_NOTE,
		    "DEBUG: iscsi_rx_cmd_rsp_cmd_status: status: "
		    "%d cmd_status: %d dlen: %u scbp: %p statuslen: %d "
		    "arg_len: %d", issrhp->cmd_status & STATUS_MASK,
		    issrhp->cmd_status, dlength, (void *)pkt->pkt_scbp,
		    icmdp->cmd_un.scsi.statuslen,
		    (int)sizeof (struct scsi_arq_status));
		pkt->pkt_resid = 0;
		/* pass SCSI status up stack */
		if (pkt->pkt_scbp) {
			pkt->pkt_scbp[0] = issrhp->cmd_status;
		}
	}

	return (affect);
}

/*
 * iscsi_rx_process_login_pdup - Process login response PDU.  This function
 * copies the data into the connection context so that the login code can
 * interpret it.
 */

idm_status_t
iscsi_rx_process_login_pdu(idm_conn_t *ic, idm_pdu_t *pdu)
{
	iscsi_conn_t		*icp;

	icp = ic->ic_handle;

	/*
	 * Copy header and data into connection structure so iscsi_login()
	 * can process it.
	 */
	mutex_enter(&icp->conn_login_mutex);
	/*
	 * If conn_login_state != LOGIN_TX then we are not ready to handle
	 * this login response and we should just  drop it.
	 */
	if (icp->conn_login_state == LOGIN_TX) {
		icp->conn_login_datalen = pdu->isp_datalen;
		bcopy(pdu->isp_hdr, &icp->conn_login_resp_hdr,
		    sizeof (iscsi_hdr_t));
		/*
		 * Login code is sloppy with it's NULL handling so make sure
		 * we don't leave any stale data in there.
		 */
		bzero(icp->conn_login_data, icp->conn_login_max_data_length);
		bcopy(pdu->isp_data, icp->conn_login_data,
		    MIN(pdu->isp_datalen, icp->conn_login_max_data_length));
		iscsi_login_update_state_locked(icp, LOGIN_RX);
	}
	mutex_exit(&icp->conn_login_mutex);

	return (IDM_STATUS_SUCCESS);
}

/*
 * iscsi_rx_process_cmd_rsp - Process received scsi command response.  This
 * will contain sense data if the command was not successful.  This data needs
 * to be copied into the scsi_pkt.  Otherwise we just complete the IO.
 */
static idm_status_t
iscsi_rx_process_cmd_rsp(idm_conn_t *ic, idm_pdu_t *pdu)
{
	iscsi_conn_t		*icp	= ic->ic_handle;
	iscsi_sess_t		*isp	= icp->conn_sess;
	iscsi_scsi_rsp_hdr_t	*issrhp	= (iscsi_scsi_rsp_hdr_t *)pdu->isp_hdr;
	uint8_t			*data	= pdu->isp_data;
	iscsi_cmd_t		*icmdp	= NULL;
	struct scsi_pkt		*pkt	= NULL;
	idm_status_t		rval;
	struct buf		*bp;
	boolean_t		flush	= B_FALSE;
	uint32_t		cmd_sn	= 0;
	uint16_t		lun_num = 0;

	/* make sure we get status in order */
	mutex_enter(&icp->conn_queue_active.mutex);

	if ((rval = iscsi_rx_chk(icp, isp, issrhp,
	    &icmdp)) != IDM_STATUS_SUCCESS) {
		if (icmdp != NULL) {
			iscsi_task_cleanup(issrhp->opcode, icmdp);
		}
		mutex_exit(&icp->conn_queue_active.mutex);
		return (rval);
	}

	/*
	 * If we are in "idm aborting" state then we shouldn't continue
	 * to process this command.  By definition this command is no longer
	 * on the active queue so we shouldn't try to remove it either.
	 */
	mutex_enter(&icmdp->cmd_mutex);
	if (icmdp->cmd_state == ISCSI_CMD_STATE_IDM_ABORTING) {
		mutex_exit(&icmdp->cmd_mutex);
		mutex_exit(&icp->conn_queue_active.mutex);
		return (IDM_STATUS_SUCCESS);
	}
	mutex_exit(&icmdp->cmd_mutex);

	/* Get the IDM buffer and bytes transferred */
	bp = icmdp->cmd_un.scsi.bp;
	if (ic->ic_conn_flags & IDM_CONN_USE_SCOREBOARD) {
		/* Transport tracks bytes transferred so use those counts */
		if (bp && (bp->b_flags & B_READ)) {
			icmdp->cmd_un.scsi.data_transferred +=
			    icmdp->cmd_itp->idt_rx_bytes;
		} else {
			icmdp->cmd_un.scsi.data_transferred +=
			    icmdp->cmd_itp->idt_tx_bytes;
		}
	} else {
		/*
		 * Some transports cannot track the bytes transferred on
		 * the initiator side (like iSER) so we have to use the
		 * status info.  If the response field indicates that
		 * the command actually completed then we will assume
		 * the data_transferred value represents the entire buffer
		 * unless the resid field says otherwise.  This is a bit
		 * unintuitive but it's really impossible to know what
		 * has been transferred without detailed consideration
		 * of the SCSI status and sense key and that is outside
		 * the scope of the transport.  Instead the target/class driver
		 * can consider these values along with the resid and figure
		 * it out.  The data_transferred concept is just belt and
		 * suspenders anyway -- RFC 3720 actually explicitly rejects
		 * scoreboarding ("Initiators SHOULD NOT keep track of the
		 * data transferred to or from the target (scoreboarding)")
		 * perhaps for this very reason.
		 */
		if (issrhp->response != 0) {
			icmdp->cmd_un.scsi.data_transferred = 0;
		} else {
			icmdp->cmd_un.scsi.data_transferred =
			    (bp == NULL) ? 0 : bp->b_bcount;
			if (issrhp->flags & ISCSI_FLAG_CMD_UNDERFLOW) {
				icmdp->cmd_un.scsi.data_transferred -=
				    ntohl(issrhp->residual_count);
			}
		}
	}

	ISCSI_CHECK_SCSI_READ(icmdp, issrhp,
	    icmdp->cmd_un.scsi.data_transferred,
	    BP_CHECK_THOROUGH);

	ISCSI_IO_LOG(CE_NOTE, "DEBUG: rx_process_cmd_rsp: ic: %p pdu: %p itt:"
	    " %x expcmdsn: %x sess_cmd: %x sess_expcmdsn: %x data_transfered:"
	    " %lu ibp: %p obp: %p", (void *)ic, (void *)pdu, issrhp->itt,
	    issrhp->expcmdsn, isp->sess_cmdsn, isp->sess_expcmdsn,
	    icmdp->cmd_un.scsi.data_transferred,
	    (void *)icmdp->cmd_un.scsi.ibp_ibuf,
	    (void *)icmdp->cmd_un.scsi.ibp_obuf);

	iscsi_task_cleanup(issrhp->opcode, icmdp);

	if (issrhp->response) {
		/* The target failed the command. */
		ISCSI_IO_LOG(CE_NOTE, "DEBUG: rx_process_cmd_rsp: ic: %p pdu:"
		    " %p response: %d bcount: %lu", (void *)ic, (void *)pdu,
		    issrhp->response, icmdp->cmd_un.scsi.bp->b_bcount);
		pkt = icmdp->cmd_un.scsi.pkt;
		pkt->pkt_reason = CMD_TRAN_ERR;
		if (icmdp->cmd_un.scsi.bp) {
			pkt->pkt_resid = icmdp->cmd_un.scsi.bp->b_bcount;
		} else {
			pkt->pkt_resid = 0;
		}
	} else {
		/* success */
		iscsi_cmd_rsp_chk(icmdp, issrhp);
		flush = iscsi_cmd_rsp_cmd_status(icmdp, issrhp, data);

		ASSERT(icmdp->cmd_lun == NULL || icmdp->cmd_lun->lun_num ==
		    (icmdp->cmd_un.scsi.lun & ISCSI_LUN_MASK));

		if (flush == B_TRUE) {
			cmd_sn = icmdp->cmd_sn;
			lun_num = icmdp->cmd_un.scsi.lun & ISCSI_LUN_MASK;
		}
	}

	iscsi_cmd_state_machine(icmdp, ISCSI_CMD_EVENT_E3, isp);
	if (flush == B_TRUE) {
		iscsi_flush_cmd_after_reset(cmd_sn, lun_num, icp);
	}
	mutex_exit(&icp->conn_queue_active.mutex);
	return (IDM_STATUS_SUCCESS);
}

static void
iscsi_data_rsp_pkt(iscsi_cmd_t *icmdp, iscsi_data_rsp_hdr_t *idrhp)
{
	struct buf		*bp	= NULL;
	size_t			data_transferred;
	struct scsi_pkt		*pkt;

	bp = icmdp->cmd_un.scsi.bp;
	pkt = icmdp->cmd_un.scsi.pkt;
	data_transferred = icmdp->cmd_un.scsi.data_transferred;
	/*
	 * The command* must be completed now, since we won't get a command
	 * response PDU. The cmd_status and residual_count are
	 * not meaningful unless status_present is set.
	 */
	pkt->pkt_resid = 0;
	/* Check the residual count */
	if (bp && (data_transferred != bp->b_bcount)) {
		/*
		 * We didn't xfer the expected amount of data -
		 * the residual_count in the header is only valid
		 * if the underflow flag is set.
		 */
		if (idrhp->flags & ISCSI_FLAG_DATA_UNDERFLOW) {
			pkt->pkt_resid = ntohl(idrhp->residual_count);
			ISCSI_IO_LOG(CE_NOTE, "DEBUG: iscsi_data_rsp_pkt: "
			    "underflow: itt: %d "
			    "transferred: %lu count: %lu", idrhp->itt,
			    data_transferred, bp->b_bcount);
		} else {
			if (bp->b_bcount > data_transferred) {
				/* Some data fell on the floor somehw */
				ISCSI_IO_LOG(CE_NOTE, "DEBUG: "
				    "iscsi_data_rsp_pkt: data fell: itt: %d "
				    "transferred: %lu count: %lu", idrhp->itt,
				    data_transferred, bp->b_bcount);
				pkt->pkt_resid =
				    bp->b_bcount - data_transferred;
			}
		}
	}

	pkt->pkt_reason = CMD_CMPLT;
	pkt->pkt_state |= (STATE_XFERRED_DATA | STATE_GOT_STATUS);

	if (((idrhp->cmd_status & STATUS_MASK) != STATUS_GOOD) &&
	    (icmdp->cmd_un.scsi.statuslen >=
	    sizeof (struct scsi_arq_status)) && pkt->pkt_scbp) {

		/*
		 * Not supposed to get exception status here!
		 * We have no request sense data so just do the
		 * best we can
		 */
		struct scsi_arq_status *arqstat =
		    (struct scsi_arq_status *)pkt->pkt_scbp;


		bzero(arqstat, sizeof (struct scsi_arq_status));

		*((uchar_t *)&arqstat->sts_status) =
		    idrhp->cmd_status;

		/* sense residual is set to whole size of sense buffer */
		arqstat->sts_rqpkt_resid = icmdp->cmd_un.scsi.statuslen -
		    ISCSI_ARQ_STATUS_NOSENSE_LEN;
		ISCSI_IO_LOG(CE_NOTE, "DEBUG: iscsi_data_rsp_pkt: "
		    "exception status: itt: %d resid: %d",
		    idrhp->itt, arqstat->sts_rqpkt_resid);

	} else if (pkt->pkt_scbp) {
		/* just pass along the status we got */
		pkt->pkt_scbp[0] = idrhp->cmd_status;
	}
}

/*
 * iscsi_rx_process_data_rsp -
 * This currently processes the final data sequence denoted by the data response
 * PDU Status bit being set.  We will not receive the SCSI response.
 * This bit denotes that the PDU is the successful completion of the
 * command.
 */
static idm_status_t
iscsi_rx_process_data_rsp(idm_conn_t *ic, idm_pdu_t *pdu)
{
	iscsi_sess_t		*isp	= NULL;
	iscsi_data_rsp_hdr_t	*idrhp	= (iscsi_data_rsp_hdr_t *)pdu->isp_hdr;
	iscsi_cmd_t		*icmdp	= NULL;
	struct buf		*bp	= NULL;
	iscsi_conn_t		*icp	= ic->ic_handle;
	idm_buf_t		*ibp;
	idm_status_t		rval;


	/* should only call this when the data rsp contains final rsp */
	ASSERT(idrhp->flags & ISCSI_FLAG_DATA_STATUS);
	isp = icp->conn_sess;

	mutex_enter(&icp->conn_queue_active.mutex);
	if ((rval = iscsi_rx_chk(icp, isp, (iscsi_scsi_rsp_hdr_t *)idrhp,
	    &icmdp)) != IDM_STATUS_SUCCESS) {
		if (icmdp != NULL) {
			iscsi_task_cleanup(idrhp->opcode, icmdp);
		}
		mutex_exit(&icp->conn_queue_active.mutex);
		return (rval);
	}

	/*
	 * If we are in "idm aborting" state then we shouldn't continue
	 * to process this command.  By definition this command is no longer
	 * on the active queue so we shouldn't try to remove it either.
	 */
	mutex_enter(&icmdp->cmd_mutex);
	if (icmdp->cmd_state == ISCSI_CMD_STATE_IDM_ABORTING) {
		mutex_exit(&icmdp->cmd_mutex);
		mutex_exit(&icp->conn_queue_active.mutex);
		return (IDM_STATUS_SUCCESS);
	}
	mutex_exit(&icmdp->cmd_mutex);

	/*
	 * Holding the pending/active queue locks across the
	 * iscsi_rx_data call later in this function may cause
	 * deadlock during fault injections.  Instead remove
	 * the cmd from the active queue and release the locks.
	 * Then before returning or completing the command
	 * return the cmd to the active queue and reacquire
	 * the locks.
	 */
	iscsi_dequeue_active_cmd(icp, icmdp);

	mutex_exit(&icp->conn_queue_active.mutex);

	/* shorthand some values */
	bp = icmdp->cmd_un.scsi.bp;

	/*
	 * some poorly behaved targets have been observed
	 * sending data-in pdu's during a write operation
	 */
	if (bp != NULL) {
		if (!(bp->b_flags & B_READ)) {
			cmn_err(CE_WARN,
			    "iscsi connection(%u) protocol error - "
			    "received data response during write operation "
			    "itt:0x%x",
			    icp->conn_oid, idrhp->itt);
			mutex_enter(&icp->conn_queue_active.mutex);
			iscsi_enqueue_active_cmd(icp, icmdp);
			mutex_exit(&icp->conn_queue_active.mutex);
			return (IDM_STATUS_PROTOCOL_ERROR);
		}
	}

	ibp = icmdp->cmd_un.scsi.ibp_ibuf;
	if (ibp == NULL) {
		/*
		 * After the check of bp above we *should* have a corresponding
		 * idm_buf_t (ibp).  It's possible that the original call
		 * to idm_buf_alloc failed due to a pending connection state
		 * transition in which case this value can be NULL.  It's
		 * highly unlikely that the connection would be shutting down
		 * *and* we manage to process a data response and get to this
		 * point in the code but just in case we should check for it.
		 * This isn't really a protocol error -- we are almost certainly
		 * closing the connection anyway so just return a generic error.
		 */
		mutex_enter(&icp->conn_queue_active.mutex);
		iscsi_enqueue_active_cmd(icp, icmdp);
		mutex_exit(&icp->conn_queue_active.mutex);
		return (IDM_STATUS_FAIL);
	}

	if (ic->ic_conn_flags & IDM_CONN_USE_SCOREBOARD) {
		icmdp->cmd_un.scsi.data_transferred =
		    icmdp->cmd_itp->idt_rx_bytes;
	} else {
		icmdp->cmd_un.scsi.data_transferred = bp->b_bcount;
		if (idrhp->flags & ISCSI_FLAG_CMD_UNDERFLOW) {
			icmdp->cmd_un.scsi.data_transferred -=
			    ntohl(idrhp->residual_count);
		}
	}

	ISCSI_IO_LOG(CE_NOTE, "DEBUG: rx_process_data_rsp: icp: %p pdu: %p "
	    "itt: %d ibp: %p icmdp: %p xfer_len: %lu transferred: %lu dlen: %u",
	    (void *)icp, (void *)pdu, idrhp->itt, (void *)bp, (void *)icmdp,
	    (ibp == NULL) ? 0 : ibp->idb_xfer_len,
	    icmdp->cmd_un.scsi.data_transferred,
	    n2h24(idrhp->dlength));

	iscsi_task_cleanup(idrhp->opcode, icmdp);

	iscsi_data_rsp_pkt(icmdp, idrhp);

	mutex_enter(&icp->conn_queue_active.mutex);
	iscsi_enqueue_active_cmd(icp, icmdp);
	iscsi_cmd_state_machine(icmdp, ISCSI_CMD_EVENT_E3, isp);
	mutex_exit(&icp->conn_queue_active.mutex);

	return (IDM_STATUS_SUCCESS);
}

/*
 * iscsi_rx_process_nop - Process a received nop.  If nop is in response
 * to a ping we sent update stats.  If initiated by the target we need
 * to response back to the target with a nop.  Schedule the response.
 */
/* ARGSUSED */
static idm_status_t
iscsi_rx_process_nop(idm_conn_t *ic, idm_pdu_t *pdu)
{
	iscsi_sess_t		*isp	= NULL;
	iscsi_nop_in_hdr_t	*inihp	= (iscsi_nop_in_hdr_t *)pdu->isp_hdr;
	iscsi_cmd_t		*icmdp	= NULL;
	iscsi_conn_t		*icp	= ic->ic_handle;

	if (icp->conn_expstatsn != ntohl(inihp->statsn)) {
		cmn_err(CE_WARN, "iscsi connection(%u/%x) protocol error - "
		    "received status out of order itt:0x%x statsn:0x%x "
		    "expstatsn:0x%x", icp->conn_oid, inihp->opcode, inihp->itt,
		    ntohl(inihp->statsn), icp->conn_expstatsn);
		return (IDM_STATUS_PROTOCOL_ERROR);
	}
	isp = icp->conn_sess;
	ASSERT(isp != NULL);
	mutex_enter(&isp->sess_queue_pending.mutex);
	mutex_enter(&icp->conn_queue_active.mutex);
	mutex_enter(&isp->sess_cmdsn_mutex);
	if (inihp->itt != ISCSI_RSVD_TASK_TAG) {
		if (!ISCSI_SUCCESS(iscsi_rx_process_itt_to_icmdp(
		    isp, (iscsi_hdr_t *)inihp, &icmdp))) {
			cmn_err(CE_WARN, "iscsi connection(%u) protocol error "
			    "- can not find cmd for itt:0x%x",
			    icp->conn_oid, inihp->itt);
			mutex_exit(&isp->sess_cmdsn_mutex);
			mutex_exit(&icp->conn_queue_active.mutex);
			mutex_exit(&isp->sess_queue_pending.mutex);
			return (IDM_STATUS_PROTOCOL_ERROR);
		}
	}

	/* update expcmdsn and maxcmdsn */
	iscsi_update_flow_control(isp, ntohl(inihp->maxcmdsn),
	    ntohl(inihp->expcmdsn));
	mutex_exit(&isp->sess_cmdsn_mutex);

	if ((inihp->itt != ISCSI_RSVD_TASK_TAG) &&
	    (inihp->ttt == ISCSI_RSVD_TASK_TAG)) {
		/* This is the only type of nop that incs. the expstatsn */
		icp->conn_expstatsn++;

		/*
		 * This is a targets response to our nop
		 */
		iscsi_cmd_state_machine(icmdp, ISCSI_CMD_EVENT_E3, isp);
	} else if (inihp->ttt != ISCSI_RSVD_TASK_TAG) {
		/*
		 * Target requested a nop.  Send one.
		 */
		iscsi_handle_nop(icp, ISCSI_RSVD_TASK_TAG, inihp->ttt);
	} else {
		/*
		 * This is a target-initiated ping that doesn't expect
		 * a response; nothing to do except update our flow control
		 * (which we do in all cases above).
		 */
		/* EMPTY */
	}
	mutex_exit(&icp->conn_queue_active.mutex);
	mutex_exit(&isp->sess_queue_pending.mutex);

	return (IDM_STATUS_SUCCESS);
}


/*
 * iscsi_rx_process_reject_rsp - The server rejected a PDU
 */
static idm_status_t
iscsi_rx_process_reject_rsp(idm_conn_t *ic, idm_pdu_t *pdu)
{
	iscsi_reject_rsp_hdr_t	*irrhp = (iscsi_reject_rsp_hdr_t *)pdu->isp_hdr;
	iscsi_sess_t		*isp		= NULL;
	uint32_t		dlength		= 0;
	iscsi_hdr_t		*old_ihp	= NULL;
	iscsi_conn_t		*icp		= ic->ic_handle;
	uint8_t			*data		= pdu->isp_data;
	idm_status_t		status		= IDM_STATUS_SUCCESS;
	int			i		= 0;

	ASSERT(data != NULL);
	isp = icp->conn_sess;
	ASSERT(isp != NULL);

	/*
	 * In RFC3720 section 10.17, this 4 bytes should be all 0xff.
	 */
	for (i = 0; i < 4; i++) {
		if (irrhp->must_be_ff[i] != 0xff) {
			return (IDM_STATUS_PROTOCOL_ERROR);
		}
	}
	mutex_enter(&isp->sess_cmdsn_mutex);

	if (icp->conn_expstatsn == ntohl(irrhp->statsn)) {
		icp->conn_expstatsn++;
	} else {
		cmn_err(CE_WARN, "iscsi connection(%u/%x) protocol error - "
		    "received status out of order statsn:0x%x "
		    "expstatsn:0x%x", icp->conn_oid, irrhp->opcode,
		    ntohl(irrhp->statsn), icp->conn_expstatsn);
		mutex_exit(&isp->sess_cmdsn_mutex);
		return (IDM_STATUS_PROTOCOL_ERROR);
	}
	/* update expcmdsn and maxcmdsn */
	iscsi_update_flow_control(isp, ntohl(irrhp->maxcmdsn),
	    ntohl(irrhp->expcmdsn));

	mutex_exit(&isp->sess_cmdsn_mutex);

	/* If we don't have the rejected header we can't do anything */
	dlength = n2h24(irrhp->dlength);
	if (dlength < sizeof (iscsi_hdr_t)) {
		return (IDM_STATUS_PROTOCOL_ERROR);
	}

	/* map old ihp */
	old_ihp = (iscsi_hdr_t *)data;

	switch (irrhp->reason) {
	/*
	 * ISCSI_REJECT_IMM_CMD_REJECT - Immediate Command Reject
	 * too many immediate commands (original cmd can be resent)
	 */
	case ISCSI_REJECT_IMM_CMD_REJECT:
		/*
		 * We have exceeded the server's capacity for outstanding
		 * immediate commands.   This must be a task management
		 * command so try to find it in the abortingqueue and
		 * complete it.
		 */
		if (!(old_ihp->opcode & ISCSI_OP_IMMEDIATE)) {
			/* Rejecting IMM but old old_hdr wasn't IMM */
			return (IDM_STATUS_PROTOCOL_ERROR);
		}

		/*
		 * We only send NOP and TASK_MGT as IMM.  All other
		 * cases should be considered as a protocol error.
		 */
		switch (old_ihp->opcode & ISCSI_OPCODE_MASK) {
		case ISCSI_OP_NOOP_OUT:
			/*
			 * A ping was rejected - treat this like
			 * ping response.  The down side is we
			 * didn't get an updated MaxCmdSn.
			 */
			break;
		case ISCSI_OP_SCSI_TASK_MGT_MSG:
			status =
			    iscsi_rx_process_rejected_tsk_mgt(ic, old_ihp);
			break;
		default:
			cmn_err(CE_WARN, "iscsi connection(%u) protocol error "
			    "- received a reject for a command(0x%02x) not "
			    "sent as an immediate", icp->conn_oid,
			    old_ihp->opcode);
			status = IDM_STATUS_PROTOCOL_ERROR;
			break;
		}
		break;

	/*
	 * For the rest of the reject cases just use the general
	 * hammer of dis/reconnecting.  This will resolve all
	 * noted issues although could be more graceful.
	 */
	case ISCSI_REJECT_DATA_DIGEST_ERROR:
	case ISCSI_REJECT_CMD_BEFORE_LOGIN:
	case ISCSI_REJECT_SNACK_REJECT:
	case ISCSI_REJECT_PROTOCOL_ERROR:
	case ISCSI_REJECT_CMD_NOT_SUPPORTED:
	case ISCSI_REJECT_TASK_IN_PROGRESS:
	case ISCSI_REJECT_INVALID_DATA_ACK:
	case ISCSI_REJECT_INVALID_PDU_FIELD:
	case ISCSI_REJECT_LONG_OPERATION_REJECT:
	case ISCSI_REJECT_NEGOTIATION_RESET:
	default:
		cmn_err(CE_WARN, "iscsi connection(%u/%x) closing connection - "
		    "target requested reason:0x%x",
		    icp->conn_oid, irrhp->opcode, irrhp->reason);
		status = IDM_STATUS_PROTOCOL_ERROR;
		break;
	}

	return (status);
}


/*
 * iscsi_rx_process_rejected_tsk_mgt -
 */
/* ARGSUSED */
static idm_status_t
iscsi_rx_process_rejected_tsk_mgt(idm_conn_t *ic, iscsi_hdr_t *old_ihp)
{
	iscsi_sess_t		*isp	= NULL;
	iscsi_cmd_t		*icmdp	= NULL;
	iscsi_conn_t		*icp	= ic->ic_handle;

	isp = icp->conn_sess;
	ASSERT(old_ihp != NULL);
	ASSERT(isp != NULL);

	mutex_enter(&icp->conn_queue_active.mutex);
	mutex_enter(&isp->sess_cmdsn_mutex);
	if (!ISCSI_SUCCESS(iscsi_rx_process_itt_to_icmdp(
	    isp, old_ihp, &icmdp))) {
		mutex_exit(&isp->sess_cmdsn_mutex);
		mutex_exit(&icp->conn_queue_active.mutex);
		return (IDM_STATUS_PROTOCOL_ERROR);
	}
	mutex_exit(&isp->sess_cmdsn_mutex);

	switch (icmdp->cmd_type) {
	case ISCSI_CMD_TYPE_ABORT:
	case ISCSI_CMD_TYPE_RESET:
		iscsi_cmd_state_machine(icmdp, ISCSI_CMD_EVENT_E4,
		    icp->conn_sess);
		break;
	/* We don't send any other task mgr types */
	default:
		ASSERT(B_FALSE);
		break;
	}
	mutex_exit(&icp->conn_queue_active.mutex);

	return (IDM_STATUS_SUCCESS);
}


/*
 * iscsi_rx_process_task_mgt_rsp -
 */
/* ARGSUSED */
static idm_status_t
iscsi_rx_process_task_mgt_rsp(idm_conn_t *ic, idm_pdu_t *pdu)
{
	iscsi_sess_t			*isp		= NULL;
	iscsi_scsi_task_mgt_rsp_hdr_t	*istmrhp	= NULL;
	iscsi_cmd_t			*icmdp		= NULL;
	iscsi_conn_t			*icp		= ic->ic_handle;
	idm_status_t			status = IDM_STATUS_SUCCESS;

	isp = icp->conn_sess;
	istmrhp = (iscsi_scsi_task_mgt_rsp_hdr_t *)pdu->isp_hdr;

	mutex_enter(&icp->conn_queue_active.mutex);
	if ((status = iscsi_rx_chk(icp, isp, (iscsi_scsi_rsp_hdr_t *)istmrhp,
	    &icmdp)) != IDM_STATUS_SUCCESS) {
		mutex_exit(&icp->conn_queue_active.mutex);
		return (status);
	}

	switch (icmdp->cmd_type) {
	case ISCSI_CMD_TYPE_ABORT:
	case ISCSI_CMD_TYPE_RESET:
		switch (istmrhp->response) {
		case SCSI_TCP_TM_RESP_COMPLETE:
			/* success */
			iscsi_cmd_state_machine(icmdp,
			    ISCSI_CMD_EVENT_E3, isp);
			break;
		case SCSI_TCP_TM_RESP_NO_TASK:
			/*
			 * If the array no longer knows about
			 * an ABORT RTT and we no longer have
			 * a parent SCSI command it was just
			 * completed, free this ABORT resource.
			 * Otherwise FALLTHRU this will flag a
			 * protocol problem.
			 */
			if ((icmdp->cmd_type == ISCSI_CMD_TYPE_ABORT) &&
			    (icmdp->cmd_un.abort.icmdp == NULL)) {
				iscsi_cmd_state_machine(icmdp,
				    ISCSI_CMD_EVENT_E4, isp);
				break;
			}
			/* FALLTHRU */
		case SCSI_TCP_TM_RESP_REJECTED:
			/*
			 * If the target rejects our reset task,
			 * we should record the response and complete
			 * this command with the result.
			 */
			if (icmdp->cmd_type == ISCSI_CMD_TYPE_RESET) {
				icmdp->cmd_un.reset.response =
				    istmrhp->response;
				iscsi_cmd_state_machine(icmdp,
				    ISCSI_CMD_EVENT_E3, isp);
				break;
			}
			/* FALLTHRU */
		case SCSI_TCP_TM_RESP_NO_LUN:
		case SCSI_TCP_TM_RESP_TASK_ALLEGIANT:
		case SCSI_TCP_TM_RESP_NO_FAILOVER:
		case SCSI_TCP_TM_RESP_IN_PRGRESS:
		default:
			/*
			 * Something is out of sync.  Flush
			 * active queues and resync the
			 * the connection to try and recover
			 * to a known state.
			 */
			status = IDM_STATUS_PROTOCOL_ERROR;
		}
		break;

	default:
		cmn_err(CE_WARN, "iscsi connection(%u) protocol error - "
		    "received a task mgt response for a non-task mgt "
		    "cmd itt:0x%x type:%d", icp->conn_oid, istmrhp->itt,
		    icmdp->cmd_type);
		status = IDM_STATUS_PROTOCOL_ERROR;
		break;
	}

	mutex_exit(&icp->conn_queue_active.mutex);
	return (status);
}


/*
 * iscsi_rx_process_logout_rsp -
 *
 */
/* ARGSUSED */
idm_status_t
iscsi_rx_process_logout_rsp(idm_conn_t *ic, idm_pdu_t *pdu)
{
	iscsi_conn_t		*icp	= ic->ic_handle;
	iscsi_logout_rsp_hdr_t	*ilrhp	=
	    (iscsi_logout_rsp_hdr_t *)pdu->isp_hdr;
	iscsi_cmd_t		*icmdp	= NULL;
	iscsi_sess_t		*isp;
	idm_status_t		status = IDM_STATUS_SUCCESS;

	isp = icp->conn_sess;

	if (icp->conn_expstatsn != ntohl(ilrhp->statsn)) {
		cmn_err(CE_WARN, "iscsi connection(%u/%x) protocol error - "
		    "received status out of order itt:0x%x statsn:0x%x "
		    "expstatsn:0x%x", icp->conn_oid, ilrhp->opcode, ilrhp->itt,
		    ntohl(ilrhp->statsn), icp->conn_expstatsn);
		return (IDM_STATUS_PROTOCOL_ERROR);
	}

	mutex_enter(&icp->conn_queue_active.mutex);
	mutex_enter(&isp->sess_cmdsn_mutex);
	if (ilrhp->itt != ISCSI_RSVD_TASK_TAG) {
		if (!ISCSI_SUCCESS(iscsi_rx_process_itt_to_icmdp(
		    isp, (iscsi_hdr_t *)ilrhp, &icmdp))) {
			mutex_exit(&isp->sess_cmdsn_mutex);
			mutex_exit(&icp->conn_queue_active.mutex);
			return (IDM_STATUS_PROTOCOL_ERROR);
		}
	}

	/* update expcmdsn and maxcmdsn */
	iscsi_update_flow_control(isp, ntohl(ilrhp->maxcmdsn),
	    ntohl(ilrhp->expcmdsn));
	mutex_exit(&isp->sess_cmdsn_mutex);

	ISCSI_IO_LOG(CE_NOTE,
	    "DEBUG: iscsi_rx_process_logout_rsp: response: %d",
	    ilrhp->response);
	switch (ilrhp->response) {
	case ISCSI_LOGOUT_CID_NOT_FOUND:
		/*
		 * If the target doesn't know about our connection
		 * then we can consider our self disconnected.
		 */
		/* FALLTHRU */
	case ISCSI_LOGOUT_RECOVERY_UNSUPPORTED:
		/*
		 * We don't support ErrorRecovery levels above 0
		 * currently so consider this success.
		 */
		/* FALLTHRU */
	case ISCSI_LOGOUT_CLEANUP_FAILED:
		/*
		 * per spec. "cleanup failed for various reasons."
		 * Although those various reasons are undefined.
		 * Not sure what to do here.  So fake success,
		 * which will disconnect the connection.
		 */
		/* FALLTHRU */
	case ISCSI_LOGOUT_SUCCESS:
		iscsi_cmd_state_machine(icmdp, ISCSI_CMD_EVENT_E3, isp);
		mutex_exit(&icp->conn_queue_active.mutex);
		iscsi_drop_conn_cleanup(icp);
		break;
	default:
		mutex_exit(&icp->conn_queue_active.mutex);
		status = IDM_STATUS_PROTOCOL_ERROR;
		break;

	}
	return (status);
}

/*
 * iscsi_rx_process_async_rsp
 *
 */
/* ARGSUSED */
static idm_status_t
iscsi_rx_process_async_rsp(idm_conn_t *ic, idm_pdu_t *pdu)
{
	iscsi_conn_t		*icp	= ic->ic_handle;
	iscsi_sess_t		*isp	= icp->conn_sess;
	idm_status_t		rval	= IDM_STATUS_SUCCESS;
	iscsi_task_t		*itp;
	iscsi_async_evt_hdr_t	*iaehp	=
	    (iscsi_async_evt_hdr_t *)pdu->isp_hdr;

	ASSERT(icp != NULL);
	ASSERT(pdu != NULL);
	ASSERT(isp != NULL);

	mutex_enter(&isp->sess_cmdsn_mutex);
	if (icp->conn_expstatsn == ntohl(iaehp->statsn)) {
		icp->conn_expstatsn++;
	} else {
		cmn_err(CE_WARN, "iscsi connection(%u) protocol error - "
		    "received status out of order statsn:0x%x "
		    "expstatsn:0x%x", icp->conn_oid,
		    ntohl(iaehp->statsn), icp->conn_expstatsn);
		mutex_exit(&isp->sess_cmdsn_mutex);
		return (IDM_STATUS_PROTOCOL_ERROR);
	}
	mutex_exit(&isp->sess_cmdsn_mutex);

	switch (iaehp->async_event) {
	case ISCSI_ASYNC_EVENT_SCSI_EVENT:
		/*
		 * SCSI asynchronous event is reported in
		 * the sense data.  Sense data that accompanies
		 * the report in the data segment identifies the
		 * condition.  If the target supports SCSI
		 * asynchronous events reporting (see [SAM2])
		 * as indicated in the stardard INQUIRY data
		 * (see [SPC3]), its use may be enabled by
		 * parameters in the SCSI control mode page
		 * (see [SPC3]).
		 *
		 * T-10 has removed SCSI asunchronous events
		 * from the standard.  Although we have seen
		 * a couple targets still spending these requests.
		 * Those targets were specifically sending them
		 * for notification of a LUN/Volume change
		 * (ex. LUN addition/removal). Fire the enumeration
		 * to handle the change.
		 */
		if (isp->sess_type == ISCSI_SESS_TYPE_NORMAL) {
			rw_enter(&isp->sess_state_rwlock, RW_READER);
			if (isp->sess_state == ISCSI_SESS_STATE_LOGGED_IN) {
				(void) iscsi_sess_enum_request(isp, B_FALSE,
				    isp->sess_state_event_count);
			}
			rw_exit(&isp->sess_state_rwlock);
		}
		break;

	case ISCSI_ASYNC_EVENT_REQUEST_LOGOUT:
		/*
		 * We've been asked to logout by the target --
		 * we need to treat this differently from a normal logout
		 * due to a discovery failure.  Normal logouts result in
		 * an N3 event to the session state machine and an offline
		 * of the lun.  In this case we want to put the connection
		 * into "failed" state and generate N5 to the session state
		 * machine since the initiator logged out at the target's
		 * request.  To track this we set a flag indicating we
		 * received this async logout request from the tharget
		 */
		mutex_enter(&icp->conn_state_mutex);
		icp->conn_async_logout = B_TRUE;
		mutex_exit(&icp->conn_state_mutex);

		/* Hold is released in iscsi_handle_logout. */
		idm_conn_hold(ic);

		/* Target has requested this connection to logout. */
		itp = kmem_zalloc(sizeof (iscsi_task_t), KM_SLEEP);
		itp->t_arg = icp;
		itp->t_blocking = B_FALSE;
		if (ddi_taskq_dispatch(isp->sess_login_taskq,
		    (void(*)())iscsi_logout_start, itp, DDI_SLEEP) !=
		    DDI_SUCCESS) {
			idm_conn_rele(ic);
			/* Disconnect if we couldn't dispatch the task */
			idm_ini_conn_disconnect(ic);
		}
		break;

	case ISCSI_ASYNC_EVENT_DROPPING_CONNECTION:
		/*
		 * Target is going to drop our connection.
		 *	param1 - CID which will be dropped.
		 *	param2 - Min time to reconnect.
		 *	param3 - Max time to reconnect.
		 *
		 * For now just let fail as another disconnect.
		 *
		 * MC/S Once we support > 1 connections then
		 * we need to check the CID and drop that
		 * specific connection.
		 */
		iscsi_conn_set_login_min_max(icp, iaehp->param2,
		    iaehp->param3);
		idm_ini_conn_disconnect(ic);
		break;

	case ISCSI_ASYNC_EVENT_DROPPING_ALL_CONNECTIONS:
		/*
		 * Target is going to drop ALL connections.
		 *	param2 - Min time to reconnect.
		 *	param3 - Max time to reconnect.
		 *
		 * For now just let fail as anyother disconnect.
		 *
		 * MC/S Once we support more than > 1 connections
		 * then we need to drop all connections on the
		 * session.
		 */
		iscsi_conn_set_login_min_max(icp, iaehp->param2,
		    iaehp->param3);
		idm_ini_conn_disconnect(ic);
		break;

	case ISCSI_ASYNC_EVENT_PARAM_NEGOTIATION:
		/*
		 * Target requests parameter negotiation
		 * on this connection.
		 *
		 * The initiator must honor this request.  For
		 * now we will request a logout.  We can't
		 * just ignore this or it might force corruption?
		 */

		/* Hold is released in iscsi_handle_logout */
		idm_conn_hold(ic);
		itp = kmem_zalloc(sizeof (iscsi_task_t), KM_SLEEP);
		itp->t_arg = icp;
		itp->t_blocking = B_FALSE;
		if (ddi_taskq_dispatch(isp->sess_login_taskq,
		    (void(*)())iscsi_logout_start, itp, DDI_SLEEP) !=
		    DDI_SUCCESS) {
			/* Disconnect if we couldn't dispatch the task */
			idm_conn_rele(ic);
			idm_ini_conn_disconnect(ic);
		}
		break;

	case ISCSI_ASYNC_EVENT_VENDOR_SPECIFIC:
		/*
		 * We currently don't handle any vendor
		 * specific async events.  So just ignore
		 * the request.
		 */
		idm_ini_conn_disconnect(ic);
		break;
	default:
		rval = IDM_STATUS_PROTOCOL_ERROR;
	}

	return (rval);
}

/*
 * iscsi_rx_process_text_rsp - processes iSCSI text response.  It sets
 * the cmd_result field of the command data structure with the actual
 * status value instead of returning the status value.  The return value
 * is SUCCESS in order to let iscsi_handle_text control the operation of
 * a text request.
 * Text requests are a handled a little different than other types of
 * iSCSI commands because the initiator sends additional empty text requests
 * in order to obtain the remaining responses required to complete the
 * request.  iscsi_handle_text controls the operation of text request, while
 * iscsi_rx_process_text_rsp just process the current response.
 */
static idm_status_t
iscsi_rx_process_text_rsp(idm_conn_t *ic, idm_pdu_t *pdu)
{
	iscsi_sess_t		*isp	= NULL;
	iscsi_text_rsp_hdr_t	*ithp	=
	    (iscsi_text_rsp_hdr_t *)pdu->isp_hdr;
	iscsi_conn_t		*icp	= ic->ic_handle;
	iscsi_cmd_t		*icmdp	= NULL;
	boolean_t		final	= B_FALSE;
	uint32_t		data_len;
	uint8_t			*data = pdu->isp_data;
	idm_status_t		rval;

	isp = icp->conn_sess;

	mutex_enter(&icp->conn_queue_active.mutex);
	if ((rval = iscsi_rx_chk(icp, isp, (iscsi_scsi_rsp_hdr_t *)ithp,
	    &icmdp)) != IDM_STATUS_SUCCESS) {
		mutex_exit(&icp->conn_queue_active.mutex);
		return (rval);
	}

	/* update local final response flag */
	if (ithp->flags & ISCSI_FLAG_FINAL) {
		final = B_TRUE;
	}

	/*
	 * validate received TTT value.  RFC3720 specifies the following:
	 * - F bit set to 1 MUST have a reserved TTT value 0xffffffff
	 * - F bit set to 0 MUST have a non-reserved TTT value !0xffffffff
	 * In addition, the received TTT value must not change between
	 * responses of a long text response
	 */
	if (((final == B_TRUE) && (ithp->ttt != ISCSI_RSVD_TASK_TAG)) ||
	    ((final == B_FALSE) && (ithp->ttt == ISCSI_RSVD_TASK_TAG))) {
		icmdp->cmd_result = ISCSI_STATUS_PROTOCOL_ERROR;
		icmdp->cmd_un.text.stage = ISCSI_CMD_TEXT_FINAL_RSP;
		mutex_exit(&icp->conn_queue_active.mutex);
		cmn_err(CE_WARN, "iscsi connection(%u) protocol error - "
		    "received text response with invalid flags:0x%x or "
		    "ttt:0x%x", icp->conn_oid, ithp->flags, ithp->itt);
		return (IDM_STATUS_PROTOCOL_ERROR);
	}

	if ((icmdp->cmd_un.text.stage == ISCSI_CMD_TEXT_INITIAL_REQ) &&
	    (ithp->ttt == ISCSI_RSVD_TASK_TAG) &&
	    (final == B_FALSE)) {
		/* TTT should have matched reserved value */
		icmdp->cmd_result = ISCSI_STATUS_PROTOCOL_ERROR;
		icmdp->cmd_un.text.stage = ISCSI_CMD_TEXT_FINAL_RSP;
		mutex_exit(&icp->conn_queue_active.mutex);
		cmn_err(CE_WARN, "iscsi connection(%u) protocol "
		    "error - received text response with invalid "
		    "ttt:0x%x", icp->conn_oid, ithp->ttt);
		return (IDM_STATUS_PROTOCOL_ERROR);
	}

	/*
	 * If this is first response, save away TTT value for later use
	 * in a long text request/response sequence
	 */
	if (icmdp->cmd_un.text.stage == ISCSI_CMD_TEXT_INITIAL_REQ) {
		icmdp->cmd_un.text.ttt = ithp->ttt;
	}

	data_len = ntoh24(ithp->dlength);

	/* check whether enough buffer available to copy data */
	if ((icmdp->cmd_un.text.total_rx_len + data_len) >
	    icmdp->cmd_un.text.buf_len) {
		icmdp->cmd_un.text.total_rx_len += data_len;
		icmdp->cmd_result = ISCSI_STATUS_DATA_OVERFLOW;
		/*
		 * DATA_OVERFLOW will result in a SUCCESS return so that
		 * iscsi_handle_text can continue to obtain the remaining
		 * text response if needed.
		 */
	} else {
		char *buf_data = (icmdp->cmd_un.text.buf +
		    icmdp->cmd_un.text.offset);

		bcopy(data, buf_data, data_len);
		icmdp->cmd_un.text.offset += data_len;
		icmdp->cmd_un.text.total_rx_len += data_len;
		icmdp->cmd_result = ISCSI_STATUS_SUCCESS;
		bcopy(ithp->rsvd4, icmdp->cmd_un.text.lun,
		    sizeof (icmdp->cmd_un.text.lun));
	}

	/* update stage  */
	if (final == B_TRUE) {
		icmdp->cmd_un.text.stage = ISCSI_CMD_TEXT_FINAL_RSP;
	} else {
		icmdp->cmd_un.text.stage = ISCSI_CMD_TEXT_CONTINUATION;
	}

	iscsi_cmd_state_machine(icmdp, ISCSI_CMD_EVENT_E3, isp);
	mutex_exit(&icp->conn_queue_active.mutex);
	return (IDM_STATUS_SUCCESS);
}

/*
 * iscsi_rx_process_scsi_itt_to_icmdp - Lookup itt using IDM to find matching
 * icmdp.  Verify itt in hdr and icmdp are the same.
 */
static iscsi_status_t
iscsi_rx_process_scsi_itt_to_icmdp(iscsi_sess_t *isp, idm_conn_t *ic,
    iscsi_scsi_rsp_hdr_t *ihp, iscsi_cmd_t **icmdp)
{
	idm_task_t *itp;

	ASSERT(isp != NULL);
	ASSERT(ihp != NULL);
	ASSERT(icmdp != NULL);
	ASSERT(mutex_owned(&isp->sess_cmdsn_mutex));
	itp = idm_task_find_and_complete(ic, ihp->itt, ISCSI_INI_TASK_TTT);
	if (itp == NULL) {
		cmn_err(CE_WARN, "iscsi session(%u) protocol error - "
		    "received unknown itt:0x%x - protocol error",
		    isp->sess_oid, ihp->itt);
		return (ISCSI_STATUS_INTERNAL_ERROR);
	}
	*icmdp = itp->idt_private;

	idm_task_rele(itp);

	return (ISCSI_STATUS_SUCCESS);

}

/*
 * iscsi_rx_process_itt_to_icmdp - Lookup itt in the session's
 * cmd table to find matching icmdp.  Verify itt in hdr and
 * icmdp are the same.
 */
static iscsi_status_t
iscsi_rx_process_itt_to_icmdp(iscsi_sess_t *isp, iscsi_hdr_t *ihp,
    iscsi_cmd_t **icmdp)
{
	int cmd_table_idx = 0;

	ASSERT(isp != NULL);
	ASSERT(ihp != NULL);
	ASSERT(icmdp != NULL);
	ASSERT(mutex_owned(&isp->sess_cmdsn_mutex));

	/* try to find an associated iscsi_pkt */
	cmd_table_idx = (ihp->itt - IDM_TASKIDS_MAX) % ISCSI_CMD_TABLE_SIZE;
	if (isp->sess_cmd_table[cmd_table_idx] == NULL) {
		cmn_err(CE_WARN, "iscsi session(%u) protocol error - "
		    "received unknown itt:0x%x - protocol error",
		    isp->sess_oid, ihp->itt);
		return (ISCSI_STATUS_INTERNAL_ERROR);
	}

	/* verify itt */
	if (isp->sess_cmd_table[cmd_table_idx]->cmd_itt != ihp->itt) {
		cmn_err(CE_WARN, "iscsi session(%u) received itt:0x%x "
		    " which is out of sync with itt:0x%x", isp->sess_oid,
		    ihp->itt, isp->sess_cmd_table[cmd_table_idx]->cmd_itt);
		return (ISCSI_STATUS_INTERNAL_ERROR);
	}

	/* ensure that icmdp is still in Active state */
	if (isp->sess_cmd_table[cmd_table_idx]->cmd_state !=
	    ISCSI_CMD_STATE_ACTIVE) {
		cmn_err(CE_WARN, "iscsi session(%u) received itt:0x%x "
		    "but icmdp (%p) is not in active state",
		    isp->sess_oid, ihp->itt,
		    (void *)isp->sess_cmd_table[cmd_table_idx]);
		return (ISCSI_STATUS_INTERNAL_ERROR);
	}

	/* make sure this is a SCSI cmd */
	*icmdp = isp->sess_cmd_table[cmd_table_idx];

	return (ISCSI_STATUS_SUCCESS);
}

/*
 * +--------------------------------------------------------------------+
 * | End of protocol receive routines					|
 * +--------------------------------------------------------------------+
 */

/*
 * +--------------------------------------------------------------------+
 * | Beginning of protocol send routines				|
 * +--------------------------------------------------------------------+
 */


/*
 * iscsi_tx_thread - This thread is the driving point for all
 * iSCSI PDUs after login.  No PDUs should call idm_pdu_tx()
 * directly they should be funneled through iscsi_tx_thread.
 */
void
iscsi_tx_thread(iscsi_thread_t *thread, void *arg)
{
	iscsi_conn_t	*icp	= (iscsi_conn_t *)arg;
	iscsi_sess_t	*isp	= NULL;
	iscsi_cmd_t	*icmdp	= NULL;
	clock_t		tout;
	int		ret	= 1;

	ASSERT(icp != NULL);
	isp = icp->conn_sess;
	ASSERT(isp != NULL);
	ASSERT(thread != NULL);
	ASSERT(thread->signature == SIG_ISCSI_THREAD);

	tout = SEC_TO_TICK(1);
	/*
	 * Transfer icmdps until shutdown by owning session.
	 */
	while (ret != 0) {

		isp->sess_window_open = B_TRUE;
		/*
		 * While the window is open, there are commands available
		 * to send and the session state allows those commands to
		 * be sent try to transfer them.
		 */
		mutex_enter(&isp->sess_queue_pending.mutex);
		while ((isp->sess_window_open == B_TRUE) &&
		    ((icmdp = isp->sess_queue_pending.head) != NULL)) {
			if (((icmdp->cmd_type != ISCSI_CMD_TYPE_SCSI) &&
			    (ISCSI_CONN_STATE_FULL_FEATURE(icp->conn_state))) ||
			    (icp->conn_state == ISCSI_CONN_STATE_LOGGED_IN)) {

				/* update command with this connection info */
				icmdp->cmd_conn = icp;
				/* attempt to send this command */
				iscsi_cmd_state_machine(icmdp,
				    ISCSI_CMD_EVENT_E2, isp);

				ASSERT(!mutex_owned(
				    &isp->sess_queue_pending.mutex));
				mutex_enter(&isp->sess_queue_pending.mutex);
			} else {
				while (icmdp != NULL) {
					if ((icmdp->cmd_type !=
					    ISCSI_CMD_TYPE_SCSI) &&
					    (ISCSI_CONN_STATE_FULL_FEATURE
					    (icp->conn_state) != B_TRUE)) {
						icmdp->cmd_misc_flags |=
						    ISCSI_CMD_MISCFLAG_STUCK;
					} else if (icp->conn_state !=
					    ISCSI_CONN_STATE_LOGGED_IN) {
						icmdp->cmd_misc_flags |=
						    ISCSI_CMD_MISCFLAG_STUCK;
					}
					icmdp = icmdp->cmd_next;
				}
				break;
			}
		}
		mutex_exit(&isp->sess_queue_pending.mutex);

		/*
		 * Go to sleep until there is something new
		 * to process (awoken via cv_boardcast).
		 * Or the timer goes off.
		 */
		ret = iscsi_thread_wait(thread, tout);
	}

}


/*
 * iscsi_tx_cmd - transfers icmdp across wire as iscsi pdu
 *
 * Just prior to sending the command to the networking layer the
 * pending queue lock will be dropped.  At this point only local
 * resources will be used, not the icmdp.  Holding the queue lock
 * across the networking call can lead to a hang.  (This is due
 * to the the target driver and networking layers competing use
 * of the timeout() resources and the queue lock being held for
 * both sides.)  Upon the completion of this command the lock
 * will have been re-acquired.
 */
iscsi_status_t
iscsi_tx_cmd(iscsi_sess_t *isp, iscsi_cmd_t *icmdp)
{
	iscsi_status_t	rval = ISCSI_STATUS_INTERNAL_ERROR;

	ASSERT(isp != NULL);
	ASSERT(icmdp != NULL);

	/* transfer specific command type */
	switch (icmdp->cmd_type) {
	case ISCSI_CMD_TYPE_SCSI:
		rval = iscsi_tx_scsi(isp, icmdp);
		break;
	case ISCSI_CMD_TYPE_NOP:
		rval = iscsi_tx_nop(isp, icmdp);
		break;
	case ISCSI_CMD_TYPE_ABORT:
		rval = iscsi_tx_abort(isp, icmdp);
		break;
	case ISCSI_CMD_TYPE_RESET:
		rval = iscsi_tx_reset(isp, icmdp);
		break;
	case ISCSI_CMD_TYPE_LOGOUT:
		rval = iscsi_tx_logout(isp, icmdp);
		break;
	case ISCSI_CMD_TYPE_TEXT:
		rval = iscsi_tx_text(isp, icmdp);
		break;
	default:
		cmn_err(CE_WARN, "iscsi_tx_cmd: invalid cmdtype: %d",
		    icmdp->cmd_type);
		ASSERT(FALSE);
	}

	ASSERT(!mutex_owned(&isp->sess_queue_pending.mutex));
	return (rval);
}

/*
 * a variable length cdb can be up to 16K, but we obviously don't want
 * to put that on the stack; go with 200 bytes; if we get something
 * bigger than that we will kmem_alloc a buffer
 */
#define	DEF_CDB_LEN	200

/*
 * given the size of the cdb, return how many bytes the header takes,
 * which is the sizeof addl_hdr_t + the CDB size, minus the 16 bytes
 * stored in the basic header, minus sizeof (ahs_extscb)
 */
#define	ADDLHDRSZ(x)		(sizeof (iscsi_addl_hdr_t) + (x) - \
					16 - 4)

static void
iscsi_tx_init_hdr(iscsi_sess_t *isp, iscsi_conn_t *icp,
    iscsi_text_hdr_t *ihp, int opcode, iscsi_cmd_t *icmdp)
{
	ihp->opcode		= opcode;
	ihp->itt		= icmdp->cmd_itt;
	mutex_enter(&isp->sess_cmdsn_mutex);
	icmdp->cmd_sn		= isp->sess_cmdsn;
	ihp->cmdsn		= htonl(isp->sess_cmdsn);
	isp->sess_cmdsn++;
	mutex_exit(&isp->sess_cmdsn_mutex);
	ihp->expstatsn		= htonl(icp->conn_expstatsn);
	icp->conn_laststatsn = icp->conn_expstatsn;
}


static void
iscsi_tx_scsi_data(iscsi_cmd_t *icmdp, iscsi_scsi_cmd_hdr_t *ihp,
    iscsi_conn_t *icp, idm_pdu_t *pdu)
{
	struct buf		*bp		= NULL;
	size_t			buflen		= 0;
	uint32_t		first_burst_length = 0;
	struct scsi_pkt		*pkt;

	pkt = icmdp->cmd_un.scsi.pkt;
	bp = icmdp->cmd_un.scsi.bp;
	if ((bp != NULL) && bp->b_bcount) {
		buflen = bp->b_bcount;
		first_burst_length =
		    icp->conn_params.first_burst_length;

		if (bp->b_flags & B_READ) {
			ihp->flags = ISCSI_FLAG_FINAL;
			/*
			 * fix problem where OS sends bp (B_READ &
			 * b_bcount!=0) for a TUR or START_STOP.
			 * (comment came from cisco code.)
			 */
			if ((pkt->pkt_cdbp[0] != SCMD_TEST_UNIT_READY) &&
			    (pkt->pkt_cdbp[0] != SCMD_START_STOP)) {
				ihp->flags |= ISCSI_FLAG_CMD_READ;
				ihp->data_length = htonl(buflen);
			}
		} else {
			ihp->flags = ISCSI_FLAG_CMD_WRITE;
			/*
			 * FinalBit on the the iSCSI PDU denotes this
			 * is the last PDU in the sequence.
			 *
			 * initial_r2t = true means R2T is required
			 * for additional PDU, so there will be no more
			 * unsolicited PDUs following
			 */
			if (icp->conn_params.initial_r2t) {
				ihp->flags |= ISCSI_FLAG_FINAL;
			}

			/* Check if we should send ImmediateData */
			if (icp->conn_params.immediate_data) {
				pdu->isp_data =
				    (uint8_t *)icmdp->
				    cmd_un.scsi.bp->b_un.b_addr;

				pdu->isp_datalen = MIN(MIN(buflen,
				    first_burst_length),
				    icmdp->cmd_conn->conn_params.
				    max_xmit_data_seg_len);

				/*
				 * if everything fits immediate, or
				 * we can send all burst data immediate
				 * (not unsol), set F
				 */
				/*
				 * XXX This doesn't look right -- it's not
				 * clear how we can handle transmitting
				 * any unsolicited data.  It looks like
				 * we only support immediate data.  So what
				 * happens if we don't set ISCSI_FLAG_FINAL?
				 *
				 * Unless there's magic code somewhere that
				 * is sending the remaining PDU's we should
				 * simply set ISCSI_FLAG_FINAL and forget
				 * about sending unsolicited data.  The big
				 * win is the immediate data anyway for small
				 * PDU's.
				 */
				if ((pdu->isp_datalen == buflen) ||
				    (pdu->isp_datalen == first_burst_length)) {
					ihp->flags |= ISCSI_FLAG_FINAL;
				}

				hton24(ihp->dlength, pdu->isp_datalen);
			}
			/* total data transfer length */
			ihp->data_length = htonl(buflen);
		}
	} else {
		ihp->flags = ISCSI_FLAG_FINAL;
	}
	icmdp->cmd_un.scsi.data_transferred += pdu->isp_datalen;
	/* XXX How is this different from the code above? */
	/* will idm send the next data command up to burst length? */
	/* send the burstlen if we haven't sent immediate data */
	/* CRM: should idm send difference min(buflen, first_burst) and  imm? */
	/*    (MIN(first_burst_length, buflen) - imdata > 0) */
	/* CRM_LATER: change this to generate unsolicited pdu */
	if ((buflen > 0) &&
	    ((bp->b_flags & B_READ) == 0) &&
	    (icp->conn_params.initial_r2t == 0) &&
	    pdu->isp_datalen == 0) {

		pdu->isp_datalen = MIN(first_burst_length, buflen);
		if ((pdu->isp_datalen == buflen) ||
		    (pdu->isp_datalen == first_burst_length)) {
			ihp->flags |= ISCSI_FLAG_FINAL;
		}
		pdu->isp_data = (uint8_t *)icmdp->cmd_un.scsi.bp->b_un.b_addr;
		hton24(ihp->dlength, pdu->isp_datalen);
	}
}

static void
iscsi_tx_scsi_init_pkt(iscsi_cmd_t *icmdp, iscsi_scsi_cmd_hdr_t *ihp)
{
	struct scsi_pkt *pkt;

	pkt = icmdp->cmd_un.scsi.pkt;
	pkt->pkt_state = (STATE_GOT_BUS | STATE_GOT_TARGET);
	pkt->pkt_reason = CMD_INCOMPLETE;

	/* tagged queuing */
	if (pkt->pkt_flags & FLAG_HTAG) {
		ihp->flags |= ISCSI_ATTR_HEAD_OF_QUEUE;
	} else if (pkt->pkt_flags & FLAG_OTAG) {
		ihp->flags |= ISCSI_ATTR_ORDERED;
	} else if (pkt->pkt_flags & FLAG_STAG) {
		ihp->flags |= ISCSI_ATTR_SIMPLE;
	} else {
		/* ihp->flags |= ISCSI_ATTR_UNTAGGED; */
		/* EMPTY */
	}

	/* iscsi states lun is based on spc.2 */
	ISCSI_LUN_BYTE_COPY(ihp->lun, icmdp->cmd_un.scsi.lun);

	if (icmdp->cmd_un.scsi.cmdlen <= 16) {
		/* copy the SCSI Command Block into the PDU */
		bcopy(pkt->pkt_cdbp, ihp->scb,
		    icmdp->cmd_un.scsi.cmdlen);
	} else {
		iscsi_addl_hdr_t *iahp;

		iahp = (iscsi_addl_hdr_t *)ihp;

		ihp->hlength = (ADDLHDRSZ(icmdp->cmd_un.scsi.cmdlen) -
		    sizeof (iscsi_scsi_cmd_hdr_t) + 3) / 4;
		iahp->ahs_hlen_hi = 0;
		iahp->ahs_hlen_lo = (icmdp->cmd_un.scsi.cmdlen - 15);
		iahp->ahs_key = 0x01;
		iahp->ahs_resv = 0;
		bcopy(pkt->pkt_cdbp, ihp->scb, 16);
		bcopy(((char *)pkt->pkt_cdbp) + 16, &iahp->ahs_extscb[0],
		    icmdp->cmd_un.scsi.cmdlen);
	}

	/*
	 * Update all values before transfering.
	 * We should never touch the icmdp after
	 * transfering if there is no more data
	 * to send.  The only case the idm_pdu_tx()
	 * will fail is a on a connection disconnect
	 * in that case the command will be flushed.
	 */
	pkt->pkt_state |= STATE_SENT_CMD;
}

static void
iscsi_tx_scsi_init_task(iscsi_cmd_t *icmdp, iscsi_conn_t *icp,
    iscsi_scsi_cmd_hdr_t *ihp)
{
	idm_task_t		*itp;
	struct buf		*bp		= NULL;
	uint32_t		data_length;

	bp = icmdp->cmd_un.scsi.bp;

	itp = icmdp->cmd_itp;
	ASSERT(itp != NULL);
	data_length = ntohl(ihp->data_length);
	ISCSI_IO_LOG(CE_NOTE,
	    "DEBUG: iscsi_tx_init_task: task_start: %p idt_tt: %x cmdsn: %x "
	    "sess_cmdsn: %x cmd: %p "
	    "cmdtype: %d datalen: %u",
	    (void *)itp, itp->idt_tt, ihp->cmdsn, icp->conn_sess->sess_cmdsn,
	    (void *)icmdp, icmdp->cmd_type, data_length);
	if (data_length > 0) {
		if (bp->b_flags & B_READ) {
			icmdp->cmd_un.scsi.ibp_ibuf =
			    idm_buf_alloc(icp->conn_ic,
			    bp->b_un.b_addr, bp->b_bcount);
			if (icmdp->cmd_un.scsi.ibp_ibuf)
				idm_buf_bind_in(itp,
				    icmdp->cmd_un.scsi.ibp_ibuf);
		} else {
			icmdp->cmd_un.scsi.ibp_obuf =
			    idm_buf_alloc(icp->conn_ic,
			    bp->b_un.b_addr, bp->b_bcount);
			if (icmdp->cmd_un.scsi.ibp_obuf)
				idm_buf_bind_out(itp,
				    icmdp->cmd_un.scsi.ibp_obuf);
		}
		ISCSI_IO_LOG(CE_NOTE,
		    "DEBUG: pdu_tx: task_start(%s): %p ic: %p idt_tt: %x "
		    "cmdsn: %x sess_cmdsn: %x sess_expcmdsn: %x obuf: %p "
		    "cmdp: %p cmdtype: %d "
		    "buflen: %lu " "bpaddr: %p datalen: %u ",
		    bp->b_flags & B_READ ? "B_READ" : "B_WRITE",
		    (void *)itp, (void *)icp->conn_ic,
		    itp->idt_tt, ihp->cmdsn,
		    icp->conn_sess->sess_cmdsn,
		    icp->conn_sess->sess_expcmdsn,
		    (void *)icmdp->cmd_un.scsi.ibp_ibuf,
		    (void *)icmdp, icmdp->cmd_type, bp->b_bcount,
		    (void *)bp->b_un.b_addr,
		    data_length);
	}

	/*
	 * Task is now active
	 */
	idm_task_start(itp, ISCSI_INI_TASK_TTT);
}

/*
 * iscsi_tx_scsi -
 *
 */
static iscsi_status_t
iscsi_tx_scsi(iscsi_sess_t *isp, iscsi_cmd_t *icmdp)
{
	iscsi_status_t		rval		= ISCSI_STATUS_SUCCESS;
	iscsi_conn_t		*icp		= NULL;
	struct scsi_pkt		*pkt		= NULL;
	iscsi_scsi_cmd_hdr_t	*ihp		= NULL;
	int			cdblen		= 0;
	idm_pdu_t		*pdu;
	int			len;

	ASSERT(isp != NULL);
	ASSERT(icmdp != NULL);

	pdu = kmem_zalloc(sizeof (idm_pdu_t), KM_SLEEP);

	pkt = icmdp->cmd_un.scsi.pkt;
	ASSERT(pkt != NULL);
	icp = icmdp->cmd_conn;
	ASSERT(icp != NULL);

	/* Reset counts in case we are on a retry */
	icmdp->cmd_un.scsi.data_transferred = 0;

	if (icmdp->cmd_un.scsi.cmdlen > DEF_CDB_LEN) {
		cdblen = icmdp->cmd_un.scsi.cmdlen;
		ihp = kmem_zalloc(ADDLHDRSZ(cdblen), KM_SLEEP);
		len = ADDLHDRSZ(cdblen);
	} else {
		/*
		 * only bzero the basic header; the additional header
		 * will be set up correctly later, if needed
		 */
		ihp = kmem_zalloc(sizeof (iscsi_scsi_cmd_hdr_t), KM_SLEEP);
		len = sizeof (iscsi_scsi_cmd_hdr_t);
	}

	iscsi_tx_init_hdr(isp, icp, (iscsi_text_hdr_t *)ihp,
	    ISCSI_OP_SCSI_CMD, icmdp);

	idm_pdu_init(pdu, icp->conn_ic, (void *)icmdp, &iscsi_tx_done);
	idm_pdu_init_hdr(pdu, (uint8_t *)ihp, len);
	pdu->isp_data = NULL;
	pdu->isp_datalen = 0;

	/*
	 * Sestion 12.11 of the iSCSI specification has a good table
	 * describing when uncolicited data and/or immediate data
	 * should be sent.
	 */

	iscsi_tx_scsi_data(icmdp, ihp, icp, pdu);

	iscsi_tx_scsi_init_pkt(icmdp, ihp);

	/* Calls idm_task_start */
	iscsi_tx_scsi_init_task(icmdp, icp, ihp);

	mutex_exit(&isp->sess_queue_pending.mutex);

	idm_pdu_tx(pdu);

	icmdp->cmd_misc_flags |= ISCSI_CMD_MISCFLAG_SENT;

	return (rval);
}


/* ARGSUSED */
static void
iscsi_tx_done(idm_pdu_t *pdu, idm_status_t status)
{
	kmem_free((iscsi_hdr_t *)pdu->isp_hdr, pdu->isp_hdrlen);
	kmem_free(pdu, sizeof (idm_pdu_t));
}


static void
iscsi_tx_pdu(iscsi_conn_t *icp, int opcode, void *hdr, int hdrlen,
    iscsi_cmd_t *icmdp)
{
	idm_pdu_t	*tx_pdu;
	iscsi_hdr_t	*ihp = (iscsi_hdr_t *)hdr;

	tx_pdu = kmem_zalloc(sizeof (idm_pdu_t), KM_SLEEP);
	ASSERT(tx_pdu != NULL);

	idm_pdu_init(tx_pdu, icp->conn_ic, icmdp, &iscsi_tx_done);
	idm_pdu_init_hdr(tx_pdu, hdr, hdrlen);
	if (opcode == ISCSI_OP_TEXT_CMD) {
		idm_pdu_init_data(tx_pdu,
		    (uint8_t *)icmdp->cmd_un.text.buf,
		    ntoh24(ihp->dlength));
	}

	mutex_exit(&icp->conn_sess->sess_queue_pending.mutex);
	idm_pdu_tx(tx_pdu);
	icmdp->cmd_misc_flags |= ISCSI_CMD_MISCFLAG_SENT;
}


/*
 * iscsi_tx_nop -
 *
 */
static iscsi_status_t
iscsi_tx_nop(iscsi_sess_t *isp, iscsi_cmd_t *icmdp)
{
	iscsi_status_t		rval	= ISCSI_STATUS_SUCCESS;
	iscsi_conn_t		*icp	= NULL;
	iscsi_nop_out_hdr_t	*inohp;

	ASSERT(isp != NULL);
	ASSERT(icmdp != NULL);
	icp = icmdp->cmd_conn;
	ASSERT(icp != NULL);

	inohp = kmem_zalloc(sizeof (iscsi_nop_out_hdr_t), KM_SLEEP);
	ASSERT(inohp != NULL);

	inohp->opcode	= ISCSI_OP_NOOP_OUT | ISCSI_OP_IMMEDIATE;
	inohp->flags	= ISCSI_FLAG_FINAL;
	inohp->itt	= icmdp->cmd_itt;
	inohp->ttt	= icmdp->cmd_ttt;
	mutex_enter(&isp->sess_cmdsn_mutex);
	icmdp->cmd_sn	= isp->sess_cmdsn;
	inohp->cmdsn	= htonl(isp->sess_cmdsn);
	mutex_exit(&isp->sess_cmdsn_mutex);
	inohp->expstatsn	= htonl(icp->conn_expstatsn);
	icp->conn_laststatsn = icp->conn_expstatsn;
	iscsi_tx_pdu(icp, ISCSI_OP_NOOP_OUT, inohp,
	    sizeof (iscsi_nop_out_hdr_t), icmdp);
	return (rval);
}


/*
 * iscsi_tx_abort -
 *
 */
static iscsi_status_t
iscsi_tx_abort(iscsi_sess_t *isp, iscsi_cmd_t *icmdp)
{
	iscsi_status_t			rval	= ISCSI_STATUS_SUCCESS;
	iscsi_conn_t			*icp	= NULL;
	iscsi_scsi_task_mgt_hdr_t	*istmh;

	ASSERT(isp != NULL);
	ASSERT(icmdp != NULL);
	icp = icmdp->cmd_conn;
	ASSERT(icp != NULL);

	istmh = kmem_zalloc(sizeof (iscsi_scsi_task_mgt_hdr_t), KM_SLEEP);
	ASSERT(istmh != NULL);
	mutex_enter(&isp->sess_cmdsn_mutex);
	icmdp->cmd_sn	= isp->sess_cmdsn;
	istmh->cmdsn	= htonl(isp->sess_cmdsn);
	mutex_exit(&isp->sess_cmdsn_mutex);
	istmh->expstatsn = htonl(icp->conn_expstatsn);
	icp->conn_laststatsn = icp->conn_expstatsn;
	istmh->itt	= icmdp->cmd_itt;
	istmh->opcode	= ISCSI_OP_SCSI_TASK_MGT_MSG | ISCSI_OP_IMMEDIATE;
	istmh->function	= ISCSI_FLAG_FINAL | ISCSI_TM_FUNC_ABORT_TASK;
	ISCSI_LUN_BYTE_COPY(istmh->lun,
	    icmdp->cmd_un.abort.icmdp->cmd_un.scsi.lun);
	istmh->rtt	= icmdp->cmd_un.abort.icmdp->cmd_itt;
	iscsi_tx_pdu(icp, ISCSI_OP_SCSI_TASK_MGT_MSG, istmh,
	    sizeof (iscsi_scsi_task_mgt_hdr_t), icmdp);

	return (rval);
}


/*
 * iscsi_tx_reset -
 *
 */
static iscsi_status_t
iscsi_tx_reset(iscsi_sess_t *isp, iscsi_cmd_t *icmdp)
{
	iscsi_status_t			rval	= ISCSI_STATUS_SUCCESS;
	iscsi_conn_t			*icp	= NULL;
	iscsi_scsi_task_mgt_hdr_t	*istmh;

	ASSERT(isp != NULL);
	ASSERT(icmdp != NULL);
	icp = icmdp->cmd_conn;
	ASSERT(icp != NULL);

	istmh = kmem_zalloc(sizeof (iscsi_scsi_task_mgt_hdr_t), KM_SLEEP);
	ASSERT(istmh != NULL);
	istmh->opcode	= ISCSI_OP_SCSI_TASK_MGT_MSG | ISCSI_OP_IMMEDIATE;
	mutex_enter(&isp->sess_cmdsn_mutex);
	icmdp->cmd_sn	= isp->sess_cmdsn;
	istmh->cmdsn	= htonl(isp->sess_cmdsn);
	mutex_exit(&isp->sess_cmdsn_mutex);
	istmh->expstatsn	= htonl(icp->conn_expstatsn);
	istmh->itt	= icmdp->cmd_itt;

	switch (icmdp->cmd_un.reset.level) {
	case RESET_LUN:
		istmh->function	= ISCSI_FLAG_FINAL |
		    ISCSI_TM_FUNC_LOGICAL_UNIT_RESET;
		ISCSI_LUN_BYTE_COPY(istmh->lun, icmdp->cmd_lun->lun_num);
		break;
	case RESET_TARGET:
	case RESET_BUS:
		istmh->function	= ISCSI_FLAG_FINAL |
		    ISCSI_TM_FUNC_TARGET_WARM_RESET;
		break;
	default:
		/* unsupported / unknown level */
		ASSERT(FALSE);
		break;
	}

	iscsi_tx_pdu(icp, ISCSI_OP_SCSI_TASK_MGT_MSG, istmh,
	    sizeof (iscsi_scsi_task_mgt_hdr_t), icmdp);

	return (rval);
}


/*
 * iscsi_tx_logout -
 *
 */
static iscsi_status_t
iscsi_tx_logout(iscsi_sess_t *isp, iscsi_cmd_t *icmdp)
{
	iscsi_status_t		rval	= ISCSI_STATUS_SUCCESS;
	iscsi_conn_t		*icp	= NULL;
	iscsi_logout_hdr_t	*ilh;

	ASSERT(isp != NULL);
	ASSERT(icmdp != NULL);
	icp = icmdp->cmd_conn;
	ASSERT(icp != NULL);

	ilh = kmem_zalloc(sizeof (iscsi_logout_hdr_t), KM_SLEEP);
	ilh->opcode	= ISCSI_OP_LOGOUT_CMD | ISCSI_OP_IMMEDIATE;
	ilh->flags	= ISCSI_FLAG_FINAL | ISCSI_LOGOUT_REASON_CLOSE_SESSION;
	ilh->itt		= icmdp->cmd_itt;
	ilh->cid		= icp->conn_cid;
	mutex_enter(&isp->sess_cmdsn_mutex);
	icmdp->cmd_sn	= isp->sess_cmdsn;
	ilh->cmdsn	= htonl(isp->sess_cmdsn);
	mutex_exit(&isp->sess_cmdsn_mutex);
	ilh->expstatsn	= htonl(icp->conn_expstatsn);
	iscsi_tx_pdu(icp, ISCSI_OP_LOGOUT_CMD, ilh,
	    sizeof (iscsi_logout_hdr_t), icmdp);

	return (rval);
}

/*
 * iscsi_tx_text - setup iSCSI text request header and send PDU with
 * data given in the buffer attached to the command.  For a single
 * text request, the target may need to send its response in multiple
 * text response.  In this case, empty text requests are sent after
 * each received response to notify the target the initiator is ready
 * for more response.  For the initial request, the data_len field in
 * the text specific portion of a command is set to the amount of data
 * the initiator wants to send as part of the request. If additional
 * empty text requests are required for long responses, the data_len
 * field is set to 0 by the iscsi_handle_text function.
 */
static iscsi_status_t
iscsi_tx_text(iscsi_sess_t *isp, iscsi_cmd_t *icmdp)
{
	iscsi_status_t		rval	= ISCSI_STATUS_SUCCESS;
	iscsi_conn_t		*icp	= NULL;
	iscsi_text_hdr_t	*ith;

	ASSERT(icmdp != NULL);
	icp = icmdp->cmd_conn;
	ASSERT(icp != NULL);

	ith = kmem_zalloc(sizeof (iscsi_text_hdr_t), KM_SLEEP);
	ASSERT(ith != NULL);
	ith->flags	= ISCSI_FLAG_FINAL;
	hton24(ith->dlength, icmdp->cmd_un.text.data_len);
	ith->ttt		= icmdp->cmd_un.text.ttt;
	iscsi_tx_init_hdr(isp, icp, (iscsi_text_hdr_t *)ith,
	    ISCSI_OP_TEXT_CMD, icmdp);
	bcopy(icmdp->cmd_un.text.lun, ith->rsvd4, sizeof (ith->rsvd4));

	iscsi_tx_pdu(icp, ISCSI_OP_TEXT_CMD, ith, sizeof (iscsi_text_hdr_t),
	    icmdp);

	return (rval);
}

/*
 * +--------------------------------------------------------------------+
 * | End of protocol send routines					|
 * +--------------------------------------------------------------------+
 */

/*
 * iscsi_handle_abort -
 *
 */
void
iscsi_handle_abort(void *arg)
{
	iscsi_sess_t	*isp		= NULL;
	iscsi_cmd_t	*icmdp		= (iscsi_cmd_t *)arg;
	iscsi_cmd_t	*new_icmdp;
	iscsi_conn_t	*icp;

	ASSERT(icmdp != NULL);
	icp = icmdp->cmd_conn;
	ASSERT(icp != NULL);
	isp = icp->conn_sess;
	ASSERT(isp != NULL);

	/* there should only be one abort */
	ASSERT(icmdp->cmd_un.scsi.abort_icmdp == NULL);

	new_icmdp = iscsi_cmd_alloc(icp, KM_SLEEP);
	new_icmdp->cmd_type		    = ISCSI_CMD_TYPE_ABORT;
	new_icmdp->cmd_lun		    = icmdp->cmd_lun;
	new_icmdp->cmd_un.abort.icmdp	    = icmdp;
	new_icmdp->cmd_conn		    = icmdp->cmd_conn;
	icmdp->cmd_un.scsi.abort_icmdp	    = new_icmdp;

	/* pending queue mutex is already held by timeout_checks */
	iscsi_cmd_state_machine(new_icmdp, ISCSI_CMD_EVENT_E1, isp);
}

/*
 * Callback from IDM indicating that the task has been suspended or aborted.
 */
void
iscsi_task_aborted(idm_task_t *idt, idm_status_t status)
{
	iscsi_cmd_t *icmdp = idt->idt_private;
	iscsi_conn_t *icp = icmdp->cmd_conn;
	iscsi_sess_t *isp = icp->conn_sess;

	ASSERT(icmdp->cmd_conn != NULL);

	switch (status) {
	case IDM_STATUS_SUSPENDED:
		/*
		 * If the task is suspended, it may be aborted later,
		 * so we can ignore this notification.
		 */
		break;

	case IDM_STATUS_ABORTED:
		mutex_enter(&icp->conn_queue_active.mutex);
		iscsi_cmd_state_machine(icmdp, ISCSI_CMD_EVENT_E9, isp);
		mutex_exit(&icp->conn_queue_active.mutex);
		break;

	default:
		/*
		 * Unexpected status.
		 */
		ASSERT(0);
	}

}

/*
 * iscsi_handle_nop -
 *
 */
static void
iscsi_handle_nop(iscsi_conn_t *icp, uint32_t itt, uint32_t ttt)
{
	iscsi_sess_t	*isp	= NULL;
	iscsi_cmd_t	*icmdp	= NULL;

	ASSERT(icp != NULL);
	isp = icp->conn_sess;
	ASSERT(isp != NULL);

	icmdp = iscsi_cmd_alloc(icp, KM_NOSLEEP);
	if (icmdp == NULL) {
		return;
	}

	icmdp->cmd_type		= ISCSI_CMD_TYPE_NOP;
	icmdp->cmd_itt		= itt;
	icmdp->cmd_ttt		= ttt;
	icmdp->cmd_lun		= NULL;
	icp->conn_nop_lbolt	= ddi_get_lbolt();

	iscsi_cmd_state_machine(icmdp, ISCSI_CMD_EVENT_E1, isp);
}

/*
 * iscsi_handle_reset - send reset request to the target
 *
 */
iscsi_status_t
iscsi_handle_reset(iscsi_sess_t *isp, int level, iscsi_lun_t *ilp)
{
	iscsi_status_t	rval	= ISCSI_STATUS_SUCCESS;
	iscsi_conn_t	*icp;
	iscsi_cmd_t	icmd;

	ASSERT(isp != NULL);

	if (level == RESET_LUN) {
		rw_enter(&isp->sess_lun_list_rwlock, RW_WRITER);
		ASSERT(ilp != NULL);
		if (ilp->lun_state & ISCSI_LUN_STATE_BUSY) {
			rw_exit(&isp->sess_lun_list_rwlock);
			return (ISCSI_STATUS_SUCCESS);
		}
		ilp->lun_state |= ISCSI_LUN_STATE_BUSY;
		rw_exit(&isp->sess_lun_list_rwlock);
	} else {
		mutex_enter(&isp->sess_reset_mutex);
		if (isp->sess_reset_in_progress == B_TRUE) {
			/*
			 * If the reset is in progress, it is unnecessary
			 * to send reset to the target redunantly.
			 */
			mutex_exit(&isp->sess_reset_mutex);
			return (ISCSI_STATUS_SUCCESS);
		}
		isp->sess_reset_in_progress = B_TRUE;
		mutex_exit(&isp->sess_reset_mutex);
	}

	bzero(&icmd, sizeof (iscsi_cmd_t));
	icmd.cmd_sig		= ISCSI_SIG_CMD;
	icmd.cmd_state		= ISCSI_CMD_STATE_FREE;
	icmd.cmd_type		= ISCSI_CMD_TYPE_RESET;
	icmd.cmd_lun		= ilp;
	icmd.cmd_un.reset.level	= level;
	icmd.cmd_result		= ISCSI_STATUS_SUCCESS;
	icmd.cmd_completed	= B_FALSE;
	icmd.cmd_un.reset.response = SCSI_TCP_TM_RESP_COMPLETE;

	mutex_init(&icmd.cmd_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&icmd.cmd_completion, NULL, CV_DRIVER, NULL);
	/*
	 * If we received an IO and we are not in the
	 * LOGGED_IN state we are in the process of
	 * failing.  Just respond that we are BUSY.
	 */
	rw_enter(&isp->sess_state_rwlock, RW_READER);
	if (!ISCSI_SESS_STATE_FULL_FEATURE(isp->sess_state)) {
		/* We aren't connected to the target fake success */
		rw_exit(&isp->sess_state_rwlock);

		if (level == RESET_LUN) {
			rw_enter(&isp->sess_lun_list_rwlock, RW_WRITER);
			ilp->lun_state &= ~ISCSI_LUN_STATE_BUSY;
			rw_exit(&isp->sess_lun_list_rwlock);
		} else {
			mutex_enter(&isp->sess_reset_mutex);
			isp->sess_reset_in_progress = B_FALSE;
			mutex_exit(&isp->sess_reset_mutex);
		}

		return (ISCSI_STATUS_SUCCESS);
	}

	mutex_enter(&isp->sess_queue_pending.mutex);
	iscsi_cmd_state_machine(&icmd, ISCSI_CMD_EVENT_E1, isp);
	mutex_exit(&isp->sess_queue_pending.mutex);
	rw_exit(&isp->sess_state_rwlock);

	/* stall until completed */
	mutex_enter(&icmd.cmd_mutex);
	while (icmd.cmd_completed == B_FALSE) {
		cv_wait(&icmd.cmd_completion, &icmd.cmd_mutex);
	}
	mutex_exit(&icmd.cmd_mutex);

	/* copy rval */
	rval = icmd.cmd_result;

	if (rval == ISCSI_STATUS_SUCCESS) {
		/*
		 * Reset was successful.  We need to flush
		 * all active IOs.
		 */
		rw_enter(&isp->sess_conn_list_rwlock, RW_READER);
		icp = isp->sess_conn_list;
		while (icp != NULL) {
			iscsi_cmd_t *t_icmdp = NULL;
			iscsi_cmd_t *next_icmdp = NULL;

			mutex_enter(&icp->conn_queue_active.mutex);
			t_icmdp = icp->conn_queue_active.head;
			while (t_icmdp != NULL) {
				next_icmdp = t_icmdp->cmd_next;
				mutex_enter(&t_icmdp->cmd_mutex);
				if (!(t_icmdp->cmd_misc_flags &
				    ISCSI_CMD_MISCFLAG_SENT)) {
					/*
					 * Although this command is in the
					 * active queue, it has not been sent.
					 * Skip it.
					 */
					mutex_exit(&t_icmdp->cmd_mutex);
					t_icmdp = next_icmdp;
					continue;
				}
				if (level == RESET_LUN) {
					if (icmd.cmd_lun == NULL ||
					    t_icmdp->cmd_lun == NULL ||
					    (icmd.cmd_lun->lun_num !=
					    t_icmdp->cmd_lun->lun_num)) {
						mutex_exit(&t_icmdp->cmd_mutex);
						t_icmdp = next_icmdp;
						continue;
					}
				}

				if (icmd.cmd_sn == t_icmdp->cmd_sn) {
					/*
					 * This command may be replied with
					 * UA sense key later. So currently
					 * it is not a suitable time to flush
					 * it. Mark its flag with FLUSH. There
					 * is no harm to keep it for a while.
					 */
					t_icmdp->cmd_misc_flags |=
					    ISCSI_CMD_MISCFLAG_FLUSH;
					if (t_icmdp->cmd_type ==
					    ISCSI_CMD_TYPE_SCSI) {
						t_icmdp->cmd_un.scsi.pkt_stat |=
						    STAT_BUS_RESET;
					}
					mutex_exit(&t_icmdp->cmd_mutex);
				} else if ((icmd.cmd_sn > t_icmdp->cmd_sn) ||
				    ((t_icmdp->cmd_sn - icmd.cmd_sn) >
				    ISCSI_CMD_SN_WRAP)) {
					/*
					 * This reset request must act on all
					 * the commnds from the same session
					 * having a CmdSN lower than the task
					 * mangement CmdSN. So flush these
					 * commands here.
					 */
					if (t_icmdp->cmd_type ==
					    ISCSI_CMD_TYPE_SCSI) {
						t_icmdp->cmd_un.scsi.pkt_stat |=
						    STAT_BUS_RESET;
					}
					mutex_exit(&t_icmdp->cmd_mutex);
					iscsi_cmd_state_machine(t_icmdp,
					    ISCSI_CMD_EVENT_E7, isp);
				} else {
					mutex_exit(&t_icmdp->cmd_mutex);
				}

				t_icmdp = next_icmdp;
			}

			mutex_exit(&icp->conn_queue_active.mutex);
			icp = icp->conn_next;
		}
		rw_exit(&isp->sess_conn_list_rwlock);
	}

	/* clean up */
	cv_destroy(&icmd.cmd_completion);
	mutex_destroy(&icmd.cmd_mutex);

	if (level == RESET_LUN) {
		rw_enter(&isp->sess_lun_list_rwlock, RW_WRITER);
		ilp->lun_state &= ~ISCSI_LUN_STATE_BUSY;
		rw_exit(&isp->sess_lun_list_rwlock);
	} else {
		mutex_enter(&isp->sess_reset_mutex);
		isp->sess_reset_in_progress = B_FALSE;
		mutex_exit(&isp->sess_reset_mutex);
	}

	return (rval);
}

/*
 * iscsi_logout_start - task handler for deferred logout
 * Acquire a hold before call, released in iscsi_handle_logout
 */
static void
iscsi_logout_start(void *arg)
{
	iscsi_task_t		*itp = (iscsi_task_t *)arg;
	iscsi_conn_t		*icp;

	icp = (iscsi_conn_t *)itp->t_arg;

	mutex_enter(&icp->conn_state_mutex);
	(void) iscsi_handle_logout(icp);
	mutex_exit(&icp->conn_state_mutex);
}

/*
 * iscsi_handle_logout - This function will issue a logout for
 * the session from a specific connection.
 * Acquire idm_conn_hold before call.  Released internally.
 */
iscsi_status_t
iscsi_handle_logout(iscsi_conn_t *icp)
{
	iscsi_sess_t	*isp;
	idm_conn_t	*ic;
	iscsi_cmd_t	*icmdp;
	int		rval;

	ASSERT(icp != NULL);
	isp = icp->conn_sess;
	ic = icp->conn_ic;
	ASSERT(isp != NULL);
	ASSERT(isp->sess_hba != NULL);
	ASSERT(mutex_owned(&icp->conn_state_mutex));

	/*
	 * If the connection has already gone down (e.g. if the transport
	 * failed between when this LOGOUT was generated and now) then we
	 * can and must skip sending the LOGOUT.  Check the same condition
	 * we use below to determine that connection has "settled".
	 */
	if ((icp->conn_state == ISCSI_CONN_STATE_FREE) ||
	    (icp->conn_state == ISCSI_CONN_STATE_FAILED) ||
	    (icp->conn_state == ISCSI_CONN_STATE_POLLING)) {
		idm_conn_rele(ic);
		return (0);
	}

	icmdp = iscsi_cmd_alloc(icp, KM_SLEEP);
	ASSERT(icmdp != NULL);
	icmdp->cmd_type		= ISCSI_CMD_TYPE_LOGOUT;
	icmdp->cmd_result	= ISCSI_STATUS_SUCCESS;
	icmdp->cmd_completed	= B_FALSE;

	mutex_enter(&isp->sess_queue_pending.mutex);
	iscsi_cmd_state_machine(icmdp, ISCSI_CMD_EVENT_E1, isp);
	mutex_exit(&isp->sess_queue_pending.mutex);

	/*
	 * release connection state mutex to avoid a deadlock.  This
	 * function is called from within the connection state
	 * machine with the lock held.  When the logout response is
	 * received another call to the connection state machine
	 * occurs which causes the deadlock
	 */
	mutex_exit(&icp->conn_state_mutex);

	/* stall until completed */
	mutex_enter(&icmdp->cmd_mutex);
	while (icmdp->cmd_completed == B_FALSE) {
		cv_wait(&icmdp->cmd_completion, &icmdp->cmd_mutex);
	}
	mutex_exit(&icmdp->cmd_mutex);
	mutex_enter(&icp->conn_state_mutex);

	/* copy rval */
	rval = icmdp->cmd_result;

	/* clean up */
	iscsi_cmd_free(icmdp);

	if (rval != 0) {
		/* If the logout failed then drop the connection */
		idm_ini_conn_disconnect(icp->conn_ic);
	}

	/* stall until connection settles */
	while ((icp->conn_state != ISCSI_CONN_STATE_FREE) &&
	    (icp->conn_state != ISCSI_CONN_STATE_FAILED) &&
	    (icp->conn_state != ISCSI_CONN_STATE_POLLING)) {
		/* wait for transition */
		cv_wait(&icp->conn_state_change, &icp->conn_state_mutex);
	}

	idm_conn_rele(ic);

	/*
	 * Return value reflects whether the logout command completed --
	 * regardless of the return value the connection is closed and
	 * ready for reconnection.
	 */
	return (rval);
}


/*
 * iscsi_handle_text - main control function for iSCSI text requests.  This
 * function handles allocating the command, sending initial text request, and
 * handling long response sequence.
 * If a data overflow condition occurs, iscsi_handle_text continues to
 * receive responses until the all data has been recieved.  This allows
 * the full data length to be returned to the caller.
 */
iscsi_status_t
iscsi_handle_text(iscsi_conn_t *icp, char *buf, uint32_t buf_len,
    uint32_t data_len, uint32_t *rx_data_len)
{
	iscsi_sess_t	*isp;
	iscsi_cmd_t	*icmdp;
	iscsi_status_t	rval	= ISCSI_STATUS_SUCCESS;

	ASSERT(icp != NULL);
	ASSERT(buf != NULL);
	ASSERT(rx_data_len != NULL);

	isp = icp->conn_sess;
	ASSERT(isp != NULL);

	/*
	 * Ensure data for text request command is not greater
	 * than the negotiated maximum receive data seqment length.
	 *
	 * Although iSCSI allows for long text requests (multiple
	 * pdus), this function places a restriction on text
	 * requests to ensure it is handled by a single PDU.
	 */
	if (data_len > icp->conn_params.max_xmit_data_seg_len) {
		return (ISCSI_STATUS_CMD_FAILED);
	}

	icmdp = iscsi_cmd_alloc(icp, KM_SLEEP);
	ASSERT(icmdp != NULL);

	icmdp->cmd_type		= ISCSI_CMD_TYPE_TEXT;
	icmdp->cmd_result	= ISCSI_STATUS_SUCCESS;
	icmdp->cmd_misc_flags	&= ~ISCSI_CMD_MISCFLAG_FREE;
	icmdp->cmd_completed	= B_FALSE;

	icmdp->cmd_un.text.buf		= buf;
	icmdp->cmd_un.text.buf_len	= buf_len;
	icmdp->cmd_un.text.offset	= 0;
	icmdp->cmd_un.text.data_len	= data_len;
	icmdp->cmd_un.text.total_rx_len	= 0;
	icmdp->cmd_un.text.ttt		= ISCSI_RSVD_TASK_TAG;
	icmdp->cmd_un.text.stage	= ISCSI_CMD_TEXT_INITIAL_REQ;

long_text_response:
	rw_enter(&isp->sess_state_rwlock, RW_READER);
	if (!ISCSI_SESS_STATE_FULL_FEATURE(isp->sess_state)) {
		iscsi_cmd_free(icmdp);
		rw_exit(&isp->sess_state_rwlock);
		return (ISCSI_STATUS_NO_CONN_LOGGED_IN);
	}

	mutex_enter(&isp->sess_queue_pending.mutex);
	iscsi_cmd_state_machine(icmdp, ISCSI_CMD_EVENT_E1, isp);
	mutex_exit(&isp->sess_queue_pending.mutex);
	rw_exit(&isp->sess_state_rwlock);

	/* stall until completed */
	mutex_enter(&icmdp->cmd_mutex);
	while (icmdp->cmd_completed == B_FALSE) {
		cv_wait(&icmdp->cmd_completion, &icmdp->cmd_mutex);
	}
	mutex_exit(&icmdp->cmd_mutex);

	/*
	 * check if error occured.  If data overflow occured, continue on
	 * to ensure we get all data so that the full data length can be
	 * returned to the user
	 */
	if ((icmdp->cmd_result != ISCSI_STATUS_SUCCESS) &&
	    (icmdp->cmd_result != ISCSI_STATUS_DATA_OVERFLOW)) {
		cmn_err(CE_NOTE, "iscsi: SendTarget discovery failed (%d)",
		    icmdp->cmd_result);
		rval = icmdp->cmd_result;
		iscsi_cmd_free(icmdp);
		return (rval);
	}

	/* check if this was a partial text PDU  */
	if (icmdp->cmd_un.text.stage != ISCSI_CMD_TEXT_FINAL_RSP) {
		/*
		 * If a paritial text rexponse received, send an empty
		 * text request.  This follows the behaviour specified
		 * in RFC3720 regarding long text responses.
		 */
		icmdp->cmd_misc_flags		&= ~ISCSI_CMD_MISCFLAG_FREE;
		icmdp->cmd_completed		= B_FALSE;
		icmdp->cmd_un.text.data_len	= 0;
		icmdp->cmd_un.text.stage	= ISCSI_CMD_TEXT_CONTINUATION;
		goto long_text_response;
	}

	/*
	 * set total received data length.  If data overflow this would be
	 * amount of data that would have been received if buffer large
	 * enough.
	 */
	*rx_data_len = icmdp->cmd_un.text.total_rx_len;

	/* copy rval */
	rval = icmdp->cmd_result;

	/* clean up  */
	iscsi_cmd_free(icmdp);

	return (rval);
}

/*
 * iscsi_handle_passthru - This function is used to send a uscsi_cmd
 * to a specific target lun.  This routine is used for internal purposes
 * during enumeration and via the ISCSI_USCSICMD IOCTL.  We restrict
 * the CDBs that can be issued to a target/lun to INQUIRY, REPORT_LUNS,
 * and READ_CAPACITY for security purposes.
 *
 * The logic here is broken into three phases.
 * 1) Allocate and initialize a pkt/icmdp
 * 2) Send the pkt/icmdp
 * 3) cv_wait for completion
 */
iscsi_status_t
iscsi_handle_passthru(iscsi_sess_t *isp, uint16_t lun, struct uscsi_cmd *ucmdp)
{
	iscsi_status_t		rval;
	iscsi_cmd_t		*icmdp;
	struct scsi_pkt		*pkt;
	struct buf		*bp;
	struct scsi_arq_status  *arqstat;
	int			statuslen;

	ASSERT(isp != NULL);
	ASSERT(ucmdp != NULL);

	if (ucmdp->uscsi_rqlen > SENSE_LENGTH) {
		/*
		 * The caller provided sense buffer large enough for additional
		 * sense bytes. We need to allocate pkt_scbp to fit them there
		 * too.
		 */
		statuslen = ucmdp->uscsi_rqlen + ISCSI_ARQ_STATUS_NOSENSE_LEN;
	} else {
		/* The default size of pkt_scbp */
		statuslen = sizeof (struct scsi_arq_status);
	}

	/*
	 * Step 1. Setup structs - KM_SLEEP will always succeed
	 */
	bp = kmem_zalloc(sizeof (struct buf), KM_SLEEP);
	ASSERT(bp != NULL);
	pkt = kmem_zalloc(sizeof (struct scsi_pkt), KM_SLEEP);
	ASSERT(pkt != NULL);
	icmdp = iscsi_cmd_alloc(NULL, KM_SLEEP);
	ASSERT(icmdp != NULL);

	/* setup bp structure */
	bp->b_flags		= B_READ;
	bp->b_bcount		= ucmdp->uscsi_buflen;
	bp->b_un.b_addr		= ucmdp->uscsi_bufaddr;

	/* setup scsi_pkt structure */
	pkt->pkt_ha_private	= icmdp;
	pkt->pkt_scbp		= kmem_zalloc(statuslen, KM_SLEEP);
	pkt->pkt_cdbp		= kmem_zalloc(ucmdp->uscsi_cdblen, KM_SLEEP);
	/* callback routine for passthru, will wake cv_wait */
	pkt->pkt_comp		= iscsi_handle_passthru_callback;
	pkt->pkt_time		= ucmdp->uscsi_timeout;

	/* setup iscsi_cmd structure */
	icmdp->cmd_lun			= NULL;
	icmdp->cmd_type			= ISCSI_CMD_TYPE_SCSI;
	icmdp->cmd_un.scsi.lun		= lun;
	icmdp->cmd_un.scsi.pkt		= pkt;
	icmdp->cmd_un.scsi.bp		= bp;
	bcopy(ucmdp->uscsi_cdb, pkt->pkt_cdbp, ucmdp->uscsi_cdblen);
	icmdp->cmd_un.scsi.cmdlen	= ucmdp->uscsi_cdblen;
	icmdp->cmd_un.scsi.statuslen	= statuslen;
	icmdp->cmd_crc_error_seen	= B_FALSE;
	icmdp->cmd_completed		= B_FALSE;
	icmdp->cmd_result		= ISCSI_STATUS_SUCCESS;

	/*
	 * Step 2. Push IO onto pending queue.  If we aren't in
	 * FULL_FEATURE we need to fail the IO.
	 */
	rw_enter(&isp->sess_state_rwlock, RW_READER);
	if (!ISCSI_SESS_STATE_FULL_FEATURE(isp->sess_state)) {
		rw_exit(&isp->sess_state_rwlock);

		iscsi_cmd_free(icmdp);
		kmem_free(pkt->pkt_cdbp, ucmdp->uscsi_cdblen);
		kmem_free(pkt->pkt_scbp, statuslen);
		kmem_free(pkt, sizeof (struct scsi_pkt));
		kmem_free(bp, sizeof (struct buf));

		return (ISCSI_STATUS_CMD_FAILED);
	}

	mutex_enter(&isp->sess_queue_pending.mutex);
	iscsi_cmd_state_machine(icmdp, ISCSI_CMD_EVENT_E1, isp);
	mutex_exit(&isp->sess_queue_pending.mutex);
	rw_exit(&isp->sess_state_rwlock);

	/*
	 * Step 3. Wait on cv_wait for completion routine
	 */
	mutex_enter(&icmdp->cmd_mutex);
	while (icmdp->cmd_completed == B_FALSE) {
		cv_wait(&icmdp->cmd_completion, &icmdp->cmd_mutex);
	}
	mutex_exit(&icmdp->cmd_mutex);

	/* copy rval */
	rval = icmdp->cmd_result;

	ucmdp->uscsi_resid = pkt->pkt_resid;

	/* update scsi status */
	arqstat = (struct scsi_arq_status *)pkt->pkt_scbp;
	ucmdp->uscsi_status = ((char *)&arqstat->sts_status)[0];

	/* copy request sense buffers if caller gave space */
	if ((ucmdp->uscsi_rqlen > 0) &&
	    (ucmdp->uscsi_rqbuf != NULL)) {
		ASSERT(ucmdp->uscsi_rqlen >= arqstat->sts_rqpkt_resid);
		ucmdp->uscsi_rqresid = arqstat->sts_rqpkt_resid;
		bcopy(&arqstat->sts_sensedata, ucmdp->uscsi_rqbuf,
		    ucmdp->uscsi_rqlen - arqstat->sts_rqpkt_resid);
	}

	if ((ucmdp->uscsi_status == STATUS_CHECK) &&
	    ((icmdp->cmd_misc_flags & ISCSI_CMD_MISCFLAG_INTERNAL)) == B_TRUE) {
		/*
		 * Internal SCSI commands received status
		 */
		(void) iscsi_decode_sense(
		    (uint8_t *)&arqstat->sts_sensedata, icmdp);
	}

	/* clean up */
	iscsi_cmd_free(icmdp);
	kmem_free(pkt->pkt_cdbp, ucmdp->uscsi_cdblen);
	kmem_free(pkt->pkt_scbp, statuslen);
	kmem_free(pkt, sizeof (struct scsi_pkt));
	kmem_free(bp, sizeof (struct buf));

	return (rval);
}


/*
 * iscsi_handle_passthru_callback -
 *
 */
static void
iscsi_handle_passthru_callback(struct scsi_pkt *pkt)
{
	iscsi_cmd_t		*icmdp  = NULL;

	ASSERT(pkt != NULL);
	icmdp = (iscsi_cmd_t *)pkt->pkt_ha_private;
	ASSERT(icmdp != NULL);

	mutex_enter(&icmdp->cmd_mutex);
	icmdp->cmd_completed    = B_TRUE;
	icmdp->cmd_result	= ISCSI_STATUS_SUCCESS;
	cv_broadcast(&icmdp->cmd_completion);
	mutex_exit(&icmdp->cmd_mutex);

}

/*
 * IDM callbacks
 */
void
iscsi_build_hdr(idm_task_t *idm_task, idm_pdu_t *pdu, uint8_t opcode)
{
	iscsi_cmd_t *icmdp = idm_task->idt_private;
	iscsi_conn_t *icp = icmdp->cmd_conn;
	iscsi_data_hdr_t *ihp = (iscsi_data_hdr_t *)pdu->isp_hdr;

	mutex_enter(&icmdp->cmd_mutex);
	if (opcode == ISCSI_OP_SCSI_DATA) {
		uint32_t	data_sn;
		uint32_t	lun;
		icmdp = idm_task->idt_private;
		icp = icmdp->cmd_conn;
		ihp->opcode	= opcode;
		ihp->itt	= icmdp->cmd_itt;
		ihp->ttt	= idm_task->idt_r2t_ttt;
		ihp->expstatsn	= htonl(icp->conn_expstatsn);
		icp->conn_laststatsn = icp->conn_expstatsn;
		data_sn = ntohl(ihp->datasn);
		data_sn++;
		lun = icmdp->cmd_un.scsi.lun;
		ISCSI_LUN_BYTE_COPY(ihp->lun, lun);
		/* CRM: upate_flow_control */
		ISCSI_IO_LOG(CE_NOTE, "DEBUG: iscsi_build_hdr"
		    "(ISCSI_OP_SCSI_DATA): task: %p icp: %p ic: %p itt: %x "
		    "exp: %d data_sn: %d", (void *)idm_task, (void *)icp,
		    (void *)icp->conn_ic, ihp->itt, icp->conn_expstatsn,
		    data_sn);
	} else {
		cmn_err(CE_WARN, "iscsi_build_hdr: unprocessed build "
		    "header opcode: %x", opcode);
	}
	mutex_exit(&icmdp->cmd_mutex);
}

static void
iscsi_process_rsp_status(iscsi_sess_t *isp, iscsi_conn_t *icp,
    idm_status_t status)
{
	switch (status) {
	case IDM_STATUS_SUCCESS:
		if ((isp->sess_state == ISCSI_SESS_STATE_IN_FLUSH) &&
		    (icp->conn_queue_active.count == 0)) {
			iscsi_drop_conn_cleanup(icp);
		}
		break;
	case IDM_STATUS_PROTOCOL_ERROR:
		KSTAT_INC_CONN_ERR_PROTOCOL(icp);
		iscsi_drop_conn_cleanup(icp);
		break;
	default:
		break;
	}
}

static void
iscsi_drop_conn_cleanup(iscsi_conn_t *icp)
{
	mutex_enter(&icp->conn_state_mutex);
	idm_ini_conn_disconnect(icp->conn_ic);
	mutex_exit(&icp->conn_state_mutex);
}

void
iscsi_rx_error_pdu(idm_conn_t *ic, idm_pdu_t *pdu, idm_status_t status)
{
	iscsi_conn_t *icp = (iscsi_conn_t *)ic->ic_handle;
	iscsi_sess_t *isp;

	ASSERT(icp != NULL);
	isp = icp->conn_sess;
	ASSERT(isp != NULL);
	iscsi_process_rsp_status(isp, icp, status);
	idm_pdu_complete(pdu, status);
}

void
iscsi_rx_misc_pdu(idm_conn_t *ic, idm_pdu_t *pdu)
{
	iscsi_conn_t		*icp;
	iscsi_hdr_t		*ihp	= (iscsi_hdr_t *)pdu->isp_hdr;
	iscsi_sess_t		*isp;
	idm_status_t		status;

	icp = ic->ic_handle;
	isp = icp->conn_sess;
	isp->sess_rx_lbolt = icp->conn_rx_lbolt = ddi_get_lbolt();
	switch (ihp->opcode & ISCSI_OPCODE_MASK) {
	case ISCSI_OP_LOGIN_RSP:
		status = iscsi_rx_process_login_pdu(ic, pdu);
		idm_pdu_complete(pdu, status);
		break;
	case ISCSI_OP_LOGOUT_RSP:
		status = iscsi_rx_process_logout_rsp(ic, pdu);
		idm_pdu_complete(pdu, status);
		break;
	case ISCSI_OP_REJECT_MSG:
		status = iscsi_rx_process_reject_rsp(ic, pdu);
		break;
	case ISCSI_OP_SCSI_TASK_MGT_RSP:
		status = iscsi_rx_process_task_mgt_rsp(ic, pdu);
		idm_pdu_complete(pdu, status);
		break;
	case ISCSI_OP_NOOP_IN:
		status = iscsi_rx_process_nop(ic, pdu);
		idm_pdu_complete(pdu, status);
		break;
	case ISCSI_OP_ASYNC_EVENT:
		status = iscsi_rx_process_async_rsp(ic, pdu);
		break;
	case ISCSI_OP_TEXT_RSP:
		status = iscsi_rx_process_text_rsp(ic, pdu);
		idm_pdu_complete(pdu, status);
		break;
	default:
		cmn_err(CE_WARN, "iscsi connection(%u) protocol error "
		    "- received misc unsupported opcode 0x%02x",
		    icp->conn_oid, ihp->opcode);
		status = IDM_STATUS_PROTOCOL_ERROR;
		break;
	}
	iscsi_process_rsp_status(isp, icp, status);
}

/*
 * +--------------------------------------------------------------------+
 * | Beginning of completion routines					|
 * +--------------------------------------------------------------------+
 */

/*
 * iscsi_ic_thread -
 */
void
iscsi_ic_thread(iscsi_thread_t *thread, void *arg)
{
	iscsi_sess_t	*isp = (iscsi_sess_t *)arg;
	int		ret;
	iscsi_queue_t	q;
	iscsi_cmd_t	*icmdp;
	iscsi_cmd_t	*next_icmdp;

	ASSERT(isp != NULL);
	ASSERT(thread != NULL);
	ASSERT(thread->signature == SIG_ISCSI_THREAD);

	for (;;) {

		/*
		 * We wait till iodone or somebody else wakes us up.
		 */
		ret = iscsi_thread_wait(thread, -1);

		/*
		 * The value should never be negative since we never timeout.
		 */
		ASSERT(ret >= 0);

		q.count = 0;
		q.head  = NULL;
		q.tail  = NULL;
		mutex_enter(&isp->sess_queue_completion.mutex);
		icmdp = isp->sess_queue_completion.head;
		while (icmdp != NULL) {
			next_icmdp = icmdp->cmd_next;
			mutex_enter(&icmdp->cmd_mutex);
			/*
			 * check if the associated r2t/abort has finished
			 * yet.  If not, don't complete the command.
			 */
			if ((icmdp->cmd_un.scsi.r2t_icmdp == NULL) &&
			    (icmdp->cmd_un.scsi.abort_icmdp == NULL)) {
				mutex_exit(&icmdp->cmd_mutex);
				(void) iscsi_dequeue_cmd(&isp->
				    sess_queue_completion.head,
				    &isp->sess_queue_completion.tail,
				    icmdp);
				--isp->sess_queue_completion.count;
				iscsi_enqueue_cmd_head(&q.head,
				    &q.tail, icmdp);
			} else {
				mutex_exit(&icmdp->cmd_mutex);
			}
			icmdp = next_icmdp;
		}
		mutex_exit(&isp->sess_queue_completion.mutex);
		icmdp = q.head;
		while (icmdp != NULL) {
			next_icmdp = icmdp->cmd_next;
			iscsi_cmd_state_machine(icmdp, ISCSI_CMD_EVENT_E8, isp);
			icmdp = next_icmdp;
		}

		if (ret > 0)
			/* Somebody woke us up to work */
			continue;
		else
			/*
			 * Somebody woke us up to kill ourselves. We will
			 * make sure, however that the completion queue is
			 * empty before leaving.  After we've done that it
			 * is the originator of the signal that has to make
			 * sure no other SCSI command is posted.
			 */
			break;
	}

}

/*
 * iscsi_iodone -
 *
 */
void
iscsi_iodone(iscsi_sess_t *isp, iscsi_cmd_t *icmdp)
{
	struct scsi_pkt		*pkt	= NULL;
	struct buf		*bp	= icmdp->cmd_un.scsi.bp;

	ASSERT(isp != NULL);
	ASSERT(icmdp != NULL);
	pkt = icmdp->cmd_un.scsi.pkt;
	ASSERT(pkt != NULL);

	ASSERT(icmdp->cmd_un.scsi.abort_icmdp == NULL);
	ASSERT(icmdp->cmd_un.scsi.r2t_icmdp == NULL);
	if (pkt->pkt_reason == CMD_CMPLT) {
		if (bp) {
			if (bp->b_flags & B_READ) {
				KSTAT_SESS_RX_IO_DONE(isp, bp->b_bcount);
			} else {
				KSTAT_SESS_TX_IO_DONE(isp, bp->b_bcount);
			}
		}
	}

	if (pkt->pkt_flags & FLAG_NOINTR) {
		cv_broadcast(&icmdp->cmd_completion);
		mutex_exit(&icmdp->cmd_mutex);
	} else {
		/*
		 * Release mutex.  As soon as callback is
		 * issued the caller may destroy the command.
		 */
		mutex_exit(&icmdp->cmd_mutex);
		/*
		 * We can't just directly call the pk_comp routine.  In
		 * many error cases the target driver will use the calling
		 * thread to re-drive error handling (reset, retries...)
		 * back into the hba driver (iscsi).  If the target redrives
		 * a reset back into the iscsi driver off this thead we have
		 * a chance of deadlocking. So instead use the io completion
		 * thread.
		 */
		(*icmdp->cmd_un.scsi.pkt->pkt_comp)(icmdp->cmd_un.scsi.pkt);
	}
}

/*
 * +--------------------------------------------------------------------+
 * | End of completion routines						|
 * +--------------------------------------------------------------------+
 */

/*
 * +--------------------------------------------------------------------+
 * | Beginning of watchdog routines					|
 * +--------------------------------------------------------------------+
 */

/*
 * iscsi_watchdog_thread -
 *
 */
void
iscsi_wd_thread(iscsi_thread_t *thread, void *arg)
{
	iscsi_sess_t	*isp = (iscsi_sess_t *)arg;
	int		rc = 1;

	ASSERT(isp != NULL);

	while (rc != 0) {

		iscsi_timeout_checks(isp);
		iscsi_nop_checks(isp);

		rc = iscsi_thread_wait(thread, SEC_TO_TICK(1));
	}
}

/*
 * iscsi_timeout_checks -
 *
 */
static void
iscsi_timeout_checks(iscsi_sess_t *isp)
{
	clock_t		now = ddi_get_lbolt();
	iscsi_conn_t	*icp;
	iscsi_cmd_t	*icmdp, *nicmdp;

	ASSERT(isp != NULL);

	/* PENDING */
	rw_enter(&isp->sess_state_rwlock, RW_READER);
	mutex_enter(&isp->sess_queue_pending.mutex);
	for (icmdp = isp->sess_queue_pending.head;
	    icmdp; icmdp = nicmdp) {
		nicmdp = icmdp->cmd_next;

		/* Skip entries with no timeout */
		if (icmdp->cmd_lbolt_timeout == 0)
			continue;

		/*
		 * Skip pending queue entries for cmd_type values that depend
		 * on having an open cmdsn window for successfull transition
		 * from pending to the active (i.e. ones that depend on
		 * sess_cmdsn .vs. sess_maxcmdsn). For them, the timer starts
		 * when they are successfully moved to the active queue by
		 * iscsi_cmd_state_pending() code.
		 */
		/*
		 * If the cmd is stuck, at least give it a chance
		 * to timeout
		 */
		if (((icmdp->cmd_type == ISCSI_CMD_TYPE_SCSI) ||
		    (icmdp->cmd_type == ISCSI_CMD_TYPE_TEXT)) &&
		    !(icmdp->cmd_misc_flags & ISCSI_CMD_MISCFLAG_STUCK))
			continue;

		/* Skip if timeout still in the future */
		if (now <= icmdp->cmd_lbolt_timeout)
			continue;

		/* timeout */
		iscsi_cmd_state_machine(icmdp, ISCSI_CMD_EVENT_E6, isp);
	}
	mutex_exit(&isp->sess_queue_pending.mutex);
	rw_exit(&isp->sess_state_rwlock);

	rw_enter(&isp->sess_conn_list_rwlock, RW_READER);
	icp = isp->sess_conn_list;
	while (icp != NULL) {

		icp->conn_timeout = B_FALSE;
		/* ACTIVE */
		mutex_enter(&icp->conn_state_mutex);
		mutex_enter(&isp->sess_queue_pending.mutex);
		mutex_enter(&icp->conn_queue_active.mutex);
		for (icmdp = icp->conn_queue_active.head;
		    icmdp; icmdp = nicmdp) {
			nicmdp = icmdp->cmd_next;

			if (iscsi_nop_timeout_checks(icmdp) == B_TRUE) {
				icp->conn_timeout = B_TRUE;
			}

			/* Skip entries with no timeout */
			if (icmdp->cmd_lbolt_timeout == 0)
				continue;

			/*
			 * Skip if command is not active or not needed
			 * to flush.
			 */
			if (icmdp->cmd_state != ISCSI_CMD_STATE_ACTIVE &&
			    !(icmdp->cmd_misc_flags & ISCSI_CMD_MISCFLAG_FLUSH))
				continue;

			/* Skip if timeout still in the future */
			if (now <= icmdp->cmd_lbolt_timeout)
				continue;

			if (icmdp->cmd_misc_flags & ISCSI_CMD_MISCFLAG_FLUSH) {
				/*
				 * This command is left during target reset,
				 * we can flush it now.
				 */
				iscsi_cmd_state_machine(icmdp,
				    ISCSI_CMD_EVENT_E7, isp);
			} else if (icmdp->cmd_state == ISCSI_CMD_STATE_ACTIVE) {
				/* timeout */
				iscsi_cmd_state_machine(icmdp,
				    ISCSI_CMD_EVENT_E6, isp);
			}

		}
		mutex_exit(&icp->conn_queue_active.mutex);
		mutex_exit(&isp->sess_queue_pending.mutex);
		mutex_exit(&icp->conn_state_mutex);

		icp = icp->conn_next;
	}

	icp = isp->sess_conn_list;
	while (icp != NULL) {
		if (icp->conn_timeout == B_TRUE) {
			/* timeout on this connect detected */
			idm_ini_conn_disconnect(icp->conn_ic);
			icp->conn_timeout = B_FALSE;
		}
		icp = icp->conn_next;
	}
	rw_exit(&isp->sess_conn_list_rwlock);
}

/*
 * iscsi_nop_checks - sends a NOP on idle connections
 *
 * This function walks the connections on a session and
 * issues NOPs on those connections that are in FULL
 * FEATURE mode and have not received data for the
 * time period specified by iscsi_nop_delay (global).
 */
static void
iscsi_nop_checks(iscsi_sess_t *isp)
{
	iscsi_conn_t	*icp;

	ASSERT(isp != NULL);

	if (isp->sess_type == ISCSI_SESS_TYPE_DISCOVERY) {
		return;
	}

	rw_enter(&isp->sess_conn_list_rwlock, RW_READER);
	icp = isp->sess_conn_act;
	if (icp != NULL) {

		mutex_enter(&icp->conn_state_mutex);
		if ((ISCSI_CONN_STATE_FULL_FEATURE(icp->conn_state)) &&
		    (ddi_get_lbolt() > isp->sess_conn_act->conn_rx_lbolt +
		    SEC_TO_TICK(iscsi_nop_delay)) && (ddi_get_lbolt() >
		    isp->sess_conn_act->conn_nop_lbolt +
		    SEC_TO_TICK(iscsi_nop_delay))) {

			/*
			 * We haven't received anything from the
			 * target is a defined period of time,
			 * send NOP to see if the target is alive.
			 */
			mutex_enter(&isp->sess_queue_pending.mutex);
			iscsi_handle_nop(isp->sess_conn_act,
			    0, ISCSI_RSVD_TASK_TAG);
			mutex_exit(&isp->sess_queue_pending.mutex);
		}
		mutex_exit(&icp->conn_state_mutex);

		icp = icp->conn_next;
	}
	rw_exit(&isp->sess_conn_list_rwlock);
}

static boolean_t
iscsi_nop_timeout_checks(iscsi_cmd_t *icmdp)
{
	if (icmdp->cmd_type == ISCSI_CMD_TYPE_NOP) {
		if ((ddi_get_lbolt() - icmdp->cmd_lbolt_active) >
		    SEC_TO_TICK(ISCSI_CONN_TIEMOUT_DETECT)) {
			return (B_TRUE);
		} else {
			return (B_FALSE);
		}
	}
	return (B_FALSE);
}
/*
 * +--------------------------------------------------------------------+
 * | End of wd routines						|
 * +--------------------------------------------------------------------+
 */

/*
 * iscsi_flush_cmd_after_reset - flush commands after reset
 *
 * Here we will flush all the commands for a specified LUN whose cmdsn is less
 * than the one received with the Unit Attention.
 */
static void
iscsi_flush_cmd_after_reset(uint32_t cmd_sn, uint16_t lun_num,
    iscsi_conn_t *icp)
{
	iscsi_cmd_t	*t_icmdp    = NULL;
	iscsi_cmd_t	*next_icmdp = NULL;

	ASSERT(icp != NULL);

	t_icmdp = icp->conn_queue_active.head;
	while (t_icmdp != NULL) {
		next_icmdp = t_icmdp->cmd_next;
		mutex_enter(&t_icmdp->cmd_mutex);
		/*
		 * We will flush the commands whose cmdsn is less than the one
		 * got Unit Attention.
		 * Here we will check for wrap by subtracting and compare to
		 * 1/2 of a 32 bit number, if greater then we wrapped.
		 */
		if ((t_icmdp->cmd_misc_flags & ISCSI_CMD_MISCFLAG_SENT) &&
		    ((cmd_sn > t_icmdp->cmd_sn) ||
		    ((t_icmdp->cmd_sn - cmd_sn) >
		    ISCSI_CMD_SN_WRAP))) {
			/*
			 * Internally generated SCSI commands do not have
			 * t_icmdp->cmd_lun set, but the LUN can be retrieved
			 * from t_icmdp->cmd_un.scsi.lun.
			 */
			if ((t_icmdp->cmd_lun != NULL &&
			    t_icmdp->cmd_lun->lun_num == lun_num) ||
			    (t_icmdp->cmd_type == ISCSI_CMD_TYPE_SCSI &&
			    (t_icmdp->cmd_un.scsi.lun & ISCSI_LUN_MASK) ==
			    lun_num)) {
				t_icmdp->cmd_misc_flags |=
				    ISCSI_CMD_MISCFLAG_FLUSH;
				if (t_icmdp->cmd_type == ISCSI_CMD_TYPE_SCSI) {
					t_icmdp->cmd_un.scsi.pkt_stat |=
					    STAT_BUS_RESET;
				}
			}
		}
		mutex_exit(&t_icmdp->cmd_mutex);
		t_icmdp = next_icmdp;
	}
}

/*
 * iscsi_decode_sense - decode the sense data in the cmd response
 * and take proper actions
 */
static boolean_t
iscsi_decode_sense(uint8_t *sense_data, iscsi_cmd_t *icmdp)
{
	uint8_t		sense_key	= 0;
	uint8_t		asc		= 0;
	uint8_t		ascq		= 0;
	boolean_t	flush_io	= B_FALSE;
	boolean_t	reconfig_lun	= B_FALSE;
	iscsi_sess_t	*isp		= NULL;

	ASSERT(sense_data != NULL);

	isp = icmdp->cmd_conn->conn_sess;

	sense_key = scsi_sense_key(sense_data);
	switch (sense_key) {
		case KEY_UNIT_ATTENTION:
			asc = scsi_sense_asc(sense_data);
			switch (asc) {
				case ISCSI_SCSI_RESET_SENSE_CODE:
					/*
					 * POWER ON, RESET, OR BUS_DEVICE RESET
					 * OCCURRED
					 */
					flush_io = B_TRUE;
					break;
				case ISCSI_SCSI_LUNCHANGED_CODE:
					ascq = scsi_sense_ascq(sense_data);
					if (ascq == ISCSI_SCSI_LUNCHANGED_ASCQ)
						reconfig_lun = B_TRUE;
				default:
					break;
			}
			break;
		default:
			/*
			 * Currently we don't care
			 * about other sense key.
			 */
			break;
	}

	if (reconfig_lun == B_TRUE) {
		rw_enter(&isp->sess_state_rwlock, RW_READER);
		if ((isp->sess_state == ISCSI_SESS_STATE_LOGGED_IN) &&
		    (iscsi_sess_enum_request(isp, B_FALSE,
		    isp->sess_state_event_count) !=
		    ISCSI_SESS_ENUM_SUBMITTED)) {
			cmn_err(CE_WARN, "Unable to commit re-enumeration for"
			    " session(%u) %s", isp->sess_oid, isp->sess_name);
		}
		rw_exit(&isp->sess_state_rwlock);
	}

	return (flush_io);
}
