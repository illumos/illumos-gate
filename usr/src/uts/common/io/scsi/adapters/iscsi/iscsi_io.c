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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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

#include "iscsi.h"		/* iscsi driver */
#include <sys/scsi/adapters/iscsi_protocol.h>	/* iscsi protocol */

/* generic io helpers */
static uint32_t n2h24(uchar_t *ptr);
static int iscsi_sna_lt(uint32_t n1, uint32_t n2);
static void iscsi_update_flow_control(iscsi_sess_t *isp,
    uint32_t max, uint32_t exp);

/* receivers */
static iscsi_status_t iscsi_rx_process_hdr(iscsi_conn_t *icp,
    iscsi_hdr_t *ihp, char *data, int data_size);
static iscsi_status_t iscsi_rx_process_nop(iscsi_conn_t *icp,
    iscsi_hdr_t *ihp, char *data);
static iscsi_status_t iscsi_rx_process_data_rsp(iscsi_conn_t *icp,
    iscsi_hdr_t *ihp);
static iscsi_status_t iscsi_rx_process_cmd_rsp(iscsi_conn_t *icp,
    iscsi_hdr_t *ihp, char *data);
static iscsi_status_t iscsi_rx_process_rtt_rsp(iscsi_conn_t *icp,
    iscsi_hdr_t *ihp, char *data);
static iscsi_status_t iscsi_rx_process_reject_rsp(iscsi_conn_t *icp,
    iscsi_hdr_t *ihp, char *data);
static iscsi_status_t iscsi_rx_process_rejected_tsk_mgt(iscsi_conn_t *icp,
    iscsi_hdr_t *old_ihp);
static iscsi_status_t iscsi_rx_process_itt_to_icmdp(iscsi_sess_t *isp,
    iscsi_hdr_t *ihp, iscsi_cmd_t **icmdp);
static iscsi_status_t iscsi_rx_process_task_mgt_rsp(iscsi_conn_t *icp,
    iscsi_hdr_t *ihp, void *data);
static iscsi_status_t iscsi_rx_process_logout_rsp(iscsi_conn_t *icp,
    iscsi_hdr_t *ihp, char *data);
static iscsi_status_t iscsi_rx_process_async_rsp(iscsi_conn_t *icp,
    iscsi_hdr_t *ihp, char *data);
static iscsi_status_t iscsi_rx_process_text_rsp(iscsi_conn_t *icp,
    iscsi_hdr_t *ihp, char *data);


/* senders */
static iscsi_status_t iscsi_tx_scsi(iscsi_sess_t *isp, iscsi_cmd_t *icmdp);
static iscsi_status_t iscsi_tx_r2t(iscsi_sess_t *isp, iscsi_cmd_t *icmdp);
static iscsi_status_t iscsi_tx_data(iscsi_sess_t *isp, iscsi_conn_t *icp,
    iscsi_cmd_t *icmdp, uint32_t ttt, size_t datalen, size_t offset);
static iscsi_status_t iscsi_tx_nop(iscsi_sess_t *isp, iscsi_cmd_t *icmdp);
static iscsi_status_t iscsi_tx_abort(iscsi_sess_t *isp, iscsi_cmd_t *icmdp);
static iscsi_status_t iscsi_tx_reset(iscsi_sess_t *isp, iscsi_cmd_t *icmdp);
static iscsi_status_t iscsi_tx_logout(iscsi_sess_t *isp, iscsi_cmd_t *icmdp);
static iscsi_status_t iscsi_tx_text(iscsi_sess_t *isp, iscsi_cmd_t *icmdp);


/* helpers */
static void iscsi_handle_r2t(iscsi_conn_t *icp, iscsi_cmd_t *icmdp,
    uint32_t offset, uint32_t length, uint32_t ttt);
static void iscsi_handle_passthru_callback(struct scsi_pkt *pkt);
static void iscsi_handle_nop(iscsi_conn_t *icp, uint32_t itt, uint32_t ttt);

static void iscsi_timeout_checks(iscsi_sess_t *isp);
static void iscsi_nop_checks(iscsi_sess_t *isp);


#define	ISCSI_CONN_TO_NET_DIGEST(icp)					    \
	((icp->conn_params.header_digest ? ISCSI_NET_HEADER_DIGEST : 0) |   \
	(icp->conn_params.data_digest ? ISCSI_NET_DATA_DIGEST : 0))

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
static void
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
 * iscsi_rx_thread - The connection creates a thread of this
 * function during login.  After which point this thread is
 * used to receive and process all iSCSI PDUs on this connection.
 * The PDUs received on this connection are used to drive the
 * commands through their state machine.  This thread will
 * continue processing while the connection is on a LOGGED_IN
 * or IN_LOGOUT state.  Once the connection moves out of this
 * state the thread will die.
 */
void
iscsi_rx_thread(iscsi_thread_t *thread, void *arg)
{
	iscsi_status_t		rval		= ISCSI_STATUS_SUCCESS;
	iscsi_conn_t		*icp		= (iscsi_conn_t *)arg;
	iscsi_sess_t		*isp		= NULL;
	char			*hdr		= NULL;
	int			hdr_size	= 0;
	char			*data		= NULL;
	int			data_size	= 0;
	iscsi_hdr_t		*ihp;

	ASSERT(icp != NULL);
	isp = icp->conn_sess;
	ASSERT(isp != NULL);

	/* pre-alloc recv header buffer for common actions */
	hdr_size = sizeof (iscsi_hdr_t) + 255; /* 255 = one byte hlength */
	hdr = (char *)kmem_zalloc(hdr_size, KM_SLEEP);
	ihp = (iscsi_hdr_t *)hdr;
	ASSERT(ihp != NULL);

	/* pre-alloc max_recv_size buffer for common actions */
	data_size = icp->conn_params.max_recv_data_seg_len;
	data = (char *)kmem_zalloc(data_size, KM_SLEEP);
	ASSERT(data != NULL);

	do {
		/* Wait for the next iSCSI header */
		rval = iscsi_net->recvhdr(icp->conn_socket,
		    ihp, hdr_size, 0, (icp->conn_params.header_digest ?
		    ISCSI_NET_HEADER_DIGEST : 0));
		if (ISCSI_SUCCESS(rval)) {
			isp->sess_rx_lbolt =
			    icp->conn_rx_lbolt =
			    ddi_get_lbolt();

			/* Perform specific hdr handling */
			rval = iscsi_rx_process_hdr(icp, ihp,
			    data, data_size);
		}

		/*
		 * handle failures
		 */
		switch (rval) {
		case ISCSI_STATUS_SUCCESS:
			/*
			 * If we successfully completed a receive
			 * and we are in an IN_FLUSH state then
			 * check the active queue count to see
			 * if its empty.  If its empty then force
			 * a disconnect event on the connection.
			 * This will move the session from IN_FLUSH
			 * to FLUSHED and complete the login
			 * parameter update.
			 */
			if ((isp->sess_state == ISCSI_SESS_STATE_IN_FLUSH) &&
			    (icp->conn_queue_active.count == 0)) {
				mutex_enter(&icp->conn_state_mutex);
				(void) iscsi_conn_state_machine(icp,
				    ISCSI_CONN_EVENT_T14);
				mutex_exit(&icp->conn_state_mutex);
			}
			break;
		case ISCSI_STATUS_TCP_RX_ERROR:
			/* connection had an error */
			mutex_enter(&icp->conn_state_mutex);
			(void) iscsi_conn_state_machine(icp,
			    ISCSI_CONN_EVENT_T15);
			mutex_exit(&icp->conn_state_mutex);
			break;
		case ISCSI_STATUS_HEADER_DIGEST_ERROR:
			/*
			 * If we encounter a digest error we have to restart
			 * all the connections on this session. per iSCSI
			 * Level 0 Recovery.
			 */
			KSTAT_INC_CONN_ERR_HEADER_DIGEST(icp);
			mutex_enter(&icp->conn_state_mutex);
			(void) iscsi_conn_state_machine(icp,
			    ISCSI_CONN_EVENT_T14);
			mutex_exit(&icp->conn_state_mutex);
			break;
		case ISCSI_STATUS_DATA_DIGEST_ERROR:
			/*
			 * We can continue with a data digest error.  The
			 * icmdp was flaged as having a crc problem.  It
			 * will be aborted when all data is received.  This
			 * saves us from restarting the session when we
			 * might be able to keep it going.  If the data
			 * digest issue was really bad we will hit a
			 * status protocol error on the next pdu, which
			 * will force a connection retstart.
			 */
			KSTAT_INC_CONN_ERR_DATA_DIGEST(icp);
			break;
		case ISCSI_STATUS_PROTOCOL_ERROR:
			/*
			 * A protocol problem was encountered.  Reset
			 * session to try and repair issue.
			 */
			KSTAT_INC_CONN_ERR_PROTOCOL(icp);
			mutex_enter(&icp->conn_state_mutex);
			(void) iscsi_conn_state_machine(icp,
			    ISCSI_CONN_EVENT_T14);
			mutex_exit(&icp->conn_state_mutex);
			break;
		case ISCSI_STATUS_INTERNAL_ERROR:
			/*
			 * These should have all been handled before now.
			 */
			break;
		default:
			cmn_err(CE_WARN, "iscsi connection(%u) encountered "
			    "unknown error(%d) on a receive", icp->conn_oid,
			    rval);
			ASSERT(B_FALSE);
		}

	} while ((ISCSI_CONN_STATE_FULL_FEATURE(icp->conn_state)) &&
	    (iscsi_thread_wait(thread, 0) != 0));

	kmem_free(hdr, hdr_size);
	kmem_free(data, data_size);
}


/*
 * iscsi_rx_process_hdr - This function collects data for all PDUs
 * that do not have data that will be mapped to a specific scsi_pkt.
 * Then for each hdr type fan out the processing.
 */
static iscsi_status_t
iscsi_rx_process_hdr(iscsi_conn_t *icp, iscsi_hdr_t *ihp,
    char *data, int data_size)
{
	iscsi_status_t	rval	= ISCSI_STATUS_SUCCESS;
	iscsi_sess_t	*isp	= NULL;

	ASSERT(icp != NULL);
	ASSERT(ihp != NULL);
	ASSERT(data != NULL);
	isp = icp->conn_sess;
	ASSERT(isp != NULL);

	/* If this is not a SCSI_DATA_RSP we can go ahead and get the data */
	if ((ihp->opcode & ISCSI_OPCODE_MASK) != ISCSI_OP_SCSI_DATA_RSP) {
		rval = iscsi_net->recvdata(icp->conn_socket, ihp,
		    data, data_size, 0, (icp->conn_params.data_digest) ?
		    ISCSI_NET_DATA_DIGEST : 0);
		if (!ISCSI_SUCCESS(rval)) {
			return (rval);
		}
		isp->sess_rx_lbolt = icp->conn_rx_lbolt = ddi_get_lbolt();
	}

	/* fan out the hdr processing */
	switch (ihp->opcode & ISCSI_OPCODE_MASK) {
	case ISCSI_OP_SCSI_DATA_RSP:
		rval = iscsi_rx_process_data_rsp(icp, ihp);
		break;
	case ISCSI_OP_SCSI_RSP:
		rval = iscsi_rx_process_cmd_rsp(icp, ihp, data);
		break;
	case ISCSI_OP_RTT_RSP:
		rval = iscsi_rx_process_rtt_rsp(icp, ihp, data);
		break;
	case ISCSI_OP_NOOP_IN:
		rval = iscsi_rx_process_nop(icp, ihp, data);
		break;
	case ISCSI_OP_REJECT_MSG:
		rval = iscsi_rx_process_reject_rsp(icp, ihp, data);
		break;
	case ISCSI_OP_SCSI_TASK_MGT_RSP:
		rval = iscsi_rx_process_task_mgt_rsp(icp, ihp, data);
		break;
	case ISCSI_OP_LOGOUT_RSP:
		rval = iscsi_rx_process_logout_rsp(icp, ihp, data);
		break;
	case ISCSI_OP_ASYNC_EVENT:
		rval = iscsi_rx_process_async_rsp(icp, ihp, data);
		break;
	case ISCSI_OP_TEXT_RSP:
		rval = iscsi_rx_process_text_rsp(icp, ihp, data);
		break;
	default:
		cmn_err(CE_WARN, "iscsi connection(%u) protocol error - "
		    "received an unsupported opcode 0x%02x",
		    icp->conn_oid, ihp->opcode);
		rval = ISCSI_STATUS_PROTOCOL_ERROR;
	}

	return (rval);
}


/*
 * iscsi_rx_process_data_rsp - Processed received data header.  Once
 * header is processed we read data off the connection directly into
 * the scsi_pkt to avoid duplicate bcopy of a large amount of data.
 * If this is the final data sequence denoted by the data response
 * PDU Status bit being set.  We will not receive the SCSI response.
 * This bit denotes that the PDU is the successful completion of the
 * command.  In this case complete the command.  If This bit isn't
 * set we wait for more data or a scsi command response.
 */
static iscsi_status_t
iscsi_rx_process_data_rsp(iscsi_conn_t *icp, iscsi_hdr_t *ihp)
{
	iscsi_status_t		rval		= ISCSI_STATUS_SUCCESS;
	iscsi_sess_t		*isp		= NULL;
	iscsi_data_rsp_hdr_t	*idrhp		= (iscsi_data_rsp_hdr_t *)ihp;
	iscsi_cmd_t		*icmdp		= NULL;
	struct scsi_pkt		*pkt		= NULL;
	struct buf		*bp		= NULL;
	uint32_t		offset		= 0;
	uint32_t		dlength		= 0;
	char			*bcp		= NULL;

	ASSERT(icp != NULL);
	ASSERT(ihp != NULL);
	isp = icp->conn_sess;
	ASSERT(isp != NULL);

	if (idrhp->flags & ISCSI_FLAG_DATA_STATUS) {
		/* make sure we got status in order */
		if (icp->conn_expstatsn == ntohl(idrhp->statsn)) {
			icp->conn_expstatsn++;
		} else {
			cmn_err(CE_WARN, "iscsi connection(%u) protocol error "
			    "- received status out of order itt:0x%x "
			    "statsn:0x%x expstatsn:0x%x", icp->conn_oid,
			    idrhp->itt, ntohl(idrhp->statsn),
			    icp->conn_expstatsn);
			return (ISCSI_STATUS_PROTOCOL_ERROR);
		}
	}

	/* match itt in the session's command table */
	mutex_enter(&icp->conn_queue_active.mutex);
	mutex_enter(&isp->sess_cmdsn_mutex);
	if (!ISCSI_SUCCESS(iscsi_rx_process_itt_to_icmdp(isp, ihp, &icmdp))) {
		mutex_exit(&isp->sess_cmdsn_mutex);
		mutex_exit(&icp->conn_queue_active.mutex);
		return (ISCSI_STATUS_PROTOCOL_ERROR);
	}
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

	/* update expcmdsn and maxcmdsn */
	iscsi_update_flow_control(isp, ntohl(idrhp->maxcmdsn),
	    ntohl(idrhp->expcmdsn));
	mutex_exit(&isp->sess_cmdsn_mutex);
	mutex_exit(&icp->conn_queue_active.mutex);

	/* shorthand some values */
	pkt = icmdp->cmd_un.scsi.pkt;
	bp = icmdp->cmd_un.scsi.bp;
	offset = ntohl(idrhp->offset);
	dlength = n2h24(idrhp->dlength);

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
			return (ISCSI_STATUS_PROTOCOL_ERROR);
		}

		/*
		 * We can't tolerate the target sending too much
		 * data for our buffer
		 */
		if ((dlength >
		    (bp->b_bcount - icmdp->cmd_un.scsi.data_transferred)) ||
		    (dlength > (bp->b_bcount - offset))) {
			cmn_err(CE_WARN,
			    "iscsi connection(%u) protocol error - "
			    "received too much data itt:0x%x",
			    icp->conn_oid, idrhp->itt);
			mutex_enter(&icp->conn_queue_active.mutex);
			iscsi_enqueue_active_cmd(icp, icmdp);
			mutex_exit(&icp->conn_queue_active.mutex);
			return (ISCSI_STATUS_PROTOCOL_ERROR);
		}

		bcp = ((char *)bp->b_un.b_addr) + offset;

		/*
		 * Get the rest of the data and copy it directly into
		 * the scsi_pkt.
		 */
		rval = iscsi_net->recvdata(icp->conn_socket, ihp,
		    bcp, dlength, 0, (icp->conn_params.data_digest ?
		    ISCSI_NET_DATA_DIGEST : 0));
		if (ISCSI_SUCCESS(rval)) {
			KSTAT_ADD_CONN_RX_BYTES(icp, dlength);
		} else {
			/* If digest error flag icmdp with a crc error */
			if (rval == ISCSI_STATUS_DATA_DIGEST_ERROR) {
				icmdp->cmd_crc_error_seen = B_TRUE;
			}
			mutex_enter(&icp->conn_queue_active.mutex);
			iscsi_enqueue_active_cmd(icp, icmdp);
			mutex_exit(&icp->conn_queue_active.mutex);
			return (rval);
		}
		isp->sess_rx_lbolt = icp->conn_rx_lbolt = ddi_get_lbolt();

		/* update icmdp statistics */
		icmdp->cmd_un.scsi.data_transferred += dlength;
	}

	/*
	 * We got status. This should only happen if we have
	 * received all the data with no errors.  The command
	 * must be completed now, since we won't get a command
	 * response PDU. The cmd_status and residual_count are
	 * not meaningful unless status_present is set.
	 */
	if (idrhp->flags & ISCSI_FLAG_DATA_STATUS) {
		pkt->pkt_resid = 0;
		/* Check the residual count */
		if (bp &&
		    (icmdp->cmd_un.scsi.data_transferred !=
		    bp->b_bcount)) {
			/*
			 * We didn't xfer the expected amount of data -
			 * the residual_count in the header is only valid
			 * if the underflow flag is set.
			 */
			if (idrhp->flags & ISCSI_FLAG_DATA_UNDERFLOW) {
				pkt->pkt_resid = ntohl(idrhp->residual_count);
			} else {
				if (bp->b_bcount >
				    icmdp->cmd_un.scsi.data_transferred) {
					/* Some data fell on the floor somehw */
					pkt->pkt_resid =
					    bp->b_bcount -
					    icmdp->cmd_un.scsi.data_transferred;
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

			arqstat->sts_rqpkt_resid =
			    sizeof (struct scsi_extended_sense);

		} else if (pkt->pkt_scbp) {
			/* just pass along the status we got */
			pkt->pkt_scbp[0] = idrhp->cmd_status;
		}

		mutex_enter(&icp->conn_queue_active.mutex);
		iscsi_enqueue_active_cmd(icp, icmdp);
		iscsi_cmd_state_machine(icmdp, ISCSI_CMD_EVENT_E3, isp);
		mutex_exit(&icp->conn_queue_active.mutex);
	} else {
		mutex_enter(&icp->conn_queue_active.mutex);
		iscsi_enqueue_active_cmd(icp, icmdp);
		mutex_exit(&icp->conn_queue_active.mutex);
	}

	return (ISCSI_STATUS_SUCCESS);
}


/*
 * iscsi_rx_process_cmd_rsp - Process received scsi command response.  This
 * will contain sense data if the command was not successful.  This data needs
 * to be copied into the scsi_pkt.  Otherwise we just complete the IO.
 */
static iscsi_status_t
iscsi_rx_process_cmd_rsp(iscsi_conn_t *icp, iscsi_hdr_t *ihp, char *data)
{
	iscsi_sess_t		*isp		= icp->conn_sess;
	iscsi_scsi_rsp_hdr_t	*issrhp		= (iscsi_scsi_rsp_hdr_t *)ihp;
	iscsi_cmd_t		*icmdp		= NULL;
	struct scsi_pkt		*pkt		= NULL;
	uint32_t		dlength		= 0;
	struct scsi_arq_status	*arqstat	= NULL;
	size_t			senselen	= 0;

	/* make sure we get status in order */
	if (icp->conn_expstatsn == ntohl(issrhp->statsn)) {
		icp->conn_expstatsn++;
	} else {
		cmn_err(CE_WARN, "iscsi connection(%u) protocol error - "
		    "received status out of order itt:0x%x statsn:0x%x "
		    "expstatsn:0x%x", icp->conn_oid, issrhp->itt,
		    ntohl(issrhp->statsn), icp->conn_expstatsn);
		return (ISCSI_STATUS_PROTOCOL_ERROR);
	}

	mutex_enter(&icp->conn_queue_active.mutex);
	mutex_enter(&isp->sess_cmdsn_mutex);
	if (!ISCSI_SUCCESS(iscsi_rx_process_itt_to_icmdp(isp, ihp, &icmdp))) {
		mutex_exit(&isp->sess_cmdsn_mutex);
		mutex_exit(&icp->conn_queue_active.mutex);
		return (ISCSI_STATUS_PROTOCOL_ERROR);
	}

	/* update expcmdsn and maxcmdsn */
	iscsi_update_flow_control(isp, ntohl(issrhp->maxcmdsn),
	    ntohl(issrhp->expcmdsn));
	mutex_exit(&isp->sess_cmdsn_mutex);

	pkt = icmdp->cmd_un.scsi.pkt;

	if (issrhp->response) {
		/* The target failed the command. */
		pkt->pkt_reason = CMD_TRAN_ERR;
		if (icmdp->cmd_un.scsi.bp) {
			pkt->pkt_resid = icmdp->cmd_un.scsi.bp->b_bcount;
		} else {
			pkt->pkt_resid = 0;
		}
	} else {
		/* success */
		pkt->pkt_resid = 0;
		/* Check the residual count */
		if ((icmdp->cmd_un.scsi.bp) &&
		    (icmdp->cmd_un.scsi.data_transferred !=
		    icmdp->cmd_un.scsi.bp->b_bcount)) {
			/*
			 * We didn't xfer the expected amount of data -
			 * the residual_count in the header is only
			 * valid if the underflow flag is set.
			 */
			if (issrhp->flags & ISCSI_FLAG_CMD_UNDERFLOW) {
				pkt->pkt_resid = ntohl(issrhp->residual_count);
			} else {
				if (icmdp->cmd_un.scsi.bp->b_bcount >
				    icmdp->cmd_un.scsi.data_transferred) {
					/*
					 * Some data fell on the floor
					 * somehow - probably a CRC error
					 */
					pkt->pkt_resid =
					    icmdp->cmd_un.scsi.bp->b_bcount -
					    icmdp->cmd_un.scsi.data_transferred;
				}
			}
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

				if (senselen == 0) {
					/* auto request sense failed */
					arqstat->sts_rqpkt_status.sts_chk = 1;
					arqstat->sts_rqpkt_resid =
					    sizeof (struct scsi_extended_sense);
				} else if (senselen <
				    sizeof (struct scsi_extended_sense)) {
					/* auto request sense short */
					arqstat->sts_rqpkt_resid =
					    sizeof (struct scsi_extended_sense)
					    - senselen;
				} else {
					/* auto request sense complete */
					arqstat->sts_rqpkt_resid = 0;
				}
				arqstat->sts_rqpkt_statistics = 0;
				pkt->pkt_state |= STATE_ARQ_DONE;

				/* copy auto request sense */
				dlength = min(senselen,
				    sizeof (struct scsi_extended_sense));
				if (dlength) {
					bcopy(&data[2], (uchar_t *)&arqstat->
					    sts_sensedata, dlength);
				}
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
			pkt->pkt_resid = 0;
			/* pass SCSI status up stack */
			if (pkt->pkt_scbp) {
				pkt->pkt_scbp[0] = issrhp->cmd_status;
			}
		}
	}

	iscsi_cmd_state_machine(icmdp, ISCSI_CMD_EVENT_E3, isp);
	mutex_exit(&icp->conn_queue_active.mutex);

	return (ISCSI_STATUS_SUCCESS);
}

/*
 * iscsi_rx_process_rtt_rsp - Process received RTT.  This means the target is
 * requesting data.
 */
/* ARGSUSED */
static iscsi_status_t
iscsi_rx_process_rtt_rsp(iscsi_conn_t *icp, iscsi_hdr_t *ihp, char *data)
{
	iscsi_sess_t		*isp = (iscsi_sess_t *)icp->conn_sess;
	iscsi_rtt_hdr_t		*irhp		= (iscsi_rtt_hdr_t *)ihp;
	iscsi_cmd_t		*icmdp		= NULL;
	struct buf		*bp		= NULL;
	uint32_t		data_length;
	iscsi_status_t		status = ISCSI_STATUS_PROTOCOL_ERROR;


	mutex_enter(&isp->sess_queue_pending.mutex);
	mutex_enter(&icp->conn_queue_active.mutex);
	mutex_enter(&isp->sess_cmdsn_mutex);
	if (!ISCSI_SUCCESS(iscsi_rx_process_itt_to_icmdp(isp, ihp, &icmdp))) {
		mutex_exit(&isp->sess_cmdsn_mutex);
		mutex_exit(&icp->conn_queue_active.mutex);
		mutex_exit(&isp->sess_queue_pending.mutex);
		return (status);
	}

	/* update expcmdsn and maxcmdsn */
	iscsi_update_flow_control(isp, ntohl(irhp->maxcmdsn),
	    ntohl(irhp->expcmdsn));
	mutex_enter(&icmdp->cmd_mutex);
	mutex_exit(&isp->sess_cmdsn_mutex);

	bp = icmdp->cmd_un.scsi.bp;
	data_length = ntohl(irhp->data_length);

	/*
	 * Perform boundary-checks per RFC 3720 (section 10.8.4).
	 * The Desired Data Transfer Length must satisfy this relation:
	 *
	 *	0 < Desired Data Transfer Length <= MaxBurstLength
	 */
	if ((bp == NULL) || (data_length == 0)) {
		cmn_err(CE_WARN, "iscsi connection(%u) received r2t but pkt "
		    "has no data itt:0x%x - protocol error", icp->conn_oid,
		    irhp->itt);
	} else if (data_length > icp->conn_params.max_burst_length) {
		cmn_err(CE_WARN, "iscsi connection(%u) received r2t but pkt "
		    "is larger than MaxBurstLength itt:0x%x len:0x%x - "
		    "protocol error",
		    icp->conn_oid, irhp->itt, data_length);
	} else {
		iscsi_handle_r2t(icp, icmdp, ntohl(irhp->data_offset),
		    data_length, irhp->ttt);
		status = ISCSI_STATUS_SUCCESS;
	}

	mutex_exit(&icmdp->cmd_mutex);
	mutex_exit(&icp->conn_queue_active.mutex);
	mutex_exit(&isp->sess_queue_pending.mutex);

	return (status);
}


/*
 * iscsi_rx_process_nop - Process a received nop.  If nop is in response
 * to a ping we sent update stats.  If initiated by the target we need
 * to response back to the target with a nop.  Schedule the response.
 */
/* ARGSUSED */
static iscsi_status_t
iscsi_rx_process_nop(iscsi_conn_t *icp, iscsi_hdr_t *ihp, char *data)
{
	iscsi_status_t		rval	= ISCSI_STATUS_SUCCESS;
	iscsi_sess_t		*isp	= NULL;
	iscsi_nop_in_hdr_t	*inihp	= (iscsi_nop_in_hdr_t *)ihp;
	iscsi_cmd_t		*icmdp	= NULL;

	ASSERT(icp != NULL);
	ASSERT(ihp != NULL);
	/* ASSERT(data != NULL) data is allowed to be NULL */
	isp = icp->conn_sess;
	ASSERT(isp != NULL);

	if (icp->conn_expstatsn != ntohl(inihp->statsn)) {
		cmn_err(CE_WARN, "iscsi connection(%u) protocol error - "
		    "received status out of order itt:0x%x statsn:0x%x "
		    "expstatsn:0x%x", icp->conn_oid, inihp->itt,
		    ntohl(inihp->statsn), icp->conn_expstatsn);
		return (ISCSI_STATUS_PROTOCOL_ERROR);
	}

	mutex_enter(&isp->sess_queue_pending.mutex);
	mutex_enter(&icp->conn_queue_active.mutex);
	mutex_enter(&isp->sess_cmdsn_mutex);
	if (inihp->itt != ISCSI_RSVD_TASK_TAG) {
		if (!ISCSI_SUCCESS(iscsi_rx_process_itt_to_icmdp(
		    isp, ihp, &icmdp))) {
			mutex_exit(&isp->sess_cmdsn_mutex);
			mutex_exit(&icp->conn_queue_active.mutex);
			mutex_exit(&isp->sess_queue_pending.mutex);
			return (ISCSI_STATUS_PROTOCOL_ERROR);
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

	return (rval);
}


/*
 * iscsi_rx_process_reject_rsp - The server rejected a PDU
 */
static iscsi_status_t
iscsi_rx_process_reject_rsp(iscsi_conn_t *icp,
    iscsi_hdr_t *ihp, char *data)
{
	iscsi_reject_rsp_hdr_t		*irrhp = (iscsi_reject_rsp_hdr_t *)ihp;
	iscsi_sess_t			*isp		= NULL;
	uint32_t			dlength		= 0;
	iscsi_hdr_t			*old_ihp	= NULL;

	ASSERT(icp != NULL);
	isp = icp->conn_sess;
	ASSERT(ihp != NULL);
	ASSERT(data != NULL);

	/* make sure we only Ack Status numbers that we've actually received. */
	if (icp->conn_expstatsn == ntohl(irrhp->statsn)) {
		icp->conn_expstatsn++;
	} else {
		cmn_err(CE_WARN, "iscsi connection(%u) protocol error - "
		    "received status out of order itt:0x%x statsn:0x%x "
		    "expstatsn:0x%x", icp->conn_oid, ihp->itt,
		    ntohl(irrhp->statsn), icp->conn_expstatsn);
		return (ISCSI_STATUS_PROTOCOL_ERROR);
	}

	/* update expcmdsn and maxcmdsn */
	mutex_enter(&isp->sess_cmdsn_mutex);
	iscsi_update_flow_control(isp, ntohl(irrhp->maxcmdsn),
	    ntohl(irrhp->expcmdsn));
	mutex_exit(&isp->sess_cmdsn_mutex);

	/* If we don't have the rejected header we can't do anything */
	dlength = n2h24(irrhp->dlength);
	if (dlength < sizeof (iscsi_hdr_t)) {
		return (ISCSI_STATUS_PROTOCOL_ERROR);
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
			return (ISCSI_STATUS_PROTOCOL_ERROR);
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
			(void) iscsi_rx_process_rejected_tsk_mgt(icp,
			    old_ihp);
			break;
		default:
			cmn_err(CE_WARN, "iscsi connection(%u) protocol error "
			    "- received a reject for a command(0x%02x) not "
			    "sent as an immediate", icp->conn_oid,
			    old_ihp->opcode);
			return (ISCSI_STATUS_PROTOCOL_ERROR);
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
		cmn_err(CE_WARN, "iscsi connection(%u) closing connection - "
		    "target requested itt:0x%x reason:0x%x",
		    icp->conn_oid, ihp->itt, irrhp->reason);
		return (ISCSI_STATUS_PROTOCOL_ERROR);
	}

	return (ISCSI_STATUS_SUCCESS);
}


/*
 * iscsi_rx_process_rejected_tsk_mgt -
 */
static iscsi_status_t
iscsi_rx_process_rejected_tsk_mgt(iscsi_conn_t *icp,
    iscsi_hdr_t *old_ihp)
{
	iscsi_sess_t			*isp	= NULL;
	iscsi_cmd_t			*icmdp	= NULL;

	ASSERT(icp != NULL);
	isp = icp->conn_sess;
	ASSERT(old_ihp != NULL);
	ASSERT(icp->conn_sess != NULL);

	mutex_enter(&icp->conn_queue_active.mutex);
	mutex_enter(&isp->sess_cmdsn_mutex);
	if (!ISCSI_SUCCESS(iscsi_rx_process_itt_to_icmdp(
	    isp, old_ihp, &icmdp))) {
		mutex_exit(&isp->sess_cmdsn_mutex);
		mutex_exit(&icp->conn_queue_active.mutex);
		return (ISCSI_STATUS_PROTOCOL_ERROR);
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

	return (ISCSI_STATUS_SUCCESS);
}


/*
 * iscsi_rx_process_task_mgt_rsp -
 */
/* ARGSUSED */
static iscsi_status_t
iscsi_rx_process_task_mgt_rsp(iscsi_conn_t *icp,
    iscsi_hdr_t *ihp, void *data)
{
	iscsi_sess_t			*isp		= NULL;
	iscsi_scsi_task_mgt_rsp_hdr_t	*istmrhp	= NULL;
	iscsi_cmd_t			*icmdp		= NULL;

	ASSERT(ihp != NULL);
	ASSERT(icp != NULL);
	isp = icp->conn_sess;
	ASSERT(isp != NULL);
	istmrhp = (iscsi_scsi_task_mgt_rsp_hdr_t *)ihp;

	if (icp->conn_expstatsn == ntohl(istmrhp->statsn)) {
		icp->conn_expstatsn++;
	} else {
		cmn_err(CE_WARN, "iscsi connection(%u) protocol error - "
		    "received status out of order itt:0x%x statsn:0x%x "
		    "expstatsn:0x%x", icp->conn_oid, istmrhp->itt,
		    ntohl(istmrhp->statsn), icp->conn_expstatsn);
		return (ISCSI_STATUS_PROTOCOL_ERROR);
	}

	/* make sure we only Ack Status numbers that we've actually received. */
	mutex_enter(&icp->conn_queue_active.mutex);
	mutex_enter(&isp->sess_cmdsn_mutex);
	if (!ISCSI_SUCCESS(iscsi_rx_process_itt_to_icmdp(isp, ihp, &icmdp))) {
		mutex_exit(&isp->sess_cmdsn_mutex);
		mutex_exit(&icp->conn_queue_active.mutex);
		return (ISCSI_STATUS_PROTOCOL_ERROR);
	}

	/* update expcmdsn and maxcmdn */
	iscsi_update_flow_control(isp, ntohl(istmrhp->maxcmdsn),
	    ntohl(istmrhp->expcmdsn));
	mutex_exit(&isp->sess_cmdsn_mutex);

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
		case SCSI_TCP_TM_RESP_NO_LUN:
		case SCSI_TCP_TM_RESP_TASK_ALLEGIANT:
		case SCSI_TCP_TM_RESP_NO_FAILOVER:
		case SCSI_TCP_TM_RESP_IN_PRGRESS:
		case SCSI_TCP_TM_RESP_REJECTED:
		default:
			/*
			 * Something is out of sync.  Flush
			 * active queues and resync the
			 * the connection to try and recover
			 * to a known state.
			 */
			mutex_exit(&icp->conn_queue_active.mutex);
			return (ISCSI_STATUS_PROTOCOL_ERROR);
		}
		break;

	default:
		cmn_err(CE_WARN, "iscsi connection(%u) protocol error - "
		    "received a task mgt response for a non-task mgt "
		    "cmd itt:0x%x type:%d", icp->conn_oid, istmrhp->itt,
		    icmdp->cmd_type);
		mutex_exit(&icp->conn_queue_active.mutex);
		return (ISCSI_STATUS_PROTOCOL_ERROR);
	}

	mutex_exit(&icp->conn_queue_active.mutex);
	return (ISCSI_STATUS_SUCCESS);
}


/*
 * iscsi_rx_process_logout -
 *
 */
/* ARGSUSED */
static iscsi_status_t
iscsi_rx_process_logout_rsp(iscsi_conn_t *icp, iscsi_hdr_t *ihp, char *data)
{
	iscsi_status_t		rval	= ISCSI_STATUS_SUCCESS;
	iscsi_sess_t		*isp	= icp->conn_sess;
	iscsi_logout_rsp_hdr_t	*ilrhp	= (iscsi_logout_rsp_hdr_t *)ihp;
	iscsi_cmd_t		*icmdp	= NULL;

	ASSERT(icp != NULL);
	ASSERT(ihp != NULL);
	isp = icp->conn_sess;
	ASSERT(isp != NULL);

	if (icp->conn_expstatsn != ntohl(ilrhp->statsn)) {
		cmn_err(CE_WARN, "iscsi connection(%u) protocol error - "
		    "received status out of order itt:0x%x statsn:0x%x "
		    "expstatsn:0x%x", icp->conn_oid, ilrhp->itt,
		    ntohl(ilrhp->statsn), icp->conn_expstatsn);
		return (ISCSI_STATUS_PROTOCOL_ERROR);
	}

	mutex_enter(&icp->conn_queue_active.mutex);
	mutex_enter(&isp->sess_cmdsn_mutex);
	if (ilrhp->itt != ISCSI_RSVD_TASK_TAG) {
		if (!ISCSI_SUCCESS(iscsi_rx_process_itt_to_icmdp(
		    isp, ihp, &icmdp))) {
			mutex_exit(&isp->sess_cmdsn_mutex);
			mutex_exit(&icp->conn_queue_active.mutex);
			return (ISCSI_STATUS_PROTOCOL_ERROR);
		}
	}

	/* update expcmdsn and maxcmdsn */
	iscsi_update_flow_control(isp, ntohl(ilrhp->maxcmdsn),
	    ntohl(ilrhp->expcmdsn));
	mutex_exit(&isp->sess_cmdsn_mutex);

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
		/* logout completed successfully notify the conn */
		mutex_enter(&icp->conn_state_mutex);
		(void) iscsi_conn_state_machine(icp, ISCSI_CONN_EVENT_T17);
		mutex_exit(&icp->conn_state_mutex);
		break;
	default:
		mutex_exit(&icp->conn_queue_active.mutex);
		rval = ISCSI_STATUS_PROTOCOL_ERROR;
	}

	return (rval);
}


/*
 * iscsi_rx_process_logout -
 *
 */
/* ARGSUSED */
static iscsi_status_t
iscsi_rx_process_async_rsp(iscsi_conn_t *icp, iscsi_hdr_t *ihp, char *data)
{
	iscsi_status_t		rval	= ISCSI_STATUS_SUCCESS;
	iscsi_async_evt_hdr_t	*iaehp	= (iscsi_async_evt_hdr_t *)ihp;

	ASSERT(icp != NULL);
	ASSERT(ihp != NULL);
	ASSERT(icp->conn_sess != NULL);

	if (icp->conn_expstatsn != ntohl(iaehp->statsn)) {
		cmn_err(CE_WARN, "iscsi connection(%u) protocol error - "
		    "received status out of order itt:0x%x statsn:0x%x "
		    "expstatsn:0x%x", icp->conn_oid, ihp->itt,
		    ntohl(iaehp->statsn), icp->conn_expstatsn);
		return (ISCSI_STATUS_PROTOCOL_ERROR);
	}

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
		 * (ex. LUN addition/removal).  Take a general
		 * action to these events of dis/reconnecting.
		 * Once reconnected we perform a reenumeration.
		 */
		mutex_enter(&icp->conn_state_mutex);
		(void) iscsi_conn_state_machine(icp, ISCSI_CONN_EVENT_T14);
		mutex_exit(&icp->conn_state_mutex);
		break;

	case ISCSI_ASYNC_EVENT_REQUEST_LOGOUT:
		/* Target has requested this connection to logout. */
		mutex_enter(&icp->conn_state_mutex);
		(void) iscsi_conn_state_machine(icp, ISCSI_CONN_EVENT_T14);
		mutex_exit(&icp->conn_state_mutex);
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
		iscsi_conn_set_login_min_max(icp, iaehp->param2, iaehp->param3);
		mutex_enter(&icp->conn_state_mutex);
		(void) iscsi_conn_state_machine(icp, ISCSI_CONN_EVENT_T14);
		mutex_exit(&icp->conn_state_mutex);
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
		iscsi_conn_set_login_min_max(icp, iaehp->param2, iaehp->param3);
		mutex_enter(&icp->conn_state_mutex);
		(void) iscsi_conn_state_machine(icp, ISCSI_CONN_EVENT_T14);
		mutex_exit(&icp->conn_state_mutex);
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
		mutex_enter(&icp->conn_state_mutex);
		(void) iscsi_conn_state_machine(icp, ISCSI_CONN_EVENT_T14);
		mutex_exit(&icp->conn_state_mutex);
		break;

	case ISCSI_ASYNC_EVENT_VENDOR_SPECIFIC:
		/*
		 * We currently don't handle any vendor
		 * specific async events.  So just ignore
		 * the request.
		 */
		mutex_enter(&icp->conn_state_mutex);
		(void) iscsi_conn_state_machine(icp, ISCSI_CONN_EVENT_T14);
		mutex_exit(&icp->conn_state_mutex);
		break;
	default:
		rval = ISCSI_STATUS_PROTOCOL_ERROR;
	}

	return (rval);
}

/*
 * iscsi_rx_process_text_rsp - processes iSCSI text response.  It sets
 * the cmd_result field of the command data structure with the actual
 * status value instead of returning the status value.  The return value
 * is SUCCESS in order to let iscsi_handle_text control the operation of
 * a text request.
 * Test requests are a handled a little different than other types of
 * iSCSI commands because the initiator sends additional empty text requests
 * in order to obtain the remaining responses required to complete the
 * request.  iscsi_handle_text controls the operation of text request, while
 * iscsi_rx_process_text_rsp just process the current response.
 */
static iscsi_status_t
iscsi_rx_process_text_rsp(iscsi_conn_t *icp, iscsi_hdr_t *ihp, char *data)
{
	iscsi_sess_t		*isp	= NULL;
	iscsi_text_rsp_hdr_t	*ithp	= (iscsi_text_rsp_hdr_t *)ihp;
	iscsi_cmd_t		*icmdp	= NULL;
	boolean_t		final	= B_FALSE;
	uint32_t		data_len;

	ASSERT(icp != NULL);
	ASSERT(ihp != NULL);
	ASSERT(data != NULL);

	isp = icp->conn_sess;
	ASSERT(isp != NULL);

	if (icp->conn_expstatsn == ntohl(ithp->statsn)) {
		icp->conn_expstatsn++;
	} else {
		cmn_err(CE_WARN, "iscsi connection(%u) protocol error - "
		    "received status out of order itt:0x%x statsn:0x%x "
		    "expstatsn:0x%x", icp->conn_oid, ithp->itt,
		    ntohl(ithp->statsn), icp->conn_expstatsn);
		return (ISCSI_STATUS_PROTOCOL_ERROR);
	}

	mutex_enter(&icp->conn_queue_active.mutex);
	mutex_enter(&isp->sess_cmdsn_mutex);
	if (!ISCSI_SUCCESS(iscsi_rx_process_itt_to_icmdp(isp, ihp, &icmdp))) {
		mutex_exit(&isp->sess_cmdsn_mutex);
		mutex_exit(&icp->conn_queue_active.mutex);
		return (ISCSI_STATUS_PROTOCOL_ERROR);
	}

	/* update expcmdsn and maxcmdsn */
	iscsi_update_flow_control(isp, ntohl(ithp->maxcmdsn),
	    ntohl(ithp->expcmdsn));
	mutex_exit(&isp->sess_cmdsn_mutex);

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
		return (ISCSI_STATUS_PROTOCOL_ERROR);
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
		return (ISCSI_STATUS_PROTOCOL_ERROR);
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
	cmd_table_idx = ihp->itt % ISCSI_CMD_TABLE_SIZE;
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
 * iSCSI PDUs after login.  No PDUs should call sendpdu()
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
		    ((icmdp = isp->sess_queue_pending.head) != NULL) &&
		    (((icmdp->cmd_type != ISCSI_CMD_TYPE_SCSI) &&
		    (ISCSI_CONN_STATE_FULL_FEATURE(icp->conn_state))) ||
		    (icp->conn_state == ISCSI_CONN_STATE_LOGGED_IN))) {

			/* update command with this connection info */
			icmdp->cmd_conn = icp;
			/* attempt to send this command */
			iscsi_cmd_state_machine(icmdp, ISCSI_CMD_EVENT_E2, isp);

			ASSERT(!mutex_owned(&isp->sess_queue_pending.mutex));
			mutex_enter(&isp->sess_queue_pending.mutex);
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
	case ISCSI_CMD_TYPE_R2T:
		rval = iscsi_tx_r2t(isp, icmdp);
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
	struct buf		*bp		= NULL;
	union {
		iscsi_scsi_cmd_hdr_t	isch;
		iscsi_addl_hdr_t	iah;
		uchar_t			arr[ADDLHDRSZ(DEF_CDB_LEN)];
	} hdr_un;
	iscsi_scsi_cmd_hdr_t	*ihp		=
	    (iscsi_scsi_cmd_hdr_t *)&hdr_un.isch;
	int			cdblen		= 0;
	size_t			buflen		= 0;
	uint32_t		imdata		= 0;
	uint32_t		first_burst_length = 0;

	ASSERT(isp != NULL);
	ASSERT(icmdp != NULL);
	pkt = icmdp->cmd_un.scsi.pkt;
	ASSERT(pkt != NULL);
	bp = icmdp->cmd_un.scsi.bp;
	icp = icmdp->cmd_conn;
	ASSERT(icp != NULL);

	/* Reset counts in case we are on a retry */
	icmdp->cmd_un.scsi.data_transferred = 0;

	if (icmdp->cmd_un.scsi.cmdlen > DEF_CDB_LEN) {
		cdblen = icmdp->cmd_un.scsi.cmdlen;
		ihp = kmem_zalloc(ADDLHDRSZ(cdblen), KM_SLEEP);
	} else {
		/*
		 * only bzero the basic header; the additional header
		 * will be set up correctly later, if needed
		 */
		bzero(ihp, sizeof (iscsi_scsi_cmd_hdr_t));
	}
	ihp->opcode		= ISCSI_OP_SCSI_CMD;
	ihp->itt		= icmdp->cmd_itt;
	mutex_enter(&isp->sess_cmdsn_mutex);
	ihp->cmdsn		= htonl(isp->sess_cmdsn);
	isp->sess_cmdsn++;
	mutex_exit(&isp->sess_cmdsn_mutex);
	ihp->expstatsn		= htonl(icp->conn_expstatsn);
	icp->conn_laststatsn = icp->conn_expstatsn;

	pkt->pkt_state = (STATE_GOT_BUS | STATE_GOT_TARGET);
	pkt->pkt_reason = CMD_INCOMPLETE;

	/*
	 * Sestion 12.11 of the iSCSI specification has a good table
	 * describing when uncolicited data and/or immediate data
	 * should be sent.
	 */
	bp = icmdp->cmd_un.scsi.bp;
	if ((bp != NULL) && bp->b_bcount) {
		buflen = bp->b_bcount;
		first_burst_length = icp->conn_params.first_burst_length;

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
				imdata = MIN(MIN(buflen,
				    first_burst_length),
				    icmdp->cmd_conn->conn_params.
				    max_xmit_data_seg_len);

				/*
				 * if everything fits immediate, or
				 * we can send all burst data immediate
				 * (not unsol), set F
				 */
				if ((imdata == buflen) ||
				    (imdata == first_burst_length)) {
					ihp->flags |= ISCSI_FLAG_FINAL;
				}

				hton24(ihp->dlength, imdata);
			}

			/* total data transfer length */
			ihp->data_length = htonl(buflen);
		}
	} else {
		ihp->flags = ISCSI_FLAG_FINAL;
		buflen = 0;
	}

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
	 * to send.  The only case the sendpdu()
	 * will fail is a on a connection disconnect
	 * in that case the command will be flushed.
	 */
	pkt->pkt_state |= STATE_SENT_CMD;

	icmdp->cmd_un.scsi.data_transferred += imdata;

	/*
	 * Check if there is additional data to transfer beyond what
	 * will be sent as part of the initial command.  If InitialR2T
	 * is disabled then we should fake up a R2T so all the data,
	 * up to first burst length, is sent in an unsolicited
	 * fashion.  We have already sent as much immediate data
	 * as possible.
	 */
	if ((buflen > 0) &&
	    ((bp->b_flags & B_READ) == 0) &&
	    (icp->conn_params.initial_r2t == 0) &&
	    (MIN(first_burst_length, buflen) - imdata > 0)) {

		uint32_t xfer_len = MIN(first_burst_length, buflen) - imdata;
		/* data will be chunked at tx */
		iscsi_handle_r2t(icp, icmdp, imdata,
		    xfer_len, ISCSI_RSVD_TASK_TAG);
	}

	/* release pending queue mutex across the network call */
	mutex_exit(&isp->sess_queue_pending.mutex);

	/* Transfer Cmd PDU */
	if (imdata) {
		rval = iscsi_net->sendpdu(icp->conn_socket,
		    (iscsi_hdr_t *)ihp, icmdp->cmd_un.scsi.bp->b_un.b_addr,
		    ISCSI_CONN_TO_NET_DIGEST(icp));
		if (ISCSI_SUCCESS(rval)) {
			KSTAT_ADD_CONN_TX_BYTES(icp, imdata);
		}
	} else {
		rval = iscsi_net->sendpdu(icp->conn_socket,
		    (iscsi_hdr_t *)ihp, NULL,
		    ISCSI_CONN_TO_NET_DIGEST(icp));
	}
	if (cdblen) {
		kmem_free(ihp, ADDLHDRSZ(cdblen));
	}

	return (rval);
}


/*
 * iscsi_tx_r2t -
 *
 */
static iscsi_status_t
iscsi_tx_r2t(iscsi_sess_t *isp, iscsi_cmd_t *icmdp)
{
	iscsi_status_t	rval		= ISCSI_STATUS_SUCCESS;
	iscsi_conn_t	*icp		= NULL;
	iscsi_cmd_t	*orig_icmdp	= NULL;

	ASSERT(isp != NULL);
	ASSERT(icmdp != NULL);
	icp = icmdp->cmd_conn;
	ASSERT(icp);
	orig_icmdp = icmdp->cmd_un.r2t.icmdp;
	ASSERT(orig_icmdp);

	/* validate the offset and length against the buffer size */
	if ((icmdp->cmd_un.r2t.offset + icmdp->cmd_un.r2t.length) >
	    orig_icmdp->cmd_un.scsi.bp->b_bcount) {
		cmn_err(CE_WARN, "iscsi session(%u) ignoring invalid r2t "
		    "for icmd itt:0x%x offset:0x%x length:0x%x bufsize:0x%lx",
		    isp->sess_oid, icmdp->cmd_itt, icmdp->cmd_un.r2t.offset,
		    icmdp->cmd_un.r2t.length, orig_icmdp->cmd_un.scsi.bp->
		    b_bcount);
		mutex_exit(&isp->sess_queue_pending.mutex);
		return (ISCSI_STATUS_INTERNAL_ERROR);
	}
	ASSERT(orig_icmdp->cmd_un.scsi.r2t_icmdp);

	rval = iscsi_tx_data(isp, icp, orig_icmdp, icmdp->cmd_ttt,
	    icmdp->cmd_un.r2t.length, icmdp->cmd_un.r2t.offset);

	mutex_enter(&orig_icmdp->cmd_mutex);
	orig_icmdp->cmd_un.scsi.r2t_icmdp = NULL;
	icmdp->cmd_un.r2t.icmdp = NULL;
	/*
	 * we're finished with this r2t; there could be another r2t
	 * waiting on us to finish, so signal it.
	 */
	cv_broadcast(&orig_icmdp->cmd_completion);
	mutex_exit(&orig_icmdp->cmd_mutex);
	/*
	 * the parent command may be waiting for us to finish; if so,
	 * wake the _ic_ thread
	 */
	if ((orig_icmdp->cmd_state == ISCSI_CMD_STATE_COMPLETED) &&
	    (ISCSI_SESS_STATE_FULL_FEATURE(isp->sess_state)))
		iscsi_thread_send_wakeup(isp->sess_ic_thread);
	ASSERT(!mutex_owned(&isp->sess_queue_pending.mutex));
	return (rval);
}


/*
 * iscsi_tx_data -
 */
static iscsi_status_t
iscsi_tx_data(iscsi_sess_t *isp, iscsi_conn_t *icp, iscsi_cmd_t *icmdp,
    uint32_t ttt, size_t datalen, size_t offset)
{
	iscsi_status_t		rval		= ISCSI_STATUS_SUCCESS;
	struct buf		*bp		= NULL;
	size_t			remainder	= 0;
	size_t			chunk		= 0;
	char			*data		= NULL;
	uint32_t		data_sn		= 0;
	iscsi_data_hdr_t	idhp;
	uint32_t		itt;
	uint32_t		lun;

	ASSERT(isp != NULL);
	ASSERT(icp != NULL);
	ASSERT(icmdp != NULL);
	bp = icmdp->cmd_un.scsi.bp;

	/* verify there is data to send */
	if (bp == NULL) {
		mutex_exit(&isp->sess_queue_pending.mutex);
		return (ISCSI_STATUS_INTERNAL_ERROR);
	}

	itt = icmdp->cmd_itt;
	lun = icmdp->cmd_un.scsi.lun;

	/*
	 * update the LUN with the amount of data we will
	 * transfer.  If there is a failure it's because of
	 * a network fault and the command will get flushed.
	 */
	icmdp->cmd_un.scsi.data_transferred += datalen;

	/* release pending queue mutex across the network call */
	mutex_exit(&isp->sess_queue_pending.mutex);

	remainder = datalen;
	while (remainder) {

		/* Check so see if we need to chunk the data */
		if ((icp->conn_params.max_xmit_data_seg_len > 0) &&
		    (remainder > icp->conn_params.max_xmit_data_seg_len)) {
			chunk = icp->conn_params.max_xmit_data_seg_len;
		} else {
			chunk = remainder;
		}

		/* setup iscsi data hdr */
		bzero(&idhp, sizeof (iscsi_data_hdr_t));
		idhp.opcode	= ISCSI_OP_SCSI_DATA;
		idhp.itt	= itt;
		idhp.ttt	= ttt;
		ISCSI_LUN_BYTE_COPY(idhp.lun, lun);
		idhp.expstatsn	= htonl(icp->conn_expstatsn);
		icp->conn_laststatsn = icp->conn_expstatsn;
		idhp.datasn	= htonl(data_sn);
		data_sn++;
		idhp.offset	= htonl(offset);
		hton24(idhp.dlength, chunk);

		if (chunk == remainder) {
			idhp.flags = ISCSI_FLAG_FINAL; /* final chunk */
		}

		/* setup data */
		data = bp->b_un.b_addr + offset;

		/*
		 * Keep track of how much data we have
		 * transfer so far and how much is remaining.
		 */
		remainder -= chunk;
		offset += chunk;

		rval = iscsi_net->sendpdu(icp->conn_socket,
		    (iscsi_hdr_t *)&idhp, data,
		    ISCSI_CONN_TO_NET_DIGEST(icp));

		if (ISCSI_SUCCESS(rval)) {
			KSTAT_ADD_CONN_TX_BYTES(icp, chunk);
		} else {
			break;
		}
	}

	return (rval);
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
	iscsi_nop_out_hdr_t	inohp;

	ASSERT(isp != NULL);
	ASSERT(icmdp != NULL);
	icp = icmdp->cmd_conn;
	ASSERT(icp != NULL);

	bzero(&inohp, sizeof (iscsi_nop_out_hdr_t));
	inohp.opcode	= ISCSI_OP_NOOP_OUT | ISCSI_OP_IMMEDIATE;
	inohp.flags	= ISCSI_FLAG_FINAL;
	inohp.itt	= icmdp->cmd_itt;
	inohp.ttt	= icmdp->cmd_ttt;
	mutex_enter(&isp->sess_cmdsn_mutex);
	inohp.cmdsn	= htonl(isp->sess_cmdsn);
	mutex_exit(&isp->sess_cmdsn_mutex);
	inohp.expstatsn	= htonl(icp->conn_expstatsn);
	icp->conn_laststatsn = icp->conn_expstatsn;

	/* release pending queue mutex across the network call */
	mutex_exit(&isp->sess_queue_pending.mutex);

	rval = iscsi_net->sendpdu(icp->conn_socket,
	    (iscsi_hdr_t *)&inohp, NULL,
	    ISCSI_CONN_TO_NET_DIGEST(icp));

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
	iscsi_scsi_task_mgt_hdr_t	istmh;

	ASSERT(isp != NULL);
	ASSERT(icmdp != NULL);
	icp = icmdp->cmd_conn;
	ASSERT(icp != NULL);

	bzero(&istmh, sizeof (iscsi_scsi_task_mgt_hdr_t));
	mutex_enter(&isp->sess_cmdsn_mutex);
	istmh.cmdsn	= htonl(isp->sess_cmdsn);
	mutex_exit(&isp->sess_cmdsn_mutex);
	istmh.expstatsn = htonl(icp->conn_expstatsn);
	icp->conn_laststatsn = icp->conn_expstatsn;
	istmh.itt	= icmdp->cmd_itt;
	istmh.opcode	= ISCSI_OP_SCSI_TASK_MGT_MSG | ISCSI_OP_IMMEDIATE;
	istmh.function	= ISCSI_FLAG_FINAL | ISCSI_TM_FUNC_ABORT_TASK;
	ISCSI_LUN_BYTE_COPY(istmh.lun,
	    icmdp->cmd_un.abort.icmdp->cmd_un.scsi.lun);
	istmh.rtt	= icmdp->cmd_un.abort.icmdp->cmd_itt;

	/* release pending queue mutex across the network call */
	mutex_exit(&isp->sess_queue_pending.mutex);

	rval = iscsi_net->sendpdu(icp->conn_socket,
	    (iscsi_hdr_t *)&istmh, NULL,
	    ISCSI_CONN_TO_NET_DIGEST(icp));

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
	iscsi_scsi_task_mgt_hdr_t	istmh;

	ASSERT(isp != NULL);
	ASSERT(icmdp != NULL);
	icp = icmdp->cmd_conn;
	ASSERT(icp != NULL);

	bzero(&istmh, sizeof (iscsi_scsi_task_mgt_hdr_t));
	istmh.opcode	= ISCSI_OP_SCSI_TASK_MGT_MSG | ISCSI_OP_IMMEDIATE;
	mutex_enter(&isp->sess_cmdsn_mutex);
	istmh.cmdsn	= htonl(isp->sess_cmdsn);
	mutex_exit(&isp->sess_cmdsn_mutex);
	istmh.expstatsn	= htonl(icp->conn_expstatsn);
	istmh.itt	= icmdp->cmd_itt;

	switch (icmdp->cmd_un.reset.level) {
	case RESET_LUN:
		istmh.function	= ISCSI_FLAG_FINAL |
		    ISCSI_TM_FUNC_LOGICAL_UNIT_RESET;
		ISCSI_LUN_BYTE_COPY(istmh.lun, icmdp->cmd_lun->lun_num);
		break;
	case RESET_TARGET:
	case RESET_BUS:
		istmh.function	= ISCSI_FLAG_FINAL |
		    ISCSI_TM_FUNC_TARGET_WARM_RESET;
		break;
	default:
		/* unsupported / unknown level */
		ASSERT(FALSE);
		break;
	}

	/* release pending queue mutex across the network call */
	mutex_exit(&isp->sess_queue_pending.mutex);

	rval = iscsi_net->sendpdu(icp->conn_socket,
	    (iscsi_hdr_t *)&istmh, NULL,
	    ISCSI_CONN_TO_NET_DIGEST(icp));

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
	iscsi_logout_hdr_t	ilh;

	ASSERT(isp != NULL);
	ASSERT(icmdp != NULL);
	icp = icmdp->cmd_conn;
	ASSERT(icp != NULL);

	bzero(&ilh, sizeof (iscsi_logout_hdr_t));
	ilh.opcode	= ISCSI_OP_LOGOUT_CMD | ISCSI_OP_IMMEDIATE;
	ilh.flags	= ISCSI_FLAG_FINAL | ISCSI_LOGOUT_REASON_CLOSE_SESSION;
	ilh.itt		= icmdp->cmd_itt;
	ilh.cid		= icp->conn_cid;
	mutex_enter(&isp->sess_cmdsn_mutex);
	ilh.cmdsn	= htonl(isp->sess_cmdsn);
	mutex_exit(&isp->sess_cmdsn_mutex);
	ilh.expstatsn	= htonl(icp->conn_expstatsn);

	/* release pending queue mutex across the network call */
	mutex_exit(&isp->sess_queue_pending.mutex);

	rval = iscsi_net->sendpdu(icp->conn_socket,
	    (iscsi_hdr_t *)&ilh, NULL,
	    ISCSI_CONN_TO_NET_DIGEST(icp));

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
	iscsi_text_hdr_t	ith;

	ASSERT(isp != NULL);
	ASSERT(icmdp != NULL);
	icp = icmdp->cmd_conn;
	ASSERT(icp != NULL);

	bzero(&ith, sizeof (iscsi_text_hdr_t));
	ith.opcode	= ISCSI_OP_TEXT_CMD;
	ith.flags	= ISCSI_FLAG_FINAL;
	hton24(ith.dlength, icmdp->cmd_un.text.data_len);
	ith.itt		= icmdp->cmd_itt;
	ith.ttt		= icmdp->cmd_un.text.ttt;
	mutex_enter(&isp->sess_cmdsn_mutex);
	ith.cmdsn	= htonl(isp->sess_cmdsn);
	isp->sess_cmdsn++;
	ith.expstatsn	= htonl(icp->conn_expstatsn);
	mutex_exit(&isp->sess_cmdsn_mutex);
	bcopy(icmdp->cmd_un.text.lun, ith.rsvd4, sizeof (ith.rsvd4));

	/* release pending queue mutex across the network call */
	mutex_exit(&isp->sess_queue_pending.mutex);

	rval = iscsi_net->sendpdu(icp->conn_socket,
	    (iscsi_hdr_t *)&ith, icmdp->cmd_un.text.buf,
	    ISCSI_CONN_TO_NET_DIGEST(icp));

	return (rval);
}

/*
 * +--------------------------------------------------------------------+
 * | End of protocol send routines					|
 * +--------------------------------------------------------------------+
 */

/*
 * iscsi_handle_r2t -
 */
static void
iscsi_handle_r2t(iscsi_conn_t *icp, iscsi_cmd_t *icmdp,
    uint32_t offset, uint32_t length, uint32_t ttt)
{
	iscsi_sess_t	*isp		= NULL;
	iscsi_cmd_t	*new_icmdp	= NULL;

	ASSERT(icp != NULL);
	isp = icp->conn_sess;
	ASSERT(isp != NULL);

	/*
	 * the sosendmsg from a previous r2t can be slow to return;
	 * the array may have sent another r2t at this point, so
	 * wait until the first one finishes and signals us.
	 */
	while (icmdp->cmd_un.scsi.r2t_icmdp != NULL) {
		ASSERT(icmdp->cmd_state != ISCSI_CMD_STATE_COMPLETED);
		cv_wait(&icmdp->cmd_completion, &icmdp->cmd_mutex);
	}
	/*
	 * try to create an R2T task to send it later.  If we can't,
	 * we're screwed, and the command will eventually time out
	 * and be retried by the SCSI layer.
	 */
	new_icmdp = iscsi_cmd_alloc(icp, KM_SLEEP);
	new_icmdp->cmd_type		= ISCSI_CMD_TYPE_R2T;
	new_icmdp->cmd_un.r2t.icmdp	= icmdp;
	new_icmdp->cmd_un.r2t.offset	= offset;
	new_icmdp->cmd_un.r2t.length	= length;
	new_icmdp->cmd_ttt		= ttt;
	new_icmdp->cmd_itt		= icmdp->cmd_itt;
	new_icmdp->cmd_lun		= icmdp->cmd_lun;
	icmdp->cmd_un.scsi.r2t_icmdp	= new_icmdp;

	/*
	 * pending queue mutex is already held by the
	 * tx_thread or rtt_rsp function.
	 */
	iscsi_cmd_state_machine(new_icmdp, ISCSI_CMD_EVENT_E1, isp);
}


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
	new_icmdp->cmd_type		= ISCSI_CMD_TYPE_ABORT;
	new_icmdp->cmd_lun		= icmdp->cmd_lun;
	new_icmdp->cmd_un.abort.icmdp	= icmdp;
	new_icmdp->cmd_conn		= icmdp->cmd_conn;
	icmdp->cmd_un.scsi.abort_icmdp	= new_icmdp;

	/* pending queue mutex is already held by timeout_checks */
	iscsi_cmd_state_machine(new_icmdp, ISCSI_CMD_EVENT_E1, isp);
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
 * iscsi_handle_reset -
 *
 */
iscsi_status_t
iscsi_handle_reset(iscsi_sess_t *isp, int level, iscsi_lun_t *ilp)
{
	iscsi_status_t	rval	= ISCSI_STATUS_SUCCESS;
	iscsi_conn_t	*icp;
	iscsi_cmd_t	icmd;

	ASSERT(isp != NULL);

	bzero(&icmd, sizeof (iscsi_cmd_t));
	icmd.cmd_sig		= ISCSI_SIG_CMD;
	icmd.cmd_state		= ISCSI_CMD_STATE_FREE;
	icmd.cmd_type		= ISCSI_CMD_TYPE_RESET;
	icmd.cmd_lun		= ilp;
	icmd.cmd_un.reset.level	= level;
	icmd.cmd_result		= ISCSI_STATUS_SUCCESS;
	icmd.cmd_completed	= B_FALSE;
	mutex_init(&icmd.cmd_mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&icmd.cmd_completion, NULL, CV_DRIVER, NULL);
	/*
	 * If we received an IO and we are not in the
	 * LOGGED_IN state we are in the process of
	 * failing.  Just respond that we are BUSY.
	 */
	mutex_enter(&isp->sess_state_mutex);
	if (!ISCSI_SESS_STATE_FULL_FEATURE(isp->sess_state)) {
		/* We aren't connected to the target fake success */
		mutex_exit(&isp->sess_state_mutex);
		return (ISCSI_STATUS_SUCCESS);
	}

	mutex_enter(&isp->sess_queue_pending.mutex);
	iscsi_cmd_state_machine(&icmd, ISCSI_CMD_EVENT_E1, isp);
	mutex_exit(&isp->sess_queue_pending.mutex);
	mutex_exit(&isp->sess_state_mutex);

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

			mutex_enter(&icp->conn_queue_active.mutex);
			t_icmdp = icp->conn_queue_active.head;
			while (t_icmdp != NULL) {
				iscsi_cmd_state_machine(t_icmdp,
				    ISCSI_CMD_EVENT_E7, isp);
				t_icmdp = icp->conn_queue_active.head;
			}

			mutex_exit(&icp->conn_queue_active.mutex);
			icp = icp->conn_next;
		}
		rw_exit(&isp->sess_conn_list_rwlock);
	}

	/* clean up */
	cv_destroy(&icmd.cmd_completion);
	mutex_destroy(&icmd.cmd_mutex);

	return (rval);
}


/*
 * iscsi_handle_logout - This function will issue a logout for
 * the session from a specific connection.
 */
iscsi_status_t
iscsi_handle_logout(iscsi_conn_t *icp)
{
	iscsi_sess_t	*isp;
	iscsi_cmd_t	*icmdp;
	int		rval;

	ASSERT(icp != NULL);
	isp = icp->conn_sess;
	ASSERT(isp != NULL);
	ASSERT(isp->sess_hba != NULL);

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

	/*
	 * another way to do this would be to send t17 unconditionally,
	 * but then the _rx_ thread would get bumped out with a receive
	 * error, and send another t17.
	 */
	if (rval != ISCSI_STATUS_SUCCESS) {
		(void) iscsi_conn_state_machine(icp, ISCSI_CONN_EVENT_T17);
	}

	/* clean up */
	iscsi_cmd_free(icmdp);

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
	icmdp->cmd_free		= B_FALSE;
	icmdp->cmd_completed	= B_FALSE;

	icmdp->cmd_un.text.buf		= buf;
	icmdp->cmd_un.text.buf_len	= buf_len;
	icmdp->cmd_un.text.offset	= 0;
	icmdp->cmd_un.text.data_len	= data_len;
	icmdp->cmd_un.text.total_rx_len	= 0;
	icmdp->cmd_un.text.ttt		= ISCSI_RSVD_TASK_TAG;
	icmdp->cmd_un.text.stage	= ISCSI_CMD_TEXT_INITIAL_REQ;

long_text_response:
	mutex_enter(&isp->sess_state_mutex);
	if (!ISCSI_SESS_STATE_FULL_FEATURE(isp->sess_state)) {
		iscsi_cmd_free(icmdp);
		mutex_exit(&isp->sess_state_mutex);
		return (ISCSI_STATUS_NO_CONN_LOGGED_IN);
	}

	mutex_enter(&isp->sess_queue_pending.mutex);
	iscsi_cmd_state_machine(icmdp, ISCSI_CMD_EVENT_E1, isp);
	mutex_exit(&isp->sess_queue_pending.mutex);
	mutex_exit(&isp->sess_state_mutex);

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
		icmdp->cmd_free			= B_FALSE;
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
	iscsi_status_t		rval		= ISCSI_STATUS_SUCCESS;
	iscsi_cmd_t		*icmdp		= NULL;
	struct scsi_pkt		*pkt		= NULL;
	struct buf		*bp		= NULL;
	struct scsi_arq_status  *arqstat	= NULL;
	int			rqlen		= SENSE_LENGTH;

	ASSERT(isp != NULL);
	ASSERT(ucmdp != NULL);

	/*
	 * If the caller didn't provide a sense buffer we need
	 * to allocation one to get the scsi status.
	 */
	if (ucmdp->uscsi_rqlen > SENSE_LENGTH) {
		rqlen = ucmdp->uscsi_rqlen;
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
	pkt->pkt_scbp		= kmem_zalloc(rqlen, KM_SLEEP);
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
	icmdp->cmd_un.scsi.statuslen	= rqlen;
	icmdp->cmd_crc_error_seen	= B_FALSE;
	icmdp->cmd_completed		= B_FALSE;
	icmdp->cmd_result		= ISCSI_STATUS_SUCCESS;

	/*
	 * Step 2. Push IO onto pending queue.  If we aren't in
	 * FULL_FEATURE we need to fail the IO.
	 */
	mutex_enter(&isp->sess_state_mutex);
	if (!ISCSI_SESS_STATE_FULL_FEATURE(isp->sess_state)) {
		mutex_exit(&isp->sess_state_mutex);

		iscsi_cmd_free(icmdp);
		kmem_free(pkt->pkt_cdbp, ucmdp->uscsi_cdblen);
		kmem_free(pkt->pkt_scbp, rqlen);
		kmem_free(pkt, sizeof (struct scsi_pkt));
		kmem_free(bp, sizeof (struct buf));

		return (ISCSI_STATUS_CMD_FAILED);
	}

	mutex_enter(&isp->sess_queue_pending.mutex);
	iscsi_cmd_state_machine(icmdp, ISCSI_CMD_EVENT_E1, isp);
	mutex_exit(&isp->sess_queue_pending.mutex);
	mutex_exit(&isp->sess_state_mutex);

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
		bcopy(arqstat, ucmdp->uscsi_rqbuf,
		    MIN(sizeof (struct scsi_arq_status), rqlen));
	}

	/* clean up */
	iscsi_cmd_free(icmdp);
	kmem_free(pkt->pkt_cdbp, ucmdp->uscsi_cdblen);
	kmem_free(pkt->pkt_scbp, rqlen);
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
			} else
				mutex_exit(&icmdp->cmd_mutex);
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

	while (rc != NULL) {

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
	iscsi_cmd_t	*icmdp, *nicmdp;
	iscsi_conn_t	*icp;

	ASSERT(isp != NULL);

	/* PENDING */
	mutex_enter(&isp->sess_state_mutex);
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
		if ((icmdp->cmd_type == ISCSI_CMD_TYPE_SCSI) ||
		    (icmdp->cmd_type == ISCSI_CMD_TYPE_TEXT))
			continue;

		/* Skip if timeout still in the future */
		if (now <= icmdp->cmd_lbolt_timeout)
			continue;

		/* timeout */
		iscsi_cmd_state_machine(icmdp, ISCSI_CMD_EVENT_E6, isp);
	}
	mutex_exit(&isp->sess_queue_pending.mutex);
	mutex_exit(&isp->sess_state_mutex);

	rw_enter(&isp->sess_conn_list_rwlock, RW_READER);
	icp = isp->sess_conn_list;
	while (icp != NULL) {

		/* ACTIVE */
		mutex_enter(&icp->conn_state_mutex);
		mutex_enter(&isp->sess_queue_pending.mutex);
		mutex_enter(&icp->conn_queue_active.mutex);
		for (icmdp = icp->conn_queue_active.head;
		    icmdp; icmdp = nicmdp) {
			nicmdp = icmdp->cmd_next;

			/* Skip entries with no timeout */
			if (icmdp->cmd_lbolt_timeout == 0)
				continue;

			/* Skip if command is not active */
			if (icmdp->cmd_state != ISCSI_CMD_STATE_ACTIVE)
				continue;

			/* Skip if timeout still in the future */
			if (now <= icmdp->cmd_lbolt_timeout)
				continue;

			/* timeout */
			iscsi_cmd_state_machine(icmdp, ISCSI_CMD_EVENT_E6, isp);
		}
		mutex_exit(&icp->conn_queue_active.mutex);
		mutex_exit(&isp->sess_queue_pending.mutex);
		mutex_exit(&icp->conn_state_mutex);

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

/*
 * +--------------------------------------------------------------------+
 * | End of wd routines						|
 * +--------------------------------------------------------------------+
 */
