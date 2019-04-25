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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/conf.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cpuvar.h>
#include <sys/sdt.h>

#include <sys/socket.h>
#include <sys/strsubr.h>
#include <sys/socketvar.h>
#include <sys/sysmacros.h>

#include <sys/idm/idm.h>
#include <sys/idm/idm_so.h>
#include <hd_crc.h>

extern idm_transport_t  idm_transport_list[];
/*
 * -1 - uninitialized
 * 0  - applicable
 * others - NA
 */
static int iscsi_crc32_hd = -1;

void
idm_pdu_rx(idm_conn_t *ic, idm_pdu_t *pdu)
{
	iscsi_async_evt_hdr_t *async_evt;

	/*
	 * If we are in full-featured mode then route SCSI-related
	 * commands to the appropriate function vector
	 */
	ic->ic_timestamp = ddi_get_lbolt();
	mutex_enter(&ic->ic_state_mutex);
	if (ic->ic_ffp && ic->ic_pdu_events == 0) {
		mutex_exit(&ic->ic_state_mutex);

		if (idm_pdu_rx_forward_ffp(ic, pdu) == B_TRUE) {
			/* Forwarded SCSI-related commands */
			return;
		}
		mutex_enter(&ic->ic_state_mutex);
	}

	/*
	 * If we get here with a SCSI-related PDU then we are not in
	 * full-feature mode and the PDU is a protocol error (SCSI command
	 * PDU's may sometimes be an exception, see below).  All
	 * non-SCSI PDU's get treated them the same regardless of whether
	 * we are in full-feature mode.
	 *
	 * Look at the opcode and in some cases the PDU status and
	 * determine the appropriate event to send to the connection
	 * state machine.  Generate the event, passing the PDU as data.
	 * If the current connection state allows reception of the event
	 * the PDU will be submitted to the IDM client for processing,
	 * otherwise the PDU will be dropped.
	 */
	switch (IDM_PDU_OPCODE(pdu)) {
	case ISCSI_OP_LOGIN_CMD:
		DTRACE_ISCSI_2(login__command, idm_conn_t *, ic,
		    iscsi_login_hdr_t *, (iscsi_login_hdr_t *)pdu->isp_hdr);
		idm_conn_rx_pdu_event(ic, CE_LOGIN_RCV, (uintptr_t)pdu);
		break;
	case ISCSI_OP_LOGIN_RSP:
		idm_parse_login_rsp(ic, pdu, /* RX */ B_TRUE);
		break;
	case ISCSI_OP_LOGOUT_CMD:
		DTRACE_ISCSI_2(logout__command, idm_conn_t *, ic,
		    iscsi_logout_hdr_t *,
		    (iscsi_logout_hdr_t *)pdu->isp_hdr);
		idm_parse_logout_req(ic, pdu, /* RX */ B_TRUE);
		break;
	case ISCSI_OP_LOGOUT_RSP:
		idm_parse_logout_rsp(ic, pdu, /* RX */ B_TRUE);
		break;
	case ISCSI_OP_ASYNC_EVENT:
		async_evt = (iscsi_async_evt_hdr_t *)pdu->isp_hdr;
		switch (async_evt->async_event) {
		case ISCSI_ASYNC_EVENT_REQUEST_LOGOUT:
			idm_conn_rx_pdu_event(ic, CE_ASYNC_LOGOUT_RCV,
			    (uintptr_t)pdu);
			break;
		case ISCSI_ASYNC_EVENT_DROPPING_CONNECTION:
			idm_conn_rx_pdu_event(ic, CE_ASYNC_DROP_CONN_RCV,
			    (uintptr_t)pdu);
			break;
		case ISCSI_ASYNC_EVENT_DROPPING_ALL_CONNECTIONS:
			idm_conn_rx_pdu_event(ic, CE_ASYNC_DROP_ALL_CONN_RCV,
			    (uintptr_t)pdu);
			break;
		case ISCSI_ASYNC_EVENT_SCSI_EVENT:
		case ISCSI_ASYNC_EVENT_PARAM_NEGOTIATION:
		default:
			idm_conn_rx_pdu_event(ic, CE_MISC_RX,
			    (uintptr_t)pdu);
			break;
		}
		break;
	case ISCSI_OP_SCSI_CMD:
		/*
		 * Consider this scenario:  We are a target connection
		 * in "in login" state and a "login success sent" event has
		 * been generated but not yet handled.  Since we've sent
		 * the login response but we haven't actually transitioned
		 * to FFP mode we might conceivably receive a SCSI command
		 * from the initiator before we are ready.  We are actually
		 * in FFP we just don't know it yet -- to address this we
		 * can generate an event corresponding to the SCSI command.
		 * At the point when the event is handled by the state
		 * machine the login request will have been handled and we
		 * should be in FFP.  If we are not in FFP by that time
		 * we can reject the SCSI command with a protocol error.
		 *
		 * This scenario only applies to the target.
		 *
		 * Handle dtrace probe in iscsit so we can find all the
		 * pieces of the CDB
		 */
		idm_conn_rx_pdu_event(ic, CE_MISC_RX, (uintptr_t)pdu);
		break;
	case ISCSI_OP_SCSI_DATA:
		DTRACE_ISCSI_2(data__receive, idm_conn_t *, ic,
		    iscsi_data_hdr_t *,
		    (iscsi_data_hdr_t *)pdu->isp_hdr);
		idm_conn_rx_pdu_event(ic, CE_MISC_RX, (uintptr_t)pdu);
		break;
	case ISCSI_OP_SCSI_TASK_MGT_MSG:
		DTRACE_ISCSI_2(task__command, idm_conn_t *, ic,
		    iscsi_scsi_task_mgt_hdr_t *,
		    (iscsi_scsi_task_mgt_hdr_t *)pdu->isp_hdr);
		idm_conn_rx_pdu_event(ic, CE_MISC_RX, (uintptr_t)pdu);
		break;
	case ISCSI_OP_NOOP_OUT:
		DTRACE_ISCSI_2(nop__receive, idm_conn_t *, ic,
		    iscsi_nop_out_hdr_t *,
		    (iscsi_nop_out_hdr_t *)pdu->isp_hdr);
		idm_conn_rx_pdu_event(ic, CE_MISC_RX, (uintptr_t)pdu);
		break;
	case ISCSI_OP_TEXT_CMD:
		DTRACE_ISCSI_2(text__command, idm_conn_t *, ic,
		    iscsi_text_hdr_t *,
		    (iscsi_text_hdr_t *)pdu->isp_hdr);
		idm_conn_rx_pdu_event(ic, CE_MISC_RX, (uintptr_t)pdu);
		break;
	/* Initiator PDU's */
	case ISCSI_OP_SCSI_DATA_RSP:
	case ISCSI_OP_RTT_RSP:
	case ISCSI_OP_SNACK_CMD:
	case ISCSI_OP_NOOP_IN:
	case ISCSI_OP_TEXT_RSP:
	case ISCSI_OP_REJECT_MSG:
	case ISCSI_OP_SCSI_TASK_MGT_RSP:
		/* Validate received PDU against current state */
		idm_conn_rx_pdu_event(ic, CE_MISC_RX,
		    (uintptr_t)pdu);
		break;
	}
	mutex_exit(&ic->ic_state_mutex);
}

void
idm_pdu_tx_forward(idm_conn_t *ic, idm_pdu_t *pdu)
{
	(*ic->ic_transport_ops->it_tx_pdu)(ic, pdu);
}

boolean_t
idm_pdu_rx_forward_ffp(idm_conn_t *ic, idm_pdu_t *pdu)
{
	/*
	 * If this is an FFP request, call the appropriate handler
	 * and return B_TRUE, otherwise return B_FALSE.
	 */
	switch (IDM_PDU_OPCODE(pdu)) {
	case ISCSI_OP_SCSI_CMD:
		(*ic->ic_conn_ops.icb_rx_scsi_cmd)(ic, pdu);
		return (B_TRUE);
	case ISCSI_OP_SCSI_DATA:
		DTRACE_ISCSI_2(data__receive, idm_conn_t *, ic,
		    iscsi_data_hdr_t *,
		    (iscsi_data_hdr_t *)pdu->isp_hdr);
		(*ic->ic_transport_ops->it_rx_dataout)(ic, pdu);
		return (B_TRUE);
	case ISCSI_OP_SCSI_TASK_MGT_MSG:
		DTRACE_ISCSI_2(task__command, idm_conn_t *, ic,
		    iscsi_scsi_task_mgt_hdr_t *,
		    (iscsi_scsi_task_mgt_hdr_t *)pdu->isp_hdr);
		(*ic->ic_conn_ops.icb_rx_misc)(ic, pdu);
		return (B_TRUE);
	case ISCSI_OP_NOOP_OUT:
		DTRACE_ISCSI_2(nop__receive, idm_conn_t *, ic,
		    iscsi_nop_out_hdr_t *,
		    (iscsi_nop_out_hdr_t *)pdu->isp_hdr);
		(*ic->ic_conn_ops.icb_rx_misc)(ic, pdu);
		return (B_TRUE);
	case ISCSI_OP_TEXT_CMD:
		DTRACE_ISCSI_2(text__command, idm_conn_t *, ic,
		    iscsi_text_hdr_t *,
		    (iscsi_text_hdr_t *)pdu->isp_hdr);
		(*ic->ic_conn_ops.icb_rx_misc)(ic, pdu);
		return (B_TRUE);
		/* Initiator only */
	case ISCSI_OP_SCSI_RSP:
		(*ic->ic_conn_ops.icb_rx_scsi_rsp)(ic, pdu);
		return (B_TRUE);
	case ISCSI_OP_SCSI_DATA_RSP:
		(*ic->ic_transport_ops->it_rx_datain)(ic, pdu);
		return (B_TRUE);
	case ISCSI_OP_RTT_RSP:
		(*ic->ic_transport_ops->it_rx_rtt)(ic, pdu);
		return (B_TRUE);
	case ISCSI_OP_SCSI_TASK_MGT_RSP:
	case ISCSI_OP_TEXT_RSP:
	case ISCSI_OP_NOOP_IN:
		(*ic->ic_conn_ops.icb_rx_misc)(ic, pdu);
		return (B_TRUE);
	default:
		return (B_FALSE);
	}
	/*NOTREACHED*/
}

void
idm_pdu_rx_forward(idm_conn_t *ic, idm_pdu_t *pdu)
{
	/*
	 * Some PDU's specific to FFP get special handling.  This function
	 * will normally never be called in FFP with an FFP PDU since this
	 * is a slow path but in can happen on the target side during
	 * the transition to FFP.  We primarily call
	 * idm_pdu_rx_forward_ffp here to avoid code duplication.
	 */
	if (idm_pdu_rx_forward_ffp(ic, pdu) == B_FALSE) {
		/*
		 * Non-FFP PDU, use generic RC handler
		 */
		(*ic->ic_conn_ops.icb_rx_misc)(ic, pdu);
	}
}

void
idm_parse_login_rsp(idm_conn_t *ic, idm_pdu_t *login_rsp_pdu, boolean_t rx)
{
	iscsi_login_rsp_hdr_t	*login_rsp =
	    (iscsi_login_rsp_hdr_t *)login_rsp_pdu->isp_hdr;
	idm_conn_event_t	new_event;

	if (login_rsp->status_class == ISCSI_STATUS_CLASS_SUCCESS) {
		if (!(login_rsp->flags & ISCSI_FLAG_LOGIN_CONTINUE) &&
		    (login_rsp->flags & ISCSI_FLAG_LOGIN_TRANSIT) &&
		    (ISCSI_LOGIN_NEXT_STAGE(login_rsp->flags) ==
		    ISCSI_FULL_FEATURE_PHASE)) {
			new_event = (rx ? CE_LOGIN_SUCCESS_RCV :
			    CE_LOGIN_SUCCESS_SND);
		} else {
			new_event = (rx ? CE_MISC_RX : CE_MISC_TX);
		}
	} else {
		new_event = (rx ? CE_LOGIN_FAIL_RCV : CE_LOGIN_FAIL_SND);
	}

	if (rx) {
		idm_conn_rx_pdu_event(ic, new_event, (uintptr_t)login_rsp_pdu);
	} else {
		idm_conn_tx_pdu_event(ic, new_event, (uintptr_t)login_rsp_pdu);
	}
}


void
idm_parse_logout_req(idm_conn_t *ic, idm_pdu_t *logout_req_pdu, boolean_t rx)
{
	iscsi_logout_hdr_t	*logout_req =
	    (iscsi_logout_hdr_t *)logout_req_pdu->isp_hdr;
	idm_conn_event_t	new_event;
	uint8_t			reason =
	    (logout_req->flags & ISCSI_FLAG_LOGOUT_REASON_MASK);

	/*
	 *	For a normal logout (close connection or close session) IDM
	 *	will terminate processing of all tasks completing the tasks
	 *	back to the client with a status indicating the connection
	 *	was logged out.  These tasks do not get completed.
	 *
	 *	For a "close connection for recovery logout) IDM suspends
	 *	processing of all tasks and completes them back to the client
	 *	with a status indicating connection was logged out for
	 *	recovery.  Both initiator and target hang onto these tasks.
	 *	When we add ERL2 support IDM will need to provide mechanisms
	 *	to change the task and buffer associations to a new connection.
	 *
	 *	This code doesn't address the possibility of MC/S.  We'll
	 *	need to decide how the separate connections get handled
	 *	in that case.  One simple option is to make the client
	 *	generate the events for the other connections.
	 */
	if (reason == ISCSI_LOGOUT_REASON_CLOSE_SESSION) {
		new_event =
		    (rx ? CE_LOGOUT_SESSION_RCV : CE_LOGOUT_SESSION_SND);
	} else if ((reason == ISCSI_LOGOUT_REASON_CLOSE_CONNECTION) ||
	    (reason == ISCSI_LOGOUT_REASON_RECOVERY)) {
		/* Check logout CID against this connection's CID */
		if (ntohs(logout_req->cid) == ic->ic_login_cid) {
			/* Logout is for this connection */
			new_event = (rx ? CE_LOGOUT_THIS_CONN_RCV :
			    CE_LOGOUT_THIS_CONN_SND);
		} else {
			/*
			 * Logout affects another connection.  This is not
			 * a relevant event for this connection so we'll
			 * just treat it as a normal PDU event.  Client
			 * will need to lookup the other connection and
			 * generate the event.
			 */
			new_event = (rx ? CE_MISC_RX : CE_MISC_TX);
		}
	} else {
		/* Invalid reason code */
		new_event = (rx ? CE_RX_PROTOCOL_ERROR : CE_TX_PROTOCOL_ERROR);
	}

	if (rx) {
		idm_conn_rx_pdu_event(ic, new_event, (uintptr_t)logout_req_pdu);
	} else {
		idm_conn_tx_pdu_event(ic, new_event, (uintptr_t)logout_req_pdu);
	}
}



void
idm_parse_logout_rsp(idm_conn_t *ic, idm_pdu_t *logout_rsp_pdu, boolean_t rx)
{
	idm_conn_event_t	new_event;
	iscsi_logout_rsp_hdr_t *logout_rsp =
	    (iscsi_logout_rsp_hdr_t *)logout_rsp_pdu->isp_hdr;

	if (logout_rsp->response == ISCSI_STATUS_CLASS_SUCCESS) {
		new_event = rx ? CE_LOGOUT_SUCCESS_RCV : CE_LOGOUT_SUCCESS_SND;
	} else {
		new_event = rx ? CE_LOGOUT_FAIL_RCV : CE_LOGOUT_FAIL_SND;
	}

	if (rx) {
		idm_conn_rx_pdu_event(ic, new_event, (uintptr_t)logout_rsp_pdu);
	} else {
		idm_conn_tx_pdu_event(ic, new_event, (uintptr_t)logout_rsp_pdu);
	}
}

/*
 * idm_svc_conn_create()
 * Transport-agnostic service connection creation, invoked from the transport
 * layer.
 */
idm_status_t
idm_svc_conn_create(idm_svc_t *is, idm_transport_type_t tt,
    idm_conn_t **ic_result)
{
	idm_conn_t	*ic;
	idm_status_t	rc;

	/*
	 * Skip some work if we can already tell we are going offline.
	 * Otherwise we will destroy this connection later as part of
	 * shutting down the svc.
	 */
	mutex_enter(&is->is_mutex);
	if (!is->is_online) {
		mutex_exit(&is->is_mutex);
		return (IDM_STATUS_FAIL);
	}
	mutex_exit(&is->is_mutex);

	ic = idm_conn_create_common(CONN_TYPE_TGT, tt,
	    &is->is_svc_req.sr_conn_ops);
	if (ic == NULL) {
		return (IDM_STATUS_FAIL);
	}
	ic->ic_svc_binding = is;

	/*
	 * Prepare connection state machine
	 */
	if ((rc = idm_conn_sm_init(ic)) != 0) {
		idm_conn_destroy_common(ic);
		return (rc);
	}


	*ic_result = ic;

	mutex_enter(&idm.idm_global_mutex);
	list_insert_tail(&idm.idm_tgt_conn_list, ic);
	idm.idm_tgt_conn_count++;
	mutex_exit(&idm.idm_global_mutex);

	return (IDM_STATUS_SUCCESS);
}

void
idm_svc_conn_destroy(idm_conn_t *ic)
{
	mutex_enter(&idm.idm_global_mutex);
	list_remove(&idm.idm_tgt_conn_list, ic);
	idm.idm_tgt_conn_count--;
	mutex_exit(&idm.idm_global_mutex);

	if (ic->ic_transport_private != NULL) {
		ic->ic_transport_ops->it_tgt_conn_destroy(ic);
	}
	idm_conn_destroy_common(ic);
}

/*
 * idm_conn_create_common()
 *
 * Allocate and initialize IDM connection context
 */
idm_conn_t *
idm_conn_create_common(idm_conn_type_t conn_type, idm_transport_type_t tt,
    idm_conn_ops_t *conn_ops)
{
	idm_conn_t		*ic;
	idm_transport_t		*it;
	idm_transport_type_t	type;

	for (type = 0; type < IDM_TRANSPORT_NUM_TYPES; type++) {
		it = &idm_transport_list[type];

		if ((it->it_ops != NULL) && (it->it_type == tt))
			break;
	}
	ASSERT(it->it_type == tt);
	if (it->it_type != tt)
		return (NULL);

	ic = kmem_zalloc(sizeof (idm_conn_t), KM_SLEEP);

	/* Initialize data */
	ic->ic_target_name[0] = '\0';
	ic->ic_initiator_name[0] = '\0';
	ic->ic_isid[0] = '\0';
	ic->ic_tsih[0] = '\0';
	ic->ic_conn_type = conn_type;
	ic->ic_conn_ops = *conn_ops;
	ic->ic_transport_ops = it->it_ops;
	ic->ic_transport_type = tt;
	ic->ic_transport_private = NULL; /* Set by transport service */
	ic->ic_internal_cid = idm_cid_alloc();
	if (ic->ic_internal_cid == 0) {
		kmem_free(ic, sizeof (idm_conn_t));
		return (NULL);
	}
	mutex_init(&ic->ic_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&ic->ic_cv, NULL, CV_DEFAULT, NULL);
	idm_refcnt_init(&ic->ic_refcnt, ic);

	return (ic);
}

void
idm_conn_destroy_common(idm_conn_t *ic)
{
	idm_conn_sm_fini(ic);
	idm_refcnt_destroy(&ic->ic_refcnt);
	cv_destroy(&ic->ic_cv);
	mutex_destroy(&ic->ic_mutex);
	idm_cid_free(ic->ic_internal_cid);

	kmem_free(ic, sizeof (idm_conn_t));
}

/*
 * Invoked from the SM as a result of client's invocation of
 * idm_ini_conn_connect()
 */
idm_status_t
idm_ini_conn_finish(idm_conn_t *ic)
{
	/* invoke transport-specific connection */
	return (ic->ic_transport_ops->it_ini_conn_connect(ic));
}

idm_status_t
idm_tgt_conn_finish(idm_conn_t *ic)
{
	idm_status_t rc;

	rc = idm_notify_client(ic, CN_CONNECT_ACCEPT, (uintptr_t)NULL);
	if (rc != IDM_STATUS_SUCCESS) {
		return (IDM_STATUS_REJECT);
	}

	/* Target client is ready to receive a login, start connection */
	return (ic->ic_transport_ops->it_tgt_conn_connect(ic));
}

idm_transport_t *
idm_transport_lookup(idm_conn_req_t *cr)
{
	idm_transport_type_t	type;
	idm_transport_t		*it;
	idm_transport_caps_t	caps;

	/*
	 * Make sure all available transports are setup.  We call this now
	 * instead of at initialization time in case IB has become available
	 * since we started (hotplug, etc).
	 */
	idm_transport_setup(cr->cr_li, cr->cr_boot_conn);

	/* Determine the transport for this connection */
	for (type = 0; type < IDM_TRANSPORT_NUM_TYPES; type++) {
		it = &idm_transport_list[type];

		if (it->it_ops == NULL) {
			/* transport is not registered */
			continue;
		}

		if (it->it_ops->it_conn_is_capable(cr, &caps)) {
			return (it);
		}
	}

	ASSERT(0);
	return (NULL); /* Make gcc happy */
}

void
idm_transport_setup(ldi_ident_t li, boolean_t boot_conn)
{
	idm_transport_type_t	type;
	idm_transport_t		*it;
	int			rc;

	for (type = 0; type < IDM_TRANSPORT_NUM_TYPES; type++) {
		it = &idm_transport_list[type];
		/*
		 * We may want to store the LDI handle in the idm_svc_t
		 * and then allow multiple calls to ldi_open_by_name.  This
		 * would enable the LDI code to track who has the device open
		 * which could be useful in the case where we have multiple
		 * services and perhaps also have initiator and target opening
		 * the transport simultaneously.  For now we stick with the
		 * plan.
		 */
		if (it->it_ops == NULL) {
			/* transport is not ready, try to initialize it */
			if (it->it_type == IDM_TRANSPORT_TYPE_SOCKETS) {
				idm_so_init(it);
			} else {
				if (boot_conn == B_TRUE) {
					/*
					 * iSCSI boot doesn't need iSER.
					 * Open iSER here may drive IO to
					 * a failed session and cause
					 * deadlock
					 */
					continue;
				}
				rc = ldi_open_by_name(it->it_device_path,
				    FREAD | FWRITE, kcred, &it->it_ldi_hdl, li);
				/*
				 * If the open is successful we will have
				 * filled in the LDI handle in the transport
				 * table and we expect that the transport
				 * registered itself.
				 */
				if (rc != 0) {
					it->it_ldi_hdl = NULL;
				}
			}
		}
	}
}

void
idm_transport_teardown()
{
	idm_transport_type_t	type;
	idm_transport_t		*it;

	ASSERT(mutex_owned(&idm.idm_global_mutex));

	/* Caller holds the IDM global mutex */
	for (type = 0; type < IDM_TRANSPORT_NUM_TYPES; type++) {
		it = &idm_transport_list[type];
		/* If we have an open LDI handle on this driver, close it */
		if (it->it_ldi_hdl != NULL) {
			(void) ldi_close(it->it_ldi_hdl, FNDELAY, kcred);
			it->it_ldi_hdl = NULL;
		}
	}
}

/*
 * ID pool code.  We use this to generate unique structure identifiers without
 * searching the existing structures.  This avoids the need to lock entire
 * sets of structures at inopportune times.  Adapted from the CIFS server code.
 *
 *    A pool of IDs is a pool of 16 bit numbers. It is implemented as a bitmap.
 *    A bit set to '1' indicates that that particular value has been allocated.
 *    The allocation process is done shifting a bit through the whole bitmap.
 *    The current position of that index bit is kept in the idm_idpool_t
 *    structure and represented by a byte index (0 to buffer size minus 1) and
 *    a bit index (0 to 7).
 *
 *    The pools start with a size of 8 bytes or 64 IDs. Each time the pool runs
 *    out of IDs its current size is doubled until it reaches its maximum size
 *    (8192 bytes or 65536 IDs). The IDs 0 and 65535 are never given out which
 *    means that a pool can have a maximum number of 65534 IDs available.
 */

static int
idm_idpool_increment(
    idm_idpool_t	*pool)
{
	uint8_t		*new_pool;
	uint32_t	new_size;

	ASSERT(pool->id_magic == IDM_IDPOOL_MAGIC);

	new_size = pool->id_size * 2;
	if (new_size <= IDM_IDPOOL_MAX_SIZE) {
		new_pool = kmem_alloc(new_size / 8, KM_NOSLEEP);
		if (new_pool) {
			bzero(new_pool, new_size / 8);
			bcopy(pool->id_pool, new_pool, pool->id_size / 8);
			kmem_free(pool->id_pool, pool->id_size / 8);
			pool->id_pool = new_pool;
			pool->id_free_counter += new_size - pool->id_size;
			pool->id_max_free_counter += new_size - pool->id_size;
			pool->id_size = new_size;
			pool->id_idx_msk = (new_size / 8) - 1;
			if (new_size >= IDM_IDPOOL_MAX_SIZE) {
				/* id -1 made unavailable */
				pool->id_pool[pool->id_idx_msk] = 0x80;
				pool->id_free_counter--;
				pool->id_max_free_counter--;
			}
			return (0);
		}
	}
	return (-1);
}

/*
 * idm_idpool_constructor
 *
 * This function initializes the pool structure provided.
 */

int
idm_idpool_create(idm_idpool_t *pool)
{

	ASSERT(pool->id_magic != IDM_IDPOOL_MAGIC);

	pool->id_size = IDM_IDPOOL_MIN_SIZE;
	pool->id_idx_msk = (IDM_IDPOOL_MIN_SIZE / 8) - 1;
	pool->id_free_counter = IDM_IDPOOL_MIN_SIZE - 1;
	pool->id_max_free_counter = IDM_IDPOOL_MIN_SIZE - 1;
	pool->id_bit = 0x02;
	pool->id_bit_idx = 1;
	pool->id_idx = 0;
	pool->id_pool = (uint8_t *)kmem_alloc((IDM_IDPOOL_MIN_SIZE / 8),
	    KM_SLEEP);
	bzero(pool->id_pool, (IDM_IDPOOL_MIN_SIZE / 8));
	/* -1 id made unavailable */
	pool->id_pool[0] = 0x01;		/* id 0 made unavailable */
	mutex_init(&pool->id_mutex, NULL, MUTEX_DEFAULT, NULL);
	pool->id_magic = IDM_IDPOOL_MAGIC;
	return (0);
}

/*
 * idm_idpool_destructor
 *
 * This function tears down and frees the resources associated with the
 * pool provided.
 */

void
idm_idpool_destroy(idm_idpool_t *pool)
{
	ASSERT(pool->id_magic == IDM_IDPOOL_MAGIC);
	ASSERT(pool->id_free_counter == pool->id_max_free_counter);
	pool->id_magic = (uint32_t)~IDM_IDPOOL_MAGIC;
	mutex_destroy(&pool->id_mutex);
	kmem_free(pool->id_pool, (size_t)(pool->id_size / 8));
}

/*
 * idm_idpool_alloc
 *
 * This function allocates an ID from the pool provided.
 */
int
idm_idpool_alloc(idm_idpool_t *pool, uint16_t *id)
{
	uint32_t	i;
	uint8_t		bit;
	uint8_t		bit_idx;
	uint8_t		byte;

	ASSERT(pool->id_magic == IDM_IDPOOL_MAGIC);

	mutex_enter(&pool->id_mutex);
	if ((pool->id_free_counter == 0) && idm_idpool_increment(pool)) {
		mutex_exit(&pool->id_mutex);
		return (-1);
	}

	i = pool->id_size;
	while (i) {
		bit = pool->id_bit;
		bit_idx = pool->id_bit_idx;
		byte = pool->id_pool[pool->id_idx];
		while (bit) {
			if (byte & bit) {
				bit = bit << 1;
				bit_idx++;
				continue;
			}
			pool->id_pool[pool->id_idx] |= bit;
			*id = (uint16_t)(pool->id_idx * 8 + (uint32_t)bit_idx);
			pool->id_free_counter--;
			pool->id_bit = bit;
			pool->id_bit_idx = bit_idx;
			mutex_exit(&pool->id_mutex);
			return (0);
		}
		pool->id_bit = 1;
		pool->id_bit_idx = 0;
		pool->id_idx++;
		pool->id_idx &= pool->id_idx_msk;
		--i;
	}
	/*
	 * This section of code shouldn't be reached. If there are IDs
	 * available and none could be found there's a problem.
	 */
	ASSERT(0);
	mutex_exit(&pool->id_mutex);
	return (-1);
}

/*
 * idm_idpool_free
 *
 * This function frees the ID provided.
 */
void
idm_idpool_free(idm_idpool_t *pool, uint16_t id)
{
	ASSERT(pool->id_magic == IDM_IDPOOL_MAGIC);
	ASSERT(id != 0);
	ASSERT(id != 0xFFFF);

	mutex_enter(&pool->id_mutex);
	if (pool->id_pool[id >> 3] & (1 << (id & 7))) {
		pool->id_pool[id >> 3] &= ~(1 << (id & 7));
		pool->id_free_counter++;
		ASSERT(pool->id_free_counter <= pool->id_max_free_counter);
		mutex_exit(&pool->id_mutex);
		return;
	}
	/* Freeing a free ID. */
	ASSERT(0);
	mutex_exit(&pool->id_mutex);
}

uint32_t
idm_cid_alloc(void)
{
	/*
	 * ID pool works with 16-bit identifiers right now.  That should
	 * be plenty since we will probably never have more than 2^16
	 * connections simultaneously.
	 */
	uint16_t cid16;

	if (idm_idpool_alloc(&idm.idm_conn_id_pool, &cid16) == -1) {
		return (0); /* Fail */
	}

	return ((uint32_t)cid16);
}

void
idm_cid_free(uint32_t cid)
{
	idm_idpool_free(&idm.idm_conn_id_pool, (uint16_t)cid);
}


/*
 * Code for generating the header and data digests
 *
 * This is the CRC-32C table
 * Generated with:
 * width = 32 bits
 * poly = 0x1EDC6F41
 * reflect input bytes = true
 * reflect output bytes = true
 */

uint32_t idm_crc32c_table[256] =
{
	0x00000000, 0xF26B8303, 0xE13B70F7, 0x1350F3F4,
	0xC79A971F, 0x35F1141C, 0x26A1E7E8, 0xD4CA64EB,
	0x8AD958CF, 0x78B2DBCC, 0x6BE22838, 0x9989AB3B,
	0x4D43CFD0, 0xBF284CD3, 0xAC78BF27, 0x5E133C24,
	0x105EC76F, 0xE235446C, 0xF165B798, 0x030E349B,
	0xD7C45070, 0x25AFD373, 0x36FF2087, 0xC494A384,
	0x9A879FA0, 0x68EC1CA3, 0x7BBCEF57, 0x89D76C54,
	0x5D1D08BF, 0xAF768BBC, 0xBC267848, 0x4E4DFB4B,
	0x20BD8EDE, 0xD2D60DDD, 0xC186FE29, 0x33ED7D2A,
	0xE72719C1, 0x154C9AC2, 0x061C6936, 0xF477EA35,
	0xAA64D611, 0x580F5512, 0x4B5FA6E6, 0xB93425E5,
	0x6DFE410E, 0x9F95C20D, 0x8CC531F9, 0x7EAEB2FA,
	0x30E349B1, 0xC288CAB2, 0xD1D83946, 0x23B3BA45,
	0xF779DEAE, 0x05125DAD, 0x1642AE59, 0xE4292D5A,
	0xBA3A117E, 0x4851927D, 0x5B016189, 0xA96AE28A,
	0x7DA08661, 0x8FCB0562, 0x9C9BF696, 0x6EF07595,
	0x417B1DBC, 0xB3109EBF, 0xA0406D4B, 0x522BEE48,
	0x86E18AA3, 0x748A09A0, 0x67DAFA54, 0x95B17957,
	0xCBA24573, 0x39C9C670, 0x2A993584, 0xD8F2B687,
	0x0C38D26C, 0xFE53516F, 0xED03A29B, 0x1F682198,
	0x5125DAD3, 0xA34E59D0, 0xB01EAA24, 0x42752927,
	0x96BF4DCC, 0x64D4CECF, 0x77843D3B, 0x85EFBE38,
	0xDBFC821C, 0x2997011F, 0x3AC7F2EB, 0xC8AC71E8,
	0x1C661503, 0xEE0D9600, 0xFD5D65F4, 0x0F36E6F7,
	0x61C69362, 0x93AD1061, 0x80FDE395, 0x72966096,
	0xA65C047D, 0x5437877E, 0x4767748A, 0xB50CF789,
	0xEB1FCBAD, 0x197448AE, 0x0A24BB5A, 0xF84F3859,
	0x2C855CB2, 0xDEEEDFB1, 0xCDBE2C45, 0x3FD5AF46,
	0x7198540D, 0x83F3D70E, 0x90A324FA, 0x62C8A7F9,
	0xB602C312, 0x44694011, 0x5739B3E5, 0xA55230E6,
	0xFB410CC2, 0x092A8FC1, 0x1A7A7C35, 0xE811FF36,
	0x3CDB9BDD, 0xCEB018DE, 0xDDE0EB2A, 0x2F8B6829,
	0x82F63B78, 0x709DB87B, 0x63CD4B8F, 0x91A6C88C,
	0x456CAC67, 0xB7072F64, 0xA457DC90, 0x563C5F93,
	0x082F63B7, 0xFA44E0B4, 0xE9141340, 0x1B7F9043,
	0xCFB5F4A8, 0x3DDE77AB, 0x2E8E845F, 0xDCE5075C,
	0x92A8FC17, 0x60C37F14, 0x73938CE0, 0x81F80FE3,
	0x55326B08, 0xA759E80B, 0xB4091BFF, 0x466298FC,
	0x1871A4D8, 0xEA1A27DB, 0xF94AD42F, 0x0B21572C,
	0xDFEB33C7, 0x2D80B0C4, 0x3ED04330, 0xCCBBC033,
	0xA24BB5A6, 0x502036A5, 0x4370C551, 0xB11B4652,
	0x65D122B9, 0x97BAA1BA, 0x84EA524E, 0x7681D14D,
	0x2892ED69, 0xDAF96E6A, 0xC9A99D9E, 0x3BC21E9D,
	0xEF087A76, 0x1D63F975, 0x0E330A81, 0xFC588982,
	0xB21572C9, 0x407EF1CA, 0x532E023E, 0xA145813D,
	0x758FE5D6, 0x87E466D5, 0x94B49521, 0x66DF1622,
	0x38CC2A06, 0xCAA7A905, 0xD9F75AF1, 0x2B9CD9F2,
	0xFF56BD19, 0x0D3D3E1A, 0x1E6DCDEE, 0xEC064EED,
	0xC38D26C4, 0x31E6A5C7, 0x22B65633, 0xD0DDD530,
	0x0417B1DB, 0xF67C32D8, 0xE52CC12C, 0x1747422F,
	0x49547E0B, 0xBB3FFD08, 0xA86F0EFC, 0x5A048DFF,
	0x8ECEE914, 0x7CA56A17, 0x6FF599E3, 0x9D9E1AE0,
	0xD3D3E1AB, 0x21B862A8, 0x32E8915C, 0xC083125F,
	0x144976B4, 0xE622F5B7, 0xF5720643, 0x07198540,
	0x590AB964, 0xAB613A67, 0xB831C993, 0x4A5A4A90,
	0x9E902E7B, 0x6CFBAD78, 0x7FAB5E8C, 0x8DC0DD8F,
	0xE330A81A, 0x115B2B19, 0x020BD8ED, 0xF0605BEE,
	0x24AA3F05, 0xD6C1BC06, 0xC5914FF2, 0x37FACCF1,
	0x69E9F0D5, 0x9B8273D6, 0x88D28022, 0x7AB90321,
	0xAE7367CA, 0x5C18E4C9, 0x4F48173D, 0xBD23943E,
	0xF36E6F75, 0x0105EC76, 0x12551F82, 0xE03E9C81,
	0x34F4F86A, 0xC69F7B69, 0xD5CF889D, 0x27A40B9E,
	0x79B737BA, 0x8BDCB4B9, 0x988C474D, 0x6AE7C44E,
	0xBE2DA0A5, 0x4C4623A6, 0x5F16D052, 0xAD7D5351
};

/*
 * iscsi_crc32c - Steps through buffer one byte at at time, calculates
 * reflected crc using table.
 */
uint32_t
idm_crc32c(void *address, unsigned long length)
{
	uint8_t *buffer = address;
	uint32_t crc = 0xffffffff, result;
#ifdef _BIG_ENDIAN
	uint8_t byte0, byte1, byte2, byte3;
#endif

	ASSERT(address != NULL);

	if (iscsi_crc32_hd == -1) {
		if (hd_crc32_avail((uint32_t *)idm_crc32c_table) == B_TRUE) {
			iscsi_crc32_hd = 0;
		} else {
			iscsi_crc32_hd = 1;
		}
	}
	if (iscsi_crc32_hd == 0)
		return (HW_CRC32(buffer, length, crc));

	while (length--) {
		crc = idm_crc32c_table[(crc ^ *buffer++) & 0xFFL] ^
		    (crc >> 8);
	}
	result = crc ^ 0xffffffff;

#ifdef	_BIG_ENDIAN
	byte0 = (uint8_t)(result & 0xFF);
	byte1 = (uint8_t)((result >> 8) & 0xFF);
	byte2 = (uint8_t)((result >> 16) & 0xFF);
	byte3 = (uint8_t)((result >> 24) & 0xFF);
	result = ((byte0 << 24) | (byte1 << 16) | (byte2 << 8) | byte3);
#endif	/* _BIG_ENDIAN */

	return (result);
}


/*
 * idm_crc32c_continued - Continues stepping through buffer one
 * byte at at time, calculates reflected crc using table.
 */
uint32_t
idm_crc32c_continued(void *address, unsigned long length, uint32_t crc)
{
	uint8_t *buffer = address;
	uint32_t result;
#ifdef	_BIG_ENDIAN
	uint8_t byte0, byte1, byte2, byte3;
#endif

	ASSERT(address != NULL);

	if (iscsi_crc32_hd == -1) {
		if (hd_crc32_avail((uint32_t *)idm_crc32c_table) == B_TRUE) {
			iscsi_crc32_hd = 0;
		} else {
			iscsi_crc32_hd = 1;
		}
	}
	if (iscsi_crc32_hd == 0)
		return (HW_CRC32_CONT(buffer, length, crc));


#ifdef	_BIG_ENDIAN
	byte0 = (uint8_t)((crc >> 24) & 0xFF);
	byte1 = (uint8_t)((crc >> 16) & 0xFF);
	byte2 = (uint8_t)((crc >> 8) & 0xFF);
	byte3 = (uint8_t)(crc & 0xFF);
	crc = ((byte3 << 24) | (byte2 << 16) | (byte1 << 8) | byte0);
#endif

	crc = crc ^ 0xffffffff;
	while (length--) {
		crc = idm_crc32c_table[(crc ^ *buffer++) & 0xFFL] ^
		    (crc >> 8);
	}
	result = crc ^ 0xffffffff;

#ifdef	_BIG_ENDIAN
	byte0 = (uint8_t)(result & 0xFF);
	byte1 = (uint8_t)((result >> 8) & 0xFF);
	byte2 = (uint8_t)((result >> 16) & 0xFF);
	byte3 = (uint8_t)((result >> 24) & 0xFF);
	result = ((byte0 << 24) | (byte1 << 16) | (byte2 << 8) | byte3);
#endif
	return (result);
}

/* ARGSUSED */
int
idm_task_constructor(void *hdl, void *arg, int flags)
{
	idm_task_t *idt = (idm_task_t *)hdl;
	uint32_t next_task;

	mutex_init(&idt->idt_mutex, NULL, MUTEX_DEFAULT, NULL);

	/* Find the next free task ID */
	rw_enter(&idm.idm_taskid_table_lock, RW_WRITER);
	next_task = idm.idm_taskid_next;
	while (idm.idm_taskid_table[next_task]) {
		next_task++;
		if (next_task == idm.idm_taskid_max)
			next_task = 0;
		if (next_task == idm.idm_taskid_next) {
			rw_exit(&idm.idm_taskid_table_lock);
			return (-1);
		}
	}

	idm.idm_taskid_table[next_task] = idt;
	idm.idm_taskid_next = (next_task + 1) % idm.idm_taskid_max;
	rw_exit(&idm.idm_taskid_table_lock);

	idt->idt_tt = next_task;

	list_create(&idt->idt_inbufv, sizeof (idm_buf_t),
	    offsetof(idm_buf_t, idb_buflink));
	list_create(&idt->idt_outbufv, sizeof (idm_buf_t),
	    offsetof(idm_buf_t, idb_buflink));
	idm_refcnt_init(&idt->idt_refcnt, idt);

	/*
	 * Set the transport header pointer explicitly.  This removes the
	 * need for per-transport header allocation, which simplifies cache
	 * init considerably.  If at a later date we have an additional IDM
	 * transport that requires a different size, we'll revisit this.
	 */
	idt->idt_transport_hdr = (void *)(idt + 1); /* pointer arithmetic */
	idt->idt_flags = 0;
	return (0);
}

/* ARGSUSED */
void
idm_task_destructor(void *hdl, void *arg)
{
	idm_task_t *idt = (idm_task_t *)hdl;

	/* Remove the task from the ID table */
	rw_enter(&idm.idm_taskid_table_lock, RW_WRITER);
	idm.idm_taskid_table[idt->idt_tt] = NULL;
	rw_exit(&idm.idm_taskid_table_lock);

	/* free the inbuf and outbuf */
	idm_refcnt_destroy(&idt->idt_refcnt);
	list_destroy(&idt->idt_inbufv);
	list_destroy(&idt->idt_outbufv);

	/*
	 * The final call to idm_task_rele may happen with the task
	 * mutex held which may invoke this destructor immediately.
	 * Stall here until the task mutex owner lets go.
	 */
	mutex_enter(&idt->idt_mutex);
	mutex_destroy(&idt->idt_mutex);
}

/*
 * idm_listbuf_insert searches from the back of the list looking for the
 * insertion point.
 */
void
idm_listbuf_insert(list_t *lst, idm_buf_t *buf)
{
	idm_buf_t	*idb;

	/* iterate through the list to find the insertion point */
	for (idb = list_tail(lst); idb != NULL; idb = list_prev(lst, idb)) {

		if (idb->idb_bufoffset < buf->idb_bufoffset) {

			list_insert_after(lst, idb, buf);
			return;
		}
	}

	/* add the buf to the head of the list */
	list_insert_head(lst, buf);

}

/*ARGSUSED*/
void
idm_wd_thread(void *arg)
{
	idm_conn_t	*ic;
	clock_t		wake_time = SEC_TO_TICK(IDM_WD_INTERVAL);
	clock_t		idle_time;

	/* Record the thread id for thread_join() */
	idm.idm_wd_thread_did = curthread->t_did;
	mutex_enter(&idm.idm_global_mutex);
	idm.idm_wd_thread_running = B_TRUE;
	cv_signal(&idm.idm_wd_cv);

	while (idm.idm_wd_thread_running) {
		for (ic = list_head(&idm.idm_tgt_conn_list);
		    ic != NULL;
		    ic = list_next(&idm.idm_tgt_conn_list, ic)) {
			idle_time = ddi_get_lbolt() - ic->ic_timestamp;

			/*
			 * If this connection is in FFP then grab a hold
			 * and check the various timeout thresholds.  Otherwise
			 * the connection is closing and we should just
			 * move on to the next one.
			 */
			mutex_enter(&ic->ic_state_mutex);
			if (ic->ic_ffp) {
				idm_conn_hold(ic);
			} else {
				mutex_exit(&ic->ic_state_mutex);
				continue;
			}

			/*
			 * If there hasn't been any activity on this
			 * connection for the keepalive timeout period
			 * and if the client has provided a keepalive
			 * callback then call the keepalive callback.
			 * This allows the client to take action to keep
			 * the link alive (like send a nop PDU).
			 */
			if ((TICK_TO_SEC(idle_time) >=
			    IDM_TRANSPORT_KEEPALIVE_IDLE_TIMEOUT) &&
			    !ic->ic_keepalive) {
				ic->ic_keepalive = B_TRUE;
				if (ic->ic_conn_ops.icb_keepalive) {
					mutex_exit(&ic->ic_state_mutex);
					mutex_exit(&idm.idm_global_mutex);
					(*ic->ic_conn_ops.icb_keepalive)(ic);
					mutex_enter(&idm.idm_global_mutex);
					mutex_enter(&ic->ic_state_mutex);
				}
			} else if ((TICK_TO_SEC(idle_time) <
			    IDM_TRANSPORT_KEEPALIVE_IDLE_TIMEOUT)) {
				/* Reset keepalive */
				ic->ic_keepalive = B_FALSE;
			}

			/*
			 * If there hasn't been any activity on this
			 * connection for the failure timeout period then
			 * drop the connection.  We expect the initiator
			 * to keep the connection alive if it wants the
			 * connection to stay open.
			 *
			 * If it turns out to be desireable to take a
			 * more active role in maintaining the connect
			 * we could add a client callback to send
			 * a "keepalive" kind of message (no doubt a nop)
			 * and fire that on a shorter timer.
			 */
			if (TICK_TO_SEC(idle_time) >
			    IDM_TRANSPORT_FAIL_IDLE_TIMEOUT) {
				mutex_exit(&ic->ic_state_mutex);
				mutex_exit(&idm.idm_global_mutex);
				IDM_SM_LOG(CE_WARN, "idm_wd_thread: "
				    "conn %p idle for %d seconds, "
				    "sending CE_TRANSPORT_FAIL",
				    (void *)ic, (int)idle_time);
				idm_conn_event(ic, CE_TRANSPORT_FAIL,
				    (uintptr_t)NULL);
				mutex_enter(&idm.idm_global_mutex);
				mutex_enter(&ic->ic_state_mutex);
			}

			idm_conn_rele(ic);

			mutex_exit(&ic->ic_state_mutex);
		}

		(void) cv_reltimedwait(&idm.idm_wd_cv, &idm.idm_global_mutex,
		    wake_time, TR_CLOCK_TICK);
	}
	mutex_exit(&idm.idm_global_mutex);

	thread_exit();
}
