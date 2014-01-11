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
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/cpuvar.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/scsi/generic/persist.h>

#include <sys/socket.h>
#include <sys/strsubr.h>
#include <sys/sysmacros.h>
#include <sys/note.h>
#include <sys/sdt.h>

#include <sys/stmf.h>
#include <sys/stmf_ioctl.h>
#include <sys/portif.h>
#include <sys/idm/idm.h>
#include <sys/idm/idm_text.h>

#define	ISCSIT_LOGIN_SM_STRINGS
#include "iscsit.h"
#include "iscsit_auth.h"

typedef struct {
	list_node_t		le_ctx_node;
	iscsit_login_event_t	le_ctx_event;
	idm_pdu_t		*le_pdu;
} login_event_ctx_t;

#ifndef TRUE
#define	TRUE B_TRUE
#endif

#ifndef FALSE
#define	FALSE B_FALSE
#endif

#define	DEFAULT_RADIUS_PORT	1812

static void
login_sm_complete(void *ict_void);

static void
login_sm_event_dispatch(iscsit_conn_login_t *lsm, iscsit_conn_t *ict,
    login_event_ctx_t *ctx);

static void
login_sm_init(iscsit_conn_t *ict, login_event_ctx_t *ctx);

static void
login_sm_waiting(iscsit_conn_t *ict, login_event_ctx_t *ctx);

static void
login_sm_processing(iscsit_conn_t *ict, login_event_ctx_t *ctx);

static void
login_sm_responding(iscsit_conn_t *ict, login_event_ctx_t *ctx);

static void
login_sm_responded(iscsit_conn_t *ict, login_event_ctx_t *ctx);

static void
login_sm_ffp(iscsit_conn_t *ict, login_event_ctx_t *ctx);

static void
login_sm_done(iscsit_conn_t *ict, login_event_ctx_t *ctx);

static void
login_sm_error(iscsit_conn_t *ict, login_event_ctx_t *ctx);

static void
login_sm_new_state(iscsit_conn_t *ict, login_event_ctx_t *ctx,
    iscsit_login_state_t new_state);

static void
login_sm_send_ack(iscsit_conn_t *ict, idm_pdu_t *pdu);

static idm_status_t
login_sm_validate_ack(iscsit_conn_t *ict, idm_pdu_t *pdu);

static boolean_t
login_sm_is_last_response(idm_pdu_t *pdu);

static void
login_sm_handle_initial_login(iscsit_conn_t *ict, idm_pdu_t *pdu);

static void
login_sm_send_next_response(iscsit_conn_t *ict, idm_pdu_t *pdu);

static void
login_sm_process_request(iscsit_conn_t *ict);

static idm_status_t
login_sm_req_pdu_check(iscsit_conn_t *ict, idm_pdu_t *pdu);

static idm_status_t
login_sm_process_nvlist(iscsit_conn_t *ict);

static idm_status_t
login_sm_check_security(iscsit_conn_t *ict);

static idm_pdu_t *
login_sm_build_login_response(iscsit_conn_t *ict);

static void
login_sm_ffp_actions(iscsit_conn_t *ict);

static idm_status_t
login_sm_validate_initial_parameters(iscsit_conn_t *ict);

static idm_status_t
login_sm_session_bind(iscsit_conn_t *ict);

static idm_status_t
login_sm_set_auth(iscsit_conn_t *ict);

static idm_status_t
login_sm_session_register(iscsit_conn_t *ict);

static kv_status_t
iscsit_handle_key(iscsit_conn_t *ict, nvpair_t *nvp, char *nvp_name);

static kv_status_t
iscsit_handle_common_key(iscsit_conn_t *ict, nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx);

static kv_status_t
iscsit_handle_security_key(iscsit_conn_t *ict, nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx);

static kv_status_t
iscsit_reply_security_key(iscsit_conn_t *ict);

static kv_status_t
iscsit_handle_operational_key(iscsit_conn_t *ict, nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx);

static kv_status_t
iscsit_reply_numerical(iscsit_conn_t *ict,
    const char *nvp_name, const uint64_t value);

static kv_status_t
iscsit_reply_string(iscsit_conn_t *ict,
    const char *nvp_name, const char *text);

static kv_status_t
iscsit_handle_digest(iscsit_conn_t *ict, nvpair_t *choices,
    const idm_kv_xlate_t *ikvx);

static kv_status_t
iscsit_handle_boolean(iscsit_conn_t *ict, nvpair_t *nvp, boolean_t value,
    const idm_kv_xlate_t *ikvx, boolean_t iscsit_value);

static kv_status_t
iscsit_handle_numerical(iscsit_conn_t *ict, nvpair_t *nvp, uint64_t value,
    const idm_kv_xlate_t *ikvx,
    uint64_t iscsi_min_value, uint64_t iscsi_max_value,
    uint64_t iscsit_max_value);

static void
iscsit_process_negotiated_values(iscsit_conn_t *ict);

static void
login_resp_complete_cb(idm_pdu_t *pdu, idm_status_t status);

static idm_status_t
iscsit_add_declarative_keys(iscsit_conn_t *ict);

uint64_t max_dataseglen_target = ISCSIT_MAX_RECV_DATA_SEGMENT_LENGTH;

/*
 * global mutex defined in iscsit.c to enforce
 * login_sm_session_bind as a critical section
 */
extern kmutex_t login_sm_session_mutex;

idm_status_t
iscsit_login_sm_init(iscsit_conn_t *ict)
{
	iscsit_conn_login_t *lsm = &ict->ict_login_sm;

	bzero(lsm, sizeof (iscsit_conn_login_t));

	(void) nvlist_alloc(&lsm->icl_negotiated_values, NV_UNIQUE_NAME,
	    KM_SLEEP);

	/*
	 * Hold connection until the login state machine completes
	 */
	iscsit_conn_hold(ict);

	/*
	 * Pre-allocating a login response PDU means we will always be
	 * able to respond to a login request -- even if we can't allocate
	 * a data buffer to hold the text responses we can at least send
	 * a login failure.
	 */
	lsm->icl_login_resp_tmpl = kmem_zalloc(sizeof (iscsi_login_rsp_hdr_t),
	    KM_SLEEP);

	idm_sm_audit_init(&lsm->icl_state_audit);
	mutex_init(&lsm->icl_mutex, NULL, MUTEX_DEFAULT, NULL);
	list_create(&lsm->icl_login_events, sizeof (login_event_ctx_t),
	    offsetof(login_event_ctx_t, le_ctx_node));
	list_create(&lsm->icl_pdu_list, sizeof (idm_pdu_t),
	    offsetof(idm_pdu_t, isp_client_lnd));

	lsm->icl_login_state = ILS_LOGIN_INIT;
	lsm->icl_login_last_state = ILS_LOGIN_INIT;

	/*
	 * Initialize operational parameters to default values.  Anything
	 * we don't specifically negotiate stays at the default.
	 */
	ict->ict_op.op_discovery_session = B_FALSE;
	ict->ict_op.op_initial_r2t = ISCSI_DEFAULT_INITIALR2T;
	ict->ict_op.op_immed_data = ISCSI_DEFAULT_IMMEDIATE_DATA;
	ict->ict_op.op_data_pdu_in_order = ISCSI_DEFAULT_DATA_PDU_IN_ORDER;
	ict->ict_op.op_data_sequence_in_order =
	    ISCSI_DEFAULT_DATA_SEQUENCE_IN_ORDER;
	ict->ict_op.op_max_connections = ISCSI_DEFAULT_MAX_CONNECTIONS;
	ict->ict_op.op_max_recv_data_segment_length =
	    ISCSI_DEFAULT_MAX_RECV_SEG_LEN;
	ict->ict_op.op_max_burst_length = ISCSI_DEFAULT_MAX_BURST_LENGTH;
	ict->ict_op.op_first_burst_length = ISCSI_DEFAULT_FIRST_BURST_LENGTH;
	ict->ict_op.op_default_time_2_wait = ISCSI_DEFAULT_TIME_TO_WAIT;
	ict->ict_op.op_default_time_2_retain = ISCSI_DEFAULT_TIME_TO_RETAIN;
	ict->ict_op.op_max_outstanding_r2t = ISCSI_DEFAULT_MAX_OUT_R2T;
	ict->ict_op.op_error_recovery_level =
	    ISCSI_DEFAULT_ERROR_RECOVERY_LEVEL;

	return (IDM_STATUS_SUCCESS);
}

static void
login_resp_complete_cb(idm_pdu_t *pdu, idm_status_t status)
{
	iscsit_conn_t *ict = pdu->isp_private;

	/*
	 * Check that this is a login pdu
	 */
	ASSERT((pdu->isp_flags & IDM_PDU_LOGIN_TX) != 0);
	idm_pdu_free(pdu);

	if ((status != IDM_STATUS_SUCCESS) ||
	    (ict->ict_login_sm.icl_login_resp_err_class != 0)) {
		/*
		 * Transport or login error occurred.
		 */
		iscsit_login_sm_event(ict, ILE_LOGIN_ERROR, NULL);
	}
	iscsit_conn_rele(ict);
}

void
iscsit_login_sm_fini(iscsit_conn_t *ict)
{
	iscsit_conn_login_t *lsm = &ict->ict_login_sm;

	mutex_enter(&lsm->icl_mutex);
	list_destroy(&lsm->icl_pdu_list);
	list_destroy(&lsm->icl_login_events);

	kmem_free(lsm->icl_login_resp_tmpl, sizeof (iscsi_login_rsp_hdr_t));

	/* clean up the login response idm text buffer */
	if (lsm->icl_login_resp_itb != NULL) {
		idm_itextbuf_free(lsm->icl_login_resp_itb);
		lsm->icl_login_resp_itb = NULL;
	}

	nvlist_free(lsm->icl_negotiated_values);
	mutex_destroy(&lsm->icl_mutex);
}

void
iscsit_login_sm_event(iscsit_conn_t *ict, iscsit_login_event_t event,
    idm_pdu_t *pdu)
{
	/*
	 * This is a bit ugly but if we're already in ILS_LOGIN_ERROR
	 * or ILS_LOGIN_DONE then just drop any additional events.  They
	 * won't change the state and it's possible we've already called
	 * iscsit_login_sm_fini in which case the mutex is destroyed.
	 */
	if ((ict->ict_login_sm.icl_login_state == ILS_LOGIN_ERROR) ||
	    (ict->ict_login_sm.icl_login_state == ILS_LOGIN_DONE))
		return;

	mutex_enter(&ict->ict_login_sm.icl_mutex);
	iscsit_login_sm_event_locked(ict, event, pdu);
	mutex_exit(&ict->ict_login_sm.icl_mutex);
}
void
iscsit_login_sm_event_locked(iscsit_conn_t *ict, iscsit_login_event_t event,
    idm_pdu_t *pdu)
{
	iscsit_conn_login_t *lsm = &ict->ict_login_sm;
	login_event_ctx_t *ctx;

	ASSERT(mutex_owned(&lsm->icl_mutex));
	ctx = kmem_zalloc(sizeof (*ctx), KM_SLEEP);

	ctx->le_ctx_event = event;
	ctx->le_pdu = pdu;

	list_insert_tail(&lsm->icl_login_events, ctx);

	/*
	 * Use the icl_busy flag to keep the state machine single threaded.
	 * This also serves as recursion avoidance since this flag will
	 * always be set if we call login_sm_event from within the
	 * state machine code.
	 */
	if (!lsm->icl_busy) {
		lsm->icl_busy = B_TRUE;
		while (!list_is_empty(&lsm->icl_login_events)) {
			ctx = list_head(&lsm->icl_login_events);
			list_remove(&lsm->icl_login_events, ctx);
			idm_sm_audit_event(&lsm->icl_state_audit,
			    SAS_ISCSIT_LOGIN, (int)lsm->icl_login_state,
			    (int)ctx->le_ctx_event, (uintptr_t)pdu);

			/*
			 * If the lsm is in a terminal state, just drain
			 * any remaining events.
			 */
			if ((lsm->icl_login_state == ILS_LOGIN_ERROR) ||
			    (lsm->icl_login_state == ILS_LOGIN_DONE)) {
				kmem_free(ctx, sizeof (*ctx));
				continue;
			}
			mutex_exit(&lsm->icl_mutex);
			login_sm_event_dispatch(lsm, ict, ctx);
			mutex_enter(&lsm->icl_mutex);
		}
		lsm->icl_busy = B_FALSE;

		/*
		 * When the state machine reaches ILS_LOGIN_DONE or
		 * ILS_LOGIN_ERROR state the login process has completed
		 * and it's time to cleanup.  The state machine code will
		 * mark itself "complete" when this happens.
		 *
		 * To protect against spurious events (which shouldn't
		 * happen) set icl_busy again.
		 */
		if (lsm->icl_login_complete) {
			lsm->icl_busy = B_TRUE;
			if (taskq_dispatch(iscsit_global.global_dispatch_taskq,
			    login_sm_complete, ict, DDI_SLEEP) == NULL) {
				cmn_err(CE_WARN, "iscsit_login_sm_event_locked:"
				    " Failed to dispatch task");
			}
		}
	}
}

static void
login_sm_complete(void *ict_void)
{
	iscsit_conn_t *ict = ict_void;

	/*
	 * State machine has run to completion, resources
	 * will be cleaned up when connection is destroyed.
	 */
	iscsit_conn_rele(ict);
}

static void
login_sm_event_dispatch(iscsit_conn_login_t *lsm, iscsit_conn_t *ict,
    login_event_ctx_t *ctx)
{
	idm_pdu_t *pdu = ctx->le_pdu; /* Only valid for some events */

	DTRACE_PROBE2(login__event, iscsit_conn_t *, ict,
	    login_event_ctx_t *, ctx);

	IDM_SM_LOG(CE_NOTE, "login_sm_event_dispatch: ict %p event %s(%d)",
	    (void *)ict,
	    iscsit_ile_name[ctx->le_ctx_event], ctx->le_ctx_event);

	/* State independent actions */
	switch (ctx->le_ctx_event) {
	case ILE_LOGIN_RCV:
		/* Perform basic sanity checks on the header */
		if (login_sm_req_pdu_check(ict, pdu) != IDM_STATUS_SUCCESS) {
			idm_pdu_t *rpdu;

			SET_LOGIN_ERROR(ict, ISCSI_STATUS_CLASS_INITIATOR_ERR,
			    ISCSI_LOGIN_STATUS_INVALID_REQUEST);
			/*
			 * If we haven't processed any PDU's yet then use
			 * this one as a template for the response
			 */
			if (ict->ict_login_sm.icl_login_resp_tmpl->opcode == 0)
				login_sm_handle_initial_login(ict, pdu);
			rpdu = login_sm_build_login_response(ict);
			login_sm_send_next_response(ict, rpdu);
			idm_pdu_complete(pdu, IDM_STATUS_SUCCESS);
			kmem_free(ctx, sizeof (*ctx));
			return;
		}
		break;
	default:
		break;
	}

	/* State dependent actions */
	switch (lsm->icl_login_state) {
	case ILS_LOGIN_INIT:
		login_sm_init(ict, ctx);
		break;
	case ILS_LOGIN_WAITING:
		login_sm_waiting(ict, ctx);
		break;
	case ILS_LOGIN_PROCESSING:
		login_sm_processing(ict, ctx);
		break;
	case ILS_LOGIN_RESPONDING:
		login_sm_responding(ict, ctx);
		break;
	case ILS_LOGIN_RESPONDED:
		login_sm_responded(ict, ctx);
		break;
	case ILS_LOGIN_FFP:
		login_sm_ffp(ict, ctx);
		break;
	case ILS_LOGIN_DONE:
		login_sm_done(ict, ctx);
		break;
	case ILS_LOGIN_ERROR:
		login_sm_error(ict, ctx);
		break;
	}

	kmem_free(ctx, sizeof (*ctx));
}

static void
login_sm_init(iscsit_conn_t *ict, login_event_ctx_t *ctx)
{
	idm_pdu_t *pdu;

	switch (ctx->le_ctx_event) {
	case ILE_LOGIN_RCV:
		pdu = ctx->le_pdu;

		/*
		 * This is the first login PDU we've received so use
		 * it to build the login response template and set our CSG.
		 */
		login_sm_handle_initial_login(ict, pdu);

		/*
		 * Accumulate all the login PDU's that make up this
		 * request on a queue.
		 */
		mutex_enter(&ict->ict_login_sm.icl_mutex);
		list_insert_tail(&ict->ict_login_sm.icl_pdu_list, pdu);
		mutex_exit(&ict->ict_login_sm.icl_mutex);

		if (pdu->isp_hdr->flags & ISCSI_FLAG_LOGIN_CONTINUE) {
			login_sm_send_ack(ict, pdu);
			login_sm_new_state(ict, ctx, ILS_LOGIN_WAITING);
		} else {
			login_sm_new_state(ict, ctx, ILS_LOGIN_PROCESSING);
		}
		break;
	case ILE_LOGIN_CONN_ERROR:
	case ILE_LOGIN_ERROR:
		login_sm_new_state(ict, ctx, ILS_LOGIN_ERROR);
		break;
	default:
		ASSERT(0);
	}
}

static void
login_sm_waiting(iscsit_conn_t *ict, login_event_ctx_t *ctx)
{
	idm_pdu_t *pdu;

	switch (ctx->le_ctx_event) {
	case ILE_LOGIN_RCV:
		pdu = ctx->le_pdu;
		mutex_enter(&ict->ict_login_sm.icl_mutex);
		list_insert_tail(&ict->ict_login_sm.icl_pdu_list, pdu);
		mutex_exit(&ict->ict_login_sm.icl_mutex);
		if (!(pdu->isp_hdr->flags & ISCSI_FLAG_LOGIN_CONTINUE)) {
			login_sm_new_state(ict, ctx, ILS_LOGIN_PROCESSING);
		} else {
			login_sm_send_ack(ict, pdu);
		}
		break;
	case ILE_LOGIN_ERROR:
		login_sm_new_state(ict, ctx, ILS_LOGIN_ERROR);
		break;
	case ILE_LOGIN_RESP_COMPLETE:
		break;
	default:
		ASSERT(0);
	}
}

static void
login_sm_processing(iscsit_conn_t *ict, login_event_ctx_t *ctx)
{
	switch (ctx->le_ctx_event) {
	case ILE_LOGIN_RESP_READY:
		login_sm_new_state(ict, ctx, ILS_LOGIN_RESPONDING);
		break;
	case ILE_LOGIN_RCV:
		idm_pdu_complete(ctx->le_pdu, IDM_STATUS_SUCCESS);
		/*FALLTHROUGH*/
	case ILE_LOGIN_CONN_ERROR:
	case ILE_LOGIN_ERROR:
		login_sm_new_state(ict, ctx, ILS_LOGIN_ERROR);
		break;
	default:
		ASSERT(0);
	}
}

static void
login_sm_responding(iscsit_conn_t *ict, login_event_ctx_t *ctx)
{
	idm_pdu_t *pdu, *rpdu;

	switch (ctx->le_ctx_event) {
	case ILE_LOGIN_RCV:
		pdu = ctx->le_pdu;
		/*
		 * We should only be in "responding" state if we have not
		 * sent the last PDU of a multi-PDU login response sequence.
		 * In that case we expect this received PDU to be an
		 * acknowledgement from the initiator (login PDU with C
		 * bit cleared and no data).  If it's the acknowledgement
		 * we are expecting then we send the next PDU in the login
		 * response sequence.  Otherwise it's a protocol error and
		 * the login fails.
		 */
		if (login_sm_validate_ack(ict, pdu) == IDM_STATUS_SUCCESS) {
			rpdu = login_sm_build_login_response(ict);
			login_sm_send_next_response(ict, rpdu);
		} else {
			login_sm_new_state(ict, ctx, ILS_LOGIN_ERROR);
		}
		idm_pdu_complete(pdu, IDM_STATUS_SUCCESS);
		break;
	case ILE_LOGIN_FFP:
		login_sm_new_state(ict, ctx, ILS_LOGIN_FFP);
		break;
	case ILE_LOGIN_RESP_COMPLETE:
		login_sm_new_state(ict, ctx, ILS_LOGIN_RESPONDED);
		break;
	case ILE_LOGIN_CONN_ERROR:
	case ILE_LOGIN_ERROR:
		login_sm_new_state(ict, ctx, ILS_LOGIN_ERROR);
		break;
	default:
		ASSERT(0);
	}
}

static void
login_sm_responded(iscsit_conn_t *ict, login_event_ctx_t *ctx)
{
	idm_pdu_t		*pdu;
	iscsi_login_hdr_t	*lh;

	switch (ctx->le_ctx_event) {
	case ILE_LOGIN_RCV:
		pdu = ctx->le_pdu;
		lh = (iscsi_login_hdr_t *)pdu->isp_hdr;
		/*
		 * Set the CSG, NSG and Transit bits based on the this PDU.
		 * The CSG already validated in login_sm_req_pdu_check().
		 * We'll clear the transit bit if we encounter any login
		 * parameters in the request that required an additional
		 * login transfer (i.e. no acceptable
		 * choices in range or we needed to change a boolean
		 * value from "Yes" to "No").
		 */
		ict->ict_login_sm.icl_login_csg =
		    ISCSI_LOGIN_CURRENT_STAGE(lh->flags);
		ict->ict_login_sm.icl_login_nsg =
		    ISCSI_LOGIN_NEXT_STAGE(lh->flags);
		ict->ict_login_sm.icl_login_transit =
		    lh->flags & ISCSI_FLAG_LOGIN_TRANSIT;
		mutex_enter(&ict->ict_login_sm.icl_mutex);
		list_insert_tail(&ict->ict_login_sm.icl_pdu_list, pdu);
		mutex_exit(&ict->ict_login_sm.icl_mutex);
		if (pdu->isp_hdr->flags & ISCSI_FLAG_LOGIN_CONTINUE) {
			login_sm_send_ack(ict, pdu);
			login_sm_new_state(ict, ctx, ILS_LOGIN_WAITING);
		} else {
			login_sm_new_state(ict, ctx, ILS_LOGIN_PROCESSING);
		}
		break;
	case ILE_LOGIN_CONN_ERROR:
	case ILE_LOGIN_ERROR:
		login_sm_new_state(ict, ctx, ILS_LOGIN_ERROR);
		break;
	default:
		ASSERT(0);
	}
}

static void
login_sm_ffp(iscsit_conn_t *ict, login_event_ctx_t *ctx)
{
	switch (ctx->le_ctx_event) {
	case ILE_LOGIN_RESP_COMPLETE:
		login_sm_new_state(ict, ctx, ILS_LOGIN_DONE);
		break;
	case ILE_LOGIN_CONN_ERROR:
	case ILE_LOGIN_ERROR:
		login_sm_new_state(ict, ctx, ILS_LOGIN_ERROR);
		break;
	default:
		ASSERT(0);
	}

}

/*ARGSUSED*/
static void
login_sm_done(iscsit_conn_t *ict, login_event_ctx_t *ctx)
{
	/* Terminal state, we should get no events */
	switch (ctx->le_ctx_event) {
	case ILE_LOGIN_RCV:
		/*
		 * We've already processed everything we're going to
		 * process.  Drop any additional login PDU's.
		 */
		idm_pdu_complete(ctx->le_pdu, IDM_STATUS_SUCCESS);
		break;
	case ILE_LOGIN_CONN_ERROR:
		/* Don't care */
		break;
	default:
		ASSERT(0);
	}
}

/*ARGSUSED*/
static void
login_sm_error(iscsit_conn_t *ict, login_event_ctx_t *ctx)
{
	switch (ctx->le_ctx_event) {
	case ILE_LOGIN_RCV:
		/*
		 * We've already processed everything we're going to
		 * process.  Drop any additional login PDU's.
		 */
		idm_pdu_complete(ctx->le_pdu, IDM_STATUS_SUCCESS);
		break;
	case ILE_LOGIN_CONN_ERROR:
		/* Don't care */
		break;
	default:
		ASSERT(0);
	}
}

static void
login_sm_new_state(iscsit_conn_t *ict, login_event_ctx_t *ctx,
    iscsit_login_state_t new_state)
{
	iscsit_conn_login_t *lsm = &ict->ict_login_sm;
	idm_pdu_t *rpdu;

	/*
	 * Validate new state
	 */
	ASSERT(new_state != ILS_UNDEFINED);
	ASSERT3U(new_state, <, ILS_MAX_STATE);

	new_state = (new_state < ILS_MAX_STATE) ?
	    new_state : ILS_UNDEFINED;

	IDM_SM_LOG(CE_NOTE, "login_sm_new_state: conn %p "
	    "%s (%d) --> %s (%d)\n", (void *)ict->ict_ic,
	    iscsit_ils_name[lsm->icl_login_state], lsm->icl_login_state,
	    iscsit_ils_name[new_state], new_state);

	DTRACE_PROBE3(login__state__change,
	    iscsit_conn_t *, ict, login_event_ctx_t *, ctx,
	    iscsit_login_state_t, new_state);

	mutex_enter(&lsm->icl_mutex);
	idm_sm_audit_state_change(&lsm->icl_state_audit, SAS_ISCSIT_LOGIN,
	    (int)lsm->icl_login_state, (int)new_state);
	lsm->icl_login_last_state = lsm->icl_login_state;
	lsm->icl_login_state = new_state;
	mutex_exit(&lsm->icl_mutex);

	switch (lsm->icl_login_state) {
	case ILS_LOGIN_WAITING:
		/* Do nothing, waiting for more login PDU's */
		break;
	case ILS_LOGIN_PROCESSING:
		/* All login PDU's received, process login request */
		login_sm_process_request(ict);
		break;
	case ILS_LOGIN_RESPONDING:
		rpdu = login_sm_build_login_response(ict);
		login_sm_send_next_response(ict, rpdu);
		break;
	case ILS_LOGIN_RESPONDED:
		/* clean up the login response idm text buffer */
		if (lsm->icl_login_resp_itb != NULL) {
			idm_itextbuf_free(lsm->icl_login_resp_itb);
			lsm->icl_login_resp_itb = NULL;
		}
		break;
	case ILS_LOGIN_FFP:
		login_sm_ffp_actions(ict);
		break;
	case ILS_LOGIN_DONE:
	case ILS_LOGIN_ERROR:
		/*
		 * Flag the terminal state for the dispatcher
		 */
		lsm->icl_login_complete = B_TRUE;
		break;
	case ILS_LOGIN_INIT: /* Initial state, can't return */
	default:
		ASSERT(0);
		/*NOTREACHED*/
	}
}

/*ARGSUSED*/
static void
login_sm_send_ack(iscsit_conn_t *ict, idm_pdu_t *pdu)
{
	iscsit_conn_login_t	*lsm = &ict->ict_login_sm;
	idm_pdu_t		*lack;

	/*
	 * allocate the response pdu
	 */
	lack = idm_pdu_alloc(sizeof (iscsi_hdr_t), 0);
	idm_pdu_init(lack, ict->ict_ic, ict, login_resp_complete_cb);
	lack->isp_flags |= IDM_PDU_LOGIN_TX;

	/*
	 * copy the response template into the response pdu
	 */
	bcopy(lsm->icl_login_resp_tmpl, lack->isp_hdr, sizeof (iscsi_hdr_t));

	iscsit_conn_hold(ict);
	idm_pdu_tx(lack);
}

/*ARGSUSED*/
static idm_status_t
login_sm_validate_ack(iscsit_conn_t *ict, idm_pdu_t *pdu)
{
	iscsi_hdr_t *ihp = pdu->isp_hdr;
	if (ihp->flags & ISCSI_FLAG_TEXT_CONTINUE) {
		return (IDM_STATUS_FAIL);
	}
	if (ntoh24(ihp->dlength) != 0) {
		return (IDM_STATUS_FAIL);
	}
	return (IDM_STATUS_SUCCESS);
}

static boolean_t
login_sm_is_last_response(idm_pdu_t *pdu)
{

	if (pdu->isp_hdr->flags & ISCSI_FLAG_LOGIN_CONTINUE) {
		return (B_FALSE);
	}
	return (B_TRUE);
}


static void
login_sm_handle_initial_login(iscsit_conn_t *ict, idm_pdu_t *pdu)
{
	iscsi_login_hdr_t *lh_req = (iscsi_login_hdr_t *)pdu->isp_hdr;
	iscsi_login_rsp_hdr_t *lh_resp =
	    ict->ict_login_sm.icl_login_resp_tmpl;

	/*
	 * First login PDU, this connection should not have a sesssion
	 * associated.
	 */
	ASSERT(ict->ict_sess == NULL);

	/*
	 * Save off TSIH and ISID for later use in finding a session
	 */
	ict->ict_login_sm.icl_cmdsn = ntohl(lh_req->cmdsn);
	ict->ict_login_sm.icl_tsih = ntohs(lh_req->tsid);
	bcopy(lh_req->isid, ict->ict_login_sm.icl_isid, ISCSI_ISID_LEN);

	/*
	 * We'll need the CID as well
	 */
	ict->ict_cid = ntohs(lh_req->cid);

	/*
	 * Set the CSG, NSG and Transit bits based on the first PDU
	 * in the login sequence.  The CSG already validated in
	 * login_sm_req_pdu_check(). We'll clear the transit bit if
	 * we encounter any login parameters in the request that
	 * required an additional login transfer (i.e. no acceptable
	 * choices in range or we needed to change a boolean
	 * value from "Yes" to "No").
	 */
	ict->ict_login_sm.icl_login_csg =
	    ISCSI_LOGIN_CURRENT_STAGE(lh_req->flags);
	ict->ict_login_sm.icl_login_nsg =
	    ISCSI_LOGIN_NEXT_STAGE(lh_req->flags);
	ict->ict_login_sm.icl_login_transit =
	    lh_req->flags & ISCSI_FLAG_LOGIN_TRANSIT;

	/*
	 * Initialize header for login reject response.  This will also
	 * be copied for use as a template for other login responses
	 */
	lh_resp->opcode = ISCSI_OP_LOGIN_RSP;
	lh_resp->max_version = ISCSIT_MAX_VERSION;

	/*
	 * We already validated that we can support one of the initiator's
	 * versions in login_sm_req_pdu_check().
	 */
#if (ISCSIT_MAX_VERSION > 0)
	if (ISCSIT_MAX_VERSION >= lh_req->min_version) {
		lh_resp->active_version =
		    MIN(lh_req->max_version, ISCSIT_MAX_VERSION);
	} else {
		ASSERT(ISCSIT_MAX_VERSION <= lh_req->max_version);
		lh_resp->active_version = ISCSIT_MAX_VERSION;
	}
#endif

	lh_resp->hlength = 0; /* No AHS */
	bcopy(lh_req->isid, lh_resp->isid, ISCSI_ISID_LEN);
	lh_resp->tsid = lh_req->tsid;
	lh_resp->itt = lh_req->itt;

	/*
	 * StatSn, ExpCmdSn and MaxCmdSn will be set immediately before
	 * transmission
	 */
}

static void
login_sm_send_next_response(iscsit_conn_t *ict, idm_pdu_t *pdu)
{
	iscsi_login_rsp_hdr_t *lh_resp = (iscsi_login_rsp_hdr_t *)pdu->isp_hdr;

	/* Make sure this PDU is part of the login phase */
	ASSERT((pdu->isp_flags & IDM_PDU_LOGIN_TX) != 0);

	/*
	 * Fill in header values
	 */
	hton24(lh_resp->dlength, pdu->isp_datalen);

	/*
	 * If the login is successful, this login response will contain
	 * the next StatSN and advance the StatSN for the connection.
	 */
	if (lh_resp->status_class == ISCSI_STATUS_CLASS_SUCCESS) {
		ASSERT(ict->ict_sess != NULL);

		if ((lh_resp->flags & ISCSI_FLAG_LOGIN_TRANSIT) &&
		    (ISCSI_LOGIN_NEXT_STAGE(lh_resp->flags) ==
		    ISCSI_FULL_FEATURE_PHASE) &&
		    !(lh_resp->flags & ISCSI_FLAG_LOGIN_CONTINUE)) {
			iscsit_login_sm_event(ict, ILE_LOGIN_FFP, NULL);
		}
		if (login_sm_is_last_response(pdu) == B_TRUE) {
			/*
			 * The last of a potentially mult-PDU response finished.
			 */
			iscsit_login_sm_event(ict, ILE_LOGIN_RESP_COMPLETE,
			    NULL);
		}

		iscsit_conn_hold(ict);
		pdu->isp_flags |= IDM_PDU_SET_STATSN | IDM_PDU_ADVANCE_STATSN;
		iscsit_pdu_tx(pdu);
	} else {
		/*
		 * If status_class != ISCSI_STATUS_CLASS_SUCCESS then
		 * StatSN is not valid and we can call idm_pdu_tx instead
		 * of iscsit_pdu_tx.  This is very good thing since in
		 * some cases of login failure we may not have a session.
		 * Since iscsit_calc_rspsn grabs the session mutex while
		 * it is retrieving values for expcmdsn and maxcmdsn this
		 * would cause a panic.
		 *
		 * Since we still want a value for expcmdsn, fill in an
		 * appropriate value based on the login request before
		 * sending the response. Cmdsn/expcmdsn do not advance during
		 * login phase.
		 */
		lh_resp->expcmdsn = htonl(ict->ict_login_sm.icl_cmdsn);
		lh_resp->maxcmdsn = htonl(ict->ict_login_sm.icl_cmdsn + 1);

		iscsit_conn_hold(ict);
		idm_pdu_tx(pdu);
	}

}

static void
login_sm_process_request(iscsit_conn_t *ict)
{
	iscsit_conn_login_t	*lsm = &ict->ict_login_sm;
	uint8_t			error_class = 0;
	uint8_t			error_detail = 0;

	/*
	 * First walk all the PDU's that make up this login request
	 * and compile all the iSCSI key-value pairs into nvlist format.
	 */

	ASSERT(lsm->icl_request_nvlist == NULL);
	/* create an nvlist for request key/value pairs */
	if (idm_pdu_list_to_nvlist(&lsm->icl_pdu_list,
	    &lsm->icl_request_nvlist, &error_detail) != IDM_STATUS_SUCCESS) {
		error_class = ISCSI_STATUS_CLASS_TARGET_ERR;
		SET_LOGIN_ERROR(ict, error_class, error_detail);
		goto request_fail;
	}

	/* Allocate a new nvlist for response key/value pairs */
	ASSERT(lsm->icl_response_nvlist == NULL);
	if (nvlist_alloc(&lsm->icl_response_nvlist, NV_UNIQUE_NAME,
	    KM_NOSLEEP) != 0) {
		error_class = ISCSI_STATUS_CLASS_TARGET_ERR;
		error_detail = ISCSI_LOGIN_STATUS_NO_RESOURCES;
		SET_LOGIN_ERROR(ict, error_class, error_detail);
		goto request_fail;
	}

	/*
	 * This would be a very good time to make sure we have
	 * negotiated the required values for the login phase.  For
	 * example we definitely should have defined InitiatorName,
	 * and Target name regardless of our current login phase.
	 */
	if (!ict->ict_op.op_initial_params_set) {
		if (login_sm_validate_initial_parameters(ict) !=
		    IDM_STATUS_SUCCESS) {
			goto request_fail;
		}

		/*
		 * Now setup our session association.  This includes
		 * create a new session or looking up an existing session,
		 * and if this is not a discovery session then we will
		 * also register this session with STMF.
		 */
		if (login_sm_session_bind(ict) != IDM_STATUS_SUCCESS) {
			goto request_fail;
		}

		if (login_sm_set_auth(ict) != IDM_STATUS_SUCCESS) {
			goto request_fail;
		}

		/*
		 * Prepend TargetAlias and PortalGroupTag
		 */
		if (ict->ict_op.op_discovery_session == B_FALSE) {
			if ((lsm->icl_auth.ca_tgt_alias[0]) != '\0') {
				(void) iscsit_reply_string(ict,
				    "TargetAlias",
				    &lsm->icl_auth.ca_tgt_alias[0]);
			}
			(void) iscsit_reply_numerical(ict,
			    "TargetPortalGroupTag",
			    (uint64_t)lsm->icl_tpgt_tag);
		}

		ict->ict_op.op_initial_params_set = B_TRUE;
	}

	if (login_sm_process_nvlist(ict) != IDM_STATUS_SUCCESS) {
		goto request_fail;
	}

	if (login_sm_check_security(ict) != IDM_STATUS_SUCCESS) {
		goto request_fail;
	}

	/* clean up request_nvlist */
	if (lsm->icl_request_nvlist != NULL) {
		nvlist_free(lsm->icl_request_nvlist);
		lsm->icl_request_nvlist = NULL;
	}

	/* convert any responses to textbuf form */
	ASSERT(lsm->icl_login_resp_itb == NULL);
	if (lsm->icl_response_nvlist) {
		lsm->icl_login_resp_itb = idm_nvlist_to_itextbuf(
		    lsm->icl_response_nvlist);
		if (lsm->icl_login_resp_itb == NULL) {
			/* Still need to send the resp so continue */
			SET_LOGIN_ERROR(ict,
			    ISCSI_STATUS_CLASS_TARGET_ERR,
			    ISCSI_LOGIN_STATUS_NO_RESOURCES);
		}
		/* clean up response_nvlist */
		nvlist_free(lsm->icl_response_nvlist);
		lsm->icl_response_nvlist = NULL;
	}

	/* tell the state machine to send the textbuf */
	iscsit_login_sm_event(ict, ILE_LOGIN_RESP_READY, NULL);
	return;

request_fail:

	/* clean up request_nvlist and response_nvlist */
	if (lsm->icl_request_nvlist != NULL) {
		nvlist_free(lsm->icl_request_nvlist);
		lsm->icl_request_nvlist = NULL;
	}
	if (lsm->icl_response_nvlist != NULL) {
		nvlist_free(lsm->icl_response_nvlist);
		lsm->icl_response_nvlist = NULL;
	}
	/* Make sure we already set the login error */
	if (ict->ict_login_sm.icl_login_resp_err_class ==
	    ISCSI_STATUS_CLASS_SUCCESS) {
		SET_LOGIN_ERROR(ict,
		    ISCSI_STATUS_CLASS_TARGET_ERR,
		    ISCSI_LOGIN_STATUS_TARGET_ERROR);
	}
	iscsit_login_sm_event(ict, ILE_LOGIN_RESP_READY, NULL);
}


static void
login_sm_ffp_actions(iscsit_conn_t *ict)
{
	iscsit_process_negotiated_values(ict);
}

static idm_status_t
login_sm_validate_initial_parameters(iscsit_conn_t *ict)
{
	int		nvrc;
	char		*string_val;
	uint8_t		error_class = ISCSI_STATUS_CLASS_INITIATOR_ERR;
	uint8_t		error_detail = ISCSI_LOGIN_STATUS_MISSING_FIELDS;
	idm_status_t	status = IDM_STATUS_FAIL;
	iscsit_conn_login_t *lsm = &ict->ict_login_sm;

	/*
	 * Make sure we received the required information from the initial
	 * login. Add these declaratives to the negotiated list and
	 * remove them from the request list as we go. If anything fails,
	 * the caller will clean-up the nvlists.
	 */

	/*
	 * Initiator name
	 */
	if ((nvrc = nvlist_lookup_string(lsm->icl_request_nvlist,
	    "InitiatorName", &string_val)) != 0) {
		goto initial_params_done;
	}
	if ((nvrc = nvlist_add_string(lsm->icl_negotiated_values,
	    "InitiatorName", string_val)) != 0) {
		goto initial_params_done;
	}
	if ((nvrc = nvlist_lookup_string(lsm->icl_negotiated_values,
	    "InitiatorName", &string_val)) != 0) {
		goto initial_params_done;
	}
	lsm->icl_initiator_name = string_val;
	idm_conn_set_initiator_name(ict->ict_ic, lsm->icl_initiator_name);
	if ((nvrc = nvlist_remove(lsm->icl_request_nvlist,
	    "InitiatorName", DATA_TYPE_STRING)) != 0) {
		goto initial_params_done;
	}

	/*
	 * Session type
	 */
	ict->ict_op.op_discovery_session = B_FALSE;
	nvrc = nvlist_lookup_string(lsm->icl_request_nvlist,
	    "SessionType", &string_val);
	if (nvrc != ENOENT && nvrc != 0) {
		goto initial_params_done;
	}
	if (nvrc == 0) {
		if (strcmp(string_val, "Discovery") == 0) {
			ict->ict_op.op_discovery_session = B_TRUE;
		} else if (strcmp(string_val, "Normal") != 0) {
			goto initial_params_done;
		}
		if ((nvrc = nvlist_add_string(lsm->icl_negotiated_values,
		    "SessionType", string_val)) != 0) {
			goto initial_params_done;
		}
		if ((nvrc = nvlist_remove(lsm->icl_request_nvlist,
		    "SessionType", DATA_TYPE_STRING)) != 0) {
			goto initial_params_done;
		}
	}

	/*
	 * Must have either TargetName or SessionType==Discovery
	 */
	lsm->icl_target_name = NULL;
	nvrc = nvlist_lookup_string(lsm->icl_request_nvlist,
	    "TargetName", &string_val);
	if (nvrc != ENOENT && nvrc != 0) {
		goto initial_params_done;
	}
	if (nvrc == 0) {
		if ((nvrc = nvlist_add_string(lsm->icl_negotiated_values,
		    "TargetName", string_val)) != 0) {
			goto initial_params_done;
		}
		if ((nvrc = nvlist_lookup_string(lsm->icl_negotiated_values,
		    "TargetName", &string_val)) != 0) {
			goto initial_params_done;
		}
		lsm->icl_target_name = string_val;
		idm_conn_set_target_name(ict->ict_ic, lsm->icl_target_name);
		if ((nvrc = nvlist_remove(lsm->icl_request_nvlist,
		    "TargetName", DATA_TYPE_STRING)) != 0) {
			goto initial_params_done;
		}
	} else if (ict->ict_op.op_discovery_session == B_FALSE) {
		/*
		 * Missing target name
		 */
		goto initial_params_done;
	}

	idm_conn_set_isid(ict->ict_ic, lsm->icl_isid);
	(void) snprintf(ict->ict_ic->ic_tsih, ISCSI_MAX_TSIH_LEN + 1, "0x%04x",
	    lsm->icl_tsih);

	IDM_SM_LOG(CE_NOTE, "conn %p: initiator=%s", (void *)ict->ict_ic,
	    (lsm->icl_initiator_name == NULL) ? "N/A" :
	    lsm->icl_initiator_name);
	IDM_SM_LOG(CE_NOTE, "conn %p: target=%s", (void *)ict->ict_ic,
	    (lsm->icl_target_name == NULL) ? "N/A" :
	    lsm->icl_target_name);
	IDM_SM_LOG(CE_NOTE, "conn %p: sessiontype=%s", (void *)ict->ict_ic,
	    ict->ict_op.op_discovery_session ? "Discovery" : "Normal");

	/* Sucess */
	status = IDM_STATUS_SUCCESS;
	error_class = ISCSI_STATUS_CLASS_SUCCESS;
	error_detail = ISCSI_LOGIN_STATUS_ACCEPT;

initial_params_done:
	SET_LOGIN_ERROR(ict, error_class, error_detail);
	return (status);
}


/*
 * login_sm_session_bind
 *
 * This function looks at the data from the initial login request
 * of a new connection and either looks up and existing session,
 * creates a new session, or returns an error.  RFC3720 section 5.3.1
 * defines these rules:
 *
 * +------------------------------------------------------------------+
 * |ISID      | TSIH        | CID    |     Target action              |
 * +------------------------------------------------------------------+
 * |new       | non-zero    | any    |     fail the login             |
 * |          |             |        |     ("session does not exist") |
 * +------------------------------------------------------------------+
 * |new       | zero        | any    |     instantiate a new session  |
 * +------------------------------------------------------------------+
 * |existing  | zero        | any    |     do session reinstatement   |
 * |          |             |        |     (see section 5.3.5)        |
 * +------------------------------------------------------------------+
 * |existing  | non-zero    | new    |     add a new connection to    |
 * |          | existing    |        |     the session                |
 * +------------------------------------------------------------------+
 * |existing  | non-zero    |existing|     do connection reinstatement|
 * |          | existing    |        |    (see section 5.3.4)         |
 * +------------------------------------------------------------------+
 * |existing  | non-zero    | any    |         fail the login         |
 * |          | new         |        |     ("session does not exist") |
 * +------------------------------------------------------------------+
 *
 */

/*
 * Map an <ipv6,port> address to an <ipv4,port> address if possible.
 * Returns:
 *    1 - success
 *    0 - address not mapable
 */

int
iscsit_is_v4_mapped(struct sockaddr_storage *sa, struct sockaddr_storage *v4sa)
{
	struct sockaddr_in *sin;
	struct in_addr *in;
	struct sockaddr_in6 *sin6;
	struct in6_addr *in6;
	int ret = 0;

	sin6 = (struct sockaddr_in6 *)sa;
	in6 = &sin6->sin6_addr;
	if ((sa->ss_family == AF_INET6) &&
	    (IN6_IS_ADDR_V4MAPPED(in6) || IN6_IS_ADDR_V4COMPAT(in6))) {
		sin = (struct sockaddr_in *)v4sa;
		in = &sin->sin_addr;
		v4sa->ss_family = AF_INET;
		sin->sin_port = sin6->sin6_port;
		IN6_V4MAPPED_TO_INADDR(in6, in);
		ret = 1;
	}
	return (ret);
}

static idm_status_t
login_sm_session_bind(iscsit_conn_t *ict)
{
	iscsit_conn_login_t	*lsm = &ict->ict_login_sm;
	iscsit_tgt_t		*tgt = NULL;
	iscsit_tpgt_t		*tpgt = NULL;
	iscsit_portal_t		*portal = NULL;
	iscsit_sess_t		*existing_sess = NULL;
	iscsit_sess_t		*new_sess = NULL;
	iscsit_conn_t		*existing_ict = NULL;
	uint8_t			error_class;
	uint8_t			error_detail;

	/*
	 * The multi-threaded execution of binding login sessions to target
	 * introduced race conditions in the session creation/binding and
	 * allowed duplicate sessions to tbe created. The addition of the
	 * global mutex login_sm_session_mutex makes this function single
	 * threaded to avoid such race conditions. Although this causes
	 * a small portion of the login to be serialized, it is unlikely
	 * that there would be numerous simultaneous logins to become a
	 * performance issue.
	 */
	mutex_enter(&login_sm_session_mutex);

	/*
	 * Look up target and then check if there are sessions or connections
	 * that match this request (see below).  Any holds taken on objects
	 * must be released at the end of the function (let's keep things
	 * simple).
	 *
	 * If target name is set then we should have a corresponding target
	 * context configured.
	 */
	if (lsm->icl_target_name != NULL) {
		/*
		 * iscsit_tgt_lookup implicitly takes a ref on the target
		 */
		ISCSIT_GLOBAL_LOCK(RW_READER);
		tgt = iscsit_tgt_lookup_locked(lsm->icl_target_name);
		if (tgt == NULL) {
			ISCSIT_GLOBAL_UNLOCK();
			SET_LOGIN_ERROR(ict, ISCSI_STATUS_CLASS_INITIATOR_ERR,
			    ISCSI_LOGIN_STATUS_TGT_NOT_FOUND);
			goto session_bind_error;
		} else {
			mutex_enter(&tgt->target_mutex);
			tpgt = avl_first(&tgt->target_tpgt_list);

			if (IS_DEFAULT_TPGT(tpgt)) {
				lsm->icl_tpgt_tag = ISCSIT_DEFAULT_TPGT;
			} else {
				/*
				 * Find the portal group tag for the
				 * login response.
				 */
				struct sockaddr_storage v4sa, *sa;

				sa = &ict->ict_ic->ic_laddr;
				portal = iscsit_tgt_lookup_portal(tgt,
				    sa, &tpgt);
				if (portal == NULL &&
				    iscsit_is_v4_mapped(sa, &v4sa)) {
					/*
					 * Try again if the local address
					 * was v6 mappable to v4.
					 */
					portal = iscsit_tgt_lookup_portal(tgt,
					    &v4sa, &tpgt);

				}
				if (portal == NULL) {
					/*
					 * Initiator came in on wrong address
					 */
					SET_LOGIN_ERROR(ict,
					    ISCSI_STATUS_CLASS_INITIATOR_ERR,
					    ISCSI_LOGIN_STATUS_TGT_NOT_FOUND);
					mutex_exit(&tgt->target_mutex);
					ISCSIT_GLOBAL_UNLOCK();
					goto session_bind_error;
				}

				/*
				 * Need to release holds on the portal and
				 * tpgt after processing is complete.
				 */
				lsm->icl_tpgt_tag = tpgt->tpgt_tag;
				iscsit_portal_rele(portal);
				iscsit_tpgt_rele(tpgt);
			}

			mutex_enter(&iscsit_global.global_state_mutex);
			if ((tgt->target_state != TS_STMF_ONLINE) ||
			    ((iscsit_global.global_svc_state != ISE_ENABLED) &&
			    ((iscsit_global.global_svc_state != ISE_BUSY)))) {
				mutex_exit(&iscsit_global.global_state_mutex);
				SET_LOGIN_ERROR(ict,
				    ISCSI_STATUS_CLASS_TARGET_ERR,
				    ISCSI_LOGIN_STATUS_SVC_UNAVAILABLE);
				mutex_exit(&tgt->target_mutex);
				ISCSIT_GLOBAL_UNLOCK();
				goto session_bind_error;
			}
			mutex_exit(&iscsit_global.global_state_mutex);
			mutex_exit(&tgt->target_mutex);
			ISCSIT_GLOBAL_UNLOCK();
		}
	}

	ASSERT((tgt != NULL) || (ict->ict_op.op_discovery_session == B_TRUE));

	/*
	 * Check if there is an existing session matching this ISID.  If
	 * tgt == NULL then we'll look for the session on the global list
	 * of discovery session.  If we find a session then the ISID
	 * exists.
	 */
	existing_sess = iscsit_tgt_lookup_sess(tgt, lsm->icl_initiator_name,
	    lsm->icl_isid, lsm->icl_tsih, lsm->icl_tpgt_tag);
	if (existing_sess != NULL) {
		existing_ict = iscsit_sess_lookup_conn(existing_sess,
		    ict->ict_cid);
	}

	/*
	 * If this is a discovery session, make sure it has appropriate
	 * parameters.
	 */
	if ((ict->ict_op.op_discovery_session == B_TRUE) &&
	    ((lsm->icl_tsih != ISCSI_UNSPEC_TSIH) || (existing_sess != NULL))) {
		/* XXX Do we need to check for existing ISID (sess != NULL)? */
		SET_LOGIN_ERROR(ict, ISCSI_STATUS_CLASS_INITIATOR_ERR,
		    ISCSI_LOGIN_STATUS_INVALID_REQUEST);
		goto session_bind_error;
	}

	/*
	 * Check the two error conditions from the table.
	 *
	 * ISID=new, TSIH=non-zero
	 */
	if ((existing_sess == NULL) && (lsm->icl_tsih != ISCSI_UNSPEC_TSIH)) {
		/* fail the login */
		SET_LOGIN_ERROR(ict, ISCSI_STATUS_CLASS_INITIATOR_ERR,
		    ISCSI_LOGIN_STATUS_NO_SESSION);
		goto session_bind_error;
	}

	/* ISID=existing, TSIH=non-zero new */
	if ((existing_sess != NULL) && (lsm->icl_tsih != 0) &&
	    (existing_sess->ist_tsih != lsm->icl_tsih)) {
		/* fail the login */
		SET_LOGIN_ERROR(ict, ISCSI_STATUS_CLASS_INITIATOR_ERR,
		    ISCSI_LOGIN_STATUS_NO_SESSION);
		goto session_bind_error;
	}

	/*
	 * Handle the remaining table cases in order
	 */
	if (existing_sess == NULL) {
		/* Should have caught this above */
		ASSERT(lsm->icl_tsih == ISCSI_UNSPEC_TSIH);
		/*
		 * ISID=new, TSIH=zero --> instantiate a new session
		 */
		new_sess = iscsit_sess_create(tgt, ict, lsm->icl_cmdsn,
		    lsm->icl_isid, lsm->icl_tpgt_tag, lsm->icl_initiator_name,
		    lsm->icl_target_name, &error_class, &error_detail);
		ASSERT(new_sess != NULL);

		/* Session create may have failed even if it returned a value */
		if (error_class != ISCSI_STATUS_CLASS_SUCCESS) {
			SET_LOGIN_ERROR(ict, error_class, error_detail);
			goto session_bind_error;
		}

		/*
		 * If we don't already have an STMF session and this is not
		 * a discovery session then we need to allocate and register
		 * one.
		 */
		if (!ict->ict_op.op_discovery_session) {
			if (login_sm_session_register(ict) !=
			    IDM_STATUS_SUCCESS) {
				/* login_sm_session_register sets error codes */
				goto session_bind_error;
			}
		}

	} else {
		if (lsm->icl_tsih == ISCSI_UNSPEC_TSIH) {
			/*
			 * ISID=existing, TSIH=zero --> Session reinstatement
			 */
			new_sess = iscsit_sess_reinstate(tgt, existing_sess,
			    ict, &error_class, &error_detail);
			ASSERT(new_sess != NULL);

			if (error_class != ISCSI_STATUS_CLASS_SUCCESS) {
				SET_LOGIN_ERROR(ict, error_class, error_detail);
				goto session_bind_error;
			}

			/*
			 * If we don't already have an STMF session and this is
			 * not a discovery session then we need to allocate and
			 * register one.
			 */
			if (!ict->ict_op.op_discovery_session) {
				if (login_sm_session_register(ict) !=
				    IDM_STATUS_SUCCESS) {
					/*
					 * login_sm_session_register sets
					 * error codes
					 */
					goto session_bind_error;
				}
			}
		} else {
			/*
			 * The following code covers these two cases:
			 * ISID=existing, TSIH=non-zero existing, CID=new
			 * --> add new connection to MC/S session
			 * ISID=existing, TSIH=non-zero existing, CID=existing
			 * --> do connection reinstatement
			 *
			 * Session continuation uses this path as well
			 */
			cmn_err(CE_NOTE, "login_sm_session_bind: add new "
			    "conn/sess continue");
			if (existing_ict != NULL) {
				/*
				 * ISID=existing, TSIH=non-zero existing,
				 * CID=existing --> do connection reinstatement
				 */
				if (iscsit_conn_reinstate(existing_ict, ict) !=
				    IDM_STATUS_SUCCESS) {
					/*
					 * Most likely this means the connection
					 * the initiator is trying to reinstate
					 * is not in an acceptable state.
					 */
					SET_LOGIN_ERROR(ict,
					    ISCSI_STATUS_CLASS_INITIATOR_ERR,
					    ISCSI_LOGIN_STATUS_INIT_ERR);
					goto session_bind_error;
				}
			}

			iscsit_sess_sm_event(existing_sess, SE_CONN_IN_LOGIN,
			    ict);
		}
	}

	if (tgt != NULL)
		iscsit_tgt_rele(tgt);
	if (existing_sess != NULL)
		iscsit_sess_rele(existing_sess);
	if (existing_ict != NULL)
		iscsit_conn_rele(existing_ict);

	mutex_exit(&login_sm_session_mutex);
	return (IDM_STATUS_SUCCESS);

session_bind_error:
	if (tgt != NULL)
		iscsit_tgt_rele(tgt);
	if (existing_sess != NULL)
		iscsit_sess_rele(existing_sess);
	if (existing_ict != NULL)
		iscsit_conn_rele(existing_ict);

	/*
	 * If session bind fails we will fail the login but don't destroy
	 * the session until later.
	 */
	mutex_exit(&login_sm_session_mutex);
	return (IDM_STATUS_FAIL);
}


static idm_status_t
login_sm_set_auth(iscsit_conn_t *ict)
{
	idm_status_t		idmrc = IDM_STATUS_SUCCESS;
	iscsit_conn_login_t	*lsm = &ict->ict_login_sm;
	iscsit_ini_t		*ini;
	iscsit_tgt_t		*tgt;
	char			*auth = "";
	char			*radiusserver = "";
	char			*radiussecret = "";
	char			*chapuser = "";
	char			*chapsecret = "";
	char			*targetchapuser = "";
	char			*targetchapsecret = "";
	char			*targetalias = "";
	int			i;

	ISCSIT_GLOBAL_LOCK(RW_READER);

	/*
	 * Set authentication method to none for discovery session.
	 */
	if (ict->ict_op.op_discovery_session == B_TRUE) {
		lsm->icl_auth.ca_method_valid_list[0] = AM_NONE;
		ISCSIT_GLOBAL_UNLOCK();
		return (idmrc);
	}

	/*
	 * Get all the authentication parameters we need -- since we hold
	 * the global config lock we guarantee that the parameters will
	 * be consistent with each other.
	 */
	(void) nvlist_lookup_string(iscsit_global.global_props,
	    PROP_AUTH, &auth);
	(void) nvlist_lookup_string(iscsit_global.global_props,
	    PROP_RADIUS_SERVER, &radiusserver);
	(void) nvlist_lookup_string(iscsit_global.global_props,
	    PROP_RADIUS_SECRET, &radiussecret);

	ini = iscsit_ini_lookup_locked(lsm->icl_initiator_name);
	if (ini != NULL) {
		/* Get Initiator CHAP parameters */
		(void) nvlist_lookup_string(ini->ini_props, PROP_CHAP_USER,
		    &chapuser);
		(void) nvlist_lookup_string(ini->ini_props, PROP_CHAP_SECRET,
		    &chapsecret);
	}

	tgt = ict->ict_sess->ist_tgt;
	if (tgt != NULL) {
		/* See if we have a target-specific authentication setting */
		(void) nvlist_lookup_string(tgt->target_props, PROP_AUTH,
		    &auth);
		/* Get target CHAP parameters */
		(void) nvlist_lookup_string(tgt->target_props,
		    PROP_TARGET_CHAP_USER, &targetchapuser);
		(void) nvlist_lookup_string(tgt->target_props,
		    PROP_TARGET_CHAP_SECRET, &targetchapsecret);
		/* Get alias */
		(void) nvlist_lookup_string(tgt->target_props,
		    PROP_ALIAS, &targetalias);
	}

	/* Set authentication method */
	i = 0;
	if (strcmp(auth, PA_AUTH_RADIUS) == 0) {
		/* CHAP authentication using RADIUS server */
		lsm->icl_auth.ca_method_valid_list[i++] = AM_CHAP;
		lsm->icl_auth.ca_use_radius = B_TRUE;
	} else if (strcmp(auth, PA_AUTH_CHAP) == 0) {
		/* Local CHAP authentication */
		lsm->icl_auth.ca_method_valid_list[i++] = AM_CHAP;
		lsm->icl_auth.ca_use_radius = B_FALSE;
	} else if ((strcmp(auth, PA_AUTH_NONE) == 0) ||
	    (strcmp(auth, "") == 0)) {
		/* No authentication */
		lsm->icl_auth.ca_method_valid_list[i++] = AM_NONE;
	}

	/*
	 * If initiator/target CHAP username is not set then use the
	 * node name.  If lsm->icl_target_name == NULL then this is
	 * a discovery session so we don't need to work about the target.
	 */
	if (strcmp(chapuser, "") == 0) {
		(void) strlcpy(lsm->icl_auth.ca_ini_chapuser,
		    lsm->icl_initiator_name,
		    min(iscsitAuthStringMaxLength, MAX_ISCSI_NODENAMELEN));
	} else {
		(void) strlcpy(lsm->icl_auth.ca_ini_chapuser, chapuser,
		    iscsitAuthStringMaxLength);
	}
	if ((lsm->icl_target_name != NULL) &&
	    (strcmp(targetchapuser, "") == 0)) {
		(void) strlcpy(lsm->icl_auth.ca_tgt_chapuser,
		    lsm->icl_target_name,
		    min(iscsitAuthStringMaxLength, MAX_ISCSI_NODENAMELEN));
	} else {
		(void) strlcpy(lsm->icl_auth.ca_tgt_chapuser,
		    targetchapuser, iscsitAuthStringMaxLength);
	}

	/*
	 * Secrets are stored in base64-encoded format so we need to
	 * decode them into binary form
	 */
	if (strcmp(chapsecret, "") == 0) {
		lsm->icl_auth.ca_ini_chapsecretlen = 0;
	} else {
		if (iscsi_base64_str_to_binary(chapsecret,
		    strnlen(chapsecret, iscsitAuthStringMaxLength),
		    lsm->icl_auth.ca_ini_chapsecret, iscsitAuthStringMaxLength,
		    &lsm->icl_auth.ca_ini_chapsecretlen) != 0) {
			cmn_err(CE_WARN, "Corrupted CHAP secret"
			    " for initiator %s", lsm->icl_initiator_name);
			lsm->icl_auth.ca_ini_chapsecretlen = 0;
		}
	}
	if (strcmp(targetchapsecret, "") == 0) {
		lsm->icl_auth.ca_tgt_chapsecretlen = 0;
	} else {
		if (iscsi_base64_str_to_binary(targetchapsecret,
		    strnlen(targetchapsecret, iscsitAuthStringMaxLength),
		    lsm->icl_auth.ca_tgt_chapsecret, iscsitAuthStringMaxLength,
		    &lsm->icl_auth.ca_tgt_chapsecretlen) != 0) {
			cmn_err(CE_WARN, "Corrupted CHAP secret"
			    " for target %s", lsm->icl_target_name);
			lsm->icl_auth.ca_tgt_chapsecretlen = 0;
		}
	}
	if (strcmp(radiussecret, "") == 0) {
		lsm->icl_auth.ca_radius_secretlen = 0;
	} else {
		if (iscsi_base64_str_to_binary(radiussecret,
		    strnlen(radiussecret, iscsitAuthStringMaxLength),
		    lsm->icl_auth.ca_radius_secret, iscsitAuthStringMaxLength,
		    &lsm->icl_auth.ca_radius_secretlen) != 0) {
			cmn_err(CE_WARN, "Corrupted RADIUS secret");
			lsm->icl_auth.ca_radius_secretlen = 0;
		}
	}

	/*
	 * Set alias
	 */
	(void) strlcpy(lsm->icl_auth.ca_tgt_alias, targetalias,
	    MAX_ISCSI_NODENAMELEN);

	/*
	 * Now that authentication parameters are setup, validate the parameters
	 * against the authentication mode
	 * Decode RADIUS server value int lsm->icl_auth.ca_radius_server
	 */
	if ((strcmp(auth, PA_AUTH_RADIUS) == 0) &&
	    ((lsm->icl_auth.ca_radius_secretlen == 0) ||
	    (strcmp(radiusserver, "") == 0) ||
	    it_common_convert_sa(radiusserver,
	    &lsm->icl_auth.ca_radius_server,
	    DEFAULT_RADIUS_PORT) == NULL)) {
		cmn_err(CE_WARN, "RADIUS authentication selected "
		    "for target %s but RADIUS parameters are not "
		    "configured.", lsm->icl_target_name);
		SET_LOGIN_ERROR(ict, ISCSI_STATUS_CLASS_TARGET_ERR,
		    ISCSI_LOGIN_STATUS_TARGET_ERROR);
		idmrc = IDM_STATUS_FAIL;
	} else if ((strcmp(auth, PA_AUTH_CHAP) == 0) &&
	    (lsm->icl_auth.ca_ini_chapsecretlen == 0)) {
		SET_LOGIN_ERROR(ict, ISCSI_STATUS_CLASS_INITIATOR_ERR,
		    ISCSI_LOGIN_STATUS_AUTH_FAILED);
		idmrc = IDM_STATUS_FAIL;
	}

	ISCSIT_GLOBAL_UNLOCK();

	return (idmrc);
}


static idm_status_t
login_sm_session_register(iscsit_conn_t *ict)
{
	iscsit_sess_t		*ist = ict->ict_sess;
	stmf_scsi_session_t	*ss;
	iscsi_transport_id_t	*iscsi_tptid;
	uint16_t		ident_len, adn_len, tptid_sz;

	/*
	 * Hold target mutex until we have finished registering with STMF
	 */
	mutex_enter(&ist->ist_tgt->target_mutex);
	if (ist->ist_tgt->target_state != TS_STMF_ONLINE) {
		mutex_exit(&ist->ist_tgt->target_mutex);
		SET_LOGIN_ERROR(ict, ISCSI_STATUS_CLASS_INITIATOR_ERR,
		    ISCSI_LOGIN_STATUS_TGT_REMOVED);
		return (IDM_STATUS_FAIL);
	}

	ss = stmf_alloc(STMF_STRUCT_SCSI_SESSION, 0,
	    0);
	if (ss == NULL) {
		mutex_exit(&ist->ist_tgt->target_mutex);
		SET_LOGIN_ERROR(ict, ISCSI_STATUS_CLASS_TARGET_ERR,
		    ISCSI_LOGIN_STATUS_NO_RESOURCES);
		return (IDM_STATUS_FAIL);
	}

	ident_len = strlen(ist->ist_initiator_name) + 1;
	ss->ss_rport_id = kmem_zalloc(sizeof (scsi_devid_desc_t) +
	    ident_len, KM_SLEEP);
	(void) strcpy((char *)ss->ss_rport_id->ident, ist->ist_initiator_name);
	ss->ss_rport_id->ident_length = ident_len - 1;
	ss->ss_rport_id->protocol_id = PROTOCOL_iSCSI;
	ss->ss_rport_id->piv = 1;
	ss->ss_rport_id->code_set = CODE_SET_ASCII;
	ss->ss_rport_id->association = ID_IS_TARGET_PORT;

	/* adn_len should be 4 byte aligned, SPC3 rev 23, section 7.54.6 */
	adn_len = (ident_len + 3) & ~ 3;
	tptid_sz = sizeof (iscsi_transport_id_t) - 1 + adn_len;
	ss->ss_rport = stmf_remote_port_alloc(tptid_sz);
	ss->ss_rport->rport_tptid->protocol_id = PROTOCOL_iSCSI;
	ss->ss_rport->rport_tptid->format_code = 0;
	iscsi_tptid = (iscsi_transport_id_t *)ss->ss_rport->rport_tptid;
	SCSI_WRITE16(&iscsi_tptid->add_len, adn_len);
	(void) strlcpy((char *)iscsi_tptid->iscsi_name,
	    ist->ist_initiator_name, ident_len);

	ss->ss_lport = ist->ist_lport;

	if (stmf_register_scsi_session(ict->ict_sess->ist_lport, ss) !=
	    STMF_SUCCESS) {
		mutex_exit(&ist->ist_tgt->target_mutex);
		kmem_free(ss->ss_rport_id,
		    sizeof (scsi_devid_desc_t) +
		    strlen(ist->ist_initiator_name) + 1);
		stmf_remote_port_free(ss->ss_rport);
		stmf_free(ss);
		SET_LOGIN_ERROR(ict, ISCSI_STATUS_CLASS_TARGET_ERR,
		    ISCSI_LOGIN_STATUS_TARGET_ERROR);
		return (IDM_STATUS_FAIL);
	}

	ss->ss_port_private = ict->ict_sess;
	ict->ict_sess->ist_stmf_sess = ss;
	mutex_exit(&ist->ist_tgt->target_mutex);

	return (IDM_STATUS_SUCCESS);
}


static idm_status_t
login_sm_req_pdu_check(iscsit_conn_t *ict, idm_pdu_t *pdu)
{
	uint8_t			csg_req;
	iscsit_conn_login_t	*lsm = &ict->ict_login_sm;
	iscsi_login_hdr_t	*lh = (iscsi_login_hdr_t *)pdu->isp_hdr;
	iscsi_login_rsp_hdr_t *lh_resp = lsm->icl_login_resp_tmpl;

	/*
	 * Check CSG
	 */
	csg_req = ISCSI_LOGIN_CURRENT_STAGE(lh->flags);
	switch (csg_req) {
	case ISCSI_SECURITY_NEGOTIATION_STAGE:
	case ISCSI_OP_PARMS_NEGOTIATION_STAGE:
		if ((csg_req != lsm->icl_login_csg) &&
		    (lsm->icl_login_state != ILS_LOGIN_INIT)) {
			/*
			 * Inappropriate CSG change.  Initiator can only
			 * change CSG after we've responded with the
			 * transit bit set.  If we had responded with
			 * a CSG change previous we would have updated
			 * our copy of CSG.
			 *
			 * The exception is when we are in ILS_LOGIN_INIT
			 * state since we haven't determined our initial
			 * CSG value yet.
			 */
			goto pdu_check_fail;
		}
		break;
	case ISCSI_FULL_FEATURE_PHASE:
	default:
		goto pdu_check_fail;
	}

	/*
	 * If this is the first login PDU for a new connection then
	 * the session will be NULL.
	 */
	if (ict->ict_sess != NULL) {
		/*
		 * We've already created a session on a previous PDU.  Make
		 * sure this PDU is consistent with what we've already seen
		 */
		if ((ict->ict_cid != ntohs(lh->cid)) ||
		    (bcmp(ict->ict_sess->ist_isid, lh->isid,
		    ISCSI_ISID_LEN) != 0)) {
			goto pdu_check_fail;
		}
	}

	/*
	 * Make sure we are compatible with the version range
	 */
#if (ISCSIT_MAX_VERSION > 0)
	if ((lh->min_version > ISCSIT_MAX_VERSION) ||
	    (lh->max_version < ISCSIT_MIN_VERSION)) {
		goto pdu_check_fail;
	}
#endif

	/*
	 * Just in case the initiator changes things up on us along the way
	 * check against our active_version -- we can't change the active
	 * version and the initiator is not *supposed* to change its
	 * min_version and max_version values so this should never happen.
	 * Of course we only do this if the response header template has
	 * been built.
	 */
	if ((lh_resp->opcode == ISCSI_OP_LOGIN_RSP) && /* header valid */
	    ((lh->min_version > lh_resp->active_version) ||
	    (lh->max_version < lh_resp->active_version))) {
		goto pdu_check_fail;
	}

	return (IDM_STATUS_SUCCESS);

pdu_check_fail:
	return (IDM_STATUS_FAIL);
}

static idm_status_t
login_sm_process_nvlist(iscsit_conn_t *ict)
{
	iscsit_conn_login_t	*lsm = &ict->ict_login_sm;
	char			*nvp_name;
	nvpair_t		*nvp;
	nvpair_t		*next_nvp;
	nvpair_t		*negotiated_nvp;
	kv_status_t		kvrc;
	uint8_t			error_class;
	uint8_t			error_detail;
	idm_status_t		idm_status;

	error_class = ISCSI_STATUS_CLASS_SUCCESS;
	error_detail = ISCSI_LOGIN_STATUS_ACCEPT;

	/* First, request that the transport process the list */
	kvrc = idm_negotiate_key_values(ict->ict_ic, lsm->icl_request_nvlist,
	    lsm->icl_response_nvlist, lsm->icl_negotiated_values);
	idm_kvstat_to_error(kvrc, &error_class, &error_detail);
	if (error_class != ISCSI_STATUS_CLASS_SUCCESS) {
		SET_LOGIN_ERROR(ict, error_class, error_detail);
		idm_status = IDM_STATUS_FAIL;
		return (idm_status);
	}

	/* Ensure we clear transit bit if the transport layer has countered */
	if (kvrc == KV_HANDLED_NO_TRANSIT) {
		lsm->icl_login_transit = B_FALSE;
	}

	/* Prepend the declarative params */
	if (!ict->ict_op.op_declarative_params_set &&
	    lsm->icl_login_csg == ISCSI_OP_PARMS_NEGOTIATION_STAGE) {
		if (iscsit_add_declarative_keys(ict) != IDM_STATUS_SUCCESS) {
			idm_status = IDM_STATUS_FAIL;
			return (idm_status);
		}
		ict->ict_op.op_declarative_params_set = B_TRUE;
	}

	/* Now, move on and process the rest of the pairs */
	nvp = nvlist_next_nvpair(lsm->icl_request_nvlist, NULL);
	while (nvp != NULL) {
		next_nvp = nvlist_next_nvpair(lsm->icl_request_nvlist, nvp);
		nvp_name = nvpair_name(nvp);
		/*
		 * If we've already agreed upon a value then make sure this
		 * is not attempting to change that value.  From RFC3270
		 * section 5.3:
		 *
		 * "Neither the initiator nor the target should attempt to
		 * declare or negotiate a parameter more than once during
		 * login except for responses to specific keys that
		 * explicitly allow repeated key declarations (e.g.,
		 * TargetAddress).  An attempt to renegotiate/redeclare
		 * parameters not specifically allowed MUST be detected
		 * by the initiator and target.  If such an attempt is
		 * detected by the target, the target MUST respond
		 * with Login reject (initiator error); ..."
		 */
		if (nvlist_lookup_nvpair(lsm->icl_negotiated_values,
		    nvp_name, &negotiated_nvp) == 0) {
			kvrc = KV_HANDLED;
		} else {
			kvrc = iscsit_handle_key(ict, nvp, nvp_name);
		}

		idm_kvstat_to_error(kvrc, &error_class, &error_detail);
		if (error_class != ISCSI_STATUS_CLASS_SUCCESS) {
			break;
		}

		nvp = next_nvp;
	}

	if (error_class == ISCSI_STATUS_CLASS_SUCCESS) {
		idm_status = IDM_STATUS_SUCCESS;
	} else {
		/* supply login class/detail for login errors */
		SET_LOGIN_ERROR(ict, error_class, error_detail);
		idm_status = IDM_STATUS_FAIL;
	}

	return (idm_status);
}

static idm_status_t
login_sm_check_security(iscsit_conn_t *ict)
{
	iscsit_conn_login_t	*lsm = &ict->ict_login_sm;
	conn_auth_t		*auth = &lsm->icl_auth;
	iscsit_auth_method_t	*am_list = &auth->ca_method_valid_list[0];
	kv_status_t		kvrc;
	uint8_t			error_class;
	uint8_t			error_detail;
	idm_status_t		idm_status;

	error_class = ISCSI_STATUS_CLASS_SUCCESS;
	error_detail = ISCSI_LOGIN_STATUS_ACCEPT;

	/* Check authentication status. */
	if (lsm->icl_login_csg == ISCSI_SECURITY_NEGOTIATION_STAGE) {
		/*
		 * We should have some authentication key/value pair(s)
		 * received from initiator and the authentication phase
		 * has been shifted when the key/value pair(s) are being
		 * handled in the previous call iscsit_handle_security_key.
		 * Now it turns to target to check the authentication phase
		 * and shift it after taking some authentication action.
		 */
		kvrc = iscsit_reply_security_key(ict);
		idm_kvstat_to_error(kvrc, &error_class, &error_detail);
	} else if (!ict->ict_login_sm.icl_auth_pass) {
		/*
		 * Check to see if the target allows initiators to bypass the
		 * security check.  If the target is configured to require
		 * authentication, we reject the connection.
		 */
		if (am_list[0] == AM_NONE || am_list[0] == 0) {
			ict->ict_login_sm.icl_auth_pass = 1;
		} else {
			error_class = ISCSI_STATUS_CLASS_INITIATOR_ERR;
			error_detail = ISCSI_LOGIN_STATUS_AUTH_FAILED;
		}
	}

	if (error_class == ISCSI_STATUS_CLASS_SUCCESS) {
		idm_status = IDM_STATUS_SUCCESS;
	} else {
		/* supply login class/detail for login errors */
		SET_LOGIN_ERROR(ict, error_class, error_detail);
		idm_status = IDM_STATUS_FAIL;
	}

	return (idm_status);
}

static idm_pdu_t *
login_sm_build_login_response(iscsit_conn_t *ict)
{
	iscsit_conn_login_t	*lsm = &ict->ict_login_sm;
	iscsi_login_rsp_hdr_t	*lh;
	int			transit, text_transit = 1;
	idm_pdu_t		*login_resp;

	/*
	 * Create a response PDU and fill it with as much of
	 * the response text that will fit.
	 */

	if (lsm->icl_login_resp_itb) {
		/* allocate a pdu with space for text */
		login_resp = idm_pdu_alloc(sizeof (iscsi_hdr_t),
		    ISCSI_DEFAULT_MAX_RECV_SEG_LEN);
		/* copy a chunk of text into the pdu */
		lsm->icl_login_resp_buf = idm_pdu_init_text_data(
		    login_resp, lsm->icl_login_resp_itb,
		    ISCSI_DEFAULT_MAX_RECV_SEG_LEN,
		    lsm->icl_login_resp_buf, &text_transit);
		if (text_transit) {
			/* text buf has been consumed */
			idm_itextbuf_free(lsm->icl_login_resp_itb);
			lsm->icl_login_resp_itb = NULL;
			lsm->icl_login_resp_buf = NULL;
		}
	} else {
		/* allocate a pdu for just a header */
		login_resp = idm_pdu_alloc(sizeof (iscsi_hdr_t), 0);
	}
	/* finish initializing the pdu */
	idm_pdu_init(login_resp,
	    ict->ict_ic, ict, login_resp_complete_cb);
	login_resp->isp_flags |= IDM_PDU_LOGIN_TX;

	/*
	 * Use the BHS header values from the response template
	 */
	bcopy(lsm->icl_login_resp_tmpl,
	    login_resp->isp_hdr, sizeof (iscsi_login_rsp_hdr_t));

	lh = (iscsi_login_rsp_hdr_t *)login_resp->isp_hdr;

	/* Set error class/detail */
	lh->status_class = lsm->icl_login_resp_err_class;
	lh->status_detail = lsm->icl_login_resp_err_detail;
	/* Set CSG, NSG and Transit */
	lh->flags = 0;
	lh->flags |= lsm->icl_login_csg << 2;


	if (lh->status_class == ISCSI_STATUS_CLASS_SUCCESS) {
		if (lsm->icl_login_transit &&
		    lsm->icl_auth_pass != 0) {
			transit = 1;
		} else {
			transit = 0;
		}
		/*
		 * inititalize the text data
		 */
		if (transit == 1 && text_transit == 1) {
			lh->flags |= lsm->icl_login_nsg;
			lsm->icl_login_csg = lsm->icl_login_nsg;
			lh->flags |= ISCSI_FLAG_LOGIN_TRANSIT;
		} else {
			lh->flags &= ~ISCSI_FLAG_LOGIN_TRANSIT;
		}

		/* If we are transitioning to FFP then set TSIH */
		if (transit && (lh->flags & ISCSI_FLAG_LOGIN_TRANSIT) &&
		    lsm->icl_login_csg == ISCSI_FULL_FEATURE_PHASE) {
			lh->tsid = htons(ict->ict_sess->ist_tsih);
		}
	} else {
		login_resp->isp_data = 0;
		login_resp->isp_datalen = 0;
	}
	return (login_resp);
}

static kv_status_t
iscsit_handle_key(iscsit_conn_t *ict, nvpair_t *nvp, char *nvp_name)
{
	iscsit_conn_login_t	*lsm = &ict->ict_login_sm;
	kv_status_t		kvrc;
	const idm_kv_xlate_t	*ikvx;

	ikvx = idm_lookup_kv_xlate(nvp_name, strlen(nvp_name));
	if (ikvx->ik_key_id == KI_MAX_KEY) {
		/*
		 * Any key not understood by the acceptor may be igonred
		 * by the acceptor without affecting the basic function.
		 * However, the answer for a key not understood MUST be
		 * key=NotUnderstood.
		 */
		kvrc = iscsit_reply_string(ict, nvp_name,
		    ISCSI_TEXT_NOTUNDERSTOOD);
	} else {
		kvrc = iscsit_handle_common_key(ict, nvp, ikvx);
		if (kvrc == KV_UNHANDLED) {
			switch (lsm->icl_login_csg) {
			case ISCSI_SECURITY_NEGOTIATION_STAGE:
				kvrc = iscsit_handle_security_key(
				    ict, nvp, ikvx);
				break;
			case ISCSI_OP_PARMS_NEGOTIATION_STAGE:
				kvrc = iscsit_handle_operational_key(
				    ict, nvp, ikvx);
				break;
			case ISCSI_FULL_FEATURE_PHASE:
			default:
				/* What are we doing here? */
				ASSERT(0);
				kvrc = KV_UNHANDLED;
			}
		}
	}

	return (kvrc);
}

static kv_status_t
iscsit_handle_common_key(iscsit_conn_t *ict, nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx)
{
	iscsit_conn_login_t	*lsm = &ict->ict_login_sm;
	kv_status_t		kvrc;
	char			*string_val;
	int			nvrc;

	switch (ikvx->ik_key_id) {
	case KI_INITIATOR_NAME:
	case KI_INITIATOR_ALIAS:
		nvrc = nvlist_add_nvpair(lsm->icl_negotiated_values, nvp);
		kvrc = idm_nvstat_to_kvstat(nvrc);
		break;
	case KI_TARGET_NAME:
		/* We'll validate the target during login_sm_session_bind() */
		nvrc = nvpair_value_string(nvp, &string_val);
		ASSERT(nvrc == 0); /* We built this nvlist */

		nvrc = nvlist_add_nvpair(lsm->icl_negotiated_values, nvp);
		kvrc = idm_nvstat_to_kvstat(nvrc);
		break;
	case KI_TARGET_ALIAS:
	case KI_TARGET_ADDRESS:
	case KI_TARGET_PORTAL_GROUP_TAG:
		kvrc = KV_TARGET_ONLY; /* Only the target can declare this */
		break;
	case KI_SESSION_TYPE:
		/*
		 * If we don't receive this key on the initial login
		 * we assume this is a normal session.
		 */
		nvrc = nvlist_add_nvpair(lsm->icl_negotiated_values, nvp);
		kvrc = idm_nvstat_to_kvstat(nvrc);
		nvrc = nvpair_value_string(nvp, &string_val);
		ASSERT(nvrc == 0); /* We built this nvlist */
		ict->ict_op.op_discovery_session =
		    strcmp(string_val, "Discovery") == 0 ? B_TRUE : B_FALSE;
		break;
	default:
		/*
		 * This is not really an error but we should
		 * leave this nvpair on the list since we
		 * didn't do anything with it.  Either
		 * the security or operational phase
		 * handling functions should process it.
		 */
		kvrc = KV_UNHANDLED;
		break;
	}

	return (kvrc);
}

static kv_status_t
iscsit_handle_security_key(iscsit_conn_t *ict, nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx)
{
	iscsit_conn_login_t	*lsm = &ict->ict_login_sm;
	iscsit_auth_client_t	*client = &lsm->icl_auth_client;
	iscsikey_id_t		kv_id;
	kv_status_t		kvrc;
	iscsit_auth_handler_t	handler;

	/*
	 * After all of security keys are handled, this function will
	 * be called again to verify current authentication status
	 * and perform some actual authentication work. At this time,
	 * the nvp and ikvx will be passed in as NULLs.
	 */
	if (ikvx != NULL) {
		kv_id = ikvx->ik_key_id;
	} else {
		kv_id = 0;
	}

	handler = iscsit_auth_get_handler(client, kv_id);
	if (handler) {
		kvrc = handler(ict, nvp, ikvx);
	} else {
		kvrc = KV_UNHANDLED; /* invalid request */
	}

	return (kvrc);
}

static kv_status_t
iscsit_reply_security_key(iscsit_conn_t *ict)
{
	return (iscsit_handle_security_key(ict, NULL, NULL));
}

static kv_status_t
iscsit_handle_operational_key(iscsit_conn_t *ict, nvpair_t *nvp,
    const idm_kv_xlate_t *ikvx)
{
	kv_status_t		kvrc = KV_UNHANDLED;
	boolean_t		bool_val;
	uint64_t		num_val;
	int			nvrc;

	/*
	 * Retrieve values.  All value lookups are expected to succeed
	 * since we build the nvlist while decoding the text buffer.  This
	 * step is intended to eliminate some duplication of code (for example
	 * we only need to code the numerical value lookup once).  We will
	 * handle the values (if necessary) below.
	 */
	switch (ikvx->ik_key_id) {
		/* Lists */
	case KI_HEADER_DIGEST:
	case KI_DATA_DIGEST:
		break;
		/* Booleans */
	case KI_INITIAL_R2T:
	case KI_IMMEDIATE_DATA:
	case KI_DATA_PDU_IN_ORDER:
	case KI_DATA_SEQUENCE_IN_ORDER:
	case KI_IFMARKER:
	case KI_OFMARKER:
		nvrc = nvpair_value_boolean_value(nvp, &bool_val);
		ASSERT(nvrc == 0); /* We built this nvlist */
		break;
		/* Numericals */
	case KI_MAX_CONNECTIONS:
	case KI_MAX_RECV_DATA_SEGMENT_LENGTH:
	case KI_MAX_BURST_LENGTH:
	case KI_FIRST_BURST_LENGTH:
	case KI_DEFAULT_TIME_2_WAIT:
	case KI_DEFAULT_TIME_2_RETAIN:
	case KI_MAX_OUTSTANDING_R2T:
	case KI_ERROR_RECOVERY_LEVEL:
		nvrc = nvpair_value_uint64(nvp, &num_val);
		ASSERT(nvrc == 0);
		break;
		/* Ranges */
	case KI_OFMARKERINT:
	case KI_IFMARKERINT:
		break;
	default:
		break;
	}

	/*
	 * Now handle the values according to the key name.  Sometimes we
	 * don't care what the value is -- in that case we just add the nvpair
	 * to the negotiated values list.
	 */
	switch (ikvx->ik_key_id) {
	case KI_HEADER_DIGEST:
		kvrc = iscsit_handle_digest(ict, nvp, ikvx);
		break;
	case KI_DATA_DIGEST:
		kvrc = iscsit_handle_digest(ict, nvp, ikvx);
		break;
	case KI_INITIAL_R2T:
		/* We *require* INITIAL_R2T=yes */
		kvrc = iscsit_handle_boolean(ict, nvp, bool_val, ikvx,
		    B_TRUE);
		break;
	case KI_IMMEDIATE_DATA:
		kvrc = iscsit_handle_boolean(ict, nvp, bool_val, ikvx,
		    bool_val);
		break;
	case KI_DATA_PDU_IN_ORDER:
		kvrc = iscsit_handle_boolean(ict, nvp, bool_val, ikvx,
		    B_TRUE);
		break;
	case KI_DATA_SEQUENCE_IN_ORDER:
		/* We allow any value for DATA_SEQUENCE_IN_ORDER */
		kvrc = iscsit_handle_boolean(ict, nvp, bool_val, ikvx,
		    bool_val);
		break;
	case KI_OFMARKER:
	case KI_IFMARKER:
		/* We don't support markers */
		kvrc = iscsit_handle_boolean(ict, nvp, bool_val, ikvx,
		    B_FALSE);
		break;
	case KI_MAX_CONNECTIONS:
		kvrc = iscsit_handle_numerical(ict, nvp, num_val, ikvx,
		    ISCSI_MIN_CONNECTIONS,
		    ISCSI_MAX_CONNECTIONS,
		    ISCSIT_MAX_CONNECTIONS);
		break;
		/* this is a declartive param */
	case KI_MAX_RECV_DATA_SEGMENT_LENGTH:
		kvrc = iscsit_handle_numerical(ict, nvp, num_val, ikvx,
		    ISCSI_MIN_RECV_DATA_SEGMENT_LENGTH,
		    ISCSI_MAX_RECV_DATA_SEGMENT_LENGTH,
		    ISCSI_MAX_RECV_DATA_SEGMENT_LENGTH);
		break;
	case KI_MAX_BURST_LENGTH:
		kvrc = iscsit_handle_numerical(ict, nvp, num_val, ikvx,
		    ISCSI_MIN_MAX_BURST_LENGTH,
		    ISCSI_MAX_BURST_LENGTH,
		    ISCSIT_MAX_BURST_LENGTH);
		break;
	case KI_FIRST_BURST_LENGTH:
		kvrc = iscsit_handle_numerical(ict, nvp, num_val, ikvx,
		    ISCSI_MIN_FIRST_BURST_LENGTH,
		    ISCSI_MAX_FIRST_BURST_LENGTH,
		    ISCSIT_MAX_FIRST_BURST_LENGTH);
		break;
	case KI_DEFAULT_TIME_2_WAIT:
		kvrc = iscsit_handle_numerical(ict, nvp, num_val, ikvx,
		    ISCSI_MIN_TIME2WAIT,
		    ISCSI_MAX_TIME2WAIT,
		    ISCSIT_MAX_TIME2WAIT);
		break;
	case KI_DEFAULT_TIME_2_RETAIN:
		kvrc = iscsit_handle_numerical(ict, nvp, num_val, ikvx,
		    ISCSI_MIN_TIME2RETAIN,
		    ISCSI_MAX_TIME2RETAIN,
		    ISCSIT_MAX_TIME2RETAIN);
		break;
	case KI_MAX_OUTSTANDING_R2T:
		kvrc = iscsit_handle_numerical(ict, nvp, num_val, ikvx,
		    ISCSI_MIN_MAX_OUTSTANDING_R2T,
		    ISCSI_MAX_OUTSTANDING_R2T,
		    ISCSIT_MAX_OUTSTANDING_R2T);
		break;
	case KI_ERROR_RECOVERY_LEVEL:
		kvrc = iscsit_handle_numerical(ict, nvp, num_val, ikvx,
		    ISCSI_MIN_ERROR_RECOVERY_LEVEL,
		    ISCSI_MAX_ERROR_RECOVERY_LEVEL,
		    ISCSIT_MAX_ERROR_RECOVERY_LEVEL);
		break;
	case KI_OFMARKERINT:
	case KI_IFMARKERINT:
		kvrc = iscsit_reply_string(ict, ikvx->ik_key_name,
		    ISCSI_TEXT_IRRELEVANT);
		break;
	default:
		kvrc = KV_UNHANDLED; /* invalid request */
		break;
	}

	return (kvrc);
}

static kv_status_t
iscsit_reply_numerical(iscsit_conn_t *ict,
    const char *nvp_name, const uint64_t value)
{
	iscsit_conn_login_t	*lsm = &ict->ict_login_sm;
	kv_status_t		kvrc;
	int			nvrc;

	nvrc = nvlist_add_uint64(lsm->icl_response_nvlist,
	    nvp_name, value);
	kvrc = idm_nvstat_to_kvstat(nvrc);

	return (kvrc);
}

static kv_status_t
iscsit_reply_string(iscsit_conn_t *ict,
    const char *nvp_name, const char *text)
{
	iscsit_conn_login_t	*lsm = &ict->ict_login_sm;
	kv_status_t		kvrc;
	int			nvrc;

	nvrc = nvlist_add_string(lsm->icl_response_nvlist,
	    nvp_name, text);
	kvrc = idm_nvstat_to_kvstat(nvrc);

	return (kvrc);
}

static kv_status_t
iscsit_handle_digest(iscsit_conn_t *ict, nvpair_t *choices,
    const idm_kv_xlate_t *ikvx)
{
	iscsit_conn_login_t	*lsm = &ict->ict_login_sm;
	kv_status_t		kvrc = KV_VALUE_ERROR;
	int			nvrc;
	nvpair_t		*digest_choice;
	char			*digest_choice_string;

	/*
	 * Need to add persistent config here if we want users to allow
	 * disabling of digests on the target side.  You could argue that
	 * this makes things too complicated... just let the initiator state
	 * what it wants and we'll take it.  For now that's exactly what
	 * we'll do.
	 *
	 * Basic digest negotiation happens here at iSCSI level.   IDM
	 * can override this during negotiate_key_values phase to
	 * decline to set up any digest processing.
	 */
	digest_choice = idm_get_next_listvalue(choices, NULL);

	/*
	 * Loop through all choices.  As soon as we find a choice
	 * that we support add the value to our negotiated values list
	 * and respond with that value in the login response.
	 */
	while (digest_choice != NULL) {
		nvrc = nvpair_value_string(digest_choice,
		    &digest_choice_string);
		ASSERT(nvrc == 0);

		if ((strcasecmp(digest_choice_string, "crc32c") == 0) ||
		    (strcasecmp(digest_choice_string, "none") == 0)) {
			/* Add to negotiated values list */
			nvrc = nvlist_add_string(lsm->icl_negotiated_values,
			    ikvx->ik_key_name, digest_choice_string);
			kvrc = idm_nvstat_to_kvstat(nvrc);
			if (nvrc == 0) {
				/* Add to login response list */
				nvrc = nvlist_add_string(
				    lsm->icl_response_nvlist,
				    ikvx->ik_key_name, digest_choice_string);
				kvrc = idm_nvstat_to_kvstat(nvrc);
			}
			break;
		}
		digest_choice = idm_get_next_listvalue(choices,
		    digest_choice);
	}

	if (digest_choice == NULL)
		kvrc = KV_VALUE_ERROR;

	return (kvrc);
}

static kv_status_t
iscsit_handle_boolean(iscsit_conn_t *ict, nvpair_t *nvp, boolean_t value,
    const idm_kv_xlate_t *ikvx, boolean_t iscsit_value)
{
	iscsit_conn_login_t	*lsm = &ict->ict_login_sm;
	kv_status_t		kvrc;
	int			nvrc;

	if (ikvx->ik_declarative) {
		nvrc = nvlist_add_nvpair(lsm->icl_negotiated_values, nvp);
	} else {
		if (value != iscsit_value) {
			/* Respond back to initiator with our value */
			value = iscsit_value;
			nvrc = nvlist_add_boolean_value(
			    lsm->icl_negotiated_values,
			    ikvx->ik_key_name, value);
			lsm->icl_login_transit = B_FALSE;
		} else {
			/* Add this to our negotiated values */
			nvrc = nvlist_add_nvpair(lsm->icl_negotiated_values,
			    nvp);
		}

		/* Response of Simple-value Negotiation */
		if (nvrc == 0) {
			nvrc = nvlist_add_boolean_value(
			    lsm->icl_response_nvlist, ikvx->ik_key_name, value);
		}
	}

	kvrc = idm_nvstat_to_kvstat(nvrc);

	return (kvrc);
}

static kv_status_t
iscsit_handle_numerical(iscsit_conn_t *ict, nvpair_t *nvp, uint64_t value,
    const idm_kv_xlate_t *ikvx,
    uint64_t iscsi_min_value, uint64_t iscsi_max_value,
    uint64_t iscsit_max_value)
{
	iscsit_conn_login_t	*lsm = &ict->ict_login_sm;
	kv_status_t		kvrc;
	int			nvrc;

	/* Validate against standard */
	if ((value < iscsi_min_value) || (value > iscsi_max_value)) {
		kvrc = KV_VALUE_ERROR;
	} else if (ikvx->ik_declarative) {
		nvrc = nvlist_add_nvpair(lsm->icl_negotiated_values, nvp);
		kvrc = idm_nvstat_to_kvstat(nvrc);
	} else {
		if (value > iscsit_max_value) {
			/* Respond back to initiator with our value */
			value = iscsit_max_value;
			nvrc = nvlist_add_uint64(lsm->icl_negotiated_values,
			    ikvx->ik_key_name, value);
			lsm->icl_login_transit = B_FALSE;
		} else {
			/* Add this to our negotiated values */
			nvrc = nvlist_add_nvpair(lsm->icl_negotiated_values,
			    nvp);
		}

		/* Response of Simple-value Negotiation */
		if (nvrc == 0) {
			nvrc = nvlist_add_uint64(lsm->icl_response_nvlist,
			    ikvx->ik_key_name, value);
		}
		kvrc = idm_nvstat_to_kvstat(nvrc);
	}

	return (kvrc);
}


static void
iscsit_process_negotiated_values(iscsit_conn_t *ict)
{
	iscsit_conn_login_t	*lsm = &ict->ict_login_sm;
	char			*string_val;
	boolean_t		boolean_val;
	uint64_t		uint64_val;
	int			nvrc;

	/* Let the IDM level activate its parameters first */
	idm_notice_key_values(ict->ict_ic, lsm->icl_negotiated_values);

	/*
	 * Initiator alias and target alias
	 */
	if ((nvrc = nvlist_lookup_string(lsm->icl_negotiated_values,
	    "InitiatorAlias", &string_val)) != ENOENT) {
		ASSERT(nvrc == 0);
		ict->ict_sess->ist_initiator_alias =
		    kmem_alloc(strlen(string_val) + 1, KM_SLEEP);
		(void) strcpy(ict->ict_sess->ist_initiator_alias, string_val);
		if (ict->ict_sess->ist_stmf_sess)
			ict->ict_sess->ist_stmf_sess->ss_rport_alias =
			    strdup(string_val);
	}

	if ((nvrc = nvlist_lookup_string(lsm->icl_negotiated_values,
	    "TargetAlias", &string_val)) != ENOENT) {
		ASSERT(nvrc == 0);
		ict->ict_sess->ist_target_alias =
		    kmem_alloc(strlen(string_val) + 1, KM_SLEEP);
		(void) strcpy(ict->ict_sess->ist_target_alias, string_val);
	}

	/*
	 * Operational parameters.  We process SessionType when it is
	 * initially received since it is required on the initial login.
	 */
	if ((nvrc = nvlist_lookup_boolean_value(lsm->icl_negotiated_values,
	    "InitialR2T", &boolean_val)) != ENOENT) {
		ASSERT(nvrc == 0);
		ict->ict_op.op_initial_r2t = boolean_val;
	}

	if ((nvrc = nvlist_lookup_boolean_value(lsm->icl_negotiated_values,
	    "ImmediateData", &boolean_val)) != ENOENT) {
		ASSERT(nvrc == 0);
		ict->ict_op.op_immed_data = boolean_val;
	}

	if ((nvrc = nvlist_lookup_boolean_value(lsm->icl_negotiated_values,
	    "DataPDUInOrder", &boolean_val)) != ENOENT) {
		ASSERT(nvrc == 0);
		ict->ict_op.op_data_pdu_in_order = boolean_val;
	}

	if ((nvrc = nvlist_lookup_boolean_value(lsm->icl_negotiated_values,
	    "DataSequenceInOrder", &boolean_val)) != ENOENT) {
		ASSERT(nvrc == 0);
		ict->ict_op.op_data_sequence_in_order = boolean_val;
	}

	if ((nvrc = nvlist_lookup_uint64(lsm->icl_negotiated_values,
	    "MaxConnections", &uint64_val)) != ENOENT) {
		ASSERT(nvrc == 0);
		ict->ict_op.op_max_connections = uint64_val;
	}

	if ((nvrc = nvlist_lookup_uint64(lsm->icl_negotiated_values,
	    "MaxRecvDataSegmentLength", &uint64_val)) != ENOENT) {
		ASSERT(nvrc == 0);
		ict->ict_op.op_max_recv_data_segment_length = uint64_val;
	}

	if ((nvrc = nvlist_lookup_uint64(lsm->icl_negotiated_values,
	    "MaxBurstLength", &uint64_val)) != ENOENT) {
		ASSERT(nvrc == 0);
		ict->ict_op.op_max_burst_length = uint64_val;
	}

	if ((nvrc = nvlist_lookup_uint64(lsm->icl_negotiated_values,
	    "FirstBurstLength", &uint64_val)) != ENOENT) {
		ASSERT(nvrc == 0);
		ict->ict_op.op_first_burst_length = uint64_val;
	}

	if ((nvrc = nvlist_lookup_uint64(lsm->icl_negotiated_values,
	    "DefaultTime2Wait", &uint64_val)) != ENOENT) {
		ASSERT(nvrc == 0);
		ict->ict_op.op_default_time_2_wait = uint64_val;
	}

	if ((nvrc = nvlist_lookup_uint64(lsm->icl_negotiated_values,
	    "DefaultTime2Retain", &uint64_val)) != ENOENT) {
		ASSERT(nvrc == 0);
		ict->ict_op.op_default_time_2_retain = uint64_val;
	}

	if ((nvrc = nvlist_lookup_uint64(lsm->icl_negotiated_values,
	    "MaxOutstandingR2T", &uint64_val)) != ENOENT) {
		ASSERT(nvrc == 0);
		ict->ict_op.op_max_outstanding_r2t = uint64_val;
	}

	if ((nvrc = nvlist_lookup_uint64(lsm->icl_negotiated_values,
	    "ErrorRecoveryLevel", &uint64_val)) != ENOENT) {
		ASSERT(nvrc == 0);
		ict->ict_op.op_error_recovery_level = uint64_val;
	}
}

static idm_status_t
iscsit_add_declarative_keys(iscsit_conn_t *ict)
{
	nvlist_t		*cfg_nv = NULL;
	kv_status_t		kvrc;
	int			nvrc;
	iscsit_conn_login_t	*lsm = &ict->ict_login_sm;
	uint8_t			error_class;
	uint8_t			error_detail;
	idm_status_t		idm_status;

	if ((nvrc = nvlist_alloc(&cfg_nv, NV_UNIQUE_NAME, KM_NOSLEEP)) != 0) {
		kvrc = idm_nvstat_to_kvstat(nvrc);
		goto alloc_fail;
	}
	if ((nvrc = nvlist_add_uint64(cfg_nv, "MaxRecvDataSegmentLength",
	    max_dataseglen_target)) != 0) {
		kvrc = idm_nvstat_to_kvstat(nvrc);
		goto done;
	}

	kvrc = idm_declare_key_values(ict->ict_ic, cfg_nv,
	    lsm->icl_response_nvlist);
done:
	nvlist_free(cfg_nv);
alloc_fail:
	idm_kvstat_to_error(kvrc, &error_class, &error_detail);
	if (error_class == ISCSI_STATUS_CLASS_SUCCESS) {
		idm_status = IDM_STATUS_SUCCESS;
	} else {
		SET_LOGIN_ERROR(ict, error_class, error_detail);
		idm_status = IDM_STATUS_FAIL;
	}
	return (idm_status);
}
