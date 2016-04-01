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
 * Copyright (c) 2013 by Delphix. All rights reserved.
 * Copyright 2015 Nexenta Systems, Inc.  All rights reserved.
 */

#include <sys/cpuvar.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/socket.h>
#include <sys/strsubr.h>
#include <sys/note.h>
#include <sys/sdt.h>

#define	IDM_CONN_SM_STRINGS
#define	IDM_CN_NOTIFY_STRINGS
#include <sys/idm/idm.h>

boolean_t	idm_sm_logging = B_FALSE;

extern idm_global_t	idm; /* Global state */

static void
idm_conn_event_handler(void *event_ctx_opaque);

static void
idm_state_s1_free(idm_conn_t *ic, idm_conn_event_ctx_t *event_ctx);

static void
idm_state_s2_xpt_wait(idm_conn_t *ic, idm_conn_event_ctx_t *event_ctx);

static void
idm_state_s3_xpt_up(idm_conn_t *ic, idm_conn_event_ctx_t *event_ctx);

static void
idm_state_s4_in_login(idm_conn_t *ic, idm_conn_event_ctx_t *event_ctx);

static void
idm_state_s5_logged_in(idm_conn_t *ic, idm_conn_event_ctx_t *event_ctx);

static void
idm_state_s6_in_logout(idm_conn_t *ic, idm_conn_event_ctx_t *event_ctx);

static void
idm_logout_req_timeout(void *arg);

static void
idm_state_s7_logout_req(idm_conn_t *ic, idm_conn_event_ctx_t *event_ctx);

static void
idm_state_s8_cleanup(idm_conn_t *ic, idm_conn_event_ctx_t *event_ctx);

static void
idm_state_s9_init_error(idm_conn_t *ic, idm_conn_event_ctx_t *event_ctx);

static void
idm_state_s9a_rejected(idm_conn_t *ic, idm_conn_event_ctx_t *event_ctx);

static void
idm_state_s9b_wait_snd_done_cb(idm_pdu_t *pdu,
    idm_status_t status);

static void
idm_state_s9b_wait_snd_done(idm_conn_t *ic,
    idm_conn_event_ctx_t *event_ctx);

static void
idm_state_s10_in_cleanup(idm_conn_t *ic, idm_conn_event_ctx_t *event_ctx);

static void
idm_state_s11_complete(idm_conn_t *ic, idm_conn_event_ctx_t *event_ctx);

static void
idm_state_s12_enable_dm(idm_conn_t *ic, idm_conn_event_ctx_t *event_ctx);

static void
idm_update_state(idm_conn_t *ic, idm_conn_state_t new_state,
    idm_conn_event_ctx_t *event_ctx);

static void
idm_conn_unref(void *ic_void);

static void
idm_conn_reject_unref(void *ic_void);

static idm_pdu_event_action_t
idm_conn_sm_validate_pdu(idm_conn_t *ic, idm_conn_event_ctx_t *event_ctx,
    idm_pdu_t *pdu);

static idm_status_t
idm_ffp_enable(idm_conn_t *ic);

static void
idm_ffp_disable(idm_conn_t *ic, idm_ffp_disable_t disable_type);

static void
idm_initial_login_actions(idm_conn_t *ic, idm_conn_event_ctx_t *event_ctx);

static void
idm_login_success_actions(idm_conn_t *ic, idm_conn_event_ctx_t *event_ctx);

idm_status_t
idm_conn_sm_init(idm_conn_t *ic)
{
	char taskq_name[32];

	/*
	 * Caller should have assigned a unique connection ID.  Use this
	 * connection ID to create a unique connection name string
	 */
	ASSERT(ic->ic_internal_cid != 0);
	(void) snprintf(taskq_name, sizeof (taskq_name) - 1, "conn_sm%08x",
	    ic->ic_internal_cid);

	ic->ic_state_taskq = taskq_create(taskq_name, 1, minclsyspri, 4, 16384,
	    TASKQ_PREPOPULATE);
	if (ic->ic_state_taskq == NULL) {
		return (IDM_STATUS_FAIL);
	}

	idm_sm_audit_init(&ic->ic_state_audit);
	mutex_init(&ic->ic_state_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&ic->ic_state_cv, NULL, CV_DEFAULT, NULL);

	ic->ic_state = CS_S1_FREE;
	ic->ic_last_state = CS_S1_FREE;

	return (IDM_STATUS_SUCCESS);
}

void
idm_conn_sm_fini(idm_conn_t *ic)
{

	/*
	 * The connection may only be partially created. If there
	 * is no taskq, then the connection SM was not initialized.
	 */
	if (ic->ic_state_taskq == NULL) {
		return;
	}

	taskq_destroy(ic->ic_state_taskq);

	cv_destroy(&ic->ic_state_cv);
	/*
	 * The thread that generated the event that got us here may still
	 * hold the ic_state_mutex. Once it is released we can safely
	 * destroy it since there is no way to locate the object now.
	 */
	mutex_enter(&ic->ic_state_mutex);
	IDM_SM_TIMER_CLEAR(ic);
	mutex_destroy(&ic->ic_state_mutex);
}

void
idm_conn_event(idm_conn_t *ic, idm_conn_event_t event, uintptr_t event_info)
{
	mutex_enter(&ic->ic_state_mutex);
	idm_conn_event_locked(ic, event, event_info, CT_NONE);
	mutex_exit(&ic->ic_state_mutex);
}


idm_status_t
idm_conn_reinstate_event(idm_conn_t *old_ic, idm_conn_t *new_ic)
{
	int result;

	mutex_enter(&old_ic->ic_state_mutex);
	if (((old_ic->ic_conn_type == CONN_TYPE_INI) &&
	    (old_ic->ic_state != CS_S8_CLEANUP)) ||
	    ((old_ic->ic_conn_type == CONN_TYPE_TGT) &&
	    (old_ic->ic_state < CS_S5_LOGGED_IN))) {
		result = IDM_STATUS_FAIL;
	} else {
		result = IDM_STATUS_SUCCESS;
		new_ic->ic_reinstate_conn = old_ic;
		idm_conn_event_locked(new_ic->ic_reinstate_conn,
		    CE_CONN_REINSTATE, (uintptr_t)new_ic, CT_NONE);
	}
	mutex_exit(&old_ic->ic_state_mutex);

	return (result);
}

void
idm_conn_tx_pdu_event(idm_conn_t *ic, idm_conn_event_t event,
    uintptr_t event_info)
{
	ASSERT(mutex_owned(&ic->ic_state_mutex));
	ic->ic_pdu_events++;
	idm_conn_event_locked(ic, event, event_info, CT_TX_PDU);
}

void
idm_conn_rx_pdu_event(idm_conn_t *ic, idm_conn_event_t event,
    uintptr_t event_info)
{
	ASSERT(mutex_owned(&ic->ic_state_mutex));
	ic->ic_pdu_events++;
	idm_conn_event_locked(ic, event, event_info, CT_RX_PDU);
}

void
idm_conn_event_locked(idm_conn_t *ic, idm_conn_event_t event,
    uintptr_t event_info, idm_pdu_event_type_t pdu_event_type)
{
	idm_conn_event_ctx_t	*event_ctx;

	ASSERT(mutex_owned(&ic->ic_state_mutex));

	idm_sm_audit_event(&ic->ic_state_audit, SAS_IDM_CONN,
	    (int)ic->ic_state, (int)event, event_info);

	/*
	 * It's very difficult to prevent a few straggling events
	 * at the end.  For example idm_sorx_thread will generate
	 * a CE_TRANSPORT_FAIL event when it exits.  Rather than
	 * push complicated restrictions all over the code to
	 * prevent this we will simply drop the events (and in
	 * the case of PDU events release them appropriately)
	 * since they are irrelevant once we are in a terminal state.
	 * Of course those threads need to have appropriate holds on
	 * the connection otherwise it might disappear.
	 */
	if ((ic->ic_state == CS_S9_INIT_ERROR) ||
	    (ic->ic_state == CS_S9A_REJECTED) ||
	    (ic->ic_state == CS_S11_COMPLETE)) {
		if ((pdu_event_type == CT_TX_PDU) ||
		    (pdu_event_type == CT_RX_PDU)) {
			ic->ic_pdu_events--;
			idm_pdu_complete((idm_pdu_t *)event_info,
			    IDM_STATUS_SUCCESS);
		}
		IDM_SM_LOG(CE_NOTE, "*** Dropping event %s (%d) because of"
		    "state %s (%d)",
		    idm_ce_name[event], event,
		    idm_cs_name[ic->ic_state], ic->ic_state);
		return;
	}

	/*
	 * Normal event handling
	 */
	idm_conn_hold(ic);

	event_ctx = kmem_zalloc(sizeof (*event_ctx), KM_SLEEP);
	event_ctx->iec_ic = ic;
	event_ctx->iec_event = event;
	event_ctx->iec_info = event_info;
	event_ctx->iec_pdu_event_type = pdu_event_type;

	(void) taskq_dispatch(ic->ic_state_taskq, &idm_conn_event_handler,
	    event_ctx, TQ_SLEEP);
}

static void
idm_conn_event_handler(void *event_ctx_opaque)
{
	idm_conn_event_ctx_t *event_ctx = event_ctx_opaque;
	idm_conn_t *ic = event_ctx->iec_ic;
	idm_pdu_t *pdu = (idm_pdu_t *)event_ctx->iec_info;
	idm_pdu_event_action_t action;

	IDM_SM_LOG(CE_NOTE, "idm_conn_event_handler: conn %p event %s(%d)",
	    (void *)ic, idm_ce_name[event_ctx->iec_event],
	    event_ctx->iec_event);
	DTRACE_PROBE2(conn__event,
	    idm_conn_t *, ic, idm_conn_event_ctx_t *, event_ctx);

	/*
	 * Validate event
	 */
	ASSERT(event_ctx->iec_event != CE_UNDEFINED);
	ASSERT3U(event_ctx->iec_event, <, CE_MAX_EVENT);

	/*
	 * Validate current state
	 */
	ASSERT(ic->ic_state != CS_S0_UNDEFINED);
	ASSERT3U(ic->ic_state, <, CS_MAX_STATE);

	/*
	 * Validate PDU-related events against the current state.  If a PDU
	 * is not allowed in the current state we change the event to a
	 * protocol error.  This simplifies the state-specific event handlers.
	 * For example the CS_S2_XPT_WAIT state only needs to handle the
	 * CE_TX_PROTOCOL_ERROR and CE_RX_PROTOCOL_ERROR events since
	 * no PDU's can be transmitted or received in that state.
	 */
	event_ctx->iec_pdu_forwarded = B_FALSE;
	if (event_ctx->iec_pdu_event_type != CT_NONE) {
		ASSERT(pdu != NULL);
		action = idm_conn_sm_validate_pdu(ic, event_ctx, pdu);

		switch (action) {
		case CA_TX_PROTOCOL_ERROR:
			/*
			 * Change event and forward the PDU
			 */
			event_ctx->iec_event = CE_TX_PROTOCOL_ERROR;
			break;
		case CA_RX_PROTOCOL_ERROR:
			/*
			 * Change event and forward the PDU.
			 */
			event_ctx->iec_event = CE_RX_PROTOCOL_ERROR;
			break;
		case CA_FORWARD:
			/*
			 * Let the state-specific event handlers take
			 * care of it.
			 */
			break;
		case CA_DROP:
			/*
			 * It never even happened
			 */
			IDM_SM_LOG(CE_NOTE, "*** drop PDU %p", (void *) pdu);
			idm_pdu_complete(pdu, IDM_STATUS_FAIL);
			break;
		default:
			ASSERT(0);
			break;
		}
	}

	switch (ic->ic_state) {
	case CS_S1_FREE:
		idm_state_s1_free(ic, event_ctx);
		break;
	case CS_S2_XPT_WAIT:
		idm_state_s2_xpt_wait(ic, event_ctx);
		break;
	case CS_S3_XPT_UP:
		idm_state_s3_xpt_up(ic, event_ctx);
		break;
	case CS_S4_IN_LOGIN:
		idm_state_s4_in_login(ic, event_ctx);
		break;
	case CS_S5_LOGGED_IN:
		idm_state_s5_logged_in(ic, event_ctx);
		break;
	case CS_S6_IN_LOGOUT:
		idm_state_s6_in_logout(ic, event_ctx);
		break;
	case CS_S7_LOGOUT_REQ:
		idm_state_s7_logout_req(ic, event_ctx);
		break;
	case CS_S8_CLEANUP:
		idm_state_s8_cleanup(ic, event_ctx);
		break;
	case CS_S9A_REJECTED:
		idm_state_s9a_rejected(ic, event_ctx);
		break;
	case CS_S9B_WAIT_SND_DONE:
		idm_state_s9b_wait_snd_done(ic, event_ctx);
		break;
	case CS_S9_INIT_ERROR:
		idm_state_s9_init_error(ic, event_ctx);
		break;
	case CS_S10_IN_CLEANUP:
		idm_state_s10_in_cleanup(ic, event_ctx);
		break;
	case CS_S11_COMPLETE:
		idm_state_s11_complete(ic, event_ctx);
		break;
	case CS_S12_ENABLE_DM:
		idm_state_s12_enable_dm(ic, event_ctx);
		break;
	default:
		ASSERT(0);
		break;
	}

	/*
	 * Now that we've updated the state machine, if this was
	 * a PDU-related event take the appropriate action on the PDU
	 * (transmit it, forward it to the clients RX callback, drop
	 * it, etc).
	 */
	if (event_ctx->iec_pdu_event_type != CT_NONE) {
		switch (action) {
		case CA_TX_PROTOCOL_ERROR:
			idm_pdu_tx_protocol_error(ic, pdu);
			break;
		case CA_RX_PROTOCOL_ERROR:
			idm_pdu_rx_protocol_error(ic, pdu);
			break;
		case CA_FORWARD:
			if (!event_ctx->iec_pdu_forwarded) {
				if (event_ctx->iec_pdu_event_type ==
				    CT_RX_PDU) {
					idm_pdu_rx_forward(ic, pdu);
				} else {
					idm_pdu_tx_forward(ic, pdu);
				}
			}
			break;
		default:
			ASSERT(0);
			break;
		}
	}

	/*
	 * Update outstanding PDU event count (see idm_pdu_tx for
	 * how this is used)
	 */
	if ((event_ctx->iec_pdu_event_type == CT_TX_PDU) ||
	    (event_ctx->iec_pdu_event_type == CT_RX_PDU)) {
		mutex_enter(&ic->ic_state_mutex);
		ic->ic_pdu_events--;
		mutex_exit(&ic->ic_state_mutex);
	}

	idm_conn_rele(ic);
	kmem_free(event_ctx, sizeof (*event_ctx));
}

static void
idm_state_s1_free(idm_conn_t *ic, idm_conn_event_ctx_t *event_ctx)
{
	switch (event_ctx->iec_event) {
	case CE_CONNECT_REQ:
		/* T1 */
		idm_update_state(ic, CS_S2_XPT_WAIT, event_ctx);
		break;
	case CE_CONNECT_ACCEPT:
		/* T3 */
		idm_update_state(ic, CS_S3_XPT_UP, event_ctx);
		break;
	case CE_TX_PROTOCOL_ERROR:
	case CE_RX_PROTOCOL_ERROR:
		/* This should never happen */
		idm_update_state(ic, CS_S9_INIT_ERROR, event_ctx);
		break;
	default:
		ASSERT(0);
		/*NOTREACHED*/
	}
}


static void
idm_state_s2_xpt_wait(idm_conn_t *ic, idm_conn_event_ctx_t *event_ctx)
{
	switch (event_ctx->iec_event) {
	case CE_CONNECT_SUCCESS:
		/* T4 */
		idm_update_state(ic, CS_S4_IN_LOGIN, event_ctx);
		break;
	case CE_TRANSPORT_FAIL:
	case CE_CONNECT_FAIL:
	case CE_LOGOUT_OTHER_CONN_RCV:
	case CE_TX_PROTOCOL_ERROR:
	case CE_RX_PROTOCOL_ERROR:
		/* T2 */
		idm_update_state(ic, CS_S9_INIT_ERROR, event_ctx);
		break;
	default:
		ASSERT(0);
		/*NOTREACHED*/
	}
}


static void
idm_login_timeout(void *arg)
{
	idm_conn_t *ic = arg;

	ic->ic_state_timeout = 0;
	idm_conn_event(ic, CE_LOGIN_TIMEOUT, NULL);
}

static void
idm_state_s3_xpt_up(idm_conn_t *ic, idm_conn_event_ctx_t *event_ctx)
{
	switch (event_ctx->iec_event) {
	case CE_LOGIN_RCV:
		/* T4 */
		/* Keep login timeout active through S3 and into S4 */
		idm_initial_login_actions(ic, event_ctx);
		idm_update_state(ic, CS_S4_IN_LOGIN, event_ctx);
		break;
	case CE_LOGIN_TIMEOUT:
		/*
		 * Don't need to cancel login timer since the timer is
		 * presumed to be the source of this event.
		 */
		(void) idm_notify_client(ic, CN_LOGIN_FAIL, NULL);
		idm_update_state(ic, CS_S9_INIT_ERROR, event_ctx);
		break;
	case CE_CONNECT_REJECT:
		/*
		 * Iscsit doesn't want to hear from us again in this case.
		 * Since it rejected the connection it doesn't have a
		 * connection context to handle additional notifications.
		 * IDM needs to just clean things up on its own.
		 */
		IDM_SM_TIMER_CLEAR(ic);
		idm_update_state(ic, CS_S9A_REJECTED, event_ctx);
		break;
	case CE_CONNECT_FAIL:
	case CE_TRANSPORT_FAIL:
	case CE_LOGOUT_OTHER_CONN_SND:
		/* T6 */
		IDM_SM_TIMER_CLEAR(ic);
		(void) idm_notify_client(ic, CN_LOGIN_FAIL, NULL);
		idm_update_state(ic, CS_S9_INIT_ERROR, event_ctx);
		break;
	case CE_TX_PROTOCOL_ERROR:
	case CE_RX_PROTOCOL_ERROR:
		/* Don't care */
		break;
	default:
		ASSERT(0);
		/*NOTREACHED*/
	}
}

static void
idm_state_s4_in_login(idm_conn_t *ic, idm_conn_event_ctx_t *event_ctx)
{
	idm_pdu_t *pdu;

	/*
	 * Login timer should no longer be active after leaving this
	 * state.
	 */
	switch (event_ctx->iec_event) {
	case CE_LOGIN_SUCCESS_RCV:
	case CE_LOGIN_SUCCESS_SND:
		ASSERT(ic->ic_client_callback == NULL);

		IDM_SM_TIMER_CLEAR(ic);
		idm_login_success_actions(ic, event_ctx);
		if (ic->ic_rdma_extensions) {
			/* T19 */
			idm_update_state(ic, CS_S12_ENABLE_DM, event_ctx);
		} else {
			/* T5 */
			idm_update_state(ic, CS_S5_LOGGED_IN, event_ctx);
		}
		break;
	case CE_LOGIN_TIMEOUT:
		/* T7 */
		(void) idm_notify_client(ic, CN_LOGIN_FAIL, NULL);
		idm_update_state(ic, CS_S9_INIT_ERROR, event_ctx);
		break;
	case CE_LOGIN_FAIL_SND:
		/*
		 * Allow the logout response pdu to be sent and defer
		 * the state machine cleanup until the completion callback.
		 * Only 1 level or callback interposition is allowed.
		 */
		IDM_SM_TIMER_CLEAR(ic);
		pdu = (idm_pdu_t *)event_ctx->iec_info;
		ASSERT(ic->ic_client_callback == NULL);
		ic->ic_client_callback = pdu->isp_callback;
		pdu->isp_callback =
		    idm_state_s9b_wait_snd_done_cb;
		idm_update_state(ic, CS_S9B_WAIT_SND_DONE,
		    event_ctx);
		break;
	case CE_LOGIN_FAIL_RCV:
		ASSERT(ic->ic_client_callback == NULL);
		/*
		 * Need to deliver this PDU to the initiator now because after
		 * we update the state to CS_S9_INIT_ERROR the initiator will
		 * no longer be in an appropriate state.
		 */
		event_ctx->iec_pdu_forwarded = B_TRUE;
		pdu = (idm_pdu_t *)event_ctx->iec_info;
		idm_pdu_rx_forward(ic, pdu);
		/* FALLTHROUGH */
	case CE_TRANSPORT_FAIL:
	case CE_LOGOUT_OTHER_CONN_SND:
	case CE_LOGOUT_OTHER_CONN_RCV:
		/* T7 */
		IDM_SM_TIMER_CLEAR(ic);
		(void) idm_notify_client(ic, CN_LOGIN_FAIL, NULL);
		idm_update_state(ic, CS_S9_INIT_ERROR, event_ctx);
		break;
	case CE_LOGOUT_SESSION_SUCCESS:
		/*
		 * T8
		 * A session reinstatement request can be received while a
		 * session is active and a login is in process. The iSCSI
		 * connections are shut down by a CE_LOGOUT_SESSION_SUCCESS
		 * event sent from the session to the IDM layer.
		 */
		IDM_SM_TIMER_CLEAR(ic);
		if (IDM_CONN_ISTGT(ic)) {
			ic->ic_transport_ops->it_tgt_conn_disconnect(ic);
		} else {
			ic->ic_transport_ops->it_ini_conn_disconnect(ic);
		}
		idm_update_state(ic, CS_S11_COMPLETE, event_ctx);
		break;

	case CE_LOGIN_SND:
		ASSERT(ic->ic_client_callback == NULL);
		/*
		 * Initiator connections will see initial login PDU
		 * in this state.  Target connections see initial
		 * login PDU in "xpt up" state.
		 */
		mutex_enter(&ic->ic_state_mutex);
		if (!(ic->ic_state_flags & CF_INITIAL_LOGIN)) {
			idm_initial_login_actions(ic, event_ctx);
		}
		mutex_exit(&ic->ic_state_mutex);
		break;
	case CE_MISC_TX:
	case CE_MISC_RX:
	case CE_LOGIN_RCV:
	case CE_TX_PROTOCOL_ERROR:
	case CE_RX_PROTOCOL_ERROR:
		/* Don't care */
		break;
	default:
		ASSERT(0);
		/*NOTREACHED*/
	}
}


static void
idm_state_s5_logged_in(idm_conn_t *ic, idm_conn_event_ctx_t *event_ctx)
{
	switch (event_ctx->iec_event) {
	case CE_MISC_RX:
		/* MC/S: when removing the non-leading connection */
	case CE_LOGOUT_THIS_CONN_RCV:
	case CE_LOGOUT_THIS_CONN_SND:
	case CE_LOGOUT_OTHER_CONN_RCV:
	case CE_LOGOUT_OTHER_CONN_SND:
		/* T9 */
		idm_ffp_disable(ic, FD_CONN_LOGOUT); /* Explicit logout */
		idm_update_state(ic, CS_S6_IN_LOGOUT, event_ctx);
		break;
	case CE_LOGOUT_SESSION_RCV:
	case CE_LOGOUT_SESSION_SND:
		/* T9 */
		idm_ffp_disable(ic, FD_SESS_LOGOUT); /* Explicit logout */
		idm_update_state(ic, CS_S6_IN_LOGOUT, event_ctx);
		break;
	case CE_LOGOUT_SESSION_SUCCESS:
		/* T8 */
		idm_ffp_disable(ic, FD_SESS_LOGOUT); /* Explicit logout */

		/* Close connection */
		if (IDM_CONN_ISTGT(ic)) {
			ic->ic_transport_ops->it_tgt_conn_disconnect(ic);
		} else {
			ic->ic_transport_ops->it_ini_conn_disconnect(ic);
		}

		idm_update_state(ic, CS_S11_COMPLETE, event_ctx);
		break;
	case CE_ASYNC_LOGOUT_RCV:
	case CE_ASYNC_LOGOUT_SND:
		/* T11 */
		idm_update_state(ic, CS_S7_LOGOUT_REQ, event_ctx);
		break;
	case CE_TRANSPORT_FAIL:
	case CE_ASYNC_DROP_CONN_RCV:
	case CE_ASYNC_DROP_CONN_SND:
	case CE_ASYNC_DROP_ALL_CONN_RCV:
	case CE_ASYNC_DROP_ALL_CONN_SND:
		/* T15 */
		idm_ffp_disable(ic, FD_CONN_FAIL); /* Implicit logout */
		idm_update_state(ic, CS_S8_CLEANUP, event_ctx);
		break;
	case CE_MISC_TX:
	case CE_TX_PROTOCOL_ERROR:
	case CE_RX_PROTOCOL_ERROR:
	case CE_LOGIN_TIMEOUT:
		/* Don't care */
		break;
	default:
		ASSERT(0);
	}
}

static void
idm_state_s6_in_logout_success_snd_done(idm_pdu_t *pdu, idm_status_t status)
{
	idm_conn_t		*ic = pdu->isp_ic;

	/*
	 * This pdu callback can be invoked by the tx thread,
	 * so run the disconnect code from another thread.
	 */
	pdu->isp_status = status;
	idm_conn_event(ic, CE_LOGOUT_SUCCESS_SND_DONE, (uintptr_t)pdu);
}

static void
idm_state_s6_in_logout_fail_snd_done(idm_pdu_t *pdu, idm_status_t status)
{
	idm_conn_t		*ic = pdu->isp_ic;

	/*
	 * This pdu callback can be invoked by the tx thread,
	 * so run the disconnect code from another thread.
	 */
	pdu->isp_status = status;
	idm_conn_event(ic, CE_LOGOUT_FAIL_SND_DONE, (uintptr_t)pdu);
}

static void
idm_state_s6_in_logout(idm_conn_t *ic, idm_conn_event_ctx_t *event_ctx)
{
	idm_pdu_t *pdu;

	switch (event_ctx->iec_event) {
	case CE_LOGOUT_SUCCESS_SND_DONE:
		pdu = (idm_pdu_t *)event_ctx->iec_info;

		/* Close connection (if it's not already closed) */
		ASSERT(IDM_CONN_ISTGT(ic));
		ic->ic_transport_ops->it_tgt_conn_disconnect(ic);

		/* restore client callback */
		pdu->isp_callback =  ic->ic_client_callback;
		ic->ic_client_callback = NULL;
		idm_pdu_complete(pdu, pdu->isp_status);
		idm_update_state(ic, CS_S11_COMPLETE, event_ctx);
		break;
	case CE_LOGOUT_FAIL_SND_DONE:
		pdu = (idm_pdu_t *)event_ctx->iec_info;
		/* restore client callback */
		pdu->isp_callback =  ic->ic_client_callback;
		ic->ic_client_callback = NULL;
		idm_pdu_complete(pdu, pdu->isp_status);
		idm_update_state(ic, CS_S8_CLEANUP, event_ctx);
		break;
	case CE_LOGOUT_SUCCESS_SND:
	case CE_LOGOUT_FAIL_SND:
		/*
		 * Allow the logout response pdu to be sent and defer
		 * the state machine update until the completion callback.
		 * Only 1 level or callback interposition is allowed.
		 */
		pdu = (idm_pdu_t *)event_ctx->iec_info;
		ASSERT(ic->ic_client_callback == NULL);
		ic->ic_client_callback = pdu->isp_callback;
		if (event_ctx->iec_event == CE_LOGOUT_SUCCESS_SND) {
			pdu->isp_callback =
			    idm_state_s6_in_logout_success_snd_done;
		} else {
			pdu->isp_callback =
			    idm_state_s6_in_logout_fail_snd_done;
		}
		break;
	case CE_LOGOUT_SUCCESS_RCV:
		/*
		 * Need to deliver this PDU to the initiator now because after
		 * we update the state to CS_S11_COMPLETE the initiator will
		 * no longer be in an appropriate state.
		 */
		event_ctx->iec_pdu_forwarded = B_TRUE;
		pdu = (idm_pdu_t *)event_ctx->iec_info;
		idm_pdu_rx_forward(ic, pdu);
		/* FALLTHROUGH */
	case CE_LOGOUT_SESSION_SUCCESS:
		/* T13 */

		/* Close connection (if it's not already closed) */
		if (IDM_CONN_ISTGT(ic)) {
			ic->ic_transport_ops->it_tgt_conn_disconnect(ic);
		} else {
			ic->ic_transport_ops->it_ini_conn_disconnect(ic);
		}

		idm_update_state(ic, CS_S11_COMPLETE, event_ctx);
		break;
	case CE_ASYNC_LOGOUT_RCV:
		/* T14 Do nothing */
		break;
	case CE_TRANSPORT_FAIL:
	case CE_ASYNC_DROP_CONN_RCV:
	case CE_ASYNC_DROP_CONN_SND:
	case CE_ASYNC_DROP_ALL_CONN_RCV:
	case CE_ASYNC_DROP_ALL_CONN_SND:
	case CE_LOGOUT_FAIL_RCV:
		idm_update_state(ic, CS_S8_CLEANUP, event_ctx);
		break;
	case CE_TX_PROTOCOL_ERROR:
	case CE_RX_PROTOCOL_ERROR:
	case CE_MISC_TX:
	case CE_MISC_RX:
	case CE_LOGIN_TIMEOUT:
		/* Don't care */
		break;
	default:
		ASSERT(0);
	}
}


static void
idm_logout_req_timeout(void *arg)
{
	idm_conn_t *ic = arg;

	ic->ic_state_timeout = 0;
	idm_conn_event(ic, CE_LOGOUT_TIMEOUT, NULL);
}

static void
idm_state_s7_logout_req(idm_conn_t *ic, idm_conn_event_ctx_t *event_ctx)
{
	/* Must cancel logout timer before leaving this state */
	switch (event_ctx->iec_event) {
	case CE_LOGOUT_THIS_CONN_RCV:
	case CE_LOGOUT_THIS_CONN_SND:
	case CE_LOGOUT_OTHER_CONN_RCV:
	case CE_LOGOUT_OTHER_CONN_SND:
		/* T10 */
		if (IDM_CONN_ISTGT(ic)) {
			IDM_SM_TIMER_CLEAR(ic);
		}
		idm_ffp_disable(ic, FD_CONN_LOGOUT); /* Explicit logout */
		idm_update_state(ic, CS_S6_IN_LOGOUT, event_ctx);
		break;
	case CE_LOGOUT_SESSION_RCV:
	case CE_LOGOUT_SESSION_SND:
		/* T10 */
		if (IDM_CONN_ISTGT(ic)) {
			IDM_SM_TIMER_CLEAR(ic);
		}
		idm_ffp_disable(ic, FD_SESS_LOGOUT); /* Explicit logout */
		idm_update_state(ic, CS_S6_IN_LOGOUT, event_ctx);
		break;
	case CE_ASYNC_LOGOUT_RCV:
	case CE_ASYNC_LOGOUT_SND:
		/* T12 Do nothing */
		break;
	case CE_TRANSPORT_FAIL:
	case CE_ASYNC_DROP_CONN_RCV:
	case CE_ASYNC_DROP_CONN_SND:
	case CE_ASYNC_DROP_ALL_CONN_RCV:
	case CE_ASYNC_DROP_ALL_CONN_SND:
		/* T16 */
		if (IDM_CONN_ISTGT(ic)) {
			IDM_SM_TIMER_CLEAR(ic);
		}
		/* FALLTHROUGH */
	case CE_LOGOUT_TIMEOUT:
		idm_ffp_disable(ic, FD_CONN_FAIL); /* Implicit logout */
		idm_update_state(ic, CS_S8_CLEANUP, event_ctx);
		break;
	case CE_LOGOUT_SESSION_SUCCESS:
		/* T18 */
		if (IDM_CONN_ISTGT(ic)) {
			IDM_SM_TIMER_CLEAR(ic);
		}
		idm_ffp_disable(ic, FD_SESS_LOGOUT); /* Explicit logout */

		/* Close connection (if it's not already closed) */
		if (IDM_CONN_ISTGT(ic)) {
			ic->ic_transport_ops->it_tgt_conn_disconnect(ic);
		} else {
			ic->ic_transport_ops->it_ini_conn_disconnect(ic);
		}

		idm_update_state(ic, CS_S11_COMPLETE, event_ctx);
		break;
	case CE_TX_PROTOCOL_ERROR:
	case CE_RX_PROTOCOL_ERROR:
	case CE_MISC_TX:
	case CE_MISC_RX:
	case CE_LOGIN_TIMEOUT:
		/* Don't care */
		break;
	default:
		ASSERT(0);
	}
}


static void
idm_cleanup_timeout(void *arg)
{
	idm_conn_t *ic = arg;

	ic->ic_state_timeout = 0;
	idm_conn_event(ic, CE_CLEANUP_TIMEOUT, NULL);
}

static void
idm_state_s8_cleanup(idm_conn_t *ic, idm_conn_event_ctx_t *event_ctx)
{
	idm_pdu_t *pdu;

	/*
	 * Need to cancel the cleanup timeout before leaving this state
	 * if it hasn't already fired.
	 */
	switch (event_ctx->iec_event) {
	case CE_LOGOUT_SUCCESS_RCV:
	case CE_LOGOUT_SUCCESS_SND:
	case CE_LOGOUT_SESSION_SUCCESS:
		IDM_SM_TIMER_CLEAR(ic);
		/*FALLTHROUGH*/
	case CE_CLEANUP_TIMEOUT:
		/* M1 */
		idm_update_state(ic, CS_S11_COMPLETE, event_ctx);
		break;
	case CE_LOGOUT_OTHER_CONN_RCV:
	case CE_LOGOUT_OTHER_CONN_SND:
		/* M2 */
		idm_update_state(ic, CS_S10_IN_CLEANUP, event_ctx);
		break;
	case CE_LOGOUT_SUCCESS_SND_DONE:
	case CE_LOGOUT_FAIL_SND_DONE:
		pdu = (idm_pdu_t *)event_ctx->iec_info;
		/* restore client callback */
		pdu->isp_callback =  ic->ic_client_callback;
		ic->ic_client_callback = NULL;
		idm_pdu_complete(pdu, pdu->isp_status);
		break;
	case CE_LOGOUT_SESSION_RCV:
	case CE_LOGOUT_SESSION_SND:
	case CE_TX_PROTOCOL_ERROR:
	case CE_RX_PROTOCOL_ERROR:
	case CE_MISC_TX:
	case CE_MISC_RX:
	case CE_TRANSPORT_FAIL:
	case CE_LOGIN_TIMEOUT:
	case CE_LOGOUT_TIMEOUT:
		/* Don't care */
		break;
	default:
		ASSERT(0);
	}
}

/* ARGSUSED */
static void
idm_state_s9_init_error(idm_conn_t *ic, idm_conn_event_ctx_t *event_ctx)
{
	/* All events ignored in this state */
}

/* ARGSUSED */
static void
idm_state_s9a_rejected(idm_conn_t *ic, idm_conn_event_ctx_t *event_ctx)
{
	/* All events ignored in this state */
}


static void
idm_state_s9b_wait_snd_done_cb(idm_pdu_t *pdu, idm_status_t status)
{
	idm_conn_t		*ic = pdu->isp_ic;

	/*
	 * This pdu callback can be invoked by the tx thread,
	 * so run the disconnect code from another thread.
	 */
	pdu->isp_status = status;
	idm_conn_event(ic, CE_LOGIN_FAIL_SND_DONE, (uintptr_t)pdu);
}

/*
 * CS_S9B_WAIT_SND_DONE -- wait for callback completion.
 */
/* ARGSUSED */
static void
idm_state_s9b_wait_snd_done(idm_conn_t *ic, idm_conn_event_ctx_t *event_ctx)
{
	idm_pdu_t *pdu;
	/*
	 * Wait for completion of the login fail sequence and then
	 * go to state S9_INIT_ERROR to clean up the connection.
	 */
	switch (event_ctx->iec_event) {
	case CE_LOGIN_FAIL_SND_DONE:
		pdu = (idm_pdu_t *)event_ctx->iec_info;
		/* restore client callback */
		pdu->isp_callback =  ic->ic_client_callback;
		ic->ic_client_callback = NULL;
		idm_pdu_complete(pdu, pdu->isp_status);
		idm_update_state(ic, CS_S9_INIT_ERROR, event_ctx);
		break;

	/* All other events ignored */
	}
}




static void
idm_state_s10_in_cleanup(idm_conn_t *ic, idm_conn_event_ctx_t *event_ctx)
{
	idm_pdu_t *pdu;

	/*
	 * Need to cancel the cleanup timeout before leaving this state
	 * if it hasn't already fired.
	 */
	switch (event_ctx->iec_event) {
	case CE_LOGOUT_FAIL_RCV:
	case CE_LOGOUT_FAIL_SND:
		idm_update_state(ic, CS_S8_CLEANUP, event_ctx);
		break;
	case CE_LOGOUT_SUCCESS_SND:
	case CE_LOGOUT_SUCCESS_RCV:
	case CE_LOGOUT_SESSION_SUCCESS:
		IDM_SM_TIMER_CLEAR(ic);
		/*FALLTHROUGH*/
	case CE_CLEANUP_TIMEOUT:
		idm_update_state(ic, CS_S11_COMPLETE, event_ctx);
		break;
	case CE_LOGOUT_SUCCESS_SND_DONE:
	case CE_LOGOUT_FAIL_SND_DONE:
		pdu = (idm_pdu_t *)event_ctx->iec_info;
		/* restore client callback */
		pdu->isp_callback =  ic->ic_client_callback;
		ic->ic_client_callback = NULL;
		idm_pdu_complete(pdu, pdu->isp_status);
		break;
	case CE_TX_PROTOCOL_ERROR:
	case CE_RX_PROTOCOL_ERROR:
	case CE_MISC_TX:
	case CE_MISC_RX:
	case CE_LOGIN_TIMEOUT:
	case CE_LOGOUT_TIMEOUT:
		/* Don't care */
		break;
	default:
		ASSERT(0);
	}
}

/* ARGSUSED */
static void
idm_state_s11_complete(idm_conn_t *ic, idm_conn_event_ctx_t *event_ctx)
{
	idm_pdu_t *pdu;

	/*
	 * Cleanup logout success/fail completion if it's been delayed
	 * until now.
	 *
	 * All new events are filtered out before reaching this state, but
	 * there might already be events in the event queue, so handle the
	 * SND_DONE events here. Note that if either of the following
	 * SND_DONE events happens AFTER the change to state S11, then the
	 * event filter inside dm_conn_event_locked does enough cleanup.
	 */
	switch (event_ctx->iec_event) {
	case CE_LOGOUT_SUCCESS_SND_DONE:
	case CE_LOGOUT_FAIL_SND_DONE:
		pdu = (idm_pdu_t *)event_ctx->iec_info;
		/* restore client callback */
		pdu->isp_callback =  ic->ic_client_callback;
		ic->ic_client_callback = NULL;
		idm_pdu_complete(pdu, pdu->isp_status);
		break;
	}

}

static void
idm_state_s12_enable_dm(idm_conn_t *ic, idm_conn_event_ctx_t *event_ctx)
{
	switch (event_ctx->iec_event) {
	case CE_ENABLE_DM_SUCCESS:
		/* T20 */
		idm_update_state(ic, CS_S5_LOGGED_IN, event_ctx);
		break;
	case CE_ENABLE_DM_FAIL:
		/* T21 */
		idm_update_state(ic, CS_S9_INIT_ERROR, event_ctx);
		break;
	case CE_TRANSPORT_FAIL:
		/*
		 * We expect to always hear back from the transport layer
		 * once we have an "enable data-mover" request outstanding.
		 * Therefore we'll ignore other events that may occur even
		 * when they clearly indicate a problem and wait for
		 * CE_ENABLE_DM_FAIL.  On a related note this means the
		 * transport must ensure that it eventually completes the
		 * "enable data-mover" operation with either success or
		 * failure -- otherwise we'll be stuck here.
		 */
		break;
	default:
		ASSERT(0);
		break;
	}
}

static void
idm_update_state(idm_conn_t *ic, idm_conn_state_t new_state,
    idm_conn_event_ctx_t *event_ctx)
{
	int rc;
	idm_status_t idm_status;

	/*
	 * Validate new state
	 */
	ASSERT(new_state != CS_S0_UNDEFINED);
	ASSERT3U(new_state, <, CS_MAX_STATE);

	/*
	 * Update state in context.  We protect this with a mutex
	 * even though the state machine code is single threaded so that
	 * other threads can check the state value atomically.
	 */
	new_state = (new_state < CS_MAX_STATE) ?
	    new_state : CS_S0_UNDEFINED;

	IDM_SM_LOG(CE_NOTE, "idm_update_state: conn %p, evt %s(%d), "
	    "%s(%d) --> %s(%d)", (void *)ic,
	    idm_ce_name[event_ctx->iec_event], event_ctx->iec_event,
	    idm_cs_name[ic->ic_state], ic->ic_state,
	    idm_cs_name[new_state], new_state);

	DTRACE_PROBE2(conn__state__change,
	    idm_conn_t *, ic, idm_conn_state_t, new_state);

	mutex_enter(&ic->ic_state_mutex);
	idm_sm_audit_state_change(&ic->ic_state_audit, SAS_IDM_CONN,
	    (int)ic->ic_state, (int)new_state);
	ic->ic_last_state = ic->ic_state;
	ic->ic_state = new_state;
	cv_signal(&ic->ic_state_cv);
	mutex_exit(&ic->ic_state_mutex);

	switch (ic->ic_state) {
	case CS_S1_FREE:
		ASSERT(0); /* Initial state, can't return */
		break;
	case CS_S2_XPT_WAIT:
		if ((rc = idm_ini_conn_finish(ic)) != 0) {
			idm_conn_event(ic, CE_CONNECT_FAIL, NULL);
		} else {
			idm_conn_event(ic, CE_CONNECT_SUCCESS, NULL);
		}
		break;
	case CS_S3_XPT_UP:
		/*
		 * Finish any connection related setup including
		 * waking up the idm_tgt_conn_accept thread.
		 * and starting the login timer.  If the function
		 * fails then we return to "free" state.
		 */
		if ((rc = idm_tgt_conn_finish(ic)) != IDM_STATUS_SUCCESS) {
			switch (rc) {
			case IDM_STATUS_REJECT:
				idm_conn_event(ic, CE_CONNECT_REJECT, NULL);
				break;
			default:
				idm_conn_event(ic, CE_CONNECT_FAIL, NULL);
				break;
			}
		}

		/*
		 * First login received will cause a transition to
		 * CS_S4_IN_LOGIN.  Start login timer.
		 */
		IDM_SM_TIMER_CHECK(ic);
		ic->ic_state_timeout = timeout(idm_login_timeout, ic,
		    drv_usectohz(IDM_LOGIN_SECONDS*1000000));
		break;
	case CS_S4_IN_LOGIN:
		if (ic->ic_conn_type == CONN_TYPE_INI) {
			(void) idm_notify_client(ic, CN_READY_FOR_LOGIN, NULL);
			mutex_enter(&ic->ic_state_mutex);
			ic->ic_state_flags |= CF_LOGIN_READY;
			cv_signal(&ic->ic_state_cv);
			mutex_exit(&ic->ic_state_mutex);
		}
		break;
	case CS_S5_LOGGED_IN:
		ASSERT(!ic->ic_ffp);
		/*
		 * IDM can go to FFP before the initiator but it
		 * needs to go to FFP after the target (IDM target should
		 * go to FFP after notify_ack).
		 */
		idm_status = idm_ffp_enable(ic);
		if (idm_status != IDM_STATUS_SUCCESS) {
			idm_conn_event(ic, CE_TRANSPORT_FAIL, NULL);
		}

		if (ic->ic_reinstate_conn) {
			/* Connection reinstatement is complete */
			idm_conn_event(ic->ic_reinstate_conn,
			    CE_CONN_REINSTATE_SUCCESS, NULL);
		}
		break;
	case CS_S6_IN_LOGOUT:
		break;
	case CS_S7_LOGOUT_REQ:
		/* Start logout timer for target connections */
		if (IDM_CONN_ISTGT(ic)) {
			IDM_SM_TIMER_CHECK(ic);
			ic->ic_state_timeout = timeout(idm_logout_req_timeout,
			    ic, drv_usectohz(IDM_LOGOUT_SECONDS*1000000));
		}
		break;
	case CS_S8_CLEANUP:
		/* Close connection (if it's not already closed) */
		if (IDM_CONN_ISTGT(ic)) {
			ic->ic_transport_ops->it_tgt_conn_disconnect(ic);
		} else {
			ic->ic_transport_ops->it_ini_conn_disconnect(ic);
		}

		/* Stop executing active tasks */
		idm_task_abort(ic, NULL, AT_INTERNAL_SUSPEND);

		/* Start logout timer */
		IDM_SM_TIMER_CHECK(ic);
		ic->ic_state_timeout = timeout(idm_cleanup_timeout, ic,
		    drv_usectohz(IDM_CLEANUP_SECONDS*1000000));
		break;
	case CS_S10_IN_CLEANUP:
		break;
	case CS_S9A_REJECTED:
		/*
		 * We never finished establishing the connection so no
		 * disconnect.  No client notifications because the client
		 * rejected the connection.
		 */
		idm_refcnt_async_wait_ref(&ic->ic_refcnt,
		    &idm_conn_reject_unref);
		break;
	case CS_S9B_WAIT_SND_DONE:
		break;
	case CS_S9_INIT_ERROR:
		if (IDM_CONN_ISTGT(ic)) {
			ic->ic_transport_ops->it_tgt_conn_disconnect(ic);
		} else {
			mutex_enter(&ic->ic_state_mutex);
			ic->ic_state_flags |= CF_ERROR;
			ic->ic_conn_sm_status = IDM_STATUS_FAIL;
			cv_signal(&ic->ic_state_cv);
			mutex_exit(&ic->ic_state_mutex);
			if (ic->ic_last_state != CS_S1_FREE &&
			    ic->ic_last_state != CS_S2_XPT_WAIT) {
				ic->ic_transport_ops->it_ini_conn_disconnect(
				    ic);
			} else {
				(void) idm_notify_client(ic, CN_CONNECT_FAIL,
				    NULL);
			}
		}
		/*FALLTHROUGH*/
	case CS_S11_COMPLETE:
		/*
		 * No more traffic on this connection.  If this is an
		 * initiator connection and we weren't connected yet
		 * then don't send the "connect lost" event.
		 * It's useful to the initiator to know whether we were
		 * logging in at the time so send that information in the
		 * data field.
		 */
		if (IDM_CONN_ISTGT(ic) ||
		    ((ic->ic_last_state != CS_S1_FREE) &&
		    (ic->ic_last_state != CS_S2_XPT_WAIT))) {
			(void) idm_notify_client(ic, CN_CONNECT_LOST,
			    (uintptr_t)(ic->ic_last_state == CS_S4_IN_LOGIN));
		}

		/* Abort all tasks */
		idm_task_abort(ic, NULL, AT_INTERNAL_ABORT);

		/*
		 * Handle terminal state actions on the global taskq so
		 * we can clean up all the connection resources from
		 * a separate thread context.
		 */
		idm_refcnt_async_wait_ref(&ic->ic_refcnt, &idm_conn_unref);
		break;
	case CS_S12_ENABLE_DM:

		/*
		 * The Enable DM state indicates the initiator to initiate
		 * the hello sequence and the target to get ready to accept
		 * the iSER Hello Message.
		 */
		idm_status = (IDM_CONN_ISINI(ic)) ?
		    ic->ic_transport_ops->it_ini_enable_datamover(ic) :
		    ic->ic_transport_ops->it_tgt_enable_datamover(ic);

		if (idm_status == IDM_STATUS_SUCCESS) {
			idm_conn_event(ic, CE_ENABLE_DM_SUCCESS, NULL);
		} else {
			idm_conn_event(ic, CE_ENABLE_DM_FAIL, NULL);
		}

		break;

	default:
		ASSERT(0);
		break;

	}
}


static void
idm_conn_unref(void *ic_void)
{
	idm_conn_t *ic = ic_void;

	/*
	 * Client should not be notified that the connection is destroyed
	 * until all references on the idm connection have been removed.
	 * Otherwise references on the associated client context would need
	 * to be tracked separately which seems like a waste (at least when
	 * there is a one for one correspondence with references on the
	 * IDM connection).
	 */
	if (IDM_CONN_ISTGT(ic)) {
		(void) idm_notify_client(ic, CN_CONNECT_DESTROY, NULL);
		idm_svc_conn_destroy(ic);
	} else {
		/* Initiator may destroy connection during this call */
		(void) idm_notify_client(ic, CN_CONNECT_DESTROY, NULL);
	}
}

static void
idm_conn_reject_unref(void *ic_void)
{
	idm_conn_t *ic = ic_void;

	ASSERT(IDM_CONN_ISTGT(ic));

	/* Don't notify the client since it rejected the connection */
	idm_svc_conn_destroy(ic);
}



static idm_pdu_event_action_t
idm_conn_sm_validate_pdu(idm_conn_t *ic, idm_conn_event_ctx_t *event_ctx,
	idm_pdu_t *pdu)
{
	char			*reason_string;
	idm_pdu_event_action_t	action;

	ASSERT((event_ctx->iec_pdu_event_type == CT_RX_PDU) ||
	    (event_ctx->iec_pdu_event_type == CT_TX_PDU));

	/*
	 * Let's check the simple stuff first.  Make sure if this is a
	 * target connection that the PDU is appropriate for a target
	 * and if this is an initiator connection that the PDU is
	 * appropriate for an initiator.  This code is not in the data
	 * path so organization is more important than performance.
	 */
	switch (IDM_PDU_OPCODE(pdu)) {
	case ISCSI_OP_NOOP_OUT:
	case ISCSI_OP_SCSI_CMD:
	case ISCSI_OP_SCSI_TASK_MGT_MSG:
	case ISCSI_OP_LOGIN_CMD:
	case ISCSI_OP_TEXT_CMD:
	case ISCSI_OP_SCSI_DATA:
	case ISCSI_OP_LOGOUT_CMD:
	case ISCSI_OP_SNACK_CMD:
		/*
		 * Only the initiator should send these PDU's and
		 * only the target should receive them.
		 */
		if (IDM_CONN_ISINI(ic) &&
		    (event_ctx->iec_pdu_event_type == CT_RX_PDU)) {
			reason_string = "Invalid RX PDU for initiator";
			action = CA_RX_PROTOCOL_ERROR;
			goto validate_pdu_done;
		}

		if (IDM_CONN_ISTGT(ic) &&
		    (event_ctx->iec_pdu_event_type == CT_TX_PDU)) {
			reason_string = "Invalid TX PDU for target";
			action = CA_TX_PROTOCOL_ERROR;
			goto validate_pdu_done;
		}
		break;
	case ISCSI_OP_NOOP_IN:
	case ISCSI_OP_SCSI_RSP:
	case ISCSI_OP_SCSI_TASK_MGT_RSP:
	case ISCSI_OP_LOGIN_RSP:
	case ISCSI_OP_TEXT_RSP:
	case ISCSI_OP_SCSI_DATA_RSP:
	case ISCSI_OP_LOGOUT_RSP:
	case ISCSI_OP_RTT_RSP:
	case ISCSI_OP_ASYNC_EVENT:
	case ISCSI_OP_REJECT_MSG:
		/*
		 * Only the target should send these PDU's and
		 * only the initiator should receive them.
		 */
		if (IDM_CONN_ISTGT(ic) &&
		    (event_ctx->iec_pdu_event_type == CT_RX_PDU)) {
			reason_string = "Invalid RX PDU for target";
			action = CA_RX_PROTOCOL_ERROR;
			goto validate_pdu_done;
		}

		if (IDM_CONN_ISINI(ic) &&
		    (event_ctx->iec_pdu_event_type == CT_TX_PDU)) {
			reason_string = "Invalid TX PDU for initiator";
			action = CA_TX_PROTOCOL_ERROR;
			goto validate_pdu_done;
		}
		break;
	default:
		reason_string = "Unknown PDU Type";
		action = ((event_ctx->iec_pdu_event_type == CT_TX_PDU) ?
		    CA_TX_PROTOCOL_ERROR : CA_RX_PROTOCOL_ERROR);
		goto validate_pdu_done;
	}

	/*
	 * Now validate the opcodes against the current state.
	 */
	reason_string = "PDU not allowed in current state";
	switch (IDM_PDU_OPCODE(pdu)) {
	case ISCSI_OP_NOOP_OUT:
	case ISCSI_OP_NOOP_IN:
		/*
		 * Obviously S1-S3 are not allowed since login hasn't started.
		 * S8 is probably out as well since the connection has been
		 * dropped.
		 */
		switch (ic->ic_state) {
		case CS_S4_IN_LOGIN:
		case CS_S5_LOGGED_IN:
		case CS_S6_IN_LOGOUT:
		case CS_S7_LOGOUT_REQ:
			action = CA_FORWARD;
			goto validate_pdu_done;
		case CS_S8_CLEANUP:
		case CS_S10_IN_CLEANUP:
			action = CA_DROP;
			break;
		default:
			action = ((event_ctx->iec_pdu_event_type == CT_TX_PDU) ?
			    CA_TX_PROTOCOL_ERROR : CA_RX_PROTOCOL_ERROR);
			goto validate_pdu_done;
		}
		/*NOTREACHED*/
	case ISCSI_OP_SCSI_CMD:
	case ISCSI_OP_SCSI_RSP:
	case ISCSI_OP_SCSI_TASK_MGT_MSG:
	case ISCSI_OP_SCSI_TASK_MGT_RSP:
	case ISCSI_OP_SCSI_DATA:
	case ISCSI_OP_SCSI_DATA_RSP:
	case ISCSI_OP_RTT_RSP:
	case ISCSI_OP_SNACK_CMD:
	case ISCSI_OP_TEXT_CMD:
	case ISCSI_OP_TEXT_RSP:
		switch (ic->ic_state) {
		case CS_S5_LOGGED_IN:
		case CS_S6_IN_LOGOUT:
		case CS_S7_LOGOUT_REQ:
			action = CA_FORWARD;
			goto validate_pdu_done;
		case CS_S8_CLEANUP:
		case CS_S10_IN_CLEANUP:
			action = CA_DROP;
			break;
		default:
			action = ((event_ctx->iec_pdu_event_type == CT_TX_PDU) ?
			    CA_TX_PROTOCOL_ERROR : CA_RX_PROTOCOL_ERROR);
			goto validate_pdu_done;
		}
		/*NOTREACHED*/
	case ISCSI_OP_LOGOUT_CMD:
	case ISCSI_OP_LOGOUT_RSP:
	case ISCSI_OP_REJECT_MSG:
	case ISCSI_OP_ASYNC_EVENT:
		switch (ic->ic_state) {
		case CS_S5_LOGGED_IN:
		case CS_S6_IN_LOGOUT:
		case CS_S7_LOGOUT_REQ:
			action = CA_FORWARD;
			goto validate_pdu_done;
		case CS_S8_CLEANUP:
		case CS_S10_IN_CLEANUP:
			action = CA_DROP;
			break;
		default:
			action = ((event_ctx->iec_pdu_event_type == CT_TX_PDU) ?
			    CA_TX_PROTOCOL_ERROR : CA_RX_PROTOCOL_ERROR);
			goto validate_pdu_done;
		}
		/*NOTREACHED*/
	case ISCSI_OP_LOGIN_CMD:
	case ISCSI_OP_LOGIN_RSP:
		switch (ic->ic_state) {
		case CS_S3_XPT_UP:
		case CS_S4_IN_LOGIN:
			action = CA_FORWARD;
			goto validate_pdu_done;
		default:
			action = ((event_ctx->iec_pdu_event_type == CT_TX_PDU) ?
			    CA_TX_PROTOCOL_ERROR : CA_RX_PROTOCOL_ERROR);
			goto validate_pdu_done;
		}
		/*NOTREACHED*/
	default:
		/* This should never happen -- we already checked above */
		ASSERT(0);
		/*NOTREACHED*/
	}

	action = ((event_ctx->iec_pdu_event_type == CT_TX_PDU) ?
	    CA_TX_PROTOCOL_ERROR : CA_RX_PROTOCOL_ERROR);

validate_pdu_done:
	if (action != CA_FORWARD) {
		DTRACE_PROBE2(idm__int__protocol__error,
		    idm_conn_event_ctx_t *, event_ctx,
		    char *, reason_string);
	}

	return (action);
}

/* ARGSUSED */
void
idm_pdu_tx_protocol_error(idm_conn_t *ic, idm_pdu_t *pdu)
{
	/*
	 * Return the PDU to the caller indicating it was a protocol error.
	 * Caller can take appropriate action.
	 */
	idm_pdu_complete(pdu, IDM_STATUS_PROTOCOL_ERROR);
}

void
idm_pdu_rx_protocol_error(idm_conn_t *ic, idm_pdu_t *pdu)
{
	/*
	 * Forward PDU to caller indicating it is a protocol error.
	 * Caller should take appropriate action.
	 */
	(*ic->ic_conn_ops.icb_rx_error)(ic, pdu, IDM_STATUS_PROTOCOL_ERROR);
}

idm_status_t
idm_notify_client(idm_conn_t *ic, idm_client_notify_t cn, uintptr_t data)
{
	/*
	 * We may want to make this more complicated at some point but
	 * for now lets just call the client's notify function and return
	 * the status.
	 */
	ASSERT(!mutex_owned(&ic->ic_state_mutex));
	cn = (cn > CN_MAX) ? CN_MAX : cn;
	IDM_SM_LOG(CE_NOTE, "idm_notify_client: ic=%p %s(%d)\n",
	    (void *)ic, idm_cn_strings[cn], cn);
	return ((*ic->ic_conn_ops.icb_client_notify)(ic, cn, data));
}

static idm_status_t
idm_ffp_enable(idm_conn_t *ic)
{
	idm_status_t rc;

	/*
	 * On the initiator side the client will see this notification
	 * before the actual login succes PDU.  This shouldn't be a big
	 * deal since the initiator drives the connection.  It can simply
	 * wait for the login response then start sending SCSI commands.
	 * Kind ugly though compared with the way things work on target
	 * connections.
	 */
	mutex_enter(&ic->ic_state_mutex);
	ic->ic_ffp = B_TRUE;
	mutex_exit(&ic->ic_state_mutex);

	rc = idm_notify_client(ic, CN_FFP_ENABLED, NULL);
	if (rc != IDM_STATUS_SUCCESS) {
		mutex_enter(&ic->ic_state_mutex);
		ic->ic_ffp = B_FALSE;
		mutex_exit(&ic->ic_state_mutex);
	}
	return (rc);
}

static void
idm_ffp_disable(idm_conn_t *ic, idm_ffp_disable_t disable_type)
{
	mutex_enter(&ic->ic_state_mutex);
	ic->ic_ffp = B_FALSE;
	mutex_exit(&ic->ic_state_mutex);

	/* Client can't "fail" CN_FFP_DISABLED */
	(void) idm_notify_client(ic, CN_FFP_DISABLED,
	    (uintptr_t)disable_type);
}

static void
idm_initial_login_actions(idm_conn_t *ic, idm_conn_event_ctx_t *event_ctx)
{
	ASSERT((event_ctx->iec_event == CE_LOGIN_RCV) ||
	    (event_ctx->iec_event == CE_LOGIN_SND));

	/*
	 * Currently it's not clear what we would do here -- since
	 * we went to the trouble of coding an "initial login" hook
	 * we'll leave it in for now.  Remove before integration if
	 * it's not used for anything.
	 */
	ic->ic_state_flags |= CF_INITIAL_LOGIN;
}

static void
idm_login_success_actions(idm_conn_t *ic, idm_conn_event_ctx_t *event_ctx)
{
	idm_pdu_t		*pdu = (idm_pdu_t *)event_ctx->iec_info;
	iscsi_login_hdr_t	*login_req =
	    (iscsi_login_hdr_t *)pdu->isp_hdr;

	ASSERT((event_ctx->iec_event == CE_LOGIN_SUCCESS_RCV) ||
	    (event_ctx->iec_event == CE_LOGIN_SUCCESS_SND));

	/*
	 * Save off CID
	 */
	mutex_enter(&ic->ic_state_mutex);
	ic->ic_login_cid = ntohs(login_req->cid);
	ic->ic_login_info_valid =  B_TRUE;

	mutex_exit(&ic->ic_state_mutex);
}
