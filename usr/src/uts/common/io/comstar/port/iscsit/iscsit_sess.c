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
 * Copyright 2011 Nexenta Systems, Inc. All rights reserved.
 */

#include <sys/cpuvar.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/sysmacros.h>
#include <sys/scsi/generic/persist.h>

#include <sys/socket.h>
#include <sys/strsubr.h>
#include <sys/note.h>
#include <sys/sdt.h>

#include <sys/stmf.h>
#include <sys/stmf_ioctl.h>
#include <sys/portif.h>
#include <sys/idm/idm.h>

#define	ISCSIT_SESS_SM_STRINGS
#include "iscsit.h"

typedef struct {
	list_node_t		se_ctx_node;
	iscsit_session_event_t	se_ctx_event;
	iscsit_conn_t		*se_event_data;
} sess_event_ctx_t;

static void
sess_sm_event_locked(iscsit_sess_t *ist, iscsit_session_event_t event,
iscsit_conn_t *ict);

static void
sess_sm_event_dispatch(iscsit_sess_t *ist, sess_event_ctx_t *ctx);

static void
sess_sm_q1_free(iscsit_sess_t *ist, sess_event_ctx_t *ctx);

static void
sess_sm_q2_active(iscsit_sess_t *ist, sess_event_ctx_t *ctx);

static void
sess_sm_q3_logged_in(iscsit_sess_t *ist, sess_event_ctx_t *ctx);

static void
sess_sm_q4_failed(iscsit_sess_t *ist, sess_event_ctx_t *ctx);

static void
sess_sm_q5_continue(iscsit_sess_t *ist, sess_event_ctx_t *ctx);

static void
sess_sm_q6_done(iscsit_sess_t *ist, sess_event_ctx_t *ctx);

static void
sess_sm_q7_error(iscsit_sess_t *ist, sess_event_ctx_t *ctx);

static void
sess_sm_new_state(iscsit_sess_t *ist, sess_event_ctx_t *ctx,
    iscsit_session_state_t new_state);

static int
iscsit_task_itt_compare(const void *void_task1, const void *void_task2);

static uint16_t
iscsit_tsih_alloc(void)
{
	uintptr_t result;

	result = (uintptr_t)vmem_alloc(iscsit_global.global_tsih_pool,
	    1, VM_NOSLEEP | VM_NEXTFIT);

	/* ISCSI_UNSPEC_TSIH (0) indicates failure */
	if (result > ISCSI_MAX_TSIH) {
		vmem_free(iscsit_global.global_tsih_pool, (void *)result, 1);
		result = ISCSI_UNSPEC_TSIH;
	}

	return ((uint16_t)result);
}

static void
iscsit_tsih_free(uint16_t tsih)
{
	vmem_free(iscsit_global.global_tsih_pool, (void *)(uintptr_t)tsih, 1);
}


iscsit_sess_t *
iscsit_sess_create(iscsit_tgt_t *tgt, iscsit_conn_t *ict,
    uint32_t cmdsn, uint8_t *isid, uint16_t tag,
    char *initiator_name, char *target_name,
    uint8_t *error_class, uint8_t *error_detail)
{
	iscsit_sess_t *result;

	*error_class = ISCSI_STATUS_CLASS_SUCCESS;

	/*
	 * Even if this session create "fails" for some reason we still need
	 * to return a valid session pointer so that we can send the failed
	 * login response.
	 */
	result = kmem_zalloc(sizeof (*result), KM_SLEEP);

	/* Allocate TSIH */
	if ((result->ist_tsih = iscsit_tsih_alloc()) == ISCSI_UNSPEC_TSIH) {
		/* Out of TSIH's */
		*error_class = ISCSI_STATUS_CLASS_TARGET_ERR;
		*error_detail = ISCSI_LOGIN_STATUS_NO_RESOURCES;
		/*
		 * Continue initializing this session so we can use it
		 * to complete the login process.
		 */
	}

	idm_sm_audit_init(&result->ist_state_audit);
	mutex_init(&result->ist_sn_mutex, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&result->ist_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&result->ist_cv, NULL, CV_DEFAULT, NULL);
	list_create(&result->ist_events, sizeof (sess_event_ctx_t),
	    offsetof(sess_event_ctx_t, se_ctx_node));
	list_create(&result->ist_conn_list, sizeof (iscsit_conn_t),
	    offsetof(iscsit_conn_t, ict_sess_ln));
	avl_create(&result->ist_task_list, iscsit_task_itt_compare,
	    sizeof (iscsit_task_t), offsetof(iscsit_task_t, it_sess_ln));
	result->ist_rxpdu_queue = kmem_zalloc(sizeof (iscsit_cbuf_t), KM_SLEEP);
	result->ist_state = SS_Q1_FREE;
	result->ist_last_state = SS_Q1_FREE;
	bcopy(isid, result->ist_isid, ISCSI_ISID_LEN);
	result->ist_tpgt_tag = tag;

	result->ist_tgt = tgt;
	/*
	 * cmdsn/expcmdsn do not advance during login phase.
	 */
	result->ist_expcmdsn = cmdsn;
	result->ist_maxcmdsn = result->ist_expcmdsn + 1;

	result->ist_initiator_name =
	    kmem_alloc(strlen(initiator_name) + 1, KM_SLEEP);
	(void) strcpy(result->ist_initiator_name, initiator_name);
	if (target_name) {
		/* A discovery session might not have a target name */
		result->ist_target_name =
		    kmem_alloc(strlen(target_name) + 1, KM_SLEEP);
		(void) strcpy(result->ist_target_name, target_name);
	}
	idm_refcnt_init(&result->ist_refcnt, result);

	/* Login code will fill in ist_stmf_sess if necessary */

	if (*error_class == ISCSI_STATUS_CLASS_SUCCESS) {
		/*
		 * Make sure the service is still enabled and if so get a global
		 * hold to represent this session.
		 */
		mutex_enter(&iscsit_global.global_state_mutex);
		if (iscsit_global.global_svc_state == ISE_ENABLED) {
			iscsit_global_hold();
			mutex_exit(&iscsit_global.global_state_mutex);

			/*
			 * Kick session state machine (also binds connection
			 * to session)
			 */
			iscsit_sess_sm_event(result, SE_CONN_IN_LOGIN, ict);

			*error_class = ISCSI_STATUS_CLASS_SUCCESS;
		} else {
			mutex_exit(&iscsit_global.global_state_mutex);
			*error_class = ISCSI_STATUS_CLASS_TARGET_ERR;
			*error_detail = ISCSI_LOGIN_STATUS_SVC_UNAVAILABLE;
		}
	}

	/*
	 * As noted above we must return a session pointer even if something
	 * failed.  The resources will get freed later.
	 */
	return (result);
}

static void
iscsit_sess_unref(void *ist_void)
{
	iscsit_sess_t *ist = ist_void;
	stmf_scsi_session_t *iss;

	/*
	 * State machine has run to completion, destroy session
	 *
	 * If we have an associated STMF session we should clean it
	 * up now.
	 *
	 * This session is no longer associated with a target at this
	 * point so don't touch the target.
	 */
	mutex_enter(&ist->ist_mutex);
	ASSERT(ist->ist_conn_count == 0);
	iss = ist->ist_stmf_sess;
	if (iss != NULL) {
		stmf_deregister_scsi_session(ist->ist_lport, iss);
		kmem_free(iss->ss_rport_id, sizeof (scsi_devid_desc_t) +
		    strlen(ist->ist_initiator_name) + 1);
		stmf_remote_port_free(iss->ss_rport);
		if (iss->ss_rport_alias)
			strfree(iss->ss_rport_alias);
		stmf_free(iss);
	}
	mutex_exit(&ist->ist_mutex);

	iscsit_sess_destroy(ist);
	iscsit_global_rele();
}

void
iscsit_sess_destroy(iscsit_sess_t *ist)
{
	idm_refcnt_destroy(&ist->ist_refcnt);
	if (ist->ist_initiator_name)
		kmem_free(ist->ist_initiator_name,
		    strlen(ist->ist_initiator_name) + 1);
	if (ist->ist_initiator_alias)
		kmem_free(ist->ist_initiator_alias,
		    strlen(ist->ist_initiator_alias) + 1);
	if (ist->ist_target_name)
		kmem_free(ist->ist_target_name,
		    strlen(ist->ist_target_name) + 1);
	if (ist->ist_target_alias)
		kmem_free(ist->ist_target_alias,
		    strlen(ist->ist_target_alias) + 1);
	avl_destroy(&ist->ist_task_list);
	kmem_free(ist->ist_rxpdu_queue, sizeof (iscsit_cbuf_t));
	list_destroy(&ist->ist_conn_list);
	list_destroy(&ist->ist_events);
	cv_destroy(&ist->ist_cv);
	mutex_destroy(&ist->ist_mutex);
	mutex_destroy(&ist->ist_sn_mutex);
	kmem_free(ist, sizeof (*ist));
}

void
iscsit_sess_close(iscsit_sess_t *ist)
{
	iscsit_conn_t *ict;

	mutex_enter(&ist->ist_mutex);
	/*
	 * Note in the session state that we are forcing this session
	 * to close so that the session state machine can avoid
	 * pointless delays like transitions to SS_Q4_FAILED state.
	 */
	ist->ist_admin_close = B_TRUE;
	if (ist->ist_state == SS_Q3_LOGGED_IN) {
		for (ict = list_head(&ist->ist_conn_list);
		    ict != NULL;
		    ict = list_next(&ist->ist_conn_list, ict)) {
			iscsit_send_async_event(ict,
			    ISCSI_ASYNC_EVENT_REQUEST_LOGOUT);
		}
	}
	mutex_exit(&ist->ist_mutex);
}


void
iscsit_sess_bind_conn(iscsit_sess_t *ist, iscsit_conn_t *ict)
{
	iscsit_conn_hold(ict);
	iscsit_sess_hold(ist);
	ict->ict_sess = ist;
	mutex_enter(&ist->ist_mutex);
	ist->ist_conn_count++;
	list_insert_tail(&ist->ist_conn_list, ict);
	mutex_exit(&ist->ist_mutex);
}

void
iscsit_sess_unbind_conn(iscsit_sess_t *ist, iscsit_conn_t *ict)
{
	mutex_enter(&ist->ist_mutex);
	list_remove(&ist->ist_conn_list, ict);
	ist->ist_conn_count--;
	mutex_exit(&ist->ist_mutex);
	iscsit_sess_rele(ist);
	iscsit_conn_rele(ict);
}

void
iscsit_sess_hold(iscsit_sess_t *ist)
{
	idm_refcnt_hold(&ist->ist_refcnt);
}

void
iscsit_sess_rele(iscsit_sess_t *ist)
{
	idm_refcnt_rele(&ist->ist_refcnt);
}

idm_status_t
iscsit_sess_check_hold(iscsit_sess_t *ist)
{
	mutex_enter(&ist->ist_mutex);
	if (ist->ist_state != SS_Q6_DONE &&
	    ist->ist_state != SS_Q7_ERROR) {
		idm_refcnt_hold(&ist->ist_refcnt);
		mutex_exit(&ist->ist_mutex);
		return (IDM_STATUS_SUCCESS);
	}
	mutex_exit(&ist->ist_mutex);
	return (IDM_STATUS_FAIL);
}

iscsit_conn_t *
iscsit_sess_lookup_conn(iscsit_sess_t *ist, uint16_t cid)
{
	iscsit_conn_t *result;

	mutex_enter(&ist->ist_mutex);
	for (result = list_head(&ist->ist_conn_list);
	    result != NULL;
	    result = list_next(&ist->ist_conn_list, result)) {
		if (result->ict_cid == cid) {
			iscsit_conn_hold(result);
			mutex_exit(&ist->ist_mutex);
			return (result);
		}
	}
	mutex_exit(&ist->ist_mutex);

	return (NULL);
}

iscsit_sess_t *
iscsit_sess_reinstate(iscsit_tgt_t *tgt, iscsit_sess_t *ist, iscsit_conn_t *ict,
    uint8_t *error_class, uint8_t *error_detail)
{
	iscsit_sess_t *new_sess;

	mutex_enter(&ist->ist_mutex);

	/*
	 * Session reinstatement replaces a current session with a new session.
	 * The new session will have the same ISID as the existing session.
	 */
	new_sess = iscsit_sess_create(tgt, ict, 0,
	    ist->ist_isid, ist->ist_tpgt_tag,
	    ist->ist_initiator_name, ist->ist_target_name,
	    error_class, error_detail);
	ASSERT(new_sess != NULL);

	/* Copy additional fields from original session */
	new_sess->ist_expcmdsn = ist->ist_expcmdsn;
	new_sess->ist_maxcmdsn = ist->ist_expcmdsn + 1;

	if (ist->ist_state != SS_Q6_DONE &&
	    ist->ist_state != SS_Q7_ERROR) {
		/*
		 * Generate reinstate event
		 */
		sess_sm_event_locked(ist, SE_SESSION_REINSTATE, NULL);
	}
	mutex_exit(&ist->ist_mutex);

	return (new_sess);
}

int
iscsit_sess_avl_compare(const void *void_sess1, const void *void_sess2)
{
	const iscsit_sess_t	*sess1 = void_sess1;
	const iscsit_sess_t	*sess2 = void_sess2;
	int 			result;

	/*
	 * Sort by initiator name, then ISID then portal group tag
	 */
	result = strcmp(sess1->ist_initiator_name, sess2->ist_initiator_name);
	if (result < 0) {
		return (-1);
	} else if (result > 0) {
		return (1);
	}

	/*
	 * Initiator names match, compare ISIDs
	 */
	result = memcmp(sess1->ist_isid, sess2->ist_isid, ISCSI_ISID_LEN);
	if (result < 0) {
		return (-1);
	} else if (result > 0) {
		return (1);
	}

	/*
	 * ISIDs match, compare portal group tags
	 */
	if (sess1->ist_tpgt_tag < sess2->ist_tpgt_tag) {
		return (-1);
	} else if (sess1->ist_tpgt_tag > sess2->ist_tpgt_tag) {
		return (1);
	}

	/*
	 * Portal group tags match, compare TSIHs
	 */
	if (sess1->ist_tsih < sess2->ist_tsih) {
		return (-1);
	} else if (sess1->ist_tsih > sess2->ist_tsih) {
		return (1);
	}

	/*
	 * Sessions match
	 */
	return (0);
}

int
iscsit_task_itt_compare(const void *void_task1, const void *void_task2)
{
	const iscsit_task_t	*task1 = void_task1;
	const iscsit_task_t	*task2 = void_task2;

	if (task1->it_itt < task2->it_itt)
		return (-1);
	else if (task1->it_itt > task2->it_itt)
		return (1);

	return (0);
}

/*
 * State machine
 */

void
iscsit_sess_sm_event(iscsit_sess_t *ist, iscsit_session_event_t event,
    iscsit_conn_t *ict)
{
	mutex_enter(&ist->ist_mutex);
	sess_sm_event_locked(ist, event, ict);
	mutex_exit(&ist->ist_mutex);
}

static void
sess_sm_event_locked(iscsit_sess_t *ist, iscsit_session_event_t event,
    iscsit_conn_t *ict)
{
	sess_event_ctx_t *ctx;

	iscsit_sess_hold(ist);

	ctx = kmem_zalloc(sizeof (*ctx), KM_SLEEP);

	ctx->se_ctx_event = event;
	ctx->se_event_data = ict;

	list_insert_tail(&ist->ist_events, ctx);
	/*
	 * Use the ist_sm_busy to keep the state machine single threaded.
	 * This also serves as recursion avoidance since this flag will
	 * always be set if we call login_sm_event from within the
	 * state machine code.
	 */
	if (!ist->ist_sm_busy) {
		ist->ist_sm_busy = B_TRUE;
		while (!list_is_empty(&ist->ist_events)) {
			ctx = list_head(&ist->ist_events);
			list_remove(&ist->ist_events, ctx);
			idm_sm_audit_event(&ist->ist_state_audit,
			    SAS_ISCSIT_SESS, (int)ist->ist_state,
			    (int)ctx->se_ctx_event, (uintptr_t)ict);
			mutex_exit(&ist->ist_mutex);
			sess_sm_event_dispatch(ist, ctx);
			mutex_enter(&ist->ist_mutex);
		}
		ist->ist_sm_busy = B_FALSE;

	}

	iscsit_sess_rele(ist);
}

static void
sess_sm_event_dispatch(iscsit_sess_t *ist, sess_event_ctx_t *ctx)
{
	iscsit_conn_t	*ict;

	DTRACE_PROBE2(session__event, iscsit_sess_t *, ist,
	    sess_event_ctx_t *, ctx);

	IDM_SM_LOG(CE_NOTE, "sess_sm_event_dispatch: sess %p event %s(%d)",
	    (void *)ist, iscsit_se_name[ctx->se_ctx_event], ctx->se_ctx_event);

	/* State independent actions */
	switch (ctx->se_ctx_event) {
	case SE_CONN_IN_LOGIN:
		ict = ctx->se_event_data;
		iscsit_sess_bind_conn(ist, ict);
		break;
	case SE_CONN_FAIL:
		ict = ctx->se_event_data;
		iscsit_sess_unbind_conn(ist, ict);
		break;
	}

	/* State dependent actions */
	switch (ist->ist_state) {
	case SS_Q1_FREE:
		sess_sm_q1_free(ist, ctx);
		break;
	case SS_Q2_ACTIVE:
		sess_sm_q2_active(ist, ctx);
		break;
	case SS_Q3_LOGGED_IN:
		sess_sm_q3_logged_in(ist, ctx);
		break;
	case SS_Q4_FAILED:
		sess_sm_q4_failed(ist, ctx);
		break;
	case SS_Q5_CONTINUE:
		sess_sm_q5_continue(ist, ctx);
		break;
	case SS_Q6_DONE:
		sess_sm_q6_done(ist, ctx);
		break;
	case SS_Q7_ERROR:
		sess_sm_q7_error(ist, ctx);
		break;
	default:
		ASSERT(0);
		break;
	}

	kmem_free(ctx, sizeof (*ctx));
}

static void
sess_sm_q1_free(iscsit_sess_t *ist, sess_event_ctx_t *ctx)
{
	switch (ctx->se_ctx_event) {
	case SE_CONN_IN_LOGIN:
		/* N1 */
		sess_sm_new_state(ist, ctx, SS_Q2_ACTIVE);
		break;
	default:
		ASSERT(0);
		break;
	}
}


static void
sess_sm_q2_active(iscsit_sess_t *ist, sess_event_ctx_t *ctx)
{
	iscsit_conn_t	*ict;

	switch (ctx->se_ctx_event) {
	case SE_CONN_LOGGED_IN:
		/* N2 track FFP connections */
		ist->ist_ffp_conn_count++;
		sess_sm_new_state(ist, ctx, SS_Q3_LOGGED_IN);
		break;
	case SE_CONN_IN_LOGIN:
		/* N2.1, don't care stay in this state */
		break;
	case SE_CONN_FAIL:
		/* N9 */
		sess_sm_new_state(ist, ctx, SS_Q7_ERROR);
		break;
	case SE_SESSION_REINSTATE:
		/* N11 */
		/*
		 * Shutdown the iSCSI connections by
		 * sending an implicit logout to all
		 * the IDM connections and transition
		 * the session to SS_Q6_DONE state.
		 */
		mutex_enter(&ist->ist_mutex);
		for (ict = list_head(&ist->ist_conn_list);
		    ict != NULL;
		    ict = list_next(&ist->ist_conn_list, ict)) {
			iscsit_conn_logout(ict);
		}
		mutex_exit(&ist->ist_mutex);
		sess_sm_new_state(ist, ctx, SS_Q6_DONE);
		break;
	default:
		ASSERT(0);
		break;
	}
}

static void
sess_sm_q3_logged_in(iscsit_sess_t *ist, sess_event_ctx_t *ctx)
{
	iscsit_conn_t	*ict;

	switch (ctx->se_ctx_event) {
	case SE_CONN_IN_LOGIN:
	case SE_CONN_FAIL:
		/* N2.2, don't care */
		break;
	case SE_CONN_LOGGED_IN:
		/* N2.2, track FFP connections */
		ist->ist_ffp_conn_count++;
		break;
	case SE_CONN_FFP_FAIL:
	case SE_CONN_FFP_DISABLE:
		/*
		 * Event data from event context is the associated connection
		 * which in this case happens to be the last FFP connection
		 * for the session.  In certain cases we need to refer
		 * to this last valid connection (i.e. RFC3720 section 12.16)
		 * so we'll save off a pointer here for later use.
		 */
		ASSERT(ist->ist_ffp_conn_count >= 1);
		ist->ist_failed_conn = (iscsit_conn_t *)ctx->se_event_data;
		ist->ist_ffp_conn_count--;
		if (ist->ist_ffp_conn_count == 0) {
			/*
			 * N5(fail) or N3(disable)
			 *
			 * If the event is SE_CONN_FFP_FAIL but we are
			 * in the midst of an administrative session close
			 * because of a service or target offline then
			 * there is no need to go to "failed" state.
			 */
			sess_sm_new_state(ist, ctx,
			    ((ctx->se_ctx_event == SE_CONN_FFP_DISABLE) ||
			    (ist->ist_admin_close)) ?
			    SS_Q6_DONE : SS_Q4_FAILED);
		}
		break;
	case SE_SESSION_CLOSE:
	case SE_SESSION_REINSTATE:
		/* N3 */
		mutex_enter(&ist->ist_mutex);
		if (ctx->se_ctx_event == SE_SESSION_CLOSE) {
			ASSERT(ist->ist_ffp_conn_count >= 1);
			ist->ist_ffp_conn_count--;
		}
		for (ict = list_head(&ist->ist_conn_list);
		    ict != NULL;
		    ict = list_next(&ist->ist_conn_list, ict)) {
			if ((ctx->se_ctx_event == SE_SESSION_CLOSE) &&
			    ((iscsit_conn_t *)ctx->se_event_data == ict)) {
				/*
				 * Skip this connection since it will
				 * see the logout response
				 */
				continue;
			}
			iscsit_conn_logout(ict);
		}
		mutex_exit(&ist->ist_mutex);

		sess_sm_new_state(ist, ctx, SS_Q6_DONE);
		break;
	default:
		ASSERT(0);
		break;
	}
}

static void
sess_sm_timeout(void *arg)
{
	iscsit_sess_t *ist = arg;

	iscsit_sess_sm_event(ist, SE_SESSION_TIMEOUT, NULL);
}

static void
sess_sm_q4_failed(iscsit_sess_t *ist, sess_event_ctx_t *ctx)
{
	/* Session timer must not be running when we leave this event */
	switch (ctx->se_ctx_event) {
	case SE_CONN_IN_LOGIN:
		/* N7 */
		sess_sm_new_state(ist, ctx, SS_Q5_CONTINUE);
		break;
	case SE_SESSION_REINSTATE:
		/* N6 */
		(void) untimeout(ist->ist_state_timeout);
		/*FALLTHROUGH*/
	case SE_SESSION_TIMEOUT:
		/* N6 */
		sess_sm_new_state(ist, ctx, SS_Q6_DONE);
		break;
	case SE_CONN_FAIL:
		/* Don't care */
		break;
	default:
		ASSERT(0);
		break;
	}
}

static void
sess_sm_q5_continue(iscsit_sess_t *ist, sess_event_ctx_t *ctx)
{
	switch (ctx->se_ctx_event) {
	case SE_CONN_FAIL:
		/* N5 */
		sess_sm_new_state(ist, ctx, SS_Q4_FAILED);
		break;
	case SE_CONN_LOGGED_IN:
		/* N10 */
		sess_sm_new_state(ist, ctx, SS_Q3_LOGGED_IN);
		break;
	case SE_SESSION_REINSTATE:
		/* N11 */
		sess_sm_new_state(ist, ctx, SS_Q6_DONE);
		break;
	default:
		ASSERT(0);
		break;
	}
}

static void
sess_sm_q6_done(iscsit_sess_t *ist, sess_event_ctx_t *ctx)
{
	/* Terminal state */
	switch (ctx->se_ctx_event) {
	case SE_CONN_LOGGED_IN:
		/*
		 * It's possible to get this event if we encountered
		 * an SE_SESSION_REINSTATE_EVENT while we were in
		 * SS_Q2_ACTIVE state.  If so we want to update
		 * ist->ist_ffp_conn_count because we know an
		 * SE_CONN_FFP_FAIL or SE_CONN_FFP_DISABLE is on the
		 * way.
		 */
		ist->ist_ffp_conn_count++;
		break;
	case SE_CONN_FFP_FAIL:
	case SE_CONN_FFP_DISABLE:
		ASSERT(ist->ist_ffp_conn_count >= 1);
		ist->ist_ffp_conn_count--;
		break;
	case SE_CONN_FAIL:
		if (ist->ist_conn_count == 0) {
			idm_refcnt_async_wait_ref(&ist->ist_refcnt,
			    &iscsit_sess_unref);
		}
		break;
	default:
		break;
	}
}

static void
sess_sm_q7_error(iscsit_sess_t *ist, sess_event_ctx_t *ctx)
{
	/* Terminal state */
	switch (ctx->se_ctx_event) {
	case SE_CONN_FAIL:
		if (ist->ist_conn_count == 0) {
			idm_refcnt_async_wait_ref(&ist->ist_refcnt,
			    &iscsit_sess_unref);
		}
		break;
	default:
		break;
	}
}

static void
sess_sm_new_state(iscsit_sess_t *ist, sess_event_ctx_t *ctx,
    iscsit_session_state_t new_state)
{
	int t2r_secs;

	/*
	 * Validate new state
	 */
	ASSERT(new_state != SS_UNDEFINED);
	ASSERT3U(new_state, <, SS_MAX_STATE);

	new_state = (new_state < SS_MAX_STATE) ?
	    new_state : SS_UNDEFINED;

	IDM_SM_LOG(CE_NOTE, "sess_sm_new_state: sess %p, evt %s(%d), "
	    "%s(%d) --> %s(%d)\n", (void *) ist,
	    iscsit_se_name[ctx->se_ctx_event], ctx->se_ctx_event,
	    iscsit_ss_name[ist->ist_state], ist->ist_state,
	    iscsit_ss_name[new_state], new_state);

	DTRACE_PROBE3(sess__state__change,
	    iscsit_sess_t *, ist, sess_event_ctx_t *, ctx,
	    iscsit_session_state_t, new_state);

	mutex_enter(&ist->ist_mutex);
	idm_sm_audit_state_change(&ist->ist_state_audit, SAS_ISCSIT_SESS,
	    (int)ist->ist_state, (int)new_state);
	ist->ist_last_state = ist->ist_state;
	ist->ist_state = new_state;
	mutex_exit(&ist->ist_mutex);

	switch (ist->ist_state) {
	case SS_Q1_FREE:
		break;
	case SS_Q2_ACTIVE:
		iscsit_tgt_bind_sess(ist->ist_tgt, ist);
		break;
	case SS_Q3_LOGGED_IN:
		break;
	case SS_Q4_FAILED:
		t2r_secs =
		    ist->ist_failed_conn->ict_op.op_default_time_2_retain;
		ist->ist_state_timeout = timeout(sess_sm_timeout, ist,
		    drv_usectohz(t2r_secs*1000000));
		break;
	case SS_Q5_CONTINUE:
		break;
	case SS_Q6_DONE:
	case SS_Q7_ERROR:
		/*
		 * We won't need our TSIH anymore and it represents an
		 * implicit reference to the global TSIH pool.  Get rid
		 * of it.
		 */
		if (ist->ist_tsih != ISCSI_UNSPEC_TSIH) {
			iscsit_tsih_free(ist->ist_tsih);
		}

		/*
		 * We don't want this session to show up anymore so unbind
		 * it now.  After this call this session cannot have any
		 * references outside itself (implicit or explicit).
		 */
		iscsit_tgt_unbind_sess(ist->ist_tgt, ist);

		/*
		 * If we have more connections bound then more events
		 * are comming so don't wait for idle yet.
		 */
		if (ist->ist_conn_count == 0) {
			idm_refcnt_async_wait_ref(&ist->ist_refcnt,
			    &iscsit_sess_unref);
		}
		break;
	default:
		ASSERT(0);
		/*NOTREACHED*/
	}
}
