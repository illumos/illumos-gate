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
 * Copyright 2011, 2015 Nexenta Systems, Inc. All rights reserved.
 */

#include <sys/cpuvar.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/sysmacros.h>
#include <sys/sdt.h>

#include <sys/socket.h>
#include <sys/strsubr.h>

#include <sys/stmf.h>
#include <sys/stmf_ioctl.h>
#include <sys/portif.h>
#include <sys/idm/idm.h>

#define	ISCSIT_TGT_SM_STRINGS
#include "iscsit.h"
#include "iscsit_isns.h"

typedef struct {
	list_node_t		te_ctx_node;
	iscsit_tgt_event_t	te_ctx_event;
} tgt_event_ctx_t;

static void
tgt_sm_event_dispatch(iscsit_tgt_t *tgt, tgt_event_ctx_t *ctx);

static void
tgt_sm_created(iscsit_tgt_t *tgt, tgt_event_ctx_t *ctx);

static void
tgt_sm_onlining(iscsit_tgt_t *tgt, tgt_event_ctx_t *ctx);

static void
tgt_sm_online(iscsit_tgt_t *tgt, tgt_event_ctx_t *ctx);

static void
tgt_sm_stmf_online(iscsit_tgt_t *tgt, tgt_event_ctx_t *ctx);

static void
tgt_sm_deleting_need_offline(iscsit_tgt_t *tgt, tgt_event_ctx_t *ctx);

static void
tgt_sm_offlining(iscsit_tgt_t *tgt, tgt_event_ctx_t *ctx);

static void
tgt_sm_offline(iscsit_tgt_t *tgt, tgt_event_ctx_t *ctx);

static void
tgt_sm_stmf_offline(iscsit_tgt_t *tgt, tgt_event_ctx_t *ctx);

static void
tgt_sm_deleting_stmf_dereg(iscsit_tgt_t *tgt, tgt_event_ctx_t *ctx);

static void
tgt_sm_deleting_stmf_dereg_fail(iscsit_tgt_t *tgt, tgt_event_ctx_t *ctx);

static void
tgt_sm_deleting(iscsit_tgt_t *tgt, tgt_event_ctx_t *ctx);

static void
iscsit_tgt_dereg_retry(void *arg);

static void
iscsit_tgt_dereg_task(void *arg);

static void
tgt_sm_new_state(iscsit_tgt_t *tgt, tgt_event_ctx_t *ctx,
    iscsit_tgt_state_t new_state);


static iscsit_tgt_t *
iscsit_tgt_create(it_tgt_t *cfg_tgt);

static void
iscsit_tgt_unref(void *tgt);

static void
iscsit_tgt_async_wait_ref(iscsit_tgt_t *tgt, idm_refcnt_cb_t *cb_func);

static void
iscsit_tgt_destroy(iscsit_tgt_t *tgt);

static iscsit_tpgt_t *
iscsit_tgt_lookup_tpgt_locked(iscsit_tgt_t *tgt, uint16_t tag);

static iscsit_tpg_t *
iscsit_tpg_lookup_locked(char *tpg_name);

static iscsit_portal_t *
iscsit_tpg_portal_lookup_locked(iscsit_tpg_t *tpg,
    struct sockaddr_storage *sa);

static idm_status_t
iscsit_tgt_online(iscsit_tgt_t *tgt);

static void
iscsit_tgt_offline(iscsit_tgt_t *tgt);

static idm_status_t
iscsit_tgt_modify(iscsit_tgt_t *tgt, it_tgt_t *cfg_tgt);

static idm_status_t
iscsit_tgt_merge_tpgt(iscsit_tgt_t *tgt, it_tgt_t *cfg_tgt,
    list_t *tpgt_del_list);

static iscsit_tpgt_t *
iscsit_tpgt_create(it_tpgt_t *cfg_tpgt);

static iscsit_tpgt_t *
iscsit_tpgt_create_default();

static void
iscsit_tpgt_destroy(iscsit_tpgt_t *tpgt);

static iscsit_tpg_t *
iscsit_tpg_create(it_tpg_t *tpg);

static void
iscsit_tpg_modify(iscsit_tpg_t *tpg, it_tpg_t *cfg_tpg);

static void
iscsit_tpg_destroy(iscsit_tpg_t *tpg);

static iscsit_portal_t *
iscsit_portal_create(iscsit_tpg_t *tpg, struct sockaddr_storage *sa);

static void
iscsit_portal_delete(iscsit_portal_t *portal);

static idm_status_t
iscsit_portal_online(iscsit_portal_t *portal);

static void
iscsit_portal_offline(iscsit_portal_t *portal);



/*
 * Target state machine
 */

void
iscsit_tgt_sm_event(iscsit_tgt_t *tgt, iscsit_tgt_event_t event)
{
	mutex_enter(&tgt->target_mutex);
	tgt_sm_event_locked(tgt, event);
	mutex_exit(&tgt->target_mutex);
}

void
tgt_sm_event_locked(iscsit_tgt_t *tgt, iscsit_tgt_event_t event)
{
	tgt_event_ctx_t *ctx;

	iscsit_tgt_hold(tgt);

	ctx = kmem_zalloc(sizeof (*ctx), KM_SLEEP);

	ctx->te_ctx_event = event;

	list_insert_tail(&tgt->target_events, ctx);
	/*
	 * Use the target_sm_busy flag to keep the state machine single
	 * threaded.  This also serves as recursion avoidance since this
	 * flag will always be set if we call iscsit_tgt_sm_event from
	 * within the state machine code.
	 */
	if (!tgt->target_sm_busy) {
		tgt->target_sm_busy = B_TRUE;
		while (!list_is_empty(&tgt->target_events)) {
			ctx = list_head(&tgt->target_events);
			list_remove(&tgt->target_events, ctx);
			idm_sm_audit_event(&tgt->target_state_audit,
			    SAS_ISCSIT_TGT, (int)tgt->target_state,
			    (int)ctx->te_ctx_event, 0);
			mutex_exit(&tgt->target_mutex);
			tgt_sm_event_dispatch(tgt, ctx);
			mutex_enter(&tgt->target_mutex);
		}
		tgt->target_sm_busy = B_FALSE;

	}

	iscsit_tgt_rele(tgt);
}

static void
tgt_sm_event_dispatch(iscsit_tgt_t *tgt, tgt_event_ctx_t *ctx)
{
	DTRACE_PROBE2(tgt__event, iscsit_tgt_t *, tgt,
	    tgt_event_ctx_t *, ctx);

	IDM_SM_LOG(CE_NOTE, "tgt_sm_event_dispatch: tgt %p event %s(%d)",
	    (void *)tgt, iscsit_te_name[ctx->te_ctx_event], ctx->te_ctx_event);

	/* State independent actions */
	switch (ctx->te_ctx_event) {
	case TE_DELETE:
		tgt->target_deleting = B_TRUE;
		break;
	}

	/* State dependent actions */
	switch (tgt->target_state) {
	case TS_CREATED:
		tgt_sm_created(tgt, ctx);
		break;
	case TS_ONLINING:
		tgt_sm_onlining(tgt, ctx);
		break;
	case TS_ONLINE:
		tgt_sm_online(tgt, ctx);
		break;
	case TS_STMF_ONLINE:
		tgt_sm_stmf_online(tgt, ctx);
		break;
	case TS_DELETING_NEED_OFFLINE:
		tgt_sm_deleting_need_offline(tgt, ctx);
		break;
	case TS_OFFLINING:
		tgt_sm_offlining(tgt, ctx);
		break;
	case TS_OFFLINE:
		tgt_sm_offline(tgt, ctx);
		break;
	case TS_STMF_OFFLINE:
		tgt_sm_stmf_offline(tgt, ctx);
		break;
	case TS_DELETING_STMF_DEREG:
		tgt_sm_deleting_stmf_dereg(tgt, ctx);
		break;
	case TS_DELETING_STMF_DEREG_FAIL:
		tgt_sm_deleting_stmf_dereg_fail(tgt, ctx);
		break;
	case TS_DELETING:
		tgt_sm_deleting(tgt, ctx);
		break;
	default:
		ASSERT(0);
	}

	kmem_free(ctx, sizeof (*ctx));
}

static void
tgt_sm_created(iscsit_tgt_t *tgt, tgt_event_ctx_t *ctx)
{
	stmf_change_status_t	scs;

	switch (ctx->te_ctx_event) {
	case TE_STMF_ONLINE_REQ:
		tgt_sm_new_state(tgt, ctx, TS_ONLINING);
		break;
	case TE_DELETE:
		tgt_sm_new_state(tgt, ctx, TS_DELETING_STMF_DEREG);
		break;
	case TE_STMF_OFFLINE_REQ:
		/*
		 * We're already offline but update to an equivelant
		 * state just to note that STMF talked to us.
		 */
		scs.st_completion_status = STMF_SUCCESS;
		scs.st_additional_info = NULL;
		tgt_sm_new_state(tgt, ctx, TS_OFFLINE);
		(void) stmf_ctl(STMF_CMD_LPORT_OFFLINE_COMPLETE,
		    tgt->target_stmf_lport, &scs);
		break;
	case TE_STMF_ONLINE_COMPLETE_ACK:
	case TE_STMF_OFFLINE_COMPLETE_ACK:
		/* Ignore */
		break;
	default:
		ASSERT(0);
	}
}

static void
tgt_sm_onlining(iscsit_tgt_t *tgt, tgt_event_ctx_t *ctx)
{
	stmf_change_status_t	scs;

	switch (ctx->te_ctx_event) {
	case TE_ONLINE_SUCCESS:
		tgt_sm_new_state(tgt, ctx, TS_ONLINE);
		break;
	case TE_ONLINE_FAIL:
		tgt_sm_new_state(tgt, ctx, TS_STMF_OFFLINE);
		break;
	case TE_DELETE:
		/* TE_DELETE is handled in tgt_sm_event_dispatch() */
		break;
	case TE_STMF_ONLINE_REQ:
	case TE_STMF_OFFLINE_REQ:
		/*
		 * We can't complete STMF's request since we are busy going
		 * online.
		 */
		scs.st_completion_status = STMF_INVALID_ARG;
		scs.st_additional_info = NULL;
		(void) stmf_ctl((ctx->te_ctx_event == TE_STMF_ONLINE_REQ) ?
		    STMF_CMD_LPORT_ONLINE_COMPLETE :
		    STMF_CMD_LPORT_OFFLINE_COMPLETE,
		    tgt->target_stmf_lport, &scs);
		break;
	case TE_STMF_ONLINE_COMPLETE_ACK:
	case TE_STMF_OFFLINE_COMPLETE_ACK:
		/* Ignore */
		break;
	default:
		ASSERT(0);
	}
}

static void
tgt_sm_online(iscsit_tgt_t *tgt, tgt_event_ctx_t *ctx)
{
	stmf_change_status_t	scs;

	switch (ctx->te_ctx_event) {
	case TE_STMF_ONLINE_COMPLETE_ACK:
		if (tgt->target_deleting) {
			tgt_sm_new_state(tgt, ctx, TS_DELETING_NEED_OFFLINE);
		} else {
			tgt_sm_new_state(tgt, ctx, TS_STMF_ONLINE);
		}
		break;
	case TE_DELETE:
		/* TE_DELETE is handled in tgt_sm_event_dispatch() */
		break;
	case TE_STMF_ONLINE_REQ:
	case TE_STMF_OFFLINE_REQ:
		/*
		 * We can't complete STMF's request since we are busy going
		 * online (waiting for acknowlegement from STMF)
		 */
		scs.st_completion_status = STMF_INVALID_ARG;
		scs.st_additional_info = NULL;
		(void) stmf_ctl((ctx->te_ctx_event == TE_STMF_ONLINE_REQ) ?
		    STMF_CMD_LPORT_ONLINE_COMPLETE :
		    STMF_CMD_LPORT_OFFLINE_COMPLETE,
		    tgt->target_stmf_lport, &scs);
		break;
	case TE_STMF_OFFLINE_COMPLETE_ACK:
		/* Ignore */
		break;
	default:
		ASSERT(0);
	}
}


static void
tgt_sm_stmf_online(iscsit_tgt_t *tgt, tgt_event_ctx_t *ctx)
{
	stmf_change_status_t	scs;

	/* Deregister target with iSNS whenever we leave this state */

	switch (ctx->te_ctx_event) {
	case TE_DELETE:
		(void) iscsit_isns_deregister(tgt);
		tgt_sm_new_state(tgt, ctx, TS_DELETING_NEED_OFFLINE);
		break;
	case TE_STMF_OFFLINE_REQ:
		(void) iscsit_isns_deregister(tgt);
		tgt_sm_new_state(tgt, ctx, TS_OFFLINING);
		break;
	case TE_STMF_ONLINE_REQ:
		/* Already online */
		scs.st_completion_status = STMF_ALREADY;
		scs.st_additional_info = NULL;
		(void) stmf_ctl(STMF_CMD_LPORT_ONLINE_COMPLETE,
		    tgt->target_stmf_lport, &scs);
		break;
	case TE_STMF_ONLINE_COMPLETE_ACK:
	case TE_STMF_OFFLINE_COMPLETE_ACK:
		/* Ignore */
		break;
	default:
		ASSERT(0);
	}
}


static void
tgt_sm_deleting_need_offline(iscsit_tgt_t *tgt, tgt_event_ctx_t *ctx)
{
	stmf_change_status_t	scs;

	switch (ctx->te_ctx_event) {
	case TE_STMF_OFFLINE_REQ:
		tgt_sm_new_state(tgt, ctx, TS_OFFLINING);
		break;
	case TE_DELETE:
		/* TE_DELETE is handled in tgt_sm_event_dispatch() */
		break;
	case TE_STMF_ONLINE_REQ:
		/*
		 * We can't complete STMF's request since we need to be offlined
		 */
		scs.st_completion_status = STMF_INVALID_ARG;
		scs.st_additional_info = NULL;
		(void) stmf_ctl(STMF_CMD_LPORT_ONLINE_COMPLETE,
		    tgt->target_stmf_lport, &scs);
		break;
	case TE_STMF_ONLINE_COMPLETE_ACK:
	case TE_STMF_OFFLINE_COMPLETE_ACK:
		/* Ignore */
		break;
	default:
		ASSERT(0);
	}
}


static void
tgt_sm_offlining(iscsit_tgt_t *tgt, tgt_event_ctx_t *ctx)
{
	stmf_change_status_t	scs;

	switch (ctx->te_ctx_event) {
	case TE_OFFLINE_COMPLETE:
		tgt_sm_new_state(tgt, ctx, TS_OFFLINE);
		break;
	case TE_DELETE:
		/* TE_DELETE is handled in tgt_sm_event_dispatch() */
		break;
	case TE_STMF_ONLINE_REQ:
	case TE_STMF_OFFLINE_REQ:
		/*
		 * We can't complete STMF's request since we are busy going
		 * offline.
		 */
		scs.st_completion_status = STMF_INVALID_ARG;
		scs.st_additional_info = NULL;
		(void) stmf_ctl((ctx->te_ctx_event == TE_STMF_ONLINE_REQ) ?
		    STMF_CMD_LPORT_ONLINE_COMPLETE :
		    STMF_CMD_LPORT_OFFLINE_COMPLETE,
		    tgt->target_stmf_lport, &scs);
		break;
	case TE_STMF_ONLINE_COMPLETE_ACK:
	case TE_STMF_OFFLINE_COMPLETE_ACK:
		/* Ignore */
		break;
	default:
		ASSERT(0);
	}
}


static void
tgt_sm_offline(iscsit_tgt_t *tgt, tgt_event_ctx_t *ctx)
{
	stmf_change_status_t	scs;

	switch (ctx->te_ctx_event) {
	case TE_STMF_OFFLINE_COMPLETE_ACK:
		if (tgt->target_deleting) {
			tgt_sm_new_state(tgt, ctx, TS_DELETING_STMF_DEREG);
		} else {
			tgt_sm_new_state(tgt, ctx, TS_STMF_OFFLINE);
		}
		break;
	case TE_DELETE:
		/* TE_DELETE is handled in tgt_sm_event_dispatch() */
		break;
	case TE_STMF_ONLINE_REQ:
	case TE_STMF_OFFLINE_REQ:
		/*
		 * We can't complete STMF's request since we are busy going
		 * offline.
		 */
		scs.st_completion_status = STMF_INVALID_ARG;
		scs.st_additional_info = NULL;
		(void) stmf_ctl((ctx->te_ctx_event == TE_STMF_ONLINE_REQ) ?
		    STMF_CMD_LPORT_ONLINE_COMPLETE :
		    STMF_CMD_LPORT_OFFLINE_COMPLETE,
		    tgt->target_stmf_lport, &scs);
		break;
	case TE_STMF_ONLINE_COMPLETE_ACK:
		/* Ignore */
		break;
	default:
		ASSERT(0);
	}
}


static void
tgt_sm_stmf_offline(iscsit_tgt_t *tgt, tgt_event_ctx_t *ctx)
{
	stmf_change_status_t	scs;

	switch (ctx->te_ctx_event) {
	case TE_STMF_ONLINE_REQ:
		tgt_sm_new_state(tgt, ctx, TS_ONLINING);
		break;
	case TE_DELETE:
		tgt_sm_new_state(tgt, ctx, TS_DELETING_STMF_DEREG);
		break;
	case TE_STMF_OFFLINE_REQ:
		/* Already offline */
		scs.st_completion_status = STMF_ALREADY;
		scs.st_additional_info = NULL;
		(void) stmf_ctl(STMF_CMD_LPORT_OFFLINE_COMPLETE,
		    tgt->target_stmf_lport, &scs);
		break;
	case TE_STMF_ONLINE_COMPLETE_ACK:
	case TE_STMF_OFFLINE_COMPLETE_ACK:
		/* Ignore */
		break;
	default:
		ASSERT(0);
	}
}


static void
tgt_sm_deleting_stmf_dereg(iscsit_tgt_t *tgt, tgt_event_ctx_t *ctx)
{
	stmf_change_status_t	scs;

	/* Terminal state, no events */
	switch (ctx->te_ctx_event) {
	case TE_STMF_ONLINE_REQ:
	case TE_STMF_OFFLINE_REQ:
		/*
		 * We can't complete STMF's request since we are being deleted
		 */
		scs.st_completion_status = STMF_INVALID_ARG;
		scs.st_additional_info = NULL;
		(void) stmf_ctl((ctx->te_ctx_event == TE_STMF_ONLINE_REQ) ?
		    STMF_CMD_LPORT_ONLINE_COMPLETE :
		    STMF_CMD_LPORT_OFFLINE_COMPLETE,
		    tgt->target_stmf_lport, &scs);
		break;
	case TE_STMF_ONLINE_COMPLETE_ACK:
	case TE_STMF_OFFLINE_COMPLETE_ACK:
		/* Ignore */
		break;
	case TE_STMF_DEREG_SUCCESS:
		tgt_sm_new_state(tgt, ctx, TS_DELETING);
		break;
	case TE_STMF_DEREG_FAIL:
		tgt_sm_new_state(tgt, ctx, TS_DELETING_STMF_DEREG_FAIL);
		break;
	default:
		ASSERT(0);
	}
}

static void
tgt_sm_deleting_stmf_dereg_fail(iscsit_tgt_t *tgt, tgt_event_ctx_t *ctx)
{
	stmf_change_status_t	scs;

	/* Terminal state, no events */
	switch (ctx->te_ctx_event) {
	case TE_STMF_ONLINE_REQ:
	case TE_STMF_OFFLINE_REQ:
		/*
		 * We can't complete STMF's request since we are being deleted
		 */
		scs.st_completion_status = STMF_INVALID_ARG;
		scs.st_additional_info = NULL;
		(void) stmf_ctl((ctx->te_ctx_event == TE_STMF_ONLINE_REQ) ?
		    STMF_CMD_LPORT_ONLINE_COMPLETE :
		    STMF_CMD_LPORT_OFFLINE_COMPLETE,
		    tgt->target_stmf_lport, &scs);
		break;
	case TE_STMF_ONLINE_COMPLETE_ACK:
	case TE_STMF_OFFLINE_COMPLETE_ACK:
		/* Ignore */
		break;
	case TE_STMF_DEREG_RETRY:
		tgt_sm_new_state(tgt, ctx, TS_DELETING_STMF_DEREG);
		break;
	default:
		ASSERT(0);
	}
}

static void
tgt_sm_deleting(iscsit_tgt_t *tgt, tgt_event_ctx_t *ctx)
{
	stmf_change_status_t	scs;

	/* Terminal state, no events */
	switch (ctx->te_ctx_event) {
	case TE_STMF_ONLINE_REQ:
	case TE_STMF_OFFLINE_REQ:
		/*
		 * We can't complete STMF's request since we are being deleted
		 */
		scs.st_completion_status = STMF_INVALID_ARG;
		scs.st_additional_info = NULL;
		(void) stmf_ctl((ctx->te_ctx_event == TE_STMF_ONLINE_REQ) ?
		    STMF_CMD_LPORT_ONLINE_COMPLETE :
		    STMF_CMD_LPORT_OFFLINE_COMPLETE,
		    tgt->target_stmf_lport, &scs);
		break;
	case TE_STMF_ONLINE_COMPLETE_ACK:
	case TE_STMF_OFFLINE_COMPLETE_ACK:
		/* Ignore */
		break;
	default:
		ASSERT(0);
	}
}


static void
iscsit_tgt_dereg_retry(void *arg)
{
	iscsit_tgt_t *tgt = arg;

	/*
	 * Rather than guaranteeing the target state machine code will not
	 * block for long periods of time (tying up this callout thread)
	 * we will queue a task on the taskq to send the retry event.
	 * If it fails we'll setup another timeout and try again later.
	 */
	if (taskq_dispatch(iscsit_global.global_dispatch_taskq,
	    iscsit_tgt_dereg_task, tgt, DDI_NOSLEEP) == NULL) {
		/* Dispatch failed, try again later */
		(void) timeout(iscsit_tgt_dereg_retry, tgt,
		    drv_usectohz(TGT_DEREG_RETRY_SECONDS * 1000000));
	}
}

static void
iscsit_tgt_dereg_task(void *arg)
{
	iscsit_tgt_t *tgt = arg;

	iscsit_tgt_sm_event(tgt, TE_STMF_DEREG_RETRY);
}

static void
tgt_sm_new_state(iscsit_tgt_t *tgt, tgt_event_ctx_t *ctx,
    iscsit_tgt_state_t new_state)
{
	stmf_local_port_t		*lport = tgt->target_stmf_lport;
	stmf_change_status_t		scs;
	stmf_state_change_info_t	sci;
	idm_status_t			idmrc;
	stmf_status_t			stmfrc;

	scs.st_completion_status = STMF_SUCCESS;
	scs.st_additional_info = NULL;

	/*
	 * Validate new state
	 */
	ASSERT(new_state != TS_UNDEFINED);
	ASSERT3U(new_state, <, TS_MAX_STATE);

	new_state = (new_state < TS_MAX_STATE) ?
	    new_state : TS_UNDEFINED;

	IDM_SM_LOG(CE_NOTE, "tgt_sm_new_state: tgt %p, %s(%d) --> %s(%d)\n",
	    (void *) tgt, iscsit_ts_name[tgt->target_state], tgt->target_state,
	    iscsit_ts_name[new_state], new_state);
	DTRACE_PROBE3(target__state__change,
	    iscsit_tgt_t *, tgt, tgt_event_ctx_t *, ctx,
	    iscsit_tgt_state_t, new_state);

	mutex_enter(&tgt->target_mutex);
	idm_sm_audit_state_change(&tgt->target_state_audit, SAS_ISCSIT_TGT,
	    (int)tgt->target_state, (int)new_state);
	tgt->target_last_state = tgt->target_state;
	tgt->target_state = new_state;
	mutex_exit(&tgt->target_mutex);

	switch (tgt->target_state) {
	case TS_ONLINING:
		idmrc = iscsit_tgt_online(tgt);
		if (idmrc != IDM_STATUS_SUCCESS) {
			scs.st_completion_status = STMF_TARGET_FAILURE;
			iscsit_tgt_sm_event(tgt, TE_ONLINE_FAIL);
		} else {
			iscsit_tgt_sm_event(tgt, TE_ONLINE_SUCCESS);
		}
		/*
		 * Let STMF know the how the online operation completed.
		 * STMF will respond with an acknowlege later
		 */
		(void) stmf_ctl(STMF_CMD_LPORT_ONLINE_COMPLETE, lport, &scs);
		break;
	case TS_ONLINE:
		break;
	case TS_STMF_ONLINE:
		(void) iscsit_isns_register(tgt);
		break;
	case TS_DELETING_NEED_OFFLINE:
		sci.st_rflags = STMF_RFLAG_STAY_OFFLINED;
		sci.st_additional_info = "Offline for delete";
		(void) stmf_ctl(STMF_CMD_LPORT_OFFLINE, lport, &sci);
		break;
	case TS_OFFLINING:
		/* Async callback generates completion event */
		iscsit_tgt_offline(tgt);
		break;
	case TS_OFFLINE:
		break;
	case TS_STMF_OFFLINE:
		break;
	case TS_DELETING_STMF_DEREG:
		stmfrc = stmf_deregister_local_port(tgt->target_stmf_lport);
		if (stmfrc == STMF_SUCCESS) {
			iscsit_tgt_sm_event(tgt, TE_STMF_DEREG_SUCCESS);
		} else {
			iscsit_tgt_sm_event(tgt, TE_STMF_DEREG_FAIL);
		}
		break;
	case TS_DELETING_STMF_DEREG_FAIL:
		/* Retry dereg in 1 second */
		(void) timeout(iscsit_tgt_dereg_retry, tgt,
		    drv_usectohz(TGT_DEREG_RETRY_SECONDS * 1000000));
		break;
	case TS_DELETING:
		iscsit_tgt_async_wait_ref(tgt, iscsit_tgt_unref);
		break;
	default:
		ASSERT(0);
	}
}


/*
 * Target, TPGT, TPG utility functions
 */

it_cfg_status_t
iscsit_config_merge_tgt(it_config_t *cfg)
{
	it_tgt_t	*cfg_tgt;
	iscsit_tgt_t	*tgt, *next_tgt;
	it_cfg_status_t	itrc = ITCFG_SUCCESS;


	/*
	 * 1. >> Lock <<
	 * 2. Removing deleted objects
	 * 3. Add deleted targets to global delete list
	 * 4. "delete" event to target state machine
	 * 5. >> Unlock <<
	 * 6. Create new targets, update modified targets
	 */
	for (tgt = avl_first(&iscsit_global.global_target_list);
	    tgt != NULL;
	    tgt = next_tgt) {
		next_tgt = AVL_NEXT(&iscsit_global.global_target_list, tgt);

		if (it_tgt_lookup(cfg, tgt->target_name) == NULL) {
			avl_remove(&iscsit_global.global_target_list, tgt);
			list_insert_tail(
			    &iscsit_global.global_deleted_target_list, tgt);
			iscsit_tgt_sm_event(tgt, TE_DELETE);
		}
	}

	/* Now walk through the list of configured targets */
	for (cfg_tgt = cfg->config_tgt_list;
	    cfg_tgt != NULL;
	    cfg_tgt = cfg_tgt->tgt_next) {
		/* See if we have an existing target */
		tgt = iscsit_tgt_lookup_locked(cfg_tgt->tgt_name);

		if (tgt == NULL) {
			tgt = iscsit_tgt_create(cfg_tgt);
			if (tgt == NULL)
				return (ITCFG_TGT_CREATE_ERR);
			avl_add(&iscsit_global.global_target_list, tgt);
		} else {
			if (iscsit_tgt_modify(tgt, cfg_tgt) !=
			    IDM_STATUS_SUCCESS)
				itrc = ITCFG_MISC_ERR;
			iscsit_tgt_rele(tgt);
		}
	}

	/*
	 * Targets on the iscsit_global.global_deleted_target_list will remove
	 * and destroy themselves when their associated state machines reach
	 * the TS_DELETED state and all references are released.
	 */
	return (itrc);
}

iscsit_tgt_t *
iscsit_tgt_lookup(char *target_name)
{
	iscsit_tgt_t	*result;

	ISCSIT_GLOBAL_LOCK(RW_READER);
	result = iscsit_tgt_lookup_locked(target_name);
	ISCSIT_GLOBAL_UNLOCK();

	return (result);
}

iscsit_tgt_t *
iscsit_tgt_lookup_locked(char *target_name)
{
	iscsit_tgt_t	tmp_tgt;
	iscsit_tgt_t	*result;

	/*
	 * Use a dummy target for lookup, filling in all fields used in AVL
	 * comparison.
	 */
	tmp_tgt.target_name = target_name;
	if ((result = avl_find(&iscsit_global.global_target_list,
	    &tmp_tgt, NULL)) != NULL) {
		iscsit_tgt_hold(result);
	}

	return (result);
}

iscsit_tgt_t *
iscsit_tgt_create(it_tgt_t *cfg_tgt)
{
	iscsit_tgt_t		*result;
	stmf_local_port_t	*lport;
	char			*alias;

	/*
	 * Each target is an STMF local port.
	 */
	lport = stmf_alloc(STMF_STRUCT_STMF_LOCAL_PORT,
	    sizeof (iscsit_tgt_t) + sizeof (scsi_devid_desc_t) +
	    strnlen(cfg_tgt->tgt_name, MAX_ISCSI_NODENAMELEN) + 1, 0);
	if (lport == NULL) {
		return (NULL);
	}

	result = lport->lport_port_private;
	result->target_state = TS_CREATED;
	result->target_stmf_lport_registered = 0;
	/* Use pointer arithmetic to find scsi_devid_desc_t */
	result->target_devid = (scsi_devid_desc_t *)(result + 1);
	(void) strcpy((char *)result->target_devid->ident, cfg_tgt->tgt_name);
	result->target_devid->ident_length =
	    strnlen(cfg_tgt->tgt_name, MAX_ISCSI_NODENAMELEN);
	result->target_devid->protocol_id = PROTOCOL_iSCSI;
	result->target_devid->piv = 1;
	result->target_devid->code_set = CODE_SET_ASCII;
	result->target_devid->association = ID_IS_TARGET_PORT;

	/* Store a shortcut to the target name */
	result->target_name = (char *)result->target_devid->ident;
	idm_sm_audit_init(&result->target_state_audit);
	mutex_init(&result->target_mutex, NULL, MUTEX_DEFAULT, NULL);
	avl_create(&result->target_sess_list, iscsit_sess_avl_compare,
	    sizeof (iscsit_sess_t), offsetof(iscsit_sess_t, ist_tgt_ln));
	avl_create(&result->target_tpgt_list, iscsit_tpgt_avl_compare,
	    sizeof (iscsit_tpgt_t), offsetof(iscsit_tpgt_t, tpgt_tgt_ln));
	list_create(&result->target_events, sizeof (tgt_event_ctx_t),
	    offsetof(tgt_event_ctx_t, te_ctx_node));
	idm_refcnt_init(&result->target_refcnt, result);
	idm_refcnt_init(&result->target_sess_refcnt, result);

	/* Set target alias */
	if (nvlist_lookup_string(cfg_tgt->tgt_properties, "alias", &alias) == 0)
		lport->lport_alias = strdup(alias);

	/* Finish initializing local port */
	/*
	 * Would like infinite timeout, but this is about as long as can
	 * be specified to stmf on a 32 bit kernel.
	 */
	lport->lport_abort_timeout = 2000; /* seconds */
	lport->lport_id = result->target_devid;
	lport->lport_pp = iscsit_global.global_pp;
	lport->lport_ds = iscsit_global.global_dbuf_store;
	lport->lport_xfer_data = &iscsit_xfer_scsi_data;
	lport->lport_send_status = &iscsit_send_scsi_status;
	lport->lport_task_free = &iscsit_lport_task_free;
	lport->lport_abort = &iscsit_abort;
	lport->lport_ctl = &iscsit_ctl;
	result->target_stmf_lport = lport;

	/*
	 * We need a global hold until the STMF-ONLINE state machine
	 * completes.  Acquire that hold now, in case we need to call
	 * iscsit_tgt_destroy, which will also release the hold.
	 */
	iscsit_global_hold();

	/*
	 * Additional target modifications from config
	 */
	if (iscsit_tgt_modify(result, cfg_tgt) != IDM_STATUS_SUCCESS) {
		iscsit_tgt_destroy(result);
		return (NULL);
	}

	/*
	 * Register the target with STMF but not until we have all the
	 * TPGT bindings and any other additional config setup.  STMF
	 * may immediately ask us to go online.
	 */
	if (stmf_register_local_port(lport) != STMF_SUCCESS) {
		iscsit_tgt_destroy(result);
		return (NULL);
	}
	result->target_stmf_lport_registered = 1;

	return (result);
}

static idm_status_t
iscsit_tgt_modify(iscsit_tgt_t *tgt, it_tgt_t *cfg_tgt)
{
	idm_status_t	idmrc = IDM_STATUS_SUCCESS;
	list_t		tpgt_del_list;
	char		*alias;

	/* Merge TPGT */
	list_create(&tpgt_del_list, sizeof (iscsit_tpgt_t),
	    offsetof(iscsit_tpgt_t, tpgt_delete_ln));

	mutex_enter(&tgt->target_mutex);
	if (tgt->target_props) {
		nvlist_free(tgt->target_props);
		tgt->target_props = NULL;
	}
	(void) nvlist_dup(cfg_tgt->tgt_properties, &tgt->target_props,
	    KM_SLEEP);

	/* Update alias */
	if (tgt->target_stmf_lport->lport_alias) {
		strfree(tgt->target_stmf_lport->lport_alias);
		tgt->target_stmf_lport->lport_alias = NULL;
	}
	if (nvlist_lookup_string(tgt->target_props, "alias", &alias) == 0)
		tgt->target_stmf_lport->lport_alias = strdup(alias);

	if ((idmrc = iscsit_tgt_merge_tpgt(tgt, cfg_tgt, &tpgt_del_list)) !=
	    IDM_STATUS_SUCCESS) {
		/* This should never happen */
		cmn_err(CE_WARN, "Fail to configure TPGTs for "
		    "target %s, the target modification could not be "
		    "completed.", tgt->target_name);
	}

	mutex_exit(&tgt->target_mutex);

	iscsit_config_destroy_tpgts(&tpgt_del_list);

	/*
	 * If the target is truly modified (not newly created),
	 * inform iSNS to update the target registration.
	 */
	if ((tgt->target_generation > 0) &&
	    (cfg_tgt->tgt_generation > tgt->target_generation)) {
		iscsit_isns_target_update(tgt);
	}

	tgt->target_generation = cfg_tgt->tgt_generation;

	return (idmrc);
}

void
iscsit_config_destroy_tpgts(list_t *tpgt_del_list)
{
	iscsit_tpgt_t	*tpgt, *next_tpgt;

	for (tpgt = list_head(tpgt_del_list);
	    tpgt != NULL;
	    tpgt = next_tpgt) {
		next_tpgt = list_next(tpgt_del_list, tpgt);

		list_remove(tpgt_del_list, tpgt);
		idm_refcnt_wait_ref(&tpgt->tpgt_refcnt);
		iscsit_tpgt_destroy(tpgt);
	}
}

void
iscsit_tgt_unref(void *tgt_void)
{
	iscsit_tgt_t	*tgt = tgt_void;

	ISCSIT_GLOBAL_LOCK(RW_WRITER);
	list_remove(&iscsit_global.global_deleted_target_list, tgt);
	ISCSIT_GLOBAL_UNLOCK();
	iscsit_tgt_destroy(tgt);
}

void
iscsit_tgt_async_wait_ref(iscsit_tgt_t *tgt, idm_refcnt_cb_t *cb_func)
{
	idm_refcnt_async_wait_ref(&tgt->target_refcnt, cb_func);
}

static void
iscsit_tgt_destroy(iscsit_tgt_t *tgt)
{
	iscsit_tpgt_t *tpgt, *next_tpgt;

	ASSERT(tgt->target_state == TS_DELETING ||
	    (tgt->target_state == TS_CREATED &&
	    tgt->target_stmf_lport_registered == 0));

	/*
	 * Destroy all target portal group tags
	 */
	mutex_enter(&tgt->target_mutex);
	for (tpgt = avl_first(&tgt->target_tpgt_list);
	    tpgt != NULL;
	    tpgt = next_tpgt) {
		next_tpgt = AVL_NEXT(&tgt->target_tpgt_list, tpgt);
		avl_remove(&tgt->target_tpgt_list, tpgt);
		iscsit_tpgt_destroy(tpgt);
	}

	if (tgt->target_props) {
		nvlist_free(tgt->target_props);
	}
	mutex_exit(&tgt->target_mutex);

	/*
	 * Destroy target
	 */
	idm_refcnt_destroy(&tgt->target_sess_refcnt);
	idm_refcnt_destroy(&tgt->target_refcnt);
	list_destroy(&tgt->target_events);
	avl_destroy(&tgt->target_tpgt_list);
	avl_destroy(&tgt->target_sess_list);
	mutex_destroy(&tgt->target_mutex);
	if (tgt->target_stmf_lport->lport_alias)
		strfree(tgt->target_stmf_lport->lport_alias);
	stmf_free(tgt->target_stmf_lport); /* Also frees "tgt' */
	iscsit_global_rele();
}

void
iscsit_tgt_hold(iscsit_tgt_t *tgt)
{
	idm_refcnt_hold(&tgt->target_refcnt);
}

void
iscsit_tgt_rele(iscsit_tgt_t *tgt)
{
	idm_refcnt_rele(&tgt->target_refcnt);
}

int
iscsit_tgt_avl_compare(const void *void_tgt1, const void *void_tgt2)
{
	const iscsit_tgt_t	*tgt1 = void_tgt1;
	const iscsit_tgt_t	*tgt2 = void_tgt2;
	int 			result;

	/*
	 * Sort by ISID first then TSIH
	 */
	result = strcmp(tgt1->target_name, tgt2->target_name);
	if (result < 0) {
		return (-1);
	} else if (result > 0) {
		return (1);
	}

	return (0);
}


iscsit_tpgt_t *
iscsit_tgt_lookup_tpgt(iscsit_tgt_t *tgt, uint16_t tag)
{
	iscsit_tpgt_t *result;

	mutex_enter(&tgt->target_mutex);
	result = iscsit_tgt_lookup_tpgt_locked(tgt, tag);
	mutex_exit(&tgt->target_mutex);

	return (result);
}

static iscsit_tpgt_t *
iscsit_tgt_lookup_tpgt_locked(iscsit_tgt_t *tgt, uint16_t tag)
{
	iscsit_tpgt_t	tmp_tpgt;
	iscsit_tpgt_t	*result;

	/* Caller holds tgt->target_mutex */
	tmp_tpgt.tpgt_tag = tag;
	if ((result = avl_find(&tgt->target_tpgt_list, &tmp_tpgt, NULL)) !=
	    NULL) {
		iscsit_tpgt_hold(result);
	}

	return (result);
}

iscsit_portal_t *
iscsit_tgt_lookup_portal(iscsit_tgt_t *tgt, struct sockaddr_storage *sa,
    iscsit_tpgt_t **output_tpgt)
{
	iscsit_tpgt_t 	*tpgt;
	iscsit_portal_t	*portal;

	/* Caller holds tgt->target_mutex */
	ASSERT(mutex_owned(&tgt->target_mutex));
	for (tpgt = avl_first(&tgt->target_tpgt_list);
	    tpgt != NULL;
	    tpgt = AVL_NEXT(&tgt->target_tpgt_list, tpgt)) {
		portal = iscsit_tpg_portal_lookup(tpgt->tpgt_tpg, sa);
		if (portal) {
			iscsit_tpgt_hold(tpgt);
			*output_tpgt = tpgt;
			return (portal);
		}
	}

	return (NULL);
}


void
iscsit_tgt_bind_sess(iscsit_tgt_t *tgt, iscsit_sess_t *sess)
{
	if (tgt) {
		sess->ist_lport = tgt->target_stmf_lport;
		iscsit_tgt_hold(tgt);
		idm_refcnt_hold(&tgt->target_sess_refcnt);
		mutex_enter(&tgt->target_mutex);
		avl_add(&tgt->target_sess_list, sess);
		mutex_exit(&tgt->target_mutex);
	} else {
		/* Discovery session */
		sess->ist_lport = NULL;
		ISCSIT_GLOBAL_LOCK(RW_WRITER);
		avl_add(&iscsit_global.global_discovery_sessions, sess);
		ISCSIT_GLOBAL_UNLOCK();
	}
}

void
iscsit_tgt_unbind_sess(iscsit_tgt_t *tgt, iscsit_sess_t *sess)
{
	if (tgt) {
		mutex_enter(&tgt->target_mutex);
		avl_remove(&tgt->target_sess_list, sess);
		mutex_exit(&tgt->target_mutex);
		sess->ist_tgt = (iscsit_tgt_t *)SESS_UNBOUND_FROM_TGT;
		idm_refcnt_rele(&tgt->target_sess_refcnt);
		iscsit_tgt_rele(tgt);
	} else {
		/* Discovery session */
		ISCSIT_GLOBAL_LOCK(RW_WRITER);
		avl_remove(&iscsit_global.global_discovery_sessions, sess);
		ISCSIT_GLOBAL_UNLOCK();
	}
}

#define	LOCK_FOR_SESS_LOOKUP(lookup_tgt) { 			\
	if ((lookup_tgt) == NULL) {				\
		ISCSIT_GLOBAL_LOCK(RW_READER);			\
	} else {						\
		mutex_enter(&(lookup_tgt)->target_mutex);	\
	}							\
}

#define	UNLOCK_FOR_SESS_LOOKUP(lookup_tgt) { 			\
	if ((lookup_tgt) == NULL) {				\
		ISCSIT_GLOBAL_UNLOCK();				\
	} else {					 	\
		mutex_exit(&(lookup_tgt)->target_mutex); 	\
	}							\
}

iscsit_sess_t *
iscsit_tgt_lookup_sess(iscsit_tgt_t *tgt, char *initiator_name,
    uint8_t *isid, uint16_t tsih, uint16_t tag)
{
	iscsit_sess_t	tmp_sess;
	avl_tree_t	*sess_avl;
	avl_index_t	where;
	iscsit_sess_t	*result;

	/*
	 * If tgt is NULL then we are looking for a discovery session
	 */
	if (tgt == NULL) {
		sess_avl = &iscsit_global.global_discovery_sessions;
	} else {
		sess_avl = &tgt->target_sess_list;
	}

	LOCK_FOR_SESS_LOOKUP(tgt);
	if (avl_numnodes(sess_avl) == NULL) {
		UNLOCK_FOR_SESS_LOOKUP(tgt);
		return (NULL);
	}

	/*
	 * We'll try to find a session matching ISID + TSIH first.  If we
	 * can't find one then we will return the closest match.  If the
	 * caller needs an exact match it must compare the TSIH after
	 * the session is returned.
	 *
	 * The reason we do this "fuzzy matching" is to allow matching
	 * sessions with different TSIH values on the same AVL list.  This
	 * makes session reinstatement much easier since the new session can
	 * live on the list at the same time as the old session is cleaning up.
	 */
	bcopy(isid, tmp_sess.ist_isid, ISCSI_ISID_LEN);
	tmp_sess.ist_initiator_name = initiator_name;
	tmp_sess.ist_tsih = tsih;
	tmp_sess.ist_tpgt_tag = tag;

	result = avl_find(sess_avl, &tmp_sess, &where);
	if (result != NULL) {
		goto found_result;
	}

	/*
	 * avl_find_nearest() may return a result with a different ISID so
	 * we should only return a result if the name and ISID match
	 */
	result = avl_nearest(sess_avl, where, AVL_BEFORE);
	if ((result != NULL) &&
	    (strcmp(result->ist_initiator_name, initiator_name) == 0) &&
	    (memcmp(result->ist_isid, isid, ISCSI_ISID_LEN) == 0) &&
	    (result->ist_tpgt_tag == tag)) {
		goto found_result;
	}

	result = avl_nearest(sess_avl, where, AVL_AFTER);
	if ((result != NULL) &&
	    (strcmp(result->ist_initiator_name, initiator_name) == 0) &&
	    (memcmp(result->ist_isid, isid, ISCSI_ISID_LEN) == 0) &&
	    (result->ist_tpgt_tag == tag)) {
		goto found_result;
	}

	result = NULL;

found_result:
	if ((result != NULL) &&
	    (iscsit_sess_check_hold(result) != IDM_STATUS_SUCCESS)) {
		result = NULL;
	}
	UNLOCK_FOR_SESS_LOOKUP(tgt);
	return (result);
}

static idm_status_t
iscsit_tgt_merge_tpgt(iscsit_tgt_t *tgt, it_tgt_t *cfg_tgt,
    list_t *tpgt_del_list)
{
	iscsit_tpgt_t	*tpgt, *next_tpgt;
	it_tpgt_t	*cfg_tpgt;
	idm_status_t	status = IDM_STATUS_SUCCESS;

	/*
	 * 1. >> Lock <<
	 * 2. Removing all objects and place on a temp list
	 * 3. Add new objects
	 * 4. >> Unlock <<
	 * 5. tpgt_del_list contains deleted objects
	 */
	ASSERT(avl_is_empty(&tgt->target_tpgt_list) ||
	    (tpgt_del_list != NULL));

	if (tpgt_del_list) {
		for (tpgt = avl_first(&tgt->target_tpgt_list);
		    tpgt != NULL; tpgt = next_tpgt) {
			next_tpgt = AVL_NEXT(&tgt->target_tpgt_list, tpgt);
			avl_remove(&tgt->target_tpgt_list, tpgt);
			if (tgt->target_state == TS_STMF_ONLINE) {
				tpgt->tpgt_needs_tpg_offline = B_TRUE;
			}
			list_insert_tail(tpgt_del_list, tpgt);
		}
	}

	if (cfg_tgt->tgt_tpgt_list != NULL) {
		/* Add currently defined TPGTs */
		for (cfg_tpgt = cfg_tgt->tgt_tpgt_list;
		    cfg_tpgt != NULL;
		    cfg_tpgt = cfg_tpgt->tpgt_next) {
			tpgt = iscsit_tpgt_create(cfg_tpgt);
			if (tpgt == NULL) {
				/*
				 * There is a problem in the configuration we
				 * received from the ioctl -- a missing tpg.
				 * All the unbind operations have already
				 * taken place.  To leave the system in a
				 * non-panic'd state, use the default tpgt.
				 */
				status = IDM_STATUS_FAIL;
				continue;
			}
			if (tgt->target_state == TS_STMF_ONLINE) {
				(void) iscsit_tpg_online(tpgt->tpgt_tpg);
			}
			avl_add(&tgt->target_tpgt_list, tpgt);
		}
	}

	/* If no TPGTs defined, add the default TPGT */
	if (avl_numnodes(&tgt->target_tpgt_list) == 0) {
		tpgt = iscsit_tpgt_create_default();
		if (tgt->target_state == TS_STMF_ONLINE) {
			(void) iscsit_tpg_online(tpgt->tpgt_tpg);
		}
		avl_add(&tgt->target_tpgt_list, tpgt);
	}

	return (status);
}

static iscsit_tpgt_t *
iscsit_tpgt_create(it_tpgt_t *cfg_tpgt)
{
	iscsit_tpg_t	*tpg;
	iscsit_tpgt_t	*result;

	/* This takes a reference on the TPG */
	tpg = iscsit_tpg_lookup_locked(cfg_tpgt->tpgt_tpg_name);
	if (tpg == NULL)
		return (NULL);

	result = kmem_zalloc(sizeof (*result), KM_SLEEP);

	result->tpgt_tpg = tpg;
	result->tpgt_tag = cfg_tpgt->tpgt_tag;

	return (result);
}

iscsit_tpgt_t *
iscsit_tpgt_create_default()
{
	iscsit_tpgt_t	*result;

	result = kmem_zalloc(sizeof (*result), KM_SLEEP);

	result->tpgt_tpg = iscsit_global.global_default_tpg;
	iscsit_tpg_hold(result->tpgt_tpg);
	result->tpgt_tag = ISCSIT_DEFAULT_TPGT;

	return (result);
}

void
iscsit_tpgt_destroy(iscsit_tpgt_t *tpgt)
{
	if (tpgt->tpgt_needs_tpg_offline) {
		iscsit_tpg_offline(tpgt->tpgt_tpg);
	}
	iscsit_tpg_rele(tpgt->tpgt_tpg);
	kmem_free(tpgt, sizeof (*tpgt));
}

void
iscsit_tpgt_hold(iscsit_tpgt_t *tpgt)
{
	idm_refcnt_hold(&tpgt->tpgt_refcnt);
}

void
iscsit_tpgt_rele(iscsit_tpgt_t *tpgt)
{
	idm_refcnt_rele(&tpgt->tpgt_refcnt);
}

int
iscsit_tpgt_avl_compare(const void *void_tpgt1, const void *void_tpgt2)
{
	const iscsit_tpgt_t	*tpgt1 = void_tpgt1;
	const iscsit_tpgt_t	*tpgt2 = void_tpgt2;

	if (tpgt1->tpgt_tag < tpgt2->tpgt_tag)
		return (-1);
	else if (tpgt1->tpgt_tag > tpgt2->tpgt_tag)
		return (1);

	return (0);
}

static idm_status_t
iscsit_tgt_online(iscsit_tgt_t *tgt)
{
	iscsit_tpgt_t 		*tpgt, *tpgt_fail;
	idm_status_t		rc;

	mutex_enter(&tgt->target_mutex);

	ASSERT(tgt->target_sess_list.avl_numnodes == 0);
	idm_refcnt_reset(&tgt->target_sess_refcnt);
	for (tpgt = avl_first(&tgt->target_tpgt_list);
	    tpgt != NULL;
	    tpgt = AVL_NEXT(&tgt->target_tpgt_list, tpgt)) {
		rc = iscsit_tpg_online(tpgt->tpgt_tpg);
		if (rc != IDM_STATUS_SUCCESS) {
			tpgt_fail = tpgt;
			goto tgt_online_fail;
		}
	}

	mutex_exit(&tgt->target_mutex);

	return (IDM_STATUS_SUCCESS);

tgt_online_fail:
	/* Offline all the tpgs we successfully onlined up to the failure */
	for (tpgt = avl_first(&tgt->target_tpgt_list);
	    tpgt != tpgt_fail;
	    tpgt = AVL_NEXT(&tgt->target_tpgt_list, tpgt)) {
		iscsit_tpg_offline(tpgt->tpgt_tpg);
	}
	mutex_exit(&tgt->target_mutex);
	return (rc);
}

static void
iscsit_tgt_offline_cb(void *tgt_void)
{
	iscsit_tgt_t *tgt = tgt_void;
	stmf_change_status_t	scs;

	iscsit_tgt_sm_event(tgt, TE_OFFLINE_COMPLETE);

	scs.st_completion_status = STMF_SUCCESS;
	scs.st_additional_info = NULL;
	(void) stmf_ctl(STMF_CMD_LPORT_OFFLINE_COMPLETE,
	    tgt->target_stmf_lport, &scs);
}

static void
iscsit_tgt_offline(iscsit_tgt_t *tgt)
{
	iscsit_tpgt_t 		*tpgt;
	iscsit_sess_t		*ist;

	mutex_enter(&tgt->target_mutex);

	/* Offline target portal groups */
	for (tpgt = avl_first(&tgt->target_tpgt_list);
	    tpgt != NULL;
	    tpgt = AVL_NEXT(&tgt->target_tpgt_list, tpgt)) {
		iscsit_tpg_offline(tpgt->tpgt_tpg);
	}

	/* Close any active sessions */
	for (ist = avl_first(&tgt->target_sess_list);
	    ist != NULL;
	    ist = AVL_NEXT(&tgt->target_sess_list, ist)) {
		/*
		 * This is not a synchronous operation but after all
		 * sessions have been cleaned up there will be no
		 * more session-related holds on the target.
		 */
		iscsit_sess_close(ist);
	}

	mutex_exit(&tgt->target_mutex);

	/*
	 * Wait for all the sessions to quiesce.
	 */
	idm_refcnt_async_wait_ref(&tgt->target_sess_refcnt,
	    &iscsit_tgt_offline_cb);
}

it_cfg_status_t
iscsit_config_merge_tpg(it_config_t *cfg, list_t *tpg_del_list)
{
	it_tpg_t	*cfg_tpg;
	iscsit_tpg_t	*tpg, *next_tpg;

	/*
	 * 1. >> Lock <<
	 * 2. Removing deleted objects and place on a temp list
	 * 3. Add new objects
	 * 4. >> Unlock <<
	 * 5. tpg_del_list contains objects to destroy
	 */
	for (tpg = avl_first(&iscsit_global.global_tpg_list);
	    tpg != NULL;
	    tpg = next_tpg) {
		next_tpg = AVL_NEXT(&iscsit_global.global_tpg_list, tpg);

		if (it_tpg_lookup(cfg, tpg->tpg_name) == NULL) {
			/*
			 * The policy around when to allow a target portal
			 * group to be deleted is implemented in libiscsit.
			 * By the time the request gets to the kernel module
			 * we expect that it conforms to policy so we will
			 * cleanup all references to TPG and destroy it if it
			 * is possible to do so.
			 *
			 */
			avl_remove(&iscsit_global.global_tpg_list, tpg);
			list_insert_tail(tpg_del_list, tpg);
		}
	}

	/* Now walk through the list of configured target portal groups */
	for (cfg_tpg = cfg->config_tpg_list;
	    cfg_tpg != NULL;
	    cfg_tpg = cfg_tpg->tpg_next) {
		/* See if we have an existing target portal group */
		tpg = iscsit_tpg_lookup_locked(cfg_tpg->tpg_name);

		if (tpg == NULL) {
			tpg = iscsit_tpg_create(cfg_tpg);
			ASSERT(tpg != NULL);
			avl_add(&iscsit_global.global_tpg_list, tpg);
		} else {
			mutex_enter(&tpg->tpg_mutex);
			iscsit_tpg_modify(tpg, cfg_tpg);
			mutex_exit(&tpg->tpg_mutex);
			iscsit_tpg_rele(tpg);
		}
	}

	return (ITCFG_SUCCESS);
}


void
iscsit_config_destroy_tpgs(list_t *tpg_del_list)
{
	iscsit_tpg_t	*tpg, *next_tpg;

	/* Now finish destroying the target portal groups */
	for (tpg = list_head(tpg_del_list);
	    tpg != NULL;
	    tpg = next_tpg) {
		next_tpg = list_next(tpg_del_list, tpg);
		list_remove(tpg_del_list, tpg);
		idm_refcnt_wait_ref(&tpg->tpg_refcnt);

		/* Kill it */
		iscsit_tpg_destroy(tpg);
	}
}

iscsit_tpg_t *
iscsit_tpg_lookup(char *tpg_name)
{
	iscsit_tpg_t *result;

	ISCSIT_GLOBAL_LOCK(RW_READER);
	result = iscsit_tpg_lookup_locked(tpg_name);
	ISCSIT_GLOBAL_UNLOCK();

	return (result);
}

static iscsit_tpg_t *
iscsit_tpg_lookup_locked(char *tpg_name)
{
	iscsit_tpg_t	tmp_tpg;
	iscsit_tpg_t	*result;

	(void) strlcpy(tmp_tpg.tpg_name, tpg_name, MAX_ISCSI_NODENAMELEN);
	if ((result = avl_find(&iscsit_global.global_tpg_list,
	    &tmp_tpg, NULL)) != NULL) {
		iscsit_tpg_hold(result);
	}

	return (result);
}

iscsit_tpg_t *
iscsit_tpg_create(it_tpg_t *cfg_tpg)
{
	iscsit_tpg_t *tpg;

	tpg = kmem_zalloc(sizeof (*tpg), KM_SLEEP);

	mutex_init(&tpg->tpg_mutex, NULL, MUTEX_DEFAULT, NULL);
	(void) strlcpy(tpg->tpg_name, cfg_tpg->tpg_name, MAX_TPG_NAMELEN);
	avl_create(&tpg->tpg_portal_list, iscsit_portal_avl_compare,
	    sizeof (iscsit_portal_t), offsetof(iscsit_portal_t, portal_tpg_ln));
	idm_refcnt_init(&tpg->tpg_refcnt, tpg);

	mutex_enter(&tpg->tpg_mutex);
	iscsit_tpg_modify(tpg, cfg_tpg);
	mutex_exit(&tpg->tpg_mutex);
	iscsit_global_hold();

	return (tpg);
}

static void
iscsit_tpg_modify(iscsit_tpg_t *tpg, it_tpg_t *cfg_tpg)
{
	iscsit_portal_t		*portal, *next_portal;
	it_portal_t		*cfg_portal;

	/* Update portals */
	for (portal = avl_first(&tpg->tpg_portal_list);
	    portal != NULL;
	    portal = next_portal) {
		next_portal = AVL_NEXT(&tpg->tpg_portal_list, portal);
		if (it_portal_lookup(cfg_tpg, &portal->portal_addr) == NULL) {
			avl_remove(&tpg->tpg_portal_list, portal);
			iscsit_portal_delete(portal);
			/*
			 * If the last portal is deleted from the target
			 * portal group, then the tpg->tpg_online count
			 * must be decremented. The other two callers of
			 * iscsit_portal_delete() destroy the target portal
			 * after deleting the portal so it is not necessary
			 * to decrement the tpg->tpg_online count.
			 */
			if (avl_is_empty(&tpg->tpg_portal_list)) {
				tpg->tpg_online--;
			}
		}
	}

	for (cfg_portal = cfg_tpg->tpg_portal_list;
	    cfg_portal != NULL;
	    cfg_portal = cfg_portal->portal_next) {
		if ((portal = iscsit_tpg_portal_lookup_locked(tpg,
		    &cfg_portal->portal_addr)) == NULL) {
			(void) iscsit_portal_create(tpg,
			    &cfg_portal->portal_addr);
		} else {
			iscsit_portal_rele(portal);
		}
	}
}

void
iscsit_tpg_destroy(iscsit_tpg_t *tpg)
{
	iscsit_portal_t *portal, *next_portal;

	for (portal = avl_first(&tpg->tpg_portal_list);
	    portal != NULL;
	    portal = next_portal) {
		next_portal = AVL_NEXT(&tpg->tpg_portal_list, portal);
		avl_remove(&tpg->tpg_portal_list, portal);
		iscsit_portal_delete(portal);
	}

	idm_refcnt_wait_ref(&tpg->tpg_refcnt);
	idm_refcnt_destroy(&tpg->tpg_refcnt);
	avl_destroy(&tpg->tpg_portal_list);
	mutex_destroy(&tpg->tpg_mutex);
	kmem_free(tpg, sizeof (*tpg));
	iscsit_global_rele();
}

void
iscsit_tpg_hold(iscsit_tpg_t *tpg)
{
	idm_refcnt_hold(&tpg->tpg_refcnt);
}

void
iscsit_tpg_rele(iscsit_tpg_t *tpg)
{
	idm_refcnt_rele(&tpg->tpg_refcnt);
}

iscsit_tpg_t *
iscsit_tpg_createdefault()
{
	iscsit_tpg_t *tpg;

	tpg = kmem_zalloc(sizeof (*tpg), KM_SLEEP);

	mutex_init(&tpg->tpg_mutex, NULL, MUTEX_DEFAULT, NULL);
	(void) strlcpy(tpg->tpg_name, ISCSIT_DEFAULT_TPG, MAX_TPG_NAMELEN);
	avl_create(&tpg->tpg_portal_list, iscsit_portal_avl_compare,
	    sizeof (iscsit_portal_t), offsetof(iscsit_portal_t, portal_tpg_ln));
	idm_refcnt_init(&tpg->tpg_refcnt, tpg);

	/* Now create default portal */
	if (iscsit_portal_create(tpg, NULL) == NULL) {
		iscsit_tpg_destroy(tpg);
		return (NULL);
	}

	return (tpg);
}

void
iscsit_tpg_destroydefault(iscsit_tpg_t *tpg)
{
	iscsit_portal_t *portal;

	portal = avl_first(&tpg->tpg_portal_list);
	ASSERT(portal != NULL);
	avl_remove(&tpg->tpg_portal_list, portal);
	iscsit_portal_delete(portal);

	idm_refcnt_wait_ref(&tpg->tpg_refcnt);
	idm_refcnt_destroy(&tpg->tpg_refcnt);
	avl_destroy(&tpg->tpg_portal_list);
	mutex_destroy(&tpg->tpg_mutex);
	kmem_free(tpg, sizeof (*tpg));
}

int
iscsit_tpg_avl_compare(const void *void_tpg1, const void *void_tpg2)
{
	const iscsit_tpg_t	*tpg1 = void_tpg1;
	const iscsit_tpg_t	*tpg2 = void_tpg2;
	int 			result;

	/*
	 * Sort by ISID first then TSIH
	 */
	result = strcmp(tpg1->tpg_name, tpg2->tpg_name);
	if (result < 0) {
		return (-1);
	} else if (result > 0) {
		return (1);
	}

	return (0);
}

idm_status_t
iscsit_tpg_online(iscsit_tpg_t *tpg)
{
	iscsit_portal_t *portal, *portal_fail;
	idm_status_t	rc;

	mutex_enter(&tpg->tpg_mutex);
	if (tpg->tpg_online == 0) {
		for (portal = avl_first(&tpg->tpg_portal_list);
		    portal != NULL;
		    portal = AVL_NEXT(&tpg->tpg_portal_list, portal)) {
			rc = iscsit_portal_online(portal);
			if (rc != IDM_STATUS_SUCCESS) {
				portal_fail = portal;
				goto tpg_online_fail;
			}
		}
	}
	tpg->tpg_online++;

	mutex_exit(&tpg->tpg_mutex);
	return (IDM_STATUS_SUCCESS);

tpg_online_fail:
	/* Offline all the portals we successfully onlined up to the failure */
	for (portal = avl_first(&tpg->tpg_portal_list);
	    portal != portal_fail;
	    portal = AVL_NEXT(&tpg->tpg_portal_list, portal)) {
		iscsit_portal_offline(portal);
	}
	mutex_exit(&tpg->tpg_mutex);
	return (rc);
}

void
iscsit_tpg_offline(iscsit_tpg_t *tpg)
{
	iscsit_portal_t *portal;

	mutex_enter(&tpg->tpg_mutex);
	tpg->tpg_online--;
	if (tpg->tpg_online == 0) {
		for (portal = avl_first(&tpg->tpg_portal_list);
		    portal != NULL;
		    portal = AVL_NEXT(&tpg->tpg_portal_list, portal)) {
			iscsit_portal_offline(portal);
		}
	}
	mutex_exit(&tpg->tpg_mutex);
}

iscsit_portal_t *
iscsit_tpg_portal_lookup(iscsit_tpg_t *tpg, struct sockaddr_storage *sa)
{
	iscsit_portal_t	*result;

	mutex_enter(&tpg->tpg_mutex);
	result = iscsit_tpg_portal_lookup_locked(tpg, sa);
	mutex_exit(&tpg->tpg_mutex);

	return (result);
}

static iscsit_portal_t *
iscsit_tpg_portal_lookup_locked(iscsit_tpg_t *tpg,
    struct sockaddr_storage *sa)
{
	iscsit_portal_t	tmp_portal;
	iscsit_portal_t	*result;

	/* Caller holds tpg->tpg_mutex */
	bcopy(sa, &tmp_portal.portal_addr, sizeof (*sa));
	if ((result = avl_find(&tpg->tpg_portal_list, &tmp_portal, NULL)) !=
	    NULL) {
		iscsit_portal_hold(result);
	}

	return (result);
}

iscsit_portal_t *
iscsit_portal_create(iscsit_tpg_t *tpg, struct sockaddr_storage *sa)
{
	iscsit_portal_t *portal;

	portal = kmem_zalloc(sizeof (*portal), KM_SLEEP);
	/*
	 * If (sa == NULL) then we are being asked to create the default
	 * portal -- targets will use this portal when no portals are
	 * explicitly configured.
	 */
	if (sa == NULL) {
		portal->portal_default = B_TRUE;
	} else {
		portal->portal_default = B_FALSE;
		bcopy(sa, &portal->portal_addr, sizeof (*sa));
	}

	idm_refcnt_init(&portal->portal_refcnt, portal);

	/*
	 * Add this portal to the list
	 */
	avl_add(&tpg->tpg_portal_list, portal);

	return (portal);
}

void
iscsit_portal_delete(iscsit_portal_t *portal)
{
	if (portal->portal_online > 0) {
		iscsit_portal_offline(portal);
	}

	if (portal->portal_online == 0) {
		ASSERT(portal->portal_svc == NULL);
		idm_refcnt_destroy(&portal->portal_refcnt);
		kmem_free(portal, sizeof (*portal));
	}
}

void
iscsit_portal_hold(iscsit_portal_t *portal)
{
	idm_refcnt_hold(&portal->portal_refcnt);
}

void
iscsit_portal_rele(iscsit_portal_t *portal)
{
	idm_refcnt_rele(&portal->portal_refcnt);
}

int
iscsit_portal_avl_compare(const void *void_portal1, const void *void_portal2)
{
	const iscsit_portal_t			*portal1 = void_portal1;
	const iscsit_portal_t			*portal2 = void_portal2;
	const struct sockaddr_storage		*ss1, *ss2;
	const struct in_addr			*in1, *in2;
	const struct in6_addr			*in61, *in62;
	int i;

	/*
	 * Compare ports, then address family, then ip address
	 */
	ss1 = &portal1->portal_addr;
	ss2 = &portal2->portal_addr;
	if (((struct sockaddr_in *)ss1)->sin_port !=
	    ((struct sockaddr_in *)ss2)->sin_port) {
		if (((struct sockaddr_in *)ss1)->sin_port >
		    ((struct sockaddr_in *)ss2)->sin_port)
			return (1);
		else
			return (-1);
	}

	/*
	 * ports are the same
	 */
	if (ss1->ss_family != ss2->ss_family) {
		if (ss1->ss_family == AF_INET)
			return (1);
		else
			return (-1);
	}
	/*
	 * address families are the same
	 */
	if (ss1->ss_family == AF_INET) {
		in1 = &((struct sockaddr_in *)ss1)->sin_addr;
		in2 = &((struct sockaddr_in *)ss2)->sin_addr;

		if (in1->s_addr > in2->s_addr)
			return (1);
		else if (in1->s_addr < in2->s_addr)
			return (-1);
		else
			return (0);
	} else if (ss1->ss_family == AF_INET6) {
		in61 = &((struct sockaddr_in6 *)ss1)->sin6_addr;
		in62 = &((struct sockaddr_in6 *)ss2)->sin6_addr;

		for (i = 0; i < 4; i++) {
			if (in61->s6_addr32[i] > in62->s6_addr32[i])
				return (1);
			else if (in61->s6_addr32[i] < in62->s6_addr32[i])
				return (-1);
		}
		return (0);
	} else
		cmn_err(CE_WARN,
		    "iscsit_portal_avl_compare: unknown ss_family %d",
		    ss1->ss_family);

	return (1);
}


idm_status_t
iscsit_portal_online(iscsit_portal_t *portal)
{
	idm_status_t rc = 0;
	idm_svc_t	*svc;
	idm_svc_req_t	sr;
	uint16_t	port;
	struct sockaddr_in *sin;

	/* Caller holds parent TPG mutex */
	if (portal->portal_online == 0) {
		/*
		 * If there is no existing IDM service instance for this port,
		 * create one.  If the service exists, then the lookup,
		 * creates a reference on the existing service.
		 */
		sin = (struct sockaddr_in *)&portal->portal_addr;
		port = ntohs(sin->sin_port);
		if (port == 0)
			port = ISCSI_LISTEN_PORT;
		ASSERT(portal->portal_svc == NULL);
		if ((svc = idm_tgt_svc_lookup(port)) == NULL) {
			sr.sr_port = port;
			sr.sr_li = iscsit_global.global_li;
			sr.sr_conn_ops.icb_rx_scsi_cmd = &iscsit_op_scsi_cmd;
			sr.sr_conn_ops.icb_rx_scsi_rsp = &iscsit_rx_scsi_rsp;
			sr.sr_conn_ops.icb_rx_misc = &iscsit_rx_pdu;
			sr.sr_conn_ops.icb_rx_error = &iscsit_rx_pdu_error;
			sr.sr_conn_ops.icb_task_aborted = &iscsit_task_aborted;
			sr.sr_conn_ops.icb_client_notify =
			    &iscsit_client_notify;
			sr.sr_conn_ops.icb_build_hdr = &iscsit_build_hdr;
			sr.sr_conn_ops.icb_update_statsn =
			    &iscsit_update_statsn;
			sr.sr_conn_ops.icb_keepalive = &iscsit_keepalive;

			if (idm_tgt_svc_create(&sr, &svc) !=
			    IDM_STATUS_SUCCESS) {
				return (IDM_STATUS_FAIL);
			}

			/* Get reference on the service we just created */
			idm_tgt_svc_hold(svc);
		}
		if ((rc = idm_tgt_svc_online(svc)) != IDM_STATUS_SUCCESS) {
			idm_tgt_svc_rele_and_destroy(svc);
			return (IDM_STATUS_FAIL);
		}
		portal->portal_svc = svc;

		/*
		 * Only call iSNS for first online
		 */
		iscsit_isns_portal_online(portal);
	}

	portal->portal_online++;

	return (rc);
}

void
iscsit_portal_offline(iscsit_portal_t *portal)
{
	portal->portal_online--;

	if (portal->portal_online == 0) {
		/*
		 * Only call iSNS for last offline
		 */
		iscsit_isns_portal_offline(portal);
		idm_tgt_svc_offline(portal->portal_svc);
		/* If service is unreferenced, destroy it too */
		idm_tgt_svc_rele_and_destroy(portal->portal_svc);
		portal->portal_svc = NULL;
	}

}

it_cfg_status_t
iscsit_config_merge_ini(it_config_t *cfg)
{
	iscsit_ini_t	*ini, *next_ini;
	it_ini_t	*cfg_ini;

	/*
	 * Initiator objects are so simple we will just destroy all the current
	 * objects and build new ones.  Nothing should ever reference an
	 * initator object.. instead just lookup the initiator object and
	 * grab the properties while holding the global config lock.
	 */
	for (ini = avl_first(&iscsit_global.global_ini_list);
	    ini != NULL;
	    ini = next_ini) {
		next_ini = AVL_NEXT(&iscsit_global.global_ini_list, ini);
		avl_remove(&iscsit_global.global_ini_list, ini);
		nvlist_free(ini->ini_props);
		kmem_free(ini, sizeof (*ini));
		iscsit_global_rele();
	}

	for (cfg_ini = cfg->config_ini_list;
	    cfg_ini != NULL;
	    cfg_ini = cfg_ini->ini_next) {
		ini = kmem_zalloc(sizeof (iscsit_ini_t), KM_SLEEP);
		(void) strlcpy(ini->ini_name, cfg_ini->ini_name,
		    MAX_ISCSI_NODENAMELEN);
		(void) nvlist_dup(cfg_ini->ini_properties, &ini->ini_props,
		    KM_SLEEP);
		avl_add(&iscsit_global.global_ini_list, ini);
		iscsit_global_hold();
	}

	return (ITCFG_SUCCESS);
}

int
iscsit_ini_avl_compare(const void *void_ini1, const void *void_ini2)
{
	const iscsit_ini_t	*ini1 = void_ini1;
	const iscsit_ini_t	*ini2 = void_ini2;
	int 			result;

	/*
	 * Sort by ISID first then TSIH
	 */
	result = strcmp(ini1->ini_name, ini2->ini_name);
	if (result < 0) {
		return (-1);
	} else if (result > 0) {
		return (1);
	}

	return (0);
}

iscsit_ini_t *
iscsit_ini_lookup_locked(char *ini_name)
{
	iscsit_ini_t	tmp_ini;
	iscsit_ini_t	*result;

	/*
	 * Use a dummy target for lookup, filling in all fields used in AVL
	 * comparison.
	 */
	(void) strlcpy(tmp_ini.ini_name, ini_name, MAX_ISCSI_NODENAMELEN);
	result = avl_find(&iscsit_global.global_ini_list, &tmp_ini, NULL);

	return (result);
}
