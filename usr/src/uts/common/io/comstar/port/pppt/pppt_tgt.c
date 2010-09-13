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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/cpuvar.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/sysmacros.h>

#include <sys/socket.h>
#include <sys/strsubr.h>
#include <sys/door.h>
#include <sys/note.h>
#include <sys/sdt.h>

#include <sys/stmf.h>
#include <sys/stmf_ioctl.h>
#include <sys/portif.h>
#define	PPPT_TGT_SM_STRINGS
#include "pppt.h"

typedef struct {
	list_node_t		te_ctx_node;
	pppt_tgt_event_t	te_ctx_event;
} tgt_event_ctx_t;

static void
pppt_tgt_sm_event(pppt_tgt_t *tgt, pppt_tgt_event_t event);

static void
tgt_sm_event_locked(pppt_tgt_t *tgt, pppt_tgt_event_t event);

static void
tgt_sm_event_dispatch(pppt_tgt_t *tgt, tgt_event_ctx_t *ctx);

static void
tgt_sm_created(pppt_tgt_t *tgt, tgt_event_ctx_t *ctx);

static void
tgt_sm_onlining(pppt_tgt_t *tgt, tgt_event_ctx_t *ctx);

static void
tgt_sm_online(pppt_tgt_t *tgt, tgt_event_ctx_t *ctx);

static void
tgt_sm_stmf_online(pppt_tgt_t *tgt, tgt_event_ctx_t *ctx);

static void
tgt_sm_deleting_need_offline(pppt_tgt_t *tgt, tgt_event_ctx_t *ctx);

static void
tgt_sm_offlining(pppt_tgt_t *tgt, tgt_event_ctx_t *ctx);

static void
tgt_sm_offline(pppt_tgt_t *tgt, tgt_event_ctx_t *ctx);

static void
tgt_sm_stmf_offline(pppt_tgt_t *tgt, tgt_event_ctx_t *ctx);

static void
tgt_sm_deleting_stmf_dereg(pppt_tgt_t *tgt, tgt_event_ctx_t *ctx);

static void
tgt_sm_deleting_stmf_dereg_fail(pppt_tgt_t *tgt, tgt_event_ctx_t *ctx);

static void
tgt_sm_deleting(pppt_tgt_t *tgt, tgt_event_ctx_t *ctx);

static void
pppt_tgt_offline_task(void *arg);

static void
pppt_tgt_dereg_retry(void *arg);

static void
pppt_tgt_dereg_task(void *arg);

static void
tgt_sm_new_state(pppt_tgt_t *tgt, tgt_event_ctx_t *ctx,
    pppt_tgt_state_t new_state);

/*ARGSUSED*/
void
pppt_tgt_sm_ctl(stmf_local_port_t *lport, int cmd, void *arg)
{
	pppt_tgt_t		*pppt_tgt;

	pppt_tgt = (pppt_tgt_t *)lport->lport_port_private;

	switch (cmd) {
	case STMF_CMD_LPORT_ONLINE:
		pppt_tgt_sm_event(pppt_tgt, TE_STMF_ONLINE_REQ);
		break;
	case STMF_CMD_LPORT_OFFLINE:
		pppt_tgt_sm_event(pppt_tgt, TE_STMF_OFFLINE_REQ);
		break;
	case STMF_ACK_LPORT_ONLINE_COMPLETE:
		pppt_tgt_sm_event(pppt_tgt, TE_STMF_ONLINE_COMPLETE_ACK);
		break;
	case STMF_ACK_LPORT_OFFLINE_COMPLETE:
		pppt_tgt_sm_event(pppt_tgt, TE_STMF_OFFLINE_COMPLETE_ACK);
		break;

	default:
		ASSERT(0);
		break;
	}
}

pppt_tgt_t *
pppt_tgt_create(stmf_ic_reg_port_msg_t *reg_port, stmf_status_t *msg_errcode)
{
	pppt_tgt_t		*result;
	stmf_local_port_t	*lport;
	int			total_devid_len;

	total_devid_len = sizeof (scsi_devid_desc_t) +
	    reg_port->icrp_port_id->ident_length - 1;

	/*
	 * Each target is an STMF local port.  Allocate an STMF local port
	 * including enough space to store a scsi_devid_desc_t for this target.
	 */
	lport = stmf_alloc(STMF_STRUCT_STMF_LOCAL_PORT,
	    sizeof (pppt_tgt_t) + total_devid_len, 0);
	if (lport == NULL) {
		*msg_errcode = STMF_ALLOC_FAILURE;
		return (NULL);
	}

	result = lport->lport_port_private;
	result->target_state = TS_CREATED;
	/* Use pointer arithmetic to find scsi_devid_desc_t */
	result->target_devid = (scsi_devid_desc_t *)(result + 1);
	bcopy(reg_port->icrp_port_id, result->target_devid, total_devid_len);
	result->target_devid->piv = 1;
	result->target_devid->code_set = CODE_SET_ASCII;
	result->target_devid->association = ID_IS_TARGET_PORT;

	mutex_init(&result->target_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&result->target_cv, NULL, CV_DEFAULT, NULL);
	list_create(&result->target_events, sizeof (tgt_event_ctx_t),
	    offsetof(tgt_event_ctx_t, te_ctx_node));
	avl_create(&result->target_sess_list, pppt_sess_avl_compare_by_name,
	    sizeof (pppt_sess_t), offsetof(pppt_sess_t, ps_target_ln));

	lport->lport_abort_timeout = 120; /* seconds */
	lport->lport_id = result->target_devid;
	lport->lport_pp = pppt_global.global_pp;
	lport->lport_ds = pppt_global.global_dbuf_store;
	lport->lport_xfer_data = &pppt_lport_xfer_data;
	lport->lport_send_status = &pppt_lport_send_status;
	lport->lport_task_free = &pppt_lport_task_free;
	lport->lport_abort = &pppt_lport_abort;
	lport->lport_ctl = &pppt_lport_ctl;
	result->target_stmf_lport = lport;

	/*
	 * Since this is a proxy port we need to do set the relative
	 * target port identifier before registering it with STMF.
	 */
	stmf_set_port_standby(lport, reg_port->icrp_relative_port_id);

	/*
	 * Register the target with STMF.  STMF may immediately ask us to go
	 * online so insure any additional config setup is complete.
	 */
	if (stmf_register_local_port(lport) != STMF_SUCCESS) {
		*msg_errcode = STMF_FAILURE;
		pppt_tgt_destroy(result);
		return (NULL);
	}

	return (result);

}

void
pppt_tgt_destroy(pppt_tgt_t *tgt)
{
	/* Destroy target */
	avl_destroy(&tgt->target_sess_list);
	list_destroy(&tgt->target_events);
	cv_destroy(&tgt->target_cv);
	mutex_destroy(&tgt->target_mutex);
	stmf_free(tgt->target_stmf_lport); /* Also frees "tgt' */
}

pppt_tgt_t *
pppt_tgt_lookup(scsi_devid_desc_t *tgt_devid)
{
	pppt_tgt_t	*result;
	PPPT_GLOBAL_LOCK();
	result = pppt_tgt_lookup_locked(tgt_devid);
	PPPT_GLOBAL_UNLOCK();

	return (result);
}

pppt_tgt_t *
pppt_tgt_lookup_locked(scsi_devid_desc_t *tgt_devid)
{
	pppt_tgt_t	*result;
	pppt_tgt_t	tmptgt;

	bzero(&tmptgt, sizeof (tmptgt));
	tmptgt.target_devid = tgt_devid;

	result = avl_find(&pppt_global.global_target_list, &tmptgt, NULL);

	return (result);
}

void
pppt_tgt_async_delete(pppt_tgt_t *tgt)
{
	/* Generate TE_DELETE event to target state machine */
	pppt_tgt_sm_event(tgt, TE_DELETE);
}

int
pppt_tgt_avl_compare(const void *void_tgt1, const void *void_tgt2)
{
	const	pppt_tgt_t	*ptgt1 = void_tgt1;
	const	pppt_tgt_t	*ptgt2 = void_tgt2;
	int			result;

	/* Sort by code set then ident */
	if (ptgt1->target_devid->code_set <
	    ptgt2->target_devid->code_set) {
		return (-1);
	} else if (ptgt1->target_devid->code_set >
	    ptgt2->target_devid->code_set) {
		return (1);
	}

	/* Next by ident length */
	if (ptgt1->target_devid->ident_length <
	    ptgt2->target_devid->ident_length) {
		return (-1);
	} else if (ptgt1->target_devid->ident_length >
	    ptgt2->target_devid->ident_length) {
		return (1);
	}

	/* Code set and ident length both match, now compare idents */
	result = memcmp(ptgt1->target_devid->ident, ptgt2->target_devid->ident,
	    ptgt1->target_devid->ident_length);

	if (result < 0) {
		return (-1);
	} else if (result > 0) {
		return (1);
	}

	return (0);
}

/*
 * Target state machine
 */

static void
pppt_tgt_sm_event(pppt_tgt_t *tgt, pppt_tgt_event_t event)
{
	mutex_enter(&tgt->target_mutex);
	tgt_sm_event_locked(tgt, event);
	mutex_exit(&tgt->target_mutex);
}

static void
tgt_sm_event_locked(pppt_tgt_t *tgt, pppt_tgt_event_t event)
{
	tgt_event_ctx_t *ctx;

	event = (event < TE_MAX_EVENT) ? event : TE_UNDEFINED;
	DTRACE_PROBE2(pppt__tgt__event, pppt_tgt_t *, tgt,
	    pppt_tgt_event_t, event);
	stmf_trace("pppt", "pppt_tgt_event: tgt %p event %s(%d)",
	    (void *)tgt, pppt_te_name[event], event);

	tgt->target_refcount++;

	ctx = kmem_zalloc(sizeof (*ctx), KM_SLEEP);

	ctx->te_ctx_event = event;

	list_insert_tail(&tgt->target_events, ctx);

	/*
	 * Use the target_sm_busy flag to keep the state machine single
	 * threaded.  This also serves as recursion avoidance since this
	 * flag will always be set if we call pppt_tgt_sm_event from
	 * within the state machine code.
	 */
	if (!tgt->target_sm_busy) {
		tgt->target_sm_busy = B_TRUE;
		while (!list_is_empty(&tgt->target_events)) {
			ctx = list_head(&tgt->target_events);
			list_remove(&tgt->target_events, ctx);
			mutex_exit(&tgt->target_mutex);
			tgt_sm_event_dispatch(tgt, ctx);
			mutex_enter(&tgt->target_mutex);
		}
		tgt->target_sm_busy = B_FALSE;

	}

	tgt->target_refcount--;
	cv_signal(&tgt->target_cv);
}

static void
tgt_sm_event_dispatch(pppt_tgt_t *tgt, tgt_event_ctx_t *ctx)
{
	stmf_trace("pppt", "pppt_tgt_event_dispatch: tgt %p event %s(%d)",
	    (void *)tgt, pppt_te_name[ctx->te_ctx_event], ctx->te_ctx_event);

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
tgt_sm_created(pppt_tgt_t *tgt, tgt_event_ctx_t *ctx)
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
tgt_sm_onlining(pppt_tgt_t *tgt, tgt_event_ctx_t *ctx)
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
tgt_sm_online(pppt_tgt_t *tgt, tgt_event_ctx_t *ctx)
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
tgt_sm_stmf_online(pppt_tgt_t *tgt, tgt_event_ctx_t *ctx)
{
	stmf_change_status_t	scs;

	switch (ctx->te_ctx_event) {
	case TE_DELETE:
		tgt_sm_new_state(tgt, ctx, TS_DELETING_NEED_OFFLINE);
		break;
	case TE_STMF_OFFLINE_REQ:
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
tgt_sm_deleting_need_offline(pppt_tgt_t *tgt, tgt_event_ctx_t *ctx)
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
tgt_sm_offlining(pppt_tgt_t *tgt, tgt_event_ctx_t *ctx)
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
tgt_sm_offline(pppt_tgt_t *tgt, tgt_event_ctx_t *ctx)
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
tgt_sm_stmf_offline(pppt_tgt_t *tgt, tgt_event_ctx_t *ctx)
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
tgt_sm_deleting_stmf_dereg(pppt_tgt_t *tgt, tgt_event_ctx_t *ctx)
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
tgt_sm_deleting_stmf_dereg_fail(pppt_tgt_t *tgt, tgt_event_ctx_t *ctx)
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
tgt_sm_deleting(pppt_tgt_t *tgt, tgt_event_ctx_t *ctx)
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
pppt_tgt_offline(pppt_tgt_t *tgt)
{
	(void) taskq_dispatch(pppt_global.global_dispatch_taskq,
	    pppt_tgt_offline_task, tgt, KM_SLEEP);
}

static void
pppt_tgt_offline_task(void *arg)
{
	pppt_tgt_t		*tgt = arg;
	pppt_sess_t		*ps, *next_ps;
	stmf_change_status_t	scs;

	stmf_trace("pppt", "pppt_tgt_offline %p", (void *)tgt);

	PPPT_GLOBAL_LOCK();
	mutex_enter(&tgt->target_mutex);
	for (ps = avl_first(&tgt->target_sess_list); ps != NULL; ps = next_ps) {
		next_ps = AVL_NEXT(&tgt->target_sess_list, ps);
		mutex_enter(&ps->ps_mutex);
		if (!ps->ps_closed) {
			pppt_sess_close_locked(ps);
		}
		mutex_exit(&ps->ps_mutex);
	}
	mutex_exit(&tgt->target_mutex);
	PPPT_GLOBAL_UNLOCK();

	pppt_tgt_sm_event(tgt, TE_OFFLINE_COMPLETE);

	scs.st_completion_status = STMF_SUCCESS;
	scs.st_additional_info = NULL;
	(void) stmf_ctl(STMF_CMD_LPORT_OFFLINE_COMPLETE,
	    tgt->target_stmf_lport, &scs);

	stmf_trace("pppt", "pppt_tgt_offline complete %p", (void *)tgt);
}

static void
pppt_tgt_dereg_retry(void *arg)
{
	pppt_tgt_t *tgt = arg;

	/*
	 * Rather than guaranteeing the target state machine code will not
	 * block for long periods of time (tying up this callout thread)
	 * we will queue a task on the taskq to send the retry event.
	 * If it fails we'll setup another timeout and try again later.
	 */
	if (taskq_dispatch(pppt_global.global_dispatch_taskq,
	    pppt_tgt_dereg_task, tgt, KM_NOSLEEP) == NULL) {
		/* Dispatch failed, try again later */
		(void) timeout(pppt_tgt_dereg_retry, tgt,
		    drv_usectohz(TGT_DEREG_RETRY_SECONDS * 1000000));
	}
}

static void
pppt_tgt_dereg_task(void *arg)
{
	pppt_tgt_t *tgt = arg;

	pppt_tgt_sm_event(tgt, TE_STMF_DEREG_RETRY);
}

/*ARGSUSED*/
static void
tgt_sm_new_state(pppt_tgt_t *tgt, tgt_event_ctx_t *ctx,
    pppt_tgt_state_t new_state)
{
	stmf_local_port_t		*lport = tgt->target_stmf_lport;
	stmf_change_status_t		scs;
	stmf_state_change_info_t	sci;
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

	stmf_trace("pppt", "pppt_target_state_change: "
	    "tgt %p, %s(%d) --> %s(%d)\n",
	    (void *) tgt, pppt_ts_name[tgt->target_state], tgt->target_state,
	    pppt_ts_name[new_state], new_state);
	DTRACE_PROBE3(pppt__target__state__change,
	    pppt_tgt_t *, tgt, tgt_event_ctx_t *, ctx,
	    pppt_tgt_state_t, new_state);

	mutex_enter(&tgt->target_mutex);
	tgt->target_last_state = tgt->target_state;
	tgt->target_state = new_state;
	cv_signal(&tgt->target_cv);
	mutex_exit(&tgt->target_mutex);

	switch (tgt->target_state) {
	case TS_ONLINING:
		pppt_tgt_sm_event(tgt, TE_ONLINE_SUCCESS);

		/*
		 * Let STMF know the how the online operation completed.
		 * STMF will respond with an acknowlege later
		 */
		(void) stmf_ctl(STMF_CMD_LPORT_ONLINE_COMPLETE, lport, &scs);
		break;
	case TS_ONLINE:
		break;
	case TS_STMF_ONLINE:
		break;
	case TS_DELETING_NEED_OFFLINE:
		sci.st_rflags = STMF_RFLAG_STAY_OFFLINED;
		sci.st_additional_info = "Offline for delete";
		(void) stmf_ctl(STMF_CMD_LPORT_OFFLINE, lport, &sci);
		break;
	case TS_OFFLINING:
		/* Async callback generates completion event */
		pppt_tgt_offline(tgt);
		break;
	case TS_OFFLINE:
		break;
	case TS_STMF_OFFLINE:
		break;
	case TS_DELETING_STMF_DEREG:
		stmfrc = stmf_deregister_local_port(tgt->target_stmf_lport);
		if (stmfrc == STMF_SUCCESS) {
			pppt_tgt_sm_event(tgt, TE_STMF_DEREG_SUCCESS);
		} else {
			pppt_tgt_sm_event(tgt, TE_STMF_DEREG_FAIL);
		}
		break;
	case TS_DELETING_STMF_DEREG_FAIL:
		/* Retry dereg in 1 second */
		(void) timeout(pppt_tgt_dereg_retry, tgt,
		    drv_usectohz(TGT_DEREG_RETRY_SECONDS * 1000000));
		break;
	case TS_DELETING:
		break;
	default:
		ASSERT(0);
	}
}
