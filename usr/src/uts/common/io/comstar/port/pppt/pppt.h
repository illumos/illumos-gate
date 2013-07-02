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
 * Copyright 2013, Nexenta Systems, Inc. All rights reserved.
 */
#ifndef _PPPT_H
#define	_PPPT_H

#include <sys/pppt_ic_if.h>

#ifdef	__cplusplus
extern "C" {
#endif

#define	PPPT_GLOBAL_LOCK() mutex_enter(&pppt_global.global_lock)
#define	PPPT_GLOBAL_UNLOCK() mutex_exit(&pppt_global.global_lock)

extern int pppt_logging;

#define	PPPT_LOG if (pppt_logging) cmn_err

#define	TGT_DEREG_RETRY_SECONDS	1

typedef enum {
	PPPT_STATUS_SUCCESS = 0,
	PPPT_STATUS_FAIL,
	PPPT_STATUS_ABORTED,
	PPPT_STATUS_DONE
} pppt_status_t;

#define	PPPT_MODNAME "pppt"

/* Target states and events, update pppt_ts_name table whenever modified */
typedef enum {
	TS_UNDEFINED = 0,
	TS_CREATED,
	TS_ONLINING,
	TS_ONLINE,
	TS_STMF_ONLINE,
	TS_DELETING_NEED_OFFLINE,
	TS_OFFLINING,
	TS_OFFLINE,
	TS_STMF_OFFLINE,
	TS_DELETING_STMF_DEREG,
	TS_DELETING_STMF_DEREG_FAIL,
	TS_DELETING,
	TS_MAX_STATE
} pppt_tgt_state_t;

#ifdef PPPT_TGT_SM_STRINGS
static const char *pppt_ts_name[TS_MAX_STATE+1] = {
	"TS_UNDEFINED",
	"TS_CREATED",
	"TS_ONLINING",
	"TS_ONLINE",
	"TS_STMF_ONLINE",
	"TS_DELETING_NEED_OFFLINE",
	"TS_OFFLINING",
	"TS_OFFLINE",
	"TS_STMF_OFFLINE",
	"TS_DELETING_STMF_DEREG",
	"TS_DELETING_STMF_DEREG_FAIL",
	"TS_DELETING",
	"TS_MAX_STATE"
};
#endif

typedef enum {
	TE_UNDEFINED = 0,
	TE_STMF_ONLINE_REQ,
	TE_ONLINE_SUCCESS,
	TE_ONLINE_FAIL,
	TE_STMF_ONLINE_COMPLETE_ACK,
	TE_STMF_OFFLINE_REQ,
	TE_OFFLINE_COMPLETE,
	TE_STMF_OFFLINE_COMPLETE_ACK,
	TE_DELETE,
	TE_STMF_DEREG_SUCCESS,
	TE_STMF_DEREG_FAIL,
	TE_STMF_DEREG_RETRY,
	TE_WAIT_REF_COMPLETE, /* XXX */
	TE_MAX_EVENT
} pppt_tgt_event_t;

#ifdef PPPT_TGT_SM_STRINGS
static const char *pppt_te_name[TE_MAX_EVENT+1] = {
	"TE_UNDEFINED",
	"TE_STMF_ONLINE_REQ",
	"TE_ONLINE_SUCCESS",
	"TE_ONLINE_FAIL",
	"TE_STMF_ONLINE_COMPLETE_ACK",
	"TE_STMF_OFFLINE_REQ",
	"TE_OFFLINE_COMPLETE",
	"TE_STMF_OFFLINE_COMPLETE_ACK",
	"TE_DELETE",
	"TE_STMF_DEREG_SUCCESS",
	"TE_STMF_DEREG_FAIL",
	"TE_STMF_DEREG_RETRY",
	"TE_WAIT_REF_COMPLETE",
	"TE_MAX_EVENT"
};
#endif

typedef struct pppt_tgt_s {
	kmutex_t		target_mutex;
	kcondvar_t		target_cv;
	avl_node_t		target_global_ln;
	scsi_devid_desc_t	*target_devid;
	stmf_local_port_t	*target_stmf_lport;
	avl_tree_t		target_sess_list;

	/* Target state */
	boolean_t		target_sm_busy;
	boolean_t		target_deleting;
	pppt_tgt_state_t	target_state;
	pppt_tgt_state_t	target_last_state;
	int			target_refcount;
	list_t			target_events;
} pppt_tgt_t;

typedef struct {
	struct pppt_tgt_s	*ps_target;
	uint64_t		ps_session_id;
	int			ps_refcnt;
	kmutex_t		ps_mutex;
	kcondvar_t		ps_cv;
	boolean_t		ps_closed;
	avl_node_t		ps_global_ln;
	avl_node_t		ps_target_ln;
	avl_tree_t		ps_task_list;
	stmf_scsi_session_t	*ps_stmf_sess;
} pppt_sess_t;

typedef struct {
	stmf_data_buf_t		*pbuf_stmf_buf;
	boolean_t		pbuf_is_immed;
	stmf_ic_msg_t		*pbuf_immed_msg;
} pppt_buf_t;

typedef enum {
	PTS_INIT = 0,
	PTS_ACTIVE,
	PTS_DONE,
	PTS_SENT_STATUS,
	PTS_ABORTED
} pppt_task_state_t;

typedef struct {
	pppt_sess_t		*pt_sess;
	avl_node_t		pt_sess_ln;
	int			pt_refcnt;
	kmutex_t		pt_mutex;
	stmf_ic_msgid_t		pt_task_id;
	uint8_t			pt_lun_id[16];
	pppt_task_state_t	pt_state;
	scsi_task_t		*pt_stmf_task;
	pppt_buf_t		*pt_immed_data;
	pppt_buf_t		*pt_read_buf;
	stmf_ic_msgid_t		pt_read_xfer_msgid;
} pppt_task_t;

/*
 * Error statistics
 */
typedef struct {
	uint64_t		es_tgt_reg_svc_disabled;
	uint64_t		es_tgt_reg_duplicate;
	uint64_t		es_tgt_reg_create_fail;
	uint64_t		es_tgt_dereg_svc_disabled;
	uint64_t		es_tgt_dereg_not_found;
	uint64_t		es_sess_destroy_no_session;
	uint64_t		es_sess_lookup_no_session;
	uint64_t		es_sess_lookup_ident_mismatch;
	uint64_t		es_sess_lookup_bad_tgt_state;
	uint64_t		es_scmd_ptask_alloc_fail;
	uint64_t		es_scmd_sess_create_fail;
	uint64_t		es_scmd_stask_alloc_fail;
	uint64_t		es_scmd_dup_task_count;
} pppt_error_stats_t;

#define	PPPT_INC_STAT(stat_field) \
	atomic_inc_64(&pppt_global.global_error_stats.stat_field);

/*
 * State values for the iscsit service
 */
typedef enum {
	PSS_UNDEFINED = 0,
	PSS_DETACHED,
	PSS_DISABLED,
	PSS_ENABLING,
	PSS_ENABLED,
	PSS_BUSY,
	PSS_DISABLING
} pppt_service_state_t;


typedef struct {
	pppt_service_state_t	global_svc_state;
	dev_info_t		*global_dip;
	stmf_port_provider_t	*global_pp;
	stmf_dbuf_store_t	*global_dbuf_store;
	taskq_t			*global_dispatch_taskq;
	taskq_t			*global_sess_taskq;
	avl_tree_t		global_sess_list;
	avl_tree_t		global_target_list;
	kmutex_t		global_lock;
	door_handle_t		global_door;
	kmutex_t		global_door_lock;
	pppt_error_stats_t	global_error_stats;
} pppt_global_t;

extern pppt_global_t pppt_global;

stmf_status_t pppt_lport_xfer_data(scsi_task_t *task, stmf_data_buf_t *dbuf,
    uint32_t ioflags);

void pppt_xfer_read_complete(pppt_task_t *pppt_task, stmf_status_t status);

stmf_status_t pppt_lport_send_status(scsi_task_t *task, uint32_t ioflags);

void pppt_lport_task_free(scsi_task_t *task);

stmf_status_t pppt_lport_abort(stmf_local_port_t *lport, int abort_cmd,
    void *arg, uint32_t flags);

void pppt_lport_ctl(stmf_local_port_t *lport, int cmd, void *arg);

pppt_sess_t *pppt_sess_lookup_locked(uint64_t session_id,
    scsi_devid_desc_t *lport_devid,
    stmf_remote_port_t *rport);

pppt_sess_t *pppt_sess_lookup_by_id_locked(uint64_t session_id);

pppt_sess_t *pppt_sess_lookup_create(scsi_devid_desc_t *lport_devid,
    scsi_devid_desc_t *rport_devid, stmf_remote_port_t *rport,
    uint64_t session_id, stmf_status_t *statusp);

void pppt_sess_rele(pppt_sess_t *sks);

void pppt_sess_rele_locked(pppt_sess_t *sks);

void pppt_sess_close_locked(pppt_sess_t *ps);

int pppt_sess_avl_compare_by_id(const void *void_sess1,
    const void *void_sess2);

int pppt_sess_avl_compare_by_name(const void *void_sess1,
    const void *void_sess2);

pppt_task_t *pppt_task_alloc(void);

void pppt_task_free(pppt_task_t *ptask);

pppt_status_t pppt_task_start(pppt_task_t *ptask);

pppt_status_t pppt_task_done(pppt_task_t *ptask);

pppt_task_t *pppt_task_lookup(stmf_ic_msgid_t msgid);

void pppt_msg_rx(stmf_ic_msg_t *msg);

void pppt_msg_tx_status(stmf_ic_msg_t *orig_msg, stmf_status_t status);

pppt_tgt_t *pppt_tgt_lookup(scsi_devid_desc_t *tgt_devid);

pppt_tgt_t *pppt_tgt_lookup_locked(scsi_devid_desc_t *tgt_devid);

pppt_tgt_t *pppt_tgt_create(stmf_ic_reg_port_msg_t *reg_port,
    stmf_status_t *errcode);

void pppt_tgt_async_delete(pppt_tgt_t *tgt);

void pppt_tgt_destroy(pppt_tgt_t *tgt);

int pppt_tgt_avl_compare(const void *void_tgt1, const void *void_tgt2);

void pppt_tgt_sm_ctl(stmf_local_port_t *lport, int cmd, void *arg);

pppt_status_t pppt_task_hold(pppt_task_t *);

#ifdef	__cplusplus
}
#endif

#endif	/* _PPPT_H */
