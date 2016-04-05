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

#ifndef _ISCSIT_H_
#define	_ISCSIT_H_

#include <sys/iscsit/iscsi_if.h>
#include <sys/iscsit/iscsit_common.h>

#include "iscsit_authclient.h"

/*
 * For some reason iscsi_protocol.h lists the max version as "0x02" and the
 * min version as "0x00".  RFC3720 clearly states that the current version
 * number is 0x00 so that is what we will use.
 */
#define	ISCSIT_MIN_VERSION			0x00
#define	ISCSIT_MAX_VERSION			0x00
#define	ISCSIT_MAX_CONNECTIONS			32 /* MC/S support  */
#define	ISCSIT_MAX_RECV_DATA_SEGMENT_LENGTH	(32*1024)
#define	ISCSIT_MAX_BURST_LENGTH			(1024*1024)
#define	ISCSIT_MAX_FIRST_BURST_LENGTH		ISCSI_DEFAULT_FIRST_BURST_LENGTH
#define	ISCSIT_MAX_TIME2WAIT			ISCSI_MAX_TIME2WAIT
#define	ISCSIT_MAX_TIME2RETAIN			ISCSI_DEFAULT_TIME_TO_RETAIN
#define	ISCSIT_MAX_OUTSTANDING_R2T		ISCSI_DEFAULT_MAX_OUT_R2T
#define	ISCSIT_MAX_ERROR_RECOVERY_LEVEL		0
#define	ISCSIT_MAX_OUTSTANDING_UNEXPECTED_PDUS	0

#define	ISCSIT_DEFAULT_TPG	"iscsit-default-tpg"
#define	ISCSIT_DEFAULT_TPGT	1

#define	ISCSI_MAX_TSIH		0xffff
#define	ISCSI_UNSPEC_TSIH	0

/* Max targets per system */
#define	ISCSIT_MAX_TARGETS	1024

#define	ISCSIT_MAX_WINDOW	1024
#define	ISCSIT_RXPDU_QUEUE_LEN	2048

#define	ISCSIT_CMDSN_LT_EXPCMDSN	-1
#define	ISCSIT_CMDSN_EQ_EXPCMDSN	1
#define	ISCSIT_CMDSN_GT_EXPCMDSN	0
/*
 * MC/S: A timeout is maintained to recover from lost CmdSN (holes in the
 * CmdSN ordering). When the timeout is reached, the ExpCmdSN is advanced
 * past the hole to continue processing the queued commands. This value is
 * system-tunable (volatile rxpdu_queue_threshold) and should be in the
 * range from 5 to 30 seconds.
 */
#define	ISCSIT_RXPDU_QUEUE_THRESHOLD		5	/* 5 seconds */
#define	ISCSIT_RXPDU_QUEUE_MONITOR_INTERVAL	5	/* 5 seconds */

/* Time in seconds to wait between calls to stmf_deregister_local_port */
#define	TGT_DEREG_RETRY_SECONDS	1

#define	ISCSIT_GLOBAL_LOCK(rw) rw_enter(&iscsit_global.global_rwlock, (rw))
#define	ISCSIT_GLOBAL_UNLOCK() rw_exit(&iscsit_global.global_rwlock)

/* Circular buffer to hold the out-of-order PDUs in MC/S */
typedef struct {
	idm_pdu_t	*cb_buffer[ISCSIT_RXPDU_QUEUE_LEN];
	int		cb_num_elems;
} iscsit_cbuf_t;

/*
 * Used for serial number arithmetic (RFC 1982)
 */
#define	ISCSIT_SNA32_CHECK	0x80000000

typedef struct {
	char		tpg_name[MAX_TPG_NAMELEN];
	kmutex_t	tpg_mutex;
	idm_refcnt_t	tpg_refcnt;
	int		tpg_online;
	avl_tree_t	tpg_portal_list;
	avl_node_t	tpg_global_ln;
	list_node_t	tpg_delete_ln;
} iscsit_tpg_t;

#define	IS_DEFAULT_TPGT(TPGT) \
	(((TPGT) != NULL) && \
	    ((TPGT)->tpgt_tpg == iscsit_global.global_default_tpg))

typedef struct {
	iscsit_tpg_t	*tpgt_tpg;
	idm_refcnt_t	tpgt_refcnt;
	avl_node_t	tpgt_tgt_ln;
	list_node_t	tpgt_delete_ln;
	uint16_t	tpgt_tag;
	boolean_t	tpgt_needs_tpg_offline;
} iscsit_tpgt_t;

typedef struct {
	struct sockaddr_storage portal_addr;
	int			portal_online;
	idm_refcnt_t		portal_refcnt;
	avl_node_t		portal_tpg_ln;
	iscsit_tpg_t		*portal_tpg;
	idm_svc_t		*portal_svc;
	boolean_t		portal_default;
	void			*portal_isns;
} iscsit_portal_t;


/* Target states and events, update iscsit_ts_name table whenever modified */
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
} iscsit_tgt_state_t;

#ifdef ISCSIT_TGT_SM_STRINGS
static const char *iscsit_ts_name[TS_MAX_STATE+1] = {
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
	TE_WAIT_REF_COMPLETE,
	TE_MAX_EVENT
} iscsit_tgt_event_t;

#ifdef ISCSIT_TGT_SM_STRINGS
static const char *iscsit_te_name[TE_MAX_EVENT+1] = {
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

typedef struct {
	char			*target_name;
	nvlist_t		*target_props;
	kmutex_t		target_mutex;
	idm_refcnt_t		target_refcnt;
	idm_refcnt_t		target_sess_refcnt;
	avl_tree_t		target_tpgt_list;
	avl_tree_t		target_sess_list;
	avl_node_t		target_global_ln;
	avl_node_t		target_global_deleted_ln;
	/* STMF lport == iSCSI target */
	scsi_devid_desc_t	*target_devid;
	stmf_local_port_t	*target_stmf_lport;
	uint8_t			target_stmf_lport_registered;

	/* Target state */
	boolean_t		target_sm_busy;
	boolean_t		target_deleting;
	iscsit_tgt_state_t	target_state;
	iscsit_tgt_state_t	target_last_state;
	sm_audit_buf_t		target_state_audit;
	list_t			target_events;
	uint64_t		target_generation;
} iscsit_tgt_t;

typedef struct {
	char			ini_name[MAX_ISCSI_NODENAMELEN];
	nvlist_t		*ini_props;
	avl_node_t		ini_global_ln;
} iscsit_ini_t;

/*
 * iSCSI Auth Information
 */
typedef struct conn_auth {
	char			ca_tgt_chapuser[iscsitAuthStringMaxLength];
	uint8_t			ca_tgt_chapsecret[iscsitAuthStringMaxLength];
	int			ca_tgt_chapsecretlen;

	char			ca_ini_chapuser[iscsitAuthStringMaxLength];
	uint8_t			ca_ini_chapsecret[iscsitAuthStringMaxLength];
	int			ca_ini_chapsecretlen;

	/* RADIUS authentication information   	*/
	boolean_t		ca_use_radius;
	struct sockaddr_storage	ca_radius_server;
	uint8_t			ca_radius_secret[iscsitAuthStringMaxLength];
	int			ca_radius_secretlen;

	/* authentication method list */
	iscsit_auth_method_t	ca_method_valid_list[iscsitAuthMethodMaxCount];

	/* Target alias */
	char			ca_tgt_alias[MAX_ISCSI_NODENAMELEN];
} conn_auth_t;

/*
 * We have three state machines (so far) between the IDM connection state
 * machine, the session state machine, and the login state machine.  All
 * of these states have some concept of "full feature mode".  It's going
 * to be obnoxious if we use a mixture of these "ffp" representations
 * since it will be difficult to ensure the three state machines
 * transition at exactly the same time.  We should drive decisions that
 * depend on FFP from the IDM state machine which is actually snooping
 * the iSCSI PDU's and will always transition at the correct time.
 *
 * A consequence of this approach is that there is a window just after
 * login completes where we may get a SCSI request but the session
 * or login state machine has not quite transitioned to "FFP".  Whether
 * this is a problem depends on how we use those state machines.  This
 * is what we should use them for:
 *
 * IDM Connection state machine - Decisions related to command processing
 * including whether a connection is in FFP
 *
 * Session state machine - Summarize the state of all available connections
 * for the purposes of ERL1, ERL2 and MC/S.  A session in LOGGED_IN state
 * should always have at least one FFP connection but there may be a brief
 * window where a session in ACTIVE might have one or more FFP connections
 * even though ACTIVE is not strictly an FFP state according to the RFC.
 *
 * Login state machine -- drive the login process, collect negotiated
 * parameters.  Another side effect of this approach is that we may get
 * the "notify ffp" callback from the IDM connection state machine before
 * the login state machine has actually transitioned to FFP state.
 */

struct iscsit_conn_s;

/* Update iscsit_ss_name table whenever session states are modified */
typedef enum {
	SS_UNDEFINED = 0,
	SS_Q1_FREE,
	SS_Q2_ACTIVE,
	SS_Q3_LOGGED_IN,
	SS_Q4_FAILED,
	SS_Q5_CONTINUE,
	SS_Q6_DONE,
	SS_Q7_ERROR,
	/* Add new session states above SS_MAX_STATE */
	SS_MAX_STATE
} iscsit_session_state_t;

#ifdef ISCSIT_SESS_SM_STRINGS
/* An array of state text values, for use in logging state transitions */
static const char *iscsit_ss_name[SS_MAX_STATE+1] = {
	"SS_UNDEFINED",
	"SS_Q1_FREE",
	"SS_Q2_ACTIVE",
	"SS_Q3_LOGGED_IN",
	"SS_Q4_FAILED",
	"SS_Q5_CONTINUE",
	"SS_Q6_DONE",
	"SS_Q7_ERROR",
	"SS_MAX_STATE"
};
#endif

/* Update iscsit_se_name table whenever session events are modified */
typedef enum {
	SE_UNDEFINED = 0,
	SE_CONN_IN_LOGIN,	/* From login state machine */
	SE_CONN_LOGGED_IN,	/* FFP enabled client notification */
	SE_CONN_FFP_FAIL,	/* FFP disabled client notification */
	SE_CONN_FFP_DISABLE,	/* FFP disabled client notification */
	SE_CONN_FAIL,		/* Conn destroy client notification */
	SE_SESSION_CLOSE,	/* FFP disabled client notification */
	SE_SESSION_REINSTATE,	/* From login state machine */
	SE_SESSION_TIMEOUT,	/* Internal */
	SE_SESSION_CONTINUE,	/* From login state machine */
	SE_SESSION_CONTINUE_FAIL, /* From login state machine? */
	/* Add new events above SE_MAX_EVENT */
	SE_MAX_EVENT
} iscsit_session_event_t;

#ifdef ISCSIT_SESS_SM_STRINGS
/* An array of event text values, for use in logging events */
static const char *iscsit_se_name[SE_MAX_EVENT+1] = {
	"SE_UNDEFINED",
	"SE_CONN_IN_LOGIN",
	"SE_CONN_LOGGED_IN",
	"SE_CONN_FFP_FAIL",
	"SE_CONN_FFP_DISABLE",
	"SE_CONN_FAIL",
	"SE_SESSION_CLOSE",
	"SE_SESSION_REINSTATE",
	"SE_SESSION_TIMEOUT",
	"SE_SESSION_CONTINUE",
	"SE_SESSION_CONTINUE_FAIL",
	"SE_MAX_EVENT"
};
#endif

/*
 * Set in ist_tgt after iscsit_tgt_unbind_sess to differentiate an unbound
 * session from a discovery session.
 */
#define	SESS_UNBOUND_FROM_TGT	-1

typedef struct {
	stmf_scsi_session_t	*ist_stmf_sess;
	stmf_local_port_t	*ist_lport;
	iscsit_tgt_t		*ist_tgt;
	idm_refcnt_t		ist_refcnt;
	kmem_cache_t		*ist_task_cache;
	kmutex_t		ist_sn_mutex;
	kmutex_t		ist_mutex;
	kcondvar_t		ist_cv;
	iscsit_session_state_t	ist_state;
	iscsit_session_state_t	ist_last_state;
	sm_audit_buf_t		ist_state_audit;
	boolean_t		ist_sm_busy;
	boolean_t		ist_sm_complete;
	boolean_t		ist_admin_close;
	list_t			ist_events;
	int			ist_conn_count;
	int			ist_ffp_conn_count;
	struct iscsit_conn_s	*ist_failed_conn;
	timeout_id_t		ist_state_timeout;
	list_t			ist_conn_list;
	avl_node_t		ist_tgt_ln;
	char			*ist_initiator_name;
	char			*ist_initiator_alias;
	char			*ist_target_name;
	char			*ist_target_alias;
	uint8_t			ist_isid[ISCSI_ISID_LEN];
	uint16_t		ist_tsih;
	uint16_t		ist_tpgt_tag;
	uint32_t		ist_expcmdsn;
	uint32_t		ist_maxcmdsn;
	avl_tree_t		ist_task_list;
	iscsit_cbuf_t		*ist_rxpdu_queue;
} iscsit_sess_t;

/* Update iscsit_ils_name table whenever login states are modified */
typedef enum {
	ILS_UNDEFINED = 0,
	ILS_LOGIN_INIT,
	ILS_LOGIN_WAITING,	/* Waiting for more login PDU's */
	ILS_LOGIN_PROCESSING,	/* Processing login request */
	ILS_LOGIN_RESPONDING,	/* Sending login response */
	ILS_LOGIN_RESPONDED,	/* Sent login response (no trans. to FFP) */
	ILS_LOGIN_FFP,		/* Sending last login PDU for final response */
	ILS_LOGIN_DONE,		/* Last login PDU sent (so we can free it) */
	ILS_LOGIN_ERROR,	/* Login error, login failed */
	/* Add new login states above ILS_MAX_STATE */
	ILS_MAX_STATE
} iscsit_login_state_t;

#ifdef ISCSIT_LOGIN_SM_STRINGS
/* An array of login state text values, for use in logging login progress */
static const char *iscsit_ils_name[ILS_MAX_STATE+1] = {
	"ILS_UNDEFINED",
	"ILS_LOGIN_INIT",
	"ILS_LOGIN_WAITING",
	"ILS_LOGIN_PROCESSING",
	"ILS_LOGIN_RESPONDING",
	"ILS_LOGIN_RESPONDED",
	"ILS_LOGIN_FFP",
	"ILS_LOGIN_DONE",
	"ILS_LOGIN_ERROR",
	"ILS_MAX_STATE"
};
#endif

/* Update iscsit_ile_name table whenever login events are modified */
typedef enum {
	ILE_UNDEFINED = 0,
	ILE_LOGIN_RCV,
	ILE_LOGIN_RESP_READY,
	ILE_LOGIN_FFP,
	ILE_LOGIN_RESP_COMPLETE,
	ILE_LOGIN_ERROR,
	ILE_LOGIN_CONN_ERROR,
	/* Add new login events above ILE_MAX_EVENT */
	ILE_MAX_EVENT
} iscsit_login_event_t;

#ifdef ISCSIT_LOGIN_SM_STRINGS
/* An array of login event text values, for use in logging login events */
static const char *iscsit_ile_name[ILE_MAX_EVENT+1] = {
	"ILE_UNDEFINED",
	"ILE_LOGIN_RCV",
	"ILE_LOGIN_RESP_READY",
	"ILE_LOGIN_FFP",
	"ILE_LOGIN_RESP_COMPLETE",
	"ILE_LOGIN_ERROR",
	"ILE_LOGIN_CONN_ERROR",
	"ILE_MAX_EVENT"
};
#endif

typedef struct {
	uint32_t		op_initial_params_set:1,
				op_discovery_session:1,
				op_initial_r2t:1,
				op_immed_data:1,
				op_data_pdu_in_order:1,
				op_data_sequence_in_order:1,
				op_declarative_params_set:1;
	uint64_t		op_max_connections;
	uint64_t		op_max_recv_data_segment_length;
	uint64_t		op_max_burst_length;
	uint64_t		op_first_burst_length;
	uint64_t		op_default_time_2_wait;
	uint64_t		op_default_time_2_retain;
	uint64_t		op_max_outstanding_r2t;
	uint64_t		op_error_recovery_level;
} iscsit_op_params_t;

typedef struct {
	iscsit_login_state_t 	icl_login_state;
	iscsit_login_state_t 	icl_login_last_state;
	sm_audit_buf_t		icl_state_audit;
	boolean_t		icl_busy;
	boolean_t		icl_login_complete;
	kmutex_t		icl_mutex;
	uint32_t		icl_login_itt;
	uint8_t			icl_login_csg;
	uint8_t			icl_login_nsg;
	boolean_t		icl_login_transit;
	conn_auth_t		icl_auth;
	iscsit_auth_client_t	icl_auth_client;
	int			icl_auth_pass;
	list_t			icl_login_events;
	list_t			icl_pdu_list;
	uint16_t		icl_tsih;
	uint8_t			icl_isid[ISCSI_ISID_LEN];
	uint32_t		icl_cmdsn;
	uint16_t		icl_tpgt_tag;
	char			*icl_target_name;
	char			*icl_target_alias;
	char			*icl_initiator_name;
	char			*icl_login_resp_buf;
	void			*icl_login_resp_itb; /* mult-pdu idm buf */
	int			icl_login_resp_len; /* For kmem_free */
	int			icl_login_resp_valid_len;
	uint8_t			icl_login_resp_err_class;
	uint8_t			icl_login_resp_err_detail;
	iscsi_login_rsp_hdr_t	*icl_login_resp_tmpl;
	nvlist_t		*icl_request_nvlist;
	nvlist_t		*icl_response_nvlist;
	nvlist_t		*icl_negotiated_values;
} iscsit_conn_login_t;

#define	SET_LOGIN_ERROR(SLE_ICT, SLE_CLASS, SLE_DETAIL) \
	(SLE_ICT)->ict_login_sm.icl_login_resp_err_class = (SLE_CLASS); \
	(SLE_ICT)->ict_login_sm.icl_login_resp_err_detail = (SLE_DETAIL);

typedef struct iscsit_conn_s {
	idm_conn_t		*ict_ic;
	iscsit_sess_t		*ict_sess;
	kmutex_t		ict_mutex;
	idm_refcnt_t		ict_refcnt;
	idm_refcnt_t		ict_dispatch_refcnt;
	list_node_t		ict_sess_ln;
	iscsit_conn_login_t	ict_login_sm;
	iscsit_op_params_t	ict_op;
	uint16_t		ict_cid;
	uint32_t		ict_statsn;
	kmutex_t		ict_statsn_mutex;
	uint32_t		ict_keepalive_ttt;
	struct iscsit_conn_s	*ict_reinstate_conn;
	uint32_t		ict_reinstating:1,
				ict_lost:1,
				ict_destroyed:1;
	/*
	 * Parameters for processing text commands
	 */
	char			*ict_text_rsp_buf;
	uint32_t		ict_text_rsp_len;
	uint32_t		ict_text_rsp_valid_len;
	uint32_t		ict_text_rsp_off;
	uint32_t		ict_text_req_itt;	/* from initiator */
	uint32_t		ict_text_rsp_ttt;
} iscsit_conn_t;

#define	ICT_FLAGS_DISCOVERY	0x00000001

typedef struct {
	idm_buf_t		*ibuf_idm_buf;
	stmf_data_buf_t		*ibuf_stmf_buf;
	idm_pdu_t		*ibuf_immed_data_pdu;
	boolean_t		ibuf_is_immed;
} iscsit_buf_t;

typedef struct {
	scsi_task_t		*it_stmf_task;
	idm_task_t		*it_idm_task;
	iscsit_buf_t		*it_immed_data;
	iscsit_conn_t		*it_ict;
	kmutex_t		it_mutex;
	idm_pdu_t		*it_tm_pdu;
	uint32_t		it_stmf_abort:1,
				it_aborted:1,
				it_active:1,
				it_tm_task:1,
				it_tm_responded:1;
	uint32_t		it_cmdsn;
	uint32_t		it_itt;
	uint32_t		it_ttt;
	avl_node_t		it_sess_ln;
} iscsit_task_t;

typedef struct iscsit_isns_cfg {
	kmutex_t		isns_mutex;
	boolean_t		isns_state;
	list_t			isns_svrs;
} iscsit_isns_cfg_t;

/*
 * State values for the iscsit service
 */
typedef enum {
	ISE_UNDEFINED = 0,
	ISE_DETACHED,
	ISE_DISABLED,
	ISE_ENABLING,
	ISE_ENABLED,
	ISE_BUSY,
	ISE_DISABLING
} iscsit_service_enabled_t;


typedef struct {
	iscsit_service_enabled_t	global_svc_state;
	dev_info_t			*global_dip;
	ldi_ident_t			global_li;
	nvlist_t			*global_props;
	stmf_port_provider_t		*global_pp;
	stmf_dbuf_store_t		*global_dbuf_store;
	taskq_t				*global_dispatch_taskq;
	idm_refcnt_t			global_refcnt;
	avl_tree_t			global_discovery_sessions;
	avl_tree_t			global_target_list;
	list_t				global_deleted_target_list;
	avl_tree_t			global_tpg_list;
	avl_tree_t			global_ini_list;
	iscsit_tpg_t			*global_default_tpg;
	vmem_t				*global_tsih_pool;
	iscsit_isns_cfg_t		global_isns_cfg;
	iscsi_radius_props_t		global_radius_server;
	krwlock_t			global_rwlock;
	kmutex_t			global_state_mutex;
} iscsit_global_t;

extern iscsit_global_t iscsit_global;

void
iscsit_global_hold();

void
iscsit_global_rele();

void
iscsit_global_wait_ref();

idm_status_t
iscsit_login_sm_init(iscsit_conn_t *ict);

void
iscsit_login_sm_fini(iscsit_conn_t *ict);

void
iscsit_login_sm_event(iscsit_conn_t *ic, iscsit_login_event_t event,
    idm_pdu_t *pdu);

void
iscsit_login_sm_event_locked(iscsit_conn_t *ic, iscsit_login_event_t event,
    idm_pdu_t *pdu);

int
iscsit_is_v4_mapped(struct sockaddr_storage *sa, struct sockaddr_storage *v4sa);

void
iscsit_send_async_event(iscsit_conn_t *ict, uint8_t async_event);

void
iscsit_pdu_tx(idm_pdu_t *pdu);

void
iscsit_send_reject(iscsit_conn_t *ict, idm_pdu_t *rejected_pdu, uint8_t reason);

void
iscsit_text_cmd_fini(iscsit_conn_t *ict);

/*
 * IDM conn ops
 */

idm_rx_pdu_cb_t		iscsit_op_scsi_cmd;
idm_rx_pdu_cb_t		iscsit_rx_pdu;
idm_rx_pdu_error_cb_t	iscsit_rx_pdu_error;
idm_rx_pdu_cb_t		iscsit_rx_scsi_rsp;
idm_task_cb_t		iscsit_task_aborted;
idm_client_notify_cb_t	iscsit_client_notify;
idm_build_hdr_cb_t	iscsit_build_hdr;
idm_update_statsn_cb_t	iscsit_update_statsn;
idm_keepalive_cb_t	iscsit_keepalive;

/*
 * lport entry points
 */
stmf_status_t
iscsit_xfer_scsi_data(scsi_task_t *task, stmf_data_buf_t *dbuf,
    uint32_t ioflags);

stmf_status_t
iscsit_send_scsi_status(scsi_task_t *task, uint32_t ioflags);

void
iscsit_lport_task_free(scsi_task_t *task);

stmf_status_t
iscsit_abort(stmf_local_port_t *lport, int abort_cmd, void *arg,
    uint32_t flags);

void
iscsit_ctl(stmf_local_port_t *lport, int cmd, void *arg);

/*
 * Connection functions
 */
idm_status_t
iscsit_conn_reinstate(iscsit_conn_t *existing_ict, iscsit_conn_t *ict);

void
iscsit_conn_destroy_done(iscsit_conn_t *ict);

void
iscsit_conn_set_auth(iscsit_conn_t *ict);

void
iscsit_conn_hold(iscsit_conn_t *ict);

void
iscsit_conn_rele(iscsit_conn_t *ict);

void
iscsit_conn_logout(iscsit_conn_t *ict);

/*
 * Session functions
 */
int
iscsit_sess_avl_compare(const void *void_sess1, const void *void_sess2);

iscsit_sess_t *
iscsit_sess_create(iscsit_tgt_t *tgt, iscsit_conn_t *ict,
    uint32_t cmdsn, uint8_t *isid, uint16_t tag,
    char *initiator_name, char *target_name,
    uint8_t *error_class, uint8_t *error_detail);

void
iscsit_sess_destroy(iscsit_sess_t *ist);

void
iscsit_sess_hold(iscsit_sess_t *ist);

idm_status_t
iscsit_sess_check_hold(iscsit_sess_t *ist);

void
iscsit_sess_rele(iscsit_sess_t *ist);

iscsit_conn_t *
iscsit_sess_lookup_conn(iscsit_sess_t *ist, uint16_t cid);

void
iscsit_sess_bind_conn(iscsit_sess_t *ist, iscsit_conn_t *ict);

void
iscsit_sess_unbind_conn(iscsit_sess_t *ist, iscsit_conn_t *ict);

void
iscsit_sess_close(iscsit_sess_t *ist);

iscsit_sess_t *
iscsit_sess_reinstate(iscsit_tgt_t *tgt, iscsit_sess_t *ist, iscsit_conn_t *ict,
    uint8_t *error_class, uint8_t *error_detail);

void
iscsit_sess_sm_event(iscsit_sess_t *ist, iscsit_session_event_t event,
    iscsit_conn_t *ict);

/*
 * Target, TPGT, TPGT and portal functions
 */

void
iscsit_tgt_sm_event(iscsit_tgt_t *tgt, iscsit_tgt_event_t event);

void
tgt_sm_event_locked(iscsit_tgt_t *tgt, iscsit_tgt_event_t event);

it_cfg_status_t
iscsit_config_merge_tgt(it_config_t *cfg);

void
iscsit_config_destroy_tgts(list_t *tgt_del_list);

void
iscsit_config_destroy_tpgts(list_t *tpgt_del_list);

iscsit_tgt_t *
iscsit_tgt_lookup(char *target_name);

iscsit_tgt_t *
iscsit_tgt_lookup_locked(char *target_name);

int
iscsit_tgt_avl_compare(const void *void_tgt1, const void *void_tgt2);

int
iscsit_tpgt_avl_compare(const void *void_tpgt1, const void *void_tpgt2);

void
iscsit_tgt_hold(iscsit_tgt_t *tgt);

void
iscsit_tgt_rele(iscsit_tgt_t *tgt);

iscsit_tpgt_t *
iscsit_tgt_lookup_tpgt(iscsit_tgt_t *tgt, uint16_t tag);

void
iscsit_tpgt_hold(iscsit_tpgt_t *tpgt);

void
iscsit_tpgt_rele(iscsit_tpgt_t *tpgt);

iscsit_portal_t *
iscsit_tgt_lookup_portal(iscsit_tgt_t *tgt, struct sockaddr_storage *sa,
    iscsit_tpgt_t **output_tpgt);

iscsit_sess_t *
iscsit_tgt_lookup_sess(iscsit_tgt_t *tgt, char *initiator_name,
    uint8_t *isid, uint16_t tsih, uint16_t tag);

void
iscsit_tgt_bind_sess(iscsit_tgt_t *tgt, iscsit_sess_t *sess);

void
iscsit_tgt_unbind_sess(iscsit_tgt_t *tgt, iscsit_sess_t *sess);

it_cfg_status_t
iscsit_config_merge_tpg(it_config_t *cfg, list_t *tpg_del_list);

void
iscsit_config_destroy_tpgs(list_t *tpg_del_list);

iscsit_tpg_t *
iscsit_tpg_lookup(char *tpg_name);

int
iscsit_tpg_avl_compare(const void *void_tpg1, const void *void_tpg2);

void
iscsit_tpg_hold(iscsit_tpg_t *tpg);

void
iscsit_tpg_rele(iscsit_tpg_t *tpg);

iscsit_tpg_t *
iscsit_tpg_createdefault();

void
iscsit_tpg_destroydefault(iscsit_tpg_t *tpg);

idm_status_t
iscsit_tpg_online(iscsit_tpg_t *tpg);

void
iscsit_tpg_offline(iscsit_tpg_t *tpg);

iscsit_portal_t *
iscsit_tpg_portal_lookup(iscsit_tpg_t *tpg, struct sockaddr_storage *sa);

void
iscsit_portal_hold(iscsit_portal_t *portal);

void
iscsit_portal_rele(iscsit_portal_t *portal);

it_cfg_status_t
iscsit_config_merge_ini(it_config_t *cfg);

int
iscsit_ini_avl_compare(const void *void_ini1, const void *void_ini2);

iscsit_ini_t *
iscsit_ini_lookup_locked(char *ini_name);

int
iscsit_portal_avl_compare(const void *void_portal1, const void *void_portal2);

int
iscsit_verify_chap_resp(iscsit_conn_login_t *lsm,
    unsigned int chap_i, uchar_t *chap_c, unsigned int challenge_len,
    uchar_t *chap_r, unsigned int resp_len);

void
iscsit_rxpdu_queue_monitor_start(void);

void
iscsit_rxpdu_queue_monitor_stop(void);

#endif /* _ISCSIT_H_ */
