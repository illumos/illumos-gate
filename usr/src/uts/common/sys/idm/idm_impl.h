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
/*
 * Copyright 2014 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef	_IDM_IMPL_H_
#define	_IDM_IMPL_H_

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/avl.h>
#include <sys/socket_impl.h>
#include <sys/taskq_impl.h>

/*
 * IDM lock order:
 *
 * idm_taskid_table_lock, idm_task_t.idt_mutex
 */

#define	CF_LOGIN_READY		0x00000001
#define	CF_INITIAL_LOGIN	0x00000002
#define	CF_ERROR		0x80000000

typedef enum {
	CONN_TYPE_INI = 1,
	CONN_TYPE_TGT
} idm_conn_type_t;

/*
 * Watchdog interval in seconds
 */
#define	IDM_WD_INTERVAL			5

/*
 * Timeout period before the client "keepalive" callback is invoked in
 * seconds if the connection is idle.
 */
#define	IDM_TRANSPORT_KEEPALIVE_IDLE_TIMEOUT	20

/*
 * Timeout period before a TRANSPORT_FAIL event is generated in seconds
 * if the connection is idle.
 */
#define	IDM_TRANSPORT_FAIL_IDLE_TIMEOUT	30

/*
 * IDM reference count structure.  Audit code is shamelessly adapted
 * from CIFS server.
 */

#define	REFCNT_AUDIT_STACK_DEPTH	16
#define	REFCNT_AUDIT_BUF_MAX_REC	16

typedef struct {
	uint32_t		anr_refcnt;
	int			anr_depth;
	pc_t			anr_stack[REFCNT_AUDIT_STACK_DEPTH];
} refcnt_audit_record_t;

typedef struct {
	int			anb_index;
	int			anb_max_index;
	refcnt_audit_record_t	anb_records[REFCNT_AUDIT_BUF_MAX_REC];
} refcnt_audit_buf_t;

#define	REFCNT_AUDIT(_rf_) {				\
	refcnt_audit_record_t	*anr;			\
							\
	anr = (_rf_)->ir_audit_buf.anb_records;		\
	anr += (_rf_)->ir_audit_buf.anb_index;		\
	(_rf_)->ir_audit_buf.anb_index++;		\
	(_rf_)->ir_audit_buf.anb_index &=		\
	    (_rf_)->ir_audit_buf.anb_max_index;		\
	anr->anr_refcnt = (_rf_)->ir_refcnt;		\
	anr->anr_depth = getpcstack(anr->anr_stack,	\
	    REFCNT_AUDIT_STACK_DEPTH);			\
}

struct idm_refcnt_s;

typedef void (idm_refcnt_cb_t)(void *ref_obj);

typedef enum {
	REF_NOWAIT,
	REF_WAIT_SYNC,
	REF_WAIT_ASYNC
} idm_refcnt_wait_t;

typedef struct idm_refcnt_s {
	int			ir_refcnt;
	void			*ir_referenced_obj;
	idm_refcnt_wait_t	ir_waiting;
	kmutex_t		ir_mutex;
	kcondvar_t		ir_cv;
	idm_refcnt_cb_t		*ir_cb;
	refcnt_audit_buf_t	ir_audit_buf;
} idm_refcnt_t;

/*
 * connection parameters - These parameters would be populated at
 * connection create, or during key-value negotiation at login
 */
typedef struct idm_conn_params_s {
	uint32_t		max_recv_dataseglen;
	uint32_t		max_xmit_dataseglen;
	uint32_t		conn_login_max;
	uint32_t		conn_login_interval;
	boolean_t		nonblock_socket;
} idm_conn_param_t;

typedef struct idm_svc_s {
	list_node_t		is_list_node;
	kmutex_t		is_mutex;
	kcondvar_t		is_cv;
	kmutex_t		is_count_mutex;
	kcondvar_t		is_count_cv;
	idm_refcnt_t		is_refcnt;
	int			is_online;
	/* transport-specific service components */
	void			*is_so_svc;
	void			*is_iser_svc;
	idm_svc_req_t		is_svc_req;
} idm_svc_t;

#define	ISCSI_MAX_TSIH_LEN	6	/* 0x%04x */
#define	ISCSI_MAX_ISID_LEN	ISCSI_ISID_LEN * 2

typedef struct idm_conn_s {
	list_node_t		ic_list_node;
	void			*ic_handle;
	idm_refcnt_t		ic_refcnt;
	idm_svc_t		*ic_svc_binding; /* Target conn. only */
	idm_sockaddr_t 		ic_ini_dst_addr;
	struct sockaddr_storage	ic_laddr;	/* conn local address */
	struct sockaddr_storage	ic_raddr;	/* conn remote address */

	/*
	 * the target_name, initiator_name, initiator session
	 * identifier and target session identifying handle
	 * are only used for target connections.
	 */
	char			ic_target_name[ISCSI_MAX_NAME_LEN + 1];
	char			ic_initiator_name[ISCSI_MAX_NAME_LEN + 1];
	char			ic_tsih[ISCSI_MAX_TSIH_LEN + 1];
	char			ic_isid[ISCSI_MAX_ISID_LEN + 1];
	idm_conn_state_t	ic_state;
	idm_conn_state_t	ic_last_state;
	sm_audit_buf_t		ic_state_audit;
	kmutex_t		ic_state_mutex;
	kcondvar_t		ic_state_cv;
	uint32_t		ic_state_flags;
	timeout_id_t		ic_state_timeout;
	struct idm_conn_s	*ic_reinstate_conn; /* For conn reinst. */
	struct idm_conn_s	*ic_logout_conn; /* For other conn logout */
	taskq_t			*ic_state_taskq;
	int			ic_pdu_events;
	boolean_t		ic_login_info_valid;
	boolean_t		ic_rdma_extensions;
	uint16_t		ic_login_cid;

	kmutex_t		ic_mutex;
	kcondvar_t		ic_cv;
	idm_status_t		ic_conn_sm_status;

	boolean_t		ic_ffp;
	boolean_t		ic_keepalive;
	uint32_t		ic_internal_cid;

	uint32_t		ic_conn_flags;
	idm_conn_type_t		ic_conn_type;
	idm_conn_ops_t		ic_conn_ops;
	idm_transport_ops_t	*ic_transport_ops;
	idm_transport_type_t	ic_transport_type;
	int			ic_transport_hdrlen;
	void			*ic_transport_private;
	idm_conn_param_t	ic_conn_params;
	/*
	 * Save client callback to interpose idm callback
	 */
	idm_pdu_cb_t		*ic_client_callback;
	clock_t			ic_timestamp;
} idm_conn_t;

#define	IDM_CONN_HEADER_DIGEST	0x00000001
#define	IDM_CONN_DATA_DIGEST	0x00000002
#define	IDM_CONN_USE_SCOREBOARD	0x00000004

#define	IDM_CONN_ISINI(ICI_IC)	((ICI_IC)->ic_conn_type == CONN_TYPE_INI)
#define	IDM_CONN_ISTGT(ICI_IC)	((ICI_IC)->ic_conn_type == CONN_TYPE_TGT)

/*
 * An IDM target task can transfer data using multiple buffers. The task
 * will maintain a list of buffers, and each buffer will contain the relative
 * offset of the transfer and a pointer to the next buffer in the list.
 *
 * Note on client private data:
 * idt_private is intended to be a pointer to some sort of client-
 * specific state.
 *
 * idt_client_handle is a more generic client-private piece of data that can
 * be used by the client for the express purpose of task lookup.  The driving
 * use case for this is for the client to store the initiator task tag for
 * a given task so that it may be more easily retrieved for task management.
 *
 * The key take away here is that clients should never call
 * idm_task_find_by_handle in the performance path.
 *
 * An initiator will require only one buffer per task, the offset will be 0.
 */

typedef struct idm_task_s {
	idm_conn_t		*idt_ic;	/* Associated connection */
	/* connection type is in idt_ic->ic_conn_type */
	kmutex_t		idt_mutex;
	void			*idt_private;	/* Client private data */
	uintptr_t		idt_client_handle;	/* Client private */
	uint32_t		idt_tt;		/* Task tag */
	uint32_t		idt_r2t_ttt;	/* R2T Target Task tag */
	idm_task_state_t	idt_state;
	idm_refcnt_t		idt_refcnt;

	/*
	 * Statistics
	 */
	int			idt_tx_to_ini_start;
	int			idt_tx_to_ini_done;
	int			idt_rx_from_ini_start;
	int			idt_rx_from_ini_done;
	int			idt_tx_bytes;	/* IDM_CONN_USE_SCOREBOARD */
	int			idt_rx_bytes;	/* IDM_CONN_USE_SCOREBOARD */

	uint32_t		idt_exp_datasn;	/* expected datasn */
	uint32_t		idt_exp_rttsn;	/* expected rttsn */
	list_t			idt_inbufv;	/* chunks of IN buffers */
	list_t			idt_outbufv;	/* chunks of OUT buffers */

	/*
	 * Transport header, which describes this tasks remote tagged buffer
	 */
	int			idt_transport_hdrlen;
	void			*idt_transport_hdr;
	uint32_t		idt_flags;	/* phase collapse */
} idm_task_t;

int idm_task_constructor(void *task_void, void *arg, int flags);
void idm_task_destructor(void *task_void, void *arg);

#define	IDM_TASKIDS_MAX		16384
#define	IDM_BUF_MAGIC		0x49425546	/* "IBUF" */

#define	IDM_TASK_PHASECOLLAPSE_REQ	0x00000001 /* request phase collapse */
#define	IDM_TASK_PHASECOLLAPSE_SUCCESS	0x00000002 /* phase collapse success */

/* Protect with task mutex */
typedef struct idm_buf_s {
	uint32_t	idb_magic;	/* "IBUF" */

	/*
	 * Note: idm_tx_link *must* be the second element in the list for
	 * proper TX PDU ordering.
	 */
	list_node_t	idm_tx_link;	/* link in a list of TX objects */

	list_node_t	idb_buflink;	/* link in a multi-buffer data xfer */
	idm_conn_t	*idb_ic;	/* Associated connection */
	void		*idb_buf;	/* data */
	uint64_t	idb_buflen;	/* length of buffer */
	size_t		idb_bufoffset;	/* offset in a multi-buffer xfer */
	boolean_t	idb_bufalloc;  /* true if alloc'd in idm_buf_alloc */
	/*
	 * DataPDUInOrder=Yes, so to track that the PDUs in a sequence are sent
	 * in continuously increasing address order, check that offsets for a
	 * single buffer xfer are in order.
	 */
	uint32_t	idb_exp_offset;
	size_t		idb_xfer_len;	/* Current requested xfer len */
	void		*idb_buf_private; /* transport-specific buf handle */
	void		*idb_reg_private; /* transport-specific reg handle */
	void		*idb_bufptr; /* transport-specific bcopy pointer */
	boolean_t	idb_bufbcopy;	/* true if bcopy required */

	idm_buf_cb_t	*idb_buf_cb;	/* Data Completion Notify, tgt only */
	void		*idb_cb_arg;	/* Client private data */
	idm_task_t	*idb_task_binding;
	timespec_t	idb_xfer_start;
	timespec_t	idb_xfer_done;
	boolean_t	idb_in_transport;
	boolean_t	idb_tx_thread;		/* Sockets only */
	iscsi_hdr_t	idb_data_hdr_tmpl;	/* Sockets only */
	idm_status_t	idb_status;
} idm_buf_t;

typedef enum {
	BP_CHECK_QUICK,
	BP_CHECK_THOROUGH,
	BP_CHECK_ASSERT
} idm_bufpat_check_type_t;

#define	BUFPAT_MATCH(bc_bufpat, bc_idb) 		\
	((bufpat->bufpat_idb == bc_idb) &&		\
	    (bufpat->bufpat_bufmagic == IDM_BUF_MAGIC))

typedef struct idm_bufpat_s {
	void		*bufpat_idb;
	uint32_t	bufpat_bufmagic;
	uint32_t	bufpat_offset;
} idm_bufpat_t;

#define	PDU_MAX_IOVLEN	12
#define	IDM_PDU_MAGIC	0x49504455	/* "IPDU" */

typedef struct idm_pdu_s {
	uint32_t	isp_magic;	/* "IPDU" */

	/*
	 * Internal - Order is vital.  idm_tx_link *must* be the second
	 * element in this structure for proper TX PDU ordering.
	 */
	list_node_t	idm_tx_link;

	list_node_t	isp_client_lnd;

	idm_conn_t	*isp_ic;	/* Must be set */
	iscsi_hdr_t	*isp_hdr;
	uint_t		isp_hdrlen;
	uint8_t		*isp_data;
	uint_t		isp_datalen;

	/* Transport header */
	void		*isp_transport_hdr;
	uint32_t	isp_transport_hdrlen;
	void		*isp_transport_private;

	/*
	 * isp_data is used for sending SCSI status, NOP, text, scsi and
	 * non-scsi data. Data is received using isp_iov and isp_iovlen
	 * to support data over multiple buffers.
	 */
	void		*isp_private;
	idm_pdu_cb_t	*isp_callback;
	idm_status_t	isp_status;

	/*
	 * The following four elements are only used in
	 * idm_sorecv_scsidata() currently.
	 */
	struct iovec	isp_iov[PDU_MAX_IOVLEN];
	int		isp_iovlen;
	idm_buf_t	*isp_sorx_buf;

	/* Implementation data for idm_pdu_alloc and sorx PDU cache */
	uint32_t	isp_flags;
	uint_t		isp_hdrbuflen;
	uint_t		isp_databuflen;
	hrtime_t	isp_queue_time;

	/* Taskq dispatching state for deferred PDU */
	taskq_ent_t	isp_tqent;
} idm_pdu_t;

/*
 * This "generic" object is used when removing an item from the ic_tx_list
 * in order to determine whether it's an idm_pdu_t or an idm_buf_t
 */

typedef struct {
	uint32_t	idm_tx_obj_magic;
	/*
	 * idm_tx_link *must* be the second element in this structure.
	 */
	list_node_t	idm_tx_link;
} idm_tx_obj_t;


#define	IDM_PDU_OPCODE(PDU) \
	((PDU)->isp_hdr->opcode & ISCSI_OPCODE_MASK)

#define	IDM_PDU_ALLOC		0x00000001
#define	IDM_PDU_ADDL_HDR	0x00000002
#define	IDM_PDU_ADDL_DATA	0x00000004
#define	IDM_PDU_LOGIN_TX	0x00000008
#define	IDM_PDU_SET_STATSN	0x00000010
#define	IDM_PDU_ADVANCE_STATSN	0x00000020

#define	OSD_EXT_CDB_AHSLEN	(200 - 15)
#define	BIDI_AHS_LENGTH		5
#define	IDM_SORX_CACHE_AHSLEN \
	(((OSD_EXT_CDB_AHSLEN + 3) + \
	    (BIDI_AHS_LENGTH + 3)) / sizeof (uint32_t))
#define	IDM_SORX_CACHE_HDRLEN	(sizeof (iscsi_hdr_t) + IDM_SORX_CACHE_AHSLEN)

/*
 * ID pool
 */

#define	IDM_IDPOOL_MAGIC	0x4944504C	/* IDPL */
#define	IDM_IDPOOL_MIN_SIZE	64	/* Number of IDs to begin with */
#define	IDM_IDPOOL_MAX_SIZE	64 * 1024

typedef struct idm_idpool {
	uint32_t	id_magic;
	kmutex_t	id_mutex;
	uint8_t		*id_pool;
	uint32_t	id_size;
	uint8_t		id_bit;
	uint8_t		id_bit_idx;
	uint32_t	id_idx;
	uint32_t	id_idx_msk;
	uint32_t	id_free_counter;
	uint32_t	id_max_free_counter;
} idm_idpool_t;

/*
 * Global IDM state structure
 */
typedef struct {
	kmutex_t	idm_global_mutex;
	taskq_t		*idm_global_taskq;
	kthread_t	*idm_wd_thread;
	kt_did_t	idm_wd_thread_did;
	boolean_t	idm_wd_thread_running;
	kcondvar_t	idm_wd_cv;
	list_t		idm_tgt_svc_list;
	kcondvar_t	idm_tgt_svc_cv;
	list_t		idm_tgt_conn_list;
	int		idm_tgt_conn_count;
	list_t		idm_ini_conn_list;
	kmem_cache_t	*idm_buf_cache;
	kmem_cache_t	*idm_task_cache;
	krwlock_t	idm_taskid_table_lock;
	idm_task_t	**idm_taskid_table;
	uint32_t	idm_taskid_next;
	uint32_t	idm_taskid_max;
	idm_idpool_t	idm_conn_id_pool;
	kmem_cache_t	*idm_sotx_pdu_cache;
	kmem_cache_t	*idm_sorx_pdu_cache;
	kmem_cache_t	*idm_so_128k_buf_cache;
} idm_global_t;

idm_global_t	idm; /* Global state */

int
idm_idpool_create(idm_idpool_t	*pool);

void
idm_idpool_destroy(idm_idpool_t *pool);

int
idm_idpool_alloc(idm_idpool_t *pool, uint16_t *id);

void
idm_idpool_free(idm_idpool_t *pool, uint16_t id);

void
idm_pdu_rx(idm_conn_t *ic, idm_pdu_t *pdu);

void
idm_pdu_tx_forward(idm_conn_t *ic, idm_pdu_t *pdu);

boolean_t
idm_pdu_rx_forward_ffp(idm_conn_t *ic, idm_pdu_t *pdu);

void
idm_pdu_rx_forward(idm_conn_t *ic, idm_pdu_t *pdu);

void
idm_pdu_tx_protocol_error(idm_conn_t *ic, idm_pdu_t *pdu);

void
idm_pdu_rx_protocol_error(idm_conn_t *ic, idm_pdu_t *pdu);

void idm_parse_login_rsp(idm_conn_t *ic, idm_pdu_t *logout_req_pdu,
    boolean_t rx);

void idm_parse_logout_req(idm_conn_t *ic, idm_pdu_t *logout_req_pdu,
    boolean_t rx);

void idm_parse_logout_rsp(idm_conn_t *ic, idm_pdu_t *login_rsp_pdu,
    boolean_t rx);

idm_status_t idm_svc_conn_create(idm_svc_t *is, idm_transport_type_t type,
    idm_conn_t **ic_result);

void idm_svc_conn_destroy(idm_conn_t *ic);

idm_status_t idm_ini_conn_finish(idm_conn_t *ic);

idm_status_t idm_tgt_conn_finish(idm_conn_t *ic);

idm_conn_t *idm_conn_create_common(idm_conn_type_t conn_type,
    idm_transport_type_t tt, idm_conn_ops_t *conn_ops);

void idm_conn_destroy_common(idm_conn_t *ic);

void idm_conn_close(idm_conn_t *ic);

uint32_t idm_cid_alloc(void);

void idm_cid_free(uint32_t cid);

uint32_t idm_crc32c(void *address, unsigned long length);

uint32_t idm_crc32c_continued(void *address, unsigned long length,
    uint32_t crc);

void idm_listbuf_insert(list_t *lst, idm_buf_t *buf);

idm_conn_t *idm_lookup_conn(uint8_t *isid, uint16_t tsih, uint16_t cid);

#ifdef	__cplusplus
}
#endif

#endif /* _IDM_IMPL_H_ */
