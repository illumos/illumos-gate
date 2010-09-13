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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _IDM_H
#define	_IDM_H

#ifdef	__cplusplus
extern "C" {
#endif

typedef enum {
	IDM_STATUS_SUCCESS = 0,
	IDM_STATUS_FAIL,
	IDM_STATUS_NORESOURCES,
	IDM_STATUS_REJECT,
	IDM_STATUS_IO,
	IDM_STATUS_ABORTED,
	IDM_STATUS_SUSPENDED,
	IDM_STATUS_HEADER_DIGEST,
	IDM_STATUS_DATA_DIGEST,
	IDM_STATUS_PROTOCOL_ERROR,
	IDM_STATUS_LOGIN_FAIL
} idm_status_t;


typedef enum {
	CN_CONNECT_ACCEPT = 1,	/* Target only */
	CN_LOGIN_FAIL,
	CN_READY_FOR_LOGIN,	/* Initiator only */
	CN_FFP_ENABLED,
	CN_FFP_DISABLED,
	CN_CONNECT_LOST,
	CN_CONNECT_DESTROY,
	CN_CONNECT_FAIL,
	CN_MAX
} idm_client_notify_t;

#ifdef IDM_CN_NOTIFY_STRINGS
static const char *idm_cn_strings[CN_MAX + 1] = {
	"CN_UNDEFINED",
	"CN_CONNECT_ACCEPT",
	"CN_LOGIN_FAIL",
	"CN_READY_FOR_LOGIN",
	"CN_FFP_ENABLED",
	"CN_FFP_DISABLED",
	"CN_CONNECT_LOST",
	"CN_CONNECT_DESTROY",
	"CN_CONNECT_FAIL",
	"CN_MAX"
};
#endif

typedef enum {
	FD_CONN_FAIL,
	FD_CONN_LOGOUT,
	FD_SESS_LOGOUT
} idm_ffp_disable_t;

typedef enum {
	AT_INTERNAL_SUSPEND,
	AT_INTERNAL_ABORT,
	AT_TASK_MGMT_ABORT
} idm_abort_type_t;

typedef enum {
	TASK_IDLE,
	TASK_ACTIVE,
	TASK_SUSPENDING,
	TASK_SUSPENDED,
	TASK_ABORTING,
	TASK_ABORTED,
	TASK_COMPLETE,
	TASK_MAX_STATE
} idm_task_state_t;

#ifdef IDM_TASK_SM_STRINGS
static const char *idm_ts_name[TASK_MAX_STATE+1] = {
	"TASK_IDLE",
	"TASK_ACTIVE",
	"TASK_SUSPENDING",
	"TASK_SUSPENDED",
	"TASK_ABORTING",
	"TASK_ABORTED",
	"TASK_COMPLETE",
	"TASK_MAX_STATE"
};
#endif

typedef enum {
	KV_HANDLED = 0,
	KV_HANDLED_NO_TRANSIT,
	KV_UNHANDLED,
	KV_TARGET_ONLY,
	KV_NO_RESOURCES,
	KV_INTERNAL_ERROR,
	KV_VALUE_ERROR,
	KV_MISSING_FIELDS,
	KV_AUTH_FAILED
} kv_status_t;

/*
 * Request structures
 */

/* Defined in idm_impl.h */
struct idm_conn_s;
struct idm_svc_s;
struct idm_buf_s;
struct idm_pdu_s;
struct idm_task_s;

typedef idm_status_t (idm_client_notify_cb_t)(
    struct idm_conn_s *ic, idm_client_notify_t cn, uintptr_t data);

typedef void (idm_rx_pdu_cb_t)(struct idm_conn_s *ic, struct idm_pdu_s *pdu);

typedef void (idm_rx_pdu_error_cb_t)(struct idm_conn_s *ic,
    struct idm_pdu_s *pdu, idm_status_t status);

typedef void (idm_buf_cb_t)(struct idm_buf_s *idb, idm_status_t status);

typedef void (idm_pdu_cb_t)(struct idm_pdu_s *pdu, idm_status_t status);

typedef void (idm_task_cb_t)(struct idm_task_s *task, idm_status_t status);

typedef void (idm_build_hdr_cb_t)(
    struct idm_task_s *task, struct idm_pdu_s *pdu, uint8_t opcode);

typedef void (idm_update_statsn_cb_t)(
    struct idm_task_s *task, struct idm_pdu_s *pdu);

typedef void (idm_keepalive_cb_t)(struct idm_conn_s *ic);

typedef union idm_sockaddr {
	struct sockaddr		sin;
	struct sockaddr_in	sin4;
	struct sockaddr_in6	sin6;
} idm_sockaddr_t;

#define	SIZEOF_SOCKADDR(so)		\
	((so)->sa_family == AF_INET ?	\
	sizeof (struct sockaddr_in) : sizeof (struct sockaddr_in6))

typedef struct {
	idm_rx_pdu_cb_t		*icb_rx_scsi_cmd;
	idm_rx_pdu_cb_t		*icb_rx_scsi_rsp;
	idm_rx_pdu_cb_t		*icb_rx_misc;
	idm_rx_pdu_error_cb_t	*icb_rx_error;
	idm_task_cb_t		*icb_task_aborted;
	idm_client_notify_cb_t	*icb_client_notify;
	idm_build_hdr_cb_t	*icb_build_hdr;
	idm_update_statsn_cb_t	*icb_update_statsn; /* advance statsn */
	idm_keepalive_cb_t	*icb_keepalive;
} idm_conn_ops_t;

typedef struct {
	int			cr_domain;
	int			cr_type;
	int			cr_protocol;
	boolean_t		cr_bound;
	idm_sockaddr_t		cr_bound_addr;
	idm_sockaddr_t		cr_ini_dst_addr;
	ldi_ident_t		cr_li;
	idm_conn_ops_t		icr_conn_ops;
	boolean_t		cr_boot_conn;
} idm_conn_req_t;

typedef struct {
	uint16_t		sr_port;
	ldi_ident_t		sr_li;
	idm_conn_ops_t		sr_conn_ops;
} idm_svc_req_t;


/* This is not how other networking code handles this */
typedef struct {
	union {
		struct in_addr	in4;
		struct in6_addr	in6;
	} i_addr;
	/* i_insize determines which is valid in the union above */
	int			i_insize;
} idm_ipaddr_t;

typedef struct {
	idm_ipaddr_t		a_addr;
	uint32_t		a_port,
				a_oid;
} idm_addr_t;

typedef struct {
	uint32_t		al_vers,			/* In */
				al_oid;				/* In */
	uint32_t		al_in_cnt;			/* In */
	uint32_t		al_out_cnt;			/* Out */
	uint32_t		al_tpgt;			/* Out */
	idm_addr_t		al_addrs[1];			/* Out */
} idm_addr_list_t;

/*
 * State machine auditing
 */

#define	SM_AUDIT_BUF_MAX_REC	32

typedef enum {
	SAR_UNDEFINED = 0,
	SAR_STATE_EVENT,
	SAR_STATE_CHANGE
} sm_audit_record_type_t;

typedef enum {
	SAS_UNDEFINED = 0,
	SAS_IDM_CONN,
	SAS_IDM_TASK,
	SAS_ISCSIT_TGT,
	SAS_ISCSIT_SESS,
	SAS_ISCSIT_LOGIN,
	SAS_ISCSI_CMD,
	SAS_ISCSI_SESS,
	SAS_ISCSI_CONN,
	SAS_ISCSI_LOGIN
} sm_audit_sm_type_t;

typedef struct {
	timespec_t		sar_timestamp;
	sm_audit_sm_type_t	sar_sm_type;
	sm_audit_record_type_t	sar_type;
	int			sar_state;
	int			sar_new_state;	/* Only for SAR_STATE_CHANGE */
	int			sar_event;	/* Only for SAR_STATE_EVENT */
	uintptr_t		sar_event_info;	/* Only for SAR_STATE_EVENT */
} sm_audit_record_t;

typedef struct {
	int			sab_index;
	int			sab_max_index;
	sm_audit_record_t	sab_records[SM_AUDIT_BUF_MAX_REC];
} sm_audit_buf_t;

extern boolean_t idm_sm_logging;
extern boolean_t idm_conn_logging;
extern boolean_t idm_svc_logging;

#define	IDM_SM_LOG if (idm_sm_logging) cmn_err
#define	IDM_CONN_LOG if (idm_conn_logging) cmn_err
#define	IDM_SVC_LOG if (idm_svc_logging) cmn_err

void idm_sm_audit_init(sm_audit_buf_t *audit_buf);

void idm_sm_audit_event(sm_audit_buf_t *audit_buf,
    sm_audit_sm_type_t sm_type,
    int state, int event, uintptr_t event_info);

void idm_sm_audit_state_change(sm_audit_buf_t *audit_buf,
    sm_audit_sm_type_t sm_type, int state, int new_state);


#include <sys/iscsi_protocol.h>
#include <sys/idm/idm_conn_sm.h>
#include <sys/idm/idm_transport.h>
#include <sys/idm/idm_impl.h>
#include <sys/idm/idm_text.h>
#include <sys/idm/idm_so.h>

/*
 * iSCSI Initiator Services
 */

idm_status_t
idm_ini_conn_create(idm_conn_req_t *cr, idm_conn_t **new_con);

idm_status_t
idm_ini_conn_connect(idm_conn_t *ic);

void
idm_ini_conn_disconnect(idm_conn_t *ic);

void
idm_ini_conn_disconnect_sync(idm_conn_t *ic);

void
idm_ini_conn_destroy(idm_conn_t *ic);

/*
 * iSCSI Target Services
 */

idm_status_t
idm_tgt_svc_create(idm_svc_req_t *sr, idm_svc_t **new_svc);

idm_status_t
idm_tgt_svc_online(idm_svc_t *is);

void
idm_tgt_svc_offline(idm_svc_t *is);

void
idm_tgt_svc_destroy(idm_svc_t *is);

void
idm_tgt_svc_destroy_if_unref(idm_svc_t *is);

idm_svc_t *
idm_tgt_svc_lookup(uint16_t port);

void
idm_tgt_svc_hold(idm_svc_t *is);

void
idm_tgt_svc_rele_and_destroy(idm_svc_t *is);

idm_status_t
idm_tgt_conn_accept(idm_conn_t *ic);

void
idm_tgt_conn_reject(idm_conn_t *ic);

void
idm_conn_hold(idm_conn_t *ic);

void
idm_conn_rele(idm_conn_t *ic);

void
idm_conn_set_target_name(idm_conn_t *ic, char *target_name);

void
idm_conn_set_initiator_name(idm_conn_t *ic, char *initiator_name);

void
idm_conn_set_isid(idm_conn_t *ic, uint8_t isid[ISCSI_ISID_LEN]);

/*
 * Target data transfer services
 */
idm_status_t
idm_buf_tx_to_ini(idm_task_t *idt, idm_buf_t *idb,
    uint32_t offset, uint32_t xfer_length,
    idm_buf_cb_t idb_buf_cb, void *cb_arg);

idm_status_t
idm_buf_rx_from_ini(idm_task_t *idt, idm_buf_t *idb,
    uint32_t offset, uint32_t xfer_length,
    idm_buf_cb_t idb_buf_cb, void *cb_arg);

void
idm_buf_tx_to_ini_done(idm_task_t *idt, idm_buf_t *idb, idm_status_t status);

void
idm_buf_rx_from_ini_done(idm_task_t *idt, idm_buf_t *idb, idm_status_t status);

#define	XFER_BUF_TX_TO_INI	0
#define	XFER_BUF_RX_FROM_INI	1
/*
 * Shared Initiator/Target Services
 */
kv_status_t
idm_negotiate_key_values(idm_conn_t *ic, nvlist_t *request_nvl,
    nvlist_t *response_nvl, nvlist_t *negotiated_nvl);

void
idm_notice_key_values(idm_conn_t *ic, nvlist_t *negotiated_nvl);

kv_status_t
idm_declare_key_values(idm_conn_t *ic, nvlist_t *config_nvl,
    nvlist_t *outgoing_nvl);

/*
 * Buffer services
 */

idm_buf_t *
idm_buf_alloc(idm_conn_t *ic, void *bufptr, uint64_t buflen);

void
idm_buf_free(idm_buf_t *idb);

void
idm_buf_bind_in(idm_task_t *idt, idm_buf_t *buf);

void
idm_buf_bind_out(idm_task_t *idt, idm_buf_t *buf);

void
idm_buf_unbind_in(idm_task_t *idt, idm_buf_t *buf);

void
idm_buf_unbind_out(idm_task_t *idt, idm_buf_t *buf);

idm_buf_t *
idm_buf_find(void *lbuf, size_t data_offset);

void
idm_bufpat_set(idm_buf_t *idb);

boolean_t
idm_bufpat_check(idm_buf_t *idb, int check_len, idm_bufpat_check_type_t type);

extern boolean_t idm_pattern_checking;

#define	IDM_BUFPAT_SET(CHK_BUF) 				\
	if (idm_pattern_checking && (CHK_BUF)->idb_bufalloc) {	\
		idm_bufpat_set(CHK_BUF);			\
	}

#define	IDM_BUFPAT_CHECK(CHK_BUF, CHK_LEN, CHK_TYPE) 		\
	if (idm_pattern_checking) {				\
		(void) idm_bufpat_check(CHK_BUF, CHK_LEN, CHK_TYPE);	\
	}

/*
 * Task services
 */
idm_task_t *
idm_task_alloc(idm_conn_t *ic);

void
idm_task_start(idm_task_t *idt, uintptr_t handle);

void
idm_task_abort(idm_conn_t *ic, idm_task_t *idt, idm_abort_type_t abort_type);

void
idm_task_cleanup(idm_task_t *idt);

void
idm_task_done(idm_task_t *idt);

void
idm_task_free(idm_task_t *idt);

idm_task_t *
idm_task_find(idm_conn_t *ic, uint32_t itt, uint32_t ttt);

idm_task_t *
idm_task_find_and_complete(idm_conn_t *ic, uint32_t itt, uint32_t ttt);

void *
idm_task_find_by_handle(idm_conn_t *ic, uintptr_t handle);

void
idm_task_hold(idm_task_t *idt);

void
idm_task_rele(idm_task_t *idt);

/*
 * PDU Services
 */

idm_pdu_t *
idm_pdu_alloc(uint_t hdrlen, uint_t datalen);

idm_pdu_t *
idm_pdu_alloc_nosleep(uint_t hdrlen, uint_t datalen);

void
idm_pdu_free(idm_pdu_t *pdu);

void
idm_pdu_init(idm_pdu_t *pdu, idm_conn_t *ic, void *private, idm_pdu_cb_t *cb);

void
idm_pdu_init_hdr(idm_pdu_t *pdu, uint8_t *hdr, uint_t hdrlen);

void
idm_pdu_init_data(idm_pdu_t *pdu, uint8_t *data, uint_t datalen);

void
idm_pdu_complete(idm_pdu_t *pdu, idm_status_t status);

void
idm_pdu_tx(idm_pdu_t *pdu);

/*
 * Object reference tracking
 */

void
idm_refcnt_init(idm_refcnt_t *refcnt, void *referenced_obj);

void
idm_refcnt_destroy(idm_refcnt_t *refcnt);

void
idm_refcnt_reset(idm_refcnt_t *refcnt);

void
idm_refcnt_hold(idm_refcnt_t *refcnt);

void
idm_refcnt_rele(idm_refcnt_t *refcnt);

void
idm_refcnt_rele_and_destroy(idm_refcnt_t *refcnt, idm_refcnt_cb_t *cb_func);

void
idm_refcnt_wait_ref(idm_refcnt_t *refcnt);

void
idm_refcnt_async_wait_ref(idm_refcnt_t *refcnt, idm_refcnt_cb_t *cb_func);


#ifdef	__cplusplus
}
#endif

#endif /* _IDM_H */
