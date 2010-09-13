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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_IDM_TRANSPORT_H_
#define	_IDM_TRANSPORT_H_

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/nvpair.h>
#include <sys/sunldi.h>

#define	IDM_TRANSPORT_PATHLEN	0x40

/* Note, this is tied to iSER currently */
#define	IDM_TRANSPORT_HEADER_LENGTH	0x20

/*
 * idm_transport_type_t
 * An enumerated list of the transports available to iSER.
 * Note that new transports should be added to the enum prior to NUM_TYPES.
 */
typedef enum {
	IDM_TRANSPORT_TYPE_ISER	= 0,
	IDM_TRANSPORT_TYPE_SOCKETS,
	IDM_TRANSPORT_NUM_TYPES,
	IDM_TRANSPORT_TYPE_UNDEFINED
} idm_transport_type_t;

/*
 * idm_transport_caps_t
 * Encodes a set of attributes describing an IDM transport's capabilities.
 *	JB - do we need this?
 */
typedef struct idm_transport_caps_s {
	uint32_t	flags;
} idm_transport_caps_t;

/*
 * Transport routine definitions for idm_transport_ops_t below
 */

/* Send_Control - transmit a Control-type PDU */
typedef void (transport_tx_op_t)(struct idm_conn_s *ic, struct idm_pdu_s *pdu);

/*
 * Target transport data primitives, caller (IDM) holds idt->idt_mutex,
 * and the transport should release the mutex before returning.
 */
typedef idm_status_t (transport_buf_tx_to_ini_op_t)(struct idm_task_s *idt,
    struct idm_buf_s *idb);
typedef idm_status_t (transport_buf_rx_from_ini_op_t)(struct idm_task_s *idt,
    struct idm_buf_s *idb);

/* Initiator transport data handlers */
typedef void (transport_rx_datain_op_t)(struct idm_conn_s *ic,
    struct idm_pdu_s *pdu);
typedef void (transport_rx_rtt_op_t)(struct idm_conn_s *ic,
    struct idm_pdu_s *pdu);

/* Target transport Data-out handler */
typedef void (transport_rx_dataout_op_t)(struct idm_conn_s *ic,
    struct idm_pdu_s *pdu);

/* Transport-specific resource allocation and free */
typedef idm_status_t (transport_alloc_conn_rsrc_op_t)(struct idm_conn_s *ic);
typedef idm_status_t (transport_free_conn_rsrc_op_t)(struct idm_conn_s *ic);

/* Transport driver operations enable/disable */
typedef idm_status_t (transport_tgt_enable_datamover_op_t)(struct
    idm_conn_s *ic);
typedef idm_status_t (transport_ini_enable_datamover_op_t)(struct
    idm_conn_s *ic);
typedef idm_status_t (transport_conn_terminate_op_t)(struct idm_conn_s *ic);

/* Task resource cleanup */
typedef idm_status_t (transport_free_task_rsrcs_op_t)(struct idm_task_s *it);

/* Negotiate key value pairs */
typedef kv_status_t (transport_negotiate_key_values_op_t)(struct
    idm_conn_s *ic, nvlist_t *request_nvl, nvlist_t *response_nvl,
    nvlist_t *negotiated_nvl);

/* Activate the negotiated key value pairs */
typedef void (transport_notice_key_values_op_t)(struct idm_conn_s *ic,
    nvlist_t *negotiated_nvl);

/* Declare the declarative key value pairs */
typedef kv_status_t (transport_declare_key_values_op_t)(struct idm_conn_s *ic,
    nvlist_t *config_nvl, nvlist_t *outgoing_nvl);

/* Transport capability probe */
typedef boolean_t (transport_conn_is_capable_op_t)(idm_conn_req_t *ic,
    struct idm_transport_caps_s *caps);

/* Transport buffer services */
typedef idm_status_t (transport_buf_alloc_op_t)(struct idm_buf_s *idb,
    uint64_t buflen);
typedef idm_status_t (transport_buf_setup_op_t)(struct idm_buf_s *idb);
typedef void (transport_buf_teardown_op_t)(struct idm_buf_s *idb);
typedef void (transport_buf_free_op_t)(struct idm_buf_s *idb);

/* Transport target context and service management services */
typedef idm_status_t (transport_tgt_svc_create_op_t)(idm_svc_req_t *sr,
    struct idm_svc_s *is);
typedef void (transport_tgt_svc_destroy_op_t)(struct idm_svc_s *is);
typedef idm_status_t (transport_tgt_svc_online_op_t)(struct idm_svc_s *is);
typedef void (transport_tgt_svc_offline_op_t)(struct idm_svc_s *is);

/* Transport target connection establishment */
typedef void (transport_tgt_conn_destroy_op_t)(struct idm_conn_s *ic);
typedef idm_status_t (transport_tgt_conn_connect_op_t)(struct idm_conn_s *ic);
typedef void (transport_tgt_conn_disconnect_op_t)(struct idm_conn_s *ic);

/* Transport initiator context and connection management services */
typedef idm_status_t (transport_ini_conn_create_op_t)(idm_conn_req_t *cr,
    struct idm_conn_s *ic);
typedef void (transport_ini_conn_destroy_op_t)(struct idm_conn_s *ic);
typedef idm_status_t (transport_ini_conn_connect_op_t)(struct idm_conn_s *ic);
typedef void (transport_ini_conn_disconnect_op_t)(struct idm_conn_s *ic);


/*
 * idm_transport_ops_t
 * Encodes a set of vectors into an IDM transport driver that implement the
 * transport-specific Datamover operations for IDM usage. These routines are
 * invoked by the IDM layer to execute the transport-specific implementations
 * of the DataMover primitives and supporting routines.
 */
typedef struct idm_transport_ops_s {
	transport_tx_op_t			*it_tx_pdu;
	transport_buf_tx_to_ini_op_t		*it_buf_tx_to_ini;
	transport_buf_rx_from_ini_op_t		*it_buf_rx_from_ini;
	transport_rx_datain_op_t		*it_rx_datain;
	transport_rx_rtt_op_t			*it_rx_rtt;
	transport_rx_dataout_op_t		*it_rx_dataout;
	transport_alloc_conn_rsrc_op_t		*it_alloc_conn_rsrc;
	transport_free_conn_rsrc_op_t		*it_free_conn_rsrc;
	transport_tgt_enable_datamover_op_t	*it_tgt_enable_datamover;
	transport_ini_enable_datamover_op_t	*it_ini_enable_datamover;
	transport_conn_terminate_op_t		*it_conn_terminate;
	transport_free_task_rsrcs_op_t		*it_free_task_rsrc;
	transport_negotiate_key_values_op_t	*it_negotiate_key_values;
	transport_notice_key_values_op_t	*it_notice_key_values;
	transport_conn_is_capable_op_t		*it_conn_is_capable;
	transport_buf_alloc_op_t		*it_buf_alloc;
	transport_buf_free_op_t			*it_buf_free;
	transport_buf_setup_op_t		*it_buf_setup;
	transport_buf_teardown_op_t		*it_buf_teardown;
	transport_tgt_svc_create_op_t		*it_tgt_svc_create;
	transport_tgt_svc_destroy_op_t		*it_tgt_svc_destroy;
	transport_tgt_svc_online_op_t		*it_tgt_svc_online;
	transport_tgt_svc_offline_op_t		*it_tgt_svc_offline;
	transport_tgt_conn_destroy_op_t		*it_tgt_conn_destroy;
	transport_tgt_conn_connect_op_t		*it_tgt_conn_connect;
	transport_tgt_conn_disconnect_op_t	*it_tgt_conn_disconnect;
	transport_ini_conn_create_op_t		*it_ini_conn_create;
	transport_ini_conn_destroy_op_t		*it_ini_conn_destroy;
	transport_ini_conn_connect_op_t		*it_ini_conn_connect;
	transport_ini_conn_disconnect_op_t	*it_ini_conn_disconnect;
	transport_declare_key_values_op_t	*it_declare_key_values;
} idm_transport_ops_t;

/*
 * idm_transport_t encodes all of the data related to an IDM transport
 * type. In addition to type and capabilities, it also stores a pointer
 * to the connection and transport operation implementations, and also
 * it stores the LDI handle.
 */
typedef struct idm_transport_s {
	idm_transport_type_t	it_type;
	char			*it_device_path;
	ldi_handle_t		it_ldi_hdl;
	idm_transport_ops_t	*it_ops;
	idm_transport_caps_t	*it_caps;
} idm_transport_t;

/*
 * idm_transport_attr_t encodes details of a transport driver seeking
 * registration with the IDM kernel module.
 */
typedef struct idm_transport_attr_s {
	idm_transport_type_t	type;
	idm_transport_ops_t	*it_ops;
	idm_transport_caps_t	*it_caps;
} idm_transport_attr_t;

/* IDM transport API */
idm_status_t
idm_transport_register(idm_transport_attr_t *attr);

idm_transport_t *
idm_transport_lookup(idm_conn_req_t *cr);

void
idm_transport_setup(ldi_ident_t li, boolean_t boot_conn);

void
idm_transport_teardown();

#ifdef	__cplusplus
}
#endif

#endif /* _IDM_TRANSPORT_H_ */
