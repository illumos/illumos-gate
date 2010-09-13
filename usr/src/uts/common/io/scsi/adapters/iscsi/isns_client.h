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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_ISNS_CLIENT_H
#define	_ISNS_CLIENT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/scsi/adapters/iscsi_if.h>

#define	ISNS_DEFAULT_ESI_SCN_PORT	32046
#define	ISNS_DEFAULT_PORTAL_GROUP_TAG	1

typedef enum isns_status {
	isns_ok,
	isns_no_svr_found,
	isns_internal_err,
	isns_create_msg_err,
	isns_open_conn_err,
	isns_send_msg_err,
	isns_rcv_msg_err,
	isns_no_rsp_rcvd,
	isns_op_failed,
	isns_op_partially_failed,
	isns_no_transport_found
} isns_status_t;

#define	ISNSP_MULT_PAYLOAD_HEADER_SIZE		8
/*
 * when we concatenate payloads from multiple pdus, we need
 * a larger payload_len then what is defined in isns_protocol.h
 *
 * for each payload that comes in, we need to save off the payload_len
 * and the payload
 */
typedef struct isns_pdu_mult_payload {
	size_t payload_len;
	uint8_t payload[1];
} isns_pdu_mult_payload_t;

typedef struct isns_scn_callback_arg {
	uint32_t scn_type;
	uint8_t source_key_attr[ISCSI_MAX_NAME_LEN];
} isns_scn_callback_arg_t;

/*
 * To initialize the iSNS Client module.
 */
void
isns_client_init(void);

/*
 * To clean up the resources associated with the iSNS Client module.
 */
void
isns_client_cleanup(void);

/*
 * To register a network entity against the iSNS server(s) visible to the
 * specified LHBA.
 */
isns_status_t
isns_reg(uint8_t *lhba_handle,
	uint8_t *node_name,
	size_t node_name_len,
	uint8_t *node_alias,
	size_t node_alias_len,
	uint32_t node_type,
	void (*scn_callback)(void *));

/*
 * To register a network entity against the specified iSNS server.
 */
isns_status_t
isns_reg_one_server(entry_t *isns_server,
	uint8_t *lhba_handle,
	uint8_t *node_name,
	size_t node_name_len,
	uint8_t *node_alias,
	size_t node_alias_len,
	uint32_t node_type,
	void (*scn_callback)(void *));

/*
 * To deregister a network entity from the all iSNS server(s) visible to the
 * specified LHBA.
 */
isns_status_t
isns_dereg(uint8_t *lhba_handle, uint8_t *node_name);

/*
 * To deregister a network entity from the specified iSNS server.
 */
isns_status_t
isns_dereg_one_server(entry_t *isns_server, uint8_t *node_name,
	boolean_t is_last_isns_server);

/*
 * To query all portal group objects that are visible to the specified LHBA
 * registered through all iSNS servers this LHBA discovered.
 * pg_list is NULL if no portal group object is found.
 */
isns_status_t
isns_query(uint8_t *lhba_handle,
	uint8_t *node_name,
	uint8_t *node_alias,
	uint32_t node_type,
	isns_portal_group_list_t **pg_list);

/*
 * To query all portal group objects registered through the specified iSNS
 * server registered through the specified iSNS server. pg_list is NULL if
 * no portal group object is found.
 */
isns_status_t
isns_query_one_server(iscsi_addr_t *isns_server_addr,
	uint8_t *lhba_handle,
	uint8_t *node_name,
	uint8_t *node_alias,
	uint32_t node_type,
	isns_portal_group_list_t **pg_list);

/*
 * To query the portal group objects associated with the specified storage
 * node through all iSNS servers this LHBA discovered. pg_list is NULL if
 * no portal group object is found.
 */
isns_status_t
isns_query_one_node(uint8_t *target_node_name,
	uint8_t *lhba_handle,
	uint8_t *source_node_name,
	uint8_t *source_node_alias,
	uint32_t source_node_type,
	isns_portal_group_list_t **pg_list);

/*
 * To query the portal group objects associated with the specified storage
 * node registered through the specified iSNS server. pg_list is NULL if
 * no portal group object is found.
 */
isns_status_t
isns_query_one_server_one_node(iscsi_addr_t *isns_server_addr,
	uint8_t *target_node_name,
	uint8_t *lhba_handle,
	uint8_t *source_node_name,
	uint8_t *source_node_alias,
	uint32_t source_node_type,
	isns_portal_group_list_t **pg_list);

#ifdef __cplusplus
}
#endif

#endif /* _ISNS_CLIENT_H */
