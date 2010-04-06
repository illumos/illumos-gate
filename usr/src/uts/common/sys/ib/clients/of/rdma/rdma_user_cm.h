/*
 * This file contains definitions used in OFED defined user/kernel
 * interfaces. These are imported from the OFED header rdma_user_cm.h. Oracle
 * elects to have and use the contents of rdma_user_cm.h under and governed
 * by the OpenIB.org BSD license (see below for for full license text).
 * However, * the following notice accompanied the original version of this
 * file:
 */

/*
 * Copyright (c) 2005-2006 Intel Corporation.  All rights reserved.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * OpenIB.org BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

#ifndef _SYS_IB_CLIENTS_OF_RDMA_RDMA_USER_CM_H
#define	_SYS_IB_CLIENTS_OF_RDMA_RDMA_USER_CM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ib/clients/of/rdma/ib_user_verbs.h>
#include <sys/ib/clients/of/rdma/ib_user_sa.h>

#define	RDMA_USER_CM_ABI_VERSION	4

#define	RDMA_MAX_PRIVATE_DATA		256

#pragma pack(1)
enum {
	RDMA_USER_CM_CMD_CREATE_ID,
	RDMA_USER_CM_CMD_DESTROY_ID,
	RDMA_USER_CM_CMD_BIND_ADDR,
	RDMA_USER_CM_CMD_RESOLVE_ADDR,
	RDMA_USER_CM_CMD_RESOLVE_ROUTE,
	RDMA_USER_CM_CMD_QUERY_ROUTE,
	RDMA_USER_CM_CMD_CONNECT,
	RDMA_USER_CM_CMD_LISTEN,
	RDMA_USER_CM_CMD_ACCEPT,
	RDMA_USER_CM_CMD_REJECT,
	RDMA_USER_CM_CMD_DISCONNECT,
	RDMA_USER_CM_CMD_INIT_QP_ATTR,
	RDMA_USER_CM_CMD_GET_EVENT,
	RDMA_USER_CM_CMD_GET_OPTION,
	RDMA_USER_CM_CMD_SET_OPTION,
	RDMA_USER_CM_CMD_NOTIFY,
	RDMA_USER_CM_CMD_JOIN_MCAST,
	RDMA_USER_CM_CMD_LEAVE_MCAST
};

/*
 * command ABI structures.
 */
struct rdma_ucm_cmd_hdr {
	uint32_t cmd;
	uint16_t in;
	uint16_t out;
};

struct rdma_ucm_create_id {
	uint64_t uid;
	ofv_resp_addr_t response;
	uint16_t ps;
	uint8_t  reserved[6];
};

struct rdma_ucm_create_id_resp {
	uint32_t id;
};

struct rdma_ucm_destroy_id {
	ofv_resp_addr_t response;
	uint32_t id;
	uint32_t reserved;
};

struct rdma_ucm_destroy_id_resp {
	uint32_t events_reported;
};

struct rdma_ucm_bind_addr {
	uint64_t response;
	struct sockaddr_in6 addr;
	uint32_t id;
	uint32_t reserved;
};

struct rdma_ucm_resolve_addr {
	struct sockaddr_in6 src_addr;
	struct sockaddr_in6 dst_addr;
	uint32_t id;
	uint32_t timeout_ms;
};

struct rdma_ucm_resolve_route {
	uint32_t id;
	uint32_t timeout_ms;
};

struct rdma_ucm_query_route {
	ofv_resp_addr_t response;
	uint32_t id;
	uint32_t reserved;
};

struct rdma_ucm_query_route_resp {
	uint64_t node_guid;
	struct ib_user_path_rec ib_route[2];
	struct sockaddr_in6 src_addr;
	struct sockaddr_in6 dst_addr;
	uint32_t num_paths;
	uint8_t port_num;
	uint8_t reserved[3];
};

struct rdma_ucm_conn_param {
	uint32_t qp_num;
	uint32_t reserved;
	uint8_t  private_data[RDMA_MAX_PRIVATE_DATA];
	uint8_t  private_data_len;
	uint8_t  srq;
	uint8_t  responder_resources;
	uint8_t  initiator_depth;
	uint8_t  flow_control;
	uint8_t  retry_count;
	uint8_t  rnr_retry_count;
	uint8_t  valid;
};

struct rdma_ucm_ud_param {
	uint32_t qp_num;
	uint32_t qkey;
	struct ib_uverbs_ah_attr ah_attr;
	uint8_t  private_data[RDMA_MAX_PRIVATE_DATA];
	uint8_t  private_data_len;
	uint8_t  reserved[7];
	uint8_t  reserved2[4];
};

struct rdma_ucm_connect {
	struct rdma_ucm_conn_param conn_param;
	uint32_t id;
	uint32_t reserved;
};

struct rdma_ucm_listen {
	uint32_t id;
	uint32_t backlog;
};

struct rdma_ucm_accept {
	uint64_t uid;
	struct rdma_ucm_conn_param conn_param;
	uint32_t id;
	uint32_t reserved;
};

struct rdma_ucm_reject {
	uint32_t id;
	uint8_t  private_data_len;
	uint8_t  reserved[3];
	uint8_t  private_data[RDMA_MAX_PRIVATE_DATA];
};

struct rdma_ucm_disconnect {
	uint32_t id;
};

struct rdma_ucm_init_qp_attr {
	ofv_resp_addr_t response;
	uint32_t id;
	uint32_t qp_state;
};

struct rdma_ucm_notify {
	uint32_t id;
	uint32_t event;
};

struct rdma_ucm_join_mcast {
	ofv_resp_addr_t response;
	uint64_t uid;
	struct sockaddr_in6 addr;
	uint32_t id;
	uint32_t reserved;
};

struct rdma_ucm_get_event {
	ofv_resp_addr_t response;
};

struct rdma_ucm_event_resp {
	uint64_t uid;
	uint32_t id;
	uint32_t event;
	uint32_t status;
	union {
		struct rdma_ucm_conn_param conn;
		struct rdma_ucm_ud_param   ud;
	} param;
};

/* Option levels */
enum {
	RDMA_OPTION_ID		= 0
};

/* Option details */
enum {
	RDMA_OPTION_ID_TOS	= 0
};

struct rdma_ucm_set_option {
	uint64_t optval;
	uint32_t id;
	uint32_t level;
	uint32_t optname;
	uint32_t optlen;
};
#pragma	pack()

#ifdef __cplusplus
}
#endif
#endif /* _SYS_IB_CLIENTS_OF_RDMA_RDMA_USER_CM_H */
