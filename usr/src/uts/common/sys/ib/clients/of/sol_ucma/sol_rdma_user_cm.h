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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_IB_CLIENTS_OF_SOL_UCMA_SOL_RDMA_USER_CM_H
#define	_SYS_IB_CLIENTS_OF_SOL_UCMA_SOL_RDMA_USER_CM_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/ib/clients/of/ofa_solaris.h>
#include <sys/ib/clients/of/rdma/rdma_user_cm.h>

/*
 * Typedefs for data structures defined in rdma_user_cm.h
 */
typedef struct rdma_ucm_cmd_hdr		sol_ucma_cmd_hdr_t;
typedef struct rdma_ucm_create_id	sol_ucma_create_id_t;
typedef struct rdma_ucm_create_id_resp	sol_ucma_create_id_resp_t;
typedef struct rdma_ucm_destroy_id	sol_ucma_destroy_id_t;
typedef struct rdma_ucm_destroy_id_resp	sol_ucma_destroy_id_resp_t;
typedef struct rdma_ucm_bind_addr	sol_ucma_bind_addr_t;
typedef struct rdma_ucm_resolve_addr	sol_ucma_resolve_addr_t;
typedef struct rdma_ucm_resolve_route	sol_ucma_resolve_route_t;
typedef struct rdma_ucm_query_route	sol_ucma_query_route_t;
typedef struct rdma_ucm_query_route_resp
    sol_ucma_query_route_resp_t;
typedef struct rdma_ucm_connect		sol_ucma_connect_t;
typedef struct rdma_ucm_listen		sol_ucma_listen_t;
typedef struct rdma_ucm_accept		sol_ucma_accept_t;
typedef struct rdma_ucm_reject 		sol_ucma_reject_t;
typedef struct rdma_ucm_disconnect	sol_ucma_disconnect_t;
typedef struct rdma_ucm_init_qp_attr	sol_ucma_init_qp_attr_t;
typedef struct rdma_ucm_notify		sol_ucma_notify_t;
typedef struct rdma_ucm_join_mcast	sol_ucma_join_mcast_t;
typedef struct rdma_ucm_get_event	sol_ucma_get_event_t;
typedef struct rdma_ucm_event_resp	sol_ucma_event_resp_t;
typedef struct rdma_ucm_ud_param	sol_ucma_ud_param_t;
typedef struct rdma_ucm_set_option	sol_ucma_set_option_t;

#pragma pack(1)
typedef struct {
	uint64_t		response;
	struct sockaddr_in6	addr;
	uint32_t		id;
} sol_ucma_bind_addr32_t;

typedef struct {
	uint64_t		response;
	struct sockaddr_in6	addr;
	uint32_t		id;
	uint32_t		reserved;
} sol_ucma_bind_addr64_t;

typedef struct {
	uint64_t		response;
	uint64_t		uid;
	struct sockaddr_in6	addr;
	uint32_t		id;
} sol_ucma_join_mcast32_t;

typedef struct {
	uint64_t		response;
	uint64_t		uid;
	struct sockaddr_in6	addr;
	uint32_t		id;
	uint32_t		reserved;
} sol_ucma_join_mcast64_t;
#pragma pack()

#ifdef __cplusplus
}
#endif

#endif /* _SYS_IB_CLIENTS_OF_SOL_UCMA_SOL_RDMA_USER_CM_H */
