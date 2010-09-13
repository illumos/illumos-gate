/*
 * This file contains definitions used in OFED defined user/kernel
 * interfaces. These are imported from the OFED header ib_user_verbs.h. Oracle
 * elects to have and use the contents of ib_user_verbs.h under and governed
 * by the OpenIB.org BSD license (see below for full license text). However,
 * the following notice accompanied the original version of this file:
 */

/*
 * Copyright (c) 2005 Topspin Communications.  All rights reserved.
 * Copyright (c) 2005, 2006 Cisco Systems.  All rights reserved.
 * Copyright (c) 2005 PathScale, Inc.  All rights reserved.
 * Copyright (c) 2006 Mellanox Technologies.  All rights reserved.
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
 *
 */

#ifndef _SYS_IB_CLIENTS_OF_RDMA_IB_USER_VERBS_H
#define	_SYS_IB_CLIENTS_OF_RDMA_IB_USER_VERBS_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Increment this value if any changes that break userspace ABI
 * compatibility are made.
 */
#define	IB_USER_VERBS_ABI_VERSION	6

enum {
	IB_USER_VERBS_CMD_GET_CONTEXT,
	IB_USER_VERBS_CMD_QUERY_DEVICE,
	IB_USER_VERBS_CMD_QUERY_PORT,
	IB_USER_VERBS_CMD_ALLOC_PD,
	IB_USER_VERBS_CMD_DEALLOC_PD,
	IB_USER_VERBS_CMD_CREATE_AH,
	IB_USER_VERBS_CMD_MODIFY_AH,
	IB_USER_VERBS_CMD_QUERY_AH,
	IB_USER_VERBS_CMD_DESTROY_AH,
	IB_USER_VERBS_CMD_REG_MR,
	IB_USER_VERBS_CMD_REG_SMR,
	IB_USER_VERBS_CMD_REREG_MR,
	IB_USER_VERBS_CMD_QUERY_MR,
	IB_USER_VERBS_CMD_DEREG_MR,
	IB_USER_VERBS_CMD_ALLOC_MW,
	IB_USER_VERBS_CMD_BIND_MW,
	IB_USER_VERBS_CMD_DEALLOC_MW,
	IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL,
	IB_USER_VERBS_CMD_CREATE_CQ,
	IB_USER_VERBS_CMD_RESIZE_CQ,
	IB_USER_VERBS_CMD_DESTROY_CQ,
	IB_USER_VERBS_CMD_POLL_CQ,
	IB_USER_VERBS_CMD_PEEK_CQ,
	IB_USER_VERBS_CMD_REQ_NOTIFY_CQ,
	IB_USER_VERBS_CMD_CREATE_QP,
	IB_USER_VERBS_CMD_QUERY_QP,
	IB_USER_VERBS_CMD_MODIFY_QP,
	IB_USER_VERBS_CMD_DESTROY_QP,
	IB_USER_VERBS_CMD_POST_SEND,
	IB_USER_VERBS_CMD_POST_RECV,
	IB_USER_VERBS_CMD_ATTACH_MCAST,
	IB_USER_VERBS_CMD_DETACH_MCAST,
	IB_USER_VERBS_CMD_CREATE_SRQ,
	IB_USER_VERBS_CMD_MODIFY_SRQ,
	IB_USER_VERBS_CMD_QUERY_SRQ,
	IB_USER_VERBS_CMD_DESTROY_SRQ,
	IB_USER_VERBS_CMD_POST_SRQ_RECV,
	IB_USER_VERBS_CMD_CREATE_XRC_SRQ,
	IB_USER_VERBS_CMD_OPEN_XRC_DOMAIN,
	IB_USER_VERBS_CMD_CLOSE_XRC_DOMAIN,
	IB_USER_VERBS_CMD_CREATE_XRC_RCV_QP,
	IB_USER_VERBS_CMD_MODIFY_XRC_RCV_QP,
	IB_USER_VERBS_CMD_QUERY_XRC_RCV_QP,
	IB_USER_VERBS_CMD_REG_XRC_RCV_QP,
	IB_USER_VERBS_CMD_UNREG_XRC_RCV_QP,
	IB_USER_VERBS_CMD_QUERY_GID,
	IB_USER_VERBS_CMD_QUERY_PKEY
};

/*
 * Make sure that all structs defined in this file remain laid out so
 * that they pack the same way on 32-bit and 64-bit architectures (to
 * avoid incompatibility between 32-bit userspace and 64-bit kernels).
 * Specifically:
 *  - Do not use pointer types -- pass pointers in uint64_t instead.
 *  - Make sure that any structure larger than 4 bytes is padded to a
 *    multiple of 8 bytes.  Otherwise the structure size will be
 *    different between 32-bit and 64-bit architectures.
 */

struct ib_uverbs_async_event_desc {
	uint64_t element;
	uint32_t event_type;	/* enum ib_event_type */
	uint32_t reserved;
};

struct ib_uverbs_comp_event_desc {
	uint64_t cq_handle;
};

/*
 * All commands from userspace should start with a uint32_t command field
 * followed by uint16_t in_words and out_words fields (which give the
 * length of the command block and response buffer if any in 32-bit
 * words).  The kernel driver will read these fields first and read
 * the rest of the command struct based on these value.
 */

struct ib_uverbs_cmd_hdr {
	uint32_t command;
	uint16_t in_words;
	uint16_t out_words;
};

struct ib_uverbs_get_context {
	ofv_resp_addr_t response;
	uint64_t driver_data[];
};

struct ib_uverbs_get_context_resp {
	uint32_t async_fd;
	uint32_t num_comp_vectors;
};

struct ib_uverbs_query_device {
	ofv_resp_addr_t response;
	uint64_t driver_data[];
};

struct ib_uverbs_query_device_resp {
	uint64_t fw_ver;
	uint64_t node_guid;
	uint64_t sys_image_guid;
	uint64_t max_mr_size;
	uint64_t page_size_cap;
	uint32_t vendor_id;
	uint32_t vendor_part_id;
	uint32_t hw_ver;
	uint32_t max_qp;
	uint32_t max_qp_wr;
	uint32_t device_cap_flags;
	uint32_t max_sge;
	uint32_t max_sge_rd;
	uint32_t max_cq;
	uint32_t max_cqe;
	uint32_t max_mr;
	uint32_t max_pd;
	uint32_t max_qp_rd_atom;
	uint32_t max_ee_rd_atom;
	uint32_t max_res_rd_atom;
	uint32_t max_qp_init_rd_atom;
	uint32_t max_ee_init_rd_atom;
	uint32_t atomic_cap;
	uint32_t max_ee;
	uint32_t max_rdd;
	uint32_t max_mw;
	uint32_t max_raw_ipv6_qp;
	uint32_t max_raw_ethy_qp;
	uint32_t max_mcast_grp;
	uint32_t max_mcast_qp_attach;
	uint32_t max_total_mcast_qp_attach;
	uint32_t max_ah;
	uint32_t max_fmr;
	uint32_t max_map_per_fmr;
	uint32_t max_srq;
	uint32_t max_srq_wr;
	uint32_t max_srq_sge;
	uint16_t max_pkeys;
	uint8_t  local_ca_ack_delay;
	uint8_t  phys_port_cnt;
	uint8_t  reserved[4];
};

struct ib_uverbs_query_port {
	ofv_resp_addr_t response;
	uint8_t  port_num;
	uint8_t  reserved[7];
	uint64_t driver_data[];
};

struct ib_uverbs_query_port_resp {
	uint32_t port_cap_flags;
	uint32_t max_msg_sz;
	uint32_t bad_pkey_cntr;
	uint32_t qkey_viol_cntr;
	uint32_t gid_tbl_len;
	uint16_t pkey_tbl_len;
	uint16_t lid;
	uint16_t sm_lid;
	uint8_t  state;
	uint8_t  max_mtu;
	uint8_t  active_mtu;
	uint8_t  lmc;
	uint8_t  max_vl_num;
	uint8_t  sm_sl;
	uint8_t  subnet_timeout;
	uint8_t  init_type_reply;
	uint8_t  active_width;
	uint8_t  active_speed;
	uint8_t  phys_state;
	uint8_t  reserved[3];
};

struct ib_uverbs_query_gid {
	ofv_resp_addr_t response;
	uint32_t  gid_index;
	uint8_t   port_num;
	uint8_t   reserved[3];
	uint64_t  driver_data;
};

struct ib_uverbs_query_gid_resp {
	uint8_t   gid[16];
};

struct ib_uverbs_query_pkey {
	ofv_resp_addr_t response;
	uint32_t  pkey_index;
	uint8_t   port_num;
	uint8_t   reserved[3];
	uint64_t  driver_data;
};

struct ib_uverbs_query_pkey_resp {
	uint16_t  pkey;
	uint16_t  reserved;
};

struct ib_uverbs_alloc_pd {
	ofv_resp_addr_t response;
	uint64_t driver_data[];
};

/*
 * PD responses may pass opaque data to userspace drivers, we choose a value
 * larger than what any HCA requires.
 */
#define	SOL_UVERBS_PD_DATA_OUT_SIZE	24
typedef uint64_t uverbs_pd_drv_out_data_t[SOL_UVERBS_PD_DATA_OUT_SIZE];

struct ib_uverbs_alloc_pd_resp {
	uint32_t  pd_handle;
	uint32_t  reserved;
	uverbs_pd_drv_out_data_t drv_out;
};

struct ib_uverbs_dealloc_pd {
	uint32_t pd_handle;
};

struct ib_uverbs_reg_mr {
	ofv_resp_addr_t response;
	uint64_t start;
	uint64_t length;
	uint64_t hca_va;
	uint32_t pd_handle;
	uint32_t access_flags;
	uint64_t driver_data[];
};

struct ib_uverbs_reg_mr_resp {
	uint32_t mr_handle;
	uint32_t lkey;
	uint32_t rkey;
};

struct ib_uverbs_dereg_mr {
	uint32_t mr_handle;
};

struct ib_uverbs_create_comp_channel {
	ofv_resp_addr_t response;
};

struct ib_uverbs_create_comp_channel_resp {
	uint32_t fd;
};

struct ib_uverbs_create_cq {
	ofv_resp_addr_t response;
	uint64_t user_handle;
	uint32_t cqe;
	uint32_t comp_vector;
	int32_t  comp_channel;
	uint32_t reserved;
	uint64_t driver_data[];
};

/*
 * CQ responses pass opaque data to userspace drivers, we choose a value
 * larger than what any HCA requires.
 */
#define	SOL_UVERBS_CQ_DATA_OUT_SIZE	24
typedef uint64_t uverbs_cq_drv_out_data_t[SOL_UVERBS_CQ_DATA_OUT_SIZE];

struct ib_uverbs_create_cq_resp {
	uint32_t  cq_handle;
	uint32_t  cqe;
	uverbs_cq_drv_out_data_t  drv_out;
};

struct ib_uverbs_resize_cq {
	ofv_resp_addr_t response;
	uint32_t cq_handle;
	uint32_t cqe;
	uint64_t driver_data[];
};

struct ib_uverbs_resize_cq_resp {
	uint32_t cqe;
	uint32_t reserved;
	uverbs_cq_drv_out_data_t  drv_out;
};

struct ib_uverbs_poll_cq {
	ofv_resp_addr_t response;
	uint32_t cq_handle;
	uint32_t ne;
};

struct ib_uverbs_wc {
	uint64_t wr_id;
	uint32_t status;
	uint32_t opcode;
	uint32_t vendor_err;
	uint32_t byte_len;
	uint32_t imm_data;
	uint32_t qp_num;
	uint32_t src_qp;
	uint32_t wc_flags;
	uint16_t pkey_index;
	uint16_t slid;
	uint8_t  sl;
	uint8_t  dlid_path_bits;
	uint8_t  port_num;
	uint8_t  reserved;
};

struct ib_uverbs_poll_cq_resp {
	uint32_t count;
	uint32_t reserved;
	struct ib_uverbs_wc wc[];
};

struct ib_uverbs_req_notify_cq {
	uint32_t cq_handle;
	uint32_t solicited_only;
};

struct ib_uverbs_destroy_cq {
	ofv_resp_addr_t response;
	uint32_t cq_handle;
	uint32_t reserved;
};

struct ib_uverbs_destroy_cq_resp {
	uint32_t comp_events_reported;
	uint32_t async_events_reported;
};

struct ib_uverbs_global_route {
	uint8_t  dgid[16];
	uint32_t flow_label;
	uint8_t  sgid_index;
	uint8_t  hop_limit;
	uint8_t  traffic_class;
	uint8_t  reserved;
};

struct ib_uverbs_ah_attr {
	struct ib_uverbs_global_route grh;
	uint16_t dlid;
	uint8_t  sl;
	uint8_t  src_path_bits;
	uint8_t  static_rate;
	uint8_t  is_global;
	uint8_t  port_num;
	uint8_t  reserved;
};

struct ib_uverbs_qp_attr {
	uint32_t	qp_attr_mask;
	uint32_t	qp_state;
	uint32_t	cur_qp_state;
	uint32_t	path_mtu;
	uint32_t	path_mig_state;
	uint32_t	qkey;
	uint32_t	rq_psn;
	uint32_t	sq_psn;
	uint32_t	dest_qp_num;
	uint32_t	qp_access_flags;

	struct ib_uverbs_ah_attr ah_attr;
	struct ib_uverbs_ah_attr alt_ah_attr;

	/* ib_qp_cap */
	uint32_t	max_send_wr;
	uint32_t	max_recv_wr;
	uint32_t	max_send_sge;
	uint32_t	max_recv_sge;
	uint32_t	max_inline_data;

	uint16_t	pkey_index;
	uint16_t	alt_pkey_index;
	uint8_t		en_sqd_async_notify;
	uint8_t		sq_draining;
	uint8_t		max_rd_atomic;
	uint8_t		max_dest_rd_atomic;
	uint8_t		min_rnr_timer;
	uint8_t		port_num;
	uint8_t		timeout;
	uint8_t		retry_cnt;
	uint8_t		rnr_retry;
	uint8_t		alt_port_num;
	uint8_t		alt_timeout;
	uint8_t		reserved[5];
};

struct ib_uverbs_create_qp {
	ofv_resp_addr_t response;
	uint64_t user_handle;
	uint32_t pd_handle;
	uint32_t send_cq_handle;
	uint32_t recv_cq_handle;
	uint32_t srq_handle;
	uint32_t max_send_wr;
	uint32_t max_recv_wr;
	uint32_t max_send_sge;
	uint32_t max_recv_sge;
	uint32_t max_inline_data;
	uint8_t  sq_sig_all;
	uint8_t  qp_type;
	uint8_t  is_srq;
	uint8_t  reserved;
	uint64_t driver_data[];
};

/*
 * QP responses pass opaque data to userspace drivers, we choose a value
 * larger than what any HCA requires.
 */
#define	SOL_UVERBS_QP_DATA_OUT_SIZE	24
typedef uint64_t uverbs_qp_drv_out_data_t[SOL_UVERBS_QP_DATA_OUT_SIZE];

struct ib_uverbs_create_qp_resp {
	uint32_t qp_handle;
	uint32_t qpn;
	uint32_t max_send_wr;
	uint32_t max_recv_wr;
	uint32_t max_send_sge;
	uint32_t max_recv_sge;
	uint32_t max_inline_data;
	uint32_t reserved;
	uverbs_qp_drv_out_data_t drv_out;
};

/*
 * This struct needs to remain a multiple of 8 bytes to keep the
 * alignment of the modify QP parameters.
 */
struct ib_uverbs_qp_dest {
	uint8_t  dgid[16];
	uint32_t flow_label;
	uint16_t dlid;
	uint16_t reserved;
	uint8_t  sgid_index;
	uint8_t  hop_limit;
	uint8_t  traffic_class;
	uint8_t  sl;
	uint8_t  src_path_bits;
	uint8_t  static_rate;
	uint8_t  is_global;
	uint8_t  port_num;
};

struct ib_uverbs_query_qp {
	ofv_resp_addr_t response;
	uint32_t qp_handle;
	uint32_t attr_mask;
	uint64_t driver_data[];
};

struct ib_uverbs_query_qp_resp {
	struct ib_uverbs_qp_dest dest;
	struct ib_uverbs_qp_dest alt_dest;
	uint32_t max_send_wr;
	uint32_t max_recv_wr;
	uint32_t max_send_sge;
	uint32_t max_recv_sge;
	uint32_t max_inline_data;
	uint32_t qkey;
	uint32_t rq_psn;
	uint32_t sq_psn;
	uint32_t dest_qp_num;
	uint32_t qp_access_flags;
	uint16_t pkey_index;
	uint16_t alt_pkey_index;
	uint8_t  qp_state;
	uint8_t  cur_qp_state;
	uint8_t  path_mtu;
	uint8_t  path_mig_state;
	uint8_t  sq_draining;
	uint8_t  max_rd_atomic;
	uint8_t  max_dest_rd_atomic;
	uint8_t  min_rnr_timer;
	uint8_t  port_num;
	uint8_t  timeout;
	uint8_t  retry_cnt;
	uint8_t  rnr_retry;
	uint8_t  alt_port_num;
	uint8_t  alt_timeout;
	uint8_t  sq_sig_all;
	uint8_t  reserved[5];
	uint64_t driver_data[];
};

struct ib_uverbs_modify_qp {
	struct ib_uverbs_qp_dest dest;
	struct ib_uverbs_qp_dest alt_dest;
	uint32_t qp_handle;
	uint32_t attr_mask;
	uint32_t qkey;
	uint32_t rq_psn;
	uint32_t sq_psn;
	uint32_t dest_qp_num;
	uint32_t qp_access_flags;
	uint16_t pkey_index;
	uint16_t alt_pkey_index;
	uint8_t  qp_state;
	uint8_t  cur_qp_state;
	uint8_t  path_mtu;
	uint8_t  path_mig_state;
	uint8_t  en_sqd_async_notify;
	uint8_t  max_rd_atomic;
	uint8_t  max_dest_rd_atomic;
	uint8_t  min_rnr_timer;
	uint8_t  port_num;
	uint8_t  timeout;
	uint8_t  retry_cnt;
	uint8_t  rnr_retry;
	uint8_t  alt_port_num;
	uint8_t  alt_timeout;
	uint8_t  reserved[2];
	uint64_t driver_data[];
};


struct ib_uverbs_destroy_qp {
	ofv_resp_addr_t response;
	uint32_t qp_handle;
	uint32_t reserved;
};

struct ib_uverbs_destroy_qp_resp {
	uint32_t events_reported;
};

/*
 * The ib_uverbs_sge structure isn't used anywhere, since we assume
 * the ib_sge structure is packed the same way on 32-bit and 64-bit
 * architectures in both kernel and user space.  It's just here to
 * document the ABI.
 */
struct ib_uverbs_sge {
	uint64_t addr;
	uint32_t length;
	uint32_t lkey;
};

struct ib_uverbs_send_wr {
	uint64_t wr_id;
	uint32_t num_sge;
	uint32_t opcode;
	uint32_t send_flags;
	uint32_t imm_data;
	union {
		struct {
			uint64_t remote_addr;
			uint32_t rkey;
			uint32_t reserved;
		} rdma;
		struct {
			uint64_t remote_addr;
			uint64_t compare_add;
			uint64_t swap;
			uint32_t rkey;
			uint32_t reserved;
		} atomic;
		struct {
			uint32_t ah;
			uint32_t remote_qpn;
			uint32_t remote_qkey;
			uint32_t reserved;
		} ud;
	} wr;
};

struct ib_uverbs_post_send {
	uint64_t response;
	uint32_t qp_handle;
	uint32_t wr_count;
	uint32_t sge_count;
	uint32_t wqe_size;
	struct ib_uverbs_send_wr send_wr[];
};

struct ib_uverbs_post_send_resp {
	uint32_t bad_wr;
};

struct ib_uverbs_recv_wr {
	uint64_t wr_id;
	uint32_t num_sge;
	uint32_t reserved;
};

struct ib_uverbs_post_recv {
	uint64_t response;
	uint32_t qp_handle;
	uint32_t wr_count;
	uint32_t sge_count;
	uint32_t wqe_size;
	struct ib_uverbs_recv_wr recv_wr[];
};

struct ib_uverbs_post_recv_resp {
	uint32_t bad_wr;
};

struct ib_uverbs_post_srq_recv {
	uint64_t response;
	uint32_t srq_handle;
	uint32_t wr_count;
	uint32_t sge_count;
	uint32_t wqe_size;
	struct ib_uverbs_recv_wr recv[];
};

struct ib_uverbs_post_srq_recv_resp {
	uint32_t bad_wr;
};

struct ib_uverbs_create_ah {
	uint64_t response;
	uint64_t user_handle;
	uint32_t pd_handle;
	uint32_t reserved;
	struct ib_uverbs_ah_attr attr;
};

struct ib_uverbs_create_ah_resp {
	uint32_t ah_handle;
};

struct ib_uverbs_destroy_ah {
	uint32_t ah_handle;
};

struct ib_uverbs_attach_mcast {
	uint8_t  gid[16];
	uint32_t qp_handle;
	uint16_t mlid;
	uint16_t reserved;
	uint64_t driver_data[];
};

struct ib_uverbs_detach_mcast {
	uint8_t  gid[16];
	uint32_t qp_handle;
	uint16_t mlid;
	uint16_t reserved;
	uint64_t driver_data[];
};

struct ib_uverbs_create_srq {
	ofv_resp_addr_t response;
	uint64_t user_handle;
	uint32_t pd_handle;
	uint32_t max_wr;
	uint32_t max_sge;
	uint32_t srq_limit;
	uint64_t driver_data[];
};

/*
 * SRQ responses pass opaque data to userspace drivers, we choose a value
 * larger than what any HCA requires.
 */
#define	SOL_UVERBS_SRQ_DATA_OUT_SIZE	24
typedef uint64_t uverbs_srq_drv_out_data_t[SOL_UVERBS_SRQ_DATA_OUT_SIZE];

struct ib_uverbs_create_srq_resp {
	uint32_t srq_handle;
	uint32_t max_wr;
	uint32_t max_sge;
	uint32_t reserved;
	uverbs_srq_drv_out_data_t  drv_out;
};

struct ib_uverbs_modify_srq {
	uint32_t srq_handle;
	uint32_t attr_mask;
	uint32_t max_wr;
	uint32_t srq_limit;
	uint64_t driver_data[];
};

struct ib_uverbs_query_srq {
	ofv_resp_addr_t response;
	uint32_t srq_handle;
	uint32_t reserved;
	uint64_t driver_data[];
};

struct ib_uverbs_query_srq_resp {
	uint32_t max_wr;
	uint32_t max_sge;
	uint32_t srq_limit;
	uint32_t reserved;
};

struct ib_uverbs_destroy_srq {
	ofv_resp_addr_t response;
	uint32_t srq_handle;
	uint32_t reserved;
};

struct ib_uverbs_destroy_srq_resp {
	uint32_t events_reported;
};

#ifdef __cplusplus
}
#endif
#endif /* _SYS_IB_CLIENTS_OF_RDMA_IB_USER_VERBS_H */
