/*
 * This file contains definitions used in OFED defined user/kernel
 * interfaces. These are imported from the OFED header ib_verbs.h. Oracle
 * elects to have and use the contents of ib_verbs.h under and governed
 * by the OpenIB.org BSD license (see below for full license text). However,
 * the following notice accompanied the original version of this file:
 */

/*
 * Copyright (c) 2004 Mellanox Technologies Ltd.  All rights reserved.
 * Copyright (c) 2004 Infinicon Corporation.  All rights reserved.
 * Copyright (c) 2004 Intel Corporation.  All rights reserved.
 * Copyright (c) 2004 Topspin Corporation.  All rights reserved.
 * Copyright (c) 2004 Voltaire Corporation.  All rights reserved.
 * Copyright (c) 2005 Sun Microsystems, Inc. All rights reserved.
 * Copyright (c) 2005, 2006, 2007 Cisco Systems.  All rights reserved.
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
#ifndef _SYS_IB_CLIENTS_OF_IB_VERBS_H
#define	_SYS_IB_CLIENTS_OF_IB_VERBS_H

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/atomic.h>
#include <sys/mutex.h>
#include <sys/ib/ibtl/ibvti.h>
#include <sys/ib/clients/of/ofa_solaris.h>
#include <sys/ib/clients/of/sol_ofs/sol_ofs_common.h>

typedef struct sol_ofs_client_s *ofs_client_p_t;

union ib_gid {
	uint8_t	raw[16];
	struct {
		uint64_t	subnet_prefix;
		uint64_t	interface_id;
	} global;
};

enum rdma_node_type {
	/* IB values map to NodeInfo:NodeType. */
	RDMA_NODE_IB_CA 	= 1,
	RDMA_NODE_IB_SWITCH,
	RDMA_NODE_IB_ROUTER,
	RDMA_NODE_RNIC
};

enum rdma_transport_type {
	RDMA_TRANSPORT_IB,
	RDMA_TRANSPORT_IWARP
};

#define	__attribute_const__		__attribute__((__const__))
enum rdma_transport_type
rdma_node_get_transport(enum rdma_node_type node_type) __attribute_const__;

enum ib_device_cap_flags {
	IB_DEVICE_RESIZE_MAX_WR		= 1,
	IB_DEVICE_BAD_PKEY_CNTR		= (1<<1),
	IB_DEVICE_BAD_QKEY_CNTR		= (1<<2),
	IB_DEVICE_RAW_MULTI		= (1<<3),
	IB_DEVICE_AUTO_PATH_MIG		= (1<<4),
	IB_DEVICE_CHANGE_PHY_PORT	= (1<<5),
	IB_DEVICE_UD_AV_PORT_ENFORCE	= (1<<6),
	IB_DEVICE_CURR_QP_STATE_MOD	= (1<<7),
	IB_DEVICE_SHUTDOWN_PORT		= (1<<8),
	IB_DEVICE_INIT_TYPE		= (1<<9),
	IB_DEVICE_PORT_ACTIVE_EVENT	= (1<<10),
	IB_DEVICE_SYS_IMAGE_GUID	= (1<<11),
	IB_DEVICE_RC_RNR_NAK_GEN	= (1<<12),
	IB_DEVICE_SRQ_RESIZE		= (1<<13),
	IB_DEVICE_N_NOTIFY_CQ		= (1<<14),
	IB_DEVICE_ZERO_STAG		= (1<<15),
	IB_DEVICE_SEND_W_INV		= (1<<16),
	IB_DEVICE_MEM_WINDOW		= (1<<17)
};

enum ib_atomic_cap {
	IB_ATOMIC_NONE,
	IB_ATOMIC_HCA,
	IB_ATOMIC_GLOB
};

struct ib_device_attr {
	uint64_t		fw_ver;
	uint64_t		sys_image_guid;
	uint64_t		max_mr_size;
	uint64_t		page_size_cap;
	uint32_t		vendor_id;
	uint32_t		vendor_part_id;
	uint32_t		hw_ver;
	int			max_qp;
	int			max_qp_wr;
	int			device_cap_flags;
	int			max_sge;
	int			max_sge_rd;
	int			max_cq;
	int			max_cqe;
	int			max_mr;
	int			max_pd;
	int			max_qp_rd_atom;
	int			max_ee_rd_atom;
	int			max_res_rd_atom;
	int			max_qp_init_rd_atom;
	int			max_ee_init_rd_atom;
	enum ib_atomic_cap	atomic_cap;
	int			max_ee;
	int			max_rdd;
	int			max_mw;
	int			max_raw_ipv6_qp;
	int			max_raw_ethy_qp;
	int			max_mcast_grp;
	int			max_mcast_qp_attach;
	int			max_total_mcast_qp_attach;
	int			max_ah;
	int			max_fmr;
	int			max_map_per_fmr;
	int			max_srq;
	int			max_srq_wr;
	int			max_srq_sge;
	uint16_t		max_pkeys;
	uint8_t			local_ca_ack_delay;
};

enum ib_mtu {
	OFED_IB_MTU_256  = 1,
	OFED_IB_MTU_512  = 2,
	OFED_IB_MTU_1024 = 3,
	OFED_IB_MTU_2048 = 4,
	OFED_IB_MTU_4096 = 5
};

enum ib_port_state {
	IB_PORT_NOP		= 0,
	IB_PORT_DOWN		= 1,
	IB_PORT_INIT		= 2,
	IB_PORT_ARMED		= 3,
	IB_PORT_ACTIVE		= 4,
	IB_PORT_ACTIVE_DEFER	= 5
};

enum ib_port_cap_flags {
	IB_PORT_SM				= 1 <<  1,
	IB_PORT_NOTICE_SUP			= 1 <<  2,
	IB_PORT_TRAP_SUP			= 1 <<  3,
	IB_PORT_OPT_IPD_SUP			= 1 <<  4,
	IB_PORT_AUTO_MIGR_SUP			= 1 <<  5,
	IB_PORT_SL_MAP_SUP			= 1 <<  6,
	IB_PORT_MKEY_NVRAM			= 1 <<  7,
	IB_PORT_PKEY_NVRAM			= 1 <<  8,
	IB_PORT_LED_INFO_SUP			= 1 <<  9,
	IB_PORT_SM_DISABLED			= 1 << 10,
	IB_PORT_SYS_IMAGE_GUID_SUP		= 1 << 11,
	IB_PORT_PKEY_SW_EXT_PORT_TRAP_SUP	= 1 << 12,
	IB_PORT_CM_SUP				= 1 << 16,
	IB_PORT_SNMP_TUNNEL_SUP			= 1 << 17,
	IB_PORT_REINIT_SUP			= 1 << 18,
	IB_PORT_DEVICE_MGMT_SUP			= 1 << 19,
	IB_PORT_VENDOR_CLASS_SUP		= 1 << 20,
	IB_PORT_DR_NOTICE_SUP			= 1 << 21,
	IB_PORT_CAP_MASK_NOTICE_SUP		= 1 << 22,
	IB_PORT_BOOT_MGMT_SUP			= 1 << 23,
	IB_PORT_LINK_LATENCY_SUP		= 1 << 24,
	IB_PORT_CLIENT_REG_SUP			= 1 << 25
};

enum ib_port_width {
	IB_WIDTH_1X	= 1,
	IB_WIDTH_4X	= 2,
	IB_WIDTH_8X	= 4,
	IB_WIDTH_12X	= 8
};

static inline int ib_width_enum_to_int(enum ib_port_width width)
{
	switch (width) {
		case IB_WIDTH_1X:  return  1;
		case IB_WIDTH_4X:  return  4;
		case IB_WIDTH_8X:  return  8;
		case IB_WIDTH_12X: return 12;
		default: return -1;
	}
}

struct ib_port_attr {
	enum ib_port_state	state;
	enum ib_mtu		max_mtu;
	enum ib_mtu		active_mtu;
	int			gid_tbl_len;
	uint32_t		port_cap_flags;
	uint32_t		max_msg_sz;
	uint32_t		bad_pkey_cntr;
	uint32_t		qkey_viol_cntr;
	uint16_t		pkey_tbl_len;
	uint16_t		lid;
	uint16_t		sm_lid;
	uint8_t			lmc;
	uint8_t			max_vl_num;
	uint8_t			sm_sl;
	uint8_t			subnet_timeout;
	uint8_t			init_type_reply;
	uint8_t			active_width;
	uint8_t			active_speed;
	uint8_t			phys_state;
};

enum ib_device_modify_flags {
	IB_DEVICE_MODIFY_SYS_IMAGE_GUID	= 1 << 0,
	IB_DEVICE_MODIFY_NODE_DESC	= 1 << 1
};

struct ib_device_modify {
	uint64_t	sys_image_guid;
	char	node_desc[64];
};

enum ib_port_modify_flags {
	IB_PORT_SHUTDOWN		= 1,
	IB_PORT_INIT_TYPE		= (1<<2),
	IB_PORT_RESET_QKEY_CNTR		= (1<<3)
};

struct ib_port_modify {
	uint32_t	set_port_cap_mask;
	uint32_t	clr_port_cap_mask;
	uint8_t	init_type;
};

enum ib_event_type {
	IB_EVENT_CQ_ERR,
	IB_EVENT_QP_FATAL,
	IB_EVENT_QP_REQ_ERR,
	IB_EVENT_QP_ACCESS_ERR,
	IB_EVENT_COMM_EST,
	IB_EVENT_SQ_DRAINED,
	IB_EVENT_PATH_MIG,
	IB_EVENT_PATH_MIG_ERR,
	IB_EVENT_DEVICE_FATAL,
	IB_EVENT_PORT_ACTIVE,
	IB_EVENT_PORT_ERR,
	IB_EVENT_LID_CHANGE,
	IB_EVENT_PKEY_CHANGE,
	IB_EVENT_SM_CHANGE,
	IB_EVENT_SRQ_ERR,
	IB_EVENT_SRQ_LIMIT_REACHED,
	IB_EVENT_QP_LAST_WQE_REACHED,
	IB_EVENT_CLIENT_REREGISTER
};

struct ib_event {
	struct ib_device	*device;
	union {
		struct ib_cq	*cq;
		struct ib_qp	*qp;
		struct ib_srq	*srq;
		uint8_t		port_num;
	} element;
	enum ib_event_type	event;
};

struct ib_event_handler {
	struct ib_device	*device;
	void 			(*handler)(struct ib_event_handler *,
				    struct ib_event *);
	llist_head_t	list;
};

struct ib_global_route {
	union ib_gid	dgid;
	uint32_t	flow_label;
	uint8_t		sgid_index;
	uint8_t		hop_limit;
	uint8_t		traffic_class;
};

enum ib_ah_flags {
	IB_AH_GRH	= 1
};

enum ib_rate {
	IB_RATE_PORT_CURRENT = 0,
	IB_RATE_2_5_GBPS = 2,
	IB_RATE_5_GBPS   = 5,
	IB_RATE_10_GBPS  = 3,
	IB_RATE_20_GBPS  = 6,
	IB_RATE_30_GBPS  = 4,
	IB_RATE_40_GBPS  = 7,
	IB_RATE_60_GBPS  = 8,
	IB_RATE_80_GBPS  = 9,
	IB_RATE_120_GBPS = 10
};

struct ib_ah_attr {
	struct ib_global_route	grh;
	uint16_t		dlid;
	uint8_t			sl;
	uint8_t			src_path_bits;
	uint8_t			static_rate;
	uint8_t			ah_flags;
	uint8_t			port_num;
};

enum ib_wc_status {
	IB_WC_SUCCESS,
	IB_WC_LOC_LEN_ERR,
	IB_WC_LOC_QP_OP_ERR,
	IB_WC_LOC_EEC_OP_ERR,
	IB_WC_LOC_PROT_ERR,
	IB_WC_WR_FLUSH_ERR,
	IB_WC_MW_BIND_ERR,
	IB_WC_BAD_RESP_ERR,
	IB_WC_LOC_ACCESS_ERR,
	IB_WC_REM_INV_REQ_ERR,
	IB_WC_REM_ACCESS_ERR,
	IB_WC_REM_OP_ERR,
	IB_WC_RETRY_EXC_ERR,
	IB_WC_RNR_RETRY_EXC_ERR,
	IB_WC_LOC_RDD_VIOL_ERR,
	IB_WC_REM_INV_RD_REQ_ERR,
	IB_WC_REM_ABORT_ERR,
	IB_WC_INV_EECN_ERR,
	IB_WC_INV_EEC_STATE_ERR,
	IB_WC_FATAL_ERR,
	IB_WC_RESP_TIMEOUT_ERR,
	IB_WC_GENERAL_ERR
};

enum ib_wc_opcode {
	IB_WC_SEND,
	IB_WC_RDMA_WRITE,
	IB_WC_RDMA_READ,
	IB_WC_COMP_SWAP,
	IB_WC_FETCH_ADD,
	IB_WC_BIND_MW,
/*
 * Set value of IB_WC_RECV so consumers can test if a completion is a
 * receive by testing (opcode & IB_WC_RECV).
 */
	IB_WC_RECV			= 1 << 7,
	IB_WC_RECV_RDMA_WITH_IMM
};

enum ib_wc_flags {
	IB_WC_GRH		= 1,
	IB_WC_WITH_IMM		= (1<<1),
};

struct ib_wc {
	uint64_t		wr_id;
	enum ib_wc_status	status;
	enum ib_wc_opcode	opcode;
	uint32_t		vendor_err;
	uint32_t		byte_len;
	struct ib_qp		*qp;
	uint32_t		imm_data;
	uint32_t		src_qp;
	int			wc_flags;
	uint16_t		pkey_index;
	uint16_t		slid;
	uint8_t			sl;
	uint8_t			dlid_path_bits;
	uint8_t			port_num;
};

enum ib_cq_notify_flags {
	IB_CQ_SOLICITED			= 1 << 0,
	IB_CQ_NEXT_COMP			= 1 << 1,
	IB_CQ_SOLICITED_MASK		= IB_CQ_SOLICITED | IB_CQ_NEXT_COMP,
	IB_CQ_REPORT_MISSED_EVENTS	= 1 << 2,
};

enum ib_srq_attr_mask {
	IB_SRQ_MAX_WR	= 1 << 0,
	IB_SRQ_LIMIT	= 1 << 1,
};

struct ib_srq_attr {
	uint32_t	max_wr;
	uint32_t	max_sge;
	uint32_t	srq_limit;
};

struct ib_srq_init_attr {
	void			(*event_handler)(struct ib_event *, void *);
	void			*srq_context;
	struct ib_srq_attr	attr;
};

struct ib_qp_cap {
	uint32_t	max_send_wr;
	uint32_t	max_recv_wr;
	uint32_t	max_send_sge;
	uint32_t	max_recv_sge;
	uint32_t	max_inline_data;
};

enum ib_sig_type {
	IB_SIGNAL_ALL_WR,
	IB_SIGNAL_REQ_WR
};

enum ib_qp_type {
	/*
	 * IB_QPT_SMI and IB_QPT_GSI have to be the first two entries
	 * here (and in that order) since the MAD layer uses them as
	 * indices into a 2-entry table.
	 */
	IB_QPT_SMI,
	IB_QPT_GSI,

	IB_QPT_RC,
	IB_QPT_UC,
	IB_QPT_UD,
	IB_QPT_RAW_IPV6,
	IB_QPT_RAW_ETY
};

struct ib_qp_init_attr {
	void			(*event_handler)(struct ib_event *, void *);
	void			*qp_context;
	struct ib_cq		*send_cq;
	struct ib_cq		*recv_cq;
	struct ib_srq		*srq;
	struct ib_qp_cap	cap;
	enum ib_sig_type	sq_sig_type;
	enum ib_qp_type		qp_type;
	uint8_t			port_num; /* special QP types only */
};

enum ib_rnr_timeout {
	IB_RNR_TIMER_655_36 =  0,
	IB_RNR_TIMER_000_01 =  1,
	IB_RNR_TIMER_000_02 =  2,
	IB_RNR_TIMER_000_03 =  3,
	IB_RNR_TIMER_000_04 =  4,
	IB_RNR_TIMER_000_06 =  5,
	IB_RNR_TIMER_000_08 =  6,
	IB_RNR_TIMER_000_12 =  7,
	IB_RNR_TIMER_000_16 =  8,
	IB_RNR_TIMER_000_24 =  9,
	IB_RNR_TIMER_000_32 = 10,
	IB_RNR_TIMER_000_48 = 11,
	IB_RNR_TIMER_000_64 = 12,
	IB_RNR_TIMER_000_96 = 13,
	IB_RNR_TIMER_001_28 = 14,
	IB_RNR_TIMER_001_92 = 15,
	IB_RNR_TIMER_002_56 = 16,
	IB_RNR_TIMER_003_84 = 17,
	IB_RNR_TIMER_005_12 = 18,
	IB_RNR_TIMER_007_68 = 19,
	IB_RNR_TIMER_010_24 = 20,
	IB_RNR_TIMER_015_36 = 21,
	IB_RNR_TIMER_020_48 = 22,
	IB_RNR_TIMER_030_72 = 23,
	IB_RNR_TIMER_040_96 = 24,
	IB_RNR_TIMER_061_44 = 25,
	IB_RNR_TIMER_081_92 = 26,
	IB_RNR_TIMER_122_88 = 27,
	IB_RNR_TIMER_163_84 = 28,
	IB_RNR_TIMER_245_76 = 29,
	IB_RNR_TIMER_327_68 = 30,
	IB_RNR_TIMER_491_52 = 31
};

enum ib_qp_attr_mask {
	IB_QP_STATE			= 1,
	IB_QP_CUR_STATE			= (1<<1),
	IB_QP_EN_SQD_ASYNC_NOTIFY	= (1<<2),
	IB_QP_ACCESS_FLAGS		= (1<<3),
	IB_QP_PKEY_INDEX		= (1<<4),
	IB_QP_PORT			= (1<<5),
	IB_QP_QKEY			= (1<<6),
	IB_QP_AV			= (1<<7),
	IB_QP_PATH_MTU			= (1<<8),
	IB_QP_TIMEOUT			= (1<<9),
	IB_QP_RETRY_CNT			= (1<<10),
	IB_QP_RNR_RETRY			= (1<<11),
	IB_QP_RQ_PSN			= (1<<12),
	IB_QP_MAX_QP_RD_ATOMIC		= (1<<13),
	IB_QP_ALT_PATH			= (1<<14),
	IB_QP_MIN_RNR_TIMER		= (1<<15),
	IB_QP_SQ_PSN			= (1<<16),
	IB_QP_MAX_DEST_RD_ATOMIC	= (1<<17),
	IB_QP_PATH_MIG_STATE		= (1<<18),
	IB_QP_CAP			= (1<<19),
	IB_QP_DEST_QPN			= (1<<20)
};

enum ib_qp_state {
	IB_QPS_RESET,
	IB_QPS_INIT,
	IB_QPS_RTR,
	IB_QPS_RTS,
	IB_QPS_SQD,
	IB_QPS_SQE,
	IB_QPS_ERR
};

enum ib_mig_state {
	IB_MIG_MIGRATED,
	IB_MIG_REARM,
	IB_MIG_ARMED
};

struct ib_qp_attr {
	enum ib_qp_state	qp_state;
	enum ib_qp_state	cur_qp_state;
	enum ib_mtu		path_mtu;
	enum ib_mig_state	path_mig_state;
	uint32_t		qkey;
	uint32_t		rq_psn;
	uint32_t		sq_psn;
	uint32_t		dest_qp_num;
	int			qp_access_flags;
	struct ib_qp_cap	cap;
	struct ib_ah_attr	ah_attr;
	struct ib_ah_attr	alt_ah_attr;
	uint16_t		pkey_index;
	uint16_t		alt_pkey_index;
	uint8_t			en_sqd_async_notify;
	uint8_t			sq_draining;
	uint8_t			max_rd_atomic;
	uint8_t			max_dest_rd_atomic;
	uint8_t			min_rnr_timer;
	uint8_t			port_num;
	uint8_t			timeout;
	uint8_t			retry_cnt;
	uint8_t			rnr_retry;
	uint8_t			alt_port_num;
	uint8_t			alt_timeout;
};

enum ib_wr_opcode {
	IB_WR_RDMA_WRITE,
	IB_WR_RDMA_WRITE_WITH_IMM,
	IB_WR_SEND,
	IB_WR_SEND_WITH_IMM,
	IB_WR_RDMA_READ,
	IB_WR_ATOMIC_CMP_AND_SWP,
	IB_WR_ATOMIC_FETCH_AND_ADD
};

enum ib_access_flags {
	IB_ACCESS_LOCAL_WRITE	= 1,
	IB_ACCESS_REMOTE_WRITE	= (1<<1),
	IB_ACCESS_REMOTE_READ	= (1<<2),
	IB_ACCESS_REMOTE_ATOMIC	= (1<<3),
	IB_ACCESS_MW_BIND	= (1<<4),
	IB_ACCESS_SO		= (1<<5)	/* MR with Strong Ordering */
};

struct ib_pd {
	struct ib_device	*device;
	ibt_pd_hdl_t		ibt_pd;
};

typedef void (*ib_comp_handler)(struct ib_cq *cq, void *cq_context);

struct ib_cq {
	struct ib_device	*device;
	ib_comp_handler		comp_handler;
	void			(*event_handler)(struct ib_event *, void *);
	void			*cq_context;
	int			cqe;
	ibt_cq_hdl_t		ibt_cq;
	kmutex_t		lock;
};

struct ib_srq {
	struct ib_device	*device;
	struct ib_pd		*pd;
	void			(*event_handler)(struct ib_event *, void *);
	void			*srq_context;
	ibt_srq_hdl_t		ibt_srq;
};

struct ib_qp {
	struct ib_device	*device;
	struct ib_pd		*pd;
	struct ib_cq		*send_cq;
	struct ib_cq		*recv_cq;
	struct ib_srq		*srq;
	void			(*event_handler)(struct ib_event *, void *);
	void			*qp_context;
	uint32_t		qp_num;
	enum ib_qp_type		qp_type;
	ibt_qp_hdl_t		ibt_qp;
	kmutex_t 		lock;
};

#define	IB_DEVICE_NAME_MAX	64

typedef struct ib_device {
	ibt_hca_hdl_t		hca_hdl;
	char			name[IB_DEVICE_NAME_MAX];
	uint64_t		node_guid;
	uint32_t		local_dma_lkey;
	uint8_t			phys_port_cnt;
	uint8_t			node_type;
	enum {
				IB_DEV_UNINITIALIZED,
				IB_DEV_REGISTERED,
				IB_DEV_UNREGISTERED,
				IB_DEV_CLOSE = 100,
				IB_DEV_OPEN
	} reg_state;
	void 			*data;
	ofs_client_p_t 		clnt_hdl;
	struct llist_head 	list;
} ib_device_t;

typedef struct ib_client {
	char		*name;
	void		(*add)   (struct ib_device *);
	void		(*remove)(struct ib_device *);
	dev_info_t	*dip;
	ofs_client_p_t 	clnt_hdl;
	enum {
			IB_CLNT_UNINITIALIZED,
			IB_CLNT_INITIALIZED
	} state;
} ib_client_t;

int ib_register_client(struct ib_client *client);
void ib_unregister_client(struct ib_client *client);

void *ib_get_client_data(struct ib_device *device, struct ib_client *client);
void  ib_set_client_data(struct ib_device *device, struct ib_client *client,
    void *data);

int ib_query_device(struct ib_device *device,
    struct ib_device_attr *device_attr);

/*
 * ib_alloc_pd - Allocates an unused protection domain.
 * @device: The device on which to allocate the protection domain.
 *
 * A protection domain object provides an association between QPs, shared
 * receive queues, address handles, memory regions, and memory windows.
 */
struct ib_pd *ib_alloc_pd(struct ib_device *device);

/*
 * ib_dealloc_pd - Deallocates a protection domain.
 * @pd: The protection domain to deallocate.
 */
int ib_dealloc_pd(struct ib_pd *pd);

/*
 * ib_create_qp - Creates a QP associated with the specified protection
 *   domain.
 * @pd: The protection domain associated with the QP.
 * @qp_init_attr: A list of initial attributes required to create the
 *   QP.  If QP creation succeeds, then the attributes are updated to
 *   the actual capabilities of the created QP.
 */
struct ib_qp *ib_create_qp(struct ib_pd *pd,
    struct ib_qp_init_attr *qp_init_attr);

/*
 * ib_modify_qp - Modifies the attributes for the specified QP and then
 *   transitions the QP to the given state.
 * @qp: The QP to modify.
 * @qp_attr: On input, specifies the QP attributes to modify.  On output,
 *   the current values of selected QP attributes are returned.
 * @qp_attr_mask: A bit-mask used to specify which attributes of the QP
 *   are being modified.
 */
int ib_modify_qp(struct ib_qp *qp, struct ib_qp_attr *qp_attr,
    int qp_attr_mask);

/*
 * ib_destroy_qp - Destroys the specified QP.
 * @qp: The QP to destroy.
 */
int ib_destroy_qp(struct ib_qp *qp);

/*
 * IB_CQ_VECTOR_LEAST_ATTACHED: The constant specifies that
 *      the CQ will be attached to the completion vector that has
 *      the least number of CQs already attached to it.
 */
#define	IB_CQ_VECTOR_LEAST_ATTACHED	0xffffffff

/*
 * ib_create_cq - Creates a CQ on the specified device.
 * @device: The device on which to create the CQ.
 * @comp_handler: A user-specified callback that is invoked when a
 *   completion event occurs on the CQ.
 * @event_handler: A user-specified callback that is invoked when an
 *   asynchronous event not associated with a completion occurs on the CQ.
 * @cq_context: Context associated with the CQ returned to the user via
 *   the associated completion and event handlers.
 * @cqe: The minimum size of the CQ.
 * @comp_vector - Completion queue sched handle.
 *
 * Users can examine the cq structure to determine the actual CQ size.
 */
struct ib_cq *ib_create_cq(struct ib_device *device,
    ib_comp_handler comp_handler,
    void (*event_handler)(struct ib_event *, void *),
    void *cq_context, int cqe, void *comp_vector);

/*
 * ib_destroy_cq - Destroys the specified CQ.
 * @cq: The CQ to destroy.
 */
int ib_destroy_cq(struct ib_cq *cq);

/*
 * ib_poll_cq - poll a CQ for completion(s)
 * @cq:the CQ being polled
 * @num_entries:maximum number of completions to return
 * @wc:array of at least @num_entries &struct ib_wc where completions
 *   will be returned
 *
 * Poll a CQ for (possibly multiple) completions.  If the return value
 * is < 0, an error occurred.  If the return value is >= 0, it is the
 * number of completions returned.  If the return value is
 * non-negative and < num_entries, then the CQ was emptied.
 */
int ib_poll_cq(struct ib_cq *cq, int num_entries, struct ib_wc *wc);

/*
 * ib_req_notify_cq - Request completion notification on a CQ.
 * @cq: The CQ to generate an event for.
 * @flags:
 *   Must contain exactly one of %IB_CQ_SOLICITED or %IB_CQ_NEXT_COMP
 *   to request an event on the next solicited event or next work
 *   completion at any type, respectively. %IB_CQ_REPORT_MISSED_EVENTS
 *   may also be |ed in to request a hint about missed events, as
 *   described below.
 *
 * Return Value:
 *    < 0 means an error occurred while requesting notification
 *   == 0 means notification was requested successfully, and if
 *        IB_CQ_REPORT_MISSED_EVENTS was passed in, then no events
 *        were missed and it is safe to wait for another event.  In
 *        this case is it guaranteed that any work completions added
 *        to the CQ since the last CQ poll will trigger a completion
 *        notification event.
 *    > 0 is only returned if IB_CQ_REPORT_MISSED_EVENTS was passed
 *        in.  It means that the consumer must poll the CQ again to
 *        make sure it is empty to avoid missing an event because of a
 *        race between requesting notification and an entry being
 *        added to the CQ.  This return value means it is possible
 *        (but not guaranteed) that a work completion has been added
 *        to the CQ since the last poll without triggering a
 *        completion notification event.
 */
int ib_req_notify_cq(struct ib_cq *cq, enum ib_cq_notify_flags flags);

struct rdma_cm_id;
ibt_hca_hdl_t ib_get_ibt_hca_hdl(struct ib_device *device);

ibt_channel_hdl_t
ib_get_ibt_channel_hdl(struct rdma_cm_id *cm);

#ifdef __cplusplus
}
#endif
#endif /* _SYS_IB_CLIENTS_OF_IB_VERBS_H */
