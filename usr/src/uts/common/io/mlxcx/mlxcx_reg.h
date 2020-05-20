/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2020, The University of Queensland
 * Copyright (c) 2018, Joyent, Inc.
 * Copyright 2020 RackTop Systems, Inc.
 */

#ifndef _MLXCX_REG_H
#define	_MLXCX_REG_H

#include <sys/types.h>
#include <sys/byteorder.h>

#include <mlxcx_endint.h>

#if !defined(_BIT_FIELDS_HTOL) && !defined(_BIT_FIELDS_LTOH)
#error "Need _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH"
#endif

/*
 * Register offsets.
 */

#define	MLXCX_ISS_FIRMWARE	0x0000
#define	MLXCX_ISS_FW_MAJOR(x)	(((x) & 0xffff))
#define	MLXCX_ISS_FW_MINOR(x)	(((x) >> 16) & 0xffff)
#define	MLXCX_ISS_FW_CMD	0x0004
#define	MLXCX_ISS_FW_REV(x)	(((x) & 0xffff))
#define	MLXCX_ISS_CMD_REV(x)	(((x) >> 16) & 0xffff)
#define	MLXCX_ISS_CMD_HIGH	0x0010
#define	MLXCX_ISS_CMD_LOW	0x0014
#define	MLXCX_ISS_CMDQ_SIZE(x)	(((x) >> 4) & 0xf)
#define	MLXCX_ISS_CMDQ_STRIDE(x)	((x) & 0xf)

#define	MLXCX_ISS_CMD_DOORBELL	0x0018
#define	MLXCX_ISS_INIT		0x01fc
#define	MLXCX_ISS_INITIALIZING(x)	(((x) >> 31) & 0x1)
#define	MLXCX_ISS_HEALTH_BUF	0x0200
#define	MLXCX_ISS_NO_DRAM_NIC	0x0240
#define	MLXCX_ISS_TIMER		0x1000
#define	MLXCX_ISS_HEALTH_COUNT	0x1010
#define	MLXCX_ISS_HEALTH_SYND	0x1013

#define	MLXCX_CMD_INLINE_INPUT_LEN	16
#define	MLXCX_CMD_INLINE_OUTPUT_LEN	16

#define	MLXCX_CMD_MAILBOX_LEN		512

#define	MLXCX_CMD_TRANSPORT_PCI		7
#define	MLXCX_CMD_HW_OWNED		0x01
#define	MLXCX_CMD_STATUS(x)		((x) >> 1)

#define	MLXCX_UAR_CQ_ARM	0x0020
#define	MLXCX_UAR_EQ_ARM	0x0040
#define	MLXCX_UAR_EQ_NOARM	0x0048

/* Number of blue flame reg pairs per UAR */
#define	MLXCX_BF_PER_UAR	2
#define	MLXCX_BF_PER_UAR_MASK	0x1
#define	MLXCX_BF_SIZE		0x100
#define	MLXCX_BF_BASE		0x0800

/* CSTYLED */
#define	MLXCX_EQ_ARM_EQN	(bitdef_t){24, 0xff000000}
/* CSTYLED */
#define	MLXCX_EQ_ARM_CI		(bitdef_t){0,  0x00ffffff}

/*
 * Hardware structure that is used to represent a command.
 */
#pragma pack(1)
typedef struct {
	uint8_t		mce_type;
	uint8_t		mce_rsvd[3];
	uint32be_t	mce_in_length;
	uint64be_t	mce_in_mbox;
	uint8_t		mce_input[MLXCX_CMD_INLINE_INPUT_LEN];
	uint8_t		mce_output[MLXCX_CMD_INLINE_OUTPUT_LEN];
	uint64be_t	mce_out_mbox;
	uint32be_t	mce_out_length;
	uint8_t		mce_token;
	uint8_t		mce_sig;
	uint8_t		mce_rsvd1;
	uint8_t		mce_status;
} mlxcx_cmd_ent_t;

typedef struct {
	uint8_t		mlxb_data[MLXCX_CMD_MAILBOX_LEN];
	uint8_t		mlxb_rsvd[48];
	uint64be_t	mlxb_nextp;
	uint32be_t	mlxb_blockno;
	uint8_t		mlxb_rsvd1;
	uint8_t		mlxb_token;
	uint8_t		mlxb_ctrl_sig;
	uint8_t		mlxb_sig;
} mlxcx_cmd_mailbox_t;

typedef struct {
	uint8_t		mled_page_request_rsvd[2];
	uint16be_t	mled_page_request_function_id;
	uint32be_t	mled_page_request_num_pages;
} mlxcx_evdata_page_request_t;

/* CSTYLED */
#define	MLXCX_EVENT_PORT_NUM	(bitdef_t){ .bit_shift = 4, .bit_mask = 0xF0 }

typedef struct {
	uint8_t		mled_port_state_rsvd[8];
	bits8_t		mled_port_state_port_num;
} mlxcx_evdata_port_state_t;

typedef enum {
	MLXCX_MODULE_INITIALIZING	= 0x0,
	MLXCX_MODULE_PLUGGED		= 0x1,
	MLXCX_MODULE_UNPLUGGED		= 0x2,
	MLXCX_MODULE_ERROR		= 0x3
} mlxcx_module_status_t;

typedef enum {
	MLXCX_MODULE_ERR_POWER_BUDGET		= 0x0,
	MLXCX_MODULE_ERR_LONG_RANGE		= 0x1,
	MLXCX_MODULE_ERR_BUS_STUCK		= 0x2,
	MLXCX_MODULE_ERR_NO_EEPROM		= 0x3,
	MLXCX_MODULE_ERR_ENFORCEMENT		= 0x4,
	MLXCX_MODULE_ERR_UNKNOWN_IDENT		= 0x5,
	MLXCX_MODULE_ERR_HIGH_TEMP		= 0x6,
	MLXCX_MODULE_ERR_CABLE_SHORTED		= 0x7,
} mlxcx_module_error_type_t;

typedef struct {
	uint8_t		mled_port_mod_rsvd;
	uint8_t		mled_port_mod_module;
	uint8_t		mled_port_mod_rsvd2;
	uint8_t		mled_port_mod_module_status;
	uint8_t		mled_port_mod_rsvd3[2];
	uint8_t		mled_port_mod_error_type;
	uint8_t		mled_port_mod_rsvd4;
} mlxcx_evdata_port_mod_t;

typedef struct {
	uint8_t		mled_completion_rsvd[25];
	uint24be_t	mled_completion_cqn;
} mlxcx_evdata_completion_t;

typedef enum {
	MLXCX_EV_QUEUE_TYPE_QP	= 0x0,
	MLXCX_EV_QUEUE_TYPE_RQ	= 0x1,
	MLXCX_EV_QUEUE_TYPE_SQ	= 0x2,
} mlxcx_evdata_queue_type_t;

typedef struct {
	uint8_t		mled_queue_rsvd[20];
	uint8_t		mled_queue_type;
	uint8_t		mled_queue_rsvd2[4];
	uint24be_t	mled_queue_num;
} mlxcx_evdata_queue_t;

#define	MLXCX_EQ_OWNER_INIT	1

typedef struct {
	uint8_t		mleqe_rsvd[1];
	uint8_t		mleqe_event_type;
	uint8_t		mleqe_rsvd2[1];
	uint8_t		mleqe_event_sub_type;
	uint8_t		mleqe_rsvd3[28];
	union {
		uint8_t				mleqe_unknown_data[28];
		mlxcx_evdata_completion_t	mleqe_completion;
		mlxcx_evdata_page_request_t	mleqe_page_request;
		mlxcx_evdata_port_state_t	mleqe_port_state;
		mlxcx_evdata_port_mod_t		mleqe_port_mod;
		mlxcx_evdata_queue_t		mleqe_queue;
	};
	uint8_t		mleqe_rsvd4[2];
	uint8_t		mleqe_signature;
	uint8_t		mleqe_owner;
} mlxcx_eventq_ent_t;

typedef enum {
	MLXCX_CQE_L3_HDR_NONE		= 0x0,
	MLXCX_CQE_L3_HDR_RCV_BUF	= 0x1,
	MLXCX_CQE_L3_HDR_CQE		= 0x2,
} mlxcx_cqe_l3_hdr_placement_t;

typedef enum {
	MLXCX_CQE_CSFLAGS_L4_OK		= 1 << 2,
	MLXCX_CQE_CSFLAGS_L3_OK		= 1 << 1,
	MLXCX_CQE_CSFLAGS_L2_OK		= 1 << 0,
} mlxcx_cqe_csflags_t;

typedef enum {
	MLXCX_CQE_L4_TYPE_NONE		= 0,
	MLXCX_CQE_L4_TYPE_TCP		= 1,
	MLXCX_CQE_L4_TYPE_UDP		= 2,
	MLXCX_CQE_L4_TYPE_TCP_EMPTY_ACK	= 3,
	MLXCX_CQE_L4_TYPE_TCP_ACK	= 4,
} mlxcx_cqe_l4_hdr_type_t;

typedef enum {
	MLXCX_CQE_L3_TYPE_NONE		= 0,
	MLXCX_CQE_L3_TYPE_IPv6		= 1,
	MLXCX_CQE_L3_TYPE_IPv4		= 2,
} mlxcx_cqe_l3_hdr_type_t;

typedef enum {
	MLXCX_CQE_RX_HASH_NONE		= 0,
	MLXCX_CQE_RX_HASH_IPv4		= 1,
	MLXCX_CQE_RX_HASH_IPv6		= 2,
	MLXCX_CQE_RX_HASH_IPSEC_SPI	= 3,
} mlxcx_cqe_rx_hash_type_t;
/* BEGIN CSTYLED */
#define	MLXCX_CQE_RX_HASH_IP_SRC	(bitdef_t){0, 0x3}
#define	MLXCX_CQE_RX_HASH_IP_DEST	(bitdef_t){2, (0x3 << 2)}
#define	MLXCX_CQE_RX_HASH_L4_SRC	(bitdef_t){4, (0x3 << 4)}
#define	MLXCX_CQE_RX_HASH_L4_DEST	(bitdef_t){6, (0x3 << 6)}
/* END CSTYLED */

typedef enum {
	MLXCX_CQE_OP_REQ		= 0x0,
	MLXCX_CQE_OP_RESP_RDMA		= 0x1,
	MLXCX_CQE_OP_RESP		= 0x2,
	MLXCX_CQE_OP_RESP_IMMEDIATE	= 0x3,
	MLXCX_CQE_OP_RESP_INVALIDATE	= 0x4,
	MLXCX_CQE_OP_RESIZE_CQ		= 0x5,
	MLXCX_CQE_OP_SIG_ERR		= 0x12,
	MLXCX_CQE_OP_REQ_ERR		= 0xd,
	MLXCX_CQE_OP_RESP_ERR		= 0xe,
	MLXCX_CQE_OP_INVALID		= 0xf
} mlxcx_cqe_opcode_t;

typedef enum {
	MLXCX_CQE_FORMAT_BASIC		= 0,
	MLXCX_CQE_FORMAT_INLINE_32	= 1,
	MLXCX_CQE_FORMAT_INLINE_64	= 2,
	MLXCX_CQE_FORMAT_COMPRESSED	= 3,
} mlxcx_cqe_format_t;

typedef enum {
	MLXCX_CQE_OWNER_INIT		= 1
} mlxcx_cqe_owner_t;

typedef enum {
	MLXCX_VLAN_TYPE_NONE,
	MLXCX_VLAN_TYPE_CVLAN,
	MLXCX_VLAN_TYPE_SVLAN,
} mlxcx_vlan_type_t;

typedef enum {
	MLXCX_CQ_ERR_LOCAL_LENGTH	= 0x1,
	MLXCX_CQ_ERR_LOCAL_QP_OP	= 0x2,
	MLXCX_CQ_ERR_LOCAL_PROTECTION	= 0x4,
	MLXCX_CQ_ERR_WR_FLUSHED		= 0x5,
	MLXCX_CQ_ERR_MEM_WINDOW_BIND	= 0x6,
	MLXCX_CQ_ERR_BAD_RESPONSE	= 0x10,
	MLXCX_CQ_ERR_LOCAL_ACCESS	= 0x11,
	MLXCX_CQ_ERR_XPORT_RETRY_CTR	= 0x15,
	MLXCX_CQ_ERR_RNR_RETRY_CTR	= 0x16,
	MLXCX_CQ_ERR_ABORTED		= 0x22
} mlxcx_cq_error_syndrome_t;

typedef struct {
	uint8_t		mlcqee_rsvd[2];
	uint16be_t	mlcqee_wqe_id;
	uint8_t		mlcqee_rsvd2[29];
	uint24be_t	mlcqee_user_index;
	uint8_t		mlcqee_rsvd3[8];
	uint32be_t	mlcqee_byte_cnt;
	uint8_t		mlcqee_rsvd4[6];
	uint8_t		mlcqee_vendor_error_syndrome;
	uint8_t		mlcqee_syndrome;
	uint8_t		mlcqee_wqe_opcode;
	uint24be_t	mlcqee_flow_tag;
	uint16be_t	mlcqee_wqe_counter;
	uint8_t		mlcqee_signature;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint8_t		mlcqe_opcode:4;
		uint8_t		mlcqe_rsvd5:3;
		uint8_t		mlcqe_owner:1;
#elif defined(_BIT_FIELDS_LTOH)
		uint8_t		mlcqe_owner:1;
		uint8_t		mlcqe_rsvd5:3;
		uint8_t		mlcqe_opcode:4;
#endif
	};
} mlxcx_completionq_error_ent_t;

typedef struct {
	uint8_t		mlcqe_tunnel_flags;
	uint8_t		mlcqe_rsvd[3];
	uint8_t		mlcqe_lro_flags;
	uint8_t		mlcqe_lro_min_ttl;
	uint16be_t	mlcqe_lro_tcp_win;
	uint32be_t	mlcqe_lro_ack_seq_num;
	uint32be_t	mlcqe_rx_hash_result;
	bits8_t		mlcqe_rx_hash_type;
	uint8_t		mlcqe_ml_path;
	uint8_t		mlcqe_rsvd2[2];
	uint16be_t	mlcqe_checksum;
	uint16be_t	mlcqe_slid_smac_lo;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint8_t		mlcqe_rsvd3:1;
		uint8_t		mlcqe_force_loopback:1;
		uint8_t		mlcqe_l3_hdr:2;
		uint8_t		mlcqe_sl_roce_pktype:4;
#elif defined(_BIT_FIELDS_LTOH)
		uint8_t		mlcqe_sl_roce_pktype:4;
		uint8_t		mlcqe_l3_hdr:2;
		uint8_t		mlcqe_force_loopback:1;
		uint8_t		mlcqe_rsvd3:1;
#endif
	};
	uint24be_t	mlcqe_rqpn;
	bits8_t		mlcqe_csflags;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint8_t		mlcqe_ip_frag:1;
		uint8_t		mlcqe_l4_hdr_type:3;
		uint8_t		mlcqe_l3_hdr_type:2;
		uint8_t		mlcqe_ip_ext_opts:1;
		uint8_t		mlcqe_cv:1;
#elif defined(_BIT_FIELDS_LTOH)
		uint8_t		mlcqe_cv:1;
		uint8_t		mlcqe_ip_ext_opts:1;
		uint8_t		mlcqe_l3_hdr_type:2;
		uint8_t		mlcqe_l4_hdr_type:3;
		uint8_t		mlcqe_ip_frag:1;
#endif
	};
	uint16be_t	mlcqe_up_cfi_vid;
	uint8_t		mlcqe_lro_num_seg;
	uint24be_t	mlcqe_user_index;
	uint32be_t	mlcqe_immediate;
	uint8_t		mlcqe_rsvd4[4];
	uint32be_t	mlcqe_byte_cnt;
	union {
		struct {
			uint32be_t	mlcqe_lro_timestamp_value;
			uint32be_t	mlcqe_lro_timestamp_echo;
		};
		uint64be_t	mlcqe_timestamp;
	};
	union {
		uint8_t		mlcqe_rx_drop_counter;
		uint8_t		mlcqe_send_wqe_opcode;
	};
	uint24be_t	mlcqe_flow_tag;
	uint16be_t	mlcqe_wqe_counter;
	uint8_t		mlcqe_signature;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint8_t		mlcqe_opcode:4;
		uint8_t		mlcqe_format:2;
		uint8_t		mlcqe_se:1;
		uint8_t		mlcqe_owner:1;
#elif defined(_BIT_FIELDS_LTOH)
		uint8_t		mlcqe_owner:1;
		uint8_t		mlcqe_se:1;
		uint8_t		mlcqe_format:2;
		uint8_t		mlcqe_opcode:4;
#endif
	};
} mlxcx_completionq_ent_t;

typedef struct {
	uint8_t			mlcqe_data[64];
	mlxcx_completionq_ent_t	mlcqe_ent;
} mlxcx_completionq_ent128_t;

typedef enum {
	MLXCX_WQE_OP_NOP		= 0x00,
	MLXCX_WQE_OP_SEND_INVALIDATE	= 0x01,
	MLXCX_WQE_OP_RDMA_W		= 0x08,
	MLXCX_WQE_OP_RDMA_W_IMMEDIATE	= 0x09,
	MLXCX_WQE_OP_SEND		= 0x0A,
	MLXCX_WQE_OP_SEND_IMMEDIATE	= 0x0B,
	MLXCX_WQE_OP_LSO		= 0x0E,
	MLXCX_WQE_OP_WAIT		= 0x0F,
	MLXCX_WQE_OP_RDMA_R		= 0x10,
} mlxcx_wqe_opcode_t;

#define	MLXCX_WQE_OCTOWORD	16
#define	MLXCX_SQE_MAX_DS	((1 << 6) - 1)
/*
 * Calculate the max number of address pointers in a single ethernet
 * send message. This is the remainder from MLXCX_SQE_MAX_DS
 * after accounting for the Control and Ethernet segements.
 */
#define	MLXCX_SQE_MAX_PTRS	(MLXCX_SQE_MAX_DS - \
	(sizeof (mlxcx_wqe_eth_seg_t) + sizeof (mlxcx_wqe_control_seg_t)) / \
	MLXCX_WQE_OCTOWORD)

typedef enum {
	MLXCX_SQE_FENCE_NONE		= 0x0,
	MLXCX_SQE_FENCE_WAIT_OTHERS	= 0x1,
	MLXCX_SQE_FENCE_START		= 0x2,
	MLXCX_SQE_FENCE_STRONG_ORDER	= 0x3,
	MLXCX_SQE_FENCE_START_WAIT	= 0x4
} mlxcx_sqe_fence_mode_t;

typedef enum {
	MLXCX_SQE_CQE_ON_EACH_ERROR	= 0x0,
	MLXCX_SQE_CQE_ON_FIRST_ERROR	= 0x1,
	MLXCX_SQE_CQE_ALWAYS		= 0x2,
	MLXCX_SQE_CQE_ALWAYS_PLUS_EQE	= 0x3
} mlxcx_sqe_completion_mode_t;

#define	MLXCX_SQE_SOLICITED		(1 << 1)
/* CSTYLED */
#define	MLXCX_SQE_FENCE_MODE		(bitdef_t){5, 0xe0}
/* CSTYLED */
#define	MLXCX_SQE_COMPLETION_MODE	(bitdef_t){2, 0x0c}

typedef struct {
	uint8_t		mlcs_opcode_mod;
	uint16be_t	mlcs_wqe_index;
	uint8_t		mlcs_opcode;
	uint24be_t	mlcs_qp_or_sq;
	uint8_t		mlcs_ds;
	uint8_t		mlcs_signature;
	uint8_t		mlcs_rsvd2[2];
	bits8_t		mlcs_flags;
	uint32be_t	mlcs_immediate;
} mlxcx_wqe_control_seg_t;

typedef enum {
	MLXCX_SQE_ETH_CSFLAG_L4_CHECKSUM		= 1 << 7,
	MLXCX_SQE_ETH_CSFLAG_L3_CHECKSUM		= 1 << 6,
	MLXCX_SQE_ETH_CSFLAG_L4_INNER_CHECKSUM		= 1 << 5,
	MLXCX_SQE_ETH_CSFLAG_L3_INNER_CHECKSUM		= 1 << 4,
} mlxcx_wqe_eth_flags_t;

/* CSTYLED */
#define	MLXCX_SQE_ETH_INLINE_HDR_SZ	(bitdef_t){0, 0x03ff}
#define	MLXCX_SQE_ETH_SZFLAG_VLAN	(1 << 15)
#define	MLXCX_MAX_INLINE_HEADERLEN	64

typedef struct {
	uint8_t		mles_rsvd[4];
	bits8_t		mles_csflags;
	uint8_t		mles_rsvd2[1];
	uint16_t	mles_mss;
	uint8_t		mles_rsvd3[4];
	bits16_t	mles_szflags;
	uint8_t		mles_inline_headers[18];
} mlxcx_wqe_eth_seg_t;

typedef struct {
	uint32be_t	mlds_byte_count;
	uint32be_t	mlds_lkey;
	uint64be_t	mlds_address;
} mlxcx_wqe_data_seg_t;

#define	MLXCX_SENDQ_STRIDE_SHIFT	6

typedef struct {
	mlxcx_wqe_control_seg_t		mlsqe_control;
	mlxcx_wqe_eth_seg_t		mlsqe_eth;
	mlxcx_wqe_data_seg_t		mlsqe_data[1];
} mlxcx_sendq_ent_t;

typedef struct {
	uint64be_t			mlsqbf_qwords[8];
} mlxcx_sendq_bf_t;

typedef struct {
	mlxcx_wqe_data_seg_t		mlsqe_data[4];
} mlxcx_sendq_extra_ent_t;

#define	MLXCX_RECVQ_STRIDE_SHIFT	7
/*
 * Each mlxcx_wqe_data_seg_t is 1<<4 bytes long (there's a CTASSERT to verify
 * this in mlxcx_cmd.c), so the number of pointers is 1 << (shift - 4).
 */
#define	MLXCX_RECVQ_MAX_PTRS		(1 << (MLXCX_RECVQ_STRIDE_SHIFT - 4))
typedef struct {
	mlxcx_wqe_data_seg_t		mlrqe_data[MLXCX_RECVQ_MAX_PTRS];
} mlxcx_recvq_ent_t;

/* CSTYLED */
#define MLXCX_CQ_ARM_CI			(bitdef_t){ .bit_shift = 0, \
						.bit_mask = 0x00ffffff }
/* CSTYLED */
#define	MLXCX_CQ_ARM_SEQ		(bitdef_t){ .bit_shift = 28, \
						.bit_mask = 0x30000000 }
#define	MLXCX_CQ_ARM_SOLICITED		(1 << 24)

typedef struct {
	uint8_t		mlcqd_rsvd;
	uint24be_t	mlcqd_update_ci;
	bits32_t	mlcqd_arm_ci;
} mlxcx_completionq_doorbell_t;

typedef struct {
	uint16be_t	mlwqd_rsvd;
	uint16be_t	mlwqd_recv_counter;
	uint16be_t	mlwqd_rsvd2;
	uint16be_t	mlwqd_send_counter;
} mlxcx_workq_doorbell_t;

#define	MLXCX_EQ_STATUS_OK		(0x0 << 4)
#define	MLXCX_EQ_STATUS_WRITE_FAILURE	(0xA << 4)

#define	MLXCX_EQ_OI			(1 << 1)
#define	MLXCX_EQ_EC			(1 << 2)

#define	MLXCX_EQ_ST_ARMED		0x9
#define	MLXCX_EQ_ST_FIRED		0xA

/* CSTYLED */
#define	MLXCX_EQ_LOG_PAGE_SIZE		(bitdef_t){ .bit_shift = 24, \
						.bit_mask = 0x1F000000 }

typedef struct {
	uint8_t		mleqc_status;
	uint8_t		mleqc_ecoi;
	uint8_t		mleqc_state;
	uint8_t		mleqc_rsvd[7];
	uint16be_t	mleqc_page_offset;
	uint8_t		mleqc_log_eq_size;
	uint24be_t	mleqc_uar_page;
	uint8_t		mleqc_rsvd3[7];
	uint8_t		mleqc_intr;
	uint32be_t	mleqc_log_page;
	uint8_t		mleqc_rsvd4[13];
	uint24be_t	mleqc_consumer_counter;
	uint8_t		mleqc_rsvd5;
	uint24be_t	mleqc_producer_counter;
	uint8_t		mleqc_rsvd6[16];
} mlxcx_eventq_ctx_t;

typedef enum {
	MLXCX_CQC_CQE_SIZE_64	= 0x0,
	MLXCX_CQC_CQE_SIZE_128	= 0x1,
} mlxcx_cqc_cqe_sz_t;

typedef enum {
	MLXCX_CQC_STATUS_OK		= 0x0,
	MLXCX_CQC_STATUS_OVERFLOW	= 0x9,
	MLXCX_CQC_STATUS_WRITE_FAIL	= 0xA,
	MLXCX_CQC_STATUS_INVALID	= 0xF
} mlxcx_cqc_status_t;

typedef enum {
	MLXCX_CQC_STATE_ARMED_SOLICITED	= 0x6,
	MLXCX_CQC_STATE_ARMED		= 0x9,
	MLXCX_CQC_STATE_FIRED		= 0xA
} mlxcx_cqc_state_t;

/* CSTYLED */
#define	MLXCX_CQ_CTX_STATUS		(bitdef_t){28, 0xf0000000}
/* CSTYLED */
#define	MLXCX_CQ_CTX_CQE_SZ		(bitdef_t){21, 0x00e00000}
/* CSTYLED */
#define	MLXCX_CQ_CTX_PERIOD_MODE	(bitdef_t){15, 0x00018000}
/* CSTYLED */
#define	MLXCX_CQ_CTX_MINI_CQE_FORMAT	(bitdef_t){12, 0x00003000}
/* CSTYLED */
#define	MLXCX_CQ_CTX_STATE		(bitdef_t){8,  0x00000f00}

typedef struct mlxcx_completionq_ctx {
	bits32_t	mlcqc_flags;

	uint8_t		mlcqc_rsvd4[4];

	uint8_t		mlcqc_rsvd5[2];
	uint16be_t	mlcqc_page_offset;

	uint8_t		mlcqc_log_cq_size;
	uint24be_t	mlcqc_uar_page;

	uint16be_t	mlcqc_cq_period;
	uint16be_t	mlcqc_cq_max_count;

	uint8_t		mlcqc_rsvd7[3];
	uint8_t		mlcqc_eqn;

	uint8_t		mlcqc_log_page_size;
	uint8_t		mlcqc_rsvd8[3];

	uint8_t		mlcqc_rsvd9[4];

	uint8_t		mlcqc_rsvd10;
	uint24be_t	mlcqc_last_notified_index;
	uint8_t		mlcqc_rsvd11;
	uint24be_t	mlcqc_last_solicit_index;
	uint8_t		mlcqc_rsvd12;
	uint24be_t	mlcqc_consumer_counter;
	uint8_t		mlcqc_rsvd13;
	uint24be_t	mlcqc_producer_counter;

	uint8_t		mlcqc_rsvd14[8];

	uint64be_t	mlcqc_dbr_addr;
} mlxcx_completionq_ctx_t;

typedef enum {
	MLXCX_WORKQ_TYPE_LINKED_LIST		= 0x0,
	MLXCX_WORKQ_TYPE_CYCLIC			= 0x1,
	MLXCX_WORKQ_TYPE_LINKED_LIST_STRIDING	= 0x2,
	MLXCX_WORKQ_TYPE_CYCLIC_STRIDING	= 0x3
} mlxcx_workq_ctx_type_t;

typedef enum {
	MLXCX_WORKQ_END_PAD_NONE		= 0x0,
	MLXCX_WORKQ_END_PAD_ALIGN		= 0x1
} mlxcx_workq_end_padding_t;

/* CSTYLED */
#define	MLXCX_WORKQ_CTX_TYPE			(bitdef_t){ \
						.bit_shift = 28, \
						.bit_mask = 0xf0000000 }
#define	MLXCX_WORKQ_CTX_SIGNATURE		(1 << 27)
#define	MLXCX_WORKQ_CTX_CD_SLAVE		(1 << 24)
/* CSTYLED */
#define	MLXCX_WORKQ_CTX_END_PADDING		(bitdef_t){ \
						.bit_shift = 25, \
						.bit_mask = 0x06000000 }

#define	MLXCX_WORKQ_CTX_MAX_ADDRESSES		128

typedef struct mlxcx_workq_ctx {
	bits32_t	mlwqc_flags;
	uint8_t		mlwqc_rsvd[2];
	uint16be_t	mlwqc_lwm;
	uint8_t		mlwqc_rsvd2;
	uint24be_t	mlwqc_pd;
	uint8_t		mlwqc_rsvd3;
	uint24be_t	mlwqc_uar_page;
	uint64be_t	mlwqc_dbr_addr;
	uint32be_t	mlwqc_hw_counter;
	uint32be_t	mlwqc_sw_counter;
	uint8_t		mlwqc_rsvd4;
	uint8_t		mlwqc_log_wq_stride;
	uint8_t		mlwqc_log_wq_pg_sz;
	uint8_t		mlwqc_log_wq_sz;
	uint8_t		mlwqc_rsvd5[2];
	bits16_t	mlwqc_strides;
	uint8_t		mlwqc_rsvd6[152];
	uint64be_t	mlwqc_pas[MLXCX_WORKQ_CTX_MAX_ADDRESSES];
} mlxcx_workq_ctx_t;

#define	MLXCX_RQ_FLAGS_RLKEY			(1UL << 31)
#define	MLXCX_RQ_FLAGS_SCATTER_FCS		(1 << 29)
#define	MLXCX_RQ_FLAGS_VLAN_STRIP_DISABLE	(1 << 28)
#define	MLXCX_RQ_FLAGS_FLUSH_IN_ERROR		(1 << 18)
/* CSTYLED */
#define	MLXCX_RQ_MEM_RQ_TYPE			(bitdef_t){ \
						.bit_shift = 24, \
						.bit_mask = 0x0f000000 }
/* CSTYLED */
#define	MLXCX_RQ_STATE				(bitdef_t){ \
						.bit_shift = 20, \
						.bit_mask = 0x00f00000 }

typedef struct mlxcx_rq_ctx {
	bits32_t	mlrqc_flags;
	uint8_t		mlrqc_rsvd;
	uint24be_t	mlrqc_user_index;
	uint8_t		mlrqc_rsvd2;
	uint24be_t	mlrqc_cqn;
	uint8_t		mlrqc_counter_set_id;
	uint8_t		mlrqc_rsvd3[4];
	uint24be_t	mlrqc_rmpn;
	uint8_t		mlrqc_rsvd4[28];
	mlxcx_workq_ctx_t	mlrqc_wq;
} mlxcx_rq_ctx_t;

#define	MLXCX_SQ_FLAGS_RLKEY			(1UL << 31)
#define	MLXCX_SQ_FLAGS_CD_MASTER		(1 << 30)
#define	MLXCX_SQ_FLAGS_FRE			(1 << 29)
#define	MLXCX_SQ_FLAGS_FLUSH_IN_ERROR		(1 << 28)
#define	MLXCX_SQ_FLAGS_ALLOW_MULTI_PKT		(1 << 27)
#define	MLXCX_SQ_FLAGS_REG_UMR			(1 << 19)

typedef enum {
	MLXCX_ETH_CAP_INLINE_REQUIRE_L2		= 0,
	MLXCX_ETH_CAP_INLINE_VPORT_CTX		= 1,
	MLXCX_ETH_CAP_INLINE_NOT_REQUIRED	= 2
} mlxcx_eth_cap_inline_mode_t;

typedef enum {
	MLXCX_ETH_INLINE_NONE			= 0,
	MLXCX_ETH_INLINE_L2			= 1,
	MLXCX_ETH_INLINE_L3			= 2,
	MLXCX_ETH_INLINE_L4			= 3,
	MLXCX_ETH_INLINE_INNER_L2		= 5,
	MLXCX_ETH_INLINE_INNER_L3		= 6,
	MLXCX_ETH_INLINE_INNER_L4		= 7
} mlxcx_eth_inline_mode_t;

/* CSTYLED */
#define	MLXCX_SQ_MIN_WQE_INLINE			(bitdef_t){ \
						.bit_shift = 24, \
						.bit_mask = 0x07000000 }
/* CSTYLED */
#define	MLXCX_SQ_STATE				(bitdef_t){ \
						.bit_shift = 20, \
						.bit_mask = 0x00f00000 }

typedef struct mlxcx_sq_ctx {
	bits32_t	mlsqc_flags;
	uint8_t		mlsqc_rsvd;
	uint24be_t	mlsqc_user_index;
	uint8_t		mlsqc_rsvd2;
	uint24be_t	mlsqc_cqn;
	uint8_t		mlsqc_rsvd3[18];
	uint16be_t	mlsqc_packet_pacing_rate_limit_index;
	uint16be_t	mlsqc_tis_lst_sz;
	uint8_t		mlsqc_rsvd4[11];
	uint24be_t	mlsqc_tis_num;
	mlxcx_workq_ctx_t	mlsqc_wq;
} mlxcx_sq_ctx_t;

#define	MLXCX_NIC_VPORT_CTX_MAX_ADDRESSES	64

typedef enum {
	MLXCX_VPORT_PROMISC_UCAST	= 1 << 15,
	MLXCX_VPORT_PROMISC_MCAST	= 1 << 14,
	MLXCX_VPORT_PROMISC_ALL		= 1 << 13
} mlxcx_nic_vport_ctx_promisc_t;

#define	MLXCX_VPORT_LIST_TYPE_MASK	0x07
#define	MLXCX_VPORT_LIST_TYPE_SHIFT	0

/* CSTYLED */
#define	MLXCX_VPORT_CTX_MIN_WQE_INLINE	(bitdef_t){56, 0x0700000000000000}

typedef struct {
	bits64_t	mlnvc_flags;
	uint8_t		mlnvc_rsvd[28];
	uint8_t		mlnvc_rsvd2[2];
	uint16be_t	mlnvc_mtu;
	uint64be_t	mlnvc_system_image_guid;
	uint64be_t	mlnvc_port_guid;
	uint64be_t	mlnvc_node_guid;
	uint8_t		mlnvc_rsvd3[40];
	uint16be_t	mlnvc_qkey_violation_counter;
	uint8_t		mlnvc_rsvd4[2];
	uint8_t		mlnvc_rsvd5[132];
	bits16_t	mlnvc_promisc_list_type;
	uint16be_t	mlnvc_allowed_list_size;
	uint8_t		mlnvc_rsvd6[2];
	uint8_t		mlnvc_permanent_address[6];
	uint8_t		mlnvc_rsvd7[4];
	uint64be_t	mlnvc_address[MLXCX_NIC_VPORT_CTX_MAX_ADDRESSES];
} mlxcx_nic_vport_ctx_t;

typedef struct {
	uint8_t		mlftc_flags;
	uint8_t		mlftc_level;
	uint8_t		mlftc_rsvd;
	uint8_t		mlftc_log_size;
	uint8_t		mlftc_rsvd2;
	uint24be_t	mlftc_table_miss_id;
	uint8_t		mlftc_rsvd3[4];
	uint8_t		mlftc_rsvd4[28];
} mlxcx_flow_table_ctx_t;

/* CSTYLED */
#define	MLXCX_FLOW_HDR_FIRST_VID		(bitdef_t){0, 0x07ff}
/* CSTYLED */
#define	MLXCX_FLOW_HDR_FIRST_PRIO		(bitdef_t){13,0x7000}
#define	MLXCX_FLOW_HDR_FIRST_CFI		(1 << 12)

#define	MLXCX_FLOW_HDR_IP_DSCP_SHIFT		18
#define	MLXCX_FLOW_HDR_IP_DSCP_MASK		0xfc0000
#define	MLXCX_FLOW_HDR_IP_ECN_SHIFT		16
#define	MLXCX_FLOW_HDR_IP_ECN_MASK		0x030000
#define	MLXCX_FLOW_HDR_CVLAN_TAG		(1 << 15)
#define	MLXCX_FLOW_HDR_SVLAN_TAG		(1 << 14)
#define	MLXCX_FLOW_HDR_FRAG			(1 << 13)
/* CSTYLED */
#define	MLXCX_FLOW_HDR_IP_VERSION		(bitdef_t){ \
						.bit_shift = 9, \
						.bit_mask = 0x001e00 }
/* CSTYLED */
#define	MLXCX_FLOW_HDR_TCP_FLAGS		(bitdef_t){ \
						.bit_shift = 0, \
						.bit_mask = 0x0001ff }

typedef struct {
	uint8_t		mlfh_smac[6];
	uint16be_t	mlfh_ethertype;
	uint8_t		mlfh_dmac[6];
	bits16_t	mlfh_first_vid_flags;
	uint8_t		mlfh_ip_protocol;
	bits24_t	mlfh_tcp_ip_flags;
	uint16be_t	mlfh_tcp_sport;
	uint16be_t	mlfh_tcp_dport;
	uint8_t		mlfh_rsvd[3];
	uint8_t		mlfh_ip_ttl_hoplimit;
	uint16be_t	mlfh_udp_sport;
	uint16be_t	mlfh_udp_dport;
	uint8_t		mlfh_src_ip[16];
	uint8_t		mlfh_dst_ip[16];
} mlxcx_flow_header_match_t;

typedef struct {
	uint8_t		mlfp_rsvd;
	uint24be_t	mlfp_source_sqn;
	uint8_t		mlfp_rsvd2[2];
	uint16be_t	mlfp_source_port;
	bits16_t	mlfp_outer_second_vid_flags;
	bits16_t	mlfp_inner_second_vid_flags;
	bits16_t	mlfp_vlan_flags;
	uint16be_t	mlfp_gre_protocol;
	uint32be_t	mlfp_gre_key;
	uint24be_t	mlfp_vxlan_vni;
	uint8_t		mlfp_rsvd3;
	uint8_t		mlfp_rsvd4[4];
	uint8_t		mlfp_rsvd5;
	uint24be_t	mlfp_outer_ipv6_flow_label;
	uint8_t		mlfp_rsvd6;
	uint24be_t	mlfp_inner_ipv6_flow_label;
	uint8_t		mlfp_rsvd7[28];
} mlxcx_flow_params_match_t;

typedef struct {
	mlxcx_flow_header_match_t	mlfm_outer_headers;
	mlxcx_flow_params_match_t	mlfm_misc_parameters;
	mlxcx_flow_header_match_t	mlfm_inner_headers;
	uint8_t				mlfm_rsvd[320];
} mlxcx_flow_match_t;

#define	MLXCX_FLOW_MAX_DESTINATIONS	64
typedef enum {
	MLXCX_FLOW_DEST_VPORT		= 0x0,
	MLXCX_FLOW_DEST_FLOW_TABLE	= 0x1,
	MLXCX_FLOW_DEST_TIR		= 0x2,
	MLXCX_FLOW_DEST_QP		= 0x3
} mlxcx_flow_destination_type_t;

typedef struct {
	uint8_t		mlfd_destination_type;
	uint24be_t	mlfd_destination_id;
	uint8_t		mlfd_rsvd[4];
} mlxcx_flow_dest_t;

typedef enum {
	MLXCX_FLOW_ACTION_ALLOW		= 1 << 0,
	MLXCX_FLOW_ACTION_DROP		= 1 << 1,
	MLXCX_FLOW_ACTION_FORWARD	= 1 << 2,
	MLXCX_FLOW_ACTION_COUNT		= 1 << 3,
	MLXCX_FLOW_ACTION_ENCAP		= 1 << 4,
	MLXCX_FLOW_ACTION_DECAP		= 1 << 5
} mlxcx_flow_action_t;

typedef struct {
	uint8_t		mlfec_rsvd[4];
	uint32be_t	mlfec_group_id;
	uint8_t		mlfec_rsvd2;
	uint24be_t	mlfec_flow_tag;
	uint8_t		mlfec_rsvd3[2];
	uint16be_t	mlfec_action;
	uint8_t		mlfec_rsvd4;
	uint24be_t	mlfec_destination_list_size;
	uint8_t		mlfec_rsvd5;
	uint24be_t	mlfec_flow_counter_list_size;
	uint32be_t	mlfec_encap_id;
	uint8_t		mlfec_rsvd6[36];
	mlxcx_flow_match_t	mlfec_match_value;
	uint8_t		mlfec_rsvd7[192];
	mlxcx_flow_dest_t	mlfec_destination[MLXCX_FLOW_MAX_DESTINATIONS];
} mlxcx_flow_entry_ctx_t;

/* CSTYLED */
#define	MLXCX_TIR_CTX_DISP_TYPE		(bitdef_t){ 4, 0xf0 }
typedef enum {
	MLXCX_TIR_DIRECT	= 0x0,
	MLXCX_TIR_INDIRECT	= 0x1,
} mlxcx_tir_type_t;

/* CSTYLED */
#define	MLXCX_TIR_LRO_TIMEOUT		(bitdef_t){ 12, 0x0ffff000 }
/* CSTYLED */
#define	MLXCX_TIR_LRO_ENABLE_MASK	(bitdef_t){ 8,  0x00000f00 }
/* CSTYLED */
#define	MLXCX_TIR_LRO_MAX_MSG_SZ	(bitdef_t){ 0,  0x000000ff }

/* CSTYLED */
#define	MLXCX_TIR_RX_HASH_FN		(bitdef_t){ 4, 0xf0 }
typedef enum {
	MLXCX_TIR_HASH_NONE	= 0x0,
	MLXCX_TIR_HASH_XOR8	= 0x1,
	MLXCX_TIR_HASH_TOEPLITZ	= 0x2
} mlxcx_tir_hash_fn_t;
#define	MLXCX_TIR_LB_UNICAST		(1 << 24)
#define	MLXCX_TIR_LB_MULTICAST		(1 << 25)

/* CSTYLED */
#define	MLXCX_RX_HASH_L3_TYPE		(bitdef_t){ 31, 0x80000000 }
typedef enum {
	MLXCX_RX_HASH_L3_IPv4	= 0,
	MLXCX_RX_HASH_L3_IPv6	= 1
} mlxcx_tir_rx_hash_l3_type_t;
/* CSTYLED */
#define	MLXCX_RX_HASH_L4_TYPE		(bitdef_t){ 30, 0x40000000 }
typedef enum {
	MLXCX_RX_HASH_L4_TCP	= 0,
	MLXCX_RX_HASH_L4_UDP	= 1
} mlxcx_tir_rx_hash_l4_type_t;
/* CSTYLED */
#define	MLXCX_RX_HASH_FIELDS		(bitdef_t){ 0,  0x3fffffff }
typedef enum {
	MLXCX_RX_HASH_SRC_IP		= 1 << 0,
	MLXCX_RX_HASH_DST_IP		= 1 << 1,
	MLXCX_RX_HASH_L4_SPORT		= 1 << 2,
	MLXCX_RX_HASH_L4_DPORT		= 1 << 3,
	MLXCX_RX_HASH_IPSEC_SPI		= 1 << 4
} mlxcx_tir_rx_hash_fields_t;

typedef struct {
	uint8_t		mltirc_rsvd[4];
	bits8_t		mltirc_disp_type;
	uint8_t		mltirc_rsvd2[11];
	bits32_t	mltirc_lro;
	uint8_t		mltirc_rsvd3[9];
	uint24be_t	mltirc_inline_rqn;
	bits8_t		mltirc_flags;
	uint24be_t	mltirc_indirect_table;
	bits8_t		mltirc_hash_lb;
	uint24be_t	mltirc_transport_domain;
	uint8_t		mltirc_rx_hash_toeplitz_key[40];
	bits32_t	mltirc_rx_hash_fields_outer;
	bits32_t	mltirc_rx_hash_fields_inner;
	uint8_t		mltirc_rsvd4[152];
} mlxcx_tir_ctx_t;

typedef struct {
	uint8_t		mltisc_rsvd;
	uint8_t		mltisc_prio_or_sl;
	uint8_t		mltisc_rsvd2[35];
	uint24be_t	mltisc_transport_domain;
	uint8_t		mltisc_rsvd3[120];
} mlxcx_tis_ctx_t;

#define	MLXCX_RQT_MAX_RQ_REFS		64

typedef struct {
	uint8_t		mlrqtr_rsvd;
	uint24be_t	mlrqtr_rqn;
} mlxcx_rqtable_rq_ref_t;

typedef struct {
	uint8_t		mlrqtc_rsvd[22];
	uint16be_t	mlrqtc_max_size;
	uint8_t		mlrqtc_rsvd2[2];
	uint16be_t	mlrqtc_actual_size;
	uint8_t		mlrqtc_rsvd3[212];
	mlxcx_rqtable_rq_ref_t	mlrqtc_rqref[MLXCX_RQT_MAX_RQ_REFS];
} mlxcx_rqtable_ctx_t;

#pragma pack()

typedef enum {
	MLXCX_EVENT_COMPLETION		= 0x00,
	MLXCX_EVENT_PATH_MIGRATED	= 0x01,
	MLXCX_EVENT_COMM_ESTABLISH	= 0x02,
	MLXCX_EVENT_SENDQ_DRAIN		= 0x03,
	MLXCX_EVENT_LAST_WQE		= 0x13,
	MLXCX_EVENT_SRQ_LIMIT		= 0x14,
	MLXCX_EVENT_DCT_ALL_CLOSED	= 0x1C,
	MLXCX_EVENT_DCT_ACCKEY_VIOL	= 0x1D,
	MLXCX_EVENT_CQ_ERROR		= 0x04,
	MLXCX_EVENT_WQ_CATASTROPHE	= 0x05,
	MLXCX_EVENT_PATH_MIGRATE_FAIL	= 0x07,
	MLXCX_EVENT_PAGE_FAULT		= 0x0C,
	MLXCX_EVENT_WQ_INVALID_REQ	= 0x10,
	MLXCX_EVENT_WQ_ACCESS_VIOL	= 0x11,
	MLXCX_EVENT_SRQ_CATASTROPHE	= 0x12,
	MLXCX_EVENT_INTERNAL_ERROR	= 0x08,
	MLXCX_EVENT_PORT_STATE		= 0x09,
	MLXCX_EVENT_GPIO		= 0x15,
	MLXCX_EVENT_PORT_MODULE		= 0x16,
	MLXCX_EVENT_TEMP_WARNING	= 0x17,
	MLXCX_EVENT_REMOTE_CONFIG	= 0x19,
	MLXCX_EVENT_DCBX_CHANGE		= 0x1E,
	MLXCX_EVENT_DOORBELL_CONGEST	= 0x1A,
	MLXCX_EVENT_STALL_VL		= 0x1B,
	MLXCX_EVENT_CMD_COMPLETION	= 0x0A,
	MLXCX_EVENT_PAGE_REQUEST	= 0x0B,
	MLXCX_EVENT_NIC_VPORT		= 0x0D,
	MLXCX_EVENT_EC_PARAMS_CHANGE	= 0x0E,
	MLXCX_EVENT_XRQ_ERROR		= 0x18
} mlxcx_event_t;

typedef enum {
	MLXCX_CMD_R_OK			= 0x00,
	MLXCX_CMD_R_INTERNAL_ERR	= 0x01,
	MLXCX_CMD_R_BAD_OP		= 0x02,
	MLXCX_CMD_R_BAD_PARAM		= 0x03,
	MLXCX_CMD_R_BAD_SYS_STATE	= 0x04,
	MLXCX_CMD_R_BAD_RESOURCE	= 0x05,
	MLXCX_CMD_R_RESOURCE_BUSY	= 0x06,
	MLXCX_CMD_R_EXCEED_LIM		= 0x08,
	MLXCX_CMD_R_BAD_RES_STATE	= 0x09,
	MLXCX_CMD_R_BAD_INDEX		= 0x0a,
	MLXCX_CMD_R_NO_RESOURCES	= 0x0f,
	MLXCX_CMD_R_BAD_INPUT_LEN	= 0x50,
	MLXCX_CMD_R_BAD_OUTPUT_LEN	= 0x51,
	MLXCX_CMD_R_BAD_RESOURCE_STATE	= 0x10,
	MLXCX_CMD_R_BAD_PKT		= 0x30,
	MLXCX_CMD_R_BAD_SIZE		= 0x40,
	MLXCX_CMD_R_TIMEOUT		= 0xFF
} mlxcx_cmd_ret_t;

typedef enum {
	MLXCX_OP_QUERY_HCA_CAP = 0x100,
	MLXCX_OP_QUERY_ADAPTER = 0x101,
	MLXCX_OP_INIT_HCA = 0x102,
	MLXCX_OP_TEARDOWN_HCA = 0x103,
	MLXCX_OP_ENABLE_HCA = 0x104,
	MLXCX_OP_DISABLE_HCA = 0x105,
	MLXCX_OP_QUERY_PAGES = 0x107,
	MLXCX_OP_MANAGE_PAGES = 0x108,
	MLXCX_OP_SET_HCA_CAP = 0x109,
	MLXCX_OP_QUERY_ISSI = 0x10A,
	MLXCX_OP_SET_ISSI = 0x10B,
	MLXCX_OP_SET_DRIVER_VERSION = 0x10D,
	MLXCX_OP_QUERY_OTHER_HCA_CAP = 0x10E,
	MLXCX_OP_MODIFY_OTHER_HCA_CAP = 0x10F,
	MLXCX_OP_SET_TUNNELED_OPERATIONS = 0x110,
	MLXCX_OP_CREATE_MKEY = 0x200,
	MLXCX_OP_QUERY_MKEY = 0x201,
	MLXCX_OP_DESTROY_MKEY = 0x202,
	MLXCX_OP_QUERY_SPECIAL_CONTEXTS = 0x203,
	MLXCX_OP_PAGE_FAULT_RESUME = 0x204,
	MLXCX_OP_CREATE_EQ = 0x301,
	MLXCX_OP_DESTROY_EQ = 0x302,
	MLXCX_OP_QUERY_EQ = 0x303,
	MLXCX_OP_GEN_EQE = 0x304,
	MLXCX_OP_CREATE_CQ = 0x400,
	MLXCX_OP_DESTROY_CQ = 0x401,
	MLXCX_OP_QUERY_CQ = 0x402,
	MLXCX_OP_MODIFY_CQ = 0x403,
	MLXCX_OP_CREATE_QP = 0x500,
	MLXCX_OP_DESTROY_QP = 0x501,
	MLXCX_OP_RST2INIT_QP = 0x502,
	MLXCX_OP_INIT2RTR_QP = 0x503,
	MLXCX_OP_RTR2RTS_QP = 0x504,
	MLXCX_OP_RTS2RTS_QP = 0x505,
	MLXCX_OP_SQERR2RTS_QP = 0x506,
	MLXCX_OP__2ERR_QP = 0x507,
	MLXCX_OP__2RST_QP = 0x50A,
	MLXCX_OP_QUERY_QP = 0x50B,
	MLXCX_OP_SQD_RTS_QP = 0x50C,
	MLXCX_OP_INIT2INIT_QP = 0x50E,
	MLXCX_OP_CREATE_PSV = 0x600,
	MLXCX_OP_DESTROY_PSV = 0x601,
	MLXCX_OP_CREATE_SRQ = 0x700,
	MLXCX_OP_DESTROY_SRQ = 0x701,
	MLXCX_OP_QUERY_SRQ = 0x702,
	MLXCX_OP_ARM_RQ = 0x703,
	MLXCX_OP_CREATE_XRC_SRQ = 0x705,
	MLXCX_OP_DESTROY_XRC_SRQ = 0x706,
	MLXCX_OP_QUERY_XRC_SRQ = 0x707,
	MLXCX_OP_ARM_XRC_SRQ = 0x708,
	MLXCX_OP_CREATE_DCT = 0x710,
	MLXCX_OP_DESTROY_DCT = 0x711,
	MLXCX_OP_DRAIN_DCT = 0x712,
	MLXCX_OP_QUERY_DCT = 0x713,
	MLXCX_OP_ARM_DCT_FOR_KEY_VIOLATION = 0x714,
	MLXCX_OP_CREATE_XRQ = 0x717,
	MLXCX_OP_DESTROY_XRQ = 0x718,
	MLXCX_OP_QUERY_XRQ = 0x719,
	MLXCX_OP_CREATE_NVMF_BACKEND_CONTROLLER = 0x720,
	MLXCX_OP_DESTROY_NVMF_BACKEND_CONTROLLER = 0x721,
	MLXCX_OP_QUERY_NVMF_BACKEND_CONTROLLER = 0x722,
	MLXCX_OP_ATTACH_NVMF_NAMESPACE = 0x723,
	MLXCX_OP_DETACH_NVMF_NAMESPACE = 0x724,
	MLXCX_OP_QUERY_XRQ_DC_PARAMS_ENTRY = 0x725,
	MLXCX_OP_SET_XRQ_DC_PARAMS_ENTRY = 0x726,
	MLXCX_OP_QUERY_XRQ_ERROR_PARAMS = 0x727,
	MLXCX_OP_QUERY_VPORT_STATE = 0x750,
	MLXCX_OP_MODIFY_VPORT_STATE = 0x751,
	MLXCX_OP_QUERY_ESW_VPORT_CONTEXT = 0x752,
	MLXCX_OP_MODIFY_ESW_VPORT_CONTEXT = 0x753,
	MLXCX_OP_QUERY_NIC_VPORT_CONTEXT = 0x754,
	MLXCX_OP_MODIFY_NIC_VPORT_CONTEXT = 0x755,
	MLXCX_OP_QUERY_ROCE_ADDRESS = 0x760,
	MLXCX_OP_SET_ROCE_ADDRESS = 0x761,
	MLXCX_OP_QUERY_HCA_VPORT_CONTEXT = 0x762,
	MLXCX_OP_MODIFY_HCA_VPORT_CONTEXT = 0x763,
	MLXCX_OP_QUERY_HCA_VPORT_GID = 0x764,
	MLXCX_OP_QUERY_HCA_VPORT_PKEY = 0x765,
	MLXCX_OP_QUERY_VPORT_COUNTER = 0x770,
	MLXCX_OP_ALLOC_Q_COUNTER = 0x771,
	MLXCX_OP_DEALLOC_Q_COUNTER = 0x772,
	MLXCX_OP_QUERY_Q_COUNTER = 0x773,
	MLXCX_OP_SET_PP_RATE_LIMIT = 0x780,
	MLXCX_OP_QUERY_PP_RATE_LIMIT = 0x781,
	MLXCX_OP_ALLOC_PD = 0x800,
	MLXCX_OP_DEALLOC_PD = 0x801,
	MLXCX_OP_ALLOC_UAR = 0x802,
	MLXCX_OP_DEALLOC_UAR = 0x803,
	MLXCX_OP_CONFIG_INT_MODERATION = 0x804,
	MLXCX_OP_ACCESS_REG = 0x805,
	MLXCX_OP_ATTACH_TO_MCG = 0x806,
	MLXCX_OP_DETACH_FROM_MCG = 0x807,
	MLXCX_OP_MAD_IFC = 0x50D,
	MLXCX_OP_QUERY_MAD_DEMUX = 0x80B,
	MLXCX_OP_SET_MAD_DEMUX = 0x80C,
	MLXCX_OP_NOP = 0x80D,
	MLXCX_OP_ALLOC_XRCD = 0x80E,
	MLXCX_OP_DEALLOC_XRCD = 0x80F,
	MLXCX_OP_ALLOC_TRANSPORT_DOMAIN = 0x816,
	MLXCX_OP_DEALLOC_TRANSPORT_DOMAIN = 0x817,
	MLXCX_OP_QUERY_CONG_STATUS = 0x822,
	MLXCX_OP_MODIFY_CONG_STATUS = 0x823,
	MLXCX_OP_QUERY_CONG_PARAMS = 0x824,
	MLXCX_OP_MODIFY_CONG_PARAMS = 0x825,
	MLXCX_OP_QUERY_CONG_STATISTICS = 0x826,
	MLXCX_OP_ADD_VXLAN_UDP_DPORT = 0x827,
	MLXCX_OP_DELETE_VXLAN_UDP_DPORT = 0x828,
	MLXCX_OP_SET_L2_TABLE_ENTRY = 0x829,
	MLXCX_OP_QUERY_L2_TABLE_ENTRY = 0x82A,
	MLXCX_OP_DELETE_L2_TABLE_ENTRY = 0x82B,
	MLXCX_OP_SET_WOL_ROL = 0x830,
	MLXCX_OP_QUERY_WOL_ROL = 0x831,
	MLXCX_OP_CREATE_TIR = 0x900,
	MLXCX_OP_MODIFY_TIR = 0x901,
	MLXCX_OP_DESTROY_TIR = 0x902,
	MLXCX_OP_QUERY_TIR = 0x903,
	MLXCX_OP_CREATE_SQ = 0x904,
	MLXCX_OP_MODIFY_SQ = 0x905,
	MLXCX_OP_DESTROY_SQ = 0x906,
	MLXCX_OP_QUERY_SQ = 0x907,
	MLXCX_OP_CREATE_RQ = 0x908,
	MLXCX_OP_MODIFY_RQ = 0x909,
	MLXCX_OP_DESTROY_RQ = 0x90A,
	MLXCX_OP_QUERY_RQ = 0x90B,
	MLXCX_OP_CREATE_RMP = 0x90C,
	MLXCX_OP_MODIFY_RMP = 0x90D,
	MLXCX_OP_DESTROY_RMP = 0x90E,
	MLXCX_OP_QUERY_RMP = 0x90F,
	MLXCX_OP_CREATE_TIS = 0x912,
	MLXCX_OP_MODIFY_TIS = 0x913,
	MLXCX_OP_DESTROY_TIS = 0x914,
	MLXCX_OP_QUERY_TIS = 0x915,
	MLXCX_OP_CREATE_RQT = 0x916,
	MLXCX_OP_MODIFY_RQT = 0x917,
	MLXCX_OP_DESTROY_RQT = 0x918,
	MLXCX_OP_QUERY_RQT = 0x919,
	MLXCX_OP_SET_FLOW_TABLE_ROOT = 0x92f,
	MLXCX_OP_CREATE_FLOW_TABLE = 0x930,
	MLXCX_OP_DESTROY_FLOW_TABLE = 0x931,
	MLXCX_OP_QUERY_FLOW_TABLE = 0x932,
	MLXCX_OP_CREATE_FLOW_GROUP = 0x933,
	MLXCX_OP_DESTROY_FLOW_GROUP = 0x934,
	MLXCX_OP_QUERY_FLOW_GROUP = 0x935,
	MLXCX_OP_SET_FLOW_TABLE_ENTRY = 0x936,
	MLXCX_OP_QUERY_FLOW_TABLE_ENTRY = 0x937,
	MLXCX_OP_DELETE_FLOW_TABLE_ENTRY = 0x938,
	MLXCX_OP_ALLOC_FLOW_COUNTER = 0x939,
	MLXCX_OP_DEALLOC_FLOW_COUNTER = 0x93a,
	MLXCX_OP_QUERY_FLOW_COUNTER = 0x93b,
	MLXCX_OP_MODIFY_FLOW_TABLE = 0x93c,
	MLXCX_OP_ALLOC_ENCAP_HEADER = 0x93d,
	MLXCX_OP_DEALLOC_ENCAP_HEADER = 0x93e,
	MLXCX_OP_QUERY_ENCAP_HEADER = 0x93f
} mlxcx_cmd_op_t;

/*
 * Definitions for relevant commands
 */
#pragma pack(1)
typedef struct {
	uint16be_t	mci_opcode;
	uint8_t		mci_rsvd[4];
	uint16be_t	mci_op_mod;
} mlxcx_cmd_in_t;

typedef struct {
	uint8_t		mco_status;
	uint8_t		mco_rsvd[3];
	uint32be_t	mco_syndrome;
} mlxcx_cmd_out_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_enable_hca_head;
	uint8_t		mlxi_enable_hca_rsvd[2];
	uint16be_t	mlxi_enable_hca_func;
	uint8_t		mlxi_enable_hca_rsvd1[4];
} mlxcx_cmd_enable_hca_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_enable_hca_head;
	uint8_t		mlxo_enable_hca_rsvd[8];
} mlxcx_cmd_enable_hca_out_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_disable_hca_head;
	uint8_t		mlxi_disable_hca_rsvd[2];
	uint16be_t	mlxi_disable_hca_func;
	uint8_t		mlxi_disable_hca_rsvd1[4];
} mlxcx_cmd_disable_hca_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_disable_hca_head;
	uint8_t		mlxo_disable_hca_rsvd[8];
} mlxcx_cmd_disable_hca_out_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_query_issi_head;
	uint8_t		mlxi_query_issi_rsvd[8];
} mlxcx_cmd_query_issi_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_query_issi_head;
	uint8_t		mlxo_query_issi_rsv[2];
	uint16be_t	mlxo_query_issi_current;
	uint8_t		mlxo_query_issi_rsvd1[20];
	/*
	 * To date we only support version 1 of the ISSI. The last byte has the
	 * ISSI data that we care about, therefore we phrase the struct this
	 * way.
	 */
	uint8_t		mlxo_query_issi_rsvd2[79];
	uint8_t		mlxo_supported_issi;
} mlxcx_cmd_query_issi_out_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_set_issi_head;
	uint8_t		mlxi_set_issi_rsvd[2];
	uint16be_t	mlxi_set_issi_current;
	uint8_t		mlxi_set_iss_rsvd1[4];
} mlxcx_cmd_set_issi_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_set_issi_head;
	uint8_t		mlxo_set_issi_rsvd[8];
} mlxcx_cmd_set_issi_out_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_init_hca_head;
	uint8_t		mlxi_init_hca_rsvd[8];
} mlxcx_cmd_init_hca_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_init_hca_head;
	uint8_t		mlxo_init_hca_rsvd[8];
} mlxcx_cmd_init_hca_out_t;

#define	MLXCX_TEARDOWN_HCA_GRACEFUL	0x00
#define	MLXCX_TEARDOWN_HCA_FORCE	0x01

typedef struct {
	mlxcx_cmd_in_t	mlxi_teardown_hca_head;
	uint8_t		mlxi_teardown_hca_rsvd[2];
	uint16be_t	mlxi_teardown_hca_profile;
	uint8_t		mlxi_teardown_hca_rsvd1[4];
} mlxcx_cmd_teardown_hca_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_teardown_hca_head;
	uint8_t		mlxo_teardown_hca_rsvd[7];
	uint8_t		mlxo_teardown_hca_state;
} mlxcx_cmd_teardown_hca_out_t;

#define	MLXCX_QUERY_PAGES_OPMOD_BOOT	0x01
#define	MLXCX_QUERY_PAGES_OPMOD_INIT	0x02
#define	MLXCX_QUERY_PAGES_OPMOD_REGULAR	0x03

typedef struct {
	mlxcx_cmd_in_t	mlxi_query_pages_head;
	uint8_t		mlxi_query_pages_rsvd[2];
	uint16be_t	mlxi_query_pages_func;
	uint8_t		mlxi_query_pages_rsvd1[4];
} mlxcx_cmd_query_pages_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_query_pages_head;
	uint8_t		mlxo_query_pages_rsvd[2];
	uint16be_t	mlxo_query_pages_func;
	uint32be_t	mlxo_query_pages_npages;
} mlxcx_cmd_query_pages_out_t;

#define	MLXCX_MANAGE_PAGES_OPMOD_ALLOC_FAIL	0x00
#define	MLXCX_MANAGE_PAGES_OPMOD_GIVE_PAGES	0x01
#define	MLXCX_MANAGE_PAGES_OPMOD_RETURN_PAGES	0x02

/*
 * This is an artificial limit that we're imposing on our actions.
 */
#define	MLXCX_MANAGE_PAGES_MAX_PAGES	512

typedef struct {
	mlxcx_cmd_in_t	mlxi_manage_pages_head;
	uint8_t		mlxi_manage_pages_rsvd[2];
	uint16be_t	mlxi_manage_pages_func;
	uint32be_t	mlxi_manage_pages_npages;
	uint64be_t	mlxi_manage_pages_pas[MLXCX_MANAGE_PAGES_MAX_PAGES];
} mlxcx_cmd_manage_pages_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_manage_pages_head;
	uint32be_t	mlxo_manage_pages_npages;
	uint8_t		mlxo_manage_pages_rsvd[4];
	uint64be_t	mlxo_manage_pages_pas[MLXCX_MANAGE_PAGES_MAX_PAGES];
} mlxcx_cmd_manage_pages_out_t;

typedef enum {
	MLXCX_HCA_CAP_MODE_MAX		= 0x0,
	MLXCX_HCA_CAP_MODE_CURRENT	= 0x1
} mlxcx_hca_cap_mode_t;

typedef enum {
	MLXCX_HCA_CAP_GENERAL		= 0x0,
	MLXCX_HCA_CAP_ETHERNET		= 0x1,
	MLXCX_HCA_CAP_ODP		= 0x2,
	MLXCX_HCA_CAP_ATOMIC		= 0x3,
	MLXCX_HCA_CAP_ROCE		= 0x4,
	MLXCX_HCA_CAP_IPoIB		= 0x5,
	MLXCX_HCA_CAP_NIC_FLOW		= 0x7,
	MLXCX_HCA_CAP_ESWITCH_FLOW	= 0x8,
	MLXCX_HCA_CAP_ESWITCH		= 0x9,
	MLXCX_HCA_CAP_VECTOR		= 0xb,
	MLXCX_HCA_CAP_QoS		= 0xc,
	MLXCX_HCA_CAP_NVMEoF		= 0xe
} mlxcx_hca_cap_type_t;

typedef enum {
	MLXCX_CAP_GENERAL_PORT_TYPE_IB		= 0x0,
	MLXCX_CAP_GENERAL_PORT_TYPE_ETHERNET	= 0x1,
} mlxcx_hca_cap_general_port_type_t;

typedef enum {
	MLXCX_CAP_GENERAL_FLAGS_C_ESW_FLOW_TABLE	= (1 << 8),
	MLXCX_CAP_GENERAL_FLAGS_C_NIC_FLOW_TABLE	= (1 << 9),
} mlxcx_hca_cap_general_flags_c_t;

typedef struct {
	uint8_t		mlcap_general_access_other_hca_roce;
	uint8_t		mlcap_general_rsvd[3];

	uint8_t		mlcap_general_rsvd2[12];

	uint8_t		mlcap_general_log_max_srq_sz;
	uint8_t		mlcap_general_log_max_qp_sz;
	uint8_t		mlcap_general_rsvd3[1];
	uint8_t		mlcap_general_log_max_qp;

	uint8_t		mlcap_general_rsvd4[1];
	uint8_t		mlcap_general_log_max_srq;
	uint8_t		mlcap_general_rsvd5[2];

	uint8_t		mlcap_general_rsvd6[1];
	uint8_t		mlcap_general_log_max_cq_sz;
	uint8_t		mlcap_general_rsvd7[1];
	uint8_t		mlcap_general_log_max_cq;

	uint8_t		mlcap_general_log_max_eq_sz;
	uint8_t		mlcap_general_log_max_mkey_flags;
	uint8_t		mlcap_general_rsvd8[1];
	uint8_t		mlcap_general_log_max_eq;

	uint8_t		mlcap_general_max_indirection;
	uint8_t		mlcap_general_log_max_mrw_sz_flags;
	uint8_t		mlcap_general_log_max_bsf_list_size_flags;
	uint8_t		mlcap_general_log_max_klm_list_size_flags;

	uint8_t		mlcap_general_rsvd9[1];
	uint8_t		mlcap_general_log_max_ra_req_dc;
	uint8_t		mlcap_general_rsvd10[1];
	uint8_t		mlcap_general_log_max_ra_res_dc;

	uint8_t		mlcap_general_rsvd11[1];
	uint8_t		mlcap_general_log_max_ra_req_qp;
	uint8_t		mlcap_general_rsvd12[1];
	uint8_t		mlcap_general_log_max_ra_res_qp;

	uint16be_t	mlcap_general_flags_a;
	uint16be_t	mlcap_general_gid_table_size;

	bits16_t	mlcap_general_flags_b;
	uint16be_t	mlcap_general_pkey_table_size;

	bits16_t	mlcap_general_flags_c;
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint8_t		mlcap_general_flags_d:6;
		uint8_t		mlcap_general_port_type:2;
#elif defined(_BIT_FIELDS_LTOH)
		uint8_t		mlcap_general_port_type:2;
		uint8_t		mlcap_general_flags_d:6;
#endif
	};
	uint8_t		mlcap_general_num_ports;

	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint8_t		mlcap_general_rsvd13:3;
		uint8_t		mlcap_general_log_max_msg:5;
#elif defined(_BIT_FIELDS_LTOH)
		uint8_t		mlcap_general_log_max_msg:5;
		uint8_t		mlcap_general_rsvd13:3;
#endif
	};
	uint8_t		mlcap_general_max_tc;
	bits16_t	mlcap_general_flags_d_wol;

	uint16be_t	mlcap_general_state_rate_support;
	uint8_t		mlcap_general_rsvd14[1];
	struct {
#if defined(_BIT_FIELDS_HTOL)
		uint8_t		mlcap_general_rsvd15:4;
		uint8_t		mlcap_general_cqe_version:4;
#elif defined(_BIT_FIELDS_LTOH)
		uint8_t		mlcap_general_cqe_version:4;
		uint8_t		mlcap_general_rsvd15:4;
#endif
	};

	uint32be_t	mlcap_general_flags_e;

	uint32be_t	mlcap_general_flags_f;

	uint8_t		mlcap_general_rsvd16[1];
	uint8_t		mlcap_general_uar_sz;
	uint8_t		mlcap_general_cnak;
	uint8_t		mlcap_general_log_pg_sz;
	uint8_t		mlcap_general_rsvd17[32];
	bits8_t		mlcap_general_log_max_rq_flags;
	uint8_t		mlcap_general_log_max_sq;
	uint8_t		mlcap_general_log_max_tir;
	uint8_t		mlcap_general_log_max_tis;
} mlxcx_hca_cap_general_caps_t;

typedef enum {
	MLXCX_ETH_CAP_TUNNEL_STATELESS_VXLAN		= 1 << 0,
	MLXCX_ETH_CAP_TUNNEL_STATELESS_GRE		= 1 << 1,
	MLXCX_ETH_CAP_TUNNEL_LSO_CONST_OUT_IP_ID	= 1 << 4,
	MLXCX_ETH_CAP_SCATTER_FCS			= 1 << 6,
	MLXCX_ETH_CAP_REG_UMR_SQ			= 1 << 7,
	MLXCX_ETH_CAP_SELF_LB_UC			= 1 << 21,
	MLXCX_ETH_CAP_SELF_LB_MC			= 1 << 22,
	MLXCX_ETH_CAP_SELF_LB_EN_MODIFIABLE		= 1 << 23,
	MLXCX_ETH_CAP_WQE_VLAN_INSERT			= 1 << 24,
	MLXCX_ETH_CAP_LRO_TIME_STAMP			= 1 << 27,
	MLXCX_ETH_CAP_LRO_PSH_FLAG			= 1 << 28,
	MLXCX_ETH_CAP_LRO_CAP				= 1 << 29,
	MLXCX_ETH_CAP_VLAN_STRIP			= 1 << 30,
	MLXCX_ETH_CAP_CSUM_CAP				= 1UL << 31
} mlxcx_hca_eth_cap_flags_t;

/* CSTYLED */
#define	MLXCX_ETH_CAP_RSS_IND_TBL_CAP		(bitdef_t){8,  0x00000f00}
/* CSTYLED */
#define	MLXCX_ETH_CAP_WQE_INLINE_MODE		(bitdef_t){12, 0x00003000}
/* CSTYLED */
#define	MLXCX_ETH_CAP_MULTI_PKT_SEND_WQE	(bitdef_t){14, 0x0000c000}
/* CSTYLED */
#define	MLXCX_ETH_CAP_MAX_LSO_CAP		(bitdef_t){16, 0x001f0000}
/* CSTYLED */
#define	MLXCX_ETH_CAP_LRO_MAX_MSG_SZ_MODE	(bitdef_t){25, 0x06000000}

typedef struct {
	bits32_t	mlcap_eth_flags;
	uint8_t		mlcap_eth_rsvd[6];
	uint16be_t	mlcap_eth_lro_min_mss_size;
	uint8_t		mlcap_eth_rsvd2[36];
	uint32be_t	mlcap_eth_lro_timer_supported_periods[4];
} mlxcx_hca_cap_eth_caps_t;

typedef enum {
	MLXCX_FLOW_CAP_PROPS_DECAP			= 1 << 23,
	MLXCX_FLOW_CAP_PROPS_ENCAP			= 1 << 24,
	MLXCX_FLOW_CAP_PROPS_MODIFY_TBL			= 1 << 25,
	MLXCX_FLOW_CAP_PROPS_MISS_TABLE			= 1 << 26,
	MLXCX_FLOW_CAP_PROPS_MODIFY_ROOT_TBL		= 1 << 27,
	MLXCX_FLOW_CAP_PROPS_MODIFY			= 1 << 28,
	MLXCX_FLOW_CAP_PROPS_COUNTER			= 1 << 29,
	MLXCX_FLOW_CAP_PROPS_TAG			= 1 << 30,
	MLXCX_FLOW_CAP_PROPS_SUPPORT			= 1UL << 31
} mlxcx_hca_cap_flow_cap_props_flags_t;

typedef struct {
	bits32_t	mlcap_flow_prop_flags;
	uint8_t		mlcap_flow_prop_log_max_ft_size;
	uint8_t		mlcap_flow_prop_rsvd[2];
	uint8_t		mlcap_flow_prop_max_ft_level;
	uint8_t		mlcap_flow_prop_rsvd2[7];
	uint8_t		mlcap_flow_prop_log_max_ft_num;
	uint8_t		mlcap_flow_prop_rsvd3[2];
	uint8_t		mlcap_flow_prop_log_max_flow_counter;
	uint8_t		mlcap_flow_prop_log_max_destination;
	uint8_t		mlcap_flow_prop_rsvd4[3];
	uint8_t		mlcap_flow_prop_log_max_flow;
	uint8_t		mlcap_flow_prop_rsvd5[8];
	bits32_t	mlcap_flow_prop_support[4];
	bits32_t	mlcap_flow_prop_bitmask[4];
} mlxcx_hca_cap_flow_cap_props_t;

typedef struct {
	bits32_t	mlcap_flow_flags;
	uint8_t		mlcap_flow_rsvd[60];
	mlxcx_hca_cap_flow_cap_props_t	mlcap_flow_nic_rx;
	mlxcx_hca_cap_flow_cap_props_t	mlcap_flow_nic_rx_rdma;
	mlxcx_hca_cap_flow_cap_props_t	mlcap_flow_nic_rx_sniffer;
	mlxcx_hca_cap_flow_cap_props_t	mlcap_flow_nic_tx;
	mlxcx_hca_cap_flow_cap_props_t	mlcap_flow_nic_tx_rdma;
	mlxcx_hca_cap_flow_cap_props_t	mlcap_flow_nic_tx_sniffer;
} mlxcx_hca_cap_flow_caps_t;

/*
 * Size of a buffer that is required to hold the output data.
 */
#define	MLXCX_HCA_CAP_SIZE	0x1000

typedef struct {
	mlxcx_cmd_in_t	mlxi_query_hca_cap_head;
	uint8_t		mlxi_query_hca_cap_rsvd[8];
} mlxcx_cmd_query_hca_cap_in_t;

typedef struct {
	mlxcx_cmd_out_t mlxo_query_hca_cap_head;
	uint8_t		mlxo_query_hca_cap_rsvd[8];
	uint8_t		mlxo_query_hca_cap_data[MLXCX_HCA_CAP_SIZE];
} mlxcx_cmd_query_hca_cap_out_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_set_driver_version_head;
	uint8_t		mlxi_set_driver_version_rsvd[8];
	char		mlxi_set_driver_version_version[64];
} mlxcx_cmd_set_driver_version_in_t;

typedef struct {
	mlxcx_cmd_out_t mlxo_set_driver_version_head;
	uint8_t		mlxo_set_driver_version_rsvd[8];
} mlxcx_cmd_set_driver_version_out_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_alloc_uar_head;
	uint8_t		mlxi_alloc_uar_rsvd[8];
} mlxcx_cmd_alloc_uar_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_alloc_uar_head;
	uint8_t		mlxo_alloc_uar_rsvd;
	uint24be_t	mlxo_alloc_uar_uar;
	uint8_t		mlxo_alloc_uar_rsvd2[4];
} mlxcx_cmd_alloc_uar_out_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_dealloc_uar_head;
	uint8_t		mlxi_dealloc_uar_rsvd;
	uint24be_t	mlxi_dealloc_uar_uar;
	uint8_t		mlxi_dealloc_uar_rsvd2[4];
} mlxcx_cmd_dealloc_uar_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_dealloc_uar_head;
	uint8_t		mlxo_dealloc_uar_rsvd[8];
} mlxcx_cmd_dealloc_uar_out_t;

/*
 * This is an artificial limit that we're imposing on our actions.
 */
#define	MLXCX_CREATE_QUEUE_MAX_PAGES	128

typedef struct {
	mlxcx_cmd_in_t	mlxi_create_eq_head;
	uint8_t		mlxi_create_eq_rsvd[8];
	mlxcx_eventq_ctx_t	mlxi_create_eq_context;
	uint8_t		mlxi_create_eq_rsvd2[8];
	uint64be_t	mlxi_create_eq_event_bitmask;
	uint8_t		mlxi_create_eq_rsvd3[176];
	uint64be_t	mlxi_create_eq_pas[MLXCX_CREATE_QUEUE_MAX_PAGES];
} mlxcx_cmd_create_eq_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_create_eq_head;
	uint8_t		mlxo_create_eq_rsvd[3];
	uint8_t		mlxo_create_eq_eqn;
	uint8_t		mlxo_create_eq_rsvd2[4];
} mlxcx_cmd_create_eq_out_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_query_eq_head;
	uint8_t		mlxi_query_eq_rsvd[3];
	uint8_t		mlxi_query_eq_eqn;
	uint8_t		mlxi_query_eq_rsvd2[4];
} mlxcx_cmd_query_eq_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_query_eq_head;
	uint8_t		mlxo_query_eq_rsvd[8];
	mlxcx_eventq_ctx_t	mlxo_query_eq_context;
	uint8_t		mlxi_query_eq_rsvd2[8];
	uint64be_t	mlxi_query_eq_event_bitmask;
	uint8_t		mlxi_query_eq_rsvd3[176];
	uint64be_t	mlxi_create_eq_pas[MLXCX_CREATE_QUEUE_MAX_PAGES];
} mlxcx_cmd_query_eq_out_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_destroy_eq_head;
	uint8_t		mlxi_destroy_eq_rsvd[3];
	uint8_t		mlxi_destroy_eq_eqn;
	uint8_t		mlxi_destroy_eq_rsvd2[4];
} mlxcx_cmd_destroy_eq_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_destroy_eq_head;
	uint8_t		mlxo_destroy_eq_rsvd[8];
} mlxcx_cmd_destroy_eq_out_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_alloc_pd_head;
	uint8_t		mlxi_alloc_pd_rsvd[8];
} mlxcx_cmd_alloc_pd_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_alloc_pd_head;
	uint8_t		mlxo_alloc_pd_rsvd;
	uint24be_t	mlxo_alloc_pd_pdn;
	uint8_t		mlxo_alloc_pd_rsvd2[4];
} mlxcx_cmd_alloc_pd_out_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_dealloc_pd_head;
	uint8_t		mlxi_dealloc_pd_rsvd;
	uint24be_t	mlxi_dealloc_pd_pdn;
	uint8_t		mlxi_dealloc_pd_rsvd2[4];
} mlxcx_cmd_dealloc_pd_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_dealloc_pd_head;
	uint8_t		mlxo_dealloc_pd_rsvd[8];
} mlxcx_cmd_dealloc_pd_out_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_alloc_tdom_head;
	uint8_t		mlxi_alloc_tdom_rsvd[8];
} mlxcx_cmd_alloc_tdom_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_alloc_tdom_head;
	uint8_t		mlxo_alloc_tdom_rsvd;
	uint24be_t	mlxo_alloc_tdom_tdomn;
	uint8_t		mlxo_alloc_tdom_rsvd2[4];
} mlxcx_cmd_alloc_tdom_out_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_dealloc_tdom_head;
	uint8_t		mlxi_dealloc_tdom_rsvd;
	uint24be_t	mlxi_dealloc_tdom_tdomn;
	uint8_t		mlxi_dealloc_tdom_rsvd2[4];
} mlxcx_cmd_dealloc_tdom_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_dealloc_tdom_head;
	uint8_t		mlxo_dealloc_tdom_rsvd[8];
} mlxcx_cmd_dealloc_tdom_out_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_create_tir_head;
	uint8_t		mlxi_create_tir_rsvd[24];
	mlxcx_tir_ctx_t	mlxi_create_tir_context;
} mlxcx_cmd_create_tir_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_create_tir_head;
	uint8_t		mlxo_create_tir_rsvd;
	uint24be_t	mlxo_create_tir_tirn;
	uint8_t		mlxo_create_tir_rsvd2[4];
} mlxcx_cmd_create_tir_out_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_destroy_tir_head;
	uint8_t		mlxi_destroy_tir_rsvd;
	uint24be_t	mlxi_destroy_tir_tirn;
	uint8_t		mlxi_destroy_tir_rsvd2[4];
} mlxcx_cmd_destroy_tir_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_destroy_tir_head;
	uint8_t		mlxo_destroy_tir_rsvd[8];
} mlxcx_cmd_destroy_tir_out_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_create_tis_head;
	uint8_t		mlxi_create_tis_rsvd[24];
	mlxcx_tis_ctx_t	mlxi_create_tis_context;
} mlxcx_cmd_create_tis_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_create_tis_head;
	uint8_t		mlxo_create_tis_rsvd;
	uint24be_t	mlxo_create_tis_tisn;
	uint8_t		mlxo_create_tis_rsvd2[4];
} mlxcx_cmd_create_tis_out_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_destroy_tis_head;
	uint8_t		mlxi_destroy_tis_rsvd;
	uint24be_t	mlxi_destroy_tis_tisn;
	uint8_t		mlxi_destroy_tis_rsvd2[4];
} mlxcx_cmd_destroy_tis_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_destroy_tis_head;
	uint8_t		mlxo_destroy_tis_rsvd[8];
} mlxcx_cmd_destroy_tis_out_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_query_special_ctxs_head;
	uint8_t		mlxi_query_special_ctxs_rsvd[8];
} mlxcx_cmd_query_special_ctxs_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_query_special_ctxs_head;
	uint8_t		mlxo_query_special_ctxs_rsvd[4];
	uint32be_t	mlxo_query_special_ctxs_resd_lkey;
	uint32be_t	mlxo_query_special_ctxs_null_mkey;
	uint8_t		mlxo_query_special_ctxs_rsvd2[12];
} mlxcx_cmd_query_special_ctxs_out_t;

typedef enum {
	MLXCX_VPORT_TYPE_VNIC		= 0x0,
	MLXCX_VPORT_TYPE_ESWITCH	= 0x1,
	MLXCX_VPORT_TYPE_UPLINK		= 0x2,
} mlxcx_cmd_vport_op_mod_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_query_nic_vport_ctx_head;
	uint8_t		mlxi_query_nic_vport_ctx_other_vport;
	uint8_t		mlxi_query_nic_vport_ctx_rsvd[1];
	uint16be_t	mlxi_query_nic_vport_ctx_vport_number;
	uint8_t		mlxi_query_nic_vport_ctx_allowed_list_type;
	uint8_t		mlxi_query_nic_vport_ctx_rsvd2[3];
} mlxcx_cmd_query_nic_vport_ctx_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_query_nic_vport_ctx_head;
	uint8_t		mlxo_query_nic_vport_ctx_rsvd[8];
	mlxcx_nic_vport_ctx_t	mlxo_query_nic_vport_ctx_context;
} mlxcx_cmd_query_nic_vport_ctx_out_t;

typedef enum {
	MLXCX_MODIFY_NIC_VPORT_CTX_ROCE_EN	= 1 << 1,
	MLXCX_MODIFY_NIC_VPORT_CTX_ADDR_LIST	= 1 << 2,
	MLXCX_MODIFY_NIC_VPORT_CTX_PERM_ADDR	= 1 << 3,
	MLXCX_MODIFY_NIC_VPORT_CTX_PROMISC	= 1 << 4,
	MLXCX_MODIFY_NIC_VPORT_CTX_EVENT	= 1 << 5,
	MLXCX_MODIFY_NIC_VPORT_CTX_MTU		= 1 << 6,
	MLXCX_MODIFY_NIC_VPORT_CTX_WQE_INLINE	= 1 << 7,
	MLXCX_MODIFY_NIC_VPORT_CTX_PORT_GUID	= 1 << 8,
	MLXCX_MODIFY_NIC_VPORT_CTX_NODE_GUID	= 1 << 9,
} mlxcx_modify_nic_vport_ctx_fields_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_modify_nic_vport_ctx_head;
	uint8_t		mlxi_modify_nic_vport_ctx_other_vport;
	uint8_t		mlxi_modify_nic_vport_ctx_rsvd[1];
	uint16be_t	mlxi_modify_nic_vport_ctx_vport_number;
	uint32be_t	mlxi_modify_nic_vport_ctx_field_select;
	uint8_t		mlxi_modify_nic_vport_ctx_rsvd2[240];
	mlxcx_nic_vport_ctx_t	mlxi_modify_nic_vport_ctx_context;
} mlxcx_cmd_modify_nic_vport_ctx_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_modify_nic_vport_ctx_head;
	uint8_t		mlxo_modify_nic_vport_ctx_rsvd[8];
} mlxcx_cmd_modify_nic_vport_ctx_out_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_query_vport_state_head;
	uint8_t		mlxi_query_vport_state_other_vport;
	uint8_t		mlxi_query_vport_state_rsvd[1];
	uint16be_t	mlxi_query_vport_state_vport_number;
	uint8_t		mlxi_query_vport_state_rsvd2[4];
} mlxcx_cmd_query_vport_state_in_t;

/* CSTYLED */
#define	MLXCX_VPORT_ADMIN_STATE		(bitdef_t){4, 0xF0}
/* CSTYLED */
#define	MLXCX_VPORT_OPER_STATE		(bitdef_t){0, 0x0F}

typedef enum {
	MLXCX_VPORT_OPER_STATE_DOWN	= 0x0,
	MLXCX_VPORT_OPER_STATE_UP	= 0x1,
} mlxcx_vport_oper_state_t;

typedef enum {
	MLXCX_VPORT_ADMIN_STATE_DOWN	= 0x0,
	MLXCX_VPORT_ADMIN_STATE_UP	= 0x1,
	MLXCX_VPORT_ADMIN_STATE_FOLLOW	= 0x2,
} mlxcx_vport_admin_state_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_query_vport_state_head;
	uint8_t		mlxo_query_vport_state_rsvd[4];
	uint16be_t	mlxo_query_vport_state_max_tx_speed;
	uint8_t		mlxo_query_vport_state_rsvd2[1];
	uint8_t		mlxo_query_vport_state_state;
} mlxcx_cmd_query_vport_state_out_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_create_cq_head;
	uint8_t		mlxi_create_cq_rsvd[8];
	mlxcx_completionq_ctx_t		mlxi_create_cq_context;
	uint8_t		mlxi_create_cq_rsvd2[192];
	uint64be_t	mlxi_create_cq_pas[MLXCX_CREATE_QUEUE_MAX_PAGES];
} mlxcx_cmd_create_cq_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_create_cq_head;
	uint8_t		mlxo_create_cq_rsvd;
	uint24be_t	mlxo_create_cq_cqn;
	uint8_t		mlxo_create_cq_rsvd2[4];
} mlxcx_cmd_create_cq_out_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_destroy_cq_head;
	uint8_t		mlxi_destroy_cq_rsvd;
	uint24be_t	mlxi_destroy_cq_cqn;
	uint8_t		mlxi_destroy_cq_rsvd2[4];
} mlxcx_cmd_destroy_cq_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_destroy_cq_head;
	uint8_t		mlxo_destroy_cq_rsvd[8];
} mlxcx_cmd_destroy_cq_out_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_query_cq_head;
	uint8_t		mlxi_query_cq_rsvd;
	uint24be_t	mlxi_query_cq_cqn;
	uint8_t		mlxi_query_cq_rsvd2[4];
} mlxcx_cmd_query_cq_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_query_cq_head;
	uint8_t		mlxo_query_cq_rsvd[8];
	mlxcx_completionq_ctx_t		mlxo_query_cq_context;
	uint8_t		mlxo_query_cq_rsvd2[192];
	uint64be_t	mlxo_query_cq_pas[MLXCX_CREATE_QUEUE_MAX_PAGES];
} mlxcx_cmd_query_cq_out_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_create_rq_head;
	uint8_t		mlxi_create_rq_rsvd[24];
	mlxcx_rq_ctx_t	mlxi_create_rq_context;
} mlxcx_cmd_create_rq_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_create_rq_head;
	uint8_t		mlxo_create_rq_rsvd;
	uint24be_t	mlxo_create_rq_rqn;
	uint8_t		mlxo_create_rq_rsvd2[4];
} mlxcx_cmd_create_rq_out_t;

/* CSTYLED */
#define	MLXCX_CMD_MODIFY_RQ_STATE	(bitdef_t){ \
					.bit_shift = 4, .bit_mask = 0xF0 }

typedef enum {
	MLXCX_MODIFY_RQ_SCATTER_FCS		= 1 << 2,
	MLXCX_MODIFY_RQ_VSD			= 1 << 1,
	MLXCX_MODIFY_RQ_COUNTER_SET_ID		= 1 << 3,
	MLXCX_MODIFY_RQ_LWM			= 1 << 0
} mlxcx_cmd_modify_rq_bitmask_t;

typedef enum {
	MLXCX_RQ_STATE_RST	= 0x0,
	MLXCX_RQ_STATE_RDY	= 0x1,
	MLXCX_RQ_STATE_ERR	= 0x3
} mlxcx_rq_state_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_modify_rq_head;
	bits8_t		mlxi_modify_rq_state;
	uint24be_t	mlxi_modify_rq_rqn;
	uint8_t		mlxi_modify_rq_rsvd[4];
	uint64be_t	mlxi_modify_rq_bitmask;
	uint8_t		mlxi_modify_rq_rsvd2[8];
	mlxcx_rq_ctx_t	mlxi_modify_rq_context;
} mlxcx_cmd_modify_rq_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_modify_rq_head;
	uint8_t		mlxo_modify_rq_rsvd[8];
} mlxcx_cmd_modify_rq_out_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_query_rq_head;
	uint8_t		mlxi_query_rq_rsvd;
	uint24be_t	mlxi_query_rq_rqn;
	uint8_t		mlxi_query_rq_rsvd2[4];
} mlxcx_cmd_query_rq_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_query_rq_head;
	uint8_t		mlxo_query_rq_rsvd[24];
	mlxcx_rq_ctx_t	mlxo_query_rq_context;
} mlxcx_cmd_query_rq_out_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_destroy_rq_head;
	uint8_t		mlxi_destroy_rq_rsvd;
	uint24be_t	mlxi_destroy_rq_rqn;
	uint8_t		mlxi_destroy_rq_rsvd2[4];
} mlxcx_cmd_destroy_rq_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_destroy_rq_head;
	uint8_t		mlxo_destroy_rq_rsvd[8];
} mlxcx_cmd_destroy_rq_out_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_create_sq_head;
	uint8_t		mlxi_create_sq_rsvd[24];
	mlxcx_sq_ctx_t	mlxi_create_sq_context;
} mlxcx_cmd_create_sq_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_create_sq_head;
	uint8_t		mlxo_create_sq_rsvd;
	uint24be_t	mlxo_create_sq_sqn;
	uint8_t		mlxo_create_sq_rsvd2[4];
} mlxcx_cmd_create_sq_out_t;

/* CSTYLED */
#define	MLXCX_CMD_MODIFY_SQ_STATE	(bitdef_t){ \
					.bit_shift = 4, .bit_mask = 0xF0 }

typedef enum {
	MLXCX_MODIFY_SQ_PACKET_PACING_INDEX	= 1 << 0,
} mlxcx_cmd_modify_sq_bitmask_t;

typedef enum {
	MLXCX_SQ_STATE_RST	= 0x0,
	MLXCX_SQ_STATE_RDY	= 0x1,
	MLXCX_SQ_STATE_ERR	= 0x3
} mlxcx_sq_state_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_modify_sq_head;
	bits8_t		mlxi_modify_sq_state;
	uint24be_t	mlxi_modify_sq_sqn;
	uint8_t		mlxi_modify_sq_rsvd[4];
	uint64be_t	mlxi_modify_sq_bitmask;
	uint8_t		mlxi_modify_sq_rsvd2[8];
	mlxcx_sq_ctx_t	mlxi_modify_sq_context;
} mlxcx_cmd_modify_sq_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_modify_sq_head;
	uint8_t		mlxo_modify_sq_rsvd[8];
} mlxcx_cmd_modify_sq_out_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_query_sq_head;
	uint8_t		mlxi_query_sq_rsvd;
	uint24be_t	mlxi_query_sq_sqn;
	uint8_t		mlxi_query_sq_rsvd2[4];
} mlxcx_cmd_query_sq_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_query_sq_head;
	uint8_t		mlxo_query_sq_rsvd[24];
	mlxcx_sq_ctx_t	mlxo_query_sq_context;
} mlxcx_cmd_query_sq_out_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_destroy_sq_head;
	uint8_t		mlxi_destroy_sq_rsvd;
	uint24be_t	mlxi_destroy_sq_sqn;
	uint8_t		mlxi_destroy_sq_rsvd2[4];
} mlxcx_cmd_destroy_sq_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_destroy_sq_head;
	uint8_t		mlxo_destroy_sq_rsvd[8];
} mlxcx_cmd_destroy_sq_out_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_create_rqt_head;
	uint8_t		mlxi_create_rqt_rsvd[24];
	mlxcx_rqtable_ctx_t	mlxi_create_rqt_context;
} mlxcx_cmd_create_rqt_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_create_rqt_head;
	uint8_t		mlxo_create_rqt_rsvd;
	uint24be_t	mlxo_create_rqt_rqtn;
	uint8_t		mlxo_create_rqt_rsvd2[4];
} mlxcx_cmd_create_rqt_out_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_destroy_rqt_head;
	uint8_t		mlxi_destroy_rqt_rsvd;
	uint24be_t	mlxi_destroy_rqt_rqtn;
	uint8_t		mlxi_destroy_rqt_rsvd2[4];
} mlxcx_cmd_destroy_rqt_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_destroy_rqt_head;
	uint8_t		mlxo_destroy_rqt_rsvd[8];
} mlxcx_cmd_destroy_rqt_out_t;

typedef enum {
	MLXCX_FLOW_TABLE_NIC_RX		= 0x0,
	MLXCX_FLOW_TABLE_NIC_TX		= 0x1,
	MLXCX_FLOW_TABLE_ESW_OUT	= 0x2,
	MLXCX_FLOW_TABLE_ESW_IN		= 0x3,
	MLXCX_FLOW_TABLE_ESW_FDB	= 0x4,
	MLXCX_FLOW_TABLE_NIC_RX_SNIFF	= 0x5,
	MLXCX_FLOW_TABLE_NIC_TX_SNIFF	= 0x6,
	MLXCX_FLOW_TABLE_NIC_RX_RDMA	= 0x7,
	MLXCX_FLOW_TABLE_NIC_TX_RDMA	= 0x8
} mlxcx_flow_table_type_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_create_flow_table_head;
	uint8_t		mlxi_create_flow_table_other_vport;
	uint8_t		mlxi_create_flow_table_rsvd;
	uint16be_t	mlxi_create_flow_table_vport_number;
	uint8_t		mlxi_create_flow_table_rsvd2[4];
	uint8_t		mlxi_create_flow_table_table_type;
	uint8_t		mlxi_create_flow_table_rsvd3[7];
	mlxcx_flow_table_ctx_t	mlxi_create_flow_table_context;
} mlxcx_cmd_create_flow_table_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_create_flow_table_head;
	uint8_t		mlxo_create_flow_table_rsvd;
	uint24be_t	mlxo_create_flow_table_table_id;
	uint8_t		mlxo_create_flow_table_rsvd2[4];
} mlxcx_cmd_create_flow_table_out_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_destroy_flow_table_head;
	uint8_t		mlxi_destroy_flow_table_other_vport;
	uint8_t		mlxi_destroy_flow_table_rsvd;
	uint16be_t	mlxi_destroy_flow_table_vport_number;
	uint8_t		mlxi_destroy_flow_table_rsvd2[4];
	uint8_t		mlxi_destroy_flow_table_table_type;
	uint8_t		mlxi_destroy_flow_table_rsvd3[4];
	uint24be_t	mlxi_destroy_flow_table_table_id;
	uint8_t		mlxi_destroy_flow_table_rsvd4[4];
} mlxcx_cmd_destroy_flow_table_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_destroy_flow_table_head;
	uint8_t		mlxo_destroy_flow_table_rsvd[8];
} mlxcx_cmd_destroy_flow_table_out_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_set_flow_table_root_head;
	uint8_t		mlxi_set_flow_table_root_other_vport;
	uint8_t		mlxi_set_flow_table_root_rsvd;
	uint16be_t	mlxi_set_flow_table_root_vport_number;
	uint8_t		mlxi_set_flow_table_root_rsvd2[4];
	uint8_t		mlxi_set_flow_table_root_table_type;
	uint8_t		mlxi_set_flow_table_root_rsvd3[4];
	uint24be_t	mlxi_set_flow_table_root_table_id;
	uint8_t		mlxi_set_flow_table_root_rsvd4[4];
} mlxcx_cmd_set_flow_table_root_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_set_flow_table_root_head;
	uint8_t		mlxo_set_flow_table_root_rsvd[8];
} mlxcx_cmd_set_flow_table_root_out_t;

typedef enum {
	MLXCX_FLOW_GROUP_MATCH_OUTER_HDRS	= 1 << 0,
	MLXCX_FLOW_GROUP_MATCH_MISC_PARAMS	= 1 << 1,
	MLXCX_FLOW_GROUP_MATCH_INNER_HDRS	= 1 << 2,
} mlxcx_flow_group_match_criteria_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_create_flow_group_head;
	uint8_t		mlxi_create_flow_group_other_vport;
	uint8_t		mlxi_create_flow_group_rsvd;
	uint16be_t	mlxi_create_flow_group_vport_number;
	uint8_t		mlxi_create_flow_group_rsvd2[4];
	uint8_t		mlxi_create_flow_group_table_type;
	uint8_t		mlxi_create_flow_group_rsvd3[4];
	uint24be_t	mlxi_create_flow_group_table_id;
	uint8_t		mlxi_create_flow_group_rsvd4[4];
	uint32be_t	mlxi_create_flow_group_start_flow_index;
	uint8_t		mlxi_create_flow_group_rsvd5[4];
	uint32be_t	mlxi_create_flow_group_end_flow_index;
	uint8_t		mlxi_create_flow_group_rsvd6[23];
	uint8_t		mlxi_create_flow_group_match_criteria_en;
	mlxcx_flow_match_t	mlxi_create_flow_group_match_criteria;
	uint8_t		mlxi_create_flow_group_rsvd7[448];
} mlxcx_cmd_create_flow_group_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_create_flow_group_head;
	uint8_t		mlxo_create_flow_group_rsvd;
	uint24be_t	mlxo_create_flow_group_group_id;
	uint8_t		mlxo_create_flow_group_rsvd2[4];
} mlxcx_cmd_create_flow_group_out_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_destroy_flow_group_head;
	uint8_t		mlxi_destroy_flow_group_other_vport;
	uint8_t		mlxi_destroy_flow_group_rsvd;
	uint16be_t	mlxi_destroy_flow_group_vport_number;
	uint8_t		mlxi_destroy_flow_group_rsvd2[4];
	uint8_t		mlxi_destroy_flow_group_table_type;
	uint8_t		mlxi_destroy_flow_group_rsvd3[4];
	uint24be_t	mlxi_destroy_flow_group_table_id;
	uint32be_t	mlxi_destroy_flow_group_group_id;
	uint8_t		mlxi_destroy_flow_group_rsvd4[36];
} mlxcx_cmd_destroy_flow_group_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_destroy_flow_group_head;
	uint8_t		mlxo_destroy_flow_group_rsvd[8];
} mlxcx_cmd_destroy_flow_group_out_t;

typedef enum {
	MLXCX_CMD_FLOW_ENTRY_SET_NEW		= 0,
	MLXCX_CMD_FLOW_ENTRY_MODIFY		= 1,
} mlxcx_cmd_set_flow_table_entry_opmod_t;

typedef enum {
	MLXCX_CMD_FLOW_ENTRY_SET_ACTION		= 1 << 0,
	MLXCX_CMD_FLOW_ENTRY_SET_FLOW_TAG	= 1 << 1,
	MLXCX_CMD_FLOW_ENTRY_SET_DESTINATION	= 1 << 2,
	MLXCX_CMD_FLOW_ENTRY_SET_COUNTERS	= 1 << 3,
	MLXCX_CMD_FLOW_ENTRY_SET_ENCAP		= 1 << 4
} mlxcx_cmd_set_flow_table_entry_bitmask_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_set_flow_table_entry_head;
	uint8_t		mlxi_set_flow_table_entry_other_vport;
	uint8_t		mlxi_set_flow_table_entry_rsvd;
	uint16be_t	mlxi_set_flow_table_entry_vport_number;
	uint8_t		mlxi_set_flow_table_entry_rsvd2[4];
	uint8_t		mlxi_set_flow_table_entry_table_type;
	uint8_t		mlxi_set_flow_table_entry_rsvd3[4];
	uint24be_t	mlxi_set_flow_table_entry_table_id;
	uint8_t		mlxi_set_flow_table_entry_rsvd4[3];
	bits8_t		mlxi_set_flow_table_entry_modify_bitmask;
	uint8_t		mlxi_set_flow_table_entry_rsvd5[4];
	uint32be_t	mlxi_set_flow_table_entry_flow_index;
	uint8_t		mlxi_set_flow_table_entry_rsvd6[28];
	mlxcx_flow_entry_ctx_t	mlxi_set_flow_table_entry_context;
} mlxcx_cmd_set_flow_table_entry_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_set_flow_table_entry_head;
	uint8_t		mlxo_set_flow_table_entry_rsvd[8];
} mlxcx_cmd_set_flow_table_entry_out_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_delete_flow_table_entry_head;
	uint8_t		mlxi_delete_flow_table_entry_other_vport;
	uint8_t		mlxi_delete_flow_table_entry_rsvd;
	uint16be_t	mlxi_delete_flow_table_entry_vport_number;
	uint8_t		mlxi_delete_flow_table_entry_rsvd2[4];
	uint8_t		mlxi_delete_flow_table_entry_table_type;
	uint8_t		mlxi_delete_flow_table_entry_rsvd3[4];
	uint24be_t	mlxi_delete_flow_table_entry_table_id;
	uint8_t		mlxi_delete_flow_table_entry_rsvd4[8];
	uint32be_t	mlxi_delete_flow_table_entry_flow_index;
	uint8_t		mlxi_delete_flow_table_entry_rsvd5[28];
} mlxcx_cmd_delete_flow_table_entry_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_delete_flow_table_entry_head;
	uint8_t		mlxo_delete_flow_table_entry_rsvd[8];
} mlxcx_cmd_delete_flow_table_entry_out_t;

typedef enum {
	MLXCX_CMD_CONFIG_INT_MOD_READ = 1,
	MLXCX_CMD_CONFIG_INT_MOD_WRITE = 0
} mlxcx_cmd_config_int_mod_opmod_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_config_int_mod_head;
	uint16be_t	mlxi_config_int_mod_min_delay;
	uint16be_t	mlxi_config_int_mod_int_vector;
	uint8_t		mlxi_config_int_mod_rsvd[4];
} mlxcx_cmd_config_int_mod_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_config_int_mod_head;
	uint16be_t	mlxo_config_int_mod_min_delay;
	uint16be_t	mlxo_config_int_mod_int_vector;
	uint8_t		mlxo_config_int_mod_rsvd[4];
} mlxcx_cmd_config_int_mod_out_t;

typedef struct {
	uint8_t		mlrd_pmtu_rsvd;
	uint8_t		mlrd_pmtu_local_port;
	uint8_t		mlrd_pmtu_rsvd2[2];

	uint16be_t	mlrd_pmtu_max_mtu;
	uint8_t		mlrd_pmtu_rsvd3[2];

	uint16be_t	mlrd_pmtu_admin_mtu;
	uint8_t		mlrd_pmtu_rsvd4[2];

	uint16be_t	mlrd_pmtu_oper_mtu;
	uint8_t		mlrd_pmtu_rsvd5[2];
} mlxcx_reg_pmtu_t;

typedef enum {
	MLXCX_PORT_STATUS_UP		= 1,
	MLXCX_PORT_STATUS_DOWN		= 2,
	MLXCX_PORT_STATUS_UP_ONCE	= 3,
	MLXCX_PORT_STATUS_DISABLED	= 4,
} mlxcx_port_status_t;

typedef enum {
	MLXCX_PAOS_ADMIN_ST_EN		= 1UL << 31,
} mlxcx_paos_flags_t;

typedef struct {
	uint8_t		mlrd_paos_swid;
	uint8_t		mlrd_paos_local_port;
	uint8_t		mlrd_paos_admin_status;
	uint8_t		mlrd_paos_oper_status;
	bits32_t	mlrd_paos_flags;
	uint8_t		mlrd_paos_rsvd[8];
} mlxcx_reg_paos_t;

typedef enum {
	MLXCX_PROTO_SGMII			= 1 << 0,
	MLXCX_PROTO_1000BASE_KX			= 1 << 1,
	MLXCX_PROTO_10GBASE_CX4			= 1 << 2,
	MLXCX_PROTO_10GBASE_KX4			= 1 << 3,
	MLXCX_PROTO_10GBASE_KR			= 1 << 4,
	MLXCX_PROTO_UNKNOWN_1			= 1 << 5,
	MLXCX_PROTO_40GBASE_CR4			= 1 << 6,
	MLXCX_PROTO_40GBASE_KR4			= 1 << 7,
	MLXCX_PROTO_UNKNOWN_2			= 1 << 8,
	MLXCX_PROTO_SGMII_100BASE		= 1 << 9,
	MLXCX_PROTO_UNKNOWN_3			= 1 << 10,
	MLXCX_PROTO_UNKNOWN_4			= 1 << 11,
	MLXCX_PROTO_10GBASE_CR			= 1 << 12,
	MLXCX_PROTO_10GBASE_SR			= 1 << 13,
	MLXCX_PROTO_10GBASE_ER_LR		= 1 << 14,
	MLXCX_PROTO_40GBASE_SR4			= 1 << 15,
	MLXCX_PROTO_40GBASE_LR4_ER4		= 1 << 16,
	MLXCX_PROTO_UNKNOWN_5			= 1 << 17,
	MLXCX_PROTO_50GBASE_SR2			= 1 << 18,
	MLXCX_PROTO_UNKNOWN_6			= 1 << 19,
	MLXCX_PROTO_100GBASE_CR4		= 1 << 20,
	MLXCX_PROTO_100GBASE_SR4		= 1 << 21,
	MLXCX_PROTO_100GBASE_KR4		= 1 << 22,
	MLXCX_PROTO_UNKNOWN_7			= 1 << 23,
	MLXCX_PROTO_UNKNOWN_8			= 1 << 24,
	MLXCX_PROTO_UNKNOWN_9			= 1 << 25,
	MLXCX_PROTO_UNKNOWN_10			= 1 << 26,
	MLXCX_PROTO_25GBASE_CR			= 1 << 27,
	MLXCX_PROTO_25GBASE_KR			= 1 << 28,
	MLXCX_PROTO_25GBASE_SR			= 1 << 29,
	MLXCX_PROTO_50GBASE_CR2			= 1 << 30,
	MLXCX_PROTO_50GBASE_KR2			= 1UL << 31,
} mlxcx_eth_proto_t;

#define	MLXCX_PROTO_100M	MLXCX_PROTO_SGMII_100BASE

#define	MLXCX_PROTO_1G		(MLXCX_PROTO_1000BASE_KX | MLXCX_PROTO_SGMII)

#define	MLXCX_PROTO_10G		(MLXCX_PROTO_10GBASE_CX4 | \
	MLXCX_PROTO_10GBASE_KX4 | MLXCX_PROTO_10GBASE_KR | \
	MLXCX_PROTO_10GBASE_CR | MLXCX_PROTO_10GBASE_SR | \
	MLXCX_PROTO_10GBASE_ER_LR)

#define	MLXCX_PROTO_25G		(MLXCX_PROTO_25GBASE_CR | \
	MLXCX_PROTO_25GBASE_KR | MLXCX_PROTO_25GBASE_SR)

#define	MLXCX_PROTO_40G		(MLXCX_PROTO_40GBASE_SR4 | \
	MLXCX_PROTO_40GBASE_LR4_ER4 | MLXCX_PROTO_40GBASE_CR4 | \
	MLXCX_PROTO_40GBASE_KR4)

#define	MLXCX_PROTO_50G		(MLXCX_PROTO_50GBASE_CR2 | \
	MLXCX_PROTO_50GBASE_KR2 | MLXCX_PROTO_50GBASE_SR2)

#define	MLXCX_PROTO_100G	(MLXCX_PROTO_100GBASE_CR4 | \
	MLXCX_PROTO_100GBASE_SR4 | MLXCX_PROTO_100GBASE_KR4)

typedef enum {
	MLXCX_AUTONEG_DISABLE_CAP	= 1 << 5,
	MLXCX_AUTONEG_DISABLE		= 1 << 6
} mlxcx_autoneg_flags_t;

typedef enum {
	MLXCX_PTYS_PROTO_MASK_IB	= 1 << 0,
	MLXCX_PTYS_PROTO_MASK_ETH	= 1 << 2,
} mlxcx_reg_ptys_proto_mask_t;

typedef struct {
	bits8_t		mlrd_ptys_autoneg_flags;
	uint8_t		mlrd_ptys_local_port;
	uint8_t		mlrd_ptys_rsvd;
	bits8_t		mlrd_ptys_proto_mask;

	bits8_t		mlrd_ptys_autoneg_status;
	uint8_t		mlrd_ptys_rsvd2;
	uint16be_t	mlrd_ptys_data_rate_oper;

	uint8_t		mlrd_ptys_rsvd3[4];

	bits32_t	mlrd_ptys_proto_cap;
	uint8_t		mlrd_ptys_rsvd4[8];
	bits32_t	mlrd_ptys_proto_admin;
	uint8_t		mlrd_ptys_rsvd5[8];
	bits32_t	mlrd_ptys_proto_oper;
	uint8_t		mlrd_ptys_rsvd6[8];
	bits32_t	mlrd_ptys_proto_partner_advert;
	uint8_t		mlrd_ptys_rsvd7[12];
} mlxcx_reg_ptys_t;

typedef enum {
	MLXCX_LED_TYPE_BOTH		= 0x0,
	MLXCX_LED_TYPE_UID		= 0x1,
	MLXCX_LED_TYPE_PORT		= 0x2,
} mlxcx_led_type_t;

#define	MLXCX_MLCR_INDIVIDUAL_ONLY	(1 << 4)
/* CSTYLED */
#define	MLXCX_MLCR_LED_TYPE		(bitdef_t){ 0, 0x0F }

typedef struct {
	uint8_t		mlrd_mlcr_rsvd;
	uint8_t		mlrd_mlcr_local_port;
	uint8_t		mlrd_mlcr_rsvd2;
	bits8_t		mlrd_mlcr_flags;
	uint8_t		mlrd_mlcr_rsvd3[2];
	uint16be_t	mlrd_mlcr_beacon_duration;
	uint8_t		mlrd_mlcr_rsvd4[2];
	uint16be_t	mlrd_mlcr_beacon_remain;
} mlxcx_reg_mlcr_t;

typedef struct {
	uint8_t		mlrd_pmaos_rsvd;
	uint8_t		mlrd_pmaos_module;
	uint8_t		mlrd_pmaos_admin_status;
	uint8_t		mlrd_pmaos_oper_status;
	bits8_t		mlrd_pmaos_flags;
	uint8_t		mlrd_pmaos_rsvd2;
	uint8_t		mlrd_pmaos_error_type;
	uint8_t		mlrd_pmaos_event_en;
	uint8_t		mlrd_pmaos_rsvd3[8];
} mlxcx_reg_pmaos_t;

typedef enum {
	MLXCX_MCIA_STATUS_OK		= 0x0,
	MLXCX_MCIA_STATUS_NO_EEPROM	= 0x1,
	MLXCX_MCIA_STATUS_NOT_SUPPORTED	= 0x2,
	MLXCX_MCIA_STATUS_NOT_CONNECTED	= 0x3,
	MLXCX_MCIA_STATUS_I2C_ERROR	= 0x9,
	MLXCX_MCIA_STATUS_DISABLED	= 0x10
} mlxcx_mcia_status_t;

typedef struct {
	bits8_t		mlrd_mcia_flags;
	uint8_t		mlrd_mcia_module;
	uint8_t		mlrd_mcia_rsvd;
	uint8_t		mlrd_mcia_status;
	uint8_t		mlrd_mcia_i2c_device_addr;
	uint8_t		mlrd_mcia_page_number;
	uint16be_t	mlrd_mcia_device_addr;
	uint8_t		mlrd_mcia_rsvd2[2];
	uint16be_t	mlrd_mcia_size;
	uint8_t		mlrd_mcia_rsvd3[4];
	uint8_t		mlrd_mcia_data[48];
} mlxcx_reg_mcia_t;

typedef struct {
	uint64be_t	mlppc_ieee_802_3_frames_tx;
	uint64be_t	mlppc_ieee_802_3_frames_rx;
	uint64be_t	mlppc_ieee_802_3_fcs_err;
	uint64be_t	mlppc_ieee_802_3_align_err;
	uint64be_t	mlppc_ieee_802_3_bytes_tx;
	uint64be_t	mlppc_ieee_802_3_bytes_rx;
	uint64be_t	mlppc_ieee_802_3_mcast_tx;
	uint64be_t	mlppc_ieee_802_3_bcast_tx;
	uint64be_t	mlppc_ieee_802_3_mcast_rx;
	uint64be_t	mlppc_ieee_802_3_bcast_rx;
	uint64be_t	mlppc_ieee_802_3_in_range_len_err;
	uint64be_t	mlppc_ieee_802_3_out_of_range_len_err;
	uint64be_t	mlppc_ieee_802_3_frame_too_long_err;
	uint64be_t	mlppc_ieee_802_3_symbol_err;
	uint64be_t	mlppc_ieee_802_3_mac_ctrl_tx;
	uint64be_t	mlppc_ieee_802_3_mac_ctrl_rx;
	uint64be_t	mlppc_ieee_802_3_unsup_opcodes_rx;
	uint64be_t	mlppc_ieee_802_3_pause_rx;
	uint64be_t	mlppc_ieee_802_3_pause_tx;
} mlxcx_ppcnt_ieee_802_3_t;

typedef struct {
	uint64be_t	mlppc_rfc_2863_in_octets;
	uint64be_t	mlppc_rfc_2863_in_ucast_pkts;
	uint64be_t	mlppc_rfc_2863_in_discards;
	uint64be_t	mlppc_rfc_2863_in_errors;
	uint64be_t	mlppc_rfc_2863_in_unknown_protos;
	uint64be_t	mlppc_rfc_2863_out_octets;
	uint64be_t	mlppc_rfc_2863_out_ucast_pkts;
	uint64be_t	mlppc_rfc_2863_out_discards;
	uint64be_t	mlppc_rfc_2863_out_errors;
	uint64be_t	mlppc_rfc_2863_in_mcast_pkts;
	uint64be_t	mlppc_rfc_2863_in_bcast_pkts;
	uint64be_t	mlppc_rfc_2863_out_mcast_pkts;
	uint64be_t	mlppc_rfc_2863_out_bcast_pkts;
} mlxcx_ppcnt_rfc_2863_t;

typedef struct {
	uint64be_t	mlppc_phy_stats_time_since_last_clear;
	uint64be_t	mlppc_phy_stats_rx_bits;
	uint64be_t	mlppc_phy_stats_symbol_errs;
	uint64be_t	mlppc_phy_stats_corrected_bits;
	uint8_t		mlppc_phy_stats_rsvd[2];
	uint8_t		mlppc_phy_stats_raw_ber_mag;
	uint8_t		mlppc_phy_stats_raw_ber_coef;
	uint8_t		mlppc_phy_stats_rsvd2[2];
	uint8_t		mlppc_phy_stats_eff_ber_mag;
	uint8_t		mlppc_phy_stats_eff_ber_coef;
} mlxcx_ppcnt_phy_stats_t;

typedef enum {
	MLXCX_PPCNT_GRP_IEEE_802_3	= 0x0,
	MLXCX_PPCNT_GRP_RFC_2863	= 0x1,
	MLXCX_PPCNT_GRP_RFC_2819	= 0x2,
	MLXCX_PPCNT_GRP_RFC_3635	= 0x3,
	MLXCX_PPCNT_GRP_ETH_EXTD	= 0x5,
	MLXCX_PPCNT_GRP_ETH_DISCARD	= 0x6,
	MLXCX_PPCNT_GRP_PER_PRIO	= 0x10,
	MLXCX_PPCNT_GRP_PER_TC		= 0x11,
	MLXCX_PPCNT_GRP_PER_TC_CONGEST	= 0x13,
	MLXCX_PPCNT_GRP_PHY_STATS	= 0x16
} mlxcx_ppcnt_grp_t;

typedef enum {
	MLXCX_PPCNT_CLEAR		= (1 << 7),
	MLXCX_PPCNT_NO_CLEAR		= 0
} mlxcx_ppcnt_clear_t;

typedef struct {
	uint8_t		mlrd_ppcnt_swid;
	uint8_t		mlrd_ppcnt_local_port;
	uint8_t		mlrd_ppcnt_pnat;
	uint8_t		mlrd_ppcnt_grp;
	uint8_t		mlrd_ppcnt_clear;
	uint8_t		mlrd_ppcnt_rsvd[2];
	uint8_t		mlrd_ppcnt_prio_tc;
	union {
		uint8_t				mlrd_ppcnt_data[248];
		mlxcx_ppcnt_ieee_802_3_t	mlrd_ppcnt_ieee_802_3;
		mlxcx_ppcnt_rfc_2863_t		mlrd_ppcnt_rfc_2863;
		mlxcx_ppcnt_phy_stats_t		mlrd_ppcnt_phy_stats;
	};
} mlxcx_reg_ppcnt_t;

typedef enum {
	MLXCX_PPLM_FEC_CAP_AUTO			= 0,
	MLXCX_PPLM_FEC_CAP_NONE			= (1 << 0),
	MLXCX_PPLM_FEC_CAP_FIRECODE		= (1 << 1),
	MLXCX_PPLM_FEC_CAP_RS			= (1 << 2),
} mlxcx_pplm_fec_caps_t;

typedef enum {
	MLXCX_PPLM_FEC_ACTIVE_NONE		= (1 << 0),
	MLXCX_PPLM_FEC_ACTIVE_FIRECODE		= (1 << 1),
	MLXCX_PPLM_FEC_ACTIVE_RS528		= (1 << 2),
	MLXCX_PPLM_FEC_ACTIVE_RS271		= (1 << 3),
	MLXCX_PPLM_FEC_ACTIVE_RS544		= (1 << 7),
	MLXCX_PPLM_FEC_ACTIVE_RS272		= (1 << 9),
} mlxcx_pplm_fec_active_t;

/* CSTYLED */
#define	MLXCX_PPLM_CAP_56G		(bitdef_t){ 16, 0x000f0000 }
/* CSTYLED */
#define	MLXCX_PPLM_CAP_100G		(bitdef_t){ 12, 0x0000f000 }
/* CSTYLED */
#define	MLXCX_PPLM_CAP_50G		(bitdef_t){ 8, 0x00000f00 }
/* CSTYLED */
#define	MLXCX_PPLM_CAP_25G		(bitdef_t){ 4, 0x000000f0 }
/* CSTYLED */
#define	MLXCX_PPLM_CAP_10_40G		(bitdef_t){ 0, 0x0000000f }

typedef struct {
	uint8_t		mlrd_pplm_rsvd;
	uint8_t		mlrd_pplm_local_port;
	uint8_t		mlrd_pplm_rsvd1[11];
	uint24be_t	mlrd_pplm_fec_mode_active;
	bits32_t	mlrd_pplm_fec_override_cap;
	bits32_t	mlrd_pplm_fec_override_admin;
	uint16be_t	mlrd_pplm_fec_override_cap_400g_8x;
	uint16be_t	mlrd_pplm_fec_override_cap_200g_4x;
	uint16be_t	mlrd_pplm_fec_override_cap_100g_2x;
	uint16be_t	mlrd_pplm_fec_override_cap_50g_1x;
	uint16be_t	mlrd_pplm_fec_override_admin_400g_8x;
	uint16be_t	mlrd_pplm_fec_override_admin_200g_4x;
	uint16be_t	mlrd_pplm_fec_override_admin_100g_2x;
	uint16be_t	mlrd_pplm_fec_override_admin_50g_1x;
	uint8_t		mlrd_pplm_rsvd2[8];
	uint16be_t	mlrd_pplm_fec_override_cap_hdr;
	uint16be_t	mlrd_pplm_fec_override_cap_edr;
	uint16be_t	mlrd_pplm_fec_override_cap_fdr;
	uint16be_t	mlrd_pplm_fec_override_cap_fdr10;
	uint16be_t	mlrd_pplm_fec_override_admin_hdr;
	uint16be_t	mlrd_pplm_fec_override_admin_edr;
	uint16be_t	mlrd_pplm_fec_override_admin_fdr;
	uint16be_t	mlrd_pplm_fec_override_admin_fdr10;
} mlxcx_reg_pplm_t;

typedef enum {
	MLXCX_REG_PMTU		= 0x5003,
	MLXCX_REG_PTYS		= 0x5004,
	MLXCX_REG_PAOS		= 0x5006,
	MLXCX_REG_PMAOS		= 0x5012,
	MLXCX_REG_MSGI		= 0x9021,
	MLXCX_REG_MLCR		= 0x902B,
	MLXCX_REG_MCIA		= 0x9014,
	MLXCX_REG_PPCNT		= 0x5008,
	MLXCX_REG_PPLM		= 0x5023,
} mlxcx_register_id_t;

typedef union {
	mlxcx_reg_pmtu_t		mlrd_pmtu;
	mlxcx_reg_paos_t		mlrd_paos;
	mlxcx_reg_ptys_t		mlrd_ptys;
	mlxcx_reg_mlcr_t		mlrd_mlcr;
	mlxcx_reg_pmaos_t		mlrd_pmaos;
	mlxcx_reg_mcia_t		mlrd_mcia;
	mlxcx_reg_ppcnt_t		mlrd_ppcnt;
	mlxcx_reg_pplm_t		mlrd_pplm;
} mlxcx_register_data_t;

typedef enum {
	MLXCX_CMD_ACCESS_REGISTER_READ		= 1,
	MLXCX_CMD_ACCESS_REGISTER_WRITE		= 0
} mlxcx_cmd_reg_opmod_t;

typedef struct {
	mlxcx_cmd_in_t	mlxi_access_register_head;
	uint8_t		mlxi_access_register_rsvd[2];
	uint16be_t	mlxi_access_register_register_id;
	uint32be_t	mlxi_access_register_argument;
	mlxcx_register_data_t	mlxi_access_register_data;
} mlxcx_cmd_access_register_in_t;

typedef struct {
	mlxcx_cmd_out_t	mlxo_access_register_head;
	uint8_t		mlxo_access_register_rsvd[8];
	mlxcx_register_data_t	mlxo_access_register_data;
} mlxcx_cmd_access_register_out_t;

#pragma pack()

CTASSERT(MLXCX_SQE_MAX_PTRS > 0);

#ifdef __cplusplus
}
#endif

#endif /* _MLXCX_REG_H */
