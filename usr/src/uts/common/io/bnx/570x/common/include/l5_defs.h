/*
 * Copyright 2014-2017 Cavium, Inc.
 * The contents of this file are subject to the terms of the Common Development
 * and Distribution License, v.1,  (the "License").
 *
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at available
 * at http://opensource.org/licenses/CDDL-1.0
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */


#ifndef _l5_defs_h_
#define _l5_defs_h_

#include "5706_reg.h"
#include "l2_defs.h"
#include "l2_ftq.h"

/* data structure defs: */

typedef struct ddp_tagged_msg_header
{
    u16_t   mpa_length;
	u16_t   control;
    u32_t   stag;
	u64_t   to;
} ddp_tagged_msg_header_t;

typedef struct ddp_untagged_msg_header
{
    u16_t   mpa_length;
	u16_t   control;
	union
	{
        u32_t   reserved;
        u32_t   invalidated_stag;
    } rdmap_rsvd;
	u32_t   queue_number;
	u32_t   msn;
	u32_t   mo;
} ddp_untagged_msg_header_t;

typedef struct rdmap_read_request_header
{
    ddp_untagged_msg_header_t  ddp_header;
	u32_t  sink_stag;
	u64_t  sink_to;
	u32_t  length;
	u32_t  source_stag;
	u64_t  source_to;
} rdmap_read_request_header_t;


/****************************************************************************
 * L5 Window Reference Count Table Entry
 ****************************************************************************/

typedef struct l5_window_ref_cnt_table_entry
{
    u8_t wrcte_pidx;    /* Incremented by CP whenever a SQ work request or
                           incoming RDMA Read Request is processed that
                           references the associated window for source data. */

    u8_t wrcte_cidx;    /* Incremented by COM whenever an entry is removed from
                           the command queue where the associated window is
                           the data source. */

} l5_window_ref_cnt_table_entry_t;


/* constants and macros: */

#define   RDMA_WRITE_CMD      0
#define   RDMA_READ_REQ_CMD   1
#define   RDMA_READ_RSP_CMD   2
#define   RDMA_SEND_CMD       3
#define   RDMA_SEND_W_EVENT   4

#define   RDMA_MPA_HDR_LENGTH            2
#define   RDMA_MPA_CRC_LENGTH            4
#define   RDMA_MPA_MARKER_SIZE           4

#define   RDMA_DDP_TAGGED_HDR_LENGTH     14
#define   RDMA_DDP_UNTAGGED_HDR_LENGTH   18

#define   RDMA_READ_REQ_MSG_LENGTH       28

#define   RDMA_WRITE_HDR_LENGTH          (RDMA_MPA_HDR_LENGTH + RDMA_DDP_TAGGED_HDR_LENGTH)
#define   RDMA_SEND_MSG_HDR_LENGTH       (RDMA_MPA_HDR_LENGTH + RDMA_DDP_UNTAGGED_HDR_LENGTH)
#define   RDMA_READ_REQ_HDR_LENGTH       (RDMA_MPA_HDR_LENGTH + RDMA_DDP_UNTAGGED_HDR_LENGTH + RDMA_READ_REQ_MSG_LENGTH)
#define   RDMA_READ_RESP_HDR_LENGTH      (RDMA_MPA_HDR_LENGTH + RDMA_DDP_TAGGED_HDR_LENGTH)

#define   RDMA_STANDARD_L5_OVERHEAD (RDMA_STANDARD_HDR_LENGTH + RDMA_MPA_HDR_LENGTH + RDMA_MPA_CRC_LENGTH)
#define   RDMA_READ_REQ_L5_OVERHEAD (RDMA_READ_REQ_HDR_LENGTH + RDMA_MPA_HDR_LENGTH + RDMA_MPA_CRC_LENGTH)

#define   RDMA_SEND_QUEUE_NUMBER    0x00000000
#define   RDMA_READ_QUEUE_NUMBER    0x00000001
#define   RDMA_TERM_QUEUE_NUMBER    0x00000002

#define   RDMA_MPA_MARKER_INTERVAL       512                                                /* MPA marker interval */
#define   RDMA_DATA_MARKER_INTERVAL      (RDMA_MPA_MARKER_INTERVAL - RDMA_MPA_MARKER_SIZE)  /* Data between markers */
#define   RDMA_MPA_MARKER_INTERVAL_SHIFT   9

#define   DDP_CTRL_RDMA_WRITE           0x8000
#define   DDP_CTRL_RDMA_READ_REQ        0x0001
#define   DDP_CTRL_RDMA_READ_RSP        0x8002
#define   DDP_CTRL_SEND_MSG             0x0003
#define   DDP_CTRL_SEND_INV_MSG         0x0004
#define   DDP_CTRL_SEND_EVT_MSG         0x0005
#define   DDP_CTRL_SEND_INV_EVT_MSG     0x0006

#define   DDP_CTRL_L_BIT                0x4000
#define   DDP_CTRL_T_BIT                0x8000

#define   DDP_CTRL_DDP_VERSION_MASK     0x0300
#define   DDP_CTRL_DDP_VERSION          0x0000

#define   DDP_TAGGED_HDR_LENGTH         14
#define   DDP_UNTAGGED_HDR_LENGTH       18

#define   DDP_QN_SEND_MESSAGE_QUEUE       0x00000000
#define   DDP_QN_RDMA_READ_REQUEST_QUEUE  0x00000001
#define   DDP_QN_RDMA_TERMINATE_QUEUE     0x00000002

#define   DDP_MAX_UNTAGGED_QUEUES         0x00000003

#define   RDMAP_CTRL_RDMAP_VERSION_MASK   0x00C0
#define   RDMAP_CTRL_RDMAP_VERSION        0x0000

#define   RDMAP_CTRL_RDMAP_OPCODE_MASK    0x0F

#define   RDMAP_CTRL_RDMA_WRITE           0x00
#define   RDMAP_CTRL_RDMA_READ_REQ        0x01
#define   RDMAP_CTRL_RDMA_READ_RSP        0x02
#define   RDMAP_CTRL_SEND_MSG             0x03
#define   RDMAP_CTRL_SEND_W_INV_MSG       0x04
#define   RDMAP_CTRL_SEND_W_EVT_MSG       0x05
#define   RDMAP_CTRL_SEND_W_INV_EVT_MSG   0x06

#define   L5_MEMORY_REGION_STAG_BIT       0x00800000
#define   L5_STAG_INDEX_MASK              0x00FFFFFF
#define   L5_STAG_KEY_MASK                0xFF000000
#define   L5_MIN_HOST_PAGE_SIZE           0x100    /* 256 bytes */
#define   L5_WINDOW_CACHE_KEY_BASE        0x2000


/* define context memory-related constants for things
   like STag validation: */

#define   L5_RX_VCID_SIZE                 128


/* L5 RxP protocol errors: */

#define   RX_PROTO_ERR_MPA_LEN_NON_MULT_FOUR     0x00000001
#define   RX_PROTO_ERR_INVALID_MPA_LEN           0x00000002
#define   RX_PROTO_ERR_INVALID_MARKER            0x00000003
#define   RX_PROTO_ERR_INVALID_TAGGED_OPCODE     0x00000004
#define   RX_PROTO_ERR_INVALID_UNTAGGED_OPCODE   0x00000005

#define   RX_PROTO_ERR_STAG_INVALID              0x00000006
#define   RX_PROTO_ERR_STAG_BASE_BOUNDS          0x00000007
#define   RX_PROTO_ERR_STAG_ACCESS_RIGHTS        0x00000008
#define   RX_PROTO_ERR_STAG_PROTECTION           0x00000009
#define   RX_PROTO_ERR_STAG_TO_WRAP              0x0000000A

#define   RX_PROTO_ERR_INVALID_DDP_VERSION       0x0000000B
#define   RX_PROTO_ERR_INVALID_RDMAP_VERSION     0x0000000C
#define   RX_PROTO_ERR_INVALID_DDP_QUEUE_NUMBER  0x0000000D
#define   RX_PROTO_ERR_IRD_EXCEEDED              0x0000000E

#define   RX_PROTO_ERR_MSN_GAP                   0x0000000F
#define   RX_PROTO_ERR_MSN_RANGE                 0x00000010

#define   RX_PROTO_ERR_NO_RCV_BUFF_AVAIL         0x00000011
#define   RX_PROTO_ERR_RCV_BASE_BOUNDS           0x00000012
#define   RX_PROTO_ERR_RCV_MO_WRAP               0x00000013

#define   RX_PROTO_ERR_INVALID_MPA_CRC           0x00000014

#define   RX_PROTO_ERR_NO_RCV_BUFF_POSTED        0x00000080

#define   RX_PROTO_ERR_TERM_MSG_RECEIVED         0x000000FF

/* L5 */
#define L5_TCP_MAX_DACK		2

/* Iscsi */

//#define THIN_CONN_ESTAB

#define RDMA_CONFIG_CRC_OFFSET_SHIFT	18

#define VCID_SIZE          128
#define VCID_SHIFT         7

#define CID_ENC(_idx)      ((_idx)<<VCID_SHIFT)

#define CID_ISCSI_CONF_PARAMS CID_ENC(46) // context ID of iSCSI configuration params

#define	MAX_RQ_BUF_SIZE			256
#define ISCSI_CRC_SIZE			4
#define ISCSI_CRC_SIZE_LOG2		2
#define ISCSI_HDR_SIZE			48
#define ISCSI_CRC_RESULT		0x1c2d19ed

#define ISCSI_CRC_TABLE_SIZE 256

#define ISCSI_PROCESS_ERROR			(-1)
#define ISCSI_PROCESS_WARNING		(-2)
#define ISCSI_SILENT_DROP			(-3)

/* Completion types */
#define ISCSI_COMP_TYPE_MP			(0<<0)
#define ISCSI_COMP_TYPE_FP			(1<<0)

/* Command types for placement in RV2P */
#define ISCSI_PLACE_TYPE_RQ			(0<<0)
#define ISCSI_PLACE_TYPE_SGL		(1<<0)

/* RV2P iscsi placement opcodes */
#define GENERIC_OPCODE_RV2PPQ_VALUE_ISCSI_SGL_PLACE	(22<<0)
#define GENERIC_OPCODE_RV2PPQ_VALUE_ISCSI_RQ_PLACE 	(23<<0)
#define GENERIC_OPCODE_RV2PPQ_VALUE_ISCSI_RQ_FLUSH	(24<<0)
#define GENERIC_OPCODE_RV2PPQ_VALUE_ISCSI_SGL_FLUSH	(25<<0)

/* COM L5 (iSCSI/RDMA) opaque types */
#define L5_OPAQUE_TCP_ACK_TYPE			(0x80)
#define L5_OPAQUE_TCP_ERROR_TYPE		(0x81)

/* COM iSCSI opaque types */
#define ISCSI_OPAQUE_COMPLETION_TYPE	(0x82)
#define ISCSI_OPAQUE_FREE_MBUF_TYPE		(0x83)
#define ISCSI_OPAQUE_ERROR_TYPE			(0x84)
#define ISCSI_OPAQUE_FREE_CU_MBUF_TYPE  (0x85)

#define HDR_ISCSI_OPCODE			(0x3f<<0)

#define ISCSI_INVALID_VALUE			(0xffffffff)

#define TCP_L5CM_MAX_RETRIES 3

typedef struct iscsi_ctx_offsets
{
    u32_t task_offset;     // offset of the task array
    u32_t r2tq_offset;     // offset of R2TQ section

    u32_t max_num_of_tasks;     // maximal number of pending tasks 
    u32_t max_num_of_ccells;    // maximal number of ccells 
} iscsi_ctx_offsets_t;


/*
 *  rv2ppq_iscsi_sgl_place definition
 */
typedef struct rv2ppq_iscsi_sgl_place
{
	u32_t	iscsi_sgl_place_cid;
	u32_t 	iscsi_sgl_place_mbuf_cluster;
	u16_t 	iscsi_sgl_place_operand_flags;
		#define ISCSI_PLACE_OPERAND_FLAGS_LAST_PKT		(1<<7)
        #define ISCSI_PLACE_OPERAND_FLAGS_FLUSH			(1<<11)
		#define ISCSI_PLACE_OPERAND_FLAGS_USE_SEED		(1<<12)
		#define ISCSI_PLACE_OPERAND_FLAGS_DIGEST_EN		(1<<13)
		#define ISCSI_PLACE_OPERAND_FLAGS_COMPLETE		(1<<14)
        /* overloading bit 14 */
        #define ISCSI_PLACE_OPERAND_FLAGS_CU_PKT        (1<<14)  
		#define ISCSI_PLACE_OPERAND_FLAGS_FREE_MBUF		(1<<15)

	u8_t	iscsi_sgl_place_tcp_flags;
	u8_t	iscsi_sgl_place_opcode;
    u16_t 	iscsi_sgl_place_offset; //cut in COM
	u16_t 	iscsi_sgl_place_length; //cut in COM
	u16_t 	iscsi_sgl_place_ctx_offset_to_pad_baddr;
	u16_t 	iscsi_sgl_place_num_pad_bytes;
	u32_t	iscsi_sgl_place_reserved1;
	u32_t	iscsi_sgl_place_tcp_ack_sn;
	u32_t	iscsi_sgl_place_reserved2[2]; //cut in COM
	u32_t	iscsi_sgl_place_crc_seed;
		#define ISCSI_PLACE_CRC_SEED_VAL		(0xFFFFFFFF)

	u32_t	iscsi_sgl_place_task_cache_key;
	u32_t	iscsi_sgl_place_task_cid;
	u32_t	iscsi_sgl_place_rdma_action;
} rv2ppq_iscsi_sgl_place_t;

/*
 *  rv2ppq_iscsi_rq_place definition
 */
typedef struct rv2ppq_iscsi_rq_place
{
	u32_t	iscsi_rq_place_cid;
	u32_t	iscsi_rq_place_mbuf_cluster;
	u16_t	iscsi_rq_place_operand_flags;
		#define ISCSI_PLACE_OPERAND_FLAGS_PAGE_SIZE_SHIFT	(8)
		#define ISCSI_PLACE_OPERAND_FLAGS_PAGE_SIZE_MASK	(0xf<<8)

	u8_t	iscsi_rq_place_tcp_flags;
	u8_t	iscsi_rq_place_opcode;
	u16_t	iscsi_rq_place_offset; //cut in COM
	u16_t	iscsi_rq_place_length; //cut in COM
	u16_t	iscsi_rq_place_ctx_offset_to_pad_baddr;
	u16_t 	iscsi_rq_place_num_pad_bytes;
    u32_t	iscsi_rq_place_first_page_offset;
	u32_t	iscsi_rq_place_tcp_ack_sn;
	u32_t	iscsi_rq_place_page_table_base_addr_h; //cut in COM
	u32_t	iscsi_rq_place_page_table_base_addr_l; //cut in COM
	u32_t	iscsi_rq_place_crc_seed;
	u32_t	iscsi_rq_place_rbdc_key;
    u32_t	iscsi_rq_place_rq_buffer_offset;
	u32_t	iscsi_rq_place_rdma_action;
} rv2ppq_iscsi_rq_place_t;

/*
 *  rv2ppq_iscsi_sgl_flush definition
 */
typedef struct rv2ppq_iscsi_sgl_flush
{
	u32_t	iscsi_sgl_flush_task_cid;
	u32_t 	iscsi_sgl_flush_unused_a;
	u16_t	iscsi_sgl_flush_unsused_b;
	u8_t	iscsi_sgl_flush_unsused_c;
	u8_t	iscsi_sgl_flush_opcode;
	u32_t	iscsi_sgl_flush_unsused_d[9];
} rv2ppq_iscsi_sgl_flush_t;

/*
 *  rv2ppq_iscsi_rq_flush definition
 */
typedef struct rv2ppq_iscsi_rq_flush 
{
	u32_t	iscsi_rq_flush_cid;
	u32_t	iscsi_rq_flush_unsused_a;
	u16_t	iscsi_rq_flush_unsused_b;
	u8_t	iscsi_rq_flush_unsused_c;
	u8_t	iscsi_rq_flush_opcode;
	u32_t	iscsi_rq_flush_unsused_d;
	u16_t	iscsi_rq_flush_rbdc_key;
	u16_t	iscsi_rq_flush_unsused_e;
	u32_t	iscsi_rq_flush_unsused_f[7];
	u32_t	iscsi_rq_flush_rdma_spec;
} rv2ppq_iscsi_rq_flush_t;

/*
 *  comq_iscsi_sgl_place definition
 */
typedef struct comq_iscsi_sgl_place
{
	u32_t	cid;
	u32_t	mbuf_cluster;
	u16_t	operand_flags;
	u8_t	tcp_flags;
	u8_t	opcode;
	u16_t   ctx_offset_to_pad_baddr;
	u16_t	num_pad_bytes;
	u32_t   unused;
	u32_t   tcp_ack_sn;
	u32_t   crc_result;
	u32_t   reserved;
	u32_t   task_cid;

} comq_iscsi_sgl_place_t;

typedef struct itt32_fields 
{
	u32_t   task_rsrv	: 16;
	u32_t 	task_type 	: 2;
	u32_t   task_idx 	: 14;
	
} itt32_fields_t;

typedef union itt32_union 
{
    itt32_fields_t 	fields;
    u32_t           itt32;

} itt32_union_t;

/*
 *  rv2ppq_opaque_iscsi definition
 */
typedef struct rv2ppq_opaque_iscsi_comp_msg_a
{
	u32_t	cid;
	u8_t	unused_a;
	u8_t	iscsi_err_code;
    u16_t	hdr_itt;
	u16_t	opaque_flags_opcode;
	u8_t	tcp_flags;				// Only 8 bits relevant
	u8_t	opcode;
	u16_t 	o_iscsi_unused_b[2];
	u32_t	hdr_dword0;
	u32_t	hdr_dword1;
	u32_t	tcp_ack_sn;
    u32_t 	o_iscsi_unused_c[2];
	u32_t	hdr_exp_cmd_sn;
	u32_t	hdr_max_cmd_sn;
	u32_t	hdr_res_count;
} rv2ppq_opaque_iscsi_comp_msg_a_t;

typedef struct rv2ppq_opaque_iscsi_comp_msg_b
{
	u32_t	cid;
	u32_t	reserved0;
    u16_t	opaque_flags_opcode;
	u8_t	reserved1;
	u8_t	opcode;
	u16_t 	o_iscsi_unused_a[2];
    u32_t	hdr_dword2;
	u32_t	hdr_dword3;
	u32_t	hdr_ttt;
    u32_t 	o_iscsi_unused_b[2];
	u32_t	hdr_stat_sn;
	u32_t	hdr_dword9;
	u32_t	hdr_dword10;
} rv2ppq_opaque_iscsi_comp_msg_b_t;

typedef struct rv2ppq_opaque_iscsi_free_mbuf
{
	u32_t	cid;
	u32_t 	mbuf_cluster;
	u16_t	opaque_flags_opcode;
	u8_t	rsrv;
	u8_t	opcode;
	u16_t 	o_iscsi_unused_a[2];
	u16_t 	o_iscsi_allowed16[6];
	u32_t 	o_iscsi_unused_b[2];
	u32_t 	o_iscsi_allowed32[3];
} rv2ppq_opaque_iscsi_free_mbuf_t;

typedef union rv2ppq_opaque_iscsi
{
	rv2ppq_opaque_iscsi_comp_msg_a_t	rv2p_o_comp_msg_a;
    rv2ppq_opaque_iscsi_comp_msg_b_t	rv2p_o_comp_msg_b;
	rv2ppq_opaque_iscsi_free_mbuf_t		rv2p_o_free_mbuf;

} rv2ppq_opaque_iscsi_t;

// Used for TCP messages from RXP to COM (Mutual to RDMA and iSCSI)
typedef struct rv2ppq_opaque_l5
{
	u32_t	cid;
	u32_t 	o_l5_allowed32_a;
	u16_t	opaque_flags_opcode;
	u8_t	tcp_flags;
	u8_t	opcode;
	u16_t 	o_l5_unused_a[2];
	u16_t 	o_l5_allowed16[4];
	u32_t	tcp_ack_sn;
	u32_t 	o_l5_unused_b[2];
	u32_t 	o_l5_allowed32_b[3];
} rv2ppq_opaque_l5_t;

/*
 *  comq_opaque_iscsi definition
 */
typedef struct comq_opaque_iscsi_comp_msg_a
{
	u32_t	cid;
	u8_t	unused;
	u8_t	iscsi_err_code;
    u16_t	hdr_itt;
	u16_t	opaque_flags_opcode;
	u8_t	tcp_flags;				// Only 8 bits relevant
	u8_t	opcode;
    u32_t	hdr_dword0;
	u32_t	hdr_dword1;
	u32_t	tcp_ack_sn;
	u32_t	hdr_exp_cmd_sn;
	u32_t	hdr_max_cmd_sn;
	u32_t	hdr_res_count;

} comq_opaque_iscsi_comp_msg_a_t;

typedef struct comq_opaque_iscsi_comp_msg_b
{
	u32_t	cid;
	u32_t	reserved0;
	u16_t	opaque_flags_opcode;
	u8_t	reserved1;
	u8_t	opcode;
	u32_t	hdr_dword2;
	u32_t	hdr_dword3;
    u32_t	hdr_ttt;
	u32_t	hdr_stat_sn;
	u32_t	hdr_dword9;
	u32_t	hdr_dword10;

} comq_opaque_iscsi_comp_msg_b_t;

typedef union comq_opaque_iscsi
{
	comq_opaque_iscsi_comp_msg_a_t 	com_o_comp_msg_a;
	comq_opaque_iscsi_comp_msg_b_t 	com_o_comp_msg_b;

} comq_opaque_iscsi_t;

// TCP opaque message for L5 (no data)
typedef struct comq_opaque_l5
{
	u32_t	cid;
	u32_t 	o_l5_allowed32_a;
	u16_t	opaque_flags_opcode;
	u8_t	tcp_flags;
	u8_t	opcode;
	u16_t 	o_l5_allowed16[4];
	u32_t	tcp_ack_sn;
    u32_t 	o_l5_allowed32_b[3];

} comq_opaque_l5_t;

typedef struct rv2ppq_opaque_iscsi_kcqe_comp
{
    u32_t cid;                                           
    u32_t iscsi_conn_id;                                           
    u16_t opaque_flags_opcode;                              
    u8_t reserved1;                                          
    u8_t opcode;                                         
    u16_t unused_a[2];
	u32_t reserved2[3];
    u32_t unused_b[2];
	u32_t status_code;
    u32_t reserved3[2];
} rv2ppq_opaque_iscsi_kcqe_comp_t;

typedef struct comq_opaque_iscsi_kcqe_comp
{
	u32_t cid;                                           
	u32_t iscsi_conn_id;                                           
	u16_t opaque_flags_opcode;                              
	u8_t reserved1;                                          
	u8_t opcode;                                         
	u32_t reserved2[3];
	u32_t status_code;
	u32_t reserved3[2];

} comq_opaque_iscsi_kcqe_comp_t;

// L5 context manager parameters context struct
typedef struct l5_cm_fixed_connect_context
{
    u32_t fixed_seed /* 32 bits of secret passed by the driver for port 0 */; 
    u32_t rsrv[31] /*  */; 

} l5_cm_fixed_connect_context_t; 

// TCP general message for L5
typedef struct comq_l5_tcp
{
	u32_t	cid;
	u32_t	reserved0;
	u16_t	reserved1;
	u8_t	tcp_flags;
		#define L5_FLAGS_TCP_SMALL_WIN		(1<<0)
		#define L5_FLAGS_TCP_SILENT_DROP	(1<<1)
		#define L5_FLAGS_TCP_RELEASE_MBUF	(1<<2)
		#define L5_FLAGS_TCP_ACK_PROCESS	(1<<3)
		#define L5_FLAGS_TCP_PURE_ACK		(1<<4) // No payload and no window update
		#define L5_FLAGS_TCP_IP_FRAG		(1<<5)
		#define L5_FLAGS_TCP_IP_OPTION		(1<<6)
		#define L5_FLAGS_TCP_URGENT_FLAG	(1<<7)

	u8_t	reserved2;
    u32_t	reserved3[2];
	u32_t	tcp_ack_sn;
	u32_t	reserved4[3];

} comq_l5_tcp_t;




/*
 *  rv2ppq_l5_place definition
 */
typedef struct rv2ppq_l5_place_b
{
    u32_t l5_place_cid;
    u32_t l5_place_mbuf_cluster;
    u16_t l5_place_operand_flags;
        #define L5_PLACE_OPERAND_FLAGS_MARKERS_PRESENT      (1<<0)
        #define L5_PLACE_OPERAND_FLAGS_NEW_ISLAND           (1<<1)
        #define L5_PLACE_OPERAND_FLAGS_TCP_HOLE_CLOSED      (1<<2)
        #define L5_PLACE_OPERAND_FLAGS_IN_ORDER             (1<<3)
        #define L5_PLACE_OPERAND_FLAGS_LBIT_STATUS          (1<<4)
        #define L5_PLACE_OPERAND_FLAGS_FLUSH                (1<<5)
        #define L5_PLACE_OPERAND_FLAGS_PG_SZ                (0xf<<8)
            #define L5_PLACE_OPERAND_FLAGS_PG_SZ_256        (0<<8)
            #define L5_PLACE_OPERAND_FLAGS_PG_SZ_512        (1<<8)
            #define L5_PLACE_OPERAND_FLAGS_PG_SZ_1K         (2<<8)
            #define L5_PLACE_OPERAND_FLAGS_PG_SZ_2K         (3<<8)
            #define L5_PLACE_OPERAND_FLAGS_PG_SZ_4K         (4<<8)
            #define L5_PLACE_OPERAND_FLAGS_PG_SZ_8K         (5<<8)
            #define L5_PLACE_OPERAND_FLAGS_PG_SZ_16K        (6<<8)
            #define L5_PLACE_OPERAND_FLAGS_PG_SZ_32K        (7<<8)
            #define L5_PLACE_OPERAND_FLAGS_PG_SZ_64K        (8<<8)
            #define L5_PLACE_OPERAND_FLAGS_PG_SZ_128K       (9<<8)
            #define L5_PLACE_OPERAND_FLAGS_PG_SZ_256K       (10<<8)
            #define L5_PLACE_OPERAND_FLAGS_PG_SZ_512K       (11<<8)
            #define L5_PLACE_OPERAND_FLAGS_PG_SZ_1M         (12<<8)
            #define L5_PLACE_OPERAND_FLAGS_PG_SZ_2M         (13<<8)
            #define L5_PLACE_OPERAND_FLAGS_PG_SZ_4M         (14<<8)
            #define L5_PLACE_OPERAND_FLAGS_PG_SZ_8M         (15<<8)

    u8_t l5_place_knum;
    u8_t l5_place_opcode;
    u16_t l5_place_offset;
    u16_t l5_place_length;
    u16_t l5_place_offset_to_first_marker;
    u16_t l5_place_rbdc_key;
    u32_t l5_place_first_page_offset;
    u16_t l5_place_l5_header_length;
    u16_t l5_place_l5_cmd_type;
        #define L5_PLACE_L5_CMD_TYPE_CMD_VALUE              (0xf<<0)
            #define L5_PLACE_L5_CMD_TYPE_CMD_VALUE_UNDEFINED  (0<<0)
            #define L5_PLACE_L5_CMD_TYPE_CMD_VALUE_SEND     (1<<0)
            #define L5_PLACE_L5_CMD_TYPE_CMD_VALUE_SEND_W_SE  (2<<0)
            #define L5_PLACE_L5_CMD_TYPE_CMD_VALUE_SEND_W_INV  (3<<0)
            #define L5_PLACE_L5_CMD_TYPE_CMD_VALUE_SEND_W_SE_INV  (4<<0)
            #define L5_PLACE_L5_CMD_TYPE_CMD_VALUE_RDMA_WRITE  (5<<0)
            #define L5_PLACE_L5_CMD_TYPE_CMD_VALUE_RDMA_READ  (6<<0)
            #define L5_PLACE_L5_CMD_TYPE_CMD_VALUE_RDMA_READ_W_INV  (7<<0)
            #define L5_PLACE_L5_CMD_TYPE_CMD_VALUE_WINDOW_BIND  (8<<0)
            #define L5_PLACE_L5_CMD_TYPE_CMD_VALUE_FAST_REGISTER  (9<<0)
            #define L5_PLACE_L5_CMD_TYPE_CMD_VALUE_LOCAL_INVALIDATE  (10<<0)
            #define L5_PLACE_L5_CMD_TYPE_CMD_VALUE_RDMA_READ_RESPONSE  (11<<0)
            #define L5_PLACE_L5_CMD_TYPE_CMD_VALUE_TCP_ACK  (12<<0)

    u32_t l5_place_page_table_base_addr_h;
    u32_t l5_place_page_table_base_addr_l;
    u32_t l5_place_tcp_ack_seq;
    u32_t l5_place_sink_bfr_target_offset_h;
    u32_t l5_place_sink_bfr_target_offset_l;
    u8_t l5_place_rdma_action;  // no need to be cleared by RXP, RV2P will do it
    u8_t l5_place_cs16_pkt_len;
    u16_t l5_place_cs16;
} rv2ppq_l5_place_b_t;

typedef struct rv2ppq_l5_place_l
{
    u32_t l5_place_cid;
    u32_t l5_place_mbuf_cluster;
    u8_t l5_place_opcode;
    u8_t l5_place_knum;
    u16_t l5_place_operand_flags;
    u16_t l5_place_length;
    u16_t l5_place_offset;
    u16_t l5_place_rbdc_key;
    u16_t l5_place_offset_to_first_marker;
    u32_t l5_place_first_page_offset;
    u16_t l5_place_l5_cmd_type;
    u16_t l5_place_l5_header_length;
    u32_t l5_place_page_table_base_addr_h;
    u32_t l5_place_page_table_base_addr_l;
    u32_t l5_place_tcp_ack_seq;
    u32_t l5_place_sink_bfr_target_offset_h;
    u32_t l5_place_sink_bfr_target_offset_l;
    u16_t l5_place_cs16;
    u8_t l5_place_cs16_pkt_len;
    u8_t l5_place_rdma_action;  // no need to be cleared by RXP, RV2P will do it
} rv2ppq_l5_place_l_t;

#if defined(LITTLE_ENDIAN)
    typedef rv2ppq_l5_place_l_t rv2ppq_l5_place_t;
#elif defined(BIG_ENDIAN)
    typedef rv2ppq_l5_place_b_t rv2ppq_l5_place_t;
#endif


/*
 *  rv2ppq_l5_flush definition
 */
typedef struct rv2ppq_l5_flush_b
{
    u32_t unused_0[2];
    u16_t unused_1;
    u8_t unused_2;
    u8_t l5_flush_opcode;
    u32_t unused_3;
    u16_t l5_flush_rbdc_key;
    u16_t unused_4;
    u32_t unused_5[7];
    u8_t l5_flush_rdma_action;  // no need to be cleared by RXP, RV2P will do it
    u8_t l5_flush_cs16_pkt_len;
    u16_t l5_flush_cs16;
} rv2ppq_l5_flush_b_t;

typedef struct rv2ppq_l5_flush_l
{
    u32_t unused_0[2];
    u8_t l5_flush_opcode;
    u8_t unused_2;
    u16_t unused_1;
    u32_t unused_3;
    u16_t unused_4;
    u16_t l5_flush_rbdc_key;
    u32_t unused_5[7];
    u16_t l5_flush_cs16;
    u8_t l5_flush_cs16_pkt_len;
    u8_t l5_flush_rdma_action;  // no need to be cleared by RXP, RV2P will do it
} rv2ppq_l5_flush_l_t;

#if defined(LITTLE_ENDIAN)
    typedef rv2ppq_l5_flush_l_t rv2ppq_l5_flush_t;
#elif defined(BIG_ENDIAN)
    typedef rv2ppq_l5_flush_b_t rv2ppq_l5_flush_t;
#endif



/*
 *  comq_l5_place definition
 */
typedef struct comq_l5_place_b
{
    u32_t l5_place_cid;
    u32_t l5_place_mbuf_cluster;
    u16_t l5_place_operand_flags;
        #define L5_PLACE_OPERAND_FLAGS_MARKERS_PRESENT      (1<<0)
        #define L5_PLACE_OPERAND_FLAGS_NEW_ISLAND           (1<<1)
        #define L5_PLACE_OPERAND_FLAGS_TCP_HOLE_CLOSED      (1<<2)
        #define L5_PLACE_OPERAND_FLAGS_IN_ORDER             (1<<3)
        #define L5_PLACE_OPERAND_FLAGS_LBIT_STATUS          (1<<4)
        #define L5_PLACE_OPERAND_FLAGS_PG_SZ                (0xf<<8)
            #define L5_PLACE_OPERAND_FLAGS_PG_SZ_256        (0<<8)
            #define L5_PLACE_OPERAND_FLAGS_PG_SZ_512        (1<<8)
            #define L5_PLACE_OPERAND_FLAGS_PG_SZ_1K         (2<<8)
            #define L5_PLACE_OPERAND_FLAGS_PG_SZ_2K         (3<<8)
            #define L5_PLACE_OPERAND_FLAGS_PG_SZ_4K         (4<<8)
            #define L5_PLACE_OPERAND_FLAGS_PG_SZ_8K         (5<<8)
            #define L5_PLACE_OPERAND_FLAGS_PG_SZ_16K        (6<<8)
            #define L5_PLACE_OPERAND_FLAGS_PG_SZ_32K        (7<<8)
            #define L5_PLACE_OPERAND_FLAGS_PG_SZ_64K        (8<<8)
            #define L5_PLACE_OPERAND_FLAGS_PG_SZ_128K       (9<<8)
            #define L5_PLACE_OPERAND_FLAGS_PG_SZ_256K       (10<<8)
            #define L5_PLACE_OPERAND_FLAGS_PG_SZ_512K       (11<<8)
            #define L5_PLACE_OPERAND_FLAGS_PG_SZ_1M         (12<<8)
            #define L5_PLACE_OPERAND_FLAGS_PG_SZ_2M         (13<<8)
            #define L5_PLACE_OPERAND_FLAGS_PG_SZ_4M         (14<<8)
            #define L5_PLACE_OPERAND_FLAGS_PG_SZ_8M         (15<<8)

    u8_t l5_place_knum;
    u8_t l5_place_opcode;
    u16_t l5_place_offset_to_first_marker;
    u16_t l5_place_rbdc_key;
    u32_t l5_place_first_page_offset;
    u16_t l5_place_l5_header_length;
    u16_t l5_place_l5_cmd_type;
        #define L5_PLACE_L5_CMD_TYPE_CMD_VALUE              (0xf<<0)
            #define L5_PLACE_L5_CMD_TYPE_CMD_VALUE_UNDEFINED  (0<<0)
            #define L5_PLACE_L5_CMD_TYPE_CMD_VALUE_SEND     (1<<0)
            #define L5_PLACE_L5_CMD_TYPE_CMD_VALUE_SEND_W_SE  (2<<0)
            #define L5_PLACE_L5_CMD_TYPE_CMD_VALUE_SEND_W_INV  (3<<0)
            #define L5_PLACE_L5_CMD_TYPE_CMD_VALUE_SEND_W_SE_INV  (4<<0)
            #define L5_PLACE_L5_CMD_TYPE_CMD_VALUE_RDMA_WRITE  (5<<0)
            #define L5_PLACE_L5_CMD_TYPE_CMD_VALUE_RDMA_READ  (6<<0)
            #define L5_PLACE_L5_CMD_TYPE_CMD_VALUE_RDMA_READ_W_INV  (7<<0)
            #define L5_PLACE_L5_CMD_TYPE_CMD_VALUE_WINDOW_BIND  (8<<0)
            #define L5_PLACE_L5_CMD_TYPE_CMD_VALUE_FAST_REGISTER  (9<<0)
            #define L5_PLACE_L5_CMD_TYPE_CMD_VALUE_LOCAL_INVALIDATE  (10<<0)
            #define L5_PLACE_L5_CMD_TYPE_CMD_VALUE_RDMA_READ_RESPONSE  (11<<0)
            #define L5_PLACE_L5_CMD_TYPE_CMD_VALUE_TCP_ACK  (12<<0)

    u32_t l5_place_tcp_ack_seq;
    u32_t l5_place_sink_bfr_target_offset_h;
    u32_t l5_place_sink_bfr_target_offset_l;
    u8_t l5_place_rdma_action;
    u8_t l5_place_cs16_pkt_len;
    u16_t l5_place_cs16;
} comq_l5_place_b_t;

typedef struct comq_l5_place_l

{
    u32_t l5_place_cid;
    u32_t l5_place_mbuf_cluster;
    u8_t l5_place_opcode;
    u8_t l5_place_knum;
    u16_t l5_place_operand_flags;
    u16_t l5_place_rbdc_key;
    u16_t l5_place_offset_to_first_marker;
    u32_t l5_place_first_page_offset;
    u16_t l5_place_l5_cmd_type;
    u16_t l5_place_l5_header_length;
    u32_t l5_place_tcp_ack_seq;
    u32_t l5_place_sink_bfr_target_offset_h;
    u32_t l5_place_sink_bfr_target_offset_l;
    u16_t l5_place_cs16;
    u8_t l5_place_cs16_pkt_len;
    u8_t l5_place_rdma_action;
} comq_l5_place_l_t;

#if defined(LITTLE_ENDIAN)
    typedef comq_l5_place_l_t comq_l5_place_t;
#elif defined(BIG_ENDIAN)
    typedef comq_l5_place_b_t comq_l5_place_t;
#endif


/*
 *  comq_l5_flush definition
 */
typedef struct comq_l5_flush_b
{
    u32_t unused_0[2];
    u16_t unused_1;
    u8_t unused_2;
    u8_t l5_flush_opcode;
    u16_t l5_flush_rbdc_key;
    u16_t unused_3;
    u32_t unused_4[5];
    u8_t l5_flush_rdma_action;
    u8_t l5_flush_cs16_pkt_len;
    u16_t l5_flush_cs16;
} comq_l5_flush_b_t;

typedef struct comq_l5_flush_l
{
    u32_t unused_0[2];
    u8_t l5_flush_opcode;
    u8_t unused_2;
    u16_t unused_1;
    u16_t unused_3;
    u16_t l5_flush_rbdc_key;
    u32_t unused_4[5];
    u16_t l5_flush_cs16;
    u8_t l5_flush_cs16_pkt_len;
    u8_t l5_flush_rdma_action;
} comq_l5_flush_l_t;

#if defined(LITTLE_ENDIAN)
    typedef comq_l5_flush_l_t comq_l5_flush_t;
#elif defined(BIG_ENDIAN)
    typedef comq_l5_flush_b_t comq_l5_flush_t;
#endif

/*
 *  l5_local_region_table_entry_b definition
 */
typedef struct l5_local_region_table_entry_b
{
    u8_t rte_flags;

    u8_t rte_bind_cnt;
    u16_t rte_pd;
} l5_local_region_table_entry_b_t;



/*
 *  l5_local_region_table_entry_b definition
 */
typedef struct l5_local_region_table_entry_b_xi
{
    u8_t rte_flags;
        #define RTE_FLAGS_FLAGS_MASK                        (0xff<<0)
            #define RTE_FLAGS_FLAGS_MASK_UNDEFINED          (0<<0)
            #define RTE_FLAGS_FLAGS_MASK_VALID              (1<<0)
            #define RTE_FLAGS_FLAGS_MASK_LOCAL_READ         (2<<0)
            #define RTE_FLAGS_FLAGS_MASK_LOCAL_WRITE        (4<<0)
            #define RTE_FLAGS_FLAGS_MASK_REMOTE_REGION      (8<<0)
            #define RTE_FLAGS_FLAGS_MASK_ALLOW_WIND_BIND    (16<<0)
            #define RTE_FLAGS_FLAGS_MASK_INVALIDATE_IN_PROGRESS  (32<<0)
            #define RTE_FLAGS_FLAGS_MASK_RX_FLUSH_IN_PROGRESS  (64<<0)

    u8_t rte_bind_cnt;
    u16_t rte_pd;
} l5_local_region_table_entry_b_xi_t;


/*
 *  l5_local_region_table_entry_l definition
 */
typedef struct l5_local_region_table_entry_l
{
    u16_t rte_pd;
    u8_t rte_bind_cnt;
    u8_t rte_flags;

} l5_local_region_table_entry_l_t;



/*
 *  l5_local_region_table_entry_l definition
 */
typedef struct l5_local_region_table_entry_l_xi
{
    u16_t rte_pd;
    u8_t rte_bind_cnt;
    u8_t rte_flags;
        #define RTE_FLAGS_FLAGS_MASK                        (0xff<<0)
            #define RTE_FLAGS_FLAGS_MASK_UNDEFINED          (0<<0)
            #define RTE_FLAGS_FLAGS_MASK_VALID              (1<<0)
            #define RTE_FLAGS_FLAGS_MASK_LOCAL_READ         (2<<0)
            #define RTE_FLAGS_FLAGS_MASK_LOCAL_WRITE        (4<<0)
            #define RTE_FLAGS_FLAGS_MASK_REMOTE_REGION      (8<<0)
            #define RTE_FLAGS_FLAGS_MASK_ALLOW_WIND_BIND    (16<<0)
            #define RTE_FLAGS_FLAGS_MASK_INVALIDATE_IN_PROGRESS  (32<<0)
            #define RTE_FLAGS_FLAGS_MASK_RX_FLUSH_IN_PROGRESS  (64<<0)

} l5_local_region_table_entry_l_xi_t;


/*
 * l5_local_region_table_entry select
 */
#if defined(LITTLE_ENDIAN)
    typedef l5_local_region_table_entry_l_t l5_local_region_table_entry_t;
    typedef l5_local_region_table_entry_l_xi_t l5_local_region_table_entry_xi_t;
#elif defined(BIG_ENDIAN)
    typedef l5_local_region_table_entry_b_t l5_local_region_table_entry_t;
    typedef l5_local_region_table_entry_b_xi_t l5_local_region_table_entry_xi_t;
#endif


/*
 *  l5_remote_region_table_entry_b definition
 */
typedef struct l5_remote_region_table_entry_b
{
    u8_t rte_flags;

    u8_t rte_wintbl_stag_hi;
    u16_t rte_wintbl_stag_lo;
} l5_remote_region_table_entry_b_t;



/*
 *  l5_remote_region_table_entry_b definition
 */
typedef struct l5_remote_region_table_entry_b_xi
{
    u8_t rte_flags;
        #define RTE_FLAGS_FLAGS_MASK                        (0xff<<0)
            #define RTE_FLAGS_FLAGS_MASK_UNDEFINED          (0<<0)
            #define RTE_FLAGS_FLAGS_MASK_VALID              (1<<0)
            #define RTE_FLAGS_FLAGS_MASK_LOCAL_READ         (2<<0)
            #define RTE_FLAGS_FLAGS_MASK_LOCAL_WRITE        (4<<0)
            #define RTE_FLAGS_FLAGS_MASK_REMOTE_REGION      (8<<0)
            #define RTE_FLAGS_FLAGS_MASK_ALLOW_WIND_BIND    (16<<0)
            #define RTE_FLAGS_FLAGS_MASK_INVALIDATE_IN_PROGRESS  (32<<0)
            #define RTE_FLAGS_FLAGS_MASK_RX_FLUSH_IN_PROGRESS  (64<<0)

    u8_t rte_wintbl_stag_hi;
    u16_t rte_wintbl_stag_lo;
} l5_remote_region_table_entry_b_xi_t;


/*
 *  l5_remote_region_table_entry_l definition
 */
typedef struct l5_remote_region_table_entry_l
{
    u16_t rte_wintbl_stag_lo;
    u8_t rte_wintbl_stag_hi;
    u8_t rte_flags;

} l5_remote_region_table_entry_l_t;



/*
 *  l5_remote_region_table_entry_l definition
 */
typedef struct l5_remote_region_table_entry_l_xi
{
    u16_t rte_wintbl_stag_lo;
    u8_t rte_wintbl_stag_hi;
    u8_t rte_flags;
        #define RTE_FLAGS_FLAGS_MASK                        (0xff<<0)
            #define RTE_FLAGS_FLAGS_MASK_UNDEFINED          (0<<0)
            #define RTE_FLAGS_FLAGS_MASK_VALID              (1<<0)
            #define RTE_FLAGS_FLAGS_MASK_LOCAL_READ         (2<<0)
            #define RTE_FLAGS_FLAGS_MASK_LOCAL_WRITE        (4<<0)
            #define RTE_FLAGS_FLAGS_MASK_REMOTE_REGION      (8<<0)
            #define RTE_FLAGS_FLAGS_MASK_ALLOW_WIND_BIND    (16<<0)
            #define RTE_FLAGS_FLAGS_MASK_INVALIDATE_IN_PROGRESS  (32<<0)
            #define RTE_FLAGS_FLAGS_MASK_RX_FLUSH_IN_PROGRESS  (64<<0)

} l5_remote_region_table_entry_l_xi_t;


/*
 * l5_remote_region_table_entry select
 */
#if defined(LITTLE_ENDIAN)
    typedef l5_remote_region_table_entry_l_t l5_remote_region_table_entry_t;
    typedef l5_remote_region_table_entry_l_xi_t l5_remote_region_table_entry_xi_t;
#elif defined(BIG_ENDIAN)
    typedef l5_remote_region_table_entry_b_t l5_remote_region_table_entry_t;
    typedef l5_remote_region_table_entry_b_xi_t l5_remote_region_table_entry_xi_t;
#endif


/*
 *  l5_region_ref_cnt_table_entry_b definition
 */
typedef struct l5_region_ref_cnt_table_entry_b
{
    u16_t rrcte_pidx;
    u16_t rrcte_cidx;
} l5_region_ref_cnt_table_entry_b_t;



/*
 *  l5_region_ref_cnt_table_entry_b definition
 */
typedef struct l5_region_ref_cnt_table_entry_b_xi
{
    u16_t rrcte_pidx;
    u16_t rrcte_cidx;
} l5_region_ref_cnt_table_entry_b_xi_t;


/*
 *  l5_region_ref_cnt_table_entry_l definition
 */
typedef struct l5_region_ref_cnt_table_entry_l
{
    u16_t rrcte_cidx;
    u16_t rrcte_pidx;
} l5_region_ref_cnt_table_entry_l_t;



/*
 *  l5_region_ref_cnt_table_entry_l definition
 */
typedef struct l5_region_ref_cnt_table_entry_l_xi
{
    u16_t rrcte_cidx;
    u16_t rrcte_pidx;
} l5_region_ref_cnt_table_entry_l_xi_t;


/*
 * l5_region_ref_cnt_table_entry select
 */
#if defined(LITTLE_ENDIAN)
    typedef l5_region_ref_cnt_table_entry_l_t l5_region_ref_cnt_table_entry_t;
    typedef l5_region_ref_cnt_table_entry_l_xi_t l5_region_ref_cnt_table_entry_xi_t;
#elif defined(BIG_ENDIAN)
    typedef l5_region_ref_cnt_table_entry_b_t l5_region_ref_cnt_table_entry_t;
    typedef l5_region_ref_cnt_table_entry_b_xi_t l5_region_ref_cnt_table_entry_xi_t;
#endif


/*
 *  l5_window_table_entry_b definition
 */
typedef struct l5_window_table_entry_b
{
    u32_t wte_virtual_base_addr_hi;
    u32_t wte_virtual_base_addr_lo;
    u32_t wte_pt_phy_base_addr_hi;
    u32_t wte_pt_phy_base_addr_lo;
    u32_t wte_length;
    u32_t wte_qp_or_pd;
    u16_t wte_region_table_index;
    u16_t wte_cache_key;
    u16_t wte_flags;

    u8_t wte_bind_cnt;
    u8_t wte_stag_key;
} l5_window_table_entry_b_t;



/*
 *  l5_window_table_entry_b definition
 */
typedef struct l5_window_table_entry_b_xi
{
    u32_t wte_virtual_base_addr_hi;
    u32_t wte_virtual_base_addr_lo;
    u32_t wte_pt_phy_base_addr_hi;
    u32_t wte_pt_phy_base_addr_lo;
    u32_t wte_length;
    u32_t wte_qp_or_pd;
    u16_t wte_region_table_index;
    u16_t wte_cache_key;
    u16_t wte_flags;
        #define WTE_FLAGS_REGION_PAGE_SIZE                  (0xf<<0)
            #define WTE_FLAGS_REGION_PAGE_SIZE_256          (0<<0)
            #define WTE_FLAGS_REGION_PAGE_SIZE_512          (1<<0)
            #define WTE_FLAGS_REGION_PAGE_SIZE_1K           (2<<0)
            #define WTE_FLAGS_REGION_PAGE_SIZE_2K           (3<<0)
            #define WTE_FLAGS_REGION_PAGE_SIZE_4K           (4<<0)
            #define WTE_FLAGS_REGION_PAGE_SIZE_8K           (5<<0)
            #define WTE_FLAGS_REGION_PAGE_SIZE_16K          (6<<0)
            #define WTE_FLAGS_REGION_PAGE_SIZE_32K          (7<<0)
            #define WTE_FLAGS_REGION_PAGE_SIZE_64K          (8<<0)
            #define WTE_FLAGS_REGION_PAGE_SIZE_128K         (9<<0)
            #define WTE_FLAGS_REGION_PAGE_SIZE_256K         (10<<0)
            #define WTE_FLAGS_REGION_PAGE_SIZE_512K         (11<<0)
            #define WTE_FLAGS_REGION_PAGE_SIZE_1M           (12<<0)
            #define WTE_FLAGS_REGION_PAGE_SIZE_2M           (13<<0)
            #define WTE_FLAGS_REGION_PAGE_SIZE_4M           (14<<0)
            #define WTE_FLAGS_REGION_PAGE_SIZE_8M           (15<<0)
        #define WTE_FLAGS_WT_FLAGS                          (0xfff<<4)
            #define WTE_FLAGS_WT_FLAGS_WT_UNDEFINED         (0<<4)
            #define WTE_FLAGS_WT_FLAGS_VALID                (1<<4)
            #define WTE_FLAGS_WT_FLAGS_REGION               (2<<4)
            #define WTE_FLAGS_WT_FLAGS_UNBOUND_WINDOW       (4<<4)
            #define WTE_FLAGS_WT_FLAGS_BOUND_WINDOW         (8<<4)
            #define WTE_FLAGS_WT_FLAGS_REMOTE_READ          (16<<4)
            #define WTE_FLAGS_WT_FLAGS_REMOTE_WRITE         (32<<4)
            #define WTE_FLAGS_WT_FLAGS_ALLOW_WINDOW_BINDS   (64<<4)
            #define WTE_FLAGS_WT_FLAGS_INVALIDATE_IN_PROGRESS  (128<<4)
            #define WTE_FLAGS_WT_FLAGS_RX_FLUSH_IN_PROGRESS  (256<<4)
            #define WTE_FLAGS_WT_FLAGS_READ_W_LINV_IN_PROGRESS  (512<<4)
            #define WTE_FLAGS_WT_FLAGS_DEALLOCATE_FLUSH_INITIATED  (1024<<4)
            #define WTE_FLAGS_WT_FLAGS_DEALLOCATE_FLUSH_COMPLETE  (2048<<4)

    u8_t wte_bind_cnt;
    u8_t wte_stag_key;
} l5_window_table_entry_b_xi_t;


/*
 *  l5_window_table_entry_l definition
 */
typedef struct l5_window_table_entry_l
{
    u32_t wte_virtual_base_addr_hi;
    u32_t wte_virtual_base_addr_lo;
    u32_t wte_pt_phy_base_addr_hi;
    u32_t wte_pt_phy_base_addr_lo;
    u32_t wte_length;
    u32_t wte_qp_or_pd;
    u16_t wte_cache_key;
    u16_t wte_region_table_index;
    u8_t wte_stag_key;
    u8_t wte_bind_cnt;
    u16_t wte_flags;

} l5_window_table_entry_l_t;



/*
 *  l5_window_table_entry_l definition
 */
typedef struct l5_window_table_entry_l_xi
{
    u32_t wte_virtual_base_addr_hi;
    u32_t wte_virtual_base_addr_lo;
    u32_t wte_pt_phy_base_addr_hi;
    u32_t wte_pt_phy_base_addr_lo;
    u32_t wte_length;
    u32_t wte_qp_or_pd;
    u16_t wte_cache_key;
    u16_t wte_region_table_index;
    u8_t wte_stag_key;
    u8_t wte_bind_cnt;
    u16_t wte_flags;
        #define WTE_FLAGS_REGION_PAGE_SIZE                  (0xf<<0)
            #define WTE_FLAGS_REGION_PAGE_SIZE_256          (0<<0)
            #define WTE_FLAGS_REGION_PAGE_SIZE_512          (1<<0)
            #define WTE_FLAGS_REGION_PAGE_SIZE_1K           (2<<0)
            #define WTE_FLAGS_REGION_PAGE_SIZE_2K           (3<<0)
            #define WTE_FLAGS_REGION_PAGE_SIZE_4K           (4<<0)
            #define WTE_FLAGS_REGION_PAGE_SIZE_8K           (5<<0)
            #define WTE_FLAGS_REGION_PAGE_SIZE_16K          (6<<0)
            #define WTE_FLAGS_REGION_PAGE_SIZE_32K          (7<<0)
            #define WTE_FLAGS_REGION_PAGE_SIZE_64K          (8<<0)
            #define WTE_FLAGS_REGION_PAGE_SIZE_128K         (9<<0)
            #define WTE_FLAGS_REGION_PAGE_SIZE_256K         (10<<0)
            #define WTE_FLAGS_REGION_PAGE_SIZE_512K         (11<<0)
            #define WTE_FLAGS_REGION_PAGE_SIZE_1M           (12<<0)
            #define WTE_FLAGS_REGION_PAGE_SIZE_2M           (13<<0)
            #define WTE_FLAGS_REGION_PAGE_SIZE_4M           (14<<0)
            #define WTE_FLAGS_REGION_PAGE_SIZE_8M           (15<<0)
        #define WTE_FLAGS_WT_FLAGS                          (0xfff<<4)
            #define WTE_FLAGS_WT_FLAGS_WT_UNDEFINED         (0<<4)
            #define WTE_FLAGS_WT_FLAGS_VALID                (1<<4)
            #define WTE_FLAGS_WT_FLAGS_REGION               (2<<4)
            #define WTE_FLAGS_WT_FLAGS_UNBOUND_WINDOW       (4<<4)
            #define WTE_FLAGS_WT_FLAGS_BOUND_WINDOW         (8<<4)
            #define WTE_FLAGS_WT_FLAGS_REMOTE_READ          (16<<4)
            #define WTE_FLAGS_WT_FLAGS_REMOTE_WRITE         (32<<4)
            #define WTE_FLAGS_WT_FLAGS_ALLOW_WINDOW_BINDS   (64<<4)
            #define WTE_FLAGS_WT_FLAGS_INVALIDATE_IN_PROGRESS  (128<<4)
            #define WTE_FLAGS_WT_FLAGS_RX_FLUSH_IN_PROGRESS  (256<<4)
            #define WTE_FLAGS_WT_FLAGS_READ_W_LINV_IN_PROGRESS  (512<<4)
            #define WTE_FLAGS_WT_FLAGS_DEALLOCATE_FLUSH_INITIATED  (1024<<4)
            #define WTE_FLAGS_WT_FLAGS_DEALLOCATE_FLUSH_COMPLETE  (2048<<4)

} l5_window_table_entry_l_xi_t;


/*
 * l5_window_table_entry select
 */
#if defined(LITTLE_ENDIAN)
    typedef l5_window_table_entry_l_t l5_window_table_entry_t;
    typedef l5_window_table_entry_l_xi_t l5_window_table_entry_xi_t;
#elif defined(BIG_ENDIAN)
    typedef l5_window_table_entry_b_t l5_window_table_entry_t;
    typedef l5_window_table_entry_b_xi_t l5_window_table_entry_xi_t;
#endif


/*
 *  l5_cq_table_entry_b definition
 */
typedef struct l5_cq_table_entry_b
{
    u32_t cqte_pgtbl_phaddr_hi;
    u8_t cqte_pgtbl_phaddr_lo[3];
    u8_t cqte_flags;

    u16_t cqte_pidx;
    u16_t cqte_cqes_per_page;
    u16_t cqte_max_cqes;
    u16_t cqte_nx_qe_self_seq;
    u16_t cqte_nx_pg_qidx;
    u16_t cqte_pgtbl_pgidx;
    u16_t cqte_pgtbl_npages;
    u16_t cqte_cqe_pidx;
    u32_t cqte_cached_pte_phaddr_hi;
    u32_t cqte_cached_pte_phaddr_lo;
} l5_cq_table_entry_b_t;


/*
 *  l5_cq_table_entry_b definition
 */
typedef struct l5_cq_table_entry_b_xi
{
    u32_t cqte_pgtbl_phaddr_hi;
    u8_t cqte_pgtbl_phaddr_lo[3];
    u8_t cqte_flags;
        #define CQTE_FLAGS_PAGE_SIZE                        (0xf<<0)
            #define CQTE_FLAGS_PAGE_SIZE_256                (0<<0)
            #define CQTE_FLAGS_PAGE_SIZE_512                (1<<0)
            #define CQTE_FLAGS_PAGE_SIZE_1K                 (2<<0)
            #define CQTE_FLAGS_PAGE_SIZE_2K                 (3<<0)
            #define CQTE_FLAGS_PAGE_SIZE_4K                 (4<<0)
            #define CQTE_FLAGS_PAGE_SIZE_8K                 (5<<0)
            #define CQTE_FLAGS_PAGE_SIZE_16K                (6<<0)
            #define CQTE_FLAGS_PAGE_SIZE_32K                (7<<0)
            #define CQTE_FLAGS_PAGE_SIZE_64K                (8<<0)
            #define CQTE_FLAGS_PAGE_SIZE_128K               (9<<0)
            #define CQTE_FLAGS_PAGE_SIZE_256K               (10<<0)
            #define CQTE_FLAGS_PAGE_SIZE_512K               (11<<0)
            #define CQTE_FLAGS_PAGE_SIZE_1M                 (12<<0)
            #define CQTE_FLAGS_PAGE_SIZE_2M                 (13<<0)
        #define CQTE_FLAGS_FLAGS                            (0xf<<4)
            #define CQTE_FLAGS_FLAGS_UNDEFINED              (0<<4)
            #define CQTE_FLAGS_FLAGS_VALID                  (1<<4)
            #define CQTE_FLAGS_FLAGS_ARMED                  (2<<4)
            #define CQTE_FLAGS_FLAGS_ARMED_SEND_SE          (4<<4)
            #define CQTE_FLAGS_FLAGS_CQE_NOT_ARMED          (8<<4)

    u16_t cqte_pidx;
    u16_t cqte_cqes_per_page;
    u16_t cqte_max_cqes;
    u16_t cqte_nx_qe_self_seq;
    u16_t cqte_nx_pg_qidx;
    u16_t cqte_pgtbl_pgidx;
    u16_t cqte_pgtbl_npages;
    u16_t cqte_cqe_pidx;
    u32_t cqte_cached_pte_phaddr_hi;
    u32_t cqte_cached_pte_phaddr_lo;
} l5_cq_table_entry_b_xi_t;


/*
 *  l5_cq_table_entry_l definition
 */
typedef struct l5_cq_table_entry_l
{
    u32_t cqte_pgtbl_phaddr_hi;
    u8_t cqte_flags;

    u8_t cqte_pgtbl_phaddr_lo[3];
    u16_t cqte_cqes_per_page;
    u16_t cqte_pidx;
    u16_t cqte_nx_qe_self_seq;
    u16_t cqte_max_cqes;
    u16_t cqte_pgtbl_pgidx;
    u16_t cqte_nx_pg_qidx;
    u16_t cqte_cqe_pidx;
    u16_t cqte_pgtbl_npages;
    u32_t cqte_cached_pte_phaddr_hi;
    u32_t cqte_cached_pte_phaddr_lo;
} l5_cq_table_entry_l_t;



/*
 *  l5_cq_table_entry_l definition
 */
typedef struct l5_cq_table_entry_l_xi
{
    u32_t cqte_pgtbl_phaddr_hi;
    u8_t cqte_flags;
        #define CQTE_FLAGS_PAGE_SIZE                        (0xf<<0)
            #define CQTE_FLAGS_PAGE_SIZE_256                (0<<0)
            #define CQTE_FLAGS_PAGE_SIZE_512                (1<<0)
            #define CQTE_FLAGS_PAGE_SIZE_1K                 (2<<0)
            #define CQTE_FLAGS_PAGE_SIZE_2K                 (3<<0)
            #define CQTE_FLAGS_PAGE_SIZE_4K                 (4<<0)
            #define CQTE_FLAGS_PAGE_SIZE_8K                 (5<<0)
            #define CQTE_FLAGS_PAGE_SIZE_16K                (6<<0)
            #define CQTE_FLAGS_PAGE_SIZE_32K                (7<<0)
            #define CQTE_FLAGS_PAGE_SIZE_64K                (8<<0)
            #define CQTE_FLAGS_PAGE_SIZE_128K               (9<<0)
            #define CQTE_FLAGS_PAGE_SIZE_256K               (10<<0)
            #define CQTE_FLAGS_PAGE_SIZE_512K               (11<<0)
            #define CQTE_FLAGS_PAGE_SIZE_1M                 (12<<0)
            #define CQTE_FLAGS_PAGE_SIZE_2M                 (13<<0)
        #define CQTE_FLAGS_FLAGS                            (0xf<<4)
            #define CQTE_FLAGS_FLAGS_UNDEFINED              (0<<4)
            #define CQTE_FLAGS_FLAGS_VALID                  (1<<4)
            #define CQTE_FLAGS_FLAGS_ARMED                  (2<<4)
            #define CQTE_FLAGS_FLAGS_ARMED_SEND_SE          (4<<4)
            #define CQTE_FLAGS_FLAGS_CQE_NOT_ARMED          (8<<4)

    u8_t cqte_pgtbl_phaddr_lo[3];
    u16_t cqte_cqes_per_page;
    u16_t cqte_pidx;
    u16_t cqte_nx_qe_self_seq;
    u16_t cqte_max_cqes;
    u16_t cqte_pgtbl_pgidx;
    u16_t cqte_nx_pg_qidx;
    u16_t cqte_cqe_pidx;
    u16_t cqte_pgtbl_npages;
    u32_t cqte_cached_pte_phaddr_hi;
    u32_t cqte_cached_pte_phaddr_lo;
} l5_cq_table_entry_l_xi_t;


/*
 * l5_cq_table_entry select
 */
#if defined(LITTLE_ENDIAN)
    typedef l5_cq_table_entry_l_t l5_cq_table_entry_t;
    typedef l5_cq_table_entry_l_xi_t l5_cq_table_entry_xi_t;
#elif defined(BIG_ENDIAN)
    typedef l5_cq_table_entry_b_t l5_cq_table_entry_t;
    typedef l5_cq_table_entry_b_xi_t l5_cq_table_entry_xi_t;
#endif


/*
 *  l5_cmd_cell_b definition
 */
typedef struct l5_cmd_cell_b
{
    u16_t l5ccell_cmd_type;

    u16_t l5ccell_wq_idx;
    u8_t unused_0;
    u8_t l5ccell_cmd_val;
    u16_t l5ccell_distance_to_first_marker;
    u32_t unused_1;
    u32_t l5ccell_ddp_hdr_word1;
    u32_t l5ccell_ddp_hdr_word2;
    u32_t l5ccell_ddp_hdr_word3;
    u32_t l5ccell_tcp_sn_first_byte;
    u32_t l5ccell_tcp_sn_last_byte;
} l5_cmd_cell_b_t;



/*
 *  l5_cmd_cell_l definition
 */
typedef struct l5_cmd_cell_l
{
    u16_t l5ccell_wq_idx;
    u16_t l5ccell_cmd_type;

    u16_t l5ccell_distance_to_first_marker;
    u8_t l5ccell_cmd_val;
    u8_t unused_0;
    u32_t unused_1;
    u32_t l5ccell_ddp_hdr_word1;
    u32_t l5ccell_ddp_hdr_word2;
    u32_t l5ccell_ddp_hdr_word3;
    u32_t l5ccell_tcp_sn_first_byte;
    u32_t l5ccell_tcp_sn_last_byte;
} l5_cmd_cell_l_t;



/*
 * l5_cmd_cell select
 */
#if defined(LITTLE_ENDIAN)
    typedef l5_cmd_cell_l_t l5_cmd_cell_t;
#elif defined(BIG_ENDIAN)
    typedef l5_cmd_cell_b_t l5_cmd_cell_t;
#endif


/*
 *  l5_abuf_cell_b definition
 */
typedef struct l5_abuf_cell_b
{
    u32_t l5acell_pgtbl_phaddr_hi;
    u8_t l5acell_pgtbl_phaddr_lo[3];
    u8_t l5acell_flags;

    u16_t l5acell_wq_idx;
    u16_t l5acell_first_page_offset;
    u32_t l5acell_buffer_offset;
    u16_t l5acell_rbdc_key;
    u16_t l5acell_receive_length;
    u32_t l5acell_buffer_length;
    u32_t l5acell_tcp_sn_L_bit_segment;
} l5_abuf_cell_b_t;



/*
 *  l5_abuf_cell_b definition
 */
typedef struct l5_abuf_cell_b_xi
{
    u32_t l5acell_pgtbl_phaddr_hi;
    u8_t l5acell_pgtbl_phaddr_lo[3];
    u8_t l5acell_flags;
        #define L5ACELL_FLAGS_REGION_PAGE_SIZE              (0xf<<0)
            #define L5ACELL_FLAGS_REGION_PAGE_SIZE_256      (0<<0)
            #define L5ACELL_FLAGS_REGION_PAGE_SIZE_512      (1<<0)
            #define L5ACELL_FLAGS_REGION_PAGE_SIZE_1K       (2<<0)
            #define L5ACELL_FLAGS_REGION_PAGE_SIZE_2K       (3<<0)
            #define L5ACELL_FLAGS_REGION_PAGE_SIZE_4K       (4<<0)
            #define L5ACELL_FLAGS_REGION_PAGE_SIZE_8K       (5<<0)
            #define L5ACELL_FLAGS_REGION_PAGE_SIZE_16K      (6<<0)
            #define L5ACELL_FLAGS_REGION_PAGE_SIZE_32K      (7<<0)
            #define L5ACELL_FLAGS_REGION_PAGE_SIZE_64K      (8<<0)
            #define L5ACELL_FLAGS_REGION_PAGE_SIZE_128K     (9<<0)
            #define L5ACELL_FLAGS_REGION_PAGE_SIZE_256K     (10<<0)
            #define L5ACELL_FLAGS_REGION_PAGE_SIZE_512K     (11<<0)
            #define L5ACELL_FLAGS_REGION_PAGE_SIZE_1M       (12<<0)
            #define L5ACELL_FLAGS_REGION_PAGE_SIZE_2M       (13<<0)
            #define L5ACELL_FLAGS_REGION_PAGE_SIZE_4M       (14<<0)
            #define L5ACELL_FLAGS_REGION_PAGE_SIZE_8M       (15<<0)
        #define L5ACELL_FLAGS_ABUF_FLAGS                    (0xf<<4)
            #define L5ACELL_FLAGS_ABUF_FLAGS_ABUF_UNDEFINED  (0<<4)
            #define L5ACELL_FLAGS_ABUF_FLAGS_L_BIT_RCVD     (1<<4)
            #define L5ACELL_FLAGS_ABUF_FLAGS_GEN_EVT        (2<<4)
            #define L5ACELL_FLAGS_ABUF_FLAGS_INV_STAG       (4<<4)
            #define L5ACELL_FLAGS_ABUF_FLAGS_COMP_ERROR     (8<<4)

    u16_t l5acell_wq_idx;
    u16_t l5acell_first_page_offset;
    u32_t l5acell_buffer_offset;
    u16_t l5acell_rbdc_key;
    u16_t l5acell_receive_length;
    u32_t l5acell_buffer_length;
    u32_t l5acell_tcp_sn_L_bit_segment;
} l5_abuf_cell_b_xi_t;


/*
 *  l5_abuf_cell_l definition
 */
typedef struct l5_abuf_cell_l
{
    u32_t l5acell_pgtbl_phaddr_hi;
    u8_t l5acell_flags;

    u8_t l5acell_pgtbl_phaddr_lo[3];
    u16_t l5acell_first_page_offset;
    u16_t l5acell_wq_idx;
    u32_t l5acell_buffer_offset;
    u16_t l5acell_receive_length;
    u16_t l5acell_rbdc_key;
    u32_t l5acell_buffer_length;
    u32_t l5acell_tcp_sn_L_bit_segment;
} l5_abuf_cell_l_t;



/*
 *  l5_abuf_cell_l definition
 */
typedef struct l5_abuf_cell_l_xi
{
    u32_t l5acell_pgtbl_phaddr_hi;
    u8_t l5acell_flags;
        #define L5ACELL_FLAGS_REGION_PAGE_SIZE              (0xf<<0)
            #define L5ACELL_FLAGS_REGION_PAGE_SIZE_256      (0<<0)
            #define L5ACELL_FLAGS_REGION_PAGE_SIZE_512      (1<<0)
            #define L5ACELL_FLAGS_REGION_PAGE_SIZE_1K       (2<<0)
            #define L5ACELL_FLAGS_REGION_PAGE_SIZE_2K       (3<<0)
            #define L5ACELL_FLAGS_REGION_PAGE_SIZE_4K       (4<<0)
            #define L5ACELL_FLAGS_REGION_PAGE_SIZE_8K       (5<<0)
            #define L5ACELL_FLAGS_REGION_PAGE_SIZE_16K      (6<<0)
            #define L5ACELL_FLAGS_REGION_PAGE_SIZE_32K      (7<<0)
            #define L5ACELL_FLAGS_REGION_PAGE_SIZE_64K      (8<<0)
            #define L5ACELL_FLAGS_REGION_PAGE_SIZE_128K     (9<<0)
            #define L5ACELL_FLAGS_REGION_PAGE_SIZE_256K     (10<<0)
            #define L5ACELL_FLAGS_REGION_PAGE_SIZE_512K     (11<<0)
            #define L5ACELL_FLAGS_REGION_PAGE_SIZE_1M       (12<<0)
            #define L5ACELL_FLAGS_REGION_PAGE_SIZE_2M       (13<<0)
            #define L5ACELL_FLAGS_REGION_PAGE_SIZE_4M       (14<<0)
            #define L5ACELL_FLAGS_REGION_PAGE_SIZE_8M       (15<<0)
        #define L5ACELL_FLAGS_ABUF_FLAGS                    (0xf<<4)
            #define L5ACELL_FLAGS_ABUF_FLAGS_ABUF_UNDEFINED  (0<<4)
            #define L5ACELL_FLAGS_ABUF_FLAGS_L_BIT_RCVD     (1<<4)
            #define L5ACELL_FLAGS_ABUF_FLAGS_GEN_EVT        (2<<4)
            #define L5ACELL_FLAGS_ABUF_FLAGS_INV_STAG       (4<<4)
            #define L5ACELL_FLAGS_ABUF_FLAGS_COMP_ERROR     (8<<4)

    u8_t l5acell_pgtbl_phaddr_lo[3];
    u16_t l5acell_first_page_offset;
    u16_t l5acell_wq_idx;
    u32_t l5acell_buffer_offset;
    u16_t l5acell_receive_length;
    u16_t l5acell_rbdc_key;
    u32_t l5acell_buffer_length;
    u32_t l5acell_tcp_sn_L_bit_segment;
} l5_abuf_cell_l_xi_t;


/*
 * l5_abuf_cell select
 */
#if defined(LITTLE_ENDIAN)
    typedef l5_abuf_cell_l_t l5_abuf_cell_t;
    typedef l5_abuf_cell_l_xi_t l5_abuf_cell_xi_t;
#elif defined(BIG_ENDIAN)
    typedef l5_abuf_cell_b_t l5_abuf_cell_t;
    typedef l5_abuf_cell_b_xi_t l5_abuf_cell_xi_t;
#endif


/*
 *  l5_irrq_entry_b definition
 */
typedef struct l5_irrq_entry_b
{
    u32_t irrqe_sink_stag;
    u32_t irrqe_sink_to_hi;
    u32_t irrqe_sink_to_lo;
    u32_t irrqe_msg_length;
    u32_t irrqe_source_stag;
    u32_t irrqe_source_to_hi;
    u32_t irrqe_source_to_lo;
} l5_irrq_entry_b_t;



/*
 *  l5_irrq_entry_b definition
 */
typedef struct l5_irrq_entry_b_xi
{
    u32_t irrqe_sink_stag;
    u32_t irrqe_sink_to_hi;
    u32_t irrqe_sink_to_lo;
    u32_t irrqe_msg_length;
    u32_t irrqe_source_stag;
    u32_t irrqe_source_to_hi;
    u32_t irrqe_source_to_lo;
} l5_irrq_entry_b_xi_t;


/*
 *  l5_irrq_entry_l definition
 */
typedef struct l5_irrq_entry_l
{
    u32_t irrqe_sink_stag;
    u32_t irrqe_sink_to_hi;
    u32_t irrqe_sink_to_lo;
    u32_t irrqe_msg_length;
    u32_t irrqe_source_stag;
    u32_t irrqe_source_to_hi;
    u32_t irrqe_source_to_lo;
} l5_irrq_entry_l_t;



/*
 *  l5_irrq_entry_l definition
 */
typedef struct l5_irrq_entry_l_xi
{
    u32_t irrqe_sink_stag;
    u32_t irrqe_sink_to_hi;
    u32_t irrqe_sink_to_lo;
    u32_t irrqe_msg_length;
    u32_t irrqe_source_stag;
    u32_t irrqe_source_to_hi;
    u32_t irrqe_source_to_lo;
} l5_irrq_entry_l_xi_t;


/*
 * l5_irrq_entry select
 */
#if defined(LITTLE_ENDIAN)
    typedef l5_irrq_entry_l_t l5_irrq_entry_t;
    typedef l5_irrq_entry_l_xi_t l5_irrq_entry_xi_t;
#elif defined(BIG_ENDIAN)
    typedef l5_irrq_entry_b_t l5_irrq_entry_t;
    typedef l5_irrq_entry_b_xi_t l5_irrq_entry_xi_t;
#endif


/*
 *  l5_orrq_entry_b definition
 */
typedef struct l5_orrq_entry_b
{
    u32_t orrqe_tcp_sn_read_rsp_L_bit_segment;
    u32_t orrqe_source_to_hi;
    u32_t orrqe_source_to_low;
} l5_orrq_entry_b_t;



/*
 *  l5_orrq_entry_b definition
 */
typedef struct l5_orrq_entry_b_xi
{
    u32_t orrqe_tcp_sn_read_rsp_L_bit_segment;
    u32_t orrqe_source_to_hi;
    u32_t orrqe_source_to_low;
} l5_orrq_entry_b_xi_t;


/*
 *  l5_orrq_entry_l definition
 */
typedef struct l5_orrq_entry_l
{
    u32_t orrqe_tcp_sn_read_rsp_L_bit_segment;
    u32_t orrqe_source_to_hi;
    u32_t orrqe_source_to_low;
} l5_orrq_entry_l_t;



/*
 *  l5_orrq_entry_l definition
 */
typedef struct l5_orrq_entry_l_xi
{
    u32_t orrqe_tcp_sn_read_rsp_L_bit_segment;
    u32_t orrqe_source_to_hi;
    u32_t orrqe_source_to_low;
} l5_orrq_entry_l_xi_t;


/*
 * l5_orrq_entry select
 */
#if defined(LITTLE_ENDIAN)
    typedef l5_orrq_entry_l_t l5_orrq_entry_t;
    typedef l5_orrq_entry_l_xi_t l5_orrq_entry_xi_t;
#elif defined(BIG_ENDIAN)
    typedef l5_orrq_entry_b_t l5_orrq_entry_t;
    typedef l5_orrq_entry_b_xi_t l5_orrq_entry_xi_t;
#endif


/*
 *  l5_context_b definition
 */
typedef struct l5_context_b
{
    u8_t l5ctx_type;

    u8_t l5ctx_size;
    u16_t l5ctx_cq_cidx;
    u8_t l5ctx_gen_bd_max;
    u8_t l5ctx_oubits;

    u16_t l5ctx_sq_pidx;
    u16_t l5ctx_tcp_pgid;
    u16_t l5ctx_rq_pidx;
    u32_t l5ctx_tcp_timer1;

    u16_t l5ctx_tcp_timer2;

    u16_t l5ctx_tcp_timer3;

    u16_t l5ctx_tcp_timer4;

    u16_t l5ctx_tcp_timer5;

    u32_t l5ctx_tcp_snd_wl1;
    u32_t l5ctx_tcp_snd_wl2;
    u8_t l5ctx_tcp_ttl;
    u8_t l5ctx_tcp_tos;
    u8_t l5ctx_tcp_dack;
    u8_t l5ctx_tcp_modes;

    u32_t l5ctx_tcp_max_adv_win;
    u32_t l5ctx_tcp_timer;
    u32_t l5ctx_tcp_ip_src;
    u32_t l5ctx_tcp_ip_dst;
    u8_t l5ctx_tcp_iphdr_nbytes;
    u8_t l5ctx_tcp_snd_seg_scale;
    u8_t l5ctx_tcp_rcv_seg_scale;
    u8_t l5ctx_tcp_tcp_hlen;
    u16_t l5ctx_tcp_src_port;
    u16_t l5ctx_tcp_dst_port;
    u16_t l5ctx_tcp_mss;
    u8_t l5ctx_tcp_flags;

    u8_t l5ctx_tcp_state;

    u32_t l5ctx_tcp_rcv_next;
    u32_t l5ctx_last_ack_sent;
    u32_t l5ctx_tcp_rcv_win_seq;
    u32_t l5ctx_tcp_snd_una;
    u32_t l5ctx_tcp_snd_next;
    u32_t l5ctx_tcp_snd_max;
    u32_t l5ctx_tcp_snd_win;
    u32_t l5ctx_tcp_snd_cwin;
    u32_t l5ctx_tcp_tstamp;
    u32_t l5ctx_tcp_ssthresh;
    u16_t l5ctx_tcp_sm_rtt;
    u16_t l5ctx_tcp_sm_delta;
    u32_t l5ctx_tcp_max_snd_win;
    u32_t l5ctx_tcp_tsch_snd_next;
    u32_t l5ctx_tcp_slot_size;

    u8_t l5ctx_tcp_cp_cmd;
    u8_t l5ctx_tcp_tsch_cmd;
    u8_t l5ctx_tcp_cons_retx_num;
    u8_t l5ctx_tcp_tsch_xnum;

    u8_t l5ctx_tcp_num_dupack;
    u8_t l5ctx_tcp_tx_protocol_flags;

    u8_t l5ctx_tcp_prod_retx_num;
    u8_t l5ctx_tcp_tsch_cons_retx_num;
    u8_t l5ctx_tcp_comp_cons_retx_num;
    u8_t l5ctx_tcp_num_retx;
    u8_t l5ctx_tcp_upload_reason;

    u8_t l5ctx_tcp_txp_cmd;
    u32_t unused_0;
    tcp_context_cmd_cell_b_te_t l5ctx_cmd[3];
    u16_t l5ctx_snd_q_max_wqes;
    u16_t l5ctx_snd_q_fw_qidx;
    u16_t l5ctx_snd_q_nx_pg_qidx;
    u16_t l5ctx_snd_q_pgtbl_pgidx;
    u16_t l5ctx_snd_q_wqes_per_page;
    u16_t l5ctx_snd_q_num_pages;
    u8_t l5ctx_snd_q_pidx;
    u8_t l5ctx_snd_q_cidx;
    u8_t l5ctx_snd_q_max_cached_wqes;
    u8_t l5ctx_snd_q_flags;

    u32_t l5ctx_snd_q_pgtbl_phaddr_hi;
    u8_t l5ctx_snd_q_pgtbl_phaddr_lo[3];
    u8_t l5ctx_snd_q_read_rsp_wait;
    u32_t l5ctx_snd_q_cached_pte_phaddr_hi;
    u32_t l5ctx_snd_q_cached_pte_phaddr_lo;
    l5_cmd_cell_b_t l5ctx_snd_q_cmd[3];
    u16_t l5ctx_rcv_q_max_wqes;
    u16_t l5ctx_rcv_q_fw_qidx;
    u16_t l5ctx_rcv_q_nx_pg_qidx;
    u16_t l5ctx_rcv_q_pgtbl_pgidx;
    u16_t l5ctx_rcv_q_wqes_per_page;
    u16_t l5ctx_rcv_q_num_pages;
    u8_t l5ctx_rcv_q_pidx;
    u8_t l5ctx_rcv_q_rxp_cidx;
    u8_t l5ctx_rcv_q_com_cidx;
    u8_t l5ctx_rcv_q_flags;

    u32_t l5ctx_rcv_q_pgtbl_phaddr_hi;
    u8_t l5ctx_rcv_q_pgtbl_phaddr_lo[3];
    u8_t l5ctx_rcv_q_qp_ou_state;
        #define L5CTX_RCV_Q_QP_OU_STATE_UPLOADED            (1<<0)
        #define L5CTX_RCV_Q_QP_OU_STATE_OFFLOADED           (1<<1)
        #define L5CTX_RCV_Q_QP_OU_STATE_UPLOAD_REQ          (1<<2)
        #define L5CTX_RCV_Q_QP_OU_STATE_OFFLOAD_REQ         (1<<3)

    u32_t l5ctx_rcv_q_cached_pte_phaddr_hi;
    u32_t l5ctx_rcv_q_cached_pte_phaddr_lo;
    l5_abuf_cell_b_t l5ctx_rcv_q_abuf[2];
    u32_t l5ctx_cq_cid;
    u32_t l5ctx_curr_send_msn;
    u32_t l5ctx_curr_rdma_read_msn;
    u16_t l5ctx_pd;
    u8_t l5ctx_rcv_path_op_state;

    u8_t l5ctx_ird;
    u32_t l5ctx_tx_initial_tcp_sn;
    u16_t l5ctx_tsch_mult_value;
    u8_t l5ctx_null_cmd_cell_pidx;
    u8_t l5ctx_null_cmd_cell_cidx;
    l5_orrq_entry_b_t l5ctx_orrq[1];
    l5_irrq_entry_b_t l5ctx_irrq[1];
    u8_t l5ctx_miq_index;
    u8_t l5ctx_rx_comp_flags;

    u8_t l5ctx_qp_flags;

    u8_t l5ctx_upload_flag;

    u8_t l5ctx_upload_rxp;

    u8_t l5ctx_ooo_read_resp_segs_w_L_bit;
    u8_t l5ctx_ooo_send_msg_segs_w_L_bit;
    u8_t l5ctx_ooo_read_request_msgs;
    u32_t l5ctx_high_tcp_ack_sn_rcvd;
    u32_t l5ctx_rx_initial_tcp_sn;
    u32_t l5ctx_send_msg_high_msn_completed;
    u32_t l5ctx_read_req_high_msn_queued;
    u32_t l5ctx_rsvd_l4_hole_mgmt[3];
    u16_t l5ctx_cam_index;
    u16_t l5ctx_offload_flag;
} l5_context_b_t;



/*
 *  l5_context_b definition
 */
typedef struct l5_context_b_xi
{
    u32_t l5ctx_tcp_tsch_snd_next;
    u32_t l5ctx_tcp_snd_max;
    u8_t l5ctx_tcp_cp_cmd;
    u8_t l5ctx_tcp_tsch_cmd;
    u8_t l5ctx_tcp_cons_retx_num;
    u8_t l5ctx_tcp_tsch_xnum;
        #define L5CTX_TCP_TSCH_XNUM_VAL                     (0x7f<<0)
        #define L5CTX_TCP_TSCH_XNUM_L4                      (1<<7)

    u16_t l5ctx_tcp_pgid;
        #define L5CTX_TCP_PGID_VAL                          (0x3fff<<0)

    u8_t l5ctx_tcp_prod_retx_num;
    u8_t l5ctx_tcp_tsch_cons_retx_num;
    u8_t l5ctx_tcp_l2_slot_size;
    u8_t unused_0;
    u16_t unused_1;
    u32_t unused_2;
    u8_t l5ctx_tcp_ttl;
    u8_t l5ctx_tcp_tos;
    u8_t l5ctx_tcp_dack;
    u8_t l5ctx_tcp_modes;
        #define L5CTX_TCP_MODES_RST_INDICATED               (1<<0)
        #define L5CTX_TCP_MODES_DISC_BD                     (1<<1)
        #define L5CTX_TCP_MODES_UPLOAD_INITED               (1<<2)
        #define L5CTX_TCP_MODES_RMT_DISC                    (1<<3)
        #define L5CTX_TCP_MODES_PG_INVALIDATED              (1<<4)
        #define L5CTX_TCP_MODES_ABORT_PENDING               (1<<5)
        #define L5CTX_TCP_MODES_DISC_PENDING                (1<<6)
        #define L5CTX_TCP_MODES_SS                          (1<<7)

    u32_t l5ctx_tcp_max_adv_win;
    u32_t l5ctx_timer;
    u32_t l5ctx_tcp_ip_src;
    u32_t l5ctx_tcp_ip_dst;
    u8_t l5ctx_tcp_iphdr_nbytes;
    u8_t l5ctx_tcp_snd_seg_scale;
    u8_t l5ctx_tcp_rcv_seg_scale;
    u8_t l5ctx_tcp_tcp_hlen;
    u16_t l5ctx_tcp_src_port;
    u16_t l5ctx_tcp_dst_port;
    u32_t l5ctx_tx_initial_tcp_sn;
    u8_t l5ctx_upload_flag;
        #define L5CTX_UPLOAD_FLAG_TXP                       (1<<0)
        #define L5CTX_UPLOAD_FLAG_TXP_COM                   (1<<1)
    u8_t unused_3;
    u16_t unused_4;
    u32_t unused_5[17];

    u8_t l5ctx_type;
        #define L5CTX_TYPE_TYPE                             (0xf<<4)
            #define L5CTX_TYPE_TYPE_EMPTY                   (0<<4)
            #define L5CTX_TYPE_TYPE_L2                      (1<<4)
            #define L5CTX_TYPE_TYPE_TCP                     (2<<4)
            #define L5CTX_TYPE_TYPE_L5                      (3<<4)
            #define L5CTX_TYPE_TYPE_L2_BD_CHN               (4<<4)

    u8_t l5ctx_size;
        #define L5CTX_SIZE_ARM_CQ                           (1<<0)

    u16_t l5ctx_cq_cidx;
    u8_t l5ctx_gen_bd_max;
    u8_t l5ctx_oubits;
        #define L5CTX_OUBITS_ACTIVATE                       (1<<0)
        #define L5CTX_OUBITS_CP_UPLOAD                      (1<<1)
        #define L5CTX_OUBITS_RXP_UPLOAD                     (1<<2)
        #define L5CTX_OUBITS_TXP_UPLOAD                     (1<<3)
        #define L5CTX_OUBITS_COM_RX_UPLOAD                  (1<<4)
        #define L5CTX_OUBITS_COM_TX_UPLOAD                  (1<<5)
        #define L5CTX_OUBITS_CP_UPLOAD_COMP                 (1<<6)
        #define L5CTX_OUBITS_HOST_ACK                       (1<<7)

    u16_t l5ctx_sq_pidx;
    u16_t unused_6;
    u16_t l5ctx_rq_pidx;
    u32_t l5ctx_tcp_timer1;
        #define L5CTX_TCP_TIMER1_DISABLE                    (1UL<<0)
        #define L5CTX_TCP_TIMER1_VALUE                      (0x7fffffffL<<1)

    u16_t l5ctx_tcp_timer2;
        #define L5CTX_TCP_TIMER2_DISABLE                    (1<<0)
        #define L5CTX_TCP_TIMER2_VALUE                      (0x7fff<<1)

    u16_t l5ctx_tcp_timer3;
        #define L5CTX_TCP_TIMER3_DISABLE                    (1<<0)
        #define L5CTX_TCP_TIMER3_VALUE                      (0x7fff<<1)

    u16_t l5ctx_tcp_timer4;
        #define L5CTX_TCP_TIMER4_DISABLE                    (1<<0)
        #define L5CTX_TCP_TIMER4_VALUE                      (0x7fff<<1)

    u16_t l5ctx_tcp_timer5;
        #define L5CTX_TCP_TIMER5_DISABLE                    (1<<0)
        #define L5CTX_TCP_TIMER5_VALUE                      (0x7fff<<1)

    u32_t l5ctx_tcp_slot_size;
        #define L5CTX_TCP_SLOT_SIZE_SLOT_SIZE               (0xffffffL<<0)
        #define L5CTX_TCP_SLOT_SIZE_CMD_MAX                 (0x7fL<<24)
        #define L5CTX_TCP_SLOT_SIZE_STOP                    (1UL<<31)

    u32_t l5ctx_tcp_snd_cwin;
    u32_t l5ctx_tcp_snd_win;
    u8_t l5ctx_tcp_num_dupack;
    u8_t l5ctx_tcp_tx_protocol_flags;
        #define L5CTX_TCP_TX_PROTOCOL_FLAGS_TIMER_DELAY_ACK  (1<<0)
        #define L5CTX_TCP_TX_PROTOCOL_FLAGS_UPLOAD          (1<<1)
        #define L5CTX_TCP_TX_PROTOCOL_FLAGS_FORCE_ACK       (1<<2)
        #define L5CTX_TCP_TX_PROTOCOL_FLAGS_LAST_ACK        (1<<3)
        #define L5CTX_TCP_TX_PROTOCOL_FLAGS_LAST_RST        (1<<4)
        #define L5CTX_TCP_TX_PROTOCOL_FLAGS_FORCE_RST       (1<<5)
        #define L5CTX_TCP_TX_PROTOCOL_FLAGS_FORCE_ACK_MINUS  (1<<6)
        #define L5CTX_TCP_TX_PROTOCOL_FLAGS_TSCH_WA         (1<<7)

    u8_t l5ctx_upload_rxp;
        #define L5CTX_UPLOAD_RXP_COM                        (1<<0)

    u8_t l5ctx_qp_ou_state;
        #define L5CTX_QP_OU_STATE_UPLOADED                  (1<<0)
        #define L5CTX_QP_OU_STATE_OFFLOADED                 (1<<1)
        #define L5CTX_QP_OU_STATE_UPLOAD_REQ                (1<<2)
        #define L5CTX_QP_OU_STATE_OFFLOAD_REQ               (1<<3)
    u32_t unused_7;

    u16_t l5ctx_tcp_mss;
    u8_t l5ctx_tcp_flags;
        #define L5CTX_TCP_FLAGS_NO_DELAY_ACK                (1<<0)
        #define L5CTX_TCP_FLAGS_KEEP_ALIVE                  (1<<1)
        #define L5CTX_TCP_FLAGS_NAGLE                       (1<<2)
        #define L5CTX_TCP_FLAGS_TIME_STAMP                  (1<<3)
        #define L5CTX_TCP_FLAGS_SACK                        (1<<4)
        #define L5CTX_TCP_FLAGS_SEG_SCALING                 (1<<5)

    u8_t l5ctx_tcp_state;
        #define L5CTX_TCP_STATE_VALUE                       (0xff<<0)
            #define L5CTX_TCP_STATE_VALUE_UNDEFINED         (0<<0)
            #define L5CTX_TCP_STATE_VALUE_LISTEN            (2<<0)
            #define L5CTX_TCP_STATE_VALUE_SYN_SENT          (4<<0)
            #define L5CTX_TCP_STATE_VALUE_SYN_RECV          (6<<0)
            #define L5CTX_TCP_STATE_VALUE_CLOSE_WAIT        (8<<0)
            #define L5CTX_TCP_STATE_VALUE_ESTABLISHED       (10<<0)
            #define L5CTX_TCP_STATE_VALUE_FIN_WAIT1         (12<<0)
            #define L5CTX_TCP_STATE_VALUE_FIN_WAIT2         (14<<0)
            #define L5CTX_TCP_STATE_VALUE_TIME_WAIT         (16<<0)
            #define L5CTX_TCP_STATE_VALUE_CLOSE             (18<<0)
            #define L5CTX_TCP_STATE_VALUE_LAST_ACK          (20<<0)
            #define L5CTX_TCP_STATE_VALUE_CLOSING           (22<<0)

    u32_t l5ctx_tcp_rcv_next;
    u32_t l5ctx_last_ack_sent;
    u32_t l5ctx_tcp_rcv_win_seq;
    u32_t l5ctx_tcp_snd_una;
    u32_t l5ctx_tcp_snd_next;
    u32_t l5ctx_tcp_tstamp;
    u32_t l5ctx_tcp_ssthresh;
    u16_t l5ctx_tcp_sm_rtt;
    u16_t l5ctx_tcp_sm_delta;
    u32_t l5ctx_tcp_max_snd_win;
    u8_t l5ctx_tcp_comp_cons_retx_num;
    u8_t l5ctx_tcp_num_retx;
    u8_t unused_8;
    u8_t l5ctx_tcp_txp_cmd;
    u32_t unused_9;
    u8_t l5ctx_snd_q_max_cached_wqes;
    u8_t l5ctx_null_cmd_cell_pidx;
    u8_t l5ctx_null_cmd_cell_cidx;
    u8_t l5ctx_qp_flags;
        #define L5CTX_QP_FLAGS_QP_VALID                     (1<<0)
        #define L5CTX_QP_FLAGS_SUPPORTS_LAZY_WQES           (1<<1)
        #define L5CTX_QP_FLAGS_INBOUND_RDMA_READ_DISABLED   (1<<2)
        #define L5CTX_QP_FLAGS_INBOUND_RDMA_WRITE_DISABLED  (1<<3)
        #define L5CTX_QP_FLAGS_WINDOW_BINDS_ENABLED         (1<<4)
        #define L5CTX_QP_FLAGS_LOCAL_INVALIDATE_IN_PROGRESS  (1<<5)

    l5_orrq_entry_b_xi_t l5ctx_orrq[1];
    u32_t l5ctx_cq_cid;
    u32_t unused_10[4];
    u32_t l5ctx_rdma_crc;
    u32_t l5ctx_tcp_snd_wl1;
    u32_t l5ctx_tcp_snd_wl2;
    u16_t unused_11;
    u8_t l5ctx_tcp_upload_reason;
        #define L5CTX_TCP_UPLOAD_REASON_KEEP_ALIVE          (1<<0)
        #define L5CTX_TCP_UPLOAD_REASON_FIN                 (1<<1)
        #define L5CTX_TCP_UPLOAD_REASON_URG                 (1<<2)
        #define L5CTX_TCP_UPLOAD_REASON_FRAGMENT            (1<<3)
        #define L5CTX_TCP_UPLOAD_REASON_IP_OPTION           (1<<4)
        #define L5CTX_TCP_UPLOAD_REASON_RST                 (1<<5)
        #define L5CTX_TCP_UPLOAD_REASON_SYN                 (1<<6)
        #define L5CTX_TCP_UPLOAD_REASON_TIMEOUT             (1<<7)
    u8_t unused_12;

    u32_t l5ctx_tcp_offload_seq;
    u32_t l5ctx_pg_cwin;
    u32_t l5ctx_high_tcp_ack_sn_rcvd;
    u16_t l5ctx_pd;
    u8_t l5ctx_snd_q_cidx;
    u8_t l5ctx_snd_q_pidx;
    u8_t l5ctx_read_rsp_wait;
    u8_t l5ctx_rcv_q_flags;
        #define L5CTX_RCV_Q_FLAGS_PAGE_SIZE                 (0xf<<0)
            #define L5CTX_RCV_Q_FLAGS_PAGE_SIZE_256         (0<<0)
            #define L5CTX_RCV_Q_FLAGS_PAGE_SIZE_512         (1<<0)
            #define L5CTX_RCV_Q_FLAGS_PAGE_SIZE_1K          (2<<0)
            #define L5CTX_RCV_Q_FLAGS_PAGE_SIZE_2K          (3<<0)
            #define L5CTX_RCV_Q_FLAGS_PAGE_SIZE_4K          (4<<0)
            #define L5CTX_RCV_Q_FLAGS_PAGE_SIZE_8K          (5<<0)
            #define L5CTX_RCV_Q_FLAGS_PAGE_SIZE_16K         (6<<0)
            #define L5CTX_RCV_Q_FLAGS_PAGE_SIZE_32K         (7<<0)
            #define L5CTX_RCV_Q_FLAGS_PAGE_SIZE_64K         (8<<0)
            #define L5CTX_RCV_Q_FLAGS_PAGE_SIZE_128K        (9<<0)
            #define L5CTX_RCV_Q_FLAGS_PAGE_SIZE_256K        (10<<0)
            #define L5CTX_RCV_Q_FLAGS_PAGE_SIZE_512K        (11<<0)
            #define L5CTX_RCV_Q_FLAGS_PAGE_SIZE_1M          (12<<0)
            #define L5CTX_RCV_Q_FLAGS_PAGE_SIZE_2M          (13<<0)
        #define L5CTX_RCV_Q_FLAGS_QUEUE_SIZE                (0xf<<4)
            #define L5CTX_RCV_Q_FLAGS_QUEUE_SIZE_1          (0<<4)
            #define L5CTX_RCV_Q_FLAGS_QUEUE_SIZE_2          (1<<4)
            #define L5CTX_RCV_Q_FLAGS_QUEUE_SIZE_4          (2<<4)
            #define L5CTX_RCV_Q_FLAGS_QUEUE_SIZE_8          (3<<4)
            #define L5CTX_RCV_Q_FLAGS_QUEUE_SIZE_16         (4<<4)
            #define L5CTX_RCV_Q_FLAGS_QUEUE_SIZE_32         (5<<4)
            #define L5CTX_RCV_Q_FLAGS_QUEUE_SIZE_64         (6<<4)
            #define L5CTX_RCV_Q_FLAGS_QUEUE_SIZE_128        (7<<4)

    u8_t l5ctx_rcv_q_pidx;
    u8_t l5ctx_rcv_q_rxp_cidx;
    u8_t l5ctx_rcv_q_com_cidx;
    u8_t l5ctx_ird;
    u8_t l5ctx_rx_comp_flags;
        #define L5CTX_RX_COMP_FLAGS_TCP_HOLE_EXISTS         (1<<0)
        #define L5CTX_RX_COMP_FLAGS_MARKER_IN_ISLAND        (1<<1)
        #define L5CTX_RX_COMP_FLAGS_READ_REQ_OUTSTANDING    (1<<2)
        #define L5CTX_RX_COMP_FLAGS_TCP_ISLAND_CREATED      (1<<3)

    u8_t l5ctx_ooo_read_resp_segs_w_L_bit;
    u8_t l5ctx_ooo_send_msg_segs_w_L_bit;
    u8_t l5ctx_ooo_read_request_msgs;
    u8_t l5ctx_miq_index;
    u8_t l5ctx_rcv_path_op_state;
        #define L5CTX_RCV_PATH_OP_STATE_OPERATIONAL         (1<<0)
        #define L5CTX_RCV_PATH_OP_STATE_BYPASS              (1<<1)

    u32_t l5ctx_send_msg_high_msn_completed;
    u32_t l5ctx_read_req_high_msn_queued;
    u32_t l5ctx_rx_initial_tcp_sn;
    u32_t l5ctx_rsvd_l4_hole_mgmt[4];
    l5_irrq_entry_b_xi_t l5ctx_irrq[1];
    l5_abuf_cell_b_xi_t l5ctx_rcv_q_abuf[2];
    u32_t unused_13[9];
    u16_t l5ctx_snd_q_max_wqes;
    u16_t l5ctx_snd_q_fw_qidx;
    u16_t l5ctx_snd_q_pgtbl_pgidx;
    u16_t l5ctx_snd_q_wqes_per_page;
    u16_t l5ctx_snd_q_num_pages;
    u16_t l5ctx_snd_q_nx_pg_qidx;
    u32_t l5ctx_snd_q_pgtbl_phaddr_hi;
    u8_t l5ctx_snd_q_pgtbl_phaddr_lo[3];
    u8_t l5ctx_snd_q_flags;
        #define L5CTX_SND_Q_FLAGS_PAGE_SIZE                 (0xf<<0)
            #define L5CTX_SND_Q_FLAGS_PAGE_SIZE_256         (0<<0)
            #define L5CTX_SND_Q_FLAGS_PAGE_SIZE_512         (1<<0)
            #define L5CTX_SND_Q_FLAGS_PAGE_SIZE_1K          (2<<0)
            #define L5CTX_SND_Q_FLAGS_PAGE_SIZE_2K          (3<<0)
            #define L5CTX_SND_Q_FLAGS_PAGE_SIZE_4K          (4<<0)
            #define L5CTX_SND_Q_FLAGS_PAGE_SIZE_8K          (5<<0)
            #define L5CTX_SND_Q_FLAGS_PAGE_SIZE_16K         (6<<0)
            #define L5CTX_SND_Q_FLAGS_PAGE_SIZE_32K         (7<<0)
            #define L5CTX_SND_Q_FLAGS_PAGE_SIZE_64K         (8<<0)
            #define L5CTX_SND_Q_FLAGS_PAGE_SIZE_128K        (9<<0)
            #define L5CTX_SND_Q_FLAGS_PAGE_SIZE_256K        (10<<0)
            #define L5CTX_SND_Q_FLAGS_PAGE_SIZE_512K        (11<<0)
            #define L5CTX_SND_Q_FLAGS_PAGE_SIZE_1M          (12<<0)
            #define L5CTX_SND_Q_FLAGS_PAGE_SIZE_2M          (13<<0)
        #define L5CTX_SND_Q_FLAGS_QUEUE_SIZE                (0xf<<4)
            #define L5CTX_SND_Q_FLAGS_QUEUE_SIZE_1          (0<<4)
            #define L5CTX_SND_Q_FLAGS_QUEUE_SIZE_2          (1<<4)
            #define L5CTX_SND_Q_FLAGS_QUEUE_SIZE_4          (2<<4)
            #define L5CTX_SND_Q_FLAGS_QUEUE_SIZE_8          (3<<4)
            #define L5CTX_SND_Q_FLAGS_QUEUE_SIZE_16         (4<<4)
            #define L5CTX_SND_Q_FLAGS_QUEUE_SIZE_32         (5<<4)
            #define L5CTX_SND_Q_FLAGS_QUEUE_SIZE_64         (6<<4)
            #define L5CTX_SND_Q_FLAGS_QUEUE_SIZE_128        (7<<4)

    u32_t l5ctx_rcv_q_pgtbl_phaddr_hi;
    u8_t l5ctx_rcv_q_pgtbl_phaddr_lo[3];
    u8_t l5ctx_ord;
    u16_t l5ctx_rcv_q_nx_pg_qidx;
    u16_t l5ctx_tsch_mult_value;
    u16_t l5ctx_rcv_q_max_wqes;
    u16_t l5ctx_rcv_q_fw_qidx;
    u16_t l5ctx_rcv_q_pgtbl_pgidx;
    u16_t l5ctx_rcv_q_wqes_per_page;
    u16_t l5ctx_rcv_q_num_pages;
    u8_t l5ctx_max_scatter_list_elements;
    u8_t l5ctx_max_gather_list_elements;
    u32_t l5ctx_curr_send_msn;
    u32_t l5ctx_curr_rdma_read_msn;
    u32_t l5ctx_snd_q_cached_pte_phaddr_hi;
    u32_t l5ctx_snd_q_cached_pte_phaddr_lo;
    u32_t l5ctx_rcv_q_cached_pte_phaddr_hi;
    u32_t l5ctx_rcv_q_cached_pte_phaddr_lo;
    u32_t unused_14[15];
    tcp_context_cmd_cell_b_xi_t l5ctx_cmd[3];
} l5_context_b_xi_t;


/*
 *  l5_context_l definition
 */
typedef struct l5_context_l
{
    u16_t l5ctx_cq_cidx;
    u8_t l5ctx_size;
    u8_t l5ctx_type;

    u16_t l5ctx_sq_pidx;
    u8_t l5ctx_oubits;

    u8_t l5ctx_gen_bd_max;
    u16_t l5ctx_rq_pidx;
    u16_t l5ctx_tcp_pgid;
    u32_t l5ctx_tcp_timer1;

    u16_t l5ctx_tcp_timer3;

    u16_t l5ctx_tcp_timer2;

    u16_t l5ctx_tcp_timer5;

    u16_t l5ctx_tcp_timer4;

    u32_t l5ctx_tcp_snd_wl1;
    u32_t l5ctx_tcp_snd_wl2;
    u8_t l5ctx_tcp_modes;

    u8_t l5ctx_tcp_dack;
    u8_t l5ctx_tcp_tos;
    u8_t l5ctx_tcp_ttl;
    u32_t l5ctx_tcp_max_adv_win;
    u32_t l5ctx_tcp_timer;
    u32_t l5ctx_tcp_ip_src;
    u32_t l5ctx_tcp_ip_dst;
    u8_t l5ctx_tcp_tcp_hlen;
    u8_t l5ctx_tcp_rcv_seg_scale;
    u8_t l5ctx_tcp_snd_seg_scale;
    u8_t l5ctx_tcp_iphdr_nbytes;
    u16_t l5ctx_tcp_dst_port;
    u16_t l5ctx_tcp_src_port;
    u8_t l5ctx_tcp_state;

    u8_t l5ctx_tcp_flags;

    u16_t l5ctx_tcp_mss;
    u32_t l5ctx_tcp_rcv_next;
    u32_t l5ctx_last_ack_sent;
    u32_t l5ctx_tcp_rcv_win_seq;
    u32_t l5ctx_tcp_snd_una;
    u32_t l5ctx_tcp_snd_next;
    u32_t l5ctx_tcp_snd_max;
    u32_t l5ctx_tcp_snd_win;
    u32_t l5ctx_tcp_snd_cwin;
    u32_t l5ctx_tcp_tstamp;
    u32_t l5ctx_tcp_ssthresh;
    u16_t l5ctx_tcp_sm_delta;
    u16_t l5ctx_tcp_sm_rtt;
    u32_t l5ctx_tcp_max_snd_win;
    u32_t l5ctx_tcp_tsch_snd_next;
    u32_t l5ctx_tcp_slot_size;

    u8_t l5ctx_tcp_tsch_xnum;

    u8_t l5ctx_tcp_cons_retx_num;
    u8_t l5ctx_tcp_tsch_cmd;
    u8_t l5ctx_tcp_cp_cmd;
    u8_t l5ctx_tcp_tsch_cons_retx_num;
    u8_t l5ctx_tcp_prod_retx_num;
    u8_t l5ctx_tcp_tx_protocol_flags;

    u8_t l5ctx_tcp_num_dupack;
    u8_t l5ctx_tcp_txp_cmd;
    u8_t l5ctx_tcp_upload_reason;

    u8_t l5ctx_tcp_num_retx;
    u8_t l5ctx_tcp_comp_cons_retx_num;
    u32_t unused_0;
    tcp_context_cmd_cell_l_te_t l5ctx_cmd[3];
    u16_t l5ctx_snd_q_fw_qidx;
    u16_t l5ctx_snd_q_max_wqes;
    u16_t l5ctx_snd_q_pgtbl_pgidx;
    u16_t l5ctx_snd_q_nx_pg_qidx;
    u16_t l5ctx_snd_q_num_pages;
    u16_t l5ctx_snd_q_wqes_per_page;
    u8_t l5ctx_snd_q_flags;

    u8_t l5ctx_snd_q_max_cached_wqes;
    u8_t l5ctx_snd_q_cidx;
    u8_t l5ctx_snd_q_pidx;
    u32_t l5ctx_snd_q_pgtbl_phaddr_hi;
    u8_t l5ctx_snd_q_read_rsp_wait;
    u8_t l5ctx_snd_q_pgtbl_phaddr_lo[3];
    u32_t l5ctx_snd_q_cached_pte_phaddr_hi;
    u32_t l5ctx_snd_q_cached_pte_phaddr_lo;
    l5_cmd_cell_l_t l5ctx_snd_q_cmd[3];
    u16_t l5ctx_rcv_q_fw_qidx;
    u16_t l5ctx_rcv_q_max_wqes;
    u16_t l5ctx_rcv_q_pgtbl_pgidx;
    u16_t l5ctx_rcv_q_nx_pg_qidx;
    u16_t l5ctx_rcv_q_num_pages;
    u16_t l5ctx_rcv_q_wqes_per_page;
    u8_t l5ctx_rcv_q_flags;

    u8_t l5ctx_rcv_q_com_cidx;
    u8_t l5ctx_rcv_q_rxp_cidx;
    u8_t l5ctx_rcv_q_pidx;
    u32_t l5ctx_rcv_q_pgtbl_phaddr_hi;
    u8_t l5ctx_rcv_q_qp_ou_state;
        #define L5CTX_RCV_Q_QP_OU_STATE_UPLOADED            (1<<0)
        #define L5CTX_RCV_Q_QP_OU_STATE_OFFLOADED           (1<<1)
        #define L5CTX_RCV_Q_QP_OU_STATE_UPLOAD_REQ          (1<<2)
        #define L5CTX_RCV_Q_QP_OU_STATE_OFFLOAD_REQ         (1<<3)

    u8_t l5ctx_rcv_q_pgtbl_phaddr_lo[3];
    u32_t l5ctx_rcv_q_cached_pte_phaddr_hi;
    u32_t l5ctx_rcv_q_cached_pte_phaddr_lo;
    l5_abuf_cell_l_t l5ctx_rcv_q_abuf[2];
    u32_t l5ctx_cq_cid;
    u32_t l5ctx_curr_send_msn;
    u32_t l5ctx_curr_rdma_read_msn;
    u8_t l5ctx_ird;
    u8_t l5ctx_rcv_path_op_state;

    u16_t l5ctx_pd;
    u32_t l5ctx_tx_initial_tcp_sn;
    u8_t l5ctx_null_cmd_cell_cidx;
    u8_t l5ctx_null_cmd_cell_pidx;
    u16_t l5ctx_tsch_mult_value;
    l5_orrq_entry_l_t l5ctx_orrq[1];
    l5_irrq_entry_l_t l5ctx_irrq[1];
    u8_t l5ctx_upload_flag;

    u8_t l5ctx_qp_flags;

    u8_t l5ctx_rx_comp_flags;

    u8_t l5ctx_miq_index;
    u8_t l5ctx_ooo_read_request_msgs;
    u8_t l5ctx_ooo_send_msg_segs_w_L_bit;
    u8_t l5ctx_ooo_read_resp_segs_w_L_bit;
    u8_t l5ctx_upload_rxp;

    u32_t l5ctx_high_tcp_ack_sn_rcvd;
    u32_t l5ctx_rx_initial_tcp_sn;
    u32_t l5ctx_send_msg_high_msn_completed;
    u32_t l5ctx_read_req_high_msn_queued;
    u32_t l5ctx_rsvd_l4_hole_mgmt[3];
    u16_t l5ctx_offload_flag;
    u16_t l5ctx_cam_index;
} l5_context_l_t;



/*
 *  l5_context_l definition
 */
typedef struct l5_context_l_xi
{
    u32_t l5ctx_tcp_tsch_snd_next;
    u32_t l5ctx_tcp_snd_max;
    u8_t l5ctx_tcp_tsch_xnum;
        #define L5CTX_TCP_TSCH_XNUM_VAL                     (0x7f<<0)
        #define L5CTX_TCP_TSCH_XNUM_L4                      (1<<7)

    u8_t l5ctx_tcp_cons_retx_num;
    u8_t l5ctx_tcp_tsch_cmd;
    u8_t l5ctx_tcp_cp_cmd;
    u8_t l5ctx_tcp_tsch_cons_retx_num;
    u8_t l5ctx_tcp_prod_retx_num;
    u16_t l5ctx_tcp_pgid;
        #define L5CTX_TCP_PGID_VAL                          (0x3fff<<0)
    u16_t unused_0;
    u8_t unused_1;

    u8_t l5ctx_tcp_l2_slot_size;
    u32_t unused_2;
    u8_t l5ctx_tcp_modes;
        #define L5CTX_TCP_MODES_RST_INDICATED               (1<<0)
        #define L5CTX_TCP_MODES_DISC_BD                     (1<<1)
        #define L5CTX_TCP_MODES_UPLOAD_INITED               (1<<2)
        #define L5CTX_TCP_MODES_RMT_DISC                    (1<<3)
        #define L5CTX_TCP_MODES_PG_INVALIDATED              (1<<4)
        #define L5CTX_TCP_MODES_ABORT_PENDING               (1<<5)
        #define L5CTX_TCP_MODES_DISC_PENDING                (1<<6)
        #define L5CTX_TCP_MODES_SS                          (1<<7)

    u8_t l5ctx_tcp_dack;
    u8_t l5ctx_tcp_tos;
    u8_t l5ctx_tcp_ttl;
    u32_t l5ctx_tcp_max_adv_win;
    u32_t l5ctx_timer;
    u32_t l5ctx_tcp_ip_src;
    u32_t l5ctx_tcp_ip_dst;
    u8_t l5ctx_tcp_tcp_hlen;
    u8_t l5ctx_tcp_rcv_seg_scale;
    u8_t l5ctx_tcp_snd_seg_scale;
    u8_t l5ctx_tcp_iphdr_nbytes;
    u16_t l5ctx_tcp_dst_port;
    u16_t l5ctx_tcp_src_port;
    u32_t l5ctx_tx_initial_tcp_sn;
    u16_t unused_3;
    u8_t unused_4;
    u8_t l5ctx_upload_flag;
        #define L5CTX_UPLOAD_FLAG_TXP                       (1<<0)
        #define L5CTX_UPLOAD_FLAG_TXP_COM                   (1<<1)
    u32_t unused_5[17];

    u16_t l5ctx_cq_cidx;
    u8_t l5ctx_size;
        #define L5CTX_SIZE_ARM_CQ                           (1<<0)

    u8_t l5ctx_type;
        #define L5CTX_TYPE_TYPE                             (0xf<<4)
            #define L5CTX_TYPE_TYPE_EMPTY                   (0<<4)
            #define L5CTX_TYPE_TYPE_L2                      (1<<4)
            #define L5CTX_TYPE_TYPE_TCP                     (2<<4)
            #define L5CTX_TYPE_TYPE_L5                      (3<<4)
            #define L5CTX_TYPE_TYPE_L2_BD_CHN               (4<<4)

    u16_t l5ctx_sq_pidx;
    u8_t l5ctx_oubits;
        #define L5CTX_OUBITS_ACTIVATE                       (1<<0)
        #define L5CTX_OUBITS_CP_UPLOAD                      (1<<1)
        #define L5CTX_OUBITS_RXP_UPLOAD                     (1<<2)
        #define L5CTX_OUBITS_TXP_UPLOAD                     (1<<3)
        #define L5CTX_OUBITS_COM_RX_UPLOAD                  (1<<4)
        #define L5CTX_OUBITS_COM_TX_UPLOAD                  (1<<5)
        #define L5CTX_OUBITS_CP_UPLOAD_COMP                 (1<<6)
        #define L5CTX_OUBITS_HOST_ACK                       (1<<7)

    u8_t l5ctx_gen_bd_max;
    u16_t l5ctx_rq_pidx;
    u16_t unused_6;
    u32_t l5ctx_tcp_timer1;
        #define L5CTX_TCP_TIMER1_DISABLE                    (1UL<<0)
        #define L5CTX_TCP_TIMER1_VALUE                      (0x7fffffffL<<1)

    u16_t l5ctx_tcp_timer3;
        #define L5CTX_TCP_TIMER3_DISABLE                    (1<<0)
        #define L5CTX_TCP_TIMER3_VALUE                      (0x7fff<<1)

    u16_t l5ctx_tcp_timer2;
        #define L5CTX_TCP_TIMER2_DISABLE                    (1<<0)
        #define L5CTX_TCP_TIMER2_VALUE                      (0x7fff<<1)

    u16_t l5ctx_tcp_timer5;
        #define L5CTX_TCP_TIMER5_DISABLE                    (1<<0)
        #define L5CTX_TCP_TIMER5_VALUE                      (0x7fff<<1)

    u16_t l5ctx_tcp_timer4;
        #define L5CTX_TCP_TIMER4_DISABLE                    (1<<0)
        #define L5CTX_TCP_TIMER4_VALUE                      (0x7fff<<1)

    u32_t l5ctx_tcp_slot_size;
        #define L5CTX_TCP_SLOT_SIZE_SLOT_SIZE               (0xffffffL<<0)
        #define L5CTX_TCP_SLOT_SIZE_CMD_MAX                 (0x7fL<<24)
        #define L5CTX_TCP_SLOT_SIZE_STOP                    (1UL<<31)

    u32_t l5ctx_tcp_snd_cwin;
    u32_t l5ctx_tcp_snd_win;
    u8_t l5ctx_qp_ou_state;
        #define L5CTX_QP_OU_STATE_UPLOADED                  (1<<0)
        #define L5CTX_QP_OU_STATE_OFFLOADED                 (1<<1)
        #define L5CTX_QP_OU_STATE_UPLOAD_REQ                (1<<2)
        #define L5CTX_QP_OU_STATE_OFFLOAD_REQ               (1<<3)

    u8_t l5ctx_upload_rxp;
        #define L5CTX_UPLOAD_RXP_COM                        (1<<0)

    u8_t l5ctx_tcp_tx_protocol_flags;
        #define L5CTX_TCP_TX_PROTOCOL_FLAGS_TIMER_DELAY_ACK  (1<<0)
        #define L5CTX_TCP_TX_PROTOCOL_FLAGS_UPLOAD          (1<<1)
        #define L5CTX_TCP_TX_PROTOCOL_FLAGS_FORCE_ACK       (1<<2)
        #define L5CTX_TCP_TX_PROTOCOL_FLAGS_LAST_ACK        (1<<3)
        #define L5CTX_TCP_TX_PROTOCOL_FLAGS_LAST_RST        (1<<4)
        #define L5CTX_TCP_TX_PROTOCOL_FLAGS_FORCE_RST       (1<<5)
        #define L5CTX_TCP_TX_PROTOCOL_FLAGS_FORCE_ACK_MINUS  (1<<6)
        #define L5CTX_TCP_TX_PROTOCOL_FLAGS_TSCH_WA         (1<<7)

    u8_t l5ctx_tcp_num_dupack;
    u32_t unused_7;
    u8_t l5ctx_tcp_state;
        #define L5CTX_TCP_STATE_VALUE                       (0xff<<0)
            #define L5CTX_TCP_STATE_VALUE_UNDEFINED         (0<<0)
            #define L5CTX_TCP_STATE_VALUE_LISTEN            (2<<0)
            #define L5CTX_TCP_STATE_VALUE_SYN_SENT          (4<<0)
            #define L5CTX_TCP_STATE_VALUE_SYN_RECV          (6<<0)
            #define L5CTX_TCP_STATE_VALUE_CLOSE_WAIT        (8<<0)
            #define L5CTX_TCP_STATE_VALUE_ESTABLISHED       (10<<0)
            #define L5CTX_TCP_STATE_VALUE_FIN_WAIT1         (12<<0)
            #define L5CTX_TCP_STATE_VALUE_FIN_WAIT2         (14<<0)
            #define L5CTX_TCP_STATE_VALUE_TIME_WAIT         (16<<0)
            #define L5CTX_TCP_STATE_VALUE_CLOSE             (18<<0)
            #define L5CTX_TCP_STATE_VALUE_LAST_ACK          (20<<0)
            #define L5CTX_TCP_STATE_VALUE_CLOSING           (22<<0)

    u8_t l5ctx_tcp_flags;
        #define L5CTX_TCP_FLAGS_NO_DELAY_ACK                (1<<0)
        #define L5CTX_TCP_FLAGS_KEEP_ALIVE                  (1<<1)
        #define L5CTX_TCP_FLAGS_NAGLE                       (1<<2)
        #define L5CTX_TCP_FLAGS_TIME_STAMP                  (1<<3)
        #define L5CTX_TCP_FLAGS_SACK                        (1<<4)
        #define L5CTX_TCP_FLAGS_SEG_SCALING                 (1<<5)

    u16_t l5ctx_tcp_mss;
    u32_t l5ctx_tcp_rcv_next;
    u32_t l5ctx_last_ack_sent;
    u32_t l5ctx_tcp_rcv_win_seq;
    u32_t l5ctx_tcp_snd_una;
    u32_t l5ctx_tcp_snd_next;
    u32_t l5ctx_tcp_tstamp;
    u32_t l5ctx_tcp_ssthresh;
    u16_t l5ctx_tcp_sm_delta;
    u16_t l5ctx_tcp_sm_rtt;
    u32_t l5ctx_tcp_max_snd_win;
    u8_t l5ctx_tcp_txp_cmd;
    u8_t unused_8;
    u8_t l5ctx_tcp_num_retx;
    u8_t l5ctx_tcp_comp_cons_retx_num;
    u32_t unused_9;
    u8_t l5ctx_qp_flags;
        #define L5CTX_QP_FLAGS_QP_VALID                     (1<<0)
        #define L5CTX_QP_FLAGS_SUPPORTS_LAZY_WQES           (1<<1)
        #define L5CTX_QP_FLAGS_INBOUND_RDMA_READ_DISABLED   (1<<2)
        #define L5CTX_QP_FLAGS_INBOUND_RDMA_WRITE_DISABLED  (1<<3)
        #define L5CTX_QP_FLAGS_WINDOW_BINDS_ENABLED         (1<<4)
        #define L5CTX_QP_FLAGS_LOCAL_INVALIDATE_IN_PROGRESS  (1<<5)

    u8_t l5ctx_null_cmd_cell_cidx;
    u8_t l5ctx_null_cmd_cell_pidx;
    u8_t l5ctx_snd_q_max_cached_wqes;
    l5_orrq_entry_l_xi_t l5ctx_orrq[1];
    u32_t l5ctx_cq_cid;
    u32_t unused_10[4];
    u32_t l5ctx_rdma_crc;
    u32_t l5ctx_tcp_snd_wl1;
    u32_t l5ctx_tcp_snd_wl2;
    u8_t unused_11;
    u8_t l5ctx_tcp_upload_reason;
        #define L5CTX_TCP_UPLOAD_REASON_KEEP_ALIVE          (1<<0)
        #define L5CTX_TCP_UPLOAD_REASON_FIN                 (1<<1)
        #define L5CTX_TCP_UPLOAD_REASON_URG                 (1<<2)
        #define L5CTX_TCP_UPLOAD_REASON_FRAGMENT            (1<<3)
        #define L5CTX_TCP_UPLOAD_REASON_IP_OPTION           (1<<4)
        #define L5CTX_TCP_UPLOAD_REASON_RST                 (1<<5)
        #define L5CTX_TCP_UPLOAD_REASON_SYN                 (1<<6)
        #define L5CTX_TCP_UPLOAD_REASON_TIMEOUT             (1<<7)
    u16_t unused_12;

    u32_t l5ctx_tcp_offload_seq;
    u32_t l5ctx_pg_cwin;
    u32_t l5ctx_high_tcp_ack_sn_rcvd;
    u8_t l5ctx_snd_q_pidx;
    u8_t l5ctx_snd_q_cidx;
    u16_t l5ctx_pd;
    u8_t l5ctx_rcv_q_rxp_cidx;
    u8_t l5ctx_rcv_q_pidx;
    u8_t l5ctx_rcv_q_flags;
        #define L5CTX_RCV_Q_FLAGS_PAGE_SIZE                 (0xf<<0)
            #define L5CTX_RCV_Q_FLAGS_PAGE_SIZE_256         (0<<0)
            #define L5CTX_RCV_Q_FLAGS_PAGE_SIZE_512         (1<<0)
            #define L5CTX_RCV_Q_FLAGS_PAGE_SIZE_1K          (2<<0)
            #define L5CTX_RCV_Q_FLAGS_PAGE_SIZE_2K          (3<<0)
            #define L5CTX_RCV_Q_FLAGS_PAGE_SIZE_4K          (4<<0)
            #define L5CTX_RCV_Q_FLAGS_PAGE_SIZE_8K          (5<<0)
            #define L5CTX_RCV_Q_FLAGS_PAGE_SIZE_16K         (6<<0)
            #define L5CTX_RCV_Q_FLAGS_PAGE_SIZE_32K         (7<<0)
            #define L5CTX_RCV_Q_FLAGS_PAGE_SIZE_64K         (8<<0)
            #define L5CTX_RCV_Q_FLAGS_PAGE_SIZE_128K        (9<<0)
            #define L5CTX_RCV_Q_FLAGS_PAGE_SIZE_256K        (10<<0)
            #define L5CTX_RCV_Q_FLAGS_PAGE_SIZE_512K        (11<<0)
            #define L5CTX_RCV_Q_FLAGS_PAGE_SIZE_1M          (12<<0)
            #define L5CTX_RCV_Q_FLAGS_PAGE_SIZE_2M          (13<<0)
        #define L5CTX_RCV_Q_FLAGS_QUEUE_SIZE                (0xf<<4)
            #define L5CTX_RCV_Q_FLAGS_QUEUE_SIZE_1          (0<<4)
            #define L5CTX_RCV_Q_FLAGS_QUEUE_SIZE_2          (1<<4)
            #define L5CTX_RCV_Q_FLAGS_QUEUE_SIZE_4          (2<<4)
            #define L5CTX_RCV_Q_FLAGS_QUEUE_SIZE_8          (3<<4)
            #define L5CTX_RCV_Q_FLAGS_QUEUE_SIZE_16         (4<<4)
            #define L5CTX_RCV_Q_FLAGS_QUEUE_SIZE_32         (5<<4)
            #define L5CTX_RCV_Q_FLAGS_QUEUE_SIZE_64         (6<<4)
            #define L5CTX_RCV_Q_FLAGS_QUEUE_SIZE_128        (7<<4)

    u8_t l5ctx_read_rsp_wait;
    u8_t l5ctx_ooo_read_resp_segs_w_L_bit;
    u8_t l5ctx_rx_comp_flags;
        #define L5CTX_RX_COMP_FLAGS_TCP_HOLE_EXISTS         (1<<0)
        #define L5CTX_RX_COMP_FLAGS_MARKER_IN_ISLAND        (1<<1)
        #define L5CTX_RX_COMP_FLAGS_READ_REQ_OUTSTANDING    (1<<2)
        #define L5CTX_RX_COMP_FLAGS_TCP_ISLAND_CREATED      (1<<3)

    u8_t l5ctx_ird;
    u8_t l5ctx_rcv_q_com_cidx;
    u8_t l5ctx_rcv_path_op_state;
        #define L5CTX_RCV_PATH_OP_STATE_OPERATIONAL         (1<<0)
        #define L5CTX_RCV_PATH_OP_STATE_BYPASS              (1<<1)

    u8_t l5ctx_miq_index;
    u8_t l5ctx_ooo_read_request_msgs;
    u8_t l5ctx_ooo_send_msg_segs_w_L_bit;
    u32_t l5ctx_send_msg_high_msn_completed;
    u32_t l5ctx_read_req_high_msn_queued;
    u32_t l5ctx_rx_initial_tcp_sn;
    u32_t l5ctx_rsvd_l4_hole_mgmt[4];
    l5_irrq_entry_l_xi_t l5ctx_irrq[1];
    l5_abuf_cell_l_xi_t l5ctx_rcv_q_abuf[2];
    u32_t unused_13[9];
    u16_t l5ctx_snd_q_fw_qidx;
    u16_t l5ctx_snd_q_max_wqes;
    u16_t l5ctx_snd_q_wqes_per_page;
    u16_t l5ctx_snd_q_pgtbl_pgidx;
    u16_t l5ctx_snd_q_nx_pg_qidx;
    u16_t l5ctx_snd_q_num_pages;
    u32_t l5ctx_snd_q_pgtbl_phaddr_hi;
    u8_t l5ctx_snd_q_flags;
        #define L5CTX_SND_Q_FLAGS_PAGE_SIZE                 (0xf<<0)
            #define L5CTX_SND_Q_FLAGS_PAGE_SIZE_256         (0<<0)
            #define L5CTX_SND_Q_FLAGS_PAGE_SIZE_512         (1<<0)
            #define L5CTX_SND_Q_FLAGS_PAGE_SIZE_1K          (2<<0)
            #define L5CTX_SND_Q_FLAGS_PAGE_SIZE_2K          (3<<0)
            #define L5CTX_SND_Q_FLAGS_PAGE_SIZE_4K          (4<<0)
            #define L5CTX_SND_Q_FLAGS_PAGE_SIZE_8K          (5<<0)
            #define L5CTX_SND_Q_FLAGS_PAGE_SIZE_16K         (6<<0)
            #define L5CTX_SND_Q_FLAGS_PAGE_SIZE_32K         (7<<0)
            #define L5CTX_SND_Q_FLAGS_PAGE_SIZE_64K         (8<<0)
            #define L5CTX_SND_Q_FLAGS_PAGE_SIZE_128K        (9<<0)
            #define L5CTX_SND_Q_FLAGS_PAGE_SIZE_256K        (10<<0)
            #define L5CTX_SND_Q_FLAGS_PAGE_SIZE_512K        (11<<0)
            #define L5CTX_SND_Q_FLAGS_PAGE_SIZE_1M          (12<<0)
            #define L5CTX_SND_Q_FLAGS_PAGE_SIZE_2M          (13<<0)
        #define L5CTX_SND_Q_FLAGS_QUEUE_SIZE                (0xf<<4)
            #define L5CTX_SND_Q_FLAGS_QUEUE_SIZE_1          (0<<4)
            #define L5CTX_SND_Q_FLAGS_QUEUE_SIZE_2          (1<<4)
            #define L5CTX_SND_Q_FLAGS_QUEUE_SIZE_4          (2<<4)
            #define L5CTX_SND_Q_FLAGS_QUEUE_SIZE_8          (3<<4)
            #define L5CTX_SND_Q_FLAGS_QUEUE_SIZE_16         (4<<4)
            #define L5CTX_SND_Q_FLAGS_QUEUE_SIZE_32         (5<<4)
            #define L5CTX_SND_Q_FLAGS_QUEUE_SIZE_64         (6<<4)
            #define L5CTX_SND_Q_FLAGS_QUEUE_SIZE_128        (7<<4)

    u8_t l5ctx_snd_q_pgtbl_phaddr_lo[3];
    u32_t l5ctx_rcv_q_pgtbl_phaddr_hi;
    u8_t l5ctx_ord;
    u8_t l5ctx_rcv_q_pgtbl_phaddr_lo[3];
    u16_t l5ctx_tsch_mult_value;
    u16_t l5ctx_rcv_q_nx_pg_qidx;
    u16_t l5ctx_rcv_q_fw_qidx;
    u16_t l5ctx_rcv_q_max_wqes;
    u16_t l5ctx_rcv_q_wqes_per_page;
    u16_t l5ctx_rcv_q_pgtbl_pgidx;
    u8_t l5ctx_max_gather_list_elements;
    u8_t l5ctx_max_scatter_list_elements;
    u16_t l5ctx_rcv_q_num_pages;
    u32_t l5ctx_curr_send_msn;
    u32_t l5ctx_curr_rdma_read_msn;
    u32_t l5ctx_snd_q_cached_pte_phaddr_hi;
    u32_t l5ctx_snd_q_cached_pte_phaddr_lo;
    u32_t l5ctx_rcv_q_cached_pte_phaddr_hi;
    u32_t l5ctx_rcv_q_cached_pte_phaddr_lo;
    u32_t unused_14[15];
    tcp_context_cmd_cell_l_xi_t l5ctx_cmd[3];
} l5_context_l_xi_t;


/*
 * l5_context select
 */
#if defined(LITTLE_ENDIAN)
    typedef l5_context_l_t l5_context_t;
    typedef l5_context_l_xi_t l5_context_xi_t;
#elif defined(BIG_ENDIAN)
    typedef l5_context_b_t l5_context_t;
    typedef l5_context_b_xi_t l5_context_xi_t;
#endif
    

#endif /* _l5_defs_h_ */
