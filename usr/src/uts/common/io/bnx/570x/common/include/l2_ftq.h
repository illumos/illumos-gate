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

#ifndef _l2_ftq_h_
#define _l2_ftq_h_

#include "l2_defs.h"

// This is to avoid compiling error for drivers compilation
#if  !defined (TARGET_CHIP)
    #define TARGET_CHIP      5709
#endif




/*
 *  rxp cmd enqueue definition
 *  offset: 0000
 */


#if defined(LITTLE_ENDIAN)
    typedef struct rxpcq_l
    {
        u32_t cid;
	    union{
            u32_t host_opaque;
            u32_t generic1;
        }u1;
	    union{
            struct {
                u16_t status;
                u8_t  opcode;
                u8_t  flags; 
            }s1;
            u32_t generic2;
        }u2;
    } rxpcq_l_t;

    typedef rxpcq_l_t rxpcq_t;
#elif defined(BIG_ENDIAN)
    typedef struct rxpcq_b
    {
        u32_t cid;
	    union{
            u32_t host_opaque;
            u32_t generic1;
        } u1;
	    union{
            struct {
                u8_t  flags; 
                u8_t  opcode;
                u16_t status;
            } s1;
            u32_t generic2;
        } u2;
    } rxpcq_b_t;

    typedef rxpcq_b_t rxpcq_t;
#endif


/*
 *  rxp enqueue definition
 *  offset: 0000
 */
typedef struct rxpq_b
{
    u32_t bits_errors;
    u32_t bits_status;
   
    u8_t  bit_mcast_hash_idx;
    u8_t  bits_acpi_pat;
    u8_t  knum;
    u8_t  unused1;
    
    u16_t rule_tag;
    u16_t pkt_len;
    
    u16_t vlan_tag;
    u8_t  ip_hdr_offset;
    u8_t  rx_qid;
    
    u16_t ip_xsum;
    // this field has been extended to 2-byte in Xinan
#if (TARGET_CHIP == 5706)
    u8_t  tcp_udp_hdr_offset;
    u8_t  unused2;     
#else
    u16_t tcp_udp_hdr_offset;
#endif    
    u16_t tcp_udp_xsum;
    u16_t tcp_payload_len;
    
    u16_t pseud_xsum;
    u16_t l2_payload_raw_xsum;
    // this field has been extended to 2-byte in Xinan
#if (TARGET_CHIP == 5706)
    u8_t  data_offset;
    u8_t  unused3;                                      
#else
    u16_t data_offset;
#endif
    u16_t l3_payload_raw_xsum;
    
    u32_t mbuf_cluster;
    u32_t cid;

    u16_t cs16;
    u16_t unused4;

    u16_t ext_status;
    u16_t unused5;
    
} rxpq_b_t;

typedef struct rxpq_l
{
    u32_t bits_errors;
    u32_t bits_status;
   
    u8_t  unused1;
    u8_t  knum;
    u8_t  bits_acpi_pat;
    u8_t  bit_mcast_hash_idx;
    
    u16_t pkt_len;
    u16_t rule_tag;
    
    u8_t  rx_qid;
    u8_t  ip_hdr_offset;
    u16_t vlan_tag;
    
    // this field has been extended to 2-byte in Xinan
#if (TARGET_CHIP == 5706)
    u8_t  unused2;                                      
    u8_t tcp_udp_hdr_offset;
#else
    u16_t tcp_udp_hdr_offset;
#endif
    u16_t ip_xsum;
    
    u16_t tcp_payload_len;
    u16_t tcp_udp_xsum;
    
    u16_t l2_payload_raw_xsum;
    u16_t pseud_xsum;

    u16_t l3_payload_raw_xsum;
    // this field has been extended to 2-byte in Xinan
#if (TARGET_CHIP == 5706)
    u8_t  unused3;                                      
    u8_t  data_offset;
#else
    u16_t data_offset;
#endif    
    u32_t mbuf_cluster;
    u32_t cid;

    u16_t unused4;
    u16_t cs16;

    u16_t unused5;
    u16_t ext_status;
    
} rxpq_l_t;

#if defined(LITTLE_ENDIAN)
    typedef rxpq_l_t rxpq_t;
#elif defined(BIG_ENDIAN)
    typedef rxpq_b_t rxpq_t;
#endif

/*
 *  rv2ppq_generic definition
 */
typedef struct rv2ppq_generic_b
{
    u32_t cid;
    u32_t mbuf_cluster;
    u16_t operand_flags;
    u8_t knum;
    u8_t opcode;
        #define GENERIC_OPCODE_RV2PPQ_VALUE_UNUSED               0
        #define GENERIC_OPCODE_RV2PPQ_VALUE_NOP                  1
        #define GENERIC_OPCODE_RV2PPQ_VALUE_OPAQUE               2
        #define GENERIC_OPCODE_RV2PPQ_VALUE_L2_PLACE             3
        #define GENERIC_OPCODE_RV2PPQ_VALUE_L4_PLACE             4
        #define GENERIC_OPCODE_RV2PPQ_VALUE_L4_FLUSH             5
        #define GENERIC_OPCODE_RV2PPQ_VALUE_L5_PLACE            10
        #define GENERIC_OPCODE_RV2PPQ_VALUE_L5_FLUSH            14
        #define GENERIC_OPCODE_RV2PPQ_VALUE_DBG_RDMA            17
        #define GENERIC_OPCODE_RV2PPQ_VALUE_DBG_RV2P            18
        #define GENERIC_OPCODE_RV2PPQ_VALUE_L4_INDICATE_TIMEOUT 20
        #define GENERIC_OPCODE_RV2PPQ_VALUE_L2_JUMBO_PLACE      26
        #define GENERIC_OPCODE_RV2PPQ_VALUE_L2_FLUSH_BD_CHAIN   28
        #define GENERIC_OPCODE_RV2PPQ_VALUE_FLR                 29 // X1V only

    u16_t operand16_0;    // Note that 16_0 and 16_1 will be absorbed 
    u16_t operand16_1;    // by RDMA and won't be passed to COM
    u16_t operand16_2;
    u16_t operand16_3;
    u16_t operand16_4;
    u16_t operand16_5;
    u16_t operand16_6;
    u16_t operand16_7;
    u32_t operand32_0;    // Note that 32_0 and 32_1 will be absorbed
    u32_t operand32_1;    // by RDMA and won't be passed to COM 
    u32_t operand32_2;
    u32_t operand32_3;
    u32_t operand32_4;
    u8_t rdma_action;   // no need to be cleared by RXP, RV2P will do it
    u8_t cs16_pkt_len;
    u16_t cs16;
} rv2ppq_generic_b_t;

typedef struct rv2ppq_generic_l
{
    u32_t cid;
    u32_t mbuf_cluster;
    u8_t  opcode;
    u8_t  knum;
    u16_t operand_flags;
    u16_t operand16_1;    // by RDMA and won't be passed to COM
    u16_t operand16_0;    // Note that 16_0 and 16_1 will be absorbed 
    u16_t operand16_3;
    u16_t operand16_2;
    u16_t operand16_5;
    u16_t operand16_4;
    u16_t operand16_7;
    u16_t operand16_6;
    u32_t operand32_0;    // Note that 32_0 and 32_1 will be absorbed
    u32_t operand32_1;    // by RDMA and won't be passed to COM 
    u32_t operand32_2;
    u32_t operand32_3;
    u32_t operand32_4;
    u16_t cs16;
    u8_t cs16_pkt_len;
    u8_t rdma_action;   // no need to be cleared by RXP, RV2P will do it
} rv2ppq_generic_l_t;

#if defined(LITTLE_ENDIAN)
    typedef rv2ppq_generic_l_t rv2ppq_generic_t;
#elif defined(BIG_ENDIAN)
    typedef rv2ppq_generic_b_t rv2ppq_generic_t;
#endif



/*
 *  rv2ppq_l2_place definition
 */
typedef struct rv2ppq_l2_place_b
{
    u32_t cid;
    u32_t mbuf_cluster;
    u16_t operand_flags;
        #define L2_OPERAND_FLAGS_PREPEND_L2_FRAME_HEADER  (1<<0)
        #define L2_OPERAND_FLAGS_LAST                     (1<<1)
        #define L2_OPERAND_FLAGS_ENQUEUE_TO_MCP           (1<<2)
        #define L2_OPERAND_FLAGS_DROP_PKT                 (1<<3)
        #define L2_OPERAND_FLAGS_MCAST                    (1<<4)
        #define L2_OPERAND_FLAGS_BCAST                    (1<<5)
        #define L2_OPERAND_FLAGS_VMQ                      (1<<6)
        #define L2_OPERAND_FLAGS_OOO_PLACE                (1<<7)
        #define L2_OPERAND_FLAGS_CU_PKT                   (1<<14)

    u8_t knum;
    u8_t opcode;
    u16_t offset;
    u16_t length; // represent look-ahead_hdr length if VMQ flag is set (total pkt len otherwise)
    u16_t bits_status;
    u16_t vlan_tag;
    u16_t ip_xsum;
    u16_t udp_tcp_xsum;
    u16_t unused_0;
    u16_t packet_length; // represent total packet length 
    u32_t unused_1[2];
    u16_t unused_2;
    u16_t error_flags;
        #define L2_ERROR_FLAGS_CRC_ERROR              (1<<1)
        #define L2_ERROR_FLAGS_PHY_DECODE_ERROR       (1<<2)
        #define L2_ERROR_FLAGS_ALIGNMENT_ERROR        (1<<3)
        #define L2_ERROR_FLAGS_TOO_SHORT_ERROR        (1<<4)
        #define L2_ERROR_FLAGS_GIANT_FRAME_ERROR      (1<<5)

    u32_t hash;
    u32_t rt_bt;
    u8_t rdma_action;  // no need to be cleared by RXP, RV2P will do it
    u8_t cs16_pkt_len;
    u16_t cs16;
   
} rv2ppq_l2_place_b_t;

typedef struct rv2ppq_l2_place_l
{
    u32_t cid;
    u32_t mbuf_cluster;
    u8_t opcode;
    u8_t knum;
    u16_t operand_flags;
    u16_t length; // represent look-ahead_hdr_length if VMQ flag is set (total pkt len otherwise)
    u16_t offset;
    u16_t vlan_tag;
    u16_t bits_status;
    u16_t udp_tcp_xsum;
    u16_t ip_xsum;
    u16_t packet_length; // represent total packet length if VMQ flag is set 
    u16_t unused_0;
    u32_t unused_1[2];
    u16_t error_flags;
    u16_t unused_2;
    u32_t hash;
    u32_t rt_bt;
    u16_t cs16;
    u8_t cs16_pkt_len;
    u8_t rdma_action;  // no need to be cleared by RXP, RV2P will do it

} rv2ppq_l2_place_l_t;

#if defined(LITTLE_ENDIAN)
    typedef rv2ppq_l2_place_l_t rv2ppq_l2_place_t;
#elif defined(BIG_ENDIAN)
    typedef rv2ppq_l2_place_b_t rv2ppq_l2_place_t;
#endif


/*
 *  rv2ppq_l2_flush_bd_chain definition
 */
typedef struct rv2ppq_l2_flush_bd_chain_b
{
    u32_t cid;
    u32_t unused_0;
    u16_t unused_1;
    u8_t unused_2;
    u8_t opcode;
    u32_t unused_3[9];
    u8_t rdma_action; // no need to be cleared by RXP, RV2P will do it
    u8_t cs16_pkt_len;
    u16_t cs16;
    
} rv2ppq_l2_flush_bd_chain_b_t;

typedef struct rv2ppq_l2_flush_bd_chain_l
{
    u32_t cid;
    u32_t unused_0;
    u8_t opcode;
    u8_t unused_2;
    u16_t unused_1;
    u32_t unused_3[9];
    u16_t cs16;
    u8_t cs16_pkt_len;
    u8_t rdma_action; // no need to be cleared by RXP, RV2P will do it
    
} rv2ppq_l2_flush_bd_chain_l_t;

#if defined(LITTLE_ENDIAN)
    typedef rv2ppq_l2_flush_bd_chain_l_t rv2ppq_l2_flush_bd_chain_t;
#elif defined(BIG_ENDIAN)
    typedef rv2ppq_l2_flush_bd_chain_b_t rv2ppq_l2_flush_bd_chain_t;
#endif

/*
 *  comq_generic definition
 */
typedef enum 
{
    GENERIC_OPCODE_COMQ_VALUE_UNUSED                =  0,
    GENERIC_OPCODE_COMQ_VALUE_NOP                   = GENERIC_OPCODE_RV2PPQ_VALUE_NOP      ,
    GENERIC_OPCODE_COMQ_VALUE_OPAQUE                = GENERIC_OPCODE_RV2PPQ_VALUE_OPAQUE   ,
    GENERIC_OPCODE_COMQ_VALUE_L2_COMPLETION         = GENERIC_OPCODE_RV2PPQ_VALUE_L2_PLACE ,
    GENERIC_OPCODE_COMQ_VALUE_L4_COMPLETION         = GENERIC_OPCODE_RV2PPQ_VALUE_L4_PLACE ,
    GENERIC_OPCODE_COMQ_VALUE_L4_FLUSH              = GENERIC_OPCODE_RV2PPQ_VALUE_L4_FLUSH ,
    GENERIC_OPCODE_COMQ_VALUE_L4_STARTGEN           =  6,
    GENERIC_OPCODE_COMQ_VALUE_L4_ADDGEN             =  7,
    GENERIC_OPCODE_COMQ_VALUE_L4_PLACE              =  8,
    GENERIC_OPCODE_COMQ_VALUE_L4_DISCARDGEN         =  9,
    GENERIC_OPCODE_COMQ_VALUE_L5_PLACE              = GENERIC_OPCODE_RV2PPQ_VALUE_L5_PLACE,
    GENERIC_OPCODE_COMQ_VALUE_L2_NOBUFFER           = 11,
    GENERIC_OPCODE_COMQ_VALUE_L4_ARMPUSH            = 12,
    GENERIC_OPCODE_COMQ_VALUE_L4_RWINUPDATE         = 13,
    GENERIC_OPCODE_COMQ_VALUE_L5_FLUSH              = GENERIC_OPCODE_RV2PPQ_VALUE_L5_FLUSH,
    GENERIC_OPCODE_COMQ_VALUE_L4_INDICATE           = 15,
    GENERIC_OPCODE_COMQ_VALUE_L4_COPYGEN            = 16,
    GENERIC_OPCODE_COMQ_VALUE_DBG_RDMA              = GENERIC_OPCODE_RV2PPQ_VALUE_DBG_RDMA,
    GENERIC_OPCODE_COMQ_VALUE_DBG_RV2P              = GENERIC_OPCODE_RV2PPQ_VALUE_DBG_RV2P,
    GENERIC_OPCODE_COMQ_VALUE_L4_MQUPLOAD           = 19,
    GENERIC_OPCODE_COMQ_VALUE_ISCSI_SGL_PLACE	    = 22,
    GENERIC_OPCODE_COMQ_VALUE_ISCSI_RQ_PLACE 	    = 23,
    GENERIC_OPCODE_COMQ_VALUE_ISCSI_RQ_FLUSH	    = 24,
    GENERIC_OPCODE_COMQ_VALUE_ISCSI_SGL_FLUSH	    = 25,

    // Jumbo mode and L2 FLUSH are for Linux only
    GENERIC_OPCODE_COMQ_VALUE_L2_JUMBO_COMPLETION   = GENERIC_OPCODE_RV2PPQ_VALUE_L2_JUMBO_PLACE,
    GENERIC_OPCODE_COMQ_VALUE_L2_JUMBO_NOBUFFER     = 27,
    GENERIC_OPCODE_COMQ_VALUE_L2_FLUSH_BD_CHAIN     = GENERIC_OPCODE_RV2PPQ_VALUE_L2_FLUSH_BD_CHAIN,
    GENERIC_OPCODE_COMQ_VALUE_FLR                   = GENERIC_OPCODE_RV2PPQ_VALUE_FLR,
    MAX_COMQ_OPCODE 
}GENERIC_OPCODE_COMQ_t ;


typedef struct comq_generic_b
{
    u32_t cid;
    u32_t mbuf_cluster;
    u16_t operand_flags;
    u8_t knum;
    u8_t opcode;
        #define GENERIC_OPCODE_COMQ_VALUE                   (0xff<<0)
    u16_t operand16_2;
    u16_t operand16_3;
    u16_t operand16_4;
    u16_t operand16_5;
    u16_t operand16_6;
    u16_t operand16_7;
    u32_t operand32_2;
    u32_t operand32_3;
    u32_t operand32_4;
    u8_t rdma_action;
    u8_t cs16_pkt_len;
    u16_t cs16;
} comq_generic_b_t;

typedef struct comq_generic_l
{
    u32_t cid;
    u32_t mbuf_cluster;
    u8_t opcode;
    u8_t knum;
    u16_t operand_flags;
    u16_t operand16_3;
    u16_t operand16_2;
    u16_t operand16_5;
    u16_t operand16_4;
    u16_t operand16_7;
    u16_t operand16_6;
    u32_t operand32_2;
    u32_t operand32_3;
    u32_t operand32_4;
    u16_t cs16;
    u8_t cs16_pkt_len;
    u8_t rdma_action;
} comq_generic_l_t;

#if defined(LITTLE_ENDIAN)
    typedef comq_generic_l_t comq_generic_t;
#elif defined(BIG_ENDIAN)
    typedef comq_generic_b_t comq_generic_t;
#endif


/*
 *  comq_l2_completion definition
 */
typedef struct comq_l2_completion_b
{
    u32_t cid;
    u32_t mbuf_cluster;
    u16_t operand_flags;
    u8_t knum;
    u8_t opcode;
    u16_t bits_status;
    u16_t vlan_tag;
    u16_t ip_xsum;
    u16_t udp_tcp_xsum;
    u16_t nx_bidx;
    u16_t packet_length;  // total pkt len (MCP will need this info)
    u16_t unused_0;
    u16_t error_flags;
    u32_t hash;
    u32_t rt_bt;
    u8_t rdma_action;
    u8_t cs16_pkt_len;
    u16_t cs16;

} comq_l2_completion_b_t;

typedef struct comq_l2_completion_l
{
    u32_t cid;
    u32_t mbuf_cluster;
    u8_t opcode;
    u8_t knum;
    u16_t operand_flags;
    u16_t vlan_tag;
    u16_t bits_status;
    u16_t udp_tcp_xsum;
    u16_t ip_xsum;
    u16_t packet_length;  // total pkt len (MCP will need this info)
    u16_t nx_bidx;
    u16_t error_flags;
    u16_t unused_0;
    u32_t hash;
    u32_t rt_bt;
    u16_t cs16;
    u8_t cs16_pkt_len;
    u8_t rdma_action;
    
} comq_l2_completion_l_t;

#if defined(LITTLE_ENDIAN)
    typedef comq_l2_completion_l_t comq_l2_completion_t;
#elif defined(BIG_ENDIAN)
    typedef comq_l2_completion_b_t comq_l2_completion_t;
#endif

/*
 *  comq_l2_nobuffer definition
 */
typedef struct comq_l2_nobuffer_b
{
    u32_t l2_nobuff_cid;
    u32_t l2_nobuff_mbuf_cluster;
    u16_t l2_nobuff_operand_flags;
    u8_t l2_nobuff_knum;
    u8_t l2_nobuff_opcode;
    u16_t l2_nobuff_bits_status;
    u16_t l2_nobuff_vlan_tag;
    u16_t l2_nobuff_ip_xsum;
    u16_t l2_nobuff_udp_tcp_xsum;
    u16_t l2_nobuff_nx_bidx;
    u16_t l2_nobuff_packet_length;  // total pkt len (MCP will need this info)
    u16_t unused_1;
    u16_t l2_nobuff_error_flags;
    u32_t l2_nobuff_hash;
    u32_t unused_2;
    u8_t l2_nobuff_rdma_action;
    u8_t l2_nobuff_cs16_pkt_len;
    u16_t l2_nobuff_cs16;
    
} comq_l2_nobuffer_b_t;

typedef struct comq_l2_nobuffer_l
{
    u32_t l2_nobuff_cid;
    u32_t l2_nobuff_mbuf_cluster;
    u8_t l2_nobuff_opcode;
    u8_t l2_nobuff_knum;
    u16_t l2_nobuff_operand_flags;
    u16_t l2_nobuff_vlan_tag;
    u16_t l2_nobuff_bits_status;
    u16_t l2_nobuff_udp_tcp_xsum;
    u16_t l2_nobuff_ip_xsum;
    u16_t l2_nobuff_packet_length;  // total pkt len (MCP will need this info)
    u16_t l2_nobuff_nx_bidx;
    u16_t l2_nobuff_error_flags;
    u16_t unused_1;
    u32_t l2_nobuff_hash;
    u32_t unused_2;
    u16_t l2_nobuff_cs16;
    u8_t l2_nobuff_cs16_pkt_len;
    u8_t l2_nobuff_rdma_action;
    
} comq_l2_nobuffer_l_t;

#if defined(LITTLE_ENDIAN)
    typedef comq_l2_nobuffer_l_t comq_l2_nobuffer_t;
#elif defined(BIG_ENDIAN)
    typedef comq_l2_nobuffer_b_t comq_l2_nobuffer_t;
#endif


/*
 *  comq_l2_flr definition
 */
typedef struct comq_l2_flr_b
{
    u32_t cid;
    u32_t mbuf_cluster;
    u16_t operand_flags;
    u8_t  knum;
    u8_t  opcode;
    u16_t bits_status;
    u16_t vlan_tag;
    u16_t ip_xsum;
    u16_t udp_tcp_xsum;
    u16_t nx_bidx;
    u16_t unused_0;
    u16_t unused_1;
    u16_t error_flags;
    u32_t hash;
    u32_t unused_2;
    u8_t  rdma_action;
    u8_t  cs16_pkt_len;
    u16_t cs16;
    
} comq_l2_flr_b_t;

typedef struct comq_l2_flr_l
{
    u32_t cid;
    u32_t mbuf_cluster;
    u8_t  opcode;
    u8_t  knum;
    u16_t operand_flags;
    u16_t vlan_tag;
    u16_t bits_status;
    u16_t udp_tcp_xsum;
    u16_t ip_xsum;
    u16_t unused_0;
    u16_t nx_bidx;
    u16_t error_flags;
    u16_t unused_1;
    u32_t hash;
    u32_t unused_2;
    u16_t cs16;
    u8_t  cs16_pkt_len;
    u8_t  rdma_action;
    
} comq_l2_flr_l_t;

#if defined(LITTLE_ENDIAN)
    typedef comq_l2_flr_l_t comq_l2_flr_t;
#elif defined(BIG_ENDIAN)
    typedef comq_l2_flr_b_t comq_l2_flr_t;
#endif

/*
 * comxq_t
 */
typedef struct comxq_b
{
    u32_t cid;
    u16_t flags;
    u16_t unused1;
    u32_t snd_next;
}comxq_b_t;

typedef struct comxq_l
{
    u32_t cid;
    u16_t unused1;
    u16_t flags;
    u32_t snd_next;
}comxq_l_t;

#if defined(LITTLE_ENDIAN)
    typedef comxq_l_t comxq_t;
#elif defined(BIG_ENDIAN)
    typedef comxq_b_t comxq_t;
#endif
    
/*
 * comtq_t
 */
typedef struct comtq_b
{
    u32_t cid;
    u32_t val;
    u8_t  type;
    u8_t  unused[3];
}comtq_b_t;

typedef struct comtq_l
{
    u32_t cid;
    u32_t val;
    u8_t  unused[3];
    u8_t  type;
}comtq_l_t;

#if defined(LITTLE_ENDIAN)
    typedef comtq_l_t comtq_t;
#elif defined(BIG_ENDIAN)
    typedef comtq_b_t comtq_t;
#endif

/*
 * csq_t
 */
typedef struct csq_b
{
    u32_t cid;
        // bit 7 lsb of CID is always 0, but CSQ can be enqueued by MQ or COM.
        // For L4, we can use this bit to indicate the source
        // Note that 7 lsb is ALWAYS masked out to be zero by HW
        #define CSQ_SRC_MQ     0
        #define CSQ_SRC_COM    0x80
        #define CSQ_SRC_MASK   0xFF  
    u8_t  flags;
    u8_t  unused[3];
}csq_b_t;

typedef struct csq_l
{
    u32_t cid;
    u8_t  unused[3];
    u8_t  flags;
}csq_l_t;

#if defined(LITTLE_ENDIAN)
    typedef csq_l_t csq_t;
#elif defined(BIG_ENDIAN)
    typedef csq_b_t csq_t;
#endif

/*
 * cpq_t
 */
typedef struct cpq_b
{
    u32_t cid;
}cpq_b_t;

typedef struct cpq_l
{
    u32_t cid;
}cpq_l_t;

#if defined(LITTLE_ENDIAN)
    typedef cpq_l_t cpq_t;
#elif defined(BIG_ENDIAN)
    typedef cpq_b_t cpq_t;
#endif

/*
 * rv2ptq_t
 */
typedef struct rv2ptq_b
{
    u32_t cid;
}rv2ptq_b_t;

typedef struct rv2ptq_l
{
    u32_t cid;
}rv2ptq_l_t;

#if defined(LITTLE_ENDIAN)
    typedef rv2ptq_l_t rv2ptq_t;
#elif defined(BIG_ENDIAN)
    typedef rv2ptq_b_t rv2ptq_t;
#endif


    /* TX FTQs */
  
typedef struct tschq_b
{
    u32_t cid;
    u8_t  flags;
    u8_t  unused[3];
}tschq_b_t;

typedef struct tschq_l
{
    u32_t cid;
    u8_t  unused[3];
    u8_t  flags;
}tschq_l_t;

#if defined(LITTLE_ENDIAN)
    typedef tschq_l_t tschq_t;
#elif defined(BIG_ENDIAN)
    typedef tschq_b_t tschq_t;
#endif

typedef struct txpq_b
{
    u32_t cid;
    u32_t bseq;
    u8_t  flags_flags;
    u8_t  cmd;
    u8_t  xnum;
    u8_t  protocol_flags;
    u32_t tcp_rcv_nxt;
}txpq_b_t;

typedef struct txpq_l
{
    u32_t cid;
    u32_t bseq;
    u8_t  protocol_flags;
    u8_t  xnum;
    u8_t  cmd;
    u8_t  flags_flags;
    u32_t tcp_rcv_nxt;
}txpq_l_t;

#if defined(LITTLE_ENDIAN)
    typedef txpq_l_t txpq_t;
#elif defined(BIG_ENDIAN)
    typedef txpq_b_t txpq_t;
#endif

typedef struct tdmaq_b
{
    u32_t cid;
    tx_bidx_boff_t bidx_boff;
    u32_t bseq;
    u32_t snd_next;
    u8_t  cmd;
    u8_t  xnum;
    u8_t  knum;
    u8_t  unused1;
    u32_t flags_flags;
    u16_t nbytes;
    u16_t hole0_boff;
    u16_t hole1_boff;
    u16_t hole2_boff;
    u32_t hole0_fill;
    u32_t hole1_fill;
    u32_t hole2_fill;
    u8_t  fnum;
    u8_t  txp_act_cmd;
    u16_t unused2;
}tdmaq_b_t;

typedef struct tdmaq_l
{
    u32_t cid;
    tx_bidx_boff_t bidx_boff;
    u32_t bseq;
    u32_t snd_next;
    u8_t  unused1;
    u8_t  knum;
    u8_t  xnum;
    u8_t  cmd;
    u32_t flags_flags;
    u16_t hole0_boff;
    u16_t nbytes;
    u16_t hole2_boff;
    u16_t hole1_boff;
    u32_t hole0_fill;
    u32_t hole1_fill;
    u32_t hole2_fill;
    u16_t unused2;
    u8_t  txp_act_cmd;
    u8_t  fnum;
}tdmaq_l_t;

#if defined(LITTLE_ENDIAN)
    typedef tdmaq_l_t tdmaq_t;
#elif defined(BIG_ENDIAN)
    typedef tdmaq_b_t tdmaq_t;
#endif

typedef struct tpatq_b
{
    u32_t cid;
    u16_t nbytes;
    u8_t  xnum;
    u8_t  knum;
    u32_t flags_flags;
    u16_t raw_chksum;
    u16_t tpat_bidx;
}tpatq_b_t;

typedef struct tpatq_l
{
    u32_t cid;
    u8_t  knum;
    u8_t  xnum;
    u16_t nbytes;
    u32_t flags_flags;
    u16_t tpat_bidx;
    u16_t raw_chksum;
}tpatq_l_t;

#if defined(LITTLE_ENDIAN)
    typedef tpatq_l_t tpatq_t;
#elif defined(BIG_ENDIAN)
    typedef tpatq_b_t tpatq_t;
#endif

typedef struct taspq_b    
{
    u16_t taspq_hdr_skip;
    u16_t taspq_hdr_post_skip;
    u16_t taspq_hdr_size;
    u16_t taspq_payload_skip;
    u16_t taspq_payload_size;
    u16_t taspq_flags;
#if (TARGET_CHIP == 5709)
        #define TASPQ_FLAGS_PKT_END                 TPATF_TASQ_FLAGS_PKT_END
        #define TASPQ_FLAGS_MGMT_PACKET             TPATF_TASQ_FLAGS_MGMT_PACKET
        #define TASPQ_FLAGS_DEST_RPC_CATCHUP        TPATF_TASQ_FLAGS_CATCHUP_PACKET
        #define TASPQ_FLAGS_DONT_GEN_CRC            TPATF_TASQ_FLAGS_DONT_GEN_CRC
        #define TASPQ_FLAGS_RESERVED                TPATF_TASQ_FLAGS_RESERVED
        #define TASPQ_FLAGS_DEST_EMAC               TPATF_TASQ_FLAGS_DEST_EMAC
        #define TASPQ_FLAGS_DEST_RPC_MIRROR         TPATF_TASQ_FLAGS_DEST_RPC_MIRROR
        #define TASPQ_FLAGS_DEST_RPC_LOOPBACK       TPATF_TASQ_FLAGS_DEST_RPC_LOOPBACK
        #define TASPQ_FLAGS_MGMT_PKT_TAG            TPATF_TASQ_FLAGS_MGMT_PKT_TAG
        #define TASPQ_FLAGS_CS16_VLD                TPATF_TASQ_FLAGS_CS16_VLD          
#else
        #define TASPQ_FLAGS_PKT_END                 TPATF_TASPQ_FLAGS_PKT_END
        #define TASPQ_FLAGS_MGMT_PACKET             TPATF_TASPQ_FLAGS_MGMT_PACKET
        #define TASPQ_FLAGS_DEST_RPC_CATCHUP        TPATF_TASPQ_FLAGS_DEST_RPC_CATCHUP
        #define TASPQ_FLAGS_DONT_GEN_CRC            TPATF_TASPQ_FLAGS_DONT_GEN_CRC
        #define TASPQ_FLAGS_RESERVED                TPATF_TASPQ_FLAGS_RESERVED
        #define TASPQ_FLAGS_DEST_EMAC               TPATF_TASPQ_FLAGS_DEST_EMAC
        #define TASPQ_FLAGS_DEST_RPC_MIRROR         TPATF_TASPQ_FLAGS_DEST_RPC_MIRROR
        #define TASPQ_FLAGS_DEST_RPC_LOOPBACK       TPATF_TASPQ_FLAGS_DEST_RPC_LOOPBACK
        #define TASPQ_FLAGS_MGMT_PKT_TAG            TPATF_TASPQ_FLAGS_MGMT_PKT_TAG
        #define TASPQ_FLAGS_CS16_VLD                TPATF_TASPQ_FLAGS_CS16_VLD          
#endif
    u16_t taspq_cs16;
    u16_t taspq_uftq_cmd;  /* Only the upper 16 bit of the ftq cmd is used */
#if (TARGET_CHIP == 5709)
        #define TASPQ_FTQ_CMD_CPY_DATA              TPATF_TASQ_FTQ_CMD_CPY_DATA
        #define TASPQ_FTQ_CMD_ADD_INTERVEN          TPATF_TASQ_FTQ_CMD_ADD_INTERVEN
        #define TASPQ_FTQ_CMD_ADD_DATA              TPATF_TASQ_FTQ_CMD_ADD_DATA
        #define TASPQ_FTQ_CMD_BUSY                  TPATF_TASQ_FTQ_CMD_BUSY
#else
        #define TASPQ_FTQ_CMD_CPY_DATA              TPATF_TASPQ_FTQ_CMD_CPY_DATA
        #define TASPQ_FTQ_CMD_ADD_INTERVEN          TPATF_TASPQ_FTQ_CMD_ADD_INTERVEN
        #define TASPQ_FTQ_CMD_ADD_DATA              TPATF_TASPQ_FTQ_CMD_ADD_DATA
        #define TASPQ_FTQ_CMD_BUSY                  TPATF_TASPQ_FTQ_CMD_BUSY
#endif    
} taspq_b_t;

typedef struct taspq_l    
{
    u16_t taspq_hdr_post_skip;
    u16_t taspq_hdr_skip;
    u16_t taspq_payload_skip;
    u16_t taspq_hdr_size;
    u16_t taspq_flags;
#if (TARGET_CHIP == 5709)
        #define TASPQ_FLAGS_PKT_END                 TPATF_TASQ_FLAGS_PKT_END
        #define TASPQ_FLAGS_MGMT_PACKET             TPATF_TASQ_FLAGS_MGMT_PACKET
        #define TASPQ_FLAGS_DEST_RPC_CATCHUP        TPATF_TASQ_FLAGS_CATCHUP_PACKET
        #define TASPQ_FLAGS_DONT_GEN_CRC            TPATF_TASQ_FLAGS_DONT_GEN_CRC
        #define TASPQ_FLAGS_RESERVED                TPATF_TASQ_FLAGS_RESERVED
        #define TASPQ_FLAGS_DEST_EMAC               TPATF_TASQ_FLAGS_DEST_EMAC
        #define TASPQ_FLAGS_DEST_RPC_MIRROR         TPATF_TASQ_FLAGS_DEST_RPC_MIRROR
        #define TASPQ_FLAGS_DEST_RPC_LOOPBACK       TPATF_TASQ_FLAGS_DEST_RPC_LOOPBACK
        #define TASPQ_FLAGS_MGMT_PKT_TAG            TPATF_TASQ_FLAGS_MGMT_PKT_TAG
        #define TASPQ_FLAGS_CS16_VLD                TPATF_TASQ_FLAGS_CS16_VLD          
#else
        #define TASPQ_FLAGS_PKT_END                 TPATF_TASPQ_FLAGS_PKT_END
        #define TASPQ_FLAGS_MGMT_PACKET             TPATF_TASPQ_FLAGS_MGMT_PACKET
        #define TASPQ_FLAGS_DEST_RPC_CATCHUP        TPATF_TASPQ_FLAGS_DEST_RPC_CATCHUP
        #define TASPQ_FLAGS_DONT_GEN_CRC            TPATF_TASPQ_FLAGS_DONT_GEN_CRC
        #define TASPQ_FLAGS_RESERVED                TPATF_TASPQ_FLAGS_RESERVED
        #define TASPQ_FLAGS_DEST_EMAC               TPATF_TASPQ_FLAGS_DEST_EMAC
        #define TASPQ_FLAGS_DEST_RPC_MIRROR         TPATF_TASPQ_FLAGS_DEST_RPC_MIRROR
        #define TASPQ_FLAGS_DEST_RPC_LOOPBACK       TPATF_TASPQ_FLAGS_DEST_RPC_LOOPBACK
        #define TASPQ_FLAGS_MGMT_PKT_TAG            TPATF_TASPQ_FLAGS_MGMT_PKT_TAG
        #define TASPQ_FLAGS_CS16_VLD                TPATF_TASPQ_FLAGS_CS16_VLD          
#endif
    u16_t taspq_payload_size;
    u16_t taspq_uftq_cmd;  /* Only the upper 16 bit of the ftq cmd is used */
#if (TARGET_CHIP == 5709)
        #define TASPQ_FTQ_CMD_CPY_DATA              TPATF_TASQ_FTQ_CMD_CPY_DATA
        #define TASPQ_FTQ_CMD_ADD_INTERVEN          TPATF_TASQ_FTQ_CMD_ADD_INTERVEN
        #define TASPQ_FTQ_CMD_ADD_DATA              TPATF_TASQ_FTQ_CMD_ADD_DATA
        #define TASPQ_FTQ_CMD_BUSY                  TPATF_TASQ_FTQ_CMD_BUSY
#else
        #define TASPQ_FTQ_CMD_CPY_DATA              TPATF_TASPQ_FTQ_CMD_CPY_DATA
        #define TASPQ_FTQ_CMD_ADD_INTERVEN          TPATF_TASPQ_FTQ_CMD_ADD_INTERVEN
        #define TASPQ_FTQ_CMD_ADD_DATA              TPATF_TASPQ_FTQ_CMD_ADD_DATA
        #define TASPQ_FTQ_CMD_BUSY                  TPATF_TASPQ_FTQ_CMD_BUSY
#endif    
    u16_t taspq_cs16;
} taspq_l_t;

#if defined(LITTLE_ENDIAN)
    typedef taspq_l_t taspq_t;
#elif defined(BIG_ENDIAN)
    typedef taspq_b_t taspq_t;
#endif
    
#endif /* _l2_ftq_h_ */
