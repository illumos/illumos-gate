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

#include "bcmtype.h"

#ifndef _5709_reg_h_
#define _5709_reg_h_

// ???? #pragma pack(4)

#ifndef STATUS_BLOCK_SPACING
#define STATUS_BLOCK_SPACING            64
#endif

#if !defined(LITTLE_ENDIAN) && !defined(BIG_ENDIAN)
    #error "Missing either LITTLE_ENDIAN or BIG_ENDIAN definition."
#endif



/*
 *  tx_bd_b definition
 */
typedef struct tx_bd_b
{
    u32_t tx_bd_haddr_hi;
    u32_t tx_bd_haddr_lo;
    u16_t tx_bd_reserved;
        #define TX_BD_RESERVED_MSS                          (0x3fff<<0)
        #define TX_BD_RESERVED_BIT14_15                     (0x03<<14) 
    u16_t tx_bd_nbytes;
    u16_t tx_bd_vlan_tag;
    u16_t tx_bd_flags;
        #define TX_BD_FLAGS_CONN_FAULT                      (1<<0)
        #define TX_BD_FLAGS_TCP_UDP_CKSUM                   (1<<1)
        #define TX_BD_FLAGS_IP_CKSUM                        (1<<2)
        #define TX_BD_FLAGS_VLAN_TAG                        (1<<3)
        #define TX_BD_FLAGS_COAL_NOW                        (1<<4)
        #define TX_BD_FLAGS_DONT_GEN_CRC                    (1<<5)
        #define TX_BD_FLAGS_END                             (1<<6)
        #define TX_BD_FLAGS_START                           (1<<7)
        #define TX_BD_FLAGS_SW_OPTION_WORD                  (0x1f<<8)
        #define TX_BD_FLAGS_SW_OPTION_MSB                   (1<<12)
        #define TX_BD_FLAGS_SW_END                          (1<<12)
        #define TX_BD_FLAGS_SW_FLAGS                        (1<<13)
        #define TX_BD_FLAGS_SW_SNAP                         (1<<14)
        #define TX_BD_FLAGS_SW_LSO                          (1<<15)

} tx_bd_b_t;


/*
 *  tx_bd_l definition
 */
typedef struct tx_bd_l
{
    u32_t tx_bd_haddr_hi;
    u32_t tx_bd_haddr_lo;
    u16_t tx_bd_nbytes;
    u16_t tx_bd_reserved;
        #define TX_BD_RESERVED_MSS                          (0x3fff<<0)
        #define TX_BD_RESERVED_BIT14_15                     (0x03<<14) 
    u16_t tx_bd_flags;
        #define TX_BD_FLAGS_CONN_FAULT                      (1<<0)
        #define TX_BD_FLAGS_TCP_UDP_CKSUM                   (1<<1)
        #define TX_BD_FLAGS_IP_CKSUM                        (1<<2)
        #define TX_BD_FLAGS_VLAN_TAG                        (1<<3)
        #define TX_BD_FLAGS_COAL_NOW                        (1<<4)
        #define TX_BD_FLAGS_DONT_GEN_CRC                    (1<<5)
        #define TX_BD_FLAGS_END                             (1<<6)
        #define TX_BD_FLAGS_START                           (1<<7)
        #define TX_BD_FLAGS_SW_OPTION_WORD                  (0x1f<<8)
        #define TX_BD_FLAGS_SW_OPTION_MSB                   (1<<12)
        #define TX_BD_FLAGS_SW_END                          (1<<12)
        #define TX_BD_FLAGS_SW_FLAGS                        (1<<13)
        #define TX_BD_FLAGS_SW_SNAP                         (1<<14)
        #define TX_BD_FLAGS_SW_LSO                          (1<<15)

    u16_t tx_bd_vlan_tag;
} tx_bd_l_t;


/*
 * tx_bd select
 */
#if defined(LITTLE_ENDIAN)
    typedef tx_bd_l_t tx_bd_t;
#elif defined(BIG_ENDIAN)
    typedef tx_bd_b_t tx_bd_t;
#endif


/*
 *  tx_bd_next definition
 */
typedef struct tx_bd_next
{
    u32_t tx_bd_next_paddr_hi;
    u32_t tx_bd_next_paddr_lo;
    u8_t tx_bd_next_reserved[8];
} tx_bd_next_t;


/*
 *  hqc_basic_b definition
 */
typedef struct hqc_basic_b
{
    u8_t hqc_type;
        #define HQC_TYPE_N64W                               (0xf<<0)
        #define HQC_TYPE_VALUE                              (0xf<<4)
            #define HQC_TYPE_VALUE_BASIC                    (0<<4)
            #define HQC_TYPE_VALUE_TOE                      (1<<4)
            #define HQC_TYPE_VALUE_HOLE                     (2<<4)
            #define HQC_TYPE_VALUE_LSO_CAPTURE              (3<<4)
            #define HQC_TYPE_VALUE_LSO_DUPLICATE            (4<<4)
            #define HQC_TYPE_VALUE_IWARP_STD                (5<<4)
            #define HQC_TYPE_VALUE_IWARP_EDGE               (6<<4)

    u8_t hqc_knum;
    u16_t hqc_hdr_nbytes;
    u32_t unused_0;
} hqc_basic_b_t;


/*
 *  hqc_basic_l definition
 */
typedef struct hqc_basic_l
{
    u16_t hqc_hdr_nbytes;
    u8_t hqc_knum;
    u8_t hqc_type;
        #define HQC_TYPE_N64W                               (0xf<<0)
        #define HQC_TYPE_VALUE                              (0xf<<4)
            #define HQC_TYPE_VALUE_BASIC                    (0<<4)
            #define HQC_TYPE_VALUE_TOE                      (1<<4)
            #define HQC_TYPE_VALUE_HOLE                     (2<<4)
            #define HQC_TYPE_VALUE_LSO_CAPTURE              (3<<4)
            #define HQC_TYPE_VALUE_LSO_DUPLICATE            (4<<4)
            #define HQC_TYPE_VALUE_IWARP_STD                (5<<4)
            #define HQC_TYPE_VALUE_IWARP_EDGE               (6<<4)
            #define HQC_TYPE_VALUE_ISCSI                    (7<<4)  
    u32_t unused_0;
} hqc_basic_l_t;


/*
 * hqc_basic select
 */
#if defined(LITTLE_ENDIAN)
    typedef hqc_basic_l_t hqc_basic_t;
#elif defined(BIG_ENDIAN)
    typedef hqc_basic_b_t hqc_basic_t;
#endif


/*
 *  hqc_toe_b definition
 */
typedef struct hqc_toe_b
{
    u8_t hqt_type;
    u8_t hqt_knum;
    u16_t hqt_hdr_nbytes;
        #define HQT_HDR_NBYTES_VALUE                        (0x3fff<<0)
        #define HQT_HDR_NBYTES_PLUS_TWO                     (1<<15)

    u16_t unused_0;
    u16_t hqt_xsum_boff;
} hqc_toe_b_t;


/*
 *  hqc_toe_l definition
 */
typedef struct hqc_toe_l
{
    u16_t hqt_hdr_nbytes;
        #define HQT_HDR_NBYTES_VALUE                        (0x3fff<<0)
        #define HQT_HDR_NBYTES_PLUS_TWO                     (1<<15)

    u8_t hqt_knum;
    u8_t hqt_type;
    u16_t hqt_xsum_boff;
    u16_t unused_0;
} hqc_toe_l_t;


/*
 * hqc_toe select
 */
#if defined(LITTLE_ENDIAN)
    typedef hqc_toe_l_t hqc_toe_t;
#elif defined(BIG_ENDIAN)
    typedef hqc_toe_b_t hqc_toe_t;
#endif


/*
 *  hqc_hole_b definition
 */
typedef struct hqc_hole_b
{
    u8_t hqh_type;
    u8_t hqh_knum;
    u16_t hqh_hdr_nbytes;
        #define HQH_HDR_NBYTES_VALUE                        (0x3fff<<0)
        #define HQH_HDR_NBYTES_PLUS_TWO                     (1<<15)

    u16_t hqh_hole_bytes;
    u16_t hqh_hole_pos;
    u8_t hqh_value[4];
    u32_t unused_0;
} hqc_hole_b_t;


/*
 *  hqc_hole_l definition
 */
typedef struct hqc_hole_l
{
    u16_t hqh_hdr_nbytes;
        #define HQH_HDR_NBYTES_VALUE                        (0x3fff<<0)
        #define HQH_HDR_NBYTES_PLUS_TWO                     (1<<15)

    u8_t hqh_knum;
    u8_t hqh_type;
    u16_t hqh_hole_pos;
    u16_t hqh_hole_bytes;
    u8_t hqh_value[4];
    u32_t unused_0;
} hqc_hole_l_t;


/*
 * hqc_hole select
 */
#if defined(LITTLE_ENDIAN)
    typedef hqc_hole_l_t hqc_hole_t;
#elif defined(BIG_ENDIAN)
    typedef hqc_hole_b_t hqc_hole_t;
#endif


/*
 *  hqc_lso_cap_b definition
 */
typedef struct hqc_lso_cap_b
{
    u8_t hqca_type;
    u8_t hqca_knum;
    u16_t hqca_hdr_nbytes;
        #define HQCA_HDR_NBYTES_VALUE                       (0x3fff<<0)
        #define HQCA_HDR_NBYTES_PLUS_TWO                    (1<<15)

    u16_t hqca_cap_hdr_nbytes;
    u16_t hqca_l2hdr_nbytes;
    u32_t hqca_vlan_tag;
    u32_t hqca_ipv6_exthdr_len;
        #define HQDU_FLAGS_IPV6_EXTHDR_LEN                  (0x7fffffffUL<<0)
        #define HQDU_FLAGS_BSEQ_FLAGS_LAST_PKT              (1UL<<31)
} hqc_lso_cap_b_t;


/*
 *  hqc_lso_cap_l definition
 */
typedef struct hqc_lso_cap_l
{
    u16_t hqca_hdr_nbytes;
        #define HQCA_HDR_NBYTES_VALUE                       (0x3fff<<0)
        #define HQCA_HDR_NBYTES_PLUS_TWO                    (1<<15)

    u8_t hqca_knum;
    u8_t hqca_type;
    u16_t hqca_l2hdr_nbytes;
    u16_t hqca_cap_hdr_nbytes;
    u32_t hqca_vlan_tag;
    u32_t hqca_ipv6_exthdr_len;
        #define HQDU_FLAGS_IPV6_EXTHDR_LEN                  (0x7fffffffUL<<0)
        #define HQDU_FLAGS_BSEQ_FLAGS_LAST_PKT              (1UL<<31)
} hqc_lso_cap_l_t;


/*
 * hqc_lso_cap select
 */
#if defined(LITTLE_ENDIAN)
    typedef hqc_lso_cap_l_t hqc_lso_cap_t;
#elif defined(BIG_ENDIAN)
    typedef hqc_lso_cap_b_t hqc_lso_cap_t;
#endif


/*
 *  hqc_lso_dup_b definition
 */
typedef struct hqc_lso_dup_b
{
    u8_t hqdu_type;
    u8_t hqdu_knum;
    u16_t hqdu_hdr_nbytes;
        #define HQDU_HDR_NBYTES_VALUE                       (0x3fff<<0)
        #define HQDU_HDR_NBYTES_PLUS_TWO                    (1<<15)

    u32_t hqdu_flags_bseq;
        #define HQDU_FLAGS_BSEQ_BSEQ_VALUE                  (0x7fffffffUL<<0)
        #define HQDU_FLAGS_BSEQ_FLAGS_LAST_PKT              (1UL<<31)

} hqc_lso_dup_b_t;


/*
 *  hqc_lso_dup_l definition
 */
typedef struct hqc_lso_dup_l
{
    u16_t hqdu_hdr_nbytes;
        #define HQDU_HDR_NBYTES_VALUE                       (0x3fff<<0)
        #define HQDU_HDR_NBYTES_PLUS_TWO                    (1<<15)

    u8_t hqdu_knum;
    u8_t hqdu_type;
    u32_t hqdu_flags_bseq;
        #define HQDU_FLAGS_BSEQ_BSEQ_VALUE                  (0x7fffffffUL<<0)
        #define HQDU_FLAGS_BSEQ_FLAGS_LAST_PKT              (1UL<<31)

} hqc_lso_dup_l_t;


/*
 * hqc_lso_dup select
 */
#if defined(LITTLE_ENDIAN)
    typedef hqc_lso_dup_l_t hqc_lso_dup_t;
#elif defined(BIG_ENDIAN)
    typedef hqc_lso_dup_b_t hqc_lso_dup_t;
#endif


/*
 *  hqc_iwarp_std_b definition
 */
typedef struct hqc_iwarp_std_b
{
    u8_t hqis_type;
    u8_t hqis_knum;
    u16_t hqis_hdr_nbytes;
        #define HQIS_HDR_NBYTES_HDR_NBYTES_VALUE            (0x3fff<<0)

    u16_t hqis_l5_hdr_nbytes;
    u16_t hqis_xsum_boff;
} hqc_iwarp_std_b_t;


/*
 *  hqc_iwarp_std_l definition
 */
typedef struct hqc_iwarp_std_l
{
    u16_t hqis_hdr_nbytes;
        #define HQIS_HDR_NBYTES_HDR_NBYTES_VALUE            (0x3fff<<0)

    u8_t hqis_knum;
    u8_t hqis_type;
    u16_t hqis_xsum_boff;
    u16_t hqis_l5_hdr_nbytes;
} hqc_iwarp_std_l_t;


/*
 * hqc_iwarp_std select
 */
#if defined(LITTLE_ENDIAN)
    typedef hqc_iwarp_std_l_t hqc_iwarp_std_t;
#elif defined(BIG_ENDIAN)
    typedef hqc_iwarp_std_b_t hqc_iwarp_std_t;
#endif


/*
 *  hqc_iwarp_edge_b definition
 */
typedef struct hqc_iwarp_edge_b
{
    u8_t hqie_type;
    u8_t hqie_knum;
    u16_t hqie_hdr_nbytes;
        #define HQIE_HDR_NBYTES_HDR_NBYTES_VALUE            (0x3fff<<0)

    u16_t hqie_l5_hdr_nbytes;
    u16_t hqie_xsum_boff;
    u32_t hqie_marker_value;
    u32_t unused_0;
} hqc_iwarp_edge_b_t;


/*
 *  hqc_iwarp_edge_l definition
 */
typedef struct hqc_iwarp_edge_l
{
    u16_t hqie_hdr_nbytes;
        #define HQIE_HDR_NBYTES_HDR_NBYTES_VALUE            (0x3fff<<0)

    u8_t hqie_knum;
    u8_t hqie_type;
    u16_t hqie_xsum_boff;
    u16_t hqie_l5_hdr_nbytes;
    u32_t hqie_marker_value;
    u32_t unused_0;
} hqc_iwarp_edge_l_t;


/*
 * hqc_iwarp_edge select
 */
#if defined(LITTLE_ENDIAN)
    typedef hqc_iwarp_edge_l_t hqc_iwarp_edge_t;
#elif defined(BIG_ENDIAN)
    typedef hqc_iwarp_edge_b_t hqc_iwarp_edge_t;
#endif


/*
 *  rx_bd_b definition
 */
typedef struct rx_bd_b
{
    u32_t rx_bd_haddr_hi;
    u32_t rx_bd_haddr_lo;
    u32_t rx_bd_len;
    u16_t unused_0;
    u16_t rx_bd_flags;
        #define RX_BD_FLAGS_NOPUSH                          (1<<0)
        #define RX_BD_FLAGS_DUMMY                           (1<<1)
        #define RX_BD_FLAGS_END                             (1<<2)
        #define RX_BD_FLAGS_START                           (1<<3)
        #define RX_BD_FLAGS_INTRMDT                         (1<<4)       // intermediate boundary for partial io buffer
        #define RX_BD_FLAGS_HEADERSPLIT                     (1<<5)       
} rx_bd_b_t;


/*
 *  rx_bd_l definition
 */
typedef struct rx_bd_l
{
    u32_t rx_bd_haddr_hi;
    u32_t rx_bd_haddr_lo;
    u32_t rx_bd_len;
    u16_t rx_bd_flags;
        #define RX_BD_FLAGS_NOPUSH                          (1<<0)
        #define RX_BD_FLAGS_DUMMY                           (1<<1)
        #define RX_BD_FLAGS_END                             (1<<2)
        #define RX_BD_FLAGS_START                           (1<<3)
        #define RX_BD_FLAGS_INTRMDT                         (1<<4)       // intermediate boundary for partial io buffer
        #define RX_BD_FLAGS_HEADERSPLIT                     (1<<5)       
    u16_t unused_0;
} rx_bd_l_t;


/*
 * rx_bd select
 */
#if defined(LITTLE_ENDIAN)
    typedef rx_bd_l_t rx_bd_t;
#elif defined(BIG_ENDIAN)
    typedef rx_bd_b_t rx_bd_t;
#endif


/*
 *  rx_generic_bd_b definition
 */
typedef struct rx_generic_bd_b
{
    u16_t rx_generic_bd_tag;
    u16_t rx_generic_bd_haddr_hi;
    u32_t rx_generic_bd_haddr_lo;
        #define RX_GENERIC_BD_HADDR_LO_SELECT               (0x3UL<<0)
        #define RX_GENERIC_BD_HADDR_LO_ADDR                 (0x3fffUL<<2)

    u32_t rx_generic_bd_len;
    u16_t unused_0;
    u16_t rx_generic_bd_flags;
        #define RX_GENERIC_BD_FLAGS_END                     (1<<2)
        #define RX_GENERIC_BD_FLAGS_START                   (1<<3)

} rx_generic_bd_b_t;


/*
 *  rx_generic_bd_l definition
 */
typedef struct rx_generic_bd_l
{
    u16_t rx_generic_bd_haddr_hi;
    u16_t rx_generic_bd_tag;
    u32_t rx_generic_bd_haddr_lo;
        #define RX_GENERIC_BD_HADDR_LO_SELECT               (0x3UL<<0)
        #define RX_GENERIC_BD_HADDR_LO_ADDR                 (0x3fffUL<<2)

    u32_t rx_generic_bd_len;
    u16_t rx_generic_bd_flags;
        #define RX_GENERIC_BD_FLAGS_END                     (1<<2)
        #define RX_GENERIC_BD_FLAGS_START                   (1<<3)

    u16_t unused_0;
} rx_generic_bd_l_t;


/*
 * rx_generic_bd select
 */
#if defined(LITTLE_ENDIAN)
    typedef rx_generic_bd_l_t rx_generic_bd_t;
#elif defined(BIG_ENDIAN)
    typedef rx_generic_bd_b_t rx_generic_bd_t;
#endif


/*
 *  attentions definition
 */
typedef struct attentions
{
    u32_t attentions_bits;
        #define ATTENTIONS_BITS_LINK_STATE                  (1UL<<0)
        #define ATTENTIONS_BITS_TX_SCHEDULER_ABORT          (1UL<<1)
        #define ATTENTIONS_BITS_TX_BD_READ_ABORT            (1UL<<2)
        #define ATTENTIONS_BITS_TX_BD_CACHE_ABORT           (1UL<<3)
        #define ATTENTIONS_BITS_TX_PROCESSOR_ABORT          (1UL<<4)
        #define ATTENTIONS_BITS_TX_DMA_ABORT                (1UL<<5)
        #define ATTENTIONS_BITS_TX_PATCHUP_ABORT            (1UL<<6)
        #define ATTENTIONS_BITS_TX_ASSEMBLER_ABORT          (1UL<<7)
        #define ATTENTIONS_BITS_RX_PARSER_MAC_ABORT         (1UL<<8)
        #define ATTENTIONS_BITS_RX_PARSER_CATCHUP_ABORT     (1UL<<9)
        #define ATTENTIONS_BITS_RX_MBUF_ABORT               (1UL<<10)
        #define ATTENTIONS_BITS_RX_LOOKUP_ABORT             (1UL<<11)
        #define ATTENTIONS_BITS_RX_PROCESSOR_ABORT          (1UL<<12)
        #define ATTENTIONS_BITS_RX_V2P_ABORT                (1UL<<13)
        #define ATTENTIONS_BITS_RX_BD_CACHE_ABORT           (1UL<<14)
        #define ATTENTIONS_BITS_RX_DMA_ABORT                (1UL<<15)
        #define ATTENTIONS_BITS_COMPLETION_ABORT            (1UL<<16)
        #define ATTENTIONS_BITS_HOST_COALESCE_ABORT         (1UL<<17)
        #define ATTENTIONS_BITS_MAILBOX_QUEUE_ABORT         (1UL<<18)
        #define ATTENTIONS_BITS_CONTEXT_ABORT               (1UL<<19)
        #define ATTENTIONS_BITS_CMD_SCHEDULER_ABORT         (1UL<<20)
        #define ATTENTIONS_BITS_CMD_PROCESSOR_ABORT         (1UL<<21)
        #define ATTENTIONS_BITS_MGMT_PROCESSOR_ABORT        (1UL<<22)
        #define ATTENTIONS_BITS_MAC_ABORT                   (1UL<<23)
        #define ATTENTIONS_BITS_TIMER_ABORT                 (1UL<<24)
        #define ATTENTIONS_BITS_DMAE_ABORT                  (1UL<<25)
        #define ATTENTIONS_BITS_FLSH_ABORT                  (1UL<<26)
        #define ATTENTIONS_BITS_GRC_ABORT                   (1UL<<27)
        #define ATTENTIONS_BITS_EPB_ERROR                   (1UL<<30)
        #define ATTENTIONS_BITS_PARITY_ERROR                (1UL<<31)

} attentions_t;


/*
 *  status_block_b definition
 */
typedef struct status_block_b
{
    u32_t status_attn_bits;
        #define STATUS_ATTN_BITS_LINK_STATE                 (1UL<<0)
        #define STATUS_ATTN_BITS_TX_SCHEDULER_ABORT         (1UL<<1)
        #define STATUS_ATTN_BITS_TX_BD_READ_ABORT           (1UL<<2)
        #define STATUS_ATTN_BITS_TX_BD_CACHE_ABORT          (1UL<<3)
        #define STATUS_ATTN_BITS_TX_PROCESSOR_ABORT         (1UL<<4)
        #define STATUS_ATTN_BITS_TX_DMA_ABORT               (1UL<<5)
        #define STATUS_ATTN_BITS_TX_PATCHUP_ABORT           (1UL<<6)
        #define STATUS_ATTN_BITS_TX_ASSEMBLER_ABORT         (1UL<<7)
        #define STATUS_ATTN_BITS_RX_PARSER_MAC_ABORT        (1UL<<8)
        #define STATUS_ATTN_BITS_RX_PARSER_CATCHUP_ABORT    (1UL<<9)
        #define STATUS_ATTN_BITS_RX_MBUF_ABORT              (1UL<<10)
        #define STATUS_ATTN_BITS_RX_LOOKUP_ABORT            (1UL<<11)
        #define STATUS_ATTN_BITS_RX_PROCESSOR_ABORT         (1UL<<12)
        #define STATUS_ATTN_BITS_RX_V2P_ABORT               (1UL<<13)
        #define STATUS_ATTN_BITS_RX_BD_CACHE_ABORT          (1UL<<14)
        #define STATUS_ATTN_BITS_RX_DMA_ABORT               (1UL<<15)
        #define STATUS_ATTN_BITS_COMPLETION_ABORT           (1UL<<16)
        #define STATUS_ATTN_BITS_HOST_COALESCE_ABORT        (1UL<<17)
        #define STATUS_ATTN_BITS_MAILBOX_QUEUE_ABORT        (1UL<<18)
        #define STATUS_ATTN_BITS_CONTEXT_ABORT              (1UL<<19)
        #define STATUS_ATTN_BITS_CMD_SCHEDULER_ABORT        (1UL<<20)
        #define STATUS_ATTN_BITS_CMD_PROCESSOR_ABORT        (1UL<<21)
        #define STATUS_ATTN_BITS_MGMT_PROCESSOR_ABORT       (1UL<<22)
        #define STATUS_ATTN_BITS_MAC_ABORT                  (1UL<<23)
        #define STATUS_ATTN_BITS_TIMER_ABORT                (1UL<<24)
        #define STATUS_ATTN_BITS_DMAE_ABORT                 (1UL<<25)
        #define STATUS_ATTN_BITS_FLSH_ABORT                 (1UL<<26)
        #define STATUS_ATTN_BITS_GRC_ABORT                  (1UL<<27)
        #define STATUS_ATTN_BITS_EPB_ERROR                  (1UL<<30)
        #define STATUS_ATTN_BITS_PARITY_ERROR               (1UL<<31)

    u32_t status_attn_bits_ack;
    u16_t status_tx_quick_consumer_index0;
    u16_t status_tx_quick_consumer_index1;
    u16_t status_tx_quick_consumer_index2;
    u16_t status_tx_quick_consumer_index3;
    u16_t status_rx_quick_consumer_index0;
    u16_t status_rx_quick_consumer_index1;
    u16_t status_rx_quick_consumer_index2;
    u16_t status_rx_quick_consumer_index3;
    u16_t status_rx_quick_consumer_index4;
    u16_t status_rx_quick_consumer_index5;
    u16_t status_rx_quick_consumer_index6;
    u16_t status_rx_quick_consumer_index7;
    u16_t status_rx_quick_consumer_index8;
    u16_t status_rx_quick_consumer_index9;
    u16_t status_rx_quick_consumer_index10;
    u16_t status_rx_quick_consumer_index11;
    u16_t status_rx_quick_consumer_index12;
    u16_t status_rx_quick_consumer_index13;
    u16_t status_rx_quick_consumer_index14;
    u16_t status_rx_quick_consumer_index15;
    u16_t status_completion_producer_index;
    u16_t status_cmd_consumer_index;
    u16_t status_idx;
    u8_t unused_0;
    u8_t status_blk_num;
    u32_t unused_1[2];
    #if (STATUS_BLOCK_SPACING > 64)
    u32_t unused_z[STATUS_BLOCK_SPACING/4-64/4];
    #endif

} status_block_b_t;


/*
 *  status_block_l definition
 */
typedef struct status_block_l
{
    u32_t status_attn_bits;
        #define STATUS_ATTN_BITS_LINK_STATE                 (1UL<<0)
        #define STATUS_ATTN_BITS_TX_SCHEDULER_ABORT         (1UL<<1)
        #define STATUS_ATTN_BITS_TX_BD_READ_ABORT           (1UL<<2)
        #define STATUS_ATTN_BITS_TX_BD_CACHE_ABORT          (1UL<<3)
        #define STATUS_ATTN_BITS_TX_PROCESSOR_ABORT         (1UL<<4)
        #define STATUS_ATTN_BITS_TX_DMA_ABORT               (1UL<<5)
        #define STATUS_ATTN_BITS_TX_PATCHUP_ABORT           (1UL<<6)
        #define STATUS_ATTN_BITS_TX_ASSEMBLER_ABORT         (1UL<<7)
        #define STATUS_ATTN_BITS_RX_PARSER_MAC_ABORT        (1UL<<8)
        #define STATUS_ATTN_BITS_RX_PARSER_CATCHUP_ABORT    (1UL<<9)
        #define STATUS_ATTN_BITS_RX_MBUF_ABORT              (1UL<<10)
        #define STATUS_ATTN_BITS_RX_LOOKUP_ABORT            (1UL<<11)
        #define STATUS_ATTN_BITS_RX_PROCESSOR_ABORT         (1UL<<12)
        #define STATUS_ATTN_BITS_RX_V2P_ABORT               (1UL<<13)
        #define STATUS_ATTN_BITS_RX_BD_CACHE_ABORT          (1UL<<14)
        #define STATUS_ATTN_BITS_RX_DMA_ABORT               (1UL<<15)
        #define STATUS_ATTN_BITS_COMPLETION_ABORT           (1UL<<16)
        #define STATUS_ATTN_BITS_HOST_COALESCE_ABORT        (1UL<<17)
        #define STATUS_ATTN_BITS_MAILBOX_QUEUE_ABORT        (1UL<<18)
        #define STATUS_ATTN_BITS_CONTEXT_ABORT              (1UL<<19)
        #define STATUS_ATTN_BITS_CMD_SCHEDULER_ABORT        (1UL<<20)
        #define STATUS_ATTN_BITS_CMD_PROCESSOR_ABORT        (1UL<<21)
        #define STATUS_ATTN_BITS_MGMT_PROCESSOR_ABORT       (1UL<<22)
        #define STATUS_ATTN_BITS_MAC_ABORT                  (1UL<<23)
        #define STATUS_ATTN_BITS_TIMER_ABORT                (1UL<<24)
        #define STATUS_ATTN_BITS_DMAE_ABORT                 (1UL<<25)
        #define STATUS_ATTN_BITS_FLSH_ABORT                 (1UL<<26)
        #define STATUS_ATTN_BITS_GRC_ABORT                  (1UL<<27)
        #define STATUS_ATTN_BITS_EPB_ERROR                  (1UL<<30)
        #define STATUS_ATTN_BITS_PARITY_ERROR               (1UL<<31)

    u32_t status_attn_bits_ack;
    u16_t status_tx_quick_consumer_index1;
    u16_t status_tx_quick_consumer_index0;
    u16_t status_tx_quick_consumer_index3;
    u16_t status_tx_quick_consumer_index2;
    u16_t status_rx_quick_consumer_index1;
    u16_t status_rx_quick_consumer_index0;
    u16_t status_rx_quick_consumer_index3;
    u16_t status_rx_quick_consumer_index2;
    u16_t status_rx_quick_consumer_index5;
    u16_t status_rx_quick_consumer_index4;
    u16_t status_rx_quick_consumer_index7;
    u16_t status_rx_quick_consumer_index6;
    u16_t status_rx_quick_consumer_index9;
    u16_t status_rx_quick_consumer_index8;
    u16_t status_rx_quick_consumer_index11;
    u16_t status_rx_quick_consumer_index10;
    u16_t status_rx_quick_consumer_index13;
    u16_t status_rx_quick_consumer_index12;
    u16_t status_rx_quick_consumer_index15;
    u16_t status_rx_quick_consumer_index14;
    u16_t status_cmd_consumer_index;
    u16_t status_completion_producer_index;
    u8_t status_blk_num;
    u8_t unused_0;
    u16_t status_idx;
    u32_t unused_1[2];
    #if (STATUS_BLOCK_SPACING > 64)
    u32_t unused_z[STATUS_BLOCK_SPACING/4-64/4];
    #endif

} status_block_l_t;


/*
 * status_block select
 */
#if defined(LITTLE_ENDIAN)
    typedef status_block_l_t status_block_t;
#elif defined(BIG_ENDIAN)
    typedef status_block_b_t status_block_t;
#endif


/*
 *  status_per_cpu_block_b definition
 */
typedef struct status_per_cpu_block_b
{
    u16_t status_pcpu_tx_quick_consumer_index;
    u16_t status_pcpu_rx_quick_consumer_index;
    u16_t status_pcpu_completion_producer_index;
    u16_t status_pcpu_cmd_consumer_index;
    u32_t unused_0;
    u16_t status_pcpu_idx;
    u8_t unused_1;
    u8_t status_pcpu_blk_num;
    u32_t unused_z[STATUS_BLOCK_SPACING/4-16/4];

} status_per_cpu_block_b_t;


/*
 *  status_per_cpu_block_l definition
 */
typedef struct status_per_cpu_block_l
{
    u16_t status_pcpu_rx_quick_consumer_index;
    u16_t status_pcpu_tx_quick_consumer_index;
    u16_t status_pcpu_cmd_consumer_index;
    u16_t status_pcpu_completion_producer_index;
    u32_t unused_0;
    u8_t status_pcpu_blk_num;
    u8_t unused_1;
    u16_t status_pcpu_idx;
    u32_t unused_z[STATUS_BLOCK_SPACING/4-16/4];

} status_per_cpu_block_l_t;


/*
 * status_per_cpu_block select
 */
#if defined(LITTLE_ENDIAN)
    typedef status_per_cpu_block_l_t status_per_cpu_block_t;
#elif defined(BIG_ENDIAN)
    typedef status_per_cpu_block_b_t status_per_cpu_block_t;
#endif


/*
 *  status_blk_combined definition
 */
typedef struct status_blk_combined
{
    status_block_t deflt;
    status_per_cpu_block_t proc[8];
} status_blk_combined_t;


/*
 *  statistics_block definition
 */
typedef struct statistics_block
{
    u32_t stat_IfHCInOctets_hi;
    u32_t stat_IfHCInOctets_lo;
    u32_t stat_IfHCInBadOctets_hi;
    u32_t stat_IfHCInBadOctets_lo;
    u32_t stat_IfHCOutOctets_hi;
    u32_t stat_IfHCOutOctets_lo;
    u32_t stat_IfHCOutBadOctets_hi;
    u32_t stat_IfHCOutBadOctets_lo;
    u32_t stat_IfHCInUcastPkts_hi;
    u32_t stat_IfHCInUcastPkts_lo;
    u32_t stat_IfHCInMulticastPkts_hi;
    u32_t stat_IfHCInMulticastPkts_lo;
    u32_t stat_IfHCInBroadcastPkts_hi;
    u32_t stat_IfHCInBroadcastPkts_lo;
    u32_t stat_IfHCOutUcastPkts_hi;
    u32_t stat_IfHCOutUcastPkts_lo;
    u32_t stat_IfHCOutMulticastPkts_hi;
    u32_t stat_IfHCOutMulticastPkts_lo;
    u32_t stat_IfHCOutBroadcastPkts_hi;
    u32_t stat_IfHCOutBroadcastPkts_lo;
    u32_t stat_emac_tx_stat_dot3statsinternalmactransmiterrors;
    u32_t stat_Dot3StatsCarrierSenseErrors;
    u32_t stat_Dot3StatsFCSErrors;
    u32_t stat_Dot3StatsAlignmentErrors;
    u32_t stat_Dot3StatsSingleCollisionFrames;
    u32_t stat_Dot3StatsMultipleCollisionFrames;
    u32_t stat_Dot3StatsDeferredTransmissions;
    u32_t stat_Dot3StatsExcessiveCollisions;
    u32_t stat_Dot3StatsLateCollisions;
    u32_t stat_EtherStatsCollisions;
    u32_t stat_EtherStatsFragments;
    u32_t stat_EtherStatsJabbers;
    u32_t stat_EtherStatsUndersizePkts;
    u32_t stat_EtherStatsOverrsizePkts;
    u32_t stat_EtherStatsPktsRx64Octets;
    u32_t stat_EtherStatsPktsRx65Octetsto127Octets;
    u32_t stat_EtherStatsPktsRx128Octetsto255Octets;
    u32_t stat_EtherStatsPktsRx256Octetsto511Octets;
    u32_t stat_EtherStatsPktsRx512Octetsto1023Octets;
    u32_t stat_EtherStatsPktsRx1024Octetsto1522Octets;
    u32_t stat_EtherStatsPktsRx1523Octetsto9022Octets;
    u32_t stat_EtherStatsPktsTx64Octets;
    u32_t stat_EtherStatsPktsTx65Octetsto127Octets;
    u32_t stat_EtherStatsPktsTx128Octetsto255Octets;
    u32_t stat_EtherStatsPktsTx256Octetsto511Octets;
    u32_t stat_EtherStatsPktsTx512Octetsto1023Octets;
    u32_t stat_EtherStatsPktsTx1024Octetsto1522Octets;
    u32_t stat_EtherStatsPktsTx1523Octetsto9022Octets;
    u32_t stat_XonPauseFramesReceived;
    u32_t stat_XoffPauseFramesReceived;
    u32_t stat_OutXonSent;
    u32_t stat_OutXoffSent;
    u32_t stat_FlowControlDone;
    u32_t stat_MacControlFramesReceived;
    u32_t stat_XoffStateEntered;
    u32_t stat_IfInFramesL2FilterDiscards;
    u32_t stat_IfInRuleCheckerDiscards;
    u32_t stat_IfInFTQDiscards;
    u32_t stat_IfInMBUFDiscards;
    u32_t stat_IfInRuleCheckerP4Hit;
    u32_t stat_CatchupInRuleCheckerDiscards;
    u32_t stat_CatchupInFTQDiscards;
    u32_t stat_CatchupInMBUFDiscards;
    u32_t stat_CatchupInRuleCheckerP4Hit;
    u32_t stat_GenStat00;
    u32_t stat_GenStat01;
    u32_t stat_GenStat02;
    u32_t stat_GenStat03;
    u32_t stat_GenStat04;
    u32_t stat_GenStat05;
    u32_t stat_GenStat06;
    u32_t stat_GenStat07;
    u32_t stat_GenStat08;
    u32_t stat_GenStat09;
    u32_t stat_GenStat10;
    u32_t stat_GenStat11;
    u32_t stat_GenStat12;
    u32_t stat_GenStat13;
    u32_t stat_GenStat14;
    u32_t stat_GenStat15;
} statistics_block_t;


/*
 *  l2_fhdr_b definition
 */
typedef struct l2_fhdr_b
{
    u16_t l2_fhdr_errors;
        #define L2_FHDR_ERRORS_ABORT_PKT                    (1<<0)
        #define L2_FHDR_ERRORS_BAD_CRC                      (1<<1)
        #define L2_FHDR_ERRORS_PHY_DECODE                   (1<<2)
        #define L2_FHDR_ERRORS_ALIGNMENT                    (1<<3)
        #define L2_FHDR_ERRORS_TOO_SHORT                    (1<<4)
        #define L2_FHDR_ERRORS_GIANT_FRAME                  (1<<5)
        #define L2_FHDR_ERRORS_IP_BAD_XSUM                  (1<<10)
        #define L2_FHDR_ERRORS_TCP_BAD_XSUM                 (1<<12)
        #define L2_FHDR_ERRORS_UDP_BAD_XSUM                 (1<<15)

    u16_t l2_fhdr_status;
        #define L2_FHDR_STATUS_RULE_CLASS                   (0x7<<0)
        #define L2_FHDR_STATUS_RULE_P2                      (1<<3)
        #define L2_FHDR_STATUS_RULE_P3                      (1<<4)
        #define L2_FHDR_STATUS_RULE_P4                      (1<<5)
        #define L2_FHDR_STATUS_L2_VLAN_TAG                  (1<<6)
        #define L2_FHDR_STATUS_L2_LLC_SNAP                  (1<<7)
        #define L2_FHDR_STATUS_RSS_HASH                     (1<<8)
        #define L2_FHDR_STATUS_IP_DATAGRAM                  (1<<13)
        #define L2_FHDR_STATUS_TCP_SEGMENT                  (1<<14)
        #define L2_FHDR_STATUS_UDP_DATAGRAM                 (1<<15)

    u32_t l2_fhdr_hash;
    u16_t l2_fhdr_pkt_len;
    u16_t l2_fhdr_vlan_tag;
    u16_t l2_fhdr_ip_xsum;
    u16_t l2_fhdr_tcp_udp_xsum;
} l2_fhdr_b_t;


/*
 *  l2_fhdr_l definition
 */
typedef struct l2_fhdr_l
{
    u16_t l2_fhdr_status;
        #define L2_FHDR_STATUS_RULE_CLASS                   (0x7<<0)
        #define L2_FHDR_STATUS_RULE_P2                      (1<<3)
        #define L2_FHDR_STATUS_RULE_P3                      (1<<4)
        #define L2_FHDR_STATUS_RULE_P4                      (1<<5)
        #define L2_FHDR_STATUS_L2_VLAN_TAG                  (1<<6)
        #define L2_FHDR_STATUS_L2_LLC_SNAP                  (1<<7)
        #define L2_FHDR_STATUS_RSS_HASH                     (1<<8)
        #define L2_FHDR_STATUS_IP_DATAGRAM                  (1<<13)
        #define L2_FHDR_STATUS_TCP_SEGMENT                  (1<<14)
        #define L2_FHDR_STATUS_UDP_DATAGRAM                 (1<<15)
    
    u16_t l2_fhdr_errors;
        #define L2_FHDR_ERRORS_ABORT_PKT                    (1<<0)
        #define L2_FHDR_ERRORS_BAD_CRC                      (1<<1)
        #define L2_FHDR_ERRORS_PHY_DECODE                   (1<<2)
        #define L2_FHDR_ERRORS_ALIGNMENT                    (1<<3)
        #define L2_FHDR_ERRORS_TOO_SHORT                    (1<<4)
        #define L2_FHDR_ERRORS_GIANT_FRAME                  (1<<5)
        #define L2_FHDR_ERRORS_IP_BAD_XSUM                  (1<<10)
        #define L2_FHDR_ERRORS_TCP_BAD_XSUM                 (1<<12)
        #define L2_FHDR_ERRORS_UDP_BAD_XSUM                 (1<<15)

    u32_t l2_fhdr_hash;
    u16_t l2_fhdr_vlan_tag;
    u16_t l2_fhdr_pkt_len;
    u16_t l2_fhdr_tcp_udp_xsum;
    u16_t l2_fhdr_ip_xsum;
} l2_fhdr_l_t;


/*
 * l2_fhdr select
 */
#if defined(LITTLE_ENDIAN)
    typedef l2_fhdr_l_t l2_fhdr_t;
#elif defined(BIG_ENDIAN)
    typedef l2_fhdr_b_t l2_fhdr_t;
#endif

/*
 *  l2_fhdr_ooo_b definition
 */
typedef struct l2_fhdr_ooo_b
{
    u8_t  l2_fhdr_block_idx;
    u8_t  l2_fhdr_opcode;
        #define L2_FHDR_OPCODE_ADD_PEN         (0)
        #define L2_FHDR_OPCODE_ADD_NEW         (1)
        #define L2_FHDR_OPCODE_ADD_RIGHT       (2)
        #define L2_FHDR_OPCODE_ADD_LEFT        (3)
        #define L2_FHDR_OPCODE_JOIN            (4)
        #define L2_FHDR_OPCODE_NOOP            (5)
        #define L2_FHDR_OPCODE_CLEAN_UP        (10)
    u8_t  l2_fhdr_drop_size;
    u8_t  l2_fhdr_drop_block_idx;
    u32_t l2_fhdr_icid;
    
    u16_t l2_fhdr_pkt_len;
    u16_t l2_fhdr_vlan_tag;
    u16_t l2_fhdr_ip_xsum;
    u16_t l2_fhdr_tcp_udp_xsum;
} l2_fhdr_ooo_b_t;


/*
 *  l2_fhdr_ooo_l definition
 */
typedef struct l2_fhdr_ooo_l
{
    u8_t  l2_fhdr_drop_block_idx;
    u8_t  l2_fhdr_drop_size;
    u8_t  l2_fhdr_opcode;
    u8_t  l2_fhdr_block_idx;
    u32_t l2_fhdr_icid;
    
    u16_t l2_fhdr_vlan_tag;
    u16_t l2_fhdr_pkt_len;
    u16_t l2_fhdr_tcp_udp_xsum;
    u16_t l2_fhdr_ip_xsum;
} l2_fhdr_ooo_l_t;

/*
 * l2_fhdr_ooo select
 */
#if defined(LITTLE_ENDIAN)
    typedef l2_fhdr_ooo_l_t l2_fhdr_ooo_t;
#elif defined(BIG_ENDIAN)
    typedef l2_fhdr_ooo_b_t l2_fhdr_ooo_t;
#endif

/*
 *  pci_config definition
 *  offset: 0000
 */
typedef struct pci_config
{
    u16_t pcicfg_vendor_id;
    u16_t pcicfg_device_id;
    u16_t pcicfg_command;
        #define PCICFG_COMMAND_IO_SPACE                     (1<<0)
        #define PCICFG_COMMAND_MEM_SPACE                    (1<<1)
        #define PCICFG_COMMAND_BUS_MASTER                   (1<<2)
        #define PCICFG_COMMAND_SPECIAL_CYCLES               (1<<3)
        #define PCICFG_COMMAND_MWI_CYCLES                   (1<<4)
        #define PCICFG_COMMAND_VGA_SNOOP                    (1<<5)
        #define PCICFG_COMMAND_PERR_ENA                     (1<<6)
        #define PCICFG_COMMAND_STEPPING                     (1<<7)
        #define PCICFG_COMMAND_SERR_ENA                     (1<<8)
        #define PCICFG_COMMAND_FAST_B2B                     (1<<9)
        #define PCICFG_COMMAND_INT_DISABLE                  (1<<10)
        #define PCICFG_COMMAND_RESERVED                     (0x1f<<11)

    u16_t pcicfg_status;
        #define PCICFG_STATUS_RESERVED1                     (0x7<<0)
        #define PCICFG_STATUS_INT_STATUS                    (1<<3)
        #define PCICFG_STATUS_CAP_LIST                      (1<<4)
        #define PCICFG_STATUS_66MHZ_CAP                     (1<<5)
        #define PCICFG_STATUS_RESERVED2                     (1<<6)
        #define PCICFG_STATUS_FAST_B2B_CAP                  (1<<7)
        #define PCICFG_STATUS_SIG_PERR_TE                      (1<<8)
        #define PCICFG_STATUS_MSTR_PERR_XI                     (1<<8)
        #define PCICFG_STATUS_DEVSEL_TIMING                 (0x3<<9)
        #define PCICFG_STATUS_SIG_TGT_ABT                   (1<<11)
        #define PCICFG_STATUS_RCV_TGT_ABT                   (1<<12)
        #define PCICFG_STATUS_RCV_MSTR_ABT                  (1<<13)
        #define PCICFG_STATUS_SIG_SERR                      (1<<14)
        #define PCICFG_STATUS_PAR_ERR                       (1<<15)

    u32_t pcicfg_class_code;
        #define PCICFG_CLASS_CODE_REV_ID                    (0xffUL<<0)
        #define PCICFG_CLASS_CODE_VALUE                     (0xffffffUL<<8)

    u8_t pcicfg_cache_line_size;
    u8_t pcicfg_latency_timer;
    u8_t pcicfg_header_type;
    u8_t pcicfg_bist;
    u32_t pcicfg_bar_1;
        #define PCICFG_BAR_1_MEM_SPACE                      (1UL<<0)
        #define PCICFG_BAR_1_SPACE_TYPE                     (0x3UL<<1)
        #define PCICFG_BAR_1_PREFETCH                       (1UL<<3)
        #define PCICFG_BAR_1_ADDRESS                        (0xfffffffUL<<4)

    u32_t pcicfg_bar_2;
        #define PCICFG_BAR_2_ADDR                           (0xffffffffUL<<0)

    u32_t pcicfg_bar_3;
        #define PCICFG_BAR_3_MEM_SPACE                      (1UL<<0)
        #define PCICFG_BAR_3_SPACE_TYPE                     (0x3UL<<1)
        #define PCICFG_BAR_3_PREFETCH                       (1UL<<3)
        #define PCICFG_BAR_3_ADDRESS                        (0xfffffffUL<<4)

    u32_t pcicfg_bar_4;
        #define PCICFG_BAR_4_ADDR                           (0xffffffffUL<<0)

    u32_t pcicfg_bar_5;
    u32_t pcicfg_bar_6;
    u32_t pcicfg_cardbus_cis;
    u16_t pcicfg_subsystem_vendor_id;
    u16_t pcicfg_subsystem_id;
    u32_t pcicfg_exp_rom_bar;
        #define PCICFG_EXP_ROM_BAR_BAR_ENA                  (1UL<<0)
        #define PCICFG_EXP_ROM_BAR_LOW_TE                      (0x1ffUL<<1)
        #define PCICFG_EXP_ROM_BAR_SIZE_TE                     (0x3fffUL<<10)
        #define PCICFG_EXP_ROM_BAR_LOW_XI                      (0x3ffUL<<1)
        #define PCICFG_EXP_ROM_BAR_SIZE_XI                     (0x1fffUL<<11)
        #define PCICFG_EXP_ROM_BAR_ADDRESS                  (0xffUL<<24)

    u8_t pcicfg_cap_pointer;
    u8_t unused_0;
    u16_t unused_1;
    u32_t unused_2;
    u8_t pcicfg_int_line;
    u8_t pcicfg_int_pin;
    u8_t pcicfg_min_grant;
    u8_t pcicfg_maximum_latency;
    u8_t pcicfg_pcix_cap_id;
    u8_t pcicfg_pcix_next_cap_ptr;
    u16_t pcicfg_pcix_command;
        #define PCICFG_PCIX_COMMAND_DATA_PAR_ERR            (1<<0)
        #define PCICFG_PCIX_COMMAND_RELAX_ORDER             (1<<1)
        #define PCICFG_PCIX_COMMAND_MAX_MEM_READ            (0x3<<2)
            #define PCICFG_PCIX_COMMAND_MAX_MEM_READ_512    (0<<2)
            #define PCICFG_PCIX_COMMAND_MAX_MEM_READ_1K     (1<<2)
            #define PCICFG_PCIX_COMMAND_MAX_MEM_READ_2K     (2<<2)
            #define PCICFG_PCIX_COMMAND_MAX_MEM_READ_4K     (3<<2)
        #define PCICFG_PCIX_COMMAND_MAX_SPLIT               (0x7<<4)
            #define PCICFG_PCIX_COMMAND_MAX_SPLIT_MAX_SPLIT_1  (0<<4)
            #define PCICFG_PCIX_COMMAND_MAX_SPLIT_MAX_SPLIT_2  (1<<4)
            #define PCICFG_PCIX_COMMAND_MAX_SPLIT_MAX_SPLIT_3  (2<<4)
            #define PCICFG_PCIX_COMMAND_MAX_SPLIT_MAX_SPLIT_4  (3<<4)
            #define PCICFG_PCIX_COMMAND_MAX_SPLIT_MAX_SPLIT_8  (4<<4)
            #define PCICFG_PCIX_COMMAND_MAX_SPLIT_MAX_SPLIT_12  (5<<4)
            #define PCICFG_PCIX_COMMAND_MAX_SPLIT_MAX_SPLIT_16  (6<<4)
            #define PCICFG_PCIX_COMMAND_MAX_SPLIT_MAX_SPLIT_32  (7<<4)
            #define PCICFG_PCIX_COMMAND_MAX_SPLIT_RESERVED  (511<<4)

    u32_t pcicfg_pcix_status;
        #define PCICFG_PCIX_STATUS_FUNC_NUM                 (0x7UL<<0)
        #define PCICFG_PCIX_STATUS_DEV_NUM                  (0x1fUL<<3)
        #define PCICFG_PCIX_STATUS_BUS_NUM                  (0xffUL<<8)
        #define PCICFG_PCIX_STATUS_64_BIT                   (1UL<<16)
        #define PCICFG_PCIX_STATUS_MAX_133_ADVERTIZE        (1UL<<17)
        #define PCICFG_PCIX_STATUS_SPLIT_DISCARD            (1UL<<18)
        #define PCICFG_PCIX_STATUS_UNEXPECTED_SPLIT         (1UL<<19)
        #define PCICFG_PCIX_STATUS_DEV_COMPLEX              (1UL<<20)
        #define PCICFG_PCIX_STATUS_MAX_MEM_READ             (0x3UL<<21)
            #define PCICFG_PCIX_STATUS_MAX_MEM_READ_512     (0UL<<21)
            #define PCICFG_PCIX_STATUS_MAX_MEM_READ_1K      (1UL<<21)
            #define PCICFG_PCIX_STATUS_MAX_MEM_READ_2K      (2UL<<21)
            #define PCICFG_PCIX_STATUS_MAX_MEM_READ_4K      (3UL<<21)
        #define PCICFG_PCIX_STATUS_MAX_SPLIT                (0x7UL<<23)
            #define PCICFG_PCIX_STATUS_MAX_SPLIT_1          (0UL<<23)
            #define PCICFG_PCIX_STATUS_MAX_SPLIT_2          (1UL<<23)
            #define PCICFG_PCIX_STATUS_MAX_SPLIT_3          (2UL<<23)
            #define PCICFG_PCIX_STATUS_MAX_SPLIT_4          (3UL<<23)
            #define PCICFG_PCIX_STATUS_MAX_SPLIT_8          (4UL<<23)
            #define PCICFG_PCIX_STATUS_MAX_SPLIT_12         (5UL<<23)
            #define PCICFG_PCIX_STATUS_MAX_SPLIT_16         (6UL<<23)
            #define PCICFG_PCIX_STATUS_MAX_SPLIT_32         (7UL<<23)
        #define PCICFG_PCIX_STATUS_MAX_CUM_SIZE             (0x7UL<<26)
            #define PCICFG_PCIX_STATUS_MAX_CUM_SIZE_1KB     (0UL<<26)
            #define PCICFG_PCIX_STATUS_MAX_CUM_SIZE_2KB     (1UL<<26)
            #define PCICFG_PCIX_STATUS_MAX_CUM_SIZE_4KB     (2UL<<26)
            #define PCICFG_PCIX_STATUS_MAX_CUM_SIZE_8KB     (3UL<<26)
            #define PCICFG_PCIX_STATUS_MAX_CUM_SIZE_16KB    (4UL<<26)
            #define PCICFG_PCIX_STATUS_MAX_CUM_SIZE_32KB    (5UL<<26)
            #define PCICFG_PCIX_STATUS_MAX_CUM_SIZE_64KB    (6UL<<26)
            #define PCICFG_PCIX_STATUS_MAX_CUM_SIZE_128KB   (7UL<<26)
        #define PCICFG_PCIX_STATUS_SPLIT_ERR                (1UL<<29)
        #define PCICFG_PCIX_STATUS_RESERVED                 (0x3UL<<30)

    u8_t pcicfg_pm_cap_id;
    u8_t pcicfg_pm_next_cap_ptr;
    u16_t pcicfg_pm_capability;
        #define PCICFG_PM_CAPABILITY_VERSION                (0x3<<0)
        #define PCICFG_PM_CAPABILITY_CLOCK                  (1<<3)
        #define PCICFG_PM_CAPABILITY_RESERVED               (1<<4)
        #define PCICFG_PM_CAPABILITY_DSI                    (1<<5)
        #define PCICFG_PM_CAPABILITY_AUX_CURRENT            (0x7<<6)
        #define PCICFG_PM_CAPABILITY_D1_SUPPORT             (1<<9)
        #define PCICFG_PM_CAPABILITY_D2_SUPPORT             (1<<10)
        #define PCICFG_PM_CAPABILITY_PME_IN_D0              (1<<11)
        #define PCICFG_PM_CAPABILITY_PME_IN_D1              (1<<12)
        #define PCICFG_PM_CAPABILITY_PME_IN_D2              (1<<13)
        #define PCICFG_PM_CAPABILITY_PME_IN_D3_HOT          (1<<14)
        #define PCICFG_PM_CAPABILITY_PME_IN_D3_COLD         (1<<15)

    u16_t pcicfg_pm_csr;
        #define PCICFG_PM_CSR_STATE                         (0x3<<0)
            #define PCICFG_PM_CSR_STATE_D0                  (0<<0)
            #define PCICFG_PM_CSR_STATE_D1                  (1<<0)
            #define PCICFG_PM_CSR_STATE_D2                  (2<<0)
            #define PCICFG_PM_CSR_STATE_D3_HOT              (3<<0)
        #define PCICFG_PM_CSR_RESERVED_TE                      (0x3f<<2)
        #define PCICFG_PM_CSR_RESERVED0_XI                     (1<<2)
        #define PCICFG_PM_CSR_NO_SOFT_RESET_XI                 (1<<3)
        #define PCICFG_PM_CSR_RESERVED1_XI                     (0xf<<4)
        #define PCICFG_PM_CSR_PME_ENABLE                    (1<<8)
        #define PCICFG_PM_CSR_DATA_SEL                      (0xf<<9)
            #define PCICFG_PM_CSR_DATA_SEL_0                (0<<9)
            #define PCICFG_PM_CSR_DATA_SEL_1                (1<<9)
            #define PCICFG_PM_CSR_DATA_SEL_2                (2<<9)
            #define PCICFG_PM_CSR_DATA_SEL_3                (3<<9)
            #define PCICFG_PM_CSR_DATA_SEL_4                (4<<9)
            #define PCICFG_PM_CSR_DATA_SEL_5                (5<<9)
            #define PCICFG_PM_CSR_DATA_SEL_6                (6<<9)
            #define PCICFG_PM_CSR_DATA_SEL_7                (7<<9)
        #define PCICFG_PM_CSR_DATA_SCALE                    (0x3<<13)
            #define PCICFG_PM_CSR_DATA_SCALE_0              (0<<13)
            #define PCICFG_PM_CSR_DATA_SCALE_1              (1<<13)
            #define PCICFG_PM_CSR_DATA_SCALE_2              (2<<13)
            #define PCICFG_PM_CSR_DATA_SCALE_3              (3<<13)
        #define PCICFG_PM_CSR_PME_STATUS                    (1<<15)

    u8_t pcicfg_pm_csr_bse;
    u8_t pcicfg_pm_data;
    u8_t pcicfg_vpd_cap_id;
    u8_t pcicfg_vpd_next_cap_ptr;
    u16_t pcicfg_vpd_flag_addr;
        #define PCICFG_VPD_FLAG_ADDR_ADDRESS                (0x1fff<<2)
        #define PCICFG_VPD_FLAG_ADDR_FLAG                   (1<<15)

    u32_t pcicfg_vpd_data;
    u8_t pcicfg_msi_cap_id;
    u8_t pcicfg_msi_next_cap_ptr;
    u16_t pcicfg_msi_control;
        #define PCICFG_MSI_CONTROL_ENABLE                   (1<<0)
        #define PCICFG_MSI_CONTROL_MCAP                     (0x7<<1)
            #define PCICFG_MSI_CONTROL_MCAP_1               (0<<1)
            #define PCICFG_MSI_CONTROL_MCAP_2               (1<<1)
            #define PCICFG_MSI_CONTROL_MCAP_4               (2<<1)
            #define PCICFG_MSI_CONTROL_MCAP_8               (3<<1)
            #define PCICFG_MSI_CONTROL_MCAP_16              (4<<1)
            #define PCICFG_MSI_CONTROL_MCAP_32              (5<<1)
        #define PCICFG_MSI_CONTROL_MENA                     (0x7<<4)
            #define PCICFG_MSI_CONTROL_MENA_1               (0<<4)
            #define PCICFG_MSI_CONTROL_MENA_2               (1<<4)
            #define PCICFG_MSI_CONTROL_MENA_4               (2<<4)
            #define PCICFG_MSI_CONTROL_MENA_8               (3<<4)
            #define PCICFG_MSI_CONTROL_MENA_16              (4<<4)
            #define PCICFG_MSI_CONTROL_MENA_32              (5<<4)
        #define PCICFG_MSI_CONTROL_64_BIT_ADDR_CAP          (1<<7)
        #define PCICFG_MSI_CONTROL_MSI_PVMASK_CAPABLE       (1<<8)

    u32_t pcicfg_msi_addr_l;
        #define PCICFG_MSI_ADDR_L_VAL                       (0x3fffffffUL<<2)

    u32_t pcicfg_msi_addr_h;
    u16_t pcicfg_msi_data;
    u16_t pcicfg_reserved;
    u32_t pcicfg_misc_config;
        #define PCICFG_MISC_CONFIG_TARGET_BYTE_SWAP         (1UL<<2)
        #define PCICFG_MISC_CONFIG_TARGET_MB_WORD_SWAP      (1UL<<3)
        #define PCICFG_MISC_CONFIG_RESERVED1                (1UL<<4)
        #define PCICFG_MISC_CONFIG_CLOCK_CTL_ENA            (1UL<<5)
        #define PCICFG_MISC_CONFIG_TARGET_GRC_WORD_SWAP     (1UL<<6)
        #define PCICFG_MISC_CONFIG_REG_WINDOW_ENA           (1UL<<7)
        #define PCICFG_MISC_CONFIG_CORE_RST_REQ             (1UL<<8)
        #define PCICFG_MISC_CONFIG_CORE_RST_BSY             (1UL<<9)
        #define PCICFG_MISC_CONFIG_GRC_WIN1_SWAP_EN         (1UL<<10)
        #define PCICFG_MISC_CONFIG_GRC_WIN2_SWAP_EN         (1UL<<11)
        #define PCICFG_MISC_CONFIG_GRC_WIN3_SWAP_EN         (1UL<<12)
        #define PCICFG_MISC_CONFIG_ASIC_METAL_REV           (0xffUL<<16)
        #define PCICFG_MISC_CONFIG_ASIC_BASE_REV            (0xfUL<<24)
        #define PCICFG_MISC_CONFIG_ASIC_ID                  (0xfUL<<28)

    u32_t pcicfg_misc_status;
        #define PCICFG_MISC_STATUS_INTA_VALUE               (1UL<<0)
        #define PCICFG_MISC_STATUS_32BIT_DET                (1UL<<1)
        #define PCICFG_MISC_STATUS_M66EN                    (1UL<<2)
        #define PCICFG_MISC_STATUS_PCIX_DET                 (1UL<<3)
        #define PCICFG_MISC_STATUS_PCIX_SPEED               (0x3UL<<4)
            #define PCICFG_MISC_STATUS_PCIX_SPEED_66        (0UL<<4)
            #define PCICFG_MISC_STATUS_PCIX_SPEED_100       (1UL<<4)
            #define PCICFG_MISC_STATUS_PCIX_SPEED_133       (2UL<<4)
            #define PCICFG_MISC_STATUS_PCIX_SPEED_PCI_MODE  (3UL<<4)
        #define PCICFG_MISC_STATUS_BAD_MEM_WRITE_BE         (1UL<<8)

    u32_t pcicfg_pci_clock_control_bits;
        #define PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET  (0xfUL<<0)
            #define PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_32MHZ  (0UL<<0)
            #define PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_38MHZ  (1UL<<0)
            #define PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_48MHZ  (2UL<<0)
            #define PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_55MHZ  (3UL<<0)
            #define PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_66MHZ  (4UL<<0)
            #define PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_80MHZ  (5UL<<0)
            #define PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_95MHZ  (6UL<<0)
            #define PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_133MHZ  (7UL<<0)
            #define PCICFG_PCI_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_LOW  (15UL<<0)
        #define PCICFG_PCI_CLOCK_CONTROL_BITS_CORE_CLK_DISABLE  (1UL<<6)
        #define PCICFG_PCI_CLOCK_CONTROL_BITS_CORE_CLK_ALT  (1UL<<7)
        #define PCICFG_PCI_CLOCK_CONTROL_BITS_CORE_CLK_ALT_SRC  (0x7UL<<8)
            #define PCICFG_PCI_CLOCK_CONTROL_BITS_CORE_CLK_ALT_SRC_UNDEF  (0UL<<8)
            #define PCICFG_PCI_CLOCK_CONTROL_BITS_CORE_CLK_ALT_SRC_12  (1UL<<8)
            #define PCICFG_PCI_CLOCK_CONTROL_BITS_CORE_CLK_ALT_SRC_6  (2UL<<8)
            #define PCICFG_PCI_CLOCK_CONTROL_BITS_CORE_CLK_ALT_SRC_62  (4UL<<8)
        #define PCICFG_PCI_CLOCK_CONTROL_BITS_MIN_POWER     (1UL<<11)
        #define PCICFG_PCI_CLOCK_CONTROL_BITS_CORE_CLK_PLL_SPEED  (0xfUL<<12)
            #define PCICFG_PCI_CLOCK_CONTROL_BITS_CORE_CLK_PLL_SPEED_100  (0UL<<12)
            #define PCICFG_PCI_CLOCK_CONTROL_BITS_CORE_CLK_PLL_SPEED_80  (1UL<<12)
            #define PCICFG_PCI_CLOCK_CONTROL_BITS_CORE_CLK_PLL_SPEED_50  (2UL<<12)
            #define PCICFG_PCI_CLOCK_CONTROL_BITS_CORE_CLK_PLL_SPEED_40  (4UL<<12)
            #define PCICFG_PCI_CLOCK_CONTROL_BITS_CORE_CLK_PLL_SPEED_25  (8UL<<12)
        #define PCICFG_PCI_CLOCK_CONTROL_BITS_CORE_CLK_PLL_STOP  (1UL<<16)
        #define PCICFG_PCI_CLOCK_CONTROL_BITS_RESERVED_17   (1UL<<17)
        #define PCICFG_PCI_CLOCK_CONTROL_BITS_RESERVED_18   (1UL<<18)
        #define PCICFG_PCI_CLOCK_CONTROL_BITS_RESERVED_19   (1UL<<19)
        #define PCICFG_PCI_CLOCK_CONTROL_BITS_RESERVED      (0xfffUL<<20)

    u32_t unused_3;
    u32_t pcicfg_reg_window_address;
        #define PCICFG_REG_WINDOW_ADDRESS_VAL               (0xfffffUL<<2)

    u32_t unused_4;
    u32_t pcicfg_reg_window;
    u32_t pcicfg_int_ack_cmd;
        #define PCICFG_INT_ACK_CMD_INDEX                    (0xffffUL<<0)
        #define PCICFG_INT_ACK_CMD_INDEX_VALID              (1UL<<16)
        #define PCICFG_INT_ACK_CMD_USE_INT_HC_PARAM         (1UL<<17)
        #define PCICFG_INT_ACK_CMD_MASK_INT                 (1UL<<18)
        #define PCICFG_INT_ACK_CMD_INTERRUPT_NUM            (0xfUL<<24)

    u32_t pcicfg_status_bit_set_cmd;
    u32_t pcicfg_status_bit_clear_cmd;
    u32_t pcicfg_mailbox_queue_addr;
    u32_t pcicfg_mailbox_queue_data;
    u32_t unused_5[2];
    u8_t pcicfg_msix_cap_id;
    u8_t pcicfg_msix_next_cap_ptr;
    u16_t pcicfg_msix_control;
        #define PCICFG_MSIX_CONTROL_TABLE_SIZE              (0x7ff<<0)
        #define PCICFG_MSIX_CONTROL_RESERVED                (0x7<<11)
        #define PCICFG_MSIX_CONTROL_FUNC_MASK               (1<<14)
        #define PCICFG_MSIX_CONTROL_MSIX_ENABLE             (1<<15)

    u32_t pcicfg_msix_tbl_off_bir;
        #define PCICFG_MSIX_TBL_OFF_BIR_TABLE_BIR           (0x7UL<<0)
        #define PCICFG_MSIX_TBL_OFF_BIR_TABLE_OFFSET        (0x1fffffffUL<<3)

    u32_t pcicfg_msix_pba_off_bir;
        #define PCICFG_MSIX_PBA_OFF_BIR_PBA_BIR             (0x7UL<<0)
        #define PCICFG_MSIX_PBA_OFF_BIR_PBA_OFFSET          (0x1fffffffUL<<3)

    u8_t pcicfg_pcie_cap_id;
    u8_t pcicfg_pcie_next_cap_ptr;
    u16_t pcicfg_pcie_capability;
        #define PCICFG_PCIE_CAPABILITY_VER                  (0xf<<0)
        #define PCICFG_PCIE_CAPABILITY_TYPE                 (0xf<<4)

    u32_t pcicfg_device_capability;
        #define PCICFG_DEVICE_CAPABILITY_MAX_PAYLOAD        (0x7UL<<0)
        #define PCICFG_DEVICE_CAPABILITY_PHANTOM_SUPPT      (0x3UL<<3)
        #define PCICFG_DEVICE_CAPABILITY_EXT_TAG_SUPPT      (1UL<<5)
        #define PCICFG_DEVICE_CAPABILITY_EP_L0S_ACCP_LAT    (0x7UL<<6)
        #define PCICFG_DEVICE_CAPABILITY_EP_L1_ACCP_LAT     (0x7UL<<9)

    u16_t pcicfg_device_control;
        #define PCICFG_DEVICE_CONTROL_CORR_ERR_REP_ENA      (1<<0)
        #define PCICFG_DEVICE_CONTROL_NON_FATAL_REP_ENA     (1<<1)
        #define PCICFG_DEVICE_CONTROL_FATAL_REP_ENA         (1<<2)
        #define PCICFG_DEVICE_CONTROL_UNSUP_REQ_ENA         (1<<3)
        #define PCICFG_DEVICE_CONTROL_RELAX_ENA             (1<<4)
        #define PCICFG_DEVICE_CONTROL_MAX_PAYLOAD           (0x7<<5)
        #define PCICFG_DEVICE_CONTROL_EXT_TAG_ENA           (1<<8)
        #define PCICFG_DEVICE_CONTROL_AUX_PWR_PM_ENA        (1<<10)
        #define PCICFG_DEVICE_CONTROL_ENA_NO_SNOOP          (1<<11)
        #define PCICFG_DEVICE_CONTROL_MAX_RD_REQ            (0x7<<12)

    u16_t pcicfg_device_status;
        #define PCICFG_DEVICE_STATUS_CORR_ERR_DET           (1<<0)
        #define PCICFG_DEVICE_STATUS_NON_FATAL_ERR_DET      (1<<1)
        #define PCICFG_DEVICE_STATUS_FATAL_ERR_DET          (1<<2)
        #define PCICFG_DEVICE_STATUS_UNSUP_REQ_DET          (1<<3)
        #define PCICFG_DEVICE_STATUS_AUX_PWR_DET            (1<<4)
        #define PCICFG_DEVICE_STATUS_NO_PEND                (1<<5)

    u32_t pcicfg_link_capability;
        #define PCICFG_LINK_CAPABILITY_MAX_LINK_SPEED       (0xfUL<<0)
            #define PCICFG_LINK_CAPABILITY_MAX_LINK_SPEED_2_5  (1UL<<0)
            #define PCICFG_LINK_CAPABILITY_MAX_LINK_SPEED_5  (2UL<<0)
        #define PCICFG_LINK_CAPABILITY_MAX_LINK_WIDTH       (0x3fUL<<4)
            #define PCICFG_LINK_CAPABILITY_MAX_LINK_WIDTH_1  (1UL<<4)
            #define PCICFG_LINK_CAPABILITY_MAX_LINK_WIDTH_2  (2UL<<4)
            #define PCICFG_LINK_CAPABILITY_MAX_LINK_WIDTH_4  (4UL<<4)
            #define PCICFG_LINK_CAPABILITY_MAX_LINK_WIDTH_8  (8UL<<4)
        #define PCICFG_LINK_CAPABILITY_ASPM_SUPT            (0x3UL<<10)
            #define PCICFG_LINK_CAPABILITY_ASPM_SUPT_RES_0  (0UL<<10)
            #define PCICFG_LINK_CAPABILITY_ASPM_SUPT_L0S    (0UL<<10)
            #define PCICFG_LINK_CAPABILITY_ASPM_SUPT_RES_2  (0UL<<10)
            #define PCICFG_LINK_CAPABILITY_ASPM_SUPT_L0S_L1  (0UL<<10)
        #define PCICFG_LINK_CAPABILITY_L0S_EXIT_LAT         (0x7UL<<12)
            #define PCICFG_LINK_CAPABILITY_L0S_EXIT_LAT_1_2  (5UL<<12)
            #define PCICFG_LINK_CAPABILITY_L0S_EXIT_LAT_2_4  (6UL<<12)
        #define PCICFG_LINK_CAPABILITY_L1_EXIT_LAT          (0x7UL<<15)
            #define PCICFG_LINK_CAPABILITY_L1_EXIT_LAT_1_2  (1UL<<15)
            #define PCICFG_LINK_CAPABILITY_L1_EXIT_LAT_2_4  (2UL<<15)
        #define PCICFG_LINK_CAPABILITY_CLK_PWR_MGMT         (1UL<<18)
        #define PCICFG_LINK_CAPABILITY_PORT_NUMBER          (0xffUL<<24)

    u16_t pcicfg_link_control;
        #define PCICFG_LINK_CONTROL_ASPM_CTRL               (0x3<<0)
        #define PCICFG_LINK_CONTROL_RD_COMP_BOUND           (1<<3)
            #define PCICFG_LINK_CONTROL_RD_COMP_BOUND_64    (0<<3)
            #define PCICFG_LINK_CONTROL_RD_COMP_BOUND_128   (1<<3)
        #define PCICFG_LINK_CONTROL_LINK_CR_COMMON_CLK      (1<<6)
        #define PCICFG_LINK_CONTROL_LINK_CR_EXT_SYNC        (1<<7)

    u16_t pcicfg_link_status;
        #define PCICFG_LINK_STATUS_SPEED                    (0xf<<0)
        #define PCICFG_LINK_STATUS_NEG_LINK_WIDTH           (0x3f<<4)
        #define PCICFG_LINK_STATUS_TRAINING_ERR             (1<<10)
        #define PCICFG_LINK_STATUS_TRAINING                 (1<<11)
        #define PCICFG_LINK_STATUS_SLOT_CLK                 (1<<12)

    u32_t pcicfg_slot_capability;
    u16_t pcicfg_slot_control;
    u16_t pcicfg_slot_status;
    u16_t pcicfg_root_control;
    u16_t pcicfg_root_cap;
    u32_t pcicfg_root_status;
    u32_t pcicfg_device_capability_2;
        #define PCICFG_DEVICE_CAPABILITY_2_CMPL_TO_RANGE_SUPP  (0xfUL<<0)
            #define PCICFG_DEVICE_CAPABILITY_2_CMPL_TO_RANGE_SUPP_ABCD  (15UL<<0)
        #define PCICFG_DEVICE_CAPABILITY_2_CMPL_TO_DISABL_SUPP  (1UL<<4)

    u16_t pcicfg_device_control_2;
        #define PCICFG_DEVICE_CONTROL_2_CMPL_TO_VALUE       (0xf<<0)
            #define PCICFG_DEVICE_CONTROL_2_CMPL_TO_VALUE_50MS  (0<<0)
            #define PCICFG_DEVICE_CONTROL_2_CMPL_TO_VALUE_100US  (1<<0)
            #define PCICFG_DEVICE_CONTROL_2_CMPL_TO_VALUE_10MS  (2<<0)
            #define PCICFG_DEVICE_CONTROL_2_CMPL_TO_VALUE_55MS  (3<<0)
            #define PCICFG_DEVICE_CONTROL_2_CMPL_TO_VALUE_210MS  (4<<0)
            #define PCICFG_DEVICE_CONTROL_2_CMPL_TO_VALUE_900MS  (5<<0)
            #define PCICFG_DEVICE_CONTROL_2_CMPL_TO_VALUE_3_5S  (6<<0)
            #define PCICFG_DEVICE_CONTROL_2_CMPL_TO_VALUE_13S  (7<<0)
            #define PCICFG_DEVICE_CONTROL_2_CMPL_TO_VALUE_64S  (8<<0)
        #define PCICFG_DEVICE_CONTROL_2_CMPL_TO_DISABLE     (1<<4)

    u16_t pcicfg_device_status_2;
    u32_t pcicfg_link_capability_2;
    u16_t pcicfg_link_control_2;
        #define PCICFG_LINK_CONTROL_2_TARGET_LINK_SPEED     (0xf<<0)
            #define PCICFG_LINK_CONTROL_2_TARGET_LINK_SPEED_2_5  (0<<0)
            #define PCICFG_LINK_CONTROL_2_TARGET_LINK_SPEED_5_0  (1<<0)
        #define PCICFG_LINK_CONTROL_2_ENTER_COMPLIANCE      (1<<4)
        #define PCICFG_LINK_CONTROL_2_HW_AUTO_SPEED_DISABLE  (1<<5)
        #define PCICFG_LINK_CONTROL_2_SEL_DEEMPHASIS        (1<<6)
            #define PCICFG_LINK_CONTROL_2_SEL_DEEMPHASIS_0  (0<<6)
            #define PCICFG_LINK_CONTROL_2_SEL_DEEMPHASIS_1  (1<<6)
        #define PCICFG_LINK_CONTROL_2_TX_MARGIN             (0x7<<7)
            #define PCICFG_LINK_CONTROL_2_TX_MARGIN_000     (0<<7)
            #define PCICFG_LINK_CONTROL_2_TX_MARGIN_001     (1<<7)
            #define PCICFG_LINK_CONTROL_2_TX_MARGIN_010     (2<<7)
            #define PCICFG_LINK_CONTROL_2_TX_MARGIN_011     (3<<7)
            #define PCICFG_LINK_CONTROL_2_TX_MARGIN_100     (4<<7)
            #define PCICFG_LINK_CONTROL_2_TX_MARGIN_101     (5<<7)
            #define PCICFG_LINK_CONTROL_2_TX_MARGIN_110     (6<<7)
            #define PCICFG_LINK_CONTROL_2_TX_MARGIN_111     (7<<7)

    u16_t pcicfg_link_status_2;
    u32_t unused_6[8];
    u16_t pcicfg_device_ser_num_cap_id;
    u16_t pcicfg_device_ser_num_cap_off;
        #define PCICFG_DEVICE_SER_NUM_CAP_OFF_VER           (0xf<<0)
        #define PCICFG_DEVICE_SER_NUM_CAP_OFF_NEXT          (0xfff<<4)

    u32_t pcicfg_lower_ser_num;
    u32_t pcicfg_upper_ser_num;
    u32_t unused_7;
    u16_t pcicfg_adv_err_cap_id;
    u16_t pcicfg_adv_err_cap_off;
        #define PCICFG_ADV_ERR_CAP_OFF_VER                  (0xf<<0)
        #define PCICFG_ADV_ERR_CAP_OFF_NEXT                 (0xfff<<4)

    u32_t pcicfg_ucorr_err_status;
        #define PCICFG_UCORR_ERR_STATUS_DLPES               (1UL<<4)
        #define PCICFG_UCORR_ERR_STATUS_PTLPS               (1UL<<12)
        #define PCICFG_UCORR_ERR_STATUS_FCPES               (1UL<<13)
        #define PCICFG_UCORR_ERR_STATUS_CTS                 (1UL<<14)
        #define PCICFG_UCORR_ERR_STATUS_CAS                 (1UL<<15)
        #define PCICFG_UCORR_ERR_STATUS_UCS                 (1UL<<16)
        #define PCICFG_UCORR_ERR_STATUS_ROS                 (1UL<<17)
        #define PCICFG_UCORR_ERR_STATUS_MTLPS               (1UL<<18)
        #define PCICFG_UCORR_ERR_STATUS_ECRCS               (1UL<<19)
        #define PCICFG_UCORR_ERR_STATUS_URES                (1UL<<20)

    u32_t pcicfg_ucorr_err_mask;
        #define PCICFG_UCORR_ERR_MASK_DLPEM                 (1UL<<4)
        #define PCICFG_UCORR_ERR_MASK_SDEM                  (1UL<<5)
        #define PCICFG_UCORR_ERR_MASK_PTLPM                 (1UL<<12)
        #define PCICFG_UCORR_ERR_MASK_FCPEM                 (1UL<<13)
        #define PCICFG_UCORR_ERR_MASK_CTM                   (1UL<<14)
        #define PCICFG_UCORR_ERR_MASK_CAM                   (1UL<<15)
        #define PCICFG_UCORR_ERR_MASK_UCM                   (1UL<<16)
        #define PCICFG_UCORR_ERR_MASK_ROM                   (1UL<<17)
        #define PCICFG_UCORR_ERR_MASK_MTLPM                 (1UL<<18)
        #define PCICFG_UCORR_ERR_MASK_ECRCEM                (1UL<<19)
        #define PCICFG_UCORR_ERR_MASK_UREM                  (1UL<<20)

    u32_t pcicfg_ucorr_err_sevr;
        #define PCICFG_UCORR_ERR_SEVR_DLPES                 (1UL<<4)
        #define PCICFG_UCORR_ERR_SEVR_SDES                  (1UL<<5)
        #define PCICFG_UCORR_ERR_SEVR_PTLPS                 (1UL<<12)
        #define PCICFG_UCORR_ERR_SEVR_FCPES                 (1UL<<13)
        #define PCICFG_UCORR_ERR_SEVR_CTS                   (1UL<<14)
        #define PCICFG_UCORR_ERR_SEVR_CAS                   (1UL<<15)
        #define PCICFG_UCORR_ERR_SEVR_UCS                   (1UL<<16)
        #define PCICFG_UCORR_ERR_SEVR_ROS                   (1UL<<17)
        #define PCICFG_UCORR_ERR_SEVR_MTLPS                 (1UL<<18)
        #define PCICFG_UCORR_ERR_SEVR_ECRCES                (1UL<<19)
        #define PCICFG_UCORR_ERR_SEVR_URES                  (1UL<<20)

    u32_t pcicfg_corr_err_status;
        #define PCICFG_CORR_ERR_STATUS_RES                  (1UL<<0)
        #define PCICFG_CORR_ERR_STATUS_BDLLPS               (1UL<<7)
        #define PCICFG_CORR_ERR_STATUS_BTLPS                (1UL<<7)
        #define PCICFG_CORR_ERR_STATUS_RNRS                 (1UL<<8)
        #define PCICFG_CORR_ERR_STATUS_RTTS                 (1UL<<12)
        #define PCICFG_CORR_ERR_STATUS_ANFS                 (1UL<<13)

    u32_t pcicfg_corr_err_mask;
        #define PCICFG_CORR_ERR_MASK_RES                    (1UL<<0)
        #define PCICFG_CORR_ERR_MASK_BTLPS                  (1UL<<6)
        #define PCICFG_CORR_ERR_MASK_BDLLPS                 (1UL<<7)
        #define PCICFG_CORR_ERR_MASK_RNRS                   (1UL<<8)
        #define PCICFG_CORR_ERR_MASK_RTTS                   (1UL<<12)
        #define PCICFG_CORR_ERR_MASK_ANFM                   (1UL<<13)

    u32_t pcicfg_adv_err_cap_control;
        #define PCICFG_ADV_ERR_CAP_CONTROL_FIRST_UERR_PTR   (0x1fUL<<0)
        #define PCICFG_ADV_ERR_CAP_CONTROL_ECRCGCAP         (1UL<<5)
        #define PCICFG_ADV_ERR_CAP_CONTROL_ECRCGEN          (1UL<<6)
        #define PCICFG_ADV_ERR_CAP_CONTROL_ECRCCAP          (1UL<<7)
        #define PCICFG_ADV_ERR_CAP_CONTROL_ECRCEN           (1UL<<8)

    u32_t pcicfg_header_log1;
    u32_t pcicfg_header_log2;
    u32_t pcicfg_header_log3;
    u32_t pcicfg_header_log4;
    u32_t unused_8[5];
    u16_t pcicfg_pwr_bdgt_cap_id;
    u16_t pcicfg_pwr_bdgt_cap_off;
        #define PCICFG_PWR_BDGT_CAP_OFF_VER                 (0xf<<0)
        #define PCICFG_PWR_BDGT_CAP_OFF_NEXT                (0xfff<<4)

    u32_t pcicfg_pwr_bdgt_data_sel;
        #define PCICFG_PWR_BDGT_DATA_SEL_DS_VALUE           (0xffUL<<0)
            #define PCICFG_PWR_BDGT_DATA_SEL_DS_VALUE_0     (0UL<<0)
            #define PCICFG_PWR_BDGT_DATA_SEL_DS_VALUE_1     (1UL<<0)
            #define PCICFG_PWR_BDGT_DATA_SEL_DS_VALUE_2     (2UL<<0)
            #define PCICFG_PWR_BDGT_DATA_SEL_DS_VALUE_3     (3UL<<0)
            #define PCICFG_PWR_BDGT_DATA_SEL_DS_VALUE_4     (4UL<<0)
            #define PCICFG_PWR_BDGT_DATA_SEL_DS_VALUE_5     (5UL<<0)
            #define PCICFG_PWR_BDGT_DATA_SEL_DS_VALUE_6     (6UL<<0)
            #define PCICFG_PWR_BDGT_DATA_SEL_DS_VALUE_7     (7UL<<0)

    u32_t pcicfg_pwr_bdgt_data;
        #define PCICFG_PWR_BDGT_DATA_BASE_PWR               (0xffUL<<0)
        #define PCICFG_PWR_BDGT_DATA_DSCALE                 (0x3UL<<8)
        #define PCICFG_PWR_BDGT_DATA_PM_STATE               (0x3UL<<13)
        #define PCICFG_PWR_BDGT_DATA_TYPE                   (0x7UL<<15)
        #define PCICFG_PWR_BDGT_DATA_RAIL                   (0x7UL<<18)

    u32_t pcicfg_pwr_bdgt_capability;
        #define PCICFG_PWR_BDGT_CAPABILITY_PCIE_CFG_PB_CAP_SYS_ALLOC  (1UL<<0)

    u16_t pcicfg_vc_cap_id;
    u16_t pcicfg_vc_cap_off;
        #define PCICFG_VC_CAP_OFF_VER                       (0xf<<0)
        #define PCICFG_VC_CAP_OFF_NEXT                      (0xfff<<4)

    u32_t pcicfg_port_vc_capability;
    u32_t pcicfg_port_vc_capability2;
    u16_t pcicfg_port_vc_control;
    u16_t pcicfg_port_vc_status;
    u32_t pcicfg_port_arb_table;
    u32_t pcicfg_vc_rsrc_control;
        #define PCICFG_VC_RSRC_CONTROL_TC_VC_MAP            (0xffUL<<0)
        #define PCICFG_VC_RSRC_CONTROL_VC_ENABLE            (1UL<<31)

    u16_t pcicfg_rsvdp;
    u16_t pcicfg_vc_rsrc_status;
    u32_t unused_9[161];
} pci_config_t;


/*
 *  pci_reg definition
 *  offset: 0x400
 */
typedef struct pci_reg
{
    u32_t pci_grc_window_addr;
        #define PCI_GRC_WINDOW_ADDR_VALUE                   (0x1ffUL<<13)
        #define PCI_GRC_WINDOW_ADDR_SEP_WIN                 (1UL<<31)

    u32_t pci_config_1;
        #define PCI_CONFIG_1_RESERVED0                      (0xffUL<<0)
        #define PCI_CONFIG_1_READ_BOUNDARY                  (0x7UL<<8)
            #define PCI_CONFIG_1_READ_BOUNDARY_OFF          (0UL<<8)
            #define PCI_CONFIG_1_READ_BOUNDARY_16           (1UL<<8)
            #define PCI_CONFIG_1_READ_BOUNDARY_32           (2UL<<8)
            #define PCI_CONFIG_1_READ_BOUNDARY_64           (3UL<<8)
            #define PCI_CONFIG_1_READ_BOUNDARY_128          (4UL<<8)
            #define PCI_CONFIG_1_READ_BOUNDARY_256          (5UL<<8)
            #define PCI_CONFIG_1_READ_BOUNDARY_512          (6UL<<8)
            #define PCI_CONFIG_1_READ_BOUNDARY_1024         (7UL<<8)
        #define PCI_CONFIG_1_WRITE_BOUNDARY                 (0x7UL<<11)
            #define PCI_CONFIG_1_WRITE_BOUNDARY_OFF         (0UL<<11)
            #define PCI_CONFIG_1_WRITE_BOUNDARY_16          (1UL<<11)
            #define PCI_CONFIG_1_WRITE_BOUNDARY_32          (2UL<<11)
            #define PCI_CONFIG_1_WRITE_BOUNDARY_64          (3UL<<11)
            #define PCI_CONFIG_1_WRITE_BOUNDARY_128         (4UL<<11)
            #define PCI_CONFIG_1_WRITE_BOUNDARY_256         (5UL<<11)
            #define PCI_CONFIG_1_WRITE_BOUNDARY_512         (6UL<<11)
            #define PCI_CONFIG_1_WRITE_BOUNDARY_1024        (7UL<<11)
        #define PCI_CONFIG_1_RESERVED1                      (0x3ffffUL<<14)

    u32_t pci_config_2;
        #define PCI_CONFIG_2_BAR1_SIZE                      (0xfUL<<0)
            #define PCI_CONFIG_2_BAR1_SIZE_DISABLED         (0UL<<0)
            #define PCI_CONFIG_2_BAR1_SIZE_64K              (1UL<<0)
            #define PCI_CONFIG_2_BAR1_SIZE_128K             (2UL<<0)
            #define PCI_CONFIG_2_BAR1_SIZE_256K             (3UL<<0)
            #define PCI_CONFIG_2_BAR1_SIZE_512K             (4UL<<0)
            #define PCI_CONFIG_2_BAR1_SIZE_1M               (5UL<<0)
            #define PCI_CONFIG_2_BAR1_SIZE_2M               (6UL<<0)
            #define PCI_CONFIG_2_BAR1_SIZE_4M               (7UL<<0)
            #define PCI_CONFIG_2_BAR1_SIZE_8M               (8UL<<0)
            #define PCI_CONFIG_2_BAR1_SIZE_16M              (9UL<<0)
            #define PCI_CONFIG_2_BAR1_SIZE_32M              (10UL<<0)
            #define PCI_CONFIG_2_BAR1_SIZE_64M              (11UL<<0)
            #define PCI_CONFIG_2_BAR1_SIZE_128M             (12UL<<0)
            #define PCI_CONFIG_2_BAR1_SIZE_256M             (13UL<<0)
            #define PCI_CONFIG_2_BAR1_SIZE_512M             (14UL<<0)
            #define PCI_CONFIG_2_BAR1_SIZE_1G               (15UL<<0)
        #define PCI_CONFIG_2_BAR1_64ENA                     (1UL<<4)
        #define PCI_CONFIG_2_EXP_ROM_RETRY                  (1UL<<5)
        #define PCI_CONFIG_2_CFG_CYCLE_RETRY                (1UL<<6)
        #define PCI_CONFIG_2_FIRST_CFG_DONE                 (1UL<<7)
        #define PCI_CONFIG_2_EXP_ROM_SIZE                   (0xffUL<<8)
            #define PCI_CONFIG_2_EXP_ROM_SIZE_DISABLED      (0UL<<8)
            #define PCI_CONFIG_2_EXP_ROM_SIZE_1K_TE            (1UL<<8)
            #define PCI_CONFIG_2_EXP_ROM_SIZE_2K_TE            (2UL<<8)
            #define PCI_CONFIG_2_EXP_ROM_SIZE_4K_TE            (3UL<<8)
            #define PCI_CONFIG_2_EXP_ROM_SIZE_8K_TE            (4UL<<8)
            #define PCI_CONFIG_2_EXP_ROM_SIZE_16K_TE           (5UL<<8)
            #define PCI_CONFIG_2_EXP_ROM_SIZE_32K_TE           (6UL<<8)
            #define PCI_CONFIG_2_EXP_ROM_SIZE_64K_TE           (7UL<<8)
            #define PCI_CONFIG_2_EXP_ROM_SIZE_128K_TE          (8UL<<8)
            #define PCI_CONFIG_2_EXP_ROM_SIZE_256K_TE          (9UL<<8)
            #define PCI_CONFIG_2_EXP_ROM_SIZE_512K_TE          (10UL<<8)
            #define PCI_CONFIG_2_EXP_ROM_SIZE_1M_TE            (11UL<<8)
            #define PCI_CONFIG_2_EXP_ROM_SIZE_2M_TE            (12UL<<8)
            #define PCI_CONFIG_2_EXP_ROM_SIZE_4M_TE            (13UL<<8)
            #define PCI_CONFIG_2_EXP_ROM_SIZE_8M_TE            (14UL<<8)
            #define PCI_CONFIG_2_EXP_ROM_SIZE_16M_TE           (15UL<<8)
            #define PCI_CONFIG_2_EXP_ROM_SIZE_2K_XI            (1UL<<8)
            #define PCI_CONFIG_2_EXP_ROM_SIZE_4K_XI            (2UL<<8)
            #define PCI_CONFIG_2_EXP_ROM_SIZE_8K_XI            (3UL<<8)
            #define PCI_CONFIG_2_EXP_ROM_SIZE_16K_XI           (4UL<<8)
            #define PCI_CONFIG_2_EXP_ROM_SIZE_32K_XI           (5UL<<8)
            #define PCI_CONFIG_2_EXP_ROM_SIZE_64K_XI           (6UL<<8)
            #define PCI_CONFIG_2_EXP_ROM_SIZE_128K_XI          (7UL<<8)
            #define PCI_CONFIG_2_EXP_ROM_SIZE_256K_XI          (8UL<<8)
            #define PCI_CONFIG_2_EXP_ROM_SIZE_512K_XI          (9UL<<8)
            #define PCI_CONFIG_2_EXP_ROM_SIZE_1M_XI            (10UL<<8)
            #define PCI_CONFIG_2_EXP_ROM_SIZE_2M_XI            (11UL<<8)
            #define PCI_CONFIG_2_EXP_ROM_SIZE_4M_XI            (12UL<<8)
            #define PCI_CONFIG_2_EXP_ROM_SIZE_8M_XI            (13UL<<8)
            #define PCI_CONFIG_2_EXP_ROM_SIZE_16M_XI           (14UL<<8)
            #define PCI_CONFIG_2_EXP_ROM_SIZE_32M_XI           (15UL<<8)
        #define PCI_CONFIG_2_MAX_SPLIT_LIMIT_TE                (0x1fUL<<16)
        #define PCI_CONFIG_2_MAX_READ_LIMIT_TE                 (0x3UL<<21)
            #define PCI_CONFIG_2_MAX_READ_LIMIT_512_TE         (0UL<<21)
            #define PCI_CONFIG_2_MAX_READ_LIMIT_1K_TE          (1UL<<21)
            #define PCI_CONFIG_2_MAX_READ_LIMIT_2K_TE          (2UL<<21)
            #define PCI_CONFIG_2_MAX_READ_LIMIT_4K_TE          (3UL<<21)
        #define PCI_CONFIG_2_FORCE_32_BIT_MSTR_TE              (1UL<<23)
        #define PCI_CONFIG_2_FORCE_32_BIT_TGT_TE               (1UL<<24)
        #define PCI_CONFIG_2_KEEP_REQ_ASSERT_TE                (1UL<<25)
        #define PCI_CONFIG_2_RESERVED0_TE                      (0x3fUL<<26)
        #define PCI_CONFIG_2_BAR_PREFETCH_XI                   (1UL<<16)
        #define PCI_CONFIG_2_RESERVED0_XI                      (0x7fffUL<<17)

    u32_t pci_config_3;
        #define PCI_CONFIG_3_STICKY_BYTE                    (0xffUL<<0)
        #define PCI_CONFIG_3_REG_STICKY_BYTE                (0xffUL<<8)
        #define PCI_CONFIG_3_FORCE_PME                      (1UL<<24)
        #define PCI_CONFIG_3_PME_STATUS                     (1UL<<25)
        #define PCI_CONFIG_3_PME_ENABLE                     (1UL<<26)
        #define PCI_CONFIG_3_PM_STATE                       (0x3UL<<27)
        #define PCI_CONFIG_3_VAUX_PRESET                    (1UL<<30)
        #define PCI_CONFIG_3_PCI_POWER                      (1UL<<31)

    u32_t pci_pm_data_a;
        #define PCI_PM_DATA_A_PM_DATA_0_PRG                 (0xffUL<<0)
        #define PCI_PM_DATA_A_PM_DATA_1_PRG                 (0xffUL<<8)
        #define PCI_PM_DATA_A_PM_DATA_2_PRG                 (0xffUL<<16)
        #define PCI_PM_DATA_A_PM_DATA_3_PRG                 (0xffUL<<24)

    u32_t pci_pm_data_b;
        #define PCI_PM_DATA_B_PM_DATA_4_PRG                 (0xffUL<<0)
        #define PCI_PM_DATA_B_PM_DATA_5_PRG                 (0xffUL<<8)
        #define PCI_PM_DATA_B_PM_DATA_6_PRG                 (0xffUL<<16)
        #define PCI_PM_DATA_B_PM_DATA_7_PRG                 (0xffUL<<24)

    u32_t pci_swap_diag0;
    u32_t pci_swap_diag1;
    u32_t pci_exp_rom_addr;
        #define PCI_EXP_ROM_ADDR_ADDRESS                    (0x3fffffUL<<2)
        #define PCI_EXP_ROM_ADDR_REQ                        (1UL<<31)

    u32_t pci_exp_rom_data;
    u32_t pci_vpd_intf;
        #define PCI_VPD_INTF_INTF_REQ                       (1UL<<0)

    u16_t unused_0;
    u16_t pci_vpd_addr_flag;
        #define PCI_VPD_ADDR_FLAG_ADDRESS                   (0x1fff<<2)
        #define PCI_VPD_ADDR_FLAG_WR                        (1<<15)

    u32_t pci_vpd_data;
    u32_t pci_id_val1;
        #define PCI_ID_VAL1_DEVICE_ID                       (0xffffUL<<0)
        #define PCI_ID_VAL1_VENDOR_ID                       (0xffffUL<<16)

    u32_t pci_id_val2;
        #define PCI_ID_VAL2_SUBSYSTEM_VENDOR_ID             (0xffffUL<<0)
        #define PCI_ID_VAL2_SUBSYSTEM_ID                    (0xffffUL<<16)

    u32_t pci_id_val3;
        #define PCI_ID_VAL3_CLASS_CODE                      (0xffffffUL<<0)
        #define PCI_ID_VAL3_REVISION_ID                     (0xffUL<<24)

    u32_t pci_id_val4;
        #define PCI_ID_VAL4_CAP_ENA                         (0xfUL<<0)
            #define PCI_ID_VAL4_CAP_ENA_0                   (0UL<<0)
            #define PCI_ID_VAL4_CAP_ENA_1                   (1UL<<0)
            #define PCI_ID_VAL4_CAP_ENA_2                   (2UL<<0)
            #define PCI_ID_VAL4_CAP_ENA_3                   (3UL<<0)
            #define PCI_ID_VAL4_CAP_ENA_4                   (4UL<<0)
            #define PCI_ID_VAL4_CAP_ENA_5                   (5UL<<0)
            #define PCI_ID_VAL4_CAP_ENA_6                   (6UL<<0)
            #define PCI_ID_VAL4_CAP_ENA_7                   (7UL<<0)
            #define PCI_ID_VAL4_CAP_ENA_8                   (8UL<<0)
            #define PCI_ID_VAL4_CAP_ENA_9                   (9UL<<0)
            #define PCI_ID_VAL4_CAP_ENA_10                  (10UL<<0)
            #define PCI_ID_VAL4_CAP_ENA_11                  (11UL<<0)
            #define PCI_ID_VAL4_CAP_ENA_12                  (12UL<<0)
            #define PCI_ID_VAL4_CAP_ENA_13                  (13UL<<0)
            #define PCI_ID_VAL4_CAP_ENA_14                  (14UL<<0)
            #define PCI_ID_VAL4_CAP_ENA_15                  (15UL<<0)
        #define PCI_ID_VAL4_RESERVED0                       (0x3UL<<4)
        #define PCI_ID_VAL4_PM_SCALE_PRG                    (0x3UL<<6)
            #define PCI_ID_VAL4_PM_SCALE_PRG_0              (0UL<<6)
            #define PCI_ID_VAL4_PM_SCALE_PRG_1              (1UL<<6)
            #define PCI_ID_VAL4_PM_SCALE_PRG_2              (2UL<<6)
            #define PCI_ID_VAL4_PM_SCALE_PRG_3              (3UL<<6)
        #define PCI_ID_VAL4_MSI_PV_MASK_CAP                 (1UL<<8)
        #define PCI_ID_VAL4_MSI_LIMIT                       (0x7UL<<9)
        #define PCI_ID_VAL4_MULTI_MSG_CAP                   (0x7UL<<12)
        #define PCI_ID_VAL4_MSI_ENABLE                      (1UL<<15)
        #define PCI_ID_VAL4_MAX_64_ADVERTIZE_TE                (1UL<<16)
        #define PCI_ID_VAL4_MAX_133_ADVERTIZE_TE               (1UL<<17)
        #define PCI_ID_VAL4_RESERVED2_TE                       (0x7UL<<18)
        #define PCI_ID_VAL4_MAX_CUMULATIVE_SIZE_B21_TE         (0x3UL<<21)
        #define PCI_ID_VAL4_MAX_SPLIT_SIZE_B21_TE              (0x3UL<<23)
        #define PCI_ID_VAL4_MAX_CUMULATIVE_SIZE_B0_TE          (1UL<<25)
        #define PCI_ID_VAL4_MAX_MEM_READ_SIZE_B10_TE           (0x3UL<<26)
        #define PCI_ID_VAL4_MAX_SPLIT_SIZE_B0_TE               (1UL<<28)
        #define PCI_ID_VAL4_RESERVED3_TE                       (0x7UL<<29)
        #define PCI_ID_VAL4_RESERVED3_XI                       (0xffffUL<<16)

    u32_t pci_id_val5;
        #define PCI_ID_VAL5_D1_SUPPORT                      (1UL<<0)
        #define PCI_ID_VAL5_D2_SUPPORT                      (1UL<<1)
        #define PCI_ID_VAL5_PME_IN_D0                       (1UL<<2)
        #define PCI_ID_VAL5_PME_IN_D1                       (1UL<<3)
        #define PCI_ID_VAL5_PME_IN_D2                       (1UL<<4)
        #define PCI_ID_VAL5_PME_IN_D3_HOT                   (1UL<<5)
        #define PCI_ID_VAL5_RESERVED0_TE                       (0x3ffffffUL<<6)
        #define PCI_ID_VAL5_PM_VERSION_XI                      (0x7UL<<6)
        #define PCI_ID_VAL5_NO_SOFT_RESET_XI                   (1UL<<9)
        #define PCI_ID_VAL5_RESERVED0_XI                       (0x3fffffUL<<10)

    u32_t pci_pcix_extended_status;
        #define PCI_PCIX_EXTENDED_STATUS_NO_SNOOP           (1UL<<8)
        #define PCI_PCIX_EXTENDED_STATUS_LONG_BURST         (1UL<<9)
        #define PCI_PCIX_EXTENDED_STATUS_SPLIT_COMP_MSG_CLASS  (0xfUL<<16)
        #define PCI_PCIX_EXTENDED_STATUS_SPLIT_COMP_MSG_IDX  (0xffUL<<24)

    u32_t pci_id_val6;
        #define PCI_ID_VAL6_MAX_LAT                         (0xffUL<<0)
        #define PCI_ID_VAL6_MIN_GNT                         (0xffUL<<8)
        #define PCI_ID_VAL6_BIST                            (0xffUL<<16)
        #define PCI_ID_VAL6_RESERVED0                       (0xffUL<<24)

    u32_t pci_msi_data;
        #define PCI_MSI_DATA_MSI_DATA                       (0xffffUL<<0)

    u32_t pci_msi_addr_h;
    u32_t pci_msi_addr_l;
        #define PCI_MSI_ADDR_L_VAL                          (0x3fffffffUL<<2)

    u32_t pci_cfg_access_cmd;
        #define PCI_CFG_ACCESS_CMD_ADR                      (0x3fUL<<2)
        #define PCI_CFG_ACCESS_CMD_RD_REQ                   (1UL<<27)
        #define PCI_CFG_ACCESS_CMD_WR_REQ                   (0xfUL<<28)

    u32_t pci_cfg_access_data;
    u32_t pci_msi_mask;
        #define PCI_MSI_MASK_MSI_MASK                       (0xffffffffUL<<0)

    u32_t pci_msi_pend;
        #define PCI_MSI_PEND_MSI_PEND                       (0xffffffffUL<<0)

    u32_t pci_pm_data_c;
        #define PCI_PM_DATA_C_PM_DATA_8_PRG                 (0xffUL<<0)
        #define PCI_PM_DATA_C_RESERVED0                     (0xffffffUL<<8)

    u32_t unused_1[20];
    u32_t pci_msix_control;
        #define PCI_MSIX_CONTROL_MSIX_TBL_SIZ               (0x7ffUL<<0)
        #define PCI_MSIX_CONTROL_RESERVED0                  (0x1fffffUL<<11)

    u32_t pci_msix_tbl_off_bir;
        #define PCI_MSIX_TBL_OFF_BIR_MSIX_TBL_BIR           (0x7UL<<0)
        #define PCI_MSIX_TBL_OFF_BIR_MSIX_TBL_OFF           (0x1fffffffUL<<3)

    u32_t pci_msix_pba_off_bit;
        #define PCI_MSIX_PBA_OFF_BIT_MSIX_PBA_BIR           (0x7UL<<0)
        #define PCI_MSIX_PBA_OFF_BIT_MSIX_PBA_OFF           (0x1fffffffUL<<3)

    u32_t unused_2;
    u32_t pci_pcie_capability;
        #define PCI_PCIE_CAPABILITY_INTERRUPT_MSG_NUM       (0x1fUL<<0)
        #define PCI_PCIE_CAPABILITY_COMPLY_PCIE_1_1         (1UL<<5)

    u32_t pci_device_capability;
        #define PCI_DEVICE_CAPABILITY_MAX_PL_SIZ_SUPPORTED  (0x7UL<<0)
        #define PCI_DEVICE_CAPABILITY_EXTENDED_TAG_SUPPORT  (1UL<<5)
        #define PCI_DEVICE_CAPABILITY_L0S_ACCEPTABLE_LATENCY  (0x7UL<<6)
        #define PCI_DEVICE_CAPABILITY_L1_ACCEPTABLE_LATENCY  (0x7UL<<9)
        #define PCI_DEVICE_CAPABILITY_ROLE_BASED_ERR_RPT    (1UL<<15)

    u32_t unused_3;
    u32_t pci_link_capability;
        #define PCI_LINK_CAPABILITY_MAX_LINK_SPEED          (0xfUL<<0)
            #define PCI_LINK_CAPABILITY_MAX_LINK_SPEED_0001  (1UL<<0)
            #define PCI_LINK_CAPABILITY_MAX_LINK_SPEED_0010  (2UL<<0)
        #define PCI_LINK_CAPABILITY_MAX_LINK_WIDTH          (0x1fUL<<4)
        #define PCI_LINK_CAPABILITY_CLK_POWER_MGMT          (1UL<<9)
        #define PCI_LINK_CAPABILITY_ASPM_SUPPORT            (0x3UL<<10)
        #define PCI_LINK_CAPABILITY_L0S_EXIT_LAT            (0x7UL<<12)
            #define PCI_LINK_CAPABILITY_L0S_EXIT_LAT_101    (5UL<<12)
            #define PCI_LINK_CAPABILITY_L0S_EXIT_LAT_110    (6UL<<12)
        #define PCI_LINK_CAPABILITY_L1_EXIT_LAT             (0x7UL<<15)
            #define PCI_LINK_CAPABILITY_L1_EXIT_LAT_001     (1UL<<15)
            #define PCI_LINK_CAPABILITY_L1_EXIT_LAT_010     (2UL<<15)
        #define PCI_LINK_CAPABILITY_L0S_EXIT_COMM_LAT       (0x7UL<<18)
            #define PCI_LINK_CAPABILITY_L0S_EXIT_COMM_LAT_101  (5UL<<18)
            #define PCI_LINK_CAPABILITY_L0S_EXIT_COMM_LAT_110  (6UL<<18)
        #define PCI_LINK_CAPABILITY_L1_EXIT_COMM_LAT        (0x7UL<<21)
            #define PCI_LINK_CAPABILITY_L1_EXIT_COMM_LAT_001  (1UL<<21)
            #define PCI_LINK_CAPABILITY_L1_EXIT_COMM_LAT_010  (2UL<<21)
        #define PCI_LINK_CAPABILITY_PORT_NUM                (0xffUL<<24)

    u32_t pci_bar2_config;
        #define PCI_BAR2_CONFIG_BAR2_SIZE                   (0xfUL<<0)
            #define PCI_BAR2_CONFIG_BAR2_SIZE_DISABLED      (0UL<<0)
            #define PCI_BAR2_CONFIG_BAR2_SIZE_64K           (1UL<<0)
            #define PCI_BAR2_CONFIG_BAR2_SIZE_128K          (2UL<<0)
            #define PCI_BAR2_CONFIG_BAR2_SIZE_256K          (3UL<<0)
            #define PCI_BAR2_CONFIG_BAR2_SIZE_512K          (4UL<<0)
            #define PCI_BAR2_CONFIG_BAR2_SIZE_1M            (5UL<<0)
            #define PCI_BAR2_CONFIG_BAR2_SIZE_2M            (6UL<<0)
            #define PCI_BAR2_CONFIG_BAR2_SIZE_4M            (7UL<<0)
            #define PCI_BAR2_CONFIG_BAR2_SIZE_8M            (8UL<<0)
            #define PCI_BAR2_CONFIG_BAR2_SIZE_16M           (9UL<<0)
            #define PCI_BAR2_CONFIG_BAR2_SIZE_32M           (10UL<<0)
            #define PCI_BAR2_CONFIG_BAR2_SIZE_64M           (11UL<<0)
            #define PCI_BAR2_CONFIG_BAR2_SIZE_128M          (12UL<<0)
            #define PCI_BAR2_CONFIG_BAR2_SIZE_256M          (13UL<<0)
            #define PCI_BAR2_CONFIG_BAR2_SIZE_512M          (14UL<<0)
            #define PCI_BAR2_CONFIG_BAR2_SIZE_1G            (15UL<<0)
        #define PCI_BAR2_CONFIG_BAR2_64ENA                  (1UL<<4)
        #define PCI_BAR2_CONFIG_BAR2_PREFETCH               (1UL<<5)
        #define PCI_BAR2_CONFIG_RESERVED                    (0x3ffffffUL<<6)

    u32_t pci_pcie_device_capability_2;
        #define PCI_PCIE_DEVICE_CAPABILITY_2_CMPL_TO_RANGE_SUPP  (0xfUL<<0)
        #define PCI_PCIE_DEVICE_CAPABILITY_2_CMPL_TO_DISABL_SUPP  (1UL<<4)
        #define PCI_PCIE_DEVICE_CAPABILITY_2_RESERVED       (0x7ffffffUL<<5)

    u32_t pci_pcie_link_capability_2;
        #define PCI_PCIE_LINK_CAPABILITY_2_RESERVED         (0xffffffffUL<<0)

    u32_t unused_4[5];
    u32_t pci_dev_ser_num_cap_id;
        #define PCI_DEV_SER_NUM_CAP_ID_CAP_ID               (0xffffUL<<0)
        #define PCI_DEV_SER_NUM_CAP_ID_CAP_VER              (0xfUL<<16)
        #define PCI_DEV_SER_NUM_CAP_ID_EXT_CAP_ENA          (0xfUL<<20)
            #define PCI_DEV_SER_NUM_CAP_ID_EXT_CAP_ENA_8    (8UL<<20)
            #define PCI_DEV_SER_NUM_CAP_ID_EXT_CAP_ENA_9    (9UL<<20)
            #define PCI_DEV_SER_NUM_CAP_ID_EXT_CAP_ENA_10   (10UL<<20)
            #define PCI_DEV_SER_NUM_CAP_ID_EXT_CAP_ENA_11   (11UL<<20)
            #define PCI_DEV_SER_NUM_CAP_ID_EXT_CAP_ENA_12   (12UL<<20)
            #define PCI_DEV_SER_NUM_CAP_ID_EXT_CAP_ENA_13   (13UL<<20)
            #define PCI_DEV_SER_NUM_CAP_ID_EXT_CAP_ENA_14   (14UL<<20)
            #define PCI_DEV_SER_NUM_CAP_ID_EXT_CAP_ENA_15   (15UL<<20)

    u32_t pci_lower_ser_num;
        #define PCI_LOWER_SER_NUM_LOWER_SER_NUM             (0xffffffffUL<<0)

    u32_t pci_upper_ser_num;
        #define PCI_UPPER_SER_NUM_UPPER_SER_NUM             (0xffffffffUL<<0)

    u32_t pci_adv_err_cap;
        #define PCI_ADV_ERR_CAP_ECRC_CHK_CAP                (1UL<<0)
        #define PCI_ADV_ERR_CAP_ECRC_GEN_CAP                (1UL<<1)

    u32_t pci_pwr_bdgt_data_0;
        #define PCI_PWR_BDGT_DATA_0_PWR_BDGT_DATA_0         (0x1fffffUL<<0)
        #define PCI_PWR_BDGT_DATA_0_RESERVED                (0x7ffUL<<21)

    u32_t pci_pwr_bdgt_data_1;
        #define PCI_PWR_BDGT_DATA_1_PWR_BDGT_DATA_1         (0x1fffffUL<<0)
        #define PCI_PWR_BDGT_DATA_1_RW                      (0x7ffUL<<21)

    u32_t pci_pwr_bdgt_data_2;
        #define PCI_PWR_BDGT_DATA_2_PWR_BDGT_DATA_2         (0x1fffffUL<<0)
        #define PCI_PWR_BDGT_DATA_2_RW                      (0x7ffUL<<21)

    u32_t pci_pwd_bdgt_data_3;
        #define PCI_PWD_BDGT_DATA_3_PWR_BDGT_DATA_3         (0x1fffffUL<<0)
        #define PCI_PWD_BDGT_DATA_3_RW                      (0x7ffUL<<21)

    u32_t pci_pwr_bdgt_data_4;
        #define PCI_PWR_BDGT_DATA_4_PWR_BDGT_DATA_4         (0x1fffffUL<<0)
        #define PCI_PWR_BDGT_DATA_4_RW                      (0x7ffUL<<21)

    u32_t pci_pwr_bdgt_data_5;
        #define PCI_PWR_BDGT_DATA_5_PWR_BDGT_DATA_5         (0x1fffffUL<<0)
        #define PCI_PWR_BDGT_DATA_5_RW                      (0x7ffUL<<21)

    u32_t pci_pwr_bdgt_data_6;
        #define PCI_PWR_BDGT_DATA_6_PWR_BDGT_DATA_6         (0x1fffffUL<<0)
        #define PCI_PWR_BDGT_DATA_6_RW                      (0x7ffUL<<21)

    u32_t pci_pwr_bdgt_data_7;
        #define PCI_PWR_BDGT_DATA_7_PWR_BDGT_DATA_7         (0x1fffffUL<<0)
        #define PCI_PWR_BDGT_DATA_7_RW                      (0x7ffUL<<21)

    u32_t unused_5[8];
    u32_t pci_pwr_bdgt_capability_ctl;
        #define PCI_PWR_BDGT_CAPABILITY_CTL_PWR_SYSTEM_ALLOC  (1UL<<0)
        #define PCI_PWR_BDGT_CAPABILITY_CTL_RESERVED        (0x7fffffffUL<<1)

    u32_t unused_6[47];
    u32_t pci_grc_window1_addr;
        #define PCI_GRC_WINDOW1_ADDR_VALUE                  (0x1ffUL<<13)

    u32_t pci_grc_window2_addr;
        #define PCI_GRC_WINDOW2_ADDR_VALUE                  (0x1ffUL<<13)

    u32_t pci_grc_window3_addr;
        #define PCI_GRC_WINDOW3_ADDR_VALUE                  (0x1ffUL<<13)

    u32_t unused_7[9];
    u32_t pci_exp_rom_adr;
        #define PCI_EXP_ROM_ADR_ADDRESS                     (0x3fffffUL<<2)
        #define PCI_EXP_ROM_ADR_ADDR_SIZE                   (0x3UL<<24)
        #define PCI_EXP_ROM_ADR_REQ                         (1UL<<31)

    u32_t pci_exp_rom_data0;
    u32_t pci_exp_rom_data1;
    u32_t pci_exp_rom_data2;
    u32_t pci_exp_rom_ctrl;
        #define PCI_EXP_ROM_CTRL_ENA                        (1UL<<0)
        #define PCI_EXP_ROM_CTRL_BFRD                       (1UL<<1)
        #define PCI_EXP_ROM_CTRL_ARB_NUM                    (0x3UL<<4)
        #define PCI_EXP_ROM_CTRL_STATE                      (0xfUL<<16)
        #define PCI_EXP_ROM_CTRL_CACHE_VALID                (1UL<<28)
        #define PCI_EXP_ROM_CTRL_ARB_TIMEOUT                (1UL<<29)
        #define PCI_EXP_ROM_CTRL_READ_TIMEOUT               (1UL<<30)
        #define PCI_EXP_ROM_CTRL_ACTIVE                     (1UL<<31)

    u32_t pci_exp_rom_baddr;
        #define PCI_EXP_ROM_BADDR_VALUE                     (0x3fffffUL<<2)

    u32_t pci_exp_rom_cfg;
        #define PCI_EXP_ROM_CFG_ARB_TIMEOUT_SHFT            (0xfUL<<0)
        #define PCI_EXP_ROM_CFG_READ_TIMEOUT_SHFT           (0xfUL<<4)

    u32_t unused_8[41];
    u32_t pci_debug_vect_peek;
        #define PCI_DEBUG_VECT_PEEK_1_VALUE                 (0x7ffUL<<0)
        #define PCI_DEBUG_VECT_PEEK_1_EN                    (1UL<<11)
        #define PCI_DEBUG_VECT_PEEK_1_SEL                   (0xfUL<<12)
        #define PCI_DEBUG_VECT_PEEK_2_VALUE                 (0x7ffUL<<16)
        #define PCI_DEBUG_VECT_PEEK_2_EN                    (1UL<<27)
        #define PCI_DEBUG_VECT_PEEK_2_SEL                   (0xfUL<<28)

    u32_t unused_9[63];
} pci_reg_t;


/*
 *  pcie_reg definition
 *  offset: 0x300000
 */
typedef struct pcie_reg
{
    u16_t pci1_cfg_device_id;
    u16_t pci1_cfg_vendor_id;
    u16_t pci1_cfg_status;
        #define PCI1_CFG_STATUS_RESERVED1                   (0x7<<0)
        #define PCI1_CFG_STATUS_INT_STATUS                  (1<<3)
        #define PCI1_CFG_STATUS_CAP_LIST                    (1<<4)
        #define PCI1_CFG_STATUS_66MHZ_CAP                   (1<<5)
        #define PCI1_CFG_STATUS_RESERVED2                   (1<<6)
        #define PCI1_CFG_STATUS_FAST_B2B_CAP                (1<<7)
        #define PCI1_CFG_STATUS_MSTR_PERR                   (1<<8)
        #define PCI1_CFG_STATUS_DEVSEL_TIMING               (0x3<<9)
        #define PCI1_CFG_STATUS_SIG_TGT_ABT                 (1<<11)
        #define PCI1_CFG_STATUS_RCV_TGT_ABT                 (1<<12)
        #define PCI1_CFG_STATUS_RCV_MSTR_ABT                (1<<13)
        #define PCI1_CFG_STATUS_SIG_SERR                    (1<<14)
        #define PCI1_CFG_STATUS_PAR_ERR                     (1<<15)

    u16_t pci1_cfg_command;
        #define PCI1_CFG_COMMAND_IO_SPACE                   (1<<0)
        #define PCI1_CFG_COMMAND_MEM_SPACE                  (1<<1)
        #define PCI1_CFG_COMMAND_BUS_MASTER                 (1<<2)
        #define PCI1_CFG_COMMAND_SPECIAL_CYCLES             (1<<3)
        #define PCI1_CFG_COMMAND_MWI_CYCLES                 (1<<4)
        #define PCI1_CFG_COMMAND_VGA_SNOOP                  (1<<5)
        #define PCI1_CFG_COMMAND_PERR_ENA                   (1<<6)
        #define PCI1_CFG_COMMAND_STEPPING                   (1<<7)
        #define PCI1_CFG_COMMAND_SERR_ENA                   (1<<8)
        #define PCI1_CFG_COMMAND_FAST_B2B                   (1<<9)
        #define PCI1_CFG_COMMAND_INT_DISABLE                (1<<10)
        #define PCI1_CFG_COMMAND_RESERVED                   (0x1f<<11)

    u32_t pci1_cfg_class_code;
        #define PCI1_CFG_CLASS_CODE_REV_ID                  (0xffUL<<0)
        #define PCI1_CFG_CLASS_CODE_VALUE                   (0xffffffUL<<8)

    u8_t pci1_cfg_bist;
    u8_t pci1_cfg_header_type;
    u8_t pci1_cfg_latency_timer;
    u8_t pci1_cfg_cache_line_size;
    u32_t pci1_cfg_bar_1;
        #define PCI1_CFG_BAR_1_MEM_SPACE                    (1UL<<0)
        #define PCI1_CFG_BAR_1_SPACE_TYPE                   (0x3UL<<1)
        #define PCI1_CFG_BAR_1_PREFETCH                     (1UL<<3)
        #define PCI1_CFG_BAR_1_ADDRESS                      (0xfffffffUL<<4)

    u32_t pci1_cfg_bar_2;
        #define PCI1_CFG_BAR_2_ADDR                         (0xffffffffUL<<0)

    u32_t pci1_cfg_bar_3;
        #define PCI1_CFG_BAR_3_MEM_SPACE                    (1UL<<0)
        #define PCI1_CFG_BAR_3_SPACE_TYPE                   (0x3UL<<1)
        #define PCI1_CFG_BAR_3_PREFETCH                     (1UL<<3)
        #define PCI1_CFG_BAR_3_ADDRESS                      (0xfffffffUL<<4)

    u32_t pci1_cfg_bar_4;
        #define PCI1_CFG_BAR_4_ADDR                         (0xffffffffUL<<0)

    u32_t pci1_cfg_bar_5;
    u32_t pci1_cfg_bar_6;
    u32_t pci1_cfg_cardbus_cis;
    u16_t pci1_cfg_subsystem_id;
    u16_t pci1_cfg_subsystem_vendor_id;
    u32_t pci1_cfg_exp_rom_bar;
        #define PCI1_CFG_EXP_ROM_BAR_BAR_ENA                (1UL<<0)
        #define PCI1_CFG_EXP_ROM_BAR_LOW                    (0x3ffUL<<1)
        #define PCI1_CFG_EXP_ROM_BAR_SIZE                   (0x1fffUL<<11)
        #define PCI1_CFG_EXP_ROM_BAR_ADDRESS                (0xffUL<<24)

    u16_t unused_0;
    u8_t unused_1;
    u8_t pci1_cfg_cap_pointer;
    u32_t unused_2;
    u8_t pci1_cfg_maximum_latency;
    u8_t pci1_cfg_min_grant;
    u8_t pci1_cfg_int_pin;
    u8_t pci1_cfg_int_line;
    u32_t unused_3[2];
    u16_t pci1_cfg_pm_capability;
        #define PCI1_CFG_PM_CAPABILITY_VERSION              (0x3<<0)
        #define PCI1_CFG_PM_CAPABILITY_CLOCK                (1<<3)
        #define PCI1_CFG_PM_CAPABILITY_RESERVED             (1<<4)
        #define PCI1_CFG_PM_CAPABILITY_DSI                  (1<<5)
        #define PCI1_CFG_PM_CAPABILITY_AUX_CURRENT          (0x7<<6)
        #define PCI1_CFG_PM_CAPABILITY_D1_SUPPORT           (1<<9)
        #define PCI1_CFG_PM_CAPABILITY_D2_SUPPORT           (1<<10)
        #define PCI1_CFG_PM_CAPABILITY_PME_IN_D0            (1<<11)
        #define PCI1_CFG_PM_CAPABILITY_PME_IN_D1            (1<<12)
        #define PCI1_CFG_PM_CAPABILITY_PME_IN_D2            (1<<13)
        #define PCI1_CFG_PM_CAPABILITY_PME_IN_D3_HOT        (1<<14)
        #define PCI1_CFG_PM_CAPABILITY_PME_IN_D3_COLD       (1<<15)

    u8_t pci1_cfg_pm_next_cap_ptr;
    u8_t pci1_cfg_pm_cap_id;
    u8_t pci1_cfg_pm_data;
    u8_t pci1_cfg_pm_csr_bse;
    u16_t pci1_cfg_pm_csr;
        #define PCI1_CFG_PM_CSR_STATE                       (0x3<<0)
            #define PCI1_CFG_PM_CSR_STATE_D0                (0<<0)
            #define PCI1_CFG_PM_CSR_STATE_D1                (1<<0)
            #define PCI1_CFG_PM_CSR_STATE_D2                (2<<0)
            #define PCI1_CFG_PM_CSR_STATE_D3_HOT            (3<<0)
        #define PCI1_CFG_PM_CSR_RESERVED0                   (1<<2)
        #define PCI1_CFG_PM_CSR_NO_SOFT_RESET               (1<<3)
        #define PCI1_CFG_PM_CSR_RESERVED1                   (0xf<<4)
        #define PCI1_CFG_PM_CSR_PME_ENABLE                  (1<<8)
        #define PCI1_CFG_PM_CSR_DATA_SEL                    (0xf<<9)
            #define PCI1_CFG_PM_CSR_DATA_SEL_0              (0<<9)
            #define PCI1_CFG_PM_CSR_DATA_SEL_1              (1<<9)
            #define PCI1_CFG_PM_CSR_DATA_SEL_2              (2<<9)
            #define PCI1_CFG_PM_CSR_DATA_SEL_3              (3<<9)
            #define PCI1_CFG_PM_CSR_DATA_SEL_4              (4<<9)
            #define PCI1_CFG_PM_CSR_DATA_SEL_5              (5<<9)
            #define PCI1_CFG_PM_CSR_DATA_SEL_6              (6<<9)
            #define PCI1_CFG_PM_CSR_DATA_SEL_7              (7<<9)
        #define PCI1_CFG_PM_CSR_DATA_SCALE                  (0x3<<13)
            #define PCI1_CFG_PM_CSR_DATA_SCALE_0            (0<<13)
            #define PCI1_CFG_PM_CSR_DATA_SCALE_1            (1<<13)
            #define PCI1_CFG_PM_CSR_DATA_SCALE_2            (2<<13)
            #define PCI1_CFG_PM_CSR_DATA_SCALE_3            (3<<13)
        #define PCI1_CFG_PM_CSR_PME_STATUS                  (1<<15)

    u16_t pci1_cfg_vpd_flag_addr;
        #define PCI1_CFG_VPD_FLAG_ADDR_ADDRESS              (0x1fff<<2)
        #define PCI1_CFG_VPD_FLAG_ADDR_FLAG                 (1<<15)

    u8_t pci1_cfg_vpd_next_cap_ptr;
    u8_t pci1_cfg_vpd_cap_id;
    u32_t pci1_cfg_vpd_data;
    u16_t pci1_cfg_msi_control;
        #define PCI1_CFG_MSI_CONTROL_ENABLE                 (1<<0)
        #define PCI1_CFG_MSI_CONTROL_MCAP                   (0x7<<1)
            #define PCI1_CFG_MSI_CONTROL_MCAP_1             (0<<1)
            #define PCI1_CFG_MSI_CONTROL_MCAP_2             (1<<1)
            #define PCI1_CFG_MSI_CONTROL_MCAP_4             (2<<1)
            #define PCI1_CFG_MSI_CONTROL_MCAP_8             (3<<1)
            #define PCI1_CFG_MSI_CONTROL_MCAP_16            (4<<1)
            #define PCI1_CFG_MSI_CONTROL_MCAP_32            (5<<1)
        #define PCI1_CFG_MSI_CONTROL_MENA                   (0x7<<4)
            #define PCI1_CFG_MSI_CONTROL_MENA_1             (0<<4)
            #define PCI1_CFG_MSI_CONTROL_MENA_2             (1<<4)
            #define PCI1_CFG_MSI_CONTROL_MENA_4             (2<<4)
            #define PCI1_CFG_MSI_CONTROL_MENA_8             (3<<4)
            #define PCI1_CFG_MSI_CONTROL_MENA_16            (4<<4)
            #define PCI1_CFG_MSI_CONTROL_MENA_32            (5<<4)
        #define PCI1_CFG_MSI_CONTROL_64_BIT_ADDR_CAP        (1<<7)
        #define PCI1_CFG_MSI_CONTROL_MSI_PVMASK_CAPABLE     (1<<8)

    u8_t pci1_cfg_msi_next_cap_ptr;
    u8_t pci1_cfg_msi_cap_id;
    u32_t pci1_cfg_msi_addr_l;
        #define PCI1_CFG_MSI_ADDR_L_VAL                     (0x3fffffffUL<<2)

    u32_t pci1_cfg_msi_addr_h;
    u16_t unused_4;
    u16_t pci1_cfg_msi_data;
    u32_t pci1_cfg_misc_config;
        #define PCI1_CFG_MISC_CONFIG_TARGET_BYTE_SWAP       (1UL<<2)
        #define PCI1_CFG_MISC_CONFIG_TARGET_MB_WORD_SWAP    (1UL<<3)
        #define PCI1_CFG_MISC_CONFIG_TARGET_GRC_WORD_SWAP   (1UL<<6)
        #define PCI1_CFG_MISC_CONFIG_REG_WINDOW_ENA         (1UL<<7)
        #define PCI1_CFG_MISC_CONFIG_GRC_WIN1_SWAP_EN       (1UL<<10)
        #define PCI1_CFG_MISC_CONFIG_GRC_WIN2_SWAP_EN       (1UL<<11)
        #define PCI1_CFG_MISC_CONFIG_GRC_WIN3_SWAP_EN       (1UL<<12)
        #define PCI1_CFG_MISC_CONFIG_ASIC_METAL_REV         (0xffUL<<16)
        #define PCI1_CFG_MISC_CONFIG_ASIC_BASE_REV          (0xfUL<<24)
        #define PCI1_CFG_MISC_CONFIG_ASIC_ID                (0xfUL<<28)

    u32_t pci1_cfg_misc_status;
        #define PCI1_CFG_MISC_STATUS_INTA_VALUE             (1UL<<0)
        #define PCI1_CFG_MISC_STATUS_BAD_MEM_WRITE_BE       (1UL<<8)

    u32_t unused_5[2];
    u32_t pci1_cfg_reg_window_address;
    u32_t unused_6;
    u32_t pci1_cfg_reg_window;
    u32_t pci1_cfg_int_ack_cmd;
        #define PCI1_CFG_INT_ACK_CMD_INDEX                  (0xffffUL<<0)
        #define PCI1_CFG_INT_ACK_CMD_INDEX_VALID            (1UL<<16)
        #define PCI1_CFG_INT_ACK_CMD_USE_INT_HC_PARAM       (1UL<<17)
        #define PCI1_CFG_INT_ACK_CMD_MASK_INT               (1UL<<18)
        #define PCI1_CFG_INT_ACK_CMD_INTERRUPT_NUM          (0xfUL<<24)

    u32_t pci1_cfg_status_bit_set_cmd;
    u32_t pci1_cfg_status_bit_clear_cmd;
    u32_t pci1_cfg_mailbox_queue_addr;
    u32_t pci1_cfg_mailbox_queue_data;
    u32_t unused_7[2];
    u16_t pci1_cfg_msix_control;
        #define PCI1_CFG_MSIX_CONTROL_TABLE_SIZE            (0x7ff<<0)
        #define PCI1_CFG_MSIX_CONTROL_RESERVED              (0x7<<11)
        #define PCI1_CFG_MSIX_CONTROL_FUNC_MASK             (1<<14)
        #define PCI1_CFG_MSIX_CONTROL_MSIX_ENABLE           (1<<15)

    u8_t pci1_cfg_msix_next_cap_ptr;
    u8_t pci1_cfg_msix_cap_id;
    u32_t pci1_cfg_msix_tbl_off_bir;
        #define PCI1_CFG_MSIX_TBL_OFF_BIR_TABLE_BIR         (0x7UL<<0)
        #define PCI1_CFG_MSIX_TBL_OFF_BIR_TABLE_OFFSET      (0x1fffffffUL<<3)

    u32_t pci1_cfg_msix_pba_off_bir;
        #define PCI1_CFG_MSIX_PBA_OFF_BIR_PBA_BIR           (0x7UL<<0)
        #define PCI1_CFG_MSIX_PBA_OFF_BIR_PBA_OFFSET        (0x1fffffffUL<<3)

    u16_t pci1_cfg_pcie_capability;
        #define PCI1_CFG_PCIE_CAPABILITY_VER                (0xf<<0)
        #define PCI1_CFG_PCIE_CAPABILITY_TYPE               (0xf<<4)

    u8_t pci1_cfg_pcie_next_cap_ptr;
    u8_t pci1_cfg_pcie_cap_id;
    u32_t pci1_cfg_device_capability;
        #define PCI1_CFG_DEVICE_CAPABILITY_MAX_PAYLOAD      (0x7UL<<0)
        #define PCI1_CFG_DEVICE_CAPABILITY_PHANTOM_SUPPT    (0x3UL<<3)
        #define PCI1_CFG_DEVICE_CAPABILITY_EXT_TAG_SUPPT    (1UL<<5)
        #define PCI1_CFG_DEVICE_CAPABILITY_EP_L0S_ACCP_LAT  (0x7UL<<6)
        #define PCI1_CFG_DEVICE_CAPABILITY_EP_L1_ACCP_LAT   (0x7UL<<9)

    u16_t pci1_cfg_device_status;
        #define PCI1_CFG_DEVICE_STATUS_CORR_ERR_DET         (1<<0)
        #define PCI1_CFG_DEVICE_STATUS_NON_FATAL_ERR_DET    (1<<1)
        #define PCI1_CFG_DEVICE_STATUS_FATAL_ERR_DET        (1<<2)
        #define PCI1_CFG_DEVICE_STATUS_UNSUP_REQ_DET        (1<<3)
        #define PCI1_CFG_DEVICE_STATUS_AUX_PWR_DET          (1<<4)
        #define PCI1_CFG_DEVICE_STATUS_NO_PEND              (1<<5)

    u16_t pci1_cfg_device_control;
        #define PCI1_CFG_DEVICE_CONTROL_CORR_ERR_REP_ENA    (1<<0)
        #define PCI1_CFG_DEVICE_CONTROL_NON_FATAL_REP_ENA   (1<<1)
        #define PCI1_CFG_DEVICE_CONTROL_FATAL_REP_ENA       (1<<2)
        #define PCI1_CFG_DEVICE_CONTROL_UNSUP_REQ_ENA       (1<<3)
        #define PCI1_CFG_DEVICE_CONTROL_RELAX_ENA           (1<<4)
        #define PCI1_CFG_DEVICE_CONTROL_MAX_PAYLOAD         (0x7<<5)
        #define PCI1_CFG_DEVICE_CONTROL_EXT_TAG_ENA         (1<<8)
        #define PCI1_CFG_DEVICE_CONTROL_AUX_PWR_PM_ENA      (1<<10)
        #define PCI1_CFG_DEVICE_CONTROL_ENA_NO_SNOOP        (1<<11)
        #define PCI1_CFG_DEVICE_CONTROL_MAX_RD_REQ          (0x7<<12)

    u32_t pci1_cfg_link_capability;
        #define PCI1_CFG_LINK_CAPABILITY_MAX_LINK_SPEED     (0xfUL<<0)
            #define PCI1_CFG_LINK_CAPABILITY_MAX_LINK_SPEED_2_5  (1UL<<0)
            #define PCI1_CFG_LINK_CAPABILITY_MAX_LINK_SPEED_5  (2UL<<0)
        #define PCI1_CFG_LINK_CAPABILITY_MAX_LINK_WIDTH     (0x3fUL<<4)
            #define PCI1_CFG_LINK_CAPABILITY_MAX_LINK_WIDTH_1  (1UL<<4)
            #define PCI1_CFG_LINK_CAPABILITY_MAX_LINK_WIDTH_2  (2UL<<4)
            #define PCI1_CFG_LINK_CAPABILITY_MAX_LINK_WIDTH_4  (4UL<<4)
            #define PCI1_CFG_LINK_CAPABILITY_MAX_LINK_WIDTH_8  (8UL<<4)
        #define PCI1_CFG_LINK_CAPABILITY_ASPM_SUPT          (0x3UL<<10)
            #define PCI1_CFG_LINK_CAPABILITY_ASPM_SUPT_RES_0  (0UL<<10)
            #define PCI1_CFG_LINK_CAPABILITY_ASPM_SUPT_L0S  (0UL<<10)
            #define PCI1_CFG_LINK_CAPABILITY_ASPM_SUPT_RES_2  (0UL<<10)
            #define PCI1_CFG_LINK_CAPABILITY_ASPM_SUPT_L0S_L1  (0UL<<10)
        #define PCI1_CFG_LINK_CAPABILITY_L0S_EXIT_LAT       (0x7UL<<12)
            #define PCI1_CFG_LINK_CAPABILITY_L0S_EXIT_LAT_1_2  (5UL<<12)
            #define PCI1_CFG_LINK_CAPABILITY_L0S_EXIT_LAT_2_4  (6UL<<12)
        #define PCI1_CFG_LINK_CAPABILITY_L1_EXIT_LAT        (0x7UL<<15)
            #define PCI1_CFG_LINK_CAPABILITY_L1_EXIT_LAT_1_2  (1UL<<15)
            #define PCI1_CFG_LINK_CAPABILITY_L1_EXIT_LAT_2_4  (2UL<<15)
        #define PCI1_CFG_LINK_CAPABILITY_CLK_PWR_MGMT       (1UL<<18)
        #define PCI1_CFG_LINK_CAPABILITY_PORT_NUMBER        (0xffUL<<24)

    u16_t pci1_cfg_link_status;
        #define PCI1_CFG_LINK_STATUS_SPEED                  (0xf<<0)
        #define PCI1_CFG_LINK_STATUS_NEG_LINK_WIDTH         (0x3f<<4)
        #define PCI1_CFG_LINK_STATUS_TRAINING_ERR           (1<<10)
        #define PCI1_CFG_LINK_STATUS_TRAINING               (1<<11)
        #define PCI1_CFG_LINK_STATUS_SLOT_CLK               (1<<12)

    u16_t pci1_cfg_link_control;
        #define PCI1_CFG_LINK_CONTROL_ASPM_CTRL             (0x3<<0)
        #define PCI1_CFG_LINK_CONTROL_RD_COMP_BOUND         (1<<3)
            #define PCI1_CFG_LINK_CONTROL_RD_COMP_BOUND_64  (0<<3)
            #define PCI1_CFG_LINK_CONTROL_RD_COMP_BOUND_128  (1<<3)
        #define PCI1_CFG_LINK_CONTROL_LINK_CR_COMMON_CLK    (1<<6)
        #define PCI1_CFG_LINK_CONTROL_LINK_CR_EXT_SYNC      (1<<7)

    u32_t pci1_cfg_slot_capability;
    u16_t pci1_cfg_slot_status;
    u16_t pci1_cfg_slot_control;
    u16_t pci1_cfg_root_cap;
    u16_t pci1_cfg_root_control;
    u32_t pci1_cfg_root_status;
    u32_t pci1_cfg_device_capability_2;
        #define PCI1_CFG_DEVICE_CAPABILITY_2_CMPL_TO_RANGE_SUPP  (0xfUL<<0)
            #define PCI1_CFG_DEVICE_CAPABILITY_2_CMPL_TO_RANGE_SUPP_ABCD  (15UL<<0)
        #define PCI1_CFG_DEVICE_CAPABILITY_2_CMPL_TO_DISABL_SUPP  (1UL<<4)

    u16_t pci1_cfg_device_status_2;
    u16_t pci1_cfg_device_control_2;
        #define PCI1_CFG_DEVICE_CONTROL_2_CMPL_TO_VALUE     (0xf<<0)
            #define PCI1_CFG_DEVICE_CONTROL_2_CMPL_TO_VALUE_50MS  (0<<0)
            #define PCI1_CFG_DEVICE_CONTROL_2_CMPL_TO_VALUE_100US  (1<<0)
            #define PCI1_CFG_DEVICE_CONTROL_2_CMPL_TO_VALUE_10MS  (2<<0)
            #define PCI1_CFG_DEVICE_CONTROL_2_CMPL_TO_VALUE_55MS  (3<<0)
            #define PCI1_CFG_DEVICE_CONTROL_2_CMPL_TO_VALUE_210MS  (4<<0)
            #define PCI1_CFG_DEVICE_CONTROL_2_CMPL_TO_VALUE_900MS  (5<<0)
            #define PCI1_CFG_DEVICE_CONTROL_2_CMPL_TO_VALUE_3_5S  (6<<0)
            #define PCI1_CFG_DEVICE_CONTROL_2_CMPL_TO_VALUE_13S  (7<<0)
            #define PCI1_CFG_DEVICE_CONTROL_2_CMPL_TO_VALUE_64S  (8<<0)
        #define PCI1_CFG_DEVICE_CONTROL_2_CMPL_TO_DISABLE   (1<<4)

    u32_t pci1_cfg_link_capability_2;
    u16_t pci1_cfg_link_status_2;
    u16_t pci1_cfg_link_control_2;
        #define PCI1_CFG_LINK_CONTROL_2_TARGET_LINK_SPEED   (0xf<<0)
            #define PCI1_CFG_LINK_CONTROL_2_TARGET_LINK_SPEED_2_5  (0<<0)
            #define PCI1_CFG_LINK_CONTROL_2_TARGET_LINK_SPEED_5_0  (1<<0)
        #define PCI1_CFG_LINK_CONTROL_2_ENTER_COMPLIANCE    (1<<4)
        #define PCI1_CFG_LINK_CONTROL_2_HW_AUTO_SPEED_DISABLE  (1<<5)
        #define PCI1_CFG_LINK_CONTROL_2_SEL_DEEMPHASIS      (1<<6)
            #define PCI1_CFG_LINK_CONTROL_2_SEL_DEEMPHASIS_0  (0<<6)
            #define PCI1_CFG_LINK_CONTROL_2_SEL_DEEMPHASIS_1  (1<<6)
        #define PCI1_CFG_LINK_CONTROL_2_TX_MARGIN           (0x7<<7)
            #define PCI1_CFG_LINK_CONTROL_2_TX_MARGIN_000   (0<<7)
            #define PCI1_CFG_LINK_CONTROL_2_TX_MARGIN_001   (1<<7)
            #define PCI1_CFG_LINK_CONTROL_2_TX_MARGIN_010   (2<<7)
            #define PCI1_CFG_LINK_CONTROL_2_TX_MARGIN_011   (3<<7)
            #define PCI1_CFG_LINK_CONTROL_2_TX_MARGIN_100   (4<<7)
            #define PCI1_CFG_LINK_CONTROL_2_TX_MARGIN_101   (5<<7)
            #define PCI1_CFG_LINK_CONTROL_2_TX_MARGIN_110   (6<<7)
            #define PCI1_CFG_LINK_CONTROL_2_TX_MARGIN_111   (7<<7)

    u32_t unused_8[8];
    u16_t pci1_cfg_device_ser_num_cap_off;
        #define PCI1_CFG_DEVICE_SER_NUM_CAP_OFF_VER         (0xf<<0)
        #define PCI1_CFG_DEVICE_SER_NUM_CAP_OFF_NEXT        (0xfff<<4)

    u16_t pci1_cfg_device_ser_num_cap_id;
    u32_t pci1_cfg_lower_ser_num;
    u32_t pci1_cfg_upper_ser_num;
    u32_t unused_9;
    u16_t pci1_cfg_adv_err_cap_off;
        #define PCI1_CFG_ADV_ERR_CAP_OFF_VER                (0xf<<0)
        #define PCI1_CFG_ADV_ERR_CAP_OFF_NEXT               (0xfff<<4)

    u16_t pci1_cfg_adv_err_cap_id;
    u32_t pci1_cfg_ucorr_err_status;
        #define PCI1_CFG_UCORR_ERR_STATUS_DLPES             (1UL<<4)
        #define PCI1_CFG_UCORR_ERR_STATUS_PTLPS             (1UL<<12)
        #define PCI1_CFG_UCORR_ERR_STATUS_FCPES             (1UL<<13)
        #define PCI1_CFG_UCORR_ERR_STATUS_CTS               (1UL<<14)
        #define PCI1_CFG_UCORR_ERR_STATUS_CAS               (1UL<<15)
        #define PCI1_CFG_UCORR_ERR_STATUS_UCS               (1UL<<16)
        #define PCI1_CFG_UCORR_ERR_STATUS_ROS               (1UL<<17)
        #define PCI1_CFG_UCORR_ERR_STATUS_MTLPS             (1UL<<18)
        #define PCI1_CFG_UCORR_ERR_STATUS_ECRCS             (1UL<<19)
        #define PCI1_CFG_UCORR_ERR_STATUS_URES              (1UL<<20)

    u32_t pci1_cfg_ucorr_err_mask;
        #define PCI1_CFG_UCORR_ERR_MASK_DLPEM               (1UL<<4)
        #define PCI1_CFG_UCORR_ERR_MASK_SDEM                (1UL<<5)
        #define PCI1_CFG_UCORR_ERR_MASK_PTLPM               (1UL<<12)
        #define PCI1_CFG_UCORR_ERR_MASK_FCPEM               (1UL<<13)
        #define PCI1_CFG_UCORR_ERR_MASK_CTM                 (1UL<<14)
        #define PCI1_CFG_UCORR_ERR_MASK_CAM                 (1UL<<15)
        #define PCI1_CFG_UCORR_ERR_MASK_UCM                 (1UL<<16)
        #define PCI1_CFG_UCORR_ERR_MASK_ROM                 (1UL<<17)
        #define PCI1_CFG_UCORR_ERR_MASK_MTLPM               (1UL<<18)
        #define PCI1_CFG_UCORR_ERR_MASK_ECRCEM              (1UL<<19)
        #define PCI1_CFG_UCORR_ERR_MASK_UREM                (1UL<<20)

    u32_t pci1_cfg_ucorr_err_sevr;
        #define PCI1_CFG_UCORR_ERR_SEVR_DLPES               (1UL<<4)
        #define PCI1_CFG_UCORR_ERR_SEVR_SDES                (1UL<<5)
        #define PCI1_CFG_UCORR_ERR_SEVR_PTLPS               (1UL<<12)
        #define PCI1_CFG_UCORR_ERR_SEVR_FCPES               (1UL<<13)
        #define PCI1_CFG_UCORR_ERR_SEVR_CTS                 (1UL<<14)
        #define PCI1_CFG_UCORR_ERR_SEVR_CAS                 (1UL<<15)
        #define PCI1_CFG_UCORR_ERR_SEVR_UCS                 (1UL<<16)
        #define PCI1_CFG_UCORR_ERR_SEVR_ROS                 (1UL<<17)
        #define PCI1_CFG_UCORR_ERR_SEVR_MTLPS               (1UL<<18)
        #define PCI1_CFG_UCORR_ERR_SEVR_ECRCES              (1UL<<19)
        #define PCI1_CFG_UCORR_ERR_SEVR_URES                (1UL<<20)

    u32_t pci1_cfg_corr_err_status;
        #define PCI1_CFG_CORR_ERR_STATUS_RES                (1UL<<0)
        #define PCI1_CFG_CORR_ERR_STATUS_BDLLPS             (1UL<<7)
        #define PCI1_CFG_CORR_ERR_STATUS_BTLPS              (1UL<<7)
        #define PCI1_CFG_CORR_ERR_STATUS_RNRS               (1UL<<8)
        #define PCI1_CFG_CORR_ERR_STATUS_RTTS               (1UL<<12)
        #define PCI1_CFG_CORR_ERR_STATUS_ANFS               (1UL<<13)

    u32_t pci1_cfg_corr_err_mask;
        #define PCI1_CFG_CORR_ERR_MASK_RES                  (1UL<<0)
        #define PCI1_CFG_CORR_ERR_MASK_BTLPS                (1UL<<6)
        #define PCI1_CFG_CORR_ERR_MASK_BDLLPS               (1UL<<7)
        #define PCI1_CFG_CORR_ERR_MASK_RNRS                 (1UL<<8)
        #define PCI1_CFG_CORR_ERR_MASK_RTTS                 (1UL<<12)
        #define PCI1_CFG_CORR_ERR_MASK_ANFM                 (1UL<<13)

    u32_t pci1_cfg_adv_err_cap_control;
        #define PCI1_CFG_ADV_ERR_CAP_CONTROL_FIRST_UERR_PTR  (0x1fUL<<0)
        #define PCI1_CFG_ADV_ERR_CAP_CONTROL_ECRCGCAP       (1UL<<5)
        #define PCI1_CFG_ADV_ERR_CAP_CONTROL_ECRCGEN        (1UL<<6)
        #define PCI1_CFG_ADV_ERR_CAP_CONTROL_ECRCCAP        (1UL<<7)
        #define PCI1_CFG_ADV_ERR_CAP_CONTROL_ECRCEN         (1UL<<8)

    u32_t pci1_cfg_header_log1;
    u32_t pci1_cfg_header_log2;
    u32_t pci1_cfg_header_log3;
    u32_t pci1_cfg_header_log4;
    u32_t unused_10[5];
    u16_t pci1_cfg_pwr_bdgt_cap_off;
        #define PCI1_CFG_PWR_BDGT_CAP_OFF_VER               (0xf<<0)
        #define PCI1_CFG_PWR_BDGT_CAP_OFF_NEXT              (0xfff<<4)

    u16_t pci1_cfg_pwr_bdgt_cap_id;
    u32_t pci1_cfg_pwr_bdgt_data_sel;
        #define PCI1_CFG_PWR_BDGT_DATA_SEL_DS_VALUE         (0xffUL<<0)
            #define PCI1_CFG_PWR_BDGT_DATA_SEL_DS_VALUE_0   (0UL<<0)
            #define PCI1_CFG_PWR_BDGT_DATA_SEL_DS_VALUE_1   (1UL<<0)
            #define PCI1_CFG_PWR_BDGT_DATA_SEL_DS_VALUE_2   (2UL<<0)
            #define PCI1_CFG_PWR_BDGT_DATA_SEL_DS_VALUE_3   (3UL<<0)
            #define PCI1_CFG_PWR_BDGT_DATA_SEL_DS_VALUE_4   (4UL<<0)
            #define PCI1_CFG_PWR_BDGT_DATA_SEL_DS_VALUE_5   (5UL<<0)
            #define PCI1_CFG_PWR_BDGT_DATA_SEL_DS_VALUE_6   (6UL<<0)
            #define PCI1_CFG_PWR_BDGT_DATA_SEL_DS_VALUE_7   (7UL<<0)

    u32_t pci1_cfg_pwr_bdgt_data;
        #define PCI1_CFG_PWR_BDGT_DATA_BASE_PWR             (0xffUL<<0)
        #define PCI1_CFG_PWR_BDGT_DATA_DSCALE               (0x3UL<<8)
        #define PCI1_CFG_PWR_BDGT_DATA_PM_STATE             (0x3UL<<13)
        #define PCI1_CFG_PWR_BDGT_DATA_TYPE                 (0x7UL<<15)
        #define PCI1_CFG_PWR_BDGT_DATA_RAIL                 (0x7UL<<18)

    u32_t pci1_cfg_pwr_bdgt_capability;
        #define PCI1_CFG_PWR_BDGT_CAPABILITY_PCIE_CFG_PB_CAP_SYS_ALLOC  (1UL<<0)

    u16_t pci1_cfg_vc_cap_off;
        #define PCI1_CFG_VC_CAP_OFF_VER                     (0xf<<0)
        #define PCI1_CFG_VC_CAP_OFF_NEXT                    (0xfff<<4)

    u16_t pci1_cfg_vc_cap_id;
    u32_t pci1_cfg_port_vc_capability;
    u32_t pci1_cfg_port_vc_capability2;
    u16_t pci1_cfg_port_vc_status;
    u16_t pci1_cfg_port_vc_control;
    u32_t pci1_cfg_port_arb_table;
    u32_t pci1_cfg_vc_rsrc_control;
        #define PCI1_CFG_VC_RSRC_CONTROL_TC_VC_MAP          (0xffUL<<0)
        #define PCI1_CFG_VC_RSRC_CONTROL_VC_ENABLE          (1UL<<31)

    u16_t pci1_cfg_vc_rsrc_status;
    u16_t pci1_cfg_rsvdp;
    u32_t unused_11[161];
    u32_t pci1_grc_window_addr;
        #define PCI1_GRC_WINDOW_ADDR_VALUE                  (0x1ffUL<<13)
        #define PCI1_GRC_WINDOW_ADDR_SEP_WIN                (1UL<<31)

    u32_t unused_12;
    u32_t pci1_config_2;
        #define PCI1_CONFIG_2_BAR1_SIZE                     (0xfUL<<0)
            #define PCI1_CONFIG_2_BAR1_SIZE_DISABLED        (0UL<<0)
            #define PCI1_CONFIG_2_BAR1_SIZE_64K             (1UL<<0)
            #define PCI1_CONFIG_2_BAR1_SIZE_128K            (2UL<<0)
            #define PCI1_CONFIG_2_BAR1_SIZE_256K            (3UL<<0)
            #define PCI1_CONFIG_2_BAR1_SIZE_512K            (4UL<<0)
            #define PCI1_CONFIG_2_BAR1_SIZE_1M              (5UL<<0)
            #define PCI1_CONFIG_2_BAR1_SIZE_2M              (6UL<<0)
            #define PCI1_CONFIG_2_BAR1_SIZE_4M              (7UL<<0)
            #define PCI1_CONFIG_2_BAR1_SIZE_8M              (8UL<<0)
            #define PCI1_CONFIG_2_BAR1_SIZE_16M             (9UL<<0)
            #define PCI1_CONFIG_2_BAR1_SIZE_32M             (10UL<<0)
            #define PCI1_CONFIG_2_BAR1_SIZE_64M             (11UL<<0)
            #define PCI1_CONFIG_2_BAR1_SIZE_128M            (12UL<<0)
            #define PCI1_CONFIG_2_BAR1_SIZE_256M            (13UL<<0)
            #define PCI1_CONFIG_2_BAR1_SIZE_512M            (14UL<<0)
            #define PCI1_CONFIG_2_BAR1_SIZE_1G              (15UL<<0)
        #define PCI1_CONFIG_2_BAR1_64ENA                    (1UL<<4)
        #define PCI1_CONFIG_2_EXP_ROM_RETRY                 (1UL<<5)
        #define PCI1_CONFIG_2_CFG_CYCLE_RETRY               (1UL<<6)
        #define PCI1_CONFIG_2_FIRST_CFG_DONE                (1UL<<7)
        #define PCI1_CONFIG_2_EXP_ROM_SIZE                  (0xffUL<<8)
            #define PCI1_CONFIG_2_EXP_ROM_SIZE_DISABLED     (0UL<<8)
            #define PCI1_CONFIG_2_EXP_ROM_SIZE_2K           (1UL<<8)
            #define PCI1_CONFIG_2_EXP_ROM_SIZE_4K           (2UL<<8)
            #define PCI1_CONFIG_2_EXP_ROM_SIZE_8K           (3UL<<8)
            #define PCI1_CONFIG_2_EXP_ROM_SIZE_16K          (4UL<<8)
            #define PCI1_CONFIG_2_EXP_ROM_SIZE_32K          (5UL<<8)
            #define PCI1_CONFIG_2_EXP_ROM_SIZE_64K          (6UL<<8)
            #define PCI1_CONFIG_2_EXP_ROM_SIZE_128K         (7UL<<8)
            #define PCI1_CONFIG_2_EXP_ROM_SIZE_256K         (8UL<<8)
            #define PCI1_CONFIG_2_EXP_ROM_SIZE_512K         (9UL<<8)
            #define PCI1_CONFIG_2_EXP_ROM_SIZE_1M           (10UL<<8)
            #define PCI1_CONFIG_2_EXP_ROM_SIZE_2M           (11UL<<8)
            #define PCI1_CONFIG_2_EXP_ROM_SIZE_4M           (12UL<<8)
            #define PCI1_CONFIG_2_EXP_ROM_SIZE_8M           (13UL<<8)
            #define PCI1_CONFIG_2_EXP_ROM_SIZE_16M          (14UL<<8)
            #define PCI1_CONFIG_2_EXP_ROM_SIZE_32M          (15UL<<8)
        #define PCI1_CONFIG_2_BAR_PREFETCH                  (1UL<<16)
        #define PCI1_CONFIG_2_RESERVED0                     (0x7fffUL<<17)

    u32_t pci1_config_3;
        #define PCI1_CONFIG_3_STICKY_BYTE                   (0xffUL<<0)
        #define PCI1_CONFIG_3_REG_STICKY_BYTE               (0xffUL<<8)
        #define PCI1_CONFIG_3_FORCE_PME                     (1UL<<24)
        #define PCI1_CONFIG_3_PME_STATUS                    (1UL<<25)
        #define PCI1_CONFIG_3_PME_ENABLE                    (1UL<<26)
        #define PCI1_CONFIG_3_PM_STATE                      (0x3UL<<27)
        #define PCI1_CONFIG_3_VAUX_PRESET                   (1UL<<30)
        #define PCI1_CONFIG_3_PCI_POWER                     (1UL<<31)

    u32_t pci1_pm_data_a;
        #define PCI1_PM_DATA_A_PM_DATA_0_PRG                (0xffUL<<0)
        #define PCI1_PM_DATA_A_PM_DATA_1_PRG                (0xffUL<<8)
        #define PCI1_PM_DATA_A_PM_DATA_2_PRG                (0xffUL<<16)
        #define PCI1_PM_DATA_A_PM_DATA_3_PRG                (0xffUL<<24)

    u32_t pci1_pm_data_b;
        #define PCI1_PM_DATA_B_PM_DATA_4_PRG                (0xffUL<<0)
        #define PCI1_PM_DATA_B_PM_DATA_5_PRG                (0xffUL<<8)
        #define PCI1_PM_DATA_B_PM_DATA_6_PRG                (0xffUL<<16)
        #define PCI1_PM_DATA_B_PM_DATA_7_PRG                (0xffUL<<24)

    u32_t pci1_swap_diag0;
    u32_t pci1_swap_diag1;
    u32_t unused_13[2];
    u32_t pci1_vpd_intf;
        #define PCI1_VPD_INTF_INTF_REQ                      (1UL<<0)

    u16_t unused_14;
    u16_t pci1_vpd_addr_flag;
        #define PCI1_VPD_ADDR_FLAG_ADDRESS                  (0x1fff<<2)
        #define PCI1_VPD_ADDR_FLAG_WR                       (1<<15)

    u32_t pci1_vpd_data;
    u32_t pci1_id_val1;
        #define PCI1_ID_VAL1_DEVICE_ID                      (0xffffUL<<0)
        #define PCI1_ID_VAL1_VENDOR_ID                      (0xffffUL<<16)

    u32_t pci1_id_val2;
        #define PCI1_ID_VAL2_SUBSYSTEM_VENDOR_ID            (0xffffUL<<0)
        #define PCI1_ID_VAL2_SUBSYSTEM_ID                   (0xffffUL<<16)

    u32_t pci1_id_val3;
        #define PCI1_ID_VAL3_CLASS_CODE                     (0xffffffUL<<0)
        #define PCI1_ID_VAL3_REVISION_ID                    (0xffUL<<24)

    u32_t pci1_id_val4;
        #define PCI1_ID_VAL4_CAP_ENA                        (0xfUL<<0)
            #define PCI1_ID_VAL4_CAP_ENA_0                  (0UL<<0)
            #define PCI1_ID_VAL4_CAP_ENA_1                  (1UL<<0)
            #define PCI1_ID_VAL4_CAP_ENA_2                  (2UL<<0)
            #define PCI1_ID_VAL4_CAP_ENA_3                  (3UL<<0)
            #define PCI1_ID_VAL4_CAP_ENA_4                  (4UL<<0)
            #define PCI1_ID_VAL4_CAP_ENA_5                  (5UL<<0)
            #define PCI1_ID_VAL4_CAP_ENA_6                  (6UL<<0)
            #define PCI1_ID_VAL4_CAP_ENA_7                  (7UL<<0)
            #define PCI1_ID_VAL4_CAP_ENA_8                  (8UL<<0)
            #define PCI1_ID_VAL4_CAP_ENA_9                  (9UL<<0)
            #define PCI1_ID_VAL4_CAP_ENA_10                 (10UL<<0)
            #define PCI1_ID_VAL4_CAP_ENA_11                 (11UL<<0)
            #define PCI1_ID_VAL4_CAP_ENA_12                 (12UL<<0)
            #define PCI1_ID_VAL4_CAP_ENA_13                 (13UL<<0)
            #define PCI1_ID_VAL4_CAP_ENA_14                 (14UL<<0)
            #define PCI1_ID_VAL4_CAP_ENA_15                 (15UL<<0)
        #define PCI1_ID_VAL4_PM_SCALE_PRG                   (0x3UL<<6)
            #define PCI1_ID_VAL4_PM_SCALE_PRG_0             (0UL<<6)
            #define PCI1_ID_VAL4_PM_SCALE_PRG_1             (1UL<<6)
            #define PCI1_ID_VAL4_PM_SCALE_PRG_2             (2UL<<6)
            #define PCI1_ID_VAL4_PM_SCALE_PRG_3             (3UL<<6)
        #define PCI1_ID_VAL4_MSI_PV_MASK_CAP                (1UL<<8)
        #define PCI1_ID_VAL4_MSI_LIMIT                      (0x7UL<<9)
        #define PCI1_ID_VAL4_MULTI_MSG_CAP                  (0x7UL<<12)
        #define PCI1_ID_VAL4_MSI_ENABLE                     (1UL<<15)
        #define PCI1_ID_VAL4_RESERVED3                      (0xffffUL<<16)

    u32_t pci1_id_val5;
        #define PCI1_ID_VAL5_D1_SUPPORT                     (1UL<<0)
        #define PCI1_ID_VAL5_D2_SUPPORT                     (1UL<<1)
        #define PCI1_ID_VAL5_PME_IN_D0                      (1UL<<2)
        #define PCI1_ID_VAL5_PME_IN_D1                      (1UL<<3)
        #define PCI1_ID_VAL5_PME_IN_D2                      (1UL<<4)
        #define PCI1_ID_VAL5_PME_IN_D3_HOT                  (1UL<<5)
        #define PCI1_ID_VAL5_PM_VERSION                     (0x7UL<<6)
        #define PCI1_ID_VAL5_NO_SOFT_RESET                  (1UL<<9)
        #define PCI1_ID_VAL5_RESERVED0                      (0x3fffffUL<<10)

    u32_t unused_15;
    u32_t pci1_id_val6;
        #define PCI1_ID_VAL6_BIST                           (0xffUL<<16)

    u32_t pci1_msi_data;
        #define PCI1_MSI_DATA_MSI_DATA                      (0xffffUL<<0)

    u32_t pci1_msi_addr_h;
    u32_t pci1_msi_addr_l;
        #define PCI1_MSI_ADDR_L_VAL                         (0x3fffffffUL<<2)

    u32_t unused_16[2];
    u32_t pci1_msi_mask;
        #define PCI1_MSI_MASK_MSI_MASK                      (0xffffffffUL<<0)

    u32_t pci1_msi_pend;
        #define PCI1_MSI_PEND_MSI_PEND                      (0xffffffffUL<<0)

    u32_t pci1_pm_data_c;
        #define PCI1_PM_DATA_C_PM_DATA_8_PRG                (0xffUL<<0)
        #define PCI1_PM_DATA_C_RESERVED0                    (0xffffffUL<<8)

    u32_t unused_17[20];
    u32_t pci1_msix_control;
        #define PCI1_MSIX_CONTROL_MSIX_TBL_SIZ              (0x7ffUL<<0)
        #define PCI1_MSIX_CONTROL_RESERVED0                 (0x1fffffUL<<11)

    u32_t pci1_msix_tbl_off_bir;
        #define PCI1_MSIX_TBL_OFF_BIR_MSIX_TBL_BIR          (0x7UL<<0)
        #define PCI1_MSIX_TBL_OFF_BIR_MSIX_TBL_OFF          (0x1fffffffUL<<3)

    u32_t pci1_msix_pba_off_bit;
        #define PCI1_MSIX_PBA_OFF_BIT_MSIX_PBA_BIR          (0x7UL<<0)
        #define PCI1_MSIX_PBA_OFF_BIT_MSIX_PBA_OFF          (0x1fffffffUL<<3)

    u32_t unused_18;
    u32_t pci1_pcie_capability;
        #define PCI1_PCIE_CAPABILITY_INTERRUPT_MSG_NUM      (0x1fUL<<0)
        #define PCI1_PCIE_CAPABILITY_COMPLY_PCIE_1_1        (1UL<<5)

    u32_t pci1_device_capability;
        #define PCI1_DEVICE_CAPABILITY_MAX_PL_SIZ_SUPPORTED  (0x7UL<<0)
        #define PCI1_DEVICE_CAPABILITY_EXTENDED_TAG_SUPPORT  (1UL<<5)
        #define PCI1_DEVICE_CAPABILITY_L0S_ACCEPTABLE_LATENCY  (0x7UL<<6)
        #define PCI1_DEVICE_CAPABILITY_L1_ACCEPTABLE_LATENCY  (0x7UL<<9)
        #define PCI1_DEVICE_CAPABILITY_ROLE_BASED_ERR_RPT   (1UL<<15)

    u32_t unused_19;
    u32_t pci1_link_capability;
        #define PCI1_LINK_CAPABILITY_MAX_LINK_SPEED         (0xfUL<<0)
            #define PCI1_LINK_CAPABILITY_MAX_LINK_SPEED_0001  (1UL<<0)
            #define PCI1_LINK_CAPABILITY_MAX_LINK_SPEED_0010  (2UL<<0)
        #define PCI1_LINK_CAPABILITY_MAX_LINK_WIDTH         (0x1fUL<<4)
        #define PCI1_LINK_CAPABILITY_CLK_POWER_MGMT         (1UL<<9)
        #define PCI1_LINK_CAPABILITY_ASPM_SUPPORT           (0x3UL<<10)
        #define PCI1_LINK_CAPABILITY_L0S_EXIT_LAT           (0x7UL<<12)
            #define PCI1_LINK_CAPABILITY_L0S_EXIT_LAT_101   (5UL<<12)
            #define PCI1_LINK_CAPABILITY_L0S_EXIT_LAT_110   (6UL<<12)
        #define PCI1_LINK_CAPABILITY_L1_EXIT_LAT            (0x7UL<<15)
            #define PCI1_LINK_CAPABILITY_L1_EXIT_LAT_001    (1UL<<15)
            #define PCI1_LINK_CAPABILITY_L1_EXIT_LAT_010    (2UL<<15)
        #define PCI1_LINK_CAPABILITY_L0S_EXIT_COMM_LAT      (0x7UL<<18)
            #define PCI1_LINK_CAPABILITY_L0S_EXIT_COMM_LAT_101  (5UL<<18)
            #define PCI1_LINK_CAPABILITY_L0S_EXIT_COMM_LAT_110  (6UL<<18)
        #define PCI1_LINK_CAPABILITY_L1_EXIT_COMM_LAT       (0x7UL<<21)
            #define PCI1_LINK_CAPABILITY_L1_EXIT_COMM_LAT_001  (1UL<<21)
            #define PCI1_LINK_CAPABILITY_L1_EXIT_COMM_LAT_010  (2UL<<21)
        #define PCI1_LINK_CAPABILITY_PORT_NUM               (0xffUL<<24)

    u32_t pci1_bar2_config;
        #define PCI1_BAR2_CONFIG_BAR2_SIZE                  (0xfUL<<0)
            #define PCI1_BAR2_CONFIG_BAR2_SIZE_DISABLED     (0UL<<0)
            #define PCI1_BAR2_CONFIG_BAR2_SIZE_64K          (1UL<<0)
            #define PCI1_BAR2_CONFIG_BAR2_SIZE_128K         (2UL<<0)
            #define PCI1_BAR2_CONFIG_BAR2_SIZE_256K         (3UL<<0)
            #define PCI1_BAR2_CONFIG_BAR2_SIZE_512K         (4UL<<0)
            #define PCI1_BAR2_CONFIG_BAR2_SIZE_1M           (5UL<<0)
            #define PCI1_BAR2_CONFIG_BAR2_SIZE_2M           (6UL<<0)
            #define PCI1_BAR2_CONFIG_BAR2_SIZE_4M           (7UL<<0)
            #define PCI1_BAR2_CONFIG_BAR2_SIZE_8M           (8UL<<0)
            #define PCI1_BAR2_CONFIG_BAR2_SIZE_16M          (9UL<<0)
            #define PCI1_BAR2_CONFIG_BAR2_SIZE_32M          (10UL<<0)
            #define PCI1_BAR2_CONFIG_BAR2_SIZE_64M          (11UL<<0)
            #define PCI1_BAR2_CONFIG_BAR2_SIZE_128M         (12UL<<0)
            #define PCI1_BAR2_CONFIG_BAR2_SIZE_256M         (13UL<<0)
            #define PCI1_BAR2_CONFIG_BAR2_SIZE_512M         (14UL<<0)
            #define PCI1_BAR2_CONFIG_BAR2_SIZE_1G           (15UL<<0)
        #define PCI1_BAR2_CONFIG_BAR2_64ENA                 (1UL<<4)
        #define PCI1_BAR2_CONFIG_BAR2_PREFETCH              (1UL<<5)
        #define PCI1_BAR2_CONFIG_RESERVED                   (0x3ffffffUL<<6)

    u32_t pci1_pcie_device_capability_2;
        #define PCI1_PCIE_DEVICE_CAPABILITY_2_CMPL_TO_RANGE_SUPP  (0xfUL<<0)
        #define PCI1_PCIE_DEVICE_CAPABILITY_2_CMPL_TO_DISABL_SUPP  (1UL<<4)
        #define PCI1_PCIE_DEVICE_CAPABILITY_2_RESERVED      (0x7ffffffUL<<5)

    u32_t pci1_pcie_link_capability_2;
        #define PCI1_PCIE_LINK_CAPABILITY_2_RESERVED        (0xffffffffUL<<0)

    u32_t unused_20[5];
    u32_t pci1_dev_ser_num_cap_id;
        #define PCI1_DEV_SER_NUM_CAP_ID_CAP_ID              (0xffffUL<<0)
        #define PCI1_DEV_SER_NUM_CAP_ID_CAP_VER             (0xfUL<<16)
        #define PCI1_DEV_SER_NUM_CAP_ID_EXT_CAP_ENA         (0xfUL<<20)
            #define PCI1_DEV_SER_NUM_CAP_ID_EXT_CAP_ENA_8   (8UL<<20)
            #define PCI1_DEV_SER_NUM_CAP_ID_EXT_CAP_ENA_9   (9UL<<20)
            #define PCI1_DEV_SER_NUM_CAP_ID_EXT_CAP_ENA_10  (10UL<<20)
            #define PCI1_DEV_SER_NUM_CAP_ID_EXT_CAP_ENA_11  (11UL<<20)
            #define PCI1_DEV_SER_NUM_CAP_ID_EXT_CAP_ENA_12  (12UL<<20)
            #define PCI1_DEV_SER_NUM_CAP_ID_EXT_CAP_ENA_13  (13UL<<20)
            #define PCI1_DEV_SER_NUM_CAP_ID_EXT_CAP_ENA_14  (14UL<<20)
            #define PCI1_DEV_SER_NUM_CAP_ID_EXT_CAP_ENA_15  (15UL<<20)

    u32_t pci1_lower_ser_num;
        #define PCI1_LOWER_SER_NUM_LOWER_SER_NUM            (0xffffffffUL<<0)

    u32_t pci1_upper_ser_num;
        #define PCI1_UPPER_SER_NUM_UPPER_SER_NUM            (0xffffffffUL<<0)

    u32_t pci1_adv_err_cap;
        #define PCI1_ADV_ERR_CAP_ECRC_CHK_CAP               (1UL<<0)
        #define PCI1_ADV_ERR_CAP_ECRC_GEN_CAP               (1UL<<1)

    u32_t pci1_pwr_bdgt_data_0;
        #define PCI1_PWR_BDGT_DATA_0_PWR_BDGT_DATA_0        (0x1fffffUL<<0)
        #define PCI1_PWR_BDGT_DATA_0_RESERVED               (0x7ffUL<<21)

    u32_t pci1_pwr_bdgt_data_1;
        #define PCI1_PWR_BDGT_DATA_1_PWR_BDGT_DATA_1        (0x1fffffUL<<0)
        #define PCI1_PWR_BDGT_DATA_1_RW                     (0x7ffUL<<21)

    u32_t pci1_pwr_bdgt_data_2;
        #define PCI1_PWR_BDGT_DATA_2_PWR_BDGT_DATA_2        (0x1fffffUL<<0)
        #define PCI1_PWR_BDGT_DATA_2_RW                     (0x7ffUL<<21)

    u32_t pci1_pwd_bdgt_data_3;
        #define PCI1_PWD_BDGT_DATA_3_PWR_BDGT_DATA_3        (0x1fffffUL<<0)
        #define PCI1_PWD_BDGT_DATA_3_RW                     (0x7ffUL<<21)

    u32_t pci1_pwr_bdgt_data_4;
        #define PCI1_PWR_BDGT_DATA_4_PWR_BDGT_DATA_4        (0x1fffffUL<<0)
        #define PCI1_PWR_BDGT_DATA_4_RW                     (0x7ffUL<<21)

    u32_t pci1_pwr_bdgt_data_5;
        #define PCI1_PWR_BDGT_DATA_5_PWR_BDGT_DATA_5        (0x1fffffUL<<0)
        #define PCI1_PWR_BDGT_DATA_5_RW                     (0x7ffUL<<21)

    u32_t pci1_pwr_bdgt_data_6;
        #define PCI1_PWR_BDGT_DATA_6_PWR_BDGT_DATA_6        (0x1fffffUL<<0)
        #define PCI1_PWR_BDGT_DATA_6_RW                     (0x7ffUL<<21)

    u32_t pci1_pwr_bdgt_data_7;
        #define PCI1_PWR_BDGT_DATA_7_PWR_BDGT_DATA_7        (0x1fffffUL<<0)
        #define PCI1_PWR_BDGT_DATA_7_RW                     (0x7ffUL<<21)

    u32_t unused_21[8];
    u32_t pci1_pwr_bdgt_capability_ctl;
        #define PCI1_PWR_BDGT_CAPABILITY_CTL_PWR_SYSTEM_ALLOC  (1UL<<0)
        #define PCI1_PWR_BDGT_CAPABILITY_CTL_RESERVED       (0x7fffffffUL<<1)

    u32_t unused_22[47];
    u32_t pci1_grc_window1_addr;
        #define PCI1_GRC_WINDOW1_ADDR_VALUE                 (0x1ffUL<<13)

    u32_t pci1_grc_window2_addr;
        #define PCI1_GRC_WINDOW2_ADDR_VALUE                 (0x1ffUL<<13)

    u32_t pci1_grc_window3_addr;
        #define PCI1_GRC_WINDOW3_ADDR_VALUE                 (0x1ffUL<<13)

    u32_t unused_23[9];
    u32_t pci1_exp_rom_adr;
        #define PCI1_EXP_ROM_ADR_ADDRESS                    (0x3fffffUL<<2)
        #define PCI1_EXP_ROM_ADR_ADDR_SIZE                  (0x3UL<<24)
        #define PCI1_EXP_ROM_ADR_REQ                        (1UL<<31)

    u32_t pci1_exp_rom_data0;
    u32_t pci1_exp_rom_data1;
    u32_t pci1_exp_rom_data2;
    u32_t pci1_exp_rom_ctrl;
        #define PCI1_EXP_ROM_CTRL_ENA                       (1UL<<0)
        #define PCI1_EXP_ROM_CTRL_BFRD                      (1UL<<1)
        #define PCI1_EXP_ROM_CTRL_ARB_NUM                   (0x3UL<<4)
        #define PCI1_EXP_ROM_CTRL_STATE                     (0xfUL<<16)
        #define PCI1_EXP_ROM_CTRL_CACHE_VALID               (1UL<<28)
        #define PCI1_EXP_ROM_CTRL_ARB_TIMEOUT               (1UL<<29)
        #define PCI1_EXP_ROM_CTRL_READ_TIMEOUT              (1UL<<30)
        #define PCI1_EXP_ROM_CTRL_ACTIVE                    (1UL<<31)

    u32_t pci1_exp_rom_baddr;
        #define PCI1_EXP_ROM_BADDR_VALUE                    (0x3fffffUL<<2)

    u32_t pci1_exp_rom_cfg;
        #define PCI1_EXP_ROM_CFG_ARB_TIMEOUT_SHFT           (0xfUL<<0)
        #define PCI1_EXP_ROM_CFG_READ_TIMEOUT_SHFT          (0xfUL<<4)

    u32_t unused_24[41];
    u32_t pci1_debug_vect_peek;
        #define PCI1_DEBUG_VECT_PEEK_1_VALUE                (0x7ffUL<<0)
        #define PCI1_DEBUG_VECT_PEEK_1_EN                   (1UL<<11)
        #define PCI1_DEBUG_VECT_PEEK_1_SEL                  (0xfUL<<12)
        #define PCI1_DEBUG_VECT_PEEK_2_VALUE                (0x7ffUL<<16)
        #define PCI1_DEBUG_VECT_PEEK_2_EN                   (1UL<<27)
        #define PCI1_DEBUG_VECT_PEEK_2_SEL                  (0xfUL<<28)

    u32_t unused_25[63];
    u32_t pci1_tl_control_0;
        #define PCI1_TL_CONTROL_0_PM_TL_IGNORE_REQS         (1UL<<0)
        #define PCI1_TL_CONTROL_0_TIMEOUT                   (0x3fUL<<1)
        #define PCI1_TL_CONTROL_0_FUNC0_HIDDEN              (1UL<<16)
        #define PCI1_TL_CONTROL_0_FUNC1_HIDDEN              (1UL<<17)
        #define PCI1_TL_CONTROL_0_BEACON_MULTI_LN_EN        (1UL<<19)
        #define PCI1_TL_CONTROL_0_BEACON_DIS                (1UL<<20)
        #define PCI1_TL_CONTROL_0_WAKE_L0_L1_EN             (1UL<<21)
        #define PCI1_TL_CONTROL_0_OOB_EN                    (1UL<<22)
        #define PCI1_TL_CONTROL_0_RST_IGNORE_DLPDOWN        (1UL<<23)
        #define PCI1_TL_CONTROL_0_DISABL_L1_REENTRY         (1UL<<24)
        #define PCI1_TL_CONTROL_0_TX_MARGIN_SEL             (1UL<<25)
            #define PCI1_TL_CONTROL_0_TX_MARGIN_SEL_0       (0UL<<25)
            #define PCI1_TL_CONTROL_0_TX_MARGIN_SEL_1       (1UL<<25)

    u32_t pci1_tl_control_1;
        #define PCI1_TL_CONTROL_1_EN_4G_CHK                 (1UL<<0)
        #define PCI1_TL_CONTROL_1_EN_4K_CHK                 (1UL<<1)
        #define PCI1_TL_CONTROL_1_EN_BC_CHK                 (1UL<<2)
        #define PCI1_TL_CONTROL_1_EN_BE_CHK                 (1UL<<3)
        #define PCI1_TL_CONTROL_1_EN_EP_CHK                 (1UL<<4)
        #define PCI1_TL_CONTROL_1_EN_MPS_CHECK              (1UL<<5)
        #define PCI1_TL_CONTROL_1_EN_RCB_CHK                (1UL<<6)
        #define PCI1_TL_CONTROL_1_EN_RTE_CHK                (1UL<<7)
        #define PCI1_TL_CONTROL_1_EN_TAC_CHK                (1UL<<8)
        #define PCI1_TL_CONTROL_1_EN_FC_CHK                 (1UL<<9)
        #define PCI1_TL_CONTROL_1_EN_TO_CHK                 (1UL<<10)
        #define PCI1_TL_CONTROL_1_RESERVED                  (0x1fffffUL<<11)

    u32_t pci1_tl_control_2;
        #define PCI1_TL_CONTROL_2_PES0                      (1UL<<0)
        #define PCI1_TL_CONTROL_2_FCPES0                    (1UL<<1)
        #define PCI1_TL_CONTROL_2_CTS0                      (1UL<<2)
        #define PCI1_TL_CONTROL_2_CAS0                      (1UL<<3)
        #define PCI1_TL_CONTROL_2_UCS0                      (1UL<<4)
        #define PCI1_TL_CONTROL_2_ROS0                      (1UL<<5)
        #define PCI1_TL_CONTROL_2_MTLPS0                    (1UL<<6)
        #define PCI1_TL_CONTROL_2_ECRCS0                    (1UL<<7)
        #define PCI1_TL_CONTROL_2_URES0                     (1UL<<8)
        #define PCI1_TL_CONTROL_2_RXTABRT0                  (1UL<<9)
        #define PCI1_TL_CONTROL_2_PES1                      (1UL<<10)
        #define PCI1_TL_CONTROL_2_FCPES1                    (1UL<<11)
        #define PCI1_TL_CONTROL_2_CTS1                      (1UL<<12)
        #define PCI1_TL_CONTROL_2_CAS1                      (1UL<<13)
        #define PCI1_TL_CONTROL_2_UCS1                      (1UL<<14)
        #define PCI1_TL_CONTROL_2_ROS1                      (1UL<<15)
        #define PCI1_TL_CONTROL_2_MTLPS1                    (1UL<<16)
        #define PCI1_TL_CONTROL_2_ECRCS1                    (1UL<<17)
        #define PCI1_TL_CONTROL_2_URES1                     (1UL<<18)
        #define PCI1_TL_CONTROL_2_RXTABRT1                  (1UL<<19)
        #define PCI1_TL_CONTROL_2_DLPES                     (1UL<<20)
        #define PCI1_TL_CONTROL_2_PHYES                     (1UL<<21)

    u32_t pci1_tl_control_3;
        #define PCI1_TL_CONTROL_3_EN_CMPL_RETRY             (1UL<<0)
        #define PCI1_TL_CONTROL_3_EN_PSND_RETRY             (1UL<<1)
        #define PCI1_TL_CONTROL_3_EN_HOLD_PHCRDT            (1UL<<2)
        #define PCI1_TL_CONTROL_3_MAX_INTER_L1_GAP          (0xffffUL<<16)

    u32_t pci1_tl_control_4;
        #define PCI1_TL_CONTROL_4_RESERVED2                 (0xffffUL<<0)
        #define PCI1_TL_CONTROL_4_RESERVED1                 (0xffffUL<<16)

    u32_t pci1_tl_control_5;
        #define PCI1_TL_CONTROL_5_PES0                      (1UL<<0)
        #define PCI1_TL_CONTROL_5_FCPES0                    (1UL<<1)
        #define PCI1_TL_CONTROL_5_CTS0                      (1UL<<2)
        #define PCI1_TL_CONTROL_5_CAS0                      (1UL<<3)
        #define PCI1_TL_CONTROL_5_UCS0                      (1UL<<4)
        #define PCI1_TL_CONTROL_5_ROS0                      (1UL<<5)
        #define PCI1_TL_CONTROL_5_MTLPS0                    (1UL<<6)
        #define PCI1_TL_CONTROL_5_ECRCS0                    (1UL<<7)
        #define PCI1_TL_CONTROL_5_URES0                     (1UL<<8)
        #define PCI1_TL_CONTROL_5_RXTABRT0                  (1UL<<9)
        #define PCI1_TL_CONTROL_5_PES1                      (1UL<<10)
        #define PCI1_TL_CONTROL_5_FCPES1                    (1UL<<11)
        #define PCI1_TL_CONTROL_5_CTS1                      (1UL<<12)
        #define PCI1_TL_CONTROL_5_CAS1                      (1UL<<13)
        #define PCI1_TL_CONTROL_5_UCS1                      (1UL<<14)
        #define PCI1_TL_CONTROL_5_ROS1                      (1UL<<15)
        #define PCI1_TL_CONTROL_5_MTLPS1                    (1UL<<16)
        #define PCI1_TL_CONTROL_5_ECRCS1                    (1UL<<17)
        #define PCI1_TL_CONTROL_5_URES1                     (1UL<<18)
        #define PCI1_TL_CONTROL_5_RXTABRT1                  (1UL<<19)
        #define PCI1_TL_CONTROL_5_DLPES                     (1UL<<20)
        #define PCI1_TL_CONTROL_5_PHYES                     (1UL<<21)

    u32_t unused_26[23];
    u32_t pci1_TL_CTLSTAT_0;
        #define PCI1_TL_CTLSTAT_0_PCIE_FUNC_1_HIDDEN        (1UL<<0)
        #define PCI1_TL_CTLSTAT_0_RESERVED                  (0x7fffffffUL<<1)

    u32_t pci1_pm_status_0;
        #define PCI1_PM_STATUS_0_PME_SENT_SM0               (0x1fUL<<0)
        #define PCI1_PM_STATUS_0_PME_SENT_SM1               (0x1fUL<<8)
        #define PCI1_PM_STATUS_0_PM_LINK_STATE_SM           (0x7fUL<<25)

    u32_t pci1_pm_status_1;
        #define PCI1_PM_STATUS_1_CFG_PME_ENABLE0B           (1UL<<0)
        #define PCI1_PM_STATUS_1_CFG_PME_STATUS0            (1UL<<1)
        #define PCI1_PM_STATUS_1_CFG_AUX_PWR_PM_EN0         (1UL<<2)
        #define PCI1_PM_STATUS_1_CFG_PME_ENABLE1            (1UL<<3)
        #define PCI1_PM_STATUS_1_CFG_PME_STATUS1            (1UL<<4)
        #define PCI1_PM_STATUS_1_CFG_AUX_PWR_PM_EN1         (1UL<<5)

    u32_t unused_27[32];
    u32_t pci1_tl_status_0;
        #define PCI1_TL_STATUS_0_DEVICE_NO                  (0xfUL<<0)
        #define PCI1_TL_STATUS_0_FUNC_NO                    (0x7UL<<4)
        #define PCI1_TL_STATUS_0_TC                         (0x7UL<<7)
        #define PCI1_TL_STATUS_0_ATTR                       (0x3UL<<10)
        #define PCI1_TL_STATUS_0_BYTE_COUNT                 (0x1fffUL<<12)
        #define PCI1_TL_STATUS_0_LWR_ADDR                   (0x7fUL<<25)

    u32_t pci1_tl_status_1;
    u32_t pci1_tl_status_2;
    u32_t pci1_tl_status_3;
    u32_t pci1_tl_status_4;
    u32_t pci1_tl_status_5;
    u32_t pci1_tl_status_6;
    u32_t pci1_tl_status_7;
    u32_t pci1_tl_status_8;
    u32_t pci1_tl_status_9;
    u32_t pci1_tl_status_10;
    u32_t pci1_tl_status_11;
    u32_t pci1_tl_status_12;
    u32_t pci1_tl_status_13;
    u32_t pci1_tl_status_14;
    u32_t pci1_tl_status_15;
    u32_t pci1_tl_status_16;
    u32_t pci1_tl_status_17;
    u32_t pci1_tl_status_18;
    u32_t pci1_tl_status_19;
    u32_t pci1_tl_status_20;
    u32_t pci1_tl_status_21;
    u32_t pci1_tl_status_22;
    u32_t pci1_tl_status_23;
    u32_t pci1_tl_status_24;
    u32_t pci1_tl_status_25;
    u32_t pci1_tl_status_26;
    u32_t pci1_tl_status_27;
    u32_t pci1_tl_status_28;
    u32_t pci1_tl_status_29;
    u32_t pci1_tl_status_30;
    u32_t pci1_tl_status_31;
    u32_t pci1_tl_hdr_fc_st;
        #define PCI1_TL_HDR_FC_ST_NPH_AVAIL                 (0xffUL<<0)
        #define PCI1_TL_HDR_FC_ST_PH_AVAIL                  (0xffUL<<8)
        #define PCI1_TL_HDR_FC_ST_CPLH_AVAIL                (0xffUL<<16)

    u32_t pci1_tl_dat_fc_st;
        #define PCI1_TL_DAT_FC_ST_PD_AVAIL                  (0xfffUL<<0)
        #define PCI1_TL_DAT_FC_ST_CPLD_AVAIL                (0xfffUL<<16)

    u32_t pci1_tl_hdr_fccon_st;
        #define PCI1_TL_HDR_FCCON_ST_NPH_CC                 (0xffUL<<0)
        #define PCI1_TL_HDR_FCCON_ST_PH_CC                  (0xffUL<<8)
        #define PCI1_TL_HDR_FCCON_ST_CPLH_CC                (0xffUL<<16)

    u32_t pci1_tl_dat_fccon_st;
        #define PCI1_TL_DAT_FCCON_ST_PD_CC                  (0xfffUL<<0)
        #define PCI1_TL_DAT_FCCON_ST_CPLD_CC                (0xfffUL<<16)

    u32_t pci1_tl_tgt_crdt_st;
        #define PCI1_TL_TGT_CRDT_ST_PH_CRDT_CNTR            (0x7fUL<<0)
        #define PCI1_TL_TGT_CRDT_ST_PD_CRDT_CNTR            (0x7fUL<<8)
        #define PCI1_TL_TGT_CRDT_ST_NP_CRDT_CNTR            (1UL<<16)

    u32_t pci1_tl_crdt_alloc_st;
        #define PCI1_TL_CRDT_ALLOC_ST_NPH_ALLOC             (0xffUL<<0)
        #define PCI1_TL_CRDT_ALLOC_ST_NPD_ALLOC             (0xffUL<<8)
        #define PCI1_TL_CRDT_ALLOC_ST_PH_ALLOC              (0xffUL<<16)
        #define PCI1_TL_CRDT_ALLOC_ST_PD_ALLOC              (0xffUL<<24)

    u32_t pci1_tl_smlogic_st;
        #define PCI1_TL_SMLOGIC_ST_NP_CURR_STATE            (0xfUL<<0)
        #define PCI1_TL_SMLOGIC_ST_PH_CURR_STATE            (0xfUL<<4)
        #define PCI1_TL_SMLOGIC_ST_CPL_CURR_STATE           (0x3UL<<8)
        #define PCI1_TL_SMLOGIC_ST_TX_SM                    (0x7UL<<16)

    u32_t unused_28[409];
    u32_t pci1_pdl_control_0;
        #define PCI1_PDL_CONTROL_0_ENABLE_SCRAMB            (1UL<<0)
        #define PCI1_PDL_CONTROL_0_DISABLE_REVERSE          (1UL<<1)
        #define PCI1_PDL_CONTROL_0_DISABLE_REPLAY_TIMER     (1UL<<2)
        #define PCI1_PDL_CONTROL_0_DISABLE_FRAM_CHECK       (1UL<<3)
        #define PCI1_PDL_CONTROL_0_DISABLE_CRC_DLL          (1UL<<4)
        #define PCI1_PDL_CONTROL_0_DISABLE_CRC_DLP          (1UL<<5)
        #define PCI1_PDL_CONTROL_0_DISABLE_REPLAY_BUFF      (1UL<<6)
        #define PCI1_PDL_CONTROL_0_DISABLE_SKEW_RET         (1UL<<7)
        #define PCI1_PDL_CONTROL_0_ENABLE_COMPLIANCE        (1UL<<8)
        #define PCI1_PDL_CONTROL_0_DISABLE_8B10_BYPAS       (1UL<<9)
        #define PCI1_PDL_CONTROL_0_DISABLE_LOST_SYNCH       (1UL<<10)
        #define PCI1_PDL_CONTROL_0_DISABLE_AUTO_CRDUPD      (1UL<<11)
        #define PCI1_PDL_CONTROL_0_DISABLE_RETRAIN_REQ      (1UL<<12)
        #define PCI1_PDL_CONTROL_0_FORCE_L0TOL1             (1UL<<13)
        #define PCI1_PDL_CONTROL_0_RESERVED                 (1UL<<14)
        #define PCI1_PDL_CONTROL_0_DISABLE_REV_LANE         (1UL<<15)
        #define PCI1_PDL_CONTROL_0_ENABLE_TX_ERR_MUX        (1UL<<16)
        #define PCI1_PDL_CONTROL_0_ENABLE_RX_ERR_MUX        (1UL<<17)
        #define PCI1_PDL_CONTROL_0_ENABLE_ERR_FRAMING       (1UL<<18)
        #define PCI1_PDL_CONTROL_0_ENABLE_SINGLE_ERR        (1UL<<19)
        #define PCI1_PDL_CONTROL_0_ENCOMFORSIG              (1UL<<20)
        #define PCI1_PDL_CONTROL_0_DISABLE_TLPRDNXT         (1UL<<21)
        #define PCI1_PDL_CONTROL_0_DISABLE_GENE_TIMER       (1UL<<22)
        #define PCI1_PDL_CONTROL_0_DISABLETXDETECT          (1UL<<23)
        #define PCI1_PDL_CONTROL_0_LOOPBACK_CNTL_REG        (0x7UL<<24)
        #define PCI1_PDL_CONTROL_0_FORCE_L0TOL2             (1UL<<27)
        #define PCI1_PDL_CONTROL_0_DISABLE_HOT_SERDES       (1UL<<28)
        #define PCI1_PDL_CONTROL_0_DISSKEWCHECK             (1UL<<29)
        #define PCI1_PDL_CONTROL_0_DISABLERXSKIP            (1UL<<30)
        #define PCI1_PDL_CONTROL_0_FORCE_RECTOCONF          (1UL<<31)

    u32_t pci1_pdl_control_1;
        #define PCI1_PDL_CONTROL_1_MAX_DLP_IDLE_CNT         (0x7fUL<<0)
        #define PCI1_PDL_CONTROL_1_DISABLE_CC_DESKEW        (1UL<<8)
        #define PCI1_PDL_CONTROL_1_DISABLE_DLPTX_BB         (1UL<<10)
        #define PCI1_PDL_CONTROL_1_FORCE_L0TOL0S            (1UL<<11)
        #define PCI1_PDL_CONTROL_1_MAX_REPLAY_NUM           (0x3UL<<12)
        #define PCI1_PDL_CONTROL_1_RETRAIN_REQ              (1UL<<14)
        #define PCI1_PDL_CONTROL_1_PHYRX_DETECT_ERROR_DIS   (1UL<<15)
        #define PCI1_PDL_CONTROL_1_MAX_DLP_L1_ENTRANCE      (0x7fUL<<16)
        #define PCI1_PDL_CONTROL_1_REPLAY_INTDEL_GEN2       (0x1ffUL<<23)

    u32_t pci1_pdl_control_2;
        #define PCI1_PDL_CONTROL_2_MAX_SYMB_SKIP_OS         (0x7UL<<0)
        #define PCI1_PDL_CONTROL_2_ENABLE_ACK_LAT_TIMER     (1UL<<3)
        #define PCI1_PDL_CONTROL_2_SW_ACK_LAT_SEL           (1UL<<4)
        #define PCI1_PDL_CONTROL_2_SW_REPLAY_TIMER_SEL      (1UL<<5)
        #define PCI1_PDL_CONTROL_2_SELDETECT_DELAY          (0x3UL<<6)
        #define PCI1_PDL_CONTROL_2_MAX_WAIT_RX_L0S_ENTRY    (0xfUL<<8)
        #define PCI1_PDL_CONTROL_2_MAX_WAIT_TX_L0S_ENTRY    (0xfUL<<12)
        #define PCI1_PDL_CONTROL_2_ENABLE_CRD_LAT_P         (1UL<<16)
        #define PCI1_PDL_CONTROL_2_ENABLE_CRD_LAT_N         (1UL<<17)
        #define PCI1_PDL_CONTROL_2_CORR_ERR_REG_MAX         (0x3ffUL<<18)
        #define PCI1_PDL_CONTROL_2_DISABLE_DESKEW_ERR       (1UL<<28)
        #define PCI1_PDL_CONTROL_2_ENABLE_SKIP_RST_ERR      (1UL<<29)
        #define PCI1_PDL_CONTROL_2_DISABLE_FASTACQ          (1UL<<30)
        #define PCI1_PDL_CONTROL_2_DISABLE_RX_ELEC          (1UL<<31)

    u32_t pci1_pdl_control_3;
        #define PCI1_PDL_CONTROL_3_MAX_TX_FTS_LIMIT         (0xffUL<<0)
        #define PCI1_PDL_CONTROL_3_MAX_TX_FTS_LIMIT_LONG    (0xffUL<<8)
        #define PCI1_PDL_CONTROL_3_MAX_TX_FTS_LIMIT_GEN2    (0xffUL<<16)
        #define PCI1_PDL_CONTROL_3_MAX_TX_FTS_LIMIT_LONG_GEN2  (0xffUL<<24)

    u32_t pci1_pdl_control_4;
        #define PCI1_PDL_CONTROL_4_NPD_FC_INIT              (0xfffUL<<0)
        #define PCI1_PDL_CONTROL_4_PD_FC_INIT               (0xfffUL<<12)
        #define PCI1_PDL_CONTROL_4_NPH_FC_INIT              (0xffUL<<24)

    u32_t pci1_pdl_control_5;
        #define PCI1_PDL_CONTROL_5_PH_FC_INIT               (0xffUL<<0)
        #define PCI1_PDL_CONTROL_5_LINK_UPSTREAM            (1UL<<8)
        #define PCI1_PDL_CONTROL_5_GLOOPBACK                (1UL<<9)
        #define PCI1_PDL_CONTROL_5_RESERVED                 (0x3fUL<<10)
        #define PCI1_PDL_CONTROL_5_LOOPBACK_REG             (0xffffUL<<16)

    u32_t pci1_pdl_control_6;
        #define PCI1_PDL_CONTROL_6_LOOPBACK_REG             (0xffffffffUL<<0)

    u32_t pci1_pdl_control_7;
        #define PCI1_PDL_CONTROL_7_LOOPBACK_REG             (0xffffffffUL<<0)

    u32_t pci1_pdl_control_8;
        #define PCI1_PDL_CONTROL_8_LOOPBACK_REG             (0xffffffffUL<<0)

    u32_t pci1_pdl_control_9;
        #define PCI1_PDL_CONTROL_9_LOOPBACK_REG             (0xffffffffUL<<0)

    u32_t pci1_pdl_control_10;
        #define PCI1_PDL_CONTROL_10_DL_HI_WATERMARK         (0x1fUL<<0)
        #define PCI1_PDL_CONTROL_10_DL_CS_RXENABLE          (1UL<<8)
        #define PCI1_PDL_CONTROL_10_DL_CS_ENABLE            (1UL<<9)
        #define PCI1_PDL_CONTROL_10_DL_CS_WRITE_NULLIFY     (1UL<<10)
        #define PCI1_PDL_CONTROL_10_DL_CS_NULLIFY           (1UL<<11)

    u32_t pci1_pdl_control_11;
        #define PCI1_PDL_CONTROL_11_REPLAY_TIMER_LIMIT_GEN1  (0xfffUL<<0)
        #define PCI1_PDL_CONTROL_11_REPLAY_TIMER_LIMIT_GEN2  (0xfffUL<<12)
        #define PCI1_PDL_CONTROL_11_RESERVED                (0xffUL<<24)

    u32_t pci1_pdl_control_12;
        #define PCI1_PDL_CONTROL_12_UPDATE_FREQ_GEN1        (0xffUL<<0)
        #define PCI1_PDL_CONTROL_12_UPDATE_FREQ_GEN2        (0xffUL<<8)
        #define PCI1_PDL_CONTROL_12_RESERVED                (0xffffUL<<16)

    u32_t pci1_pdl_control_13;
        #define PCI1_PDL_CONTROL_13_ACK_LATENCY_TIMER_GEN1  (0x3ffUL<<0)
        #define PCI1_PDL_CONTROL_13_ACK_LATENCY_TIMER_GEN2  (0x3ffUL<<10)
        #define PCI1_PDL_CONTROL_13_ACK_INTDEL_GEN2         (0xffUL<<20)
        #define PCI1_PDL_CONTROL_13_RESERVED                (0xfUL<<28)

    u32_t pci1_pdl_control_14;
        #define PCI1_PDL_CONTROL_14_DEBUG_EXT_SEL_0         (0x1fffUL<<0)
        #define PCI1_PDL_CONTROL_14_DEBUG_EXT_SEL_1         (0x1fffUL<<13)
        #define PCI1_PDL_CONTROL_14_DEBUG_GRC_SEL_0         (0x3UL<<27)
            #define PCI1_PDL_CONTROL_14_DEBUG_GRC_SEL_0_00  (0UL<<27)
            #define PCI1_PDL_CONTROL_14_DEBUG_GRC_SEL_0_01  (1UL<<27)
            #define PCI1_PDL_CONTROL_14_DEBUG_GRC_SEL_0_10  (2UL<<27)
            #define PCI1_PDL_CONTROL_14_DEBUG_GRC_SEL_0_11  (2UL<<27)
        #define PCI1_PDL_CONTROL_14_DEBUG_GRC_SEL_1         (0x3UL<<29)
            #define PCI1_PDL_CONTROL_14_DEBUG_GRC_SEL_1_00  (0UL<<29)
            #define PCI1_PDL_CONTROL_14_DEBUG_GRC_SEL_1_01  (1UL<<29)
            #define PCI1_PDL_CONTROL_14_DEBUG_GRC_SEL_1_10  (2UL<<29)
            #define PCI1_PDL_CONTROL_14_DEBUG_GRC_SEL_1_11  (2UL<<29)
        #define PCI1_PDL_CONTROL_14_DEBUG_GRC_ENA           (1UL<<31)

    u32_t pci1_pdl_control_15;
        #define PCI1_PDL_CONTROL_15_FORCE_UPDATE_GEN2       (0x7fffUL<<0)
        #define PCI1_PDL_CONTROL_15_FORCE_UPDATE_EXTENDED_SYNC_GEN2  (0x7fffUL<<15)

    u32_t pci1_DL_ATTN_VECTOR;
        #define PCI1_DL_ATTN_VECTOR_DL_CKSUM_ERR_AT         (1UL<<0)
        #define PCI1_DL_ATTN_VECTOR_DL_D2TBUF_OFLOW_ERR     (1UL<<1)
        #define PCI1_DL_ATTN_VECTOR_DLP2TLP_PARITY_ERROR    (1UL<<2)
        #define PCI1_DL_ATTN_VECTOR_REPLAY_ADDRESS_PARITY_ERROR  (1UL<<3)
        #define PCI1_DL_ATTN_VECTOR_REPLAY_WRAPPER_PARITY_ERROR  (1UL<<4)
        #define PCI1_DL_ATTN_VECTOR_DL_CORRECTABLE_ERROR    (1UL<<5)
        #define PCI1_DL_ATTN_VECTOR_DE_FRAMING_ERROR        (1UL<<6)
        #define PCI1_DL_ATTN_VECTOR_DLP_ERROR_STATUS        (1UL<<7)
        #define PCI1_DL_ATTN_VECTOR_DLP_INCORRECT           (1UL<<8)
        #define PCI1_DL_ATTN_VECTOR_TLPBUFRDERR             (1UL<<9)
        #define PCI1_DL_ATTN_VECTOR_REPLAY_SEQUENCE_OVERRUN  (1UL<<10)
        #define PCI1_DL_ATTN_VECTOR_DLL_ERROR_ACK           (1UL<<11)
        #define PCI1_DL_ATTN_VECTOR_REPLAY_BUFFER_OVERRUN   (1UL<<12)
        #define PCI1_DL_ATTN_VECTOR_REPLAY_NUMBER_ROLL_OVER  (1UL<<13)
        #define PCI1_DL_ATTN_VECTOR_REPLAY_TIMEOUT          (1UL<<14)
        #define PCI1_DL_ATTN_VECTOR_FCPE_ERROR_STATUS       (1UL<<15)
        #define PCI1_DL_ATTN_VECTOR_DLL_ERROR_STATUS        (1UL<<16)
        #define PCI1_DL_ATTN_VECTOR_DLL_PE_INIT_STATUS      (1UL<<17)
        #define PCI1_DL_ATTN_VECTOR_COL_FULL                (1UL<<18)
        #define PCI1_DL_ATTN_VECTOR_TLP_INCORRECT           (1UL<<19)
        #define PCI1_DL_ATTN_VECTOR_TLP_SYNC_ERROR          (1UL<<20)

    u32_t pci1_DL_ATTN_MASK;
        #define PCI1_DL_ATTN_MASK_MASK_FOR_DL_ATTENTIONS    (0x1fffffUL<<0)
        #define PCI1_DL_ATTN_MASK_RESERVED1                 (0x7ffUL<<21)

    u32_t pci1_DL_STATUS;
        #define PCI1_DL_STATUS_CORR_ERR_REG                 (0x3ffUL<<0)
        #define PCI1_DL_STATUS_REPLAY_ALM_FULL              (1UL<<10)
        #define PCI1_DL_STATUS_PHYLINKUP                    (1UL<<13)
        #define PCI1_DL_STATUS_DL_ACTIVE                    (1UL<<14)
        #define PCI1_DL_STATUS_DL_INIT                      (1UL<<15)
        #define PCI1_DL_STATUS_RESERVED                     (0xffffUL<<16)

    u32_t pci1_DL_TX_Checksum;
        #define PCI1_DL_TX_CHECKSUM_EXPECTED_TX_CHECKSUM    (0xffffUL<<0)
        #define PCI1_DL_TX_CHECKSUM_ACTUAL_TX_CHECKSUM      (0xffffUL<<16)

    u32_t pci1_dl_forced_update_gen1;
        #define PCI1_DL_FORCED_UPDATE_GEN1_FORCE_UPDATE_GEN1  (0x7fffUL<<0)
        #define PCI1_DL_FORCED_UPDATE_GEN1_FORCE_UPDATE_EXTENDED_SYNC_GEN1  (0x7fffUL<<15)

    u32_t unused_29[43];
    u32_t pci1_mdio_addr;
        #define PCI1_MDIO_ADDR_ADR                          (0xffffUL<<0)
        #define PCI1_MDIO_ADDR_PORT                         (0xfUL<<16)
        #define PCI1_MDIO_ADDR_CMD                          (0xfffUL<<20)

    u32_t pci1_mdio_wr_data;
        #define PCI1_MDIO_WR_DATA_DATA                      (0xffffUL<<0)
        #define PCI1_MDIO_WR_DATA_CMD                       (1UL<<31)

    u32_t pci1_mdio_rd_data;
        #define PCI1_MDIO_RD_DATA_DATA                      (0xffffUL<<0)
        #define PCI1_MDIO_RD_DATA_CMD                       (1UL<<31)

    u32_t unused_30[189];
    u32_t pci1_dl_rx_pn_credit_limit;
        #define PCI1_DL_RX_PN_CREDIT_LIMIT_DL_RX_PN_CREDIT_LIMIT  (0xffffffffUL<<0)

    u32_t pci1_dl_rx_c_credit_limit;
        #define PCI1_DL_RX_C_CREDIT_LIMIT_DL_RX_C_CREDIT_LIMIT  (0xffffffffUL<<0)

    u32_t pci1_dl_rx_ack_nack;
        #define PCI1_DL_RX_ACK_NACK_DL_RX_ACK_NACK          (0xffffffffUL<<0)

    u32_t pci1_dl_coldat_lsb;
        #define PCI1_DL_COLDAT_LSB_DL_COLDAT_LSB            (0xffffffffUL<<0)

    u32_t pci1_dl_coldat_msb;
        #define PCI1_DL_COLDAT_MSB_DL_COLDAT_MSB            (0xffffffffUL<<0)

    u32_t pci1_dl_colcntl;
        #define PCI1_DL_COLCNTL_DL_COLCNTL                  (0xffffffffUL<<0)

    u32_t pci1_dl_coldeb;
        #define PCI1_DL_COLDEB_DL_COLDEB                    (0xffffffffUL<<0)

    u32_t pci1_dl_pwr_mgmt;
        #define PCI1_DL_PWR_MGMT_DL_PWR_MGMT                (0xffffffffUL<<0)

    u32_t pci1_dl_t2d_rxcksum;
        #define PCI1_DL_T2D_RXCKSUM_DL_T2D_RXCKSUM          (0xffffffffUL<<0)

    u32_t pci1_dl_resend0_dlptx0;
        #define PCI1_DL_RESEND0_DLPTX0_DL_RESEND0_DLPTX0    (0xffffffffUL<<0)

    u32_t pci1_dl_resend1_dlptx1;
        #define PCI1_DL_RESEND1_DLPTX1_DL_RESEND1_DLPTX1    (0xffffffffUL<<0)

    u32_t pci1_dl_resend2_dlptx2;
        #define PCI1_DL_RESEND2_DLPTX2_DL_RESEND2_DLPTX2    (0xffffffffUL<<0)

    u32_t pci1_dl_resend2_dlptx3;
        #define PCI1_DL_RESEND2_DLPTX3_DL_RESEND2_DLPTX3    (0xffffffffUL<<0)

    u32_t pci1_dl_phyrx0_d2trx0;
        #define PCI1_DL_PHYRX0_D2TRX0_DL_PHYRX0_D2TRX0      (0xffffffffUL<<0)

    u32_t pci1_dl_phyrx1_d2trx1;
        #define PCI1_DL_PHYRX1_D2TRX1_DL_PHYRX1_D2TRX1      (0xffffffffUL<<0)

    u32_t pci1_dl_phyrx2_d2trx1;
        #define PCI1_DL_PHYRX2_D2TRX1_DL_PHYRX2_D2TRX1      (0xffffffffUL<<0)

    u32_t pci1_dl_coldeb_vec1;
        #define PCI1_DL_COLDEB_VEC1_DL_COLDEB_VEC1          (0xffffffffUL<<0)

    u32_t pci1_dl_d2tbuf_0;
        #define PCI1_DL_D2TBUF_0_DL_D2TBUF_0                (0xffffffffUL<<0)

    u32_t pci1_dl_d2trx1;
        #define PCI1_DL_D2TRX1_DL_D2TRX1                    (0xffffffffUL<<0)

    u32_t pci1_dl_tx_nullify;
        #define PCI1_DL_TX_NULLIFY_DL_TX_NULLIFY            (0xffffffffUL<<0)

    u32_t pci1_dl_datapathtx0;
        #define PCI1_DL_DATAPATHTX0_DL_DATAPATHTX0          (0xffffffffUL<<0)

    u32_t pci1_dl_datapathtx1;
        #define PCI1_DL_DATAPATHTX1_DL_DATAPATHTX1          (0xffffffffUL<<0)

    u32_t pci1_dl_datapathtx2;
        #define PCI1_DL_DATAPATHTX2_DL_DATAPATHTX2          (0xffffffffUL<<0)

    u32_t pci1_dl_dllrx0;
        #define PCI1_DL_DLLRX0_DL_DLLRX0                    (0xffffffffUL<<0)

    u32_t pci1_dl_dllrx1;
        #define PCI1_DL_DLLRX1_DL_DLLRX1                    (0xffffffffUL<<0)

    u32_t pci1_dl_dllrx2;
        #define PCI1_DL_DLLRX2_DL_DLLRX2                    (0xffffffffUL<<0)

    u32_t pci1_dl_rx_tx;
        #define PCI1_DL_RX_TX_DL_RX_TX                      (0xffffffffUL<<0)

    u32_t pci1_dbg_dl_ctrl_status0;
        #define PCI1_DBG_DL_CTRL_STATUS0_MAX_FORCE_UPDATE   (0x7fffUL<<0)
        #define PCI1_DBG_DL_CTRL_STATUS0_EXTENDED_SYNC      (1UL<<15)
        #define PCI1_DBG_DL_CTRL_STATUS0_FORCE_UPD_VAL_FOR_GEN1  (0x7fffUL<<16)
        #define PCI1_DBG_DL_CTRL_STATUS0_PCIE_PHY_RATE      (1UL<<31)

    u32_t pci1_dbg_dl_ctrl_status1;
        #define PCI1_DBG_DL_CTRL_STATUS1_MAX_FORCE_UPDATE   (0x7fffUL<<0)
        #define PCI1_DBG_DL_CTRL_STATUS1_MAX_UPDATE_FREQUENCY  (0x1ffUL<<15)
        #define PCI1_DBG_DL_CTRL_STATUS1_MAX_REPLAY_TIMER   (0xffUL<<24)

    u32_t pci1_dbg_dl_ctrl_status2;
        #define PCI1_DBG_DL_CTRL_STATUS2_DBG_MAX_REPLAY_TIMER  (0x1fffUL<<0)
        #define PCI1_DBG_DL_CTRL_STATUS2_RX_L0S_ADJUSTMENT_R  (0x3ffUL<<13)
        #define PCI1_DBG_DL_CTRL_STATUS2_DBG_MAX_REPLAY_TIMER_LIMIT  (0x1ffUL<<23)

    u32_t pci1_dbg_dl_ctrl_status3;
        #define PCI1_DBG_DL_CTRL_STATUS3_MAX_REPLAY_TIMER_LIMIT  (0xfffUL<<0)
        #define PCI1_DBG_DL_CTRL_STATUS3_REPLAYLIMIT_WO_INTDEL  (0xfffUL<<12)
        #define PCI1_DBG_DL_CTRL_STATUS3_REPLAY_INTDEL      (0xffUL<<24)

    u32_t unused_31[225];
    u32_t pci1_phy_ctl_0;
        #define PCI1_PHY_CTL_0_SPEED_CHANGE_REQ             (1UL<<1)
        #define PCI1_PHY_CTL_0_WIDTH_CHANGE_REQ             (1UL<<1)
        #define PCI1_PHY_CTL_0_DIS_X2_LINK_WIDTH            (1UL<<2)
        #define PCI1_PHY_CTL_0_LINK_LOOPBACK                (1UL<<3)
        #define PCI1_PHY_CTL_0_LINK_DISABLE                 (1UL<<4)
        #define PCI1_PHY_CTL_0_IDL_TO_RLOCK_ENA             (1UL<<5)
        #define PCI1_PHY_CTL_0_UPCONFIG_ENA                 (1UL<<6)
        #define PCI1_PHY_CTL_0_HI_AVAIL_COMPLI_EN           (1UL<<7)
        #define PCI1_PHY_CTL_0_RESERVED                     (0xffffffUL<<8)

    u32_t pci1_phy_ctl_1;
        #define PCI1_PHY_CTL_1_FORCE_16BIT                  (1UL<<0)
        #define PCI1_PHY_CTL_1_AUTO_TRAIN_ENA               (1UL<<1)
        #define PCI1_PHY_CTL_1_LANE_PWRDN_ENA               (1UL<<2)
        #define PCI1_PHY_CTL_1_P2_PWRDWN_ENA                (1UL<<3)
        #define PCI1_PHY_CTL_1_FAREND_LPBK_REQ              (1UL<<4)
        #define PCI1_PHY_CTL_1_DIS_SKIP_IN_SPEED            (1UL<<5)
        #define PCI1_PHY_CTL_1_RESERVED1                    (1UL<<6)
        #define PCI1_PHY_CTL_1_EIDL_DLY                     (0x1fUL<<7)
        #define PCI1_PHY_CTL_1_RESERVED                     (0xfffffUL<<12)

    u32_t pci1_phy_ctl_2;
    u32_t pci1_phy_ctl_3;
    u32_t pci1_phy_ctl_4;
        #define PCI1_PHY_CTL_4_PRESCALE                     (0x7ffUL<<0)
        #define PCI1_PHY_CTL_4_RESERVED_B                   (0x1fUL<<11)
        #define PCI1_PHY_CTL_4_EIDL_RX_MAX                  (0x7ffUL<<16)
        #define PCI1_PHY_CTL_4_EIDL_RX_PRESCALE             (1UL<<27)
        #define PCI1_PHY_CTL_4_RESERVED                     (0xfUL<<28)

    u32_t pci1_phy_ctl_5;
        #define PCI1_PHY_CTL_5_EIDL_TX_GOOD_MAX             (0x7ffUL<<0)
        #define PCI1_PHY_CTL_5_RESERVED_2                   (0x1fUL<<11)
        #define PCI1_PHY_CTL_5_EIDL_TX_BAD_MAX              (0x7ffUL<<16)
        #define PCI1_PHY_CTL_5_RESERVED                     (0x1fUL<<27)

    u32_t pci1_phy_ctl_6;
        #define PCI1_PHY_CTL_6_EIDL_INF_COM_MAX             (0x7ffUL<<0)
        #define PCI1_PHY_CTL_6_EIDL_INF_COM_PRESCALE        (1UL<<11)
        #define PCI1_PHY_CTL_6_RESERVED                     (0x7UL<<12)
        #define PCI1_PHY_CTL_6_EIDL_INF_EIES_PRESCALE       (1UL<<15)
        #define PCI1_PHY_CTL_6_EIDL_INF_EIES_MAX            (0xffffUL<<16)

    u32_t pci1_phy_ctl_7;
        #define PCI1_PHY_CTL_7_L1_MIN_WAIT_MAX              (0x3fUL<<0)
        #define PCI1_PHY_CTL_7_RESERVED1                    (0x3ffUL<<6)
        #define PCI1_PHY_CTL_7_DETECT_MIN_WAIT_MAX          (0x3fffUL<<16)
        #define PCI1_PHY_CTL_7_RESERVED                     (0x3UL<<30)

    u32_t pci1_phy_err_attn_vec;
        #define PCI1_PHY_ERR_ATTN_VEC_ELASTIC_ERR           (1UL<<0)
        #define PCI1_PHY_ERR_ATTN_VEC_DISPARITY_ERR         (1UL<<1)
        #define PCI1_PHY_ERR_ATTN_VEC_DECODE_ERR            (1UL<<2)
        #define PCI1_PHY_ERR_ATTN_VEC_LINK_IS_SKEW          (1UL<<3)
        #define PCI1_PHY_ERR_ATTN_VEC_TRAIN_ERR             (1UL<<4)
        #define PCI1_PHY_ERR_ATTN_VEC_L0S_MAIN_ERR          (1UL<<5)
        #define PCI1_PHY_ERR_ATTN_VEC_RETRAIN_REQ           (1UL<<6)
        #define PCI1_PHY_ERR_ATTN_VEC_CC_ERR_STATUS         (1UL<<7)
        #define PCI1_PHY_ERR_ATTN_VEC_RESERVED              (0xffffffUL<<8)

    u32_t pci1_phy_err_attn_mask;
        #define PCI1_PHY_ERR_ATTN_MASK_MASK_ELASTIC_ERR     (1UL<<0)
        #define PCI1_PHY_ERR_ATTN_MASK_MASK_DISPARITY_ERR   (1UL<<1)
        #define PCI1_PHY_ERR_ATTN_MASK_MASK_DECODE_ERR      (1UL<<2)
        #define PCI1_PHY_ERR_ATTN_MASK_MASK_LINK_IS_SKEW    (1UL<<3)
        #define PCI1_PHY_ERR_ATTN_MASK_MASK_TRAIN_ERR       (1UL<<4)
        #define PCI1_PHY_ERR_ATTN_MASK_MASK_L0S_MAIN_ERR    (1UL<<5)
        #define PCI1_PHY_ERR_ATTN_MASK_MASK_RETRAIN_REQ     (1UL<<6)
        #define PCI1_PHY_ERR_ATTN_MASK_MASK_CC_ERR_STATUS   (1UL<<7)
        #define PCI1_PHY_ERR_ATTN_MASK_RESERVED             (0xffffffUL<<8)

    u32_t unused_32[307];
    u32_t pci1_phy_ltssm_hist_0;
        #define PCI1_PHY_LTSSM_HIST_0_LTSSM_HIST_0          (0xffffffffUL<<0)

    u32_t pci1_phy_ltssm_hist_1;
        #define PCI1_PHY_LTSSM_HIST_1_LTSSM_HIST_1          (0xffffffffUL<<0)

    u32_t pci1_phy_ltssm_hist_2;
        #define PCI1_PHY_LTSSM_HIST_2_LTSSM_HIST_2          (0xffffffffUL<<0)

    u32_t pci1_phy_dbg_0;
        #define PCI1_PHY_DBG_0_PHY_DBG_0                    (0xffffffffUL<<0)

    u32_t pci1_phy_dbg_1;
        #define PCI1_PHY_DBG_1_PHY_DBG_1                    (0xffffffffUL<<0)

    u32_t pci1_phy_dbg_2;
        #define PCI1_PHY_DBG_2_PHY_DBG_2                    (0xffffffffUL<<0)

    u32_t pci1_phy_dbg_3;
        #define PCI1_PHY_DBG_3_PHY_DBG_3                    (0xffffffffUL<<0)

    u32_t pci1_phy_dbg_4;
        #define PCI1_PHY_DBG_4_PHY_DBG_4                    (0xffffffffUL<<0)

    u32_t pci1_phy_dbg_5;
        #define PCI1_PHY_DBG_5_PHY_DBG_5                    (0xffffffffUL<<0)

    u32_t pci1_phy_dbg_6;
        #define PCI1_PHY_DBG_6_PHY_DBG_6                    (0xffffffffUL<<0)

    u32_t pci1_phy_dbg_7;
        #define PCI1_PHY_DBG_7_PHY_DBG_7                    (0xffffffffUL<<0)

    u32_t pci1_phy_dbg_8;
        #define PCI1_PHY_DBG_8_PHY_DBG_8                    (0xffffffffUL<<0)

    u32_t pci1_phy_dbg_9;
        #define PCI1_PHY_DBG_9_PHY_DBG_9                    (0xffffffffUL<<0)

    u32_t pci1_phy_dbg_10;
        #define PCI1_PHY_DBG_10_PHY_DBG_10                  (0xffffffffUL<<0)

    u32_t pci1_phy_dbg_11;
        #define PCI1_PHY_DBG_11_PHY_DBG_11                  (0xffffffffUL<<0)

    u32_t unused_33[180];
    u32_t pci1_function1[1536];
    u32_t unused_34[12800];
} pcie_reg_t;


/*
 *  misc_reg definition
 *  offset: 0x800
 */
typedef struct misc_reg
{
    u32_t misc_command;
        #define MISC_COMMAND_ENABLE_ALL                     (1UL<<0)
        #define MISC_COMMAND_DISABLE_ALL                    (1UL<<1)
        #define MISC_COMMAND_SW_RESET                       (1UL<<4)
        #define MISC_COMMAND_POR_RESET                      (1UL<<5)
        #define MISC_COMMAND_HD_RESET                       (1UL<<6)
        #define MISC_COMMAND_CMN_SW_RESET                   (1UL<<7)
        #define MISC_COMMAND_PAR_ERROR                      (1UL<<8)
        #define MISC_COMMAND_CS16_ERR                       (1UL<<9)
        #define MISC_COMMAND_CS16_ERR_LOC                   (0xfUL<<12)
        #define MISC_COMMAND_PAR_ERR_RAM                    (0x7fUL<<16)
        #define MISC_COMMAND_POWERDOWN_EVENT                (1UL<<23)
        #define MISC_COMMAND_SW_SHUTDOWN                    (1UL<<24)
        #define MISC_COMMAND_SHUTDOWN_EN                    (1UL<<25)
        #define MISC_COMMAND_DINTEG_ATTN_EN                 (1UL<<26)
        #define MISC_COMMAND_PCIE_LINK_IN_L23               (1UL<<27)
        #define MISC_COMMAND_PCIE_DIS                       (1UL<<28)

    u32_t misc_cfg;
        #define MISC_CFG_GRC_TMOUT                          (1UL<<0)
        #define MISC_CFG_NVM_WR_EN                          (0x3UL<<1)
            #define MISC_CFG_NVM_WR_EN_PROTECT              (0UL<<1)
            #define MISC_CFG_NVM_WR_EN_PCI                  (1UL<<1)
            #define MISC_CFG_NVM_WR_EN_ALLOW                (2UL<<1)
            #define MISC_CFG_NVM_WR_EN_ALLOW2               (3UL<<1)
        #define MISC_CFG_BIST_EN                            (1UL<<3)
        #define MISC_CFG_CK25_OUT_ALT_SRC                   (1UL<<4)
        #define MISC_CFG_RESERVED5_TE                          (1UL<<5)
        #define MISC_CFG_RESERVED6_TE                          (1UL<<6)
        #define MISC_CFG_CLK_CTL_OVERRIDE_TE                   (1UL<<7)
        #define MISC_CFG_LEDMODE_TE                            (0x7UL<<8)
            #define MISC_CFG_LEDMODE_MAC_TE                    (0UL<<8)
            #define MISC_CFG_LEDMODE_PHY1_TE                   (1UL<<8)
            #define MISC_CFG_LEDMODE_PHY2_TE                   (2UL<<8)
            #define MISC_CFG_LEDMODE_PHY3_TE                   (3UL<<8)
            #define MISC_CFG_LEDMODE_PHY4_TE                   (4UL<<8)
            #define MISC_CFG_LEDMODE_PHY5_TE                   (5UL<<8)
            #define MISC_CFG_LEDMODE_PHY6_TE                   (6UL<<8)
            #define MISC_CFG_LEDMODE_PHY7_TE                   (7UL<<8)
        #define MISC_CFG_MCP_GRC_TMOUT_TE                      (1UL<<11)
        #define MISC_CFG_DBU_GRC_TMOUT_TE                      (1UL<<12)
        #define MISC_CFG_LEDMODE_XI                            (0xfUL<<8)
            #define MISC_CFG_LEDMODE_MAC_XI                    (0UL<<8)
            #define MISC_CFG_LEDMODE_PHY1_XI                   (1UL<<8)
            #define MISC_CFG_LEDMODE_PHY2_XI                   (2UL<<8)
            #define MISC_CFG_LEDMODE_PHY3_XI                   (3UL<<8)
            #define MISC_CFG_LEDMODE_MAC2_XI                   (4UL<<8)
            #define MISC_CFG_LEDMODE_PHY4_XI                   (5UL<<8)
            #define MISC_CFG_LEDMODE_PHY5_XI                   (6UL<<8)
            #define MISC_CFG_LEDMODE_PHY6_XI                   (7UL<<8)
            #define MISC_CFG_LEDMODE_MAC3_XI                   (8UL<<8)
            #define MISC_CFG_LEDMODE_PHY7_XI                   (9UL<<8)
            #define MISC_CFG_LEDMODE_PHY8_XI                   (10UL<<8)
            #define MISC_CFG_LEDMODE_PHY9_XI                   (11UL<<8)
            #define MISC_CFG_LEDMODE_MAC4_XI                   (12UL<<8)
            #define MISC_CFG_LEDMODE_PHY10_XI                  (13UL<<8)
            #define MISC_CFG_LEDMODE_PHY11_XI                  (14UL<<8)
            #define MISC_CFG_LEDMODE_UNUSED_XI                 (15UL<<8)
        #define MISC_CFG_PORT_SELECT_XI                        (1UL<<13)
        #define MISC_CFG_PARITY_MODE_XI                        (1UL<<14)

    u32_t misc_id;
        #define MISC_ID_BOND_ID                             (0xfUL<<0)
            #define MISC_ID_BOND_ID_X                       (0UL<<0)
            #define MISC_ID_BOND_ID_C                       (3UL<<0)
            #define MISC_ID_BOND_ID_S                       (12UL<<0)
        #define MISC_ID_CHIP_METAL                          (0xffUL<<4)
        #define MISC_ID_CHIP_REV                            (0xfUL<<12)
        #define MISC_ID_CHIP_NUM                            (0xffffUL<<16)

    u32_t misc_enable_status_bits;
        #define MISC_ENABLE_STATUS_BITS_TX_SCHEDULER_ENABLE  (1UL<<0)
        #define MISC_ENABLE_STATUS_BITS_TX_BD_READ_ENABLE   (1UL<<1)
        #define MISC_ENABLE_STATUS_BITS_TX_BD_CACHE_ENABLE  (1UL<<2)
        #define MISC_ENABLE_STATUS_BITS_TX_PROCESSOR_ENABLE  (1UL<<3)
        #define MISC_ENABLE_STATUS_BITS_TX_DMA_ENABLE       (1UL<<4)
        #define MISC_ENABLE_STATUS_BITS_TX_PATCHUP_ENABLE   (1UL<<5)
        #define MISC_ENABLE_STATUS_BITS_TX_PAYLOAD_Q_ENABLE  (1UL<<6)
        #define MISC_ENABLE_STATUS_BITS_TX_HEADER_Q_ENABLE  (1UL<<7)
        #define MISC_ENABLE_STATUS_BITS_TX_ASSEMBLER_ENABLE  (1UL<<8)
        #define MISC_ENABLE_STATUS_BITS_EMAC_ENABLE         (1UL<<9)
        #define MISC_ENABLE_STATUS_BITS_RX_PARSER_MAC_ENABLE  (1UL<<10)
        #define MISC_ENABLE_STATUS_BITS_RX_PARSER_CATCHUP_ENABLE  (1UL<<11)
        #define MISC_ENABLE_STATUS_BITS_RX_MBUF_ENABLE      (1UL<<12)
        #define MISC_ENABLE_STATUS_BITS_RX_LOOKUP_ENABLE    (1UL<<13)
        #define MISC_ENABLE_STATUS_BITS_RX_PROCESSOR_ENABLE  (1UL<<14)
        #define MISC_ENABLE_STATUS_BITS_RX_V2P_ENABLE       (1UL<<15)
        #define MISC_ENABLE_STATUS_BITS_RX_BD_CACHE_ENABLE  (1UL<<16)
        #define MISC_ENABLE_STATUS_BITS_RX_DMA_ENABLE       (1UL<<17)
        #define MISC_ENABLE_STATUS_BITS_COMPLETION_ENABLE   (1UL<<18)
        #define MISC_ENABLE_STATUS_BITS_HOST_COALESCE_ENABLE  (1UL<<19)
        #define MISC_ENABLE_STATUS_BITS_MAILBOX_QUEUE_ENABLE  (1UL<<20)
        #define MISC_ENABLE_STATUS_BITS_CONTEXT_ENABLE      (1UL<<21)
        #define MISC_ENABLE_STATUS_BITS_CMD_SCHEDULER_ENABLE  (1UL<<22)
        #define MISC_ENABLE_STATUS_BITS_CMD_PROCESSOR_ENABLE  (1UL<<23)
        #define MISC_ENABLE_STATUS_BITS_MGMT_PROCESSOR_ENABLE  (1UL<<24)
        #define MISC_ENABLE_STATUS_BITS_TIMER_ENABLE        (1UL<<25)
        #define MISC_ENABLE_STATUS_BITS_DMA_ENGINE_ENABLE   (1UL<<26)
        #define MISC_ENABLE_STATUS_BITS_UMP_ENABLE          (1UL<<27)
        #define MISC_ENABLE_STATUS_BITS_RV2P_CMD_SCHEDULER_ENABLE  (1UL<<28)
        #define MISC_ENABLE_STATUS_BITS_RSVD_FUTURE_ENABLE  (0x7UL<<29)

    u32_t misc_enable_set_bits;
        #define MISC_ENABLE_SET_BITS_TX_SCHEDULER_ENABLE    (1UL<<0)
        #define MISC_ENABLE_SET_BITS_TX_BD_READ_ENABLE      (1UL<<1)
        #define MISC_ENABLE_SET_BITS_TX_BD_CACHE_ENABLE     (1UL<<2)
        #define MISC_ENABLE_SET_BITS_TX_PROCESSOR_ENABLE    (1UL<<3)
        #define MISC_ENABLE_SET_BITS_TX_DMA_ENABLE          (1UL<<4)
        #define MISC_ENABLE_SET_BITS_TX_PATCHUP_ENABLE      (1UL<<5)
        #define MISC_ENABLE_SET_BITS_TX_PAYLOAD_Q_ENABLE    (1UL<<6)
        #define MISC_ENABLE_SET_BITS_TX_HEADER_Q_ENABLE     (1UL<<7)
        #define MISC_ENABLE_SET_BITS_TX_ASSEMBLER_ENABLE    (1UL<<8)
        #define MISC_ENABLE_SET_BITS_EMAC_ENABLE            (1UL<<9)
        #define MISC_ENABLE_SET_BITS_RX_PARSER_MAC_ENABLE   (1UL<<10)
        #define MISC_ENABLE_SET_BITS_RX_PARSER_CATCHUP_ENABLE  (1UL<<11)
        #define MISC_ENABLE_SET_BITS_RX_MBUF_ENABLE         (1UL<<12)
        #define MISC_ENABLE_SET_BITS_RX_LOOKUP_ENABLE       (1UL<<13)
        #define MISC_ENABLE_SET_BITS_RX_PROCESSOR_ENABLE    (1UL<<14)
        #define MISC_ENABLE_SET_BITS_RX_V2P_ENABLE          (1UL<<15)
        #define MISC_ENABLE_SET_BITS_RX_BD_CACHE_ENABLE     (1UL<<16)
        #define MISC_ENABLE_SET_BITS_RX_DMA_ENABLE          (1UL<<17)
        #define MISC_ENABLE_SET_BITS_COMPLETION_ENABLE      (1UL<<18)
        #define MISC_ENABLE_SET_BITS_HOST_COALESCE_ENABLE   (1UL<<19)
        #define MISC_ENABLE_SET_BITS_MAILBOX_QUEUE_ENABLE   (1UL<<20)
        #define MISC_ENABLE_SET_BITS_CONTEXT_ENABLE         (1UL<<21)
        #define MISC_ENABLE_SET_BITS_CMD_SCHEDULER_ENABLE   (1UL<<22)
        #define MISC_ENABLE_SET_BITS_CMD_PROCESSOR_ENABLE   (1UL<<23)
        #define MISC_ENABLE_SET_BITS_MGMT_PROCESSOR_ENABLE  (1UL<<24)
        #define MISC_ENABLE_SET_BITS_TIMER_ENABLE           (1UL<<25)
        #define MISC_ENABLE_SET_BITS_DMA_ENGINE_ENABLE      (1UL<<26)
        #define MISC_ENABLE_SET_BITS_UMP_ENABLE             (1UL<<27)
        #define MISC_ENABLE_SET_BITS_RV2P_CMD_SCHEDULER_ENABLE  (1UL<<28)
        #define MISC_ENABLE_SET_BITS_RSVD_FUTURE_ENABLE     (0x7UL<<29)

    u32_t misc_enable_clr_bits;
        #define MISC_ENABLE_CLR_BITS_TX_SCHEDULER_ENABLE    (1UL<<0)
        #define MISC_ENABLE_CLR_BITS_TX_BD_READ_ENABLE      (1UL<<1)
        #define MISC_ENABLE_CLR_BITS_TX_BD_CACHE_ENABLE     (1UL<<2)
        #define MISC_ENABLE_CLR_BITS_TX_PROCESSOR_ENABLE    (1UL<<3)
        #define MISC_ENABLE_CLR_BITS_TX_DMA_ENABLE          (1UL<<4)
        #define MISC_ENABLE_CLR_BITS_TX_PATCHUP_ENABLE      (1UL<<5)
        #define MISC_ENABLE_CLR_BITS_TX_PAYLOAD_Q_ENABLE    (1UL<<6)
        #define MISC_ENABLE_CLR_BITS_TX_HEADER_Q_ENABLE     (1UL<<7)
        #define MISC_ENABLE_CLR_BITS_TX_ASSEMBLER_ENABLE    (1UL<<8)
        #define MISC_ENABLE_CLR_BITS_EMAC_ENABLE            (1UL<<9)
        #define MISC_ENABLE_CLR_BITS_RX_PARSER_MAC_ENABLE   (1UL<<10)
        #define MISC_ENABLE_CLR_BITS_RX_PARSER_CATCHUP_ENABLE  (1UL<<11)
        #define MISC_ENABLE_CLR_BITS_RX_MBUF_ENABLE         (1UL<<12)
        #define MISC_ENABLE_CLR_BITS_RX_LOOKUP_ENABLE       (1UL<<13)
        #define MISC_ENABLE_CLR_BITS_RX_PROCESSOR_ENABLE    (1UL<<14)
        #define MISC_ENABLE_CLR_BITS_RX_V2P_ENABLE          (1UL<<15)
        #define MISC_ENABLE_CLR_BITS_RX_BD_CACHE_ENABLE     (1UL<<16)
        #define MISC_ENABLE_CLR_BITS_RX_DMA_ENABLE          (1UL<<17)
        #define MISC_ENABLE_CLR_BITS_COMPLETION_ENABLE      (1UL<<18)
        #define MISC_ENABLE_CLR_BITS_HOST_COALESCE_ENABLE   (1UL<<19)
        #define MISC_ENABLE_CLR_BITS_MAILBOX_QUEUE_ENABLE   (1UL<<20)
        #define MISC_ENABLE_CLR_BITS_CONTEXT_ENABLE         (1UL<<21)
        #define MISC_ENABLE_CLR_BITS_CMD_SCHEDULER_ENABLE   (1UL<<22)
        #define MISC_ENABLE_CLR_BITS_CMD_PROCESSOR_ENABLE   (1UL<<23)
        #define MISC_ENABLE_CLR_BITS_MGMT_PROCESSOR_ENABLE  (1UL<<24)
        #define MISC_ENABLE_CLR_BITS_TIMER_ENABLE           (1UL<<25)
        #define MISC_ENABLE_CLR_BITS_DMA_ENGINE_ENABLE      (1UL<<26)
        #define MISC_ENABLE_CLR_BITS_UMP_ENABLE             (1UL<<27)
        #define MISC_ENABLE_CLR_BITS_RV2P_CMD_SCHEDULER_ENABLE  (1UL<<28)
        #define MISC_ENABLE_CLR_BITS_RSVD_FUTURE_ENABLE     (0x7UL<<29)

    u32_t misc_clock_control_bits;
        #define MISC_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET     (0xfUL<<0)
            #define MISC_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_32MHZ  (0UL<<0)
            #define MISC_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_38MHZ  (1UL<<0)
            #define MISC_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_48MHZ  (2UL<<0)
            #define MISC_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_55MHZ  (3UL<<0)
            #define MISC_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_66MHZ  (4UL<<0)
            #define MISC_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_80MHZ  (5UL<<0)
            #define MISC_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_95MHZ  (6UL<<0)
            #define MISC_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_133MHZ  (7UL<<0)
            #define MISC_CLOCK_CONTROL_BITS_PCI_CLK_SPD_DET_LOW  (15UL<<0)
        #define MISC_CLOCK_CONTROL_BITS_CORE_CLK_DISABLE    (1UL<<6)
        #define MISC_CLOCK_CONTROL_BITS_CORE_CLK_ALT        (1UL<<7)
        #define MISC_CLOCK_CONTROL_BITS_CORE_CLK_ALT_SRC_TE    (0x7UL<<8)
            #define MISC_CLOCK_CONTROL_BITS_CORE_CLK_ALT_SRC_UNDEF_TE  (0UL<<8)
            #define MISC_CLOCK_CONTROL_BITS_CORE_CLK_ALT_SRC_12_TE  (1UL<<8)
            #define MISC_CLOCK_CONTROL_BITS_CORE_CLK_ALT_SRC_6_TE  (2UL<<8)
            #define MISC_CLOCK_CONTROL_BITS_CORE_CLK_ALT_SRC_62_TE  (4UL<<8)
        #define MISC_CLOCK_CONTROL_BITS_RESERVED0_XI           (0x7UL<<8)
        #define MISC_CLOCK_CONTROL_BITS_MIN_POWER           (1UL<<11)
        #define MISC_CLOCK_CONTROL_BITS_CORE_CLK_PLL_SPEED_TE  (0xfUL<<12)
            #define MISC_CLOCK_CONTROL_BITS_CORE_CLK_PLL_SPEED_100_TE  (0UL<<12)
            #define MISC_CLOCK_CONTROL_BITS_CORE_CLK_PLL_SPEED_80_TE  (1UL<<12)
            #define MISC_CLOCK_CONTROL_BITS_CORE_CLK_PLL_SPEED_50_TE  (2UL<<12)
            #define MISC_CLOCK_CONTROL_BITS_CORE_CLK_PLL_SPEED_40_TE  (4UL<<12)
            #define MISC_CLOCK_CONTROL_BITS_CORE_CLK_PLL_SPEED_25_TE  (8UL<<12)
        #define MISC_CLOCK_CONTROL_BITS_RESERVED1_XI           (0xfUL<<12)
        #define MISC_CLOCK_CONTROL_BITS_CORE_CLK_PLL_STOP   (1UL<<16)
        #define MISC_CLOCK_CONTROL_BITS_RESERVED_17_TE         (1UL<<17)
        #define MISC_CLOCK_CONTROL_BITS_RESERVED_18_TE         (1UL<<18)
        #define MISC_CLOCK_CONTROL_BITS_RESERVED_19_TE         (1UL<<19)
        #define MISC_CLOCK_CONTROL_BITS_RESERVED_TE            (0xfffUL<<20)
        #define MISC_CLOCK_CONTROL_BITS_CORE_CLK_ALT_MGMT_XI   (1UL<<17)
        #define MISC_CLOCK_CONTROL_BITS_RESERVED2_XI           (0x3fUL<<18)
        #define MISC_CLOCK_CONTROL_BITS_CORE_CLK_PLL_VCO_XI    (0x7UL<<24)
        #define MISC_CLOCK_CONTROL_BITS_RESERVED3_XI           (1UL<<27)
        #define MISC_CLOCK_CONTROL_BITS_CORE_CLK_PLL_SPEED_XI  (0xfUL<<28)

    u32_t misc_spio;
        #define MISC_SPIO_VALUE                             (0xffUL<<0)
        #define MISC_SPIO_SET                               (0xffUL<<8)
        #define MISC_SPIO_CLR                               (0xffUL<<16)
        #define MISC_SPIO_FLOAT                             (0xffUL<<24)

    u32_t misc_spio_int;
        #define MISC_SPIO_INT_INT_STATE_TE                     (0xfUL<<0)
        #define MISC_SPIO_INT_OLD_VALUE_TE                     (0xfUL<<8)
        #define MISC_SPIO_INT_OLD_SET_TE                       (0xfUL<<16)
        #define MISC_SPIO_INT_OLD_CLR_TE                       (0xfUL<<24)
        #define MISC_SPIO_INT_INT_STATE_XI                     (0xffUL<<0)
        #define MISC_SPIO_INT_OLD_VALUE_XI                     (0xffUL<<8)
        #define MISC_SPIO_INT_OLD_SET_XI                       (0xffUL<<16)
        #define MISC_SPIO_INT_OLD_CLR_XI                       (0xffUL<<24)

    u32_t misc_config_lfsr;
        #define MISC_CONFIG_LFSR_DIV                        (0xffffUL<<0)

    u32_t misc_lfsr_mask_bits;
        #define MISC_LFSR_MASK_BITS_TX_SCHEDULER_ENABLE     (1UL<<0)
        #define MISC_LFSR_MASK_BITS_TX_BD_READ_ENABLE       (1UL<<1)
        #define MISC_LFSR_MASK_BITS_TX_BD_CACHE_ENABLE      (1UL<<2)
        #define MISC_LFSR_MASK_BITS_TX_PROCESSOR_ENABLE     (1UL<<3)
        #define MISC_LFSR_MASK_BITS_TX_DMA_ENABLE           (1UL<<4)
        #define MISC_LFSR_MASK_BITS_TX_PATCHUP_ENABLE       (1UL<<5)
        #define MISC_LFSR_MASK_BITS_TX_PAYLOAD_Q_ENABLE     (1UL<<6)
        #define MISC_LFSR_MASK_BITS_TX_HEADER_Q_ENABLE      (1UL<<7)
        #define MISC_LFSR_MASK_BITS_TX_ASSEMBLER_ENABLE     (1UL<<8)
        #define MISC_LFSR_MASK_BITS_EMAC_ENABLE             (1UL<<9)
        #define MISC_LFSR_MASK_BITS_RX_PARSER_MAC_ENABLE    (1UL<<10)
        #define MISC_LFSR_MASK_BITS_RX_PARSER_CATCHUP_ENABLE  (1UL<<11)
        #define MISC_LFSR_MASK_BITS_RX_MBUF_ENABLE          (1UL<<12)
        #define MISC_LFSR_MASK_BITS_RX_LOOKUP_ENABLE        (1UL<<13)
        #define MISC_LFSR_MASK_BITS_RX_PROCESSOR_ENABLE     (1UL<<14)
        #define MISC_LFSR_MASK_BITS_RX_V2P_ENABLE           (1UL<<15)
        #define MISC_LFSR_MASK_BITS_RX_BD_CACHE_ENABLE      (1UL<<16)
        #define MISC_LFSR_MASK_BITS_RX_DMA_ENABLE           (1UL<<17)
        #define MISC_LFSR_MASK_BITS_COMPLETION_ENABLE       (1UL<<18)
        #define MISC_LFSR_MASK_BITS_HOST_COALESCE_ENABLE    (1UL<<19)
        #define MISC_LFSR_MASK_BITS_MAILBOX_QUEUE_ENABLE    (1UL<<20)
        #define MISC_LFSR_MASK_BITS_CONTEXT_ENABLE          (1UL<<21)
        #define MISC_LFSR_MASK_BITS_CMD_SCHEDULER_ENABLE    (1UL<<22)
        #define MISC_LFSR_MASK_BITS_CMD_PROCESSOR_ENABLE    (1UL<<23)
        #define MISC_LFSR_MASK_BITS_MGMT_PROCESSOR_ENABLE   (1UL<<24)
        #define MISC_LFSR_MASK_BITS_TIMER_ENABLE            (1UL<<25)
        #define MISC_LFSR_MASK_BITS_DMA_ENGINE_ENABLE       (1UL<<26)
        #define MISC_LFSR_MASK_BITS_UMP_ENABLE              (1UL<<27)
        #define MISC_LFSR_MASK_BITS_RV2P_CMD_SCHEDULER_ENABLE  (1UL<<28)
        #define MISC_LFSR_MASK_BITS_RSVD_FUTURE_ENABLE      (0x7UL<<29)

    u32_t misc_arb_req[5];
    u32_t misc_arb_free[5];
    u32_t misc_arb_req_status[5];
    u32_t misc_arb_gnt0;
        #define MISC_ARB_GNT0_0                             (0x7UL<<0)
        #define MISC_ARB_GNT0_1                             (0x7UL<<4)
        #define MISC_ARB_GNT0_2                             (0x7UL<<8)
        #define MISC_ARB_GNT0_3                             (0x7UL<<12)
        #define MISC_ARB_GNT0_4                             (0x7UL<<16)
        #define MISC_ARB_GNT0_5                             (0x7UL<<20)
        #define MISC_ARB_GNT0_6                             (0x7UL<<24)
        #define MISC_ARB_GNT0_7                             (0x7UL<<28)

    u32_t misc_arb_gnt1;
        #define MISC_ARB_GNT1_8                             (0x7UL<<0)
        #define MISC_ARB_GNT1_9                             (0x7UL<<4)
        #define MISC_ARB_GNT1_10                            (0x7UL<<8)
        #define MISC_ARB_GNT1_11                            (0x7UL<<12)
        #define MISC_ARB_GNT1_12                            (0x7UL<<16)
        #define MISC_ARB_GNT1_13                            (0x7UL<<20)
        #define MISC_ARB_GNT1_14                            (0x7UL<<24)
        #define MISC_ARB_GNT1_15                            (0x7UL<<28)

    u32_t misc_arb_gnt2;
        #define MISC_ARB_GNT2_16                            (0x7UL<<0)
        #define MISC_ARB_GNT2_17                            (0x7UL<<4)
        #define MISC_ARB_GNT2_18                            (0x7UL<<8)
        #define MISC_ARB_GNT2_19                            (0x7UL<<12)
        #define MISC_ARB_GNT2_20                            (0x7UL<<16)
        #define MISC_ARB_GNT2_21                            (0x7UL<<20)
        #define MISC_ARB_GNT2_22                            (0x7UL<<24)
        #define MISC_ARB_GNT2_23                            (0x7UL<<28)

    u32_t misc_arb_gnt3;
        #define MISC_ARB_GNT3_24                            (0x7UL<<0)
        #define MISC_ARB_GNT3_25                            (0x7UL<<4)
        #define MISC_ARB_GNT3_26                            (0x7UL<<8)
        #define MISC_ARB_GNT3_27                            (0x7UL<<12)
        #define MISC_ARB_GNT3_28                            (0x7UL<<16)
        #define MISC_ARB_GNT3_29                            (0x7UL<<20)
        #define MISC_ARB_GNT3_30                            (0x7UL<<24)
        #define MISC_ARB_GNT3_31                            (0x7UL<<28)

    u32_t misc_reserved1;
        #define MISC_RESERVED1_MISC_RESERVED1_VALUE         (0x3fUL<<0)

    u32_t misc_reserved2;
        #define MISC_RESERVED2_PCIE_DIS                     (1UL<<0)
        #define MISC_RESERVED2_LINK_IN_L23                  (1UL<<1)

    u32_t misc_sm_asf_control;
        #define MISC_SM_ASF_CONTROL_ASF_RST                 (1UL<<0)
        #define MISC_SM_ASF_CONTROL_TSC_EN                  (1UL<<1)
        #define MISC_SM_ASF_CONTROL_WG_TO                   (1UL<<2)
        #define MISC_SM_ASF_CONTROL_HB_TO                   (1UL<<3)
        #define MISC_SM_ASF_CONTROL_PA_TO                   (1UL<<4)
        #define MISC_SM_ASF_CONTROL_PL_TO                   (1UL<<5)
        #define MISC_SM_ASF_CONTROL_RT_TO                   (1UL<<6)
        #define MISC_SM_ASF_CONTROL_SMB_EVENT               (1UL<<7)
        #define MISC_SM_ASF_CONTROL_STRETCH_EN              (1UL<<8)
        #define MISC_SM_ASF_CONTROL_STRETCH_PULSE           (1UL<<9)
        #define MISC_SM_ASF_CONTROL_RES                     (0x3UL<<10)
        #define MISC_SM_ASF_CONTROL_SMB_EN                  (1UL<<12)
        #define MISC_SM_ASF_CONTROL_SMB_BB_EN               (1UL<<13)
        #define MISC_SM_ASF_CONTROL_SMB_NO_ADDR_FILT        (1UL<<14)
        #define MISC_SM_ASF_CONTROL_SMB_AUTOREAD            (1UL<<15)
        #define MISC_SM_ASF_CONTROL_NIC_SMB_ADDR1           (0x7fUL<<16)
        #define MISC_SM_ASF_CONTROL_NIC_SMB_ADDR2           (0x7fUL<<23)
        #define MISC_SM_ASF_CONTROL_EN_NIC_SMB_ADDR_0       (1UL<<30)
        #define MISC_SM_ASF_CONTROL_SMB_EARLY_ATTN          (1UL<<31)

    u32_t misc_smb_in;
        #define MISC_SMB_IN_DAT_IN                          (0xffUL<<0)
        #define MISC_SMB_IN_RDY                             (1UL<<8)
        #define MISC_SMB_IN_DONE                            (1UL<<9)
        #define MISC_SMB_IN_FIRSTBYTE                       (1UL<<10)
        #define MISC_SMB_IN_STATUS                          (0x7UL<<11)
            #define MISC_SMB_IN_STATUS_OK                   (0UL<<11)
            #define MISC_SMB_IN_STATUS_PEC                  (1UL<<11)
            #define MISC_SMB_IN_STATUS_OFLOW                (2UL<<11)
            #define MISC_SMB_IN_STATUS_STOP                 (3UL<<11)
            #define MISC_SMB_IN_STATUS_TIMEOUT              (4UL<<11)

    u32_t misc_smb_out;
        #define MISC_SMB_OUT_DAT_OUT                        (0xffUL<<0)
        #define MISC_SMB_OUT_RDY                            (1UL<<8)
        #define MISC_SMB_OUT_START                          (1UL<<9)
        #define MISC_SMB_OUT_LAST                           (1UL<<10)
        #define MISC_SMB_OUT_ACC_TYPE                       (1UL<<11)
        #define MISC_SMB_OUT_ENB_PEC                        (1UL<<12)
        #define MISC_SMB_OUT_GET_RX_LEN                     (1UL<<13)
        #define MISC_SMB_OUT_SMB_READ_LEN                   (0x3fUL<<14)
        #define MISC_SMB_OUT_SMB_OUT_STATUS                 (0xfUL<<20)
            #define MISC_SMB_OUT_SMB_OUT_STATUS_OK          (0UL<<20)
            #define MISC_SMB_OUT_SMB_OUT_STATUS_FIRST_NACK  (1UL<<20)
            #define MISC_SMB_OUT_SMB_OUT_STATUS_UFLOW       (2UL<<20)
            #define MISC_SMB_OUT_SMB_OUT_STATUS_STOP        (3UL<<20)
            #define MISC_SMB_OUT_SMB_OUT_STATUS_TIMEOUT     (4UL<<20)
            #define MISC_SMB_OUT_SMB_OUT_STATUS_FIRST_LOST  (5UL<<20)
            #define MISC_SMB_OUT_SMB_OUT_STATUS_BADACK      (6UL<<20)
            #define MISC_SMB_OUT_SMB_OUT_STATUS_SUB_NACK    (9UL<<20)
            #define MISC_SMB_OUT_SMB_OUT_STATUS_SUB_LOST    (13UL<<20)
        #define MISC_SMB_OUT_SMB_OUT_SLAVEMODE              (1UL<<24)
        #define MISC_SMB_OUT_SMB_OUT_DAT_EN                 (1UL<<25)
        #define MISC_SMB_OUT_SMB_OUT_DAT_IN                 (1UL<<26)
        #define MISC_SMB_OUT_SMB_OUT_CLK_EN                 (1UL<<27)
        #define MISC_SMB_OUT_SMB_OUT_CLK_IN                 (1UL<<28)

    u32_t misc_smb_watchdog;
        #define MISC_SMB_WATCHDOG_WATCHDOG                  (0xffffUL<<0)

    u32_t misc_smb_heartbeat;
        #define MISC_SMB_HEARTBEAT_HEARTBEAT                (0xffffUL<<0)

    u32_t misc_smb_poll_asf;
        #define MISC_SMB_POLL_ASF_POLL_ASF                  (0xffffUL<<0)

    u32_t misc_smb_poll_legacy;
        #define MISC_SMB_POLL_LEGACY_POLL_LEGACY            (0xffffUL<<0)

    u32_t misc_smb_retran;
        #define MISC_SMB_RETRAN_RETRAN                      (0xffUL<<0)

    u32_t misc_smb_timestamp;
        #define MISC_SMB_TIMESTAMP_TIMESTAMP                (0xffffffffUL<<0)

    u32_t misc_perr_ena0;
        #define MISC_PERR_ENA0_COM_MISC_CTXC_TE                (1UL<<0)
        #define MISC_PERR_ENA0_COM_MISC_REGF_TE                (1UL<<1)
        #define MISC_PERR_ENA0_COM_MISC_SCPAD_TE               (1UL<<2)
        #define MISC_PERR_ENA0_CP_MISC_CTXC_TE                 (1UL<<3)
        #define MISC_PERR_ENA0_CP_MISC_REGF_TE                 (1UL<<4)
        #define MISC_PERR_ENA0_CP_MISC_SCPAD_TE                (1UL<<5)
        #define MISC_PERR_ENA0_CS_MISC_TMEM_TE                 (1UL<<6)
        #define MISC_PERR_ENA0_CTX_MISC_ACCM0_TE               (1UL<<7)
        #define MISC_PERR_ENA0_CTX_MISC_ACCM1_TE               (1UL<<8)
        #define MISC_PERR_ENA0_CTX_MISC_ACCM2_TE               (1UL<<9)
        #define MISC_PERR_ENA0_CTX_MISC_ACCM3_TE               (1UL<<10)
        #define MISC_PERR_ENA0_CTX_MISC_ACCM4_TE               (1UL<<11)
        #define MISC_PERR_ENA0_CTX_MISC_ACCM5_TE               (1UL<<12)
        #define MISC_PERR_ENA0_CTX_MISC_PGTBL_TE               (1UL<<13)
        #define MISC_PERR_ENA0_DMAE_MISC_DR0_TE                (1UL<<14)
        #define MISC_PERR_ENA0_DMAE_MISC_DR1_TE                (1UL<<15)
        #define MISC_PERR_ENA0_DMAE_MISC_DR2_TE                (1UL<<16)
        #define MISC_PERR_ENA0_DMAE_MISC_DR3_TE                (1UL<<17)
        #define MISC_PERR_ENA0_DMAE_MISC_DR4_TE                (1UL<<18)
        #define MISC_PERR_ENA0_DMAE_MISC_DW0_TE                (1UL<<19)
        #define MISC_PERR_ENA0_DMAE_MISC_DW1_TE                (1UL<<20)
        #define MISC_PERR_ENA0_DMAE_MISC_DW2_TE                (1UL<<21)
        #define MISC_PERR_ENA0_HC_MISC_DMA_TE                  (1UL<<22)
        #define MISC_PERR_ENA0_MCP_MISC_REGF_TE                (1UL<<23)
        #define MISC_PERR_ENA0_MCP_MISC_SCPAD_TE               (1UL<<24)
        #define MISC_PERR_ENA0_MQ_MISC_CTX_TE                  (1UL<<25)
        #define MISC_PERR_ENA0_RBDC_MISC_TE                    (1UL<<26)
        #define MISC_PERR_ENA0_RBUF_MISC_MB_TE                 (1UL<<27)
        #define MISC_PERR_ENA0_RBUF_MISC_PTR_TE                (1UL<<28)
        #define MISC_PERR_ENA0_RDE_MISC_RPC_TE                 (1UL<<29)
        #define MISC_PERR_ENA0_RDE_MISC_RPM_TE                 (1UL<<30)
        #define MISC_PERR_ENA0_RV2P_MISC_CB0REGS_TE            (1UL<<31)
        #define MISC_PERR_ENA0_COM_DMAE_PERR_EN_XI             (1UL<<0)
        #define MISC_PERR_ENA0_CP_DMAE_PERR_EN_XI              (1UL<<1)
        #define MISC_PERR_ENA0_RPM_ACPIBEMEM_PERR_EN_XI        (1UL<<2)
        #define MISC_PERR_ENA0_CTX_USAGE_CNT_PERR_EN_XI        (1UL<<3)
        #define MISC_PERR_ENA0_CTX_PGTBL_PERR_EN_XI            (1UL<<4)
        #define MISC_PERR_ENA0_CTX_CACHE_PERR_EN_XI            (1UL<<5)
        #define MISC_PERR_ENA0_CTX_MIRROR_PERR_EN_XI           (1UL<<6)
        #define MISC_PERR_ENA0_COM_CTXC_PERR_EN_XI             (1UL<<7)
        #define MISC_PERR_ENA0_COM_SCPAD_PERR_EN_XI            (1UL<<8)
        #define MISC_PERR_ENA0_CP_CTXC_PERR_EN_XI              (1UL<<9)
        #define MISC_PERR_ENA0_CP_SCPAD_PERR_EN_XI             (1UL<<10)
        #define MISC_PERR_ENA0_RXP_RBUFC_PERR_EN_XI            (1UL<<11)
        #define MISC_PERR_ENA0_RXP_CTXC_PERR_EN_XI             (1UL<<12)
        #define MISC_PERR_ENA0_RXP_SCPAD_PERR_EN_XI            (1UL<<13)
        #define MISC_PERR_ENA0_TPAT_SCPAD_PERR_EN_XI           (1UL<<14)
        #define MISC_PERR_ENA0_TXP_CTXC_PERR_EN_XI             (1UL<<15)
        #define MISC_PERR_ENA0_TXP_SCPAD_PERR_EN_XI            (1UL<<16)
        #define MISC_PERR_ENA0_CS_TMEM_PERR_EN_XI              (1UL<<17)
        #define MISC_PERR_ENA0_MQ_CTX_PERR_EN_XI               (1UL<<18)
        #define MISC_PERR_ENA0_RPM_DFIFOMEM_PERR_EN_XI         (1UL<<19)
        #define MISC_PERR_ENA0_RPC_DFIFOMEM_PERR_EN_XI         (1UL<<20)
        #define MISC_PERR_ENA0_RBUF_PTRMEM_PERR_EN_XI          (1UL<<21)
        #define MISC_PERR_ENA0_RBUF_DATAMEM_PERR_EN_XI         (1UL<<22)
        #define MISC_PERR_ENA0_RV2P_P2IRAM_PERR_EN_XI          (1UL<<23)
        #define MISC_PERR_ENA0_RV2P_P1IRAM_PERR_EN_XI          (1UL<<24)
        #define MISC_PERR_ENA0_RV2P_CB1REGS_PERR_EN_XI         (1UL<<25)
        #define MISC_PERR_ENA0_RV2P_CB0REGS_PERR_EN_XI         (1UL<<26)
        #define MISC_PERR_ENA0_TPBUF_PERR_EN_XI                (1UL<<27)
        #define MISC_PERR_ENA0_THBUF_PERR_EN_XI                (1UL<<28)
        #define MISC_PERR_ENA0_TDMA_PERR_EN_XI                 (1UL<<29)
        #define MISC_PERR_ENA0_TBDC_PERR_EN_XI                 (1UL<<30)
        #define MISC_PERR_ENA0_TSCH_LR_PERR_EN_XI              (1UL<<31)

    u32_t misc_perr_ena1;
        #define MISC_PERR_ENA1_RV2P_MISC_CB1REGS_TE            (1UL<<0)
        #define MISC_PERR_ENA1_RV2P_MISC_P1IRAM_TE             (1UL<<1)
        #define MISC_PERR_ENA1_RV2P_MISC_P2IRAM_TE             (1UL<<2)
        #define MISC_PERR_ENA1_RXP_MISC_CTXC_TE                (1UL<<3)
        #define MISC_PERR_ENA1_RXP_MISC_REGF_TE                (1UL<<4)
        #define MISC_PERR_ENA1_RXP_MISC_SCPAD_TE               (1UL<<5)
        #define MISC_PERR_ENA1_RXP_MISC_RBUFC_TE               (1UL<<6)
        #define MISC_PERR_ENA1_TBDC_MISC_TE                    (1UL<<7)
        #define MISC_PERR_ENA1_TDMA_MISC_TE                    (1UL<<8)
        #define MISC_PERR_ENA1_THBUF_MISC_MB0_TE               (1UL<<9)
        #define MISC_PERR_ENA1_THBUF_MISC_MB1_TE               (1UL<<10)
        #define MISC_PERR_ENA1_TPAT_MISC_REGF_TE               (1UL<<11)
        #define MISC_PERR_ENA1_TPAT_MISC_SCPAD_TE              (1UL<<12)
        #define MISC_PERR_ENA1_TPBUF_MISC_MB_TE                (1UL<<13)
        #define MISC_PERR_ENA1_TSCH_MISC_LR_TE                 (1UL<<14)
        #define MISC_PERR_ENA1_TXP_MISC_CTXC_TE                (1UL<<15)
        #define MISC_PERR_ENA1_TXP_MISC_REGF_TE                (1UL<<16)
        #define MISC_PERR_ENA1_TXP_MISC_SCPAD_TE               (1UL<<17)
        #define MISC_PERR_ENA1_UMP_MISC_FIORX_TE               (1UL<<18)
        #define MISC_PERR_ENA1_UMP_MISC_FIOTX_TE               (1UL<<19)
        #define MISC_PERR_ENA1_UMP_MISC_RX_TE                  (1UL<<20)
        #define MISC_PERR_ENA1_UMP_MISC_TX_TE                  (1UL<<21)
        #define MISC_PERR_ENA1_RDMAQ_MISC_TE                   (1UL<<22)
        #define MISC_PERR_ENA1_CSQ_MISC_TE                     (1UL<<23)
        #define MISC_PERR_ENA1_CPQ_MISC_TE                     (1UL<<24)
        #define MISC_PERR_ENA1_MCPQ_MISC_TE                    (1UL<<25)
        #define MISC_PERR_ENA1_RV2PMQ_MISC_TE                  (1UL<<26)
        #define MISC_PERR_ENA1_RV2PPQ_MISC_TE                  (1UL<<27)
        #define MISC_PERR_ENA1_RV2PTQ_MISC_TE                  (1UL<<28)
        #define MISC_PERR_ENA1_RXPQ_MISC_TE                    (1UL<<29)
        #define MISC_PERR_ENA1_RXPCQ_MISC_TE                   (1UL<<30)
        #define MISC_PERR_ENA1_RLUPQ_MISC_TE                   (1UL<<31)
        #define MISC_PERR_ENA1_RBDC_PERR_EN_XI                 (1UL<<0)
        #define MISC_PERR_ENA1_RDMA_DFIFO_PERR_EN_XI           (1UL<<2)
        #define MISC_PERR_ENA1_HC_STATS_PERR_EN_XI             (1UL<<3)
        #define MISC_PERR_ENA1_HC_MSIX_PERR_EN_XI              (1UL<<4)
        #define MISC_PERR_ENA1_HC_PRODUCSTB_PERR_EN_XI         (1UL<<5)
        #define MISC_PERR_ENA1_HC_CONSUMSTB_PERR_EN_XI         (1UL<<6)
        #define MISC_PERR_ENA1_TPATQ_PERR_EN_XI                (1UL<<7)
        #define MISC_PERR_ENA1_MCPQ_PERR_EN_XI                 (1UL<<8)
        #define MISC_PERR_ENA1_TDMAQ_PERR_EN_XI                (1UL<<9)
        #define MISC_PERR_ENA1_TXPQ_PERR_EN_XI                 (1UL<<10)
        #define MISC_PERR_ENA1_COMTQ_PERR_EN_XI                (1UL<<11)
        #define MISC_PERR_ENA1_COMQ_PERR_EN_XI                 (1UL<<12)
        #define MISC_PERR_ENA1_RLUPQ_PERR_EN_XI                (1UL<<13)
        #define MISC_PERR_ENA1_RXPQ_PERR_EN_XI                 (1UL<<14)
        #define MISC_PERR_ENA1_RV2PPQ_PERR_EN_XI               (1UL<<15)
        #define MISC_PERR_ENA1_RDMAQ_PERR_EN_XI                (1UL<<16)
        #define MISC_PERR_ENA1_TASQ_PERR_EN_XI                 (1UL<<17)
        #define MISC_PERR_ENA1_TBDRQ_PERR_EN_XI                (1UL<<18)
        #define MISC_PERR_ENA1_TSCHQ_PERR_EN_XI                (1UL<<19)
        #define MISC_PERR_ENA1_COMXQ_PERR_EN_XI                (1UL<<20)
        #define MISC_PERR_ENA1_RXPCQ_PERR_EN_XI                (1UL<<21)
        #define MISC_PERR_ENA1_RV2PTQ_PERR_EN_XI               (1UL<<22)
        #define MISC_PERR_ENA1_RV2PMQ_PERR_EN_XI               (1UL<<23)
        #define MISC_PERR_ENA1_CPQ_PERR_EN_XI                  (1UL<<24)
        #define MISC_PERR_ENA1_CSQ_PERR_EN_XI                  (1UL<<25)
        #define MISC_PERR_ENA1_RLUP_CID_PERR_EN_XI             (1UL<<26)
        #define MISC_PERR_ENA1_RV2PCS_TMEM_PERR_EN_XI          (1UL<<27)
        #define MISC_PERR_ENA1_RV2PCSQ_PERR_EN_XI              (1UL<<28)
        #define MISC_PERR_ENA1_MQ_IDX_PERR_EN_XI               (1UL<<29)

    u32_t misc_perr_ena2;
        #define MISC_PERR_ENA2_COMQ_MISC_TE                    (1UL<<0)
        #define MISC_PERR_ENA2_COMXQ_MISC_TE                   (1UL<<1)
        #define MISC_PERR_ENA2_COMTQ_MISC_TE                   (1UL<<2)
        #define MISC_PERR_ENA2_TSCHQ_MISC_TE                   (1UL<<3)
        #define MISC_PERR_ENA2_TBDRQ_MISC_TE                   (1UL<<4)
        #define MISC_PERR_ENA2_TXPQ_MISC_TE                    (1UL<<5)
        #define MISC_PERR_ENA2_TDMAQ_MISC_TE                   (1UL<<6)
        #define MISC_PERR_ENA2_TPATQ_MISC_TE                   (1UL<<7)
        #define MISC_PERR_ENA2_TASQ_MISC_TE                    (1UL<<8)
        #define MISC_PERR_ENA2_TGT_FIFO_PERR_EN_XI             (1UL<<0)
        #define MISC_PERR_ENA2_UMP_TX_PERR_EN_XI               (1UL<<1)
        #define MISC_PERR_ENA2_UMP_RX_PERR_EN_XI               (1UL<<2)
        #define MISC_PERR_ENA2_MCP_ROM_PERR_EN_XI              (1UL<<3)
        #define MISC_PERR_ENA2_MCP_SCPAD_PERR_EN_XI            (1UL<<4)
        #define MISC_PERR_ENA2_HB_MEM_PERR_EN_XI               (1UL<<5)
        #define MISC_PERR_ENA2_PCIE_REPLAY_PERR_EN_XI          (1UL<<6)

    u32_t misc_debug_vector_sel;
        #define MISC_DEBUG_VECTOR_SEL_0                     (0xfffUL<<0)
        #define MISC_DEBUG_VECTOR_SEL_1_TE                     (0xfffUL<<12)
        #define MISC_DEBUG_VECTOR_SEL_1_XI                     (0xfffUL<<15)

    u32_t misc_vreg_control;
        #define MISC_VREG_CONTROL_1_2_TE                       (0xfUL<<0)
        #define MISC_VREG_CONTROL_1_0_MAIN_XI                  (0xfUL<<0)
            #define MISC_VREG_CONTROL_1_0_MAIN_PLUS14_XI       (0UL<<0)
            #define MISC_VREG_CONTROL_1_0_MAIN_PLUS12_XI       (1UL<<0)
            #define MISC_VREG_CONTROL_1_0_MAIN_PLUS10_XI       (2UL<<0)
            #define MISC_VREG_CONTROL_1_0_MAIN_PLUS8_XI        (3UL<<0)
            #define MISC_VREG_CONTROL_1_0_MAIN_PLUS6_XI        (4UL<<0)
            #define MISC_VREG_CONTROL_1_0_MAIN_PLUS4_XI        (5UL<<0)
            #define MISC_VREG_CONTROL_1_0_MAIN_PLUS2_XI        (6UL<<0)
            #define MISC_VREG_CONTROL_1_0_MAIN_NOM_XI          (7UL<<0)
            #define MISC_VREG_CONTROL_1_0_MAIN_MINUS2_XI       (8UL<<0)
            #define MISC_VREG_CONTROL_1_0_MAIN_MINUS4_XI       (9UL<<0)
            #define MISC_VREG_CONTROL_1_0_MAIN_MINUS6_XI       (10UL<<0)
            #define MISC_VREG_CONTROL_1_0_MAIN_MINUS8_XI       (11UL<<0)
            #define MISC_VREG_CONTROL_1_0_MAIN_MINUS10_XI      (12UL<<0)
            #define MISC_VREG_CONTROL_1_0_MAIN_MINUS12_XI      (13UL<<0)
            #define MISC_VREG_CONTROL_1_0_MAIN_MINUS14_XI      (14UL<<0)
            #define MISC_VREG_CONTROL_1_0_MAIN_MINUS16_XI      (15UL<<0)
        #define MISC_VREG_CONTROL_2_5                       (0xfUL<<4)
            #define MISC_VREG_CONTROL_2_5_PLUS14            (0UL<<4)
            #define MISC_VREG_CONTROL_2_5_PLUS12            (1UL<<4)
            #define MISC_VREG_CONTROL_2_5_PLUS10            (2UL<<4)
            #define MISC_VREG_CONTROL_2_5_PLUS8             (3UL<<4)
            #define MISC_VREG_CONTROL_2_5_PLUS6             (4UL<<4)
            #define MISC_VREG_CONTROL_2_5_PLUS4             (5UL<<4)
            #define MISC_VREG_CONTROL_2_5_PLUS2             (6UL<<4)
            #define MISC_VREG_CONTROL_2_5_NOM               (7UL<<4)
            #define MISC_VREG_CONTROL_2_5_MINUS2            (8UL<<4)
            #define MISC_VREG_CONTROL_2_5_MINUS4            (9UL<<4)
            #define MISC_VREG_CONTROL_2_5_MINUS6            (10UL<<4)
            #define MISC_VREG_CONTROL_2_5_MINUS8            (11UL<<4)
            #define MISC_VREG_CONTROL_2_5_MINUS10           (12UL<<4)
            #define MISC_VREG_CONTROL_2_5_MINUS12           (13UL<<4)
            #define MISC_VREG_CONTROL_2_5_MINUS14           (14UL<<4)
            #define MISC_VREG_CONTROL_2_5_MINUS16           (15UL<<4)
        #define MISC_VREG_CONTROL_1_0_MGMT                  (0xfUL<<8)
            #define MISC_VREG_CONTROL_1_0_MGMT_PLUS14       (0UL<<8)
            #define MISC_VREG_CONTROL_1_0_MGMT_PLUS12       (1UL<<8)
            #define MISC_VREG_CONTROL_1_0_MGMT_PLUS10       (2UL<<8)
            #define MISC_VREG_CONTROL_1_0_MGMT_PLUS8        (3UL<<8)
            #define MISC_VREG_CONTROL_1_0_MGMT_PLUS6        (4UL<<8)
            #define MISC_VREG_CONTROL_1_0_MGMT_PLUS4        (5UL<<8)
            #define MISC_VREG_CONTROL_1_0_MGMT_PLUS2        (6UL<<8)
            #define MISC_VREG_CONTROL_1_0_MGMT_NOM          (7UL<<8)
            #define MISC_VREG_CONTROL_1_0_MGMT_MINUS2       (8UL<<8)
            #define MISC_VREG_CONTROL_1_0_MGMT_MINUS4       (9UL<<8)
            #define MISC_VREG_CONTROL_1_0_MGMT_MINUS6       (10UL<<8)
            #define MISC_VREG_CONTROL_1_0_MGMT_MINUS8       (11UL<<8)
            #define MISC_VREG_CONTROL_1_0_MGMT_MINUS10      (12UL<<8)
            #define MISC_VREG_CONTROL_1_0_MGMT_MINUS12      (13UL<<8)
            #define MISC_VREG_CONTROL_1_0_MGMT_MINUS14      (14UL<<8)
            #define MISC_VREG_CONTROL_1_0_MGMT_MINUS16      (15UL<<8)

    u32_t misc_final_clk_ctl_val;
        #define MISC_FINAL_CLK_CTL_VAL_MISC_FINAL_CLK_CTL_VAL  (0x3ffffffUL<<6)

    u32_t misc_gp_hw_ctl0;
        #define MISC_GP_HW_CTL0_TX_DRIVE                    (1UL<<0)
        #define MISC_GP_HW_CTL0_RMII_MODE                   (1UL<<1)
        #define MISC_GP_HW_CTL0_RMII_CRSDV_SEL              (1UL<<2)
        #define MISC_GP_HW_CTL0_RVMII_MODE                  (1UL<<3)
        #define MISC_GP_HW_CTL0_FLASH_SAMP_SCLK_NEGEDGE_TE     (1UL<<4)
        #define MISC_GP_HW_CTL0_HIDDEN_REVISION_ID_TE          (1UL<<5)
        #define MISC_GP_HW_CTL0_HC_CNTL_TMOUT_CTR_RST_TE       (1UL<<6)
        #define MISC_GP_HW_CTL0_RESERVED1_XI                   (0x7UL<<4)
        #define MISC_GP_HW_CTL0_ENA_CORE_RST_ON_MAIN_PWR_GOING_AWAY  (1UL<<7)
        #define MISC_GP_HW_CTL0_ENA_SEL_VAUX_B_IN_L2_TE        (1UL<<8)
        #define MISC_GP_HW_CTL0_GRC_BNK_FREE_FIX_TE            (1UL<<9)
        #define MISC_GP_HW_CTL0_LED_ACT_SEL_TE                 (1UL<<10)
        #define MISC_GP_HW_CTL0_RESERVED2_XI                   (0x7UL<<8)
        #define MISC_GP_HW_CTL0_UP1_DEF0                    (1UL<<11)
        #define MISC_GP_HW_CTL0_FIBER_MODE_DIS_DEF          (1UL<<12)
        #define MISC_GP_HW_CTL0_FORCE2500_DEF               (1UL<<13)
        #define MISC_GP_HW_CTL0_AUTODETECT_DIS_DEF          (1UL<<14)
        #define MISC_GP_HW_CTL0_PARALLEL_DETECT_DEF         (1UL<<15)
        #define MISC_GP_HW_CTL0_OSCCTRL_DAI                 (0xfUL<<16)
            #define MISC_GP_HW_CTL0_OSCCTRL_DAI_3MA         (0UL<<16)
            #define MISC_GP_HW_CTL0_OSCCTRL_DAI_2P5MA       (1UL<<16)
            #define MISC_GP_HW_CTL0_OSCCTRL_DAI_2P0MA       (3UL<<16)
            #define MISC_GP_HW_CTL0_OSCCTRL_DAI_1P5MA       (5UL<<16)
            #define MISC_GP_HW_CTL0_OSCCTRL_DAI_1P0MA       (7UL<<16)
            #define MISC_GP_HW_CTL0_OSCCTRL_DAI_PWRDN       (15UL<<16)
        #define MISC_GP_HW_CTL0_OSCCTRL_PRE2DIS             (1UL<<20)
        #define MISC_GP_HW_CTL0_OSCCTRL_PRE1DIS             (1UL<<21)
        #define MISC_GP_HW_CTL0_OSCCTRL_CTAT                (0x3UL<<22)
            #define MISC_GP_HW_CTL0_OSCCTRL_CTAT_M6P        (0UL<<22)
            #define MISC_GP_HW_CTL0_OSCCTRL_CTAT_M0P        (1UL<<22)
            #define MISC_GP_HW_CTL0_OSCCTRL_CTAT_P0P        (2UL<<22)
            #define MISC_GP_HW_CTL0_OSCCTRL_CTAT_P6P        (3UL<<22)
        #define MISC_GP_HW_CTL0_OSCCTRL_PTAT                (0x3UL<<24)
            #define MISC_GP_HW_CTL0_OSCCTRL_PTAT_M6P        (0UL<<24)
            #define MISC_GP_HW_CTL0_OSCCTRL_PTAT_M0P        (1UL<<24)
            #define MISC_GP_HW_CTL0_OSCCTRL_PTAT_P0P        (2UL<<24)
            #define MISC_GP_HW_CTL0_OSCCTRL_PTAT_P6P        (3UL<<24)
        #define MISC_GP_HW_CTL0_OSCCTRL_IAMP_ADJ            (0x3UL<<26)
            #define MISC_GP_HW_CTL0_OSCCTRL_IAMP_ADJ_240UA  (0UL<<26)
            #define MISC_GP_HW_CTL0_OSCCTRL_IAMP_ADJ_160UA  (1UL<<26)
            #define MISC_GP_HW_CTL0_OSCCTRL_IAMP_ADJ_400UA  (2UL<<26)
            #define MISC_GP_HW_CTL0_OSCCTRL_IAMP_ADJ_320UA  (3UL<<26)
        #define MISC_GP_HW_CTL0_OSCCTRL_ICBUF_ADJ           (0x3UL<<28)
            #define MISC_GP_HW_CTL0_OSCCTRL_ICBUF_ADJ_240UA  (0UL<<28)
            #define MISC_GP_HW_CTL0_OSCCTRL_ICBUF_ADJ_160UA  (1UL<<28)
            #define MISC_GP_HW_CTL0_OSCCTRL_ICBUF_ADJ_400UA  (2UL<<28)
            #define MISC_GP_HW_CTL0_OSCCTRL_ICBUF_ADJ_320UA  (3UL<<28)
        #define MISC_GP_HW_CTL0_OSCCTRL_XTAL_ADJ            (0x3UL<<30)
            #define MISC_GP_HW_CTL0_OSCCTRL_XTAL_ADJ_1P57   (0UL<<30)
            #define MISC_GP_HW_CTL0_OSCCTRL_XTAL_ADJ_1P45   (1UL<<30)
            #define MISC_GP_HW_CTL0_OSCCTRL_XTAL_ADJ_1P62   (2UL<<30)
            #define MISC_GP_HW_CTL0_OSCCTRL_XTAL_ADJ_1P66   (3UL<<30)

    u32_t misc_gp_hw_ctl1;
        #define MISC_GP_HW_CTL1_1_ATTN_BTN_PRSNT_TE            (1UL<<0)
        #define MISC_GP_HW_CTL1_1_ATTN_IND_PRSNT_TE            (1UL<<1)
        #define MISC_GP_HW_CTL1_1_PWR_IND_PRSNT_TE             (1UL<<2)
        #define MISC_GP_HW_CTL1_0_PCIE_LOOPBACK_TE             (1UL<<3)
        #define MISC_GP_HW_CTL1_RESERVED_SOFT_XI               (0xffffUL<<0)
        #define MISC_GP_HW_CTL1_RESERVED_HARD_XI               (0xffffUL<<16)

    u32_t misc_new_hw_ctl;
        #define MISC_NEW_HW_CTL_MAIN_POR_BYPASS             (1UL<<0)
        #define MISC_NEW_HW_CTL_RINGOSC_ENABLE              (1UL<<1)
        #define MISC_NEW_HW_CTL_RINGOSC_SEL0                (1UL<<2)
        #define MISC_NEW_HW_CTL_RINGOSC_SEL1                (1UL<<3)
        #define MISC_NEW_HW_CTL_RINGOSC_TAP                 (0x7UL<<4)
        #define MISC_NEW_HW_CTL_SMBUS_FILT_EN               (1UL<<7)
        #define MISC_NEW_HW_CTL_LED_PHY_SERDES_MODE_0       (1UL<<8)
        #define MISC_NEW_HW_CTL_LED_PHY_SERDES_MODE_1       (1UL<<9)
        #define MISC_NEW_HW_CTL_SWAP_LED                    (1UL<<10)
        #define MISC_NEW_HW_CTL_SWAP_GPIO                   (1UL<<11)
        #define MISC_NEW_HW_CTL_RESERVED_SHARED             (0xfUL<<12)
        #define MISC_NEW_HW_CTL_RESERVED_SPLIT              (0xffffUL<<16)

    u32_t misc_new_core_ctl;
        #define MISC_NEW_CORE_CTL_LINK_HOLDOFF_SUCCESS      (1UL<<0)
        #define MISC_NEW_CORE_CTL_LINK_HOLDOFF_REQ          (1UL<<1)
        #define MISC_NEW_CORE_CTL_RESERVED_CMN              (0x3fffUL<<2)
        #define MISC_NEW_CORE_CTL_DMA_ENABLE                (1UL<<16)
        #define MISC_NEW_CORE_CTL_RESERVED_TC               (0x7fffUL<<17)

    u32_t misc_eco_hw_ctl;
        #define MISC_ECO_HW_CTL_LARGE_GRC_TMOUT_EN          (1UL<<0)
        #define MISC_ECO_HW_CTL_RESERVED_SOFT               (0x7fffUL<<1)
        #define MISC_ECO_HW_CTL_RESERVED_HARD               (0xffffUL<<16)

    u32_t misc_eco_core_ctl;
        #define MISC_ECO_CORE_CTL_GLOBAL_REG_ATTN_0         (1UL<<0)
        #define MISC_ECO_CORE_CTL_GLOBAL_REG_ATTN_1         (1UL<<1)
        #define MISC_ECO_CORE_CTL_RESERVED_SOFT             (0xffffUL<<0)
        #define MISC_ECO_CORE_CTL_RESERVED_HARD             (0xffffUL<<16)

    u32_t misc_ppio;
        #define MISC_PPIO_VALUE                             (0xfUL<<0)
        #define MISC_PPIO_SET                               (0xfUL<<8)
        #define MISC_PPIO_CLR                               (0xfUL<<16)
        #define MISC_PPIO_FLOAT                             (0xfUL<<24)

    u32_t misc_ppio_int;
        #define MISC_PPIO_INT_INT_STATE                     (0xfUL<<0)
        #define MISC_PPIO_INT_OLD_VALUE                     (0xfUL<<8)
        #define MISC_PPIO_INT_OLD_SET                       (0xfUL<<16)
        #define MISC_PPIO_INT_OLD_CLR                       (0xfUL<<24)

    u32_t misc_reset_nums;
        #define MISC_RESET_NUMS_NUM_HARD_RESETS             (0x7UL<<0)
        #define MISC_RESET_NUMS_NUM_PCIE_RESETS             (0x7UL<<4)
        #define MISC_RESET_NUMS_NUM_PERSTB_RESETS           (0x7UL<<8)
        #define MISC_RESET_NUMS_NUM_CMN_RESETS              (0x7UL<<12)
        #define MISC_RESET_NUMS_NUM_PORT_RESETS             (0x7UL<<16)

    u32_t misc_cs16_err;
        #define MISC_CS16_ERR_ENA_PCI                       (1UL<<0)
        #define MISC_CS16_ERR_ENA_RDMA                      (1UL<<1)
        #define MISC_CS16_ERR_ENA_TDMA                      (1UL<<2)
        #define MISC_CS16_ERR_ENA_EMAC                      (1UL<<3)
        #define MISC_CS16_ERR_ENA_CTX                       (1UL<<4)
        #define MISC_CS16_ERR_ENA_TBDR                      (1UL<<5)
        #define MISC_CS16_ERR_ENA_RBDC                      (1UL<<6)
        #define MISC_CS16_ERR_ENA_COM                       (1UL<<7)
        #define MISC_CS16_ERR_ENA_CP                        (1UL<<8)
        #define MISC_CS16_ERR_STA_PCI                       (1UL<<16)
        #define MISC_CS16_ERR_STA_RDMA                      (1UL<<17)
        #define MISC_CS16_ERR_STA_TDMA                      (1UL<<18)
        #define MISC_CS16_ERR_STA_EMAC                      (1UL<<19)
        #define MISC_CS16_ERR_STA_CTX                       (1UL<<20)
        #define MISC_CS16_ERR_STA_TBDR                      (1UL<<21)
        #define MISC_CS16_ERR_STA_RBDC                      (1UL<<22)
        #define MISC_CS16_ERR_STA_COM                       (1UL<<23)
        #define MISC_CS16_ERR_STA_CP                        (1UL<<24)

    u32_t misc_spio_event;
        #define MISC_SPIO_EVENT_ENABLE                      (0xffUL<<0)

    u32_t misc_ppio_event;
        #define MISC_PPIO_EVENT_ENABLE                      (0xfUL<<0)

    u32_t misc_dual_media_ctrl;
        #define MISC_DUAL_MEDIA_CTRL_BOND_ID                (0xffUL<<0)
            #define MISC_DUAL_MEDIA_CTRL_BOND_ID_X          (0UL<<0)
            #define MISC_DUAL_MEDIA_CTRL_BOND_ID_C          (3UL<<0)
            #define MISC_DUAL_MEDIA_CTRL_BOND_ID_S          (12UL<<0)
        #define MISC_DUAL_MEDIA_CTRL_PHY_CTRL_STRAP         (0x7UL<<8)
        #define MISC_DUAL_MEDIA_CTRL_PORT_SWAP_PIN          (1UL<<11)
        #define MISC_DUAL_MEDIA_CTRL_SERDES1_SIGDET         (1UL<<12)
        #define MISC_DUAL_MEDIA_CTRL_SERDES0_SIGDET         (1UL<<13)
        #define MISC_DUAL_MEDIA_CTRL_PHY1_SIGDET            (1UL<<14)
        #define MISC_DUAL_MEDIA_CTRL_PHY0_SIGDET            (1UL<<15)
        #define MISC_DUAL_MEDIA_CTRL_LCPLL_RST              (1UL<<16)
        #define MISC_DUAL_MEDIA_CTRL_SERDES1_RST            (1UL<<17)
        #define MISC_DUAL_MEDIA_CTRL_SERDES0_RST            (1UL<<18)
        #define MISC_DUAL_MEDIA_CTRL_PHY1_RST               (1UL<<19)
        #define MISC_DUAL_MEDIA_CTRL_PHY0_RST               (1UL<<20)
        #define MISC_DUAL_MEDIA_CTRL_PHY_CTRL               (0x7UL<<21)
        #define MISC_DUAL_MEDIA_CTRL_PORT_SWAP              (1UL<<24)
        #define MISC_DUAL_MEDIA_CTRL_STRAP_OVERRIDE         (1UL<<25)
        #define MISC_DUAL_MEDIA_CTRL_PHY_SERDES_IDDQ        (0xfUL<<26)
            #define MISC_DUAL_MEDIA_CTRL_PHY_SERDES_IDDQ_SER1_IDDQ  (1UL<<26)
            #define MISC_DUAL_MEDIA_CTRL_PHY_SERDES_IDDQ_SER0_IDDQ  (2UL<<26)
            #define MISC_DUAL_MEDIA_CTRL_PHY_SERDES_IDDQ_PHY1_IDDQ  (4UL<<26)
            #define MISC_DUAL_MEDIA_CTRL_PHY_SERDES_IDDQ_PHY0_IDDQ  (8UL<<26)

    u32_t misc_otp_cmd1;
        #define MISC_OTP_CMD1_FMODE                         (0x7UL<<0)
            #define MISC_OTP_CMD1_FMODE_IDLE                (0UL<<0)
            #define MISC_OTP_CMD1_FMODE_WRITE               (1UL<<0)
            #define MISC_OTP_CMD1_FMODE_INIT                (2UL<<0)
            #define MISC_OTP_CMD1_FMODE_SET                 (3UL<<0)
            #define MISC_OTP_CMD1_FMODE_RST                 (4UL<<0)
            #define MISC_OTP_CMD1_FMODE_VERIFY              (5UL<<0)
            #define MISC_OTP_CMD1_FMODE_RESERVED0           (6UL<<0)
            #define MISC_OTP_CMD1_FMODE_RESERVED1           (7UL<<0)
        #define MISC_OTP_CMD1_USEPINS                       (1UL<<8)
        #define MISC_OTP_CMD1_PROGSEL                       (1UL<<9)
        #define MISC_OTP_CMD1_PROGSTART                     (1UL<<10)
        #define MISC_OTP_CMD1_PCOUNT                        (0x7UL<<16)
        #define MISC_OTP_CMD1_PBYP                          (1UL<<19)
        #define MISC_OTP_CMD1_VSEL                          (0xfUL<<20)
        #define MISC_OTP_CMD1_TM                            (0x7UL<<27)
        #define MISC_OTP_CMD1_SADBYP                        (1UL<<30)
        #define MISC_OTP_CMD1_DEBUG                         (1UL<<31)

    u32_t misc_otp_cmd2;
        #define MISC_OTP_CMD2_OTP_ROM_ADDR                  (0x3ffUL<<0)
        #define MISC_OTP_CMD2_DOSEL                         (0x7fUL<<16)
            #define MISC_OTP_CMD2_DOSEL_0                   (0UL<<16)
            #define MISC_OTP_CMD2_DOSEL_1                   (1UL<<16)
            #define MISC_OTP_CMD2_DOSEL_127                 (127UL<<16)

    u32_t misc_otp_status;
        #define MISC_OTP_STATUS_DATA                        (0xffUL<<0)
        #define MISC_OTP_STATUS_VALID                       (1UL<<8)
        #define MISC_OTP_STATUS_BUSY                        (1UL<<9)
        #define MISC_OTP_STATUS_BUSYSM                      (1UL<<10)
        #define MISC_OTP_STATUS_DONE                        (1UL<<11)

    u32_t misc_otp_shift1_cmd;
        #define MISC_OTP_SHIFT1_CMD_RESET_MODE_N            (1UL<<0)
        #define MISC_OTP_SHIFT1_CMD_SHIFT_DONE              (1UL<<1)
        #define MISC_OTP_SHIFT1_CMD_SHIFT_START             (1UL<<2)
        #define MISC_OTP_SHIFT1_CMD_LOAD_DATA               (1UL<<3)
        #define MISC_OTP_SHIFT1_CMD_SHIFT_SELECT            (0x1fUL<<8)

    u32_t misc_otp_shift1_data;
    u32_t misc_otp_shift2_cmd;
        #define MISC_OTP_SHIFT2_CMD_RESET_MODE_N            (1UL<<0)
        #define MISC_OTP_SHIFT2_CMD_SHIFT_DONE              (1UL<<1)
        #define MISC_OTP_SHIFT2_CMD_SHIFT_START             (1UL<<2)
        #define MISC_OTP_SHIFT2_CMD_LOAD_DATA               (1UL<<3)
        #define MISC_OTP_SHIFT2_CMD_SHIFT_SELECT            (0x1fUL<<8)

    u32_t misc_otp_shift2_data;
    u32_t misc_bist_cs0;
        #define MISC_BIST_CS0_MBIST_EN                      (1UL<<0)
        #define MISC_BIST_CS0_BIST_SETUP                    (0x3UL<<1)
        #define MISC_BIST_CS0_MBIST_ASYNC_RESET             (1UL<<3)
        #define MISC_BIST_CS0_MBIST_DONE                    (1UL<<8)
        #define MISC_BIST_CS0_MBIST_GO                      (1UL<<9)
        #define MISC_BIST_CS0_BIST_OVERRIDE                 (1UL<<31)

    u32_t misc_bist_memstatus0;
    u32_t misc_bist_cs1;
        #define MISC_BIST_CS1_MBIST_EN                      (1UL<<0)
        #define MISC_BIST_CS1_BIST_SETUP                    (0x3UL<<1)
        #define MISC_BIST_CS1_MBIST_ASYNC_RESET             (1UL<<3)
        #define MISC_BIST_CS1_MBIST_DONE                    (1UL<<8)
        #define MISC_BIST_CS1_MBIST_GO                      (1UL<<9)

    u32_t misc_bist_memstatus1;
    u32_t misc_bist_cs2;
        #define MISC_BIST_CS2_MBIST_EN                      (1UL<<0)
        #define MISC_BIST_CS2_BIST_SETUP                    (0x3UL<<1)
        #define MISC_BIST_CS2_MBIST_ASYNC_RESET             (1UL<<3)
        #define MISC_BIST_CS2_MBIST_DONE                    (1UL<<8)
        #define MISC_BIST_CS2_MBIST_GO                      (1UL<<9)

    u32_t misc_bist_memstatus2;
    u32_t misc_bist_cs3;
        #define MISC_BIST_CS3_MBIST_EN                      (1UL<<0)
        #define MISC_BIST_CS3_BIST_SETUP                    (0x3UL<<1)
        #define MISC_BIST_CS3_MBIST_ASYNC_RESET             (1UL<<3)
        #define MISC_BIST_CS3_MBIST_DONE                    (1UL<<8)
        #define MISC_BIST_CS3_MBIST_GO                      (1UL<<9)

    u32_t misc_bist_memstatus3;
    u32_t misc_bist_cs4;
        #define MISC_BIST_CS4_MBIST_EN                      (1UL<<0)
        #define MISC_BIST_CS4_BIST_SETUP                    (0x3UL<<1)
        #define MISC_BIST_CS4_MBIST_ASYNC_RESET             (1UL<<3)
        #define MISC_BIST_CS4_MBIST_DONE                    (1UL<<8)
        #define MISC_BIST_CS4_MBIST_GO                      (1UL<<9)

    u32_t misc_bist_memstatus4;
    u32_t misc_bist_cs5;
        #define MISC_BIST_CS5_MBIST_EN                      (1UL<<0)
        #define MISC_BIST_CS5_BIST_SETUP                    (0x3UL<<1)
        #define MISC_BIST_CS5_MBIST_ASYNC_RESET             (1UL<<3)
        #define MISC_BIST_CS5_MBIST_DONE                    (1UL<<8)
        #define MISC_BIST_CS5_MBIST_GO                      (1UL<<9)

    u32_t misc_bist_memstatus5;
    u32_t misc_mem_tm0;
        #define MISC_MEM_TM0_PCIE_REPLAY_TM                 (0xfUL<<0)
        #define MISC_MEM_TM0_MCP_SCPAD                      (0xfUL<<8)
        #define MISC_MEM_TM0_UMP_TM                         (0xffUL<<16)
        #define MISC_MEM_TM0_HB_MEM_TM                      (0xfUL<<24)

    u32_t misc_uspll_ctrl;
        #define MISC_USPLL_CTRL_PH_DET_DIS                  (1UL<<0)
        #define MISC_USPLL_CTRL_FREQ_DET_DIS                (1UL<<1)
        #define MISC_USPLL_CTRL_LCPX                        (0x3fUL<<2)
        #define MISC_USPLL_CTRL_RX                          (0x3UL<<8)
        #define MISC_USPLL_CTRL_VC_EN                       (1UL<<10)
        #define MISC_USPLL_CTRL_VCO_MG                      (0x3UL<<11)
        #define MISC_USPLL_CTRL_KVCO_XF                     (0x7UL<<13)
        #define MISC_USPLL_CTRL_KVCO_XS                     (0x7UL<<16)
        #define MISC_USPLL_CTRL_TESTD_EN                    (1UL<<19)
        #define MISC_USPLL_CTRL_TESTD_SEL                   (0x7UL<<20)
        #define MISC_USPLL_CTRL_TESTA_EN                    (1UL<<23)
        #define MISC_USPLL_CTRL_TESTA_SEL                   (0x3UL<<24)
        #define MISC_USPLL_CTRL_ATTEN_FREF                  (1UL<<26)
        #define MISC_USPLL_CTRL_DIGITAL_RST                 (1UL<<27)
        #define MISC_USPLL_CTRL_ANALOG_RST                  (1UL<<28)
        #define MISC_USPLL_CTRL_LOCK                        (1UL<<29)

    u32_t misc_perr_status0;
        #define MISC_PERR_STATUS0_COM_DMAE_PERR             (1UL<<0)
        #define MISC_PERR_STATUS0_CP_DMAE_PERR              (1UL<<1)
        #define MISC_PERR_STATUS0_RPM_ACPIBEMEM_PERR        (1UL<<2)
        #define MISC_PERR_STATUS0_CTX_USAGE_CNT_PERR        (1UL<<3)
        #define MISC_PERR_STATUS0_CTX_PGTBL_PERR            (1UL<<4)
        #define MISC_PERR_STATUS0_CTX_CACHE_PERR            (1UL<<5)
        #define MISC_PERR_STATUS0_CTX_MIRROR_PERR           (1UL<<6)
        #define MISC_PERR_STATUS0_COM_CTXC_PERR             (1UL<<7)
        #define MISC_PERR_STATUS0_COM_SCPAD_PERR            (1UL<<8)
        #define MISC_PERR_STATUS0_CP_CTXC_PERR              (1UL<<9)
        #define MISC_PERR_STATUS0_CP_SCPAD_PERR             (1UL<<10)
        #define MISC_PERR_STATUS0_RXP_RBUFC_PERR            (1UL<<11)
        #define MISC_PERR_STATUS0_RXP_CTXC_PERR             (1UL<<12)
        #define MISC_PERR_STATUS0_RXP_SCPAD_PERR            (1UL<<13)
        #define MISC_PERR_STATUS0_TPAT_SCPAD_PERR           (1UL<<14)
        #define MISC_PERR_STATUS0_TXP_CTXC_PERR             (1UL<<15)
        #define MISC_PERR_STATUS0_TXP_SCPAD_PERR            (1UL<<16)
        #define MISC_PERR_STATUS0_CS_TMEM_PERR              (1UL<<17)
        #define MISC_PERR_STATUS0_MQ_CTX_PERR               (1UL<<18)
        #define MISC_PERR_STATUS0_RPM_DFIFOMEM_PERR         (1UL<<19)
        #define MISC_PERR_STATUS0_RPC_DFIFOMEM_PERR         (1UL<<20)
        #define MISC_PERR_STATUS0_RBUF_PTRMEM_PERR          (1UL<<21)
        #define MISC_PERR_STATUS0_RBUF_DATAMEM_PERR         (1UL<<22)
        #define MISC_PERR_STATUS0_RV2P_P2IRAM_PERR          (1UL<<23)
        #define MISC_PERR_STATUS0_RV2P_P1IRAM_PERR          (1UL<<24)
        #define MISC_PERR_STATUS0_RV2P_CB1REGS_PERR         (1UL<<25)
        #define MISC_PERR_STATUS0_RV2P_CB0REGS_PERR         (1UL<<26)
        #define MISC_PERR_STATUS0_TPBUF_PERR                (1UL<<27)
        #define MISC_PERR_STATUS0_THBUF_PERR                (1UL<<28)
        #define MISC_PERR_STATUS0_TDMA_PERR                 (1UL<<29)
        #define MISC_PERR_STATUS0_TBDC_PERR                 (1UL<<30)
        #define MISC_PERR_STATUS0_TSCH_LR_PERR              (1UL<<31)

    u32_t misc_perr_status1;
        #define MISC_PERR_STATUS1_RBDC_PERR                 (1UL<<0)
        #define MISC_PERR_STATUS1_RDMA_DFIFO_PERR           (1UL<<2)
        #define MISC_PERR_STATUS1_HC_STATS_PERR             (1UL<<3)
        #define MISC_PERR_STATUS1_HC_MSIX_PERR              (1UL<<4)
        #define MISC_PERR_STATUS1_HC_PRODUCSTB_PERR         (1UL<<5)
        #define MISC_PERR_STATUS1_HC_CONSUMSTB_PERR         (1UL<<6)
        #define MISC_PERR_STATUS1_TPATQ_PERR                (1UL<<7)
        #define MISC_PERR_STATUS1_MCPQ_PERR                 (1UL<<8)
        #define MISC_PERR_STATUS1_TDMAQ_PERR                (1UL<<9)
        #define MISC_PERR_STATUS1_TXPQ_PERR                 (1UL<<10)
        #define MISC_PERR_STATUS1_COMTQ_PERR                (1UL<<11)
        #define MISC_PERR_STATUS1_COMQ_PERR                 (1UL<<12)
        #define MISC_PERR_STATUS1_RLUPQ_PERR                (1UL<<13)
        #define MISC_PERR_STATUS1_RXPQ_PERR                 (1UL<<14)
        #define MISC_PERR_STATUS1_RV2PPQ_PERR               (1UL<<15)
        #define MISC_PERR_STATUS1_RDMAQ_PERR                (1UL<<16)
        #define MISC_PERR_STATUS1_TASQ_PERR                 (1UL<<17)
        #define MISC_PERR_STATUS1_TBDRQ_PERR                (1UL<<18)
        #define MISC_PERR_STATUS1_TSCHQ_PERR                (1UL<<19)
        #define MISC_PERR_STATUS1_COMXQ_PERR                (1UL<<20)
        #define MISC_PERR_STATUS1_RXPCQ_PERR                (1UL<<21)
        #define MISC_PERR_STATUS1_RV2PTQ_PERR               (1UL<<22)
        #define MISC_PERR_STATUS1_RV2PMQ_PERR               (1UL<<23)
        #define MISC_PERR_STATUS1_CPQ_PERR                  (1UL<<24)
        #define MISC_PERR_STATUS1_CSQ_PERR                  (1UL<<25)
        #define MISC_PERR_STATUS1_RLUP_CID_PERR             (1UL<<26)
        #define MISC_PERR_STATUS1_RV2PCS_TMEM_PERR          (1UL<<27)
        #define MISC_PERR_STATUS1_RV2PCSQ_PERR              (1UL<<28)
        #define MISC_PERR_STATUS1_MQ_IDX_PERR               (1UL<<29)

    u32_t misc_perr_status2;
        #define MISC_PERR_STATUS2_TGT_FIFO_PERR             (1UL<<0)
        #define MISC_PERR_STATUS2_UMP_TX_PERR               (1UL<<1)
        #define MISC_PERR_STATUS2_UMP_RX_PERR               (1UL<<2)
        #define MISC_PERR_STATUS2_MCP_ROM_PERR              (1UL<<3)
        #define MISC_PERR_STATUS2_MCP_SCPAD_PERR            (1UL<<4)
        #define MISC_PERR_STATUS2_HB_MEM_PERR               (1UL<<5)
        #define MISC_PERR_STATUS2_PCIE_REPLAY_PERR          (1UL<<6)

    u32_t misc_lcpll_ctrl0;
        #define MISC_LCPLL_CTRL0_OAC                        (0x7UL<<0)
            #define MISC_LCPLL_CTRL0_OAC_NEGTWENTY          (0UL<<0)
            #define MISC_LCPLL_CTRL0_OAC_ZERO               (1UL<<0)
            #define MISC_LCPLL_CTRL0_OAC_TWENTY             (3UL<<0)
            #define MISC_LCPLL_CTRL0_OAC_FORTY              (7UL<<0)
        #define MISC_LCPLL_CTRL0_ICP_CTRL                   (0x7UL<<3)
            #define MISC_LCPLL_CTRL0_ICP_CTRL_360           (0UL<<3)
            #define MISC_LCPLL_CTRL0_ICP_CTRL_480           (1UL<<3)
            #define MISC_LCPLL_CTRL0_ICP_CTRL_600           (3UL<<3)
            #define MISC_LCPLL_CTRL0_ICP_CTRL_720           (7UL<<3)
        #define MISC_LCPLL_CTRL0_BIAS_CTRL                  (0x3UL<<6)
        #define MISC_LCPLL_CTRL0_PLL_OBSERVE                (0x7UL<<8)
        #define MISC_LCPLL_CTRL0_VTH_CTRL                   (0x3UL<<11)
            #define MISC_LCPLL_CTRL0_VTH_CTRL_0             (0UL<<11)
            #define MISC_LCPLL_CTRL0_VTH_CTRL_1             (1UL<<11)
            #define MISC_LCPLL_CTRL0_VTH_CTRL_2             (2UL<<11)
        #define MISC_LCPLL_CTRL0_PLLSEQSTART                (1UL<<13)
        #define MISC_LCPLL_CTRL0_RESERVED                   (1UL<<14)
        #define MISC_LCPLL_CTRL0_CAPRETRY_EN                (1UL<<15)
        #define MISC_LCPLL_CTRL0_FREQMONITOR_EN             (1UL<<16)
        #define MISC_LCPLL_CTRL0_FREQDETRESTART_EN          (1UL<<17)
        #define MISC_LCPLL_CTRL0_FREQDETRETRY_EN            (1UL<<18)
        #define MISC_LCPLL_CTRL0_PLLFORCEFDONE_EN           (1UL<<19)
        #define MISC_LCPLL_CTRL0_PLLFORCEFDONE              (1UL<<20)
        #define MISC_LCPLL_CTRL0_PLLFORCEFPASS              (1UL<<21)
        #define MISC_LCPLL_CTRL0_PLLFORCECAPDONE_EN         (1UL<<22)
        #define MISC_LCPLL_CTRL0_PLLFORCECAPDONE            (1UL<<23)
        #define MISC_LCPLL_CTRL0_PLLFORCECAPPASS_EN         (1UL<<24)
        #define MISC_LCPLL_CTRL0_PLLFORCECAPPASS            (1UL<<25)
        #define MISC_LCPLL_CTRL0_CAPRESTART                 (1UL<<26)
        #define MISC_LCPLL_CTRL0_CAPSELECTM_EN              (1UL<<27)

    u32_t misc_lcpll_ctrl1;
        #define MISC_LCPLL_CTRL1_CAPSELECTM                 (0x1fUL<<0)
        #define MISC_LCPLL_CTRL1_CAPFORCESLOWDOWN_EN        (1UL<<5)
        #define MISC_LCPLL_CTRL1_CAPFORCESLOWDOWN           (1UL<<6)
        #define MISC_LCPLL_CTRL1_SLOWDN_XOR                 (1UL<<7)

    u32_t misc_lcpll_status;
        #define MISC_LCPLL_STATUS_FREQDONE_SM               (1UL<<0)
        #define MISC_LCPLL_STATUS_FREQPASS_SM               (1UL<<1)
        #define MISC_LCPLL_STATUS_PLLSEQDONE                (1UL<<2)
        #define MISC_LCPLL_STATUS_PLLSEQPASS                (1UL<<3)
        #define MISC_LCPLL_STATUS_PLLSTATE                  (0x7UL<<4)
        #define MISC_LCPLL_STATUS_CAPSTATE                  (0x7UL<<7)
        #define MISC_LCPLL_STATUS_CAPSELECT                 (0x1fUL<<10)
        #define MISC_LCPLL_STATUS_SLOWDN_INDICATOR          (1UL<<15)
            #define MISC_LCPLL_STATUS_SLOWDN_INDICATOR_0    (0UL<<15)
            #define MISC_LCPLL_STATUS_SLOWDN_INDICATOR_1    (1UL<<15)

    u32_t misc_oscfunds_ctrl;
        #define MISC_OSCFUNDS_CTRL_FREQ_MON                 (1UL<<5)
            #define MISC_OSCFUNDS_CTRL_FREQ_MON_OFF         (0UL<<5)
            #define MISC_OSCFUNDS_CTRL_FREQ_MON_ON          (1UL<<5)
        #define MISC_OSCFUNDS_CTRL_XTAL_ADJCM               (0x3UL<<6)
            #define MISC_OSCFUNDS_CTRL_XTAL_ADJCM_0         (0UL<<6)
            #define MISC_OSCFUNDS_CTRL_XTAL_ADJCM_1         (1UL<<6)
            #define MISC_OSCFUNDS_CTRL_XTAL_ADJCM_2         (2UL<<6)
            #define MISC_OSCFUNDS_CTRL_XTAL_ADJCM_3         (3UL<<6)
        #define MISC_OSCFUNDS_CTRL_ICBUF_ADJ                (0x3UL<<8)
            #define MISC_OSCFUNDS_CTRL_ICBUF_ADJ_0          (0UL<<8)
            #define MISC_OSCFUNDS_CTRL_ICBUF_ADJ_1          (1UL<<8)
            #define MISC_OSCFUNDS_CTRL_ICBUF_ADJ_2          (2UL<<8)
            #define MISC_OSCFUNDS_CTRL_ICBUF_ADJ_3          (3UL<<8)
        #define MISC_OSCFUNDS_CTRL_IAMP_ADJ                 (0x3UL<<10)
            #define MISC_OSCFUNDS_CTRL_IAMP_ADJ_0           (0UL<<10)
            #define MISC_OSCFUNDS_CTRL_IAMP_ADJ_1           (1UL<<10)
            #define MISC_OSCFUNDS_CTRL_IAMP_ADJ_2           (2UL<<10)
            #define MISC_OSCFUNDS_CTRL_IAMP_ADJ_3           (3UL<<10)

    u32_t misc_cpu_otp_ctrl1;
        #define MISC_CPU_OTP_CTRL1_START                    (1UL<<0)
        #define MISC_CPU_OTP_CTRL1_COMMAND                  (0xfUL<<1)
            #define MISC_CPU_OTP_CTRL1_COMMAND_READ         (0UL<<1)
            #define MISC_CPU_OTP_CTRL1_COMMAND_PGM_BIT_INT  (1UL<<1)
            #define MISC_CPU_OTP_CTRL1_COMMAND_PGM_WORD_INT  (2UL<<1)
            #define MISC_CPU_OTP_CTRL1_COMMAND_VERIFY       (3UL<<1)
            #define MISC_CPU_OTP_CTRL1_COMMAND_INIT         (4UL<<1)
            #define MISC_CPU_OTP_CTRL1_COMMAND_SET          (5UL<<1)
            #define MISC_CPU_OTP_CTRL1_COMMAND_RST          (6UL<<1)
            #define MISC_CPU_OTP_CTRL1_COMMAND_OCST         (7UL<<1)
            #define MISC_CPU_OTP_CTRL1_COMMAND_ROW_LOCK     (8UL<<1)
            #define MISC_CPU_OTP_CTRL1_COMMAND_PRESCREEN_TEST  (9UL<<1)
            #define MISC_CPU_OTP_CTRL1_COMMAND_PGM_BIT_EXT  (10UL<<1)
            #define MISC_CPU_OTP_CTRL1_COMMAND_PGM_WORD_EXT  (11UL<<1)
        #define MISC_CPU_OTP_CTRL1_WRP_PROG_SEL             (1UL<<5)
        #define MISC_CPU_OTP_CTRL1_WRP_VSEL                 (0xfUL<<6)
        #define MISC_CPU_OTP_CTRL1_WRP_PCOUNT               (0x7UL<<10)
        #define MISC_CPU_OTP_CTRL1_WRP_PBYP                 (1UL<<13)
        #define MISC_CPU_OTP_CTRL1_WRP_SADBYP               (1UL<<15)
        #define MISC_CPU_OTP_CTRL1_WRP_TIME_MARGIN          (0x7UL<<16)
        #define MISC_CPU_OTP_CTRL1_WRP_CONTINUE_ON_FAIL     (1UL<<19)
        #define MISC_CPU_OTP_CTRL1_OTP_DEBUG_MODE           (1UL<<20)
        #define MISC_CPU_OTP_CTRL1_OTP_PROG_EN              (1UL<<21)
        #define MISC_CPU_OTP_CTRL1_ACCESS_MODE              (0x3UL<<22)
            #define MISC_CPU_OTP_CTRL1_ACCESS_MODE_RAW      (0UL<<22)
            #define MISC_CPU_OTP_CTRL1_ACCESS_MODE_MFG      (1UL<<22)
            #define MISC_CPU_OTP_CTRL1_ACCESS_MODE_CFG      (2UL<<22)
            #define MISC_CPU_OTP_CTRL1_ACCESS_MODE_REP      (3UL<<22)
        #define MISC_CPU_OTP_CTRL1_BURST_STAT_SEL           (1UL<<24)

    u32_t misc_cpu_otp_ctrl2;
        #define MISC_CPU_OTP_CTRL2_OTP_ROM_ADDR             (0x3ffUL<<0)
        #define MISC_CPU_OTP_CTRL2_DOSEL                    (0x7fUL<<16)
            #define MISC_CPU_OTP_CTRL2_DOSEL_16             (16UL<<16)
            #define MISC_CPU_OTP_CTRL2_DOSEL_17             (17UL<<16)
            #define MISC_CPU_OTP_CTRL2_DOSEL_127            (127UL<<16)
        #define MISC_CPU_OTP_CTRL2_JTAG_CPU_MODE            (1UL<<31)

    u32_t misc_cpu_otp_status;
        #define MISC_CPU_OTP_STATUS_COMMAND_DONE            (1UL<<0)
        #define MISC_CPU_OTP_STATUS_WRP_DATA_READY          (1UL<<1)
        #define MISC_CPU_OTP_STATUS_WRP_DOUT                (1UL<<2)
        #define MISC_CPU_OTP_STATUS_WRP_BUSY                (1UL<<3)
        #define MISC_CPU_OTP_STATUS_WRP_FAIL                (1UL<<4)
        #define MISC_CPU_OTP_STATUS_INVALID_PROG_REQ        (1UL<<5)
        #define MISC_CPU_OTP_STATUS_PROG_BLOCKED            (1UL<<6)
        #define MISC_CPU_OTP_STATUS_INIT_WAIT_DONE          (1UL<<7)
        #define MISC_CPU_OTP_STATUS_DATA                    (0xffUL<<8)

    u32_t misc_cpu_otp_write_data;
    u32_t misc_cpu_otp_read_data;
    u32_t misc_mem_65_tm0;
        #define MISC_MEM_65_TM0_UMP_EGRESS_TM               (0xffUL<<0)
        #define MISC_MEM_65_TM0_MCP_SCPAD_TM                (0xfUL<<8)
        #define MISC_MEM_65_TM0_UMP_INGRESS_TM              (0xffUL<<16)
        #define MISC_MEM_65_TM0_HB_MEM_TM                   (0xfUL<<24)

    u32_t misc_mem_65_tm1;
        #define MISC_MEM_65_TM1_MCP_ROM_TM                  (0x1fUL<<0)
        #define MISC_MEM_65_TM1_PCIE_DLP2TLP_BUF_TMA        (0x3UL<<8)
        #define MISC_MEM_65_TM1_PCIE_DLP2TLP_BUF_TMB        (0x3UL<<12)
        #define MISC_MEM_65_TM1_PCIE_REPLAY_TM              (0xfUL<<16)
        #define MISC_MEM_65_TM1_PCIE_REPLAY_ADDR_TM         (0x3UL<<24)
        #define MISC_MEM_65_TM1_TGT_FIFO_TM                 (0x3UL<<28)

    u32_t misc_weak_wr_cmdstat;
        #define MISC_WEAK_WR_CMDSTAT_WW_MODE                (1UL<<0)
        #define MISC_WEAK_WR_CMDSTAT_WW_START               (1UL<<1)
        #define MISC_WEAK_WR_CMDSTAT_WW_DONE                (1UL<<2)
        #define MISC_WEAK_WR_CMDSTAT_HB_MEM_FAIL_FLAG       (1UL<<4)
        #define MISC_WEAK_WR_CMDSTAT_PCIE_REPLAY_FAIL_FLAG  (1UL<<5)
        #define MISC_WEAK_WR_CMDSTAT_UMP_INGRESS_FAIL_FLAG  (1UL<<6)
        #define MISC_WEAK_WR_CMDSTAT_UMP_EGRESS_FAIL_FLAG   (1UL<<7)
        #define MISC_WEAK_WR_CMDSTAT_MCP_SCPAD_FAIL_FLAG    (1UL<<8)

    u32_t misc_new_id;
        #define MISC_NEW_ID_CHIP_METAL                      (0xffUL<<0)
        #define MISC_NEW_ID_CHIP_REV                        (0xfUL<<8)
        #define MISC_NEW_ID_CHIP_NUM                        (0xfffffUL<<12)

    u32_t misc_add_core_ctl;
        #define MISC_ADD_CORE_CTL_RESERVED_SOFT             (0xffffUL<<0)
        #define MISC_ADD_CORE_CTL_RESERVED_HARD             (0xffffUL<<16)

    u32_t misc_full_reset_nums0;
        #define MISC_FULL_RESET_NUMS0_NUM_HARD_RESETS       (0xffUL<<0)
        #define MISC_FULL_RESET_NUMS0_NUM_PCIE_RESETS       (0xffUL<<8)
        #define MISC_FULL_RESET_NUMS0_NUM_PERSTB_RESETS     (0xffUL<<16)
        #define MISC_FULL_RESET_NUMS0_NUM_CMN_RESETS        (0xffUL<<24)

    u32_t misc_full_reset_nums1;
        #define MISC_FULL_RESET_NUMS1_NUM_PORT_RESETS       (0xffUL<<0)

    u32_t misc_uspll65_ctrl0;
        #define MISC_USPLL65_CTRL0_NUM_PORT_RESETS          (0xffffffffUL<<0)

    u32_t misc_uspll65_ctrl1;
        #define MISC_USPLL65_CTRL1_NUM_PORT_RESETS          (0xffffffffUL<<0)

    u32_t misc_lcpll65_ctrl0;
        #define MISC_LCPLL65_CTRL0_NUM_PORT_RESETS          (0xffffffffUL<<0)

    u32_t misc_lcpll65_ctrl1;
        #define MISC_LCPLL65_CTRL1_NUM_PORT_RESETS          (0xffffffffUL<<0)

    u32_t misc_lcpll65_status;
        #define MISC_LCPLL65_STATUS_NUM_PORT_RESETS         (0xffffffffUL<<0)

    u32_t misc_lcpll65_ctrl2;
        #define MISC_LCPLL65_CTRL2_NUM_PORT_RESETS          (0xffffffffUL<<0)

    u32_t misc_lcpll65_ctrl3;
        #define MISC_LCPLL65_CTRL3_NUM_PORT_RESETS          (0xffffffffUL<<0)

    u32_t misc_oscfunds65_ctrl1;
        #define MISC_OSCFUNDS65_CTRL1_NUM_PORT_RESETS       (0xffffffffUL<<0)

    u32_t unused_1[148];
} misc_reg_t;


/*
 *  p2r_reg definition
 *  offset: 0x240000
 */
typedef struct p2r_reg
{
    u32_t p2r_epb_config[256];
    u32_t p2r_debug[256];
    u32_t p2r_mdio_addr;
        #define P2R_MDIO_ADDR_ADR                           (0xffffUL<<0)
        #define P2R_MDIO_ADDR_PORT                          (0xfUL<<16)
        #define P2R_MDIO_ADDR_CMD                           (0xfffUL<<20)

    u32_t p2r_mdio_wr_data;
        #define P2R_MDIO_WR_DATA_DATA                       (0xffffUL<<0)
        #define P2R_MDIO_WR_DATA_CMD                        (1UL<<31)

    u32_t p2r_mdio_rd_data;
        #define P2R_MDIO_RD_DATA_DATA                       (0xffffUL<<0)
        #define P2R_MDIO_RD_DATA_CMD                        (1UL<<31)

    u32_t unused_0[3581];
    u32_t p2r_command;
        #define P2R_COMMAND_P2R_CMD_GRC_TIMEOUT             (1UL<<0)

    u32_t unused_1[64511];
} p2r_reg_t;


/*
 *  nvm_reg definition
 *  offset: 0x6400
 */
typedef struct nvm_reg
{
    u32_t nvm_command;
        #define NVM_COMMAND_RST                             (1UL<<0)
        #define NVM_COMMAND_DONE                            (1UL<<3)
        #define NVM_COMMAND_DOIT                            (1UL<<4)
        #define NVM_COMMAND_WR                              (1UL<<5)
        #define NVM_COMMAND_ERASE                           (1UL<<6)
        #define NVM_COMMAND_FIRST                           (1UL<<7)
        #define NVM_COMMAND_LAST                            (1UL<<8)
        #define NVM_COMMAND_WREN                            (1UL<<16)
        #define NVM_COMMAND_WRDI                            (1UL<<17)
        #define NVM_COMMAND_EWSR                            (1UL<<18)
        #define NVM_COMMAND_WRSR                            (1UL<<19)
        #define NVM_COMMAND_RD_ID                           (1UL<<20)
        #define NVM_COMMAND_RD_STATUS                       (1UL<<21)
        #define NVM_COMMAND_MODE_256                        (1UL<<22)

    u32_t nvm_status;
        #define NVM_STATUS_PI_FSM_STATE_TE                     (0xfUL<<0)
        #define NVM_STATUS_EE_FSM_STATE_TE                     (0xfUL<<4)
        #define NVM_STATUS_EQ_FSM_STATE_TE                     (0xfUL<<8)
        #define NVM_STATUS_SPI_FSM_STATE_XI                    (0x1fUL<<0)
            #define NVM_STATUS_SPI_FSM_STATE_SPI_IDLE_XI       (0UL<<0)
            #define NVM_STATUS_SPI_FSM_STATE_SPI_CMD0_XI       (1UL<<0)
            #define NVM_STATUS_SPI_FSM_STATE_SPI_CMD1_XI       (2UL<<0)
            #define NVM_STATUS_SPI_FSM_STATE_SPI_CMD_FINISH0_XI  (3UL<<0)
            #define NVM_STATUS_SPI_FSM_STATE_SPI_CMD_FINISH1_XI  (4UL<<0)
            #define NVM_STATUS_SPI_FSM_STATE_SPI_ADDR0_XI      (5UL<<0)
            #define NVM_STATUS_SPI_FSM_STATE_SPI_WRITE_DATA0_XI  (6UL<<0)
            #define NVM_STATUS_SPI_FSM_STATE_SPI_WRITE_DATA1_XI  (7UL<<0)
            #define NVM_STATUS_SPI_FSM_STATE_SPI_WRITE_DATA2_XI  (8UL<<0)
            #define NVM_STATUS_SPI_FSM_STATE_SPI_READ_DATA0_XI  (9UL<<0)
            #define NVM_STATUS_SPI_FSM_STATE_SPI_READ_DATA1_XI  (10UL<<0)
            #define NVM_STATUS_SPI_FSM_STATE_SPI_READ_DATA2_XI  (11UL<<0)
            #define NVM_STATUS_SPI_FSM_STATE_SPI_READ_STATUS_RDID0_XI  (12UL<<0)
            #define NVM_STATUS_SPI_FSM_STATE_SPI_READ_STATUS_RDID1_XI  (13UL<<0)
            #define NVM_STATUS_SPI_FSM_STATE_SPI_READ_STATUS_RDID2_XI  (14UL<<0)
            #define NVM_STATUS_SPI_FSM_STATE_SPI_READ_STATUS_RDID3_XI  (15UL<<0)
            #define NVM_STATUS_SPI_FSM_STATE_SPI_READ_STATUS_RDID4_XI  (16UL<<0)
            #define NVM_STATUS_SPI_FSM_STATE_SPI_CHECK_BUSY0_XI  (17UL<<0)
            #define NVM_STATUS_SPI_FSM_STATE_SPI_ST_WREN_XI    (18UL<<0)
            #define NVM_STATUS_SPI_FSM_STATE_SPI_WAIT_XI       (19UL<<0)

    u32_t nvm_write;
        #define NVM_WRITE_NVM_WRITE_VALUE                   (0xffffffffUL<<0)
            #define NVM_WRITE_NVM_WRITE_VALUE_BIT_BANG      (0UL<<0)
            #define NVM_WRITE_NVM_WRITE_VALUE_EECLK_TE         (1UL<<0)
            #define NVM_WRITE_NVM_WRITE_VALUE_EEDATA_TE        (2UL<<0)
            #define NVM_WRITE_NVM_WRITE_VALUE_SCLK_TE          (4UL<<0)
            #define NVM_WRITE_NVM_WRITE_VALUE_CS_B_TE          (8UL<<0)
            #define NVM_WRITE_NVM_WRITE_VALUE_SO_TE            (16UL<<0)
            #define NVM_WRITE_NVM_WRITE_VALUE_SI_TE            (32UL<<0)
            #define NVM_WRITE_NVM_WRITE_VALUE_SI_XI            (1UL<<0)
            #define NVM_WRITE_NVM_WRITE_VALUE_SO_XI            (2UL<<0)
            #define NVM_WRITE_NVM_WRITE_VALUE_CS_B_XI          (4UL<<0)
            #define NVM_WRITE_NVM_WRITE_VALUE_SCLK_XI          (8UL<<0)

    u32_t nvm_addr;
        #define NVM_ADDR_NVM_ADDR_VALUE                     (0xffffffUL<<0)
            #define NVM_ADDR_NVM_ADDR_VALUE_BIT_BANG        (0UL<<0)
            #define NVM_ADDR_NVM_ADDR_VALUE_EECLK_TE           (1UL<<0)
            #define NVM_ADDR_NVM_ADDR_VALUE_EEDATA_TE          (2UL<<0)
            #define NVM_ADDR_NVM_ADDR_VALUE_SCLK_TE            (4UL<<0)
            #define NVM_ADDR_NVM_ADDR_VALUE_CS_B_TE            (8UL<<0)
            #define NVM_ADDR_NVM_ADDR_VALUE_SO_TE              (16UL<<0)
            #define NVM_ADDR_NVM_ADDR_VALUE_SI_TE              (32UL<<0)
            #define NVM_ADDR_NVM_ADDR_VALUE_SI_XI              (1UL<<0)
            #define NVM_ADDR_NVM_ADDR_VALUE_SO_XI              (2UL<<0)
            #define NVM_ADDR_NVM_ADDR_VALUE_CS_B_XI            (4UL<<0)
            #define NVM_ADDR_NVM_ADDR_VALUE_SCLK_XI            (8UL<<0)

    u32_t nvm_read;
        #define NVM_READ_NVM_READ_VALUE                     (0xffffffffUL<<0)
            #define NVM_READ_NVM_READ_VALUE_BIT_BANG        (0UL<<0)
            #define NVM_READ_NVM_READ_VALUE_EECLK_TE           (1UL<<0)
            #define NVM_READ_NVM_READ_VALUE_EEDATA_TE          (2UL<<0)
            #define NVM_READ_NVM_READ_VALUE_SCLK_TE            (4UL<<0)
            #define NVM_READ_NVM_READ_VALUE_CS_B_TE            (8UL<<0)
            #define NVM_READ_NVM_READ_VALUE_SO_TE              (16UL<<0)
            #define NVM_READ_NVM_READ_VALUE_SI_TE              (32UL<<0)
            #define NVM_READ_NVM_READ_VALUE_SI_XI              (1UL<<0)
            #define NVM_READ_NVM_READ_VALUE_SO_XI              (2UL<<0)
            #define NVM_READ_NVM_READ_VALUE_CS_B_XI            (4UL<<0)
            #define NVM_READ_NVM_READ_VALUE_SCLK_XI            (8UL<<0)

    u32_t nvm_cfg1;
        #define NVM_CFG1_FLASH_MODE                         (1UL<<0)
        #define NVM_CFG1_BUFFER_MODE                        (1UL<<1)
        #define NVM_CFG1_PASS_MODE                          (1UL<<2)
        #define NVM_CFG1_BITBANG_MODE                       (1UL<<3)
        #define NVM_CFG1_STATUS_BIT                         (0x7UL<<4)
            #define NVM_CFG1_STATUS_BIT_FLASH_RDY           (0UL<<4)
            #define NVM_CFG1_STATUS_BIT_BUFFER_RDY          (7UL<<4)
        #define NVM_CFG1_SPI_CLK_DIV                        (0xfUL<<7)
        #define NVM_CFG1_SEE_CLK_DIV                        (0x7ffUL<<11)
        #define NVM_CFG1_STRAP_CONTROL_0                    (1UL<<23)
        #define NVM_CFG1_PROTECT_MODE                       (1UL<<24)
        #define NVM_CFG1_FLASH_SIZE                         (1UL<<25)
        #define NVM_CFG1_FW_USTRAP_1                        (1UL<<26)
        #define NVM_CFG1_FW_USTRAP_0                        (1UL<<27)
        #define NVM_CFG1_FW_USTRAP_2                        (1UL<<28)
        #define NVM_CFG1_FW_USTRAP_3                        (1UL<<29)
        #define NVM_CFG1_FW_FLASH_TYPE_EN                   (1UL<<30)
        #define NVM_CFG1_COMPAT_BYPASSS                     (1UL<<31)

    u32_t nvm_cfg2;
        #define NVM_CFG2_ERASE_CMD                          (0xffUL<<0)
        #define NVM_CFG2_DUMMY                              (0xffUL<<8)
        #define NVM_CFG2_STATUS_CMD                         (0xffUL<<16)
        #define NVM_CFG2_READ_ID                            (0xffUL<<24)

    u32_t nvm_cfg3;
        #define NVM_CFG3_BUFFER_RD_CMD                      (0xffUL<<0)
        #define NVM_CFG3_WRITE_CMD                          (0xffUL<<8)
        #define NVM_CFG3_BUFFER_WRITE_CMD                   (0xffUL<<16)
        #define NVM_CFG3_READ_CMD                           (0xffUL<<24)

    u32_t nvm_sw_arb;
        #define NVM_SW_ARB_ARB_REQ_SET0                     (1UL<<0)
        #define NVM_SW_ARB_ARB_REQ_SET1                     (1UL<<1)
        #define NVM_SW_ARB_ARB_REQ_SET2                     (1UL<<2)
        #define NVM_SW_ARB_ARB_REQ_SET3                     (1UL<<3)
        #define NVM_SW_ARB_ARB_REQ_CLR0                     (1UL<<4)
        #define NVM_SW_ARB_ARB_REQ_CLR1                     (1UL<<5)
        #define NVM_SW_ARB_ARB_REQ_CLR2                     (1UL<<6)
        #define NVM_SW_ARB_ARB_REQ_CLR3                     (1UL<<7)
        #define NVM_SW_ARB_ARB_ARB0                         (1UL<<8)
        #define NVM_SW_ARB_ARB_ARB1                         (1UL<<9)
        #define NVM_SW_ARB_ARB_ARB2                         (1UL<<10)
        #define NVM_SW_ARB_ARB_ARB3                         (1UL<<11)
        #define NVM_SW_ARB_REQ0                             (1UL<<12)
        #define NVM_SW_ARB_REQ1                             (1UL<<13)
        #define NVM_SW_ARB_REQ2                             (1UL<<14)
        #define NVM_SW_ARB_REQ3                             (1UL<<15)

    u32_t nvm_access_enable;
        #define NVM_ACCESS_ENABLE_EN                        (1UL<<0)
        #define NVM_ACCESS_ENABLE_WR_EN                     (1UL<<1)

    u32_t nvm_write1;
        #define NVM_WRITE1_WREN_CMD                         (0xffUL<<0)
        #define NVM_WRITE1_WRDI_CMD                         (0xffUL<<8)
        #define NVM_WRITE1_SR_DATA                          (0xffUL<<16)

    u32_t nvm_cfg4;
        #define NVM_CFG4_FLASH_SIZE                         (0x7UL<<0)
            #define NVM_CFG4_FLASH_SIZE_1MBIT               (0UL<<0)
            #define NVM_CFG4_FLASH_SIZE_2MBIT               (1UL<<0)
            #define NVM_CFG4_FLASH_SIZE_4MBIT               (2UL<<0)
            #define NVM_CFG4_FLASH_SIZE_8MBIT               (3UL<<0)
            #define NVM_CFG4_FLASH_SIZE_16MBIT              (4UL<<0)
            #define NVM_CFG4_FLASH_SIZE_32MBIT              (5UL<<0)
            #define NVM_CFG4_FLASH_SIZE_64MBIT              (6UL<<0)
            #define NVM_CFG4_FLASH_SIZE_128MBIT             (7UL<<0)
        #define NVM_CFG4_FLASH_VENDOR                       (1UL<<3)
            #define NVM_CFG4_FLASH_VENDOR_ST                (0UL<<3)
            #define NVM_CFG4_FLASH_VENDOR_ATMEL             (1UL<<3)
        #define NVM_CFG4_MODE_256_EMPTY_BIT_LOC             (0x3UL<<4)
            #define NVM_CFG4_MODE_256_EMPTY_BIT_LOC_BIT8    (0UL<<4)
            #define NVM_CFG4_MODE_256_EMPTY_BIT_LOC_BIT9    (1UL<<4)
            #define NVM_CFG4_MODE_256_EMPTY_BIT_LOC_BIT10   (2UL<<4)
            #define NVM_CFG4_MODE_256_EMPTY_BIT_LOC_BIT11   (3UL<<4)
        #define NVM_CFG4_STATUS_BIT_POLARITY                (1UL<<6)
        #define NVM_CFG4_RESERVED                           (0x1ffffffUL<<7)

    u32_t nvm_reconfig;
        #define NVM_RECONFIG_ORIG_STRAP_VALUE               (0xfUL<<0)
            #define NVM_RECONFIG_ORIG_STRAP_VALUE_ST        (0UL<<0)
            #define NVM_RECONFIG_ORIG_STRAP_VALUE_ATMEL     (1UL<<0)
        #define NVM_RECONFIG_RECONFIG_STRAP_VALUE           (0xfUL<<4)
        #define NVM_RECONFIG_RESERVED                       (0x7fffffUL<<8)
        #define NVM_RECONFIG_RECONFIG_DONE                  (1UL<<31)

    u32_t unused_0[243];
} nvm_reg_t;


/*
 *  dma_reg definition
 *  offset: 0xc00
 */
typedef struct dma_reg
{
    u32_t dma_command;
        #define DMA_COMMAND_ENABLE                          (1UL<<0)

    u32_t dma_status;
        #define DMA_STATUS_PAR_ERROR_STATE_TE                  (1UL<<0)
        #define DMA_STATUS_READ_TRANSFERS_STAT_TE              (1UL<<16)
        #define DMA_STATUS_READ_DELAY_PCI_CLKS_STAT_TE         (1UL<<17)
        #define DMA_STATUS_BIG_READ_TRANSFERS_STAT_TE          (1UL<<18)
        #define DMA_STATUS_BIG_READ_DELAY_PCI_CLKS_STAT_TE     (1UL<<19)
        #define DMA_STATUS_BIG_READ_RETRY_AFTER_DATA_STAT_TE   (1UL<<20)
        #define DMA_STATUS_WRITE_TRANSFERS_STAT_TE             (1UL<<21)
        #define DMA_STATUS_WRITE_DELAY_PCI_CLKS_STAT_TE        (1UL<<22)
        #define DMA_STATUS_BIG_WRITE_TRANSFERS_STAT_TE         (1UL<<23)
        #define DMA_STATUS_BIG_WRITE_DELAY_PCI_CLKS_STAT_TE    (1UL<<24)
        #define DMA_STATUS_BIG_WRITE_RETRY_AFTER_DATA_STAT_TE  (1UL<<25)
        #define DMA_STATUS_GLOBAL_ERR_XI                       (1UL<<0)
        #define DMA_STATUS_BME_XI                              (1UL<<4)

    u32_t dma_config;
        #define DMA_CONFIG_DATA_BYTE_SWAP_TE                   (1UL<<0)
        #define DMA_CONFIG_DATA_WORD_SWAP_TE                   (1UL<<1)
        #define DMA_CONFIG_CNTL_BYTE_SWAP_TE                   (1UL<<4)
        #define DMA_CONFIG_CNTL_WORD_SWAP_TE                   (1UL<<5)
        #define DMA_CONFIG_ONE_DMA_TE                          (1UL<<6)
        #define DMA_CONFIG_CNTL_TWO_DMA_TE                     (1UL<<7)
        #define DMA_CONFIG_CNTL_FPGA_MODE_TE                   (1UL<<8)
        #define DMA_CONFIG_CNTL_PING_PONG_DMA_TE               (1UL<<10)
        #define DMA_CONFIG_CNTL_PCI_COMP_DLY_TE                (1UL<<11)
        #define DMA_CONFIG_NO_RCHANS_IN_USE_TE                 (0xfUL<<12)
        #define DMA_CONFIG_NO_WCHANS_IN_USE_TE                 (0xfUL<<16)
        #define DMA_CONFIG_PCI_CLK_CMP_BITS_TE                 (0x7UL<<20)
        #define DMA_CONFIG_PCI_FAST_CLK_CMP_TE                 (1UL<<23)
        #define DMA_CONFIG_BIG_SIZE_TE                         (0xfUL<<24)
            #define DMA_CONFIG_BIG_SIZE_NONE_TE                (0UL<<24)
            #define DMA_CONFIG_BIG_SIZE_64_TE                  (1UL<<24)
            #define DMA_CONFIG_BIG_SIZE_128_TE                 (2UL<<24)
            #define DMA_CONFIG_BIG_SIZE_256_TE                 (4UL<<24)
            #define DMA_CONFIG_BIG_SIZE_512_TE                 (8UL<<24)
        #define DMA_CONFIG_DAT_WBSWAP_MODE_XI                  (0x3UL<<0)
        #define DMA_CONFIG_CTL_WBSWAP_MODE_XI                  (0x3UL<<4)
        #define DMA_CONFIG_MAX_PL_XI                           (0x7UL<<12)
            #define DMA_CONFIG_MAX_PL_128B_XI                  (0UL<<12)
            #define DMA_CONFIG_MAX_PL_256B_XI                  (1UL<<12)
            #define DMA_CONFIG_MAX_PL_512B_XI                  (2UL<<12)
        #define DMA_CONFIG_MAX_PL_EN_XI                        (1UL<<15)
        #define DMA_CONFIG_MAX_RRS_XI                          (0x7UL<<16)
            #define DMA_CONFIG_MAX_RRS_128B_XI                 (0UL<<16)
            #define DMA_CONFIG_MAX_RRS_256B_XI                 (1UL<<16)
            #define DMA_CONFIG_MAX_RRS_512B_XI                 (2UL<<16)
            #define DMA_CONFIG_MAX_RRS_1024B_XI                (3UL<<16)
            #define DMA_CONFIG_MAX_RRS_2048B_XI                (4UL<<16)
            #define DMA_CONFIG_MAX_RRS_4096B_XI                (5UL<<16)
        #define DMA_CONFIG_MAX_RRS_EN_XI                       (1UL<<19)
        #define DMA_CONFIG_NO_64SWAP_EN_XI                     (1UL<<31)

    u32_t dma_blackout;
        #define DMA_BLACKOUT_RD_RETRY_BLACKOUT              (0xffUL<<0)
        #define DMA_BLACKOUT_2ND_RD_RETRY_BLACKOUT          (0xffUL<<8)
        #define DMA_BLACKOUT_WR_RETRY_BLACKOUT              (0xffUL<<16)

    u32_t dma_read_master_setting_0;
        #define DMA_READ_MASTER_SETTING_0_TBDC_NO_SNOOP     (1UL<<0)
        #define DMA_READ_MASTER_SETTING_0_TBDC_RELAX_ORDER  (1UL<<1)
        #define DMA_READ_MASTER_SETTING_0_TBDC_PRIORITY     (1UL<<2)
        #define DMA_READ_MASTER_SETTING_0_TBDC_TRAFFIC_CLASS  (0x7UL<<4)
        #define DMA_READ_MASTER_SETTING_0_TBDC_PARAM_EN     (1UL<<7)
        #define DMA_READ_MASTER_SETTING_0_RBDC_NO_SNOOP     (1UL<<8)
        #define DMA_READ_MASTER_SETTING_0_RBDC_RELAX_ORDER  (1UL<<9)
        #define DMA_READ_MASTER_SETTING_0_RBDC_PRIORITY     (1UL<<10)
        #define DMA_READ_MASTER_SETTING_0_RBDC_TRAFFIC_CLASS  (0x7UL<<12)
        #define DMA_READ_MASTER_SETTING_0_RBDC_PARAM_EN     (1UL<<15)
        #define DMA_READ_MASTER_SETTING_0_TDMA_NO_SNOOP     (1UL<<16)
        #define DMA_READ_MASTER_SETTING_0_TDMA_RELAX_ORDER  (1UL<<17)
        #define DMA_READ_MASTER_SETTING_0_TDMA_PRIORITY     (1UL<<18)
        #define DMA_READ_MASTER_SETTING_0_TDMA_TRAFFIC_CLASS  (0x7UL<<20)
        #define DMA_READ_MASTER_SETTING_0_TDMA_PARAM_EN     (1UL<<23)
        #define DMA_READ_MASTER_SETTING_0_CTX_NO_SNOOP      (1UL<<24)
        #define DMA_READ_MASTER_SETTING_0_CTX_RELAX_ORDER   (1UL<<25)
        #define DMA_READ_MASTER_SETTING_0_CTX_PRIORITY      (1UL<<26)
        #define DMA_READ_MASTER_SETTING_0_CTX_TRAFFIC_CLASS  (0x7UL<<28)
        #define DMA_READ_MASTER_SETTING_0_CTX_PARAM_EN      (1UL<<31)

    u32_t dma_read_master_setting_1;
        #define DMA_READ_MASTER_SETTING_1_COM_NO_SNOOP      (1UL<<0)
        #define DMA_READ_MASTER_SETTING_1_COM_RELAX_ORDER   (1UL<<1)
        #define DMA_READ_MASTER_SETTING_1_COM_PRIORITY      (1UL<<2)
        #define DMA_READ_MASTER_SETTING_1_COM_TRAFFIC_CLASS  (0x7UL<<4)
        #define DMA_READ_MASTER_SETTING_1_COM_PARAM_EN      (1UL<<7)
        #define DMA_READ_MASTER_SETTING_1_CP_NO_SNOOP       (1UL<<8)
        #define DMA_READ_MASTER_SETTING_1_CP_RELAX_ORDER    (1UL<<9)
        #define DMA_READ_MASTER_SETTING_1_CP_PRIORITY       (1UL<<10)
        #define DMA_READ_MASTER_SETTING_1_CP_TRAFFIC_CLASS  (0x7UL<<12)
        #define DMA_READ_MASTER_SETTING_1_CP_PARAM_EN       (1UL<<15)

    u32_t dma_write_master_setting_0;
        #define DMA_WRITE_MASTER_SETTING_0_HC_NO_SNOOP      (1UL<<0)
        #define DMA_WRITE_MASTER_SETTING_0_HC_RELAX_ORDER   (1UL<<1)
        #define DMA_WRITE_MASTER_SETTING_0_HC_PRIORITY      (1UL<<2)
        #define DMA_WRITE_MASTER_SETTING_0_HC_CS_VLD        (1UL<<3)
        #define DMA_WRITE_MASTER_SETTING_0_HC_TRAFFIC_CLASS  (0x7UL<<4)
        #define DMA_WRITE_MASTER_SETTING_0_HC_PARAM_EN      (1UL<<7)
        #define DMA_WRITE_MASTER_SETTING_0_RDMA_NO_SNOOP    (1UL<<8)
        #define DMA_WRITE_MASTER_SETTING_0_RDMA_RELAX_ORDER  (1UL<<9)
        #define DMA_WRITE_MASTER_SETTING_0_RDMA_PRIORITY    (1UL<<10)
        #define DMA_WRITE_MASTER_SETTING_0_RDMA_CS_VLD      (1UL<<11)
        #define DMA_WRITE_MASTER_SETTING_0_RDMA_TRAFFIC_CLASS  (0x7UL<<12)
        #define DMA_WRITE_MASTER_SETTING_0_RDMA_PARAM_EN    (1UL<<15)
        #define DMA_WRITE_MASTER_SETTING_0_CTX_NO_SNOOP     (1UL<<24)
        #define DMA_WRITE_MASTER_SETTING_0_CTX_RELAX_ORDER  (1UL<<25)
        #define DMA_WRITE_MASTER_SETTING_0_CTX_PRIORITY     (1UL<<26)
        #define DMA_WRITE_MASTER_SETTING_0_CTX_CS_VLD       (1UL<<27)
        #define DMA_WRITE_MASTER_SETTING_0_CTX_TRAFFIC_CLASS  (0x7UL<<28)
        #define DMA_WRITE_MASTER_SETTING_0_CTX_PARAM_EN     (1UL<<31)

    u32_t dma_write_master_setting_1;
        #define DMA_WRITE_MASTER_SETTING_1_COM_NO_SNOOP     (1UL<<0)
        #define DMA_WRITE_MASTER_SETTING_1_COM_RELAX_ORDER  (1UL<<1)
        #define DMA_WRITE_MASTER_SETTING_1_COM_PRIORITY     (1UL<<2)
        #define DMA_WRITE_MASTER_SETTING_1_COM_CS_VLD       (1UL<<3)
        #define DMA_WRITE_MASTER_SETTING_1_COM_TRAFFIC_CLASS  (0x7UL<<4)
        #define DMA_WRITE_MASTER_SETTING_1_COM_PARAM_EN     (1UL<<7)
        #define DMA_WRITE_MASTER_SETTING_1_CP_NO_SNOOP      (1UL<<8)
        #define DMA_WRITE_MASTER_SETTING_1_CP_RELAX_ORDER   (1UL<<9)
        #define DMA_WRITE_MASTER_SETTING_1_CP_PRIORITY      (1UL<<10)
        #define DMA_WRITE_MASTER_SETTING_1_CP_CS_VLD        (1UL<<11)
        #define DMA_WRITE_MASTER_SETTING_1_CP_TRAFFIC_CLASS  (0x7UL<<12)
        #define DMA_WRITE_MASTER_SETTING_1_CP_PARAM_EN      (1UL<<15)

    u32_t dma_arbiter;
        #define DMA_ARBITER_NUM_READS                       (0x7UL<<0)
        #define DMA_ARBITER_WR_ARB_MODE                     (1UL<<4)
            #define DMA_ARBITER_WR_ARB_MODE_STRICT          (0UL<<4)
            #define DMA_ARBITER_WR_ARB_MODE_RND_RBN         (1UL<<4)
        #define DMA_ARBITER_RD_ARB_MODE                     (0x3UL<<5)
            #define DMA_ARBITER_RD_ARB_MODE_STRICT          (0UL<<5)
            #define DMA_ARBITER_RD_ARB_MODE_RND_RBN         (1UL<<5)
            #define DMA_ARBITER_RD_ARB_MODE_WGT_RND_RBN     (2UL<<5)
        #define DMA_ARBITER_ALT_MODE_EN                     (1UL<<8)
        #define DMA_ARBITER_RR_MODE                         (1UL<<9)
        #define DMA_ARBITER_TIMER_MODE                      (1UL<<10)
        #define DMA_ARBITER_OUSTD_READ_REQ                  (0xfUL<<12)

    u32_t dma_arb_timers;
        #define DMA_ARB_TIMERS_RD_DRR_WAIT_TIME             (0xffUL<<0)
        #define DMA_ARB_TIMERS_TM_MIN_TIMEOUT               (0xffUL<<12)
        #define DMA_ARB_TIMERS_TM_MAX_TIMEOUT               (0xfffUL<<20)

    u32_t unused_0;
    u32_t dma_debug_vect_peek;
        #define DMA_DEBUG_VECT_PEEK_1_VALUE                 (0x7ffUL<<0)
        #define DMA_DEBUG_VECT_PEEK_1_PEEK_EN               (1UL<<11)
        #define DMA_DEBUG_VECT_PEEK_1_SEL                   (0xfUL<<12)
        #define DMA_DEBUG_VECT_PEEK_2_VALUE                 (0x7ffUL<<16)
        #define DMA_DEBUG_VECT_PEEK_2_PEEK_EN               (1UL<<27)
        #define DMA_DEBUG_VECT_PEEK_2_SEL                   (0xfUL<<28)

    u32_t dma_tag_ram_00;
        #define DMA_TAG_RAM_00_CHANNEL                      (0xfUL<<0)
        #define DMA_TAG_RAM_00_MASTER                       (0x7UL<<4)
            #define DMA_TAG_RAM_00_MASTER_CTX               (0UL<<4)
            #define DMA_TAG_RAM_00_MASTER_RBDC              (1UL<<4)
            #define DMA_TAG_RAM_00_MASTER_TBDC              (2UL<<4)
            #define DMA_TAG_RAM_00_MASTER_COM               (3UL<<4)
            #define DMA_TAG_RAM_00_MASTER_CP                (4UL<<4)
            #define DMA_TAG_RAM_00_MASTER_TDMA              (5UL<<4)
        #define DMA_TAG_RAM_00_SWAP                         (0x3UL<<7)
            #define DMA_TAG_RAM_00_SWAP_CONFIG              (0UL<<7)
            #define DMA_TAG_RAM_00_SWAP_DATA                (1UL<<7)
            #define DMA_TAG_RAM_00_SWAP_CONTROL             (2UL<<7)
        #define DMA_TAG_RAM_00_FUNCTION                     (1UL<<9)
        #define DMA_TAG_RAM_00_VALID                        (1UL<<10)

    u32_t dma_tag_ram_01;
        #define DMA_TAG_RAM_01_CHANNEL                      (0xfUL<<0)
        #define DMA_TAG_RAM_01_MASTER                       (0x7UL<<4)
            #define DMA_TAG_RAM_01_MASTER_CTX               (0UL<<4)
            #define DMA_TAG_RAM_01_MASTER_RBDC              (1UL<<4)
            #define DMA_TAG_RAM_01_MASTER_TBDC              (2UL<<4)
            #define DMA_TAG_RAM_01_MASTER_COM               (3UL<<4)
            #define DMA_TAG_RAM_01_MASTER_CP                (4UL<<4)
            #define DMA_TAG_RAM_01_MASTER_TDMA              (5UL<<4)
        #define DMA_TAG_RAM_01_SWAP                         (0x3UL<<7)
            #define DMA_TAG_RAM_01_SWAP_CONFIG              (0UL<<7)
            #define DMA_TAG_RAM_01_SWAP_DATA                (1UL<<7)
            #define DMA_TAG_RAM_01_SWAP_CONTROL             (2UL<<7)
        #define DMA_TAG_RAM_01_FUNCTION                     (1UL<<9)
        #define DMA_TAG_RAM_01_VALID                        (1UL<<10)

    u32_t dma_tag_ram_02;
        #define DMA_TAG_RAM_02_CHANNEL                      (0xfUL<<0)
        #define DMA_TAG_RAM_02_MASTER                       (0x7UL<<4)
            #define DMA_TAG_RAM_02_MASTER_CTX               (0UL<<4)
            #define DMA_TAG_RAM_02_MASTER_RBDC              (1UL<<4)
            #define DMA_TAG_RAM_02_MASTER_TBDC              (2UL<<4)
            #define DMA_TAG_RAM_02_MASTER_COM               (3UL<<4)
            #define DMA_TAG_RAM_02_MASTER_CP                (4UL<<4)
            #define DMA_TAG_RAM_02_MASTER_TDMA              (5UL<<4)
        #define DMA_TAG_RAM_02_SWAP                         (0x3UL<<7)
            #define DMA_TAG_RAM_02_SWAP_CONFIG              (0UL<<7)
            #define DMA_TAG_RAM_02_SWAP_DATA                (1UL<<7)
            #define DMA_TAG_RAM_02_SWAP_CONTROL             (2UL<<7)
        #define DMA_TAG_RAM_02_FUNCTION                     (1UL<<9)
        #define DMA_TAG_RAM_02_VALID                        (1UL<<10)

    u32_t dma_tag_ram_03;
        #define DMA_TAG_RAM_03_CHANNEL                      (0xfUL<<0)
        #define DMA_TAG_RAM_03_MASTER                       (0x7UL<<4)
            #define DMA_TAG_RAM_03_MASTER_CTX               (0UL<<4)
            #define DMA_TAG_RAM_03_MASTER_RBDC              (1UL<<4)
            #define DMA_TAG_RAM_03_MASTER_TBDC              (2UL<<4)
            #define DMA_TAG_RAM_03_MASTER_COM               (3UL<<4)
            #define DMA_TAG_RAM_03_MASTER_CP                (4UL<<4)
            #define DMA_TAG_RAM_03_MASTER_TDMA              (5UL<<4)
        #define DMA_TAG_RAM_03_SWAP                         (0x3UL<<7)
            #define DMA_TAG_RAM_03_SWAP_CONFIG              (0UL<<7)
            #define DMA_TAG_RAM_03_SWAP_DATA                (1UL<<7)
            #define DMA_TAG_RAM_03_SWAP_CONTROL             (2UL<<7)
        #define DMA_TAG_RAM_03_FUNCTION                     (1UL<<9)
        #define DMA_TAG_RAM_03_VALID                        (1UL<<10)

    u32_t dma_tag_ram_04;
        #define DMA_TAG_RAM_04_CHANNEL                      (0xfUL<<0)
        #define DMA_TAG_RAM_04_MASTER                       (0x7UL<<4)
            #define DMA_TAG_RAM_04_MASTER_CTX               (0UL<<4)
            #define DMA_TAG_RAM_04_MASTER_RBDC              (1UL<<4)
            #define DMA_TAG_RAM_04_MASTER_TBDC              (2UL<<4)
            #define DMA_TAG_RAM_04_MASTER_COM               (3UL<<4)
            #define DMA_TAG_RAM_04_MASTER_CP                (4UL<<4)
            #define DMA_TAG_RAM_04_MASTER_TDMA              (5UL<<4)
        #define DMA_TAG_RAM_04_SWAP                         (0x3UL<<7)
            #define DMA_TAG_RAM_04_SWAP_CONFIG              (0UL<<7)
            #define DMA_TAG_RAM_04_SWAP_DATA                (1UL<<7)
            #define DMA_TAG_RAM_04_SWAP_CONTROL             (2UL<<7)
        #define DMA_TAG_RAM_04_FUNCTION                     (1UL<<9)
        #define DMA_TAG_RAM_04_VALID                        (1UL<<10)

    u32_t dma_tag_ram_05;
        #define DMA_TAG_RAM_05_CHANNEL                      (0xfUL<<0)
        #define DMA_TAG_RAM_05_MASTER                       (0x7UL<<4)
            #define DMA_TAG_RAM_05_MASTER_CTX               (0UL<<4)
            #define DMA_TAG_RAM_05_MASTER_RBDC              (1UL<<4)
            #define DMA_TAG_RAM_05_MASTER_TBDC              (2UL<<4)
            #define DMA_TAG_RAM_05_MASTER_COM               (3UL<<4)
            #define DMA_TAG_RAM_05_MASTER_CP                (4UL<<4)
            #define DMA_TAG_RAM_05_MASTER_TDMA              (5UL<<4)
        #define DMA_TAG_RAM_05_SWAP                         (0x3UL<<7)
            #define DMA_TAG_RAM_05_SWAP_CONFIG              (0UL<<7)
            #define DMA_TAG_RAM_05_SWAP_DATA                (1UL<<7)
            #define DMA_TAG_RAM_05_SWAP_CONTROL             (2UL<<7)
        #define DMA_TAG_RAM_05_FUNCTION                     (1UL<<9)
        #define DMA_TAG_RAM_05_VALID                        (1UL<<10)

    u32_t dma_tag_ram_06;
        #define DMA_TAG_RAM_06_CHANNEL                      (0xfUL<<0)
        #define DMA_TAG_RAM_06_MASTER                       (0x7UL<<4)
            #define DMA_TAG_RAM_06_MASTER_CTX               (0UL<<4)
            #define DMA_TAG_RAM_06_MASTER_RBDC              (1UL<<4)
            #define DMA_TAG_RAM_06_MASTER_TBDC              (2UL<<4)
            #define DMA_TAG_RAM_06_MASTER_COM               (3UL<<4)
            #define DMA_TAG_RAM_06_MASTER_CP                (4UL<<4)
            #define DMA_TAG_RAM_06_MASTER_TDMA              (5UL<<4)
        #define DMA_TAG_RAM_06_SWAP                         (0x3UL<<7)
            #define DMA_TAG_RAM_06_SWAP_CONFIG              (0UL<<7)
            #define DMA_TAG_RAM_06_SWAP_DATA                (1UL<<7)
            #define DMA_TAG_RAM_06_SWAP_CONTROL             (2UL<<7)
        #define DMA_TAG_RAM_06_FUNCTION                     (1UL<<9)
        #define DMA_TAG_RAM_06_VALID                        (1UL<<10)

    u32_t dma_tag_ram_07;
        #define DMA_TAG_RAM_07_CHANNEL                      (0xfUL<<0)
        #define DMA_TAG_RAM_07_MASTER                       (0x7UL<<4)
            #define DMA_TAG_RAM_07_MASTER_CTX               (0UL<<4)
            #define DMA_TAG_RAM_07_MASTER_RBDC              (1UL<<4)
            #define DMA_TAG_RAM_07_MASTER_TBDC              (2UL<<4)
            #define DMA_TAG_RAM_07_MASTER_COM               (3UL<<4)
            #define DMA_TAG_RAM_07_MASTER_CP                (4UL<<4)
            #define DMA_TAG_RAM_07_MASTER_TDMA              (5UL<<4)
        #define DMA_TAG_RAM_07_SWAP                         (0x3UL<<7)
            #define DMA_TAG_RAM_07_SWAP_CONFIG              (0UL<<7)
            #define DMA_TAG_RAM_07_SWAP_DATA                (1UL<<7)
            #define DMA_TAG_RAM_07_SWAP_CONTROL             (2UL<<7)
        #define DMA_TAG_RAM_07_FUNCTION                     (1UL<<9)
        #define DMA_TAG_RAM_07_VALID                        (1UL<<10)

    u32_t dma_tag_ram_08;
        #define DMA_TAG_RAM_08_CHANNEL                      (0xfUL<<0)
        #define DMA_TAG_RAM_08_MASTER                       (0x7UL<<4)
            #define DMA_TAG_RAM_08_MASTER_CTX               (0UL<<4)
            #define DMA_TAG_RAM_08_MASTER_RBDC              (1UL<<4)
            #define DMA_TAG_RAM_08_MASTER_TBDC              (2UL<<4)
            #define DMA_TAG_RAM_08_MASTER_COM               (3UL<<4)
            #define DMA_TAG_RAM_08_MASTER_CP                (4UL<<4)
            #define DMA_TAG_RAM_08_MASTER_TDMA              (5UL<<4)
        #define DMA_TAG_RAM_08_SWAP                         (0x3UL<<7)
            #define DMA_TAG_RAM_08_SWAP_CONFIG              (0UL<<7)
            #define DMA_TAG_RAM_08_SWAP_DATA                (1UL<<7)
            #define DMA_TAG_RAM_08_SWAP_CONTROL             (2UL<<7)
        #define DMA_TAG_RAM_08_FUNCTION                     (1UL<<9)
        #define DMA_TAG_RAM_08_VALID                        (1UL<<10)

    u32_t dma_tag_ram_09;
        #define DMA_TAG_RAM_09_CHANNEL                      (0xfUL<<0)
        #define DMA_TAG_RAM_09_MASTER                       (0x7UL<<4)
            #define DMA_TAG_RAM_09_MASTER_CTX               (0UL<<4)
            #define DMA_TAG_RAM_09_MASTER_RBDC              (1UL<<4)
            #define DMA_TAG_RAM_09_MASTER_TBDC              (2UL<<4)
            #define DMA_TAG_RAM_09_MASTER_COM               (3UL<<4)
            #define DMA_TAG_RAM_09_MASTER_CP                (4UL<<4)
            #define DMA_TAG_RAM_09_MASTER_TDMA              (5UL<<4)
        #define DMA_TAG_RAM_09_SWAP                         (0x3UL<<7)
            #define DMA_TAG_RAM_09_SWAP_CONFIG              (0UL<<7)
            #define DMA_TAG_RAM_09_SWAP_DATA                (1UL<<7)
            #define DMA_TAG_RAM_09_SWAP_CONTROL             (2UL<<7)
        #define DMA_TAG_RAM_09_FUNCTION                     (1UL<<9)
        #define DMA_TAG_RAM_09_VALID                        (1UL<<10)

    u32_t dma_tag_ram_10;
        #define DMA_TAG_RAM_10_CHANNEL                      (0xfUL<<0)
        #define DMA_TAG_RAM_10_MASTER                       (0x7UL<<4)
            #define DMA_TAG_RAM_10_MASTER_CTX               (0UL<<4)
            #define DMA_TAG_RAM_10_MASTER_RBDC              (1UL<<4)
            #define DMA_TAG_RAM_10_MASTER_TBDC              (2UL<<4)
            #define DMA_TAG_RAM_10_MASTER_COM               (3UL<<4)
            #define DMA_TAG_RAM_10_MASTER_CP                (4UL<<4)
            #define DMA_TAG_RAM_10_MASTER_TDMA              (5UL<<4)
        #define DMA_TAG_RAM_10_SWAP                         (0x3UL<<7)
            #define DMA_TAG_RAM_10_SWAP_CONFIG              (0UL<<7)
            #define DMA_TAG_RAM_10_SWAP_DATA                (1UL<<7)
            #define DMA_TAG_RAM_10_SWAP_CONTROL             (2UL<<7)
        #define DMA_TAG_RAM_10_FUNCTION                     (1UL<<9)
        #define DMA_TAG_RAM_10_VALID                        (1UL<<10)

    u32_t dma_tag_ram_11;
        #define DMA_TAG_RAM_11_CHANNEL                      (0xfUL<<0)
        #define DMA_TAG_RAM_11_MASTER                       (0x7UL<<4)
            #define DMA_TAG_RAM_11_MASTER_CTX               (0UL<<4)
            #define DMA_TAG_RAM_11_MASTER_RBDC              (1UL<<4)
            #define DMA_TAG_RAM_11_MASTER_TBDC              (2UL<<4)
            #define DMA_TAG_RAM_11_MASTER_COM               (3UL<<4)
            #define DMA_TAG_RAM_11_MASTER_CP                (4UL<<4)
            #define DMA_TAG_RAM_11_MASTER_TDMA              (5UL<<4)
        #define DMA_TAG_RAM_11_SWAP                         (0x3UL<<7)
            #define DMA_TAG_RAM_11_SWAP_CONFIG              (0UL<<7)
            #define DMA_TAG_RAM_11_SWAP_DATA                (1UL<<7)
            #define DMA_TAG_RAM_11_SWAP_CONTROL             (2UL<<7)
        #define DMA_TAG_RAM_11_FUNCTION                     (1UL<<9)
        #define DMA_TAG_RAM_11_VALID                        (1UL<<10)

    u32_t dma_rchan_stat_22;
    u32_t dma_rchan_stat_30;
    u32_t dma_rchan_stat_31;
    u32_t dma_rchan_stat_32;
    u32_t dma_rchan_stat_40;
    u32_t dma_rchan_stat_41;
    u32_t dma_rchan_stat_42;
    u32_t dma_rchan_stat_50;
    u32_t dma_rchan_stat_51;
    u32_t dma_rchan_stat_52;
    u32_t dma_rchan_stat_60;
    u32_t dma_rchan_stat_61;
    u32_t dma_rchan_stat_62;
    u32_t dma_rchan_stat_70;
    u32_t dma_rchan_stat_71;
    u32_t dma_rchan_stat_72;
    u32_t dma_wchan_stat_00;
        #define DMA_WCHAN_STAT_00_WCHAN_STA_HOST_ADDR_LOW   (0xffffffffUL<<0)

    u32_t dma_wchan_stat_01;
        #define DMA_WCHAN_STAT_01_WCHAN_STA_HOST_ADDR_HIGH  (0xffffffffUL<<0)

    u32_t dma_wchan_stat_02;
        #define DMA_WCHAN_STAT_02_LENGTH                    (0xffffUL<<0)
        #define DMA_WCHAN_STAT_02_WORD_SWAP                 (1UL<<16)
        #define DMA_WCHAN_STAT_02_BYTE_SWAP                 (1UL<<17)
        #define DMA_WCHAN_STAT_02_PRIORITY_LVL              (1UL<<18)

    u32_t dma_wchan_stat_10;
    u32_t dma_wchan_stat_11;
    u32_t dma_wchan_stat_12;
    u32_t dma_wchan_stat_20;
    u32_t dma_wchan_stat_21;
    u32_t dma_wchan_stat_22;
    u32_t dma_wchan_stat_30;
    u32_t dma_wchan_stat_31;
    u32_t dma_wchan_stat_32;
    u32_t dma_wchan_stat_40;
    u32_t dma_wchan_stat_41;
    u32_t dma_wchan_stat_42;
    u32_t dma_wchan_stat_50;
    u32_t dma_wchan_stat_51;
    u32_t dma_wchan_stat_52;
    u32_t dma_wchan_stat_60;
    u32_t dma_wchan_stat_61;
    u32_t dma_wchan_stat_62;
    u32_t dma_wchan_stat_70;
    u32_t dma_wchan_stat_71;
    u32_t dma_wchan_stat_72;
    u32_t dma_arb_stat_00;
        #define DMA_ARB_STAT_00_MASTER                      (0xffffUL<<0)
        #define DMA_ARB_STAT_00_MASTER_ENC                  (0xffUL<<16)
        #define DMA_ARB_STAT_00_CUR_BINMSTR                 (0xffUL<<24)

    u32_t dma_arb_stat_01;
        #define DMA_ARB_STAT_01_LPR_RPTR                    (0xfUL<<0)
        #define DMA_ARB_STAT_01_LPR_WPTR                    (0xfUL<<4)
        #define DMA_ARB_STAT_01_LPB_RPTR                    (0xfUL<<8)
        #define DMA_ARB_STAT_01_LPB_WPTR                    (0xfUL<<12)
        #define DMA_ARB_STAT_01_HPR_RPTR                    (0xfUL<<16)
        #define DMA_ARB_STAT_01_HPR_WPTR                    (0xfUL<<20)
        #define DMA_ARB_STAT_01_HPB_RPTR                    (0xfUL<<24)
        #define DMA_ARB_STAT_01_HPB_WPTR                    (0xfUL<<28)

    u32_t unused_1[126];
    u32_t dma_fuse_ctrl0_cmd;
        #define DMA_FUSE_CTRL0_CMD_PWRUP_DONE               (1UL<<0)
        #define DMA_FUSE_CTRL0_CMD_SHIFT_DONE               (1UL<<1)
        #define DMA_FUSE_CTRL0_CMD_SHIFT                    (1UL<<2)
        #define DMA_FUSE_CTRL0_CMD_LOAD                     (1UL<<3)
        #define DMA_FUSE_CTRL0_CMD_SEL                      (0xfUL<<8)

    u32_t dma_fuse_ctrl0_data;
    u32_t dma_fuse_ctrl1_cmd;
        #define DMA_FUSE_CTRL1_CMD_PWRUP_DONE               (1UL<<0)
        #define DMA_FUSE_CTRL1_CMD_SHIFT_DONE               (1UL<<1)
        #define DMA_FUSE_CTRL1_CMD_SHIFT                    (1UL<<2)
        #define DMA_FUSE_CTRL1_CMD_LOAD                     (1UL<<3)
        #define DMA_FUSE_CTRL1_CMD_SEL                      (0xfUL<<8)

    u32_t dma_fuse_ctrl1_data;
    u32_t dma_fuse_ctrl2_cmd;
        #define DMA_FUSE_CTRL2_CMD_PWRUP_DONE               (1UL<<0)
        #define DMA_FUSE_CTRL2_CMD_SHIFT_DONE               (1UL<<1)
        #define DMA_FUSE_CTRL2_CMD_SHIFT                    (1UL<<2)
        #define DMA_FUSE_CTRL2_CMD_LOAD                     (1UL<<3)
        #define DMA_FUSE_CTRL2_CMD_SEL                      (0xfUL<<8)

    u32_t dma_fuse_ctrl2_data;
    u32_t unused_2[58];
} dma_reg_t;


/*
 *  context_reg definition
 *  offset: 0x1000
 */
typedef struct context_reg
{
    u32_t ctx_command;
        #define CTX_COMMAND_ENABLED                         (1UL<<0)
        #define CTX_COMMAND_DISABLE_USAGE_CNT               (1UL<<1)
        #define CTX_COMMAND_DISABLE_PLRU                    (1UL<<2)
        #define CTX_COMMAND_DISABLE_COMBINE_READ            (1UL<<3)
        #define CTX_COMMAND_FLUSH_AHEAD                     (0x1fUL<<8)
        #define CTX_COMMAND_MEM_INIT                        (1UL<<13)
        #define CTX_COMMAND_PAGE_SIZE                       (0xfUL<<16)
            #define CTX_COMMAND_PAGE_SIZE_256               (0UL<<16)
            #define CTX_COMMAND_PAGE_SIZE_512               (1UL<<16)
            #define CTX_COMMAND_PAGE_SIZE_1K                (2UL<<16)
            #define CTX_COMMAND_PAGE_SIZE_2K                (3UL<<16)
            #define CTX_COMMAND_PAGE_SIZE_4K                (4UL<<16)
            #define CTX_COMMAND_PAGE_SIZE_8K                (5UL<<16)
            #define CTX_COMMAND_PAGE_SIZE_16K               (6UL<<16)
            #define CTX_COMMAND_PAGE_SIZE_32K               (7UL<<16)
            #define CTX_COMMAND_PAGE_SIZE_64K               (8UL<<16)
            #define CTX_COMMAND_PAGE_SIZE_128K              (9UL<<16)
            #define CTX_COMMAND_PAGE_SIZE_256K              (10UL<<16)
            #define CTX_COMMAND_PAGE_SIZE_512K              (11UL<<16)
            #define CTX_COMMAND_PAGE_SIZE_1M                (12UL<<16)

    u32_t ctx_status;
        #define CTX_STATUS_LOCK_WAIT                        (1UL<<0)
        #define CTX_STATUS_READ_STAT                        (1UL<<16)
        #define CTX_STATUS_WRITE_STAT                       (1UL<<17)
        #define CTX_STATUS_ACC_STALL_STAT                   (1UL<<18)
        #define CTX_STATUS_LOCK_STALL_STAT                  (1UL<<19)
        #define CTX_STATUS_EXT_READ_STAT                    (1UL<<20)
        #define CTX_STATUS_EXT_WRITE_STAT                   (1UL<<21)
        #define CTX_STATUS_MISS_STAT                        (1UL<<22)
        #define CTX_STATUS_HIT_STAT                         (1UL<<23)
        #define CTX_STATUS_DEAD_LOCK                        (1UL<<24)
        #define CTX_STATUS_USAGE_CNT_ERR                    (1UL<<25)
        #define CTX_STATUS_INVALID_PAGE                     (1UL<<26)

    u32_t ctx_virt_addr;
        #define CTX_VIRT_ADDR_VIRT_ADDR                     (0x7fffUL<<6)

    u32_t ctx_page_tbl;
        #define CTX_PAGE_TBL_PAGE_TBL                       (0x3fffUL<<6)

    u32_t ctx_data_adr;
        #define CTX_DATA_ADR_DATA_ADR                       (0x7ffffUL<<2)

    u32_t ctx_data;
    u32_t ctx_lock;
        #define CTX_LOCK_TYPE                               (0x7UL<<0)
            #define CTX_LOCK_TYPE_LOCK_TYPE_VOID_TE            (0UL<<0)
            #define CTX_LOCK_TYPE_LOCK_TYPE_PROTOCOL_TE        (1UL<<0)
            #define CTX_LOCK_TYPE_LOCK_TYPE_TX_TE              (2UL<<0)
            #define CTX_LOCK_TYPE_LOCK_TYPE_TIMER_TE           (4UL<<0)
            #define CTX_LOCK_TYPE_LOCK_TYPE_COMPLETE_TE        (7UL<<0)
            #define CTX_LOCK_TYPE_VOID_XI                      (0UL<<0)
            #define CTX_LOCK_TYPE_PROTOCOL_XI                  (1UL<<0)
            #define CTX_LOCK_TYPE_TX_XI                        (2UL<<0)
            #define CTX_LOCK_TYPE_TIMER_XI                     (4UL<<0)
            #define CTX_LOCK_TYPE_COMPLETE_XI                  (7UL<<0)
        #define CTX_LOCK_CID_VALUE                          (0x3fffUL<<7)
        #define CTX_LOCK_GRANTED                            (1UL<<26)
        #define CTX_LOCK_MODE                               (0x7UL<<27)
            #define CTX_LOCK_MODE_UNLOCK                    (0UL<<27)
            #define CTX_LOCK_MODE_IMMEDIATE                 (1UL<<27)
            #define CTX_LOCK_MODE_SURE                      (2UL<<27)
        #define CTX_LOCK_STATUS                             (1UL<<30)
        #define CTX_LOCK_REQ                                (1UL<<31)

    u32_t ctx_ctx_ctrl;
        #define CTX_CTX_CTRL_CTX_ADDR                       (0x7ffffUL<<2)
        #define CTX_CTX_CTRL_MOD_USAGE_CNT                  (0x3UL<<21)
        #define CTX_CTX_CTRL_NO_RAM_ACC                     (1UL<<23)
        #define CTX_CTX_CTRL_PREFETCH_SIZE                  (0x3UL<<24)
        #define CTX_CTX_CTRL_ATTR                           (1UL<<26)
        #define CTX_CTX_CTRL_WRITE_REQ                      (1UL<<30)
        #define CTX_CTX_CTRL_READ_REQ                       (1UL<<31)

    u32_t ctx_ctx_data;
    u32_t unused_0[7];
    u32_t ctx_access_status;
        #define CTX_ACCESS_STATUS_MASTERENCODED_TE             (0xfUL<<0)
        #define CTX_ACCESS_STATUS_ACCESSMEMORYSM_TE            (0x3UL<<10)
        #define CTX_ACCESS_STATUS_PAGETABLEINITSM_TE           (0x3UL<<12)
        #define CTX_ACCESS_STATUS_ACCESSMEMORYINITSM_TE        (0x3UL<<14)
        #define CTX_ACCESS_STATUS_QUALIFIED_REQUEST_TE         (0x7ffUL<<17)
        #define CTX_ACCESS_STATUS_CAMMASTERENCODED_XI          (0x1fUL<<0)
        #define CTX_ACCESS_STATUS_CACHEMASTERENCODED_XI        (0x1fUL<<5)
        #define CTX_ACCESS_STATUS_REQUEST_XI                   (0x3fffffUL<<10)

    u32_t ctx_dbg_lock_status;
        #define CTX_DBG_LOCK_STATUS_SM                      (0x3ffUL<<0)
        #define CTX_DBG_LOCK_STATUS_MATCH                   (0x3ffUL<<22)

    u32_t ctx_cache_ctrl_status;
        #define CTX_CACHE_CTRL_STATUS_RFIFO_OVERFLOW        (1UL<<0)
        #define CTX_CACHE_CTRL_STATUS_INVALID_READ_COMP     (1UL<<1)
        #define CTX_CACHE_CTRL_STATUS_FLUSH_START           (1UL<<6)
        #define CTX_CACHE_CTRL_STATUS_FREE_ENTRY_CNT        (0x3fUL<<7)
        #define CTX_CACHE_CTRL_STATUS_CACHE_ENTRY_NEEDED    (0x3fUL<<13)
        #define CTX_CACHE_CTRL_STATUS_RD_CHAN0_ACTIVE       (1UL<<19)
        #define CTX_CACHE_CTRL_STATUS_RD_CHAN1_ACTIVE       (1UL<<20)
        #define CTX_CACHE_CTRL_STATUS_RD_CHAN2_ACTIVE       (1UL<<21)
        #define CTX_CACHE_CTRL_STATUS_RD_CHAN3_ACTIVE       (1UL<<22)
        #define CTX_CACHE_CTRL_STATUS_RD_CHAN4_ACTIVE       (1UL<<23)
        #define CTX_CACHE_CTRL_STATUS_RD_CHAN5_ACTIVE       (1UL<<24)
        #define CTX_CACHE_CTRL_STATUS_RD_CHAN6_ACTIVE       (1UL<<25)
        #define CTX_CACHE_CTRL_STATUS_RD_CHAN7_ACTIVE       (1UL<<26)
        #define CTX_CACHE_CTRL_STATUS_RD_CHAN8_ACTIVE       (1UL<<27)
        #define CTX_CACHE_CTRL_STATUS_RD_CHAN9_ACTIVE       (1UL<<28)
        #define CTX_CACHE_CTRL_STATUS_RD_CHAN10_ACTIVE      (1UL<<29)

    u32_t ctx_cache_ctrl_sm_status;
        #define CTX_CACHE_CTRL_SM_STATUS_CS_DWC             (0x7UL<<0)
        #define CTX_CACHE_CTRL_SM_STATUS_CS_WFIFOC          (0x7UL<<3)
        #define CTX_CACHE_CTRL_SM_STATUS_CS_RTAGC           (0x7UL<<6)
        #define CTX_CACHE_CTRL_SM_STATUS_CS_RFIFOC          (0x7UL<<9)
        #define CTX_CACHE_CTRL_SM_STATUS_INVALID_BLK_ADDR   (0x7fffUL<<16)

    u32_t ctx_cache_status;
        #define CTX_CACHE_STATUS_HELD_ENTRIES               (0x3ffUL<<0)
        #define CTX_CACHE_STATUS_MAX_HELD_ENTRIES           (0x3ffUL<<16)

    u32_t ctx_dma_status;
        #define CTX_DMA_STATUS_RD_CHAN0_STATUS              (0x3UL<<0)
        #define CTX_DMA_STATUS_RD_CHAN1_STATUS              (0x3UL<<2)
        #define CTX_DMA_STATUS_RD_CHAN2_STATUS              (0x3UL<<4)
        #define CTX_DMA_STATUS_RD_CHAN3_STATUS              (0x3UL<<6)
        #define CTX_DMA_STATUS_RD_CHAN4_STATUS              (0x3UL<<8)
        #define CTX_DMA_STATUS_RD_CHAN5_STATUS              (0x3UL<<10)
        #define CTX_DMA_STATUS_RD_CHAN6_STATUS              (0x3UL<<12)
        #define CTX_DMA_STATUS_RD_CHAN7_STATUS              (0x3UL<<14)
        #define CTX_DMA_STATUS_RD_CHAN8_STATUS              (0x3UL<<16)
        #define CTX_DMA_STATUS_RD_CHAN9_STATUS              (0x3UL<<18)
        #define CTX_DMA_STATUS_RD_CHAN10_STATUS             (0x3UL<<20)

    u32_t ctx_rep_status;
        #define CTX_REP_STATUS_ERROR_ENTRY                  (0x3ffUL<<0)
        #define CTX_REP_STATUS_ERROR_CLIENT_ID              (0x1fUL<<10)
        #define CTX_REP_STATUS_USAGE_CNT_MAX_ERR            (1UL<<16)
        #define CTX_REP_STATUS_USAGE_CNT_MIN_ERR            (1UL<<17)
        #define CTX_REP_STATUS_USAGE_CNT_MISS_ERR           (1UL<<18)

    u32_t ctx_cksum_error_status;
        #define CTX_CKSUM_ERROR_STATUS_CALCULATED           (0xffffUL<<0)
        #define CTX_CKSUM_ERROR_STATUS_EXPECTED             (0xffffUL<<16)

    u32_t unused_1[8];
    u32_t ctx_chnl_lock_status_0;
        #define CTX_CHNL_LOCK_STATUS_0_CID                  (0x3fffUL<<0)
        #define CTX_CHNL_LOCK_STATUS_0_TYPE_TE                 (0x3UL<<14)
        #define CTX_CHNL_LOCK_STATUS_0_MODE_TE                 (1UL<<16)
        #define CTX_CHNL_LOCK_STATUS_0_MODE_XI                 (1UL<<14)
        #define CTX_CHNL_LOCK_STATUS_0_TYPE_XI                 (0x7UL<<15)

    u32_t ctx_chnl_lock_status_1;
    u32_t ctx_chnl_lock_status_2;
    u32_t ctx_chnl_lock_status_3;
    u32_t ctx_chnl_lock_status_4;
    u32_t ctx_chnl_lock_status_5;
    u32_t ctx_chnl_lock_status_6;
    u32_t ctx_chnl_lock_status_7;
    u32_t ctx_chnl_lock_status_8;
    u32_t ctx_chnl_lock_status_9;
    u32_t ctx_debug_sm;
    u32_t unused_2[5];
    u32_t ctx_cache_ctrl;
        #define CTX_CACHE_CTRL_CACHE_ADDR                   (0x3fffUL<<2)
        #define CTX_CACHE_CTRL_WRITE_REQ                    (1UL<<30)
        #define CTX_CACHE_CTRL_READ_REQ                     (1UL<<31)

    u32_t ctx_cache_data;
    u32_t ctx_host_page_tbl_ctrl;
        #define CTX_HOST_PAGE_TBL_CTRL_PAGE_TBL_ADDR        (0x1ffUL<<0)
        #define CTX_HOST_PAGE_TBL_CTRL_WRITE_REQ            (1UL<<30)
        #define CTX_HOST_PAGE_TBL_CTRL_READ_REQ             (1UL<<31)

    u32_t ctx_host_page_tbl_data0;
        #define CTX_HOST_PAGE_TBL_DATA0_VALID               (1UL<<0)
        #define CTX_HOST_PAGE_TBL_DATA0_VALUE               (0xffffffUL<<8)

    u32_t ctx_host_page_tbl_data1;
    u32_t ctx_cam_ctrl;
        #define CTX_CAM_CTRL_CAM_ADDR                       (0x3ffUL<<0)
        #define CTX_CAM_CTRL_RESET                          (1UL<<27)
        #define CTX_CAM_CTRL_INVALIDATE                     (1UL<<28)
        #define CTX_CAM_CTRL_SEARCH                         (1UL<<29)
        #define CTX_CAM_CTRL_WRITE_REQ                      (1UL<<30)
        #define CTX_CAM_CTRL_READ_REQ                       (1UL<<31)

    u32_t ctx_cam_data;
        #define CTX_CAM_DATA_CAM_DATA                       (0xffffUL<<0)

    u32_t ctx_mirror_ctrl;
        #define CTX_MIRROR_CTRL_MIRROR_ADDR                 (0x3ffUL<<0)
        #define CTX_MIRROR_CTRL_WRITE_REQ                   (1UL<<30)
        #define CTX_MIRROR_CTRL_READ_REQ                    (1UL<<31)

    u32_t ctx_mirror_data;
        #define CTX_MIRROR_DATA_MIRROR_DATA                 (0x7fffUL<<0)

    u32_t ctx_usage_cnt_ctrl;
        #define CTX_USAGE_CNT_CTRL_USAGE_CNT_ADDR           (0x3ffUL<<0)
        #define CTX_USAGE_CNT_CTRL_WRITE_REQ                (1UL<<30)
        #define CTX_USAGE_CNT_CTRL_READ_REQ                 (1UL<<31)

    u32_t ctx_usage_cnt_data;
        #define CTX_USAGE_CNT_DATA_USAGE_CNT_DATA           (0x7fUL<<0)
        #define CTX_USAGE_CNT_DATA_USAGE_CNT_ZERO           (1UL<<7)

    u32_t unused_3[191];
    u32_t ctx_cam_bist_command;
        #define CTX_CAM_BIST_COMMAND_BIST_RST_B             (1UL<<0)
        #define CTX_CAM_BIST_COMMAND_BIST_EN                (1UL<<1)
        #define CTX_CAM_BIST_COMMAND_BIST_DONE              (1UL<<2)
        #define CTX_CAM_BIST_COMMAND_BIST_PASSED            (1UL<<3)

    u32_t ctx_cam_bist_status0;
        #define CTX_CAM_BIST_STATUS0_MATCH_STATUS           (1UL<<0)
        #define CTX_CAM_BIST_STATUS0_ACTUAL_BITPOS          (0xfUL<<1)
        #define CTX_CAM_BIST_STATUS0_ACTUAL_ADDROUT         (0x3ffUL<<5)

    u32_t ctx_cam_bist_status1;
        #define CTX_CAM_BIST_STATUS1_MATCH_STATUS           (1UL<<0)
        #define CTX_CAM_BIST_STATUS1_ADDROUT_STATUS         (1UL<<1)
        #define CTX_CAM_BIST_STATUS1_ACTUAL_ADDROUT         (0x3ffUL<<2)
        #define CTX_CAM_BIST_STATUS1_EXPECTED_ADDROUT       (0x3ffUL<<12)

    u32_t ctx_cam_bist_status2;
        #define CTX_CAM_BIST_STATUS2_MATCH_STATUS           (1UL<<0)
        #define CTX_CAM_BIST_STATUS2_ACTUAL_BITPOS          (0xfUL<<1)
        #define CTX_CAM_BIST_STATUS2_ACTUAL_ADDROUT         (0x3ffUL<<5)

    u32_t ctx_cam_bist_status3;
        #define CTX_CAM_BIST_STATUS3_MATCH_STATUS           (1UL<<0)
        #define CTX_CAM_BIST_STATUS3_ADDROUT_STATUS         (1UL<<1)
        #define CTX_CAM_BIST_STATUS3_ACTUAL_ADDROUT         (0x3ffUL<<2)
        #define CTX_CAM_BIST_STATUS3_EXPECTED_ADDROUT       (0x3ffUL<<12)

    u32_t ctx_cam_bist_status4;
        #define CTX_CAM_BIST_STATUS4_MATCH_STATUS           (1UL<<0)
        #define CTX_CAM_BIST_STATUS4_ACTUAL_ADDROUT         (0x3ffUL<<1)

} context_reg_t;


/*
 *  emac_reg definition
 *  offset: 0x1400
 */
typedef struct emac_reg
{
    u32_t emac_mode;
        #define EMAC_MODE_RESET                             (1UL<<0)
        #define EMAC_MODE_HALF_DUPLEX                       (1UL<<1)
        #define EMAC_MODE_PORT                              (0x3UL<<2)
            #define EMAC_MODE_PORT_NONE                     (0UL<<2)
            #define EMAC_MODE_PORT_MII                      (1UL<<2)
            #define EMAC_MODE_PORT_GMII                     (2UL<<2)
            #define EMAC_MODE_PORT_MII_10M                  (3UL<<2)
        #define EMAC_MODE_MAC_LOOP                          (1UL<<4)
        #define EMAC_MODE_25G_MODE                          (1UL<<5)
        #define EMAC_MODE_TAGGED_MAC_CTL                    (1UL<<7)
        #define EMAC_MODE_TX_BURST                          (1UL<<8)
        #define EMAC_MODE_MAX_DEFER_DROP_ENA                (1UL<<9)
        #define EMAC_MODE_EXT_LINK_POL                      (1UL<<10)
        #define EMAC_MODE_FORCE_LINK                        (1UL<<11)
        #define EMAC_MODE_SERDES_MODE                       (1UL<<12)
        #define EMAC_MODE_BOND_OVRD                         (1UL<<13)
        #define EMAC_MODE_MPKT                              (1UL<<18)
        #define EMAC_MODE_MPKT_RCVD                         (1UL<<19)
        #define EMAC_MODE_ACPI_RCVD                         (1UL<<20)

    u32_t emac_status;
        #define EMAC_STATUS_LINK                            (1UL<<11)
        #define EMAC_STATUS_LINK_CHANGE                     (1UL<<12)
        #define EMAC_STATUS_SERDES_AUTONEG_COMPLETE         (1UL<<13)
        #define EMAC_STATUS_SERDES_AUTONEG_CHANGE           (1UL<<14)
        #define EMAC_STATUS_SERDES_NXT_PG_CHANGE            (1UL<<16)
        #define EMAC_STATUS_SERDES_RX_CONFIG_IS_0           (1UL<<17)
        #define EMAC_STATUS_SERDES_RX_CONFIG_IS_0_CHANGE    (1UL<<18)
        #define EMAC_STATUS_MI_COMPLETE                     (1UL<<22)
        #define EMAC_STATUS_MI_INT                          (1UL<<23)
        #define EMAC_STATUS_AP_ERROR                        (1UL<<24)
        #define EMAC_STATUS_PARITY_ERROR_STATE              (1UL<<31)

    u32_t emac_attention_ena;
        #define EMAC_ATTENTION_ENA_LINK                     (1UL<<11)
        #define EMAC_ATTENTION_ENA_AUTONEG_CHANGE           (1UL<<14)
        #define EMAC_ATTENTION_ENA_NXT_PG_CHANGE            (1UL<<16)
        #define EMAC_ATTENTION_ENA_SERDES_RX_CONFIG_IS_0_CHANGE  (1UL<<18)
        #define EMAC_ATTENTION_ENA_MI_COMPLETE              (1UL<<22)
        #define EMAC_ATTENTION_ENA_MI_INT                   (1UL<<23)
        #define EMAC_ATTENTION_ENA_AP_ERROR                 (1UL<<24)

    u32_t emac_led;
        #define EMAC_LED_OVERRIDE                           (1UL<<0)
        #define EMAC_LED_1000MB_OVERRIDE                    (1UL<<1)
        #define EMAC_LED_100MB_OVERRIDE                     (1UL<<2)
        #define EMAC_LED_10MB_OVERRIDE                      (1UL<<3)
        #define EMAC_LED_TRAFFIC_OVERRIDE                   (1UL<<4)
        #define EMAC_LED_BLNK_TRAFFIC                       (1UL<<5)
        #define EMAC_LED_TRAFFIC                            (1UL<<6)
        #define EMAC_LED_1000MB                             (1UL<<7)
        #define EMAC_LED_100MB                              (1UL<<8)
        #define EMAC_LED_10MB                               (1UL<<9)
        #define EMAC_LED_TRAFFIC_STAT                       (1UL<<10)
        #define EMAC_LED_2500MB                             (1UL<<11)
        #define EMAC_LED_2500MB_OVERRIDE                    (1UL<<12)
        #define EMAC_LED_ACTIVITY_SEL                       (0x3UL<<17)
            #define EMAC_LED_ACTIVITY_SEL_0                 (0UL<<17)
            #define EMAC_LED_ACTIVITY_SEL_1                 (1UL<<17)
            #define EMAC_LED_ACTIVITY_SEL_2                 (2UL<<17)
            #define EMAC_LED_ACTIVITY_SEL_3                 (3UL<<17)
        #define EMAC_LED_BLNK_RATE                          (0xfffUL<<19)
        #define EMAC_LED_BLNK_RATE_ENA                      (1UL<<31)

    u32_t emac_mac_match[32];
    u32_t unused_0[2];
    u32_t emac_backoff_seed;
        #define EMAC_BACKOFF_SEED_EMAC_BACKOFF_SEED         (0x3ffUL<<0)

    u32_t emac_rx_mtu_size;
        #define EMAC_RX_MTU_SIZE_MTU_SIZE                   (0xffffUL<<0)
        #define EMAC_RX_MTU_SIZE_JUMBO_ENA                  (1UL<<31)

    u32_t unused_1[3];
    u32_t emac_mdio_comm;
        #define EMAC_MDIO_COMM_DATA                         (0xffffUL<<0)
        #define EMAC_MDIO_COMM_REG_ADDR                     (0x1fUL<<16)
        #define EMAC_MDIO_COMM_PHY_ADDR                     (0x1fUL<<21)
        #define EMAC_MDIO_COMM_COMMAND                      (0x3UL<<26)
            #define EMAC_MDIO_COMM_COMMAND_UNDEFINED_0      (0UL<<26)
            #define EMAC_MDIO_COMM_COMMAND_ADDRESS          (0UL<<26)
            #define EMAC_MDIO_COMM_COMMAND_WRITE_TE            (1UL<<26)
            #define EMAC_MDIO_COMM_COMMAND_READ_TE             (2UL<<26)
            #define EMAC_MDIO_COMM_COMMAND_WRITE_22_XI         (1UL<<26)
            #define EMAC_MDIO_COMM_COMMAND_WRITE_45_XI         (1UL<<26)
            #define EMAC_MDIO_COMM_COMMAND_READ_22_XI          (2UL<<26)
            #define EMAC_MDIO_COMM_COMMAND_READ_INC_45_XI      (2UL<<26)
            #define EMAC_MDIO_COMM_COMMAND_UNDEFINED_3      (3UL<<26)
            #define EMAC_MDIO_COMM_COMMAND_READ_45          (3UL<<26)
        #define EMAC_MDIO_COMM_FAIL                         (1UL<<28)
        #define EMAC_MDIO_COMM_START_BUSY                   (1UL<<29)
        #define EMAC_MDIO_COMM_DISEXT                       (1UL<<30)

    u32_t emac_mdio_status;
        #define EMAC_MDIO_STATUS_LINK                       (1UL<<0)
        #define EMAC_MDIO_STATUS_10MB                       (1UL<<1)

    u32_t emac_mdio_mode;
        #define EMAC_MDIO_MODE_SHORT_PREAMBLE               (1UL<<1)
        #define EMAC_MDIO_MODE_AUTO_POLL                    (1UL<<4)
        #define EMAC_MDIO_MODE_BIT_BANG                     (1UL<<8)
        #define EMAC_MDIO_MODE_MDIO                         (1UL<<9)
        #define EMAC_MDIO_MODE_MDIO_OE                      (1UL<<10)
        #define EMAC_MDIO_MODE_MDC                          (1UL<<11)
        #define EMAC_MDIO_MODE_MDINT                        (1UL<<12)
        #define EMAC_MDIO_MODE_EXT_MDINT                    (1UL<<13)
        #define EMAC_MDIO_MODE_CLOCK_CNT_TE                    (0x1fUL<<16)
        #define EMAC_MDIO_MODE_CLOCK_CNT_XI                    (0x3fUL<<16)
        #define EMAC_MDIO_MODE_CLAUSE_45_XI                    (1UL<<31)

    u32_t emac_mdio_auto_status;
        #define EMAC_MDIO_AUTO_STATUS_AUTO_ERR              (1UL<<0)

    u32_t emac_tx_mode;
        #define EMAC_TX_MODE_RESET                          (1UL<<0)
        #define EMAC_TX_MODE_CS16_TEST                      (1UL<<2)
        #define EMAC_TX_MODE_EXT_PAUSE_EN                   (1UL<<3)
        #define EMAC_TX_MODE_FLOW_EN                        (1UL<<4)
        #define EMAC_TX_MODE_BIG_BACKOFF                    (1UL<<5)
        #define EMAC_TX_MODE_LONG_PAUSE                     (1UL<<6)
        #define EMAC_TX_MODE_LINK_AWARE                     (1UL<<7)

    u32_t emac_tx_status;
        #define EMAC_TX_STATUS_XOFFED                       (1UL<<0)
        #define EMAC_TX_STATUS_XOFF_SENT                    (1UL<<1)
        #define EMAC_TX_STATUS_XON_SENT                     (1UL<<2)
        #define EMAC_TX_STATUS_LINK_UP                      (1UL<<3)
        #define EMAC_TX_STATUS_UNDERRUN                     (1UL<<4)
        #define EMAC_TX_STATUS_CS16_ERROR                   (1UL<<5)

    u32_t emac_tx_lengths;
        #define EMAC_TX_LENGTHS_SLOT                        (0xffUL<<0)
        #define EMAC_TX_LENGTHS_IPG                         (0xfUL<<8)
        #define EMAC_TX_LENGTHS_IPG_CRS                     (0x3UL<<12)

    u32_t emac_rx_mode;
        #define EMAC_RX_MODE_RESET                          (1UL<<0)
        #define EMAC_RX_MODE_FLOW_EN                        (1UL<<2)
        #define EMAC_RX_MODE_KEEP_MAC_CONTROL               (1UL<<3)
        #define EMAC_RX_MODE_KEEP_PAUSE                     (1UL<<4)
        #define EMAC_RX_MODE_ACCEPT_OVERSIZE                (1UL<<5)
        #define EMAC_RX_MODE_ACCEPT_RUNTS                   (1UL<<6)
        #define EMAC_RX_MODE_LLC_CHK                        (1UL<<7)
        #define EMAC_RX_MODE_PROMISCUOUS                    (1UL<<8)
        #define EMAC_RX_MODE_NO_CRC_CHK                     (1UL<<9)
        #define EMAC_RX_MODE_KEEP_VLAN_TAG                  (1UL<<10)
        #define EMAC_RX_MODE_FILT_BROADCAST                 (1UL<<11)
        #define EMAC_RX_MODE_SORT_MODE                      (1UL<<12)

    u32_t emac_rx_status;
        #define EMAC_RX_STATUS_FFED                         (1UL<<0)
        #define EMAC_RX_STATUS_FF_RECEIVED                  (1UL<<1)
        #define EMAC_RX_STATUS_N_RECEIVED                   (1UL<<2)

    u32_t emac_multicast_hash[8];
    u32_t emac_cksum_error_status;
        #define EMAC_CKSUM_ERROR_STATUS_CALCULATED          (0xffffUL<<0)
        #define EMAC_CKSUM_ERROR_STATUS_EXPECTED            (0xffffUL<<16)

    u32_t unused_2[3];
    u32_t emac_rx_stat_ifhcinoctets;
    u32_t emac_rx_stat_ifhcinbadoctets;
    u32_t emac_rx_stat_etherstatsfragments;
    u32_t emac_rx_stat_ifhcinucastpkts;
    u32_t emac_rx_stat_ifhcinmulticastpkts;
    u32_t emac_rx_stat_ifhcinbroadcastpkts;
    u32_t emac_rx_stat_dot3statsfcserrors;
    u32_t emac_rx_stat_dot3statsalignmenterrors;
    u32_t emac_rx_stat_dot3statscarriersenseerrors;
    u32_t emac_rx_stat_xonpauseframesreceived;
    u32_t emac_rx_stat_xoffpauseframesreceived;
    u32_t emac_rx_stat_maccontrolframesreceived;
    u32_t emac_rx_stat_xoffstateentered;
    u32_t emac_rx_stat_dot3statsframestoolong;
    u32_t emac_rx_stat_etherstatsjabbers;
    u32_t emac_rx_stat_etherstatsundersizepkts;
    u32_t emac_rx_stat_etherstatspkts64octets;
    u32_t emac_rx_stat_etherstatspkts65octetsto127octets;
    u32_t emac_rx_stat_etherstatspkts128octetsto255octets;
    u32_t emac_rx_stat_etherstatspkts256octetsto511octets;
    u32_t emac_rx_stat_etherstatspkts512octetsto1023octets;
    u32_t emac_rx_stat_etherstatspkts1024octetsto1522octets;
    u32_t emac_rx_stat_etherstatspktsover1522octets;
    u32_t emac_rxmac_debug0;
    u32_t emac_rxmac_debug1;
        #define EMAC_RXMAC_DEBUG1_LENGTH_NE_BYTE_COUNT      (1UL<<0)
        #define EMAC_RXMAC_DEBUG1_LENGTH_OUT_RANGE          (1UL<<1)
        #define EMAC_RXMAC_DEBUG1_BAD_CRC                   (1UL<<2)
        #define EMAC_RXMAC_DEBUG1_RX_ERROR                  (1UL<<3)
        #define EMAC_RXMAC_DEBUG1_ALIGN_ERROR               (1UL<<4)
        #define EMAC_RXMAC_DEBUG1_LAST_DATA                 (1UL<<5)
        #define EMAC_RXMAC_DEBUG1_ODD_BYTE_START            (1UL<<6)
        #define EMAC_RXMAC_DEBUG1_BYTE_COUNT                (0xffffUL<<7)
        #define EMAC_RXMAC_DEBUG1_SLOT_TIME                 (0xffUL<<23)

    u32_t emac_rxmac_debug2;
        #define EMAC_RXMAC_DEBUG2_SM_STATE                  (0x7UL<<0)
            #define EMAC_RXMAC_DEBUG2_SM_STATE_IDLE         (0UL<<0)
            #define EMAC_RXMAC_DEBUG2_SM_STATE_SFD          (1UL<<0)
            #define EMAC_RXMAC_DEBUG2_SM_STATE_DATA         (2UL<<0)
            #define EMAC_RXMAC_DEBUG2_SM_STATE_SKEEP        (3UL<<0)
            #define EMAC_RXMAC_DEBUG2_SM_STATE_EXT          (4UL<<0)
            #define EMAC_RXMAC_DEBUG2_SM_STATE_DROP         (5UL<<0)
            #define EMAC_RXMAC_DEBUG2_SM_STATE_SDROP        (6UL<<0)
            #define EMAC_RXMAC_DEBUG2_SM_STATE_FC           (7UL<<0)
        #define EMAC_RXMAC_DEBUG2_IDI_STATE                 (0xfUL<<3)
            #define EMAC_RXMAC_DEBUG2_IDI_STATE_IDLE        (0UL<<3)
            #define EMAC_RXMAC_DEBUG2_IDI_STATE_DATA0       (1UL<<3)
            #define EMAC_RXMAC_DEBUG2_IDI_STATE_DATA1       (2UL<<3)
            #define EMAC_RXMAC_DEBUG2_IDI_STATE_DATA2       (3UL<<3)
            #define EMAC_RXMAC_DEBUG2_IDI_STATE_DATA3       (4UL<<3)
            #define EMAC_RXMAC_DEBUG2_IDI_STATE_ABORT       (5UL<<3)
            #define EMAC_RXMAC_DEBUG2_IDI_STATE_WAIT        (6UL<<3)
            #define EMAC_RXMAC_DEBUG2_IDI_STATE_STATUS      (7UL<<3)
            #define EMAC_RXMAC_DEBUG2_IDI_STATE_LAST        (8UL<<3)
        #define EMAC_RXMAC_DEBUG2_BYTE_IN                   (0xffUL<<7)
        #define EMAC_RXMAC_DEBUG2_FALSEC                    (1UL<<15)
        #define EMAC_RXMAC_DEBUG2_TAGGED                    (1UL<<16)
        #define EMAC_RXMAC_DEBUG2_PAUSE_STATE               (1UL<<18)
            #define EMAC_RXMAC_DEBUG2_PAUSE_STATE_IDLE      (0UL<<18)
            #define EMAC_RXMAC_DEBUG2_PAUSE_STATE_PAUSED    (1UL<<18)
        #define EMAC_RXMAC_DEBUG2_SE_COUNTER                (0xfUL<<19)
        #define EMAC_RXMAC_DEBUG2_QUANTA                    (0x1fUL<<23)

    u32_t emac_rxmac_debug3;
        #define EMAC_RXMAC_DEBUG3_PAUSE_CTR                 (0xffffUL<<0)
        #define EMAC_RXMAC_DEBUG3_TMP_PAUSE_CTR             (0xffffUL<<16)

    u32_t emac_rxmac_debug4;
        #define EMAC_RXMAC_DEBUG4_TYPE_FIELD                (0xffffUL<<0)
        #define EMAC_RXMAC_DEBUG4_FILT_STATE                (0x3fUL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_IDLE       (0UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_UMAC2      (1UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_UMAC3      (2UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_UNI        (3UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_MMAC3      (5UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_PSA1       (6UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_MMAC2      (7UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_PSA2       (7UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_PSA3       (8UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_MC2        (9UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_MC3        (10UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_MWAIT1     (14UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_MWAIT2     (15UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_MCHECK     (16UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_MC         (17UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_BC2        (18UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_BC3        (19UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_BSA1       (20UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_BSA2       (21UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_BSA3       (22UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_BTYPE      (23UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_BC         (24UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_PTYPE      (25UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_CMD        (26UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_MAC        (27UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_LATCH      (28UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_XOFF       (29UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_XON        (30UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_PAUSED     (31UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_NPAUSED    (32UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_TTYPE      (33UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_TVAL       (34UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_USA1       (35UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_USA2       (36UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_USA3       (37UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_UTYPE      (38UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_UTTYPE     (39UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_UTVAL      (40UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_MTYPE      (41UL<<16)
            #define EMAC_RXMAC_DEBUG4_FILT_STATE_DROP       (42UL<<16)
        #define EMAC_RXMAC_DEBUG4_DROP_PKT                  (1UL<<22)
        #define EMAC_RXMAC_DEBUG4_SLOT_FILLED               (1UL<<23)
        #define EMAC_RXMAC_DEBUG4_FALSE_CARRIER             (1UL<<24)
        #define EMAC_RXMAC_DEBUG4_LAST_DATA                 (1UL<<25)
        #define EMAC_RXMAC_DEBUG4_SFD_FOUND                 (1UL<<26)
        #define EMAC_RXMAC_DEBUG4_ADVANCE                   (1UL<<27)
        #define EMAC_RXMAC_DEBUG4_START                     (1UL<<28)

    u32_t emac_rxmac_debug5;
        #define EMAC_RXMAC_DEBUG5_PS_IDISM                  (0x7UL<<0)
            #define EMAC_RXMAC_DEBUG5_PS_IDISM_IDLE         (0UL<<0)
            #define EMAC_RXMAC_DEBUG5_PS_IDISM_WAIT_EOF     (1UL<<0)
            #define EMAC_RXMAC_DEBUG5_PS_IDISM_WAIT_STAT    (2UL<<0)
            #define EMAC_RXMAC_DEBUG5_PS_IDISM_SET_EOF4FCRC  (3UL<<0)
            #define EMAC_RXMAC_DEBUG5_PS_IDISM_SET_EOF4RDE  (4UL<<0)
            #define EMAC_RXMAC_DEBUG5_PS_IDISM_SET_EOF4ALL  (5UL<<0)
            #define EMAC_RXMAC_DEBUG5_PS_IDISM_1WD_WAIT_STAT  (6UL<<0)
        #define EMAC_RXMAC_DEBUG5_CCODE_BUF1                (0x7UL<<4)
            #define EMAC_RXMAC_DEBUG5_CCODE_BUF1_VDW        (0UL<<4)
            #define EMAC_RXMAC_DEBUG5_CCODE_BUF1_STAT       (1UL<<4)
            #define EMAC_RXMAC_DEBUG5_CCODE_BUF1_AEOF       (2UL<<4)
            #define EMAC_RXMAC_DEBUG5_CCODE_BUF1_NEOF       (3UL<<4)
            #define EMAC_RXMAC_DEBUG5_CCODE_BUF1_SOF        (4UL<<4)
            #define EMAC_RXMAC_DEBUG5_CCODE_BUF1_SAEOF      (6UL<<4)
            #define EMAC_RXMAC_DEBUG5_CCODE_BUF1_SNEOF      (7UL<<4)
        #define EMAC_RXMAC_DEBUG5_EOF_DETECTED              (1UL<<7)
        #define EMAC_RXMAC_DEBUG5_CCODE_BUF0                (0x7UL<<8)
        #define EMAC_RXMAC_DEBUG5_RPM_IDI_FIFO_FULL         (1UL<<11)
        #define EMAC_RXMAC_DEBUG5_LOAD_CCODE                (1UL<<12)
        #define EMAC_RXMAC_DEBUG5_LOAD_DATA                 (1UL<<13)
        #define EMAC_RXMAC_DEBUG5_LOAD_STAT                 (1UL<<14)
        #define EMAC_RXMAC_DEBUG5_CLR_STAT                  (1UL<<15)
        #define EMAC_RXMAC_DEBUG5_IDI_RPM_CCODE             (0x3UL<<16)
        #define EMAC_RXMAC_DEBUG5_IDI_RPM_ACCEPT            (1UL<<19)
        #define EMAC_RXMAC_DEBUG5_FMLEN                     (0xfffUL<<20)

    u32_t emac_rx_stat_falsecarriererrors;
    u32_t unused_3[2];
    u32_t emac_rx_stat_ac[23];
    u32_t emac_rxmac_suc_dbg_overrunvec;
    u32_t unused_4[5];
    u32_t emac_rx_stat_ac_28;
    u32_t unused_5[2];
    u32_t emac_tx_stat_ifhcoutoctets;
    u32_t emac_tx_stat_ifhcoutbadoctets;
    u32_t emac_tx_stat_etherstatscollisions;
    u32_t emac_tx_stat_outxonsent;
    u32_t emac_tx_stat_outxoffsent;
    u32_t emac_tx_stat_flowcontroldone;
    u32_t emac_tx_stat_dot3statssinglecollisionframes;
    u32_t emac_tx_stat_dot3statsmultiplecollisionframes;
    u32_t emac_tx_stat_dot3statsdeferredtransmissions;
    u32_t emac_tx_stat_dot3statsexcessivecollisions;
    u32_t emac_tx_stat_dot3statslatecollisions;
    u32_t emac_tx_stat_ifhcoutucastpkts;
    u32_t emac_tx_stat_ifhcoutmulticastpkts;
    u32_t emac_tx_stat_ifhcoutbroadcastpkts;
    u32_t emac_tx_stat_etherstatspkts64octets;
    u32_t emac_tx_stat_etherstatspkts65octetsto127octets;
    u32_t emac_tx_stat_etherstatspkts128octetsto255octets;
    u32_t emac_tx_stat_etherstatspkts256octetsto511octets;
    u32_t emac_tx_stat_etherstatspkts512octetsto1023octets;
    u32_t emac_tx_stat_etherstatspkts1024octetsto1522octets;
    u32_t emac_tx_stat_etherstatspktsover1522octets;
    u32_t emac_tx_stat_dot3statsinternalmactransmiterrors;
    u32_t emac_txmac_debug0;
    u32_t emac_txmac_debug1;
        #define EMAC_TXMAC_DEBUG1_ODI_STATE                 (0xfUL<<0)
            #define EMAC_TXMAC_DEBUG1_ODI_STATE_IDLE        (0UL<<0)
            #define EMAC_TXMAC_DEBUG1_ODI_STATE_START0      (1UL<<0)
            #define EMAC_TXMAC_DEBUG1_ODI_STATE_DATA0       (4UL<<0)
            #define EMAC_TXMAC_DEBUG1_ODI_STATE_DATA1       (5UL<<0)
            #define EMAC_TXMAC_DEBUG1_ODI_STATE_DATA2       (6UL<<0)
            #define EMAC_TXMAC_DEBUG1_ODI_STATE_DATA3       (7UL<<0)
            #define EMAC_TXMAC_DEBUG1_ODI_STATE_WAIT0       (8UL<<0)
            #define EMAC_TXMAC_DEBUG1_ODI_STATE_WAIT1       (9UL<<0)
        #define EMAC_TXMAC_DEBUG1_CRS_ENABLE                (1UL<<4)
        #define EMAC_TXMAC_DEBUG1_BAD_CRC                   (1UL<<5)
        #define EMAC_TXMAC_DEBUG1_SE_COUNTER                (0xfUL<<6)
        #define EMAC_TXMAC_DEBUG1_SEND_PAUSE                (1UL<<10)
        #define EMAC_TXMAC_DEBUG1_LATE_COLLISION            (1UL<<11)
        #define EMAC_TXMAC_DEBUG1_MAX_DEFER                 (1UL<<12)
        #define EMAC_TXMAC_DEBUG1_DEFERRED                  (1UL<<13)
        #define EMAC_TXMAC_DEBUG1_ONE_BYTE                  (1UL<<14)
        #define EMAC_TXMAC_DEBUG1_IPG_TIME                  (0xfUL<<15)
        #define EMAC_TXMAC_DEBUG1_SLOT_TIME                 (0xffUL<<19)

    u32_t emac_txmac_debug2;
        #define EMAC_TXMAC_DEBUG2_BACK_OFF                  (0x3ffUL<<0)
        #define EMAC_TXMAC_DEBUG2_BYTE_COUNT                (0xffffUL<<10)
        #define EMAC_TXMAC_DEBUG2_COL_COUNT                 (0x1fUL<<26)
        #define EMAC_TXMAC_DEBUG2_COL_BIT                   (1UL<<31)

    u32_t emac_txmac_debug3;
        #define EMAC_TXMAC_DEBUG3_SM_STATE                  (0xfUL<<0)
            #define EMAC_TXMAC_DEBUG3_SM_STATE_IDLE         (0UL<<0)
            #define EMAC_TXMAC_DEBUG3_SM_STATE_PRE1         (1UL<<0)
            #define EMAC_TXMAC_DEBUG3_SM_STATE_PRE2         (2UL<<0)
            #define EMAC_TXMAC_DEBUG3_SM_STATE_SFD          (3UL<<0)
            #define EMAC_TXMAC_DEBUG3_SM_STATE_DATA         (4UL<<0)
            #define EMAC_TXMAC_DEBUG3_SM_STATE_CRC1         (5UL<<0)
            #define EMAC_TXMAC_DEBUG3_SM_STATE_CRC2         (6UL<<0)
            #define EMAC_TXMAC_DEBUG3_SM_STATE_EXT          (7UL<<0)
            #define EMAC_TXMAC_DEBUG3_SM_STATE_STATB        (8UL<<0)
            #define EMAC_TXMAC_DEBUG3_SM_STATE_STATG        (9UL<<0)
            #define EMAC_TXMAC_DEBUG3_SM_STATE_JAM          (10UL<<0)
            #define EMAC_TXMAC_DEBUG3_SM_STATE_EJAM         (11UL<<0)
            #define EMAC_TXMAC_DEBUG3_SM_STATE_BJAM         (12UL<<0)
            #define EMAC_TXMAC_DEBUG3_SM_STATE_SWAIT        (13UL<<0)
            #define EMAC_TXMAC_DEBUG3_SM_STATE_BACKOFF      (14UL<<0)
        #define EMAC_TXMAC_DEBUG3_FILT_STATE                (0x7UL<<4)
            #define EMAC_TXMAC_DEBUG3_FILT_STATE_IDLE       (0UL<<4)
            #define EMAC_TXMAC_DEBUG3_FILT_STATE_WAIT       (1UL<<4)
            #define EMAC_TXMAC_DEBUG3_FILT_STATE_UNI        (2UL<<4)
            #define EMAC_TXMAC_DEBUG3_FILT_STATE_MC         (3UL<<4)
            #define EMAC_TXMAC_DEBUG3_FILT_STATE_BC2        (4UL<<4)
            #define EMAC_TXMAC_DEBUG3_FILT_STATE_BC3        (5UL<<4)
            #define EMAC_TXMAC_DEBUG3_FILT_STATE_BC         (6UL<<4)
        #define EMAC_TXMAC_DEBUG3_CRS_DONE                  (1UL<<7)
        #define EMAC_TXMAC_DEBUG3_XOFF                      (1UL<<8)
        #define EMAC_TXMAC_DEBUG3_SE_COUNTER                (0xfUL<<9)
        #define EMAC_TXMAC_DEBUG3_QUANTA_COUNTER            (0x1fUL<<13)

    u32_t emac_txmac_debug4;
        #define EMAC_TXMAC_DEBUG4_PAUSE_COUNTER             (0xffffUL<<0)
        #define EMAC_TXMAC_DEBUG4_PAUSE_STATE               (0xfUL<<16)
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_IDLE      (0UL<<16)
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_MCA1      (2UL<<16)
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_MCA2      (3UL<<16)
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_SRC3      (4UL<<16)
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_SRC2      (5UL<<16)
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_MCA3      (6UL<<16)
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_SRC1      (7UL<<16)
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_CRC1      (8UL<<16)
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_CRC2      (9UL<<16)
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_TIME      (10UL<<16)
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_TYPE      (12UL<<16)
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_WAIT      (13UL<<16)
            #define EMAC_TXMAC_DEBUG4_PAUSE_STATE_CMD       (14UL<<16)
        #define EMAC_TXMAC_DEBUG4_STATS0_VALID              (1UL<<20)
        #define EMAC_TXMAC_DEBUG4_APPEND_CRC                (1UL<<21)
        #define EMAC_TXMAC_DEBUG4_SLOT_FILLED               (1UL<<22)
        #define EMAC_TXMAC_DEBUG4_MAX_DEFER                 (1UL<<23)
        #define EMAC_TXMAC_DEBUG4_SEND_EXTEND               (1UL<<24)
        #define EMAC_TXMAC_DEBUG4_SEND_PADDING              (1UL<<25)
        #define EMAC_TXMAC_DEBUG4_EOF_LOC                   (1UL<<26)
        #define EMAC_TXMAC_DEBUG4_COLLIDING                 (1UL<<27)
        #define EMAC_TXMAC_DEBUG4_COL_IN                    (1UL<<28)
        #define EMAC_TXMAC_DEBUG4_BURSTING                  (1UL<<29)
        #define EMAC_TXMAC_DEBUG4_ADVANCE                   (1UL<<30)
        #define EMAC_TXMAC_DEBUG4_GO                        (1UL<<31)

    u32_t unused_6[5];
    u32_t emac_tx_stat_ac[22];
    u32_t emac_txmac_suc_dbg_overrunvec;
    u32_t unused_7[8];
    u32_t emac_tx_rate_limit_ctrl;
        #define EMAC_TX_RATE_LIMIT_CTRL_TX_THROTTLE_INC     (0x7fUL<<0)
        #define EMAC_TX_RATE_LIMIT_CTRL_TX_THROTTLE_NUM     (0x7fUL<<16)
        #define EMAC_TX_RATE_LIMIT_CTRL_RATE_LIMITER_EN     (1UL<<31)

    u32_t unused_8[64];
} emac_reg_t;


/*
 *  rpm_reg definition
 *  offset: 0x1800
 */
typedef struct rpm_reg
{
    u32_t rpm_command;
        #define RPM_COMMAND_ENABLED                         (1UL<<0)
        #define RPM_COMMAND_OVERRUN_ABORT                   (1UL<<4)

    u32_t rpm_status;
        #define RPM_STATUS_MBUF_WAIT                        (1UL<<0)
        #define RPM_STATUS_FREE_WAIT                        (1UL<<1)

    u32_t rpm_config;
        #define RPM_CONFIG_NO_PSD_HDR_CKSUM                 (1UL<<0)
        #define RPM_CONFIG_ACPI_ENA                         (1UL<<1)
        #define RPM_CONFIG_ACPI_KEEP                        (1UL<<2)
        #define RPM_CONFIG_MP_KEEP                          (1UL<<3)
        #define RPM_CONFIG_SORT_VECT_VAL                    (0xfUL<<4)
        #define RPM_CONFIG_DISABLE_WOL_ASSERT               (1UL<<30)
        #define RPM_CONFIG_IGNORE_VLAN                      (1UL<<31)

    u32_t rpm_mgmt_pkt_ctrl;
        #define RPM_MGMT_PKT_CTRL_MGMT_SORT                 (0xfUL<<0)
        #define RPM_MGMT_PKT_CTRL_MGMT_RULE                 (0xfUL<<4)
        #define RPM_MGMT_PKT_CTRL_MGMT_DISCARD_EN           (1UL<<30)
        #define RPM_MGMT_PKT_CTRL_MGMT_EN                   (1UL<<31)

    u32_t rpm_vlan_match0;
        #define RPM_VLAN_MATCH0_RPM_VLAN_MTCH0_VALUE        (0xfffUL<<0)

    u32_t rpm_vlan_match1;
        #define RPM_VLAN_MATCH1_RPM_VLAN_MTCH1_VALUE        (0xfffUL<<0)

    u32_t rpm_vlan_match2;
        #define RPM_VLAN_MATCH2_RPM_VLAN_MTCH2_VALUE        (0xfffUL<<0)

    u32_t rpm_vlan_match3;
        #define RPM_VLAN_MATCH3_RPM_VLAN_MTCH3_VALUE        (0xfffUL<<0)

    u32_t rpm_sort_user0;
        #define RPM_SORT_USER0_PM_EN                        (0xffffUL<<0)
        #define RPM_SORT_USER0_BC_EN                        (1UL<<16)
        #define RPM_SORT_USER0_MC_EN                        (1UL<<17)
        #define RPM_SORT_USER0_MC_HSH_EN                    (1UL<<18)
        #define RPM_SORT_USER0_PROM_EN                      (1UL<<19)
        #define RPM_SORT_USER0_VLAN_EN                      (0xfUL<<20)
        #define RPM_SORT_USER0_PROM_VLAN                    (1UL<<24)
        #define RPM_SORT_USER0_VLAN_NOTMATCH                (1UL<<25)
        #define RPM_SORT_USER0_ENA                          (1UL<<31)

    u32_t rpm_sort_user1;
        #define RPM_SORT_USER1_PM_EN                        (0xffffUL<<0)
        #define RPM_SORT_USER1_BC_EN                        (1UL<<16)
        #define RPM_SORT_USER1_MC_EN                        (1UL<<17)
        #define RPM_SORT_USER1_MC_HSH_EN                    (1UL<<18)
        #define RPM_SORT_USER1_PROM_EN                      (1UL<<19)
        #define RPM_SORT_USER1_VLAN_EN                      (0xfUL<<20)
        #define RPM_SORT_USER1_PROM_VLAN                    (1UL<<24)
        #define RPM_SORT_USER1_ENA                          (1UL<<31)

    u32_t rpm_sort_user2;
        #define RPM_SORT_USER2_PM_EN                        (0xffffUL<<0)
        #define RPM_SORT_USER2_BC_EN                        (1UL<<16)
        #define RPM_SORT_USER2_MC_EN                        (1UL<<17)
        #define RPM_SORT_USER2_MC_HSH_EN                    (1UL<<18)
        #define RPM_SORT_USER2_PROM_EN                      (1UL<<19)
        #define RPM_SORT_USER2_VLAN_EN                      (0xfUL<<20)
        #define RPM_SORT_USER2_PROM_VLAN                    (1UL<<24)
        #define RPM_SORT_USER2_ENA                          (1UL<<31)

    u32_t rpm_sort_user3;
        #define RPM_SORT_USER3_PM_EN                        (0xffffUL<<0)
        #define RPM_SORT_USER3_BC_EN                        (1UL<<16)
        #define RPM_SORT_USER3_MC_EN                        (1UL<<17)
        #define RPM_SORT_USER3_MC_HSH_EN                    (1UL<<18)
        #define RPM_SORT_USER3_PROM_EN                      (1UL<<19)
        #define RPM_SORT_USER3_VLAN_EN                      (0xfUL<<20)
        #define RPM_SORT_USER3_PROM_VLAN                    (1UL<<24)
        #define RPM_SORT_USER3_ENA                          (1UL<<31)

    u32_t unused_0[4];
    u32_t rpm_stat_l2_filter_discards;
    u32_t rpm_stat_rule_checker_discards;
    u32_t rpm_stat_ifinftqdiscards;
    u32_t rpm_stat_ifinmbufdiscard;
    u32_t rpm_stat_rule_checker_p4_hit;
    u32_t rpm_ipv6_programmable_extension0;
        #define RPM_IPV6_PROGRAMMABLE_EXTENSION0_NEXT_HEADER_LEN  (0xffUL<<0)
        #define RPM_IPV6_PROGRAMMABLE_EXTENSION0_NEXT_HEADER  (0xffUL<<16)
        #define RPM_IPV6_PROGRAMMABLE_EXTENSION0_NEXT_HEADER_LEN_TYPE  (1UL<<30)
        #define RPM_IPV6_PROGRAMMABLE_EXTENSION0_NEXT_HEADER_EN  (1UL<<31)

    u32_t rpm_ipv6_programmable_extension1;
        #define RPM_IPV6_PROGRAMMABLE_EXTENSION1_NEXT_HEADER_LEN  (0xffUL<<0)
        #define RPM_IPV6_PROGRAMMABLE_EXTENSION1_NEXT_HEADER  (0xffUL<<16)
        #define RPM_IPV6_PROGRAMMABLE_EXTENSION1_NEXT_HEADER_LEN_TYPE  (1UL<<30)
        #define RPM_IPV6_PROGRAMMABLE_EXTENSION1_NEXT_HEADER_EN  (1UL<<31)

    u32_t rpm_ipv6_programmable_extension2;
        #define RPM_IPV6_PROGRAMMABLE_EXTENSION2_NEXT_HEADER_LEN  (0xffUL<<0)
        #define RPM_IPV6_PROGRAMMABLE_EXTENSION2_NEXT_HEADER  (0xffUL<<16)
        #define RPM_IPV6_PROGRAMMABLE_EXTENSION2_NEXT_HEADER_LEN_TYPE  (1UL<<30)
        #define RPM_IPV6_PROGRAMMABLE_EXTENSION2_NEXT_HEADER_EN  (1UL<<31)

    u32_t rpm_ipv6_programmable_extension3;
        #define RPM_IPV6_PROGRAMMABLE_EXTENSION3_NEXT_HEADER_LEN  (0xffUL<<0)
        #define RPM_IPV6_PROGRAMMABLE_EXTENSION3_NEXT_HEADER  (0xffUL<<16)
        #define RPM_IPV6_PROGRAMMABLE_EXTENSION3_NEXT_HEADER_LEN_TYPE  (1UL<<30)
        #define RPM_IPV6_PROGRAMMABLE_EXTENSION3_NEXT_HEADER_EN  (1UL<<31)

    u32_t rpm_ipv6_programmable_extension4;
        #define RPM_IPV6_PROGRAMMABLE_EXTENSION4_NEXT_HEADER_LEN  (0xffUL<<0)
        #define RPM_IPV6_PROGRAMMABLE_EXTENSION4_NEXT_HEADER  (0xffUL<<16)
        #define RPM_IPV6_PROGRAMMABLE_EXTENSION4_NEXT_HEADER_LEN_TYPE  (1UL<<30)
        #define RPM_IPV6_PROGRAMMABLE_EXTENSION4_NEXT_HEADER_EN  (1UL<<31)

    u32_t rpm_ipv6_programmable_extension5;
        #define RPM_IPV6_PROGRAMMABLE_EXTENSION5_NEXT_HEADER_LEN  (0xffUL<<0)
        #define RPM_IPV6_PROGRAMMABLE_EXTENSION5_NEXT_HEADER  (0xffUL<<16)
        #define RPM_IPV6_PROGRAMMABLE_EXTENSION5_NEXT_HEADER_LEN_TYPE  (1UL<<30)
        #define RPM_IPV6_PROGRAMMABLE_EXTENSION5_NEXT_HEADER_EN  (1UL<<31)

    u32_t rpm_ipv6_programmable_extension6;
        #define RPM_IPV6_PROGRAMMABLE_EXTENSION6_NEXT_HEADER_LEN  (0xffUL<<0)
        #define RPM_IPV6_PROGRAMMABLE_EXTENSION6_NEXT_HEADER  (0xffUL<<16)
        #define RPM_IPV6_PROGRAMMABLE_EXTENSION6_NEXT_HEADER_LEN_TYPE  (1UL<<30)
        #define RPM_IPV6_PROGRAMMABLE_EXTENSION6_NEXT_HEADER_EN  (1UL<<31)

    u32_t rpm_ipv6_programmable_extension7;
        #define RPM_IPV6_PROGRAMMABLE_EXTENSION7_NEXT_HEADER_LEN  (0xffUL<<0)
        #define RPM_IPV6_PROGRAMMABLE_EXTENSION7_NEXT_HEADER  (0xffUL<<16)
        #define RPM_IPV6_PROGRAMMABLE_EXTENSION7_NEXT_HEADER_LEN_TYPE  (1UL<<30)
        #define RPM_IPV6_PROGRAMMABLE_EXTENSION7_NEXT_HEADER_EN  (1UL<<31)

    u32_t unused_1[3];
    u32_t rpm_stat_ac[5];
    u32_t unused_2[19];
    u32_t rpm_rc_cntl_16;
        #define RPM_RC_CNTL_16_OFFSET                       (0xffUL<<0)
        #define RPM_RC_CNTL_16_CLASS                        (0x7UL<<8)
        #define RPM_RC_CNTL_16_PRIORITY                     (1UL<<11)
        #define RPM_RC_CNTL_16_P4                           (1UL<<12)
        #define RPM_RC_CNTL_16_HDR_TYPE                     (0x7UL<<13)
            #define RPM_RC_CNTL_16_HDR_TYPE_START           (0UL<<13)
            #define RPM_RC_CNTL_16_HDR_TYPE_IP              (1UL<<13)
            #define RPM_RC_CNTL_16_HDR_TYPE_TCP             (2UL<<13)
            #define RPM_RC_CNTL_16_HDR_TYPE_UDP             (3UL<<13)
            #define RPM_RC_CNTL_16_HDR_TYPE_DATA            (4UL<<13)
            #define RPM_RC_CNTL_16_HDR_TYPE_TCP_UDP         (5UL<<13)
            #define RPM_RC_CNTL_16_HDR_TYPE_ICMPV6          (6UL<<13)
        #define RPM_RC_CNTL_16_COMP                         (0x3UL<<16)
            #define RPM_RC_CNTL_16_COMP_EQUAL               (0UL<<16)
            #define RPM_RC_CNTL_16_COMP_NEQUAL              (1UL<<16)
            #define RPM_RC_CNTL_16_COMP_GREATER             (2UL<<16)
            #define RPM_RC_CNTL_16_COMP_LESS                (3UL<<16)
        #define RPM_RC_CNTL_16_MAP                          (1UL<<18)
        #define RPM_RC_CNTL_16_SBIT                         (1UL<<19)
        #define RPM_RC_CNTL_16_CMDSEL                       (0x1fUL<<20)
        #define RPM_RC_CNTL_16_DISCARD                      (1UL<<25)
        #define RPM_RC_CNTL_16_MASK                         (1UL<<26)
        #define RPM_RC_CNTL_16_P1                           (1UL<<27)
        #define RPM_RC_CNTL_16_P2                           (1UL<<28)
        #define RPM_RC_CNTL_16_P3                           (1UL<<29)
        #define RPM_RC_CNTL_16_NBIT                         (1UL<<30)

    u32_t rpm_rc_value_mask_16;
        #define RPM_RC_VALUE_MASK_16_VALUE                  (0xffffUL<<0)
        #define RPM_RC_VALUE_MASK_16_MASK                   (0xffffUL<<16)

    u32_t rpm_rc_cntl_17;
        #define RPM_RC_CNTL_17_OFFSET                       (0xffUL<<0)
        #define RPM_RC_CNTL_17_CLASS                        (0x7UL<<8)
        #define RPM_RC_CNTL_17_PRIORITY                     (1UL<<11)
        #define RPM_RC_CNTL_17_P4                           (1UL<<12)
        #define RPM_RC_CNTL_17_HDR_TYPE                     (0x7UL<<13)
            #define RPM_RC_CNTL_17_HDR_TYPE_START           (0UL<<13)
            #define RPM_RC_CNTL_17_HDR_TYPE_IP              (1UL<<13)
            #define RPM_RC_CNTL_17_HDR_TYPE_TCP             (2UL<<13)
            #define RPM_RC_CNTL_17_HDR_TYPE_UDP             (3UL<<13)
            #define RPM_RC_CNTL_17_HDR_TYPE_DATA            (4UL<<13)
            #define RPM_RC_CNTL_17_HDR_TYPE_TCP_UDP         (5UL<<13)
            #define RPM_RC_CNTL_17_HDR_TYPE_ICMPV6          (6UL<<13)
        #define RPM_RC_CNTL_17_COMP                         (0x3UL<<16)
            #define RPM_RC_CNTL_17_COMP_EQUAL               (0UL<<16)
            #define RPM_RC_CNTL_17_COMP_NEQUAL              (1UL<<16)
            #define RPM_RC_CNTL_17_COMP_GREATER             (2UL<<16)
            #define RPM_RC_CNTL_17_COMP_LESS                (3UL<<16)
        #define RPM_RC_CNTL_17_MAP                          (1UL<<18)
        #define RPM_RC_CNTL_17_SBIT                         (1UL<<19)
        #define RPM_RC_CNTL_17_CMDSEL                       (0x1fUL<<20)
        #define RPM_RC_CNTL_17_DISCARD                      (1UL<<25)
        #define RPM_RC_CNTL_17_MASK                         (1UL<<26)
        #define RPM_RC_CNTL_17_P1                           (1UL<<27)
        #define RPM_RC_CNTL_17_P2                           (1UL<<28)
        #define RPM_RC_CNTL_17_P3                           (1UL<<29)
        #define RPM_RC_CNTL_17_NBIT                         (1UL<<30)

    u32_t rpm_rc_value_mask_17;
        #define RPM_RC_VALUE_MASK_17_VALUE                  (0xffffUL<<0)
        #define RPM_RC_VALUE_MASK_17_MASK                   (0xffffUL<<16)

    u32_t rpm_rc_cntl_18;
        #define RPM_RC_CNTL_18_OFFSET                       (0xffUL<<0)
        #define RPM_RC_CNTL_18_CLASS                        (0x7UL<<8)
        #define RPM_RC_CNTL_18_PRIORITY                     (1UL<<11)
        #define RPM_RC_CNTL_18_P4                           (1UL<<12)
        #define RPM_RC_CNTL_18_HDR_TYPE                     (0x7UL<<13)
            #define RPM_RC_CNTL_18_HDR_TYPE_START           (0UL<<13)
            #define RPM_RC_CNTL_18_HDR_TYPE_IP              (1UL<<13)
            #define RPM_RC_CNTL_18_HDR_TYPE_TCP             (2UL<<13)
            #define RPM_RC_CNTL_18_HDR_TYPE_UDP             (3UL<<13)
            #define RPM_RC_CNTL_18_HDR_TYPE_DATA            (4UL<<13)
            #define RPM_RC_CNTL_18_HDR_TYPE_TCP_UDP         (5UL<<13)
            #define RPM_RC_CNTL_18_HDR_TYPE_ICMPV6          (6UL<<13)
        #define RPM_RC_CNTL_18_COMP                         (0x3UL<<16)
            #define RPM_RC_CNTL_18_COMP_EQUAL               (0UL<<16)
            #define RPM_RC_CNTL_18_COMP_NEQUAL              (1UL<<16)
            #define RPM_RC_CNTL_18_COMP_GREATER             (2UL<<16)
            #define RPM_RC_CNTL_18_COMP_LESS                (3UL<<16)
        #define RPM_RC_CNTL_18_MAP                          (1UL<<18)
        #define RPM_RC_CNTL_18_SBIT                         (1UL<<19)
        #define RPM_RC_CNTL_18_CMDSEL                       (0x1fUL<<20)
        #define RPM_RC_CNTL_18_DISCARD                      (1UL<<25)
        #define RPM_RC_CNTL_18_MASK                         (1UL<<26)
        #define RPM_RC_CNTL_18_P1                           (1UL<<27)
        #define RPM_RC_CNTL_18_P2                           (1UL<<28)
        #define RPM_RC_CNTL_18_P3                           (1UL<<29)
        #define RPM_RC_CNTL_18_NBIT                         (1UL<<30)

    u32_t rpm_rc_value_mask_18;
        #define RPM_RC_VALUE_MASK_18_VALUE                  (0xffffUL<<0)
        #define RPM_RC_VALUE_MASK_18_MASK                   (0xffffUL<<16)

    u32_t rpm_rc_cntl_19;
        #define RPM_RC_CNTL_19_OFFSET                       (0xffUL<<0)
        #define RPM_RC_CNTL_19_CLASS                        (0x7UL<<8)
        #define RPM_RC_CNTL_19_PRIORITY                     (1UL<<11)
        #define RPM_RC_CNTL_19_P4                           (1UL<<12)
        #define RPM_RC_CNTL_19_HDR_TYPE                     (0x7UL<<13)
            #define RPM_RC_CNTL_19_HDR_TYPE_START           (0UL<<13)
            #define RPM_RC_CNTL_19_HDR_TYPE_IP              (1UL<<13)
            #define RPM_RC_CNTL_19_HDR_TYPE_TCP             (2UL<<13)
            #define RPM_RC_CNTL_19_HDR_TYPE_UDP             (3UL<<13)
            #define RPM_RC_CNTL_19_HDR_TYPE_DATA            (4UL<<13)
            #define RPM_RC_CNTL_19_HDR_TYPE_TCP_UDP         (5UL<<13)
            #define RPM_RC_CNTL_19_HDR_TYPE_ICMPV6          (6UL<<13)
        #define RPM_RC_CNTL_19_COMP                         (0x3UL<<16)
            #define RPM_RC_CNTL_19_COMP_EQUAL               (0UL<<16)
            #define RPM_RC_CNTL_19_COMP_NEQUAL              (1UL<<16)
            #define RPM_RC_CNTL_19_COMP_GREATER             (2UL<<16)
            #define RPM_RC_CNTL_19_COMP_LESS                (3UL<<16)
        #define RPM_RC_CNTL_19_MAP                          (1UL<<18)
        #define RPM_RC_CNTL_19_SBIT                         (1UL<<19)
        #define RPM_RC_CNTL_19_CMDSEL                       (0x1fUL<<20)
        #define RPM_RC_CNTL_19_DISCARD                      (1UL<<25)
        #define RPM_RC_CNTL_19_MASK                         (1UL<<26)
        #define RPM_RC_CNTL_19_P1                           (1UL<<27)
        #define RPM_RC_CNTL_19_P2                           (1UL<<28)
        #define RPM_RC_CNTL_19_P3                           (1UL<<29)
        #define RPM_RC_CNTL_19_NBIT                         (1UL<<30)

    u32_t rpm_rc_value_mask_19;
        #define RPM_RC_VALUE_MASK_19_VALUE                  (0xffffUL<<0)
        #define RPM_RC_VALUE_MASK_19_MASK                   (0xffffUL<<16)

    u32_t rpm_rc_cntl_0;
        #define RPM_RC_CNTL_0_OFFSET                        (0xffUL<<0)
        #define RPM_RC_CNTL_0_CLASS                         (0x7UL<<8)
        #define RPM_RC_CNTL_0_PRIORITY                      (1UL<<11)
        #define RPM_RC_CNTL_0_P4                            (1UL<<12)
        #define RPM_RC_CNTL_0_HDR_TYPE                      (0x7UL<<13)
            #define RPM_RC_CNTL_0_HDR_TYPE_START            (0UL<<13)
            #define RPM_RC_CNTL_0_HDR_TYPE_IP               (1UL<<13)
            #define RPM_RC_CNTL_0_HDR_TYPE_TCP              (2UL<<13)
            #define RPM_RC_CNTL_0_HDR_TYPE_UDP              (3UL<<13)
            #define RPM_RC_CNTL_0_HDR_TYPE_DATA             (4UL<<13)
            #define RPM_RC_CNTL_0_HDR_TYPE_TCP_UDP          (5UL<<13)
            #define RPM_RC_CNTL_0_HDR_TYPE_ICMPV6           (6UL<<13)
        #define RPM_RC_CNTL_0_COMP                          (0x3UL<<16)
            #define RPM_RC_CNTL_0_COMP_EQUAL                (0UL<<16)
            #define RPM_RC_CNTL_0_COMP_NEQUAL               (1UL<<16)
            #define RPM_RC_CNTL_0_COMP_GREATER              (2UL<<16)
            #define RPM_RC_CNTL_0_COMP_LESS                 (3UL<<16)
        #define RPM_RC_CNTL_0_MAP_XI                           (1UL<<18)
        #define RPM_RC_CNTL_0_SBIT                          (1UL<<19)
        #define RPM_RC_CNTL_0_CMDSEL_TE                        (0xfUL<<20)
        #define RPM_RC_CNTL_0_MAP_TE                           (1UL<<24)
        #define RPM_RC_CNTL_0_CMDSEL_XI                        (0x1fUL<<20)
        #define RPM_RC_CNTL_0_DISCARD                       (1UL<<25)
        #define RPM_RC_CNTL_0_MASK                          (1UL<<26)
        #define RPM_RC_CNTL_0_P1                            (1UL<<27)
        #define RPM_RC_CNTL_0_P2                            (1UL<<28)
        #define RPM_RC_CNTL_0_P3                            (1UL<<29)
        #define RPM_RC_CNTL_0_NBIT                          (1UL<<30)

    u32_t rpm_rc_value_mask_0;
        #define RPM_RC_VALUE_MASK_0_VALUE                   (0xffffUL<<0)
        #define RPM_RC_VALUE_MASK_0_MASK                    (0xffffUL<<16)

    u32_t rpm_rc_cntl_1;
        #define RPM_RC_CNTL_1_A_TE                             (0x3ffffUL<<0)
        #define RPM_RC_CNTL_1_B_TE                             (0xfffUL<<19)
        #define RPM_RC_CNTL_1_OFFSET_XI                        (0xffUL<<0)
        #define RPM_RC_CNTL_1_CLASS_XI                         (0x7UL<<8)
        #define RPM_RC_CNTL_1_PRIORITY_XI                      (1UL<<11)
        #define RPM_RC_CNTL_1_P4_XI                            (1UL<<12)
        #define RPM_RC_CNTL_1_HDR_TYPE_XI                      (0x7UL<<13)
            #define RPM_RC_CNTL_1_HDR_TYPE_START_XI            (0UL<<13)
            #define RPM_RC_CNTL_1_HDR_TYPE_IP_XI               (1UL<<13)
            #define RPM_RC_CNTL_1_HDR_TYPE_TCP_XI              (2UL<<13)
            #define RPM_RC_CNTL_1_HDR_TYPE_UDP_XI              (3UL<<13)
            #define RPM_RC_CNTL_1_HDR_TYPE_DATA_XI             (4UL<<13)
            #define RPM_RC_CNTL_1_HDR_TYPE_TCP_UDP_XI          (5UL<<13)
            #define RPM_RC_CNTL_1_HDR_TYPE_ICMPV6_XI           (6UL<<13)
        #define RPM_RC_CNTL_1_COMP_XI                          (0x3UL<<16)
            #define RPM_RC_CNTL_1_COMP_EQUAL_XI                (0UL<<16)
            #define RPM_RC_CNTL_1_COMP_NEQUAL_XI               (1UL<<16)
            #define RPM_RC_CNTL_1_COMP_GREATER_XI              (2UL<<16)
            #define RPM_RC_CNTL_1_COMP_LESS_XI                 (3UL<<16)
        #define RPM_RC_CNTL_1_MAP_XI                           (1UL<<18)
        #define RPM_RC_CNTL_1_SBIT_XI                          (1UL<<19)
        #define RPM_RC_CNTL_1_CMDSEL_XI                        (0x1fUL<<20)
        #define RPM_RC_CNTL_1_DISCARD_XI                       (1UL<<25)
        #define RPM_RC_CNTL_1_MASK_XI                          (1UL<<26)
        #define RPM_RC_CNTL_1_P1_XI                            (1UL<<27)
        #define RPM_RC_CNTL_1_P2_XI                            (1UL<<28)
        #define RPM_RC_CNTL_1_P3_XI                            (1UL<<29)
        #define RPM_RC_CNTL_1_NBIT_XI                          (1UL<<30)

    u32_t rpm_rc_value_mask_1;
        #define RPM_RC_VALUE_MASK_1_VALUE                   (0xffffUL<<0)
        #define RPM_RC_VALUE_MASK_1_MASK                    (0xffffUL<<16)

    u32_t rpm_rc_cntl_2;
        #define RPM_RC_CNTL_2_A_TE                             (0x3ffffUL<<0)
        #define RPM_RC_CNTL_2_B_TE                             (0xfffUL<<19)
        #define RPM_RC_CNTL_2_OFFSET_XI                        (0xffUL<<0)
        #define RPM_RC_CNTL_2_CLASS_XI                         (0x7UL<<8)
        #define RPM_RC_CNTL_2_PRIORITY_XI                      (1UL<<11)
        #define RPM_RC_CNTL_2_P4_XI                            (1UL<<12)
        #define RPM_RC_CNTL_2_HDR_TYPE_XI                      (0x7UL<<13)
            #define RPM_RC_CNTL_2_HDR_TYPE_START_XI            (0UL<<13)
            #define RPM_RC_CNTL_2_HDR_TYPE_IP_XI               (1UL<<13)
            #define RPM_RC_CNTL_2_HDR_TYPE_TCP_XI              (2UL<<13)
            #define RPM_RC_CNTL_2_HDR_TYPE_UDP_XI              (3UL<<13)
            #define RPM_RC_CNTL_2_HDR_TYPE_DATA_XI             (4UL<<13)
            #define RPM_RC_CNTL_2_HDR_TYPE_TCP_UDP_XI          (5UL<<13)
            #define RPM_RC_CNTL_2_HDR_TYPE_ICMPV6_XI           (6UL<<13)
        #define RPM_RC_CNTL_2_COMP_XI                          (0x3UL<<16)
            #define RPM_RC_CNTL_2_COMP_EQUAL_XI                (0UL<<16)
            #define RPM_RC_CNTL_2_COMP_NEQUAL_XI               (1UL<<16)
            #define RPM_RC_CNTL_2_COMP_GREATER_XI              (2UL<<16)
            #define RPM_RC_CNTL_2_COMP_LESS_XI                 (3UL<<16)
        #define RPM_RC_CNTL_2_MAP_XI                           (1UL<<18)
        #define RPM_RC_CNTL_2_SBIT_XI                          (1UL<<19)
        #define RPM_RC_CNTL_2_CMDSEL_XI                        (0x1fUL<<20)
        #define RPM_RC_CNTL_2_DISCARD_XI                       (1UL<<25)
        #define RPM_RC_CNTL_2_MASK_XI                          (1UL<<26)
        #define RPM_RC_CNTL_2_P1_XI                            (1UL<<27)
        #define RPM_RC_CNTL_2_P2_XI                            (1UL<<28)
        #define RPM_RC_CNTL_2_P3_XI                            (1UL<<29)
        #define RPM_RC_CNTL_2_NBIT_XI                          (1UL<<30)

    u32_t rpm_rc_value_mask_2;
        #define RPM_RC_VALUE_MASK_2_VALUE                   (0xffffUL<<0)
        #define RPM_RC_VALUE_MASK_2_MASK                    (0xffffUL<<16)

    u32_t rpm_rc_cntl_3;
        #define RPM_RC_CNTL_3_A_TE                             (0x3ffffUL<<0)
        #define RPM_RC_CNTL_3_B_TE                             (0xfffUL<<19)
        #define RPM_RC_CNTL_3_OFFSET_XI                        (0xffUL<<0)
        #define RPM_RC_CNTL_3_CLASS_XI                         (0x7UL<<8)
        #define RPM_RC_CNTL_3_PRIORITY_XI                      (1UL<<11)
        #define RPM_RC_CNTL_3_P4_XI                            (1UL<<12)
        #define RPM_RC_CNTL_3_HDR_TYPE_XI                      (0x7UL<<13)
            #define RPM_RC_CNTL_3_HDR_TYPE_START_XI            (0UL<<13)
            #define RPM_RC_CNTL_3_HDR_TYPE_IP_XI               (1UL<<13)
            #define RPM_RC_CNTL_3_HDR_TYPE_TCP_XI              (2UL<<13)
            #define RPM_RC_CNTL_3_HDR_TYPE_UDP_XI              (3UL<<13)
            #define RPM_RC_CNTL_3_HDR_TYPE_DATA_XI             (4UL<<13)
            #define RPM_RC_CNTL_3_HDR_TYPE_TCP_UDP_XI          (5UL<<13)
            #define RPM_RC_CNTL_3_HDR_TYPE_ICMPV6_XI           (6UL<<13)
        #define RPM_RC_CNTL_3_COMP_XI                          (0x3UL<<16)
            #define RPM_RC_CNTL_3_COMP_EQUAL_XI                (0UL<<16)
            #define RPM_RC_CNTL_3_COMP_NEQUAL_XI               (1UL<<16)
            #define RPM_RC_CNTL_3_COMP_GREATER_XI              (2UL<<16)
            #define RPM_RC_CNTL_3_COMP_LESS_XI                 (3UL<<16)
        #define RPM_RC_CNTL_3_MAP_XI                           (1UL<<18)
        #define RPM_RC_CNTL_3_SBIT_XI                          (1UL<<19)
        #define RPM_RC_CNTL_3_CMDSEL_XI                        (0x1fUL<<20)
        #define RPM_RC_CNTL_3_DISCARD_XI                       (1UL<<25)
        #define RPM_RC_CNTL_3_MASK_XI                          (1UL<<26)
        #define RPM_RC_CNTL_3_P1_XI                            (1UL<<27)
        #define RPM_RC_CNTL_3_P2_XI                            (1UL<<28)
        #define RPM_RC_CNTL_3_P3_XI                            (1UL<<29)
        #define RPM_RC_CNTL_3_NBIT_XI                          (1UL<<30)

    u32_t rpm_rc_value_mask_3;
        #define RPM_RC_VALUE_MASK_3_VALUE                   (0xffffUL<<0)
        #define RPM_RC_VALUE_MASK_3_MASK                    (0xffffUL<<16)

    u32_t rpm_rc_cntl_4;
        #define RPM_RC_CNTL_4_A_TE                             (0x3ffffUL<<0)
        #define RPM_RC_CNTL_4_B_TE                             (0xfffUL<<19)
        #define RPM_RC_CNTL_4_OFFSET_XI                        (0xffUL<<0)
        #define RPM_RC_CNTL_4_CLASS_XI                         (0x7UL<<8)
        #define RPM_RC_CNTL_4_PRIORITY_XI                      (1UL<<11)
        #define RPM_RC_CNTL_4_P4_XI                            (1UL<<12)
        #define RPM_RC_CNTL_4_HDR_TYPE_XI                      (0x7UL<<13)
            #define RPM_RC_CNTL_4_HDR_TYPE_START_XI            (0UL<<13)
            #define RPM_RC_CNTL_4_HDR_TYPE_IP_XI               (1UL<<13)
            #define RPM_RC_CNTL_4_HDR_TYPE_TCP_XI              (2UL<<13)
            #define RPM_RC_CNTL_4_HDR_TYPE_UDP_XI              (3UL<<13)
            #define RPM_RC_CNTL_4_HDR_TYPE_DATA_XI             (4UL<<13)
            #define RPM_RC_CNTL_4_HDR_TYPE_TCP_UDP_XI          (5UL<<13)
            #define RPM_RC_CNTL_4_HDR_TYPE_ICMPV6_XI           (6UL<<13)
        #define RPM_RC_CNTL_4_COMP_XI                          (0x3UL<<16)
            #define RPM_RC_CNTL_4_COMP_EQUAL_XI                (0UL<<16)
            #define RPM_RC_CNTL_4_COMP_NEQUAL_XI               (1UL<<16)
            #define RPM_RC_CNTL_4_COMP_GREATER_XI              (2UL<<16)
            #define RPM_RC_CNTL_4_COMP_LESS_XI                 (3UL<<16)
        #define RPM_RC_CNTL_4_MAP_XI                           (1UL<<18)
        #define RPM_RC_CNTL_4_SBIT_XI                          (1UL<<19)
        #define RPM_RC_CNTL_4_CMDSEL_XI                        (0x1fUL<<20)
        #define RPM_RC_CNTL_4_DISCARD_XI                       (1UL<<25)
        #define RPM_RC_CNTL_4_MASK_XI                          (1UL<<26)
        #define RPM_RC_CNTL_4_P1_XI                            (1UL<<27)
        #define RPM_RC_CNTL_4_P2_XI                            (1UL<<28)
        #define RPM_RC_CNTL_4_P3_XI                            (1UL<<29)
        #define RPM_RC_CNTL_4_NBIT_XI                          (1UL<<30)

    u32_t rpm_rc_value_mask_4;
        #define RPM_RC_VALUE_MASK_4_VALUE                   (0xffffUL<<0)
        #define RPM_RC_VALUE_MASK_4_MASK                    (0xffffUL<<16)

    u32_t rpm_rc_cntl_5;
        #define RPM_RC_CNTL_5_A_TE                             (0x3ffffUL<<0)
        #define RPM_RC_CNTL_5_B_TE                             (0xfffUL<<19)
        #define RPM_RC_CNTL_5_OFFSET_XI                        (0xffUL<<0)
        #define RPM_RC_CNTL_5_CLASS_XI                         (0x7UL<<8)
        #define RPM_RC_CNTL_5_PRIORITY_XI                      (1UL<<11)
        #define RPM_RC_CNTL_5_P4_XI                            (1UL<<12)
        #define RPM_RC_CNTL_5_HDR_TYPE_XI                      (0x7UL<<13)
            #define RPM_RC_CNTL_5_HDR_TYPE_START_XI            (0UL<<13)
            #define RPM_RC_CNTL_5_HDR_TYPE_IP_XI               (1UL<<13)
            #define RPM_RC_CNTL_5_HDR_TYPE_TCP_XI              (2UL<<13)
            #define RPM_RC_CNTL_5_HDR_TYPE_UDP_XI              (3UL<<13)
            #define RPM_RC_CNTL_5_HDR_TYPE_DATA_XI             (4UL<<13)
            #define RPM_RC_CNTL_5_HDR_TYPE_TCP_UDP_XI          (5UL<<13)
            #define RPM_RC_CNTL_5_HDR_TYPE_ICMPV6_XI           (6UL<<13)
        #define RPM_RC_CNTL_5_COMP_XI                          (0x3UL<<16)
            #define RPM_RC_CNTL_5_COMP_EQUAL_XI                (0UL<<16)
            #define RPM_RC_CNTL_5_COMP_NEQUAL_XI               (1UL<<16)
            #define RPM_RC_CNTL_5_COMP_GREATER_XI              (2UL<<16)
            #define RPM_RC_CNTL_5_COMP_LESS_XI                 (3UL<<16)
        #define RPM_RC_CNTL_5_MAP_XI                           (1UL<<18)
        #define RPM_RC_CNTL_5_SBIT_XI                          (1UL<<19)
        #define RPM_RC_CNTL_5_CMDSEL_XI                        (0x1fUL<<20)
        #define RPM_RC_CNTL_5_DISCARD_XI                       (1UL<<25)
        #define RPM_RC_CNTL_5_MASK_XI                          (1UL<<26)
        #define RPM_RC_CNTL_5_P1_XI                            (1UL<<27)
        #define RPM_RC_CNTL_5_P2_XI                            (1UL<<28)
        #define RPM_RC_CNTL_5_P3_XI                            (1UL<<29)
        #define RPM_RC_CNTL_5_NBIT_XI                          (1UL<<30)

    u32_t rpm_rc_value_mask_5;
        #define RPM_RC_VALUE_MASK_5_VALUE                   (0xffffUL<<0)
        #define RPM_RC_VALUE_MASK_5_MASK                    (0xffffUL<<16)

    u32_t rpm_rc_cntl_6;
        #define RPM_RC_CNTL_6_A_TE                             (0x3ffffUL<<0)
        #define RPM_RC_CNTL_6_B_TE                             (0xfffUL<<19)
        #define RPM_RC_CNTL_6_OFFSET_XI                        (0xffUL<<0)
        #define RPM_RC_CNTL_6_CLASS_XI                         (0x7UL<<8)
        #define RPM_RC_CNTL_6_PRIORITY_XI                      (1UL<<11)
        #define RPM_RC_CNTL_6_P4_XI                            (1UL<<12)
        #define RPM_RC_CNTL_6_HDR_TYPE_XI                      (0x7UL<<13)
            #define RPM_RC_CNTL_6_HDR_TYPE_START_XI            (0UL<<13)
            #define RPM_RC_CNTL_6_HDR_TYPE_IP_XI               (1UL<<13)
            #define RPM_RC_CNTL_6_HDR_TYPE_TCP_XI              (2UL<<13)
            #define RPM_RC_CNTL_6_HDR_TYPE_UDP_XI              (3UL<<13)
            #define RPM_RC_CNTL_6_HDR_TYPE_DATA_XI             (4UL<<13)
            #define RPM_RC_CNTL_6_HDR_TYPE_TCP_UDP_XI          (5UL<<13)
            #define RPM_RC_CNTL_6_HDR_TYPE_ICMPV6_XI           (6UL<<13)
        #define RPM_RC_CNTL_6_COMP_XI                          (0x3UL<<16)
            #define RPM_RC_CNTL_6_COMP_EQUAL_XI                (0UL<<16)
            #define RPM_RC_CNTL_6_COMP_NEQUAL_XI               (1UL<<16)
            #define RPM_RC_CNTL_6_COMP_GREATER_XI              (2UL<<16)
            #define RPM_RC_CNTL_6_COMP_LESS_XI                 (3UL<<16)
        #define RPM_RC_CNTL_6_MAP_XI                           (1UL<<18)
        #define RPM_RC_CNTL_6_SBIT_XI                          (1UL<<19)
        #define RPM_RC_CNTL_6_CMDSEL_XI                        (0x1fUL<<20)
        #define RPM_RC_CNTL_6_DISCARD_XI                       (1UL<<25)
        #define RPM_RC_CNTL_6_MASK_XI                          (1UL<<26)
        #define RPM_RC_CNTL_6_P1_XI                            (1UL<<27)
        #define RPM_RC_CNTL_6_P2_XI                            (1UL<<28)
        #define RPM_RC_CNTL_6_P3_XI                            (1UL<<29)
        #define RPM_RC_CNTL_6_NBIT_XI                          (1UL<<30)

    u32_t rpm_rc_value_mask_6;
        #define RPM_RC_VALUE_MASK_6_VALUE                   (0xffffUL<<0)
        #define RPM_RC_VALUE_MASK_6_MASK                    (0xffffUL<<16)

    u32_t rpm_rc_cntl_7;
        #define RPM_RC_CNTL_7_A_TE                             (0x3ffffUL<<0)
        #define RPM_RC_CNTL_7_B_TE                             (0xfffUL<<19)
        #define RPM_RC_CNTL_7_OFFSET_XI                        (0xffUL<<0)
        #define RPM_RC_CNTL_7_CLASS_XI                         (0x7UL<<8)
        #define RPM_RC_CNTL_7_PRIORITY_XI                      (1UL<<11)
        #define RPM_RC_CNTL_7_P4_XI                            (1UL<<12)
        #define RPM_RC_CNTL_7_HDR_TYPE_XI                      (0x7UL<<13)
            #define RPM_RC_CNTL_7_HDR_TYPE_START_XI            (0UL<<13)
            #define RPM_RC_CNTL_7_HDR_TYPE_IP_XI               (1UL<<13)
            #define RPM_RC_CNTL_7_HDR_TYPE_TCP_XI              (2UL<<13)
            #define RPM_RC_CNTL_7_HDR_TYPE_UDP_XI              (3UL<<13)
            #define RPM_RC_CNTL_7_HDR_TYPE_DATA_XI             (4UL<<13)
            #define RPM_RC_CNTL_7_HDR_TYPE_TCP_UDP_XI          (5UL<<13)
            #define RPM_RC_CNTL_7_HDR_TYPE_ICMPV6_XI           (6UL<<13)
        #define RPM_RC_CNTL_7_COMP_XI                          (0x3UL<<16)
            #define RPM_RC_CNTL_7_COMP_EQUAL_XI                (0UL<<16)
            #define RPM_RC_CNTL_7_COMP_NEQUAL_XI               (1UL<<16)
            #define RPM_RC_CNTL_7_COMP_GREATER_XI              (2UL<<16)
            #define RPM_RC_CNTL_7_COMP_LESS_XI                 (3UL<<16)
        #define RPM_RC_CNTL_7_MAP_XI                           (1UL<<18)
        #define RPM_RC_CNTL_7_SBIT_XI                          (1UL<<19)
        #define RPM_RC_CNTL_7_CMDSEL_XI                        (0x1fUL<<20)
        #define RPM_RC_CNTL_7_DISCARD_XI                       (1UL<<25)
        #define RPM_RC_CNTL_7_MASK_XI                          (1UL<<26)
        #define RPM_RC_CNTL_7_P1_XI                            (1UL<<27)
        #define RPM_RC_CNTL_7_P2_XI                            (1UL<<28)
        #define RPM_RC_CNTL_7_P3_XI                            (1UL<<29)
        #define RPM_RC_CNTL_7_NBIT_XI                          (1UL<<30)

    u32_t rpm_rc_value_mask_7;
        #define RPM_RC_VALUE_MASK_7_VALUE                   (0xffffUL<<0)
        #define RPM_RC_VALUE_MASK_7_MASK                    (0xffffUL<<16)

    u32_t rpm_rc_cntl_8;
        #define RPM_RC_CNTL_8_A_TE                             (0x3ffffUL<<0)
        #define RPM_RC_CNTL_8_B_TE                             (0xfffUL<<19)
        #define RPM_RC_CNTL_8_OFFSET_XI                        (0xffUL<<0)
        #define RPM_RC_CNTL_8_CLASS_XI                         (0x7UL<<8)
        #define RPM_RC_CNTL_8_PRIORITY_XI                      (1UL<<11)
        #define RPM_RC_CNTL_8_P4_XI                            (1UL<<12)
        #define RPM_RC_CNTL_8_HDR_TYPE_XI                      (0x7UL<<13)
            #define RPM_RC_CNTL_8_HDR_TYPE_START_XI            (0UL<<13)
            #define RPM_RC_CNTL_8_HDR_TYPE_IP_XI               (1UL<<13)
            #define RPM_RC_CNTL_8_HDR_TYPE_TCP_XI              (2UL<<13)
            #define RPM_RC_CNTL_8_HDR_TYPE_UDP_XI              (3UL<<13)
            #define RPM_RC_CNTL_8_HDR_TYPE_DATA_XI             (4UL<<13)
            #define RPM_RC_CNTL_8_HDR_TYPE_TCP_UDP_XI          (5UL<<13)
            #define RPM_RC_CNTL_8_HDR_TYPE_ICMPV6_XI           (6UL<<13)
        #define RPM_RC_CNTL_8_COMP_XI                          (0x3UL<<16)
            #define RPM_RC_CNTL_8_COMP_EQUAL_XI                (0UL<<16)
            #define RPM_RC_CNTL_8_COMP_NEQUAL_XI               (1UL<<16)
            #define RPM_RC_CNTL_8_COMP_GREATER_XI              (2UL<<16)
            #define RPM_RC_CNTL_8_COMP_LESS_XI                 (3UL<<16)
        #define RPM_RC_CNTL_8_MAP_XI                           (1UL<<18)
        #define RPM_RC_CNTL_8_SBIT_XI                          (1UL<<19)
        #define RPM_RC_CNTL_8_CMDSEL_XI                        (0x1fUL<<20)
        #define RPM_RC_CNTL_8_DISCARD_XI                       (1UL<<25)
        #define RPM_RC_CNTL_8_MASK_XI                          (1UL<<26)
        #define RPM_RC_CNTL_8_P1_XI                            (1UL<<27)
        #define RPM_RC_CNTL_8_P2_XI                            (1UL<<28)
        #define RPM_RC_CNTL_8_P3_XI                            (1UL<<29)
        #define RPM_RC_CNTL_8_NBIT_XI                          (1UL<<30)

    u32_t rpm_rc_value_mask_8;
        #define RPM_RC_VALUE_MASK_8_VALUE                   (0xffffUL<<0)
        #define RPM_RC_VALUE_MASK_8_MASK                    (0xffffUL<<16)

    u32_t rpm_rc_cntl_9;
        #define RPM_RC_CNTL_9_A_TE                             (0x3ffffUL<<0)
        #define RPM_RC_CNTL_9_B_TE                             (0xfffUL<<19)
        #define RPM_RC_CNTL_9_OFFSET_XI                        (0xffUL<<0)
        #define RPM_RC_CNTL_9_CLASS_XI                         (0x7UL<<8)
        #define RPM_RC_CNTL_9_PRIORITY_XI                      (1UL<<11)
        #define RPM_RC_CNTL_9_P4_XI                            (1UL<<12)
        #define RPM_RC_CNTL_9_HDR_TYPE_XI                      (0x7UL<<13)
            #define RPM_RC_CNTL_9_HDR_TYPE_START_XI            (0UL<<13)
            #define RPM_RC_CNTL_9_HDR_TYPE_IP_XI               (1UL<<13)
            #define RPM_RC_CNTL_9_HDR_TYPE_TCP_XI              (2UL<<13)
            #define RPM_RC_CNTL_9_HDR_TYPE_UDP_XI              (3UL<<13)
            #define RPM_RC_CNTL_9_HDR_TYPE_DATA_XI             (4UL<<13)
            #define RPM_RC_CNTL_9_HDR_TYPE_TCP_UDP_XI          (5UL<<13)
            #define RPM_RC_CNTL_9_HDR_TYPE_ICMPV6_XI           (6UL<<13)
        #define RPM_RC_CNTL_9_COMP_XI                          (0x3UL<<16)
            #define RPM_RC_CNTL_9_COMP_EQUAL_XI                (0UL<<16)
            #define RPM_RC_CNTL_9_COMP_NEQUAL_XI               (1UL<<16)
            #define RPM_RC_CNTL_9_COMP_GREATER_XI              (2UL<<16)
            #define RPM_RC_CNTL_9_COMP_LESS_XI                 (3UL<<16)
        #define RPM_RC_CNTL_9_MAP_XI                           (1UL<<18)
        #define RPM_RC_CNTL_9_SBIT_XI                          (1UL<<19)
        #define RPM_RC_CNTL_9_CMDSEL_XI                        (0x1fUL<<20)
        #define RPM_RC_CNTL_9_DISCARD_XI                       (1UL<<25)
        #define RPM_RC_CNTL_9_MASK_XI                          (1UL<<26)
        #define RPM_RC_CNTL_9_P1_XI                            (1UL<<27)
        #define RPM_RC_CNTL_9_P2_XI                            (1UL<<28)
        #define RPM_RC_CNTL_9_P3_XI                            (1UL<<29)
        #define RPM_RC_CNTL_9_NBIT_XI                          (1UL<<30)

    u32_t rpm_rc_value_mask_9;
        #define RPM_RC_VALUE_MASK_9_VALUE                   (0xffffUL<<0)
        #define RPM_RC_VALUE_MASK_9_MASK                    (0xffffUL<<16)

    u32_t rpm_rc_cntl_10;
        #define RPM_RC_CNTL_10_A_TE                            (0x3ffffUL<<0)
        #define RPM_RC_CNTL_10_B_TE                            (0xfffUL<<19)
        #define RPM_RC_CNTL_10_OFFSET_XI                       (0xffUL<<0)
        #define RPM_RC_CNTL_10_CLASS_XI                        (0x7UL<<8)
        #define RPM_RC_CNTL_10_PRIORITY_XI                     (1UL<<11)
        #define RPM_RC_CNTL_10_P4_XI                           (1UL<<12)
        #define RPM_RC_CNTL_10_HDR_TYPE_XI                     (0x7UL<<13)
            #define RPM_RC_CNTL_10_HDR_TYPE_START_XI           (0UL<<13)
            #define RPM_RC_CNTL_10_HDR_TYPE_IP_XI              (1UL<<13)
            #define RPM_RC_CNTL_10_HDR_TYPE_TCP_XI             (2UL<<13)
            #define RPM_RC_CNTL_10_HDR_TYPE_UDP_XI             (3UL<<13)
            #define RPM_RC_CNTL_10_HDR_TYPE_DATA_XI            (4UL<<13)
            #define RPM_RC_CNTL_10_HDR_TYPE_TCP_UDP_XI         (5UL<<13)
            #define RPM_RC_CNTL_10_HDR_TYPE_ICMPV6_XI          (6UL<<13)
        #define RPM_RC_CNTL_10_COMP_XI                         (0x3UL<<16)
            #define RPM_RC_CNTL_10_COMP_EQUAL_XI               (0UL<<16)
            #define RPM_RC_CNTL_10_COMP_NEQUAL_XI              (1UL<<16)
            #define RPM_RC_CNTL_10_COMP_GREATER_XI             (2UL<<16)
            #define RPM_RC_CNTL_10_COMP_LESS_XI                (3UL<<16)
        #define RPM_RC_CNTL_10_MAP_XI                          (1UL<<18)
        #define RPM_RC_CNTL_10_SBIT_XI                         (1UL<<19)
        #define RPM_RC_CNTL_10_CMDSEL_XI                       (0x1fUL<<20)
        #define RPM_RC_CNTL_10_DISCARD_XI                      (1UL<<25)
        #define RPM_RC_CNTL_10_MASK_XI                         (1UL<<26)
        #define RPM_RC_CNTL_10_P1_XI                           (1UL<<27)
        #define RPM_RC_CNTL_10_P2_XI                           (1UL<<28)
        #define RPM_RC_CNTL_10_P3_XI                           (1UL<<29)
        #define RPM_RC_CNTL_10_NBIT_XI                         (1UL<<30)

    u32_t rpm_rc_value_mask_10;
        #define RPM_RC_VALUE_MASK_10_VALUE                  (0xffffUL<<0)
        #define RPM_RC_VALUE_MASK_10_MASK                   (0xffffUL<<16)

    u32_t rpm_rc_cntl_11;
        #define RPM_RC_CNTL_11_A_TE                            (0x3ffffUL<<0)
        #define RPM_RC_CNTL_11_B_TE                            (0xfffUL<<19)
        #define RPM_RC_CNTL_11_OFFSET_XI                       (0xffUL<<0)
        #define RPM_RC_CNTL_11_CLASS_XI                        (0x7UL<<8)
        #define RPM_RC_CNTL_11_PRIORITY_XI                     (1UL<<11)
        #define RPM_RC_CNTL_11_P4_XI                           (1UL<<12)
        #define RPM_RC_CNTL_11_HDR_TYPE_XI                     (0x7UL<<13)
            #define RPM_RC_CNTL_11_HDR_TYPE_START_XI           (0UL<<13)
            #define RPM_RC_CNTL_11_HDR_TYPE_IP_XI              (1UL<<13)
            #define RPM_RC_CNTL_11_HDR_TYPE_TCP_XI             (2UL<<13)
            #define RPM_RC_CNTL_11_HDR_TYPE_UDP_XI             (3UL<<13)
            #define RPM_RC_CNTL_11_HDR_TYPE_DATA_XI            (4UL<<13)
            #define RPM_RC_CNTL_11_HDR_TYPE_TCP_UDP_XI         (5UL<<13)
            #define RPM_RC_CNTL_11_HDR_TYPE_ICMPV6_XI          (6UL<<13)
        #define RPM_RC_CNTL_11_COMP_XI                         (0x3UL<<16)
            #define RPM_RC_CNTL_11_COMP_EQUAL_XI               (0UL<<16)
            #define RPM_RC_CNTL_11_COMP_NEQUAL_XI              (1UL<<16)
            #define RPM_RC_CNTL_11_COMP_GREATER_XI             (2UL<<16)
            #define RPM_RC_CNTL_11_COMP_LESS_XI                (3UL<<16)
        #define RPM_RC_CNTL_11_MAP_XI                          (1UL<<18)
        #define RPM_RC_CNTL_11_SBIT_XI                         (1UL<<19)
        #define RPM_RC_CNTL_11_CMDSEL_XI                       (0x1fUL<<20)
        #define RPM_RC_CNTL_11_DISCARD_XI                      (1UL<<25)
        #define RPM_RC_CNTL_11_MASK_XI                         (1UL<<26)
        #define RPM_RC_CNTL_11_P1_XI                           (1UL<<27)
        #define RPM_RC_CNTL_11_P2_XI                           (1UL<<28)
        #define RPM_RC_CNTL_11_P3_XI                           (1UL<<29)
        #define RPM_RC_CNTL_11_NBIT_XI                         (1UL<<30)

    u32_t rpm_rc_value_mask_11;
        #define RPM_RC_VALUE_MASK_11_VALUE                  (0xffffUL<<0)
        #define RPM_RC_VALUE_MASK_11_MASK                   (0xffffUL<<16)

    u32_t rpm_rc_cntl_12;
        #define RPM_RC_CNTL_12_A_TE                            (0x3ffffUL<<0)
        #define RPM_RC_CNTL_12_B_TE                            (0xfffUL<<19)
        #define RPM_RC_CNTL_12_OFFSET_XI                       (0xffUL<<0)
        #define RPM_RC_CNTL_12_CLASS_XI                        (0x7UL<<8)
        #define RPM_RC_CNTL_12_PRIORITY_XI                     (1UL<<11)
        #define RPM_RC_CNTL_12_P4_XI                           (1UL<<12)
        #define RPM_RC_CNTL_12_HDR_TYPE_XI                     (0x7UL<<13)
            #define RPM_RC_CNTL_12_HDR_TYPE_START_XI           (0UL<<13)
            #define RPM_RC_CNTL_12_HDR_TYPE_IP_XI              (1UL<<13)
            #define RPM_RC_CNTL_12_HDR_TYPE_TCP_XI             (2UL<<13)
            #define RPM_RC_CNTL_12_HDR_TYPE_UDP_XI             (3UL<<13)
            #define RPM_RC_CNTL_12_HDR_TYPE_DATA_XI            (4UL<<13)
            #define RPM_RC_CNTL_12_HDR_TYPE_TCP_UDP_XI         (5UL<<13)
            #define RPM_RC_CNTL_12_HDR_TYPE_ICMPV6_XI          (6UL<<13)
        #define RPM_RC_CNTL_12_COMP_XI                         (0x3UL<<16)
            #define RPM_RC_CNTL_12_COMP_EQUAL_XI               (0UL<<16)
            #define RPM_RC_CNTL_12_COMP_NEQUAL_XI              (1UL<<16)
            #define RPM_RC_CNTL_12_COMP_GREATER_XI             (2UL<<16)
            #define RPM_RC_CNTL_12_COMP_LESS_XI                (3UL<<16)
        #define RPM_RC_CNTL_12_MAP_XI                          (1UL<<18)
        #define RPM_RC_CNTL_12_SBIT_XI                         (1UL<<19)
        #define RPM_RC_CNTL_12_CMDSEL_XI                       (0x1fUL<<20)
        #define RPM_RC_CNTL_12_DISCARD_XI                      (1UL<<25)
        #define RPM_RC_CNTL_12_MASK_XI                         (1UL<<26)
        #define RPM_RC_CNTL_12_P1_XI                           (1UL<<27)
        #define RPM_RC_CNTL_12_P2_XI                           (1UL<<28)
        #define RPM_RC_CNTL_12_P3_XI                           (1UL<<29)
        #define RPM_RC_CNTL_12_NBIT_XI                         (1UL<<30)

    u32_t rpm_rc_value_mask_12;
        #define RPM_RC_VALUE_MASK_12_VALUE                  (0xffffUL<<0)
        #define RPM_RC_VALUE_MASK_12_MASK                   (0xffffUL<<16)

    u32_t rpm_rc_cntl_13;
        #define RPM_RC_CNTL_13_A_TE                            (0x3ffffUL<<0)
        #define RPM_RC_CNTL_13_B_TE                            (0xfffUL<<19)
        #define RPM_RC_CNTL_13_OFFSET_XI                       (0xffUL<<0)
        #define RPM_RC_CNTL_13_CLASS_XI                        (0x7UL<<8)
        #define RPM_RC_CNTL_13_PRIORITY_XI                     (1UL<<11)
        #define RPM_RC_CNTL_13_P4_XI                           (1UL<<12)
        #define RPM_RC_CNTL_13_HDR_TYPE_XI                     (0x7UL<<13)
            #define RPM_RC_CNTL_13_HDR_TYPE_START_XI           (0UL<<13)
            #define RPM_RC_CNTL_13_HDR_TYPE_IP_XI              (1UL<<13)
            #define RPM_RC_CNTL_13_HDR_TYPE_TCP_XI             (2UL<<13)
            #define RPM_RC_CNTL_13_HDR_TYPE_UDP_XI             (3UL<<13)
            #define RPM_RC_CNTL_13_HDR_TYPE_DATA_XI            (4UL<<13)
            #define RPM_RC_CNTL_13_HDR_TYPE_TCP_UDP_XI         (5UL<<13)
            #define RPM_RC_CNTL_13_HDR_TYPE_ICMPV6_XI          (6UL<<13)
        #define RPM_RC_CNTL_13_COMP_XI                         (0x3UL<<16)
            #define RPM_RC_CNTL_13_COMP_EQUAL_XI               (0UL<<16)
            #define RPM_RC_CNTL_13_COMP_NEQUAL_XI              (1UL<<16)
            #define RPM_RC_CNTL_13_COMP_GREATER_XI             (2UL<<16)
            #define RPM_RC_CNTL_13_COMP_LESS_XI                (3UL<<16)
        #define RPM_RC_CNTL_13_MAP_XI                          (1UL<<18)
        #define RPM_RC_CNTL_13_SBIT_XI                         (1UL<<19)
        #define RPM_RC_CNTL_13_CMDSEL_XI                       (0x1fUL<<20)
        #define RPM_RC_CNTL_13_DISCARD_XI                      (1UL<<25)
        #define RPM_RC_CNTL_13_MASK_XI                         (1UL<<26)
        #define RPM_RC_CNTL_13_P1_XI                           (1UL<<27)
        #define RPM_RC_CNTL_13_P2_XI                           (1UL<<28)
        #define RPM_RC_CNTL_13_P3_XI                           (1UL<<29)
        #define RPM_RC_CNTL_13_NBIT_XI                         (1UL<<30)

    u32_t rpm_rc_value_mask_13;
        #define RPM_RC_VALUE_MASK_13_VALUE                  (0xffffUL<<0)
        #define RPM_RC_VALUE_MASK_13_MASK                   (0xffffUL<<16)

    u32_t rpm_rc_cntl_14;
        #define RPM_RC_CNTL_14_A_TE                            (0x3ffffUL<<0)
        #define RPM_RC_CNTL_14_B_TE                            (0xfffUL<<19)
        #define RPM_RC_CNTL_14_OFFSET_XI                       (0xffUL<<0)
        #define RPM_RC_CNTL_14_CLASS_XI                        (0x7UL<<8)
        #define RPM_RC_CNTL_14_PRIORITY_XI                     (1UL<<11)
        #define RPM_RC_CNTL_14_P4_XI                           (1UL<<12)
        #define RPM_RC_CNTL_14_HDR_TYPE_XI                     (0x7UL<<13)
            #define RPM_RC_CNTL_14_HDR_TYPE_START_XI           (0UL<<13)
            #define RPM_RC_CNTL_14_HDR_TYPE_IP_XI              (1UL<<13)
            #define RPM_RC_CNTL_14_HDR_TYPE_TCP_XI             (2UL<<13)
            #define RPM_RC_CNTL_14_HDR_TYPE_UDP_XI             (3UL<<13)
            #define RPM_RC_CNTL_14_HDR_TYPE_DATA_XI            (4UL<<13)
            #define RPM_RC_CNTL_14_HDR_TYPE_TCP_UDP_XI         (5UL<<13)
            #define RPM_RC_CNTL_14_HDR_TYPE_ICMPV6_XI          (6UL<<13)
        #define RPM_RC_CNTL_14_COMP_XI                         (0x3UL<<16)
            #define RPM_RC_CNTL_14_COMP_EQUAL_XI               (0UL<<16)
            #define RPM_RC_CNTL_14_COMP_NEQUAL_XI              (1UL<<16)
            #define RPM_RC_CNTL_14_COMP_GREATER_XI             (2UL<<16)
            #define RPM_RC_CNTL_14_COMP_LESS_XI                (3UL<<16)
        #define RPM_RC_CNTL_14_MAP_XI                          (1UL<<18)
        #define RPM_RC_CNTL_14_SBIT_XI                         (1UL<<19)
        #define RPM_RC_CNTL_14_CMDSEL_XI                       (0x1fUL<<20)
        #define RPM_RC_CNTL_14_DISCARD_XI                      (1UL<<25)
        #define RPM_RC_CNTL_14_MASK_XI                         (1UL<<26)
        #define RPM_RC_CNTL_14_P1_XI                           (1UL<<27)
        #define RPM_RC_CNTL_14_P2_XI                           (1UL<<28)
        #define RPM_RC_CNTL_14_P3_XI                           (1UL<<29)
        #define RPM_RC_CNTL_14_NBIT_XI                         (1UL<<30)

    u32_t rpm_rc_value_mask_14;
        #define RPM_RC_VALUE_MASK_14_VALUE                  (0xffffUL<<0)
        #define RPM_RC_VALUE_MASK_14_MASK                   (0xffffUL<<16)

    u32_t rpm_rc_cntl_15;
        #define RPM_RC_CNTL_15_A_TE                            (0x3ffffUL<<0)
        #define RPM_RC_CNTL_15_B_TE                            (0xfffUL<<19)
        #define RPM_RC_CNTL_15_OFFSET_XI                       (0xffUL<<0)
        #define RPM_RC_CNTL_15_CLASS_XI                        (0x7UL<<8)
        #define RPM_RC_CNTL_15_PRIORITY_XI                     (1UL<<11)
        #define RPM_RC_CNTL_15_P4_XI                           (1UL<<12)
        #define RPM_RC_CNTL_15_HDR_TYPE_XI                     (0x7UL<<13)
            #define RPM_RC_CNTL_15_HDR_TYPE_START_XI           (0UL<<13)
            #define RPM_RC_CNTL_15_HDR_TYPE_IP_XI              (1UL<<13)
            #define RPM_RC_CNTL_15_HDR_TYPE_TCP_XI             (2UL<<13)
            #define RPM_RC_CNTL_15_HDR_TYPE_UDP_XI             (3UL<<13)
            #define RPM_RC_CNTL_15_HDR_TYPE_DATA_XI            (4UL<<13)
            #define RPM_RC_CNTL_15_HDR_TYPE_TCP_UDP_XI         (5UL<<13)
            #define RPM_RC_CNTL_15_HDR_TYPE_ICMPV6_XI          (6UL<<13)
        #define RPM_RC_CNTL_15_COMP_XI                         (0x3UL<<16)
            #define RPM_RC_CNTL_15_COMP_EQUAL_XI               (0UL<<16)
            #define RPM_RC_CNTL_15_COMP_NEQUAL_XI              (1UL<<16)
            #define RPM_RC_CNTL_15_COMP_GREATER_XI             (2UL<<16)
            #define RPM_RC_CNTL_15_COMP_LESS_XI                (3UL<<16)
        #define RPM_RC_CNTL_15_MAP_XI                          (1UL<<18)
        #define RPM_RC_CNTL_15_SBIT_XI                         (1UL<<19)
        #define RPM_RC_CNTL_15_CMDSEL_XI                       (0x1fUL<<20)
        #define RPM_RC_CNTL_15_DISCARD_XI                      (1UL<<25)
        #define RPM_RC_CNTL_15_MASK_XI                         (1UL<<26)
        #define RPM_RC_CNTL_15_P1_XI                           (1UL<<27)
        #define RPM_RC_CNTL_15_P2_XI                           (1UL<<28)
        #define RPM_RC_CNTL_15_P3_XI                           (1UL<<29)
        #define RPM_RC_CNTL_15_NBIT_XI                         (1UL<<30)

    u32_t rpm_rc_value_mask_15;
        #define RPM_RC_VALUE_MASK_15_VALUE                  (0xffffUL<<0)
        #define RPM_RC_VALUE_MASK_15_MASK                   (0xffffUL<<16)

    u32_t rpm_rc_config;
        #define RPM_RC_CONFIG_RULE_ENABLE_TE                   (0xffffUL<<0)
        #define RPM_RC_CONFIG_RULE_ENABLE_XI                   (0xfffffUL<<0)
        #define RPM_RC_CONFIG_DEF_CLASS                     (0x7UL<<24)
        #define RPM_RC_CONFIG_KNUM_OVERWRITE                (1UL<<31)

    u32_t rpm_debug0;
        #define RPM_DEBUG0_FM_BCNT                          (0xffffUL<<0)
        #define RPM_DEBUG0_T_DATA_OFST_VLD                  (1UL<<16)
        #define RPM_DEBUG0_T_UDP_OFST_VLD                   (1UL<<17)
        #define RPM_DEBUG0_T_TCP_OFST_VLD                   (1UL<<18)
        #define RPM_DEBUG0_T_IP_OFST_VLD                    (1UL<<19)
        #define RPM_DEBUG0_IP_MORE_FRGMT                    (1UL<<20)
        #define RPM_DEBUG0_T_IP_NO_TCP_UDP_HDR              (1UL<<21)
        #define RPM_DEBUG0_LLC_SNAP                         (1UL<<22)
        #define RPM_DEBUG0_FM_STARTED                       (1UL<<23)
        #define RPM_DEBUG0_DONE                             (1UL<<24)
        #define RPM_DEBUG0_WAIT_4_DONE                      (1UL<<25)
        #define RPM_DEBUG0_USE_TPBUF_CKSUM                  (1UL<<26)
        #define RPM_DEBUG0_RX_NO_PSD_HDR_CKSUM              (1UL<<27)
        #define RPM_DEBUG0_IGNORE_VLAN                      (1UL<<28)
        #define RPM_DEBUG0_RP_ENA_ACTIVE                    (1UL<<31)

    u32_t rpm_debug1;
        #define RPM_DEBUG1_FSM_CUR_ST                       (0xffffUL<<0)
            #define RPM_DEBUG1_FSM_CUR_ST_IDLE              (0UL<<0)
            #define RPM_DEBUG1_FSM_CUR_ST_ETYPE_B6_ALL      (1UL<<0)
            #define RPM_DEBUG1_FSM_CUR_ST_ETYPE_B2_IPLLC    (2UL<<0)
            #define RPM_DEBUG1_FSM_CUR_ST_ETYPE_B6_IP       (4UL<<0)
            #define RPM_DEBUG1_FSM_CUR_ST_ETYPE_B2_IP       (8UL<<0)
            #define RPM_DEBUG1_FSM_CUR_ST_IP_START          (16UL<<0)
            #define RPM_DEBUG1_FSM_CUR_ST_IP                (32UL<<0)
            #define RPM_DEBUG1_FSM_CUR_ST_TCP               (64UL<<0)
            #define RPM_DEBUG1_FSM_CUR_ST_UDP               (128UL<<0)
            #define RPM_DEBUG1_FSM_CUR_ST_AH                (256UL<<0)
            #define RPM_DEBUG1_FSM_CUR_ST_ESP               (512UL<<0)
            #define RPM_DEBUG1_FSM_CUR_ST_ESP_PAYLOAD       (1024UL<<0)
            #define RPM_DEBUG1_FSM_CUR_ST_DATA              (2048UL<<0)
            #define RPM_DEBUG1_FSM_CUR_ST_ADD_CARRY         (8192UL<<0)
            #define RPM_DEBUG1_FSM_CUR_ST_ADD_CARRYOUT      (16384UL<<0)
            #define RPM_DEBUG1_FSM_CUR_ST_LATCH_RESULT      (32768UL<<0)
        #define RPM_DEBUG1_HDR_BCNT                         (0x7ffUL<<16)
        #define RPM_DEBUG1_UNKNOWN_ETYPE_D                  (1UL<<28)
        #define RPM_DEBUG1_VLAN_REMOVED_D2                  (1UL<<29)
        #define RPM_DEBUG1_VLAN_REMOVED_D1                  (1UL<<30)
        #define RPM_DEBUG1_EOF_0XTRA_WD                     (1UL<<31)

    u32_t rpm_debug2;
        #define RPM_DEBUG2_CMD_HIT_VEC                      (0xffffUL<<0)
        #define RPM_DEBUG2_IP_BCNT                          (0xffUL<<16)
        #define RPM_DEBUG2_THIS_CMD_M4                      (1UL<<24)
        #define RPM_DEBUG2_THIS_CMD_M3                      (1UL<<25)
        #define RPM_DEBUG2_THIS_CMD_M2                      (1UL<<26)
        #define RPM_DEBUG2_THIS_CMD_M1                      (1UL<<27)
        #define RPM_DEBUG2_IPIPE_EMPTY                      (1UL<<28)
        #define RPM_DEBUG2_FM_DISCARD                       (1UL<<29)
        #define RPM_DEBUG2_LAST_RULE_IN_FM_D2               (1UL<<30)
        #define RPM_DEBUG2_LAST_RULE_IN_FM_D1               (1UL<<31)

    u32_t rpm_debug3;
        #define RPM_DEBUG3_AVAIL_MBUF_PTR                   (0x1ffUL<<0)
        #define RPM_DEBUG3_RDE_RLUPQ_WR_REQ_INT             (1UL<<9)
        #define RPM_DEBUG3_RDE_RBUF_WR_LAST_INT             (1UL<<10)
        #define RPM_DEBUG3_RDE_RBUF_WR_REQ_INT              (1UL<<11)
        #define RPM_DEBUG3_RDE_RBUF_FREE_REQ                (1UL<<12)
        #define RPM_DEBUG3_RDE_RBUF_ALLOC_REQ               (1UL<<13)
        #define RPM_DEBUG3_DFSM_MBUF_NOTAVAIL               (1UL<<14)
        #define RPM_DEBUG3_RBUF_RDE_SOF_DROP                (1UL<<15)
        #define RPM_DEBUG3_DFIFO_VLD_ENTRY_CT               (0xfUL<<16)
        #define RPM_DEBUG3_RDE_SRC_FIFO_ALMFULL             (1UL<<21)
        #define RPM_DEBUG3_DROP_NXT_VLD                     (1UL<<22)
        #define RPM_DEBUG3_DROP_NXT                         (1UL<<23)
        #define RPM_DEBUG3_FTQ_FSM                          (0x3UL<<24)
            #define RPM_DEBUG3_FTQ_FSM_IDLE                 (0UL<<24)
            #define RPM_DEBUG3_FTQ_FSM_WAIT_ACK             (1UL<<24)
            #define RPM_DEBUG3_FTQ_FSM_WAIT_FREE            (2UL<<24)
        #define RPM_DEBUG3_MBWRITE_FSM                      (0x3UL<<26)
            #define RPM_DEBUG3_MBWRITE_FSM_WAIT_SOF         (0UL<<26)
            #define RPM_DEBUG3_MBWRITE_FSM_GET_MBUF         (1UL<<26)
            #define RPM_DEBUG3_MBWRITE_FSM_DMA_DATA         (2UL<<26)
            #define RPM_DEBUG3_MBWRITE_FSM_WAIT_DATA        (3UL<<26)
            #define RPM_DEBUG3_MBWRITE_FSM_WAIT_EOF         (4UL<<26)
            #define RPM_DEBUG3_MBWRITE_FSM_WAIT_MF_ACK      (5UL<<26)
            #define RPM_DEBUG3_MBWRITE_FSM_WAIT_DROP_NXT_VLD  (6UL<<26)
            #define RPM_DEBUG3_MBWRITE_FSM_DONE             (7UL<<26)
        #define RPM_DEBUG3_MBFREE_FSM                       (1UL<<29)
            #define RPM_DEBUG3_MBFREE_FSM_IDLE              (0UL<<29)
            #define RPM_DEBUG3_MBFREE_FSM_WAIT_ACK          (1UL<<29)
        #define RPM_DEBUG3_MBALLOC_FSM                      (1UL<<30)
            #define RPM_DEBUG3_MBALLOC_FSM_ET_MBUF          (0UL<<30)
            #define RPM_DEBUG3_MBALLOC_FSM_IVE_MBUF         (1UL<<30)
        #define RPM_DEBUG3_CCODE_EOF_ERROR                  (1UL<<31)

    u32_t rpm_debug4;
        #define RPM_DEBUG4_DFSM_MBUF_CLUSTER                (0x1ffffffUL<<0)
        #define RPM_DEBUG4_DFIFO_CUR_CCODE                  (0x7UL<<25)
        #define RPM_DEBUG4_MBWRITE_FSM                      (0x7UL<<28)
        #define RPM_DEBUG4_DFIFO_EMPTY                      (1UL<<31)

    u32_t rpm_debug5;
        #define RPM_DEBUG5_RDROP_WPTR                       (0x1fUL<<0)
        #define RPM_DEBUG5_RDROP_ACPI_RPTR                  (0x1fUL<<5)
        #define RPM_DEBUG5_RDROP_MC_RPTR                    (0x1fUL<<10)
        #define RPM_DEBUG5_RDROP_RC_RPTR                    (0x1fUL<<15)
        #define RPM_DEBUG5_RDROP_ACPI_EMPTY                 (1UL<<20)
        #define RPM_DEBUG5_RDROP_MC_EMPTY                   (1UL<<21)
        #define RPM_DEBUG5_RDROP_AEOF_VEC_AT_RDROP_MC_RPTR  (1UL<<22)
        #define RPM_DEBUG5_HOLDREG_WOL_DROP_INT             (1UL<<23)
        #define RPM_DEBUG5_HOLDREG_DISCARD                  (1UL<<24)
        #define RPM_DEBUG5_HOLDREG_MBUF_NOTAVAIL            (1UL<<25)
        #define RPM_DEBUG5_HOLDREG_MC_EMPTY                 (1UL<<26)
        #define RPM_DEBUG5_HOLDREG_RC_EMPTY                 (1UL<<27)
        #define RPM_DEBUG5_HOLDREG_FC_EMPTY                 (1UL<<28)
        #define RPM_DEBUG5_HOLDREG_ACPI_EMPTY               (1UL<<29)
        #define RPM_DEBUG5_HOLDREG_FULL_T                   (1UL<<30)
        #define RPM_DEBUG5_HOLDREG_RD                       (1UL<<31)

    u32_t rpm_debug6;
        #define RPM_DEBUG6_ACPI_VEC                         (0xffffUL<<0)
        #define RPM_DEBUG6_VEC                              (0xffffUL<<16)

    u32_t rpm_debug7;
        #define RPM_DEBUG7_RPM_DBG7_LAST_CRC                (0xffffffffUL<<0)

    u32_t rpm_debug8;
        #define RPM_DEBUG8_PS_ACPI_FSM                      (0xfUL<<0)
            #define RPM_DEBUG8_PS_ACPI_FSM_IDLE             (0UL<<0)
            #define RPM_DEBUG8_PS_ACPI_FSM_SOF_W1_ADDR      (1UL<<0)
            #define RPM_DEBUG8_PS_ACPI_FSM_SOF_W2_ADDR      (2UL<<0)
            #define RPM_DEBUG8_PS_ACPI_FSM_SOF_W3_ADDR      (3UL<<0)
            #define RPM_DEBUG8_PS_ACPI_FSM_SOF_WAIT_THBUF   (4UL<<0)
            #define RPM_DEBUG8_PS_ACPI_FSM_W3_DATA          (5UL<<0)
            #define RPM_DEBUG8_PS_ACPI_FSM_W0_ADDR          (6UL<<0)
            #define RPM_DEBUG8_PS_ACPI_FSM_W1_ADDR          (7UL<<0)
            #define RPM_DEBUG8_PS_ACPI_FSM_W2_ADDR          (8UL<<0)
            #define RPM_DEBUG8_PS_ACPI_FSM_W3_ADDR          (9UL<<0)
            #define RPM_DEBUG8_PS_ACPI_FSM_WAIT_THBUF       (10UL<<0)
        #define RPM_DEBUG8_COMPARE_AT_W0                    (1UL<<4)
        #define RPM_DEBUG8_COMPARE_AT_W3_DATA               (1UL<<5)
        #define RPM_DEBUG8_COMPARE_AT_SOF_WAIT              (1UL<<6)
        #define RPM_DEBUG8_COMPARE_AT_SOF_W3                (1UL<<7)
        #define RPM_DEBUG8_COMPARE_AT_SOF_W2                (1UL<<8)
        #define RPM_DEBUG8_EOF_W_LTEQ6_VLDBYTES             (1UL<<9)
        #define RPM_DEBUG8_EOF_W_LTEQ4_VLDBYTES             (1UL<<10)
        #define RPM_DEBUG8_NXT_EOF_W_12_VLDBYTES            (1UL<<11)
        #define RPM_DEBUG8_EOF_DET                          (1UL<<12)
        #define RPM_DEBUG8_SOF_DET                          (1UL<<13)
        #define RPM_DEBUG8_WAIT_4_SOF                       (1UL<<14)
        #define RPM_DEBUG8_ALL_DONE                         (1UL<<15)
        #define RPM_DEBUG8_THBUF_ADDR                       (0x7fUL<<16)
        #define RPM_DEBUG8_BYTE_CTR                         (0xffUL<<24)

    u32_t rpm_debug9;
        #define RPM_DEBUG9_OUTFIFO_COUNT_TE                    (0x7UL<<0)
        #define RPM_DEBUG9_RDE_ACPI_RDY_TE                     (1UL<<3)
        #define RPM_DEBUG9_VLD_RD_ENTRY_CT_TE                  (0x7UL<<4)
        #define RPM_DEBUG9_OUTFIFO_OVERRUN_OCCURRED_TE         (1UL<<28)
        #define RPM_DEBUG9_INFIFO_OVERRUN_OCCURRED_TE          (1UL<<29)
        #define RPM_DEBUG9_ACPI_MATCH_INT_TE                   (1UL<<30)
        #define RPM_DEBUG9_ACPI_ENABLE_SYN_TE                  (1UL<<31)
        #define RPM_DEBUG9_BEMEM_R_XI                          (0x1fUL<<0)
        #define RPM_DEBUG9_EO_XI                               (1UL<<5)
        #define RPM_DEBUG9_AEOF_DE_XI                          (1UL<<6)
        #define RPM_DEBUG9_SO_XI                               (1UL<<7)
        #define RPM_DEBUG9_WD64_CT_XI                          (0x1fUL<<8)
        #define RPM_DEBUG9_EOF_VLDBYTE_XI                      (0x7UL<<13)
        #define RPM_DEBUG9_ACPI_RDE_PAT_ID_XI                  (0xfUL<<16)
        #define RPM_DEBUG9_CALCRC_RESULT_XI                    (0x3ffUL<<20)
        #define RPM_DEBUG9_DATA_IN_VL_XI                       (1UL<<30)
        #define RPM_DEBUG9_CALCRC_BUFFER_VLD_XI                (1UL<<31)

    u32_t unused_3[5];
    u32_t rpm_acpi_dbg_buf_w0[4];
    u32_t rpm_acpi_dbg_buf_w1[4];
    u32_t rpm_acpi_dbg_buf_w2[4];
    u32_t rpm_acpi_dbg_buf_w3[4];
    u32_t rpm_acpi_byte_enable_ctrl;
        #define RPM_ACPI_BYTE_ENABLE_CTRL_BYTE_ADDRESS      (0xffffUL<<0)
        #define RPM_ACPI_BYTE_ENABLE_CTRL_DEBUGRD           (1UL<<28)
        #define RPM_ACPI_BYTE_ENABLE_CTRL_MODE              (1UL<<29)
        #define RPM_ACPI_BYTE_ENABLE_CTRL_INIT              (1UL<<30)
        #define RPM_ACPI_BYTE_ENABLE_CTRL_WR                (1UL<<31)

    u32_t rpm_acpi_pattern_ctrl;
        #define RPM_ACPI_PATTERN_CTRL_PATTERN_ID            (0xfUL<<0)
        #define RPM_ACPI_PATTERN_CTRL_CRC_SM_CLR            (1UL<<30)
        #define RPM_ACPI_PATTERN_CTRL_WR                    (1UL<<31)

    u32_t rpm_acpi_data;
        #define RPM_ACPI_DATA_PATTERN_BE                    (0xffffffffUL<<0)

    u32_t rpm_acpi_pattern_len0;
        #define RPM_ACPI_PATTERN_LEN0_PATTERN_LEN3          (0xffUL<<0)
        #define RPM_ACPI_PATTERN_LEN0_PATTERN_LEN2          (0xffUL<<8)
        #define RPM_ACPI_PATTERN_LEN0_PATTERN_LEN1          (0xffUL<<16)
        #define RPM_ACPI_PATTERN_LEN0_PATTERN_LEN0          (0xffUL<<24)

    u32_t rpm_acpi_pattern_len1;
        #define RPM_ACPI_PATTERN_LEN1_PATTERN_LEN7          (0xffUL<<0)
        #define RPM_ACPI_PATTERN_LEN1_PATTERN_LEN6          (0xffUL<<8)
        #define RPM_ACPI_PATTERN_LEN1_PATTERN_LEN5          (0xffUL<<16)
        #define RPM_ACPI_PATTERN_LEN1_PATTERN_LEN4          (0xffUL<<24)

    u32_t unused_4;
    u32_t rpm_acpi_pattern_crc0;
        #define RPM_ACPI_PATTERN_CRC0_PATTERN_CRC0          (0xffffffffUL<<0)

    u32_t rpm_acpi_pattern_crc1;
        #define RPM_ACPI_PATTERN_CRC1_PATTERN_CRC1          (0xffffffffUL<<0)

    u32_t rpm_acpi_pattern_crc2;
        #define RPM_ACPI_PATTERN_CRC2_PATTERN_CRC2          (0xffffffffUL<<0)

    u32_t rpm_acpi_pattern_crc3;
        #define RPM_ACPI_PATTERN_CRC3_PATTERN_CRC3          (0xffffffffUL<<0)

    u32_t rpm_acpi_pattern_crc4;
        #define RPM_ACPI_PATTERN_CRC4_PATTERN_CRC4          (0xffffffffUL<<0)

    u32_t rpm_acpi_pattern_crc5;
        #define RPM_ACPI_PATTERN_CRC5_PATTERN_CRC5          (0xffffffffUL<<0)

    u32_t rpm_acpi_pattern_crc6;
        #define RPM_ACPI_PATTERN_CRC6_PATTERN_CRC6          (0xffffffffUL<<0)

    u32_t rpm_acpi_pattern_crc7;
        #define RPM_ACPI_PATTERN_CRC7_PATTERN_CRC7          (0xffffffffUL<<0)

    u32_t unused_5[114];
} rpm_reg_t;

typedef rpm_reg_t rx_parser_reg_t;

/*
 *  rpc_reg definition
 *  offset: 0x1c00
 */
typedef struct rpc_reg
{
    u32_t rpc_command;
        #define RPC_COMMAND_ENABLED                         (1UL<<0)
        #define RPC_COMMAND_OVERRUN_ABORT                   (1UL<<4)

    u32_t rpc_status;
        #define RPC_STATUS_MBUF_WAIT                        (1UL<<0)
        #define RPC_STATUS_FREE_WAIT                        (1UL<<1)

    u32_t rpc_config;
        #define RPC_CONFIG_NO_PSD_HDR_CKSUM                 (1UL<<0)
        #define RPC_CONFIG_SORT_VECT_VAL                    (0xfUL<<4)
        #define RPC_CONFIG_IGNORE_VLAN                      (1UL<<31)

    u32_t unused_0[13];
    u32_t rpc_stat_l2_filter_discards;
    u32_t rpc_stat_rule_checker_discards;
    u32_t rpc_stat_ifinftqdiscards;
    u32_t rpc_stat_ifinmbufdiscard;
    u32_t rpc_stat_rule_checker_p4_hit;
    u32_t rpc_ipv6_programmable_extension0;
        #define RPC_IPV6_PROGRAMMABLE_EXTENSION0_NEXT_HEADER_LEN  (0xffUL<<0)
        #define RPC_IPV6_PROGRAMMABLE_EXTENSION0_NEXT_HEADER  (0xffUL<<16)
        #define RPC_IPV6_PROGRAMMABLE_EXTENSION0_NEXT_HEADER_LEN_TYPE  (1UL<<30)
        #define RPC_IPV6_PROGRAMMABLE_EXTENSION0_NEXT_HEADER_EN  (1UL<<31)

    u32_t rpc_ipv6_programmable_extension1;
        #define RPC_IPV6_PROGRAMMABLE_EXTENSION1_NEXT_HEADER_LEN  (0xffUL<<0)
        #define RPC_IPV6_PROGRAMMABLE_EXTENSION1_NEXT_HEADER  (0xffUL<<16)
        #define RPC_IPV6_PROGRAMMABLE_EXTENSION1_NEXT_HEADER_LEN_TYPE  (1UL<<30)
        #define RPC_IPV6_PROGRAMMABLE_EXTENSION1_NEXT_HEADER_EN  (1UL<<31)

    u32_t rpc_ipv6_programmable_extension2;
        #define RPC_IPV6_PROGRAMMABLE_EXTENSION2_NEXT_HEADER_LEN  (0xffUL<<0)
        #define RPC_IPV6_PROGRAMMABLE_EXTENSION2_NEXT_HEADER  (0xffUL<<16)
        #define RPC_IPV6_PROGRAMMABLE_EXTENSION2_NEXT_HEADER_LEN_TYPE  (1UL<<30)
        #define RPC_IPV6_PROGRAMMABLE_EXTENSION2_NEXT_HEADER_EN  (1UL<<31)

    u32_t rpc_ipv6_programmable_extension3;
        #define RPC_IPV6_PROGRAMMABLE_EXTENSION3_NEXT_HEADER_LEN  (0xffUL<<0)
        #define RPC_IPV6_PROGRAMMABLE_EXTENSION3_NEXT_HEADER  (0xffUL<<16)
        #define RPC_IPV6_PROGRAMMABLE_EXTENSION3_NEXT_HEADER_LEN_TYPE  (1UL<<30)
        #define RPC_IPV6_PROGRAMMABLE_EXTENSION3_NEXT_HEADER_EN  (1UL<<31)

    u32_t rpc_ipv6_programmable_extension4;
        #define RPC_IPV6_PROGRAMMABLE_EXTENSION4_NEXT_HEADER_LEN  (0xffUL<<0)
        #define RPC_IPV6_PROGRAMMABLE_EXTENSION4_NEXT_HEADER  (0xffUL<<16)
        #define RPC_IPV6_PROGRAMMABLE_EXTENSION4_NEXT_HEADER_LEN_TYPE  (1UL<<30)
        #define RPC_IPV6_PROGRAMMABLE_EXTENSION4_NEXT_HEADER_EN  (1UL<<31)

    u32_t rpc_ipv6_programmable_extension5;
        #define RPC_IPV6_PROGRAMMABLE_EXTENSION5_NEXT_HEADER_LEN  (0xffUL<<0)
        #define RPC_IPV6_PROGRAMMABLE_EXTENSION5_NEXT_HEADER  (0xffUL<<16)
        #define RPC_IPV6_PROGRAMMABLE_EXTENSION5_NEXT_HEADER_LEN_TYPE  (1UL<<30)
        #define RPC_IPV6_PROGRAMMABLE_EXTENSION5_NEXT_HEADER_EN  (1UL<<31)

    u32_t rpc_ipv6_programmable_extension6;
        #define RPC_IPV6_PROGRAMMABLE_EXTENSION6_NEXT_HEADER_LEN  (0xffUL<<0)
        #define RPC_IPV6_PROGRAMMABLE_EXTENSION6_NEXT_HEADER  (0xffUL<<16)
        #define RPC_IPV6_PROGRAMMABLE_EXTENSION6_NEXT_HEADER_LEN_TYPE  (1UL<<30)
        #define RPC_IPV6_PROGRAMMABLE_EXTENSION6_NEXT_HEADER_EN  (1UL<<31)

    u32_t rpc_ipv6_programmable_extension7;
        #define RPC_IPV6_PROGRAMMABLE_EXTENSION7_NEXT_HEADER_LEN  (0xffUL<<0)
        #define RPC_IPV6_PROGRAMMABLE_EXTENSION7_NEXT_HEADER  (0xffUL<<16)
        #define RPC_IPV6_PROGRAMMABLE_EXTENSION7_NEXT_HEADER_LEN_TYPE  (1UL<<30)
        #define RPC_IPV6_PROGRAMMABLE_EXTENSION7_NEXT_HEADER_EN  (1UL<<31)

    u32_t unused_1[3];
    u32_t rpc_stat_ac[5];
    u32_t unused_2[27];
    u32_t rpc_rc_cntl_0;
        #define RPC_RC_CNTL_0_OFFSET                        (0xffUL<<0)
        #define RPC_RC_CNTL_0_CLASS                         (0x7UL<<8)
        #define RPC_RC_CNTL_0_PRIORITY                      (1UL<<11)
        #define RPC_RC_CNTL_0_P4                            (1UL<<12)
        #define RPC_RC_CNTL_0_HDR_TYPE                      (0x7UL<<13)
            #define RPC_RC_CNTL_0_HDR_TYPE_START            (0UL<<13)
            #define RPC_RC_CNTL_0_HDR_TYPE_IP               (1UL<<13)
            #define RPC_RC_CNTL_0_HDR_TYPE_TCP              (2UL<<13)
            #define RPC_RC_CNTL_0_HDR_TYPE_UDP              (3UL<<13)
            #define RPC_RC_CNTL_0_HDR_TYPE_DATA             (4UL<<13)
        #define RPC_RC_CNTL_0_COMP                          (0x3UL<<16)
            #define RPC_RC_CNTL_0_COMP_EQUAL                (0UL<<16)
            #define RPC_RC_CNTL_0_COMP_NEQUAL               (1UL<<16)
            #define RPC_RC_CNTL_0_COMP_GREATER              (2UL<<16)
            #define RPC_RC_CNTL_0_COMP_LESS                 (3UL<<16)
        #define RPC_RC_CNTL_0_MAP_XI                           (1UL<<18)
        #define RPC_RC_CNTL_0_SBIT                          (1UL<<19)
        #define RPC_RC_CNTL_0_CMDSEL_TE                        (0xfUL<<20)
        #define RPC_RC_CNTL_0_MAP_TE                           (1UL<<24)
        #define RPC_RC_CNTL_0_CMDSEL_XI                        (0x1fUL<<20)
        #define RPC_RC_CNTL_0_DISCARD                       (1UL<<25)
        #define RPC_RC_CNTL_0_MASK                          (1UL<<26)
        #define RPC_RC_CNTL_0_P1                            (1UL<<27)
        #define RPC_RC_CNTL_0_P2                            (1UL<<28)
        #define RPC_RC_CNTL_0_P3                            (1UL<<29)
        #define RPC_RC_CNTL_0_NBIT                          (1UL<<30)

    u32_t rpc_rc_value_mask_0;
        #define RPC_RC_VALUE_MASK_0_VALUE                   (0xffffUL<<0)
        #define RPC_RC_VALUE_MASK_0_MASK                    (0xffffUL<<16)

    u32_t rpc_rc_cntl_1;
        #define RPC_RC_CNTL_1_A_TE                             (0x3ffffUL<<0)
        #define RPC_RC_CNTL_1_B_TE                             (0xfffUL<<19)
        #define RPC_RC_CNTL_1_OFFSET_XI                        (0xffUL<<0)
        #define RPC_RC_CNTL_1_CLASS_XI                         (0x7UL<<8)
        #define RPC_RC_CNTL_1_PRIORITY_XI                      (1UL<<11)
        #define RPC_RC_CNTL_1_P4_XI                            (1UL<<12)
        #define RPC_RC_CNTL_1_HDR_TYPE_XI                      (0x7UL<<13)
            #define RPC_RC_CNTL_1_HDR_TYPE_START_XI            (0UL<<13)
            #define RPC_RC_CNTL_1_HDR_TYPE_IP_XI               (1UL<<13)
            #define RPC_RC_CNTL_1_HDR_TYPE_TCP_XI              (2UL<<13)
            #define RPC_RC_CNTL_1_HDR_TYPE_UDP_XI              (3UL<<13)
            #define RPC_RC_CNTL_1_HDR_TYPE_DATA_XI             (4UL<<13)
        #define RPC_RC_CNTL_1_COMP_XI                          (0x3UL<<16)
            #define RPC_RC_CNTL_1_COMP_EQUAL_XI                (0UL<<16)
            #define RPC_RC_CNTL_1_COMP_NEQUAL_XI               (1UL<<16)
            #define RPC_RC_CNTL_1_COMP_GREATER_XI              (2UL<<16)
            #define RPC_RC_CNTL_1_COMP_LESS_XI                 (3UL<<16)
        #define RPC_RC_CNTL_1_MAP_XI                           (1UL<<18)
        #define RPC_RC_CNTL_1_SBIT_XI                          (1UL<<19)
        #define RPC_RC_CNTL_1_CMDSEL_XI                        (0x1fUL<<20)
        #define RPC_RC_CNTL_1_DISCARD_XI                       (1UL<<25)
        #define RPC_RC_CNTL_1_MASK_XI                          (1UL<<26)
        #define RPC_RC_CNTL_1_P1_XI                            (1UL<<27)
        #define RPC_RC_CNTL_1_P2_XI                            (1UL<<28)
        #define RPC_RC_CNTL_1_P3_XI                            (1UL<<29)
        #define RPC_RC_CNTL_1_NBIT_XI                          (1UL<<30)

    u32_t rpc_rc_value_mask_1;
        #define RPC_RC_VALUE_MASK_1_VALUE                   (0xffffUL<<0)
        #define RPC_RC_VALUE_MASK_1_MASK                    (0xffffUL<<16)

    u32_t rpc_rc_cntl_2;
        #define RPC_RC_CNTL_2_A_TE                             (0x3ffffUL<<0)
        #define RPC_RC_CNTL_2_B_TE                             (0xfffUL<<19)
        #define RPC_RC_CNTL_2_OFFSET_XI                        (0xffUL<<0)
        #define RPC_RC_CNTL_2_CLASS_XI                         (0x7UL<<8)
        #define RPC_RC_CNTL_2_PRIORITY_XI                      (1UL<<11)
        #define RPC_RC_CNTL_2_P4_XI                            (1UL<<12)
        #define RPC_RC_CNTL_2_HDR_TYPE_XI                      (0x7UL<<13)
            #define RPC_RC_CNTL_2_HDR_TYPE_START_XI            (0UL<<13)
            #define RPC_RC_CNTL_2_HDR_TYPE_IP_XI               (1UL<<13)
            #define RPC_RC_CNTL_2_HDR_TYPE_TCP_XI              (2UL<<13)
            #define RPC_RC_CNTL_2_HDR_TYPE_UDP_XI              (3UL<<13)
            #define RPC_RC_CNTL_2_HDR_TYPE_DATA_XI             (4UL<<13)
        #define RPC_RC_CNTL_2_COMP_XI                          (0x3UL<<16)
            #define RPC_RC_CNTL_2_COMP_EQUAL_XI                (0UL<<16)
            #define RPC_RC_CNTL_2_COMP_NEQUAL_XI               (1UL<<16)
            #define RPC_RC_CNTL_2_COMP_GREATER_XI              (2UL<<16)
            #define RPC_RC_CNTL_2_COMP_LESS_XI                 (3UL<<16)
        #define RPC_RC_CNTL_2_MAP_XI                           (1UL<<18)
        #define RPC_RC_CNTL_2_SBIT_XI                          (1UL<<19)
        #define RPC_RC_CNTL_2_CMDSEL_XI                        (0x1fUL<<20)
        #define RPC_RC_CNTL_2_DISCARD_XI                       (1UL<<25)
        #define RPC_RC_CNTL_2_MASK_XI                          (1UL<<26)
        #define RPC_RC_CNTL_2_P1_XI                            (1UL<<27)
        #define RPC_RC_CNTL_2_P2_XI                            (1UL<<28)
        #define RPC_RC_CNTL_2_P3_XI                            (1UL<<29)
        #define RPC_RC_CNTL_2_NBIT_XI                          (1UL<<30)

    u32_t rpc_rc_value_mask_2;
        #define RPC_RC_VALUE_MASK_2_VALUE                   (0xffffUL<<0)
        #define RPC_RC_VALUE_MASK_2_MASK                    (0xffffUL<<16)

    u32_t rpc_rc_cntl_3;
        #define RPC_RC_CNTL_3_A_TE                             (0x3ffffUL<<0)
        #define RPC_RC_CNTL_3_B_TE                             (0xfffUL<<19)
        #define RPC_RC_CNTL_3_OFFSET_XI                        (0xffUL<<0)
        #define RPC_RC_CNTL_3_CLASS_XI                         (0x7UL<<8)
        #define RPC_RC_CNTL_3_PRIORITY_XI                      (1UL<<11)
        #define RPC_RC_CNTL_3_P4_XI                            (1UL<<12)
        #define RPC_RC_CNTL_3_HDR_TYPE_XI                      (0x7UL<<13)
            #define RPC_RC_CNTL_3_HDR_TYPE_START_XI            (0UL<<13)
            #define RPC_RC_CNTL_3_HDR_TYPE_IP_XI               (1UL<<13)
            #define RPC_RC_CNTL_3_HDR_TYPE_TCP_XI              (2UL<<13)
            #define RPC_RC_CNTL_3_HDR_TYPE_UDP_XI              (3UL<<13)
            #define RPC_RC_CNTL_3_HDR_TYPE_DATA_XI             (4UL<<13)
        #define RPC_RC_CNTL_3_COMP_XI                          (0x3UL<<16)
            #define RPC_RC_CNTL_3_COMP_EQUAL_XI                (0UL<<16)
            #define RPC_RC_CNTL_3_COMP_NEQUAL_XI               (1UL<<16)
            #define RPC_RC_CNTL_3_COMP_GREATER_XI              (2UL<<16)
            #define RPC_RC_CNTL_3_COMP_LESS_XI                 (3UL<<16)
        #define RPC_RC_CNTL_3_MAP_XI                           (1UL<<18)
        #define RPC_RC_CNTL_3_SBIT_XI                          (1UL<<19)
        #define RPC_RC_CNTL_3_CMDSEL_XI                        (0x1fUL<<20)
        #define RPC_RC_CNTL_3_DISCARD_XI                       (1UL<<25)
        #define RPC_RC_CNTL_3_MASK_XI                          (1UL<<26)
        #define RPC_RC_CNTL_3_P1_XI                            (1UL<<27)
        #define RPC_RC_CNTL_3_P2_XI                            (1UL<<28)
        #define RPC_RC_CNTL_3_P3_XI                            (1UL<<29)
        #define RPC_RC_CNTL_3_NBIT_XI                          (1UL<<30)

    u32_t rpc_rc_value_mask_3;
        #define RPC_RC_VALUE_MASK_3_VALUE                   (0xffffUL<<0)
        #define RPC_RC_VALUE_MASK_3_MASK                    (0xffffUL<<16)

    u32_t rpc_rc_cntl_4;
        #define RPC_RC_CNTL_4_A                             (0x3ffffUL<<0)
        #define RPC_RC_CNTL_4_B                             (0xfffUL<<19)

    u32_t rpc_rc_value_mask_4;
    u32_t rpc_rc_cntl_5;
        #define RPC_RC_CNTL_5_A                             (0x3ffffUL<<0)
        #define RPC_RC_CNTL_5_B                             (0xfffUL<<19)

    u32_t rpc_rc_value_mask_5;
    u32_t rpc_rc_cntl_6;
        #define RPC_RC_CNTL_6_A                             (0x3ffffUL<<0)
        #define RPC_RC_CNTL_6_B                             (0xfffUL<<19)

    u32_t rpc_rc_value_mask_6;
    u32_t rpc_rc_cntl_7;
        #define RPC_RC_CNTL_7_A                             (0x3ffffUL<<0)
        #define RPC_RC_CNTL_7_B                             (0xfffUL<<19)

    u32_t rpc_rc_value_mask_7;
    u32_t rpc_rc_cntl_8;
        #define RPC_RC_CNTL_8_A                             (0x3ffffUL<<0)
        #define RPC_RC_CNTL_8_B                             (0xfffUL<<19)

    u32_t rpc_rc_value_mask_8;
    u32_t rpc_rc_cntl_9;
        #define RPC_RC_CNTL_9_A                             (0x3ffffUL<<0)
        #define RPC_RC_CNTL_9_B                             (0xfffUL<<19)

    u32_t rpc_rc_value_mask_9;
    u32_t rpc_rc_cntl_10;
        #define RPC_RC_CNTL_10_A                            (0x3ffffUL<<0)
        #define RPC_RC_CNTL_10_B                            (0xfffUL<<19)

    u32_t rpc_rc_value_mask_10;
    u32_t rpc_rc_cntl_11;
        #define RPC_RC_CNTL_11_A                            (0x3ffffUL<<0)
        #define RPC_RC_CNTL_11_B                            (0xfffUL<<19)

    u32_t rpc_rc_value_mask_11;
    u32_t rpc_rc_cntl_12;
        #define RPC_RC_CNTL_12_A                            (0x3ffffUL<<0)
        #define RPC_RC_CNTL_12_B                            (0xfffUL<<19)

    u32_t rpc_rc_value_mask_12;
    u32_t rpc_rc_cntl_13;
        #define RPC_RC_CNTL_13_A                            (0x3ffffUL<<0)
        #define RPC_RC_CNTL_13_B                            (0xfffUL<<19)

    u32_t rpc_rc_value_mask_13;
    u32_t rpc_rc_cntl_14;
        #define RPC_RC_CNTL_14_A                            (0x3ffffUL<<0)
        #define RPC_RC_CNTL_14_B                            (0xfffUL<<19)

    u32_t rpc_rc_value_mask_14;
    u32_t rpc_rc_cntl_15;
        #define RPC_RC_CNTL_15_A                            (0x3ffffUL<<0)
        #define RPC_RC_CNTL_15_B                            (0xfffUL<<19)

    u32_t rpc_rc_value_mask_15;
    u32_t rpc_rc_config;
        #define RPC_RC_CONFIG_RULE_ENABLE_TE                   (0xffffUL<<0)
        #define RPC_RC_CONFIG_RULE_ENABLE_XI                   (0xfUL<<0)
        #define RPC_RC_CONFIG_DEF_CLASS                     (0x7UL<<24)

    u32_t rpc_debug0;
        #define RPC_DEBUG0_FM_BCNT                          (0xffffUL<<0)
        #define RPC_DEBUG0_T_DATA_OFST_VLD                  (1UL<<16)
        #define RPC_DEBUG0_T_UDP_OFST_VLD                   (1UL<<17)
        #define RPC_DEBUG0_T_TCP_OFST_VLD                   (1UL<<18)
        #define RPC_DEBUG0_T_IP_OFST_VLD                    (1UL<<19)
        #define RPC_DEBUG0_IP_MORE_FRGMT                    (1UL<<20)
        #define RPC_DEBUG0_T_IP_NO_TCP_UDP_HDR              (1UL<<21)
        #define RPC_DEBUG0_LLC_SNAP                         (1UL<<22)
        #define RPC_DEBUG0_FM_STARTED                       (1UL<<23)
        #define RPC_DEBUG0_DONE                             (1UL<<24)
        #define RPC_DEBUG0_WAIT_4_DONE                      (1UL<<25)
        #define RPC_DEBUG0_USE_TPBUF_CKSUM                  (1UL<<26)
        #define RPC_DEBUG0_RX_NO_PSD_HDR_CKSUM              (1UL<<27)
        #define RPC_DEBUG0_IGNORE_VLAN                      (1UL<<28)
        #define RPC_DEBUG0_RP_ENA_ACTIVE                    (1UL<<31)

    u32_t rpc_debug1;
        #define RPC_DEBUG1_FSM_CUR_ST                       (0xffffUL<<0)
            #define RPC_DEBUG1_FSM_CUR_ST_IDLE              (0UL<<0)
            #define RPC_DEBUG1_FSM_CUR_ST_ETYPE_B6_ALL      (1UL<<0)
            #define RPC_DEBUG1_FSM_CUR_ST_ETYPE_B2_IPLLC    (2UL<<0)
            #define RPC_DEBUG1_FSM_CUR_ST_ETYPE_B6_IP       (4UL<<0)
            #define RPC_DEBUG1_FSM_CUR_ST_ETYPE_B2_IP       (8UL<<0)
            #define RPC_DEBUG1_FSM_CUR_ST_IP_START          (16UL<<0)
            #define RPC_DEBUG1_FSM_CUR_ST_IP                (32UL<<0)
            #define RPC_DEBUG1_FSM_CUR_ST_TCP               (64UL<<0)
            #define RPC_DEBUG1_FSM_CUR_ST_UDP               (128UL<<0)
            #define RPC_DEBUG1_FSM_CUR_ST_AH                (256UL<<0)
            #define RPC_DEBUG1_FSM_CUR_ST_ESP               (512UL<<0)
            #define RPC_DEBUG1_FSM_CUR_ST_ESP_PAYLOAD       (1024UL<<0)
            #define RPC_DEBUG1_FSM_CUR_ST_DATA              (2048UL<<0)
            #define RPC_DEBUG1_FSM_CUR_ST_ADD_CARRY         (8192UL<<0)
            #define RPC_DEBUG1_FSM_CUR_ST_ADD_CARRYOUT      (16384UL<<0)
            #define RPC_DEBUG1_FSM_CUR_ST_LATCH_RESULT      (32768UL<<0)
        #define RPC_DEBUG1_HDR_BCNT                         (0x7ffUL<<16)
        #define RPC_DEBUG1_UNKNOWN_ETYPE_D                  (1UL<<28)
        #define RPC_DEBUG1_VLAN_REMOVED_D2                  (1UL<<29)
        #define RPC_DEBUG1_VLAN_REMOVED_D1                  (1UL<<30)
        #define RPC_DEBUG1_EOF_0XTRA_WD                     (1UL<<31)

    u32_t rpc_debug2;
        #define RPC_DEBUG2_CMD_HIT_VEC                      (0xffffUL<<0)
        #define RPC_DEBUG2_IP_BCNT                          (0xffUL<<16)
        #define RPC_DEBUG2_THIS_CMD_M4                      (1UL<<24)
        #define RPC_DEBUG2_THIS_CMD_M3                      (1UL<<25)
        #define RPC_DEBUG2_THIS_CMD_M2                      (1UL<<26)
        #define RPC_DEBUG2_THIS_CMD_M1                      (1UL<<27)
        #define RPC_DEBUG2_IPIPE_EMPTY                      (1UL<<28)
        #define RPC_DEBUG2_FM_DISCARD                       (1UL<<29)
        #define RPC_DEBUG2_LAST_RULE_IN_FM_D2               (1UL<<30)
        #define RPC_DEBUG2_LAST_RULE_IN_FM_D1               (1UL<<31)

    u32_t rpc_debug3;
        #define RPC_DEBUG3_AVAIL_MBUF_PTR                   (0x1ffUL<<0)
        #define RPC_DEBUG3_RDE_RLUPQ_WR_REQ_INT             (1UL<<9)
        #define RPC_DEBUG3_RDE_RBUF_WR_LAST_INT             (1UL<<10)
        #define RPC_DEBUG3_RDE_RBUF_WR_REQ_INT              (1UL<<11)
        #define RPC_DEBUG3_RDE_RBUF_FREE_REQ                (1UL<<12)
        #define RPC_DEBUG3_RDE_RBUF_ALLOC_REQ               (1UL<<13)
        #define RPC_DEBUG3_DFSM_MBUF_NOTAVAIL               (1UL<<14)
        #define RPC_DEBUG3_RBUF_RDE_SOF_DROP                (1UL<<15)
        #define RPC_DEBUG3_DFIFO_VLD_ENTRY_CT               (0xfUL<<16)
        #define RPC_DEBUG3_RDE_SRC_FIFO_ALMFULL             (1UL<<21)
        #define RPC_DEBUG3_DROP_NXT_VLD                     (1UL<<22)
        #define RPC_DEBUG3_DROP_NXT                         (1UL<<23)
        #define RPC_DEBUG3_FTQ_FSM                          (0x3UL<<24)
            #define RPC_DEBUG3_FTQ_FSM_IDLE                 (0UL<<24)
            #define RPC_DEBUG3_FTQ_FSM_WAIT_ACK             (1UL<<24)
            #define RPC_DEBUG3_FTQ_FSM_WAIT_FREE            (2UL<<24)
        #define RPC_DEBUG3_MBWRITE_FSM                      (0x3UL<<26)
            #define RPC_DEBUG3_MBWRITE_FSM_WAIT_SOF         (0UL<<26)
            #define RPC_DEBUG3_MBWRITE_FSM_GET_MBUF         (1UL<<26)
            #define RPC_DEBUG3_MBWRITE_FSM_DMA_DATA         (2UL<<26)
            #define RPC_DEBUG3_MBWRITE_FSM_WAIT_DATA        (3UL<<26)
            #define RPC_DEBUG3_MBWRITE_FSM_WAIT_EOF         (4UL<<26)
            #define RPC_DEBUG3_MBWRITE_FSM_WAIT_MF_ACK      (5UL<<26)
            #define RPC_DEBUG3_MBWRITE_FSM_WAIT_DROP_NXT_VLD  (6UL<<26)
            #define RPC_DEBUG3_MBWRITE_FSM_DONE             (7UL<<26)
        #define RPC_DEBUG3_MBFREE_FSM                       (1UL<<29)
            #define RPC_DEBUG3_MBFREE_FSM_IDLE              (0UL<<29)
            #define RPC_DEBUG3_MBFREE_FSM_WAIT_ACK          (1UL<<29)
        #define RPC_DEBUG3_MBALLOC_FSM                      (1UL<<30)
            #define RPC_DEBUG3_MBALLOC_FSM_ET_MBUF          (0UL<<30)
            #define RPC_DEBUG3_MBALLOC_FSM_IVE_MBUF         (1UL<<30)
        #define RPC_DEBUG3_CCODE_EOF_ERROR                  (1UL<<31)

    u32_t rpc_debug4;
        #define RPC_DEBUG4_DFSM_MBUF_CLUSTER                (0x1ffffffUL<<0)
        #define RPC_DEBUG4_DFIFO_CUR_CCODE                  (0x7UL<<25)
        #define RPC_DEBUG4_MBWRITE_FSM                      (0x7UL<<28)
        #define RPC_DEBUG4_DFIFO_EMPTY                      (1UL<<31)

    u32_t rpc_debug5;
        #define RPC_DEBUG5_RDROP_WPTR                       (0x1fUL<<0)
        #define RPC_DEBUG5_RDROP_ACPI_RPTR                  (0x1fUL<<5)
        #define RPC_DEBUG5_RDROP_MC_RPTR                    (0x1fUL<<10)
        #define RPC_DEBUG5_RDROP_RC_RPTR                    (0x1fUL<<15)
        #define RPC_DEBUG5_RDROP_ACPI_EMPTY                 (1UL<<20)
        #define RPC_DEBUG5_RDROP_MC_EMPTY                   (1UL<<21)
        #define RPC_DEBUG5_RDROP_AEOF_VEC_AT_RDROP_MC_RPTR  (1UL<<22)
        #define RPC_DEBUG5_HOLDREG_WOL_DROP_INT             (1UL<<23)
        #define RPC_DEBUG5_HOLDREG_DISCARD                  (1UL<<24)
        #define RPC_DEBUG5_HOLDREG_MBUF_NOTAVAIL            (1UL<<25)
        #define RPC_DEBUG5_HOLDREG_MC_EMPTY                 (1UL<<26)
        #define RPC_DEBUG5_HOLDREG_RC_EMPTY                 (1UL<<27)
        #define RPC_DEBUG5_HOLDREG_FC_EMPTY                 (1UL<<28)
        #define RPC_DEBUG5_HOLDREG_ACPI_EMPTY               (1UL<<29)
        #define RPC_DEBUG5_HOLDREG_FULL_T                   (1UL<<30)
        #define RPC_DEBUG5_HOLDREG_RD                       (1UL<<31)

    u32_t rpc_debug6;
        #define RPC_DEBUG6_ACPI_VEC                         (0xffffUL<<0)
        #define RPC_DEBUG6_VEC                              (0xffffUL<<16)

    u32_t rpc_debug7;
        #define RPC_DEBUG7_RPM_DBG7_LAST_CRC                (0xffffffffUL<<0)

    u32_t rpc_debug8;
        #define RPC_DEBUG8_PS_ACPI_FSM                      (0xfUL<<0)
            #define RPC_DEBUG8_PS_ACPI_FSM_IDLE             (0UL<<0)
            #define RPC_DEBUG8_PS_ACPI_FSM_SOF_W1_ADDR      (1UL<<0)
            #define RPC_DEBUG8_PS_ACPI_FSM_SOF_W2_ADDR      (2UL<<0)
            #define RPC_DEBUG8_PS_ACPI_FSM_SOF_W3_ADDR      (3UL<<0)
            #define RPC_DEBUG8_PS_ACPI_FSM_SOF_WAIT_THBUF   (4UL<<0)
            #define RPC_DEBUG8_PS_ACPI_FSM_W3_DATA          (5UL<<0)
            #define RPC_DEBUG8_PS_ACPI_FSM_W0_ADDR          (6UL<<0)
            #define RPC_DEBUG8_PS_ACPI_FSM_W1_ADDR          (7UL<<0)
            #define RPC_DEBUG8_PS_ACPI_FSM_W2_ADDR          (8UL<<0)
            #define RPC_DEBUG8_PS_ACPI_FSM_W3_ADDR          (9UL<<0)
            #define RPC_DEBUG8_PS_ACPI_FSM_WAIT_THBUF       (10UL<<0)
        #define RPC_DEBUG8_COMPARE_AT_W0                    (1UL<<4)
        #define RPC_DEBUG8_COMPARE_AT_W3_DATA               (1UL<<5)
        #define RPC_DEBUG8_COMPARE_AT_SOF_WAIT              (1UL<<6)
        #define RPC_DEBUG8_COMPARE_AT_SOF_W3                (1UL<<7)
        #define RPC_DEBUG8_COMPARE_AT_SOF_W2                (1UL<<8)
        #define RPC_DEBUG8_EOF_W_LTEQ6_VLDBYTES             (1UL<<9)
        #define RPC_DEBUG8_EOF_W_LTEQ4_VLDBYTES             (1UL<<10)
        #define RPC_DEBUG8_NXT_EOF_W_12_VLDBYTES            (1UL<<11)
        #define RPC_DEBUG8_EOF_DET                          (1UL<<12)
        #define RPC_DEBUG8_SOF_DET                          (1UL<<13)
        #define RPC_DEBUG8_WAIT_4_SOF                       (1UL<<14)
        #define RPC_DEBUG8_ALL_DONE                         (1UL<<15)
        #define RPC_DEBUG8_THBUF_ADDR                       (0x7fUL<<16)
        #define RPC_DEBUG8_BYTE_CTR                         (0xffUL<<24)

    u32_t rpc_debug9;
        #define RPC_DEBUG9_OUTFIFO_COUNT                    (0x7UL<<0)
        #define RPC_DEBUG9_RDE_ACPI_RDY                     (1UL<<3)
        #define RPC_DEBUG9_VLD_RD_ENTRY_CT                  (0x7UL<<4)
        #define RPC_DEBUG9_OUTFIFO_OVERRUN_OCCURRED         (1UL<<28)
        #define RPC_DEBUG9_INFIFO_OVERRUN_OCCURRED          (1UL<<29)
        #define RPC_DEBUG9_ACPI_MATCH_INT                   (1UL<<30)
        #define RPC_DEBUG9_ACPI_ENABLE_SYN                  (1UL<<31)

    u32_t unused_3[149];
} rpc_reg_t;

typedef rpc_reg_t rx_cu_parser_reg_t;

/*
 *  rlupq definition
 *  offset: 0000
 */
typedef struct rlupq
{
    u32_t rlupq_ip_destadd0;
    u32_t rlupq_ip_destadd1;
    u32_t rlupq_ip_destadd2;
    u32_t rlupq_ip_destadd3;
    u32_t rlupq_wd4;
        #define RLUPQ_TCP_SRCPORT                           (0xffff<<16)
        #define RLUPQ_TCP_DSTPORT                           (0xffff<<0)

    u32_t rlupq_wd5;
        #define RLUPQ_CS16                                  (0xffff<<16)

    u32_t rlupq_wd6;
        #define RLUPQ_EXT_STATUS_TCP_SYNC_PRESENT           (1<<16)
        #define RLUPQ_EXT_STATUS_RLUP_HIT2                  (1<<17)
        #define RLUPQ_EXT_STATUS_TCP_UDP_XSUM_IS_0          (1<<18)
        #define RLUPQ_EXT_STATUS_IP_ROUTING_HDR_PRESENT     (0x3<<19)
            #define RLUPQ_EXT_STATUS_IP_ROUTING_HDR_PRESENT_00  (0<<19)
            #define RLUPQ_EXT_STATUS_IP_ROUTING_HDR_PRESENT_01  (1<<19)
            #define RLUPQ_EXT_STATUS_IP_ROUTING_HDR_PRESENT_10  (2<<19)
            #define RLUPQ_EXT_STATUS_IP_ROUTING_HDR_PRESENT_11  (3<<19)
        #define RLUPQ_EXT_STATUS_ACPI_MATCH                 (1<<21)

    u32_t unused_0[9];
    u32_t rlupq_bits_errors;
        #define RLUPQ_BITS_ERRORS_L2_BAD_CRC                (1UL<<1)
        #define RLUPQ_BITS_ERRORS_L2_PHY_DECODE             (1UL<<2)
        #define RLUPQ_BITS_ERRORS_L2_ALIGNMENT              (1UL<<3)
        #define RLUPQ_BITS_ERRORS_L2_TOO_SHORT              (1UL<<4)
        #define RLUPQ_BITS_ERRORS_L2_GIANT_FRAME            (1UL<<5)
        #define RLUPQ_BITS_ERRORS_IP_BAD_LEN                (1UL<<6)
        #define RLUPQ_BITS_ERRORS_IP_TOO_SHORT              (1UL<<7)
        #define RLUPQ_BITS_ERRORS_IP_BAD_VERSION            (1UL<<8)
        #define RLUPQ_BITS_ERRORS_IP_BAD_HLEN               (1UL<<9)
        #define RLUPQ_BITS_ERRORS_IP_BAD_XSUM               (1UL<<10)
        #define RLUPQ_BITS_ERRORS_TCP_TOO_SHORT             (1UL<<11)
        #define RLUPQ_BITS_ERRORS_TCP_BAD_XSUM              (1UL<<12)
        #define RLUPQ_BITS_ERRORS_TCP_BAD_OFFSET            (1UL<<13)
        #define RLUPQ_BITS_ERRORS_UDP_BAD_XSUM              (1UL<<15)
        #define RLUPQ_BITS_ERRORS_IP_BAD_ORDER              (1UL<<16)
        #define RLUPQ_BITS_ERRORS_IP_HDR_MISMATCH           (1UL<<18)

    u32_t rlupq_bits_status;
        #define RLUPQ_BITS_STATUS_RULE_CLASS                (0x7UL<<0)
        #define RLUPQ_BITS_STATUS_RULE_P2                   (1UL<<3)
        #define RLUPQ_BITS_STATUS_RULE_P3                   (1UL<<4)
        #define RLUPQ_BITS_STATUS_RULE_P4                   (1UL<<5)
        #define RLUPQ_BITS_STATUS_L2_VLAN_TAG               (1UL<<6)
        #define RLUPQ_BITS_STATUS_L2_LLC_SNAP               (1UL<<7)
        #define RLUPQ_BITS_STATUS_RSS_HASH                  (1UL<<8)
        #define RLUPQ_BITS_STATUS_SORT_VECT                 (0xfUL<<9)
        #define RLUPQ_BITS_STATUS_IP_DATAGRAM               (1UL<<13)
        #define RLUPQ_BITS_STATUS_TCP_SEGMENT               (1UL<<14)
        #define RLUPQ_BITS_STATUS_UDP_DATAGRAM              (1UL<<15)
        #define RLUPQ_BITS_STATUS_CU_FRAME                  (1UL<<16)
        #define RLUPQ_BITS_STATUS_IP_PROG_EXT               (1UL<<17)
        #define RLUPQ_BITS_STATUS_IP_TYPE                   (1UL<<18)
        #define RLUPQ_BITS_STATUS_RULE_P1                   (1UL<<19)
        #define RLUPQ_BITS_STATUS_RLUP_HIT4                 (1UL<<20)
        #define RLUPQ_BITS_STATUS_IP_FRAGMENT               (1UL<<21)
        #define RLUPQ_BITS_STATUS_IP_OPTIONS_PRESENT        (1UL<<22)
        #define RLUPQ_BITS_STATUS_TCP_OPTIONS_PRESENT       (1UL<<23)
        #define RLUPQ_BITS_STATUS_L2_PM_IDX                 (0xfUL<<24)
        #define RLUPQ_BITS_STATUS_L2_PM_HIT                 (1UL<<28)
        #define RLUPQ_BITS_STATUS_L2_MC_HASH_HIT            (1UL<<29)
        #define RLUPQ_BITS_STATUS_RDMAC_CRC_PASS            (1UL<<30)
        #define RLUPQ_BITS_STATUS_MP_HIT                    (1UL<<31)

    u32_t rlupq_wd18;
        #define RLUPQ_BITS_MULTICAST_HASH_IDX               (0xff<<24)
        #define RLUPQ_BITS_ACPI_PAT_ACPI_PAT                (0xf<<16)
            #define RLUPQ_BITS_ACPI_PAT_ACPI_PAT_0          (0<<16)
            #define RLUPQ_BITS_ACPI_PAT_ACPI_PAT_1          (1<<16)
            #define RLUPQ_BITS_ACPI_PAT_ACPI_PAT_2          (2<<16)
            #define RLUPQ_BITS_ACPI_PAT_ACPI_PAT_3          (3<<16)
            #define RLUPQ_BITS_ACPI_PAT_ACPI_PAT_4          (4<<16)
            #define RLUPQ_BITS_ACPI_PAT_ACPI_PAT_5          (5<<16)
            #define RLUPQ_BITS_ACPI_PAT_ACPI_PAT_6          (6<<16)
            #define RLUPQ_BITS_ACPI_PAT_ACPI_PAT_NONE       (7<<16)
            #define RLUPQ_BITS_ACPI_PAT_ACPI_PAT_8          (8<<16)
        #define RLUPQ_KNUM                                  (0xff<<8)

    u32_t rlupq_wd19;
        #define RLUPQ_RULE_TAG                              (0xffff<<16)
        #define RLUPQ_PKT_LEN_VALUE                         (0x3fff<<0)

    u32_t rlupq_wd20;
        #define RLUPQ_VLAN_TAG                              (0xffff<<16)
        #define RLUPQ_IP_HDR_OFFSET                         (0xff<<8)

    u32_t rlupq_wd21;
        #define RLUPQ_IP_XSUM                               (0xffff<<16)
        #define RLUPQ_TCP_UDP_HDR_OFFSET                    (0xffff<<0)

    u32_t rlupq_wd22;
        #define RLUPQ_TCP_UDP_XSUM                          (0xffff<<16)
        #define RLUPQ_TCP_PAYLOAD_LEN                       (0xffff<<0)

    u32_t rlupq_wd23;
        #define RLUPQ_PSEUD_XSUM                            (0xffff<<16)
        #define RLUPQ_L2_PAYLOAD_RAW_XSUM                   (0xffff<<0)

    u32_t rlupq_wd24;
        #define RLUPQ_DATA_OFFSET                           (0xffff<<16)
        #define RLUPQ_L3_PAYLOAD_RAW_XSUM                   (0xffff<<0)

    u32_t rlupq_mbuf_cluster;
        #define RLUPQ_MBUF_CLUSTER_VALUE                    (0x1ffffffUL<<0)

    u32_t rlupq_ip_srcadd0;
    u32_t rlupq_ip_srcadd1;
    u32_t rlupq_ip_srcadd2;
    u32_t rlupq_ip_srcadd3;
} rlupq_t;


/*
 *  rlup_reg definition
 *  offset: 0x2000
 */
typedef struct rlup_reg
{
    u32_t rlup_command;
        #define RLUP_COMMAND_ENABLED                        (1UL<<0)
        #define RLUP_COMMAND_ADD                            (1UL<<1)
        #define RLUP_COMMAND_INVALIDATE                     (1UL<<2)
        #define RLUP_COMMAND_LOOKUP                         (1UL<<3)
        #define RLUP_COMMAND_READ_TE                           (1UL<<4)
        #define RLUP_COMMAND_WRITE_TE                          (1UL<<5)
        #define RLUP_COMMAND_READ_CAM_XI                       (1UL<<4)
        #define RLUP_COMMAND_WRITE_CAM_XI                      (1UL<<5)
        #define RLUP_COMMAND_CAM_RESET                      (1UL<<6)
        #define RLUP_COMMAND_READ_RAM                       (1UL<<7)
        #define RLUP_COMMAND_WRITE_RAM                      (1UL<<8)
        #define RLUP_COMMAND_ENTRY_TYPE                     (0x3UL<<9)
            #define RLUP_COMMAND_ENTRY_TYPE_IPV4            (0UL<<9)
            #define RLUP_COMMAND_ENTRY_TYPE_IPV6_4_TUPLE    (1UL<<9)
            #define RLUP_COMMAND_ENTRY_TYPE_IPV6_2_TUPLE    (2UL<<9)
            #define RLUP_COMMAND_ENTRY_TYPE_RES             (3UL<<9)
        #define RLUP_COMMAND_2ND_TUPLE_LOOKUP_EN            (1UL<<11)
        #define RLUP_COMMAND_MAINTENANCE_MODE               (1UL<<12)

    u32_t rlup_status;
        #define RLUP_STATUS_FTQ                             (1UL<<0)
        #define RLUP_STATUS_SUCCESS                         (1UL<<1)
        #define RLUP_STATUS_WORD_MATCH_TE                      (1UL<<2)
        #define RLUP_STATUS_LOOKUP_MATCH_STAT_TE               (1UL<<3)
        #define RLUP_STATUS_LOOKUP_SM_TE                       (0x7UL<<16)
            #define RLUP_STATUS_LOOKUP_SM_IDLE_TE              (0UL<<16)
            #define RLUP_STATUS_LOOKUP_SM_INPUT_TE             (1UL<<16)
            #define RLUP_STATUS_LOOKUP_SM_CAM_GRC_TE           (2UL<<16)
            #define RLUP_STATUS_LOOKUP_SM_CAM_STROBE_TE        (3UL<<16)
            #define RLUP_STATUS_LOOKUP_SM_CAM_WAIT_TE          (4UL<<16)
            #define RLUP_STATUS_LOOKUP_SM_RSS_WAIT_TE          (5UL<<16)
            #define RLUP_STATUS_LOOKUP_SM_FTQ_WR_TE            (6UL<<16)
            #define RLUP_STATUS_LOOKUP_SM_FTQ_POP_TE           (7UL<<16)
        #define RLUP_STATUS_REGCAM_SM_TE                       (0x3UL<<20)
            #define RLUP_STATUS_REGCAM_SM_IDLE_TE              (0UL<<20)
            #define RLUP_STATUS_REGCAM_SM_STROBE_TE            (1UL<<20)
            #define RLUP_STATUS_REGCAM_SM_WAIT_TE              (2UL<<20)
        #define RLUP_STATUS_ACK_SM_TE                          (0x3UL<<24)
            #define RLUP_STATUS_ACK_SM_IDLE_TE                 (0UL<<24)
            #define RLUP_STATUS_ACK_SM_WAIT_TE                 (1UL<<24)
            #define RLUP_STATUS_ACK_SM_STROBE_TE               (2UL<<24)
        #define RLUP_STATUS_LOOKUP_MATCH_STAT_XI               (1UL<<2)
        #define RLUP_STATUS_2TUPLE_LOOKUP_MATCH_STAT_XI        (1UL<<3)
        #define RLUP_STATUS_CAM_FULL_XI                        (1UL<<4)
        #define RLUP_STATUS_DUPLICATE_ENTRY_XI                 (1UL<<5)
        #define RLUP_STATUS_ZERO_CNT_ERR_XI                    (1UL<<6)

    u32_t rlup_ipsrc;
    u32_t rlup_ipdest;
    u32_t rlup_tcpport;
        #define RLUP_TCPPORT_DESTPORT                       (0xffffUL<<0)
        #define RLUP_TCPPORT_SRCPORT                        (0xffffUL<<16)

    u32_t rlup_cid;
        #define RLUP_CID_VALUE                              (0x3fffUL<<7)
        #define RLUP_CID_VALID                              (1UL<<31)

    u32_t rlup_idx;
        #define RLUP_IDX_IDX_VALUE                          (0x3ffUL<<0)

    u32_t rlup_rss_config;
        #define RLUP_RSS_CONFIG_RSS_TE                         (0x3UL<<0)
            #define RLUP_RSS_CONFIG_RSS_OFF_TE                 (0UL<<0)
            #define RLUP_RSS_CONFIG_RSS_ALL_TE                 (1UL<<0)
            #define RLUP_RSS_CONFIG_RSS_IP_ONLY_TE             (2UL<<0)
            #define RLUP_RSS_CONFIG_RSS_RES_TE                 (3UL<<0)
        #define RLUP_RSS_CONFIG_IPV4_RSS_TYPE_XI               (0x3UL<<0)
            #define RLUP_RSS_CONFIG_IPV4_RSS_TYPE_OFF_XI       (0UL<<0)
            #define RLUP_RSS_CONFIG_IPV4_RSS_TYPE_ALL_XI       (1UL<<0)
            #define RLUP_RSS_CONFIG_IPV4_RSS_TYPE_IP_ONLY_XI   (2UL<<0)
            #define RLUP_RSS_CONFIG_IPV4_RSS_TYPE_RES_XI       (3UL<<0)
        #define RLUP_RSS_CONFIG_IPV6_RSS_TYPE_XI               (0x3UL<<2)
            #define RLUP_RSS_CONFIG_IPV6_RSS_TYPE_OFF_XI       (0UL<<2)
            #define RLUP_RSS_CONFIG_IPV6_RSS_TYPE_ALL_XI       (1UL<<2)
            #define RLUP_RSS_CONFIG_IPV6_RSS_TYPE_IP_ONLY_XI   (2UL<<2)
            #define RLUP_RSS_CONFIG_IPV6_RSS_TYPE_RES_XI       (3UL<<2)

    u32_t rlup_rss_key1;
    u32_t rlup_rss_key2;
    u32_t rlup_rss_key3;
    u32_t rlup_rss_key4;
    u32_t rlup_ipv6_rss_key5;
    u32_t rlup_ipv6_rss_key6;
    u32_t rlup_ipv6_rss_key7;
    u32_t rlup_ipv6_rss_key8;
    u32_t rlup_ipv6_rss_key9;
    u32_t rlup_ipv6_rss_key10;
    u32_t rlup_rss_command;
        #define RLUP_RSS_COMMAND_RSS_IND_TABLE_ADDR         (0xfUL<<0)
        #define RLUP_RSS_COMMAND_RSS_WRITE_MASK             (0xffUL<<4)
        #define RLUP_RSS_COMMAND_WRITE                      (1UL<<12)
        #define RLUP_RSS_COMMAND_READ                       (1UL<<13)
        #define RLUP_RSS_COMMAND_HASH_MASK                  (0x7UL<<14)

    u32_t rlup_rss_data;
        #define RLUP_RSS_DATA_RSS_D0                        (0xfUL<<0)
        #define RLUP_RSS_DATA_RSS_D1                        (0xfUL<<4)
        #define RLUP_RSS_DATA_RSS_D2                        (0xfUL<<8)
        #define RLUP_RSS_DATA_RSS_D3                        (0xfUL<<12)
        #define RLUP_RSS_DATA_RSS_D4                        (0xfUL<<16)
        #define RLUP_RSS_DATA_RSS_D5                        (0xfUL<<20)
        #define RLUP_RSS_DATA_RSS_D6                        (0xfUL<<24)
        #define RLUP_RSS_DATA_RSS_D7                        (0xfUL<<28)

    u32_t unused_0[9];
    u32_t rlup_free_count;
        #define RLUP_FREE_COUNT_FREE_COUNT                  (0x7ffUL<<0)

    u32_t rlup_ipv6_src1;
    u32_t rlup_ipv6_src2;
    u32_t rlup_ipv6_src3;
    u32_t rlup_ipv6_src4;
    u32_t rlup_ipv6_dest1;
    u32_t rlup_ipv6_dest2;
    u32_t rlup_ipv6_dest3;
    u32_t rlup_ipv6_dest4;
    u32_t unused_1[154];
    u32_t rlup_cam_bist_command;
        #define RLUP_CAM_BIST_COMMAND_BIST_RST_B            (1UL<<0)
        #define RLUP_CAM_BIST_COMMAND_BIST_EN               (1UL<<1)
        #define RLUP_CAM_BIST_COMMAND_BIST_DONE             (1UL<<2)
        #define RLUP_CAM_BIST_COMMAND_BIST_PASSED           (1UL<<3)

    u32_t rlup_cam_bist_status0;
        #define RLUP_CAM_BIST_STATUS0_MATCH_STATUS          (1UL<<0)
        #define RLUP_CAM_BIST_STATUS0_ACTUAL_BITPOS         (0x7fUL<<1)
        #define RLUP_CAM_BIST_STATUS0_ACTUAL_ADDROUT        (0x3ffUL<<8)

    u32_t rlup_cam_bist_status1;
        #define RLUP_CAM_BIST_STATUS1_MATCH_STATUS          (1UL<<0)
        #define RLUP_CAM_BIST_STATUS1_ADDROUT_STATUS        (1UL<<1)
        #define RLUP_CAM_BIST_STATUS1_ACTUAL_ADDROUT        (0x3ffUL<<2)
        #define RLUP_CAM_BIST_STATUS1_EXPECTED_ADDROUT      (0x3ffUL<<12)

    u32_t rlup_cam_bist_status2;
        #define RLUP_CAM_BIST_STATUS2_MATCH_STATUS          (1UL<<0)
        #define RLUP_CAM_BIST_STATUS2_ACTUAL_BITPOS         (0x7fUL<<1)
        #define RLUP_CAM_BIST_STATUS2_ACTUAL_ADDROUT        (0x3ffUL<<8)

    u32_t rlup_cam_bist_status3;
        #define RLUP_CAM_BIST_STATUS3_MATCH_STATUS          (1UL<<0)
        #define RLUP_CAM_BIST_STATUS3_ADDROUT_STATUS        (1UL<<1)
        #define RLUP_CAM_BIST_STATUS3_ACTUAL_ADDROUT        (0x3ffUL<<2)
        #define RLUP_CAM_BIST_STATUS3_EXPECTED_ADDROUT      (0x3ffUL<<12)

    u32_t rlup_cam_bist_status4;
        #define RLUP_CAM_BIST_STATUS4_MATCH_STATUS          (1UL<<0)
        #define RLUP_CAM_BIST_STATUS4_ACTUAL_ADDROUT        (0x3ffUL<<1)

    u32_t unused_2[10];
    u32_t rlup_debug_vect_peek;
        #define RLUP_DEBUG_VECT_PEEK_1_VALUE                (0x7ffUL<<0)
        #define RLUP_DEBUG_VECT_PEEK_1_PEEK_EN              (1UL<<11)
        #define RLUP_DEBUG_VECT_PEEK_1_SEL                  (0xfUL<<12)
        #define RLUP_DEBUG_VECT_PEEK_2_VALUE                (0x7ffUL<<16)
        #define RLUP_DEBUG_VECT_PEEK_2_PEEK_EN              (1UL<<27)
        #define RLUP_DEBUG_VECT_PEEK_2_SEL                  (0xfUL<<28)

    u32_t unused_3[15];
    rlupq_t rlup_rlupq;
    u32_t rlup_ftq_cmd;
        #define RLUP_FTQ_CMD_OFFSET                         (0x3ffUL<<0)
        #define RLUP_FTQ_CMD_WR_TOP                         (1UL<<10)
            #define RLUP_FTQ_CMD_WR_TOP_0                   (0UL<<10)
            #define RLUP_FTQ_CMD_WR_TOP_1                   (1UL<<10)
        #define RLUP_FTQ_CMD_SFT_RESET                      (1UL<<25)
        #define RLUP_FTQ_CMD_RD_DATA                        (1UL<<26)
        #define RLUP_FTQ_CMD_ADD_INTERVEN                   (1UL<<27)
        #define RLUP_FTQ_CMD_ADD_DATA                       (1UL<<28)
        #define RLUP_FTQ_CMD_INTERVENE_CLR                  (1UL<<29)
        #define RLUP_FTQ_CMD_POP                            (1UL<<30)
        #define RLUP_FTQ_CMD_BUSY                           (1UL<<31)

    u32_t rlup_ftq_ctl;
        #define RLUP_FTQ_CTL_INTERVENE                      (1UL<<0)
        #define RLUP_FTQ_CTL_OVERFLOW                       (1UL<<1)
        #define RLUP_FTQ_CTL_FORCE_INTERVENE                (1UL<<2)
        #define RLUP_FTQ_CTL_MAX_DEPTH                      (0x3ffUL<<12)
        #define RLUP_FTQ_CTL_CUR_DEPTH                      (0x3ffUL<<22)

} rlup_reg_t;

typedef rlup_reg_t rx_lookup_reg_t;

/*
 *  rx_v2p_mailbox_enqueue definition
 *  offset: 0000
 */
typedef struct rx_v2p_mailbox_enqueue
{
    u32_t rx_v2p_mailbox_enqueue_cid;
        #define RX_V2P_MAILBOX_ENQUEUE_CID_VALUE            (0x3fffUL<<7)

} rx_v2p_mailbox_enqueue_t;


/*
 *  rx_v2p_timeout_enqueue definition
 *  offset: 0000
 */
typedef struct rx_v2p_timeout_enqueue
{
    u32_t rx_v2p_timeout_enqueue_cid;
        #define RX_V2P_TIMEOUT_ENQUEUE_CID_VALUE            (0x3fffUL<<7)

} rx_v2p_timeout_enqueue_t;


/*
 *  rx_v2p_enqueue definition
 *  offset: 0000
 */
typedef struct rx_v2p_enqueue
{
    u32_t rx_v2p_enqueue_cid;
        #define RX_V2P_ENQUEUE_CID_VALUE                    (0x3fffUL<<7)

    u32_t rx_v2p_enqueue_mbuf_cluster;
        #define RX_V2P_ENQUEUE_MBUF_CLUSTER_VALUE           (0x1ffffffUL<<0)

    u32_t rx_v2p_enqueue_wd2;
        #define RX_V2P_ENQUEUE_OPERAND_FLAGS                (0xffff<<16)
        #define RX_V2P_ENQUEUE_KNUM                         (0xff<<8)
        #define RX_V2P_ENQUEUE_OPCODE                       (0xff<<0)

    u32_t rx_v2p_enqueue_wd3;
        #define RX_V2P_ENQUEUE_OPERAND16_0                  (0xffff<<16)
        #define RX_V2P_ENQUEUE_OPERAND16_1                  (0xffff<<0)

    u32_t rx_v2p_enqueue_wd4;
        #define RX_V2P_ENQUEUE_OPERAND16_2                  (0xffff<<16)
        #define RX_V2P_ENQUEUE_OPERAND16_3                  (0xffff<<0)

    u32_t rx_v2p_enqueue_wd5;
        #define RX_V2P_ENQUEUE_OPERAND16_4                  (0xffff<<16)
        #define RX_V2P_ENQUEUE_OPERAND16_5                  (0xffff<<0)

    u32_t rx_v2p_enqueue_wd6;
        #define RX_V2P_ENQUEUE_OPERAND16_6                  (0xffff<<16)
        #define RX_V2P_ENQUEUE_OPERAND16_7                  (0xffff<<0)

    u32_t rx_v2p_enqueue_operand32_0;
    u32_t rx_v2p_enqueue_operand32_1;
    u32_t rx_v2p_enqueue_operand32_2;
    u32_t rx_v2p_enqueue_operand32_3;
    u32_t rx_v2p_enqueue_operand32_4;
    u32_t rx_v2p_enqueue_wd12;
        #define RX_V2P_ENQUEUE_RDMA_ACTION_CS16_VLD         (1<<30)
        #define RX_V2P_ENQUEUE_RDMA_ACTION_NO_SNOOP         (1<<31)
        #define RX_V2P_ENQUEUE_CS16_PKT_LEN_VALUE           (0x7f<<16)
        #define RX_V2P_ENQUEUE_CS16                         (0xffff<<0)

} rx_v2p_enqueue_t;


/*
 *  rv2p_reg definition
 *  offset: 0x2800
 */
typedef struct rv2p_reg
{
    u32_t rv2p_command;
        #define RV2P_COMMAND_ENABLED                        (1UL<<0)
        #define RV2P_COMMAND_PROC1_INTRPT                   (1UL<<1)
        #define RV2P_COMMAND_PROC2_INTRPT                   (1UL<<2)
        #define RV2P_COMMAND_ABORT0                         (1UL<<4)
        #define RV2P_COMMAND_ABORT1                         (1UL<<5)
        #define RV2P_COMMAND_ABORT2                         (1UL<<6)
        #define RV2P_COMMAND_ABORT3                         (1UL<<7)
        #define RV2P_COMMAND_ABORT4                         (1UL<<8)
        #define RV2P_COMMAND_ABORT5                         (1UL<<9)
        #define RV2P_COMMAND_PROC1_RESET                    (1UL<<16)
        #define RV2P_COMMAND_PROC2_RESET                    (1UL<<17)
        #define RV2P_COMMAND_CTXIF_RESET                    (1UL<<18)

    u32_t rv2p_status;
        #define RV2P_STATUS_ALWAYS_0                        (1UL<<0)
        #define RV2P_STATUS_RV2P_GEN_STAT0_CNT              (1UL<<8)
        #define RV2P_STATUS_RV2P_GEN_STAT1_CNT              (1UL<<9)
        #define RV2P_STATUS_RV2P_GEN_STAT2_CNT              (1UL<<10)
        #define RV2P_STATUS_RV2P_GEN_STAT3_CNT              (1UL<<11)
        #define RV2P_STATUS_RV2P_GEN_STAT4_CNT              (1UL<<12)
        #define RV2P_STATUS_RV2P_GEN_STAT5_CNT              (1UL<<13)

    u32_t rv2p_config;
        #define RV2P_CONFIG_STALL_PROC1                     (1UL<<0)
        #define RV2P_CONFIG_STALL_PROC2                     (1UL<<1)
        #define RV2P_CONFIG_PROC1_STALL_ON_ABORT0           (1UL<<8)
        #define RV2P_CONFIG_PROC1_STALL_ON_ABORT1           (1UL<<9)
        #define RV2P_CONFIG_PROC1_STALL_ON_ABORT2           (1UL<<10)
        #define RV2P_CONFIG_PROC1_STALL_ON_ABORT3           (1UL<<11)
        #define RV2P_CONFIG_PROC1_STALL_ON_ABORT4           (1UL<<12)
        #define RV2P_CONFIG_PROC1_STALL_ON_ABORT5           (1UL<<13)
        #define RV2P_CONFIG_PROC2_STALL_ON_ABORT0           (1UL<<16)
        #define RV2P_CONFIG_PROC2_STALL_ON_ABORT1           (1UL<<17)
        #define RV2P_CONFIG_PROC2_STALL_ON_ABORT2           (1UL<<18)
        #define RV2P_CONFIG_PROC2_STALL_ON_ABORT3           (1UL<<19)
        #define RV2P_CONFIG_PROC2_STALL_ON_ABORT4           (1UL<<20)
        #define RV2P_CONFIG_PROC2_STALL_ON_ABORT5           (1UL<<21)
        #define RV2P_CONFIG_PAGE_SIZE                       (0xfUL<<24)
            #define RV2P_CONFIG_PAGE_SIZE_256               (0UL<<24)
            #define RV2P_CONFIG_PAGE_SIZE_512               (1UL<<24)
            #define RV2P_CONFIG_PAGE_SIZE_1K                (2UL<<24)
            #define RV2P_CONFIG_PAGE_SIZE_2K                (3UL<<24)
            #define RV2P_CONFIG_PAGE_SIZE_4K                (4UL<<24)
            #define RV2P_CONFIG_PAGE_SIZE_8K                (5UL<<24)
            #define RV2P_CONFIG_PAGE_SIZE_16K               (6UL<<24)
            #define RV2P_CONFIG_PAGE_SIZE_32K               (7UL<<24)
            #define RV2P_CONFIG_PAGE_SIZE_64K               (8UL<<24)
            #define RV2P_CONFIG_PAGE_SIZE_128K              (9UL<<24)
            #define RV2P_CONFIG_PAGE_SIZE_256K              (10UL<<24)
            #define RV2P_CONFIG_PAGE_SIZE_512K              (11UL<<24)
            #define RV2P_CONFIG_PAGE_SIZE_1M                (12UL<<24)

    u32_t unused_0;
    u32_t rv2p_gen_bfr_addr_0;
        #define RV2P_GEN_BFR_ADDR_0_VALUE                   (0xffffUL<<16)

    u32_t rv2p_gen_bfr_addr_1;
        #define RV2P_GEN_BFR_ADDR_1_VALUE                   (0xffffUL<<16)

    u32_t rv2p_gen_bfr_addr_2;
        #define RV2P_GEN_BFR_ADDR_2_VALUE                   (0xffffUL<<16)

    u32_t rv2p_gen_bfr_addr_3;
        #define RV2P_GEN_BFR_ADDR_3_VALUE                   (0xffffUL<<16)

    u32_t unused_1[4];
    u32_t rv2p_instr_high;
        #define RV2P_INSTR_HIGH_HIGH                        (0x1fUL<<0)

    u32_t rv2p_instr_low;
        #define RV2P_INSTR_LOW_LOW                          (0xffffffffUL<<0)

    u32_t rv2p_proc1_addr_cmd;
        #define RV2P_PROC1_ADDR_CMD_ADD                     (0x3ffUL<<0)
        #define RV2P_PROC1_ADDR_CMD_RDWR                    (1UL<<31)

    u32_t rv2p_proc2_addr_cmd;
        #define RV2P_PROC2_ADDR_CMD_ADD                     (0x3ffUL<<0)
        #define RV2P_PROC2_ADDR_CMD_RDWR                    (1UL<<31)

    u32_t rv2p_proc1_grc_debug;
    u32_t rv2p_proc2_grc_debug;
    u32_t rv2p_grc_proc_debug;
    u32_t rv2p_debug_vect_peek;
        #define RV2P_DEBUG_VECT_PEEK_1_VALUE                (0x7ffUL<<0)
        #define RV2P_DEBUG_VECT_PEEK_1_PEEK_EN              (1UL<<11)
        #define RV2P_DEBUG_VECT_PEEK_1_SEL                  (0xfUL<<12)
        #define RV2P_DEBUG_VECT_PEEK_2_VALUE                (0x7ffUL<<16)
        #define RV2P_DEBUG_VECT_PEEK_2_PEEK_EN              (1UL<<27)
        #define RV2P_DEBUG_VECT_PEEK_2_SEL                  (0xfUL<<28)

    u32_t unused_2[171];
    u32_t rv2p_mpfe_pfe_ctl;
        #define RV2P_MPFE_PFE_CTL_INC_USAGE_CNT             (1UL<<0)
        #define RV2P_MPFE_PFE_CTL_PFE_SIZE                  (0xfUL<<4)
            #define RV2P_MPFE_PFE_CTL_PFE_SIZE_0            (0UL<<4)
            #define RV2P_MPFE_PFE_CTL_PFE_SIZE_1            (1UL<<4)
            #define RV2P_MPFE_PFE_CTL_PFE_SIZE_2            (2UL<<4)
            #define RV2P_MPFE_PFE_CTL_PFE_SIZE_3            (3UL<<4)
            #define RV2P_MPFE_PFE_CTL_PFE_SIZE_4            (4UL<<4)
            #define RV2P_MPFE_PFE_CTL_PFE_SIZE_5            (5UL<<4)
            #define RV2P_MPFE_PFE_CTL_PFE_SIZE_6            (6UL<<4)
            #define RV2P_MPFE_PFE_CTL_PFE_SIZE_7            (7UL<<4)
            #define RV2P_MPFE_PFE_CTL_PFE_SIZE_8            (8UL<<4)
            #define RV2P_MPFE_PFE_CTL_PFE_SIZE_9            (9UL<<4)
            #define RV2P_MPFE_PFE_CTL_PFE_SIZE_10           (10UL<<4)
            #define RV2P_MPFE_PFE_CTL_PFE_SIZE_11           (11UL<<4)
            #define RV2P_MPFE_PFE_CTL_PFE_SIZE_12           (12UL<<4)
            #define RV2P_MPFE_PFE_CTL_PFE_SIZE_13           (13UL<<4)
            #define RV2P_MPFE_PFE_CTL_PFE_SIZE_14           (14UL<<4)
            #define RV2P_MPFE_PFE_CTL_PFE_SIZE_15           (15UL<<4)
        #define RV2P_MPFE_PFE_CTL_PFE_COUNT                 (0xfUL<<12)
        #define RV2P_MPFE_PFE_CTL_OFFSET                    (0x1ffUL<<16)

    u32_t unused_3[16];
    rx_v2p_enqueue_t rv2p_rv2ppq;
    u32_t unused_4;
    u32_t rv2p_pftq_cmd;
        #define RV2P_PFTQ_CMD_OFFSET                        (0x3ffUL<<0)
        #define RV2P_PFTQ_CMD_WR_TOP                        (1UL<<10)
            #define RV2P_PFTQ_CMD_WR_TOP_0                  (0UL<<10)
            #define RV2P_PFTQ_CMD_WR_TOP_1                  (1UL<<10)
        #define RV2P_PFTQ_CMD_SFT_RESET                     (1UL<<25)
        #define RV2P_PFTQ_CMD_RD_DATA                       (1UL<<26)
        #define RV2P_PFTQ_CMD_ADD_INTERVEN                  (1UL<<27)
        #define RV2P_PFTQ_CMD_ADD_DATA                      (1UL<<28)
        #define RV2P_PFTQ_CMD_INTERVENE_CLR                 (1UL<<29)
        #define RV2P_PFTQ_CMD_POP                           (1UL<<30)
        #define RV2P_PFTQ_CMD_BUSY                          (1UL<<31)

    u32_t rv2p_pftq_ctl;
        #define RV2P_PFTQ_CTL_INTERVENE                     (1UL<<0)
        #define RV2P_PFTQ_CTL_OVERFLOW                      (1UL<<1)
        #define RV2P_PFTQ_CTL_FORCE_INTERVENE               (1UL<<2)
        #define RV2P_PFTQ_CTL_MAX_DEPTH                     (0x3ffUL<<12)
        #define RV2P_PFTQ_CTL_CUR_DEPTH                     (0x3ffUL<<22)

    rx_v2p_timeout_enqueue_t rv2p_rv2ptq;
    u32_t unused_5[13];
    u32_t rv2p_tftq_cmd;
        #define RV2P_TFTQ_CMD_OFFSET                        (0x3ffUL<<0)
        #define RV2P_TFTQ_CMD_WR_TOP                        (1UL<<10)
            #define RV2P_TFTQ_CMD_WR_TOP_0                  (0UL<<10)
            #define RV2P_TFTQ_CMD_WR_TOP_1                  (1UL<<10)
        #define RV2P_TFTQ_CMD_SFT_RESET                     (1UL<<25)
        #define RV2P_TFTQ_CMD_RD_DATA                       (1UL<<26)
        #define RV2P_TFTQ_CMD_ADD_INTERVEN                  (1UL<<27)
        #define RV2P_TFTQ_CMD_ADD_DATA                      (1UL<<28)
        #define RV2P_TFTQ_CMD_INTERVENE_CLR                 (1UL<<29)
        #define RV2P_TFTQ_CMD_POP                           (1UL<<30)
        #define RV2P_TFTQ_CMD_BUSY                          (1UL<<31)

    u32_t rv2p_tftq_ctl;
        #define RV2P_TFTQ_CTL_INTERVENE                     (1UL<<0)
        #define RV2P_TFTQ_CTL_OVERFLOW                      (1UL<<1)
        #define RV2P_TFTQ_CTL_FORCE_INTERVENE               (1UL<<2)
        #define RV2P_TFTQ_CTL_MAX_DEPTH                     (0x3ffUL<<12)
        #define RV2P_TFTQ_CTL_CUR_DEPTH                     (0x3ffUL<<22)

    rx_v2p_mailbox_enqueue_t rv2p_rv2pmq;
    u32_t unused_6[13];
    u32_t rv2p_mftq_cmd;
        #define RV2P_MFTQ_CMD_OFFSET                        (0x3ffUL<<0)
        #define RV2P_MFTQ_CMD_WR_TOP                        (1UL<<10)
            #define RV2P_MFTQ_CMD_WR_TOP_0                  (0UL<<10)
            #define RV2P_MFTQ_CMD_WR_TOP_1                  (1UL<<10)
        #define RV2P_MFTQ_CMD_SFT_RESET                     (1UL<<25)
        #define RV2P_MFTQ_CMD_RD_DATA                       (1UL<<26)
        #define RV2P_MFTQ_CMD_ADD_INTERVEN                  (1UL<<27)
        #define RV2P_MFTQ_CMD_ADD_DATA                      (1UL<<28)
        #define RV2P_MFTQ_CMD_INTERVENE_CLR                 (1UL<<29)
        #define RV2P_MFTQ_CMD_POP                           (1UL<<30)
        #define RV2P_MFTQ_CMD_BUSY                          (1UL<<31)

    u32_t rv2p_mftq_ctl;
        #define RV2P_MFTQ_CTL_INTERVENE                     (1UL<<0)
        #define RV2P_MFTQ_CTL_OVERFLOW                      (1UL<<1)
        #define RV2P_MFTQ_CTL_FORCE_INTERVENE               (1UL<<2)
        #define RV2P_MFTQ_CTL_MAX_DEPTH                     (0x3ffUL<<12)
        #define RV2P_MFTQ_CTL_CUR_DEPTH                     (0x3ffUL<<22)

} rv2p_reg_t;

typedef rv2p_reg_t rx_v2p_reg_t;

/*
 *  rx_dma_enqueue definition
 *  offset: 0000
 */
typedef struct rx_dma_enqueue
{
    u32_t rx_dma_enqueue_cid;
        #define RX_DMA_ENQUEUE_CID_VALUE                    (0x3fffUL<<7)

    u32_t rx_dma_enqueue_mbuf_cluster;
        #define RX_DMA_ENQUEUE_MBUF_CLUSTER_VALUE           (0x1ffffffUL<<0)

    u32_t rx_dma_enqueue_wd2;
        #define RX_DMA_ENQUEUE_OPERAND_FLAGS                (0xffff<<16)
        #define RX_DMA_ENQUEUE_KNUM                         (0xff<<8)
        #define RX_DMA_ENQUEUE_OPCODE                       (0xff<<0)

    u32_t rx_dma_enqueue_wd3;
        #define RX_DMA_ENQUEUE_OPERAND16_0                  (0xffff<<16)
        #define RX_DMA_ENQUEUE_OPERAND16_1                  (0xffff<<0)

    u32_t rx_dma_enqueue_wd4;
        #define RX_DMA_ENQUEUE_OPERAND16_2                  (0xffff<<16)
        #define RX_DMA_ENQUEUE_OPERAND16_3                  (0xffff<<0)

    u32_t rx_dma_enqueue_wd5;
        #define RX_DMA_ENQUEUE_OPERAND16_4                  (0xffff<<16)
        #define RX_DMA_ENQUEUE_OPERAND16_5                  (0xffff<<0)

    u32_t rx_dma_enqueue_wd6;
        #define RX_DMA_ENQUEUE_OPERAND16_6                  (0xffff<<16)
        #define RX_DMA_ENQUEUE_OPERAND16_7                  (0xffff<<0)

    u32_t rx_dma_enqueue_operand32_0;
    u32_t rx_dma_enqueue_operand32_1;
    u32_t rx_dma_enqueue_operand32_2;
    u32_t rx_dma_enqueue_operand32_3;
    u32_t rx_dma_enqueue_operand32_4;
    u32_t rx_dma_enqueue_wd12;
        #define RX_DMA_ENQUEUE_RDMA_ACTION_DO_DMA           (1<<24)
        #define RX_DMA_ENQUEUE_RDMA_ACTION_PREPEND_L2_FRAME_HDR  (1<<25)
        #define RX_DMA_ENQUEUE_RDMA_ACTION_CRC_ENABLE       (1<<26)
        #define RX_DMA_ENQUEUE_RDMA_ACTION_CRC_USE_CTX_SEED  (1<<27)
        #define RX_DMA_ENQUEUE_RDMA_ACTION_CS16_FIRST       (1<<28)
        #define RX_DMA_ENQUEUE_RDMA_ACTION_CS16_LAST        (1<<29)
        #define RX_DMA_ENQUEUE_RDMA_ACTION_CS16_VLD         (1<<30)
        #define RX_DMA_ENQUEUE_RDMA_ACTION_NO_SNOOP         (1<<31)
        #define RX_DMA_ENQUEUE_CS16_PKT_LEN_VALUE           (0x7f<<16)
        #define RX_DMA_ENQUEUE_CS16                         (0xffff<<0)

} rx_dma_enqueue_t;


/*
 *  rdma_reg definition
 *  offset: 0x2c00
 */
typedef struct rdma_reg
{
    u32_t rdma_command;
        #define RDMA_COMMAND_ENABLED                        (1UL<<0)
        #define RDMA_COMMAND_MASTER_ABORT                   (1UL<<4)

    u32_t rdma_status;
        #define RDMA_STATUS_DMA_WAIT                        (1UL<<0)
        #define RDMA_STATUS_MBUF_WAIT                       (1UL<<1)
        #define RDMA_STATUS_CMP_FTQ_WAIT                    (1UL<<2)
        #define RDMA_STATUS_DMA_CNT_STAT                    (1UL<<16)
        #define RDMA_STATUS_BURST_CNT_STAT                  (1UL<<17)
        #define RDMA_STATUS_ERR                             (0xffUL<<20)
        #define RDMA_STATUS_CS16_ERR                        (1UL<<31)

    u32_t rdma_config;
        #define RDMA_CONFIG_MAX_DMAS                        (0x3UL<<0)
        #define RDMA_CONFIG_ONE_RECORD                      (1UL<<2)
        #define RDMA_CONFIG_CACHE_ALIGN_EN                  (1UL<<3)
        #define RDMA_CONFIG_LIMIT_SZ                        (0x7UL<<4)
            #define RDMA_CONFIG_LIMIT_SZ_8                  (0UL<<4)
            #define RDMA_CONFIG_LIMIT_SZ_16                 (1UL<<4)
            #define RDMA_CONFIG_LIMIT_SZ_32                 (2UL<<4)
            #define RDMA_CONFIG_LIMIT_SZ_64                 (3UL<<4)
            #define RDMA_CONFIG_LIMIT_SZ_128                (4UL<<4)
            #define RDMA_CONFIG_LIMIT_SZ_256                (5UL<<4)
            #define RDMA_CONFIG_LIMIT_SZ_512                (6UL<<4)
        #define RDMA_CONFIG_LINE_SZ                         (0x7UL<<8)
            #define RDMA_CONFIG_LINE_SZ_8                   (0UL<<8)
            #define RDMA_CONFIG_LINE_SZ_16                  (1UL<<8)
            #define RDMA_CONFIG_LINE_SZ_32                  (2UL<<8)
            #define RDMA_CONFIG_LINE_SZ_64                  (3UL<<8)
            #define RDMA_CONFIG_LINE_SZ_128                 (4UL<<8)
            #define RDMA_CONFIG_LINE_SZ_256                 (5UL<<8)
            #define RDMA_CONFIG_LINE_SZ_512                 (6UL<<8)
        #define RDMA_CONFIG_DI_DISABLE                      (1UL<<12)
        #define RDMA_CONFIG_CTXCACHE_DISABLE                (1UL<<16)
        #define RDMA_CONFIG_CRC_OFFSET                      (0x3ffUL<<18)
        #define RDMA_CONFIG_DMA_BREAKUP                     (0x3UL<<28)
            #define RDMA_CONFIG_DMA_BREAKUP_00              (0UL<<28)
            #define RDMA_CONFIG_DMA_BREAKUP_01              (1UL<<28)
            #define RDMA_CONFIG_DMA_BREAKUP_10              (2UL<<28)
            #define RDMA_CONFIG_DMA_BREAKUP_11              (3UL<<28)
        #define RDMA_CONFIG_DMA_BREAK_OVERRIDE              (1UL<<31)

    u32_t rdma_debug_vect_peek;
        #define RDMA_DEBUG_VECT_PEEK_1_VALUE                (0x7ffUL<<0)
        #define RDMA_DEBUG_VECT_PEEK_1_PEEK_EN              (1UL<<11)
        #define RDMA_DEBUG_VECT_PEEK_1_SEL                  (0xfUL<<12)
        #define RDMA_DEBUG_VECT_PEEK_2_VALUE                (0x7ffUL<<16)
        #define RDMA_DEBUG_VECT_PEEK_2_PEEK_EN              (1UL<<27)
        #define RDMA_DEBUG_VECT_PEEK_2_SEL                  (0xfUL<<28)

    u32_t rdma_cksum_error_status;
        #define RDMA_CKSUM_ERROR_STATUS_CALCULATED          (0xffffUL<<0)
        #define RDMA_CKSUM_ERROR_STATUS_EXPECTED            (0xffffUL<<16)

    u32_t unused_0[235];
    rx_dma_enqueue_t rdma_rdmaq;
    u32_t unused_1;
    u32_t rdma_ftq_cmd;
        #define RDMA_FTQ_CMD_OFFSET                         (0x3ffUL<<0)
        #define RDMA_FTQ_CMD_WR_TOP                         (1UL<<10)
            #define RDMA_FTQ_CMD_WR_TOP_0                   (0UL<<10)
            #define RDMA_FTQ_CMD_WR_TOP_1                   (1UL<<10)
        #define RDMA_FTQ_CMD_SFT_RESET                      (1UL<<25)
        #define RDMA_FTQ_CMD_RD_DATA                        (1UL<<26)
        #define RDMA_FTQ_CMD_ADD_INTERVEN                   (1UL<<27)
        #define RDMA_FTQ_CMD_ADD_DATA                       (1UL<<28)
        #define RDMA_FTQ_CMD_INTERVENE_CLR                  (1UL<<29)
        #define RDMA_FTQ_CMD_POP                            (1UL<<30)
        #define RDMA_FTQ_CMD_BUSY                           (1UL<<31)

    u32_t rdma_ftq_ctl;
        #define RDMA_FTQ_CTL_INTERVENE                      (1UL<<0)
        #define RDMA_FTQ_CTL_OVERFLOW                       (1UL<<1)
        #define RDMA_FTQ_CTL_FORCE_INTERVENE                (1UL<<2)
        #define RDMA_FTQ_CTL_MAX_DEPTH                      (0x3ffUL<<12)
        #define RDMA_FTQ_CTL_CUR_DEPTH                      (0x3ffUL<<22)

} rdma_reg_t;

typedef rdma_reg_t rx_dma_reg_t;

/*
 *  rbdc_reg definition
 *  offset: 0x3000
 */
typedef struct rbdc_reg
{
    u32_t rbdc_command;
        #define RBDC_COMMAND_ENABLED                        (1UL<<0)
        #define RBDC_COMMAND_FLUSH                          (1UL<<1)
        #define RBDC_COMMAND_SOFT_RST                       (1UL<<2)
        #define RBDC_COMMAND_REG_ARB                        (1UL<<3)
        #define RBDC_COMMAND_MASTER_ABORT                   (1UL<<4)

    u32_t rbdc_status;
        #define RBDC_STATUS_LOCKED_CNT                      (0xffUL<<0)
        #define RBDC_STATUS_DMA_WAIT_COMP                   (1UL<<8)
        #define RBDC_STATUS_DMA_WAIT_ALLOC                  (1UL<<9)
        #define RBDC_STATUS_DMA_WAIT_FREE                   (1UL<<10)
        #define RBDC_STATUS_ZLD1                            (1UL<<11)
        #define RBDC_STATUS_ZLD2                            (1UL<<12)
        #define RBDC_STATUS_BURST_CNT                       (1UL<<20)
        #define RBDC_STATUS_PROC1_MISS_CNT                  (1UL<<21)
        #define RBDC_STATUS_PROC2_MISS_CNT                  (1UL<<22)

    u32_t rbdc_control;
        #define RBDC_CONTROL_SWAP_MODE                      (1UL<<0)
        #define RBDC_CONTROL_PRIORITY                       (1UL<<1)
        //  This bit forces RBDC to run in a single channel mode, in other words
        //  it will only have outstanding DMA read request. This bit is 
        //  available starting from Xinan 65nm.  
        #define RBDC_CONTROL_ONE_CHNL                       (1UL<<4)
        // The bit forces RBDC to limit the DMA requests to 64bytes at a time. 
        // This bit is available starting from Xinan 65nm.  
        #define REQ64_MODE                                  (1UL<<5)
    u32_t rbdc_bd_haddr_hi;
    u32_t rbdc_bd_haddr_lo;
    u32_t rbdc_bd_len;
        #define RBDC_BD_UNUSED_UNUSED                       (0xffffUL<<0)

    u32_t unused_0;
    u32_t rbdc_bd_flags;
        #define RBDC_BD_FLAGS_FLAGS                         (0xffffUL<<0)

    u32_t rbdc_add;
        #define RBDC_ADD_ADD                                (0x1ffUL<<0)

    u32_t rbdc_bdidx;
        #define RBDC_BDIDX_BDIDX                            (0xffffUL<<0)

    u32_t rbdc_cid;
        #define RBDC_CID_CID                                (0x3fffUL<<7)

    u32_t rbdc_flength;
        #define RBDC_FLENGTH_FLENGTH                        (0x1fUL<<0)

    u32_t rbdc_opcode;
        #define RBDC_OPCODE_OPCODE                          (0xfUL<<0)
        #define RBDC_OPCODE_BDPT_B                          (1UL<<4)

    u32_t rbdc_haddr_hi;
    u32_t rbdc_haddr_lo;
    u32_t rbdc_fillhi;
        #define RBDC_FILLHI_FILLHI                          (0xfUL<<0)

    u32_t rbdc_filllo;
        #define RBDC_FILLLO_FILLLO                          (0xfUL<<0)

    u32_t rbdc_validhi;
        #define RBDC_VALIDHI_VALIDHI                        (0xfUL<<0)

    u32_t rbdc_validlo;
        #define RBDC_VALIDLO_VALIDLO                        (0xfUL<<0)

    u32_t rbdc_lockcount;
        #define RBDC_LOCKCOUNT_LOCKCOUNT                    (0x3UL<<0)

    u32_t rbdc_valid;
        #define RBDC_VALID_VALID                            (1UL<<0)

    u32_t rbdc_debug_vect_peek;
        #define RBDC_DEBUG_VECT_PEEK_1_VALUE                (0x7ffUL<<0)
        #define RBDC_DEBUG_VECT_PEEK_1_PEEK_EN              (1UL<<11)
        #define RBDC_DEBUG_VECT_PEEK_1_SEL                  (0xfUL<<12)
        #define RBDC_DEBUG_VECT_PEEK_2_VALUE                (0x7ffUL<<16)
        #define RBDC_DEBUG_VECT_PEEK_2_PEEK_EN              (1UL<<27)
        #define RBDC_DEBUG_VECT_PEEK_2_SEL                  (0xfUL<<28)

    u32_t rbdc_cksum_error_status;
        #define RBDC_CKSUM_ERROR_STATUS_CALCULATED          (0xffffUL<<0)
        #define RBDC_CKSUM_ERROR_STATUS_EXPECTED            (0xffffUL<<16)

    u32_t unused_1[233];
} rbdc_reg_t;

typedef rbdc_reg_t rx_bd_cache_reg_t;

/*
 *  rbuf_reg definition
 *  offset: 0x200000
 */
typedef struct rbuf_reg
{
    u32_t rbuf_command;
        #define RBUF_COMMAND_ENABLED                        (1UL<<0)
        #define RBUF_COMMAND_FREE_INIT                      (1UL<<1)
        #define RBUF_COMMAND_RAM_INIT                       (1UL<<2)
        #define RBUF_COMMAND_PKT_OFFSET_OVFL                (1UL<<3)
        #define RBUF_COMMAND_OVER_FREE                      (1UL<<4)
        #define RBUF_COMMAND_ALLOC_REQ_TE                      (1UL<<5)
        #define RBUF_COMMAND_EN_PRI_CHNGE_TE                   (1UL<<6)
        #define RBUF_COMMAND_CU_ISOLATE_XI                     (1UL<<5)
        #define RBUF_COMMAND_EN_PRI_CHANGE_XI                  (1UL<<6)
        #define RBUF_COMMAND_GRC_ENDIAN_CONV_DIS_XI            (1UL<<7)

    u32_t rbuf_status1;
        #define RBUF_STATUS1_FREE_COUNT                     (0x3ffUL<<0)

    u32_t rbuf_status2;
        #define RBUF_STATUS2_FREE_TAIL                      (0x1ffUL<<0)
        #define RBUF_STATUS2_FREE_HEAD                      (0x1ffUL<<16)

    u32_t rbuf_config;
        #define RBUF_CONFIG_XOFF_TRIP                       (0x3ffUL<<0)
        #define RBUF_CONFIG_XON_TRIP                        (0x3ffUL<<16)

    u32_t rbuf_fw_buf_alloc;
        #define RBUF_FW_BUF_ALLOC_VALUE                     (0x1ffUL<<7)
        #define RBUF_FW_BUF_ALLOC_TYPE                      (1UL<<16)
        #define RBUF_FW_BUF_ALLOC_ALLOC_REQ                 (1UL<<31)

    u32_t rbuf_fw_buf_free;
        #define RBUF_FW_BUF_FREE_COUNT                      (0x7fUL<<0)
        #define RBUF_FW_BUF_FREE_TAIL                       (0x1ffUL<<7)
        #define RBUF_FW_BUF_FREE_HEAD                       (0x1ffUL<<16)
        #define RBUF_FW_BUF_FREE_TYPE                       (1UL<<25)
        #define RBUF_FW_BUF_FREE_FREE_REQ                   (1UL<<31)

    u32_t rbuf_fw_buf_sel;
        #define RBUF_FW_BUF_SEL_COUNT                       (0x7fUL<<0)
        #define RBUF_FW_BUF_SEL_TAIL                        (0x1ffUL<<7)
        #define RBUF_FW_BUF_SEL_HEAD                        (0x1ffUL<<16)
        #define RBUF_FW_BUF_SEL_SEL_REQ                     (1UL<<31)

    u32_t rbuf_config2;
        #define RBUF_CONFIG2_MAC_DROP_TRIP                  (0x3ffUL<<0)
        #define RBUF_CONFIG2_MAC_KEEP_TRIP                  (0x3ffUL<<16)

    u32_t rbuf_config3;
        #define RBUF_CONFIG3_CU_DROP_TRIP                   (0x3ffUL<<0)
        #define RBUF_CONFIG3_CU_KEEP_TRIP                   (0x3ffUL<<16)

    u32_t rbuf_mbuf_count;
        #define RBUF_MBUF_COUNT_OCCUPIED_COUNT              (0x3ffUL<<0)
        #define RBUF_MBUF_COUNT_MAX_COUNT                   (0x3ffUL<<16)
        #define RBUF_MBUF_COUNT_CLR                         (1UL<<31)

    u32_t rbuf_cu_mbuf_count;
        #define RBUF_CU_MBUF_COUNT_OCCUPIED_COUNT           (0x3ffUL<<0)
        #define RBUF_CU_MBUF_COUNT_MAX_COUNT                (0x3ffUL<<16)
        #define RBUF_CU_MBUF_COUNT_CLR                      (1UL<<31)

    u32_t rbuf_cu_buffer_size;
        #define RBUF_CU_BUFFER_SIZE_CU_BUFFER_SIZE          (0x3ffUL<<0)

    u32_t rbuf_cu_free_count;
        #define RBUF_CU_FREE_COUNT_CU_FREE_COUNT            (0x3ffUL<<0)

    u32_t unused_0[243];
    u32_t rbuf_bist_cs0;
        #define RBUF_BIST_CS0_MBIST_EN                      (1UL<<0)
        #define RBUF_BIST_CS0_BIST_SETUP                    (0x3UL<<1)
        #define RBUF_BIST_CS0_MBIST_ASYNC_RESET             (1UL<<3)
        #define RBUF_BIST_CS0_MBIST_DONE                    (1UL<<8)
        #define RBUF_BIST_CS0_MBIST_GO                      (1UL<<9)

    u32_t rbuf_bist_memstatus0;
    u32_t rbuf_bist_cs1;
        #define RBUF_BIST_CS1_MBIST_EN                      (1UL<<0)
        #define RBUF_BIST_CS1_BIST_SETUP                    (0x3UL<<1)
        #define RBUF_BIST_CS1_MBIST_ASYNC_RESET             (1UL<<3)
        #define RBUF_BIST_CS1_MBIST_DONE                    (1UL<<8)
        #define RBUF_BIST_CS1_MBIST_GO                      (1UL<<9)

    u32_t rbuf_bist_memstatus1;
    u32_t rbuf_bist_cs2;
        #define RBUF_BIST_CS2_MBIST_EN                      (1UL<<0)
        #define RBUF_BIST_CS2_BIST_SETUP                    (0x3UL<<1)
        #define RBUF_BIST_CS2_MBIST_ASYNC_RESET             (1UL<<3)
        #define RBUF_BIST_CS2_MBIST_DONE                    (1UL<<8)
        #define RBUF_BIST_CS2_MBIST_GO                      (1UL<<9)

    u32_t rbuf_bist_memstatus2;
    u32_t rbuf_bist_cs3;
        #define RBUF_BIST_CS3_MBIST_EN                      (1UL<<0)
        #define RBUF_BIST_CS3_BIST_SETUP                    (0x3UL<<1)
        #define RBUF_BIST_CS3_MBIST_ASYNC_RESET             (1UL<<3)
        #define RBUF_BIST_CS3_MBIST_DONE                    (1UL<<8)
        #define RBUF_BIST_CS3_MBIST_GO                      (1UL<<9)

    u32_t rbuf_bist_memstatus3;
    u32_t rbuf_bist_cs4;
        #define RBUF_BIST_CS4_MBIST_EN                      (1UL<<0)
        #define RBUF_BIST_CS4_BIST_SETUP                    (0x3UL<<1)
        #define RBUF_BIST_CS4_MBIST_ASYNC_RESET             (1UL<<3)
        #define RBUF_BIST_CS4_MBIST_DONE                    (1UL<<8)
        #define RBUF_BIST_CS4_MBIST_GO                      (1UL<<9)

    u32_t rbuf_bist_memstatus4;
    u32_t rbuf_bist_cs5;
        #define RBUF_BIST_CS5_MBIST_EN                      (1UL<<0)
        #define RBUF_BIST_CS5_BIST_SETUP                    (0x3UL<<1)
        #define RBUF_BIST_CS5_MBIST_ASYNC_RESET             (1UL<<3)
        #define RBUF_BIST_CS5_MBIST_DONE                    (1UL<<8)
        #define RBUF_BIST_CS5_MBIST_GO                      (1UL<<9)

    u32_t rbuf_bist_memstatus5;
    u32_t rbuf_bist_cs6;
        #define RBUF_BIST_CS6_MBIST_EN                      (1UL<<0)
        #define RBUF_BIST_CS6_BIST_SETUP                    (0x3UL<<1)
        #define RBUF_BIST_CS6_MBIST_ASYNC_RESET             (1UL<<3)
        #define RBUF_BIST_CS6_MBIST_DONE                    (1UL<<8)
        #define RBUF_BIST_CS6_MBIST_GO                      (1UL<<9)

    u32_t rbuf_bist_memstatus6;
    u32_t rbuf_bist_cs7;
        #define RBUF_BIST_CS7_MBIST_EN                      (1UL<<0)
        #define RBUF_BIST_CS7_BIST_SETUP                    (0x3UL<<1)
        #define RBUF_BIST_CS7_MBIST_ASYNC_RESET             (1UL<<3)
        #define RBUF_BIST_CS7_MBIST_DONE                    (1UL<<8)
        #define RBUF_BIST_CS7_MBIST_GO                      (1UL<<9)

    u32_t rbuf_bist_memstatus7;
    u32_t rbuf_mem_tm0;
        #define RBUF_MEM_TM0_CTX_USAGE_CNT_TMB              (0x3UL<<0)
        #define RBUF_MEM_TM0_CTX_USAGE_CNT_TMA              (0x3UL<<2)
        #define RBUF_MEM_TM0_CTX_PAGE_TABLE_TM              (0xfUL<<4)
        #define RBUF_MEM_TM0_CTX_CACHE_TM                   (0xfUL<<8)
        #define RBUF_MEM_TM0_CTX_CAM_TM                     (0x7ffUL<<12)

    u32_t rbuf_mem_tm1;
        #define RBUF_MEM_TM1_CTX_CAM_MIRROR_TM              (0xfUL<<0)
        #define RBUF_MEM_TM1_RXPQ_TM                        (0xffUL<<8)
        #define RBUF_MEM_TM1_THBUF_DATAMEM_TM               (0xffUL<<16)
        #define RBUF_MEM_TM1_TSCH_CONN_LIST_TM              (0xfUL<<24)
        #define RBUF_MEM_TM1_MQ_IDX_STOR_TM                 (0xfUL<<28)

    u32_t rbuf_mem_tm2;
        #define RBUF_MEM_TM2_RV2P_PROC2_TM                  (0xfUL<<0)
        #define RBUF_MEM_TM2_CS_TMEM_TM                     (0xfUL<<4)
        #define RBUF_MEM_TM2_RV2PCS_TMEM_TM                 (0xfUL<<8)
        #define RBUF_MEM_TM2_CP_SCPAD_TM                    (0xfUL<<12)
        #define RBUF_MEM_TM2_RLUP_CAM_TM                    (0x7ffUL<<16)

    u32_t rbuf_mem_tm3;
        #define RBUF_MEM_TM3_RX_BDCACHE_TM                  (0xffUL<<0)
        #define RBUF_MEM_TM3_TX_BDCACHE_TM                  (0xffUL<<8)
        #define RBUF_MEM_TM3_RLUP_CID_TM                    (0xfUL<<16)
        #define RBUF_MEM_TM3_RV2P_PROC1_TM                  (0xfUL<<24)

    u32_t rbuf_mem_tm4;
        #define RBUF_MEM_TM4_COM_CP_CACHE_TM                (0xfUL<<0)
        #define RBUF_MEM_TM4_TPAT_SCPAD_TM                  (0xfUL<<8)
        #define RBUF_MEM_TM4_TXP_SCPAD_TM                   (0xfUL<<16)
        #define RBUF_MEM_TM4_RXP_SCPAD_TM                   (0xfUL<<24)

    u32_t rbuf_mem_tm5;
        #define RBUF_MEM_TM5_TPBUF_DATAMEM_TM               (0xffUL<<0)
        #define RBUF_MEM_TM5_RBUF_DATAMEM_TM                (0xffUL<<8)
        #define RBUF_MEM_TM5_RBUF_PTRMEM_TMA                (0x3UL<<16)
        #define RBUF_MEM_TM5_RBUF_PTRMEM_TMB                (0x3UL<<24)

    u32_t rbuf_mem_65_tm0;
        #define RBUF_MEM_65_TM0_CTX_USAGE_CNT_TMB           (0xfUL<<0)
        #define RBUF_MEM_65_TM0_CTX_PAGE_TABLE_TM           (0xfUL<<4)
        #define RBUF_MEM_65_TM0_CTX_CACHE_TM                (0xfUL<<8)
        #define RBUF_MEM_65_TM0_CTX_CAM_TM                  (0x7ffUL<<12)
        #define RBUF_MEM_65_TM0_CTX_USAGE_CNT_TMA           (0xfUL<<28)

    u32_t rbuf_mem_65_tm1;
        #define RBUF_MEM_65_TM1_CTX_CAM_MIRROR_TM           (0xfUL<<0)
        #define RBUF_MEM_65_TM1_RXPQ_TM                     (0xffUL<<8)
        #define RBUF_MEM_65_TM1_THBUF_DATAMEM_TM            (0xffUL<<16)
        #define RBUF_MEM_65_TM1_TSCH_CONN_LIST_TM           (0xfUL<<24)
        #define RBUF_MEM_65_TM1_MQ_IDX_STOR_TM              (0xfUL<<28)

    u32_t rbuf_mem_65_tm2;
        #define RBUF_MEM_65_TM2_RV2P_PROC2_TM               (0xfUL<<0)
        #define RBUF_MEM_65_TM2_CS_TMEM_TM                  (0xfUL<<4)
        #define RBUF_MEM_65_TM2_RV2PCS_TMEM_TM              (0xfUL<<8)
        #define RBUF_MEM_65_TM2_CP_SCPAD_TM                 (0xfUL<<12)
        #define RBUF_MEM_65_TM2_RLUB_CAM_TM                 (0x7ffUL<<16)
        #define RBUF_MEM_65_TM2_TDMA_IFIFO_TMB              (0x3UL<<28)
        #define RBUF_MEM_65_TM2_TDMA_IFIFO_TMA              (0x3UL<<30)

    u32_t rbuf_mem_65_tm3;
        #define RBUF_MEM_65_TM3_RX_BDCACHE_TM               (0xffUL<<0)
        #define RBUF_MEM_65_TM3_TX_BDCACHE_TM               (0xffUL<<8)
        #define RBUF_MEM_65_TM3_RLUP_CID_TM                 (0xfUL<<16)
        #define RBUF_MEM_65_TM3_RV2P_PROC1_TM               (0xfUL<<24)
        #define RBUF_MEM_65_TM3_RDMA_DFIFO_TM               (0x3UL<<28)
        #define RBUF_MEM_65_TM3_MQ_FIFO_TM                  (0x3UL<<30)

    u32_t rbuf_mem_65_tm4;
        #define RBUF_MEM_65_TM4_TPAT_SCPAD_TM               (0xfUL<<8)
        #define RBUF_MEM_65_TM4_COM_SCPAD_TM                (0xfUL<<8)
        #define RBUF_MEM_65_TM4_CTX_CP_BURST_BUFS_TM        (0x3UL<<14)
        #define RBUF_MEM_65_TM4_TXP_SCPAD_TM                (0xfUL<<16)
        #define RBUF_MEM_65_TM4_CTX_TXP_BURST_BUFS_TM       (0x3UL<<22)
        #define RBUF_MEM_65_TM4_RXP_SCPAD_TM                (0xfUL<<24)
        #define RBUF_MEM_65_TM4_CTX_RXP_BURST_BUFS_TM       (0x3UL<<30)

    u32_t rbuf_mem_65_tm5;
        #define RBUF_MEM_65_TM5_TPBUF_DATAMEM_TM            (0xffUL<<0)
        #define RBUF_MEM_65_TM5_RBUF_DATAMEM_TM             (0xffUL<<8)
        #define RBUF_MEM_65_TM5_RBUF_PTRMEM_TMA             (0xfUL<<16)
        #define RBUF_MEM_65_TM5_DMAE_COM_CACHE_TM           (0x3UL<<22)
        #define RBUF_MEM_65_TM5_RBUF_PTRMEM_TMB             (0xfUL<<24)
        #define RBUF_MEM_65_TM5_DMAE_CP_CACHE_TM            (0x3UL<<30)

    u32_t rbuf_weak_wr_cmdstat;
        #define RBUF_WEAK_WR_CMDSTAT_WW_MODE                (1UL<<0)
        #define RBUF_WEAK_WR_CMDSTAT_WW_START               (1UL<<1)
        #define RBUF_WEAK_WR_CMDSTAT_WW_DONE                (1UL<<2)
        #define RBUF_WEAK_WR_CMDSTAT_RBUF_DATAMEM_FAIL_FLAG  (1UL<<4)
        #define RBUF_WEAK_WR_CMDSTAT_TPBUF_DATAMEM_FAIL_FLAG  (1UL<<5)
        #define RBUF_WEAK_WR_CMDSTAT_RBUF_PTMEM_FAIL_FLAG   (1UL<<6)
        #define RBUF_WEAK_WR_CMDSTAT_RXP_SCPAD_FAIL_FLAG    (1UL<<7)
        #define RBUF_WEAK_WR_CMDSTAT_TPAT_SCPAD_FAIL_FLAG   (1UL<<8)
        #define RBUF_WEAK_WR_CMDSTAT_CTX_USAGE_CNT_FAIL_FLAG  (1UL<<9)
        #define RBUF_WEAK_WR_CMDSTAT_CTX_PAGE_TABLE_FAIL_FLAG  (1UL<<10)
        #define RBUF_WEAK_WR_CMDSTAT_CTX_CACHE_FAIL_FLAG    (1UL<<11)
        #define RBUF_WEAK_WR_CMDSTAT_CS_TMEM_1_FAIL_FLAG    (1UL<<12)
        #define RBUF_WEAK_WR_CMDSTAT_RLUP_CID_RAM_FAIL_FLAG  (1UL<<13)
        #define RBUF_WEAK_WR_CMDSTAT_RV2P_PROC2_FAIL_FLAG   (1UL<<14)
        #define RBUF_WEAK_WR_CMDSTAT_RV2P_PROC1_FAIL_FLAG   (1UL<<15)
        #define RBUF_WEAK_WR_CMDSTAT_TSCH_CONN_LIST_FAIL_FLAG  (1UL<<16)
        #define RBUF_WEAK_WR_CMDSTAT_RX_BDCACHE_FAIL_FLAG   (1UL<<17)
        #define RBUF_WEAK_WR_CMDSTAT_THBUF_DATAMEM_FAIL_FLAG  (1UL<<18)
        #define RBUF_WEAK_WR_CMDSTAT_CS_TMEM_2_FAIL_FLAG    (1UL<<19)
        #define RBUF_WEAK_WR_CMDSTAT_MQ_INDEX_STORAGE_FAIL_FLAG  (1UL<<20)
        #define RBUF_WEAK_WR_CMDSTAT_RXPQ_1_FAIL_FLAG       (1UL<<21)
        #define RBUF_WEAK_WR_CMDSTAT_RXPQ_2_FAIL_FLAG       (1UL<<22)
        #define RBUF_WEAK_WR_CMDSTAT_TX_BDCACHE_FAIL_FLAG   (1UL<<23)
        #define RBUF_WEAK_WR_CMDSTAT_COM_SCPAD_FAIL_FLAG    (1UL<<24)
        #define RBUF_WEAK_WR_CMDSTAT_CP_SCPAD_FAIL_FLAG     (1UL<<25)
        #define RBUF_WEAK_WR_CMDSTAT_CTX_CAM_MIRROR_FAIL_FLAG  (1UL<<26)
        #define RBUF_WEAK_WR_CMDSTAT_TXP_SCPAD_FAIL_FLAG    (1UL<<27)

    u32_t unused_1[7907];
    u32_t rbuf_pkt_data[2250];
    u32_t unused_2[5942];
    u32_t rbuf_clist_data[512];
    u32_t unused_3[15872];
    u32_t rbuf_buf_data[16384];
    u32_t unused_4[16384];
} rbuf_reg_t;

typedef rbuf_reg_t rx_mbuf_reg_t;

/*
 *  idb_state_val definition
 *  offset: 0000
 */
typedef struct idb_state_val
{
    u32_t idb_state_val_val;
        #define IDB_STATE_VAL_VAL_STATE                     (0x7UL<<0)
            #define IDB_STATE_VAL_VAL_STATE_IDLE            (0UL<<0)
            #define IDB_STATE_VAL_VAL_STATE_FILLING         (1UL<<0)
            #define IDB_STATE_VAL_VAL_STATE_TRIGGERED       (2UL<<0)
            #define IDB_STATE_VAL_VAL_STATE_FULL            (3UL<<0)
            #define IDB_STATE_VAL_VAL_STATE_OUTWAIT         (4UL<<0)
        #define IDB_STATE_VAL_VAL_CID                       (0x3fffUL<<7)

} idb_state_val_t;


/*
 *  mq_reg definition
 *  offset: 0x3c00
 */
typedef struct mq_reg
{
    u32_t mq_command;
        #define MQ_COMMAND_ENABLED                          (1UL<<0)
        #define MQ_COMMAND_INIT                             (1UL<<1)
        #define MQ_COMMAND_OVERFLOW                         (1UL<<4)
        #define MQ_COMMAND_WR_ERROR                         (1UL<<5)
        #define MQ_COMMAND_RD_ERROR                         (1UL<<6)
        #define MQ_COMMAND_IDB_CFG_ERROR                    (1UL<<7)
        #define MQ_COMMAND_IDB_OVERFLOW                     (1UL<<10)
        #define MQ_COMMAND_NO_BIN_ERROR                     (1UL<<11)
        #define MQ_COMMAND_NO_MAP_ERROR                     (1UL<<12)

    u32_t mq_status;
        #define MQ_STATUS_CTX_ACCESS_STAT                   (1UL<<16)
        #define MQ_STATUS_CTX_ACCESS64_STAT                 (1UL<<17)
        #define MQ_STATUS_PCI_STALL_STAT                    (1UL<<18)
        #define MQ_STATUS_IDB_OFLOW_STAT                    (1UL<<19)

    u32_t mq_config;
        #define MQ_CONFIG_TX_HIGH_PRI                       (1UL<<0)
        #define MQ_CONFIG_HALT_DIS                          (1UL<<1)
        #define MQ_CONFIG_BIN_MQ_MODE                       (1UL<<2)
        #define MQ_CONFIG_DIS_IDB_DROP                      (1UL<<3)
        #define MQ_CONFIG_KNL_BYP_BLK_SIZE                  (0x7UL<<4)
            #define MQ_CONFIG_KNL_BYP_BLK_SIZE_256          (0UL<<4)
            #define MQ_CONFIG_KNL_BYP_BLK_SIZE_512          (1UL<<4)
            #define MQ_CONFIG_KNL_BYP_BLK_SIZE_1K           (2UL<<4)
            #define MQ_CONFIG_KNL_BYP_BLK_SIZE_2K           (3UL<<4)
            #define MQ_CONFIG_KNL_BYP_BLK_SIZE_4K           (4UL<<4)
        #define MQ_CONFIG_MAX_DEPTH                         (0x7fUL<<8)
        #define MQ_CONFIG_CUR_DEPTH                         (0x7fUL<<20)

    u32_t mq_enqueue1;
        #define MQ_ENQUEUE1_OFFSET                          (0x3fUL<<2)
        #define MQ_ENQUEUE1_CID                             (0x3fffUL<<8)
        #define MQ_ENQUEUE1_BYTE_MASK                       (0xfUL<<24)
        #define MQ_ENQUEUE1_KNL_MODE                        (1UL<<28)

    u32_t mq_enqueue2;
    u32_t mq_bad_wr_addr;
    u32_t mq_bad_rd_addr;
    u32_t mq_knl_byp_wind_start;
        #define MQ_KNL_BYP_WIND_START_VALUE                 (0xfffffUL<<12)

    u32_t mq_knl_wind_end;
        #define MQ_KNL_WIND_END_VALUE                       (0xffffffUL<<8)

    u32_t mq_knl_write_mask1;
    u32_t mq_knl_tx_mask1;
    u32_t mq_knl_cmd_mask1;
    u32_t mq_knl_cond_enqueue_mask1;
    u32_t mq_knl_rx_v2p_mask1;
    u32_t mq_knl_write_mask2;
    u32_t mq_knl_tx_mask2;
    u32_t mq_knl_cmd_mask2;
    u32_t mq_knl_cond_enqueue_mask2;
    u32_t mq_knl_rx_v2p_mask2;
    u32_t mq_knl_byp_write_mask1;
    u32_t mq_knl_byp_tx_mask1;
    u32_t mq_knl_byp_cmd_mask1;
    u32_t mq_knl_byp_cond_enqueue_mask1;
    u32_t mq_knl_byp_rx_v2p_mask1;
    u32_t mq_knl_byp_write_mask2;
    u32_t mq_knl_byp_tx_mask2;
    u32_t mq_knl_byp_cmd_mask2;
    u32_t mq_knl_byp_cond_enqueue_mask2;
    u32_t mq_knl_byp_rx_v2p_mask2;
    u32_t mq_mem_wr_addr;
        #define MQ_MEM_WR_ADDR_VALUE                        (0x3fUL<<0)

    u32_t mq_mem_wr_data0;
        #define MQ_MEM_WR_DATA0_VALUE                       (0xffffffffUL<<0)

    u32_t mq_mem_wr_data1;
        #define MQ_MEM_WR_DATA1_VALUE                       (0xffffffffUL<<0)

    u32_t mq_mem_wr_data2;
        #define MQ_MEM_WR_DATA2_VALUE_TE                       (0x3fffffffUL<<0)
        #define MQ_MEM_WR_DATA2_VALUE_XI                       (0x7fffffffUL<<0)

    u32_t mq_mem_rd_addr;
        #define MQ_MEM_RD_ADDR_VALUE                        (0x3fUL<<0)

    u32_t mq_mem_rd_data0;
        #define MQ_MEM_RD_DATA0_VALUE                       (0xffffffffUL<<0)

    u32_t mq_mem_rd_data1;
        #define MQ_MEM_RD_DATA1_VALUE                       (0xffffffffUL<<0)

    u32_t mq_mem_rd_data2;
        #define MQ_MEM_RD_DATA2_VALUE_TE                       (0x3fffffffUL<<0)
        #define MQ_MEM_RD_DATA2_VALUE_XI                       (0x7fffffffUL<<0)

    u32_t mq_debug_vect_peek;
        #define MQ_DEBUG_VECT_PEEK_1_VALUE                  (0x7ffUL<<0)
        #define MQ_DEBUG_VECT_PEEK_1_EN                     (1UL<<11)
        #define MQ_DEBUG_VECT_PEEK_1_SEL                    (0xfUL<<12)
        #define MQ_DEBUG_VECT_PEEK_2_VALUE                  (0x7ffUL<<16)
        #define MQ_DEBUG_VECT_PEEK_2_EN                     (1UL<<27)
        #define MQ_DEBUG_VECT_PEEK_2_SEL                    (0xfUL<<28)

    u32_t unused_0[2];
    u32_t mq_idb_cfg;
        #define MQ_IDB_CFG_MB_START                         (0x3UL<<0)
            #define MQ_IDB_CFG_MB_START_256                 (0UL<<0)
            #define MQ_IDB_CFG_MB_START_512                 (1UL<<0)
            #define MQ_IDB_CFG_MB_START_1K                  (2UL<<0)
            #define MQ_IDB_CFG_MB_START_2K                  (3UL<<0)
        #define MQ_IDB_CFG_MB_SIZE                          (0x3UL<<4)
            #define MQ_IDB_CFG_MB_SIZE_256                  (0UL<<4)
            #define MQ_IDB_CFG_MB_SIZE_512                  (1UL<<4)
            #define MQ_IDB_CFG_MB_SIZE_1K                   (2UL<<4)
            #define MQ_IDB_CFG_MB_SIZE_2K                   (3UL<<4)
        #define MQ_IDB_CFG_ADD_BYTE_SWAP                    (1UL<<6)
        #define MQ_IDB_CFG_ADD_WORD_SWAP                    (1UL<<7)
        #define MQ_IDB_CFG_WQE_SIZE                         (0x3UL<<8)
            #define MQ_IDB_CFG_WQE_SIZE_NONE                (0UL<<8)
            #define MQ_IDB_CFG_WQE_SIZE_64B                 (1UL<<8)
            #define MQ_IDB_CFG_WQE_SIZE_128B                (2UL<<8)
        #define MQ_IDB_CFG_CTX_LOC                          (0x7ffUL<<10)
        #define MQ_IDB_CFG_TRIG_LOC                         (0x3fUL<<24)
        #define MQ_IDB_CFG_ENA                              (1UL<<31)

    u32_t mq_idb_free;
        #define MQ_IDB_FREE_CID                             (0x3fffUL<<7)

    u32_t unused_1[2];
    u32_t mq_idb_state0_val;
        #define MQ_IDB_STATE0_VAL_STATE                     (0x7UL<<0)
            #define MQ_IDB_STATE0_VAL_STATE_IDLE            (0UL<<0)
            #define MQ_IDB_STATE0_VAL_STATE_FILLING         (1UL<<0)
            #define MQ_IDB_STATE0_VAL_STATE_TRIGGERED       (2UL<<0)
            #define MQ_IDB_STATE0_VAL_STATE_FULL            (3UL<<0)
            #define MQ_IDB_STATE0_VAL_STATE_OUTWAIT         (4UL<<0)
        #define MQ_IDB_STATE0_VAL_CID                       (0x3fffUL<<7)

    idb_state_val_t mq_idb_state1;
    idb_state_val_t mq_idb_state2;
    idb_state_val_t mq_idb_state3;
    u32_t unused_2[16];
    u32_t mq_config2;
        #define MQ_CONFIG2_CONT_SZ                          (0x7UL<<4)
            #define MQ_CONFIG2_CONT_SZ_4PER                 (2UL<<4)
            #define MQ_CONFIG2_CONT_SZ_6PER                 (3UL<<4)
            #define MQ_CONFIG2_CONT_SZ_8PER                 (4UL<<4)
            #define MQ_CONFIG2_CONT_SZ_10PER                (5UL<<4)
            #define MQ_CONFIG2_CONT_SZ_12PER                (6UL<<4)
            #define MQ_CONFIG2_CONT_SZ_14PER                (7UL<<4)
        #define MQ_CONFIG2_FIRST_L4L5                       (0x1fUL<<8)
        #define MQ_CONFIG2_IDB_DROP_AUTO_RECOV              (1UL<<16)
        #define MQ_CONFIG2_IDB_AUTO_ON                      (0x3UL<<17)
            #define MQ_CONFIG2_IDB_AUTO_ON_32               (0UL<<17)
            #define MQ_CONFIG2_IDB_AUTO_ON_16               (1UL<<17)
            #define MQ_CONFIG2_IDB_AUTO_ON_8                (2UL<<17)
            #define MQ_CONFIG2_IDB_AUTO_ON_4                (3UL<<17)
        #define MQ_CONFIG2_SCNR_CTHRU_DIS                   (1UL<<20)

    u32_t mq_idx_cmd;
        #define MQ_IDX_CMD_RD_CMD                           (1UL<<0)
        #define MQ_IDX_CMD_WR_CMD                           (0x3UL<<1)
            #define MQ_IDX_CMD_WR_CMD_NOTHING               (0UL<<1)
            #define MQ_IDX_CMD_WR_CMD_LOW                   (1UL<<1)
            #define MQ_IDX_CMD_WR_CMD_HIGH                  (2UL<<1)
            #define MQ_IDX_CMD_WR_CMD_BOTH                  (3UL<<1)
        #define MQ_IDX_CMD_SP                               (0x3UL<<4)
        #define MQ_IDX_CMD_BIN_OFFSET                       (0x3UL<<12)
        #define MQ_IDX_CMD_BIN                              (0xfffUL<<16)

    u32_t mq_idx_data;
    u32_t mq_scnr_cmd;
        #define MQ_SCNR_CMD_RD_CMD                          (1UL<<0)
        #define MQ_SCNR_CMD_WR_CMD                          (1UL<<1)
        #define MQ_SCNR_CMD_BIN                             (0xfffUL<<16)

    u32_t mq_scnr_data;
    u32_t unused_3[3];
    u32_t mq_map_l2_0;
        #define MQ_MAP_L2_0_MQ_OFFSET                       (0xffUL<<0)
        #define MQ_MAP_L2_0_SZ                              (0x3UL<<8)
            #define MQ_MAP_L2_0_SZ_8B                       (1UL<<8)
            #define MQ_MAP_L2_0_SZ_16B                      (2UL<<8)
            #define MQ_MAP_L2_0_SZ_32B                      (3UL<<8)
        #define MQ_MAP_L2_0_CTX_OFFSET                      (0x3ffUL<<10)
        #define MQ_MAP_L2_0_BIN_OFFSET                      (0x7UL<<23)
            #define MQ_MAP_L2_0_BIN_OFFSET_0                (0UL<<23)
            #define MQ_MAP_L2_0_BIN_OFFSET_1                (1UL<<23)
            #define MQ_MAP_L2_0_BIN_OFFSET_2                (2UL<<23)
            #define MQ_MAP_L2_0_BIN_OFFSET_4                (4UL<<23)
            #define MQ_MAP_L2_0_BIN_OFFSET_5                (5UL<<23)
            #define MQ_MAP_L2_0_BIN_OFFSET_6                (6UL<<23)
        #define MQ_MAP_L2_0_ARM                             (0x3UL<<26)
            #define MQ_MAP_L2_0_ARM_NONE                    (0UL<<26)
            #define MQ_MAP_L2_0_ARM_TSCH                    (1UL<<26)
            #define MQ_MAP_L2_0_ARM_CS                      (2UL<<26)
            #define MQ_MAP_L2_0_ARM_RV2PCS                  (3UL<<26)
        #define MQ_MAP_L2_0_ENA                             (1UL<<31)

    u32_t mq_map_l2_1;
        #define MQ_MAP_L2_1_MQ_OFFSET                       (0xffUL<<0)
        #define MQ_MAP_L2_1_SZ                              (0x3UL<<8)
        #define MQ_MAP_L2_1_CTX_OFFSET                      (0x3ffUL<<10)
        #define MQ_MAP_L2_1_BIN_OFFSET                      (0x7UL<<23)
        #define MQ_MAP_L2_1_ARM                             (0x3UL<<26)
        #define MQ_MAP_L2_1_ENA                             (1UL<<31)

    u32_t mq_map_l2_2;
        #define MQ_MAP_L2_2_MQ_OFFSET                       (0xffUL<<0)
        #define MQ_MAP_L2_2_SZ                              (0x3UL<<8)
        #define MQ_MAP_L2_2_CTX_OFFSET                      (0x3ffUL<<10)
        #define MQ_MAP_L2_2_BIN_OFFSET                      (0x7UL<<23)
        #define MQ_MAP_L2_2_ARM                             (0x3UL<<26)
        #define MQ_MAP_L2_2_ENA                             (1UL<<31)

    u32_t mq_map_l2_3;
        #define MQ_MAP_L2_3_MQ_OFFSET                       (0xffUL<<0)
        #define MQ_MAP_L2_3_SZ                              (0x3UL<<8)
        #define MQ_MAP_L2_3_CTX_OFFSET                      (0x3ffUL<<10)
        #define MQ_MAP_L2_3_BIN_OFFSET                      (0x7UL<<23)
        #define MQ_MAP_L2_3_ARM                             (0x3UL<<26)
        #define MQ_MAP_L2_3_ENA                             (1UL<<31)

    u32_t mq_map_l2_4;
        #define MQ_MAP_L2_4_MQ_OFFSET                       (0xffUL<<0)
        #define MQ_MAP_L2_4_SZ                              (0x3UL<<8)
        #define MQ_MAP_L2_4_CTX_OFFSET                      (0x3ffUL<<10)
        #define MQ_MAP_L2_4_BIN_OFFSET                      (0x7UL<<23)
        #define MQ_MAP_L2_4_ARM                             (0x3UL<<26)
        #define MQ_MAP_L2_4_ENA                             (1UL<<31)

    u32_t mq_map_l2_5;
        #define MQ_MAP_L2_5_MQ_OFFSET                       (0xffUL<<0)
        #define MQ_MAP_L2_5_SZ                              (0x3UL<<8)
        #define MQ_MAP_L2_5_CTX_OFFSET                      (0x3ffUL<<10)
        #define MQ_MAP_L2_5_BIN_OFFSET                      (0x7UL<<23)
        #define MQ_MAP_L2_5_ARM                             (0x3UL<<26)
        #define MQ_MAP_L2_5_ENA                             (1UL<<31)

    u32_t unused_4[2];
    u32_t mq_map_l4_0;
        #define MQ_MAP_L4_0_MQ_OFFSET                       (0xffUL<<0)
        #define MQ_MAP_L4_0_SZ                              (0x3UL<<8)
        #define MQ_MAP_L4_0_CTX_OFFSET                      (0x3ffUL<<10)
        #define MQ_MAP_L4_0_BIN_OFFSET                      (0x7UL<<23)
        #define MQ_MAP_L4_0_ARM                             (0x3UL<<26)
        #define MQ_MAP_L4_0_ENA                             (1UL<<31)

    u32_t mq_map_l4_1;
        #define MQ_MAP_L4_1_MQ_OFFSET                       (0xffUL<<0)
        #define MQ_MAP_L4_1_SZ                              (0x3UL<<8)
        #define MQ_MAP_L4_1_CTX_OFFSET                      (0x3ffUL<<10)
        #define MQ_MAP_L4_1_BIN_OFFSET                      (0x7UL<<23)
        #define MQ_MAP_L4_1_ARM                             (0x3UL<<26)
        #define MQ_MAP_L4_1_ENA                             (1UL<<31)

    u32_t mq_map_l4_2;
        #define MQ_MAP_L4_2_MQ_OFFSET                       (0xffUL<<0)
        #define MQ_MAP_L4_2_SZ                              (0x3UL<<8)
        #define MQ_MAP_L4_2_CTX_OFFSET                      (0x3ffUL<<10)
        #define MQ_MAP_L4_2_BIN_OFFSET                      (0x7UL<<23)
        #define MQ_MAP_L4_2_ARM                             (0x3UL<<26)
        #define MQ_MAP_L4_2_ENA                             (1UL<<31)

    u32_t mq_map_l4_3;
        #define MQ_MAP_L4_3_MQ_OFFSET                       (0xffUL<<0)
        #define MQ_MAP_L4_3_SZ                              (0x3UL<<8)
        #define MQ_MAP_L4_3_CTX_OFFSET                      (0x3ffUL<<10)
        #define MQ_MAP_L4_3_BIN_OFFSET                      (0x7UL<<23)
        #define MQ_MAP_L4_3_ARM                             (0x3UL<<26)
        #define MQ_MAP_L4_3_ENA                             (1UL<<31)

    u32_t mq_map_l4_4;
        #define MQ_MAP_L4_4_MQ_OFFSET                       (0xffUL<<0)
        #define MQ_MAP_L4_4_SZ                              (0x3UL<<8)
        #define MQ_MAP_L4_4_CTX_OFFSET                      (0x3ffUL<<10)
        #define MQ_MAP_L4_4_BIN_OFFSET                      (0x7UL<<23)
        #define MQ_MAP_L4_4_ARM                             (0x3UL<<26)
        #define MQ_MAP_L4_4_ENA                             (1UL<<31)

    u32_t mq_map_l4_5;
        #define MQ_MAP_L4_5_MQ_OFFSET                       (0xffUL<<0)
        #define MQ_MAP_L4_5_SZ                              (0x3UL<<8)
        #define MQ_MAP_L4_5_CTX_OFFSET                      (0x3ffUL<<10)
        #define MQ_MAP_L4_5_BIN_OFFSET                      (0x7UL<<23)
        #define MQ_MAP_L4_5_ARM                             (0x3UL<<26)
        #define MQ_MAP_L4_5_ENA                             (1UL<<31)

    u32_t unused_5[2];
    u32_t mq_map_l5_0;
        #define MQ_MAP_L5_0_MQ_OFFSET                       (0xffUL<<0)
        #define MQ_MAP_L5_0_SZ                              (0x3UL<<8)
        #define MQ_MAP_L5_0_CTX_OFFSET                      (0x3ffUL<<10)
        #define MQ_MAP_L5_0_BIN_OFFSET                      (0x7UL<<23)
        #define MQ_MAP_L5_0_ARM                             (0x3UL<<26)
        #define MQ_MAP_L5_0_ENA                             (1UL<<31)

    u32_t mq_map_l5_1;
        #define MQ_MAP_L5_1_MQ_OFFSET                       (0xffUL<<0)
        #define MQ_MAP_L5_1_SZ                              (0x3UL<<8)
        #define MQ_MAP_L5_1_CTX_OFFSET                      (0x3ffUL<<10)
        #define MQ_MAP_L5_1_BIN_OFFSET                      (0x7UL<<23)
        #define MQ_MAP_L5_1_ARM                             (0x3UL<<26)
        #define MQ_MAP_L5_1_ENA                             (1UL<<31)

    u32_t mq_map_l5_2;
        #define MQ_MAP_L5_2_MQ_OFFSET                       (0xffUL<<0)
        #define MQ_MAP_L5_2_SZ                              (0x3UL<<8)
        #define MQ_MAP_L5_2_CTX_OFFSET                      (0x3ffUL<<10)
        #define MQ_MAP_L5_2_BIN_OFFSET                      (0x7UL<<23)
        #define MQ_MAP_L5_2_ARM                             (0x3UL<<26)
        #define MQ_MAP_L5_2_ENA                             (1UL<<31)

    u32_t mq_map_l5_3;
        #define MQ_MAP_L5_3_MQ_OFFSET                       (0xffUL<<0)
        #define MQ_MAP_L5_3_SZ                              (0x3UL<<8)
        #define MQ_MAP_L5_3_CTX_OFFSET                      (0x3ffUL<<10)
        #define MQ_MAP_L5_3_BIN_OFFSET                      (0x7UL<<23)
        #define MQ_MAP_L5_3_ARM                             (0x3UL<<26)
        #define MQ_MAP_L5_3_ENA                             (1UL<<31)

    u32_t mq_map_l5_4;
        #define MQ_MAP_L5_4_MQ_OFFSET                       (0xffUL<<0)
        #define MQ_MAP_L5_4_SZ                              (0x3UL<<8)
        #define MQ_MAP_L5_4_CTX_OFFSET                      (0x3ffUL<<10)
        #define MQ_MAP_L5_4_BIN_OFFSET                      (0x7UL<<23)
        #define MQ_MAP_L5_4_ARM                             (0x3UL<<26)
        #define MQ_MAP_L5_4_ENA                             (1UL<<31)

    u32_t mq_map_l5_5;
        #define MQ_MAP_L5_5_MQ_OFFSET                       (0xffUL<<0)
        #define MQ_MAP_L5_5_SZ                              (0x3UL<<8)
        #define MQ_MAP_L5_5_CTX_OFFSET                      (0x3ffUL<<10)
        #define MQ_MAP_L5_5_BIN_OFFSET                      (0x7UL<<23)
        #define MQ_MAP_L5_5_ARM                             (0x3UL<<26)
        #define MQ_MAP_L5_5_ENA                             (1UL<<31)

    u32_t unused_6[162];
} mq_reg_t;

typedef mq_reg_t mailbox_queue_reg_t;

/*
 *  cmd_scheduler_enqueue definition
 *  offset: 0000
 */
typedef struct cmd_scheduler_enqueue
{
    u32_t cmd_scheduler_enqueue_cid;
        #define CMD_SCHEDULER_ENQUEUE_CID_VALUE             (0x3fffUL<<7)

    u32_t cmd_scheduler_enqueue_wd1;
        #define CMD_SCHEDULER_ENQUEUE_FLAGS_NORMAL  (1<<25)
        #define CMD_SCHEDULER_ENQUEUE_FLAGS_DELIST  (1<<24)

} cmd_scheduler_enqueue_t;


/*
 *  csch_reg definition
 *  offset: 0x4000
 */
typedef struct csch_reg
{
    u32_t csch_ch_command;
        #define CSCH_CH_COMMAND_ENABLE                      (1UL<<0)

    u32_t csch_ch_status;
        #define CSCH_CH_STATUS_CMD_CNT_STAT                 (1UL<<16)
        #define CSCH_CH_STATUS_SLOT_CNT_STAT                (1UL<<17)

    u32_t csch_ch_list_ram_addr;
        #define CSCH_CH_LIST_RAM_ADDR_CSCH_LIST_RAM_ADDR_VALUE  (0x1ffUL<<4)

    u32_t csch_ch_list_ram_data;
    u32_t csch_ch_hard_cid;
        #define CSCH_CH_HARD_CID_VALUE                      (0x3fffUL<<7)

    u32_t unused_0[7];
    u32_t csch_ch_valid_array0;
    u32_t csch_ch_valid_array1;
    u32_t csch_ch_valid_array2;
    u32_t csch_ch_valid_array3;
    u32_t csch_ch_valid_array4;
    u32_t csch_ch_valid_array5;
    u32_t csch_ch_valid_array6;
    u32_t csch_ch_valid_array7;
    u32_t csch_ch_valid_array8;
    u32_t csch_ch_valid_array9;
    u32_t csch_ch_valid_array10;
    u32_t csch_ch_valid_array11;
    u32_t csch_ch_valid_array12;
    u32_t csch_ch_valid_array13;
    u32_t csch_ch_valid_array14;
    u32_t csch_ch_valid_array15;
    u32_t csch_hc_sch_stat;
        #define CSCH_HC_SCH_STAT_PS_CSARB                   (0xfUL<<0)
        #define CSCH_HC_SCH_STAT_PS_CPQIF                   (1UL<<8)
        #define CSCH_HC_SCH_STAT_CUR_ACT_CID                (0x3fffUL<<16)

    u32_t csch_ch_csqif_stat;
        #define CSCH_CH_CSQIF_STAT_CSQIF_STAT_PS_CSQSM      (0x3UL<<0)

    u32_t csch_ch_tmem_fsm;
        #define CSCH_CH_TMEM_FSM_MEMARB                     (0x3UL<<0)
        #define CSCH_CH_TMEM_FSM_TMEMCLR                    (0x3UL<<8)
        #define CSCH_CH_TMEM_FSM_ARBLK_1                    (1UL<<16)
        #define CSCH_CH_TMEM_FSM_ARBLK_0                    (1UL<<17)
        #define CSCH_CH_TMEM_FSM_CSQLK                      (1UL<<18)

    u32_t csch_ch_tmem_stat;
        #define CSCH_CH_TMEM_STAT_ARB_1                     (0x3ffUL<<0)
        #define CSCH_CH_TMEM_STAT_ARB_0                     (0x3ffUL<<10)
        #define CSCH_CH_TMEM_STAT_CSQ                       (0x3ffUL<<20)

    u32_t unused_1[208];
    cmd_scheduler_enqueue_t csch_csq;
    u32_t unused_2[12];
    u32_t csch_ch_ftq_cmd;
        #define CSCH_CH_FTQ_CMD_OFFSET                      (0x3ffUL<<0)
        #define CSCH_CH_FTQ_CMD_WR_TOP                      (1UL<<10)
            #define CSCH_CH_FTQ_CMD_WR_TOP_0                (0UL<<10)
            #define CSCH_CH_FTQ_CMD_WR_TOP_1                (1UL<<10)
        #define CSCH_CH_FTQ_CMD_SFT_RESET                   (1UL<<25)
        #define CSCH_CH_FTQ_CMD_RD_DATA                     (1UL<<26)
        #define CSCH_CH_FTQ_CMD_ADD_INTERVEN                (1UL<<27)
        #define CSCH_CH_FTQ_CMD_ADD_DATA                    (1UL<<28)
        #define CSCH_CH_FTQ_CMD_INTERVENE_CLR               (1UL<<29)
        #define CSCH_CH_FTQ_CMD_POP                         (1UL<<30)
        #define CSCH_CH_FTQ_CMD_BUSY                        (1UL<<31)

    u32_t csch_ch_ftq_ctl;
        #define CSCH_CH_FTQ_CTL_INTERVENE                   (1UL<<0)
        #define CSCH_CH_FTQ_CTL_OVERFLOW                    (1UL<<1)
        #define CSCH_CH_FTQ_CTL_FORCE_INTERVENE             (1UL<<2)
        #define CSCH_CH_FTQ_CTL_MAX_DEPTH                   (0x3ffUL<<12)
        #define CSCH_CH_FTQ_CTL_CUR_DEPTH                   (0x3ffUL<<22)

} csch_reg_t;

typedef csch_reg_t cmd_scheduler_reg_t;


/*
 *  timer_reg definition
 *  offset: 0x4400
 */
typedef struct timer_reg
{
    u32_t timer_command;
        #define TIMER_COMMAND_ENABLED                       (1UL<<0)

    u32_t timer_status;
        #define TIMER_STATUS_CMP_FTQ_WAIT                   (1UL<<0)
        #define TIMER_STATUS_POLL_PASS_CNT                  (1UL<<8)
        #define TIMER_STATUS_TMR1_CNT                       (1UL<<9)
        #define TIMER_STATUS_TMR2_CNT                       (1UL<<10)
        #define TIMER_STATUS_TMR3_CNT                       (1UL<<11)
        #define TIMER_STATUS_TMR4_CNT                       (1UL<<12)
        #define TIMER_STATUS_TMR5_CNT                       (1UL<<13)

    u32_t timer_config;
        #define TIMER_CONFIG_SCAN_WD_CNT_TE                    (0xffUL<<0)
        #define TIMER_CONFIG_SCAN_WD_CNT_XI                    (0x7ffUL<<0)
        #define TIMER_CONFIG_TMR1_BASE                      (0x7UL<<16)
            #define TIMER_CONFIG_TMR1_BASE_CORE             (0UL<<16)
            #define TIMER_CONFIG_TMR1_BASE_1US              (1UL<<16)
            #define TIMER_CONFIG_TMR1_BASE_10US             (2UL<<16)
            #define TIMER_CONFIG_TMR1_BASE_100US            (3UL<<16)
            #define TIMER_CONFIG_TMR1_BASE_1MS              (4UL<<16)
            #define TIMER_CONFIG_TMR1_BASE_10MS             (5UL<<16)
            #define TIMER_CONFIG_TMR1_BASE_100MS            (6UL<<16)
            #define TIMER_CONFIG_TMR1_BASE_1S               (7UL<<16)
        #define TIMER_CONFIG_TMR2_BASE                      (0x7UL<<19)
            #define TIMER_CONFIG_TMR2_BASE_CORE             (0UL<<19)
            #define TIMER_CONFIG_TMR2_BASE_1US              (1UL<<19)
            #define TIMER_CONFIG_TMR2_BASE_10US             (2UL<<19)
            #define TIMER_CONFIG_TMR2_BASE_100US            (3UL<<19)
            #define TIMER_CONFIG_TMR2_BASE_1MS              (4UL<<19)
            #define TIMER_CONFIG_TMR2_BASE_10MS             (5UL<<19)
            #define TIMER_CONFIG_TMR2_BASE_100MS            (6UL<<19)
            #define TIMER_CONFIG_TMR2_BASE_1S               (7UL<<19)
        #define TIMER_CONFIG_TMR3_BASE                      (0x7UL<<22)
            #define TIMER_CONFIG_TMR3_BASE_CORE             (0UL<<22)
            #define TIMER_CONFIG_TMR3_BASE_1US              (1UL<<22)
            #define TIMER_CONFIG_TMR3_BASE_10US             (2UL<<22)
            #define TIMER_CONFIG_TMR3_BASE_100US            (3UL<<22)
            #define TIMER_CONFIG_TMR3_BASE_1MS              (4UL<<22)
            #define TIMER_CONFIG_TMR3_BASE_10MS             (5UL<<22)
            #define TIMER_CONFIG_TMR3_BASE_100MS            (6UL<<22)
            #define TIMER_CONFIG_TMR3_BASE_1S               (7UL<<22)
        #define TIMER_CONFIG_TMR4_BASE                      (0x7UL<<25)
            #define TIMER_CONFIG_TMR4_BASE_CORE             (0UL<<25)
            #define TIMER_CONFIG_TMR4_BASE_1US              (1UL<<25)
            #define TIMER_CONFIG_TMR4_BASE_10US             (2UL<<25)
            #define TIMER_CONFIG_TMR4_BASE_100US            (3UL<<25)
            #define TIMER_CONFIG_TMR4_BASE_1MS              (4UL<<25)
            #define TIMER_CONFIG_TMR4_BASE_10MS             (5UL<<25)
            #define TIMER_CONFIG_TMR4_BASE_100MS            (6UL<<25)
            #define TIMER_CONFIG_TMR4_BASE_1S               (7UL<<25)
        #define TIMER_CONFIG_TMR5_BASE                      (0x7UL<<28)
            #define TIMER_CONFIG_TMR5_BASE_CORE             (0UL<<28)
            #define TIMER_CONFIG_TMR5_BASE_1US              (1UL<<28)
            #define TIMER_CONFIG_TMR5_BASE_10US             (2UL<<28)
            #define TIMER_CONFIG_TMR5_BASE_100US            (3UL<<28)
            #define TIMER_CONFIG_TMR5_BASE_1MS              (4UL<<28)
            #define TIMER_CONFIG_TMR5_BASE_10MS             (5UL<<28)
            #define TIMER_CONFIG_TMR5_BASE_100MS            (6UL<<28)
            #define TIMER_CONFIG_TMR5_BASE_1S               (7UL<<28)

    u32_t timer_value1;
    u16_t unused_0;
    u16_t timer_value2;
    u16_t unused_1;
    u16_t timer_value3;
    u16_t unused_2;
    u16_t timer_value4;
    u16_t unused_3;
    u16_t timer_value5;
    u32_t timer_ctx_scan_start_addr;
        #define TIMER_CTX_SCAN_START_ADDR_VALUE             (0x3ffffUL<<3)
        #define TIMER_CTX_SCAN_START_ADDR_RESTART_BASE      (0x7UL<<21)
            #define TIMER_CTX_SCAN_START_ADDR_RESTART_BASE_CORE  (0UL<<21)
            #define TIMER_CTX_SCAN_START_ADDR_RESTART_BASE_1US  (1UL<<21)
            #define TIMER_CTX_SCAN_START_ADDR_RESTART_BASE_10US  (2UL<<21)
            #define TIMER_CTX_SCAN_START_ADDR_RESTART_BASE_100US  (3UL<<21)
            #define TIMER_CTX_SCAN_START_ADDR_RESTART_BASE_1MS  (4UL<<21)
            #define TIMER_CTX_SCAN_START_ADDR_RESTART_BASE_10MS  (5UL<<21)
            #define TIMER_CTX_SCAN_START_ADDR_RESTART_BASE_100MS  (6UL<<21)
            #define TIMER_CTX_SCAN_START_ADDR_RESTART_BASE_1S  (7UL<<21)
        #define TIMER_CTX_SCAN_START_ADDR_RESTART_RELOAD    (0xffUL<<24)

    u32_t timer_sw_tmr_cfg1;
        #define TIMER_SW_TMR_CFG1_ENA                       (1UL<<0)
        #define TIMER_SW_TMR_CFG1_RELOAD                    (1UL<<1)
        #define TIMER_SW_TMR_CFG1_ATTN                      (1UL<<2)
        #define TIMER_SW_TMR_CFG1_COM                       (1UL<<3)
        #define TIMER_SW_TMR_CFG1_BASE                      (0x7UL<<4)
            #define TIMER_SW_TMR_CFG1_BASE_CORE             (0UL<<4)
            #define TIMER_SW_TMR_CFG1_BASE_1US              (1UL<<4)
            #define TIMER_SW_TMR_CFG1_BASE_10US             (2UL<<4)
            #define TIMER_SW_TMR_CFG1_BASE_100US            (3UL<<4)
            #define TIMER_SW_TMR_CFG1_BASE_1MS              (4UL<<4)
            #define TIMER_SW_TMR_CFG1_BASE_10MS             (5UL<<4)
            #define TIMER_SW_TMR_CFG1_BASE_100MS            (6UL<<4)
            #define TIMER_SW_TMR_CFG1_BASE_1S               (7UL<<4)

    u32_t timer_sw_tmr_value1;
    u32_t timer_sw_tmr_reload_value1;
    u32_t timer_sw_tmr_value2;
    u32_t timer_sw_tmr_reload_value2;
    u32_t timer_sw_tmr_value3;
    u32_t timer_sw_tmr_reload_value3;
    u32_t timer_sw_tmr_value4;
    u32_t timer_sw_tmr_reload_value4;
    u32_t timer_25mhz_free_run;
    u32_t timer_sw_tmr_cfg2;
        #define TIMER_SW_TMR_CFG2_ENA                       (1UL<<0)
        #define TIMER_SW_TMR_CFG2_RELOAD                    (1UL<<1)
        #define TIMER_SW_TMR_CFG2_ATTN                      (1UL<<2)
        #define TIMER_SW_TMR_CFG2_COM                       (1UL<<3)
        #define TIMER_SW_TMR_CFG2_BASE                      (0x7UL<<4)
            #define TIMER_SW_TMR_CFG2_BASE_CORE             (0UL<<4)
            #define TIMER_SW_TMR_CFG2_BASE_1US              (1UL<<4)
            #define TIMER_SW_TMR_CFG2_BASE_10US             (2UL<<4)
            #define TIMER_SW_TMR_CFG2_BASE_100US            (3UL<<4)
            #define TIMER_SW_TMR_CFG2_BASE_1MS              (4UL<<4)
            #define TIMER_SW_TMR_CFG2_BASE_10MS             (5UL<<4)
            #define TIMER_SW_TMR_CFG2_BASE_100MS            (6UL<<4)
            #define TIMER_SW_TMR_CFG2_BASE_1S               (7UL<<4)

    u32_t timer_sw_tmr_cfg3;
        #define TIMER_SW_TMR_CFG3_ENA                       (1UL<<0)
        #define TIMER_SW_TMR_CFG3_RELOAD                    (1UL<<1)
        #define TIMER_SW_TMR_CFG3_ATTN                      (1UL<<2)
        #define TIMER_SW_TMR_CFG3_COM                       (1UL<<3)
        #define TIMER_SW_TMR_CFG3_BASE                      (0x7UL<<4)
            #define TIMER_SW_TMR_CFG3_BASE_CORE             (0UL<<4)
            #define TIMER_SW_TMR_CFG3_BASE_1US              (1UL<<4)
            #define TIMER_SW_TMR_CFG3_BASE_10US             (2UL<<4)
            #define TIMER_SW_TMR_CFG3_BASE_100US            (3UL<<4)
            #define TIMER_SW_TMR_CFG3_BASE_1MS              (4UL<<4)
            #define TIMER_SW_TMR_CFG3_BASE_10MS             (5UL<<4)
            #define TIMER_SW_TMR_CFG3_BASE_100MS            (6UL<<4)
            #define TIMER_SW_TMR_CFG3_BASE_1S               (7UL<<4)

    u32_t timer_sw_tmr_cfg4;
        #define TIMER_SW_TMR_CFG4_ENA                       (1UL<<0)
        #define TIMER_SW_TMR_CFG4_RELOAD                    (1UL<<1)
        #define TIMER_SW_TMR_CFG4_ATTN                      (1UL<<2)
        #define TIMER_SW_TMR_CFG4_COM                       (1UL<<3)
        #define TIMER_SW_TMR_CFG4_BASE                      (0x7UL<<4)
            #define TIMER_SW_TMR_CFG4_BASE_CORE             (0UL<<4)
            #define TIMER_SW_TMR_CFG4_BASE_1US              (1UL<<4)
            #define TIMER_SW_TMR_CFG4_BASE_10US             (2UL<<4)
            #define TIMER_SW_TMR_CFG4_BASE_100US            (3UL<<4)
            #define TIMER_SW_TMR_CFG4_BASE_1MS              (4UL<<4)
            #define TIMER_SW_TMR_CFG4_BASE_10MS             (5UL<<4)
            #define TIMER_SW_TMR_CFG4_BASE_100MS            (6UL<<4)
            #define TIMER_SW_TMR_CFG4_BASE_1S               (7UL<<4)

    u32_t timer_sw_tmr_event_clr;
        #define TIMER_SW_TMR_EVENT_CLR_TMR1_EVENT_CLR       (1UL<<0)
        #define TIMER_SW_TMR_EVENT_CLR_TMR2_EVENT_CLR       (1UL<<1)
        #define TIMER_SW_TMR_EVENT_CLR_TMR3_EVENT_CLR       (1UL<<2)
        #define TIMER_SW_TMR_EVENT_CLR_TMR4_EVENT_CLR       (1UL<<3)

    u32_t unused_4[2];
    u32_t timer_fsm_tmr;
        #define TIMER_FSM_TMR_TMR_CTX_IF                    (0x7ffUL<<0)
            #define TIMER_FSM_TMR_TMR_CTX_IF_IDLE           (0UL<<0)
            #define TIMER_FSM_TMR_TMR_CTX_IF_CTX_SCAN_REQ   (2UL<<0)
            #define TIMER_FSM_TMR_TMR_CTX_IF_CTX_SCAN_ACK   (4UL<<0)
            #define TIMER_FSM_TMR_TMR_CTX_IF_CTX_SCAN_VLD   (8UL<<0)
            #define TIMER_FSM_TMR_TMR_CTX_IF_BITFLD_EVAL    (16UL<<0)
            #define TIMER_FSM_TMR_TMR_CTX_IF_CTX_TM_REQ0    (32UL<<0)
            #define TIMER_FSM_TMR_TMR_CTX_IF_CTX_TM_REQ1    (64UL<<0)
            #define TIMER_FSM_TMR_TMR_CTX_IF_CTX_TM_VLD     (128UL<<0)
            #define TIMER_FSM_TMR_TMR_CTX_IF_CTX_TM_EVAL    (256UL<<0)
            #define TIMER_FSM_TMR_TMR_CTX_IF_CTX_LAST_ACK   (512UL<<0)
            #define TIMER_FSM_TMR_TMR_CTX_IF_CTX_TM_WAIT    (1024UL<<0)
        #define TIMER_FSM_TMR_COMTQ_IF                      (0x3UL<<16)
            #define TIMER_FSM_TMR_COMTQ_IF_IDLE             (0UL<<16)
            #define TIMER_FSM_TMR_COMTQ_IF_LOAD             (1UL<<16)
            #define TIMER_FSM_TMR_COMTQ_IF_REQ              (2UL<<16)

    u32_t timer_stat_tmr;
        #define TIMER_STAT_TMR_SCAN_WC                      (0xffffUL<<0)
        #define TIMER_STAT_TMR_CTX_OFF                      (0xffffUL<<16)

    u32_t unused_5[229];
} timer_reg_t;


/*
 *  tx_scheduler_enqueue definition
 *  offset: 0000
 */
typedef struct tx_scheduler_enqueue
{
    u32_t tx_scheduler_enqueue_cid;
        #define TX_SCHEDULER_ENQUEUE_CID_VALUE              (0x3fffUL<<7)

    u32_t tx_scheduler_enqueue_wd1;
        #define TX_SCHEDULER_ENQUEUE_FLAGS_DELIST           (1<<24)
        #define TX_SCHEDULER_ENQUEUE_FLAGS_NORMAL           (1<<25)
        #define TX_SCHEDULER_ENQUEUE_FLAGS_HIGH             (1<<26)
        #define TX_SCHEDULER_ENQUEUE_RSVD_FUTURE_VALUE      (0x3<<16)

} tx_scheduler_enqueue_t;


/*
 *  tsch_reg definition
 *  offset: 0x4c00
 */
typedef struct tsch_reg
{
    u32_t tsch_command;
        #define TSCH_COMMAND_ENABLE                         (1UL<<0)

    u32_t tsch_status;
        #define TSCH_STATUS_LS_INIT                         (1UL<<0)
        #define TSCH_STATUS_LOCK_WT                         (1UL<<1)
        #define TSCH_STATUS_INT_LOC                         (1UL<<2)
        #define TSCH_STATUS_INTERNAL_TBDR_WT                (1UL<<3)
        #define TSCH_STATUS_CMD_CNT_STAT                    (1UL<<4)
        #define TSCH_STATUS_SLOT_CNT_STAT                   (1UL<<5)

    u32_t tsch_mix;
        #define TSCH_MIX_0                                  (0x3UL<<0)
            #define TSCH_MIX_0_NORMAL                       (0UL<<0)
            #define TSCH_MIX_0_HIGH                         (1UL<<0)
            #define TSCH_MIX_0_QUICK                        (2UL<<0)
            #define TSCH_MIX_0_UNDEF                        (3UL<<0)
        #define TSCH_MIX_1                                  (0x3UL<<2)
        #define TSCH_MIX_2                                  (0x3UL<<4)
        #define TSCH_MIX_3                                  (0x3UL<<6)
        #define TSCH_MIX_4                                  (0x3UL<<8)
        #define TSCH_MIX_5                                  (0x3UL<<10)
        #define TSCH_MIX_6                                  (0x3UL<<12)
        #define TSCH_MIX_7                                  (0x3UL<<14)
        #define TSCH_MIX_8                                  (0x3UL<<16)
        #define TSCH_MIX_9                                  (0x3UL<<18)
        #define TSCH_MIX_10                                 (0x3UL<<20)
        #define TSCH_MIX_11                                 (0x3UL<<22)
        #define TSCH_MIX_12                                 (0x3UL<<24)
        #define TSCH_MIX_13                                 (0x3UL<<26)
        #define TSCH_MIX_14                                 (0x3UL<<28)
        #define TSCH_MIX_15                                 (0x3UL<<30)

    u32_t tsch_quick_slot_size;
        #define TSCH_QUICK_SLOT_SIZE_VALUE                  (0x1ffUL<<10)
        #define TSCH_QUICK_SLOT_SIZE_CTX_L2_SLOT_SIZE_EN    (1UL<<19)
        #define TSCH_QUICK_SLOT_SIZE_PESS_DIV               (0xfUL<<24)

    u32_t tsch_list_ram_addr;
        #define TSCH_LIST_RAM_ADDR_VALUE                    (0x1ffUL<<5)
        #define TSCH_LIST_RAM_ADDR_LIST_WD_SEL              (1UL<<31)

    u32_t tsch_list_ram_data;
    u32_t tsch_ctx_access_cfg;
        #define TSCH_CTX_ACCESS_CFG_TCMD_CELL_OFFSET        (0x3fUL<<0)
        #define TSCH_CTX_ACCESS_CFG_L5_TCMD_PREFETCH_SIZE   (0x7UL<<8)
        #define TSCH_CTX_ACCESS_CFG_CMN_CELL_OFFSET         (0x7UL<<16)
        #define TSCH_CTX_ACCESS_CFG_ADD_PREFETCH_SIZE       (0x3UL<<24)
        #define TSCH_CTX_ACCESS_CFG_ADD_PREFETCH_EN         (1UL<<26)

    u32_t tsch_tss_cfg;
        #define TSCH_TSS_CFG_TSS_START_CID                  (0x7ffUL<<10)
        #define TSCH_TSS_CFG_NUM_OF_TSS_CON                 (0xfUL<<24)

    u32_t unused_0[8];
    u32_t tsch_debug_1;
        #define TSCH_DEBUG_1_SLOT_PT                        (0xfUL<<0)
        #define TSCH_DEBUG_1_SERV_PT                        (0xfUL<<4)
        #define TSCH_DEBUG_1_SLOT_SM                        (0x7UL<<8)
            #define TSCH_DEBUG_1_SLOT_SM_IDLE               (0UL<<8)
            #define TSCH_DEBUG_1_SLOT_SM_TRAV               (1UL<<8)
            #define TSCH_DEBUG_1_SLOT_SM_ACK                (2UL<<8)
            #define TSCH_DEBUG_1_SLOT_SM_WAIT               (3UL<<8)
            #define TSCH_DEBUG_1_SLOT_SM_NOTIFY             (4UL<<8)
        #define TSCH_DEBUG_1_LP_REQ_SM                      (0x3UL<<12)
            #define TSCH_DEBUG_1_LP_REQ_SM_IDLE             (0UL<<12)
            #define TSCH_DEBUG_1_LP_REQ_SM_REQ_SEL          (1UL<<12)
            #define TSCH_DEBUG_1_LP_REQ_SM_REQ_CON          (2UL<<12)
        #define TSCH_DEBUG_1_HP_REQ_SM                      (0x3UL<<14)
            #define TSCH_DEBUG_1_HP_REQ_SM_IDLE             (0UL<<14)
            #define TSCH_DEBUG_1_HP_REQ_SM_REQ_SEL          (1UL<<14)
            #define TSCH_DEBUG_1_HP_REQ_SM_REQ_CON          (2UL<<14)
        #define TSCH_DEBUG_1_LIST_SM                        (0x7UL<<16)
            #define TSCH_DEBUG_1_LIST_SM_IDLE               (0UL<<16)
            #define TSCH_DEBUG_1_LIST_SM_READ               (1UL<<16)
            #define TSCH_DEBUG_1_LIST_SM_STORE              (2UL<<16)
            #define TSCH_DEBUG_1_LIST_SM_FIND_CON           (3UL<<16)
            #define TSCH_DEBUG_1_LIST_SM_FIND_WORD          (4UL<<16)
            #define TSCH_DEBUG_1_LIST_SM_WAIT               (5UL<<16)
            #define TSCH_DEBUG_1_LIST_SM_SEL                (6UL<<16)
        #define TSCH_DEBUG_1_DO_HLIST                       (1UL<<19)
        #define TSCH_DEBUG_1_LIST_EMPTY                     (1UL<<20)
        #define TSCH_DEBUG_1_HLIST_EMPTY                    (1UL<<21)
        #define TSCH_DEBUG_1_L2_SM                          (0x3UL<<22)
            #define TSCH_DEBUG_1_L2_SM_IDLE                 (0UL<<22)
            #define TSCH_DEBUG_1_L2_SM_FOUND                (1UL<<22)
            #define TSCH_DEBUG_1_L2_SM_SEL                  (2UL<<22)
        #define TSCH_DEBUG_1_ACT_L2_LIST                    (0xfUL<<24)
        #define TSCH_DEBUG_1_GENQ_SM                        (0x7UL<<28)
            #define TSCH_DEBUG_1_GENQ_SM_IDLE               (0UL<<28)
            #define TSCH_DEBUG_1_GENQ_SM_READ_INPUT         (1UL<<28)
            #define TSCH_DEBUG_1_GENQ_SM_READ_OFFLOAD       (2UL<<28)
            #define TSCH_DEBUG_1_GENQ_SM_READ_STORE         (3UL<<28)
            #define TSCH_DEBUG_1_GENQ_SM_READ_UPDATE        (4UL<<28)
            #define TSCH_DEBUG_1_GENQ_SM_READ_WRITE         (5UL<<28)
            #define TSCH_DEBUG_1_GENQ_SM_READ_POP           (6UL<<28)

    u32_t tsch_debug_2;
        #define TSCH_DEBUG_2_LO_PRI_CID                     (0x1fffUL<<0)
        #define TSCH_DEBUG_2_LO_PRI_REQ                     (1UL<<15)
        #define TSCH_DEBUG_2_HI_PRI_CID                     (0x1fffUL<<16)
        #define TSCH_DEBUG_2_HI_PRI_REQ                     (1UL<<31)

    u32_t tsch_debug_3;
        #define TSCH_DEBUG_3_CNTX_AD                        (0x1fffUL<<0)
        #define TSCH_DEBUG_3_CNTX_GO                        (1UL<<15)
        #define TSCH_DEBUG_3_CON_TYP                        (0x3UL<<24)
        #define TSCH_DEBUG_3_L2_PT                          (0x3UL<<28)
        #define TSCH_DEBUG_3_L2_REQ                         (1UL<<31)

    u32_t tsch_debug_4;
        #define TSCH_DEBUG_4_ACK_SM                         (0x3UL<<4)
            #define TSCH_DEBUG_4_ACK_SM_IDLE                (0UL<<4)
            #define TSCH_DEBUG_4_ACK_SM_READ                (1UL<<4)
            #define TSCH_DEBUG_4_ACK_SM_WRITE               (2UL<<4)
            #define TSCH_DEBUG_4_ACK_SM_ACK                 (3UL<<4)
        #define TSCH_DEBUG_4_DO_NXT_L5                      (1UL<<8)
        #define TSCH_DEBUG_4_CNTX_BUSY                      (1UL<<9)
        #define TSCH_DEBUG_4_TBDR_SM                        (1UL<<11)
        #define TSCH_DEBUG_4_LIST_RM_SM                     (0x3UL<<12)
            #define TSCH_DEBUG_4_LIST_RM_SM_IDLE            (0UL<<12)
            #define TSCH_DEBUG_4_LIST_RM_SM_REM_L2          (1UL<<12)
            #define TSCH_DEBUG_4_LIST_RM_SM_REM_L4          (2UL<<12)
        #define TSCH_DEBUG_4_CNTX_WR_SM                     (0x3UL<<16)
            #define TSCH_DEBUG_4_CNTX_WR_SM_IDLE            (0UL<<16)
            #define TSCH_DEBUG_4_CNTX_WR_SM_CTX_WR          (1UL<<16)
            #define TSCH_DEBUG_4_CNTX_WR_SM_CTX_WR_DONE     (2UL<<16)
        #define TSCH_DEBUG_4_PROC_SM                        (0xfUL<<20)
            #define TSCH_DEBUG_4_PROC_SM_IDLE               (0UL<<20)
            #define TSCH_DEBUG_4_PROC_SM_1ST_STAGE          (1UL<<20)
            #define TSCH_DEBUG_4_PROC_SM_L2_1ST_STAGE       (2UL<<20)
            #define TSCH_DEBUG_4_PROC_SM_L2_2ND_STAGE       (3UL<<20)
            #define TSCH_DEBUG_4_PROC_SM_L4_1ST_STAGE       (4UL<<20)
            #define TSCH_DEBUG_4_PROC_SM_L4_2ND_STAGE       (5UL<<20)
            #define TSCH_DEBUG_4_PROC_SM_L5_STAGE           (6UL<<20)
            #define TSCH_DEBUG_4_PROC_SM_L5_WAIT            (7UL<<20)
            #define TSCH_DEBUG_4_PROC_SM_L5_HALT            (8UL<<20)
        #define TSCH_DEBUG_4_CNTX_RD_SM                     (0x7UL<<24)
            #define TSCH_DEBUG_4_CNTX_RD_SM_IDLE            (0UL<<24)
            #define TSCH_DEBUG_4_CNTX_RD_SM_L2_1ST_READ     (1UL<<24)
            #define TSCH_DEBUG_4_CNTX_RD_SM_L2_LAST_READ    (2UL<<24)
            #define TSCH_DEBUG_4_CNTX_RD_SM_L4_1ST_READ     (3UL<<24)
            #define TSCH_DEBUG_4_CNTX_RD_SM_L4_LAST_READ    (4UL<<24)
            #define TSCH_DEBUG_4_CNTX_RD_SM_L5_1ST_READ     (5UL<<24)
            #define TSCH_DEBUG_4_CNTX_RD_SM_L5_LAST_READ    (6UL<<24)
        #define TSCH_DEBUG_4_LOCK_SM                        (0x7UL<<28)
            #define TSCH_DEBUG_4_LOCK_SM_IDLE               (0UL<<28)
            #define TSCH_DEBUG_4_LOCK_SM_REQ                (1UL<<28)
            #define TSCH_DEBUG_4_LOCK_SM_WAIT               (2UL<<28)
            #define TSCH_DEBUG_4_LOCK_SM_UNLOCK             (3UL<<28)
            #define TSCH_DEBUG_4_LOCK_SM_TBDR               (4UL<<28)
            #define TSCH_DEBUG_4_LOCK_SM_UPDATE             (5UL<<28)
            #define TSCH_DEBUG_4_LOCK_SM_ENABLE             (6UL<<28)

    u32_t tsch_debug_5;
        #define TSCH_DEBUG_5_TSCH_DBG5_NU_SLT_SZ            (0xffffffffUL<<0)

    u32_t unused_1[11];
    u32_t tsch_debug_vect_peek;
        #define TSCH_DEBUG_VECT_PEEK_1_VALUE                (0x7ffUL<<0)
        #define TSCH_DEBUG_VECT_PEEK_1_EN                   (1UL<<11)
        #define TSCH_DEBUG_VECT_PEEK_1_SEL                  (0xfUL<<12)
        #define TSCH_DEBUG_VECT_PEEK_2_VALUE                (0x7ffUL<<16)
        #define TSCH_DEBUG_VECT_PEEK_2_EN                   (1UL<<27)
        #define TSCH_DEBUG_VECT_PEEK_2_SEL                  (0xfUL<<28)

    u32_t unused_2[207];
    tx_scheduler_enqueue_t tsch_tschq;
    u32_t unused_3[12];
    u32_t tsch_ftq_cmd;
        #define TSCH_FTQ_CMD_OFFSET                         (0x3ffUL<<0)
        #define TSCH_FTQ_CMD_WR_TOP                         (1UL<<10)
            #define TSCH_FTQ_CMD_WR_TOP_0                   (0UL<<10)
            #define TSCH_FTQ_CMD_WR_TOP_1                   (1UL<<10)
        #define TSCH_FTQ_CMD_SFT_RESET                      (1UL<<25)
        #define TSCH_FTQ_CMD_RD_DATA                        (1UL<<26)
        #define TSCH_FTQ_CMD_ADD_INTERVEN                   (1UL<<27)
        #define TSCH_FTQ_CMD_ADD_DATA                       (1UL<<28)
        #define TSCH_FTQ_CMD_INTERVENE_CLR                  (1UL<<29)
        #define TSCH_FTQ_CMD_POP                            (1UL<<30)
        #define TSCH_FTQ_CMD_BUSY                           (1UL<<31)

    u32_t tsch_ftq_ctl;
        #define TSCH_FTQ_CTL_INTERVENE                      (1UL<<0)
        #define TSCH_FTQ_CTL_OVERFLOW                       (1UL<<1)
        #define TSCH_FTQ_CTL_FORCE_INTERVENE                (1UL<<2)
        #define TSCH_FTQ_CTL_MAX_DEPTH                      (0x3ffUL<<12)
        #define TSCH_FTQ_CTL_CUR_DEPTH                      (0x3ffUL<<22)

} tsch_reg_t;

typedef tsch_reg_t tx_scheduler_reg_t;

/*
 *  tx_bd_read_enqueue definition
 *  offset: 0000
 */
typedef struct tx_bd_read_enqueue
{
    u32_t tx_bd_read_enqueue_cid;
        #define TX_BD_READ_ENQUEUE_CID_VALUE                (0x3fffUL<<7)

    u32_t tx_bd_read_enqueue_bseq;
    u32_t tx_bd_read_enqueue_wd2;
        #define TX_BD_READ_ENQUEUE_FLAGS_FLAGS_QUICK_CID_ENA  (1<<24)
        #define TX_BD_READ_ENQUEUE_FLAGS_FLAGS_QUICK_CID_TE    (0x3<<25)
        #define TX_BD_READ_ENQUEUE_FLAGS_FLAGS_QUICK_CATCHUP_TE  (1<<27)
        #define TX_BD_READ_ENQUEUE_FLAGS_FLAGS_RSVD_XI         (1<<25)
        #define TX_BD_READ_ENQUEUE_FLAGS_FLAGS_BORROWED_XI     (1<<26)
        #define TX_BD_READ_ENQUEUE_FLAGS_FLAGS_BSEQ_INVLD_XI   (1<<27)
        #define TX_BD_READ_ENQUEUE_FLAGS_FLAGS_S_RETRAN     (1<<28)

    u32_t tx_bd_read_enqueue_tcp_rcv_nxt;
    u32_t tx_bd_read_enqueue_wd4;
        #define TX_BD_READ_ENQUEUE_TCMD_FNUM_VALUE          (0x3f<<24)

} tx_bd_read_enqueue_t;


/*
 *  tbdr_reg definition
 *  offset: 0x5000
 */
typedef struct tbdr_reg
{
    u32_t tbdr_command;
        #define TBDR_COMMAND_ENABLE                         (1UL<<0)
        #define TBDR_COMMAND_SOFT_RST                       (1UL<<1)
        #define TBDR_COMMAND_MSTR_ABORT                     (1UL<<4)

    u32_t tbdr_status;
        #define TBDR_STATUS_DMA_WAIT                        (1UL<<0)
        #define TBDR_STATUS_FTQ_WAIT                        (1UL<<1)
        #define TBDR_STATUS_FIFO_OVERFLOW                   (1UL<<2)
        #define TBDR_STATUS_FIFO_UNDERFLOW                  (1UL<<3)
        #define TBDR_STATUS_SEARCHMISS_ERROR                (1UL<<4)
        #define TBDR_STATUS_FTQ_ENTRY_CNT                   (1UL<<5)
        #define TBDR_STATUS_BURST_CNT                       (1UL<<6)

    u32_t tbdr_config;
        #define TBDR_CONFIG_MAX_BDS                         (0xffUL<<0)
        #define TBDR_CONFIG_SWAP_MODE                       (1UL<<8)
        #define TBDR_CONFIG_PRIORITY                        (1UL<<9)
        #define TBDR_CONFIG_CACHE_NEXT_PAGE_PTRS            (1UL<<10)
        #define TBDR_CONFIG_PAGE_SIZE                       (0xfUL<<24)
            #define TBDR_CONFIG_PAGE_SIZE_256               (0UL<<24)
            #define TBDR_CONFIG_PAGE_SIZE_512               (1UL<<24)
            #define TBDR_CONFIG_PAGE_SIZE_1K                (2UL<<24)
            #define TBDR_CONFIG_PAGE_SIZE_2K                (3UL<<24)
            #define TBDR_CONFIG_PAGE_SIZE_4K                (4UL<<24)
            #define TBDR_CONFIG_PAGE_SIZE_8K                (5UL<<24)
            #define TBDR_CONFIG_PAGE_SIZE_16K               (6UL<<24)
            #define TBDR_CONFIG_PAGE_SIZE_32K               (7UL<<24)
            #define TBDR_CONFIG_PAGE_SIZE_64K               (8UL<<24)
            #define TBDR_CONFIG_PAGE_SIZE_128K              (9UL<<24)
            #define TBDR_CONFIG_PAGE_SIZE_256K              (10UL<<24)
            #define TBDR_CONFIG_PAGE_SIZE_512K              (11UL<<24)
            #define TBDR_CONFIG_PAGE_SIZE_1M                (12UL<<24)

    u32_t tbdr_debug_vect_peek;
        #define TBDR_DEBUG_VECT_PEEK_1_VALUE                (0x7ffUL<<0)
        #define TBDR_DEBUG_VECT_PEEK_1_PEEK_EN              (1UL<<11)
        #define TBDR_DEBUG_VECT_PEEK_1_SEL                  (0xfUL<<12)
        #define TBDR_DEBUG_VECT_PEEK_2_VALUE                (0x7ffUL<<16)
        #define TBDR_DEBUG_VECT_PEEK_2_PEEK_EN              (1UL<<27)
        #define TBDR_DEBUG_VECT_PEEK_2_SEL                  (0xfUL<<28)

    u32_t tbdr_cksum_error_status;
        #define TBDR_CKSUM_ERROR_STATUS_CALCULATED          (0xffffUL<<0)
        #define TBDR_CKSUM_ERROR_STATUS_EXPECTED            (0xffffUL<<16)

    u32_t unused_0[235];
    tx_bd_read_enqueue_t tbdr_tbdrq;
    u32_t unused_1[9];
    u32_t tbdr_ftq_cmd;
        #define TBDR_FTQ_CMD_OFFSET                         (0x3ffUL<<0)
        #define TBDR_FTQ_CMD_WR_TOP                         (1UL<<10)
            #define TBDR_FTQ_CMD_WR_TOP_0                   (0UL<<10)
            #define TBDR_FTQ_CMD_WR_TOP_1                   (1UL<<10)
        #define TBDR_FTQ_CMD_SFT_RESET                      (1UL<<25)
        #define TBDR_FTQ_CMD_RD_DATA                        (1UL<<26)
        #define TBDR_FTQ_CMD_ADD_INTERVEN                   (1UL<<27)
        #define TBDR_FTQ_CMD_ADD_DATA                       (1UL<<28)
        #define TBDR_FTQ_CMD_INTERVENE_CLR                  (1UL<<29)
        #define TBDR_FTQ_CMD_POP                            (1UL<<30)
        #define TBDR_FTQ_CMD_BUSY                           (1UL<<31)

    u32_t tbdr_ftq_ctl;
        #define TBDR_FTQ_CTL_INTERVENE                      (1UL<<0)
        #define TBDR_FTQ_CTL_OVERFLOW                       (1UL<<1)
        #define TBDR_FTQ_CTL_FORCE_INTERVENE                (1UL<<2)
        #define TBDR_FTQ_CTL_MAX_DEPTH                      (0x3ffUL<<12)
        #define TBDR_FTQ_CTL_CUR_DEPTH                      (0x3ffUL<<22)

} tbdr_reg_t;

typedef tbdr_reg_t tx_bd_read_reg_t;

/*
 *  tbdc_reg definition
 *  offset: 0x5400
 */
typedef struct tbdc_reg
{
    u32_t tbdc_command;
        #define TBDC_COMMAND_CMD_ENABLED                    (1UL<<0)
        #define TBDC_COMMAND_CMD_FLUSH                      (1UL<<1)
        #define TBDC_COMMAND_CMD_SOFT_RST                   (1UL<<2)
        #define TBDC_COMMAND_CMD_REG_ARB                    (1UL<<3)
        #define TBDC_COMMAND_WRCHK_RANGE_ERROR              (1UL<<4)
        #define TBDC_COMMAND_WRCHK_ALL_ONES_ERROR           (1UL<<5)
        #define TBDC_COMMAND_WRCHK_ALL_ZEROS_ERROR          (1UL<<6)
        #define TBDC_COMMAND_WRCHK_ANY_ONES_ERROR           (1UL<<7)
        #define TBDC_COMMAND_WRCHK_ANY_ZEROS_ERROR          (1UL<<8)

    u32_t tbdc_status;
        #define TBDC_STATUS_FREE_CNT                        (0x3fUL<<0)

    u32_t tbdc_control;
        #define TBDC_CONTROL_RANGE                          (1UL<<0)
        #define TBDC_CONTROL_ALL_ONES                       (1UL<<1)
        #define TBDC_CONTROL_ALL_ZEROS                      (1UL<<2)
        #define TBDC_CONTROL_ANY_ONES                       (1UL<<3)
        #define TBDC_CONTROL_ANY_ZEROS                      (1UL<<4)

    u32_t tbdc_bd_haddr_hi;
    u32_t tbdc_bd_haddr_lo;
    u32_t tbdc_bd_nbytes;
        #define TBDC_BD_NBYTES_NBYTES                       (0xffffUL<<0)

    u32_t tbdc_bd_flags;
        #define TBDC_BD_FLAGS_FLAGS                         (0xffffUL<<0)

    u32_t tbdc_bd_reserved;
        #define TBDC_BD_RESERVED_VALUE                      (0xffffUL<<0)

    u32_t tbdc_bd_vlan_tag;
        #define TBDC_BD_VLAN_TAG_VLAN_TAG                   (0xffffUL<<0)

    u32_t tbdc_bd_addr;
        #define TBDC_BD_ADDR_ADDRESS                        (0xffUL<<0)
        #define TBDC_BD_ADDR_HIT                            (1UL<<8)

    u32_t tbdc_bd_hiaddr;
        #define TBDC_BD_HIADDR_HIADDR                       (0xffUL<<0)

    u32_t tbdc_bdidx;
        #define TBDC_BDIDX_BDIDX                            (0xffffUL<<0)
        #define TBDC_BDIDX_CMD                              (0xffUL<<24)

    u32_t tbdc_cid;
        #define TBDC_CID_CID                                (0x3fffUL<<7)

    u32_t tbdc_cam_opcode;
        #define TBDC_CAM_OPCODE_OPCODE                      (0x7UL<<0)
            #define TBDC_CAM_OPCODE_OPCODE_SEARCH           (0UL<<0)
            #define TBDC_CAM_OPCODE_OPCODE_CACHE_WRITE      (1UL<<0)
            #define TBDC_CAM_OPCODE_OPCODE_INVALIDATE       (2UL<<0)
            #define TBDC_CAM_OPCODE_OPCODE_CAM_WRITE        (4UL<<0)
            #define TBDC_CAM_OPCODE_OPCODE_CAM_READ         (5UL<<0)
            #define TBDC_CAM_OPCODE_OPCODE_RAM_WRITE        (6UL<<0)
            #define TBDC_CAM_OPCODE_OPCODE_RAM_READ         (7UL<<0)
        #define TBDC_CAM_OPCODE_SMASK_BDIDX                 (1UL<<4)
        #define TBDC_CAM_OPCODE_SMASK_CID                   (1UL<<5)
        #define TBDC_CAM_OPCODE_SMASK_CMD                   (1UL<<6)
        #define TBDC_CAM_OPCODE_WMT_FAILED                  (1UL<<7)
        #define TBDC_CAM_OPCODE_CAM_VALIDS                  (0xffUL<<8)

    u32_t tbdc_haddr_hi;
    u32_t tbdc_haddr_lo;
    u32_t tbdc_debug_vect_peek;
        #define TBDC_DEBUG_VECT_PEEK_1_VALUE                (0x7ffUL<<0)
        #define TBDC_DEBUG_VECT_PEEK_1_PEEK_EN              (1UL<<11)
        #define TBDC_DEBUG_VECT_PEEK_1_SEL                  (0xfUL<<12)
        #define TBDC_DEBUG_VECT_PEEK_2_VALUE                (0x7ffUL<<16)
        #define TBDC_DEBUG_VECT_PEEK_2_PEEK_EN              (1UL<<27)
        #define TBDC_DEBUG_VECT_PEEK_2_SEL                  (0xfUL<<28)

    u32_t unused_0[239];
} tbdc_reg_t;

typedef tbdc_reg_t tx_bd_cache_reg_t;

/*
 *  tx_dma_enqueue definition
 *  offset: 0000
 */
typedef struct tx_dma_enqueue
{
    u32_t tx_dma_enqueue_cid;
        #define TX_DMA_ENQUEUE_CID_VALUE                    (0x3fffUL<<7)

    u32_t tx_dma_enqueue_wd1;
        #define TX_DMA_ENQUEUE_TDMA_BIDX                    (0xffff<<16)
        #define TX_DMA_ENQUEUE_TDMA_BOFF                    (0xffff<<0)

    u32_t tx_dma_enqueue_tdma_bseq;
    u32_t tx_dma_enqueue_tdma_snd_next;
    u32_t tx_dma_enqueue_wd4;
        #define TX_DMA_ENQUEUE_TDMA_CMD                     (0xff<<24)
        #define TX_DMA_ENQUEUE_XNUM                         (0xff<<16)
        #define TX_DMA_ENQUEUE_KNUM                         (0xff<<8)

    u32_t tx_dma_enqueue_flags_flags;
        #define TX_DMA_ENQUEUE_FLAGS_FLAGS_PLUS_TWO         (1UL<<0)
        #define TX_DMA_ENQUEUE_FLAGS_FLAGS_TCP_UDP_CKSUM    (1UL<<1)
        #define TX_DMA_ENQUEUE_FLAGS_FLAGS_IP_CKSUM         (1UL<<2)
        #define TX_DMA_ENQUEUE_FLAGS_FLAGS_INCR_CMD         (1UL<<3)
        #define TX_DMA_ENQUEUE_FLAGS_FLAGS_COAL_NOW         (1UL<<4)
        #define TX_DMA_ENQUEUE_FLAGS_FLAGS_DONT_GEN_CRC     (1UL<<5)
        #define TX_DMA_ENQUEUE_FLAGS_FLAGS_LAST_PKT         (1UL<<6)
        #define TX_DMA_ENQUEUE_FLAGS_FLAGS_PKT_FRAG         (1UL<<7)
        #define TX_DMA_ENQUEUE_FLAGS_FLAGS_QUICK_CID_ENA    (1UL<<9)
        #define TX_DMA_ENQUEUE_FLAGS_FLAGS_QUICK_CID_TE        (0x3UL<<10)
        #define TX_DMA_ENQUEUE_FLAGS_FLAGS_RSVD_FUTURE_XI      (0x3UL<<10)
        #define TX_DMA_ENQUEUE_FLAGS_FLAGS_L5_PAGE_MODE     (1UL<<12)
        #define TX_DMA_ENQUEUE_FLAGS_FLAGS_COMPLETE         (1UL<<13)
        #define TX_DMA_ENQUEUE_FLAGS_FLAGS_RETRAN           (1UL<<14)
        #define TX_DMA_ENQUEUE_FLAGS_FLAGS_END_PADDING      (0xfUL<<16)
        #define TX_DMA_ENQUEUE_FLAGS_FLAGS_USAGE_CNT        (1UL<<20)
            #define TX_DMA_ENQUEUE_FLAGS_FLAGS_USAGE_CNT_AUTODECREMENT  (0UL<<20)
            #define TX_DMA_ENQUEUE_FLAGS_FLAGS_USAGE_CNT_DONOTDECREMENT  (1UL<<20)
        #define TX_DMA_ENQUEUE_FLAGS_FLAGS_BSEQ_INVLD       (1UL<<21)
        #define TX_DMA_ENQUEUE_FLAGS_FLAGS_WORK_AROUND      (0x3UL<<22)
        #define TX_DMA_ENQUEUE_FLAGS_FLAGS_HOLE_SZ          (0x3UL<<25)
            #define TX_DMA_ENQUEUE_FLAGS_FLAGS_HOLE_SZ_4    (0UL<<25)
            #define TX_DMA_ENQUEUE_FLAGS_FLAGS_HOLE_SZ_8    (1UL<<25)
            #define TX_DMA_ENQUEUE_FLAGS_FLAGS_HOLE_SZ_12   (2UL<<25)
            #define TX_DMA_ENQUEUE_FLAGS_FLAGS_HOLE_SZ_16   (3UL<<25)
        #define TX_DMA_ENQUEUE_FLAGS_FLAGS_HOLE0            (1UL<<28)
        #define TX_DMA_ENQUEUE_FLAGS_FLAGS_HOLE1            (1UL<<29)
        #define TX_DMA_ENQUEUE_FLAGS_FLAGS_HOLE2            (1UL<<30)

    u32_t tx_dma_enqueue_wd6;
        #define TX_DMA_ENQUEUE_NBYTES_VALUE                 (0x3fff<<16)
        #define TX_DMA_ENQUEUE_HOLE0_BOFF_VALUE             (0x3fff<<0)

    u32_t tx_dma_enqueue_wd7;
        #define TX_DMA_ENQUEUE_HOLE1_BOFF_VALUE             (0x3fff<<16)
        #define TX_DMA_ENQUEUE_HOLE2_BOFF_VALUE             (0x3fff<<0)

    u32_t tx_dma_enqueue_hole0_fill;
    u32_t tx_dma_enqueue_hole1_fill;
    u32_t tx_dma_enqueue_hole2_fill;
    u32_t tx_dma_enqueue_wd11;
        #define TX_DMA_ENQUEUE_TCMD_FNUM_VALUE              (0x3f<<24)
        #define TX_DMA_ENQUEUE_TXP_ACT_CMD                  (0xff<<16)

} tx_dma_enqueue_t;


/*
 *  tdma_reg definition
 *  offset: 0x5c00
 */
typedef struct tdma_reg
{
    u32_t tdma_command;
        #define TDMA_COMMAND_ENABLED                        (1UL<<0)
        #define TDMA_COMMAND_MASTER_ABORT                   (1UL<<4)
        #define TDMA_COMMAND_CS16_ERR                       (1UL<<5)
        #define TDMA_COMMAND_BAD_L2_LENGTH_ABORT            (1UL<<7)
        #define TDMA_COMMAND_MASK_CS1                       (1UL<<20)
        #define TDMA_COMMAND_MASK_CS2                       (1UL<<21)
        #define TDMA_COMMAND_MASK_CS3                       (1UL<<22)
        #define TDMA_COMMAND_MASK_CS4                       (1UL<<23)
        #define TDMA_COMMAND_FORCE_ILOCK_CKERR              (1UL<<24)
        #define TDMA_COMMAND_OFIFO_CLR                      (1UL<<30)
        #define TDMA_COMMAND_IFIFO_CLR                      (1UL<<31)

    u32_t tdma_status;
        #define TDMA_STATUS_DMA_WAIT                        (1UL<<0)
        #define TDMA_STATUS_PAYLOAD_WAIT                    (1UL<<1)
        #define TDMA_STATUS_PATCH_FTQ_WAIT                  (1UL<<2)
        #define TDMA_STATUS_LOCK_WAIT                       (1UL<<3)
        #define TDMA_STATUS_FTQ_ENTRY_CNT                   (1UL<<16)
        #define TDMA_STATUS_BURST_CNT                       (1UL<<17)
        #define TDMA_STATUS_MAX_IFIFO_DEPTH                 (0x3fUL<<20)
        #define TDMA_STATUS_OFIFO_OVERFLOW                  (1UL<<30)
        #define TDMA_STATUS_IFIFO_OVERFLOW                  (1UL<<31)

    u32_t tdma_config;
        #define TDMA_CONFIG_ONE_DMA                         (1UL<<0)
        #define TDMA_CONFIG_ONE_RECORD                      (1UL<<1)
        #define TDMA_CONFIG_NUM_DMA_CHAN                    (0x3UL<<2)
            #define TDMA_CONFIG_NUM_DMA_CHAN_0              (0UL<<2)
            #define TDMA_CONFIG_NUM_DMA_CHAN_1              (1UL<<2)
            #define TDMA_CONFIG_NUM_DMA_CHAN_2              (2UL<<2)
            #define TDMA_CONFIG_NUM_DMA_CHAN_3              (3UL<<2)
        #define TDMA_CONFIG_LIMIT_SZ                        (0xfUL<<4)
            #define TDMA_CONFIG_LIMIT_SZ_64                 (0UL<<4)
            #define TDMA_CONFIG_LIMIT_SZ_128                (4UL<<4)
            #define TDMA_CONFIG_LIMIT_SZ_256                (6UL<<4)
            #define TDMA_CONFIG_LIMIT_SZ_512                (8UL<<4)
        #define TDMA_CONFIG_LINE_SZ                         (0xfUL<<8)
            #define TDMA_CONFIG_LINE_SZ_64                  (0UL<<8)
            #define TDMA_CONFIG_LINE_SZ_128                 (4UL<<8)
            #define TDMA_CONFIG_LINE_SZ_256                 (6UL<<8)
            #define TDMA_CONFIG_LINE_SZ_512                 (8UL<<8)
        #define TDMA_CONFIG_ALIGN_ENA                       (1UL<<15)
        #define TDMA_CONFIG_CHK_L2_BD                       (1UL<<16)
        #define TDMA_CONFIG_CMPL_ENTRY                      (1UL<<17)
        #define TDMA_CONFIG_OFIFO_CMP                       (1UL<<19)
            #define TDMA_CONFIG_OFIFO_CMP_3                 (0UL<<19)
            #define TDMA_CONFIG_OFIFO_CMP_2                 (1UL<<19)
        #define TDMA_CONFIG_FIFO_CMP_TE                        (0xfUL<<20)
        #define TDMA_CONFIG_IFIFO_DEPTH_XI                     (0x7UL<<20)
            #define TDMA_CONFIG_IFIFO_DEPTH_0_XI               (0UL<<20)
            #define TDMA_CONFIG_IFIFO_DEPTH_4_XI               (1UL<<20)
            #define TDMA_CONFIG_IFIFO_DEPTH_8_XI               (2UL<<20)
            #define TDMA_CONFIG_IFIFO_DEPTH_16_XI              (3UL<<20)
            #define TDMA_CONFIG_IFIFO_DEPTH_32_XI              (4UL<<20)
            #define TDMA_CONFIG_IFIFO_DEPTH_64_XI              (5UL<<20)
        #define TDMA_CONFIG_FIFO_CMP_EN_XI                     (1UL<<23)
        #define TDMA_CONFIG_BYTES_OST_XI                       (0x7UL<<24)
            #define TDMA_CONFIG_BYTES_OST_512_XI               (0UL<<24)
            #define TDMA_CONFIG_BYTES_OST_1024_XI              (1UL<<24)
            #define TDMA_CONFIG_BYTES_OST_2048_XI              (2UL<<24)
            #define TDMA_CONFIG_BYTES_OST_4096_XI              (3UL<<24)
            #define TDMA_CONFIG_BYTES_OST_8192_XI              (4UL<<24)
            #define TDMA_CONFIG_BYTES_OST_16384_XI             (5UL<<24)
        #define TDMA_CONFIG_HC_BYPASS_XI                       (1UL<<27)
        #define TDMA_CONFIG_LCL_MRRS_XI                        (0x7UL<<28)
            #define TDMA_CONFIG_LCL_MRRS_128_XI                (0UL<<28)
            #define TDMA_CONFIG_LCL_MRRS_256_XI                (1UL<<28)
            #define TDMA_CONFIG_LCL_MRRS_512_XI                (2UL<<28)
            #define TDMA_CONFIG_LCL_MRRS_1024_XI               (3UL<<28)
            #define TDMA_CONFIG_LCL_MRRS_2048_XI               (4UL<<28)
            #define TDMA_CONFIG_LCL_MRRS_4096_XI               (5UL<<28)
        #define TDMA_CONFIG_LCL_MRRS_EN_XI                     (1UL<<31)

    u32_t tdma_payload_prod;
        #define TDMA_PAYLOAD_PROD_VALUE                     (0x1fffUL<<3)

    u32_t tdma_dbg_watchdog;
    u32_t tdma_dbg_trigger;
    u32_t unused_0[26];
    u32_t tdma_dmad_fsm;
        #define TDMA_DMAD_FSM_BD_INVLD                      (1UL<<0)
        #define TDMA_DMAD_FSM_PUSH                          (0xfUL<<4)
        #define TDMA_DMAD_FSM_ARB_TBDC                      (0x3UL<<8)
        #define TDMA_DMAD_FSM_ARB_CTX                       (1UL<<12)
        #define TDMA_DMAD_FSM_DR_INTF                       (1UL<<16)
        #define TDMA_DMAD_FSM_DMAD                          (0x7UL<<20)
        #define TDMA_DMAD_FSM_BD                            (0xfUL<<24)

    u32_t tdma_dmad_status;
        #define TDMA_DMAD_STATUS_RHOLD_PUSH_ENTRY           (0x3UL<<0)
        #define TDMA_DMAD_STATUS_RHOLD_DMAD_ENTRY           (0x3UL<<4)
        #define TDMA_DMAD_STATUS_RHOLD_BD_ENTRY             (0x3UL<<8)
        #define TDMA_DMAD_STATUS_IFTQ_ENUM                  (0xfUL<<12)

    u32_t tdma_dr_intf_fsm;
        #define TDMA_DR_INTF_FSM_L2_COMP                    (0x3UL<<0)
        #define TDMA_DR_INTF_FSM_TPATQ                      (0x7UL<<4)
        #define TDMA_DR_INTF_FSM_TPBUF                      (0x3UL<<8)
        #define TDMA_DR_INTF_FSM_DR_BUF                     (0x7UL<<12)
        #define TDMA_DR_INTF_FSM_DMAD                       (0x7UL<<16)

    u32_t tdma_dr_intf_status;
        #define TDMA_DR_INTF_STATUS_HOLE_PHASE              (0x7UL<<0)
        #define TDMA_DR_INTF_STATUS_DATA_AVAIL              (0x3UL<<4)
        #define TDMA_DR_INTF_STATUS_SHIFT_ADDR              (0x7UL<<8)
        #define TDMA_DR_INTF_STATUS_NXT_PNTR                (0xfUL<<12)
        #define TDMA_DR_INTF_STATUS_BYTE_COUNT              (0x7UL<<16)

    u32_t tdma_push_fsm;
    u32_t tdma_bd_if_debug;
    u32_t tdma_dmad_if_debug;
    u32_t tdma_ctx_if_debug;
    u32_t tdma_tpbuf_if_debug;
    u32_t tdma_dr_if_debug;
    u32_t tdma_tpatq_if_debug;
    u32_t tdma_tdma_ilock_cksum;
        #define TDMA_TDMA_ILOCK_CKSUM_CALCULATED            (0xffffUL<<0)
        #define TDMA_TDMA_ILOCK_CKSUM_EXPECTED              (0xffffUL<<16)

    u32_t tdma_tdma_pcie_cksum;
        #define TDMA_TDMA_PCIE_CKSUM_CALCULATED             (0xffffUL<<0)
        #define TDMA_TDMA_PCIE_CKSUM_EXPECTED               (0xffffUL<<16)

    u32_t unused_1[195];
    tx_dma_enqueue_t tdma_tdmaq;
    u32_t unused_2[2];
    u32_t tdma_ftq_cmd;
        #define TDMA_FTQ_CMD_OFFSET                         (0x3ffUL<<0)
        #define TDMA_FTQ_CMD_WR_TOP                         (1UL<<10)
            #define TDMA_FTQ_CMD_WR_TOP_0                   (0UL<<10)
            #define TDMA_FTQ_CMD_WR_TOP_1                   (1UL<<10)
        #define TDMA_FTQ_CMD_SFT_RESET                      (1UL<<25)
        #define TDMA_FTQ_CMD_RD_DATA                        (1UL<<26)
        #define TDMA_FTQ_CMD_ADD_INTERVEN                   (1UL<<27)
        #define TDMA_FTQ_CMD_ADD_DATA                       (1UL<<28)
        #define TDMA_FTQ_CMD_INTERVENE_CLR                  (1UL<<29)
        #define TDMA_FTQ_CMD_POP                            (1UL<<30)
        #define TDMA_FTQ_CMD_BUSY                           (1UL<<31)

    u32_t tdma_ftq_ctl;
        #define TDMA_FTQ_CTL_INTERVENE                      (1UL<<0)
        #define TDMA_FTQ_CTL_OVERFLOW                       (1UL<<1)
        #define TDMA_FTQ_CTL_FORCE_INTERVENE                (1UL<<2)
        #define TDMA_FTQ_CTL_MAX_DEPTH                      (0x3ffUL<<12)
        #define TDMA_FTQ_CTL_CUR_DEPTH                      (0x3ffUL<<22)

} tdma_reg_t;

typedef tdma_reg_t tx_dma_reg_t;

/*
 *  dbu_reg definition
 *  offset: 0x6000
 */
typedef struct dbu_reg
{
    u32_t dbu_cmd;
        #define DBU_CMD_ENABLE                              (1UL<<0)
        #define DBU_CMD_RX_ERROR                            (1UL<<1)
        #define DBU_CMD_RX_OVERFLOW                         (1UL<<2)

    u32_t dbu_status;
        #define DBU_STATUS_RXDATA_VALID                     (1UL<<0)
        #define DBU_STATUS_TXDATA_OCCUPIED                  (1UL<<1)

    u32_t dbu_config;
        #define DBU_CONFIG_TIMING_OVERRIDE                  (1UL<<0)
        #define DBU_CONFIG_DEBUGSM_ENABLE                   (1UL<<1)
        #define DBU_CONFIG_CRLF_ENABLE                      (1UL<<2)

    u32_t dbu_timing;
        #define DBU_TIMING_FB_SMPL_OFFSET                   (0xffffUL<<0)
        #define DBU_TIMING_BIT_INTERVAL                     (0xffffUL<<16)

    u32_t dbu_rxdata;
        #define DBU_RXDATA_VALUE                            (0xffUL<<0)
        #define DBU_RXDATA_ERROR                            (1UL<<8)

    u32_t dbu_txdata;
        #define DBU_TXDATA_VALUE                            (0xffUL<<0)

    u32_t unused_0[250];
} dbu_reg_t;


/*
 *  debug_reg definition
 *  offset: 0x7000
 */
typedef struct debug_reg
{
    u32_t debug_command;
    u32_t unused_0[511];
} debug_reg_t;


/*
 *  tx_assembler_enqueue definition
 *  offset: 0000
 */
typedef struct tx_assembler_enqueue
{
    u32_t tx_assembler_enqueue_wd0;
        #define TX_ASSEMBLER_ENQUEUE_HDR_SKIP_VALUE         (0xff<<16)
        #define TX_ASSEMBLER_ENQUEUE_HDR_POST_SKIP_VALUE    (0xff<<0)

    u32_t tx_assembler_enqueue_wd1;
        #define TX_ASSEMBLER_ENQUEUE_HDR_SIZE_VALUE_TE         (0xff<<16)
        #define TX_ASSEMBLER_ENQUEUE_HDR_SIZE_VALUE_XI         (0x1fff<<16)
        #define TX_ASSEMBLER_ENQUEUE_PAYLOAD_SKIP_VALUE     (0x3fff<<0)

    u32_t tx_assembler_enqueue_wd2;
        #define TX_ASSEMBLER_ENQUEUE_PAYLOAD_SIZE_VALUE     (0x3fff<<16)
        #define TX_ASSEMBLER_ENQUEUE_FLAGS_PKT_END          (1<<0)
        #define TX_ASSEMBLER_ENQUEUE_FLAGS_MGMT_PACKET      (1<<1)
        #define TX_ASSEMBLER_ENQUEUE_FLAGS_CATCHUP_PACKET   (1<<2)
        #define TX_ASSEMBLER_ENQUEUE_FLAGS_DONT_GEN_CRC     (1<<3)
        #define TX_ASSEMBLER_ENQUEUE_FLAGS_DROP             (1<<4)
        #define TX_ASSEMBLER_ENQUEUE_FLAGS_RESERVED         (0x3<<5)
        #define TX_ASSEMBLER_ENQUEUE_FLAGS_MGMT_PKT_TAG_TE     (0xf<<8)
        #define TX_ASSEMBLER_ENQUEUE_FLAGS_MGMT_PKT_TAG_XI     (0x1f<<8)
        #define TX_ASSEMBLER_ENQUEUE_FLAGS_CS16_VLD_XI         (1<<15)

    u32_t tx_assembler_enqueue_wd3;
        #define TX_ASSEMBLER_ENQUEUE_CS16_VALUE             (0xffff<<16)

} tx_assembler_enqueue_t;


/*
 *  tas_reg definition
 *  offset: 0x1c0000
 */
typedef struct tas_reg
{
    u32_t tas_command;
        #define TAS_COMMAND_TAS_ENABLE                      (1UL<<0)
        #define TAS_COMMAND_TPBUF_ENABLE                    (1UL<<1)
        #define TAS_COMMAND_THBUF_ENABLE                    (1UL<<2)
        #define TAS_COMMAND_PKT_END_TOSHORT_ABORT           (1UL<<5)
        #define TAS_COMMAND_THBUF_INIT                      (1UL<<6)
        #define TAS_COMMAND_TPBUF_INIT                      (1UL<<7)
        #define TAS_COMMAND_RESET_STATE                     (1UL<<31)

    u32_t tas_status;
        #define TAS_STATUS_ACPI_MODE                        (1UL<<0)
        #define TAS_STATUS_KNUM_TAG                         (0xfUL<<4)
        #define TAS_STATUS_MGMT_TAG_TE                         (0xfUL<<8)
        #define TAS_STATUS_MGMT_TAG_XI                         (0x1fUL<<8)
        #define TAS_STATUS_MAC_PKTS_STAT                    (1UL<<16)
        #define TAS_STATUS_CU_PKTS_STAT                     (1UL<<17)

    u32_t tas_config;
        #define TAS_CONFIG_PAYLOAD_MAX_LOW                  (0x3ffUL<<0)
        #define TAS_CONFIG_PAYLOAD_MAX                      (0x1fUL<<10)

    u32_t tas_payload_cons;
        #define TAS_PAYLOAD_CONS_VALUE                      (0x1fffUL<<3)

    u32_t tas_header_cons;
        #define TAS_HEADER_CONS_VALUE                       (0x7ffUL<<3)

    u32_t tas_debug_vect_peek;
    u32_t unused_0[234];
    tx_assembler_enqueue_t tas_tasq;
    u32_t unused_1[10];
    u32_t tas_ftq_cmd;
        #define TAS_FTQ_CMD_OFFSET                          (0x3ffUL<<0)
        #define TAS_FTQ_CMD_WR_TOP                          (1UL<<10)
            #define TAS_FTQ_CMD_WR_TOP_0                    (0UL<<10)
            #define TAS_FTQ_CMD_WR_TOP_1                    (1UL<<10)
        #define TAS_FTQ_CMD_SFT_RESET                       (1UL<<25)
        #define TAS_FTQ_CMD_RD_DATA                         (1UL<<26)
        #define TAS_FTQ_CMD_ADD_INTERVEN                    (1UL<<27)
        #define TAS_FTQ_CMD_ADD_DATA                        (1UL<<28)
        #define TAS_FTQ_CMD_INTERVENE_CLR                   (1UL<<29)
        #define TAS_FTQ_CMD_POP                             (1UL<<30)
        #define TAS_FTQ_CMD_BUSY                            (1UL<<31)

    u32_t tas_ftq_ctl;
        #define TAS_FTQ_CTL_INTERVENE                       (1UL<<0)
        #define TAS_FTQ_CTL_OVERFLOW                        (1UL<<1)
        #define TAS_FTQ_CTL_FORCE_INTERVENE                 (1UL<<2)
        #define TAS_FTQ_CTL_MAX_DEPTH                       (0x3ffUL<<12)
        #define TAS_FTQ_CTL_CUR_DEPTH                       (0x3ffUL<<22)

    u32_t unused_2[32512];
    u32_t tas_thbuf[2048];
    u32_t unused_3[14336];
    u32_t tas_tpbuf[6144];
    u32_t unused_4[10240];
} tas_reg_t;

typedef tas_reg_t tx_assembler_reg_t;

/*
 *  hc_reg definition
 *  offset: 0x6800
 */
typedef struct hc_reg
{
    u32_t hc_command;
        #define HC_COMMAND_ENABLE                           (1UL<<0)
        #define HC_COMMAND_SKIP_ABORT                       (1UL<<4)
        #define HC_COMMAND_COAL_NOW                         (1UL<<16)
        #define HC_COMMAND_COAL_NOW_WO_INT                  (1UL<<17)
        #define HC_COMMAND_STATS_NOW                        (1UL<<18)
        #define HC_COMMAND_FORCE_INT                        (0x3UL<<19)
            #define HC_COMMAND_FORCE_INT_NULL               (0UL<<19)
            #define HC_COMMAND_FORCE_INT_HIGH               (1UL<<19)
            #define HC_COMMAND_FORCE_INT_LOW                (2UL<<19)
            #define HC_COMMAND_FORCE_INT_FREE               (3UL<<19)
        #define HC_COMMAND_CLR_STAT_NOW                     (1UL<<21)
        #define HC_COMMAND_MAIN_PWR_INT                     (1UL<<22)
        #define HC_COMMAND_COAL_ON_NEXT_EVENT               (1UL<<27)

    u32_t hc_status;
        #define HC_STATUS_MASTER_ABORT                      (1UL<<0)
        #define HC_STATUS_PARITY_ERROR_STATE                (1UL<<1)
        #define HC_STATUS_PCI_CLK_CNT_STAT                  (1UL<<16)
        #define HC_STATUS_CORE_CLK_CNT_STAT                 (1UL<<17)
        #define HC_STATUS_NUM_STATUS_BLOCKS_STAT            (1UL<<18)
        #define HC_STATUS_NUM_INT_GEN_STAT                  (1UL<<19)
        #define HC_STATUS_NUM_INT_MBOX_WR_STAT              (1UL<<20)
        #define HC_STATUS_CORE_CLKS_TO_HW_INTACK_STAT       (1UL<<23)
        #define HC_STATUS_CORE_CLKS_TO_SW_INTACK_STAT       (1UL<<24)
        #define HC_STATUS_CORE_CLKS_DURING_SW_INTACK_STAT   (1UL<<25)

    u32_t hc_config;
        #define HC_CONFIG_COLLECT_STATS                     (1UL<<0)
        #define HC_CONFIG_RX_TMR_MODE                       (1UL<<1)
        #define HC_CONFIG_TX_TMR_MODE                       (1UL<<2)
        #define HC_CONFIG_COM_TMR_MODE                      (1UL<<3)
        #define HC_CONFIG_CMD_TMR_MODE                      (1UL<<4)
        #define HC_CONFIG_STATISTIC_PRIORITY                (1UL<<5)
        #define HC_CONFIG_STATUS_PRIORITY                   (1UL<<6)
        #define HC_CONFIG_STAT_MEM_ADDR                     (0xffUL<<8)
        #define HC_CONFIG_PER_MODE                          (1UL<<16)
        #define HC_CONFIG_ONE_SHOT                          (1UL<<17)
        #define HC_CONFIG_USE_INT_PARAM                     (1UL<<18)
        #define HC_CONFIG_SET_MASK_AT_RD                    (1UL<<19)
        #define HC_CONFIG_PER_COLLECT_LIMIT                 (0xfUL<<20)
        #define HC_CONFIG_SB_ADDR_INC                       (0x7UL<<24)
            #define HC_CONFIG_SB_ADDR_INC_64B               (0UL<<24)
            #define HC_CONFIG_SB_ADDR_INC_128B              (1UL<<24)
            #define HC_CONFIG_SB_ADDR_INC_256B              (2UL<<24)
            #define HC_CONFIG_SB_ADDR_INC_512B              (3UL<<24)
            #define HC_CONFIG_SB_ADDR_INC_1024B             (4UL<<24)
            #define HC_CONFIG_SB_ADDR_INC_2048B             (5UL<<24)
            #define HC_CONFIG_SB_ADDR_INC_4096B             (6UL<<24)
            #define HC_CONFIG_SB_ADDR_INC_8192B             (7UL<<24)
        #define HC_CONFIG_GEN_STAT_AVG_INTR                 (1UL<<29)
        #define HC_CONFIG_UNMASK_ALL                        (1UL<<30)
        #define HC_CONFIG_TX_SEL                            (1UL<<31)

    u32_t hc_attn_bits_enable;
    u32_t hc_status_addr_l;
    u32_t hc_status_addr_h;
    u32_t hc_statistics_addr_l;
    u32_t hc_statistics_addr_h;
    u32_t hc_tx_quick_cons_trip;
        #define HC_TX_QUICK_CONS_TRIP_VALUE                 (0xffUL<<0)
        #define HC_TX_QUICK_CONS_TRIP_INT                   (0xffUL<<16)

    u32_t hc_comp_prod_trip;
        #define HC_COMP_PROD_TRIP_VALUE                     (0xffUL<<0)
        #define HC_COMP_PROD_TRIP_INT                       (0xffUL<<16)

    u32_t hc_rx_quick_cons_trip;
        #define HC_RX_QUICK_CONS_TRIP_VALUE                 (0xffUL<<0)
        #define HC_RX_QUICK_CONS_TRIP_INT                   (0xffUL<<16)

    u32_t hc_rx_ticks;
        #define HC_RX_TICKS_VALUE                           (0x3ffUL<<0)
        #define HC_RX_TICKS_INT                             (0x3ffUL<<16)

    u32_t hc_tx_ticks;
        #define HC_TX_TICKS_VALUE                           (0x3ffUL<<0)
        #define HC_TX_TICKS_INT                             (0x3ffUL<<16)

    u32_t hc_com_ticks;
        #define HC_COM_TICKS_VALUE                          (0x3ffUL<<0)
        #define HC_COM_TICKS_INT                            (0x3ffUL<<16)

    u32_t hc_cmd_ticks;
        #define HC_CMD_TICKS_VALUE                          (0x3ffUL<<0)
        #define HC_CMD_TICKS_INT                            (0x3ffUL<<16)

    u32_t hc_periodic_ticks;
        #define HC_PERIODIC_TICKS_HC_PERIODIC_TICKS         (0xffffUL<<0)
        #define HC_PERIODIC_TICKS_HC_INT_PERIODIC_TICKS     (0xffffUL<<16)

    u32_t hc_stat_collect_ticks;
        #define HC_STAT_COLLECT_TICKS_HC_STAT_COLL_TICKS    (0xffUL<<4)

    u32_t hc_stats_ticks;
        #define HC_STATS_TICKS_HC_STAT_TICKS                (0xffffUL<<8)

    u32_t hc_stats_interrupt_status;
        #define HC_STATS_INTERRUPT_STATUS_SB_STATUS         (0x1ffUL<<0)
        #define HC_STATS_INTERRUPT_STATUS_INT_STATUS        (0x1ffUL<<16)

    u32_t hc_stat_mem_data;
    u32_t hc_stat_gen_sel_0;
        #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TE                 (0x7fUL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT0_TE   (0UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT1_TE   (1UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT2_TE   (2UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT3_TE   (3UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT4_TE   (4UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT5_TE   (5UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT6_TE   (6UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT7_TE   (7UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT8_TE   (8UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT9_TE   (9UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT10_TE  (10UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT11_TE  (11UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TXP_STAT0_TE   (12UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TXP_STAT1_TE   (13UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TXP_STAT2_TE   (14UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TXP_STAT3_TE   (15UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TXP_STAT4_TE   (16UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TXP_STAT5_TE   (17UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TXP_STAT6_TE   (18UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TXP_STAT7_TE   (19UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_COM_STAT0_TE   (20UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_COM_STAT1_TE   (21UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_COM_STAT2_TE   (22UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_COM_STAT3_TE   (23UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_COM_STAT4_TE   (24UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_COM_STAT5_TE   (25UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_COM_STAT6_TE   (26UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_COM_STAT7_TE   (27UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_COM_STAT8_TE   (28UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_COM_STAT9_TE   (29UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_COM_STAT10_TE  (30UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_COM_STAT11_TE  (31UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TPAT_STAT0_TE  (32UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TPAT_STAT1_TE  (33UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TPAT_STAT2_TE  (34UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TPAT_STAT3_TE  (35UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CP_STAT0_TE    (36UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CP_STAT1_TE    (37UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CP_STAT2_TE    (38UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CP_STAT3_TE    (39UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CP_STAT4_TE    (40UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CP_STAT5_TE    (41UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CP_STAT6_TE    (42UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CP_STAT7_TE    (43UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_MCP_STAT0_TE   (44UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_MCP_STAT1_TE   (45UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_MCP_STAT2_TE   (46UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_MCP_STAT3_TE   (47UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_MCP_STAT4_TE   (48UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_MCP_STAT5_TE   (49UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_MCP_STAT6_TE   (50UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_MCP_STAT7_TE   (51UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_PCI_CLK_CNT_TE  (52UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CORE_CLK_CNT_TE  (53UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_STATUS_BLOCKS_TE  (54UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_GEN_TE  (55UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_MBOX_WR_TE  (56UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_HW_INTACK_TE  (59UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_SW_INTACK_TE  (60UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_DURING_SW_INTACK_TE  (61UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TSCH_CMD_CNT_TE  (62UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TSCH_SLOT_CNT_TE  (63UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CSCH_CMD_CNT_TE  (64UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CSCH_SLOT_CNT_TE  (65UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RLUPQ_VALID_CNT_TE  (66UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RXPQ_VALID_CNT_TE  (67UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RXPCQ_VALID_CNT_TE  (68UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RV2PPQ_VALID_CNT_TE  (69UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RV2PMQ_VALID_CNT_TE  (70UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RV2PTQ_VALID_CNT_TE  (71UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RDMAQ_VALID_CNT_TE  (72UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TSCHQ_VALID_CNT_TE  (73UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TBDRQ_VALID_CNT_TE  (74UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TXPQ_VALID_CNT_TE  (75UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TDMAQ_VALID_CNT_TE  (76UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TPATQ_VALID_CNT_TE  (77UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TASQ_VALID_CNT_TE  (78UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CSQ_VALID_CNT_TE  (79UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CPQ_VALID_CNT_TE  (80UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_COMXQ_VALID_CNT_TE  (81UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_COMTQ_VALID_CNT_TE  (82UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_COMQ_VALID_CNT_TE  (83UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_MGMQ_VALID_CNT_TE  (84UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_DMAE_READ_TRANSFERS_CNT_TE  (85UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_DMAE_READ_DELAY_PCI_CLKS_CNT_TE  (86UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_DMAE_BIG_READ_TRANSFERS_CNT_TE  (87UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_DMAE_BIG_READ_DELAY_PCI_CLKS_CNT_TE  (88UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_DMAE_BIG_READ_RETRY_AFTER_DATA_CNT_TE  (89UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_DMAE_WRITE_TRANSFERS_CNT_TE  (90UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_DMAE_WRITE_DELAY_PCI_CLKS_CNT_TE  (91UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_DMAE_BIG_WRITE_TRANSFERS_CNT_TE  (92UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_DMAE_BIG_WRITE_DELAY_PCI_CLKS_CNT_TE  (93UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_DMAE_BIG_WRITE_RETRY_AFTER_DATA_CNT_TE  (94UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CTX_WR_CNT64_TE  (95UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CTX_RD_CNT64_TE  (96UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CTX_ACC_STALL_CLKS_TE  (97UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CTX_LOCK_STALL_CLKS_TE  (98UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_MBQ_CTX_ACCESS_STAT_TE  (99UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_MBQ_CTX_ACCESS64_STAT_TE  (100UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_MBQ_PCI_STALL_STAT_TE  (101UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TBDR_FTQ_ENTRY_CNT_TE  (102UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TBDR_BURST_CNT_TE  (103UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TDMA_FTQ_ENTRY_CNT_TE  (104UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TDMA_BURST_CNT_TE  (105UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RDMA_FTQ_ENTRY_CNT_TE  (106UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RDMA_BURST_CNT_TE  (107UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RLUP_MATCH_CNT_TE  (108UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TMR_POLL_PASS_CNT_TE  (109UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TMR_TMR1_CNT_TE  (110UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TMR_TMR2_CNT_TE  (111UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TMR_TMR3_CNT_TE  (112UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TMR_TMR4_CNT_TE  (113UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TMR_TMR5_CNT_TE  (114UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RV2P_STAT0_TE  (115UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RV2P_STAT1_TE  (116UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RV2P_STAT2_TE  (117UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RV2P_STAT3_TE  (118UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RV2P_STAT4_TE  (119UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RV2P_STAT5_TE  (120UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RBDC_PROC1_MISS_TE  (121UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RBDC_PROC2_MISS_TE  (122UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RBDC_BURST_CNT_TE  (127UL<<0)
        #define HC_STAT_GEN_SEL_0_GEN_SEL_1_TE                 (0x7fUL<<8)
        #define HC_STAT_GEN_SEL_0_GEN_SEL_2_TE                 (0x7fUL<<16)
        #define HC_STAT_GEN_SEL_0_GEN_SEL_3_TE                 (0x7fUL<<24)
        #define HC_STAT_GEN_SEL_0_GEN_SEL_0_XI                 (0xffUL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT0_XI   (0UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT1_XI   (1UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT2_XI   (2UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT3_XI   (3UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT4_XI   (4UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT5_XI   (5UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT6_XI   (6UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT7_XI   (7UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT8_XI   (8UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT9_XI   (9UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT10_XI  (10UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT11_XI  (11UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TXP_STAT0_XI   (12UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TXP_STAT1_XI   (13UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TXP_STAT2_XI   (14UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TXP_STAT3_XI   (15UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TXP_STAT4_XI   (16UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TXP_STAT5_XI   (17UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TXP_STAT6_XI   (18UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TXP_STAT7_XI   (19UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_COM_STAT0_XI   (20UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_COM_STAT1_XI   (21UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_COM_STAT2_XI   (22UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_COM_STAT3_XI   (23UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_COM_STAT4_XI   (24UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_COM_STAT5_XI   (25UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_COM_STAT6_XI   (26UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_COM_STAT7_XI   (27UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_COM_STAT8_XI   (28UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_COM_STAT9_XI   (29UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_COM_STAT10_XI  (30UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_COM_STAT11_XI  (31UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TPAT_STAT0_XI  (32UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TPAT_STAT1_XI  (33UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TPAT_STAT2_XI  (34UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TPAT_STAT3_XI  (35UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CP_STAT0_XI    (36UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CP_STAT1_XI    (37UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CP_STAT2_XI    (38UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CP_STAT3_XI    (39UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CP_STAT4_XI    (40UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CP_STAT5_XI    (41UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CP_STAT6_XI    (42UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CP_STAT7_XI    (43UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_MCP_STAT0_XI   (44UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_MCP_STAT1_XI   (45UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_MCP_STAT2_XI   (46UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_MCP_STAT3_XI   (47UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_MCP_STAT4_XI   (48UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_MCP_STAT5_XI   (49UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_MCP_STAT6_XI   (50UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_MCP_STAT7_XI   (51UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UMP_RX_FRAME_DROP_XI  (52UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CORE_CLK_CNT_XI  (53UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_STATUS_BLOCKS_XI  (54UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_GEN_XI  (55UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_MBOX_WR_XI  (56UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S0_XI   (57UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S1_XI   (58UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_HW_INTACK_XI  (59UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_SW_INTACK_XI  (60UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_DURING_SW_INTACK_XI  (61UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TSCH_CMD_CNT_XI  (62UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TSCH_SLOT_CNT_XI  (63UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CSCH_CMD_CNT_XI  (64UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CSCH_SLOT_CNT_XI  (65UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RLUPQ_VALID_CNT_XI  (66UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RXPQ_VALID_CNT_XI  (67UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RXPCQ_VALID_CNT_XI  (68UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RV2PPQ_VALID_CNT_XI  (69UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RV2PMQ_VALID_CNT_XI  (70UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RV2PTQ_VALID_CNT_XI  (71UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RDMAQ_VALID_CNT_XI  (72UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TSCHQ_VALID_CNT_XI  (73UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TBDRQ_VALID_CNT_XI  (74UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TXPQ_VALID_CNT_XI  (75UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TDMAQ_VALID_CNT_XI  (76UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TPATQ_VALID_CNT_XI  (77UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TASQ_VALID_CNT_XI  (78UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CSQ_VALID_CNT_XI  (79UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CPQ_VALID_CNT_XI  (80UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_COMXQ_VALID_CNT_XI  (81UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_COMTQ_VALID_CNT_XI  (82UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_COMQ_VALID_CNT_XI  (83UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_MGMQ_VALID_CNT_XI  (84UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S2_XI   (85UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S3_XI   (86UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S4_XI   (87UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S5_XI   (88UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S6_XI   (89UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S7_XI   (90UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S8_XI   (91UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S9_XI   (92UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S10_XI  (93UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_MQ_IDB_OFLOW_XI  (94UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CTX_WR_CNT64_XI  (95UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CTX_RD_CNT64_XI  (96UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CTX_ACC_STALL_CLKS_XI  (97UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CTX_LOCK_STALL_CLKS_XI  (98UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_MBQ_CTX_ACCESS_STAT_XI  (99UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_MBQ_CTX_ACCESS64_STAT_XI  (100UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_MBQ_PCI_STALL_STAT_XI  (101UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TBDR_FTQ_ENTRY_CNT_XI  (102UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TBDR_BURST_CNT_XI  (103UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TDMA_FTQ_ENTRY_CNT_XI  (104UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TDMA_BURST_CNT_XI  (105UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RDMA_FTQ_ENTRY_CNT_XI  (106UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RDMA_BURST_CNT_XI  (107UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RLUP_MATCH_CNT_XI  (108UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TMR_POLL_PASS_CNT_XI  (109UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TMR_TMR1_CNT_XI  (110UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TMR_TMR2_CNT_XI  (111UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TMR_TMR3_CNT_XI  (112UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TMR_TMR4_CNT_XI  (113UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_TMR_TMR5_CNT_XI  (114UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RV2P_STAT0_XI  (115UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RV2P_STAT1_XI  (116UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RV2P_STAT2_XI  (117UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RV2P_STAT3_XI  (118UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RV2P_STAT4_XI  (119UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RV2P_STAT5_XI  (120UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RBDC_PROC1_MISS_XI  (121UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RBDC_PROC2_MISS_XI  (122UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CTX_BLK_RD_CNT_XI  (123UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CTX_BLK_WR_CNT_XI  (124UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CTX_HITS_XI    (125UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_CTX_MISSES_XI  (126UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RBDC_BURST_CNT_XI  (127UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_STATUS_BLOCKS_VEC1_XI  (128UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_GEN_VEC1_XI  (129UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_MBOX_WR_VEC1_XI  (130UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_HW_INTACK_VEC1_XI  (131UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_SW_INTACK_VEC1_XI  (132UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_DURING_SW_INTACK_VEC1_XI  (133UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_STATUS_BLOCKS_VEC2_XI  (134UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_GEN_VEC2_XI  (135UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_MBOX_WR_VEC2_XI  (136UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_HW_INTACK_VEC2_XI  (137UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_SW_INTACK_VEC2_XI  (138UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_DURING_SW_INTACK_VEC2_XI  (139UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_STATUS_BLOCKS_VEC3_XI  (140UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_GEN_VEC3_XI  (141UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_MBOX_WR_VEC3_XI  (142UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_HW_INTACK_VEC3_XI  (143UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_SW_INTACK_VEC3_XI  (144UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_DURING_SW_INTACK_VEC3_XI  (145UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_STATUS_BLOCKS_VEC4_XI  (146UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_GEN_VEC4_XI  (147UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_MBOX_WR_VEC4_XI  (148UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_HW_INTACK_VEC4_XI  (149UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_SW_INTACK_VEC4_XI  (150UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_DURING_SW_INTACK_VEC4_XI  (151UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_STATUS_BLOCKS_VEC5_XI  (152UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_GEN_VEC5_XI  (153UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_MBOX_WR_VEC5_XI  (154UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_HW_INTACK_VEC5_XI  (155UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_SW_INTACK_VEC5_XI  (156UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_DURING_SW_INTACK_VEC5_XI  (157UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_STATUS_BLOCKS_VEC6_XI  (158UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_GEN_VEC6_XI  (159UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_MBOX_WR_VEC6_XI  (160UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_HW_INTACK_VEC6_XI  (161UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_SW_INTACK_VEC6_XI  (162UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_DURING_SW_INTACK_VEC6_XI  (163UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_STATUS_BLOCKS_VEC7_XI  (164UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_GEN_VEC7_XI  (165UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_MBOX_WR_VEC7_XI  (166UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_HW_INTACK_VEC7_XI  (167UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_SW_INTACK_VEC7_XI  (168UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_DURING_SW_INTACK_VEC7_XI  (169UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_STATUS_BLOCKS_VEC8_XI  (170UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_GEN_VEC8_XI  (171UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_MBOX_WR_VEC8_XI  (172UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_HW_INTACK_VEC8_XI  (173UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_SW_INTACK_VEC8_XI  (174UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_DURING_SW_INTACK_VEC8_XI  (175UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RV2PCS_CMD_CNT_XI  (176UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RV2PCS_SLOT_CNT_XI  (177UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_RV2PCSQ_VALID_CNT_XI  (178UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S15_XI  (179UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S16_XI  (180UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S17_XI  (181UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S18_XI  (182UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S19_XI  (183UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S20_XI  (184UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S21_XI  (185UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S22_XI  (186UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S23_XI  (187UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S24_XI  (188UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S25_XI  (189UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S26_XI  (190UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S27_XI  (191UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S28_XI  (192UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S29_XI  (193UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S30_XI  (194UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S31_XI  (195UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S32_XI  (196UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S33_XI  (197UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S34_XI  (198UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S35_XI  (199UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S36_XI  (200UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S37_XI  (201UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S38_XI  (202UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S39_XI  (203UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S40_XI  (204UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S41_XI  (205UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S42_XI  (206UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S43_XI  (207UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S44_XI  (208UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S45_XI  (209UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S46_XI  (210UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S47_XI  (211UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S48_XI  (212UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S49_XI  (213UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S50_XI  (214UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S51_XI  (215UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S52_XI  (216UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S53_XI  (217UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S54_XI  (218UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S55_XI  (219UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S56_XI  (220UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S57_XI  (221UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S58_XI  (222UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S59_XI  (223UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S60_XI  (224UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S61_XI  (225UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S62_XI  (226UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S63_XI  (227UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S64_XI  (228UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S65_XI  (229UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S66_XI  (230UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S67_XI  (231UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S68_XI  (232UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S69_XI  (233UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S70_XI  (234UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S71_XI  (235UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S72_XI  (236UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S73_XI  (237UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S74_XI  (238UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S75_XI  (239UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S76_XI  (240UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S77_XI  (241UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S78_XI  (242UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S79_XI  (243UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S80_XI  (244UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S81_XI  (245UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S82_XI  (246UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S83_XI  (247UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S84_XI  (248UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S85_XI  (249UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S86_XI  (250UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S87_XI  (251UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S88_XI  (252UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S89_XI  (253UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S90_XI  (254UL<<0)
            #define HC_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S91_XI  (255UL<<0)
        #define HC_STAT_GEN_SEL_0_GEN_SEL_1_XI                 (0xffUL<<8)
        #define HC_STAT_GEN_SEL_0_GEN_SEL_2_XI                 (0xffUL<<16)
        #define HC_STAT_GEN_SEL_0_GEN_SEL_3_XI                 (0xffUL<<24)

    u32_t hc_stat_gen_sel_1;
        #define HC_STAT_GEN_SEL_1_GEN_SEL_4_TE                 (0x7fUL<<0)
        #define HC_STAT_GEN_SEL_1_GEN_SEL_5_TE                 (0x7fUL<<8)
        #define HC_STAT_GEN_SEL_1_GEN_SEL_6_TE                 (0x7fUL<<16)
        #define HC_STAT_GEN_SEL_1_GEN_SEL_7_TE                 (0x7fUL<<24)
        #define HC_STAT_GEN_SEL_1_GEN_SEL_4_XI                 (0xffUL<<0)
        #define HC_STAT_GEN_SEL_1_GEN_SEL_5_XI                 (0xffUL<<8)
        #define HC_STAT_GEN_SEL_1_GEN_SEL_6_XI                 (0xffUL<<16)
        #define HC_STAT_GEN_SEL_1_GEN_SEL_7_XI                 (0xffUL<<24)

    u32_t hc_stat_gen_sel_2;
        #define HC_STAT_GEN_SEL_2_GEN_SEL_8_TE                 (0x7fUL<<0)
        #define HC_STAT_GEN_SEL_2_GEN_SEL_9_TE                 (0x7fUL<<8)
        #define HC_STAT_GEN_SEL_2_GEN_SEL_10_TE                (0x7fUL<<16)
        #define HC_STAT_GEN_SEL_2_GEN_SEL_11_TE                (0x7fUL<<24)
        #define HC_STAT_GEN_SEL_2_GEN_SEL_8_XI                 (0xffUL<<0)
        #define HC_STAT_GEN_SEL_2_GEN_SEL_9_XI                 (0xffUL<<8)
        #define HC_STAT_GEN_SEL_2_GEN_SEL_10_XI                (0xffUL<<16)
        #define HC_STAT_GEN_SEL_2_GEN_SEL_11_XI                (0xffUL<<24)

    u32_t hc_stat_gen_sel_3;
        #define HC_STAT_GEN_SEL_3_GEN_SEL_12_TE                (0x7fUL<<0)
        #define HC_STAT_GEN_SEL_3_GEN_SEL_13_TE                (0x7fUL<<8)
        #define HC_STAT_GEN_SEL_3_GEN_SEL_14_TE                (0x7fUL<<16)
        #define HC_STAT_GEN_SEL_3_GEN_SEL_15_TE                (0x7fUL<<24)
        #define HC_STAT_GEN_SEL_3_GEN_SEL_12_XI                (0xffUL<<0)
        #define HC_STAT_GEN_SEL_3_GEN_SEL_13_XI                (0xffUL<<8)
        #define HC_STAT_GEN_SEL_3_GEN_SEL_14_XI                (0xffUL<<16)
        #define HC_STAT_GEN_SEL_3_GEN_SEL_15_XI                (0xffUL<<24)

    u32_t unused_0[10];
    u32_t hc_stat_gen_stat[16];
    u32_t hc_stat_gen_stat_ac[16];
    u32_t hc_vis;
        #define HC_VIS_STAT_BUILD_STATE                     (0xfUL<<0)
            #define HC_VIS_STAT_BUILD_STATE_IDLE            (0UL<<0)
            #define HC_VIS_STAT_BUILD_STATE_START           (1UL<<0)
            #define HC_VIS_STAT_BUILD_STATE_REQUEST         (2UL<<0)
            #define HC_VIS_STAT_BUILD_STATE_UPDATE64        (3UL<<0)
            #define HC_VIS_STAT_BUILD_STATE_UPDATE32        (4UL<<0)
            #define HC_VIS_STAT_BUILD_STATE_UPDATE_DONE     (5UL<<0)
            #define HC_VIS_STAT_BUILD_STATE_DMA             (6UL<<0)
            #define HC_VIS_STAT_BUILD_STATE_MSI_CONTROL     (7UL<<0)
            #define HC_VIS_STAT_BUILD_STATE_MSI_LOW         (8UL<<0)
            #define HC_VIS_STAT_BUILD_STATE_MSI_HIGH        (9UL<<0)
            #define HC_VIS_STAT_BUILD_STATE_MSI_DATA        (10UL<<0)
        #define HC_VIS_DMA_STAT_STATE                       (0xfUL<<8)
            #define HC_VIS_DMA_STAT_STATE_IDLE              (0UL<<8)
            #define HC_VIS_DMA_STAT_STATE_STATUS_PARAM      (1UL<<8)
            #define HC_VIS_DMA_STAT_STATE_STATUS_DMA        (2UL<<8)
            #define HC_VIS_DMA_STAT_STATE_WRITE_COMP        (3UL<<8)
            #define HC_VIS_DMA_STAT_STATE_COMP              (4UL<<8)
            #define HC_VIS_DMA_STAT_STATE_STATISTIC_PARAM   (5UL<<8)
            #define HC_VIS_DMA_STAT_STATE_STATISTIC_DMA     (6UL<<8)
            #define HC_VIS_DMA_STAT_STATE_WRITE_COMP_1      (7UL<<8)
            #define HC_VIS_DMA_STAT_STATE_WRITE_COMP_2      (8UL<<8)
            #define HC_VIS_DMA_STAT_STATE_WAIT              (9UL<<8)
            #define HC_VIS_DMA_STAT_STATE_ABORT             (15UL<<8)
        #define HC_VIS_DMA_MSI_STATE                        (0x7UL<<12)
        #define HC_VIS_STATISTIC_DMA_EN_STATE               (0x3UL<<15)
            #define HC_VIS_STATISTIC_DMA_EN_STATE_IDLE      (0UL<<15)
            #define HC_VIS_STATISTIC_DMA_EN_STATE_COUNT     (1UL<<15)
            #define HC_VIS_STATISTIC_DMA_EN_STATE_START     (2UL<<15)

    u32_t hc_vis_1;
        #define HC_VIS_1_HW_INTACK_STATE                    (1UL<<4)
            #define HC_VIS_1_HW_INTACK_STATE_IDLE           (0UL<<4)
            #define HC_VIS_1_HW_INTACK_STATE_COUNT          (1UL<<4)
        #define HC_VIS_1_SW_INTACK_STATE                    (1UL<<5)
            #define HC_VIS_1_SW_INTACK_STATE_IDLE           (0UL<<5)
            #define HC_VIS_1_SW_INTACK_STATE_COUNT          (1UL<<5)
        #define HC_VIS_1_DURING_SW_INTACK_STATE             (1UL<<6)
            #define HC_VIS_1_DURING_SW_INTACK_STATE_IDLE    (0UL<<6)
            #define HC_VIS_1_DURING_SW_INTACK_STATE_COUNT   (1UL<<6)
        #define HC_VIS_1_MAILBOX_COUNT_STATE                (1UL<<7)
            #define HC_VIS_1_MAILBOX_COUNT_STATE_IDLE       (0UL<<7)
            #define HC_VIS_1_MAILBOX_COUNT_STATE_COUNT      (1UL<<7)
        #define HC_VIS_1_RAM_RD_ARB_STATE                   (0xfUL<<17)
            #define HC_VIS_1_RAM_RD_ARB_STATE_IDLE          (0UL<<17)
            #define HC_VIS_1_RAM_RD_ARB_STATE_DMA           (1UL<<17)
            #define HC_VIS_1_RAM_RD_ARB_STATE_UPDATE        (2UL<<17)
            #define HC_VIS_1_RAM_RD_ARB_STATE_ASSIGN        (3UL<<17)
            #define HC_VIS_1_RAM_RD_ARB_STATE_WAIT          (4UL<<17)
            #define HC_VIS_1_RAM_RD_ARB_STATE_REG_UPDATE    (5UL<<17)
            #define HC_VIS_1_RAM_RD_ARB_STATE_REG_ASSIGN    (6UL<<17)
            #define HC_VIS_1_RAM_RD_ARB_STATE_REG_WAIT      (7UL<<17)
        #define HC_VIS_1_RAM_WR_ARB_STATE                   (0x3UL<<21)
            #define HC_VIS_1_RAM_WR_ARB_STATE_NORMAL        (0UL<<21)
            #define HC_VIS_1_RAM_WR_ARB_STATE_CLEAR         (1UL<<21)
        #define HC_VIS_1_INT_GEN_STATE                      (1UL<<23)
            #define HC_VIS_1_INT_GEN_STATE_DLE              (0UL<<23)
            #define HC_VIS_1_INT_GEN_STATE_NTERRUPT         (1UL<<23)
        #define HC_VIS_1_STAT_CHAN_ID                       (0x7UL<<24)
        #define HC_VIS_1_INT_B                              (1UL<<27)

    u32_t hc_debug_vect_peek;
        #define HC_DEBUG_VECT_PEEK_1_VALUE                  (0x7ffUL<<0)
        #define HC_DEBUG_VECT_PEEK_1_PEEK_EN                (1UL<<11)
        #define HC_DEBUG_VECT_PEEK_1_SEL                    (0xfUL<<12)
        #define HC_DEBUG_VECT_PEEK_2_VALUE                  (0x7ffUL<<16)
        #define HC_DEBUG_VECT_PEEK_2_PEEK_EN                (1UL<<27)
        #define HC_DEBUG_VECT_PEEK_2_SEL                    (0xfUL<<28)

    u32_t hc_coalesce_now;
        #define HC_COALESCE_NOW_COAL_NOW                    (0x1ffUL<<1)
        #define HC_COALESCE_NOW_COAL_NOW_WO_INT             (0x1ffUL<<11)
        #define HC_COALESCE_NOW_COAL_ON_NXT_EVENT           (0x1ffUL<<21)

    u32_t hc_msix_bit_vector;
        #define HC_MSIX_BIT_VECTOR_VAL                      (0x1ffUL<<0)

    u32_t unused_1[57];
    u32_t hc_sb_config_1;
        #define HC_SB_CONFIG_1_RX_TMR_MODE                  (1UL<<1)
        #define HC_SB_CONFIG_1_TX_TMR_MODE                  (1UL<<2)
        #define HC_SB_CONFIG_1_COM_TMR_MODE                 (1UL<<3)
        #define HC_SB_CONFIG_1_CMD_TMR_MODE                 (1UL<<4)
        #define HC_SB_CONFIG_1_PER_MODE                     (1UL<<16)
        #define HC_SB_CONFIG_1_ONE_SHOT                     (1UL<<17)
        #define HC_SB_CONFIG_1_USE_INT_PARAM                (1UL<<18)
        #define HC_SB_CONFIG_1_PER_COLLECT_LIMIT            (0xfUL<<20)

    u32_t hc_tx_quick_cons_trip_1;
        #define HC_TX_QUICK_CONS_TRIP_1_VALUE               (0xffUL<<0)
        #define HC_TX_QUICK_CONS_TRIP_1_INT                 (0xffUL<<16)

    u32_t hc_comp_prod_trip_1;
        #define HC_COMP_PROD_TRIP_1_VALUE                   (0xffUL<<0)
        #define HC_COMP_PROD_TRIP_1_INT                     (0xffUL<<16)

    u32_t hc_rx_quick_cons_trip_1;
        #define HC_RX_QUICK_CONS_TRIP_1_VALUE               (0xffUL<<0)
        #define HC_RX_QUICK_CONS_TRIP_1_INT                 (0xffUL<<16)

    u32_t hc_rx_ticks_1;
        #define HC_RX_TICKS_1_VALUE                         (0x3ffUL<<0)
        #define HC_RX_TICKS_1_INT                           (0x3ffUL<<16)

    u32_t hc_tx_ticks_1;
        #define HC_TX_TICKS_1_VALUE                         (0x3ffUL<<0)
        #define HC_TX_TICKS_1_INT                           (0x3ffUL<<16)

    u32_t hc_com_ticks_1;
        #define HC_COM_TICKS_1_VALUE                        (0x3ffUL<<0)
        #define HC_COM_TICKS_1_INT                          (0x3ffUL<<16)

    u32_t hc_cmd_ticks_1;
        #define HC_CMD_TICKS_1_VALUE                        (0x3ffUL<<0)
        #define HC_CMD_TICKS_1_INT                          (0x3ffUL<<16)

    u32_t hc_periodic_ticks_1;
        #define HC_PERIODIC_TICKS_1_HC_PERIODIC_TICKS       (0xffffUL<<0)
        #define HC_PERIODIC_TICKS_1_HC_INT_PERIODIC_TICKS   (0xffffUL<<16)

    u32_t hc_sb_config_2;
        #define HC_SB_CONFIG_2_RX_TMR_MODE                  (1UL<<1)
        #define HC_SB_CONFIG_2_TX_TMR_MODE                  (1UL<<2)
        #define HC_SB_CONFIG_2_COM_TMR_MODE                 (1UL<<3)
        #define HC_SB_CONFIG_2_CMD_TMR_MODE                 (1UL<<4)
        #define HC_SB_CONFIG_2_PER_MODE                     (1UL<<16)
        #define HC_SB_CONFIG_2_ONE_SHOT                     (1UL<<17)
        #define HC_SB_CONFIG_2_USE_INT_PARAM                (1UL<<18)
        #define HC_SB_CONFIG_2_PER_COLLECT_LIMIT            (0xfUL<<20)

    u32_t hc_tx_quick_cons_trip_2;
        #define HC_TX_QUICK_CONS_TRIP_2_VALUE               (0xffUL<<0)
        #define HC_TX_QUICK_CONS_TRIP_2_INT                 (0xffUL<<16)

    u32_t hc_comp_prod_trip_2;
        #define HC_COMP_PROD_TRIP_2_VALUE                   (0xffUL<<0)
        #define HC_COMP_PROD_TRIP_2_INT                     (0xffUL<<16)

    u32_t hc_rx_quick_cons_trip_2;
        #define HC_RX_QUICK_CONS_TRIP_2_VALUE               (0xffUL<<0)
        #define HC_RX_QUICK_CONS_TRIP_2_INT                 (0xffUL<<16)

    u32_t hc_rx_ticks_2;
        #define HC_RX_TICKS_2_VALUE                         (0x3ffUL<<0)
        #define HC_RX_TICKS_2_INT                           (0x3ffUL<<16)

    u32_t hc_tx_ticks_2;
        #define HC_TX_TICKS_2_VALUE                         (0x3ffUL<<0)
        #define HC_TX_TICKS_2_INT                           (0x3ffUL<<16)

    u32_t hc_com_ticks_2;
        #define HC_COM_TICKS_2_VALUE                        (0x3ffUL<<0)
        #define HC_COM_TICKS_2_INT                          (0x3ffUL<<16)

    u32_t hc_cmd_ticks_2;
        #define HC_CMD_TICKS_2_VALUE                        (0x3ffUL<<0)
        #define HC_CMD_TICKS_2_INT                          (0x3ffUL<<16)

    u32_t hc_periodic_ticks_2;
        #define HC_PERIODIC_TICKS_2_HC_PERIODIC_TICKS       (0xffffUL<<0)
        #define HC_PERIODIC_TICKS_2_HC_INT_PERIODIC_TICKS   (0xffffUL<<16)

    u32_t hc_sb_config_3;
        #define HC_SB_CONFIG_3_RX_TMR_MODE                  (1UL<<1)
        #define HC_SB_CONFIG_3_TX_TMR_MODE                  (1UL<<2)
        #define HC_SB_CONFIG_3_COM_TMR_MODE                 (1UL<<3)
        #define HC_SB_CONFIG_3_CMD_TMR_MODE                 (1UL<<4)
        #define HC_SB_CONFIG_3_PER_MODE                     (1UL<<16)
        #define HC_SB_CONFIG_3_ONE_SHOT                     (1UL<<17)
        #define HC_SB_CONFIG_3_USE_INT_PARAM                (1UL<<18)
        #define HC_SB_CONFIG_3_PER_COLLECT_LIMIT            (0xfUL<<20)

    u32_t hc_tx_quick_cons_trip_3;
        #define HC_TX_QUICK_CONS_TRIP_3_VALUE               (0xffUL<<0)
        #define HC_TX_QUICK_CONS_TRIP_3_INT                 (0xffUL<<16)

    u32_t hc_comp_prod_trip_3;
        #define HC_COMP_PROD_TRIP_3_VALUE                   (0xffUL<<0)
        #define HC_COMP_PROD_TRIP_3_INT                     (0xffUL<<16)

    u32_t hc_rx_quick_cons_trip_3;
        #define HC_RX_QUICK_CONS_TRIP_3_VALUE               (0xffUL<<0)
        #define HC_RX_QUICK_CONS_TRIP_3_INT                 (0xffUL<<16)

    u32_t hc_rx_ticks_3;
        #define HC_RX_TICKS_3_VALUE                         (0x3ffUL<<0)
        #define HC_RX_TICKS_3_INT                           (0x3ffUL<<16)

    u32_t hc_tx_ticks_3;
        #define HC_TX_TICKS_3_VALUE                         (0x3ffUL<<0)
        #define HC_TX_TICKS_3_INT                           (0x3ffUL<<16)

    u32_t hc_com_ticks_3;
        #define HC_COM_TICKS_3_VALUE                        (0x3ffUL<<0)
        #define HC_COM_TICKS_3_INT                          (0x3ffUL<<16)

    u32_t hc_cmd_ticks_3;
        #define HC_CMD_TICKS_3_VALUE                        (0x3ffUL<<0)
        #define HC_CMD_TICKS_3_INT                          (0x3ffUL<<16)

    u32_t hc_periodic_ticks_3;
        #define HC_PERIODIC_TICKS_3_HC_PERIODIC_TICKS       (0xffffUL<<0)
        #define HC_PERIODIC_TICKS_3_HC_INT_PERIODIC_TICKS   (0xffffUL<<16)

    u32_t hc_sb_config_4;
        #define HC_SB_CONFIG_4_RX_TMR_MODE                  (1UL<<1)
        #define HC_SB_CONFIG_4_TX_TMR_MODE                  (1UL<<2)
        #define HC_SB_CONFIG_4_COM_TMR_MODE                 (1UL<<3)
        #define HC_SB_CONFIG_4_CMD_TMR_MODE                 (1UL<<4)
        #define HC_SB_CONFIG_4_PER_MODE                     (1UL<<16)
        #define HC_SB_CONFIG_4_ONE_SHOT                     (1UL<<17)
        #define HC_SB_CONFIG_4_USE_INT_PARAM                (1UL<<18)
        #define HC_SB_CONFIG_4_PER_COLLECT_LIMIT            (0xfUL<<20)

    u32_t hc_tx_quick_cons_trip_4;
        #define HC_TX_QUICK_CONS_TRIP_4_VALUE               (0xffUL<<0)
        #define HC_TX_QUICK_CONS_TRIP_4_INT                 (0xffUL<<16)

    u32_t hc_comp_prod_trip_4;
        #define HC_COMP_PROD_TRIP_4_VALUE                   (0xffUL<<0)
        #define HC_COMP_PROD_TRIP_4_INT                     (0xffUL<<16)

    u32_t hc_rx_quick_cons_trip_4;
        #define HC_RX_QUICK_CONS_TRIP_4_VALUE               (0xffUL<<0)
        #define HC_RX_QUICK_CONS_TRIP_4_INT                 (0xffUL<<16)

    u32_t hc_rx_ticks_4;
        #define HC_RX_TICKS_4_VALUE                         (0x3ffUL<<0)
        #define HC_RX_TICKS_4_INT                           (0x3ffUL<<16)

    u32_t hc_tx_ticks_4;
        #define HC_TX_TICKS_4_VALUE                         (0x3ffUL<<0)
        #define HC_TX_TICKS_4_INT                           (0x3ffUL<<16)

    u32_t hc_com_ticks_4;
        #define HC_COM_TICKS_4_VALUE                        (0x3ffUL<<0)
        #define HC_COM_TICKS_4_INT                          (0x3ffUL<<16)

    u32_t hc_cmd_ticks_4;
        #define HC_CMD_TICKS_4_VALUE                        (0x3ffUL<<0)
        #define HC_CMD_TICKS_4_INT                          (0x3ffUL<<16)

    u32_t hc_periodic_ticks_4;
        #define HC_PERIODIC_TICKS_4_HC_PERIODIC_TICKS       (0xffffUL<<0)
        #define HC_PERIODIC_TICKS_4_HC_INT_PERIODIC_TICKS   (0xffffUL<<16)

    u32_t hc_sb_config_5;
        #define HC_SB_CONFIG_5_RX_TMR_MODE                  (1UL<<1)
        #define HC_SB_CONFIG_5_TX_TMR_MODE                  (1UL<<2)
        #define HC_SB_CONFIG_5_COM_TMR_MODE                 (1UL<<3)
        #define HC_SB_CONFIG_5_CMD_TMR_MODE                 (1UL<<4)
        #define HC_SB_CONFIG_5_PER_MODE                     (1UL<<16)
        #define HC_SB_CONFIG_5_ONE_SHOT                     (1UL<<17)
        #define HC_SB_CONFIG_5_USE_INT_PARAM                (1UL<<18)
        #define HC_SB_CONFIG_5_PER_COLLECT_LIMIT            (0xfUL<<20)

    u32_t hc_tx_quick_cons_trip_5;
        #define HC_TX_QUICK_CONS_TRIP_5_VALUE               (0xffUL<<0)
        #define HC_TX_QUICK_CONS_TRIP_5_INT                 (0xffUL<<16)

    u32_t hc_comp_prod_trip_5;
        #define HC_COMP_PROD_TRIP_5_VALUE                   (0xffUL<<0)
        #define HC_COMP_PROD_TRIP_5_INT                     (0xffUL<<16)

    u32_t hc_rx_quick_cons_trip_5;
        #define HC_RX_QUICK_CONS_TRIP_5_VALUE               (0xffUL<<0)
        #define HC_RX_QUICK_CONS_TRIP_5_INT                 (0xffUL<<16)

    u32_t hc_rx_ticks_5;
        #define HC_RX_TICKS_5_VALUE                         (0x3ffUL<<0)
        #define HC_RX_TICKS_5_INT                           (0x3ffUL<<16)

    u32_t hc_tx_ticks_5;
        #define HC_TX_TICKS_5_VALUE                         (0x3ffUL<<0)
        #define HC_TX_TICKS_5_INT                           (0x3ffUL<<16)

    u32_t hc_com_ticks_5;
        #define HC_COM_TICKS_5_VALUE                        (0x3ffUL<<0)
        #define HC_COM_TICKS_5_INT                          (0x3ffUL<<16)

    u32_t hc_cmd_ticks_5;
        #define HC_CMD_TICKS_5_VALUE                        (0x3ffUL<<0)
        #define HC_CMD_TICKS_5_INT                          (0x3ffUL<<16)

    u32_t hc_periodic_ticks_5;
        #define HC_PERIODIC_TICKS_5_HC_PERIODIC_TICKS       (0xffffUL<<0)
        #define HC_PERIODIC_TICKS_5_HC_INT_PERIODIC_TICKS   (0xffffUL<<16)

    u32_t hc_sb_config_6;
        #define HC_SB_CONFIG_6_RX_TMR_MODE                  (1UL<<1)
        #define HC_SB_CONFIG_6_TX_TMR_MODE                  (1UL<<2)
        #define HC_SB_CONFIG_6_COM_TMR_MODE                 (1UL<<3)
        #define HC_SB_CONFIG_6_CMD_TMR_MODE                 (1UL<<4)
        #define HC_SB_CONFIG_6_PER_MODE                     (1UL<<16)
        #define HC_SB_CONFIG_6_ONE_SHOT                     (1UL<<17)
        #define HC_SB_CONFIG_6_USE_INT_PARAM                (1UL<<18)
        #define HC_SB_CONFIG_6_PER_COLLECT_LIMIT            (0xfUL<<20)

    u32_t hc_tx_quick_cons_trip_6;
        #define HC_TX_QUICK_CONS_TRIP_6_VALUE               (0xffUL<<0)
        #define HC_TX_QUICK_CONS_TRIP_6_INT                 (0xffUL<<16)

    u32_t hc_comp_prod_trip_6;
        #define HC_COMP_PROD_TRIP_6_VALUE                   (0xffUL<<0)
        #define HC_COMP_PROD_TRIP_6_INT                     (0xffUL<<16)

    u32_t hc_rx_quick_cons_trip_6;
        #define HC_RX_QUICK_CONS_TRIP_6_VALUE               (0xffUL<<0)
        #define HC_RX_QUICK_CONS_TRIP_6_INT                 (0xffUL<<16)

    u32_t hc_rx_ticks_6;
        #define HC_RX_TICKS_6_VALUE                         (0x3ffUL<<0)
        #define HC_RX_TICKS_6_INT                           (0x3ffUL<<16)

    u32_t hc_tx_ticks_6;
        #define HC_TX_TICKS_6_VALUE                         (0x3ffUL<<0)
        #define HC_TX_TICKS_6_INT                           (0x3ffUL<<16)

    u32_t hc_com_ticks_6;
        #define HC_COM_TICKS_6_VALUE                        (0x3ffUL<<0)
        #define HC_COM_TICKS_6_INT                          (0x3ffUL<<16)

    u32_t hc_cmd_ticks_6;
        #define HC_CMD_TICKS_6_VALUE                        (0x3ffUL<<0)
        #define HC_CMD_TICKS_6_INT                          (0x3ffUL<<16)

    u32_t hc_periodic_ticks_6;
        #define HC_PERIODIC_TICKS_6_HC_PERIODIC_TICKS       (0xffffUL<<0)
        #define HC_PERIODIC_TICKS_6_HC_INT_PERIODIC_TICKS   (0xffffUL<<16)

    u32_t hc_sb_config_7;
        #define HC_SB_CONFIG_7_RX_TMR_MODE                  (1UL<<1)
        #define HC_SB_CONFIG_7_TX_TMR_MODE                  (1UL<<2)
        #define HC_SB_CONFIG_7_COM_TMR_MODE                 (1UL<<3)
        #define HC_SB_CONFIG_7_CMD_TMR_MODE                 (1UL<<4)
        #define HC_SB_CONFIG_7_PER_MODE                     (1UL<<16)
        #define HC_SB_CONFIG_7_ONE_SHOT                     (1UL<<17)
        #define HC_SB_CONFIG_7_USE_INT_PARAM                (1UL<<18)
        #define HC_SB_CONFIG_7_PER_COLLECT_LIMIT            (0xfUL<<20)

    u32_t hc_tx_quick_cons_trip_7;
        #define HC_TX_QUICK_CONS_TRIP_7_VALUE               (0xffUL<<0)
        #define HC_TX_QUICK_CONS_TRIP_7_INT                 (0xffUL<<16)

    u32_t hc_comp_prod_trip_7;
        #define HC_COMP_PROD_TRIP_7_VALUE                   (0xffUL<<0)
        #define HC_COMP_PROD_TRIP_7_INT                     (0xffUL<<16)

    u32_t hc_rx_quick_cons_trip_7;
        #define HC_RX_QUICK_CONS_TRIP_7_VALUE               (0xffUL<<0)
        #define HC_RX_QUICK_CONS_TRIP_7_INT                 (0xffUL<<16)

    u32_t hc_rx_ticks_7;
        #define HC_RX_TICKS_7_VALUE                         (0x3ffUL<<0)
        #define HC_RX_TICKS_7_INT                           (0x3ffUL<<16)

    u32_t hc_tx_ticks_7;
        #define HC_TX_TICKS_7_VALUE                         (0x3ffUL<<0)
        #define HC_TX_TICKS_7_INT                           (0x3ffUL<<16)

    u32_t hc_com_ticks_7;
        #define HC_COM_TICKS_7_VALUE                        (0x3ffUL<<0)
        #define HC_COM_TICKS_7_INT                          (0x3ffUL<<16)

    u32_t hc_cmd_ticks_7;
        #define HC_CMD_TICKS_7_VALUE                        (0x3ffUL<<0)
        #define HC_CMD_TICKS_7_INT                          (0x3ffUL<<16)

    u32_t hc_periodic_ticks_7;
        #define HC_PERIODIC_TICKS_7_HC_PERIODIC_TICKS       (0xffffUL<<0)
        #define HC_PERIODIC_TICKS_7_HC_INT_PERIODIC_TICKS   (0xffffUL<<16)

    u32_t hc_sb_config_8;
        #define HC_SB_CONFIG_8_RX_TMR_MODE                  (1UL<<1)
        #define HC_SB_CONFIG_8_TX_TMR_MODE                  (1UL<<2)
        #define HC_SB_CONFIG_8_COM_TMR_MODE                 (1UL<<3)
        #define HC_SB_CONFIG_8_CMD_TMR_MODE                 (1UL<<4)
        #define HC_SB_CONFIG_8_PER_MODE                     (1UL<<16)
        #define HC_SB_CONFIG_8_ONE_SHOT                     (1UL<<17)
        #define HC_SB_CONFIG_8_USE_INT_PARAM                (1UL<<18)
        #define HC_SB_CONFIG_8_PER_COLLECT_LIMIT            (0xfUL<<20)

    u32_t hc_tx_quick_cons_trip_8;
        #define HC_TX_QUICK_CONS_TRIP_8_VALUE               (0xffUL<<0)
        #define HC_TX_QUICK_CONS_TRIP_8_INT                 (0xffUL<<16)

    u32_t hc_comp_prod_trip_8;
        #define HC_COMP_PROD_TRIP_8_VALUE                   (0xffUL<<0)
        #define HC_COMP_PROD_TRIP_8_INT                     (0xffUL<<16)

    u32_t hc_rx_quick_cons_trip_8;
        #define HC_RX_QUICK_CONS_TRIP_8_VALUE               (0xffUL<<0)
        #define HC_RX_QUICK_CONS_TRIP_8_INT                 (0xffUL<<16)

    u32_t hc_rx_ticks_8;
        #define HC_RX_TICKS_8_VALUE                         (0x3ffUL<<0)
        #define HC_RX_TICKS_8_INT                           (0x3ffUL<<16)

    u32_t hc_tx_ticks_8;
        #define HC_TX_TICKS_8_VALUE                         (0x3ffUL<<0)
        #define HC_TX_TICKS_8_INT                           (0x3ffUL<<16)

    u32_t hc_com_ticks_8;
        #define HC_COM_TICKS_8_VALUE                        (0x3ffUL<<0)
        #define HC_COM_TICKS_8_INT                          (0x3ffUL<<16)

    u32_t hc_cmd_ticks_8;
        #define HC_CMD_TICKS_8_VALUE                        (0x3ffUL<<0)
        #define HC_CMD_TICKS_8_INT                          (0x3ffUL<<16)

    u32_t hc_periodic_ticks_8;
        #define HC_PERIODIC_TICKS_8_HC_PERIODIC_TICKS       (0xffffUL<<0)
        #define HC_PERIODIC_TICKS_8_HC_INT_PERIODIC_TICKS   (0xffffUL<<16)

    u32_t unused_2[56];
} hc_reg_t;

typedef hc_reg_t host_coalesce_reg_t;

/*
 *  hc1_reg definition
 *  offset: 0x310000
 */
typedef struct hc1_reg
{
    u32_t hc1_command;
        #define HC1_COMMAND_ENABLE                          (1UL<<0)
        #define HC1_COMMAND_COAL_NOW                        (1UL<<16)
        #define HC1_COMMAND_COAL_NOW_WO_INT                 (1UL<<17)
        #define HC1_COMMAND_STATS_NOW                       (1UL<<18)
        #define HC1_COMMAND_FORCE_INT                       (0x3UL<<19)
            #define HC1_COMMAND_FORCE_INT_NULL              (0UL<<19)
            #define HC1_COMMAND_FORCE_INT_HIGH              (1UL<<19)
            #define HC1_COMMAND_FORCE_INT_LOW               (2UL<<19)
            #define HC1_COMMAND_FORCE_INT_FREE              (3UL<<19)
        #define HC1_COMMAND_CLR_STAT_NOW                    (1UL<<21)
        #define HC1_COMMAND_MAIN_PWR_INT                    (1UL<<22)
        #define HC1_COMMAND_COAL_ON_NEXT_EVENT              (1UL<<27)

    u32_t hc1_status;
        #define HC1_STATUS_PARITY_ERROR_STATE               (1UL<<1)
        #define HC1_STATUS_CORE_CLK_CNT_STAT                (1UL<<17)
        #define HC1_STATUS_NUM_STATUS_BLOCKS_STAT           (1UL<<18)
        #define HC1_STATUS_NUM_INT_GEN_STAT                 (1UL<<19)
        #define HC1_STATUS_NUM_INT_MBOX_WR_STAT             (1UL<<20)
        #define HC1_STATUS_CORE_CLKS_TO_HW_INTACK_STAT      (1UL<<23)
        #define HC1_STATUS_CORE_CLKS_TO_SW_INTACK_STAT      (1UL<<24)
        #define HC1_STATUS_CORE_CLKS_DURING_SW_INTACK_STAT  (1UL<<25)

    u32_t hc1_config;
        #define HC1_CONFIG_COLLECT_STATS                    (1UL<<0)
        #define HC1_CONFIG_RX_TMR_MODE                      (1UL<<1)
        #define HC1_CONFIG_TX_TMR_MODE                      (1UL<<2)
        #define HC1_CONFIG_COM_TMR_MODE                     (1UL<<3)
        #define HC1_CONFIG_CMD_TMR_MODE                     (1UL<<4)
        #define HC1_CONFIG_STATISTIC_PRIORITY               (1UL<<5)
        #define HC1_CONFIG_STATUS_PRIORITY                  (1UL<<6)
        #define HC1_CONFIG_STAT_MEM_ADDR                    (0xffUL<<8)
        #define HC1_CONFIG_PER_MODE                         (1UL<<16)
        #define HC1_CONFIG_ONE_SHOT                         (1UL<<17)
        #define HC1_CONFIG_USE_INT_PARAM                    (1UL<<18)
        #define HC1_CONFIG_SET_MASK_AT_RD                   (1UL<<19)
        #define HC1_CONFIG_PER_COLLECT_LIMIT                (0xfUL<<20)
        #define HC1_CONFIG_SB_ADDR_INC                      (0x7UL<<24)
            #define HC1_CONFIG_SB_ADDR_INC_64B              (0UL<<24)
            #define HC1_CONFIG_SB_ADDR_INC_128B             (1UL<<24)
            #define HC1_CONFIG_SB_ADDR_INC_256B             (2UL<<24)
            #define HC1_CONFIG_SB_ADDR_INC_512B             (3UL<<24)
            #define HC1_CONFIG_SB_ADDR_INC_1024B            (4UL<<24)
            #define HC1_CONFIG_SB_ADDR_INC_2048B            (5UL<<24)
            #define HC1_CONFIG_SB_ADDR_INC_4096B            (6UL<<24)
            #define HC1_CONFIG_SB_ADDR_INC_8192B            (7UL<<24)
        #define HC1_CONFIG_GEN_STAT_AVG_INTR                (1UL<<29)
        #define HC1_CONFIG_UNMASK_ALL                       (1UL<<30)
        #define HC1_CONFIG_TX_SEL                           (1UL<<31)

    u32_t hc1_attn_bits_enable;
    u32_t hc1_status_addr_l;
    u32_t hc1_status_addr_h;
    u32_t hc1_statistics_addr_l;
    u32_t hc1_statistics_addr_h;
    u32_t hc1_tx_quick_cons_trip;
        #define HC1_TX_QUICK_CONS_TRIP_VALUE                (0xffUL<<0)
        #define HC1_TX_QUICK_CONS_TRIP_INT                  (0xffUL<<16)

    u32_t hc1_comp_prod_trip;
        #define HC1_COMP_PROD_TRIP_VALUE                    (0xffUL<<0)
        #define HC1_COMP_PROD_TRIP_INT                      (0xffUL<<16)

    u32_t hc1_rx_quick_cons_trip;
        #define HC1_RX_QUICK_CONS_TRIP_VALUE                (0xffUL<<0)
        #define HC1_RX_QUICK_CONS_TRIP_INT                  (0xffUL<<16)

    u32_t hc1_rx_ticks;
        #define HC1_RX_TICKS_VALUE                          (0x3ffUL<<0)
        #define HC1_RX_TICKS_INT                            (0x3ffUL<<16)

    u32_t hc1_tx_ticks;
        #define HC1_TX_TICKS_VALUE                          (0x3ffUL<<0)
        #define HC1_TX_TICKS_INT                            (0x3ffUL<<16)

    u32_t hc1_com_ticks;
        #define HC1_COM_TICKS_VALUE                         (0x3ffUL<<0)
        #define HC1_COM_TICKS_INT                           (0x3ffUL<<16)

    u32_t hc1_cmd_ticks;
        #define HC1_CMD_TICKS_VALUE                         (0x3ffUL<<0)
        #define HC1_CMD_TICKS_INT                           (0x3ffUL<<16)

    u32_t hc1_periodic_ticks;
        #define HC1_PERIODIC_TICKS_HC_PERIODIC_TICKS        (0xffffUL<<0)
        #define HC1_PERIODIC_TICKS_HC_INT_PERIODIC_TICKS    (0xffffUL<<16)

    u32_t hc1_stat_collect_ticks;
        #define HC1_STAT_COLLECT_TICKS_HC_STAT_COLL_TICKS   (0xffUL<<4)

    u32_t hc1_stats_ticks;
        #define HC1_STATS_TICKS_HC_STAT_TICKS               (0xffffUL<<8)

    u32_t hc1_stats_interrupt_status;
        #define HC1_STATS_INTERRUPT_STATUS_SB_STATUS        (0x1ffUL<<0)
        #define HC1_STATS_INTERRUPT_STATUS_INT_STATUS       (0x1ffUL<<16)

    u32_t hc1_stat_mem_data;
    u32_t hc1_stat_gen_sel_0;
        #define HC1_STAT_GEN_SEL_0_GEN_SEL_0                (0xffUL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT0  (0UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT1  (1UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT2  (2UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT3  (3UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT4  (4UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT5  (5UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT6  (6UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT7  (7UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT8  (8UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT9  (9UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT10  (10UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_RXP_STAT11  (11UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_TXP_STAT0  (12UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_TXP_STAT1  (13UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_TXP_STAT2  (14UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_TXP_STAT3  (15UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_TXP_STAT4  (16UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_TXP_STAT5  (17UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_TXP_STAT6  (18UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_TXP_STAT7  (19UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_COM_STAT0  (20UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_COM_STAT1  (21UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_COM_STAT2  (22UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_COM_STAT3  (23UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_COM_STAT4  (24UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_COM_STAT5  (25UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_COM_STAT6  (26UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_COM_STAT7  (27UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_COM_STAT8  (28UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_COM_STAT9  (29UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_COM_STAT10  (30UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_COM_STAT11  (31UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_TPAT_STAT0  (32UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_TPAT_STAT1  (33UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_TPAT_STAT2  (34UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_TPAT_STAT3  (35UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_CP_STAT0   (36UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_CP_STAT1   (37UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_CP_STAT2   (38UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_CP_STAT3   (39UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_CP_STAT4   (40UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_CP_STAT5   (41UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_CP_STAT6   (42UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_CP_STAT7   (43UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_MCP_STAT0  (44UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_MCP_STAT1  (45UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_MCP_STAT2  (46UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_MCP_STAT3  (47UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_MCP_STAT4  (48UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_MCP_STAT5  (49UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_MCP_STAT6  (50UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_MCP_STAT7  (51UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UMP_RX_FRAME_DROP  (52UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_CORE_CLK_CNT  (53UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_STATUS_BLOCKS  (54UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_GEN  (55UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_MBOX_WR  (56UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S0  (57UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S1  (58UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_HW_INTACK  (59UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_SW_INTACK  (60UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_DURING_SW_INTACK  (61UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_TSCH_CMD_CNT  (62UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_TSCH_SLOT_CNT  (63UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_CSCH_CMD_CNT  (64UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_CSCH_SLOT_CNT  (65UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_RLUPQ_VALID_CNT  (66UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_RXPQ_VALID_CNT  (67UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_RXPCQ_VALID_CNT  (68UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_RV2PPQ_VALID_CNT  (69UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_RV2PMQ_VALID_CNT  (70UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_RV2PTQ_VALID_CNT  (71UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_RDMAQ_VALID_CNT  (72UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_TSCHQ_VALID_CNT  (73UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_TBDRQ_VALID_CNT  (74UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_TXPQ_VALID_CNT  (75UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_TDMAQ_VALID_CNT  (76UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_TPATQ_VALID_CNT  (77UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_TASQ_VALID_CNT  (78UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_CSQ_VALID_CNT  (79UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_CPQ_VALID_CNT  (80UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_COMXQ_VALID_CNT  (81UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_COMTQ_VALID_CNT  (82UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_COMQ_VALID_CNT  (83UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_MGMQ_VALID_CNT  (84UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S2  (85UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S3  (86UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S4  (87UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S5  (88UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S6  (89UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S7  (90UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S8  (91UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S9  (92UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S10  (93UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_MQ_IDB_OFLOW  (94UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_CTX_WR_CNT64  (95UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_CTX_RD_CNT64  (96UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_CTX_ACC_STALL_CLKS  (97UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_CTX_LOCK_STALL_CLKS  (98UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_MBQ_CTX_ACCESS_STAT  (99UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_MBQ_CTX_ACCESS64_STAT  (100UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_MBQ_PCI_STALL_STAT  (101UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_TBDR_FTQ_ENTRY_CNT  (102UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_TBDR_BURST_CNT  (103UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_TDMA_FTQ_ENTRY_CNT  (104UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_TDMA_BURST_CNT  (105UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_RDMA_FTQ_ENTRY_CNT  (106UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_RDMA_BURST_CNT  (107UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_RLUP_MATCH_CNT  (108UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_TMR_POLL_PASS_CNT  (109UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_TMR_TMR1_CNT  (110UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_TMR_TMR2_CNT  (111UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_TMR_TMR3_CNT  (112UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_TMR_TMR4_CNT  (113UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_TMR_TMR5_CNT  (114UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_RV2P_STAT0  (115UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_RV2P_STAT1  (116UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_RV2P_STAT2  (117UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_RV2P_STAT3  (118UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_RV2P_STAT4  (119UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_RV2P_STAT5  (120UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_RBDC_PROC1_MISS  (121UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_RBDC_PROC2_MISS  (122UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_CTX_BLK_RD_CNT  (123UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_CTX_BLK_WR_CNT  (124UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_CTX_HITS   (125UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_CTX_MISSES  (126UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_RBDC_BURST_CNT  (127UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_STATUS_BLOCKS_VEC1  (128UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_GEN_VEC1  (129UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_MBOX_WR_VEC1  (130UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_HW_INTACK_VEC1  (131UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_SW_INTACK_VEC1  (132UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_DURING_SW_INTACK_VEC1  (133UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_STATUS_BLOCKS_VEC2  (134UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_GEN_VEC2  (135UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_MBOX_WR_VEC2  (136UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_HW_INTACK_VEC2  (137UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_SW_INTACK_VEC2  (138UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_DURING_SW_INTACK_VEC2  (139UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_STATUS_BLOCKS_VEC3  (140UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_GEN_VEC3  (141UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_MBOX_WR_VEC3  (142UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_HW_INTACK_VEC3  (143UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_SW_INTACK_VEC3  (144UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_DURING_SW_INTACK_VEC3  (145UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_STATUS_BLOCKS_VEC4  (146UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_GEN_VEC4  (147UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_MBOX_WR_VEC4  (148UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_HW_INTACK_VEC4  (149UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_SW_INTACK_VEC4  (150UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_DURING_SW_INTACK_VEC4  (151UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_STATUS_BLOCKS_VEC5  (152UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_GEN_VEC5  (153UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_MBOX_WR_VEC5  (154UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_HW_INTACK_VEC5  (155UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_SW_INTACK_VEC5  (156UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_DURING_SW_INTACK_VEC5  (157UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_STATUS_BLOCKS_VEC6  (158UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_GEN_VEC6  (159UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_MBOX_WR_VEC6  (160UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_HW_INTACK_VEC6  (161UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_SW_INTACK_VEC6  (162UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_DURING_SW_INTACK_VEC6  (163UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_STATUS_BLOCKS_VEC7  (164UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_GEN_VEC7  (165UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_MBOX_WR_VEC7  (166UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_HW_INTACK_VEC7  (167UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_SW_INTACK_VEC7  (168UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_DURING_SW_INTACK_VEC7  (169UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_STATUS_BLOCKS_VEC8  (170UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_GEN_VEC8  (171UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_NUM_INT_MBOX_WR_VEC8  (172UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_HW_INTACK_VEC8  (173UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_TO_SW_INTACK_VEC8  (174UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_HC_CORE_CLKS_DURING_SW_INTACK_VEC8  (175UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_RV2PCS_CMD_CNT  (176UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_RV2PCS_SLOT_CNT  (177UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_RV2PCSQ_VALID_CNT  (178UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S15  (179UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S16  (180UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S17  (181UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S18  (182UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S19  (183UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S20  (184UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S21  (185UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S22  (186UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S23  (187UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S24  (188UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S25  (189UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S26  (190UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S27  (191UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S28  (192UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S29  (193UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S30  (194UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S31  (195UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S32  (196UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S33  (197UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S34  (198UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S35  (199UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S36  (200UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S37  (201UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S38  (202UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S39  (203UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S40  (204UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S41  (205UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S42  (206UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S43  (207UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S44  (208UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S45  (209UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S46  (210UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S47  (211UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S48  (212UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S49  (213UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S50  (214UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S51  (215UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S52  (216UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S53  (217UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S54  (218UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S55  (219UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S56  (220UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S57  (221UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S58  (222UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S59  (223UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S60  (224UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S61  (225UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S62  (226UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S63  (227UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S64  (228UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S65  (229UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S66  (230UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S67  (231UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S68  (232UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S69  (233UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S70  (234UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S71  (235UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S72  (236UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S73  (237UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S74  (238UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S75  (239UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S76  (240UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S77  (241UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S78  (242UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S79  (243UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S80  (244UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S81  (245UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S82  (246UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S83  (247UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S84  (248UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S85  (249UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S86  (250UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S87  (251UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S88  (252UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S89  (253UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S90  (254UL<<0)
            #define HC1_STAT_GEN_SEL_0_GEN_SEL_0_UNUSED_S91  (255UL<<0)
        #define HC1_STAT_GEN_SEL_0_GEN_SEL_1                (0xffUL<<8)
        #define HC1_STAT_GEN_SEL_0_GEN_SEL_2                (0xffUL<<16)
        #define HC1_STAT_GEN_SEL_0_GEN_SEL_3                (0xffUL<<24)

    u32_t hc1_stat_gen_sel_1;
        #define HC1_STAT_GEN_SEL_1_GEN_SEL_4                (0xffUL<<0)
        #define HC1_STAT_GEN_SEL_1_GEN_SEL_5                (0xffUL<<8)
        #define HC1_STAT_GEN_SEL_1_GEN_SEL_6                (0xffUL<<16)
        #define HC1_STAT_GEN_SEL_1_GEN_SEL_7                (0xffUL<<24)

    u32_t hc1_stat_gen_sel_2;
        #define HC1_STAT_GEN_SEL_2_GEN_SEL_8                (0xffUL<<0)
        #define HC1_STAT_GEN_SEL_2_GEN_SEL_9                (0xffUL<<8)
        #define HC1_STAT_GEN_SEL_2_GEN_SEL_10               (0xffUL<<16)
        #define HC1_STAT_GEN_SEL_2_GEN_SEL_11               (0xffUL<<24)

    u32_t hc1_stat_gen_sel_3;
        #define HC1_STAT_GEN_SEL_3_GEN_SEL_12               (0xffUL<<0)
        #define HC1_STAT_GEN_SEL_3_GEN_SEL_13               (0xffUL<<8)
        #define HC1_STAT_GEN_SEL_3_GEN_SEL_14               (0xffUL<<16)
        #define HC1_STAT_GEN_SEL_3_GEN_SEL_15               (0xffUL<<24)

    u32_t unused_0[10];
    u32_t hc1_stat_gen_stat[16];
    u32_t hc1_stat_gen_stat_ac[16];
    u32_t hc1_vis;
    u32_t hc1_vis_1;
    u32_t hc1_debug_vect_peek;
        #define HC1_DEBUG_VECT_PEEK_1_VALUE                 (0x7ffUL<<0)
        #define HC1_DEBUG_VECT_PEEK_1_PEEK_EN               (1UL<<11)
        #define HC1_DEBUG_VECT_PEEK_1_SEL                   (0xfUL<<12)
        #define HC1_DEBUG_VECT_PEEK_2_VALUE                 (0x7ffUL<<16)
        #define HC1_DEBUG_VECT_PEEK_2_PEEK_EN               (1UL<<27)
        #define HC1_DEBUG_VECT_PEEK_2_SEL                   (0xfUL<<28)

    u32_t hc1_coalesce_now;
        #define HC1_COALESCE_NOW_COAL_NOW                   (0x1ffUL<<1)
        #define HC1_COALESCE_NOW_COAL_NOW_WO_INT            (0x1ffUL<<11)
        #define HC1_COALESCE_NOW_COAL_ON_NXT_EVENT          (0x1ffUL<<21)

    u32_t hc1_msix_bit_vector;
        #define HC1_MSIX_BIT_VECTOR_VAL                     (0x1ffUL<<0)

    u32_t unused_1[57];
    u32_t hc1_sb_config_1;
        #define HC1_SB_CONFIG_1_RX_TMR_MODE                 (1UL<<1)
        #define HC1_SB_CONFIG_1_TX_TMR_MODE                 (1UL<<2)
        #define HC1_SB_CONFIG_1_COM_TMR_MODE                (1UL<<3)
        #define HC1_SB_CONFIG_1_CMD_TMR_MODE                (1UL<<4)
        #define HC1_SB_CONFIG_1_PER_MODE                    (1UL<<16)
        #define HC1_SB_CONFIG_1_ONE_SHOT                    (1UL<<17)
        #define HC1_SB_CONFIG_1_USE_INT_PARAM               (1UL<<18)
        #define HC1_SB_CONFIG_1_PER_COLLECT_LIMIT           (0xfUL<<20)

    u32_t hc1_tx_quick_cons_trip_1;
        #define HC1_TX_QUICK_CONS_TRIP_1_VALUE              (0xffUL<<0)
        #define HC1_TX_QUICK_CONS_TRIP_1_INT                (0xffUL<<16)

    u32_t hc1_comp_prod_trip_1;
        #define HC1_COMP_PROD_TRIP_1_VALUE                  (0xffUL<<0)
        #define HC1_COMP_PROD_TRIP_1_INT                    (0xffUL<<16)

    u32_t hc1_rx_quick_cons_trip_1;
        #define HC1_RX_QUICK_CONS_TRIP_1_VALUE              (0xffUL<<0)
        #define HC1_RX_QUICK_CONS_TRIP_1_INT                (0xffUL<<16)

    u32_t hc1_rx_ticks_1;
        #define HC1_RX_TICKS_1_VALUE                        (0x3ffUL<<0)
        #define HC1_RX_TICKS_1_INT                          (0x3ffUL<<16)

    u32_t hc1_tx_ticks_1;
        #define HC1_TX_TICKS_1_VALUE                        (0x3ffUL<<0)
        #define HC1_TX_TICKS_1_INT                          (0x3ffUL<<16)

    u32_t hc1_com_ticks_1;
        #define HC1_COM_TICKS_1_VALUE                       (0x3ffUL<<0)
        #define HC1_COM_TICKS_1_INT                         (0x3ffUL<<16)

    u32_t hc1_cmd_ticks_1;
        #define HC1_CMD_TICKS_1_VALUE                       (0x3ffUL<<0)
        #define HC1_CMD_TICKS_1_INT                         (0x3ffUL<<16)

    u32_t hc1_periodic_ticks_1;
        #define HC1_PERIODIC_TICKS_1_HC_PERIODIC_TICKS      (0xffffUL<<0)
        #define HC1_PERIODIC_TICKS_1_HC_INT_PERIODIC_TICKS  (0xffffUL<<16)

    u32_t hc1_sb_config_2;
        #define HC1_SB_CONFIG_2_RX_TMR_MODE                 (1UL<<1)
        #define HC1_SB_CONFIG_2_TX_TMR_MODE                 (1UL<<2)
        #define HC1_SB_CONFIG_2_COM_TMR_MODE                (1UL<<3)
        #define HC1_SB_CONFIG_2_CMD_TMR_MODE                (1UL<<4)
        #define HC1_SB_CONFIG_2_PER_MODE                    (1UL<<16)
        #define HC1_SB_CONFIG_2_ONE_SHOT                    (1UL<<17)
        #define HC1_SB_CONFIG_2_USE_INT_PARAM               (1UL<<18)
        #define HC1_SB_CONFIG_2_PER_COLLECT_LIMIT           (0xfUL<<20)

    u32_t hc1_tx_quick_cons_trip_2;
        #define HC1_TX_QUICK_CONS_TRIP_2_VALUE              (0xffUL<<0)
        #define HC1_TX_QUICK_CONS_TRIP_2_INT                (0xffUL<<16)

    u32_t hc1_comp_prod_trip_2;
        #define HC1_COMP_PROD_TRIP_2_VALUE                  (0xffUL<<0)
        #define HC1_COMP_PROD_TRIP_2_INT                    (0xffUL<<16)

    u32_t hc1_rx_quick_cons_trip_2;
        #define HC1_RX_QUICK_CONS_TRIP_2_VALUE              (0xffUL<<0)
        #define HC1_RX_QUICK_CONS_TRIP_2_INT                (0xffUL<<16)

    u32_t hc1_rx_ticks_2;
        #define HC1_RX_TICKS_2_VALUE                        (0x3ffUL<<0)
        #define HC1_RX_TICKS_2_INT                          (0x3ffUL<<16)

    u32_t hc1_tx_ticks_2;
        #define HC1_TX_TICKS_2_VALUE                        (0x3ffUL<<0)
        #define HC1_TX_TICKS_2_INT                          (0x3ffUL<<16)

    u32_t hc1_com_ticks_2;
        #define HC1_COM_TICKS_2_VALUE                       (0x3ffUL<<0)
        #define HC1_COM_TICKS_2_INT                         (0x3ffUL<<16)

    u32_t hc1_cmd_ticks_2;
        #define HC1_CMD_TICKS_2_VALUE                       (0x3ffUL<<0)
        #define HC1_CMD_TICKS_2_INT                         (0x3ffUL<<16)

    u32_t hc1_periodic_ticks_2;
        #define HC1_PERIODIC_TICKS_2_HC_PERIODIC_TICKS      (0xffffUL<<0)
        #define HC1_PERIODIC_TICKS_2_HC_INT_PERIODIC_TICKS  (0xffffUL<<16)

    u32_t hc1_sb_config_3;
        #define HC1_SB_CONFIG_3_RX_TMR_MODE                 (1UL<<1)
        #define HC1_SB_CONFIG_3_TX_TMR_MODE                 (1UL<<2)
        #define HC1_SB_CONFIG_3_COM_TMR_MODE                (1UL<<3)
        #define HC1_SB_CONFIG_3_CMD_TMR_MODE                (1UL<<4)
        #define HC1_SB_CONFIG_3_PER_MODE                    (1UL<<16)
        #define HC1_SB_CONFIG_3_ONE_SHOT                    (1UL<<17)
        #define HC1_SB_CONFIG_3_USE_INT_PARAM               (1UL<<18)
        #define HC1_SB_CONFIG_3_PER_COLLECT_LIMIT           (0xfUL<<20)

    u32_t hc1_tx_quick_cons_trip_3;
        #define HC1_TX_QUICK_CONS_TRIP_3_VALUE              (0xffUL<<0)
        #define HC1_TX_QUICK_CONS_TRIP_3_INT                (0xffUL<<16)

    u32_t hc1_comp_prod_trip_3;
        #define HC1_COMP_PROD_TRIP_3_VALUE                  (0xffUL<<0)
        #define HC1_COMP_PROD_TRIP_3_INT                    (0xffUL<<16)

    u32_t hc1_rx_quick_cons_trip_3;
        #define HC1_RX_QUICK_CONS_TRIP_3_VALUE              (0xffUL<<0)
        #define HC1_RX_QUICK_CONS_TRIP_3_INT                (0xffUL<<16)

    u32_t hc1_rx_ticks_3;
        #define HC1_RX_TICKS_3_VALUE                        (0x3ffUL<<0)
        #define HC1_RX_TICKS_3_INT                          (0x3ffUL<<16)

    u32_t hc1_tx_ticks_3;
        #define HC1_TX_TICKS_3_VALUE                        (0x3ffUL<<0)
        #define HC1_TX_TICKS_3_INT                          (0x3ffUL<<16)

    u32_t hc1_com_ticks_3;
        #define HC1_COM_TICKS_3_VALUE                       (0x3ffUL<<0)
        #define HC1_COM_TICKS_3_INT                         (0x3ffUL<<16)

    u32_t hc1_cmd_ticks_3;
        #define HC1_CMD_TICKS_3_VALUE                       (0x3ffUL<<0)
        #define HC1_CMD_TICKS_3_INT                         (0x3ffUL<<16)

    u32_t hc1_periodic_ticks_3;
        #define HC1_PERIODIC_TICKS_3_HC_PERIODIC_TICKS      (0xffffUL<<0)
        #define HC1_PERIODIC_TICKS_3_HC_INT_PERIODIC_TICKS  (0xffffUL<<16)

    u32_t hc1_sb_config_4;
        #define HC1_SB_CONFIG_4_RX_TMR_MODE                 (1UL<<1)
        #define HC1_SB_CONFIG_4_TX_TMR_MODE                 (1UL<<2)
        #define HC1_SB_CONFIG_4_COM_TMR_MODE                (1UL<<3)
        #define HC1_SB_CONFIG_4_CMD_TMR_MODE                (1UL<<4)
        #define HC1_SB_CONFIG_4_PER_MODE                    (1UL<<16)
        #define HC1_SB_CONFIG_4_ONE_SHOT                    (1UL<<17)
        #define HC1_SB_CONFIG_4_USE_INT_PARAM               (1UL<<18)
        #define HC1_SB_CONFIG_4_PER_COLLECT_LIMIT           (0xfUL<<20)

    u32_t hc1_tx_quick_cons_trip_4;
        #define HC1_TX_QUICK_CONS_TRIP_4_VALUE              (0xffUL<<0)
        #define HC1_TX_QUICK_CONS_TRIP_4_INT                (0xffUL<<16)

    u32_t hc1_comp_prod_trip_4;
        #define HC1_COMP_PROD_TRIP_4_VALUE                  (0xffUL<<0)
        #define HC1_COMP_PROD_TRIP_4_INT                    (0xffUL<<16)

    u32_t hc1_rx_quick_cons_trip_4;
        #define HC1_RX_QUICK_CONS_TRIP_4_VALUE              (0xffUL<<0)
        #define HC1_RX_QUICK_CONS_TRIP_4_INT                (0xffUL<<16)

    u32_t hc1_rx_ticks_4;
        #define HC1_RX_TICKS_4_VALUE                        (0x3ffUL<<0)
        #define HC1_RX_TICKS_4_INT                          (0x3ffUL<<16)

    u32_t hc1_tx_ticks_4;
        #define HC1_TX_TICKS_4_VALUE                        (0x3ffUL<<0)
        #define HC1_TX_TICKS_4_INT                          (0x3ffUL<<16)

    u32_t hc1_com_ticks_4;
        #define HC1_COM_TICKS_4_VALUE                       (0x3ffUL<<0)
        #define HC1_COM_TICKS_4_INT                         (0x3ffUL<<16)

    u32_t hc1_cmd_ticks_4;
        #define HC1_CMD_TICKS_4_VALUE                       (0x3ffUL<<0)
        #define HC1_CMD_TICKS_4_INT                         (0x3ffUL<<16)

    u32_t hc1_periodic_ticks_4;
        #define HC1_PERIODIC_TICKS_4_HC_PERIODIC_TICKS      (0xffffUL<<0)
        #define HC1_PERIODIC_TICKS_4_HC_INT_PERIODIC_TICKS  (0xffffUL<<16)

    u32_t hc1_sb_config_5;
        #define HC1_SB_CONFIG_5_RX_TMR_MODE                 (1UL<<1)
        #define HC1_SB_CONFIG_5_TX_TMR_MODE                 (1UL<<2)
        #define HC1_SB_CONFIG_5_COM_TMR_MODE                (1UL<<3)
        #define HC1_SB_CONFIG_5_CMD_TMR_MODE                (1UL<<4)
        #define HC1_SB_CONFIG_5_PER_MODE                    (1UL<<16)
        #define HC1_SB_CONFIG_5_ONE_SHOT                    (1UL<<17)
        #define HC1_SB_CONFIG_5_USE_INT_PARAM               (1UL<<18)
        #define HC1_SB_CONFIG_5_PER_COLLECT_LIMIT           (0xfUL<<20)

    u32_t hc1_tx_quick_cons_trip_5;
        #define HC1_TX_QUICK_CONS_TRIP_5_VALUE              (0xffUL<<0)
        #define HC1_TX_QUICK_CONS_TRIP_5_INT                (0xffUL<<16)

    u32_t hc1_comp_prod_trip_5;
        #define HC1_COMP_PROD_TRIP_5_VALUE                  (0xffUL<<0)
        #define HC1_COMP_PROD_TRIP_5_INT                    (0xffUL<<16)

    u32_t hc1_rx_quick_cons_trip_5;
        #define HC1_RX_QUICK_CONS_TRIP_5_VALUE              (0xffUL<<0)
        #define HC1_RX_QUICK_CONS_TRIP_5_INT                (0xffUL<<16)

    u32_t hc1_rx_ticks_5;
        #define HC1_RX_TICKS_5_VALUE                        (0x3ffUL<<0)
        #define HC1_RX_TICKS_5_INT                          (0x3ffUL<<16)

    u32_t hc1_tx_ticks_5;
        #define HC1_TX_TICKS_5_VALUE                        (0x3ffUL<<0)
        #define HC1_TX_TICKS_5_INT                          (0x3ffUL<<16)

    u32_t hc1_com_ticks_5;
        #define HC1_COM_TICKS_5_VALUE                       (0x3ffUL<<0)
        #define HC1_COM_TICKS_5_INT                         (0x3ffUL<<16)

    u32_t hc1_cmd_ticks_5;
        #define HC1_CMD_TICKS_5_VALUE                       (0x3ffUL<<0)
        #define HC1_CMD_TICKS_5_INT                         (0x3ffUL<<16)

    u32_t hc1_periodic_ticks_5;
        #define HC1_PERIODIC_TICKS_5_HC_PERIODIC_TICKS      (0xffffUL<<0)
        #define HC1_PERIODIC_TICKS_5_HC_INT_PERIODIC_TICKS  (0xffffUL<<16)

    u32_t hc1_sb_config_6;
        #define HC1_SB_CONFIG_6_RX_TMR_MODE                 (1UL<<1)
        #define HC1_SB_CONFIG_6_TX_TMR_MODE                 (1UL<<2)
        #define HC1_SB_CONFIG_6_COM_TMR_MODE                (1UL<<3)
        #define HC1_SB_CONFIG_6_CMD_TMR_MODE                (1UL<<4)
        #define HC1_SB_CONFIG_6_PER_MODE                    (1UL<<16)
        #define HC1_SB_CONFIG_6_ONE_SHOT                    (1UL<<17)
        #define HC1_SB_CONFIG_6_USE_INT_PARAM               (1UL<<18)
        #define HC1_SB_CONFIG_6_PER_COLLECT_LIMIT           (0xfUL<<20)

    u32_t hc1_tx_quick_cons_trip_6;
        #define HC1_TX_QUICK_CONS_TRIP_6_VALUE              (0xffUL<<0)
        #define HC1_TX_QUICK_CONS_TRIP_6_INT                (0xffUL<<16)

    u32_t hc1_comp_prod_trip_6;
        #define HC1_COMP_PROD_TRIP_6_VALUE                  (0xffUL<<0)
        #define HC1_COMP_PROD_TRIP_6_INT                    (0xffUL<<16)

    u32_t hc1_rx_quick_cons_trip_6;
        #define HC1_RX_QUICK_CONS_TRIP_6_VALUE              (0xffUL<<0)
        #define HC1_RX_QUICK_CONS_TRIP_6_INT                (0xffUL<<16)

    u32_t hc1_rx_ticks_6;
        #define HC1_RX_TICKS_6_VALUE                        (0x3ffUL<<0)
        #define HC1_RX_TICKS_6_INT                          (0x3ffUL<<16)

    u32_t hc1_tx_ticks_6;
        #define HC1_TX_TICKS_6_VALUE                        (0x3ffUL<<0)
        #define HC1_TX_TICKS_6_INT                          (0x3ffUL<<16)

    u32_t hc1_com_ticks_6;
        #define HC1_COM_TICKS_6_VALUE                       (0x3ffUL<<0)
        #define HC1_COM_TICKS_6_INT                         (0x3ffUL<<16)

    u32_t hc1_cmd_ticks_6;
        #define HC1_CMD_TICKS_6_VALUE                       (0x3ffUL<<0)
        #define HC1_CMD_TICKS_6_INT                         (0x3ffUL<<16)

    u32_t hc1_periodic_ticks_6;
        #define HC1_PERIODIC_TICKS_6_HC_PERIODIC_TICKS      (0xffffUL<<0)
        #define HC1_PERIODIC_TICKS_6_HC_INT_PERIODIC_TICKS  (0xffffUL<<16)

    u32_t hc1_sb_config_7;
        #define HC1_SB_CONFIG_7_RX_TMR_MODE                 (1UL<<1)
        #define HC1_SB_CONFIG_7_TX_TMR_MODE                 (1UL<<2)
        #define HC1_SB_CONFIG_7_COM_TMR_MODE                (1UL<<3)
        #define HC1_SB_CONFIG_7_CMD_TMR_MODE                (1UL<<4)
        #define HC1_SB_CONFIG_7_PER_MODE                    (1UL<<16)
        #define HC1_SB_CONFIG_7_ONE_SHOT                    (1UL<<17)
        #define HC1_SB_CONFIG_7_USE_INT_PARAM               (1UL<<18)
        #define HC1_SB_CONFIG_7_PER_COLLECT_LIMIT           (0xfUL<<20)

    u32_t hc1_tx_quick_cons_trip_7;
        #define HC1_TX_QUICK_CONS_TRIP_7_VALUE              (0xffUL<<0)
        #define HC1_TX_QUICK_CONS_TRIP_7_INT                (0xffUL<<16)

    u32_t hc1_comp_prod_trip_7;
        #define HC1_COMP_PROD_TRIP_7_VALUE                  (0xffUL<<0)
        #define HC1_COMP_PROD_TRIP_7_INT                    (0xffUL<<16)

    u32_t hc1_rx_quick_cons_trip_7;
        #define HC1_RX_QUICK_CONS_TRIP_7_VALUE              (0xffUL<<0)
        #define HC1_RX_QUICK_CONS_TRIP_7_INT                (0xffUL<<16)

    u32_t hc1_rx_ticks_7;
        #define HC1_RX_TICKS_7_VALUE                        (0x3ffUL<<0)
        #define HC1_RX_TICKS_7_INT                          (0x3ffUL<<16)

    u32_t hc1_tx_ticks_7;
        #define HC1_TX_TICKS_7_VALUE                        (0x3ffUL<<0)
        #define HC1_TX_TICKS_7_INT                          (0x3ffUL<<16)

    u32_t hc1_com_ticks_7;
        #define HC1_COM_TICKS_7_VALUE                       (0x3ffUL<<0)
        #define HC1_COM_TICKS_7_INT                         (0x3ffUL<<16)

    u32_t hc1_cmd_ticks_7;
        #define HC1_CMD_TICKS_7_VALUE                       (0x3ffUL<<0)
        #define HC1_CMD_TICKS_7_INT                         (0x3ffUL<<16)

    u32_t hc1_periodic_ticks_7;
        #define HC1_PERIODIC_TICKS_7_HC_PERIODIC_TICKS      (0xffffUL<<0)
        #define HC1_PERIODIC_TICKS_7_HC_INT_PERIODIC_TICKS  (0xffffUL<<16)

    u32_t hc1_sb_config_8;
        #define HC1_SB_CONFIG_8_RX_TMR_MODE                 (1UL<<1)
        #define HC1_SB_CONFIG_8_TX_TMR_MODE                 (1UL<<2)
        #define HC1_SB_CONFIG_8_COM_TMR_MODE                (1UL<<3)
        #define HC1_SB_CONFIG_8_CMD_TMR_MODE                (1UL<<4)
        #define HC1_SB_CONFIG_8_PER_MODE                    (1UL<<16)
        #define HC1_SB_CONFIG_8_ONE_SHOT                    (1UL<<17)
        #define HC1_SB_CONFIG_8_USE_INT_PARAM               (1UL<<18)
        #define HC1_SB_CONFIG_8_PER_COLLECT_LIMIT           (0xfUL<<20)

    u32_t hc1_tx_quick_cons_trip_8;
        #define HC1_TX_QUICK_CONS_TRIP_8_VALUE              (0xffUL<<0)
        #define HC1_TX_QUICK_CONS_TRIP_8_INT                (0xffUL<<16)

    u32_t hc1_comp_prod_trip_8;
        #define HC1_COMP_PROD_TRIP_8_VALUE                  (0xffUL<<0)
        #define HC1_COMP_PROD_TRIP_8_INT                    (0xffUL<<16)

    u32_t hc1_rx_quick_cons_trip_8;
        #define HC1_RX_QUICK_CONS_TRIP_8_VALUE              (0xffUL<<0)
        #define HC1_RX_QUICK_CONS_TRIP_8_INT                (0xffUL<<16)

    u32_t hc1_rx_ticks_8;
        #define HC1_RX_TICKS_8_VALUE                        (0x3ffUL<<0)
        #define HC1_RX_TICKS_8_INT                          (0x3ffUL<<16)

    u32_t hc1_tx_ticks_8;
        #define HC1_TX_TICKS_8_VALUE                        (0x3ffUL<<0)
        #define HC1_TX_TICKS_8_INT                          (0x3ffUL<<16)

    u32_t hc1_com_ticks_8;
        #define HC1_COM_TICKS_8_VALUE                       (0x3ffUL<<0)
        #define HC1_COM_TICKS_8_INT                         (0x3ffUL<<16)

    u32_t hc1_cmd_ticks_8;
        #define HC1_CMD_TICKS_8_VALUE                       (0x3ffUL<<0)
        #define HC1_CMD_TICKS_8_INT                         (0x3ffUL<<16)

    u32_t hc1_periodic_ticks_8;
        #define HC1_PERIODIC_TICKS_8_HC_PERIODIC_TICKS      (0xffffUL<<0)
        #define HC1_PERIODIC_TICKS_8_HC_INT_PERIODIC_TICKS  (0xffffUL<<16)

    u32_t unused_2[7992];
    u32_t hc1_msix_vector0_addr_l;
        #define HC1_MSIX_VECTOR0_ADDR_L_MSG_ADDR_LOW        (0x3fffffffUL<<2)

    u32_t hc1_msix_vector0_addr_h;
        #define HC1_MSIX_VECTOR0_ADDR_H_MSG_ADDR_HIGH       (0xffffffffUL<<0)

    u32_t hc1_msix_vector0_data;
        #define HC1_MSIX_VECTOR0_DATA_MSG_DATA              (0xffffffffUL<<0)

    u32_t hc1_msix_vector0_mask;
        #define HC1_MSIX_VECTOR0_MASK_MSG_MASK              (1UL<<0)

    u32_t hc1_msix_vector1_addr_l;
        #define HC1_MSIX_VECTOR1_ADDR_L_MSG_ADDR_LOW        (0x3fffffffUL<<2)

    u32_t hc1_msix_vector1_addr_h;
        #define HC1_MSIX_VECTOR1_ADDR_H_MSG_ADDR_HIGH       (0xffffffffUL<<0)

    u32_t hc1_msix_vector1_data;
        #define HC1_MSIX_VECTOR1_DATA_MSG_DATA              (0xffffffffUL<<0)

    u32_t hc1_msix_vector1_mask;
        #define HC1_MSIX_VECTOR1_MASK_MSG_MASK              (1UL<<0)

    u32_t hc1_msix_vector2_addr_l;
        #define HC1_MSIX_VECTOR2_ADDR_L_MSG_ADDR_LOW        (0x3fffffffUL<<2)

    u32_t hc1_msix_vector2_addr_h;
        #define HC1_MSIX_VECTOR2_ADDR_H_MSG_ADDR_HIGH       (0xffffffffUL<<0)

    u32_t hc1_msix_vector2_data;
        #define HC1_MSIX_VECTOR2_DATA_MSG_DATA              (0xffffffffUL<<0)

    u32_t hc1_msix_vector2_mask;
        #define HC1_MSIX_VECTOR2_MASK_MSG_MASK              (1UL<<0)

    u32_t hc1_msix_vector3_addr_l;
        #define HC1_MSIX_VECTOR3_ADDR_L_MSG_ADDR_LOW        (0x3fffffffUL<<2)

    u32_t hc1_msix_vector3_addr_h;
        #define HC1_MSIX_VECTOR3_ADDR_H_MSG_ADDR_HIGH       (0xffffffffUL<<0)

    u32_t hc1_msix_vector3_data;
        #define HC1_MSIX_VECTOR3_DATA_MSG_DATA              (0xffffffffUL<<0)

    u32_t hc1_msix_vector3_mask;
        #define HC1_MSIX_VECTOR3_MASK_MSG_MASK              (1UL<<0)

    u32_t hc1_msix_vector4_addr_l;
        #define HC1_MSIX_VECTOR4_ADDR_L_MSG_ADDR_LOW        (0x3fffffffUL<<2)

    u32_t hc1_msix_vector4_addr_h;
        #define HC1_MSIX_VECTOR4_ADDR_H_MSG_ADDR_HIGH       (0xffffffffUL<<0)

    u32_t hc1_msix_vector4_data;
        #define HC1_MSIX_VECTOR4_DATA_MSG_DATA              (0xffffffffUL<<0)

    u32_t hc1_msix_vector4_mask;
        #define HC1_MSIX_VECTOR4_MASK_MSG_MASK              (1UL<<0)

    u32_t hc1_msix_vector5_addr_l;
        #define HC1_MSIX_VECTOR5_ADDR_L_MSG_ADDR_LOW        (0x3fffffffUL<<2)

    u32_t hc1_msix_vector5_addr_h;
        #define HC1_MSIX_VECTOR5_ADDR_H_MSG_ADDR_HIGH       (0xffffffffUL<<0)

    u32_t hc1_msix_vector5_data;
        #define HC1_MSIX_VECTOR5_DATA_MSG_DATA              (0xffffffffUL<<0)

    u32_t hc1_msix_vector5_mask;
        #define HC1_MSIX_VECTOR5_MASK_MSG_MASK              (1UL<<0)

    u32_t hc1_msix_vector6_addr_l;
        #define HC1_MSIX_VECTOR6_ADDR_L_MSG_ADDR_LOW        (0x3fffffffUL<<2)

    u32_t hc1_msix_vector6_addr_h;
        #define HC1_MSIX_VECTOR6_ADDR_H_MSG_ADDR_HIGH       (0xffffffffUL<<0)

    u32_t hc1_msix_vector6_data;
        #define HC1_MSIX_VECTOR6_DATA_MSG_DATA              (0xffffffffUL<<0)

    u32_t hc1_msix_vector6_mask;
        #define HC1_MSIX_VECTOR6_MASK_MSG_MASK              (1UL<<0)

    u32_t hc1_msix_vector7_addr_l;
        #define HC1_MSIX_VECTOR7_ADDR_L_MSG_ADDR_LOW        (0x3fffffffUL<<2)

    u32_t hc1_msix_vector7_addr_h;
        #define HC1_MSIX_VECTOR7_ADDR_H_MSG_ADDR_HIGH       (0xffffffffUL<<0)

    u32_t hc1_msix_vector7_data;
        #define HC1_MSIX_VECTOR7_DATA_MSG_DATA              (0xffffffffUL<<0)

    u32_t hc1_msix_vector7_mask;
        #define HC1_MSIX_VECTOR7_MASK_MSG_MASK              (1UL<<0)

    u32_t hc1_msix_vector8_addr_l;
        #define HC1_MSIX_VECTOR8_ADDR_L_MSG_ADDR_LOW        (0x3fffffffUL<<2)

    u32_t hc1_msix_vector8_addr_h;
        #define HC1_MSIX_VECTOR8_ADDR_H_MSG_ADDR_HIGH       (0xffffffffUL<<0)

    u32_t hc1_msix_vector8_data;
        #define HC1_MSIX_VECTOR8_DATA_MSG_DATA              (0xffffffffUL<<0)

    u32_t hc1_msix_vector8_mask;
        #define HC1_MSIX_VECTOR8_MASK_MSG_MASK              (1UL<<0)

    u32_t unused_3[4060];
    u32_t hc1_msix_pending_bits;
        #define HC1_MSIX_PENDING_BITS_PENDING_BITS          (0x1ffUL<<0)

    u32_t unused_4[4095];
} hc1_reg_t;

typedef hc1_reg_t host_coalesce_full_reg_t;

/*
 *  tx_processor_enqueue definition
 *  offset: 0000
 */
typedef struct tx_processor_enqueue
{
    u32_t tx_processor_enqueue_cid;
        #define TX_PROCESSOR_ENQUEUE_CID_VALUE              (0x3fffUL<<7)

    u32_t tx_processor_enqueue_bseq;
    u32_t tx_processor_enqueue_wd2;
        #define TX_PROCESSOR_ENQUEUE_FLAGS_FLAGS_QUICK_CID_ENA  (1<<24)
        #define TX_PROCESSOR_ENQUEUE_FLAGS_FLAGS_QUICK_CID_TE  (0x3<<25)
        #define TX_PROCESSOR_ENQUEUE_FLAGS_FLAGS_QUICK_CATCHUP_TE  (1<<27)
        #define TX_PROCESSOR_ENQUEUE_FLAGS_FLAGS_RSVD_XI       (1<<25)
        #define TX_PROCESSOR_ENQUEUE_FLAGS_FLAGS_BORROWED_XI   (1<<26)
        #define TX_PROCESSOR_ENQUEUE_FLAGS_FLAGS_BSEQ_INVLD_XI  (1<<27)
        #define TX_PROCESSOR_ENQUEUE_FLAGS_FLAGS_S_RETRAN   (1<<28)

    u32_t tx_processor_enqueue_tcp_rcv_nxt;
        #define TX_PROCESSOR_ENQUEUE_TCP_RCV_NXT_VALUE      (0xffffffffUL<<0)

    u32_t tx_processor_enqueue_wd4;
        #define TX_PROCESSOR_ENQUEUE_TCMD_FNUM_VALUE        (0x3f<<24)

} tx_processor_enqueue_t;


/*
 *  txp_reg definition
 *  offset: 0x40000
 */
typedef struct txp_reg
{
    u32_t unused_0[5120];
    u32_t txp_cpu_mode;
        #define TXP_CPU_MODE_LOCAL_RST                      (1UL<<0)
        #define TXP_CPU_MODE_STEP_ENA                       (1UL<<1)
        #define TXP_CPU_MODE_PAGE_0_DATA_ENA                (1UL<<2)
        #define TXP_CPU_MODE_PAGE_0_INST_ENA                (1UL<<3)
        #define TXP_CPU_MODE_MSG_BIT1                       (1UL<<6)
        #define TXP_CPU_MODE_INTERRUPT_ENA                  (1UL<<7)
        #define TXP_CPU_MODE_SOFT_HALT                      (1UL<<10)
        #define TXP_CPU_MODE_BAD_DATA_HALT_ENA              (1UL<<11)
        #define TXP_CPU_MODE_BAD_INST_HALT_ENA              (1UL<<12)
        #define TXP_CPU_MODE_FIO_ABORT_HALT_ENA             (1UL<<13)
        #define TXP_CPU_MODE_SPAD_UNDERFLOW_HALT_ENA        (1UL<<15)

    u32_t txp_cpu_state;
        #define TXP_CPU_STATE_BREAKPOINT                    (1UL<<0)
        #define TXP_CPU_STATE_BAD_INST_HALTED               (1UL<<2)
        #define TXP_CPU_STATE_PAGE_0_DATA_HALTED            (1UL<<3)
        #define TXP_CPU_STATE_PAGE_0_INST_HALTED            (1UL<<4)
        #define TXP_CPU_STATE_BAD_DATA_ADDR_HALTED          (1UL<<5)
        #define TXP_CPU_STATE_BAD_PC_HALTED                 (1UL<<6)
        #define TXP_CPU_STATE_ALIGN_HALTED                  (1UL<<7)
        #define TXP_CPU_STATE_FIO_ABORT_HALTED              (1UL<<8)
        #define TXP_CPU_STATE_SOFT_HALTED                   (1UL<<10)
        #define TXP_CPU_STATE_SPAD_UNDERFLOW                (1UL<<11)
        #define TXP_CPU_STATE_INTERRRUPT                    (1UL<<12)
        #define TXP_CPU_STATE_DATA_ACCESS_STALL             (1UL<<14)
        #define TXP_CPU_STATE_INST_FETCH_STALL              (1UL<<15)
        #define TXP_CPU_STATE_BLOCKED_READ                  (1UL<<31)

    u32_t txp_cpu_event_mask;
        #define TXP_CPU_EVENT_MASK_BREAKPOINT_MASK          (1UL<<0)
        #define TXP_CPU_EVENT_MASK_BAD_INST_HALTED_MASK     (1UL<<2)
        #define TXP_CPU_EVENT_MASK_PAGE_0_DATA_HALTED_MASK  (1UL<<3)
        #define TXP_CPU_EVENT_MASK_PAGE_0_INST_HALTED_MASK  (1UL<<4)
        #define TXP_CPU_EVENT_MASK_BAD_DATA_ADDR_HALTED_MASK  (1UL<<5)
        #define TXP_CPU_EVENT_MASK_BAD_PC_HALTED_MASK       (1UL<<6)
        #define TXP_CPU_EVENT_MASK_ALIGN_HALTED_MASK        (1UL<<7)
        #define TXP_CPU_EVENT_MASK_FIO_ABORT_MASK           (1UL<<8)
        #define TXP_CPU_EVENT_MASK_SOFT_HALTED_MASK         (1UL<<10)
        #define TXP_CPU_EVENT_MASK_SPAD_UNDERFLOW_MASK      (1UL<<11)
        #define TXP_CPU_EVENT_MASK_INTERRUPT_MASK           (1UL<<12)

    u32_t unused_1[4];
    u32_t txp_cpu_program_counter;
    u32_t txp_cpu_instruction;
    u32_t txp_cpu_data_access;
    u32_t txp_cpu_interrupt_enable;
    u32_t txp_cpu_interrupt_vector;
    u32_t txp_cpu_interrupt_saved_PC;
    u32_t txp_cpu_hw_breakpoint;
        #define TXP_CPU_HW_BREAKPOINT_DISABLE               (1UL<<0)
        #define TXP_CPU_HW_BREAKPOINT_ADDRESS               (0x3fffffffUL<<2)

    u32_t txp_cpu_debug_vect_peek;
        #define TXP_CPU_DEBUG_VECT_PEEK_1_VALUE             (0x7ffUL<<0)
        #define TXP_CPU_DEBUG_VECT_PEEK_1_PEEK_EN           (1UL<<11)
        #define TXP_CPU_DEBUG_VECT_PEEK_1_SEL               (0xfUL<<12)
        #define TXP_CPU_DEBUG_VECT_PEEK_2_VALUE             (0x7ffUL<<16)
        #define TXP_CPU_DEBUG_VECT_PEEK_2_PEEK_EN           (1UL<<27)
        #define TXP_CPU_DEBUG_VECT_PEEK_2_SEL               (0xfUL<<28)

    u32_t unused_2[3];
    u32_t txp_cpu_last_branch_addr;
        #define TXP_CPU_LAST_BRANCH_ADDR_TYPE               (1UL<<1)
            #define TXP_CPU_LAST_BRANCH_ADDR_TYPE_JUMP      (0UL<<1)
            #define TXP_CPU_LAST_BRANCH_ADDR_TYPE_BRANCH    (1UL<<1)
        #define TXP_CPU_LAST_BRANCH_ADDR_LBA                (0x3fffffffUL<<2)

    u32_t unused_3[109];
    u32_t txp_cpu_reg_file[32];
    u32_t unused_4[80];
    tx_processor_enqueue_t txp_txpq;
    u32_t unused_5[9];
    u32_t txp_ftq_cmd;
        #define TXP_FTQ_CMD_OFFSET                          (0x3ffUL<<0)
        #define TXP_FTQ_CMD_WR_TOP                          (1UL<<10)
            #define TXP_FTQ_CMD_WR_TOP_0                    (0UL<<10)
            #define TXP_FTQ_CMD_WR_TOP_1                    (1UL<<10)
        #define TXP_FTQ_CMD_SFT_RESET                       (1UL<<25)
        #define TXP_FTQ_CMD_RD_DATA                         (1UL<<26)
        #define TXP_FTQ_CMD_ADD_INTERVEN                    (1UL<<27)
        #define TXP_FTQ_CMD_ADD_DATA                        (1UL<<28)
        #define TXP_FTQ_CMD_INTERVENE_CLR                   (1UL<<29)
        #define TXP_FTQ_CMD_POP                             (1UL<<30)
        #define TXP_FTQ_CMD_BUSY                            (1UL<<31)

    u32_t txp_ftq_ctl;
        #define TXP_FTQ_CTL_INTERVENE                       (1UL<<0)
        #define TXP_FTQ_CTL_OVERFLOW                        (1UL<<1)
        #define TXP_FTQ_CTL_FORCE_INTERVENE                 (1UL<<2)
        #define TXP_FTQ_CTL_MAX_DEPTH                       (0x3ffUL<<12)
        #define TXP_FTQ_CTL_CUR_DEPTH                       (0x3ffUL<<22)

    u32_t unused_6[27392];
    u32_t txp_scratch[8192];
    u32_t unused_7[24576];
} txp_reg_t;

typedef txp_reg_t tx_processor_reg_t;

/*
 *  tx_patchup_enqueue definition
 *  offset: 0000
 */
typedef struct tx_patchup_enqueue
{
    u32_t tx_patchup_enqueue_cid;
        #define TX_PATCHUP_ENQUEUE_CID_VALUE                (0x3fffUL<<7)

    u32_t tx_patchup_enqueue_wd1;
        #define TX_PATCHUP_ENQUEUE_NBYTES_VALUE             (0x3fff<<16)
        #define TX_PATCHUP_ENQUEUE_XNUM                     (0xff<<8)
        #define TX_PATCHUP_ENQUEUE_KNUM                     (0xff<<0)

    u32_t tx_patchup_enqueue_flags_flags;
        #define TX_PATCHUP_ENQUEUE_FLAGS_FLAGS_PLUS_TWO     (1UL<<0)
        #define TX_PATCHUP_ENQUEUE_FLAGS_FLAGS_TCP_UDP_CKSUM  (1UL<<1)
        #define TX_PATCHUP_ENQUEUE_FLAGS_FLAGS_IP_CKSUM     (1UL<<2)
        #define TX_PATCHUP_ENQUEUE_FLAGS_FLAGS_INCR_CMD     (1UL<<3)
        #define TX_PATCHUP_ENQUEUE_FLAGS_FLAGS_COAL_NOW     (1UL<<4)
        #define TX_PATCHUP_ENQUEUE_FLAGS_FLAGS_DONT_GEN_CRC  (1UL<<5)
        #define TX_PATCHUP_ENQUEUE_FLAGS_FLAGS_LAST_PKT     (1UL<<6)
        #define TX_PATCHUP_ENQUEUE_FLAGS_FLAGS_PKT_FRAG     (1UL<<7)
        #define TX_PATCHUP_ENQUEUE_FLAGS_FLAGS_QUICK_CID_ENA  (1UL<<9)
        #define TX_PATCHUP_ENQUEUE_FLAGS_FLAGS_QUICK_CID_TE    (0x3UL<<10)
        #define TX_PATCHUP_ENQUEUE_FLAGS_FLAGS_RSVD_FUTURE_XI  (0x3UL<<10)
        #define TX_PATCHUP_ENQUEUE_FLAGS_FLAGS_L5_PAGE_MODE  (1UL<<12)
        #define TX_PATCHUP_ENQUEUE_FLAGS_FLAGS_COMPLETE     (1UL<<13)
        #define TX_PATCHUP_ENQUEUE_FLAGS_FLAGS_RETRAN       (1UL<<14)
        #define TX_PATCHUP_ENQUEUE_FLAGS_FLAGS_END_PADDING  (0xfUL<<16)
        #define TX_PATCHUP_ENQUEUE_FLAGS_FLAGS_USAGE_CNT    (1UL<<20)
            #define TX_PATCHUP_ENQUEUE_FLAGS_FLAGS_USAGE_CNT_AUTODECREMENT  (0UL<<20)
            #define TX_PATCHUP_ENQUEUE_FLAGS_FLAGS_USAGE_CNT_DONOTDECREMENT  (1UL<<20)
        #define TX_PATCHUP_ENQUEUE_FLAGS_FLAGS_BSEQ_INVLD   (1UL<<21)
        #define TX_PATCHUP_ENQUEUE_FLAGS_FLAGS_WORK_AROUND  (0x3UL<<22)
        #define TX_PATCHUP_ENQUEUE_FLAGS_FLAGS_HOLE_SZ      (0x3UL<<25)
            #define TX_PATCHUP_ENQUEUE_FLAGS_FLAGS_HOLE_SZ_4  (0UL<<25)
            #define TX_PATCHUP_ENQUEUE_FLAGS_FLAGS_HOLE_SZ_8  (1UL<<25)
            #define TX_PATCHUP_ENQUEUE_FLAGS_FLAGS_HOLE_SZ_12  (2UL<<25)
            #define TX_PATCHUP_ENQUEUE_FLAGS_FLAGS_HOLE_SZ_16  (3UL<<25)
        #define TX_PATCHUP_ENQUEUE_FLAGS_FLAGS_HOLE0        (1UL<<28)
        #define TX_PATCHUP_ENQUEUE_FLAGS_FLAGS_HOLE1        (1UL<<29)
        #define TX_PATCHUP_ENQUEUE_FLAGS_FLAGS_HOLE2        (1UL<<30)

    u32_t tx_patchup_enqueue_wd3;
        #define TX_PATCHUP_ENQUEUE_RAW_CHKSUM               (0xffff<<16)
        #define TX_PATCHUP_ENQUEUE_TPAT_BIDX                (0xffff<<0)

    u32_t tx_patchup_enqueue_wd4;
        #define TX_PATCHUP_ENQUEUE_STATUS_CS16_ERR          (1<<24)

} tx_patchup_enqueue_t;


/*
 *  tpat_reg definition
 *  offset: 0x80000
 */
typedef struct tpat_reg
{
    u32_t unused_0[5120];
    u32_t tpat_cpu_mode;
        #define TPAT_CPU_MODE_LOCAL_RST                     (1UL<<0)
        #define TPAT_CPU_MODE_STEP_ENA                      (1UL<<1)
        #define TPAT_CPU_MODE_PAGE_0_DATA_ENA               (1UL<<2)
        #define TPAT_CPU_MODE_PAGE_0_INST_ENA               (1UL<<3)
        #define TPAT_CPU_MODE_MSG_BIT1                      (1UL<<6)
        #define TPAT_CPU_MODE_INTERRUPT_ENA                 (1UL<<7)
        #define TPAT_CPU_MODE_SOFT_HALT                     (1UL<<10)
        #define TPAT_CPU_MODE_BAD_DATA_HALT_ENA             (1UL<<11)
        #define TPAT_CPU_MODE_BAD_INST_HALT_ENA             (1UL<<12)
        #define TPAT_CPU_MODE_FIO_ABORT_HALT_ENA            (1UL<<13)
        #define TPAT_CPU_MODE_SPAD_UNDERFLOW_HALT_ENA       (1UL<<15)

    u32_t tpat_cpu_state;
        #define TPAT_CPU_STATE_BREAKPOINT                   (1UL<<0)
        #define TPAT_CPU_STATE_BAD_INST_HALTED              (1UL<<2)
        #define TPAT_CPU_STATE_PAGE_0_DATA_HALTED           (1UL<<3)
        #define TPAT_CPU_STATE_PAGE_0_INST_HALTED           (1UL<<4)
        #define TPAT_CPU_STATE_BAD_DATA_ADDR_HALTED         (1UL<<5)
        #define TPAT_CPU_STATE_BAD_PC_HALTED                (1UL<<6)
        #define TPAT_CPU_STATE_ALIGN_HALTED                 (1UL<<7)
        #define TPAT_CPU_STATE_FIO_ABORT_HALTED             (1UL<<8)
        #define TPAT_CPU_STATE_SOFT_HALTED                  (1UL<<10)
        #define TPAT_CPU_STATE_SPAD_UNDERFLOW               (1UL<<11)
        #define TPAT_CPU_STATE_INTERRRUPT                   (1UL<<12)
        #define TPAT_CPU_STATE_DATA_ACCESS_STALL            (1UL<<14)
        #define TPAT_CPU_STATE_INST_FETCH_STALL             (1UL<<15)
        #define TPAT_CPU_STATE_BLOCKED_READ                 (1UL<<31)

    u32_t tpat_cpu_event_mask;
        #define TPAT_CPU_EVENT_MASK_BREAKPOINT_MASK         (1UL<<0)
        #define TPAT_CPU_EVENT_MASK_BAD_INST_HALTED_MASK    (1UL<<2)
        #define TPAT_CPU_EVENT_MASK_PAGE_0_DATA_HALTED_MASK  (1UL<<3)
        #define TPAT_CPU_EVENT_MASK_PAGE_0_INST_HALTED_MASK  (1UL<<4)
        #define TPAT_CPU_EVENT_MASK_BAD_DATA_ADDR_HALTED_MASK  (1UL<<5)
        #define TPAT_CPU_EVENT_MASK_BAD_PC_HALTED_MASK      (1UL<<6)
        #define TPAT_CPU_EVENT_MASK_ALIGN_HALTED_MASK       (1UL<<7)
        #define TPAT_CPU_EVENT_MASK_FIO_ABORT_MASK          (1UL<<8)
        #define TPAT_CPU_EVENT_MASK_SOFT_HALTED_MASK        (1UL<<10)
        #define TPAT_CPU_EVENT_MASK_SPAD_UNDERFLOW_MASK     (1UL<<11)
        #define TPAT_CPU_EVENT_MASK_INTERRUPT_MASK          (1UL<<12)

    u32_t unused_1[4];
    u32_t tpat_cpu_program_counter;
    u32_t tpat_cpu_instruction;
    u32_t tpat_cpu_data_access;
    u32_t tpat_cpu_interrupt_enable;
    u32_t tpat_cpu_interrupt_vector;
    u32_t tpat_cpu_interrupt_saved_PC;
    u32_t tpat_cpu_hw_breakpoint;
        #define TPAT_CPU_HW_BREAKPOINT_DISABLE              (1UL<<0)
        #define TPAT_CPU_HW_BREAKPOINT_ADDRESS              (0x3fffffffUL<<2)

    u32_t tpat_cpu_debug_vect_peek;
        #define TPAT_CPU_DEBUG_VECT_PEEK_1_VALUE            (0x7ffUL<<0)
        #define TPAT_CPU_DEBUG_VECT_PEEK_1_PEEK_EN          (1UL<<11)
        #define TPAT_CPU_DEBUG_VECT_PEEK_1_SEL              (0xfUL<<12)
        #define TPAT_CPU_DEBUG_VECT_PEEK_2_VALUE            (0x7ffUL<<16)
        #define TPAT_CPU_DEBUG_VECT_PEEK_2_PEEK_EN          (1UL<<27)
        #define TPAT_CPU_DEBUG_VECT_PEEK_2_SEL              (0xfUL<<28)

    u32_t unused_2[3];
    u32_t tpat_cpu_last_branch_addr;
        #define TPAT_CPU_LAST_BRANCH_ADDR_TYPE              (1UL<<1)
            #define TPAT_CPU_LAST_BRANCH_ADDR_TYPE_JUMP     (0UL<<1)
            #define TPAT_CPU_LAST_BRANCH_ADDR_TYPE_BRANCH   (1UL<<1)
        #define TPAT_CPU_LAST_BRANCH_ADDR_LBA               (0x3fffffffUL<<2)

    u32_t unused_3[109];
    u32_t tpat_cpu_reg_file[32];
    u32_t unused_4[80];
    tx_patchup_enqueue_t tpat_tpatq;
    u32_t unused_5[9];
    u32_t tpat_ftq_cmd;
        #define TPAT_FTQ_CMD_OFFSET                         (0x3ffUL<<0)
        #define TPAT_FTQ_CMD_WR_TOP                         (1UL<<10)
            #define TPAT_FTQ_CMD_WR_TOP_0                   (0UL<<10)
            #define TPAT_FTQ_CMD_WR_TOP_1                   (1UL<<10)
        #define TPAT_FTQ_CMD_SFT_RESET                      (1UL<<25)
        #define TPAT_FTQ_CMD_RD_DATA                        (1UL<<26)
        #define TPAT_FTQ_CMD_ADD_INTERVEN                   (1UL<<27)
        #define TPAT_FTQ_CMD_ADD_DATA                       (1UL<<28)
        #define TPAT_FTQ_CMD_INTERVENE_CLR                  (1UL<<29)
        #define TPAT_FTQ_CMD_POP                            (1UL<<30)
        #define TPAT_FTQ_CMD_BUSY                           (1UL<<31)

    u32_t tpat_ftq_ctl;
        #define TPAT_FTQ_CTL_INTERVENE                      (1UL<<0)
        #define TPAT_FTQ_CTL_OVERFLOW                       (1UL<<1)
        #define TPAT_FTQ_CTL_FORCE_INTERVENE                (1UL<<2)
        #define TPAT_FTQ_CTL_MAX_DEPTH                      (0x3ffUL<<12)
        #define TPAT_FTQ_CTL_CUR_DEPTH                      (0x3ffUL<<22)

    u32_t unused_6[27392];
    u32_t tpat_scratch[3072];
    u32_t unused_7[29696];
} tpat_reg_t;

typedef tpat_reg_t tx_patchup_reg_t;

/*
 *  rx_processor_cmd_enqueue definition
 *  offset: 0000
 */
typedef struct rx_processor_cmd_enqueue
{
    u32_t rx_processor_cmd_enqueue_cid;
        #define RX_PROCESSOR_CMD_ENQUEUE_CID_VALUE          (0x3fffUL<<7)

    u32_t rx_processor_cmd_enqueue_wd1;
        #define RX_PROCESSOR_CMD_ENQUEUE_WORK_ID            (0xffff<<16)
        #define RX_PROCESSOR_CMD_ENQUEUE_CMD_TYPE           (0xffff<<0)

    u32_t rx_processor_cmd_enqueue_wd2;
        #define RX_PROCESSOR_CMD_ENQUEUE_CMD_STATUS_VALUE   (0xfff<<16)
        #define RX_PROCESSOR_CMD_ENQUEUE_CMD_STATUS_DRIVER_ID  (0xf<<28)
        #define RX_PROCESSOR_CMD_ENQUEUE_OPAQUE             (0xffff<<0)

    u32_t rx_processor_cmd_enqueue_wd3;
        #define RX_PROCESSOR_CMD_ENQUEUE_RSVD_FUTURE_VALUE  (0x3<<24)

} rx_processor_cmd_enqueue_t;


/*
 *  rx_processor_enqueue definition
 *  offset: 0000
 */
typedef struct rx_processor_enqueue
{
    u32_t rx_processor_enqueue_bits_errors;
        #define RX_PROCESSOR_ENQUEUE_BITS_ERRORS_L2_BAD_CRC  (1UL<<1)
        #define RX_PROCESSOR_ENQUEUE_BITS_ERRORS_L2_PHY_DECODE  (1UL<<2)
        #define RX_PROCESSOR_ENQUEUE_BITS_ERRORS_L2_ALIGNMENT  (1UL<<3)
        #define RX_PROCESSOR_ENQUEUE_BITS_ERRORS_L2_TOO_SHORT  (1UL<<4)
        #define RX_PROCESSOR_ENQUEUE_BITS_ERRORS_L2_GIANT_FRAME  (1UL<<5)
        #define RX_PROCESSOR_ENQUEUE_BITS_ERRORS_IP_BAD_LEN  (1UL<<6)
        #define RX_PROCESSOR_ENQUEUE_BITS_ERRORS_IP_TOO_SHORT  (1UL<<7)
        #define RX_PROCESSOR_ENQUEUE_BITS_ERRORS_IP_BAD_VERSION  (1UL<<8)
        #define RX_PROCESSOR_ENQUEUE_BITS_ERRORS_IP_BAD_HLEN  (1UL<<9)
        #define RX_PROCESSOR_ENQUEUE_BITS_ERRORS_IP_BAD_XSUM  (1UL<<10)
        #define RX_PROCESSOR_ENQUEUE_BITS_ERRORS_TCP_TOO_SHORT  (1UL<<11)
        #define RX_PROCESSOR_ENQUEUE_BITS_ERRORS_TCP_BAD_XSUM  (1UL<<12)
        #define RX_PROCESSOR_ENQUEUE_BITS_ERRORS_TCP_BAD_OFFSET  (1UL<<13)
        #define RX_PROCESSOR_ENQUEUE_BITS_ERRORS_TCP_SYNC_PRESENT  (1UL<<14)
        #define RX_PROCESSOR_ENQUEUE_BITS_ERRORS_UDP_BAD_XSUM  (1UL<<15)
        #define RX_PROCESSOR_ENQUEUE_BITS_ERRORS_IP_BAD_ORDER  (1UL<<16)
        #define RX_PROCESSOR_ENQUEUE_BITS_ERRORS_IP_HDR_MISMATCH  (1UL<<18)

    u32_t rx_processor_enqueue_bits_status;
        #define RX_PROCESSOR_ENQUEUE_BITS_STATUS_RULE_CLASS  (0x7UL<<0)
        #define RX_PROCESSOR_ENQUEUE_BITS_STATUS_RULE_P2    (1UL<<3)
        #define RX_PROCESSOR_ENQUEUE_BITS_STATUS_RULE_P3    (1UL<<4)
        #define RX_PROCESSOR_ENQUEUE_BITS_STATUS_RULE_P4    (1UL<<5)
        #define RX_PROCESSOR_ENQUEUE_BITS_STATUS_L2_VLAN_TAG  (1UL<<6)
        #define RX_PROCESSOR_ENQUEUE_BITS_STATUS_L2_LLC_SNAP  (1UL<<7)
        #define RX_PROCESSOR_ENQUEUE_BITS_STATUS_RSS_HASH   (1UL<<8)
        #define RX_PROCESSOR_ENQUEUE_BITS_STATUS_SORT_VECT  (0xfUL<<9)
        #define RX_PROCESSOR_ENQUEUE_BITS_STATUS_IP_DATAGRAM  (1UL<<13)
        #define RX_PROCESSOR_ENQUEUE_BITS_STATUS_TCP_SEGMENT  (1UL<<14)
        #define RX_PROCESSOR_ENQUEUE_BITS_STATUS_UDP_DATAGRAM  (1UL<<15)
        #define RX_PROCESSOR_ENQUEUE_BITS_STATUS_CU_FRAME   (1UL<<16)
        #define RX_PROCESSOR_ENQUEUE_BITS_STATUS_IP_PROG_EXT  (1UL<<17)
        #define RX_PROCESSOR_ENQUEUE_BITS_STATUS_IP_TYPE    (1UL<<18)
        #define RX_PROCESSOR_ENQUEUE_BITS_STATUS_RULE_P1    (1UL<<19)
        #define RX_PROCESSOR_ENQUEUE_BITS_STATUS_VALID_TE      (1UL<<20)
        #define RX_PROCESSOR_ENQUEUE_BITS_STATUS_RLUP_HIT4_XI  (1UL<<20)
        #define RX_PROCESSOR_ENQUEUE_BITS_STATUS_IP_FRAGMENT  (1UL<<21)
        #define RX_PROCESSOR_ENQUEUE_BITS_STATUS_IP_OPTIONS_PRESENT  (1UL<<22)
        #define RX_PROCESSOR_ENQUEUE_BITS_STATUS_TCP_OPTIONS_PRESENT  (1UL<<23)
        #define RX_PROCESSOR_ENQUEUE_BITS_STATUS_L2_PM_IDX  (0xfUL<<24)
        #define RX_PROCESSOR_ENQUEUE_BITS_STATUS_L2_PM_HIT  (1UL<<28)
        #define RX_PROCESSOR_ENQUEUE_BITS_STATUS_L2_MC_HASH_HIT  (1UL<<29)
        #define RX_PROCESSOR_ENQUEUE_BITS_STATUS_RDMAC_CRC_PASS  (1UL<<30)
        #define RX_PROCESSOR_ENQUEUE_BITS_STATUS_MP_HIT     (1UL<<31)

    u32_t rx_processor_enqueue_wd2;
        #define RX_PROCESSOR_ENQUEUE_BITS_MULTICAST_HASH_IDX  (0xff<<24)
        #define RX_PROCESSOR_ENQUEUE_BITS_ACPI_PAT_ACPI_PAT_TE  (0x7<<16)
            #define RX_PROCESSOR_ENQUEUE_BITS_ACPI_PAT_ACPI_PAT_0_TE  (0<<16)
            #define RX_PROCESSOR_ENQUEUE_BITS_ACPI_PAT_ACPI_PAT_1_TE  (1<<16)
            #define RX_PROCESSOR_ENQUEUE_BITS_ACPI_PAT_ACPI_PAT_2_TE  (2<<16)
            #define RX_PROCESSOR_ENQUEUE_BITS_ACPI_PAT_ACPI_PAT_3_TE  (3<<16)
            #define RX_PROCESSOR_ENQUEUE_BITS_ACPI_PAT_ACPI_PAT_4_TE  (4<<16)
            #define RX_PROCESSOR_ENQUEUE_BITS_ACPI_PAT_ACPI_PAT_5_TE  (5<<16)
            #define RX_PROCESSOR_ENQUEUE_BITS_ACPI_PAT_ACPI_PAT_6_TE  (6<<16)
            #define RX_PROCESSOR_ENQUEUE_BITS_ACPI_PAT_ACPI_PAT_NONE_TE  (7<<16)
        #define RX_PROCESSOR_ENQUEUE_BITS_ACPI_PAT_ACPI_PAT_XI  (0xf<<16)
            #define RX_PROCESSOR_ENQUEUE_BITS_ACPI_PAT_ACPI_PAT_0_XI  (0<<16)
            #define RX_PROCESSOR_ENQUEUE_BITS_ACPI_PAT_ACPI_PAT_1_XI  (1<<16)
            #define RX_PROCESSOR_ENQUEUE_BITS_ACPI_PAT_ACPI_PAT_2_XI  (2<<16)
            #define RX_PROCESSOR_ENQUEUE_BITS_ACPI_PAT_ACPI_PAT_3_XI  (3<<16)
            #define RX_PROCESSOR_ENQUEUE_BITS_ACPI_PAT_ACPI_PAT_4_XI  (4<<16)
            #define RX_PROCESSOR_ENQUEUE_BITS_ACPI_PAT_ACPI_PAT_5_XI  (5<<16)
            #define RX_PROCESSOR_ENQUEUE_BITS_ACPI_PAT_ACPI_PAT_6_XI  (6<<16)
            #define RX_PROCESSOR_ENQUEUE_BITS_ACPI_PAT_ACPI_PAT_NONE_XI  (7<<16)
            #define RX_PROCESSOR_ENQUEUE_BITS_ACPI_PAT_ACPI_PAT_8_XI  (8<<16)
        #define RX_PROCESSOR_ENQUEUE_KNUM                   (0xff<<8)

    u32_t rx_processor_enqueue_wd3;
        #define RX_PROCESSOR_ENQUEUE_RULE_TAG               (0xffff<<16)
        #define RX_PROCESSOR_ENQUEUE_PKT_LEN_VALUE          (0x3fff<<0)

    u32_t rx_processor_enqueue_wd4;
        #define RX_PROCESSOR_ENQUEUE_VLAN_TAG               (0xffff<<16)
        #define RX_PROCESSOR_ENQUEUE_IP_HDR_OFFSET          (0xff<<8)
        #define RX_PROCESSOR_ENQUEUE_RX_QID_VALUE           (0xf<<0)

    u32_t rx_processor_enqueue_wd5;
        #define RX_PROCESSOR_ENQUEUE_IP_XSUM                (0xffff<<16)
        #define RX_PROCESSOR_ENQUEUE_TCP_UDP_HDR_OFFSET     (0xffff<<0)

    u32_t rx_processor_enqueue_wd6;
        #define RX_PROCESSOR_ENQUEUE_TCP_UDP_XSUM           (0xffff<<16)
        #define RX_PROCESSOR_ENQUEUE_TCP_PAYLOAD_LEN        (0xffff<<0)

    u32_t rx_processor_enqueue_wd7;
        #define RX_PROCESSOR_ENQUEUE_PSEUD_XSUM             (0xffff<<16)
        #define RX_PROCESSOR_ENQUEUE_L2_PAYLOAD_RAW_XSUM    (0xffff<<0)

    u32_t rx_processor_enqueue_wd8;
        #define RX_PROCESSOR_ENQUEUE_DATA_OFFSET            (0xffff<<16)
        #define RX_PROCESSOR_ENQUEUE_L3_PAYLOAD_RAW_XSUM    (0xffff<<0)

    u32_t rx_processor_enqueue_mbuf_cluster;
        #define RX_PROCESSOR_ENQUEUE_MBUF_CLUSTER_VALUE     (0x1ffffffUL<<0)

    u32_t rx_processor_enqueue_cid;
        #define RX_PROCESSOR_ENQUEUE_CID_VALUE              (0x3fffUL<<7)

    u32_t rx_processor_enqueue_wd11;
        #define RX_PROCESSOR_ENQUEUE_CS16_VALUE             (0xffff<<16)

    u32_t rx_processor_enqueue_wd12;
        #define RX_PROCESSOR_ENQUEUE_EXT_STATUS_TCP_SYNC_PRESENT  (1<<16)
        #define RX_PROCESSOR_ENQUEUE_EXT_STATUS_RLUP_HIT2   (1<<17)
        #define RX_PROCESSOR_ENQUEUE_EXT_STATUS_TCP_UDP_XSUM_IS_0  (1<<18)
        #define RX_PROCESSOR_ENQUEUE_EXT_STATUS_IP_ROUTING_HDR_PRESENT  (0x3<<19)
            #define RX_PROCESSOR_ENQUEUE_EXT_STATUS_IP_ROUTING_HDR_PRESENT_00  (0<<19)
            #define RX_PROCESSOR_ENQUEUE_EXT_STATUS_IP_ROUTING_HDR_PRESENT_01  (1<<19)
            #define RX_PROCESSOR_ENQUEUE_EXT_STATUS_IP_ROUTING_HDR_PRESENT_10  (2<<19)
            #define RX_PROCESSOR_ENQUEUE_EXT_STATUS_IP_ROUTING_HDR_PRESENT_11  (3<<19)
        #define RX_PROCESSOR_ENQUEUE_EXT_STATUS_ACPI_MATCH  (1<<21)

} rx_processor_enqueue_t;


/*
 *  rxp_reg definition
 *  offset: 0xc0000
 */
typedef struct rxp_reg
{
    u32_t unused_0[5120];
    u32_t rxp_cpu_mode;
        #define RXP_CPU_MODE_LOCAL_RST                      (1UL<<0)
        #define RXP_CPU_MODE_STEP_ENA                       (1UL<<1)
        #define RXP_CPU_MODE_PAGE_0_DATA_ENA                (1UL<<2)
        #define RXP_CPU_MODE_PAGE_0_INST_ENA                (1UL<<3)
        #define RXP_CPU_MODE_MSG_BIT1                       (1UL<<6)
        #define RXP_CPU_MODE_INTERRUPT_ENA                  (1UL<<7)
        #define RXP_CPU_MODE_SOFT_HALT                      (1UL<<10)
        #define RXP_CPU_MODE_BAD_DATA_HALT_ENA              (1UL<<11)
        #define RXP_CPU_MODE_BAD_INST_HALT_ENA              (1UL<<12)
        #define RXP_CPU_MODE_FIO_ABORT_HALT_ENA             (1UL<<13)
        #define RXP_CPU_MODE_SPAD_UNDERFLOW_HALT_ENA        (1UL<<15)

    u32_t rxp_cpu_state;
        #define RXP_CPU_STATE_BREAKPOINT                    (1UL<<0)
        #define RXP_CPU_STATE_BAD_INST_HALTED               (1UL<<2)
        #define RXP_CPU_STATE_PAGE_0_DATA_HALTED            (1UL<<3)
        #define RXP_CPU_STATE_PAGE_0_INST_HALTED            (1UL<<4)
        #define RXP_CPU_STATE_BAD_DATA_ADDR_HALTED          (1UL<<5)
        #define RXP_CPU_STATE_BAD_PC_HALTED                 (1UL<<6)
        #define RXP_CPU_STATE_ALIGN_HALTED                  (1UL<<7)
        #define RXP_CPU_STATE_FIO_ABORT_HALTED              (1UL<<8)
        #define RXP_CPU_STATE_SOFT_HALTED                   (1UL<<10)
        #define RXP_CPU_STATE_SPAD_UNDERFLOW                (1UL<<11)
        #define RXP_CPU_STATE_INTERRRUPT                    (1UL<<12)
        #define RXP_CPU_STATE_DATA_ACCESS_STALL             (1UL<<14)
        #define RXP_CPU_STATE_INST_FETCH_STALL              (1UL<<15)
        #define RXP_CPU_STATE_BLOCKED_READ                  (1UL<<31)

    u32_t rxp_cpu_event_mask;
        #define RXP_CPU_EVENT_MASK_BREAKPOINT_MASK          (1UL<<0)
        #define RXP_CPU_EVENT_MASK_BAD_INST_HALTED_MASK     (1UL<<2)
        #define RXP_CPU_EVENT_MASK_PAGE_0_DATA_HALTED_MASK  (1UL<<3)
        #define RXP_CPU_EVENT_MASK_PAGE_0_INST_HALTED_MASK  (1UL<<4)
        #define RXP_CPU_EVENT_MASK_BAD_DATA_ADDR_HALTED_MASK  (1UL<<5)
        #define RXP_CPU_EVENT_MASK_BAD_PC_HALTED_MASK       (1UL<<6)
        #define RXP_CPU_EVENT_MASK_ALIGN_HALTED_MASK        (1UL<<7)
        #define RXP_CPU_EVENT_MASK_FIO_ABORT_MASK           (1UL<<8)
        #define RXP_CPU_EVENT_MASK_SOFT_HALTED_MASK         (1UL<<10)
        #define RXP_CPU_EVENT_MASK_SPAD_UNDERFLOW_MASK      (1UL<<11)
        #define RXP_CPU_EVENT_MASK_INTERRUPT_MASK           (1UL<<12)

    u32_t unused_1[4];
    u32_t rxp_cpu_program_counter;
    u32_t rxp_cpu_instruction;
    u32_t rxp_cpu_data_access;
    u32_t rxp_cpu_interrupt_enable;
    u32_t rxp_cpu_interrupt_vector;
    u32_t rxp_cpu_interrupt_saved_PC;
    u32_t rxp_cpu_hw_breakpoint;
        #define RXP_CPU_HW_BREAKPOINT_DISABLE               (1UL<<0)
        #define RXP_CPU_HW_BREAKPOINT_ADDRESS               (0x3fffffffUL<<2)

    u32_t rxp_cpu_debug_vect_peek;
        #define RXP_CPU_DEBUG_VECT_PEEK_1_VALUE             (0x7ffUL<<0)
        #define RXP_CPU_DEBUG_VECT_PEEK_1_PEEK_EN           (1UL<<11)
        #define RXP_CPU_DEBUG_VECT_PEEK_1_SEL               (0xfUL<<12)
        #define RXP_CPU_DEBUG_VECT_PEEK_2_VALUE             (0x7ffUL<<16)
        #define RXP_CPU_DEBUG_VECT_PEEK_2_PEEK_EN           (1UL<<27)
        #define RXP_CPU_DEBUG_VECT_PEEK_2_SEL               (0xfUL<<28)

    u32_t unused_2[3];
    u32_t rxp_cpu_last_branch_addr;
        #define RXP_CPU_LAST_BRANCH_ADDR_TYPE               (1UL<<1)
            #define RXP_CPU_LAST_BRANCH_ADDR_TYPE_JUMP      (0UL<<1)
            #define RXP_CPU_LAST_BRANCH_ADDR_TYPE_BRANCH    (1UL<<1)
        #define RXP_CPU_LAST_BRANCH_ADDR_LBA                (0x3fffffffUL<<2)

    u32_t unused_3[109];
    u32_t rxp_cpu_reg_file[32];
    u32_t unused_4[63];
    u32_t rxp_pfe_pfe_ctl;
        #define RXP_PFE_PFE_CTL_INC_USAGE_CNT               (1UL<<0)
        #define RXP_PFE_PFE_CTL_PFE_SIZE                    (0xfUL<<4)
            #define RXP_PFE_PFE_CTL_PFE_SIZE_0              (0UL<<4)
            #define RXP_PFE_PFE_CTL_PFE_SIZE_1              (1UL<<4)
            #define RXP_PFE_PFE_CTL_PFE_SIZE_2              (2UL<<4)
            #define RXP_PFE_PFE_CTL_PFE_SIZE_3              (3UL<<4)
            #define RXP_PFE_PFE_CTL_PFE_SIZE_4              (4UL<<4)
            #define RXP_PFE_PFE_CTL_PFE_SIZE_5              (5UL<<4)
            #define RXP_PFE_PFE_CTL_PFE_SIZE_6              (6UL<<4)
            #define RXP_PFE_PFE_CTL_PFE_SIZE_7              (7UL<<4)
            #define RXP_PFE_PFE_CTL_PFE_SIZE_8              (8UL<<4)
            #define RXP_PFE_PFE_CTL_PFE_SIZE_9              (9UL<<4)
            #define RXP_PFE_PFE_CTL_PFE_SIZE_10             (10UL<<4)
            #define RXP_PFE_PFE_CTL_PFE_SIZE_11             (11UL<<4)
            #define RXP_PFE_PFE_CTL_PFE_SIZE_12             (12UL<<4)
            #define RXP_PFE_PFE_CTL_PFE_SIZE_13             (13UL<<4)
            #define RXP_PFE_PFE_CTL_PFE_SIZE_14             (14UL<<4)
            #define RXP_PFE_PFE_CTL_PFE_SIZE_15             (15UL<<4)
        #define RXP_PFE_PFE_CTL_PFE_COUNT                   (0xfUL<<12)
        #define RXP_PFE_PFE_CTL_OFFSET                      (0x1ffUL<<16)

    rx_processor_cmd_enqueue_t rxp_rxpcq;
    u32_t unused_5[10];
    u32_t rxp_cftq_cmd;
        #define RXP_CFTQ_CMD_OFFSET                         (0x3ffUL<<0)
        #define RXP_CFTQ_CMD_WR_TOP                         (1UL<<10)
            #define RXP_CFTQ_CMD_WR_TOP_0                   (0UL<<10)
            #define RXP_CFTQ_CMD_WR_TOP_1                   (1UL<<10)
        #define RXP_CFTQ_CMD_SFT_RESET                      (1UL<<25)
        #define RXP_CFTQ_CMD_RD_DATA                        (1UL<<26)
        #define RXP_CFTQ_CMD_ADD_INTERVEN                   (1UL<<27)
        #define RXP_CFTQ_CMD_ADD_DATA                       (1UL<<28)
        #define RXP_CFTQ_CMD_INTERVENE_CLR                  (1UL<<29)
        #define RXP_CFTQ_CMD_POP                            (1UL<<30)
        #define RXP_CFTQ_CMD_BUSY                           (1UL<<31)

    u32_t rxp_cftq_ctl;
        #define RXP_CFTQ_CTL_INTERVENE                      (1UL<<0)
        #define RXP_CFTQ_CTL_OVERFLOW                       (1UL<<1)
        #define RXP_CFTQ_CTL_FORCE_INTERVENE                (1UL<<2)
        #define RXP_CFTQ_CTL_MAX_DEPTH                      (0x3ffUL<<12)
        #define RXP_CFTQ_CTL_CUR_DEPTH                      (0x3ffUL<<22)

    rx_processor_enqueue_t rxp_rxpq;
    u32_t unused_6;
    u32_t rxp_ftq_cmd;
        #define RXP_FTQ_CMD_OFFSET                          (0x3ffUL<<0)
        #define RXP_FTQ_CMD_WR_TOP                          (1UL<<10)
            #define RXP_FTQ_CMD_WR_TOP_0                    (0UL<<10)
            #define RXP_FTQ_CMD_WR_TOP_1                    (1UL<<10)
        #define RXP_FTQ_CMD_SFT_RESET                       (1UL<<25)
        #define RXP_FTQ_CMD_RD_DATA                         (1UL<<26)
        #define RXP_FTQ_CMD_ADD_INTERVEN                    (1UL<<27)
        #define RXP_FTQ_CMD_ADD_DATA                        (1UL<<28)
        #define RXP_FTQ_CMD_INTERVENE_CLR                   (1UL<<29)
        #define RXP_FTQ_CMD_POP                             (1UL<<30)
        #define RXP_FTQ_CMD_BUSY                            (1UL<<31)

    u32_t rxp_ftq_ctl;
        #define RXP_FTQ_CTL_INTERVENE                       (1UL<<0)
        #define RXP_FTQ_CTL_OVERFLOW                        (1UL<<1)
        #define RXP_FTQ_CTL_FORCE_INTERVENE                 (1UL<<2)
        #define RXP_FTQ_CTL_MAX_DEPTH                       (0x3ffUL<<12)
        #define RXP_FTQ_CTL_CUR_DEPTH                       (0x3ffUL<<22)

    u32_t unused_7[27392];
    u32_t rxp_scratch[10240];
    u32_t unused_8[22528];
} rxp_reg_t;

typedef rxp_reg_t rx_processor_reg_t;

/*
 *  completion_tx_enqueue definition
 *  offset: 0000
 */
typedef struct completion_tx_enqueue
{
    u32_t completion_tx_enqueue_cid;
        #define COMPLETION_TX_ENQUEUE_CID_VALUE             (0x3fffUL<<7)

    u32_t completion_tx_enqueue_wd1;
        #define COMPLETION_TX_ENQUEUE_FLAGS_CMD             (0xff<<16)
        #define COMPLETION_TX_ENQUEUE_FLAGS_COMPLETE        (1<<24)
        #define COMPLETION_TX_ENQUEUE_FLAGS_RETRAN          (1<<25)

    u32_t completion_tx_enqueue_snd_next;
    u32_t completion_tx_enqueue_wd3;
        #define COMPLETION_TX_ENQUEUE_NEW_FLAGS_USAGE_CNT   (1<<24)
            #define COMPLETION_TX_ENQUEUE_NEW_FLAGS_USAGE_CNT_AUTODECREMENT  (0<<24)
            #define COMPLETION_TX_ENQUEUE_NEW_FLAGS_USAGE_CNT_DONOTDECREMENT  (1<<24)
        #define COMPLETION_TX_ENQUEUE_NEW_FLAGS_BSEQ_INVLD  (1<<25)
        #define COMPLETION_TX_ENQUEUE_NEW_FLAGS_WORK_AROUND  (0x3<<26)

} completion_tx_enqueue_t;


/*
 *  completion_timeout_enqueue definition
 *  offset: 0000
 */
typedef struct completion_timeout_enqueue
{
    u32_t completion_timeout_enqueue_cid;
        #define COMPLETION_TIMEOUT_ENQUEUE_CID_VALUE        (0x3fffUL<<7)

    u32_t completion_timeout_enqueue_tmr_val;
    u32_t completion_timeout_enqueue_wd2;
        #define COMPLETION_TIMEOUT_ENQUEUE_TMR_TYPE_TYPE    (0x7<<24)
            #define COMPLETION_TIMEOUT_ENQUEUE_TMR_TYPE_TYPE_SW  (0<<24)
            #define COMPLETION_TIMEOUT_ENQUEUE_TMR_TYPE_TYPE_RETRAN  (1<<24)
            #define COMPLETION_TIMEOUT_ENQUEUE_TMR_TYPE_TYPE_PUSH  (2<<24)
            #define COMPLETION_TIMEOUT_ENQUEUE_TMR_TYPE_TYPE_DELAY_ACK  (3<<24)
            #define COMPLETION_TIMEOUT_ENQUEUE_TMR_TYPE_TYPE_KEEP_ALIVE  (4<<24)
            #define COMPLETION_TIMEOUT_ENQUEUE_TMR_TYPE_TYPE_NAGLE  (5<<24)
        #define COMPLETION_TIMEOUT_ENQUEUE_TMR_TYPE_EVENT_UNUSED  (1<<28)
        #define COMPLETION_TIMEOUT_ENQUEUE_RSVD_FUTURE_VALUE  (0x3<<16)

} completion_timeout_enqueue_t;


/*
 *  completion_enqueue definition
 *  offset: 0000
 */
typedef struct completion_enqueue
{
    u32_t completion_enqueue_cid;
        #define COMPLETION_ENQUEUE_CID_VALUE                (0x3fffUL<<7)

    u32_t completion_enqueue_mbuf_cluster;
        #define COMPLETION_ENQUEUE_MBUF_CLUSTER_VALUE       (0x1ffffffUL<<0)

    u32_t completion_enqueue_wd2;
        #define COMPLETION_ENQUEUE_OPERAND_FLAGS            (0xffff<<16)
        #define COMPLETION_ENQUEUE_KNUM                     (0xff<<8)
        #define COMPLETION_ENQUEUE_OPCODE                   (0xff<<0)

    u32_t completion_enqueue_wd3;
        #define COMPLETION_ENQUEUE_OPERAND16_2              (0xffff<<16)
        #define COMPLETION_ENQUEUE_OPERAND16_3              (0xffff<<0)

    u32_t completion_enqueue_wd4;
        #define COMPLETION_ENQUEUE_OPERAND16_4              (0xffff<<16)
        #define COMPLETION_ENQUEUE_OPERAND16_5              (0xffff<<0)

    u32_t completion_enqueue_wd5;
        #define COMPLETION_ENQUEUE_OPERAND16_6              (0xffff<<16)
        #define COMPLETION_ENQUEUE_OPERAND16_7              (0xffff<<0)

    u32_t completion_enqueue_operand32_2;
    u32_t completion_enqueue_operand32_3;
    u32_t completion_enqueue_operand32_4;
    u32_t completion_enqueue_wd9;
        #define COMPLETION_ENQUEUE_RDMA_ACTION_DO_DMA       (1<<24)
        #define COMPLETION_ENQUEUE_RDMA_ACTION_PREPEND_L2_FRAME_HDR  (1<<25)
        #define COMPLETION_ENQUEUE_RDMA_ACTION_CRC_ENABLE   (1<<26)
        #define COMPLETION_ENQUEUE_RDMA_ACTION_CRC_USE_CTX_SEED  (1<<27)
        #define COMPLETION_ENQUEUE_RDMA_ACTION_CS16_FIRST   (1<<28)
        #define COMPLETION_ENQUEUE_RDMA_ACTION_CS16_LAST    (1<<29)
        #define COMPLETION_ENQUEUE_RDMA_ACTION_CS16_VLD     (1<<30)
        #define COMPLETION_ENQUEUE_RDMA_ACTION_CS16_ERR     (1<<31)
        #define COMPLETION_ENQUEUE_CS16_PKT_LEN_VALUE       (0x7f<<16)
        #define COMPLETION_ENQUEUE_CS16                     (0xffff<<0)

} completion_enqueue_t;


/*
 *  com_reg definition
 *  offset: 0x100000
 */
typedef struct com_reg
{
    u32_t com_cksum_error_status;
        #define COM_CKSUM_ERROR_STATUS_CALCULATED           (0xffffUL<<0)
        #define COM_CKSUM_ERROR_STATUS_EXPECTED             (0xffffUL<<16)

    u32_t unused_0[5119];
    u32_t com_cpu_mode;
        #define COM_CPU_MODE_LOCAL_RST                      (1UL<<0)
        #define COM_CPU_MODE_STEP_ENA                       (1UL<<1)
        #define COM_CPU_MODE_PAGE_0_DATA_ENA                (1UL<<2)
        #define COM_CPU_MODE_PAGE_0_INST_ENA                (1UL<<3)
        #define COM_CPU_MODE_MSG_BIT1                       (1UL<<6)
        #define COM_CPU_MODE_INTERRUPT_ENA                  (1UL<<7)
        #define COM_CPU_MODE_SOFT_HALT                      (1UL<<10)
        #define COM_CPU_MODE_BAD_DATA_HALT_ENA              (1UL<<11)
        #define COM_CPU_MODE_BAD_INST_HALT_ENA              (1UL<<12)
        #define COM_CPU_MODE_FIO_ABORT_HALT_ENA             (1UL<<13)
        #define COM_CPU_MODE_SPAD_UNDERFLOW_HALT_ENA        (1UL<<15)

    u32_t com_cpu_state;
        #define COM_CPU_STATE_BREAKPOINT                    (1UL<<0)
        #define COM_CPU_STATE_BAD_INST_HALTED               (1UL<<2)
        #define COM_CPU_STATE_PAGE_0_DATA_HALTED            (1UL<<3)
        #define COM_CPU_STATE_PAGE_0_INST_HALTED            (1UL<<4)
        #define COM_CPU_STATE_BAD_DATA_ADDR_HALTED          (1UL<<5)
        #define COM_CPU_STATE_BAD_PC_HALTED                 (1UL<<6)
        #define COM_CPU_STATE_ALIGN_HALTED                  (1UL<<7)
        #define COM_CPU_STATE_FIO_ABORT_HALTED              (1UL<<8)
        #define COM_CPU_STATE_SOFT_HALTED                   (1UL<<10)
        #define COM_CPU_STATE_SPAD_UNDERFLOW                (1UL<<11)
        #define COM_CPU_STATE_INTERRRUPT                    (1UL<<12)
        #define COM_CPU_STATE_DATA_ACCESS_STALL             (1UL<<14)
        #define COM_CPU_STATE_INST_FETCH_STALL              (1UL<<15)
        #define COM_CPU_STATE_BLOCKED_READ                  (1UL<<31)

    u32_t com_cpu_event_mask;
        #define COM_CPU_EVENT_MASK_BREAKPOINT_MASK          (1UL<<0)
        #define COM_CPU_EVENT_MASK_BAD_INST_HALTED_MASK     (1UL<<2)
        #define COM_CPU_EVENT_MASK_PAGE_0_DATA_HALTED_MASK  (1UL<<3)
        #define COM_CPU_EVENT_MASK_PAGE_0_INST_HALTED_MASK  (1UL<<4)
        #define COM_CPU_EVENT_MASK_BAD_DATA_ADDR_HALTED_MASK  (1UL<<5)
        #define COM_CPU_EVENT_MASK_BAD_PC_HALTED_MASK       (1UL<<6)
        #define COM_CPU_EVENT_MASK_ALIGN_HALTED_MASK        (1UL<<7)
        #define COM_CPU_EVENT_MASK_FIO_ABORT_MASK           (1UL<<8)
        #define COM_CPU_EVENT_MASK_SOFT_HALTED_MASK         (1UL<<10)
        #define COM_CPU_EVENT_MASK_SPAD_UNDERFLOW_MASK      (1UL<<11)
        #define COM_CPU_EVENT_MASK_INTERRUPT_MASK           (1UL<<12)

    u32_t unused_1[4];
    u32_t com_cpu_program_counter;
    u32_t com_cpu_instruction;
    u32_t com_cpu_data_access;
    u32_t com_cpu_interrupt_enable;
    u32_t com_cpu_interrupt_vector;
    u32_t com_cpu_interrupt_saved_PC;
    u32_t com_cpu_hw_breakpoint;
        #define COM_CPU_HW_BREAKPOINT_DISABLE               (1UL<<0)
        #define COM_CPU_HW_BREAKPOINT_ADDRESS               (0x3fffffffUL<<2)

    u32_t com_cpu_debug_vect_peek;
        #define COM_CPU_DEBUG_VECT_PEEK_1_VALUE             (0x7ffUL<<0)
        #define COM_CPU_DEBUG_VECT_PEEK_1_PEEK_EN           (1UL<<11)
        #define COM_CPU_DEBUG_VECT_PEEK_1_SEL               (0xfUL<<12)
        #define COM_CPU_DEBUG_VECT_PEEK_2_VALUE             (0x7ffUL<<16)
        #define COM_CPU_DEBUG_VECT_PEEK_2_PEEK_EN           (1UL<<27)
        #define COM_CPU_DEBUG_VECT_PEEK_2_SEL               (0xfUL<<28)

    u32_t unused_2[3];
    u32_t com_cpu_last_branch_addr;
        #define COM_CPU_LAST_BRANCH_ADDR_TYPE               (1UL<<1)
            #define COM_CPU_LAST_BRANCH_ADDR_TYPE_JUMP      (0UL<<1)
            #define COM_CPU_LAST_BRANCH_ADDR_TYPE_BRANCH    (1UL<<1)
        #define COM_CPU_LAST_BRANCH_ADDR_LBA                (0x3fffffffUL<<2)

    u32_t unused_3[109];
    u32_t com_cpu_reg_file[32];
    u32_t unused_4[15];
    u32_t com_comtq_pfe_pfe_ctl;
        #define COM_COMTQ_PFE_PFE_CTL_INC_USAGE_CNT         (1UL<<0)
        #define COM_COMTQ_PFE_PFE_CTL_PFE_SIZE              (0xfUL<<4)
            #define COM_COMTQ_PFE_PFE_CTL_PFE_SIZE_0        (0UL<<4)
            #define COM_COMTQ_PFE_PFE_CTL_PFE_SIZE_1        (1UL<<4)
            #define COM_COMTQ_PFE_PFE_CTL_PFE_SIZE_2        (2UL<<4)
            #define COM_COMTQ_PFE_PFE_CTL_PFE_SIZE_3        (3UL<<4)
            #define COM_COMTQ_PFE_PFE_CTL_PFE_SIZE_4        (4UL<<4)
            #define COM_COMTQ_PFE_PFE_CTL_PFE_SIZE_5        (5UL<<4)
            #define COM_COMTQ_PFE_PFE_CTL_PFE_SIZE_6        (6UL<<4)
            #define COM_COMTQ_PFE_PFE_CTL_PFE_SIZE_7        (7UL<<4)
            #define COM_COMTQ_PFE_PFE_CTL_PFE_SIZE_8        (8UL<<4)
            #define COM_COMTQ_PFE_PFE_CTL_PFE_SIZE_9        (9UL<<4)
            #define COM_COMTQ_PFE_PFE_CTL_PFE_SIZE_10       (10UL<<4)
            #define COM_COMTQ_PFE_PFE_CTL_PFE_SIZE_11       (11UL<<4)
            #define COM_COMTQ_PFE_PFE_CTL_PFE_SIZE_12       (12UL<<4)
            #define COM_COMTQ_PFE_PFE_CTL_PFE_SIZE_13       (13UL<<4)
            #define COM_COMTQ_PFE_PFE_CTL_PFE_SIZE_14       (14UL<<4)
            #define COM_COMTQ_PFE_PFE_CTL_PFE_SIZE_15       (15UL<<4)
        #define COM_COMTQ_PFE_PFE_CTL_PFE_COUNT             (0xfUL<<12)
        #define COM_COMTQ_PFE_PFE_CTL_OFFSET                (0x1ffUL<<16)

    u32_t unused_5[32];
    completion_tx_enqueue_t com_comxq;
    u32_t unused_6[10];
    u32_t com_comxq_ftq_cmd;
        #define COM_COMXQ_FTQ_CMD_OFFSET                    (0x3ffUL<<0)
        #define COM_COMXQ_FTQ_CMD_WR_TOP                    (1UL<<10)
            #define COM_COMXQ_FTQ_CMD_WR_TOP_0              (0UL<<10)
            #define COM_COMXQ_FTQ_CMD_WR_TOP_1              (1UL<<10)
        #define COM_COMXQ_FTQ_CMD_SFT_RESET                 (1UL<<25)
        #define COM_COMXQ_FTQ_CMD_RD_DATA                   (1UL<<26)
        #define COM_COMXQ_FTQ_CMD_ADD_INTERVEN              (1UL<<27)
        #define COM_COMXQ_FTQ_CMD_ADD_DATA                  (1UL<<28)
        #define COM_COMXQ_FTQ_CMD_INTERVENE_CLR             (1UL<<29)
        #define COM_COMXQ_FTQ_CMD_POP                       (1UL<<30)
        #define COM_COMXQ_FTQ_CMD_BUSY                      (1UL<<31)

    u32_t com_comxq_ftq_ctl;
        #define COM_COMXQ_FTQ_CTL_INTERVENE                 (1UL<<0)
        #define COM_COMXQ_FTQ_CTL_OVERFLOW                  (1UL<<1)
        #define COM_COMXQ_FTQ_CTL_FORCE_INTERVENE           (1UL<<2)
        #define COM_COMXQ_FTQ_CTL_MAX_DEPTH                 (0x3ffUL<<12)
        #define COM_COMXQ_FTQ_CTL_CUR_DEPTH                 (0x3ffUL<<22)

    completion_timeout_enqueue_t com_comtq;
    u32_t unused_7[11];
    u32_t com_comtq_ftq_cmd;
        #define COM_COMTQ_FTQ_CMD_OFFSET                    (0x3ffUL<<0)
        #define COM_COMTQ_FTQ_CMD_WR_TOP                    (1UL<<10)
            #define COM_COMTQ_FTQ_CMD_WR_TOP_0              (0UL<<10)
            #define COM_COMTQ_FTQ_CMD_WR_TOP_1              (1UL<<10)
        #define COM_COMTQ_FTQ_CMD_SFT_RESET                 (1UL<<25)
        #define COM_COMTQ_FTQ_CMD_RD_DATA                   (1UL<<26)
        #define COM_COMTQ_FTQ_CMD_ADD_INTERVEN              (1UL<<27)
        #define COM_COMTQ_FTQ_CMD_ADD_DATA                  (1UL<<28)
        #define COM_COMTQ_FTQ_CMD_INTERVENE_CLR             (1UL<<29)
        #define COM_COMTQ_FTQ_CMD_POP                       (1UL<<30)
        #define COM_COMTQ_FTQ_CMD_BUSY                      (1UL<<31)

    u32_t com_comtq_ftq_ctl;
        #define COM_COMTQ_FTQ_CTL_INTERVENE                 (1UL<<0)
        #define COM_COMTQ_FTQ_CTL_OVERFLOW                  (1UL<<1)
        #define COM_COMTQ_FTQ_CTL_FORCE_INTERVENE           (1UL<<2)
        #define COM_COMTQ_FTQ_CTL_MAX_DEPTH                 (0x3ffUL<<12)
        #define COM_COMTQ_FTQ_CTL_CUR_DEPTH                 (0x3ffUL<<22)

    completion_enqueue_t com_comq;
    u32_t unused_8[4];
    u32_t com_comq_ftq_cmd;
        #define COM_COMQ_FTQ_CMD_OFFSET                     (0x3ffUL<<0)
        #define COM_COMQ_FTQ_CMD_WR_TOP                     (1UL<<10)
            #define COM_COMQ_FTQ_CMD_WR_TOP_0               (0UL<<10)
            #define COM_COMQ_FTQ_CMD_WR_TOP_1               (1UL<<10)
        #define COM_COMQ_FTQ_CMD_SFT_RESET                  (1UL<<25)
        #define COM_COMQ_FTQ_CMD_RD_DATA                    (1UL<<26)
        #define COM_COMQ_FTQ_CMD_ADD_INTERVEN               (1UL<<27)
        #define COM_COMQ_FTQ_CMD_ADD_DATA                   (1UL<<28)
        #define COM_COMQ_FTQ_CMD_INTERVENE_CLR              (1UL<<29)
        #define COM_COMQ_FTQ_CMD_POP                        (1UL<<30)
        #define COM_COMQ_FTQ_CMD_BUSY                       (1UL<<31)

    u32_t com_comq_ftq_ctl;
        #define COM_COMQ_FTQ_CTL_INTERVENE                  (1UL<<0)
        #define COM_COMQ_FTQ_CTL_OVERFLOW                   (1UL<<1)
        #define COM_COMQ_FTQ_CTL_FORCE_INTERVENE            (1UL<<2)
        #define COM_COMQ_FTQ_CTL_MAX_DEPTH                  (0x3ffUL<<12)
        #define COM_COMQ_FTQ_CTL_CUR_DEPTH                  (0x3ffUL<<22)

    u32_t unused_9[27392];
    u32_t com_scratch[10240];
    u32_t unused_10[22528];
} com_reg_t;

typedef com_reg_t completion_reg_t;

/*
 *  cmd_processor_enqueue definition
 *  offset: 0000
 */
typedef struct cmd_processor_enqueue
{
    u32_t cmd_processor_enqueue_cid;
        #define CMD_PROCESSOR_ENQUEUE_CID_VALUE             (0x3fffUL<<7)

} cmd_processor_enqueue_t;


/*
 *  cp_reg definition
 *  offset: 0x180000
 */
typedef struct cp_reg
{
    u32_t cp_cksum_error_status;
        #define CP_CKSUM_ERROR_STATUS_CALCULATED            (0xffffUL<<0)
        #define CP_CKSUM_ERROR_STATUS_EXPECTED              (0xffffUL<<16)

    u32_t unused_0[5119];
    u32_t cp_cpu_mode;
        #define CP_CPU_MODE_LOCAL_RST                       (1UL<<0)
        #define CP_CPU_MODE_STEP_ENA                        (1UL<<1)
        #define CP_CPU_MODE_PAGE_0_DATA_ENA                 (1UL<<2)
        #define CP_CPU_MODE_PAGE_0_INST_ENA                 (1UL<<3)
        #define CP_CPU_MODE_MSG_BIT1                        (1UL<<6)
        #define CP_CPU_MODE_INTERRUPT_ENA                   (1UL<<7)
        #define CP_CPU_MODE_SOFT_HALT                       (1UL<<10)
        #define CP_CPU_MODE_BAD_DATA_HALT_ENA               (1UL<<11)
        #define CP_CPU_MODE_BAD_INST_HALT_ENA               (1UL<<12)
        #define CP_CPU_MODE_FIO_ABORT_HALT_ENA              (1UL<<13)
        #define CP_CPU_MODE_SPAD_UNDERFLOW_HALT_ENA         (1UL<<15)

    u32_t cp_cpu_state;
        #define CP_CPU_STATE_BREAKPOINT                     (1UL<<0)
        #define CP_CPU_STATE_BAD_INST_HALTED                (1UL<<2)
        #define CP_CPU_STATE_PAGE_0_DATA_HALTED             (1UL<<3)
        #define CP_CPU_STATE_PAGE_0_INST_HALTED             (1UL<<4)
        #define CP_CPU_STATE_BAD_DATA_ADDR_HALTED           (1UL<<5)
        #define CP_CPU_STATE_BAD_PC_HALTED                  (1UL<<6)
        #define CP_CPU_STATE_ALIGN_HALTED                   (1UL<<7)
        #define CP_CPU_STATE_FIO_ABORT_HALTED               (1UL<<8)
        #define CP_CPU_STATE_SOFT_HALTED                    (1UL<<10)
        #define CP_CPU_STATE_SPAD_UNDERFLOW                 (1UL<<11)
        #define CP_CPU_STATE_INTERRRUPT                     (1UL<<12)
        #define CP_CPU_STATE_DATA_ACCESS_STALL              (1UL<<14)
        #define CP_CPU_STATE_INST_FETCH_STALL               (1UL<<15)
        #define CP_CPU_STATE_BLOCKED_READ                   (1UL<<31)

    u32_t cp_cpu_event_mask;
        #define CP_CPU_EVENT_MASK_BREAKPOINT_MASK           (1UL<<0)
        #define CP_CPU_EVENT_MASK_BAD_INST_HALTED_MASK      (1UL<<2)
        #define CP_CPU_EVENT_MASK_PAGE_0_DATA_HALTED_MASK   (1UL<<3)
        #define CP_CPU_EVENT_MASK_PAGE_0_INST_HALTED_MASK   (1UL<<4)
        #define CP_CPU_EVENT_MASK_BAD_DATA_ADDR_HALTED_MASK  (1UL<<5)
        #define CP_CPU_EVENT_MASK_BAD_PC_HALTED_MASK        (1UL<<6)
        #define CP_CPU_EVENT_MASK_ALIGN_HALTED_MASK         (1UL<<7)
        #define CP_CPU_EVENT_MASK_FIO_ABORT_MASK            (1UL<<8)
        #define CP_CPU_EVENT_MASK_SOFT_HALTED_MASK          (1UL<<10)
        #define CP_CPU_EVENT_MASK_SPAD_UNDERFLOW_MASK       (1UL<<11)
        #define CP_CPU_EVENT_MASK_INTERRUPT_MASK            (1UL<<12)

    u32_t unused_1[4];
    u32_t cp_cpu_program_counter;
    u32_t cp_cpu_instruction;
    u32_t cp_cpu_data_access;
    u32_t cp_cpu_interrupt_enable;
    u32_t cp_cpu_interrupt_vector;
    u32_t cp_cpu_interrupt_saved_PC;
    u32_t cp_cpu_hw_breakpoint;
        #define CP_CPU_HW_BREAKPOINT_DISABLE                (1UL<<0)
        #define CP_CPU_HW_BREAKPOINT_ADDRESS                (0x3fffffffUL<<2)

    u32_t cp_cpu_debug_vect_peek;
        #define CP_CPU_DEBUG_VECT_PEEK_1_VALUE              (0x7ffUL<<0)
        #define CP_CPU_DEBUG_VECT_PEEK_1_PEEK_EN            (1UL<<11)
        #define CP_CPU_DEBUG_VECT_PEEK_1_SEL                (0xfUL<<12)
        #define CP_CPU_DEBUG_VECT_PEEK_2_VALUE              (0x7ffUL<<16)
        #define CP_CPU_DEBUG_VECT_PEEK_2_PEEK_EN            (1UL<<27)
        #define CP_CPU_DEBUG_VECT_PEEK_2_SEL                (0xfUL<<28)

    u32_t unused_2[3];
    u32_t cp_cpu_last_branch_addr;
        #define CP_CPU_LAST_BRANCH_ADDR_TYPE                (1UL<<1)
            #define CP_CPU_LAST_BRANCH_ADDR_TYPE_JUMP       (0UL<<1)
            #define CP_CPU_LAST_BRANCH_ADDR_TYPE_BRANCH     (1UL<<1)
        #define CP_CPU_LAST_BRANCH_ADDR_LBA                 (0x3fffffffUL<<2)

    u32_t unused_3[109];
    u32_t cp_cpu_reg_file[32];
    u32_t unused_4[79];
    u32_t cp_cpq_pfe_pfe_ctl;
        #define CP_CPQ_PFE_PFE_CTL_INC_USAGE_CNT            (1UL<<0)
        #define CP_CPQ_PFE_PFE_CTL_PFE_SIZE                 (0xfUL<<4)
            #define CP_CPQ_PFE_PFE_CTL_PFE_SIZE_0           (0UL<<4)
            #define CP_CPQ_PFE_PFE_CTL_PFE_SIZE_1           (1UL<<4)
            #define CP_CPQ_PFE_PFE_CTL_PFE_SIZE_2           (2UL<<4)
            #define CP_CPQ_PFE_PFE_CTL_PFE_SIZE_3           (3UL<<4)
            #define CP_CPQ_PFE_PFE_CTL_PFE_SIZE_4           (4UL<<4)
            #define CP_CPQ_PFE_PFE_CTL_PFE_SIZE_5           (5UL<<4)
            #define CP_CPQ_PFE_PFE_CTL_PFE_SIZE_6           (6UL<<4)
            #define CP_CPQ_PFE_PFE_CTL_PFE_SIZE_7           (7UL<<4)
            #define CP_CPQ_PFE_PFE_CTL_PFE_SIZE_8           (8UL<<4)
            #define CP_CPQ_PFE_PFE_CTL_PFE_SIZE_9           (9UL<<4)
            #define CP_CPQ_PFE_PFE_CTL_PFE_SIZE_10          (10UL<<4)
            #define CP_CPQ_PFE_PFE_CTL_PFE_SIZE_11          (11UL<<4)
            #define CP_CPQ_PFE_PFE_CTL_PFE_SIZE_12          (12UL<<4)
            #define CP_CPQ_PFE_PFE_CTL_PFE_SIZE_13          (13UL<<4)
            #define CP_CPQ_PFE_PFE_CTL_PFE_SIZE_14          (14UL<<4)
            #define CP_CPQ_PFE_PFE_CTL_PFE_SIZE_15          (15UL<<4)
        #define CP_CPQ_PFE_PFE_CTL_PFE_COUNT                (0xfUL<<12)
        #define CP_CPQ_PFE_PFE_CTL_OFFSET                   (0x1ffUL<<16)

    cmd_processor_enqueue_t cp_cpq;
    u32_t unused_5[13];
    u32_t cp_cpq_ftq_cmd;
        #define CP_CPQ_FTQ_CMD_OFFSET                       (0x3ffUL<<0)
        #define CP_CPQ_FTQ_CMD_WR_TOP                       (1UL<<10)
            #define CP_CPQ_FTQ_CMD_WR_TOP_0                 (0UL<<10)
            #define CP_CPQ_FTQ_CMD_WR_TOP_1                 (1UL<<10)
        #define CP_CPQ_FTQ_CMD_SFT_RESET                    (1UL<<25)
        #define CP_CPQ_FTQ_CMD_RD_DATA                      (1UL<<26)
        #define CP_CPQ_FTQ_CMD_ADD_INTERVEN                 (1UL<<27)
        #define CP_CPQ_FTQ_CMD_ADD_DATA                     (1UL<<28)
        #define CP_CPQ_FTQ_CMD_INTERVENE_CLR                (1UL<<29)
        #define CP_CPQ_FTQ_CMD_POP                          (1UL<<30)
        #define CP_CPQ_FTQ_CMD_BUSY                         (1UL<<31)

    u32_t cp_cpq_ftq_ctl;
        #define CP_CPQ_FTQ_CTL_INTERVENE                    (1UL<<0)
        #define CP_CPQ_FTQ_CTL_OVERFLOW                     (1UL<<1)
        #define CP_CPQ_FTQ_CTL_FORCE_INTERVENE              (1UL<<2)
        #define CP_CPQ_FTQ_CTL_MAX_DEPTH                    (0x3ffUL<<12)
        #define CP_CPQ_FTQ_CTL_CUR_DEPTH                    (0x3ffUL<<22)

    u32_t unused_6[27392];
    u32_t cp_scratch[10240];
    u32_t unused_7[22528];
} cp_reg_t;

typedef cp_reg_t cmd_processor_reg_t;

/*
 *  management_enqueue definition
 *  offset: 0000
 */
typedef struct management_enqueue
{
    u32_t management_enqueue_bits_status;
        #define MANAGEMENT_ENQUEUE_BITS_STATUS_RULE_CLASS   (0x7UL<<0)
        #define MANAGEMENT_ENQUEUE_BITS_STATUS_RULE_P2      (1UL<<3)
        #define MANAGEMENT_ENQUEUE_BITS_STATUS_RULE_P3      (1UL<<4)
        #define MANAGEMENT_ENQUEUE_BITS_STATUS_RULE_P4      (1UL<<5)
        #define MANAGEMENT_ENQUEUE_BITS_STATUS_L2_VLAN_TAG  (1UL<<6)
        #define MANAGEMENT_ENQUEUE_BITS_STATUS_L2_LLC_SNAP  (1UL<<7)
        #define MANAGEMENT_ENQUEUE_BITS_STATUS_RSS_HASH     (1UL<<8)
        #define MANAGEMENT_ENQUEUE_BITS_STATUS_SORT_VECT    (0xfUL<<9)
        #define MANAGEMENT_ENQUEUE_BITS_STATUS_IP_DATAGRAM  (1UL<<13)
        #define MANAGEMENT_ENQUEUE_BITS_STATUS_TCP_SEGMENT  (1UL<<14)
        #define MANAGEMENT_ENQUEUE_BITS_STATUS_UDP_DATAGRAM  (1UL<<15)
        #define MANAGEMENT_ENQUEUE_BITS_STATUS_CU_FRAME     (1UL<<16)
        #define MANAGEMENT_ENQUEUE_BITS_STATUS_IP_PROG_EXT  (1UL<<17)
        #define MANAGEMENT_ENQUEUE_BITS_STATUS_IP_TYPE      (1UL<<18)
        #define MANAGEMENT_ENQUEUE_BITS_STATUS_RULE_P1      (1UL<<19)
        #define MANAGEMENT_ENQUEUE_BITS_STATUS_RLUP_HIT4    (1UL<<20)
        #define MANAGEMENT_ENQUEUE_BITS_STATUS_IP_FRAGMENT  (1UL<<21)
        #define MANAGEMENT_ENQUEUE_BITS_STATUS_IP_OPTIONS_PRESENT  (1UL<<22)
        #define MANAGEMENT_ENQUEUE_BITS_STATUS_TCP_OPTIONS_PRESENT  (1UL<<23)
        #define MANAGEMENT_ENQUEUE_BITS_STATUS_L2_PM_IDX    (0xfUL<<24)
        #define MANAGEMENT_ENQUEUE_BITS_STATUS_L2_PM_HIT    (1UL<<28)
        #define MANAGEMENT_ENQUEUE_BITS_STATUS_L2_MC_HASH_HIT  (1UL<<29)
        #define MANAGEMENT_ENQUEUE_BITS_STATUS_RDMAC_CRC_PASS  (1UL<<30)
        #define MANAGEMENT_ENQUEUE_BITS_STATUS_MP_HIT       (1UL<<31)

    u32_t management_enqueue_wd1;
        #define MANAGEMENT_ENQUEUE_PKT_LEN_VALUE            (0x3fff<<16)
        #define MANAGEMENT_ENQUEUE_VLAN_TAG                 (0xffff<<0)

    u32_t management_enqueue_mbuf_cluster;
        #define MANAGEMENT_ENQUEUE_MBUF_CLUSTER_VALUE       (0x1ffffffUL<<0)

    u32_t management_enqueue_frm_errors;
        #define MANAGEMENT_ENQUEUE_FRM_ERRORS_L2_BAD_CRC    (1UL<<1)
        #define MANAGEMENT_ENQUEUE_FRM_ERRORS_L2_PHY_DECODE  (1UL<<2)
        #define MANAGEMENT_ENQUEUE_FRM_ERRORS_L2_ALIGNMENT  (1UL<<3)
        #define MANAGEMENT_ENQUEUE_FRM_ERRORS_L2_TOO_SHORT  (1UL<<4)
        #define MANAGEMENT_ENQUEUE_FRM_ERRORS_L2_GIANT_FRAME  (1UL<<5)
        #define MANAGEMENT_ENQUEUE_FRM_ERRORS_IP_BAD_LEN    (1UL<<6)
        #define MANAGEMENT_ENQUEUE_FRM_ERRORS_IP_TOO_SHORT  (1UL<<7)
        #define MANAGEMENT_ENQUEUE_FRM_ERRORS_IP_BAD_VERSION  (1UL<<8)
        #define MANAGEMENT_ENQUEUE_FRM_ERRORS_IP_BAD_HLEN   (1UL<<9)
        #define MANAGEMENT_ENQUEUE_FRM_ERRORS_IP_BAD_XSUM   (1UL<<10)
        #define MANAGEMENT_ENQUEUE_FRM_ERRORS_TCP_TOO_SHORT  (1UL<<11)
        #define MANAGEMENT_ENQUEUE_FRM_ERRORS_TCP_BAD_XSUM  (1UL<<12)
        #define MANAGEMENT_ENQUEUE_FRM_ERRORS_TCP_BAD_OFFSET  (1UL<<13)
        #define MANAGEMENT_ENQUEUE_FRM_ERRORS_UDP_BAD_XSUM  (1UL<<15)
        #define MANAGEMENT_ENQUEUE_FRM_ERRORS_IP_BAD_ORDER  (1UL<<16)
        #define MANAGEMENT_ENQUEUE_FRM_ERRORS_IP_HDR_MISMATCH  (1UL<<18)

    u32_t management_enqueue_wd4;
        #define MANAGEMENT_ENQUEUE_EXT_STATUS_TCP_SYNC_PRESENT  (1<<16)
        #define MANAGEMENT_ENQUEUE_EXT_STATUS_RLUP_HIT2     (1<<17)
        #define MANAGEMENT_ENQUEUE_EXT_STATUS_TCP_UDP_XSUM_IS_0  (1<<18)
        #define MANAGEMENT_ENQUEUE_EXT_STATUS_IP_ROUTING_HDR_PRESENT  (0x3<<19)
            #define MANAGEMENT_ENQUEUE_EXT_STATUS_IP_ROUTING_HDR_PRESENT_00  (0<<19)
            #define MANAGEMENT_ENQUEUE_EXT_STATUS_IP_ROUTING_HDR_PRESENT_01  (1<<19)
            #define MANAGEMENT_ENQUEUE_EXT_STATUS_IP_ROUTING_HDR_PRESENT_10  (2<<19)
            #define MANAGEMENT_ENQUEUE_EXT_STATUS_IP_ROUTING_HDR_PRESENT_11  (3<<19)
        #define MANAGEMENT_ENQUEUE_EXT_STATUS_ACPI_MATCH    (1<<21)
        #define MANAGEMENT_ENQUEUE_RESERVED                 (0xffff<<0)

} management_enqueue_t;


/*
 *  mcp_reg definition
 *  offset: 0x140000
 */
typedef struct mcp_reg
{
    u32_t unused_0[32];
    u32_t mcp_mcp_control;
        #define MCP_MCP_CONTROL_SMBUS_SEL                   (1UL<<30)
        #define MCP_MCP_CONTROL_MCP_ISOLATE                 (1UL<<31)

    u32_t mcp_mcp_attention_status;
        #define MCP_MCP_ATTENTION_STATUS_DRV_DOORBELL       (1UL<<29)
        #define MCP_MCP_ATTENTION_STATUS_WATCHDOG_TIMEOUT   (1UL<<30)
        #define MCP_MCP_ATTENTION_STATUS_CPU_EVENT          (1UL<<31)

    u32_t mcp_mcp_heartbeat_control;
        #define MCP_MCP_HEARTBEAT_CONTROL_MCP_HEARTBEAT_ENABLE  (1UL<<31)

    u32_t mcp_mcp_heartbeat_status;
        #define MCP_MCP_HEARTBEAT_STATUS_MCP_HEARTBEAT_PERIOD  (0x7ffUL<<0)
        #define MCP_MCP_HEARTBEAT_STATUS_VALID              (1UL<<31)

    u32_t mcp_mcp_heartbeat;
        #define MCP_MCP_HEARTBEAT_MCP_HEARTBEAT_COUNT       (0x3fffffffUL<<0)
        #define MCP_MCP_HEARTBEAT_MCP_HEARTBEAT_INC         (1UL<<30)
        #define MCP_MCP_HEARTBEAT_MCP_HEARTBEAT_RESET       (1UL<<31)

    u32_t mcp_watchdog_reset;
        #define MCP_WATCHDOG_RESET_WATCHDOG_RESET           (1UL<<31)

    u32_t mcp_watchdog_control;
        #define MCP_WATCHDOG_CONTROL_WATCHDOG_TIMEOUT       (0xfffffffUL<<0)
        #define MCP_WATCHDOG_CONTROL_WATCHDOG_ATTN          (1UL<<29)
        #define MCP_WATCHDOG_CONTROL_MCP_RST_ENABLE         (1UL<<30)
        #define MCP_WATCHDOG_CONTROL_WATCHDOG_ENABLE        (1UL<<31)

    u32_t mcp_access_lock;
        #define MCP_ACCESS_LOCK_LOCK                        (1UL<<31)

    u32_t mcp_toe_id;
        #define MCP_TOE_ID_FUNCTION_ID                      (1UL<<31)

    u32_t mcp_mailbox_cfg;
        #define MCP_MAILBOX_CFG_MAILBOX_OFFSET              (0x3fffUL<<0)
        #define MCP_MAILBOX_CFG_MAILBOX_SIZE                (0xfffUL<<20)

    u32_t mcp_mailbox_cfg_other_func;
        #define MCP_MAILBOX_CFG_OTHER_FUNC_MAILBOX_OFFSET   (0x3fffUL<<0)
        #define MCP_MAILBOX_CFG_OTHER_FUNC_MAILBOX_SIZE     (0xfffUL<<20)

    u32_t mcp_mcp_doorbell;
        #define MCP_MCP_DOORBELL_MCP_DOORBELL               (1UL<<31)

    u32_t mcp_driver_doorbell;
        #define MCP_DRIVER_DOORBELL_DRIVER_DOORBELL         (1UL<<31)

    u32_t mcp_driver_doorbell_other_func;
        #define MCP_DRIVER_DOORBELL_OTHER_FUNC_DRIVER_DOORBELL  (1UL<<31)

    u32_t unused_1[5074];
    u32_t mcp_cpu_mode;
        #define MCP_CPU_MODE_LOCAL_RST                      (1UL<<0)
        #define MCP_CPU_MODE_STEP_ENA                       (1UL<<1)
        #define MCP_CPU_MODE_PAGE_0_DATA_ENA                (1UL<<2)
        #define MCP_CPU_MODE_PAGE_0_INST_ENA                (1UL<<3)
        #define MCP_CPU_MODE_MSG_BIT1                       (1UL<<6)
        #define MCP_CPU_MODE_INTERRUPT_ENA                  (1UL<<7)
        #define MCP_CPU_MODE_SOFT_HALT                      (1UL<<10)
        #define MCP_CPU_MODE_BAD_DATA_HALT_ENA              (1UL<<11)
        #define MCP_CPU_MODE_BAD_INST_HALT_ENA              (1UL<<12)
        #define MCP_CPU_MODE_FIO_ABORT_HALT_ENA             (1UL<<13)
        #define MCP_CPU_MODE_SPAD_UNDERFLOW_HALT_ENA        (1UL<<15)

    u32_t mcp_cpu_state;
        #define MCP_CPU_STATE_BREAKPOINT                    (1UL<<0)
        #define MCP_CPU_STATE_BAD_INST_HALTED               (1UL<<2)
        #define MCP_CPU_STATE_PAGE_0_DATA_HALTED            (1UL<<3)
        #define MCP_CPU_STATE_PAGE_0_INST_HALTED            (1UL<<4)
        #define MCP_CPU_STATE_BAD_DATA_ADDR_HALTED          (1UL<<5)
        #define MCP_CPU_STATE_BAD_PC_HALTED                 (1UL<<6)
        #define MCP_CPU_STATE_ALIGN_HALTED                  (1UL<<7)
        #define MCP_CPU_STATE_FIO_ABORT_HALTED              (1UL<<8)
        #define MCP_CPU_STATE_SOFT_HALTED                   (1UL<<10)
        #define MCP_CPU_STATE_SPAD_UNDERFLOW                (1UL<<11)
        #define MCP_CPU_STATE_INTERRRUPT                    (1UL<<12)
        #define MCP_CPU_STATE_DATA_ACCESS_STALL             (1UL<<14)
        #define MCP_CPU_STATE_INST_FETCH_STALL              (1UL<<15)
        #define MCP_CPU_STATE_BLOCKED_READ                  (1UL<<31)

    u32_t mcp_cpu_event_mask;
        #define MCP_CPU_EVENT_MASK_BREAKPOINT_MASK          (1UL<<0)
        #define MCP_CPU_EVENT_MASK_BAD_INST_HALTED_MASK     (1UL<<2)
        #define MCP_CPU_EVENT_MASK_PAGE_0_DATA_HALTED_MASK  (1UL<<3)
        #define MCP_CPU_EVENT_MASK_PAGE_0_INST_HALTED_MASK  (1UL<<4)
        #define MCP_CPU_EVENT_MASK_BAD_DATA_ADDR_HALTED_MASK  (1UL<<5)
        #define MCP_CPU_EVENT_MASK_BAD_PC_HALTED_MASK       (1UL<<6)
        #define MCP_CPU_EVENT_MASK_ALIGN_HALTED_MASK        (1UL<<7)
        #define MCP_CPU_EVENT_MASK_FIO_ABORT_MASK           (1UL<<8)
        #define MCP_CPU_EVENT_MASK_SOFT_HALTED_MASK         (1UL<<10)
        #define MCP_CPU_EVENT_MASK_SPAD_UNDERFLOW_MASK      (1UL<<11)
        #define MCP_CPU_EVENT_MASK_INTERRUPT_MASK           (1UL<<12)

    u32_t unused_2[4];
    u32_t mcp_cpu_program_counter;
    u32_t mcp_cpu_instruction;
    u32_t mcp_cpu_data_access;
    u32_t mcp_cpu_interrupt_enable;
    u32_t mcp_cpu_interrupt_vector;
    u32_t mcp_cpu_interrupt_saved_PC;
    u32_t mcp_cpu_hw_breakpoint;
        #define MCP_CPU_HW_BREAKPOINT_DISABLE               (1UL<<0)
        #define MCP_CPU_HW_BREAKPOINT_ADDRESS               (0x3fffffffUL<<2)

    u32_t mcp_cpu_debug_vect_peek;
        #define MCP_CPU_DEBUG_VECT_PEEK_1_VALUE             (0x7ffUL<<0)
        #define MCP_CPU_DEBUG_VECT_PEEK_1_PEEK_EN           (1UL<<11)
        #define MCP_CPU_DEBUG_VECT_PEEK_1_SEL               (0xfUL<<12)
        #define MCP_CPU_DEBUG_VECT_PEEK_2_VALUE             (0x7ffUL<<16)
        #define MCP_CPU_DEBUG_VECT_PEEK_2_PEEK_EN           (1UL<<27)
        #define MCP_CPU_DEBUG_VECT_PEEK_2_SEL               (0xfUL<<28)

    u32_t unused_3[3];
    u32_t mcp_cpu_last_branch_addr;
        #define MCP_CPU_LAST_BRANCH_ADDR_TYPE               (1UL<<1)
            #define MCP_CPU_LAST_BRANCH_ADDR_TYPE_JUMP      (0UL<<1)
            #define MCP_CPU_LAST_BRANCH_ADDR_TYPE_BRANCH    (1UL<<1)
        #define MCP_CPU_LAST_BRANCH_ADDR_LBA                (0x3fffffffUL<<2)

    u32_t unused_4[109];
    u32_t mcp_cpu_reg_file[32];
    u32_t unused_5[80];
    management_enqueue_t mcp_mcpq;
    u32_t unused_6[9];
    u32_t mcp_mcpq_ftq_cmd;
        #define MCP_MCPQ_FTQ_CMD_OFFSET                     (0x3ffUL<<0)
        #define MCP_MCPQ_FTQ_CMD_WR_TOP                     (1UL<<10)
            #define MCP_MCPQ_FTQ_CMD_WR_TOP_0               (0UL<<10)
            #define MCP_MCPQ_FTQ_CMD_WR_TOP_1               (1UL<<10)
        #define MCP_MCPQ_FTQ_CMD_SFT_RESET                  (1UL<<25)
        #define MCP_MCPQ_FTQ_CMD_RD_DATA                    (1UL<<26)
        #define MCP_MCPQ_FTQ_CMD_ADD_INTERVEN               (1UL<<27)
        #define MCP_MCPQ_FTQ_CMD_ADD_DATA                   (1UL<<28)
        #define MCP_MCPQ_FTQ_CMD_INTERVENE_CLR              (1UL<<29)
        #define MCP_MCPQ_FTQ_CMD_POP                        (1UL<<30)
        #define MCP_MCPQ_FTQ_CMD_BUSY                       (1UL<<31)

    u32_t mcp_mcpq_ftq_ctl;
        #define MCP_MCPQ_FTQ_CTL_INTERVENE                  (1UL<<0)
        #define MCP_MCPQ_FTQ_CTL_OVERFLOW                   (1UL<<1)
        #define MCP_MCPQ_FTQ_CTL_FORCE_INTERVENE            (1UL<<2)
        #define MCP_MCPQ_FTQ_CTL_MAX_DEPTH                  (0x3ffUL<<12)
        #define MCP_MCPQ_FTQ_CTL_CUR_DEPTH                  (0x3ffUL<<22)

    u32_t unused_7[1024];
    u32_t mcp_nvm_command;
        #define MCP_NVM_COMMAND_RST                         (1UL<<0)
        #define MCP_NVM_COMMAND_DONE                        (1UL<<3)
        #define MCP_NVM_COMMAND_DOIT                        (1UL<<4)
        #define MCP_NVM_COMMAND_WR                          (1UL<<5)
        #define MCP_NVM_COMMAND_ERASE                       (1UL<<6)
        #define MCP_NVM_COMMAND_FIRST                       (1UL<<7)
        #define MCP_NVM_COMMAND_LAST                        (1UL<<8)
        #define MCP_NVM_COMMAND_WREN                        (1UL<<16)
        #define MCP_NVM_COMMAND_WRDI                        (1UL<<17)
        #define MCP_NVM_COMMAND_RD_ID                       (1UL<<20)
        #define MCP_NVM_COMMAND_RD_STATUS                   (1UL<<21)
        #define MCP_NVM_COMMAND_MODE_256                    (1UL<<22)

    u32_t mcp_nvm_status;
        #define MCP_NVM_STATUS_SPI_FSM_STATE                (0x1fUL<<0)
            #define MCP_NVM_STATUS_SPI_FSM_STATE_SPI_IDLE   (0UL<<0)
            #define MCP_NVM_STATUS_SPI_FSM_STATE_SPI_CMD0   (1UL<<0)
            #define MCP_NVM_STATUS_SPI_FSM_STATE_SPI_CMD1   (2UL<<0)
            #define MCP_NVM_STATUS_SPI_FSM_STATE_SPI_CMD_FINISH0  (3UL<<0)
            #define MCP_NVM_STATUS_SPI_FSM_STATE_SPI_CMD_FINISH1  (4UL<<0)
            #define MCP_NVM_STATUS_SPI_FSM_STATE_SPI_ADDR0  (5UL<<0)
            #define MCP_NVM_STATUS_SPI_FSM_STATE_SPI_WRITE_DATA0  (6UL<<0)
            #define MCP_NVM_STATUS_SPI_FSM_STATE_SPI_WRITE_DATA1  (7UL<<0)
            #define MCP_NVM_STATUS_SPI_FSM_STATE_SPI_WRITE_DATA2  (8UL<<0)
            #define MCP_NVM_STATUS_SPI_FSM_STATE_SPI_READ_DATA0  (9UL<<0)
            #define MCP_NVM_STATUS_SPI_FSM_STATE_SPI_READ_DATA1  (10UL<<0)
            #define MCP_NVM_STATUS_SPI_FSM_STATE_SPI_READ_DATA2  (11UL<<0)
            #define MCP_NVM_STATUS_SPI_FSM_STATE_SPI_READ_STATUS_RDID0  (12UL<<0)
            #define MCP_NVM_STATUS_SPI_FSM_STATE_SPI_READ_STATUS_RDID1  (13UL<<0)
            #define MCP_NVM_STATUS_SPI_FSM_STATE_SPI_READ_STATUS_RDID2  (14UL<<0)
            #define MCP_NVM_STATUS_SPI_FSM_STATE_SPI_READ_STATUS_RDID3  (15UL<<0)
            #define MCP_NVM_STATUS_SPI_FSM_STATE_SPI_READ_STATUS_RDID4  (16UL<<0)
            #define MCP_NVM_STATUS_SPI_FSM_STATE_SPI_CHECK_BUSY0  (17UL<<0)
            #define MCP_NVM_STATUS_SPI_FSM_STATE_SPI_ST_WREN  (18UL<<0)
            #define MCP_NVM_STATUS_SPI_FSM_STATE_SPI_WAIT   (19UL<<0)

    u32_t mcp_nvm_write;
        #define MCP_NVM_WRITE_NVM_WRITE_VALUE               (0xffffffffUL<<0)
            #define MCP_NVM_WRITE_NVM_WRITE_VALUE_BIT_BANG  (0UL<<0)
            #define MCP_NVM_WRITE_NVM_WRITE_VALUE_SI        (1UL<<0)
            #define MCP_NVM_WRITE_NVM_WRITE_VALUE_SO        (2UL<<0)
            #define MCP_NVM_WRITE_NVM_WRITE_VALUE_CS_B      (4UL<<0)
            #define MCP_NVM_WRITE_NVM_WRITE_VALUE_SCLK      (8UL<<0)

    u32_t mcp_nvm_addr;
        #define MCP_NVM_ADDR_NVM_ADDR_VALUE                 (0xffffffUL<<0)
            #define MCP_NVM_ADDR_NVM_ADDR_VALUE_BIT_BANG    (0UL<<0)
            #define MCP_NVM_ADDR_NVM_ADDR_VALUE_SI          (1UL<<0)
            #define MCP_NVM_ADDR_NVM_ADDR_VALUE_SO          (2UL<<0)
            #define MCP_NVM_ADDR_NVM_ADDR_VALUE_CS_B        (4UL<<0)
            #define MCP_NVM_ADDR_NVM_ADDR_VALUE_SCLK        (8UL<<0)

    u32_t mcp_nvm_read;
        #define MCP_NVM_READ_NVM_READ_VALUE                 (0xffffffffUL<<0)
            #define MCP_NVM_READ_NVM_READ_VALUE_BIT_BANG    (0UL<<0)
            #define MCP_NVM_READ_NVM_READ_VALUE_SI          (1UL<<0)
            #define MCP_NVM_READ_NVM_READ_VALUE_SO          (2UL<<0)
            #define MCP_NVM_READ_NVM_READ_VALUE_CS_B        (4UL<<0)
            #define MCP_NVM_READ_NVM_READ_VALUE_SCLK        (8UL<<0)

    u32_t mcp_nvm_cfg1;
        #define MCP_NVM_CFG1_FLASH_MODE                     (1UL<<0)
        #define MCP_NVM_CFG1_BUFFER_MODE                    (1UL<<1)
        #define MCP_NVM_CFG1_PASS_MODE                      (1UL<<2)
        #define MCP_NVM_CFG1_BITBANG_MODE                   (1UL<<3)
        #define MCP_NVM_CFG1_STATUS_BIT                     (0x7UL<<4)
        #define MCP_NVM_CFG1_SPI_CLK_DIV                    (0xfUL<<7)
        #define MCP_NVM_CFG1_SEE_CLK_DIV                    (0x7ffUL<<11)
        #define MCP_NVM_CFG1_STRAP_CONTROL_0                (1UL<<23)
        #define MCP_NVM_CFG1_PROTECT_MODE                   (1UL<<24)
        #define MCP_NVM_CFG1_FLASH_SIZE                     (1UL<<25)
        #define MCP_NVM_CFG1_FW_USTRAP_1                    (1UL<<26)
        #define MCP_NVM_CFG1_FW_USTRAP_0                    (1UL<<27)
        #define MCP_NVM_CFG1_FW_USTRAP_2                    (1UL<<28)
        #define MCP_NVM_CFG1_FW_USTRAP_3                    (1UL<<29)
        #define MCP_NVM_CFG1_FW_FLASH_TYPE_EN               (1UL<<30)
        #define MCP_NVM_CFG1_COMPAT_BYPASSS                 (1UL<<31)

    u32_t mcp_nvm_cfg2;
        #define MCP_NVM_CFG2_ERASE_CMD                      (0xffUL<<0)
        #define MCP_NVM_CFG2_STATUS_CMD                     (0xffUL<<16)
        #define MCP_NVM_CFG2_READ_ID                        (0xffUL<<24)

    u32_t mcp_nvm_cfg3;
        #define MCP_NVM_CFG3_BUFFER_RD_CMD                  (0xffUL<<0)
        #define MCP_NVM_CFG3_WRITE_CMD                      (0xffUL<<8)
        #define MCP_NVM_CFG3_READ_CMD                       (0xffUL<<24)

    u32_t mcp_nvm_sw_arb;
        #define MCP_NVM_SW_ARB_ARB_REQ_SET0                 (1UL<<0)
        #define MCP_NVM_SW_ARB_ARB_REQ_SET1                 (1UL<<1)
        #define MCP_NVM_SW_ARB_ARB_REQ_SET2                 (1UL<<2)
        #define MCP_NVM_SW_ARB_ARB_REQ_SET3                 (1UL<<3)
        #define MCP_NVM_SW_ARB_ARB_REQ_CLR0                 (1UL<<4)
        #define MCP_NVM_SW_ARB_ARB_REQ_CLR1                 (1UL<<5)
        #define MCP_NVM_SW_ARB_ARB_REQ_CLR2                 (1UL<<6)
        #define MCP_NVM_SW_ARB_ARB_REQ_CLR3                 (1UL<<7)
        #define MCP_NVM_SW_ARB_ARB_ARB0                     (1UL<<8)
        #define MCP_NVM_SW_ARB_ARB_ARB1                     (1UL<<9)
        #define MCP_NVM_SW_ARB_ARB_ARB2                     (1UL<<10)
        #define MCP_NVM_SW_ARB_ARB_ARB3                     (1UL<<11)
        #define MCP_NVM_SW_ARB_REQ0                         (1UL<<12)
        #define MCP_NVM_SW_ARB_REQ1                         (1UL<<13)
        #define MCP_NVM_SW_ARB_REQ2                         (1UL<<14)
        #define MCP_NVM_SW_ARB_REQ3                         (1UL<<15)

    u32_t mcp_nvm_access_enable;
        #define MCP_NVM_ACCESS_ENABLE_EN                    (1UL<<0)
        #define MCP_NVM_ACCESS_ENABLE_WR_EN                 (1UL<<1)

    u32_t mcp_nvm_write1;
        #define MCP_NVM_WRITE1_WREN_CMD                     (0xffUL<<0)
        #define MCP_NVM_WRITE1_WRDI_CMD                     (0xffUL<<8)

    u32_t mcp_nvm_cfg4;
        #define MCP_NVM_CFG4_FLASH_SIZE                     (0x7UL<<0)
            #define MCP_NVM_CFG4_FLASH_SIZE_1MBIT           (0UL<<0)
            #define MCP_NVM_CFG4_FLASH_SIZE_2MBIT           (1UL<<0)
            #define MCP_NVM_CFG4_FLASH_SIZE_4MBIT           (2UL<<0)
            #define MCP_NVM_CFG4_FLASH_SIZE_8MBIT           (3UL<<0)
            #define MCP_NVM_CFG4_FLASH_SIZE_16MBIT          (4UL<<0)
            #define MCP_NVM_CFG4_FLASH_SIZE_32MBIT          (5UL<<0)
            #define MCP_NVM_CFG4_FLASH_SIZE_64MBIT          (6UL<<0)
            #define MCP_NVM_CFG4_FLASH_SIZE_128MBIT         (7UL<<0)
        #define MCP_NVM_CFG4_FLASH_VENDOR                   (1UL<<3)
            #define MCP_NVM_CFG4_FLASH_VENDOR_ST            (0UL<<3)
            #define MCP_NVM_CFG4_FLASH_VENDOR_ATMEL         (1UL<<3)
        #define MCP_NVM_CFG4_MODE_256_EMPTY_BIT_LOC         (0x3UL<<4)
            #define MCP_NVM_CFG4_MODE_256_EMPTY_BIT_LOC_BIT8  (0UL<<4)
            #define MCP_NVM_CFG4_MODE_256_EMPTY_BIT_LOC_BIT9  (1UL<<4)
            #define MCP_NVM_CFG4_MODE_256_EMPTY_BIT_LOC_BIT10  (2UL<<4)
            #define MCP_NVM_CFG4_MODE_256_EMPTY_BIT_LOC_BIT11  (3UL<<4)
        #define MCP_NVM_CFG4_STATUS_BIT_POLARITY            (1UL<<6)
        #define MCP_NVM_CFG4_RESERVED                       (0x1ffffffUL<<7)

    u32_t mcp_nvm_reconfig;
        #define MCP_NVM_RECONFIG_ORIG_STRAP_VALUE           (0xfUL<<0)
            #define MCP_NVM_RECONFIG_ORIG_STRAP_VALUE_ST    (0UL<<0)
            #define MCP_NVM_RECONFIG_ORIG_STRAP_VALUE_ATMEL  (1UL<<0)
        #define MCP_NVM_RECONFIG_RECONFIG_STRAP_VALUE       (0xfUL<<4)
        #define MCP_NVM_RECONFIG_RESERVED                   (0x7fffffUL<<8)
        #define MCP_NVM_RECONFIG_RECONFIG_DONE              (1UL<<31)

    u32_t unused_8[1779];
    u32_t mcp_smbus_config;
        #define MCP_SMBUS_CONFIG_HW_ARP_ASSIGN_ADDR         (1UL<<7)
        #define MCP_SMBUS_CONFIG_ARP_EN0                    (1UL<<8)
        #define MCP_SMBUS_CONFIG_ARP_EN1                    (1UL<<9)
        #define MCP_SMBUS_CONFIG_MASTER_RTRY_CNT            (0xfUL<<16)
        #define MCP_SMBUS_CONFIG_TIMESTAMP_CNT_EN           (1UL<<26)
        #define MCP_SMBUS_CONFIG_PROMISCOUS_MODE            (1UL<<27)
        #define MCP_SMBUS_CONFIG_EN_NIC_SMB_ADDR_0          (1UL<<28)
        #define MCP_SMBUS_CONFIG_BIT_BANG_EN                (1UL<<29)
        #define MCP_SMBUS_CONFIG_SMB_EN                     (1UL<<30)
        #define MCP_SMBUS_CONFIG_RESET                      (1UL<<31)

    u32_t mcp_smbus_timing_config;
        #define MCP_SMBUS_TIMING_CONFIG_SMBUS_IDLE_TIME     (0xffUL<<8)
        #define MCP_SMBUS_TIMING_CONFIG_PERIODIC_SLAVE_STRETCH  (0xffUL<<16)
        #define MCP_SMBUS_TIMING_CONFIG_RANDOM_SLAVE_STRETCH  (0x7fUL<<24)
        #define MCP_SMBUS_TIMING_CONFIG_MODE_400            (1UL<<31)

    u32_t mcp_smbus_address;
        #define MCP_SMBUS_ADDRESS_NIC_SMB_ADDR0             (0x7fUL<<0)
        #define MCP_SMBUS_ADDRESS_EN_NIC_SMB_ADDR0          (1UL<<7)
        #define MCP_SMBUS_ADDRESS_NIC_SMB_ADDR1             (0x7fUL<<8)
        #define MCP_SMBUS_ADDRESS_EN_NIC_SMB_ADDR1          (1UL<<15)
        #define MCP_SMBUS_ADDRESS_NIC_SMB_ADDR2             (0x7fUL<<16)
        #define MCP_SMBUS_ADDRESS_EN_NIC_SMB_ADDR2          (1UL<<23)
        #define MCP_SMBUS_ADDRESS_NIC_SMB_ADDR3             (0x7fUL<<24)
        #define MCP_SMBUS_ADDRESS_EN_NIC_SMB_ADDR3          (1UL<<31)

    u32_t mcp_smbus_master_fifo_control;
        #define MCP_SMBUS_MASTER_FIFO_CONTROL_MASTER_RX_FIFO_THRESHOLD  (0x7fUL<<8)
        #define MCP_SMBUS_MASTER_FIFO_CONTROL_MASTER_RX_PKT_COUNT  (0x7fUL<<16)
        #define MCP_SMBUS_MASTER_FIFO_CONTROL_MASTER_TX_FIFO_FLUSH  (1UL<<30)
        #define MCP_SMBUS_MASTER_FIFO_CONTROL_MASTER_RX_FIFO_FLUSH  (1UL<<31)

    u32_t mcp_smbus_slave_fifo_control;
        #define MCP_SMBUS_SLAVE_FIFO_CONTROL_SLAVE_RX_FIFO_THRESHOLD  (0x7fUL<<8)
        #define MCP_SMBUS_SLAVE_FIFO_CONTROL_SLAVE_RX_PKT_COUNT  (0x7fUL<<16)
        #define MCP_SMBUS_SLAVE_FIFO_CONTROL_SLAVE_TX_FIFO_FLUSH  (1UL<<30)
        #define MCP_SMBUS_SLAVE_FIFO_CONTROL_SLAVE_RX_FIFO_FLUSH  (1UL<<31)

    u32_t mcp_smbus_bit_bang_control;
        #define MCP_SMBUS_BIT_BANG_CONTROL_SMBDAT_OUT_EN    (1UL<<28)
        #define MCP_SMBUS_BIT_BANG_CONTROL_SMBDAT_IN        (1UL<<29)
        #define MCP_SMBUS_BIT_BANG_CONTROL_SMBCLK_OUT_EN    (1UL<<30)
        #define MCP_SMBUS_BIT_BANG_CONTROL_SMBCLK_IN        (1UL<<31)

    u32_t mcp_smbus_watchdog;
        #define MCP_SMBUS_WATCHDOG_WATCHDOG                 (0xffffUL<<0)

    u32_t mcp_smbus_heartbeat;
        #define MCP_SMBUS_HEARTBEAT_HEARTBEAT               (0xffffUL<<0)

    u32_t mcp_smbus_poll_asf;
        #define MCP_SMBUS_POLL_ASF_POLL_ASF                 (0xffffUL<<0)

    u32_t mcp_smbus_poll_legacy;
        #define MCP_SMBUS_POLL_LEGACY_POLL_LEGACY           (0xffffUL<<0)

    u32_t mcp_smbus_retran;
        #define MCP_SMBUS_RETRAN_RETRAN                     (0xffUL<<0)

    u32_t mcp_smbus_timestamp;
        #define MCP_SMBUS_TIMESTAMP_TIMESTAMP               (0xffffffffUL<<0)

    u32_t mcp_smbus_master_command;
        #define MCP_SMBUS_MASTER_COMMAND_RD_BYTE_COUNT      (0xffUL<<0)
        #define MCP_SMBUS_MASTER_COMMAND_PEC                (1UL<<8)
        #define MCP_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL     (0xfUL<<9)
            #define MCP_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL_0000  (0UL<<9)
            #define MCP_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL_0001  (1UL<<9)
            #define MCP_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL_0010  (2UL<<9)
            #define MCP_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL_0011  (3UL<<9)
            #define MCP_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL_0100  (4UL<<9)
            #define MCP_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL_0101  (5UL<<9)
            #define MCP_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL_0110  (6UL<<9)
            #define MCP_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL_0111  (7UL<<9)
            #define MCP_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL_1000  (8UL<<9)
            #define MCP_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL_1001  (9UL<<9)
            #define MCP_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL_1010  (10UL<<9)
            #define MCP_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL_1011  (11UL<<9)
        #define MCP_SMBUS_MASTER_COMMAND_STATUS             (0x7UL<<25)
            #define MCP_SMBUS_MASTER_COMMAND_STATUS_000     (0UL<<25)
            #define MCP_SMBUS_MASTER_COMMAND_STATUS_001     (1UL<<25)
            #define MCP_SMBUS_MASTER_COMMAND_STATUS_010     (2UL<<25)
            #define MCP_SMBUS_MASTER_COMMAND_STATUS_011     (3UL<<25)
            #define MCP_SMBUS_MASTER_COMMAND_STATUS_100     (4UL<<25)
            #define MCP_SMBUS_MASTER_COMMAND_STATUS_101     (5UL<<25)
            #define MCP_SMBUS_MASTER_COMMAND_STATUS_110     (6UL<<25)
            #define MCP_SMBUS_MASTER_COMMAND_STATUS_111     (7UL<<25)
        #define MCP_SMBUS_MASTER_COMMAND_ABORT              (1UL<<30)
        #define MCP_SMBUS_MASTER_COMMAND_START_BUSY         (1UL<<31)

    u32_t mcp_smbus_slave_command;
        #define MCP_SMBUS_SLAVE_COMMAND_PEC                 (1UL<<8)
        #define MCP_SMBUS_SLAVE_COMMAND_STATUS              (0x7UL<<23)
            #define MCP_SMBUS_SLAVE_COMMAND_STATUS_000      (0UL<<23)
            #define MCP_SMBUS_SLAVE_COMMAND_STATUS_101      (5UL<<23)
            #define MCP_SMBUS_SLAVE_COMMAND_STATUS_111      (7UL<<23)
        #define MCP_SMBUS_SLAVE_COMMAND_ABORT               (1UL<<30)
        #define MCP_SMBUS_SLAVE_COMMAND_START               (1UL<<31)

    u32_t mcp_smbus_event_enable;
        #define MCP_SMBUS_EVENT_ENABLE_WATCHDOG_TO_EN       (1UL<<0)
        #define MCP_SMBUS_EVENT_ENABLE_HEARTBEAT_TO_EN      (1UL<<1)
        #define MCP_SMBUS_EVENT_ENABLE_POLL_ASF_TO_EN       (1UL<<2)
        #define MCP_SMBUS_EVENT_ENABLE_POLL_LEGACY_TO_EN    (1UL<<3)
        #define MCP_SMBUS_EVENT_ENABLE_RETRANSMIT_TO_EN     (1UL<<4)
        #define MCP_SMBUS_EVENT_ENABLE_SLAVE_ARP_EVENT_EN   (1UL<<20)
        #define MCP_SMBUS_EVENT_ENABLE_SLAVE_RD_EVENT_EN    (1UL<<21)
        #define MCP_SMBUS_EVENT_ENABLE_SLAVE_TX_UNDERRUN_EN  (1UL<<22)
        #define MCP_SMBUS_EVENT_ENABLE_SLAVE_START_BUSY_EN  (1UL<<23)
        #define MCP_SMBUS_EVENT_ENABLE_SLAVE_RX_EVENT_EN    (1UL<<24)
        #define MCP_SMBUS_EVENT_ENABLE_SLAVE_RX_THRESHOLD_HIT_EN  (1UL<<25)
        #define MCP_SMBUS_EVENT_ENABLE_SLAVE_RX_FIFO_FULL_EN  (1UL<<26)
        #define MCP_SMBUS_EVENT_ENABLE_MASTER_TX_UNDERRUN_EN  (1UL<<27)
        #define MCP_SMBUS_EVENT_ENABLE_MASTER_START_BUSY_EN  (1UL<<28)
        #define MCP_SMBUS_EVENT_ENABLE_MASTER_RX_EVENT_EN   (1UL<<29)
        #define MCP_SMBUS_EVENT_ENABLE_MASTER_RX_THRESHOLD_HIT_EN  (1UL<<30)
        #define MCP_SMBUS_EVENT_ENABLE_MASTER_RX_FIFO_FULL_EN  (1UL<<31)

    u32_t mcp_smbus_event_status;
        #define MCP_SMBUS_EVENT_STATUS_WATCHDOG_TO          (1UL<<0)
        #define MCP_SMBUS_EVENT_STATUS_HEARTBEAT_TO         (1UL<<1)
        #define MCP_SMBUS_EVENT_STATUS_POLL_ASF_TO          (1UL<<2)
        #define MCP_SMBUS_EVENT_STATUS_POLL_LEGACY_TO       (1UL<<3)
        #define MCP_SMBUS_EVENT_STATUS_RETRANSMIT_TO        (1UL<<4)
        #define MCP_SMBUS_EVENT_STATUS_SLAVE_ARP_EVENT      (1UL<<20)
        #define MCP_SMBUS_EVENT_STATUS_SLAVE_RD_EVENT       (1UL<<21)
        #define MCP_SMBUS_EVENT_STATUS_SLAVE_TX_UNDERRUN    (1UL<<22)
        #define MCP_SMBUS_EVENT_STATUS_SLAVE_START_BUSY     (1UL<<23)
        #define MCP_SMBUS_EVENT_STATUS_SLAVE_RX_EVENT       (1UL<<24)
        #define MCP_SMBUS_EVENT_STATUS_SLAVE_RX_THRESHOLD_HIT  (1UL<<25)
        #define MCP_SMBUS_EVENT_STATUS_SLAVE_RX_FIFO_FULL   (1UL<<26)
        #define MCP_SMBUS_EVENT_STATUS_MASTER_TX_UNDERRUN   (1UL<<27)
        #define MCP_SMBUS_EVENT_STATUS_MASTER_START_BUSY    (1UL<<28)
        #define MCP_SMBUS_EVENT_STATUS_MASTER_RX_EVENT      (1UL<<29)
        #define MCP_SMBUS_EVENT_STATUS_MASTER_RX_THRESHOLD_HIT  (1UL<<30)
        #define MCP_SMBUS_EVENT_STATUS_MASTER_RX_FIFO_FULL  (1UL<<31)

    u32_t mcp_smbus_master_data_write;
        #define MCP_SMBUS_MASTER_DATA_WRITE_MASTER_SMBUS_WR_DATA  (0xffUL<<0)
        #define MCP_SMBUS_MASTER_DATA_WRITE_WR_STATUS       (1UL<<31)

    u32_t mcp_smbus_master_data_read;
        #define MCP_SMBUS_MASTER_DATA_READ_MASTER_SMBUS_RD_DATA  (0xffUL<<0)
        #define MCP_SMBUS_MASTER_DATA_READ_PEC_ERR          (1UL<<29)
        #define MCP_SMBUS_MASTER_DATA_READ_RD_STATUS        (0x3UL<<30)
            #define MCP_SMBUS_MASTER_DATA_READ_RD_STATUS_00  (0UL<<30)
            #define MCP_SMBUS_MASTER_DATA_READ_RD_STATUS_01  (1UL<<30)
            #define MCP_SMBUS_MASTER_DATA_READ_RD_STATUS_10  (2UL<<30)
            #define MCP_SMBUS_MASTER_DATA_READ_RD_STATUS_11  (3UL<<30)

    u32_t mcp_smbus_slave_data_write;
        #define MCP_SMBUS_SLAVE_DATA_WRITE_SLAVE_SMBUS_WR_DATA  (0xffUL<<0)
        #define MCP_SMBUS_SLAVE_DATA_WRITE_WR_STATUS        (1UL<<31)
            #define MCP_SMBUS_SLAVE_DATA_WRITE_WR_STATUS_0  (0UL<<31)
            #define MCP_SMBUS_SLAVE_DATA_WRITE_WR_STATUS_1  (1UL<<31)

    u32_t mcp_smbus_slave_data_read;
        #define MCP_SMBUS_SLAVE_DATA_READ_SLAVE_SMBUS_RD_DATA  (0xffUL<<0)
        #define MCP_SMBUS_SLAVE_DATA_READ_ERR_STATUS        (0x3UL<<28)
            #define MCP_SMBUS_SLAVE_DATA_READ_ERR_STATUS_00  (0UL<<28)
            #define MCP_SMBUS_SLAVE_DATA_READ_ERR_STATUS_01  (1UL<<28)
            #define MCP_SMBUS_SLAVE_DATA_READ_ERR_STATUS_10  (2UL<<28)
            #define MCP_SMBUS_SLAVE_DATA_READ_ERR_STATUS_11  (3UL<<28)
        #define MCP_SMBUS_SLAVE_DATA_READ_RD_STATUS         (0x3UL<<30)
            #define MCP_SMBUS_SLAVE_DATA_READ_RD_STATUS_00  (0UL<<30)
            #define MCP_SMBUS_SLAVE_DATA_READ_RD_STATUS_01  (1UL<<30)
            #define MCP_SMBUS_SLAVE_DATA_READ_RD_STATUS_10  (2UL<<30)
            #define MCP_SMBUS_SLAVE_DATA_READ_RD_STATUS_11  (3UL<<30)

    u32_t unused_9[12];
    u32_t mcp_smbus_arp_state;
        #define MCP_SMBUS_ARP_STATE_AV_FLAG0                (1UL<<0)
        #define MCP_SMBUS_ARP_STATE_AR_FLAG0                (1UL<<1)
        #define MCP_SMBUS_ARP_STATE_AV_FLAG1                (1UL<<4)
        #define MCP_SMBUS_ARP_STATE_AR_FLAG1                (1UL<<5)

    u32_t unused_10[3];
    u32_t mcp_smbus_udid0_3;
        #define MCP_SMBUS_UDID0_3_BYTE_12                   (0xffUL<<0)
        #define MCP_SMBUS_UDID0_3_BYTE_13                   (0xffUL<<8)
        #define MCP_SMBUS_UDID0_3_BYTE_14                   (0xffUL<<16)
        #define MCP_SMBUS_UDID0_3_BYTE_15                   (0xffUL<<24)

    u32_t mcp_smbus_udid0_2;
        #define MCP_SMBUS_UDID0_2_BYTE_8                    (0xffUL<<0)
        #define MCP_SMBUS_UDID0_2_BYTE_9                    (0xffUL<<8)
        #define MCP_SMBUS_UDID0_2_BYTE_10                   (0xffUL<<16)
        #define MCP_SMBUS_UDID0_2_BYTE_11                   (0xffUL<<24)

    u32_t mcp_smbus_udid0_1;
        #define MCP_SMBUS_UDID0_1_BYTE_4                    (0xffUL<<0)
        #define MCP_SMBUS_UDID0_1_BYTE_5                    (0xffUL<<8)
        #define MCP_SMBUS_UDID0_1_BYTE_6                    (0xffUL<<16)
        #define MCP_SMBUS_UDID0_1_BYTE_7                    (0xffUL<<24)

    u32_t mcp_smbus_udid0_0;
        #define MCP_SMBUS_UDID0_0_BYTE_0                    (0xffUL<<0)
        #define MCP_SMBUS_UDID0_0_BYTE_1                    (0xffUL<<8)
        #define MCP_SMBUS_UDID0_0_BYTE_2                    (0xffUL<<16)
        #define MCP_SMBUS_UDID0_0_BYTE_3                    (0xffUL<<24)

    u32_t mcp_smbus_udid1_3;
        #define MCP_SMBUS_UDID1_3_BYTE_12                   (0xffUL<<0)
        #define MCP_SMBUS_UDID1_3_BYTE_13                   (0xffUL<<8)
        #define MCP_SMBUS_UDID1_3_BYTE_14                   (0xffUL<<16)
        #define MCP_SMBUS_UDID1_3_BYTE_15                   (0xffUL<<24)

    u32_t mcp_smbus_udid1_2;
        #define MCP_SMBUS_UDID1_2_BYTE_8                    (0xffUL<<0)
        #define MCP_SMBUS_UDID1_2_BYTE_9                    (0xffUL<<8)
        #define MCP_SMBUS_UDID1_2_BYTE_10                   (0xffUL<<16)
        #define MCP_SMBUS_UDID1_2_BYTE_11                   (0xffUL<<24)

    u32_t mcp_smbus_udid1_1;
        #define MCP_SMBUS_UDID1_1_BYTE_4                    (0xffUL<<0)
        #define MCP_SMBUS_UDID1_1_BYTE_5                    (0xffUL<<8)
        #define MCP_SMBUS_UDID1_1_BYTE_6                    (0xffUL<<16)
        #define MCP_SMBUS_UDID1_1_BYTE_7                    (0xffUL<<24)

    u32_t mcp_smbus_udid1_0;
        #define MCP_SMBUS_UDID1_0_BYTE_0                    (0xffUL<<0)
        #define MCP_SMBUS_UDID1_0_BYTE_1                    (0xffUL<<8)
        #define MCP_SMBUS_UDID1_0_BYTE_2                    (0xffUL<<16)
        #define MCP_SMBUS_UDID1_0_BYTE_3                    (0xffUL<<24)

    u32_t unused_11[468];
    u32_t mcp_legacy_smb_asf_control;
        #define MCP_LEGACY_SMB_ASF_CONTROL_ASF_RST          (1UL<<0)
        #define MCP_LEGACY_SMB_ASF_CONTROL_TSC_EN           (1UL<<1)
        #define MCP_LEGACY_SMB_ASF_CONTROL_WG_TO            (1UL<<2)
        #define MCP_LEGACY_SMB_ASF_CONTROL_HB_TO            (1UL<<3)
        #define MCP_LEGACY_SMB_ASF_CONTROL_PA_TO            (1UL<<4)
        #define MCP_LEGACY_SMB_ASF_CONTROL_PL_TO            (1UL<<5)
        #define MCP_LEGACY_SMB_ASF_CONTROL_RT_TO            (1UL<<6)
        #define MCP_LEGACY_SMB_ASF_CONTROL_SMB_EVENT        (1UL<<7)
        #define MCP_LEGACY_SMB_ASF_CONTROL_STRETCH_EN       (1UL<<8)
        #define MCP_LEGACY_SMB_ASF_CONTROL_STRETCH_PULSE    (1UL<<9)
        #define MCP_LEGACY_SMB_ASF_CONTROL_RES              (0x3UL<<10)
        #define MCP_LEGACY_SMB_ASF_CONTROL_SMB_EN           (1UL<<12)
        #define MCP_LEGACY_SMB_ASF_CONTROL_SMB_BB_EN        (1UL<<13)
        #define MCP_LEGACY_SMB_ASF_CONTROL_SMB_NO_ADDR_FILT  (1UL<<14)
        #define MCP_LEGACY_SMB_ASF_CONTROL_SMB_AUTOREAD     (1UL<<15)
        #define MCP_LEGACY_SMB_ASF_CONTROL_NIC_SMB_ADDR1    (0x7fUL<<16)
        #define MCP_LEGACY_SMB_ASF_CONTROL_NIC_SMB_ADDR2    (0x7fUL<<23)
        #define MCP_LEGACY_SMB_ASF_CONTROL_EN_NIC_SMB_ADDR_0  (1UL<<30)
        #define MCP_LEGACY_SMB_ASF_CONTROL_SMB_EARLY_ATTN   (1UL<<31)

    u32_t mcp_legacy_smb_in;
        #define MCP_LEGACY_SMB_IN_DAT_IN                    (0xffUL<<0)
        #define MCP_LEGACY_SMB_IN_RDY                       (1UL<<8)
        #define MCP_LEGACY_SMB_IN_DONE                      (1UL<<9)
        #define MCP_LEGACY_SMB_IN_FIRSTBYTE                 (1UL<<10)
        #define MCP_LEGACY_SMB_IN_STATUS                    (0x7UL<<11)
            #define MCP_LEGACY_SMB_IN_STATUS_OK             (0UL<<11)
            #define MCP_LEGACY_SMB_IN_STATUS_PEC            (1UL<<11)
            #define MCP_LEGACY_SMB_IN_STATUS_OFLOW          (2UL<<11)
            #define MCP_LEGACY_SMB_IN_STATUS_STOP           (3UL<<11)
            #define MCP_LEGACY_SMB_IN_STATUS_TIMEOUT        (4UL<<11)

    u32_t mcp_legacy_smb_out;
        #define MCP_LEGACY_SMB_OUT_DAT_OUT                  (0xffUL<<0)
        #define MCP_LEGACY_SMB_OUT_RDY                      (1UL<<8)
        #define MCP_LEGACY_SMB_OUT_START                    (1UL<<9)
        #define MCP_LEGACY_SMB_OUT_LAST                     (1UL<<10)
        #define MCP_LEGACY_SMB_OUT_ACC_TYPE                 (1UL<<11)
        #define MCP_LEGACY_SMB_OUT_ENB_PEC                  (1UL<<12)
        #define MCP_LEGACY_SMB_OUT_GET_RX_LEN               (1UL<<13)
        #define MCP_LEGACY_SMB_OUT_SMB_READ_LEN             (0x3fUL<<14)
        #define MCP_LEGACY_SMB_OUT_SMB_OUT_STATUS           (0xfUL<<20)
            #define MCP_LEGACY_SMB_OUT_SMB_OUT_STATUS_OK    (0UL<<20)
            #define MCP_LEGACY_SMB_OUT_SMB_OUT_STATUS_FIRST_NACK  (1UL<<20)
            #define MCP_LEGACY_SMB_OUT_SMB_OUT_STATUS_UFLOW  (2UL<<20)
            #define MCP_LEGACY_SMB_OUT_SMB_OUT_STATUS_STOP  (3UL<<20)
            #define MCP_LEGACY_SMB_OUT_SMB_OUT_STATUS_TIMEOUT  (4UL<<20)
            #define MCP_LEGACY_SMB_OUT_SMB_OUT_STATUS_FIRST_LOST  (5UL<<20)
            #define MCP_LEGACY_SMB_OUT_SMB_OUT_STATUS_BADACK  (6UL<<20)
            #define MCP_LEGACY_SMB_OUT_SMB_OUT_STATUS_SUB_NACK  (9UL<<20)
            #define MCP_LEGACY_SMB_OUT_SMB_OUT_STATUS_SUB_LOST  (13UL<<20)
        #define MCP_LEGACY_SMB_OUT_SMB_OUT_SLAVEMODE        (1UL<<24)
        #define MCP_LEGACY_SMB_OUT_SMB_OUT_DAT_EN           (1UL<<25)
        #define MCP_LEGACY_SMB_OUT_SMB_OUT_DAT_IN           (1UL<<26)
        #define MCP_LEGACY_SMB_OUT_SMB_OUT_CLK_EN           (1UL<<27)
        #define MCP_LEGACY_SMB_OUT_SMB_OUT_CLK_IN           (1UL<<28)

    u32_t mcp_legacy_smb_watchdog;
        #define MCP_LEGACY_SMB_WATCHDOG_WATCHDOG            (0xffffUL<<0)

    u32_t mcp_legacy_smb_heartbeat;
        #define MCP_LEGACY_SMB_HEARTBEAT_HEARTBEAT          (0xffffUL<<0)

    u32_t mcp_legacy_smb_poll_asf;
        #define MCP_LEGACY_SMB_POLL_ASF_POLL_ASF            (0xffffUL<<0)

    u32_t mcp_legacy_smb_poll_legacy;
        #define MCP_LEGACY_SMB_POLL_LEGACY_POLL_LEGACY      (0xffffUL<<0)

    u32_t mcp_legacy_smb_retran;
        #define MCP_LEGACY_SMB_RETRAN_RETRAN                (0xffUL<<0)

    u32_t mcp_legacy_smb_timestamp;
        #define MCP_LEGACY_SMB_TIMESTAMP_TIMESTAMP          (0xffffffffUL<<0)

    u32_t unused_12[7671];
    u32_t mcp_rom[320];
    u32_t unused_13[7872];
    u32_t mcp_ump_ump_cmd;
        #define MCP_UMP_UMP_CMD_EGRESS_FIFO_ENABLED         (1UL<<0)
        #define MCP_UMP_UMP_CMD_INGRESS_FIFO_ENABLED        (1UL<<1)
        #define MCP_UMP_UMP_CMD_FC_EN                       (1UL<<2)
        #define MCP_UMP_UMP_CMD_MAC_LOOPBACK                (1UL<<3)
        #define MCP_UMP_UMP_CMD_EGRESS_MAC_DISABLE          (1UL<<5)
        #define MCP_UMP_UMP_CMD_INGRESS_MAC_DISABLE         (1UL<<6)
        #define MCP_UMP_UMP_CMD_INGRESS_DRIVE               (1UL<<8)
        #define MCP_UMP_UMP_CMD_SW_PAUSE                    (1UL<<9)
        #define MCP_UMP_UMP_CMD_AUTO_DRIVE                  (1UL<<13)
        #define MCP_UMP_UMP_CMD_INGRESS_RESET               (1UL<<14)
        #define MCP_UMP_UMP_CMD_NO_PLUS_TWO                 (1UL<<15)
        #define MCP_UMP_UMP_CMD_EGRESS_PKT_FLUSH            (1UL<<16)
        #define MCP_UMP_UMP_CMD_CMD_IPG                     (0x1fUL<<17)
        #define MCP_UMP_UMP_CMD_EGRESS_FIO_RESET            (1UL<<28)
        #define MCP_UMP_UMP_CMD_INGRESS_FIO_RESET           (1UL<<29)
        #define MCP_UMP_UMP_CMD_EGRESS_MAC_RESET            (1UL<<30)
        #define MCP_UMP_UMP_CMD_INGRESS_MAC_RESET           (1UL<<31)

    u32_t mcp_ump_ump_config;
        #define MCP_UMP_UMP_CONFIG_RMII_MODE                (1UL<<4)
        #define MCP_UMP_UMP_CONFIG_RVMII_MODE               (1UL<<6)
        #define MCP_UMP_UMP_CONFIG_INGRESS_MODE             (1UL<<7)
        #define MCP_UMP_UMP_CONFIG_INGRESS_WORD_ACCM        (0xffUL<<8)

    u32_t mcp_ump_ump_fc_trip;
        #define MCP_UMP_UMP_FC_TRIP_XON_TRIP                (0x1ffUL<<0)
        #define MCP_UMP_UMP_FC_TRIP_XOFF_TRIP               (0x1ffUL<<16)

    u32_t unused_14[33];
    u32_t mcp_ump_ump_egress_frm_rd_status;
        #define MCP_UMP_UMP_EGRESS_FRM_RD_STATUS_NEW_FRM    (1UL<<0)
        #define MCP_UMP_UMP_EGRESS_FRM_RD_STATUS_FRM_IN_PRO  (1UL<<1)
        #define MCP_UMP_UMP_EGRESS_FRM_RD_STATUS_FIFO_EMPTY  (1UL<<2)
        #define MCP_UMP_UMP_EGRESS_FRM_RD_STATUS_BCNT       (0x7ffUL<<3)
        #define MCP_UMP_UMP_EGRESS_FRM_RD_STATUS_EGRESS_FIFO_STATE  (0x1fUL<<27)
            #define MCP_UMP_UMP_EGRESS_FRM_RD_STATUS_EGRESS_FIFO_STATE_IDLE  (0UL<<27)
            #define MCP_UMP_UMP_EGRESS_FRM_RD_STATUS_EGRESS_FIFO_STATE_READY  (1UL<<27)
            #define MCP_UMP_UMP_EGRESS_FRM_RD_STATUS_EGRESS_FIFO_STATE_BUSY  (2UL<<27)
            #define MCP_UMP_UMP_EGRESS_FRM_RD_STATUS_EGRESS_FIFO_STATE_EXTRA_RD  (3UL<<27)
            #define MCP_UMP_UMP_EGRESS_FRM_RD_STATUS_EGRESS_FIFO_STATE_LATCH_IP_HDR  (4UL<<27)

    u32_t mcp_ump_ump_egress_frm_rd_data;
    u32_t mcp_ump_ump_ingress_frm_wr_ctl;
        #define MCP_UMP_UMP_INGRESS_FRM_WR_CTL_NEW_FRM      (1UL<<0)
        #define MCP_UMP_UMP_INGRESS_FRM_WR_CTL_FIFO_RDY     (1UL<<1)
        #define MCP_UMP_UMP_INGRESS_FRM_WR_CTL_BCNT_RDY     (1UL<<2)
        #define MCP_UMP_UMP_INGRESS_FRM_WR_CTL_BCNT         (0x7ffUL<<3)
        #define MCP_UMP_UMP_INGRESS_FRM_WR_CTL_INGRESS_FIFO_STATE  (0x3UL<<30)
            #define MCP_UMP_UMP_INGRESS_FRM_WR_CTL_INGRESS_FIFO_STATE_IDLE  (0UL<<30)
            #define MCP_UMP_UMP_INGRESS_FRM_WR_CTL_INGRESS_FIFO_STATE_WAIT  (1UL<<30)
            #define MCP_UMP_UMP_INGRESS_FRM_WR_CTL_INGRESS_FIFO_STATE_BUSY  (2UL<<30)
            #define MCP_UMP_UMP_INGRESS_FRM_WR_CTL_INGRESS_FIFO_STATE_EXTRA_WR  (3UL<<30)

    u32_t mcp_ump_ump_ingress_frm_wr_data;
    u32_t mcp_ump_ump_egress_frame_type;
    u32_t mcp_ump_ump_fifo_remaining_words;
        #define MCP_UMP_UMP_FIFO_REMAINING_WORDS_EGRESS_FIFO_DEPTH  (0x7ffUL<<0)
        #define MCP_UMP_UMP_FIFO_REMAINING_WORDS_INGRESS_FIFO_DEPTH  (0x3ffUL<<16)

    u32_t mcp_ump_ump_egress_fifo_ptrs;
        #define MCP_UMP_UMP_EGRESS_FIFO_PTRS_EGRESS_FIFO_RD_PTR  (0xfffUL<<0)
        #define MCP_UMP_UMP_EGRESS_FIFO_PTRS_UPDATE_RDPTR   (1UL<<15)
        #define MCP_UMP_UMP_EGRESS_FIFO_PTRS_EGRESS_FIFO_WR_PTR  (0xfffUL<<16)
        #define MCP_UMP_UMP_EGRESS_FIFO_PTRS_UPDATE_WRPTR   (1UL<<31)

    u32_t mcp_ump_ump_ingress_fifo_ptrs;
        #define MCP_UMP_UMP_INGRESS_FIFO_PTRS_INGRESS_FIFO_RD_PTR  (0x7ffUL<<0)
        #define MCP_UMP_UMP_INGRESS_FIFO_PTRS_UPDATE_RDPTR  (1UL<<15)
        #define MCP_UMP_UMP_INGRESS_FIFO_PTRS_INGRESS_FIFO_WR_PTR  (0x7ffUL<<16)
        #define MCP_UMP_UMP_INGRESS_FIFO_PTRS_UPDATE_WRPTR  (1UL<<31)

    u32_t unused_15;
    u32_t mcp_ump_ump_egress_packet_sa_0;
        #define MCP_UMP_UMP_EGRESS_PACKET_SA_0_EGRESS_SA    (0xffffUL<<0)

    u32_t mcp_ump_ump_egress_packet_sa_1;
        #define MCP_UMP_UMP_EGRESS_PACKET_SA_1_EGRESS_SA    (0xffffffffUL<<0)

    u32_t mcp_ump_ump_ingress_burst_command;
        #define MCP_UMP_UMP_INGRESS_BURST_COMMAND_INGRESS_DMA_START  (1UL<<0)
        #define MCP_UMP_UMP_INGRESS_BURST_COMMAND_INGRESS_PORT  (1UL<<1)
        #define MCP_UMP_UMP_INGRESS_BURST_COMMAND_DMA_LENGTH  (0x7ffUL<<2)
        #define MCP_UMP_UMP_INGRESS_BURST_COMMAND_RBUF_OFFSET  (0x3fffUL<<16)

    u32_t mcp_ump_ump_ingress_rbuf_cluster;
        #define MCP_UMP_UMP_INGRESS_RBUF_CLUSTER_RBUF_CLUSTER  (0x1ffffffUL<<0)

    u32_t mcp_ump_ump_ingress_vlan;
        #define MCP_UMP_UMP_INGRESS_VLAN_INGRESS_VLAN_TAG   (0xffffUL<<0)
        #define MCP_UMP_UMP_INGRESS_VLAN_VLAN_INS           (1UL<<16)
        #define MCP_UMP_UMP_INGRESS_VLAN_VLAN_DEL           (1UL<<17)

    u32_t mcp_ump_ump_ingress_burst_status;
        #define MCP_UMP_UMP_INGRESS_BURST_STATUS_RESULT     (0x3UL<<0)
            #define MCP_UMP_UMP_INGRESS_BURST_STATUS_RESULT_BUSY  (0UL<<0)
            #define MCP_UMP_UMP_INGRESS_BURST_STATUS_RESULT_DONE  (1UL<<0)
            #define MCP_UMP_UMP_INGRESS_BURST_STATUS_RESULT_ERR  (2UL<<0)
            #define MCP_UMP_UMP_INGRESS_BURST_STATUS_RESULT_ERR1  (3UL<<0)

    u32_t mcp_ump_ump_egress_burst_command;
        #define MCP_UMP_UMP_EGRESS_BURST_COMMAND_EGRESS_DMA_START  (1UL<<0)
        #define MCP_UMP_UMP_EGRESS_BURST_COMMAND_EGRESS_PORT  (1UL<<1)
        #define MCP_UMP_UMP_EGRESS_BURST_COMMAND_DMA_LENGTH  (0x7ffUL<<2)
        #define MCP_UMP_UMP_EGRESS_BURST_COMMAND_TPBUF_OFFSET  (0x1fffUL<<16)

    u32_t mcp_ump_ump_egress_vlan;
        #define MCP_UMP_UMP_EGRESS_VLAN_EGRESS_VLAN_TAG     (0xffffUL<<0)
        #define MCP_UMP_UMP_EGRESS_VLAN_VLAN_INS            (1UL<<16)
        #define MCP_UMP_UMP_EGRESS_VLAN_VLAN_DEL            (1UL<<17)

    u32_t mcp_ump_ump_egress_burst_status;
        #define MCP_UMP_UMP_EGRESS_BURST_STATUS_RESULT      (0x3UL<<0)
            #define MCP_UMP_UMP_EGRESS_BURST_STATUS_RESULT_BUSY  (0UL<<0)
            #define MCP_UMP_UMP_EGRESS_BURST_STATUS_RESULT_DONE  (1UL<<0)
            #define MCP_UMP_UMP_EGRESS_BURST_STATUS_RESULT_ERR0  (2UL<<0)
            #define MCP_UMP_UMP_EGRESS_BURST_STATUS_RESULT_RSVD  (3UL<<0)

    u32_t mcp_ump_ump_egress_statistic;
        #define MCP_UMP_UMP_EGRESS_STATISTIC_EGRESS_GOOD_CNT  (0xffffUL<<0)
        #define MCP_UMP_UMP_EGRESS_STATISTIC_EGRESS_ERROR_CNT  (0xffUL<<16)
        #define MCP_UMP_UMP_EGRESS_STATISTIC_EGRESS_DROP_CNT  (0xffUL<<24)

    u32_t mcp_ump_ump_ingress_statistic;
        #define MCP_UMP_UMP_INGRESS_STATISTIC_INGRESS_PKT_CNT  (0xffffUL<<0)

    u32_t mcp_ump_ump_arb_cmd;
        #define MCP_UMP_UMP_ARB_CMD_UMP_ID                  (0x7UL<<0)
        #define MCP_UMP_UMP_ARB_CMD_UMP_ARB_DISABLE         (1UL<<4)
        #define MCP_UMP_UMP_ARB_CMD_UMP_ARB_START           (1UL<<5)
        #define MCP_UMP_UMP_ARB_CMD_UMP_ARB_BYPASS          (1UL<<6)
        #define MCP_UMP_UMP_ARB_CMD_UMP_ARB_AUTOBYPASS      (1UL<<7)
        #define MCP_UMP_UMP_ARB_CMD_UMP_ARB_TOKEN_IPG       (0x1fUL<<8)
        #define MCP_UMP_UMP_ARB_CMD_UMP_ARB_TOKEN_VALID     (1UL<<13)
        #define MCP_UMP_UMP_ARB_CMD_UMP_ARB_FC_DISABLE      (1UL<<15)
        #define MCP_UMP_UMP_ARB_CMD_UMP_ARB_TIMEOUT         (0xffffUL<<16)

    u32_t unused_16[3];
    u32_t mcp_ump_ump_egress_statistic_ac;
        #define MCP_UMP_UMP_EGRESS_STATISTIC_AC_EGRESS_GOOD_CNT  (0xffffUL<<0)
        #define MCP_UMP_UMP_EGRESS_STATISTIC_AC_EGRESS_ERROR_CNT  (0xffUL<<16)
        #define MCP_UMP_UMP_EGRESS_STATISTIC_AC_EGRESS_DROP_CNT  (0xffUL<<24)

    u32_t mcp_ump_ump_ingress_statistic_ac;
        #define MCP_UMP_UMP_INGRESS_STATISTIC_AC_INGRESS_PKT_CNT  (0xffffUL<<0)

    u32_t mcp_ump_ump_event;
        #define MCP_UMP_UMP_EVENT_INGRESS_RDY_EVENT         (1UL<<0)
        #define MCP_UMP_UMP_EVENT_EGRESS_RDY_EVENT          (1UL<<1)
        #define MCP_UMP_UMP_EVENT_INGRESSBURST_DONE_EVENT   (1UL<<2)
        #define MCP_UMP_UMP_EVENT_EGRESSBURST_DONE_EVENT    (1UL<<3)
        #define MCP_UMP_UMP_EVENT_EGRESS_FRAME_DROP_EVENT   (1UL<<4)
        #define MCP_UMP_UMP_EVENT_INGRESS_RDY_EVENT_EN      (1UL<<16)
        #define MCP_UMP_UMP_EVENT_EGRESS_RDY_EVENT_EN       (1UL<<17)
        #define MCP_UMP_UMP_EVENT_INGRESSBURST_DONE_EVENT_EN  (1UL<<18)
        #define MCP_UMP_UMP_EVENT_EGRESSBURST_DONE_EVENT_EN  (1UL<<19)
        #define MCP_UMP_UMP_EVENT_EGRESS_FRAME_DROP_EVENT_EN  (1UL<<20)

    u32_t unused_17[4033];
    u32_t mcp_ump_ump_egress_fifo_flat_space[1920];
    u32_t unused_18[128];
    u32_t mcp_ump_ump_ingress_fifo_flat_space[768];
    u32_t unused_19[1280];
    u32_t mcp_scratch[16384];
    u32_t unused_20[16384];
} mcp_reg_t;

typedef mcp_reg_t management_reg_t;

/*
 *  hb_reg definition
 *  offset: 0x240000
 */
typedef struct hb_reg
{
    u32_t hb_command;
        #define HB_COMMAND_ARM                              (1UL<<0)
        #define HB_COMMAND_TRIG_NOW                         (1UL<<1)
        #define HB_COMMAND_TRIG_MATCH                       (1UL<<2)
        #define HB_COMMAND_TRIG_POS                         (0x7UL<<5)
            #define HB_COMMAND_TRIG_POS_START               (0UL<<5)
            #define HB_COMMAND_TRIG_POS_25P                 (1UL<<5)
            #define HB_COMMAND_TRIG_POS_50P                 (2UL<<5)
            #define HB_COMMAND_TRIG_POS_75P                 (3UL<<5)
            #define HB_COMMAND_TRIG_POS_END                 (4UL<<5)
        #define HB_COMMAND_PC_MATCH                         (0x1ffffUL<<12)

    u32_t hb_status;
        #define HB_STATUS_ARMED                             (1UL<<0)
        #define HB_STATUS_TRIGGERED                         (1UL<<1)
        #define HB_STATUS_ARM_CNT                           (0x3ffUL<<8)
        #define HB_STATUS_CAP_ADDR                          (0x1ffUL<<20)

    u32_t hb_config;
        #define HB_CONFIG_PROC_SEL                          (0xfUL<<0)
            #define HB_CONFIG_PROC_SEL_TXP0                 (0UL<<0)
            #define HB_CONFIG_PROC_SEL_TXP1                 (1UL<<0)
            #define HB_CONFIG_PROC_SEL_TPAT0                (2UL<<0)
            #define HB_CONFIG_PROC_SEL_TPAT1                (3UL<<0)
            #define HB_CONFIG_PROC_SEL_RXP0                 (4UL<<0)
            #define HB_CONFIG_PROC_SEL_RXP1                 (5UL<<0)
            #define HB_CONFIG_PROC_SEL_COM0                 (6UL<<0)
            #define HB_CONFIG_PROC_SEL_COM1                 (7UL<<0)
            #define HB_CONFIG_PROC_SEL_CP0                  (8UL<<0)
            #define HB_CONFIG_PROC_SEL_CP1                  (9UL<<0)
            #define HB_CONFIG_PROC_SEL_MCP                  (10UL<<0)

    u32_t unused_0[1021];
    u32_t hb_hb_buf_data[1024];
} hb_reg_t;


/*
 *  reg_space definition
 */
typedef struct reg_space
{
    pci_config_t pci_config;
    pci_reg_t pci;
    misc_reg_t misc;
    dma_reg_t dma;
    context_reg_t context;
    emac_reg_t emac;
    rx_parser_reg_t rpm;
    rx_cu_parser_reg_t rpc;
    rx_lookup_reg_t rlup;
    cmd_scheduler_reg_t rv2pcs;
    rx_v2p_reg_t rv2p;
    rx_dma_reg_t rdma;
    rx_bd_cache_reg_t rbdc;
    u32_t unused_0[512];
    mailbox_queue_reg_t mq;
    cmd_scheduler_reg_t csch;
    timer_reg_t timer;
    u32_t unused_1[256];
    tx_scheduler_reg_t tsch;
    tx_bd_read_reg_t tbdr;
    tx_bd_cache_reg_t tbdc;
    u32_t unused_2[256];
    tx_dma_reg_t tdma;
    dbu_reg_t dbu;
    nvm_reg_t nvm;
    host_coalesce_reg_t hc;
    u32_t unused_3[256];
    debug_reg_t debug;
    u32_t unused_4[57856];
    tx_processor_reg_t txp;
    tx_patchup_reg_t tpat;
    rx_processor_reg_t rxp;
    completion_reg_t com;
    management_reg_t mcp;
    cmd_processor_reg_t cp;
    tx_assembler_reg_t tas;
    rx_mbuf_reg_t rbuf;
    u32_t unused_5[196608];
    pcie_reg_t pci1;
    host_coalesce_full_reg_t hc1;
    hb_reg_t hb;
} reg_space_t;


/*
 *  txp_fio definition
 *  offset: 0x80000000
 */
typedef struct txp_fio
{
    u32_t txpf_events_bits;
        #define TXPF_EVENTS_BITS_GPIO0                      (1UL<<15)
        #define TXPF_EVENTS_BITS_GPIO1                      (1UL<<16)
        #define TXPF_EVENTS_BITS_GPIO2                      (1UL<<17)
        #define TXPF_EVENTS_BITS_GPIO3                      (1UL<<18)

    u32_t txpf_attentions_bits;
        #define TXPF_ATTENTIONS_BITS_EPB_ERROR              (1UL<<30)

    u32_t txpf_event_enable;
    u32_t txpf_attention_enable;
    u32_t txpf_fio_status;
    u32_t unused_0[3];

    u32_t txpf_ctx_window_cid1;

    u32_t txpf_ctx_window_cid2;

    u32_t txpf_ctx_window_cid3;
        #define TXPF_CTX_WINDOW_CID3_CTX_WINDOW_CID3_VALUE  (0x3fffUL<<7)

    u32_t txpf_ctx_window_cid4;
        #define TXPF_CTX_WINDOW_CID4_CTX_WINDOW_CID4_VALUE  (0x3fffUL<<7)
    u32_t unused_1[4];

    u32_t txpf_txp_hc_inc_stat[8];
    u32_t unused_2[4];
    u32_t txpf_free_counter_value;
    u32_t txpf_timer_retran_value;
    u16_t txpf_timer_rxpush_value;
    u16_t txpf_timer_delayack_value;
    u16_t txpf_timer_keepalive_value;
    u16_t txpf_timer_nagle_value;
    u32_t txpf_bdcache_window_cid;

    u32_t txpf_bdcache_window_idx;
    u16_t unused_3;

    u16_t txpf_tas_txp_thbuf_cons;
    u32_t unused_4[29];

    u32_t txpf_txpq_cid;
    u32_t txpf_txpq_bseq;
    u8_t txpf_txpq_flags_flags;
        #define TXPF_TXPQ_FLAGS_FLAGS_QUICK_CID             (0x3<<1)
        #define TXPF_TXPQ_FLAGS_FLAGS_QUICK_CATCHUP         (1<<3)

    u8_t txpf_txpq_cmd;
    u8_t txpf_txpq_xnum;
    u8_t txpf_txpq_protocol_flags;
    u32_t unused_5[11];
    u32_t txpf_txpq_ftq_cmd;
    u32_t unused_6;

    u32_t txpf_tdmaq_cid;
    u16_t txpf_tdmaq_bidx;
    u16_t txpf_tdmaq_boff;
    u32_t txpf_tdmaq_bseq;
    u32_t txpf_tdmaq_snd_next;
    u8_t txpf_tdmaq_cmd;
    u8_t txpf_tdmaq_xnum;
    u8_t txpf_tdmaq_knum;
    u8_t unused_7;
    u32_t txpf_tdmaq_flags_flags;
        #define TXPF_TDMAQ_FLAGS_FLAGS_QUICK_CID            (0x3UL<<10)

    u16_t txpf_tdmaq_nbytes;
    u16_t txpf_tdmaq_hole0_boff;
    u16_t txpf_tdmaq_hole1_boff;
    u16_t txpf_tdmaq_hole2_boff;
    u32_t txpf_tdmaq_hole0_fill;
    u32_t txpf_tdmaq_hole1_fill;
    u32_t txpf_tdmaq_hole2_fill;
    u32_t unused_8[3];
    u32_t txpf_tdmaq_ftq_cmd;
    u32_t unused_9[417];

    u32_t txpf_burst_base0;

    u32_t txpf_burst_base1;

    u32_t txpf_burst_base2;

    u32_t txpf_burst_base3;

    u32_t txpf_burst_cmd0;

    u32_t txpf_burst_cmd1;

    u32_t txpf_burst_cmd2;

    u32_t txpf_burst_cmd3;
    u32_t unused_10[56];

    u32_t txpf_burst_data0[16];
    u32_t txpf_burst_data1[16];
    u32_t txpf_burst_data2[16];
    u32_t txpf_burst_data3[16];
    u32_t unused_11[128];
    u32_t txpf_bd_cache_window[6];
    u32_t unused_12[122];
    u32_t txpf_bd_scan_cmd;

    u32_t txpf_bd_scan_len;

    u16_t txpf_bd_scan_flags;
    u16_t txpf_bd_scan_vlan_tag;
    u16_t txpf_bd_scan_reserved;
    u16_t unused_13;
    u16_t txpf_bd_scan_bidx_current;
    u16_t txpf_bd_scan_boff_current;
    u16_t txpf_bd_scan_bidx_prev;
    u16_t txpf_bd_scan_boff_prev;
    u32_t txpf_bd_scan_bseq_current;
    u32_t txpf_bd_scan_bseq_prev;
    u32_t unused_14[3192];
    u32_t txpf_thbuf[4096];
    u32_t unused_15[122880];
    u32_t txpf_ctx_window1[32768];
    u32_t txpf_ctx_window2[32768];
    u32_t txpf_ctx_window3[32768];
    u32_t txpf_ctx_window4[32768];
} txp_fio_t;


/*
 *  txp_fio definition
 *  offset: 0x80000000
 */
typedef struct txp_fio_xi
{
    u32_t txpf_events_bits;
        #define TXPF_EVENTS_BITS_FTQ0_VALID                 (1UL<<0)
        #define TXPF_EVENTS_BITS_FTQ1_VALID                 (1UL<<1)
        #define TXPF_EVENTS_BITS_FTQ2_VALID                 (1UL<<2)
        #define TXPF_EVENTS_BITS_SCANNER_DONE               (1UL<<3)
        #define TXPF_EVENTS_BITS_DMA_WR_DONE                (1UL<<4)
        #define TXPF_EVENTS_BITS_DMA_RD_DONE                (1UL<<5)
        #define TXPF_EVENTS_BITS_CRACKER_DONE               (1UL<<6)
        #define TXPF_EVENTS_BITS_MULTIPLY_DONE              (1UL<<7)
        #define TXPF_EVENTS_BITS_EXP_ROM                    (1UL<<8)
        #define TXPF_EVENTS_BITS_VPD                        (1UL<<9)
        #define TXPF_EVENTS_BITS_FLASH                      (1UL<<10)
        #define TXPF_EVENTS_BITS_SMB0                       (1UL<<11)
        #define TXPF_EVENTS_BITS_RESERVED0                  (1UL<<12)
        #define TXPF_EVENTS_BITS_RESERVED1                  (1UL<<13)
        #define TXPF_EVENTS_BITS_RESERVED2                  (1UL<<14)
        #define TXPF_EVENTS_BITS_GPIO                       (1UL<<15)
        #define TXPF_EVENTS_BITS_SW_TMR_1                   (1UL<<19)
        #define TXPF_EVENTS_BITS_SW_TMR_2                   (1UL<<20)
        #define TXPF_EVENTS_BITS_SW_TMR_3                   (1UL<<21)
        #define TXPF_EVENTS_BITS_SW_TMR_4                   (1UL<<22)
        #define TXPF_EVENTS_BITS_LINK_CHANGED               (1UL<<23)
        #define TXPF_EVENTS_BITS_MI_INT                     (1UL<<25)
        #define TXPF_EVENTS_BITS_MI_COMPLETE                (1UL<<26)
        #define TXPF_EVENTS_BITS_MAIN_PWR_INT               (1UL<<27)
        #define TXPF_EVENTS_BITS_NOT_ENABLED                (1UL<<30)
        #define TXPF_EVENTS_BITS_ATTENTIONS_VALID           (1UL<<31)

    u32_t txpf_attentions_bits;
        #define TXPF_ATTENTIONS_BITS_LINK_STATE             (1UL<<0)
        #define TXPF_ATTENTIONS_BITS_TX_SCHEDULER_ABORT     (1UL<<1)
        #define TXPF_ATTENTIONS_BITS_TX_BD_READ_ABORT       (1UL<<2)
        #define TXPF_ATTENTIONS_BITS_TX_BD_CACHE_ABORT      (1UL<<3)
        #define TXPF_ATTENTIONS_BITS_TX_PROCESSOR_ABORT     (1UL<<4)
        #define TXPF_ATTENTIONS_BITS_TX_DMA_ABORT           (1UL<<5)
        #define TXPF_ATTENTIONS_BITS_TX_PATCHUP_ABORT       (1UL<<6)
        #define TXPF_ATTENTIONS_BITS_TX_ASSEMBLER_ABORT     (1UL<<7)
        #define TXPF_ATTENTIONS_BITS_RX_PARSER_MAC_ABORT    (1UL<<8)
        #define TXPF_ATTENTIONS_BITS_RX_PARSER_CATCHUP_ABORT  (1UL<<9)
        #define TXPF_ATTENTIONS_BITS_RX_MBUF_ABORT          (1UL<<10)
        #define TXPF_ATTENTIONS_BITS_RX_LOOKUP_ABORT        (1UL<<11)
        #define TXPF_ATTENTIONS_BITS_RX_PROCESSOR_ABORT     (1UL<<12)
        #define TXPF_ATTENTIONS_BITS_RX_V2P_ABORT           (1UL<<13)
        #define TXPF_ATTENTIONS_BITS_RX_BD_CACHE_ABORT      (1UL<<14)
        #define TXPF_ATTENTIONS_BITS_RX_DMA_ABORT           (1UL<<15)
        #define TXPF_ATTENTIONS_BITS_COMPLETION_ABORT       (1UL<<16)
        #define TXPF_ATTENTIONS_BITS_HOST_COALESCE_ABORT    (1UL<<17)
        #define TXPF_ATTENTIONS_BITS_MAILBOX_QUEUE_ABORT    (1UL<<18)
        #define TXPF_ATTENTIONS_BITS_CONTEXT_ABORT          (1UL<<19)
        #define TXPF_ATTENTIONS_BITS_CMD_SCHEDULER_ABORT    (1UL<<20)
        #define TXPF_ATTENTIONS_BITS_CMD_PROCESSOR_ABORT    (1UL<<21)
        #define TXPF_ATTENTIONS_BITS_MGMT_PROCESSOR_ABORT   (1UL<<22)
        #define TXPF_ATTENTIONS_BITS_MAC_ABORT              (1UL<<23)
        #define TXPF_ATTENTIONS_BITS_TIMER_ABORT            (1UL<<24)
        #define TXPF_ATTENTIONS_BITS_DMAE_ABORT             (1UL<<25)
        #define TXPF_ATTENTIONS_BITS_FLSH_ABORT             (1UL<<26)
        #define TXPF_ATTENTIONS_BITS_GRC_ABORT              (1UL<<27)
        #define TXPF_ATTENTIONS_BITS_PARITY_ERROR           (1UL<<31)

    u32_t txpf_event_enable;
    u32_t txpf_attention_enable;
    u32_t txpf_fio_status;
        #define TXPF_FIO_STATUS_ENABLED                     (1UL<<0)
        #define TXPF_FIO_STATUS_FORCE_ENA                   (1UL<<1)

    u32_t txpf_l2_compatibility;
        #define TXPF_L2_COMPATIBILITY_CTX_OFFSET            (0x1ffUL<<3)
        #define TXPF_L2_COMPATIBILITY_COMP_ENABLE           (1UL<<31)
    u32_t unused_0[2];

    u32_t txpf_ctx_window_cid1;
        #define TXPF_CTX_WINDOW_CID1_LOCK_TYPE              (0x7UL<<0)
            #define TXPF_CTX_WINDOW_CID1_LOCK_TYPE_VOID     (0UL<<0)
            #define TXPF_CTX_WINDOW_CID1_LOCK_TYPE_PROTOCOL  (1UL<<0)
            #define TXPF_CTX_WINDOW_CID1_LOCK_TYPE_TX       (2UL<<0)
            #define TXPF_CTX_WINDOW_CID1_LOCK_TYPE_TIMER    (4UL<<0)
            #define TXPF_CTX_WINDOW_CID1_LOCK_TYPE_COMPLETE  (7UL<<0)
        #define TXPF_CTX_WINDOW_CID1_VALUE                  (0x3fffUL<<7)
        #define TXPF_CTX_WINDOW_CID1_MOD_USAGE_CNT          (0x3UL<<24)
            #define TXPF_CTX_WINDOW_CID1_MOD_USAGE_CNT_00   (0UL<<24)
            #define TXPF_CTX_WINDOW_CID1_MOD_USAGE_CNT_01   (1UL<<24)
            #define TXPF_CTX_WINDOW_CID1_MOD_USAGE_CNT_10   (2UL<<24)
            #define TXPF_CTX_WINDOW_CID1_MOD_USAGE_CNT_11   (3UL<<24)
        #define TXPF_CTX_WINDOW_CID1_LOCK_GRANTED           (1UL<<26)
        #define TXPF_CTX_WINDOW_CID1_LOCK_MODE              (0x3UL<<27)
            #define TXPF_CTX_WINDOW_CID1_LOCK_MODE_UNLOCK   (0UL<<27)
            #define TXPF_CTX_WINDOW_CID1_LOCK_MODE_IMMEDIATE  (1UL<<27)
            #define TXPF_CTX_WINDOW_CID1_LOCK_MODE_SURE     (2UL<<27)
        #define TXPF_CTX_WINDOW_CID1_NO_EXT_ACC             (1UL<<29)
        #define TXPF_CTX_WINDOW_CID1_LOCK_STATUS            (1UL<<30)
        #define TXPF_CTX_WINDOW_CID1_LOCK_REQ               (1UL<<31)

    u32_t txpf_ctx_window_cid2;
        #define TXPF_CTX_WINDOW_CID2_LOCK_TYPE              (0x7UL<<0)
            #define TXPF_CTX_WINDOW_CID2_LOCK_TYPE_VOID     (0UL<<0)
            #define TXPF_CTX_WINDOW_CID2_LOCK_TYPE_PROTOCOL  (1UL<<0)
            #define TXPF_CTX_WINDOW_CID2_LOCK_TYPE_TX       (2UL<<0)
            #define TXPF_CTX_WINDOW_CID2_LOCK_TYPE_TIMER    (4UL<<0)
            #define TXPF_CTX_WINDOW_CID2_LOCK_TYPE_COMPLETE  (7UL<<0)
        #define TXPF_CTX_WINDOW_CID2_VALUE                  (0x3fffUL<<7)
        #define TXPF_CTX_WINDOW_CID2_MOD_USAGE_CNT          (0x3UL<<24)
            #define TXPF_CTX_WINDOW_CID2_MOD_USAGE_CNT_00   (0UL<<24)
            #define TXPF_CTX_WINDOW_CID2_MOD_USAGE_CNT_01   (1UL<<24)
            #define TXPF_CTX_WINDOW_CID2_MOD_USAGE_CNT_10   (2UL<<24)
            #define TXPF_CTX_WINDOW_CID2_MOD_USAGE_CNT_11   (3UL<<24)
        #define TXPF_CTX_WINDOW_CID2_LOCK_GRANTED           (1UL<<26)
        #define TXPF_CTX_WINDOW_CID2_LOCK_MODE              (0x3UL<<27)
            #define TXPF_CTX_WINDOW_CID2_LOCK_MODE_UNLOCK   (0UL<<27)
            #define TXPF_CTX_WINDOW_CID2_LOCK_MODE_IMMEDIATE  (1UL<<27)
            #define TXPF_CTX_WINDOW_CID2_LOCK_MODE_SURE     (2UL<<27)
        #define TXPF_CTX_WINDOW_CID2_NO_EXT_ACC             (1UL<<29)
        #define TXPF_CTX_WINDOW_CID2_LOCK_STATUS            (1UL<<30)
        #define TXPF_CTX_WINDOW_CID2_LOCK_REQ               (1UL<<31)

    u32_t txpf_ctx_window_cid3;
        #define TXPF_CTX_WINDOW_CID3_LOCK_TYPE              (0x7UL<<0)
            #define TXPF_CTX_WINDOW_CID3_LOCK_TYPE_VOID     (0UL<<0)
            #define TXPF_CTX_WINDOW_CID3_LOCK_TYPE_PROTOCOL  (1UL<<0)
            #define TXPF_CTX_WINDOW_CID3_LOCK_TYPE_TX       (2UL<<0)
            #define TXPF_CTX_WINDOW_CID3_LOCK_TYPE_TIMER    (4UL<<0)
            #define TXPF_CTX_WINDOW_CID3_LOCK_TYPE_COMPLETE  (7UL<<0)
        #define TXPF_CTX_WINDOW_CID3_VALUE                  (0x3fffUL<<7)
        #define TXPF_CTX_WINDOW_CID3_MOD_USAGE_CNT          (0x3UL<<24)
            #define TXPF_CTX_WINDOW_CID3_MOD_USAGE_CNT_00   (0UL<<24)
            #define TXPF_CTX_WINDOW_CID3_MOD_USAGE_CNT_01   (1UL<<24)
            #define TXPF_CTX_WINDOW_CID3_MOD_USAGE_CNT_10   (2UL<<24)
            #define TXPF_CTX_WINDOW_CID3_MOD_USAGE_CNT_11   (3UL<<24)
        #define TXPF_CTX_WINDOW_CID3_LOCK_GRANTED           (1UL<<26)
        #define TXPF_CTX_WINDOW_CID3_LOCK_MODE              (0x3UL<<27)
            #define TXPF_CTX_WINDOW_CID3_LOCK_MODE_UNLOCK   (0UL<<27)
            #define TXPF_CTX_WINDOW_CID3_LOCK_MODE_IMMEDIATE  (1UL<<27)
            #define TXPF_CTX_WINDOW_CID3_LOCK_MODE_SURE     (2UL<<27)
        #define TXPF_CTX_WINDOW_CID3_NO_EXT_ACC             (1UL<<29)
        #define TXPF_CTX_WINDOW_CID3_LOCK_STATUS            (1UL<<30)
        #define TXPF_CTX_WINDOW_CID3_LOCK_REQ               (1UL<<31)

    u32_t txpf_ctx_window_cid4;
        #define TXPF_CTX_WINDOW_CID4_LOCK_TYPE              (0x7UL<<0)
            #define TXPF_CTX_WINDOW_CID4_LOCK_TYPE_VOID     (0UL<<0)
            #define TXPF_CTX_WINDOW_CID4_LOCK_TYPE_PROTOCOL  (1UL<<0)
            #define TXPF_CTX_WINDOW_CID4_LOCK_TYPE_TX       (2UL<<0)
            #define TXPF_CTX_WINDOW_CID4_LOCK_TYPE_TIMER    (4UL<<0)
            #define TXPF_CTX_WINDOW_CID4_LOCK_TYPE_COMPLETE  (7UL<<0)
        #define TXPF_CTX_WINDOW_CID4_VALUE                  (0x3fffUL<<7)
        #define TXPF_CTX_WINDOW_CID4_MOD_USAGE_CNT          (0x3UL<<24)
            #define TXPF_CTX_WINDOW_CID4_MOD_USAGE_CNT_00   (0UL<<24)
            #define TXPF_CTX_WINDOW_CID4_MOD_USAGE_CNT_01   (1UL<<24)
            #define TXPF_CTX_WINDOW_CID4_MOD_USAGE_CNT_10   (2UL<<24)
            #define TXPF_CTX_WINDOW_CID4_MOD_USAGE_CNT_11   (3UL<<24)
        #define TXPF_CTX_WINDOW_CID4_LOCK_GRANTED           (1UL<<26)
        #define TXPF_CTX_WINDOW_CID4_LOCK_MODE              (0x3UL<<27)
            #define TXPF_CTX_WINDOW_CID4_LOCK_MODE_UNLOCK   (0UL<<27)
            #define TXPF_CTX_WINDOW_CID4_LOCK_MODE_IMMEDIATE  (1UL<<27)
            #define TXPF_CTX_WINDOW_CID4_LOCK_MODE_SURE     (2UL<<27)
        #define TXPF_CTX_WINDOW_CID4_NO_EXT_ACC             (1UL<<29)
        #define TXPF_CTX_WINDOW_CID4_LOCK_STATUS            (1UL<<30)
        #define TXPF_CTX_WINDOW_CID4_LOCK_REQ               (1UL<<31)
    u32_t unused_1[4];

    u32_t txpf_txp_hc_inc_stat[8];
    u32_t unused_2[4];
    u32_t txpf_free_counter_value;
    u32_t txpf_timer_retran_value;
    u16_t txpf_timer_rxpush_value;
    u16_t txpf_timer_delayack_value;
    u16_t txpf_timer_keepalive_value;
    u16_t txpf_timer_nagle_value;
    u32_t txpf_bdcache_window_cid;
        #define TXPF_BDCACHE_WINDOW_CID_HIT                 (1UL<<0)
        #define TXPF_BDCACHE_WINDOW_CID_RDY                 (1UL<<1)
        #define TXPF_BDCACHE_WINDOW_CID_CID_VALUE           (0x3fffUL<<7)
        #define TXPF_BDCACHE_WINDOW_CID_CMD_VALUE           (0xffUL<<24)

    u32_t txpf_bdcache_window_idx;
        #define TXPF_BDCACHE_WINDOW_IDX_BDCACHE_WINDOW_IDX_VALUE  (0xffffUL<<0)
    u16_t unused_3;

    u16_t txpf_tas_txp_thbuf_cons;
        #define TXPF_TAS_TXP_THBUF_CONS_VALUE               (0xfff<<3)
    u32_t unused_4;

    u32_t txpf_ctx_window_cid5;
        #define TXPF_CTX_WINDOW_CID5_LOCK_TYPE              (0x7UL<<0)
            #define TXPF_CTX_WINDOW_CID5_LOCK_TYPE_VOID     (0UL<<0)
            #define TXPF_CTX_WINDOW_CID5_LOCK_TYPE_PROTOCOL  (1UL<<0)
            #define TXPF_CTX_WINDOW_CID5_LOCK_TYPE_TX       (2UL<<0)
            #define TXPF_CTX_WINDOW_CID5_LOCK_TYPE_TIMER    (4UL<<0)
            #define TXPF_CTX_WINDOW_CID5_LOCK_TYPE_COMPLETE  (7UL<<0)
        #define TXPF_CTX_WINDOW_CID5_VALUE                  (0x3fffUL<<7)
        #define TXPF_CTX_WINDOW_CID5_MOD_USAGE_CNT          (0x3UL<<24)
            #define TXPF_CTX_WINDOW_CID5_MOD_USAGE_CNT_00   (0UL<<24)
            #define TXPF_CTX_WINDOW_CID5_MOD_USAGE_CNT_01   (1UL<<24)
            #define TXPF_CTX_WINDOW_CID5_MOD_USAGE_CNT_10   (2UL<<24)
            #define TXPF_CTX_WINDOW_CID5_MOD_USAGE_CNT_11   (3UL<<24)
        #define TXPF_CTX_WINDOW_CID5_LOCK_GRANTED           (1UL<<26)
        #define TXPF_CTX_WINDOW_CID5_LOCK_MODE              (0x3UL<<27)
            #define TXPF_CTX_WINDOW_CID5_LOCK_MODE_UNLOCK   (0UL<<27)
            #define TXPF_CTX_WINDOW_CID5_LOCK_MODE_IMMEDIATE  (1UL<<27)
            #define TXPF_CTX_WINDOW_CID5_LOCK_MODE_SURE     (2UL<<27)
        #define TXPF_CTX_WINDOW_CID5_NO_EXT_ACC             (1UL<<29)
        #define TXPF_CTX_WINDOW_CID5_LOCK_STATUS            (1UL<<30)
        #define TXPF_CTX_WINDOW_CID5_LOCK_REQ               (1UL<<31)

    u32_t txpf_ctx_window_cid6;
        #define TXPF_CTX_WINDOW_CID6_LOCK_TYPE              (0x7UL<<0)
            #define TXPF_CTX_WINDOW_CID6_LOCK_TYPE_VOID     (0UL<<0)
            #define TXPF_CTX_WINDOW_CID6_LOCK_TYPE_PROTOCOL  (1UL<<0)
            #define TXPF_CTX_WINDOW_CID6_LOCK_TYPE_TX       (2UL<<0)
            #define TXPF_CTX_WINDOW_CID6_LOCK_TYPE_TIMER    (4UL<<0)
            #define TXPF_CTX_WINDOW_CID6_LOCK_TYPE_COMPLETE  (7UL<<0)
        #define TXPF_CTX_WINDOW_CID6_VALUE                  (0x3fffUL<<7)
        #define TXPF_CTX_WINDOW_CID6_MOD_USAGE_CNT          (0x3UL<<24)
            #define TXPF_CTX_WINDOW_CID6_MOD_USAGE_CNT_00   (0UL<<24)
            #define TXPF_CTX_WINDOW_CID6_MOD_USAGE_CNT_01   (1UL<<24)
            #define TXPF_CTX_WINDOW_CID6_MOD_USAGE_CNT_10   (2UL<<24)
            #define TXPF_CTX_WINDOW_CID6_MOD_USAGE_CNT_11   (3UL<<24)
        #define TXPF_CTX_WINDOW_CID6_LOCK_GRANTED           (1UL<<26)
        #define TXPF_CTX_WINDOW_CID6_LOCK_MODE              (0x3UL<<27)
            #define TXPF_CTX_WINDOW_CID6_LOCK_MODE_UNLOCK   (0UL<<27)
            #define TXPF_CTX_WINDOW_CID6_LOCK_MODE_IMMEDIATE  (1UL<<27)
            #define TXPF_CTX_WINDOW_CID6_LOCK_MODE_SURE     (2UL<<27)
        #define TXPF_CTX_WINDOW_CID6_NO_EXT_ACC             (1UL<<29)
        #define TXPF_CTX_WINDOW_CID6_LOCK_STATUS            (1UL<<30)
        #define TXPF_CTX_WINDOW_CID6_LOCK_REQ               (1UL<<31)
    u32_t unused_5[26];

    u32_t txpf_txpq_cid;
    u32_t txpf_txpq_bseq;
    u8_t txpf_txpq_flags_flags;
        #define TXPF_TXPQ_FLAGS_FLAGS_QUICK_CID_ENA         (1<<0)
        #define TXPF_TXPQ_FLAGS_FLAGS_RSVD                  (1<<1)
        #define TXPF_TXPQ_FLAGS_FLAGS_BORROWED              (1<<2)
        #define TXPF_TXPQ_FLAGS_FLAGS_BSEQ_INVLD            (1<<3)
        #define TXPF_TXPQ_FLAGS_FLAGS_S_RETRAN              (1<<4)
        #define TXPF_TXPQ_FLAGS_FLAGS_WORKAROUND            (0x3<<5)

    u8_t txpf_txpq_cmd;
    u8_t txpf_txpq_xnum;
    u8_t txpf_txpq_protocol_flags;
    u32_t txpf_txpq_tcp_rcv_nxt;
        #define TXPF_TXPQ_TCP_RCV_NXT_VALUE                 (0xffffffffUL<<0)

    u8_t txpf_tcmd_fnum;
        #define TXPF_TCMD_FNUM_VALUE                        (0x3f<<0)
    u8_t unused_6;
    u16_t unused_7;
    u32_t unused_8[9];

    u32_t txpf_txpq_ftq_cmd;
        #define TXPF_TXPQ_FTQ_CMD_TXPQ_FTQ_CMD_POP          (1UL<<30)
    u32_t unused_9;

    u32_t txpf_tdmaq_cid;
    u16_t txpf_tdmaq_bidx;
    u16_t txpf_tdmaq_boff;
    u32_t txpf_tdmaq_bseq;
    u32_t txpf_tdmaq_snd_next;
    u8_t txpf_tdmaq_cmd;
    u8_t txpf_tdmaq_xnum;
    u8_t txpf_tdmaq_knum;
    u8_t unused_10;
    u32_t txpf_tdmaq_flags_flags;
        #define TXPF_TDMAQ_FLAGS_FLAGS_PLUS_TWO             (1UL<<0)
        #define TXPF_TDMAQ_FLAGS_FLAGS_TCP_UDP_CKSUM        (1UL<<1)
        #define TXPF_TDMAQ_FLAGS_FLAGS_IP_CKSUM             (1UL<<2)
        #define TXPF_TDMAQ_FLAGS_FLAGS_INCR_CMD             (1UL<<3)
        #define TXPF_TDMAQ_FLAGS_FLAGS_COAL_NOW             (1UL<<4)
        #define TXPF_TDMAQ_FLAGS_FLAGS_DONT_GEN_CRC         (1UL<<5)
        #define TXPF_TDMAQ_FLAGS_FLAGS_LAST_PKT             (1UL<<6)
        #define TXPF_TDMAQ_FLAGS_FLAGS_PKT_FRAG             (1UL<<7)
        #define TXPF_TDMAQ_FLAGS_FLAGS_QUICK_CID_ENA        (1UL<<9)
        #define TXPF_TDMAQ_FLAGS_FLAGS_RSVD_FUTURE          (0x3UL<<10)
        #define TXPF_TDMAQ_FLAGS_FLAGS_L5_PAGE_MODE         (1UL<<12)
        #define TXPF_TDMAQ_FLAGS_FLAGS_COMPLETE             (1UL<<13)
        #define TXPF_TDMAQ_FLAGS_FLAGS_RETRAN               (1UL<<14)
        #define TXPF_TDMAQ_FLAGS_FLAGS_END_PADDING          (0xfUL<<16)
        #define TXPF_TDMAQ_FLAGS_FLAGS_USAGE_CNT            (1UL<<20)
            #define TXPF_TDMAQ_FLAGS_FLAGS_USAGE_CNT_AUTODECREMENT  (0UL<<20)
            #define TXPF_TDMAQ_FLAGS_FLAGS_USAGE_CNT_DONOTDECREMENT  (1UL<<20)
        #define TXPF_TDMAQ_FLAGS_FLAGS_BSEQ_INVLD           (1UL<<21)
        #define TXPF_TDMAQ_FLAGS_FLAGS_WORK_AROUND          (0x3UL<<22)
        #define TXPF_TDMAQ_FLAGS_FLAGS_HOLE_SZ              (0x3UL<<25)
            #define TXPF_TDMAQ_FLAGS_FLAGS_HOLE_SZ_4        (0UL<<25)
            #define TXPF_TDMAQ_FLAGS_FLAGS_HOLE_SZ_8        (1UL<<25)
            #define TXPF_TDMAQ_FLAGS_FLAGS_HOLE_SZ_12       (2UL<<25)
            #define TXPF_TDMAQ_FLAGS_FLAGS_HOLE_SZ_16       (3UL<<25)
        #define TXPF_TDMAQ_FLAGS_FLAGS_HOLE0                (1UL<<28)
        #define TXPF_TDMAQ_FLAGS_FLAGS_HOLE1                (1UL<<29)
        #define TXPF_TDMAQ_FLAGS_FLAGS_HOLE2                (1UL<<30)

    u16_t txpf_tdmaq_nbytes;
    u16_t txpf_tdmaq_hole0_boff;
    u16_t txpf_tdmaq_hole1_boff;
    u16_t txpf_tdmaq_hole2_boff;
    u32_t txpf_tdmaq_hole0_fill;
    u32_t txpf_tdmaq_hole1_fill;
    u32_t txpf_tdmaq_hole2_fill;
    u8_t txpf_tdmaq_tcmd_fnum;
        #define TXPF_TDMAQ_TCMD_FNUM_VALUE                  (0x3f<<0)

    u8_t txpf_tdmaq_txp_act_cmd;
    u16_t unused_11;
    u32_t unused_12[2];
    u32_t txpf_tdmaq_ftq_cmd;
        #define TXPF_TDMAQ_FTQ_CMD_CPY_DATA                 (1UL<<11)
        #define TXPF_TDMAQ_FTQ_CMD_ADD_INTERVEN             (1UL<<27)
        #define TXPF_TDMAQ_FTQ_CMD_ADD_DATA                 (1UL<<28)
        #define TXPF_TDMAQ_FTQ_CMD_BUSY                     (1UL<<31)
    u32_t unused_13[417];

    u32_t txpf_burst_base0;
        #define TXPF_BURST_BASE0_BASE_VAL0                  (0x3fffUL<<7)

    u32_t txpf_burst_base1;
        #define TXPF_BURST_BASE1_BASE_VAL1                  (0x3fffUL<<7)

    u32_t txpf_burst_base2;
        #define TXPF_BURST_BASE2_BASE_VAL2                  (0x3fffUL<<7)

    u32_t txpf_burst_base3;
        #define TXPF_BURST_BASE3_BASE_VAL3                  (0x3fffUL<<7)

    u32_t txpf_burst_cmd0;
        #define TXPF_BURST_CMD0_FTQ_SEL                     (0x3UL<<0)
            #define TXPF_BURST_CMD0_FTQ_SEL_0               (0UL<<0)
            #define TXPF_BURST_CMD0_FTQ_SEL_1               (1UL<<0)
            #define TXPF_BURST_CMD0_FTQ_SEL_2               (2UL<<0)
            #define TXPF_BURST_CMD0_FTQ_SEL_3               (3UL<<0)
        #define TXPF_BURST_CMD0_BUSY                        (1UL<<2)
        #define TXPF_BURST_CMD0_OFFSET                      (0x1ffUL<<3)
        #define TXPF_BURST_CMD0_BASE_REG_SEL                (1UL<<23)
        #define TXPF_BURST_CMD0_MOD_USAGE_CNT               (0x3UL<<24)
            #define TXPF_BURST_CMD0_MOD_USAGE_CNT_00        (0UL<<24)
            #define TXPF_BURST_CMD0_MOD_USAGE_CNT_01        (1UL<<24)
            #define TXPF_BURST_CMD0_MOD_USAGE_CNT_10        (2UL<<24)
            #define TXPF_BURST_CMD0_MOD_USAGE_CNT_11        (3UL<<24)
        #define TXPF_BURST_CMD0_PREFETCH_SIZE               (0x3UL<<26)
        #define TXPF_BURST_CMD0_NO_RAM_ACCESS               (1UL<<28)
        #define TXPF_BURST_CMD0_NO_CACHE                    (1UL<<29)
        #define TXPF_BURST_CMD0_CROSS_BOUNDARY              (1UL<<30)

    u32_t txpf_burst_cmd1;
        #define TXPF_BURST_CMD1_FTQ_SEL                     (0x3UL<<0)
            #define TXPF_BURST_CMD1_FTQ_SEL_0               (0UL<<0)
            #define TXPF_BURST_CMD1_FTQ_SEL_1               (1UL<<0)
            #define TXPF_BURST_CMD1_FTQ_SEL_2               (2UL<<0)
            #define TXPF_BURST_CMD1_FTQ_SEL_3               (3UL<<0)
        #define TXPF_BURST_CMD1_BUSY                        (1UL<<2)
        #define TXPF_BURST_CMD1_OFFSET                      (0x1ffUL<<3)
        #define TXPF_BURST_CMD1_BASE_REG_SEL                (1UL<<23)
        #define TXPF_BURST_CMD1_MOD_USAGE_CNT               (0x3UL<<24)
            #define TXPF_BURST_CMD1_MOD_USAGE_CNT_00        (0UL<<24)
            #define TXPF_BURST_CMD1_MOD_USAGE_CNT_01        (1UL<<24)
            #define TXPF_BURST_CMD1_MOD_USAGE_CNT_10        (2UL<<24)
            #define TXPF_BURST_CMD1_MOD_USAGE_CNT_11        (3UL<<24)
        #define TXPF_BURST_CMD1_PREFETCH_SIZE               (0x3UL<<26)
        #define TXPF_BURST_CMD1_NO_RAM_ACCESS               (1UL<<28)
        #define TXPF_BURST_CMD1_NO_CACHE                    (1UL<<29)
        #define TXPF_BURST_CMD1_CROSS_BOUNDARY              (1UL<<30)

    u32_t txpf_burst_cmd2;
        #define TXPF_BURST_CMD2_FTQ_SEL                     (0x3UL<<0)
            #define TXPF_BURST_CMD2_FTQ_SEL_0               (0UL<<0)
            #define TXPF_BURST_CMD2_FTQ_SEL_1               (1UL<<0)
            #define TXPF_BURST_CMD2_FTQ_SEL_2               (2UL<<0)
            #define TXPF_BURST_CMD2_FTQ_SEL_3               (3UL<<0)
        #define TXPF_BURST_CMD2_BUSY                        (1UL<<2)
        #define TXPF_BURST_CMD2_OFFSET                      (0x1ffUL<<3)
        #define TXPF_BURST_CMD2_BASE_REG_SEL                (1UL<<23)
        #define TXPF_BURST_CMD2_MOD_USAGE_CNT               (0x3UL<<24)
            #define TXPF_BURST_CMD2_MOD_USAGE_CNT_00        (0UL<<24)
            #define TXPF_BURST_CMD2_MOD_USAGE_CNT_01        (1UL<<24)
            #define TXPF_BURST_CMD2_MOD_USAGE_CNT_10        (2UL<<24)
            #define TXPF_BURST_CMD2_MOD_USAGE_CNT_11        (3UL<<24)
        #define TXPF_BURST_CMD2_PREFETCH_SIZE               (0x3UL<<26)
        #define TXPF_BURST_CMD2_NO_RAM_ACCESS               (1UL<<28)
        #define TXPF_BURST_CMD2_NO_CACHE                    (1UL<<29)
        #define TXPF_BURST_CMD2_CROSS_BOUNDARY              (1UL<<30)

    u32_t txpf_burst_cmd3;
        #define TXPF_BURST_CMD3_FTQ_SEL                     (0x3UL<<0)
            #define TXPF_BURST_CMD3_FTQ_SEL_0               (0UL<<0)
            #define TXPF_BURST_CMD3_FTQ_SEL_1               (1UL<<0)
            #define TXPF_BURST_CMD3_FTQ_SEL_2               (2UL<<0)
            #define TXPF_BURST_CMD3_FTQ_SEL_3               (3UL<<0)
        #define TXPF_BURST_CMD3_BUSY                        (1UL<<2)
        #define TXPF_BURST_CMD3_OFFSET                      (0x1ffUL<<3)
        #define TXPF_BURST_CMD3_BASE_REG_SEL                (1UL<<23)
        #define TXPF_BURST_CMD3_MOD_USAGE_CNT               (0x3UL<<24)
            #define TXPF_BURST_CMD3_MOD_USAGE_CNT_00        (0UL<<24)
            #define TXPF_BURST_CMD3_MOD_USAGE_CNT_01        (1UL<<24)
            #define TXPF_BURST_CMD3_MOD_USAGE_CNT_10        (2UL<<24)
            #define TXPF_BURST_CMD3_MOD_USAGE_CNT_11        (3UL<<24)
        #define TXPF_BURST_CMD3_PREFETCH_SIZE               (0x3UL<<26)
        #define TXPF_BURST_CMD3_NO_RAM_ACCESS               (1UL<<28)
        #define TXPF_BURST_CMD3_NO_CACHE                    (1UL<<29)
        #define TXPF_BURST_CMD3_CROSS_BOUNDARY              (1UL<<30)

    u32_t txpf_burst_cmd4;
        #define TXPF_BURST_CMD4_FTQ_SEL                     (0x3UL<<0)
            #define TXPF_BURST_CMD4_FTQ_SEL_0               (0UL<<0)
            #define TXPF_BURST_CMD4_FTQ_SEL_1               (1UL<<0)
            #define TXPF_BURST_CMD4_FTQ_SEL_2               (2UL<<0)
            #define TXPF_BURST_CMD4_FTQ_SEL_3               (3UL<<0)
        #define TXPF_BURST_CMD4_BUSY                        (1UL<<2)
        #define TXPF_BURST_CMD4_OFFSET                      (0x1ffUL<<3)
        #define TXPF_BURST_CMD4_BASE_REG_SEL                (1UL<<23)
        #define TXPF_BURST_CMD4_MOD_USAGE_CNT               (0x3UL<<24)
            #define TXPF_BURST_CMD4_MOD_USAGE_CNT_00        (0UL<<24)
            #define TXPF_BURST_CMD4_MOD_USAGE_CNT_01        (1UL<<24)
            #define TXPF_BURST_CMD4_MOD_USAGE_CNT_10        (2UL<<24)
            #define TXPF_BURST_CMD4_MOD_USAGE_CNT_11        (3UL<<24)
        #define TXPF_BURST_CMD4_PREFETCH_SIZE               (0x3UL<<26)
        #define TXPF_BURST_CMD4_NO_RAM_ACCESS               (1UL<<28)
        #define TXPF_BURST_CMD4_NO_CACHE                    (1UL<<29)
        #define TXPF_BURST_CMD4_CROSS_BOUNDARY              (1UL<<30)

    u32_t txpf_burst_cmd5;
        #define TXPF_BURST_CMD5_FTQ_SEL                     (0x3UL<<0)
            #define TXPF_BURST_CMD5_FTQ_SEL_0               (0UL<<0)
            #define TXPF_BURST_CMD5_FTQ_SEL_1               (1UL<<0)
            #define TXPF_BURST_CMD5_FTQ_SEL_2               (2UL<<0)
            #define TXPF_BURST_CMD5_FTQ_SEL_3               (3UL<<0)
        #define TXPF_BURST_CMD5_BUSY                        (1UL<<2)
        #define TXPF_BURST_CMD5_OFFSET                      (0x1ffUL<<3)
        #define TXPF_BURST_CMD5_BASE_REG_SEL                (1UL<<23)
        #define TXPF_BURST_CMD5_MOD_USAGE_CNT               (0x3UL<<24)
            #define TXPF_BURST_CMD5_MOD_USAGE_CNT_00        (0UL<<24)
            #define TXPF_BURST_CMD5_MOD_USAGE_CNT_01        (1UL<<24)
            #define TXPF_BURST_CMD5_MOD_USAGE_CNT_10        (2UL<<24)
            #define TXPF_BURST_CMD5_MOD_USAGE_CNT_11        (3UL<<24)
        #define TXPF_BURST_CMD5_PREFETCH_SIZE               (0x3UL<<26)
        #define TXPF_BURST_CMD5_NO_RAM_ACCESS               (1UL<<28)
        #define TXPF_BURST_CMD5_NO_CACHE                    (1UL<<29)
        #define TXPF_BURST_CMD5_CROSS_BOUNDARY              (1UL<<30)

    u32_t txpf_burst_cmd6;
        #define TXPF_BURST_CMD6_FTQ_SEL                     (0x3UL<<0)
            #define TXPF_BURST_CMD6_FTQ_SEL_0               (0UL<<0)
            #define TXPF_BURST_CMD6_FTQ_SEL_1               (1UL<<0)
            #define TXPF_BURST_CMD6_FTQ_SEL_2               (2UL<<0)
            #define TXPF_BURST_CMD6_FTQ_SEL_3               (3UL<<0)
        #define TXPF_BURST_CMD6_BUSY                        (1UL<<2)
        #define TXPF_BURST_CMD6_OFFSET                      (0x1ffUL<<3)
        #define TXPF_BURST_CMD6_BASE_REG_SEL                (1UL<<23)
        #define TXPF_BURST_CMD6_MOD_USAGE_CNT               (0x3UL<<24)
            #define TXPF_BURST_CMD6_MOD_USAGE_CNT_00        (0UL<<24)
            #define TXPF_BURST_CMD6_MOD_USAGE_CNT_01        (1UL<<24)
            #define TXPF_BURST_CMD6_MOD_USAGE_CNT_10        (2UL<<24)
            #define TXPF_BURST_CMD6_MOD_USAGE_CNT_11        (3UL<<24)
        #define TXPF_BURST_CMD6_PREFETCH_SIZE               (0x3UL<<26)
        #define TXPF_BURST_CMD6_NO_RAM_ACCESS               (1UL<<28)
        #define TXPF_BURST_CMD6_NO_CACHE                    (1UL<<29)
        #define TXPF_BURST_CMD6_CROSS_BOUNDARY              (1UL<<30)

    u32_t txpf_burst_cmd7;
        #define TXPF_BURST_CMD7_FTQ_SEL                     (0x3UL<<0)
            #define TXPF_BURST_CMD7_FTQ_SEL_0               (0UL<<0)
            #define TXPF_BURST_CMD7_FTQ_SEL_1               (1UL<<0)
            #define TXPF_BURST_CMD7_FTQ_SEL_2               (2UL<<0)
            #define TXPF_BURST_CMD7_FTQ_SEL_3               (3UL<<0)
        #define TXPF_BURST_CMD7_BUSY                        (1UL<<2)
        #define TXPF_BURST_CMD7_OFFSET                      (0x1ffUL<<3)
        #define TXPF_BURST_CMD7_BASE_REG_SEL                (1UL<<23)
        #define TXPF_BURST_CMD7_MOD_USAGE_CNT               (0x3UL<<24)
            #define TXPF_BURST_CMD7_MOD_USAGE_CNT_00        (0UL<<24)
            #define TXPF_BURST_CMD7_MOD_USAGE_CNT_01        (1UL<<24)
            #define TXPF_BURST_CMD7_MOD_USAGE_CNT_10        (2UL<<24)
            #define TXPF_BURST_CMD7_MOD_USAGE_CNT_11        (3UL<<24)
        #define TXPF_BURST_CMD7_PREFETCH_SIZE               (0x3UL<<26)
        #define TXPF_BURST_CMD7_NO_RAM_ACCESS               (1UL<<28)
        #define TXPF_BURST_CMD7_NO_CACHE                    (1UL<<29)
        #define TXPF_BURST_CMD7_CROSS_BOUNDARY              (1UL<<30)

    u32_t txpf_ctx_cmd;
        #define TXPF_CTX_CMD_NUM_BLOCKS                     (0x3UL<<0)
        #define TXPF_CTX_CMD_OFFSET                         (0x1ffUL<<3)
        #define TXPF_CTX_CMD_CID_VALUE                      (0x3fffUL<<12)
        #define TXPF_CTX_CMD_PREFETCH_SIZE                  (0x3UL<<26)
        #define TXPF_CTX_CMD_MOD_USAGE_CNT                  (0x3UL<<28)
            #define TXPF_CTX_CMD_MOD_USAGE_CNT_00           (0UL<<28)
            #define TXPF_CTX_CMD_MOD_USAGE_CNT_01           (1UL<<28)
            #define TXPF_CTX_CMD_MOD_USAGE_CNT_10           (2UL<<28)
            #define TXPF_CTX_CMD_MOD_USAGE_CNT_11           (3UL<<28)
    u32_t unused_14[51];

    u32_t txpf_burst_data0[16];
    u32_t txpf_burst_data1[16];
    u32_t txpf_burst_data2[16];
    u32_t txpf_burst_data3[16];
    u32_t txpf_burst_data4[16];
    u32_t txpf_burst_data5[16];
    u32_t txpf_burst_data6[16];
    u32_t txpf_burst_data7[16];
    u32_t unused_15[64];
    u32_t txpf_bd_cache_window[6];
    u32_t unused_16[122];
    u32_t txpf_bd_scan_cmd;
        #define TXPF_BD_SCAN_CMD_CMD                        (0xffffffUL<<0)
            #define TXPF_BD_SCAN_CMD_CMD_SCAN               (0UL<<0)
            #define TXPF_BD_SCAN_CMD_CMD_RELOAD             (16777213UL<<0)
        #define TXPF_BD_SCAN_CMD_PAGE_SIZE                  (0xfUL<<24)
        #define TXPF_BD_SCAN_CMD_CLR_OVERRUN                (1UL<<29)
        #define TXPF_BD_SCAN_CMD_ACCUM                      (1UL<<30)
        #define TXPF_BD_SCAN_CMD_NO_STOP                    (1UL<<31)

    u32_t txpf_bd_scan_len;
        #define TXPF_BD_SCAN_LEN_BD_SCAN_LEN_OVERRUN        (1UL<<31)

    u16_t txpf_bd_scan_flags;
    u16_t txpf_bd_scan_vlan_tag;
    u16_t txpf_bd_scan_reserved;
    u16_t unused_17;
    u16_t txpf_bd_scan_bidx_current;
    u16_t txpf_bd_scan_boff_current;
    u16_t txpf_bd_scan_bidx_prev;
    u16_t txpf_bd_scan_boff_prev;
    u32_t txpf_bd_scan_bseq_current;
    u32_t txpf_bd_scan_bseq_prev;
    u32_t unused_18[3192];
    u32_t txpf_thbuf[4096];
    u32_t unused_19[57344];
    u32_t txpf_ctx_window5[32768];
    u32_t txpf_ctx_window6[32768];
    u32_t txpf_ctx_window1[32768];
    u32_t txpf_ctx_window2[32768];
    u32_t txpf_ctx_window3[32768];
    u32_t txpf_ctx_window4[32768];
} txp_fio_xi_t;


/*
 *  tpat_fio definition
 *  offset: 0x80000000
 */
typedef struct tpat_fio
{
    u32_t tpatf_events_bits;
        #define TPATF_EVENTS_BITS_GPIO0                     (1UL<<15)
        #define TPATF_EVENTS_BITS_GPIO1                     (1UL<<16)
        #define TPATF_EVENTS_BITS_GPIO2                     (1UL<<17)
        #define TPATF_EVENTS_BITS_GPIO3                     (1UL<<18)

    u32_t tpatf_attentions_bits;
        #define TPATF_ATTENTIONS_BITS_EPB_ERROR             (1UL<<30)

    u32_t tpatf_event_enable;
    u32_t tpatf_attention_enable;
    u32_t tpatf_fio_status;
    u32_t unused_0[3];

    u32_t tpatf_ctx_window_cid1;
        #define TPATF_CTX_WINDOW_CID1_1_LOCK_TYPE           (0x7UL<<0)
            #define TPATF_CTX_WINDOW_CID1_1_LOCK_TYPE_VOID  (0UL<<0)
            #define TPATF_CTX_WINDOW_CID1_1_LOCK_TYPE_PROTOCOL  (1UL<<0)
            #define TPATF_CTX_WINDOW_CID1_1_LOCK_TYPE_TX    (2UL<<0)
            #define TPATF_CTX_WINDOW_CID1_1_LOCK_TYPE_TIMER  (4UL<<0)
            #define TPATF_CTX_WINDOW_CID1_1_LOCK_TYPE_COMPLETE  (7UL<<0)
        #define TPATF_CTX_WINDOW_CID1_1_VALUE               (0x3fffUL<<7)
        #define TPATF_CTX_WINDOW_CID1_1_LOCK_GRANTED        (1UL<<26)
        #define TPATF_CTX_WINDOW_CID1_1_LOCK_MODE           (0x3UL<<27)
            #define TPATF_CTX_WINDOW_CID1_1_LOCK_MODE_UNLOCK  (0UL<<27)
            #define TPATF_CTX_WINDOW_CID1_1_LOCK_MODE_IMMEDIATE  (1UL<<27)
            #define TPATF_CTX_WINDOW_CID1_1_LOCK_MODE_SURE  (2UL<<27)
        #define TPATF_CTX_WINDOW_CID1_1_LOCK_STATUS         (1UL<<30)
        #define TPATF_CTX_WINDOW_CID1_0_LOCK_REQ            (1UL<<31)

    u32_t tpatf_ctx_window_cid2;
        #define TPATF_CTX_WINDOW_CID2_CTX_WINDOW_CID2_VALUE  (0x3fffUL<<7)

    u32_t tpatf_ctx_window_cid3;
        #define TPATF_CTX_WINDOW_CID3_CTX_WINDOW_CID3_VALUE  (0x3fffUL<<7)

    u32_t tpatf_ctx_window_cid4;
        #define TPATF_CTX_WINDOW_CID4_CTX_WINDOW_CID4_VALUE  (0x3fffUL<<7)
    u32_t unused_1[4];

    u32_t tpatf_tpat_hc_inc_stat[4];
    u32_t unused_2[8];
    u32_t tpatf_free_counter_value;
    u32_t unused_3[3];
    u32_t tpatf_tpat_pq_cons;

    u32_t tpatf_tpat_hq_cons;
    u32_t unused_4[30];

    u32_t tpatf_tpatq_cid;
    u16_t tpatf_tpatq_nbytes;
    u8_t tpatf_tpatq_xnum;
    u8_t tpatf_tpatq_knum;
    u32_t tpatf_tpatq_flags_flags;
        #define TPATF_TPATQ_FLAGS_FLAGS_QUICK_CID           (0x3UL<<10)

    u16_t tpatf_tpatq_raw_chksum;
    u16_t unused_5;
    u32_t unused_6[10];
    u32_t tpatf_tpatq_ftq_cmd;
    u32_t unused_7;

    u16_t tpatf_tasq_hdr_skip;
    u16_t tpatf_tasq_hdr_post_skip;
    u16_t tpatf_tasq_hdr_size;
    u16_t tpatf_tasq_payload_skip;
    u16_t tpatf_tasq_payload_size;
    u16_t tpatf_tasq_flags;
        #define TPATF_TASQ_FLAGS_PKT_END                    (1<<0)
        #define TPATF_TASQ_FLAGS_SA_REPLACE                 (1<<4)
        #define TPATF_TASQ_FLAGS_SA_SELECT                  (0x3<<5)
        #define TPATF_TASQ_FLAGS_MGMT_PKT_TAG_TE               (0xf<<8)
    u32_t unused_8[11];

    u32_t tpatf_tasq_ftq_cmd;
    u32_t unused_9[929];

    u32_t tpatf_tpat_crack_cmd;

    u16_t tpatf_tpat_crack_ip_offset;
    u16_t tpatf_tpat_crack_ip_len;
    u16_t tpatf_tpat_crack_tcp_offset;
    u16_t tpatf_tpat_crack_tcp_len;
    u16_t tpatf_tpat_crack_l5_offset;
    u16_t tpatf_tpat_crack_l5_len;
    u16_t tpatf_tpat_crack_ip_chksum;
    u16_t tpatf_tpat_crack_ip_pseudo_chksum;
    u16_t tpatf_tpat_crack_tcp_chksum;
    u16_t tpatf_tpat_crack_crc32_1_start;
    u32_t tpatf_tpat_crack_crc32_1_seed;
    u32_t tpatf_tpat_crack_crc32_1_result;
    u32_t tpatf_tpat_crack_crc32_2_result;
    u32_t unused_10[3063];
    u32_t tpatf_tx_header_queue[4096];
    u32_t tpatf_tx_payload_queue[16384];
    u32_t unused_11[106496];
    u32_t tpatf_ctx_window1[32768];
    u32_t tpatf_ctx_window2[32768];
    u32_t tpatf_ctx_window3[32768];
    u32_t tpatf_ctx_window4[32768];
} tpat_fio_t;


/*
 *  tpat_fio definition
 *  offset: 0x80000000
 */
typedef struct tpat_fio_xi
{
    u32_t tpatf_events_bits;
        #define TPATF_EVENTS_BITS_FTQ0_VALID                (1UL<<0)
        #define TPATF_EVENTS_BITS_FTQ1_VALID                (1UL<<1)
        #define TPATF_EVENTS_BITS_FTQ2_VALID                (1UL<<2)
        #define TPATF_EVENTS_BITS_SCANNER_DONE              (1UL<<3)
        #define TPATF_EVENTS_BITS_DMA_WR_DONE               (1UL<<4)
        #define TPATF_EVENTS_BITS_DMA_RD_DONE               (1UL<<5)
        #define TPATF_EVENTS_BITS_CRACKER_DONE              (1UL<<6)
        #define TPATF_EVENTS_BITS_MULTIPLY_DONE             (1UL<<7)
        #define TPATF_EVENTS_BITS_EXP_ROM                   (1UL<<8)
        #define TPATF_EVENTS_BITS_VPD                       (1UL<<9)
        #define TPATF_EVENTS_BITS_FLASH                     (1UL<<10)
        #define TPATF_EVENTS_BITS_SMB0                      (1UL<<11)
        #define TPATF_EVENTS_BITS_RESERVED0                 (1UL<<12)
        #define TPATF_EVENTS_BITS_RESERVED1                 (1UL<<13)
        #define TPATF_EVENTS_BITS_RESERVED2                 (1UL<<14)
        #define TPATF_EVENTS_BITS_GPIO                      (1UL<<15)
        #define TPATF_EVENTS_BITS_SW_TMR_1                  (1UL<<19)
        #define TPATF_EVENTS_BITS_SW_TMR_2                  (1UL<<20)
        #define TPATF_EVENTS_BITS_SW_TMR_3                  (1UL<<21)
        #define TPATF_EVENTS_BITS_SW_TMR_4                  (1UL<<22)
        #define TPATF_EVENTS_BITS_LINK_CHANGED              (1UL<<23)
        #define TPATF_EVENTS_BITS_MI_INT                    (1UL<<25)
        #define TPATF_EVENTS_BITS_MI_COMPLETE               (1UL<<26)
        #define TPATF_EVENTS_BITS_MAIN_PWR_INT              (1UL<<27)
        #define TPATF_EVENTS_BITS_NOT_ENABLED               (1UL<<30)
        #define TPATF_EVENTS_BITS_ATTENTIONS_VALID          (1UL<<31)

    u32_t tpatf_attentions_bits;
        #define TPATF_ATTENTIONS_BITS_LINK_STATE            (1UL<<0)
        #define TPATF_ATTENTIONS_BITS_TX_SCHEDULER_ABORT    (1UL<<1)
        #define TPATF_ATTENTIONS_BITS_TX_BD_READ_ABORT      (1UL<<2)
        #define TPATF_ATTENTIONS_BITS_TX_BD_CACHE_ABORT     (1UL<<3)
        #define TPATF_ATTENTIONS_BITS_TX_PROCESSOR_ABORT    (1UL<<4)
        #define TPATF_ATTENTIONS_BITS_TX_DMA_ABORT          (1UL<<5)
        #define TPATF_ATTENTIONS_BITS_TX_PATCHUP_ABORT      (1UL<<6)
        #define TPATF_ATTENTIONS_BITS_TX_ASSEMBLER_ABORT    (1UL<<7)
        #define TPATF_ATTENTIONS_BITS_RX_PARSER_MAC_ABORT   (1UL<<8)
        #define TPATF_ATTENTIONS_BITS_RX_PARSER_CATCHUP_ABORT  (1UL<<9)
        #define TPATF_ATTENTIONS_BITS_RX_MBUF_ABORT         (1UL<<10)
        #define TPATF_ATTENTIONS_BITS_RX_LOOKUP_ABORT       (1UL<<11)
        #define TPATF_ATTENTIONS_BITS_RX_PROCESSOR_ABORT    (1UL<<12)
        #define TPATF_ATTENTIONS_BITS_RX_V2P_ABORT          (1UL<<13)
        #define TPATF_ATTENTIONS_BITS_RX_BD_CACHE_ABORT     (1UL<<14)
        #define TPATF_ATTENTIONS_BITS_RX_DMA_ABORT          (1UL<<15)
        #define TPATF_ATTENTIONS_BITS_COMPLETION_ABORT      (1UL<<16)
        #define TPATF_ATTENTIONS_BITS_HOST_COALESCE_ABORT   (1UL<<17)
        #define TPATF_ATTENTIONS_BITS_MAILBOX_QUEUE_ABORT   (1UL<<18)
        #define TPATF_ATTENTIONS_BITS_CONTEXT_ABORT         (1UL<<19)
        #define TPATF_ATTENTIONS_BITS_CMD_SCHEDULER_ABORT   (1UL<<20)
        #define TPATF_ATTENTIONS_BITS_CMD_PROCESSOR_ABORT   (1UL<<21)
        #define TPATF_ATTENTIONS_BITS_MGMT_PROCESSOR_ABORT  (1UL<<22)
        #define TPATF_ATTENTIONS_BITS_MAC_ABORT             (1UL<<23)
        #define TPATF_ATTENTIONS_BITS_TIMER_ABORT           (1UL<<24)
        #define TPATF_ATTENTIONS_BITS_DMAE_ABORT            (1UL<<25)
        #define TPATF_ATTENTIONS_BITS_FLSH_ABORT            (1UL<<26)
        #define TPATF_ATTENTIONS_BITS_GRC_ABORT             (1UL<<27)
        #define TPATF_ATTENTIONS_BITS_PARITY_ERROR          (1UL<<31)

    u32_t tpatf_event_enable;
    u32_t tpatf_attention_enable;
    u32_t tpatf_fio_status;
        #define TPATF_FIO_STATUS_ENABLED                    (1UL<<0)
        #define TPATF_FIO_STATUS_FORCE_ENA                  (1UL<<1)
    u32_t unused_0[3];

    u32_t tpatf_ctx_window_cid1;
        #define TPATF_CTX_WINDOW_CID1_LOCK_TYPE             (0x7UL<<0)
            #define TPATF_CTX_WINDOW_CID1_LOCK_TYPE_VOID    (0UL<<0)
            #define TPATF_CTX_WINDOW_CID1_LOCK_TYPE_PROTOCOL  (1UL<<0)
            #define TPATF_CTX_WINDOW_CID1_LOCK_TYPE_TX      (2UL<<0)
            #define TPATF_CTX_WINDOW_CID1_LOCK_TYPE_TIMER   (4UL<<0)
            #define TPATF_CTX_WINDOW_CID1_LOCK_TYPE_COMPLETE  (7UL<<0)
        #define TPATF_CTX_WINDOW_CID1_VALUE                 (0x3fffUL<<7)
        #define TPATF_CTX_WINDOW_CID1_MOD_USAGE_CNT         (0x3UL<<24)
            #define TPATF_CTX_WINDOW_CID1_MOD_USAGE_CNT_00  (0UL<<24)
            #define TPATF_CTX_WINDOW_CID1_MOD_USAGE_CNT_01  (1UL<<24)
            #define TPATF_CTX_WINDOW_CID1_MOD_USAGE_CNT_10  (2UL<<24)
            #define TPATF_CTX_WINDOW_CID1_MOD_USAGE_CNT_11  (3UL<<24)
        #define TPATF_CTX_WINDOW_CID1_LOCK_GRANTED          (1UL<<26)
        #define TPATF_CTX_WINDOW_CID1_LOCK_MODE             (0x3UL<<27)
            #define TPATF_CTX_WINDOW_CID1_LOCK_MODE_UNLOCK  (0UL<<27)
            #define TPATF_CTX_WINDOW_CID1_LOCK_MODE_IMMEDIATE  (1UL<<27)
            #define TPATF_CTX_WINDOW_CID1_LOCK_MODE_SURE    (2UL<<27)
        #define TPATF_CTX_WINDOW_CID1_NO_EXT_ACC            (1UL<<29)
        #define TPATF_CTX_WINDOW_CID1_LOCK_STATUS           (1UL<<30)
        #define TPATF_CTX_WINDOW_CID1_LOCK_REQ              (1UL<<31)

    u32_t tpatf_ctx_window_cid2;
        #define TPATF_CTX_WINDOW_CID2_LOCK_TYPE             (0x7UL<<0)
            #define TPATF_CTX_WINDOW_CID2_LOCK_TYPE_VOID    (0UL<<0)
            #define TPATF_CTX_WINDOW_CID2_LOCK_TYPE_PROTOCOL  (1UL<<0)
            #define TPATF_CTX_WINDOW_CID2_LOCK_TYPE_TX      (2UL<<0)
            #define TPATF_CTX_WINDOW_CID2_LOCK_TYPE_TIMER   (4UL<<0)
            #define TPATF_CTX_WINDOW_CID2_LOCK_TYPE_COMPLETE  (7UL<<0)
        #define TPATF_CTX_WINDOW_CID2_VALUE                 (0x3fffUL<<7)
        #define TPATF_CTX_WINDOW_CID2_MOD_USAGE_CNT         (0x3UL<<24)
            #define TPATF_CTX_WINDOW_CID2_MOD_USAGE_CNT_00  (0UL<<24)
            #define TPATF_CTX_WINDOW_CID2_MOD_USAGE_CNT_01  (1UL<<24)
            #define TPATF_CTX_WINDOW_CID2_MOD_USAGE_CNT_10  (2UL<<24)
            #define TPATF_CTX_WINDOW_CID2_MOD_USAGE_CNT_11  (3UL<<24)
        #define TPATF_CTX_WINDOW_CID2_LOCK_GRANTED          (1UL<<26)
        #define TPATF_CTX_WINDOW_CID2_LOCK_MODE             (0x3UL<<27)
            #define TPATF_CTX_WINDOW_CID2_LOCK_MODE_UNLOCK  (0UL<<27)
            #define TPATF_CTX_WINDOW_CID2_LOCK_MODE_IMMEDIATE  (1UL<<27)
            #define TPATF_CTX_WINDOW_CID2_LOCK_MODE_SURE    (2UL<<27)
        #define TPATF_CTX_WINDOW_CID2_NO_EXT_ACC            (1UL<<29)
        #define TPATF_CTX_WINDOW_CID2_LOCK_STATUS           (1UL<<30)
        #define TPATF_CTX_WINDOW_CID2_LOCK_REQ              (1UL<<31)

    u32_t tpatf_ctx_window_cid3;
        #define TPATF_CTX_WINDOW_CID3_LOCK_TYPE             (0x7UL<<0)
            #define TPATF_CTX_WINDOW_CID3_LOCK_TYPE_VOID    (0UL<<0)
            #define TPATF_CTX_WINDOW_CID3_LOCK_TYPE_PROTOCOL  (1UL<<0)
            #define TPATF_CTX_WINDOW_CID3_LOCK_TYPE_TX      (2UL<<0)
            #define TPATF_CTX_WINDOW_CID3_LOCK_TYPE_TIMER   (4UL<<0)
            #define TPATF_CTX_WINDOW_CID3_LOCK_TYPE_COMPLETE  (7UL<<0)
        #define TPATF_CTX_WINDOW_CID3_VALUE                 (0x3fffUL<<7)
        #define TPATF_CTX_WINDOW_CID3_MOD_USAGE_CNT         (0x3UL<<24)
            #define TPATF_CTX_WINDOW_CID3_MOD_USAGE_CNT_00  (0UL<<24)
            #define TPATF_CTX_WINDOW_CID3_MOD_USAGE_CNT_01  (1UL<<24)
            #define TPATF_CTX_WINDOW_CID3_MOD_USAGE_CNT_10  (2UL<<24)
            #define TPATF_CTX_WINDOW_CID3_MOD_USAGE_CNT_11  (3UL<<24)
        #define TPATF_CTX_WINDOW_CID3_LOCK_GRANTED          (1UL<<26)
        #define TPATF_CTX_WINDOW_CID3_LOCK_MODE             (0x3UL<<27)
            #define TPATF_CTX_WINDOW_CID3_LOCK_MODE_UNLOCK  (0UL<<27)
            #define TPATF_CTX_WINDOW_CID3_LOCK_MODE_IMMEDIATE  (1UL<<27)
            #define TPATF_CTX_WINDOW_CID3_LOCK_MODE_SURE    (2UL<<27)
        #define TPATF_CTX_WINDOW_CID3_NO_EXT_ACC            (1UL<<29)
        #define TPATF_CTX_WINDOW_CID3_LOCK_STATUS           (1UL<<30)
        #define TPATF_CTX_WINDOW_CID3_LOCK_REQ              (1UL<<31)

    u32_t tpatf_ctx_window_cid4;
        #define TPATF_CTX_WINDOW_CID4_LOCK_TYPE             (0x7UL<<0)
            #define TPATF_CTX_WINDOW_CID4_LOCK_TYPE_VOID    (0UL<<0)
            #define TPATF_CTX_WINDOW_CID4_LOCK_TYPE_PROTOCOL  (1UL<<0)
            #define TPATF_CTX_WINDOW_CID4_LOCK_TYPE_TX      (2UL<<0)
            #define TPATF_CTX_WINDOW_CID4_LOCK_TYPE_TIMER   (4UL<<0)
            #define TPATF_CTX_WINDOW_CID4_LOCK_TYPE_COMPLETE  (7UL<<0)
        #define TPATF_CTX_WINDOW_CID4_VALUE                 (0x3fffUL<<7)
        #define TPATF_CTX_WINDOW_CID4_MOD_USAGE_CNT         (0x3UL<<24)
            #define TPATF_CTX_WINDOW_CID4_MOD_USAGE_CNT_00  (0UL<<24)
            #define TPATF_CTX_WINDOW_CID4_MOD_USAGE_CNT_01  (1UL<<24)
            #define TPATF_CTX_WINDOW_CID4_MOD_USAGE_CNT_10  (2UL<<24)
            #define TPATF_CTX_WINDOW_CID4_MOD_USAGE_CNT_11  (3UL<<24)
        #define TPATF_CTX_WINDOW_CID4_LOCK_GRANTED          (1UL<<26)
        #define TPATF_CTX_WINDOW_CID4_LOCK_MODE             (0x3UL<<27)
            #define TPATF_CTX_WINDOW_CID4_LOCK_MODE_UNLOCK  (0UL<<27)
            #define TPATF_CTX_WINDOW_CID4_LOCK_MODE_IMMEDIATE  (1UL<<27)
            #define TPATF_CTX_WINDOW_CID4_LOCK_MODE_SURE    (2UL<<27)
        #define TPATF_CTX_WINDOW_CID4_NO_EXT_ACC            (1UL<<29)
        #define TPATF_CTX_WINDOW_CID4_LOCK_STATUS           (1UL<<30)
        #define TPATF_CTX_WINDOW_CID4_LOCK_REQ              (1UL<<31)
    u32_t unused_1[4];

    u32_t tpatf_tpat_hc_inc_stat[4];
    u32_t unused_2[8];
    u32_t tpatf_free_counter_value;
    u32_t tpatf_tpat_tx_quick_cons_idx;
        #define TPATF_TPAT_TX_QUICK_CONS_IDX_INDEX_VAL      (0xffffUL<<0)
        #define TPATF_TPAT_TX_QUICK_CONS_IDX_INDEX_NUM      (0xfUL<<20)
        #define TPATF_TPAT_TX_QUICK_CONS_IDX_COALESCE_NOW   (1UL<<30)
        #define TPATF_TPAT_TX_QUICK_CONS_IDX_REQ_N          (1UL<<31)
    u32_t unused_3[2];

    u32_t tpatf_tpat_pq_cons;
        #define TPATF_TPAT_PQ_CONS_PQ_CONS_VAL              (0x1fffUL<<3)

    u32_t tpatf_tpat_hq_cons;
        #define TPATF_TPAT_HQ_CONS_HQ_CONS_VAL              (0x7ffUL<<3)
    u32_t unused_4[2];

    u32_t tpatf_ctx_window_cid5;
        #define TPATF_CTX_WINDOW_CID5_LOCK_TYPE             (0x7UL<<0)
            #define TPATF_CTX_WINDOW_CID5_LOCK_TYPE_VOID    (0UL<<0)
            #define TPATF_CTX_WINDOW_CID5_LOCK_TYPE_PROTOCOL  (1UL<<0)
            #define TPATF_CTX_WINDOW_CID5_LOCK_TYPE_TX      (2UL<<0)
            #define TPATF_CTX_WINDOW_CID5_LOCK_TYPE_TIMER   (4UL<<0)
            #define TPATF_CTX_WINDOW_CID5_LOCK_TYPE_COMPLETE  (7UL<<0)
        #define TPATF_CTX_WINDOW_CID5_VALUE                 (0x3fffUL<<7)
        #define TPATF_CTX_WINDOW_CID5_MOD_USAGE_CNT         (0x3UL<<24)
            #define TPATF_CTX_WINDOW_CID5_MOD_USAGE_CNT_00  (0UL<<24)
            #define TPATF_CTX_WINDOW_CID5_MOD_USAGE_CNT_01  (1UL<<24)
            #define TPATF_CTX_WINDOW_CID5_MOD_USAGE_CNT_10  (2UL<<24)
            #define TPATF_CTX_WINDOW_CID5_MOD_USAGE_CNT_11  (3UL<<24)
        #define TPATF_CTX_WINDOW_CID5_LOCK_GRANTED          (1UL<<26)
        #define TPATF_CTX_WINDOW_CID5_LOCK_MODE             (0x3UL<<27)
            #define TPATF_CTX_WINDOW_CID5_LOCK_MODE_UNLOCK  (0UL<<27)
            #define TPATF_CTX_WINDOW_CID5_LOCK_MODE_IMMEDIATE  (1UL<<27)
            #define TPATF_CTX_WINDOW_CID5_LOCK_MODE_SURE    (2UL<<27)
        #define TPATF_CTX_WINDOW_CID5_NO_EXT_ACC            (1UL<<29)
        #define TPATF_CTX_WINDOW_CID5_LOCK_STATUS           (1UL<<30)
        #define TPATF_CTX_WINDOW_CID5_LOCK_REQ              (1UL<<31)

    u32_t tpatf_ctx_window_cid6;
        #define TPATF_CTX_WINDOW_CID6_LOCK_TYPE             (0x7UL<<0)
            #define TPATF_CTX_WINDOW_CID6_LOCK_TYPE_VOID    (0UL<<0)
            #define TPATF_CTX_WINDOW_CID6_LOCK_TYPE_PROTOCOL  (1UL<<0)
            #define TPATF_CTX_WINDOW_CID6_LOCK_TYPE_TX      (2UL<<0)
            #define TPATF_CTX_WINDOW_CID6_LOCK_TYPE_TIMER   (4UL<<0)
            #define TPATF_CTX_WINDOW_CID6_LOCK_TYPE_COMPLETE  (7UL<<0)
        #define TPATF_CTX_WINDOW_CID6_VALUE                 (0x3fffUL<<7)
        #define TPATF_CTX_WINDOW_CID6_MOD_USAGE_CNT         (0x3UL<<24)
            #define TPATF_CTX_WINDOW_CID6_MOD_USAGE_CNT_00  (0UL<<24)
            #define TPATF_CTX_WINDOW_CID6_MOD_USAGE_CNT_01  (1UL<<24)
            #define TPATF_CTX_WINDOW_CID6_MOD_USAGE_CNT_10  (2UL<<24)
            #define TPATF_CTX_WINDOW_CID6_MOD_USAGE_CNT_11  (3UL<<24)
        #define TPATF_CTX_WINDOW_CID6_LOCK_GRANTED          (1UL<<26)
        #define TPATF_CTX_WINDOW_CID6_LOCK_MODE             (0x3UL<<27)
            #define TPATF_CTX_WINDOW_CID6_LOCK_MODE_UNLOCK  (0UL<<27)
            #define TPATF_CTX_WINDOW_CID6_LOCK_MODE_IMMEDIATE  (1UL<<27)
            #define TPATF_CTX_WINDOW_CID6_LOCK_MODE_SURE    (2UL<<27)
        #define TPATF_CTX_WINDOW_CID6_NO_EXT_ACC            (1UL<<29)
        #define TPATF_CTX_WINDOW_CID6_LOCK_STATUS           (1UL<<30)
        #define TPATF_CTX_WINDOW_CID6_LOCK_REQ              (1UL<<31)
    u32_t unused_5[26];

    u32_t tpatf_tpatq_cid;
        #define TPATF_TPATQ_CID_VALUE                       (0x3fffUL<<7)

    u16_t tpatf_tpatq_nbytes;
        #define TPATF_TPATQ_NBYTES_VALUE                    (0x3fff<<0)

    u8_t tpatf_tpatq_xnum;
    u8_t tpatf_tpatq_knum;
    u32_t tpatf_tpatq_flags_flags;
        #define TPATF_TPATQ_FLAGS_FLAGS_PLUS_TWO            (1UL<<0)
        #define TPATF_TPATQ_FLAGS_FLAGS_TCP_UDP_CKSUM       (1UL<<1)
        #define TPATF_TPATQ_FLAGS_FLAGS_IP_CKSUM            (1UL<<2)
        #define TPATF_TPATQ_FLAGS_FLAGS_INCR_CMD            (1UL<<3)
        #define TPATF_TPATQ_FLAGS_FLAGS_COAL_NOW            (1UL<<4)
        #define TPATF_TPATQ_FLAGS_FLAGS_DONT_GEN_CRC        (1UL<<5)
        #define TPATF_TPATQ_FLAGS_FLAGS_LAST_PKT            (1UL<<6)
        #define TPATF_TPATQ_FLAGS_FLAGS_PKT_FRAG            (1UL<<7)
        #define TPATF_TPATQ_FLAGS_FLAGS_QUICK_CID_ENA       (1UL<<9)
        #define TPATF_TPATQ_FLAGS_FLAGS_RSVD_FUTURE         (0x3UL<<10)
        #define TPATF_TPATQ_FLAGS_FLAGS_L5_PAGE_MODE        (1UL<<12)
        #define TPATF_TPATQ_FLAGS_FLAGS_COMPLETE            (1UL<<13)
        #define TPATF_TPATQ_FLAGS_FLAGS_RETRAN              (1UL<<14)
        #define TPATF_TPATQ_FLAGS_FLAGS_END_PADDING         (0xfUL<<16)
        #define TPATF_TPATQ_FLAGS_FLAGS_USAGE_CNT           (1UL<<20)
            #define TPATF_TPATQ_FLAGS_FLAGS_USAGE_CNT_AUTODECREMENT  (0UL<<20)
            #define TPATF_TPATQ_FLAGS_FLAGS_USAGE_CNT_DONOTDECREMENT  (1UL<<20)
        #define TPATF_TPATQ_FLAGS_FLAGS_BSEQ_INVLD          (1UL<<21)
        #define TPATF_TPATQ_FLAGS_FLAGS_WORK_AROUND         (0x3UL<<22)
        #define TPATF_TPATQ_FLAGS_FLAGS_HOLE_SZ             (0x3UL<<25)
            #define TPATF_TPATQ_FLAGS_FLAGS_HOLE_SZ_4       (0UL<<25)
            #define TPATF_TPATQ_FLAGS_FLAGS_HOLE_SZ_8       (1UL<<25)
            #define TPATF_TPATQ_FLAGS_FLAGS_HOLE_SZ_12      (2UL<<25)
            #define TPATF_TPATQ_FLAGS_FLAGS_HOLE_SZ_16      (3UL<<25)
        #define TPATF_TPATQ_FLAGS_FLAGS_HOLE0               (1UL<<28)
        #define TPATF_TPATQ_FLAGS_FLAGS_HOLE1               (1UL<<29)
        #define TPATF_TPATQ_FLAGS_FLAGS_HOLE2               (1UL<<30)

    u16_t tpatf_tpatq_raw_chksum;
    u16_t tpatf_tpatq_tpat_bidx;
    u8_t tpatf_tpatq_status;
        #define TPATF_TPATQ_STATUS_CS16_ERR                 (1<<0)
    u8_t unused_6;
    u16_t unused_7;
    u32_t unused_8[9];

    u32_t tpatf_tpatq_ftq_cmd;
        #define TPATF_TPATQ_FTQ_CMD_TPATQ_CMD_POP           (1UL<<30)
    u32_t unused_9;

    u16_t tpatf_tasq_hdr_skip;
    u16_t tpatf_tasq_hdr_post_skip;
    u16_t tpatf_tasq_hdr_size;
    u16_t tpatf_tasq_payload_skip;
    u16_t tpatf_tasq_payload_size;
    u16_t tpatf_tasq_flags;
        #define TPATF_TASQ_FLAGS_PKT_END                    (1<<0)
        #define TPATF_TASQ_FLAGS_MGMT_PACKET                (1<<1)
        #define TPATF_TASQ_FLAGS_CATCHUP_PACKET             (1<<2)
        #define TPATF_TASQ_FLAGS_DONT_GEN_CRC               (1<<3)
        #define TPATF_TASQ_FLAGS_DROP                       (1<<4)
        #define TPATF_TASQ_FLAGS_RESERVED                   (0x3<<5)
        #define TPATF_TASQ_FLAGS_MGMT_PKT_TAG_XI               (0x1f<<8)
        #define TPATF_TASQ_FLAGS_CS16_VLD                   (1<<15)

    u16_t tpatf_tasq_cs16;
        #define TPATF_TASQ_CS16_VALUE                       (0xffff<<0)
    u16_t unused_10;
    u32_t unused_11[10];

    u32_t tpatf_tasq_ftq_cmd;
        #define TPATF_TASQ_FTQ_CMD_CPY_DATA                 (1UL<<11)
        #define TPATF_TASQ_FTQ_CMD_ADD_INTERVEN             (1UL<<27)
        #define TPATF_TASQ_FTQ_CMD_ADD_DATA                 (1UL<<28)
        #define TPATF_TASQ_FTQ_CMD_BUSY                     (1UL<<31)
    u32_t unused_12[429];

    u32_t tpatf_ctx_cmd;
        #define TPATF_CTX_CMD_NUM_BLOCKS                    (0x3UL<<0)
        #define TPATF_CTX_CMD_OFFSET                        (0x1ffUL<<3)
        #define TPATF_CTX_CMD_CID_VALUE                     (0x3fffUL<<12)
        #define TPATF_CTX_CMD_PREFETCH_SIZE                 (0x3UL<<26)
        #define TPATF_CTX_CMD_MOD_USAGE_CNT                 (0x3UL<<28)
            #define TPATF_CTX_CMD_MOD_USAGE_CNT_00          (0UL<<28)
            #define TPATF_CTX_CMD_MOD_USAGE_CNT_01          (1UL<<28)
            #define TPATF_CTX_CMD_MOD_USAGE_CNT_10          (2UL<<28)
            #define TPATF_CTX_CMD_MOD_USAGE_CNT_11          (3UL<<28)
    u32_t unused_13[499];

    u32_t tpatf_tpat_crack_cmd;
        #define TPATF_TPAT_CRACK_CMD_CRC32_1_LEN            (0xffffUL<<0)
        #define TPATF_TPAT_CRACK_CMD_CRACK                  (1UL<<16)
        #define TPATF_TPAT_CRACK_CMD_L2_VLAN                (1UL<<17)
        #define TPATF_TPAT_CRACK_CMD_L2_LLC                 (1UL<<18)
        #define TPATF_TPAT_CRACK_CMD_PLUS_TWO               (1UL<<19)
        #define TPATF_TPAT_CRACK_CMD_L3_UPDATE              (1UL<<20)
        #define TPATF_TPAT_CRACK_CMD_L4_UDP                 (1UL<<21)
        #define TPATF_TPAT_CRACK_CMD_L4_USE_RAW             (1UL<<22)
        #define TPATF_TPAT_CRACK_CMD_PART_HDR_CS            (1UL<<23)
        #define TPATF_TPAT_CRACK_CMD_L4_UPDATE              (1UL<<24)
        #define TPATF_TPAT_CRACK_CMD_CRC32_2_START          (1UL<<25)
        #define TPATF_TPAT_CRACK_CMD_CRC32_1_INIT           (1UL<<26)
        #define TPATF_TPAT_CRACK_CMD_IPV6_ADDR              (1UL<<27)
        #define TPATF_TPAT_CRACK_CMD_RESULT_REG_CLEAR       (1UL<<28)
        #define TPATF_TPAT_CRACK_CMD_DATA_PATH_CLEAR        (1UL<<29)
        #define TPATF_TPAT_CRACK_CMD_DONE                   (1UL<<31)

    u16_t tpatf_tpat_crack_ip_offset;
    u16_t tpatf_tpat_crack_ip_len;
    u16_t tpatf_tpat_crack_tcp_offset;
    u16_t tpatf_tpat_crack_tcp_len;
    u16_t tpatf_tpat_crack_l5_offset;
    u16_t tpatf_tpat_crack_l5_len;
    u16_t tpatf_tpat_crack_ip_chksum;
    u16_t tpatf_tpat_crack_ip_pseudo_chksum;
    u16_t tpatf_tpat_crack_tcp_chksum;
    u16_t tpatf_tpat_crack_crc32_1_start;
    u32_t tpatf_tpat_crack_crc32_1_seed;
    u32_t tpatf_tpat_crack_crc32_1_result;
    u32_t tpatf_tpat_crack_crc32_2_result;
    u32_t tpatf_ipv6_programmable_extension0;
        #define TPATF_IPV6_PROGRAMMABLE_EXTENSION0_NEXT_HEADER_LEN  (0xffUL<<0)
        #define TPATF_IPV6_PROGRAMMABLE_EXTENSION0_NEXT_HEADER  (0xffUL<<16)
        #define TPATF_IPV6_PROGRAMMABLE_EXTENSION0_NEXT_HEADER_LEN_TYPE  (1UL<<30)
        #define TPATF_IPV6_PROGRAMMABLE_EXTENSION0_NEXT_HEADER_EN  (1UL<<31)

    u32_t tpatf_ipv6_programmable_extension1;
        #define TPATF_IPV6_PROGRAMMABLE_EXTENSION1_NEXT_HEADER_LEN  (0xffUL<<0)
        #define TPATF_IPV6_PROGRAMMABLE_EXTENSION1_NEXT_HEADER  (0xffUL<<16)
        #define TPATF_IPV6_PROGRAMMABLE_EXTENSION1_NEXT_HEADER_LEN_TYPE  (1UL<<30)
        #define TPATF_IPV6_PROGRAMMABLE_EXTENSION1_NEXT_HEADER_EN  (1UL<<31)

    u32_t tpatf_ipv6_programmable_extension2;
        #define TPATF_IPV6_PROGRAMMABLE_EXTENSION2_NEXT_HEADER_LEN  (0xffUL<<0)
        #define TPATF_IPV6_PROGRAMMABLE_EXTENSION2_NEXT_HEADER  (0xffUL<<16)
        #define TPATF_IPV6_PROGRAMMABLE_EXTENSION2_NEXT_HEADER_LEN_TYPE  (1UL<<30)
        #define TPATF_IPV6_PROGRAMMABLE_EXTENSION2_NEXT_HEADER_EN  (1UL<<31)

    u32_t tpatf_ipv6_programmable_extension3;
        #define TPATF_IPV6_PROGRAMMABLE_EXTENSION3_NEXT_HEADER_LEN  (0xffUL<<0)
        #define TPATF_IPV6_PROGRAMMABLE_EXTENSION3_NEXT_HEADER  (0xffUL<<16)
        #define TPATF_IPV6_PROGRAMMABLE_EXTENSION3_NEXT_HEADER_LEN_TYPE  (1UL<<30)
        #define TPATF_IPV6_PROGRAMMABLE_EXTENSION3_NEXT_HEADER_EN  (1UL<<31)

    u32_t tpatf_ipv6_programmable_extension4;
        #define TPATF_IPV6_PROGRAMMABLE_EXTENSION4_NEXT_HEADER_LEN  (0xffUL<<0)
        #define TPATF_IPV6_PROGRAMMABLE_EXTENSION4_NEXT_HEADER  (0xffUL<<16)
        #define TPATF_IPV6_PROGRAMMABLE_EXTENSION4_NEXT_HEADER_LEN_TYPE  (1UL<<30)
        #define TPATF_IPV6_PROGRAMMABLE_EXTENSION4_NEXT_HEADER_EN  (1UL<<31)

    u32_t tpatf_ipv6_programmable_extension5;
        #define TPATF_IPV6_PROGRAMMABLE_EXTENSION5_NEXT_HEADER_LEN  (0xffUL<<0)
        #define TPATF_IPV6_PROGRAMMABLE_EXTENSION5_NEXT_HEADER  (0xffUL<<16)
        #define TPATF_IPV6_PROGRAMMABLE_EXTENSION5_NEXT_HEADER_LEN_TYPE  (1UL<<30)
        #define TPATF_IPV6_PROGRAMMABLE_EXTENSION5_NEXT_HEADER_EN  (1UL<<31)

    u32_t tpatf_ipv6_programmable_extension6;
        #define TPATF_IPV6_PROGRAMMABLE_EXTENSION6_NEXT_HEADER_LEN  (0xffUL<<0)
        #define TPATF_IPV6_PROGRAMMABLE_EXTENSION6_NEXT_HEADER  (0xffUL<<16)
        #define TPATF_IPV6_PROGRAMMABLE_EXTENSION6_NEXT_HEADER_LEN_TYPE  (1UL<<30)
        #define TPATF_IPV6_PROGRAMMABLE_EXTENSION6_NEXT_HEADER_EN  (1UL<<31)

    u32_t tpatf_ipv6_programmable_extension7;
        #define TPATF_IPV6_PROGRAMMABLE_EXTENSION7_NEXT_HEADER_LEN  (0xffUL<<0)
        #define TPATF_IPV6_PROGRAMMABLE_EXTENSION7_NEXT_HEADER  (0xffUL<<16)
        #define TPATF_IPV6_PROGRAMMABLE_EXTENSION7_NEXT_HEADER_LEN_TYPE  (1UL<<30)
        #define TPATF_IPV6_PROGRAMMABLE_EXTENSION7_NEXT_HEADER_EN  (1UL<<31)

    u32_t tpatf_tpatc_debug1;
    u32_t tpatf_tpatc_debug2;
    u32_t unused_14[3053];
    u32_t tpatf_tx_header_queue[4096];
    u32_t tpatf_tx_payload_queue[16384];
    u32_t unused_15[40960];
    u32_t tpatf_ctx_window5[32768];
    u32_t tpatf_ctx_window6[32768];
    u32_t tpatf_ctx_window1[32768];
    u32_t tpatf_ctx_window2[32768];
    u32_t tpatf_ctx_window3[32768];
    u32_t tpatf_ctx_window4[32768];
} tpat_fio_xi_t;


/*
 *  rxp_fio definition
 *  offset: 0x80000000
 */
typedef struct rxp_fio
{
    u32_t rxpf_events_bits;
        #define RXPF_EVENTS_BITS_GPIO0                      (1UL<<15)
        #define RXPF_EVENTS_BITS_GPIO1                      (1UL<<16)
        #define RXPF_EVENTS_BITS_GPIO2                      (1UL<<17)
        #define RXPF_EVENTS_BITS_GPIO3                      (1UL<<18)

    u32_t rxpf_attentions_bits;
        #define RXPF_ATTENTIONS_BITS_EPB_ERROR              (1UL<<30)

    u32_t rxpf_event_enable;
    u32_t rxpf_attention_enable;
    u32_t rxpf_fio_status;

    u32_t rxpf_mult_result;
    u32_t rxpf_mult_a;

    u32_t rxpf_mult_b;

    u32_t rxpf_ctx_window_cid1;

    u32_t rxpf_ctx_window_cid2;
        #define RXPF_CTX_WINDOW_CID2_CTX_WINDOW_CID2_VALUE  (0x3fffUL<<7)

    u32_t rxpf_ctx_window_cid3;
        #define RXPF_CTX_WINDOW_CID3_CTX_WINDOW_CID3_VALUE  (0x3fffUL<<7)

    u32_t rxpf_ctx_window_cid4;
        #define RXPF_CTX_WINDOW_CID4_CTX_WINDOW_CID4_VALUE  (0x3fffUL<<7)
    u32_t unused_0[4];

    u32_t rxpf_hc_inc_tcp_insegs;
    u32_t rxpf_hc_inc_tcp_inerrs;
    u32_t rxpf_hc_inc_ip_inreceives;
    u32_t rxpf_hc_inc_ip_inhdrerrors;
    u32_t rxpf_hc_inc_ip_indiscards;
    u32_t rxpf_hc_inc_ip_indelivers;
    u32_t rxpf_hc_inc_ip_reasmreqds;
    u32_t rxpf_hc_inc_ip_reasmoks;
    u32_t rxpf_hc_inc_ip_reasmfails;
    u32_t rxpf_hc_inc_stat[3];
    u32_t rxpf_free_counter_value;
    u32_t rxpf_timer_retran_value;
    u16_t rxpf_timer_rxpush_value;
    u16_t rxpf_timer_delayack_value;
    u16_t rxpf_timer_keepalive_value;
    u16_t rxpf_timer_nagle_value;
    u32_t rxpf_rxp_rbuf_cluster;

    u32_t rxpf_rxp_rbuf_burst_offset;
        #define RXPF_RXP_RBUF_BURST_OFFSET_OFFSET_TE           (0x7ffUL<<3)
    u32_t unused_1[30];

    u32_t rxpf_rxpq_bits_errors;
        #define RXPF_RXPQ_BITS_ERRORS_TCP_SYNC_PRESENT      (1UL<<14)

    u32_t rxpf_rxpq_bits_status;
        #define RXPF_RXPQ_BITS_STATUS_VALID                 (1UL<<20)

    u8_t rxpf_rxpq_bits_multicast_hash_idx;
    u8_t rxpf_rxpq_bits_acpi_pat;
        #define RXPF_RXPQ_BITS_ACPI_PAT_ACPI_PAT_TE            (0x7<<0)

    u8_t rxpf_rxpq_knum;
    u8_t unused_2;
    u16_t rxpf_rxpq_rule_tag;
    u16_t rxpf_rxpq_pkt_len;
    u16_t rxpf_rxpq_vlan_tag;
    u8_t rxpf_rxpq_ip_hdr_offset;
    u8_t unused_3;
    u16_t rxpf_rxpq_ip_xsum;
    u8_t  rxpf_rxpq_tcp_udp_hdr_offset;
    u8_t  unused_4;                                      
    u16_t rxpf_rxpq_tcp_udp_xsum;
    u16_t rxpf_rxpq_tcp_payload_len;
    u16_t rxpf_rxpq_pseud_xsum;
    u16_t rxpf_rxpq_l2_payload_raw_xsum;
    u8_t  rxpf_rxpq_data_offset;                             
    u8_t  unused_5[3];                                   
    u32_t rxpf_rxpq_mbuf_cluster;
    u32_t rxpf_rxpq_cid;
    u32_t unused_6[3];
    u32_t rxpf_rxpq_ftq_cmd;

    u32_t rxpf_rx_proc_ftq_trip;

    u32_t rxpf_rxpcq_cid;
    u32_t rxpf_rxpcq_generic1;
    u32_t rxpf_rxpcq_generic2;
    u32_t unused_7[11];
    u32_t rxpf_rxpcq_ftq_cmd;
    u32_t unused_8;

    u32_t rxpf_rv2ppq_cid;
    u32_t rxpf_rv2ppq_mbuf_cluster;
    u16_t rxpf_rv2ppq_operand_flags;
    u8_t rxpf_rv2ppq_knum;
    u8_t rxpf_rv2ppq_opcode;
    u16_t rxpf_rv2ppq_operand16_0;  // Note that 16_0 and 16_1 will be absorbed 
    u16_t rxpf_rv2ppq_operand16_1;  // by RDMA and won't be passed to COM
    u16_t rxpf_rv2ppq_operand16_2;
    u16_t rxpf_rv2ppq_operand16_3;
    u16_t rxpf_rv2ppq_operand16_4;
    u16_t rxpf_rv2ppq_operand16_5;
    u16_t rxpf_rv2ppq_operand16_6;
    u16_t rxpf_rv2ppq_operand16_7;
    u32_t rxpf_rv2ppq_operand32_0;   // Note that 32_0 and 32_1 will be absorbed 
    u32_t rxpf_rv2ppq_operand32_1;   // by RDMA and won't be passed to COM
    u32_t rxpf_rv2ppq_operand32_2;
    u32_t rxpf_rv2ppq_operand32_3;
    u32_t rxpf_rv2ppq_operand32_4;
    u32_t unused_9[2];
    u32_t rxpf_rv2ppq_ftq_cmd;
    u32_t unused_10;

    u32_t rxpf_mcpq_bits_status;
    u16_t rxpf_mcpq_pkt_len;
    u16_t unused_11;
    u32_t rxpf_mcpq_mbuf_cluster;
    u32_t unused_12[11];
    u32_t rxpf_mcpq_ftq_cmd;
    u32_t unused_13;

    u32_t rxpf_csq_cid;
    u8_t rxpf_csq_flags;
    u8_t unused_14;
    u16_t unused_15;
    u32_t unused_16[12];
    u32_t rxpf_csq_ftq_cmd;
    u32_t unused_17[369];

    u32_t rxpf_burst_base0;

    u32_t rxpf_burst_base1;

    u32_t rxpf_burst_base2;

    u32_t rxpf_burst_base3;

    u32_t rxpf_burst_cmd0;

    u32_t rxpf_burst_cmd1;
    u32_t unused_18[58];

    u32_t rxpf_burst_data0[16];
    u32_t rxpf_burst_data1[16];
    u32_t unused_19[32];
    u32_t rxpf_rbuf_burst_data[16];
    u32_t unused_20[3440];
    u32_t rxpf_rx_mbuf[4096];
    u32_t unused_21[122880];
    u32_t rxpf_ctx_window1[32768];
    u32_t rxpf_ctx_window2[32768];
    u32_t rxpf_ctx_window3[32768];
    u32_t rxpf_ctx_window4[32768];
} rxp_fio_t;


/*
 *  rxp_fio definition
 *  offset: 0x80000000
 */
typedef struct rxp_fio_xi
{
    u32_t rxpf_events_bits;
        #define RXPF_EVENTS_BITS_FTQ0_VALID                 (1UL<<0)
        #define RXPF_EVENTS_BITS_FTQ1_VALID                 (1UL<<1)
        #define RXPF_EVENTS_BITS_FTQ2_VALID                 (1UL<<2)
        #define RXPF_EVENTS_BITS_SCANNER_DONE               (1UL<<3)
        #define RXPF_EVENTS_BITS_DMA_WR_DONE                (1UL<<4)
        #define RXPF_EVENTS_BITS_DMA_RD_DONE                (1UL<<5)
        #define RXPF_EVENTS_BITS_CRACKER_DONE               (1UL<<6)
        #define RXPF_EVENTS_BITS_MULTIPLY_DONE              (1UL<<7)
        #define RXPF_EVENTS_BITS_EXP_ROM                    (1UL<<8)
        #define RXPF_EVENTS_BITS_VPD                        (1UL<<9)
        #define RXPF_EVENTS_BITS_FLASH                      (1UL<<10)
        #define RXPF_EVENTS_BITS_SMB0                       (1UL<<11)
        #define RXPF_EVENTS_BITS_RESERVED0                  (1UL<<12)
        #define RXPF_EVENTS_BITS_RESERVED1                  (1UL<<13)
        #define RXPF_EVENTS_BITS_RESERVED2                  (1UL<<14)
        #define RXPF_EVENTS_BITS_GPIO                       (1UL<<15)
        #define RXPF_EVENTS_BITS_SW_TMR_1                   (1UL<<19)
        #define RXPF_EVENTS_BITS_SW_TMR_2                   (1UL<<20)
        #define RXPF_EVENTS_BITS_SW_TMR_3                   (1UL<<21)
        #define RXPF_EVENTS_BITS_SW_TMR_4                   (1UL<<22)
        #define RXPF_EVENTS_BITS_LINK_CHANGED               (1UL<<23)
        #define RXPF_EVENTS_BITS_MI_INT                     (1UL<<25)
        #define RXPF_EVENTS_BITS_MI_COMPLETE                (1UL<<26)
        #define RXPF_EVENTS_BITS_MAIN_PWR_INT               (1UL<<27)
        #define RXPF_EVENTS_BITS_NOT_ENABLED                (1UL<<30)
        #define RXPF_EVENTS_BITS_ATTENTIONS_VALID           (1UL<<31)

    u32_t rxpf_attentions_bits;
        #define RXPF_ATTENTIONS_BITS_LINK_STATE             (1UL<<0)
        #define RXPF_ATTENTIONS_BITS_TX_SCHEDULER_ABORT     (1UL<<1)
        #define RXPF_ATTENTIONS_BITS_TX_BD_READ_ABORT       (1UL<<2)
        #define RXPF_ATTENTIONS_BITS_TX_BD_CACHE_ABORT      (1UL<<3)
        #define RXPF_ATTENTIONS_BITS_TX_PROCESSOR_ABORT     (1UL<<4)
        #define RXPF_ATTENTIONS_BITS_TX_DMA_ABORT           (1UL<<5)
        #define RXPF_ATTENTIONS_BITS_TX_PATCHUP_ABORT       (1UL<<6)
        #define RXPF_ATTENTIONS_BITS_TX_ASSEMBLER_ABORT     (1UL<<7)
        #define RXPF_ATTENTIONS_BITS_RX_PARSER_MAC_ABORT    (1UL<<8)
        #define RXPF_ATTENTIONS_BITS_RX_PARSER_CATCHUP_ABORT  (1UL<<9)
        #define RXPF_ATTENTIONS_BITS_RX_MBUF_ABORT          (1UL<<10)
        #define RXPF_ATTENTIONS_BITS_RX_LOOKUP_ABORT        (1UL<<11)
        #define RXPF_ATTENTIONS_BITS_RX_PROCESSOR_ABORT     (1UL<<12)
        #define RXPF_ATTENTIONS_BITS_RX_V2P_ABORT           (1UL<<13)
        #define RXPF_ATTENTIONS_BITS_RX_BD_CACHE_ABORT      (1UL<<14)
        #define RXPF_ATTENTIONS_BITS_RX_DMA_ABORT           (1UL<<15)
        #define RXPF_ATTENTIONS_BITS_COMPLETION_ABORT       (1UL<<16)
        #define RXPF_ATTENTIONS_BITS_HOST_COALESCE_ABORT    (1UL<<17)
        #define RXPF_ATTENTIONS_BITS_MAILBOX_QUEUE_ABORT    (1UL<<18)
        #define RXPF_ATTENTIONS_BITS_CONTEXT_ABORT          (1UL<<19)
        #define RXPF_ATTENTIONS_BITS_CMD_SCHEDULER_ABORT    (1UL<<20)
        #define RXPF_ATTENTIONS_BITS_CMD_PROCESSOR_ABORT    (1UL<<21)
        #define RXPF_ATTENTIONS_BITS_MGMT_PROCESSOR_ABORT   (1UL<<22)
        #define RXPF_ATTENTIONS_BITS_MAC_ABORT              (1UL<<23)
        #define RXPF_ATTENTIONS_BITS_TIMER_ABORT            (1UL<<24)
        #define RXPF_ATTENTIONS_BITS_DMAE_ABORT             (1UL<<25)
        #define RXPF_ATTENTIONS_BITS_FLSH_ABORT             (1UL<<26)
        #define RXPF_ATTENTIONS_BITS_GRC_ABORT              (1UL<<27)
        #define RXPF_ATTENTIONS_BITS_PARITY_ERROR           (1UL<<31)

    u32_t rxpf_event_enable;
    u32_t rxpf_attention_enable;
    u32_t rxpf_fio_status;
        #define RXPF_FIO_STATUS_ENABLED                     (1UL<<0)
        #define RXPF_FIO_STATUS_FORCE_ENA                   (1UL<<1)

    u32_t rxpf_mult_result;
    u32_t rxpf_mult_a;
        #define RXPF_MULT_A_VALUE                           (0xffffUL<<0)

    u32_t rxpf_mult_b;
        #define RXPF_MULT_B_VALUE                           (0xffffUL<<0)

    u32_t rxpf_ctx_window_cid1;
        #define RXPF_CTX_WINDOW_CID1_LOCK_TYPE              (0x7UL<<0)
            #define RXPF_CTX_WINDOW_CID1_LOCK_TYPE_VOID     (0UL<<0)
            #define RXPF_CTX_WINDOW_CID1_LOCK_TYPE_PROTOCOL  (1UL<<0)
            #define RXPF_CTX_WINDOW_CID1_LOCK_TYPE_TX       (2UL<<0)
            #define RXPF_CTX_WINDOW_CID1_LOCK_TYPE_TIMER    (4UL<<0)
            #define RXPF_CTX_WINDOW_CID1_LOCK_TYPE_COMPLETE  (7UL<<0)
        #define RXPF_CTX_WINDOW_CID1_VALUE                  (0x3fffUL<<7)
        #define RXPF_CTX_WINDOW_CID1_MOD_USAGE_CNT          (0x3UL<<24)
            #define RXPF_CTX_WINDOW_CID1_MOD_USAGE_CNT_00   (0UL<<24)
            #define RXPF_CTX_WINDOW_CID1_MOD_USAGE_CNT_01   (1UL<<24)
            #define RXPF_CTX_WINDOW_CID1_MOD_USAGE_CNT_10   (2UL<<24)
            #define RXPF_CTX_WINDOW_CID1_MOD_USAGE_CNT_11   (3UL<<24)
        #define RXPF_CTX_WINDOW_CID1_LOCK_GRANTED           (1UL<<26)
        #define RXPF_CTX_WINDOW_CID1_LOCK_MODE              (0x3UL<<27)
            #define RXPF_CTX_WINDOW_CID1_LOCK_MODE_UNLOCK   (0UL<<27)
            #define RXPF_CTX_WINDOW_CID1_LOCK_MODE_IMMEDIATE  (1UL<<27)
            #define RXPF_CTX_WINDOW_CID1_LOCK_MODE_SURE     (2UL<<27)
        #define RXPF_CTX_WINDOW_CID1_NO_EXT_ACC             (1UL<<29)
        #define RXPF_CTX_WINDOW_CID1_LOCK_STATUS            (1UL<<30)
        #define RXPF_CTX_WINDOW_CID1_LOCK_REQ               (1UL<<31)

    u32_t rxpf_ctx_window_cid2;
        #define RXPF_CTX_WINDOW_CID2_LOCK_TYPE              (0x7UL<<0)
            #define RXPF_CTX_WINDOW_CID2_LOCK_TYPE_VOID     (0UL<<0)
            #define RXPF_CTX_WINDOW_CID2_LOCK_TYPE_PROTOCOL  (1UL<<0)
            #define RXPF_CTX_WINDOW_CID2_LOCK_TYPE_TX       (2UL<<0)
            #define RXPF_CTX_WINDOW_CID2_LOCK_TYPE_TIMER    (4UL<<0)
            #define RXPF_CTX_WINDOW_CID2_LOCK_TYPE_COMPLETE  (7UL<<0)
        #define RXPF_CTX_WINDOW_CID2_VALUE                  (0x3fffUL<<7)
        #define RXPF_CTX_WINDOW_CID2_MOD_USAGE_CNT          (0x3UL<<24)
            #define RXPF_CTX_WINDOW_CID2_MOD_USAGE_CNT_00   (0UL<<24)
            #define RXPF_CTX_WINDOW_CID2_MOD_USAGE_CNT_01   (1UL<<24)
            #define RXPF_CTX_WINDOW_CID2_MOD_USAGE_CNT_10   (2UL<<24)
            #define RXPF_CTX_WINDOW_CID2_MOD_USAGE_CNT_11   (3UL<<24)
        #define RXPF_CTX_WINDOW_CID2_LOCK_GRANTED           (1UL<<26)
        #define RXPF_CTX_WINDOW_CID2_LOCK_MODE              (0x3UL<<27)
            #define RXPF_CTX_WINDOW_CID2_LOCK_MODE_UNLOCK   (0UL<<27)
            #define RXPF_CTX_WINDOW_CID2_LOCK_MODE_IMMEDIATE  (1UL<<27)
            #define RXPF_CTX_WINDOW_CID2_LOCK_MODE_SURE     (2UL<<27)
        #define RXPF_CTX_WINDOW_CID2_NO_EXT_ACC             (1UL<<29)
        #define RXPF_CTX_WINDOW_CID2_LOCK_STATUS            (1UL<<30)
        #define RXPF_CTX_WINDOW_CID2_LOCK_REQ               (1UL<<31)

    u32_t rxpf_ctx_window_cid3;
        #define RXPF_CTX_WINDOW_CID3_LOCK_TYPE              (0x7UL<<0)
            #define RXPF_CTX_WINDOW_CID3_LOCK_TYPE_VOID     (0UL<<0)
            #define RXPF_CTX_WINDOW_CID3_LOCK_TYPE_PROTOCOL  (1UL<<0)
            #define RXPF_CTX_WINDOW_CID3_LOCK_TYPE_TX       (2UL<<0)
            #define RXPF_CTX_WINDOW_CID3_LOCK_TYPE_TIMER    (4UL<<0)
            #define RXPF_CTX_WINDOW_CID3_LOCK_TYPE_COMPLETE  (7UL<<0)
        #define RXPF_CTX_WINDOW_CID3_VALUE                  (0x3fffUL<<7)
        #define RXPF_CTX_WINDOW_CID3_MOD_USAGE_CNT          (0x3UL<<24)
            #define RXPF_CTX_WINDOW_CID3_MOD_USAGE_CNT_00   (0UL<<24)
            #define RXPF_CTX_WINDOW_CID3_MOD_USAGE_CNT_01   (1UL<<24)
            #define RXPF_CTX_WINDOW_CID3_MOD_USAGE_CNT_10   (2UL<<24)
            #define RXPF_CTX_WINDOW_CID3_MOD_USAGE_CNT_11   (3UL<<24)
        #define RXPF_CTX_WINDOW_CID3_LOCK_GRANTED           (1UL<<26)
        #define RXPF_CTX_WINDOW_CID3_LOCK_MODE              (0x3UL<<27)
            #define RXPF_CTX_WINDOW_CID3_LOCK_MODE_UNLOCK   (0UL<<27)
            #define RXPF_CTX_WINDOW_CID3_LOCK_MODE_IMMEDIATE  (1UL<<27)
            #define RXPF_CTX_WINDOW_CID3_LOCK_MODE_SURE     (2UL<<27)
        #define RXPF_CTX_WINDOW_CID3_NO_EXT_ACC             (1UL<<29)
        #define RXPF_CTX_WINDOW_CID3_LOCK_STATUS            (1UL<<30)
        #define RXPF_CTX_WINDOW_CID3_LOCK_REQ               (1UL<<31)

    u32_t rxpf_ctx_window_cid4;
        #define RXPF_CTX_WINDOW_CID4_LOCK_TYPE              (0x7UL<<0)
            #define RXPF_CTX_WINDOW_CID4_LOCK_TYPE_VOID     (0UL<<0)
            #define RXPF_CTX_WINDOW_CID4_LOCK_TYPE_PROTOCOL  (1UL<<0)
            #define RXPF_CTX_WINDOW_CID4_LOCK_TYPE_TX       (2UL<<0)
            #define RXPF_CTX_WINDOW_CID4_LOCK_TYPE_TIMER    (4UL<<0)
            #define RXPF_CTX_WINDOW_CID4_LOCK_TYPE_COMPLETE  (7UL<<0)
        #define RXPF_CTX_WINDOW_CID4_VALUE                  (0x3fffUL<<7)
        #define RXPF_CTX_WINDOW_CID4_MOD_USAGE_CNT          (0x3UL<<24)
            #define RXPF_CTX_WINDOW_CID4_MOD_USAGE_CNT_00   (0UL<<24)
            #define RXPF_CTX_WINDOW_CID4_MOD_USAGE_CNT_01   (1UL<<24)
            #define RXPF_CTX_WINDOW_CID4_MOD_USAGE_CNT_10   (2UL<<24)
            #define RXPF_CTX_WINDOW_CID4_MOD_USAGE_CNT_11   (3UL<<24)
        #define RXPF_CTX_WINDOW_CID4_LOCK_GRANTED           (1UL<<26)
        #define RXPF_CTX_WINDOW_CID4_LOCK_MODE              (0x3UL<<27)
            #define RXPF_CTX_WINDOW_CID4_LOCK_MODE_UNLOCK   (0UL<<27)
            #define RXPF_CTX_WINDOW_CID4_LOCK_MODE_IMMEDIATE  (1UL<<27)
            #define RXPF_CTX_WINDOW_CID4_LOCK_MODE_SURE     (2UL<<27)
        #define RXPF_CTX_WINDOW_CID4_NO_EXT_ACC             (1UL<<29)
        #define RXPF_CTX_WINDOW_CID4_LOCK_STATUS            (1UL<<30)
        #define RXPF_CTX_WINDOW_CID4_LOCK_REQ               (1UL<<31)
    u32_t unused_0[4];

    u32_t rxpf_hc_inc_tcp_insegs;
    u32_t rxpf_hc_inc_tcp_inerrs;
    u32_t rxpf_hc_inc_ip_inreceives;
    u32_t rxpf_hc_inc_ip_inhdrerrors;
    u32_t rxpf_hc_inc_ip_indiscards;
    u32_t rxpf_hc_inc_ip_indelivers;
    u32_t rxpf_hc_inc_ip_reasmreqds;
    u32_t rxpf_hc_inc_ip_reasmoks;
    u32_t rxpf_hc_inc_ip_reasmfails;
    u32_t rxpf_hc_inc_stat[3];
    u32_t rxpf_free_counter_value;
    u32_t rxpf_timer_retran_value;
    u16_t rxpf_timer_rxpush_value;
    u16_t rxpf_timer_delayack_value;
    u16_t rxpf_timer_keepalive_value;
    u16_t rxpf_timer_nagle_value;
    u32_t rxpf_rxp_rbuf_cluster;
        #define RXPF_RXP_RBUF_CLUSTER_COUNT                 (0x7fUL<<0)
        #define RXPF_RXP_RBUF_CLUSTER_TAIL                  (0x1ffUL<<7)
        #define RXPF_RXP_RBUF_CLUSTER_HEAD                  (0x1ffUL<<16)

    u32_t rxpf_rxp_rbuf_burst_offset;
        #define RXPF_RXP_RBUF_BURST_OFFSET_OFFSET_XI           (0x3ffUL<<4)
        #define RXPF_RXP_RBUF_BURST_OFFSET_BUSY             (1UL<<31)
    u32_t unused_1[2];

    u32_t rxpf_ctx_window_cid5;
        #define RXPF_CTX_WINDOW_CID5_LOCK_TYPE              (0x7UL<<0)
            #define RXPF_CTX_WINDOW_CID5_LOCK_TYPE_VOID     (0UL<<0)
            #define RXPF_CTX_WINDOW_CID5_LOCK_TYPE_PROTOCOL  (1UL<<0)
            #define RXPF_CTX_WINDOW_CID5_LOCK_TYPE_TX       (2UL<<0)
            #define RXPF_CTX_WINDOW_CID5_LOCK_TYPE_TIMER    (4UL<<0)
            #define RXPF_CTX_WINDOW_CID5_LOCK_TYPE_COMPLETE  (7UL<<0)
        #define RXPF_CTX_WINDOW_CID5_VALUE                  (0x3fffUL<<7)
        #define RXPF_CTX_WINDOW_CID5_MOD_USAGE_CNT          (0x3UL<<24)
            #define RXPF_CTX_WINDOW_CID5_MOD_USAGE_CNT_00   (0UL<<24)
            #define RXPF_CTX_WINDOW_CID5_MOD_USAGE_CNT_01   (1UL<<24)
            #define RXPF_CTX_WINDOW_CID5_MOD_USAGE_CNT_10   (2UL<<24)
            #define RXPF_CTX_WINDOW_CID5_MOD_USAGE_CNT_11   (3UL<<24)
        #define RXPF_CTX_WINDOW_CID5_LOCK_GRANTED           (1UL<<26)
        #define RXPF_CTX_WINDOW_CID5_LOCK_MODE              (0x3UL<<27)
            #define RXPF_CTX_WINDOW_CID5_LOCK_MODE_UNLOCK   (0UL<<27)
            #define RXPF_CTX_WINDOW_CID5_LOCK_MODE_IMMEDIATE  (1UL<<27)
            #define RXPF_CTX_WINDOW_CID5_LOCK_MODE_SURE     (2UL<<27)
        #define RXPF_CTX_WINDOW_CID5_NO_EXT_ACC             (1UL<<29)
        #define RXPF_CTX_WINDOW_CID5_LOCK_STATUS            (1UL<<30)
        #define RXPF_CTX_WINDOW_CID5_LOCK_REQ               (1UL<<31)

    u32_t rxpf_ctx_window_cid6;
        #define RXPF_CTX_WINDOW_CID6_LOCK_TYPE              (0x7UL<<0)
            #define RXPF_CTX_WINDOW_CID6_LOCK_TYPE_VOID     (0UL<<0)
            #define RXPF_CTX_WINDOW_CID6_LOCK_TYPE_PROTOCOL  (1UL<<0)
            #define RXPF_CTX_WINDOW_CID6_LOCK_TYPE_TX       (2UL<<0)
            #define RXPF_CTX_WINDOW_CID6_LOCK_TYPE_TIMER    (4UL<<0)
            #define RXPF_CTX_WINDOW_CID6_LOCK_TYPE_COMPLETE  (7UL<<0)
        #define RXPF_CTX_WINDOW_CID6_VALUE                  (0x3fffUL<<7)
        #define RXPF_CTX_WINDOW_CID6_MOD_USAGE_CNT          (0x3UL<<24)
            #define RXPF_CTX_WINDOW_CID6_MOD_USAGE_CNT_00   (0UL<<24)
            #define RXPF_CTX_WINDOW_CID6_MOD_USAGE_CNT_01   (1UL<<24)
            #define RXPF_CTX_WINDOW_CID6_MOD_USAGE_CNT_10   (2UL<<24)
            #define RXPF_CTX_WINDOW_CID6_MOD_USAGE_CNT_11   (3UL<<24)
        #define RXPF_CTX_WINDOW_CID6_LOCK_GRANTED           (1UL<<26)
        #define RXPF_CTX_WINDOW_CID6_LOCK_MODE              (0x3UL<<27)
            #define RXPF_CTX_WINDOW_CID6_LOCK_MODE_UNLOCK   (0UL<<27)
            #define RXPF_CTX_WINDOW_CID6_LOCK_MODE_IMMEDIATE  (1UL<<27)
            #define RXPF_CTX_WINDOW_CID6_LOCK_MODE_SURE     (2UL<<27)
        #define RXPF_CTX_WINDOW_CID6_NO_EXT_ACC             (1UL<<29)
        #define RXPF_CTX_WINDOW_CID6_LOCK_STATUS            (1UL<<30)
        #define RXPF_CTX_WINDOW_CID6_LOCK_REQ               (1UL<<31)
    u32_t unused_2[2];

    u32_t rxpf_crc32_command;
        #define RXPF_CRC32_COMMAND_OFFSET                   (0x7fUL<<0)
        #define RXPF_CRC32_COMMAND_LENGTH                   (0x7fUL<<8)
        #define RXPF_CRC32_COMMAND_USE_INTM_SEED            (1UL<<20)
        #define RXPF_CRC32_COMMAND_START                    (1UL<<31)

    u32_t rxpf_crc32_seed;
    u32_t rxpf_crc32_result;
    u32_t rxpf_crc32_intm_seed;
    u32_t unused_3[20];
    u32_t rxpf_rxpq_bits_errors;
        #define RXPF_RXPQ_BITS_ERRORS_L2_USE_HEADER_LENGTH  (1UL<<0)      // For Jumbo Frame support
        #define RXPF_RXPQ_BITS_ERRORS_L2_BAD_CRC            (1UL<<1)
        #define RXPF_RXPQ_BITS_ERRORS_L2_PHY_DECODE         (1UL<<2)
        #define RXPF_RXPQ_BITS_ERRORS_L2_ALIGNMENT          (1UL<<3)
        #define RXPF_RXPQ_BITS_ERRORS_L2_TOO_SHORT          (1UL<<4)
        #define RXPF_RXPQ_BITS_ERRORS_L2_GIANT_FRAME        (1UL<<5)
        #define RXPF_RXPQ_BITS_ERRORS_IP_BAD_LEN            (1UL<<6)
        #define RXPF_RXPQ_BITS_ERRORS_IP_TOO_SHORT          (1UL<<7)
        #define RXPF_RXPQ_BITS_ERRORS_IP_BAD_VERSION        (1UL<<8)
        #define RXPF_RXPQ_BITS_ERRORS_IP_BAD_HLEN           (1UL<<9)
        #define RXPF_RXPQ_BITS_ERRORS_IP_BAD_XSUM           (1UL<<10)
        #define RXPF_RXPQ_BITS_ERRORS_TCP_TOO_SHORT         (1UL<<11)
        #define RXPF_RXPQ_BITS_ERRORS_TCP_BAD_XSUM          (1UL<<12)
        #define RXPF_RXPQ_BITS_ERRORS_TCP_BAD_OFFSET        (1UL<<13)
		#define RXPF_RXPQ_BITS_ERRORS_TCP_SYNC_PRESENT      (1UL<<14)
        #define RXPF_RXPQ_BITS_ERRORS_UDP_BAD_XSUM          (1UL<<15)
        #define RXPF_RXPQ_BITS_ERRORS_IP_BAD_ORDER          (1UL<<16)
        #define RXPF_RXPQ_BITS_ERRORS_IP_HDR_MISMATCH       (1UL<<18)

    u32_t rxpf_rxpq_bits_status;
        #define RXPF_RXPQ_BITS_STATUS_RULE_CLASS            (0x7UL<<0)
        #define RXPF_RXPQ_BITS_STATUS_RULE_P2               (1UL<<3)
        #define RXPF_RXPQ_BITS_STATUS_RULE_P3               (1UL<<4)
        #define RXPF_RXPQ_BITS_STATUS_RULE_P4               (1UL<<5)
        #define RXPF_RXPQ_BITS_STATUS_L2_VLAN_TAG           (1UL<<6)
        #define RXPF_RXPQ_BITS_STATUS_L2_LLC_SNAP           (1UL<<7)
        #define RXPF_RXPQ_BITS_STATUS_RSS_HASH              (1UL<<8)
        #define RXPF_RXPQ_BITS_STATUS_SORT_VECT             (0xfUL<<9)
        #define RXPF_RXPQ_BITS_STATUS_IP_DATAGRAM           (1UL<<13)
        #define RXPF_RXPQ_BITS_STATUS_TCP_SEGMENT           (1UL<<14)
        #define RXPF_RXPQ_BITS_STATUS_UDP_DATAGRAM          (1UL<<15)
        #define RXPF_RXPQ_BITS_STATUS_CU_FRAME              (1UL<<16)
        #define RXPF_RXPQ_BITS_STATUS_IP_PROG_EXT           (1UL<<17)
        #define RXPF_RXPQ_BITS_STATUS_IP_TYPE               (1UL<<18)
        #define RXPF_RXPQ_BITS_STATUS_RULE_P1               (1UL<<19)
        #define RXPF_RXPQ_BITS_STATUS_RLUP_HIT4             (1UL<<20)
        #define RXPF_RXPQ_BITS_STATUS_IP_FRAGMENT           (1UL<<21)
        #define RXPF_RXPQ_BITS_STATUS_IP_OPTIONS_PRESENT    (1UL<<22)
        #define RXPF_RXPQ_BITS_STATUS_TCP_OPTIONS_PRESENT   (1UL<<23)
        #define RXPF_RXPQ_BITS_STATUS_L2_PM_IDX             (0xfUL<<24)
        #define RXPF_RXPQ_BITS_STATUS_L2_PM_HIT             (1UL<<28)
        #define RXPF_RXPQ_BITS_STATUS_L2_MC_HASH_HIT        (1UL<<29)
        #define RXPF_RXPQ_BITS_STATUS_RDMAC_CRC_PASS        (1UL<<30)
        #define RXPF_RXPQ_BITS_STATUS_MP_HIT                (1UL<<31)

    u8_t rxpf_rxpq_bits_multicast_hash_idx;
    u8_t rxpf_rxpq_bits_acpi_pat;
        #define RXPF_RXPQ_BITS_ACPI_PAT_ACPI_PAT_XI            (0xf<<0)
            #define RXPF_RXPQ_BITS_ACPI_PAT_ACPI_PAT_0      (0<<0)
            #define RXPF_RXPQ_BITS_ACPI_PAT_ACPI_PAT_1      (1<<0)
            #define RXPF_RXPQ_BITS_ACPI_PAT_ACPI_PAT_2      (2<<0)
            #define RXPF_RXPQ_BITS_ACPI_PAT_ACPI_PAT_3      (3<<0)
            #define RXPF_RXPQ_BITS_ACPI_PAT_ACPI_PAT_4      (4<<0)
            #define RXPF_RXPQ_BITS_ACPI_PAT_ACPI_PAT_5      (5<<0)
            #define RXPF_RXPQ_BITS_ACPI_PAT_ACPI_PAT_6      (6<<0)
            #define RXPF_RXPQ_BITS_ACPI_PAT_ACPI_PAT_NONE   (7<<0)
            #define RXPF_RXPQ_BITS_ACPI_PAT_ACPI_PAT_8      (8<<0)

    u8_t rxpf_rxpq_knum;
    u8_t unused_4;
    u16_t rxpf_rxpq_rule_tag;
    u16_t rxpf_rxpq_pkt_len;
        #define RXPF_RXPQ_PKT_LEN_VALUE                     (0x3fff<<0)

    u16_t rxpf_rxpq_vlan_tag;
    u8_t rxpf_rxpq_ip_hdr_offset;
    u8_t rxpf_rxpq_rx_qid;
        #define RXPF_RXPQ_RX_QID_VALUE                      (0xf<<0)

    u16_t rxpf_rxpq_ip_xsum;
    u16_t rxpf_rxpq_tcp_udp_hdr_offset;
    u16_t rxpf_rxpq_tcp_udp_xsum;
    u16_t rxpf_rxpq_tcp_payload_len;
    u16_t rxpf_rxpq_pseud_xsum;
    u16_t rxpf_rxpq_l2_payload_raw_xsum;
    u16_t rxpf_rxpq_data_offset;
    u16_t rxpf_rxpq_l3_payload_raw_xsum;
    u32_t rxpf_rxpq_mbuf_cluster;
        #define RXPF_RXPQ_MBUF_CLUSTER_VALUE                (0x1ffffffUL<<0)

    u32_t rxpf_rxpq_cid;
        #define RXPF_RXPQ_CID_VALUE                         (0x3fffUL<<7)

    u16_t rxpf_rxpq_cs16;
        #define RXPF_RXPQ_CS16_VALUE                        (0xffff<<0)
    u16_t unused_5;

    u16_t rxpf_rxpq_ext_status;
        #define RXPF_RXPQ_EXT_STATUS_TCP_SYNC_PRESENT       (1<<0)
        #define RXPF_RXPQ_EXT_STATUS_RLUP_HIT2              (1<<1)
        #define RXPF_RXPQ_EXT_STATUS_TCP_UDP_XSUM_IS_0      (1<<2)
        #define RXPF_RXPQ_EXT_STATUS_IP_ROUTING_HDR_PRESENT  (0x3<<3)
            #define RXPF_RXPQ_EXT_STATUS_IP_ROUTING_HDR_PRESENT_00  (0<<3)
            #define RXPF_RXPQ_EXT_STATUS_IP_ROUTING_HDR_PRESENT_01  (1<<3)
            #define RXPF_RXPQ_EXT_STATUS_IP_ROUTING_HDR_PRESENT_10  (2<<3)
            #define RXPF_RXPQ_EXT_STATUS_IP_ROUTING_HDR_PRESENT_11  (3<<3)
        #define RXPF_RXPQ_EXT_STATUS_ACPI_MATCH             (1<<5)
    u16_t unused_6;
    u32_t unused_7;

    u32_t rxpf_rxpq_ftq_cmd;
        #define RXPF_RXPQ_FTQ_CMD_RXPQ_CMD_POP              (1UL<<30)

    u32_t rxpf_rx_proc_ftq_trip;
        #define RXPF_RX_PROC_FTQ_TRIP_FF                    (0x1ffUL<<0)
        #define RXPF_RX_PROC_FTQ_TRIP_N                     (0x1ffUL<<16)

    u32_t rxpf_rxpcq_cid;
    u32_t rxpf_rxpcq_generic1;
    u32_t rxpf_rxpcq_generic2;
    u32_t unused_8[11];
    u32_t rxpf_rxpcq_ftq_cmd;
        #define RXPF_RXPCQ_FTQ_CMD_RXPCQ_CMD_POP            (1UL<<30)
    u32_t unused_9;

    u32_t rxpf_rv2ppq_cid;
    u32_t rxpf_rv2ppq_mbuf_cluster;
    u16_t rxpf_rv2ppq_operand_flags;
    u8_t rxpf_rv2ppq_knum;
    u8_t rxpf_rv2ppq_opcode;
    u16_t rxpf_rv2ppq_operand16_0;
    u16_t rxpf_rv2ppq_operand16_1;
    u16_t rxpf_rv2ppq_operand16_2;
    u16_t rxpf_rv2ppq_operand16_3;
    u16_t rxpf_rv2ppq_operand16_4;
    u16_t rxpf_rv2ppq_operand16_5;
    u16_t rxpf_rv2ppq_operand16_6;
    u16_t rxpf_rv2ppq_operand16_7;
    u32_t rxpf_rv2ppq_operand32_0;
    u32_t rxpf_rv2ppq_operand32_1;
    u32_t rxpf_rv2ppq_operand32_2;
    u32_t rxpf_rv2ppq_operand32_3;
    u32_t rxpf_rv2ppq_operand32_4;
    u8_t rxpf_rv2ppq_rdma_action;
        #define RXPF_RV2PPQ_RDMA_ACTION_CS16_VLD            (1<<6)
        #define RXPF_RV2PPQ_RDMA_ACTION_NO_SNOOP            (1<<7)

    u8_t rxpf_rv2ppq_cs16_pkt_len;
        #define RXPF_RV2PPQ_CS16_PKT_LEN_VALUE              (0x7f<<0)

    u16_t rxpf_rv2ppq_cs16;
    u32_t unused_10;
    u32_t rxpf_rv2ppq_ftq_cmd;
        #define RXPF_RV2PPQ_FTQ_CMD_CPY_DATA                (1UL<<11)
        #define RXPF_RV2PPQ_FTQ_CMD_ADD_INTERVEN            (1UL<<27)
        #define RXPF_RV2PPQ_FTQ_CMD_ADD_DATA                (1UL<<28)
        #define RXPF_RV2PPQ_FTQ_CMD_BUSY                    (1UL<<31)
    u32_t unused_11;

    u32_t rxpf_mcpq_bits_status;
    u16_t rxpf_mcpq_pkt_len;
    u16_t unused_12;
    u32_t rxpf_mcpq_mbuf_cluster;
    u32_t rxpf_mcpq_rx_errors;
    u16_t rxpf_mcpq_ext_status;
    u16_t unused_13;
    u32_t unused_14[9];
    u32_t rxpf_mcpq_ftq_cmd;
        #define RXPF_MCPQ_FTQ_CMD_CPY_DATA                  (1UL<<11)
        #define RXPF_MCPQ_FTQ_CMD_ADD_INTERVEN              (1UL<<27)
        #define RXPF_MCPQ_FTQ_CMD_ADD_DATA                  (1UL<<28)
        #define RXPF_MCPQ_FTQ_CMD_BUSY                      (1UL<<31)
    u32_t unused_15;

    u32_t rxpf_csq_cid;
    u8_t rxpf_csq_flags;
    u8_t unused_16;
    u16_t unused_17;
    u32_t unused_18[12];
    u32_t rxpf_csq_ftq_cmd;
        #define RXPF_CSQ_FTQ_CMD_CPY_DATA                   (1UL<<11)
        #define RXPF_CSQ_FTQ_CMD_ADD_INTERVEN               (1UL<<27)
        #define RXPF_CSQ_FTQ_CMD_ADD_DATA                   (1UL<<28)
        #define RXPF_CSQ_FTQ_CMD_BUSY                       (1UL<<31)
    u32_t unused_19;

    u32_t rxpf_tschq_cid;
        #define RXPF_TSCHQ_CID_VALUE                        (0x3fffUL<<7)

    u8_t rxpf_tschq_flags;
        #define RXPF_TSCHQ_FLAGS_DELIST                     (1<<0)
        #define RXPF_TSCHQ_FLAGS_NORMAL                     (1<<1)
        #define RXPF_TSCHQ_FLAGS_HIGH                       (1<<2)

    u8_t rxpf_tschq_rsvd_future;
        #define RXPF_TSCHQ_RSVD_FUTURE_VALUE                (0x3<<0)
    u16_t unused_20;
    u32_t unused_21[12];

    u32_t rxpf_tschq_ftq_cmd;
        #define RXPF_TSCHQ_FTQ_CMD_CPY_DATA                 (1UL<<11)
        #define RXPF_TSCHQ_FTQ_CMD_ADD_INTERVEN             (1UL<<27)
        #define RXPF_TSCHQ_FTQ_CMD_ADD_DATA                 (1UL<<28)
        #define RXPF_TSCHQ_FTQ_CMD_BUSY                     (1UL<<31)
    u32_t unused_22[353];

    u32_t rxpf_burst_base0;
        #define RXPF_BURST_BASE0_BASE_VAL0                  (0x3fffUL<<7)

    u32_t rxpf_burst_base1;
        #define RXPF_BURST_BASE1_BASE_VAL1                  (0x3fffUL<<7)

    u32_t rxpf_burst_base2;
        #define RXPF_BURST_BASE2_BASE_VAL2                  (0x3fffUL<<7)

    u32_t rxpf_burst_base3;
        #define RXPF_BURST_BASE3_BASE_VAL3                  (0x3fffUL<<7)

    u32_t rxpf_burst_cmd0;
        #define RXPF_BURST_CMD0_FTQ_SEL                     (0x3UL<<0)
            #define RXPF_BURST_CMD0_FTQ_SEL_0               (0UL<<0)
            #define RXPF_BURST_CMD0_FTQ_SEL_1               (1UL<<0)
            #define RXPF_BURST_CMD0_FTQ_SEL_2               (2UL<<0)
            #define RXPF_BURST_CMD0_FTQ_SEL_3               (3UL<<0)
        #define RXPF_BURST_CMD0_BUSY                        (1UL<<2)
        #define RXPF_BURST_CMD0_OFFSET                      (0x1ffUL<<3)
        #define RXPF_BURST_CMD0_BASE_REG_SEL                (1UL<<23)
        #define RXPF_BURST_CMD0_MOD_USAGE_CNT               (0x3UL<<24)
            #define RXPF_BURST_CMD0_MOD_USAGE_CNT_00        (0UL<<24)
            #define RXPF_BURST_CMD0_MOD_USAGE_CNT_01        (1UL<<24)
            #define RXPF_BURST_CMD0_MOD_USAGE_CNT_10        (2UL<<24)
            #define RXPF_BURST_CMD0_MOD_USAGE_CNT_11        (3UL<<24)
        #define RXPF_BURST_CMD0_PREFETCH_SIZE               (0x3UL<<26)
        #define RXPF_BURST_CMD0_NO_RAM_ACCESS               (1UL<<28)
        #define RXPF_BURST_CMD0_NO_CACHE                    (1UL<<29)
        #define RXPF_BURST_CMD0_CROSS_BOUNDARY              (1UL<<30)

    u32_t rxpf_burst_cmd1;
        #define RXPF_BURST_CMD1_FTQ_SEL                     (0x3UL<<0)
            #define RXPF_BURST_CMD1_FTQ_SEL_0               (0UL<<0)
            #define RXPF_BURST_CMD1_FTQ_SEL_1               (1UL<<0)
            #define RXPF_BURST_CMD1_FTQ_SEL_2               (2UL<<0)
            #define RXPF_BURST_CMD1_FTQ_SEL_3               (3UL<<0)
        #define RXPF_BURST_CMD1_BUSY                        (1UL<<2)
        #define RXPF_BURST_CMD1_OFFSET                      (0x1ffUL<<3)
        #define RXPF_BURST_CMD1_BASE_REG_SEL                (1UL<<23)
        #define RXPF_BURST_CMD1_MOD_USAGE_CNT               (0x3UL<<24)
            #define RXPF_BURST_CMD1_MOD_USAGE_CNT_00        (0UL<<24)
            #define RXPF_BURST_CMD1_MOD_USAGE_CNT_01        (1UL<<24)
            #define RXPF_BURST_CMD1_MOD_USAGE_CNT_10        (2UL<<24)
            #define RXPF_BURST_CMD1_MOD_USAGE_CNT_11        (3UL<<24)
        #define RXPF_BURST_CMD1_PREFETCH_SIZE               (0x3UL<<26)
        #define RXPF_BURST_CMD1_NO_RAM_ACCESS               (1UL<<28)
        #define RXPF_BURST_CMD1_NO_CACHE                    (1UL<<29)
        #define RXPF_BURST_CMD1_CROSS_BOUNDARY              (1UL<<30)

    u32_t rxpf_burst_cmd2;
        #define RXPF_BURST_CMD2_FTQ_SEL                     (0x3UL<<0)
            #define RXPF_BURST_CMD2_FTQ_SEL_0               (0UL<<0)
            #define RXPF_BURST_CMD2_FTQ_SEL_1               (1UL<<0)
            #define RXPF_BURST_CMD2_FTQ_SEL_2               (2UL<<0)
            #define RXPF_BURST_CMD2_FTQ_SEL_3               (3UL<<0)
        #define RXPF_BURST_CMD2_BUSY                        (1UL<<2)
        #define RXPF_BURST_CMD2_OFFSET                      (0x1ffUL<<3)
        #define RXPF_BURST_CMD2_BASE_REG_SEL                (1UL<<23)
        #define RXPF_BURST_CMD2_MOD_USAGE_CNT               (0x3UL<<24)
            #define RXPF_BURST_CMD2_MOD_USAGE_CNT_00        (0UL<<24)
            #define RXPF_BURST_CMD2_MOD_USAGE_CNT_01        (1UL<<24)
            #define RXPF_BURST_CMD2_MOD_USAGE_CNT_10        (2UL<<24)
            #define RXPF_BURST_CMD2_MOD_USAGE_CNT_11        (3UL<<24)
        #define RXPF_BURST_CMD2_PREFETCH_SIZE               (0x3UL<<26)
        #define RXPF_BURST_CMD2_NO_RAM_ACCESS               (1UL<<28)
        #define RXPF_BURST_CMD2_NO_CACHE                    (1UL<<29)
        #define RXPF_BURST_CMD2_CROSS_BOUNDARY              (1UL<<30)

    u32_t rxpf_burst_cmd3;
        #define RXPF_BURST_CMD3_FTQ_SEL                     (0x3UL<<0)
            #define RXPF_BURST_CMD3_FTQ_SEL_0               (0UL<<0)
            #define RXPF_BURST_CMD3_FTQ_SEL_1               (1UL<<0)
            #define RXPF_BURST_CMD3_FTQ_SEL_2               (2UL<<0)
            #define RXPF_BURST_CMD3_FTQ_SEL_3               (3UL<<0)
        #define RXPF_BURST_CMD3_BUSY                        (1UL<<2)
        #define RXPF_BURST_CMD3_OFFSET                      (0x1ffUL<<3)
        #define RXPF_BURST_CMD3_BASE_REG_SEL                (1UL<<23)
        #define RXPF_BURST_CMD3_MOD_USAGE_CNT               (0x3UL<<24)
            #define RXPF_BURST_CMD3_MOD_USAGE_CNT_00        (0UL<<24)
            #define RXPF_BURST_CMD3_MOD_USAGE_CNT_01        (1UL<<24)
            #define RXPF_BURST_CMD3_MOD_USAGE_CNT_10        (2UL<<24)
            #define RXPF_BURST_CMD3_MOD_USAGE_CNT_11        (3UL<<24)
        #define RXPF_BURST_CMD3_PREFETCH_SIZE               (0x3UL<<26)
        #define RXPF_BURST_CMD3_NO_RAM_ACCESS               (1UL<<28)
        #define RXPF_BURST_CMD3_NO_CACHE                    (1UL<<29)
        #define RXPF_BURST_CMD3_CROSS_BOUNDARY              (1UL<<30)

    u32_t rxpf_burst_cmd4;
        #define RXPF_BURST_CMD4_FTQ_SEL                     (0x3UL<<0)
            #define RXPF_BURST_CMD4_FTQ_SEL_0               (0UL<<0)
            #define RXPF_BURST_CMD4_FTQ_SEL_1               (1UL<<0)
            #define RXPF_BURST_CMD4_FTQ_SEL_2               (2UL<<0)
            #define RXPF_BURST_CMD4_FTQ_SEL_3               (3UL<<0)
        #define RXPF_BURST_CMD4_BUSY                        (1UL<<2)
        #define RXPF_BURST_CMD4_OFFSET                      (0x1ffUL<<3)
        #define RXPF_BURST_CMD4_BASE_REG_SEL                (1UL<<23)
        #define RXPF_BURST_CMD4_MOD_USAGE_CNT               (0x3UL<<24)
            #define RXPF_BURST_CMD4_MOD_USAGE_CNT_00        (0UL<<24)
            #define RXPF_BURST_CMD4_MOD_USAGE_CNT_01        (1UL<<24)
            #define RXPF_BURST_CMD4_MOD_USAGE_CNT_10        (2UL<<24)
            #define RXPF_BURST_CMD4_MOD_USAGE_CNT_11        (3UL<<24)
        #define RXPF_BURST_CMD4_PREFETCH_SIZE               (0x3UL<<26)
        #define RXPF_BURST_CMD4_NO_RAM_ACCESS               (1UL<<28)
        #define RXPF_BURST_CMD4_NO_CACHE                    (1UL<<29)
        #define RXPF_BURST_CMD4_CROSS_BOUNDARY              (1UL<<30)

    u32_t rxpf_burst_cmd5;
        #define RXPF_BURST_CMD5_FTQ_SEL                     (0x3UL<<0)
            #define RXPF_BURST_CMD5_FTQ_SEL_0               (0UL<<0)
            #define RXPF_BURST_CMD5_FTQ_SEL_1               (1UL<<0)
            #define RXPF_BURST_CMD5_FTQ_SEL_2               (2UL<<0)
            #define RXPF_BURST_CMD5_FTQ_SEL_3               (3UL<<0)
        #define RXPF_BURST_CMD5_BUSY                        (1UL<<2)
        #define RXPF_BURST_CMD5_OFFSET                      (0x1ffUL<<3)
        #define RXPF_BURST_CMD5_BASE_REG_SEL                (1UL<<23)
        #define RXPF_BURST_CMD5_MOD_USAGE_CNT               (0x3UL<<24)
            #define RXPF_BURST_CMD5_MOD_USAGE_CNT_00        (0UL<<24)
            #define RXPF_BURST_CMD5_MOD_USAGE_CNT_01        (1UL<<24)
            #define RXPF_BURST_CMD5_MOD_USAGE_CNT_10        (2UL<<24)
            #define RXPF_BURST_CMD5_MOD_USAGE_CNT_11        (3UL<<24)
        #define RXPF_BURST_CMD5_PREFETCH_SIZE               (0x3UL<<26)
        #define RXPF_BURST_CMD5_NO_RAM_ACCESS               (1UL<<28)
        #define RXPF_BURST_CMD5_NO_CACHE                    (1UL<<29)
        #define RXPF_BURST_CMD5_CROSS_BOUNDARY              (1UL<<30)

    u32_t rxpf_burst_cmd6;
        #define RXPF_BURST_CMD6_FTQ_SEL                     (0x3UL<<0)
            #define RXPF_BURST_CMD6_FTQ_SEL_0               (0UL<<0)
            #define RXPF_BURST_CMD6_FTQ_SEL_1               (1UL<<0)
            #define RXPF_BURST_CMD6_FTQ_SEL_2               (2UL<<0)
            #define RXPF_BURST_CMD6_FTQ_SEL_3               (3UL<<0)
        #define RXPF_BURST_CMD6_BUSY                        (1UL<<2)
        #define RXPF_BURST_CMD6_OFFSET                      (0x1ffUL<<3)
        #define RXPF_BURST_CMD6_BASE_REG_SEL                (1UL<<23)
        #define RXPF_BURST_CMD6_MOD_USAGE_CNT               (0x3UL<<24)
            #define RXPF_BURST_CMD6_MOD_USAGE_CNT_00        (0UL<<24)
            #define RXPF_BURST_CMD6_MOD_USAGE_CNT_01        (1UL<<24)
            #define RXPF_BURST_CMD6_MOD_USAGE_CNT_10        (2UL<<24)
            #define RXPF_BURST_CMD6_MOD_USAGE_CNT_11        (3UL<<24)
        #define RXPF_BURST_CMD6_PREFETCH_SIZE               (0x3UL<<26)
        #define RXPF_BURST_CMD6_NO_RAM_ACCESS               (1UL<<28)
        #define RXPF_BURST_CMD6_NO_CACHE                    (1UL<<29)
        #define RXPF_BURST_CMD6_CROSS_BOUNDARY              (1UL<<30)

    u32_t rxpf_burst_cmd7;
        #define RXPF_BURST_CMD7_FTQ_SEL                     (0x3UL<<0)
            #define RXPF_BURST_CMD7_FTQ_SEL_0               (0UL<<0)
            #define RXPF_BURST_CMD7_FTQ_SEL_1               (1UL<<0)
            #define RXPF_BURST_CMD7_FTQ_SEL_2               (2UL<<0)
            #define RXPF_BURST_CMD7_FTQ_SEL_3               (3UL<<0)
        #define RXPF_BURST_CMD7_BUSY                        (1UL<<2)
        #define RXPF_BURST_CMD7_OFFSET                      (0x1ffUL<<3)
        #define RXPF_BURST_CMD7_BASE_REG_SEL                (1UL<<23)
        #define RXPF_BURST_CMD7_MOD_USAGE_CNT               (0x3UL<<24)
            #define RXPF_BURST_CMD7_MOD_USAGE_CNT_00        (0UL<<24)
            #define RXPF_BURST_CMD7_MOD_USAGE_CNT_01        (1UL<<24)
            #define RXPF_BURST_CMD7_MOD_USAGE_CNT_10        (2UL<<24)
            #define RXPF_BURST_CMD7_MOD_USAGE_CNT_11        (3UL<<24)
        #define RXPF_BURST_CMD7_PREFETCH_SIZE               (0x3UL<<26)
        #define RXPF_BURST_CMD7_NO_RAM_ACCESS               (1UL<<28)
        #define RXPF_BURST_CMD7_NO_CACHE                    (1UL<<29)
        #define RXPF_BURST_CMD7_CROSS_BOUNDARY              (1UL<<30)

    u32_t rxpf_ctx_cmd;
        #define RXPF_CTX_CMD_NUM_BLOCKS                     (0x3UL<<0)
        #define RXPF_CTX_CMD_OFFSET                         (0x1ffUL<<3)
        #define RXPF_CTX_CMD_CID_VALUE                      (0x3fffUL<<12)
        #define RXPF_CTX_CMD_PREFETCH_SIZE                  (0x3UL<<26)
        #define RXPF_CTX_CMD_MOD_USAGE_CNT                  (0x3UL<<28)
            #define RXPF_CTX_CMD_MOD_USAGE_CNT_00           (0UL<<28)
            #define RXPF_CTX_CMD_MOD_USAGE_CNT_01           (1UL<<28)
            #define RXPF_CTX_CMD_MOD_USAGE_CNT_10           (2UL<<28)
            #define RXPF_CTX_CMD_MOD_USAGE_CNT_11           (3UL<<28)
    u32_t unused_23[51];

    u32_t rxpf_burst_data0[16];
    u32_t rxpf_burst_data1[16];
    u32_t rxpf_burst_data2[16];
    u32_t rxpf_burst_data3[16];
    u32_t rxpf_burst_data4[16];
    u32_t rxpf_burst_data5[16];
    u32_t rxpf_burst_data6[16];
    u32_t rxpf_burst_data7[16];
    u32_t unused_24[64];
    u32_t rxpf_rbuf_burst_data[32];
    u32_t unused_25[3296];
    u32_t rxpf_rx_mbuf[4096];
    u32_t unused_26[57344];
    u32_t rxpf_ctx_window5[32768];
    u32_t rxpf_ctx_window6[32768];
    u32_t rxpf_ctx_window1[32768];
    u32_t rxpf_ctx_window2[32768];
    u32_t rxpf_ctx_window3[32768];
    u32_t rxpf_ctx_window4[32768];
} rxp_fio_xi_t;

             
/*
 *  com_fio definition
 *  offset: 0x80000000
 */
typedef struct com_fio
{
    u32_t comf_events_bits;
        #define COMF_EVENTS_BITS_GPIO0                      (1UL<<15)
        #define COMF_EVENTS_BITS_GPIO1                      (1UL<<16)
        #define COMF_EVENTS_BITS_GPIO2                      (1UL<<17)
        #define COMF_EVENTS_BITS_GPIO3                      (1UL<<18)

    u32_t comf_attentions_bits;
        #define COMF_ATTENTIONS_BITS_EPB_ERROR              (1UL<<30)

    u32_t comf_event_enable;
    u32_t comf_attention_enable;
    u32_t comf_fio_status;

    u32_t comf_mult_result;
    u32_t comf_mult_a;

    u32_t comf_mult_b;

    u32_t comf_ctx_window_cid1;

    u32_t comf_ctx_window_cid2;
        #define COMF_CTX_WINDOW_CID2_CTX_WINDOW_CID2_VALUE  (0x3fffUL<<7)

    u32_t comf_ctx_window_cid3;
        #define COMF_CTX_WINDOW_CID3_CTX_WINDOW_CID3_VALUE  (0x3fffUL<<7)

    u32_t comf_ctx_window_cid4;
        #define COMF_CTX_WINDOW_CID4_CTX_WINDOW_CID4_VALUE  (0x3fffUL<<7)

    u32_t comf_dma_len;
        #define COMF_DMA_LEN_BYTE_SWAP                      (1UL<<24)

    u32_t comf_dma_status;
        #define COMF_DMA_STATUS_WRITE_MASTER_ABORT          (1UL<<3)
        #define COMF_DMA_STATUS_READ_MASTER_ABORT           (1UL<<20)

    u32_t comf_dma_addr_h;
    u32_t comf_dma_addr_l;
    u32_t comf_com_hc_inc_stat[12];
    u32_t comf_free_counter_value;
    u32_t comf_timer_retran_value;
    u16_t comf_timer_rxpush_value;
    u16_t comf_timer_delayack_value;
    u16_t comf_timer_keepalive_value;
    u16_t comf_timer_nagle_value;
    u16_t comf_com_hc_rx_quick_cons_idx[16];
    u16_t comf_com_hc_cmd;
        #define COMF_COM_HC_CMD_COALESCE_NOW                (1<<0)

    u16_t comf_com_hc_prod_idx;
    u32_t comf_rbdc_flush;

    u32_t comf_com_rbuf_cluster;
    u32_t unused_0[17];

    u32_t comf_msi_req_value;
    u32_t comf_msi_status;
        #define COMF_MSI_STATUS_BUSY                        (1UL<<31)

    u32_t comf_msi_addr_h;
    u32_t comf_msi_addr_l;
    u32_t comf_comq_cid;
    u32_t comf_comq_mbuf_cluster;
    u16_t comf_comq_operand_flags;
    u8_t comf_comq_knum;
    u8_t comf_comq_opcode;
    u16_t comf_comq_operand16_2;
    u16_t comf_comq_operand16_3;
    u16_t comf_comq_operand16_4;
    u16_t comf_comq_operand16_5;
    u16_t comf_comq_operand16_6;
    u16_t comf_comq_operand16_7;
    u32_t comf_comq_operand32_2;
    u32_t comf_comq_operand32_3;
    u32_t comf_comq_operand32_4;
    u8_t comf_comq_rdma_action;
    u8_t unused_1;
    u16_t unused_2;
    u32_t unused_3[4];
    u32_t comf_comq_ftq_cmd;
    u32_t unused_4;

    u32_t comf_comtq_cid;
    u32_t comf_comtq_val;
    u8_t comf_comtq_type;
    u8_t unused_5;
    u16_t unused_6;
    u32_t unused_7[11];
    u32_t comf_comtq_ftq_cmd;
    u32_t unused_8;

    u32_t comf_comxq_cid;
    u16_t comf_comxq_flags;
    u16_t unused_9;

    u32_t comf_comxq_snd_next;
    u32_t unused_10[11];
    u32_t comf_comxq_ftq_cmd;
    u32_t unused_11;

    u32_t comf_tschq_cid;
    u8_t comf_tschq_flags;
    u8_t unused_12;
    u16_t unused_13;
    u32_t unused_14[12];

    u32_t comf_tschq_ftq_cmd;
    u32_t unused_15;

    u32_t comf_rv2ptq_cid;
    u32_t unused_16[13];
    u32_t comf_rv2ptq_ftq_cmd;
    u32_t unused_17;

    u32_t comf_csq_cid;
    u8_t comf_csq_flags;
    u8_t unused_18;
    u16_t unused_19;
    u32_t unused_20[12];

    u32_t comf_csq_ftq_cmd;
    u32_t unused_21;

    u32_t comf_mcpq_bits_status;
    u16_t comf_mcpq_pkt_len;
    u16_t unused_22;
    u32_t comf_mcpq_mbuf_cluster;
    u32_t unused_23[11];
    u32_t comf_mcpq_ftq_cmd;
    u32_t unused_24[81];

    u32_t comf_dma_data[128];
    u32_t unused_25[128];
    u32_t comf_burst_base0;

    u32_t comf_burst_base1;

    u32_t comf_burst_base2;

    u32_t comf_burst_base3;

    u32_t comf_burst_cmd0;

    u32_t comf_burst_cmd1;

    u32_t comf_burst_cmd2;

    u32_t comf_burst_cmd3;
    u32_t unused_26[56];

    u32_t comf_burst_data0[16];
    u32_t comf_burst_data1[16];
    u32_t comf_burst_data2[16];
    u32_t comf_burst_data3[16];
    u32_t unused_27[3456];
    u32_t comf_com_mbuf[4096];
    u32_t unused_28[122880];
    u32_t comf_ctx_window1[32768];
    u32_t comf_ctx_window2[32768];
    u32_t comf_ctx_window3[32768];
    u32_t comf_ctx_window4[32768];
} com_fio_t;


/*
 *  com_fio definition
 *  offset: 0x80000000
 */
typedef struct com_fio_xi
{
    u32_t comf_events_bits;
        #define COMF_EVENTS_BITS_FTQ0_VALID                 (1UL<<0)
        #define COMF_EVENTS_BITS_FTQ1_VALID                 (1UL<<1)
        #define COMF_EVENTS_BITS_FTQ2_VALID                 (1UL<<2)
        #define COMF_EVENTS_BITS_SCANNER_DONE               (1UL<<3)
        #define COMF_EVENTS_BITS_DMA_WR_DONE                (1UL<<4)
        #define COMF_EVENTS_BITS_DMA_RD_DONE                (1UL<<5)
        #define COMF_EVENTS_BITS_CRACKER_DONE               (1UL<<6)
        #define COMF_EVENTS_BITS_MULTIPLY_DONE              (1UL<<7)
        #define COMF_EVENTS_BITS_EXP_ROM                    (1UL<<8)
        #define COMF_EVENTS_BITS_VPD                        (1UL<<9)
        #define COMF_EVENTS_BITS_FLASH                      (1UL<<10)
        #define COMF_EVENTS_BITS_SMB0                       (1UL<<11)
        #define COMF_EVENTS_BITS_RESERVED0                  (1UL<<12)
        #define COMF_EVENTS_BITS_RESERVED1                  (1UL<<13)
        #define COMF_EVENTS_BITS_RESERVED2                  (1UL<<14)
        #define COMF_EVENTS_BITS_GPIO                       (1UL<<15)
        #define COMF_EVENTS_BITS_SW_TMR_1                   (1UL<<19)
        #define COMF_EVENTS_BITS_SW_TMR_2                   (1UL<<20)
        #define COMF_EVENTS_BITS_SW_TMR_3                   (1UL<<21)
        #define COMF_EVENTS_BITS_SW_TMR_4                   (1UL<<22)
        #define COMF_EVENTS_BITS_LINK_CHANGED               (1UL<<23)
        #define COMF_EVENTS_BITS_MI_INT                     (1UL<<25)
        #define COMF_EVENTS_BITS_MI_COMPLETE                (1UL<<26)
        #define COMF_EVENTS_BITS_MAIN_PWR_INT               (1UL<<27)
        #define COMF_EVENTS_BITS_NOT_ENABLED                (1UL<<30)
        #define COMF_EVENTS_BITS_ATTENTIONS_VALID           (1UL<<31)

    u32_t comf_attentions_bits;
        #define COMF_ATTENTIONS_BITS_LINK_STATE             (1UL<<0)
        #define COMF_ATTENTIONS_BITS_TX_SCHEDULER_ABORT     (1UL<<1)
        #define COMF_ATTENTIONS_BITS_TX_BD_READ_ABORT       (1UL<<2)
        #define COMF_ATTENTIONS_BITS_TX_BD_CACHE_ABORT      (1UL<<3)
        #define COMF_ATTENTIONS_BITS_TX_PROCESSOR_ABORT     (1UL<<4)
        #define COMF_ATTENTIONS_BITS_TX_DMA_ABORT           (1UL<<5)
        #define COMF_ATTENTIONS_BITS_TX_PATCHUP_ABORT       (1UL<<6)
        #define COMF_ATTENTIONS_BITS_TX_ASSEMBLER_ABORT     (1UL<<7)
        #define COMF_ATTENTIONS_BITS_RX_PARSER_MAC_ABORT    (1UL<<8)
        #define COMF_ATTENTIONS_BITS_RX_PARSER_CATCHUP_ABORT  (1UL<<9)
        #define COMF_ATTENTIONS_BITS_RX_MBUF_ABORT          (1UL<<10)
        #define COMF_ATTENTIONS_BITS_RX_LOOKUP_ABORT        (1UL<<11)
        #define COMF_ATTENTIONS_BITS_RX_PROCESSOR_ABORT     (1UL<<12)
        #define COMF_ATTENTIONS_BITS_RX_V2P_ABORT           (1UL<<13)
        #define COMF_ATTENTIONS_BITS_RX_BD_CACHE_ABORT      (1UL<<14)
        #define COMF_ATTENTIONS_BITS_RX_DMA_ABORT           (1UL<<15)
        #define COMF_ATTENTIONS_BITS_COMPLETION_ABORT       (1UL<<16)
        #define COMF_ATTENTIONS_BITS_HOST_COALESCE_ABORT    (1UL<<17)
        #define COMF_ATTENTIONS_BITS_MAILBOX_QUEUE_ABORT    (1UL<<18)
        #define COMF_ATTENTIONS_BITS_CONTEXT_ABORT          (1UL<<19)
        #define COMF_ATTENTIONS_BITS_CMD_SCHEDULER_ABORT    (1UL<<20)
        #define COMF_ATTENTIONS_BITS_CMD_PROCESSOR_ABORT    (1UL<<21)
        #define COMF_ATTENTIONS_BITS_MGMT_PROCESSOR_ABORT   (1UL<<22)
        #define COMF_ATTENTIONS_BITS_MAC_ABORT              (1UL<<23)
        #define COMF_ATTENTIONS_BITS_TIMER_ABORT            (1UL<<24)
        #define COMF_ATTENTIONS_BITS_DMAE_ABORT             (1UL<<25)
        #define COMF_ATTENTIONS_BITS_FLSH_ABORT             (1UL<<26)
        #define COMF_ATTENTIONS_BITS_GRC_ABORT              (1UL<<27)
        #define COMF_ATTENTIONS_BITS_PARITY_ERROR           (1UL<<31)

    u32_t comf_event_enable;
    u32_t comf_attention_enable;
    u32_t comf_fio_status;
        #define COMF_FIO_STATUS_ENABLED                     (1UL<<0)
        #define COMF_FIO_STATUS_FORCE_ENA                   (1UL<<1)

    u32_t comf_mult_result;
    u32_t comf_mult_a;
        #define COMF_MULT_A_VALUE                           (0xffffUL<<0)

    u32_t comf_mult_b;
        #define COMF_MULT_B_VALUE                           (0xffffUL<<0)

    u32_t comf_ctx_window_cid1;
        #define COMF_CTX_WINDOW_CID1_LOCK_TYPE              (0x7UL<<0)
            #define COMF_CTX_WINDOW_CID1_LOCK_TYPE_VOID     (0UL<<0)
            #define COMF_CTX_WINDOW_CID1_LOCK_TYPE_PROTOCOL  (1UL<<0)
            #define COMF_CTX_WINDOW_CID1_LOCK_TYPE_TX       (2UL<<0)
            #define COMF_CTX_WINDOW_CID1_LOCK_TYPE_TIMER    (4UL<<0)
            #define COMF_CTX_WINDOW_CID1_LOCK_TYPE_COMPLETE  (7UL<<0)
        #define COMF_CTX_WINDOW_CID1_VALUE                  (0x3fffUL<<7)
        #define COMF_CTX_WINDOW_CID1_MOD_USAGE_CNT          (0x3UL<<24)
            #define COMF_CTX_WINDOW_CID1_MOD_USAGE_CNT_00   (0UL<<24)
            #define COMF_CTX_WINDOW_CID1_MOD_USAGE_CNT_01   (1UL<<24)
            #define COMF_CTX_WINDOW_CID1_MOD_USAGE_CNT_10   (2UL<<24)
            #define COMF_CTX_WINDOW_CID1_MOD_USAGE_CNT_11   (3UL<<24)
        #define COMF_CTX_WINDOW_CID1_LOCK_GRANTED           (1UL<<26)
        #define COMF_CTX_WINDOW_CID1_LOCK_MODE              (0x3UL<<27)
            #define COMF_CTX_WINDOW_CID1_LOCK_MODE_UNLOCK   (0UL<<27)
            #define COMF_CTX_WINDOW_CID1_LOCK_MODE_IMMEDIATE  (1UL<<27)
            #define COMF_CTX_WINDOW_CID1_LOCK_MODE_SURE     (2UL<<27)
        #define COMF_CTX_WINDOW_CID1_NO_EXT_ACC             (1UL<<29)
        #define COMF_CTX_WINDOW_CID1_LOCK_STATUS            (1UL<<30)
        #define COMF_CTX_WINDOW_CID1_LOCK_REQ               (1UL<<31)

    u32_t comf_ctx_window_cid2;
        #define COMF_CTX_WINDOW_CID2_LOCK_TYPE              (0x7UL<<0)
            #define COMF_CTX_WINDOW_CID2_LOCK_TYPE_VOID     (0UL<<0)
            #define COMF_CTX_WINDOW_CID2_LOCK_TYPE_PROTOCOL  (1UL<<0)
            #define COMF_CTX_WINDOW_CID2_LOCK_TYPE_TX       (2UL<<0)
            #define COMF_CTX_WINDOW_CID2_LOCK_TYPE_TIMER    (4UL<<0)
            #define COMF_CTX_WINDOW_CID2_LOCK_TYPE_COMPLETE  (7UL<<0)
        #define COMF_CTX_WINDOW_CID2_VALUE                  (0x3fffUL<<7)
        #define COMF_CTX_WINDOW_CID2_MOD_USAGE_CNT          (0x3UL<<24)
            #define COMF_CTX_WINDOW_CID2_MOD_USAGE_CNT_00   (0UL<<24)
            #define COMF_CTX_WINDOW_CID2_MOD_USAGE_CNT_01   (1UL<<24)
            #define COMF_CTX_WINDOW_CID2_MOD_USAGE_CNT_10   (2UL<<24)
            #define COMF_CTX_WINDOW_CID2_MOD_USAGE_CNT_11   (3UL<<24)
        #define COMF_CTX_WINDOW_CID2_LOCK_GRANTED           (1UL<<26)
        #define COMF_CTX_WINDOW_CID2_LOCK_MODE              (0x3UL<<27)
            #define COMF_CTX_WINDOW_CID2_LOCK_MODE_UNLOCK   (0UL<<27)
            #define COMF_CTX_WINDOW_CID2_LOCK_MODE_IMMEDIATE  (1UL<<27)
            #define COMF_CTX_WINDOW_CID2_LOCK_MODE_SURE     (2UL<<27)
        #define COMF_CTX_WINDOW_CID2_NO_EXT_ACC             (1UL<<29)
        #define COMF_CTX_WINDOW_CID2_LOCK_STATUS            (1UL<<30)
        #define COMF_CTX_WINDOW_CID2_LOCK_REQ               (1UL<<31)

    u32_t comf_ctx_window_cid3;
        #define COMF_CTX_WINDOW_CID3_LOCK_TYPE              (0x7UL<<0)
            #define COMF_CTX_WINDOW_CID3_LOCK_TYPE_VOID     (0UL<<0)
            #define COMF_CTX_WINDOW_CID3_LOCK_TYPE_PROTOCOL  (1UL<<0)
            #define COMF_CTX_WINDOW_CID3_LOCK_TYPE_TX       (2UL<<0)
            #define COMF_CTX_WINDOW_CID3_LOCK_TYPE_TIMER    (4UL<<0)
            #define COMF_CTX_WINDOW_CID3_LOCK_TYPE_COMPLETE  (7UL<<0)
        #define COMF_CTX_WINDOW_CID3_VALUE                  (0x3fffUL<<7)
        #define COMF_CTX_WINDOW_CID3_MOD_USAGE_CNT          (0x3UL<<24)
            #define COMF_CTX_WINDOW_CID3_MOD_USAGE_CNT_00   (0UL<<24)
            #define COMF_CTX_WINDOW_CID3_MOD_USAGE_CNT_01   (1UL<<24)
            #define COMF_CTX_WINDOW_CID3_MOD_USAGE_CNT_10   (2UL<<24)
            #define COMF_CTX_WINDOW_CID3_MOD_USAGE_CNT_11   (3UL<<24)
        #define COMF_CTX_WINDOW_CID3_LOCK_GRANTED           (1UL<<26)
        #define COMF_CTX_WINDOW_CID3_LOCK_MODE              (0x3UL<<27)
            #define COMF_CTX_WINDOW_CID3_LOCK_MODE_UNLOCK   (0UL<<27)
            #define COMF_CTX_WINDOW_CID3_LOCK_MODE_IMMEDIATE  (1UL<<27)
            #define COMF_CTX_WINDOW_CID3_LOCK_MODE_SURE     (2UL<<27)
        #define COMF_CTX_WINDOW_CID3_NO_EXT_ACC             (1UL<<29)
        #define COMF_CTX_WINDOW_CID3_LOCK_STATUS            (1UL<<30)
        #define COMF_CTX_WINDOW_CID3_LOCK_REQ               (1UL<<31)

    u32_t comf_ctx_window_cid4;
        #define COMF_CTX_WINDOW_CID4_LOCK_TYPE              (0x7UL<<0)
            #define COMF_CTX_WINDOW_CID4_LOCK_TYPE_VOID     (0UL<<0)
            #define COMF_CTX_WINDOW_CID4_LOCK_TYPE_PROTOCOL  (1UL<<0)
            #define COMF_CTX_WINDOW_CID4_LOCK_TYPE_TX       (2UL<<0)
            #define COMF_CTX_WINDOW_CID4_LOCK_TYPE_TIMER    (4UL<<0)
            #define COMF_CTX_WINDOW_CID4_LOCK_TYPE_COMPLETE  (7UL<<0)
        #define COMF_CTX_WINDOW_CID4_VALUE                  (0x3fffUL<<7)
        #define COMF_CTX_WINDOW_CID4_MOD_USAGE_CNT          (0x3UL<<24)
            #define COMF_CTX_WINDOW_CID4_MOD_USAGE_CNT_00   (0UL<<24)
            #define COMF_CTX_WINDOW_CID4_MOD_USAGE_CNT_01   (1UL<<24)
            #define COMF_CTX_WINDOW_CID4_MOD_USAGE_CNT_10   (2UL<<24)
            #define COMF_CTX_WINDOW_CID4_MOD_USAGE_CNT_11   (3UL<<24)
        #define COMF_CTX_WINDOW_CID4_LOCK_GRANTED           (1UL<<26)
        #define COMF_CTX_WINDOW_CID4_LOCK_MODE              (0x3UL<<27)
            #define COMF_CTX_WINDOW_CID4_LOCK_MODE_UNLOCK   (0UL<<27)
            #define COMF_CTX_WINDOW_CID4_LOCK_MODE_IMMEDIATE  (1UL<<27)
            #define COMF_CTX_WINDOW_CID4_LOCK_MODE_SURE     (2UL<<27)
        #define COMF_CTX_WINDOW_CID4_NO_EXT_ACC             (1UL<<29)
        #define COMF_CTX_WINDOW_CID4_LOCK_STATUS            (1UL<<30)
        #define COMF_CTX_WINDOW_CID4_LOCK_REQ               (1UL<<31)

    u32_t comf_dma_len;
        #define COMF_DMA_LEN_LEN                            (0x3ffUL<<0)
        #define COMF_DMA_LEN_WRITE_START                    (1UL<<16)
        #define COMF_DMA_LEN_WRITE_STOP                     (1UL<<17)
        #define COMF_DMA_LEN_WRITE_EVENT_CLEAR              (1UL<<18)
        #define COMF_DMA_LEN_READ_START                     (1UL<<20)
        #define COMF_DMA_LEN_READ_STOP                      (1UL<<21)
        #define COMF_DMA_LEN_READ_EVENT_CLEAR               (1UL<<22)
        #define COMF_DMA_LEN_TYPE                           (0x3UL<<23)
            #define COMF_DMA_LEN_TYPE_CONFIG                (0UL<<23)
            #define COMF_DMA_LEN_TYPE_DATA                  (1UL<<23)
            #define COMF_DMA_LEN_TYPE_CONTROL               (2UL<<23)
        #define COMF_DMA_LEN_NO_SNOOP                       (1UL<<25)
        #define COMF_DMA_LEN_PRIORITY                       (1UL<<26)
        #define COMF_DMA_LEN_RELAXED_ORDERING               (1UL<<27)
        #define COMF_DMA_LEN_WRITE_RESET                    (1UL<<30)
        #define COMF_DMA_LEN_READ_RESET                     (1UL<<31)

    u32_t comf_dma_status;
        #define COMF_DMA_STATUS_WRITE_CHAN_REQ              (1UL<<0)
        #define COMF_DMA_STATUS_WRITE_ACTIVE                (1UL<<1)
        #define COMF_DMA_STATUS_WRITE_DONE                  (1UL<<2)
        #define COMF_DMA_STATUS_READ_CHAN_REQ               (1UL<<16)
        #define COMF_DMA_STATUS_READ_ACTIVE                 (1UL<<17)
        #define COMF_DMA_STATUS_READ_DONE                   (1UL<<19)
        #define COMF_DMA_STATUS_READ_CS16_ERROR             (1UL<<20)

    u32_t comf_dma_addr_h;
    u32_t comf_dma_addr_l;
    u32_t comf_com_hc_inc_stat[12];
    u32_t comf_free_counter_value;
    u32_t comf_timer_retran_value;
    u16_t comf_timer_rxpush_value;
    u16_t comf_timer_delayack_value;
    u16_t comf_timer_keepalive_value;
    u16_t comf_timer_nagle_value;
    u32_t comf_com_rx_quick_cons_idx;
        #define COMF_COM_RX_QUICK_CONS_IDX_INDEX_VAL        (0xffffUL<<0)
        #define COMF_COM_RX_QUICK_CONS_IDX_INDEX_NUM        (0xfUL<<20)
        #define COMF_COM_RX_QUICK_CONS_IDX_COALESCE_NOW     (1UL<<30)
        #define COMF_COM_RX_QUICK_CONS_IDX_REQ_N            (1UL<<31)
    u32_t unused_0[3];

    u32_t comf_ctx_window_cid5;
        #define COMF_CTX_WINDOW_CID5_LOCK_TYPE              (0x7UL<<0)
            #define COMF_CTX_WINDOW_CID5_LOCK_TYPE_VOID     (0UL<<0)
            #define COMF_CTX_WINDOW_CID5_LOCK_TYPE_PROTOCOL  (1UL<<0)
            #define COMF_CTX_WINDOW_CID5_LOCK_TYPE_TX       (2UL<<0)
            #define COMF_CTX_WINDOW_CID5_LOCK_TYPE_TIMER    (4UL<<0)
            #define COMF_CTX_WINDOW_CID5_LOCK_TYPE_COMPLETE  (7UL<<0)
        #define COMF_CTX_WINDOW_CID5_VALUE                  (0x3fffUL<<7)
        #define COMF_CTX_WINDOW_CID5_MOD_USAGE_CNT          (0x3UL<<24)
            #define COMF_CTX_WINDOW_CID5_MOD_USAGE_CNT_00   (0UL<<24)
            #define COMF_CTX_WINDOW_CID5_MOD_USAGE_CNT_01   (1UL<<24)
            #define COMF_CTX_WINDOW_CID5_MOD_USAGE_CNT_10   (2UL<<24)
            #define COMF_CTX_WINDOW_CID5_MOD_USAGE_CNT_11   (3UL<<24)
        #define COMF_CTX_WINDOW_CID5_LOCK_GRANTED           (1UL<<26)
        #define COMF_CTX_WINDOW_CID5_LOCK_MODE              (0x3UL<<27)
            #define COMF_CTX_WINDOW_CID5_LOCK_MODE_UNLOCK   (0UL<<27)
            #define COMF_CTX_WINDOW_CID5_LOCK_MODE_IMMEDIATE  (1UL<<27)
            #define COMF_CTX_WINDOW_CID5_LOCK_MODE_SURE     (2UL<<27)
        #define COMF_CTX_WINDOW_CID5_NO_EXT_ACC             (1UL<<29)
        #define COMF_CTX_WINDOW_CID5_LOCK_STATUS            (1UL<<30)
        #define COMF_CTX_WINDOW_CID5_LOCK_REQ               (1UL<<31)

    u32_t comf_ctx_window_cid6;
        #define COMF_CTX_WINDOW_CID6_LOCK_TYPE              (0x7UL<<0)
            #define COMF_CTX_WINDOW_CID6_LOCK_TYPE_VOID     (0UL<<0)
            #define COMF_CTX_WINDOW_CID6_LOCK_TYPE_PROTOCOL  (1UL<<0)
            #define COMF_CTX_WINDOW_CID6_LOCK_TYPE_TX       (2UL<<0)
            #define COMF_CTX_WINDOW_CID6_LOCK_TYPE_TIMER    (4UL<<0)
            #define COMF_CTX_WINDOW_CID6_LOCK_TYPE_COMPLETE  (7UL<<0)
        #define COMF_CTX_WINDOW_CID6_VALUE                  (0x3fffUL<<7)
        #define COMF_CTX_WINDOW_CID6_MOD_USAGE_CNT          (0x3UL<<24)
            #define COMF_CTX_WINDOW_CID6_MOD_USAGE_CNT_00   (0UL<<24)
            #define COMF_CTX_WINDOW_CID6_MOD_USAGE_CNT_01   (1UL<<24)
            #define COMF_CTX_WINDOW_CID6_MOD_USAGE_CNT_10   (2UL<<24)
            #define COMF_CTX_WINDOW_CID6_MOD_USAGE_CNT_11   (3UL<<24)
        #define COMF_CTX_WINDOW_CID6_LOCK_GRANTED           (1UL<<26)
        #define COMF_CTX_WINDOW_CID6_LOCK_MODE              (0x3UL<<27)
            #define COMF_CTX_WINDOW_CID6_LOCK_MODE_UNLOCK   (0UL<<27)
            #define COMF_CTX_WINDOW_CID6_LOCK_MODE_IMMEDIATE  (1UL<<27)
            #define COMF_CTX_WINDOW_CID6_LOCK_MODE_SURE     (2UL<<27)
        #define COMF_CTX_WINDOW_CID6_NO_EXT_ACC             (1UL<<29)
        #define COMF_CTX_WINDOW_CID6_LOCK_STATUS            (1UL<<30)
        #define COMF_CTX_WINDOW_CID6_LOCK_REQ               (1UL<<31)
    u32_t unused_1[2];

    u32_t comf_com_comp_prod_idx;
        #define COMF_COM_COMP_PROD_IDX_INDEX_VAL            (0xffffUL<<0)
        #define COMF_COM_COMP_PROD_IDX_INDEX_NUM            (0xfUL<<20)
        #define COMF_COM_COMP_PROD_IDX_COALESCE_NOW         (1UL<<30)
        #define COMF_COM_COMP_PROD_IDX_REQ_N                (1UL<<31)

    u32_t comf_rbdc_flush;
        #define COMF_RBDC_FLUSH_TYPE                        (1UL<<0)
        #define COMF_RBDC_FLUSH_CID                         (0x3fffUL<<7)

    u32_t comf_com_rbuf_cluster;
        #define COMF_COM_RBUF_CLUSTER_COUNT                 (0x7fUL<<0)
        #define COMF_COM_RBUF_CLUSTER_TAIL                  (0x1ffUL<<7)
        #define COMF_COM_RBUF_CLUSTER_HEAD                  (0x1ffUL<<16)
        #define COMF_COM_RBUF_CLUSTER_TYPE                  (1UL<<25)
        #define COMF_COM_RBUF_CLUSTER_FREE                  (1UL<<31)
    u32_t unused_2[21];

    const u32_t comf_comq_cid;
    const u32_t comf_comq_mbuf_cluster;
    const u16_t comf_comq_operand_flags;
    const u8_t comf_comq_knum;
    const u8_t comf_comq_opcode;
    const u16_t comf_comq_operand16_2;
    const u16_t comf_comq_operand16_3;
    const u16_t comf_comq_operand16_4;
    const u16_t comf_comq_operand16_5;
    const u16_t comf_comq_operand16_6;
    const u16_t comf_comq_operand16_7;
    const u32_t comf_comq_operand32_2;
    const u32_t comf_comq_operand32_3;
    const u32_t comf_comq_operand32_4;
    const u8_t comf_comq_rdma_action;
    const u8_t comf_comq_cs16_pkt_len;
    const u16_t comf_comq_cs16;
    const u32_t unused_3[4];
    u32_t comf_comq_ftq_cmd;
        #define COMF_COMQ_FTQ_CMD_POP                       (1UL<<30)
    const u32_t unused_4;

    const u32_t comf_comtq_cid;
    const u32_t comf_comtq_val;
    const u8_t comf_comtq_type;
    const u8_t comf_comtq_rsvd_future;
    const u16_t unused_5;
    const u32_t unused_6[11];
    u32_t comf_comtq_ftq_cmd;
        #define COMF_COMTQ_FTQ_CMD_POP                      (1UL<<30)
    const u32_t unused_7;
    const u32_t comf_comxq_cid;
    const u16_t comf_comxq_flags;
        #define COMF_COMXQ_FLAGS_COMPLETE                   (1<<8)
        #define COMF_COMXQ_FLAGS_RETRAN                     (1<<9)
    const u16_t unused_8;
    const u32_t comf_comxq_snd_next;
    const u8_t comf_comxq_new_flags;
    const u8_t unused_9;
    const u16_t unused_10;
    const u32_t unused_11[10];
    u32_t comf_comxq_ftq_cmd;
        #define COMF_COMXQ_FTQ_CMD_POP                      (1UL<<30)
    u32_t unused_12;

    u32_t comf_tschq_cid;
    u8_t comf_tschq_flags;
        #define COMF_TSCHQ_FLAGS_DELIST                     (1<<0)
        #define COMF_TSCHQ_FLAGS_NORMAL                     (1<<1)
        #define COMF_TSCHQ_FLAGS_HIGH                       (1<<2)

    u8_t comf_tschq_rsvd_future;
    u16_t unused_13;
    u32_t unused_14[12];
    u32_t comf_tschq_ftq_cmd;
        #define COMF_TSCHQ_FTQ_CMD_ADD_INTERVEN             (1UL<<27)
        #define COMF_TSCHQ_FTQ_CMD_ADD_DATA                 (1UL<<28)
        #define COMF_TSCHQ_FTQ_CMD_BUSY                     (1UL<<31)
    u32_t unused_15;

    u32_t comf_rv2ptq_cid;
    u32_t unused_16[13];
    u32_t comf_rv2ptq_ftq_cmd;
        #define COMF_RV2PTQ_FTQ_CMD_ADD_INTERVEN            (1UL<<27)
        #define COMF_RV2PTQ_FTQ_CMD_ADD_DATA                (1UL<<28)
        #define COMF_RV2PTQ_FTQ_CMD_BUSY                    (1UL<<31)
    u32_t unused_17;

    u32_t comf_csq_cid;
    u8_t comf_csq_flags;
        #define COMF_CSQ_FLAGS_DELIST                       (1<<0)
        #define COMF_CSQ_FLAGS_NORMAL                       (1<<1)
        #define COMF_CSQ_FLAGS_HIGH                         (1<<2)
    u8_t unused_18;
    u16_t unused_19;
    u32_t unused_20[12];

    u32_t comf_csq_ftq_cmd;
        #define COMF_CSQ_FTQ_CMD_ADD_INTERVEN               (1UL<<27)
        #define COMF_CSQ_FTQ_CMD_ADD_DATA                   (1UL<<28)
        #define COMF_CSQ_FTQ_CMD_BUSY                       (1UL<<31)
    u32_t unused_21;

    u32_t comf_mcpq_bits_status;
    u16_t comf_mcpq_pkt_len;
    u16_t comf_mcpq_vlan_tag;
    u32_t comf_mcpq_mbuf_cluster;
    u32_t comf_mcpq_rx_errors;
    u16_t comf_mcpq_ext_status;
    u16_t unused_23;
    u32_t unused_24[9];
    u32_t comf_mcpq_ftq_cmd;
        #define COMF_MCPQ_FTQ_CMD_ADD_INTERVEN              (1UL<<27)
        #define COMF_MCPQ_FTQ_CMD_ADD_DATA                  (1UL<<28)
        #define COMF_MCPQ_FTQ_CMD_BUSY                      (1UL<<31)
    u32_t unused_25[81];

    u32_t comf_dma_data[128];
    u32_t unused_26[128];
    u32_t comf_burst_base0;
        #define COMF_BURST_BASE0_BASE_VAL0                  (0x3fffUL<<7)

    u32_t comf_burst_base1;
        #define COMF_BURST_BASE1_BASE_VAL1                  (0x3fffUL<<7)

    u32_t comf_burst_base2;
        #define COMF_BURST_BASE2_BASE_VAL2                  (0x3fffUL<<7)

    u32_t comf_burst_base3;
        #define COMF_BURST_BASE3_BASE_VAL3                  (0x3fffUL<<7)

    u32_t comf_burst_cmd0;
        #define COMF_BURST_CMD0_FTQ_SEL                     (0x3UL<<0)
            #define COMF_BURST_CMD0_FTQ_SEL_0               (0UL<<0)
            #define COMF_BURST_CMD0_FTQ_SEL_1               (1UL<<0)
            #define COMF_BURST_CMD0_FTQ_SEL_2               (2UL<<0)
            #define COMF_BURST_CMD0_FTQ_SEL_3               (3UL<<0)
        #define COMF_BURST_CMD0_BUSY                        (1UL<<2)
        #define COMF_BURST_CMD0_OFFSET                      (0x1ffUL<<3)
        #define COMF_BURST_CMD0_BASE_REG_SEL                (1UL<<23)
        #define COMF_BURST_CMD0_MOD_USAGE_CNT               (0x3UL<<24)
            #define COMF_BURST_CMD0_MOD_USAGE_CNT_00        (0UL<<24)
            #define COMF_BURST_CMD0_MOD_USAGE_CNT_01        (1UL<<24)
            #define COMF_BURST_CMD0_MOD_USAGE_CNT_10        (2UL<<24)
            #define COMF_BURST_CMD0_MOD_USAGE_CNT_11        (3UL<<24)
        #define COMF_BURST_CMD0_PREFETCH_SIZE               (0x3UL<<26)
        #define COMF_BURST_CMD0_NO_RAM_ACCESS               (1UL<<28)
        #define COMF_BURST_CMD0_NO_CACHE                    (1UL<<29)
        #define COMF_BURST_CMD0_CROSS_BOUNDARY              (1UL<<30)

    u32_t comf_burst_cmd1;
        #define COMF_BURST_CMD1_FTQ_SEL                     (0x3UL<<0)
            #define COMF_BURST_CMD1_FTQ_SEL_0               (0UL<<0)
            #define COMF_BURST_CMD1_FTQ_SEL_1               (1UL<<0)
            #define COMF_BURST_CMD1_FTQ_SEL_2               (2UL<<0)
            #define COMF_BURST_CMD1_FTQ_SEL_3               (3UL<<0)
        #define COMF_BURST_CMD1_BUSY                        (1UL<<2)
        #define COMF_BURST_CMD1_OFFSET                      (0x1ffUL<<3)
        #define COMF_BURST_CMD1_BASE_REG_SEL                (1UL<<23)
        #define COMF_BURST_CMD1_MOD_USAGE_CNT               (0x3UL<<24)
            #define COMF_BURST_CMD1_MOD_USAGE_CNT_00        (0UL<<24)
            #define COMF_BURST_CMD1_MOD_USAGE_CNT_01        (1UL<<24)
            #define COMF_BURST_CMD1_MOD_USAGE_CNT_10        (2UL<<24)
            #define COMF_BURST_CMD1_MOD_USAGE_CNT_11        (3UL<<24)
        #define COMF_BURST_CMD1_PREFETCH_SIZE               (0x3UL<<26)
        #define COMF_BURST_CMD1_NO_RAM_ACCESS               (1UL<<28)
        #define COMF_BURST_CMD1_NO_CACHE                    (1UL<<29)
        #define COMF_BURST_CMD1_CROSS_BOUNDARY              (1UL<<30)

    u32_t comf_burst_cmd2;
        #define COMF_BURST_CMD2_FTQ_SEL                     (0x3UL<<0)
            #define COMF_BURST_CMD2_FTQ_SEL_0               (0UL<<0)
            #define COMF_BURST_CMD2_FTQ_SEL_1               (1UL<<0)
            #define COMF_BURST_CMD2_FTQ_SEL_2               (2UL<<0)
            #define COMF_BURST_CMD2_FTQ_SEL_3               (3UL<<0)
        #define COMF_BURST_CMD2_BUSY                        (1UL<<2)
        #define COMF_BURST_CMD2_OFFSET                      (0x1ffUL<<3)
        #define COMF_BURST_CMD2_BASE_REG_SEL                (1UL<<23)
        #define COMF_BURST_CMD2_MOD_USAGE_CNT               (0x3UL<<24)
            #define COMF_BURST_CMD2_MOD_USAGE_CNT_00        (0UL<<24)
            #define COMF_BURST_CMD2_MOD_USAGE_CNT_01        (1UL<<24)
            #define COMF_BURST_CMD2_MOD_USAGE_CNT_10        (2UL<<24)
            #define COMF_BURST_CMD2_MOD_USAGE_CNT_11        (3UL<<24)
        #define COMF_BURST_CMD2_PREFETCH_SIZE               (0x3UL<<26)
        #define COMF_BURST_CMD2_NO_RAM_ACCESS               (1UL<<28)
        #define COMF_BURST_CMD2_NO_CACHE                    (1UL<<29)
        #define COMF_BURST_CMD2_CROSS_BOUNDARY              (1UL<<30)

    u32_t comf_burst_cmd3;
        #define COMF_BURST_CMD3_FTQ_SEL                     (0x3UL<<0)
            #define COMF_BURST_CMD3_FTQ_SEL_0               (0UL<<0)
            #define COMF_BURST_CMD3_FTQ_SEL_1               (1UL<<0)
            #define COMF_BURST_CMD3_FTQ_SEL_2               (2UL<<0)
            #define COMF_BURST_CMD3_FTQ_SEL_3               (3UL<<0)
        #define COMF_BURST_CMD3_BUSY                        (1UL<<2)
        #define COMF_BURST_CMD3_OFFSET                      (0x1ffUL<<3)
        #define COMF_BURST_CMD3_BASE_REG_SEL                (1UL<<23)
        #define COMF_BURST_CMD3_MOD_USAGE_CNT               (0x3UL<<24)
            #define COMF_BURST_CMD3_MOD_USAGE_CNT_00        (0UL<<24)
            #define COMF_BURST_CMD3_MOD_USAGE_CNT_01        (1UL<<24)
            #define COMF_BURST_CMD3_MOD_USAGE_CNT_10        (2UL<<24)
            #define COMF_BURST_CMD3_MOD_USAGE_CNT_11        (3UL<<24)
        #define COMF_BURST_CMD3_PREFETCH_SIZE               (0x3UL<<26)
        #define COMF_BURST_CMD3_NO_RAM_ACCESS               (1UL<<28)
        #define COMF_BURST_CMD3_NO_CACHE                    (1UL<<29)
        #define COMF_BURST_CMD3_CROSS_BOUNDARY              (1UL<<30)
    u32_t unused_27[4];

    u32_t comf_ctx_cmd;
        #define COMF_CTX_CMD_NUM_BLOCKS                     (0x3UL<<0)
        #define COMF_CTX_CMD_OFFSET                         (0x1ffUL<<3)
        #define COMF_CTX_CMD_CID_VALUE                      (0x3fffUL<<12)
        #define COMF_CTX_CMD_PREFETCH_SIZE                  (0x3UL<<26)
        #define COMF_CTX_CMD_MOD_USAGE_CNT                  (0x3UL<<28)
            #define COMF_CTX_CMD_MOD_USAGE_CNT_00           (0UL<<28)
            #define COMF_CTX_CMD_MOD_USAGE_CNT_01           (1UL<<28)
            #define COMF_CTX_CMD_MOD_USAGE_CNT_10           (2UL<<28)
            #define COMF_CTX_CMD_MOD_USAGE_CNT_11           (3UL<<28)
    u32_t unused_28[51];

    u32_t comf_burst_data0[16];
    u32_t comf_burst_data1[16];
    u32_t comf_burst_data2[16];
    u32_t comf_burst_data3[16];
    u32_t unused_29[64896];
    u32_t comf_ctx_window5[32768];
    u32_t comf_ctx_window6[32768];
    u32_t comf_ctx_window1[32768];
    u32_t comf_ctx_window2[32768];
    u32_t comf_ctx_window3[32768];
    u32_t comf_ctx_window4[32768];
} com_fio_xi_t;


/*
 *  cp_fio definition
 *  offset: 0x80000000
 */
typedef struct cp_fio
{
    u32_t cpf_events_bits;
        #define CPF_EVENTS_BITS_GPIO0                       (1UL<<15)
        #define CPF_EVENTS_BITS_GPIO1                       (1UL<<16)
        #define CPF_EVENTS_BITS_GPIO2                       (1UL<<17)
        #define CPF_EVENTS_BITS_GPIO3                       (1UL<<18)

    u32_t cpf_attentions_bits;
        #define CPF_ATTENTIONS_BITS_EPB_ERROR               (1UL<<30)

    u32_t cpf_event_enable;
    u32_t cpf_attention_enable;
    u32_t cpf_fio_status;

    u32_t cpf_mult_result;
    u32_t cpf_mult_a;

    u32_t cpf_mult_b;

    u32_t cpf_ctx_window_cid1;

    u32_t cpf_ctx_window_cid2;
        #define CPF_CTX_WINDOW_CID2_CTX_WINDOW_CID2_VALUE   (0x3fffUL<<7)

    u32_t cpf_ctx_window_cid3;
        #define CPF_CTX_WINDOW_CID3_CTX_WINDOW_CID3_VALUE   (0x3fffUL<<7)

    u32_t cpf_ctx_window_cid4;
        #define CPF_CTX_WINDOW_CID4_CTX_WINDOW_CID4_VALUE   (0x3fffUL<<7)

    u32_t cpf_dma_len;
        #define CPF_DMA_LEN_BYTE_SWAP                       (1UL<<24)

    u32_t cpf_dma_status;
        #define CPF_DMA_STATUS_WRITE_MASTER_ABORT           (1UL<<3)
        #define CPF_DMA_STATUS_READ_MASTER_ABORT            (1UL<<20)

    u32_t cpf_dma_addr_h;
    u32_t cpf_dma_addr_l;
    u32_t cpf_cp_hc_inc_stat[8];
    u32_t unused_0[4];
    u32_t cpf_free_counter_value;
    u32_t cpf_timer_retran_value;
    u16_t cpf_timer_rxpush_value;
    u16_t cpf_timer_delayack_value;
    u16_t cpf_timer_keepalive_value;
    u16_t cpf_timer_nagle_value;
    u16_t cpf_cp_hc_cons_idx;
    u16_t cpf_cp_hc_cmd;
        #define CPF_CP_HC_CMD_COALESCE_NOW                  (1<<0)
    u32_t unused_1[31];

    u32_t cpf_cpq_cid;
    u32_t cpf_cpq_val;
    u8_t cpf_cpq_type;
    u8_t unused_2;
    u16_t unused_3;
    u32_t unused_4[11];
    u32_t cpf_cpq_ftq_cmd;
    u32_t unused_5;

    u32_t cpf_tschq_cid;
    u8_t cpf_tschq_flags;
    u8_t unused_6;
    u16_t unused_7;
    u32_t unused_8[12];

    u32_t cpf_tschq_ftq_cmd;
    u32_t unused_9;

    u32_t cpf_rxpcq_cid;
    u32_t cpf_rxpcq_generic1;
    u32_t cpf_rxpcq_generic2;
    u32_t unused_10[11];
    u32_t cpf_rxpcq_ftq_cmd;
    u32_t unused_11[145];

    u32_t cpf_dma_data[128];
    u32_t unused_12[128];
    u32_t cpf_burst_base0;

    u32_t cpf_burst_base1;

    u32_t cpf_burst_base2;

    u32_t cpf_burst_base3;

    u32_t cpf_burst_cmd0;

    u32_t cpf_burst_cmd1;

    u32_t cpf_burst_cmd2;

    u32_t cpf_burst_cmd3;
    u32_t unused_13[56];

    u32_t cpf_burst_data0[16];
    u32_t cpf_burst_data1[16];
    u32_t cpf_burst_data2[16];
    u32_t cpf_burst_data3[16];
    u32_t unused_14[130432];
    u32_t cpf_ctx_window1[32768];
    u32_t cpf_ctx_window2[32768];
    u32_t cpf_ctx_window3[32768];
    u32_t cpf_ctx_window4[32768];
} cp_fio_t;


/*
 *  cp_fio definition
 *  offset: 0x80000000
 */
typedef struct cp_fio_xi
{
    u32_t cpf_events_bits;
        #define CPF_EVENTS_BITS_FTQ0_VALID                  (1UL<<0)
        #define CPF_EVENTS_BITS_FTQ1_VALID                  (1UL<<1)
        #define CPF_EVENTS_BITS_FTQ2_VALID                  (1UL<<2)
        #define CPF_EVENTS_BITS_SCANNER_DONE                (1UL<<3)
        #define CPF_EVENTS_BITS_DMA_WR_DONE                 (1UL<<4)
        #define CPF_EVENTS_BITS_DMA_RD_DONE                 (1UL<<5)
        #define CPF_EVENTS_BITS_CRACKER_DONE                (1UL<<6)
        #define CPF_EVENTS_BITS_MULTIPLY_DONE               (1UL<<7)
        #define CPF_EVENTS_BITS_EXP_ROM                     (1UL<<8)
        #define CPF_EVENTS_BITS_VPD                         (1UL<<9)
        #define CPF_EVENTS_BITS_FLASH                       (1UL<<10)
        #define CPF_EVENTS_BITS_SMB0                        (1UL<<11)
        #define CPF_EVENTS_BITS_RESERVED0                   (1UL<<12)
        #define CPF_EVENTS_BITS_RESERVED1                   (1UL<<13)
        #define CPF_EVENTS_BITS_RESERVED2                   (1UL<<14)
        #define CPF_EVENTS_BITS_GPIO                        (1UL<<15)
        #define CPF_EVENTS_BITS_SW_TMR_1                    (1UL<<19)
        #define CPF_EVENTS_BITS_SW_TMR_2                    (1UL<<20)
        #define CPF_EVENTS_BITS_SW_TMR_3                    (1UL<<21)
        #define CPF_EVENTS_BITS_SW_TMR_4                    (1UL<<22)
        #define CPF_EVENTS_BITS_LINK_CHANGED                (1UL<<23)
        #define CPF_EVENTS_BITS_MI_INT                      (1UL<<25)
        #define CPF_EVENTS_BITS_MI_COMPLETE                 (1UL<<26)
        #define CPF_EVENTS_BITS_MAIN_PWR_INT                (1UL<<27)
        #define CPF_EVENTS_BITS_NOT_ENABLED                 (1UL<<30)
        #define CPF_EVENTS_BITS_ATTENTIONS_VALID            (1UL<<31)

    u32_t cpf_attentions_bits;
        #define CPF_ATTENTIONS_BITS_LINK_STATE              (1UL<<0)
        #define CPF_ATTENTIONS_BITS_TX_SCHEDULER_ABORT      (1UL<<1)
        #define CPF_ATTENTIONS_BITS_TX_BD_READ_ABORT        (1UL<<2)
        #define CPF_ATTENTIONS_BITS_TX_BD_CACHE_ABORT       (1UL<<3)
        #define CPF_ATTENTIONS_BITS_TX_PROCESSOR_ABORT      (1UL<<4)
        #define CPF_ATTENTIONS_BITS_TX_DMA_ABORT            (1UL<<5)
        #define CPF_ATTENTIONS_BITS_TX_PATCHUP_ABORT        (1UL<<6)
        #define CPF_ATTENTIONS_BITS_TX_ASSEMBLER_ABORT      (1UL<<7)
        #define CPF_ATTENTIONS_BITS_RX_PARSER_MAC_ABORT     (1UL<<8)
        #define CPF_ATTENTIONS_BITS_RX_PARSER_CATCHUP_ABORT  (1UL<<9)
        #define CPF_ATTENTIONS_BITS_RX_MBUF_ABORT           (1UL<<10)
        #define CPF_ATTENTIONS_BITS_RX_LOOKUP_ABORT         (1UL<<11)
        #define CPF_ATTENTIONS_BITS_RX_PROCESSOR_ABORT      (1UL<<12)
        #define CPF_ATTENTIONS_BITS_RX_V2P_ABORT            (1UL<<13)
        #define CPF_ATTENTIONS_BITS_RX_BD_CACHE_ABORT       (1UL<<14)
        #define CPF_ATTENTIONS_BITS_RX_DMA_ABORT            (1UL<<15)
        #define CPF_ATTENTIONS_BITS_COMPLETION_ABORT        (1UL<<16)
        #define CPF_ATTENTIONS_BITS_HOST_COALESCE_ABORT     (1UL<<17)
        #define CPF_ATTENTIONS_BITS_MAILBOX_QUEUE_ABORT     (1UL<<18)
        #define CPF_ATTENTIONS_BITS_CONTEXT_ABORT           (1UL<<19)
        #define CPF_ATTENTIONS_BITS_CMD_SCHEDULER_ABORT     (1UL<<20)
        #define CPF_ATTENTIONS_BITS_CMD_PROCESSOR_ABORT     (1UL<<21)
        #define CPF_ATTENTIONS_BITS_MGMT_PROCESSOR_ABORT    (1UL<<22)
        #define CPF_ATTENTIONS_BITS_MAC_ABORT               (1UL<<23)
        #define CPF_ATTENTIONS_BITS_TIMER_ABORT             (1UL<<24)
        #define CPF_ATTENTIONS_BITS_DMAE_ABORT              (1UL<<25)
        #define CPF_ATTENTIONS_BITS_FLSH_ABORT              (1UL<<26)
        #define CPF_ATTENTIONS_BITS_GRC_ABORT               (1UL<<27)
        #define CPF_ATTENTIONS_BITS_PARITY_ERROR            (1UL<<31)

    u32_t cpf_event_enable;
    u32_t cpf_attention_enable;
    u32_t cpf_fio_status;
        #define CPF_FIO_STATUS_ENABLED                      (1UL<<0)
        #define CPF_FIO_STATUS_FORCE_ENA                    (1UL<<1)

    u32_t cpf_mult_result;
    u32_t cpf_mult_a;
        #define CPF_MULT_A_VALUE                            (0xffffUL<<0)

    u32_t cpf_mult_b;
        #define CPF_MULT_B_VALUE                            (0xffffUL<<0)

    u32_t cpf_ctx_window_cid1;
        #define CPF_CTX_WINDOW_CID1_LOCK_TYPE               (0x7UL<<0)
            #define CPF_CTX_WINDOW_CID1_LOCK_TYPE_VOID      (0UL<<0)
            #define CPF_CTX_WINDOW_CID1_LOCK_TYPE_PROTOCOL  (1UL<<0)
            #define CPF_CTX_WINDOW_CID1_LOCK_TYPE_TX        (2UL<<0)
            #define CPF_CTX_WINDOW_CID1_LOCK_TYPE_TIMER     (4UL<<0)
            #define CPF_CTX_WINDOW_CID1_LOCK_TYPE_COMPLETE  (7UL<<0)
        #define CPF_CTX_WINDOW_CID1_VALUE                   (0x3fffUL<<7)
        #define CPF_CTX_WINDOW_CID1_MOD_USAGE_CNT           (0x3UL<<24)
            #define CPF_CTX_WINDOW_CID1_MOD_USAGE_CNT_00    (0UL<<24)
            #define CPF_CTX_WINDOW_CID1_MOD_USAGE_CNT_01    (1UL<<24)
            #define CPF_CTX_WINDOW_CID1_MOD_USAGE_CNT_10    (2UL<<24)
            #define CPF_CTX_WINDOW_CID1_MOD_USAGE_CNT_11    (3UL<<24)
        #define CPF_CTX_WINDOW_CID1_LOCK_GRANTED            (1UL<<26)
        #define CPF_CTX_WINDOW_CID1_LOCK_MODE               (0x3UL<<27)
            #define CPF_CTX_WINDOW_CID1_LOCK_MODE_UNLOCK    (0UL<<27)
            #define CPF_CTX_WINDOW_CID1_LOCK_MODE_IMMEDIATE  (1UL<<27)
            #define CPF_CTX_WINDOW_CID1_LOCK_MODE_SURE      (2UL<<27)
        #define CPF_CTX_WINDOW_CID1_NO_EXT_ACC              (1UL<<29)
        #define CPF_CTX_WINDOW_CID1_LOCK_STATUS             (1UL<<30)
        #define CPF_CTX_WINDOW_CID1_LOCK_REQ                (1UL<<31)

    u32_t cpf_ctx_window_cid2;
        #define CPF_CTX_WINDOW_CID2_LOCK_TYPE               (0x7UL<<0)
            #define CPF_CTX_WINDOW_CID2_LOCK_TYPE_VOID      (0UL<<0)
            #define CPF_CTX_WINDOW_CID2_LOCK_TYPE_PROTOCOL  (1UL<<0)
            #define CPF_CTX_WINDOW_CID2_LOCK_TYPE_TX        (2UL<<0)
            #define CPF_CTX_WINDOW_CID2_LOCK_TYPE_TIMER     (4UL<<0)
            #define CPF_CTX_WINDOW_CID2_LOCK_TYPE_COMPLETE  (7UL<<0)
        #define CPF_CTX_WINDOW_CID2_VALUE                   (0x3fffUL<<7)
        #define CPF_CTX_WINDOW_CID2_MOD_USAGE_CNT           (0x3UL<<24)
            #define CPF_CTX_WINDOW_CID2_MOD_USAGE_CNT_00    (0UL<<24)
            #define CPF_CTX_WINDOW_CID2_MOD_USAGE_CNT_01    (1UL<<24)
            #define CPF_CTX_WINDOW_CID2_MOD_USAGE_CNT_10    (2UL<<24)
            #define CPF_CTX_WINDOW_CID2_MOD_USAGE_CNT_11    (3UL<<24)
        #define CPF_CTX_WINDOW_CID2_LOCK_GRANTED            (1UL<<26)
        #define CPF_CTX_WINDOW_CID2_LOCK_MODE               (0x3UL<<27)
            #define CPF_CTX_WINDOW_CID2_LOCK_MODE_UNLOCK    (0UL<<27)
            #define CPF_CTX_WINDOW_CID2_LOCK_MODE_IMMEDIATE  (1UL<<27)
            #define CPF_CTX_WINDOW_CID2_LOCK_MODE_SURE      (2UL<<27)
        #define CPF_CTX_WINDOW_CID2_NO_EXT_ACC              (1UL<<29)
        #define CPF_CTX_WINDOW_CID2_LOCK_STATUS             (1UL<<30)
        #define CPF_CTX_WINDOW_CID2_LOCK_REQ                (1UL<<31)

    u32_t cpf_ctx_window_cid3;
        #define CPF_CTX_WINDOW_CID3_LOCK_TYPE               (0x7UL<<0)
            #define CPF_CTX_WINDOW_CID3_LOCK_TYPE_VOID      (0UL<<0)
            #define CPF_CTX_WINDOW_CID3_LOCK_TYPE_PROTOCOL  (1UL<<0)
            #define CPF_CTX_WINDOW_CID3_LOCK_TYPE_TX        (2UL<<0)
            #define CPF_CTX_WINDOW_CID3_LOCK_TYPE_TIMER     (4UL<<0)
            #define CPF_CTX_WINDOW_CID3_LOCK_TYPE_COMPLETE  (7UL<<0)
        #define CPF_CTX_WINDOW_CID3_VALUE                   (0x3fffUL<<7)
        #define CPF_CTX_WINDOW_CID3_MOD_USAGE_CNT           (0x3UL<<24)
            #define CPF_CTX_WINDOW_CID3_MOD_USAGE_CNT_00    (0UL<<24)
            #define CPF_CTX_WINDOW_CID3_MOD_USAGE_CNT_01    (1UL<<24)
            #define CPF_CTX_WINDOW_CID3_MOD_USAGE_CNT_10    (2UL<<24)
            #define CPF_CTX_WINDOW_CID3_MOD_USAGE_CNT_11    (3UL<<24)
        #define CPF_CTX_WINDOW_CID3_LOCK_GRANTED            (1UL<<26)
        #define CPF_CTX_WINDOW_CID3_LOCK_MODE               (0x3UL<<27)
            #define CPF_CTX_WINDOW_CID3_LOCK_MODE_UNLOCK    (0UL<<27)
            #define CPF_CTX_WINDOW_CID3_LOCK_MODE_IMMEDIATE  (1UL<<27)
            #define CPF_CTX_WINDOW_CID3_LOCK_MODE_SURE      (2UL<<27)
        #define CPF_CTX_WINDOW_CID3_NO_EXT_ACC              (1UL<<29)
        #define CPF_CTX_WINDOW_CID3_LOCK_STATUS             (1UL<<30)
        #define CPF_CTX_WINDOW_CID3_LOCK_REQ                (1UL<<31)

    u32_t cpf_ctx_window_cid4;
        #define CPF_CTX_WINDOW_CID4_LOCK_TYPE               (0x7UL<<0)
            #define CPF_CTX_WINDOW_CID4_LOCK_TYPE_VOID      (0UL<<0)
            #define CPF_CTX_WINDOW_CID4_LOCK_TYPE_PROTOCOL  (1UL<<0)
            #define CPF_CTX_WINDOW_CID4_LOCK_TYPE_TX        (2UL<<0)
            #define CPF_CTX_WINDOW_CID4_LOCK_TYPE_TIMER     (4UL<<0)
            #define CPF_CTX_WINDOW_CID4_LOCK_TYPE_COMPLETE  (7UL<<0)
        #define CPF_CTX_WINDOW_CID4_VALUE                   (0x3fffUL<<7)
        #define CPF_CTX_WINDOW_CID4_MOD_USAGE_CNT           (0x3UL<<24)
            #define CPF_CTX_WINDOW_CID4_MOD_USAGE_CNT_00    (0UL<<24)
            #define CPF_CTX_WINDOW_CID4_MOD_USAGE_CNT_01    (1UL<<24)
            #define CPF_CTX_WINDOW_CID4_MOD_USAGE_CNT_10    (2UL<<24)
            #define CPF_CTX_WINDOW_CID4_MOD_USAGE_CNT_11    (3UL<<24)
        #define CPF_CTX_WINDOW_CID4_LOCK_GRANTED            (1UL<<26)
        #define CPF_CTX_WINDOW_CID4_LOCK_MODE               (0x3UL<<27)
            #define CPF_CTX_WINDOW_CID4_LOCK_MODE_UNLOCK    (0UL<<27)
            #define CPF_CTX_WINDOW_CID4_LOCK_MODE_IMMEDIATE  (1UL<<27)
            #define CPF_CTX_WINDOW_CID4_LOCK_MODE_SURE      (2UL<<27)
        #define CPF_CTX_WINDOW_CID4_NO_EXT_ACC              (1UL<<29)
        #define CPF_CTX_WINDOW_CID4_LOCK_STATUS             (1UL<<30)
        #define CPF_CTX_WINDOW_CID4_LOCK_REQ                (1UL<<31)

    u32_t cpf_dma_len;
        #define CPF_DMA_LEN_LEN                             (0x3ffUL<<0)
        #define CPF_DMA_LEN_WRITE_START                     (1UL<<16)
        #define CPF_DMA_LEN_WRITE_STOP                      (1UL<<17)
        #define CPF_DMA_LEN_WRITE_EVENT_CLEAR               (1UL<<18)
        #define CPF_DMA_LEN_READ_START                      (1UL<<20)
        #define CPF_DMA_LEN_READ_STOP                       (1UL<<21)
        #define CPF_DMA_LEN_READ_EVENT_CLEAR                (1UL<<22)
        #define CPF_DMA_LEN_TYPE                            (0x3UL<<23)
            #define CPF_DMA_LEN_TYPE_CONFIG                 (0UL<<23)
            #define CPF_DMA_LEN_TYPE_DATA                   (1UL<<23)
            #define CPF_DMA_LEN_TYPE_CONTROL                (2UL<<23)
        #define CPF_DMA_LEN_NO_SNOOP                        (1UL<<25)
        #define CPF_DMA_LEN_PRIORITY                        (1UL<<26)
        #define CPF_DMA_LEN_RELAXED_ORDERING                (1UL<<27)
        #define CPF_DMA_LEN_WRITE_RESET                     (1UL<<30)
        #define CPF_DMA_LEN_READ_RESET                      (1UL<<31)

    u32_t cpf_dma_status;
        #define CPF_DMA_STATUS_WRITE_CHAN_REQ               (1UL<<0)
        #define CPF_DMA_STATUS_WRITE_ACTIVE                 (1UL<<1)
        #define CPF_DMA_STATUS_WRITE_DONE                   (1UL<<2)
        #define CPF_DMA_STATUS_READ_CHAN_REQ                (1UL<<16)
        #define CPF_DMA_STATUS_READ_ACTIVE                  (1UL<<17)
        #define CPF_DMA_STATUS_READ_DONE                    (1UL<<19)
        #define CPF_DMA_STATUS_READ_CS16_ERROR              (1UL<<20)

    u32_t cpf_dma_addr_h;
    u32_t cpf_dma_addr_l;
    u32_t cpf_cp_hc_inc_stat[8];
    u32_t unused_0[4];
    u32_t cpf_free_counter_value;
    u32_t cpf_timer_retran_value;
    u16_t cpf_timer_rxpush_value;
    u16_t cpf_timer_delayack_value;
    u16_t cpf_timer_keepalive_value;
    u16_t cpf_timer_nagle_value;
    u32_t cpf_cp_cmd_cons_idx;
        #define CPF_CP_CMD_CONS_IDX_INDEX_VAL               (0xffffUL<<0)
        #define CPF_CP_CMD_CONS_IDX_INDEX_NUM               (0xfUL<<20)
        #define CPF_CP_CMD_CONS_IDX_COALESCE_NOW            (1UL<<30)
        #define CPF_CP_CMD_CONS_IDX_REQ_N                   (1UL<<31)
    u32_t unused_1[3];

    u32_t cpf_ctx_window_cid5;
        #define CPF_CTX_WINDOW_CID5_LOCK_TYPE               (0x7UL<<0)
            #define CPF_CTX_WINDOW_CID5_LOCK_TYPE_VOID      (0UL<<0)
            #define CPF_CTX_WINDOW_CID5_LOCK_TYPE_PROTOCOL  (1UL<<0)
            #define CPF_CTX_WINDOW_CID5_LOCK_TYPE_TX        (2UL<<0)
            #define CPF_CTX_WINDOW_CID5_LOCK_TYPE_TIMER     (4UL<<0)
            #define CPF_CTX_WINDOW_CID5_LOCK_TYPE_COMPLETE  (7UL<<0)
        #define CPF_CTX_WINDOW_CID5_VALUE                   (0x3fffUL<<7)
        #define CPF_CTX_WINDOW_CID5_MOD_USAGE_CNT           (0x3UL<<24)
            #define CPF_CTX_WINDOW_CID5_MOD_USAGE_CNT_00    (0UL<<24)
            #define CPF_CTX_WINDOW_CID5_MOD_USAGE_CNT_01    (1UL<<24)
            #define CPF_CTX_WINDOW_CID5_MOD_USAGE_CNT_10    (2UL<<24)
            #define CPF_CTX_WINDOW_CID5_MOD_USAGE_CNT_11    (3UL<<24)
        #define CPF_CTX_WINDOW_CID5_LOCK_GRANTED            (1UL<<26)
        #define CPF_CTX_WINDOW_CID5_LOCK_MODE               (0x3UL<<27)
            #define CPF_CTX_WINDOW_CID5_LOCK_MODE_UNLOCK    (0UL<<27)
            #define CPF_CTX_WINDOW_CID5_LOCK_MODE_IMMEDIATE  (1UL<<27)
            #define CPF_CTX_WINDOW_CID5_LOCK_MODE_SURE      (2UL<<27)
        #define CPF_CTX_WINDOW_CID5_NO_EXT_ACC              (1UL<<29)
        #define CPF_CTX_WINDOW_CID5_LOCK_STATUS             (1UL<<30)
        #define CPF_CTX_WINDOW_CID5_LOCK_REQ                (1UL<<31)

    u32_t cpf_ctx_window_cid6;
        #define CPF_CTX_WINDOW_CID6_LOCK_TYPE               (0x7UL<<0)
            #define CPF_CTX_WINDOW_CID6_LOCK_TYPE_VOID      (0UL<<0)
            #define CPF_CTX_WINDOW_CID6_LOCK_TYPE_PROTOCOL  (1UL<<0)
            #define CPF_CTX_WINDOW_CID6_LOCK_TYPE_TX        (2UL<<0)
            #define CPF_CTX_WINDOW_CID6_LOCK_TYPE_TIMER     (4UL<<0)
            #define CPF_CTX_WINDOW_CID6_LOCK_TYPE_COMPLETE  (7UL<<0)
        #define CPF_CTX_WINDOW_CID6_VALUE                   (0x3fffUL<<7)
        #define CPF_CTX_WINDOW_CID6_MOD_USAGE_CNT           (0x3UL<<24)
            #define CPF_CTX_WINDOW_CID6_MOD_USAGE_CNT_00    (0UL<<24)
            #define CPF_CTX_WINDOW_CID6_MOD_USAGE_CNT_01    (1UL<<24)
            #define CPF_CTX_WINDOW_CID6_MOD_USAGE_CNT_10    (2UL<<24)
            #define CPF_CTX_WINDOW_CID6_MOD_USAGE_CNT_11    (3UL<<24)
        #define CPF_CTX_WINDOW_CID6_LOCK_GRANTED            (1UL<<26)
        #define CPF_CTX_WINDOW_CID6_LOCK_MODE               (0x3UL<<27)
            #define CPF_CTX_WINDOW_CID6_LOCK_MODE_UNLOCK    (0UL<<27)
            #define CPF_CTX_WINDOW_CID6_LOCK_MODE_IMMEDIATE  (1UL<<27)
            #define CPF_CTX_WINDOW_CID6_LOCK_MODE_SURE      (2UL<<27)
        #define CPF_CTX_WINDOW_CID6_NO_EXT_ACC              (1UL<<29)
        #define CPF_CTX_WINDOW_CID6_LOCK_STATUS             (1UL<<30)
        #define CPF_CTX_WINDOW_CID6_LOCK_REQ                (1UL<<31)
    u32_t unused_2[26];

    u32_t cpf_cpq_cid;
    u32_t unused_3[13];
    u32_t cpf_cpq_ftq_cmd;
        #define CPF_CPQ_FTQ_CMD_POP                         (1UL<<30)
    u32_t unused_4;

    u32_t cpf_tschq_cid;
    u8_t cpf_tschq_flags;
        #define CPF_TSCHQ_FLAGS_DELIST                      (1<<0)
        #define CPF_TSCHQ_FLAGS_NORMAL                      (1<<1)
        #define CPF_TSCHQ_FLAGS_HIGH                        (1<<2)

    u8_t cpf_tschq_rsvd_future;
    u16_t unused_5;
    u32_t unused_6[12];
    u32_t cpf_tschq_ftq_cmd;
        #define CPF_TSCHQ_FTQ_CMD_ADD_INTERVEN              (1UL<<27)
        #define CPF_TSCHQ_FTQ_CMD_ADD_DATA                  (1UL<<28)
        #define CPF_TSCHQ_FTQ_CMD_BUSY                      (1UL<<31)
    u32_t unused_7;

    u32_t cpf_rxpcq_cid;
    u32_t cpf_rxpcq_generic1;
    u32_t cpf_rxpcq_generic2;
    u32_t unused_8[11];
    u32_t cpf_rxpcq_ftq_cmd;
        #define CPF_RXPCQ_FTQ_CMD_ADD_INTERVEN              (1UL<<27)
        #define CPF_RXPCQ_FTQ_CMD_ADD_DATA                  (1UL<<28)
        #define CPF_RXPCQ_FTQ_CMD_BUSY                      (1UL<<31)
    u32_t unused_9[145];

    u32_t cpf_dma_data[128];
    u32_t unused_10[128];
    u32_t cpf_burst_base0;
        #define CPF_BURST_BASE0_BASE_VAL0                   (0x3fffUL<<7)

    u32_t cpf_burst_base1;
        #define CPF_BURST_BASE1_BASE_VAL1                   (0x3fffUL<<7)

    u32_t cpf_burst_base2;
        #define CPF_BURST_BASE2_BASE_VAL2                   (0x3fffUL<<7)

    u32_t cpf_burst_base3;
        #define CPF_BURST_BASE3_BASE_VAL3                   (0x3fffUL<<7)

    u32_t cpf_burst_cmd0;
        #define CPF_BURST_CMD0_FTQ_SEL                      (0x3UL<<0)
            #define CPF_BURST_CMD0_FTQ_SEL_0                (0UL<<0)
            #define CPF_BURST_CMD0_FTQ_SEL_1                (1UL<<0)
            #define CPF_BURST_CMD0_FTQ_SEL_2                (2UL<<0)
            #define CPF_BURST_CMD0_FTQ_SEL_3                (3UL<<0)
        #define CPF_BURST_CMD0_BUSY                         (1UL<<2)
        #define CPF_BURST_CMD0_OFFSET                       (0x1ffUL<<3)
        #define CPF_BURST_CMD0_BASE_REG_SEL                 (1UL<<23)
        #define CPF_BURST_CMD0_MOD_USAGE_CNT                (0x3UL<<24)
            #define CPF_BURST_CMD0_MOD_USAGE_CNT_00         (0UL<<24)
            #define CPF_BURST_CMD0_MOD_USAGE_CNT_01         (1UL<<24)
            #define CPF_BURST_CMD0_MOD_USAGE_CNT_10         (2UL<<24)
            #define CPF_BURST_CMD0_MOD_USAGE_CNT_11         (3UL<<24)
        #define CPF_BURST_CMD0_PREFETCH_SIZE                (0x3UL<<26)
        #define CPF_BURST_CMD0_NO_RAM_ACCESS                (1UL<<28)
        #define CPF_BURST_CMD0_NO_CACHE                     (1UL<<29)
        #define CPF_BURST_CMD0_CROSS_BOUNDARY               (1UL<<30)

    u32_t cpf_burst_cmd1;
        #define CPF_BURST_CMD1_FTQ_SEL                      (0x3UL<<0)
            #define CPF_BURST_CMD1_FTQ_SEL_0                (0UL<<0)
            #define CPF_BURST_CMD1_FTQ_SEL_1                (1UL<<0)
            #define CPF_BURST_CMD1_FTQ_SEL_2                (2UL<<0)
            #define CPF_BURST_CMD1_FTQ_SEL_3                (3UL<<0)
        #define CPF_BURST_CMD1_BUSY                         (1UL<<2)
        #define CPF_BURST_CMD1_OFFSET                       (0x1ffUL<<3)
        #define CPF_BURST_CMD1_BASE_REG_SEL                 (1UL<<23)
        #define CPF_BURST_CMD1_MOD_USAGE_CNT                (0x3UL<<24)
            #define CPF_BURST_CMD1_MOD_USAGE_CNT_00         (0UL<<24)
            #define CPF_BURST_CMD1_MOD_USAGE_CNT_01         (1UL<<24)
            #define CPF_BURST_CMD1_MOD_USAGE_CNT_10         (2UL<<24)
            #define CPF_BURST_CMD1_MOD_USAGE_CNT_11         (3UL<<24)
        #define CPF_BURST_CMD1_PREFETCH_SIZE                (0x3UL<<26)
        #define CPF_BURST_CMD1_NO_RAM_ACCESS                (1UL<<28)
        #define CPF_BURST_CMD1_NO_CACHE                     (1UL<<29)
        #define CPF_BURST_CMD1_CROSS_BOUNDARY               (1UL<<30)

    u32_t cpf_burst_cmd2;
        #define CPF_BURST_CMD2_FTQ_SEL                      (0x3UL<<0)
            #define CPF_BURST_CMD2_FTQ_SEL_0                (0UL<<0)
            #define CPF_BURST_CMD2_FTQ_SEL_1                (1UL<<0)
            #define CPF_BURST_CMD2_FTQ_SEL_2                (2UL<<0)
            #define CPF_BURST_CMD2_FTQ_SEL_3                (3UL<<0)
        #define CPF_BURST_CMD2_BUSY                         (1UL<<2)
        #define CPF_BURST_CMD2_OFFSET                       (0x1ffUL<<3)
        #define CPF_BURST_CMD2_BASE_REG_SEL                 (1UL<<23)
        #define CPF_BURST_CMD2_MOD_USAGE_CNT                (0x3UL<<24)
            #define CPF_BURST_CMD2_MOD_USAGE_CNT_00         (0UL<<24)
            #define CPF_BURST_CMD2_MOD_USAGE_CNT_01         (1UL<<24)
            #define CPF_BURST_CMD2_MOD_USAGE_CNT_10         (2UL<<24)
            #define CPF_BURST_CMD2_MOD_USAGE_CNT_11         (3UL<<24)
        #define CPF_BURST_CMD2_PREFETCH_SIZE                (0x3UL<<26)
        #define CPF_BURST_CMD2_NO_RAM_ACCESS                (1UL<<28)
        #define CPF_BURST_CMD2_NO_CACHE                     (1UL<<29)
        #define CPF_BURST_CMD2_CROSS_BOUNDARY               (1UL<<30)

    u32_t cpf_burst_cmd3;
        #define CPF_BURST_CMD3_FTQ_SEL                      (0x3UL<<0)
            #define CPF_BURST_CMD3_FTQ_SEL_0                (0UL<<0)
            #define CPF_BURST_CMD3_FTQ_SEL_1                (1UL<<0)
            #define CPF_BURST_CMD3_FTQ_SEL_2                (2UL<<0)
            #define CPF_BURST_CMD3_FTQ_SEL_3                (3UL<<0)
        #define CPF_BURST_CMD3_BUSY                         (1UL<<2)
        #define CPF_BURST_CMD3_OFFSET                       (0x1ffUL<<3)
        #define CPF_BURST_CMD3_BASE_REG_SEL                 (1UL<<23)
        #define CPF_BURST_CMD3_MOD_USAGE_CNT                (0x3UL<<24)
            #define CPF_BURST_CMD3_MOD_USAGE_CNT_00         (0UL<<24)
            #define CPF_BURST_CMD3_MOD_USAGE_CNT_01         (1UL<<24)
            #define CPF_BURST_CMD3_MOD_USAGE_CNT_10         (2UL<<24)
            #define CPF_BURST_CMD3_MOD_USAGE_CNT_11         (3UL<<24)
        #define CPF_BURST_CMD3_PREFETCH_SIZE                (0x3UL<<26)
        #define CPF_BURST_CMD3_NO_RAM_ACCESS                (1UL<<28)
        #define CPF_BURST_CMD3_NO_CACHE                     (1UL<<29)
        #define CPF_BURST_CMD3_CROSS_BOUNDARY               (1UL<<30)

    u32_t cpf_burst_cmd4;
        #define CPF_BURST_CMD4_FTQ_SEL                      (0x3UL<<0)
            #define CPF_BURST_CMD4_FTQ_SEL_0                (0UL<<0)
            #define CPF_BURST_CMD4_FTQ_SEL_1                (1UL<<0)
            #define CPF_BURST_CMD4_FTQ_SEL_2                (2UL<<0)
            #define CPF_BURST_CMD4_FTQ_SEL_3                (3UL<<0)
        #define CPF_BURST_CMD4_BUSY                         (1UL<<2)
        #define CPF_BURST_CMD4_OFFSET                       (0x1ffUL<<3)
        #define CPF_BURST_CMD4_BASE_REG_SEL                 (1UL<<23)
        #define CPF_BURST_CMD4_MOD_USAGE_CNT                (0x3UL<<24)
            #define CPF_BURST_CMD4_MOD_USAGE_CNT_00         (0UL<<24)
            #define CPF_BURST_CMD4_MOD_USAGE_CNT_01         (1UL<<24)
            #define CPF_BURST_CMD4_MOD_USAGE_CNT_10         (2UL<<24)
            #define CPF_BURST_CMD4_MOD_USAGE_CNT_11         (3UL<<24)
        #define CPF_BURST_CMD4_PREFETCH_SIZE                (0x3UL<<26)
        #define CPF_BURST_CMD4_NO_RAM_ACCESS                (1UL<<28)
        #define CPF_BURST_CMD4_NO_CACHE                     (1UL<<29)
        #define CPF_BURST_CMD4_CROSS_BOUNDARY               (1UL<<30)

    u32_t cpf_burst_cmd5;
        #define CPF_BURST_CMD5_FTQ_SEL                      (0x3UL<<0)
            #define CPF_BURST_CMD5_FTQ_SEL_0                (0UL<<0)
            #define CPF_BURST_CMD5_FTQ_SEL_1                (1UL<<0)
            #define CPF_BURST_CMD5_FTQ_SEL_2                (2UL<<0)
            #define CPF_BURST_CMD5_FTQ_SEL_3                (3UL<<0)
        #define CPF_BURST_CMD5_BUSY                         (1UL<<2)
        #define CPF_BURST_CMD5_OFFSET                       (0x1ffUL<<3)
        #define CPF_BURST_CMD5_BASE_REG_SEL                 (1UL<<23)
        #define CPF_BURST_CMD5_MOD_USAGE_CNT                (0x3UL<<24)
            #define CPF_BURST_CMD5_MOD_USAGE_CNT_00         (0UL<<24)
            #define CPF_BURST_CMD5_MOD_USAGE_CNT_01         (1UL<<24)
            #define CPF_BURST_CMD5_MOD_USAGE_CNT_10         (2UL<<24)
            #define CPF_BURST_CMD5_MOD_USAGE_CNT_11         (3UL<<24)
        #define CPF_BURST_CMD5_PREFETCH_SIZE                (0x3UL<<26)
        #define CPF_BURST_CMD5_NO_RAM_ACCESS                (1UL<<28)
        #define CPF_BURST_CMD5_NO_CACHE                     (1UL<<29)
        #define CPF_BURST_CMD5_CROSS_BOUNDARY               (1UL<<30)

    u32_t cpf_burst_cmd6;
        #define CPF_BURST_CMD6_FTQ_SEL                      (0x3UL<<0)
            #define CPF_BURST_CMD6_FTQ_SEL_0                (0UL<<0)
            #define CPF_BURST_CMD6_FTQ_SEL_1                (1UL<<0)
            #define CPF_BURST_CMD6_FTQ_SEL_2                (2UL<<0)
            #define CPF_BURST_CMD6_FTQ_SEL_3                (3UL<<0)
        #define CPF_BURST_CMD6_BUSY                         (1UL<<2)
        #define CPF_BURST_CMD6_OFFSET                       (0x1ffUL<<3)
        #define CPF_BURST_CMD6_BASE_REG_SEL                 (1UL<<23)
        #define CPF_BURST_CMD6_MOD_USAGE_CNT                (0x3UL<<24)
            #define CPF_BURST_CMD6_MOD_USAGE_CNT_00         (0UL<<24)
            #define CPF_BURST_CMD6_MOD_USAGE_CNT_01         (1UL<<24)
            #define CPF_BURST_CMD6_MOD_USAGE_CNT_10         (2UL<<24)
            #define CPF_BURST_CMD6_MOD_USAGE_CNT_11         (3UL<<24)
        #define CPF_BURST_CMD6_PREFETCH_SIZE                (0x3UL<<26)
        #define CPF_BURST_CMD6_NO_RAM_ACCESS                (1UL<<28)
        #define CPF_BURST_CMD6_NO_CACHE                     (1UL<<29)
        #define CPF_BURST_CMD6_CROSS_BOUNDARY               (1UL<<30)

    u32_t cpf_burst_cmd7;
        #define CPF_BURST_CMD7_FTQ_SEL                      (0x3UL<<0)
            #define CPF_BURST_CMD7_FTQ_SEL_0                (0UL<<0)
            #define CPF_BURST_CMD7_FTQ_SEL_1                (1UL<<0)
            #define CPF_BURST_CMD7_FTQ_SEL_2                (2UL<<0)
            #define CPF_BURST_CMD7_FTQ_SEL_3                (3UL<<0)
        #define CPF_BURST_CMD7_BUSY                         (1UL<<2)
        #define CPF_BURST_CMD7_OFFSET                       (0x1ffUL<<3)
        #define CPF_BURST_CMD7_BASE_REG_SEL                 (1UL<<23)
        #define CPF_BURST_CMD7_MOD_USAGE_CNT                (0x3UL<<24)
            #define CPF_BURST_CMD7_MOD_USAGE_CNT_00         (0UL<<24)
            #define CPF_BURST_CMD7_MOD_USAGE_CNT_01         (1UL<<24)
            #define CPF_BURST_CMD7_MOD_USAGE_CNT_10         (2UL<<24)
            #define CPF_BURST_CMD7_MOD_USAGE_CNT_11         (3UL<<24)
        #define CPF_BURST_CMD7_PREFETCH_SIZE                (0x3UL<<26)
        #define CPF_BURST_CMD7_NO_RAM_ACCESS                (1UL<<28)
        #define CPF_BURST_CMD7_NO_CACHE                     (1UL<<29)
        #define CPF_BURST_CMD7_CROSS_BOUNDARY               (1UL<<30)

    u32_t cpf_ctx_cmd;
        #define CPF_CTX_CMD_NUM_BLOCKS                      (0x3UL<<0)
        #define CPF_CTX_CMD_OFFSET                          (0x1ffUL<<3)
        #define CPF_CTX_CMD_CID_VALUE                       (0x3fffUL<<12)
        #define CPF_CTX_CMD_PREFETCH_SIZE                   (0x3UL<<26)
        #define CPF_CTX_CMD_MOD_USAGE_CNT                   (0x3UL<<28)
            #define CPF_CTX_CMD_MOD_USAGE_CNT_00            (0UL<<28)
            #define CPF_CTX_CMD_MOD_USAGE_CNT_01            (1UL<<28)
            #define CPF_CTX_CMD_MOD_USAGE_CNT_10            (2UL<<28)
            #define CPF_CTX_CMD_MOD_USAGE_CNT_11            (3UL<<28)
    u32_t unused_11[51];

    u32_t cpf_burst_data0[16];
    u32_t cpf_burst_data1[16];
    u32_t cpf_burst_data2[16];
    u32_t cpf_burst_data3[16];
    u32_t cpf_burst_data4[16];
    u32_t cpf_burst_data5[16];
    u32_t cpf_burst_data6[16];
    u32_t cpf_burst_data7[16];
    u32_t unused_12[64832];
    u32_t cpf_ctx_window5[32768];
    u32_t cpf_ctx_window6[32768];
    u32_t cpf_ctx_window1[32768];
    u32_t cpf_ctx_window2[32768];
    u32_t cpf_ctx_window3[32768];
    u32_t cpf_ctx_window4[32768];
} cp_fio_xi_t;


/*
 *  mcp_fio definition
 *  offset: 0x80000000
 */
typedef struct mcp_fio
{
    u32_t mcpf_events_bits;
        #define MCPF_EVENTS_BITS_FTQ2_VALID                 (1UL<<2)
        #define MCPF_EVENTS_BITS_SCANNER_DONE               (1UL<<3)
        #define MCPF_EVENTS_BITS_DMA_WR_DONE                (1UL<<4)
        #define MCPF_EVENTS_BITS_DMA_RD_DONE                (1UL<<5)
        #define MCPF_EVENTS_BITS_CRACKER_DONE               (1UL<<6)
        #define MCPF_EVENTS_BITS_MULTIPLY_DONE              (1UL<<7)
        #define MCPF_EVENTS_BITS_GPIO0                      (1UL<<15)
        #define MCPF_EVENTS_BITS_GPIO1                      (1UL<<16)
        #define MCPF_EVENTS_BITS_GPIO2                      (1UL<<17)
        #define MCPF_EVENTS_BITS_GPIO3                      (1UL<<18)

    u32_t mcpf_attentions_bits;
        #define MCPF_ATTENTIONS_BITS_EPB_ERROR              (1UL<<30)

    u32_t mcpf_event_enable;
    u32_t mcpf_attention_enable;
    u32_t mcpf_fio_status;
    u32_t unused_0[11];

    u32_t mcpf_mcp_hc_inc_stat[8];
    u32_t unused_1[4];
    u32_t mcpf_free_counter_value;
    u32_t unused_2[3];
    u32_t mcpf_ump_cmd;
        #define MCPF_UMP_CMD_RX_FIFO_ENABLED                (1UL<<0)
        #define MCPF_UMP_CMD_TX_FIFO_ENABLED                (1UL<<1)
        #define MCPF_UMP_CMD_FLOWMODE                       (1UL<<3)
        #define MCPF_UMP_CMD_HDFLOWSEL                      (1UL<<4)
        #define MCPF_UMP_CMD_RX_MAC_DISABLE                 (1UL<<5)
        #define MCPF_UMP_CMD_TX_MAC_DISABLE                 (1UL<<6)
        #define MCPF_UMP_CMD_TX_DROP                        (1UL<<7)
        #define MCPF_UMP_CMD_TX_DRIVE                       (1UL<<8)
        #define MCPF_UMP_CMD_TX_RESET                       (1UL<<14)

    u32_t mcpf_ump_status;
        #define MCPF_UMP_STATUS_TX_IDLE                     (1UL<<0)
        #define MCPF_UMP_STATUS_FDX                         (1UL<<1)
        #define MCPF_UMP_STATUS_RX_FRM_DROP                 (1UL<<3)
        #define MCPF_UMP_STATUS_SRC_ADDR_CHG                (1UL<<5)
        #define MCPF_UMP_STATUS_XOFF_TRIP                   (0xffUL<<16)
        #define MCPF_UMP_STATUS_XON_TRIP                    (0xffUL<<24)
    u32_t unused_3[2];

    u32_t mcpf_ump_frm_rd_status;
        #define MCPF_UMP_FRM_RD_STATUS_NEW_FRM              (1UL<<0)
        #define MCPF_UMP_FRM_RD_STATUS_FRM_IN_PRO           (1UL<<1)
        #define MCPF_UMP_FRM_RD_STATUS_FIFO_EMPTY           (1UL<<2)
        #define MCPF_UMP_FRM_RD_STATUS_BCNT                 (0x7ffUL<<3)
        #define MCPF_UMP_FRM_RD_STATUS_RX_FIFO_STATE        (0x7UL<<29)
            #define MCPF_UMP_FRM_RD_STATUS_RX_FIFO_STATE_IDLE  (0UL<<29)
            #define MCPF_UMP_FRM_RD_STATUS_RX_FIFO_STATE_READY  (1UL<<29)
            #define MCPF_UMP_FRM_RD_STATUS_RX_FIFO_STATE_BUSY  (2UL<<29)
            #define MCPF_UMP_FRM_RD_STATUS_RX_FIFO_STATE_EXTRA_RD  (3UL<<29)
            #define MCPF_UMP_FRM_RD_STATUS_RX_FIFO_STATE_LATCH_IP_HDR  (4UL<<29)

    u32_t mcpf_ump_frm_rd_data;
    u32_t mcpf_ump_frm_wr_ctl;
        #define MCPF_UMP_FRM_WR_CTL_NEW_FRM                 (1UL<<0)
        #define MCPF_UMP_FRM_WR_CTL_FIFO_RDY                (1UL<<1)
        #define MCPF_UMP_FRM_WR_CTL_BCNT_RDY                (1UL<<2)
        #define MCPF_UMP_FRM_WR_CTL_BCNT                    (0x7ffUL<<3)
        #define MCPF_UMP_FRM_WR_CTL_TX_FIFO_STATE           (0x3UL<<30)
            #define MCPF_UMP_FRM_WR_CTL_TX_FIFO_STATE_IDLE  (0UL<<30)
            #define MCPF_UMP_FRM_WR_CTL_TX_FIFO_STATE_WAIT  (1UL<<30)
            #define MCPF_UMP_FRM_WR_CTL_TX_FIFO_STATE_BUSY  (2UL<<30)
            #define MCPF_UMP_FRM_WR_CTL_TX_FIFO_STATE_EXTRA_WR  (3UL<<30)

    u32_t mcpf_ump_frm_wr_data;
    u32_t mcpf_ump_frm_pre_fetch;
    u32_t mcpf_ump_fifo_remain;
        #define MCPF_UMP_FIFO_REMAIN_TX_FIFO_REMAIN         (0x1ffUL<<0)
        #define MCPF_UMP_FIFO_REMAIN_RX_FIFO_REMAIN         (0x1ffUL<<16)

    u32_t mcpf_ump_rxfifo_ptrs;
        #define MCPF_UMP_RXFIFO_PTRS_WA_CPU                 (0x1ffUL<<0)
        #define MCPF_UMP_RXFIFO_PTRS_WA_TOGGLE_CPU          (1UL<<9)
        #define MCPF_UMP_RXFIFO_PTRS_RA                     (0x1ffUL<<16)
        #define MCPF_UMP_RXFIFO_PTRS_RA_TOGGLE              (1UL<<25)

    u32_t mcpf_ump_txfifo_ptrs;
        #define MCPF_UMP_TXFIFO_PTRS_WA                     (0x1ffUL<<0)
        #define MCPF_UMP_TXFIFO_PTRS_WA_TOGGLE              (1UL<<9)
        #define MCPF_UMP_TXFIFO_PTRS_RA_CPU                 (0x1ffUL<<16)
        #define MCPF_UMP_TXFIFO_PTRS_RA_TOGGLE_CPU          (1UL<<25)

    u32_t mcpf_ump_ump_debug;
        #define MCPF_UMP_UMP_DEBUG_RXBUF_ALM_FULL_CORE      (1UL<<0)
        #define MCPF_UMP_UMP_DEBUG_FIFO_FULL_ERR            (1UL<<1)
        #define MCPF_UMP_UMP_DEBUG_NEW_PACKET               (1UL<<2)
        #define MCPF_UMP_UMP_DEBUG_LOCAL_PKT_ABT            (1UL<<3)
        #define MCPF_UMP_UMP_DEBUG_SETABT                   (1UL<<4)
    u32_t unused_4[19];

    u32_t mcpf_mcpq_bits_status;
    u16_t mcpf_mcpq_pkt_len;
    u16_t unused_5;
    u32_t mcpf_mcpq_mbuf_cluster;
    u32_t unused_6[11];
    u32_t mcpf_mcpq_cmd;
    u32_t unused_7;

} mcp_fio_t;


/*
 *  mcp_fio definition
 *  offset: 0x80000000
 */
typedef struct mcp_fio_xi
{
    u32_t mcpf_events_bits;
        #define MCPF_EVENTS_BITS_FTQ0_VALID                 (1UL<<0)
        #define MCPF_EVENTS_BITS_FTQ1_VALID                 (1UL<<1)
        #define MCPF_EVENTS_BITS_UMP_EVENT                  (1UL<<2)
        #define MCPF_EVENTS_BITS_SMBUS_EVENT                (1UL<<3)
        #define MCPF_EVENTS_BITS_FLASH_EVENT                (1UL<<4)
        #define MCPF_EVENTS_BITS_MCP_DOORBELL               (1UL<<5)
        #define MCPF_EVENTS_BITS_UNUSED_A                   (1UL<<6)
        #define MCPF_EVENTS_BITS_UNUSED_B                   (1UL<<7)
        #define MCPF_EVENTS_BITS_EXP_ROM                    (1UL<<8)
        #define MCPF_EVENTS_BITS_VPD                        (1UL<<9)
        #define MCPF_EVENTS_BITS_FLASH                      (1UL<<10)
        #define MCPF_EVENTS_BITS_SMB0                       (1UL<<11)
        #define MCPF_EVENTS_BITS_RESERVED0                  (1UL<<12)
        #define MCPF_EVENTS_BITS_RESERVED1                  (1UL<<13)
        #define MCPF_EVENTS_BITS_RESERVED2                  (1UL<<14)
        #define MCPF_EVENTS_BITS_GPIO                       (1UL<<15)
        #define MCPF_EVENTS_BITS_SW_TMR_1                   (1UL<<19)
        #define MCPF_EVENTS_BITS_SW_TMR_2                   (1UL<<20)
        #define MCPF_EVENTS_BITS_SW_TMR_3                   (1UL<<21)
        #define MCPF_EVENTS_BITS_SW_TMR_4                   (1UL<<22)
        #define MCPF_EVENTS_BITS_LINK_CHANGED               (1UL<<23)
        #define MCPF_EVENTS_BITS_MI_INT                     (1UL<<25)
        #define MCPF_EVENTS_BITS_MI_COMPLETE                (1UL<<26)
        #define MCPF_EVENTS_BITS_MAIN_PWR_INT               (1UL<<27)
        #define MCPF_EVENTS_BITS_NOT_ENABLED                (1UL<<30)
        #define MCPF_EVENTS_BITS_ATTENTIONS_VALID           (1UL<<31)

    u32_t mcpf_attentions_bits;
        #define MCPF_ATTENTIONS_BITS_LINK_STATE             (1UL<<0)
        #define MCPF_ATTENTIONS_BITS_TX_SCHEDULER_ABORT     (1UL<<1)
        #define MCPF_ATTENTIONS_BITS_TX_BD_READ_ABORT       (1UL<<2)
        #define MCPF_ATTENTIONS_BITS_TX_BD_CACHE_ABORT      (1UL<<3)
        #define MCPF_ATTENTIONS_BITS_TX_PROCESSOR_ABORT     (1UL<<4)
        #define MCPF_ATTENTIONS_BITS_TX_DMA_ABORT           (1UL<<5)
        #define MCPF_ATTENTIONS_BITS_TX_PATCHUP_ABORT       (1UL<<6)
        #define MCPF_ATTENTIONS_BITS_TX_ASSEMBLER_ABORT     (1UL<<7)
        #define MCPF_ATTENTIONS_BITS_RX_PARSER_MAC_ABORT    (1UL<<8)
        #define MCPF_ATTENTIONS_BITS_RX_PARSER_CATCHUP_ABORT  (1UL<<9)
        #define MCPF_ATTENTIONS_BITS_RX_MBUF_ABORT          (1UL<<10)
        #define MCPF_ATTENTIONS_BITS_RX_LOOKUP_ABORT        (1UL<<11)
        #define MCPF_ATTENTIONS_BITS_RX_PROCESSOR_ABORT     (1UL<<12)
        #define MCPF_ATTENTIONS_BITS_RX_V2P_ABORT           (1UL<<13)
        #define MCPF_ATTENTIONS_BITS_RX_BD_CACHE_ABORT      (1UL<<14)
        #define MCPF_ATTENTIONS_BITS_RX_DMA_ABORT           (1UL<<15)
        #define MCPF_ATTENTIONS_BITS_COMPLETION_ABORT       (1UL<<16)
        #define MCPF_ATTENTIONS_BITS_HOST_COALESCE_ABORT    (1UL<<17)
        #define MCPF_ATTENTIONS_BITS_MAILBOX_QUEUE_ABORT    (1UL<<18)
        #define MCPF_ATTENTIONS_BITS_CONTEXT_ABORT          (1UL<<19)
        #define MCPF_ATTENTIONS_BITS_CMD_SCHEDULER_ABORT    (1UL<<20)
        #define MCPF_ATTENTIONS_BITS_CMD_PROCESSOR_ABORT    (1UL<<21)
        #define MCPF_ATTENTIONS_BITS_MGMT_PROCESSOR_ABORT   (1UL<<22)
        #define MCPF_ATTENTIONS_BITS_MAC_ABORT              (1UL<<23)
        #define MCPF_ATTENTIONS_BITS_TIMER_ABORT            (1UL<<24)
        #define MCPF_ATTENTIONS_BITS_DMAE_ABORT             (1UL<<25)
        #define MCPF_ATTENTIONS_BITS_FLSH_ABORT             (1UL<<26)
        #define MCPF_ATTENTIONS_BITS_GRC_ABORT              (1UL<<27)
        #define MCPF_ATTENTIONS_BITS_PARITY_ERROR           (1UL<<31)

    u32_t mcpf_event_enable;
    u32_t mcpf_attention_enable;
    u32_t mcpf_fio_status;
        #define MCPF_FIO_STATUS_ENABLED                     (1UL<<0)
        #define MCPF_FIO_STATUS_FORCE_ENA                   (1UL<<1)

    u32_t mcpf_interrupt_status;
        #define MCPF_INTERRUPT_STATUS_EVENT0                (1UL<<0)
        #define MCPF_INTERRUPT_STATUS_ATTN0                 (1UL<<1)
        #define MCPF_INTERRUPT_STATUS_EVENT1                (1UL<<2)
        #define MCPF_INTERRUPT_STATUS_ATTN1                 (1UL<<3)
    u32_t unused_0[10];

    u32_t mcpf_mcp_hc_inc_stat[8];
    u32_t unused_1[4];
    u32_t mcpf_free_counter_value;
    u32_t unused_2[35];
    u32_t mcpf_mcpq_bits_status;
        #define MCPF_MCPQ_BITS_STATUS_RULE_CLASS            (0x7UL<<0)
        #define MCPF_MCPQ_BITS_STATUS_RULE_P2               (1UL<<3)
        #define MCPF_MCPQ_BITS_STATUS_RULE_P3               (1UL<<4)
        #define MCPF_MCPQ_BITS_STATUS_RULE_P4               (1UL<<5)
        #define MCPF_MCPQ_BITS_STATUS_L2_VLAN_TAG           (1UL<<6)
        #define MCPF_MCPQ_BITS_STATUS_L2_LLC_SNAP           (1UL<<7)
        #define MCPF_MCPQ_BITS_STATUS_RSS_HASH              (1UL<<8)
        #define MCPF_MCPQ_BITS_STATUS_SORT_VECT             (0xfUL<<9)
        #define MCPF_MCPQ_BITS_STATUS_IP_DATAGRAM           (1UL<<13)
        #define MCPF_MCPQ_BITS_STATUS_TCP_SEGMENT           (1UL<<14)
        #define MCPF_MCPQ_BITS_STATUS_UDP_DATAGRAM          (1UL<<15)
        #define MCPF_MCPQ_BITS_STATUS_CU_FRAME              (1UL<<16)
        #define MCPF_MCPQ_BITS_STATUS_IP_PROG_EXT           (1UL<<17)
        #define MCPF_MCPQ_BITS_STATUS_IP_TYPE               (1UL<<18)
        #define MCPF_MCPQ_BITS_STATUS_RULE_P1               (1UL<<19)
        #define MCPF_MCPQ_BITS_STATUS_RLUP_HIT4             (1UL<<20)
        #define MCPF_MCPQ_BITS_STATUS_IP_FRAGMENT           (1UL<<21)
        #define MCPF_MCPQ_BITS_STATUS_IP_OPTIONS_PRESENT    (1UL<<22)
        #define MCPF_MCPQ_BITS_STATUS_TCP_OPTIONS_PRESENT   (1UL<<23)
        #define MCPF_MCPQ_BITS_STATUS_L2_PM_IDX             (0xfUL<<24)
        #define MCPF_MCPQ_BITS_STATUS_L2_PM_HIT             (1UL<<28)
        #define MCPF_MCPQ_BITS_STATUS_L2_MC_HASH_HIT        (1UL<<29)
        #define MCPF_MCPQ_BITS_STATUS_RDMAC_CRC_PASS        (1UL<<30)
        #define MCPF_MCPQ_BITS_STATUS_MP_HIT                (1UL<<31)

    u16_t mcpf_mcpq_pkt_len;
        #define MCPF_MCPQ_PKT_LEN_VALUE                     (0x3fff<<0)

    u16_t mcpf_mcpq_vlan_tag;
    u32_t mcpf_mcpq_mbuf_cluster;
        #define MCPF_MCPQ_MBUF_CLUSTER_VALUE                (0x1ffffffUL<<0)

    u32_t mcpf_mcpq_frm_errors;
        #define MCPF_MCPQ_FRM_ERRORS_L2_BAD_CRC             (1UL<<1)
        #define MCPF_MCPQ_FRM_ERRORS_L2_PHY_DECODE          (1UL<<2)
        #define MCPF_MCPQ_FRM_ERRORS_L2_ALIGNMENT           (1UL<<3)
        #define MCPF_MCPQ_FRM_ERRORS_L2_TOO_SHORT           (1UL<<4)
        #define MCPF_MCPQ_FRM_ERRORS_L2_GIANT_FRAME         (1UL<<5)
        #define MCPF_MCPQ_FRM_ERRORS_IP_BAD_LEN             (1UL<<6)
        #define MCPF_MCPQ_FRM_ERRORS_IP_TOO_SHORT           (1UL<<7)
        #define MCPF_MCPQ_FRM_ERRORS_IP_BAD_VERSION         (1UL<<8)
        #define MCPF_MCPQ_FRM_ERRORS_IP_BAD_HLEN            (1UL<<9)
        #define MCPF_MCPQ_FRM_ERRORS_IP_BAD_XSUM            (1UL<<10)
        #define MCPF_MCPQ_FRM_ERRORS_TCP_TOO_SHORT          (1UL<<11)
        #define MCPF_MCPQ_FRM_ERRORS_TCP_BAD_XSUM           (1UL<<12)
        #define MCPF_MCPQ_FRM_ERRORS_TCP_BAD_OFFSET         (1UL<<13)
        #define MCPF_MCPQ_FRM_ERRORS_UDP_BAD_XSUM           (1UL<<15)
        #define MCPF_MCPQ_FRM_ERRORS_IP_BAD_ORDER           (1UL<<16)
        #define MCPF_MCPQ_FRM_ERRORS_IP_HDR_MISMATCH        (1UL<<18)

    u16_t mcpf_mcpq_ext_status;
        #define MCPF_MCPQ_EXT_STATUS_TCP_SYNC_PRESENT       (1<<0)
        #define MCPF_MCPQ_EXT_STATUS_RLUP_HIT2              (1<<1)
        #define MCPF_MCPQ_EXT_STATUS_TCP_UDP_XSUM_IS_0      (1<<2)
        #define MCPF_MCPQ_EXT_STATUS_IP_ROUTING_HDR_PRESENT  (0x3<<3)
            #define MCPF_MCPQ_EXT_STATUS_IP_ROUTING_HDR_PRESENT_00  (0<<3)
            #define MCPF_MCPQ_EXT_STATUS_IP_ROUTING_HDR_PRESENT_01  (1<<3)
            #define MCPF_MCPQ_EXT_STATUS_IP_ROUTING_HDR_PRESENT_10  (2<<3)
            #define MCPF_MCPQ_EXT_STATUS_IP_ROUTING_HDR_PRESENT_11  (3<<3)
        #define MCPF_MCPQ_EXT_STATUS_ACPI_MATCH             (1<<5)

    u16_t mcpf_mcpq_reserved;
    u32_t unused_3[9];
    u32_t mcpf_mcpq_cmd;
        #define MCPF_MCPQ_CMD_MCPQ_CMD_POP                  (1UL<<30)
    u32_t unused_4[39089];

    u32_t mcpf_nvm_command;
        #define MCPF_NVM_COMMAND_RST                        (1UL<<0)
        #define MCPF_NVM_COMMAND_DONE                       (1UL<<3)
        #define MCPF_NVM_COMMAND_DOIT                       (1UL<<4)
        #define MCPF_NVM_COMMAND_WR                         (1UL<<5)
        #define MCPF_NVM_COMMAND_ERASE                      (1UL<<6)
        #define MCPF_NVM_COMMAND_FIRST                      (1UL<<7)
        #define MCPF_NVM_COMMAND_LAST                       (1UL<<8)
        #define MCPF_NVM_COMMAND_WREN                       (1UL<<16)
        #define MCPF_NVM_COMMAND_WRDI                       (1UL<<17)
        #define MCPF_NVM_COMMAND_RD_ID                      (1UL<<20)
        #define MCPF_NVM_COMMAND_RD_STATUS                  (1UL<<21)
        #define MCPF_NVM_COMMAND_MODE_256                   (1UL<<22)

    u32_t mcpf_nvm_status;
        #define MCPF_NVM_STATUS_SPI_FSM_STATE               (0x1fUL<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_IDLE  (0UL<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_CMD0  (1UL<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_CMD1  (2UL<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_CMD_FINISH0  (3UL<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_CMD_FINISH1  (4UL<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_ADDR0  (5UL<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_WRITE_DATA0  (6UL<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_WRITE_DATA1  (7UL<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_WRITE_DATA2  (8UL<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_READ_DATA0  (9UL<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_READ_DATA1  (10UL<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_READ_DATA2  (11UL<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_READ_STATUS_RDID0  (12UL<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_READ_STATUS_RDID1  (13UL<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_READ_STATUS_RDID2  (14UL<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_READ_STATUS_RDID3  (15UL<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_READ_STATUS_RDID4  (16UL<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_CHECK_BUSY0  (17UL<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_ST_WREN  (18UL<<0)
            #define MCPF_NVM_STATUS_SPI_FSM_STATE_SPI_WAIT  (19UL<<0)

    u32_t mcpf_nvm_write;
        #define MCPF_NVM_WRITE_NVM_WRITE_VALUE              (0xffffffffUL<<0)
            #define MCPF_NVM_WRITE_NVM_WRITE_VALUE_BIT_BANG  (0UL<<0)
            #define MCPF_NVM_WRITE_NVM_WRITE_VALUE_SI       (1UL<<0)
            #define MCPF_NVM_WRITE_NVM_WRITE_VALUE_SO       (2UL<<0)
            #define MCPF_NVM_WRITE_NVM_WRITE_VALUE_CS_B     (4UL<<0)
            #define MCPF_NVM_WRITE_NVM_WRITE_VALUE_SCLK     (8UL<<0)

    u32_t mcpf_nvm_addr;
        #define MCPF_NVM_ADDR_NVM_ADDR_VALUE                (0xffffffUL<<0)
            #define MCPF_NVM_ADDR_NVM_ADDR_VALUE_BIT_BANG   (0UL<<0)
            #define MCPF_NVM_ADDR_NVM_ADDR_VALUE_SI         (1UL<<0)
            #define MCPF_NVM_ADDR_NVM_ADDR_VALUE_SO         (2UL<<0)
            #define MCPF_NVM_ADDR_NVM_ADDR_VALUE_CS_B       (4UL<<0)
            #define MCPF_NVM_ADDR_NVM_ADDR_VALUE_SCLK       (8UL<<0)

    u32_t mcpf_nvm_read;
        #define MCPF_NVM_READ_NVM_READ_VALUE                (0xffffffffUL<<0)
            #define MCPF_NVM_READ_NVM_READ_VALUE_BIT_BANG   (0UL<<0)
            #define MCPF_NVM_READ_NVM_READ_VALUE_SI         (1UL<<0)
            #define MCPF_NVM_READ_NVM_READ_VALUE_SO         (2UL<<0)
            #define MCPF_NVM_READ_NVM_READ_VALUE_CS_B       (4UL<<0)
            #define MCPF_NVM_READ_NVM_READ_VALUE_SCLK       (8UL<<0)

    u32_t mcpf_nvm_cfg1;
        #define MCPF_NVM_CFG1_FLASH_MODE                    (1UL<<0)
        #define MCPF_NVM_CFG1_BUFFER_MODE                   (1UL<<1)
        #define MCPF_NVM_CFG1_PASS_MODE                     (1UL<<2)
        #define MCPF_NVM_CFG1_BITBANG_MODE                  (1UL<<3)
        #define MCPF_NVM_CFG1_STATUS_BIT                    (0x7UL<<4)
        #define MCPF_NVM_CFG1_SPI_CLK_DIV                   (0xfUL<<7)
        #define MCPF_NVM_CFG1_SEE_CLK_DIV                   (0x7ffUL<<11)
        #define MCPF_NVM_CFG1_STRAP_CONTROL_0               (1UL<<23)
        #define MCPF_NVM_CFG1_PROTECT_MODE                  (1UL<<24)
        #define MCPF_NVM_CFG1_FLASH_SIZE                    (1UL<<25)
        #define MCPF_NVM_CFG1_FW_USTRAP_1                   (1UL<<26)
        #define MCPF_NVM_CFG1_FW_USTRAP_0                   (1UL<<27)
        #define MCPF_NVM_CFG1_FW_USTRAP_2                   (1UL<<28)
        #define MCPF_NVM_CFG1_FW_USTRAP_3                   (1UL<<29)
        #define MCPF_NVM_CFG1_FW_FLASH_TYPE_EN              (1UL<<30)
        #define MCPF_NVM_CFG1_COMPAT_BYPASSS                (1UL<<31)

    u32_t mcpf_nvm_cfg2;
        #define MCPF_NVM_CFG2_ERASE_CMD                     (0xffUL<<0)
        #define MCPF_NVM_CFG2_STATUS_CMD                    (0xffUL<<16)
        #define MCPF_NVM_CFG2_READ_ID                       (0xffUL<<24)

    u32_t mcpf_nvm_cfg3;
        #define MCPF_NVM_CFG3_BUFFER_RD_CMD                 (0xffUL<<0)
        #define MCPF_NVM_CFG3_WRITE_CMD                     (0xffUL<<8)
        #define MCPF_NVM_CFG3_READ_CMD                      (0xffUL<<24)

    u32_t mcpf_nvm_sw_arb;
        #define MCPF_NVM_SW_ARB_ARB_REQ_SET0                (1UL<<0)
        #define MCPF_NVM_SW_ARB_ARB_REQ_SET1                (1UL<<1)
        #define MCPF_NVM_SW_ARB_ARB_REQ_SET2                (1UL<<2)
        #define MCPF_NVM_SW_ARB_ARB_REQ_SET3                (1UL<<3)
        #define MCPF_NVM_SW_ARB_ARB_REQ_CLR0                (1UL<<4)
        #define MCPF_NVM_SW_ARB_ARB_REQ_CLR1                (1UL<<5)
        #define MCPF_NVM_SW_ARB_ARB_REQ_CLR2                (1UL<<6)
        #define MCPF_NVM_SW_ARB_ARB_REQ_CLR3                (1UL<<7)
        #define MCPF_NVM_SW_ARB_ARB_ARB0                    (1UL<<8)
        #define MCPF_NVM_SW_ARB_ARB_ARB1                    (1UL<<9)
        #define MCPF_NVM_SW_ARB_ARB_ARB2                    (1UL<<10)
        #define MCPF_NVM_SW_ARB_ARB_ARB3                    (1UL<<11)
        #define MCPF_NVM_SW_ARB_REQ0                        (1UL<<12)
        #define MCPF_NVM_SW_ARB_REQ1                        (1UL<<13)
        #define MCPF_NVM_SW_ARB_REQ2                        (1UL<<14)
        #define MCPF_NVM_SW_ARB_REQ3                        (1UL<<15)

    u32_t mcpf_nvm_access_enable;
        #define MCPF_NVM_ACCESS_ENABLE_EN                   (1UL<<0)
        #define MCPF_NVM_ACCESS_ENABLE_WR_EN                (1UL<<1)

    u32_t mcpf_nvm_write1;
        #define MCPF_NVM_WRITE1_WREN_CMD                    (0xffUL<<0)
        #define MCPF_NVM_WRITE1_WRDI_CMD                    (0xffUL<<8)

    u32_t mcpf_nvm_cfg4;
        #define MCPF_NVM_CFG4_FLASH_SIZE                    (0x7UL<<0)
            #define MCPF_NVM_CFG4_FLASH_SIZE_1MBIT          (0UL<<0)
            #define MCPF_NVM_CFG4_FLASH_SIZE_2MBIT          (1UL<<0)
            #define MCPF_NVM_CFG4_FLASH_SIZE_4MBIT          (2UL<<0)
            #define MCPF_NVM_CFG4_FLASH_SIZE_8MBIT          (3UL<<0)
            #define MCPF_NVM_CFG4_FLASH_SIZE_16MBIT         (4UL<<0)
            #define MCPF_NVM_CFG4_FLASH_SIZE_32MBIT         (5UL<<0)
            #define MCPF_NVM_CFG4_FLASH_SIZE_64MBIT         (6UL<<0)
            #define MCPF_NVM_CFG4_FLASH_SIZE_128MBIT        (7UL<<0)
        #define MCPF_NVM_CFG4_FLASH_VENDOR                  (1UL<<3)
            #define MCPF_NVM_CFG4_FLASH_VENDOR_ST           (0UL<<3)
            #define MCPF_NVM_CFG4_FLASH_VENDOR_ATMEL        (1UL<<3)
        #define MCPF_NVM_CFG4_MODE_256_EMPTY_BIT_LOC        (0x3UL<<4)
            #define MCPF_NVM_CFG4_MODE_256_EMPTY_BIT_LOC_BIT8  (0UL<<4)
            #define MCPF_NVM_CFG4_MODE_256_EMPTY_BIT_LOC_BIT9  (1UL<<4)
            #define MCPF_NVM_CFG4_MODE_256_EMPTY_BIT_LOC_BIT10  (2UL<<4)
            #define MCPF_NVM_CFG4_MODE_256_EMPTY_BIT_LOC_BIT11  (3UL<<4)
        #define MCPF_NVM_CFG4_STATUS_BIT_POLARITY           (1UL<<6)
        #define MCPF_NVM_CFG4_RESERVED                      (0x1ffffffUL<<7)

    u32_t mcpf_nvm_reconfig;
        #define MCPF_NVM_RECONFIG_ORIG_STRAP_VALUE          (0xfUL<<0)
            #define MCPF_NVM_RECONFIG_ORIG_STRAP_VALUE_ST   (0UL<<0)
            #define MCPF_NVM_RECONFIG_ORIG_STRAP_VALUE_ATMEL  (1UL<<0)
        #define MCPF_NVM_RECONFIG_RECONFIG_STRAP_VALUE      (0xfUL<<4)
        #define MCPF_NVM_RECONFIG_RESERVED                  (0x7fffffUL<<8)
        #define MCPF_NVM_RECONFIG_RECONFIG_DONE             (1UL<<31)
    u32_t unused_5[1779];

    u32_t mcpf_smbus_config;
        #define MCPF_SMBUS_CONFIG_HW_ARP_ASSIGN_ADDR        (1UL<<7)
        #define MCPF_SMBUS_CONFIG_ARP_EN0                   (1UL<<8)
        #define MCPF_SMBUS_CONFIG_ARP_EN1                   (1UL<<9)
        #define MCPF_SMBUS_CONFIG_MASTER_RTRY_CNT           (0xfUL<<16)
        #define MCPF_SMBUS_CONFIG_TIMESTAMP_CNT_EN          (1UL<<26)
        #define MCPF_SMBUS_CONFIG_PROMISCOUS_MODE           (1UL<<27)
        #define MCPF_SMBUS_CONFIG_EN_NIC_SMB_ADDR_0         (1UL<<28)
        #define MCPF_SMBUS_CONFIG_BIT_BANG_EN               (1UL<<29)
        #define MCPF_SMBUS_CONFIG_SMB_EN                    (1UL<<30)
        #define MCPF_SMBUS_CONFIG_RESET                     (1UL<<31)

    u32_t mcpf_smbus_timing_config;
        #define MCPF_SMBUS_TIMING_CONFIG_SMBUS_IDLE_TIME    (0xffUL<<8)
        #define MCPF_SMBUS_TIMING_CONFIG_PERIODIC_SLAVE_STRETCH  (0xffUL<<16)
        #define MCPF_SMBUS_TIMING_CONFIG_RANDOM_SLAVE_STRETCH  (0x7fUL<<24)
        #define MCPF_SMBUS_TIMING_CONFIG_MODE_400           (1UL<<31)

    u32_t mcpf_smbus_address;
        #define MCPF_SMBUS_ADDRESS_NIC_SMB_ADDR0            (0x7fUL<<0)
        #define MCPF_SMBUS_ADDRESS_EN_NIC_SMB_ADDR0         (1UL<<7)
        #define MCPF_SMBUS_ADDRESS_NIC_SMB_ADDR1            (0x7fUL<<8)
        #define MCPF_SMBUS_ADDRESS_EN_NIC_SMB_ADDR1         (1UL<<15)
        #define MCPF_SMBUS_ADDRESS_NIC_SMB_ADDR2            (0x7fUL<<16)
        #define MCPF_SMBUS_ADDRESS_EN_NIC_SMB_ADDR2         (1UL<<23)
        #define MCPF_SMBUS_ADDRESS_NIC_SMB_ADDR3            (0x7fUL<<24)
        #define MCPF_SMBUS_ADDRESS_EN_NIC_SMB_ADDR3         (1UL<<31)

    u32_t mcpf_smbus_master_fifo_control;
        #define MCPF_SMBUS_MASTER_FIFO_CONTROL_MASTER_RX_FIFO_THRESHOLD  (0x7fUL<<8)
        #define MCPF_SMBUS_MASTER_FIFO_CONTROL_MASTER_RX_PKT_COUNT  (0x7fUL<<16)
        #define MCPF_SMBUS_MASTER_FIFO_CONTROL_MASTER_TX_FIFO_FLUSH  (1UL<<30)
        #define MCPF_SMBUS_MASTER_FIFO_CONTROL_MASTER_RX_FIFO_FLUSH  (1UL<<31)

    u32_t mcpf_smbus_slave_fifo_control;
        #define MCPF_SMBUS_SLAVE_FIFO_CONTROL_SLAVE_RX_FIFO_THRESHOLD  (0x7fUL<<8)
        #define MCPF_SMBUS_SLAVE_FIFO_CONTROL_SLAVE_RX_PKT_COUNT  (0x7fUL<<16)
        #define MCPF_SMBUS_SLAVE_FIFO_CONTROL_SLAVE_TX_FIFO_FLUSH  (1UL<<30)
        #define MCPF_SMBUS_SLAVE_FIFO_CONTROL_SLAVE_RX_FIFO_FLUSH  (1UL<<31)

    u32_t mcpf_smbus_bit_bang_control;
        #define MCPF_SMBUS_BIT_BANG_CONTROL_SMBDAT_OUT_EN   (1UL<<28)
        #define MCPF_SMBUS_BIT_BANG_CONTROL_SMBDAT_IN       (1UL<<29)
        #define MCPF_SMBUS_BIT_BANG_CONTROL_SMBCLK_OUT_EN   (1UL<<30)
        #define MCPF_SMBUS_BIT_BANG_CONTROL_SMBCLK_IN       (1UL<<31)

    u32_t mcpf_smbus_watchdog;
        #define MCPF_SMBUS_WATCHDOG_WATCHDOG                (0xffffUL<<0)

    u32_t mcpf_smbus_heartbeat;
        #define MCPF_SMBUS_HEARTBEAT_HEARTBEAT              (0xffffUL<<0)

    u32_t mcpf_smbus_poll_asf;
        #define MCPF_SMBUS_POLL_ASF_POLL_ASF                (0xffffUL<<0)

    u32_t mcpf_smbus_poll_legacy;
        #define MCPF_SMBUS_POLL_LEGACY_POLL_LEGACY          (0xffffUL<<0)

    u32_t mcpf_smbus_retran;
        #define MCPF_SMBUS_RETRAN_RETRAN                    (0xffUL<<0)

    u32_t mcpf_smbus_timestamp;
        #define MCPF_SMBUS_TIMESTAMP_TIMESTAMP              (0xffffffffUL<<0)

    u32_t mcpf_smbus_master_command;
        #define MCPF_SMBUS_MASTER_COMMAND_RD_BYTE_COUNT     (0xffUL<<0)
        #define MCPF_SMBUS_MASTER_COMMAND_PEC               (1UL<<8)
        #define MCPF_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL    (0xfUL<<9)
            #define MCPF_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL_0000  (0UL<<9)
            #define MCPF_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL_0001  (1UL<<9)
            #define MCPF_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL_0010  (2UL<<9)
            #define MCPF_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL_0011  (3UL<<9)
            #define MCPF_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL_0100  (4UL<<9)
            #define MCPF_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL_0101  (5UL<<9)
            #define MCPF_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL_0110  (6UL<<9)
            #define MCPF_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL_0111  (7UL<<9)
            #define MCPF_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL_1000  (8UL<<9)
            #define MCPF_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL_1001  (9UL<<9)
            #define MCPF_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL_1010  (10UL<<9)
            #define MCPF_SMBUS_MASTER_COMMAND_SMBUS_PROTOCOL_1011  (11UL<<9)
        #define MCPF_SMBUS_MASTER_COMMAND_STATUS            (0x7UL<<25)
            #define MCPF_SMBUS_MASTER_COMMAND_STATUS_000    (0UL<<25)
            #define MCPF_SMBUS_MASTER_COMMAND_STATUS_001    (1UL<<25)
            #define MCPF_SMBUS_MASTER_COMMAND_STATUS_010    (2UL<<25)
            #define MCPF_SMBUS_MASTER_COMMAND_STATUS_011    (3UL<<25)
            #define MCPF_SMBUS_MASTER_COMMAND_STATUS_100    (4UL<<25)
            #define MCPF_SMBUS_MASTER_COMMAND_STATUS_101    (5UL<<25)
            #define MCPF_SMBUS_MASTER_COMMAND_STATUS_110    (6UL<<25)
            #define MCPF_SMBUS_MASTER_COMMAND_STATUS_111    (7UL<<25)
        #define MCPF_SMBUS_MASTER_COMMAND_ABORT             (1UL<<30)
        #define MCPF_SMBUS_MASTER_COMMAND_START_BUSY        (1UL<<31)

    u32_t mcpf_smbus_slave_command;
        #define MCPF_SMBUS_SLAVE_COMMAND_PEC                (1UL<<8)
        #define MCPF_SMBUS_SLAVE_COMMAND_STATUS             (0x7UL<<23)
            #define MCPF_SMBUS_SLAVE_COMMAND_STATUS_000     (0UL<<23)
            #define MCPF_SMBUS_SLAVE_COMMAND_STATUS_101     (5UL<<23)
            #define MCPF_SMBUS_SLAVE_COMMAND_STATUS_111     (7UL<<23)
        #define MCPF_SMBUS_SLAVE_COMMAND_ABORT              (1UL<<30)
        #define MCPF_SMBUS_SLAVE_COMMAND_START              (1UL<<31)

    u32_t mcpf_smbus_event_enable;
        #define MCPF_SMBUS_EVENT_ENABLE_WATCHDOG_TO_EN      (1UL<<0)
        #define MCPF_SMBUS_EVENT_ENABLE_HEARTBEAT_TO_EN     (1UL<<1)
        #define MCPF_SMBUS_EVENT_ENABLE_POLL_ASF_TO_EN      (1UL<<2)
        #define MCPF_SMBUS_EVENT_ENABLE_POLL_LEGACY_TO_EN   (1UL<<3)
        #define MCPF_SMBUS_EVENT_ENABLE_RETRANSMIT_TO_EN    (1UL<<4)
        #define MCPF_SMBUS_EVENT_ENABLE_SLAVE_ARP_EVENT_EN  (1UL<<20)
        #define MCPF_SMBUS_EVENT_ENABLE_SLAVE_RD_EVENT_EN   (1UL<<21)
        #define MCPF_SMBUS_EVENT_ENABLE_SLAVE_TX_UNDERRUN_EN  (1UL<<22)
        #define MCPF_SMBUS_EVENT_ENABLE_SLAVE_START_BUSY_EN  (1UL<<23)
        #define MCPF_SMBUS_EVENT_ENABLE_SLAVE_RX_EVENT_EN   (1UL<<24)
        #define MCPF_SMBUS_EVENT_ENABLE_SLAVE_RX_THRESHOLD_HIT_EN  (1UL<<25)
        #define MCPF_SMBUS_EVENT_ENABLE_SLAVE_RX_FIFO_FULL_EN  (1UL<<26)
        #define MCPF_SMBUS_EVENT_ENABLE_MASTER_TX_UNDERRUN_EN  (1UL<<27)
        #define MCPF_SMBUS_EVENT_ENABLE_MASTER_START_BUSY_EN  (1UL<<28)
        #define MCPF_SMBUS_EVENT_ENABLE_MASTER_RX_EVENT_EN  (1UL<<29)
        #define MCPF_SMBUS_EVENT_ENABLE_MASTER_RX_THRESHOLD_HIT_EN  (1UL<<30)
        #define MCPF_SMBUS_EVENT_ENABLE_MASTER_RX_FIFO_FULL_EN  (1UL<<31)

    u32_t mcpf_smbus_event_status;
        #define MCPF_SMBUS_EVENT_STATUS_WATCHDOG_TO         (1UL<<0)
        #define MCPF_SMBUS_EVENT_STATUS_HEARTBEAT_TO        (1UL<<1)
        #define MCPF_SMBUS_EVENT_STATUS_POLL_ASF_TO         (1UL<<2)
        #define MCPF_SMBUS_EVENT_STATUS_POLL_LEGACY_TO      (1UL<<3)
        #define MCPF_SMBUS_EVENT_STATUS_RETRANSMIT_TO       (1UL<<4)
        #define MCPF_SMBUS_EVENT_STATUS_SLAVE_ARP_EVENT     (1UL<<20)
        #define MCPF_SMBUS_EVENT_STATUS_SLAVE_RD_EVENT      (1UL<<21)
        #define MCPF_SMBUS_EVENT_STATUS_SLAVE_TX_UNDERRUN   (1UL<<22)
        #define MCPF_SMBUS_EVENT_STATUS_SLAVE_START_BUSY    (1UL<<23)
        #define MCPF_SMBUS_EVENT_STATUS_SLAVE_RX_EVENT      (1UL<<24)
        #define MCPF_SMBUS_EVENT_STATUS_SLAVE_RX_THRESHOLD_HIT  (1UL<<25)
        #define MCPF_SMBUS_EVENT_STATUS_SLAVE_RX_FIFO_FULL  (1UL<<26)
        #define MCPF_SMBUS_EVENT_STATUS_MASTER_TX_UNDERRUN  (1UL<<27)
        #define MCPF_SMBUS_EVENT_STATUS_MASTER_START_BUSY   (1UL<<28)
        #define MCPF_SMBUS_EVENT_STATUS_MASTER_RX_EVENT     (1UL<<29)
        #define MCPF_SMBUS_EVENT_STATUS_MASTER_RX_THRESHOLD_HIT  (1UL<<30)
        #define MCPF_SMBUS_EVENT_STATUS_MASTER_RX_FIFO_FULL  (1UL<<31)

    u32_t mcpf_smbus_master_data_write;
        #define MCPF_SMBUS_MASTER_DATA_WRITE_MASTER_SMBUS_WR_DATA  (0xffUL<<0)
        #define MCPF_SMBUS_MASTER_DATA_WRITE_WR_STATUS      (1UL<<31)

    u32_t mcpf_smbus_master_data_read;
        #define MCPF_SMBUS_MASTER_DATA_READ_MASTER_SMBUS_RD_DATA  (0xffUL<<0)
        #define MCPF_SMBUS_MASTER_DATA_READ_PEC_ERR         (1UL<<29)
        #define MCPF_SMBUS_MASTER_DATA_READ_RD_STATUS       (0x3UL<<30)
            #define MCPF_SMBUS_MASTER_DATA_READ_RD_STATUS_00  (0UL<<30)
            #define MCPF_SMBUS_MASTER_DATA_READ_RD_STATUS_01  (1UL<<30)
            #define MCPF_SMBUS_MASTER_DATA_READ_RD_STATUS_10  (2UL<<30)
            #define MCPF_SMBUS_MASTER_DATA_READ_RD_STATUS_11  (3UL<<30)

    u32_t mcpf_smbus_slave_data_write;
        #define MCPF_SMBUS_SLAVE_DATA_WRITE_SLAVE_SMBUS_WR_DATA  (0xffUL<<0)
        #define MCPF_SMBUS_SLAVE_DATA_WRITE_WR_STATUS       (1UL<<31)
            #define MCPF_SMBUS_SLAVE_DATA_WRITE_WR_STATUS_0  (0UL<<31)
            #define MCPF_SMBUS_SLAVE_DATA_WRITE_WR_STATUS_1  (1UL<<31)

    u32_t mcpf_smbus_slave_data_read;
        #define MCPF_SMBUS_SLAVE_DATA_READ_SLAVE_SMBUS_RD_DATA  (0xffUL<<0)
        #define MCPF_SMBUS_SLAVE_DATA_READ_ERR_STATUS       (0x3UL<<28)
            #define MCPF_SMBUS_SLAVE_DATA_READ_ERR_STATUS_00  (0UL<<28)
            #define MCPF_SMBUS_SLAVE_DATA_READ_ERR_STATUS_01  (1UL<<28)
            #define MCPF_SMBUS_SLAVE_DATA_READ_ERR_STATUS_10  (2UL<<28)
            #define MCPF_SMBUS_SLAVE_DATA_READ_ERR_STATUS_11  (3UL<<28)
        #define MCPF_SMBUS_SLAVE_DATA_READ_RD_STATUS        (0x3UL<<30)
            #define MCPF_SMBUS_SLAVE_DATA_READ_RD_STATUS_00  (0UL<<30)
            #define MCPF_SMBUS_SLAVE_DATA_READ_RD_STATUS_01  (1UL<<30)
            #define MCPF_SMBUS_SLAVE_DATA_READ_RD_STATUS_10  (2UL<<30)
            #define MCPF_SMBUS_SLAVE_DATA_READ_RD_STATUS_11  (3UL<<30)
    u32_t unused_6[12];

    u32_t mcpf_smbus_arp_state;
        #define MCPF_SMBUS_ARP_STATE_AV_FLAG0               (1UL<<0)
        #define MCPF_SMBUS_ARP_STATE_AR_FLAG0               (1UL<<1)
        #define MCPF_SMBUS_ARP_STATE_AV_FLAG1               (1UL<<4)
        #define MCPF_SMBUS_ARP_STATE_AR_FLAG1               (1UL<<5)
    u32_t unused_7[3];

    u32_t mcpf_smbus_udid0_3;
        #define MCPF_SMBUS_UDID0_3_BYTE_12                  (0xffUL<<0)
        #define MCPF_SMBUS_UDID0_3_BYTE_13                  (0xffUL<<8)
        #define MCPF_SMBUS_UDID0_3_BYTE_14                  (0xffUL<<16)
        #define MCPF_SMBUS_UDID0_3_BYTE_15                  (0xffUL<<24)

    u32_t mcpf_smbus_udid0_2;
        #define MCPF_SMBUS_UDID0_2_BYTE_8                   (0xffUL<<0)
        #define MCPF_SMBUS_UDID0_2_BYTE_9                   (0xffUL<<8)
        #define MCPF_SMBUS_UDID0_2_BYTE_10                  (0xffUL<<16)
        #define MCPF_SMBUS_UDID0_2_BYTE_11                  (0xffUL<<24)

    u32_t mcpf_smbus_udid0_1;
        #define MCPF_SMBUS_UDID0_1_BYTE_4                   (0xffUL<<0)
        #define MCPF_SMBUS_UDID0_1_BYTE_5                   (0xffUL<<8)
        #define MCPF_SMBUS_UDID0_1_BYTE_6                   (0xffUL<<16)
        #define MCPF_SMBUS_UDID0_1_BYTE_7                   (0xffUL<<24)

    u32_t mcpf_smbus_udid0_0;
        #define MCPF_SMBUS_UDID0_0_BYTE_0                   (0xffUL<<0)
        #define MCPF_SMBUS_UDID0_0_BYTE_1                   (0xffUL<<8)
        #define MCPF_SMBUS_UDID0_0_BYTE_2                   (0xffUL<<16)
        #define MCPF_SMBUS_UDID0_0_BYTE_3                   (0xffUL<<24)

    u32_t mcpf_smbus_udid1_3;
        #define MCPF_SMBUS_UDID1_3_BYTE_12                  (0xffUL<<0)
        #define MCPF_SMBUS_UDID1_3_BYTE_13                  (0xffUL<<8)
        #define MCPF_SMBUS_UDID1_3_BYTE_14                  (0xffUL<<16)
        #define MCPF_SMBUS_UDID1_3_BYTE_15                  (0xffUL<<24)

    u32_t mcpf_smbus_udid1_2;
        #define MCPF_SMBUS_UDID1_2_BYTE_8                   (0xffUL<<0)
        #define MCPF_SMBUS_UDID1_2_BYTE_9                   (0xffUL<<8)
        #define MCPF_SMBUS_UDID1_2_BYTE_10                  (0xffUL<<16)
        #define MCPF_SMBUS_UDID1_2_BYTE_11                  (0xffUL<<24)

    u32_t mcpf_smbus_udid1_1;
        #define MCPF_SMBUS_UDID1_1_BYTE_4                   (0xffUL<<0)
        #define MCPF_SMBUS_UDID1_1_BYTE_5                   (0xffUL<<8)
        #define MCPF_SMBUS_UDID1_1_BYTE_6                   (0xffUL<<16)
        #define MCPF_SMBUS_UDID1_1_BYTE_7                   (0xffUL<<24)

    u32_t mcpf_smbus_udid1_0;
        #define MCPF_SMBUS_UDID1_0_BYTE_0                   (0xffUL<<0)
        #define MCPF_SMBUS_UDID1_0_BYTE_1                   (0xffUL<<8)
        #define MCPF_SMBUS_UDID1_0_BYTE_2                   (0xffUL<<16)
        #define MCPF_SMBUS_UDID1_0_BYTE_3                   (0xffUL<<24)
    u32_t unused_8[468];

    u32_t mcpf_legacy_smb_asf_control;
        #define MCPF_LEGACY_SMB_ASF_CONTROL_ASF_RST         (1UL<<0)
        #define MCPF_LEGACY_SMB_ASF_CONTROL_TSC_EN          (1UL<<1)
        #define MCPF_LEGACY_SMB_ASF_CONTROL_WG_TO           (1UL<<2)
        #define MCPF_LEGACY_SMB_ASF_CONTROL_HB_TO           (1UL<<3)
        #define MCPF_LEGACY_SMB_ASF_CONTROL_PA_TO           (1UL<<4)
        #define MCPF_LEGACY_SMB_ASF_CONTROL_PL_TO           (1UL<<5)
        #define MCPF_LEGACY_SMB_ASF_CONTROL_RT_TO           (1UL<<6)
        #define MCPF_LEGACY_SMB_ASF_CONTROL_SMB_EVENT       (1UL<<7)
        #define MCPF_LEGACY_SMB_ASF_CONTROL_STRETCH_EN      (1UL<<8)
        #define MCPF_LEGACY_SMB_ASF_CONTROL_STRETCH_PULSE   (1UL<<9)
        #define MCPF_LEGACY_SMB_ASF_CONTROL_RES             (0x3UL<<10)
        #define MCPF_LEGACY_SMB_ASF_CONTROL_SMB_EN          (1UL<<12)
        #define MCPF_LEGACY_SMB_ASF_CONTROL_SMB_BB_EN       (1UL<<13)
        #define MCPF_LEGACY_SMB_ASF_CONTROL_SMB_NO_ADDR_FILT  (1UL<<14)
        #define MCPF_LEGACY_SMB_ASF_CONTROL_SMB_AUTOREAD    (1UL<<15)
        #define MCPF_LEGACY_SMB_ASF_CONTROL_NIC_SMB_ADDR1   (0x7fUL<<16)
        #define MCPF_LEGACY_SMB_ASF_CONTROL_NIC_SMB_ADDR2   (0x7fUL<<23)
        #define MCPF_LEGACY_SMB_ASF_CONTROL_EN_NIC_SMB_ADDR_0  (1UL<<30)
        #define MCPF_LEGACY_SMB_ASF_CONTROL_SMB_EARLY_ATTN  (1UL<<31)

    u32_t mcpf_legacy_smb_in;
        #define MCPF_LEGACY_SMB_IN_DAT_IN                   (0xffUL<<0)
        #define MCPF_LEGACY_SMB_IN_RDY                      (1UL<<8)
        #define MCPF_LEGACY_SMB_IN_DONE                     (1UL<<9)
        #define MCPF_LEGACY_SMB_IN_FIRSTBYTE                (1UL<<10)
        #define MCPF_LEGACY_SMB_IN_STATUS                   (0x7UL<<11)
            #define MCPF_LEGACY_SMB_IN_STATUS_OK            (0UL<<11)
            #define MCPF_LEGACY_SMB_IN_STATUS_PEC           (1UL<<11)
            #define MCPF_LEGACY_SMB_IN_STATUS_OFLOW         (2UL<<11)
            #define MCPF_LEGACY_SMB_IN_STATUS_STOP          (3UL<<11)
            #define MCPF_LEGACY_SMB_IN_STATUS_TIMEOUT       (4UL<<11)

    u32_t mcpf_legacy_smb_out;
        #define MCPF_LEGACY_SMB_OUT_DAT_OUT                 (0xffUL<<0)
        #define MCPF_LEGACY_SMB_OUT_RDY                     (1UL<<8)
        #define MCPF_LEGACY_SMB_OUT_START                   (1UL<<9)
        #define MCPF_LEGACY_SMB_OUT_LAST                    (1UL<<10)
        #define MCPF_LEGACY_SMB_OUT_ACC_TYPE                (1UL<<11)
        #define MCPF_LEGACY_SMB_OUT_ENB_PEC                 (1UL<<12)
        #define MCPF_LEGACY_SMB_OUT_GET_RX_LEN              (1UL<<13)
        #define MCPF_LEGACY_SMB_OUT_SMB_READ_LEN            (0x3fUL<<14)
        #define MCPF_LEGACY_SMB_OUT_SMB_OUT_STATUS          (0xfUL<<20)
            #define MCPF_LEGACY_SMB_OUT_SMB_OUT_STATUS_OK   (0UL<<20)
            #define MCPF_LEGACY_SMB_OUT_SMB_OUT_STATUS_FIRST_NACK  (1UL<<20)
            #define MCPF_LEGACY_SMB_OUT_SMB_OUT_STATUS_UFLOW  (2UL<<20)
            #define MCPF_LEGACY_SMB_OUT_SMB_OUT_STATUS_STOP  (3UL<<20)
            #define MCPF_LEGACY_SMB_OUT_SMB_OUT_STATUS_TIMEOUT  (4UL<<20)
            #define MCPF_LEGACY_SMB_OUT_SMB_OUT_STATUS_FIRST_LOST  (5UL<<20)
            #define MCPF_LEGACY_SMB_OUT_SMB_OUT_STATUS_BADACK  (6UL<<20)
            #define MCPF_LEGACY_SMB_OUT_SMB_OUT_STATUS_SUB_NACK  (9UL<<20)
            #define MCPF_LEGACY_SMB_OUT_SMB_OUT_STATUS_SUB_LOST  (13UL<<20)
        #define MCPF_LEGACY_SMB_OUT_SMB_OUT_SLAVEMODE       (1UL<<24)
        #define MCPF_LEGACY_SMB_OUT_SMB_OUT_DAT_EN          (1UL<<25)
        #define MCPF_LEGACY_SMB_OUT_SMB_OUT_DAT_IN          (1UL<<26)
        #define MCPF_LEGACY_SMB_OUT_SMB_OUT_CLK_EN          (1UL<<27)
        #define MCPF_LEGACY_SMB_OUT_SMB_OUT_CLK_IN          (1UL<<28)

    u32_t mcpf_legacy_smb_watchdog;
        #define MCPF_LEGACY_SMB_WATCHDOG_WATCHDOG           (0xffffUL<<0)

    u32_t mcpf_legacy_smb_heartbeat;
        #define MCPF_LEGACY_SMB_HEARTBEAT_HEARTBEAT         (0xffffUL<<0)

    u32_t mcpf_legacy_smb_poll_asf;
        #define MCPF_LEGACY_SMB_POLL_ASF_POLL_ASF           (0xffffUL<<0)

    u32_t mcpf_legacy_smb_poll_legacy;
        #define MCPF_LEGACY_SMB_POLL_LEGACY_POLL_LEGACY     (0xffffUL<<0)

    u32_t mcpf_legacy_smb_retran;
        #define MCPF_LEGACY_SMB_RETRAN_RETRAN               (0xffUL<<0)

    u32_t mcpf_legacy_smb_timestamp;
        #define MCPF_LEGACY_SMB_TIMESTAMP_TIMESTAMP         (0xffffffffUL<<0)
    u32_t unused_9[15863];

    u32_t mcpf_ump_cmd;
        #define MCPF_UMP_CMD_EGRESS_FIFO_ENABLED            (1UL<<0)
        #define MCPF_UMP_CMD_INGRESS_FIFO_ENABLED           (1UL<<1)
        #define MCPF_UMP_CMD_FC_EN                          (1UL<<2)
        #define MCPF_UMP_CMD_MAC_LOOPBACK                   (1UL<<3)
        #define MCPF_UMP_CMD_EGRESS_MAC_DISABLE             (1UL<<5)
        #define MCPF_UMP_CMD_INGRESS_MAC_DISABLE            (1UL<<6)
        #define MCPF_UMP_CMD_INGRESS_DRIVE                  (1UL<<8)
        #define MCPF_UMP_CMD_SW_PAUSE                       (1UL<<9)
        #define MCPF_UMP_CMD_AUTO_DRIVE                     (1UL<<13)
        #define MCPF_UMP_CMD_INGRESS_RESET                  (1UL<<14)
        #define MCPF_UMP_CMD_NO_PLUS_TWO                    (1UL<<15)
        #define MCPF_UMP_CMD_EGRESS_PKT_FLUSH               (1UL<<16)
        #define MCPF_UMP_CMD_CMD_IPG                        (0x1fUL<<17)
        #define MCPF_UMP_CMD_EGRESS_FIO_RESET               (1UL<<28)
        #define MCPF_UMP_CMD_INGRESS_FIO_RESET              (1UL<<29)
        #define MCPF_UMP_CMD_EGRESS_MAC_RESET               (1UL<<30)
        #define MCPF_UMP_CMD_INGRESS_MAC_RESET              (1UL<<31)

    u32_t mcpf_ump_config;
        #define MCPF_UMP_CONFIG_RMII_MODE                   (1UL<<4)
        #define MCPF_UMP_CONFIG_RVMII_MODE                  (1UL<<6)
        #define MCPF_UMP_CONFIG_INGRESS_MODE                (1UL<<7)
        #define MCPF_UMP_CONFIG_INGRESS_WORD_ACCM           (0xffUL<<8)

    u32_t mcpf_ump_fc_trip;
        #define MCPF_UMP_FC_TRIP_XON_TRIP                   (0x1ffUL<<0)
        #define MCPF_UMP_FC_TRIP_XOFF_TRIP                  (0x1ffUL<<16)
    u32_t unused_10[33];

    u32_t mcpf_ump_egress_frm_rd_status;
        #define MCPF_UMP_EGRESS_FRM_RD_STATUS_NEW_FRM       (1UL<<0)
        #define MCPF_UMP_EGRESS_FRM_RD_STATUS_FRM_IN_PRO    (1UL<<1)
        #define MCPF_UMP_EGRESS_FRM_RD_STATUS_FIFO_EMPTY    (1UL<<2)
        #define MCPF_UMP_EGRESS_FRM_RD_STATUS_BCNT          (0x7ffUL<<3)
        #define MCPF_UMP_EGRESS_FRM_RD_STATUS_EGRESS_FIFO_STATE  (0x1fUL<<27)
            #define MCPF_UMP_EGRESS_FRM_RD_STATUS_EGRESS_FIFO_STATE_IDLE  (0UL<<27)
            #define MCPF_UMP_EGRESS_FRM_RD_STATUS_EGRESS_FIFO_STATE_READY  (1UL<<27)
            #define MCPF_UMP_EGRESS_FRM_RD_STATUS_EGRESS_FIFO_STATE_BUSY  (2UL<<27)
            #define MCPF_UMP_EGRESS_FRM_RD_STATUS_EGRESS_FIFO_STATE_EXTRA_RD  (3UL<<27)
            #define MCPF_UMP_EGRESS_FRM_RD_STATUS_EGRESS_FIFO_STATE_LATCH_IP_HDR  (4UL<<27)

    u32_t mcpf_ump_egress_frm_rd_data;
    u32_t mcpf_ump_ingress_frm_wr_ctl;
        #define MCPF_UMP_INGRESS_FRM_WR_CTL_NEW_FRM         (1UL<<0)
        #define MCPF_UMP_INGRESS_FRM_WR_CTL_FIFO_RDY        (1UL<<1)
        #define MCPF_UMP_INGRESS_FRM_WR_CTL_BCNT_RDY        (1UL<<2)
        #define MCPF_UMP_INGRESS_FRM_WR_CTL_BCNT            (0x7ffUL<<3)
        #define MCPF_UMP_INGRESS_FRM_WR_CTL_INGRESS_FIFO_STATE  (0x3UL<<30)
            #define MCPF_UMP_INGRESS_FRM_WR_CTL_INGRESS_FIFO_STATE_IDLE  (0UL<<30)
            #define MCPF_UMP_INGRESS_FRM_WR_CTL_INGRESS_FIFO_STATE_WAIT  (1UL<<30)
            #define MCPF_UMP_INGRESS_FRM_WR_CTL_INGRESS_FIFO_STATE_BUSY  (2UL<<30)
            #define MCPF_UMP_INGRESS_FRM_WR_CTL_INGRESS_FIFO_STATE_EXTRA_WR  (3UL<<30)

    u32_t mcpf_ump_ingress_frm_wr_data;
    u32_t mcpf_ump_egress_frame_type;
    u32_t mcpf_ump_fifo_remaining_words;
        #define MCPF_UMP_FIFO_REMAINING_WORDS_EGRESS_FIFO_DEPTH  (0x7ffUL<<0)
        #define MCPF_UMP_FIFO_REMAINING_WORDS_INGRESS_FIFO_DEPTH  (0x3ffUL<<16)

    u32_t mcpf_ump_egress_fifo_ptrs;
        #define MCPF_UMP_EGRESS_FIFO_PTRS_EGRESS_FIFO_RD_PTR  (0xfffUL<<0)
        #define MCPF_UMP_EGRESS_FIFO_PTRS_UPDATE_RDPTR      (1UL<<15)
        #define MCPF_UMP_EGRESS_FIFO_PTRS_EGRESS_FIFO_WR_PTR  (0xfffUL<<16)
        #define MCPF_UMP_EGRESS_FIFO_PTRS_UPDATE_WRPTR      (1UL<<31)

    u32_t mcpf_ump_ingress_fifo_ptrs;
        #define MCPF_UMP_INGRESS_FIFO_PTRS_INGRESS_FIFO_RD_PTR  (0x7ffUL<<0)
        #define MCPF_UMP_INGRESS_FIFO_PTRS_UPDATE_RDPTR     (1UL<<15)
        #define MCPF_UMP_INGRESS_FIFO_PTRS_INGRESS_FIFO_WR_PTR  (0x7ffUL<<16)
        #define MCPF_UMP_INGRESS_FIFO_PTRS_UPDATE_WRPTR     (1UL<<31)
    u32_t unused_11;

    u32_t mcpf_ump_egress_packet_sa_0;
        #define MCPF_UMP_EGRESS_PACKET_SA_0_EGRESS_SA       (0xffffUL<<0)

    u32_t mcpf_ump_egress_packet_sa_1;
        #define MCPF_UMP_EGRESS_PACKET_SA_1_EGRESS_SA       (0xffffffffUL<<0)

    u32_t mcpf_ump_ingress_burst_command;
        #define MCPF_UMP_INGRESS_BURST_COMMAND_INGRESS_DMA_START  (1UL<<0)
        #define MCPF_UMP_INGRESS_BURST_COMMAND_INGRESS_PORT  (1UL<<1)
        #define MCPF_UMP_INGRESS_BURST_COMMAND_DMA_LENGTH   (0x7ffUL<<2)
        #define MCPF_UMP_INGRESS_BURST_COMMAND_RBUF_OFFSET  (0x3fffUL<<16)

    u32_t mcpf_ump_ingress_rbuf_cluster;
        #define MCPF_UMP_INGRESS_RBUF_CLUSTER_RBUF_CLUSTER  (0x1ffffffUL<<0)

    u32_t mcpf_ump_ingress_vlan;
        #define MCPF_UMP_INGRESS_VLAN_INGRESS_VLAN_TAG      (0xffffUL<<0)
        #define MCPF_UMP_INGRESS_VLAN_VLAN_INS              (1UL<<16)
        #define MCPF_UMP_INGRESS_VLAN_VLAN_DEL              (1UL<<17)

    u32_t mcpf_ump_ingress_burst_status;
        #define MCPF_UMP_INGRESS_BURST_STATUS_RESULT        (0x3UL<<0)
            #define MCPF_UMP_INGRESS_BURST_STATUS_RESULT_BUSY  (0UL<<0)
            #define MCPF_UMP_INGRESS_BURST_STATUS_RESULT_DONE  (1UL<<0)
            #define MCPF_UMP_INGRESS_BURST_STATUS_RESULT_ERR  (2UL<<0)
            #define MCPF_UMP_INGRESS_BURST_STATUS_RESULT_ERR1  (3UL<<0)

    u32_t mcpf_ump_egress_burst_command;
        #define MCPF_UMP_EGRESS_BURST_COMMAND_EGRESS_DMA_START  (1UL<<0)
        #define MCPF_UMP_EGRESS_BURST_COMMAND_EGRESS_PORT   (1UL<<1)
        #define MCPF_UMP_EGRESS_BURST_COMMAND_DMA_LENGTH    (0x7ffUL<<2)
        #define MCPF_UMP_EGRESS_BURST_COMMAND_TPBUF_OFFSET  (0x1fffUL<<16)

    u32_t mcpf_ump_egress_vlan;
        #define MCPF_UMP_EGRESS_VLAN_EGRESS_VLAN_TAG        (0xffffUL<<0)
        #define MCPF_UMP_EGRESS_VLAN_VLAN_INS               (1UL<<16)
        #define MCPF_UMP_EGRESS_VLAN_VLAN_DEL               (1UL<<17)

    u32_t mcpf_ump_egress_burst_status;
        #define MCPF_UMP_EGRESS_BURST_STATUS_RESULT         (0x3UL<<0)
            #define MCPF_UMP_EGRESS_BURST_STATUS_RESULT_BUSY  (0UL<<0)
            #define MCPF_UMP_EGRESS_BURST_STATUS_RESULT_DONE  (1UL<<0)
            #define MCPF_UMP_EGRESS_BURST_STATUS_RESULT_ERR0  (2UL<<0)
            #define MCPF_UMP_EGRESS_BURST_STATUS_RESULT_RSVD  (3UL<<0)

    u32_t mcpf_ump_egress_statistic;
        #define MCPF_UMP_EGRESS_STATISTIC_EGRESS_GOOD_CNT   (0xffffUL<<0)
        #define MCPF_UMP_EGRESS_STATISTIC_EGRESS_ERROR_CNT  (0xffUL<<16)
        #define MCPF_UMP_EGRESS_STATISTIC_EGRESS_DROP_CNT   (0xffUL<<24)

    u32_t mcpf_ump_ingress_statistic;
        #define MCPF_UMP_INGRESS_STATISTIC_INGRESS_PKT_CNT  (0xffffUL<<0)

    u32_t mcpf_ump_arb_cmd;
        #define MCPF_UMP_ARB_CMD_UMP_ID                     (0x7UL<<0)
        #define MCPF_UMP_ARB_CMD_UMP_ARB_DISABLE            (1UL<<4)
        #define MCPF_UMP_ARB_CMD_UMP_ARB_START              (1UL<<5)
        #define MCPF_UMP_ARB_CMD_UMP_ARB_BYPASS             (1UL<<6)
        #define MCPF_UMP_ARB_CMD_UMP_ARB_AUTOBYPASS         (1UL<<7)
        #define MCPF_UMP_ARB_CMD_UMP_ARB_TOKEN_IPG          (0x1fUL<<8)
        #define MCPF_UMP_ARB_CMD_UMP_ARB_TOKEN_VALID        (1UL<<13)
        #define MCPF_UMP_ARB_CMD_UMP_ARB_FC_DISABLE         (1UL<<15)
        #define MCPF_UMP_ARB_CMD_UMP_ARB_TIMEOUT            (0xffffUL<<16)
    u32_t unused_12[3];

    u32_t mcpf_ump_egress_statistic_ac;
        #define MCPF_UMP_EGRESS_STATISTIC_AC_EGRESS_GOOD_CNT  (0xffffUL<<0)
        #define MCPF_UMP_EGRESS_STATISTIC_AC_EGRESS_ERROR_CNT  (0xffUL<<16)
        #define MCPF_UMP_EGRESS_STATISTIC_AC_EGRESS_DROP_CNT  (0xffUL<<24)

    u32_t mcpf_ump_ingress_statistic_ac;
        #define MCPF_UMP_INGRESS_STATISTIC_AC_INGRESS_PKT_CNT  (0xffffUL<<0)

    u32_t mcpf_ump_event;
        #define MCPF_UMP_EVENT_INGRESS_RDY_EVENT            (1UL<<0)
        #define MCPF_UMP_EVENT_EGRESS_RDY_EVENT             (1UL<<1)
        #define MCPF_UMP_EVENT_INGRESSBURST_DONE_EVENT      (1UL<<2)
        #define MCPF_UMP_EVENT_EGRESSBURST_DONE_EVENT       (1UL<<3)
        #define MCPF_UMP_EVENT_EGRESS_FRAME_DROP_EVENT      (1UL<<4)
        #define MCPF_UMP_EVENT_INGRESS_RDY_EVENT_EN         (1UL<<16)
        #define MCPF_UMP_EVENT_EGRESS_RDY_EVENT_EN          (1UL<<17)
        #define MCPF_UMP_EVENT_INGRESSBURST_DONE_EVENT_EN   (1UL<<18)
        #define MCPF_UMP_EVENT_EGRESSBURST_DONE_EVENT_EN    (1UL<<19)
        #define MCPF_UMP_EVENT_EGRESS_FRAME_DROP_EVENT_EN   (1UL<<20)
    u32_t unused_13[4033];

    u32_t mcpf_ump_egress_fifo_flat_space[1920];
    u32_t unused_14[128];
    u32_t mcpf_ump_ingress_fifo_flat_space[768];
} mcp_fio_xi_t;







/*
 *  msqe_b definition
 */
typedef struct msqe_b
{
    u8_t msqe_cmd_type;
    u8_t msqe_retx_num;
    u16_t msqe_ctx_index;
    u32_t msqe_tcp_seq;
} msqe_b_t;



/*
 *  msqe_b definition
 */
typedef struct msqe_b_xi
{
    u8_t msqe_cmd_type;
    u8_t msqe_retx_num;
    u16_t msqe_ctx_index;
    u32_t msqe_tcp_seq;
} msqe_b_xi_t;


/*
 *  msqe_l definition
 */
typedef struct msqe_l
{
    u16_t msqe_ctx_index;
    u8_t msqe_retx_num;
    u8_t msqe_cmd_type;
    u32_t msqe_tcp_seq;
} msqe_l_t;



/*
 *  msqe_l definition
 */
typedef struct msqe_l_xi
{
    u16_t msqe_ctx_index;
    u8_t msqe_retx_num;
    u8_t msqe_cmd_type;
    u32_t msqe_tcp_seq;
} msqe_l_xi_t;


/*
 * msqe select
 */
#if defined(LITTLE_ENDIAN)
    typedef msqe_l_t msqe_t;
    typedef msqe_l_xi_t msqe_xi_t;
#elif defined(BIG_ENDIAN)
    typedef msqe_b_t msqe_t;
    typedef msqe_b_xi_t msqe_xi_t;
#endif


/*
 *  msq_context_b definition
 */
typedef struct msq_context_b
{
    u8_t msq_ctx_type;

    u8_t msq_ctx_size;
    u8_t msq_pidx;
    u8_t msq_cidx;
    u32_t msq_joe;
    msqe_b_t msq_q[15];
} msq_context_b_t;



/*
 *  msq_context_b definition
 */
typedef struct msq_context_b_xi
{
    u8_t msq_ctx_type;
        #define MSQ_CTX_TYPE_TYPE                           (0xf<<4)
            #define MSQ_CTX_TYPE_TYPE_EMPTY                 (0<<4)
            #define MSQ_CTX_TYPE_TYPE_L2                    (1<<4)
            #define MSQ_CTX_TYPE_TYPE_TCP                   (2<<4)
            #define MSQ_CTX_TYPE_TYPE_L5                    (3<<4)
            #define MSQ_CTX_TYPE_TYPE_L2_BD_CHN             (4<<4)
            #define MSQ_CTX_TYPE_TYPE_CP_MSG                (5<<4)

    u8_t msq_ctx_size;
    u8_t msq_pidx;
    u8_t msq_cidx;
    u32_t msq_joe;
    msqe_b_xi_t msq_q[15];
} msq_context_b_xi_t;


/*
 *  msq_context_l definition
 */
typedef struct msq_context_l
{
    u8_t msq_cidx;
    u8_t msq_pidx;
    u8_t msq_ctx_size;
    u8_t msq_ctx_type;

    u32_t msq_joe;
    msqe_l_t msq_q[15];
} msq_context_l_t;



/*
 *  msq_context_l definition
 */
typedef struct msq_context_l_xi
{
    u8_t msq_cidx;
    u8_t msq_pidx;
    u8_t msq_ctx_size;
    u8_t msq_ctx_type;
        #define MSQ_CTX_TYPE_TYPE                           (0xf<<4)
            #define MSQ_CTX_TYPE_TYPE_EMPTY                 (0<<4)
            #define MSQ_CTX_TYPE_TYPE_L2                    (1<<4)
            #define MSQ_CTX_TYPE_TYPE_TCP                   (2<<4)
            #define MSQ_CTX_TYPE_TYPE_L5                    (3<<4)
            #define MSQ_CTX_TYPE_TYPE_L2_BD_CHN             (4<<4)
            #define MSQ_CTX_TYPE_TYPE_CP_MSG                (5<<4)

    u32_t msq_joe;
    msqe_l_xi_t msq_q[15];
} msq_context_l_xi_t;


/*
 * msq_context select
 */
#if defined(LITTLE_ENDIAN)
    typedef msq_context_l_t msq_context_t;
    typedef msq_context_l_xi_t msq_context_xi_t;
#elif defined(BIG_ENDIAN)
    typedef msq_context_b_t msq_context_t;
    typedef msq_context_b_xi_t msq_context_xi_t;
#endif


#define ROFFSET(_field) \
    ((u32_t) (((u8_t *) &(((reg_space_t *) 0)->_field)) - ((u8_t *) 0)))

/*
 * TX header Q and payload Q
 */
#define HDRQ_NBYTES     (1<<13)
#define HDRQ_MASK       (u16_t)(HDRQ_NBYTES - 1)
#define PLDQ_NBYTES     (1<<13)
#define PLDQ_MASK       (u32_t)(PLDQ_NBYTES - 1)


#endif

