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

#ifndef _RXP_HSI_H
#define _RXP_HSI_H

#define RSS_TABLE_MAX           128

// Offset of xxx_hsi in 32 bit words from beginning of scratchpad
#define RXP_HSI_OFFSET 0x4

typedef struct _rxp_hsi_t {
    fw_version_t version;
    u32_t rxp_knum; 
    u32_t rxp_flood;
    u32_t ric; 
    u32_t l2_forward_to_mcp; 
    u32_t tcp_syn_dos_defense; 
    u32_t rss_enable;   
    u32_t rss_table_size;   
    u8_t  rss_table[RSS_TABLE_MAX]; 
    u32_t rxp_os_flag; 
    u32_t discard_all;     
    u32_t rxp_num_discard_all;     
    u32_t rtca;     
    u32_t rtcc;     
    u32_t rxp_pm_ctrl;
        #define L2_NORMAL_MODE              0
        #define L2_EMC_RXQ_MODE_ENABLE      1
        #define L2_EMC_RXQ_MODE_DISABLE     2
    u32_t ooo_pkt_cnt;  
    u32_t l2_cu_cnt;  
    u32_t rxp_invalid_context_cnt;
    u64_t rxp_unicast_bytes_rcvd; 
    u64_t rxp_multicast_bytes_rcvd;
    u64_t rxp_broadcast_bytes_rcvd;
    u64_t volatile idle_count;
    u32_t hash_lookup[12][256];
    u32_t ulp_out_of_order_packets;     // number of OOO packets that were received in L5 connections
    u32_t cps_index;
    u32_t cps_array[32];
    u32_t iscsi_rq_size;                // number of RQ buffers. Note this is not size of page table
    u32_t iscsi_rq_buf_size;            // size of receive buffer in RQ
    u32_t iscsi_err_bitmap[2];          // Error/Warning bitmap ("1" for warning)
    u32_t iscsi_tcp_config;             // Configuration register - Enable/Disable of DA/KA mechanisms
    u32_t iscsi_teton_l4_cmd_offset;    // Teton only: offset of L4 ccell command array
    u32_t iscsi_teton_l5_offset;        // Teton only: offset of L5 section
    u32_t iscsi_teton_l5_cmd_offset;    // Teton only: offset of L5 ccell command array
    u32_t iscsi_task_offset;            // offset of the task array
    u32_t iscsi_r2tq_offset;            // offset of R2TQ section
    u32_t iscsi_max_num_of_tasks;       // maximal number of pending tasks 
    u32_t iscsi_max_num_of_ccells;      // maximal number of ccells

    u64_t iscsi_rxp_unicast_bytes_rcvd; 
    u64_t iscsi_rxp_multicast_bytes_rcvd;
    u64_t iscsi_rxp_broadcast_bytes_rcvd;
    u32_t after_fin_pkt_cnt;            // number of packets that came after FIN
    u32_t extra_fin_pkt_cnt;            // extra FIN packets that came after FIN
    u32_t vmq_netq_cnt;                 // number of vmq or netq  
    u32_t hw_filter_ctx_offset;                         
    u32_t iooo_rx_cid;
    u32_t iooo_flags;
    u32_t iooo_dbg_size;
    u32_t iooo_dbg_ptr;
    u32_t ooo_cu_pkt_cnt;
    u32_t ooo_cu_pkt_drop_cnt;
    u32_t ooo_max_blk_reach_cnt;
    u32_t ooo_max_blk_pkt_drop_cnt;
    u32_t cu_rate_limiter_enable;
    u32_t ooo_max_blk_per_conn;
    u64_t rxp_total_bytes_rcvd;
} rxp_hsi_t;

// This macro can be used for little or big endian 32-bit system
#define RXP_HSI_OFFSETOFF(m)  (OFFSETOF(rxp_hsi_t,m) + 0x10)
#define RXP_HSI_SIZEOF(m)     (sizeof (((rxp_hsi_t *)0)->m))

// Calling the following macro will actually get optimized during compile 
// time. Its sole purpose is to ensure HSI variables cannot be modified/moved 
// unnoticed     scratch[10240] 0xe0000 (RW/Reset: undefined)
#define TEST_RXP_HSI(){                                                   \
if (0){                                                                    \
 1/(RXP_HSI_OFFSETOFF(version)                       == (RXP_HSI_OFFSET * sizeof(u32_t) + 0x000) &&  \
    RXP_HSI_OFFSETOFF(rxp_knum)                      == (RXP_HSI_OFFSET * sizeof(u32_t) + 0x010) &&  \
    RXP_HSI_OFFSETOFF(rxp_flood)                     == (RXP_HSI_OFFSET * sizeof(u32_t) + 0x014) &&  \
    RXP_HSI_OFFSETOFF(ric)                           == (RXP_HSI_OFFSET * sizeof(u32_t) + 0x018) &&  \
    RXP_HSI_OFFSETOFF(l2_forward_to_mcp)             == (RXP_HSI_OFFSET * sizeof(u32_t) + 0x01c) &&  \
    RXP_HSI_OFFSETOFF(tcp_syn_dos_defense)           == (RXP_HSI_OFFSET * sizeof(u32_t) + 0x020) &&  \
    RXP_HSI_OFFSETOFF(rss_enable)                    == (RXP_HSI_OFFSET * sizeof(u32_t) + 0x024) &&  \
    RXP_HSI_OFFSETOFF(rss_table_size)                == (RXP_HSI_OFFSET * sizeof(u32_t) + 0x028) &&  \
    RXP_HSI_OFFSETOFF(rss_table)                     == (RXP_HSI_OFFSET * sizeof(u32_t) + 0x02c) &&  \
    RXP_HSI_OFFSETOFF(rxp_os_flag)                   == (RXP_HSI_OFFSET * sizeof(u32_t) + 0x0ac) &&  \
    RXP_HSI_OFFSETOFF(discard_all)                   == (RXP_HSI_OFFSET * sizeof(u32_t) + 0x0b0) &&  \
    RXP_HSI_OFFSETOFF(rxp_num_discard_all)           == (RXP_HSI_OFFSET * sizeof(u32_t) + 0x0b4) &&  \
    RXP_HSI_OFFSETOFF(rtca)                          == (RXP_HSI_OFFSET * sizeof(u32_t) + 0x0b8) &&  \
    RXP_HSI_OFFSETOFF(rtcc)                          == (RXP_HSI_OFFSET * sizeof(u32_t) + 0x0bc) &&  \
    RXP_HSI_OFFSETOFF(rxp_pm_ctrl)                   == (RXP_HSI_OFFSET * sizeof(u32_t) + 0x0c0) &&  \
    RXP_HSI_OFFSETOFF(ooo_pkt_cnt)                   == (RXP_HSI_OFFSET * sizeof(u32_t) + 0x0c4) &&  \
    RXP_HSI_OFFSETOFF(l2_cu_cnt)                     == (RXP_HSI_OFFSET * sizeof(u32_t) + 0x0c8) &&  \
    RXP_HSI_OFFSETOFF(rxp_invalid_context_cnt)       == (RXP_HSI_OFFSET * sizeof(u32_t) + 0x0cc) &&  \
    RXP_HSI_OFFSETOFF(rxp_unicast_bytes_rcvd)        == (RXP_HSI_OFFSET * sizeof(u32_t) + 0x0d0) &&  \
    RXP_HSI_OFFSETOFF(rxp_multicast_bytes_rcvd)      == (RXP_HSI_OFFSET * sizeof(u32_t) + 0x0d8) &&  \
    RXP_HSI_OFFSETOFF(rxp_broadcast_bytes_rcvd)      == (RXP_HSI_OFFSET * sizeof(u32_t) + 0x0e0) &&  \
    RXP_HSI_OFFSETOFF(idle_count)                    == (RXP_HSI_OFFSET * sizeof(u32_t) + 0x0e8) &&  \
    RXP_HSI_OFFSETOFF(hash_lookup)                   == (RXP_HSI_OFFSET * sizeof(u32_t) + 0x0f0) &&  \
    RXP_HSI_OFFSETOFF(ulp_out_of_order_packets)      == (RXP_HSI_OFFSET * sizeof(u32_t) +0x30f0) &&  \
    RXP_HSI_OFFSETOFF(cps_index)                     == (RXP_HSI_OFFSET * sizeof(u32_t) +0x30f4) &&  \
    RXP_HSI_OFFSETOFF(cps_array)                     == (RXP_HSI_OFFSET * sizeof(u32_t) +0x30f8) &&  \
    RXP_HSI_OFFSETOFF(iscsi_rq_size)                 == (RXP_HSI_OFFSET * sizeof(u32_t) +0x3178) &&  \
    RXP_HSI_OFFSETOFF(iscsi_rq_buf_size)             == (RXP_HSI_OFFSET * sizeof(u32_t) +0x317c) &&  \
    RXP_HSI_OFFSETOFF(iscsi_err_bitmap[0])           == (RXP_HSI_OFFSET * sizeof(u32_t) +0x3180) &&  \
    RXP_HSI_OFFSETOFF(iscsi_err_bitmap[1])           == (RXP_HSI_OFFSET * sizeof(u32_t) +0x3184) &&  \
    RXP_HSI_OFFSETOFF(iscsi_tcp_config)              == (RXP_HSI_OFFSET * sizeof(u32_t) +0x3188) &&  \
    RXP_HSI_OFFSETOFF(iscsi_teton_l4_cmd_offset)     == (RXP_HSI_OFFSET * sizeof(u32_t) +0x318c) &&  \
    RXP_HSI_OFFSETOFF(iscsi_teton_l5_offset)         == (RXP_HSI_OFFSET * sizeof(u32_t) +0x3190) &&  \
    RXP_HSI_OFFSETOFF(iscsi_teton_l5_cmd_offset)     == (RXP_HSI_OFFSET * sizeof(u32_t) +0x3194) &&  \
    RXP_HSI_OFFSETOFF(iscsi_task_offset)             == (RXP_HSI_OFFSET * sizeof(u32_t) +0x3198) &&  \
    RXP_HSI_OFFSETOFF(iscsi_r2tq_offset)             == (RXP_HSI_OFFSET * sizeof(u32_t) +0x319c) &&  \
    RXP_HSI_OFFSETOFF(iscsi_max_num_of_tasks)        == (RXP_HSI_OFFSET * sizeof(u32_t) +0x31a0) &&  \
    RXP_HSI_OFFSETOFF(iscsi_max_num_of_ccells)       == (RXP_HSI_OFFSET * sizeof(u32_t) +0x31a4) &&  \
    RXP_HSI_OFFSETOFF(iscsi_rxp_unicast_bytes_rcvd)  == (RXP_HSI_OFFSET * sizeof(u32_t) +0x31a8) &&  \
    RXP_HSI_OFFSETOFF(iscsi_rxp_multicast_bytes_rcvd)== (RXP_HSI_OFFSET * sizeof(u32_t) +0x31b0) &&  \
    RXP_HSI_OFFSETOFF(iscsi_rxp_broadcast_bytes_rcvd)== (RXP_HSI_OFFSET * sizeof(u32_t) +0x31b8) &&  \
    RXP_HSI_OFFSETOFF(after_fin_pkt_cnt)             == (RXP_HSI_OFFSET * sizeof(u32_t) +0x31c0) &&  \
    RXP_HSI_OFFSETOFF(extra_fin_pkt_cnt)             == (RXP_HSI_OFFSET * sizeof(u32_t) +0x31c4) &&  \
    RXP_HSI_OFFSETOFF(vmq_netq_cnt)                  == (RXP_HSI_OFFSET * sizeof(u32_t) +0x31c8) &&  \
    RXP_HSI_OFFSETOFF(hw_filter_ctx_offset)          == (RXP_HSI_OFFSET * sizeof(u32_t) +0x31cc) &&  \
    RXP_HSI_OFFSETOFF(iooo_rx_cid)                   == (RXP_HSI_OFFSET * sizeof(u32_t) +0x31d0) &&  \
    RXP_HSI_OFFSETOFF(iooo_flags)                    == (RXP_HSI_OFFSET * sizeof(u32_t) +0x31d4) &&  \
    RXP_HSI_OFFSETOFF(iooo_dbg_size)                 == (RXP_HSI_OFFSET * sizeof(u32_t) +0x31d8) &&  \
    RXP_HSI_OFFSETOFF(iooo_dbg_ptr)                  == (RXP_HSI_OFFSET * sizeof(u32_t) +0x31dc) &&  \
    RXP_HSI_OFFSETOFF(ooo_cu_pkt_cnt)                == (RXP_HSI_OFFSET * sizeof(u32_t) +0x31e0) &&  \
    RXP_HSI_OFFSETOFF(ooo_cu_pkt_drop_cnt)           == (RXP_HSI_OFFSET * sizeof(u32_t) +0x31e4) &&  \
    RXP_HSI_OFFSETOFF(ooo_max_blk_reach_cnt)         == (RXP_HSI_OFFSET * sizeof(u32_t) +0x31e8) &&  \
    RXP_HSI_OFFSETOFF(ooo_max_blk_pkt_drop_cnt)      == (RXP_HSI_OFFSET * sizeof(u32_t) +0x31ec) &&  \
    RXP_HSI_OFFSETOFF(cu_rate_limiter_enable)        == (RXP_HSI_OFFSET * sizeof(u32_t) +0x31f0) &&  \
    RXP_HSI_OFFSETOFF(ooo_max_blk_per_conn)          == (RXP_HSI_OFFSET * sizeof(u32_t) +0x31f4) &&  \
    RXP_HSI_OFFSETOFF(rxp_total_bytes_rcvd)          == (RXP_HSI_OFFSET * sizeof(u32_t) +0x31f8) &&  \
    RXP_HSI_OFFSETOFF(rxp_total_bytes_rcvd)+RXP_HSI_SIZEOF(rxp_total_bytes_rcvd) == (RXP_HSI_OFFSET * sizeof(u32_t) + sizeof(rxp_hsi_t)));}}
#endif

