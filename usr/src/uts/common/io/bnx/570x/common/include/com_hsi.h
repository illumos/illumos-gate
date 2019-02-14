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


#ifndef _COM_HSI_H
#define _COM_HSI_H

// Offset of xxx_hsi in 32 bit words from beginning of scratchpad
#define COM_HSI_OFFSET 0x4

typedef struct _com_hsi_t {
    fw_version_t version;
    u32_t fw_doorbell;        
        #define KCQ_READY        (1<<0)
        #define KCQ1_READY       (1<<1)
        #define KCQ2_READY       (1<<2)
        #define KCQ3_READY       (1<<3)
    u32_t dups;        
    u32_t dacks;
    u32_t pushs;
    u32_t compbits;
    u32_t num_comq;  
    u32_t num_comtq; 
    u32_t num_comxq; 
    u32_t unused_num_fail_reloads;   
    u32_t rx_place;      
    u32_t rtxs;          //  max_retx_cnt : maximum number of tcp retries
    u32_t min_rto_tick;  //  min_rto (in ticks of retx timer)
    u32_t max_rto_tick;  //  max_rto (in ticks of retx timer)
    u32_t max_caf;       // max allowed ack frequency 
    u32_t false_ooo_fin_cnt;   
    u32_t l2_forward_to_mcp; 
    u32_t l2_drop_mcpq_busy;  
    u32_t drtxs;        // doubt reacheability tx count threshold (rfc 2923)
                        // drtxs - maximum number of times that the offload target should 
                        // retransmit a segment before indicating to the host stack that 
                        // the reachability of a neighbor is in doubt.  
    u32_t abort_ooo_fin_cnt;
    u32_t total_ooo_fin_cnt;
    u32_t caus;
    u32_t dtic;
    u32_t defer_ooo_fin_cnt;
    u32_t l4_drop_cnt;  // number of l4 packets dropped by RV2P
    u32_t cozr;
    u32_t com_l2_no_buffer; 
    u32_t com_cu_host_bseq;  
    u32_t tnda;  
    u32_t tcnas; 
    u32_t tccas; 
    u32_t caf;          // ack frequency
    u32_t cmpl_dbg_cnt;  
    u32_t hcwa_kwq_cons_idx;  
    u32_t hcwa_last_kwq_cons_idx; 
    u32_t eaiv;
    u32_t reload_aft_fin_cnt;           // Number of reload after FIN
    u32_t enable_fast_iscsi_response;
    u32_t tsch_restart;
    u64_t volatile idle_count;
    u32_t iscsi_rtxs;                   // Number of retransmissions in iSCSI
    u32_t iscsi_cq_size;                // Number of elements in queue. Its k lsb bits must be 0. bit 0 - arm bit - means CQ is armed
    u32_t iscsi_cq_cqes_per_page;       // Number of CQEs per page
    u32_t iscsi_cq_num_pages;           // Number of pages of CQ ( = entries in page table)
    u32_t iscsi_cq_cqes_per_page_log2;  // Log2 of the Number of CQEs per page 
    u32_t iscsi_data_dig_err;           // Indication on Error="1" / Warning="0" of data digest
    u32_t iscsi_tcp_config;             // Configuration register - Enable/Disable of DA/KA mechanisms
    u32_t iscsi_teton_l4_cmd_offset;    // Teton Only: offset of L4 ccell command array
    u32_t iscsi_teton_l5_offset;        // Teton Only: offset of L5 section
    u32_t iscsi_teton_l5_cmd_offset;    // Teton Only: offset of L5 ccell command array
    u32_t iscsi_task_offset;            // offset of the task array
    u32_t iscsi_r2tq_offset;            // offset of R2TQ section
    u32_t iscsi_max_num_of_tasks;       // maximal number of pending tasks 
    u32_t iscsi_max_num_of_ccells;      // maximal number of ccells                                 
    u32_t com_cu_buf_size;                                               
    u32_t com_l2_iscsi_no_buffer; 
    u32_t com_unicast_no_buffer; 
    u32_t com_mcast_no_buffer; 
    u32_t com_bcast_no_buffer; 
    u32_t l2_drop_pkt_cnt;  // keep tracks of packet drop requested by RXP (e.g. not enough bytes in BD to place the pkt)                                                
    u32_t com_cu_free_cnt;
    u32_t cu_rate_limiter_enable;
}com_hsi_t;

// This macro can be used for little or big endian 32-bit system
#define COM_HSI_OFFSETOFF(m)  (OFFSETOF(com_hsi_t,m) + 0x10)
#define COM_HSI_SIZEOF(m)     (sizeof (((com_hsi_t *)0)->m))

// Calling the following macro will actually get optimized during compile 
// time. Its sole purpose is to ensure HSI variables cannot be modified/moved 
// unnoticed   scratch[10240] 0x120000 (RW/Reset: undefined)
#define TEST_COM_HSI(){                                                    \
if (0){                                                                    \
 1/(COM_HSI_OFFSETOFF(version)                       == (COM_HSI_OFFSET * sizeof(u32_t) + 0x000) &&  \
    COM_HSI_OFFSETOFF(fw_doorbell)                   == (COM_HSI_OFFSET * sizeof(u32_t) + 0x010) &&  \
    COM_HSI_OFFSETOFF(dups)                          == (COM_HSI_OFFSET * sizeof(u32_t) + 0x014) &&  \
    COM_HSI_OFFSETOFF(dacks)                         == (COM_HSI_OFFSET * sizeof(u32_t) + 0x018) &&  \
    COM_HSI_OFFSETOFF(pushs)                         == (COM_HSI_OFFSET * sizeof(u32_t) + 0x01c) &&  \
    COM_HSI_OFFSETOFF(compbits)                      == (COM_HSI_OFFSET * sizeof(u32_t) + 0x020) &&  \
    COM_HSI_OFFSETOFF(num_comq)                      == (COM_HSI_OFFSET * sizeof(u32_t) + 0x024) &&  \
    COM_HSI_OFFSETOFF(num_comtq)                     == (COM_HSI_OFFSET * sizeof(u32_t) + 0x028) &&  \
    COM_HSI_OFFSETOFF(num_comxq)                     == (COM_HSI_OFFSET * sizeof(u32_t) + 0x02c) &&  \
    COM_HSI_OFFSETOFF(unused_num_fail_reloads)       == (COM_HSI_OFFSET * sizeof(u32_t) + 0x030) &&  \
    COM_HSI_OFFSETOFF(rx_place)                      == (COM_HSI_OFFSET * sizeof(u32_t) + 0x034) &&  \
    COM_HSI_OFFSETOFF(rtxs)                          == (COM_HSI_OFFSET * sizeof(u32_t) + 0x038) &&  \
    COM_HSI_OFFSETOFF(min_rto_tick)                  == (COM_HSI_OFFSET * sizeof(u32_t) + 0x03c) &&  \
    COM_HSI_OFFSETOFF(max_rto_tick)                  == (COM_HSI_OFFSET * sizeof(u32_t) + 0x040) &&  \
    COM_HSI_OFFSETOFF(max_caf)                       == (COM_HSI_OFFSET * sizeof(u32_t) + 0x044) &&  \
    COM_HSI_OFFSETOFF(false_ooo_fin_cnt)             == (COM_HSI_OFFSET * sizeof(u32_t) + 0x048) &&  \
    COM_HSI_OFFSETOFF(l2_forward_to_mcp)             == (COM_HSI_OFFSET * sizeof(u32_t) + 0x04c) &&  \
    COM_HSI_OFFSETOFF(l2_drop_mcpq_busy)             == (COM_HSI_OFFSET * sizeof(u32_t) + 0x050) &&  \
    COM_HSI_OFFSETOFF(drtxs)                         == (COM_HSI_OFFSET * sizeof(u32_t) + 0x054) &&  \
    COM_HSI_OFFSETOFF(abort_ooo_fin_cnt)             == (COM_HSI_OFFSET * sizeof(u32_t) + 0x058) &&  \
    COM_HSI_OFFSETOFF(total_ooo_fin_cnt)             == (COM_HSI_OFFSET * sizeof(u32_t) + 0x05c) &&  \
    COM_HSI_OFFSETOFF(caus)                          == (COM_HSI_OFFSET * sizeof(u32_t) + 0x060) &&  \
    COM_HSI_OFFSETOFF(dtic)                          == (COM_HSI_OFFSET * sizeof(u32_t) + 0x064) &&  \
    COM_HSI_OFFSETOFF(defer_ooo_fin_cnt)             == (COM_HSI_OFFSET * sizeof(u32_t) + 0x068) &&  \
    COM_HSI_OFFSETOFF(l4_drop_cnt)                   == (COM_HSI_OFFSET * sizeof(u32_t) + 0x06c) &&  \
    COM_HSI_OFFSETOFF(cozr)                          == (COM_HSI_OFFSET * sizeof(u32_t) + 0x070) &&  \
    COM_HSI_OFFSETOFF(com_l2_no_buffer)              == (COM_HSI_OFFSET * sizeof(u32_t) + 0x074) &&  \
    COM_HSI_OFFSETOFF(com_cu_host_bseq)              == (COM_HSI_OFFSET * sizeof(u32_t) + 0x078) &&  \
    COM_HSI_OFFSETOFF(tnda)                          == (COM_HSI_OFFSET * sizeof(u32_t) + 0x07c) &&  \
    COM_HSI_OFFSETOFF(tcnas)                         == (COM_HSI_OFFSET * sizeof(u32_t) + 0x080) &&  \
    COM_HSI_OFFSETOFF(tccas)                         == (COM_HSI_OFFSET * sizeof(u32_t) + 0x084) &&  \
    COM_HSI_OFFSETOFF(caf)                           == (COM_HSI_OFFSET * sizeof(u32_t) + 0x088) &&  \
    COM_HSI_OFFSETOFF(cmpl_dbg_cnt)                  == (COM_HSI_OFFSET * sizeof(u32_t) + 0x08c) &&  \
    COM_HSI_OFFSETOFF(hcwa_kwq_cons_idx)             == (COM_HSI_OFFSET * sizeof(u32_t) + 0x090) &&  \
    COM_HSI_OFFSETOFF(hcwa_last_kwq_cons_idx)        == (COM_HSI_OFFSET * sizeof(u32_t) + 0x094) &&  \
    COM_HSI_OFFSETOFF(eaiv)                          == (COM_HSI_OFFSET * sizeof(u32_t) + 0x098) &&  \
    COM_HSI_OFFSETOFF(reload_aft_fin_cnt)            == (COM_HSI_OFFSET * sizeof(u32_t) + 0x09c) &&  \
    COM_HSI_OFFSETOFF(enable_fast_iscsi_response)    == (COM_HSI_OFFSET * sizeof(u32_t) + 0x0a0) &&  \
    COM_HSI_OFFSETOFF(tsch_restart)                  == (COM_HSI_OFFSET * sizeof(u32_t) + 0x0a4) &&  \
    COM_HSI_OFFSETOFF(idle_count)                    == (COM_HSI_OFFSET * sizeof(u32_t) + 0x0a8) &&  \
    COM_HSI_OFFSETOFF(iscsi_rtxs)                    == (COM_HSI_OFFSET * sizeof(u32_t) + 0x0b0) &&  \
    COM_HSI_OFFSETOFF(iscsi_cq_size)                 == (COM_HSI_OFFSET * sizeof(u32_t) + 0x0b4) &&  \
    COM_HSI_OFFSETOFF(iscsi_cq_cqes_per_page)        == (COM_HSI_OFFSET * sizeof(u32_t) + 0x0b8) &&  \
    COM_HSI_OFFSETOFF(iscsi_cq_num_pages)            == (COM_HSI_OFFSET * sizeof(u32_t) + 0x0bc) &&  \
    COM_HSI_OFFSETOFF(iscsi_cq_cqes_per_page_log2)   == (COM_HSI_OFFSET * sizeof(u32_t) + 0x0c0) &&  \
    COM_HSI_OFFSETOFF(iscsi_data_dig_err)            == (COM_HSI_OFFSET * sizeof(u32_t) + 0x0c4) &&  \
    COM_HSI_OFFSETOFF(iscsi_tcp_config)              == (COM_HSI_OFFSET * sizeof(u32_t) + 0x0c8) &&  \
    COM_HSI_OFFSETOFF(iscsi_teton_l4_cmd_offset)     == (COM_HSI_OFFSET * sizeof(u32_t) + 0x0cc) &&  \
    COM_HSI_OFFSETOFF(iscsi_teton_l5_offset)         == (COM_HSI_OFFSET * sizeof(u32_t) + 0x0d0) &&  \
    COM_HSI_OFFSETOFF(iscsi_teton_l5_cmd_offset)     == (COM_HSI_OFFSET * sizeof(u32_t) + 0x0d4) &&  \
    COM_HSI_OFFSETOFF(iscsi_task_offset)             == (COM_HSI_OFFSET * sizeof(u32_t) + 0x0d8) &&  \
    COM_HSI_OFFSETOFF(iscsi_r2tq_offset)             == (COM_HSI_OFFSET * sizeof(u32_t) + 0x0dc) &&  \
    COM_HSI_OFFSETOFF(iscsi_max_num_of_tasks)        == (COM_HSI_OFFSET * sizeof(u32_t) + 0x0e0) &&  \
    COM_HSI_OFFSETOFF(iscsi_max_num_of_ccells)       == (COM_HSI_OFFSET * sizeof(u32_t) + 0x0e4) &&  \
    COM_HSI_OFFSETOFF(com_cu_buf_size)               == (COM_HSI_OFFSET * sizeof(u32_t) + 0x0e8) &&  \
    COM_HSI_OFFSETOFF(com_l2_iscsi_no_buffer)        == (COM_HSI_OFFSET * sizeof(u32_t) + 0x0ec) &&  \
    COM_HSI_OFFSETOFF(com_unicast_no_buffer)         == (COM_HSI_OFFSET * sizeof(u32_t) + 0x0f0) &&  \
    COM_HSI_OFFSETOFF(com_mcast_no_buffer)           == (COM_HSI_OFFSET * sizeof(u32_t) + 0x0f4) &&  \
    COM_HSI_OFFSETOFF(com_bcast_no_buffer)           == (COM_HSI_OFFSET * sizeof(u32_t) + 0x0f8) &&  \
    COM_HSI_OFFSETOFF(l2_drop_pkt_cnt)               == (COM_HSI_OFFSET * sizeof(u32_t) + 0x0fc) &&  \
    COM_HSI_OFFSETOFF(com_cu_free_cnt)               == (COM_HSI_OFFSET * sizeof(u32_t) + 0x100) &&  \
    COM_HSI_OFFSETOFF(cu_rate_limiter_enable)        == (COM_HSI_OFFSET * sizeof(u32_t) + 0x104) &&  \
    COM_HSI_OFFSETOFF(cu_rate_limiter_enable)+COM_HSI_SIZEOF(cu_rate_limiter_enable) == (COM_HSI_OFFSET * sizeof(u32_t) + sizeof(com_hsi_t)));}}

#endif

