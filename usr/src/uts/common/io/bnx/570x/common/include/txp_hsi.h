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

#ifndef _TXP_HSI_H
#define _TXP_HSI_H

// Offset of xxx_hsi in 32 bit words from beginning of scratchpad
#define TXP_HSI_OFFSET 0x4

typedef struct _txp_hsi_t {
    fw_version_t version;
    u32_t cu_rate_limiter_enable;
    u32_t min_rto_tick;
    u32_t max_rto_tick;
    u32_t txp_os_flag;
        #define OS_LH      (1<<0)
    u32_t invalid_ctx_cnt;               // unknown context type entries
    u32_t cmpl_cnt;            // count of tx completion
    u32_t non_zero_slot_cnt;
    u32_t txp_cid_last;
    u32_t txp_oubits;
    u32_t txpq_protocol_flags;
    u32_t txp_append_context;
    u32_t txp_overide_catchup;
    u32_t txp_comxq_seq;
    u32_t tsch_reset;
    u32_t iscsi_ctx_num_tasks;          // size of task array in iSCSI context
    u32_t iscsi_ctx_num_ccells;         // size of command queue in iSCSI context
    u32_t txp_tdbcThrhld;
    u32_t num_retx_flushes;             // number of retransmit flush
    u64_t volatile idle_count;
    u64_t volatile idle_tdma;
    u64_t volatile idle_ctx_lock;
    u64_t volatile idle_hdrq;
    u32_t txp_coalsce_cnt;
    u32_t iscsi_teton_task_offset;      // Teton only: offset of the task array
    u32_t iscsi_teton_l5_offset;        // Teton only: offset of L5 section
    u32_t neg_slot_cnt;
    u32_t sws_prevention_ticks;  // sws (silly window syndrome) prevention timer (in Timer1 tick resolution)
    u32_t tx_after_fin_cnt;      // number of tx occurs after FIN
    u32_t mtu_size;
    u32_t bd_validation;
} txp_hsi_t;

// This the default cache line parameter that used by tcp nagle alogrithm
#define DEFAULT_TDBCTRHLD           29    /* 29 cached line free */
#define NAGLE_TDBCTRHLD             22    /* 22 cached line free */

// This macro can be used for little or big endian 32-bit system
#define TXP_HSI_OFFSETOFF(m)  (OFFSETOF(txp_hsi_t,m) + 0x10)
#define TXP_HSI_SIZEOF(m)     (sizeof (((txp_hsi_t *)0)->m))

// Calling the following macro will actually get optimized during compile
// time. Its sole purpose is to ensure HSI variables cannot be modified/moved
// unnoticed   scratch[8192]  0x60000  (RW/Reset: undefined)
#define TEST_TXP_HSI(){                                                    \
if (0){                                                                    \
 1/(TXP_HSI_OFFSETOFF(version)                   == (TXP_HSI_OFFSET * sizeof(u32_t) + 0x000) &&      \
    TXP_HSI_OFFSETOFF(cu_rate_limiter_enable)    == (TXP_HSI_OFFSET * sizeof(u32_t) + 0x010) &&      \
    TXP_HSI_OFFSETOFF(min_rto_tick)              == (TXP_HSI_OFFSET * sizeof(u32_t) + 0x014) &&      \
    TXP_HSI_OFFSETOFF(max_rto_tick)              == (TXP_HSI_OFFSET * sizeof(u32_t) + 0x018) &&      \
    TXP_HSI_OFFSETOFF(txp_os_flag)               == (TXP_HSI_OFFSET * sizeof(u32_t) + 0x01c) &&      \
    TXP_HSI_OFFSETOFF(invalid_ctx_cnt)           == (TXP_HSI_OFFSET * sizeof(u32_t) + 0x020) &&      \
    TXP_HSI_OFFSETOFF(cmpl_cnt)                  == (TXP_HSI_OFFSET * sizeof(u32_t) + 0x024) &&      \
    TXP_HSI_OFFSETOFF(non_zero_slot_cnt)         == (TXP_HSI_OFFSET * sizeof(u32_t) + 0x028) &&      \
    TXP_HSI_OFFSETOFF(txp_cid_last)              == (TXP_HSI_OFFSET * sizeof(u32_t) + 0x02c) &&      \
    TXP_HSI_OFFSETOFF(txp_oubits)                == (TXP_HSI_OFFSET * sizeof(u32_t) + 0x030) &&      \
    TXP_HSI_OFFSETOFF(txpq_protocol_flags)       == (TXP_HSI_OFFSET * sizeof(u32_t) + 0x034) &&      \
    TXP_HSI_OFFSETOFF(txp_append_context)        == (TXP_HSI_OFFSET * sizeof(u32_t) + 0x038) &&      \
    TXP_HSI_OFFSETOFF(txp_overide_catchup)       == (TXP_HSI_OFFSET * sizeof(u32_t) + 0x03c) &&      \
    TXP_HSI_OFFSETOFF(txp_comxq_seq)             == (TXP_HSI_OFFSET * sizeof(u32_t) + 0x040) &&      \
    TXP_HSI_OFFSETOFF(tsch_reset)                == (TXP_HSI_OFFSET * sizeof(u32_t) + 0x044) &&      \
    TXP_HSI_OFFSETOFF(iscsi_ctx_num_tasks)       == (TXP_HSI_OFFSET * sizeof(u32_t) + 0x048) &&      \
    TXP_HSI_OFFSETOFF(iscsi_ctx_num_ccells)      == (TXP_HSI_OFFSET * sizeof(u32_t) + 0x04c) &&      \
    TXP_HSI_OFFSETOFF(txp_tdbcThrhld)            == (TXP_HSI_OFFSET * sizeof(u32_t) + 0x050) &&      \
    TXP_HSI_OFFSETOFF(num_retx_flushes)          == (TXP_HSI_OFFSET * sizeof(u32_t) + 0x054) &&      \
    TXP_HSI_OFFSETOFF(idle_count)                == (TXP_HSI_OFFSET * sizeof(u32_t) + 0x058) &&      \
    TXP_HSI_OFFSETOFF(idle_tdma)                 == (TXP_HSI_OFFSET * sizeof(u32_t) + 0x060) &&      \
    TXP_HSI_OFFSETOFF(idle_ctx_lock)             == (TXP_HSI_OFFSET * sizeof(u32_t) + 0x068) &&      \
    TXP_HSI_OFFSETOFF(idle_hdrq)                 == (TXP_HSI_OFFSET * sizeof(u32_t) + 0x070) &&      \
    TXP_HSI_OFFSETOFF(txp_coalsce_cnt)           == (TXP_HSI_OFFSET * sizeof(u32_t) + 0x078) &&      \
    TXP_HSI_OFFSETOFF(iscsi_teton_task_offset)   == (TXP_HSI_OFFSET * sizeof(u32_t) + 0x07c) &&      \
    TXP_HSI_OFFSETOFF(iscsi_teton_l5_offset)     == (TXP_HSI_OFFSET * sizeof(u32_t) + 0x080) &&      \
    TXP_HSI_OFFSETOFF(neg_slot_cnt)              == (TXP_HSI_OFFSET * sizeof(u32_t) + 0x084) &&      \
    TXP_HSI_OFFSETOFF(sws_prevention_ticks)      == (TXP_HSI_OFFSET * sizeof(u32_t) + 0x088) &&      \
    TXP_HSI_OFFSETOFF(tx_after_fin_cnt)          == (TXP_HSI_OFFSET * sizeof(u32_t) + 0x08c) &&      \
    TXP_HSI_OFFSETOFF(mtu_size)                  == (TXP_HSI_OFFSET * sizeof(u32_t) + 0x090) &&      \
    TXP_HSI_OFFSETOFF(bd_validation)             == (TXP_HSI_OFFSET * sizeof(u32_t) + 0x094) &&      \
    TXP_HSI_OFFSETOFF(bd_validation)+TXP_HSI_SIZEOF(bd_validation) == (TXP_HSI_OFFSET * sizeof(u32_t) + sizeof(txp_hsi_t)));}}

#endif

