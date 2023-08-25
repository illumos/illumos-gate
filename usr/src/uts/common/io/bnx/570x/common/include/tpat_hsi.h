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

#ifndef _TPAT_HSI_H
#define _TPAT_HSI_H

// Offset of xxx_hsi in 32 bit words from beginning of scratchpad
#define TPAT_HSI_OFFSET 0x104

typedef struct _tpat_hsi_t {
    fw_version_t version;
    u32_t l2_pseudo_checksum;
    u32_t num_catchup_processed;
    u32_t num_catchup_pause ;
    // Debug
    u32_t tpat_num_complete;
    u32_t tpat_udp_patchup;
    u32_t fault_insertion;
    u32_t l4_segment_count;
    // Catchup overide for RSS
    u32_t catchup_overide;
	u64_t unicast_bytes_xmit;
	u64_t multicast_bytes_xmit;
	u64_t broadcast_bytes_xmit;
    u64_t volatile idle_count;
    u32_t iscsi_ctx_num_tasks;          // size of task array in iSCSI context
    u32_t iscsi_ctx_num_ccells;         // size of command queue in iSCSI context
	u64_t iscsi_unicast_bytes_xmit;
	u64_t iscsi_multicast_bytes_xmit;
	u64_t iscsi_broadcast_bytes_xmit;
    u32_t iscsi_teton_task_offset;      // Teton only: offset of the task array
    u32_t iscsi_teton_l5_offset;        // Teton only: offset of L5 section
    u64_t total_bytes_xmit;
}tpat_hsi_t;

// This macro can be used for little or big endian 32-bit system
#define TPAT_HSI_OFFSETOFF(m)  (OFFSETOF(tpat_hsi_t,m) + 0x410)
#define TPAT_HSI_SIZEOF(m)     (sizeof (((tpat_hsi_t *)0)->m))

// Calling the following macro will actually get optimized during compile
// time. Its sole purpose is to ensure HSI variables cannot be modified/moved
// unnoticed   scratch[3072] 0xa0000 (RW/Reset: undefined)
#define TEST_TPAT_HSI(){                                                    \
if (0){                                                                     \
 1/(TPAT_HSI_OFFSETOFF(version)                     == (TPAT_HSI_OFFSET * sizeof(u32_t) + 0x000) &&   \
    TPAT_HSI_OFFSETOFF(l2_pseudo_checksum)          == (TPAT_HSI_OFFSET * sizeof(u32_t) + 0x010) &&   \
    TPAT_HSI_OFFSETOFF(num_catchup_processed)       == (TPAT_HSI_OFFSET * sizeof(u32_t) + 0x014) &&   \
    TPAT_HSI_OFFSETOFF(num_catchup_pause)           == (TPAT_HSI_OFFSET * sizeof(u32_t) + 0x018) &&   \
    TPAT_HSI_OFFSETOFF(tpat_num_complete)           == (TPAT_HSI_OFFSET * sizeof(u32_t) + 0x01c) &&   \
    TPAT_HSI_OFFSETOFF(tpat_udp_patchup)            == (TPAT_HSI_OFFSET * sizeof(u32_t) + 0x020) &&   \
    TPAT_HSI_OFFSETOFF(fault_insertion)             == (TPAT_HSI_OFFSET * sizeof(u32_t) + 0x024) &&   \
    TPAT_HSI_OFFSETOFF(l4_segment_count)            == (TPAT_HSI_OFFSET * sizeof(u32_t) + 0x028) &&   \
    TPAT_HSI_OFFSETOFF(catchup_overide)             == (TPAT_HSI_OFFSET * sizeof(u32_t) + 0x02c) &&   \
    TPAT_HSI_OFFSETOFF(unicast_bytes_xmit)          == (TPAT_HSI_OFFSET * sizeof(u32_t) + 0x030) &&   \
    TPAT_HSI_OFFSETOFF(multicast_bytes_xmit)        == (TPAT_HSI_OFFSET * sizeof(u32_t) + 0x038) &&   \
    TPAT_HSI_OFFSETOFF(broadcast_bytes_xmit)        == (TPAT_HSI_OFFSET * sizeof(u32_t) + 0x040) &&   \
    TPAT_HSI_OFFSETOFF(idle_count)                  == (TPAT_HSI_OFFSET * sizeof(u32_t) + 0x048) &&   \
    TPAT_HSI_OFFSETOFF(iscsi_ctx_num_tasks)         == (TPAT_HSI_OFFSET * sizeof(u32_t) + 0x050) &&   \
    TPAT_HSI_OFFSETOFF(iscsi_ctx_num_ccells)        == (TPAT_HSI_OFFSET * sizeof(u32_t) + 0x054) &&   \
    TPAT_HSI_OFFSETOFF(iscsi_unicast_bytes_xmit)    == (TPAT_HSI_OFFSET * sizeof(u32_t) + 0x058) &&   \
    TPAT_HSI_OFFSETOFF(iscsi_multicast_bytes_xmit)  == (TPAT_HSI_OFFSET * sizeof(u32_t) + 0x060) &&   \
    TPAT_HSI_OFFSETOFF(iscsi_broadcast_bytes_xmit)  == (TPAT_HSI_OFFSET * sizeof(u32_t) + 0x068) &&   \
    TPAT_HSI_OFFSETOFF(iscsi_teton_task_offset)     == (TPAT_HSI_OFFSET * sizeof(u32_t) + 0x070) &&   \
    TPAT_HSI_OFFSETOFF(iscsi_teton_l5_offset)       == (TPAT_HSI_OFFSET * sizeof(u32_t) + 0x074) &&   \
	TPAT_HSI_OFFSETOFF(total_bytes_xmit)            == (TPAT_HSI_OFFSET * sizeof(u32_t) + 0x078) &&   \
    TPAT_HSI_OFFSETOFF(total_bytes_xmit)+TPAT_HSI_SIZEOF(total_bytes_xmit) == (TPAT_HSI_OFFSET * sizeof(u32_t) + sizeof(tpat_hsi_t)));}}
#endif

