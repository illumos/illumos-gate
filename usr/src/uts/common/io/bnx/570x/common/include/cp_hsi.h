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

#ifndef _CP_HSI_H
#define _CP_HSI_H

// Offset of xxx_hsi in 32 bit words from beginning of scratchpad
#define CP_HSI_OFFSET 0x4

typedef struct _fio_dbg_b_t {
    u8_t    cpu_src;
    u8_t    is_read;
    u16_t   fio_addr;
    u32_t   fio_data;
}fio_dbg_b_t;

typedef struct _fio_dbg_l_t {
    u16_t   fio_addr;
    u8_t    is_read;
    u8_t    cpu_src;
    u32_t   fio_data;
}fio_dbg_l_t;

#if defined(LITTLE_ENDIAN)
    typedef fio_dbg_l_t fio_dbg_t;
#elif defined(BIG_ENDIAN)
    typedef fio_dbg_b_t fio_dbg_t;
#endif

/*
 * Runtime Configurable Parameters
 */
typedef struct _cp_hsi_t {
    fw_version_t  version;
    u32_t fw_doorbell;
	    #define  KWQ_READY     (1<<0)
        #define  KWQ1_READY    (1<<1)
        #define  KWQ2_READY    (1<<2)
        #define  KWQ3_READY    (1<<3)
    u32_t iscsi_sq_size;				// Number of elements in queue. Its k lsb bits must be 0.
    u32_t cp_cpq_kwq[2];
    u32_t iscsi_xinan_unit;				// Xinan only: number of VCIDs for an iscsi connection
    u32_t pg_ctx_map;                   /* Xinan only: pg ctx start and end */
    u64_t volatile idle_count;
    u32_t iscsi_sq_wqes_per_page;		// Number of WQEs per page
    u32_t iscsi_sq_num_pages;			// Number of pages ( = entries in SQ page table)
    u32_t cp_gen_bd_max;
    u32_t iscsi_teton_l4_cmd_offset;   	// Teton Only: offset of L4 ccell command array
    u32_t iscsi_teton_l5_offset;       	// Teton Only: offset of L5 section
    u32_t iscsi_teton_l5_cmd_offset;   	// Teton Only: offset of L5 ccell command array
    u32_t iscsi_task_offset;     		// offset of the task array
    u32_t iscsi_r2tq_offset;     		// offset of R2TQ section
    u32_t iscsi_max_num_of_tasks;     	// maximal number of pending tasks
    u32_t iscsi_max_num_of_ccells;    	// maximal number of ccells
    u32_t iscsi_dbg_ctx_addr_h;
	u32_t iscsi_dbg_ctx_addr_l;
	u32_t iscsi_dbg_ctx_cid;
    u32_t iscsi_ctx_map;                /* Xinan only: iscsi ctx start and end */
    u32_t num_tcp_nagle_allow;          /* threshold of num of TOE conn that we allow
                                           for stricter tcp nagle alogrithm. */
    u32_t timer_scan_freq;              /* Xinan only: control timer scan frequency */
	u32_t iscsi_max_conn;				/* Read only parameter for the host to read */
    u32_t num_kwqe_limit;               /* restrict number kwqes to be process per dma */
    u32_t idle_ts_period;               /* time slice period for each tasks during idle loop */
    u32_t toe_ofld_retx_cnt;            /* Number of TOE connections that is oflded with retx */
    fio_dbg_t   fio_dbg_info;           /* for debugging fio access */
    u32_t l2_cid_cnt;                   /* Track erroneous cpq entry */
    u32_t unused;
}cp_hsi_t;


// This macro can be used for little or big endian 32-bit system
#define CP_HSI_OFFSETOFF(m)  (OFFSETOF(cp_hsi_t,m) + 0x10)
#define CP_HSI_SIZEOF(m)     (sizeof (((cp_hsi_t *)0)->m))

// Calling the following macro will actually get optimized during compile
// time. Its sole purpose is to ensure HSI variables cannot be modified/moved
// unnoticed  scratch[10240]  0x1a0000  (RW/Reset: undefined)
#define TEST_CP_HSI(){                                                    \
if (0){                                                                   \
 1/(CP_HSI_OFFSETOFF(version)                        == (CP_HSI_OFFSET * sizeof(u32_t) + 0x000) && \
    CP_HSI_OFFSETOFF(fw_doorbell)                    == (CP_HSI_OFFSET * sizeof(u32_t) + 0x010) && \
    CP_HSI_OFFSETOFF(iscsi_sq_size)                  == (CP_HSI_OFFSET * sizeof(u32_t) + 0x014) && \
    CP_HSI_OFFSETOFF(cp_cpq_kwq[0])                  == (CP_HSI_OFFSET * sizeof(u32_t) + 0x018) && \
    CP_HSI_OFFSETOFF(cp_cpq_kwq[1])                  == (CP_HSI_OFFSET * sizeof(u32_t) + 0x01c) && \
    CP_HSI_OFFSETOFF(iscsi_xinan_unit)               == (CP_HSI_OFFSET * sizeof(u32_t) + 0x020) && \
    CP_HSI_OFFSETOFF(pg_ctx_map)                     == (CP_HSI_OFFSET * sizeof(u32_t) + 0x024) && \
    CP_HSI_OFFSETOFF(idle_count)                     == (CP_HSI_OFFSET * sizeof(u32_t) + 0x028) && \
    CP_HSI_OFFSETOFF(iscsi_sq_wqes_per_page)         == (CP_HSI_OFFSET * sizeof(u32_t) + 0x030) && \
    CP_HSI_OFFSETOFF(iscsi_sq_num_pages)             == (CP_HSI_OFFSET * sizeof(u32_t) + 0x034) && \
    CP_HSI_OFFSETOFF(cp_gen_bd_max)                  == (CP_HSI_OFFSET * sizeof(u32_t) + 0x038) && \
    CP_HSI_OFFSETOFF(iscsi_teton_l4_cmd_offset)      == (CP_HSI_OFFSET * sizeof(u32_t) + 0x03c) && \
    CP_HSI_OFFSETOFF(iscsi_teton_l5_offset)          == (CP_HSI_OFFSET * sizeof(u32_t) + 0x040) && \
    CP_HSI_OFFSETOFF(iscsi_teton_l5_cmd_offset)      == (CP_HSI_OFFSET * sizeof(u32_t) + 0x044) && \
    CP_HSI_OFFSETOFF(iscsi_task_offset)              == (CP_HSI_OFFSET * sizeof(u32_t) + 0x048) && \
    CP_HSI_OFFSETOFF(iscsi_r2tq_offset)              == (CP_HSI_OFFSET * sizeof(u32_t) + 0x04c) && \
    CP_HSI_OFFSETOFF(iscsi_max_num_of_tasks)         == (CP_HSI_OFFSET * sizeof(u32_t) + 0x050) && \
    CP_HSI_OFFSETOFF(iscsi_max_num_of_ccells)        == (CP_HSI_OFFSET * sizeof(u32_t) + 0x054) && \
    CP_HSI_OFFSETOFF(iscsi_dbg_ctx_addr_h)           == (CP_HSI_OFFSET * sizeof(u32_t) + 0x058) && \
    CP_HSI_OFFSETOFF(iscsi_dbg_ctx_addr_l)           == (CP_HSI_OFFSET * sizeof(u32_t) + 0x05c) && \
    CP_HSI_OFFSETOFF(iscsi_dbg_ctx_cid)              == (CP_HSI_OFFSET * sizeof(u32_t) + 0x060) && \
    CP_HSI_OFFSETOFF(iscsi_ctx_map)                  == (CP_HSI_OFFSET * sizeof(u32_t) + 0x064) && \
    CP_HSI_OFFSETOFF(num_tcp_nagle_allow)            == (CP_HSI_OFFSET * sizeof(u32_t) + 0x068) && \
    CP_HSI_OFFSETOFF(timer_scan_freq)                == (CP_HSI_OFFSET * sizeof(u32_t) + 0x06c) && \
	CP_HSI_OFFSETOFF(iscsi_max_conn)                 == (CP_HSI_OFFSET * sizeof(u32_t) + 0x070) && \
	CP_HSI_OFFSETOFF(num_kwqe_limit)                 == (CP_HSI_OFFSET * sizeof(u32_t) + 0x074) && \
	CP_HSI_OFFSETOFF(idle_ts_period)                 == (CP_HSI_OFFSET * sizeof(u32_t) + 0x078) && \
	CP_HSI_OFFSETOFF(toe_ofld_retx_cnt)              == (CP_HSI_OFFSET * sizeof(u32_t) + 0x07c) && \
    CP_HSI_OFFSETOFF(fio_dbg_info)                   == (CP_HSI_OFFSET * sizeof(u32_t) + 0x080) && \
    CP_HSI_OFFSETOFF(l2_cid_cnt)                     == (CP_HSI_OFFSET * sizeof(u32_t) + 0x088) && \
    CP_HSI_OFFSETOFF(unused)                         == (CP_HSI_OFFSET * sizeof(u32_t) + 0x08C) && \
    CP_HSI_OFFSETOFF(unused)+CP_HSI_SIZEOF(unused) == (CP_HSI_OFFSET * sizeof(u32_t) + sizeof(cp_hsi_t)));}}

#endif
