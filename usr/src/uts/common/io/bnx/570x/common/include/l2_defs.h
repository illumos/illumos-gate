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


#ifndef _l2_defs_h_
#define _l2_defs_h_


typedef struct tx_bidx_boff_b{
    u16_t bidx;
    u16_t boff;
}tx_bidx_boff_b_t;

typedef struct tx_bidx_boff_l{
    u16_t boff;
    u16_t bidx;
}tx_bidx_boff_l_t;

#if defined(LITTLE_ENDIAN)
    typedef tx_bidx_boff_l_t tx_bidx_boff_t;
#elif defined(BIG_ENDIAN)
    typedef tx_bidx_boff_b_t tx_bidx_boff_t;
#endif


typedef struct bd_scan_b{
    u32_t cmd;

    u32_t len;

    u16_t flags;
    u16_t vlan_tag;
    u16_t reserved;
    u16_t unused_13;
    tx_bidx_boff_t bidx_boff_current;
    tx_bidx_boff_t bidx_boff_prev;
    u32_t bseq_current;
    u32_t bseq_prev;
}bd_scan_b_t;

typedef struct bd_scan_l{
    u32_t cmd;

    u32_t len;

    u16_t vlan_tag;
    u16_t flags;

    u16_t unused_13;
    u16_t reserved;
    tx_bidx_boff_t bidx_boff_current;
    tx_bidx_boff_t bidx_boff_prev;
    u32_t bseq_current;
    u32_t bseq_prev;
}bd_scan_l_t;

#if defined(LITTLE_ENDIAN)
    typedef bd_scan_l_t bd_scan_t;
#elif defined(BIG_ENDIAN)
    typedef bd_scan_b_t bd_scan_t;
#endif


#if defined(LITTLE_ENDIAN)
struct idx16_fields_t {
    u16_t   idx : 15;
	u16_t 	msb : 1;
};
#elif defined(BIG_ENDIAN)
struct idx16_fields_t {
	u16_t 	msb : 1;
	u16_t   idx : 15;
};
#endif

union idx16_union_t {
    struct idx16_fields_t   fields;
    u16_t                   idx16;
};

// Refer to Timer Architecture document.
// The timers have different sizes, however, the LSB of each timer indicates
// whether the timer is armed or dis-armed (a value of '1' indicates that the
// timer is dis-armed, a value of '0' indicates that the timer is armed). The
// MSB of each timer indicates whether the timer value has rolled over during
// the course of operation. Thus a 32-bit timer is essentially a 30-bit timer
// with the MSB and LSB used for different purposes.
#define MAX_TMR1_CNT_LIMIT                     0x3FFFFFFF // 30-bit timer
#define TMR1_TICKS_PER_SEC                     1000
#define TMR1_MSEC(x)                                  \
        ((u32_t)((x) * TMR1_TICKS_PER_SEC/1000) ?     \
         (u32_t)((x) * TMR1_TICKS_PER_SEC/1000) : 1)

#define MAX_TMR2_CNT_LIMIT                     0x3FFF     // 14-bit timer
#define TMR2_TICKS_PER_SEC                     100
#define TMR2_MSEC(x)                                  \
        ((u32_t)((x) * TMR2_TICKS_PER_SEC/1000) ?     \
         (u32_t)((x) * TMR2_TICKS_PER_SEC/1000) : 1)

#define MAX_TMR3_CNT_LIMIT                     0x3FFF     // 14-bit timer
#define TMR3_TICKS_PER_SEC                     1000
#define TMR3_MSEC(x)                                  \
        ((u32_t)((x) * TMR3_TICKS_PER_SEC/1000) ?     \
         (u32_t)((x) * TMR3_TICKS_PER_SEC/1000) : 1)

#define MAX_TMR4_CNT_LIMIT                     0x3FFF     // 14-bit timer
#define TMR4_TICKS_PER_SEC                     10
#define TMR4_MSEC(x)                                  \
        ((u32_t)((x) * TMR4_TICKS_PER_SEC/1000) ?     \
         (u32_t)((x) * TMR4_TICKS_PER_SEC/1000) : 1)

#define MAX_TMR5_CNT_LIMIT                     0x3FFF     // 14-bit timer
#define TMR5_TICKS_PER_SEC                     10000
#define TMR5_MSEC(x)                                  \
        ((u32_t)((x) * TMR5_TICKS_PER_SEC/1000) ?     \
         (u32_t)((x) * TMR5_TICKS_PER_SEC/1000) : 1)


/*
 *  l2_bd_chain_context_b definition
 */
typedef struct l2_bd_chain_context_b
{
    u8_t  l2ctx_ctx_type;
            #define L2CTX_CTX_TYPE_CTX_BD_CHN_TYPE              (0xf<<4)
            #define L2CTX_CTX_TYPE_CTX_BD_CHN_TYPE_UNDEFINED    (0<<4)
            #define L2CTX_CTX_TYPE_CTX_BD_CHN_TYPE_VALUE        (1<<4)

    u8_t  l2ctx_ctx_size;
    u8_t  l2ctx_bd_pre_read;
    // L2 flow control watermarks b0-b3 and b4-b7 are the low and high
    // watermark respectively
    u8_t  l2ctx_watermarks;
    u8_t  l2ctx_sb_num;
    u8_t  l2ctx_krnlq_id;
    u16_t l2ctx_host_bdidx;
    u32_t l2ctx_host_bseq;
    u32_t l2ctx_nx_bseq;
    u32_t l2ctx_nx_bdhaddr_hi;
    u32_t l2ctx_nx_bdhaddr_lo;
    u16_t l2ctx_v2p_flags;
        // only valid in Linux for Flow control (maintained by RV2P)
        #define L2CTX_V2P_FLAGS_PAUSE    (1<<0)
    u16_t l2ctx_nx_bdidx;
    u8_t  unused_1;
    u8_t  l2ctx_queue_type;
    u8_t  l2ctx_filter_type;
    u8_t  reserved;
    u16_t unused_2;
    u16_t l2ctx_max_pkt_len;       // max L2 pkt length the RX BD can accomodate
    u32_t unused[7];
    u16_t l2ctx_vmq_lookahead_sz;   /* VMQ look ahead size */
    // Following fields are for LINUX only (jumbo pkt mode)
    u8_t  l2ctx_pg_bd_pre_read;
    u8_t  unused_4;
    u16_t unused_5;
    u16_t l2ctx_host_pg_bidx;
    u16_t l2ctx_skb_buf_size;
    u16_t l2ctx_pg_buf_size;
    u16_t unused_6;
    u16_t l2ctx_rbdc_key;
    u32_t l2ctx_nx_pg_bdhaddr_hi;
    u32_t l2ctx_nx_pg_bdhaddr_lo;
    u16_t unused_7;
    u16_t l2ctx_nx_pg_bdidx;
    u32_t unused_8[9];
} l2_bd_chain_context_b_t;


/*
 *  l2_bd_chain_context_l definition
 */
typedef struct l2_bd_chain_context_l
{
    // L2 flow control watermarks b0-b3 and b4-b7 are the low and high
    // watermark respectively  (Linux L2 flow control only)
    u8_t  l2ctx_watermarks;
    u8_t  l2ctx_bd_pre_read;
    u8_t  l2ctx_ctx_size;
    u8_t  l2ctx_ctx_type;
            #define L2CTX_CTX_TYPE_CTX_BD_CHN_TYPE              (0xf<<4)
            #define L2CTX_CTX_TYPE_CTX_BD_CHN_TYPE_UNDEFINED    (0<<4)
            #define L2CTX_CTX_TYPE_CTX_BD_CHN_TYPE_VALUE        (1<<4)

    u16_t l2ctx_host_bdidx;
    u8_t  l2ctx_krnlq_id;
    u8_t  l2ctx_sb_num;    // Linux only
    u32_t l2ctx_host_bseq;
    u32_t l2ctx_nx_bseq;
    u32_t l2ctx_nx_bdhaddr_hi;
    u32_t l2ctx_nx_bdhaddr_lo;
    u16_t l2ctx_nx_bdidx;
    u16_t l2ctx_v2p_flags;
        // only valid in Linux for Flow control (maintained by RV2P)
        #define L2CTX_V2P_FLAGS_PAUSE    (1<<0)
    u8_t  reserved;
    u8_t  l2ctx_filter_type;
    u8_t  l2ctx_queue_type;
    u8_t  unused_1;
    u16_t l2ctx_max_pkt_len;       // max L2 pkt length the RX BD can accomodate
    u16_t unused_2;
    u32_t unused[7];
    u8_t  unused_4;
    u8_t  l2ctx_pg_bd_pre_read;     // Linux jumbo pkt mode only
    u16_t l2ctx_vmq_lookahead_sz;
    // Following fields are for LINUX only (jumbo pkt mode)
    u16_t l2ctx_host_pg_bidx;
    u16_t unused_5;
    u16_t l2ctx_pg_buf_size;
    u16_t l2ctx_skb_buf_size;
    u16_t l2ctx_rbdc_key;
    u16_t unused_6;
    u32_t l2ctx_nx_pg_bdhaddr_hi;
    u32_t l2ctx_nx_pg_bdhaddr_lo;
    u16_t l2ctx_nx_pg_bdidx;
    u16_t unused_7;
    u32_t unused_8[9];
} l2_bd_chain_context_l_t;


/*
 * l2_bd_chain_context select
 */
#if defined(LITTLE_ENDIAN)
    typedef l2_bd_chain_context_l_t l2_bd_chain_context_t;
#elif defined(BIG_ENDIAN)
#if defined(CONFIG_PPC64) || defined(__sparc)
    typedef l2_bd_chain_context_l_t l2_bd_chain_context_t;
#else
    typedef l2_bd_chain_context_b_t l2_bd_chain_context_t;
#endif
#endif

/*
 *  tcp_context_cmd_cell_b_te definition
 */
typedef struct tcp_context_cmd_cell_b_te
{
    u8_t ccell_cmd_type;

    u8_t ccell_est_nbd;
    u16_t ccell_tx_host_bidx;
    u32_t ccell_tx_mss;

    u32_t ccell_tx_host_bseq;
    u32_t ccell_tsch_bseq;
    u32_t ccell_tbdr_bseq;
    tx_bidx_boff_t  ccell_tbdr_bidx_boff;
#if defined(_ANSI_C_)
    // compiler switch is to avoid complaints from some ANSI compilers
    // (e.g. Solaris) that don't support unnamed union
    struct {
        u32_t hi;
        u32_t lo;
    } ccell_tbdr_bhaddr;
#else
    union {
        struct {
            u32_t ccell_tbdr_bhaddr_hi;
            u32_t ccell_tbdr_bhaddr_lo;
        };
        u64_t ccell_tbdr_bhaddr;
    };
#endif
    tx_bidx_boff_t ccell_txp_bidx_boff;
    u32_t ccell_txp_bseq;
} tcp_context_cmd_cell_b_te_t;



/*
 *  tcp_context_cmd_cell_l_te definition
 */
typedef struct tcp_context_cmd_cell_l_te
{
    u16_t ccell_tx_host_bidx;
    u8_t ccell_est_nbd;
    u8_t ccell_cmd_type;
    u32_t ccell_tx_mss;

    u32_t ccell_tx_host_bseq;
    u32_t ccell_tsch_bseq;
    u32_t ccell_tbdr_bseq;
    tx_bidx_boff_t  ccell_tbdr_bidx_boff;
    struct {
        u32_t hi;
        u32_t lo;
    } ccell_tbdr_bhaddr;
    tx_bidx_boff_t ccell_txp_bidx_boff;
    u32_t ccell_txp_bseq;
} tcp_context_cmd_cell_l_te_t;


typedef struct tcp_context_cmd_cell_b_xi
{
    u8_t ccell_cmd_type;
        #define CCELL_CMD_TYPE_TYPE                         (0xf<<0)
            #define CCELL_CMD_TYPE_TYPE_L2                  (0<<0)
            #define CCELL_CMD_TYPE_TYPE_TCP                 (1<<0)
            #define CCELL_CMD_TYPE_TYPE_L5_CHAIN            (2<<0)
            #define CCELL_CMD_TYPE_TYPE_SEND_L5_PGTBL       (3<<0)
            #define CCELL_CMD_TYPE_TYPE_WRITE_L5_PGTBL      (4<<0)
            #define CCELL_CMD_TYPE_TYPE_RDREQ_L5_PGTBL      (5<<0)
            #define CCELL_CMD_TYPE_TYPE_L5_DONOTHING        (6<<0)
            #define CCELL_CMD_TYPE_TYPE_7_L5_PGTBL          (7<<0)
            #define CCELL_CMD_TYPE_TYPE_8_CHAIN             (8<<0)
            #define CCELL_CMD_TYPE_TYPE_9_CHAIN             (9<<0)
            #define CCELL_CMD_TYPE_TYPE_10_CHAIN            (10<<0)
            #define CCELL_CMD_TYPE_TYPE_11_PGTBL            (11<<0)
            #define CCELL_CMD_TYPE_TYPE_12_PGTBL            (12<<0)
            #define CCELL_CMD_TYPE_TYPE_13_PGTBL            (13<<0)
            #define CCELL_CMD_TYPE_TYPE_14_PGTBL            (14<<0)
            #define CCELL_CMD_TYPE_TYPE_15_PGTBL            (15<<0)
        #define CCELL_CMD_TYPE_PG_SZ                        (0xf<<4)
            #define CCELL_CMD_TYPE_PG_SZ_256                (0<<4)
            #define CCELL_CMD_TYPE_PG_SZ_512                (1<<4)
            #define CCELL_CMD_TYPE_PG_SZ_1K                 (2<<4)
            #define CCELL_CMD_TYPE_PG_SZ_2K                 (3<<4)
            #define CCELL_CMD_TYPE_PG_SZ_4K                 (4<<4)
            #define CCELL_CMD_TYPE_PG_SZ_8K                 (5<<4)
            #define CCELL_CMD_TYPE_PG_SZ_16K                (6<<4)
            #define CCELL_CMD_TYPE_PG_SZ_32K                (7<<4)
            #define CCELL_CMD_TYPE_PG_SZ_64K                (8<<4)
            #define CCELL_CMD_TYPE_PG_SZ_128K               (9<<4)
            #define CCELL_CMD_TYPE_PG_SZ_256K               (10<<4)
            #define CCELL_CMD_TYPE_PG_SZ_512K               (11<<4)
            #define CCELL_CMD_TYPE_PG_SZ_1M                 (12<<4)
            #define CCELL_CMD_TYPE_PG_SZ_2M                 (13<<4)
            #define CCELL_CMD_TYPE_PG_SZ_4M                 (14<<4)
            #define CCELL_CMD_TYPE_PG_SZ_8M                 (15<<4)
    u8_t ccell_est_nbd;
    u16_t ccell_tx_host_bidx;
    u32_t ccell_tx_mss;
        #define CCELL_TX_MSS_MSS                            (0x3fffL<<0)
        #define CCELL_TX_MSS_MULT                           (0x7ffL<<14)
        #define CCELL_TX_MSS_PESS_ON                        (1UL<<25)
        #define CCELL_TX_MSS_OH                             (0x3fL<<26)
    u32_t ccell_tx_host_bseq;
    u32_t ccell_tsch_bseq;
    u32_t ccell_tbdr_bseq;
    tx_bidx_boff_t  ccell_tbdr_bidx_boff;
#if defined(_ANSI_C_)
    // compiler switch is to avoid complaints from some ANSI compilers
    // (e.g. Solaris) that don't support unnamed union
    struct {
        u32_t hi;
        u32_t lo;
    } ccell_tbdr_bhaddr;
#else
    union {
        struct {
            u32_t ccell_tbdr_bhaddr_hi;
            u32_t ccell_tbdr_bhaddr_lo;
        };
        u64_t ccell_tbdr_bhaddr;
    };
#endif
    tx_bidx_boff_t ccell_txp_bidx_boff;
    u32_t ccell_txp_bseq;
    u8_t ccell_reserved0[3];
    const u8_t ccell_tcmd_fnum; // NOTE: FW must NEVER change or initialize this field!
    u32_t reserved1;            // 8 byte alignment
} tcp_context_cmd_cell_b_xi_t;




/*
 *  tcp_context_cmd_cell_l_xi definition
 */
typedef struct tcp_context_cmd_cell_l_xi
{
    u16_t ccell_tx_host_bidx;
    u8_t ccell_est_nbd;
    u8_t ccell_cmd_type;
        #define CCELL_CMD_TYPE_TYPE                         (0xf<<0)
            #define CCELL_CMD_TYPE_TYPE_L2                  (0<<0)
            #define CCELL_CMD_TYPE_TYPE_TCP                 (1<<0)
            #define CCELL_CMD_TYPE_TYPE_L5_CHAIN            (2<<0)
            #define CCELL_CMD_TYPE_TYPE_SEND_L5_PGTBL       (3<<0)
            #define CCELL_CMD_TYPE_TYPE_WRITE_L5_PGTBL      (4<<0)
            #define CCELL_CMD_TYPE_TYPE_RDREQ_L5_PGTBL      (5<<0)
            #define CCELL_CMD_TYPE_TYPE_L5_DONOTHING        (6<<0)
            #define CCELL_CMD_TYPE_TYPE_7_L5_PGTBL          (7<<0)
            #define CCELL_CMD_TYPE_TYPE_8_CHAIN             (8<<0)
            #define CCELL_CMD_TYPE_TYPE_9_CHAIN             (9<<0)
            #define CCELL_CMD_TYPE_TYPE_10_CHAIN            (10<<0)
            #define CCELL_CMD_TYPE_TYPE_11_PGTBL            (11<<0)
            #define CCELL_CMD_TYPE_TYPE_12_PGTBL            (12<<0)
            #define CCELL_CMD_TYPE_TYPE_13_PGTBL            (13<<0)
            #define CCELL_CMD_TYPE_TYPE_14_PGTBL            (14<<0)
            #define CCELL_CMD_TYPE_TYPE_15_PGTBL            (15<<0)
        #define CCELL_CMD_TYPE_PG_SZ                        (0xf<<4)
            #define CCELL_CMD_TYPE_PG_SZ_256                (0<<4)
            #define CCELL_CMD_TYPE_PG_SZ_512                (1<<4)
            #define CCELL_CMD_TYPE_PG_SZ_1K                 (2<<4)
            #define CCELL_CMD_TYPE_PG_SZ_2K                 (3<<4)
            #define CCELL_CMD_TYPE_PG_SZ_4K                 (4<<4)
            #define CCELL_CMD_TYPE_PG_SZ_8K                 (5<<4)
            #define CCELL_CMD_TYPE_PG_SZ_16K                (6<<4)
            #define CCELL_CMD_TYPE_PG_SZ_32K                (7<<4)
            #define CCELL_CMD_TYPE_PG_SZ_64K                (8<<4)
            #define CCELL_CMD_TYPE_PG_SZ_128K               (9<<4)
            #define CCELL_CMD_TYPE_PG_SZ_256K               (10<<4)
            #define CCELL_CMD_TYPE_PG_SZ_512K               (11<<4)
            #define CCELL_CMD_TYPE_PG_SZ_1M                 (12<<4)
            #define CCELL_CMD_TYPE_PG_SZ_2M                 (13<<4)
            #define CCELL_CMD_TYPE_PG_SZ_4M                 (14<<4)
            #define CCELL_CMD_TYPE_PG_SZ_8M                 (15<<4)

    u32_t ccell_tx_mss;
        #define CCELL_TX_MSS_MSS                            (0x3fffL<<0)
        #define CCELL_TX_MSS_MULT                           (0x7ffL<<14)
        #define CCELL_TX_MSS_PESS_ON                        (1UL<<25)
        #define CCELL_TX_MSS_OH                             (0x3fL<<26)

    u32_t ccell_tx_host_bseq;
    u32_t ccell_tsch_bseq;
    u32_t ccell_tbdr_bseq;
    tx_bidx_boff_t  ccell_tbdr_bidx_boff;
    struct {
        u32_t hi;
        u32_t lo;
    } ccell_tbdr_bhaddr;
    tx_bidx_boff_t ccell_txp_bidx_boff;
    u32_t ccell_txp_bseq;
    const u8_t ccell_tcmd_fnum; // NOTE: FW must NEVER change or initialize this field!
    u8_t ccell_reserved0[3];
    u32_t reserved1;            // 8 byte alignment
} tcp_context_cmd_cell_l_xi_t;


/*
 * tcp_context_cmd_cell select
 */
#if defined(LITTLE_ENDIAN)
    typedef tcp_context_cmd_cell_l_te_t tcp_context_cmd_cell_te_t;
    typedef tcp_context_cmd_cell_l_xi_t tcp_context_cmd_cell_xi_t;
#elif defined(BIG_ENDIAN)
#if defined(CONFIG_PPC64) || defined(__sparc)
    typedef tcp_context_cmd_cell_l_te_t tcp_context_cmd_cell_te_t;
    typedef tcp_context_cmd_cell_l_xi_t tcp_context_cmd_cell_xi_t;
#else
    typedef tcp_context_cmd_cell_b_te_t tcp_context_cmd_cell_te_t;
    typedef tcp_context_cmd_cell_b_xi_t tcp_context_cmd_cell_xi_t;
#endif
#endif

/*
 *  pg_context_b definition
 */
typedef struct pg_context_b
{
    u8_t pg_type;
        #define PG_TYPE_TYPE                                (0xf<<4)
            #define PG_TYPE_TYPE_EMPTY                      (0<<4)
            #define PG_TYPE_TYPE_L2                         (1<<4)
            #define PG_TYPE_TYPE_TCP                        (2<<4)
            #define PG_TYPE_TYPE_L5                         (3<<4)
            #define PG_TYPE_TYPE_L2_BD_CHN                  (4<<4)
            #define PG_TYPE_TYPE_PG                         (5<<4)

    u8_t pg_size;
    u8_t pg_krnlq_id;     // Xinan and X1V only
    u8_t unused_0;
    u32_t unused_1[2];
    u32_t pg_timer1;
    u16_t pg_timer2;
    u16_t pg_timer3;
    u16_t pg_timer4;
    u16_t pg_timer5;
    u8_t pg_l2hdr_nbytes;
    u8_t pg_flags;
        #define PG_FLAGS_SNAP_ENCAP                         (1<<0)
        #define PG_FLAGS_VLAN_TAGGING                       (1<<1)

    u8_t pg_da[6];
    u8_t pg_sa[6];
    u16_t pg_etype;
    u16_t pg_vlan_tag;
    u16_t pg_ipid_start;
    u16_t pg_ipid_count;
    u16_t unused_2;
} pg_context_b_t;


/*
 *  pg_context_l definition
 */
typedef struct pg_context_l
{
    u8_t unused_0;
    u8_t pg_krnlq_id;     // Xinan and X1V only
    u8_t pg_size;
    u8_t pg_type;
        #define PG_TYPE_TYPE                                (0xf<<4)
            #define PG_TYPE_TYPE_EMPTY                      (0<<4)
            #define PG_TYPE_TYPE_L2                         (1<<4)
            #define PG_TYPE_TYPE_TCP                        (2<<4)
            #define PG_TYPE_TYPE_L5                         (3<<4)
            #define PG_TYPE_TYPE_L2_BD_CHN                  (4<<4)
            #define PG_TYPE_TYPE_PG                         (5<<4)
    u32_t unused_1[2];

    u32_t pg_timer1;
    u16_t pg_timer3;
    u16_t pg_timer2;
    u16_t pg_timer5;
    u16_t pg_timer4;
    u8_t pg_da[6];
    u8_t pg_flags;
        #define PG_FLAGS_SNAP_ENCAP                         (1<<0)
        #define PG_FLAGS_VLAN_TAGGING                       (1<<1)

    u8_t pg_l2hdr_nbytes;
    u8_t pg_sa[6];
    u16_t pg_etype;
    u16_t pg_ipid_start;
    u16_t pg_vlan_tag;
    u16_t unused_2;
    u16_t pg_ipid_count;
} pg_context_l_t;


/*
 * pg_context select
 */
#if defined(LITTLE_ENDIAN)
    typedef pg_context_l_t pg_context_t;
#elif defined(BIG_ENDIAN)
    typedef pg_context_b_t pg_context_t;
#endif




#endif /* _l2_defs_h_ */


