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

#ifndef _TOE_CTX_H
#define _TOE_CTX_H

#include "tcp_ctx.h"



/////////////////////////////////////////////////////////////////////
// TOE TX section
/////////////////////////////////////////////////////////////////////
typedef struct {
    u32_t rto_intvl;     // current unbounded rto interval (in ticks)
    u32_t unused;
    u32_t tcp_last_rcv_win_seq;
    u8_t  tx_in_coalesce;
    u8_t  tx_ind_silly_win;
    u8_t  tx_large_bd;
    u8_t  tx_comp_defer;
    u16_t max_rt_tick;               // maximum total retransmit timeout (in ticks)
    u16_t total_rt_tick;             // total retransmit timeout  (in ticks)
    u32_t tcp_sack_start;             // keep track of rx SACK
    u8_t  tx_comp_prod;
    u8_t  tx_comp_cons;
    u8_t  persist_probe_cnt;
    u8_t  in_generic;
    u32_t tx_comp_step;
    u32_t reply_ts;
        #define TOE_RTT_SAMPLED                   (1<<0)
    u32_t tcp_save_cwin;
    u32_t unused2;
    u32_t host_win_update;
} toe_l4_tx_ctx_b_t;

typedef struct {
    u32_t rto_intvl;     // current unbounded rto interval (in ticks)
    u32_t unused;
    u32_t tcp_last_rcv_win_seq;
    u8_t  tx_comp_defer;
    u8_t  tx_large_bd;
    u8_t  tx_ind_silly_win;
    u8_t  tx_in_coalesce;
    u16_t total_rt_tick;             // total retransmit timeout  (in ticks)
    u16_t max_rt_tick;               // maximum total retransmit timeout (in ticks)
    u32_t tcp_sack_start;             // keep track of rx SACK
    u8_t  in_generic;
    u8_t  persist_probe_cnt;
    u8_t  tx_comp_cons;
    u8_t  tx_comp_prod;
    u32_t tx_comp_step;
    u32_t reply_ts;
        #define TOE_RTT_SAMPLED                   (1<<0)
    u32_t tcp_save_cwin;
    u32_t unused2;
    u32_t host_win_update;
} toe_l4_tx_ctx_l_t;

#if defined(LITTLE_ENDIAN)
    typedef toe_l4_tx_ctx_l_t  toe_l4_tx_ctx_t;
#elif defined(BIG_ENDIAN)
    typedef toe_l4_tx_ctx_b_t  toe_l4_tx_ctx_t;
#endif

    typedef struct {
    tcp_tx_ctx_t        tcp;
    toe_l4_tx_ctx_t     toe;
} toe_tx_ctx_t;

/////////////////////////////////////////////////////////////////////
// TOE CMN section
/////////////////////////////////////////////////////////////////////
typedef struct {
    u32_t   tcp_disconnect_seq;           // last snd seq # before disconnecting
    u32_t   last_fin_seq;                  // last rx seq # in FIN packet
    u8_t    tcp_retx_defer;
    u8_t    tcp_flow_state;
        #define TOE_FLOW_STATE_NORMAL_INIT           (0<<0)
        #define TOE_FLOW_STATE_NORMAL_RUNNING        (1<<0)
        #define TOE_FLOW_STATE_LIMIT_TX_ACTIVE       (2<<0)
        #define TOE_FLOW_STATE_IN_LOSS_RECOVERY      (3<<0)
        #define TOE_FLOW_STATE_FAST_RETX_INIT1       (4<<0)
        #define TOE_FLOW_STATE_FAST_RETX_INIT2       (5<<0)
        #define TOE_FLOW_STATE_FAST_RETX_RELOAD      (6<<0)
        #define TOE_FLOW_STATE_FAST_RETX_ACTIVE1     (7<<0)
        #define TOE_FLOW_STATE_FAST_RETX_ACTIVE2     (8<<0)
        #define TOE_FLOW_STATE_FAST_RECOVERY_INIT1   (9<<0)
        #define TOE_FLOW_STATE_FAST_RECOVERY_INIT2   (10<<0)
        #define TOE_FLOW_STATE_FAST_RECOVERY_ACTIVE  (11<<0)
        #define TOE_FLOW_STATE_FAST_RECOVERY_EXIT    (12<<0)
    u8_t    tcp_partial_ack_cnt;
    u8_t    timer1_mode;        // timer1 is overloaded for retx, persist, sws prevention and FIN_WAIT2 timer
    u32_t   tcp_snd_recover;
    u16_t   gen_buff_accum;
    u8_t    ooo_fin_upload_state;
        #define OOO_FIN_UPLOAD_IDLE                   (0<<0)
        #define OOO_FIN_UPLOAD_DEFER                  (1<<0)
        #define OOO_FIN_UPLOAD_NOW                    (2<<0)
        #define OOO_FIN_UPLOAD_DONE                   (3<<0)
        #define OOO_FIN_UPLOAD_DEFER_PENDING          (4<<0)
        #define OOO_FIN_UPLOAD_UNKNOWN                (5<<0)
    u8_t    reload_comp_status;
        #define RELOAD_COMP_IDLE                      (0<<0)
        #define RELOAD_COMP_HOST_PENDING              (1<<0)
        #define RELOAD_COMP_ONCHIP_PENDING            (2<<0)
    u32_t   ooo_fin_seq;
} toe_l4_cmn_ctx_b_t;

typedef struct {
    u32_t   tcp_disconnect_seq;           // last snd seq # before disconnecting
    u32_t   last_fin_seq;                  // last rx seq # in FIN packet
    u8_t    timer1_mode;        // timer1 is overloaded for retx, persist, sws prevention and FIN_WAIT2 timer
        #define TIMER1_RETX_MODE        (0)
        #define TIMER1_PERSIST_MODE     (1)
        #define TIMER1_SWS_PREVENT_MODE (2)
        #define TIMER1_FIN_WAIT2_MODE   (3)
    u8_t    tcp_partial_ack_cnt;
    u8_t    tcp_flow_state;
        #define TOE_FLOW_STATE_NORMAL_INIT            (0<<0)
        #define TOE_FLOW_STATE_NORMAL_RUNNING         (1<<0)
        #define TOE_FLOW_STATE_LIMIT_TX_ACTIVE        (2<<0)
        #define TOE_FLOW_STATE_IN_LOSS_RECOVERY       (3<<0)
        #define TOE_FLOW_STATE_FAST_RETX_INIT1        (4<<0)
        #define TOE_FLOW_STATE_FAST_RETX_INIT2        (5<<0)
        #define TOE_FLOW_STATE_FAST_RETX_RELOAD       (6<<0)
        #define TOE_FLOW_STATE_FAST_RETX_ACTIVE1      (7<<0)
        #define TOE_FLOW_STATE_FAST_RETX_ACTIVE2      (8<<0)
        #define TOE_FLOW_STATE_FAST_RECOVERY_INIT1    (9<<0)
        #define TOE_FLOW_STATE_FAST_RECOVERY_INIT2    (10<<0)
        #define TOE_FLOW_STATE_FAST_RECOVERY_ACTIVE   (11<<0)
        #define TOE_FLOW_STATE_FAST_RECOVERY_EXIT     (12<<0)
    u8_t    tcp_retx_defer;
    u32_t   tcp_snd_recover;
    u8_t    reload_comp_status;
        #define RELOAD_COMP_IDLE                      (0<<0)
        #define RELOAD_COMP_HOST_PENDING              (1<<0)
        #define RELOAD_COMP_ONCHIP_PENDING            (2<<0)
    u8_t    ooo_fin_upload_state;
    u16_t   gen_buff_accum;
    u32_t   ooo_fin_seq;
} toe_l4_cmn_ctx_l_t;

#if defined(LITTLE_ENDIAN)
    typedef toe_l4_cmn_ctx_l_t  toe_l4_cmn_ctx_t;
#elif defined(BIG_ENDIAN)
    typedef toe_l4_cmn_ctx_b_t  toe_l4_cmn_ctx_t;
#endif

typedef struct {
    tcp_cmn_ctx_t        tcp;
    toe_l4_cmn_ctx_t     toe;
} toe_cmn_ctx_t;

/////////////////////////////////////////////////////////////////////
// TOE RX section
/////////////////////////////////////////////////////////////////////
typedef struct {
    u32_t ccell_hist_bseq;
    u32_t ccell_hist_bhaddr_hi;
    u32_t ccell_hist_bhaddr_lo;
    u16_t ccell_hist_bidx;
    u16_t ccell_hist_bd_nbytes;
} toe_ccell_hist_b_t;

typedef struct {
    u32_t ccell_hist_bseq;
    u32_t ccell_hist_bhaddr_hi;
    u32_t ccell_hist_bhaddr_lo;
    u16_t ccell_hist_bd_nbytes;
    u16_t ccell_hist_bidx;
} toe_ccell_hist_l_t;

#if defined(LITTLE_ENDIAN)
    typedef toe_ccell_hist_l_t  toe_ccell_hist_t;
#elif defined(BIG_ENDIAN)
    typedef toe_ccell_hist_b_t  toe_ccell_hist_t;
#endif

#define MAX_CCELL_HIST_ENTRY    9

typedef struct {
    u8_t  l4_bd_chain_v2p_proc1flags;
    u8_t  l4_bd_chain_host_gen_count;
    u16_t l4_bd_chain_host_bdidx;
    u32_t l4_bd_chain_host_bseq;
    u32_t l4_bd_chain_nx_bdhaddr_hi;
    u32_t l4_bd_chain_nx_bdhaddr_lo;
    u32_t l4_bd_chain_nx_seq;
    u8_t  l4_bd_chain_v2p_flags;
    u8_t  l4_bd_chain_v2p_gen_count;
    u16_t l4_bd_chain_nx_bdidx;
    u16_t l4_bd_chain_gen_used;
    u16_t l4_bd_chain_nx_boff;
    u32_t l4_bd_chain_cmpl_seq;
    u32_t l4_bd_chain_cmpl_bdhaddr_hi;
    u32_t l4_bd_chain_cmpl_bdhaddr_lo;
    u16_t l4_bd_chain_gen_size;
    u16_t l4_bd_chain_cmpl_bdidx;
    u32_t l4_bd_chain_io_seq;
    u32_t l4_bd_chain_hole_seq;
    u32_t l4_bd_chain_end_seq;
    u32_t l4_bd_chain_bseq_lead;
    u32_t l4_bd_chain_push_seq;
    u32_t l4_bd_chain_gen_start_seq;
    u32_t l4_bd_chain_gen_seq;
    u32_t l4_bd_chain_gen_bfr_hi;
    u32_t l4_bd_chain_gen_bfr_lo;
    u32_t l4_bd_chain_hole2_seq;      // to keep track of 2nd holes
    u32_t l4_bd_chain_end2_seq;
    u8_t  ccell_hist_prod_idx;
    u8_t  ccell_hist_cons_idx;
    u8_t  ccell_hist_num_entry;
    u8_t  unused;
    toe_ccell_hist_t ccell_hist_tbl[MAX_CCELL_HIST_ENTRY];
} toe_l4_rx_ctx_b_t;

typedef struct {
    u16_t l4_bd_chain_host_bdidx;
    u8_t  l4_bd_chain_host_gen_count;
    u8_t  l4_bd_chain_v2p_proc1flags;
    u32_t l4_bd_chain_host_bseq;
    u32_t l4_bd_chain_nx_bdhaddr_hi;
    u32_t l4_bd_chain_nx_bdhaddr_lo;
    u32_t l4_bd_chain_nx_seq;
    u16_t l4_bd_chain_nx_bdidx;
    u8_t  l4_bd_chain_v2p_gen_count;
    u8_t  l4_bd_chain_v2p_flags;
    u16_t l4_bd_chain_nx_boff;
    u16_t l4_bd_chain_gen_used;
    u32_t l4_bd_chain_cmpl_seq;
    u32_t l4_bd_chain_cmpl_bdhaddr_hi;
    u32_t l4_bd_chain_cmpl_bdhaddr_lo;
    u16_t l4_bd_chain_cmpl_bdidx;
    u16_t l4_bd_chain_gen_size;
    u32_t l4_bd_chain_io_seq;
    u32_t l4_bd_chain_hole_seq;
    u32_t l4_bd_chain_end_seq;
    u32_t l4_bd_chain_bseq_lead;
    u32_t l4_bd_chain_push_seq;
    u32_t l4_bd_chain_gen_start_seq;
    u32_t l4_bd_chain_gen_seq;
    u32_t l4_bd_chain_gen_bfr_hi;
    u32_t l4_bd_chain_gen_bfr_lo;
    u32_t l4_bd_chain_hole2_seq;      // to keep track of 2nd holes
    u32_t l4_bd_chain_end2_seq;
    toe_ccell_hist_t ccell_hist_tbl[MAX_CCELL_HIST_ENTRY];
    u8_t  unused;
    u8_t  ccell_hist_num_entry;
    u8_t  ccell_hist_cons_idx;
    u8_t  ccell_hist_prod_idx;
} toe_l4_rx_ctx_l_t;

#if defined(LITTLE_ENDIAN)
    typedef toe_l4_rx_ctx_l_t  toe_l4_rx_ctx_t;
#elif defined(BIG_ENDIAN)
    typedef toe_l4_rx_ctx_b_t  toe_l4_rx_ctx_t;
#endif

typedef struct {
    tcp_rx_ctx_t        tcp;
    toe_l4_rx_ctx_t     toe;
} toe_rx_ctx_t;

/* container structure for entire L4 ctx, it is mainly used by VBD debugging tools */
typedef struct {
    toe_tx_ctx_t            toe_tx;
    u8_t                    unused_0[128 - sizeof(toe_tx_ctx_t)];
    toe_cmn_ctx_t           toe_cmn;   /* ctx_cmn is full */
//    u8_t                    unused_0[128 - sizeof(toe_cmn_ctx_t)];
    toe_rx_ctx_t            toe_rx;
    u8_t                    unused_1[256 - sizeof(toe_rx_ctx_t)];
    u8_t                    reserved[64];
    tcp_context_cmd_cell_te_t  toe_cmd_cell;
} toe_ctx_t;



// Calling the following macro will actually get optimized during compile
// time. Its sole purpose is to ensure the context variable locations are
// not moved by accident
#define TEST_TOE_CTX(){                           \
if (0){                                           \
 1/((sizeof(toe_ctx_t) == 0x268) &&               \
    (OFFSETOF(toe_ctx_t, toe_cmn) == 128) &&      \
    (OFFSETOF(toe_ctx_t, toe_rx)  == 128+128) &&  \
    (OFFSETOF(toe_ctx_t, toe_cmd_cell)  == 128+128+256+64));}}


/*
 *  l4_bd_chain_context_b definition
 */
typedef struct l4_bd_chain_context_b
{
    u8_t l4bdctx_v2p_proc1flags;
        #define L4BDCTX_V2P_PROC1FLAGS_BD_CHN_FLUSH         (1<<0)
        #define L4BDCTX_V2P_PROC1FLAGS_BD_FORCE_PUSH        (1<<1)

    u8_t l4bdctx_host_gen_count;
    u16_t l4bdctx_host_bdidx;
    u32_t l4bdctx_host_bseq;
    u32_t l4bdctx_nx_bdhaddr_hi;
    u32_t l4bdctx_nx_bdhaddr_lo;
    u32_t l4bdctx_nx_seq;
    u8_t l4bdctx_v2p_flags;
    u8_t l4bdctx_v2p_gen_count;
    u16_t l4bdctx_nx_bdidx;
    u16_t l4bdctx_gen_used;
    u16_t l4bdctx_nx_boff;
    u32_t l4bdctx_cmpl_seq;
    u32_t l4bdctx_cmpl_bdhaddr_hi;
    u32_t l4bdctx_cmpl_bdhaddr_lo;
    u16_t l4bdctx_gen_size;
    u16_t l4bdctx_cmpl_bdidx;
    u32_t l4bdctx_io_seq;
    u32_t l4bdctx_hole_seq;
    u32_t l4bdctx_end_seq;
    u32_t l4bdctx_bseq_lead;
    u32_t l4bdctx_push_seq;
    u32_t l4bdctx_gen_start_seq;
    u32_t l4bdctx_gen_seq;
    u32_t l4bdctx_gen_bfr_hi;
    u32_t l4bdctx_gen_bfr_lo;
} l4_bd_chain_context_b_t;


/*
 *  l4_bd_chain_context_l definition
 */
typedef struct l4_bd_chain_context_l
{
    u16_t l4bdctx_host_bdidx;
    u8_t l4bdctx_host_gen_count;
    u8_t l4bdctx_v2p_proc1flags;
        #define L4BDCTX_V2P_PROC1FLAGS_BD_CHN_FLUSH         (1<<0)
        #define L4BDCTX_V2P_PROC1FLAGS_BD_FORCE_PUSH        (1<<1)

    u32_t l4bdctx_host_bseq;
    u32_t l4bdctx_nx_bdhaddr_hi;
    u32_t l4bdctx_nx_bdhaddr_lo;
    u32_t l4bdctx_nx_seq;
    u16_t l4bdctx_nx_bdidx;
    u8_t l4bdctx_v2p_gen_count;
    u8_t l4bdctx_v2p_flags;
    u16_t l4bdctx_nx_boff;
    u16_t l4bdctx_gen_used;
    u32_t l4bdctx_cmpl_seq;
    u32_t l4bdctx_cmpl_bdhaddr_hi;
    u32_t l4bdctx_cmpl_bdhaddr_lo;
    u16_t l4bdctx_cmpl_bdidx;
    u16_t l4bdctx_gen_size;
    u32_t l4bdctx_io_seq;
    u32_t l4bdctx_hole_seq;
    u32_t l4bdctx_end_seq;
    u32_t l4bdctx_bseq_lead;
    u32_t l4bdctx_push_seq;
    u32_t l4bdctx_gen_start_seq;
    u32_t l4bdctx_gen_seq;
    u32_t l4bdctx_gen_bfr_hi;
    u32_t l4bdctx_gen_bfr_lo;
} l4_bd_chain_context_l_t;


/*
 * l4_bd_chain_context select
 */
#if defined(LITTLE_ENDIAN)
    typedef l4_bd_chain_context_l_t l4_bd_chain_context_t;
#elif defined(BIG_ENDIAN)
    typedef l4_bd_chain_context_b_t l4_bd_chain_context_t;
#endif

/*
 *  l4_context_b definition
 */
typedef struct l4_context_b
{
    u8_t l4ctx_ctx_type;
        #define L4CTX_TYPE_TYPE                             (0xf<<4)
        #define L4CTX_TYPE_TYPE_EMPTY                       (0<<4)
        #define L4CTX_TYPE_TYPE_L2                          (1<<4)
        #define L4CTX_TYPE_TYPE_TCP                         (2<<4)
        #define L4CTX_TYPE_TYPE_L5                          (3<<4)
        #define L4CTX_TYPE_TYPE_L2_BD_CHN                   (4<<4)
        #define L4CTX_TYPE_TYPE_ISCSI                       (5<<4)

    u8_t l4ctx_size;
    u8_t l4ctx_bd_pre_read;
    u8_t l4ctx_gen_bd_cid;
    u8_t l4ctx_gen_bd_max;
    u8_t l4ctx_oubits;
        #define L4CTX_OUBITS_ACTIVATE                       (1<<0)
        #define L4CTX_OUBITS_CP_UPLOAD                      (1<<1)
        #define L4CTX_OUBITS_RXP_UPLOAD                     (1<<2)
        #define L4CTX_OUBITS_TXP_UPLOAD                     (1<<3)
        #define L4CTX_OUBITS_COM_RX_UPLOAD                  (1<<4)
        #define L4CTX_OUBITS_COM_TX_UPLOAD                  (1<<5)
        #define L4CTX_OUBITS_CP_UPLOAD_COMP                 (1<<6)

    u8_t    l4ctx_force_ack_pending;
    u8_t    l4ctx_challenge_ack_state;         // refer to tcpm-tcpsecure-09 requirement
        #define CHALLENGE_ACK_NOT_SENT          0            // Challenge Ack not sent
        #define CHALLENGE_ACK_SENT_KA_DISABLED  1            // Challenge ACK is sent while KA was disabled
        #define CHALLENGE_ACK_SENT_KA_ENABLED   2            // Challenge ACK is sent while KA was enabled
    u16_t   l4ctx_tcp_pgid;
    u8_t    unused;
    u8_t    l4ctx_tcp_retx_defer;
    u32_t l4ctx_tcp_timer1;
        #define L4CTX_TCP_TIMER1_DISABLE                    (1UL<<0)
        #define L4CTX_TCP_TIMER1_VALUE                      (0x7fffffffL<<1)

    u16_t l4ctx_tcp_timer2;
        #define L4CTX_TCP_TIMER2_DISABLE                    (1<<0)
        #define L4CTX_TCP_TIMER2_VALUE                      (0x7fff<<1)

    u16_t l4ctx_tcp_timer3;
        #define L4CTX_TCP_TIMER3_DISABLE                    (1<<0)
        #define L4CTX_TCP_TIMER3_VALUE                      (0x7fff<<1)

    u16_t l4ctx_tcp_timer4;
        #define L4CTX_TCP_TIMER4_DISABLE                    (1<<0)
        #define L4CTX_TCP_TIMER4_VALUE                      (0x7fff<<1)

    u16_t l4ctx_tcp_timer5;
        #define L4CTX_TCP_TIMER5_DISABLE                    (1<<0)
        #define L4CTX_TCP_TIMER5_VALUE                      (0x7fff<<1)

    u32_t l4ctx_tcp_snd_wl1;
    u32_t l4ctx_tcp_snd_wl2;
    u8_t l4ctx_tcp_ttl;
    u8_t l4ctx_tcp_tos;
    u8_t l4ctx_tcp_dack;
    u8_t l4ctx_tcp_modes;
        #define L4CTX_TCP_MODES_RST_INDICATED_PENDING       (1<<0)
        #define L4CTX_TCP_MODES_DISC_BD                     (1<<1)
        #define L4CTX_TCP_MODES_UPLOAD_INITED               (1<<2)
        #define L4CTX_TCP_MODES_RMT_DISC                    (1<<3)
        #define L4CTX_TCP_MODES_PG_INVALIDATED              (1<<4)
        #define L4CTX_TCP_MODES_ABORT_PENDING               (1<<5)
        #define L4CTX_TCP_MODES_DISC_PENDING                (1<<6)
        #define L4CTX_TCP_MODES_STOP_TX                     (1<<7)

    u32_t l4ctx_tcp_max_adv_win;
    u32_t l4ctx_rto_intvl;         // current unbounded retransmission timeout (RTO)
    u32_t l4ctx_tcp_ip_src;
    u32_t l4ctx_tcp_ip_dst;
    u8_t l4ctx_tcp_iphdr_nbytes;
    u8_t l4ctx_tcp_snd_seg_scale;
    u8_t l4ctx_tcp_rcv_seg_scale;
    u8_t l4ctx_tcp_tcp_hlen;
    u16_t l4ctx_tcp_src_port;
    u16_t l4ctx_tcp_dst_port;
    u16_t l4ctx_tcp_mss;
    u8_t l4ctx_tcp_flags;
        #define L4CTX_TCP_FLAGS_NO_DELAY_ACK                (1<<0)
        #define L4CTX_TCP_FLAGS_KEEP_ALIVE                  (1<<1)
        #define L4CTX_TCP_FLAGS_NAGLE                       (1<<2)
        #define L4CTX_TCP_FLAGS_TIME_STAMP                  (1<<3)
        #define L4CTX_TCP_FLAGS_SACK                        (1<<4)
        #define L4CTX_TCP_FLAGS_SEG_SCALING                 (1<<5)
        #define L4CTX_TCP_FLAGS_OPTION2                     (1<<6)

    u8_t l4ctx_tcp_state;
        #define L4CTX_TCP_STATE_VALUE                       (0xff<<0)
        #define L4CTX_TCP_STATE_VALUE_UNDEFINED             (0<<0)
        #define L4CTX_TCP_STATE_VALUE_LISTEN                (2<<0)
        #define L4CTX_TCP_STATE_VALUE_SYN_SENT              (4<<0)
        #define L4CTX_TCP_STATE_VALUE_SYN_RECV              (6<<0)
        #define L4CTX_TCP_STATE_VALUE_CLOSE_WAIT            (8<<0)
        #define L4CTX_TCP_STATE_VALUE_ESTABLISHED           (10<<0)
        #define L4CTX_TCP_STATE_VALUE_FIN_WAIT1             (12<<0)
        #define L4CTX_TCP_STATE_VALUE_FIN_WAIT2             (14<<0)
        #define L4CTX_TCP_STATE_VALUE_TIME_WAIT             (16<<0)
        #define L4CTX_TCP_STATE_VALUE_CLOSED                (18<<0)
        #define L4CTX_TCP_STATE_VALUE_LAST_ACK              (20<<0)
        #define L4CTX_TCP_STATE_VALUE_CLOSING               (22<<0)
        #define L4CTX_TCP_STATE_VALUE_ABORT_CONNECTION      (24<<0)

    u32_t l4ctx_tcp_rcv_next;
    u32_t l4ctx_last_ack_sent;
    u32_t l4ctx_tcp_rcv_win_seq;
    u32_t l4ctx_tcp_snd_una;
    u32_t l4ctx_tcp_snd_next;
    u32_t l4ctx_tcp_snd_max;
    u32_t l4ctx_tcp_snd_win;
    u32_t l4ctx_tcp_snd_cwin;
    u32_t l4ctx_tcp_tstamp;
    u32_t l4ctx_tcp_ssthresh;
    u16_t l4ctx_tcp_sm_rtt;
    u16_t l4ctx_tcp_sm_delta;
    u32_t l4ctx_tcp_max_snd_win;
    u32_t l4ctx_tcp_tsch_snd_next;
    u32_t l4ctx_tcp_slot_size;
        #define L4CTX_TCP_SLOT_SIZE_SLOT_SIZE               (0xffffffL<<0)
        #define L4CTX_TCP_SLOT_SIZE_CMD_MAX                 (0x7fL<<24)
        #define L4CTX_TCP_SLOT_SIZE_STOP                    (1UL<<31)

    u8_t l4ctx_tcp_cp_cmd;
    u8_t l4ctx_tcp_tsch_cmd;
    u8_t l4ctx_tcp_cons_retx_num;
    u8_t l4ctx_tcp_tsch_xnum;
        #define L4CTX_TCP_TSCH_XNUM_VAL                     (0x7f<<0)
        #define L4CTX_TCP_TSCH_XNUM_L4                      (1<<7)

    u8_t l4ctx_tcp_num_dupack;
    u8_t l4ctx_tcp_tx_protocol_flags;
        #define L4CTX_TCP_TX_PROTOCOL_FLAGS_TIMER_DELAY_ACK  (1<<0)
        #define L4CTX_TCP_TX_PROTOCOL_FLAGS_UPLOAD          (1<<1)
        #define L4CTX_TCP_TX_PROTOCOL_FLAGS_FORCE_ACK       (1<<2)
        #define L4CTX_TCP_TX_PROTOCOL_FLAGS_LAST_ACK        (1<<3)
        #define L4CTX_TCP_TX_PROTOCOL_FLAGS_LAST_RST        (1<<4)
        /* TOE stack overload bit 4 to signal TXP to sends out pure ack
         * TOE stack should never use last RST bit
         */
        #define L4CTX_TCP_TX_PROTOCOL_FLAGS_PURE_ACK        L4CTX_TCP_TX_PROTOCOL_FLAGS_LAST_RST
        #define L4CTX_TCP_TX_PROTOCOL_FLAGS_FORCE_RST       (1<<5)
        #define L4CTX_TCP_TX_PROTOCOL_FLAGS_FORCE_ACK_MINUS (1<<6)
        #define L4CTX_TCP_TX_PROTOCOL_FLAGS_SKIP_KA         (1<<7)

    u8_t l4ctx_tcp_prod_retx_num;
    u8_t l4ctx_tcp_tsch_cons_retx_num;
    u8_t l4ctx_tcp_comp_cons_retx_num;
    u8_t l4ctx_tcp_num_retx;
    u8_t l4ctx_tcp_upload_reason;
        #define L4CTX_TCP_UPLOAD_REASON_KEEP_ALIVE          (1<<0)
        #define L4CTX_TCP_UPLOAD_REASON_FIN                 (1<<1)
        #define L4CTX_TCP_UPLOAD_REASON_URG                 (1<<2)
        #define L4CTX_TCP_UPLOAD_REASON_FRAGMENT            (1<<3)
        #define L4CTX_TCP_UPLOAD_REASON_IP_OPTION           (1<<4)
        #define L4CTX_TCP_UPLOAD_REASON_RST                 (1<<5)
        #define L4CTX_TCP_UPLOAD_REASON_SYN                 (1<<6)
        #define L4CTX_TCP_UPLOAD_REASON_TIMEOUT             (1<<7)

    u8_t l4ctx_tcp_txp_cmd;
    u32_t l4ctx_tcp_offload_seq;
    tcp_context_cmd_cell_te_t l4ctx_cmd[1];
    u8_t l4ctx_l4_bd_chain_v2p_proc1flags;
        #define L4CTX_L4_BD_CHAIN_V2P_PROC1FLAGS_BD_CHN_FLUSH             (1<<0)
        #define L4CTX_L4_BD_CHAIN_V2P_PROC1FLAGS_BD_CHN_FORCE_PUSH        (1<<1)

    u8_t l4ctx_l4_bd_chain_host_gen_count;
    u16_t l4ctx_l4_bd_chain_host_bdidx;
    u32_t l4ctx_l4_bd_chain_host_bseq;
    u32_t l4ctx_l4_bd_chain_nx_bdhaddr_hi;
    u32_t l4ctx_l4_bd_chain_nx_bdhaddr_lo;
    u32_t l4ctx_l4_bd_chain_nx_seq;
    u8_t l4ctx_l4_bd_chain_v2p_flags;
        #define L4CTX_L4_BD_CHAIN_V2P_FLAGS_GEN_BD_IN_USE   (1<<1)
        #define L4CTX_L4_BD_CHAIN_V2P_FLAGS_HOLE_MODE       (1<<2)
        #define L4CTX_L4_BD_CHAIN_V2P_FLAGS_INDICATED       (1<<3)
        #define L4CTX_L4_BD_CHAIN_V2P_FLAGS_PUSH_ARMED      (1<<4)
        #define L4CTX_L4_BD_CHAIN_V2P_FLAGS_PUSH_PENDING    (1<<5)
        #define L4CTX_L4_BD_CHAIN_V2P_FLAGS_2ND_HOLE_MODE   (1<<6)
        #define L4CTX_L4_BD_CHAIN_V2P_FLAGS_NEW_ISLAND      (1<<7)  // 0 : 1st (inside) island is newer
                                                                    // 1 : 2nd (outside) island is newer
    u8_t l4ctx_l4_bd_chain_v2p_gen_count;
    u16_t l4ctx_l4_bd_chain_nx_bdidx;
    u16_t l4ctx_l4_bd_chain_gen_used;
    u16_t l4ctx_l4_bd_chain_nx_boff;
    u32_t l4ctx_l4_bd_chain_cmpl_seq;
    u32_t l4ctx_l4_bd_chain_cmpl_bdhaddr_hi;
    u32_t l4ctx_l4_bd_chain_cmpl_bdhaddr_lo;
    u16_t l4ctx_l4_bd_chain_gen_size;
    u16_t l4ctx_l4_bd_chain_cmpl_bdidx;
    u32_t l4ctx_l4_bd_chain_io_seq;
    u32_t l4ctx_l4_bd_chain_hole_seq;
    u32_t l4ctx_l4_bd_chain_end_seq;
    u32_t l4ctx_l4_bd_chain_bseq_lead;
    u32_t l4ctx_l4_bd_chain_push_seq;
    u32_t l4ctx_l4_bd_chain_gen_start_seq;
    u32_t l4ctx_l4_bd_chain_gen_seq;
    u32_t l4ctx_l4_bd_chain_gen_bfr_hi;
    u32_t l4ctx_l4_bd_chain_gen_bfr_lo;
    u32_t l4ctx_tx_comp_step;
    u16_t l4ctx_max_rt_tick;               // maximum total retransmit timeout (in ticks)
    u16_t l4ctx_total_rt_tick;             // total retransmit timeout  (in ticks)
    u32_t l4ctx_ooo_fin_seq;
    u32_t l4ctx_unused;
    u32_t l4ctx_tcp_last_rcv_win_seq;
    u32_t l4ctx_tcp_save_cwin;
    u8_t  l4ctx_tcp_flow_state;
        #define  TOE_FLOW_STATE_NORMAL_INIT           (0<<0)
        #define  TOE_FLOW_STATE_NORMAL_RUNNING        (1<<0)
        #define  TOE_FLOW_STATE_LIMIT_TX_ACTIVE       (2<<0)
        #define  TOE_FLOW_STATE_IN_LOSS_RECOVERY      (3<<0)
        #define  TOE_FLOW_STATE_FAST_RETX_INIT1       (4<<0)
        #define  TOE_FLOW_STATE_FAST_RETX_INIT2       (5<<0)
        #define  TOE_FLOW_STATE_FAST_RETX_RELOAD      (6<<0)
        #define  TOE_FLOW_STATE_FAST_RETX_ACTIVE1     (7<<0)
        #define  TOE_FLOW_STATE_FAST_RETX_ACTIVE2     (8<<0)
        #define  TOE_FLOW_STATE_FAST_RECOVERY_INIT1   (9<<0)
        #define  TOE_FLOW_STATE_FAST_RECOVERY_INIT2   (10<<0)
        #define  TOE_FLOW_STATE_FAST_RECOVERY_ACTIVE  (11<<0)
        #define  TOE_FLOW_STATE_FAST_RECOVERY_EXIT    (12<<0)
        #define  TCP_FLOW_NORMAL(x)         ((x) <= TOE_FLOW_STATE_NORMAL_RUNNING)
        #define  TCP_FLOW_LIMIT_TX(x)       ((x) == TOE_FLOW_STATE_LIMIT_TX_ACTIVE )
        #define  TCP_FLOW_LOSS_RECOVERY(x)  ((x) == TOE_FLOW_STATE_LOSS_RECOVERY )
        #define  TCP_FLOW_FAST_RETX(x)      ((x) >= TOE_FLOW_STATE_FAST_RETX_INIT1  \
                                          && (x) <= TOE_FLOW_STATE_FAST_RECOVERY_ACTIVE)
        #define  TCP_FLOW_FAST_RECOVERY(x)  ((x) >= TOE_FLOW_STATE_FAST_RECOVERY_INIT1)
    u8_t  l4ctx_tcp_partial_ack_cnt;
    u8_t  l4ctx_timer1_mode;        // timer1 is overloaded for retx, persist, sws prevention and FIN_WAIT2 timer
        #define TIMER1_RETX_MODE                      (0)
        #define TIMER1_PERSIST_MODE                   (1)
        #define TIMER1_SWS_PREVENT_MODE               (2)
        #define TIMER1_FIN_WAIT2_MODE                 (3)
    u8_t  l4ctx_ooo_fin_upload_state;
        #define OOO_FIN_UPLOAD_IDLE                   (0<<0)
        #define OOO_FIN_UPLOAD_DEFER                  (1<<0)
        #define OOO_FIN_UPLOAD_NOW                    (2<<0)
        #define OOO_FIN_UPLOAD_DONE                   (3<<0)
        #define OOO_FIN_UPLOAD_DEFER_PENDING          (4<<0)
        #define OOO_FIN_UPLOAD_UNKNOWN                (5<<0)
    u32_t l4ctx_last_fin_seq;              // last rx seq # in FIN packet
    u8_t  l4ctx_persist_probe_cnt;
    u8_t  l4ctx_reload_comp_status;
        #define RELOAD_COMP_IDLE                      (0<<0)
        #define RELOAD_COMP_HOST_PENDING              (1<<0)
        #define RELOAD_COMP_ONCHIP_PENDING            (2<<0)
    u8_t  l4ctx_tx_flags;
        #define L4CTX_TX_FLAGS_IN_COALESCE            (1<<1)
        #define L4CTX_TX_FLAGS_IND_SILLY_WIN          (1<<2)
        #define L4CTX_TX_FLAGS_LARGE_BD               (1<<3)
    u8_t  l4ctx_ka_probe_cnt;

    u32_t l4ctx_tcp_disconnect_seq;          // last snd seq # before disconnecting
    u32_t l4ctx_tcp_snd_recover;
    u32_t l4ctx_reply_ts;
        #define TOE_RTT_SAMPLED                       (1<<0)
    u16_t l4ctx_ka_timeout_tick;
    u16_t l4ctx_ka_interval_tick;

    u8_t  l4ctx_tx_comp_prod;
    u8_t  l4ctx_tx_comp_cons;
    u8_t  l4ctx_ka_max_probe_cnt;
    u8_t  l4ctx_in_generic;

    u32_t l4ctx_host_win_update;
    u16_t l4ctx_cam_index;
    u16_t l4ctx_gen_buff_accum;
} l4_context_b_t;




/*
 *  l4_context_l definition
 */
typedef struct l4_context_l
{
    u8_t l4ctx_gen_bd_cid;
    u8_t l4ctx_bd_pre_read;
    u8_t l4ctx_size;
    u8_t l4ctx_ctx_type;
        #define L4CTX_TYPE_TYPE                             (0xf<<4)
        #define L4CTX_TYPE_TYPE_EMPTY                       (0<<4)
        #define L4CTX_TYPE_TYPE_L2                          (1<<4)
        #define L4CTX_TYPE_TYPE_TCP                         (2<<4)
        #define L4CTX_TYPE_TYPE_L5                          (3<<4)
        #define L4CTX_TYPE_TYPE_L2_BD_CHN                   (4<<4)
        #define L4CTX_TYPE_TYPE_ISCSI                       (5<<4)

    u8_t    l4ctx_challenge_ack_state;         // refer to tcpm-tcpsecure-09 requirement
    u8_t    l4ctx_force_ack_pending;
    u8_t l4ctx_oubits;
        #define L4CTX_OUBITS_ACTIVATE                       (1<<0)
        #define L4CTX_OUBITS_CP_UPLOAD                      (1<<1)
        #define L4CTX_OUBITS_RXP_UPLOAD                     (1<<2)
        #define L4CTX_OUBITS_TXP_UPLOAD                     (1<<3)
        #define L4CTX_OUBITS_COM_RX_UPLOAD                  (1<<4)
        #define L4CTX_OUBITS_COM_TX_UPLOAD                  (1<<5)
        #define L4CTX_OUBITS_CP_UPLOAD_COMP                 (1<<6)

    u8_t l4ctx_gen_bd_max;
    u8_t l4ctx_tcp_retx_defer;
    u8_t unused;
    u16_t l4ctx_tcp_pgid;
    u32_t l4ctx_tcp_timer1;
        #define L4CTX_TCP_TIMER1_DISABLE                    (1UL<<0)
        #define L4CTX_TCP_TIMER1_VALUE                      (0x7fffffffL<<1)

    u16_t l4ctx_tcp_timer3;
        #define L4CTX_TCP_TIMER3_DISABLE                    (1<<0)
        #define L4CTX_TCP_TIMER3_VALUE                      (0x7fff<<1)

    u16_t l4ctx_tcp_timer2;
        #define L4CTX_TCP_TIMER2_DISABLE                    (1<<0)
        #define L4CTX_TCP_TIMER2_VALUE                      (0x7fff<<1)

    u16_t l4ctx_tcp_timer5;
        #define L4CTX_TCP_TIMER5_DISABLE                    (1<<0)
        #define L4CTX_TCP_TIMER5_VALUE                      (0x7fff<<1)

    u16_t l4ctx_tcp_timer4;
        #define L4CTX_TCP_TIMER4_DISABLE                    (1<<0)
        #define L4CTX_TCP_TIMER4_VALUE                      (0x7fff<<1)

    u32_t l4ctx_tcp_snd_wl1;
    u32_t l4ctx_tcp_snd_wl2;
    u8_t l4ctx_tcp_modes;
        #define L4CTX_TCP_MODES_RST_INDICATED               (1<<0)
        #define L4CTX_TCP_MODES_DISC_BD                     (1<<1)
        #define L4CTX_TCP_MODES_UPLOAD_INITED               (1<<2)
        #define L4CTX_TCP_MODES_RMT_DISC                    (1<<3)
        #define L4CTX_TCP_MODES_PG_INVALIDATED              (1<<4)
        #define L4CTX_TCP_MODES_ABORT_PENDING               (1<<5)
        #define L4CTX_TCP_MODES_DISC_PENDING                (1<<6)
        #define L4CTX_TCP_MODES_SS                          (1<<7)

    u8_t l4ctx_tcp_dack;
    u8_t l4ctx_tcp_tos;
    u8_t l4ctx_tcp_ttl;
    u32_t l4ctx_tcp_max_adv_win;
    u32_t l4ctx_tcp_rto_intvl;     // current  unbounded retransmission timeout (RTO)
    u32_t l4ctx_tcp_ip_src;
    u32_t l4ctx_tcp_ip_dst;
    u8_t l4ctx_tcp_tcp_hlen;
    u8_t l4ctx_tcp_rcv_seg_scale;
    u8_t l4ctx_tcp_snd_seg_scale;
    u8_t l4ctx_tcp_iphdr_nbytes;
    u16_t l4ctx_tcp_dst_port;
    u16_t l4ctx_tcp_src_port;
    u8_t l4ctx_tcp_state;
        #define L4CTX_TCP_STATE_VALUE                       (0xff<<0)
        #define L4CTX_TCP_STATE_VALUE_UNDEFINED             (0<<0)
        #define L4CTX_TCP_STATE_VALUE_LISTEN                (2<<0)
        #define L4CTX_TCP_STATE_VALUE_SYN_SENT              (4<<0)
        #define L4CTX_TCP_STATE_VALUE_SYN_RECV              (6<<0)
        #define L4CTX_TCP_STATE_VALUE_CLOSE_WAIT            (8<<0)
        #define L4CTX_TCP_STATE_VALUE_ESTABLISHED           (10<<0)
        #define L4CTX_TCP_STATE_VALUE_FIN_WAIT1             (12<<0)
        #define L4CTX_TCP_STATE_VALUE_FIN_WAIT2             (14<<0)
        #define L4CTX_TCP_STATE_VALUE_TIME_WAIT             (16<<0)
        #define L4CTX_TCP_STATE_VALUE_CLOSED                (18<<0)
        #define L4CTX_TCP_STATE_VALUE_LAST_ACK              (20<<0)
        #define L4CTX_TCP_STATE_VALUE_CLOSING               (22<<0)
        #define L4CTX_TCP_STATE_VALUE_ABORT_CONNECTION      (24<<0)

    u8_t l4ctx_tcp_flags;
        #define L4CTX_TCP_FLAGS_NO_DELAY_ACK                (1<<0)
        #define L4CTX_TCP_FLAGS_KEEP_ALIVE                  (1<<1)
        #define L4CTX_TCP_FLAGS_NAGLE                       (1<<2)
        #define L4CTX_TCP_FLAGS_TIME_STAMP                  (1<<3)
        #define L4CTX_TCP_FLAGS_SACK                        (1<<4)
        #define L4CTX_TCP_FLAGS_SEG_SCALING                 (1<<5)
        #define L4CTX_TCP_FLAGS_OPTION2                     (1<<6)
        #define L4CTX_TCP_FLAGS_SEND_SYN                    (1<<7)

    u16_t l4ctx_tcp_mss;
    u32_t l4ctx_tcp_rcv_next;
    u32_t l4ctx_last_ack_sent;
    u32_t l4ctx_tcp_rcv_win_seq;
    u32_t l4ctx_tcp_snd_una;
    u32_t l4ctx_tcp_snd_next;
    u32_t l4ctx_tcp_snd_max;
    u32_t l4ctx_tcp_snd_win;
    u32_t l4ctx_tcp_snd_cwin;
    u32_t l4ctx_tcp_tstamp;
    u32_t l4ctx_tcp_ssthresh;
    u16_t l4ctx_tcp_sm_delta;
    u16_t l4ctx_tcp_sm_rtt;
    u32_t l4ctx_tcp_max_snd_win;
    u32_t l4ctx_tcp_tsch_snd_next;
    u32_t l4ctx_tcp_slot_size;
        #define L4CTX_TCP_SLOT_SIZE_SLOT_SIZE               (0xffffffL<<0)
        #define L4CTX_TCP_SLOT_SIZE_CMD_MAX                 (0x7fL<<24)
        #define L4CTX_TCP_SLOT_SIZE_STOP                    (1UL<<31)

    u8_t l4ctx_tcp_tsch_xnum;
        #define L4CTX_TCP_TSCH_XNUM_VAL                     (0x7f<<0)
        #define L4CTX_TCP_TSCH_XNUM_L4                      (1<<7)

    u8_t l4ctx_tcp_cons_retx_num;
    u8_t l4ctx_tcp_tsch_cmd;
    u8_t l4ctx_tcp_cp_cmd;
    u8_t l4ctx_tcp_tsch_cons_retx_num;
    u8_t l4ctx_tcp_prod_retx_num;
    u8_t l4ctx_tcp_tx_protocol_flags;
    u8_t l4ctx_tcp_num_dupack;
    u8_t l4ctx_tcp_txp_cmd;
    u8_t l4ctx_tcp_upload_reason;
        #define L4CTX_TCP_UPLOAD_REASON_KEEP_ALIVE          (1<<0)
        #define L4CTX_TCP_UPLOAD_REASON_FIN                 (1<<1)
        #define L4CTX_TCP_UPLOAD_REASON_URG                 (1<<2)
        #define L4CTX_TCP_UPLOAD_REASON_FRAGMENT            (1<<3)
        #define L4CTX_TCP_UPLOAD_REASON_IP_OPTION           (1<<4)
        #define L4CTX_TCP_UPLOAD_REASON_RST                 (1<<5)
        #define L4CTX_TCP_UPLOAD_REASON_SYN                 (1<<6)
        #define L4CTX_TCP_UPLOAD_REASON_TIMEOUT             (1<<7)

    u8_t l4ctx_tcp_num_retx;
    u8_t l4ctx_tcp_comp_cons_retx_num;
    u32_t l4ctx_tcp_offload_seq;
    tcp_context_cmd_cell_te_t l4ctx_cmd[1];
    u16_t l4ctx_l4_bd_chain_host_bdidx;
    u8_t l4ctx_l4_bd_chain_host_gen_count;
    u8_t l4ctx_l4_bd_chain_v2p_proc1flags;
        #define L4CTX_L4_BD_CHAIN_V2P_PROC1FLAGS_BD_CHN_FLUSH             (1<<0)
        #define L4CTX_L4_BD_CHAIN_V2P_PROC1FLAGS_BD_CHN_FORCE_PUSH        (1<<1)
    u32_t l4ctx_l4_bd_chain_host_bseq;
    u32_t l4ctx_l4_bd_chain_nx_bdhaddr_hi;
    u32_t l4ctx_l4_bd_chain_nx_bdhaddr_lo;
    u32_t l4ctx_l4_bd_chain_nx_seq;
    u16_t l4ctx_l4_bd_chain_nx_bdidx;
    u8_t l4ctx_l4_bd_chain_v2p_gen_count;
    u8_t l4ctx_l4_bd_chain_v2p_flags;
    u16_t l4ctx_l4_bd_chain_nx_boff;
    u16_t l4ctx_l4_bd_chain_gen_used;
    u32_t l4ctx_l4_bd_chain_cmpl_seq;
    u32_t l4ctx_l4_bd_chain_cmpl_bdhaddr_hi;
    u32_t l4ctx_l4_bd_chain_cmpl_bdhaddr_lo;
    u16_t l4ctx_l4_bd_chain_cmpl_bdidx;
    u16_t l4ctx_l4_bd_chain_gen_size;
    u32_t l4ctx_l4_bd_chain_io_seq;
    u32_t l4ctx_l4_bd_chain_hole_seq;
    u32_t l4ctx_l4_bd_chain_end_seq;
    u32_t l4ctx_l4_bd_chain_bseq_lead;
    u32_t l4ctx_l4_bd_chain_push_seq;
    u32_t l4ctx_l4_bd_chain_gen_start_seq;
    u32_t l4ctx_l4_bd_chain_gen_seq;
    u32_t l4ctx_l4_bd_chain_gen_bfr_hi;
    u32_t l4ctx_l4_bd_chain_gen_bfr_lo;
    u32_t l4ctx_tx_comp_step;
    u16_t l4ctx_total_rt_tick;             // total retransmit timeout  (in ticks)
    u16_t l4ctx_max_rt_tick;               // maximum total retransmit timeout (in ticks)
    u32_t l4ctx_ooo_fin_seq;
    u32_t l4ctx_unused;
    u32_t l4ctx_tcp_last_rcv_win_seq;
    u32_t l4ctx_tcp_save_cwin;
    u8_t  l4ctx_ooo_fin_upload_state;
    u8_t  l4ctx_timer1_mode;        // timer1 is overloaded for retx, persist, sws prevention and FIN_WAIT2 timer
    u8_t  l4ctx_tcp_partial_ack_cnt;
    u8_t  l4ctx_tcp_flow_state;
        #define  TOE_FLOW_STATE_NORMAL_INIT           (0<<0)
        #define  TOE_FLOW_STATE_NORMAL_RUNNING        (1<<0)
        #define  TOE_FLOW_STATE_LIMIT_TX_ACTIVE       (2<<0)
        #define  TOE_FLOW_STATE_IN_LOSS_RECOVERY      (3<<0)
        #define  TOE_FLOW_STATE_FAST_RETX_INIT1       (4<<0)
        #define  TOE_FLOW_STATE_FAST_RETX_INIT2       (5<<0)
        #define  TOE_FLOW_STATE_FAST_RETX_RELOAD      (6<<0)
        #define  TOE_FLOW_STATE_FAST_RETX_ACTIVE1     (7<<0)
        #define  TOE_FLOW_STATE_FAST_RETX_ACTIVE2     (8<<0)
        #define  TOE_FLOW_STATE_FAST_RECOVERY_INIT1   (9<<0)
        #define  TOE_FLOW_STATE_FAST_RECOVERY_INIT2   (10<<0)
        #define  TOE_FLOW_STATE_FAST_RECOVERY_ACTIVE  (11<<0)
        #define  TOE_FLOW_STATE_FAST_RECOVERY_EXIT    (12<<0)
    u32_t l4ctx_last_fin_seq;              // last rx seq # in FIN packet
    u8_t  l4ctx_ka_probe_cnt;
    u8_t  l4ctx_tx_flags;
        #define L4CTX_TX_FLAGS_IN_COALESCE            (1<<1)
        #define L4CTX_TX_FLAGS_IND_SILLY_WIN          (1<<2)
    u8_t  l4ctx_reload_comp_status;
        #define RELOAD_COMP_IDLE                      (0<<0)
        #define RELOAD_COMP_HOST_PENDING              (1<<0)
        #define RELOAD_COMP_ONCHIP_PENDING            (2<<0)
    u8_t  l4ctx_persist_probe_cnt;
    u32_t l4ctx_tcp_disconnect_seq;          // last snd seq # before disconnecting
    u32_t l4ctx_tcp_snd_recover;
    u32_t l4ctx_reply_ts;
        #define TOE_RTT_SAMPLED                       (1<<0)
    u16_t l4ctx_ka_interval;
    u16_t l4ctx_ka_timeout;
    u8_t  l4ctx_in_generic;
    u8_t  l4ctx_ka_max_probe_cnt;
    u8_t  l4ctx_tx_comp_con;
    u8_t  l4ctx_tx_comp_prod;
    u32_t l4ctx_host_win_update;
    u16_t l4ctx_gen_buff_accum;
    u16_t l4ctx_cam_index;
} l4_context_l_t;





/*
 * l4_context select
 */
#if defined(LITTLE_ENDIAN)
    typedef l4_context_l_t l4_context_t;
#elif defined(BIG_ENDIAN)
    typedef l4_context_b_t l4_context_t;
#endif


#endif /* _TOE_CTX_H */

