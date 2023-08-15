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

#ifndef _TCP_CTX_H
#define _TCP_CTX_H

#include "bcmtype.h"
#include "l2_defs.h"

/////////////////////////////////////////////////////////////////////
// TCP TX section
/////////////////////////////////////////////////////////////////////

#if defined(LITTLE_ENDIAN)
    typedef struct {
        u32_t  tcp_tsch_snd_next;        // TSCH copy of snd_next, used for window calculations
        u32_t  tcp_snd_max;              // TCP snd_max
        u8_t   tcp_tsch_xnum;            // last slot number that was scheduled by TSCH
        u8_t   tcp_cons_retx_num;        // last retransmit flush index that COM has received completion for
        u8_t   tcp_tsch_cmd;             // Index of next ccell to be scheduled by TSCH
        u8_t   tcp_cp_cmd;               // Command Queue producer
        u8_t   tcp_tsch_cons_retx_num;   // last retransmit flush index that was sent by TSCH
        u8_t   tcp_prod_retx_num;        // Retransmit flush is initiated by incrementing this member
        u16_t  tcp_pgid;                 // L2 context cid that belong to this connection
        u8_t   cam_pending;              // number of free entries in the CAM that are reserved for offloading the connection
        u8_t   tcp_tcp_hlen;             // size of TCP header in 32 bit  words
        u8_t   tcp_iphdr_nbytes;         // size of IP header in bytes
        u8_t   l2_slot_size;             // N/A for iSCSI
        u32_t  tcp_max_adv_win;          // Maximum advertised window to the remote peer
        u8_t   tcp_modes;
        u8_t   tcp_dack;
        u8_t   tcp_tos;
        u8_t   tcp_ttl;
        union {
            u32_t  tcp_ip_dst;           // destination IP address
            u32_t  tcp_ipv6_dst[4];      // destination IP v6 address
        }u1;
        union {
            u32_t  tcp_ip_src;	         // source IP address
            u32_t  tcp_ipv6_src[4];      // source IP v6 address
        }u2;
        u16_t  tcp_dst_port;             // TCP destination port number
        u16_t  tcp_src_port;             // TCP source port number
    } tcp_tx_ctx_l_t;
    typedef tcp_tx_ctx_l_t  tcp_tx_ctx_t;
#elif defined(BIG_ENDIAN)
    typedef struct {
        u32_t  tcp_tsch_snd_next;        // TSCH copy of snd_next, used for window calculations
        u32_t  tcp_snd_max;              // TCP snd_max
        u8_t   tcp_cp_cmd;               // Command Queue producer
        u8_t   tcp_tsch_cmd;             // Index of next ccell to be scheduled by TSCH
        u8_t   tcp_cons_retx_num;        // last retransmit flush index that COM has received completion for
        u8_t   tcp_tsch_xnum;            // last slot number that was scheduled by TSCH
        u16_t  tcp_pgid;                 // L2 context cid that belong to this connection
        u8_t   tcp_prod_retx_num;        // Retransmit flush is initiated by incrementing this member
        u8_t   tcp_tsch_cons_retx_num;   // last retransmit flush index that was sent by TSCH
        u8_t   l2_slot_size;             // N/A for iSCSI
        u8_t   tcp_iphdr_nbytes;         // size of IP header in bytes
        u8_t   tcp_tcp_hlen;             // size of TCP header in 32 bit  words
        u8_t   cam_pending;              // number of free entries in the CAM that are reserved for offloading the connection
        u32_t  tcp_max_adv_win;          // Maximum advertised window to the remote peer
        u8_t   tcp_ttl;
        u8_t   tcp_tos;
        u8_t   tcp_dack;
        u8_t   tcp_modes;
            #define L4CTX_TCP_MODES_RST_INDICATED_PENDING       (1<<0)
            #define L4CTX_TCP_MODES_DISC_BD                     (1<<1)
            #define L4CTX_TCP_MODES_UPLOAD_INITED               (1<<2)
            #define L4CTX_TCP_MODES_RMT_DISC                    (1<<3)
            #define L4CTX_TCP_MODES_PG_INVALIDATED              (1<<4)
            #define L4CTX_TCP_MODES_ABORT_PENDING               (1<<5)
            #define L4CTX_TCP_MODES_DISC_PENDING                (1<<6)
            #define L4CTX_TCP_MODES_STOP_TX                     (1<<7)
        union {
            u32_t  tcp_ip_dst;           // destination IP address
            u32_t  tcp_ipv6_dst[4];      // destination IP v6 address
        };
        union {
            u32_t  tcp_ip_src;	         // source IP address
            u32_t  tcp_ipv6_src[4];      // source IP v6 address
        };
        u16_t  tcp_src_port;             // TCP source port number
        u16_t  tcp_dst_port;             // TCP destination port number
    } tcp_tx_ctx_b_t;

    typedef tcp_tx_ctx_b_t  tcp_tx_ctx_t;
#endif
/////////////////////////////////////////////////////////////////////
// TCP CMN section
/////////////////////////////////////////////////////////////////////

// Congestion avoidance and slow start require that two variables be maintained
// for each connection: a congestion window, cwnd, and a slow start threshold
// size, ssthresh. Initialization for a given connection sets cwnd to one segment
// and ssthresh to 65535 (or 0xFFFF)bytes. (but MS passed down 0xFFFFFFFF as
// initial value)
#define INITIAL_SSTHRESH_VAL    0xFFFFFFFF
#define MAX_SSTHRESH_VAL        0x7FFFFFFF

typedef struct {
    u8_t    ctx_type;                   // 0x0     context type enum
        #define CTX_TYPE_ISCSI                           (5<<4)
    u8_t    size;                       // 0x1     context size in bytes
    u8_t    bd_pre_read;                // 0x2
    u8_t    gen_bd_cid;                 // 0x3
    u8_t    gen_bd_max;                 // 0x4
    u8_t    oubits;                     // 0x5
    u16_t   sq_prod;                    // 0x6     SQ producer, updated by host via mailbox. wraps at size: bits 0 - (k-1): queue element index within page, bits k - 15: page index in page table
    u8_t    tcp_flags;                  // 0x8
    u8_t    tcp_state;                  // 0x9     TCP state machine
    union idx16_union_t rq_prod;        // 0xa     RQ producer, updated by driver, wraps at rq_size
    u32_t   tcp_timer1;                 // 0xc     retransmit timer
    u16_t   tcp_timer2;                 // 0x10
    u16_t   tcp_timer3;                 //
    u16_t   tcp_timer4;                 // 0x14
    u16_t   tcp_timer5;                 //
    u32_t   tcp_slot_size;              // 0x18
        #define L4CTX_TCP_SLOT_SIZE_SLOT_SIZE               (0xffffffL<<0)
        #define L4CTX_TCP_SLOT_SIZE_CMD_MAX                 (0x7fL<<24)
        #define L4CTX_TCP_SLOT_SIZE_STOP                    (1UL<<31)
    u32_t   tcp_snd_cwin;               // 0x1c
    u32_t   tcp_snd_win;                // 0x20
    u8_t    tcp_num_dupack;             // 0x24    number of consecutive duplicate ACK received
    u8_t    tcp_tx_protocol_flags;      // 0x25    ack/rst/syn/fin indication
    u8_t    tcp_comp_cons_retx_num;     //         Last retransmit flush index that was completed by TXP
    u8_t    tcp_num_retx;               //
    u32_t   tcp_fl;                     //         TCP flow label for IPV6
    u32_t   tcp_ssthresh;               // 0x2c    TCP slow start threshold
    u32_t   tcp_rcv_next;               // 0x30    TCP receive next sequence number
    u32_t   tcp_rcv_win_seq;            //         unused in iSCSI
    u32_t   tcp_snd_una;                //
    u32_t   tcp_snd_next;               //
    u32_t   tcp_sm_rtt;                 // 0x40
    u32_t   tcp_sm_delta;               //
    u32_t   tcp_max_snd_win;            //
    u8_t    tcp_txp_cmd;                // 0x4c    index of the ccell that the TXP is currently transmitting
    u8_t    tcp_upload_reason;          //
	u8_t   	tcp_rcv_seg_scale;        	// 		   TCP segment scale that is advertised by Xinan
    u8_t    tcp_ulp_ooo_flags;
#define TCP_ULP_OOO_DETECTED		(0x01)
	u32_t  	last_ack_sent;        	//         TCP ack sequence of the previous packet transmitted
    u32_t   tcp_offload_seq;            //         initial TCP seq number of the Xinan sid (i.e. bseq + offload_seq = tcp_seq)
    u32_t   tcp_tstamp;                 //
    u16_t   tcp_mss;                    //         mss of the connection
    u8_t    ka_probe_cnt;
    u8_t    ka_max_probe_cnt;
    u8_t    force_ack_pending;
    u8_t    krnlq_id;                   //         indicate which krnlq that kcqe should be written to.
    u16_t   ka_timeout_tick;
    u16_t   ka_interval_tick;
    u8_t    unused2;
    u8_t    challenge_ack_state;         //         refer to tcpm-tcpsecure-09 requirement
        #define CHALLENGE_ACK_NOT_SENT          0            // Challenge Ack not sent
        #define CHALLENGE_ACK_SENT_KA_DISABLED  1            // Challenge ACK is sent while KA was disabled
        #define CHALLENGE_ACK_SENT_KA_ENABLED   2            // Challenge ACK is sent while KA was enabled
} tcp_cmn_ctx_b_t;

typedef struct {
    u8_t    gen_bd_cid;                 // 0x0
    u8_t    bd_pre_read;                // 0x1
    u8_t    size;                       // 0x2
    u8_t    ctx_type;                   // 0x3     context type enum
    u16_t   sq_prod;                    // 0x4     SQ producer, updated by host via mailbox. wraps at size: bits 0 - (k-1): queue element index within page, bits k - 15: page index in page table
    u8_t    oubits;                     // 0x6      ???
    u8_t    gen_bd_max;                 // 0x7
    u16_t   rq_prod;                    // 0x8     RQ producer, updated by driver, wraps at rq_size
    u8_t    tcp_state;                  // 0xa     TCP state machine
    u8_t    tcp_flags;                  // 0xb
    u32_t   tcp_timer1;                 // 0xc     retransmit timer
    u16_t   tcp_timer3;                 //
    u16_t   tcp_timer2;                 // 0x10
    u16_t   tcp_timer5;                 //
    u16_t   tcp_timer4;                 // 0x14
    u32_t   tcp_slot_size;              // 0x18
    u32_t   tcp_snd_cwin;               // 0x1c
    u32_t   tcp_snd_win;                // 0x20
    u8_t    tcp_num_retx;               //
    u8_t    tcp_comp_cons_retx_num;     //         Last retransmit flush index that was completed by TXP
    u8_t    tcp_tx_protocol_flags;      // 0x25    ack/rst/syn/fin indication
    u8_t    tcp_num_dupack;             // 0x24    number of consecutive duplicate ACK received
    u32_t   tcp_fl;                     // 0x28    TCP flow label for IPV6
    u32_t   tcp_ssthresh;               // 0x2c    TCP slow start threshold
    u32_t   tcp_rcv_next;               // 0x30    TCP receive next sequence number
    u32_t   tcp_rcv_win_seq;            //         unused in iSCSI
    u32_t   tcp_snd_una;                //
    u32_t   tcp_snd_next;               //
    u32_t   tcp_sm_rtt;                 // 0x40
    u32_t   tcp_sm_delta;               //
    u32_t   tcp_max_snd_win;            //
    u8_t    tcp_ulp_ooo_flags;
    u8_t   	tcp_rcv_seg_scale;        	//          TCP segment scale that is advertised by Xinan
    u8_t    tcp_upload_reason;          //
    u8_t    tcp_txp_cmd;                // 0x4c    index of the ccell that the TXP is currently transmitting
	u32_t  	last_ack_sent;        	// TCP ack sequence of the previous packet transmitted
    u32_t   tcp_offload_seq;            // initial TCP seq number of the Xinan side (i.e. bseq + offload_seq = tcp_seq)
    u32_t   tcp_tstamp;                 //
    u8_t    ka_max_probe_cnt;
    u8_t    ka_probe_cnt;
    u16_t   tcp_mss;                    // mss of the connection
    u16_t   ka_timeout_tick;
    u8_t    krnlq_id;                   // indicate which krnlq that kcqe should be written to.
    u8_t    force_ack_pending;
    u8_t    challenge_ack_state;        // refer to tcpm-tcpsecure-09 requirement
    u8_t    unused2;
    u16_t   ka_interval_tick;
} tcp_cmn_ctx_l_t;

#if defined(LITTLE_ENDIAN)
    typedef tcp_cmn_ctx_l_t  tcp_cmn_ctx_t;
#elif defined(BIG_ENDIAN)
    typedef tcp_cmn_ctx_b_t  tcp_cmn_ctx_t;
#endif
/////////////////////////////////////////////////////////////////////
// TCP RX section
/////////////////////////////////////////////////////////////////////
typedef struct {
    u8_t    state;                      // iooo state
    u8_t    spill_mode:1;
    u8_t    mode:7;
} iooo_tcp_b_t;

typedef struct {
    u8_t    mode:7;
    u8_t    spill_mode:1;
    u8_t    state;                      // iooo state
} iooo_tcp_l_t;

typedef struct {
    u32_t   tcp_snd_wl1;            //
    u32_t   tcp_snd_wl2;            //
    u8_t   	tcp_snd_seg_scale;    	// TCP segment scale that is advertised by the remote peer
#if (ISCSI_OOO_SUPPORT)
    iooo_tcp_b_t iooo_tcp;              // iSCSI OOO tcp manager structure
    u8_t    reserved0;
#else
    u8_t    reserved0[3];
#endif
} tcp_rx_ctx_b_t;

typedef struct {
    u32_t  tcp_snd_wl1;             //
    u32_t  tcp_snd_wl2;             //
#if (ISCSI_OOO_SUPPORT)
    iooo_tcp_l_t iooo_tcp;              // iSCSI OOO tcp manager structure
    u8_t    reserved0;
#else
    u8_t    reserved0[3];
#endif
    u8_t   	tcp_snd_seg_scale;      // TCP segment scale that is advertised by the remote peer
} tcp_rx_ctx_l_t;

#if defined(LITTLE_ENDIAN)
    typedef tcp_rx_ctx_l_t  tcp_rx_ctx_t;
#elif defined(BIG_ENDIAN)
    typedef tcp_rx_ctx_b_t  tcp_rx_ctx_t;
#endif

#endif /* _TCP_CTX_H */

