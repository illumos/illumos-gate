/*******************************************************************************
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 *
 * Copyright 2014 QLogic Corporation
 * The contents of this file are subject to the terms of the
 * QLogic End User License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at
 * http://www.qlogic.com/Resources/Documents/DriverDownloadHelp/
 * QLogic_End_User_Software_License.txt
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 ******************************************************************************/

#ifndef _L4STATES_H
#define _L4STATES_H

#include "bcmtype.h"



/*******************************************************************************
 * Disconnect type.
 ******************************************************************************/

typedef enum _l4_disconnect_type_t
{
    L4_DISCONNECT_TYPE_GRACEFUL         = 1,
    L4_DISCONNECT_TYPE_ABORTIVE         = 2,
} l4_disconnect_type_t;



/*******************************************************************************
 * Upload reason. 
 ******************************************************************************/

typedef enum _l4_upload_reason_t
{
    L4_UPLOAD_REASON_UNKNOWN            = 0,
    L4_UPLOAD_REASON_URG                = 1,
    L4_UPLOAD_REASON_FRAGMENT           = 2,
    L4_UPLOAD_REASON_IP_OPTION          = 3,
    L4_UPLOAD_REASON_KEEP_ALIVE_TIMEOUT = 4,
    L4_UPLOAD_REASON_UPLOAD_REQUESTED   = 5,
    L4_UPLOAD_REASON_LOW_ACTIVITY       = 6,
    L4_UPLOAD_REASON_HIGH_DROP_RATE     = 7,
    L4_UPLOAD_REASON_SMALL_IO           = 8,
    L4_UPLOAD_REASON_NO_BUFFER_PRE_POSTING     = 9,
    L4_UPLOAD_REASON_HIGH_OUT_OF_ORDER_PACKETS = 10,
    L4_UPLOAD_REASON_RETRANSMIT_TIMEOUT = 11,
    L4_UPLOAD_REASON_MAX
} l4_upload_reason_t;



/*******************************************************************************
* TCP connection state.
 ******************************************************************************/

typedef enum _l4_tcp_con_state_t
{
    L4_TCP_CON_STATE_UNDEFINED          = 0,
    L4_TCP_CON_STATE_CLOSED             = 1,
    L4_TCP_CON_STATE_SYN_SENT           = 2,
    L4_TCP_CON_STATE_SYN_RCVD           = 3,
    L4_TCP_CON_STATE_ESTABLISHED        = 4,
    L4_TCP_CON_STATE_FIN_WAIT1          = 5,
    L4_TCP_CON_STATE_FIN_WAIT2          = 6,
    L4_TCP_CON_STATE_CLOSING            = 7,
    L4_TCP_CON_STATE_CLOSE_WAIT         = 8,
    L4_TCP_CON_STATE_LAST_ACK           = 9,
    L4_TCP_CON_STATE_TIME_WAIT          = 10,
    L4_TCP_CON_STATE_LISTEN             = 11,
    L4_TCP_CON_STATE_MAX
} l4_tcp_con_state_t;



/*******************************************************************************
 * Neighbor information.
 ******************************************************************************/

typedef struct _l4_neigh_const_state_t
{
    u8_t src_addr[8];
    u16_t vlan_tag;     /* 4 MSBs are always 0 */
} l4_neigh_const_state_t;


typedef struct _l4_neigh_cached_state_t
{
    u8_t dst_addr[8];

    u32_t host_reachability_delta;
} l4_neigh_cached_state_t;


typedef struct _l4_neigh_delegated_state_t
{
    u32_t nic_reachability_delta;
} l4_neigh_delegated_state_t;



/*******************************************************************************
 * Path information.
 ******************************************************************************/

typedef struct _l4_path_const_state_t
{
    u8_t ip_version;
    #define IP_VERSION_IPV4     4
    #define IP_VERSION_IPV6     6

    u8_t _pad[3];

    union _u_ip_type_t
    {
        struct _ip_v4_t
        {
            u32_t dst_ip;
            u32_t src_ip;
        } ipv4;

        struct _ip_v6_t
        {
            u32_t dst_ip[4];
            u32_t src_ip[4];
        } ipv6;
    } u;
} l4_path_const_state_t;


typedef struct _l4_path_cached_state_t
{
    u32_t path_mtu;
} l4_path_cached_state_t;


typedef struct _l4_path_delegated_state_t
{
    u16_t ipv4_current_ip_id;
    u16_t _pad;
} l4_path_delegated_state_t;



/*******************************************************************************
 * TCP destination and source ports.
 ******************************************************************************/

typedef struct _l4_tcp_const_state_t
{
    u16_t tcp_flags;
    #define TCP_FLAG_ENABLE_TIME_STAMP      0x0001
    #define TCP_FLAG_ENABLE_SACK            0x0002
    #define TCP_FLAG_ENABLE_WIN_SCALING     0x0004

    u16_t dst_port; /* in host order */
    u16_t src_port; /* in host order */

    u16_t remote_mss;

    u8_t snd_seg_scale:4;   /* 0 if win scaling is disabled */
    u8_t rcv_seg_scale:4;   /* 0 if win scaling is disabled */
    u8_t _pad[3];

    u32_t hash_value;
} l4_tcp_const_state_t;


typedef struct _l4_tcp_cached_state_t
{
    u16_t tcp_flags;
    #define TCP_FLAG_ENABLE_KEEP_ALIVE      0x01
    #define TCP_FLAG_ENABLE_NAGLING         0x02
    #define TCP_FLAG_RESTART_KEEP_ALIVE     0x04
    #define TCP_FLAG_RESTART_MAX_RT         0x08
    #define TCP_FLAG_UPDATE_RCV_WINDOW      0x10

    u16_t _pad;

    u32_t initial_rcv_wnd;
    u8_t ttl_or_hop_limit;
    u8_t tos_or_traffic_class;
    u8_t ka_probe_cnt; 
    u8_t user_priority; /* 5 MSBs are always 0 */ 
    u32_t rcv_indication_size; 
    u32_t ka_time_out; 
    u32_t ka_interval; 
    u32_t max_rt;  

    /* ipv6 fields. */
    u32_t flow_label;
} l4_tcp_cached_state_t;


typedef struct _l4_tcp_delegated_state_t
{
    u32_t con_state;  /* l4_tcp_con_state_t */

    u32_t recv_next;
    u32_t recv_win_seq; /* ndis_tcp_delegated->RcvWnd + ndis_tcp_delegated->RcvNxt    */
    u32_t send_una;
    u32_t send_next;
    u32_t send_max;
    u32_t send_win;     /* ndis_tcp_delegated->SndWnd    + ndis_tcp_delegated->SndUna */
    u32_t max_send_win; /* ndis_tcp_delegated->MaxSndWnd */
    u32_t send_wl1;
    u32_t send_cwin;    /* ndis_tcp_delegated->CWnd      + ndis_tcp_delegated->SndUna */
    u32_t ss_thresh;
    u16_t sm_rtt;       /* ndis_tcp_delegated->SRtt */
    u16_t sm_delta;     /* ndis_tcp_delegated->RttVar */
    u32_t tstamp;       /* ndis_tcp_delegated->TsTime */
    u32_t ts_recent;   
    u32_t ts_recent_age; 
    u32_t total_rt;  
    u8_t dup_ack_count; 
    u8_t snd_wnd_probe_count; 
    u16_t _pad;

    /* TODO: remove the union in the next if version change. */
    union _keep_alive_or_retransmit_t
    {
        struct _keep_alive_t
        {
            u8_t probe_cnt;
            u32_t timeout_delta;
        } keep_alive;

        struct _retransmit_t
        {
            u8_t num_retx;
            u32_t retx_ms;
        } retransmit;
    } u;
} l4_tcp_delegated_state_t;



/*******************************************************************************
 * Set offload parameters. 
 ******************************************************************************/

typedef struct _l4_ofld_params_t
{
    u32_t flags;
    #define OFLD_PARAM_FLAG_SNAP_ENCAP          0x0001

    u32_t ticks_per_second;
    u8_t ack_frequency;
    u8_t delayed_ack_ticks;
    u8_t max_retx;
    u8_t doubt_reachability_retx;
    u32_t sws_prevention_ticks;
    u32_t dup_ack_threshold;
    u32_t push_ticks;
    u32_t nce_stale_ticks;
    u16_t starting_ip_id;
    u16_t _pad;
} l4_ofld_params_t;



#endif /* _L4STATES_H */

