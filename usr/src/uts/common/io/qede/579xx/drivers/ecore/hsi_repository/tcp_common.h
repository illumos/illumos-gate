/*
* CDDL HEADER START
*
* The contents of this file are subject to the terms of the
* Common Development and Distribution License, v.1,  (the "License").
* You may not use this file except in compliance with the License.
*
* You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
* or http://opensource.org/licenses/CDDL-1.0.
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
*/

/*
* Copyright 2014-2017 Cavium, Inc. 
* The contents of this file are subject to the terms of the Common Development 
* and Distribution License, v.1,  (the "License").

* You may not use this file except in compliance with the License.

* You can obtain a copy of the License at available 
* at http://opensource.org/licenses/CDDL-1.0

* See the License for the specific language governing permissions and 
* limitations under the License.
*/

#ifndef __TCP_COMMON__
#define __TCP_COMMON__ 
/********************/
/* TCP FW CONSTANTS */
/********************/

#define TCP_INVALID_TIMEOUT_VAL -1


/*
 * OOO opaque data received from LL2
 */
struct ooo_opaque
{
	__le32 cid /* connection ID  */;
	u8 drop_isle /* isle number of the first isle to drop */;
	u8 drop_size /* number of isles to drop */;
	u8 ooo_opcode /* (use enum tcp_seg_placement_event) */;
	u8 ooo_isle /* OOO isle number to add the packet to */;
};


/*
 * tcp connect mode enum
 */
enum tcp_connect_mode
{
	TCP_CONNECT_ACTIVE,
	TCP_CONNECT_PASSIVE,
	MAX_TCP_CONNECT_MODE
};


/*
 * tcp function init parameters
 */
struct tcp_init_params
{
	__le32 two_msl_timer /* 2MSL (used for TIME_WAIT state) timeout value */;
	__le16 tx_sws_timer /* Transmission silly window syndrom timeout value */;
	u8 max_fin_rt /* Minimum Fin RT */;
	u8 reserved[9];
};


/*
 * tcp IPv4/IPv6 enum
 */
enum tcp_ip_version
{
	TCP_IPV4,
	TCP_IPV6,
	MAX_TCP_IP_VERSION
};


/*
 * tcp offload parameters
 */
struct tcp_offload_params
{
	__le16 local_mac_addr_lo;
	__le16 local_mac_addr_mid;
	__le16 local_mac_addr_hi;
	__le16 remote_mac_addr_lo;
	__le16 remote_mac_addr_mid;
	__le16 remote_mac_addr_hi;
	__le16 vlan_id;
	u8 flags;
#define TCP_OFFLOAD_PARAMS_TS_EN_MASK         0x1 /* timestamp enable */
#define TCP_OFFLOAD_PARAMS_TS_EN_SHIFT        0
#define TCP_OFFLOAD_PARAMS_DA_EN_MASK         0x1 /* delayed ack enabled */
#define TCP_OFFLOAD_PARAMS_DA_EN_SHIFT        1
#define TCP_OFFLOAD_PARAMS_KA_EN_MASK         0x1 /* keep alive enabled */
#define TCP_OFFLOAD_PARAMS_KA_EN_SHIFT        2
#define TCP_OFFLOAD_PARAMS_NAGLE_EN_MASK      0x1 /* nagle algorithm enabled */
#define TCP_OFFLOAD_PARAMS_NAGLE_EN_SHIFT     3
#define TCP_OFFLOAD_PARAMS_DA_CNT_EN_MASK     0x1 /* delayed ack counter enabled */
#define TCP_OFFLOAD_PARAMS_DA_CNT_EN_SHIFT    4
#define TCP_OFFLOAD_PARAMS_FIN_SENT_MASK      0x1 /* fin already sent to far end */
#define TCP_OFFLOAD_PARAMS_FIN_SENT_SHIFT     5
#define TCP_OFFLOAD_PARAMS_FIN_RECEIVED_MASK  0x1 /* fin received */
#define TCP_OFFLOAD_PARAMS_FIN_RECEIVED_SHIFT 6
#define TCP_OFFLOAD_PARAMS_RESERVED0_MASK     0x1
#define TCP_OFFLOAD_PARAMS_RESERVED0_SHIFT    7
	u8 ip_version;
	__le32 remote_ip[4];
	__le32 local_ip[4];
	__le32 flow_label;
	u8 ttl;
	u8 tos_or_tc;
	__le16 remote_port;
	__le16 local_port;
	__le16 mss /* the mss derived from remote mss and local mtu, ipVersion options and tags */;
	u8 rcv_wnd_scale;
	u8 connect_mode /* TCP connect mode: use enum tcp_connect_mode */;
	__le16 srtt /* in ms */;
	__le32 cwnd /* absolute congestion window */;
	__le32 ss_thresh;
	__le16 reserved1;
	u8 ka_max_probe_cnt;
	u8 dup_ack_theshold;
	__le32 rcv_next;
	__le32 snd_una;
	__le32 snd_next;
	__le32 snd_max;
	__le32 snd_wnd /* absolute send window (not scaled) */;
	__le32 rcv_wnd /* absolute receive window (not scaled) */;
	__le32 snd_wl1 /* the segment sequence number used for the last window update */;
	__le32 ts_recent /* The timestamp value to send in the next ACK */;
	__le32 ts_recent_age /* The length of time, in ms, since the most recent timestamp was received */;
	__le32 total_rt /* The total time, in ms, that has been spent retransmitting the current TCP segment */;
	__le32 ka_timeout_delta /* The time remaining, in clock ticks, until the next keepalive timeout. A value of -1 indicates that the keepalive timer was not running when the connection was offloaded. */;
	__le32 rt_timeout_delta /* The time remaining, in clock ticks, until the next retransmit timeout. A value of -1 indicates that the  retransmit timer was not running when the connection was offloaded. */;
	u8 dup_ack_cnt /* The number of ACKs that have been accepted for the same sequence number */;
	u8 snd_wnd_probe_cnt /* The current send window probe round */;
	u8 ka_probe_cnt /* the number of keepalive probes that have been sent that have not received a response */;
	u8 rt_cnt /* The number of retransmits that have been sent */;
	__le16 rtt_var /* in ms */;
	__le16 fw_internal /* fw internal use - initialize value = 0 */;
	__le32 ka_timeout /* This member specifies, in ms, the timeout interval for inactivity before sending a keepalive probe */;
	__le32 ka_interval /* This member specifies, in ms, the timeout after which to retransmit a keepalive frame if no response is received to a keepalive probe  */;
	__le32 max_rt_time /* This member specifies, in ms, the maximum time that the offload target should spend retransmitting a segment */;
	__le32 initial_rcv_wnd /* Initial receive window */;
	u8 snd_wnd_scale;
	u8 ack_frequency /* delayed ack counter threshold */;
	__le16 da_timeout_value /* delayed ack timeout value in ms */;
	__le32 reserved3[2];
};


/*
 * tcp offload parameters
 */
struct tcp_offload_params_opt2
{
	__le16 local_mac_addr_lo;
	__le16 local_mac_addr_mid;
	__le16 local_mac_addr_hi;
	__le16 remote_mac_addr_lo;
	__le16 remote_mac_addr_mid;
	__le16 remote_mac_addr_hi;
	__le16 vlan_id;
	u8 flags;
#define TCP_OFFLOAD_PARAMS_OPT2_TS_EN_MASK      0x1 /* timestamp enable */
#define TCP_OFFLOAD_PARAMS_OPT2_TS_EN_SHIFT     0
#define TCP_OFFLOAD_PARAMS_OPT2_DA_EN_MASK      0x1 /* delayed ack enabled */
#define TCP_OFFLOAD_PARAMS_OPT2_DA_EN_SHIFT     1
#define TCP_OFFLOAD_PARAMS_OPT2_KA_EN_MASK      0x1 /* keep alive enabled */
#define TCP_OFFLOAD_PARAMS_OPT2_KA_EN_SHIFT     2
#define TCP_OFFLOAD_PARAMS_OPT2_RESERVED0_MASK  0x1F
#define TCP_OFFLOAD_PARAMS_OPT2_RESERVED0_SHIFT 3
	u8 ip_version;
	__le32 remote_ip[4];
	__le32 local_ip[4];
	__le32 flow_label;
	u8 ttl;
	u8 tos_or_tc;
	__le16 remote_port;
	__le16 local_port;
	__le16 mss /* the mss derived from remote mss and local mtu, ipVersion options and tags */;
	u8 rcv_wnd_scale;
	u8 connect_mode /* TCP connect mode: use enum tcp_connect_mode */;
	__le16 syn_ip_payload_length /* length of Tcp header in SYN packet - relevent for passive mode */;
	__le32 syn_phy_addr_lo /* physical address (low) of SYN buffer - relevent for passive mode */;
	__le32 syn_phy_addr_hi /* physical address (high) of SYN buffer - relevent for passive mode */;
	__le32 reserved1[22];
};


/*
 * tcp IPv4/IPv6 enum
 */
enum tcp_seg_placement_event
{
	TCP_EVENT_ADD_PEN,
	TCP_EVENT_ADD_NEW_ISLE,
	TCP_EVENT_ADD_ISLE_RIGHT,
	TCP_EVENT_ADD_ISLE_LEFT,
	TCP_EVENT_JOIN,
	TCP_EVENT_DELETE_ISLES,
	TCP_EVENT_NOP,
	MAX_TCP_SEG_PLACEMENT_EVENT
};


/*
 * tcp init parameters
 */
struct tcp_update_params
{
	__le16 flags;
#define TCP_UPDATE_PARAMS_REMOTE_MAC_ADDR_CHANGED_MASK   0x1
#define TCP_UPDATE_PARAMS_REMOTE_MAC_ADDR_CHANGED_SHIFT  0
#define TCP_UPDATE_PARAMS_MSS_CHANGED_MASK               0x1
#define TCP_UPDATE_PARAMS_MSS_CHANGED_SHIFT              1
#define TCP_UPDATE_PARAMS_TTL_CHANGED_MASK               0x1
#define TCP_UPDATE_PARAMS_TTL_CHANGED_SHIFT              2
#define TCP_UPDATE_PARAMS_TOS_OR_TC_CHANGED_MASK         0x1
#define TCP_UPDATE_PARAMS_TOS_OR_TC_CHANGED_SHIFT        3
#define TCP_UPDATE_PARAMS_KA_TIMEOUT_CHANGED_MASK        0x1
#define TCP_UPDATE_PARAMS_KA_TIMEOUT_CHANGED_SHIFT       4
#define TCP_UPDATE_PARAMS_KA_INTERVAL_CHANGED_MASK       0x1
#define TCP_UPDATE_PARAMS_KA_INTERVAL_CHANGED_SHIFT      5
#define TCP_UPDATE_PARAMS_MAX_RT_TIME_CHANGED_MASK       0x1
#define TCP_UPDATE_PARAMS_MAX_RT_TIME_CHANGED_SHIFT      6
#define TCP_UPDATE_PARAMS_FLOW_LABEL_CHANGED_MASK        0x1
#define TCP_UPDATE_PARAMS_FLOW_LABEL_CHANGED_SHIFT       7
#define TCP_UPDATE_PARAMS_INITIAL_RCV_WND_CHANGED_MASK   0x1
#define TCP_UPDATE_PARAMS_INITIAL_RCV_WND_CHANGED_SHIFT  8
#define TCP_UPDATE_PARAMS_KA_MAX_PROBE_CNT_CHANGED_MASK  0x1
#define TCP_UPDATE_PARAMS_KA_MAX_PROBE_CNT_CHANGED_SHIFT 9
#define TCP_UPDATE_PARAMS_KA_EN_CHANGED_MASK             0x1
#define TCP_UPDATE_PARAMS_KA_EN_CHANGED_SHIFT            10
#define TCP_UPDATE_PARAMS_NAGLE_EN_CHANGED_MASK          0x1
#define TCP_UPDATE_PARAMS_NAGLE_EN_CHANGED_SHIFT         11
#define TCP_UPDATE_PARAMS_KA_EN_MASK                     0x1
#define TCP_UPDATE_PARAMS_KA_EN_SHIFT                    12
#define TCP_UPDATE_PARAMS_NAGLE_EN_MASK                  0x1
#define TCP_UPDATE_PARAMS_NAGLE_EN_SHIFT                 13
#define TCP_UPDATE_PARAMS_KA_RESTART_MASK                0x1
#define TCP_UPDATE_PARAMS_KA_RESTART_SHIFT               14
#define TCP_UPDATE_PARAMS_RETRANSMIT_RESTART_MASK        0x1
#define TCP_UPDATE_PARAMS_RETRANSMIT_RESTART_SHIFT       15
	__le16 remote_mac_addr_lo;
	__le16 remote_mac_addr_mid;
	__le16 remote_mac_addr_hi;
	__le16 mss;
	u8 ttl;
	u8 tos_or_tc;
	__le32 ka_timeout;
	__le32 ka_interval;
	__le32 max_rt_time;
	__le32 flow_label;
	__le32 initial_rcv_wnd;
	u8 ka_max_probe_cnt;
	u8 reserved1[7];
};


/*
 * toe upload parameters
 */
struct tcp_upload_params
{
	__le32 rcv_next;
	__le32 snd_una;
	__le32 snd_next;
	__le32 snd_max;
	__le32 snd_wnd /* absolute send window (not scaled) */;
	__le32 rcv_wnd /* absolute receive window (not scaled) */;
	__le32 snd_wl1 /* the segment sequence number used for the last window update */;
	__le32 cwnd /* absolute congestion window */;
	__le32 ss_thresh;
	__le16 srtt /* in ms */;
	__le16 rtt_var /* in ms */;
	__le32 ts_time /* The current value of the adjusted timestamp */;
	__le32 ts_recent /* The timestamp value to send in the next ACK */;
	__le32 ts_recent_age /* The length of time, in ms, since the most recent timestamp was received */;
	__le32 total_rt /* The total time, in ms, that has been spent retransmitting the current TCP segment */;
	__le32 ka_timeout_delta /* The time remaining, in clock ticks, until the next keepalive timeout. A value of -1 indicates that the keepalive timer was not running when the connection was offloaded. */;
	__le32 rt_timeout_delta /* The time remaining, in clock ticks, until the next retransmit timeout. A value of -1 indicates that the  retransmit timer was not running when the connection was offloaded. */;
	u8 dup_ack_cnt /* The number of ACKs that have been accepted for the same sequence number */;
	u8 snd_wnd_probe_cnt /* The current send window probe round */;
	u8 ka_probe_cnt /* the number of keepalive probes that have been sent that have not received a response */;
	u8 rt_cnt /* The number of retransmits that have been sent */;
	__le32 reserved;
};

#endif /* __TCP_COMMON__ */
