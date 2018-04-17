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

#ifndef __ECORE_LL2_API_H__
#define __ECORE_LL2_API_H__

/* ECORE LL2 API: called by ECORE's upper level client  */
/* must be the asme as core_rx_conn_type */
#ifndef __EXTRACT__LINUX__

enum ecore_ll2_conn_type {
	ECORE_LL2_TYPE_FCOE /* FCoE L2 connection */,
	ECORE_LL2_TYPE_ISCSI /* Iscsi L2 connection */,
	ECORE_LL2_TYPE_TEST /* Eth TB test connection */,
	ECORE_LL2_TYPE_OOO /* Iscsi OOO L2 connection */,
	ECORE_LL2_TYPE_TOE /* toe L2 connection */,
	ECORE_LL2_TYPE_ROCE /* RoCE L2 connection */,
	ECORE_LL2_TYPE_IWARP,
	MAX_ECORE_LL2_RX_CONN_TYPE
};

enum ecore_ll2_roce_flavor_type {
	ECORE_LL2_ROCE,		/* use this as default or d/c */
	ECORE_LL2_RROCE,
	MAX_ECORE_LL2_ROCE_FLAVOR_TYPE
};

enum ecore_ll2_tx_dest
{
	ECORE_LL2_TX_DEST_NW /* Light L2 TX Destination to the Network */,
	ECORE_LL2_TX_DEST_LB /* Light L2 TX Destination to the Loopback */,
	ECORE_LL2_TX_DEST_DROP /* Light L2 Drop the TX packet */,
	ECORE_LL2_TX_DEST_MAX
};

enum ecore_ll2_error_handle
{
	ECORE_LL2_DROP_PACKET /* If error occurs drop packet */,
	ECORE_LL2_DO_NOTHING /* If error occurs do nothing */,
	ECORE_LL2_ASSERT /* If error occurs assert */,
};

struct ecore_ll2_stats {
	u64 gsi_invalid_hdr;
	u64 gsi_invalid_pkt_length;
	u64 gsi_unsupported_pkt_typ;
	u64 gsi_crcchksm_error;

	u64 packet_too_big_discard;
	u64 no_buff_discard;

	u64 rcv_ucast_bytes;
	u64 rcv_mcast_bytes;
	u64 rcv_bcast_bytes;
	u64 rcv_ucast_pkts;
	u64 rcv_mcast_pkts;
	u64 rcv_bcast_pkts;

	u64 sent_ucast_bytes;
	u64 sent_mcast_bytes;
	u64 sent_bcast_bytes;
	u64 sent_ucast_pkts;
	u64 sent_mcast_pkts;
	u64 sent_bcast_pkts;
};

struct ecore_ll2_comp_rx_data {
	u8 connection_handle;
	void *cookie;
	dma_addr_t rx_buf_addr;
	u16 parse_flags;
	u16 err_flags;
	u16 vlan;
	bool b_last_packet;

	union {
		u8 placement_offset;
		u8 data_length_error;
	} u;
	union {
		u16 packet_length;
		u16 data_length;
	} length;

	u32 opaque_data_0; /* src_mac_addr_hi */
	u32 opaque_data_1; /* src_mac_addr_lo */

	/* GSI only */
	u32 gid_dst[4];
	u16 qp_id;
};

typedef
void (*ecore_ll2_complete_rx_packet_cb)(void *cxt,
					struct ecore_ll2_comp_rx_data *data);

typedef
void (*ecore_ll2_release_rx_packet_cb)(void *cxt,
				       u8 connection_handle,
				       void *cookie,
				       dma_addr_t rx_buf_addr,
				       bool b_last_packet);

typedef
void (*ecore_ll2_complete_tx_packet_cb)(void *cxt,
					u8 connection_handle,
					void *cookie,
					dma_addr_t first_frag_addr,
					bool b_last_fragment,
					bool b_last_packet);

typedef
void (*ecore_ll2_release_tx_packet_cb)(void *cxt,
				       u8 connection_handle,
				       void *cookie,
				       dma_addr_t first_frag_addr,
				       bool b_last_fragment,
				       bool b_last_packet);

typedef
void (*ecore_ll2_slowpath_cb)(void *cxt,
			      u8 connection_handle,
			      u32 opaque_data_0,
			      u32 opaque_data_1);

struct ecore_ll2_cbs {
	ecore_ll2_complete_rx_packet_cb rx_comp_cb;
	ecore_ll2_release_rx_packet_cb rx_release_cb;
	ecore_ll2_complete_tx_packet_cb tx_comp_cb;
	ecore_ll2_release_tx_packet_cb tx_release_cb;
	ecore_ll2_slowpath_cb slowpath_cb;
	void *cookie;
};

struct ecore_ll2_acquire_data {
	enum ecore_ll2_conn_type conn_type;
	u16 mtu; /* Maximum bytes that can be placed on a BD*/
	u16 rx_num_desc;

	/* Relevant only for OOO connection if 0 OOO rx buffers=2*rx_num_desc */
	u16 rx_num_ooo_buffers;
	u8 rx_drop_ttl0_flg;

	/* if set, 802.1q tags will be removed and copied to CQE */
	u8 rx_vlan_removal_en;
	u16 tx_num_desc;
	u8 tx_max_bds_per_packet;
	u8 tx_tc;
	enum ecore_ll2_tx_dest tx_dest;
	enum ecore_ll2_error_handle ai_err_packet_too_big;
	enum ecore_ll2_error_handle ai_err_no_buf;
	u8 secondary_queue;
	u8 gsi_enable;

	/* Output container for LL2 connection's handle */
	u8 *p_connection_handle;
	const struct ecore_ll2_cbs *cbs;
};
#endif

/**
 * @brief ecore_ll2_acquire_connection - allocate resources,
 *        starts rx & tx (if relevant) queues pair. Provides
 *        connecion handler as output parameter.
 *
 *
 * @param p_hwfn
 * @param data - describes connection parameters
 * @return enum _ecore_status_t
 */
enum _ecore_status_t
ecore_ll2_acquire_connection(void *cxt,
			     struct ecore_ll2_acquire_data *data);

/**
 * @brief ecore_ll2_establish_connection - start previously
 *        allocated LL2 queues pair
 *
 * @param p_hwfn
 * @param p_ptt
 * @param connection_handle    LL2 connection's handle
 *                              obtained from
 *                              ecore_ll2_require_connection
 *
 * @return enum _ecore_status_t
 */
enum _ecore_status_t ecore_ll2_establish_connection(void *cxt,
						    u8 connection_handle);

/**
 * @brief ecore_ll2_post_rx_buffers - submit buffers to LL2 RxQ.
 *
 * @param p_hwfn
 * @param connection_handle    LL2 connection's handle
 *                              obtained from
 *                              ecore_ll2_require_connection
 * @param addr                  rx (physical address) buffers to
 *                              submit
 * @param cookie
 * @param notify_fw             produce corresponding Rx BD
 *                              immediately
 *
 * @return enum _ecore_status_t
 */
enum _ecore_status_t ecore_ll2_post_rx_buffer(void *cxt,
					      u8 connection_handle,
					      dma_addr_t addr,
					      u16 buf_len,
					      void *cookie,
					      u8 notify_fw);

#ifndef __EXTRACT__LINUX__
struct ecore_ll2_tx_pkt_info {
	u8 num_of_bds;
	u16 vlan;
	u8 bd_flags;
	u16 l4_hdr_offset_w; /* from start of packet */
	enum ecore_ll2_tx_dest tx_dest;
	enum ecore_ll2_roce_flavor_type ecore_roce_flavor;
	dma_addr_t first_frag;
	u16 first_frag_len;
	bool enable_ip_cksum;
	bool enable_l4_cksum;
	bool calc_ip_len;
	void *cookie;
};
#endif

/**
 * @brief ecore_ll2_prepare_tx_packet - request for start Tx BD
 *        to prepare Tx packet submission to FW.
 *
 *
 * @param p_hwfn
 * @param pkt - info regarding the tx packet
 * @param notify_fw - issue doorbell to fw for this packet
 *
 * @return enum _ecore_status_t
 */
enum _ecore_status_t ecore_ll2_prepare_tx_packet(
		void *cxt,
		u8 connection_handle,
		struct ecore_ll2_tx_pkt_info *pkt,
		bool notify_fw);

/**
 * @brief ecore_ll2_release_connection - releases resources
 *        allocated for LL2 connection
 *
 * @param p_hwfn
 * @param connection_handle    LL2 connection's handle
 *                              obtained from
 *                              ecore_ll2_require_connection
 */
void ecore_ll2_release_connection(void *cxt,
				  u8 connection_handle);

/**
 * @brief ecore_ll2_set_fragment_of_tx_packet - provides
 *        fragments to fill Tx BD of BDs requested by
 *        ecore_ll2_prepare_tx_packet..
 *
 *
 * @param p_hwfn
 * @param connection_handle    LL2 connection's handle
 *                              obtained from
 *                              ecore_ll2_require_connection
 * @param addr
 * @param nbytes
 *
 * @return enum _ecore_status_t
 */
enum _ecore_status_t
ecore_ll2_set_fragment_of_tx_packet(void *cxt,
				    u8 connection_handle,
				    dma_addr_t addr,
				    u16 nbytes);

/**
 * @brief ecore_ll2_terminate_connection - stops Tx/Rx queues
 *
 *
 * @param p_hwfn
 * @param connection_handle    LL2 connection's handle
 *                              obtained from
 *                              ecore_ll2_require_connection
 *
 * @return enum _ecore_status_t
 */
enum _ecore_status_t ecore_ll2_terminate_connection(void *cxt,
						    u8 connection_handle);

/**
 * @brief ecore_ll2_get_stats - get LL2 queue's statistics
 *
 *
 * @param p_hwfn
 * @param connection_handle    LL2 connection's handle
 *                              obtained from
 *                              ecore_ll2_require_connection
 * @param p_stats
 *
 * @return enum _ecore_status_t
 */
enum _ecore_status_t ecore_ll2_get_stats(void *cxt,
					 u8 connection_handle,
					 struct ecore_ll2_stats	*p_stats);

#endif
