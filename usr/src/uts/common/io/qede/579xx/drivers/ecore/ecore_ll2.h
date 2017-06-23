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

#ifndef __ECORE_LL2_H__
#define __ECORE_LL2_H__

#include "ecore.h"
#include "ecore_hsi_eth.h"
#include "ecore_chain.h"
#include "ecore_hsi_common.h"
#include "ecore_ll2_api.h"
#include "ecore_sp_api.h"

/* ECORE LL2: internal structures and functions*/
#define ECORE_MAX_NUM_OF_LL2_CONNECTIONS                    (4)

static OSAL_INLINE u8 ecore_ll2_handle_to_queue_id(struct ecore_hwfn *p_hwfn,
					      u8 handle)
{
	return p_hwfn->hw_info.resc_start[ECORE_LL2_QUEUE] + handle;
}

struct ecore_ll2_rx_packet
{
	osal_list_entry_t   list_entry;
	struct core_rx_bd_with_buff_len   *rxq_bd;
	dma_addr_t          rx_buf_addr;
	u16                 buf_length;
	void                *cookie;
	u8                  placement_offset;
	u16                 parse_flags;
	u16                 packet_length;
	u16                 vlan;
	u32                 opaque_data[2];
};

struct ecore_ll2_tx_packet
{
	osal_list_entry_t       list_entry;
	u16                     bd_used;
	bool                    notify_fw;
	void                    *cookie;
	struct {
		struct core_tx_bd       *txq_bd;
		dma_addr_t              tx_frag;
		u16                     frag_len;
	}   bds_set[1];
	/* Flexible Array of bds_set determined by max_bds_per_packet */
};

struct ecore_ll2_rx_queue {
	osal_spinlock_t		lock;
	struct ecore_chain	rxq_chain;
	struct ecore_chain	rcq_chain;
	u8			rx_sb_index;
	bool			b_cb_registred;
	__le16			*p_fw_cons;
	osal_list_t		active_descq;
	osal_list_t		free_descq;
	osal_list_t		posting_descq;
	struct ecore_ll2_rx_packet	*descq_array;
	void OSAL_IOMEM		*set_prod_addr;
};

struct ecore_ll2_tx_queue {
	osal_spinlock_t			lock;
	struct ecore_chain		txq_chain;
	u8				tx_sb_index;
	bool				b_cb_registred;
	__le16				*p_fw_cons;
	osal_list_t			active_descq;
	osal_list_t			free_descq;
	osal_list_t			sending_descq;
	struct ecore_ll2_tx_packet	*descq_array;
	struct ecore_ll2_tx_packet	*cur_send_packet;
	struct ecore_ll2_tx_packet	cur_completing_packet;
	u16				cur_completing_bd_idx;
	void OSAL_IOMEM			*doorbell_addr;
	u16				bds_idx;
	u16				cur_send_frag_num;
	u16				cur_completing_frag_num;
	bool				b_completing_packet;
};

struct ecore_ll2_info {
	osal_mutex_t			mutex;
	enum ecore_ll2_conn_type	conn_type;
	u32				cid;
	u8				my_id;
	u8				queue_id;
	u8				tx_stats_id;
	bool				b_active;
	u16				mtu;
	u8				rx_drop_ttl0_flg;
	u8				rx_vlan_removal_en;
	u8				tx_tc;
	u8				tx_max_bds_per_packet;
	enum core_tx_dest		tx_dest;
	enum core_error_handle		ai_err_packet_too_big;
	enum core_error_handle		ai_err_no_buf;
	u8				gsi_enable;
	u8				tx_stats_en;
	u8				main_func_queue;
	struct ecore_ll2_rx_queue	rx_queue;
	struct ecore_ll2_tx_queue	tx_queue;
	struct ecore_ll2_cbs		cbs;
};

/**
* @brief ecore_ll2_alloc - Allocates LL2 connections set
*
* @param p_hwfn
*
* @return enum _ecore_status_t
*/
enum _ecore_status_t ecore_ll2_alloc(struct ecore_hwfn *p_hwfn);

/**
* @brief ecore_ll2_setup - Inits LL2 connections set
*
* @param p_hwfn
*
*/
void ecore_ll2_setup(struct ecore_hwfn *p_hwfn);

/**
* @brief ecore_ll2_free - Releases LL2 connections set
*
* @param p_hwfn
*
*/
void ecore_ll2_free(struct ecore_hwfn *p_hwfn);

#ifndef LINUX_REMOVE
/**
 * @brief ecore_ll2_get_fragment_of_tx_packet
 *
 * @param p_hwfn
 * @param connection_handle    LL2 connection's handle
 *                              obtained from
 *                              ecore_ll2_require_connection
 * @param addr
 * @param last_fragment)
 *
 * @return enum _ecore_status_t
 */
enum _ecore_status_t
ecore_ll2_get_fragment_of_tx_packet(struct ecore_hwfn *p_hwfn,
				    u8 connection_handle,
				    dma_addr_t *addr,
				    bool *last_fragment);
#endif

#endif /*__ECORE_LL2_H__*/
