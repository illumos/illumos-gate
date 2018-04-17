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

#ifndef __ECORE_FCOE_API_H__
#define __ECORE_FCOE_API_H__

#include "ecore_sp_api.h"

struct ecore_fcoe_conn {
	osal_list_entry_t	list_entry;
	bool			free_on_delete;

	u16			conn_id;
	u32			icid;
	u32			fw_cid;
	u8			layer_code;

	dma_addr_t		sq_pbl_addr;
	dma_addr_t		sq_curr_page_addr;
	dma_addr_t		sq_next_page_addr;
	dma_addr_t		xferq_pbl_addr;
	void			*xferq_pbl_addr_virt_addr;
	dma_addr_t		xferq_addr[4];
	void			*xferq_addr_virt_addr[4];
	dma_addr_t		confq_pbl_addr;
	void			*confq_pbl_addr_virt_addr;
	dma_addr_t		confq_addr[2];
	void			*confq_addr_virt_addr[2];

	dma_addr_t		terminate_params;

	u16			dst_mac_addr_lo;
	u16			dst_mac_addr_mid;
	u16			dst_mac_addr_hi;
	u16			src_mac_addr_lo;
	u16			src_mac_addr_mid;
	u16			src_mac_addr_hi;

	u16			tx_max_fc_pay_len;
	u16			e_d_tov_timer_val;
	u16			rec_tov_timer_val;
	u16			rx_max_fc_pay_len;
	u16			vlan_tag;
	u16			physical_q0;

	struct fc_addr_nw	s_id;
	u8 max_conc_seqs_c3;
	struct fc_addr_nw	d_id;
	u8			flags;
	u8			def_q_idx;
}; 

#ifndef __EXTRACT__LINUX__
struct ecore_fcoe_stats {
	u64	fcoe_rx_byte_cnt;
	u64	fcoe_rx_data_pkt_cnt;
	u64	fcoe_rx_xfer_pkt_cnt;
	u64	fcoe_rx_other_pkt_cnt;
	u32	fcoe_silent_drop_pkt_cmdq_full_cnt;
	u32	fcoe_silent_drop_pkt_rq_full_cnt;
	u32	fcoe_silent_drop_pkt_crc_error_cnt;
	u32	fcoe_silent_drop_pkt_task_invalid_cnt;
	u32	fcoe_silent_drop_total_pkt_cnt;

	u64	fcoe_tx_byte_cnt;
	u64	fcoe_tx_data_pkt_cnt;
	u64	fcoe_tx_xfer_pkt_cnt;
	u64	fcoe_tx_other_pkt_cnt;
};
#endif

enum _ecore_status_t
ecore_fcoe_acquire_connection(struct ecore_hwfn *p_hwfn,
			      struct ecore_fcoe_conn *p_in_conn,
			      struct ecore_fcoe_conn **p_out_conn);

void OSAL_IOMEM *ecore_fcoe_get_db_addr(struct ecore_hwfn *p_hwfn,
					u32 cid);

void OSAL_IOMEM *ecore_fcoe_get_global_cmdq_cons(struct ecore_hwfn *p_hwfn,
						 u8 relative_q_id);

void OSAL_IOMEM *ecore_fcoe_get_primary_bdq_prod(struct ecore_hwfn *p_hwfn,
						  u8 bdq_id);

void OSAL_IOMEM *ecore_fcoe_get_secondary_bdq_prod(struct ecore_hwfn *p_hwfn,
						    u8 bdq_id);

enum _ecore_status_t
ecore_fcoe_offload_connection(struct ecore_hwfn	*p_hwfn,
			      struct ecore_fcoe_conn *p_conn);

enum _ecore_status_t
ecore_fcoe_terminate_connection(struct ecore_hwfn *p_hwfn,
				struct ecore_fcoe_conn *p_conn);

void ecore_fcoe_release_connection(struct ecore_hwfn *p_hwfn,
				   struct ecore_fcoe_conn *p_conn);

enum _ecore_status_t
ecore_sp_fcoe_func_start(struct ecore_hwfn *p_hwfn,
			 enum spq_mode comp_mode,
			 struct ecore_spq_comp_cb *p_comp_addr);

enum _ecore_status_t
ecore_sp_fcoe_func_stop(struct ecore_hwfn *p_hwfn,
			enum spq_mode comp_mode,
			struct ecore_spq_comp_cb *p_comp_addr);

enum _ecore_status_t
ecore_fcoe_get_stats(struct ecore_hwfn *p_hwfn,
		     struct ecore_fcoe_stats *stats);

#endif
