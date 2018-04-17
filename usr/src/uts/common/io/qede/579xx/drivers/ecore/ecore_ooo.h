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

#ifndef __ECORE_OOO_H__
#define __ECORE_OOO_H__

#include "ecore.h"

#define ECORE_MAX_NUM_ISLES	256
#define ECORE_MAX_NUM_OOO_HISTORY_ENTRIES	512

#define ECORE_OOO_LEFT_BUF	0
#define ECORE_OOO_RIGHT_BUF	1

struct ecore_ooo_buffer {
	osal_list_entry_t	list_entry;
	void			*rx_buffer_virt_addr;
	dma_addr_t		rx_buffer_phys_addr;
	u32			rx_buffer_size;
	u16			packet_length;
	u16			parse_flags;
	u16			vlan;
	u8			placement_offset;
};

struct ecore_ooo_isle {
	osal_list_entry_t	list_entry;
	osal_list_t		buffers_list;
};

struct ecore_ooo_archipelago {
	osal_list_t		isles_list;
};

struct ecore_ooo_history {
	struct ooo_opaque	*p_cqes;
	u32			head_idx;
	u32			num_of_cqes;
};

struct ecore_ooo_info {
	osal_list_t	 free_buffers_list;
	osal_list_t	 ready_buffers_list;
	osal_list_t	 free_isles_list;
	struct ecore_ooo_archipelago	*p_archipelagos_mem;
	struct ecore_ooo_isle	*p_isles_mem;
	struct ecore_ooo_history	ooo_history;
	u32		cur_isles_number;
	u32		max_isles_number;
	u32		gen_isles_number;
	u16		max_num_archipelagos;
	u16		cid_base;
};

enum _ecore_status_t ecore_ooo_alloc(struct ecore_hwfn *p_hwfn);

void ecore_ooo_setup(struct ecore_hwfn *p_hwfn);

void ecore_ooo_free(struct ecore_hwfn *p_hwfn);

void ecore_ooo_save_history_entry(struct ecore_hwfn       *p_hwfn,
				       struct ecore_ooo_info *p_ooo_info,
				       struct ooo_opaque *p_cqe);

void ecore_ooo_release_connection_isles(struct ecore_hwfn       *p_hwfn,
				       struct ecore_ooo_info *p_ooo_info,
				       u32 cid);

void ecore_ooo_release_all_isles(struct ecore_hwfn       *p_hwfn,
				struct ecore_ooo_info *p_ooo_info);

void ecore_ooo_put_free_buffer(struct ecore_hwfn	*p_hwfn,
			      struct ecore_ooo_info	*p_ooo_info,
			      struct ecore_ooo_buffer	*p_buffer);

struct ecore_ooo_buffer *
	ecore_ooo_get_free_buffer(struct ecore_hwfn	*p_hwfn,
				 struct ecore_ooo_info *p_ooo_info);

void ecore_ooo_put_ready_buffer(struct ecore_hwfn	*p_hwfn,
			      struct ecore_ooo_info	*p_ooo_info,
			      struct ecore_ooo_buffer	*p_buffer,
			      u8 on_tail);

struct ecore_ooo_buffer *
	ecore_ooo_get_ready_buffer(struct ecore_hwfn	*p_hwfn,
				  struct ecore_ooo_info *p_ooo_info);

void ecore_ooo_delete_isles(struct ecore_hwfn	*p_hwfn,
			   struct ecore_ooo_info *p_ooo_info,
			   u32 cid,
			   u8 drop_isle,
			   u8 drop_size);

void ecore_ooo_add_new_isle(struct ecore_hwfn	*p_hwfn,
			   struct ecore_ooo_info *p_ooo_info,
			   u32 cid,
			   u8 ooo_isle,
			   struct ecore_ooo_buffer *p_buffer);

void ecore_ooo_add_new_buffer(struct ecore_hwfn	*p_hwfn,
			     struct ecore_ooo_info *p_ooo_info,
			     u32 cid,
			     u8 ooo_isle,
			     struct ecore_ooo_buffer *p_buffer,
		             u8 buffer_side);

void ecore_ooo_join_isles(struct ecore_hwfn	*p_hwfn,
			 struct ecore_ooo_info *p_ooo_info,
			 u32 cid,
			 u8 left_isle);

void ecore_ooo_dump_rx_event(struct ecore_hwfn	*p_hwfn,
			     struct ooo_opaque *iscsi_ooo,
			     struct ecore_ooo_buffer *p_buffer);

#endif  /*__ECORE_OOO_H__*/

