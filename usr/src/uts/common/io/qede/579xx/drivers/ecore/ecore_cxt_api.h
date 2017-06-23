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

#ifndef __ECORE_CXT_API_H__
#define __ECORE_CXT_API_H__

struct ecore_hwfn;

struct ecore_cxt_info {
	void			*p_cxt;
	u32			iid;
	enum protocol_type	type;
}; 

#define MAX_TID_BLOCKS			512
struct ecore_tid_mem {
	u32 tid_size;
	u32 num_tids_per_block;
	u32 waste;
	u8 *blocks[MAX_TID_BLOCKS]; /* 4K */
};

/**
* @brief ecoreo_cid_get_cxt_info - Returns the context info for a specific cid
*
*
* @param p_hwfn
* @param p_info in/out
*
* @return enum _ecore_status_t
*/
enum _ecore_status_t ecore_cxt_get_cid_info(struct ecore_hwfn *p_hwfn,
					    struct ecore_cxt_info *p_info); 

/**
* @brief ecore_cxt_get_tid_mem_info
*
* @param p_hwfn
* @param p_info
*
* @return enum _ecore_status_t
*/
enum _ecore_status_t ecore_cxt_get_tid_mem_info(struct ecore_hwfn *p_hwfn,
						struct ecore_tid_mem *p_info); 

#endif
