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

#ifndef __ECORE_INIT_OPS__
#define __ECORE_INIT_OPS__

#include "ecore.h"

/**
 * @brief ecore_init_iro_array - init iro_arr.
 *
 *
 * @param p_dev
 */
void ecore_init_iro_array(struct ecore_dev *p_dev);

/**
 * @brief ecore_init_run - Run the init-sequence.
 *
 *
 * @param p_hwfn
 * @param p_ptt
 * @param phase 
 * @param phase_id 
 * @param modes
 * @return _ecore_status_t
 */
enum _ecore_status_t ecore_init_run(struct ecore_hwfn *p_hwfn,
				    struct ecore_ptt  *p_ptt,
				    int               phase,
				    int               phase_id,
				    int               modes);

/**
 * @brief ecore_init_hwfn_allocate - Allocate RT array, Store 'values' ptrs.
 *
 *
 * @param p_hwfn
 *
 * @return _ecore_status_t
 */
enum _ecore_status_t ecore_init_alloc(struct ecore_hwfn *p_hwfn);

/**
 * @brief ecore_init_hwfn_deallocate
 *
 *
 * @param p_hwfn
 */
void ecore_init_free(struct ecore_hwfn *p_hwfn);


/**
 * @brief ecore_init_clear_rt_data - Clears the runtime init array.
 *
 *
 * @param p_hwfn
 */
void ecore_init_clear_rt_data(struct ecore_hwfn *p_hwfn);

/**
 * @brief ecore_init_store_rt_reg - Store a configuration value in the RT array.
 *
 *
 * @param p_hwfn
 * @param rt_offset
 * @param val
 */
void ecore_init_store_rt_reg(struct ecore_hwfn *p_hwfn,
			     u32               	rt_offset,
			     u32               	val);

#define STORE_RT_REG(hwfn, offset, val)				\
	ecore_init_store_rt_reg(hwfn, offset, val)

#define OVERWRITE_RT_REG(hwfn, offset, val)			\
	ecore_init_store_rt_reg(hwfn, offset, val)

/**
* @brief
*
*
* @param p_hwfn
* @param rt_offset
* @param val
* @param size
*/

void ecore_init_store_rt_agg(struct ecore_hwfn *p_hwfn,
			     u32               rt_offset,
			     u32               *val,
			     osal_size_t       size);

#define STORE_RT_REG_AGG(hwfn, offset, val)			\
	ecore_init_store_rt_agg(hwfn, offset, (u32*)&val, sizeof(val))


/**
 * @brief 
 *      Initialize GTT global windows and set admin window
 *      related params of GTT/PTT to default values. 
 * 
 * @param p_hwfn 
 */
void ecore_gtt_init(struct ecore_hwfn *p_hwfn);
#endif /* __ECORE_INIT_OPS__ */
