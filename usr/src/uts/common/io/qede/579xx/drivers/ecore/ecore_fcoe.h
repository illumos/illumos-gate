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

#ifndef __ECORE_FCOE_H__
#define __ECORE_FCOE_H__

#include "ecore.h"
#include "ecore_chain.h"
#include "ecore_hsi_common.h"
#include "ecore_hsi_fcoe.h"
#include "ecore_fcoe_api.h"

struct ecore_fcoe_info {
	osal_spinlock_t	lock;
	osal_list_t	free_list;
};

enum _ecore_status_t ecore_fcoe_alloc(struct ecore_hwfn *p_hwfn);

void ecore_fcoe_setup(struct ecore_hwfn *p_hwfn);

void ecore_fcoe_free(struct ecore_hwfn *p_hwfn);

enum _ecore_status_t
ecore_sp_fcoe_conn_offload(struct ecore_hwfn *p_hwfn,
			   struct ecore_fcoe_conn *p_conn,
			   enum spq_mode comp_mode,
			   struct ecore_spq_comp_cb *p_comp_addr);

enum _ecore_status_t
ecore_sp_fcoe_conn_destroy(struct ecore_hwfn *p_hwfn,
			   struct ecore_fcoe_conn *p_conn,
			   enum spq_mode comp_mode,
			   struct ecore_spq_comp_cb *p_comp_addr);

#endif  /*__ECORE_FCOE_H__*/

