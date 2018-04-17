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

#ifndef __ECORE_DCBX_H__
#define __ECORE_DCBX_H__

#include "ecore.h"
#include "ecore_mcp.h"
#include "mcp_public.h"
#include "reg_addr.h"
#include "ecore_hw.h"
#include "ecore_hsi_common.h"
#include "ecore_dcbx_api.h"

struct ecore_dcbx_info {
	struct lldp_status_params_s lldp_remote[LLDP_MAX_LLDP_AGENTS];
	struct lldp_config_params_s lldp_local[LLDP_MAX_LLDP_AGENTS];
	struct dcbx_local_params local_admin;
	struct ecore_dcbx_results results;
	struct dcb_dscp_map dscp_map;
	bool dscp_nig_update;
	struct dcbx_mib operational;
	struct dcbx_mib remote;
	struct ecore_dcbx_set set;
	struct ecore_dcbx_get get;
	u8 dcbx_cap;
	u16 iwarp_port;
};

struct ecore_dcbx_mib_meta_data {
	struct lldp_config_params_s *lldp_local;
	struct lldp_status_params_s *lldp_remote;
	struct dcbx_local_params *local_admin;
	struct dcb_dscp_map *dscp_map;
	struct dcbx_mib *mib;
	osal_size_t size;
	u32 addr;
};

/* ECORE local interface routines */
enum _ecore_status_t
ecore_dcbx_mib_update_event(struct ecore_hwfn *, struct ecore_ptt *,
			    enum ecore_mib_read_type);

enum _ecore_status_t ecore_dcbx_read_lldp_params(struct ecore_hwfn *,
						 struct ecore_ptt *);
enum _ecore_status_t ecore_dcbx_info_alloc(struct ecore_hwfn *p_hwfn);
void ecore_dcbx_info_free(struct ecore_hwfn *);
void ecore_dcbx_set_pf_update_params(struct ecore_dcbx_results *p_src,
				     struct pf_update_ramrod_data *p_dest);

#endif /* __ECORE_DCBX_H__ */
