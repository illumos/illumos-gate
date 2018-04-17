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

#ifndef __ECORE_SP_API_H__
#define __ECORE_SP_API_H__

#include "ecore_status.h"

enum spq_mode {
	ECORE_SPQ_MODE_BLOCK,   /* Client will poll a designated mem. address */
	ECORE_SPQ_MODE_CB,  /* Client supplies a callback */
	ECORE_SPQ_MODE_EBLOCK,  /* ECORE should block until completion */
};

struct ecore_hwfn;
union event_ring_data;
struct eth_slow_path_rx_cqe;

struct ecore_spq_comp_cb {
	void	(*function)(struct ecore_hwfn *,
			 void *,
			 union event_ring_data *,
			 u8 fw_return_code);
	void	*cookie;
};


/**
 * @brief ecore_eth_cqe_completion - handles the completion of a
 *        ramrod on the cqe ring
 *
 * @param p_hwfn
 * @param cqe
 *
 * @return enum _ecore_status_t
 */
enum _ecore_status_t ecore_eth_cqe_completion(struct ecore_hwfn *p_hwfn,
					      struct eth_slow_path_rx_cqe *cqe);
/**
 * @brief ecore_sp_pf_update_tunn_cfg - PF Function Tunnel configuration
 *					update  Ramrod
 *
 * This ramrod is sent to update a tunneling configuration
 * for a physical function (PF).
 *
 * @param p_hwfn
 * @param p_tunn - pf update tunneling parameters
 * @param comp_mode - completion mode
 * @param p_comp_data - callback function
 *
 * @return enum _ecore_status_t
 */

enum _ecore_status_t
ecore_sp_pf_update_tunn_cfg(struct ecore_hwfn *p_hwfn,
			    struct ecore_tunnel_info *p_tunn,
			    enum spq_mode comp_mode,
			    struct ecore_spq_comp_cb *p_comp_data);
#endif
