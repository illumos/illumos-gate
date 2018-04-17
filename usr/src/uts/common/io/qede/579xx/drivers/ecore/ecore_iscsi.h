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

#ifndef __ECORE_ISCSI_H__
#define __ECORE_ISCSI_H__

#include "ecore.h"
#include "ecore_chain.h"
#include "ecore_hsi_common.h"
#include "tcp_common.h"
#include "ecore_hsi_iscsi.h"
#include "ecore_sp_commands.h"
#include "ecore_iscsi_api.h"

struct ecore_iscsi_info {
	osal_spinlock_t	 lock;
	osal_list_t	 free_list;
	u16		 max_num_outstanding_tasks;
	void		 *event_context;
	iscsi_event_cb_t event_cb;
};

enum _ecore_status_t ecore_iscsi_alloc(struct ecore_hwfn *p_hwfn);

void ecore_iscsi_setup(struct ecore_hwfn *p_hwfn);

void ecore_iscsi_free(struct ecore_hwfn *p_hwfn);

void ecore_iscsi_free_connection(struct ecore_hwfn *p_hwfn,
				 struct ecore_iscsi_conn *p_conn);

/**
 * @brief ecore_sp_iscsi_conn_offload - iSCSI connection offload
 *
 * This ramrod offloads iSCSI connection to FW
 *
 * @param p_path
 * @param p_conn
 * @param comp_mode
 * @param comp_addr
 *
 * @return enum _ecore_status_t
 */
enum _ecore_status_t
ecore_sp_iscsi_conn_offload(struct ecore_hwfn *p_hwfn,
			    struct ecore_iscsi_conn *p_conn,
			    enum spq_mode comp_mode,
			    struct ecore_spq_comp_cb *p_comp_addr);

/**
 * @brief ecore_sp_iscsi_conn_update - iSCSI connection update
 *
 * This ramrod updatess iSCSI ofloadedconnection in FW
 *
 * @param p_path
 * @param p_conn
 * @param comp_mode
 * @param comp_addr
 *
 * @return enum _ecore_status_t
 */
enum _ecore_status_t
ecore_sp_iscsi_conn_update(struct ecore_hwfn *p_hwfn,
			   struct ecore_iscsi_conn *p_conn,
			   enum spq_mode comp_mode,
			   struct ecore_spq_comp_cb *p_comp_addr);

/**
 * @brief ecore_sp_iscsi_mac_update - iSCSI connection's MAC update
 *
 * This ramrod updates remote MAC for iSCSI offloaded connection in FW
 *
 * @param p_path
 * @param p_conn
 * @param comp_mode
 * @param comp_addr
 *
 * @return enum _ecore_status_t
 */
enum _ecore_status_t
ecore_sp_iscsi_mac_update(struct ecore_hwfn *p_hwfn,
			  struct ecore_iscsi_conn *p_conn,
			  enum spq_mode comp_mode,
			  struct ecore_spq_comp_cb *p_comp_addr);

/**
 * @brief ecore_sp_iscsi_conn_terminate - iSCSI connection
 *        terminate
 *
 * This ramrod deletes iSCSI offloaded connection in FW
 *
 * @param p_path
 * @param p_conn
 * @param comp_mode
 * @param comp_addr
 *
 * @return enum _ecore_status_t
 */
enum _ecore_status_t
ecore_sp_iscsi_conn_terminate(struct ecore_hwfn *p_hwfn,
			      struct ecore_iscsi_conn *p_conn,
			      enum spq_mode comp_mode,
			      struct ecore_spq_comp_cb *p_comp_addr);

/**
 * @brief ecore_sp_iscsi_conn_clear_sq - iSCSI connection
 *        clear SQ
 *
 * This ramrod clears connection's SQ in FW
 *
 * @param p_path
 * @param p_conn
 * @param comp_mode
 * @param comp_addr
 *
 * @return enum _ecore_status_t
 */
enum _ecore_status_t
ecore_sp_iscsi_conn_clear_sq(struct ecore_hwfn *p_hwfn,
			     struct ecore_iscsi_conn *p_conn,
			     enum spq_mode comp_mode,
			     struct ecore_spq_comp_cb *p_comp_addr);

#endif  /*__ECORE_ISCSI_H__*/

