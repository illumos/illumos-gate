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

#ifndef __ECORE_PROTO_IF_H__
#define __ECORE_PROTO_IF_H__

/*
 * PF parameters (according to personality/protocol)
 */

#define ECORE_ROCE_PROTOCOL_INDEX	(3)

struct ecore_eth_pf_params {
	/* The following parameters are used during HW-init
	 * and these parameters need to be passed as arguments
	 * to update_pf_params routine invoked before slowpath start
	 */
	u16	num_cons;

	/* per-VF number of CIDs */
	u8	num_vf_cons;
#define ETH_PF_PARAMS_VF_CONS_DEFAULT	(32)

	/* To enable arfs, previous to HW-init a positive number needs to be
	 * set [as filters require allocated searcher ILT memory].
	 * This will set the maximal number of configured steering-filters.
	 */
	u32	num_arfs_filters;
};

/* Most of the the parameters below are described in the FW FCoE HSI */
struct ecore_fcoe_pf_params {
	/* The following parameters are used during protocol-init */
	u64		glbl_q_params_addr;
	u64		bdq_pbl_base_addr[2];

	/* The following parameters are used during HW-init
	 * and these parameters need to be passed as arguments
	 * to update_pf_params routine invoked before slowpath start
	 */
	u16		num_cons;
	u16		num_tasks;

	/* The following parameters are used during protocol-init */
	u16		sq_num_pbl_pages;

	u16		cq_num_entries;
	u16		cmdq_num_entries;
	u16		rq_buffer_log_size;
	u16		mtu;
	u16		dummy_icid;
	u16		bdq_xoff_threshold[2];
	u16		bdq_xon_threshold[2];
	u16		rq_buffer_size;
	u8		num_cqs; /* num of global CQs */
	u8		log_page_size;
	u8		gl_rq_pi;
	u8		gl_cmd_pi;
	u8		debug_mode;
	u8		is_target;
	u8		bdq_pbl_num_entries[2];
};

/* Most of the the parameters below are described in the FW iSCSI / TCP HSI */
struct ecore_iscsi_pf_params {

	u64		glbl_q_params_addr;
	u64		bdq_pbl_base_addr[2];
	u16		cq_num_entries;
	u16		cmdq_num_entries;
	u32		two_msl_timer;
	u16		tx_sws_timer;
	/* The following parameters are used during HW-init
	 * and these parameters need to be passed as arguments
	 * to update_pf_params routine invoked before slowpath start
	 */
	u16		num_cons;
	u16		num_tasks;

	/* The following parameters are used during protocol-init */
	u16		half_way_close_timeout;
	u16		bdq_xoff_threshold[2];
	u16		bdq_xon_threshold[2];
	u16		cmdq_xoff_threshold;
	u16		cmdq_xon_threshold;
	u16		rq_buffer_size;

	u8		num_sq_pages_in_ring;
	u8		num_r2tq_pages_in_ring;
	u8		num_uhq_pages_in_ring;
	u8		num_queues;
	u8		log_page_size;
	u8		rqe_log_size;
	u8		max_fin_rt;
	u8		gl_rq_pi;
	u8		gl_cmd_pi;
	u8		debug_mode;
	u8		ll2_ooo_queue_id;
	u8		ooo_enable;

	u8		is_target;
	u8		bdq_pbl_num_entries[2];
};

enum ecore_rdma_protocol {
	ECORE_RDMA_PROTOCOL_DEFAULT,
	ECORE_RDMA_PROTOCOL_NONE,
	ECORE_RDMA_PROTOCOL_ROCE,
	ECORE_RDMA_PROTOCOL_IWARP,
};

struct ecore_rdma_pf_params {
	/* Supplied to ECORE during resource allocation (may affect the ILT and
	 * the doorbell BAR).
	 */
	u32		min_dpis;	/* number of requested DPIs */
	u32		num_qps;	/* number of requested Queue Pairs */
	u32		num_srqs;	/* number of requested SRQ */
	u8		roce_edpm_mode; /* see QED_ROCE_EDPM_MODE_ENABLE */
	u8		gl_pi;		/* protocol index */

	/* Will allocate rate limiters to be used with QPs */
	u8		enable_dcqcn;

	/* Max number of CNQs - limits number of ECORE_RDMA_CNQ feature,
	 * Allowing an incrementation in ECORE_PF_L2_QUE.
	 * To disable CNQs, use dedicated value instead of `0'.
	 */
#define ECORE_RDMA_PF_PARAMS_CNQS_NONE	(0xffff)
	u16		max_cnqs;

	/* TCP port number used for the iwarp traffic */
	u16		iwarp_port;
	enum ecore_rdma_protocol rdma_protocol;
};

struct ecore_pf_params {
	struct ecore_eth_pf_params	eth_pf_params;
	struct ecore_fcoe_pf_params	fcoe_pf_params;
	struct ecore_iscsi_pf_params	iscsi_pf_params;
	struct ecore_rdma_pf_params	rdma_pf_params;
};

#endif


