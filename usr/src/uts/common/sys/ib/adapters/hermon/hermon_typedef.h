/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_IB_ADAPTERS_HERMON_TYPEDEF_H
#define	_SYS_IB_ADAPTERS_HERMON_TYPEDEF_H

/*
 * hermon_typedef.h
 *    Contains all the common typedefs used throughout the Hermon driver.
 *    Because the hermon.h header file (which all source files include) brings
 *    this header file in first (before any of the other Hermon header files),
 *    the typedefs defined here can be used throughout the source and header
 *    files in the rest of the driver.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef	struct hermon_state_s		hermon_state_t;
typedef	struct hermon_agent_list_s	hermon_agent_list_t;
typedef	struct hermon_qalloc_info_s	hermon_qalloc_info_t;
typedef struct hermon_rsrc_pool_info_s	hermon_rsrc_pool_info_t;
typedef	struct hermon_rsrc_s		hermon_rsrc_t;
typedef struct hermon_wrid_list_hdr_s	hermon_wrid_list_hdr_t;
typedef struct hermon_workq_avl_s	hermon_workq_avl_t;
typedef struct hermon_workq_hdr_s	hermon_workq_hdr_t;
typedef struct hermon_wq_lock_s		hermon_wq_lock_t;
typedef struct hermon_icm_info_s	hermon_icm_info_t;
typedef struct hermon_icm_table_s	hermon_icm_table_t;
typedef	struct hermon_dma_info_s	hermon_dma_info_t;
typedef struct hermon_hw_vpm_s 		hermon_hw_vpm_t;
typedef struct hermon_hw_hcr_s		hermon_hw_hcr_t;
typedef struct hermon_hw_querydevlim_s	hermon_hw_querydevlim_t;
typedef struct hermon_hw_query_port_s	hermon_hw_query_port_t;
typedef struct hermon_hw_set_port_s	hermon_hw_set_port_t;
typedef struct hermon_hw_set_port_en_s	hermon_hw_set_port_en_t;
typedef struct hermon_hw_set_port_en_rqpn_s  hermon_hw_set_port_en_rqpn_t;
typedef struct hermon_hw_set_port_en_mact_s  hermon_hw_set_port_en_mact_t;
typedef struct hermon_hw_set_port_en_vlant_s hermon_hw_set_port_en_vlant_t;
typedef struct hermon_hw_set_port_en_priot_s hermon_hw_set_port_en_priot_t;
typedef struct hermon_fw_set_port_gidtable_s hermon_fw_set_port_gidtable_t;
typedef struct hermon_hw_set_mcast_fltr_s hermon_hw_set_mcast_fltr_t;
typedef struct hermon_hw_arm_req_s	hermon_hw_arm_req_t;
typedef struct hermon_hw_config_fc_basic_s hermon_hw_config_fc_basic_t;
typedef struct hermon_hw_query_fc_s	hermon_hw_query_fc_t;

typedef struct hermon_hw_queryfw_s	hermon_hw_queryfw_t;
typedef struct hermon_hw_queryadapter_s	hermon_hw_queryadapter_t;
typedef struct hermon_hw_initqueryhca_s	hermon_hw_initqueryhca_t;
typedef struct hermon_hw_dmpt_s		hermon_hw_dmpt_t;
typedef struct hermon_hw_cmpt_s		hermon_hw_cmpt_t;
typedef struct hermon_hw_mtt_s		hermon_hw_mtt_t;
typedef struct hermon_hw_eqc_s		hermon_hw_eqc_t;
typedef struct hermon_hw_eqe_s		hermon_hw_eqe_t;
typedef struct hermon_hw_cqc_s		hermon_hw_cqc_t;
typedef struct hermon_hw_srqc_s		hermon_hw_srqc_t;
typedef struct hermon_hw_uar_s		hermon_hw_uar_t;
typedef struct hermon_hw_cqe_s		hermon_hw_cqe_t;
typedef struct hermon_hw_addr_path_s	hermon_hw_addr_path_t;
typedef	struct hermon_hw_mod_stat_cfg_s  hermon_hw_mod_stat_cfg_t;
typedef	struct hermon_hw_msg_in_mod_s	hermon_hw_msg_in_mod_t;
typedef struct hermon_hw_udav_s		hermon_hw_udav_t;
typedef struct hermon_hw_udav_enet_s	hermon_hw_udav_enet_t;
typedef struct hermon_hw_qpc_s		hermon_hw_qpc_t;
typedef struct hermon_hw_mcg_s		hermon_hw_mcg_t;
typedef struct hermon_hw_mcg_en_s	hermon_hw_mcg_en_t;
typedef struct hermon_hw_mcg_qp_list_s	hermon_hw_mcg_qp_list_t;
typedef struct hermon_hw_sm_perfcntr_s	hermon_hw_sm_perfcntr_t;
typedef struct hermon_hw_sm_extperfcntr_s hermon_hw_sm_extperfcntr_t;

typedef struct hermon_hw_snd_wqe_ud_s	hermon_hw_snd_wqe_ud_t;
typedef struct hermon_hw_snd_wqe_bind_s	hermon_hw_snd_wqe_bind_t;
typedef struct hermon_hw_snd_wqe_remaddr_s  hermon_hw_snd_wqe_remaddr_t;
typedef struct hermon_hw_snd_wqe_atomic_s   hermon_hw_snd_wqe_atomic_t;
typedef struct hermon_hw_snd_wqe_frwr_s	hermon_hw_snd_wqe_frwr_t;
typedef struct hermon_hw_snd_wqe_frwr_ext_s  hermon_hw_snd_wqe_frwr_ext_t;
typedef struct hermon_hw_snd_wqe_local_inv_s hermon_hw_snd_wqe_local_inv_t;
typedef struct hermon_hw_snd_rem_addr_s	hermon_hw_snd_rem_addr_t;
typedef struct hermon_sw_send_wqe_lso_s hermon_sw_send_wqe_lso_t;
typedef struct hermon_hw_mlx_wqe_nextctrl_s hermon_hw_mlx_wqe_nextctrl_t;
typedef struct hermon_hw_rcv_wqe_nextctrl_s hermon_hw_rcv_wqe_nextctrl_t;
typedef struct hermon_hw_wqe_sgl_s	hermon_hw_wqe_sgl_t;
typedef struct hermon_hw_snd_wqe_ctrl_s hermon_hw_snd_wqe_ctrl_t;
typedef struct hermon_hw_srq_wqe_next_s hermon_hw_srq_wqe_next_t;
typedef struct hermonw_hw_fcp3_ctrl_s 	hermonw_hw_fcp3_ctrl_t;
typedef struct hermon_hw_fcp3_init_s 	hermon_hw_fcp3_init_t;
typedef struct hermon_hw_fcmd_o_enet_s	hermon_hw_fcmd_o_enet_t;
typedef struct hermon_hw_fcmd_o_ib_s	hermon_hw_fcmd_o_ib_t;

typedef struct hermon_sw_mr_s		*hermon_mrhdl_t;
typedef struct hermon_sw_mr_s		*hermon_mwhdl_t;
typedef struct hermon_sw_pd_s		*hermon_pdhdl_t;
typedef struct hermon_sw_eq_s		*hermon_eqhdl_t;
typedef struct hermon_sw_cq_s		*hermon_cqhdl_t;
typedef struct hermon_sw_srq_s		*hermon_srqhdl_t;
typedef struct hermon_sw_fmr_s		*hermon_fmrhdl_t;
typedef struct hermon_sw_ah_s		*hermon_ahhdl_t;
typedef struct hermon_sw_qp_s		*hermon_qphdl_t;
typedef struct hermon_sw_mcg_list_s	*hermon_mcghdl_t;

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_ADAPTERS_HERMON_TYPEDEF_H */
