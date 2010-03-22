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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_IB_ADAPTERS_TAVOR_TYPEDEF_H
#define	_SYS_IB_ADAPTERS_TAVOR_TYPEDEF_H

/*
 * tavor_typedef.h
 *    Contains all the common typedefs used throughout the Tavor driver.
 *    Because the tavor.h header file (which all source files include) brings
 *    this header file in first (before any of the other Tavor header files),
 *    the typedefs defined here can be used throughout the source and header
 *    files in the rest of the driver.
 */

#ifdef __cplusplus
extern "C" {
#endif

typedef	struct tavor_state_s		tavor_state_t;
typedef	struct tavor_agent_list_s	tavor_agent_list_t;
typedef	struct tavor_qalloc_info_s	tavor_qalloc_info_t;
typedef struct tavor_rsrc_pool_info_s	tavor_rsrc_pool_info_t;
typedef	struct tavor_rsrc_s		tavor_rsrc_t;
typedef struct tavor_wrid_entry_s	tavor_wrid_entry_t;
typedef struct tavor_wrid_list_hdr_s	tavor_wrid_list_hdr_t;
typedef struct tavor_workq_hdr_s	tavor_workq_hdr_t;
typedef struct tavor_wq_lock_s		tavor_wq_lock_t;

typedef struct tavor_hw_hcr_s		tavor_hw_hcr_t;
typedef struct tavor_hw_querydevlim_s	tavor_hw_querydevlim_t;
typedef struct tavor_hw_queryfw_s	tavor_hw_queryfw_t;
typedef struct tavor_hw_queryddr_s	tavor_hw_queryddr_t;
typedef struct tavor_hw_queryadapter_s	tavor_hw_queryadapter_t;
typedef struct tavor_hw_initqueryhca_s	tavor_hw_initqueryhca_t;
typedef struct tavor_hw_initib_s	tavor_hw_initib_t;
typedef struct tavor_hw_mpt_s		tavor_hw_mpt_t;
typedef struct tavor_hw_mtt_s		tavor_hw_mtt_t;
typedef struct tavor_hw_eqc_s		tavor_hw_eqc_t;
typedef struct tavor_hw_eqe_s		tavor_hw_eqe_t;
typedef struct tavor_hw_cqc_s		tavor_hw_cqc_t;
typedef struct tavor_hw_srqc_s		tavor_hw_srqc_t;
typedef struct tavor_hw_uar_s		tavor_hw_uar_t;
typedef struct tavor_hw_cqe_s		tavor_hw_cqe_t;
typedef struct tavor_hw_addr_path_s	tavor_hw_addr_path_t;
typedef	struct tavor_hw_mod_stat_cfg_s  tavor_hw_mod_stat_cfg_t;
typedef struct tavor_hw_udav_s		tavor_hw_udav_t;
typedef struct tavor_hw_qpc_s		tavor_hw_qpc_t;
typedef struct tavor_hw_mcg_s		tavor_hw_mcg_t;
typedef struct tavor_hw_mcg_qp_list_s	tavor_hw_mcg_qp_list_t;
typedef struct tavor_hw_sm_perfcntr_s	tavor_hw_sm_perfcntr_t;
typedef struct tavor_hw_snd_wqe_nextctrl_s tavor_hw_snd_wqe_nextctrl_t;
typedef struct tavor_hw_snd_wqe_ud_s	   tavor_hw_snd_wqe_ud_t;
typedef struct tavor_hw_snd_wqe_bind_s	   tavor_hw_snd_wqe_bind_t;
typedef struct tavor_hw_snd_wqe_remaddr_s  tavor_hw_snd_wqe_remaddr_t;
typedef struct tavor_hw_snd_wqe_atomic_s   tavor_hw_snd_wqe_atomic_t;
typedef struct tavor_hw_mlx_wqe_nextctrl_s tavor_hw_mlx_wqe_nextctrl_t;
typedef struct tavor_hw_rcv_wqe_nextctrl_s tavor_hw_rcv_wqe_nextctrl_t;
typedef struct tavor_hw_wqe_sgl_s	tavor_hw_wqe_sgl_t;

typedef struct tavor_sw_mr_s		*tavor_mrhdl_t;
typedef struct tavor_sw_mr_s		*tavor_mwhdl_t;
typedef struct tavor_sw_pd_s		*tavor_pdhdl_t;
typedef struct tavor_sw_eq_s		*tavor_eqhdl_t;
typedef struct tavor_sw_cq_s		*tavor_cqhdl_t;
typedef struct tavor_sw_srq_s		*tavor_srqhdl_t;
typedef struct tavor_sw_ah_s		*tavor_ahhdl_t;
typedef struct tavor_sw_qp_s		*tavor_qphdl_t;
typedef struct tavor_sw_mcg_list_s	*tavor_mcghdl_t;

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_ADAPTERS_TAVOR_TYPEDEF_H */
