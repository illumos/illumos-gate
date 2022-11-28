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
 * Copyright (c) 2003, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * tavor_ci.c
 *    Tavor Channel Interface (CI) Routines
 *
 *    Implements all the routines necessary to interface with the IBTF.
 *    Pointers to all of these functions are passed to the IBTF at attach()
 *    time in the ibc_operations_t structure.  These functions include all
 *    of the necessary routines to implement the required InfiniBand "verbs"
 *    and additional IBTF-specific interfaces.
 */

#include <sys/types.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/ib/adapters/tavor/tavor.h>

/* HCA and port related operations */
static ibt_status_t tavor_ci_query_hca_ports(ibc_hca_hdl_t, uint8_t,
    ibt_hca_portinfo_t *);
static ibt_status_t tavor_ci_modify_ports(ibc_hca_hdl_t, uint8_t,
    ibt_port_modify_flags_t, uint8_t);
static ibt_status_t tavor_ci_modify_system_image(ibc_hca_hdl_t, ib_guid_t);

/* Protection Domains */
static ibt_status_t tavor_ci_alloc_pd(ibc_hca_hdl_t, ibt_pd_flags_t,
    ibc_pd_hdl_t *);
static ibt_status_t tavor_ci_free_pd(ibc_hca_hdl_t, ibc_pd_hdl_t);

/* Reliable Datagram Domains */
static ibt_status_t tavor_ci_alloc_rdd(ibc_hca_hdl_t, ibc_rdd_flags_t,
    ibc_rdd_hdl_t *);
static ibt_status_t tavor_ci_free_rdd(ibc_hca_hdl_t, ibc_rdd_hdl_t);

/* Address Handles */
static ibt_status_t tavor_ci_alloc_ah(ibc_hca_hdl_t, ibt_ah_flags_t,
    ibc_pd_hdl_t, ibt_adds_vect_t *, ibc_ah_hdl_t *);
static ibt_status_t tavor_ci_free_ah(ibc_hca_hdl_t, ibc_ah_hdl_t);
static ibt_status_t tavor_ci_query_ah(ibc_hca_hdl_t, ibc_ah_hdl_t,
    ibc_pd_hdl_t *, ibt_adds_vect_t *);
static ibt_status_t tavor_ci_modify_ah(ibc_hca_hdl_t, ibc_ah_hdl_t,
    ibt_adds_vect_t *);

/* Queue Pairs */
static ibt_status_t tavor_ci_alloc_qp(ibc_hca_hdl_t, ibtl_qp_hdl_t,
    ibt_qp_type_t, ibt_qp_alloc_attr_t *, ibt_chan_sizes_t *, ib_qpn_t *,
    ibc_qp_hdl_t *);
static ibt_status_t tavor_ci_alloc_special_qp(ibc_hca_hdl_t, uint8_t,
    ibtl_qp_hdl_t, ibt_sqp_type_t, ibt_qp_alloc_attr_t *,
    ibt_chan_sizes_t *, ibc_qp_hdl_t *);
static ibt_status_t tavor_ci_alloc_qp_range(ibc_hca_hdl_t, uint_t,
    ibtl_qp_hdl_t *, ibt_qp_type_t, ibt_qp_alloc_attr_t *, ibt_chan_sizes_t *,
    ibc_cq_hdl_t *, ibc_cq_hdl_t *, ib_qpn_t *, ibc_qp_hdl_t *);
static ibt_status_t tavor_ci_free_qp(ibc_hca_hdl_t, ibc_qp_hdl_t,
    ibc_free_qp_flags_t, ibc_qpn_hdl_t *);
static ibt_status_t tavor_ci_release_qpn(ibc_hca_hdl_t, ibc_qpn_hdl_t);
static ibt_status_t tavor_ci_query_qp(ibc_hca_hdl_t, ibc_qp_hdl_t,
    ibt_qp_query_attr_t *);
static ibt_status_t tavor_ci_modify_qp(ibc_hca_hdl_t, ibc_qp_hdl_t,
    ibt_cep_modify_flags_t, ibt_qp_info_t *, ibt_queue_sizes_t *);

/* Completion Queues */
static ibt_status_t tavor_ci_alloc_cq(ibc_hca_hdl_t, ibt_cq_hdl_t,
    ibt_cq_attr_t *, ibc_cq_hdl_t *, uint_t *);
static ibt_status_t tavor_ci_free_cq(ibc_hca_hdl_t, ibc_cq_hdl_t);
static ibt_status_t tavor_ci_query_cq(ibc_hca_hdl_t, ibc_cq_hdl_t, uint_t *,
    uint_t *, uint_t *, ibt_cq_handler_id_t *);
static ibt_status_t tavor_ci_resize_cq(ibc_hca_hdl_t, ibc_cq_hdl_t,
    uint_t, uint_t *);
static ibt_status_t tavor_ci_modify_cq(ibc_hca_hdl_t, ibc_cq_hdl_t,
    uint_t, uint_t, ibt_cq_handler_id_t);
static ibt_status_t tavor_ci_alloc_cq_sched(ibc_hca_hdl_t,
    ibt_cq_sched_attr_t *, ibc_sched_hdl_t *);
static ibt_status_t tavor_ci_free_cq_sched(ibc_hca_hdl_t, ibc_sched_hdl_t);

/* EE Contexts */
static ibt_status_t tavor_ci_alloc_eec(ibc_hca_hdl_t, ibc_eec_flags_t,
    ibt_eec_hdl_t, ibc_rdd_hdl_t, ibc_eec_hdl_t *);
static ibt_status_t tavor_ci_free_eec(ibc_hca_hdl_t, ibc_eec_hdl_t);
static ibt_status_t tavor_ci_query_eec(ibc_hca_hdl_t, ibc_eec_hdl_t,
    ibt_eec_query_attr_t *);
static ibt_status_t tavor_ci_modify_eec(ibc_hca_hdl_t, ibc_eec_hdl_t,
    ibt_cep_modify_flags_t, ibt_eec_info_t *);

/* Memory Registration */
static ibt_status_t tavor_ci_register_mr(ibc_hca_hdl_t, ibc_pd_hdl_t,
    ibt_mr_attr_t *, void *, ibc_mr_hdl_t *, ibt_mr_desc_t *);
static ibt_status_t tavor_ci_register_buf(ibc_hca_hdl_t, ibc_pd_hdl_t,
    ibt_smr_attr_t *, struct buf *, void *, ibt_mr_hdl_t *, ibt_mr_desc_t *);
static ibt_status_t tavor_ci_register_shared_mr(ibc_hca_hdl_t,
    ibc_mr_hdl_t, ibc_pd_hdl_t, ibt_smr_attr_t *, void *,
    ibc_mr_hdl_t *, ibt_mr_desc_t *);
static ibt_status_t tavor_ci_deregister_mr(ibc_hca_hdl_t, ibc_mr_hdl_t);
static ibt_status_t tavor_ci_query_mr(ibc_hca_hdl_t, ibc_mr_hdl_t,
    ibt_mr_query_attr_t *);
static ibt_status_t tavor_ci_reregister_mr(ibc_hca_hdl_t, ibc_mr_hdl_t,
    ibc_pd_hdl_t, ibt_mr_attr_t *, void *, ibc_mr_hdl_t *,
    ibt_mr_desc_t *);
static ibt_status_t tavor_ci_reregister_buf(ibc_hca_hdl_t, ibc_mr_hdl_t,
    ibc_pd_hdl_t, ibt_smr_attr_t *, struct buf *, void *, ibc_mr_hdl_t *,
    ibt_mr_desc_t *);
static ibt_status_t tavor_ci_sync_mr(ibc_hca_hdl_t, ibt_mr_sync_t *, size_t);
static ibt_status_t tavor_ci_register_dma_mr(ibc_hca_hdl_t, ibc_pd_hdl_t,
    ibt_dmr_attr_t *, void *, ibc_mr_hdl_t *, ibt_mr_desc_t *);

/* Memory Windows */
static ibt_status_t tavor_ci_alloc_mw(ibc_hca_hdl_t, ibc_pd_hdl_t,
    ibt_mw_flags_t, ibc_mw_hdl_t *, ibt_rkey_t *);
static ibt_status_t tavor_ci_free_mw(ibc_hca_hdl_t, ibc_mw_hdl_t);
static ibt_status_t tavor_ci_query_mw(ibc_hca_hdl_t, ibc_mw_hdl_t,
    ibt_mw_query_attr_t *);

/* Multicast Groups */
static ibt_status_t tavor_ci_attach_mcg(ibc_hca_hdl_t, ibc_qp_hdl_t,
    ib_gid_t, ib_lid_t);
static ibt_status_t tavor_ci_detach_mcg(ibc_hca_hdl_t, ibc_qp_hdl_t,
    ib_gid_t, ib_lid_t);

/* Work Request and Completion Processing */
static ibt_status_t tavor_ci_post_send(ibc_hca_hdl_t, ibc_qp_hdl_t,
    ibt_send_wr_t *, uint_t, uint_t *);
static ibt_status_t tavor_ci_post_recv(ibc_hca_hdl_t, ibc_qp_hdl_t,
    ibt_recv_wr_t *, uint_t, uint_t *);
static ibt_status_t tavor_ci_poll_cq(ibc_hca_hdl_t, ibc_cq_hdl_t,
    ibt_wc_t *, uint_t, uint_t *);
static ibt_status_t tavor_ci_notify_cq(ibc_hca_hdl_t, ibc_cq_hdl_t,
    ibt_cq_notify_flags_t);

/* CI Object Private Data */
static ibt_status_t tavor_ci_ci_data_in(ibc_hca_hdl_t, ibt_ci_data_flags_t,
    ibt_object_type_t, void *, void *, size_t);

/* CI Object Private Data */
static ibt_status_t tavor_ci_ci_data_out(ibc_hca_hdl_t, ibt_ci_data_flags_t,
    ibt_object_type_t, void *, void *, size_t);

/* Shared Receive Queues */
static ibt_status_t tavor_ci_alloc_srq(ibc_hca_hdl_t, ibt_srq_flags_t,
    ibt_srq_hdl_t, ibc_pd_hdl_t, ibt_srq_sizes_t *, ibc_srq_hdl_t *,
    ibt_srq_sizes_t *);
static ibt_status_t tavor_ci_free_srq(ibc_hca_hdl_t, ibc_srq_hdl_t);
static ibt_status_t tavor_ci_query_srq(ibc_hca_hdl_t, ibc_srq_hdl_t,
    ibc_pd_hdl_t *, ibt_srq_sizes_t *, uint_t *);
static ibt_status_t tavor_ci_modify_srq(ibc_hca_hdl_t, ibc_srq_hdl_t,
    ibt_srq_modify_flags_t, uint_t, uint_t, uint_t *);
static ibt_status_t tavor_ci_post_srq(ibc_hca_hdl_t, ibc_srq_hdl_t,
    ibt_recv_wr_t *, uint_t, uint_t *);

/* Address translation */
static ibt_status_t tavor_ci_map_mem_area(ibc_hca_hdl_t, ibt_va_attr_t *,
    void *, uint_t, ibt_reg_req_t *, ibc_ma_hdl_t *);
static ibt_status_t tavor_ci_unmap_mem_area(ibc_hca_hdl_t, ibc_ma_hdl_t);
static ibt_status_t tavor_ci_map_mem_iov(ibc_hca_hdl_t, ibt_iov_attr_t *,
    ibt_all_wr_t *, ibc_mi_hdl_t *);
static ibt_status_t tavor_ci_unmap_mem_iov(ibc_hca_hdl_t, ibc_mi_hdl_t);

/* Allocate L_Key */
static ibt_status_t tavor_ci_alloc_lkey(ibc_hca_hdl_t, ibc_pd_hdl_t,
    ibt_lkey_flags_t, uint_t, ibc_mr_hdl_t *, ibt_pmr_desc_t *);

/* Physical Register Memory Region */
static ibt_status_t tavor_ci_register_physical_mr(ibc_hca_hdl_t, ibc_pd_hdl_t,
    ibt_pmr_attr_t *, void *, ibc_mr_hdl_t *, ibt_pmr_desc_t *);
static ibt_status_t tavor_ci_reregister_physical_mr(ibc_hca_hdl_t,
    ibc_mr_hdl_t, ibc_pd_hdl_t, ibt_pmr_attr_t *, void *, ibc_mr_hdl_t *,
    ibt_pmr_desc_t *);

/* Mellanox FMR */
static ibt_status_t tavor_ci_create_fmr_pool(ibc_hca_hdl_t hca, ibc_pd_hdl_t pd,
    ibt_fmr_pool_attr_t *fmr_params, ibc_fmr_pool_hdl_t *fmr_pool);
static ibt_status_t tavor_ci_destroy_fmr_pool(ibc_hca_hdl_t hca,
    ibc_fmr_pool_hdl_t fmr_pool);
static ibt_status_t tavor_ci_flush_fmr_pool(ibc_hca_hdl_t hca,
    ibc_fmr_pool_hdl_t fmr_pool);
static ibt_status_t tavor_ci_register_physical_fmr(ibc_hca_hdl_t hca,
    ibc_fmr_pool_hdl_t fmr_pool, ibt_pmr_attr_t *mem_pattr,
    void *ibtl_reserved, ibc_mr_hdl_t *mr_hdl_p, ibt_pmr_desc_t *mem_desc_p);
static ibt_status_t tavor_ci_deregister_fmr(ibc_hca_hdl_t hca,
    ibc_mr_hdl_t mr);

static ibt_status_t tavor_ci_alloc_io_mem(ibc_hca_hdl_t, size_t,
    ibt_mr_flags_t, caddr_t *, ibc_mem_alloc_hdl_t *);
static ibt_status_t tavor_ci_free_io_mem(ibc_hca_hdl_t, ibc_mem_alloc_hdl_t);
static int tavor_mem_alloc(tavor_state_t *, size_t, ibt_mr_flags_t,
	caddr_t *, tavor_mem_alloc_hdl_t *);

static ibt_status_t tavor_ci_not_supported();

/*
 * This ibc_operations_t structure includes pointers to all the entry points
 * provided by the Tavor driver.  This structure is passed to the IBTF at
 * driver attach time, using the ibc_attach() call.
 */
ibc_operations_t tavor_ibc_ops = {
	/* HCA and port related operations */
	tavor_ci_query_hca_ports,
	tavor_ci_modify_ports,
	tavor_ci_modify_system_image,

	/* Protection Domains */
	tavor_ci_alloc_pd,
	tavor_ci_free_pd,

	/* Reliable Datagram Domains */
	tavor_ci_alloc_rdd,
	tavor_ci_free_rdd,

	/* Address Handles */
	tavor_ci_alloc_ah,
	tavor_ci_free_ah,
	tavor_ci_query_ah,
	tavor_ci_modify_ah,

	/* Queue Pairs */
	tavor_ci_alloc_qp,
	tavor_ci_alloc_special_qp,
	tavor_ci_alloc_qp_range,
	tavor_ci_free_qp,
	tavor_ci_release_qpn,
	tavor_ci_query_qp,
	tavor_ci_modify_qp,

	/* Completion Queues */
	tavor_ci_alloc_cq,
	tavor_ci_free_cq,
	tavor_ci_query_cq,
	tavor_ci_resize_cq,
	tavor_ci_modify_cq,
	tavor_ci_alloc_cq_sched,
	tavor_ci_free_cq_sched,
	tavor_ci_not_supported,	/* query_cq_handler_id */

	/* EE Contexts */
	tavor_ci_alloc_eec,
	tavor_ci_free_eec,
	tavor_ci_query_eec,
	tavor_ci_modify_eec,

	/* Memory Registration */
	tavor_ci_register_mr,
	tavor_ci_register_buf,
	tavor_ci_register_shared_mr,
	tavor_ci_deregister_mr,
	tavor_ci_query_mr,
	tavor_ci_reregister_mr,
	tavor_ci_reregister_buf,
	tavor_ci_sync_mr,

	/* Memory Windows */
	tavor_ci_alloc_mw,
	tavor_ci_free_mw,
	tavor_ci_query_mw,

	/* Multicast Groups */
	tavor_ci_attach_mcg,
	tavor_ci_detach_mcg,

	/* Work Request and Completion Processing */
	tavor_ci_post_send,
	tavor_ci_post_recv,
	tavor_ci_poll_cq,
	tavor_ci_notify_cq,

	/* CI Object Mapping Data */
	tavor_ci_ci_data_in,
	tavor_ci_ci_data_out,

	/* Shared Receive Queue */
	tavor_ci_alloc_srq,
	tavor_ci_free_srq,
	tavor_ci_query_srq,
	tavor_ci_modify_srq,
	tavor_ci_post_srq,

	/* Address translation */
	tavor_ci_map_mem_area,
	tavor_ci_unmap_mem_area,
	tavor_ci_map_mem_iov,
	tavor_ci_unmap_mem_iov,

	/* Allocate L_key */
	tavor_ci_alloc_lkey,

	/* Physical Register Memory Region */
	tavor_ci_register_physical_mr,
	tavor_ci_reregister_physical_mr,

	/* Mellanox FMR */
	tavor_ci_create_fmr_pool,
	tavor_ci_destroy_fmr_pool,
	tavor_ci_flush_fmr_pool,
	tavor_ci_register_physical_fmr,
	tavor_ci_deregister_fmr,

	/* dmable memory */
	tavor_ci_alloc_io_mem,
	tavor_ci_free_io_mem,

	/* XRC not yet supported */
	tavor_ci_not_supported,	/* ibc_alloc_xrc_domain */
	tavor_ci_not_supported,	/* ibc_free_xrc_domain */
	tavor_ci_not_supported,	/* ibc_alloc_xrc_srq */
	tavor_ci_not_supported,	/* ibc_free_xrc_srq */
	tavor_ci_not_supported,	/* ibc_query_xrc_srq */
	tavor_ci_not_supported,	/* ibc_modify_xrc_srq */
	tavor_ci_not_supported,	/* ibc_alloc_xrc_tgt_qp */
	tavor_ci_not_supported,	/* ibc_free_xrc_tgt_qp */
	tavor_ci_not_supported,	/* ibc_query_xrc_tgt_qp */
	tavor_ci_not_supported,	/* ibc_modify_xrc_tgt_qp */

	/* Memory Region (physical) */
	tavor_ci_register_dma_mr,

	/* Next enhancements */
	tavor_ci_not_supported,	/* ibc_enhancement1 */
	tavor_ci_not_supported,	/* ibc_enhancement2 */
	tavor_ci_not_supported,	/* ibc_enhancement3 */
	tavor_ci_not_supported,	/* ibc_enhancement4 */
};

/*
 * Not yet implemented OPS
 */
/* ARGSUSED */
static ibt_status_t
tavor_ci_not_supported()
{
	return (IBT_NOT_SUPPORTED);
}


/*
 * tavor_ci_query_hca_ports()
 *    Returns HCA port attributes for either one or all of the HCA's ports.
 *    Context: Can be called only from user or kernel context.
 */
static ibt_status_t
tavor_ci_query_hca_ports(ibc_hca_hdl_t hca, uint8_t query_port,
    ibt_hca_portinfo_t *info_p)
{
	tavor_state_t	*state;
	uint_t		start, end, port;
	int		status, indx;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Grab the Tavor softstate pointer */
	state = (tavor_state_t *)hca;

	/*
	 * If the specified port is zero, then we are supposed to query all
	 * ports.  Otherwise, we query only the port number specified.
	 * Setup the start and end port numbers as appropriate for the loop
	 * below.  Note:  The first Tavor port is port number one (1).
	 */
	if (query_port == 0) {
		start = 1;
		end = start + (state->ts_cfg_profile->cp_num_ports - 1);
	} else {
		end = start = query_port;
	}

	/* Query the port(s) */
	for (port = start, indx = 0; port <= end; port++, indx++) {
		status = tavor_port_query(state, port, &info_p[indx]);
		if (status != DDI_SUCCESS) {
			return (status);
		}
	}

	return (IBT_SUCCESS);
}


/*
 * tavor_ci_modify_ports()
 *    Modify HCA port attributes
 *    Context: Can be called only from user or kernel context.
 */
static ibt_status_t
tavor_ci_modify_ports(ibc_hca_hdl_t hca, uint8_t port,
    ibt_port_modify_flags_t flags, uint8_t init_type)
{
	tavor_state_t	*state;
	int		status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Grab the Tavor softstate pointer */
	state = (tavor_state_t *)hca;

	/* Modify the port(s) */
	status = tavor_port_modify(state, port, flags, init_type);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	return (IBT_SUCCESS);
}

/*
 * tavor_ci_modify_system_image()
 *    Modify the System Image GUID
 *    Context: Can be called only from user or kernel context.
 */
/* ARGSUSED */
static ibt_status_t
tavor_ci_modify_system_image(ibc_hca_hdl_t hca, ib_guid_t sys_guid)
{
	/*
	 * This is an unsupported interface for the Tavor driver.  This
	 * interface is necessary to support modification of the System
	 * Image GUID.  Tavor is only capable of modifying this parameter
	 * once (during driver initialization).
	 */

	return (IBT_NOT_SUPPORTED);
}

/*
 * tavor_ci_alloc_pd()
 *    Allocate a Protection Domain
 *    Context: Can be called only from user or kernel context.
 */
/* ARGSUSED */
static ibt_status_t
tavor_ci_alloc_pd(ibc_hca_hdl_t hca, ibt_pd_flags_t flags, ibc_pd_hdl_t *pd_p)
{
	tavor_state_t	*state;
	tavor_pdhdl_t	pdhdl;
	int		status;

	ASSERT(pd_p != NULL);

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Grab the Tavor softstate pointer */
	state = (tavor_state_t *)hca;

	/* Allocate the PD */
	status = tavor_pd_alloc(state, &pdhdl, TAVOR_NOSLEEP);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	/* Return the Tavor PD handle */
	*pd_p = (ibc_pd_hdl_t)pdhdl;

	return (IBT_SUCCESS);
}


/*
 * tavor_ci_free_pd()
 *    Free a Protection Domain
 *    Context: Can be called only from user or kernel context
 */
static ibt_status_t
tavor_ci_free_pd(ibc_hca_hdl_t hca, ibc_pd_hdl_t pd)
{
	tavor_state_t		*state;
	tavor_pdhdl_t		pdhdl;
	int			status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid PD handle pointer */
	if (pd == NULL) {
		return (IBT_PD_HDL_INVALID);
	}

	/* Grab the Tavor softstate pointer and PD handle */
	state = (tavor_state_t *)hca;
	pdhdl = (tavor_pdhdl_t)pd;

	/* Free the PD */
	status = tavor_pd_free(state, &pdhdl);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	return (IBT_SUCCESS);
}


/*
 * tavor_ci_alloc_rdd()
 *    Allocate a Reliable Datagram Domain
 *    Context: Can be called only from user or kernel context.
 */
/* ARGSUSED */
static ibt_status_t
tavor_ci_alloc_rdd(ibc_hca_hdl_t hca, ibc_rdd_flags_t flags,
    ibc_rdd_hdl_t *rdd_p)
{
	/*
	 * This is an unsupported interface for the Tavor driver.  This
	 * interface is necessary to support Reliable Datagram (RD)
	 * operations.  Tavor does not support RD.
	 */

	return (IBT_NOT_SUPPORTED);
}


/*
 * tavor_free_rdd()
 *    Free a Reliable Datagram Domain
 *    Context: Can be called only from user or kernel context.
 */
/* ARGSUSED */
static ibt_status_t
tavor_ci_free_rdd(ibc_hca_hdl_t hca, ibc_rdd_hdl_t rdd)
{
	/*
	 * This is an unsupported interface for the Tavor driver.  This
	 * interface is necessary to support Reliable Datagram (RD)
	 * operations.  Tavor does not support RD.
	 */

	return (IBT_NOT_SUPPORTED);
}


/*
 * tavor_ci_alloc_ah()
 *    Allocate an Address Handle
 *    Context: Can be called only from user or kernel context.
 */
/* ARGSUSED */
static ibt_status_t
tavor_ci_alloc_ah(ibc_hca_hdl_t hca, ibt_ah_flags_t flags, ibc_pd_hdl_t pd,
    ibt_adds_vect_t *attr_p, ibc_ah_hdl_t *ah_p)
{
	tavor_state_t	*state;
	tavor_ahhdl_t	ahhdl;
	tavor_pdhdl_t	pdhdl;
	int		status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid PD handle pointer */
	if (pd == NULL) {
		return (IBT_PD_HDL_INVALID);
	}

	/* Grab the Tavor softstate pointer and PD handle */
	state = (tavor_state_t *)hca;
	pdhdl = (tavor_pdhdl_t)pd;

	/* Allocate the AH */
	status = tavor_ah_alloc(state, pdhdl, attr_p, &ahhdl, TAVOR_NOSLEEP);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	/* Return the Tavor AH handle */
	*ah_p = (ibc_ah_hdl_t)ahhdl;

	return (IBT_SUCCESS);
}


/*
 * tavor_ci_free_ah()
 *    Free an Address Handle
 *    Context: Can be called only from user or kernel context.
 */
static ibt_status_t
tavor_ci_free_ah(ibc_hca_hdl_t hca, ibc_ah_hdl_t ah)
{
	tavor_state_t	*state;
	tavor_ahhdl_t	ahhdl;
	int		status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid address handle pointer */
	if (ah == NULL) {
		return (IBT_AH_HDL_INVALID);
	}

	/* Grab the Tavor softstate pointer and AH handle */
	state = (tavor_state_t *)hca;
	ahhdl = (tavor_ahhdl_t)ah;

	/* Free the AH */
	status = tavor_ah_free(state, &ahhdl, TAVOR_NOSLEEP);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	return (IBT_SUCCESS);
}


/*
 * tavor_ci_query_ah()
 *    Return the Address Vector information for a specified Address Handle
 *    Context: Can be called from interrupt or base context.
 */
static ibt_status_t
tavor_ci_query_ah(ibc_hca_hdl_t hca, ibc_ah_hdl_t ah, ibc_pd_hdl_t *pd_p,
    ibt_adds_vect_t *attr_p)
{
	tavor_state_t	*state;
	tavor_ahhdl_t	ahhdl;
	tavor_pdhdl_t	pdhdl;
	int		status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid address handle pointer */
	if (ah == NULL) {
		return (IBT_AH_HDL_INVALID);
	}

	/* Grab the Tavor softstate pointer and AH handle */
	state = (tavor_state_t *)hca;
	ahhdl = (tavor_ahhdl_t)ah;

	/* Query the AH */
	status = tavor_ah_query(state, ahhdl, &pdhdl, attr_p);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	/* Return the Tavor PD handle */
	*pd_p = (ibc_pd_hdl_t)pdhdl;

	return (IBT_SUCCESS);
}


/*
 * tavor_ci_modify_ah()
 *    Modify the Address Vector information of a specified Address Handle
 *    Context: Can be called from interrupt or base context.
 */
static ibt_status_t
tavor_ci_modify_ah(ibc_hca_hdl_t hca, ibc_ah_hdl_t ah, ibt_adds_vect_t *attr_p)
{
	tavor_state_t	*state;
	tavor_ahhdl_t	ahhdl;
	int		status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid address handle pointer */
	if (ah == NULL) {
		return (IBT_AH_HDL_INVALID);
	}

	/* Grab the Tavor softstate pointer and AH handle */
	state = (tavor_state_t *)hca;
	ahhdl = (tavor_ahhdl_t)ah;

	/* Modify the AH */
	status = tavor_ah_modify(state, ahhdl, attr_p);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	return (IBT_SUCCESS);
}


/*
 * tavor_ci_alloc_qp()
 *    Allocate a Queue Pair
 *    Context: Can be called only from user or kernel context.
 */
static ibt_status_t
tavor_ci_alloc_qp(ibc_hca_hdl_t hca, ibtl_qp_hdl_t ibt_qphdl,
    ibt_qp_type_t type, ibt_qp_alloc_attr_t *attr_p,
    ibt_chan_sizes_t *queue_sizes_p, ib_qpn_t *qpn, ibc_qp_hdl_t *qp_p)
{
	tavor_state_t		*state;
	tavor_qp_info_t		qpinfo;
	tavor_qp_options_t	op;
	int			status;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*attr_p))
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*queue_sizes_p))

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Grab the Tavor softstate pointer */
	state = (tavor_state_t *)hca;

	/* Allocate the QP */
	qpinfo.qpi_attrp	= attr_p;
	qpinfo.qpi_type		= type;
	qpinfo.qpi_ibt_qphdl	= ibt_qphdl;
	qpinfo.qpi_queueszp	= queue_sizes_p;
	qpinfo.qpi_qpn		= qpn;
	op.qpo_wq_loc		= state->ts_cfg_profile->cp_qp_wq_inddr;
	status = tavor_qp_alloc(state, &qpinfo, TAVOR_NOSLEEP, &op);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	/* Return the Tavor QP handle */
	*qp_p = (ibc_qp_hdl_t)qpinfo.qpi_qphdl;

	return (IBT_SUCCESS);
}


/*
 * tavor_ci_alloc_special_qp()
 *    Allocate a Special Queue Pair
 *    Context: Can be called only from user or kernel context.
 */
static ibt_status_t
tavor_ci_alloc_special_qp(ibc_hca_hdl_t hca, uint8_t port,
    ibtl_qp_hdl_t ibt_qphdl, ibt_sqp_type_t type,
    ibt_qp_alloc_attr_t *attr_p, ibt_chan_sizes_t *queue_sizes_p,
    ibc_qp_hdl_t *qp_p)
{
	tavor_state_t		*state;
	tavor_qp_info_t		qpinfo;
	tavor_qp_options_t	op;
	int			status;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*attr_p))
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*queue_sizes_p))

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Grab the Tavor softstate pointer */
	state = (tavor_state_t *)hca;

	/* Allocate the Special QP */
	qpinfo.qpi_attrp	= attr_p;
	qpinfo.qpi_type		= type;
	qpinfo.qpi_port		= port;
	qpinfo.qpi_ibt_qphdl	= ibt_qphdl;
	qpinfo.qpi_queueszp	= queue_sizes_p;
	op.qpo_wq_loc		= state->ts_cfg_profile->cp_qp_wq_inddr;
	status = tavor_special_qp_alloc(state, &qpinfo, TAVOR_NOSLEEP, &op);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	/* Return the Tavor QP handle */
	*qp_p = (ibc_qp_hdl_t)qpinfo.qpi_qphdl;

	return (IBT_SUCCESS);
}


/* ARGSUSED */
static ibt_status_t
tavor_ci_alloc_qp_range(ibc_hca_hdl_t hca, uint_t log2,
    ibtl_qp_hdl_t *ibtl_qp_p, ibt_qp_type_t type,
    ibt_qp_alloc_attr_t *attr_p, ibt_chan_sizes_t *queue_sizes_p,
    ibc_cq_hdl_t *send_cq_p, ibc_cq_hdl_t *recv_cq_p,
    ib_qpn_t *qpn_p, ibc_qp_hdl_t *qp_p)
{
	return (IBT_NOT_SUPPORTED);
}

/*
 * tavor_ci_free_qp()
 *    Free a Queue Pair
 *    Context: Can be called only from user or kernel context.
 */
static ibt_status_t
tavor_ci_free_qp(ibc_hca_hdl_t hca, ibc_qp_hdl_t qp,
    ibc_free_qp_flags_t free_qp_flags, ibc_qpn_hdl_t *qpnh_p)
{
	tavor_state_t	*state;
	tavor_qphdl_t	qphdl;
	int		status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid QP handle pointer */
	if (qp == NULL) {
		return (IBT_QP_HDL_INVALID);
	}

	/* Grab the Tavor softstate pointer and QP handle */
	state = (tavor_state_t *)hca;
	qphdl = (tavor_qphdl_t)qp;

	/* Free the QP */
	status = tavor_qp_free(state, &qphdl, free_qp_flags, qpnh_p,
	    TAVOR_NOSLEEP);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	return (IBT_SUCCESS);
}


/*
 * tavor_ci_release_qpn()
 *    Release a Queue Pair Number (QPN)
 *    Context: Can be called only from user or kernel context.
 */
static ibt_status_t
tavor_ci_release_qpn(ibc_hca_hdl_t hca, ibc_qpn_hdl_t qpnh)
{
	tavor_state_t		*state;
	tavor_qpn_entry_t	*entry;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid QP handle pointer */
	if (qpnh == NULL) {
		return (IBT_QP_HDL_INVALID);
	}

	/* Grab the Tavor softstate pointer and QP handle */
	state = (tavor_state_t *)hca;
	entry = (tavor_qpn_entry_t *)qpnh;

	/* Release the QP number */
	tavor_qp_release_qpn(state, entry, TAVOR_QPN_RELEASE);

	return (IBT_SUCCESS);
}


/*
 * tavor_ci_query_qp()
 *    Query a Queue Pair
 *    Context: Can be called from interrupt or base context.
 */
static ibt_status_t
tavor_ci_query_qp(ibc_hca_hdl_t hca, ibc_qp_hdl_t qp,
    ibt_qp_query_attr_t *attr_p)
{
	tavor_state_t	*state;
	tavor_qphdl_t	qphdl;
	int		status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid QP handle */
	if (qp == NULL) {
		return (IBT_QP_HDL_INVALID);
	}

	/* Grab the Tavor softstate pointer and QP handle */
	state = (tavor_state_t *)hca;
	qphdl = (tavor_qphdl_t)qp;

	/* Query the QP */
	status = tavor_qp_query(state, qphdl, attr_p);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	return (IBT_SUCCESS);
}


/*
 * tavor_ci_modify_qp()
 *    Modify a Queue Pair
 *    Context: Can be called from interrupt or base context.
 */
static ibt_status_t
tavor_ci_modify_qp(ibc_hca_hdl_t hca, ibc_qp_hdl_t qp,
    ibt_cep_modify_flags_t flags, ibt_qp_info_t *info_p,
    ibt_queue_sizes_t *actual_sz)
{
	tavor_state_t	*state;
	tavor_qphdl_t	qphdl;
	int		status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid QP handle */
	if (qp == NULL) {
		return (IBT_QP_HDL_INVALID);
	}

	/* Grab the Tavor softstate pointer and QP handle */
	state = (tavor_state_t *)hca;
	qphdl = (tavor_qphdl_t)qp;

	/* Modify the QP */
	status = tavor_qp_modify(state, qphdl, flags, info_p, actual_sz);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	return (IBT_SUCCESS);
}


/*
 * tavor_ci_alloc_cq()
 *    Allocate a Completion Queue
 *    Context: Can be called only from user or kernel context.
 */
/* ARGSUSED */
static ibt_status_t
tavor_ci_alloc_cq(ibc_hca_hdl_t hca, ibt_cq_hdl_t ibt_cqhdl,
    ibt_cq_attr_t *attr_p, ibc_cq_hdl_t *cq_p, uint_t *actual_size)
{
	tavor_state_t	*state;
	tavor_cqhdl_t	cqhdl;
	int		status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Grab the Tavor softstate pointer */
	state = (tavor_state_t *)hca;

	/* Allocate the CQ */
	status = tavor_cq_alloc(state, ibt_cqhdl, attr_p, actual_size,
	    &cqhdl, TAVOR_NOSLEEP);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	/* Return the Tavor CQ handle */
	*cq_p = (ibc_cq_hdl_t)cqhdl;

	return (IBT_SUCCESS);
}


/*
 * tavor_ci_free_cq()
 *    Free a Completion Queue
 *    Context: Can be called only from user or kernel context.
 */
static ibt_status_t
tavor_ci_free_cq(ibc_hca_hdl_t hca, ibc_cq_hdl_t cq)
{
	tavor_state_t	*state;
	tavor_cqhdl_t	cqhdl;
	int		status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid CQ handle pointer */
	if (cq == NULL) {
		return (IBT_CQ_HDL_INVALID);
	}

	/* Grab the Tavor softstate pointer and CQ handle */
	state = (tavor_state_t *)hca;
	cqhdl = (tavor_cqhdl_t)cq;

	/* Free the CQ */
	status = tavor_cq_free(state, &cqhdl, TAVOR_NOSLEEP);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	return (IBT_SUCCESS);
}


/*
 * tavor_ci_query_cq()
 *    Return the size of a Completion Queue
 *    Context: Can be called only from user or kernel context.
 */
static ibt_status_t
tavor_ci_query_cq(ibc_hca_hdl_t hca, ibc_cq_hdl_t cq, uint_t *entries_p,
    uint_t *count_p, uint_t *usec_p, ibt_cq_handler_id_t *hid_p)
{
	tavor_cqhdl_t	cqhdl;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid CQ handle pointer */
	if (cq == NULL) {
		return (IBT_CQ_HDL_INVALID);
	}

	/* Grab the CQ handle */
	cqhdl = (tavor_cqhdl_t)cq;

	/* Query the current CQ size */
	*entries_p = cqhdl->cq_bufsz;

	/* interrupt moderation is not supported */
	*count_p = 0;
	*usec_p = 0;
	*hid_p = 0;

	return (IBT_SUCCESS);
}


/*
 * tavor_ci_resize_cq()
 *    Change the size of a Completion Queue
 *    Context: Can be called only from user or kernel context.
 */
static ibt_status_t
tavor_ci_resize_cq(ibc_hca_hdl_t hca, ibc_cq_hdl_t cq, uint_t size,
    uint_t *actual_size)
{
	tavor_state_t		*state;
	tavor_cqhdl_t		cqhdl;
	int			status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid CQ handle pointer */
	if (cq == NULL) {
		return (IBT_CQ_HDL_INVALID);
	}

	/* Grab the Tavor softstate pointer and CQ handle */
	state = (tavor_state_t *)hca;
	cqhdl = (tavor_cqhdl_t)cq;

	/* Resize the CQ */
	status = tavor_cq_resize(state, cqhdl, size, actual_size,
	    TAVOR_NOSLEEP);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	return (IBT_SUCCESS);
}

/*
 * CQ interrupt moderation is not supported in tavor.
 */

/* ARGSUSED */
static ibt_status_t
tavor_ci_modify_cq(ibc_hca_hdl_t hca, ibc_cq_hdl_t cq,
    uint_t count, uint_t usec, ibt_cq_handler_id_t hid)
{
	return (IBT_NOT_SUPPORTED);
}

/*
 * tavor_ci_alloc_cq_sched()
 *    Reserve a CQ scheduling class resource
 *    Context: Can be called only from user or kernel context.
 */
/* ARGSUSED */
static ibt_status_t
tavor_ci_alloc_cq_sched(ibc_hca_hdl_t hca, ibt_cq_sched_attr_t *attr,
    ibc_sched_hdl_t *sched_hdl_p)
{
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}
	*sched_hdl_p = NULL;

	/*
	 * This is an unsupported interface for the Tavor driver.  Tavor
	 * does not support CQ scheduling classes.
	 */
	return (IBT_SUCCESS);
}


/*
 * tavor_ci_free_cq_sched()
 *    Free a CQ scheduling class resource
 *    Context: Can be called only from user or kernel context.
 */
/* ARGSUSED */
static ibt_status_t
tavor_ci_free_cq_sched(ibc_hca_hdl_t hca, ibc_sched_hdl_t sched_hdl)
{
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/*
	 * This is an unsupported interface for the Tavor driver.  Tavor
	 * does not support CQ scheduling classes.
	 */
	return (IBT_SUCCESS);
}


/*
 * tavor_ci_alloc_eec()
 *    Allocate an End-to-End context
 *    Context: Can be called only from user or kernel context.
 */
/* ARGSUSED */
static ibt_status_t
tavor_ci_alloc_eec(ibc_hca_hdl_t hca, ibc_eec_flags_t flags,
    ibt_eec_hdl_t ibt_eec, ibc_rdd_hdl_t rdd, ibc_eec_hdl_t *eec_p)
{
	/*
	 * This is an unsupported interface for the Tavor driver.  This
	 * interface is necessary to support Reliable Datagram (RD)
	 * operations.  Tavor does not support RD.
	 */

	return (IBT_NOT_SUPPORTED);
}


/*
 * tavor_ci_free_eec()
 *    Free an End-to-End context
 *    Context: Can be called only from user or kernel context.
 */
/* ARGSUSED */
static ibt_status_t
tavor_ci_free_eec(ibc_hca_hdl_t hca, ibc_eec_hdl_t eec)
{
	/*
	 * This is an unsupported interface for the Tavor driver.  This
	 * interface is necessary to support Reliable Datagram (RD)
	 * operations.  Tavor does not support RD.
	 */

	return (IBT_NOT_SUPPORTED);
}


/*
 * tavor_ci_query_eec()
 *    Query an End-to-End context
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static ibt_status_t
tavor_ci_query_eec(ibc_hca_hdl_t hca, ibc_eec_hdl_t eec,
    ibt_eec_query_attr_t *attr_p)
{
	/*
	 * This is an unsupported interface for the Tavor driver.  This
	 * interface is necessary to support Reliable Datagram (RD)
	 * operations.  Tavor does not support RD.
	 */

	return (IBT_NOT_SUPPORTED);
}


/*
 * tavor_ci_modify_eec()
 *    Modify an End-to-End context
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static ibt_status_t
tavor_ci_modify_eec(ibc_hca_hdl_t hca, ibc_eec_hdl_t eec,
    ibt_cep_modify_flags_t flags, ibt_eec_info_t *info_p)
{
	/*
	 * This is an unsupported interface for the Tavor driver.  This
	 * interface is necessary to support Reliable Datagram (RD)
	 * operations.  Tavor does not support RD.
	 */

	return (IBT_NOT_SUPPORTED);
}


/*
 * tavor_ci_register_mr()
 *    Prepare a virtually addressed Memory Region for use by an HCA
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static ibt_status_t
tavor_ci_register_mr(ibc_hca_hdl_t hca, ibc_pd_hdl_t pd,
    ibt_mr_attr_t *mr_attr, void *ibtl_reserved, ibc_mr_hdl_t *mr_p,
    ibt_mr_desc_t *mr_desc)
{
	tavor_mr_options_t	op;
	tavor_state_t		*state;
	tavor_pdhdl_t		pdhdl;
	tavor_mrhdl_t		mrhdl;
	int			status;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mr_desc))

	ASSERT(mr_attr != NULL);
	ASSERT(mr_p != NULL);
	ASSERT(mr_desc != NULL);

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid PD handle pointer */
	if (pd == NULL) {
		return (IBT_PD_HDL_INVALID);
	}

	/*
	 * Validate the access flags.  Both Remote Write and Remote Atomic
	 * require the Local Write flag to be set
	 */
	if (((mr_attr->mr_flags & IBT_MR_ENABLE_REMOTE_WRITE) ||
	    (mr_attr->mr_flags & IBT_MR_ENABLE_REMOTE_ATOMIC)) &&
	    !(mr_attr->mr_flags & IBT_MR_ENABLE_LOCAL_WRITE)) {
		return (IBT_MR_ACCESS_REQ_INVALID);
	}

	/* Grab the Tavor softstate pointer and PD handle */
	state = (tavor_state_t *)hca;
	pdhdl = (tavor_pdhdl_t)pd;

	/* Register the memory region */
	op.mro_bind_type   = state->ts_cfg_profile->cp_iommu_bypass;
	op.mro_bind_dmahdl = NULL;
	op.mro_bind_override_addr = 0;
	status = tavor_mr_register(state, pdhdl, mr_attr, &mrhdl, &op);
	if (status != DDI_SUCCESS) {
		return (status);
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mrhdl))

	/* Fill in the mr_desc structure */
	mr_desc->md_vaddr = mrhdl->mr_bindinfo.bi_addr;
	mr_desc->md_lkey  = mrhdl->mr_lkey;
	/* Only set RKey if remote access was requested */
	if ((mr_attr->mr_flags & IBT_MR_ENABLE_REMOTE_ATOMIC) ||
	    (mr_attr->mr_flags & IBT_MR_ENABLE_REMOTE_WRITE) ||
	    (mr_attr->mr_flags & IBT_MR_ENABLE_REMOTE_READ)) {
		mr_desc->md_rkey = mrhdl->mr_rkey;
	}

	/*
	 * If region is mapped for streaming (i.e. noncoherent), then set
	 * sync is required
	 */
	mr_desc->md_sync_required = (mrhdl->mr_bindinfo.bi_flags &
	    IBT_MR_NONCOHERENT) ? B_TRUE : B_FALSE;

	/* Return the Tavor MR handle */
	*mr_p = (ibc_mr_hdl_t)mrhdl;

	return (IBT_SUCCESS);
}


/*
 * tavor_ci_register_buf()
 *    Prepare a Memory Region specified by buf structure for use by an HCA
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static ibt_status_t
tavor_ci_register_buf(ibc_hca_hdl_t hca, ibc_pd_hdl_t pd,
    ibt_smr_attr_t *attrp, struct buf *buf, void *ibtl_reserved,
    ibt_mr_hdl_t *mr_p, ibt_mr_desc_t *mr_desc)
{
	tavor_mr_options_t	op;
	tavor_state_t		*state;
	tavor_pdhdl_t		pdhdl;
	tavor_mrhdl_t		mrhdl;
	int			status;
	ibt_mr_flags_t		flags = attrp->mr_flags;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mr_desc))

	ASSERT(mr_p != NULL);
	ASSERT(mr_desc != NULL);

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid PD handle pointer */
	if (pd == NULL) {
		return (IBT_PD_HDL_INVALID);
	}

	/*
	 * Validate the access flags.  Both Remote Write and Remote Atomic
	 * require the Local Write flag to be set
	 */
	if (((flags & IBT_MR_ENABLE_REMOTE_WRITE) ||
	    (flags & IBT_MR_ENABLE_REMOTE_ATOMIC)) &&
	    !(flags & IBT_MR_ENABLE_LOCAL_WRITE)) {
		return (IBT_MR_ACCESS_REQ_INVALID);
	}

	/* Grab the Tavor softstate pointer and PD handle */
	state = (tavor_state_t *)hca;
	pdhdl = (tavor_pdhdl_t)pd;

	/* Register the memory region */
	op.mro_bind_type   = state->ts_cfg_profile->cp_iommu_bypass;
	op.mro_bind_dmahdl = NULL;
	op.mro_bind_override_addr = 0;
	status = tavor_mr_register_buf(state, pdhdl, attrp, buf, &mrhdl, &op);
	if (status != DDI_SUCCESS) {
		return (status);
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mrhdl))

	/* Fill in the mr_desc structure */
	mr_desc->md_vaddr = mrhdl->mr_bindinfo.bi_addr;
	mr_desc->md_lkey  = mrhdl->mr_lkey;
	/* Only set RKey if remote access was requested */
	if ((flags & IBT_MR_ENABLE_REMOTE_ATOMIC) ||
	    (flags & IBT_MR_ENABLE_REMOTE_WRITE) ||
	    (flags & IBT_MR_ENABLE_REMOTE_READ)) {
		mr_desc->md_rkey = mrhdl->mr_rkey;
	}

	/*
	 * If region is mapped for streaming (i.e. noncoherent), then set
	 * sync is required
	 */
	mr_desc->md_sync_required = (mrhdl->mr_bindinfo.bi_flags &
	    IBT_MR_NONCOHERENT) ? B_TRUE : B_FALSE;

	/* Return the Tavor MR handle */
	*mr_p = (ibc_mr_hdl_t)mrhdl;

	return (IBT_SUCCESS);
}


/*
 * tavor_ci_deregister_mr()
 *    Deregister a Memory Region from an HCA translation table
 *    Context: Can be called only from user or kernel context.
 */
static ibt_status_t
tavor_ci_deregister_mr(ibc_hca_hdl_t hca, ibc_mr_hdl_t mr)
{
	tavor_state_t		*state;
	tavor_mrhdl_t		mrhdl;
	int			status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid memory region handle */
	if (mr == NULL) {
		return (IBT_MR_HDL_INVALID);
	}

	/* Grab the Tavor softstate pointer */
	state = (tavor_state_t *)hca;
	mrhdl = (tavor_mrhdl_t)mr;

	/*
	 * Deregister the memory region.
	 */
	status = tavor_mr_deregister(state, &mrhdl, TAVOR_MR_DEREG_ALL,
	    TAVOR_NOSLEEP);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	return (IBT_SUCCESS);
}


/*
 * tavor_ci_query_mr()
 *    Retrieve information about a specified Memory Region
 *    Context: Can be called from interrupt or base context.
 */
static ibt_status_t
tavor_ci_query_mr(ibc_hca_hdl_t hca, ibc_mr_hdl_t mr,
    ibt_mr_query_attr_t *mr_attr)
{
	tavor_state_t		*state;
	tavor_mrhdl_t		mrhdl;
	int			status;

	ASSERT(mr_attr != NULL);

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for MemRegion handle */
	if (mr == NULL) {
		return (IBT_MR_HDL_INVALID);
	}

	/* Grab the Tavor softstate pointer and MR handle */
	state = (tavor_state_t *)hca;
	mrhdl = (tavor_mrhdl_t)mr;

	/* Query the memory region */
	status = tavor_mr_query(state, mrhdl, mr_attr);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	return (IBT_SUCCESS);
}


/*
 * tavor_ci_register_shared_mr()
 *    Create a shared memory region matching an existing Memory Region
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static ibt_status_t
tavor_ci_register_shared_mr(ibc_hca_hdl_t hca, ibc_mr_hdl_t mr,
    ibc_pd_hdl_t pd, ibt_smr_attr_t *mr_attr, void *ibtl_reserved,
    ibc_mr_hdl_t *mr_p, ibt_mr_desc_t *mr_desc)
{
	tavor_state_t		*state;
	tavor_pdhdl_t		pdhdl;
	tavor_mrhdl_t		mrhdl, mrhdl_new;
	int			status;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mr_desc))

	ASSERT(mr_attr != NULL);
	ASSERT(mr_p != NULL);
	ASSERT(mr_desc != NULL);

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid PD handle pointer */
	if (pd == NULL) {
		return (IBT_PD_HDL_INVALID);
	}

	/* Check for valid memory region handle */
	if (mr == NULL) {
		return (IBT_MR_HDL_INVALID);
	}
	/*
	 * Validate the access flags.  Both Remote Write and Remote Atomic
	 * require the Local Write flag to be set
	 */
	if (((mr_attr->mr_flags & IBT_MR_ENABLE_REMOTE_WRITE) ||
	    (mr_attr->mr_flags & IBT_MR_ENABLE_REMOTE_ATOMIC)) &&
	    !(mr_attr->mr_flags & IBT_MR_ENABLE_LOCAL_WRITE)) {
		return (IBT_MR_ACCESS_REQ_INVALID);
	}

	/* Grab the Tavor softstate pointer and handles */
	state = (tavor_state_t *)hca;
	pdhdl = (tavor_pdhdl_t)pd;
	mrhdl = (tavor_mrhdl_t)mr;

	/* Register the shared memory region */
	status = tavor_mr_register_shared(state, mrhdl, pdhdl, mr_attr,
	    &mrhdl_new);
	if (status != DDI_SUCCESS) {
		return (status);
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mrhdl_new))

	/* Fill in the mr_desc structure */
	mr_desc->md_vaddr = mrhdl_new->mr_bindinfo.bi_addr;
	mr_desc->md_lkey  = mrhdl_new->mr_lkey;
	/* Only set RKey if remote access was requested */
	if ((mr_attr->mr_flags & IBT_MR_ENABLE_REMOTE_ATOMIC) ||
	    (mr_attr->mr_flags & IBT_MR_ENABLE_REMOTE_WRITE) ||
	    (mr_attr->mr_flags & IBT_MR_ENABLE_REMOTE_READ)) {
		mr_desc->md_rkey = mrhdl_new->mr_rkey;
	}

	/*
	 * If shared region is mapped for streaming (i.e. noncoherent), then
	 * set sync is required
	 */
	mr_desc->md_sync_required = (mrhdl_new->mr_bindinfo.bi_flags &
	    IBT_MR_NONCOHERENT) ? B_TRUE : B_FALSE;

	/* Return the Tavor MR handle */
	*mr_p = (ibc_mr_hdl_t)mrhdl_new;

	return (IBT_SUCCESS);
}


/*
 * tavor_ci_reregister_mr()
 *    Modify the attributes of an existing Memory Region
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static ibt_status_t
tavor_ci_reregister_mr(ibc_hca_hdl_t hca, ibc_mr_hdl_t mr, ibc_pd_hdl_t pd,
    ibt_mr_attr_t *mr_attr, void *ibtl_reserved, ibc_mr_hdl_t *mr_new,
    ibt_mr_desc_t *mr_desc)
{
	tavor_mr_options_t	op;
	tavor_state_t		*state;
	tavor_pdhdl_t		pdhdl;
	tavor_mrhdl_t		mrhdl, mrhdl_new;
	int			status;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mr_desc))

	ASSERT(mr_attr != NULL);
	ASSERT(mr_new != NULL);
	ASSERT(mr_desc != NULL);

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid memory region handle */
	if (mr == NULL) {
		return (IBT_MR_HDL_INVALID);
	}

	/* Grab the Tavor softstate pointer, mrhdl, and pdhdl */
	state = (tavor_state_t *)hca;
	mrhdl = (tavor_mrhdl_t)mr;
	pdhdl = (tavor_pdhdl_t)pd;

	/* Reregister the memory region */
	op.mro_bind_type = state->ts_cfg_profile->cp_iommu_bypass;
	status = tavor_mr_reregister(state, mrhdl, pdhdl, mr_attr,
	    &mrhdl_new, &op);
	if (status != DDI_SUCCESS) {
		return (status);
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mrhdl_new))

	/* Fill in the mr_desc structure */
	mr_desc->md_vaddr = mrhdl_new->mr_bindinfo.bi_addr;
	mr_desc->md_lkey  = mrhdl_new->mr_lkey;
	/* Only set RKey if remote access was requested */
	if ((mr_attr->mr_flags & IBT_MR_ENABLE_REMOTE_ATOMIC) ||
	    (mr_attr->mr_flags & IBT_MR_ENABLE_REMOTE_WRITE) ||
	    (mr_attr->mr_flags & IBT_MR_ENABLE_REMOTE_READ)) {
		mr_desc->md_rkey = mrhdl_new->mr_rkey;
	}

	/*
	 * If region is mapped for streaming (i.e. noncoherent), then set
	 * sync is required
	 */
	mr_desc->md_sync_required = (mrhdl_new->mr_bindinfo.bi_flags &
	    IBT_MR_NONCOHERENT) ? B_TRUE : B_FALSE;

	/* Return the Tavor MR handle */
	*mr_new = (ibc_mr_hdl_t)mrhdl_new;

	return (IBT_SUCCESS);
}


/*
 * tavor_ci_reregister_buf()
 *    Modify the attributes of an existing Memory Region
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static ibt_status_t
tavor_ci_reregister_buf(ibc_hca_hdl_t hca, ibc_mr_hdl_t mr, ibc_pd_hdl_t pd,
    ibt_smr_attr_t *attrp, struct buf *buf, void *ibtl_reserved,
    ibc_mr_hdl_t *mr_new, ibt_mr_desc_t *mr_desc)
{
	tavor_mr_options_t	op;
	tavor_state_t		*state;
	tavor_pdhdl_t		pdhdl;
	tavor_mrhdl_t		mrhdl, mrhdl_new;
	int			status;
	ibt_mr_flags_t		flags = attrp->mr_flags;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mr_desc))

	ASSERT(mr_new != NULL);
	ASSERT(mr_desc != NULL);

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid memory region handle */
	if (mr == NULL) {
		return (IBT_MR_HDL_INVALID);
	}

	/* Grab the Tavor softstate pointer, mrhdl, and pdhdl */
	state = (tavor_state_t *)hca;
	mrhdl = (tavor_mrhdl_t)mr;
	pdhdl = (tavor_pdhdl_t)pd;

	/* Reregister the memory region */
	op.mro_bind_type = state->ts_cfg_profile->cp_iommu_bypass;
	status = tavor_mr_reregister_buf(state, mrhdl, pdhdl, attrp, buf,
	    &mrhdl_new, &op);
	if (status != DDI_SUCCESS) {
		return (status);
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mrhdl_new))

	/* Fill in the mr_desc structure */
	mr_desc->md_vaddr = mrhdl_new->mr_bindinfo.bi_addr;
	mr_desc->md_lkey  = mrhdl_new->mr_lkey;
	/* Only set RKey if remote access was requested */
	if ((flags & IBT_MR_ENABLE_REMOTE_ATOMIC) ||
	    (flags & IBT_MR_ENABLE_REMOTE_WRITE) ||
	    (flags & IBT_MR_ENABLE_REMOTE_READ)) {
		mr_desc->md_rkey = mrhdl_new->mr_rkey;
	}

	/*
	 * If region is mapped for streaming (i.e. noncoherent), then set
	 * sync is required
	 */
	mr_desc->md_sync_required = (mrhdl_new->mr_bindinfo.bi_flags &
	    IBT_MR_NONCOHERENT) ? B_TRUE : B_FALSE;

	/* Return the Tavor MR handle */
	*mr_new = (ibc_mr_hdl_t)mrhdl_new;

	return (IBT_SUCCESS);
}

/*
 * tavor_ci_sync_mr()
 *    Synchronize access to a Memory Region
 *    Context: Can be called from interrupt or base context.
 */
static ibt_status_t
tavor_ci_sync_mr(ibc_hca_hdl_t hca, ibt_mr_sync_t *mr_segs, size_t num_segs)
{
	tavor_state_t		*state;
	int			status;

	ASSERT(mr_segs != NULL);

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Grab the Tavor softstate pointer */
	state = (tavor_state_t *)hca;

	/* Sync the memory region */
	status = tavor_mr_sync(state, mr_segs, num_segs);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	return (IBT_SUCCESS);
}


/*
 * tavor_ci_alloc_mw()
 *    Allocate a Memory Window
 *    Context: Can be called from interrupt or base context.
 */
static ibt_status_t
tavor_ci_alloc_mw(ibc_hca_hdl_t hca, ibc_pd_hdl_t pd, ibt_mw_flags_t flags,
    ibc_mw_hdl_t *mw_p, ibt_rkey_t *rkey_p)
{
	tavor_state_t		*state;
	tavor_pdhdl_t		pdhdl;
	tavor_mwhdl_t		mwhdl;
	int			status;

	ASSERT(mw_p != NULL);
	ASSERT(rkey_p != NULL);

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid PD handle pointer */
	if (pd == NULL) {
		return (IBT_PD_HDL_INVALID);
	}

	/* Grab the Tavor softstate pointer and PD handle */
	state = (tavor_state_t *)hca;
	pdhdl = (tavor_pdhdl_t)pd;

	/* Allocate the memory window */
	status = tavor_mw_alloc(state, pdhdl, flags, &mwhdl);
	if (status != DDI_SUCCESS) {
		return (status);
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mwhdl))

	/* Return the MW handle and RKey */
	*mw_p = (ibc_mw_hdl_t)mwhdl;
	*rkey_p = mwhdl->mr_rkey;

	return (IBT_SUCCESS);
}


/*
 * tavor_ci_free_mw()
 *    Free a Memory Window
 *    Context: Can be called from interrupt or base context.
 */
static ibt_status_t
tavor_ci_free_mw(ibc_hca_hdl_t hca, ibc_mw_hdl_t mw)
{
	tavor_state_t		*state;
	tavor_mwhdl_t		mwhdl;
	int			status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid MW handle */
	if (mw == NULL) {
		return (IBT_MW_HDL_INVALID);
	}

	/* Grab the Tavor softstate pointer and MW handle */
	state = (tavor_state_t *)hca;
	mwhdl = (tavor_mwhdl_t)mw;

	/* Free the memory window */
	status = tavor_mw_free(state, &mwhdl, TAVOR_NOSLEEP);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	return (IBT_SUCCESS);
}


/*
 * tavor_ci_query_mw()
 *    Return the attributes of the specified Memory Window
 *    Context: Can be called from interrupt or base context.
 */
static ibt_status_t
tavor_ci_query_mw(ibc_hca_hdl_t hca, ibc_mw_hdl_t mw,
    ibt_mw_query_attr_t *mw_attr_p)
{
	tavor_mwhdl_t		mwhdl;

	ASSERT(mw_attr_p != NULL);

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid MemWin handle */
	if (mw == NULL) {
		return (IBT_MW_HDL_INVALID);
	}

	/* Query the memory window pointer and fill in the return values */
	mwhdl = (tavor_mwhdl_t)mw;
	mutex_enter(&mwhdl->mr_lock);
	mw_attr_p->mw_pd   = (ibc_pd_hdl_t)mwhdl->mr_pdhdl;
	mw_attr_p->mw_rkey = mwhdl->mr_rkey;
	mutex_exit(&mwhdl->mr_lock);

	return (IBT_SUCCESS);
}


/* ARGSUSED */
static ibt_status_t
tavor_ci_register_dma_mr(ibc_hca_hdl_t hca, ibc_pd_hdl_t pd,
    ibt_dmr_attr_t *mr_attr, void *ibtl_reserved, ibc_mr_hdl_t *mr_p,
    ibt_mr_desc_t *mr_desc)
{
	tavor_state_t		*state;
	tavor_pdhdl_t		pdhdl;
	tavor_mrhdl_t		mrhdl;
	int			status;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mr_desc))

	ASSERT(mr_attr != NULL);
	ASSERT(mr_p != NULL);
	ASSERT(mr_desc != NULL);

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid PD handle pointer */
	if (pd == NULL) {
		return (IBT_PD_HDL_INVALID);
	}

	/*
	 * Validate the access flags.  Both Remote Write and Remote Atomic
	 * require the Local Write flag to be set
	 */
	if (((mr_attr->dmr_flags & IBT_MR_ENABLE_REMOTE_WRITE) ||
	    (mr_attr->dmr_flags & IBT_MR_ENABLE_REMOTE_ATOMIC)) &&
	    !(mr_attr->dmr_flags & IBT_MR_ENABLE_LOCAL_WRITE)) {
		return (IBT_MR_ACCESS_REQ_INVALID);
	}

	/* Grab the Tavor softstate pointer and PD handle */
	state = (tavor_state_t *)hca;
	pdhdl = (tavor_pdhdl_t)pd;

	status = tavor_dma_mr_register(state, pdhdl, mr_attr, &mrhdl);
	if (status != DDI_SUCCESS) {
		return (status);
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mrhdl))

	/* Fill in the mr_desc structure */
	mr_desc->md_vaddr = mr_attr->dmr_paddr;
	mr_desc->md_lkey  = mrhdl->mr_lkey;
	/* Only set RKey if remote access was requested */
	if ((mr_attr->dmr_flags & IBT_MR_ENABLE_REMOTE_ATOMIC) ||
	    (mr_attr->dmr_flags & IBT_MR_ENABLE_REMOTE_WRITE) ||
	    (mr_attr->dmr_flags & IBT_MR_ENABLE_REMOTE_READ)) {
		mr_desc->md_rkey = mrhdl->mr_rkey;
	}

	/*
	 * If region is mapped for streaming (i.e. noncoherent), then set
	 * sync is required
	 */
	mr_desc->md_sync_required = B_FALSE;

	/* Return the Hermon MR handle */
	*mr_p = (ibc_mr_hdl_t)mrhdl;

	return (IBT_SUCCESS);
}


/*
 * tavor_ci_attach_mcg()
 *    Attach a Queue Pair to a Multicast Group
 *    Context: Can be called only from user or kernel context.
 */
static ibt_status_t
tavor_ci_attach_mcg(ibc_hca_hdl_t hca, ibc_qp_hdl_t qp, ib_gid_t gid,
    ib_lid_t lid)
{
	tavor_state_t		*state;
	tavor_qphdl_t		qphdl;
	int			status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid QP handle pointer */
	if (qp == NULL) {
		return (IBT_QP_HDL_INVALID);
	}

	/* Grab the Tavor softstate pointer and QP handles */
	state = (tavor_state_t *)hca;
	qphdl = (tavor_qphdl_t)qp;

	/* Attach the QP to the multicast group */
	status = tavor_mcg_attach(state, qphdl, gid, lid);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	return (IBT_SUCCESS);
}


/*
 * tavor_ci_detach_mcg()
 *    Detach a Queue Pair to a Multicast Group
 *    Context: Can be called only from user or kernel context.
 */
static ibt_status_t
tavor_ci_detach_mcg(ibc_hca_hdl_t hca, ibc_qp_hdl_t qp, ib_gid_t gid,
    ib_lid_t lid)
{
	tavor_state_t		*state;
	tavor_qphdl_t		qphdl;
	int			status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid QP handle pointer */
	if (qp == NULL) {
		return (IBT_QP_HDL_INVALID);
	}

	/* Grab the Tavor softstate pointer and QP handle */
	state = (tavor_state_t *)hca;
	qphdl = (tavor_qphdl_t)qp;

	/* Detach the QP from the multicast group */
	status = tavor_mcg_detach(state, qphdl, gid, lid);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	return (IBT_SUCCESS);
}


/*
 * tavor_ci_post_send()
 *    Post send work requests to the send queue on the specified QP
 *    Context: Can be called from interrupt or base context.
 */
static ibt_status_t
tavor_ci_post_send(ibc_hca_hdl_t hca, ibc_qp_hdl_t qp, ibt_send_wr_t *wr_p,
    uint_t num_wr, uint_t *num_posted_p)
{
	tavor_state_t		*state;
	tavor_qphdl_t		qphdl;
	int			status;

	ASSERT(wr_p != NULL);
	ASSERT(num_wr != 0);

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid QP handle pointer */
	if (qp == NULL) {
		return (IBT_QP_HDL_INVALID);
	}

	/* Grab the Tavor softstate pointer and QP handle */
	state = (tavor_state_t *)hca;
	qphdl = (tavor_qphdl_t)qp;

	/* Post the send WQEs */
	status = tavor_post_send(state, qphdl, wr_p, num_wr, num_posted_p);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	return (IBT_SUCCESS);
}


/*
 * tavor_ci_post_recv()
 *    Post receive work requests to the receive queue on the specified QP
 *    Context: Can be called from interrupt or base context.
 */
static ibt_status_t
tavor_ci_post_recv(ibc_hca_hdl_t hca, ibc_qp_hdl_t qp, ibt_recv_wr_t *wr_p,
    uint_t num_wr, uint_t *num_posted_p)
{
	tavor_state_t		*state;
	tavor_qphdl_t		qphdl;
	int			status;

	ASSERT(wr_p != NULL);
	ASSERT(num_wr != 0);

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid QP handle pointer */
	if (qp == NULL) {
		return (IBT_QP_HDL_INVALID);
	}

	/* Grab the Tavor softstate pointer and QP handle */
	state = (tavor_state_t *)hca;
	qphdl = (tavor_qphdl_t)qp;

	/* Post the receive WQEs */
	status = tavor_post_recv(state, qphdl, wr_p, num_wr, num_posted_p);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	return (IBT_SUCCESS);
}


/*
 * tavor_ci_poll_cq()
 *    Poll for a work request completion
 *    Context: Can be called from interrupt or base context.
 */
static ibt_status_t
tavor_ci_poll_cq(ibc_hca_hdl_t hca, ibc_cq_hdl_t cq, ibt_wc_t *wc_p,
    uint_t num_wc, uint_t *num_polled)
{
	tavor_state_t		*state;
	tavor_cqhdl_t		cqhdl;
	uint_t			polled;
	int			status;

	ASSERT(wc_p != NULL);

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid CQ handle pointer */
	if (cq == NULL) {
		return (IBT_CQ_HDL_INVALID);
	}

	/* Check for valid num_wc field */
	if (num_wc == 0) {
		return (IBT_INVALID_PARAM);
	}

	/* Grab the Tavor softstate pointer and CQ handle */
	state = (tavor_state_t *)hca;
	cqhdl = (tavor_cqhdl_t)cq;

	/* Poll for work request completions */
	status = tavor_cq_poll(state, cqhdl, wc_p, num_wc, &polled);

	/* First fill in "num_polled" argument (only when valid) */
	if (num_polled) {
		*num_polled = polled;
	}

	/*
	 * Check the status code;
	 *   If empty, we return empty.
	 *   If error, we print out an error and then return
	 *   If success (something was polled), we return success
	 */
	if (status != DDI_SUCCESS) {
		return (status);
	}

	return (IBT_SUCCESS);
}


/*
 * tavor_ci_notify_cq()
 *    Enable notification events on the specified CQ
 *    Context: Can be called from interrupt or base context.
 */
static ibt_status_t
tavor_ci_notify_cq(ibc_hca_hdl_t hca, ibc_cq_hdl_t cq_hdl,
    ibt_cq_notify_flags_t flags)
{
	tavor_state_t		*state;
	tavor_cqhdl_t		cqhdl;
	int			status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid CQ handle pointer */
	if (cq_hdl == NULL) {
		return (IBT_CQ_HDL_INVALID);
	}

	/* Grab the Tavor softstate pointer and CQ handle */
	state = (tavor_state_t *)hca;
	cqhdl = (tavor_cqhdl_t)cq_hdl;

	/* Enable the CQ notification */
	status = tavor_cq_notify(state, cqhdl, flags);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	return (IBT_SUCCESS);
}

/*
 * tavor_ci_ci_data_in()
 *    Exchange CI-specific data.
 *    Context: Can be called only from user or kernel context.
 */
static ibt_status_t
tavor_ci_ci_data_in(ibc_hca_hdl_t hca, ibt_ci_data_flags_t flags,
    ibt_object_type_t object, void *ibc_object_handle, void *data_p,
    size_t data_sz)
{
	tavor_state_t		*state;
	int			status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Grab the Tavor softstate pointer */
	state = (tavor_state_t *)hca;

	/* Get the Tavor userland mapping information */
	status = tavor_umap_ci_data_in(state, flags, object,
	    ibc_object_handle, data_p, data_sz);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	return (IBT_SUCCESS);
}

/*
 * tavor_ci_ci_data_out()
 *    Exchange CI-specific data.
 *    Context: Can be called only from user or kernel context.
 */
static ibt_status_t
tavor_ci_ci_data_out(ibc_hca_hdl_t hca, ibt_ci_data_flags_t flags,
    ibt_object_type_t object, void *ibc_object_handle, void *data_p,
    size_t data_sz)
{
	tavor_state_t		*state;
	int			status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Grab the Tavor softstate pointer */
	state = (tavor_state_t *)hca;

	/* Get the Tavor userland mapping information */
	status = tavor_umap_ci_data_out(state, flags, object,
	    ibc_object_handle, data_p, data_sz);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	return (IBT_SUCCESS);
}


/*
 * tavor_ci_alloc_srq()
 *    Allocate a Shared Receive Queue (SRQ)
 *    Context: Can be called only from user or kernel context
 */
static ibt_status_t
tavor_ci_alloc_srq(ibc_hca_hdl_t hca, ibt_srq_flags_t flags,
    ibt_srq_hdl_t ibt_srq, ibc_pd_hdl_t pd, ibt_srq_sizes_t *sizes,
    ibc_srq_hdl_t *ibc_srq_p, ibt_srq_sizes_t *ret_sizes_p)
{
	tavor_state_t		*state;
	tavor_pdhdl_t		pdhdl;
	tavor_srqhdl_t		srqhdl;
	tavor_srq_info_t	srqinfo;
	tavor_srq_options_t	op;
	int			status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	state = (tavor_state_t *)hca;

	/* Check if SRQ is even supported */
	if (state->ts_cfg_profile->cp_srq_enable == 0) {
		return (IBT_NOT_SUPPORTED);
	}

	/* Check for valid PD handle pointer */
	if (pd == NULL) {
		return (IBT_PD_HDL_INVALID);
	}

	pdhdl = (tavor_pdhdl_t)pd;

	srqinfo.srqi_ibt_srqhdl = ibt_srq;
	srqinfo.srqi_pd		= pdhdl;
	srqinfo.srqi_sizes	= sizes;
	srqinfo.srqi_real_sizes	= ret_sizes_p;
	srqinfo.srqi_srqhdl	= &srqhdl;
	srqinfo.srqi_flags	= flags;
	op.srqo_wq_loc		= state->ts_cfg_profile->cp_srq_wq_inddr;
	status = tavor_srq_alloc(state, &srqinfo, TAVOR_NOSLEEP, &op);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	*ibc_srq_p = (ibc_srq_hdl_t)srqhdl;

	return (IBT_SUCCESS);
}

/*
 * tavor_ci_free_srq()
 *    Free a Shared Receive Queue (SRQ)
 *    Context: Can be called only from user or kernel context
 */
static ibt_status_t
tavor_ci_free_srq(ibc_hca_hdl_t hca, ibc_srq_hdl_t srq)
{
	tavor_state_t	*state;
	tavor_srqhdl_t	srqhdl;
	int		status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	state = (tavor_state_t *)hca;

	/* Check if SRQ is even supported */
	if (state->ts_cfg_profile->cp_srq_enable == 0) {
		return (IBT_NOT_SUPPORTED);
	}

	/* Check for valid SRQ handle pointer */
	if (srq == NULL) {
		return (IBT_SRQ_HDL_INVALID);
	}

	srqhdl = (tavor_srqhdl_t)srq;

	/* Free the SRQ */
	status = tavor_srq_free(state, &srqhdl, TAVOR_NOSLEEP);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	return (IBT_SUCCESS);
}

/*
 * tavor_ci_query_srq()
 *    Query properties of a Shared Receive Queue (SRQ)
 *    Context: Can be called from interrupt or base context.
 */
static ibt_status_t
tavor_ci_query_srq(ibc_hca_hdl_t hca, ibc_srq_hdl_t srq, ibc_pd_hdl_t *pd_p,
    ibt_srq_sizes_t *sizes_p, uint_t *limit_p)
{
	tavor_state_t	*state;
	tavor_srqhdl_t	srqhdl;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	state = (tavor_state_t *)hca;

	/* Check if SRQ is even supported */
	if (state->ts_cfg_profile->cp_srq_enable == 0) {
		return (IBT_NOT_SUPPORTED);
	}

	/* Check for valid SRQ handle pointer */
	if (srq == NULL) {
		return (IBT_SRQ_HDL_INVALID);
	}

	srqhdl = (tavor_srqhdl_t)srq;

	mutex_enter(&srqhdl->srq_lock);
	if (srqhdl->srq_state == TAVOR_SRQ_STATE_ERROR) {
		mutex_exit(&srqhdl->srq_lock);
		return (IBT_SRQ_ERROR_STATE);
	}

	*pd_p   = (ibc_pd_hdl_t)srqhdl->srq_pdhdl;
	sizes_p->srq_wr_sz = srqhdl->srq_real_sizes.srq_wr_sz;
	sizes_p->srq_sgl_sz = srqhdl->srq_real_sizes.srq_sgl_sz;
	mutex_exit(&srqhdl->srq_lock);
	*limit_p  = 0;

	return (IBT_SUCCESS);
}

/*
 * tavor_ci_modify_srq()
 *    Modify properties of a Shared Receive Queue (SRQ)
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static ibt_status_t
tavor_ci_modify_srq(ibc_hca_hdl_t hca, ibc_srq_hdl_t srq,
    ibt_srq_modify_flags_t flags, uint_t size, uint_t limit, uint_t *ret_size_p)
{
	tavor_state_t	*state;
	tavor_srqhdl_t	srqhdl;
	uint_t		resize_supported, cur_srq_size;
	int		status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	state = (tavor_state_t *)hca;

	/* Check if SRQ is even supported */
	if (state->ts_cfg_profile->cp_srq_enable == 0) {
		return (IBT_NOT_SUPPORTED);
	}

	/* Check for valid SRQ handle pointer */
	if (srq == NULL) {
		return (IBT_SRQ_HDL_INVALID);
	}

	srqhdl = (tavor_srqhdl_t)srq;

	/*
	 * Check Error State of SRQ.
	 * Also, while we are holding the lock we save away the current SRQ
	 * size for later use.
	 */
	mutex_enter(&srqhdl->srq_lock);
	cur_srq_size = srqhdl->srq_wq_bufsz;
	if (srqhdl->srq_state == TAVOR_SRQ_STATE_ERROR) {
		mutex_exit(&srqhdl->srq_lock);
		return (IBT_SRQ_ERROR_STATE);
	}
	mutex_exit(&srqhdl->srq_lock);

	/*
	 * Setting the limit watermark is not currently supported.  This is a
	 * tavor hardware (firmware) limitation.  We return NOT_SUPPORTED here,
	 * and have the limit code commented out for now.
	 *
	 * XXX If we enable the limit watermark support, we need to do checks
	 * and set the 'srq->srq_wr_limit' here, instead of returning not
	 * supported.  The 'tavor_srq_modify' operation below is for resizing
	 * the SRQ only, the limit work should be done here.  If this is
	 * changed to use the 'limit' field, the 'ARGSUSED' comment for this
	 * function should also be removed at that time.
	 */
	if (flags & IBT_SRQ_SET_LIMIT) {
		return (IBT_NOT_SUPPORTED);
	}

	/*
	 * Check the SET_SIZE flag.  If not set, we simply return success here.
	 * However if it is set, we check if resize is supported and only then
	 * do we continue on with our resize processing.
	 */
	if (!(flags & IBT_SRQ_SET_SIZE)) {
		return (IBT_SUCCESS);
	}

	resize_supported = state->ts_ibtfinfo.hca_attr->hca_flags &
	    IBT_HCA_RESIZE_SRQ;

	if ((flags & IBT_SRQ_SET_SIZE) && !resize_supported) {
		return (IBT_NOT_SUPPORTED);
	}

	/*
	 * We do not support resizing an SRQ to be smaller than it's current
	 * size.  If a smaller (or equal) size is requested, then we simply
	 * return success, and do nothing.
	 */
	if (size <= cur_srq_size) {
		*ret_size_p = cur_srq_size;
		return (IBT_SUCCESS);
	}

	status = tavor_srq_modify(state, srqhdl, size, ret_size_p,
	    TAVOR_NOSLEEP);
	if (status != DDI_SUCCESS) {
		/* Set return value to current SRQ size */
		*ret_size_p = cur_srq_size;
		return (status);
	}

	return (IBT_SUCCESS);
}

/*
 * tavor_ci_post_srq()
 *    Post a Work Request to the specified Shared Receive Queue (SRQ)
 *    Context: Can be called from interrupt or base context.
 */
static ibt_status_t
tavor_ci_post_srq(ibc_hca_hdl_t hca, ibc_srq_hdl_t srq,
    ibt_recv_wr_t *wr, uint_t num_wr, uint_t *num_posted_p)
{
	tavor_state_t	*state;
	tavor_srqhdl_t	srqhdl;
	int		status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	state = (tavor_state_t *)hca;

	/* Check if SRQ is even supported */
	if (state->ts_cfg_profile->cp_srq_enable == 0) {
		return (IBT_NOT_SUPPORTED);
	}

	/* Check for valid SRQ handle pointer */
	if (srq == NULL) {
		return (IBT_SRQ_HDL_INVALID);
	}

	srqhdl = (tavor_srqhdl_t)srq;

	status = tavor_post_srq(state, srqhdl, wr, num_wr, num_posted_p);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	return (IBT_SUCCESS);
}

/* Address translation */
/*
 * tavor_ci_map_mem_area()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static ibt_status_t
tavor_ci_map_mem_area(ibc_hca_hdl_t hca, ibt_va_attr_t *va_attrs,
    void *ibtl_reserved, uint_t list_len, ibt_reg_req_t *reg_req,
    ibc_ma_hdl_t *ibc_ma_hdl_p)
{
	return (IBT_NOT_SUPPORTED);
}

/*
 * tavor_ci_unmap_mem_area()
 * Unmap the memory area
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static ibt_status_t
tavor_ci_unmap_mem_area(ibc_hca_hdl_t hca, ibc_ma_hdl_t ma_hdl)
{
	return (IBT_NOT_SUPPORTED);
}

struct ibc_mi_s {
	int			imh_len;
	ddi_dma_handle_t	imh_dmahandle[1];
};
_NOTE(SCHEME_PROTECTS_DATA("safe sharing",
    ibc_mi_s::imh_len
    ibc_mi_s::imh_dmahandle))


/*
 * tavor_ci_map_mem_iov()
 * Map the memory
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static ibt_status_t
tavor_ci_map_mem_iov(ibc_hca_hdl_t hca, ibt_iov_attr_t *iov_attr,
    ibt_all_wr_t *wr, ibc_mi_hdl_t *mi_hdl_p)
{
	int			status;
	int			i, j, nds, max_nds;
	uint_t			len;
	ibt_status_t		ibt_status;
	ddi_dma_handle_t	dmahdl;
	ddi_dma_cookie_t	dmacookie;
	ddi_dma_attr_t		dma_attr;
	uint_t			cookie_cnt;
	ibc_mi_hdl_t		mi_hdl;
	ibt_lkey_t		rsvd_lkey;
	ibt_wr_ds_t		*sgl;
	tavor_state_t		*state;
	int			kmflag;
	int			(*callback)(caddr_t);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*wr))

	if (mi_hdl_p == NULL)
		return (IBT_MI_HDL_INVALID);

	/* Check for valid HCA handle */
	if (hca == NULL)
		return (IBT_HCA_HDL_INVALID);

	/* Tavor does not allow the default "use reserved lkey" */
	if ((iov_attr->iov_flags & IBT_IOV_ALT_LKEY) == 0)
		return (IBT_INVALID_PARAM);

	rsvd_lkey = iov_attr->iov_alt_lkey;

	state = (tavor_state_t *)hca;
	tavor_dma_attr_init(&dma_attr);
#ifdef	__sparc
	if (state->ts_cfg_profile->cp_iommu_bypass == TAVOR_BINDMEM_BYPASS)
		dma_attr.dma_attr_flags = DDI_DMA_FORCE_PHYSICAL;
#endif

	nds = 0;
	max_nds = iov_attr->iov_wr_nds;
	if (iov_attr->iov_lso_hdr_sz)
		max_nds -= (iov_attr->iov_lso_hdr_sz + sizeof (uint32_t) +
		    0xf) >> 4;	/* 0xf is for rounding up to a multiple of 16 */
	if ((iov_attr->iov_flags & IBT_IOV_NOSLEEP) == 0) {
		kmflag = KM_SLEEP;
		callback = DDI_DMA_SLEEP;
	} else {
		kmflag = KM_NOSLEEP;
		callback = DDI_DMA_DONTWAIT;
	}

	if (iov_attr->iov_flags & IBT_IOV_BUF) {
		mi_hdl = kmem_alloc(sizeof (*mi_hdl), kmflag);
		if (mi_hdl == NULL)
			return (IBT_INSUFF_RESOURCE);
		sgl = wr->send.wr_sgl;
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*sgl))

		status = ddi_dma_alloc_handle(state->ts_dip, &dma_attr,
		    callback, NULL, &dmahdl);
		if (status != DDI_SUCCESS) {
			kmem_free(mi_hdl, sizeof (*mi_hdl));
			return (IBT_INSUFF_RESOURCE);
		}
		status = ddi_dma_buf_bind_handle(dmahdl, iov_attr->iov_buf,
		    DDI_DMA_RDWR | DDI_DMA_CONSISTENT, callback, NULL,
		    &dmacookie, &cookie_cnt);
		if (status != DDI_DMA_MAPPED) {
			ddi_dma_free_handle(&dmahdl);
			kmem_free(mi_hdl, sizeof (*mi_hdl));
			return (ibc_get_ci_failure(0));
		}
		while (cookie_cnt-- > 0) {
			if (nds > max_nds) {
				status = ddi_dma_unbind_handle(dmahdl);
				ddi_dma_free_handle(&dmahdl);
				return (IBT_SGL_TOO_SMALL);
			}
			sgl[nds].ds_va = dmacookie.dmac_laddress;
			sgl[nds].ds_key = rsvd_lkey;
			sgl[nds].ds_len = (ib_msglen_t)dmacookie.dmac_size;
			nds++;
			if (cookie_cnt != 0)
				ddi_dma_nextcookie(dmahdl, &dmacookie);
		}
		wr->send.wr_nds = nds;
		mi_hdl->imh_len = 1;
		mi_hdl->imh_dmahandle[0] = dmahdl;
		*mi_hdl_p = mi_hdl;
		return (IBT_SUCCESS);
	}

	if (iov_attr->iov_flags & IBT_IOV_RECV)
		sgl = wr->recv.wr_sgl;
	else
		sgl = wr->send.wr_sgl;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*sgl))

	len = iov_attr->iov_list_len;
	for (i = 0, j = 0; j < len; j++) {
		if (iov_attr->iov[j].iov_len == 0)
			continue;
		i++;
	}
	mi_hdl = kmem_alloc(sizeof (*mi_hdl) +
	    (i - 1) * sizeof (ddi_dma_handle_t), kmflag);
	if (mi_hdl == NULL)
		return (IBT_INSUFF_RESOURCE);
	mi_hdl->imh_len = i;
	for (i = 0, j = 0; j < len; j++) {
		if (iov_attr->iov[j].iov_len == 0)
			continue;
		status = ddi_dma_alloc_handle(state->ts_dip, &dma_attr,
		    callback, NULL, &dmahdl);
		if (status != DDI_SUCCESS) {
			ibt_status = IBT_INSUFF_RESOURCE;
			goto fail2;
		}
		status = ddi_dma_addr_bind_handle(dmahdl, iov_attr->iov_as,
		    iov_attr->iov[j].iov_addr, iov_attr->iov[j].iov_len,
		    DDI_DMA_RDWR | DDI_DMA_CONSISTENT, callback, NULL,
		    &dmacookie, &cookie_cnt);
		if (status != DDI_DMA_MAPPED) {
			ibt_status = ibc_get_ci_failure(0);
			goto fail1;
		}
		if (nds + cookie_cnt > max_nds) {
			ibt_status = IBT_SGL_TOO_SMALL;
			goto fail2;
		}
		while (cookie_cnt-- > 0) {
			sgl[nds].ds_va = dmacookie.dmac_laddress;
			sgl[nds].ds_key = rsvd_lkey;
			sgl[nds].ds_len = (ib_msglen_t)dmacookie.dmac_size;
			nds++;
			if (cookie_cnt != 0)
				ddi_dma_nextcookie(dmahdl, &dmacookie);
		}
		mi_hdl->imh_dmahandle[i] = dmahdl;
		i++;
	}

	if (iov_attr->iov_flags & IBT_IOV_RECV)
		wr->recv.wr_nds = nds;
	else
		wr->send.wr_nds = nds;
	*mi_hdl_p = mi_hdl;
	return (IBT_SUCCESS);

fail1:
	ddi_dma_free_handle(&dmahdl);
fail2:
	while (--i >= 0) {
		status = ddi_dma_unbind_handle(mi_hdl->imh_dmahandle[i]);
		ddi_dma_free_handle(&mi_hdl->imh_dmahandle[i]);
	}
	kmem_free(mi_hdl, sizeof (*mi_hdl) +
	    (len - 1) * sizeof (ddi_dma_handle_t));
	*mi_hdl_p = NULL;
	return (ibt_status);
}

/*
 * tavor_ci_unmap_mem_iov()
 * Unmap the memory
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static ibt_status_t
tavor_ci_unmap_mem_iov(ibc_hca_hdl_t hca, ibc_mi_hdl_t mi_hdl)
{
	int		i;

	/* Check for valid HCA handle */
	if (hca == NULL)
		return (IBT_HCA_HDL_INVALID);

	if (mi_hdl == NULL)
		return (IBT_MI_HDL_INVALID);

	for (i = 0; i < mi_hdl->imh_len; i++) {
		(void) ddi_dma_unbind_handle(mi_hdl->imh_dmahandle[i]);
		ddi_dma_free_handle(&mi_hdl->imh_dmahandle[i]);
	}
	kmem_free(mi_hdl, sizeof (*mi_hdl) +
	    (mi_hdl->imh_len - 1) * sizeof (ddi_dma_handle_t));
	return (IBT_SUCCESS);
}

/* Allocate L_Key */
/*
 * tavor_ci_alloc_lkey()
 */
/* ARGSUSED */
static ibt_status_t
tavor_ci_alloc_lkey(ibc_hca_hdl_t hca, ibc_pd_hdl_t pd,
    ibt_lkey_flags_t flags, uint_t phys_buf_list_sz, ibc_mr_hdl_t *mr_p,
    ibt_pmr_desc_t *mem_desc_p)
{
	return (IBT_NOT_SUPPORTED);
}

/* Physical Register Memory Region */
/*
 * tavor_ci_register_physical_mr()
 */
/* ARGSUSED */
static ibt_status_t
tavor_ci_register_physical_mr(ibc_hca_hdl_t hca, ibc_pd_hdl_t pd,
    ibt_pmr_attr_t *mem_pattrs, void *ibtl_reserved, ibc_mr_hdl_t *mr_p,
    ibt_pmr_desc_t *mem_desc_p)
{
	return (IBT_NOT_SUPPORTED);
}

/*
 * tavor_ci_reregister_physical_mr()
 */
/* ARGSUSED */
static ibt_status_t
tavor_ci_reregister_physical_mr(ibc_hca_hdl_t hca, ibc_mr_hdl_t mr,
    ibc_pd_hdl_t pd, ibt_pmr_attr_t *mem_pattrs, void *ibtl_reserved,
    ibc_mr_hdl_t *mr_p, ibt_pmr_desc_t *mr_desc_p)
{
	return (IBT_NOT_SUPPORTED);
}

/* Mellanox FMR Support */
/*
 * tavor_ci_create_fmr_pool()
 * Creates a pool of memory regions suitable for FMR registration
 *    Context: Can be called from base context only
 */
/* ARGSUSED */
static ibt_status_t
tavor_ci_create_fmr_pool(ibc_hca_hdl_t hca, ibc_pd_hdl_t pd,
    ibt_fmr_pool_attr_t *params, ibc_fmr_pool_hdl_t *fmr_pool_p)
{
	return (IBT_NOT_SUPPORTED);
}

/*
 * tavor_ci_destroy_fmr_pool()
 * Free all resources associated with an FMR pool.
 *    Context: Can be called from base context only.
 */
/* ARGSUSED */
static ibt_status_t
tavor_ci_destroy_fmr_pool(ibc_hca_hdl_t hca, ibc_fmr_pool_hdl_t fmr_pool)
{
	return (IBT_NOT_SUPPORTED);
}

/*
 * tavor_ci_flush_fmr_pool()
 * Force a flush of the memory tables, cleaning up used FMR resources.
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static ibt_status_t
tavor_ci_flush_fmr_pool(ibc_hca_hdl_t hca, ibc_fmr_pool_hdl_t fmr_pool)
{
	return (IBT_NOT_SUPPORTED);
}

/*
 * tavor_ci_register_physical_fmr()
 * From the 'pool' of FMR regions passed in, performs register physical
 * operation.
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static ibt_status_t
tavor_ci_register_physical_fmr(ibc_hca_hdl_t hca,
    ibc_fmr_pool_hdl_t fmr_pool, ibt_pmr_attr_t *mem_pattr,
    void *ibtl_reserved, ibc_mr_hdl_t *mr_p, ibt_pmr_desc_t *mem_desc_p)
{
	return (IBT_NOT_SUPPORTED);
}

/*
 * tavor_ci_deregister_fmr()
 * Moves an FMR (specified by 'mr') to the deregistered state.
 *    Context: Can be called from base context only.
 */
/* ARGSUSED */
static ibt_status_t
tavor_ci_deregister_fmr(ibc_hca_hdl_t hca, ibc_mr_hdl_t mr)
{
	return (IBT_NOT_SUPPORTED);
}

/*
 * tavor_ci_alloc_io_mem()
 *     Allocate dmable memory
 *
 */
ibt_status_t
tavor_ci_alloc_io_mem(
	ibc_hca_hdl_t hca,
	size_t size,
	ibt_mr_flags_t mr_flag,
	caddr_t *kaddrp,
	ibc_mem_alloc_hdl_t *mem_alloc_hdl)
{
	tavor_state_t	*state;
	int		status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid mem_alloc_hdl handle pointer */
	if (mem_alloc_hdl == NULL) {
		return (IBT_MEM_ALLOC_HDL_INVALID);
	}

	/* Grab the Tavor softstate pointer and mem handle */
	state = (tavor_state_t *)hca;

	/* Allocate the AH */
	status = tavor_mem_alloc(state, size, mr_flag, kaddrp,
	    (tavor_mem_alloc_hdl_t *)mem_alloc_hdl);

	if (status != DDI_SUCCESS) {
		return (status);
	}

	return (IBT_SUCCESS);
}


/*
 * tavor_ci_free_io_mem()
 * free the memory
 */
ibt_status_t
tavor_ci_free_io_mem(ibc_hca_hdl_t hca, ibc_mem_alloc_hdl_t mem_alloc_hdl)
{
	tavor_mem_alloc_hdl_t	memhdl;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid mem_alloc_hdl handle pointer */
	if (mem_alloc_hdl == NULL) {
		return (IBT_MEM_ALLOC_HDL_INVALID);
	}

	memhdl = (tavor_mem_alloc_hdl_t)mem_alloc_hdl;

	/* free the memory */
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*memhdl))
	ddi_dma_mem_free(&memhdl->tavor_acc_hdl);
	ddi_dma_free_handle(&memhdl->tavor_dma_hdl);

	kmem_free(memhdl, sizeof (*memhdl));
	return (IBT_SUCCESS);
}


int
tavor_mem_alloc(
	tavor_state_t *state,
	size_t size,
	ibt_mr_flags_t flags,
	caddr_t *kaddrp,
	tavor_mem_alloc_hdl_t *mem_hdl)
{
	ddi_dma_handle_t	dma_hdl;
	ddi_dma_attr_t		dma_attr;
	ddi_acc_handle_t	acc_hdl;
	size_t			real_len;
	int			status;
	int 			(*ddi_cb)(caddr_t);

	tavor_dma_attr_init(&dma_attr);

	ddi_cb = (flags & IBT_MR_NOSLEEP) ? DDI_DMA_DONTWAIT : DDI_DMA_SLEEP;

	/* Allocate a DMA handle */
	status = ddi_dma_alloc_handle(state->ts_dip, &dma_attr, ddi_cb,
	    NULL, &dma_hdl);
	if (status != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/* Allocate DMA memory */
	status = ddi_dma_mem_alloc(dma_hdl, size,
	    &state->ts_reg_accattr, DDI_DMA_CONSISTENT, ddi_cb,
	    NULL,
	    kaddrp, &real_len, &acc_hdl);
	if (status != DDI_SUCCESS) {
		ddi_dma_free_handle(&dma_hdl);
		return (DDI_FAILURE);
	}

	/* Package the tavor_dma_info contents and return */
	*mem_hdl = kmem_alloc(sizeof (**mem_hdl),
	    flags & IBT_MR_NOSLEEP ? KM_NOSLEEP : KM_SLEEP);
	if (*mem_hdl == NULL) {
		ddi_dma_mem_free(&acc_hdl);
		ddi_dma_free_handle(&dma_hdl);
		return (DDI_FAILURE);
	}
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(**mem_hdl))
	(*mem_hdl)->tavor_dma_hdl = dma_hdl;
	(*mem_hdl)->tavor_acc_hdl = acc_hdl;

	return (DDI_SUCCESS);
}
