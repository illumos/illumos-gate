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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * hermon_ci.c
 *    Hermon Channel Interface (CI) Routines
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

#include <sys/ib/adapters/hermon/hermon.h>

/* HCA and port related operations */
static ibt_status_t hermon_ci_query_hca_ports(ibc_hca_hdl_t, uint8_t,
    ibt_hca_portinfo_t *);
static ibt_status_t hermon_ci_modify_ports(ibc_hca_hdl_t, uint8_t,
    ibt_port_modify_flags_t, uint8_t);
static ibt_status_t hermon_ci_modify_system_image(ibc_hca_hdl_t, ib_guid_t);

/* Protection Domains */
static ibt_status_t hermon_ci_alloc_pd(ibc_hca_hdl_t, ibt_pd_flags_t,
    ibc_pd_hdl_t *);
static ibt_status_t hermon_ci_free_pd(ibc_hca_hdl_t, ibc_pd_hdl_t);

/* Reliable Datagram Domains */
static ibt_status_t hermon_ci_alloc_rdd(ibc_hca_hdl_t, ibc_rdd_flags_t,
    ibc_rdd_hdl_t *);
static ibt_status_t hermon_ci_free_rdd(ibc_hca_hdl_t, ibc_rdd_hdl_t);

/* Address Handles */
static ibt_status_t hermon_ci_alloc_ah(ibc_hca_hdl_t, ibt_ah_flags_t,
    ibc_pd_hdl_t, ibt_adds_vect_t *, ibc_ah_hdl_t *);
static ibt_status_t hermon_ci_free_ah(ibc_hca_hdl_t, ibc_ah_hdl_t);
static ibt_status_t hermon_ci_query_ah(ibc_hca_hdl_t, ibc_ah_hdl_t,
    ibc_pd_hdl_t *, ibt_adds_vect_t *);
static ibt_status_t hermon_ci_modify_ah(ibc_hca_hdl_t, ibc_ah_hdl_t,
    ibt_adds_vect_t *);

/* Queue Pairs */
static ibt_status_t hermon_ci_alloc_qp(ibc_hca_hdl_t, ibtl_qp_hdl_t,
    ibt_qp_type_t, ibt_qp_alloc_attr_t *, ibt_chan_sizes_t *, ib_qpn_t *,
    ibc_qp_hdl_t *);
static ibt_status_t hermon_ci_alloc_special_qp(ibc_hca_hdl_t, uint8_t,
    ibtl_qp_hdl_t, ibt_sqp_type_t, ibt_qp_alloc_attr_t *,
    ibt_chan_sizes_t *, ibc_qp_hdl_t *);
static ibt_status_t hermon_ci_alloc_qp_range(ibc_hca_hdl_t, uint_t,
    ibtl_qp_hdl_t *, ibt_qp_type_t, ibt_qp_alloc_attr_t *, ibt_chan_sizes_t *,
    ibc_cq_hdl_t *, ibc_cq_hdl_t *, ib_qpn_t *, ibc_qp_hdl_t *);
static ibt_status_t hermon_ci_free_qp(ibc_hca_hdl_t, ibc_qp_hdl_t,
    ibc_free_qp_flags_t, ibc_qpn_hdl_t *);
static ibt_status_t hermon_ci_release_qpn(ibc_hca_hdl_t, ibc_qpn_hdl_t);
static ibt_status_t hermon_ci_query_qp(ibc_hca_hdl_t, ibc_qp_hdl_t,
    ibt_qp_query_attr_t *);
static ibt_status_t hermon_ci_modify_qp(ibc_hca_hdl_t, ibc_qp_hdl_t,
    ibt_cep_modify_flags_t, ibt_qp_info_t *, ibt_queue_sizes_t *);

/* Completion Queues */
static ibt_status_t hermon_ci_alloc_cq(ibc_hca_hdl_t, ibt_cq_hdl_t,
    ibt_cq_attr_t *, ibc_cq_hdl_t *, uint_t *);
static ibt_status_t hermon_ci_free_cq(ibc_hca_hdl_t, ibc_cq_hdl_t);
static ibt_status_t hermon_ci_query_cq(ibc_hca_hdl_t, ibc_cq_hdl_t,
    uint_t *, uint_t *, uint_t *, ibt_cq_handler_id_t *);
static ibt_status_t hermon_ci_resize_cq(ibc_hca_hdl_t, ibc_cq_hdl_t,
    uint_t, uint_t *);
static ibt_status_t hermon_ci_modify_cq(ibc_hca_hdl_t, ibc_cq_hdl_t,
    uint_t, uint_t, ibt_cq_handler_id_t);
static ibt_status_t hermon_ci_alloc_cq_sched(ibc_hca_hdl_t,
    ibt_cq_sched_flags_t, ibc_cq_handler_attr_t *);
static ibt_status_t hermon_ci_free_cq_sched(ibc_hca_hdl_t, ibt_cq_handler_id_t);

/* EE Contexts */
static ibt_status_t hermon_ci_alloc_eec(ibc_hca_hdl_t, ibc_eec_flags_t,
    ibt_eec_hdl_t, ibc_rdd_hdl_t, ibc_eec_hdl_t *);
static ibt_status_t hermon_ci_free_eec(ibc_hca_hdl_t, ibc_eec_hdl_t);
static ibt_status_t hermon_ci_query_eec(ibc_hca_hdl_t, ibc_eec_hdl_t,
    ibt_eec_query_attr_t *);
static ibt_status_t hermon_ci_modify_eec(ibc_hca_hdl_t, ibc_eec_hdl_t,
    ibt_cep_modify_flags_t, ibt_eec_info_t *);

/* Memory Registration */
static ibt_status_t hermon_ci_register_mr(ibc_hca_hdl_t, ibc_pd_hdl_t,
    ibt_mr_attr_t *, void *, ibc_mr_hdl_t *, ibt_mr_desc_t *);
static ibt_status_t hermon_ci_register_buf(ibc_hca_hdl_t, ibc_pd_hdl_t,
    ibt_smr_attr_t *, struct buf *, void *, ibt_mr_hdl_t *, ibt_mr_desc_t *);
static ibt_status_t hermon_ci_register_shared_mr(ibc_hca_hdl_t,
    ibc_mr_hdl_t, ibc_pd_hdl_t, ibt_smr_attr_t *, void *,
    ibc_mr_hdl_t *, ibt_mr_desc_t *);
static ibt_status_t hermon_ci_deregister_mr(ibc_hca_hdl_t, ibc_mr_hdl_t);
static ibt_status_t hermon_ci_query_mr(ibc_hca_hdl_t, ibc_mr_hdl_t,
    ibt_mr_query_attr_t *);
static ibt_status_t hermon_ci_reregister_mr(ibc_hca_hdl_t, ibc_mr_hdl_t,
    ibc_pd_hdl_t, ibt_mr_attr_t *, void *, ibc_mr_hdl_t *,
    ibt_mr_desc_t *);
static ibt_status_t hermon_ci_reregister_buf(ibc_hca_hdl_t, ibc_mr_hdl_t,
    ibc_pd_hdl_t, ibt_smr_attr_t *, struct buf *, void *, ibc_mr_hdl_t *,
    ibt_mr_desc_t *);
static ibt_status_t hermon_ci_sync_mr(ibc_hca_hdl_t, ibt_mr_sync_t *, size_t);

/* Memory Windows */
static ibt_status_t hermon_ci_alloc_mw(ibc_hca_hdl_t, ibc_pd_hdl_t,
    ibt_mw_flags_t, ibc_mw_hdl_t *, ibt_rkey_t *);
static ibt_status_t hermon_ci_free_mw(ibc_hca_hdl_t, ibc_mw_hdl_t);
static ibt_status_t hermon_ci_query_mw(ibc_hca_hdl_t, ibc_mw_hdl_t,
    ibt_mw_query_attr_t *);

/* Multicast Groups */
static ibt_status_t hermon_ci_attach_mcg(ibc_hca_hdl_t, ibc_qp_hdl_t,
    ib_gid_t, ib_lid_t);
static ibt_status_t hermon_ci_detach_mcg(ibc_hca_hdl_t, ibc_qp_hdl_t,
    ib_gid_t, ib_lid_t);

/* Work Request and Completion Processing */
static ibt_status_t hermon_ci_post_send(ibc_hca_hdl_t, ibc_qp_hdl_t,
    ibt_send_wr_t *, uint_t, uint_t *);
static ibt_status_t hermon_ci_post_recv(ibc_hca_hdl_t, ibc_qp_hdl_t,
    ibt_recv_wr_t *, uint_t, uint_t *);
static ibt_status_t hermon_ci_poll_cq(ibc_hca_hdl_t, ibc_cq_hdl_t,
    ibt_wc_t *, uint_t, uint_t *);
static ibt_status_t hermon_ci_notify_cq(ibc_hca_hdl_t, ibc_cq_hdl_t,
    ibt_cq_notify_flags_t);

/* CI Object Private Data */
static ibt_status_t hermon_ci_ci_data_in(ibc_hca_hdl_t, ibt_ci_data_flags_t,
    ibt_object_type_t, void *, void *, size_t);

/* CI Object Private Data */
static ibt_status_t hermon_ci_ci_data_out(ibc_hca_hdl_t, ibt_ci_data_flags_t,
    ibt_object_type_t, void *, void *, size_t);

/* Shared Receive Queues */
static ibt_status_t hermon_ci_alloc_srq(ibc_hca_hdl_t, ibt_srq_flags_t,
    ibt_srq_hdl_t, ibc_pd_hdl_t, ibt_srq_sizes_t *, ibc_srq_hdl_t *,
    ibt_srq_sizes_t *);
static ibt_status_t hermon_ci_free_srq(ibc_hca_hdl_t, ibc_srq_hdl_t);
static ibt_status_t hermon_ci_query_srq(ibc_hca_hdl_t, ibc_srq_hdl_t,
    ibc_pd_hdl_t *, ibt_srq_sizes_t *, uint_t *);
static ibt_status_t hermon_ci_modify_srq(ibc_hca_hdl_t, ibc_srq_hdl_t,
    ibt_srq_modify_flags_t, uint_t, uint_t, uint_t *);
static ibt_status_t hermon_ci_post_srq(ibc_hca_hdl_t, ibc_srq_hdl_t,
    ibt_recv_wr_t *, uint_t, uint_t *);

/* Address translation */
static ibt_status_t hermon_ci_map_mem_area(ibc_hca_hdl_t, ibt_va_attr_t *,
    void *, uint_t, ibt_phys_buf_t *, uint_t *, size_t *, ib_memlen_t *,
    ibc_ma_hdl_t *);
static ibt_status_t hermon_ci_unmap_mem_area(ibc_hca_hdl_t, ibc_ma_hdl_t);
static ibt_status_t hermon_ci_map_mem_iov(ibc_hca_hdl_t, ibt_iov_attr_t *,
    ibt_all_wr_t *, ibc_mi_hdl_t *);
static ibt_status_t hermon_ci_unmap_mem_iov(ibc_hca_hdl_t, ibc_mi_hdl_t);

/* Allocate L_Key */
static ibt_status_t hermon_ci_alloc_lkey(ibc_hca_hdl_t, ibc_pd_hdl_t,
    ibt_lkey_flags_t, uint_t, ibc_mr_hdl_t *, ibt_pmr_desc_t *);

/* Physical Register Memory Region */
static ibt_status_t hermon_ci_register_physical_mr(ibc_hca_hdl_t, ibc_pd_hdl_t,
    ibt_pmr_attr_t *, void *, ibc_mr_hdl_t *, ibt_pmr_desc_t *);
static ibt_status_t hermon_ci_reregister_physical_mr(ibc_hca_hdl_t,
    ibc_mr_hdl_t, ibc_pd_hdl_t, ibt_pmr_attr_t *, void *, ibc_mr_hdl_t *,
    ibt_pmr_desc_t *);

/* Mellanox FMR */
static ibt_status_t hermon_ci_create_fmr_pool(ibc_hca_hdl_t hca,
    ibc_pd_hdl_t pd, ibt_fmr_pool_attr_t *fmr_params,
    ibc_fmr_pool_hdl_t *fmr_pool);
static ibt_status_t hermon_ci_destroy_fmr_pool(ibc_hca_hdl_t hca,
    ibc_fmr_pool_hdl_t fmr_pool);
static ibt_status_t hermon_ci_flush_fmr_pool(ibc_hca_hdl_t hca,
    ibc_fmr_pool_hdl_t fmr_pool);
static ibt_status_t hermon_ci_register_physical_fmr(ibc_hca_hdl_t hca,
    ibc_fmr_pool_hdl_t fmr_pool, ibt_pmr_attr_t *mem_pattr,
    void *ibtl_reserved, ibc_mr_hdl_t *mr_hdl_p, ibt_pmr_desc_t *mem_desc_p);
static ibt_status_t hermon_ci_deregister_fmr(ibc_hca_hdl_t hca,
    ibc_mr_hdl_t mr);

/* Memory Allocation/Deallocation */
static ibt_status_t hermon_ci_alloc_io_mem(ibc_hca_hdl_t hca, size_t size,
    ibt_mr_flags_t mr_flag, caddr_t *kaddrp,
    ibc_mem_alloc_hdl_t *mem_alloc_hdl_p);
static ibt_status_t hermon_ci_free_io_mem(ibc_hca_hdl_t hca,
    ibc_mem_alloc_hdl_t mem_alloc_hdl);

/*
 * This ibc_operations_t structure includes pointers to all the entry points
 * provided by the Hermon driver.  This structure is passed to the IBTF at
 * driver attach time, using the ibc_attach() call.
 */
ibc_operations_t hermon_ibc_ops = {
	/* HCA and port related operations */
	hermon_ci_query_hca_ports,
	hermon_ci_modify_ports,
	hermon_ci_modify_system_image,

	/* Protection Domains */
	hermon_ci_alloc_pd,
	hermon_ci_free_pd,

	/* Reliable Datagram Domains */
	hermon_ci_alloc_rdd,
	hermon_ci_free_rdd,

	/* Address Handles */
	hermon_ci_alloc_ah,
	hermon_ci_free_ah,
	hermon_ci_query_ah,
	hermon_ci_modify_ah,

	/* Queue Pairs */
	hermon_ci_alloc_qp,
	hermon_ci_alloc_special_qp,
	hermon_ci_alloc_qp_range,
	hermon_ci_free_qp,
	hermon_ci_release_qpn,
	hermon_ci_query_qp,
	hermon_ci_modify_qp,

	/* Completion Queues */
	hermon_ci_alloc_cq,
	hermon_ci_free_cq,
	hermon_ci_query_cq,
	hermon_ci_resize_cq,
	hermon_ci_modify_cq,
	hermon_ci_alloc_cq_sched,
	hermon_ci_free_cq_sched,

	/* EE Contexts */
	hermon_ci_alloc_eec,
	hermon_ci_free_eec,
	hermon_ci_query_eec,
	hermon_ci_modify_eec,

	/* Memory Registration */
	hermon_ci_register_mr,
	hermon_ci_register_buf,
	hermon_ci_register_shared_mr,
	hermon_ci_deregister_mr,
	hermon_ci_query_mr,
	hermon_ci_reregister_mr,
	hermon_ci_reregister_buf,
	hermon_ci_sync_mr,

	/* Memory Windows */
	hermon_ci_alloc_mw,
	hermon_ci_free_mw,
	hermon_ci_query_mw,

	/* Multicast Groups */
	hermon_ci_attach_mcg,
	hermon_ci_detach_mcg,

	/* Work Request and Completion Processing */
	hermon_ci_post_send,
	hermon_ci_post_recv,
	hermon_ci_poll_cq,
	hermon_ci_notify_cq,

	/* CI Object Mapping Data */
	hermon_ci_ci_data_in,
	hermon_ci_ci_data_out,

	/* Shared Receive Queue */
	hermon_ci_alloc_srq,
	hermon_ci_free_srq,
	hermon_ci_query_srq,
	hermon_ci_modify_srq,
	hermon_ci_post_srq,

	/* Address translation */
	hermon_ci_map_mem_area,
	hermon_ci_unmap_mem_area,
	hermon_ci_map_mem_iov,
	hermon_ci_unmap_mem_iov,

	/* Allocate L_key */
	hermon_ci_alloc_lkey,

	/* Physical Register Memory Region */
	hermon_ci_register_physical_mr,
	hermon_ci_reregister_physical_mr,

	/* Mellanox FMR */
	hermon_ci_create_fmr_pool,
	hermon_ci_destroy_fmr_pool,
	hermon_ci_flush_fmr_pool,
	hermon_ci_register_physical_fmr,
	hermon_ci_deregister_fmr,

	/* Memory allocation */
	hermon_ci_alloc_io_mem,
	hermon_ci_free_io_mem,
};


/*
 * hermon_ci_query_hca_ports()
 *    Returns HCA port attributes for either one or all of the HCA's ports.
 *    Context: Can be called only from user or kernel context.
 */
static ibt_status_t
hermon_ci_query_hca_ports(ibc_hca_hdl_t hca, uint8_t query_port,
    ibt_hca_portinfo_t *info_p)
{
	hermon_state_t	*state;
	uint_t		start, end, port;
	int		status, indx;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Grab the Hermon softstate pointer */
	state = (hermon_state_t *)hca;

	/*
	 * If the specified port is zero, then we are supposed to query all
	 * ports.  Otherwise, we query only the port number specified.
	 * Setup the start and end port numbers as appropriate for the loop
	 * below.  Note:  The first Hermon port is port number one (1).
	 */
	if (query_port == 0) {
		start = 1;
		end = start + (state->hs_cfg_profile->cp_num_ports - 1);
	} else {
		end = start = query_port;
	}

	/* Query the port(s) */
	for (port = start, indx = 0; port <= end; port++, indx++) {
		status = hermon_port_query(state, port, &info_p[indx]);
		if (status != DDI_SUCCESS) {
			return (status);
		}
	}
	return (IBT_SUCCESS);
}


/*
 * hermon_ci_modify_ports()
 *    Modify HCA port attributes
 *    Context: Can be called only from user or kernel context.
 */
static ibt_status_t
hermon_ci_modify_ports(ibc_hca_hdl_t hca, uint8_t port,
    ibt_port_modify_flags_t flags, uint8_t init_type)
{
	hermon_state_t	*state;
	int		status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Grab the Hermon softstate pointer */
	state = (hermon_state_t *)hca;

	/* Modify the port(s) */
	status = hermon_port_modify(state, port, flags, init_type);
	return (status);
}

/*
 * hermon_ci_modify_system_image()
 *    Modify the System Image GUID
 *    Context: Can be called only from user or kernel context.
 */
/* ARGSUSED */
static ibt_status_t
hermon_ci_modify_system_image(ibc_hca_hdl_t hca, ib_guid_t sys_guid)
{
	/*
	 * This is an unsupported interface for the Hermon driver.  This
	 * interface is necessary to support modification of the System
	 * Image GUID.  Hermon is only capable of modifying this parameter
	 * once (during driver initialization).
	 */
	return (IBT_NOT_SUPPORTED);
}

/*
 * hermon_ci_alloc_pd()
 *    Allocate a Protection Domain
 *    Context: Can be called only from user or kernel context.
 */
/* ARGSUSED */
static ibt_status_t
hermon_ci_alloc_pd(ibc_hca_hdl_t hca, ibt_pd_flags_t flags, ibc_pd_hdl_t *pd_p)
{
	hermon_state_t	*state;
	hermon_pdhdl_t	pdhdl;
	int		status;

	ASSERT(pd_p != NULL);

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Grab the Hermon softstate pointer */
	state = (hermon_state_t *)hca;

	/* Allocate the PD */
	status = hermon_pd_alloc(state, &pdhdl, HERMON_NOSLEEP);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	/* Return the Hermon PD handle */
	*pd_p = (ibc_pd_hdl_t)pdhdl;

	return (IBT_SUCCESS);
}


/*
 * hermon_ci_free_pd()
 *    Free a Protection Domain
 *    Context: Can be called only from user or kernel context
 */
static ibt_status_t
hermon_ci_free_pd(ibc_hca_hdl_t hca, ibc_pd_hdl_t pd)
{
	hermon_state_t		*state;
	hermon_pdhdl_t		pdhdl;
	int			status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid PD handle pointer */
	if (pd == NULL) {
		return (IBT_PD_HDL_INVALID);
	}

	/* Grab the Hermon softstate pointer and PD handle */
	state = (hermon_state_t *)hca;
	pdhdl = (hermon_pdhdl_t)pd;

	/* Free the PD */
	status = hermon_pd_free(state, &pdhdl);
	return (status);
}


/*
 * hermon_ci_alloc_rdd()
 *    Allocate a Reliable Datagram Domain
 *    Context: Can be called only from user or kernel context.
 */
/* ARGSUSED */
static ibt_status_t
hermon_ci_alloc_rdd(ibc_hca_hdl_t hca, ibc_rdd_flags_t flags,
    ibc_rdd_hdl_t *rdd_p)
{
	/*
	 * This is an unsupported interface for the Hermon driver.  This
	 * interface is necessary to support Reliable Datagram (RD)
	 * operations.  Hermon does not support RD.
	 */
	return (IBT_NOT_SUPPORTED);
}


/*
 * hermon_free_rdd()
 *    Free a Reliable Datagram Domain
 *    Context: Can be called only from user or kernel context.
 */
/* ARGSUSED */
static ibt_status_t
hermon_ci_free_rdd(ibc_hca_hdl_t hca, ibc_rdd_hdl_t rdd)
{
	/*
	 * This is an unsupported interface for the Hermon driver.  This
	 * interface is necessary to support Reliable Datagram (RD)
	 * operations.  Hermon does not support RD.
	 */
	return (IBT_NOT_SUPPORTED);
}


/*
 * hermon_ci_alloc_ah()
 *    Allocate an Address Handle
 *    Context: Can be called only from user or kernel context.
 */
/* ARGSUSED */
static ibt_status_t
hermon_ci_alloc_ah(ibc_hca_hdl_t hca, ibt_ah_flags_t flags, ibc_pd_hdl_t pd,
    ibt_adds_vect_t *attr_p, ibc_ah_hdl_t *ah_p)
{
	hermon_state_t	*state;
	hermon_ahhdl_t	ahhdl;
	hermon_pdhdl_t	pdhdl;
	int		status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid PD handle pointer */
	if (pd == NULL) {
		return (IBT_PD_HDL_INVALID);
	}

	/* Grab the Hermon softstate pointer and PD handle */
	state = (hermon_state_t *)hca;
	pdhdl = (hermon_pdhdl_t)pd;

	/* Allocate the AH */
	status = hermon_ah_alloc(state, pdhdl, attr_p, &ahhdl, HERMON_NOSLEEP);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	/* Return the Hermon AH handle */
	*ah_p = (ibc_ah_hdl_t)ahhdl;

	return (IBT_SUCCESS);
}


/*
 * hermon_ci_free_ah()
 *    Free an Address Handle
 *    Context: Can be called only from user or kernel context.
 */
static ibt_status_t
hermon_ci_free_ah(ibc_hca_hdl_t hca, ibc_ah_hdl_t ah)
{
	hermon_state_t	*state;
	hermon_ahhdl_t	ahhdl;
	int		status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid address handle pointer */
	if (ah == NULL) {
		return (IBT_AH_HDL_INVALID);
	}

	/* Grab the Hermon softstate pointer and AH handle */
	state = (hermon_state_t *)hca;
	ahhdl = (hermon_ahhdl_t)ah;

	/* Free the AH */
	status = hermon_ah_free(state, &ahhdl, HERMON_NOSLEEP);

	return (status);
}


/*
 * hermon_ci_query_ah()
 *    Return the Address Vector information for a specified Address Handle
 *    Context: Can be called from interrupt or base context.
 */
static ibt_status_t
hermon_ci_query_ah(ibc_hca_hdl_t hca, ibc_ah_hdl_t ah, ibc_pd_hdl_t *pd_p,
    ibt_adds_vect_t *attr_p)
{
	hermon_state_t	*state;
	hermon_ahhdl_t	ahhdl;
	hermon_pdhdl_t	pdhdl;
	int		status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid address handle pointer */
	if (ah == NULL) {
		return (IBT_AH_HDL_INVALID);
	}

	/* Grab the Hermon softstate pointer and AH handle */
	state = (hermon_state_t *)hca;
	ahhdl = (hermon_ahhdl_t)ah;

	/* Query the AH */
	status = hermon_ah_query(state, ahhdl, &pdhdl, attr_p);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	/* Return the Hermon PD handle */
	*pd_p = (ibc_pd_hdl_t)pdhdl;

	return (IBT_SUCCESS);
}


/*
 * hermon_ci_modify_ah()
 *    Modify the Address Vector information of a specified Address Handle
 *    Context: Can be called from interrupt or base context.
 */
static ibt_status_t
hermon_ci_modify_ah(ibc_hca_hdl_t hca, ibc_ah_hdl_t ah, ibt_adds_vect_t *attr_p)
{
	hermon_state_t	*state;
	hermon_ahhdl_t	ahhdl;
	int		status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid address handle pointer */
	if (ah == NULL) {
		return (IBT_AH_HDL_INVALID);
	}

	/* Grab the Hermon softstate pointer and AH handle */
	state = (hermon_state_t *)hca;
	ahhdl = (hermon_ahhdl_t)ah;

	/* Modify the AH */
	status = hermon_ah_modify(state, ahhdl, attr_p);

	return (status);
}


/*
 * hermon_ci_alloc_qp()
 *    Allocate a Queue Pair
 *    Context: Can be called only from user or kernel context.
 */
static ibt_status_t
hermon_ci_alloc_qp(ibc_hca_hdl_t hca, ibtl_qp_hdl_t ibt_qphdl,
    ibt_qp_type_t type, ibt_qp_alloc_attr_t *attr_p,
    ibt_chan_sizes_t *queue_sizes_p, ib_qpn_t *qpn, ibc_qp_hdl_t *qp_p)
{
	hermon_state_t		*state;
	hermon_qp_info_t		qpinfo;
	int			status;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*attr_p))
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*queue_sizes_p))

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Grab the Hermon softstate pointer */
	state = (hermon_state_t *)hca;

	/* Allocate the QP */
	qpinfo.qpi_attrp	= attr_p;
	qpinfo.qpi_type		= type;
	qpinfo.qpi_ibt_qphdl	= ibt_qphdl;
	qpinfo.qpi_queueszp	= queue_sizes_p;
	qpinfo.qpi_qpn		= qpn;
	status = hermon_qp_alloc(state, &qpinfo, HERMON_NOSLEEP);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	/* Return the Hermon QP handle */
	*qp_p = (ibc_qp_hdl_t)qpinfo.qpi_qphdl;

	return (IBT_SUCCESS);
}


/*
 * hermon_ci_alloc_special_qp()
 *    Allocate a Special Queue Pair
 *    Context: Can be called only from user or kernel context.
 */
static ibt_status_t
hermon_ci_alloc_special_qp(ibc_hca_hdl_t hca, uint8_t port,
    ibtl_qp_hdl_t ibt_qphdl, ibt_sqp_type_t type,
    ibt_qp_alloc_attr_t *attr_p, ibt_chan_sizes_t *queue_sizes_p,
    ibc_qp_hdl_t *qp_p)
{
	hermon_state_t		*state;
	hermon_qp_info_t		qpinfo;
	int			status;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*attr_p))
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*queue_sizes_p))

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Grab the Hermon softstate pointer */
	state = (hermon_state_t *)hca;

	/* Allocate the Special QP */
	qpinfo.qpi_attrp	= attr_p;
	qpinfo.qpi_type		= type;
	qpinfo.qpi_port		= port;
	qpinfo.qpi_ibt_qphdl	= ibt_qphdl;
	qpinfo.qpi_queueszp	= queue_sizes_p;
	status = hermon_special_qp_alloc(state, &qpinfo, HERMON_NOSLEEP);
	if (status != DDI_SUCCESS) {
		return (status);
	}
	/* Return the Hermon QP handle */
	*qp_p = (ibc_qp_hdl_t)qpinfo.qpi_qphdl;

	return (IBT_SUCCESS);
}

/* ARGSUSED */
static ibt_status_t
hermon_ci_alloc_qp_range(ibc_hca_hdl_t hca, uint_t log2,
    ibtl_qp_hdl_t *ibtl_qp_p, ibt_qp_type_t type,
    ibt_qp_alloc_attr_t *attr_p, ibt_chan_sizes_t *queue_sizes_p,
    ibc_cq_hdl_t *send_cq_p, ibc_cq_hdl_t *recv_cq_p,
    ib_qpn_t *qpn_p, ibc_qp_hdl_t *qp_p)
{
	return (IBT_NOT_SUPPORTED);
}

/*
 * hermon_ci_free_qp()
 *    Free a Queue Pair
 *    Context: Can be called only from user or kernel context.
 */
static ibt_status_t
hermon_ci_free_qp(ibc_hca_hdl_t hca, ibc_qp_hdl_t qp,
    ibc_free_qp_flags_t free_qp_flags, ibc_qpn_hdl_t *qpnh_p)
{
	hermon_state_t	*state;
	hermon_qphdl_t	qphdl;
	int		status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid QP handle pointer */
	if (qp == NULL) {
		return (IBT_QP_HDL_INVALID);
	}

	/* Grab the Hermon softstate pointer and QP handle */
	state = (hermon_state_t *)hca;
	qphdl = (hermon_qphdl_t)qp;

	/* Free the QP */
	status = hermon_qp_free(state, &qphdl, free_qp_flags, qpnh_p,
	    HERMON_NOSLEEP);

	return (status);
}


/*
 * hermon_ci_release_qpn()
 *    Release a Queue Pair Number (QPN)
 *    Context: Can be called only from user or kernel context.
 */
static ibt_status_t
hermon_ci_release_qpn(ibc_hca_hdl_t hca, ibc_qpn_hdl_t qpnh)
{
	hermon_state_t		*state;
	hermon_qpn_entry_t	*entry;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid QP handle pointer */
	if (qpnh == NULL) {
		return (IBT_QP_HDL_INVALID);
	}

	/* Grab the Hermon softstate pointer and QP handle */
	state = (hermon_state_t *)hca;
	entry = (hermon_qpn_entry_t *)qpnh;

	/* Release the QP number */
	hermon_qp_release_qpn(state, entry, HERMON_QPN_RELEASE);

	return (IBT_SUCCESS);
}


/*
 * hermon_ci_query_qp()
 *    Query a Queue Pair
 *    Context: Can be called from interrupt or base context.
 */
static ibt_status_t
hermon_ci_query_qp(ibc_hca_hdl_t hca, ibc_qp_hdl_t qp,
    ibt_qp_query_attr_t *attr_p)
{
	hermon_state_t	*state;
	hermon_qphdl_t	qphdl;
	int		status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid QP handle */
	if (qp == NULL) {
		return (IBT_QP_HDL_INVALID);
	}

	/* Grab the Hermon softstate pointer and QP handle */
	state = (hermon_state_t *)hca;
	qphdl = (hermon_qphdl_t)qp;

	/* Query the QP */
	status = hermon_qp_query(state, qphdl, attr_p);
	return (status);
}


/*
 * hermon_ci_modify_qp()
 *    Modify a Queue Pair
 *    Context: Can be called from interrupt or base context.
 */
static ibt_status_t
hermon_ci_modify_qp(ibc_hca_hdl_t hca, ibc_qp_hdl_t qp,
    ibt_cep_modify_flags_t flags, ibt_qp_info_t *info_p,
    ibt_queue_sizes_t *actual_sz)
{
	hermon_state_t	*state;
	hermon_qphdl_t	qphdl;
	int		status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid QP handle */
	if (qp == NULL) {
		return (IBT_QP_HDL_INVALID);
	}

	/* Grab the Hermon softstate pointer and QP handle */
	state = (hermon_state_t *)hca;
	qphdl = (hermon_qphdl_t)qp;

	/* Modify the QP */
	status = hermon_qp_modify(state, qphdl, flags, info_p, actual_sz);
	return (status);
}


/*
 * hermon_ci_alloc_cq()
 *    Allocate a Completion Queue
 *    Context: Can be called only from user or kernel context.
 */
/* ARGSUSED */
static ibt_status_t
hermon_ci_alloc_cq(ibc_hca_hdl_t hca, ibt_cq_hdl_t ibt_cqhdl,
    ibt_cq_attr_t *attr_p, ibc_cq_hdl_t *cq_p, uint_t *actual_size)
{
	hermon_state_t	*state;
	hermon_cqhdl_t	cqhdl;
	int		status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}
	/* Grab the Hermon softstate pointer */
	state = (hermon_state_t *)hca;


	/* Allocate the CQ */
	status = hermon_cq_alloc(state, ibt_cqhdl, attr_p, actual_size,
	    &cqhdl, HERMON_NOSLEEP);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	/* Return the Hermon CQ handle */
	*cq_p = (ibc_cq_hdl_t)cqhdl;

	return (IBT_SUCCESS);
}


/*
 * hermon_ci_free_cq()
 *    Free a Completion Queue
 *    Context: Can be called only from user or kernel context.
 */
static ibt_status_t
hermon_ci_free_cq(ibc_hca_hdl_t hca, ibc_cq_hdl_t cq)
{
	hermon_state_t	*state;
	hermon_cqhdl_t	cqhdl;
	int		status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid CQ handle pointer */
	if (cq == NULL) {
		return (IBT_CQ_HDL_INVALID);
	}

	/* Grab the Hermon softstate pointer and CQ handle */
	state = (hermon_state_t *)hca;
	cqhdl = (hermon_cqhdl_t)cq;


	/* Free the CQ */
	status = hermon_cq_free(state, &cqhdl, HERMON_NOSLEEP);
	return (status);
}


/*
 * hermon_ci_query_cq()
 *    Return the size of a Completion Queue
 *    Context: Can be called only from user or kernel context.
 */
static ibt_status_t
hermon_ci_query_cq(ibc_hca_hdl_t hca, ibc_cq_hdl_t cq, uint_t *entries_p,
    uint_t *count_p, uint_t *usec_p, ibt_cq_handler_id_t *hid_p)
{
	hermon_cqhdl_t	cqhdl;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid CQ handle pointer */
	if (cq == NULL) {
		return (IBT_CQ_HDL_INVALID);
	}

	/* Grab the CQ handle */
	cqhdl = (hermon_cqhdl_t)cq;

	/* Query the current CQ size */
	*entries_p = cqhdl->cq_bufsz;
	*count_p = cqhdl->cq_intmod_count;
	*usec_p = cqhdl->cq_intmod_usec;
	*hid_p = 0;

	return (IBT_SUCCESS);
}


/*
 * hermon_ci_resize_cq()
 *    Change the size of a Completion Queue
 *    Context: Can be called only from user or kernel context.
 */
static ibt_status_t
hermon_ci_resize_cq(ibc_hca_hdl_t hca, ibc_cq_hdl_t cq, uint_t size,
    uint_t *actual_size)
{
	hermon_state_t		*state;
	hermon_cqhdl_t		cqhdl;
	int			status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid CQ handle pointer */
	if (cq == NULL) {
		return (IBT_CQ_HDL_INVALID);
	}

	/* Grab the Hermon softstate pointer and CQ handle */
	state = (hermon_state_t *)hca;
	cqhdl = (hermon_cqhdl_t)cq;

	/* Resize the CQ */
	status = hermon_cq_resize(state, cqhdl, size, actual_size,
	    HERMON_NOSLEEP);
	if (status != DDI_SUCCESS) {
		return (status);
	}
	return (IBT_SUCCESS);
}

/*
 * hermon_ci_modify_cq()
 *    Change the interrupt moderation values of a Completion Queue
 *    Context: Can be called only from user or kernel context.
 */
static ibt_status_t
hermon_ci_modify_cq(ibc_hca_hdl_t hca, ibc_cq_hdl_t cq, uint_t count,
    uint_t usec, ibt_cq_handler_id_t hid)
{
	hermon_state_t		*state;
	hermon_cqhdl_t		cqhdl;
	int			status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid CQ handle pointer */
	if (cq == NULL) {
		return (IBT_CQ_HDL_INVALID);
	}

	/* Grab the Hermon softstate pointer and CQ handle */
	state = (hermon_state_t *)hca;
	cqhdl = (hermon_cqhdl_t)cq;

	/* Resize the CQ */
	status = hermon_cq_modify(state, cqhdl, count, usec, hid,
	    HERMON_NOSLEEP);
	return (status);
}


/*
 * hermon_ci_alloc_cq_sched()
 *    Reserve a CQ scheduling class resource
 *    Context: Can be called only from user or kernel context.
 */
/* ARGSUSED */
static ibt_status_t
hermon_ci_alloc_cq_sched(ibc_hca_hdl_t hca, ibt_cq_sched_flags_t flags,
    ibc_cq_handler_attr_t *handler_attr_p)
{
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/*
	 * This is an unsupported interface for the Hermon driver.  Hermon
	 * does not support CQ scheduling classes.
	 */

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*handler_attr_p))
	handler_attr_p->h_id = NULL;
	handler_attr_p->h_pri = 0;
	handler_attr_p->h_bind = NULL;
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*handler_attr_p))
	return (IBT_SUCCESS);
}


/*
 * hermon_ci_free_cq_sched()
 *    Free a CQ scheduling class resource
 *    Context: Can be called only from user or kernel context.
 */
static ibt_status_t
hermon_ci_free_cq_sched(ibc_hca_hdl_t hca, ibt_cq_handler_id_t handler_id)
{
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/*
	 * This is an unsupported interface for the Hermon driver.  Hermon
	 * does not support CQ scheduling classes.  Returning a NULL
	 * hint is the way to treat this as unsupported.  We check for
	 * the expected NULL, but do not fail in any case.
	 */
	if (handler_id != NULL) {
		cmn_err(CE_NOTE, "hermon_ci_free_cq_sched: unexpected "
		    "non-NULL handler_id\n");
	}
	return (IBT_SUCCESS);
}


/*
 * hermon_ci_alloc_eec()
 *    Allocate an End-to-End context
 *    Context: Can be called only from user or kernel context.
 */
/* ARGSUSED */
static ibt_status_t
hermon_ci_alloc_eec(ibc_hca_hdl_t hca, ibc_eec_flags_t flags,
    ibt_eec_hdl_t ibt_eec, ibc_rdd_hdl_t rdd, ibc_eec_hdl_t *eec_p)
{
	/*
	 * This is an unsupported interface for the Hermon driver.  This
	 * interface is necessary to support Reliable Datagram (RD)
	 * operations.  Hermon does not support RD.
	 */
	return (IBT_NOT_SUPPORTED);
}


/*
 * hermon_ci_free_eec()
 *    Free an End-to-End context
 *    Context: Can be called only from user or kernel context.
 */
/* ARGSUSED */
static ibt_status_t
hermon_ci_free_eec(ibc_hca_hdl_t hca, ibc_eec_hdl_t eec)
{
	/*
	 * This is an unsupported interface for the Hermon driver.  This
	 * interface is necessary to support Reliable Datagram (RD)
	 * operations.  Hermon does not support RD.
	 */
	return (IBT_NOT_SUPPORTED);
}


/*
 * hermon_ci_query_eec()
 *    Query an End-to-End context
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static ibt_status_t
hermon_ci_query_eec(ibc_hca_hdl_t hca, ibc_eec_hdl_t eec,
    ibt_eec_query_attr_t *attr_p)
{
	/*
	 * This is an unsupported interface for the Hermon driver.  This
	 * interface is necessary to support Reliable Datagram (RD)
	 * operations.  Hermon does not support RD.
	 */
	return (IBT_NOT_SUPPORTED);
}


/*
 * hermon_ci_modify_eec()
 *    Modify an End-to-End context
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static ibt_status_t
hermon_ci_modify_eec(ibc_hca_hdl_t hca, ibc_eec_hdl_t eec,
    ibt_cep_modify_flags_t flags, ibt_eec_info_t *info_p)
{
	/*
	 * This is an unsupported interface for the Hermon driver.  This
	 * interface is necessary to support Reliable Datagram (RD)
	 * operations.  Hermon does not support RD.
	 */
	return (IBT_NOT_SUPPORTED);
}


/*
 * hermon_ci_register_mr()
 *    Prepare a virtually addressed Memory Region for use by an HCA
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static ibt_status_t
hermon_ci_register_mr(ibc_hca_hdl_t hca, ibc_pd_hdl_t pd,
    ibt_mr_attr_t *mr_attr, void *ibtl_reserved, ibc_mr_hdl_t *mr_p,
    ibt_mr_desc_t *mr_desc)
{
	hermon_mr_options_t	op;
	hermon_state_t		*state;
	hermon_pdhdl_t		pdhdl;
	hermon_mrhdl_t		mrhdl;
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

	/* Grab the Hermon softstate pointer and PD handle */
	state = (hermon_state_t *)hca;
	pdhdl = (hermon_pdhdl_t)pd;

	/* Register the memory region */
	op.mro_bind_type   = state->hs_cfg_profile->cp_iommu_bypass;
	op.mro_bind_dmahdl = NULL;
	op.mro_bind_override_addr = 0;
	status = hermon_mr_register(state, pdhdl, mr_attr, &mrhdl,
	    &op, HERMON_MPT_DMPT);
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

	/* Return the Hermon MR handle */
	*mr_p = (ibc_mr_hdl_t)mrhdl;

	return (IBT_SUCCESS);
}


/*
 * hermon_ci_register_buf()
 *    Prepare a Memory Region specified by buf structure for use by an HCA
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static ibt_status_t
hermon_ci_register_buf(ibc_hca_hdl_t hca, ibc_pd_hdl_t pd,
    ibt_smr_attr_t *attrp, struct buf *buf, void *ibtl_reserved,
    ibt_mr_hdl_t *mr_p, ibt_mr_desc_t *mr_desc)
{
	hermon_mr_options_t	op;
	hermon_state_t		*state;
	hermon_pdhdl_t		pdhdl;
	hermon_mrhdl_t		mrhdl;
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

	/* Grab the Hermon softstate pointer and PD handle */
	state = (hermon_state_t *)hca;
	pdhdl = (hermon_pdhdl_t)pd;

	/* Register the memory region */
	op.mro_bind_type   = state->hs_cfg_profile->cp_iommu_bypass;
	op.mro_bind_dmahdl = NULL;
	op.mro_bind_override_addr = 0;
	status = hermon_mr_register_buf(state, pdhdl, attrp, buf,
	    &mrhdl, &op, HERMON_MPT_DMPT);
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

	/* Return the Hermon MR handle */
	*mr_p = (ibc_mr_hdl_t)mrhdl;

	return (IBT_SUCCESS);
}


/*
 * hermon_ci_deregister_mr()
 *    Deregister a Memory Region from an HCA translation table
 *    Context: Can be called only from user or kernel context.
 */
static ibt_status_t
hermon_ci_deregister_mr(ibc_hca_hdl_t hca, ibc_mr_hdl_t mr)
{
	hermon_state_t		*state;
	hermon_mrhdl_t		mrhdl;
	int			status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid memory region handle */
	if (mr == NULL) {
		return (IBT_MR_HDL_INVALID);
	}

	/* Grab the Hermon softstate pointer */
	state = (hermon_state_t *)hca;
	mrhdl = (hermon_mrhdl_t)mr;

	/*
	 * Deregister the memory region.
	 */
	status = hermon_mr_deregister(state, &mrhdl, HERMON_MR_DEREG_ALL,
	    HERMON_NOSLEEP);
	return (status);
}


/*
 * hermon_ci_query_mr()
 *    Retrieve information about a specified Memory Region
 *    Context: Can be called from interrupt or base context.
 */
static ibt_status_t
hermon_ci_query_mr(ibc_hca_hdl_t hca, ibc_mr_hdl_t mr,
    ibt_mr_query_attr_t *mr_attr)
{
	hermon_state_t		*state;
	hermon_mrhdl_t		mrhdl;
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

	/* Grab the Hermon softstate pointer and MR handle */
	state = (hermon_state_t *)hca;
	mrhdl = (hermon_mrhdl_t)mr;

	/* Query the memory region */
	status = hermon_mr_query(state, mrhdl, mr_attr);
	return (status);
}


/*
 * hermon_ci_register_shared_mr()
 *    Create a shared memory region matching an existing Memory Region
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static ibt_status_t
hermon_ci_register_shared_mr(ibc_hca_hdl_t hca, ibc_mr_hdl_t mr,
    ibc_pd_hdl_t pd, ibt_smr_attr_t *mr_attr, void *ibtl_reserved,
    ibc_mr_hdl_t *mr_p, ibt_mr_desc_t *mr_desc)
{
	hermon_state_t		*state;
	hermon_pdhdl_t		pdhdl;
	hermon_mrhdl_t		mrhdl, mrhdl_new;
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

	/* Grab the Hermon softstate pointer and handles */
	state = (hermon_state_t *)hca;
	pdhdl = (hermon_pdhdl_t)pd;
	mrhdl = (hermon_mrhdl_t)mr;

	/* Register the shared memory region */
	status = hermon_mr_register_shared(state, mrhdl, pdhdl, mr_attr,
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

	/* Return the Hermon MR handle */
	*mr_p = (ibc_mr_hdl_t)mrhdl_new;

	return (IBT_SUCCESS);
}


/*
 * hermon_ci_reregister_mr()
 *    Modify the attributes of an existing Memory Region
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static ibt_status_t
hermon_ci_reregister_mr(ibc_hca_hdl_t hca, ibc_mr_hdl_t mr, ibc_pd_hdl_t pd,
    ibt_mr_attr_t *mr_attr, void *ibtl_reserved, ibc_mr_hdl_t *mr_new,
    ibt_mr_desc_t *mr_desc)
{
	hermon_mr_options_t	op;
	hermon_state_t		*state;
	hermon_pdhdl_t		pdhdl;
	hermon_mrhdl_t		mrhdl, mrhdl_new;
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

	/* Grab the Hermon softstate pointer, mrhdl, and pdhdl */
	state = (hermon_state_t *)hca;
	mrhdl = (hermon_mrhdl_t)mr;
	pdhdl = (hermon_pdhdl_t)pd;

	/* Reregister the memory region */
	op.mro_bind_type = state->hs_cfg_profile->cp_iommu_bypass;
	status = hermon_mr_reregister(state, mrhdl, pdhdl, mr_attr,
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

	/* Return the Hermon MR handle */
	*mr_new = (ibc_mr_hdl_t)mrhdl_new;

	return (IBT_SUCCESS);
}


/*
 * hermon_ci_reregister_buf()
 *    Modify the attributes of an existing Memory Region
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static ibt_status_t
hermon_ci_reregister_buf(ibc_hca_hdl_t hca, ibc_mr_hdl_t mr, ibc_pd_hdl_t pd,
    ibt_smr_attr_t *attrp, struct buf *buf, void *ibtl_reserved,
    ibc_mr_hdl_t *mr_new, ibt_mr_desc_t *mr_desc)
{
	hermon_mr_options_t	op;
	hermon_state_t		*state;
	hermon_pdhdl_t		pdhdl;
	hermon_mrhdl_t		mrhdl, mrhdl_new;
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

	/* Grab the Hermon softstate pointer, mrhdl, and pdhdl */
	state = (hermon_state_t *)hca;
	mrhdl = (hermon_mrhdl_t)mr;
	pdhdl = (hermon_pdhdl_t)pd;

	/* Reregister the memory region */
	op.mro_bind_type = state->hs_cfg_profile->cp_iommu_bypass;
	status = hermon_mr_reregister_buf(state, mrhdl, pdhdl, attrp, buf,
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

	/* Return the Hermon MR handle */
	*mr_new = (ibc_mr_hdl_t)mrhdl_new;

	return (IBT_SUCCESS);
}

/*
 * hermon_ci_sync_mr()
 *    Synchronize access to a Memory Region
 *    Context: Can be called from interrupt or base context.
 */
static ibt_status_t
hermon_ci_sync_mr(ibc_hca_hdl_t hca, ibt_mr_sync_t *mr_segs, size_t num_segs)
{
	hermon_state_t		*state;
	int			status;

	ASSERT(mr_segs != NULL);

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Grab the Hermon softstate pointer */
	state = (hermon_state_t *)hca;

	/* Sync the memory region */
	status = hermon_mr_sync(state, mr_segs, num_segs);
	return (status);
}


/*
 * hermon_ci_alloc_mw()
 *    Allocate a Memory Window
 *    Context: Can be called from interrupt or base context.
 */
static ibt_status_t
hermon_ci_alloc_mw(ibc_hca_hdl_t hca, ibc_pd_hdl_t pd, ibt_mw_flags_t flags,
    ibc_mw_hdl_t *mw_p, ibt_rkey_t *rkey_p)
{
	hermon_state_t		*state;
	hermon_pdhdl_t		pdhdl;
	hermon_mwhdl_t		mwhdl;
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

	/* Grab the Hermon softstate pointer and PD handle */
	state = (hermon_state_t *)hca;
	pdhdl = (hermon_pdhdl_t)pd;

	/* Allocate the memory window */
	status = hermon_mw_alloc(state, pdhdl, flags, &mwhdl);
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
 * hermon_ci_free_mw()
 *    Free a Memory Window
 *    Context: Can be called from interrupt or base context.
 */
static ibt_status_t
hermon_ci_free_mw(ibc_hca_hdl_t hca, ibc_mw_hdl_t mw)
{
	hermon_state_t		*state;
	hermon_mwhdl_t		mwhdl;
	int			status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid MW handle */
	if (mw == NULL) {
		return (IBT_MW_HDL_INVALID);
	}

	/* Grab the Hermon softstate pointer and MW handle */
	state = (hermon_state_t *)hca;
	mwhdl = (hermon_mwhdl_t)mw;

	/* Free the memory window */
	status = hermon_mw_free(state, &mwhdl, HERMON_NOSLEEP);
	return (status);
}


/*
 * hermon_ci_query_mw()
 *    Return the attributes of the specified Memory Window
 *    Context: Can be called from interrupt or base context.
 */
static ibt_status_t
hermon_ci_query_mw(ibc_hca_hdl_t hca, ibc_mw_hdl_t mw,
    ibt_mw_query_attr_t *mw_attr_p)
{
	hermon_mwhdl_t		mwhdl;

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
	mwhdl = (hermon_mwhdl_t)mw;
	mutex_enter(&mwhdl->mr_lock);
	mw_attr_p->mw_pd   = (ibc_pd_hdl_t)mwhdl->mr_pdhdl;
	mw_attr_p->mw_rkey = mwhdl->mr_rkey;
	mutex_exit(&mwhdl->mr_lock);

	return (IBT_SUCCESS);
}


/*
 * hermon_ci_attach_mcg()
 *    Attach a Queue Pair to a Multicast Group
 *    Context: Can be called only from user or kernel context.
 */
static ibt_status_t
hermon_ci_attach_mcg(ibc_hca_hdl_t hca, ibc_qp_hdl_t qp, ib_gid_t gid,
    ib_lid_t lid)
{
	hermon_state_t		*state;
	hermon_qphdl_t		qphdl;
	int			status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid QP handle pointer */
	if (qp == NULL) {
		return (IBT_QP_HDL_INVALID);
	}

	/* Grab the Hermon softstate pointer and QP handles */
	state = (hermon_state_t *)hca;
	qphdl = (hermon_qphdl_t)qp;

	/* Attach the QP to the multicast group */
	status = hermon_mcg_attach(state, qphdl, gid, lid);
	return (status);
}


/*
 * hermon_ci_detach_mcg()
 *    Detach a Queue Pair to a Multicast Group
 *    Context: Can be called only from user or kernel context.
 */
static ibt_status_t
hermon_ci_detach_mcg(ibc_hca_hdl_t hca, ibc_qp_hdl_t qp, ib_gid_t gid,
    ib_lid_t lid)
{
	hermon_state_t		*state;
	hermon_qphdl_t		qphdl;
	int			status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid QP handle pointer */
	if (qp == NULL) {
		return (IBT_QP_HDL_INVALID);
	}

	/* Grab the Hermon softstate pointer and QP handle */
	state = (hermon_state_t *)hca;
	qphdl = (hermon_qphdl_t)qp;

	/* Detach the QP from the multicast group */
	status = hermon_mcg_detach(state, qphdl, gid, lid);
	return (status);
}


/*
 * hermon_ci_post_send()
 *    Post send work requests to the send queue on the specified QP
 *    Context: Can be called from interrupt or base context.
 */
static ibt_status_t
hermon_ci_post_send(ibc_hca_hdl_t hca, ibc_qp_hdl_t qp, ibt_send_wr_t *wr_p,
    uint_t num_wr, uint_t *num_posted_p)
{
	hermon_state_t		*state;
	hermon_qphdl_t		qphdl;
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

	/* Grab the Hermon softstate pointer and QP handle */
	state = (hermon_state_t *)hca;
	qphdl = (hermon_qphdl_t)qp;

	/* Post the send WQEs */
	status = hermon_post_send(state, qphdl, wr_p, num_wr, num_posted_p);
	return (status);
}


/*
 * hermon_ci_post_recv()
 *    Post receive work requests to the receive queue on the specified QP
 *    Context: Can be called from interrupt or base context.
 */
static ibt_status_t
hermon_ci_post_recv(ibc_hca_hdl_t hca, ibc_qp_hdl_t qp, ibt_recv_wr_t *wr_p,
    uint_t num_wr, uint_t *num_posted_p)
{
	hermon_state_t		*state;
	hermon_qphdl_t		qphdl;
	int			status;

	ASSERT(wr_p != NULL);
	ASSERT(num_wr != 0);

	state = (hermon_state_t *)hca;
	qphdl = (hermon_qphdl_t)qp;

	if (state == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid QP handle pointer */
	if (qphdl == NULL) {
		return (IBT_QP_HDL_INVALID);
	}

	/* Post the receive WQEs */
	status = hermon_post_recv(state, qphdl, wr_p, num_wr, num_posted_p);
	return (status);
}


/*
 * hermon_ci_poll_cq()
 *    Poll for a work request completion
 *    Context: Can be called from interrupt or base context.
 */
static ibt_status_t
hermon_ci_poll_cq(ibc_hca_hdl_t hca, ibc_cq_hdl_t cq, ibt_wc_t *wc_p,
    uint_t num_wc, uint_t *num_polled)
{
	hermon_state_t		*state;
	hermon_cqhdl_t		cqhdl;
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

	/* Grab the Hermon softstate pointer and CQ handle */
	state = (hermon_state_t *)hca;
	cqhdl = (hermon_cqhdl_t)cq;

	/* Poll for work request completions */
	status = hermon_cq_poll(state, cqhdl, wc_p, num_wc, num_polled);
	return (status);
}


/*
 * hermon_ci_notify_cq()
 *    Enable notification events on the specified CQ
 *    Context: Can be called from interrupt or base context.
 */
static ibt_status_t
hermon_ci_notify_cq(ibc_hca_hdl_t hca, ibc_cq_hdl_t cq_hdl,
    ibt_cq_notify_flags_t flags)
{
	hermon_state_t		*state;
	hermon_cqhdl_t		cqhdl;
	int			status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid CQ handle pointer */
	if (cq_hdl == NULL) {
		return (IBT_CQ_HDL_INVALID);
	}

	/* Grab the Hermon softstate pointer and CQ handle */
	state = (hermon_state_t *)hca;
	cqhdl = (hermon_cqhdl_t)cq_hdl;

	/* Enable the CQ notification */
	status = hermon_cq_notify(state, cqhdl, flags);
	return (status);
}

/*
 * hermon_ci_ci_data_in()
 *    Exchange CI-specific data.
 *    Context: Can be called only from user or kernel context.
 */
static ibt_status_t
hermon_ci_ci_data_in(ibc_hca_hdl_t hca, ibt_ci_data_flags_t flags,
    ibt_object_type_t object, void *ibc_object_handle, void *data_p,
    size_t data_sz)
{
	hermon_state_t		*state;
	int			status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Grab the Hermon softstate pointer */
	state = (hermon_state_t *)hca;

	/* Get the Hermon userland mapping information */
	status = hermon_umap_ci_data_in(state, flags, object,
	    ibc_object_handle, data_p, data_sz);
	return (status);
}

/*
 * hermon_ci_ci_data_out()
 *    Exchange CI-specific data.
 *    Context: Can be called only from user or kernel context.
 */
static ibt_status_t
hermon_ci_ci_data_out(ibc_hca_hdl_t hca, ibt_ci_data_flags_t flags,
    ibt_object_type_t object, void *ibc_object_handle, void *data_p,
    size_t data_sz)
{
	hermon_state_t		*state;
	int			status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Grab the Hermon softstate pointer */
	state = (hermon_state_t *)hca;

	/* Get the Hermon userland mapping information */
	status = hermon_umap_ci_data_out(state, flags, object,
	    ibc_object_handle, data_p, data_sz);
	return (status);
}


/*
 * hermon_ci_alloc_srq()
 *    Allocate a Shared Receive Queue (SRQ)
 *    Context: Can be called only from user or kernel context
 */
static ibt_status_t
hermon_ci_alloc_srq(ibc_hca_hdl_t hca, ibt_srq_flags_t flags,
    ibt_srq_hdl_t ibt_srq, ibc_pd_hdl_t pd, ibt_srq_sizes_t *sizes,
    ibc_srq_hdl_t *ibc_srq_p, ibt_srq_sizes_t *ret_sizes_p)
{
	hermon_state_t		*state;
	hermon_pdhdl_t		pdhdl;
	hermon_srqhdl_t		srqhdl;
	hermon_srq_info_t	srqinfo;
	int			status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	state = (hermon_state_t *)hca;

	/* Check for valid PD handle pointer */
	if (pd == NULL) {
		return (IBT_PD_HDL_INVALID);
	}

	pdhdl = (hermon_pdhdl_t)pd;

	srqinfo.srqi_ibt_srqhdl = ibt_srq;
	srqinfo.srqi_pd		= pdhdl;
	srqinfo.srqi_sizes	= sizes;
	srqinfo.srqi_real_sizes	= ret_sizes_p;
	srqinfo.srqi_srqhdl	= &srqhdl;
	srqinfo.srqi_flags	= flags;

	status = hermon_srq_alloc(state, &srqinfo, HERMON_NOSLEEP);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	*ibc_srq_p = (ibc_srq_hdl_t)srqhdl;

	return (IBT_SUCCESS);
}

/*
 * hermon_ci_free_srq()
 *    Free a Shared Receive Queue (SRQ)
 *    Context: Can be called only from user or kernel context
 */
static ibt_status_t
hermon_ci_free_srq(ibc_hca_hdl_t hca, ibc_srq_hdl_t srq)
{
	hermon_state_t	*state;
	hermon_srqhdl_t	srqhdl;
	int		status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	state = (hermon_state_t *)hca;

	/* Check for valid SRQ handle pointer */
	if (srq == NULL) {
		return (IBT_SRQ_HDL_INVALID);
	}

	srqhdl = (hermon_srqhdl_t)srq;

	/* Free the SRQ */
	status = hermon_srq_free(state, &srqhdl, HERMON_NOSLEEP);
	return (status);
}

/*
 * hermon_ci_query_srq()
 *    Query properties of a Shared Receive Queue (SRQ)
 *    Context: Can be called from interrupt or base context.
 */
static ibt_status_t
hermon_ci_query_srq(ibc_hca_hdl_t hca, ibc_srq_hdl_t srq, ibc_pd_hdl_t *pd_p,
    ibt_srq_sizes_t *sizes_p, uint_t *limit_p)
{
	hermon_srqhdl_t	srqhdl;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid SRQ handle pointer */
	if (srq == NULL) {
		return (IBT_SRQ_HDL_INVALID);
	}

	srqhdl = (hermon_srqhdl_t)srq;

	mutex_enter(&srqhdl->srq_lock);
	if (srqhdl->srq_state == HERMON_SRQ_STATE_ERROR) {
		mutex_exit(&srqhdl->srq_lock);
		return (IBT_SRQ_ERROR_STATE);
	}

	*pd_p   = (ibc_pd_hdl_t)srqhdl->srq_pdhdl;
	sizes_p->srq_wr_sz = srqhdl->srq_real_sizes.srq_wr_sz - 1;
	sizes_p->srq_sgl_sz = srqhdl->srq_real_sizes.srq_sgl_sz;
	mutex_exit(&srqhdl->srq_lock);
	*limit_p  = 0;

	return (IBT_SUCCESS);
}

/*
 * hermon_ci_modify_srq()
 *    Modify properties of a Shared Receive Queue (SRQ)
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static ibt_status_t
hermon_ci_modify_srq(ibc_hca_hdl_t hca, ibc_srq_hdl_t srq,
    ibt_srq_modify_flags_t flags, uint_t size, uint_t limit, uint_t *ret_size_p)
{
	hermon_state_t	*state;
	hermon_srqhdl_t	srqhdl;
	uint_t		resize_supported, cur_srq_size;
	int		status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	state = (hermon_state_t *)hca;

	/* Check for valid SRQ handle pointer */
	if (srq == NULL) {
		return (IBT_SRQ_HDL_INVALID);
	}

	srqhdl = (hermon_srqhdl_t)srq;

	/*
	 * Check Error State of SRQ.
	 * Also, while we are holding the lock we save away the current SRQ
	 * size for later use.
	 */
	mutex_enter(&srqhdl->srq_lock);
	cur_srq_size = srqhdl->srq_wq_bufsz;
	if (srqhdl->srq_state == HERMON_SRQ_STATE_ERROR) {
		mutex_exit(&srqhdl->srq_lock);
		return (IBT_SRQ_ERROR_STATE);
	}
	mutex_exit(&srqhdl->srq_lock);

	/*
	 * Setting the limit watermark is not currently supported.  This is a
	 * hermon hardware (firmware) limitation.  We return NOT_SUPPORTED here,
	 * and have the limit code commented out for now.
	 *
	 * XXX If we enable the limit watermark support, we need to do checks
	 * and set the 'srq->srq_wr_limit' here, instead of returning not
	 * supported.  The 'hermon_srq_modify' operation below is for resizing
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

	resize_supported = state->hs_ibtfinfo.hca_attr->hca_flags &
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

	status = hermon_srq_modify(state, srqhdl, size, ret_size_p,
	    HERMON_NOSLEEP);
	if (status != DDI_SUCCESS) {
		/* Set return value to current SRQ size */
		*ret_size_p = cur_srq_size;
		return (status);
	}

	return (IBT_SUCCESS);
}

/*
 * hermon_ci_post_srq()
 *    Post a Work Request to the specified Shared Receive Queue (SRQ)
 *    Context: Can be called from interrupt or base context.
 */
static ibt_status_t
hermon_ci_post_srq(ibc_hca_hdl_t hca, ibc_srq_hdl_t srq,
    ibt_recv_wr_t *wr, uint_t num_wr, uint_t *num_posted_p)
{
	hermon_state_t	*state;
	hermon_srqhdl_t	srqhdl;
	int		status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	state = (hermon_state_t *)hca;

	/* Check for valid SRQ handle pointer */
	if (srq == NULL) {
		return (IBT_SRQ_HDL_INVALID);
	}

	srqhdl = (hermon_srqhdl_t)srq;

	status = hermon_post_srq(state, srqhdl, wr, num_wr, num_posted_p);
	return (status);
}

/* Address translation */
/*
 * hermon_ci_map_mem_area()
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static ibt_status_t
hermon_ci_map_mem_area(ibc_hca_hdl_t hca, ibt_va_attr_t *va_attrs,
    void *ibtl_reserved, uint_t list_len, ibt_phys_buf_t *paddr_list_p,
    uint_t *ret_num_paddr_p, size_t *paddr_buf_sz_p,
    ib_memlen_t *paddr_offset_p, ibc_ma_hdl_t *ibc_ma_hdl_p)
{
	hermon_state_t		*state;
	uint_t			cookiecnt;
	int			status;

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*paddr_list_p))

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	if ((va_attrs->va_flags & IBT_VA_BUF) && (va_attrs->va_buf == NULL)) {
		return (IBT_INVALID_PARAM);
	}

	state = (hermon_state_t *)hca;

	/*
	 * Based on the length of the buffer and the paddr_list passed in,
	 * retrieve DMA cookies for the virtual to physical address
	 * translation.
	 */
	status = hermon_get_dma_cookies(state, paddr_list_p, va_attrs,
	    list_len, &cookiecnt, ibc_ma_hdl_p);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	/*
	 * Split the cookies returned from 'hermon_get_dma_cookies() above.  We
	 * also pass in the size of the cookies we would like.
	 * Note: for now, we only support PAGESIZE cookies.
	 */
	status = hermon_split_dma_cookies(state, paddr_list_p, paddr_offset_p,
	    list_len, &cookiecnt, PAGESIZE);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	/*  Setup return values */
	*ret_num_paddr_p = cookiecnt;
	*paddr_buf_sz_p = PAGESIZE;

	return (IBT_SUCCESS);
}

/*
 * hermon_ci_unmap_mem_area()
 * Unmap the memory area
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static ibt_status_t
hermon_ci_unmap_mem_area(ibc_hca_hdl_t hca, ibc_ma_hdl_t ma_hdl)
{
	int			status = DDI_SUCCESS;

	if (ma_hdl == NULL) {
		return (IBT_MI_HDL_INVALID);
	}

	status = hermon_free_dma_cookies(ma_hdl);
	if (status != DDI_SUCCESS) {
		return (ibc_get_ci_failure(0));
	}
	return (IBT_SUCCESS);
}

struct ibc_mi_s {
	int			imh_len;
	ddi_dma_handle_t	imh_dmahandle[1];
};
_NOTE(SCHEME_PROTECTS_DATA("safe sharing",
    ibc_mi_s::imh_len
    ibc_mi_s::imh_dmahandle))


/*
 * hermon_ci_map_mem_iov()
 * Map the memory
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static ibt_status_t
hermon_ci_map_mem_iov(ibc_hca_hdl_t hca, ibt_iov_attr_t *iov_attr,
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
	hermon_state_t		*state;
	int			kmflag;
	int			(*callback)(caddr_t);

	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*wr))

	if (mi_hdl_p == NULL)
		return (IBT_MI_HDL_INVALID);

	/* Check for valid HCA handle */
	if (hca == NULL)
		return (IBT_HCA_HDL_INVALID);

	state = (hermon_state_t *)hca;
	hermon_dma_attr_init(state, &dma_attr);

	nds = 0;
	max_nds = iov_attr->iov_wr_nds;
	if (iov_attr->iov_lso_hdr_sz)
		max_nds -= (iov_attr->iov_lso_hdr_sz + sizeof (uint32_t) +
		    0xf) >> 4;	/* 0xf is for rounding up to a multiple of 16 */
	rsvd_lkey = state->hs_devlim.rsv_lkey;
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

		status = ddi_dma_alloc_handle(state->hs_dip, &dma_attr,
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
			if (nds >= max_nds) {
				status = ddi_dma_unbind_handle(dmahdl);
				if (status != DDI_SUCCESS)
					HERMON_WARNING(state, "failed to "
					    "unbind DMA mapping");
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
		status = ddi_dma_alloc_handle(state->hs_dip, &dma_attr,
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
		if (nds + cookie_cnt >= max_nds) {
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
		if (status != DDI_SUCCESS)
			HERMON_WARNING(state, "failed to unbind DMA mapping");
		ddi_dma_free_handle(&mi_hdl->imh_dmahandle[i]);
	}
	kmem_free(mi_hdl, sizeof (*mi_hdl) +
	    (len - 1) * sizeof (ddi_dma_handle_t));
	*mi_hdl_p = NULL;
	return (ibt_status);
}

/*
 * hermon_ci_unmap_mem_iov()
 * Unmap the memory
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static ibt_status_t
hermon_ci_unmap_mem_iov(ibc_hca_hdl_t hca, ibc_mi_hdl_t mi_hdl)
{
	int		status, i;
	hermon_state_t	*state;

	/* Check for valid HCA handle */
	if (hca == NULL)
		return (IBT_HCA_HDL_INVALID);

	state = (hermon_state_t *)hca;

	if (mi_hdl == NULL)
		return (IBT_MI_HDL_INVALID);

	for (i = 0; i < mi_hdl->imh_len; i++) {
		status = ddi_dma_unbind_handle(mi_hdl->imh_dmahandle[i]);
		if (status != DDI_SUCCESS)
			HERMON_WARNING(state, "failed to unbind DMA mapping");
		ddi_dma_free_handle(&mi_hdl->imh_dmahandle[i]);
	}
	kmem_free(mi_hdl, sizeof (*mi_hdl) +
	    (mi_hdl->imh_len - 1) * sizeof (ddi_dma_handle_t));
	return (IBT_SUCCESS);
}

/* Allocate L_Key */
/*
 * hermon_ci_alloc_lkey()
 */
/* ARGSUSED */
static ibt_status_t
hermon_ci_alloc_lkey(ibc_hca_hdl_t hca, ibc_pd_hdl_t pd,
    ibt_lkey_flags_t flags, uint_t phys_buf_list_sz, ibc_mr_hdl_t *mr_p,
    ibt_pmr_desc_t *mem_desc_p)
{
	return (IBT_NOT_SUPPORTED);
}

/* Physical Register Memory Region */
/*
 * hermon_ci_register_physical_mr()
 */
/* ARGSUSED */
static ibt_status_t
hermon_ci_register_physical_mr(ibc_hca_hdl_t hca, ibc_pd_hdl_t pd,
    ibt_pmr_attr_t *mem_pattrs, void *ibtl_reserved, ibc_mr_hdl_t *mr_p,
    ibt_pmr_desc_t *mem_desc_p)
{
	return (IBT_NOT_SUPPORTED);
}

/*
 * hermon_ci_reregister_physical_mr()
 */
/* ARGSUSED */
static ibt_status_t
hermon_ci_reregister_physical_mr(ibc_hca_hdl_t hca, ibc_mr_hdl_t mr,
    ibc_pd_hdl_t pd, ibt_pmr_attr_t *mem_pattrs, void *ibtl_reserved,
    ibc_mr_hdl_t *mr_p, ibt_pmr_desc_t *mr_desc_p)
{
	return (IBT_NOT_SUPPORTED);
}

/* Mellanox FMR Support */
/*
 * hermon_ci_create_fmr_pool()
 * Creates a pool of memory regions suitable for FMR registration
 *    Context: Can be called from base context only
 */
static ibt_status_t
hermon_ci_create_fmr_pool(ibc_hca_hdl_t hca, ibc_pd_hdl_t pd,
    ibt_fmr_pool_attr_t *params, ibc_fmr_pool_hdl_t *fmr_pool_p)
{
	hermon_state_t	*state;
	hermon_pdhdl_t	pdhdl;
	hermon_fmrhdl_t	fmrpoolhdl;
	int		status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	state = (hermon_state_t *)hca;

	/* Check for valid PD handle pointer */
	if (pd == NULL) {
		return (IBT_PD_HDL_INVALID);
	}

	pdhdl = (hermon_pdhdl_t)pd;

	/*
	 * Validate the access flags.  Both Remote Write and Remote Atomic
	 * require the Local Write flag to be set
	 */
	if (((params->fmr_flags & IBT_MR_ENABLE_REMOTE_WRITE) ||
	    (params->fmr_flags & IBT_MR_ENABLE_REMOTE_ATOMIC)) &&
	    !(params->fmr_flags & IBT_MR_ENABLE_LOCAL_WRITE)) {
		return (IBT_MR_ACCESS_REQ_INVALID);
	}

	status = hermon_create_fmr_pool(state, pdhdl, params, &fmrpoolhdl);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	/* Set fmr_pool from hermon handle */
	*fmr_pool_p = (ibc_fmr_pool_hdl_t)fmrpoolhdl;

	return (IBT_SUCCESS);
}

/*
 * hermon_ci_destroy_fmr_pool()
 * Free all resources associated with an FMR pool.
 *    Context: Can be called from base context only.
 */
static ibt_status_t
hermon_ci_destroy_fmr_pool(ibc_hca_hdl_t hca, ibc_fmr_pool_hdl_t fmr_pool)
{
	hermon_state_t	*state;
	hermon_fmrhdl_t	fmrpoolhdl;
	int		status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	state = (hermon_state_t *)hca;

	/* Check for valid FMR Pool handle */
	if (fmr_pool == NULL) {
		return (IBT_FMR_POOL_HDL_INVALID);
	}

	fmrpoolhdl = (hermon_fmrhdl_t)fmr_pool;

	status = hermon_destroy_fmr_pool(state, fmrpoolhdl);
	return (status);
}

/*
 * hermon_ci_flush_fmr_pool()
 * Force a flush of the memory tables, cleaning up used FMR resources.
 *    Context: Can be called from interrupt or base context.
 */
static ibt_status_t
hermon_ci_flush_fmr_pool(ibc_hca_hdl_t hca, ibc_fmr_pool_hdl_t fmr_pool)
{
	hermon_state_t	*state;
	hermon_fmrhdl_t	fmrpoolhdl;
	int		status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	state = (hermon_state_t *)hca;

	/* Check for valid FMR Pool handle */
	if (fmr_pool == NULL) {
		return (IBT_FMR_POOL_HDL_INVALID);
	}

	fmrpoolhdl = (hermon_fmrhdl_t)fmr_pool;

	status = hermon_flush_fmr_pool(state, fmrpoolhdl);
	return (status);
}

/*
 * hermon_ci_register_physical_fmr()
 * From the 'pool' of FMR regions passed in, performs register physical
 * operation.
 *    Context: Can be called from interrupt or base context.
 */
/* ARGSUSED */
static ibt_status_t
hermon_ci_register_physical_fmr(ibc_hca_hdl_t hca,
    ibc_fmr_pool_hdl_t fmr_pool, ibt_pmr_attr_t *mem_pattr,
    void *ibtl_reserved, ibc_mr_hdl_t *mr_p, ibt_pmr_desc_t *mem_desc_p)
{
	hermon_state_t		*state;
	hermon_mrhdl_t		mrhdl;
	hermon_fmrhdl_t		fmrpoolhdl;
	int			status;

	ASSERT(mem_pattr != NULL);
	ASSERT(mr_p != NULL);
	ASSERT(mem_desc_p != NULL);

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Grab the Hermon softstate pointer */
	state = (hermon_state_t *)hca;

	/* Check for valid FMR Pool handle */
	if (fmr_pool == NULL) {
		return (IBT_FMR_POOL_HDL_INVALID);
	}

	fmrpoolhdl = (hermon_fmrhdl_t)fmr_pool;

	status = hermon_register_physical_fmr(state, fmrpoolhdl, mem_pattr,
	    &mrhdl, mem_desc_p);
	if (status != DDI_SUCCESS) {
		return (status);
	}

	/*
	 * If region is mapped for streaming (i.e. noncoherent), then set
	 * sync is required
	 */
	_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(*mem_desc_p))
	mem_desc_p->pmd_sync_required = (mrhdl->mr_bindinfo.bi_flags &
	    IBT_MR_NONCOHERENT) ? B_TRUE : B_FALSE;
	if (mem_desc_p->pmd_sync_required == B_TRUE) {
		/* Fill in DMA handle for future sync operations */
		_NOTE(NOW_INVISIBLE_TO_OTHER_THREADS(mrhdl->mr_bindinfo))
		mrhdl->mr_bindinfo.bi_dmahdl =
		    (ddi_dma_handle_t)mem_pattr->pmr_ma;
	}

	/* Return the Hermon MR handle */
	*mr_p = (ibc_mr_hdl_t)mrhdl;

	return (IBT_SUCCESS);
}

/*
 * hermon_ci_deregister_fmr()
 * Moves an FMR (specified by 'mr') to the deregistered state.
 *    Context: Can be called from base context only.
 */
static ibt_status_t
hermon_ci_deregister_fmr(ibc_hca_hdl_t hca, ibc_mr_hdl_t mr)
{
	hermon_state_t		*state;
	hermon_mrhdl_t		mrhdl;
	int			status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid memory region handle */
	if (mr == NULL) {
		return (IBT_MR_HDL_INVALID);
	}

	/* Grab the Hermon softstate pointer */
	state = (hermon_state_t *)hca;
	mrhdl = (hermon_mrhdl_t)mr;

	/*
	 * Deregister the memory region, either "unmap" the FMR or deregister
	 * the normal memory region.
	 */
	status = hermon_deregister_fmr(state, mrhdl);
	return (status);
}

static int
hermon_mem_alloc(hermon_state_t *state, size_t size, ibt_mr_flags_t flags,
    caddr_t *kaddrp, ibc_mem_alloc_hdl_t *mem_hdl)
{
	ddi_dma_handle_t	dma_hdl;
	ddi_dma_attr_t		dma_attr;
	ddi_acc_handle_t	acc_hdl;
	size_t			real_len;
	int			status;
	int			(*ddi_cb)(caddr_t);
	ibc_mem_alloc_hdl_t	mem_alloc_hdl;

	hermon_dma_attr_init(state, &dma_attr);

	ddi_cb = (flags & IBT_MR_NOSLEEP) ? DDI_DMA_DONTWAIT : DDI_DMA_SLEEP;

	/* Allocate a DMA handle */
	status = ddi_dma_alloc_handle(state->hs_dip, &dma_attr, ddi_cb,
	    NULL, &dma_hdl);
	if (status != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/* Allocate DMA memory */
	status = ddi_dma_mem_alloc(dma_hdl, size,
	    &state->hs_reg_accattr, DDI_DMA_CONSISTENT, ddi_cb,
	    NULL, kaddrp, &real_len, &acc_hdl);
	if (status != DDI_SUCCESS) {
		ddi_dma_free_handle(&dma_hdl);
		return (DDI_FAILURE);
	}

	/* Package the hermon_dma_info contents and return */
	mem_alloc_hdl = kmem_alloc(sizeof (**mem_hdl),
	    (flags & IBT_MR_NOSLEEP) ? KM_NOSLEEP : KM_SLEEP);
	if (mem_alloc_hdl == NULL) {
		ddi_dma_mem_free(&acc_hdl);
		ddi_dma_free_handle(&dma_hdl);
		return (DDI_FAILURE);
	}
	mem_alloc_hdl->ibc_dma_hdl = dma_hdl;
	mem_alloc_hdl->ibc_acc_hdl = acc_hdl;

	*mem_hdl = mem_alloc_hdl;

	return (DDI_SUCCESS);
}

/*
 * hermon_ci_alloc_io_mem()
 *	Allocate dma-able memory
 *
 */
static ibt_status_t
hermon_ci_alloc_io_mem(ibc_hca_hdl_t hca, size_t size, ibt_mr_flags_t mr_flag,
    caddr_t *kaddrp, ibc_mem_alloc_hdl_t *mem_alloc_hdl_p)
{
	hermon_state_t	*state;
	int		status;

	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid mem_alloc_hdl_p handle pointer */
	if (mem_alloc_hdl_p == NULL) {
		return (IBT_MEM_ALLOC_HDL_INVALID);
	}

	/* Grab the Hermon softstate pointer and mem handle */
	state = (hermon_state_t *)hca;

	/* Allocate the memory and handles */
	status = hermon_mem_alloc(state, size, mr_flag, kaddrp,
	    mem_alloc_hdl_p);

	if (status != DDI_SUCCESS) {
		*mem_alloc_hdl_p = NULL;
		*kaddrp = NULL;
		return (status);
	}

	return (IBT_SUCCESS);
}


/*
 * hermon_ci_free_io_mem()
 * Unbind handl and free the memory
 */
static ibt_status_t
hermon_ci_free_io_mem(ibc_hca_hdl_t hca, ibc_mem_alloc_hdl_t mem_alloc_hdl)
{
	/* Check for valid HCA handle */
	if (hca == NULL) {
		return (IBT_HCA_HDL_INVALID);
	}

	/* Check for valid mem_alloc_hdl handle pointer */
	if (mem_alloc_hdl == NULL) {
		return (IBT_MEM_ALLOC_HDL_INVALID);
	}

	/* Unbind the handles and free the memory */
	(void) ddi_dma_unbind_handle(mem_alloc_hdl->ibc_dma_hdl);
	ddi_dma_mem_free(&mem_alloc_hdl->ibc_acc_hdl);
	ddi_dma_free_handle(&mem_alloc_hdl->ibc_dma_hdl);
	kmem_free(mem_alloc_hdl, sizeof (*mem_alloc_hdl));

	return (IBT_SUCCESS);
}
