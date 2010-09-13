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

#include "dapl.h"
#include "dapl_adapter_util.h"
#include "dapl_evd_util.h"
#include "dapl_cr_util.h"
#include "dapl_lmr_util.h"
#include "dapl_rmr_util.h"
#include "dapl_cookie.h"
#include "dapl_tavor_ibtf_impl.h"
#include "dapl_hash.h"

/* Function prototypes */
extern DAT_RETURN dapls_tavor_wrid_init(ib_qp_handle_t);
extern DAT_RETURN dapls_tavor_srq_wrid_init(ib_srq_handle_t);
extern void dapls_tavor_srq_wrid_free(ib_srq_handle_t);
extern DAT_BOOLEAN dapls_tavor_srq_wrid_resize(ib_srq_handle_t, uint32_t);

static DAT_RETURN dapli_ib_srq_add_ep(IN ib_srq_handle_t srq_ptr,
    IN uint32_t qpnum, IN DAPL_EP *ep_ptr);
static void dapli_ib_srq_remove_ep(IN ib_srq_handle_t srq_ptr,
    IN uint32_t qpnum);
static DAT_RETURN dapli_ib_srq_resize_internal(IN DAPL_SRQ *srq_ptr,
    IN DAT_COUNT srqlen);
/*
 * dapli_get_dto_cq
 *
 * Obtain the cq_handle for a DTO EVD. If the EVD is NULL, use the
 * null_ib_cq_handle. If it hasn't been created yet, create it now in
 * the HCA structure. It will be cleaned up in dapls_ib_cqd_destroy().
 *
 * This is strictly internal to IB. DAPL allows a NULL DTO EVD handle,
 * but IB does not. So we create a CQ under the hood and make sure
 * an error is generated if the user every tries to post, by
 * setting the WQ length to 0 in ep_create and/or ep_modify.
 *
 * Returns
 *	A valid CQ handle
 */
static ib_cq_handle_t
dapli_get_dto_cq(
	IN  DAPL_IA	*ia_ptr,
	IN  DAPL_EVD	*evd_ptr)
{
	dapl_evd_create_t	create_msg;
	ib_cq_handle_t		cq_handle;
	int			ia_fd;
	int			retval;
	mlnx_umap_cq_data_out_t	*mcq;

	if (evd_ptr != DAT_HANDLE_NULL) {
		cq_handle = evd_ptr->ib_cq_handle;
	} else if (ia_ptr->hca_ptr->null_ib_cq_handle != IB_INVALID_HANDLE) {
		cq_handle = ia_ptr->hca_ptr->null_ib_cq_handle;
	} else {
		cq_handle = (ib_cq_handle_t)
		    dapl_os_alloc(sizeof (struct dapls_ib_cq_handle));
		if (cq_handle == NULL) {
			dapl_dbg_log(DAPL_DBG_TYPE_ERR,
			    "dapli_get_dto_cq: cq malloc failed\n");
			ia_ptr->hca_ptr->null_ib_cq_handle = IB_INVALID_HANDLE;
			return (IB_INVALID_HANDLE);
		}

		/*
		 * create a fake a CQ, we don't bother to mmap this CQ
		 * since nobody know about it to reap events from it.
		 */
		(void) dapl_os_memzero(&create_msg, sizeof (create_msg));
		create_msg.evd_flags = DAT_EVD_DTO_FLAG;
		mcq = (mlnx_umap_cq_data_out_t *)create_msg.evd_cq_data_out;

		ia_fd = ia_ptr->hca_ptr->ib_hca_handle->ia_fd;

		/* call into driver to allocate cq */
		retval = ioctl(ia_fd, DAPL_EVD_CREATE, &create_msg);
		if (retval != 0) {
			dapl_dbg_log(DAPL_DBG_TYPE_ERR,
			    "dapli_get_dto_cq: DAPL_EVD_CREATE failed\n");
			dapl_os_free(cq_handle,
			    sizeof (struct dapls_ib_cq_handle));
			ia_ptr->hca_ptr->null_ib_cq_handle = IB_INVALID_HANDLE;
			return (IB_INVALID_HANDLE);
		}

		(void) dapl_os_memzero(cq_handle,
		    sizeof (struct dapls_ib_cq_handle));
		dapl_os_lock_init(&cq_handle->cq_wrid_wqhdr_lock);
		cq_handle->evd_hkey = create_msg.evd_hkey;
		cq_handle->cq_addr = NULL;
		cq_handle->cq_map_offset = mcq->mcq_mapoffset;
		cq_handle->cq_map_len = mcq->mcq_maplen;
		cq_handle->cq_num = mcq->mcq_cqnum;
		cq_handle->cq_size = create_msg.evd_cq_real_size;
		cq_handle->cq_cqesz = mcq->mcq_cqesz;
		cq_handle->cq_iauar = ia_ptr->hca_ptr->ib_hca_handle->ia_uar;

		dapl_dbg_log(DAPL_DBG_TYPE_UTIL,
		    "dapli_get_dto_cq: cq 0x%p created, hkey 0x%016llx\n",
		    cq_handle, create_msg.evd_hkey);

		/* save this dummy CQ handle into the hca */
		ia_ptr->hca_ptr->null_ib_cq_handle = cq_handle;
	}
	return (cq_handle);
}


/*
 * dapl_ib_qp_alloc
 *
 * Alloc a QP
 *
 * Input:
 *        *ep_ptr                pointer to EP INFO
 *        ib_hca_handle          provider HCA handle
 *        ib_pd_handle           provider protection domain handle
 *        cq_recv                provider recv CQ handle
 *        cq_send                provider send CQ handle
 *
 * Output:
 *        none
 *
 * Returns:
 *        DAT_SUCCESS
 *        DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN
dapls_ib_qp_alloc(
	IN DAPL_IA *ia_ptr,
	IN DAPL_EP *ep_ptr,
	IN DAPL_EP *ep_ctx_ptr)
{
	dapl_ep_create_t	ep_args;
	dapl_ep_free_t		epf_args;
	ib_qp_handle_t		qp_p;
	DAPL_SRQ		*srq_p;
	ib_cq_handle_t		cq_recv;
	ib_cq_handle_t		cq_send;
	DAPL_PZ			*pz_handle;
	DAPL_EVD		*evd_handle;
	uint32_t		mpt_mask;
	size_t			premev_size;
	uint32_t		i;
	int			ia_fd;
	int			hca_fd;
	DAT_RETURN		dat_status;
	int			retval;
	mlnx_umap_qp_data_out_t *mqp;

	/* check parameters */
	if (ia_ptr->hca_ptr->ib_hca_handle == NULL) {
		dapl_dbg_log(DAPL_DBG_TYPE_EP,
		    "qp_alloc: hca_handle == NULL\n");
		return (DAT_INVALID_PARAMETER);
	}

	ia_fd = ia_ptr->hca_ptr->ib_hca_handle->ia_fd;
	hca_fd = ia_ptr->hca_ptr->ib_hca_handle->hca_fd;
	dapl_os_assert(ep_ptr->param.pz_handle != NULL);
	dapl_os_assert(ep_ptr->param.connect_evd_handle != NULL);

	/* fill in args for ep_create */
	(void) dapl_os_memzero(&ep_args, sizeof (ep_args));
	mqp = (mlnx_umap_qp_data_out_t *)ep_args.ep_qp_data_out;
	pz_handle = (DAPL_PZ *)ep_ptr->param.pz_handle;
	ep_args.ep_pd_hkey = pz_handle->pd_handle->pd_hkey;

	cq_recv = dapli_get_dto_cq(ia_ptr,
	    (DAPL_EVD *)ep_ptr->param.recv_evd_handle);
	ep_args.ep_rcv_evd_hkey = cq_recv->evd_hkey;

	cq_send = dapli_get_dto_cq(ia_ptr,
	    (DAPL_EVD *)ep_ptr->param.request_evd_handle);
	ep_args.ep_snd_evd_hkey = cq_send->evd_hkey;

	evd_handle = (DAPL_EVD *)ep_ptr->param.connect_evd_handle;
	ep_args.ep_conn_evd_hkey = evd_handle->ib_cq_handle->evd_hkey;

	ep_args.ep_ch_sizes.dcs_sq = ep_ptr->param.ep_attr.max_request_dtos;
	ep_args.ep_ch_sizes.dcs_sq_sgl = ep_ptr->param.ep_attr.max_request_iov;

	qp_p = (ib_qp_handle_t)dapl_os_alloc(
	    sizeof (struct dapls_ib_qp_handle));
	if (qp_p == NULL) {
		dapl_dbg_log(DAPL_DBG_TYPE_EP,
		    "qp_alloc: os_alloc failed\n");
		return (DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
		    DAT_RESOURCE_MEMORY));
	}

	(void) dapl_os_memzero(qp_p, sizeof (*qp_p));

	if (ep_ptr->param.srq_handle == NULL) {
		premev_size = ep_ptr->param.ep_attr.max_recv_dtos *
		    sizeof (ib_work_completion_t);
		if (premev_size != 0) {
			qp_p->qp_premature_events = (ib_work_completion_t *)
			    dapl_os_alloc(premev_size);
			if (qp_p->qp_premature_events == NULL) {
				dapl_dbg_log(DAPL_DBG_TYPE_EP,
				    "qp_alloc:alloc premature_events failed\n");
				dapl_os_free(qp_p, sizeof (*qp_p));
				return (DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
				    DAT_RESOURCE_MEMORY));
			}
		}
		qp_p->qp_num_premature_events = 0;
		ep_args.ep_srq_hkey = 0;
		ep_args.ep_srq_attached = 0;
		ep_args.ep_ch_sizes.dcs_rq =
		    ep_ptr->param.ep_attr.max_recv_dtos;
		ep_args.ep_ch_sizes.dcs_rq_sgl =
		    ep_ptr->param.ep_attr.max_recv_iov;
	} else {
		premev_size = 0;
		srq_p = (DAPL_SRQ *)ep_ptr->param.srq_handle;
		/* premature events for EPs with SRQ sit on the SRQ */
		qp_p->qp_premature_events = srq_p->srq_handle->
		    srq_premature_events;
		qp_p->qp_num_premature_events = 0;
		ep_args.ep_srq_hkey = srq_p->srq_handle->srq_hkey;
		ep_args.ep_srq_attached = 1;
		ep_args.ep_ch_sizes.dcs_rq = 0;
		ep_args.ep_ch_sizes.dcs_rq_sgl = 0;
	}

	/*
	 * there are cases when ep_ptr is a dummy container ep, and the orig
	 * ep pointer is passed in ep_ctx_ptr. eg - dapl_ep_modify does this.
	 * ep_cookie should be the actual ep pointer, not the dummy container
	 * ep since the kernel returns this via events and the CM callback
	 * routines
	 */
	ep_args.ep_cookie = (uintptr_t)ep_ctx_ptr;

	dapl_dbg_log(DAPL_DBG_TYPE_EP,
	    "qp_alloc: ep_ptr 0x%p, pz 0x%p (0x%llx), rcv_evd 0x%p (0x%llx)\n"
	    "          snd_evd 0x%p (0x%llx), conn_evd 0x%p (0x%llx)\n"
	    "          srq_hdl 0x%p (0x%llx)\n"
	    "          sq_sz %d, rq_sz %d, sq_sgl_sz %d, rq_sgl_sz %d\n",
	    ep_ptr, pz_handle, ep_args.ep_pd_hkey,
	    ep_ptr->param.recv_evd_handle, ep_args.ep_rcv_evd_hkey,
	    ep_ptr->param.request_evd_handle, ep_args.ep_snd_evd_hkey,
	    ep_ptr->param.connect_evd_handle, ep_args.ep_conn_evd_hkey,
	    ep_ptr->param.srq_handle, ep_args.ep_srq_hkey,
	    ep_args.ep_ch_sizes.dcs_sq, ep_args.ep_ch_sizes.dcs_rq,
	    ep_args.ep_ch_sizes.dcs_sq_sgl, ep_args.ep_ch_sizes.dcs_rq_sgl);

	/* The next line is only needed for backward compatibility */
	mqp->mqp_rev = MLNX_UMAP_IF_VERSION;
	retval = ioctl(ia_fd, DAPL_EP_CREATE, &ep_args);
	if (retval != 0 || mqp->mqp_rev != MLNX_UMAP_IF_VERSION) {
		dapl_dbg_log(DAPL_DBG_TYPE_EP,
		    "qp_alloc: ep_create failed errno %d, retval %d\n",
		    errno, retval);
		if (premev_size != 0) {
			dapl_os_free(qp_p->qp_premature_events, premev_size);
		}
		dapl_os_free(qp_p, sizeof (*qp_p));
		return (dapls_convert_error(errno, retval));
	}

	/* In the case of Arbel or Hermon */
	if (mqp->mqp_sdbr_mapoffset != 0 || mqp->mqp_sdbr_maplen != 0)
		qp_p->qp_sq_dbp = dapls_ib_get_dbp(mqp->mqp_sdbr_maplen,
		    hca_fd, mqp->mqp_sdbr_mapoffset, mqp->mqp_sdbr_offset);
	if (mqp->mqp_rdbr_mapoffset != 0 || mqp->mqp_rdbr_maplen != 0)
		qp_p->qp_rq_dbp = dapls_ib_get_dbp(mqp->mqp_rdbr_maplen,
		    hca_fd, mqp->mqp_rdbr_mapoffset, mqp->mqp_rdbr_offset);

	qp_p->qp_addr = mmap64((void *)0, mqp->mqp_maplen,
	    (PROT_READ | PROT_WRITE), MAP_SHARED, hca_fd,
	    mqp->mqp_mapoffset);

	if (qp_p->qp_addr == MAP_FAILED ||
	    qp_p->qp_sq_dbp == MAP_FAILED ||
	    qp_p->qp_rq_dbp == MAP_FAILED) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "qp_alloc: mmap failed(%d)\n", errno);
		epf_args.epf_hkey = ep_args.ep_hkey;
		retval = ioctl(ia_fd, DAPL_EP_FREE, &epf_args);
		if (retval != 0) {
			dapl_dbg_log(DAPL_DBG_TYPE_ERR,
			    "qp_alloc: EP_FREE err:%d\n", errno);
		}
		if (premev_size != 0) {
			dapl_os_free(qp_p->qp_premature_events, premev_size);
		}
		dapl_os_free(qp_p, sizeof (*qp_p));
		return (dapls_convert_error(errno, 0));
	}

	qp_p->qp_map_len = mqp->mqp_maplen;
	qp_p->qp_num = mqp->mqp_qpnum;
	qp_p->qp_iauar = ia_ptr->hca_ptr->ib_hca_handle->ia_uar;
	qp_p->qp_ia_bf = ia_ptr->hca_ptr->ib_hca_handle->ia_bf;
	qp_p->qp_ia_bf_toggle = ia_ptr->hca_ptr->ib_hca_handle->ia_bf_toggle;

	evd_handle = (DAPL_EVD *)ep_ptr->param.request_evd_handle;
	qp_p->qp_sq_cqhdl = evd_handle->ib_cq_handle;
	qp_p->qp_sq_lastwqeaddr = NULL;
	qp_p->qp_sq_wqhdr = NULL;
	qp_p->qp_sq_buf = (caddr_t)(qp_p->qp_addr + mqp->mqp_sq_off);
	qp_p->qp_sq_desc_addr = mqp->mqp_sq_desc_addr;
	qp_p->qp_sq_numwqe = mqp->mqp_sq_numwqe;
	qp_p->qp_sq_wqesz = mqp->mqp_sq_wqesz;
	qp_p->qp_sq_sgl = ep_ptr->param.ep_attr.max_request_iov;
	qp_p->qp_sq_inline = ia_ptr->hca_ptr->max_inline_send;
	qp_p->qp_sq_headroom = mqp->mqp_sq_headroomwqes;

	evd_handle = (DAPL_EVD *)ep_ptr->param.recv_evd_handle;
	qp_p->qp_rq_cqhdl = evd_handle->ib_cq_handle;
	qp_p->qp_rq_lastwqeaddr = NULL;
	qp_p->qp_rq_wqhdr = NULL;
	qp_p->qp_rq_buf = (caddr_t)(qp_p->qp_addr + mqp->mqp_rq_off);
	qp_p->qp_rq_desc_addr = mqp->mqp_rq_desc_addr;
	qp_p->qp_rq_numwqe = mqp->mqp_rq_numwqe;
	qp_p->qp_rq_wqesz = mqp->mqp_rq_wqesz;
	qp_p->qp_rq_sgl = ep_ptr->param.ep_attr.max_recv_iov;

	dapl_dbg_log(DAPL_DBG_TYPE_EP,
	    "qp_alloc: created, qp_sq_buf %p, qp_rq_buf %p\n",
	    qp_p->qp_sq_buf, qp_p->qp_rq_buf);
	dapl_dbg_log(DAPL_DBG_TYPE_EP,
	    "qp_alloc: created, sq numwqe %x wqesz %x, rq numwqe %x wqesz %x\n",
	    qp_p->qp_sq_numwqe, qp_p->qp_sq_wqesz,
	    qp_p->qp_rq_numwqe, qp_p->qp_rq_wqesz);
	dapl_dbg_log(DAPL_DBG_TYPE_EP,
	    "qp_alloc: created, qp_sq_desc_addr %x, qp_rq_desc_addr %x\n",
	    mqp->mqp_sq_desc_addr, mqp->mqp_rq_desc_addr);
	dapl_dbg_log(DAPL_DBG_TYPE_EP,
	    "qp_alloc: created, ep_ptr 0x%p, ep_hkey 0x%016llx\n\n",
	    ep_ptr, ep_args.ep_hkey);

	qp_p->ep_hkey = ep_args.ep_hkey;

	/*
	 * Calculate the number of bits in max_rmrs - this is indirectly
	 * the max number of entried in the MPT table (defaults to 512K
	 * but is configurable). This value is used while creating new
	 * rkeys in bind processing (see dapl_tavor_hw.c).
	 * Stash this value in the qp handle, don't want to do this math
	 * for every bind
	 */
	mpt_mask = (uint32_t)ia_ptr->hca_ptr->ia_attr.max_rmrs - 1;
	for (i = 0; mpt_mask > 0; mpt_mask = (mpt_mask >> 1), i++)
		;
	qp_p->qp_num_mpt_shift = (uint32_t)i;

	ep_ptr->qpn = qp_p->qp_num;
	/* update the qp handle in the ep ptr */
	ep_ptr->qp_handle = qp_p;
	/*
	 * ibt_alloc_rc_channel transitions the qp state to INIT.
	 * hence we directly transition from UNATTACHED to INIT
	 */
	ep_ptr->qp_state = IBT_STATE_INIT;

	if (ep_ptr->param.srq_handle) {
		/* insert ep into the SRQ's ep_table */
		dat_status = dapli_ib_srq_add_ep(srq_p->srq_handle,
		    qp_p->qp_num, ep_ptr);
		if (dat_status != DAT_SUCCESS) {
			dapl_dbg_log(DAPL_DBG_TYPE_EP,
			    "qp_alloc: srq_add_ep failed ep_ptr 0x%p, 0x%x\n",
			    ep_ptr, dat_status);
			(void) dapls_ib_qp_free(ia_ptr, ep_ptr);
			return (DAT_INVALID_PARAMETER);
		}
		qp_p->qp_srq_enabled = 1;
		qp_p->qp_srq = srq_p->srq_handle;
	} else {
		qp_p->qp_srq_enabled = 0;
		qp_p->qp_srq = NULL;
	}
	DAPL_INIT_QP(ia_ptr)(qp_p);

	if (dapls_tavor_wrid_init(qp_p) != DAT_SUCCESS) {
		(void) dapls_ib_qp_free(ia_ptr, ep_ptr);
		return (DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
		    DAT_RESOURCE_MEMORY));
	}

	return (DAT_SUCCESS);
}


/*
 * dapls_ib_qp_free
 *
 * Free a QP
 *
 * Input:
 *        *ep_ptr                pointer to EP INFO
 *        ib_hca_handle          provider HCA handle
 *
 * Output:
 *        none
 *
 * Returns:
 *        none
 *
 */
DAT_RETURN
dapls_ib_qp_free(IN DAPL_IA *ia_ptr, IN DAPL_EP *ep_ptr)
{
	ib_qp_handle_t	qp_p = ep_ptr->qp_handle;
	ib_hca_handle_t	ib_hca_handle = ia_ptr->hca_ptr->ib_hca_handle;
	dapl_ep_free_t	args;
	int		retval;

	if ((ep_ptr->qp_handle != IB_INVALID_HANDLE) &&
	    (ep_ptr->qp_state != DAPL_QP_STATE_UNATTACHED)) {
		if (munmap((void *)qp_p->qp_addr, qp_p->qp_map_len) < 0) {
			dapl_dbg_log(DAPL_DBG_TYPE_ERR,
			    "qp_free: munmap failed(%d)\n", errno);
		}
		args.epf_hkey = qp_p->ep_hkey;
		retval = ioctl(ib_hca_handle->ia_fd, DAPL_EP_FREE, &args);
		if (retval != 0) {
			dapl_dbg_log(DAPL_DBG_TYPE_EP,
			    "qp_free: ioctl errno = %d, retval = %d\n",
			    errno, retval);
		}
		dapl_dbg_log(DAPL_DBG_TYPE_EP,
		    "qp_free: freed, ep_ptr 0x%p, ep_hkey 0x%016llx\n",
		    ep_ptr, qp_p->ep_hkey);

		if (qp_p->qp_srq) {
			dapli_ib_srq_remove_ep(qp_p->qp_srq, qp_p->qp_num);
		} else {
			if (qp_p->qp_premature_events) {
				dapl_os_free(qp_p->qp_premature_events,
				    ep_ptr->param.ep_attr.max_recv_dtos *
				    sizeof (ib_work_completion_t));
			}
		}
		dapl_os_free(qp_p, sizeof (*qp_p));
		ep_ptr->qp_handle = NULL;
	}
	return (DAT_SUCCESS);
}


/*
 * dapl_ib_qp_modify
 *
 * Set the QP to the parameters specified in an EP_PARAM
 *
 * We can't be sure what state the QP is in so we first obtain the state
 * from the driver. The EP_PARAM structure that is provided has been
 * sanitized such that only non-zero values are valid.
 *
 * Input:
 *        ib_hca_handle          HCA handle
 *        qp_handle              QP handle
 *        ep_attr                Sanitized EP Params
 *
 * Output:
 *        none
 *
 * Returns:
 *        DAT_SUCCESS
 *        DAT_INSUFFICIENT_RESOURCES
 *        DAT_INVALID_PARAMETER
 *
 */
DAT_RETURN
dapls_ib_qp_modify(IN DAPL_IA *ia_ptr, IN DAPL_EP *ep_ptr,
    IN DAT_EP_ATTR *ep_attr)
{
	dapl_ep_modify_t 	epm_args;
	boolean_t		epm_needed;
	int	ia_fd;
	int	retval;


	if (ep_ptr->qp_handle == NULL) {
		dapl_dbg_log(DAPL_DBG_TYPE_EP,
		    "qp_modify: qp_handle == NULL\n");
		return (DAT_INVALID_PARAMETER);
	}
	if (ia_ptr->hca_ptr->ib_hca_handle == NULL) {
		dapl_dbg_log(DAPL_DBG_TYPE_EP,
		    "qp_modify: hca_handle == NULL\n");
		return (DAT_INVALID_PARAMETER);
	}

	epm_needed = B_FALSE;

	/*
	 * NOTE: ep_attr->max_mtu_size  indicates the maximum message
	 * size, which is always 2GB for IB. Nothing to do with the IB
	 * implementation, nothing to set up.
	 */

	if (ep_attr->max_rdma_size > 0) {
		if (ep_attr->max_rdma_size > DAPL_IB_MAX_MESSAGE_SIZE) {
			return (DAT_ERROR(DAT_INVALID_PARAMETER, 0));
		}
	}

	(void) memset((void *)&epm_args, 0, sizeof (epm_args));
	/*
	 * The following parameters are dealt by creating a new qp
	 * in dapl_ep_modify.
	 *	- max_recv_dtos
	 *	- max_request_dtos
	 *	- max_recv_iov
	 *	- max_request_iov
	 */

	if (ep_attr->max_rdma_read_in > 0) {
		epm_args.epm_flags |= IBT_CEP_SET_RDMARA_IN;
		epm_args.epm_rdma_ra_in = ep_attr->max_rdma_read_in;
		epm_needed = B_TRUE;
	}
	if (ep_attr->max_rdma_read_out > 0) {
		epm_args.epm_flags |= IBT_CEP_SET_RDMARA_OUT;
		epm_args.epm_rdma_ra_out = ep_attr->max_rdma_read_out;
		epm_needed = B_TRUE;
	}

	if (!epm_needed) {
		dapl_dbg_log(DAPL_DBG_TYPE_EP,
		    "qp_modify: ep_hkey = %016llx nothing to do\n",
		    ep_ptr->qp_handle->ep_hkey);
		return (DAT_SUCCESS);
	}

	epm_args.epm_hkey = ep_ptr->qp_handle->ep_hkey;

	ia_fd = ia_ptr->hca_ptr->ib_hca_handle->ia_fd;

	retval = ioctl(ia_fd, DAPL_EP_MODIFY, &epm_args);
	if (retval != 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_EP,
		    "qp_modify: ioctl failed errno %d, retval %d\n",
		    errno, retval);
		return (dapls_convert_error(errno, retval));
	}

	dapl_dbg_log(DAPL_DBG_TYPE_EP,
	    "qp_modify: ep_hkey = %016llx\n", ep_ptr->qp_handle->ep_hkey);
	return (DAT_SUCCESS);
}

/*
 * Allocate the srq data structure as well as the kernel resource
 * corresponding to it.
 */
DAT_RETURN
dapls_ib_srq_alloc(IN DAPL_IA *ia_ptr, IN DAPL_SRQ *srq_ptr)
{
	dapl_srq_create_t	srqc_args;
	dapl_srq_free_t		srqf_args;
	ib_srq_handle_t		ibsrq_p;
	DAPL_PZ			*pz_handle;
	uint32_t		i;
	size_t			premev_size;
	size_t			freeev_size;
	int			ia_fd;
	int			hca_fd;
	int			retval;
	mlnx_umap_srq_data_out_t *msrq;

	/* check parameters */
	if (ia_ptr->hca_ptr->ib_hca_handle == NULL) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "srq_alloc: hca_handle == NULL\n");
		return (DAT_ERROR(DAT_INVALID_PARAMETER, DAT_INVALID_ARG1));
	}

	ia_fd = ia_ptr->hca_ptr->ib_hca_handle->ia_fd;
	hca_fd = ia_ptr->hca_ptr->ib_hca_handle->hca_fd;
	dapl_os_assert(srq_ptr->param.pz_handle != NULL);

	/* fill in args for srq_create */
	pz_handle = (DAPL_PZ *)srq_ptr->param.pz_handle;

	ibsrq_p = (ib_srq_handle_t)dapl_os_alloc(sizeof (*ibsrq_p));
	if (ibsrq_p == NULL) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "srq_alloc: os_alloc failed\n");
		return (DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
		    DAT_RESOURCE_MEMORY));
	}
	(void) dapl_os_memzero(ibsrq_p, sizeof (*ibsrq_p));

	(void) dapl_os_memzero(&srqc_args, sizeof (srqc_args));
	msrq = (mlnx_umap_srq_data_out_t *)srqc_args.srqc_data_out;
	srqc_args.srqc_pd_hkey = pz_handle->pd_handle->pd_hkey;
	srqc_args.srqc_sizes.srqs_sz = srq_ptr->param.max_recv_dtos;
	srqc_args.srqc_sizes.srqs_sgl = srq_ptr->param.max_recv_iov;

	dapl_dbg_log(DAPL_DBG_TYPE_EP,
	    "srq_alloc: srq_ptr 0x%p, pz 0x%p (0x%llx), srq_sz %d"
	    " srq_sgl %d\n",
	    srq_ptr, pz_handle, srqc_args.srqc_pd_hkey,
	    srqc_args.srqc_sizes.srqs_sz, srqc_args.srqc_sizes.srqs_sgl);

	/* The next line is only needed for backward compatibility */
	msrq->msrq_rev = MLNX_UMAP_IF_VERSION;
	retval = ioctl(ia_fd, DAPL_SRQ_CREATE, &srqc_args);
	if (retval != 0 || msrq->msrq_rev != MLNX_UMAP_IF_VERSION) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "srq_alloc: srq_create failed errno %d, retval %d\n",
		    errno, retval);
		dapl_os_free(ibsrq_p, sizeof (*ibsrq_p));
		return (dapls_convert_error(errno, retval));
	}

	/* In the case of Arbel or Hermon */
	if (msrq->msrq_rdbr_mapoffset != 0 || msrq->msrq_rdbr_maplen != 0)
		ibsrq_p->srq_dbp = dapls_ib_get_dbp(
		    msrq->msrq_rdbr_maplen, hca_fd,
		    msrq->msrq_rdbr_mapoffset, msrq->msrq_rdbr_offset);

	ibsrq_p->srq_addr = mmap64((void *)0,
	    msrq->msrq_maplen, (PROT_READ | PROT_WRITE),
	    MAP_SHARED, hca_fd, msrq->msrq_mapoffset);

	if (ibsrq_p->srq_addr == MAP_FAILED ||
	    ibsrq_p->srq_dbp == MAP_FAILED) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "srq_alloc: mmap failed(%d)\n", errno);
		srqf_args.srqf_hkey = srqc_args.srqc_hkey;
		retval = ioctl(ia_fd, DAPL_SRQ_FREE, &srqf_args);
		if (retval != 0) {
			dapl_dbg_log(DAPL_DBG_TYPE_ERR,
			    "srq_alloc: SRQ_FREE err:%d\n", errno);
		}
		dapl_os_free(ibsrq_p, sizeof (*ibsrq_p));
		return (dapls_convert_error(errno, 0));
	}

	ibsrq_p->srq_hkey = srqc_args.srqc_hkey;
	ibsrq_p->srq_map_len = msrq->msrq_maplen;
	ibsrq_p->srq_map_offset = msrq->msrq_mapoffset;
	ibsrq_p->srq_num = msrq->msrq_srqnum;
	ibsrq_p->srq_iauar = ia_ptr->hca_ptr->ib_hca_handle->ia_uar;
	/* since 0 is a valid index, -1 indicates invalid value */
	ibsrq_p->srq_wq_lastwqeindex = -1;
	ibsrq_p->srq_wq_desc_addr = msrq->msrq_desc_addr;
	ibsrq_p->srq_wq_numwqe = msrq->msrq_numwqe;
	ibsrq_p->srq_wq_wqesz = msrq->msrq_wqesz;
	ibsrq_p->srq_wq_sgl = srqc_args.srqc_real_sizes.srqs_sgl;

	/*
	 * update the srq handle in the srq ptr, this is needed since from
	 * here on cleanup is done by calling dapls_ib_srq_free()
	 */
	srq_ptr->srq_handle = ibsrq_p;

	premev_size = ibsrq_p->srq_wq_numwqe * sizeof (ib_work_completion_t);
	ibsrq_p->srq_premature_events = (ib_work_completion_t *)
	    dapl_os_alloc(premev_size);
	if (ibsrq_p->srq_premature_events == NULL) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "srq_alloc: os_alloc premature_events failed\n");
		dapls_ib_srq_free(ia_ptr, srq_ptr);
		srq_ptr->srq_handle = NULL;
		return (DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
		    DAT_RESOURCE_MEMORY));
	}

	freeev_size = ibsrq_p->srq_wq_numwqe * sizeof (uint32_t);
	ibsrq_p->srq_freepr_events = (uint32_t *)dapl_os_alloc(freeev_size);
	if (ibsrq_p->srq_freepr_events == NULL) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "srq_alloc: os_alloc freepr_events failed\n");
		dapls_ib_srq_free(ia_ptr, srq_ptr);
		srq_ptr->srq_handle = NULL;
		return (DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
		    DAT_RESOURCE_MEMORY));
	}
	ibsrq_p->srq_freepr_head = 0;
	ibsrq_p->srq_freepr_tail = 0;
	ibsrq_p->srq_freepr_num_events = ibsrq_p->srq_wq_numwqe;

	/* initialize the free list of premature events */
	for (i = 0; i < ibsrq_p->srq_freepr_num_events; i++) {
		ibsrq_p->srq_freepr_events[i] = i;
		/*
		 * wc_res_hash field is used to mark entries in the premature
		 * events list
		 */
		DAPL_SET_CQE_INVALID(&(ibsrq_p->srq_premature_events[i]));
	}

	dapl_dbg_log(DAPL_DBG_TYPE_EP,
	    "srq_alloc: created, srq_ptr 0x%p, srq_hkey 0x%016llx\n",
	    srq_ptr, srqc_args.srqc_hkey);

	DAPL_INIT_SRQ(ia_ptr)(ibsrq_p);

	if (dapls_tavor_srq_wrid_init(ibsrq_p) != DAT_SUCCESS) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "srq_alloc: wridlist alloc failed\n");
		dapls_ib_srq_free(ia_ptr, srq_ptr);
		srq_ptr->srq_handle = NULL;
		return (DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
		    DAT_RESOURCE_MEMORY));
	}
	ibsrq_p->srq_ep_table = NULL;
	/* allocate a hash table to to store EPs */
	retval = dapls_hash_create(DAPL_HASH_TABLE_DEFAULT_CAPACITY,
	    DAT_FALSE, &ibsrq_p->srq_ep_table);
	if (retval != DAT_SUCCESS) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR, "dapls_ib_srq_alloc hash "
		    "create failed %d\n", retval);
		dapls_ib_srq_free(ia_ptr, srq_ptr);
		srq_ptr->srq_handle = NULL;
		return (retval);
	}

	return (DAT_SUCCESS);
}


/*
 * SRQ Free routine
 */
void
dapls_ib_srq_free(IN DAPL_IA *ia_handle, IN DAPL_SRQ *srq_ptr)
{
	ib_srq_handle_t	srq_handle = srq_ptr->srq_handle;
	ib_hca_handle_t	ib_hca_handle = ia_handle->hca_ptr->ib_hca_handle;
	dapl_srq_free_t	srqf_args;
	int		retval;

	if (srq_handle == IB_INVALID_HANDLE) {
		return; /* nothing to do */
	}

	if (munmap((void *)srq_handle->srq_addr, srq_handle->srq_map_len) < 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "srq_free: munmap failed(%d)\n", errno);
	}
	srqf_args.srqf_hkey = srq_handle->srq_hkey;
	retval = ioctl(ib_hca_handle->ia_fd, DAPL_SRQ_FREE, &srqf_args);
	if (retval != 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "srq_free: ioctl errno = %d, retval = %d\n", errno, retval);
	}
	dapl_dbg_log(DAPL_DBG_TYPE_EP,
	    "srq_free: freed, srq_ptr 0x%p, srq_hkey 0x%016llx\n",
	    srq_ptr, srq_handle->srq_hkey);
	if (srq_handle->srq_ep_table) {
		(void) dapls_hash_free(srq_handle->srq_ep_table);
	}
	if (srq_handle->srq_wridlist) {
		dapls_tavor_srq_wrid_free(srq_handle);
	}
	if (srq_handle->srq_freepr_events) {
		dapl_os_free(srq_handle->srq_freepr_events,
		    srq_handle->srq_wq_numwqe * sizeof (ib_work_completion_t));
	}
	if (srq_handle->srq_premature_events) {
		dapl_os_free(srq_handle->srq_premature_events,
		    srq_handle->srq_wq_numwqe * sizeof (uint32_t));
	}
	dapl_os_free(srq_handle, sizeof (*srq_handle));
	srq_ptr->srq_handle = NULL;
}

/*
 * Adds EP to a hashtable in SRQ
 */
static DAT_RETURN
dapli_ib_srq_add_ep(IN ib_srq_handle_t srq_ptr, IN uint32_t qp_num,
    IN DAPL_EP *ep_ptr)
{
	DAPL_HASH_TABLE	*htable;
	DAPL_HASH_KEY	key;

	dapl_os_assert(srq_ptr);

	htable = srq_ptr->srq_ep_table;
	key = qp_num;
	dapl_dbg_log(DAPL_DBG_TYPE_EP,
	    "srq_insert_ep:%p %p %llx\n", srq_ptr, htable, key);
	return (dapls_hash_insert(htable, key, ep_ptr));
}

/*
 * Removes an EP from the hashtable in SRQ
 */
static void
dapli_ib_srq_remove_ep(IN ib_srq_handle_t srq_ptr, IN uint32_t qp_num)
{
	DAPL_HASH_TABLE	*htable;
	DAPL_HASH_KEY	key;
	DAPL_EP		*epp;
	DAT_RETURN	retval;

	dapl_os_assert(srq_ptr);

	htable = srq_ptr->srq_ep_table;
	key = qp_num;

	retval = dapls_hash_remove(htable, key, (DAPL_HASH_DATA *)&epp);
	if (retval != DAT_SUCCESS) {
		dapl_dbg_log(DAPL_DBG_TYPE_EP,
		    "srq_remove_ep(%d): %p %llx\n", retval, htable, key);
	}
}

/*
 * Lookup an EP from the hashtable in SRQ
 */
DAPL_EP *
dapls_ib_srq_lookup_ep(IN DAPL_SRQ *srq_ptr, IN ib_work_completion_t *cqe_ptr)
{
	DAPL_HASH_TABLE	*htable;
	DAPL_HASH_KEY	key;
	DAPL_EP		*epp;
	DAT_RETURN	retval;

	dapl_os_assert(srq_ptr && srq_ptr->srq_handle);

	htable = srq_ptr->srq_handle->srq_ep_table;
	key = DAPL_GET_CQE_QPN(cqe_ptr);
	epp = NULL;

	retval = dapls_hash_search(htable, key, (DAPL_HASH_DATA *)&epp);
	if (retval != DAT_SUCCESS) {
		dapl_dbg_log(DAPL_DBG_TYPE_EP,
		    "srq_lookup_ep(%x): %p %llx\n", retval, htable, key);
	}
	return (epp);
}


/*
 * dapl_ib_srq_resize
 *
 * Resize an SRQ
 *
 * Input:
 *	srq_ptr			pointer to SRQ struct
 *	srqlen			new length of the SRQ
 * Output:
 *	none
 *
 * Returns:
 *	DAT_SUCCESS
 *	DAT_INVALID_HANDLE
 *	DAT_INTERNAL_ERROR
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
DAT_RETURN
dapls_ib_srq_resize(
	IN  DAPL_SRQ		*srq_ptr,
	IN  DAT_COUNT		srqlen)
{
	ib_srq_handle_t	srq_handle;
	DAT_RETURN	dat_status;

	dat_status = dapli_ib_srq_resize_internal(srq_ptr, srqlen);
	if (DAT_INSUFFICIENT_RESOURCES == DAT_GET_TYPE(dat_status)) {
		srq_handle = srq_ptr->srq_handle;
		/* attempt to resize back to the current size */
		dat_status = dapli_ib_srq_resize_internal(srq_ptr,
		    srq_handle->srq_wq_numwqe);
		if (DAT_SUCCESS != dat_status) {
			/*
			 * XXX this is catastrophic need to post an event
			 * to the async evd
			 */
			return (DAT_INTERNAL_ERROR);
		}
	}

	return (dat_status);
}

/*
 * dapli_ib_srq_resize_internal
 *
 * An internal routine to resize a SRQ.
 *
 * Input:
 *	srq_ptr			pointer to SRQ struct
 *	srqlen			new length of the srq
 * Output:
 *	none
 *
 * Returns:
 *	DAT_SUCCESS
 *	DAT_INVALID_HANDLE
 *	DAT_INSUFFICIENT_RESOURCES
 *
 */
static DAT_RETURN
dapli_ib_srq_resize_internal(
	IN  DAPL_SRQ		*srq_ptr,
	IN  DAT_COUNT		srqlen)
{
	ib_srq_handle_t		srq_handle;
	dapl_srq_resize_t	resize_msg;
	int			ia_fd;
	int			hca_fd;
	ib_work_completion_t	*new_premature_events;
	ib_work_completion_t	*old_premature_events;
	uint32_t		*new_freepr_events;
	uint32_t		*old_freepr_events;
	size_t			old_premature_size;
	size_t			old_freepr_size;
	size_t			new_premature_size;
	size_t			new_freepr_size;
	int			idx, i;
	int			retval;
	mlnx_umap_srq_data_out_t *msrq;

	dapl_dbg_log(DAPL_DBG_TYPE_EP,
	    "dapls_ib_srq_resize: srq 0x%p srq_hdl 0x%p "
	    "srq_hkey 0x%016llx srqlen %d\n",
	    srq_ptr, (void *)srq_ptr->srq_handle,
	    srq_ptr->srq_handle->srq_hkey, srqlen);

	srq_handle = srq_ptr->srq_handle;
	/*
	 * Since SRQs are created in powers of 2 its possible that the
	 * previously allocated SRQ has sufficient entries. If the current
	 * SRQ is big enough and it is mapped we are done.
	 */
	if ((srqlen < srq_handle->srq_wq_numwqe) && (srq_handle->srq_addr)) {
		return (DAT_SUCCESS);
	}

	/* unmap the SRQ before resizing it */
	if ((srq_handle->srq_addr) && (munmap((char *)srq_handle->srq_addr,
	    srq_handle->srq_map_len) < 0)) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "srq_resize: munmap(%p:0x%llx) failed(%d)\n",
		    srq_handle->srq_addr, srq_handle->srq_map_len, errno);
		return (DAT_ERROR(DAT_INVALID_HANDLE, DAT_INVALID_HANDLE_SRQ));
	}
	/* srq_addr is unmapped and no longer valid */
	srq_handle->srq_addr = NULL;

	ia_fd = srq_ptr->header.owner_ia->hca_ptr->ib_hca_handle->ia_fd;
	hca_fd = srq_ptr->header.owner_ia->hca_ptr->ib_hca_handle->hca_fd;

	(void) dapl_os_memzero(&resize_msg, sizeof (resize_msg));
	resize_msg.srqr_hkey = srq_handle->srq_hkey;
	resize_msg.srqr_new_size = srqlen;
	msrq = (mlnx_umap_srq_data_out_t *)resize_msg.srqr_data_out;

	/* The next line is only needed for backward compatibility */
	msrq->msrq_rev = MLNX_UMAP_IF_VERSION;
	retval = ioctl(ia_fd, DAPL_SRQ_RESIZE, &resize_msg);
	if (retval != 0 || msrq->msrq_rev != MLNX_UMAP_IF_VERSION) {
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "dapls_ib_srq_resize: srq 0x%p, err: %s\n",
		    srq_ptr, strerror(errno));
		if (errno == EINVAL) { /* Couldn't find this srq */
			return (DAT_ERROR(DAT_INVALID_HANDLE,
			    DAT_INVALID_HANDLE_SRQ));
		} else { /* Need to retry resize with a smaller qlen */
			return (DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
			    DAT_RESOURCE_SRQ));
		}
	}

	dapl_os_assert(srq_handle->srq_num == msrq->msrq_srqnum);

	/* In the case of Arbel or Hermon */
	if (msrq->msrq_rdbr_mapoffset != 0 ||
	    msrq->msrq_rdbr_maplen != 0)
		srq_handle->srq_dbp = dapls_ib_get_dbp(
		    msrq->msrq_rdbr_maplen,
		    hca_fd, msrq->msrq_rdbr_mapoffset,
		    msrq->msrq_rdbr_offset);

	srq_handle->srq_addr = mmap64((void *)0,
	    msrq->msrq_maplen, (PROT_READ | PROT_WRITE),
	    MAP_SHARED, hca_fd, msrq->msrq_mapoffset);

	if (srq_handle->srq_addr == MAP_FAILED ||
	    srq_handle->srq_dbp == MAP_FAILED) {
		srq_handle->srq_addr = NULL;
		dapl_dbg_log(DAPL_DBG_TYPE_ERR,
		    "srq_resize: mmap failed(%d)\n", errno);
		/* Need to retry resize with a smaller qlen */
		return (DAT_ERROR(DAT_INSUFFICIENT_RESOURCES,
		    DAT_RESOURCE_MEMORY));
	}

	old_freepr_size = srq_handle->srq_wq_numwqe * sizeof (uint32_t);
	old_premature_size = srq_handle->srq_wq_numwqe *
	    sizeof (ib_work_completion_t);

	old_freepr_events = srq_handle->srq_freepr_events;
	old_premature_events = srq_handle->srq_premature_events;

	new_freepr_size = resize_msg.srqr_real_size * sizeof (uint32_t);
	new_premature_size = resize_msg.srqr_real_size *
	    sizeof (ib_work_completion_t);

	new_freepr_events = (uint32_t *)dapl_os_alloc(new_freepr_size);
	if (new_freepr_events == NULL) {
		goto bail;
	}
	new_premature_events = (ib_work_completion_t *)dapl_os_alloc(
	    new_premature_size);
	if (new_premature_events == NULL) {
		goto bail;
	}
	if (!dapls_tavor_srq_wrid_resize(srq_handle,
	    resize_msg.srqr_real_size)) {
		goto bail;
	}
	idx = 0;
	/* copy valid premature events  */
	for (i = 0; i < srq_handle->srq_wq_numwqe; i++) {
		if (!DAPL_CQE_IS_VALID(&old_premature_events[i])) {
			continue;
		}
		(void) dapl_os_memcpy(&new_premature_events[idx],
		    &old_premature_events[i], sizeof (ib_work_completion_t));
		idx++;
	}
	dapl_os_assert(srq_handle->srq_wq_numwqe - idx ==
	    srq_handle->srq_freepr_num_events);

	/* Initialize free events lists */
	for (i = 0; i < resize_msg.srqr_real_size - idx; i++) {
		new_freepr_events[i] = idx + i;
	}

	srq_handle->srq_freepr_events = new_freepr_events;
	srq_handle->srq_premature_events = new_premature_events;
	srq_handle->srq_freepr_num_events = resize_msg.srqr_real_size - idx;
	srq_handle->srq_freepr_head = 0;
	/* a full freepr list has tail at 0 */
	if (idx == 0) {
		srq_handle->srq_freepr_tail = 0;
	} else {
		srq_handle->srq_freepr_tail = srq_handle->srq_freepr_num_events;
	}

	if (old_freepr_events) {
		old_freepr_size = old_freepr_size; /* pacify lint */
		dapl_os_free(old_freepr_events, old_freepr_size);
	}
	if (old_premature_events) {
		old_premature_size = old_premature_size; /* pacify lint */
		dapl_os_free(old_premature_events, old_premature_size);
	}

	/*
	 * update the srq fields,
	 * note: the srq_wq_lastwqeindex doesn't change since the old
	 * work queue is copied as a whole into the new work queue.
	 */
	srq_handle->srq_map_offset = msrq->msrq_mapoffset;
	srq_handle->srq_map_len = msrq->msrq_maplen;
	srq_handle->srq_wq_desc_addr = msrq->msrq_desc_addr;
	srq_handle->srq_wq_numwqe = msrq->msrq_numwqe;
	srq_handle->srq_wq_wqesz = msrq->msrq_wqesz;

	return (DAT_SUCCESS);
bail:
	if (new_freepr_events) {
		dapl_os_free(new_freepr_events, new_freepr_size);
	}
	if (new_premature_events) {
		dapl_os_free(new_premature_events, new_premature_size);
	}
	return (DAT_ERROR(DAT_INSUFFICIENT_RESOURCES, DAT_RESOURCE_MEMORY));
}
