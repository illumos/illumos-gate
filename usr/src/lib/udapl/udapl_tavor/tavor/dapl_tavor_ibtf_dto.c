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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "dapl.h"
#include "dapl_adapter_util.h"
#include "dapl_lmr_util.h"
#include "dapl_rmr_util.h"
#include "dapl_cookie.h"

#include "dapl_tavor_ibtf_impl.h"

/*
 *
 *
 * MODULE: dapl_tavor_ibtf_dto.c
 *
 * PURPOSE: Utility routines for data transfer operations
 *
 */


/*
 * dapls_ib_post_recv
 *
 * Provider specific Post RECV function
 */
DAT_RETURN
dapls_ib_post_recv(
	IN DAPL_EP		*ep_ptr,
	IN DAPL_COOKIE		*cookie,
	IN DAT_COUNT		num_segments,
	IN DAT_LMR_TRIPLET	*local_iov,
	IN DAT_COMPLETION_FLAGS completion_flags)
{
	ibt_recv_wr_t		pr_wr;
	ibt_wr_ds_t		pr_sgl_arr[DAPL_MAX_IOV];
	ibt_wr_ds_t		*pr_sgl;
	boolean_t		suppress_notification;
	DAT_COUNT		total_len;
	int			retval;
	int			i;

	total_len = 0;

	if (ep_ptr->qp_handle == NULL) {
		dapl_dbg_log(DAPL_DBG_TYPE_EP, "dapls_ib_post_recv: "
		    "qp_handle == NULL\n");
		return (DAT_INVALID_PARAMETER);
	}

	/* allocate scatter-gather list on the heap if its large */
	if (num_segments > DAPL_MAX_IOV) {
		pr_sgl = dapl_os_alloc(num_segments * sizeof (ibt_wr_ds_t));
		if (NULL == pr_sgl) {
			dapl_dbg_log(DAPL_DBG_TYPE_ERR,
			    "dapls_ib_post_recv: pr_sgl alloc failed");
			return (DAT_INSUFFICIENT_RESOURCES);
		}
	} else {
		pr_sgl = pr_sgl_arr;
	}

	for (i = 0; i < num_segments; i++) {
		pr_sgl[i].ds_va = (ib_vaddr_t)local_iov[i].virtual_address;
		pr_sgl[i].ds_key = (ibt_lkey_t)local_iov[i].lmr_context;
		pr_sgl[i].ds_len = (ib_msglen_t)local_iov[i].segment_length;

		total_len += pr_sgl[i].ds_len;
		dapl_dbg_log(DAPL_DBG_TYPE_EP, "dapls_ib_post_recv: "
		    "i(%d) va(%p), lmrctxt(0x%x), len(%llu)\n", i,
		    pr_sgl[i].ds_va, pr_sgl[i].ds_key, pr_sgl[i].ds_len);
	}

	if (cookie != NULL) {
		cookie->val.dto.size =  total_len;
		dapl_dbg_log(DAPL_DBG_TYPE_EP,
		    "dapls_ib_post_recv: dto_cookie(%p), num_seg(%d), "
		    "size(%d) hkey(%016llx)\n", cookie, num_segments,
		    cookie->val.dto.size, ep_ptr->qp_handle->ep_hkey);
	}

	pr_wr.wr_id = (ibt_wrid_t)(uintptr_t)cookie;
	pr_wr.wr_nds = (uint32_t)num_segments;
	if (num_segments > 0) {
		pr_wr.wr_sgl = &pr_sgl[0];
	} else {
		pr_wr.wr_sgl = NULL;
	}

	if (ep_ptr->param.ep_attr.recv_completion_flags &
	    DAT_COMPLETION_UNSIGNALLED_FLAG) {
		/* This flag is used to control notification of completions */
		suppress_notification = (completion_flags &
		    DAT_COMPLETION_UNSIGNALLED_FLAG) ? B_TRUE : B_FALSE;
	} else {
		/*
		 * The evd waiter will use threshold to control wakeups
		 * Hence the event notification will be done via arming the
		 * CQ so we do not need special notification generation
		 * hence set suppression to true
		 */
		suppress_notification = B_TRUE;
	}

	retval = DAPL_RECV(ep_ptr)(ep_ptr, &pr_wr, suppress_notification);

	if (retval != 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_EP,
		    "dapls_ib_post_recv: post_recv failed %s\n",
		    strerror(errno));
	}

	/* free the pr_sgl if we had allocated it */
	if (num_segments > DAPL_MAX_IOV) {
		dapl_os_free(pr_sgl, num_segments*sizeof (ibt_wr_ds_t));
	}

	return (retval);
}

/*
 * dapls_ib_post_recv_one
 *
 * Provider specific Post RECV function
 */
DAT_RETURN
dapls_ib_post_recv_one(
	IN DAPL_EP		*ep_ptr,
	IN DAPL_COOKIE		*cookie,
	IN DAT_LMR_TRIPLET	*local_iov)
{
	ibt_recv_wr_t		pr_wr;
	ibt_wr_ds_t		pr_sgl;
	boolean_t		suppress_notification;
	DAT_COUNT		total_len;
	int			retval;

	if (ep_ptr->qp_handle == NULL) {
		dapl_dbg_log(DAPL_DBG_TYPE_EP, "dapls_ib_post_recv_one: "
		    "qp_handle == NULL\n");
		return (DAT_INVALID_PARAMETER);
	}

	pr_sgl.ds_va = (ib_vaddr_t)local_iov->virtual_address;
	pr_sgl.ds_key = (ibt_lkey_t)local_iov->lmr_context;
	pr_sgl.ds_len = (ib_msglen_t)local_iov->segment_length;

	total_len = pr_sgl.ds_len;
	dapl_dbg_log(DAPL_DBG_TYPE_EP, "dapls_ib_post_recv_one: "
	    "va(%p), lmrctxt(0x%x), len(%llu)\n",
	    pr_sgl.ds_va, pr_sgl.ds_key, pr_sgl.ds_len);

	if (cookie != NULL) {
		cookie->val.dto.size =  total_len;
		dapl_dbg_log(DAPL_DBG_TYPE_EP,
		    "dapls_ib_post_recv_one: dto_cookie(%p), num_seg(1), "
		    "size(%d) hkey(%016llx)\n", cookie,
		    cookie->val.dto.size, ep_ptr->qp_handle->ep_hkey);
	}

	pr_wr.wr_id = (ibt_wrid_t)(uintptr_t)cookie;
	pr_wr.wr_nds = 1;
	pr_wr.wr_sgl = &pr_sgl;

	if (ep_ptr->param.ep_attr.recv_completion_flags &
	    DAT_COMPLETION_UNSIGNALLED_FLAG) {
		/* This flag is used to control notification of completions */
		suppress_notification = B_FALSE;
	} else {
		/*
		 * The evd waiter will use threshold to control wakeups
		 * Hence the event notification will be done via arming the
		 * CQ so we do not need special notification generation
		 * hence set suppression to true
		 */
		suppress_notification = B_TRUE;
	}

	retval = DAPL_RECV(ep_ptr)(ep_ptr, &pr_wr, suppress_notification);

	if (retval != 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_EP,
		    "dapls_ib_post_recv_one: post_recv failed %s\n",
		    strerror(errno));
	}

	return (retval);
}

/*
 * dapls_ib_srq_post_recv
 *
 * Provider specific SRQ Post RECV function
 */
DAT_RETURN
dapls_ib_post_srq(
	IN DAPL_SRQ		*srq_ptr,
	IN DAPL_COOKIE		*cookie,
	IN DAT_COUNT		num_segments,
	IN DAT_LMR_TRIPLET	*local_iov)
{
	ibt_recv_wr_t		pr_wr;
	ibt_wr_ds_t		pr_sgl_arr[DAPL_MAX_IOV];
	ibt_wr_ds_t		*pr_sgl;
	DAT_COUNT		total_len;
	int			retval;
	int			i;

	total_len = 0;

	if (srq_ptr->srq_handle == NULL) {
		dapl_dbg_log(DAPL_DBG_TYPE_EP, "dapls_ib_post_srq: "
		    "srq_handle == NULL\n");
		return (DAT_INVALID_PARAMETER);
	}

	/* allocate scatter-gather list on the heap if its large */
	if (num_segments > DAPL_MAX_IOV) {
		pr_sgl = dapl_os_alloc(num_segments * sizeof (ibt_wr_ds_t));
		if (NULL == pr_sgl) {
			dapl_dbg_log(DAPL_DBG_TYPE_ERR,
			    "dapls_ib_post_srq: pr_sgl alloc failed");
			return (DAT_INSUFFICIENT_RESOURCES);
		}
	} else {
		pr_sgl = pr_sgl_arr;
	}

	for (i = 0; i < num_segments; i++) {
		pr_sgl[i].ds_va = (ib_vaddr_t)local_iov[i].virtual_address;
		pr_sgl[i].ds_key = (ibt_lkey_t)local_iov[i].lmr_context;
		pr_sgl[i].ds_len = (ib_msglen_t)local_iov[i].segment_length;

		total_len += pr_sgl[i].ds_len;
		dapl_dbg_log(DAPL_DBG_TYPE_EP, "dapls_ib_post_srq: "
		    "i(%d) va(%p), lmrctxt(0x%x), len(%u)\n", i,
		    pr_sgl[i].ds_va, pr_sgl[i].ds_key, pr_sgl[i].ds_len);
	}

	if (cookie != NULL) {
		cookie->val.dto.size =  total_len;
		dapl_dbg_log(DAPL_DBG_TYPE_EP,
		    "dapls_ib_post_srq: dto_cookie(%p), num_seg(%d), "
		    "size(%d) hkey(%016llx)\n", cookie, num_segments,
		    cookie->val.dto.size, srq_ptr->srq_handle->srq_hkey);
	}

	pr_wr.wr_id = (ibt_wrid_t)(uintptr_t)cookie;
	pr_wr.wr_nds = (uint32_t)num_segments;
	if (num_segments > 0) {
		pr_wr.wr_sgl = &pr_sgl[0];
	} else {
		pr_wr.wr_sgl = NULL;
	}

	retval = DAPL_SRECV(srq_ptr)(srq_ptr, &pr_wr, B_TRUE);

	if (retval != 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_EP,
		    "dapls_ib_post_srq: post_recv failed %s\n",
		    strerror(errno));
	}

	/* free the pr_sgl if we had allocated it */
	if (num_segments > DAPL_MAX_IOV) {
		dapl_os_free(pr_sgl, num_segments*sizeof (ibt_wr_ds_t));
	}

	return (retval);
}

/*
 * dapls_ib_post_send
 *
 * Provider specific Post SEND function
 */
DAT_RETURN
dapls_ib_post_send(IN DAPL_EP *ep_ptr,
    IN ib_send_op_type_t op_type,
    IN DAPL_COOKIE *cookie,
    IN DAT_COUNT num_segments,
    IN DAT_LMR_TRIPLET *local_iov,
    IN const DAT_RMR_TRIPLET *remote_iov,
    IN DAT_COMPLETION_FLAGS completion_flags)
{
	ibt_send_wr_t		ps_wr;
	ibt_wr_ds_t		ps_sgl_arr[DAPL_MAX_IOV];
	ibt_wr_ds_t		*ps_sgl;
	DAT_COUNT		total_len;
	boolean_t		suppress_notification;
	int			retval;
	int			i;

	total_len = 0;
	retval = DAT_SUCCESS;

	if (ep_ptr->qp_handle == NULL) {
		dapl_dbg_log(DAPL_DBG_TYPE_EP, "dapls_ib_post_send: "
		    "qp_handle == NULL\n");
		return (DAT_INVALID_PARAMETER);
	}

	/* allocate scatter-gather list on the heap if its large */
	if (num_segments > DAPL_MAX_IOV) {
		ps_sgl = dapl_os_alloc(num_segments * sizeof (ibt_wr_ds_t));
		if (NULL == ps_sgl) {
			dapl_dbg_log(DAPL_DBG_TYPE_ERR,
			    "dapls_ib_post_send: pr_sgl alloc failed");
			return (DAT_INSUFFICIENT_RESOURCES);
		}
	} else {
		ps_sgl = ps_sgl_arr;
	}

	for (i = 0; i < num_segments; i++) {
		ps_sgl[i].ds_va = (ib_vaddr_t)local_iov[i].virtual_address;
		ps_sgl[i].ds_key = (ibt_lkey_t)local_iov[i].lmr_context;
		ps_sgl[i].ds_len = (ib_msglen_t)local_iov[i].segment_length;
		total_len += ps_sgl[i].ds_len;

		dapl_dbg_log(DAPL_DBG_TYPE_EP, "dapls_ib_post_send: "
		    "i(%d), va(0x%llx), lmrctxt(0x%x), len(%u)\n",
		    i, ps_sgl[i].ds_va, ps_sgl[i].ds_key, ps_sgl[i].ds_len);
	}

	if (cookie != NULL)	{
		cookie->val.dto.size =  total_len;
		dapl_dbg_log(DAPL_DBG_TYPE_EVD,
		    "dapls_ib_post_send: op_type(%d), cookie(%p) "
		    "num_seg(%d) size(%d) hkey(%016llx)\n", op_type,
		    cookie, num_segments, cookie->val.dto.size,
		    ep_ptr->qp_handle->ep_hkey);
	}

	ps_wr.wr_id = (ibt_wrid_t)(uintptr_t)cookie;
	/* Translate dapl flags */
	ps_wr.wr_flags = (DAT_COMPLETION_BARRIER_FENCE_FLAG &
	    completion_flags) ? IBT_WR_SEND_FENCE : 0;
	/* suppress completions */
	ps_wr.wr_flags |= (DAT_COMPLETION_SUPPRESS_FLAG &
	    completion_flags) ? 0 : IBT_WR_SEND_SIGNAL;

	/* Solicited wait flag is valid only for post_send */
	if (op_type == OP_SEND) {
		ps_wr.wr_flags |= (DAT_COMPLETION_SOLICITED_WAIT_FLAG &
		    completion_flags) ? IBT_WR_SEND_SOLICIT : 0;
	}

	ps_wr.wr_opcode = (ibt_wrc_opcode_t)op_type;
	ps_wr.wr_nds = (uint32_t)num_segments;
	if (num_segments > 0) {
		ps_wr.wr_sgl = &ps_sgl[0];
		if (op_type == OP_RDMA_READ || op_type == OP_RDMA_WRITE) {
			if (remote_iov == NULL) {
				/* free the ps_sgl if we had allocated it */
				if (num_segments > DAPL_MAX_IOV) {
					dapl_os_free(ps_sgl,
					    num_segments*sizeof (ibt_wr_ds_t));
				}
				dapl_dbg_log(DAPL_DBG_TYPE_EP,
				    "dapls_ib_post_send: "
				    "remote_iov == NULL\n");
				return (DAT_INVALID_PARAMETER);
			}

			if (remote_iov->segment_length != (DAT_VLEN)total_len) {
				/* free the ps_sgl if we had allocated it */
				if (num_segments > DAPL_MAX_IOV) {
					dapl_os_free(ps_sgl,
					    num_segments*sizeof (ibt_wr_ds_t));
				}
				dapl_dbg_log(DAPL_DBG_TYPE_EP,
				    "dapls_ib_post_send: "
				    "remote_iov length(%llu != %llu)\n",
				    (DAT_VLEN)total_len,
				    remote_iov->segment_length);
				return (DAT_LENGTH_ERROR);
			}

			ps_wr.wr.rc.rcwr.rdma.rdma_raddr =
			    (ib_vaddr_t)remote_iov->target_address;
			ps_wr.wr.rc.rcwr.rdma.rdma_rkey =
			    (ibt_rkey_t)remote_iov->rmr_context;

			dapl_dbg_log(DAPL_DBG_TYPE_EP,
			    "dapls_ib_post_send: remote_iov taddr(0x%llx), "
			    "rmr(0x%x)\n", remote_iov->target_address,
			    remote_iov->rmr_context);
		}
	} else {
		ps_wr.wr_sgl = NULL;
	}

	if (ep_ptr->param.ep_attr.recv_completion_flags &
	    DAT_COMPLETION_UNSIGNALLED_FLAG) {
		/* This flag is used to control notification of completions */
		suppress_notification = (completion_flags &
		    DAT_COMPLETION_UNSIGNALLED_FLAG) ? B_TRUE : B_FALSE;
	} else {
		/*
		 * The evd waiter will use threshold to control wakeups
		 * Hence the event notification will be done via arming the
		 * CQ so we do not need special notification generation
		 * hence set suppression to true
		 */
		suppress_notification = B_TRUE;
	}

	retval = DAPL_SEND(ep_ptr)(ep_ptr, &ps_wr, suppress_notification);

	if (retval != 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_EP,
		    "dapls_ib_post_send: post_send failed %d\n", retval);
	}

	/* free the pr_sgl if we had allocated it */
	if (num_segments > DAPL_MAX_IOV) {
		dapl_os_free(ps_sgl, num_segments*sizeof (ibt_wr_ds_t));
	}

	return (retval);
}

/*
 * dapls_ib_post_send_one
 *
 * Provider specific Post SEND function - special case for the common case of
 * sgl num_segments == 1 and completion_flags == DAT_COMPLETION_DEFAULT_FLAG.
 */
DAT_RETURN
dapls_ib_post_send_one(IN DAPL_EP *ep_ptr,
    IN ib_send_op_type_t op_type,
    IN DAPL_COOKIE *cookie,
    IN DAT_LMR_TRIPLET *local_iov,
    IN const DAT_RMR_TRIPLET *remote_iov)
{
	ibt_send_wr_t		ps_wr;
	ibt_wr_ds_t		ps_sgl;
	boolean_t		suppress_notification;
	int			retval;

	if (ep_ptr->qp_handle == NULL) {
		dapl_dbg_log(DAPL_DBG_TYPE_EP, "dapls_ib_post_send_one: "
		    "qp_handle == NULL\n");
		return (DAT_INVALID_PARAMETER);
	}

	ps_sgl.ds_va = (ib_vaddr_t)local_iov[0].virtual_address;
	ps_sgl.ds_key = (ibt_lkey_t)local_iov[0].lmr_context;
	ps_sgl.ds_len = (ib_msglen_t)local_iov[0].segment_length;

	dapl_dbg_log(DAPL_DBG_TYPE_EP, "dapls_ib_post_send_one: "
	    "i(%d), va(0x%llx), lmrctxt(0x%x), len(%u)\n",
	    0, ps_sgl.ds_va, ps_sgl.ds_key, ps_sgl.ds_len);

	cookie->val.dto.size =  ps_sgl.ds_len;
	dapl_dbg_log(DAPL_DBG_TYPE_EVD,
	    "dapls_ib_post_send_one: op_type(%d), cookie(%p) "
	    "num_seg(%d) size(%d) hkey(%016llx)\n", op_type,
	    cookie, 1, cookie->val.dto.size,
	    ep_ptr->qp_handle->ep_hkey);

	ps_wr.wr_id = (ibt_wrid_t)(uintptr_t)cookie;
	/* suppress completions */
	ps_wr.wr_flags = IBT_WR_SEND_SIGNAL;

	ps_wr.wr_opcode = (ibt_wrc_opcode_t)op_type;
	ps_wr.wr_nds = 1;

	ps_wr.wr_sgl = &ps_sgl;
	if (op_type == OP_RDMA_READ || op_type == OP_RDMA_WRITE) {
		if (remote_iov == NULL) {
			/* free the ps_sgl if we had allocated it */
			dapl_dbg_log(DAPL_DBG_TYPE_EP,
			    "dapls_ib_post_send_one: "
			    "remote_iov == NULL\n");
			return (DAT_INVALID_PARAMETER);
		}

		if (remote_iov->segment_length != (DAT_VLEN)ps_sgl.ds_len) {
			dapl_dbg_log(DAPL_DBG_TYPE_EP,
			    "dapls_ib_post_send_one: "
			    "remote_iov length(%llu != %llu)\n",
			    (DAT_VLEN)ps_sgl.ds_len,
			    remote_iov->segment_length);
			return (DAT_LENGTH_ERROR);
		}

		ps_wr.wr.rc.rcwr.rdma.rdma_raddr =
		    (ib_vaddr_t)remote_iov->target_address;
		ps_wr.wr.rc.rcwr.rdma.rdma_rkey =
		    (ibt_rkey_t)remote_iov->rmr_context;

		dapl_dbg_log(DAPL_DBG_TYPE_EP,
		    "dapls_ib_post_send_one: remote_iov taddr(0x%llx), "
		    "rmr(0x%x)\n", remote_iov->target_address,
		    remote_iov->rmr_context);
	}

	if (ep_ptr->param.ep_attr.recv_completion_flags &
	    DAT_COMPLETION_UNSIGNALLED_FLAG) {
		/* This flag is used to control notification of completions */
		suppress_notification = B_FALSE;
	} else {
		/*
		 * The evd waiter will use threshold to control wakeups
		 * Hence the event notification will be done via arming the
		 * CQ so we do not need special notification generation
		 * hence set suppression to true
		 */
		suppress_notification = B_TRUE;
	}

	retval = DAPL_SEND(ep_ptr)(ep_ptr, &ps_wr, suppress_notification);

	if (retval != 0) {
		dapl_dbg_log(DAPL_DBG_TYPE_EP,
		    "dapls_ib_post_send_one: post_send failed %d\n", retval);
	}

	return (retval);
}
