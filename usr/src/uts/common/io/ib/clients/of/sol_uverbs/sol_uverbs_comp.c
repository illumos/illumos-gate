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
 * Copyright (c) 2010, Oracle and/or its affiliates. All rights reserved.
 */


/*
 * NAME: sol_uverbs_comp.c
 *
 * OFED User Verbs Kernel completion queue/processing implementation
 *
 */
#include <sys/file.h>
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/uio.h>
#include <sys/semaphore.h>
#include <sys/ddi.h>

#include <sys/ib/clients/of/ofa_solaris.h>
#include <sys/ib/clients/of/sol_ofs/sol_ofs_common.h>
#include <sys/ib/ibtl/ibvti.h>
#include <sys/ib/clients/of/ofed_kernel.h>
#include <sys/ib/clients/of/sol_uverbs/sol_uverbs.h>
#include <sys/ib/clients/of/sol_uverbs/sol_uverbs_comp.h>
#include <sys/ib/clients/of/sol_uverbs/sol_uverbs_event.h>

extern char	*sol_uverbs_dbg_str;

/*
 * Function:
 *      uverbs_convert_wc
 * Input:
 *      uctxt	- Pointer to the callers user context.
 *	ibt_wc	- Pointer to IBT work completion.
 * Output:
 *      ofed_wc	- Pointer to hold converted OFED work completion.
 * Returns:
 *      None
 * Description:
 *      Convert and IBT work completion to an OFED work completion.
 */
/* ARGSUSED */
static void
uverbs_convert_wc(uverbs_uctxt_uobj_t *uctxt, ibt_wc_t *ibt_wc,
    struct ib_uverbs_wc *ofed_wc)
{
	ASSERT(uctxt != NULL);
	ASSERT(ibt_wc != NULL);
	ASSERT(ofed_wc != NULL);

	ofed_wc->wr_id	= ibt_wc->wc_id;

	switch (ibt_wc->wc_status) {

		case IBT_WC_SUCCESS:
			ofed_wc->status	= IB_WC_SUCCESS;
			break;
		case IBT_WC_LOCAL_LEN_ERR:
			ofed_wc->status	= IB_WC_LOC_LEN_ERR;
			break;
		case IBT_WC_LOCAL_CHAN_OP_ERR:
			ofed_wc->status	= IB_WC_LOC_QP_OP_ERR;
			break;
		case IBT_WC_LOCAL_PROTECT_ERR:
			ofed_wc->status	= IB_WC_LOC_PROT_ERR;
			break;
		case IBT_WC_WR_FLUSHED_ERR:
			ofed_wc->status	= IB_WC_WR_FLUSH_ERR;
			break;
		case IBT_WC_MEM_WIN_BIND_ERR:
			ofed_wc->status	= IB_WC_MW_BIND_ERR;
			break;
		case IBT_WC_BAD_RESPONSE_ERR:
			ofed_wc->status	= IB_WC_BAD_RESP_ERR;
			break;
		case IBT_WC_LOCAL_ACCESS_ERR:
			ofed_wc->status	= IB_WC_LOC_ACCESS_ERR;
			break;
		case IBT_WC_REMOTE_INVALID_REQ_ERR:
			ofed_wc->status	= IB_WC_REM_INV_REQ_ERR;
			break;
		case IBT_WC_REMOTE_ACCESS_ERR:
			ofed_wc->status	= IB_WC_REM_ACCESS_ERR;
			break;
		case IBT_WC_REMOTE_OP_ERR:
			ofed_wc->status	= IB_WC_REM_OP_ERR;
			break;
		case IBT_WC_TRANS_TIMEOUT_ERR:
		case IBT_WC_RNR_NAK_TIMEOUT_ERR:
			ofed_wc->status	= IB_WC_RESP_TIMEOUT_ERR;
			break;
		default:
			ofed_wc->status	= IB_WC_FATAL_ERR;
			break;
	}

	switch (ibt_wc->wc_type) {

		case IBT_WRC_SEND:
			ofed_wc->opcode	= IB_WC_SEND;
			break;
		case IBT_WRC_RDMAR:
			ofed_wc->opcode	= IB_WC_RDMA_READ;
			break;
		case IBT_WRC_RDMAW:
			ofed_wc->opcode	= IB_WC_RDMA_WRITE;
			break;
		case IBT_WRC_CSWAP:
			ofed_wc->opcode	= IB_WC_COMP_SWAP;
			break;
		case IBT_WRC_FADD:
			ofed_wc->opcode	= IB_WC_FETCH_ADD;
			break;
		case IBT_WRC_BIND:
			ofed_wc->opcode	= IB_WC_BIND_MW;
			break;
		case IBT_WRC_RECV:
			ofed_wc->opcode	= IB_WC_RECV;
			break;
		case IBT_WRC_RECV_RDMAWI:
			ofed_wc->opcode	= IB_WC_RECV_RDMA_WITH_IMM;
			break;

		case IBT_WRC_FAST_REG_PMR:
		case IBT_WRC_LOCAL_INVALIDATE:
		default:
			ofed_wc->opcode	= -1; /* (?) What to do here */
			break;
	}

	ofed_wc->vendor_err 	= 0;
	ofed_wc->byte_len 	= ibt_wc->wc_bytes_xfer;
	ofed_wc->imm_data 	= ibt_wc->wc_immed_data;
	ofed_wc->qp_num 	= ibt_wc->wc_local_qpn;
	ofed_wc->src_qp 	= ibt_wc->wc_qpn;
	ofed_wc->wc_flags	= 0;

	if (ibt_wc->wc_flags & IBT_WC_GRH_PRESENT) {
		ofed_wc->wc_flags |= IB_WC_GRH;
	}

	if (ibt_wc->wc_flags & IBT_WC_IMMED_DATA_PRESENT) {
		ofed_wc->wc_flags |= IB_WC_WITH_IMM;
	}

	ofed_wc->pkey_index	= ibt_wc->wc_pkey_ix;
	ofed_wc->slid		= ibt_wc->wc_slid;
	ofed_wc->sl		= ibt_wc->wc_sl;
	ofed_wc->dlid_path_bits	= ibt_wc->wc_path_bits;
	ofed_wc->port_num	= 0;
	ofed_wc->reserved	= 0;
}

/*
 * Function:
 *      sol_uverbs_create_cq
 * Input:
 *	uctxt   - Pointer to the callers user context.
 *	buf     - Pointer to kernel buffer containing create CQ command.
 *	in_len  - Length in bytes of input command buffer.
 *	out_len - Length in bytes of output response buffer.
 * Output:
 *	The command output buffer is updated with command results.
 * Returns:
 *      DDI_SUCCESS on success, else error code.
 * Description:
 *      User verbs entry point to create a device CQ.
 */
/* ARGSUSED */
int
sol_uverbs_create_cq(uverbs_uctxt_uobj_t *uctxt, char *buf,
    int in_len, int out_len)
{
	struct ib_uverbs_create_cq	cmd;
	struct ib_uverbs_create_cq_resp	resp;
	uverbs_ucq_uobj_t		*ucq;
	ibt_cq_attr_t			cq_attr;
	uint_t				real_size;
	int				rc;

	(void) memcpy(&cmd, buf, sizeof (cmd));
	(void) memset(&resp, 0, sizeof (resp));
	(void) memset(&cq_attr, 0, sizeof (cq_attr));

	cq_attr.cq_size	  = cmd.cqe;
	cq_attr.cq_sched  = 0;
	cq_attr.cq_flags  = IBT_CQ_USER_MAP;

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str, "create_cq: "
	    "num_cqe=%d, sched=%x, flags=%x",
	    cq_attr.cq_size, cq_attr.cq_sched, cq_attr.cq_flags);

	/*
	 * To be consistent with OFED semantics, we fail a CQ that is being
	 * created with 0 CQ entries.
	 */
	if (!cmd.cqe) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str, "create_cq: 0 cqe");
		rc = EINVAL;
		goto err_out;
	}

	ucq = kmem_zalloc(sizeof (*ucq), KM_NOSLEEP);
	if (!ucq) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "create_cq: mem alloc failure");
		rc = ENOMEM;
		goto err_out;
	}
	sol_ofs_uobj_init(&ucq->uobj, cmd.user_handle,
	    SOL_UVERBS_UCQ_UOBJ_TYPE);
	rw_enter(&ucq->uobj.uo_lock, RW_WRITER);
	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "create_cq: ucq %p, comp_chan %d", ucq, cmd.comp_channel);

	/*
	 * If a event completion channel was specified look it up and
	 * assign the channel to the user CQ object.  Note that this
	 * places a reference on the file itself.
	 */
	if ((int)cmd.comp_channel > SOL_UVERBS_DRIVER_MAX_MINOR) {
		uverbs_uctxt_uobj_t	*compl_uctxt = NULL;
		uverbs_ufile_uobj_t	*ufile;

		SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str, "create_cq: "
		    "cmd.comp_chan %d", cmd.comp_channel);
		compl_uctxt = uverbs_uobj_get_uctxt_write(
		    cmd.comp_channel - SOL_UVERBS_DRIVER_MAX_MINOR);
		if (!compl_uctxt) {
			SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
			    "create_cq: Invalid comp channel %d",
			    cmd.comp_channel);
			rc = EINVAL;
			goto chan_err;
		}
		if (compl_uctxt->uctxt_verbs_id != uctxt->uobj.uo_id +
		    SOL_UVERBS_DRIVER_MAX_MINOR) {
			SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
			    "create_cq: Invalid comp channel %d, "
			    "verbs id %d mismatch",
			    cmd.comp_channel,
			    compl_uctxt->uctxt_verbs_id);
			rc = EINVAL;
			sol_ofs_uobj_put(&compl_uctxt->uobj);
			goto chan_err;
		}
		ufile = compl_uctxt->comp_evfile;
		ucq->comp_chan = ufile;
		rw_enter(&ufile->uobj.uo_lock, RW_WRITER);
		ufile->ufile_cq_cnt++;
		rw_exit(&ufile->uobj.uo_lock);
		sol_ofs_uobj_put(&compl_uctxt->uobj);

		SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str, "create_cq: "
		    "ucq %p, comp_chan %p", ucq, ucq->comp_chan);
	} else {
		ucq->comp_chan = NULL;
	}

	llist_head_init(&ucq->async_list, NULL);
	llist_head_init(&ucq->comp_list, NULL);

	rc = ibt_alloc_cq(uctxt->hca->hdl, &cq_attr, &ucq->cq, &real_size);

	if (rc != IBT_SUCCESS) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "create_cq: ibt_alloc_cq() (rc=%d)", rc);
		rc = sol_uverbs_ibt_to_kernel_status(rc);
		ucq->uobj.uo_uobj_sz = sizeof (uverbs_ucq_uobj_t);
		goto alloc_err;
	}

	ibt_set_cq_private(ucq->cq, ucq);

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "create_cq: ib_alloc_cq() (rc=%d), real_size=%d",
	    rc, real_size);
	/*
	 * Query underlying hardware for data used in mapping CQ back to user
	 * space, we will return this information in the user verbs command
	 * response.
	 */
	rc = ibt_ci_data_out(uctxt->hca->hdl, IBT_CI_NO_FLAGS, IBT_HDL_CQ,
	    (void *) ucq->cq,  &resp.drv_out, sizeof (resp.drv_out));
	if (rc != IBT_SUCCESS) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "create_cq: ibt_ci_data_out() rc=%d", rc);
		rc = EFAULT;
		ucq->uobj.uo_uobj_sz = sizeof (uverbs_ucq_uobj_t);
		goto err_cq_destroy;
	}

	if (sol_ofs_uobj_add(&uverbs_ucq_uo_tbl, &ucq->uobj) != 0) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "create_cq: User object add failed");
		rc = ENOMEM;
		goto err_cq_destroy;
	}

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "create_cq: ibt_ci_data_out: 0x%16llx 0x%16llx "
	    "0x%16llx 0x%16llx", resp.drv_out[0], resp.drv_out[1],
	    resp.drv_out[2], resp.drv_out[3]);

	resp.cqe	= real_size;
	resp.cq_handle	= ucq->uobj.uo_id;

#ifdef	_LP64
	rc = copyout((void*)&resp, (void*)cmd.response.r_laddr, sizeof (resp));
#else
	rc = copyout((void*)&resp, (void*)cmd.response.r_addr, sizeof (resp));
#endif
	if (rc != 0) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "create_cq: copyout failed %x", rc);
		rc = EFAULT;
		goto err_uo_delete;
	}

	ucq->uctxt = uctxt;

	mutex_enter(&uctxt->lock);
	ucq->list_entry = add_genlist(&uctxt->cq_list, (uintptr_t)ucq, uctxt);
	mutex_exit(&uctxt->lock);

	if (!ucq->list_entry) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "create_cq: Error adding ucq to cq_list");
		rc = ENOMEM;
		goto err_uo_delete;
	}

	if (ucq->comp_chan) {
		ibt_set_cq_handler(ucq->cq, sol_uverbs_comp_event_handler, ucq);
	}

	ucq->uobj.uo_live = 1;
	rw_exit(&ucq->uobj.uo_lock);

	return (DDI_SUCCESS);

err_uo_delete:
	/*
	 * Need to set uo_live, so sol_ofs_uobj_remove() will
	 * remove the object from the object table.
	 */
	ucq->uobj.uo_live = 1;
	(void) sol_ofs_uobj_remove(&uverbs_ucq_uo_tbl, &ucq->uobj);

err_cq_destroy:
	(void) ibt_free_cq(ucq->cq);

alloc_err:
	if (ucq->comp_chan) {
		uverbs_release_ucq_channel(uctxt, ucq->comp_chan, ucq);
	}

chan_err:
	rw_exit(&ucq->uobj.uo_lock);
	sol_ofs_uobj_deref(&ucq->uobj, sol_ofs_uobj_free);

err_out:
	return (rc);
}

int
uverbs_ucq_free(uverbs_ucq_uobj_t *ucq, uverbs_uctxt_uobj_t *uctxt)
{
	int	rc;

	rc = ibt_free_cq(ucq->cq);
	if (rc != IBT_SUCCESS) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "destroy_id: ibt_free_cq() rc=%d",
		    rc);
		rc = sol_uverbs_ibt_to_kernel_status(rc);
		sol_ofs_uobj_put(&ucq->uobj);
		return (rc);
	}
	(void) sol_ofs_uobj_remove(&uverbs_ucq_uo_tbl, &ucq->uobj);
	sol_ofs_uobj_put(&ucq->uobj);

	if (ucq->list_entry) {
		mutex_enter(&uctxt->lock);
		delete_genlist(&uctxt->cq_list,  ucq->list_entry);
		mutex_exit(&uctxt->lock);
	}
	sol_ofs_uobj_deref(&ucq->uobj, sol_ofs_uobj_free);
	return (0);
}

/*
 * Function:
 *      sol_uverbs_destroy_cq
 * Input:
 *	uctxt   - Pointer to the callers user context.
 *	buf     - Pointer to kernel buffer containing a destroy CQ command.
 *	in_len  - Length in bytes of input command buffer.
 *	out_len - Length in bytes of output response buffer.
 * Output:
 *	The command output buffer is updated with command results.
 * Returns:
 *      DDI_SUCCESS on success, else error code.
 * Description:
 *      User verbs entry point to destroy a device CQ.
 */
/* ARGSUSED */
int
sol_uverbs_destroy_cq(uverbs_uctxt_uobj_t *uctxt, char *buf,
    int in_len, int out_len)
{
	struct ib_uverbs_destroy_cq		cmd;
	struct ib_uverbs_destroy_cq_resp	resp;
	uverbs_ucq_uobj_t			*ucq;
	int					rc;

	(void) memcpy(&cmd, buf, sizeof (cmd));
	(void) memset(&resp, 0, sizeof (resp));

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "destroy_cq(cq_handle=%d)", cmd.cq_handle);

	ucq = uverbs_uobj_get_ucq_write(cmd.cq_handle);
	if (ucq == NULL) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "destroy_cq: Invalid handle: %d",
		    cmd.cq_handle);
		rc = EINVAL;
		goto err_out;
	}

	uverbs_release_ucq_channel(uctxt, ucq->comp_chan, ucq);
	cmd.cq_handle			= 0;
	resp.comp_events_reported	= ucq->comp_events_reported;
	resp.async_events_reported	= ucq->async_events_reported;

	if (ucq->active_qp_cnt) {
		sol_ofs_uobj_put(&ucq->uobj);
		return (EBUSY);
	} else {
		rc = uverbs_ucq_free(ucq, uctxt);
		if (rc)
			goto err_out;
	}

#ifdef	_LP64
	rc = copyout((void*)&resp, (void*)cmd.response.r_laddr, sizeof (resp));
#else
	rc = copyout((void*)&resp, (void*)cmd.response.r_addr, sizeof (resp));
#endif
	if (rc != 0) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "destroy_cq: copuout failed %x", rc);
		rc = EFAULT;
		goto err_out;
	}

	return (DDI_SUCCESS);

err_out:
	return (rc);
}

/*
 * Function:
 *      sol_uverbs_resize_cq
 * Input:
 *	uctxt   - Pointer to the callers user context.
 *	buf     - Pointer to kernel buffer containing a resize CQ command.
 *	in_len  - Length in bytes of input command buffer.
 *	out_len - Length in bytes of output response buffer.
 * Output:
 *	The command output buffer is updated with command results.
 * Returns:
 *      DDI_SUCCESS on success, else error code.
 * Description:
 *      User verbs entry point to resize a device CQ.
 */
/* ARGSUSED */
int
sol_uverbs_resize_cq(uverbs_uctxt_uobj_t *uctxt, char *buf,
    int in_len, int out_len)
{
	struct ib_uverbs_resize_cq	cmd;
	struct ib_uverbs_resize_cq_resp	resp;
	uverbs_ucq_uobj_t		*ucq;
	int				rc;
	int				resize_status;

	(void) memcpy(&cmd, buf, sizeof (cmd));
	(void) memset(&resp, 0, sizeof (resp));

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "resize_cq(cq_handle=%d)", cmd.cq_handle);

	ucq = uverbs_uobj_get_ucq_write(cmd.cq_handle);
	if (ucq == NULL) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "resize_cq: Invalid handle: %d",
		    cmd.cq_handle);
		rc = EINVAL;
		goto err_out;
	}

	/*
	 * If CQ resize fails, note the error but keep going.  In this case we
	 * expect the old CQ size to be returned, and when we extract the
	 * mapping data, we expect the offset and length are approrpriate for
	 * the old CQ.
	 */
	resize_status = ibt_resize_cq(ucq->cq, cmd.cqe, &resp.cqe);
	if (resize_status != IBT_SUCCESS) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "resize_cq: ibt_resize_cq() (resize_status=%d), using "
		    "original CQ", resize_status);
		rc = sol_uverbs_ibt_to_kernel_status(resize_status);
		goto err_out;
	}

	sol_ofs_uobj_put(&ucq->uobj);

	rc = ibt_ci_data_out(uctxt->hca->hdl, IBT_CI_NO_FLAGS, IBT_HDL_CQ,
	    (void *) ucq->cq,  &resp.drv_out, sizeof (resp.drv_out));
	if (rc != IBT_SUCCESS) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "resize_cq: Error in ibt_ci_data_out() "
		    "(rc=%d)", rc);
		rc = EFAULT;
		goto err_out;
	}

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "resize_cq: ibt_ci_data_out: 0x%16llx 0x%16llx "
	    "0x%16llx 0x%16llx", resp.drv_out[0], resp.drv_out[1],
	    resp.drv_out[2], resp.drv_out[3]);

#ifdef	_LP64
	rc = copyout((void*)&resp, (void*)cmd.response.r_laddr, sizeof (resp));
#else
	rc = copyout((void*)&resp, (void*)cmd.response.r_addr, sizeof (resp));
#endif
	if (rc != 0) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "resize_cq: copyout %d", rc);
		rc = EFAULT;
		goto err_out;
	}

	return (resize_status);

err_out:
	return (rc);
}

/*
 * Function:
 *      sol_uverbs_req_notify_cq
 * Input:
 *	uctxt   - Pointer to the callers user context.
 *	buf     - Pointer to kernel buffer containing request notify
 *	          command.
 *	in_len  - Length in bytes of input command buffer.
 *	out_len - Length in bytes of output response buffer.
 * Output:
 *	The command output buffer is updated with command results.
 * Returns:
 *      DDI_SUCCESS on success, else error code.
 * Description:
 *      User verbs entry point to request notification of CQ events.
 */
/* ARGSUSED */
int
sol_uverbs_req_notify_cq(uverbs_uctxt_uobj_t *uctxt, char *buf,
    int in_len, int out_len)
{
	struct ib_uverbs_req_notify_cq	cmd;
	ibt_cq_notify_flags_t		flag;
	uverbs_ucq_uobj_t		*ucq;
	int				rc;

	(void) memcpy(&cmd, buf, sizeof (cmd));

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "req_notify_cq(cq_handle=%d)", cmd.cq_handle);

	ucq = uverbs_uobj_get_ucq_read(cmd.cq_handle);
	if (ucq == NULL) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "req_notify_cq: List lookup failure");
		rc = EINVAL;
		goto err_out;
	}

	flag = IBT_NEXT_COMPLETION;

	if (cmd.solicited_only != 0) {
		flag = IBT_NEXT_SOLICITED;
	}

	rc = ibt_enable_cq_notify(ucq->cq, flag);
	if (rc != IBT_SUCCESS) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "req_notify_cq: ibt_enable_cq_notify() "
		    "(rc=%d)", rc);
		rc = sol_uverbs_ibt_to_kernel_status(rc);
		goto err_put;
	}

	sol_ofs_uobj_put(&ucq->uobj);
	return (DDI_SUCCESS);

err_put:
	sol_ofs_uobj_put(&ucq->uobj);

err_out:
	return (rc);
}

/*
 * Function:
 *      sol_uverbs_poll_cq
 * Input:
 *	uctxt   - Pointer to the callers user context.
 *	buf     - Pointer to kernel buffer containing poll CQ command.
 *	in_len  - Length in bytes of input command buffer.
 *	out_len - Length in bytes of output response buffer.
 * Output:
 *	The command output buffer is updated with command results.
 * Returns:
 *      DDI_SUCCESS on success, else error code.
 * Description:
 *      User verbs entry point to poll a CQ for completion events.  Note that
 * 	this is	a non OS Bypass version, the CQ normally would be polled
 *	directly from the user space driver.
 */
/* ARGSUSED */
int
sol_uverbs_poll_cq(uverbs_uctxt_uobj_t *uctxt, char *buf,
    int in_len, int out_len)
{
	struct ib_uverbs_poll_cq	cmd;
	struct ib_uverbs_poll_cq_resp	resp;
	uverbs_ucq_uobj_t		*ucq;
	ibt_wc_t			*completions;
	struct ib_uverbs_wc		ofed_wc;
	int				rc;
	int				i;

	(void) memcpy(&cmd, buf, sizeof (cmd));
	(void) memset(&resp, 0, sizeof (resp));

#ifdef DEBUG
	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "poll_cq(cq_handle=%d)", cmd.cq_handle);
#endif

	ucq = uverbs_uobj_get_ucq_read(cmd.cq_handle);
	if (ucq == NULL) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "poll_cq: List lookup failure");
		rc = EINVAL;
		goto err_find;
	}

	completions = (ibt_wc_t *)kmem_zalloc(sizeof (ibt_wc_t) * cmd.ne,
	    KM_NOSLEEP);
	if (completions == NULL) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "poll_cq: Allocation Error");
		rc = ENOMEM;
		goto err_alloc;
	}

	rc = ibt_poll_cq(ucq->cq, completions, cmd.ne, &resp.count);
	if (rc != IBT_SUCCESS) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "poll_cq: ibt_poll_cq() (rc=%d)", rc);
		rc = sol_uverbs_ibt_to_kernel_status(rc);
		goto err_poll;
	}

#ifdef	_LP64
	rc = copyout((void*)&resp, (void*)cmd.response.r_laddr, sizeof (resp));
#else
	rc = copyout((void*)&resp, (void*)cmd.response.r_addr, sizeof (resp));
#endif
	if (rc != 0) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "poll_cq: copyout %x", rc);
		rc = EFAULT;
		goto err_poll;
	}

	for (i = 0; i < resp.count; i++) {
		(void) memset(&ofed_wc, 0, sizeof (ofed_wc));
		uverbs_convert_wc(uctxt, &completions[i], &ofed_wc);

#ifdef	_LP64
		rc = copyout((void*)&ofed_wc,
		    (void *)cmd.response.r_laddr, sizeof (ofed_wc));
#else
		rc = copyout((void*)&ofed_wc,
		    (void *)cmd.response.r_addr, sizeof (ofed_wc));
#endif
		if (rc != 0) {
			SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
			    "poll_cq: copyout wc data %x", rc);
			rc = EFAULT;
			goto err_poll;
		}
	}

	kmem_free((void*)completions, sizeof (ibt_wc_t) * cmd.ne);
	sol_ofs_uobj_put(&ucq->uobj);

	return (DDI_SUCCESS);

err_poll:
	kmem_free((void *)completions, sizeof (ibt_wc_t) * cmd.ne);

err_alloc:
	sol_ofs_uobj_put(&ucq->uobj);

err_find:
	return (rc);
}

/*
 * Function:
 *      sol_uverbs_comp_event_handler
 * Input:
 *      ibt_cq  - Handle to the IBT CQ.
 *      arg     - Address of the associated Solaris User Verbs CQ
 *	          object.
 * Output:
 *      None
 * Returns:
 *      None
 * Description:
 *	Solaris User Verbs completion channel IBT CQ callback.  Queue
 *	the completion event and wakeup/notify consumers that may be
 *	blocked waiting for the completion.
 */
/* ARGSUSED */
void
sol_uverbs_comp_event_handler(ibt_cq_hdl_t ibt_cq, void *arg)
{
	uverbs_ucq_uobj_t	*ucq = arg;
	uverbs_ufile_uobj_t	*ufile;
	uverbs_event_t		*entry;

	if (!ucq || !ucq->comp_chan) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str, "comp_evt_hdlr "
		    "ucq %p ucq->comp_chan %p", ucq, (ucq) ? ucq->comp_chan :
		    NULL);
		return;
	}

#ifdef DEBUG
	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str, "comp_evt_hdlr(%p, %p) - ",
	    "ucq = %p, ucq->cq = %p, ucq->uctxt = %p, ucq->comp_chan =%p",
	    ibt_cq, arg, ucq, ucq->cq, ucq->uctxt, ucq->comp_chan);
#endif

	ufile = ucq->comp_chan;

	mutex_enter(&ufile->lock);
	if (!ufile->uctxt) {
		mutex_exit(&ufile->lock);
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str, "comp_evt_hdlr "
		    "ufile->uctxt %p", ufile->uctxt);
		return;
	}

	entry = kmem_zalloc(sizeof (*entry), KM_NOSLEEP);
	if (!entry) {
		mutex_exit(&ufile->lock);
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str, "comp_evt_hdlr() "
		    "memory allocation error");
		return;
	}

	entry->ev_desc.comp.cq_handle	= ucq->uobj.uo_user_handle;
	entry->ev_counter		= &ucq->comp_events_reported;

	/*
	 * Add to list of entries associated with completion channel
	 * and the list associated with the specific CQ.
	 */
	llist_head_init(&entry->ev_list, entry);
	llist_head_init(&entry->ev_obj_list, entry);

#ifdef DEBUG
	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str, "comp_evt_hdlr() "
	    "Add COMP entry->ev_list=%p, &entry->ev_obj_list, entry=%p",
	    &entry->ev_list, &entry->ev_obj_list, entry);
#endif

	llist_add_tail(&entry->ev_list, &ufile->event_list);
	llist_add_tail(&entry->ev_obj_list, &ucq->comp_list);

	/* Do not notify users if sol_ucma has disabled CQ notify */
	if (ufile->ufile_notify_enabled ==
	    SOL_UVERBS2UCMA_CQ_NOTIFY_DISABLE) {
		mutex_exit(&ufile->lock);
		return;
	}

	cv_signal(&ufile->poll_wait);
	mutex_exit(&ufile->lock);
	pollwakeup(&ufile->poll_head, POLLIN | POLLRDNORM);
}
