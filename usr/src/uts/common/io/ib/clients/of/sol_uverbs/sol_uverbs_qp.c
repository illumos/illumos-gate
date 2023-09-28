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
 * sol_uverbs_qp.c
 *
 * OFED User Verbs kernel agent QP implementation.
 *
 */
#include <sys/vfs.h>
#include <sys/vnode.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/uio.h>
#include <sys/semaphore.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/ib/ibtl/ibvti.h>
#include <sys/ib/clients/of/ofa_solaris.h>
#include <sys/ib/clients/of/sol_ofs/sol_ofs_common.h>
#include <sys/ib/clients/of/ofed_kernel.h>
#include <sys/ib/clients/of/sol_uverbs/sol_uverbs.h>
#include <sys/ib/clients/of/sol_uverbs/sol_uverbs_qp.h>
#include <sys/ib/clients/of/sol_uverbs/sol_uverbs_event.h>


static uint32_t	ibt_cep_flags2ibv(ibt_cep_flags_t);
static void	uverbs_cq_ctrl(uverbs_ucq_uobj_t *, sol_uverbs_cq_ctrl_t);

extern char	*sol_uverbs_dbg_str;

/*
 * Multicast Element
 */
typedef struct uverbs_mcast_entry {
	llist_head_t	list;
	ibt_mcg_info_t	mcg;
} uverbs_mcast_entry_t;

/*
 * uverbs_qp_state_table
 *
 * Determine if the requested QP modify operation is valid.  To maintain/ensure
 * consistency with the semantics expected by OFED user verbs operaton, this
 * table is used to verify a QP transition.  A valid transition is one that is
 * a legal state transition and meets the required/optional attributes
 * associated with that transition for that QP type.
 *
 * Note: The OFED kern-abi (See ib_user_verbs.h) does not provide any
 * mechanism to support queue resize, consequently the IBTA spec defined
 * valid optional parameter to modify QP size (IB_QP_CAP) is not included
 * in the state table.
 */
typedef struct {
	int			valid;
	enum ib_qp_attr_mask	req_param[IB_QPT_RAW_ETY + 1];
	enum ib_qp_attr_mask	opt_param[IB_QPT_RAW_ETY + 1];
} uverbs_qp_state_tbl_t;

static uverbs_qp_state_tbl_t
uverbs_qp_state_table[IB_QPS_ERR + 1][IB_QPS_ERR + 1] = {
	[IB_QPS_RESET] = {
		[IB_QPS_RESET] = { .valid = 1 },
		[IB_QPS_ERR]   = { .valid = 1 },
		[IB_QPS_INIT]  = { .valid = 1,
			.req_param = {
				[IB_QPT_UD] = (IB_QP_PKEY_INDEX |
						IB_QP_PORT | IB_QP_QKEY),
				[IB_QPT_UC] = (IB_QP_PKEY_INDEX | IB_QP_PORT |
						IB_QP_ACCESS_FLAGS),
				[IB_QPT_RC] = (IB_QP_PKEY_INDEX | IB_QP_PORT |
						IB_QP_ACCESS_FLAGS),
				[IB_QPT_SMI] = (IB_QP_PKEY_INDEX | IB_QP_QKEY),
				[IB_QPT_GSI] = (IB_QP_PKEY_INDEX | IB_QP_QKEY),
			}
		},
	},
	[IB_QPS_INIT]  = {
		[IB_QPS_RESET] = { .valid = 1 },
		[IB_QPS_ERR] =   { .valid = 1 },
		[IB_QPS_INIT]  = { .valid = 1,
			.opt_param = {
				[IB_QPT_UD] = (IB_QP_PKEY_INDEX | IB_QP_PORT |
						IB_QP_QKEY),
				[IB_QPT_UC] = (IB_QP_PKEY_INDEX | IB_QP_PORT |
						IB_QP_ACCESS_FLAGS),
				[IB_QPT_RC] = (IB_QP_PKEY_INDEX | IB_QP_PORT |
						IB_QP_ACCESS_FLAGS),
				[IB_QPT_SMI] = (IB_QP_PKEY_INDEX | IB_QP_QKEY),
				[IB_QPT_GSI] = (IB_QP_PKEY_INDEX | IB_QP_QKEY),
			}
		},
		[IB_QPS_RTR] = { .valid = 1,
			.req_param = {
				[IB_QPT_UC] = (IB_QP_AV | IB_QP_PATH_MTU |
						IB_QP_DEST_QPN | IB_QP_RQ_PSN),
				[IB_QPT_RC] = (IB_QP_AV | IB_QP_PATH_MTU |
						IB_QP_DEST_QPN | IB_QP_RQ_PSN |
						IB_QP_MAX_DEST_RD_ATOMIC |
						IB_QP_MIN_RNR_TIMER),
			},
			.opt_param = {
				[IB_QPT_UD] = (IB_QP_PKEY_INDEX | IB_QP_QKEY),
				[IB_QPT_UC] = (IB_QP_ALT_PATH |
						IB_QP_ACCESS_FLAGS |
						IB_QP_PKEY_INDEX),
				[IB_QPT_RC] = (IB_QP_ALT_PATH |
						IB_QP_ACCESS_FLAGS |
						IB_QP_PKEY_INDEX),
				[IB_QPT_SMI] = (IB_QP_PKEY_INDEX | IB_QP_QKEY),
				[IB_QPT_GSI] = (IB_QP_PKEY_INDEX | IB_QP_QKEY),
			}
		}
	},
	[IB_QPS_RTR] = {
		[IB_QPS_RESET] = { .valid = 1 },
		[IB_QPS_ERR] = { .valid = 1 },
		[IB_QPS_RTS] = { .valid = 1,
			.req_param = {
				[IB_QPT_UD] = IB_QP_SQ_PSN,
				[IB_QPT_UC] = IB_QP_SQ_PSN,
				[IB_QPT_RC] = (IB_QP_TIMEOUT |
						IB_QP_RETRY_CNT |
						IB_QP_RNR_RETRY |
						IB_QP_SQ_PSN |
						IB_QP_MAX_QP_RD_ATOMIC),
				[IB_QPT_SMI] = IB_QP_SQ_PSN,
				[IB_QPT_GSI] = IB_QP_SQ_PSN,
			},
			.opt_param = {
				[IB_QPT_UD] = (IB_QP_CUR_STATE | IB_QP_QKEY),
				[IB_QPT_UC] = (IB_QP_CUR_STATE |
						IB_QP_ALT_PATH |
						IB_QP_ACCESS_FLAGS |
						IB_QP_PATH_MIG_STATE),
				[IB_QPT_RC] = (IB_QP_CUR_STATE |
						IB_QP_ALT_PATH |
						IB_QP_ACCESS_FLAGS |
						IB_QP_MIN_RNR_TIMER |
						IB_QP_PATH_MIG_STATE),
				[IB_QPT_SMI] = (IB_QP_CUR_STATE | IB_QP_QKEY),
				[IB_QPT_GSI] = (IB_QP_CUR_STATE | IB_QP_QKEY),
			}
		}
	},
	[IB_QPS_RTS] = {
		[IB_QPS_RESET] = { .valid = 1 },
		[IB_QPS_ERR] = { .valid = 1 },
		[IB_QPS_RTS] = { .valid = 1,
			.opt_param = {
				[IB_QPT_UD] = (IB_QP_CUR_STATE | IB_QP_QKEY),
				[IB_QPT_UC] = (IB_QP_CUR_STATE |
						IB_QP_ACCESS_FLAGS |
						IB_QP_ALT_PATH |
						IB_QP_PATH_MIG_STATE),
				[IB_QPT_RC] = (IB_QP_CUR_STATE |
						IB_QP_ACCESS_FLAGS |
						IB_QP_ALT_PATH |
						IB_QP_PATH_MIG_STATE |
						IB_QP_MIN_RNR_TIMER),
				[IB_QPT_SMI] = (IB_QP_CUR_STATE | IB_QP_QKEY),
				[IB_QPT_GSI] = (IB_QP_CUR_STATE | IB_QP_QKEY),
			}
		},
		[IB_QPS_SQD] = { .valid = 1,
			.opt_param = {
				[IB_QPT_UD] = IB_QP_EN_SQD_ASYNC_NOTIFY,
				[IB_QPT_UC] = IB_QP_EN_SQD_ASYNC_NOTIFY,
				[IB_QPT_RC] = IB_QP_EN_SQD_ASYNC_NOTIFY,
				[IB_QPT_SMI] = IB_QP_EN_SQD_ASYNC_NOTIFY,
				[IB_QPT_GSI] = IB_QP_EN_SQD_ASYNC_NOTIFY
			}
		},
	},
	[IB_QPS_SQD] = {
		[IB_QPS_RESET] = { .valid = 1 },
		[IB_QPS_ERR] =  { .valid = 1 },
		[IB_QPS_RTS] = { .valid = 1,
			.opt_param = {
				[IB_QPT_UD] = (IB_QP_CUR_STATE | IB_QP_QKEY),
				[IB_QPT_UC] = (IB_QP_CUR_STATE |
						IB_QP_ALT_PATH |
						IB_QP_ACCESS_FLAGS |
						IB_QP_PATH_MIG_STATE),
				[IB_QPT_RC] = (IB_QP_CUR_STATE |
						IB_QP_ALT_PATH  |
						IB_QP_ACCESS_FLAGS |
						IB_QP_MIN_RNR_TIMER |
						IB_QP_PATH_MIG_STATE),
				[IB_QPT_SMI] = (IB_QP_CUR_STATE | IB_QP_QKEY),
				[IB_QPT_GSI] = (IB_QP_CUR_STATE | IB_QP_QKEY),
			}
		},
		[IB_QPS_SQD] = { .valid = 1,
			.opt_param = {
				[IB_QPT_UD] = (IB_QP_PKEY_INDEX | IB_QP_QKEY),
				[IB_QPT_UC] = (IB_QP_AV | IB_QP_ALT_PATH |
						IB_QP_ACCESS_FLAGS |
						IB_QP_PKEY_INDEX |
						IB_QP_PATH_MIG_STATE),
				[IB_QPT_RC]  = (IB_QP_PORT | IB_QP_AV |
						IB_QP_TIMEOUT |
						IB_QP_RETRY_CNT |
						IB_QP_RNR_RETRY |
						IB_QP_MAX_QP_RD_ATOMIC |
						IB_QP_MAX_DEST_RD_ATOMIC |
						IB_QP_ALT_PATH |
						IB_QP_ACCESS_FLAGS |
						IB_QP_PKEY_INDEX |
						IB_QP_MIN_RNR_TIMER |
						IB_QP_PATH_MIG_STATE),
				[IB_QPT_SMI] = (IB_QP_PKEY_INDEX | IB_QP_QKEY),
				[IB_QPT_GSI] = (IB_QP_PKEY_INDEX | IB_QP_QKEY),
			}
		}
	},
	[IB_QPS_SQE] = {
		[IB_QPS_RESET] = { .valid = 1 },
		[IB_QPS_ERR] = { .valid = 1 },
		[IB_QPS_RTS] = { .valid = 1,
			.opt_param = {
				[IB_QPT_UD] = (IB_QP_CUR_STATE | IB_QP_QKEY),
				[IB_QPT_UC] = (IB_QP_CUR_STATE |
						IB_QP_ACCESS_FLAGS),
				[IB_QPT_SMI] = (IB_QP_CUR_STATE | IB_QP_QKEY),
				[IB_QPT_GSI] = (IB_QP_CUR_STATE | IB_QP_QKEY),
			}
		}
	},
	[IB_QPS_ERR] = {
		[IB_QPS_RESET] = { .valid = 1 },
		[IB_QPS_ERR] = { .valid = 1 }
	}
};

/*
 * Function:
 *      uverbs_modify_qp_is_ok
 * Input:
 *      cur_state	- The current OFED QP state.
 *	next_state	- The OFED QP state to transition to.
 *	type		- The OFED QP transport type.
 *      mask		- The OFED QP attribute mask for the QP transition.
 * Output:
 *      None
 * Returns:
 *      Returns 1 if the operation is valid; otherwise 0 for invalid
 *	operations.
 * Description:
 *      Indicate whether the desired QP modify operation is a valid operation.
 *	To be valid, the state transition must be legal and the required and
 *	optional parameters must be valid for the transition and QP type.
 */
static int
uverbs_modify_qp_is_ok(enum ib_qp_state cur_state,
    enum ib_qp_state next_state, enum ib_qp_type type,
    enum ib_qp_attr_mask *maskp)
{
	enum ib_qp_attr_mask 	req_param, opt_param;
	uverbs_qp_state_tbl_t	*state_tblp;
	enum ib_qp_attr_mask	mask = *maskp;

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str, "modify_qp_is_ok"
	    "(%x, %x, %x, %x)", cur_state, next_state, type, mask);

	if (cur_state  < 0 || cur_state  > IB_QPS_ERR ||
	    next_state < 0 || next_state > IB_QPS_ERR) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "modify_qp_is_ok: bad state, cur %d, next %d",
		    cur_state, next_state);
		return (0);
	}

	if (mask & IB_QP_CUR_STATE &&
	    cur_state != IB_QPS_RTR && cur_state != IB_QPS_RTS &&
	    cur_state != IB_QPS_SQD && cur_state != IB_QPS_SQE) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "modify_qp_is_ok: cur_state %d is a bad state",
		    cur_state);
		return (0);
	}

	state_tblp = &uverbs_qp_state_table[cur_state][next_state];
	if (!state_tblp->valid) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str, "modify_qp: "
		    "bad transition, cur = %d, next = %d", cur_state,
		    next_state);
		return (0);
	}

	req_param = state_tblp->req_param[type];
	opt_param = state_tblp->opt_param[type];

	if ((mask & req_param) != req_param) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "modify_qp_is_ok: cur %d, next %d, "
		    "missing required parms, spec = 0x%08X, "
		    "req = 0%08X", cur_state, next_state,
		    mask, req_param);
		return (0);
	}

	if (mask & ~(req_param | opt_param | IB_QP_STATE)) {
		SOL_OFS_DPRINTF_L3(sol_uverbs_dbg_str,
		    "modify_qp_is_ok: cur %d, next %d, "
		    "illegal optional parms, parms = 0x%08X, "
		    "illegal = 0x%08X", cur_state, next_state,
		    mask, mask & ~(req_param | opt_param | IB_QP_STATE));
		*maskp = mask & (req_param | opt_param | IB_QP_STATE);
		return (0);
	}

	return (1);
}


/*
 * Function:
 *      sol_uverbs_create_qp
 * Input:
 *      uctxt   - Pointer to the callers user context.
 *      buf     - Pointer to kernel buffer containing the create command.
 *      in_len  - Length in bytes of input command buffer.
 *      out_len - Length in bytes of output response buffer.
 * Output:
 *      The command output buffer is updated with command results.
 * Returns:
 *      DDI_SUCCESS on success, else error code.
 * Description:
 *      User verbs entry point to create a new device QP.
 */
/* ARGSUSED */
int
sol_uverbs_create_qp(uverbs_uctxt_uobj_t *uctxt, char *buf,
    int in_len, int out_len)
{
	struct ib_uverbs_create_qp	cmd;
	struct ib_uverbs_create_qp_resp	resp;
	uverbs_uqp_uobj_t		*uqp;
	ibt_qp_type_t			qp_type;
	ibt_qp_alloc_attr_t		qp_attr;
	ibt_chan_sizes_t		qp_sizes;
	int				rc = 0;
	uverbs_upd_uobj_t		*upd;
	uverbs_ucq_uobj_t		*uscq;
	uverbs_ucq_uobj_t		*urcq;
	uverbs_usrq_uobj_t		*usrq = NULL;

	(void) memcpy(&cmd, buf, sizeof (cmd));
	(void) memset(&resp, 0, sizeof (resp));
	(void) memset(&qp_attr, 0, sizeof (qp_attr));
	(void) memset(&qp_sizes, 0, sizeof (qp_sizes));

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str, "create_qp(): entry");

	switch (cmd.qp_type) {
		case IB_QPT_UC:
			qp_type 		= IBT_UC_RQP;
			break;
		case IB_QPT_UD:
			qp_type 		= IBT_UD_RQP;
			break;
		case IB_QPT_RC:
			qp_type 		= IBT_RC_RQP;
			break;
		default:
			SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
			    "create_qp(): Invalid qp type");
			rc = EINVAL;
			goto err_out;
	}

	qp_attr.qp_alloc_flags = IBT_QP_USER_MAP;

	if (cmd.is_srq) {
		qp_attr.qp_alloc_flags |= IBT_QP_USES_SRQ;
	}

	qp_attr.qp_flags = IBT_WR_SIGNALED;
	if (cmd.sq_sig_all) {
		qp_attr.qp_flags = IBT_ALL_SIGNALED;
	}

	uqp = kmem_zalloc(sizeof (*uqp), KM_NOSLEEP);
	if (uqp == NULL) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "create_qp(): User object allocation failed");
		rc = ENOMEM;
		goto err_out;
	}
	sol_ofs_uobj_init(&uqp->uobj, cmd.user_handle,
	    SOL_UVERBS_UQP_UOBJ_TYPE);
	rw_enter(&uqp->uobj.uo_lock, RW_WRITER);
	llist_head_init(&uqp->mcast_list, NULL);
	llist_head_init(&uqp->async_list, NULL);

	uqp->async_events_reported	= 0;
	uqp->uctxt			= uctxt;
	uqp->disable_qp_mod		= FALSE;

	if (cmd.is_srq) {
		usrq = uverbs_uobj_get_usrq_read(cmd.srq_handle);
		uqp->uqp_rcq_srq_valid |= SOL_UVERBS_UQP_SRQ_VALID;
		uqp->uqp_srq_hdl = cmd.srq_handle;
	}
	upd  = uverbs_uobj_get_upd_read(cmd.pd_handle);
	uqp->uqp_pd_hdl = cmd.pd_handle;
	uscq = uverbs_uobj_get_ucq_read(cmd.send_cq_handle);
	uqp->uqp_scq_hdl = cmd.send_cq_handle;
	uqp->uqp_rcq_hdl = cmd.recv_cq_handle;
	if (cmd.recv_cq_handle != cmd.send_cq_handle) {
		urcq = uverbs_uobj_get_ucq_read(cmd.recv_cq_handle);
		uqp->uqp_rcq_srq_valid |= SOL_UVERBS_UQP_RCQ_VALID;
	} else
		urcq = uscq;

	if (!upd || !uscq || !urcq || (cmd.is_srq && !usrq)) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "create_qp(): Invalid resource handle");
		rc = EINVAL;
		goto err_put;
	}
	uqp->uqp_rcq = urcq;
	uqp->uqp_scq = uscq;
	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "uqp %p, rcq %p. scq %p", uqp, urcq, uscq);

	qp_attr.qp_pd_hdl	= upd->pd;
	if (usrq) {
		qp_attr.qp_srq_hdl = usrq->srq;
	}
	qp_attr.qp_scq_hdl		= uscq->cq;
	qp_attr.qp_rcq_hdl		= urcq->cq;
	qp_attr.qp_sizes.cs_sq		= cmd.max_send_wr;
	qp_attr.qp_sizes.cs_rq		= cmd.max_recv_wr;
	qp_attr.qp_sizes.cs_sq_sgl	= cmd.max_send_sge;
	qp_attr.qp_sizes.cs_rq_sgl	= cmd.max_recv_sge;

	uqp->max_inline_data	= cmd.max_inline_data;
	uqp->ofa_qp_type	= cmd.qp_type;

	/*
	 * NOTE: We allocate the QP and leave it in the RESET state to follow
	 * usage semantics consistent with OFA verbs.
	 */
	rc = ibt_alloc_qp(uctxt->hca->hdl, qp_type, &qp_attr, &qp_sizes,
	    &uqp->qp_num, &uqp->qp);
	if (rc != IBT_SUCCESS) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "create_qp(): Error in ibt_alloc_qp() (rc=%d)", rc);
		rc = sol_uverbs_ibt_to_kernel_status(rc);
		uqp->uobj.uo_uobj_sz = sizeof (uverbs_uqp_uobj_t);
		goto err_put;
	}

	ibt_set_qp_private(uqp->qp, uqp);

	/* Bump up the active_qp_cnt for CQ, SRQ & PD resources it is using */
	upd->active_qp_cnt++;
	uscq->active_qp_cnt++;
	if (cmd.recv_cq_handle != cmd.send_cq_handle)
		urcq->active_qp_cnt++;
	if (usrq)
		usrq->active_qp_cnt++;

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "\treq cs_sq=%d, actual cs_sq=%d",
	    qp_attr.qp_sizes.cs_sq, qp_sizes.cs_sq);
	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "\treq cs_sq_sgl=%d, actual cs_sg_sgl=%d",
	    qp_attr.qp_sizes.cs_sq_sgl, qp_sizes.cs_sq_sgl);
	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "\treq cs_rq=%d, actual cs_rq=%d",
	    qp_attr.qp_sizes.cs_rq, qp_sizes.cs_rq);
	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "\treq cs_rq_sgl=%d, actual cs_rq_sgl=%d",
	    qp_attr.qp_sizes.cs_rq_sgl, qp_sizes.cs_rq_sgl);

	/*
	 * Query underlying hardware for data used in mapping QP work
	 * queues back to user space, we will return this information
	 * in the user verbs command response.
	 */
	rc = ibt_ci_data_out(uctxt->hca->hdl, IBT_CI_NO_FLAGS, IBT_HDL_CHANNEL,
	    (void *)uqp->qp, &resp.drv_out, sizeof (resp.drv_out));
	if (rc != IBT_SUCCESS) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "create_qp(): Error in ibt_ci_data_out() (rc=%d)", rc);
		rc = EFAULT;
		uqp->uobj.uo_uobj_sz = sizeof (uverbs_uqp_uobj_t);
		goto err_qp_destroy;
	}

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "create_qp QP: ibt_ci_data_out:0x%016llx 0x%016llx",
	    resp.drv_out[0], resp.drv_out[1]);
	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "                          :0x%016llx 0x%016llx",
	    resp.drv_out[2], resp.drv_out[3]);
	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "                          :0x%016llx 0x%016llx",
	    resp.drv_out[4], resp.drv_out[5]);

	if (sol_ofs_uobj_add(&uverbs_uqp_uo_tbl, &uqp->uobj) != 0) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "create_qp(): User object add failed (rc=%d)", rc);
		rc = ENOMEM;
		goto err_qp_destroy;
	}

	resp.qp_handle		= uqp->uobj.uo_id;
	resp.qpn		= uqp->qp_num;
	resp.max_send_wr	= qp_sizes.cs_sq;
	resp.max_send_sge	= qp_sizes.cs_sq_sgl;
	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str, "create_qp() : "
	    "resp.qp_handle=0x%08x, resp.qpn=0x%08x", resp.qp_handle, resp.qpn);

	/*
	 * In Solaris the receive work requests and sg entries are cleared
	 * when a SRQ is used since these values are ignored.  To maintain
	 * consistency with OFED we return the requested values as is done
	 * in OFED, but these values will be ignored and SRQ valuves are
	 * used.  MTHCA lib will extract the zeroed out value from the
	 * driver out data.
	 */
	if (usrq) {
		resp.max_recv_wr    = cmd.max_recv_wr;
		resp.max_recv_sge   = cmd.max_recv_sge;
	} else {
		resp.max_recv_wr    = qp_sizes.cs_rq;
		resp.max_recv_sge   = qp_sizes.cs_rq_sgl;
	}
	resp.max_inline_data = cmd.max_inline_data;

#ifdef	_LP64
	rc = copyout((void*)&resp, (void*)cmd.response.r_laddr, sizeof (resp));
#else
	rc = copyout((void*)&resp, (void*)cmd.response.r_addr, sizeof (resp));
#endif
	if (rc != 0) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "create_qp(): Error writing resp data (rc=%d)", rc);
		rc = EFAULT;
		goto err_uo_delete;
	}

	mutex_enter(&uctxt->lock);
	uqp->list_entry = add_genlist(&uctxt->qp_list, (uintptr_t)uqp,
	    (void*)uctxt);
	mutex_exit(&uctxt->lock);

	if (!uqp->list_entry) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "create_qp(): Error adding uqp to qp_list\n");
		rc = ENOMEM;
		goto err_uo_delete;
	}
	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "create_qp() - uqp %p", uqp);

	uqp->uobj.uo_live = 1;

	sol_ofs_uobj_put(&upd->uobj);
	sol_ofs_uobj_put(&uscq->uobj);

	if (urcq != uscq) {
		sol_ofs_uobj_put(&urcq->uobj);
	}
	if (usrq) {
		sol_ofs_uobj_put(&usrq->uobj);
	}
	rw_exit(&uqp->uobj.uo_lock);

	return (DDI_SUCCESS);

err_uo_delete:
	/*
	 * Need to set uo_live, so sol_ofs_uobj_remove() will
	 * remove the object from the object table.
	 */
	uqp->uobj.uo_live = 1;
	(void) sol_ofs_uobj_remove(&uverbs_uqp_uo_tbl, &uqp->uobj);

err_qp_destroy:
	(void) ibt_free_qp(uqp->qp);

	upd->active_qp_cnt--;
	uscq->active_qp_cnt--;
	if (cmd.recv_cq_handle != cmd.send_cq_handle)
		urcq->active_qp_cnt--;
	if (usrq)
		usrq->active_qp_cnt--;

err_put:
	if (upd) {
		sol_ofs_uobj_put(&upd->uobj);
	}
	if (uscq) {
		sol_ofs_uobj_put(&uscq->uobj);
	}
	if (urcq && urcq != uscq) {
		sol_ofs_uobj_put(&urcq->uobj);
	}
	if (usrq) {
		sol_ofs_uobj_put(&usrq->uobj);
	}

	rw_exit(&uqp->uobj.uo_lock);
	sol_ofs_uobj_deref(&uqp->uobj, sol_ofs_uobj_free);

err_out:
	return (rc);
}

/*
 * Free the resources used by uqp. Return 0, if the free of all
 * resources where succesful, return non-zero, if not.
 *
 * If other uQPs are holding the resources (PD, CQ, SRQ), do not
 * free the resource, but return 0, so the free of uqp can be
 * done. Return failure only if active_cnt cannot be decremented
 * resource_free() fails.
 */
static int
uverbs_uqp_rsrc_free(uverbs_uqp_uobj_t *uqp, uverbs_uctxt_uobj_t *uctxt)
{
	uverbs_ucq_uobj_t	*uscq = NULL, *urcq = NULL;
	uverbs_usrq_uobj_t	*usrq = NULL;
	uverbs_upd_uobj_t	*upd = NULL;
	int			ret, rc = -1;

	/* Get uobj for PD, CQ & SRQ resources used. */
	upd = uverbs_uobj_get_upd_write(uqp->uqp_pd_hdl);
	if (upd == NULL) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "uqp_rsrc_free: get_upd %d failed", uqp->uqp_pd_hdl);
		goto err_free;
	}
	uscq = uverbs_uobj_get_ucq_write(uqp->uqp_scq_hdl);
	if (uscq == NULL) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "uqp_rsrc_free: get_ucq %x failed", uqp->uqp_scq_hdl);
		goto err_free;
	}
	if (uqp->uqp_rcq_srq_valid & SOL_UVERBS_UQP_RCQ_VALID) {
		urcq = uverbs_uobj_get_ucq_write(uqp->uqp_rcq_hdl);
		if (urcq == NULL) {
			SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
			    "uqp_rsrc_free: get_ucq %x failed",
			    uqp->uqp_rcq_hdl);
			goto err_free;
		}
	}
	if (uqp->uqp_rcq_srq_valid & SOL_UVERBS_UQP_SRQ_VALID) {
		usrq = uverbs_uobj_get_usrq_write(uqp->uqp_srq_hdl);
		if (usrq == NULL) {
			SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
			    "uqp_rsrc_free: get_srq %x failed",
			    uqp->uqp_srq_hdl);
			goto err_free;
		}
	}
	rc = 0;

	/* Decrement active_qp_cnt for resources used */
	upd->active_qp_cnt--;
	uscq->active_qp_cnt--;
	if (urcq)
		urcq->active_qp_cnt--;
	if (usrq)
		usrq->active_qp_cnt--;

	/*
	 * Free the resources, if active_qp_cnt is 0 and userland free
	 * already been pending for the resource.
	 */
	if (upd->active_qp_cnt == 0 && upd->free_pending) {
		ret = uverbs_upd_free(upd, uctxt);
		if (ret && rc == 0) {
			SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
			    "uqp_rsrc_free: upd_free failed");
			rc = ret;
		}
	} else if (upd)
		sol_ofs_uobj_put(&upd->uobj);
	if (uscq && uscq->active_qp_cnt == 0 && uscq->free_pending) {
		ret = uverbs_ucq_free(uscq, uctxt);
		if (ret && rc == 0) {
			SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
			    "uqp_rsrc_free: ucq_free failed");
			rc = ret;
		}
	} else if (uscq)
		sol_ofs_uobj_put(&uscq->uobj);
	if (urcq && urcq->active_qp_cnt == 0 && urcq->free_pending) {
		ret = uverbs_ucq_free(urcq, uctxt);
		if (ret && rc == 0) {
			SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
			    "uqp_rsrc_free: ucq_free failed");
			rc = ret;
		}
	} else if (urcq)
		sol_ofs_uobj_put(&urcq->uobj);
	if (usrq && usrq->active_qp_cnt == 0 && usrq->free_pending) {
		ret = uverbs_usrq_free(usrq, uctxt);
		if (ret && rc == 0) {
			SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
			    "uqp_rsrc_free: usrq_free failed");
			rc = ret;
		}
	} else if (usrq)
		sol_ofs_uobj_put(&usrq->uobj);
	return (rc);

err_free:
	if (upd)
		sol_ofs_uobj_put(&upd->uobj);
	if (uscq)
		sol_ofs_uobj_put(&uscq->uobj);
	if (urcq)
		sol_ofs_uobj_put(&urcq->uobj);

	return (rc);
}

/*
 * Free the resources held by the uqp.
 * Call ibt_free_qp() to free the IBTF QP.
 * Free uqp.
 */
int
uverbs_uqp_free(uverbs_uqp_uobj_t *uqp, uverbs_uctxt_uobj_t *uctxt)
{
	int		rc;
	ibt_status_t	status;

	/* Detach  Mcast entries, if any. */
	uverbs_detach_uqp_mcast_entries(uqp);

	if (!uqp->qp)
		goto skip_ibt_free_qp;

	status = ibt_free_qp(uqp->qp);
	if (status != IBT_SUCCESS) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "uqp_free: ibt_free_qp failed %d", status);
		sol_ofs_uobj_put(&uqp->uobj);
		return (status);
	}
	uqp->qp = NULL;

skip_ibt_free_qp :
	rc = uverbs_uqp_rsrc_free(uqp, uctxt);
	if (rc) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "uqp_free: uqp_rcrc_free failed  %d", rc);
		sol_ofs_uobj_put(&uqp->uobj);
		return (rc);
	}

	(void) sol_ofs_uobj_remove(&uverbs_uqp_uo_tbl, &uqp->uobj);
	sol_ofs_uobj_put(&uqp->uobj);

	if (uqp->list_entry) {
		mutex_enter(&uctxt->lock);
		delete_genlist(&uctxt->qp_list, uqp->list_entry);
		uqp->list_entry = NULL;
		mutex_exit(&uctxt->lock);
	}

	sol_ofs_uobj_deref(&uqp->uobj, sol_ofs_uobj_free);

	if (uctxt->uctxt_free_pending && (uctxt->qp_list).count == 0) {
		SOL_OFS_DPRINTF_L3(sol_uverbs_dbg_str,
		    "uqp_free: freeing uctxt %p", uctxt);
		sol_ofs_uobj_deref(&uctxt->uobj, sol_ofs_uobj_free);
	}
	return (0);
}

/*
 * Function:
 *      sol_uverbs_destroy_qp
 * Input:
 *      uctxt   - Pointer to the callers user context.
 *      buf     - Pointer to kernel buffer containing the destroy command.
 *      in_len  - Length in bytes of input command buffer.
 *      out_len - Length in bytes of output response buffer.
 * Output:
 *      The command output buffer is updated with command results.
 * Returns:
 *      DDI_SUCCESS on success, else error code.
 * Description:
 *      User verbs  entry point to destroy a device QP.
 */
/* ARGSUSED */
int
sol_uverbs_destroy_qp(uverbs_uctxt_uobj_t *uctxt, char *buf,
    int in_len, int out_len)
{
	struct ib_uverbs_destroy_qp		cmd;
	struct ib_uverbs_destroy_qp_resp	resp;
	uverbs_uqp_uobj_t			*uqp;
	int					rc;

	(void) memcpy(&cmd, buf, sizeof (cmd));
	(void) memset(&resp, 0, sizeof (resp));

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str, "DESTROY QP: entry "
	    "(qp_handle=%d)", cmd.qp_handle);

	uqp = uverbs_uobj_get_uqp_write(cmd.qp_handle);
	if (uqp == NULL) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "destroy_qp() : List lookup failure");
		rc = EINVAL;
		goto err_out;
	}

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str, "DESTROY QP: qp_handle=%d, "
	    "uqp %p, qp_ptr %p", cmd.qp_handle, uqp, uqp->qp);

	if (!llist_empty(&uqp->mcast_list)) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "destroy_qp() called with attached MC group(s)");
		rc = EBUSY;
		goto err_busy;
	}

	uverbs_release_uqp_uevents(uctxt->async_evfile, uqp);
	resp.events_reported = uqp->async_events_reported;

	/*
	 * If ucma has disabled QP free for this QP, set FREE_PENDING
	 * flag so that the QP can be freed when UCMA enables QP_FREE.
	 * Call ibt_free_qp() is ucma has not disabled QP free.
	 */
	if (uqp->uqp_free_state == SOL_UVERBS2UCMA_DISABLE_QP_FREE) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "destroy_qp() - UCMA disabled");
		uqp->uqp_free_state = SOL_UVERBS2UCMA_FREE_PENDING;
		sol_ofs_uobj_put(&uqp->uobj);
		rc = 0;
		goto report_qp_evts;
	} else {
		SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
		    "destroy_qp() - freeing QP : %p", uqp);
		rc = uverbs_uqp_free(uqp, uctxt);
	}

	if (rc) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "destroy_qp() - ibt_free_qp() fail %d", rc);
		rc = sol_uverbs_ibt_to_kernel_status(rc);
		goto err_out;
	}

report_qp_evts:
#ifdef	_LP64
	rc = copyout((void*)&resp, (void*)cmd.response.r_laddr, sizeof (resp));
#else
	rc = copyout((void*)&resp, (void*)cmd.response.r_addr, sizeof (resp));
#endif
	if (rc != 0) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "destroy_qp() : copyout failure %x", rc);
		rc = EFAULT;
		goto err_out;
	}

	return (DDI_SUCCESS);

err_busy:
	sol_ofs_uobj_put(&uqp->uobj);

err_out:
	return (rc);
}

/*
 * Function:
 *      uverbs_copy_path_info_from_ibv
 * Input:
 *      src_path	- IB OFED path.
 * Output:
 *      dest_path	- IBT path.
 * Returns:
 *      None
 * Description:
 *      Helper to copy from the OFED path format to IBT path format.
 */
static void
uverbs_copy_path_info_from_ibv(struct ib_uverbs_qp_dest *src_path,
    ibt_cep_path_t *dest_path)
{
	ASSERT(src_path != NULL);
	ASSERT(dest_path != NULL);

	(void) memcpy(&dest_path->cep_adds_vect.av_dgid,
	    &src_path->dgid[0], sizeof (src_path->dgid));

	dest_path->cep_adds_vect.av_flow	= src_path->flow_label;
	dest_path->cep_adds_vect.av_dlid	= src_path->dlid;
	dest_path->cep_adds_vect.av_hop		= src_path->hop_limit;
	dest_path->cep_adds_vect.av_tclass	= src_path->traffic_class;
	dest_path->cep_adds_vect.av_srvl	= src_path->sl & 0x0f;
	dest_path->cep_adds_vect.av_port_num	= src_path->port_num;
	dest_path->cep_adds_vect.av_src_path	= src_path->src_path_bits;
	dest_path->cep_adds_vect.av_send_grh	= src_path->is_global;
	dest_path->cep_adds_vect.av_sgid_ix	= src_path->sgid_index;
	dest_path->cep_adds_vect.av_srate 	= src_path->static_rate;
}

/*
 * Function:
 *      uverbs_modify_update
 * Input:
 *      cmd		- The user verbs modify command to be translated.
 *	cur_state	- The current QP state
 *	new_state	- The new QP state
 * Output:
 *      qp_query_attr	- The IBT QP attributes.
 *	flags		- The IBT flags.
 * Returns:
 *      None
 * Description:
 *      Helper to convert OFED user verbs QP modify attributes to IBT
 *	QP modify attributes.  Note that on required parameters, the
 *	individual IBT modify flags are not set (there is a global
 *	flag for the transition), only optional flags are set.
 */
static void
uverbs_modify_update(struct ib_uverbs_modify_qp *cmd,
    enum ib_qp_state cur_state, enum ib_qp_state new_state,
    ibt_qp_query_attr_t *qp_query_attr, ibt_cep_modify_flags_t *flags)
{
	ibt_qp_info_t		*qp_infop;
	ibt_qp_rc_attr_t	*rcp;
	ibt_qp_uc_attr_t	*ucp;
	ibt_qp_ud_attr_t	*udp;

	*flags = IBT_CEP_SET_NOTHING;
	qp_infop = &(qp_query_attr->qp_info);
	rcp = &(qp_infop->qp_transport.rc);
	ucp = &(qp_infop->qp_transport.uc);
	udp = &(qp_infop->qp_transport.ud);

	switch (cur_state) {
	case IB_QPS_RESET:
		qp_infop->qp_current_state = IBT_STATE_RESET;
		break;
	case IB_QPS_INIT:
		qp_infop->qp_current_state = IBT_STATE_INIT;
		break;
	case IB_QPS_RTR:
		qp_infop->qp_current_state = IBT_STATE_RTR;
		break;
	case IB_QPS_RTS:
		qp_infop->qp_current_state = IBT_STATE_RTS;
		break;
	case IB_QPS_SQD:
		qp_infop->qp_current_state = IBT_STATE_SQD;
		break;
	case IB_QPS_SQE:
		qp_infop->qp_current_state = IBT_STATE_SQE;
		break;
	case IB_QPS_ERR:
		qp_infop->qp_current_state = IBT_STATE_ERROR;
		break;
	}

	if (cmd->attr_mask & IB_QP_STATE) {
		switch (new_state) {
		case IB_QPS_RESET:
			qp_infop->qp_state = IBT_STATE_RESET;
			*flags |= IBT_CEP_SET_STATE;
			break;

		case IB_QPS_INIT:
			qp_infop->qp_state = IBT_STATE_INIT;
			if (cur_state == IB_QPS_RESET) {
				*flags |= IBT_CEP_SET_RESET_INIT;
			} else {
				*flags |= IBT_CEP_SET_STATE;
			}
			break;

		case IB_QPS_RTR:
			qp_infop->qp_state = IBT_STATE_RTR;
			if (cur_state == IB_QPS_INIT) {
				*flags |= IBT_CEP_SET_INIT_RTR;
			} else {
				*flags |= IBT_CEP_SET_STATE;
			}
			break;

		case IB_QPS_RTS:
			qp_infop->qp_state = IBT_STATE_RTS;

			/*
			 * For RTS transitions other than RTR we must
			 * specify the assumption for the qp state.
			 */
			if (cur_state == IB_QPS_RTR) {
				*flags |= IBT_CEP_SET_RTR_RTS;
			} else {
				ibt_cep_state_t *ibt_curr =
				    &qp_infop->qp_current_state;

				switch (cur_state) {
				case IB_QPS_RTS:
					*ibt_curr = IBT_STATE_RTS;
					break;

				case IB_QPS_SQD:
					*ibt_curr = IBT_STATE_SQD;
					break;

				case IB_QPS_SQE:
					*ibt_curr = IBT_STATE_SQE;
					break;
				}
				*flags |= IBT_CEP_SET_STATE;
			}
			break;

		case IB_QPS_SQD:
			qp_infop->qp_state = IBT_STATE_SQD;
			*flags |= IBT_CEP_SET_STATE;
			break;

		case IB_QPS_SQE:
			qp_infop->qp_state = IBT_STATE_SQE;
			*flags |= IBT_CEP_SET_STATE;
			break;

		case IB_QPS_ERR:
			qp_infop->qp_state = IBT_STATE_ERROR;
			*flags |= IBT_CEP_SET_STATE;
			break;
		}
	}

	if (cmd->attr_mask & IB_QP_PKEY_INDEX) {
		if (qp_infop->qp_trans == IBT_UD_SRV) {
			udp->ud_pkey_ix = cmd->pkey_index;
		} else if (qp_infop->qp_trans == IBT_RC_SRV) {
			rcp->rc_path.cep_pkey_ix = cmd->pkey_index;
		}
		*flags |= IBT_CEP_SET_PKEY_IX;
	}


	if (cmd->attr_mask & IB_QP_AV) {
		if (qp_infop->qp_trans == IBT_RC_SRV) {
			uverbs_copy_path_info_from_ibv(&cmd->dest,
			    &rcp->rc_path);
		}
		*flags |= IBT_CEP_SET_ADDS_VECT;
	}

	if (qp_infop->qp_trans == IBT_RC_SRV) {
		if (cmd->attr_mask & IB_QP_TIMEOUT) {
			rcp->rc_path.cep_timeout = cmd->timeout;
			*flags |= IBT_CEP_SET_TIMEOUT;
		}
	}

	if (cmd->attr_mask & IB_QP_PORT) {
		if (qp_infop->qp_trans == IBT_UD_SRV) {
			udp->ud_port = cmd->port_num;
		} else if (qp_infop->qp_trans == IBT_RC_SRV) {
			rcp->rc_path.cep_hca_port_num = cmd->port_num;
		}
		*flags |= IBT_CEP_SET_PORT;
	}

	if (cmd->attr_mask & IB_QP_QKEY) {
		if (qp_infop->qp_trans == IBT_UD_SRV) {
			udp->ud_qkey = cmd->qkey;
		}
		if (qp_infop->qp_trans == IBT_RD_SRV) {
			qp_infop->qp_transport.rd.rd_qkey = cmd->qkey;
		}
		*flags |= IBT_CEP_SET_QKEY;
	}

	if (cmd->attr_mask & IB_QP_PATH_MTU) {
		if (qp_infop->qp_trans == IBT_UC_SRV) {
			ucp->uc_path_mtu = cmd->path_mtu;
		}
		if (qp_infop->qp_trans == IBT_RC_SRV) {
			rcp->rc_path_mtu = cmd->path_mtu;
		}
	}

	if (cmd->attr_mask & IB_QP_RETRY_CNT) {
		if (qp_infop->qp_trans == IBT_RC_SRV) {
			rcp->rc_retry_cnt = cmd->retry_cnt & 0x7;
		}
		*flags |= IBT_CEP_SET_RETRY;
	}

	if (cmd->attr_mask & IB_QP_RNR_RETRY) {
		if (qp_infop->qp_trans == IBT_RC_SRV) {
			rcp->rc_rnr_retry_cnt = cmd->rnr_retry;
		}
		*flags |= IBT_CEP_SET_RNR_NAK_RETRY;
	}

	if (cmd->attr_mask & IB_QP_MIN_RNR_TIMER) {
		if (qp_infop->qp_trans == IBT_RC_SRV) {
			rcp->rc_min_rnr_nak = cmd->min_rnr_timer;
		}
		*flags |= IBT_CEP_SET_MIN_RNR_NAK;
	}

	if (cmd->attr_mask & IB_QP_RQ_PSN) {
		if (qp_infop->qp_trans == IBT_RC_SRV) {
			rcp->rc_rq_psn = cmd->rq_psn;
		}
		if (qp_infop->qp_trans == IBT_UC_SRV) {
			ucp->uc_rq_psn = cmd->rq_psn;
		}
	}

	if (cmd->attr_mask & IB_QP_ALT_PATH) {
		if (qp_infop->qp_trans == IBT_RC_SRV) {
			uverbs_copy_path_info_from_ibv(&cmd->alt_dest,
			    &rcp->rc_alt_path);

			rcp->rc_alt_path.cep_hca_port_num = cmd->alt_port_num;
			rcp->rc_alt_path.cep_timeout = cmd->alt_timeout;
		}

		if (qp_infop->qp_trans == IBT_UC_SRV) {
			uverbs_copy_path_info_from_ibv(&cmd->alt_dest,
			    &ucp->uc_alt_path);

			ucp->uc_alt_path.cep_hca_port_num = cmd->alt_port_num;
			ucp->uc_alt_path.cep_timeout = cmd->alt_timeout;
		}

		*flags |= IBT_CEP_SET_ALT_PATH;
	}


	if (cmd->attr_mask & IB_QP_SQ_PSN) {
		if (qp_infop->qp_trans == IBT_UD_SRV) {
			udp->ud_sq_psn = cmd->sq_psn;
		}
		if (qp_infop->qp_trans == IBT_UC_SRV) {
			ucp->uc_sq_psn = cmd->sq_psn;
		}
		if (qp_infop->qp_trans == IBT_RC_SRV) {
			rcp->rc_sq_psn = cmd->sq_psn;
		}
	}

	if (cmd->attr_mask & IB_QP_MAX_QP_RD_ATOMIC) {
		if (qp_infop->qp_trans == IBT_RC_SRV) {
			rcp->rc_rdma_ra_out = cmd->max_rd_atomic;
		}
		*flags |= IBT_CEP_SET_RDMARA_OUT | IBT_CEP_SET_STATE;
	}

	if (cmd->attr_mask & IB_QP_MAX_DEST_RD_ATOMIC) {
		if (qp_infop->qp_trans == IBT_RC_SRV) {
			rcp->rc_rdma_ra_in = cmd->max_dest_rd_atomic;
		}
		*flags |= IBT_CEP_SET_RDMARA_IN | IBT_CEP_SET_STATE;
	}

	if (cmd->attr_mask & (IB_QP_ACCESS_FLAGS |
	    IB_QP_MAX_DEST_RD_ATOMIC)) {
		if (qp_infop->qp_trans == IBT_RC_SRV) {
			uint32_t	access_flags = IBT_CEP_NO_FLAGS;

			if (rcp->rc_rdma_ra_in) {
				access_flags	|= IBT_CEP_RDMA_WR;
				*flags		|= IBT_CEP_SET_RDMA_W;
			}

			if (cmd->attr_mask & IB_QP_ACCESS_FLAGS) {
				if (cmd->qp_access_flags &
				    IB_ACCESS_REMOTE_WRITE) {
					access_flags	|= IBT_CEP_RDMA_WR;
					*flags		|= IBT_CEP_SET_RDMA_W;
				}
				if (cmd->qp_access_flags &
				    IB_ACCESS_REMOTE_READ) {
					access_flags	|= IBT_CEP_RDMA_RD;
					*flags		|= IBT_CEP_SET_RDMA_R;
				}
				if (cmd->qp_access_flags &
				    IB_ACCESS_REMOTE_ATOMIC) {
					access_flags	|= IBT_CEP_ATOMIC;
					*flags		|= IBT_CEP_SET_ATOMIC;
				}
			}
			qp_infop->qp_flags &= ~(IBT_CEP_RDMA_WR |
			    IBT_CEP_RDMA_RD | IBT_CEP_ATOMIC);
			qp_infop->qp_flags |= access_flags;
		}
	}

	if (cmd->attr_mask & IB_QP_PATH_MIG_STATE) {
		if (qp_infop->qp_trans == IBT_RC_SRV) {
			if (cmd->path_mig_state == IB_MIG_MIGRATED) {
				rcp->rc_mig_state = IBT_STATE_MIGRATED;
			}
			if (cmd->path_mig_state == IB_MIG_REARM) {
				rcp->rc_mig_state = IBT_STATE_REARMED;
			}
			if (cmd->path_mig_state == IB_MIG_ARMED) {
				rcp->rc_mig_state = IBT_STATE_ARMED;
			}
		}

		if (qp_infop->qp_trans == IBT_UC_SRV) {
			if (cmd->path_mig_state == IB_MIG_MIGRATED) {
				ucp->uc_mig_state = IBT_STATE_MIGRATED;
			}
			if (cmd->path_mig_state == IB_MIG_REARM) {
				ucp->uc_mig_state = IBT_STATE_REARMED;
			}
			if (cmd->path_mig_state == IB_MIG_ARMED) {
				ucp->uc_mig_state = IBT_STATE_ARMED;
			}
		}
		*flags |= IBT_CEP_SET_MIG;
	}

	if (cmd->attr_mask & IB_QP_DEST_QPN) {
		if (qp_infop->qp_trans == IBT_RC_SRV) {
			rcp->rc_dst_qpn = cmd->dest_qp_num;
		}
		if (qp_infop->qp_trans == IBT_UC_SRV) {
			ucp->uc_dst_qpn = cmd->dest_qp_num;
		}
	}
}


static void
uverbs_qp_print_path(ibt_cep_path_t *pathp)
{
	SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str, "qp_print_pathp %p", pathp);
	SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str, "cep_pkey_ix %x, "
	    "cep_hca_port_num %x", pathp->cep_pkey_ix, pathp->cep_hca_port_num);
}

static void
uverbs_print_query_qp(ibt_qp_hdl_t qp_hdlp)
{
	ibt_qp_query_attr_t	qp_query_attr;
	ibt_qp_info_t		*qp_infop = &qp_query_attr.qp_info;
	ibt_qp_rc_attr_t	*rcp = &((qp_infop->qp_transport).rc);
	ibt_status_t		rc;

	bzero(&qp_query_attr, sizeof (qp_query_attr));
	rc =  ibt_query_qp(qp_hdlp, &qp_query_attr);
	if (rc != IBT_SUCCESS) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str, "print_query_qp -"
		    "ibt_query_qp() failed - rc=%d", rc);
		return;
	}
	SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str, "qp_print %p", qp_hdlp);

	SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str, "qp_sq_cq %p, qp_rq_cq %p, "
	    "qp_qpn %x, qp_sq_sgl %x, qp_rq_sgl %x, qp_srq %p, qp_flags %x",
	    qp_query_attr.qp_sq_cq, qp_query_attr.qp_rq_cq,
	    qp_query_attr.qp_qpn, qp_query_attr.qp_sq_sgl,
	    qp_query_attr.qp_rq_sgl, qp_query_attr.qp_srq,
	    qp_query_attr.qp_flags);

	SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str, "qp_sq_sz %x, qp_rq_sz %x, "
	    "qp_state %x, qp_current_state %x, qp_flags %x, qp_trans %x",
	    qp_infop->qp_sq_sz, qp_infop->qp_rq_sz, qp_infop->qp_state,
	    qp_infop->qp_current_state,  qp_infop->qp_flags,
	    qp_infop->qp_trans);

	if (qp_infop->qp_trans == IBT_RC_SRV) {
	SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str, "rc_sq_psn %x, rc_rq_psn %x, "
	    "rc_dst_qpn %x, rc_mig_state %x, rc_rnr_retry_cnt %x,"
	    "rc_retry_cnt %x rc_rdma_ra_out %x, rc_rdma_ra_in %x,"
	    "rc_min_rnr_nak %x, rc_path_mtu %x",
	    rcp->rc_sq_psn, rcp->rc_rq_psn, rcp->rc_dst_qpn, rcp->rc_mig_state,
	    rcp->rc_rnr_retry_cnt, rcp->rc_retry_cnt, rcp->rc_rdma_ra_out,
	    rcp->rc_rdma_ra_in, rcp->rc_min_rnr_nak, rcp->rc_path_mtu);
	uverbs_qp_print_path(&rcp->rc_path);
	uverbs_qp_print_path(&rcp->rc_alt_path);
	}
}


/*
 * Function:
 *      sol_uverbs_modify_qp
 * Input:
 *      uctxt   - Pointer to the callers user context.
 *      buf     - Pointer to kernel buffer containing QP modify command.
 *      in_len  - Length in bytes of input command buffer.
 *      out_len - Length in bytes of output response buffer.
 * Output:
 *      The command output buffer is updated with command results.
 * Returns:
 *      DDI_SUCCESS on success, else error code.
 * Description:
 *      User verbs entry point to modify a device QP.
 */
/* ARGSUSED */
int
sol_uverbs_modify_qp(uverbs_uctxt_uobj_t *uctxt, char *buf,
    int in_len, int out_len)
{
	struct ib_uverbs_modify_qp	cmd;
	uverbs_uqp_uobj_t		*uqp;
	ibt_qp_query_attr_t		qp_query_attr;
	ibt_cep_modify_flags_t		flags;
	ibt_queue_sizes_t		size;
	int				rc;
	enum ib_qp_state		cur_state, new_state;

	(void) memcpy(&cmd, buf, sizeof (cmd));

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str, "modify_qp - qp_hdl %d, "
	    "attr_mask %x", cmd.qp_handle, cmd.attr_mask);

	uqp = uverbs_uobj_get_uqp_write(cmd.qp_handle);
	if (uqp == NULL) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str, "modify_qp -"
		    "List lookup failure");
		rc = EINVAL;
		goto err_out;
	}

	/*
	 * Has the UCMA asked us to ignore QP modify operations?
	 * This is required because of differences in the level of
	 * abstraction fo CM processing between IBT and OFED.
	 */
	if (uqp->disable_qp_mod == TRUE) {
		SOL_OFS_DPRINTF_L3(sol_uverbs_dbg_str, "modify_qp -"
		    "qp_mod disabled");
		goto done;
	}

	/*
	 * Load the current QP attributes and then do a validation
	 * based on OFA verbs expectations to see if the modify
	 * should be performed.
	 */
	bzero(&qp_query_attr, sizeof (qp_query_attr));
	rc =  ibt_query_qp(uqp->qp, &qp_query_attr);
	if (rc != IBT_SUCCESS) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str, "modify_qp -"
		    "ibt_query_qp() failed - rc=%d", rc);
		rc = sol_uverbs_ibt_to_kernel_status(rc);
		goto err_deref;
	}

	if (cmd.attr_mask & IB_QP_CUR_STATE) {
		cur_state = cmd.cur_qp_state;
	} else {
		cur_state = IBT_TO_OFA_QP_STATE(qp_query_attr.qp_info.qp_state);
	}

	new_state = cmd.attr_mask & IB_QP_STATE ? cmd.qp_state : cur_state;

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str, "modify_qp: ibt qp %p, handle "
	    "%x, cur_state %x, new_state %x, qp_type %x, attr_mask %x", uqp->qp,
	    cmd.qp_handle, cur_state, new_state, uqp->ofa_qp_type,
	    cmd.attr_mask);

	if (!uverbs_modify_qp_is_ok(cur_state, new_state, uqp->ofa_qp_type,
	    (enum ib_qp_attr_mask *)&cmd.attr_mask)) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str, "modify_qp() -"
		    "Failed modify OK test");
		rc = EINVAL;
		goto err_deref;
	}

	if (!cmd.attr_mask) {
		SOL_OFS_DPRINTF_L3(sol_uverbs_dbg_str, "modify_qp() -"
		    "attr_mask after modify OK test is 0");
		rc = 0;
		goto done;
	}

	flags = 0;

	switch (uqp->ofa_qp_type) {
		case IB_QPT_UC:
			qp_query_attr.qp_info.qp_trans = IBT_UC_SRV;
			break;
		case IB_QPT_UD:
			qp_query_attr.qp_info.qp_trans = IBT_UD_SRV;
			break;
		case IB_QPT_RC:
			qp_query_attr.qp_info.qp_trans = IBT_RC_SRV;
			break;
		default:
			SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
			    "modify_qp: Invalid QP type");
			rc = EINVAL;
			goto err_deref;
	}

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str, "modify_qp(): qp_info.qp_flags "
	    "before modify update = 0%08x", qp_query_attr.qp_info.qp_flags);

	uverbs_modify_update(&cmd, cur_state, new_state, &qp_query_attr,
	    &flags);

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str, "modify_qp(): after "
	    "modify_update hdl flags = 0x%08x, qp_info.qp_flags = 0%08x",
	    flags, qp_query_attr.qp_info.qp_flags);

	rc = ibt_modify_qp(uqp->qp, flags, &qp_query_attr.qp_info, &size);

	if (rc != IBT_SUCCESS) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "modify_qp: Error in ibt_modify_qp() (rc=%d)", rc);
		uverbs_print_query_qp(uqp->qp);
		rc = sol_uverbs_ibt_to_kernel_status(rc);
		goto err_deref;
	}

done:
	sol_ofs_uobj_put(&uqp->uobj);
	return (DDI_SUCCESS);

err_deref:
	sol_ofs_uobj_put(&uqp->uobj);

err_out:
	return (rc);
}

/*
 * Function:
 *      uverbs_copy_path_info_from_ibt
 * Input:
 *      src_path	- The IBT path.
 * Output:
 *      dest_path	- The OFED user verbs path.
 * Returns:
 *      None
 * Description:
 *      Helper to convert IBT path to OFED  user verbs path.
 */
static void
uverbs_copy_path_info_from_ibt(ibt_cep_path_t *src_path,
    struct ib_uverbs_qp_dest *dest_path)
{
	ASSERT(src_path != NULL);
	ASSERT(dest_path != NULL);

	(void) memcpy(&dest_path->dgid[0],
	    &src_path->cep_adds_vect.av_dgid, sizeof (dest_path->dgid));

	dest_path->flow_label = src_path->cep_adds_vect.av_flow;
	dest_path->dlid = src_path->cep_adds_vect.av_dlid;
	dest_path->hop_limit = src_path->cep_adds_vect.av_hop;
	dest_path->traffic_class = src_path->cep_adds_vect.av_tclass;
	dest_path->sl = src_path->cep_adds_vect.av_srvl;
	dest_path->port_num = src_path->cep_adds_vect.av_port_num;
	dest_path->src_path_bits = src_path->cep_adds_vect.av_src_path;
	dest_path->is_global = src_path->cep_adds_vect.av_send_grh;
	dest_path->sgid_index = src_path->cep_adds_vect.av_sgid_ix;
	dest_path->static_rate =  src_path->cep_adds_vect.av_srate;
}

/*
 * Function:
 *      uverbs_query_copy_rc
 * Input:
 *      src	- The IBT RC QP attributes.
 * Output:
 *      dest	- The OFED user verbs QP attributes.
 * Returns:
 *      None
 * Description:
 *      Helper to copy IBT RC QP attributes to OFED QP attributes.
 */
static void
uverbs_query_copy_rc(struct ib_uverbs_query_qp_resp *dest,
    ibt_qp_rc_attr_t *src)
{
	dest->sq_psn = src->rc_sq_psn;
	dest->rq_psn = src->rc_rq_psn;
	dest->dest_qp_num = src->rc_dst_qpn;
	dest->rnr_retry = src->rc_rnr_retry_cnt;
	dest->retry_cnt = src->rc_retry_cnt;
	dest->max_dest_rd_atomic = src->rc_rdma_ra_in;
	dest->max_rd_atomic = src->rc_rdma_ra_out;
	dest->min_rnr_timer = src->rc_min_rnr_nak;
	dest->path_mtu = src->rc_path_mtu;
	dest->timeout = src->rc_path.cep_timeout;
	dest->alt_timeout = src->rc_alt_path.cep_timeout;
	dest->port_num = src->rc_path.cep_hca_port_num;
	dest->alt_port_num = src->rc_alt_path.cep_hca_port_num;

	if (src->rc_mig_state == IBT_STATE_MIGRATED) {
		dest->path_mig_state = IB_MIG_MIGRATED;
	}
	if (src->rc_mig_state == IBT_STATE_REARMED) {
		dest->path_mig_state = IB_MIG_REARM;
	}
	if (src->rc_mig_state == IBT_STATE_ARMED) {
		dest->path_mig_state = IB_MIG_ARMED;
	}

	uverbs_copy_path_info_from_ibt(&src->rc_path, &dest->dest);
	uverbs_copy_path_info_from_ibt(&src->rc_alt_path, &dest->alt_dest);
}

/*
 * Function:
 *      uverbs_query_copy_uc
 * Input:
 *      src	- The IBT UC QP attributes.
 * Output:
 *      dest	- The OFED user verbs QP attributes.
 * Returns:
 *      None
 * Description:
 *      Helper to copy IBT UC QP attributes to OFED user verbs
 *	QP attributes.
 */
static void
uverbs_query_copy_uc(struct ib_uverbs_query_qp_resp *dest,
    ibt_qp_uc_attr_t *src)
{
	dest->sq_psn	  = src->uc_sq_psn;
	dest->rq_psn	  = src->uc_rq_psn;
	dest->dest_qp_num = src->uc_dst_qpn;
	dest->path_mtu	  = src->uc_path_mtu;

	if (src->uc_mig_state == IBT_STATE_MIGRATED) {
		dest->path_mig_state = IB_MIG_MIGRATED;
	}
	if (src->uc_mig_state == IBT_STATE_REARMED) {
		dest->path_mig_state = IB_MIG_REARM;
	}
	if (src->uc_mig_state == IBT_STATE_ARMED) {
		dest->path_mig_state = IB_MIG_ARMED;
	}

	uverbs_copy_path_info_from_ibt(&src->uc_path, &dest->dest);
	uverbs_copy_path_info_from_ibt(&src->uc_alt_path, &dest->alt_dest);
}

/*
 * Function:
 *      uverbs_query_copy_rd
 * Input:
 *      src	- The IBT RD QP attributes.
 * Output:
 *      dest	- The OFED user verbs QP attributes.
 * Returns:
 *      None
 * Description:
 *      Helper to copy IBT RD QP attributes to OFED user verb QP attributes.
 */
static void
uverbs_query_copy_rd(struct ib_uverbs_query_qp_resp *dest,
    ibt_qp_rd_attr_t *src)
{
	dest->qkey	    = src->rd_qkey;
	dest->min_rnr_timer = src->rd_min_rnr_nak;
}

/*
 * Function:
 *      uverbs_query_copy_ud
 * Input:
 *      src	- The IBT UD QP attributes.
 * Output:
 *      dest	- The OFED user verbs QP attributes.
 * Returns:
 *      None
 * Description:
 *      Helper to copy IBT UD QP attributes to OFED user verbs QP attributes.
 */
static void
uverbs_query_copy_ud(struct ib_uverbs_query_qp_resp *dest,
    ibt_qp_ud_attr_t *src)
{
	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "query_copy_ud:entry - return UD info: qkey:%08X, "
	    "psn:%d, pkey_idx:%d, port:%d", src->ud_qkey, src->ud_sq_psn,
	    src->ud_pkey_ix, src->ud_port);

	dest->qkey	 = src->ud_qkey;
	dest->sq_psn	 = src->ud_sq_psn;
	dest->pkey_index = src->ud_pkey_ix;
	dest->port_num	 = src->ud_port;
}

/*
 * Function:
 *      uverbs_query_copy_info
 * Input:
 *      src	- The IBT QP information.
 * Output:
 *      dest	- The OFED user verbs QP attributes.
 * Returns:
 *      None
 * Description:
 *      Helper to copy IBT QP info to OFED user verbs QP attributes.
 */
static void
uverbs_query_copy_info(struct ib_uverbs_query_qp_resp *dest,
    ibt_qp_info_t *src)
{

	dest->max_send_wr = src->qp_sq_sz;
	dest->max_recv_wr = src->qp_rq_sz;
	dest->qp_access_flags = ibt_cep_flags2ibv(src->qp_flags);

	switch (src->qp_state) {
		case IBT_STATE_RESET:
			dest->qp_state = IB_QPS_RESET;
			break;
		case IBT_STATE_INIT:
			dest->qp_state = IB_QPS_INIT;
			break;
		case IBT_STATE_RTR:
			dest->qp_state = IB_QPS_RTR;
			break;
		case IBT_STATE_RTS:
			dest->qp_state = IB_QPS_RTS;
			break;
		case IBT_STATE_SQD:
			dest->qp_state = IB_QPS_SQD;
			break;
		case IBT_STATE_SQE:
			dest->qp_state = IB_QPS_SQE;
			break;
		case IBT_STATE_ERROR:
		default:
			dest->qp_state = IB_QPS_ERR;
			break;
	}

	switch (src->qp_current_state) {
		case IBT_STATE_RESET:
			dest->cur_qp_state = IB_QPS_RESET;
			break;
		case IBT_STATE_INIT:
			dest->cur_qp_state = IB_QPS_INIT;
			break;
		case IBT_STATE_RTR:
			dest->cur_qp_state = IB_QPS_RTR;
			break;
		case IBT_STATE_RTS:
			dest->cur_qp_state = IB_QPS_RTS;
			break;
		case IBT_STATE_SQD:
			dest->cur_qp_state = IB_QPS_SQD;
			break;
		case IBT_STATE_SQE:
			dest->cur_qp_state = IB_QPS_SQE;
			break;
		case IBT_STATE_ERROR:
		default:
			dest->cur_qp_state = IB_QPS_ERR;
			break;
	}

	if ((src->qp_flags & IBT_ALL_SIGNALED) == IBT_ALL_SIGNALED) {
		dest->sq_sig_all = 1;
	}
}

/*
 * Function:
 *      uverbs_query_copy_attr
 * Input:
 *      src	- The IBT QP information.
 * Output:
 *      dest	- The OFED user verbs QP attributes.
 * Returns:
 *      None
 * Description:
 *      Helper to copy IBT QP attributes to OFED user verbs QP attributes.
 */
static void
uverbs_query_copy_attr(struct ib_uverbs_query_qp_resp *dest,
    ibt_qp_query_attr_t *src)
{
	dest->max_send_sge = src->qp_sq_sgl;
	dest->max_recv_sge = src->qp_rq_sgl;
}

/*
 * Function:
 *      sol_uverbs_query_qp
 * Input:
 *      uctxt   - Pointer to the callers user context.
 *      buf     - Pointer to kernel buffer containing query QP command.
 *      in_len  - Length in bytes of input command buffer.
 *      out_len - Length in bytes of output response buffer.
 * Output:
 *      The command output buffer is updated with command results.
 * Returns:
 *      DDI_SUCCESS on success, else error code.
 * Description:
 *      User verbs entry point to query a device QP properties.
 */
/* ARGSUSED */
int
sol_uverbs_query_qp(uverbs_uctxt_uobj_t *uctxt, char *buf,
    int in_len, int out_len)
{
	struct ib_uverbs_query_qp	cmd;
	struct ib_uverbs_query_qp_resp	resp;
	uverbs_uqp_uobj_t		*uqp;
	ibt_qp_query_attr_t		qp_query_attr;
	int				rc;

	(void) memset(&resp, 0, sizeof (resp));
	(void) memcpy(&cmd, buf, sizeof (cmd));

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "query_qp: entry (qp_handle=%d)", cmd.qp_handle);

	uqp = uverbs_uobj_get_uqp_read(cmd.qp_handle);
	if (uqp == NULL) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "query_qp(): List lookup failure");
		rc = EINVAL;
		goto err_out;
	}

	bzero(&qp_query_attr, sizeof (qp_query_attr));
	rc =  ibt_query_qp(uqp->qp, &qp_query_attr);
	sol_ofs_uobj_put(&uqp->uobj);

	if (rc != IBT_SUCCESS) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "query_qp: Error in ibt_query_qp() (rc=%d)", rc);
		rc = sol_uverbs_ibt_to_kernel_status(rc);
		goto err_out;
	}

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "query_qp(): qp_query_attr.qp_info.qp_trans = %d",
	    qp_query_attr.qp_info.qp_trans);

	uverbs_query_copy_attr(&resp, &qp_query_attr);
	uverbs_query_copy_info(&resp, &qp_query_attr.qp_info);

	if (qp_query_attr.qp_info.qp_trans == IBT_RC_SRV) {
		uverbs_query_copy_rc(&resp,
		    &qp_query_attr.qp_info.qp_transport.rc);
	}

	if (qp_query_attr.qp_info.qp_trans == IBT_UC_SRV) {
		uverbs_query_copy_uc(&resp,
		    &qp_query_attr.qp_info.qp_transport.uc);
	}

	if (qp_query_attr.qp_info.qp_trans == IBT_RD_SRV) {
		uverbs_query_copy_rd(&resp,
		    &qp_query_attr.qp_info.qp_transport.rd);
	}


	if (qp_query_attr.qp_info.qp_trans == IBT_UD_SRV) {
		uverbs_query_copy_ud(&resp,
		    &qp_query_attr.qp_info.qp_transport.ud);
	}

	resp.max_inline_data = uqp->max_inline_data;

#ifdef	_LP64
	rc = copyout((void*)&resp, (void*)cmd.response.r_laddr, sizeof (resp));
#else
	rc = copyout((void*)&resp, (void*)cmd.response.r_addr, sizeof (resp));
#endif
	if (rc != 0) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "query_qp(): Error writing resp data (rc=%d)", rc);
		rc = EFAULT;
		goto err_out;
	}

	return (DDI_SUCCESS);

err_out:
	return (rc);
}

/*
 * Function:
 *      sol_uverbs_create_srq
 * Input:
 *      uctxt   - Pointer to the callers user context.
 *      buf     - Pointer to kernel buffer containing command.
 *      in_len  - Length in bytes of input command buffer.
 *      out_len - Length in bytes of output response buffer.
 * Output:
 *      The command output buffer is updated with command results.
 * Returns:
 *      DDI_SUCCESS on success, else error code.
 * Description:
 *      User verbs entry point to create a device shared receive queue.
 */
/* ARGSUSED */
int
sol_uverbs_create_srq(uverbs_uctxt_uobj_t *uctxt, char *buf,
    int in_len, int out_len)
{
	struct ib_uverbs_create_srq		cmd;
	struct ib_uverbs_create_srq_resp	resp;
	uverbs_usrq_uobj_t			*usrq;
	uverbs_upd_uobj_t			*upd;
	ibt_srq_flags_t				flags = IBT_SRQ_USER_MAP;
	ibt_srq_sizes_t				attr;
	ibt_srq_sizes_t				real_attr;
	int					rc;

	(void) memcpy(&cmd, buf, sizeof (cmd));
	(void) memset(&resp, 0, sizeof (resp));
	(void) memset(&attr, 0, sizeof (attr));

	attr.srq_wr_sz   = cmd.max_wr;
	attr.srq_sgl_sz  = cmd.max_sge;

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str, "create_srq: "
	    "max_wr=%d, max_sge=%d, srq_limit=%d",
	    cmd.max_wr, cmd.max_sge, cmd.srq_limit);

	if (!attr.srq_wr_sz) {
		SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
		    "create_srq(): Invalid args, invalid work "
		    "request size");

		rc = EINVAL;
		goto err_out;
	}

	if (attr.srq_wr_sz > uctxt->hca->attr.hca_max_srqs_sz ||
	    attr.srq_sgl_sz > uctxt->hca->attr.hca_max_srq_sgl) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "create_srq(): Invalid args, too large");
		rc = EINVAL;
		goto err_out;
	}

	usrq = kmem_zalloc(sizeof (*usrq), KM_NOSLEEP);
	if (usrq == NULL) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "create_srq(): User object alloc failed");
		rc = ENOMEM;
		goto err_out;
	}
	sol_ofs_uobj_init(&usrq->uobj, cmd.user_handle,
	    SOL_UVERBS_USRQ_UOBJ_TYPE);
	rw_enter(&usrq->uobj.uo_lock, RW_WRITER);
	llist_head_init(&usrq->async_list, NULL);
	usrq->async_events_reported = 0;
	usrq->uctxt = uctxt;

	upd = uverbs_uobj_get_upd_read(cmd.pd_handle);
	if (upd == NULL) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "create_srq(): PD Invalid");
		rc = EINVAL;
		goto err_dealloc;
	}

	rc = ibt_alloc_srq(uctxt->hca->hdl, flags, upd->pd, &attr, &usrq->srq,
	    &real_attr);

	if (rc != IBT_SUCCESS) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "create_srq(): Error in ibt_alloc_srq() (rc=%d)", rc);
		usrq->srq = NULL;
		rc = sol_uverbs_ibt_to_kernel_status(rc);
		usrq->uobj.uo_uobj_sz = sizeof (uverbs_usrq_uobj_t);
		goto err_release_pd;
	}

	ibt_set_srq_private(usrq->srq, usrq);

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "create_srq(): ib_alloc_srq()real wqe_sz=%d, real_sg_sz=%d",
	    real_attr.srq_wr_sz, real_attr.srq_sgl_sz);

	/*
	 * Query underlying hardware for data used in mapping CQ back to user
	 * space, we will return this information in the user verbs command
	 * response.
	 */
	rc = ibt_ci_data_out(uctxt->hca->hdl, IBT_CI_NO_FLAGS, IBT_HDL_SRQ,
	    (void *)usrq->srq,  &resp.drv_out, sizeof (resp.drv_out));

	if (rc != IBT_SUCCESS) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "create_srq(): Error in ibt_ci_data_out() (rc=%d)", rc);
		rc = EFAULT;
		usrq->uobj.uo_uobj_sz = sizeof (uverbs_usrq_uobj_t);
		goto err_srq_destroy;
	}

	if (sol_ofs_uobj_add(&uverbs_usrq_uo_tbl, &usrq->uobj) != 0) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "create_srq(): uobj add failed");
		rc = ENOMEM;
		goto err_srq_destroy;
	}

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "create_srq(): ibt_ci_data_out: 0x%16llx 0x%16llx 0x%16llx "
	    "0x%16llx", resp.drv_out[0], resp.drv_out[1], resp.drv_out[2],
	    resp.drv_out[3]);

	resp.srq_handle	= usrq->uobj.uo_id;
	resp.max_wr	= real_attr.srq_wr_sz;
	resp.max_sge	= real_attr.srq_sgl_sz;

#ifdef	_LP64
	rc = copyout((void*)&resp, (void*)cmd.response.r_laddr, sizeof (resp));
#else
	rc = copyout((void*)&resp, (void*)cmd.response.r_addr, sizeof (resp));
#endif
	if (rc != 0) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "create_srq(): Error writing resp data (rc=%d)", rc);
		rc = EFAULT;
		goto err_uo_delete;
	}

	mutex_enter(&uctxt->lock);
	usrq->list_entry = add_genlist(&uctxt->srq_list, (uintptr_t)usrq,
	    uctxt);
	mutex_exit(&uctxt->lock);

	if (!usrq->list_entry) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "create_srq() : Error adding usrq to srq_list failed");
		rc = ENOMEM;
		goto err_uo_delete;
	}

	usrq->uobj.uo_live = 1;
	rw_exit(&usrq->uobj.uo_lock);

	sol_ofs_uobj_put(&upd->uobj);

	return (DDI_SUCCESS);

err_uo_delete:
	/*
	 * Need to set uo_live, so sol_ofs_uobj_remove() will
	 * remove the object from the object table.
	 */
	usrq->uobj.uo_live = 1;
	(void) sol_ofs_uobj_remove(&uverbs_usrq_uo_tbl, &usrq->uobj);

err_srq_destroy:
	(void) ibt_free_srq(usrq->srq);

err_release_pd:
	sol_ofs_uobj_put(&upd->uobj);

err_dealloc:
	rw_exit(&usrq->uobj.uo_lock);
	sol_ofs_uobj_deref(&usrq->uobj, sol_ofs_uobj_free);

err_out:
	return (rc);
}

/*
 * Function:
 *      sol_uverbs_modify_srq
 * Input:
 *      uctxt   - Pointer to the callers user context.
 *      buf     - Pointer to kernel buffer containing SRQ modify command.
 *      in_len  - Length in bytes of input command buffer.
 *      out_len - Length in bytes of output response buffer.
 * Output:
 *      The command output buffer is updated with command results.
 * Returns:
 *      DDI_SUCCESS on success, else error code.
 * Description:
 *      User verbs entry point to modify a device shared receive queue.
 */
/* ARGSUSED */
int
sol_uverbs_modify_srq(uverbs_uctxt_uobj_t *uctxt, char *buf,
    int in_len, int out_len)
{
	struct ib_uverbs_modify_srq	cmd;
	uverbs_usrq_uobj_t		*usrq;
	uint_t				limit = 0;
	uint_t				size = 0;
	uint_t				real_size = 0;
	ibt_srq_modify_flags_t 		flags = 0;
	int				rc;

	(void) memcpy(&cmd, buf, sizeof (cmd));

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "modify_srq(): entry (srq_handle=%d)", cmd.srq_handle);

	usrq = uverbs_uobj_get_usrq_read(cmd.srq_handle);
	if (usrq == NULL) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "modify_srq(): List lookup failure");
		rc = EINVAL;
		goto err_out;
	}

	if (cmd.attr_mask & IB_SRQ_MAX_WR) {
		flags = IBT_SRQ_SET_SIZE;
		size = cmd.max_wr;
	}

	if (cmd.attr_mask & IB_SRQ_LIMIT) {
		flags |= IBT_SRQ_SET_LIMIT;
		limit = cmd.srq_limit;
	}

	rc = ibt_modify_srq(usrq->srq, flags, size, limit, &real_size);
	if (rc != IBT_SUCCESS) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "modify_srq(): Error in ibt_modify_srq() (rc=%d)", rc);
		rc = sol_uverbs_ibt_to_kernel_status(rc);
		goto err_deref;
	}

	sol_ofs_uobj_put(&usrq->uobj);
	return (DDI_SUCCESS);

err_deref:
	sol_ofs_uobj_put(&usrq->uobj);

err_out:
	return (rc);
}

/*
 * Function:
 *      sol_uverbs_query_srq
 * Input:
 *      uctxt   - Pointer to the callers user context.
 *      buf     - Pointer to kernel buffer containing command.
 *      in_len  - Length in bytes of input command buffer.
 *      out_len - Length in bytes of output response buffer.
 * Output:
 *      The command output buffer is updated with command results.
 * Returns:
 *      DDI_SUCCESS on success, else error code.
 * Description:
 *      User verbs entry point to query a device shared receive queue
 *	properties.
 */
/* ARGSUSED */
int
sol_uverbs_query_srq(uverbs_uctxt_uobj_t *uctxt, char *buf,
    int in_len, int out_len)
{
	struct ib_uverbs_query_srq	cmd;
	struct ib_uverbs_query_srq_resp	resp;
	uverbs_usrq_uobj_t		*usrq;
	ibt_pd_hdl_t			pd;
	int				rc;
	ibt_srq_sizes_t			attr;
	uint_t				limit;

	(void) memcpy(&cmd, buf, sizeof (cmd));
	(void) memset(&resp, 0, sizeof (resp));

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "query_srq(): entry (srq_handle=%d)", cmd.srq_handle);

	usrq = uverbs_uobj_get_usrq_read(cmd.srq_handle);
	if (usrq == NULL) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "query_srq(): Invalid handle: %d", cmd.srq_handle);
		rc = EINVAL;
		goto err_out;
	}

	rc = ibt_query_srq(usrq->srq, &pd, &attr, &limit);
	sol_ofs_uobj_put(&usrq->uobj);

	if (rc != IBT_SUCCESS) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "query_srq(): Error in ibt_query_srq() (rc=%d)", rc);
		rc = sol_uverbs_ibt_to_kernel_status(rc);
		goto err_out;
	}

	resp.max_wr    = attr.srq_wr_sz;
	resp.max_sge   = attr.srq_sgl_sz;
	resp.srq_limit = limit;

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str, "query_srq() - "
	    "max_wr=%d, max_sge=%d, limit=%d", resp.max_wr,
	    resp.max_sge, resp.srq_limit);

	/*
	 * Release the reference from the find above, we leave the initial
	 * reference placed at SRQ creation time.
	 */

#ifdef	_LP64
	rc = copyout((void*)&resp, (void*)cmd.response.r_laddr, sizeof (resp));
#else
	rc = copyout((void*)&resp, (void*)cmd.response.r_addr, sizeof (resp));
#endif
	if (rc != 0) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str, "query_srq() - "
		    "copyout failure %x", rc);
		rc = EFAULT;
		goto err_out;
	}

	return (DDI_SUCCESS);

err_out:
	return (rc);
}

int
uverbs_usrq_free(uverbs_usrq_uobj_t *usrq, uverbs_uctxt_uobj_t *uctxt)
{
	int	rc;

	if (!usrq->srq)
		goto skip_ibt_free_srq;

	rc = ibt_free_srq(usrq->srq);
	if (rc != IBT_SUCCESS) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str, "usrq_free() - "
		    "Error in ibt_free_srq() (rc=%d)", rc);
		rc = sol_uverbs_ibt_to_kernel_status(rc);
		sol_ofs_uobj_put(&usrq->uobj);
		return (rc);
	}
	usrq->srq = NULL;

skip_ibt_free_srq :
	sol_ofs_uobj_put(&usrq->uobj);
	if (usrq->list_entry) {
		mutex_enter(&uctxt->lock);
		delete_genlist(&uctxt->srq_list,  usrq->list_entry);
		mutex_exit(&uctxt->lock);
		(void) sol_ofs_uobj_remove(&uverbs_usrq_uo_tbl, &usrq->uobj);
	}
	sol_ofs_uobj_deref(&usrq->uobj, sol_ofs_uobj_free);

	return (0);
}

/*
 * Function:
 *      sol_uverbs_destroy_srq
 * Input:
 *      uctxt   - Pointer to the callers user context.
 *      buf     - Pointer to kernel buffer containing command.
 *      in_len  - Length in bytes of input command buffer.
 *      out_len - Length in bytes of output response buffer.
 * Output:
 *      The command output buffer is updated with command results.
 * Returns:
 *      DDI_SUCCESS on success, else error code.
 * Description:
 *      User verbs entry point to destroy a device shared receive queue.
 */
/* ARGSUSED */
int
sol_uverbs_destroy_srq(uverbs_uctxt_uobj_t *uctxt, char *buf,
    int in_len, int out_len)
{
	struct ib_uverbs_destroy_srq		cmd;
	struct ib_uverbs_destroy_srq_resp	resp;
	uverbs_usrq_uobj_t			*usrq;
	int					rc;

	(void) memcpy(&cmd, buf, sizeof (cmd));
	(void) memset(&resp, 0, sizeof (resp));
	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str, "destroy_srq() - "
	    "srq_handle %d", cmd.srq_handle);

	usrq = uverbs_uobj_get_usrq_write(cmd.srq_handle);
	if (usrq == NULL) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "destroy_srq() : inavlid hdl %d", cmd.srq_handle);
		rc = EINVAL;
		goto err_out;
	}

	uverbs_release_usrq_uevents(uctxt->async_evfile, usrq);
	resp.events_reported = usrq->async_events_reported;
	if (usrq->active_qp_cnt) {
		sol_ofs_uobj_put(&usrq->uobj);
		return (EBUSY);
	} else {
		rc = uverbs_usrq_free(usrq, uctxt);
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
		    "destroy_srq() : copyout failure %x", rc);
		rc = EFAULT;
		goto err_out;
	}

	return (DDI_SUCCESS);

err_out:
	return (rc);
}

/*
 * Function:
 *      sol_uverbs_attach_mcast
 * Input:
 *      uctxt   - Pointer to the callers user context.
 *      buf     - Pointer to kernel buffer containing command.
 *      in_len  - Length in bytes of input command buffer.
 *      out_len - Length in bytes of output response buffer.
 * Output:
 *      The command output buffer is updated with command results.
 * Returns:
 *      DDI_SUCCESS on success, else error code.
 * Description:
 *      User verbs entry point to attach a QP to a multicast group
 */
/* ARGSUSED */
int
sol_uverbs_attach_mcast(uverbs_uctxt_uobj_t *uctxt, char *buf,
    int in_len, int out_len)
{
	struct ib_uverbs_attach_mcast	cmd;
	uverbs_uqp_uobj_t		*uqp;
	uverbs_mcast_entry_t		*mc;
	llist_head_t			*entry;
	int				rc;
	ib_gid_t			mc_gid;

	(void) memcpy(&cmd, buf, sizeof (cmd));

	/*
	 * API specifies gid in network order, Solaris expects the gid
	 * in host order, do the conversion if required.
	 */
	mc_gid.gid_prefix = b2h64(*((uint64_t *)&cmd.gid[0]));
	mc_gid.gid_guid   = b2h64(*((uint64_t *)&cmd.gid[8]));

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str, "attach_mcast(qp_handle=%d, "
	    "mlid=0x%04x, gid=%016llx:%016llx", cmd.qp_handle, cmd.mlid,
	    mc_gid.gid_prefix, mc_gid.gid_guid);

	/*
	 * Take object write to protect MC list.
	 */
	uqp = uverbs_uobj_get_uqp_write(cmd.qp_handle);
	if (uqp == NULL) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "attach_mcast QP not found");
		rc = EINVAL;
		goto err_out;
	}

	/*
	 * Look to see if we are already attached and if so no need to attach
	 * again, just return good status.
	 */
	list_for_each(entry, &uqp->mcast_list) {
		mc = (uverbs_mcast_entry_t *)entry->ptr;

		if (cmd.mlid == mc->mcg.mc_adds_vect.av_dlid &&
		    !memcmp(&mc_gid.gid, &mc->mcg.mc_adds_vect.av_dgid,
		    sizeof (mc_gid.gid))) {
			SOL_OFS_DPRINTF_L4(sol_uverbs_dbg_str,
			    "attach_mcast: match entry found");
			rc = DDI_SUCCESS;
			goto out_put;
		}
	}

	mc = kmem_zalloc(sizeof (*mc), KM_NOSLEEP);
	if (mc == NULL) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "attach_mcast: kmem_zalloc fail");
		rc = ENOMEM;
		goto out_put;
	}

	llist_head_init(&mc->list, mc);
	mc->mcg.mc_adds_vect.av_dlid  = cmd.mlid;
	bcopy(&mc_gid, &(mc->mcg.mc_adds_vect.av_dgid), sizeof (mc_gid));

	rc = ibt_attach_mcg(uqp->qp, &mc->mcg);
	if (rc != IBT_SUCCESS) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "attach_mcast: ibt_attach_mcq failed (r=%d)", rc);
		rc = sol_uverbs_ibt_to_kernel_status(rc);
		goto err_free;
	}

	llist_add_tail(&mc->list, &uqp->mcast_list);
	sol_ofs_uobj_put(&uqp->uobj);

	return (DDI_SUCCESS);

err_free:
	kmem_free(mc, sizeof (*mc));
out_put:
	sol_ofs_uobj_put(&uqp->uobj);
err_out:
	return (rc);
}

/*
 * Function:
 *      sol_uverbs_detach_mcast
 * Input:
 *      uctxt   - Pointer to the callers user context.
 *      buf     - Pointer to kernel buffer containing command.
 *      in_len  - Length in bytes of input command buffer.
 *      out_len - Length in bytes of output response buffer.
 * Output:
 *      The command output buffer is updated with command results.
 * Returns:
 *      DDI_SUCCESS on success, else error code.
 * Description:
 *      User verbs entry point to detach a QP from a multicast group
 */
/* ARGSUSED */
int
sol_uverbs_detach_mcast(uverbs_uctxt_uobj_t *uctxt, char *buf,
    int in_len, int out_len)
{
	struct ib_uverbs_detach_mcast	cmd;
	uverbs_uqp_uobj_t		*uqp;
	ibt_mcg_info_t			mcg;
	int				rc;
	uverbs_mcast_entry_t		*mc;
	llist_head_t			*entry;
	llist_head_t			*temp;
	ib_gid_t			mc_gid;

	(void) memcpy(&cmd, buf, sizeof (cmd));

	/*
	 * API specifies gid in network order, Solaris expects the gid
	 * in host order, do the conversion if required.
	 */
	mc_gid.gid_prefix = b2h64(*((uint64_t *)&cmd.gid[0]));
	mc_gid.gid_guid   = b2h64(*((uint64_t *)&cmd.gid[8]));

	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "detach_mcast: entry (qp_handle=%d, mlid=0x%04x,"
	    "gid=%016llx:%016llx", cmd.qp_handle, cmd.mlid, mc_gid.gid_prefix,
	    mc_gid.gid_guid);

	(void) memset(&mcg, 0, sizeof (mcg));

	/*
	 * Get object write to protect mcast list.
	 */
	uqp = uverbs_uobj_get_uqp_write(cmd.qp_handle);
	if (uqp == NULL) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "detach_mcast(): QP hdl %x not found", cmd.qp_handle);
		rc = EINVAL;
		goto err_out;
	}

	mcg.mc_adds_vect.av_dlid = cmd.mlid;
	mcg.mc_adds_vect.av_dgid = mc_gid;

	rc = ibt_detach_mcg(uqp->qp, &mcg);
	if (rc != IBT_SUCCESS) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "deatch_mcast(): ibt_attach_mcq failed (r=%d)", rc);
		rc = sol_uverbs_ibt_to_kernel_status(rc);
		goto err_put;
	}

	/*
	 * Find and delete MC group from the QP multicast list.
	 */
	entry = uqp->mcast_list.nxt;
	temp = entry->nxt;
	while (entry != &uqp->mcast_list) {
		ASSERT(entry);
		mc    = (uverbs_mcast_entry_t *)entry->ptr;
		ASSERT(mc);

		if (cmd.mlid == mc->mcg.mc_adds_vect.av_dlid &&
		    !memcmp(&mc_gid.gid, &mc->mcg.mc_adds_vect.av_dgid,
		    sizeof (mc_gid.gid))) {
			llist_del(&mc->list);
			kmem_free(mc, sizeof (*mc));
			break;
		}
		entry = temp;
		temp = entry->nxt;
	}

	sol_ofs_uobj_put(&uqp->uobj);

	return (DDI_SUCCESS);

err_put:
	sol_ofs_uobj_put(&uqp->uobj);

err_out:
	return (rc);
}

/*
 * Function:
 *      uverbs_release_uqp_mcast_entries
 * Input:
 *      uctxt   - Pointer to the callers user context.
 *      uqp     - Pointer to the user QP object for which the multicast
 *                list should be flushed.
 * Output:
 *      None
 * Returns:
 *      None
 * Description:
 *      Release any multicast resources held by this QP.  The
 *	user context associated with the QP should be locked
 *	externally to this routine to protect the updates to the
 *	multicast list.
 */
void
uverbs_detach_uqp_mcast_entries(uverbs_uqp_uobj_t *uqp)
{
	int			rc;
	uverbs_mcast_entry_t	*mc;
	llist_head_t		*entry;
	llist_head_t		*temp;

	/*
	 * Find and delete MC group from the QP multicast list.
	 */
	entry = uqp->mcast_list.nxt;
	temp = entry->nxt;
	while (entry != &uqp->mcast_list) {
		ASSERT(entry);
		mc    = (uverbs_mcast_entry_t *)entry->ptr;
		ASSERT(mc);

		rc = ibt_detach_mcg(uqp->qp, &mc->mcg);
		if (rc != IBT_SUCCESS) {
			SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
			    "detach_mcast() : "
			    "ibt_detach_mcq failed (r=%d)", rc);
		}
		llist_del(&mc->list);
		entry = temp;
		temp = entry->nxt;
	}
}

/*
 * Function:
 *      sol_uverbs_uqpid_to_ibt_handle
 * Input:
 *      uqpid   - A user verbs QP id, i.e. a QP handle that was
 *	          created via libibverbs and sol_uverbs.
 * Output:
 *      None
 * Returns:
 *      The ibt_qp_hdl_t associated with the user space QP handle.
 *	-1 is returned if the id is not found.
 * Description:
 *      Map the user verbs QP id to the associated IBT QP handle.
 */
ibt_qp_hdl_t
sol_uverbs_uqpid_to_ibt_handle(uint32_t uqpid)
{
	uverbs_uqp_uobj_t	*uqp;
	void			*qphdl;

	uqp = uverbs_uobj_get_uqp_read(uqpid);
	if (uqp == NULL) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "uqpid2ibthdl: QP lookup failure: id %d", uqpid);
		return (NULL);
	}
	qphdl = (void *)uqp->qp;
	sol_ofs_uobj_put(&uqp->uobj);
	return (qphdl);
}

/*
 * Function:
 *      sol_uverbs_disable_user_qp_modify
 * Input:
 *      uqpid   - A user verbs QP id, i.e. a QP handle that was
 *	          created via libibverbs and sol_uverbs.
 * Output:
 *      None
 * Returns:
 *      0 on success, EINVAL if associated QP is not found.
 * Description:
 *      Inform sol_uverbs driver to ignore user qp modify
 *	operations it receives for the specified qp.  To re-enable
 *	this capability see the function sol_uverbs_enable_user_qp_modify.
 */
int
sol_uverbs_disable_user_qp_modify(uint32_t uqpid)
{
	uverbs_uqp_uobj_t	*uqp;

	uqp = uverbs_uobj_get_uqp_write(uqpid);
	if (uqp == NULL) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "disable_uqp_modify(%d) -lookup failure", uqpid);
		return (EINVAL);
	}
	uqp->disable_qp_mod = TRUE;
	sol_ofs_uobj_put(&uqp->uobj);
	return (0);
}

/*
 * Function:
 *      sol_uverbs_enable_user_qp_modify
 * Input:
 *      uqpid   - A user verbs QP id, i.e. a QP handle that was
 *	          created via libibverbs and sol_uverbs.
 * Output:
 *      None
 * Returns:
 *      0 on success, EINVAL if associated QP is not found.
 * Description:
 *      Inform sol_uverbs driver to process user qp modify
 *	operations it receives for the specified qp.  This is
 *	the default and this routine need only be invoked if
 *	user QP modify operations have explicitly been disabled
 *	with sol_uverbs_disable_user_qp_modify.
 */
int
sol_uverbs_enable_user_qp_modify(uint32_t uqpid)
{
	uverbs_uqp_uobj_t    *uqp;

	uqp = uverbs_uobj_get_uqp_write(uqpid);
	if (uqp == NULL) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "enable_uqp_modify(%d) -lookup failure", uqpid);
		return (EINVAL);
	}
	uqp->disable_qp_mod = FALSE;
	sol_ofs_uobj_put(&uqp->uobj);
	return (0);
}

int
uverbs_uqpn_cq_ctrl(uint32_t uqpid, sol_uverbs_cq_ctrl_t ctrl)
{
	uverbs_uqp_uobj_t	*uqp;
	uverbs_ucq_uobj_t	*uscq;
	uverbs_ucq_uobj_t	*urcq;

	uqp = uverbs_uobj_get_uqp_write(uqpid);
	if (uqp == NULL) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "uqpn_cq_ctrl(%d) -lookup failure", uqpid);
		return (EINVAL);
	}
	uscq = uqp->uqp_scq;
	urcq = uqp->uqp_rcq;
	SOL_OFS_DPRINTF_L5(sol_uverbs_dbg_str,
	    "ctrl - uqp %p, rcq %p. scq %p", uqp, urcq, uscq);

	ASSERT(uscq);
	ASSERT(urcq);
	uverbs_cq_ctrl(uscq, ctrl);
	if (uscq != urcq)
		uverbs_cq_ctrl(urcq, ctrl);
	sol_ofs_uobj_put(&uqp->uobj);
	return (0);
}

extern uint32_t	sol_uverbs_qpnum2uqpid(uint32_t);

void
sol_uverbs_flush_qp(uint32_t qpnum)
{
	int32_t			uqpid;
	ibt_status_t		status;
	uverbs_uqp_uobj_t	*uqp;

	uqpid = sol_uverbs_qpnum2uqpid(qpnum);
	if (uqpid == DDI_FAILURE) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "sol_uverbs_flush_qp(%x) - Invalid qpnum",
		    qpnum);
		return;
	}
	uqp = uverbs_uobj_get_uqp_write(uqpid);
	if (uqp == NULL) {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "sol_uverbs_flush_qp(%x) - Invalid "
		    "uqpid %x", qpnum, uqpid);
		return;
	}

	if (uqp->qp) {
		status = ibt_flush_qp(uqp->qp);
		if (status != IBT_SUCCESS)
			SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
			    "sol_uverbs_flush_qp(%x) - "
			    "ibt_flush_qp(%p) failed - status %d",
			    qpnum, uqp->qp, status);
		sol_ofs_uobj_put(&uqp->uobj);
		return;
	} else {
		SOL_OFS_DPRINTF_L2(sol_uverbs_dbg_str,
		    "sol_uverbs_flush_qp(%x), uqpid %x -"
		    "uqp->qp is NULL!!", qpnum, uqpid);
		sol_ofs_uobj_put(&uqp->uobj);
		return;
	}
}
static uint32_t
ibt_cep_flags2ibv(ibt_cep_flags_t ibt_flags)
{
	uint32_t	ib_flags = 0;

	if (ibt_flags & IBT_CEP_RDMA_WR)
		ib_flags |= IB_ACCESS_REMOTE_WRITE;
	if (ibt_flags & IBT_CEP_RDMA_RD)
		ib_flags |= IB_ACCESS_REMOTE_READ;
	if (ibt_flags & IBT_CEP_ATOMIC)
		ib_flags |= IB_ACCESS_REMOTE_ATOMIC;

	return (ib_flags);
}

static void
uverbs_cq_ctrl(uverbs_ucq_uobj_t *ucq, sol_uverbs_cq_ctrl_t ctrl)
{
	uverbs_ufile_uobj_t	*ufile;

	ufile = ucq->comp_chan;
	if (!ufile) {
		SOL_OFS_DPRINTF_L3(sol_uverbs_dbg_str,
		    "cq_ctrl(%p), ufile NULL", ucq, ufile);
		return;
	}

	mutex_enter(&ufile->lock);
	ufile->ufile_notify_enabled = ctrl;

	if (ctrl == SOL_UVERBS2UCMA_CQ_NOTIFY_ENABLE) {
		if (!llist_empty(&ufile->event_list)) {
			cv_signal(&ufile->poll_wait);
			pollwakeup(&ufile->poll_head,
			    POLLIN | POLLRDNORM);
		}
	}
	mutex_exit(&ufile->lock);
}
