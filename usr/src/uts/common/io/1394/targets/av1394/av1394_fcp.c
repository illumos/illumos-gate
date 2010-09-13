/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * av1394 FCP module
 */
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/1394/targets/av1394/av1394_impl.h>

/* configuration routines */
static int	av1394_fcp_ctl_register(av1394_inst_t *);
static int	av1394_fcp_tgt_register(av1394_inst_t *);
static int	av1394_fcp_ctl_alloc_cmd(av1394_inst_t *);
static void	av1394_fcp_ctl_free_cmd(av1394_inst_t *);
static int	av1394_fcp_tgt_alloc_cmd(av1394_inst_t *);
static void	av1394_fcp_tgt_free_cmd(av1394_inst_t *);
static void	av1394_fcp_cleanup(av1394_inst_t *, int);

/* FCP write and completion handling */
static int	av1394_fcp_cmd_write_sync(av1394_inst_t *, av1394_fcp_cmd_t *);
static void	av1394_fcp_cmd_completion_cb(struct cmd1394_cmd *);
static int	av1394_fcp_cmd_write_request_cb(cmd1394_cmd_t *);
static int	av1394_fcp_resp_write_request_cb(cmd1394_cmd_t *);
static void	av1394_fcp_common_write_request_cb(cmd1394_cmd_t *, int);

/* misc routines */
static int	av1394_fcp_copyin_block(iec61883_arq_t *, mblk_t *,
		struct uio *);

#define	AV1394_TNF_ENTER(func)	\
	TNF_PROBE_0_DEBUG(func##_enter, AV1394_TNF_FCP_STACK, "");

#define	AV1394_TNF_EXIT(func)	\
	TNF_PROBE_0_DEBUG(func##_exit, AV1394_TNF_FCP_STACK, "");

/*
 *
 * --- configuration entry points
 *
 */
int
av1394_fcp_attach(av1394_inst_t *avp)
{
	av1394_fcp_t	*fcp = &avp->av_a.a_fcp;
	int		ret;

	AV1394_TNF_ENTER(av1394_fcp_attach);

	/* register FCP controller */
	if ((ret = av1394_fcp_ctl_register(avp)) != DDI_SUCCESS) {
		AV1394_TNF_EXIT(av1394_fcp_attach);
		return (ret);
	}

	/* allocate FCP controller command */
	if ((ret = av1394_fcp_ctl_alloc_cmd(avp)) != DDI_SUCCESS) {
		av1394_fcp_cleanup(avp, 1);
		AV1394_TNF_EXIT(av1394_fcp_attach);
		return (ret);
	}

	/* register FCP target */
	if ((ret = av1394_fcp_tgt_register(avp)) != DDI_SUCCESS) {
		av1394_fcp_cleanup(avp, 2);
		AV1394_TNF_EXIT(av1394_fcp_attach);
		return (ret);
	}

	/* allocate FCP target command */
	if ((ret = av1394_fcp_tgt_alloc_cmd(avp)) != DDI_SUCCESS) {
		av1394_fcp_cleanup(avp, 3);
		AV1394_TNF_EXIT(av1394_fcp_attach);
		return (ret);
	}

	cv_init(&fcp->fcp_cmd.fc_xmit_cv, NULL, CV_DRIVER, NULL);
	cv_init(&fcp->fcp_cmd.fc_busy_cv, NULL, CV_DRIVER, NULL);
	cv_init(&fcp->fcp_resp.fc_xmit_cv, NULL, CV_DRIVER, NULL);
	cv_init(&fcp->fcp_resp.fc_busy_cv, NULL, CV_DRIVER, NULL);

	AV1394_TNF_EXIT(av1394_fcp_attach);
	return (ret);
}

void
av1394_fcp_detach(av1394_inst_t *avp)
{
	AV1394_TNF_ENTER(av1394_fcp_detach);

	av1394_fcp_cleanup(avp, AV1394_CLEANUP_LEVEL_MAX);

	AV1394_TNF_EXIT(av1394_fcp_detach);
}

int
av1394_fcp_write(av1394_inst_t *avp, iec61883_arq_t *arq, struct uio *uiop)
{
	av1394_async_t	*ap = &avp->av_a;
	av1394_fcp_t	*fcp = &ap->a_fcp;
	int		len = arq->arq_len;
	av1394_fcp_cmd_t *fc;
	cmd1394_cmd_t	*cmd;
	mblk_t		*mp = NULL;
	int		ret;

	AV1394_TNF_ENTER(av1394_fcp_write);

	ASSERT((arq->arq_type == IEC61883_ARQ_FCP_CMD) ||
		(arq->arq_type == IEC61883_ARQ_FCP_RESP));

	/* check arguments */
	if ((len == 0) || (len > AV1394_FCP_ARQ_LEN_MAX) ||
	    (len % IEEE1394_QUADLET != 0)) {
		TNF_PROBE_1(av1394_fcp_write_error,
		    AV1394_TNF_FCP_ERROR, "", tnf_int, len, len);
		AV1394_TNF_EXIT(av1394_fcp_write);
		return (EINVAL);
	}

	/* block write requires an mblk */
	if (len > IEEE1394_QUADLET) {
		if ((mp = allocb(len, BPRI_HI)) == NULL) {
			AV1394_TNF_EXIT(av1394_fcp_write);
			return (ENOMEM);
		}
		if ((ret = av1394_fcp_copyin_block(arq, mp, uiop)) != 0) {
			freemsg(mp);
			AV1394_TNF_EXIT(av1394_fcp_write);
			return (ret);
		}
	}

	/* either FCP command or response */
	fc = (arq->arq_type == IEC61883_ARQ_FCP_CMD) ?
					&fcp->fcp_cmd : &fcp->fcp_resp;

	/* one command at a time */
	mutex_enter(&ap->a_mutex);
	while (fc->fc_busy) {
		if (cv_wait_sig(&fc->fc_busy_cv, &ap->a_mutex) == 0) {
			mutex_exit(&ap->a_mutex);
			freemsg(mp);
			AV1394_TNF_EXIT(av1394_fcp_write);
			return (EINTR);
		}
	}
	fc->fc_busy = B_TRUE;

	/* prepare command */
	cmd = fc->fc_cmd;
	if (len == IEEE1394_QUADLET) {
		cmd->cmd_type = CMD1394_ASYNCH_WR_QUAD;
		cmd->cmd_u.q.quadlet_data = arq->arq_data.quadlet;
	} else {
		cmd->cmd_type = CMD1394_ASYNCH_WR_BLOCK;
		cmd->cmd_u.b.data_block = mp;
		cmd->cmd_u.b.blk_length = len;
	}

	/* do the write and wait for completion */
	ret = av1394_fcp_cmd_write_sync(avp, fc);

	/* not busy anymore */
	fc->fc_busy = B_FALSE;
	cv_broadcast(&fc->fc_busy_cv);
	mutex_exit(&ap->a_mutex);

	freemsg(mp);

	AV1394_TNF_EXIT(av1394_fcp_write);
	return (ret);
}

/*
 *
 * --- configuration routines
 *
 */
static int
av1394_fcp_ctl_register(av1394_inst_t *avp)
{
	t1394_fcp_evts_t evts;
	int		ret;

	evts.fcp_write_request = av1394_fcp_resp_write_request_cb;
	evts.fcp_arg = avp;

	ret = t1394_fcp_register_controller(avp->av_t1394_hdl, &evts, 0);
	if (ret != DDI_SUCCESS) {
		TNF_PROBE_1(av1394_fcp_ctl_register_error,
		    AV1394_TNF_FCP_ERROR, "", tnf_int, ret, ret);
	}
	return (ret);
}

static int
av1394_fcp_tgt_register(av1394_inst_t *avp)
{
	t1394_fcp_evts_t evts;
	int		ret;

	evts.fcp_write_request = av1394_fcp_cmd_write_request_cb;
	evts.fcp_arg = avp;

	ret = t1394_fcp_register_target(avp->av_t1394_hdl, &evts, 0);
	if (ret != DDI_SUCCESS) {
		TNF_PROBE_1(av1394_fcp_tgt_register_error,
		    AV1394_TNF_FCP_ERROR, "", tnf_int, ret, ret);
	}
	return (ret);
}

static int
av1394_fcp_ctl_alloc_cmd(av1394_inst_t *avp)
{
	av1394_fcp_cmd_t *fc = &avp->av_a.a_fcp.fcp_cmd;
	int		ret;

	ret = t1394_alloc_cmd(avp->av_t1394_hdl, T1394_ALLOC_CMD_FCP_COMMAND,
				&fc->fc_cmd);
	if (ret != DDI_SUCCESS) {
		TNF_PROBE_1(av1394_fcp_ctl_alloc_cmd_error,
		    AV1394_TNF_FCP_ERROR, "", tnf_int, ret, ret);
	}
	return (ret);
}

static void
av1394_fcp_ctl_free_cmd(av1394_inst_t *avp)
{
	av1394_fcp_cmd_t *fc = &avp->av_a.a_fcp.fcp_cmd;
	int		ret;

	ret = t1394_free_cmd(avp->av_t1394_hdl, 0, &fc->fc_cmd);
	if (ret != DDI_SUCCESS) {
		TNF_PROBE_1(av1394_fcp_ctl_free_cmd_error,
		    AV1394_TNF_FCP_ERROR, "", tnf_int, ret, ret);
	}
}

static int
av1394_fcp_tgt_alloc_cmd(av1394_inst_t *avp)
{
	av1394_fcp_cmd_t *fc = &avp->av_a.a_fcp.fcp_resp;
	int		ret;

	ret = t1394_alloc_cmd(avp->av_t1394_hdl, T1394_ALLOC_CMD_FCP_RESPONSE,
				&fc->fc_cmd);
	if (ret != DDI_SUCCESS) {
		TNF_PROBE_1(av1394_fcp_tgt_alloc_cmd_error,
		    AV1394_TNF_FCP_ERROR, "", tnf_int, ret, ret);
	}
	return (ret);
}

static void
av1394_fcp_tgt_free_cmd(av1394_inst_t *avp)
{
	av1394_fcp_cmd_t *fc = &avp->av_a.a_fcp.fcp_resp;
	int		ret;

	ret = t1394_free_cmd(avp->av_t1394_hdl, 0, &fc->fc_cmd);
	if (ret != DDI_SUCCESS) {
		TNF_PROBE_1(av1394_fcp_tgt_free_cmd_error,
		    AV1394_TNF_FCP_ERROR, "", tnf_int, ret, ret);
	}
}

static void
av1394_fcp_cleanup(av1394_inst_t *avp, int level)
{
	av1394_fcp_t	*fcp = &avp->av_a.a_fcp;

	ASSERT((level > 0) && (level <= AV1394_CLEANUP_LEVEL_MAX));

	switch (level) {
	default:
		cv_destroy(&fcp->fcp_cmd.fc_xmit_cv);
		cv_destroy(&fcp->fcp_cmd.fc_busy_cv);
		cv_destroy(&fcp->fcp_resp.fc_xmit_cv);
		cv_destroy(&fcp->fcp_resp.fc_busy_cv);

		av1394_fcp_tgt_free_cmd(avp);
		/* FALLTHRU */
	case 3:
		(void) t1394_fcp_unregister_target(avp->av_t1394_hdl);
		/* FALLTHRU */
	case 2:
		av1394_fcp_ctl_free_cmd(avp);
		/* FALLTHRU */
	case 1:
		(void) t1394_fcp_unregister_controller(avp->av_t1394_hdl);
	}
}

/*
 *
 * --- FCP write and completion handling
 *
 */
static int
av1394_fcp_cmd_write_sync(av1394_inst_t *avp, av1394_fcp_cmd_t *fc)
{
	av1394_async_t	*ap = &avp->av_a;
	cmd1394_cmd_t	*cmd = fc->fc_cmd;
	int		ret = 0;

	cmd->completion_callback = av1394_fcp_cmd_completion_cb;
	cmd->cmd_callback_arg = avp;

	/* go */
	ASSERT(!fc->fc_xmit);
	fc->fc_xmit = B_TRUE;

	mutex_exit(&ap->a_mutex);
	ret = t1394_write(avp->av_t1394_hdl, cmd);
	mutex_enter(&ap->a_mutex);

	/* immediate error? */
	if (ret != DDI_SUCCESS) {
		fc->fc_xmit = B_FALSE;
		TNF_PROBE_2(av1394_fcp_cmd_write_sync_error,
		    AV1394_TNF_FCP_ERROR, "", tnf_int, ret, ret,
		    tnf_int, cmd_result, cmd->cmd_result);
		return (EIO);
	}

	/* wait for completion */
	while (fc->fc_xmit) {
		if (cv_wait_sig(&fc->fc_xmit_cv, &ap->a_mutex) == 0) {
			return (EINTR);
		}
	}

	if (cmd->cmd_result != CMD1394_CMDSUCCESS) {
		TNF_PROBE_1(av1394_fcp_cmd_write_sync_error,
		    AV1394_TNF_FCP_ERROR, "",
		    tnf_int, cmd_result, cmd->cmd_result);
		if (cmd->cmd_result == CMD1394_EDEVICE_BUSY) {
			return (EBUSY);
		} else {
			return (EIO);
		}
	} else {
		return (0);
	}
}

static void
av1394_fcp_cmd_completion_cb(struct cmd1394_cmd *cmd)
{
	av1394_inst_t	*avp = cmd->cmd_callback_arg;
	av1394_async_t	*ap = &avp->av_a;
	av1394_fcp_t	*fcp = &ap->a_fcp;
	av1394_fcp_cmd_t *fc;

	AV1394_TNF_ENTER(av1394_fcp_cmd_completion_cb);

	mutex_enter(&ap->a_mutex);
	/* is this FCP command or response */
	if (cmd == fcp->fcp_cmd.fc_cmd) {
		fc = &fcp->fcp_cmd;
	} else {
		ASSERT(cmd == fcp->fcp_resp.fc_cmd);
		fc = &fcp->fcp_resp;
	}

	/* wake the waiter */
	fc->fc_xmit = B_FALSE;
	cv_signal(&fc->fc_xmit_cv);
	mutex_exit(&ap->a_mutex);

	AV1394_TNF_EXIT(av1394_fcp_cmd_completion_cb);
}

/*
 * av1394_fcp_cmd_write_request_cb()
 *    Incoming response request from an FCP target
 */
static int
av1394_fcp_resp_write_request_cb(cmd1394_cmd_t *req)
{
	av1394_inst_t	*avp = req->cmd_callback_arg;
	av1394_async_t	*ap = &avp->av_a;

	AV1394_TNF_ENTER(av1394_fcp_resp_write_request_cb);

	mutex_enter(&ap->a_mutex);
	if ((ap->a_nopen == 0) ||
	    (req->bus_generation != ap->a_bus_generation) ||
	    (req->nodeID != ap->a_targetinfo.target_nodeID)) {
		mutex_exit(&ap->a_mutex);

		AV1394_TNF_EXIT(av1394_fcp_resp_write_request_cb);
		return (T1394_REQ_UNCLAIMED);
	}
	mutex_exit(&ap->a_mutex);

	av1394_fcp_common_write_request_cb(req, AV1394_M_FCP_RESP);

	AV1394_TNF_EXIT(av1394_fcp_resp_write_request_cb);
	return (T1394_REQ_CLAIMED);
}

/*
 * av1394_fcp_cmd_write_request_cb()
 *    Incoming command request from an FCP controller
 */
static int
av1394_fcp_cmd_write_request_cb(cmd1394_cmd_t *req)
{
	av1394_inst_t	*avp = req->cmd_callback_arg;
	av1394_async_t	*ap = &avp->av_a;

	AV1394_TNF_ENTER(av1394_fcp_cmd_write_request_cb);

	mutex_enter(&ap->a_mutex);
	if (ap->a_nopen == 0) {
		mutex_exit(&ap->a_mutex);

		AV1394_TNF_EXIT(av1394_fcp_cmd_write_request_cb);
		return (T1394_REQ_UNCLAIMED);
	}
	mutex_exit(&ap->a_mutex);

	av1394_fcp_common_write_request_cb(req, AV1394_M_FCP_CMD);

	AV1394_TNF_EXIT(av1394_fcp_cmd_write_request_cb);
	return (T1394_REQ_CLAIMED);
}

static void
av1394_fcp_common_write_request_cb(cmd1394_cmd_t *req, int mtype)
{
	av1394_inst_t	*avp = req->cmd_callback_arg;
	mblk_t		*mp;
	uint32_t	quadlet_data;
	int		err;

	AV1394_TNF_ENTER(av1394_fcp_common_write_request_cb);

	ASSERT((req->cmd_type == CMD1394_ASYNCH_WR_QUAD) ||
		(req->cmd_type == CMD1394_ASYNCH_WR_BLOCK));

	/* get the data */
	if (req->cmd_type == CMD1394_ASYNCH_WR_QUAD) {
		quadlet_data = req->cmd_u.q.quadlet_data;
	} else {
		mp = req->cmd_u.b.data_block;
		req->cmd_u.b.data_block = NULL;
	}

	/* complete request */
	req->cmd_result = IEEE1394_RESP_COMPLETE;

	err = t1394_recv_request_done(avp->av_t1394_hdl, req, 0);
	if (err != DDI_SUCCESS) {
		TNF_PROBE_2(av1394_fcp_common_write_request_cb_done_error,
		    AV1394_TNF_FCP_ERROR, "", tnf_int, err, err,
		    tnf_int, result, req->cmd_result);
	}

	/* allocate mblk and copy quadlet into it */
	if (req->cmd_type == CMD1394_ASYNCH_WR_QUAD) {
		mp = allocb(IEEE1394_QUADLET, BPRI_HI);
		if (mp == NULL) {
			TNF_PROBE_0(
			    av1394_fcp_common_write_request_cb_allocb_error,
			    AV1394_TNF_FCP_ERROR, "");
			AV1394_TNF_EXIT(av1394_fcp_common_write_request_cb);
			return;
		}
		*(uint32_t *)mp->b_rptr = quadlet_data;
		mp->b_wptr += IEEE1394_QUADLET;
	}

	/* queue up the data */
	DB_TYPE(mp) = mtype;
	av1394_async_putq_rq(avp, mp);

	AV1394_TNF_EXIT(av1394_fcp_common_write_request_cb);
}

/*
 *
 * --- misc routines
 *
 */
static int
av1394_fcp_copyin_block(iec61883_arq_t *arq, mblk_t *mp, struct uio *uiop)
{
	int	len = arq->arq_len;
	int	copylen;
	int	ret = 0;

	ASSERT((len > 0) && (len % IEEE1394_QUADLET == 0));

	/* first copy ARQ-embedded data */
	copylen = min(len, sizeof (arq->arq_data));
	bcopy(&arq->arq_data.buf[0], mp->b_wptr, copylen);
	mp->b_wptr += copylen;

	/* now copyin the rest of the data, if any */
	copylen = len - copylen;
	if (copylen > 0) {
		ret = uiomove(mp->b_wptr, copylen, UIO_WRITE, uiop);
		if (ret != 0) {
			TNF_PROBE_1(av1394_fcp_copyin_block_error,
			    AV1394_TNF_FCP_ERROR, "", tnf_int, ret, ret);
			return (ret);
		}
		mp->b_wptr += copylen;
	}
	return (ret);
}
