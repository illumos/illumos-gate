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
 * All Rights Reserved, Copyright (c) FUJITSU LIMITED 2006
 */

#include <sys/errno.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/kmem.h>
#include <sys/ksynch.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/termio.h>
#include <sys/ddi.h>
#include <sys/file.h>
#include <sys/disp.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/sunndi.h>
#include <sys/oplmsu/oplmsu.h>
#include <sys/oplmsu/oplmsu_proto.h>

/*
 *	UPPER WRITE SERVICE PROCEDURE
 */

/* I_PLINK ioctl command received */
int
oplmsu_uwioctl_iplink(queue_t *uwq, mblk_t *mp)
{
	struct linkblk	*lbp;
	lpath_t		*lpath;
	int		ncode;

	if (mp == NULL) {
		return (EINVAL);
	}

	if ((mp->b_cont->b_wptr - mp->b_cont->b_rptr) <
	    sizeof (struct linkblk)) {
		cmn_err(CE_WARN, "oplmsu: uw-iplink: Invalid data length");
		oplmsu_iocack(uwq, mp, EINVAL);
		return (EINVAL);
	}

	lbp = (struct linkblk *)mp->b_cont->b_rptr;
	rw_enter(&oplmsu_uinst->lock, RW_WRITER);

	/*
	 * Check whether this is called by super-user privilege.
	 *   uwq => Queue of meta control node
	 */

	ncode = oplmsu_wcmn_chknode(uwq, MSU_NODE_META, mp);
	if (ncode != SUCCESS) {
		rw_exit(&oplmsu_uinst->lock);
		oplmsu_iocack(uwq, mp, ncode);
		return (ncode);
	}

	/* Allocate kernel memory for lpath_t */
	lpath = (lpath_t *)kmem_zalloc(sizeof (lpath_t), KM_NOSLEEP);
	if (lpath == NULL) {
		rw_exit(&oplmsu_uinst->lock);
		cmn_err(CE_WARN, "oplmsu: uw-iplink: "
		    "Failed to allocate kernel memory");
		oplmsu_iocack(uwq, mp, ENOMEM);
		return (ENOMEM);
	}

	/*
	 * Initialize members of lpath_t
	 */

	lpath->rbuftbl =
	    (struct buf_tbl *)kmem_zalloc(sizeof (struct buf_tbl), KM_NOSLEEP);
	if (lpath->rbuftbl == NULL) {
		rw_exit(&oplmsu_uinst->lock);
		kmem_free(lpath, sizeof (lpath_t));
		cmn_err(CE_WARN, "oplmsu: uw-iplink: "
		    "Failed to allocate kernel memory");
		oplmsu_iocack(uwq, mp, ENOMEM);
		return (ENOMEM);
	}

	cv_init(&lpath->sw_cv, "oplmsu lpath condvar", CV_DRIVER, NULL);
	lpath->src_upath = NULL;
	lpath->status = MSU_EXT_NOTUSED;
	lpath->lower_queue = lbp->l_qbot;	/* Set lower queue pointer */
	lpath->link_id = lbp->l_index;		/* Set Link-ID */
	lpath->path_no = UNDEFINED;		/* Set initial path number */
	lpath->abt_char = oplmsu_uinst->abts;	/* Set abort character seq */

	WR(lpath->lower_queue)->q_ptr = lpath;
	RD(lpath->lower_queue)->q_ptr = lpath;

	oplmsu_link_lpath(lpath);	/* Link lpath_t */
	rw_exit(&oplmsu_uinst->lock);
	oplmsu_iocack(uwq, mp, 0);
	return (SUCCESS);
}

/* I_PUNLINK ioctl command received */
int
oplmsu_uwioctl_ipunlink(queue_t *uwq, mblk_t *mp)
{
	struct linkblk	*lbp;
	upath_t		*upath;
	lpath_t		*lpath;
	mblk_t		*hmp = NULL, *next_hmp = NULL;
	bufcall_id_t	rbuf_id;
	timeout_id_t	rtout_id;
	int		ncode;
	int		use_flag;

	if (mp == NULL) {
		return (EINVAL);
	}

	if ((mp->b_cont->b_wptr - mp->b_cont->b_rptr) <
	    sizeof (struct linkblk)) {
		cmn_err(CE_WARN, "oplmsu: uw-ipunlink: Invalid data length");
		oplmsu_iocack(uwq, mp, ENOSR);
		return (ENOSR);
	}

	lbp = (struct linkblk *)mp->b_cont->b_rptr;
	rw_enter(&oplmsu_uinst->lock, RW_WRITER);

	/*
	 * Check whether this is called by super-user privilege.
	 *   uwq => Queue of meta control node
	 */

	ncode = oplmsu_wcmn_chknode(uwq, MSU_NODE_META, mp);
	if (ncode != SUCCESS) {
		rw_exit(&oplmsu_uinst->lock);
		oplmsu_iocack(uwq, mp, ncode);
		return (ncode);
	}

	mutex_enter(&oplmsu_uinst->u_lock);
	mutex_enter(&oplmsu_uinst->l_lock);

	/*
	 * Search for a corresponding lower path information table to
	 * lbp->l_qbot from the lower queue address.
	 */

	lpath = oplmsu_uinst->first_lpath;
	while (lpath) {
		if ((lpath->lower_queue == RD(lbp->l_qbot)) ||
		    (lpath->lower_queue == WR(lbp->l_qbot))) {
			break;
		}
		lpath = lpath->l_next;
	}

	if (lpath == NULL) {
		mutex_exit(&oplmsu_uinst->l_lock);
		mutex_exit(&oplmsu_uinst->u_lock);
		rw_exit(&oplmsu_uinst->lock);
		cmn_err(CE_WARN, "oplmsu: uw-ipunlink: "
		    "Proper lpath_t doesn't find");
		oplmsu_iocack(uwq, mp, EINVAL);
		return (EINVAL);
	}

	/* lpath_t come into the busy status */
	use_flag = oplmsu_set_ioctl_path(lpath, uwq, NULL);
	if (use_flag == BUSY) {
		mutex_exit(&oplmsu_uinst->l_lock);
		mutex_exit(&oplmsu_uinst->u_lock);
		rw_exit(&oplmsu_uinst->lock);
		cmn_err(CE_WARN, "oplmsu: uw-ipunlink: "
		    "Other processing is using lower path");
		oplmsu_iocack(uwq, mp, EBUSY);
		return (EBUSY);
	}

	/* upath_t is retrieved by using the path number */
	upath = oplmsu_search_upath_info(lpath->path_no);
	if (upath != NULL) {	/* When the upath_t exists */
		switch (upath->status) {
		case MSU_PSTAT_STOP :	/* FALLTHRU */
		case MSU_PSTAT_FAIL :
			/*
			 * When traditional_status is MSU_SETID, the path
			 * status is changed into the state of disconnect.
			 */

			if (upath->traditional_status == MSU_SETID) {
				oplmsu_cmn_set_upath_sts(upath,
				    MSU_PSTAT_DISCON, upath->status,
				    MSU_DISCON);
				upath->lpath = NULL;
				break;
			}

			/*
			 * When traditional_status isn't MSU_SETID,
			 * the error is reported.
			 */

		default :
			/*
			 * When upath->status isn't MSU_PSTAT_STOP or
			 * MSU_PSTAT_FAIL, the error is reported.
			 */

			oplmsu_clear_ioctl_path(lpath);
			mutex_exit(&oplmsu_uinst->l_lock);
			cmn_err(CE_WARN, "oplmsu: uw-ipunlink: "
			    "trad_status = %lx", upath->traditional_status);
			cmn_err(CE_WARN, "oplmsu: uw-ipunlink: "
			    "status = %d", upath->status);
			mutex_exit(&oplmsu_uinst->u_lock);
			rw_exit(&oplmsu_uinst->lock);
			oplmsu_iocack(uwq, mp, EINVAL);
			return (EINVAL);
		}
	} else {
		/*
		 * This pattern is no upper info table before config_add or
		 * after config_del.
		 */

		/*
		 * When the upper path table doesn't exist, path is deleted
		 * with config_del/config_add ioctl processed.
		 */

		if ((lpath->status != MSU_LINK_NU) &&
		    (lpath->status != MSU_SETID_NU)) {
			oplmsu_clear_ioctl_path(lpath);
			mutex_exit(&oplmsu_uinst->l_lock);
			mutex_exit(&oplmsu_uinst->u_lock);
			rw_exit(&oplmsu_uinst->lock);
			oplmsu_iocack(uwq, mp, EINVAL);
			return (EINVAL);
		}
	}

	oplmsu_uinst->inst_status = oplmsu_get_inst_status();
	oplmsu_clear_ioctl_path(lpath);

	/* Free high priority message */
	if (lpath->first_lpri_hi != NULL) {
		cmn_err(CE_WARN, "oplmsu: uw-ipunlink: "
		    "Free high-priority message by unlinking lower path");

		for (hmp = lpath->first_lpri_hi; hmp; ) {
			next_hmp = hmp->b_next;
			freemsg(hmp);
			hmp = next_hmp;
		}
		lpath->first_lpri_hi = NULL;
		lpath->last_lpri_hi = NULL;
	}

	rbuf_id = lpath->rbuf_id;
	rtout_id = lpath->rtout_id;
	lpath->rbuf_id = 0;
	lpath->rtout_id = 0;

	kmem_free(lpath->rbuftbl, sizeof (struct buf_tbl));
	lpath->rbuftbl = NULL;
	cv_destroy(&lpath->sw_cv);
	oplmsu_unlink_lpath(lpath);
	kmem_free(lpath, sizeof (lpath_t));

	mutex_exit(&oplmsu_uinst->l_lock);
	mutex_exit(&oplmsu_uinst->u_lock);
	rw_exit(&oplmsu_uinst->lock);

	if (rbuf_id != 0) {
		unbufcall(rbuf_id);
	}

	if (rtout_id != 0) {
		(void) untimeout(rtout_id);
	}
	oplmsu_iocack(uwq, mp, 0);
	return (SUCCESS);
}

/* termio ioctl command received */
int
oplmsu_uwioctl_termios(queue_t *uwq, mblk_t *mp)
{
	struct iocblk	*iocp = NULL;
	queue_t		*dst_queue;
	upath_t		*upath = NULL;
	lpath_t		*lpath = NULL;
	mblk_t		*nmp = NULL;
	ctrl_t		*ctrl;
	int		term_stat;
	int		use_flag;

	if (mp == NULL) {
		return (EINVAL);
	}

	if (mp->b_cont == NULL) {
		cmn_err(CE_WARN, "oplmsu: uw-termios: "
		    "b_cont data block is NULL");
		oplmsu_iocack(uwq, mp, EINVAL);
		return (FAILURE);
	}

	if (mp->b_cont->b_rptr == NULL) {
		cmn_err(CE_WARN, "oplmsu: uw-termios: "
		    "b_rptr data pointer is NULL");
		oplmsu_iocack(uwq, mp, EINVAL);
		return (EINVAL);
	}

	iocp = (struct iocblk *)mp->b_rptr;
	rw_enter(&oplmsu_uinst->lock, RW_READER);

	/*
	 * Check control node type
	 *   uwq : Queue of user control node
	 */

	mutex_enter(&oplmsu_uinst->c_lock);
	ctrl = (ctrl_t *)uwq->q_ptr;
	if (ctrl != NULL) {
		if (ctrl->node_type != MSU_NODE_USER) {
			mutex_exit(&oplmsu_uinst->c_lock);
			rw_exit(&oplmsu_uinst->lock);
			cmn_err(CE_WARN, "oplmsu: uw-termios: "
			    "ctrl node type = %d", ctrl->node_type);
			oplmsu_iocack(uwq, mp, EINVAL);
			return (EINVAL);
		}
	}
	mutex_exit(&oplmsu_uinst->c_lock);

	switch (iocp->ioc_cmd) {
	case TCSETS :	/* FALLTHRU */
	case TCSETSW :	/* FALLTHRU */
	case TCSETSF :
		term_stat = MSU_WTCS_ACK;
		break;

	case TIOCMSET :
		term_stat = MSU_WTMS_ACK;
		break;

	case TIOCSPPS :
		term_stat = MSU_WPPS_ACK;
		break;

	case TIOCSWINSZ :
		term_stat = MSU_WWSZ_ACK;
		break;

	case TIOCSSOFTCAR :
		term_stat = MSU_WCAR_ACK;
		break;

	default :
		rw_exit(&oplmsu_uinst->lock);
		cmn_err(CE_WARN, "oplmsu: uw-termios: ioctl mismatch");
		oplmsu_iocack(uwq, mp, EINVAL);
		return (EINVAL);
	}

	if (oplmsu_uinst->lower_queue == NULL) {
		rw_exit(&oplmsu_uinst->lock);
		cmn_err(CE_WARN, "!oplmsu: uw-termios: "
		    "Active path doesn't exist");
		oplmsu_iocack(uwq, mp, ENODEV);
		return (FAILURE);
	}

	lpath = oplmsu_uinst->lower_queue->q_ptr;
	if (lpath == NULL) {
		rw_exit(&oplmsu_uinst->lock);
		cmn_err(CE_WARN, "oplmsu: uw-termios: "
		    "Proper lpath_t doesn't exist");
		oplmsu_iocack(uwq, mp, EINVAL);
		return (EINVAL);
	}

	if (oplmsu_cmn_copymb(uwq, mp, &nmp, mp, MSU_WRITE_SIDE) == FAILURE) {
		rw_exit(&oplmsu_uinst->lock);
		return (FAILURE);
	}

	mutex_enter(&oplmsu_uinst->u_lock);
	mutex_enter(&oplmsu_uinst->l_lock);

	upath = oplmsu_search_upath_info(lpath->path_no);
	if (upath == NULL) {
		mutex_exit(&oplmsu_uinst->l_lock);
		mutex_exit(&oplmsu_uinst->u_lock);
		rw_exit(&oplmsu_uinst->lock);
		cmn_err(CE_WARN, "oplmsu: uw-termios: "
		    "Proper upath_t doesn't find");
		oplmsu_iocack(uwq, mp, EINVAL);
		return (EINVAL);
	}

	/* Set ioctl command to lower path info table */
	use_flag = oplmsu_set_ioctl_path(lpath, uwq, mp);
	if (use_flag == BUSY) {
		mutex_exit(&oplmsu_uinst->l_lock);
		mutex_exit(&oplmsu_uinst->u_lock);
		freemsg(nmp);

		if (ctrl != NULL) {
			mutex_enter(&oplmsu_uinst->c_lock);
			ctrl->wait_queue = uwq;
			mutex_exit(&oplmsu_uinst->c_lock);
			rw_exit(&oplmsu_uinst->lock);

			(void) putbq(uwq, mp);
			return (SUCCESS);
		} else {
			rw_exit(&oplmsu_uinst->lock);
			oplmsu_iocack(uwq, mp, EBUSY);
			return (EBUSY);
		}
	}

	/* Set destination queue (active path) */
	dst_queue = WR(oplmsu_uinst->lower_queue);
	if (canput(dst_queue)) {
		lpath->src_upath = NULL;
		lpath->status = upath->traditional_status;
		upath->traditional_status = term_stat;
		mutex_exit(&oplmsu_uinst->l_lock);
		mutex_exit(&oplmsu_uinst->u_lock);
		rw_exit(&oplmsu_uinst->lock);

		(void) putq(dst_queue, nmp);
		return (SUCCESS);
	} else {
		oplmsu_clear_ioctl_path(lpath);
		mutex_exit(&oplmsu_uinst->l_lock);
		mutex_exit(&oplmsu_uinst->u_lock);

		freemsg(nmp);
		oplmsu_wcmn_norm_putbq(WR(uwq), mp, dst_queue);
		rw_exit(&oplmsu_uinst->lock);
		return (FAILURE);
	}
}
