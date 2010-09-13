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
#include <sys/prom_plat.h>
#include <sys/oplmsu/oplmsu.h>
#include <sys/oplmsu/oplmsu_proto.h>

/*
 *	LOWER READ SERVICE PROCEDURE
 */

/* termios ioctl response received */
int
oplmsu_lrioctl_termios(queue_t *lrq, mblk_t *mp)
{
	upath_t		*upath, *altn_upath = NULL, *stp_upath = NULL;
	lpath_t		*lpath, *altn_lpath = NULL, *stp_lpath = NULL;
	struct iocblk	*iocp, *temp_iocp = NULL;
	mblk_t		*hndl_mp, *nmp = NULL, *fmp = NULL;
	queue_t		*dst_queue;
	int		term_ioctl, term_stat, sts;
	int		ack_flag, termio_flag, chkflag;
	ulong_t		trad_sts;

	rw_enter(&oplmsu_uinst->lock, RW_READER);
	iocp = (struct iocblk *)mp->b_rptr;

	mutex_enter(&oplmsu_uinst->u_lock);
	mutex_enter(&oplmsu_uinst->l_lock);
	lpath = (lpath_t *)lrq->q_ptr;
	hndl_mp = lpath->hndl_mp;

	upath = oplmsu_search_upath_info(lpath->path_no);
	trad_sts = upath->traditional_status;
	mutex_exit(&oplmsu_uinst->l_lock);
	mutex_exit(&oplmsu_uinst->u_lock);

	if (((iocp->ioc_cmd == TCSETS) && (trad_sts == MSU_WTCS_ACK)) ||
	    ((iocp->ioc_cmd == TCSETSW) && (trad_sts == MSU_WTCS_ACK)) ||
	    ((iocp->ioc_cmd == TCSETSF) && (trad_sts == MSU_WTCS_ACK)) ||
	    ((iocp->ioc_cmd == TIOCMSET) && (trad_sts == MSU_WTMS_ACK)) ||
	    ((iocp->ioc_cmd == TIOCSPPS) && (trad_sts == MSU_WPPS_ACK)) ||
	    ((iocp->ioc_cmd == TIOCSWINSZ) && (trad_sts == MSU_WWSZ_ACK)) ||
	    ((iocp->ioc_cmd == TIOCSSOFTCAR) && (trad_sts == MSU_WCAR_ACK))) {
		if (mp->b_datap->db_type == M_IOCACK) {
			ack_flag = ACK_RES;
		} else {
			ack_flag = NAK_RES;
		}
	} else {
		rw_exit(&oplmsu_uinst->lock);
		freemsg(mp);
		cmn_err(CE_WARN, "oplmsu: lr-termios: "
		    "Status of path is improper");
		return (SUCCESS);
	}

	switch (trad_sts) {
	case MSU_WTCS_ACK :
		termio_flag = MSU_TIOS_TCSETS;
		break;

	case MSU_WTMS_ACK :
		termio_flag = MSU_TIOS_MSET;
		break;

	case MSU_WPPS_ACK :
		termio_flag = MSU_TIOS_PPS;
		break;

	case MSU_WWSZ_ACK :
		termio_flag = MSU_TIOS_WINSZP;
		break;

	case MSU_WCAR_ACK :
		termio_flag = MSU_TIOS_SOFTCAR;
		break;

	default :
		termio_flag = MSU_TIOS_END;
		break;
	}

	if (hndl_mp == NULL) {
		switch (trad_sts) {
		case MSU_WTCS_ACK :	/* FALLTHRU */
		case MSU_WTMS_ACK :	/* FALLTHRU */
		case MSU_WPPS_ACK :	/* FALLTHRU */
		case MSU_WWSZ_ACK :	/* FALLTHRU */
		case MSU_WCAR_ACK :
			chkflag = MSU_CMD_STOP;
			break;

		default :
			chkflag = FAILURE;
			break;
		}
	} else {
		/* xoff/xon received */
		if (hndl_mp->b_datap->db_type == M_DATA) {
			chkflag = MSU_CMD_ACTIVE;
		} else { /* Normal termios */
			temp_iocp = (struct iocblk *)hndl_mp->b_rptr;
			chkflag = temp_iocp->ioc_cmd;
		}
	}

	if ((chkflag == MSU_CMD_ACTIVE) || (chkflag == MSU_CMD_STOP)) {
		if (ack_flag == ACK_RES) { /* M_IOCACK received */
			ctrl_t	*ctrl;

			if (oplmsu_cmn_prechg_termio(lrq, mp, MSU_READ_SIDE,
			    termio_flag, &nmp, &term_stat) == FAILURE) {
				rw_exit(&oplmsu_uinst->lock);
				return (FAILURE);
			}

			OPLMSU_RWLOCK_UPGRADE();
			mutex_enter(&oplmsu_uinst->u_lock);
			if (term_stat != MSU_WPTH_CHG) {
				upath->traditional_status = term_stat;
				mutex_exit(&oplmsu_uinst->u_lock);
				rw_exit(&oplmsu_uinst->lock);
				freemsg(mp);

				OPLMSU_TRACE(RD(lrq), nmp, MSU_TRC_LO);

				/* Continue sending termios ioctls */
				qreply(RD(lrq), nmp);
				return (SUCCESS);
			}
			freemsg(mp);

			/* Change status of new active path */
			oplmsu_cmn_set_upath_sts(upath, MSU_PSTAT_ACTIVE,
			    upath->status, MSU_ACTIVE);

			mutex_enter(&oplmsu_uinst->l_lock);
			lpath->uinst = oplmsu_uinst;
			dst_queue = lpath->hndl_uqueue;

			ctrl = oplmsu_uinst->user_ctrl;
			if ((chkflag == MSU_CMD_ACTIVE) && (hndl_mp != NULL)) {
				/* Put a message(M_DATA) on a queue */
				if (ctrl != NULL) {
					mutex_enter(&oplmsu_uinst->c_lock);
					(void) putq(RD(ctrl->queue), hndl_mp);
					mutex_exit(&oplmsu_uinst->c_lock);
				}
			}

			oplmsu_clear_ioctl_path(lpath);
			stp_upath = lpath->src_upath;
			lpath->src_upath = NULL;
			lpath->status = MSU_EXT_NOTUSED;

			/* Notify of the active path changing */
			(void) prom_opl_switch_console(upath->ser_devcb.lsb);

			/* Send XON to notify active path */
			(void) oplmsu_cmn_put_xoffxon(WR(lrq), MSU_XON_4);

			stp_lpath = stp_upath->lpath;
			stp_lpath->uinst = NULL;
			oplmsu_clear_ioctl_path(stp_lpath);
			stp_lpath->src_upath = NULL;
			stp_lpath->status = MSU_EXT_NOTUSED;

			/* Change status of stopped or old-active path */
			if (chkflag == MSU_CMD_STOP) {
				sts = MSU_PSTAT_STOP;
				trad_sts = MSU_STOP;
			} else { /* == MSU_CMD_ACTIVE */
				sts = MSU_PSTAT_STANDBY;
				trad_sts = MSU_STANDBY;
			}
			oplmsu_cmn_set_upath_sts(stp_upath, sts,
			    stp_upath->status, trad_sts);

			/* Send XOFF to notify all standby paths */
			oplmsu_cmn_putxoff_standby();
			oplmsu_uinst->lower_queue = lrq;
			oplmsu_uinst->inst_status = oplmsu_get_inst_status();
			mutex_exit(&oplmsu_uinst->l_lock);
			mutex_exit(&oplmsu_uinst->u_lock);

			/* Change active path of user node */
			if (ctrl != NULL) {
				queue_t	*temp_queue;

				mutex_enter(&oplmsu_uinst->c_lock);
				temp_queue = WR(ctrl->queue);
				mutex_exit(&oplmsu_uinst->c_lock);

				/* Reschedule a queue for service */
				enableok(temp_queue);

				oplmsu_queue_flag = 0;
				oplmsu_wcmn_high_qenable(temp_queue, RW_WRITER);
			}
			rw_exit(&oplmsu_uinst->lock);

			if (nmp != NULL) {
				freemsg(nmp);
			}

			/* Wake up oplmsu_config_stop */
			mutex_enter(&oplmsu_uinst->l_lock);
			if (stp_lpath->sw_flag) {
				stp_lpath->sw_flag = 0;
				cv_signal(&stp_lpath->sw_cv);
			}
			mutex_exit(&oplmsu_uinst->l_lock);
			return (SUCCESS);
		} else { /* M_IOCNAK received */
			mutex_enter(&oplmsu_uinst->u_lock);
			mutex_enter(&oplmsu_uinst->l_lock);
			if ((chkflag == MSU_CMD_ACTIVE) &&
			    (lpath->hndl_uqueue == NULL)) {
				oplmsu_clear_ioctl_path(lpath);
				stp_upath = lpath->src_upath;
				lpath->src_upath = NULL;
				lpath->status = MSU_EXT_NOTUSED;
				mutex_exit(&oplmsu_uinst->l_lock);

				oplmsu_cmn_set_upath_sts(upath,
				    MSU_PSTAT_STANDBY, upath->status,
				    MSU_STANDBY);
				mutex_exit(&oplmsu_uinst->u_lock);

				if (hndl_mp != NULL) {
					freemsg(hndl_mp);
				}

				OPLMSU_RWLOCK_UPGRADE();
				mutex_enter(&oplmsu_uinst->u_lock);
				oplmsu_uinst->inst_status =
				    oplmsu_get_inst_status();
				mutex_exit(&oplmsu_uinst->u_lock);
				rw_exit(&oplmsu_uinst->lock);
				return (SUCCESS);
			} else if ((chkflag == MSU_CMD_STOP) &&
			    (lpath->src_upath != NULL) &&
			    (lpath->src_upath->lpath->sw_flag)) {
			/* MSU_CMD_STOP for active path */

				dst_queue = RD(lpath->hndl_uqueue);
				stp_upath = lpath->src_upath;

				/* Search alternate path from standby paths */
				altn_upath = oplmsu_search_standby();
				if (altn_upath == NULL) {
					altn_upath = upath;
				}

				mutex_exit(&oplmsu_uinst->l_lock);
				if (oplmsu_cmn_allocmb(lrq, mp, &fmp,
				    sizeof (char), MSU_READ_SIDE) == FAILURE) {
					mutex_exit(&oplmsu_uinst->u_lock);
					rw_exit(&oplmsu_uinst->lock);
					return (FAILURE);
				}

				if (oplmsu_cmn_prechg(lrq, mp, MSU_READ_SIDE,
				    &nmp, &term_ioctl, &term_stat) == FAILURE) {
					mutex_exit(&oplmsu_uinst->u_lock);
					rw_exit(&oplmsu_uinst->lock);
					freeb(fmp);
					return (FAILURE);
				}

				altn_upath->traditional_status = term_stat;
				altn_lpath = altn_upath->lpath;

				mutex_enter(&oplmsu_uinst->l_lock);
				altn_lpath->hndl_mp = hndl_mp;
				altn_lpath->hndl_uqueue = dst_queue;
				altn_lpath->src_upath = stp_upath;
				altn_lpath->status = MSU_EXT_VOID;
				dst_queue = RD(altn_lpath->lower_queue);

				oplmsu_cmn_set_upath_sts(upath, MSU_PSTAT_FAIL,
				    upath->status, MSU_FAIL);

				oplmsu_clear_ioctl_path(lpath);
				lpath->src_upath = NULL;
				lpath->status = MSU_EXT_NOTUSED;
				mutex_exit(&oplmsu_uinst->l_lock);
				mutex_exit(&oplmsu_uinst->u_lock);

				OPLMSU_RWLOCK_UPGRADE();
				mutex_enter(&oplmsu_uinst->u_lock);
				oplmsu_uinst->inst_status =
				    oplmsu_get_inst_status();
				mutex_exit(&oplmsu_uinst->u_lock);
				rw_exit(&oplmsu_uinst->lock);
				freemsg(mp);
				oplmsu_cmn_set_mflush(fmp);

				OPLMSU_TRACE(dst_queue, fmp, MSU_TRC_LO);
				qreply(dst_queue, fmp);

				OPLMSU_TRACE(dst_queue, nmp, MSU_TRC_LO);
				qreply(dst_queue, nmp);
				return (SUCCESS);
			}
		}
	} else if ((chkflag == TCSETS) || (chkflag == TCSETSW) ||
	    (chkflag == TCSETSF) || (chkflag == TIOCMSET) ||
	    (chkflag == TIOCSPPS) || (chkflag == TIOCSWINSZ) ||
	    (chkflag == TIOCSSOFTCAR)) {
		mutex_enter(&oplmsu_uinst->u_lock);
		mutex_enter(&oplmsu_uinst->l_lock);

		if ((ack_flag == ACK_RES) &&
		    (lpath->hndl_uqueue != NULL)) { /* M_IOCACK received */
			mutex_exit(&oplmsu_uinst->l_lock);
			mutex_exit(&oplmsu_uinst->u_lock);
			if (oplmsu_cmn_copymb(lrq, mp, &nmp, hndl_mp,
			    MSU_READ_SIDE) == FAILURE) {
				rw_exit(&oplmsu_uinst->lock);
				return (FAILURE);
			}

			OPLMSU_RWLOCK_UPGRADE();
			switch (chkflag) {
			case TCSETS :	/* FALLTHRU */
			case TCSETSW :	/* FALLTHRU */
			case TCSETSF :
				if (oplmsu_uinst->tcsets_p != NULL) {
					freemsg(oplmsu_uinst->tcsets_p);
				}
				oplmsu_uinst->tcsets_p = nmp;
				break;

			case TIOCMSET :
				if (oplmsu_uinst->tiocmset_p != NULL) {
					freemsg(oplmsu_uinst->tiocmset_p);
				}
				oplmsu_uinst->tiocmset_p = nmp;
				break;

			case TIOCSPPS :
				if (oplmsu_uinst->tiocspps_p != NULL) {
					freemsg(oplmsu_uinst->tiocspps_p);
				}
				oplmsu_uinst->tiocspps_p = nmp;
				break;

			case TIOCSWINSZ :
				if (oplmsu_uinst->tiocswinsz_p != NULL) {
					freemsg(oplmsu_uinst->tiocswinsz_p);
				}
				oplmsu_uinst->tiocswinsz_p = nmp;
				break;

			case TIOCSSOFTCAR :
				if (oplmsu_uinst->tiocssoftcar_p != NULL) {
					freemsg(oplmsu_uinst->tiocssoftcar_p);
				}
				oplmsu_uinst->tiocssoftcar_p = nmp;
				break;
			}

			mutex_enter(&oplmsu_uinst->u_lock);
			mutex_enter(&oplmsu_uinst->l_lock);
			upath->traditional_status = lpath->status;
			nmp = lpath->hndl_mp;
			nmp->b_datap->db_type = M_IOCACK;
			dst_queue = RD(lpath->hndl_uqueue);
			bcopy(mp->b_rptr, nmp->b_rptr, sizeof (struct iocblk));

			oplmsu_clear_ioctl_path(lpath);
			lpath->src_upath = NULL;
			lpath->status = MSU_EXT_NOTUSED;
			mutex_exit(&oplmsu_uinst->l_lock);
			mutex_exit(&oplmsu_uinst->u_lock);
			freemsg(mp);
			(void) putq(dst_queue, nmp);

			/* Check sleep flag and wake up thread */
			oplmsu_cmn_wakeup(dst_queue);
			rw_exit(&oplmsu_uinst->lock);
			return (SUCCESS);
		} else if ((ack_flag == NAK_RES) &&
		    (lpath->hndl_uqueue != NULL)) { /* M_IOCNAK received */
			upath->traditional_status = lpath->status;

			nmp = lpath->hndl_mp;
			nmp->b_datap->db_type = M_IOCNAK;
			dst_queue = RD(lpath->hndl_uqueue);

			oplmsu_clear_ioctl_path(lpath);
			lpath->src_upath = NULL;
			lpath->status = MSU_EXT_NOTUSED;
			mutex_exit(&oplmsu_uinst->l_lock);
			mutex_exit(&oplmsu_uinst->u_lock);
			freemsg(mp);
			(void) putq(dst_queue, nmp);

			/* Check sleep flag and wake up thread */
			oplmsu_cmn_wakeup(dst_queue);
			rw_exit(&oplmsu_uinst->lock);
			return (SUCCESS);
		}
	}

	mutex_enter(&oplmsu_uinst->u_lock);
	switch (upath->status) {
	case MSU_PSTAT_FAIL :
		upath->traditional_status = MSU_FAIL;
		break;

	case MSU_PSTAT_STOP :
		upath->traditional_status = MSU_STOP;
		break;

	case MSU_PSTAT_STANDBY :
		upath->traditional_status = MSU_STANDBY;
		break;

	case MSU_PSTAT_ACTIVE :
		upath->traditional_status = MSU_ACTIVE;
		break;
	}

	mutex_enter(&oplmsu_uinst->l_lock);
	oplmsu_clear_ioctl_path(lpath);
	mutex_exit(&oplmsu_uinst->l_lock);
	mutex_exit(&oplmsu_uinst->u_lock);
	rw_exit(&oplmsu_uinst->lock);
	freemsg(mp);
	return (SUCCESS);
}

/* M_ERROR or M_HANGUP response received */
int
oplmsu_lrmsg_error(queue_t *lrq, mblk_t *mp)
{
	upath_t	*upath, *altn_upath = NULL;
	lpath_t	*lpath, *altn_lpath = NULL;
	mblk_t	*nmp = NULL, *fmp = NULL;
	queue_t	*dst_queue = NULL;
	ctrl_t	*ctrl;
	int	term_stat, term_ioctl;

	rw_enter(&oplmsu_uinst->lock, RW_READER);
	mutex_enter(&oplmsu_uinst->c_lock);
	ctrl = oplmsu_uinst->user_ctrl;
	if (ctrl != NULL) {
		dst_queue = RD(ctrl->queue);
	}
	mutex_exit(&oplmsu_uinst->c_lock);

	mutex_enter(&oplmsu_uinst->u_lock);
	mutex_enter(&oplmsu_uinst->l_lock);
	lpath = (lpath_t *)lrq->q_ptr;
	upath = oplmsu_search_upath_info(lpath->path_no);

	if (upath == NULL) {
		mutex_exit(&oplmsu_uinst->l_lock);
		mutex_exit(&oplmsu_uinst->u_lock);
		rw_exit(&oplmsu_uinst->lock);
		freemsg(mp);
		return (SUCCESS);
	}

	if ((lpath->status == MSU_LINK_NU) ||
	    (lpath->status == MSU_SETID_NU) ||
	    (upath->traditional_status == MSU_WSTR_ACK) ||
	    (upath->traditional_status == MSU_WTCS_ACK) ||
	    (upath->traditional_status == MSU_WTMS_ACK) ||
	    (upath->traditional_status == MSU_WPPS_ACK) ||
	    (upath->traditional_status == MSU_WWSZ_ACK) ||
	    (upath->traditional_status == MSU_WCAR_ACK) ||
	    (upath->traditional_status == MSU_WSTP_ACK) ||
	    (upath->traditional_status == MSU_WPTH_CHG)) {
		mutex_exit(&oplmsu_uinst->l_lock);
		mutex_exit(&oplmsu_uinst->u_lock);
		rw_exit(&oplmsu_uinst->lock);
		freemsg(mp);
	} else if ((upath->traditional_status == MSU_MAKE_INST) ||
	    (upath->traditional_status == MSU_STOP) ||
	    (upath->traditional_status == MSU_STANDBY) ||
	    (upath->traditional_status == MSU_SETID) ||
	    (upath->traditional_status == MSU_LINK)) {
		oplmsu_cmn_set_upath_sts(upath, MSU_PSTAT_FAIL, upath->status,
		    MSU_FAIL);
		mutex_exit(&oplmsu_uinst->l_lock);
		mutex_exit(&oplmsu_uinst->u_lock);
		rw_exit(&oplmsu_uinst->lock);
		freemsg(mp);
	} else if (upath->traditional_status == MSU_FAIL) {
		mutex_exit(&oplmsu_uinst->l_lock);
		mutex_exit(&oplmsu_uinst->u_lock);
		rw_exit(&oplmsu_uinst->lock);
		freemsg(mp);
	} else if (upath->traditional_status == MSU_ACTIVE) {
		altn_upath = oplmsu_search_standby();
		if (altn_upath == NULL) {
			oplmsu_cmn_set_upath_sts(upath, MSU_PSTAT_FAIL,
			    upath->status, MSU_FAIL);

			oplmsu_clear_ioctl_path(lpath);
			lpath->src_upath = NULL;
			lpath->status = MSU_EXT_NOTUSED;
			lpath->uinst = NULL;
			mutex_exit(&oplmsu_uinst->l_lock);
			mutex_exit(&oplmsu_uinst->u_lock);

			OPLMSU_RWLOCK_UPGRADE();
			oplmsu_uinst->lower_queue = NULL;
			rw_exit(&oplmsu_uinst->lock);
			freemsg(mp);
			return (SUCCESS);
		}

		mutex_exit(&oplmsu_uinst->l_lock);
		if (oplmsu_cmn_allocmb(lrq, mp, &fmp, sizeof (char),
		    MSU_READ_SIDE) == FAILURE) {
			mutex_exit(&oplmsu_uinst->u_lock);
			rw_exit(&oplmsu_uinst->lock);
			return (FAILURE);
		}

		if (oplmsu_cmn_prechg(lrq, mp, MSU_READ_SIDE, &nmp, &term_ioctl,
		    &term_stat) == FAILURE) {
			mutex_exit(&oplmsu_uinst->u_lock);
			rw_exit(&oplmsu_uinst->lock);
			freeb(fmp);
			return (FAILURE);
		}

		oplmsu_cmn_set_upath_sts(upath, MSU_PSTAT_FAIL,
		    upath->status, MSU_FAIL);

		mutex_enter(&oplmsu_uinst->l_lock);
		lpath->uinst = NULL;

		altn_upath->traditional_status = term_stat;
		altn_lpath = altn_upath->lpath;

		altn_lpath->hndl_mp = NULL;
		altn_lpath->hndl_uqueue = NULL;
		altn_lpath->src_upath = upath;
		altn_lpath->status = MSU_EXT_VOID;
		dst_queue = RD(altn_lpath->lower_queue);
		mutex_exit(&oplmsu_uinst->l_lock);
		mutex_exit(&oplmsu_uinst->u_lock);

		OPLMSU_RWLOCK_UPGRADE();
		oplmsu_uinst->lower_queue = NULL;
		oplmsu_cmn_set_mflush(fmp);

		if (ctrl != NULL) {
			mutex_enter(&oplmsu_uinst->c_lock);
			noenable(WR(ctrl->queue));
			mutex_exit(&oplmsu_uinst->c_lock);

			oplmsu_queue_flag = 1;
		}

		rw_exit(&oplmsu_uinst->lock);
		freemsg(mp);

		OPLMSU_TRACE(dst_queue, fmp, MSU_TRC_LO);
		qreply(dst_queue, fmp);
		OPLMSU_TRACE(dst_queue, nmp, MSU_TRC_LO);
		qreply(dst_queue, nmp);
	}
	return (SUCCESS);
}

/* M_DATA[xoff/xon] was received from serial port */
int
oplmsu_lrdata_xoffxon(queue_t *lrq, mblk_t *mp)
{
	upath_t	*upath, *stp_upath = NULL;
	lpath_t	*lpath, *stp_lpath = NULL;
	mblk_t	*nmp = NULL, *fmp = NULL;
	ctrl_t	*ctrl;
	int	term_stat, term_ioctl;

	rw_enter(&oplmsu_uinst->lock, RW_READER);
	mutex_enter(&oplmsu_uinst->u_lock);
	mutex_enter(&oplmsu_uinst->l_lock);

	if (oplmsu_uinst->lower_queue != NULL) {
		/* Get lower path of active status */
		stp_lpath = (lpath_t *)oplmsu_uinst->lower_queue->q_ptr;
		if (stp_lpath != NULL) {
			stp_upath =
			    oplmsu_search_upath_info(stp_lpath->path_no);
		}
	}

	lpath = (lpath_t *)lrq->q_ptr;
	upath = oplmsu_search_upath_info(lpath->path_no);

	if (upath == NULL) {
		mutex_exit(&oplmsu_uinst->l_lock);
		mutex_exit(&oplmsu_uinst->u_lock);
		rw_exit(&oplmsu_uinst->lock);
		freemsg(mp);
		return (SUCCESS);
	}

	if ((stp_upath != NULL) && (stp_upath != upath)) {
		if ((stp_upath->status != MSU_PSTAT_ACTIVE) ||
		    (stp_upath->traditional_status != MSU_ACTIVE)) {
			mutex_exit(&oplmsu_uinst->l_lock);
			mutex_exit(&oplmsu_uinst->u_lock);
			rw_exit(&oplmsu_uinst->lock);
			(void) putbq(lrq, mp);
			return (FAILURE);
		}
	}

	if ((upath->status == MSU_PSTAT_ACTIVE) &&
	    ((upath->traditional_status == MSU_ACTIVE) ||
	    (upath->traditional_status == MSU_WTCS_ACK) ||
	    (upath->traditional_status == MSU_WTMS_ACK) ||
	    (upath->traditional_status == MSU_WPPS_ACK) ||
	    (upath->traditional_status == MSU_WWSZ_ACK) ||
	    (upath->traditional_status == MSU_WCAR_ACK))) {
		mutex_exit(&oplmsu_uinst->l_lock);
		mutex_exit(&oplmsu_uinst->u_lock);
		(void) oplmsu_rcmn_through_hndl(lrq, mp, MSU_NORM);
		rw_exit(&oplmsu_uinst->lock);
		return (SUCCESS);
	} else if ((upath->status != MSU_PSTAT_STANDBY) ||
	    (upath->traditional_status != MSU_STANDBY)) {
		mutex_exit(&oplmsu_uinst->l_lock);
		mutex_exit(&oplmsu_uinst->u_lock);
		rw_exit(&oplmsu_uinst->lock);
		freemsg(mp);
		cmn_err(CE_WARN, "oplmsu: lr-xoffxon: "
		    "Can't change to specified path");
		return (SUCCESS);
	}
	mutex_exit(&oplmsu_uinst->l_lock);

	if (oplmsu_cmn_allocmb(lrq, mp, &fmp, sizeof (char), MSU_READ_SIDE) ==
	    FAILURE) {
		mutex_exit(&oplmsu_uinst->u_lock);
		rw_exit(&oplmsu_uinst->lock);
		return (FAILURE);
	}

	if (oplmsu_cmn_prechg(lrq, mp, MSU_READ_SIDE, &nmp, &term_ioctl,
	    &term_stat) == FAILURE) {
		mutex_exit(&oplmsu_uinst->u_lock);
		rw_exit(&oplmsu_uinst->lock);
		freeb(fmp);
		return (FAILURE);
	}

	oplmsu_cmn_set_mflush(fmp);
	upath->traditional_status = term_stat;

	mutex_enter(&oplmsu_uinst->l_lock);
	lpath->hndl_mp = mp;
	lpath->hndl_uqueue = NULL;
	lpath->src_upath = stp_upath;
	lpath->status = MSU_EXT_VOID;

	mutex_enter(&oplmsu_uinst->c_lock);
	ctrl = oplmsu_uinst->user_ctrl;
	if (term_stat != MSU_WPTH_CHG) {
		/*
		 * Send termios to new active path and wait response
		 */
		if (ctrl != NULL) {
			noenable(WR(ctrl->queue));
		}
		mutex_exit(&oplmsu_uinst->c_lock);
		mutex_exit(&oplmsu_uinst->l_lock);
		mutex_exit(&oplmsu_uinst->u_lock);
		rw_exit(&oplmsu_uinst->lock);

		OPLMSU_TRACE(RD(lrq), fmp, MSU_TRC_LO);
		qreply(RD(lrq), fmp);
		OPLMSU_TRACE(RD(lrq), nmp, MSU_TRC_LO);
		qreply(RD(lrq), nmp);
	} else {
		/*
		 * No termios messages are received. Change active path.
		 */

		oplmsu_cmn_set_upath_sts(upath, MSU_PSTAT_ACTIVE, upath->status,
		    MSU_ACTIVE);

		lpath->uinst = oplmsu_uinst;
		lpath->src_upath = NULL;
		lpath->status = MSU_EXT_NOTUSED;

		/* Notify of the active path changing */
		(void) prom_opl_switch_console(upath->ser_devcb.lsb);

		(void) putq(WR(lrq), fmp);

		/* Send XON to notify active path */
		(void) oplmsu_cmn_put_xoffxon(WR(lrq), MSU_XON_4);

		if (lpath->hndl_mp != NULL) {
			/* Put a message(M_DATA) on a queue */
			if (ctrl != NULL) {
				(void) putq(RD(ctrl->queue), lpath->hndl_mp);
			}
		}

		oplmsu_clear_ioctl_path(lpath);

		if (ctrl != NULL) {
			noenable(WR(ctrl->queue));
		}

		if ((stp_upath != NULL) && (stp_lpath != NULL)) {
			/* Change the status of stop path */
			oplmsu_cmn_set_upath_sts(stp_upath, MSU_PSTAT_STANDBY,
			    stp_upath->status, MSU_STANDBY);

			oplmsu_clear_ioctl_path(stp_lpath);
			stp_lpath->uinst = NULL;
			stp_lpath->src_upath = NULL;
			stp_lpath->status = MSU_EXT_NOTUSED;
		}
#ifdef DEBUG
		oplmsu_cmn_prt_pathname(upath->ser_devcb.dip);
#endif
		/* Send XOFF to notify all standby paths */
		oplmsu_cmn_putxoff_standby();
		mutex_exit(&oplmsu_uinst->c_lock);
		mutex_exit(&oplmsu_uinst->l_lock);
		mutex_exit(&oplmsu_uinst->u_lock);

		OPLMSU_RWLOCK_UPGRADE();
		mutex_enter(&oplmsu_uinst->u_lock);
		oplmsu_uinst->lower_queue = lrq;
		oplmsu_uinst->inst_status = oplmsu_get_inst_status();
		mutex_exit(&oplmsu_uinst->u_lock);

		if (ctrl != NULL) {
			queue_t *temp_queue;

			mutex_enter(&oplmsu_uinst->c_lock);
			temp_queue = WR(ctrl->queue);
			mutex_exit(&oplmsu_uinst->c_lock);

			/* Reschedule a queue for service */
			enableok(temp_queue);

			oplmsu_queue_flag = 0;
			oplmsu_wcmn_high_qenable(temp_queue, RW_WRITER);
		}
		rw_exit(&oplmsu_uinst->lock);
	}
	return (SUCCESS);
}
