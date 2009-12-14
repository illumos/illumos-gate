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
#include <sys/strsun.h>
#include <sys/oplmsu/oplmsu.h>
#include <sys/oplmsu/oplmsu_proto.h>

/*
 * Link upper_path_table structure
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : M [RW_WRITER]
 *  -. uinst_t->u_lock : M
 *  -. uinst_t->l_lock : A
 *  -. uinst_t->c_lock : A
 */
void
oplmsu_link_upath(upath_t *add_upath)
{

	ASSERT(add_upath != NULL);
	ASSERT(RW_WRITE_HELD(&oplmsu_uinst->lock));
	ASSERT(MUTEX_HELD(&oplmsu_uinst->u_lock));

	if (oplmsu_uinst->first_upath == NULL) {
		oplmsu_uinst->first_upath = add_upath;
		add_upath->u_prev = NULL;
	} else {
		upath_t	*last_upath;

		last_upath = oplmsu_uinst->last_upath;
		last_upath->u_next = add_upath;
		add_upath->u_prev = last_upath;
	}

	oplmsu_uinst->last_upath = add_upath;
	add_upath->u_next = NULL;
}

/*
 * Unlink upper_path_table structure
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : M [RW_WRITER]
 *  -. uinst_t->u_lock : P
 *  -. uinst_t->l_lock : P
 *  -. uinst_t->c_lock : P
 */
void
oplmsu_unlink_upath(upath_t *del_upath)
{
	upath_t **first, **last;

	ASSERT(RW_WRITE_HELD(&oplmsu_uinst->lock));

	first = &oplmsu_uinst->first_upath;
	last = &oplmsu_uinst->last_upath;

	if ((*first != del_upath) && (*last != del_upath)) {
		del_upath->u_prev->u_next = del_upath->u_next;
		del_upath->u_next->u_prev = del_upath->u_prev;
	} else {
		if (*first == del_upath) {
			*first = (*first)->u_next;
			if (*first) {
				(*first)->u_prev = NULL;
			}
		}

		if (*last == del_upath) {
			*last = (*last)->u_prev;
			if (*last) {
				(*last)->u_next = NULL;
			}
		}
	}

	del_upath->u_next = NULL;
	del_upath->u_prev = NULL;
}

/*
 * Link lower_path_table structure
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : M [RW_WRITER]
 *  -. uinst_t->u_lock : A
 *  -. uinst_t->l_lock : M
 *  -. uinst_t->c_lock : A
 */
void
oplmsu_link_lpath(lpath_t *add_lpath)
{

	ASSERT(add_lpath != NULL);
	ASSERT(RW_WRITE_HELD(&oplmsu_uinst->lock));

	if (oplmsu_uinst->first_lpath == NULL) {
		oplmsu_uinst->first_lpath = add_lpath;
		add_lpath->l_prev = NULL;
	} else {
		lpath_t	*last_lpath;

		last_lpath = oplmsu_uinst->last_lpath;
		last_lpath->l_next = add_lpath;
		add_lpath->l_prev = last_lpath;
	}

	oplmsu_uinst->last_lpath = add_lpath;
	add_lpath->l_next = NULL;
}

/*
 * Unlink lower_path_table structure
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : M [RW_WRITER]
 *  -. uinst_t->u_lock : P
 *  -. uinst_t->l_lock : P
 *  -. uinst_t->c_lock : P
 */
void
oplmsu_unlink_lpath(lpath_t *del_lpath)
{
	lpath_t **first, **last;

	ASSERT(RW_WRITE_HELD(&oplmsu_uinst->lock));

	first = &oplmsu_uinst->first_lpath;
	last = &oplmsu_uinst->last_lpath;

	if ((*first != del_lpath) && (*last != del_lpath)) {
		del_lpath->l_prev->l_next = del_lpath->l_next;
		del_lpath->l_next->l_prev = del_lpath->l_prev;
	} else {
		if (*first == del_lpath) {
			*first = (*first)->l_next;
			if (*first) {
				(*first)->l_prev = NULL;
			}
		}

		if (*last == del_lpath) {
			*last = (*last)->l_prev;
			if (*last) {
				(*last)->l_next = NULL;
			}
		}
	}

	del_lpath->l_next = NULL;
	del_lpath->l_prev = NULL;
}

/*
 * Link msgb structure of high priority
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : M [RW_READER]
 *  -. uinst_t->u_lock : A
 *  -. uinst_t->l_lock : A [It depends on caller]
 *  -. uinst_t->c_lock : A [It depends on caller]
 */
void
oplmsu_link_high_primsg(mblk_t **first, mblk_t **last, mblk_t *add_msg)
{

	ASSERT(add_msg != NULL);
	ASSERT(RW_READ_HELD(&oplmsu_uinst->lock));

	if (*first == NULL) {
		*first = add_msg;
		add_msg->b_prev = NULL;
	} else {
		(*last)->b_next = add_msg;
		add_msg->b_prev = *last;
	}

	*last = add_msg;
	add_msg->b_next = NULL;
}

/*
 * Check whether lower path is usable by lower path info table address
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : M [RW_READER or RW_WRITER]
 *  -. uinst_t->u_lock : A
 *  -. uinst_t->l_lock : M
 *  -. uinst_t->c_lock : P
 */
int
oplmsu_check_lpath_usable(void)
{
	lpath_t	*lpath;
	int	rval = SUCCESS;

	ASSERT(RW_LOCK_HELD(&oplmsu_uinst->lock));
	ASSERT(MUTEX_HELD(&oplmsu_uinst->l_lock));

	lpath = oplmsu_uinst->first_lpath;
	while (lpath) {
		if ((lpath->hndl_uqueue != NULL) || (lpath->hndl_mp != NULL)) {
			rval = BUSY;
			break;
		}
		lpath = lpath->l_next;
	}
	return (rval);
}

/*
 * Search upath_t by path number
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : M [RW_READER or RW_WRITER]
 *  -. uinst_t->u_lock : M
 *  -. uinst_t->l_lock : A
 *  -. uinst_t->c_lock : P
 */
upath_t	*
oplmsu_search_upath_info(int path_no)
{
	upath_t	*upath;

	ASSERT(RW_LOCK_HELD(&oplmsu_uinst->lock));
	ASSERT(MUTEX_HELD(&oplmsu_uinst->u_lock));

	upath = oplmsu_uinst->first_upath;
	while (upath) {
		if (upath->path_no == path_no) {
			break;
		}
		upath = upath->u_next;
	}
	return (upath);
}

/*
 * Send M_IOCACK(or M_IOCNAK) message to stream
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : P
 *  -. uinst_t->u_lock : P
 *  -. uinst_t->l_lock : P
 *  -. uinst_t->c_lock : P
 */
void
oplmsu_iocack(queue_t *q, mblk_t *mp, int errno)
{
	struct iocblk	*iocp = NULL;

	ASSERT(mp != NULL);

	iocp = (struct iocblk *)mp->b_rptr;
	iocp->ioc_error = errno;

	if (errno) {	/* Error */
		mp->b_datap->db_type = M_IOCNAK;
		iocp->ioc_rval = FAILURE;

		OPLMSU_TRACE(q, mp, MSU_TRC_UO);
		qreply(q, mp);
	} else {	/* Good */
		mp->b_datap->db_type = M_IOCACK;
		iocp->ioc_rval = SUCCESS;

		OPLMSU_TRACE(q, mp, MSU_TRC_UO);
		qreply(q, mp);
	}
}

/*
 * Delete all upath_t
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : M [RW_WRITER]
 *  -. uinst_t->u_lock : M
 *  -. uinst_t->l_lock : A
 *  -. uinst_t->c_lock : A
 */
void
oplmsu_delete_upath_info(void)
{
	upath_t	*upath, *next_upath;

	ASSERT(RW_WRITE_HELD(&oplmsu_uinst->lock));
	ASSERT(MUTEX_HELD(&oplmsu_uinst->u_lock));

	upath = oplmsu_uinst->first_upath;
	oplmsu_uinst->first_upath = NULL;
	oplmsu_uinst->last_upath = NULL;

	while (upath) {
		next_upath = upath->u_next;
		kmem_free(upath, sizeof (upath_t));
		upath = next_upath;
	}
}

/*
 * Set queue and ioctl to lpath_t
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : M [RW_READER or RW_WRITER]
 *  -. uinst_t->u_lock : A
 *  -. uinst_t->l_lock : M
 *  -. uinst_t->c_lock : P
 */
int
oplmsu_set_ioctl_path(lpath_t *lpath, queue_t *hndl_queue, mblk_t *mp)
{
	int	rval = SUCCESS;

	ASSERT(RW_LOCK_HELD(&oplmsu_uinst->lock));
	ASSERT(MUTEX_HELD(&oplmsu_uinst->l_lock));

	if ((lpath->hndl_uqueue == NULL) && (lpath->hndl_mp == NULL) &&
	    (lpath->sw_flag == 0)) {
		if ((lpath->status == MSU_EXT_NOTUSED) ||
		    (lpath->status == MSU_EXT_ACTIVE_CANDIDATE) ||
		    (lpath->status == MSU_SETID_NU)) {
			if (hndl_queue == NULL) {
				lpath->hndl_uqueue = hndl_queue;
			} else {
				lpath->hndl_uqueue = WR(hndl_queue);
			}
			lpath->hndl_mp = mp;
		} else {
			rval = BUSY;
		}
	} else {
		rval = BUSY;
	}
	return (rval);
}

/*
 * Clear queue and ioctl to lpath_t
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : M [RW_READER or RW_WRITER]
 *  -. uinst_t->u_lock : A
 *  -. uinst_t->l_lock : M
 *  -. uinst_t->c_lock : P
 */
void
oplmsu_clear_ioctl_path(lpath_t *lpath)
{

	ASSERT(RW_LOCK_HELD(&oplmsu_uinst->lock));
	ASSERT(MUTEX_HELD(&oplmsu_uinst->l_lock));

	lpath->hndl_uqueue = NULL;
	lpath->hndl_mp = NULL;
}

/*
 * Get instanse status from status of upath_t
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : M [RW_READER or RW_WRITER]
 *  -. uinst_t->u_lock : M
 *  -. uinst_t->l_lock : A
 *  -. uinst_t->c_lock : P
 */
int
oplmsu_get_inst_status(void)
{
	upath_t	*upath;
	int	sts, pre_sts = INST_STAT_UNCONFIGURED;

	ASSERT(RW_LOCK_HELD(&oplmsu_uinst->lock));
	ASSERT(MUTEX_HELD(&oplmsu_uinst->u_lock));

	upath = oplmsu_uinst->first_upath;
	while (upath) {
		if (((upath->status == MSU_PSTAT_ACTIVE) &&
		    (upath->traditional_status == MSU_ACTIVE)) ||
		    ((upath->status == MSU_PSTAT_STANDBY) &&
		    (upath->traditional_status == MSU_STANDBY))) {
			sts = INST_STAT_ONLINE;
		} else if (((upath->status == MSU_PSTAT_STOP) &&
		    (upath->traditional_status == MSU_STOP)) ||
		    ((upath->status == MSU_PSTAT_FAIL) &&
		    (upath->traditional_status == MSU_FAIL))) {
			sts = INST_STAT_OFFLINE;
		} else if (((upath->status == MSU_PSTAT_DISCON) &&
		    (upath->traditional_status == MSU_DISCON)) ||
		    ((upath->status == MSU_PSTAT_EMPTY) &&
		    (upath->traditional_status == MSU_EMPTY))) {
			sts = INST_STAT_UNCONFIGURED;
		} else {
			sts = INST_STAT_BUSY;
		}

		if (pre_sts > sts) {
			pre_sts = sts;
		}
		upath = upath->u_next;
	}
	return (pre_sts);
}

/*
 * Search path of "online:standby" status
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : M [RW_READER or RW_WRITER]
 *  -. uinst_t->u_lock : M
 *  -. uinst_t->l_lock : A
 *  -. uinst_t->c_lock : P
 */
upath_t	*
oplmsu_search_standby(void)
{
	upath_t	*upath, *altn_upath = NULL;
	int	max_pathnum = UNDEFINED;

	ASSERT(RW_LOCK_HELD(&oplmsu_uinst->lock));
	ASSERT(MUTEX_HELD(&oplmsu_uinst->u_lock));

	upath = oplmsu_uinst->first_upath;
	while (upath) {
		if ((upath->status == MSU_PSTAT_STANDBY) &&
		    (upath->traditional_status == MSU_STANDBY) &&
		    (upath->lpath != NULL)) {
			if ((max_pathnum == UNDEFINED) ||
			    (max_pathnum > upath->path_no)) {
				max_pathnum = upath->path_no;
				altn_upath = upath;
			}
		}
		upath = upath->u_next;
	}
	return (altn_upath);
}

/*
 * Search path of "offline:stop" status, and minimum path number
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : M [RW_READER or RW_WRITER]
 *  -. uinst_t->u_lock : M
 *  -. uinst_t->l_lock : P
 *  -. uinst_t->c_lock : P
 */
void
oplmsu_search_min_stop_path(void)
{
	upath_t	*upath, *min_upath;
	lpath_t	*lpath;
	int	min_no = UNDEFINED;
	int	active_flag = 0;

	ASSERT(RW_LOCK_HELD(&oplmsu_uinst->lock));
	ASSERT(MUTEX_HELD(&oplmsu_uinst->u_lock));

	upath = oplmsu_uinst->first_upath;
	while (upath) {
		if ((upath->status == MSU_PSTAT_ACTIVE) &&
		    (upath->traditional_status == MSU_ACTIVE)) {
			active_flag = 1;
			break;
		} else if ((upath->status == MSU_PSTAT_STOP) &&
		    (upath->traditional_status == MSU_STOP)) {
			if (upath->lpath != NULL) {
				if ((min_no == UNDEFINED) ||
				    (upath->path_no < min_no)) {
					lpath = upath->lpath;
					mutex_enter(&oplmsu_uinst->l_lock);
					if (lpath->status == MSU_EXT_NOTUSED) {
						min_upath = upath;
						min_no = upath->path_no;
					}
					mutex_exit(&oplmsu_uinst->l_lock);
				}
			}
		}
		upath = upath->u_next;
	}

	if (active_flag == 0) {
		lpath = min_upath->lpath;
		mutex_enter(&oplmsu_uinst->l_lock);
		lpath->src_upath = NULL;
		lpath->status = MSU_EXT_ACTIVE_CANDIDATE;
		mutex_exit(&oplmsu_uinst->l_lock);
	}
}

/*
 * Get the total number of serial paths
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : M [RW_WRITER]
 *  -. uinst_t->u_lock : M
 *  -. uinst_t->l_lock : A
 *  -. uinst_t->c_lock : A
 */
int
oplmsu_get_pathnum(void)
{
	upath_t	*upath;
	int	total_num = 0;

	ASSERT(RW_WRITE_HELD(&oplmsu_uinst->lock));
	ASSERT(MUTEX_HELD(&oplmsu_uinst->u_lock));

	if (oplmsu_uinst->first_upath != NULL) {
		upath = oplmsu_uinst->first_upath;
		while (upath) {
			total_num++;
			upath = upath->u_next;
		}
	}
	return (total_num);
}

/*
 * Put XOFF/ XON message on write queue
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : M [RW_READER or RW_WRITER]
 *  -. uinst_t->u_lock : A
 *  -. uinst_t->l_lock : A
 *  -. uinst_t->c_lock : A
 */
int
oplmsu_cmn_put_xoffxon(queue_t *queue, int data)
{
	mblk_t	*mp;
	int	rval = SUCCESS;

	/* Send M_START */
	if ((mp = allocb(0, BPRI_LO)) != NULL) {
		mp->b_datap->db_type = M_START;
		(void) putq(queue, mp);

		/* Send M_DATA(XOFF, XON) */
		if ((mp = allocb(sizeof (int), BPRI_LO)) != NULL) {
			*(uint_t *)mp->b_rptr = data;
			mp->b_wptr = mp->b_rptr + sizeof (int);
			(void) putq(queue, mp);
		} else {
			rval = FAILURE;
		}
	} else {
		rval = FAILURE;
	}
	return (rval);
}

/*
 * Put XOFF message on write queue for all standby paths
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : M [RW_READER or RW_WRITER]
 *  -. uinst_t->u_lock : M
 *  -. uinst_t->l_lock : M
 *  -. uinst_t->c_lock : P
 */
void
oplmsu_cmn_putxoff_standby(void)
{
	upath_t	*upath;
	lpath_t	*lpath;

	ASSERT(RW_LOCK_HELD(&oplmsu_uinst->lock));
	ASSERT(MUTEX_HELD(&oplmsu_uinst->u_lock));
	ASSERT(MUTEX_HELD(&oplmsu_uinst->l_lock));

	upath = oplmsu_uinst->first_upath;
	while (upath) {
		lpath = upath->lpath;
		if ((upath->status != MSU_PSTAT_STANDBY) ||
		    (lpath == NULL)) {
			upath = upath->u_next;
			continue;
		}

		(void) oplmsu_cmn_put_xoffxon(
		    WR(lpath->lower_queue), MSU_XOFF_4);
		upath = upath->u_next;
	}
}

/*
 * Set M_FLUSH message
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : A [RW_READER or RW_WRITER]
 *  -. uinst_t->u_lock : A
 *  -. uinst_t->l_lock : A
 *  -. uinst_t->c_lock : A
 */
void
oplmsu_cmn_set_mflush(mblk_t *mp)
{

	mp->b_datap->db_type = M_FLUSH;
	*mp->b_rptr = FLUSHW;
	mp->b_wptr = mp->b_rptr + sizeof (char);
}

/*
 * Set status informations of upath_t
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : M [RW_READER or RW_WRITER]
 *  -. uinst_t->u_lock : M
 *  -. uinst_t->l_lock : A
 *  -. uinst_t->c_lock : A
 */
void
oplmsu_cmn_set_upath_sts(upath_t *upath, int sts, int prev_sts,
    ulong_t trad_sts)
{

	ASSERT(RW_LOCK_HELD(&oplmsu_uinst->lock));
	ASSERT(MUTEX_HELD(&oplmsu_uinst->u_lock));

	upath->status = sts;
	upath->prev_status = prev_sts;
	upath->traditional_status = trad_sts;
}

/*
 * Allocate a message block
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : M [RW_READER]
 *  -. uinst_t->u_lock : A
 *  -. uinst_t->l_lock : P
 *  -. uinst_t->c_lock : P
 */
int
oplmsu_cmn_allocmb(queue_t *q, mblk_t *mp, mblk_t **nmp, size_t size,
    int rw_flag)
{
	int	rval = SUCCESS;

	ASSERT(RW_READ_HELD(&oplmsu_uinst->lock));

	if ((*nmp = (mblk_t *)allocb(size, BPRI_LO)) == NULL) {
		oplmsu_cmn_bufcall(q, mp, size, rw_flag);
		rval = FAILURE;
	} else {
		(*nmp)->b_wptr = (*nmp)->b_rptr + size;
	}
	return (rval);
}

/*
 * Copy a message
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : M [RW_READER]
 *  -. uinst_t->u_lock : A
 *  -. uinst_t->l_lock : P
 *  -. uinst_t->c_lock : P
 */
int
oplmsu_cmn_copymb(queue_t *q, mblk_t *mp, mblk_t **nmp, mblk_t *cmp,
    int rw_flag)
{
	int	rval = SUCCESS;

	ASSERT(RW_READ_HELD(&oplmsu_uinst->lock));

	if ((*nmp = copymsg(cmp)) == NULL) {
		oplmsu_cmn_bufcall(q, mp, msgsize(cmp), rw_flag);
		rval = FAILURE;
	}
	return (rval);
}

/*
 * bufcall request
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : M [RW_READER]
 *  -. uinst_t->u_lock : A
 *  -. uinst_t->l_lock : P
 *  -. uinst_t->c_lock : P
 */
void
oplmsu_cmn_bufcall(queue_t *q, mblk_t *mp, size_t size, int rw_flag)
{

	ASSERT(RW_READ_HELD(&oplmsu_uinst->lock));

	if (rw_flag == MSU_WRITE_SIDE) {
		ctrl_t	*ctrl;

		(void) putbq(q, mp);

		mutex_enter(&oplmsu_uinst->c_lock);
		ctrl = (ctrl_t *)q->q_ptr;
		if (ctrl->wbuf_id != 0) {
			mutex_exit(&oplmsu_uinst->c_lock);
			return;
		}

		ctrl->wbuftbl->q = q;
		ctrl->wbuftbl->rw_flag = rw_flag;
		ctrl->wbuf_id = bufcall(size, BPRI_LO, oplmsu_cmn_bufcb,
		    (void *)ctrl->wbuftbl);

		if (ctrl->wbuf_id == 0) {
			if (ctrl->wtout_id != 0) {
				mutex_exit(&oplmsu_uinst->c_lock);
				return;
			}

			ctrl->wtout_id = timeout(oplmsu_cmn_bufcb,
			    (void *)ctrl->wbuftbl, drv_usectohz(MSU_TM_500MS));
		}
		mutex_exit(&oplmsu_uinst->c_lock);
	} else if (rw_flag == MSU_READ_SIDE) {
		lpath_t	*lpath;
		mblk_t	*wrk_msg;

		mutex_enter(&oplmsu_uinst->l_lock);
		lpath = (lpath_t *)q->q_ptr;
		if (mp->b_datap->db_type >= QPCTL) {
			if (lpath->first_lpri_hi == NULL) {
				lpath->last_lpri_hi = mp;
				mp->b_next = NULL;
			} else {
				wrk_msg = lpath->first_lpri_hi;
				wrk_msg->b_prev = mp;
				mp->b_next = wrk_msg;
			}
			mp->b_prev = NULL;
			lpath->first_lpri_hi = mp;
		} else {
			(void) putbq(q, mp);
		}

		if (lpath->rbuf_id != 0) {
			mutex_exit(&oplmsu_uinst->l_lock);
			return;
		}

		lpath->rbuftbl->q = q;
		lpath->rbuftbl->rw_flag = rw_flag;
		lpath->rbuf_id = bufcall(size, BPRI_LO, oplmsu_cmn_bufcb,
		    (void *)lpath->rbuftbl);

		if (lpath->rbuf_id == 0) {
			if (lpath->rtout_id != 0) {
				mutex_exit(&oplmsu_uinst->l_lock);
				return;
			}

			lpath->rtout_id = timeout(oplmsu_cmn_bufcb,
			    (void *)lpath->rbuftbl, drv_usectohz(MSU_TM_500MS));
		}
		mutex_exit(&oplmsu_uinst->l_lock);
	}
}

/*
 * Previous sequence for active path change
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : M [RW_READER]
 *  -. uinst_t->u_lock : A
 *  -. uinst_t->l_lock : P
 *  -. uinst_t->c_lock : P
 */
int
oplmsu_cmn_prechg(queue_t *q, mblk_t *mp, int rw_flag, mblk_t **term_mp,
    int *term_ioctl, int *term_stat)
{

	ASSERT(RW_READ_HELD(&oplmsu_uinst->lock));

	if (oplmsu_uinst->tcsets_p != NULL) {
		struct iocblk	*iocp;

		if (oplmsu_cmn_copymb(q, mp, term_mp, oplmsu_uinst->tcsets_p,
		    rw_flag) == -1) {
			return (FAILURE);
		}

		iocp = (struct iocblk *)(*term_mp)->b_rptr;
		*term_ioctl = iocp->ioc_cmd;
		*term_stat = MSU_WTCS_ACK;
	} else if (oplmsu_uinst->tiocmset_p != NULL) {
		if (oplmsu_cmn_copymb(q, mp, term_mp, oplmsu_uinst->tiocmset_p,
		    rw_flag) == -1) {
			return (FAILURE);
		}

		*term_ioctl = TIOCMSET;
		*term_stat = MSU_WTMS_ACK;
	} else if (oplmsu_uinst->tiocspps_p != NULL) {
		if (oplmsu_cmn_copymb(q, mp, term_mp, oplmsu_uinst->tiocspps_p,
		    rw_flag) == -1) {
			return (FAILURE);
		}

		*term_ioctl = TIOCSPPS;
		*term_stat = MSU_WPPS_ACK;
	} else if (oplmsu_uinst->tiocswinsz_p != NULL) {
		if (oplmsu_cmn_copymb(q, mp, term_mp,
		    oplmsu_uinst->tiocswinsz_p, rw_flag) == -1) {
			return (FAILURE);
		}

		*term_ioctl = TIOCSWINSZ;
		*term_stat = MSU_WWSZ_ACK;
	} else if (oplmsu_uinst->tiocssoftcar_p != NULL) {
		if (oplmsu_cmn_copymb(q, mp, term_mp,
		    oplmsu_uinst->tiocssoftcar_p, rw_flag) == -1) {
			return (FAILURE);
		}

		*term_ioctl = TIOCSSOFTCAR;
		*term_stat = MSU_WCAR_ACK;
	} else {
		*term_stat = MSU_WPTH_CHG;
		*term_mp = NULL;
	}
	return (SUCCESS);
}

/*
 * Pick up termios to re-set
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : M [RW_READER or RW_WRITER]
 *  -. uinst_t->u_lock : A
 *  -. uinst_t->l_lock : A
 *  -. uinst_t->c_lock : A
 */
int
oplmsu_stop_prechg(mblk_t **term_mp, int *term_ioctl, int *term_stat)
{

	ASSERT(RW_LOCK_HELD(&oplmsu_uinst->lock));

	if (oplmsu_uinst->tcsets_p != NULL) {
		struct iocblk	*iocp;

		if ((*term_mp = copymsg(oplmsu_uinst->tcsets_p)) == NULL) {
			return (FAILURE);
		}

		iocp = (struct iocblk *)(*term_mp)->b_rptr;
		*term_ioctl = iocp->ioc_cmd;
		*term_stat = MSU_WTCS_ACK;
	} else if (oplmsu_uinst->tiocmset_p != NULL) {
		if ((*term_mp = copymsg(oplmsu_uinst->tiocmset_p)) == NULL) {
			return (FAILURE);
		}

		*term_ioctl = TIOCMSET;
		*term_stat = MSU_WTMS_ACK;
	} else if (oplmsu_uinst->tiocspps_p != NULL) {
		if ((*term_mp = copymsg(oplmsu_uinst->tiocspps_p)) == NULL) {
			return (FAILURE);
		}

		*term_ioctl = TIOCSPPS;
		*term_stat = MSU_WPPS_ACK;
	} else if (oplmsu_uinst->tiocswinsz_p != NULL) {
		if ((*term_mp = copymsg(oplmsu_uinst->tiocswinsz_p)) == NULL) {
			return (FAILURE);
		}

		*term_ioctl = TIOCSWINSZ;
		*term_stat = MSU_WWSZ_ACK;
	} else if (oplmsu_uinst->tiocssoftcar_p != NULL) {
		if ((*term_mp = copymsg(oplmsu_uinst->tiocssoftcar_p))
		    == NULL) {
			return (FAILURE);
		}

		*term_ioctl = TIOCSSOFTCAR;
		*term_stat = MSU_WCAR_ACK;
	} else {
		*term_stat = MSU_WPTH_CHG;
		*term_mp = NULL;
	}
	return (SUCCESS);
}

/*
 * Previous sequence for active path change termio
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : M [RW_READER]
 *  -. uinst_t->u_lock : A
 *  -. uinst_t->l_lock : P
 *  -. uinst_t->c_lock : P
 */
int
oplmsu_cmn_prechg_termio(queue_t *q, mblk_t *mp, int rw_flag, int prev_flag,
    mblk_t **term_mp, int *term_stat)
{

	ASSERT(RW_READ_HELD(&oplmsu_uinst->lock));

	if ((prev_flag == MSU_TIOS_TCSETS) &&
	    (oplmsu_uinst->tiocmset_p != NULL)) {
		if (oplmsu_cmn_copymb(q, mp, term_mp, oplmsu_uinst->tiocmset_p,
		    rw_flag) == FAILURE) {
			return (FAILURE);
		}

		*term_stat = MSU_WTMS_ACK;
	} else if ((prev_flag <= MSU_TIOS_MSET) &&
	    (oplmsu_uinst->tiocspps_p != NULL)) {
		if (oplmsu_cmn_copymb(q, mp, term_mp, oplmsu_uinst->tiocspps_p,
		    rw_flag) == FAILURE) {
			return (FAILURE);
		}

		*term_stat = MSU_WPPS_ACK;
	} else if ((prev_flag <= MSU_TIOS_PPS) &&
	    (oplmsu_uinst->tiocswinsz_p != NULL)) {
		if (oplmsu_cmn_copymb(q, mp, term_mp,
		    oplmsu_uinst->tiocswinsz_p, rw_flag) == FAILURE) {
			return (FAILURE);
		}

		*term_stat = MSU_WWSZ_ACK;
	} else if ((prev_flag <= MSU_TIOS_WINSZP) &&
	    (oplmsu_uinst->tiocssoftcar_p != NULL)) {
		if (oplmsu_cmn_copymb(q, mp, term_mp,
		    oplmsu_uinst->tiocssoftcar_p, rw_flag) == FAILURE) {
			return (FAILURE);
		}

		*term_stat = MSU_WCAR_ACK;
	} else if (prev_flag <= MSU_TIOS_SOFTCAR) {
		*term_mp = NULL;
		*term_stat = MSU_WPTH_CHG;
	}
	return (SUCCESS);
}

/*
 * Pull up messages
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : P
 *  -. uinst_t->u_lock : P
 *  -. uinst_t->l_lock : P
 *  -. uinst_t->c_lock : P
 */
int
oplmsu_cmn_pullup_msg(queue_t *q, mblk_t *mp)
{
	mblk_t	*nmp = NULL;

	if ((mp != NULL) && (mp->b_cont != NULL) &&
	    (mp->b_cont->b_cont != NULL)) {
		if ((nmp = msgpullup(mp->b_cont, -1)) == NULL) {
			oplmsu_iocack(q, mp, ENOSR);
			return (FAILURE);
		} else {
			freemsg(mp->b_cont);
			mp->b_cont = nmp;
		}
	}
	return (SUCCESS);
}

/*
 * Wake up flow control
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : M [RW_READER or RW_WRITER]
 *  -. uinst_t->u_lock : P
 *  -. uinst_t->l_lock : P
 *  -. uinst_t->c_lock : P
 */
void
oplmsu_cmn_wakeup(queue_t *q)
{
	ctrl_t	*ctrl;

	ASSERT(RW_LOCK_HELD(&oplmsu_uinst->lock));

	mutex_enter(&oplmsu_uinst->c_lock);
	ctrl = (ctrl_t *)q->q_ptr;
	if (ctrl->sleep_flag == CV_SLEEP) {
		ctrl->sleep_flag = CV_WAKEUP;
		cv_signal(&ctrl->cvp);
	}
	mutex_exit(&oplmsu_uinst->c_lock);
}

/*
 * bufcall() and timeout() callback entry for read/write stream
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : P
 *  -. uinst_t->u_lock : P
 *  -. uinst_t->l_lock : P
 *  -. uinst_t->c_lock : P
 */
void
oplmsu_cmn_bufcb(void *arg)
{
	struct buf_tbl	*buftbl = arg;
	lpath_t		*lpath;
	ctrl_t		*ctrl;
	queue_t		*q;
	int		lq_flag = 0;

	rw_enter(&oplmsu_uinst->lock, RW_WRITER);
	mutex_enter(&oplmsu_uinst->l_lock);

	lpath = oplmsu_uinst->first_lpath;
	while (lpath) {
		if ((buftbl == lpath->rbuftbl) &&
		    (buftbl->rw_flag == MSU_READ_SIDE)) {
			if ((lpath->rbuf_id == 0) && (lpath->rtout_id == 0)) {
				mutex_exit(&oplmsu_uinst->l_lock);
				rw_exit(&oplmsu_uinst->lock);
			} else {
				q = lpath->rbuftbl->q;
				lpath->rbuftbl->q = NULL;
				lpath->rbuftbl->rw_flag = UNDEFINED;

				if (lpath->rbuf_id) {
					lpath->rbuf_id = 0;
				} else {
					lpath->rtout_id = 0;
				}
				mutex_exit(&oplmsu_uinst->l_lock);

				if (oplmsu_queue_flag == 1) {
					lq_flag = 1;
					oplmsu_queue_flag = 0;
				}

				rw_exit(&oplmsu_uinst->lock);
				oplmsu_rcmn_high_qenable(q);

				if (lq_flag == 1) {
					rw_enter(&oplmsu_uinst->lock,
					    RW_WRITER);
					oplmsu_queue_flag = 1;
					rw_exit(&oplmsu_uinst->lock);
				}
			}
			return;
		}
		lpath = lpath->l_next;
	}
	mutex_exit(&oplmsu_uinst->l_lock);

	mutex_enter(&oplmsu_uinst->c_lock);
	if ((ctrl = oplmsu_uinst->user_ctrl) != NULL) {
		if ((buftbl == ctrl->wbuftbl) &&
		    (buftbl->rw_flag == MSU_WRITE_SIDE)) {
			oplmsu_wbufcb_posthndl(ctrl);
			mutex_exit(&oplmsu_uinst->c_lock);
			rw_exit(&oplmsu_uinst->lock);
			return;
		}
	}

	if ((ctrl = oplmsu_uinst->meta_ctrl) != NULL) {
		if ((buftbl == ctrl->wbuftbl) &&
		    (buftbl->rw_flag == MSU_WRITE_SIDE)) {
			oplmsu_wbufcb_posthndl(ctrl);
			mutex_exit(&oplmsu_uinst->c_lock);
			rw_exit(&oplmsu_uinst->lock);
			return;
		}
	}
	mutex_exit(&oplmsu_uinst->c_lock);
	rw_exit(&oplmsu_uinst->lock);
}

/*
 * bufcall() or timeout() callback post handling for write stream
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : M [RW_WRITER]
 *  -. uinst_t->u_lock : P
 *  -. uinst_t->l_lock : P
 *  -. uinst_t->c_lock : M
 */
void
oplmsu_wbufcb_posthndl(ctrl_t *ctrl)
{
	queue_t	*q;
	int	lq_flag = 0;

	ASSERT(RW_WRITE_HELD(&oplmsu_uinst->lock));
	ASSERT(MUTEX_HELD(&oplmsu_uinst->c_lock));

	if ((ctrl->wbuf_id == 0) && (ctrl->wtout_id == 0)) {
		return;
	}

	q = ctrl->wbuftbl->q;
	ctrl->wbuftbl->q = NULL;
	ctrl->wbuftbl->rw_flag = UNDEFINED;
	if (ctrl->wbuf_id) {
		ctrl->wbuf_id = 0;
	} else {
		ctrl->wtout_id = 0;
	}

	if (oplmsu_queue_flag == 1) {
		lq_flag = 1;
		oplmsu_queue_flag = 0;
	}

	mutex_exit(&oplmsu_uinst->c_lock);
	oplmsu_wcmn_high_qenable(q, RW_WRITER);
	mutex_enter(&oplmsu_uinst->c_lock);

	if (lq_flag == 1) {
		oplmsu_queue_flag = 1;
	}
}

/*
 *	COMMON FUNCTIONS FOR WRITE STREAM
 */

/*
 * Check control node and driver privilege
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : M [RW_READER or RW_WRITER]
 *  -. uinst_t->u_lock : A
 *  -. uinst_t->l_lock : A
 *  -. uinst_t->c_lock : P
 */
int
oplmsu_wcmn_chknode(queue_t *q, int node, mblk_t *mp)
{
	struct iocblk	*iocp;

	ASSERT(RW_LOCK_HELD(&oplmsu_uinst->lock));

	mutex_enter(&oplmsu_uinst->c_lock);
	if (((ctrl_t *)q->q_ptr)->node_type != node) {
		mutex_exit(&oplmsu_uinst->c_lock);
		cmn_err(CE_WARN, "oplmsu: chk-node: ctrl node type = %d", node);
		return (EINVAL);
	}
	mutex_exit(&oplmsu_uinst->c_lock);

	/* Check super-user by oplmsu.conf */
	if (oplmsu_check_su != 0) {
		iocp = (struct iocblk *)mp->b_rptr;
		if (drv_priv(iocp->ioc_cr) != 0) {
			cmn_err(CE_WARN, "oplmsu: chk-node: Permission denied");
			return (EPERM);
		}
	}
	return (SUCCESS);
}

/*
 * Flush handle for write side stream
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : M [RW_READER or RW_WRITER]
 *  -. uinst_t->u_lock : P
 *  -. uinst_t->l_lock : P
 *  -. uinst_t->c_lock : P
 */
void
oplmsu_wcmn_flush_hndl(queue_t *q, mblk_t *mp, krw_t rw)
{
	queue_t	*dst_queue = NULL;

	ASSERT(RW_LOCK_HELD(&oplmsu_uinst->lock));

	if (*mp->b_rptr & FLUSHW) {	/* Write side */
		flushq(q, FLUSHDATA);
	}

	dst_queue = oplmsu_uinst->lower_queue;
	if (dst_queue == NULL) {
		if (*mp->b_rptr & FLUSHR) {
			flushq(RD(q), FLUSHDATA);
			*mp->b_rptr &= ~FLUSHW;

			rw_exit(&oplmsu_uinst->lock);
			OPLMSU_TRACE(q, mp, MSU_TRC_UO);
			qreply(q, mp);
			rw_enter(&oplmsu_uinst->lock, rw);
		} else {
			freemsg(mp);
		}
	} else {
		(void) putq(WR(dst_queue), mp);
	}
}

/*
 * Through message handle for write side stream
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : M [RW_READER or RW_WRITER]
 *  -. uinst_t->u_lock : P
 *  -. uinst_t->l_lock : P
 *  -. uinst_t->c_lock : P
 */
int
oplmsu_wcmn_through_hndl(queue_t *q, mblk_t *mp, int pri_flag, krw_t rw)
{
	queue_t	*usr_queue = NULL, *dst_queue = NULL;
	ctrl_t	*ctrl;

	ASSERT(RW_LOCK_HELD(&oplmsu_uinst->lock));

	mutex_enter(&oplmsu_uinst->c_lock);
	if ((ctrl = oplmsu_uinst->user_ctrl) != NULL) {
		usr_queue = ctrl->queue;
		mutex_exit(&oplmsu_uinst->c_lock);
	} else {
		mutex_exit(&oplmsu_uinst->c_lock);
		if (mp->b_datap->db_type == M_IOCTL) {
			rw_exit(&oplmsu_uinst->lock);
			oplmsu_iocack(q, mp, ENODEV);
			rw_enter(&oplmsu_uinst->lock, rw);
		} else {
			freemsg(mp);
		}
		return (SUCCESS);
	}

	if (oplmsu_uinst->lower_queue != NULL) {
		dst_queue = WR(oplmsu_uinst->lower_queue);
	} else {
		cmn_err(CE_WARN, "!oplmsu: through-lwq: "
		    "Active path doesn't exist");

		if (mp->b_datap->db_type == M_IOCTL) {
			rw_exit(&oplmsu_uinst->lock);
			oplmsu_iocack(q, mp, ENODEV);
			rw_enter(&oplmsu_uinst->lock, rw);
		} else {
			freemsg(mp);
		}
		return (SUCCESS);
	}

	if ((usr_queue == WR(q)) || (usr_queue == RD(q))) {
		if (pri_flag == MSU_HIGH) {
			(void) putq(dst_queue, mp);
		} else {
			if (canput(dst_queue)) {
				(void) putq(dst_queue, mp);
			} else {
				oplmsu_wcmn_norm_putbq(WR(q), mp, dst_queue);
				return (FAILURE);
			}
		}
	} else {
		cmn_err(CE_WARN, "oplmsu: through-lwq: "
		    "Inappropriate message for this node");

		if (mp->b_datap->db_type == M_IOCTL) {
			rw_exit(&oplmsu_uinst->lock);
			oplmsu_iocack(q, mp, ENODEV);
			rw_enter(&oplmsu_uinst->lock, rw);
		} else {
			freemsg(mp);
		}
	}
	return (SUCCESS);
}

/*
 * Get high priority message from buffer for upper write stream
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : M [RW_READER or RW_WRITER]
 *  -. uinst_t->u_lock : A
 *  -. uinst_t->l_lock : A
 *  -. uinst_t->c_lock : P
 */
mblk_t *
oplmsu_wcmn_high_getq(queue_t *uwq)
{
	mblk_t	*mp;
	ctrl_t	*ctrl;

	ASSERT(RW_LOCK_HELD(&oplmsu_uinst->lock));

	mutex_enter(&oplmsu_uinst->c_lock);
	ctrl = (ctrl_t *)uwq->q_ptr;
	mp = ctrl->first_upri_hi;
	if (mp != NULL) {
		if (mp->b_next == NULL) {
			ctrl->first_upri_hi = NULL;
			ctrl->last_upri_hi = NULL;
		} else {
			ctrl->first_upri_hi = mp->b_next;
			mp->b_next->b_prev = NULL;
			mp->b_next = NULL;
		}
		mp->b_prev = NULL;
	}
	mutex_exit(&oplmsu_uinst->c_lock);
	return (mp);
}

/*
 * putbq() function for normal priority message of write stream
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : M [RW_READER or RW_WRITER]
 *  -. uinst_t->u_lock : A
 *  -. uinst_t->l_lock : P
 *  -. uinst_t->c_lock : P
 */
void
oplmsu_wcmn_norm_putbq(queue_t *uwq, mblk_t *mp, queue_t *dq)
{
	lpath_t	*lpath;

	ASSERT(mp != NULL);
	ASSERT(RW_LOCK_HELD(&oplmsu_uinst->lock));

	mutex_enter(&oplmsu_uinst->l_lock);
	lpath = (lpath_t *)dq->q_ptr;
	lpath->uwq_flag = 1;
	lpath->uwq_queue = uwq;
	mutex_exit(&oplmsu_uinst->l_lock);
	(void) putbq(uwq, mp);
}

/*
 * Restart queuing for high priority message of write stream when flow control
 * failed
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : M [RW_READER or RW_WRITER]
 *  -. uinst_t->u_lock : P
 *  -. uinst_t->l_lock : P
 *  -. uinst_t->c_lock : P
 */
void
oplmsu_wcmn_high_qenable(queue_t *q, krw_t rw)
{
	mblk_t	*mp;

	ASSERT(RW_LOCK_HELD(&oplmsu_uinst->lock));

	if (oplmsu_queue_flag == 1) {
		return;
	}

	/* Handle high priority message */
	while (mp = oplmsu_wcmn_high_getq(WR(q))) {
		if (mp->b_datap->db_type & M_FLUSH) {
			oplmsu_wcmn_flush_hndl(q, mp, rw);
			continue;
		}

		if (oplmsu_wcmn_through_hndl(q, mp, MSU_HIGH, rw) == FAILURE) {
			return;
		}
	}
	qenable(WR(q));	/* enable upper write queue */
}

/*
 *	COMMON FUNCTIONS FOR READ STREAM
 */

/*
 * Flush handle for read side stream
 *
 * Requires lock ( M: mandatory  P: prohibited  A: allowed
 *  -. uinst_t->lock   : M [RW_READER]
 *  -. uinst_t->u_lock : P
 *  -. uinst_t->l_lock : P
 *  -. uinst_t->c_lock : P
 */
void
oplmsu_rcmn_flush_hndl(queue_t *q, mblk_t *mp)
{
	queue_t	*dst_queue = NULL;
	ctrl_t	*ctrl;

	ASSERT(RW_READ_HELD(&oplmsu_uinst->lock));

	if (*mp->b_rptr & FLUSHR) {
		/* Remove only data messages from read queue */
		flushq(q, FLUSHDATA);
	}

	mutex_enter(&oplmsu_uinst->c_lock);
	if ((ctrl = oplmsu_uinst->user_ctrl) != NULL) {
		dst_queue = RD(ctrl->queue);
		mutex_exit(&oplmsu_uinst->c_lock);

		if (dst_queue != NULL) {
			(void) putq(dst_queue, mp);
		} else {
			if (*mp->b_rptr & FLUSHW) {
				flushq(WR(q), FLUSHDATA);
				*mp->b_rptr &= ~FLUSHR;

				rw_exit(&oplmsu_uinst->lock);
				OPLMSU_TRACE(q, mp, MSU_TRC_LO);
				qreply(q, mp);
				rw_enter(&oplmsu_uinst->lock, RW_READER);
			} else {
				freemsg(mp);
			}
		}
	} else {
		mutex_exit(&oplmsu_uinst->c_lock);
		if (*mp->b_rptr & FLUSHW) {
			flushq(WR(q), FLUSHDATA);
			*mp->b_rptr &= ~FLUSHR;

			rw_exit(&oplmsu_uinst->lock);
			OPLMSU_TRACE(q, mp, MSU_TRC_LO);
			qreply(q, mp);
			rw_enter(&oplmsu_uinst->lock, RW_READER);
		} else {
			freemsg(mp);
		}
	}
}

/*
 * Through message handle for read side stream
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : M [RW_READER]
 *  -. uinst_t->u_lock : A
 *  -. uinst_t->l_lock : P
 *  -. uinst_t->c_lock : P
 */
int
oplmsu_rcmn_through_hndl(queue_t *q, mblk_t *mp, int pri_flag)
{
	lpath_t	*lpath;
	ctrl_t	*ctrl;
	queue_t	*dst_queue = NULL;
	int	act_flag;

	ASSERT(RW_READ_HELD(&oplmsu_uinst->lock));

	mutex_enter(&oplmsu_uinst->l_lock);
	lpath = (lpath_t *)q->q_ptr;
	if (lpath->uinst != NULL) {
		act_flag = ACTIVE_RES;
	} else {
		act_flag = NOT_ACTIVE_RES;
	}
	mutex_exit(&oplmsu_uinst->l_lock);

	mutex_enter(&oplmsu_uinst->c_lock);
	if (((ctrl = oplmsu_uinst->user_ctrl) != NULL) &&
	    (((mp->b_datap->db_type == M_IOCACK) ||
	    (mp->b_datap->db_type == M_IOCNAK)) || (act_flag == ACTIVE_RES))) {
		dst_queue = RD(ctrl->queue);
	} else {
		mutex_exit(&oplmsu_uinst->c_lock);
		freemsg(mp);
		return (SUCCESS);
	}

	if (pri_flag == MSU_HIGH) {
		(void) putq(dst_queue, mp);
	} else {
		if (canput(dst_queue)) {
			(void) putq(dst_queue, mp);
		} else {
			/*
			 * Place a normal priority message at the head of
			 * read queue
			 */

			ctrl = (ctrl_t *)dst_queue->q_ptr;
			ctrl->lrq_flag = 1;
			ctrl->lrq_queue = q;
			mutex_exit(&oplmsu_uinst->c_lock);
			(void) putbq(q, mp);
			return (FAILURE);
		}
	}
	mutex_exit(&oplmsu_uinst->c_lock);
	return (SUCCESS);
}

/*
 * Restart queuing for high priority message of read stream
 * when flow control failed
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : P
 *  -. uinst_t->u_lock : P
 *  -. uinst_t->l_lock : P
 *  -. uinst_t->c_lock : P
 */
void
oplmsu_rcmn_high_qenable(queue_t *q)
{
	mblk_t		*mp;
	struct iocblk	*iocp = NULL;
	lpath_t		*lpath;
	int		rval;

	rw_enter(&oplmsu_uinst->lock, RW_READER);

	for (;;) {	/* Handle high priority message */
		mutex_enter(&oplmsu_uinst->l_lock);
		lpath = (lpath_t *)q->q_ptr;
		if ((mp = lpath->first_lpri_hi) == NULL) {
			mutex_exit(&oplmsu_uinst->l_lock);
			break;
		}

		if (mp->b_next == NULL) {
			lpath->first_lpri_hi = NULL;
			lpath->last_lpri_hi = NULL;
		} else {
			lpath->first_lpri_hi = mp->b_next;
			mp->b_next->b_prev = NULL;
			mp->b_next = NULL;
		}
		mp->b_prev = NULL;
		mutex_exit(&oplmsu_uinst->l_lock);

		rval = SUCCESS;
		switch (mp->b_datap->db_type) {
		case M_IOCACK :		/* FALLTHRU */
		case M_IOCNAK :
			iocp = (struct iocblk *)mp->b_rptr;
			switch (iocp->ioc_cmd) {
			case TCSETS :		/* FALLTHRU */
			case TCSETSW :		/* FALLTHRU */
			case TCSETSF :		/* FALLTHRU */
			case TIOCMSET :		/* FALLTHRU */
			case TIOCSPPS :		/* FALLTHRU */
			case TIOCSWINSZ :	/* FALLTHRU */
			case TIOCSSOFTCAR :
				rw_exit(&oplmsu_uinst->lock);
				rval = oplmsu_lrioctl_termios(q, mp);
				rw_enter(&oplmsu_uinst->lock, RW_WRITER);
				break;

			default :
				rval = oplmsu_rcmn_through_hndl(
				    q, mp, MSU_HIGH);
				if (rval == FAILURE) {
					rw_exit(&oplmsu_uinst->lock);
					return;
				}
			}
			break;

		case M_ERROR :
			rw_exit(&oplmsu_uinst->lock);
			rval = oplmsu_lrmsg_error(q, mp);
			rw_enter(&oplmsu_uinst->lock, RW_WRITER);
			break;

		case M_FLUSH :
			oplmsu_rcmn_flush_hndl(q, mp);
			break;

		default :
			rval = oplmsu_rcmn_through_hndl(q, mp, MSU_HIGH);
			if (rval == FAILURE) {
				rw_exit(&oplmsu_uinst->lock);
				return;
			}
		}

		if (rval == FAILURE) {
			break;
		}
	}

	rw_exit(&oplmsu_uinst->lock);
	qenable(q);	/* Enable lower read queue */
}

#ifdef DEBUG
/*
 * Online trace
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : P
 *  -. uinst_t->u_lock : P
 *  -. uinst_t->l_lock : P
 *  -. uinst_t->c_lock : P
 */
void
oplmsu_cmn_trace(queue_t *q, mblk_t *mp, int op)
{
	struct iocblk	*iocp;

	if ((op < MSU_TRC_UI) || (op > MSU_TRC_CLS)) {
		return;
	}

	mutex_enter(&oplmsu_ltrc_lock);

	if (oplmsu_debug_mode & MSU_DPRINT_ON) {
		oplmsu_cmn_msglog(mp, op);
	}

	/* Trace current counter */
	(void) drv_getparm(LBOLT, (void *)&oplmsu_ltrc_ccnt);

	if (oplmsu_ltrc_cur == oplmsu_ltrc_tail) {
		oplmsu_ltrc_cur = oplmsu_ltrc_top;
	} else {
		oplmsu_ltrc_cur++;
	}
	oplmsu_ltrc_cur->q = q;
	oplmsu_ltrc_cur->mp = mp;

	switch (op) {
	case MSU_TRC_UI :
		oplmsu_ltrc_cur->op[0] = 'u';
		oplmsu_ltrc_cur->op[1] = 'i';
		break;

	case MSU_TRC_UO :
		oplmsu_ltrc_cur->op[0] = 'u';
		oplmsu_ltrc_cur->op[1] = 'o';
		break;

	case MSU_TRC_LI :
		oplmsu_ltrc_cur->op[0] = 'l';
		oplmsu_ltrc_cur->op[1] = 'i';
		break;

	case MSU_TRC_LO :
		oplmsu_ltrc_cur->op[0] = 'l';
		oplmsu_ltrc_cur->op[1] = 'o';
		break;

	case MSU_TRC_OPN :
		oplmsu_ltrc_cur->op[0] = 'o';
		oplmsu_ltrc_cur->op[1] = 'p';
		break;

	case MSU_TRC_CLS :
		oplmsu_ltrc_cur->op[0] = 'c';
		oplmsu_ltrc_cur->op[1] = 'l';
		break;
	}

	if ((op == MSU_TRC_LI) || (op == MSU_TRC_LO)) {
		mutex_enter(&oplmsu_uinst->l_lock);
		oplmsu_ltrc_cur->pathno = ((lpath_t *)q->q_ptr)->path_no;
		mutex_exit(&oplmsu_uinst->l_lock);
	} else {
		oplmsu_ltrc_cur->pathno = 0;
	}

	if ((op == MSU_TRC_OPN) || (op == MSU_TRC_CLS)) {
		oplmsu_ltrc_cur->msg_type = 0;
		oplmsu_ltrc_cur->msg_cmd = 0;
		oplmsu_ltrc_cur->data = 0;

		switch ((ulong_t)mp) {
		case MSU_NODE_USER :
			oplmsu_ltrc_cur->data = MSU_TRC_USER;
			break;

		case MSU_NODE_META :
			oplmsu_ltrc_cur->data = MSU_TRC_META;
			break;
		}
		oplmsu_ltrc_cur->mp = NULL;
	} else {
		oplmsu_ltrc_cur->msg_type = mp->b_datap->db_type;
		iocp = (struct iocblk *)mp->b_rptr;
		oplmsu_ltrc_cur->msg_cmd = iocp->ioc_cmd;

		if ((mp->b_datap->db_type == M_IOCTL) ||
		    (mp->b_datap->db_type == M_IOCACK) ||
		    (mp->b_datap->db_type == M_IOCNAK)) {
			oplmsu_ltrc_cur->msg_cmd = iocp->ioc_cmd;

			if (mp->b_cont != NULL) {
				oplmsu_ltrc_cur->data =
				    (ulong_t)mp->b_cont->b_rptr;
			} else {
				oplmsu_ltrc_cur->data = 0;
			}
		} else {
			oplmsu_ltrc_cur->msg_cmd = 0;

			if (mp->b_rptr == NULL) {
				oplmsu_ltrc_cur->data = 0;
			} else {
				oplmsu_ltrc_cur->data = *(ulong_t *)mp->b_rptr;
			}
		}
	}
	mutex_exit(&oplmsu_ltrc_lock);
}

/*
 * Display message log to console
 *
 * Requires Lock (( M: Mandatory, P: Prohibited, A: Allowed ))
 *  -. uinst_t->lock   : P
 *  -. uinst_t->u_lock : P
 *  -. uinst_t->l_lock : P
 *  -. uinst_t->c_lock : P
 */
void
oplmsu_cmn_msglog(mblk_t *mp, int direction)
{
	uchar_t	*cur = NULL;
	mblk_t	*tmp_mp = NULL;
	ulong_t	len;
	ulong_t	line;
	ulong_t	col;
	ulong_t	row;
	ulong_t	count;
	char	buffer[70];
	char	*bufp;

	if (mp == NULL) {
		return;
	}

	switch (direction) {
	case 0:
		cmn_err(CE_NOTE, "!---------- Upper in --------");
		break;

	case 1:
		cmn_err(CE_NOTE, "!---------- Upper out -------");
		break;

	case 2:
		cmn_err(CE_NOTE, "!---------- Lower in --------");
		break;

	case 3:
		cmn_err(CE_NOTE, "!---------- Lower out -------");
		break;

	default:
		return;
	}

	for (tmp_mp = mp; tmp_mp; tmp_mp = tmp_mp->b_cont) {
		cmn_err(CE_NOTE, "!db_type = 0x%02x", tmp_mp->b_datap->db_type);

		len = tmp_mp->b_wptr - tmp_mp->b_rptr;
		line = (len + 31) / 32;
		cur = (uchar_t *)tmp_mp->b_rptr;
		count = 0;

		for (col = 0; col < line; col++) {
			bufp = buffer;

			for (row = 0; row < 32; row++) {
				if (row != 0 && (row % 8) == 0) {
					*bufp = ' ';
					bufp++;
				}
				(void) sprintf(bufp, "%02x", *cur);
				bufp += 2;
				cur++;
				count++;

				if (count >= len) {
					break;
				}
			}
			*bufp = '\0';
			cmn_err(CE_NOTE, "!%s", buffer);

			if (count >= len) {
				break;
			}
		}
	}
}

void
oplmsu_cmn_prt_pathname(dev_info_t *dip)
{
	char	pathname[128];
	char	wrkbuf[128];

	(void) ddi_pathname(dip, wrkbuf);
	*(wrkbuf + strlen(wrkbuf)) = '\0';
	(void) sprintf(pathname, "/devices%s:%c", wrkbuf,
	    'a'+ ddi_get_instance(dip));

	DBG_PRINT((CE_NOTE, "oplmsu: debug-info: "
	    "Active path change to path => %s", pathname));
}
#endif
