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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/file.h>
#include <sys/user.h>
#include <sys/uio.h>
#include <sys/t_lock.h>
#include <sys/buf.h>
#include <sys/dkio.h>
#include <sys/vtoc.h>
#include <sys/kmem.h>
#include <vm/page.h>
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/stat.h>
#include <sys/open.h>
#include <sys/disp.h>
#include <sys/lvm/md_mirror.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/debug.h>
#include <sys/callb.h>

#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/svm.h>
#include <sys/lvm/mdmn_commd.h>

extern int		md_status;
extern kmutex_t		md_status_mx;
extern kmutex_t		md_mx;

extern unit_t		md_nunits;
extern set_t		md_nsets;
extern md_set_t		md_set[];
extern major_t		md_major;

extern md_ops_t		mirror_md_ops;
extern kmem_cache_t	*mirror_child_cache; /* mirror child memory pool */
extern mdq_anchor_t	md_mto_daemon;
extern daemon_request_t	mirror_timeout;
extern md_resync_t	md_cpr_resync;
extern clock_t		md_hz;
extern int		md_mtioctl_cnt;

extern kmem_cache_t	*mirror_parent_cache;
#ifdef DEBUG
extern int		mirror_debug_flag;
#endif

/*
 * Tunable resync thread timeout. This is used as the time interval for updating
 * the resync progress to the mddb. This allows restartable resyncs to be
 * continued across a system reboot.
 * Default is to update the resync progress every 5 minutes.
 */
int md_mirror_resync_update_intvl = MD_DEF_MIRROR_RESYNC_INTVL;

/*
 * Settable mirror resync buffer size.  Specified in 512 byte
 * blocks.  This is set to MD_DEF_RESYNC_BUF_SIZE by default.
 */
int md_resync_bufsz = MD_DEF_RESYNC_BUF_SIZE;

/*
 * Tunables for dirty region processing when
 * closing down a mirror.
 *
 * Dirty region processing during close of a
 * mirror is basically monitoring the state
 * of the resync region bitmaps and the number
 * of outstanding i/o's per submirror to
 * determine that there are no more dirty
 * regions left over.
 *
 * The approach taken is a retry logic over
 * md_mirror_rr_cleans iterations to monitor
 * the progress.
 *
 * There are two methods of polling the progress
 * on dirty bitmap processing: busy-waits and
 * non-busy-waits.
 *
 * Busy-waits are used at the beginning to
 * determine the final state as quick as
 * possible; md_mirror_rr_polls defines the
 * number of busy-waits.
 *
 * In case the number of busy-waits got exhausted
 * with dirty regions left over, the retry logic
 * switches over to non-busy-waits, thus giving
 * relief to an obviously heavily loaded system.
 * The timeout value is defined by the tunable
 * md_mirror_rr_sleep_timo in seconds.
 *
 * The number of non-busy-waits is given by:
 * md_mirror_rr_cleans - md_mirror_rr_polls.
 *
 * The values were found by testing on a
 * 'typical' system and may require tuning
 * to meet specific customer's requirements.
 */

int md_mirror_rr_cleans = 13;
int md_mirror_rr_polls = 3;
int md_mirror_rr_sleep_timo = 1;

/*
 * The value is not #defined because it will be computed
 * in the future.
 */
int md_max_xfer_bufsz = 2048;

/*
 * mirror_generate_rr_bitmap:
 * -------------------
 * Generate a compressed bitmap md_mn_msg_rr_clean_t for the given clean
 * bitmap associated with mirror 'un'
 *
 * Input:
 *      un      - mirror unit to get bitmap data from
 *      *msgp   - location to return newly allocated md_mn_msg_rr_clean_t
 *      *activep- location to return # of active i/os
 *
 * Returns:
 *      1 => dirty bits cleared from un_dirty_bm and DRL flush required
 *          *msgp contains bitmap of to-be-cleared bits
 *      0 => no bits cleared
 *          *msgp == NULL
 */
static int
mirror_generate_rr_bitmap(mm_unit_t *un, md_mn_msg_rr_clean_t **msgp,
    int *activep)
{
	unsigned int	i, next_bit, data_bytes, start_bit;
	int		cleared_dirty = 0;

	/* Skip any initial 0s. */
retry_dirty_scan:
	if ((start_bit = un->un_rr_clean_start_bit) >= un->un_rrd_num)
		un->un_rr_clean_start_bit = start_bit = 0;

	/*
	 * Handle case where NO bits are set in PERNODE_DIRTY but the
	 * un_dirty_bm[] map does have entries set (after a 1st resync)
	 */
	for (; start_bit < un->un_rrd_num &&
	    !IS_PERNODE_DIRTY(md_mn_mynode_id, start_bit, un) &&
	    (un->un_pernode_dirty_sum[start_bit] != (uchar_t)0); start_bit++)
		;

	if (start_bit >= un->un_rrd_num) {
		if (un->un_rr_clean_start_bit == 0) {
			return (0);
		} else {
			un->un_rr_clean_start_bit = 0;
			goto retry_dirty_scan;
		}
	}

	/* how much to fit into this message */
	data_bytes = MIN(howmany(un->un_rrd_num - start_bit, NBBY),
	    MDMN_MSG_RR_CLEAN_DATA_MAX_BYTES);

	(*msgp) = kmem_zalloc(MDMN_MSG_RR_CLEAN_SIZE_DATA(data_bytes),
	    KM_SLEEP);

	(*msgp)->rr_nodeid = md_mn_mynode_id;
	(*msgp)->rr_mnum = MD_SID(un);
	MDMN_MSG_RR_CLEAN_START_SIZE_SET(*msgp, start_bit, data_bytes);

	next_bit = MIN(start_bit + data_bytes * NBBY, un->un_rrd_num);

	for (i = start_bit; i < next_bit; i++) {
		if (un->c.un_status & MD_UN_KEEP_DIRTY && IS_KEEPDIRTY(i, un)) {
			continue;
		}
		if (!IS_REGION_DIRTY(i, un)) {
			continue;
		}
		if (un->un_outstanding_writes[i] != 0) {
			(*activep)++;
			continue;
		}

		/*
		 * Handle the case where a resync has completed and we still
		 * have the un_dirty_bm[] entries marked as dirty (these are
		 * the most recent DRL re-read from the replica). They need
		 * to be cleared from our un_dirty_bm[] but they will not have
		 * corresponding un_pernode_dirty[] entries set unless (and
		 * until) further write()s have been issued to the area.
		 * This handles the case where only the un_dirty_bm[] entry is
		 * set. Without this we'd not clear this region until a local
		 * write is issued to the affected area.
		 */
		if (IS_PERNODE_DIRTY(md_mn_mynode_id, i, un) ||
		    (un->un_pernode_dirty_sum[i] == (uchar_t)0)) {
			if (!IS_GOING_CLEAN(i, un)) {
				SET_GOING_CLEAN(i, un);
				(*activep)++;
				continue;
			}
			/*
			 * Now we've got a flagged pernode_dirty, _or_ a clean
			 * bitmap entry to process. Update the bitmap to flush
			 * the REGION_DIRTY / GOING_CLEAN bits when we send the
			 * cross-cluster message.
			 */
			cleared_dirty++;
			setbit(MDMN_MSG_RR_CLEAN_DATA(*msgp), i - start_bit);
		} else {
			/*
			 * Not marked as active in the pernode bitmap, so skip
			 * any update to this. We just increment the 0 count
			 * and adjust the active count by any outstanding
			 * un_pernode_dirty_sum[] entries. This means we don't
			 * leave the mirror permanently dirty.
			 */
			(*activep) += (int)un->un_pernode_dirty_sum[i];
		}
	}
	if (!cleared_dirty) {
		kmem_free(*msgp, MDMN_MSG_RR_CLEAN_SIZE_DATA(data_bytes));
		*msgp = NULL;
	}
	un->un_rr_clean_start_bit = next_bit;
	return (cleared_dirty);
}

/*
 * There are three paths into here:
 *
 * md_daemon -> check_resync_regions -> prr
 * mirror_internal_close -> mirror_process_unit_resync -> prr
 * mirror_set_capability -> mirror_process_unit_resync -> prr
 *
 * The first one is a kernel daemon, the other two result from system calls.
 * Thus, only the first case needs to deal with kernel CPR activity.  This
 * is indicated by the cprinfop being non-NULL for kernel daemon calls, and
 * NULL for system call paths.
 */
static int
process_resync_regions_non_owner(mm_unit_t *un, callb_cpr_t *cprinfop)
{
	int			i, start, end;
	int			cleared_dirty = 0;
	/* Number of reasons why we can not proceed shutting down the mirror. */
	int			active = 0;
	set_t			setno = MD_UN2SET(un);
	md_mn_msg_rr_clean_t	*rmsg;
	md_mn_kresult_t		*kres;
	int			rval;
	minor_t			mnum = MD_SID(un);
	mdi_unit_t		*ui = MDI_UNIT(mnum);
	md_mn_nodeid_t		owner_node;

	/*
	 * We drop the readerlock here to assist lock ordering with
	 * update_resync.  Once we have the un_rrp_inflight_mx, we
	 * can re-acquire it.
	 */
	md_unit_readerexit(ui);

	/*
	 * Resync region processing must be single threaded. We can't use
	 * un_resync_mx for this purpose since this mutex gets released
	 * when blocking on un_resync_cv.
	 */
	mutex_enter(&un->un_rrp_inflight_mx);

	(void) md_unit_readerlock(ui);

	mutex_enter(&un->un_resync_mx);

	rw_enter(&un->un_pernode_dirty_mx[md_mn_mynode_id - 1], RW_READER);
	cleared_dirty = mirror_generate_rr_bitmap(un, &rmsg, &active);
	rw_exit(&un->un_pernode_dirty_mx[md_mn_mynode_id - 1]);

	if (cleared_dirty) {
		owner_node = un->un_mirror_owner;
		mutex_exit(&un->un_resync_mx);

		/*
		 * Transmit the 'to-be-cleared' bitmap to all cluster nodes.
		 * Receipt of the message will cause the mirror owner to
		 * update the on-disk DRL.
		 */

		kres = kmem_alloc(sizeof (md_mn_kresult_t), KM_SLEEP);

		/* release readerlock before sending message */
		md_unit_readerexit(ui);

		if (cprinfop) {
			mutex_enter(&un->un_prr_cpr_mx);
			CALLB_CPR_SAFE_BEGIN(cprinfop);
		}

		rval = mdmn_ksend_message(setno, MD_MN_MSG_RR_CLEAN,
		    MD_MSGF_NO_LOG|MD_MSGF_BLK_SIGNAL|MD_MSGF_KSEND_NORETRY|
		    MD_MSGF_DIRECTED, un->un_mirror_owner,
		    (char *)rmsg, MDMN_MSG_RR_CLEAN_MSG_SIZE(rmsg), kres);

		if (cprinfop) {
			CALLB_CPR_SAFE_END(cprinfop, &un->un_prr_cpr_mx);
			mutex_exit(&un->un_prr_cpr_mx);
		}

		/* reacquire readerlock after message */
		(void) md_unit_readerlock(ui);

		if ((!MDMN_KSEND_MSG_OK(rval, kres)) &&
		    (kres->kmmr_comm_state != MDMNE_NOT_JOINED)) {
			/* if commd is gone, no point in printing a message */
			if (md_mn_is_commd_present())
				mdmn_ksend_show_error(rval, kres, "RR_CLEAN");
			kmem_free(kres, sizeof (md_mn_kresult_t));
			kmem_free(rmsg, MDMN_MSG_RR_CLEAN_MSG_SIZE(rmsg));
			mutex_exit(&un->un_rrp_inflight_mx);
			return (active);
		}
		kmem_free(kres, sizeof (md_mn_kresult_t));

		/*
		 * If ownership changed while we were sending, we probably
		 * sent the message to the wrong node.  Leave fixing that for
		 * the next cycle.
		 */
		if (un->un_mirror_owner != owner_node) {
			mutex_exit(&un->un_rrp_inflight_mx);
			return (active);
		}

		/*
		 * Now that we've sent the message, clear them from the
		 * pernode_dirty arrays.  These are ONLY cleared on a
		 * successful send, and failure has no impact.
		 */
		cleared_dirty = 0;
		start = MDMN_MSG_RR_CLEAN_START_BIT(rmsg);
		end = start + MDMN_MSG_RR_CLEAN_DATA_BYTES(rmsg) * NBBY;
		mutex_enter(&un->un_resync_mx);
		rw_enter(&un->un_pernode_dirty_mx[md_mn_mynode_id - 1],
		    RW_READER);
		for (i = start; i < end; i++) {
			if (isset(MDMN_MSG_RR_CLEAN_DATA(rmsg),
			    i - start)) {
				if (IS_PERNODE_DIRTY(md_mn_mynode_id, i, un)) {
					un->un_pernode_dirty_sum[i]--;
					CLR_PERNODE_DIRTY(md_mn_mynode_id, i,
					    un);
				}
				if (IS_REGION_DIRTY(i, un)) {
					cleared_dirty++;
					CLR_REGION_DIRTY(i, un);
					CLR_GOING_CLEAN(i, un);
				}
			}
		}
		rw_exit(&un->un_pernode_dirty_mx[md_mn_mynode_id - 1]);

		kmem_free(rmsg, MDMN_MSG_RR_CLEAN_MSG_SIZE(rmsg));
	}
	mutex_exit(&un->un_resync_mx);

	mutex_exit(&un->un_rrp_inflight_mx);

	return (active);
}

static int
process_resync_regions_owner(mm_unit_t *un)
{
	int			i, start, end;
	int			cleared_dirty = 0;
	/* Number of reasons why we can not proceed shutting down the mirror. */
	int			active = 0;
	set_t			setno = MD_UN2SET(un);
	int			mnset = MD_MNSET_SETNO(setno);
	md_mn_msg_rr_clean_t	*rmsg;
	minor_t			mnum = MD_SID(un);
	mdi_unit_t		*ui = MDI_UNIT(mnum);

	/*
	 * We drop the readerlock here to assist lock ordering with
	 * update_resync.  Once we have the un_rrp_inflight_mx, we
	 * can re-acquire it.
	 */
	md_unit_readerexit(ui);

	/*
	 * Resync region processing must be single threaded. We can't use
	 * un_resync_mx for this purpose since this mutex gets released
	 * when blocking on un_resync_cv.
	 */
	mutex_enter(&un->un_rrp_inflight_mx);

	(void) md_unit_readerlock(ui);

	mutex_enter(&un->un_resync_mx);
	un->un_waiting_to_clear++;
	while (un->un_resync_flg & MM_RF_STALL_CLEAN)
		cv_wait(&un->un_resync_cv, &un->un_resync_mx);
	un->un_waiting_to_clear--;

	if (mnset) {
		rw_enter(&un->un_pernode_dirty_mx[md_mn_mynode_id - 1],
		    RW_READER);
		cleared_dirty = mirror_generate_rr_bitmap(un, &rmsg, &active);

		if (cleared_dirty) {
			/*
			 * Clear the bits from the pernode_dirty arrays.
			 * If that results in any being cleared from the
			 * un_dirty_bm, commit it.
			 */
			cleared_dirty = 0;
			start = MDMN_MSG_RR_CLEAN_START_BIT(rmsg);
			end = start + MDMN_MSG_RR_CLEAN_DATA_BYTES(rmsg) * NBBY;
			for (i = start; i < end; i++) {
				if (isset(MDMN_MSG_RR_CLEAN_DATA(rmsg),
				    i - start)) {
					if (IS_PERNODE_DIRTY(md_mn_mynode_id, i,
					    un)) {
						un->un_pernode_dirty_sum[i]--;
						CLR_PERNODE_DIRTY(
						    md_mn_mynode_id, i, un);
					}
					if (un->un_pernode_dirty_sum[i] == 0) {
						cleared_dirty++;
						CLR_REGION_DIRTY(i, un);
						CLR_GOING_CLEAN(i, un);
					}
				}
			}
			kmem_free(rmsg, MDMN_MSG_RR_CLEAN_MSG_SIZE(rmsg));
		}
		rw_exit(&un->un_pernode_dirty_mx[md_mn_mynode_id - 1]);
	} else {
		for (i = 0; i < un->un_rrd_num; i++) {
			if (un->c.un_status & MD_UN_KEEP_DIRTY)
				if (IS_KEEPDIRTY(i, un))
					continue;

			if (!IS_REGION_DIRTY(i, un))
				continue;
			if (un->un_outstanding_writes[i] != 0) {
				active++;
				continue;
			}

			if (!IS_GOING_CLEAN(i, un)) {
				SET_GOING_CLEAN(i, un);
				active++;
				continue;
			}
			CLR_REGION_DIRTY(i, un);
			CLR_GOING_CLEAN(i, un);
			cleared_dirty++;
		}
	}

	if (cleared_dirty) {
		un->un_resync_flg |= MM_RF_GATECLOSED;
		mutex_exit(&un->un_resync_mx);
		mddb_commitrec_wrapper(un->un_rr_dirty_recid);
		mutex_enter(&un->un_resync_mx);
		un->un_resync_flg &= ~MM_RF_GATECLOSED;

		if (un->un_waiting_to_mark != 0 ||
		    un->un_waiting_to_clear != 0) {
			active++;
			cv_broadcast(&un->un_resync_cv);
		}
	}
	mutex_exit(&un->un_resync_mx);

	mutex_exit(&un->un_rrp_inflight_mx);

	return (active);
}

static int
process_resync_regions(mm_unit_t *un, callb_cpr_t *cprinfop)
{
	int	mnset = MD_MNSET_SETNO(MD_UN2SET(un));
	/*
	 * For a mirror we can only update the on-disk resync-record if we
	 * currently own the mirror. If we are called and there is no owner we
	 * bail out before scanning the outstanding_writes[] array.
	 * NOTE: we only need to check here (before scanning the array) as we
	 * 	are called with the readerlock held. This means that a change
	 * 	of ownership away from us will block until this resync check
	 * 	has completed.
	 */
	if (mnset && (MD_MN_NO_MIRROR_OWNER(un) ||
	    (!MD_MN_MIRROR_OWNER(un) && !md_mn_is_commd_present_lite()))) {
		return (0);
	} else if (mnset && !MD_MN_MIRROR_OWNER(un)) {
		return (process_resync_regions_non_owner(un, cprinfop));
	} else {
		return (process_resync_regions_owner(un));
	}
}

/*
 * Function that is callable from other modules to provide
 * ability to cleanup dirty region bitmap on demand. Used
 * on last close of a unit to avoid massive device resyncs
 * when coming back after rolling large amounts of data to
 * a mirror (e.g. at umount with logging).
 */

void
mirror_process_unit_resync(mm_unit_t *un)
{
	int	cleans = 0;

	while (process_resync_regions(un, NULL)) {

		cleans++;
		if (cleans >= md_mirror_rr_cleans) {
			cmn_err(CE_NOTE,
			    "Could not clean resync regions\n");
			break;
		}
		if (cleans > md_mirror_rr_polls) {
			/*
			 * We did not make it with md_mirror_rr_polls
			 * iterations. Give the system relief and
			 * switch over to non-busy-wait.
			 */
			delay(md_mirror_rr_sleep_timo * md_hz);
		}
	}
}

static void
check_resync_regions(daemon_request_t *timeout)
{
	mdi_unit_t	*ui;
	mm_unit_t	*un;
	md_link_t	*next;
	callb_cpr_t	cprinfo;

	rw_enter(&mirror_md_ops.md_link_rw.lock, RW_READER);
	for (next = mirror_md_ops.md_head; next != NULL; next = next->ln_next) {

		if (md_get_setstatus(next->ln_setno) & MD_SET_STALE)
			continue;

		un = MD_UNIT(next->ln_id);

		/*
		 * Register this resync thread with the CPR mechanism. This
		 * allows us to detect when the system is suspended and so
		 * keep track of the RPC failure condition.
		 */
		CALLB_CPR_INIT(&cprinfo, &un->un_prr_cpr_mx, callb_md_mrs_cpr,
		    "check_resync_regions");

		ui = MDI_UNIT(next->ln_id);
		(void) md_unit_readerlock(ui);

		/*
		 * Do not clean up resync regions if it is an ABR
		 * mirror, or if a submirror is offline (we will use the resync
		 * region to resync when back online) or if there is only one
		 * submirror.
		 */
		if ((ui->ui_tstate & MD_ABR_CAP) ||
		    (un->c.un_status & MD_UN_OFFLINE_SM) || (un->un_nsm < 2)) {
			md_unit_readerexit(ui);
			continue;
		}

		(void) process_resync_regions(un, &cprinfo);

		md_unit_readerexit(ui);

		/* Remove this thread from the CPR callback table. */
		mutex_enter(&un->un_prr_cpr_mx);
		CALLB_CPR_EXIT(&cprinfo);
	}

	rw_exit(&mirror_md_ops.md_link_rw.lock);

	/* We are done */
	mutex_enter(&mirror_timeout.dr_mx);
	timeout->dr_pending = 0;
	mutex_exit(&mirror_timeout.dr_mx);
}

static void
md_mirror_timeout(void *throwaway)
{

	mutex_enter(&mirror_timeout.dr_mx);
	if (!mirror_timeout.dr_pending) {
		mirror_timeout.dr_pending = 1;
		daemon_request(&md_mto_daemon, check_resync_regions,
		    (daemon_queue_t *)&mirror_timeout, REQ_OLD);
	}

	if (mirror_md_ops.md_head != NULL)
		mirror_timeout.dr_timeout_id = timeout(md_mirror_timeout,
		    throwaway, (int)MD_MDELAY*hz);
	else
		mirror_timeout.dr_timeout_id = 0;

	mutex_exit(&mirror_timeout.dr_mx);
}

void
resync_start_timeout(set_t setno)
{
	if (md_get_setstatus(setno) & MD_SET_STALE)
		return;

	mutex_enter(&mirror_timeout.dr_mx);
	if (mirror_timeout.dr_timeout_id == 0)
		mirror_timeout.dr_timeout_id = timeout(md_mirror_timeout,
		    (void *)NULL, (int)MD_MDELAY*hz);
	mutex_exit(&mirror_timeout.dr_mx);
}

static void
offlined_to_attached(mm_unit_t *un)
{
	int		i;
	int		changed = 0;

	if (md_get_setstatus(MD_UN2SET(un)) & MD_SET_STALE)
		return;

	for (i = 0; i < NMIRROR; i++) {
		if (SMS_BY_INDEX_IS(un, i, SMS_OFFLINE)) {
			mirror_set_sm_state(&un->un_sm[i],
			    &un->un_smic[i], SMS_ATTACHED, 1);
			changed++;
		}
		if (SMS_BY_INDEX_IS(un, i, SMS_OFFLINE_RESYNC)) {
			mirror_set_sm_state(&un->un_sm[i],
			    &un->un_smic[i], SMS_ATTACHED_RESYNC, 1);
			changed++;
		}
	}

	if (changed != 0) {
		un->c.un_status &= ~MD_UN_OFFLINE_SM;
		mddb_setrecprivate(un->c.un_record_id, MD_PRV_PENDCOM);
	}
}

static void
get_unit_resync(mm_unit_t *un)
{
	mddb_recstatus_t	status;
	struct optim_resync	*orp;

	if (un->un_rr_dirty_recid == 0) {
		offlined_to_attached(un);
		return;
	}

	status = mddb_getrecstatus(un->un_rr_dirty_recid);
	if ((status == MDDB_NORECORD) || (status == MDDB_NODATA)) {
		un->un_rr_dirty_recid = 0;
		offlined_to_attached(un);
		return;
	}

	mddb_setrecprivate(un->un_rr_dirty_recid, MD_PRV_GOTIT);
	orp = (struct optim_resync *)mddb_getrecaddr(un->un_rr_dirty_recid);
	un->un_dirty_bm = orp->or_rr;
}

static int
create_unit_resync(mm_unit_t *un, int snarfing)
{
	diskaddr_t	tb;
	int		i;
	int		blksize;	/* rr size in blocks */
	int		num_rr;
	mddb_recid_t	recid;
	size_t		size;	/* bitmap size */
	optim_resync_t	*orp;
	mddb_type_t	typ1;
	set_t		setno;

	tb = un->c.un_total_blocks;

	if (((tb + MD_MIN_RR_SIZE)/ MD_MIN_RR_SIZE) > MD_DEF_NUM_RR) {
		blksize = (int)(tb / MD_DEF_NUM_RR);
		num_rr = (int)((tb + (blksize)) / (blksize));
	} else {
		blksize = MD_MIN_RR_SIZE;
		num_rr = (int)((tb + MD_MIN_RR_SIZE) / MD_MIN_RR_SIZE);
	}

	size = howmany(num_rr, NBBY) + sizeof (*orp) - sizeof (orp->or_rr);

	setno = MD_UN2SET(un);

	typ1 = (mddb_type_t)md_getshared_key(setno,
	    mirror_md_ops.md_driver.md_drivername);

	recid =  mddb_createrec(size, typ1, RESYNC_REC,
	    MD_CRO_OPTIMIZE|MD_CRO_32BIT, setno);
	if (recid < 0) {
		if (snarfing && !(md_get_setstatus(setno) & MD_SET_STALE)) {
			md_set_setstatus(setno, MD_SET_STALE);
			cmn_err(CE_WARN, "md: state database is stale");
		}
		return (-1);
	}

	un->un_rr_dirty_recid = recid;
	orp = (optim_resync_t *)mddb_getrecaddr(recid);
	orp->or_magic = OR_MAGIC;
	orp->or_blksize = blksize;
	orp->or_num = num_rr;

	un->un_rrd_blksize = blksize;
	un->un_rrd_num  = num_rr;
	un->un_dirty_bm = orp->or_rr;

	if (snarfing)
		for (i = 0; i < howmany(num_rr, NBBY); i++)
			orp->or_rr[i] = 0xFF;

	if (!snarfing) {
		mddb_commitrec_wrapper(recid);
		mirror_commit(un, NO_SUBMIRRORS, 0);
		return (0);
	}
	mddb_setrecprivate(recid, MD_PRV_PENDCOM);
	mddb_setrecprivate(un->c.un_record_id, MD_PRV_PENDCOM);
	return (0);
}

int
unit_setup_resync(mm_unit_t *un, int snarfing)
{
	int err;
	int syncable;
	int i;
	mdi_unit_t	*ui = MDI_UNIT(MD_SID(un));
	int nonABR = 1;		/* only set if ABR marked in ui_tstate */

	un->un_dirty_bm = NULL;
	un->un_rs_buffer = NULL;

	mutex_init(&un->un_rrp_inflight_mx, "rrp mx", MUTEX_DEFAULT, NULL);

	mutex_init(&un->un_resync_mx, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&un->un_resync_cv, NULL, CV_DEFAULT, NULL);
	un->un_resync_flg = 0;
	un->un_waiting_to_mark = 0;
	un->un_waiting_to_commit = 0;
	un->un_waiting_to_clear = 0;

	un->un_goingclean_bm = NULL;
	un->un_goingdirty_bm = NULL;
	un->un_outstanding_writes = NULL;
	un->un_resync_bm = NULL;

	if (snarfing)
		get_unit_resync(un);

	if (un->un_rr_dirty_recid == 0) {
		/*
		 * If a MN diskset and snarfing and this node is not the
		 * master, do not delete any records on snarf of the
		 * mirror records (create_unit_resync deletes records).
		 *
		 * Master node should have already handled this case.
		 */
		if (MD_MNSET_SETNO(MD_UN2SET(un)) && snarfing &&
		    md_set[MD_UN2SET(un)].s_am_i_master == 0) {
#ifdef DEBUG
			cmn_err(CE_NOTE, "unit_setup_resync: no rr for %s on"
			    " nodeid %d\n", md_shortname(MD_SID(un)),
			    md_set[MD_UN2SET(un)].s_nodeid);
#endif
			return (-1);
		}
		if ((err = create_unit_resync(un, snarfing)) != 0)
			return (err);
	}

	un->un_goingclean_bm = (uchar_t *)kmem_zalloc((uint_t)(howmany(
	    un->un_rrd_num, NBBY)), KM_SLEEP);
	un->un_goingdirty_bm = (uchar_t *)kmem_zalloc((uint_t)(howmany(
	    un->un_rrd_num, NBBY)), KM_SLEEP);
	un->un_outstanding_writes = (short *)kmem_zalloc(
	    (uint_t)un->un_rrd_num * sizeof (short), KM_SLEEP);
	un->un_resync_bm = (uchar_t *)kmem_zalloc((uint_t)(howmany(
	    un->un_rrd_num, NBBY)), KM_SLEEP);

	/*
	 * Allocate pernode bitmap for this node. All other nodes' maps will
	 * be created 'on-the-fly' in the ioctl message handler
	 */
	if (MD_MNSET_SETNO(MD_UN2SET(un))) {
		un->un_pernode_dirty_sum =
		    (uchar_t *)kmem_zalloc(un->un_rrd_num, KM_SLEEP);
		if (md_mn_mynode_id > 0) {
			un->un_pernode_dirty_bm[md_mn_mynode_id-1] = (uchar_t *)
			    kmem_zalloc((uint_t)(howmany(un->un_rrd_num, NBBY)),
			    KM_SLEEP);
		}

		/*
		 * Allocate taskq to process deferred (due to locking) RR_CLEAN
		 * requests.
		 */
		un->un_drl_task = (ddi_taskq_t *)md_create_taskq(MD_UN2SET(un),
		    MD_SID(un));
	}

	if (md_get_setstatus(MD_UN2SET(un)) & MD_SET_STALE)
		return (0);

	/*
	 * Only mark mirror which has an associated DRL as requiring a resync.
	 * For ABR mirrors we need not set the resync record bitmap up.
	 */
	if (ui && (ui->ui_tstate & MD_ABR_CAP))
		nonABR = 0;

	for (i = 0, syncable = 0; i < NMIRROR; i++) {
		if (nonABR) {
			if ((SUBMIRROR_IS_READABLE(un, i) ||
			    SMS_BY_INDEX_IS(un, i,
			    (SMS_OFFLINE | SMS_OFFLINE_RESYNC))))
				syncable++;
		}
	}

	if (snarfing && un->un_pass_num && (syncable > 1)) {
		bcopy((caddr_t)un->un_dirty_bm, (caddr_t)un->un_resync_bm,
		    howmany(un->un_rrd_num, NBBY));

		un->c.un_status |= (MD_UN_OPT_NOT_DONE | MD_UN_WAR);
		un->c.un_status &= ~MD_UN_OFFLINE_SM;
		for (i = 0; i < NMIRROR; i++) {
			if ((SUBMIRROR_IS_READABLE(un, i)) ||
			    SMS_BY_INDEX_IS(un, i, SMS_OFFLINE_RESYNC))
				un->un_sm[i].sm_flags |= MD_SM_RESYNC_TARGET;

			if (SMS_BY_INDEX_IS(un, i, SMS_OFFLINE)) {
				un->un_sm[i].sm_flags |= MD_SM_RESYNC_TARGET;
				mirror_set_sm_state(&un->un_sm[i],
				    &un->un_smic[i], SMS_OFFLINE_RESYNC, 1);
				mddb_setrecprivate(un->c.un_record_id,
				    MD_PRV_PENDCOM);
			}
		}
	}
	return (0);
}

/*
 * resync_kill_pending:
 * -------------------
 * Determine if the resync thread has been requested to terminate.
 * Block if MD_RI_BLOCK or MD_RI_BLOCK_OWNER is set in un->un_rs_thread_flags.
 * MD_RI_BLOCK is only set as a result of a user-initiated ioctl via metasync.
 * MD_RI_BLOCK_OWNER is set by the ownership change of a multi-node  mirror.
 *
 * Returns:
 *	0	Kill not pending
 *	1	Kill requested	(set MD_UN_RESYNC_CANCEL in un->c.un_status)
 *
 * Note: this routine may block
 *	 the writerlock for <ui> will be dropped and reacquired if <mx_type>
 *	 is set to MD_WRITER_HELD.
 *	 the readerlock for <ui> will be dropped and reacquired if <mx_type>
 *	 is set to MD_READER_HELD.
 */
static int
resync_kill_pending(
	mm_unit_t *un,
	mdi_unit_t *ui,
	uint_t mx_type)
{
	int	retval = 0;

	/* Ensure that we don't block with any mutex held */
	if (mx_type == MD_WRITER_HELD) {
		md_unit_writerexit(ui);
	} else if (mx_type == MD_READER_HELD) {
		md_unit_readerexit(ui);
	}
	mutex_enter(&un->un_rs_thread_mx);
	while (un->un_rs_thread_flags & (MD_RI_BLOCK|MD_RI_BLOCK_OWNER)) {
		cv_wait(&un->un_rs_thread_cv, &un->un_rs_thread_mx);
		if (un->un_rs_thread_flags & (MD_RI_KILL|MD_RI_SHUTDOWN))
			break;
	}
	/* Determine if we've been asked to abort or shutdown gracefully */
	if (un->un_rs_thread_flags & MD_RI_KILL) {
		un->c.un_status |= MD_UN_RESYNC_CANCEL;
		retval = 1;
	} else if (un->un_rs_thread_flags & MD_RI_SHUTDOWN) {
		retval = 1;
	}
	mutex_exit(&un->un_rs_thread_mx);

	/* Reacquire mutex if dropped on entry */
	if (mx_type == MD_WRITER_HELD) {
		(void) md_unit_writerlock(ui);
	} else if (mx_type == MD_READER_HELD) {
		(void) md_unit_readerlock(ui);
	}
	return (retval);
}

/*
 * resync_read_buffer:
 * ------------------
 * Issue the resync source read for the specified start block and size.
 * This will cause the mirror strategy routine to issue a write-after-read
 * once this request completes successfully.
 * If 'flag_err' is set we expect to see a write error flagged in the b_error
 * field of the buffer created for this i/o request. If clear we do not expect
 * to see the error flagged for write failures.
 * Read failures will always set the B_ERROR bit which will stop the resync
 * immediately.
 */
static int
resync_read_buffer(mm_unit_t *un, diskaddr_t blk, size_t cnt, int flag_err)
{
	md_mcs_t	*sp;
	buf_t		*bp;
	int		ret = 0;

	sp = kmem_cache_alloc(mirror_child_cache, MD_ALLOCFLAGS);
	mirror_child_init(sp);

	bp = &sp->cs_buf;
	bp->b_edev = makedevice(md_major, MD_SID(un));
	bp->b_flags = B_READ;
	bp->b_lblkno = blk;
	bp->b_bcount = dbtob(cnt);
	bp->b_un.b_addr = un->un_rs_buffer;
	md_unit_readerexit(MDI_UNIT(MD_SID(un)));

	(void) md_mirror_strategy(bp, MD_STR_NOTTOP | MD_STR_MAPPED |
	    MD_STR_WAR | (flag_err ? MD_STR_FLAG_ERR : 0), NULL);

	(void) biowait(bp);

	(void) md_unit_readerlock(MDI_UNIT(MD_SID(un)));
	if (bp->b_flags & B_ERROR) {
		ret = 1;
	}
	kmem_cache_free(mirror_child_cache, sp);
	return (ret);
}

/*
 * send_mn_resync_done_message
 *
 * At the end of a resync, send a message to all nodes to indicate that
 * the resync is complete. The argument, flags, has the following values
 *
 * RESYNC_ERR - if an error occurred that terminated the resync
 * CLEAR_OPT_NOT_DONE   - Just need to clear the OPT_NOT_DONE flag
 *
 * unit writerlock set on entry
 * Only send the message if the thread is not marked as shutting down:
 * [un_rs_thread_flags & MD_RI_SHUTDOWN] or being killed:
 * [un->c.un_status & MD_UN_RESYNC_CANCEL]
 * or if there has been an error that terminated the resync:
 *	flags & RESYNC_ERR
 *
 */
static void
send_mn_resync_done_message(
	mm_unit_t	*un,
	int		flags
)
{
	md_mn_msg_resync_t	*rmsg = un->un_rs_msg;
	set_t			setno;
	mdi_unit_t		*ui = MDI_UNIT(MD_SID(un));
	md_mn_kresult_t		*kres;
	int			dont_send = 0;
	int			rval;

	rmsg = (md_mn_msg_resync_t *)un->un_rs_msg;

	/*
	 * Only send the message if this resync thread is still active. This
	 * handles the case where ownership changes to different nodes during
	 * a resync can cause multiple spurious resync_done messages to occur
	 * when the resync completes. This happens because only one node is
	 * the resync owner but other nodes will have their resync_unit thread
	 * blocked in 'resync_kill_pending'
	 */
	mutex_enter(&un->un_rs_thread_mx);
	dont_send = (un->un_rs_thread_flags & (MD_RI_KILL|MD_RI_SHUTDOWN)) ? 1
	    : 0;
	mutex_exit(&un->un_rs_thread_mx);
	dont_send |= (un->c.un_status & MD_UN_RESYNC_CANCEL) ? 1 : 0;

	/*
	 * Always send a message if we've encountered an error that terminated
	 * the resync.
	 */
	if (flags & RESYNC_ERR)
		dont_send = 0;

	if (dont_send) {
#ifdef DEBUG
		if (mirror_debug_flag) {
			printf("Don't send resync done message, mnum = %x,"
			    " type = %x, flags = %d\n", MD_SID(un),
			    un->un_rs_type, flags);
		}
#endif  /* DEBUG */
		return;
	}

#ifdef DEBUG
	if (mirror_debug_flag) {
		printf("send resync done message, mnum = %x, type = %x\n",
		    MD_SID(un), un->un_rs_type);
	}
#endif

	rmsg->msg_resync_mnum = MD_SID(un);
	rmsg->msg_resync_type = un->un_rs_type;
	rmsg->msg_originator = md_mn_mynode_id;
	rmsg->msg_resync_flags = 0;
	if (flags & RESYNC_ERR)
		rmsg->msg_resync_flags |= MD_MN_RS_ERR;
	if (flags & CLEAR_OPT_NOT_DONE)
		rmsg->msg_resync_flags |= MD_MN_RS_CLEAR_OPT_NOT_DONE;

	setno = MD_MIN2SET(MD_SID(un));
	md_unit_writerexit(ui);
	kres = kmem_alloc(sizeof (md_mn_kresult_t), KM_SLEEP);

	mutex_enter(&un->un_rs_cpr_mx);
	CALLB_CPR_SAFE_BEGIN(&un->un_rs_cprinfo);

	rval = mdmn_ksend_message(setno, MD_MN_MSG_RESYNC_PHASE_DONE,
	    MD_MSGF_NO_LOG, 0, (char *)rmsg, sizeof (md_mn_msg_resync_t), kres);

	CALLB_CPR_SAFE_END(&un->un_rs_cprinfo, &un->un_rs_cpr_mx);
	mutex_exit(&un->un_rs_cpr_mx);

	/* if the node hasn't yet joined, it's Ok. */
	if ((!MDMN_KSEND_MSG_OK(rval, kres)) &&
	    (kres->kmmr_comm_state !=  MDMNE_NOT_JOINED)) {
		mdmn_ksend_show_error(rval, kres, "RESYNC_PHASE_DONE");
		/* If we're shutting down already, pause things here. */
		if (kres->kmmr_comm_state == MDMNE_RPC_FAIL) {
			while (!md_mn_is_commd_present()) {
				delay(md_hz);
			}
		}
		cmn_err(CE_PANIC, "ksend_message failure: RESYNC_PHASE_DONE");
	}
	kmem_free(kres, sizeof (md_mn_kresult_t));
	(void) md_unit_writerlock(ui);
}

/*
 * send_mn_resync_next_message
 *
 * Sent a message to all nodes indicating the next region to be resynced.
 * The message contains the region to be resynced and the current position in
 * the resync as denoted by un_rs_resync_done and un_rs_resync_2_do.
 * On entry the unit readerlock is held.
 */
static void
send_mn_resync_next_message(
	mm_unit_t	*un,
	diskaddr_t	currentblk,
	size_t		rsize,
	int		flags
)
{
	md_mn_msg_resync_t	*rmsg = un->un_rs_msg;
	set_t			setno;
	md_mn_kresult_t		*kres;
	mdi_unit_t		*ui = MDI_UNIT(MD_SID(un));
	int			rval;
	md_mps_t		*ps;
	mm_submirror_t		*sm;
	int			smi;

	ASSERT(rmsg != NULL);
#ifdef DEBUG
	if (mirror_debug_flag) {
		printf("send resync next message, mnum = %x, start=%lld, "
		    "size=%ld, type=%x, done=%lld, 2_do=%lld\n",
		    MD_SID(un), currentblk, rsize, un->un_rs_type,
		    un->un_rs_resync_done, un->un_rs_resync_2_do);
	}
#endif
	rmsg->msg_resync_mnum = MD_SID(un);
	rmsg->msg_resync_type = un->un_rs_type;
	rmsg->msg_resync_start = currentblk;
	rmsg->msg_resync_rsize = rsize;
	rmsg->msg_resync_done = un->un_rs_resync_done;
	rmsg->msg_resync_2_do = un->un_rs_resync_2_do;
	rmsg->msg_originator = md_mn_mynode_id;
	if (flags & MD_FIRST_RESYNC_NEXT)
		rmsg->msg_resync_flags = MD_MN_RS_FIRST_RESYNC_NEXT;

	/*
	 * Copy current submirror state and flags into message. This provides
	 * a means of keeping all nodes that are currently active in the cluster
	 * synchronised with regards to their submirror state settings. If we
	 * did not pass this information here, the only time every node gets
	 * submirror state updated is at the end of a resync phase. This can be
	 * a significant amount of time for large metadevices.
	 */
	for (smi = 0; smi < NMIRROR; smi++) {
		sm = &un->un_sm[smi];
		rmsg->msg_sm_state[smi] = sm->sm_state;
		rmsg->msg_sm_flags[smi] = sm->sm_flags;
	}
	setno = MD_MIN2SET(MD_SID(un));
	md_unit_readerexit(ui);
	kres = kmem_alloc(sizeof (md_mn_kresult_t), KM_SLEEP);

	mutex_enter(&un->un_rs_cpr_mx);
	CALLB_CPR_SAFE_BEGIN(&un->un_rs_cprinfo);

	rval = mdmn_ksend_message(setno, MD_MN_MSG_RESYNC_NEXT, MD_MSGF_NO_LOG,
	    0, (char *)rmsg, sizeof (md_mn_msg_resync_t), kres);

	CALLB_CPR_SAFE_END(&un->un_rs_cprinfo, &un->un_rs_cpr_mx);
	mutex_exit(&un->un_rs_cpr_mx);

	if (!MDMN_KSEND_MSG_OK(rval, kres)) {
		mdmn_ksend_show_error(rval, kres, "RESYNC_NEXT");
		/* If we're shutting down already, pause things here. */
		if (kres->kmmr_comm_state == MDMNE_RPC_FAIL) {
			while (!md_mn_is_commd_present()) {
				delay(md_hz);
			}
		}
		cmn_err(CE_PANIC, "ksend_message failure: RESYNC_NEXT");
	}
	kmem_free(kres, sizeof (md_mn_kresult_t));
	(void) md_unit_readerlock(ui);
	ps = un->un_rs_prev_overlap;

	/* Allocate previous overlap reference if needed */
	if (ps == NULL) {
		ps = kmem_cache_alloc(mirror_parent_cache, MD_ALLOCFLAGS);
		ps->ps_un = un;
		ps->ps_ui = ui;
		ps->ps_firstblk = 0;
		ps->ps_lastblk = 0;
		ps->ps_flags = 0;
		md_unit_readerexit(ui);
		(void) md_unit_writerlock(ui);
		un->un_rs_prev_overlap = ps;
		md_unit_writerexit(ui);
		(void) md_unit_readerlock(ui);
	}

	ps->ps_firstblk = currentblk;
	ps->ps_lastblk = currentblk + rsize - 1;
}

static int
resync_read_blk_range(
	mm_unit_t *un,
	diskaddr_t currentblk,
	diskaddr_t stopbefore,
	uint_t type,
	int	flags
)
{
	size_t copysize;	/* limited by max xfer buf size */
	size_t rsize;		/* size of resync block (for MN) */
	set_t		setno;
	diskaddr_t	newstop;
	diskaddr_t	rs_startblk;
	uint_t		rs_type;
	int		flags1 = flags & MD_FIRST_RESYNC_NEXT;

	rs_type = un->un_rs_type;
	rs_startblk = currentblk;
	if (stopbefore > un->c.un_total_blocks)
		stopbefore = un->c.un_total_blocks;
	if (currentblk < un->un_resync_startbl)
		currentblk = un->un_resync_startbl;

	copysize = un->un_rs_copysize;
	rsize = MD_DEF_RESYNC_BLK_SZ;

	setno = MD_MIN2SET(MD_SID(un));
	while (currentblk < stopbefore) {
		/*
		 * Split the block up into units of MD_DEF_RESYNC_BLK_SZ and
		 * if a MN device and sendflag is set, send a RESYNC_MESSAGE
		 * to all nodes.
		 */
		if ((currentblk + MD_DEF_RESYNC_BLK_SZ) > stopbefore)
			rsize = stopbefore - currentblk;
		if (MD_MNSET_SETNO(setno) && (flags & MD_SEND_MESS_XMIT)) {
			un->un_resync_startbl = currentblk;
			rs_startblk = currentblk;
			send_mn_resync_next_message(un, currentblk, rsize,
			    flags1);
			if (flags1)
				flags1 = 0;
			/* check to see if we've been asked to terminate */
			if (resync_kill_pending(un, MDI_UNIT(MD_SID(un)), type))
				return ((un->c.un_status & MD_UN_RESYNC_CANCEL)
				    ? 1:0);
			/*
			 * Check to see if another node has completed this
			 * block, if so either the type or the resync region
			 * will have changed. If the resync type has changed,
			 * just exit.
			 * If the resync region has changed, reset currentblk
			 * to the start of the current resync region and
			 * continue.
			 */
			if (un->un_rs_type != rs_type)
				return (0);
			if (un->un_rs_prev_overlap->ps_firstblk >
			    rs_startblk) {
				currentblk =
				    un->un_rs_prev_overlap->ps_firstblk;
				continue;
			}
		}
		newstop = currentblk + rsize;
		while (currentblk < newstop) {
			if ((currentblk + copysize) > stopbefore)
				copysize = (size_t)(stopbefore - currentblk);
			if (resync_read_buffer(un, currentblk, copysize,
			    (flags & MD_RESYNC_FLAG_ERR)))
				return (1);

			/* resync_read_buffer releases/grabs a new lock */
			un = (mm_unit_t *)MD_UNIT(MD_SID(un));
			currentblk += copysize;

			/* check to see if we've been asked to terminate */
			if (resync_kill_pending(un, MDI_UNIT(MD_SID(un)), type))
				return ((un->c.un_status & MD_UN_RESYNC_CANCEL)
				    ? 1:0);
			if (MD_MNSET_SETNO(setno)) {
				/*
				 * Check to see if another node has completed
				 * this block, see above
				 */
				if (un->un_rs_type != rs_type)
					return (0);
				if (un->un_rs_prev_overlap->ps_firstblk >
				    rs_startblk)
					currentblk =
					    un->un_rs_prev_overlap->ps_firstblk;
			}
		}
	}
	return (0);
}

static void
optimized_resync(mm_unit_t *un)
{
	mdi_unit_t	*ui;
	minor_t		mnum;
	int		rr, smi;
	int		resync_regions;
	uchar_t		*dirtyregions;
	diskaddr_t	first, stopbefore;
	int		err;
	int		cnt;
	sm_state_t	state;
	int		broke_out = 0;
	set_t		setno;
	uint_t		old_rs_type = un->un_rs_type;
	uint_t		old_rs_done;
	uint_t		flags1 = MD_FIRST_RESYNC_NEXT|MD_RESYNC_FLAG_ERR;
	size_t		start_rr;

	mnum = MD_SID(un);
	ui = MDI_UNIT(mnum);
	setno = MD_UN2SET(un);

	if (!(un->c.un_status & MD_UN_OPT_NOT_DONE)) {
		/*
		 * We aren't marked as needing a resync so for multi-node
		 * sets we flag the completion so that all nodes see the same
		 * metadevice state. This is a problem when a new node joins
		 * an existing set as it has to perform a 'metasync -r' and
		 * we have to step through all of the resync phases. If we
		 * don't do this the nodes that were already in the set will
		 * have the metadevices marked as 'Okay' but the joining node
		 * will have 'Needs Maintenance' which is unclearable.
		 */
		if (MD_MNSET_SETNO(setno)) {
			send_mn_resync_done_message(un, CLEAR_OPT_NOT_DONE);
		}
		return;
	}

	/*
	 * No need for optimized resync if ABR set, clear rs_type and flags
	 * and exit
	 */
	if (ui->ui_tstate & MD_ABR_CAP) {
		un->un_rs_type = MD_RS_NONE;
		un->c.un_status &= ~(MD_UN_OPT_NOT_DONE | MD_UN_WAR);
		return;
	}

	un->un_rs_dropped_lock = 1;
	un->c.un_status |= MD_UN_WAR;
	resync_regions = un->un_rrd_num;
	dirtyregions = un->un_resync_bm;
	md_unit_writerexit(ui);

	/* For MN sets, resync NOTIFY is done when processing resync messages */
	if (!MD_MNSET_SETNO(setno)) {
		SE_NOTIFY(EC_SVM_STATE, ESC_SVM_RESYNC_START,
		    SVM_TAG_METADEVICE, setno, MD_SID(un));
	}
	un = (mm_unit_t *)md_unit_readerlock(ui);

	/* check to see if we've been asked to terminate */
	if (resync_kill_pending(un, MDI_UNIT(MD_SID(un)), MD_READER_HELD)) {
		if (un->c.un_status & MD_UN_RESYNC_CANCEL)
			broke_out = RESYNC_ERR;
	}
	/*
	 * Check that we are still performing an optimized
	 * resync. If not, another node must have completed it
	 * so we have no more work to do.
	 */
	if (un->un_rs_type != old_rs_type) {
		md_unit_readerexit(ui);
		(void) md_unit_writerlock(ui);
		return;
	}
	/*
	 * If rs_resync_done is non-zero, we must be completing an optimized
	 * resync that has already been partially done on another node.
	 * Therefore clear the bits in resync_bm for the resync regions
	 * already done. If resync_startbl is zero, calculate 2_do.
	 */
	if (un->un_rs_resync_done > 0) {
		BLK_TO_RR(start_rr, un->un_resync_startbl, un);
		for (rr = 0; rr < start_rr && rr < resync_regions; rr++)
			CLR_KEEPDIRTY(rr, un);
	} else {
		un->un_rs_resync_2_do = 0;
		for (rr = 0; rr < resync_regions; rr++)
			if (isset(dirtyregions, rr))
				un->un_rs_resync_2_do++;
	}

	for (rr = 0; (rr < resync_regions) && (broke_out != RESYNC_ERR); rr++) {
		if (isset(dirtyregions, rr)) {
			RR_TO_BLK(first, rr, un);
			RR_TO_BLK(stopbefore, rr+1, un);
			old_rs_type = un->un_rs_type;
			old_rs_done = un->un_rs_resync_done;
			err = resync_read_blk_range(un, first, stopbefore,
			    MD_READER_HELD, MD_SEND_MESS_XMIT | flags1);
			flags1 = MD_RESYNC_FLAG_ERR;

			/* resync_read_blk_range releases/grabs a new lock */
			un = (mm_unit_t *)MD_UNIT(mnum);

			if (err) {
				broke_out = RESYNC_ERR;
				break;
			}

			/*
			 * Check that we are still performing an optimized
			 * resync. If not, another node must have completed it
			 * so we have no more work to do.
			 */
			if (un->un_rs_type != old_rs_type) {
				md_unit_readerexit(ui);
				(void) md_unit_writerlock(ui);
				return;
			}

			/*
			 * If resync_done has increased, we must have
			 * blocked in resync_read_blk_range while another node
			 * continued with the resync. Therefore clear resync_bm
			 * for the blocks that have been resynced on another
			 * node and update rr to the next RR to be done.
			 */
			if (old_rs_done < un->un_rs_resync_done) {
				int i;
				BLK_TO_RR(start_rr, un->un_resync_startbl - 1,
				    un);
				for (i = rr; i < start_rr; i++)
					CLR_KEEPDIRTY(i, un);
				rr = start_rr;
			} else
				un->un_rs_resync_done++;

			for (smi = 0, cnt = 0; smi < NMIRROR; smi++)
				if (SUBMIRROR_IS_WRITEABLE(un, smi) &&
				    !(SMS_BY_INDEX_IS(un, smi, SMS_ALL_ERRED)))
					cnt++;
			if (cnt < 2) {
				broke_out = RESYNC_ERR;
				break;
			}
			CLR_KEEPDIRTY(rr, un);
			/* Check to see if we've completed the resync cleanly */
			if (un->un_rs_thread_flags & MD_RI_SHUTDOWN)
				break;

			/*
			 * Check that we haven't exceeded un_rs_resync_2_do. If
			 * we have we've completed the resync.
			 */
			if (un->un_rs_resync_done > un->un_rs_resync_2_do)
				break;
		}
	}
	md_unit_readerexit(ui);
	un = (mm_unit_t *)md_unit_writerlock(ui);

	/*
	 * If MN set send message to all nodes to indicate resync
	 * phase is complete. The processing of the message will update the
	 * mirror state
	 */
	if (MD_MNSET_SETNO(setno)) {
		send_mn_resync_done_message(un, broke_out);
	} else {

		if (!broke_out)
			un->c.un_status &= ~MD_UN_WAR;

		un->c.un_status &= ~MD_UN_KEEP_DIRTY;

		setno = MD_UN2SET(un);
		for (smi = 0; smi < NMIRROR; smi++) {
			un->un_sm[smi].sm_flags &= ~MD_SM_RESYNC_TARGET;
			if (SMS_BY_INDEX_IS(un, smi, SMS_OFFLINE_RESYNC)) {
				state = (broke_out ? SMS_OFFLINE : SMS_RUNNING);
				mirror_set_sm_state(&un->un_sm[smi],
				    &un->un_smic[smi], state, broke_out);
				mirror_commit(un, NO_SUBMIRRORS, 0);
			}
			if (SMS_BY_INDEX_IS(un, smi, SMS_OFFLINE))
				un->c.un_status |= MD_UN_OFFLINE_SM;
		}
	}

	/* For MN sets, resync NOTIFY is done when processing resync messages */
	if (!MD_MNSET_SETNO(setno)) {
		if (broke_out) {
			SE_NOTIFY(EC_SVM_STATE, ESC_SVM_RESYNC_FAILED,
			    SVM_TAG_METADEVICE, MD_UN2SET(un), MD_SID(un));
		} else {
			SE_NOTIFY(EC_SVM_STATE, ESC_SVM_RESYNC_DONE,
			    SVM_TAG_METADEVICE, MD_UN2SET(un), MD_SID(un));
		}
	}
}

/*
 * recalc_resync_done
 *
 * This function deals with a change in value of un_rs_resync_2_do in a
 * component resync. This may change if we are restarting a component
 * resync on a single node having rebooted with a different value of
 * md_resync_bufsz or if we are running in a multi-node with nodes having
 * different values of md_resync_bufsz.
 * If there is a change in un_rs_resync_2_do, we need to recalculate
 * the value of un_rs_resync_done given the new value for resync_2_do.
 * We have to calculate a new value for resync_done to be either
 * if un_resync_startbl is set, (un_resync_startbl - initblock)/(blksize + skip)
 * or if it is not set, we need to calculate it from un_rs_resync_done,
 * (un_rs_resync_done/un_rs_resync_2_do) * resync_2_do
 * In addition we need to deal with the overflow case by using a factor to
 * prevent overflow
 */

static void
recalc_resync_done(mm_unit_t *un, size_t resync_2_do, diskaddr_t initblock,
    u_longlong_t blk_size, u_longlong_t skip)
{
	diskaddr_t		x;
	uint_t			factor = 1;

	/*
	 * If resync_2_do has not yet been calculated, no need to modify
	 * resync_done
	 */
	if (un->un_rs_resync_2_do == 0) {
		return;
	}
	if (un->un_rs_resync_2_do == resync_2_do)
		return; /* No change, so nothing to do */
	/*
	 * If un_rs_startbl is set, another node must have already started
	 * this resync and hence we can calculate resync_done from
	 * resync_startbl
	 */
	if (un->un_resync_startbl) {
		un->un_rs_resync_done = (un->un_resync_startbl - initblock) /
		    (blk_size + skip);
		return;
	}
	/*
	 * un_resync_startbl is not set so we must calculate it from
	 * un_rs_resync_done.
	 * If the larger of the two values of resync_2_do is greater than 32
	 * bits, calculate a factor to divide by to ensure that we don't
	 * overflow 64 bits when calculating the new value for resync_done
	 */
	x = (un->un_rs_resync_2_do > resync_2_do) ? un->un_rs_resync_2_do :
	    resync_2_do;
	while (x > INT32_MAX) {
		x = x >> 1;
		factor = factor << 1;
	}
	un->un_rs_resync_done = ((un->un_rs_resync_done/factor) *
	    (resync_2_do/factor)) /
	    ((un->un_rs_resync_2_do + (factor * factor) - 1)/
	    (factor * factor));
}

static void
check_comp_4_resync(mm_unit_t *un, int smi, int ci)
{
	mdi_unit_t		*ui;
	minor_t			mnum;
	mm_submirror_t		*sm;
	mm_submirror_ic_t	*smic;
	size_t			count;
	u_longlong_t		skip;
	u_longlong_t		size;
	u_longlong_t		blk_size;
	diskaddr_t		initblock;
	diskaddr_t		block;
	diskaddr_t		frag = 0;
	md_m_shared_t		*shared;
	int			err;
	set_t			setno;
	int			broke_out = 0;
	int			blks;
	uint_t			old_rs_type = un->un_rs_type;
	diskaddr_t		old_rs_done;
	uint_t			flags1 = MD_FIRST_RESYNC_NEXT;
	diskaddr_t		resync_2_do;

	mnum = MD_SID(un);
	ui = MDI_UNIT(mnum);
	sm = &un->un_sm[smi];
	smic = &un->un_smic[smi];
	setno = MD_UN2SET(un);

	shared = (md_m_shared_t *)(*(smic->sm_shared_by_indx))
	    (sm->sm_dev, sm, ci);

	if (shared->ms_state != CS_RESYNC) {
		SET_RS_TYPE_NONE(un->un_rs_type);
		return;
	}

	if (shared->ms_flags & MDM_S_RS_TRIED) {
		SET_RS_TYPE_NONE(un->un_rs_type);
		return;
	}

	(void) (*(smic->sm_get_bcss))
	    (sm->sm_dev, sm, ci, &initblock, &count, &skip, &size);

	if ((count == 1) && (skip == 0)) {
		count = (size_t)(size / un->un_rs_copysize);
		if ((frag = (size - (count * un->un_rs_copysize))) != 0)
			count++;
		size = (u_longlong_t)un->un_rs_copysize;
	}
	blk_size = size; /* Save block size for this resync */

	ASSERT(count >= 1);
	resync_2_do = count;
	/*
	 * If part way through a resync, un_rs_resync_done/un_rs_resync_2_do
	 * gives the proportion of the resync that has already been done.
	 * If un_rs_copysize has changed since this previous partial resync,
	 * either because this node has been rebooted with a different value
	 * for md_resync_bufsz or because another node with a different value
	 * for md_resync_bufsz performed the previous resync, we need to
	 * recalculate un_rs_resync_done as a proportion of our value of
	 * resync_2_do.
	 */
	recalc_resync_done(un, resync_2_do, initblock, blk_size, skip);

	/*
	 * For MN mirrors we need to send a message to all nodes indicating
	 * the next region to be resynced. For a component resync, the size of
	 * the contiguous region that is processed by resync_read_blk_range()
	 * may be small if there is the interleave size.
	 * Therefore, rather than sending the message within
	 * resync_read_blk_range(), we will send a message every
	 * MD_DEF_RESYNC_BLK_SZ blocks. Calculate the frequency in terms of
	 * the number of blocks. Then, if we are restarting a resync, round
	 * un_rs_resync_done down to the previous resync region boundary. This
	 * ensures that we send a RESYNC_NEXT message before resyncing any
	 * blocks
	 */
	if (MD_MNSET_SETNO(setno)) {
		blks = ((MD_DEF_RESYNC_BLK_SZ + blk_size + skip - 1)/
		    (blk_size + skip));
		un->un_rs_resync_done = (un->un_rs_resync_done/blks) * blks;
	}
	/*
	 * un_rs_resync_done is the number of ('size' + 'skip') increments
	 * already resynced from the base 'block'
	 * un_rs_resync_2_do is the number of iterations in
	 * this component resync.
	 */
	ASSERT(count >= un->un_rs_resync_done);
	un->un_rs_resync_2_do = (diskaddr_t)count;

	un->c.un_status |= MD_UN_WAR;
	sm->sm_flags |= MD_SM_RESYNC_TARGET;
	md_unit_writerexit(ui);

	/* For MN sets, resync NOTIFY is done when processing resync messages */
	if (!MD_MNSET_SETNO(setno)) {
		SE_NOTIFY(EC_SVM_STATE, ESC_SVM_RESYNC_START,
		    SVM_TAG_METADEVICE, setno, MD_SID(un));
	}
	un = (mm_unit_t *)md_unit_readerlock(ui);

	/* check to see if we've been asked to terminate */
	if (resync_kill_pending(un, MDI_UNIT(MD_SID(un)), MD_READER_HELD)) {
		if (un->c.un_status & MD_UN_RESYNC_CANCEL)
			broke_out = RESYNC_ERR;
	}
	/*
	 * Check that we are still performing the same component
	 * resync. If not, another node must have completed it
	 * so we have no more work to do.
	 */
	if (un->un_rs_type != old_rs_type) {
		md_unit_readerexit(ui);
		(void) md_unit_writerlock(ui);
		return;
	}
	/*
	 * Adjust resync_done, resync_2_do, start of resync area and count to
	 * skip already resync'd data. We need to recalculate resync_done as
	 * we have dropped the unit lock above and may have lost ownership to
	 * another node, with a different resync buffer size and it may have
	 * sent us new values of resync_done and resync_2_do based on its
	 * resync buffer size
	 */
	recalc_resync_done(un, resync_2_do, initblock, blk_size, skip);
	un->un_rs_resync_2_do = resync_2_do;
	count -= un->un_rs_resync_done;
	block = initblock + ((blk_size + skip) * (int)un->un_rs_resync_done);

	un->un_rs_dropped_lock = 1;
	while ((count > 0) && (broke_out != RESYNC_ERR)) {
		old_rs_done = un->un_rs_resync_done;
		/*
		 * For MN mirrors send a message to the other nodes. This
		 * message includes the size of the region that must be blocked
		 * for all writes
		 */
		if (MD_MNSET_SETNO(setno)) {
			if ((un->un_rs_resync_done%blks == 0)) {
				un->un_resync_startbl = block;
				send_mn_resync_next_message(un, block,
				    (blk_size+skip)*blks, flags1);
				flags1 = 0;
				/*
				 * check to see if we've been asked to
				 * terminate
				 */
				if (resync_kill_pending(un,
				    MDI_UNIT(MD_SID(un)), MD_READER_HELD)) {
					if (un->c.un_status &
					    MD_UN_RESYNC_CANCEL) {
						broke_out = RESYNC_ERR;
						break;
					}
				}

				/*
				 * Check that we are still performing the same
				 * component resync. If not, another node must
				 * have completed it so we have no more work to
				 * do. Also reset count to remaining resync as
				 * we may have lost ownership in in
				 * send_mn_resync_next_message while another
				 * node continued with the resync and
				 * incremented resync_done.
				 */
				if (un->un_rs_type != old_rs_type) {
					md_unit_readerexit(ui);
					(void) md_unit_writerlock(ui);
					return;
				}
				/*
				 * recalculate resync_done, resync_2_do
				 * We need to recalculate resync_done as
				 * we have dropped the unit lock in
				 * send_mn_resync_next_message above and may
				 * have lost ownership to another node, with a
				 * different resync buffer size and it may have
				 * sent us new values of resync_done and
				 * resync_2_do based on its resync buffer size
				 */
				recalc_resync_done(un, resync_2_do, initblock,
				    blk_size, skip);
				un->un_rs_resync_2_do = resync_2_do;
				count = un->un_rs_resync_2_do -
				    un->un_rs_resync_done;
				/*
				 * Adjust start of resync area to skip already
				 * resync'd data
				 */
				block = initblock + ((blk_size + skip) *
				    (int)un->un_rs_resync_done);
				old_rs_done = un->un_rs_resync_done;
			}
		}
		err = resync_read_blk_range(un, block, block + size,
		    MD_READER_HELD, MD_RESYNC_FLAG_ERR);

		/* resync_read_blk_range releases/grabs a new lock */
		un = (mm_unit_t *)MD_UNIT(mnum);

		if (err) {
			broke_out = RESYNC_ERR;
			break;
		}
		/*
		 * If we are no longer resyncing this component, return as
		 * another node has progressed the resync.
		 */
		if (un->un_rs_type != old_rs_type) {
			md_unit_readerexit(ui);
			(void) md_unit_writerlock(ui);
			return;
		}

		/*
		 * recalculate resync_done, resync_2_do. We need to recalculate
		 * resync_done as we have dropped the unit lock in
		 * resync_read_blk_range above and may have lost ownership to
		 * another node, with a different resync buffer size and it may
		 * have sent us new values of resync_done and resync_2_do based
		 * on its resync buffer size
		 */
		recalc_resync_done(un, resync_2_do, initblock, blk_size, skip);
		un->un_rs_resync_2_do = resync_2_do;

		/*
		 * Reset count to remaining resync as we may have blocked in
		 * resync_read_blk_range while another node continued
		 * with the resync and incremented resync_done. Also adjust
		 * start of resync area to skip already resync'd data.
		 */
		count = un->un_rs_resync_2_do - un->un_rs_resync_done;
		block = initblock +((blk_size + skip) *
		    (int)un->un_rs_resync_done);

		/*
		 * If we are picking up from another node, we retry the last
		 * block otherwise step on to the next block
		 */
		if (old_rs_done == un->un_rs_resync_done) {
			block += blk_size + skip;
			un->un_rs_resync_done++;
			count--;
		}

		if ((count == 1) && frag)
			size = frag;
		if (shared->ms_state == CS_ERRED) {
			err = 1;
			broke_out = RESYNC_ERR;
			break;
		}

		/* Check to see if we've completed the resync cleanly */
		if (un->un_rs_thread_flags & MD_RI_SHUTDOWN)
			break;
	}

	md_unit_readerexit(ui);
	un = (mm_unit_t *)md_unit_writerlock(ui);

	/*
	 * If MN set send message to all nodes to indicate resync
	 * phase is complete. The processing of the message will update the
	 * mirror state
	 */
	if (MD_MNSET_SETNO(setno)) {
		send_mn_resync_done_message(un, broke_out);
	} else {
		un->c.un_status &= ~MD_UN_WAR;
		sm->sm_flags &= ~MD_SM_RESYNC_TARGET;

		if (err)
			shared->ms_flags |= MDM_S_RS_TRIED;
		else
			/*
			 * As we don't transmit the changes,
			 * no need to drop the lock.
			 */
			set_sm_comp_state(un, smi, ci, CS_OKAY, 0,
			    MD_STATE_NO_XMIT, (IOLOCK *)NULL);
	}

	/* For MN sets, resync NOTIFY is done when processing resync messages */
	if (!MD_MNSET_SETNO(setno)) {
		if (broke_out) {
			SE_NOTIFY(EC_SVM_STATE, ESC_SVM_RESYNC_FAILED,
			    SVM_TAG_METADEVICE, setno, MD_SID(un));
		} else {
			SE_NOTIFY(EC_SVM_STATE, ESC_SVM_RESYNC_DONE,
			    SVM_TAG_METADEVICE, setno, MD_SID(un));
		}
		SET_RS_TYPE_NONE(un->un_rs_type);
	}
}

static void
submirror_resync(mm_unit_t *un)
{
	mdi_unit_t		*ui;
	minor_t			mnum;
	mm_submirror_t		*sm;
	mm_submirror_ic_t	*smic;
	int			smi;
	diskaddr_t		chunk;
	diskaddr_t		curblk;
	int			err;
	int			cnt;
	set_t			setno;
	int			broke_out = 0;
	int			i;
	int			flags1 = MD_FIRST_RESYNC_NEXT;
	int			compcnt;

	mnum = MD_SID(un);
	ui = MDI_UNIT(mnum);
	setno = MD_UN2SET(un);

	/*
	 * If the submirror_index is non-zero, we are continuing a resync
	 * so restart resync from last submirror marked as being resynced.
	 */
	if (RS_SMI(un->un_rs_type) != 0) {
		smi = RS_SMI(un->un_rs_type);
		sm = &un->un_sm[smi];
		smic = &un->un_smic[smi];
		if (!SMS_IS(sm, SMS_ATTACHED_RESYNC)) {
			for (smi = 0; smi < NMIRROR; smi++) {
				sm = &un->un_sm[smi];
				smic = &un->un_smic[smi];
				if (SMS_IS(sm, SMS_ATTACHED_RESYNC))
					break;
			}
		}
	} else {
		for (smi = 0; smi < NMIRROR; smi++) {
			sm = &un->un_sm[smi];
			smic = &un->un_smic[smi];
			if (SMS_IS(sm, SMS_ATTACHED_RESYNC))
				break;
		}
	}
	if (smi == NMIRROR) {
		SET_RS_TYPE_NONE(un->un_rs_type);
		return;
	}

	/*
	 * If we've only got one component we can fail on a resync write
	 * if an error is encountered. This stops an unnecessary read of the
	 * whole mirror on a target write error.
	 */
	compcnt = (*(smic->sm_get_component_count))(sm->sm_dev, sm);
	if (compcnt == 1)
		flags1 |= MD_RESYNC_FLAG_ERR;

	un->c.un_status |= MD_UN_WAR;
	sm->sm_flags |= MD_SM_RESYNC_TARGET;
	SET_RS_SMI(un->un_rs_type, smi);
	md_unit_writerexit(ui);

	/* For MN sets, resync NOTIFY is done when processing resync messages */
	if (!MD_MNSET_SETNO(setno)) {
		SE_NOTIFY(EC_SVM_STATE, ESC_SVM_RESYNC_START,
		    SVM_TAG_METADEVICE, setno, MD_SID(un));
	}
	un = (mm_unit_t *)md_unit_readerlock(ui);

	un->un_rs_dropped_lock = 1;

	/* check to see if we've been asked to terminate */
	if (resync_kill_pending(un, MDI_UNIT(MD_SID(un)), MD_READER_HELD)) {
		if (un->c.un_status & MD_UN_RESYNC_CANCEL)
			broke_out = RESYNC_ERR;
	}
	/*
	 * Check that we are still performing the same submirror
	 * resync. If not, another node must have completed it
	 * so we have no more work to do.
	 */
	if (RS_TYPE(un->un_rs_type) != MD_RS_SUBMIRROR) {
		md_unit_readerexit(ui);
		(void) md_unit_writerlock(ui);
		return;
	}

	/* if > 1TB mirror, increase percent done granularity */
	if (un->c.un_total_blocks > MD_MAX_BLKS_FOR_SMALL_DEVS)
		chunk = un->c.un_total_blocks / 1000;
	else
		chunk = un->c.un_total_blocks / 100;
	if (chunk == 0)
		chunk = un->c.un_total_blocks;
	/*
	 * If a MN set, round the chunk size up to a multiple of
	 * MD_DEF_RESYNC_BLK_SZ
	 */
	if (MD_MNSET_SETNO(setno)) {
		chunk = ((chunk + MD_DEF_RESYNC_BLK_SZ)/MD_DEF_RESYNC_BLK_SZ)
		    * MD_DEF_RESYNC_BLK_SZ;
		if (chunk > un->c.un_total_blocks)
			chunk = un->c.un_total_blocks;
	}
	/*
	 * Handle restartable resyncs that continue from where the previous
	 * resync left off. The new resync range is from un_rs_resync_done ..
	 * un_rs_resync_2_do
	 */
	curblk = 0;
	if (un->un_rs_resync_done == 0) {
		un->un_rs_resync_2_do = un->c.un_total_blocks;
	} else {
		curblk = un->un_rs_resync_done;
	}
	while ((curblk != un->c.un_total_blocks) && (broke_out != RESYNC_ERR)) {
		diskaddr_t	rs_done;

		rs_done = un->un_rs_resync_done;
		err = resync_read_blk_range(un, curblk, curblk + chunk,
		    MD_READER_HELD, MD_SEND_MESS_XMIT | flags1);
		flags1 = (compcnt == 1 ? MD_RESYNC_FLAG_ERR : 0);

		/* resync_read_blk_range releases/grabs a new lock */
		un = (mm_unit_t *)MD_UNIT(mnum);

		if (err) {
			broke_out = RESYNC_ERR;
			break;
		}

		/*
		 * If we are no longer executing a submirror resync, return
		 * as another node has completed the submirror resync.
		 */
		if (RS_TYPE(un->un_rs_type) != MD_RS_SUBMIRROR) {
			md_unit_readerexit(ui);
			(void) md_unit_writerlock(ui);
			return;
		}
		/*
		 * If resync_done has changed, we must have blocked
		 * in resync_read_blk_range while another node
		 * continued with the resync so restart from resync_done.
		 */
		if (rs_done != un->un_rs_resync_done) {
			curblk = un->un_rs_resync_done;
		} else {
			curblk += chunk;
			un->un_rs_resync_done = curblk;
		}

		if ((curblk + chunk) > un->c.un_total_blocks)
			chunk = un->c.un_total_blocks - curblk;
		for (i = 0, cnt = 0; i < NMIRROR; i++)
			if (SUBMIRROR_IS_WRITEABLE(un, i) &&
			    !SMS_BY_INDEX_IS(un, i, SMS_ALL_ERRED) &&
			    (un->un_sm[i].sm_flags & MD_SM_RESYNC_TARGET))
				cnt++;
		if (cnt == 0) {
			broke_out = RESYNC_ERR;
			break;
		}

		/* Check to see if we've completed the resync cleanly */
		if (un->un_rs_thread_flags & MD_RI_SHUTDOWN)
			break;
	}
	md_unit_readerexit(ui);
	un = (mm_unit_t *)md_unit_writerlock(ui);

	/*
	 * If MN set send message to all nodes to indicate resync
	 * phase is complete. The processing of the message will update the
	 * mirror state
	 */
	if (MD_MNSET_SETNO(setno)) {
		send_mn_resync_done_message(un, broke_out);
	} else {
		sm->sm_flags &= ~MD_SM_RESYNC_TARGET;
		if (err) {
			mirror_set_sm_state(sm, smic, SMS_ATTACHED, 1);
		} else {
			mirror_set_sm_state(sm, smic, SMS_RUNNING, 0);
		}
		un->c.un_status &= ~MD_UN_WAR;
		mirror_commit(un, SMI2BIT(smi), 0);
	}

	/* For MN sets, resync NOTIFY is done when processing resync messages */
	if (!MD_MNSET_SETNO(setno)) {
		if (broke_out) {
			SE_NOTIFY(EC_SVM_STATE, ESC_SVM_RESYNC_FAILED,
			    SVM_TAG_METADEVICE, setno, MD_SID(un));
		} else {
			SE_NOTIFY(EC_SVM_STATE, ESC_SVM_RESYNC_DONE,
			    SVM_TAG_METADEVICE, setno, MD_SID(un));
		}
	}
}

static void
component_resync(mm_unit_t *un)
{
	mm_submirror_t		*sm;
	mm_submirror_ic_t	*smic;
	int			ci;
	int			i;
	int			compcnt;

	/*
	 * Handle the case where we are picking up a partially complete
	 * component resync. In this case un_rs_type contains the submirror
	 * and component index of where we should restart the resync.
	 */
	while (un->un_rs_type != MD_RS_COMPONENT) {
		i = RS_SMI(un->un_rs_type);
		ci = RS_CI(un->un_rs_type);
		check_comp_4_resync(un, i, ci);
		if (resync_kill_pending(un, MDI_UNIT(MD_SID(un)),
		    MD_WRITER_HELD))
			return;
		/*
		 * If we have no current resync, contine to scan submirror and
		 * components. If the resync has moved on to another component,
		 * restart it and if the resync is no longer a component
		 * resync, just exit
		 */
		if (RS_TYPE(un->un_rs_type) == MD_RS_NONE)
			break;
		if (RS_TYPE(un->un_rs_type) != MD_RS_COMPONENT)
			return;
	}
	/* Now continue scanning _all_ submirrors and components */
	for (i = 0; i < NMIRROR; i++) {
		sm = &un->un_sm[i];
		smic = &un->un_smic[i];
		if (!SMS_IS(sm, SMS_RUNNING | SMS_LIMPING))
			continue;
		compcnt = (*(smic->sm_get_component_count))(sm->sm_dev, sm);
		for (ci = 0; ci < compcnt; ci++) {
			SET_RS_SMI(un->un_rs_type, i);
			SET_RS_CI(un->un_rs_type, ci);
			SET_RS_TYPE(un->un_rs_type, MD_RS_COMPONENT);
			check_comp_4_resync(un, i, ci);
			/* Bail out if we've been asked to abort/shutdown */
			if (resync_kill_pending(un, MDI_UNIT(MD_SID(un)),
			    MD_WRITER_HELD))
				return;
			/*
			 * Now check if another node has continued with the
			 * resync, if we are no longer in component resync,
			 * exit, otherwise update to the current component - 1
			 * so that the next call of check_comp_4 resync() will
			 * resync the current component.
			 */
			if ((RS_TYPE(un->un_rs_type) != MD_RS_NONE) &&
			    (RS_TYPE(un->un_rs_type) != MD_RS_COMPONENT))
				return;
			else {
				if (RS_SMI(un->un_rs_type) != i) {
					i = RS_SMI(un->un_rs_type);
					ci = RS_CI(un->un_rs_type) - 1;
				} else if (RS_CI(un->un_rs_type) != ci)
					ci = RS_CI(un->un_rs_type) - 1;
			}
		}
	}
}

static void
reset_comp_flags(mm_unit_t *un)
{
	mm_submirror_t		*sm;
	mm_submirror_ic_t	*smic;
	md_m_shared_t		*shared;
	int			ci;
	int			i;
	int			compcnt;

	for (i = 0; i < NMIRROR; i++) {
		sm = &un->un_sm[i];
		smic = &un->un_smic[i];
		if (!SMS_IS(sm, SMS_INUSE))
			continue;
		compcnt = (*(smic->sm_get_component_count))(sm->sm_dev, sm);
		for (ci = 0; ci < compcnt; ci++) {
			shared = (md_m_shared_t *)(*(smic->sm_shared_by_indx))
			    (sm->sm_dev, sm, ci);
			shared->ms_flags &= ~MDM_S_RS_TRIED;
		}
	}
}

/*
 * resync_progress_thread:
 * ----------------------
 * Thread started on first resync of a unit which simply blocks until woken up
 * by a cv_signal, and then updates the mddb for the mirror unit record. This
 * saves the resync progress information (un_rs_resync_done, un_rs_resync_2_do)
 * so that an aborted resync can be continued after an intervening reboot.
 */
static void
resync_progress_thread(minor_t mnum)
{
	mm_unit_t	*un = MD_UNIT(mnum);
	mdi_unit_t	*ui = MDI_UNIT(mnum);
	set_t		setno = MD_MIN2SET(mnum);

	while (un->c.un_status & MD_UN_RESYNC_ACTIVE) {
		mutex_enter(&un->un_rs_progress_mx);
		cv_wait(&un->un_rs_progress_cv, &un->un_rs_progress_mx);
		mutex_exit(&un->un_rs_progress_mx);
		if (un->un_rs_progress_flags & MD_RI_KILL)
			break;

		/*
		 * Commit mirror unit if we're the Master node in a multi-node
		 * environment
		 */
		if (MD_MNSET_SETNO(setno) && md_set[setno].s_am_i_master) {
			(void) md_unit_readerlock(ui);
			mirror_commit(un, NO_SUBMIRRORS, 0);
			md_unit_readerexit(ui);
		}
	}
	thread_exit();
}

/*
 * resync_progress:
 * ---------------
 * Timeout handler for updating the progress of the resync thread.
 * Simply wake up the resync progress daemon which will then mirror_commit() the
 * unit structure to the mddb. This snapshots the current progress of the resync
 */
static void
resync_progress(void *arg)
{
	mm_unit_t	*un = (mm_unit_t *)arg;
	mdi_unit_t	*ui = MDI_UNIT(MD_SID(un));
	uint_t		active;

	mutex_enter(&un->un_rs_progress_mx);
	cv_signal(&un->un_rs_progress_cv);
	mutex_exit(&un->un_rs_progress_mx);

	/* schedule the next timeout if the resync is still marked active */
	(void) md_unit_readerlock(ui);
	active = un->c.un_status & MD_UN_RESYNC_ACTIVE ? 1 : 0;
	md_unit_readerexit(ui);
	if (active) {
		un->un_rs_resync_to_id = timeout(resync_progress, un,
		    (clock_t)(drv_usectohz(60000000) *
		    md_mirror_resync_update_intvl));
	}
}

/*
 * resync_unit:
 * -----------
 * Resync thread which drives all forms of resync (optimized, component,
 * submirror). Must handle thread suspension and kill to allow multi-node
 * resync to run without undue ownership changes.
 *
 * For a MN set, the reync mechanism is as follows:
 *
 * When a resync is started, either via metattach, metaonline, metareplace,
 * metasync or by a hotspare kicking in, a message is sent to all nodes, which
 * calls mirror_resync_thread. If there is currently no mirror owner, the
 * master node sends a CHOOSE_OWNER message to the handler on the master. This
 * chooses a mirror owner and sends a CHANGE_OWNER message requesting the
 * selected node to become the owner.
 * If this node is not the owner it sets itself to block in resync_kill_pending
 * and if there is no owner all nodes will block until the chosen owner is
 * selected, in which case it will unblock itself. So, on entry to this
 * function only one node will continue past resync_kill_pending().
 * Once the resync thread is started, it basically cycles through the optimized,
 * component and submirrors resyncs until there is no more work to do.
 *
 * For an ABR mirror, once a mirror owner is chosen it will complete the resync
 * unless the nodes dies in which case a new owner will be chosen and it will
 * have to complete the resync from the point at which the previous owner died.
 * To do this we broadcast a RESYNC_NEXT message before each region to be
 * resynced and this message contains the address and length of the region
 * being resynced and the current progress through the resync. The size of
 * this region is MD_DEF_RESYNC_BLK_SZ blocks. It is larger than the resync
 * block size to limit the amount of inter node traffic. The RESYNC_NEXT
 * message also indicates to all other nodes that all writes to this block
 * must be blocked until the next RESYNC_NEXT message is received. This ensures
 * that no node can write to a block that is being resynced. For all MN
 * mirrors we also block the whole resync region on the resync owner node so
 * that all writes to the resync region are blocked on all nodes. There is a
 * difference here between a MN set and a regular set in that for a MN set
 * we protect the mirror from writes to the current resync block by blocking
 * a larger region. For a regular set we just block writes to the current
 * resync block.
 *
 * For a non-ABR mirror the same RESYNC_NEXT message is sent with an
 * additional purpose. In this case, there is only one mirror owner at a time
 * and rather than continually switching ownership between the chosen mirror
 * owner and the node that is writing to the mirror, we move the resync to the
 * mirror owner. When we swich ownership, we block the old owner and unblock
 * the resync thread on the new owner. To enable the new owner to continue the
 * resync, all nodes need to have the latest resync status, Then, following each
 * resync write, we check to see if the resync state has changed and if it
 * has this must be because we have lost ownership to another node(s) for a
 * period and then have become owner again later in the resync process. If we
 * are still dealing with the same resync, we just adjust addresses and counts
 * and then continue. If the resync has moved on to a different type, for
 * example from an optimized to a submirror resync, we move on to process the
 * resync described by rs_type and continue from the position described by
 * resync_done and resync_startbl.
 *
 * Note that for non-ABR mirrors it is possible for a write to be made on a
 * non resync-owner node without a change of ownership. This is the case when
 * the mirror has a soft part created on it and a write in ABR mode is made
 * to that soft part. Therefore we still need to block writes to the resync
 * region on all nodes.
 *
 * Sending the latest resync state to all nodes also enables them to continue
 * a resync in the event that the mirror owner dies. If a mirror owner for
 * a non-ABR mirror has died, there will be dirty resync regions. Therefore,
 * regardless of whether another type of resync was in progress, we must first
 * do an optimized resync to clean up the dirty regions before continuing
 * with the interrupted resync.
 *
 * The resync status is held in the unit structure
 * On disk
 * un_rs_resync_done	The number of contiguous resyc blocks done so far
 * un_rs_resync_2_do	The total number of contiguous resync blocks
 * un_rs_type		The resync type (inc submirror and component numbers)
 * In core
 * un_resync_startbl	The address of the current resync block being processed
 *
 * In the event that the whole cluster fails we need to just use
 * un_rs_resync_done to restart the resync and to ensure that this is
 * periodically written to disk, we have a thread which writes the record
 * to disk every 5 minutes. As the granularity of un_rs_resync_done is
 * usually coarse ( for an optimized resync 1001 is the max value) there is
 * little point in writing this more frequently.
 */
static void
resync_unit(minor_t mnum)
{
	mdi_unit_t	*ui;
	mm_unit_t	*un;
	md_error_t	mde = mdnullerror;
	int		mn_resync = 0;
	int		resync_finish = 0;
	set_t		setno = MD_MIN2SET(mnum);
	uint_t		old_rs_type = MD_RS_NONE;
	uint_t		old_rs_done = 0, old_rs_2_do = 0;
	uint_t		old_rs_startbl = 0;
	int		block_resync = 1;
	char		cpr_name[23];	/* Unique CPR name */
	int		rs_copysize;
	char		*rs_buffer;

resync_restart:
#ifdef DEBUG
	if (mirror_debug_flag)
		printf("Resync started (mnum = %x)\n", mnum);
#endif
	/*
	 * increment the mirror resync count
	 */
	mutex_enter(&md_cpr_resync.md_resync_mutex);
	md_cpr_resync.md_mirror_resync++;
	mutex_exit(&md_cpr_resync.md_resync_mutex);

	ui = MDI_UNIT(mnum);
	un = MD_UNIT(mnum);

	rs_copysize = un->un_rs_copysize;
	if (rs_copysize == 0) {
		/*
		 * Don't allow buffer size to fall outside the
		 * range 0 < bufsize <= md_max_xfer_bufsz.
		 */
		if (md_resync_bufsz <= 0)
			md_resync_bufsz = MD_DEF_RESYNC_BUF_SIZE;
		rs_copysize = MIN(md_resync_bufsz, md_max_xfer_bufsz);
	}
	rs_buffer = kmem_zalloc(dbtob(rs_copysize), KM_SLEEP);
	un = md_unit_writerlock(ui);
	un->un_rs_copysize = rs_copysize;
	un->un_rs_buffer = rs_buffer;

	if (MD_MNSET_SETNO(setno)) {
		/*
		 * Register this resync thread with the CPR mechanism. This
		 * allows us to detect when the system is suspended and so
		 * keep track of the RPC failure condition.
		 */
		(void) snprintf(cpr_name, sizeof (cpr_name),
		    "mirror_resync%x", mnum);
		CALLB_CPR_INIT(&un->un_rs_cprinfo, &un->un_rs_cpr_mx,
		    callb_md_mrs_cpr, cpr_name);

		if (ui->ui_tstate & MD_RESYNC_NOT_DONE) {
			/*
			 * If this is the first resync following the initial
			 * snarf (MD_RESYNC_NOT_DONE still set) and we've
			 * been started outside a reconfig step (e.g. by being
			 * added to an existing set) we need to query the
			 * existing submirror state for this mirror.
			 * The set_status flags will have MD_MN_SET_MIR_STATE_RC
			 * set if we've been through a step4 reconfig, so only
			 * query the master if this isn't (yet) set. In this
			 * case we must continue the resync thread as there is
			 * not guaranteed to be a currently running resync on
			 * any of the other nodes. Worst case is that we will
			 * initiate an ownership change to this node and then
			 * find that there is no resync to perform. However, we
			 * will then have correct status across the cluster.
			 */
			if (!md_set[setno].s_am_i_master) {
				if (!(md_get_setstatus(setno) &
				    MD_SET_MN_MIR_STATE_RC)) {
					mirror_get_status(un, NULL);
					block_resync = 0;
#ifdef DEBUG
					if (mirror_debug_flag) {
						mm_submirror_t *sm;
						int i;
						for (i = 0; i < NMIRROR; i++) {
							sm = &un->un_sm[i];
							printf(
							    "sm[%d] state=%4x"
							    " flags=%4x\n", i,
							    sm->sm_state,
							    sm->sm_flags);
						}
					}
#endif
				}
			}
			ui->ui_tstate &= ~MD_RESYNC_NOT_DONE;
		}
		/*
		 * For MN set, if we have an owner, then start the resync on it.
		 * If there is no owner the master must send a message to
		 * choose the owner. This message will contain the current
		 * resync count and it will only be sent to the master, where
		 * the resync count will be used to choose the next node to
		 * perform a resync, by cycling through the nodes in the set.
		 * The message handler will then send a CHANGE_OWNER message to
		 * all nodes, and on receipt of that message, the chosen owner
		 * will issue a SET_OWNER ioctl to become the owner. This ioctl
		 * will be requested to spawn a thread to issue the
		 * REQUEST_OWNER message to become the owner which avoids the
		 * need for concurrent ioctl requests.
		 * After sending the message, we will block waiting for one
		 * of the nodes to become the owner and start the resync
		 */
		if (MD_MN_NO_MIRROR_OWNER(un)) {
			/*
			 * There is no owner, block and then the master will
			 * choose the owner. Only perform this if 'block_resync'
			 * is set.
			 */
			if (block_resync) {
				mutex_enter(&un->un_rs_thread_mx);
				un->un_rs_thread_flags |= MD_RI_BLOCK_OWNER;
				mutex_exit(&un->un_rs_thread_mx);
			}
			if (md_set[setno].s_am_i_master) {
				md_unit_writerexit(ui);
				(void) mirror_choose_owner(un, NULL);
				(void) md_unit_writerlock(ui);
			}
		} else {
			/* There is an owner, block if we are not it */
			if (!MD_MN_MIRROR_OWNER(un)) {
				mutex_enter(&un->un_rs_thread_mx);
				un->un_rs_thread_flags |= MD_RI_BLOCK_OWNER;
				mutex_exit(&un->un_rs_thread_mx);
			}
		}
	}
	/*
	 * Start a timeout chain to update the resync progress to the mddb.
	 * This will run every md_mirror_resync_update_intvl minutes and allows
	 * a resync to be continued over a reboot.
	 */
	ASSERT(un->un_rs_resync_to_id == 0);
	un->un_rs_resync_to_id = timeout(resync_progress, un,
	    (clock_t)(drv_usectohz(60000000) * md_mirror_resync_update_intvl));

	/*
	 * Handle resync restart from the last logged position. The contents
	 * of un_rs_resync_2_do and un_rs_resync_done are dependent on the
	 * type of resync that was in progress.
	 */
	if (MD_MNSET_SETNO(setno)) {
		switch ((uint_t)RS_TYPE(un->un_rs_type)) {
		case MD_RS_NONE:
		case MD_RS_OPTIMIZED:
		case MD_RS_COMPONENT:
		case MD_RS_SUBMIRROR:
		case MD_RS_ABR:
			break;
		default:
			un->un_rs_type = MD_RS_NONE;
		}
		/* Allocate a resync message, if required */
		if (un->un_rs_msg == NULL) {
			un->un_rs_msg = (md_mn_msg_resync_t *)kmem_zalloc(
			    sizeof (md_mn_msg_resync_t), KM_SLEEP);
		}
		mn_resync = 1;
	}

	/* Check to see if we've been requested to block/kill */
	if (resync_kill_pending(un, ui, MD_WRITER_HELD)) {
		goto bail_out;
	}

	do {
		un->un_rs_dropped_lock = 0;
		/*
		 * Always perform an optimized resync first as this will bring
		 * the mirror into an available state in the shortest time.
		 * If we are resuming an interrupted resync, other than an
		 * optimized resync, we save the type and amount done so that
		 * we can resume the appropriate resync after the optimized
		 * resync has completed.
		 */
		if ((RS_TYPE(un->un_rs_type) != MD_RS_NONE) &&
		    (RS_TYPE(un->un_rs_type) != MD_RS_OPTIMIZED)) {
			old_rs_type = un->un_rs_type;
			old_rs_done = un->un_rs_resync_done;
			old_rs_2_do = un->un_rs_resync_2_do;
			old_rs_startbl = un->un_resync_startbl;
		}
		SET_RS_TYPE(un->un_rs_type, MD_RS_OPTIMIZED);
		/*
		 * If we are continuing a resync that is not an
		 * OPTIMIZED one, then we start from the beginning when
		 * doing this optimized resync
		 */
		if (RS_TYPE(old_rs_type) != MD_RS_OPTIMIZED) {
			un->un_rs_resync_done = 0;
			un->un_rs_resync_2_do = 0;
			un->un_resync_startbl = 0;
		}
		optimized_resync(un);
		/* Check to see if we've been requested to block/kill */
		if (resync_kill_pending(un, ui, MD_WRITER_HELD)) {
			goto bail_out;
		}
		un = (mm_unit_t *)MD_UNIT(mnum);
		/*
		 * If another node has moved the resync on, we must
		 * restart the correct resync
		 */
		if (mn_resync &&
		    (RS_TYPE(un->un_rs_type) != MD_RS_NONE)) {
			old_rs_type = un->un_rs_type;
			old_rs_done = un->un_rs_resync_done;
			old_rs_2_do = un->un_rs_resync_2_do;
			old_rs_startbl = un->un_resync_startbl;
		}

		/*
		 * Restore previous resync progress or move onto a
		 * component resync.
		 */
		if (RS_TYPE(old_rs_type) != MD_RS_NONE) {
			un->un_rs_type = old_rs_type;
			un->un_rs_resync_done = old_rs_done;
			un->un_rs_resync_2_do = old_rs_2_do;
			un->un_resync_startbl = old_rs_startbl;
		} else {
			un->un_rs_type = MD_RS_COMPONENT;
			un->un_rs_resync_done = 0;
			un->un_rs_resync_2_do = 0;
			un->un_resync_startbl = 0;
		}

		if (RS_TYPE(un->un_rs_type) == MD_RS_COMPONENT) {
			component_resync(un);
			/* Check to see if we've been requested to block/kill */
			if (resync_kill_pending(un, ui, MD_WRITER_HELD)) {
				goto bail_out;
			}
			un = (mm_unit_t *)MD_UNIT(mnum);
			/*
			 * If we have moved on from a component resync, another
			 * node must have completed it and started a submirror
			 * resync, so leave the resync state alone. For non
			 * multi-node sets we move onto the submirror resync.
			 */
			if (mn_resync) {
				if (RS_TYPE(un->un_rs_type) == MD_RS_NONE) {
					un->un_rs_type = MD_RS_SUBMIRROR;
					un->un_rs_resync_done =
					    un->un_rs_resync_2_do = 0;
					un->un_resync_startbl = 0;
				}
			} else {
				un->un_rs_type = MD_RS_SUBMIRROR;
				un->un_rs_resync_done = 0;
				un->un_rs_resync_2_do = 0;
				un->un_resync_startbl = 0;
			}
		}
		if (RS_TYPE(un->un_rs_type) == MD_RS_SUBMIRROR) {
			submirror_resync(un);
			/* Check to see if we've been requested to block/kill */
			if (resync_kill_pending(un, ui, MD_WRITER_HELD)) {
				goto bail_out;
			}
			un = (mm_unit_t *)MD_UNIT(mnum);
			/*
			 * If we have moved on from a submirror resync, another
			 * node must have completed it and started a different
			 * resync, so leave the resync state alone
			 */
			if (mn_resync) {
				if (RS_TYPE(un->un_rs_type) == MD_RS_NONE) {
					un->un_rs_resync_done =
					    un->un_rs_resync_2_do = 0;
					un->un_resync_startbl = 0;
				}
			} else {
				/* If non-MN mirror, reinitialize state */
				un->un_rs_type = MD_RS_NONE;
				un->un_rs_resync_done = 0;
				un->un_rs_resync_2_do = 0;
				un->un_resync_startbl = 0;
			}
		}
	} while (un->un_rs_dropped_lock);
	mutex_enter(&un->un_rs_thread_mx);
	un->un_rs_thread_flags |= MD_RI_SHUTDOWN;
	mutex_exit(&un->un_rs_thread_mx);

	resync_finish = 1;
bail_out:
#ifdef DEBUG
	if (mirror_debug_flag)
		printf("Resync stopped (mnum = %x), resync_finish = %d\n",
		    mnum, resync_finish);
#endif
	kmem_free(un->un_rs_buffer, dbtob(un->un_rs_copysize));

	mutex_enter(&un->un_rs_progress_mx);
	un->un_rs_progress_flags |= MD_RI_KILL;
	cv_signal(&un->un_rs_progress_cv);
	mutex_exit(&un->un_rs_progress_mx);

	/*
	 * For MN Set, send a RESYNC_FINISH if this node completed the resync.
	 * There is no need to grow unit here, it will be done in the
	 * handler for the RESYNC_FINISH message together with resetting
	 * MD_UN_RESYNC_ACTIVE.
	 */
	if (mn_resync) {
		if (resync_finish) {
			/*
			 * Normal resync completion. Issue a RESYNC_FINISH
			 * message if we're part of a multi-node set.
			 */
			md_mn_kresult_t	*kres;
			md_mn_msg_resync_t *rmsg;
			int		rval;

			rmsg = (md_mn_msg_resync_t *)un->un_rs_msg;
			md_unit_writerexit(ui);

			rmsg->msg_resync_mnum = mnum;
			rmsg->msg_resync_type = 0;
			rmsg->msg_resync_done = 0;
			rmsg->msg_resync_2_do = 0;
			rmsg->msg_originator = md_mn_mynode_id;

			kres = kmem_alloc(sizeof (md_mn_kresult_t), KM_SLEEP);

			mutex_enter(&un->un_rs_cpr_mx);
			CALLB_CPR_SAFE_BEGIN(&un->un_rs_cprinfo);

			rval = mdmn_ksend_message(setno,
			    MD_MN_MSG_RESYNC_FINISH, MD_MSGF_NO_LOG, 0,
			    (char *)rmsg, sizeof (md_mn_msg_resync_t), kres);

			CALLB_CPR_SAFE_END(&un->un_rs_cprinfo,
			    &un->un_rs_cpr_mx);
			mutex_exit(&un->un_rs_cpr_mx);

			if (!MDMN_KSEND_MSG_OK(rval, kres)) {
				mdmn_ksend_show_error(rval, kres,
				    "RESYNC_FINISH");
				/* If we're shutting down, pause things here. */
				if (kres->kmmr_comm_state == MDMNE_RPC_FAIL) {
					while (!md_mn_is_commd_present()) {
						delay(md_hz);
					}
				}
				cmn_err(CE_PANIC,
				    "ksend_message failure: RESYNC_FINISH");
			}
			kmem_free(kres, sizeof (md_mn_kresult_t));
			(void) md_unit_writerlock(ui);
		}
		/*
		 * If the resync has been cancelled, clear flags, reset owner
		 * for ABR mirror and release the resync region parent
		 * structure.
		 */
		if (un->c.un_status & MD_UN_RESYNC_CANCEL) {
			md_mps_t	*ps;

			if (ui->ui_tstate & MD_ABR_CAP) {
				/* Resync finished, if ABR set owner to NULL */
				mutex_enter(&un->un_owner_mx);
				un->un_mirror_owner = 0;
				mutex_exit(&un->un_owner_mx);
			}

			un->c.un_status &= ~(MD_UN_RESYNC_CANCEL |
			    MD_UN_RESYNC_ACTIVE);
			ps = un->un_rs_prev_overlap;
			if (ps != NULL) {
				/* Remove previous overlap resync region */
				if (ps->ps_flags & MD_MPS_ON_OVERLAP)
				mirror_overlap_tree_remove(ps);
				/*
				 * Release the overlap range reference
				 */
				un->un_rs_prev_overlap = NULL;
				kmem_cache_free(mirror_parent_cache,
				    ps);
			}
		}

		/*
		 * Release resync message buffer. This will be reallocated on
		 * the next invocation of the resync_unit thread.
		 */
		if (un->un_rs_msg) {
			kmem_free(un->un_rs_msg, sizeof (md_mn_msg_resync_t));
			un->un_rs_msg = NULL;
		}
	} else {
		/* For non-MN sets deal with any pending grows */
		un->c.un_status &= ~MD_UN_RESYNC_ACTIVE;
		if (un->c.un_status & MD_UN_GROW_PENDING) {
			if ((mirror_grow_unit(un, &mde) != 0) ||
			    (! mdismderror(&mde, MDE_GROW_DELAYED))) {
				un->c.un_status &= ~MD_UN_GROW_PENDING;
			}
		}
	}

	reset_comp_flags(un);
	un->un_resync_completed = 0;
	mirror_commit(un, NO_SUBMIRRORS, 0);
	md_unit_writerexit(ui);

	/*
	 * Stop the resync progress thread.
	 */
	if (un->un_rs_resync_to_id != 0) {
		(void) untimeout(un->un_rs_resync_to_id);
		un->un_rs_resync_to_id = 0;
	}

	/*
	 * Calling mirror_internal_close() makes further reference to un / ui
	 * dangerous. If we are the only consumer of the mirror it is possible
	 * for a metaclear to be processed after completion of the m_i_c()
	 * routine. As we need to handle the case where another resync has been
	 * scheduled for the mirror, we raise the open count on the device
	 * which protects against the close / metaclear / lock => panic scenario
	 */
	(void) md_unit_incopen(MD_SID(un), FREAD|FWRITE, OTYP_LYR);
	(void) mirror_internal_close(MD_SID(un), OTYP_LYR, 0, (IOLOCK *)NULL);

	/*
	 * deccrement the mirror resync count
	 */
	mutex_enter(&md_cpr_resync.md_resync_mutex);
	md_cpr_resync.md_mirror_resync--;
	mutex_exit(&md_cpr_resync.md_resync_mutex);

	/*
	 * Remove the thread reference as we're about to exit. This allows a
	 * subsequent mirror_resync_unit() to start a new thread.
	 * If RESYNC_ACTIVE is set, mirror_resync_unit() must have been
	 * called to start a new resync, so reopen the mirror and go back to
	 * the start.
	 */
	(void) md_unit_writerlock(ui);
	mutex_enter(&un->un_rs_thread_mx);
	un->un_rs_thread_flags &= ~(MD_RI_KILL|MD_RI_SHUTDOWN);
	mutex_exit(&un->un_rs_thread_mx);
	if (un->c.un_status & MD_UN_RESYNC_ACTIVE) {
		md_unit_writerexit(ui);
		if (mirror_internal_open(MD_SID(un), (FREAD|FWRITE),
		    OTYP_LYR, 0, (IOLOCK *)NULL) == 0) {
			/* Release the reference grabbed above */
			(void) mirror_internal_close(MD_SID(un), OTYP_LYR, 0,
			    (IOLOCK *)NULL);
			goto resync_restart;
		}
		(void) md_unit_writerlock(ui);
		cmn_err(CE_NOTE,
		    "Could not open metadevice (%x) for resync\n",
		    MD_SID(un));
	}
	un->un_rs_thread = NULL;
	md_unit_writerexit(ui);

	/*
	 * Check for hotspares once we've cleared the resync thread reference.
	 * If there are any errored units a poke_hotspares() will result in
	 * a call to mirror_resync_unit() which we need to allow to start.
	 */
	(void) poke_hotspares();

	/*
	 * Remove this thread from the CPR callback table.
	 */
	if (mn_resync) {
		mutex_enter(&un->un_rs_cpr_mx);
		CALLB_CPR_EXIT(&un->un_rs_cprinfo);
	}

	/*
	 * Remove the extra reference to the unit we generated above. After
	 * this call it is *unsafe* to reference either ui or un as they may
	 * no longer be allocated.
	 */
	(void) mirror_internal_close(MD_SID(un), OTYP_LYR, 0, (IOLOCK *)NULL);

	thread_exit();
}

/*
 * mirror_resync_unit:
 * ------------------
 * Start a resync for the given mirror metadevice. Save the resync thread ID in
 * un->un_rs_thread for later manipulation.
 *
 * Returns:
 *	0	Success
 *	!=0	Error
 */
/*ARGSUSED*/
int
mirror_resync_unit(
	minor_t			mnum,
	md_resync_ioctl_t	*ri,
	md_error_t		*ep,
	IOLOCK			*lockp
)
{
	mdi_unit_t		*ui;
	mm_unit_t		*un;
	set_t			setno = MD_MIN2SET(mnum);

	ui = MDI_UNIT(mnum);

	if (md_get_setstatus(setno) & MD_SET_STALE)
		return (mdmddberror(ep, MDE_DB_STALE, mnum, setno));

	if (mirror_internal_open(mnum, (FREAD|FWRITE), OTYP_LYR, 0, lockp)) {
		return (mdmderror(ep, MDE_MIRROR_OPEN_FAILURE, mnum));
	}
	if (lockp) {
		un = (mm_unit_t *)md_ioctl_writerlock(lockp, ui);
	} else {
		un = (mm_unit_t *)md_unit_writerlock(ui);
	}

	/*
	 * Check to see if we're attempting to start a resync while one is
	 * already running.
	 */
	if (un->c.un_status & MD_UN_RESYNC_ACTIVE ||
	    un->un_rs_thread != NULL) {
		/*
		 * Ensure RESYNC_ACTIVE set, it may not be if the resync thread
		 * is in the process of terminating, setting the flag will
		 * cause the resync thread to return to the beginning
		 */
		un->c.un_status |= MD_UN_RESYNC_ACTIVE;
		if (lockp) {
			md_ioctl_writerexit(lockp);
		} else {
			md_unit_writerexit(ui);
		}
		(void) mirror_internal_close(mnum, OTYP_LYR, 0, lockp);
		return (0);
	}
	un->c.un_status |= MD_UN_RESYNC_ACTIVE;
	un->c.un_status &= ~MD_UN_RESYNC_CANCEL;
	if ((ri) && (ri->ri_copysize > 0) &&
	    (ri->ri_copysize <= md_max_xfer_bufsz))
		un->un_rs_copysize = ri->ri_copysize;
	else
		un->un_rs_copysize = 0;

	/* Start the resync progress thread off */
	un->un_rs_progress_flags = 0;
	(void) thread_create(NULL, 0, resync_progress_thread,
	    (caddr_t)(uintptr_t)mnum, 0, &p0, TS_RUN, minclsyspri);

	/*
	 * We have to store the thread ID in the unit structure so do not
	 * drop writerlock until the thread is active. This means resync_unit
	 * may spin on its first md_unit_readerlock(), but deadlock won't occur.
	 */
	mutex_enter(&un->un_rs_thread_mx);
	un->un_rs_thread_flags &= ~(MD_RI_KILL|MD_RI_SHUTDOWN);
	mutex_exit(&un->un_rs_thread_mx);
	un->un_rs_thread = thread_create(NULL, 0, resync_unit,
	    (caddr_t)(uintptr_t)mnum, 0, &p0, TS_RUN, 60);
	if (un->un_rs_thread == (kthread_id_t)NULL) {
		un->c.un_status &= ~MD_UN_RESYNC_ACTIVE;
		if (lockp) {
			md_ioctl_writerexit(lockp);
		} else {
			md_unit_writerexit(ui);
		}
		(void) mirror_internal_close(mnum, OTYP_LYR, 0, lockp);
		return (mdmderror(ep, MDE_MIRROR_THREAD_FAILURE, mnum));
	} else {
		if (lockp) {
			md_ioctl_writerexit(lockp);
		} else {
			md_unit_writerexit(ui);
		}
	}

	return (0);
}

/*
 * mirror_ioctl_resync:
 * -------------------
 * Called as a result of an MD_IOCSETSYNC ioctl. Either start, block, unblock
 * or kill the resync thread associated with the specified unit.
 * Can return with locks held since mdioctl will free any locks
 * that are marked in lock->l_flags.
 *
 * Returns:
 *	0	Success
 *	!=0	Error Code
 */
int
mirror_ioctl_resync(
	md_resync_ioctl_t	*ri,
	IOLOCK			*lock
)
{
	minor_t			mnum = ri->ri_mnum;
	mm_unit_t		*un;
	uint_t			bits;
	mm_submirror_t		*sm;
	mm_submirror_ic_t	*smic;
	int			smi;
	kt_did_t		tid;
	set_t			setno = MD_MIN2SET(mnum);

	mdclrerror(&ri->mde);

	if ((setno >= md_nsets) ||
	    (MD_MIN2UNIT(mnum) >= md_nunits)) {
		return (mdmderror(&ri->mde, MDE_INVAL_UNIT, mnum));
	}

	/* RD_LOCK flag grabs the md_ioctl_readerlock */
	un = mirror_getun(mnum, &ri->mde, RD_LOCK, lock);

	if (un == NULL) {
		return (mdmderror(&ri->mde, MDE_UNIT_NOT_SETUP, mnum));
	}
	if (un->c.un_type != MD_METAMIRROR) {
		return (mdmderror(&ri->mde, MDE_NOT_MM, mnum));
	}
	if (un->un_nsm < 2) {
		return (0);
	}

	/*
	 * Determine the action to take based on the ri_flags field:
	 * 	MD_RI_BLOCK:	Block current resync thread
	 *	MD_RI_UNBLOCK:	Unblock resync thread
	 *	MD_RI_KILL:	Abort resync thread
	 *	MD_RI_RESYNC_FORCE_MNSTART: Directly start resync thread
	 *		without using rpc.mdcommd messages.
	 *	any other:	Start resync thread
	 */
	switch (ri->ri_flags & (MD_RI_BLOCK|MD_RI_UNBLOCK|MD_RI_KILL)) {

	case MD_RI_BLOCK:
		/* Halt resync thread by setting flag in un_rs_flags */
		if (!(un->c.un_status & MD_UN_RESYNC_ACTIVE)) {
			return (0);
		}
		mutex_enter(&un->un_rs_thread_mx);
		un->un_rs_thread_flags |= MD_RI_BLOCK;
		mutex_exit(&un->un_rs_thread_mx);
		return (0);

	case MD_RI_UNBLOCK:
		/*
		 * Restart resync thread by clearing flag in un_rs_flags and
		 * cv_signal'ing the blocked thread.
		 */
		if (!(un->c.un_status & MD_UN_RESYNC_ACTIVE)) {
			return (0);
		}
		mutex_enter(&un->un_rs_thread_mx);
		un->un_rs_thread_flags &= ~MD_RI_BLOCK;
		cv_signal(&un->un_rs_thread_cv);
		mutex_exit(&un->un_rs_thread_mx);
		return (0);

	case MD_RI_KILL:
		/* Abort resync thread. */
		if (!(un->c.un_status & MD_UN_RESYNC_ACTIVE)) {
			return (0);
		}
		mutex_enter(&un->un_rs_thread_mx);
		tid = un->un_rs_thread ? (un->un_rs_thread)->t_did : 0;
		un->un_rs_thread_flags &= ~(MD_RI_BLOCK|MD_RI_BLOCK_OWNER);
		un->un_rs_thread_flags |= MD_RI_KILL;
		cv_signal(&un->un_rs_thread_cv);
		mutex_exit(&un->un_rs_thread_mx);
		if (tid != 0) {
			if (!(ri->ri_flags & MD_RI_NO_WAIT)) {
				md_ioctl_readerexit(lock);
				thread_join(tid);
				un->un_rs_thread_flags &= ~MD_RI_KILL;
				un->un_rs_thread = NULL;
				cmn_err(CE_WARN, "md: %s: Resync cancelled\n",
				    md_shortname(MD_SID(un)));
			}
		}
		return (0);
	}

	md_ioctl_readerexit(lock);

	bits = 0;
	for (smi = 0; smi < NMIRROR; smi++) {
		sm = &un->un_sm[smi];
		smic = &un->un_smic[smi];
		if (!SMS_IS(sm, SMS_ATTACHED))
			continue;
		mirror_set_sm_state(sm, smic, SMS_ATTACHED_RESYNC, 1);
		bits |= SMI2BIT(smi);
	}
	if (bits != 0)
		mirror_commit(un, bits, 0);

	/*
	 * If we are resyncing a mirror in a MN set and the rpc.mdcommd
	 * can be used, we do not start the resync at this point.
	 * Instead, the metasync command that issued the ioctl
	 * will send a RESYNC_STARTING message to start the resync thread. The
	 * reason we do it this way is to ensure that the metasync ioctl is
	 * executed on all nodes before the resync thread is started.
	 *
	 * If a MN set and the MD_RI_RESYNC_FORCE_MNSTART flag is set, then
	 * don't use rpc.mdcommd, but just start the resync thread.  This
	 * flag is set on a node when it is being added to a diskset
	 * so that the resync threads are started on the newly added node.
	 */
	if ((!(MD_MNSET_SETNO(setno))) ||
	    (ri->ri_flags & MD_RI_RESYNC_FORCE_MNSTART)) {
		return (mirror_resync_unit(mnum, ri, &ri->mde, lock));
	} else {
		return (0);
	}
}

int
mirror_mark_resync_region_non_owner(struct mm_unit *un,
	diskaddr_t startblk, diskaddr_t endblk, md_mn_nodeid_t source_node)
{
	int			no_change;
	size_t			start_rr;
	size_t			current_rr;
	size_t			end_rr;
	md_mn_msg_rr_dirty_t	*rr;
	md_mn_kresult_t		*kres;
	set_t			setno = MD_UN2SET(un);
	int			rval;
	md_mn_nodeid_t		node_idx = source_node - 1;
	mdi_unit_t		*ui = MDI_UNIT(MD_SID(un));
	md_mn_nodeid_t		owner_node;
	minor_t			mnum = MD_SID(un);

	if (un->un_nsm < 2)
		return (0);

	/*
	 * Check to see if we have a un_pernode_dirty_bm[] entry allocated. If
	 * not, allocate it and then fill the [start..end] entries.
	 * Update un_pernode_dirty_sum if we've gone 0->1.
	 * Update un_dirty_bm if the corresponding entries are clear.
	 */
	rw_enter(&un->un_pernode_dirty_mx[node_idx], RW_WRITER);
	if (un->un_pernode_dirty_bm[node_idx] == NULL) {
		un->un_pernode_dirty_bm[node_idx] =
		    (uchar_t *)kmem_zalloc(
		    (uint_t)howmany(un->un_rrd_num, NBBY), KM_SLEEP);
	}
	rw_exit(&un->un_pernode_dirty_mx[node_idx]);

	BLK_TO_RR(end_rr, endblk, un);
	BLK_TO_RR(start_rr, startblk, un);

	no_change = 1;

	mutex_enter(&un->un_resync_mx);
	rw_enter(&un->un_pernode_dirty_mx[node_idx], RW_READER);
	for (current_rr = start_rr; current_rr <= end_rr; current_rr++) {
		un->un_outstanding_writes[current_rr]++;
		if (!IS_PERNODE_DIRTY(source_node, current_rr, un)) {
			un->un_pernode_dirty_sum[current_rr]++;
			SET_PERNODE_DIRTY(source_node, current_rr, un);
		}
		CLR_GOING_CLEAN(current_rr, un);
		if (!IS_REGION_DIRTY(current_rr, un)) {
			no_change = 0;
			SET_REGION_DIRTY(current_rr, un);
			SET_GOING_DIRTY(current_rr, un);
		} else if (IS_GOING_DIRTY(current_rr, un))
			no_change = 0;
	}
	rw_exit(&un->un_pernode_dirty_mx[node_idx]);
	mutex_exit(&un->un_resync_mx);

	if (no_change) {
		return (0);
	}

	/*
	 * If we have dirty regions to commit, send a
	 * message to the owning node so that the
	 * in-core bitmap gets updated appropriately.
	 * TODO: make this a kmem_cache pool to improve
	 * alloc/free performance ???
	 */
	kres = (md_mn_kresult_t *)kmem_zalloc(sizeof (md_mn_kresult_t),
	    KM_SLEEP);
	rr = (md_mn_msg_rr_dirty_t *)kmem_alloc(sizeof (md_mn_msg_rr_dirty_t),
	    KM_SLEEP);

resend_mmrr:
	owner_node = un->un_mirror_owner;

	rr->rr_mnum = mnum;
	rr->rr_nodeid = md_mn_mynode_id;
	rr->rr_range = (ushort_t)start_rr << 16;
	rr->rr_range |= (ushort_t)end_rr & 0xFFFF;

	/* release readerlock before sending message */
	md_unit_readerexit(ui);

	rval = mdmn_ksend_message(setno, MD_MN_MSG_RR_DIRTY,
	    MD_MSGF_NO_LOG|MD_MSGF_BLK_SIGNAL|MD_MSGF_DIRECTED,
	    un->un_mirror_owner, (char *)rr,
	    sizeof (md_mn_msg_rr_dirty_t), kres);

	/* reaquire readerlock on message completion */
	(void) md_unit_readerlock(ui);

	/* if the message send failed, note it, and pass an error back up */
	if (!MDMN_KSEND_MSG_OK(rval, kres)) {
		/* if commd is gone, no point in printing a message */
		if (md_mn_is_commd_present())
			mdmn_ksend_show_error(rval, kres, "RR_DIRTY");
		kmem_free(kres, sizeof (md_mn_kresult_t));
		kmem_free(rr, sizeof (md_mn_msg_rr_dirty_t));
		return (1);
	}

	/*
	 * if the owner changed while we were sending the message, and it's
	 * not us, the new mirror owner won't yet have done the right thing
	 * with our data.  Let him know.  If we became the owner, we'll
	 * deal with that differently below.  Note that receiving a message
	 * about another node twice won't hurt anything.
	 */
	if (un->un_mirror_owner != owner_node && !MD_MN_MIRROR_OWNER(un))
		goto resend_mmrr;

	kmem_free(kres, sizeof (md_mn_kresult_t));
	kmem_free(rr, sizeof (md_mn_msg_rr_dirty_t));

	mutex_enter(&un->un_resync_mx);

	/*
	 * If we became the owner changed while we were sending the message,
	 * we have dirty bits in the un_pernode_bm that aren't yet reflected
	 * in the un_dirty_bm, as it was re-read from disk, and our bits
	 * are also not reflected in the on-disk DRL.  Fix that now.
	 */
	if (MD_MN_MIRROR_OWNER(un)) {
		rw_enter(&un->un_pernode_dirty_mx[node_idx], RW_WRITER);
		mirror_copy_rr(howmany(un->un_rrd_num, NBBY),
		    un->un_pernode_dirty_bm[node_idx], un->un_dirty_bm);
		rw_exit(&un->un_pernode_dirty_mx[node_idx]);

		un->un_resync_flg |= MM_RF_COMMITING | MM_RF_GATECLOSED;

		mutex_exit(&un->un_resync_mx);
		mddb_commitrec_wrapper(un->un_rr_dirty_recid);
		mutex_enter(&un->un_resync_mx);

		un->un_resync_flg &= ~(MM_RF_COMMITING | MM_RF_GATECLOSED);
		cv_broadcast(&un->un_resync_cv);
	}

	for (current_rr = start_rr; current_rr <= end_rr; current_rr++)
		CLR_GOING_DIRTY(current_rr, un);

	mutex_exit(&un->un_resync_mx);

	return (0);
}

int
mirror_mark_resync_region_owner(struct mm_unit *un,
	diskaddr_t startblk, diskaddr_t endblk, md_mn_nodeid_t source_node)
{
	int			no_change;
	size_t			start_rr;
	size_t			current_rr;
	size_t			end_rr;
	int			mnset = MD_MNSET_SETNO(MD_UN2SET(un));
	md_mn_nodeid_t		node_idx = source_node - 1;

	if (un->un_nsm < 2)
		return (0);

	/*
	 * Check to see if we have a un_pernode_dirty_bm[] entry allocated. If
	 * not, allocate it and then fill the [start..end] entries.
	 * Update un_pernode_dirty_sum if we've gone 0->1.
	 * Update un_dirty_bm if the corresponding entries are clear.
	 */
	if (mnset) {
		rw_enter(&un->un_pernode_dirty_mx[node_idx], RW_WRITER);
		if (un->un_pernode_dirty_bm[node_idx] == NULL) {
			un->un_pernode_dirty_bm[node_idx] =
			    (uchar_t *)kmem_zalloc(
			    (uint_t)howmany(un->un_rrd_num, NBBY), KM_SLEEP);
		}
		rw_exit(&un->un_pernode_dirty_mx[node_idx]);
	}

	mutex_enter(&un->un_resync_mx);

	if (mnset)
		rw_enter(&un->un_pernode_dirty_mx[node_idx], RW_READER);

	no_change = 1;
	BLK_TO_RR(end_rr, endblk, un);
	BLK_TO_RR(start_rr, startblk, un);
	for (current_rr = start_rr; current_rr <= end_rr; current_rr++) {
		if (!mnset || source_node == md_mn_mynode_id)
			un->un_outstanding_writes[current_rr]++;
		if (mnset) {
			if (!IS_PERNODE_DIRTY(source_node, current_rr, un))
				un->un_pernode_dirty_sum[current_rr]++;
			SET_PERNODE_DIRTY(source_node, current_rr, un);
		}
		CLR_GOING_CLEAN(current_rr, un);
		if (!IS_REGION_DIRTY(current_rr, un))
			no_change = 0;
		if (IS_GOING_DIRTY(current_rr, un))
			no_change = 0;
	}

	if (mnset)
		rw_exit(&un->un_pernode_dirty_mx[node_idx]);

	if (no_change) {
		mutex_exit(&un->un_resync_mx);
		return (0);
	}
	un->un_waiting_to_mark++;
	while (un->un_resync_flg & MM_RF_GATECLOSED) {
		if (panicstr)
			return (1);
		cv_wait(&un->un_resync_cv, &un->un_resync_mx);
	}
	un->un_waiting_to_mark--;

	no_change = 1;
	for (current_rr = start_rr; current_rr <= end_rr; current_rr++) {
		if (!IS_REGION_DIRTY(current_rr, un)) {
			SET_REGION_DIRTY(current_rr, un);
			SET_GOING_DIRTY(current_rr, un);
			no_change = 0;
		} else {
			if (IS_GOING_DIRTY(current_rr, un))
				no_change = 0;
		}
	}
	if (no_change) {
		if (un->un_waiting_to_mark == 0 || un->un_waiting_to_clear != 0)
			cv_broadcast(&un->un_resync_cv);
		mutex_exit(&un->un_resync_mx);
		return (0);
	}

	un->un_resync_flg |= MM_RF_COMMIT_NEEDED;
	un->un_waiting_to_commit++;
	while (un->un_waiting_to_mark != 0 &&
	    !(un->un_resync_flg & MM_RF_GATECLOSED)) {
		if (panicstr)
			return (1);
		cv_wait(&un->un_resync_cv, &un->un_resync_mx);
	}

	if (un->un_resync_flg & MM_RF_COMMIT_NEEDED) {
		un->un_resync_flg |= MM_RF_COMMITING | MM_RF_GATECLOSED;
		un->un_resync_flg &= ~MM_RF_COMMIT_NEEDED;

		mutex_exit(&un->un_resync_mx);
		mddb_commitrec_wrapper(un->un_rr_dirty_recid);
		mutex_enter(&un->un_resync_mx);

		un->un_resync_flg &= ~MM_RF_COMMITING;
		cv_broadcast(&un->un_resync_cv);
	}
	while (un->un_resync_flg & MM_RF_COMMITING) {
		if (panicstr)
			return (1);
		cv_wait(&un->un_resync_cv, &un->un_resync_mx);
	}

	for (current_rr = start_rr; current_rr <= end_rr; current_rr++)
		CLR_GOING_DIRTY(current_rr, un);

	if (--un->un_waiting_to_commit == 0) {
		un->un_resync_flg &= ~MM_RF_GATECLOSED;
		cv_broadcast(&un->un_resync_cv);
	}
	mutex_exit(&un->un_resync_mx);

	return (0);
}

int
mirror_mark_resync_region(struct mm_unit *un,
	diskaddr_t startblk, diskaddr_t endblk, md_mn_nodeid_t source_node)
{
	int	mnset = MD_MNSET_SETNO(MD_UN2SET(un));

	if (mnset && !MD_MN_MIRROR_OWNER(un)) {
		return (mirror_mark_resync_region_non_owner(un, startblk,
		    endblk, source_node));
	} else {
		return (mirror_mark_resync_region_owner(un, startblk, endblk,
		    source_node));
	}
}

int
mirror_resize_resync_regions(mm_unit_t *un, diskaddr_t new_tb)
{
	short		*owp;
	optim_resync_t	*orp;
	uint_t		rr_mult = 1;
	uint_t		old_nregions, new_nregions;
	int		old_bm_size, new_bm_size;
	size_t		size;
	mddb_recid_t	recid, old_recid;
	uchar_t		*old_dirty_bm;
	int		i, j;
	mddb_type_t	typ1;
	set_t		setno = MD_UN2SET(un);
	uchar_t		*old_pns;

	old_nregions = un->un_rrd_num;
	new_nregions = (uint_t)((new_tb/un->un_rrd_blksize) + 1);

	while (new_nregions > MD_MAX_NUM_RR) {
		new_nregions >>= 1;
		rr_mult <<= 1;
	}

	new_bm_size = howmany(new_nregions, NBBY);
	old_bm_size = howmany(old_nregions, NBBY);

	size = new_bm_size + sizeof (*orp) - sizeof (orp->or_rr);

	typ1 = (mddb_type_t)md_getshared_key(setno,
	    mirror_md_ops.md_driver.md_drivername);
	recid = mddb_createrec(size, typ1, RESYNC_REC,
	    MD_CRO_OPTIMIZE|MD_CRO_32BIT, setno);
	if (recid < 0)
		return (-1);

	orp = (struct optim_resync *)mddb_getrecaddr(recid);
	ASSERT(orp != NULL);

	orp->or_magic = OR_MAGIC;		/* Magic # */
	orp->or_blksize = un->un_rrd_blksize;	/* Same block size */
	orp->or_num = new_nregions;		/* New number of regions */

	old_dirty_bm = un->un_dirty_bm;
	un->un_dirty_bm = orp->or_rr;

	kmem_free((caddr_t)un->un_goingdirty_bm, old_bm_size);
	un->un_goingdirty_bm = (uchar_t *)kmem_zalloc(new_bm_size, KM_SLEEP);

	kmem_free((caddr_t)un->un_goingclean_bm, old_bm_size);
	un->un_goingclean_bm = (uchar_t *)kmem_zalloc(new_bm_size, KM_SLEEP);

	kmem_free((caddr_t)un->un_resync_bm, old_bm_size);
	un->un_resync_bm = (uchar_t *)kmem_zalloc(new_bm_size, KM_SLEEP);

	owp = un->un_outstanding_writes;
	un->un_outstanding_writes = (short *)kmem_zalloc(
	    new_nregions * sizeof (short), KM_SLEEP);

	old_pns = un->un_pernode_dirty_sum;
	if (old_pns)
		un->un_pernode_dirty_sum = (uchar_t *)kmem_zalloc(new_nregions,
		    KM_SLEEP);

	/*
	 * Now translate the old records into the new
	 * records
	 */
	for (i = 0; i < old_nregions; i++) {
		/*
		 * only bring forward the
		 * outstanding write counters and the dirty bits and also
		 * the pernode_summary counts
		 */
		if (!isset(old_dirty_bm, i))
			continue;

		setbit(un->un_dirty_bm, (i / rr_mult));
		un->un_outstanding_writes[(i / rr_mult)] += owp[i];
		if (old_pns)
			un->un_pernode_dirty_sum[(i / rr_mult)] += old_pns[i];
	}
	kmem_free((caddr_t)owp, old_nregions * sizeof (short));
	if (old_pns)
		kmem_free((caddr_t)old_pns, old_nregions);

	/*
	 * Copy all non-zero un_pernode_dirty_bm[] arrays to new versions
	 */
	for (j = 0; j < MD_MNMAXSIDES; j++) {
		rw_enter(&un->un_pernode_dirty_mx[j], RW_WRITER);
		old_dirty_bm = un->un_pernode_dirty_bm[j];
		if (old_dirty_bm) {
			un->un_pernode_dirty_bm[j] = (uchar_t *)kmem_zalloc(
			    new_bm_size, KM_SLEEP);
			for (i = 0; i < old_nregions; i++) {
				if (!isset(old_dirty_bm, i))
					continue;

				setbit(un->un_pernode_dirty_bm[j],
				    (i / rr_mult));
			}
			kmem_free((caddr_t)old_dirty_bm, old_bm_size);
		}
		rw_exit(&un->un_pernode_dirty_mx[j]);
	}

	/* Save the old record id */
	old_recid = un->un_rr_dirty_recid;

	/* Update the mirror unit struct */
	un->un_rr_dirty_recid = recid;
	un->un_rrd_num = new_nregions;
	un->un_rrd_blksize = un->un_rrd_blksize * rr_mult;

	orp->or_blksize = un->un_rrd_blksize;

	/*
	 * NOTE: The reason there are distinct calls to mddb_commitrec_wrapper
	 * instead of using mddb_commitrecs_wrapper, is that you cannot
	 * atomically commit optimized records.
	 */
	mddb_commitrec_wrapper(recid);
	mddb_commitrec_wrapper(un->c.un_record_id);
	mddb_deleterec_wrapper(old_recid);
	return (0);
}

/* lockp can be NULL for !MN diksets */
int
mirror_add_resync_regions(mm_unit_t *un, diskaddr_t new_tb)
{
	uchar_t		*old;
	short		*owp;
	optim_resync_t	*orp;
	uint_t		old_nregions, new_nregions;
	int		old_bm_size, new_bm_size;
	size_t		size;
	mddb_recid_t	recid, old_recid;
	mddb_type_t	typ1;
	set_t		setno = MD_UN2SET(un);
	int		i;

	old_nregions = un->un_rrd_num;
	new_nregions = (uint_t)((new_tb/un->un_rrd_blksize) + 1);

	new_bm_size = howmany(new_nregions, NBBY);
	old_bm_size = howmany(old_nregions, NBBY);

	size = new_bm_size + sizeof (*orp) - sizeof (orp->or_rr);

	typ1 = (mddb_type_t)md_getshared_key(setno,
	    mirror_md_ops.md_driver.md_drivername);

	recid = mddb_createrec(size, typ1, RESYNC_REC,
	    MD_CRO_OPTIMIZE|MD_CRO_32BIT, setno);
	if (recid < 0)
		return (-1);

	orp = (struct optim_resync *)mddb_getrecaddr(recid);
	ASSERT(orp != NULL);

	orp->or_magic = OR_MAGIC;		/* Magic # */
	orp->or_blksize = un->un_rrd_blksize;	/* Same block size */
	orp->or_num = new_nregions;		/* New number of regions */

	/* Copy the old bm over the new bm */
	bcopy((caddr_t)un->un_dirty_bm, (caddr_t)orp->or_rr, old_bm_size);

	/*
	 * Create new bigger incore arrays, copy, and free old ones:
	 *		un_goingdirty_bm
	 *		un_goingclean_bm
	 *		un_resync_bm
	 *		un_outstanding_writes
	 *		un_pernode_dirty_sum
	 *		un_pernode_dirty_bm[]
	 */
	old = un->un_goingdirty_bm;
	un->un_goingdirty_bm = (uchar_t *)kmem_zalloc(new_bm_size, KM_SLEEP);
	bcopy((caddr_t)old, (caddr_t)un->un_goingdirty_bm, old_bm_size);
	kmem_free((caddr_t)old, old_bm_size);

	old = un->un_goingclean_bm;
	un->un_goingclean_bm = (uchar_t *)kmem_zalloc(new_bm_size, KM_SLEEP);
	bcopy((caddr_t)old, (caddr_t)un->un_goingclean_bm, old_bm_size);
	kmem_free((caddr_t)old, old_bm_size);

	old = un->un_resync_bm;
	un->un_resync_bm = (uchar_t *)kmem_zalloc(new_bm_size, KM_SLEEP);
	bcopy((caddr_t)old, (caddr_t)un->un_resync_bm, old_bm_size);
	kmem_free((caddr_t)old, old_bm_size);

	owp = un->un_outstanding_writes;
	un->un_outstanding_writes = (short *)kmem_zalloc(
	    (uint_t)new_nregions * sizeof (short), KM_SLEEP);
	bcopy((caddr_t)owp, (caddr_t)un->un_outstanding_writes,
	    old_nregions * sizeof (short));
	kmem_free((caddr_t)owp, (old_nregions * sizeof (short)));

	old = un->un_pernode_dirty_sum;
	if (old) {
		un->un_pernode_dirty_sum = (uchar_t *)kmem_zalloc(
		    new_nregions, KM_SLEEP);
		bcopy((caddr_t)old, (caddr_t)un->un_pernode_dirty_sum,
		    old_nregions);
		kmem_free((caddr_t)old, old_nregions);
	}

	for (i = 0; i < MD_MNMAXSIDES; i++) {
		rw_enter(&un->un_pernode_dirty_mx[i], RW_WRITER);
		old = un->un_pernode_dirty_bm[i];
		if (old) {
			un->un_pernode_dirty_bm[i] = (uchar_t *)kmem_zalloc(
			    new_bm_size, KM_SLEEP);
			bcopy((caddr_t)old, (caddr_t)un->un_pernode_dirty_bm[i],
			    old_bm_size);
			kmem_free((caddr_t)old, old_bm_size);
		}
		rw_exit(&un->un_pernode_dirty_mx[i]);
	}

	/* Save the old record id */
	old_recid = un->un_rr_dirty_recid;

	/* Update the mirror unit struct */
	un->un_rr_dirty_recid = recid;
	un->un_rrd_num = new_nregions;
	un->un_dirty_bm = orp->or_rr;

	/*
	 * NOTE: The reason there are distinct calls to mddb_commitrec_wrapper
	 * instead of using mddb_commitrecs_wrapper, is that you cannot
	 * atomically commit optimized records.
	 */
	mddb_commitrec_wrapper(recid);
	mddb_commitrec_wrapper(un->c.un_record_id);
	mddb_deleterec_wrapper(old_recid);
	return (0);
}

/*
 * mirror_copy_rr:
 * --------------
 * Combine the dirty record bitmap with the in-core resync bitmap. This allows
 * us to carry a resync over an ownership change.
 */
void
mirror_copy_rr(int sz, uchar_t *src, uchar_t *dest)
{
	int	i;

	for (i = 0; i < sz; i++)
		*dest++ |= *src++;
}

/*
 * mirror_set_dirty_rr:
 * -------------------
 * Set the pernode_dirty_bm[node] entries and un_dirty_bm[] if appropriate.
 * For the owning node (DRL/mirror owner) update the on-disk RR if needed.
 * Called on every clean->dirty transition for the originating writer node.
 * Note: only the non-owning nodes will initiate this message and it is only
 * the owning node that has to process it.
 */
int
mirror_set_dirty_rr(md_mn_rr_dirty_params_t *iocp)
{

	minor_t			mnum = iocp->rr_mnum;
	mm_unit_t		*un;
	int			start = (int)iocp->rr_start;
	int			end = (int)iocp->rr_end;
	set_t			setno = MD_MIN2SET(mnum);
	md_mn_nodeid_t		orignode = iocp->rr_nodeid;	/* 1-based */
	diskaddr_t		startblk, endblk;

	mdclrerror(&iocp->mde);

	if ((setno >= md_nsets) ||
	    (MD_MIN2UNIT(mnum) >= md_nunits)) {
		return (mdmderror(&iocp->mde, MDE_INVAL_UNIT, mnum));
	}

	/* Must have _NO_ ioctl lock set if we update the RR on-disk */
	un = mirror_getun(mnum, &iocp->mde, NO_LOCK, NULL);

	if (un == NULL) {
		return (mdmderror(&iocp->mde, MDE_UNIT_NOT_SETUP, mnum));
	}
	if (un->c.un_type != MD_METAMIRROR) {
		return (mdmderror(&iocp->mde, MDE_NOT_MM, mnum));
	}
	if (orignode < 1 || orignode >= MD_MNMAXSIDES) {
		return (mdmderror(&iocp->mde, MDE_INVAL_UNIT, mnum));
	}
	if (un->un_nsm < 2) {
		return (0);
	}

	/*
	 * Only process this message if we're the owner of the mirror.
	 */
	if (!MD_MN_MIRROR_OWNER(un)) {
		return (0);
	}

	RR_TO_BLK(startblk, start, un);
	RR_TO_BLK(endblk, end, un);
	return (mirror_mark_resync_region_owner(un, startblk, endblk,
	    orignode));
}

/*
 * mirror_clean_rr_bits:
 * --------------------
 * Clear the pernode_dirty_bm[node] entries which are passed in the bitmap
 * Once _all_ references are removed (pernode_dirty_count[x] == 0) this region
 * is 'cleanable' and will get flushed out by clearing un_dirty_bm[] on all
 * nodes. Callable from ioctl / interrupt / whatever context.
 * un_resync_mx is held on entry.
 */
static void
mirror_clean_rr_bits(
	md_mn_rr_clean_params_t *iocp)
{
	minor_t			mnum = iocp->rr_mnum;
	mm_unit_t		*un;
	uint_t			cleared_bits;
	md_mn_nodeid_t		node = iocp->rr_nodeid - 1;
	md_mn_nodeid_t		orignode = iocp->rr_nodeid;
	int			i, start, end;

	un = mirror_getun(mnum, &iocp->mde, NO_LOCK, NULL);

	cleared_bits = 0;
	start = MDMN_RR_CLEAN_PARAMS_START_BIT(iocp);
	end = start + MDMN_RR_CLEAN_PARAMS_DATA_BYTES(iocp) * NBBY;
	rw_enter(&un->un_pernode_dirty_mx[node], RW_READER);
	for (i = start; i < end; i++) {
		if (isset(MDMN_RR_CLEAN_PARAMS_DATA(iocp), i - start)) {
			if (IS_PERNODE_DIRTY(orignode, i, un)) {
				un->un_pernode_dirty_sum[i]--;
				CLR_PERNODE_DIRTY(orignode, i, un);
			}
			if (un->un_pernode_dirty_sum[i] == 0) {
				cleared_bits++;
				CLR_REGION_DIRTY(i, un);
				CLR_GOING_CLEAN(i, un);
			}
		}
	}
	rw_exit(&un->un_pernode_dirty_mx[node]);
	if (cleared_bits) {
		/*
		 * We can only be called iff we are the mirror owner, however
		 * as this is a (potentially) decoupled routine the ownership
		 * may have moved from us by the time we get to execute the
		 * bit clearing. Hence we still need to check for being the
		 * owner before flushing the DRL to the replica.
		 */
		if (MD_MN_MIRROR_OWNER(un)) {
			mutex_exit(&un->un_resync_mx);
			mddb_commitrec_wrapper(un->un_rr_dirty_recid);
			mutex_enter(&un->un_resync_mx);
		}
	}
}

/*
 * mirror_drl_task:
 * ---------------
 * Service routine for clearing the DRL bits on a deferred MD_MN_RR_CLEAN call
 * We need to obtain exclusive access to the un_resync_cv and then clear the
 * necessary bits.
 * On completion, we must also free the passed in argument as it is allocated
 * at the end of the ioctl handler and won't be freed on completion.
 */
static void
mirror_drl_task(void *arg)
{
	md_mn_rr_clean_params_t	*iocp = (md_mn_rr_clean_params_t *)arg;
	minor_t			mnum = iocp->rr_mnum;
	mm_unit_t		*un;

	un = mirror_getun(mnum, &iocp->mde, NO_LOCK, NULL);

	mutex_enter(&un->un_rrp_inflight_mx);
	mutex_enter(&un->un_resync_mx);
	un->un_waiting_to_clear++;
	while (un->un_resync_flg & MM_RF_STALL_CLEAN)
		cv_wait(&un->un_resync_cv, &un->un_resync_mx);
	un->un_waiting_to_clear--;

	un->un_resync_flg |= MM_RF_GATECLOSED;
	mirror_clean_rr_bits(iocp);
	un->un_resync_flg &= ~MM_RF_GATECLOSED;
	if (un->un_waiting_to_mark != 0 || un->un_waiting_to_clear != 0) {
		cv_broadcast(&un->un_resync_cv);
	}
	mutex_exit(&un->un_resync_mx);
	mutex_exit(&un->un_rrp_inflight_mx);

	kmem_free((caddr_t)iocp, MDMN_RR_CLEAN_PARAMS_SIZE(iocp));
}

/*
 * mirror_set_clean_rr:
 * -------------------
 * Clear the pernode_dirty_bm[node] entries which are passed in the bitmap
 * Once _all_ references are removed (pernode_dirty_count[x] == 0) this region
 * is 'cleanable' and will get flushed out by clearing un_dirty_bm[] on all
 * nodes.
 *
 * Only the mirror-owner need process this message as it is the only RR updater.
 * Non-owner nodes issue this request, but as we have no point-to-point message
 * support we will receive the message on all nodes.
 */
int
mirror_set_clean_rr(md_mn_rr_clean_params_t *iocp)
{

	minor_t			mnum = iocp->rr_mnum;
	mm_unit_t		*un;
	set_t			setno = MD_MIN2SET(mnum);
	md_mn_nodeid_t		node = iocp->rr_nodeid - 1;
	int			can_clear = 0;
	md_mn_rr_clean_params_t	*newiocp;
	int			rval = 0;

	mdclrerror(&iocp->mde);

	if ((setno >= md_nsets) ||
	    (MD_MIN2UNIT(mnum) >= md_nunits)) {
		return (mdmderror(&iocp->mde, MDE_INVAL_UNIT, mnum));
	}

	/* Must have _NO_ ioctl lock set if we update the RR on-disk */
	un = mirror_getun(mnum, &iocp->mde, NO_LOCK, NULL);

	if (un == NULL) {
		return (mdmderror(&iocp->mde, MDE_UNIT_NOT_SETUP, mnum));
	}
	if (un->c.un_type != MD_METAMIRROR) {
		return (mdmderror(&iocp->mde, MDE_NOT_MM, mnum));
	}
	if (un->un_nsm < 2) {
		return (0);
	}

	/*
	 * Check to see if we're the mirror owner. If not, there's nothing
	 * for us to to.
	 */
	if (!MD_MN_MIRROR_OWNER(un)) {
		return (0);
	}

	/*
	 * Process the to-be-cleaned bitmap. We need to update the pernode_dirty
	 * bits and pernode_dirty_sum[n], and if, and only if, the sum goes 0
	 * we can then mark the un_dirty_bm entry as GOINGCLEAN. Alternatively
	 * we can just defer this cleaning until the next process_resync_regions
	 * timeout.
	 */
	rw_enter(&un->un_pernode_dirty_mx[node], RW_WRITER);
	if (un->un_pernode_dirty_bm[node] == NULL) {
		un->un_pernode_dirty_bm[node] = (uchar_t *)kmem_zalloc(
		    un->un_rrd_num, KM_SLEEP);
	}
	rw_exit(&un->un_pernode_dirty_mx[node]);

	/*
	 * See if we can simply clear the un_dirty_bm[] entries. If we're not
	 * the issuing node _and_ we aren't in the process of marking/clearing
	 * the RR bitmaps, we can simply update the bits as needed.
	 * If we're the owning node and _not_ the issuing node, we should also
	 * sync the RR if we clear any bits in it.
	 */
	mutex_enter(&un->un_resync_mx);
	can_clear = (un->un_resync_flg & MM_RF_STALL_CLEAN) ? 0 : 1;
	if (can_clear) {
		un->un_resync_flg |= MM_RF_GATECLOSED;
		mirror_clean_rr_bits(iocp);
		un->un_resync_flg &= ~MM_RF_GATECLOSED;
		if (un->un_waiting_to_mark != 0 ||
		    un->un_waiting_to_clear != 0) {
			cv_broadcast(&un->un_resync_cv);
		}
	}
	mutex_exit(&un->un_resync_mx);

	/*
	 * If we couldn't clear the bits, due to DRL update from m_m_r_r / p_r_r
	 * we must schedule a blocking call to update the DRL on this node.
	 * As we're invoked from an ioctl we are going to have the original data
	 * disappear (kmem_free) once we return. So, copy the data into a new
	 * structure and let the taskq routine release it on completion.
	 */
	if (!can_clear) {
		size_t	sz = MDMN_RR_CLEAN_PARAMS_SIZE(iocp);

		newiocp = (md_mn_rr_clean_params_t *)kmem_alloc(sz, KM_SLEEP);

		bcopy(iocp, newiocp, sz);

		if (ddi_taskq_dispatch(un->un_drl_task, mirror_drl_task,
		    newiocp, DDI_NOSLEEP) != DDI_SUCCESS) {
			kmem_free(newiocp, sz);
			rval = ENOMEM;	/* probably starvation */
		}
	}

	return (rval);
}
