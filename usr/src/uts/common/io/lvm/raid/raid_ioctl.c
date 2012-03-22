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
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

/*
 * NAME:	raid_ioctl.c
 *
 * DESCRIPTION: RAID driver source file containing IOCTL operations.
 *
 * ROUTINES PROVIDED FOR EXTERNAL USE:
 *	  raid_commit() - commits MD database updates for a RAID metadevice
 *	md_raid_ioctl() - RAID metadevice IOCTL operations entry point.
 *
 * ROUTINES PROVIDED FOR INTERNAL USE:
 *	 raid_getun() - Performs unit checking on a RAID metadevice
 *    init_col_nextio() - normal backend when zeroing column of RAID metadevice.
 *	 init_col_int() - I/O interrupt while zeroing column of RAID metadevice.
 *  raid_init_columns() - Zero one or more columns of a RAID metadevice.
 *	     raid_set() - used to create a RAID metadevice
 *	     raid_get() - used to get the unit structure of a RAID metadevice
 *	 raid_replace() - used to replace a component of a RAID metadevice
 *	    raid_grow() - Concatenate to a RAID metadevice
 *	  raid_change() - change dynamic values of a RAID metadevice
 *	   raid_reset() - used to reset (clear / remove) a RAID metadevice
 *	raid_get_geom() - used to get the geometry of a RAID metadevice
 *	raid_get_vtoc() - used to get the VTOC on a RAID metadevice
 *	raid_set_vtoc() - used to set the VTOC on a RAID metadevice
 *	raid_get_extvtoc() - used to get the extended VTOC on a RAID metadevice
 *	raid_set_extvtoc() - used to set the extended VTOC on a RAID metadevice
 *	 raid_getdevs() - return all devices within a RAID metadevice
 *   raid_admin_ioctl() - IOCTL operations unique to metadevices and RAID
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
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/stat.h>
#include <sys/open.h>
#include <sys/disp.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cred.h>
#include <sys/lvm/mdvar.h>
#include <sys/lvm/md_names.h>
#include <sys/lvm/md_mddb.h>
#include <sys/lvm/md_raid.h>
#include <sys/lvm/md_convert.h>

#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/svm.h>

extern int		md_status;
extern unit_t		md_nunits;
extern set_t		md_nsets;
extern md_set_t		md_set[];
extern md_ops_t		raid_md_ops;
extern major_t		md_major;
extern md_krwlock_t	md_unit_array_rw;
extern mdq_anchor_t	md_done_daemon;
extern mdq_anchor_t	md_ff_daemonq;
extern	int		mdopen();
extern	int		mdclose();
extern	void		md_probe_one(probe_req_t *);
extern int		md_init_probereq(md_probedev_impl_t *,
				daemon_queue_t **);
extern md_resync_t	md_cpr_resync;


extern void dump_mr_unit(mr_unit_t *);

typedef struct raid_ci {
	DAEMON_QUEUE
	struct raid_ci	*ci_next;
	mr_unit_t	*ci_un;
	int		ci_col;
	int		ci_err;
	int		ci_flag;
	size_t		ci_zerosize;
	diskaddr_t	ci_blkno;
	diskaddr_t	ci_lastblk;
	buf_t		ci_buf;
} raid_ci_t;
/* values for the ci_flag */
#define	COL_INITING	(0x0001)
#define	COL_INIT_DONE	(0x0002)
#define	COL_READY	(0x0004)

/*
 * NAME:	raid_getun
 * DESCRIPTION: performs a lot of unit checking on a RAID metadevice
 * PARAMETERS:	minor_t	      mnum - minor device number for RAID unit
 *		md_error_t    *mde - pointer to error reporting structure
 *		int	     flags - pointer to error reporting structure
 *					STALE_OK - allow stale MD memory
 *					  NO_OLD - unit must not exist
 *					 NO_LOCK - no IOCTL lock needed
 *					 WR_LOCK - write IOCTL lock needed
 *					 RD_LOCK - read IOCTL lock needed
 *		IOLOCK	     *lock - pointer to IOCTL lock
 *
 * LOCKS:	obtains unit reader or writer lock via IOLOCK
 *
 */
static mr_unit_t *
raid_getun(minor_t mnum, md_error_t *mde, int flags, IOLOCK *lock)
{
	mr_unit_t	*un;
	mdi_unit_t	*ui;
	set_t		setno = MD_MIN2SET(mnum);

	if ((setno >= md_nsets) || (MD_MIN2UNIT(mnum) >= md_nunits)) {
		(void) mdmderror(mde, MDE_INVAL_UNIT, mnum);
		return (NULL);
	}

	if (!(flags & STALE_OK)) {
		if (md_get_setstatus(setno) & MD_SET_STALE) {
			(void) mdmddberror(mde, MDE_DB_STALE, mnum, setno);
			return (NULL);
		}
	}

	ui = MDI_UNIT(mnum);
	if (flags & NO_OLD) {
		if (ui != NULL) {
			(void) mdmderror(mde, MDE_UNIT_ALREADY_SETUP, mnum);
			return (NULL);
		}
		return ((mr_unit_t *)1);
	}

	if (ui == NULL) {
		(void) mdmderror(mde, MDE_UNIT_NOT_SETUP, mnum);
		return (NULL);
	}
	if (flags & ARRAY_WRITER)
		md_array_writer(lock);
	else if (flags & ARRAY_READER)
		md_array_reader(lock);

	if (!(flags & NO_LOCK)) {
		if (flags & WR_LOCK) {
			(void) md_ioctl_io_lock(lock, ui);
			(void) md_ioctl_writerlock(lock, ui);
		} else /* RD_LOCK */
			(void) md_ioctl_readerlock(lock, ui);
	}
	un = (mr_unit_t *)MD_UNIT(mnum);

	if (un->c.un_type != MD_METARAID) {
		(void) mdmderror(mde, MDE_NOT_RAID, mnum);
		return (NULL);
	}

	return (un);
}


/*
 * NAME:	raid_commit
 * DESCRIPTION: commits MD database updates for a RAID metadevice
 * PARAMETERS:	mr_unit_t	 *un - RAID unit to update in the MD database
 *		mddb_recid_t *extras - array of other record IDs to update
 *
 * LOCKS:	assumes caller holds unit writer lock
 *
 */
void
raid_commit(mr_unit_t *un, mddb_recid_t	*extras)
{
	mddb_recid_t	*recids;
	int 		ri = 0;
	int		nrecids = 0;

	if (md_get_setstatus(MD_UN2SET(un)) & MD_SET_STALE)
		return;

	/* Count the extra recids */
	if (extras != NULL) {
		while (extras[nrecids] != 0) {
			nrecids++;
		}
	}

	/*
	 * Allocate space for two recids in addition to the extras:
	 * one for the unit structure, one for the null terminator.
	 */
	nrecids += 2;
	recids = (mddb_recid_t *)
	    kmem_zalloc(nrecids * sizeof (mddb_recid_t), KM_SLEEP);

	if (un != NULL) {
		ASSERT(MDI_UNIT(MD_SID(un)) ? UNIT_WRITER_HELD(un) : 1);
		recids[ri++] = un->c.un_record_id;
	}

	if (extras != NULL) {
		while (*extras != 0) {
			recids[ri++] = *extras;
			extras++;
		}
	}

	if (ri > 0) {
		mddb_commitrecs_wrapper(recids);
	}

	kmem_free(recids, nrecids * sizeof (mddb_recid_t));
}

static int
raid_check_pw(mr_unit_t *un)
{
	buf_t		bp;
	char		*buf;
	mr_column_t	*colptr;
	minor_t		mnum = MD_SID(un);
	int		i;
	int		err = 0;
	minor_t		unit;

	buf = kmem_zalloc((uint_t)DEV_BSIZE, KM_SLEEP);

	for (i = 0; i < un->un_totalcolumncnt; i++) {
		md_dev64_t tmpdev;

		colptr = &un->un_column[i];

		tmpdev = colptr->un_dev;
		/*
		 * Open by device id
		 * If this device is hotspared
		 * use the hotspare key
		 */
		tmpdev = md_resolve_bydevid(mnum, tmpdev, HOTSPARED(un, i) ?
		    colptr->un_hs_key : colptr->un_orig_key);
		if (md_layered_open(mnum, &tmpdev, MD_OFLG_NULL)) {
			colptr->un_dev = tmpdev;
			return (1);
		}
		colptr->un_dev = tmpdev;

		bzero((caddr_t)&bp, sizeof (buf_t));
		bp.b_back = &bp;
		bp.b_forw = &bp;
		bp.b_flags = B_READ | B_BUSY;
		sema_init(&bp.b_io, 0, NULL,
		    SEMA_DEFAULT, NULL);
		sema_init(&bp.b_sem, 0, NULL,
		    SEMA_DEFAULT, NULL);
		bp.b_edev = md_dev64_to_dev(colptr->un_dev);
		bp.b_lblkno = colptr->un_pwstart;
		bp.b_bcount = DEV_BSIZE;
		bp.b_bufsize = DEV_BSIZE;
		bp.b_un.b_addr = (caddr_t)buf;
		bp.b_offset = -1;
		(void) md_call_strategy(&bp, 0, NULL);
		if (biowait(&bp))
			err = 1;
		if (i == 0) {
			if (un->c.un_revision & MD_64BIT_META_DEV) {
				unit = ((raid_pwhdr_t *)buf)->rpw_unit;
			} else {
				unit = ((raid_pwhdr32_od_t *)buf)->rpw_unit;
			}
		}
		/*
		 * depending upon being an 64bit or 32 bit raid, the
		 * pre write headers have different layout
		 */
		if (un->c.un_revision & MD_64BIT_META_DEV) {
			if ((((raid_pwhdr_t *)buf)->rpw_column != i) ||
			    (((raid_pwhdr_t *)buf)->rpw_unit != unit))
				err = 1;
		} else {
			if ((((raid_pwhdr32_od_t *)buf)->rpw_column != i) ||
			    (((raid_pwhdr32_od_t *)buf)->rpw_unit != unit))
				err = 1;
		}
		md_layered_close(colptr->un_dev, MD_OFLG_NULL);
		if (err)
			break;
	}
	kmem_free(buf, DEV_BSIZE);
	return (err);
}

/*
 * NAME:	init_col_nextio
 * DESCRIPTION: normal backend process when zeroing column of a RAID metadevice.
 * PARAMETERS:	raid_ci_t *cur - struct for column being zeroed
 *
 * LOCKS:	assumes caller holds unit reader lock,
 *		preiodically releases and reacquires unit reader lock,
 *		broadcasts on unit conditional variable (un_cv)
 *
 */
#define	INIT_RLS_CNT	10
static void
init_col_nextio(raid_ci_t *cur)
{
	mr_unit_t	*un;

	un = cur->ci_un;

	cur->ci_blkno += cur->ci_zerosize;

	mutex_enter(&un->un_mx);
	/* ===> update un_percent_done */
	un->un_init_iocnt += btodb(cur->ci_buf.b_bcount);
	mutex_exit(&un->un_mx);

	/*
	 * When gorwing a device, normal I/O is still going on.
	 * The init thread still holds the unit reader lock which
	 * prevents I/O from doing state changes.
	 * So every INIT_RLS_CNT init I/Os, we will release the
	 * unit reader lock.
	 *
	 * CAVEAT:
	 * We know we are in the middle of a grow operation and the
	 * unit cannot be grown or removed (through reset or halt)
	 * so the mr_unit_t structure will not move or disappear.
	 * In addition, we know that only one of the init I/Os
	 * can be in col_init_nextio at a time because they are
	 * placed on the md_done_daemon queue and md only processes
	 * one element of this queue at a time. In addition, any
	 * code that needs to acquire the unit writer lock to change
	 * state is supposed to be on the md_mstr_daemon queue so
	 * it can be processing while we sit here waiting to get the
	 * unit reader lock back.
	 */

	if (cur->ci_blkno < cur->ci_lastblk) {
		/* truncate last chunk to end_addr if needed */
		if (cur->ci_blkno + cur->ci_zerosize > cur->ci_lastblk) {
			cur->ci_zerosize = (size_t)
			    (cur->ci_lastblk - cur->ci_blkno);
		}

		/* set address and length for I/O bufs */
		cur->ci_buf.b_bufsize = dbtob(cur->ci_zerosize);
		cur->ci_buf.b_bcount = dbtob(cur->ci_zerosize);
		cur->ci_buf.b_lblkno = cur->ci_blkno;

		(void) md_call_strategy(&cur->ci_buf, MD_STR_NOTTOP, NULL);
		return;
	}
	/* finished initializing this column */
	mutex_enter(&un->un_mx);
	cur->ci_flag = COL_INIT_DONE;
	uniqtime32(&un->un_column[cur->ci_col].un_devtimestamp);
	mutex_exit(&un->un_mx);
	cv_broadcast(&un->un_cv);
}

/*
 * NAME:	init_col_int
 * DESCRIPTION: I/O interrupt while zeroing column of a RAID metadevice.
 * PARAMETERS:	buf_t	  *cb - I/O buffer for which interrupt occurred
 *
 * LOCKS:	assumes caller holds unit reader or writer lock
 *
 */
static int
init_col_int(buf_t *cb)
{
	raid_ci_t	*cur;

	cur = (raid_ci_t *)cb->b_chain;
	if (cb->b_flags & B_ERROR) {
		mutex_enter(&cur->ci_un->un_mx);
		cur->ci_err = EIO;
		mutex_exit(&cur->ci_un->un_mx);
		cv_broadcast(&cur->ci_un->un_cv);
		return (1);
	}
	daemon_request(&md_done_daemon, init_col_nextio,
	    (daemon_queue_t *)cur, REQ_OLD);
	return (1);
}

/*
 * NAME:	raid_init_columns
 * DESCRIPTION: Zero one or more columns of a RAID metadevice.
 * PARAMETERS:	minor_t	 mnum - RAID unit minor identifier
 *
 * LOCKS:	obtains and releases unit reader lock,
 *		obtains and releases unit writer lock,
 *		obtains and releases md_unit_array_rw write lock,
 *		obtains and releases unit mutex (un_mx) lock,
 *		waits on unit conditional variable (un_cv)
 *
 */
static void
raid_init_columns(minor_t mnum)
{
	mr_unit_t	*un;
	mdi_unit_t	*ui;
	raid_ci_t	*ci_chain = NULL, *cur;
	rus_state_t	state;
	caddr_t		zero_addr;
	diskaddr_t	end_off;
	size_t		zerosize;
	int		err = 0;
	int		ix;
	int		colcnt = 0;
	int		col;
	set_t		setno = MD_MIN2SET(mnum);

	/*
	 * Increment the raid resync count for cpr
	 */
	mutex_enter(&md_cpr_resync.md_resync_mutex);
	md_cpr_resync.md_raid_resync++;
	mutex_exit(&md_cpr_resync.md_resync_mutex);

	/*
	 * initialization is a multiple step process.  The first step
	 * is to go through the unit structure and start each device
	 * in the init state writing zeros over the component.
	 * Next initialize the prewrite areas, so the device can be
	 * used if a metainit -k is done.  Now close the componenets.
	 *
	 * Once this complete set the state of each component being
	 * zeroed and set the correct state for the unit.
	 *
	 * last commit the records.
	 */

	ui = MDI_UNIT(mnum);
	un = md_unit_readerlock(ui);

	/* check for active init on this column */
	/* exiting is cpr safe */
	if ((un->un_init_colcnt > 0) && (un->un_resync_index != -1)) {
		md_unit_readerexit(ui);
		(void) raid_internal_close(mnum, OTYP_LYR, 0, 0);
		/*
		 * Decrement the raid resync count for cpr
		 */
		mutex_enter(&md_cpr_resync.md_resync_mutex);
		md_cpr_resync.md_raid_resync--;
		mutex_exit(&md_cpr_resync.md_resync_mutex);
		thread_exit();
	}

	SE_NOTIFY(EC_SVM_STATE, ESC_SVM_INIT_START, SVM_TAG_METADEVICE, setno,
	    MD_SID(un));
	un->un_init_colcnt = 0;
	un->un_init_iocnt = 0;
	end_off = un->un_pwsize + (un->un_segsize * un->un_segsincolumn);
	zerosize = (size_t)MIN((diskaddr_t)un->un_maxio, end_off);

	/* allocate zero-filled buffer */
	zero_addr = kmem_zalloc(dbtob(zerosize), KM_SLEEP);

	for (ix = 0; ix < un->un_totalcolumncnt; ix++) {
		if (un->un_column[ix].un_devstate != RCS_INIT)
			continue;
		/* allocate new column init structure */
		cur = (raid_ci_t *)kmem_zalloc((sizeof (raid_ci_t)), KM_SLEEP);
		ASSERT(cur != NULL);
		un->un_init_colcnt++;
		cur->ci_next = ci_chain;
		ci_chain = cur;
		cur->ci_un = un;
		cur->ci_col = ix;
		cur->ci_err = 0;
		cur->ci_flag = COL_INITING;
		cur->ci_zerosize = zerosize;
		cur->ci_blkno = un->un_column[ix].un_pwstart;
		cur->ci_lastblk = cur->ci_blkno + un->un_pwsize
		    + (un->un_segsize * un->un_segsincolumn);
		/* initialize static buf fields */
		cur->ci_buf.b_un.b_addr = zero_addr;
		cur->ci_buf.b_chain = (buf_t *)cur;
		cur->ci_buf.b_back = &cur->ci_buf;
		cur->ci_buf.b_forw = &cur->ci_buf;
		cur->ci_buf.b_iodone = init_col_int;
		cur->ci_buf.b_flags = B_BUSY | B_WRITE;
		cur->ci_buf.b_edev = md_dev64_to_dev(un->un_column[ix].un_dev);
		sema_init(&cur->ci_buf.b_io, 0, NULL, SEMA_DEFAULT, NULL);
		sema_init(&cur->ci_buf.b_sem, 0, NULL, SEMA_DEFAULT, NULL);
		/* set address and length for I/O bufs */
		cur->ci_buf.b_bufsize = dbtob(zerosize);
		cur->ci_buf.b_bcount = dbtob(zerosize);
		cur->ci_buf.b_lblkno = un->un_column[ix].un_pwstart;
		cur->ci_buf.b_offset = -1;

		if (! (un->un_column[ix].un_devflags & MD_RAID_DEV_ISOPEN)) {
			md_dev64_t tmpdev = un->un_column[ix].un_dev;
			/*
			 * Open by device id
			 * If this column is hotspared then
			 * use the hotspare key
			 */
			tmpdev = md_resolve_bydevid(mnum, tmpdev,
			    HOTSPARED(un, ix) ?
			    un->un_column[ix].un_hs_key :
			    un->un_column[ix].un_orig_key);
			if ((cur->ci_err = md_layered_open(mnum, &tmpdev,
			    MD_OFLG_NULL)) == 0)
				un->un_column[ix].un_devflags |=
				    MD_RAID_DEV_ISOPEN;
			un->un_column[ix].un_dev = tmpdev;
		}
		if (cur->ci_err == 0)
			md_call_strategy(&cur->ci_buf, MD_STR_NOTTOP, NULL);
	}

	md_unit_readerexit(ui);
	state = un->un_state;
	colcnt = un->un_init_colcnt;
	mutex_enter(&un->un_mx);
	while (colcnt) {
		cv_wait(&un->un_cv, &un->un_mx);

		colcnt = 0;
		for (cur = ci_chain; cur != NULL; cur = cur->ci_next) {
			col = cur->ci_col;
			if ((cur->ci_flag != COL_INITING) || (cur->ci_err)) {
				if (cur->ci_err)
					err = cur->ci_err;
				else if (cur->ci_flag == COL_INIT_DONE) {
					(void) init_pw_area(un,
					    un->un_column[col].un_dev,
					    un->un_column[col].un_pwstart,
					    col);
					cur->ci_flag = COL_READY;
				}
			} else {
				colcnt++;
			}
		}
	}
	mutex_exit(&un->un_mx);

	/* This prevents new opens */
	rw_enter(&md_unit_array_rw.lock, RW_WRITER);
	(void) md_io_writerlock(ui);
	un = (mr_unit_t *)md_unit_writerlock(ui);
	while (ci_chain) {
		cur = ci_chain;

		/* take this element out of the chain */
		ci_chain = cur->ci_next;
		/* free this element */
		sema_destroy(&cur->ci_buf.b_io);
		sema_destroy(&cur->ci_buf.b_sem);
		if (cur->ci_err)
			raid_set_state(cur->ci_un, cur->ci_col,
			    RCS_INIT_ERRED, 0);
		else
			raid_set_state(cur->ci_un, cur->ci_col,
			    RCS_OKAY, 0);
		kmem_free(cur, sizeof (raid_ci_t));
	}

	/* free the zeroed buffer */
	kmem_free(zero_addr, dbtob(zerosize));

	/* determine new unit state */
	if (err == 0) {
		if (state == RUS_INIT)
			un->un_state = RUS_OKAY;
		else {
			un->c.un_total_blocks = un->un_grow_tb;
			md_nblocks_set(mnum, un->c.un_total_blocks);
			un->un_grow_tb = 0;
			if (raid_state_cnt(un, RCS_OKAY) ==
			    un->un_totalcolumncnt)
				un->un_state = RUS_OKAY;
		}
	} else {  /* error orcurred */
		if (state & RUS_INIT)
			un->un_state = RUS_DOI;
	}
	uniqtime32(&un->un_timestamp);
	MD_STATUS(un) &= ~MD_UN_GROW_PENDING;
	un->un_init_colcnt = 0;
	un->un_init_iocnt = 0;
	raid_commit(un, NULL);
	md_unit_writerexit(ui);
	(void) md_io_writerexit(ui);
	rw_exit(&md_unit_array_rw.lock);
	if (err) {
		if (un->un_state & RUS_DOI) {
			SE_NOTIFY(EC_SVM_STATE, ESC_SVM_INIT_FATAL,
			    SVM_TAG_METADEVICE, setno, MD_SID(un));
		} else {
			SE_NOTIFY(EC_SVM_STATE, ESC_SVM_INIT_FAILED,
			    SVM_TAG_METADEVICE, setno, MD_SID(un));
		}
	} else {
		SE_NOTIFY(EC_SVM_STATE, ESC_SVM_INIT_SUCCESS,
		    SVM_TAG_METADEVICE, setno, MD_SID(un));
	}
	(void) raid_internal_close(mnum, OTYP_LYR, 0, 0);
	/*
	 * Decrement the raid resync count for cpr
	 */
	mutex_enter(&md_cpr_resync.md_resync_mutex);
	md_cpr_resync.md_raid_resync--;
	mutex_exit(&md_cpr_resync.md_resync_mutex);
	thread_exit();
	/*NOTREACHED*/
}

static int
raid_init_unit(minor_t mnum, md_error_t *ep)
{
	mdi_unit_t	*ui;
	mr_unit_t	*un;
	int		rval, i;
	set_t		setno = MD_MIN2SET(mnum);

	ui = MDI_UNIT(mnum);
	if (md_get_setstatus(setno) & MD_SET_STALE)
		return (mdmddberror(ep, MDE_DB_STALE, mnum, setno));

	/* Don't start an init if the device is not available */
	if ((ui == NULL) || (ui->ui_tstate & MD_DEV_ERRORED)) {
		return (mdmderror(ep, MDE_RAID_OPEN_FAILURE, mnum));
	}

	if (raid_internal_open(mnum, (FREAD | FWRITE),
	    OTYP_LYR, MD_OFLG_ISINIT)) {
		rval = mdmderror(ep, MDE_RAID_OPEN_FAILURE, mnum);
		goto out;
	}

	un = md_unit_readerlock(ui);
	un->un_percent_done = 0;
	md_unit_readerexit(ui);
	/* start resync_unit thread */
	(void) thread_create(NULL, 0, raid_init_columns,
	    (void *)(uintptr_t)mnum, 0, &p0, TS_RUN, minclsyspri);

	return (0);

out:
	un = md_unit_writerlock(ui);
	MD_STATUS(un) &= ~MD_UN_GROW_PENDING;
	/* recover state */
	for (i = 0; i < un->un_totalcolumncnt; i++)
		if (COLUMN_STATE(un, i) == RCS_INIT)
			raid_set_state(un, i, RCS_ERRED, 0);
	if (un->un_state & RUS_INIT)
		un->un_state = RUS_DOI;
	raid_commit(un, NULL);
	md_unit_writerexit(ui);
	if (un->un_state & RUS_DOI) {
		SE_NOTIFY(EC_SVM_STATE, ESC_SVM_INIT_FATAL,
		    SVM_TAG_METADEVICE, MD_UN2SET(un), MD_SID(un));
	} else {
		SE_NOTIFY(EC_SVM_STATE, ESC_SVM_INIT_FAILED,
		    SVM_TAG_METADEVICE, MD_UN2SET(un), MD_SID(un));
	}
	return (rval);
}

/*
 * NAME:	raid_regen
 *
 * DESCRIPTION:	regenerate all the parity on the raid device.  This
 *		routine starts a thread that will regenerate the
 *		parity on a raid device.  If an I/O error occurs during
 *		this process the entire device is placed in error.
 *
 * PARAMETERS:	md_set_params_t *msp - ioctl packet
 */
static void
regen_unit(minor_t mnum)
{
	mdi_unit_t	*ui = MDI_UNIT(mnum);
	mr_unit_t	*un = MD_UNIT(mnum);
	buf_t		buf, *bp;
	caddr_t		buffer;
	int		err = 0;
	diskaddr_t	total_segments;
	diskaddr_t	line;
	size_t		iosize;

	/*
	 * Increment raid resync count for cpr
	 */
	mutex_enter(&md_cpr_resync.md_resync_mutex);
	md_cpr_resync.md_raid_resync++;
	mutex_exit(&md_cpr_resync.md_resync_mutex);

	iosize = dbtob(un->un_segsize);
	buffer = kmem_alloc(iosize, KM_SLEEP);
	bp = &buf;
	total_segments = un->un_segsincolumn;
	SE_NOTIFY(EC_SVM_STATE, ESC_SVM_REGEN_START, SVM_TAG_METADEVICE,
	    MD_UN2SET(un), MD_SID(un));
	un->un_percent_done = 0;
	init_buf(bp, B_READ | B_BUSY, iosize);

	for (line = 0; line < total_segments; line++) {
		bp->b_lblkno = line *
		    ((un->un_origcolumncnt - 1) * un->un_segsize);
		bp->b_un.b_addr = buffer;
		bp->b_bcount = iosize;
		bp->b_iodone = NULL;
		/*
		 * The following assignment is only correct because
		 * md_raid_strategy is fine when it's only a minor number
		 * and not a real dev_t. Yuck.
		 */
		bp->b_edev = mnum;
		md_raid_strategy(bp, MD_STR_NOTTOP, NULL);
		if (biowait(bp)) {
			err = 1;
			break;
		}
		un->un_percent_done = (uint_t)((line * 1000) /
		    un->un_segsincolumn);
		/* just to avoid rounding errors */
		if (un->un_percent_done > 1000)
			un->un_percent_done = 1000;
		reset_buf(bp, B_READ | B_BUSY, iosize);
	}
	destroy_buf(bp);
	kmem_free(buffer, iosize);

	(void) md_io_writerlock(ui);
	(void) raid_internal_close(mnum, OTYP_LYR, 0, 0);
	(void) md_io_writerexit(ui);
	un = md_unit_writerlock(ui);
	if (!err &&
	    (raid_state_cnt(un, RCS_OKAY) == un->un_totalcolumncnt))
			un->un_state = RUS_OKAY;
	raid_commit(un, NULL);
	md_unit_writerexit(ui);
	if (err ||
	    raid_state_cnt(un, RCS_OKAY) != un->un_totalcolumncnt) {
		SE_NOTIFY(EC_SVM_STATE, ESC_SVM_REGEN_FAILED,
		    SVM_TAG_METADEVICE, MD_UN2SET(un), MD_SID(un));
	} else {
		SE_NOTIFY(EC_SVM_STATE, ESC_SVM_REGEN_DONE, SVM_TAG_METADEVICE,
		    MD_UN2SET(un), MD_SID(un));
	}

	/*
	 * Decrement the raid resync count for cpr
	 */
	mutex_enter(&md_cpr_resync.md_resync_mutex);
	md_cpr_resync.md_raid_resync--;
	mutex_exit(&md_cpr_resync.md_resync_mutex);
	thread_exit();
}

static int
raid_regen_unit(minor_t mnum, md_error_t *ep)
{
	mdi_unit_t	*ui;
	mr_unit_t	*un;
	int		i;
	set_t		setno = MD_MIN2SET(mnum);

	ui = MDI_UNIT(mnum);
	un = (mr_unit_t *)MD_UNIT(mnum);

	if (md_get_setstatus(setno) & MD_SET_STALE)
		return (mdmddberror(ep, MDE_DB_STALE, mnum, setno));

	/* Don't start a regen if the device is not available */
	if ((ui == NULL) || (ui->ui_tstate & MD_DEV_ERRORED)) {
		return (mdmderror(ep, MDE_RAID_OPEN_FAILURE, mnum));
	}

	if (raid_internal_open(mnum, (FREAD | FWRITE), OTYP_LYR, 0)) {
		(void) md_unit_writerlock(ui);
		for (i = 0; i < un->un_totalcolumncnt; i++)
			raid_set_state(un, i, RCS_ERRED, 0);
		md_unit_writerexit(ui);
		return (mdmderror(ep, MDE_RAID_OPEN_FAILURE, mnum));
	}

	/* start resync_unit thread */
	(void) thread_create(NULL, 0, regen_unit,
	    (void *)(uintptr_t)mnum, 0, &p0, TS_RUN, minclsyspri);

	return (0);
}

static int
raid_regen(md_regen_param_t *mrp, IOLOCK *lock)
{
	minor_t		mnum = mrp->mnum;
	mr_unit_t	*un;

	mdclrerror(&mrp->mde);

	un = md_unit_readerlock(MDI_UNIT(mnum));

	if (MD_STATUS(un) & MD_UN_GROW_PENDING) {
		md_unit_readerexit(MDI_UNIT(mnum));
		return (mdmderror(&mrp->mde, MDE_IN_USE, mnum));
	}

	if ((MD_STATUS(un) & MD_UN_RESYNC_ACTIVE) ||
	    (raid_state_cnt(un, RCS_RESYNC))) {
		md_unit_readerexit(MDI_UNIT(mnum));
		return (mdmderror(&mrp->mde, MDE_RESYNC_ACTIVE, mnum));
	}

	if ((raid_state_cnt(un, RCS_INIT) != 0) || (un->un_state & RUS_INIT)) {
		md_unit_readerexit(MDI_UNIT(mnum));
		return (mdmderror(&mrp->mde, MDE_IN_USE, mnum));
	}

	if ((raid_state_cnt(un, RCS_OKAY) != un->un_totalcolumncnt) ||
	    (! (un->un_state & RUS_OKAY))) {
		md_unit_readerexit(MDI_UNIT(mnum));
		return (mdmderror(&mrp->mde, MDE_RAID_NOT_OKAY, mnum));
	}

	md_unit_readerexit(MDI_UNIT(mnum));

	/* get locks and recheck to be sure something did not change */
	if ((un = raid_getun(mnum, &mrp->mde, WRITERS, lock)) == NULL)
		return (0);

	if ((raid_state_cnt(un, RCS_OKAY) != un->un_totalcolumncnt) ||
	    (! (un->un_state & RUS_OKAY))) {
		return (mdmderror(&mrp->mde, MDE_RAID_NOT_OKAY, mnum));
	}

	raid_set_state(un, 0, RCS_REGEN, 0);
	raid_commit(un, NULL);
	md_ioctl_droplocks(lock);
	return (raid_regen_unit(mnum, &mrp->mde));
}

/*
 * NAME:	raid_set
 * DESCRIPTION: used to create a RAID metadevice
 * PARAMETERS:	md_set_params_t *d   - pointer to set data structure
 *		int		mode - must be FWRITE
 *
 * LOCKS:	none
 *
 */
static int
raid_set(void	*d, int mode)
{
	minor_t		mnum;
	mr_unit_t	*un;
	mddb_recid_t	mr_recid;
	mddb_recid_t	*recids;
	mddb_type_t	typ1;
	int		err;
	set_t		setno;
	int		num_recs;
	int		rid;
	int		col;
	md_set_params_t	*msp = d;


	mnum = msp->mnum;
	setno = MD_MIN2SET(mnum);

	mdclrerror(&msp->mde);

	if (raid_getun(mnum, &msp->mde, NO_OLD, NULL) == NULL)
		return (0);

	typ1 = (mddb_type_t)md_getshared_key(setno,
	    raid_md_ops.md_driver.md_drivername);

	/* create the db record for this mdstruct */

	if (msp->options & MD_CRO_64BIT) {
#if defined(_ILP32)
		return (mdmderror(&msp->mde, MDE_UNIT_TOO_LARGE, mnum));
#else
		mr_recid = mddb_createrec(msp->size, typ1, 0,
		    MD_CRO_64BIT | MD_CRO_RAID | MD_CRO_FN, setno);
#endif
	} else {
		mr_recid = mddb_createrec(msp->size, typ1, 0,
		    MD_CRO_32BIT | MD_CRO_RAID | MD_CRO_FN, setno);
	}

	if (mr_recid < 0)
		return (mddbstatus2error(&msp->mde,
		    (int)mr_recid, mnum, setno));

	/* get the address of the mdstruct */
	un = (mr_unit_t *)mddb_getrecaddr(mr_recid);
	/*
	 * It is okay that we muck with the mdstruct here,
	 * since no one else will know about the mdstruct
	 * until we commit it. If we crash, the record will
	 * be automatically purged, since we haven't
	 * committed it yet.
	 */

	/* copy in the user's mdstruct */
	if (err = ddi_copyin((caddr_t)(uintptr_t)msp->mdp, un,
	    msp->size, mode)) {
		mddb_deleterec_wrapper(mr_recid);
		return (EFAULT);
	}
	/* All 64 bit metadevices only support EFI labels. */
	if (msp->options & MD_CRO_64BIT) {
		un->c.un_flag |= MD_EFILABEL;
	}

	/*
	 * allocate the real recids array.  since we may have to commit
	 * underlying metadevice records, we need an array of size:
	 * total number of components in raid + 3 (1 for the raid itself,
	 * one for the hotspare, one for the end marker).
	 */
	num_recs = un->un_totalcolumncnt + 3;
	rid = 0;
	recids = kmem_alloc(num_recs * sizeof (mddb_recid_t), KM_SLEEP);
	recids[rid++] = mr_recid;

	MD_SID(un) = mnum;
	MD_RECID(un) = recids[0];
	MD_CAPAB(un) = MD_CAN_PARENT | MD_CAN_SP;
	MD_PARENT(un) = MD_NO_PARENT;
	un->un_resync_copysize = 0;
	un->c.un_revision |= MD_FN_META_DEV;

	if (UNIT_STATE(un) == RUS_INIT)
		MD_STATUS(un) |= MD_UN_GROW_PENDING;

	if ((UNIT_STATE(un) != RUS_INIT) && raid_check_pw(un)) {
		mddb_deleterec_wrapper(mr_recid);
		err = mderror(&msp->mde, MDE_RAID_INVALID);
		goto out;
	}

	if (err = raid_build_incore(un, 0)) {
		if (un->mr_ic) {
			kmem_free(un->un_column_ic, sizeof (mr_column_ic_t) *
			    un->un_totalcolumncnt);
			kmem_free(un->mr_ic, sizeof (*un->mr_ic));
		}

		md_nblocks_set(mnum, -1ULL);
		MD_UNIT(mnum) = NULL;

		mddb_deleterec_wrapper(mr_recid);
		goto out;
	}

	/*
	 * Update unit availability
	 */
	md_set[setno].s_un_avail--;

	recids[rid] = 0;
	if (un->un_hsp_id != -1) {
		/* increment the reference count of the hot spare pool */
		err = md_hot_spare_ifc(HSP_INCREF, un->un_hsp_id, 0, 0,
		    &recids[rid], NULL, NULL, NULL);
		if (err) {
			md_nblocks_set(mnum, -1ULL);
			MD_UNIT(mnum) = NULL;

			mddb_deleterec_wrapper(mr_recid);
			goto out;
		}
		rid++;
	}

	/*
	 * set the parent on any metadevice components.
	 * NOTE: currently soft partitions are the only metadevices
	 * which can appear within a RAID metadevice.
	 */
	for (col = 0; col < un->un_totalcolumncnt; col++) {
		mr_column_t	*mr_col = &un->un_column[col];
		md_unit_t	*comp_un;

		if (md_getmajor(mr_col->un_dev) == md_major) {
			comp_un = MD_UNIT(md_getminor(mr_col->un_dev));
			recids[rid++] = MD_RECID(comp_un);
			md_set_parent(mr_col->un_dev, MD_SID(un));
		}
	}

	/* set the end marker */
	recids[rid] = 0;

	mddb_commitrecs_wrapper(recids);
	md_create_unit_incore(mnum, &raid_md_ops, 1);

	SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_CREATE, SVM_TAG_METADEVICE, setno,
	    MD_SID(un));

out:
	kmem_free(recids, (num_recs * sizeof (mddb_recid_t)));
	if (err)
		return (err);

	/* only attempt to init a device that is in the init state */
	if (UNIT_STATE(un) != RUS_INIT)
		return (0);

	return (raid_init_unit(mnum, &msp->mde));
}

/*
 * NAME:	raid_get
 * DESCRIPTION: used to get the unit structure of a RAID metadevice
 * PARAMETERS:	md_i_get_t   *migp - pointer to get data structure
 *		int	      mode - must be FREAD
 *		IOLOCK	     *lock - pointer to IOCTL lock
 *
 * LOCKS:	obtains unit reader lock via IOLOCK
 *
 */
static int
raid_get(
	void		*migp,
	int		mode,
	IOLOCK		*lock
)
{
	minor_t		mnum;
	mr_unit_t	*un;
	md_i_get_t	*migph = migp;


	mnum = migph->id;

	mdclrerror(&migph->mde);

	if ((un = raid_getun(mnum, &migph->mde,
	    RD_LOCK, lock)) == NULL)
		return (0);

	if (migph->size == 0) {
		migph->size = un->c.un_size;
		return (0);
	}

	if (migph->size < un->c.un_size) {
		return (EFAULT);
	}
	if (ddi_copyout(un, (void *)(uintptr_t)migph->mdp,
	    un->c.un_size, mode))
		return (EFAULT);

	return (0);
}


/*
 * NAME:	raid_replace
 * DESCRIPTION: used to replace a component of a RAID metadevice
 * PARAMETERS:	replace_params_t *mrp - pointer to replace data structure
 *		IOLOCK	     *lock - pointer to IOCTL lock
 *
 * LOCKS:	obtains unit writer lock via IOLOCK (through raid_getun),
 *		obtains and releases md_unit_array_rw write lock
 *
 */
static int
raid_replace(
	replace_params_t	*mrp,
	IOLOCK			*lock
)
{
	minor_t		mnum = mrp->mnum;
	md_dev64_t	odev = mrp->old_dev;
	md_error_t	*ep = &mrp->mde;
	mr_unit_t	*un;
	rcs_state_t	state;
	int		ix, col = -1;
	int		force = 0;
	int		err = 0;
	replace_cmd_t	cmd;
	set_t		setno;
	side_t		side;
	mdkey_t		devkey;
	int		nkeys;
	mddb_recid_t	extra_recids[3] = { 0, 0, 0 };
	int		extra_rids = 0;
	md_error_t	mde = mdnullerror;
	sv_dev_t	sv = {MD_SET_BAD, MD_SIDEWILD, MD_KEYWILD};

	mdclrerror(ep);
	setno = MD_MIN2SET(mnum);
	side = mddb_getsidenum(setno);

	un = md_unit_readerlock(MDI_UNIT(mnum));

	if ((MD_STATUS(un) & MD_UN_RESYNC_ACTIVE) ||
	    (raid_state_cnt(un, RCS_RESYNC) != 0)) {
		md_unit_readerexit(MDI_UNIT(mnum));
		return (mdmderror(ep, MDE_RESYNC_ACTIVE, mnum));
	}

	if (un->un_state & RUS_DOI) {
		md_unit_readerexit(MDI_UNIT(mnum));
		return (mdmderror(ep, MDE_RAID_DOI, mnum));
	}

	if ((raid_state_cnt(un, RCS_INIT) != 0) || (un->un_state & RUS_INIT) ||
	    (MD_STATUS(un) & MD_UN_GROW_PENDING)) {
		md_unit_readerexit(MDI_UNIT(mnum));
		return (mdmderror(ep, MDE_IN_USE, mnum));
	}

	md_unit_readerexit(MDI_UNIT(mnum));

	/* get locks and recheck to be sure something did not change */
	if ((un = raid_getun(mnum, ep, WRITERS, lock)) == NULL)
		return (0);

	if (md_getkeyfromdev(setno, side, odev, &devkey, &nkeys) != 0) {
		return (mddeverror(ep, MDE_NAME_SPACE, odev));
	}

	for (ix = 0; ix < un->un_totalcolumncnt; ix++) {
		md_dev64_t tmpdevt = un->un_column[ix].un_orig_dev;
		/*
		 * Try to resolve devt again if NODEV64
		 */
		if (tmpdevt == NODEV64) {
			tmpdevt = md_resolve_bydevid(mnum, tmpdevt,
			    un->un_column[ix].un_orig_key);
			un->un_column[ix].un_orig_dev = tmpdevt;
		}

		if (un->un_column[ix].un_orig_dev == odev) {
			col = ix;
			break;
		} else {
			if (un->un_column[ix].un_orig_dev == NODEV64) {
				/*
				 * Now we use the keys to match.
				 * If no key found, continue.
				 */
				if (nkeys == 0) {
					continue;
				}
				if (un->un_column[ix].un_orig_key == devkey) {
					if (nkeys > 1)
						return (mddeverror(ep,
						    MDE_MULTNM, odev));
					col = ix;
					break;
				}
			}
		}
	}

	if (col == -1)
		return (mdcomperror(ep, MDE_CANT_FIND_COMP,
		    mnum, odev));

	if ((MD_STATUS(un) & MD_UN_RESYNC_ACTIVE) ||
	    (raid_state_cnt(un, RCS_RESYNC) != 0))
		return (mdmderror(ep, MDE_RESYNC_ACTIVE, mnum));

	if (un->un_state & RUS_DOI)
		return (mdcomperror(ep, MDE_REPL_INVAL_STATE, mnum,
		    un->un_column[col].un_dev));

	if ((raid_state_cnt(un, RCS_INIT) != 0) || (un->un_state & RUS_INIT) ||
	    (MD_STATUS(un) & MD_UN_GROW_PENDING))
		return (mdmderror(ep, MDE_IN_USE, mnum));

	if ((mrp->cmd == FORCE_ENABLE_COMP) || (mrp->cmd == FORCE_REPLACE_COMP))
		force = 1;
	if ((mrp->cmd == FORCE_ENABLE_COMP) || (mrp->cmd == ENABLE_COMP))
		cmd = ENABLE_COMP;
	if ((mrp->cmd == FORCE_REPLACE_COMP) || (mrp->cmd == REPLACE_COMP))
		cmd = REPLACE_COMP;

	if (un->un_state == RUS_LAST_ERRED) {
		/* Must use -f force flag for unit in LAST_ERRED state */
		if (!force)
			return (mdmderror(ep, MDE_RAID_NEED_FORCE, mnum));

		/* Must use -f force flag on ERRED column first */
		if (un->un_column[col].un_devstate != RCS_ERRED) {
			for (ix = 0; ix < un->un_totalcolumncnt; ix++) {
				if (un->un_column[ix].un_devstate & RCS_ERRED)
					return (mdcomperror(ep,
					    MDE_RAID_COMP_ERRED, mnum,
					    un->un_column[ix].un_dev));
			}
		}

		/* must use -f force flag on LAST_ERRED columns next */
		if ((un->un_column[col].un_devstate != RCS_LAST_ERRED) &&
		    (un->un_column[col].un_devstate != RCS_ERRED))
			return (mdcomperror(ep, MDE_RAID_COMP_ERRED,
			    mnum, un->un_column[col].un_dev));
	}

	if (un->un_state == RUS_ERRED) {
		if (! (un->un_column[col].un_devstate &
		    (RCS_ERRED | RCS_INIT_ERRED)))
			return (mdcomperror(ep, MDE_RAID_COMP_ERRED,
			    mnum, un->un_column[ix].un_dev));
	}

	ASSERT(!(un->un_column[col].un_devflags & MD_RAID_ALT_ISOPEN));
	ASSERT(!(un->un_column[col].un_devflags & MD_RAID_WRITE_ALT));

	state = un->un_column[col].un_devstate;
	if (state & RCS_INIT_ERRED) {
		MD_STATUS(un) |= MD_UN_GROW_PENDING;
		un->un_percent_done = 0;
		raid_set_state(un, col, RCS_INIT, 0);
	} else if (((mrp->options & MDIOCTL_NO_RESYNC_RAID) == 0) &&
	    resync_request(mnum, col, 0, ep))
		return (mdmderror(ep, MDE_RESYNC_ACTIVE, mnum));


	if (cmd == REPLACE_COMP) {
		md_dev64_t tmpdev = mrp->new_dev;

		/*
		 * open the device by device id
		 */
		tmpdev = md_resolve_bydevid(mnum, tmpdev, mrp->new_key);
		if (md_layered_open(mnum, &tmpdev, MD_OFLG_NULL)) {
			return (mdcomperror(ep, MDE_COMP_OPEN_ERR, mnum,
			    tmpdev));
		}

		/*
		 * If it's a metadevice, make sure it gets reparented
		 */
		if (md_getmajor(tmpdev) == md_major) {
			minor_t		new_mnum = md_getminor(tmpdev);
			md_unit_t	*new_un = MD_UNIT(new_mnum);

			md_set_parent(tmpdev, MD_SID(un));
			extra_recids[extra_rids++] = MD_RECID(new_un);
		}

		mrp->new_dev = tmpdev;
		un->un_column[col].un_orig_dev = tmpdev;
		un->un_column[col].un_orig_key = mrp->new_key;
		un->un_column[col].un_orig_pwstart = mrp->start_blk;
		un->un_column[col].un_orig_devstart =
		    mrp->start_blk + un->un_pwsize;

		/*
		 * If the old device was a metadevice, make sure to
		 * reset its parent.
		 */
		if (md_getmajor(odev) == md_major) {
			minor_t		old_mnum = md_getminor(odev);
			md_unit_t	*old_un = MD_UNIT(old_mnum);

			md_reset_parent(odev);
			extra_recids[extra_rids++] =
			    MD_RECID(old_un);
		}

		if (HOTSPARED(un, col)) {
			md_layered_close(mrp->new_dev, MD_OFLG_NULL);
			un->un_column[col].un_alt_dev = mrp->new_dev;
			un->un_column[col].un_alt_pwstart = mrp->start_blk;
			un->un_column[col].un_alt_devstart =
			    mrp->start_blk + un->un_pwsize;
			un->un_column[col].un_devflags |= MD_RAID_COPY_RESYNC;
		} else {
			/*
			 * not hot spared.  Close the old device and
			 * move the new device in.
			 */
			if (un->un_column[col].un_devflags & MD_RAID_DEV_ISOPEN)
				md_layered_close(odev, MD_OFLG_NULL);
			un->un_column[col].un_devflags |= MD_RAID_DEV_ISOPEN;
			un->un_column[col].un_dev = mrp->new_dev;
			un->un_column[col].un_pwstart = mrp->start_blk;
			un->un_column[col].un_devstart =
			    mrp->start_blk + un->un_pwsize;
			if ((mrp->options & MDIOCTL_NO_RESYNC_RAID) == 0) {
				un->un_column[col].un_devflags |=
				    MD_RAID_REGEN_RESYNC;
			}
		}
		/*
		 * If the old device is not a metadevice then
		 * save off the set number and key so that it
		 * can be removed from the namespace later.
		 */
		if (md_getmajor(odev) != md_major) {
			sv.setno = setno;
			sv.key = devkey;
		}
	}

	if (cmd == ENABLE_COMP) {
		md_dev64_t tmpdev = un->un_column[col].un_orig_dev;
		mdkey_t raidkey =  un->un_column[col].un_orig_key;

		/*
		 * We trust the dev_t because we cannot determine the
		 * dev_t from the device id since a new disk is in the
		 * same location. Since this is a call from metareplace -e dx
		 * AND it is SCSI a new dev_t is not generated.  So the
		 * dev_t from the mddb is used. Before enabling the device
		 * we check to make sure that multiple entries for the same
		 * device does not exist in the namespace. If they do we
		 * fail the ioctl.
		 * One of the many ways multiple entries in the name space
		 * can occur is if one removed the failed component in a
		 * RAID metadevice and put another disk that was part of
		 * another metadevice. After reboot metadevadm would correctly
		 * update the device name for the metadevice whose component
		 * has moved. However now in the metadb there are two entries
		 * for the same name (ctds) that belong to different
		 * metadevices. One is valid, the other is a ghost or "last
		 * know as" ctds.
		 */
		tmpdev = md_resolve_bydevid(mnum, tmpdev, raidkey);
		if (tmpdev == NODEV64)
			tmpdev = md_getdevnum(setno, side, raidkey,
			    MD_TRUST_DEVT);
		/*
		 * check for multiple entries in namespace for the
		 * same dev
		 */

		if (md_getkeyfromdev(setno, side, tmpdev, &devkey,
		    &nkeys) != 0)
			return (mddeverror(ep, MDE_NAME_SPACE, tmpdev));
		/*
		 * If number of keys are greater that
		 * 1, then we have an invalid
		 * namespace. STOP and return.
		 */
		if (nkeys > 1)
			return (mddeverror(ep, MDE_MULTNM, tmpdev));
		if (devkey != raidkey)
			return (mdcomperror(ep, MDE_CANT_FIND_COMP,
			    mnum, tmpdev));

		if (un->un_column[col].un_orig_dev == NODEV64)
			un->un_column[col].un_orig_dev = tmpdev;

		if (HOTSPARED(un, col)) {
			un->un_column[col].un_alt_dev =
			    un->un_column[col].un_orig_dev;
			un->un_column[col].un_alt_pwstart =
			    un->un_column[col].un_orig_pwstart;
			un->un_column[col].un_alt_devstart =
			    un->un_column[col].un_orig_devstart;
			un->un_column[col].un_devflags |= MD_RAID_COPY_RESYNC;
		} else {
			if (!(un->un_column[col].un_devflags &
			    MD_RAID_DEV_ISOPEN)) {
				if (md_layered_open(mnum, &tmpdev,
				    MD_OFLG_NULL)) {
					un->un_column[col].un_dev = tmpdev;
					return (mdcomperror(ep,
					    MDE_COMP_OPEN_ERR, mnum, tmpdev));
				}
				ASSERT(tmpdev != NODEV64 &&
				    tmpdev != 0);

				if ((md_getmajor(tmpdev) != md_major) &&
				    (md_devid_found(setno, side, raidkey)
				    == 1)) {
					if (md_update_namespace_did(setno, side,
					    raidkey, &mde) != 0) {
						cmn_err(CE_WARN,
						    "md: could not"
						    " update namespace\n");
					}
				}
				un->un_column[col].un_dev =
				    un->un_column[col].un_orig_dev;
			}
			un->un_column[col].un_devflags |= MD_RAID_DEV_ISOPEN;
			un->un_column[col].un_devflags |= MD_RAID_REGEN_RESYNC;
		}
	}
	if (mrp->has_label) {
		un->un_column[col].un_devflags |= MD_RAID_HAS_LABEL;
	} else {
		un->un_column[col].un_devflags &= ~MD_RAID_HAS_LABEL;
	}

	raid_commit(un, extra_recids);

	/* If the component has been replaced - clean up the name space */
	if (sv.setno != MD_SET_BAD) {
		md_rem_names(&sv, 1);
	}

	md_ioctl_droplocks(lock);

	if ((cmd == ENABLE_COMP) || (cmd == FORCE_ENABLE_COMP)) {
		SE_NOTIFY(EC_SVM_STATE, ESC_SVM_ENABLE, SVM_TAG_METADEVICE,
		    setno, MD_SID(un));
	} else {
		SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_REPLACE, SVM_TAG_METADEVICE,
		    setno, MD_SID(un));
	}

	if (un->un_column[col].un_devstate & RCS_INIT)
		err = raid_init_unit(mnum, ep);
	else if ((mrp->options & MDIOCTL_NO_RESYNC_RAID) == 0)
		err = raid_resync_unit(mnum, ep);

	mdclrerror(ep);
	if (!err)
		return (0);

	/* be sure state */
	/* is already set by this time */
	/* fix state  and commit record */
	un = md_unit_writerlock(MDI_UNIT(mnum));
	if (state & RCS_INIT_ERRED)
		raid_set_state(un, col, state, 1);
	else if (state & RCS_OKAY)
		raid_set_state(un, col, RCS_ERRED, 0);
	else
		raid_set_state(un, col, state, 1);
	raid_commit(un, NULL);
	md_unit_writerexit(MDI_UNIT(mnum));
	mdclrerror(ep);
	return (0);
}


/*
 * NAME:	raid_set_sync
 * DESCRIPTION: used to sync a component of a RAID metadevice
 * PARAMETERS:	md_resync_ioctl_t *mrp - pointer to resync data structure
 *		int	      mode - must be FWRITE
 *		IOLOCK	     *lock - pointer to IOCTL lock
 *
 * LOCKS:	obtains unit writer lock via IOLOCK (through raid_getun),
 *		obtains and releases md_unit_array_rw write lock
 *
 */
static int
raid_set_sync(
	md_resync_ioctl_t	*rip,
	IOLOCK			*lock
)
{
	minor_t			mnum = rip->ri_mnum;
	mr_unit_t		*un;
	int			init = 0;
	int			resync = 0;
	int			regen = 0;
	int			ix;
	int			err;

	mdclrerror(&rip->mde);

	if ((un = raid_getun(mnum, &rip->mde, WRITERS, lock)) == NULL)
		return (0);

	if (un->un_state & RUS_DOI)
		return (mdmderror(&rip->mde, MDE_RAID_DOI, mnum));

	if (un->c.un_status & MD_UN_RESYNC_ACTIVE)
		return (mdmderror(&rip->mde, MDE_RESYNC_ACTIVE, mnum));

	/* This prevents new opens */

	rip->ri_flags = 0;
	if (un->un_state & RUS_REGEN)
		regen++;

	if (raid_state_cnt(un, RCS_RESYNC))
		resync++;

	if (raid_state_cnt(un, RCS_INIT) || (un->un_state & RUS_INIT))
		init++;

	ASSERT(!(resync && init && regen));
	md_ioctl_droplocks(lock);
	rip->ri_percent_done = 0;

	if (init) {
		MD_STATUS(un) |= MD_UN_GROW_PENDING;
		return (raid_init_unit(mnum, &rip->mde));
	}

	/*
	 * If resync is needed, it will call raid_internal_open forcing
	 * replay before the open completes.
	 * Otherwise, call raid_internal_open directly to force
	 * replay to complete during boot (metasync -r).
	 * NOTE: the unit writer lock must remain held while setting
	 *	 MD_UN_RESYNC_ACTIVE but must be released before
	 *	 calling raid_resync_unit or raid_internal_open.
	 */
	if (resync) {
		ASSERT(resync < 2);
		un = md_unit_writerlock(MDI_UNIT(mnum));
		MD_STATUS(un) |= MD_UN_RESYNC_ACTIVE;
		/* Must release unit writer lock for resync */
		/*
		 * correctly setup the devices before trying to start the
		 * resync operation.
		 */
		for (ix = 0; un->un_totalcolumncnt; ix++) {
			if (un->un_column[ix].un_devstate & RCS_RESYNC) {
				if ((un->un_column[ix].un_devflags &
				    MD_RAID_COPY_RESYNC) &&
				    HOTSPARED(un, ix)) {
					un->un_column[ix].un_alt_dev =
					    un->un_column[ix].un_orig_dev;
					un->un_column[ix].un_alt_devstart =
					    un->un_column[ix].un_orig_devstart;
					un->un_column[ix].un_alt_pwstart =
					    un->un_column[ix].un_orig_pwstart;
				}
				break;
			}
		}
		ASSERT(un->un_column[ix].un_devflags &
		    (MD_RAID_COPY_RESYNC | MD_RAID_REGEN_RESYNC));
		rip->ri_percent_done = 0;
		un->un_column[ix].un_devflags |= MD_RAID_RESYNC;
		(void) resync_request(mnum, ix, 0, NULL);
		md_unit_writerexit(MDI_UNIT(mnum));
		err = raid_resync_unit(mnum, &rip->mde);
		return (err);
	}

	if (regen) {
		err = raid_regen_unit(mnum, &rip->mde);
		return (err);
	}

	/* The unit requires not work so just force replay of the device */
	if (raid_internal_open(mnum, (FREAD | FWRITE), OTYP_LYR, 0))
		return (mdmderror(&rip->mde,
		    MDE_RAID_OPEN_FAILURE, mnum));
	(void) raid_internal_close(mnum, OTYP_LYR, 0, 0);

	return (0);
}

/*
 * NAME:	raid_get_resync
 * DESCRIPTION: used to check resync status on a component of a RAID metadevice
 * PARAMETERS:	md_resync_ioctl_t *mrp - pointer to resync data structure
 *		int	      mode - must be FWRITE
 *		IOLOCK	     *lock - pointer to IOCTL lock
 *
 * LOCKS:	none
 *
 */
static int
raid_get_resync(
	md_resync_ioctl_t	*rip,
	IOLOCK			*lock
)
{
	minor_t			mnum = rip->ri_mnum;
	mr_unit_t		*un;
	u_longlong_t		percent;
	int			cnt;
	int			ix;
	uint64_t		d;

	mdclrerror(&rip->mde);

	if ((un = raid_getun(mnum, &rip->mde, RD_LOCK, lock)) == NULL)
		return (0);

	rip->ri_flags = 0;
	if (MD_STATUS(un) & MD_UN_RESYNC_ACTIVE) {
		d = un->un_segsincolumn;
		percent = d ? ((1000 * un->un_resync_line_index) / d) : 0;
		if (percent > 1000)
			percent = 1000;	/* can't go over 100% */
		rip->ri_percent_done = (int)percent;
		rip->ri_flags |= MD_RI_INPROGRESS;
	}

	if (UNIT_STATE(un) & RUS_INIT) {
		d = un->un_segsize * un->un_segsincolumn *
		    un->un_totalcolumncnt;
		percent =
		    d ? ((1000 * (u_longlong_t)un->un_init_iocnt) / d) : 0;
		if (percent > 1000)
			percent = 1000;	/* can't go over 100% */
		rip->ri_percent_done = (int)percent;
		rip->ri_flags |= MD_GROW_INPROGRESS;
	} else if (MD_STATUS(un) & MD_UN_GROW_PENDING) {
		d = un->un_segsize * un->un_segsincolumn * un->un_init_colcnt;
		percent =
		    d ? (((u_longlong_t)un->un_init_iocnt * 1000) / d) : 0;
		if (percent > 1000)
			percent = 1000;
		rip->ri_percent_done = (int)percent;
		rip->ri_flags |= MD_GROW_INPROGRESS;
	}

	if (un->un_state & RUS_REGEN)
		rip->ri_percent_done = un->un_percent_done;

	cnt = 0;
	for (ix = 0; ix < un->un_totalcolumncnt; ix++) {
		switch (un->un_column[ix].un_devstate) {
		case RCS_INIT:
		case RCS_ERRED:
		case RCS_LAST_ERRED:
			cnt++;
			break;
		default:
			break;
		}
	}
	d = un->un_totalcolumncnt;
	rip->ri_percent_dirty = d ? (((u_longlong_t)cnt * 100) / d) : 0;
	return (0);
}

/*
 * NAME:	raid_grow
 * DESCRIPTION: Concatenate to a RAID metadevice
 * PARAMETERS:	md_grow_params_t *mgp
 *			      - pointer to IOCGROW data structure
 *		int	 mode - must be FWRITE
 *		IOLOCK *lockp - IOCTL read/write and unit_array_rw lock
 *
 * LOCKS:	obtains unit writer lock via IOLOCK (through raid_getun),
 *		obtains and releases md_unit_array_rw write lock
 *
 */
static int
raid_grow(void *mgp, int mode, IOLOCK *lock)
{
	minor_t		mnum;
	mr_unit_t	*un, *new_un;
	mdi_unit_t	*ui;
	mddb_type_t	typ1;
	mddb_recid_t	mr_recid;
	mddb_recid_t	old_vtoc = 0;
	mddb_recid_t	*recids;
	md_create_rec_option_t options;
	int		err;
	int		col, i;
	int64_t		tb, atb;
	u_longlong_t	unrev;
	int		tc;
	int		rval = 0;
	set_t		setno;
	mr_column_ic_t	*mrc;
	int		num_recs, rid;
	md_grow_params_t	*mgph = mgp;


	mnum = mgph->mnum;

	mdclrerror(&mgph->mde);

	ui = MDI_UNIT(mnum);
	un = md_unit_readerlock(ui);

	if (MD_STATUS(un) & MD_UN_GROW_PENDING) {
		md_unit_readerexit(ui);
		return (mdmderror(&mgph->mde, MDE_IN_USE, mnum));
	}

	if (MD_STATUS(un) & MD_UN_RESYNC_ACTIVE) {
		md_unit_readerexit(ui);
		return (mdmderror(&mgph->mde, MDE_RESYNC_ACTIVE, mnum));
	}

	if (UNIT_STATE(un) & RUS_LAST_ERRED) {
		md_unit_readerexit(ui);
		return (mdmderror(&mgph->mde, MDE_RAID_LAST_ERRED, mnum));
	}

	if (UNIT_STATE(un) & RUS_DOI) {
		md_unit_readerexit(ui);
		return (mdmderror(&mgph->mde, MDE_RAID_DOI, mnum));
	}

	if ((raid_state_cnt(un, RCS_INIT) != 0) || (un->un_state & RUS_INIT)) {
		md_unit_readerexit(ui);
		return (mdmderror(&mgph->mde, MDE_IN_USE, mnum));
	}

	md_unit_readerexit(ui);

	if ((un = raid_getun(mnum, &mgph->mde, WRITERS, lock)) ==
	    NULL)
		return (0);

	if (MD_STATUS(un) & MD_UN_GROW_PENDING)
		return (mdmderror(&mgph->mde, MDE_IN_USE, mnum));

	if (MD_STATUS(un) & MD_UN_RESYNC_ACTIVE)
		return (mdmderror(&mgph->mde, MDE_RESYNC_ACTIVE, mnum));

	if (un->c.un_size >= mgph->size)
		return (EINVAL);

	if (UNIT_STATE(un) & RUS_LAST_ERRED)
		return (mdmderror(&mgph->mde, MDE_RAID_LAST_ERRED, mnum));

	if (UNIT_STATE(un) & RUS_DOI)
		return (mdmderror(&mgph->mde, MDE_RAID_DOI, mnum));

	if ((raid_state_cnt(un, RCS_INIT) != 0) || (un->un_state & RUS_INIT))
		return (mdmderror(&mgph->mde, MDE_IN_USE, mnum));

	setno = MD_MIN2SET(mnum);

	typ1 = (mddb_type_t)md_getshared_key(setno,
	    raid_md_ops.md_driver.md_drivername);

	/*
	 * Preserve the friendly name nature of the device that is
	 * growing.
	 */
	options = MD_CRO_RAID;
	if (un->c.un_revision & MD_FN_META_DEV)
		options |= MD_CRO_FN;
	if (mgph->options & MD_CRO_64BIT) {
#if defined(_ILP32)
		return (mdmderror(&mgph->mde, MDE_UNIT_TOO_LARGE, mnum));
#else
		mr_recid = mddb_createrec(mgph->size, typ1, 0,
		    MD_CRO_64BIT | options, setno);
#endif
	} else {
		mr_recid = mddb_createrec(mgph->size, typ1, 0,
		    MD_CRO_32BIT | options, setno);
	}
	if (mr_recid < 0) {
		rval = mddbstatus2error(&mgph->mde, (int)mr_recid,
		    mnum, setno);
		return (rval);
	}

	/* get the address of the new unit */
	new_un = (mr_unit_t *)mddb_getrecaddr(mr_recid);

	/*
	 * It is okay that we muck with the new unit here,
	 * since no one else will know about the unit struct
	 * until we commit it. If we crash, the record will
	 * be automatically purged, since we haven't
	 * committed it yet and the old unit struct will be found.
	 */

	/* copy in the user's unit struct */
	err = ddi_copyin((void *)(uintptr_t)mgph->mdp, new_un,
	    mgph->size, mode);
	if (err) {
		mddb_deleterec_wrapper(mr_recid);
		return (EFAULT);
	}

	/* make sure columns are being added */
	if (un->un_totalcolumncnt >= new_un->un_totalcolumncnt) {
		mddb_deleterec_wrapper(mr_recid);
		return (EINVAL);
	}

	/*
	 * Save a few of the new unit structs fields.
	 * Before they get clobbered.
	 */
	tc = new_un->un_totalcolumncnt;
	tb = new_un->c.un_total_blocks;
	atb = new_un->c.un_actual_tb;
	unrev = new_un->c.un_revision;

	/*
	 * Copy the old unit struct (static stuff)
	 * into new unit struct
	 */
	bcopy((caddr_t)un, (caddr_t)new_un, un->c.un_size);

	/*
	 * Restore a few of the new unit struct values.
	 */
	new_un->un_totalcolumncnt = tc;
	new_un->c.un_actual_tb = atb;
	new_un->un_grow_tb = tb;
	new_un->c.un_revision = unrev;
	new_un->c.un_record_id = mr_recid;
	new_un->c.un_size = mgph->size;

	ASSERT(new_un->mr_ic == un->mr_ic);

	/*
	 * Save old column slots
	 */
	mrc = un->un_column_ic;

	/*
	 * Allocate new column slot
	 */
	new_un->un_column_ic = (mr_column_ic_t *)
	    kmem_zalloc(sizeof (mr_column_ic_t) * new_un->un_totalcolumncnt,
	    KM_SLEEP);

	/*
	 * Restore old column slots
	 * Free the old column slots
	 */
	bcopy(mrc, new_un->un_column_ic,
	    sizeof (mr_column_ic_t) * un->un_totalcolumncnt);
	kmem_free(mrc, sizeof (mr_column_ic_t) * un->un_totalcolumncnt);

	/* All 64 bit metadevices only support EFI labels. */
	if (mgph->options & MD_CRO_64BIT) {
		new_un->c.un_flag |= MD_EFILABEL;
		/*
		 * If the device was previously smaller than a terabyte,
		 * and had a vtoc record attached to it, we remove the
		 * vtoc record, because the layout has changed completely.
		 */
		if (((un->c.un_revision & MD_64BIT_META_DEV) == 0) &&
		    (un->c.un_vtoc_id != 0)) {
			old_vtoc = un->c.un_vtoc_id;
			new_un->c.un_vtoc_id =
			    md_vtoc_to_efi_record(old_vtoc, setno);
		}
	}


	/*
	 * allocate the real recids array.  since we may have to commit
	 * underlying metadevice records, we need an array of size:
	 * total number of new components being attach + 2 (one for the
	 * raid itself, one for the end marker).
	 */
	num_recs = new_un->un_totalcolumncnt + 2;
	rid = 0;
	recids = kmem_alloc(num_recs * sizeof (mddb_recid_t), KM_SLEEP);
	recids[rid++] = mr_recid;

	for (col = un->un_totalcolumncnt;
	    (col < new_un->un_totalcolumncnt); col++) {
		mr_column_t	*mr_col = &new_un->un_column[col];
		md_unit_t	*comp_un;

		if (raid_build_pw_reservation(new_un, col) != 0) {
			/* release pwslots already allocated by grow */
			for (i = un->un_totalcolumncnt; i < col; i++) {
				raid_free_pw_reservation(new_un, i);
			}
			kmem_free(new_un->un_column_ic,
			    sizeof (mr_column_ic_t) *
			    new_un->un_totalcolumncnt);
			kmem_free(new_un->mr_ic, sizeof (*un->mr_ic));
			kmem_free(recids, num_recs * sizeof (mddb_recid_t));
			mddb_deleterec_wrapper(mr_recid);
			return (EINVAL);
		}
		/*
		 * set parent on metadevices being added.
		 * NOTE: currently soft partitions are the only metadevices
		 * which can appear within a RAID metadevice.
		 */
		if (md_getmajor(mr_col->un_dev) == md_major) {
			comp_un = MD_UNIT(md_getminor(mr_col->un_dev));
			recids[rid++] = MD_RECID(comp_un);
			md_set_parent(mr_col->un_dev, MD_SID(new_un));
		}
		new_un->un_column[col].un_devflags = 0;
	}

	/* set end marker */
	recids[rid] = 0;

	/* commit new unit struct */
	mddb_commitrecs_wrapper(recids);

	/* delete old unit struct */
	mddb_deleterec_wrapper(un->c.un_record_id);

	/* place new unit in in-core array */
	md_nblocks_set(mnum, new_un->c.un_total_blocks);
	MD_UNIT(mnum) = new_un;

	/*
	 * If old_vtoc has a non zero value, we know:
	 * - This unit crossed the border from smaller to larger one TB
	 * - There was a vtoc record for the unit,
	 * - This vtoc record is no longer needed, because
	 *   a new efi record has been created for this un.
	 */
	if (old_vtoc != 0) {
		mddb_deleterec_wrapper(old_vtoc);
	}

	/* free recids */
	kmem_free(recids, num_recs * sizeof (mddb_recid_t));

	SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_GROW, SVM_TAG_METADEVICE,
	    MD_UN2SET(new_un), MD_SID(new_un));
	MD_STATUS(new_un) |= MD_UN_GROW_PENDING;

	/*
	 * Since the md_ioctl_writelock aquires the unit write lock
	 * and open/close aquires the unit reader lock it is necessary
	 * to drop the unit write lock and then reaquire it as needed
	 * later.
	 */
	md_unit_writerexit(ui);

	if (raid_internal_open(mnum, (FREAD | FWRITE), OTYP_LYR, 0)) {
		rval = mdmderror(&mgph->mde, MDE_RAID_OPEN_FAILURE, mnum);
		SE_NOTIFY(EC_SVM_STATE, ESC_SVM_OPEN_FAIL, SVM_TAG_METADEVICE,
		    MD_UN2SET(new_un), MD_SID(new_un));
		return (rval);
	}
	(void) md_unit_writerlock(ui);
	for (i = 0; i < new_un->un_totalcolumncnt; i++) {
		if (new_un->un_column[i].un_devstate & RCS_OKAY)
			(void) init_pw_area(new_un, new_un->un_column[i].un_dev,
			    new_un->un_column[i].un_pwstart, i);
	}
	md_unit_writerexit(ui);
	(void) raid_internal_close(mnum, OTYP_LYR, 0, 0);
	(void) md_unit_writerlock(ui);
	/* create a background thread to initialize the columns */
	md_ioctl_droplocks(lock);

	return (raid_init_unit(mnum, &mgph->mde));
}

/*
 * NAME:	raid_reset
 * DESCRIPTION: used to reset (clear / remove) a RAID metadevice
 * PARAMETERS:	md_i_reset_t *mirp - pointer to reset data structure
 *
 * LOCKS:	obtains and releases md_unit_array_rw write lock
 *
 */
static int
raid_reset(md_i_reset_t	*mirp)
{
	minor_t		mnum = mirp->mnum;
	mr_unit_t	*un;
	mdi_unit_t	*ui;
	set_t		setno = MD_MIN2SET(mnum);

	mdclrerror(&mirp->mde);

	rw_enter(&md_unit_array_rw.lock, RW_WRITER);
	/*
	 * NOTE: need to get md_unit_writerlock to avoid conflict
	 * with raid_init thread.
	 */
	if ((un = raid_getun(mnum, &mirp->mde, NO_LOCK, NULL)) ==
	    NULL) {
		rw_exit(&md_unit_array_rw.lock);
		return (0);
	}
	ui = MDI_UNIT(mnum);

	if (MD_HAS_PARENT(MD_PARENT(un))) {
		rw_exit(&md_unit_array_rw.lock);
		return (mdmderror(&mirp->mde, MDE_IN_USE, mnum));
	}

	un = (mr_unit_t *)md_unit_openclose_enter(ui);
	if (md_unit_isopen(MDI_UNIT(mnum))) {
		md_unit_openclose_exit(ui);
		rw_exit(&md_unit_array_rw.lock);
		return (mdmderror(&mirp->mde, MDE_IS_OPEN, mnum));
	}
	md_unit_openclose_exit(ui);
	if (UNIT_STATE(un) != RUS_OKAY && !mirp->force) {
		rw_exit(&md_unit_array_rw.lock);
		return (mdmderror(&mirp->mde, MDE_RAID_NEED_FORCE, mnum));
	}

	reset_raid(un, mnum, 1);

	/*
	 * Update unit availability
	 */
	md_set[setno].s_un_avail++;

	/*
	 * If MN set, reset s_un_next so all nodes can have
	 * the same view of the next available slot when
	 * nodes are -w and -j
	 */
	if (MD_MNSET_SETNO(setno)) {
		(void) md_upd_set_unnext(setno, MD_MIN2UNIT(mnum));
	}

	rw_exit(&md_unit_array_rw.lock);

	return (0);
}

/*
 * NAME:	raid_get_geom
 * DESCRIPTION: used to get the geometry of a RAID metadevice
 * PARAMETERS:	mr_unit_t    *un - RAID unit to get the geometry for
 *		struct dk_geom *gp - pointer to geometry data structure
 *
 * LOCKS:	none
 *
 */
static int
raid_get_geom(
	mr_unit_t	*un,
	struct dk_geom	*geomp
)
{
	md_get_geom((md_unit_t *)un, geomp);

	return (0);
}

/*
 * NAME:	raid_get_vtoc
 * DESCRIPTION: used to get the VTOC on a RAID metadevice
 * PARAMETERS:	mr_unit_t    *un - RAID unit to get the VTOC from
 *		struct vtoc *vtocp - pointer to VTOC data structure
 *
 * LOCKS:	none
 *
 */
static int
raid_get_vtoc(
	mr_unit_t	*un,
	struct vtoc	*vtocp
)
{
	md_get_vtoc((md_unit_t *)un, vtocp);

	return (0);
}

/*
 * NAME:	raid_set_vtoc
 * DESCRIPTION: used to set the VTOC on a RAID metadevice
 * PARAMETERS:	mr_unit_t    *un - RAID unit to set the VTOC on
 *		struct vtoc *vtocp - pointer to VTOC data structure
 *
 * LOCKS:	none
 *
 */
static int
raid_set_vtoc(
	mr_unit_t	*un,
	struct vtoc	*vtocp
)
{
	return (md_set_vtoc((md_unit_t *)un, vtocp));
}


/*
 * NAME:	raid_get_extvtoc
 * DESCRIPTION: used to get the extended VTOC on a RAID metadevice
 * PARAMETERS:	mr_unit_t    *un - RAID unit to get the VTOC from
 *		struct extvtoc *vtocp - pointer to extended VTOC data structure
 *
 * LOCKS:	none
 *
 */
static int
raid_get_extvtoc(
	mr_unit_t	*un,
	struct extvtoc	*vtocp
)
{
	md_get_extvtoc((md_unit_t *)un, vtocp);

	return (0);
}

/*
 * NAME:	raid_set_extvtoc
 * DESCRIPTION: used to set the extended VTOC on a RAID metadevice
 * PARAMETERS:	mr_unit_t    *un - RAID unit to set the VTOC on
 *		struct extvtoc *vtocp - pointer to extended VTOC data structure
 *
 * LOCKS:	none
 *
 */
static int
raid_set_extvtoc(
	mr_unit_t	*un,
	struct extvtoc	*vtocp
)
{
	return (md_set_extvtoc((md_unit_t *)un, vtocp));
}



/*
 * NAME:	raid_get_cgapart
 * DESCRIPTION: used to get the dk_map on a RAID metadevice
 * PARAMETERS:	mr_unit_t    *un - RAID unit to set the VTOC on
 *		struct vtoc *dkmapp - pointer to dk_map data structure
 *
 * LOCKS:	none
 *
 */

static int
raid_get_cgapart(
	mr_unit_t	*un,
	struct dk_map	*dkmapp
)
{
	md_get_cgapart((md_unit_t *)un, dkmapp);
	return (0);
}

/*
 * NAME:	raid_getdevs
 * DESCRIPTION: return all devices within a RAID metadevice
 * PARAMETERS:	md_getdevs_params_t *mgdp
 *			      - pointer to getdevs IOCTL data structure
 *		int	 mode - should be FREAD
 *		IOLOCK *lockp - IOCTL read/write lock
 *
 * LOCKS:	obtains unit reader lock via IOLOCK
 *
 */
static int
raid_getdevs(
	void			*mgdp,
	int			mode,
	IOLOCK			*lock
)
{
	minor_t			mnum;
	mr_unit_t		*un;
	md_dev64_t		*udevs;
	int			i, cnt;
	md_dev64_t		unit_dev;
	md_getdevs_params_t	*mgdph = mgdp;


	mnum = mgdph->mnum;

	/* check out unit */
	mdclrerror(&mgdph->mde);

	if ((un = raid_getun(mnum, &mgdph->mde, RD_LOCK, lock)) == NULL)
		return (0);

	udevs = (md_dev64_t *)(uintptr_t)mgdph->devs;

	for (cnt = 0, i = 0; i < un->un_totalcolumncnt; i++, cnt++) {
		if (cnt < mgdph->cnt) {
			unit_dev = un->un_column[i].un_orig_dev;
			if (md_getmajor(unit_dev) != md_major) {
				if ((unit_dev = md_xlate_mini_2_targ
				    (unit_dev)) == NODEV64)
					return (ENODEV);
			}

			if (ddi_copyout((caddr_t)&unit_dev,
			    (caddr_t)&udevs[cnt], sizeof (*udevs), mode) != 0)
				return (EFAULT);
		}
		if (HOTSPARED(un, i)) {
			cnt++;
			if (cnt >= mgdph->cnt)
				continue;

			unit_dev = un->un_column[i].un_dev;
			if (md_getmajor(unit_dev) != md_major) {
				if ((unit_dev = md_xlate_mini_2_targ
				    (unit_dev)) == NODEV64)
					return (ENODEV);
			}

			if (ddi_copyout((caddr_t)&unit_dev,
			    (caddr_t)&udevs[cnt], sizeof (*udevs), mode) != 0)
				return (EFAULT);
		}
	}
	mgdph->cnt = cnt;
	return (0);
}

/*
 * NAME:	raid_change
 * DESCRIPTION: used to change the following dynamic values:
 *			the hot spare pool
 *		in the unit structure of a RAID metadevice
 * PARAMETERS:	md_change_params_t   *mcp - pointer to change data structure
 *		IOLOCK	     *lock - pointer to IOCTL lock
 *
 * LOCKS:	obtains unit writer lock via IOLOCK (through raid_getun)
 *
 */
static int
raid_change(
	md_raid_params_t	*mrp,
	IOLOCK			*lock
)
{
	minor_t		mnum = mrp->mnum;
	mr_unit_t	*un;
	int		ix;
	mddb_recid_t	recids[3] = {0, 0, 0};
	int		err;
	int		irecid;
	int		inc_new_hsp = 0;

	mdclrerror(&mrp->mde);

	if ((un = raid_getun(mnum, &mrp->mde, WR_LOCK, lock)) == NULL)
		return (0);

	if (!mrp->params.change_hsp_id)
		return (0);

	/* verify that no hotspare is in use */
	for (ix = 0; ix < un->un_totalcolumncnt; ix++) {
		if (HOTSPARED(un, ix)) {
			return (mdmderror(&mrp->mde, MDE_HS_IN_USE, mnum));
		}
	}

	/* replace the hot spare pool */

	irecid = 0;
	if (mrp->params.hsp_id != -1) {
		/* increment the reference count of the new hsp */
		err = md_hot_spare_ifc(HSP_INCREF, mrp->params.hsp_id, 0, 0,
		    &recids[0], NULL, NULL, NULL);
		if (err) {
			return (mdhsperror(&mrp->mde, MDE_INVAL_HSP,
			    mrp->params.hsp_id));
		}
		inc_new_hsp = 1;
		irecid++;
	}

	if (un->un_hsp_id != -1) {
		/* decrement the reference count of the old hsp */
		err = md_hot_spare_ifc(HSP_DECREF, un->un_hsp_id, 0, 0,
		    &recids[irecid], NULL, NULL, NULL);
		if (err) {
			err = mdhsperror(&mrp->mde, MDE_INVAL_HSP,
			    mrp->params.hsp_id);
			if (inc_new_hsp) {
				(void) md_hot_spare_ifc(HSP_DECREF,
				    mrp->params.hsp_id, 0, 0,
				    &recids[0], NULL, NULL, NULL);
				/*
				 * Don't need to commit the record,
				 * because it wasn't committed before
				 */
			}
			return (err);
		}
	}

	un->un_hsp_id = mrp->params.hsp_id;

	raid_commit(un, recids);
	SE_NOTIFY(EC_SVM_STATE, ESC_SVM_CHANGE, SVM_TAG_METADEVICE,
	    MD_UN2SET(un), MD_SID(un));

	/* Now trigger hot spare processing in case one is needed. */
	if ((un->un_hsp_id != -1) && (un->un_state == RUS_ERRED))
		(void) raid_hotspares();

	return (0);
}

/*
 * NAME:	raid_admin_ioctl
 * DESCRIPTION: IOCTL operations unique to metadevices and RAID
 * PARAMETERS:	int	  cmd - IOCTL command to be executed
 *		void	*data - pointer to IOCTL data structure
 *		int	 mode - either FREAD or FWRITE
 *		IOLOCK *lockp - IOCTL read/write lock
 *
 * LOCKS:	none
 *
 */
static int
raid_admin_ioctl(
	int		cmd,
	void		*data,
	int		mode,
	IOLOCK		*lockp
)
{
	size_t		sz = 0;
	void		*d = NULL;
	int		err = 0;

	/* We can only handle 32-bit clients for internal commands */
	if ((mode & DATAMODEL_MASK) != DATAMODEL_ILP32) {
		return (EINVAL);
	}


	/* dispatch ioctl */
	switch (cmd) {

	case MD_IOCSET:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (md_set_params_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = raid_set(d, mode);
		break;
	}

	case MD_IOCGET:
	{
		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (md_i_get_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = raid_get(d, mode, lockp);
		break;
	}

	case MD_IOCREPLACE:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (replace_params_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = raid_replace((replace_params_t *)d, lockp);
		break;
	}

	case MD_IOCSETSYNC:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (md_resync_ioctl_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = raid_set_sync((md_resync_ioctl_t *)d, lockp);
		break;
	}

	case MD_IOCGETSYNC:
	{
		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (md_resync_ioctl_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}
		err = raid_get_resync((md_resync_ioctl_t *)d, lockp);

		break;
	}

	case MD_IOCGROW:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (md_grow_params_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = raid_grow(d, mode, lockp);
		break;
	}

	case MD_IOCCHANGE:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (md_raid_params_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = raid_change((md_raid_params_t *)d, lockp);
		break;
	}

	case MD_IOCRESET:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (md_i_reset_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = raid_reset((md_i_reset_t *)d);
		break;
	}

	case MD_IOCGET_DEVS:
	{
		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (md_getdevs_params_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = raid_getdevs(d, mode, lockp);
		break;
	}

	case MD_IOCSETREGEN:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (md_regen_param_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = raid_regen((md_regen_param_t *)d, lockp);
		break;
	}

	case MD_IOCPROBE_DEV:
	{
		md_probedev_impl_t	*p = NULL;
		md_probedev_t		*ph = NULL;
		daemon_queue_t		*hdr = NULL;
		int			i;
		size_t			sz1 = 0;


		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (md_probedev_t);

		d = kmem_alloc(sz, KM_SLEEP);

		/* now copy in the data */
		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			goto free_mem;
		}

		/*
		 * Sanity test the args. Test name should have the keyword
		 * probe.
		 */
		p = kmem_alloc(sizeof (md_probedev_impl_t), KM_SLEEP);
		p->probe_sema = NULL;
		p->probe_mx = NULL;
		p->probe.mnum_list = (uint64_t)NULL;

		ph = (md_probedev_t *)d;
		p->probe.nmdevs = ph->nmdevs;
		(void) strcpy(p->probe.test_name, ph->test_name);
		bcopy(&ph->md_driver, &(p->probe.md_driver),
		    sizeof (md_driver_t));

		if ((p->probe.nmdevs < 1) ||
		    (strstr(p->probe.test_name, "probe") == NULL)) {
			err = EINVAL;
			goto free_mem;
		}

		sz1 = sizeof (minor_t) * p->probe.nmdevs;

		p->probe.mnum_list = (uint64_t)(uintptr_t)kmem_alloc(sz1,
		    KM_SLEEP);

		if (ddi_copyin((caddr_t)(uintptr_t)ph->mnum_list,
		    (caddr_t)(uintptr_t)p->probe.mnum_list, sz1, mode)) {
			err = EFAULT;
			goto free_mem;
		}

		if (err = md_init_probereq(p, &hdr))
			goto free_mem;

		/*
		 * put the request on the queue and wait.
		 */

		daemon_request_new(&md_ff_daemonq, md_probe_one, hdr, REQ_NEW);

		(void) IOLOCK_RETURN(0, lockp);
		/* wait for the events to occur */
		for (i = 0; i < p->probe.nmdevs; i++) {
			sema_p(PROBE_SEMA(p));
		}
		while (md_ioctl_lock_enter() == EINTR)
			;

		/*
		 * clean up. The hdr list is freed in the probe routines
		 * since the list is NULL by the time we get here.
		 */
free_mem:
		if (p) {
			if (p->probe_sema != NULL) {
				sema_destroy(PROBE_SEMA(p));
				kmem_free(p->probe_sema, sizeof (ksema_t));
			}
			if (p->probe_mx != NULL) {
				mutex_destroy(PROBE_MX(p));
				kmem_free(p->probe_mx, sizeof (kmutex_t));
			}
			if (p->probe.mnum_list)
				kmem_free((caddr_t)(uintptr_t)
				    p->probe.mnum_list, sz1);

			kmem_free(p, sizeof (md_probedev_impl_t));
		}
		break;
	}

	default:
		return (ENOTTY);
	}

	/*
	 * copyout and free any args
	 */
	if (sz != 0) {
		if (err == 0) {
			if (ddi_copyout(d, data, sz, mode) != 0) {
				err = EFAULT;
			}
		}
		kmem_free(d, sz);
	}
	return (err);
}

/*
 * NAME:	md_raid_ioctl
 * DESCRIPTION: RAID metadevice IOCTL operations entry point.
 * PARAMETERS:	md_dev64_t dev - RAID device identifier
 *		int	  cmd  - IOCTL command to be executed
 *		void	*data  - pointer to IOCTL data structure
 *		int	 mode  - either FREAD or FWRITE
 *		IOLOCK *lockp  - IOCTL read/write lock
 *
 * LOCKS:	none
 *
 */
int
md_raid_ioctl(
	dev_t		dev,
	int		cmd,
	void		*data,
	int		mode,
	IOLOCK		*lockp
)
{
	minor_t		mnum = getminor(dev);
	mr_unit_t	*un;
	int		err = 0;

	/* handle admin ioctls */
	if (mnum == MD_ADM_MINOR)
		return (raid_admin_ioctl(cmd, data, mode, lockp));

	/* check unit */
	if ((MD_MIN2SET(mnum) >= md_nsets) ||
	    (MD_MIN2UNIT(mnum) >= md_nunits) ||
	    ((un = MD_UNIT(mnum)) == NULL))
		return (ENXIO);

	/* is this a supported ioctl? */
	err = md_check_ioctl_against_unit(cmd, un->c);
	if (err != 0) {
		return (err);
	}

	/* dispatch ioctl */
	switch (cmd) {

	case DKIOCINFO:
	{
		struct dk_cinfo *p;

		if (! (mode & FREAD))
			return (EACCES);

		p = kmem_alloc(sizeof (*p), KM_SLEEP);

		get_info(p, mnum);
		if (ddi_copyout((caddr_t)p, data, sizeof (*p), mode) != 0)
			err = EFAULT;

		kmem_free(p, sizeof (*p));
		return (err);
	}

	case DKIOCGMEDIAINFO:
	{
		struct dk_minfo	p;

		if (! (mode & FREAD))
			return (EACCES);

		get_minfo(&p, mnum);
		if (ddi_copyout(&p, data, sizeof (struct dk_minfo), mode) != 0)
			err = EFAULT;

		return (err);
	}

	case DKIOCGGEOM:
	{
		struct dk_geom	*p;

		if (! (mode & FREAD))
			return (EACCES);

		p = kmem_alloc(sizeof (*p), KM_SLEEP);

		if ((err = raid_get_geom(un, p)) == 0) {
			if (ddi_copyout((caddr_t)p, data, sizeof (*p),
			    mode) != 0)
				err = EFAULT;
		}

		kmem_free(p, sizeof (*p));
		return (err);
	}

	case DKIOCGVTOC:
	{
		struct vtoc	*vtoc;

		if (! (mode & FREAD))
			return (EACCES);

		vtoc = kmem_zalloc(sizeof (*vtoc), KM_SLEEP);
		if ((err = raid_get_vtoc(un, vtoc)) != 0) {
			kmem_free(vtoc, sizeof (*vtoc));
			return (err);
		}

		if ((mode & DATAMODEL_MASK) == DATAMODEL_NATIVE) {
			if (ddi_copyout(vtoc, data, sizeof (*vtoc), mode))
				err = EFAULT;
		}
#ifdef _SYSCALL32
		else {
			struct vtoc32	*vtoc32;

			vtoc32 = kmem_zalloc(sizeof (*vtoc32), KM_SLEEP);

			vtoctovtoc32((*vtoc), (*vtoc32));
			if (ddi_copyout(vtoc32, data, sizeof (*vtoc32), mode))
				err = EFAULT;
			kmem_free(vtoc32, sizeof (*vtoc32));
		}
#endif /* _SYSCALL32 */

		kmem_free(vtoc, sizeof (*vtoc));
		return (err);
	}

	case DKIOCSVTOC:
	{
		struct vtoc	*vtoc;

		if (! (mode & FWRITE))
			return (EACCES);

		vtoc = kmem_zalloc(sizeof (*vtoc), KM_SLEEP);
		if ((mode & DATAMODEL_MASK) == DATAMODEL_NATIVE) {
			if (ddi_copyin(data, vtoc, sizeof (*vtoc), mode)) {
				err = EFAULT;
			}
		}
#ifdef _SYSCALL32
		else {
			struct vtoc32	*vtoc32;

			vtoc32 = kmem_zalloc(sizeof (*vtoc32), KM_SLEEP);

			if (ddi_copyin(data, vtoc32, sizeof (*vtoc32), mode)) {
				err = EFAULT;
			} else {
				vtoc32tovtoc((*vtoc32), (*vtoc));
			}
			kmem_free(vtoc32, sizeof (*vtoc32));
		}
#endif /* _SYSCALL32 */

		if (err == 0)
			err = raid_set_vtoc(un, vtoc);

		kmem_free(vtoc, sizeof (*vtoc));
		return (err);
	}

	case DKIOCGEXTVTOC:
	{
		struct extvtoc	*extvtoc;

		if (! (mode & FREAD))
			return (EACCES);

		extvtoc = kmem_zalloc(sizeof (*extvtoc), KM_SLEEP);
		if ((err = raid_get_extvtoc(un, extvtoc)) != 0) {
			kmem_free(extvtoc, sizeof (*extvtoc));
			return (err);
		}

		if (ddi_copyout(extvtoc, data, sizeof (*extvtoc), mode))
			err = EFAULT;

		kmem_free(extvtoc, sizeof (*extvtoc));
		return (err);
	}

	case DKIOCSEXTVTOC:
	{
		struct extvtoc	*extvtoc;

		if (! (mode & FWRITE))
			return (EACCES);

		extvtoc = kmem_zalloc(sizeof (*extvtoc), KM_SLEEP);
		if (ddi_copyin(data, extvtoc, sizeof (*extvtoc), mode)) {
			err = EFAULT;
		}

		if (err == 0)
			err = raid_set_extvtoc(un, extvtoc);

		kmem_free(extvtoc, sizeof (*extvtoc));
		return (err);
	}

	case DKIOCGAPART:
	{
		struct dk_map	dmp;

		if ((err = raid_get_cgapart(un, &dmp)) != 0) {
			return (err);
		}

		if ((mode & DATAMODEL_MASK) == DATAMODEL_NATIVE) {
			if (ddi_copyout((caddr_t)&dmp, data, sizeof (dmp),
			    mode) != 0)
				err = EFAULT;
		}
#ifdef _SYSCALL32
		else {
			struct dk_map32 dmp32;

			dmp32.dkl_cylno = dmp.dkl_cylno;
			dmp32.dkl_nblk = dmp.dkl_nblk;

			if (ddi_copyout((caddr_t)&dmp32, data, sizeof (dmp32),
			    mode) != 0)
				err = EFAULT;
		}
#endif /* _SYSCALL32 */

		return (err);
	}
	case DKIOCGETEFI:
	{
		/*
		 * This one can be done centralized,
		 * no need to put in the same code for all types of metadevices
		 */
		return (md_dkiocgetefi(mnum, data, mode));
	}

	case DKIOCSETEFI:
	{
		/*
		 * This one can be done centralized,
		 * no need to put in the same code for all types of metadevices
		 */
		return (md_dkiocsetefi(mnum, data, mode));
	}

	case DKIOCPARTITION:
	{
		return (md_dkiocpartition(mnum, data, mode));
	}

	default:
		return (ENOTTY);
	}
}

/*
 * rename/exchange named service entry points and support functions follow.
 * Most functions are handled generically, except for raid-specific locking
 * and checking
 */

/*
 * NAME:	raid_may_renexch_self
 * DESCRIPTION: support routine for rename check ("MDRNM_CHECK") named service
 * PARAMETERS:	mr_unit_t	*un - unit struct of raid unit to be renamed
 *		mdi_unit_t	*ui - in-core unit struct of same raid unit
 *		md_rentxn_t	*rtxnp - rename transaction state
 *
 * LOCKS:	none
 *
 */
static int
raid_may_renexch_self(
	mr_unit_t	*un,
	mdi_unit_t	*ui,
	md_rentxn_t	*rtxnp)
{
	minor_t	from_min;
	minor_t	to_min;
	bool_t	toplevel;
	bool_t	related;

	from_min = rtxnp->from.mnum;
	to_min = rtxnp->to.mnum;

	if (!un || !ui) {
		(void) mdmderror(&rtxnp->mde, MDE_RENAME_CONFIG_ERROR,
		    from_min);
		return (EINVAL);
	}

	ASSERT(!(MD_CAPAB(un) & MD_CAN_META_CHILD));
	if (MD_CAPAB(un) & MD_CAN_META_CHILD) {
		(void) mdmderror(&rtxnp->mde, MDE_RENAME_SOURCE_BAD, from_min);
		return (EINVAL);
	}

	if (MD_PARENT(un) == MD_MULTI_PARENT) {
		(void) mdmderror(&rtxnp->mde, MDE_RENAME_SOURCE_BAD, from_min);
		return (EINVAL);
	}

	toplevel = !MD_HAS_PARENT(MD_PARENT(un));

	/* we're related if trying to swap with our parent */
	related = (!toplevel) && (MD_PARENT(un) == to_min);

	switch (rtxnp->op) {
	case MDRNOP_EXCHANGE:

		if (!related) {
			(void) mdmderror(&rtxnp->mde,
			    MDE_RENAME_TARGET_UNRELATED, to_min);
			return (EINVAL);
		}

		break;

	case MDRNOP_RENAME:
		/*
		 * if from is top-level and is open, then the kernel is using
		 * the md_dev64_t.
		 */

		if (toplevel && md_unit_isopen(ui)) {
			(void) mdmderror(&rtxnp->mde, MDE_RENAME_BUSY,
			    from_min);
			return (EBUSY);
		}
		break;

	default:
		(void) mdmderror(&rtxnp->mde, MDE_RENAME_CONFIG_ERROR,
		    from_min);
		return (EINVAL);
	}

	return (0);	/* ok */
}

/*
 * NAME:	raid_rename_check
 * DESCRIPTION: ("MDRNM_CHECK") rename/exchange named service entry point
 * PARAMETERS:	md_rendelta_t	*delta - describes changes to be made to this
 *					 raid device for rename transaction
 *		md_rentxn_t	*rtxnp - rename transaction state
 *
 * LOCKS:	none
 *
 */
intptr_t
raid_rename_check(
	md_rendelta_t	*delta,
	md_rentxn_t	*rtxnp)
{
	int		 err	= 0;
	int		 column;
	mr_unit_t	*un;

	ASSERT(delta);
	ASSERT(rtxnp);
	ASSERT(delta->unp);
	ASSERT(delta->uip);

	if (!delta || !rtxnp || !delta->unp || !delta->uip) {
		(void) mdsyserror(&rtxnp->mde, EINVAL);
		return (EINVAL);
	}

	un = (mr_unit_t *)delta->unp;

	for (column = 0; column < un->un_totalcolumncnt; column++) {
		rcs_state_t	colstate;

		colstate = un->un_column[column].un_devstate;

		if (colstate & RCS_LAST_ERRED) {
			(void) mdmderror(&rtxnp->mde, MDE_RAID_LAST_ERRED,
			    md_getminor(delta->dev));
			return (EINVAL);
		}

		if (colstate & RCS_INIT_ERRED) {
			(void) mdmderror(&rtxnp->mde, MDE_RAID_DOI,
			    md_getminor(delta->dev));
			return (EINVAL);
		}

		/* How did we get this far before detecting this? */
		if (colstate & RCS_RESYNC) {
			(void) mdmderror(&rtxnp->mde, MDE_RENAME_BUSY,
			    md_getminor(delta->dev));
			return (EBUSY);
		}

		if (colstate & RCS_ERRED) {
			(void) mdmderror(&rtxnp->mde, MDE_RAID_NOT_OKAY,
			    md_getminor(delta->dev));
			return (EINVAL);
		}

		if (!(colstate & RCS_OKAY)) {
			(void) mdmderror(&rtxnp->mde, MDE_RAID_NOT_OKAY,
			    md_getminor(delta->dev));
			return (EINVAL);
		}

		if (HOTSPARED(un, column)) {
			(void) mdmderror(&rtxnp->mde, MDE_RAID_NOT_OKAY,
			    md_getminor(delta->dev));
			return (EINVAL);
		}
	}

	/* self does additional checks */
	if (delta->old_role == MDRR_SELF) {
		err = raid_may_renexch_self((mr_unit_t *)delta->unp,
		    delta->uip, rtxnp);
	}
	return (err);
}

/*
 * NAME:	raid_rename_lock
 * DESCRIPTION: ("MDRNM_LOCK") rename/exchange named service entry point
 * PARAMETERS:	md_rendelta_t	*delta - describes changes to be made to this
 *					 raid device for rename transaction
 *		md_rentxn_t	*rtxnp - rename transaction state
 *
 * LOCKS:	io and unit locks (taken explicitly *not* via ioctl wrappers)
 *
 */
intptr_t
raid_rename_lock(
	md_rendelta_t	*delta,
	md_rentxn_t	*rtxnp)
{
	minor_t		mnum;

	ASSERT(delta);
	ASSERT(rtxnp);

	mnum = md_getminor(delta->dev);
	if (mnum == rtxnp->to.mnum && rtxnp->op == MDRNOP_RENAME) {
		return (0);
	}

	ASSERT(delta->uip);
	if (!delta->uip) {
		(void) mdmderror(&rtxnp->mde, MDE_UNIT_NOT_SETUP, mnum);
		return (ENODEV);
	}

	ASSERT(delta->unp);
	if (!delta->unp) {

		return (ENODEV);
	}

	ASSERT(!IO_WRITER_HELD(delta->unp));
	(void) md_io_writerlock(delta->uip);
	ASSERT(IO_WRITER_HELD(delta->unp));


	ASSERT(!UNIT_WRITER_HELD(delta->unp));
	(void) md_unit_writerlock(delta->uip);
	ASSERT(UNIT_WRITER_HELD(delta->unp));

	return (0);
}

/*
 * NAME:	raid_rename_unlock
 * DESCRIPTION: ("MDRNM_UNLOCK") rename/exchange named service entry point
 * PARAMETERS:	md_rendelta_t	*delta - describes changes to be made to this
 *					 raid device for rename transaction
 *		md_rentxn_t	*rtxnp - rename transaction state
 *
 * LOCKS:	drops io and unit locks
 *
 */
/* ARGSUSED */
void
raid_rename_unlock(
	md_rendelta_t	*delta,
	md_rentxn_t	*rtxnp)
{
	mr_unit_t	*un = (mr_unit_t *)delta->unp;
	minor_t		mnum = MD_SID(un);
	int		col;

	ASSERT(delta);
	ASSERT(delta->unp);
	ASSERT(delta->uip);

	ASSERT(UNIT_WRITER_HELD(delta->unp));
	md_unit_writerexit(delta->uip);
	ASSERT(!UNIT_WRITER_HELD(delta->unp));

	if (! (delta->txn_stat.role_swapped) || ! (delta->txn_stat.is_open)) {
		goto out;
	}
	if (raid_internal_open(mnum, (FREAD | FWRITE),
	    OTYP_LYR, MD_OFLG_ISINIT) == 0) {
		for (col = 0; col < un->un_totalcolumncnt; col++) {
			if (un->un_column[col].un_devstate & RCS_OKAY)
				(void) init_pw_area(un,
				    un->un_column[col].un_dev,
				    un->un_column[col].un_pwstart, col);
		}
		(void) raid_internal_close(mnum, OTYP_LYR, 0, 0);
	}

out:
	ASSERT(IO_WRITER_HELD(delta->unp));
	md_io_writerexit(delta->uip);
	ASSERT(!IO_WRITER_HELD(delta->unp));
}
/* end of rename/exchange named service and support functions */
