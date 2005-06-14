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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/debug.h>
#include <sys/errno.h>
#include <sys/sysmacros.h>
#include <sys/t_lock.h>
#include <sys/kmem.h>
#include <sys/lvm/md_trans.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/file.h>
#include <sys/proc.h>
#include <sys/disp.h>
#include <sys/lvm/md_notify.h>
#include <sys/lvm/mdvar.h>

#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/svm.h>

extern unit_t		md_nunits;
extern set_t		md_nsets;
extern md_set_t		md_set[];

extern md_ops_t		trans_md_ops;
extern major_t		md_major;




static kmutex_t		ml_lock;
static ml_unit_t	*ul_list;	/* List of all log units */
static int		md_nlogs;
static kmutex_t		ut_mutex;	/* per log list of metatrans units */
static kmutex_t		oc_mutex;	/* single threads opens/closes */

static void		md_free_cirbuf(cirbuf_ic_t *cb);

#define	IOWAIT(bp)	sema_p(&bp->b_io)
#define	IODONE(bp)	sema_v(&bp->b_io)

void
_init_ldl(void)
{
	mutex_init(&ut_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&oc_mutex, NULL, MUTEX_DRIVER, NULL);
	mutex_init(&ml_lock, NULL, MUTEX_DRIVER, NULL);
}

void
_fini_ldl(void)
{
	mutex_destroy(&ut_mutex);
	mutex_destroy(&oc_mutex);
	mutex_destroy(&ml_lock);
}

static void
ldl_errorstate(ml_unit_t *ul)
{
	char	*str;

	if (ldl_iserror(ul))
		str = "Error";
	else if (ldl_isherror(ul))
		str = "Hard Error";
	else
		str = "Okay";

	cmn_err(CE_WARN, "md: logging device: %s changed state to %s",
	    md_devname(mddb_getsetnum(ul->un_recid), ul->un_dev, NULL, 0), str);
}


/*
 * atomically commit the log unit struct and any underlying metadevice struct
 */
static void
logcommitdb(ml_unit_t *ul)
{
	mddb_recid_t	recids[4];

	TRANSSTATS(ts_logcommitdb);

	uniqtime32(&ul->un_timestamp);

	/*
	 * commit the log device and its child (if metadevice)
	 */
	recids[0] = ul->un_recid;
	if (ul->un_status & LDL_METADEVICE) {
		struct mdc_unit	*c = MD_UNIT(md_getminor(ul->un_dev));
		recids[1] = c->un_record_id;
		recids[2] = 0;
	} else
		recids[1] = 0;

	mddb_commitrecs_wrapper(recids);
}

static void
md_alloc_wrbuf(cirbuf_ic_t *cb, size_t bufsize)
{
	int	i;
	buf_t	*bp;

	/*
	 * Clear previous allocation
	 */
	if (cb->cb_nb)
		md_free_cirbuf(cb);

	bzero((caddr_t)cb, sizeof (*cb));
	rw_init(&cb->cb_rwlock.lock, NULL, RW_DRIVER, NULL);

	rw_enter(&cb->cb_rwlock.lock, RW_WRITER);

	/*
	 * preallocate 3 bp's and put them on the free list.
	 */
	for (i = 0; i < 3; ++i) {
		bp = md_trans_zalloc(sizeof (buf_t));
		sema_init(&bp->b_sem, 1, NULL, SEMA_DEFAULT, NULL);
		sema_init(&bp->b_io, 0, NULL, SEMA_DEFAULT, NULL);
		bp->b_offset = -1;
		bp->b_forw = cb->cb_free;
		cb->cb_free = bp;

		TRANSSTATS(ts_alloc_bp);
	}

	cb->cb_va = md_trans_alloc(bufsize);
	cb->cb_nb = bufsize;

	/*
	 * first bp claims entire write buffer
	 */
	bp = cb->cb_free;
	cb->cb_free = bp->b_forw;

	bp->b_forw = bp;
	bp->b_back = bp;
	cb->cb_bp = bp;
	bp->b_un.b_addr = cb->cb_va;
	bp->b_bufsize = cb->cb_nb;

	rw_exit(&cb->cb_rwlock.lock);
}

static void
md_alloc_rdbuf(cirbuf_ic_t *cb, size_t bufsize, size_t blksize)
{
	caddr_t	va;
	size_t	nb;
	buf_t	*bp;

	/*
	 * Clear previous allocation
	 */
	if (cb->cb_nb)
		md_free_cirbuf(cb);

	bzero((caddr_t)cb, sizeof (*cb));
	rw_init(&cb->cb_rwlock.lock, NULL, RW_DRIVER, NULL);

	rw_enter(&cb->cb_rwlock.lock, RW_WRITER);

	cb->cb_va = md_trans_alloc(bufsize);
	cb->cb_nb = bufsize;

	/*
	 * preallocate N bufs that are hard-sized to blksize
	 *	in other words, the read buffer pool is a linked list
	 *	of statically sized bufs.
	 */
	va = cb->cb_va;
	while ((nb = bufsize) != 0) {
		if (nb > blksize)
			nb = blksize;
		bp = md_trans_alloc(sizeof (buf_t));
		bzero((caddr_t)bp, sizeof (buf_t));
		sema_init(&bp->b_sem, 1, NULL, SEMA_DEFAULT, NULL);
		sema_init(&bp->b_io, 0, NULL, SEMA_DEFAULT, NULL);
		bp->b_un.b_addr = va;
		bp->b_bufsize = nb;
		bp->b_offset = -1;
		if (cb->cb_bp) {
			bp->b_forw = cb->cb_bp->b_forw;
			bp->b_back = cb->cb_bp;
			cb->cb_bp->b_forw->b_back = bp;
			cb->cb_bp->b_forw = bp;
		} else
			bp->b_forw = bp->b_back = bp;
		cb->cb_bp = bp;

		TRANSSTATS(ts_alloc_bp);

		bufsize -= nb;
		va += nb;
	}

	rw_exit(&cb->cb_rwlock.lock);
}


static void
md_free_cirbuf(cirbuf_ic_t *cb)
{
	buf_t	*bp;

	if (cb->cb_nb == 0)
		return;

	rw_enter(&cb->cb_rwlock.lock, RW_WRITER);
	ASSERT(cb->cb_dirty == NULL);

	/*
	 * free the active bufs
	 */
	while ((bp = cb->cb_bp) != NULL) {
		if (bp == bp->b_forw)
			cb->cb_bp = NULL;
		else
			cb->cb_bp = bp->b_forw;
		bp->b_back->b_forw = bp->b_forw;
		bp->b_forw->b_back = bp->b_back;
		sema_destroy(&bp->b_sem);
		sema_destroy(&bp->b_io);
		md_trans_free(bp, sizeof (buf_t));
	}

	/*
	 * free the free bufs
	 */
	while ((bp = cb->cb_free) != NULL) {
		cb->cb_free = bp->b_forw;
		sema_destroy(&bp->b_sem);
		sema_destroy(&bp->b_io);
		md_trans_free(bp, sizeof (buf_t));
	}
	md_trans_free(cb->cb_va, cb->cb_nb);
	cb->cb_va = NULL;
	cb->cb_nb = 0;
	rw_exit(&cb->cb_rwlock.lock);
	rw_destroy(&cb->cb_rwlock.lock);
}

int
ldl_build_incore(ml_unit_t *ul, int snarfing)
{
	size_t	bufsize;
	set_t	setno;

	setno = mddb_getsetnum(ul->un_recid);

	ASSERT(ul->un_head_lof >= ul->un_bol_lof);
	ASSERT(ul->un_bol_lof);

	if (ul->un_status & LDL_BEING_RESET) {
		mddb_setrecprivate(ul->un_recid, MD_PRV_PENDCLEAN);
		return (1);
	}

	/*
	 * If snarfing the log device,
	 *	then remake the device number
	 *	else (we are creating the log device)
	 *	    set the driver name in the shared name space.
	 */
	if (snarfing) {
		ul->un_dev = md_getdevnum(setno, mddb_getsidenum(setno),
						ul->un_key, MD_NOTRUST_DEVT);
	}

	/*
	 * With the current device id implementation there is possibility
	 * that we may have NODEV if the underlying can't be resolved at
	 * snarf time.  If this is the case we want to be consistent with
	 * the normal behavior and continue to allow log to be put on the list.
	 * We delay the resolve of the dev_t so we can resolve at the open
	 * time of the log device by device id
	 */
	if ((md_getmajor(ul->un_dev) == md_major) &&
		(md_dev_exists(ul->un_dev) == 0)) {
		return (1);
	}

	mutex_enter(&ml_lock);

	/*
	 * initialize incore structs
	 * 	LDL_FIND_TAIL flag indicates that all I/O must wait until the
	 * 	tail has been found.
	 */
	ul->un_opencnt = 0;
	ul->un_transcnt = 0;
	ul->un_resv = 0;
	ul->un_utlist = NULL;
	ul->un_logmap = NULL;
	ul->un_status |= LDL_FIND_TAIL;
	ul->un_status &= ~LDL_SCAN_ACTIVE;
	ASSERT(ul->un_devbsize == DEV_BSIZE);

	mutex_init(&ul->un_log_mutex, NULL, MUTEX_DRIVER, NULL);

	/*
	 * allocate some read and write buffers
	 */
	bufsize = md_ldl_bufsize(ul);
	ul->un_rdbuf.cb_nb = 0;
	md_alloc_rdbuf(&ul->un_rdbuf, bufsize, MAPBLOCKSIZE);
	ul->un_wrbuf.cb_nb = 0;
	md_alloc_wrbuf(&ul->un_wrbuf, bufsize);

	if (snarfing) {
		if (ul->un_error & LDL_ANYERROR) {
			ul->un_error = LDL_HERROR;
			ldl_errorstate(ul);
		} else
			ul->un_error = 0;
	}

	/* Put on the unit list */
	ul->un_next = ul_list;
	ul_list = ul;
	md_nlogs++;

	mutex_exit(&ml_lock);
	return (0);
}

ml_unit_t *
ldl_findlog(mddb_recid_t recid)
{
	ml_unit_t	*ul;

	/*
	 * Find a unit struct by database recid
	 */
	mutex_enter(&ml_lock);
	for (ul = ul_list; ul; ul = ul->un_next)
		if (ul->un_recid == recid)
			break;
	mutex_exit(&ml_lock);
	return (ul);
}

/*
 * ldl_utadd adds a metatrans device to the log's list of mt devices.
 *   WARNING: top_end_sync() scans this list W/O locking for performance!!!
 */
void
ldl_utadd(mt_unit_t *un)
{
	ml_unit_t	*ul	= un->un_l_unit;

	if (ul == NULL)
		return;

	mutex_enter(&ut_mutex);
	un->un_next = ul->un_utlist;
	ul->un_utlist = un;
	ASSERT((ul->un_logmap == NULL) || (ul->un_logmap == un->un_logmap));
	ul->un_logmap = un->un_logmap;
	mutex_exit(&ut_mutex);
}

/*
 * ldl_utdel removes a metatrans device to the log's list of mt devices.
 *   WARNING: top_end_sync() scans this list W/O locking for performance!!!
 */
static void
ldl_utdel(mt_unit_t *un)
{
	ml_unit_t	*ul	= un->un_l_unit;
	mt_unit_t	**utp	= &ul->un_utlist;

	mutex_enter(&ut_mutex);
	for (utp = &ul->un_utlist;
	    *utp && (*utp != un);
	    utp = &(*utp)->un_next);
	if (*utp)
		*utp = un->un_next;
	un->un_l_unit = NULL;
	mutex_exit(&ut_mutex);
}

mddb_recid_t
ldl_create(mdkey_t key, mt_unit_t *un)
{
	ml_unit_t 	*ul;
	mddb_recid_t	recid;
	struct timeval32 tv;
	mddb_type_t	typ1;
	set_t		setno;

	setno = MD_UN2SET(un);

	/*
	 * Find a unit struct for this key and set
	 *	If we found one then, we are done.
	 *	Else create one.
	 */
	mutex_enter(&ml_lock);
	for (ul = ul_list; ul; ul = ul->un_next)
		if ((ul->un_key == key) &&
		    (mddb_getsetnum(ul->un_recid) == setno))
			break;
	mutex_exit(&ml_lock);

	if (ul)
		return (ul->un_recid);

	typ1 = (mddb_type_t)md_getshared_key(setno,
	    trans_md_ops.md_driver.md_drivername);
	recid = mddb_createrec(ML_UNIT_ONDSZ, typ1, LOG_REC,
		MD_CRO_32BIT | MD_CRO_TRANS_LOG, setno);
	if (recid < 0)
		return (recid);
	mddb_setrecprivate(recid, MD_PRV_GOTIT);

	ul = (ml_unit_t *)mddb_getrecaddr_resize(recid, sizeof (*ul), 0);

	ul->un_recid = recid;
	ul->un_key = key;
	ul->un_dev = md_getdevnum(setno, mddb_getsidenum(setno), key,
							MD_NOTRUST_DEVT);
	ul->un_bol_lof = (off32_t)dbtob(un->un_l_sblk);
	ul->un_eol_lof = ul->un_bol_lof + (off32_t)dbtob(un->un_l_nblks);
	ul->un_pwsblk = un->un_l_pwsblk;
	ul->un_nblks = un->un_l_nblks;
	ul->un_tblks = un->un_l_tblks;
	ul->un_maxresv = un->un_l_maxresv;
	ul->un_maxtransfer = (uint_t)dbtob(un->un_l_maxtransfer);
	ul->un_devbsize = DEV_BSIZE;

	/*
	 * empty log
	 */
	uniqtime32(&tv);
	ul->un_head_lof = ul->un_bol_lof;
	ul->un_tail_lof = ul->un_bol_lof;
	ul->un_head_ident = tv.tv_sec;
	ul->un_tail_ident = tv.tv_sec;

	if (md_getmajor(ul->un_dev) == md_major)
		ul->un_status |= LDL_METADEVICE;

	md_set_parent(ul->un_dev, (int)MD_MULTI_PARENT);
	(void) ldl_build_incore(ul, 0);
	logcommitdb(ul);
	return (recid);
}

int
ldl_open_dev(mt_unit_t *un, ml_unit_t *ul)
{
	int 		err	= 0;
	md_dev64_t 	tmpdev;
	minor_t		mnum = MD_SID(un);
	set_t		setno = MD_MIN2SET(MD_SID(un));
	side_t		side = mddb_getsidenum(setno);

	mutex_enter(&oc_mutex);

	if (ul->un_opencnt) {
		ul->un_opencnt++;
		mutex_exit(&oc_mutex);
		return (0);
	}

	tmpdev = ul->un_dev;
	/*
	 * Do the open by device id if it is regular device
	 */
	if ((md_getmajor(tmpdev) != md_major) &&
		md_devid_found(setno, side, ul->un_key) == 1) {
		tmpdev = md_resolve_bydevid(mnum, tmpdev, ul->un_key);
	}
	err = md_layered_open(mnum, &tmpdev, MD_OFLG_NULL);
	ul->un_dev = tmpdev;

	if (err == 0)
		ul->un_opencnt++;

	mutex_exit(&oc_mutex);
	return (err);
}

void
ldl_close_dev(ml_unit_t *ul)
{

	mutex_enter(&oc_mutex);

	ul->un_opencnt--;

	if (ul->un_opencnt) {
		mutex_exit(&oc_mutex);
		return;
	}

	/* Last reference to the log, close it */
	md_layered_close(ul->un_dev, MD_OFLG_NULL);

	mutex_exit(&oc_mutex);
}


/*
 * LOGSCAN STUFF
 */
int
ldl_isherror(ml_unit_t *ul)
{
	return ((ul != NULL) && (ul->un_error & LDL_HERROR));
}

int
ldl_iserror(ml_unit_t *ul)
{
	return ((ul != NULL) && (ul->un_error & LDL_ERROR));
}

size_t
md_ldl_bufsize(ml_unit_t *ul)
{
	size_t	bufsize;

	/*
	 * initial guess is the maxtransfer value for this log device
	 * 	reduce by number of logs
	 * 	increase for sharing
	 * 	increase if too small
	 * 	decrease if too large
	 */
	bufsize = ul->un_maxtransfer;
	if (md_nlogs)
		bufsize /= md_nlogs;
	if (ul->un_transcnt)
		bufsize *= ul->un_transcnt;
	bufsize = dbtob(btod(bufsize));
	if (bufsize < LDL_MINBUFSIZE)
		bufsize = LDL_MINBUFSIZE;
	if (bufsize > maxphys)
		bufsize = maxphys;
	if (bufsize > ul->un_maxtransfer)
		bufsize = ul->un_maxtransfer;
	return (bufsize);
}

/*
 * if necessary; open all underlying devices for ul and start threads
 *	called at snarf, metainit, and open
 */
void
ldl_open_underlying(mt_unit_t *un)
{
	ml_unit_t	*ul	= un->un_l_unit;
	int		err	= 0;


	/*
	 * first, handle the case of detached logs
	 */
	if (ul == NULL) {
		err = trans_open_all_devs(un);
		if (err == 0) {
			un->un_flags &= ~TRANS_NEED_OPEN;
			un->un_flags |= TRANS_OPENED;
		}
	}
}

/*
 * remove log unit struct from global linked list
 */
static void
ldl_unlist(ml_unit_t *ul)
{
	ml_unit_t 	**ulp;

	/*
	 * remove from list
	 */
	mutex_enter(&ml_lock);
	for (ulp = &ul_list; *ulp && (*ulp != ul); ulp = &(*ulp)->un_next);
	if (*ulp) {
		*ulp = ul->un_next;
		--md_nlogs;
	}
	mutex_exit(&ml_lock);
}

/*
 * get rid of a log unit from the database
 */
void
ldl_cleanup(ml_unit_t *ul)
{
	sv_dev_t	sv;

	/* Save the log key */
	sv.setno = mddb_getsetnum(ul->un_recid);
	sv.key = ul->un_key;

	mddb_deleterec_wrapper(ul->un_recid);
	md_rem_names(&sv, 1);
}

static void
ldl_delete(ml_unit_t *ul, int removing)
{

	/*
	 * remove from list
	 */
	ldl_unlist(ul);

	/*
	 * free up resources
	 */
	md_free_cirbuf(&ul->un_rdbuf);
	md_free_cirbuf(&ul->un_wrbuf);

	mutex_destroy(&ul->un_log_mutex);

	if (removing) {
		md_reset_parent(ul->un_dev);
		ul->un_status |= LDL_BEING_RESET;
		logcommitdb(ul);
		ldl_cleanup(ul);
	}
}

/*
 * detach log from trans device
 * 	caller insures that trans device is idle and will remain idle
 */
/* ARGSUSED */
int
ldl_reset(mt_unit_t *un, int removing, int force)
{
	ml_unit_t	*ul	= un->un_l_unit;

	if (ul == NULL)
		return (0);

	if (un->un_flags & TRANS_DETACHING) {
		un->un_flags &= ~TRANS_DETACHING;
		un->un_flags |= TRANS_DETACHED;
		trans_commit(un, 0);
	}

	/*
	 * remove this metatrans device from the log's list of mt devices
	 */
	ldl_utdel(un);

	/*
	 * busy; do nothing
	 */
	if (ul->un_utlist)
		return (0);

	ldl_delete(ul, removing);

	return (0);
}
