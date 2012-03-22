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
 * Copyright (c) 2011 Bayard G. Bell. All rights reserved.
 * Copyright 2012 Milan Jurik. All rights reserved.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/conf.h>
#include <sys/debug.h>
#include <sys/file.h>
#include <sys/user.h>
#include <sys/uio.h>
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
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/disp.h>
#include <sys/buf.h>

#include <sys/lvm/mdvar.h>
#include <sys/lvm/md_trans.h>
#include <sys/lvm/md_notify.h>
#include <sys/lvm/md_convert.h>

#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/svm.h>

md_ops_t		trans_md_ops;
#ifndef	lint
md_ops_t		*md_interface_ops = &trans_md_ops;
#endif	/* lint */

extern unit_t		md_nunits;
extern set_t		md_nsets;
extern md_set_t		md_set[];
extern int		md_status;
extern major_t		md_major;

extern int		md_trans_ioctl(dev_t, int, void *, int, IOLOCK *);
extern md_krwlock_t	md_unit_array_rw;

extern mdq_anchor_t	md_done_daemon;

extern	int		md_in_upgrade;

static kmem_cache_t	*trans_parent_cache = NULL;
kmem_cache_t		*trans_child_cache = NULL;

#ifdef	DEBUG
/*
 * ROUTINES FOR TESTING:
 */
static int
_init_debug()
{
	extern int	_init_ioctl();

	return (_init_ioctl());
}
static int
_fini_debug()
{
	extern int	_fini_ioctl();
	int	err = 0;

	err = _fini_ioctl();
	return (err);
}

#endif	/* DEBUG */

/*
 * BEGIN RELEASE DEBUG
 *	The following routines remain in the released product for testability
 */
int
trans_done_shadow(buf_t *bp)
{
	buf_t		*pb;
	md_tps_t	*ps = (md_tps_t *)bp->b_chain;
	int		rv = 0;

	pb = ps->ps_bp;
	mutex_enter(&ps->ps_mx);
	ps->ps_count--;
	if (ps->ps_count > 0) {
		if ((bp->b_flags & B_ERROR) != 0) {
			pb->b_flags |= B_ERROR;
			pb->b_error = bp->b_error;
		}
		mutex_exit(&ps->ps_mx);
		kmem_cache_free(trans_child_cache, bp);
	} else {
		mutex_exit(&ps->ps_mx);
		mutex_destroy(&ps->ps_mx);
		rv = trans_done(bp);
	}
	return (rv);
}

static void
shadow_debug(mt_unit_t	*un,		/* trans unit info */
		buf_t	*pb,		/* primary buffer */
		md_tps_t	*ps,		/* trans parent save */
		buf_t	*cb,		/* buffer for writing to master */
		int	flag,
		void	*private)
{
	buf_t		*sb;		/* Shadow buffer */

	mutex_init(&ps->ps_mx, NULL, MUTEX_DEFAULT, NULL);
	ps->ps_count = 2;		/* Write child buffer & shadow */
	cb->b_iodone = trans_done_shadow;
	sb = kmem_cache_alloc(trans_child_cache, MD_ALLOCFLAGS);
	trans_child_init(sb);
	sb = bioclone(pb, 0, pb->b_bcount, md_dev64_to_dev(un->un_s_dev),
	    pb->b_blkno, trans_done_shadow, sb, KM_NOSLEEP);

	sb->b_flags |= B_ASYNC;
	sb->b_chain = (void *)ps;
	md_call_strategy(sb, flag | MD_STR_MAPPED, private);
}
/*
 * END RELEASE DEBUG
 */

/*
 * COMMON MEMORY ALLOCATION ROUTINES (so that we can discover leaks)
 */
void *
md_trans_zalloc(size_t nb)
{
	TRANSSTATS(ts_trans_zalloc);
	TRANSSTATSADD(ts_trans_alloced, nb);
	return (kmem_zalloc(nb, KM_SLEEP));
}
void *
md_trans_alloc(size_t nb)
{
	TRANSSTATS(ts_trans_alloc);
	TRANSSTATSADD(ts_trans_alloced, nb);
	return (kmem_alloc(nb, KM_SLEEP));
}
void
md_trans_free(void *va, size_t nb)
{
	TRANSSTATS(ts_trans_free);
	TRANSSTATSADD(ts_trans_freed, nb);
	if (nb)
		kmem_free(va, nb);
}

static void
trans_parent_init(md_tps_t *ps)
{
	bzero(ps, sizeof (md_tps_t));
}

/*ARGSUSED1*/
int
trans_child_constructor(void *p, void *d1, int d2)
{
	bioinit(p);
	return (0);
}

void
trans_child_init(struct buf *bp)
{
	md_bioreset(bp);
}

/*ARGSUSED1*/
void
trans_child_destructor(void *p, void *d)
{
	biofini(p);
}

void
trans_commit(mt_unit_t *un, int domstr)
{
	mddb_recid_t	recids[4];
	md_unit_t	*su;
	int		ri = 0;

	if (md_get_setstatus(MD_UN2SET(un)) & MD_SET_STALE)
		return;

	recids[ri++] = un->c.un_record_id;

	if (domstr)
		if (md_getmajor(un->un_m_dev) == md_major) {
			su = MD_UNIT(md_getminor(un->un_m_dev));
			recids[ri++] = su->c.un_record_id;
		}

	if (ri == 0)
		return;
	recids[ri] = 0;

	uniqtime32(&un->un_timestamp);
	mddb_commitrecs_wrapper(recids);
}

void
trans_close_all_devs(mt_unit_t *un)
{
	if ((un->un_flags & TRANS_NEED_OPEN) == 0) {
		md_layered_close(un->un_m_dev, MD_OFLG_NULL);
		if (un->un_l_unit)
			ldl_close_dev(un->un_l_unit);
		un->un_flags |= TRANS_NEED_OPEN;
	}
}

int
trans_open_all_devs(mt_unit_t *un)
{
	int		err;
	minor_t		mnum = MD_SID(un);
	md_dev64_t	tmpdev = un->un_m_dev;
	set_t		setno = MD_MIN2SET(MD_SID(un));
	side_t		side = mddb_getsidenum(setno);

	/*
	 * Do the open by device id if it is regular device
	 */
	if ((md_getmajor(tmpdev) != md_major) &&
	    md_devid_found(setno, side, un->un_m_key) == 1) {
		tmpdev = md_resolve_bydevid(mnum, tmpdev, un->un_m_key);
	}
	err = md_layered_open(mnum, &tmpdev, MD_OFLG_NULL);
	un->un_m_dev = tmpdev;

	if (err)
		return (ENXIO);

	if (un->un_l_unit) {
		err = ldl_open_dev(un, un->un_l_unit);
		if (err) {
			md_layered_close(tmpdev, MD_OFLG_NULL);
			return (ENXIO);
		}
	}
	return (0);
}

uint_t	mt_debug	= 0;

int
trans_build_incore(void *p, int snarfing)
{
	mt_unit_t	*un = (mt_unit_t *)p;
	minor_t		mnum;
	set_t		setno;

	/*
	 * initialize debug mode and always start with no shadowing.
	 */
	if (!snarfing)
		un->un_debug = mt_debug;
	un->un_s_dev = NODEV64;

	mnum = MD_SID(un);

	if (MD_UNIT(mnum) != NULL)
		return (0);

	setno = MD_MIN2SET(mnum);

	/*
	 * If snarfing the metatrans device,
	 *	then remake the device number
	 */
	if (snarfing) {
		un->un_m_dev =  md_getdevnum(setno, mddb_getsidenum(setno),
		    un->un_m_key, MD_NOTRUST_DEVT);
	}

	/*
	 * db rec is partially deleted; finish the db delete later
	 */
	if (MD_STATUS(un) & MD_UN_BEING_RESET) {
		mddb_setrecprivate(un->c.un_record_id, MD_PRV_PENDCLEAN);
		return (1);
	}

	/*
	 * With the current device id implementation there is possibility
	 * that we may have NODEV if the underlying can't be resolved at
	 * snarf time.  If this is the case we want to be consistent with
	 * the normal behavior and continue to allow the snarf of unit
	 * and resolve the devt at the open time
	 */
	if ((md_getmajor(un->un_m_dev) == md_major) &&
	    (md_dev_exists(un->un_m_dev) == 0)) {
		return (1);
	}

	/*
	 * retain the detach status; reset open status
	 */
	un->un_flags &= (TRANS_DETACHING | TRANS_DETACHED);
	un->un_flags |= TRANS_NEED_OPEN;
	if ((un->un_flags & TRANS_DETACHED) == 0)
		un->un_flags |= TRANS_ATTACHING;

	/*
	 * log device not set up yet; try again later
	 */
	if ((un->un_flags & TRANS_DETACHED) == 0)
		if (ldl_findlog(un->un_l_recid) == NULL)
			return (1);

	/*
	 * initialize incore fields
	 */
	un->un_next = NULL;
	un->un_l_unit = NULL;
	un->un_deltamap = NULL;
	un->un_udmap = NULL;
	un->un_logmap = NULL;
	un->un_matamap = NULL;
	un->un_shadowmap = NULL;
	un->un_ut = NULL;
	un->un_logreset = 0;
	un->un_dev = md_makedevice(md_major, mnum);
	MD_STATUS(un) = 0;

	/* necessary because capability didn't exist pre-4.1 */
	MD_CAPAB(un) = (MD_CAN_META_CHILD & ~MD_CAN_PARENT);

	/*
	 * attach the log
	 */
	trans_attach(un, 0);

	/*
	 * check for master dev dynconcat
	 */
	if (md_getmajor(un->un_m_dev) == md_major) {
		struct mdc_unit	*c;

		c = MD_UNIT(md_getminor(un->un_m_dev));
		un->c.un_total_blocks = c->un_total_blocks;
	}

	/* place various information in the in-core data structures */
	md_nblocks_set(mnum, un->c.un_total_blocks);
	MD_UNIT(mnum) = un;

	return (0);
}

int
trans_detach(mt_unit_t *un, int force)
{
	mdi_unit_t	*ui = MDI_UNIT(MD_SID(un));
	int		error	= 0;

	/*
	 * The caller is responsible for single-threading this routine.
	 */

	if (ui == NULL)
		return (0);

	/*
	 * already detached or the log isn't attached yet; do nothing
	 */
	if (un->un_flags & (TRANS_DETACHED | TRANS_ATTACHING))
		return (0);

	/*
	 * set state to detaching
	 */
	if (force || !md_unit_isopen(ui)) {
		un->un_flags |= TRANS_DETACHING;
		if (!MD_UPGRADE) {
			trans_commit(un, 0);
		}
		SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_DETACHING, TAG_METADEVICE,
		    MD_UN2SET(un), MD_SID(un));
	}

	/*
	 * device is busy
	 */
	if (md_unit_isopen(ui))
		return (EBUSY);

	/*
	 * detach the log
	 *	if successful
	 *		flags committed to TRANS_DETACHED in database
	 *		un->un_l_unit set to NULL
	 *		no error returned
	 */
	error = ldl_reset(un, 1, force);
	if (error)
		return (error);

	/*
	 * commit to database
	 */
	if (!MD_UPGRADE) {
		trans_commit(un, 0);
	}
	SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_DETACH, TAG_METADEVICE, MD_UN2SET(un),
	    MD_SID(un));

	return (0);
}

void
trans_attach(mt_unit_t *un, int attaching)
{
	mdi_unit_t	*ui = MDI_UNIT(MD_SID(un));
	ml_unit_t	*ul;

	/*
	 * called from snarf, set, and attach.  Hence, the attaching param
	 * The caller is responsible for single-threading this routine.
	 */

	/*
	 * not attaching; do nothing
	 */
	if ((un->un_flags & TRANS_ATTACHING) == 0)
		return;

	/*
	 * find log unit struct
	 */
	ul = ldl_findlog(un->un_l_recid);
	if (ul == NULL)
		return;
	un->un_l_dev = ul->un_dev;

	/*
	 * device is busy; do nothing
	 */
	if (attaching && md_unit_isopen(ui))
		return;
	/*
	 * other functions use non-NULL un_l_unit as detach/attach flag
	 */
	un->un_l_unit = ul;

	/*
	 *   add metatrans device to the log's list of mt devices
	 */
	ldl_utadd(un);

	/*
	 * attached
	 */
	un->un_flags &= ~TRANS_ATTACHING;

}

int
trans_reset(mt_unit_t *un, minor_t mnum, int removing, int force)
{
	sv_dev_t	sv;
	mddb_recid_t	vtoc_id;
	int		error	= 0;

	/*
	 * reset log, maps, and ufs interface
	 */
	error = ldl_reset(un, removing, force);
	if (error)
		return (error);

	/*
	 * done with underyling devices
	 */
	trans_close_all_devs(un);

	md_destroy_unit_incore(mnum, &trans_md_ops);

	md_nblocks_set(mnum, -1ULL);
	MD_UNIT(mnum) = NULL;

	if (!removing)
		return (0);

	md_reset_parent(un->un_m_dev);
	MD_STATUS(un) |= MD_UN_BEING_RESET;
	trans_commit(un, 1);
	SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_DELETE, TAG_METADEVICE, MD_UN2SET(un),
	    MD_SID(un));

	/* Save the mstr key */
	sv.setno = MD_MIN2SET(mnum);
	sv.key = un->un_m_key;

	vtoc_id = un->c.un_vtoc_id;

	mddb_deleterec_wrapper(un->c.un_record_id);

	/* Remove the vtoc, if present */
	if (vtoc_id)
		mddb_deleterec_wrapper(vtoc_id);
	md_rem_names(&sv, 1);
	return (0);
}

static void
trans_wait_panic(struct buf *cb)
{
	while ((cb->b_flags & B_DONE) == 0) {
		md_daemon(1, &md_done_daemon);
		drv_usecwait(10);
	}
}

static void
trans_error(md_tps_t *ps)
{
	md_dev64_t	md_dev;
	md_dev64_t	m_dev;
	char		*str;
	struct buf	*pb;
	mdi_unit_t	*ui;

	pb = ps->ps_bp;
	ui = ps->ps_ui;

	/*
	 * gather up params for cmn_err
	 */
	if (pb->b_flags & B_READ)
		str = "read";
	else
		str = "write";
	md_dev = md_expldev(pb->b_edev);
	m_dev = ps->ps_un->un_m_dev;

	/*
	 * free up the resources for this request and done the errored buf
	 */
	md_kstat_done(ui, pb, 0);
	kmem_cache_free(trans_parent_cache, ps);
	md_unit_readerexit(ui);
	md_biodone(pb);

	/*
	 * print pretty error message
	 */
	cmn_err(CE_WARN, "md: %s: %s error on %s",
	    md_shortname(md_getminor(md_dev)), str,
	    md_devname(MD_DEV2SET(md_dev), m_dev, NULL, 0));
}

int
trans_done(struct buf *cb)
{
	struct buf	*pb;
	mdi_unit_t	*ui;
	md_tps_t	*ps;

	ps = (md_tps_t *)cb->b_chain;
	pb = ps->ps_bp;
	ui = ps->ps_ui;

	if (cb->b_flags & B_ERROR) {
		pb->b_flags |= B_ERROR;
		pb->b_error = cb->b_error;
		/*
		 * device not in hard error state; report error
		 */
		if (!ldl_isherror(ps->ps_un->un_l_unit)) {
			daemon_request(&md_done_daemon, trans_error,
			    (daemon_queue_t *)ps, REQ_OLD);

			if (cb->b_flags & B_REMAPPED)
				bp_mapout(cb);
			if (panicstr)
				cb->b_flags |= B_DONE;
			else
				kmem_cache_free(trans_child_cache, cb);

			return (1);
		}
	}

	if (cb->b_flags & B_REMAPPED)
		bp_mapout(cb);

	if (panicstr)
		cb->b_flags |= B_DONE;
	else
		kmem_cache_free(trans_child_cache, cb);
	kmem_cache_free(trans_parent_cache, ps);
	md_kstat_done(ui, pb, 0);
	md_unit_readerexit(ui);
	md_biodone(pb);

	return (0);
}

static void
md_trans_strategy(buf_t *pb, int flag, void *private)
{
	md_tps_t	*ps;
	buf_t		*cb;		/* child buf pointer */
	mt_unit_t	*un;
	mdi_unit_t	*ui;

	ui = MDI_UNIT(getminor(pb->b_edev));

	md_kstat_waitq_enter(ui);

	un = (mt_unit_t *)md_unit_readerlock(ui);

	if (md_inc_iocount(MD_MIN2SET(getminor(pb->b_edev))) != 0) {
		pb->b_flags |= B_ERROR;
		pb->b_error = ENXIO;
		pb->b_resid = pb->b_bcount;
		md_kstat_waitq_exit(ui);
		md_unit_readerexit(ui);
		biodone(pb);
		return;
	}

	ASSERT(!(flag & MD_STR_NOTTOP));

	/* check and map */
	if (md_checkbuf(ui, (md_unit_t *)un, pb) != 0) {
		md_kstat_waitq_exit(ui);
		return;
	}

	bp_mapin(pb);

	ps = kmem_cache_alloc(trans_parent_cache, MD_ALLOCFLAGS);
	trans_parent_init(ps);

	/*
	 * Save essential information from the original buffhdr
	 * in the md_save structure.
	 */
	ps->ps_un = un;
	ps->ps_ui = ui;
	ps->ps_bp = pb;

	cb = kmem_cache_alloc(trans_child_cache, MD_ALLOCFLAGS);
	trans_child_init(cb);

	cb = bioclone(pb, 0, pb->b_bcount, md_dev64_to_dev(un->un_m_dev),
	    pb->b_blkno, trans_done, cb, KM_NOSLEEP);

	cb->b_chain = (void *)ps;

	/*
	 * RELEASE DEBUG
	 * The following calls shadow debug for testing purposes if we are
	 * writing and if shadowing is turned on.
	 */
	if ((un->un_s_dev != NODEV64) &&
	    ((pb->b_flags & B_READ) == 0))
		shadow_debug(un, pb, ps, cb, flag, private);

	md_kstat_waitq_to_runq(ui);

	(void) md_call_strategy(cb, flag | MD_STR_MAPPED | MD_NOBLOCK, private);

	/*
	 * panic in progress; process daemon queues
	 */
	if (panicstr) {
		trans_wait_panic(cb);
		kmem_cache_free(trans_child_cache, cb);
	}
}

/* ARGSUSED */
static int
md_trans_read(dev_t dev, struct uio *uio, cred_t *credp)
{
	int			error;

	if ((error = md_chk_uio(uio)) != 0)
		return (error);

	return (physio(mdstrategy, NULL, dev, B_READ, minphys, uio));
}

/* ARGSUSED */
static int
md_trans_aread(dev_t dev, struct aio_req *aio, cred_t *credp)
{
	int			error;

	if ((error = md_chk_uio(aio->aio_uio)) != 0)
		return (error);

	return (aphysio(mdstrategy, anocancel, dev, B_READ, minphys, aio));
}

/* ARGSUSED */
static int
md_trans_write(dev_t dev, struct uio *uio, cred_t *credp)
{
	int	error;

	if ((error = md_chk_uio(uio)) != 0)
		return (error);

	return (physio(mdstrategy, NULL, dev, B_WRITE, minphys, uio));
}

/* ARGSUSED */
static int
md_trans_awrite(dev_t dev, struct aio_req *aio, cred_t *credp)
{
	int	error;

	if ((error = md_chk_uio(aio->aio_uio)) != 0)
		return (error);

	return (aphysio(mdstrategy, anocancel, dev, B_WRITE, minphys, aio));
}

static void
trans_cleanup(mt_unit_t *un)
{
	sv_dev_t	sv;

	MD_STATUS(un) |= MD_UN_LOG_DELETED;
	trans_commit(un, 0);

	/* Save the mstr key */
	sv.setno = MD_UN2SET(un);
	sv.key = un->un_m_key;

	mddb_deleterec_wrapper(un->c.un_record_id);

	md_rem_names(&sv, 1);
}

static int
trans_snarf(md_snarfcmd_t cmd, set_t setno)
{
	mt_unit_t	*un;
	ml_unit_t	*ul;
	mddb_recid_t	recid;
	int		gotsomething;
	mddb_type_t	typ1;
	int		all_trans_gotten;
	mddb_de_ic_t    *dep;
	mddb_rb32_t	*rbp;
	size_t		newreqsize;
	static int	trans_found = 0;



	if (cmd == MD_SNARF_CLEANUP) {

		if (md_get_setstatus(setno) & MD_SET_STALE)
			return (0);

		/*
		 * clean up partially cleared trans devices
		 */
		typ1 = (mddb_type_t)md_getshared_key(setno,
		    trans_md_ops.md_driver.md_drivername);
		recid = mddb_makerecid(setno, 0);
		while ((recid = mddb_getnextrec(recid, typ1, TRANS_REC)) > 0) {
			un = (mt_unit_t *)mddb_getrecaddr(recid);
			(void) trans_detach(un, 1);
			if (mddb_getrecprivate(recid) & MD_PRV_CLEANUP) {
				trans_cleanup(un);
				recid = mddb_makerecid(setno, 0);
			}
		}
		/*
		 * clean up partially cleared log devices
		 */
		recid = mddb_makerecid(setno, 0);
		while ((recid = mddb_getnextrec(recid, typ1, LOG_REC)) > 0) {
			if (mddb_getrecprivate(recid) & MD_PRV_CLEANUP) {
				ul = (ml_unit_t *)mddb_getrecaddr(recid);
				ldl_cleanup(ul);
				recid = mddb_makerecid(setno, 0);
			}
		}

		return (0);
	}

	/*
	 * must snarf up the log devices first
	 */
	gotsomething = 0;
	all_trans_gotten = 1;
	typ1 = (mddb_type_t)md_getshared_key(setno,
	    trans_md_ops.md_driver.md_drivername);
	recid = mddb_makerecid(setno, 0);
	while ((recid = mddb_getnextrec(recid, typ1, LOG_REC)) > 0) {
		ml_unit_t	*big_ul;
		ml_unit32_od_t	*small_ul;

		if (mddb_getrecprivate(recid) & MD_PRV_GOTIT)
			continue;

		small_ul = (ml_unit32_od_t *)mddb_getrecaddr(recid);
		dep = mddb_getrecdep(recid);
		dep->de_flags = MDDB_F_TRANS_LOG;
		rbp = dep->de_rb;
		/*
		 * As trans records are always old records,
		 * we have to check if this record already has been converted.
		 * We don't want to do that work twice.
		 */
		if ((rbp->rb_private & MD_PRV_CONVD) == 0) {
			newreqsize = sizeof (ml_unit_t);
			big_ul = (ml_unit_t *)kmem_zalloc(newreqsize, KM_SLEEP);
			trans_log_convert((caddr_t)small_ul, (caddr_t)big_ul,
			    SMALL_2_BIG);
			kmem_free(small_ul, dep->de_reqsize);
			/*
			 * Update userdata and incore userdata
			 * incores are at the end of ul
			 */
			dep->de_rb_userdata_ic = big_ul;
			dep->de_rb_userdata = big_ul;
			dep->de_icreqsize = newreqsize;
			rbp->rb_private |= MD_PRV_CONVD;
			ul = big_ul;
		} else {
			/* already converted, just set the pointer */
			ul = dep->de_rb_userdata;
		}
		all_trans_gotten = 0;
		if (ldl_build_incore(ul, 1) == 0) {
			mddb_setrecprivate(recid, MD_PRV_GOTIT);
			gotsomething = 1;
		}
	}

	/*
	 * now snarf up metatrans devices
	 */
	gotsomething = 0;
	recid = mddb_makerecid(setno, 0);
	while ((recid = mddb_getnextrec(recid, typ1, TRANS_REC)) > 0) {
		mt_unit_t	*big_un;
		mt_unit32_od_t	*small_un;

		if (mddb_getrecprivate(recid) & MD_PRV_GOTIT)
			continue;

		if ((trans_found == 0) && (!MD_UPGRADE)) {
			cmn_err(CE_WARN, MD_EOF_TRANS_MSG MD_EOF_TRANS_WARNING);
			trans_found = 1;
		}

		small_un = (mt_unit32_od_t *)mddb_getrecaddr(recid);

		dep = mddb_getrecdep(recid);
		dep->de_flags = MDDB_F_TRANS_MASTER;
		rbp = dep->de_rb;
		/*
		 * As trans records are always old records,
		 * we have to check if this record already has been converted.
		 * We don't want to do that work twice.
		 */
		if ((rbp->rb_private & MD_PRV_CONVD) == 0) {
			newreqsize = sizeof (mt_unit_t);
			big_un = (mt_unit_t *)kmem_zalloc(newreqsize, KM_SLEEP);
			trans_master_convert((caddr_t)small_un, (caddr_t)big_un,
			    SMALL_2_BIG);
			kmem_free(small_un, dep->de_reqsize);
			/*
			 * Update userdata and incore userdata
			 * incores are at the end of ul
			 */
			dep->de_rb_userdata_ic = big_un;
			dep->de_rb_userdata = big_un;
			dep->de_icreqsize = newreqsize;
			rbp->rb_private |= MD_PRV_CONVD;
			un = big_un;
			un->c.un_revision &= ~MD_64BIT_META_DEV;
		} else {
			/* already converted, just set the pointer */
			un = dep->de_rb_userdata;
		}

		/*
		 * Create minor node for snarfed entry.
		 */
		(void) md_create_minor_node(MD_MIN2SET(MD_SID(un)), MD_SID(un));

		if (MD_UNIT(MD_SID(un)) != NULL) {
			mddb_setrecprivate(recid, MD_PRV_PENDDEL);
			continue;
		}

		all_trans_gotten = 0;
		if (trans_build_incore(un, 1) == 0) {
			mddb_setrecprivate(recid, MD_PRV_GOTIT);
			md_create_unit_incore(MD_SID(un), &trans_md_ops, 0);
			gotsomething = 1;
		}
	}

	if (!all_trans_gotten)
		return (gotsomething);

	recid = mddb_makerecid(setno, 0);
	while ((recid = mddb_getnextrec(recid, typ1, 0)) > 0)
		if (!(mddb_getrecprivate(recid) & MD_PRV_GOTIT))
			mddb_setrecprivate(recid, MD_PRV_PENDDEL);
	return (0);
}

static int
trans_halt(md_haltcmd_t cmd, set_t setno)
{
	unit_t		i;
	mdi_unit_t	*ui;
	minor_t		mnum;
	mt_unit_t	*un;

	if (cmd == MD_HALT_CLOSE) {
		for (i = 0; i < md_nunits; i++) {
			mnum = MD_MKMIN(setno, i);
			if ((ui = MDI_UNIT(mnum)) == NULL)
				continue;
			if (ui->ui_opsindex != trans_md_ops.md_selfindex)
				continue;
			if (md_unit_isopen(ui)) {
				return (1);
			}
		}
		for (i = 0; i < md_nunits; i++) {
			mnum = MD_MKMIN(setno, i);
			if ((ui = MDI_UNIT(mnum)) == NULL)
				continue;
			if (ui->ui_opsindex != trans_md_ops.md_selfindex)
				continue;
			un = (mt_unit_t *)MD_UNIT(mnum);
			if ((un->un_flags & TRANS_NEED_OPEN) == 0) {
				trans_close_all_devs(un);
			}
		}
		return (0);
	}

	if (cmd == MD_HALT_OPEN) {
		for (i = 0; i < md_nunits; i++) {
			mnum = MD_MKMIN(setno, i);
			if ((ui = MDI_UNIT(mnum)) == NULL)
				continue;
			if (ui->ui_opsindex != trans_md_ops.md_selfindex)
				continue;
			ldl_open_underlying((mt_unit_t *)MD_UNIT(mnum));
		}
		return (0);
	}

	if (cmd == MD_HALT_CHECK) {
		for (i = 0; i < md_nunits; i++) {
			mnum = MD_MKMIN(setno, i);
			if ((ui = MDI_UNIT(mnum)) == NULL)
				continue;
			if (ui->ui_opsindex != trans_md_ops.md_selfindex)
				continue;
			if (md_unit_isopen(ui)) {
				return (1);
			}
		}
		return (0);
	}
	if (cmd == MD_HALT_DOIT) {
		for (i = 0; i < md_nunits; i++) {
			mnum = MD_MKMIN(setno, i);
			if ((ui = MDI_UNIT(mnum)) == NULL)
				continue;
			if (ui->ui_opsindex != trans_md_ops.md_selfindex)
				continue;
			(void) trans_reset((mt_unit_t *)MD_UNIT(mnum), mnum,
			    0, 1);
		}
		return (0);
	}
	if (cmd == MD_HALT_UNLOAD)
		return (0);

	return (1);
}

/*ARGSUSED3*/
static int
trans_open(
	dev_t		*dev,
	int		flag,
	int		otyp,
	cred_t		*cred_p,
	int		md_oflags
)
{
	minor_t		mnum = getminor(*dev);
	mdi_unit_t	*ui = MDI_UNIT(mnum);
	mt_unit_t	*un;
	int		err;

	/* disallow layered opens (e.g., PrestoServe) */
	if (otyp == OTYP_LYR)
		return (EINVAL);

	/* single thread */
	un = (mt_unit_t *)md_unit_openclose_enter(ui);

	/* if already open, count open, return success */
	if (md_unit_isopen(ui)) {
		err = md_unit_incopen(mnum, flag, otyp);
		md_unit_openclose_exit(ui);
		if (err != 0)
			return (err);
		return (0);
	}

	/*
	 * For some reason, not all of the metatrans devices attached to
	 * this log were openable at snarf;  try again now.  All of the
	 * underlying devices have to be openable for the roll thread to work.
	 */
	if (un->un_flags & TRANS_NEED_OPEN) {
		md_unit_openclose_exit(ui);
		ldl_open_underlying(un);
		if (un->un_flags & TRANS_NEED_OPEN)
			return (EINVAL);
		un = (mt_unit_t *)md_unit_openclose_enter(ui);
	}

	/* count open */
	err = md_unit_incopen(mnum, flag, otyp);
	md_unit_openclose_exit(ui);
	if (err != 0)
		return (err);

	/* return success */
	return (0);
}

/*ARGSUSED1*/
static int
trans_close(
	dev_t		dev,
	int		flag,
	int		otyp,
	cred_t		*cred_p,
	int		md_oflags
)
{
	minor_t		mnum = getminor(dev);
	mdi_unit_t	*ui = MDI_UNIT(mnum);
	mt_unit_t	*un;
	int		err = 0;

	/* single thread */
	un = (mt_unit_t *)md_unit_openclose_enter(ui);

	/* count closed */
	if ((err = md_unit_decopen(mnum, otyp)) != 0) {
		md_unit_openclose_exit(ui);
		return (err);
	}

	/* if still open */
	if (md_unit_isopen(ui)) {
		md_unit_openclose_exit(ui);
		return (0);
	}
	md_unit_openclose_exit(ui);

	if (un->un_flags & TRANS_DETACHING) {
		/*
		 * prevent new opens and try to detach the log
		 */
		rw_enter(&md_unit_array_rw.lock, RW_WRITER);
		(void) trans_detach(un, 0);
		rw_exit(&md_unit_array_rw.lock);
	}
	if (un->un_flags & TRANS_ATTACHING) {
		/*
		 * prevent new opens and try to attach the log
		 */
		rw_enter(&md_unit_array_rw.lock, RW_WRITER);
		trans_attach(un, 1);
		rw_exit(&md_unit_array_rw.lock);
	}

	return (0);
}

static int
trans_imp_set(
	set_t	setno
)
{
	mt_unit32_od_t	*un32;
	ml_unit32_od_t	*ul32;
	mddb_recid_t	recid;
	int		gotsomething = 0;
	mddb_type_t	typ1;
	minor_t		*self_id;	/* minor needs to be updated */
	mddb_recid_t	*record_id;	/* record id needs to be updated */

	/*
	 * Do log first if there is any
	 * Note that trans record is always 32 bit
	 */
	typ1 = (mddb_type_t)md_getshared_key(setno,
	    trans_md_ops.md_driver.md_drivername);
	recid = mddb_makerecid(setno, 0);

	while ((recid = mddb_getnextrec(recid, typ1, LOG_REC)) > 0) {
		if (mddb_getrecprivate(recid) & MD_PRV_GOTIT)
			continue;

		ul32 = (ml_unit32_od_t *)mddb_getrecaddr(recid);

		/*
		 * Trans log record always is old format
		 * Go ahead update the record with the new set info
		 */
		record_id = &(ul32->un_recid);

		/*
		 * Mark the record and update it
		 */
		*record_id = MAKERECID(setno, DBID(*record_id));
		if (!md_update_minor(setno, mddb_getsidenum
		    (setno), ul32->un_key))
			goto out;
		mddb_setrecprivate(recid, MD_PRV_GOTIT);
	}


	/*
	 * Now do the master
	 */
	recid = mddb_makerecid(setno, 0);
	while ((recid = mddb_getnextrec(recid, typ1, TRANS_REC)) > 0) {
		if (mddb_getrecprivate(recid) & MD_PRV_GOTIT)
			continue;

		un32 = (mt_unit32_od_t *)mddb_getrecaddr(recid);

		/*
		 * Trans master record always is old format
		 */
		self_id = &(un32->c.un_self_id);
		record_id = &(un32->c.un_record_id);

		/*
		 * Mark the record and update it
		 */
		*record_id = MAKERECID(setno, DBID(*record_id));
		*self_id = MD_MKMIN(setno, MD_MIN2UNIT(*self_id));
		if (!md_update_minor(setno, mddb_getsidenum
		    (setno), un32->un_m_key))
			goto out;
		mddb_setrecprivate(recid, MD_PRV_GOTIT);

		gotsomething = 1;
	}

out:
	return (gotsomething);
}

static md_named_services_t	trans_named_services[] = {
	{(intptr_t (*)()) trans_rename_listkids,	MDRNM_LIST_URKIDS   },
	{(intptr_t (*)()) trans_rename_check,		MDRNM_CHECK	    },
	{(intptr_t (*)()) trans_renexch_update_kids,	MDRNM_UPDATE_KIDS   },
	{(intptr_t (*)()) trans_rename_update_self,	MDRNM_UPDATE_SELF   },
	{(intptr_t (*)()) trans_exchange_self_update_from_down,
						MDRNM_SELF_UPDATE_FROM_DOWN },
	{(intptr_t (*)()) trans_exchange_parent_update_to,
						MDRNM_PARENT_UPDATE_TO	    },
	{NULL,						0		    }
};

md_ops_t trans_md_ops = {
	trans_open,		/* open */
	trans_close,		/* close */
	md_trans_strategy,	/* strategy */
	NULL,			/* print */
	NULL,			/* dump */
	md_trans_read,		/* read */
	md_trans_write,		/* write */
	md_trans_ioctl,		/* trans ioctl */
	trans_snarf,		/* trans_snarf */
	trans_halt,		/* halt */
	md_trans_aread,		/* aread */
	md_trans_awrite,	/* awrite */
	trans_imp_set,		/* import set */
	trans_named_services
};

static void
init_init(void)
{
	_init_ldl();
	ASSERT(_init_debug());
	trans_parent_cache = kmem_cache_create("md_trans_parent",
	    sizeof (md_tps_t), 0, NULL, NULL, NULL, NULL, NULL, 0);
	trans_child_cache = kmem_cache_create("md_trans_child", biosize(), 0,
	    trans_child_constructor, trans_child_destructor,
	    NULL, NULL, NULL, 0);
}

static void
fini_uninit(void)
{
	ASSERT(_fini_debug());
	_fini_ldl();
	kmem_cache_destroy(trans_parent_cache);
	kmem_cache_destroy(trans_child_cache);
	trans_parent_cache = trans_child_cache = NULL;
}

/* define the module linkage */
MD_PLUGIN_MISC_MODULE("trans module", init_init(), fini_uninit())
