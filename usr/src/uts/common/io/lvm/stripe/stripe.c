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
#include <sys/lvm/mdio.h>
#include <sys/lvm/mdvar.h>
#include <sys/lvm/md_stripe.h>
#include <sys/lvm/md_convert.h>
#include <sys/lvm/md_notify.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/debug.h>
#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/svm.h>

md_ops_t		stripe_md_ops;
#ifndef	lint
char			_depends_on[] = "drv/md";
md_ops_t		*md_interface_ops = &stripe_md_ops;
#endif

extern unit_t		md_nunits;
extern set_t		md_nsets;
extern md_set_t		md_set[];

extern kmutex_t		md_mx;
extern kcondvar_t	md_cv;

extern int		md_status;
extern major_t		md_major;
extern mdq_anchor_t	md_done_daemon;

static int		md_stripe_mcs_buf_off;
static kmem_cache_t	*stripe_parent_cache = NULL;
static kmem_cache_t	*stripe_child_cache = NULL;

/*ARGSUSED1*/
static int
stripe_parent_constructor(void *p, void *d1, int d2)
{
	mutex_init(&((md_sps_t *)p)->ps_mx,
	    NULL, MUTEX_DEFAULT, NULL);
	return (0);
}

static void
stripe_parent_init(void *ps)
{
	bzero(ps, offsetof(md_sps_t, ps_mx));
}

/*ARGSUSED1*/
static void
stripe_parent_destructor(void *p, void *d)
{
	mutex_destroy(&((md_sps_t *)p)->ps_mx);
}

/*ARGSUSED1*/
static int
stripe_child_constructor(void *p, void *d1, int d2)
{
	bioinit(&((md_scs_t *)p)->cs_buf);
	return (0);
}

static void
stripe_child_init(md_scs_t *cs)
{
	cs->cs_mdunit = 0;
	cs->cs_ps = NULL;
	cs->cs_comp = NULL;
	md_bioreset(&cs->cs_buf);
}

/*ARGSUSED1*/
static void
stripe_child_destructor(void *p, void *d)
{
	biofini(&((md_scs_t *)p)->cs_buf);
}

/*ARGSUSED*/
static void
stripe_run_queue(void *d)
{
	if (!(md_status & MD_GBL_DAEMONS_LIVE))
		md_daemon(1, &md_done_daemon);
}

static void
stripe_close_all_devs(ms_unit_t *un, int md_cflags)
{
	int		row;
	int		i;
	int		c;
	struct ms_comp	*mdcomp;

	mdcomp = (struct ms_comp *)((void *)&((char *)un)[un->un_ocomp]);
	for (row = 0; row < un->un_nrows; row++) {
		struct ms_row *mdr = &un->un_row[row];
		for (i = 0, c = mdr->un_icomp; i < mdr->un_ncomp; i++) {
			struct ms_comp	*mdc;
			mdc = &mdcomp[c++];
			if (md_cflags & MD_OFLG_PROBEDEV) {

			/*
			 * It is possible that the md_layered_open
			 * failed because the stripe unit structure
			 * contained a NODEV.  In such a case since
			 * there is nothing to open, there is nothing
			 * to close.
			 */
				if (mdc->un_dev == NODEV64)
					continue;
			}
			if ((md_cflags & MD_OFLG_PROBEDEV) &&
			    (mdc->un_mirror.ms_flags & MDM_S_PROBEOPEN)) {
				md_layered_close(mdc->un_dev,
				    md_cflags);
				mdc->un_mirror.ms_flags &= ~MDM_S_PROBEOPEN;
			} else if (mdc->un_mirror.ms_flags & MDM_S_ISOPEN) {
				md_layered_close(mdc->un_dev, md_cflags);
				mdc->un_mirror.ms_flags &= ~MDM_S_ISOPEN;
			}
		}
	}
}

static int
stripe_open_all_devs(ms_unit_t *un, int md_oflags)
{
	minor_t		mnum = MD_SID(un);
	int		row;
	int		i;
	int		c;
	struct ms_comp	*mdcomp;
	int		err;
	int		cont_on_errors = (md_oflags & MD_OFLG_CONT_ERRS);
	int		probe_err_cnt = 0;
	int		total_comp_cnt = 0;
	set_t		setno = MD_MIN2SET(MD_SID(un));
	side_t		side = mddb_getsidenum(setno);
	mdkey_t		key;

	mdcomp = (struct ms_comp *)((void *)&((char *)un)[un->un_ocomp]);

	/*
	 * For a probe call, if any component of a stripe or a concat
	 * can be opened, it is considered to be a success. The total number
	 * of components in a stripe are computed prior to starting a probe.
	 * This number is then compared against the number of components
	 * that could be be successfully opened. If none of the components
	 * in a stripe can be opened, only then an ENXIO is returned for a
	 * probe type open.
	 */

	for (row = 0; row < un->un_nrows; row++) {
		struct ms_row *mdr = &un->un_row[row];

		if (md_oflags & MD_OFLG_PROBEDEV)
			total_comp_cnt += mdr->un_ncomp;

		for (i = 0, c = mdr->un_icomp; i < mdr->un_ncomp; i++) {
			struct ms_comp	*mdc;
			md_dev64_t tmpdev;

			mdc = &mdcomp[c++];
			tmpdev = mdc->un_dev;
			/*
			 * Do the open by device id
			 * Check if this comp is hotspared and
			 * if it is then use the key for hotspare.
			 * MN disksets don't use devids, so we better don't use
			 * md_devid_found/md_resolve_bydevid there. Rather do,
			 * what's done in stripe_build_incore()
			 */
			if (MD_MNSET_SETNO(setno)) {
				if (mdc->un_mirror.ms_hs_id != 0) {
					(void) md_hot_spare_ifc(HS_MKDEV, 0, 0,
					    0, &mdc->un_mirror.ms_hs_id, NULL,
					    &tmpdev, NULL);
				}
			} else {
				key = mdc->un_mirror.ms_hs_id ?
				    mdc->un_mirror.ms_hs_key : mdc->un_key;
				if ((md_getmajor(tmpdev) != md_major) &&
				    md_devid_found(setno, side, key) == 1) {
					tmpdev = md_resolve_bydevid(mnum,
					    tmpdev, key);
				}
			}

			/*
			 * For a submirror, we only want to open those devices
			 * that are not errored. If the device is errored then
			 * then there is no reason to open it and leaving it
			 * closed allows the RCM/DR code to work so that the
			 * errored device can be replaced.
			 */
			if ((md_oflags & MD_OFLG_PROBEDEV) ||
			    ! (mdc->un_mirror.ms_state & CS_ERRED)) {

				err = md_layered_open(mnum, &tmpdev, md_oflags);
			} else {
				err = ENXIO;
			}

			/*
			 * Only set the un_dev if the tmpdev != NODEV64. If
			 * it is NODEV64 then the md_layered_open() will have
			 * failed in some manner.
			 */
			if (tmpdev != NODEV64)
				mdc->un_dev = tmpdev;

			if (err) {
				if (!cont_on_errors) {
					stripe_close_all_devs(un, md_oflags);
					return (ENXIO);
				}

				if (md_oflags & MD_OFLG_PROBEDEV)
					probe_err_cnt++;
			} else {
				if (md_oflags & MD_OFLG_PROBEDEV) {
					mdc->un_mirror.ms_flags |=
					    MDM_S_PROBEOPEN;
				} else
					mdc->un_mirror.ms_flags |= MDM_S_ISOPEN;
			}
		}
	}

	/* If every component in a stripe could not be opened fail */
	if ((md_oflags & MD_OFLG_PROBEDEV) &&
	    (probe_err_cnt == total_comp_cnt))
		return (ENXIO);
	else
		return (0);
}

int
stripe_build_incore(void *p, int snarfing)
{
	ms_unit_t *un = (ms_unit_t *)p;
	struct ms_comp	*mdcomp;
	minor_t		mnum;
	int		row;
	int		i;
	int		c;
	int		ncomps;

	mnum = MD_SID(un);

	if (MD_UNIT(mnum) != NULL)
		return (0);

	MD_STATUS(un) = 0;

	/*
	 * Reset all the is_open flags, these are probably set
	 * cause they just came out of the database.
	 */
	mdcomp = (struct ms_comp *)((void *)&((char *)un)[un->un_ocomp]);

	ncomps = 0;
	for (row = 0; row < un->un_nrows; row++) {
		struct ms_row *mdr = &un->un_row[row];
		ncomps += mdr->un_ncomp;
	}

	for (row = 0; row < un->un_nrows; row++) {
		struct ms_row *mdr = &un->un_row[row];
		for (i = 0, c = mdr->un_icomp; i < mdr->un_ncomp; i++) {
			struct ms_comp		*mdc;
			set_t			setno;
			md_dev64_t		tmpdev;

			mdc = &mdcomp[c++];
			mdc->un_mirror.ms_flags &=
			    ~(MDM_S_ISOPEN | MDM_S_IOERR | MDM_S_RS_TRIED);

			if (!snarfing)
				continue;

			setno = MD_MIN2SET(mnum);

			tmpdev = md_getdevnum(setno, mddb_getsidenum(setno),
			    mdc->un_key, MD_NOTRUST_DEVT);
			mdc->un_dev = tmpdev;
			/*
			 * Check for hotspares. If the hotspares haven't been
			 * snarfed yet, stripe_open_all_devs() will do the
			 * remapping of the dev's later.
			 */
			if (mdc->un_mirror.ms_hs_id != 0) {
				mdc->un_mirror.ms_orig_dev = mdc->un_dev;
				(void) md_hot_spare_ifc(HS_MKDEV, 0, 0,
				    0, &mdc->un_mirror.ms_hs_id, NULL,
				    &tmpdev, NULL);
				mdc->un_dev = tmpdev;
			}
		}
	}

	/* place various information in the in-core data structures */
	md_nblocks_set(mnum, un->c.un_total_blocks);
	MD_UNIT(mnum) = un;

	return (0);
}

void
reset_stripe(ms_unit_t *un, minor_t mnum, int removing)
{
	ms_comp_t	*mdcomp;
	struct ms_row	*mdr;
	int		i, c;
	int		row;
	int		nsv;
	int		isv;
	sv_dev_t	*sv;
	mddb_recid_t	*recids;
	mddb_recid_t	vtoc_id;
	int		rid = 0;

	md_destroy_unit_incore(mnum, &stripe_md_ops);

	md_nblocks_set(mnum, -1ULL);
	MD_UNIT(mnum) = NULL;

	/*
	 * Attempt release of its minor node
	 */
	md_remove_minor_node(mnum);

	if (!removing)
		return;

	nsv = 0;
	/* Count the number of devices */
	for (row = 0; row < un->un_nrows; row++) {
		mdr = &un->un_row[row];
		nsv += mdr->un_ncomp;
	}
	sv = (sv_dev_t *)kmem_alloc(sizeof (sv_dev_t) * nsv, KM_SLEEP);

	/*
	 * allocate recids array.  since we may have to commit
	 * underlying soft partition records, we need an array
	 * of size: total number of components in stripe + 3
	 * (one for the stripe itself, one for the hotspare, one
	 * for the end marker).
	 */
	recids = kmem_alloc(sizeof (mddb_recid_t) * (nsv + 3), KM_SLEEP);

	/*
	 * Save the md_dev64_t's and driver nm indexes.
	 * Because after the mddb_deleterec() we will
	 * not be able to access the unit structure.
	 *
	 * NOTE: Deleting the names before deleting the
	 *	 unit structure would cause problems if
	 *	 the machine crashed in between the two.
	 */
	isv = 0;
	mdcomp = (struct ms_comp *)((void *)&((char *)un)[un->un_ocomp]);

	for (row = 0; row < un->un_nrows; row++) {
		mdr = &un->un_row[row];
		for (i = 0, c = mdr->un_icomp; i < mdr->un_ncomp; i++) {
			struct ms_comp	*mdc;
			md_dev64_t	child_dev;
			md_unit_t	*child_un;

			mdc = &mdcomp[c++];
			if (mdc->un_mirror.ms_hs_id != 0) {
				mdkey_t		hs_key;

				hs_key = mdc->un_mirror.ms_hs_key;

				mdc->un_dev = mdc->un_mirror.ms_orig_dev;
				mdc->un_start_block =
				    mdc->un_mirror.ms_orig_blk;
				mdc->un_mirror.ms_hs_id = 0;
				mdc->un_mirror.ms_hs_key = 0;
				mdc->un_mirror.ms_orig_dev = 0;
				recids[0] = 0;
				recids[1] = 0;	/* recids[1] filled in below */
				recids[2] = 0;
				(void) md_hot_spare_ifc(HS_FREE, un->un_hsp_id,
				    0, 0, &recids[0], &hs_key, NULL, NULL);
				mddb_commitrecs_wrapper(recids);
			}

			/*
			 * check if we've got metadevice below us and
			 * deparent it if we do.
			 * NOTE: currently soft partitions are the
			 * the only metadevices stripes can be
			 * built on top of.
			 */
			child_dev = mdc->un_dev;
			if (md_getmajor(child_dev) == md_major) {
				child_un = MD_UNIT(md_getminor(child_dev));
				md_reset_parent(child_dev);
				recids[rid++] = MD_RECID(child_un);
			}

			sv[isv].setno = MD_MIN2SET(mnum);
			sv[isv++].key = mdc->un_key;
		}
	}

	recids[rid++] = un->c.un_record_id;
	recids[rid] = 0;	/* filled in below */

	/*
	 * Decrement the HSP reference count and
	 * remove the knowledge of the HSP from the unit struct.
	 * This is done atomically to remove a window.
	 */
	if (un->un_hsp_id != -1) {
		(void) md_hot_spare_ifc(HSP_DECREF, un->un_hsp_id, 0, 0,
		    &recids[rid++], NULL, NULL, NULL);
		un->un_hsp_id = -1;
	}

	/* set end marker and commit records */
	recids[rid] = 0;
	mddb_commitrecs_wrapper(recids);

	vtoc_id = un->c.un_vtoc_id;

	/*
	 * Remove self from the namespace
	 */
	if (un->c.un_revision & MD_FN_META_DEV) {
		(void) md_rem_selfname(un->c.un_self_id);
	}

	/* Remove the unit structure */
	mddb_deleterec_wrapper(un->c.un_record_id);

	/* Remove the vtoc, if present */
	if (vtoc_id)
		mddb_deleterec_wrapper(vtoc_id);

	SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_DELETE, SVM_TAG_METADEVICE,
	    MD_MIN2SET(mnum), MD_MIN2UNIT(mnum));
	md_rem_names(sv, nsv);
	kmem_free(sv, sizeof (sv_dev_t) * nsv);
	kmem_free(recids, sizeof (mddb_recid_t) * (nsv + 3));
}

static void
stripe_error(md_sps_t *ps)
{
	struct buf	*pb = ps->ps_bp;
	mdi_unit_t	*ui = ps->ps_ui;
	md_dev64_t	dev = ps->ps_errcomp->un_dev;
	md_dev64_t	md_dev = md_expldev(pb->b_edev);
	char		*str;

	if (pb->b_flags & B_READ) {
		ps->ps_errcomp->un_mirror.ms_flags |= MDM_S_READERR;
		str = "read";
	} else {
		ps->ps_errcomp->un_mirror.ms_flags |= MDM_S_WRTERR;
		str = "write";
	}
	if (!(ps->ps_flags & MD_SPS_DONTFREE)) {
		if (MUTEX_HELD(&ps->ps_mx)) {
			mutex_exit(&ps->ps_mx);
		}
	} else {
		ASSERT(panicstr);
	}
	SPS_FREE(stripe_parent_cache, ps);
	pb->b_flags |= B_ERROR;

	md_kstat_done(ui, pb, 0);
	md_unit_readerexit(ui);
	md_biodone(pb);

	cmn_err(CE_WARN, "md: %s: %s error on %s",
	    md_shortname(md_getminor(md_dev)), str,
	    md_devname(MD_DEV2SET(md_dev), dev, NULL, 0));
}

static int
stripe_done(struct buf *cb)
{
	struct buf	*pb;
	mdi_unit_t	*ui;
	md_sps_t	*ps;
	md_scs_t	*cs;

	/*LINTED*/
	cs = (md_scs_t *)((caddr_t)cb - md_stripe_mcs_buf_off);
	ps = cs->cs_ps;
	pb = ps->ps_bp;

	mutex_enter(&ps->ps_mx);
	if (cb->b_flags & B_ERROR) {
		ps->ps_flags |= MD_SPS_ERROR;
		pb->b_error = cb->b_error;
		ps->ps_errcomp = cs->cs_comp;
	}

	if (cb->b_flags & B_REMAPPED)
		bp_mapout(cb);

	ps->ps_frags--;
	if (ps->ps_frags != 0) {
		mutex_exit(&ps->ps_mx);
		kmem_cache_free(stripe_child_cache, cs);
		return (1);
	}
	kmem_cache_free(stripe_child_cache, cs);
	if (ps->ps_flags & MD_SPS_ERROR) {
		stripe_error(ps);
		return (1);
	}
	ui = ps->ps_ui;
	if (!(ps->ps_flags & MD_SPS_DONTFREE)) {
		mutex_exit(&ps->ps_mx);
	} else {
		ASSERT(panicstr);
	}
	SPS_FREE(stripe_parent_cache, ps);
	md_kstat_done(ui, pb, 0);
	md_unit_readerexit(ui);
	md_biodone(pb);
	return (0);
}


/*
 * This routine does the mapping from virtual (dev, blkno) of a metapartition
 * to the real (dev, blkno) of a real disk partition.
 * It goes to the md_conf[] table to find out the correct real partition
 * dev and block number for this buffer.
 *
 * A single buf request can not go across real disk partition boundary.
 * When the virtual request specified by (dev, blkno) spans more than one
 * real partition, md_mapbuf will return 1. Then the caller should prepare
 * another real buf and continue calling md_mapbuf to do the mapping until
 * it returns 0.
 *
 */

static int
md_mapbuf(
	ms_unit_t	*un,
	diskaddr_t	blkno,
	u_longlong_t	bcount,
	buf_t		*bp,	/* if bp==NULL, skip bp updates */
	ms_comp_t	**mdc)	/* if bp==NULL, skip mdc update */
{
	struct ms_row	*mdr;
	struct ms_comp	*mdcomp;
	diskaddr_t	stripe_blk;
	diskaddr_t	fragment, blk_in_row, endblk;
	offset_t	interlace;
	size_t		dev_index;
	int		row_index, more;
	extern unsigned md_maxphys;
	/* Work var's when bp==NULL */
	u_longlong_t	wb_bcount;
	diskaddr_t	wb_blkno;
	md_dev64_t	wb_edev;
	ms_comp_t	*wmdc;

	/*
	 * Do a real calculation to derive the minor device of the
	 * Virtual Disk, which in turn will let us derive the
	 * device/minor of the underlying real device.
	 */


	for (row_index = 0; row_index < un->un_nrows; row_index++) {
		mdr = &un->un_row[row_index];
		if (blkno < mdr->un_cum_blocks)
			break;
	}
	ASSERT(row_index != un->un_nrows);

	mdcomp = (struct ms_comp *)((void *)&((char *)un)[un->un_ocomp]);

	blk_in_row = blkno - mdr->un_cum_blocks + mdr->un_blocks;
	endblk = (diskaddr_t)(blkno + howmany(bcount, DEV_BSIZE));
	if (mdr->un_ncomp == 1) { /* No striping */
		if (endblk > mdr->un_cum_blocks) {
			wb_bcount = ldbtob(mdr->un_cum_blocks - blkno);
			if ((row_index + 1) == un->un_nrows)
				more = 0;
			else
				more = 1;
		} else {
			wb_bcount = bcount;
			more = 0;
		}
		wmdc = &mdcomp[mdr->un_icomp];
		wb_blkno = blk_in_row;
	} else { /* Have striping */
		interlace = mdr->un_interlace;
		fragment = blk_in_row % interlace;
		if (bcount > ldbtob(interlace - fragment)) {
			more = 1;
			wb_bcount = ldbtob(interlace - fragment);
		} else {
			more = 0;
			wb_bcount = bcount;
		}

		stripe_blk = blk_in_row / interlace;
		dev_index = (size_t)(stripe_blk % mdr->un_ncomp);
		wmdc = &mdcomp[mdr->un_icomp + dev_index];
		wb_blkno = (diskaddr_t)(((stripe_blk / mdr->un_ncomp) *
		    interlace) + fragment);
	}

	wb_blkno += wmdc->un_start_block;
	wb_edev = wmdc->un_dev;

	/* only break up the I/O if we're not built on another metadevice */
	if ((md_getmajor(wb_edev) != md_major) && (wb_bcount > md_maxphys)) {
		wb_bcount = md_maxphys;
		more = 1;
	}
	if (bp != (buf_t *)NULL) {
		/*
		 * wb_bcount is limited by md_maxphys which is 'int'
		 */
		bp->b_bcount = (size_t)wb_bcount;
		bp->b_lblkno = wb_blkno;
		bp->b_edev = md_dev64_to_dev(wb_edev);
		*mdc = wmdc;
	}
	return (more);
}

static void
md_stripe_strategy(buf_t *pb, int flag, void *private)
{
	md_sps_t	*ps;
	md_scs_t	*cs;
	int		doing_writes;
	int		more;
	ms_unit_t	*un;
	mdi_unit_t	*ui;
	size_t		current_count;
	diskaddr_t	current_blkno;
	off_t		current_offset;
	buf_t		*cb;		/* child buf pointer */
	set_t		setno;

	setno = MD_MIN2SET(getminor(pb->b_edev));

	/*
	 * When doing IO to a multi owner meta device, check if set is halted.
	 * We do this check without the needed lock held, for performance
	 * reasons.
	 * If an IO just slips through while the set is locked via an
	 * MD_MN_SUSPEND_SET, we don't care about it.
	 * Only check for a suspended set if we are a top-level i/o request
	 * (MD_STR_NOTTOP is cleared in 'flag').
	 */
	if ((md_set[setno].s_status & (MD_SET_HALTED | MD_SET_MNSET)) ==
	    (MD_SET_HALTED | MD_SET_MNSET)) {
		if ((flag & MD_STR_NOTTOP) == 0) {
			mutex_enter(&md_mx);
			/* Here we loop until the set is no longer halted */
			while (md_set[setno].s_status & MD_SET_HALTED) {
				cv_wait(&md_cv, &md_mx);
			}
			mutex_exit(&md_mx);
		}
	}

	ui = MDI_UNIT(getminor(pb->b_edev));

	md_kstat_waitq_enter(ui);

	un = (ms_unit_t *)md_unit_readerlock(ui);

	if ((flag & MD_NOBLOCK) == 0) {
		if (md_inc_iocount(setno) != 0) {
			pb->b_flags |= B_ERROR;
			pb->b_error = ENXIO;
			pb->b_resid = pb->b_bcount;
			md_kstat_waitq_exit(ui);
			md_unit_readerexit(ui);
			biodone(pb);
			return;
		}
	} else {
		md_inc_iocount_noblock(setno);
	}

	if (!(flag & MD_STR_NOTTOP)) {
		if (md_checkbuf(ui, (md_unit_t *)un, pb) != 0) {
			md_kstat_waitq_exit(ui);
			return;
		}
	}

	ps = kmem_cache_alloc(stripe_parent_cache, MD_ALLOCFLAGS);
	stripe_parent_init(ps);

	/*
	 * Save essential information from the original buffhdr
	 * in the md_save structure.
	 */
	ps->ps_un = un;
	ps->ps_ui = ui;
	ps->ps_bp = pb;
	ps->ps_addr = pb->b_un.b_addr;

	if ((pb->b_flags & B_READ) == 0)
		doing_writes = 1;
	else
		doing_writes = 0;


	current_count = pb->b_bcount;
	current_blkno = pb->b_lblkno;
	current_offset  = 0;

	if (!(flag & MD_STR_NOTTOP) && panicstr)
		ps->ps_flags |= MD_SPS_DONTFREE;

	md_kstat_waitq_to_runq(ui);

	ps->ps_frags++;
	do {
		cs = kmem_cache_alloc(stripe_child_cache, MD_ALLOCFLAGS);
		stripe_child_init(cs);
		cb = &cs->cs_buf;
		cs->cs_ps = ps;
		more = md_mapbuf(un, current_blkno, current_count, cb,
		    &cs->cs_comp);

		cb = md_bioclone(pb, current_offset, cb->b_bcount, cb->b_edev,
		    cb->b_lblkno, stripe_done, cb, KM_NOSLEEP);
		/*
		 * Do these calculations now,
		 *  so that we pickup a valid b_bcount from the chld_bp.
		 */
		current_offset += cb->b_bcount;
		current_count -=  cb->b_bcount;
		current_blkno +=  (diskaddr_t)(lbtodb(cb->b_bcount));

		if (more) {
			mutex_enter(&ps->ps_mx);
			ps->ps_frags++;
			mutex_exit(&ps->ps_mx);
		}

		if (doing_writes &&
		    cs->cs_comp->un_mirror.ms_flags & MDM_S_NOWRITE) {
			(void) stripe_done(cb);
			continue;
		}
		md_call_strategy(cb, flag, private);
	} while (more);

	if (!(flag & MD_STR_NOTTOP) && panicstr) {
		while (!(ps->ps_flags & MD_SPS_DONE)) {
			md_daemon(1, &md_done_daemon);
			drv_usecwait(10);
		}
		kmem_cache_free(stripe_parent_cache, ps);
	}
}

static int
stripe_snarf(md_snarfcmd_t cmd, set_t setno)
{
	ms_unit_t	*un;
	mddb_recid_t	recid;
	int		gotsomething;
	int		all_stripes_gotten;
	mddb_type_t	typ1;
	mddb_de_ic_t	*dep;
	mddb_rb32_t	*rbp;
	size_t		newreqsize;
	ms_unit_t	*big_un;
	ms_unit32_od_t	*small_un;


	if (cmd == MD_SNARF_CLEANUP)
		return (0);

	all_stripes_gotten = 1;
	gotsomething = 0;

	typ1 = (mddb_type_t)md_getshared_key(setno,
	    stripe_md_ops.md_driver.md_drivername);
	recid = mddb_makerecid(setno, 0);

	while ((recid = mddb_getnextrec(recid, typ1, 0)) > 0) {
		if (mddb_getrecprivate(recid) & MD_PRV_GOTIT)
			continue;

		dep = mddb_getrecdep(recid);
		dep->de_flags = MDDB_F_STRIPE;
		rbp = dep->de_rb;

		switch (rbp->rb_revision) {
		case MDDB_REV_RB:
		case MDDB_REV_RBFN:
			if ((rbp->rb_private & MD_PRV_CONVD) == 0) {
				/*
				 * This means, we have an old and small record
				 * and this record hasn't already been
				 * converted.  Before we create an incore
				 * metadevice from this we have to convert it to
				 * a big record.
				 */
				small_un =
				    (ms_unit32_od_t *)mddb_getrecaddr(recid);
				newreqsize = get_big_stripe_req_size(small_un,
				    COMPLETE_STRUCTURE);
				big_un = (ms_unit_t *)kmem_zalloc(newreqsize,
				    KM_SLEEP);
				stripe_convert((caddr_t)small_un,
				    (caddr_t)big_un, SMALL_2_BIG);
				kmem_free(small_un, dep->de_reqsize);
				dep->de_rb_userdata = big_un;
				dep->de_reqsize = newreqsize;
				un = big_un;
				rbp->rb_private |= MD_PRV_CONVD;
			} else {
				/* Small device had already been converted */
				un = (ms_unit_t *)mddb_getrecaddr(recid);
			}
			un->c.un_revision &= ~MD_64BIT_META_DEV;
			break;
		case MDDB_REV_RB64:
		case MDDB_REV_RB64FN:
			/* Big device */
			un = (ms_unit_t *)mddb_getrecaddr(recid);
			un->c.un_revision |= MD_64BIT_META_DEV;
			un->c.un_flag |= MD_EFILABEL;
			break;
		}
		MDDB_NOTE_FN(rbp->rb_revision, un->c.un_revision);

		/* Create minor node for snarfed unit. */
		(void) md_create_minor_node(MD_MIN2SET(MD_SID(un)), MD_SID(un));

		if (MD_UNIT(MD_SID(un)) != NULL) {
			mddb_setrecprivate(recid, MD_PRV_PENDDEL);
			continue;
		}
		all_stripes_gotten = 0;
		if (stripe_build_incore((void *)un, 1) == 0) {
			mddb_setrecprivate(recid, MD_PRV_GOTIT);
			md_create_unit_incore(MD_SID(un), &stripe_md_ops, 0);
			gotsomething = 1;
		}
	}

	if (!all_stripes_gotten)
		return (gotsomething);

	recid = mddb_makerecid(setno, 0);
	while ((recid = mddb_getnextrec(recid, typ1, 0)) > 0)
		if (!(mddb_getrecprivate(recid) & MD_PRV_GOTIT))
			mddb_setrecprivate(recid, MD_PRV_PENDDEL);

	return (0);
}

static int
stripe_halt(md_haltcmd_t cmd, set_t setno)
{
	int		i;
	mdi_unit_t	*ui;
	minor_t		mnum;

	if (cmd == MD_HALT_CLOSE)
		return (0);

	if (cmd == MD_HALT_OPEN)
		return (0);

	if (cmd == MD_HALT_UNLOAD)
		return (0);

	if (cmd == MD_HALT_CHECK) {
		for (i = 0; i < md_nunits; i++) {
			mnum = MD_MKMIN(setno, i);
			if ((ui = MDI_UNIT(mnum)) == NULL)
				continue;
			if (ui->ui_opsindex != stripe_md_ops.md_selfindex)
				continue;
			if (md_unit_isopen(ui))
				return (1);
		}
		return (0);
	}

	if (cmd != MD_HALT_DOIT)
		return (1);

	for (i = 0; i < md_nunits; i++) {
		mnum = MD_MKMIN(setno, i);
		if ((ui = MDI_UNIT(mnum)) == NULL)
			continue;
		if (ui->ui_opsindex != stripe_md_ops.md_selfindex)
			continue;
		reset_stripe((ms_unit_t *)MD_UNIT(mnum), mnum, 0);
	}

	return (0);
}

/*ARGSUSED3*/
static int
stripe_open(dev_t *dev, int flag, int otyp, cred_t *cred_p, int md_oflags)
{
	minor_t		mnum = getminor(*dev);
	mdi_unit_t	*ui = MDI_UNIT(mnum);
	ms_unit_t	*un;
	int		err = 0;
	set_t		setno;

	/*
	 * When doing an open of a multi owner metadevice, check to see if this
	 * node is a starting node and if a reconfig cycle is underway.
	 * If so, the system isn't sufficiently set up enough to handle the
	 * open (which involves I/O during sp_validate), so fail with ENXIO.
	 */
	setno = MD_MIN2SET(mnum);
	if ((md_set[setno].s_status & (MD_SET_MNSET | MD_SET_MN_START_RC)) ==
	    (MD_SET_MNSET | MD_SET_MN_START_RC)) {
			return (ENXIO);
	}

	/* single thread */
	un = (ms_unit_t *)md_unit_openclose_enter(ui);

	/* open devices, if necessary */
	if (! md_unit_isopen(ui) || (md_oflags & MD_OFLG_PROBEDEV)) {
		if ((err = stripe_open_all_devs(un, md_oflags)) != 0) {
			goto out;
		}
	}

	/* count open */
	if ((err = md_unit_incopen(mnum, flag, otyp)) != 0)
		goto out;

	/* unlock, return success */
out:
	md_unit_openclose_exit(ui);
	return (err);
}

/*ARGSUSED1*/
static int
stripe_close(
	dev_t		dev,
	int		flag,
	int		otyp,
	cred_t		*cred_p,
	int		md_cflags
)
{
	minor_t		mnum = getminor(dev);
	mdi_unit_t	*ui = MDI_UNIT(mnum);
	ms_unit_t	*un;
	int		err = 0;

	/* single thread */
	un = (ms_unit_t *)md_unit_openclose_enter(ui);

	/* count closed */
	if ((err = md_unit_decopen(mnum, otyp)) != 0)
		goto out;

	/* close devices, if necessary */
	if (! md_unit_isopen(ui) || (md_cflags & MD_OFLG_PROBEDEV)) {
		stripe_close_all_devs(un, md_cflags);
	}

	/* unlock, return success */
out:
	md_unit_openclose_exit(ui);
	return (err);
}


static struct buf dumpbuf;

/*
 * This routine dumps memory to the disk.  It assumes that the memory has
 * already been mapped into mainbus space.  It is called at disk interrupt
 * priority when the system is in trouble.
 *
 */
static int
stripe_dump(dev_t dev, caddr_t addr, daddr_t blkno, int nblk)
{
	ms_unit_t	*un;
	buf_t		*bp;
	ms_comp_t	*mdc;
	u_longlong_t	nb;
	diskaddr_t	mapblk;
	int		result;
	int		more;
	int		saveresult = 0;

	/*
	 * Don't need to grab the unit lock.
	 * Cause nothing else is suppose to be happenning.
	 * Also dump is not suppose to sleep.
	 */
	un = (ms_unit_t *)MD_UNIT(getminor(dev));

	if ((diskaddr_t)blkno >= un->c.un_total_blocks)
		return (EINVAL);

	if ((diskaddr_t)blkno + nblk > un->c.un_total_blocks)
		return (EINVAL);

	bp = &dumpbuf;
	nb = ldbtob(nblk);
	do {
		bzero((caddr_t)bp, sizeof (*bp));
		more = md_mapbuf(un, (diskaddr_t)blkno, nb, bp, &mdc);
		nblk = btodb(bp->b_bcount);
		mapblk = bp->b_lblkno;
		if (!(mdc->un_mirror.ms_flags & MDM_S_NOWRITE)) {
			/*
			 * bdev_dump() is currently only able to take
			 * 32 bit wide blkno's.
			 */
			result = bdev_dump(bp->b_edev, addr, (daddr_t)mapblk,
			    nblk);
			if (result)
				saveresult = result;
		}

		nb -= bp->b_bcount;
		addr += bp->b_bcount;
		blkno += nblk;
	} while (more);

	return (saveresult);
}

/*ARGSUSED*/
static intptr_t
stripe_shared_by_blk(
	md_dev64_t dev,
	void *junk,
	diskaddr_t blkno,
	u_longlong_t *cnt)
{
	ms_unit_t	*un;
	buf_t		bp;
	ms_comp_t	*comp;

	un = MD_UNIT(md_getminor(dev));
	(void) md_mapbuf(un, blkno, ldbtob(*cnt), &bp, &comp);
	*cnt = (u_longlong_t)lbtodb(bp.b_bcount);
	return ((intptr_t)&comp->un_mirror);
}

/*
 * stripe_block_count_skip_size() returns the following values
 *	so that the logical to physical block mappings can
 *	be calculated without intimate knowledge of the underpinnings.
 *
 *	block - first logical block number of the device.
 *		block = [ # of blocks before THE row ] +
 *			[ # of blocks in THE row before the component ]
 *	count - # of segments (interlaced size).
 *	skip  - # of logical blocks between segments, or delta to
 *		  get to next segment
 *	size  - interlace size used for the block, count, skip.
 */
/*ARGSUSED*/
static intptr_t
stripe_block_count_skip_size(
	md_dev64_t	 dev,
	void		*junk,
	int		ci,
	diskaddr_t	*block,
	size_t		*count,
	u_longlong_t	*skip,
	u_longlong_t	*size)
{
	ms_unit_t	*un;
	int		row;
	struct ms_row	*mdr;
	int		cmpcount = 0;

	un = MD_UNIT(md_getminor(dev));

	for (row = 0; row < un->un_nrows; row++) {
		mdr = &un->un_row[row];
		if ((mdr->un_ncomp + cmpcount) > ci)
			break;
		cmpcount += mdr->un_ncomp;
	}
	ASSERT(row != un->un_nrows);

	/*
	 * Concatenations are always contiguous blocks,
	 * you cannot depend on the interlace being a usable
	 * value (except for stripes).
	 */
	if (mdr->un_ncomp == 1) {	/* Concats */
		*block = mdr->un_cum_blocks - mdr->un_blocks;
		*count = 1;
		*skip = 0;
		*size = mdr->un_blocks;
	} else {			/* Stripes */
		*block = (mdr->un_cum_blocks - mdr->un_blocks) +
		    ((ci - cmpcount) * mdr->un_interlace);
		*count	= (size_t)(mdr->un_blocks / (mdr->un_interlace *
		    mdr->un_ncomp));
		*skip = (mdr->un_interlace * mdr->un_ncomp) - mdr->un_interlace;
		*size = mdr->un_interlace;
	}

	return (0);
}

/*ARGSUSED*/
static intptr_t
stripe_shared_by_indx(md_dev64_t dev, void *junk, int indx)
{
	ms_unit_t	*un;
	ms_comp_t	*comp;

	un = MD_UNIT(md_getminor(dev));
	comp = (struct ms_comp *)((void *)&((char *)un)[un->un_ocomp]);
	comp += indx;
	return ((intptr_t)&comp->un_mirror);
}

/*ARGSUSED*/
intptr_t
stripe_component_count(md_dev64_t dev, void *junk)
{
	/*
	 * See comments for stripe_get_dev
	 */

	ms_unit_t	*un;
	int		count = 0;
	int		row;

	un = MD_UNIT(md_getminor(dev));
	for (row = 0; row < un->un_nrows; row++)
		count += un->un_row[row].un_ncomp;
	return (count);
}

/*ARGSUSED*/
intptr_t
stripe_get_dev(md_dev64_t dev, void *junk, int indx, ms_cd_info_t *cd)
{
	/*
	 * It should be noted that stripe_replace in stripe_ioctl.c calls this
	 * routine using makedevice(0, minor) for the first argument.
	 *
	 * If this routine at some point in the future needs to use the major
	 * number stripe_replace must be changed.
	 */

	ms_unit_t	*un;
	ms_comp_t	*comp;
	md_dev64_t	tmpdev;

	un = MD_UNIT(md_getminor(dev));
	comp = (struct ms_comp *)((void *)&((char *)un)[un->un_ocomp]);
	comp += indx;
	tmpdev = comp->un_dev;
	/*
	 * Try to resolve devt again if NODEV64
	 * Check if this comp is hotspared and if it is
	 * then use key for hotspare
	 */
	if (tmpdev == NODEV64) {
		tmpdev = md_resolve_bydevid(md_getminor(dev), tmpdev,
		    comp->un_mirror.ms_hs_id ?
		    comp->un_mirror.ms_hs_key :
		    comp->un_key);
		comp->un_dev = tmpdev;
	}

	cd->cd_dev = comp->un_dev;
	cd->cd_orig_dev = comp->un_mirror.ms_orig_dev;
	return (0);
}

/*ARGSUSED*/
void
stripe_replace_done(md_dev64_t dev, sv_dev_t *sv)
{
	/*
	 * See comments for stripe_get_dev
	 */

	minor_t		mnum = md_getminor(dev);

	if (sv != NULL) {
		md_rem_names(sv, 1);
		kmem_free(sv, sizeof (sv_dev_t));
	}

	md_unit_writerexit(MDI_UNIT(mnum));
}

/*ARGSUSED*/
intptr_t
stripe_replace_dev(md_dev64_t dev, void *junk, int ci, ms_new_dev_t *nd,
    mddb_recid_t *recids, int nrecids, void (**replace_done)(),
    void **replace_data)
{
	minor_t		mnum;
	ms_unit_t	*un;
	mdi_unit_t	*ui;
	ms_comp_t	*comp;
	diskaddr_t	dev_size;
	int		row;
	int		ncomps = 0;
	int		cmpcount = 0;
	int		rid = 0;
	struct ms_row	*mdr;
	sv_dev_t	*sv = NULL;
	mddb_recid_t	hs_id = 0;
	set_t		setno;
	side_t		side;
	md_dev64_t	this_dev;

	mnum = md_getminor(dev);
	ui = MDI_UNIT(mnum);
	setno = MD_MIN2SET(mnum);
	side = mddb_getsidenum(setno);

	un = md_unit_writerlock(ui);

	*replace_data = NULL;
	comp = (struct ms_comp *)((void *)&((char *)un)[un->un_ocomp]);

	comp += ci;

	/*
	 * Count the number of components
	 */
	for (row = 0; row < un->un_nrows; row++) {
		struct ms_row *mdr = &un->un_row[row];
		ncomps += mdr->un_ncomp;
	}

	recids[0] = 0;
	/*
	 * No need of checking size of new device,
	 * when hotsparing (it has already been done), or
	 * when enabling the device.
	 */
	if ((nd != NULL) && (nd->nd_hs_id == 0)) {
		for (row = 0; row < un->un_nrows; row++) {
			mdr = &un->un_row[row];
			if ((mdr->un_ncomp + cmpcount) > ci)
				break;
			cmpcount += mdr->un_ncomp;
		}
		ASSERT(row != un->un_nrows);

		/* Concatenations have a ncomp = 1 */
		dev_size = mdr->un_blocks / mdr->un_ncomp;

		/*
		 * now check to see if new comp can be used in
		 * place of old comp
		 */
		if ((un->c.un_flag & MD_LABELED) && (ci == 0) &&
		    nd->nd_labeled)
			nd->nd_start_blk = 0;
		else
			nd->nd_nblks -= nd->nd_start_blk;

		if (dev_size > nd->nd_nblks) {
			md_unit_writerexit(ui);
			return (MDE_COMP_TOO_SMALL);
		}

		sv = (sv_dev_t *)kmem_alloc(sizeof (sv_dev_t), KM_SLEEP);
		sv->setno = MD_MIN2SET(mnum);
		sv->key = comp->un_key;
	}

	/*
	 * Close this component.
	 */
	if (comp->un_mirror.ms_flags & MDM_S_ISOPEN) {
		md_layered_close(comp->un_dev, MD_OFLG_NULL);
		comp->un_mirror.ms_flags &= ~MDM_S_ISOPEN;
	}

	/*
	 * If the component is hotspared, return to the pool.
	 */
	if (comp->un_mirror.ms_hs_id != 0) {
		hs_cmds_t	cmd;
		mdkey_t		hs_key;

		hs_key = comp->un_mirror.ms_hs_key;
		comp->un_dev = comp->un_mirror.ms_orig_dev;
		comp->un_start_block = comp->un_mirror.ms_orig_blk;
		comp->un_mirror.ms_hs_key = 0;
		comp->un_mirror.ms_hs_id = 0;
		comp->un_mirror.ms_orig_dev = 0;

		cmd = HS_FREE;
		if ((comp->un_mirror.ms_state != CS_OKAY) &&
		    (comp->un_mirror.ms_state != CS_RESYNC))
			cmd = HS_BAD;
		(void) md_hot_spare_ifc(cmd, un->un_hsp_id, 0, 0, &hs_id,
		    &hs_key, NULL, NULL);
	}

	/*
	 * Open by device id; for enable (indicated by a NULL
	 * nd pointer), use the existing component info.  For
	 * replace, use the new device.
	 */
	if (nd == NULL) {
		this_dev = md_resolve_bydevid(mnum, comp->un_dev, comp->un_key);
		/*
		 * If someone replaced a new disk in the same slot
		 * we get NODEV64 since old device id cannot be
		 * resolved. The new devt is obtained from the
		 * mddb since devt is going to be unchanged for the
		 * enable case. No need to check for multiple
		 * keys here because the caller (comp_replace)
		 * has already sanity checked it for us.
		 */
		if (this_dev == NODEV64) {
			this_dev = md_getdevnum(setno, side, comp->un_key,
			    MD_TRUST_DEVT);
		}
	} else {
		/*
		 * If this is a hotspare, save the original dev_t for later
		 * use. If this has occured during boot then the value of
		 * comp->un_dev will be NODEV64 because of the failure to look
		 * up the devid of the device.
		 */
		if (nd->nd_hs_id != 0)
			comp->un_mirror.ms_orig_dev = comp->un_dev;
		this_dev = md_resolve_bydevid(mnum, nd->nd_dev, nd->nd_key);
	}

	comp->un_dev = this_dev;

	/*
	 * Now open the new device if required. Note for a single component
	 * stripe it will not be open - leave this for the mirror driver to
	 * deal with.
	 */
	if (md_unit_isopen(ui)) {
		if (md_layered_open(mnum, &this_dev, MD_OFLG_NULL)) {
			mddb_recid_t	ids[3];

			ids[0] = un->c.un_record_id;
			ids[1] = hs_id;
			ids[2] = 0;
			mddb_commitrecs_wrapper(ids);
			if ((nd != NULL) && (nd->nd_hs_id != 0)) {
				/*
				 * Revert back to the original device.
				 */
				comp->un_dev = comp->un_mirror.ms_orig_dev;

				cmn_err(CE_WARN,
				    "md: %s: open error of hotspare %s",
				    md_shortname(mnum),
				    md_devname(MD_MIN2SET(mnum), nd->nd_dev,
				    NULL, 0));
				SE_NOTIFY(EC_SVM_STATE, ESC_SVM_OPEN_FAIL,
				    SVM_TAG_HS, MD_MIN2SET(mnum), nd->nd_dev);
			}
			md_unit_writerexit(ui);
			return (MDE_COMP_OPEN_ERR);
		}
		if (nd != NULL)
			nd->nd_dev = this_dev;

		comp->un_mirror.ms_flags |= MDM_S_ISOPEN;
	}

	if (nd == NULL) {
		recids[0] = un->c.un_record_id;
		recids[1] = hs_id;
		recids[2] = 0;
		*replace_done = stripe_replace_done;
		return (0);
	}

	/* if hot sparing this device */
	if (nd->nd_hs_id != 0) {
		char	devname[MD_MAX_CTDLEN];
		char	hs_devname[MD_MAX_CTDLEN];
		set_t	setno;

		comp->un_mirror.ms_hs_id = nd->nd_hs_id;
		comp->un_mirror.ms_hs_key = nd->nd_key;

		comp->un_mirror.ms_orig_blk = comp->un_start_block;

		setno = MD_MIN2SET(mnum);

		(void) md_devname(setno, comp->un_mirror.ms_orig_dev, devname,
		    sizeof (devname));
		(void) md_devname(setno, nd->nd_dev, hs_devname,
		    sizeof (hs_devname));

		cmn_err(CE_NOTE, "md: %s: hotspared device %s with %s",
		    md_shortname(mnum), devname, hs_devname);

	} else {	/* replacing the device */
		comp->un_key = nd->nd_key;
		*replace_data = (void *)sv;

		/*
		 * For the old device, make sure to reset the parent
		 * if it's a  metadevice.
		 */
		if (md_getmajor(comp->un_dev) == md_major) {
			minor_t	  comp_mnum = md_getminor(comp->un_dev);
			md_unit_t *comp_un = MD_UNIT(comp_mnum);

			md_reset_parent(comp->un_dev);
			recids[rid++] = MD_RECID(comp_un);
		}
	}

	comp->un_dev = nd->nd_dev;
	comp->un_start_block = nd->nd_start_blk;

	/*
	 * For the new device, make sure to set the parent if it's a
	 * metadevice.
	 *
	 * If we ever support using metadevices as hot spares, this
	 * will need to be tested, and possibly moved into the
	 * preceding "else" clause, immediately following the parent
	 * reset block.  For now, it's convenient to leave it here and
	 * only compress nd->nd_dev once.
	 */
	if (md_getmajor(comp->un_dev) == md_major) {
		minor_t		comp_mnum = md_getminor(comp->un_dev);
		md_unit_t	*comp_un = MD_UNIT(comp_mnum);

		md_set_parent(comp->un_dev, MD_SID(un));
		recids[rid++] = MD_RECID(comp_un);
	}

	recids[rid++] = un->c.un_record_id;
	recids[rid++] = hs_id;
	recids[rid] = 0;
	*replace_done = stripe_replace_done;
	return (0);
}

/*ARGSUSED*/
static intptr_t
stripe_hotspare_dev(
	md_dev64_t	dev,
	void		*junk,
	int		ci,
	mddb_recid_t	*recids,
	int		nrecids,
	void		(**replace_done)(),
	void		**replace_data)
{
	ms_unit_t	*un;
	mdi_unit_t	*ui;
	ms_comp_t	*comp;
	int		row;
	struct ms_row	*mdr;
	ms_new_dev_t	nd;
	int		err;
	int		i;
	minor_t		mnum;
	set_t		setno;
	int		cmpcount = 0;

	mnum = md_getminor(dev);
	ui = MDI_UNIT(mnum);
	un = MD_UNIT(mnum);
	setno = MD_MIN2SET(mnum);

	if (md_get_setstatus(setno) & MD_SET_STALE)
		return (1);

	if (un->un_hsp_id == -1)
		return (1);

	for (row = 0; row < un->un_nrows; row++) {
		mdr = &un->un_row[row];
		if ((mdr->un_ncomp + cmpcount) > ci)
			break;
		cmpcount += mdr->un_ncomp;
	}
	ASSERT(row != un->un_nrows);

	comp = (struct ms_comp *)((void *)&((char *)un)[un->un_ocomp]);
	comp += ci;
	/* Concatenations have a ncomp = 1 */
	nd.nd_nblks = mdr->un_blocks / mdr->un_ncomp;

	if ((un->c.un_flag & MD_LABELED) && (ci == 0))
		nd.nd_labeled = 1;
	else
		nd.nd_labeled = 0;

again:
	err = md_hot_spare_ifc(HS_GET, un->un_hsp_id, nd.nd_nblks,
	    nd.nd_labeled, &nd.nd_hs_id, &nd.nd_key, &nd.nd_dev,
	    &nd.nd_start_blk);

	if (err) {
		if (!stripe_replace_dev(dev, junk, ci, NULL, recids, nrecids,
		    replace_done, replace_data)) {
			mddb_commitrecs_wrapper(recids);
			md_unit_writerexit(ui);
		}
		recids[0] = 0;
		return (1);
	}

	if (stripe_replace_dev(dev, junk, ci, &nd, recids, nrecids,
	    replace_done, replace_data)) {

		(void) md_hot_spare_ifc(HS_BAD, un->un_hsp_id, 0, 0,
		    &nd.nd_hs_id, &nd.nd_key, NULL, NULL);
		mddb_commitrec_wrapper(nd.nd_hs_id);
		goto again;
	}

	/* Leave a slot for the null recid */
	for (i = 0; i < (nrecids - 1); i++) {
		if (recids[i] == 0) {
			recids[i++] = nd.nd_hs_id;
			recids[i] = 0;
		}
	}
	return (0);
}

static int
stripe_imp_set(
	set_t	setno
)
{

	mddb_recid_t	recid;
	int		i, row, c, gotsomething;
	mddb_type_t	typ1;
	mddb_de_ic_t	*dep;
	mddb_rb32_t	*rbp;
	ms_unit32_od_t	*un32;
	ms_unit_t	*un64;
	md_dev64_t	self_devt;
	minor_t		*self_id;	/* minor needs to be updated */
	md_parent_t	*parent_id;	/* parent needs to be updated */
	mddb_recid_t	*record_id;	/* record id needs to be updated */
	mddb_recid_t	*hsp_id;
	ms_comp32_od_t	*comp32;
	ms_comp_t	*comp64;


	gotsomething = 0;

	typ1 = (mddb_type_t)md_getshared_key(setno,
	    stripe_md_ops.md_driver.md_drivername);
	recid = mddb_makerecid(setno, 0);

	while ((recid = mddb_getnextrec(recid, typ1, 0)) > 0) {
		if (mddb_getrecprivate(recid) & MD_PRV_GOTIT)
			continue;

		dep = mddb_getrecdep(recid);
		rbp = dep->de_rb;

		switch (rbp->rb_revision) {
		case MDDB_REV_RB:
		case MDDB_REV_RBFN:
			/*
			 * Small device
			 */
			un32 = (ms_unit32_od_t *)mddb_getrecaddr(recid);
			self_id = &(un32->c.un_self_id);
			parent_id = &(un32->c.un_parent);
			record_id = &(un32->c.un_record_id);
			hsp_id = &(un32->un_hsp_id);

			comp32 = (ms_comp32_od_t *)
			    ((void *)&((char *)un32)[un32->un_ocomp]);
			for (row = 0; row < un32->un_nrows; row++) {
				struct ms_row32_od *mdr = &un32->un_row[row];
				for (i = 0, c = mdr->un_icomp;
				    i < mdr->un_ncomp; i++) {
					ms_comp32_od_t *mdc;

					mdc = &comp32[c++];

					if (!md_update_minor(setno,
					    mddb_getsidenum(setno),
					    mdc->un_key))
						goto out;

					if (mdc->un_mirror.ms_hs_id != 0)
						mdc->un_mirror.ms_hs_id =
						    MAKERECID(setno,
						    mdc->un_mirror.ms_hs_id);
				}
			}
			break;
		case MDDB_REV_RB64:
		case MDDB_REV_RB64FN:
			un64 = (ms_unit_t *)mddb_getrecaddr(recid);
			self_id = &(un64->c.un_self_id);
			parent_id = &(un64->c.un_parent);
			record_id = &(un64->c.un_record_id);
			hsp_id = &(un64->un_hsp_id);

			comp64 = (ms_comp_t *)
			    ((void *)&((char *)un64)[un64->un_ocomp]);
			for (row = 0; row < un64->un_nrows; row++) {
				struct ms_row *mdr = &un64->un_row[row];

				for (i = 0, c = mdr->un_icomp;
				    i < mdr->un_ncomp; i++) {
					ms_comp_t *mdc;

					mdc = &comp64[c++];

					if (!md_update_minor(setno,
					    mddb_getsidenum(setno),
					    mdc->un_key))
						goto out;

					if (mdc->un_mirror.ms_hs_id != 0)
						mdc->un_mirror.ms_hs_id =
						    MAKERECID(setno,
						    mdc->un_mirror.ms_hs_id);
				}
			}
			break;
		}

		/*
		 * If this is a top level and a friendly name metadevice,
		 * update its minor in the namespace.
		 */
		if ((*parent_id == MD_NO_PARENT) &&
		    ((rbp->rb_revision == MDDB_REV_RBFN) ||
		    (rbp->rb_revision == MDDB_REV_RB64FN))) {

			self_devt = md_makedevice(md_major, *self_id);
			if (!md_update_top_device_minor(setno,
			    mddb_getsidenum(setno), self_devt))
				goto out;
		}

		/*
		 * Update unit with the imported setno
		 *
		 */
		mddb_setrecprivate(recid, MD_PRV_GOTIT);

		*self_id = MD_MKMIN(setno, MD_MIN2UNIT(*self_id));

		if (*hsp_id != -1)
			*hsp_id = MAKERECID(setno, DBID(*hsp_id));

		if (*parent_id != MD_NO_PARENT)
			*parent_id = MD_MKMIN(setno, MD_MIN2UNIT(*parent_id));
		*record_id = MAKERECID(setno, DBID(*record_id));

		gotsomething = 1;
	}

out:
	return (gotsomething);
}

static md_named_services_t stripe_named_services[] = {
	{stripe_shared_by_blk,			"shared by blk"		    },
	{stripe_shared_by_indx,			"shared by indx"	    },
	{stripe_component_count,		"get component count"	    },
	{stripe_block_count_skip_size,		"get block count skip size" },
	{stripe_get_dev,			"get device"		    },
	{stripe_replace_dev,			"replace device"	    },
	{stripe_hotspare_dev,			"hotspare device"	    },
	{stripe_rename_check,			MDRNM_CHECK		    },
	{NULL,					0}
};

md_ops_t stripe_md_ops = {
	stripe_open,		/* open */
	stripe_close,		/* close */
	md_stripe_strategy,	/* strategy */
	NULL,			/* print */
	stripe_dump,		/* dump */
	NULL,			/* read */
	NULL,			/* write */
	md_stripe_ioctl,	/* stripe_ioctl, */
	stripe_snarf,		/* stripe_snarf */
	stripe_halt,		/* stripe_halt */
	NULL,			/* aread */
	NULL,			/* awrite */
	stripe_imp_set,		/* import set */
	stripe_named_services
};

static void
init_init()
{
	md_stripe_mcs_buf_off = sizeof (md_scs_t) - sizeof (buf_t);

	stripe_parent_cache = kmem_cache_create("md_stripe_parent",
	    sizeof (md_sps_t), 0, stripe_parent_constructor,
	    stripe_parent_destructor, stripe_run_queue, NULL, NULL,
	    0);
	stripe_child_cache = kmem_cache_create("md_stripe_child",
	    sizeof (md_scs_t) - sizeof (buf_t) + biosize(), 0,
	    stripe_child_constructor, stripe_child_destructor,
	    stripe_run_queue, NULL, NULL, 0);
}

static void
fini_uninit()
{
	kmem_cache_destroy(stripe_parent_cache);
	kmem_cache_destroy(stripe_child_cache);
	stripe_parent_cache = stripe_child_cache = NULL;
}

/* define the module linkage */
MD_PLUGIN_MISC_MODULE("stripes module", init_init(), fini_uninit())
