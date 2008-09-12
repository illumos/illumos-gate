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
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/mkdev.h>
#include <sys/stat.h>
#include <sys/open.h>
#include <sys/lvm/mdvar.h>
#include <sys/lvm/md_stripe.h>
#include <sys/lvm/md_notify.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/debug.h>
#include <sys/model.h>

#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/svm.h>

extern int		md_status;

extern unit_t		md_nunits;
extern set_t		md_nsets;
extern md_set_t		md_set[];

extern md_ops_t		stripe_md_ops;
extern md_krwlock_t	md_unit_array_rw;
extern major_t		md_major;

static int
stripe_replace(replace_params_t *params)
{
	minor_t		mnum = params->mnum;
	ms_unit_t	*un;
	mddb_recid_t	recids[6];
	ms_new_dev_t	nd;
	ms_cd_info_t	cd;
	int		ci;
	int		cmpcnt;
	void		*repl_data;
	md_dev64_t	fake_devt;
	void		(*repl_done)();

	mdclrerror(&params->mde);

	un = (ms_unit_t *)MD_UNIT(mnum);

	if (MD_STATUS(un) & MD_UN_RESYNC_ACTIVE) {
		return (mdmderror(&params->mde, MDE_RESYNC_ACTIVE, mnum));
	}

	nd.nd_dev = params->new_dev;
	nd.nd_key = params->new_key;
	nd.nd_nblks = params->number_blks;
	nd.nd_start_blk = params->start_blk;
	nd.nd_labeled = params->has_label;
	nd.nd_hs_id = 0;

	/*
	 * stripe_component_count and stripe_get_dev only care about the
	 * minor number associated with the first argument which is a
	 * md_dev64_t
	 *
	 * The comments section for these two routines have been updated
	 * to indicate that this routine calls with fake major numbers.
	 */
	fake_devt = md_makedevice(0, mnum);
	cmpcnt = stripe_component_count(fake_devt, NULL);
	for (ci = 0; ci < cmpcnt; ci++) {
		(void) stripe_get_dev(fake_devt, NULL, ci, &cd);
		if ((cd.cd_dev == params->old_dev) ||
		    (cd.cd_orig_dev == params->old_dev))
			break;
	}
	if (ci == cmpcnt) {
		return (EINVAL);
	}

	/*  In case of a dryrun we're done here */
	if (params->options & MDIOCTL_DRYRUN) {
		return (0);
	}

	(void) stripe_replace_dev(fake_devt, 0, ci, &nd, recids, 6,
	    &repl_done, &repl_data);
	mddb_commitrecs_wrapper(recids);
	(*repl_done)(fake_devt, repl_data);

	SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_REPLACE, SVM_TAG_METADEVICE,
	    MD_UN2SET(un), MD_SID(un));
	return (0);
}

static int
stripe_set(void *d, int mode)
{
	minor_t		mnum;
	ms_unit_t	*un;
	void		*p;
	mddb_recid_t	ms_recid;
	mddb_recid_t	*recids;
	mddb_type_t	typ1;
	int		err;
	set_t		setno;
	md_error_t	*mdep;
	struct ms_comp	*mdcomp;
	int		row;
	int		rid;
	int		num_recs;
	int		i, c;
	md_set_params_t	*msp = d;

	mnum = msp->mnum;
	setno = MD_MIN2SET(mnum);

	mdep = &msp->mde;

	mdclrerror(mdep);

	if ((setno >= md_nsets) || (MD_MIN2UNIT(mnum) >= md_nunits)) {
		return (mdmderror(mdep, MDE_INVAL_UNIT, mnum));
	}

	if (md_get_setstatus(setno) & MD_SET_STALE)
		return (mdmddberror(mdep, MDE_DB_STALE, mnum, setno));

	un = MD_UNIT(mnum);
	if (un != NULL) {
		return (mdmderror(mdep, MDE_UNIT_ALREADY_SETUP, mnum));
	}


	typ1 = (mddb_type_t)md_getshared_key(setno,
	    stripe_md_ops.md_driver.md_drivername);

	/* create the db record for this mdstruct */
	if (msp->options & MD_CRO_64BIT) {
#if defined(_ILP32)
		return (mdmderror(mdep, MDE_UNIT_TOO_LARGE, mnum));
#else
		ms_recid = mddb_createrec((size_t)msp->size, typ1, 0,
		    MD_CRO_64BIT | MD_CRO_STRIPE | MD_CRO_FN, setno);
#endif
	} else {
		ms_recid = mddb_createrec((size_t)msp->size, typ1, 0,
		    MD_CRO_32BIT | MD_CRO_STRIPE | MD_CRO_FN, setno);
	}
	if (ms_recid < 0)
		return (mddbstatus2error(mdep, ms_recid, mnum, setno));

	/* get the address of the mdstruct */
	p = (void *) mddb_getrecaddr(ms_recid);
	/*
	 * It is okay that we muck with the mdstruct here,
	 * since no one else will know about the mdstruct
	 * until we commit it. If we crash, the record will
	 * be automatically purged, since we haven't
	 * committed it yet.
	 */

	/* copy in the user's mdstruct */
	if (err = ddi_copyin((caddr_t)(uintptr_t)msp->mdp, (caddr_t)p,
	    (size_t)msp->size, mode)) {
		mddb_deleterec_wrapper(ms_recid);
		return (EFAULT);
	}

	un = (ms_unit_t *)p;

	/* All 64 bit metadevices only support EFI labels. */
	if (msp->options & MD_CRO_64BIT) {
		un->c.un_flag |= MD_EFILABEL;
	}

	/*
	 * allocate the real recids array.  since we may have to commit
	 * underlying metadevice records, we need an array
	 * of size: total number of components in stripe + 3
	 * (1 for the stripe itself, one for the hotspare, one
	 * for the end marker).
	 */
	num_recs = 3;
	rid = 0;
	for (row = 0; row < un->un_nrows; row++) {
		struct ms_row *mdr = &un->un_row[row];
		num_recs += mdr->un_ncomp;
	}
	recids = kmem_alloc(num_recs * sizeof (mddb_recid_t), KM_SLEEP);
	recids[rid++] = ms_recid;

	MD_SID(un) = mnum;
	MD_RECID(un) = recids[0];
	MD_CAPAB(un) = MD_CAN_PARENT | MD_CAN_SUB_MIRROR | MD_CAN_SP;
	MD_PARENT(un) = MD_NO_PARENT;
	un->c.un_revision |= MD_FN_META_DEV;

	if (err = stripe_build_incore(p, 0)) {
		MD_UNIT(mnum) = NULL;
		mddb_deleterec_wrapper(recids[0]);
		kmem_free(recids, num_recs * sizeof (mddb_recid_t));
		return (err);
	}

	/*
	 * Update unit availability
	 */
	md_set[setno].s_un_avail--;

	recids[rid] = 0;
	if (un->un_hsp_id != -1)
		err = md_hot_spare_ifc(HSP_INCREF, un->un_hsp_id, 0, 0,
		    &recids[rid++], NULL, NULL, NULL);


	if (err) {
		MD_UNIT(mnum) = NULL;
		mddb_deleterec_wrapper(recids[0]);
		kmem_free(recids, num_recs * sizeof (mddb_recid_t));
		return (mdhsperror(mdep, MDE_INVAL_HSP, un->un_hsp_id));
	}

	/*
	 * set the parent on any metadevice components.
	 * NOTE: currently soft partitions are the only metadevices
	 * which can appear within a stripe.
	 */
	mdcomp = (ms_comp_t *)((void *)&((char *)un)[un->un_ocomp]);
	for (row = 0; row < un->un_nrows; row++) {
		struct ms_row *mdr = &un->un_row[row];
		for (i = 0, c = mdr->un_icomp; i < mdr->un_ncomp; i++) {
			ms_comp_t *mdc = &mdcomp[c++];
			md_dev64_t comp_dev;
			md_unit_t *comp_un;

			comp_dev = mdc->un_dev;
			if (md_getmajor(comp_dev) == md_major) {
				/* set parent and disallow soft partitioning */
				comp_un = MD_UNIT(md_getminor(comp_dev));
				recids[rid++] = MD_RECID(comp_un);
				md_set_parent(mdc->un_dev, MD_SID(un));
			}
		}
	}

	/* set end marker */
	recids[rid] = 0;
	mddb_commitrecs_wrapper(recids);

	md_create_unit_incore(mnum, &stripe_md_ops, 0);
	kmem_free(recids, (num_recs * sizeof (mddb_recid_t)));
	SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_CREATE, SVM_TAG_METADEVICE,
	    MD_UN2SET(un), MD_SID(un));
	return (0);
}


/*ARGSUSED*/
static int
stripe_get(void *d, int mode, IOLOCK *lock)
{
	minor_t		mnum;
	mdi_unit_t	*ui;
	ms_unit_t	*un;
	md_error_t	*mdep;
	md_i_get_t	*migp = d;


	mnum = migp->id;
	mdep = &migp->mde;

	mdclrerror(mdep);

	if ((MD_MIN2SET(mnum) >= md_nsets) || (MD_MIN2UNIT(mnum) >= md_nunits))
		return (mdmderror(mdep, MDE_INVAL_UNIT, mnum));

	if ((ui = MDI_UNIT(mnum)) == NULL) {
		return (mdmderror(mdep, MDE_UNIT_NOT_SETUP, mnum));
	}

	un = (ms_unit_t *)md_ioctl_readerlock(lock, ui);

	if (migp->size == 0) {
		migp->size = un->c.un_size;
		return (0);
	}

	if (migp->size < un->c.un_size) {
		return (EFAULT);
	}

	if (ddi_copyout(un, (void *)(uintptr_t)migp->mdp,
	    un->c.un_size, mode))
		return (EFAULT);
	return (0);
}

static int
stripe_reset(md_i_reset_t *mirp)
{
	minor_t		mnum = mirp->mnum;
	ms_unit_t	*un;
	mdi_unit_t	*ui;
	set_t		setno = MD_MIN2SET(mnum);

	mdclrerror(&mirp->mde);

	if ((setno >= md_nsets) || (MD_MIN2UNIT(mnum) >= md_nunits))
		return (mdmderror(&mirp->mde, MDE_INVAL_UNIT, mnum));

	if (md_get_setstatus(setno) & MD_SET_STALE)
		return (mdmddberror(&mirp->mde, MDE_DB_STALE, mnum, setno));

	un = MD_UNIT(mnum);
	if (un == NULL) {
		return (mdmderror(&mirp->mde, MDE_UNIT_NOT_SETUP, mnum));
	}

	/* This prevents new opens */
	rw_enter(&md_unit_array_rw.lock, RW_WRITER);

	if (MD_HAS_PARENT(un->c.un_parent)) {
		rw_exit(&md_unit_array_rw.lock);
		return (mdmderror(&mirp->mde, MDE_IN_USE, mnum));
	}

	/* single thread */
	ui = MDI_UNIT(mnum);
	un = md_unit_openclose_enter(ui);

	if (md_unit_isopen(ui)) {
		md_unit_openclose_exit(ui);
		rw_exit(&md_unit_array_rw.lock);
		return (mdmderror(&mirp->mde, MDE_IS_OPEN, mnum));
	}

	md_unit_openclose_exit(ui);
	reset_stripe(un, mnum, 1);

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

static int
stripe_grow(void *d, int mode, IOLOCK *lockp)
{
	minor_t		mnum;
	ms_unit_t	*un, *new_un;
	mdi_unit_t	*ui;
	minor_t		*par = NULL;
	IOLOCK		*plock = NULL;
	ms_comp_t	*mdcomp, *new_comp;
	int		row, i, c;
	mddb_recid_t	ms_recid;
	mddb_recid_t	old_vtoc = 0;
	mddb_recid_t	*recids;
	md_create_rec_option_t options;
	mddb_type_t	typ1;
	int		err;
	int64_t		tb, atb;
	uint_t		nr, oc;
	int		opened;
	int		rval = 0;
	set_t		setno;
	md_error_t	*mdep;
	int		npar;
	int		rid;
	int		num_recs;
	u_longlong_t	rev;
	md_grow_params_t	*mgp = d;


	mnum = mgp->mnum;
	mdep = &mgp->mde;
	setno = MD_MIN2SET(mnum);
	npar = mgp->npar;

	mdclrerror(mdep);

	if ((setno >= md_nsets) || (MD_MIN2UNIT(mnum) >= md_nunits))
		return (mdmderror(mdep, MDE_INVAL_UNIT, mnum));

	if (md_get_setstatus(setno) & MD_SET_STALE)
		return (mdmddberror(mdep, MDE_DB_STALE, mnum, setno));

	ui = MDI_UNIT(mnum);
	if (ui == NULL) {
		return (mdmderror(mdep, MDE_UNIT_NOT_SETUP, mnum));
	}

	if (npar >= 1) {
		ASSERT((minor_t *)(uintptr_t)mgp->par != NULL);
		par = kmem_alloc(npar * sizeof (*par), KM_SLEEP);
		plock = kmem_alloc(npar * sizeof (*plock), KM_SLEEP);
		if (ddi_copyin((caddr_t)(uintptr_t)mgp->par, (caddr_t)par,
		    (npar * sizeof (*par)), mode) != 0) {
			kmem_free(par, npar * sizeof (*par));
			kmem_free(plock, npar * sizeof (*plock));
			return (EFAULT);
		}
	}

	/*
	 * we grab unit reader/writer first, then parent locks,
	 * then our own.
	 * we expect parent units to be sorted to avoid deadlock
	 */
	rw_enter(&md_unit_array_rw.lock, RW_WRITER);
	for (i = 0; i < npar; ++i) {
		(void) md_ioctl_writerlock(&plock[i],
		    MDI_UNIT(par[i]));
	}
	un = (ms_unit_t *)md_ioctl_writerlock(lockp, ui);

	if (un->un_nrows != mgp->nrows) {
		rval = EINVAL;
		goto out;
	}

	typ1 = (mddb_type_t)md_getshared_key(setno,
	    stripe_md_ops.md_driver.md_drivername);

	/*
	 * Preserve the friendly name nature of growing device.
	 */
	options = MD_CRO_STRIPE;
	if (un->c.un_revision & MD_FN_META_DEV)
		options |= MD_CRO_FN;
	if (mgp->options & MD_CRO_64BIT) {
#if defined(_ILP32)
		rval = mdmderror(mdep, MDE_UNIT_TOO_LARGE, mnum);
		goto out;
#else
		ms_recid = mddb_createrec((size_t)mgp->size, typ1, 0,
		    MD_CRO_64BIT | options, setno);
#endif
	} else {
		ms_recid = mddb_createrec((size_t)mgp->size, typ1, 0,
		    MD_CRO_32BIT | options, setno);
	}


	if (ms_recid < 0) {
		rval = mddbstatus2error(mdep, (int)ms_recid, mnum, setno);
		goto out;
	}

	/* get the address of the new unit */
	new_un = (ms_unit_t *)mddb_getrecaddr(ms_recid);

	/*
	 * It is okay that we muck with the new unit here,
	 * since no one else will know about the unit struct
	 * until we commit it. If we crash, the record will
	 * be automatically purged, since we haven't
	 * committed it yet and the old unit struct will be found.
	 */

	/* copy in the user's unit struct */
	err = ddi_copyin((caddr_t)(uintptr_t)mgp->mdp, (caddr_t)new_un,
	    (size_t)mgp->size, mode);
	if (err) {
		mddb_deleterec_wrapper(ms_recid);
		rval = EFAULT;
		goto out;
	}
	if (options & MD_CRO_FN)
		new_un->c.un_revision |= MD_FN_META_DEV;

	/*
	 * allocate the real recids array.  since we may have to
	 * commit underlying metadevice records, we need an
	 * array of size: total number of new components being
	 * attached + 2 (one for the stripe itself, one for the
	 * end marker).
	 */
	num_recs = 2;
	rid = 0;
	for (row = 0; row < new_un->un_nrows; row++) {
		struct ms_row *mdr = &new_un->un_row[row];
		num_recs += mdr->un_ncomp;
	}
	recids = kmem_alloc(num_recs * sizeof (mddb_recid_t), KM_SLEEP);
	recids[rid++] = ms_recid;

	/*
	 * Save a few of the new unit structs fields.
	 * Before they get clobbered.
	 */
	tb = new_un->c.un_total_blocks;
	atb = new_un->c.un_actual_tb;
	nr = new_un->un_nrows;
	oc = new_un->un_ocomp;
	rev = new_un->c.un_revision;

	/*
	 * Copy the old unit struct (static stuff)
	 * into new unit struct
	 */
	bcopy((caddr_t)un, (caddr_t)new_un,
	    sizeof (ms_unit_t) + ((nr - 2) * (sizeof (struct ms_row))));

	/*
	 * Restore the saved stuff.
	 */
	new_un->c.un_total_blocks = tb;
	new_un->c.un_actual_tb = atb;
	new_un->un_nrows = nr;
	new_un->un_ocomp = oc;
	new_un->c.un_revision = rev;

	new_un->c.un_record_id = ms_recid;
	new_un->c.un_size = mgp->size;

	/* All 64 bit metadevices only support EFI labels. */
	if (mgp->options & MD_CRO_64BIT) {
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
	 * Copy the old component structs into the new unit struct.
	 */
	mdcomp = (ms_comp_t *)((void *)&((char *)un)[un->un_ocomp]);
	new_comp = (ms_comp_t *)((void *)&((char *)new_un)[new_un->un_ocomp]);
	for (row = 0; row < un->un_nrows; row++) {
		struct ms_row *mdr = &un->un_row[row];
		for (i = 0, c = mdr->un_icomp; i < mdr->un_ncomp; i++, c++) {
			bcopy((caddr_t)&mdcomp[c], (caddr_t)&new_comp[c],
			    sizeof (ms_comp_t));
		}
	}

	opened = md_unit_isopen(ui);

	/*
	 * Set parent on metadevices being added.
	 * Open the new devices being added.
	 * NOTE: currently soft partitions are the only metadevices
	 * which can appear within a stripe.
	 */
	for (row = un->un_nrows; row < new_un->un_nrows; row++) {
		struct ms_row *mdr = &new_un->un_row[row];
		for (i = 0, c = mdr->un_icomp; i < mdr->un_ncomp; i++) {
			struct ms_comp	*mdc = &new_comp[c++];
			md_dev64_t comp_dev;
			md_unit_t *comp_un;

			comp_dev = mdc->un_dev;
			/* set parent on any metadevices */
			if (md_getmajor(comp_dev) == md_major) {
				comp_un = MD_UNIT(md_getminor(comp_dev));
				recids[rid++] = MD_RECID(comp_un);
				md_set_parent(comp_dev, MD_SID(new_un));
			}

			if (opened) {
				md_dev64_t tmpdev = mdc->un_dev;
				/*
				 * Open by device id
				 * Check if this comp is hotspared and
				 * if it is then use the key for hotspare
				 */
				tmpdev = md_resolve_bydevid(mnum, tmpdev,
				    mdc->un_mirror.ms_hs_id ?
				    mdc->un_mirror.ms_hs_key : mdc->un_key);
				(void) md_layered_open(mnum, &tmpdev,
				    MD_OFLG_NULL);
				mdc->un_dev = tmpdev;
				mdc->un_mirror.ms_flags |= MDM_S_ISOPEN;
			}
		}
	}

	/* set end marker */
	recids[rid] = 0;
	/* commit new unit struct */
	mddb_commitrecs_wrapper(recids);

	/* delete old unit struct */
	mddb_deleterec_wrapper(un->c.un_record_id);
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

	/* free recids array */
	kmem_free(recids, num_recs * sizeof (mddb_recid_t));

	SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_GROW, SVM_TAG_METADEVICE,
	    MD_UN2SET(new_un), MD_SID(new_un));

	/* release locks, return success */
out:
	for (i =  npar - 1; (i >= 0); --i)
		md_ioctl_writerexit(&plock[i]);
	rw_exit(&md_unit_array_rw.lock);
	if (plock != NULL)
		kmem_free(plock, npar * sizeof (*plock));
	if (par != NULL)
		kmem_free(par, npar * sizeof (*par));
	return (rval);
}

static int
stripe_get_geom(
	ms_unit_t	*un,
	struct dk_geom	*geomp
)
{
	md_get_geom((md_unit_t *)un, geomp);

	return (0);
}

static int
stripe_get_vtoc(
	ms_unit_t	*un,
	struct vtoc	*vtocp
)
{
	md_get_vtoc((md_unit_t *)un, vtocp);

	return (0);
}

static int
stripe_set_vtoc(
	ms_unit_t	*un,
	struct vtoc	*vtocp
)
{
	return (md_set_vtoc((md_unit_t *)un, vtocp));
}

static int
stripe_get_extvtoc(
	ms_unit_t	*un,
	struct extvtoc	*vtocp
)
{
	md_get_extvtoc((md_unit_t *)un, vtocp);

	return (0);
}

static int
stripe_set_extvtoc(
	ms_unit_t	*un,
	struct extvtoc	*vtocp
)
{
	return (md_set_extvtoc((md_unit_t *)un, vtocp));
}

static int
stripe_get_cgapart(
	ms_unit_t	*un,
	struct dk_map	*dkmapp
)
{
	md_get_cgapart((md_unit_t *)un, dkmapp);
	return (0);
}

static int
stripe_getdevs(
	void			*d,
	int			mode,
	IOLOCK			*lock
)
{
	minor_t			mnum;
	mdi_unit_t		*ui;
	ms_unit_t		*un;
	struct ms_row		*mdr;
	ms_comp_t		*mdcomp, *mdc;
	int			r, c, i;
	int			cnt;
	md_error_t		*mdep;
	md_dev64_t		*devsp;
	md_dev64_t		unit_dev;
	md_getdevs_params_t	*mgdp = d;


	mnum = mgdp->mnum;
	mdep = &mgdp->mde;

	/* check out unit */
	mdclrerror(mdep);

	if ((MD_MIN2SET(mnum) >= md_nsets) || (MD_MIN2UNIT(mnum) >= md_nunits))
		return (mdmderror(mdep, MDE_INVAL_UNIT, mnum));

	if ((ui = MDI_UNIT(mnum)) == NULL) {
		return (mdmderror(mdep, MDE_UNIT_NOT_SETUP, mnum));
	}

	un = (ms_unit_t *)md_ioctl_readerlock(lock, ui);

	mdcomp = (struct ms_comp *)((void *)&((char *)un)[un->un_ocomp]);
	devsp = (md_dev64_t *)(uintptr_t)mgdp->devs;

	for (cnt = 0, r = 0; (r < un->un_nrows); ++r) {
		mdr = &un->un_row[r];
		for (c = 0, i = mdr->un_icomp; (c < mdr->un_ncomp); ++c) {
			mdc = &mdcomp[i++];
			if (cnt < mgdp->cnt) {
				unit_dev = mdc->un_dev;
				if (md_getmajor(unit_dev) != md_major) {
					if ((unit_dev = md_xlate_mini_2_targ
					    (unit_dev)) == NODEV64)
						return (ENODEV);
				}

				if (ddi_copyout((caddr_t)&unit_dev, devsp,
				    sizeof (*devsp), mode) != 0)
					return (EFAULT);
				++devsp;
			}
			++cnt;
		}
	}
	mgdp->cnt = cnt;
	return (0);
}

static int
stripe_change(
	md_stripe_params_t	*msp,
	IOLOCK			*lock
)
{
	ms_params_t		*pp = &msp->params;
	minor_t			mnum = msp->mnum;
	ms_unit_t		*un;
	mdi_unit_t		*ui;
	int			r, c, i;
	struct ms_row		*mdr;
	ms_comp_t		*mdcomp, *mdc;
	mddb_recid_t		recids[4];
	int			irecid;
	int			inc_new_hsp = 0;
	int			err;
	set_t			setno = MD_MIN2SET(mnum);

	mdclrerror(&msp->mde);

	if ((setno >= md_nsets) || (MD_MIN2UNIT(mnum) >= md_nunits))
		return (mdmderror(&msp->mde, MDE_INVAL_UNIT, mnum));

	if (md_get_setstatus(setno) & MD_SET_STALE)
		return (mdmddberror(&msp->mde, MDE_DB_STALE, mnum, setno));

	if ((ui = MDI_UNIT(mnum)) == NULL) {
		return (mdmderror(&msp->mde, MDE_UNIT_NOT_SETUP, mnum));
	}

	if (!pp->change_hsp_id)
		return (0);

	un = (ms_unit_t *)md_ioctl_writerlock(lock, ui);

	/* verify that no hot spares are in use */
	mdcomp = (struct ms_comp *)((void *)&((char *)un)[un->un_ocomp]);
	for (r = 0; r < un->un_nrows; r++) {
		mdr = &un->un_row[r];
		for (c = 0, i = mdr->un_icomp; c < mdr->un_ncomp; c++) {
			mdc = &mdcomp[i++];
			if (mdc->un_mirror.ms_hs_id != 0) {
				return (mdmderror(&msp->mde, MDE_HS_IN_USE,
				    mnum));
			}
		}
	}

	recids[1] = 0;
	recids[2] = 0;
	irecid = 1;
	if (pp->hsp_id != -1) {
		/* increment the reference count of the new hsp */
		err = md_hot_spare_ifc(HSP_INCREF, pp->hsp_id, 0, 0,
		    &recids[1], NULL, NULL, NULL);
		if (err) {
			return (mdhsperror(&msp->mde, MDE_INVAL_HSP,
			    pp->hsp_id));
		}
		inc_new_hsp = 1;
		irecid++;
	}

	if (un->un_hsp_id != -1) {
		/* decrement the reference count of the old hsp */
		err = md_hot_spare_ifc(HSP_DECREF, un->un_hsp_id, 0, 0,
		    &recids[irecid], NULL, NULL, NULL);
		if (err) {
			err = mdhsperror(&msp->mde, MDE_INVAL_HSP,
			    pp->hsp_id);
			if (inc_new_hsp) {
				(void) md_hot_spare_ifc(HSP_DECREF,
				    pp->hsp_id, 0, 0,
				    &recids[1], NULL, NULL, NULL);
				/*
				 * Don't need to commit the record,
				 * cause it never got commit before
				 */
			}
			return (err);
		}
	}

	un->un_hsp_id = pp->hsp_id;

	recids[0] = un->c.un_record_id;
	recids[3] = 0;
	mddb_commitrecs_wrapper(recids);
	SE_NOTIFY(EC_SVM_STATE, ESC_SVM_CHANGE, SVM_TAG_METADEVICE,
	    MD_UN2SET(un), MD_SID(un));

	return (0);
}

static int
stripe_admin_ioctl(int cmd, void *data, int mode, IOLOCK *lockp)
{
	size_t	sz = 0;
	void	*d = NULL;
	int	err = 0;

	/* We can only handle 32-bit clients for internal commands */
	if ((mode & DATAMODEL_MASK) != DATAMODEL_ILP32) {
		return (EINVAL);
	}

	/* handle ioctl */
	switch (cmd) {

	case MD_IOCSET:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (struct md_set_params);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = stripe_set(d, mode);
		break;
	}

	case MD_IOCGET:
	{
		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (struct md_i_get);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = stripe_get(d, mode, lockp);
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

		err = stripe_reset((md_i_reset_t *)d);
		break;
	}

	case MD_IOCGROW:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (struct md_grow_params);
		d  = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = stripe_grow(d, mode, lockp);
		break;
	}

	case MD_IOCGET_DEVS:
	{
		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (struct md_getdevs_params);
		d  = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = stripe_getdevs(d, mode, lockp);
		break;
	}

	case MD_IOCCHANGE:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (md_stripe_params_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = stripe_change((md_stripe_params_t *)d, lockp);
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

		err = stripe_replace((replace_params_t *)d);
		break;
	}

	case MD_IOCPROBE_DEV:
	{
		/*
		 * Ignore the request since stripe is not
		 * a type of 'redundant' metadevice
		 */
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
 * The parameters of md_stripe_ioctl are defined by the ddi and so
 *  dev is of type dev_t and not md_dev64_t
 */
int
md_stripe_ioctl(dev_t dev, int cmd, void *data, int mode, IOLOCK *lockp)
{
	minor_t		mnum = getminor(dev);
	ms_unit_t	*un;
	int		err = 0;

	/* handle admin ioctls */
	if (mnum == MD_ADM_MINOR)
		return (stripe_admin_ioctl(cmd, data, mode, lockp));

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

	/* handle ioctl */
	switch (cmd) {

	case DKIOCINFO:
	{
		struct dk_cinfo		*p;

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
		struct dk_geom		*p;

		if (! (mode & FREAD))
			return (EACCES);

		p = kmem_alloc(sizeof (*p), KM_SLEEP);

		if ((err = stripe_get_geom(un, p)) == 0) {
			if (ddi_copyout((caddr_t)p, data, sizeof (*p),
			    mode) != 0)
				err = EFAULT;
		}

		kmem_free(p, sizeof (*p));
		return (err);
	}

	case DKIOCGVTOC:
	{
		struct vtoc	vtoc;

		if (! (mode & FREAD))
			return (EACCES);

		if ((err = stripe_get_vtoc(un, &vtoc)) != 0) {
			return (err);
		}

		if ((mode & DATAMODEL_MASK) == DATAMODEL_NATIVE) {
			if (ddi_copyout(&vtoc, data, sizeof (vtoc), mode))
				err = EFAULT;
		}
#ifdef _SYSCALL32
		else {
			struct vtoc32 vtoc32;
			vtoctovtoc32(vtoc, vtoc32);
			if (ddi_copyout(&vtoc32, data, sizeof (vtoc32), mode))
				err = EFAULT;
		}
#endif /* _SYSCALL32 */

		return (err);
	}

	case DKIOCSVTOC:
	{
		struct vtoc	vtoc;

		if (! (mode & FWRITE))
			return (EACCES);

		if ((mode & DATAMODEL_MASK) == DATAMODEL_NATIVE) {
			if (ddi_copyin(data, &vtoc, sizeof (vtoc), mode)) {
				err = EFAULT;
			}
		}
#ifdef _SYSCALL32
		else {
			struct vtoc32 vtoc32;
			if (ddi_copyin(data, &vtoc32, sizeof (vtoc32), mode)) {
				err = EFAULT;
			} else {
				vtoc32tovtoc(vtoc32, vtoc);
			}
		}
#endif /* _SYSCALL32 */

		if (err == 0) {
			err = stripe_set_vtoc(un, &vtoc);
		}

		return (err);
	}


	case DKIOCGEXTVTOC:
	{
		struct extvtoc	extvtoc;

		if (! (mode & FREAD))
			return (EACCES);

		if ((err = stripe_get_extvtoc(un, &extvtoc)) != 0) {
			return (err);
		}

		if (ddi_copyout(&extvtoc, data, sizeof (extvtoc), mode))
			err = EFAULT;

		return (err);
	}

	case DKIOCSEXTVTOC:
	{
		struct extvtoc	extvtoc;

		if (! (mode & FWRITE))
			return (EACCES);

		if (ddi_copyin(data, &extvtoc, sizeof (extvtoc), mode)) {
			err = EFAULT;
		}

		if (err == 0) {
			err = stripe_set_extvtoc(un, &extvtoc);
		}

		return (err);
	}

	case DKIOCGAPART:
	{
		struct dk_map	dmp;

		if ((err = stripe_get_cgapart(un, &dmp)) != 0) {
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
 * rename named service entry points and support functions
 */

/*
 * rename/exchange role swap functions are handled generically
 */

/*
 * support routine for MDRNM_CHECK
 */
static int
stripe_may_renexch_self(
		ms_unit_t	*un,
		mdi_unit_t	*ui,
		md_rentxn_t	*rtxnp)
{
	minor_t		 from_min;
	minor_t		 to_min;
	bool_t		 toplevel;
	bool_t		 related;

	ASSERT(rtxnp);
	ASSERT((rtxnp->op == MDRNOP_RENAME) || (rtxnp->op == MDRNOP_EXCHANGE));

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
	related  = (!toplevel) && (MD_PARENT(un) == to_min);

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
		 * the device and we return EBUSY.
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
 * Named service entry point: MDRNM_CHECK
 */
intptr_t
stripe_rename_check(
	md_rendelta_t	*delta,
	md_rentxn_t	*rtxnp)
{
	int	err	= 0;

	ASSERT(delta);
	ASSERT(rtxnp);
	ASSERT(delta->unp);
	ASSERT(delta->uip);
	ASSERT((rtxnp->op == MDRNOP_RENAME) || (MDRNOP_EXCHANGE == rtxnp->op));

	if (!delta || !rtxnp || !delta->uip || !delta->unp) {
		(void) mdsyserror(&rtxnp->mde, EINVAL);
		return (EINVAL);
	}

	/* self does additional checks */
	if (delta->old_role == MDRR_SELF) {
		err = stripe_may_renexch_self((ms_unit_t *)delta->unp,
		    delta->uip, rtxnp);
	}
out:
	return (err);
}
/* end of rename/exchange */
