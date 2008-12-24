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

/*
 * Soft partitioning metadevice driver (md_sp), administrative routines.
 *
 * This file contains the administrative routines for the soft partitioning
 * metadevice driver.  All administration is done through the use of ioctl's.
 *
 * The primary ioctl's supported by soft partitions are as follows:
 *
 *	MD_IOCSET	- set up a new soft partition.
 *	MD_IOCGET	- get the unit structure of a soft partition.
 *	MD_IOCRESET	- delete a soft partition.
 *	MD_IOCGROW	- add space to a soft partition.
 *	MD_IOCGETDEVS	- get the device the soft partition is built on.
 *	MD_IOC_SPSTATUS	- set the status (un_status field in the soft
 *			  partition unit structure) for one or more soft
 *			  partitions.
 *
 * Note that, as with other metadevices, the majority of the work for
 * building/growing/deleting soft partitions is performed in userland
 * (specifically in libmeta, see meta_sp.c).  The driver's main administrative
 * function is to maintain the in-core & metadb entries associated with a soft
 * partition.
 *
 * In addition, a few other ioctl's are supported via helper routines in
 * the md driver.  These are:
 *
 *	DKIOCINFO	- get "disk" information.
 *	DKIOCGEOM	- get geometry information.
 *	DKIOCGVTOC	- get vtoc information.
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
#include <sys/lvm/md_sp.h>
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

extern md_ops_t		sp_md_ops;
extern md_krwlock_t	md_unit_array_rw;
extern major_t		md_major;

/*
 * FUNCTION:	sp_getun()
 * INPUT:	mnum	- minor number of soft partition to get.
 * OUTPUT:	mde	- return error pointer.
 * RETURNS:	mp_unit_t *	- ptr to unit structure requested
 *		NULL		- error
 * PURPOSE:	Returns a reference to the soft partition unit structure
 *		indicated by the passed-in minor number.
 */
static mp_unit_t *
sp_getun(minor_t mnum, md_error_t *mde)
{
	mp_unit_t	*un;
	mdi_unit_t	*ui;
	set_t		setno = MD_MIN2SET(mnum);

	/* check set */
	if ((setno >= md_nsets) || (MD_MIN2UNIT(mnum) >= md_nunits)) {
		(void) mdmderror(mde, MDE_INVAL_UNIT, mnum);
		return (NULL);
	}

	if (md_get_setstatus(setno) & MD_SET_STALE) {
		(void) mdmddberror(mde, MDE_DB_STALE, mnum, setno);
		return (NULL);
	}

	ui = MDI_UNIT(mnum);

	if (ui == NULL) {
		(void) mdmderror(mde, MDE_UNIT_NOT_SETUP, mnum);
		return (NULL);
	}

	un = (mp_unit_t *)MD_UNIT(mnum);

	if (un->c.un_type != MD_METASP) {
		(void) mdmderror(mde, MDE_NOT_SP, mnum);
		return (NULL);
	}

	return (un);
}


/*
 * FUNCTION:	sp_setstatus()
 * INPUT:	d	- data ptr passed in from ioctl.
 *		mode	- pass-through to ddi_copyin.
 *		lockp	- lock ptr.
 * OUTPUT:	none.
 * RETURNS:	0		- success.
 *		non-zero	- error.
 * PURPOSE:	Set the status of one or more soft partitions atomically.
 *		this implements the MD_IOC_SPSTATUS ioctl.  Soft partitions
 *		are passed in as an array of minor numbers.  The un_status
 *		field in the unit structure of each soft partition is set to
 *		the status passed in and all unit structures are recommitted
 *		to the metadb at once.
 */
static int
sp_setstatus(void *d, int mode, IOLOCK *lockp)
{
	minor_t		*minors;
	mp_unit_t	*un;
	mddb_recid_t	*recids;
	int		i, nunits, sz;
	int		err = 0;
	sp_status_t	status;
	md_error_t	*mdep;

	md_sp_statusset_t	*msp = (md_sp_statusset_t *)d;

	nunits = msp->num_units;
	sz = msp->size;
	status = msp->new_status;
	mdep = &msp->mde;

	mdclrerror(mdep);
	/* allocate minor number and recids arrays */
	minors = kmem_alloc(sz, KM_SLEEP);
	recids = kmem_alloc((nunits + 1) * sizeof (mddb_recid_t), KM_SLEEP);

	/* copyin minor number array */
	if (err = ddi_copyin((void *)(uintptr_t)msp->minors, minors, sz, mode))
		goto out;

	/* check to make sure all units are valid first */
	for (i = 0; i < nunits; i++) {
		if ((un = sp_getun(minors[i], mdep)) == NULL) {
			err = mdmderror(mdep, MDE_INVAL_UNIT, minors[i]);
			goto out;
		}
	}

	/* update state for all units */
	for (i = 0; i < nunits; i++) {
		un = sp_getun(minors[i], mdep);
		(void) md_ioctl_writerlock(lockp, MDI_UNIT(minors[i]));
		un->un_status = status;
		recids[i] = un->c.un_record_id;
		md_ioctl_writerexit(lockp);
	}

	recids[i] = 0;
	mddb_commitrecs_wrapper(recids);

out:
	kmem_free(minors, sz);
	kmem_free(recids, ((nunits + 1) * sizeof (mddb_recid_t)));
	return (err);
}


/*
 * FUNCTION:	sp_update_watermarks()
 * INPUT:	d	- data ptr passed in from ioctl.
 *		mode	- pass-through to ddi_copyin.
 * OUTPUT:	none.
 * RETURNS:	0		- success.
 *		non-zero	- error.
 * PURPOSE:	This implements the MD_IOC_SPUPDATEWM ioctl.
 *              Watermarks are passed in an array.
 */
static int
sp_update_watermarks(void *d, int mode)
{
	minor_t			mnum;
	set_t			setno;
	md_error_t		*mdep;
	mp_unit_t		*un;
	int			err = 0;
	size_t			wsz;
	size_t			osz;
	mp_watermark_t		*watermarks;
	sp_ext_offset_t		*offsets;
	md_dev64_t		device;
	buf_t			*bp;
	int			i;
	md_sp_update_wm_t	*mup = (md_sp_update_wm_t *)d;
	side_t			side;

	mnum = mup->mnum;
	setno = MD_MIN2SET(mnum);
	side = mddb_getsidenum(setno);
	un = MD_UNIT(mnum);

	if (un == NULL)
		return (EFAULT);

	mdep = &mup->mde;

	mdclrerror(mdep);

	/* Validate the set */
	if ((setno >= md_nsets) || (MD_MIN2UNIT(mnum) >= md_nunits))
		return (mdmderror(mdep, MDE_INVAL_UNIT, mnum));
	if (md_get_setstatus(setno) & MD_SET_STALE)
		return (mdmddberror(mdep, MDE_DB_STALE, mnum, setno));

	wsz = mup->count * sizeof (mp_watermark_t);
	watermarks = kmem_alloc(wsz, KM_SLEEP);

	osz = mup->count * sizeof (sp_ext_offset_t);
	offsets = kmem_alloc(osz, KM_SLEEP);

	/*
	 * Once we're here, we are no longer stateless: we cannot
	 * return without first freeing the watermarks and offset
	 * arrays we just allocated.  So use the "out" label instead
	 * of "return."
	 */

	/* Retrieve the watermark and offset arrays from user land */

	if (ddi_copyin((void *)(uintptr_t)mup->wmp, watermarks, wsz, mode)) {
		err = EFAULT;
		goto out;
	}

	if (ddi_copyin((void *)(uintptr_t)mup->osp, offsets, osz, mode)) {
		err = EFAULT;
		goto out;
	}

	/*
	 * NOTE: For multi-node sets we only commit the watermarks if we are
	 * the master node. This avoids an ioctl-within-ioctl deadlock if the
	 * underlying device is a mirror.
	 */
	if (MD_MNSET_SETNO(setno) && !md_set[setno].s_am_i_master) {
		goto out;
	}

	device = un->un_dev;
	if ((md_getmajor(device) != md_major) &&
	    (md_devid_found(setno, side, un->un_key) == 1)) {
		device = md_resolve_bydevid(mnum, device, un->un_key);
	}
	/*
	 * Flag the fact that we're coming from an ioctl handler to the
	 * underlying device so that it can take appropriate action if needed.
	 * This is necessary for multi-owner mirrors as they may need to
	 * update the metadevice state as a result of the layered open.
	 */
	if (md_layered_open(mnum, &device, MD_OFLG_FROMIOCTL)) {
		err = mdcomperror(mdep, MDE_SP_COMP_OPEN_ERR,
		    mnum, device);
		goto out;
	}

	bp = kmem_alloc(biosize(), KM_SLEEP);
	bioinit(bp);

	for (i = 0; i < mup->count; i++) {

		/*
		 * Even the "constant" fields should be initialized
		 * here, since bioreset() below will clear them.
		 */
		bp->b_flags = B_WRITE;
		bp->b_bcount = sizeof (mp_watermark_t);
		bp->b_bufsize = sizeof (mp_watermark_t);
		bp->b_un.b_addr = (caddr_t)&watermarks[i];
		bp->b_lblkno = offsets[i];
		bp->b_edev = md_dev64_to_dev(device);

		/*
		 * For MN sets only:
		 * Use a special flag MD_STR_WMUPDATE, for the following case:
		 * If the watermarks reside on a mirror disk and a switch
		 * of ownership is triggered by this IO,
		 * the message that is generated by that request must be
		 * processed even if the commd subsystem is currently suspended.
		 *
		 * For non-MN sets or non-mirror metadevices,
		 * this flag has no meaning and is not checked.
		 */

		md_call_strategy(bp, MD_NOBLOCK | MD_STR_WMUPDATE, NULL);

		if (biowait(bp)) {
			err = mdmderror(mdep,
			    MDE_SP_BADWMWRITE, mnum);
			break;
		}

		/* Get the buf_t ready for the next iteration */
		bioreset(bp);
	}

	biofini(bp);
	kmem_free(bp, biosize());

	md_layered_close(device, MD_OFLG_NULL);

out:
	kmem_free(watermarks, wsz);
	kmem_free(offsets, osz);

	return (err);
}


/*
 * FUNCTION:	sp_read_watermark()
 * INPUT:	d	- data ptr passed in from ioctl.
 *		mode	- pass-through to ddi_copyin.
 * OUTPUT:	none.
 * RETURNS:	0		- success.
 *		non-zero	- error.
 * PURPOSE:	This implements the MD_IOC_SPREADWM ioctl.
 */
static int
sp_read_watermark(void *d, int mode)
{
	md_error_t		*mdep;
	mp_watermark_t		watermark;
	md_dev64_t		device;
	buf_t			*bp;
	md_sp_read_wm_t		*mrp = (md_sp_read_wm_t *)d;

	mdep = &mrp->mde;

	mdclrerror(mdep);

	device = mrp->rdev;

	/*
	 * Flag the fact that we are being called from ioctl context so that
	 * the underlying device can take any necessary extra steps to handle
	 * this scenario.
	 */
	if (md_layered_open((minor_t)-1, &device, MD_OFLG_FROMIOCTL)) {
		return (mdcomperror(mdep, MDE_SP_COMP_OPEN_ERR,
		    (minor_t)NODEV, device));
	}

	bp = kmem_alloc(biosize(), KM_SLEEP);
	bioinit(bp);

	bp->b_flags = B_READ;
	bp->b_bcount = sizeof (mp_watermark_t);
	bp->b_bufsize = sizeof (mp_watermark_t);
	bp->b_un.b_addr = (caddr_t)&watermark;
	bp->b_lblkno = mrp->offset;
	bp->b_edev = md_dev64_to_dev(device);

	md_call_strategy(bp, MD_NOBLOCK, NULL);

	if (biowait(bp)) {
		/*
		 * Taking advantage of the knowledge that mdmderror()
		 * returns 0, so we don't really need to keep track of
		 * an error code other than in the error struct.
		 */
		(void) mdmderror(mdep, MDE_SP_BADWMREAD,
		    getminor(device));
	}

	biofini(bp);
	kmem_free(bp, biosize());

	md_layered_close(device, MD_OFLG_NULL);

	if (ddi_copyout(&watermark, (void *)(uintptr_t)mrp->wmp,
	    sizeof (mp_watermark_t), mode)) {
		return (EFAULT);
	}

	return (0);
}


/*
 * FUNCTION:	sp_set()
 * INPUT:	d	- data ptr passed in from ioctl.
 *		mode	- pass-through to ddi_copyin.
 * OUTPUT:	none.
 * RETURNS:	0		- success.
 *		non-zero	- error.
 * PURPOSE:	Create a soft partition.  The unit structure representing
 *		the soft partiton is passed down from userland.  We allocate
 *		a metadb entry, copyin the unit the structure, handle any
 *		metadevice parenting issues, then commit the record to the
 *		metadb.  Once the record is in the metadb, we must also
 *		build the associated in-core structures.  This is done via
 *		sp_build_incore() (see sp.c).
 */
static int
sp_set(void *d, int mode)
{
	minor_t		mnum;
	mp_unit_t	*un;
	void		*rec_addr;
	mddb_recid_t	recids[3];
	mddb_type_t	rec_type;
	int		err;
	set_t		setno;
	md_error_t	*mdep;
	md_unit_t	*child_un;
	md_set_params_t *msp = (md_set_params_t *)d;

	mnum = msp->mnum;
	setno = MD_MIN2SET(mnum);
	mdep = &msp->mde;

	mdclrerror(mdep);

	/* validate set */

	if ((setno >= md_nsets) || (MD_MIN2UNIT(mnum) >= md_nunits))
		return (mdmderror(mdep, MDE_INVAL_UNIT, mnum));
	if (md_get_setstatus(setno) & MD_SET_STALE)
		return (mdmddberror(mdep, MDE_DB_STALE, mnum, setno));

	/* get the record type */
	rec_type = (mddb_type_t)md_getshared_key(setno,
	    sp_md_ops.md_driver.md_drivername);

	/* check if there is already a device with this minor number */
	un = MD_UNIT(mnum);
	if (un != NULL)
		return (mdmderror(mdep, MDE_UNIT_ALREADY_SETUP, mnum));

	/* create the db record for this soft partition */

	if (msp->options & MD_CRO_64BIT) {
#if defined(_ILP32)
		return (mdmderror(mdep, MDE_UNIT_TOO_LARGE, mnum));
#else
		recids[0] = mddb_createrec((size_t)msp->size, rec_type, 0,
		    MD_CRO_64BIT | MD_CRO_SOFTPART | MD_CRO_FN, setno);
#endif
	} else {
		recids[0] = mddb_createrec((size_t)msp->size, rec_type, 0,
		    MD_CRO_32BIT | MD_CRO_SOFTPART | MD_CRO_FN, setno);
	}
	/* set initial value for possible child record */
	recids[1] = 0;
	if (recids[0] < 0)
		return (mddbstatus2error(mdep, recids[0], mnum, setno));

	/* get the address of the soft partition db record */
	rec_addr = (void *) mddb_getrecaddr(recids[0]);

	/*
	 * at this point we can happily mess with the soft partition
	 * db record since we haven't committed it to the metadb yet.
	 * if we crash before we commit, the uncommitted record will be
	 * automatically purged.
	 */

	/* copy in the user's soft partition unit struct */
	if (err = ddi_copyin((void *)(uintptr_t)msp->mdp,
	    rec_addr, (size_t)msp->size, mode)) {
		mddb_deleterec_wrapper(recids[0]);
		return (EFAULT);
	}

	/* fill in common unit structure fields which aren't set in userland */
	un = (mp_unit_t *)rec_addr;

	/* All 64 bit metadevices only support EFI labels. */
	if (msp->options & MD_CRO_64BIT) {
		un->c.un_flag |= MD_EFILABEL;
	}

	MD_SID(un) = mnum;
	MD_RECID(un) = recids[0];
	MD_PARENT(un) = MD_NO_PARENT;
	un->c.un_revision |= MD_FN_META_DEV;

	/* if we are parenting a metadevice, set our child's parent field */
	if (md_getmajor(un->un_dev) == md_major) {
		/* it's a metadevice, need to parent it */
		child_un = MD_UNIT(md_getminor(un->un_dev));
		if (child_un == NULL) {
			mddb_deleterec_wrapper(recids[0]);
			return (mdmderror(mdep, MDE_INVAL_UNIT,
			    md_getminor(un->un_dev)));
		}
		md_set_parent(un->un_dev, MD_SID(un));

		/* set child recid and recids end marker */
		recids[1] = MD_RECID(child_un);
		recids[2] = 0;
	}

	/*
	 * build the incore structures.
	 */
	if (err = sp_build_incore(rec_addr, 0)) {
		md_nblocks_set(mnum, -1ULL);
		MD_UNIT(mnum) = NULL;

		mddb_deleterec_wrapper(recids[0]);
		return (err);
	}

	/*
	 * Update unit availability
	 */
	md_set[setno].s_un_avail--;

	/*
	 * commit the record.
	 * if we had to update a child record, it will get commited
	 * as well.
	 */
	mddb_commitrecs_wrapper(recids);

	/* create the mdi_unit struct for this soft partition */
	md_create_unit_incore(mnum, &sp_md_ops, 0);

	SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_CREATE, TAG_METADEVICE, MD_UN2SET(un),
	    MD_SID(un));
	return (0);
}


/*
 * FUNCTION:	sp_get()
 * INPUT:	d	- data ptr.
 *		mode	- pass-through to ddi_copyout.
 *		lock	- lock ptr.
 * OUTPUT:	none.
 * RETURNS:	0		- success.
 *		non-zero	- error.
 * PURPOSE:	Get the soft partition unit structure specified by the
 *		minor number.  the in-core unit structure is obtained
 *		and copied into the md_i_get structure passed down from
 *		userland.
 */
static int
sp_get(void *d, int mode, IOLOCK *lock)
{
	minor_t		mnum;
	mdi_unit_t	*ui;
	mp_unit_t	*un;
	md_error_t	*mdep;
	md_i_get_t	*migp = d;


	mnum = migp->id;
	mdep = &migp->mde;

	mdclrerror(mdep);

	/* make sure this is a valid unit structure */
	if ((MD_MIN2SET(mnum) >= md_nsets) || (MD_MIN2UNIT(mnum) >= md_nunits))
		return (mdmderror(mdep, MDE_INVAL_UNIT, mnum));

	/* get the mdi_unit */
	if ((ui = MDI_UNIT(mnum)) == NULL) {
		return (mdmderror(mdep, MDE_UNIT_NOT_SETUP, mnum));
	}

	/*
	 * md_ioctl_readerlock returns a reference to the in-core
	 * unit structure.  this lock will be dropped by
	 * md_ioctl_lock_exit() before the ioctl returns.
	 */
	un = (mp_unit_t *)md_ioctl_readerlock(lock, ui);

	/* verify the md_i_get structure */
	if (migp->size == 0) {
		migp->size = un->c.un_size;
		return (0);
	}
	if (migp->size < un->c.un_size) {
		return (EFAULT);
	}

	/* copyout unit */
	if (ddi_copyout(un, (void *)(uintptr_t)migp->mdp,
	    un->c.un_size, mode))
		return (EFAULT);
	return (0);
}


/*
 * FUNCTION:	sp_reset()
 * INPUT:	reset_params	- soft partitioning reset parameters.
 * OUTPUT:	none.
 * RETURNS:	0		- success.
 *		non-zero	- error.
 * PURPOSE:	Do the setup work needed to delete a soft partition.
 *		note that the actual removal of both in-core and metadb
 *		structures is done in the reset_sp() routine (see sp.c).
 *		In addition, since multiple soft partitions may exist
 *		on top of a single metadevice, the soft partition reset
 *		parameters (md_sp_reset_t) contains information about
 *		how the soft partition should deparent/reparent the
 *		underlying metadevice.  If the underlying metadevice is
 *		to be deparented, the new_parent field will be MD_NO_PARENT,
 *		otherwise it will be contain the minor number of another
 *		soft partition built on top of the underlying metadevice.
 */
static int
sp_reset(md_sp_reset_t *softp)
{
	minor_t		mnum = softp->mnum;
	mdi_unit_t	*ui;
	mp_unit_t	*un;
	md_unit_t	*child_un;
	set_t		setno = MD_MIN2SET(mnum);

	mdclrerror(&softp->mde);

	/* get the unit structure */
	if ((un = sp_getun(mnum, &softp->mde)) == NULL) {
		return (mdmderror(&softp->mde, MDE_INVAL_UNIT, mnum));
	}

	/* don't delete if we have a parent */
	if (MD_HAS_PARENT(un->c.un_parent)) {
		return (mdmderror(&softp->mde, MDE_IN_USE, mnum));
	}

	rw_enter(&md_unit_array_rw.lock, RW_WRITER);

	ui = MDI_UNIT(mnum);
	(void) md_unit_openclose_enter(ui);

	/* don't delete if we are currently open */
	if (md_unit_isopen(ui)) {
		md_unit_openclose_exit(ui);
		rw_exit(&md_unit_array_rw.lock);
		return (mdmderror(&softp->mde, MDE_IS_OPEN, mnum));
	}

	md_unit_openclose_exit(ui);

	/*
	 * if we are built on metadevice, we need to deparent
	 * or reparent that metadevice.
	 */
	if (md_getmajor(un->un_dev) == md_major) {
		child_un = MD_UNIT(md_getminor(un->un_dev));
		md_set_parent(un->un_dev, softp->new_parent);
		mddb_commitrec_wrapper(MD_RECID(child_un));
	}
	/* remove the soft partition */
	reset_sp(un, mnum, 1);

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
		md_upd_set_unnext(setno, MD_MIN2UNIT(mnum));
	}

	/* release locks and return */
out:
	rw_exit(&md_unit_array_rw.lock);
	return (0);
}


/*
 * FUNCTION:	sp_grow()
 * INPUT:	d	- data ptr.
 *		mode	- pass-through to ddi_copyin.
 *		lockp	- lock ptr.
 * OUTPUT:	none.
 * RETURNS:	0		- success.
 *		non-zero	- error.
 * PURPOSE:	Attach more space to a soft partition.  We are passed in
 *		a new unit structure with the new extents and other updated
 *		information.  The new unit structure essentially replaces
 *		the old unit for this soft partition.  We place the new
 *		unit into the metadb, delete the old metadb record, and
 *		then update the in-core unit structure array to point to
 *		the new unit.
 */
static int
sp_grow(void *d, int mode, IOLOCK *lockp)
{
	minor_t		mnum;
	mp_unit_t	*un, *new_un;
	mdi_unit_t	*ui;
	minor_t		*par = NULL;
	IOLOCK		*plock = NULL;
	int		i;
	mddb_recid_t	recid;
	mddb_type_t	rec_type;
	mddb_recid_t	old_vtoc = 0;
	md_create_rec_option_t options;
	int		err;
	int		rval = 0;
	set_t		setno;
	md_error_t	*mdep;
	int		npar;
	md_grow_params_t *mgp = (md_grow_params_t *)d;

	mnum = mgp->mnum;
	mdep = &mgp->mde;
	setno = MD_MIN2SET(mnum);
	npar = mgp->npar;

	mdclrerror(mdep);

	/* validate set */
	if ((setno >= md_nsets) || (MD_MIN2UNIT(mnum) >= md_nunits))
		return (mdmderror(mdep, MDE_INVAL_UNIT, mnum));
	if (md_get_setstatus(setno) & MD_SET_STALE)
		return (mdmddberror(mdep, MDE_DB_STALE, mnum, setno));

	/* make sure this soft partition already exists */
	ui = MDI_UNIT(mnum);
	if (ui == NULL)
		return (mdmderror(mdep, MDE_UNIT_NOT_SETUP, mnum));

	/* handle any parents */
	if (npar >= 1) {
		ASSERT((minor_t *)(uintptr_t)mgp->par != NULL);
		par = kmem_alloc(npar * sizeof (*par), KM_SLEEP);
		plock = kmem_alloc(npar * sizeof (*plock), KM_SLEEP);
		if (ddi_copyin((void *)(uintptr_t)mgp->par, par,
		    (npar * sizeof (*par)), mode) != 0) {
			kmem_free(par, npar * sizeof (*par));
			kmem_free(plock, npar * sizeof (*plock));
			return (EFAULT);
		}
	}

	/*
	 * handle parent locking.  grab the unit writer lock,
	 * then all parent ioctl locks, and then finally our own.
	 * parents should be sorted to avoid deadlock.
	 */
	rw_enter(&md_unit_array_rw.lock, RW_WRITER);
	for (i = 0; i < npar; ++i) {
		(void) md_ioctl_writerlock(&plock[i],
		    MDI_UNIT(par[i]));
	}
	un = (mp_unit_t *)md_ioctl_writerlock(lockp, ui);

	rec_type = (mddb_type_t)md_getshared_key(setno,
	    sp_md_ops.md_driver.md_drivername);

	/*
	 * Preserve the friendly name nature of the unit that is growing.
	 */
	options = MD_CRO_SOFTPART;
	if (un->c.un_revision & MD_FN_META_DEV)
		options |= MD_CRO_FN;
	if (mgp->options & MD_CRO_64BIT) {
#if defined(_ILP32)
		rval = mdmderror(mdep, MDE_UNIT_TOO_LARGE, mnum);
		goto out;
#else
		recid = mddb_createrec((size_t)mgp->size, rec_type, 0,
		    MD_CRO_64BIT | options, setno);
#endif
	} else {
		recid = mddb_createrec((size_t)mgp->size, rec_type, 0,
		    MD_CRO_32BIT | options, setno);
	}
	if (recid < 0) {
		rval = mddbstatus2error(mdep, (int)recid, mnum, setno);
		goto out;
	}

	/* get the address of the new unit */
	new_un = (mp_unit_t *)mddb_getrecaddr(recid);

	/* copy in the user's unit struct */
	err = ddi_copyin((void *)(uintptr_t)mgp->mdp, new_un,
	    (size_t)mgp->size, mode);
	if (err) {
		mddb_deleterec_wrapper(recid);
		rval = EFAULT;
		goto out;
	}
	if (options & MD_CRO_FN)
		new_un->c.un_revision |= MD_FN_META_DEV;

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

	/* commit new unit struct */
	MD_RECID(new_un) = recid;
	mddb_commitrec_wrapper(recid);

	/*
	 * delete old unit struct.
	 */
	mddb_deleterec_wrapper(MD_RECID(un));

	/* place new unit in in-core array */
	md_nblocks_set(mnum, new_un->c.un_total_blocks);
	MD_UNIT(mnum) = new_un;

	SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_GROW, TAG_METADEVICE,
	    MD_UN2SET(new_un), MD_SID(new_un));

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

/*
 * FUNCTION:	sp_getdevs()
 * INPUT:	d	- data ptr.
 *		mode	- pass-through to ddi_copyout.
 *		lockp	- lock ptr.
 * OUTPUT:	none.
 * RETURNS:	0		- success.
 *		non-zero	- error.
 * PURPOSE:	Get the device on which the soft partition is built.
 *		This is simply a matter of copying out the md_dev64_t stored
 *		in the soft partition unit structure.
 */
static int
sp_getdevs(
	void			*d,
	int			mode,
	IOLOCK			*lockp
)
{
	minor_t			mnum;
	mdi_unit_t		*ui;
	mp_unit_t		*un;
	md_error_t		*mdep;
	md_dev64_t		*devsp;
	md_dev64_t		unit_dev;
	md_getdevs_params_t	*mgdp = (md_getdevs_params_t *)d;


	mnum = mgdp->mnum;
	mdep = &(mgdp->mde);

	mdclrerror(mdep);

	/* check set */
	if ((MD_MIN2SET(mnum) >= md_nsets) || (MD_MIN2UNIT(mnum) >= md_nunits))
		return (mdmderror(mdep, MDE_INVAL_UNIT, mnum));
	/* check unit */
	if ((ui = MDI_UNIT(mnum)) == NULL) {
		return (mdmderror(mdep, MDE_UNIT_NOT_SETUP, mnum));
	}
	/* get unit */
	un = (mp_unit_t *)md_ioctl_readerlock(lockp, ui);
	devsp = (md_dev64_t *)(uintptr_t)mgdp->devs;

	/* only ever 1 device for a soft partition */
	if (mgdp->cnt != 0) {
		/* do miniroot->target device translation */
		unit_dev = un->un_dev;
		if (md_getmajor(unit_dev) != md_major) {
			if ((unit_dev = md_xlate_mini_2_targ(unit_dev))
			    == NODEV64)
				return (ENODEV);
		}
		/* copyout dev information */
		if (ddi_copyout(&unit_dev, devsp, sizeof (*devsp), mode) != 0)
			return (EFAULT);
	}
	mgdp->cnt = 1;

	return (0);
}

/*
 * sp_set_capability:
 * ------------------
 * Called to set or clear a capability for a softpart
 * called by the MD_MN_SET_CAP ioctl.
 */
static int
sp_set_capability(md_mn_setcap_params_t *p, IOLOCK *lockp)
{
	set_t		setno;
	mdi_unit_t	*ui;
	mp_unit_t	*un;
	int		err = 0;

	if ((un = sp_getun(p->mnum, &p->mde)) == NULL)
		return (EINVAL);

	/* This function is only valid for a multi-node set */
	setno = MD_MIN2SET(p->mnum);
	if (!MD_MNSET_SETNO(setno)) {
		return (EINVAL);
	}
	ui = MDI_UNIT(p->mnum);
	(void) md_ioctl_readerlock(lockp, ui);

	if (p->sc_set & DKV_ABR_CAP) {
		void (*inc_abr_count)();

		ui->ui_tstate |= MD_ABR_CAP; /* Set ABR capability */
		/* Increment abr count in underlying metadevice */
		inc_abr_count = (void(*)())md_get_named_service(un->un_dev,
		    0, MD_INC_ABR_COUNT, 0);
		if (inc_abr_count != NULL)
			(void) (*inc_abr_count)(un->un_dev);
	} else {
		void (*dec_abr_count)();

		ui->ui_tstate &= ~MD_ABR_CAP; /* Clear ABR capability */
		/* Decrement abr count in underlying metadevice */
		dec_abr_count = (void(*)())md_get_named_service(un->un_dev,
		    0, MD_DEC_ABR_COUNT, 0);
		if (dec_abr_count != NULL)
			(void) (*dec_abr_count)(un->un_dev);
	}
	if (p->sc_set & DKV_DMR_CAP) {
		ui->ui_tstate |= MD_DMR_CAP; /* Set DMR capability */
	} else {
		ui->ui_tstate &= ~MD_DMR_CAP; /* Clear DMR capability */
	}
	md_ioctl_readerexit(lockp);
	return (err);
}


/*
 * FUNCTION:	sp_admin_ioctl().
 * INPUT:	cmd	- ioctl to be handled.
 *		data	- data ptr.
 *		mode	- pass-through to copyin/copyout routines.
 *		lockp	- lock ptr.
 * OUTPUT:	none.
 * RETURNS:	0		- success.
 *		non-zero	- error.
 * PURPOSE:	Handle administrative ioctl's.  Essentially a large
 *		switch statement to dispatch the ioctl's to their
 *		handlers.  See comment at beginning of file for specifics
 *		on which ioctl's are handled.
 */
static int
sp_admin_ioctl(int cmd, void *data, int mode, IOLOCK *lockp)
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
		/* create new soft partition */
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (md_set_params_t);

		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = sp_set(d, mode);
		break;
	}

	case MD_IOCGET:
	{
		/* get soft partition unit structure */
		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (md_i_get_t);

		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = sp_get(d, mode, lockp);
		break;
	}
	case MD_IOCRESET:
	{
		/* delete soft partition */
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (md_sp_reset_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = sp_reset((md_sp_reset_t *)d);
		break;
	}

	case MD_IOCGROW:
	{
		/* grow soft partition */
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (md_grow_params_t);
		d  = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = sp_grow(d, mode, lockp);
		break;
	}

	case MD_IOCGET_DEVS:
	{
		/* get underlying device */
		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (md_getdevs_params_t);
		d  = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = sp_getdevs(d, mode, lockp);
		break;
	}

	case MD_IOC_SPSTATUS:
	{
		/* set the status field of one or more soft partitions */
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (md_sp_statusset_t);
		d  = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = sp_setstatus(d, mode, lockp);
		break;
	}

	case MD_IOC_SPUPDATEWM:
	case MD_MN_IOC_SPUPDATEWM:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (md_sp_update_wm_t);
		d  = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = sp_update_watermarks(d, mode);
		break;
	}

	case MD_IOC_SPREADWM:
	{
		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (md_sp_read_wm_t);
		d  = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = sp_read_watermark(d, mode);
		break;
	}

	case MD_MN_SET_CAP:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (md_mn_setcap_params_t);
		d  = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = sp_set_capability((md_mn_setcap_params_t *)d, lockp);
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
 * FUNCTION:	md_sp_ioctl()
 * INPUT:	dev	- device we are operating on.
 *		cmd	- ioctl to be handled.
 *		data	- data ptr.
 *		mode	- pass-through to copyin/copyout routines.
 *		lockp	- lock ptr.
 * OUTPUT:	none.
 * RETURNS:	0		- success.
 *		non-zero	- error.
 * PURPOSE:	Dispatch ioctl's.  Administrative ioctl's are handled
 *		by sp_admin_ioctl.  All others (see comment at beginning
 *		of this file) are handled in-line here.
 */
int
md_sp_ioctl(dev_t dev, int cmd, void *data, int mode, IOLOCK *lockp)
{
	minor_t		mnum = getminor(dev);
	mp_unit_t	*un;
	mdi_unit_t	*ui;
	int		err = 0;

	/* handle admin ioctls */
	if (mnum == MD_ADM_MINOR)
		return (sp_admin_ioctl(cmd, data, mode, lockp));

	/* check unit */
	if ((MD_MIN2SET(mnum) >= md_nsets) ||
	    (MD_MIN2UNIT(mnum) >= md_nunits) ||
	    ((ui = MDI_UNIT(mnum)) == NULL) ||
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
		/* "disk" info */
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
		/* geometry information */
		struct dk_geom		*p;

		if (! (mode & FREAD))
			return (EACCES);

		p = kmem_alloc(sizeof (*p), KM_SLEEP);

		md_get_geom((md_unit_t *)un, p);
		if (ddi_copyout((caddr_t)p, data, sizeof (*p),
		    mode) != 0)
			err = EFAULT;

		kmem_free(p, sizeof (*p));
		return (err);
	}
	case DKIOCGAPART:
	{
		struct dk_map	dmp;

		err = 0;
		md_get_cgapart((md_unit_t *)un, &dmp);

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
	case DKIOCGVTOC:
	{
		/* vtoc information */
		struct vtoc	vtoc;

		if (! (mode & FREAD))
			return (EACCES);

		md_get_vtoc((md_unit_t *)un, &vtoc);

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

		if (err == 0)
			err = md_set_vtoc((md_unit_t *)un, &vtoc);

		return (err);
	}

	case DKIOCGEXTVTOC:
	{
		/* extended vtoc information */
		struct extvtoc	extvtoc;

		if (! (mode & FREAD))
			return (EACCES);

		md_get_extvtoc((md_unit_t *)un, &extvtoc);

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

		if (err == 0)
			err = md_set_extvtoc((md_unit_t *)un, &extvtoc);

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

	case DKIOCGETVOLCAP:
	{
		/*
		 * Return the supported capabilities for the soft-partition.
		 * We can only support those caps that are provided by the
		 * underlying device.
		 */

		volcap_t	vc;

		if (!MD_MNSET_SETNO(MD_MIN2SET(mnum)))
			return (EINVAL);

		if (! (mode & FREAD))
			return (EACCES);

		bzero(&vc, sizeof (vc));

		/* Send ioctl to underlying driver */

		err = md_call_ioctl(un->un_dev, cmd, &vc, (mode | FKIOCTL),
		    lockp);

		if (err == 0)
			ui->ui_capab = vc.vc_info;

		if (ddi_copyout(&vc, data, sizeof (vc), mode))
			err = EFAULT;

		return (err);
	}

	case DKIOCSETVOLCAP:
	{
		/*
		 * Enable a supported capability (as returned by DKIOCGETVOLCAP)
		 * Do not pass the request down as we're the top-level device
		 * handler for the application.
		 * If the requested capability is supported (set in ui_capab),
		 * set the corresponding bit in ui_tstate so that we can pass
		 * the appropriate flag when performing i/o.
		 * This request is propagated to all nodes.
		 */
		volcap_t	vc, vc1;
		volcapset_t	volcap = 0;
		void 		(*check_offline)();
		int		offline_status = 0;

		if (!MD_MNSET_SETNO(MD_MIN2SET(mnum)))
			return (EINVAL);

		if (! (mode & FWRITE))
			return (EACCES);

		if (ddi_copyin(data, &vc, sizeof (vc), mode))
			return (EFAULT);

		/*
		 * Send DKIOCGETVOLCAP to underlying driver to see if
		 * capability supported
		 */

		vc1.vc_info = 0;
		err = md_call_ioctl(un->un_dev, DKIOCGETVOLCAP, &vc1,
		    (mode | FKIOCTL), lockp);
		if (err != 0)
			return (err);

		/* Save capabilities */
		ui->ui_capab = vc1.vc_info;
		/*
		 * Error if required capability not supported by underlying
		 * driver
		 */
		if ((vc1.vc_info & vc.vc_set) == 0)
			return (ENOTSUP);


		/*
		 * Check if underlying mirror has an offline submirror,
		 * fail if there is on offline submirror
		 */
		check_offline = (void(*)())md_get_named_service(un->un_dev,
		    0, MD_CHECK_OFFLINE, 0);
		if (check_offline != NULL)
			(void) (*check_offline)(un->un_dev, &offline_status);
		if (offline_status)
			return (EINVAL);

		if (ui->ui_tstate & MD_ABR_CAP)
			volcap |= DKV_ABR_CAP;

		/* Only send capability message if there is a change */
		if ((vc.vc_set & (DKV_ABR_CAP)) != volcap)
			err = mdmn_send_capability_message(mnum, vc, lockp);
		return (err);
	}

	case DKIOCDMR:
	{
		/*
		 * Only valid for MN sets. We need to pass it down to the
		 * underlying driver if its a metadevice, after we've modified
		 * the offsets to pick up the correct lower-level device
		 * position.
		 */
		vol_directed_rd_t	*vdr;
#ifdef _MULTI_DATAMODEL
		vol_directed_rd32_t	*vdr32;
#endif	/* _MULTI_DATAMODEL */

		if (!MD_MNSET_SETNO(MD_MIN2SET(mnum)))
			return (EINVAL);

		if (! (ui->ui_capab & DKV_DMR_CAP))
			return (EINVAL);

		vdr = kmem_zalloc(sizeof (vol_directed_rd_t), KM_NOSLEEP);
		if (vdr == NULL)
			return (ENOMEM);

		/*
		 * Underlying device supports directed mirror read, so update
		 * the user-supplied offset to pick the correct block from the
		 * partitioned metadevice.
		 */
#ifdef _MULTI_DATAMODEL
		vdr32 = kmem_zalloc(sizeof (vol_directed_rd32_t), KM_NOSLEEP);
		if (vdr32 == NULL) {
			kmem_free(vdr, sizeof (vol_directed_rd_t));
			return (ENOMEM);
		}

		switch (ddi_model_convert_from(mode & FMODELS)) {
		case DDI_MODEL_ILP32:
			if (ddi_copyin(data, vdr32, sizeof (*vdr32), mode)) {
				kmem_free(vdr, sizeof (*vdr));
				return (EFAULT);
			}
			vdr->vdr_flags = vdr32->vdr_flags;
			vdr->vdr_offset = vdr32->vdr_offset;
			vdr->vdr_nbytes = vdr32->vdr_nbytes;
			vdr->vdr_data = (void *)(uintptr_t)vdr32->vdr_data;
			vdr->vdr_side = vdr32->vdr_side;
			break;

		case DDI_MODEL_NONE:
			if (ddi_copyin(data, vdr, sizeof (*vdr), mode)) {
				kmem_free(vdr32, sizeof (*vdr32));
				kmem_free(vdr, sizeof (*vdr));
				return (EFAULT);
			}
			break;

		default:
			kmem_free(vdr32, sizeof (*vdr32));
			kmem_free(vdr, sizeof (*vdr));
			return (EFAULT);
		}
#else	/* ! _MULTI_DATAMODEL */
		if (ddi_copyin(data, vdr, sizeof (*vdr), mode)) {
			kmem_free(vdr, sizeof (*vdr));
			return (EFAULT);
		}
#endif	/* _MULTI_DATA_MODEL */

		err = sp_directed_read(mnum, vdr, mode);


#ifdef _MULTI_DATAMODEL
		switch (ddi_model_convert_from(mode & FMODELS)) {
		case DDI_MODEL_ILP32:
			vdr32->vdr_flags = vdr->vdr_flags;
			vdr32->vdr_offset = vdr->vdr_offset;
			vdr32->vdr_side = vdr->vdr_side;
			vdr32->vdr_bytesread = vdr->vdr_bytesread;
			bcopy(vdr->vdr_side_name, vdr32->vdr_side_name,
			    sizeof (vdr32->vdr_side_name));

			if (ddi_copyout(vdr32, data, sizeof (*vdr32), mode))
				err = EFAULT;
			break;

		case DDI_MODEL_NONE:
			if (ddi_copyout(&vdr, data, sizeof (vdr), mode))
				err = EFAULT;
			break;
		}
#else	/* ! _MULTI_DATA_MODEL */
		if (ddi_copyout(&vdr, data, sizeof (vdr), mode))
			err = EFAULT;
#endif	/* _MULTI_DATA_MODEL */

#ifdef _MULTI_DATAMODEL
		kmem_free(vdr32, sizeof (*vdr32));
#endif	/* _MULTI_DATAMODEL */
		kmem_free(vdr, sizeof (*vdr));

		return (err);
	}

	}

	/* Option not handled */
	return (ENOTTY);
}
