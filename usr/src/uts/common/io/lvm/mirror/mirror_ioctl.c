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
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>

#include <sys/lvm/mdvar.h>
#include <sys/lvm/md_names.h>
#include <sys/lvm/md_mddb.h>
#include <sys/lvm/md_stripe.h>
#include <sys/lvm/md_mirror.h>

#include <sys/model.h>

#include <sys/sysevent/eventdefs.h>
#include <sys/sysevent/svm.h>
#include <sys/lvm/mdmn_commd.h>

extern int		md_status;
extern kmutex_t		md_mx;
extern kcondvar_t	md_cv;

extern unit_t		md_nunits;
extern set_t		md_nsets;
extern md_set_t		md_set[];

extern md_ops_t		mirror_md_ops;
extern int		md_ioctl_cnt;
extern md_krwlock_t	md_unit_array_rw;
extern major_t		md_major;
extern mdq_anchor_t	md_ff_daemonq;
extern void		md_probe_one(probe_req_t *);
extern void		mirror_openfail_console_info(mm_unit_t *, int, int);

#ifdef DEBUG
extern int		mirror_debug_flag;
#endif

static void
mirror_resume_writes(mm_unit_t *un)
{
	/*
	 * Release the block on writes to the mirror and resume any blocked
	 * resync thread.
	 * This is only required for MN sets
	 */
	if (MD_MNSET_SETNO(MD_UN2SET(un))) {
#ifdef DEBUG
		if (mirror_debug_flag)
			printf("mirror_resume_writes: mnum %x\n", MD_SID(un));
#endif
		mutex_enter(&un->un_suspend_wr_mx);
		un->un_suspend_wr_flag = 0;
		cv_broadcast(&un->un_suspend_wr_cv);
		mutex_exit(&un->un_suspend_wr_mx);
		mutex_enter(&un->un_rs_thread_mx);
		un->un_rs_thread_flags &= ~MD_RI_BLOCK;
		cv_signal(&un->un_rs_thread_cv);
		mutex_exit(&un->un_rs_thread_mx);
	}
}

mm_unit_t *
mirror_getun(minor_t mnum, md_error_t *mde, int flags, IOLOCK *lock)
{
	mm_unit_t	*un;
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
		return ((mm_unit_t *)1);
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
		if (flags & WR_LOCK)
			(void) md_ioctl_writerlock(lock, ui);
		else /* RD_LOCK */
			(void) md_ioctl_readerlock(lock, ui);
	}
	un = (mm_unit_t *)MD_UNIT(mnum);

	if (un->c.un_type != MD_METAMIRROR) {
		(void) mdmderror(mde, MDE_NOT_MM, mnum);
		return (NULL);
	}

	return (un);
}

static int
mirror_set(
	void		*d,
	int		mode
)
{
	minor_t		mnum;
	mm_unit_t	*un;
	mddb_recid_t	recid;
	mddb_type_t	typ1;
	int		err;
	int		i;
	set_t		setno;
	md_set_params_t	*msp = d;


	mnum = msp->mnum;

	mdclrerror(&msp->mde);

	if (mirror_getun(mnum, &msp->mde, NO_OLD, NULL) == NULL)
		return (0);

	setno = MD_MIN2SET(mnum);

	typ1 = (mddb_type_t)md_getshared_key(setno,
	    mirror_md_ops.md_driver.md_drivername);

	/*
	 * Create the db record for this mdstruct
	 * We don't store incore elements ondisk
	 */

	if (msp->options & MD_CRO_64BIT) {
#if defined(_ILP32)
		return (mdmderror(&msp->mde, MDE_UNIT_TOO_LARGE, mnum));
#else
		recid = mddb_createrec((size_t)msp->size, typ1, MIRROR_REC,
		    MD_CRO_64BIT | MD_CRO_MIRROR | MD_CRO_FN, setno);
#endif
	} else {
		/*
		 * It's important to use the correct size here
		 */
		msp->size = sizeof (mm_unit32_od_t);
		recid = mddb_createrec((size_t)msp->size, typ1, MIRROR_REC,
		    MD_CRO_32BIT | MD_CRO_MIRROR | MD_CRO_FN, setno);
	}
	if (recid < 0)
		return (mddbstatus2error(&msp->mde, (int)recid,
		    mnum, setno));

	/* Resize to include incore fields */
	un = (mm_unit_t *)mddb_getrecaddr_resize(recid, sizeof (*un), 0);
	/*
	 * It is okay that we muck with the mdstruct here,
	 * since no one else will know about the mdstruct
	 * until we commit it. If we crash, the record will
	 * be automatically purged, since we haven't
	 * committed it yet.
	 */

	/* copy in the user's mdstruct */
	if (err = ddi_copyin((caddr_t)(uintptr_t)msp->mdp, un,
	    (uint_t)msp->size, mode)) {
		mddb_deleterec_wrapper(recid);
		return (EFAULT);
	}
	/* All 64 bit metadevices only support EFI labels. */
	if (msp->options & MD_CRO_64BIT) {
		un->c.un_flag |= MD_EFILABEL;
	}

	un->c.un_revision |= MD_FN_META_DEV;
	MD_RECID(un)	= recid;
	MD_CAPAB(un)	= MD_CAN_PARENT | MD_CAN_META_CHILD | MD_CAN_SP;
	MD_PARENT(un)	= MD_NO_PARENT;

	for (i = 0; i < NMIRROR; i++) {
		struct mm_submirror	*sm;

		sm = &un->un_sm[i];
		if (!SMS_IS(sm, SMS_INUSE))
			continue;

		/* ensure that the submirror is a metadevice */
		if (md_getmajor(sm->sm_dev) != md_major)
			return (mdmderror(&msp->mde, MDE_INVAL_UNIT,
			    md_getminor(sm->sm_dev)));

		if (md_get_parent(sm->sm_dev) == MD_NO_PARENT)
			continue;

		/* mirror creation should fail here */
		md_nblocks_set(mnum, -1ULL);
		MD_UNIT(mnum) = NULL;

		mddb_deleterec_wrapper(recid);
		return (mdmderror(&msp->mde, MDE_IN_USE,
		    md_getminor(sm->sm_dev)));
	}

	if (err = mirror_build_incore(un, 0)) {
		md_nblocks_set(mnum, -1ULL);
		MD_UNIT(mnum) = NULL;

		mddb_deleterec_wrapper(recid);
		return (err);
	}

	/*
	 * Update unit availability
	 */
	md_set[setno].s_un_avail--;

	mirror_commit(un, ALL_SUBMIRRORS, 0);
	md_create_unit_incore(MD_SID(un), &mirror_md_ops, 0);
	mirror_check_failfast(mnum);
	SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_CREATE, SVM_TAG_METADEVICE, setno,
	    MD_SID(un));

	resync_start_timeout(setno);
	return (0);
}

static int
mirror_get(
	void		*migp,
	int		mode,
	IOLOCK		*lock
)
{
	mm_unit_t	*un;
	md_i_get_t	*migph = migp;

	mdclrerror(&migph->mde);

	if ((un = mirror_getun(migph->id, &migph->mde, RD_LOCK, lock)) == NULL)
		return (0);

	if (migph->size == 0) {
		migph->size = un->c.un_size;
		return (0);
	}

	if (migph->size < un->c.un_size) {
		return (EFAULT);
	}
	if (ddi_copyout(un, (caddr_t)(uintptr_t)migph->mdp,
	    un->c.un_size, mode))
		return (EFAULT);
	return (0);
}

static int
mirror_getdevs(
	void			*mgdp,
	int			mode,
	IOLOCK			*lock
)
{
	mm_unit_t		*un;
	md_dev64_t		*udevs;
	int			cnt;
	int			i;
	md_dev64_t		unit_dev;
	md_getdevs_params_t	*mgdph = mgdp;


	mdclrerror(&mgdph->mde);

	if ((un = mirror_getun(mgdph->mnum,
	    &mgdph->mde, RD_LOCK, lock)) == NULL)
		return (0);

	udevs = (md_dev64_t *)(uintptr_t)mgdph->devs;

	for (cnt = 0, i = 0; i < NMIRROR; i++) {
		if (!SMS_BY_INDEX_IS(un, i, SMS_INUSE))
			continue;
		if (cnt < mgdph->cnt) {
			unit_dev = un->un_sm[i].sm_dev;
			if (md_getmajor(unit_dev) != md_major) {
				unit_dev = md_xlate_mini_2_targ(unit_dev);
				if (unit_dev == NODEV64)
					return (ENODEV);
			}

			if (ddi_copyout((caddr_t)&unit_dev, (caddr_t)udevs,
			    sizeof (*udevs), mode) != 0)
				return (EFAULT);
			++udevs;
		}
		++cnt;
	}

	mgdph->cnt = cnt;
	return (0);
}

static int
mirror_reset(
	md_i_reset_t	*mirp
)
{
	minor_t		mnum = mirp->mnum;
	mm_unit_t	*un;
	mdi_unit_t	*ui;
	set_t		setno = MD_MIN2SET(mnum);

	mdclrerror(&mirp->mde);

	if ((un = mirror_getun(mnum, &mirp->mde, NO_LOCK, NULL)) == NULL)
		return (0);

	if (MD_HAS_PARENT(un->c.un_parent)) {
		return (mdmderror(&mirp->mde, MDE_IN_USE, mnum));
	}

	rw_enter(&md_unit_array_rw.lock, RW_WRITER);

	/* single thread */
	ui = MDI_UNIT(mnum);
	(void) md_unit_openclose_enter(ui);

	if (md_unit_isopen(ui)) {
		md_unit_openclose_exit(ui);
		rw_exit(&md_unit_array_rw.lock);
		return (mdmderror(&mirp->mde, MDE_IS_OPEN, mnum));
	}

	md_unit_openclose_exit(ui);

	if (!mirp->force) {
		int	smi;
		for (smi = 0; smi < NMIRROR; smi++) {
			if (!SMS_BY_INDEX_IS(un, smi, SMS_INUSE))
				continue;

			if (!SMS_BY_INDEX_IS(un, smi, SMS_RUNNING)) {
				rw_exit(&md_unit_array_rw.lock);
				return (mdmderror(&mirp->mde,
				    MDE_C_WITH_INVAL_SM, mnum));
			}
		}
	}

	reset_mirror(un, mnum, 1);

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
mirror_get_geom(
	mm_unit_t	*un,
	struct dk_geom	*geomp
)
{
	md_get_geom((md_unit_t *)un, geomp);

	return (0);
}

static int
mirror_get_vtoc(
	mm_unit_t	*un,
	struct vtoc	*vtocp
)
{
	md_get_vtoc((md_unit_t *)un, vtocp);

	return (0);
}

static int
mirror_set_vtoc(
	mm_unit_t	*un,
	struct vtoc	*vtocp
)
{
	return (md_set_vtoc((md_unit_t *)un, vtocp));
}

static int
mirror_get_extvtoc(
	mm_unit_t	*un,
	struct extvtoc	*vtocp
)
{
	md_get_extvtoc((md_unit_t *)un, vtocp);

	return (0);
}

static int
mirror_set_extvtoc(
	mm_unit_t	*un,
	struct extvtoc	*vtocp
)
{
	return (md_set_extvtoc((md_unit_t *)un, vtocp));
}

static int
mirror_get_cgapart(
	mm_unit_t	*un,
	struct dk_map	*dkmapp
)
{
	md_get_cgapart((md_unit_t *)un, dkmapp);
	return (0);
}

static int
mirror_getcomp_by_dev(mm_unit_t *un, replace_params_t *params,
    int *smi, int *cip)
{
	mm_submirror_t		*sm;
	mm_submirror_ic_t	*smic;
	ms_comp_t		*comp;
	ms_unit_t		*mous;
	int			ci;
	int			i;
	int			compcnt;
	ms_cd_info_t		cd;
	void			(*get_dev)();
	md_dev64_t		dev = md_expldev(params->old_dev);
	md_error_t		*ep = &params->mde;
	minor_t			mnum = params->mnum;
	mdkey_t			devkey;
	int			nkeys;
	set_t			setno;
	side_t			side;

	setno = MD_MIN2SET(MD_SID(un));
	side = mddb_getsidenum(setno);

	if (md_getkeyfromdev(setno, side, dev, &devkey, &nkeys) != 0)
		return (mddeverror(ep, MDE_NAME_SPACE, dev));

	for (i = 0; i < NMIRROR; i++) {
		sm = &un->un_sm[i];
		smic = &un->un_smic[i];

		if (!SMS_IS(sm, SMS_INUSE))
			continue;

		get_dev =
		    (void (*)())md_get_named_service(sm->sm_dev, 0,
		    "get device", 0);
		compcnt = (*(smic->sm_get_component_count))(sm->sm_dev, un);

		/*
		 * For each of the underlying stripe components get
		 * the info.
		 */
		for (ci = 0; ci < compcnt; ci++) {
			(void) (*get_dev)(sm->sm_dev, sm, ci, &cd);
			if ((cd.cd_dev == dev) || (cd.cd_orig_dev == dev)) {
				*cip = ci;
				*smi = i;
				return (1);
			}
		}

		/*
		 * now we rescan looking only for NODEV. If we find
		 * NODEV then we will check the keys to see if its a match.
		 *
		 * If no key was found to match dev, then there is
		 * no way to compare keys - so continue.
		 */
		if (nkeys == 0) {
			continue;
		}
		mous = MD_UNIT(md_getminor(sm->sm_dev));

		for (ci = 0; ci < compcnt; ci++) {

			comp = (struct ms_comp *)
			    ((void *)&((char *)mous)[mous->un_ocomp]);

			(void) (*get_dev)(sm->sm_dev, sm, ci, &cd);

			if (cd.cd_dev == NODEV64 || cd.cd_orig_dev == NODEV64) {
				comp += ci;
				if (comp->un_key == devkey) {
					if (nkeys > 1) {
						return (mddeverror(
						    ep, MDE_MULTNM, dev));
					}
					*cip = ci;
					*smi = i;
					return (1);
				}
			}
		}
	}
	return (mdcomperror(ep, MDE_CANT_FIND_COMP, mnum, dev));
}

/*
 * comp_replace:
 * ----------------
 * Called to implement the component replace function
 *
 * Owner is returned in the parameter block passed in by the caller.
 *
 * Returns:
 *	0	success
 *	error code if the functions fails
 *
 * For a MN set, on entry all writes to the mirror are suspended, on exit
 * from this function, writes must be resumed when not a dryrun.
 */
static int
comp_replace(
	replace_params_t	*params,
	IOLOCK			*lock
)
{
	minor_t			mnum = params->mnum;
	set_t			setno;
	side_t			side;
	mm_unit_t		*un;
	mdi_unit_t		*ui;
	ms_unit_t		*ms_un;
	mdi_unit_t		*ms_ui;
	ms_comp_t		*comp;
	mm_submirror_t		*sm;
	md_dev64_t		smdev;
	mddb_recid_t		recids[6]; /* recids for stripe on SP */
	int			smi, ci;
	ms_new_dev_t		nd;
	int			(*repl_dev)();
	void			(*repl_done)();
	void			*repl_data;
	int			err = 0;
	ms_cd_info_t		cd;
	void			(*get_dev)();

	mdclrerror(&params->mde);

	if ((un = mirror_getun(mnum, &params->mde, WRITERS, lock)) == NULL) {
		return (0);
	}

	ui = MDI_UNIT(mnum);
	if (ui->ui_tstate & MD_INACCESSIBLE) {
		(void) mdmderror(&params->mde, MDE_IN_UNAVAIL_STATE, mnum);
		goto errexit;
	}

	/*
	 * replace cannot be done while a resync is active or we are
	 * still waiting for an optimized resync to be started
	 */
	if (MD_STATUS(un) & (MD_UN_RESYNC_ACTIVE | MD_UN_OPT_NOT_DONE)) {
		(void) mdmderror(&params->mde, MDE_RESYNC_ACTIVE, mnum);
		goto errexit;
	}

	if (mirror_getcomp_by_dev(un, params, &smi, &ci) == 0) {
		goto errexit;
	}

	if (un->un_nsm == 1) {
		(void) mdmderror(&params->mde, MDE_LAST_SM_RE, mnum);
		goto errexit;
	}

	if (mirror_other_sources(un, smi, ci, 0) != 0) {
		(void) mdcomperror(&params->mde, MDE_REPL_INVAL_STATE,
		    mnum, md_expldev(params->old_dev));
		goto errexit;
	}

	sm = &un->un_sm[smi];
	if (sm->sm_state & (SMS_OFFLINE | SMS_OFFLINE_RESYNC)) {
		(void) mdmderror(&params->mde, MDE_ILLEGAL_SM_STATE, mnum);
		goto errexit;
	}

	get_dev = (void (*)())md_get_named_service(sm->sm_dev, 0,
	    "get device", 0);
	(void) (*get_dev)(sm->sm_dev, sm, ci, &cd);

	repl_dev = (int (*)())md_get_named_service(sm->sm_dev, 0,
	    "replace device", 0);

	smdev = sm->sm_dev;
	ms_un = MD_UNIT(md_getminor(smdev));

	if (params->cmd == ENABLE_COMP) {
		md_dev64_t	this_dev;
		int		numkeys;
		mdkey_t		this_key;

		this_dev = ((cd.cd_orig_dev == 0) ? cd.cd_dev :
		    cd.cd_orig_dev);
		setno = MD_MIN2SET(md_getminor(smdev));
		side = mddb_getsidenum(setno);
		comp = (struct ms_comp *)
		    ((void *)&((char *)ms_un)[ms_un->un_ocomp]);
		comp += ci;
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
		 * can occur is if one removed the failed component in the
		 * stripe of a mirror and put another disk that was part of
		 * another metadevice. After reboot metadevadm would correctly
		 * update the device name for the metadevice whose component
		 * has moved. However now in the metadb there are two entries
		 * for the same name (ctds) that belong to different
		 * metadevices. One is valid, the other is a ghost or "last
		 * know as" ctds.
		 */
		this_dev =  md_getdevnum(setno, side,
		    comp->un_key, MD_TRUST_DEVT);

		/*
		 * Verify that multiple keys for the same
		 * dev_t don't exist
		 */

		if (md_getkeyfromdev(setno, side, this_dev,
		    &this_key, &numkeys) != 0) {
			(void) mddeverror(&params->mde, MDE_NAME_SPACE,
			    md_expldev(params->old_dev));
			goto errexit;
		}
		/*
		 * Namespace has multiple entries
		 * for the same devt
		 */
		if (numkeys > 1) {
			(void) mddeverror(&params->mde, MDE_MULTNM,
			    md_expldev(params->old_dev));
			goto errexit;
		}
		if ((numkeys == 0) || (comp->un_key != this_key)) {
			(void) mdcomperror(&params->mde, MDE_CANT_FIND_COMP,
			    mnum, this_dev);
			goto errexit;
		}

		if ((md_getmajor(this_dev) != md_major) &&
		    (md_devid_found(setno, side, this_key) == 1)) {
			if (md_update_namespace_did(setno, side,
			    this_key, &params->mde) != 0) {
				(void) mddeverror(&params->mde, MDE_NAME_SPACE,
				    this_dev);
				goto errexit;
			}
		}

		if (md_expldev(params->new_dev) != this_dev) {
			(void) mddeverror(&params->mde, MDE_FIX_INVAL_STATE,
			    md_expldev(params->new_dev));
			goto errexit;
		}

		/* in case of dryrun, don't actually do anything */
		if ((params->options & MDIOCTL_DRYRUN) == 0) {
			err = (*repl_dev)(sm->sm_dev, 0, ci, NULL, recids, 6,
			    &repl_done, &repl_data);
		}
	} else if ((params->options & MDIOCTL_DRYRUN) == 0) {
		nd.nd_dev = md_expldev(params->new_dev);
		nd.nd_key = params->new_key;
		nd.nd_start_blk = params->start_blk;
		nd.nd_nblks = params->number_blks;
		nd.nd_labeled = params->has_label;
		nd.nd_hs_id = 0;

		err = (*repl_dev)(sm->sm_dev, 0, ci, &nd, recids, 6,
		    &repl_done, &repl_data);

	}

	if (err != 0) {
		(void) mdcomperror(&params->mde, err, mnum,
		    md_expldev(params->new_dev));
		goto errexit;
	}
	/* In case of a dryun we're done. */
	if (params->options & MDIOCTL_DRYRUN) {
		mdclrerror(&params->mde);
		return (0);
	}

	/* set_sm_comp_state() commits the modified records */
	set_sm_comp_state(un, smi, ci, CS_RESYNC, recids, MD_STATE_NO_XMIT,
	    lock);

	(*repl_done)(sm->sm_dev, repl_data);

	/*
	 * If the mirror is open then need to make sure that the submirror,
	 * on which the replace ran, is also open and if not then open it.
	 * This is only a concern for a single component sub-mirror stripe
	 * as it may not be open due to the failure of the single component.
	 *
	 * This check has to be done after the call to (*repl_done)
	 * as that function releases the writer lock on the submirror.
	 */
	if (md_unit_isopen(ui)) {
		minor_t ms_mnum = md_getminor(sm->sm_dev);

		ms_ui = MDI_UNIT(ms_mnum);

		if (!md_unit_isopen(ms_ui)) {
			/*
			 * Underlying submirror is not open so open it.
			 */
			if (md_layered_open(ms_mnum, &smdev, MD_OFLG_NULL)) {
				mirror_openfail_console_info(un, smi, ci);
				goto errexit;
			}
		}
	}

	mirror_check_failfast(mnum);

	if (params->cmd == ENABLE_COMP) {
		SE_NOTIFY(EC_SVM_STATE, ESC_SVM_ENABLE, SVM_TAG_METADEVICE,
		    MD_UN2SET(un), MD_SID(un));
	} else {
		SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_REPLACE, SVM_TAG_METADEVICE,
		    MD_UN2SET(un), MD_SID(un));
	}

	md_ioctl_writerexit(lock);
	/*
	 * Reset any saved resync location flags as we've now replaced the
	 * component. This means we have to resync the _whole_ component.
	 */
	un->un_rs_resync_done = un->un_rs_resync_2_do = 0;
	un->un_rs_type = MD_RS_NONE;
	mirror_resume_writes(un);
	if (!MD_MNSET_SETNO(MD_UN2SET(un)))
		(void) mirror_resync_unit(mnum, NULL, &params->mde, lock);
	mdclrerror(&params->mde);
	return (0);
errexit:
	/* We need to resume writes unless this is a dryrun */
	if (!(params->options & MDIOCTL_DRYRUN))
		mirror_resume_writes(un);
	return (0);
}

/*
 * mirror_attach:
 * ----------------
 * Called to implement the submirror attach function
 *
 * Owner is returned in the parameter block passed in by the caller.
 *
 * Returns:
 *	0	success
 *	error code if the functions fails
 *
 * For a MN set, on entry all writes to the mirror are suspended, on exit
 * from this function, writes must be resumed when not a dryrun.
 */
static int
mirror_attach(
	md_att_struct_t	*att,
	IOLOCK		*lock
)
{
	minor_t			mnum = att->mnum;
	mm_unit_t		*un;
	md_unit_t		*su;
	mm_submirror_t		*sm;
	mm_submirror_ic_t	*smic;
	int			smi;
	md_dev64_t		sm_dev;
	minor_t			sm_mnum;
	mdkey_t			indx;
	set_t			setno;
	uint_t			options;

	/*
	 * This routine should not be called during upgrade.
	 */
	if (MD_UPGRADE)  {
		return (0);
	}

	mdclrerror(&att->mde);
	options = att->options;

	if ((un = mirror_getun(mnum, &att->mde, WRITERS, lock)) == NULL) {
		return (0);
	}

	setno = MD_UN2SET(un);

	for (smi = 0; smi < NMIRROR; smi++)
		if (!SMS_BY_INDEX_IS(un, smi, SMS_INUSE))
			break;

	if (smi == NMIRROR) {
		(void) mdmderror(&att->mde, MDE_MIRROR_FULL, mnum);
		goto errexit;
	}

	sm = &un->un_sm[smi];
	smic = &un->un_smic[smi];
	sm_dev = att->submirror;
	sm_mnum = md_getminor(sm_dev);

	if (md_get_parent(sm_dev) != MD_NO_PARENT) {
		(void) mdmderror(&att->mde, MDE_IN_USE, sm_mnum);
		goto errexit;
	}

	if (md_unit_isopen(MDI_UNIT(sm_mnum))) {
		(void) mdmderror(&att->mde, MDE_IS_OPEN, sm_mnum);
		goto errexit;
	}

	/* Check the size */
	su = (md_unit_t *)MD_UNIT(sm_mnum);
	if (un->c.un_total_blocks > su->c.un_total_blocks) {
		(void) mdmderror(&att->mde, MDE_SM_TOO_SMALL, sm_mnum);
		goto errexit;
	}

	/* Don't attach labeled sm to unlabeled mirrors */
	if ((su->c.un_flag & MD_LABELED) && !(un->c.un_flag & MD_LABELED)) {
		(void) mdmderror(&att->mde, MDE_NO_LABELED_SM, sm_mnum);
		goto errexit;
	}

	indx = md_setshared_name(setno,
	    ddi_major_to_name(md_getmajor(sm_dev)), 0L);

	/* Open the sm, only if the mirror is open */
	if (md_unit_isopen(MDI_UNIT(mnum))) {
		if (md_layered_open(mnum, &sm_dev, MD_OFLG_NULL)) {
			(void) md_remshared_name(setno, indx);
			(void) mdmderror(&att->mde, MDE_SM_OPEN_ERR,
			    md_getminor(att->submirror));
			goto errexit;
		}
		/* in dryrun mode, don't leave the device open */
		if (options & MDIOCTL_DRYRUN) {
			md_layered_close(sm_dev, MD_OFLG_NULL);
		}
	}

	/*
	 * After this point the checks are done and action is taken.
	 * So, clean up and return in case of dryrun.
	 */

	if (options & MDIOCTL_DRYRUN) {
		md_ioctl_writerexit(lock);
		mdclrerror(&att->mde);
		return (0);
	}

	sm->sm_key = att->key;
	sm->sm_dev = sm_dev;
	md_set_parent(sm_dev, MD_SID(un));
	mirror_set_sm_state(sm, smic, SMS_ATTACHED_RESYNC, 1);
	build_submirror(un, smi, 0);
	un->un_nsm++;
	mirror_commit(un, SMI2BIT(smi), 0);
	mirror_check_failfast(mnum);
	SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_ATTACH, SVM_TAG_METADEVICE,
	    MD_UN2SET(un), MD_SID(un));

	mirror_resume_writes(un);
	md_ioctl_writerexit(lock);
	if (!MD_MNSET_SETNO(setno))
		(void) mirror_resync_unit(mnum, NULL, &att->mde, lock);
	mdclrerror(&att->mde);
	return (0);
errexit:
	/* We need to resume writes unless this is a dryrun */
	if (!(options & MDIOCTL_DRYRUN))
		mirror_resume_writes(un);
	return (0);
}


void
reset_comp_states(mm_submirror_t *sm, mm_submirror_ic_t *smic)
{
	int		compcnt;
	int		i;
	md_m_shared_t	*shared;

	compcnt = (*(smic->sm_get_component_count)) (sm->sm_dev, sm);
	for (i = 0; i < compcnt; i++) {
		shared = (md_m_shared_t *)(*(smic->sm_shared_by_indx))
		    (sm->sm_dev, sm, i);

		shared->ms_state = CS_OKAY;
		shared->ms_flags &= ~MDM_S_NOWRITE;
		shared->ms_lasterrcnt = 0;
	}
}


/*
 * mirror_detach:
 * ----------------
 * Called to implement the submirror detach function
 *
 * Owner is returned in the parameter block passed in by the caller.
 *
 * Returns:
 *	0	success
 *	error code if the functions fails
 *
 * For a MN set, on entry all writes to the mirror are suspended, on exit
 * from this function, writes must be resumed.
 */
static int
mirror_detach(
	md_detach_params_t	*det,
	IOLOCK			*lock
)
{
	minor_t			mnum = det->mnum;
	mm_unit_t		*un;
	mdi_unit_t		*ui;
	mm_submirror_t		*sm;
	mm_submirror_t		*old_sm;
	mm_submirror_t		*new_sm;
	mm_submirror_ic_t	*smic;
	int			smi;
	md_dev64_t		sm_dev;
	md_unit_t		*su;
	sv_dev_t		sv;
	mddb_recid_t		recids[2];
	int			nsv = 0;
	int			smi_remove;
	mm_submirror_ic_t	*old_smic;
	mm_submirror_ic_t	*new_smic;

	mdclrerror(&det->mde);

	if ((un = mirror_getun(mnum, &det->mde, WRITERS, lock)) == NULL) {
		return (0);
	}

	ui = MDI_UNIT(mnum);
	if (ui->ui_tstate & MD_INACCESSIBLE) {
		mirror_resume_writes(un);
		return (mdmderror(&det->mde, MDE_IN_UNAVAIL_STATE, mnum));
	}
	/*
	 * detach cannot be done while a resync is active or we are
	 * still waiting for an optimized resync to be started
	 */
	if (MD_STATUS(un) & (MD_UN_RESYNC_ACTIVE | MD_UN_OPT_NOT_DONE)) {
		mirror_resume_writes(un);
		return (mdmderror(&det->mde, MDE_RESYNC_ACTIVE, mnum));
	}

	for (smi = 0; smi < NMIRROR; smi++) {
		if (!SMS_BY_INDEX_IS(un, smi, SMS_INUSE)) {
			continue;
		}
		if (un->un_sm[smi].sm_dev == det->submirror) {
			smi_remove = smi;
			break;
		}
	}

	if (smi == NMIRROR) {
		mirror_resume_writes(un);
		return (mdmderror(&det->mde, MDE_CANT_FIND_SM, mnum));
	}

	if (un->un_nsm == 1) {
		mirror_resume_writes(un);
		return (mdmderror(&det->mde, MDE_LAST_SM, mnum));
	}

	if (mirror_other_sources(un, smi, WHOLE_SM, 0) != 0) {
		mirror_resume_writes(un);
		return (mdmderror(&det->mde, MDE_NO_READABLE_SM, mnum));
	}

	sm = &un->un_sm[smi];
	smic = &un->un_smic[smi];
	sm_dev = sm->sm_dev;
	su = (md_unit_t *)MD_UNIT(md_getminor(sm_dev));

	/*
	 * Need to pass in the extra record id,
	 * cause mirror_commit() will not commit
	 * a sm (from the smmask) if the slot is unused.
	 * Which it is, since we are detaching.
	 */
	recids[0] = ((md_unit_t *)MD_UNIT(md_getminor(sm_dev)))->c.un_record_id;
	recids[1] = 0;

	mirror_set_sm_state(sm, smic, SMS_UNUSED, det->force_detach);
	/*
	 * If there are any erred components
	 * then make the detach fail and do not unparent the
	 * submirror.
	 */
	if (sm->sm_state == SMS_UNUSED) {
		/* reallow soft partitioning of submirror */
		MD_CAPAB(su) |= MD_CAN_SP;
		md_reset_parent(sm_dev);
		reset_comp_states(sm, smic);
		un->un_nsm--;
		/* Close the sm, only if the mirror is open */
		if (md_unit_isopen(MDI_UNIT(mnum)))
			md_layered_close(sm_dev, MD_OFLG_NULL);
		sv.setno = MD_UN2SET(un);
		sv.key = sm->sm_key;
		nsv = 1;
	} else
		(void) mdmderror(&det->mde, MDE_SM_FAILED_COMPS, mnum);

	/*
	 * Perhaps the mirror changed it's size due to this detach.
	 * (void) mirror_grow_unit(un, &mde);
	 */

	/*
	 * NOTE: We are passing the detached sm recid
	 * and not the smmask field. This is correct.
	 */
	mirror_commit(un, 0, recids);
	md_rem_names(&sv, nsv);
	if (sm->sm_state == SMS_UNUSED) {
		SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_DETACH, SVM_TAG_METADEVICE,
		    MD_UN2SET(un), MD_SID(un));
	}

	/*
	 * Reshuffle the submirror devices in the array as we potentially
	 * have a dead record in the middle of it.
	 */
	for (smi = 0; nsv && (smi < NMIRROR); smi++) {
		if (smi < smi_remove) {
			continue;
		}
		if (smi > smi_remove) {
			old_sm = &un->un_sm[smi];
			new_sm = &un->un_sm[smi - 1];
			new_sm->sm_key = old_sm->sm_key;
			new_sm->sm_dev = old_sm->sm_dev;
			new_sm->sm_state = old_sm->sm_state;
			new_sm->sm_flags = old_sm->sm_flags;
			new_sm->sm_shared = old_sm->sm_shared;
			new_sm->sm_hsp_id = old_sm->sm_hsp_id;
			new_sm->sm_timestamp = old_sm->sm_timestamp;
			bzero(old_sm, sizeof (mm_submirror_t));
			old_smic = &un->un_smic[smi];
			new_smic = &un->un_smic[smi - 1];
			bcopy(old_smic, new_smic, sizeof (mm_submirror_ic_t));
			bzero(old_smic, sizeof (mm_submirror_ic_t));
		}
	}
	mirror_commit(un, 0, NULL);
	mirror_resume_writes(un);
	return (0);
}

/*
 * mirror_offline:
 * ----------------
 * Called to implement the submirror offline function
 *
 * Owner is returned in the parameter block passed in by the caller.
 *
 * Returns:
 *	0	success
 *	error code if the functions fails
 *
 * For a MN set, on entry all writes to the mirror are suspended, on exit
 * from this function, writes must be resumed.
 */
static int
mirror_offline(
	md_i_off_on_t	*miop,
	IOLOCK		*lock
)
{
	minor_t			mnum = miop->mnum;
	mm_unit_t		*un;
	mm_submirror_t		*sm;
	mm_submirror_ic_t	*smic;
	int			smi;
	mdi_unit_t		*ui = MDI_UNIT(mnum);

	mdclrerror(&miop->mde);

	if ((un = mirror_getun(mnum, &miop->mde, WR_LOCK, lock)) == NULL) {
		return (0);
	}

	/*
	 * offline cannot be done while a resync is active or we are
	 * still waiting for an optimized resync to be started
	 */
	if (MD_STATUS(un) & (MD_UN_RESYNC_ACTIVE | MD_UN_OPT_NOT_DONE)) {
		mirror_resume_writes(un);
		return (mdmderror(&miop->mde, MDE_RESYNC_ACTIVE, mnum));
	}

	/*
	 * Reject mirror_offline if ABR is set
	 */
	if ((ui->ui_tstate & MD_ABR_CAP) || un->un_abr_count) {
		mirror_resume_writes(un);
		return (mderror(&miop->mde, MDE_ABR_SET));
	}

	for (smi = 0; smi < NMIRROR; smi++) {
		if (!SMS_BY_INDEX_IS(un, smi, SMS_INUSE))
			continue;
		if (un->un_sm[smi].sm_dev == miop->submirror)
			break;
	}

	if (smi == NMIRROR) {
		mirror_resume_writes(un);
		return (mdmderror(&miop->mde, MDE_CANT_FIND_SM, mnum));
	}

	sm = &un->un_sm[smi];
	smic = &un->un_smic[smi];
	if (!SMS_IS(sm, SMS_RUNNING) && !miop->force_offline) {
		mirror_resume_writes(un);
		return (mdmderror(&miop->mde, MDE_ILLEGAL_SM_STATE, mnum));
	}

	if (mirror_other_sources(un, smi, WHOLE_SM, 0) != 0) {
		mirror_resume_writes(un);
		return (mdmderror(&miop->mde, MDE_NO_READABLE_SM, mnum));
	}
	mirror_set_sm_state(sm, smic, SMS_OFFLINE, 1);
	mirror_resume_writes(un);

	MD_STATUS(un) |= MD_UN_OFFLINE_SM;
	mirror_commit(un, NO_SUBMIRRORS, 0);
	SE_NOTIFY(EC_SVM_STATE, ESC_SVM_OFFLINE, SVM_TAG_METADEVICE,
	    MD_UN2SET(un), MD_SID(un));
	return (0);
}

/*
 * mirror_online:
 * ----------------
 * Called to implement the submirror online function
 *
 * Owner is returned in the parameter block passed in by the caller.
 *
 * Returns:
 *	0	success
 *	error code if the functions fails
 *
 * For a MN set, on entry all writes to the mirror are suspended, on exit
 * from this function, writes must be resumed.
 */
static int
mirror_online(
	md_i_off_on_t	*miop,
	IOLOCK		*lock
)
{
	minor_t			mnum = miop->mnum;
	mm_unit_t		*un;
	mm_submirror_t		*sm;
	mm_submirror_ic_t	*smic;
	int			smi;
	set_t			setno = MD_MIN2SET(mnum);

	mdclrerror(&miop->mde);

	if ((un = mirror_getun(mnum, &miop->mde, WR_LOCK, lock)) == NULL) {
		return (0);
	}

	for (smi = 0; smi < NMIRROR; smi++) {
		if (!SMS_BY_INDEX_IS(un, smi, SMS_INUSE))
			continue;
		if (un->un_sm[smi].sm_dev == miop->submirror)
			break;
	}
	if (smi == NMIRROR) {
		mirror_resume_writes(un);
		return (mdmderror(&miop->mde, MDE_CANT_FIND_SM, mnum));
	}

	sm = &un->un_sm[smi];
	smic = &un->un_smic[smi];
	if (!SMS_IS(sm, SMS_OFFLINE)) {
		mirror_resume_writes(un);
		return (mdmderror(&miop->mde, MDE_ILLEGAL_SM_STATE, mnum));
	}

	/*
	 * online cannot be done while a resync is active or we are
	 * still waiting for an optimized resync to be started
	 */
	if (MD_STATUS(un) & (MD_UN_RESYNC_ACTIVE | MD_UN_OPT_NOT_DONE)) {
		mirror_resume_writes(un);
		return (mdmderror(&miop->mde, MDE_RESYNC_ACTIVE, mnum));
	}

	mirror_set_sm_state(sm, smic, SMS_OFFLINE_RESYNC, 1);
	mirror_commit(un, NO_SUBMIRRORS, 0);
	mirror_check_failfast(mnum);
	SE_NOTIFY(EC_SVM_STATE, ESC_SVM_ONLINE, SVM_TAG_METADEVICE,
	    MD_UN2SET(un), MD_SID(un));


	/* for MN sets, re-read the resync record from disk */
	if (MD_MNSET_SETNO(MD_UN2SET(un)))
		(void) mddb_reread_rr(setno, un->un_rr_dirty_recid);

	bcopy((caddr_t)un->un_dirty_bm, (caddr_t)un->un_resync_bm,
	    howmany(un->un_rrd_num, NBBY));
	MD_STATUS(un) |= MD_UN_OPT_NOT_DONE;
	sm->sm_flags |= MD_SM_RESYNC_TARGET;
	mirror_resume_writes(un);
	md_ioctl_writerexit(lock);
	if (!MD_MNSET_SETNO(setno))
		return (mirror_resync_unit(mnum, NULL, &miop->mde, lock));
	else return (0);
}

int
mirror_grow_unit(
	mm_unit_t		*un,
	md_error_t		*ep
)
{
	md_unit_t		*su;
	mm_submirror_t		*sm;
	int			smi;
	diskaddr_t		total_blocks;
	diskaddr_t		current_tb;
	int			spc;		/* sectors per head */
	minor_t			mnum = MD_SID(un);

	/*
	 * grow_unit cannot be done while a resync is active or we are
	 * still waiting for an optimized resync to be started. Set
	 * flag to indicate GROW_PENDING and once the resync is complete
	 * the grow_unit function will be executed.
	 */
	if (MD_STATUS(un) & (MD_UN_RESYNC_ACTIVE | MD_UN_OPT_NOT_DONE)) {
		MD_STATUS(un) |= MD_UN_GROW_PENDING;
		mirror_commit(un, NO_SUBMIRRORS, 0);
		return (mdmderror(ep, MDE_GROW_DELAYED, MD_SID(un)));
	}

	/*
	 * Find the smallest submirror
	 */
	total_blocks = 0;
	for (smi = 0; smi < NMIRROR; smi++) {
		if (!SMS_BY_INDEX_IS(un, smi, SMS_INUSE))
			continue;
		sm = &un->un_sm[smi];
		/*
		 * Growth is not possible if there is one or more
		 * submirrors made up of non-Metadevices.
		 */
		if (md_getmajor(sm->sm_dev) != md_major)
			return (0);

		su = MD_UNIT(md_getminor(sm->sm_dev));
		if ((total_blocks == 0) ||
		    (su->c.un_total_blocks < total_blocks))
			total_blocks = su->c.un_total_blocks;
	}

	/*
	 * If the smallest submirror is not larger
	 * than the mirror, we are all done.
	 */
	if (total_blocks <= un->c.un_total_blocks)
		return (0);

	/*
	 * Growing the mirror now.
	 * First: Round down the actual_tb to be a multiple
	 * 	of nheads * nsects.
	 */
	spc = un->c.un_nhead * un->c.un_nsect;
	current_tb = (total_blocks/spc) * spc;

	un->c.un_total_blocks = current_tb;
	md_nblocks_set(mnum, un->c.un_total_blocks);
	un->c.un_actual_tb = total_blocks;

	/* Is the mirror growing from 32 bit device to 64 bit device? */
	if (((un->c.un_revision & MD_64BIT_META_DEV) == 0) &&
	    (un->c.un_total_blocks > MD_MAX_BLKS_FOR_SMALL_DEVS)) {
#if defined(_ILP32)
		return (mdmderror(ep, MDE_UNIT_TOO_LARGE, mnum));
#else
		mddb_type_t	typ1;
		mddb_recid_t	recid;
		set_t		setno;
		mddb_recid_t	old_recid = un->c.un_record_id;
		mddb_recid_t	old_vtoc;
		mddb_de_ic_t    *dep, *old_dep;
		md_create_rec_option_t	options;

		/* yup, new device size. So we need to replace the record */
		typ1 = (mddb_type_t)md_getshared_key(MD_UN2SET(un),
		    mirror_md_ops.md_driver.md_drivername);
		setno = MD_MIN2SET(mnum);

		/* Preserve the friendly name properties of growing unit */
		options = MD_CRO_64BIT | MD_CRO_MIRROR;
		if (un->c.un_revision & MD_FN_META_DEV)
			options |= MD_CRO_FN;
		recid = mddb_createrec(offsetof(mm_unit_t, un_smic), typ1,
		    MIRROR_REC, options, setno);
		/* Resize to include incore fields */
		un->c.un_revision |= MD_64BIT_META_DEV;
		/* All 64 bit metadevices only support EFI labels. */
		un->c.un_flag |= MD_EFILABEL;
		/*
		 * If the device had a vtoc record attached to it, we remove
		 * the vtoc record, because the layout has changed completely.
		 */
		old_vtoc = un->c.un_vtoc_id;
		if (old_vtoc != 0) {
			un->c.un_vtoc_id =
			    md_vtoc_to_efi_record(old_vtoc, setno);
		}
		MD_RECID(un) = recid;
		dep = mddb_getrecdep(recid);
		old_dep = mddb_getrecdep(old_recid);
		kmem_free(dep->de_rb_userdata, dep->de_reqsize);
		dep->de_rb_userdata = old_dep->de_rb_userdata;
		dep->de_reqsize = old_dep->de_reqsize;
		dep->de_rb_userdata_ic = old_dep->de_rb_userdata_ic;
		dep->de_icreqsize = old_dep->de_icreqsize;
		mirror_commit(un, NO_SUBMIRRORS, 0);
		old_dep->de_rb_userdata = NULL;
		old_dep->de_rb_userdata_ic = NULL;
		mddb_deleterec_wrapper(old_recid);
		/*
		 * If there was a vtoc record, it is no longer needed, because
		 * a new efi record has been created for this un.
		 */
		if (old_vtoc != 0) {
			mddb_deleterec_wrapper(old_vtoc);
		}
#endif
	}

	if ((current_tb/un->un_rrd_blksize) > MD_MAX_NUM_RR) {
		if (mirror_resize_resync_regions(un, current_tb)) {
			return (mdmderror(ep, MDE_RR_ALLOC_ERROR, MD_SID(un)));
		}
		mirror_check_failfast(mnum);
		SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_GROW, SVM_TAG_METADEVICE,
		    MD_UN2SET(un), MD_SID(un));
		return (0);
	}

	if (mirror_add_resync_regions(un, current_tb)) {
		return (mdmderror(ep, MDE_RR_ALLOC_ERROR, MD_SID(un)));
	}

	mirror_check_failfast(mnum);
	SE_NOTIFY(EC_SVM_CONFIG, ESC_SVM_GROW, SVM_TAG_METADEVICE,
	    MD_UN2SET(un), MD_SID(un));

	return (0);
}

static int
mirror_grow(
	void			*mgp,
	IOLOCK			*lock
)
{
	mm_unit_t		*un;
	md_grow_params_t	*mgph = mgp;

	mdclrerror(&mgph->mde);

	if ((un = mirror_getun(mgph->mnum,
	    &mgph->mde, WR_LOCK, lock)) == NULL)
		return (0);

	if (MD_STATUS(un) & MD_UN_GROW_PENDING)
		return (0);

	return (mirror_grow_unit(un, &mgph->mde));
}

static int
mirror_change(
	md_mirror_params_t	*mmp,
	IOLOCK			*lock
)
{
	mm_params_t		*pp = &mmp->params;
	mm_unit_t		*un;

	mdclrerror(&mmp->mde);

	if ((un = mirror_getun(mmp->mnum, &mmp->mde, WR_LOCK, lock)) == NULL)
		return (0);

	if (pp->change_read_option)
		un->un_read_option = pp->read_option;

	if (pp->change_write_option)
		un->un_write_option = pp->write_option;

	if (pp->change_pass_num)
		un->un_pass_num = pp->pass_num;

	mirror_commit(un, NO_SUBMIRRORS, 0);

	SE_NOTIFY(EC_SVM_STATE, ESC_SVM_CHANGE, SVM_TAG_METADEVICE,
	    MD_UN2SET(un), MD_SID(un));
	return (0);
}

static int
mirror_get_resync(
	md_resync_ioctl_t	*ri
)
{
	minor_t			mnum = ri->ri_mnum;
	mm_unit_t		*un;
	u_longlong_t		percent;
	uint_t			cnt;
	uint_t			rr;
	diskaddr_t		d;

	mdclrerror(&ri->mde);

	if ((un = mirror_getun(mnum, &ri->mde, STALE_OK|NO_LOCK, NULL)) == NULL)
		return (0);

	ri->ri_flags = 0;
	if (md_get_setstatus(MD_MIN2SET(mnum)) & MD_SET_STALE) {
		ri->ri_percent_done = 0;
		ri->ri_percent_dirty = 0;
		return (0);
	}

	if (MD_STATUS(un) & (MD_UN_RESYNC_ACTIVE|MD_UN_RESYNC_CANCEL)) {
		if (MD_STATUS(un) & MD_UN_RESYNC_ACTIVE)
			ri->ri_flags |= MD_RI_INPROGRESS;
		/* Return state of resync thread */
		ri->ri_flags |= (un->un_rs_thread_flags & MD_RI_BLOCK);
		d = un->un_rs_resync_2_do;
		if (d) {
			percent = un->un_rs_resync_done;
			if (un->c.un_total_blocks >
			    MD_MAX_BLKS_FOR_SMALL_DEVS) {
				percent *= 1000;
				percent /= d;
				if (percent > 1000)
					percent = 1000;
			} else {
				percent *= 100;
				percent /= d;
			}
			ri->ri_percent_done = (int)percent;
		} else {
			ri->ri_percent_done = 0;
		}
	}
	if (un->un_nsm < 2) {
		ri->ri_percent_dirty = 0;
		return (0);
	}
	cnt = 0;
	for (rr = 0; rr < un->un_rrd_num; rr++)
		if (IS_REGION_DIRTY(rr, un))
			cnt++;
	d = un->un_rrd_num;
	if (d) {
		percent = cnt;
		percent *= 100;
		percent += d - 1;		/* round up */
		percent /= d;
	} else
		percent = 0;
	ri->ri_percent_dirty = (int)percent;
	return (0);
}

/*
 * mirror_get_owner:
 * ----------------
 * Called to obtain the current owner of a mirror.
 *
 * Owner is returned in the parameter block passed in by the caller.
 *
 * Returns:
 *	0	success
 *	EINVAL	metadevice does not exist or is not a member of a multi-owned
 *		set.
 */
static int
mirror_get_owner(md_set_mmown_params_t *p, IOLOCK *lock)
{
	mm_unit_t	*un;
	set_t		setno;

	if ((un = mirror_getun(p->d.mnum, &p->mde, RD_LOCK, lock)) == NULL)
		return (EINVAL);

	setno = MD_UN2SET(un);
	if (!MD_MNSET_SETNO(setno)) {
		return (EINVAL);
	}
	p->d.owner = un->un_mirror_owner;
	return (0);
}

/*
 * mirror_choose_owner_thread:
 * --------------------------
 * Called to send a CHOOSE_OWNER message to the commd running on the master
 * node. This needs to run in a separate context so that mutex livelock is
 * avoided. This can occur because the original request is issued from a call
 * to metaioctl() which acquires the global ioctl lock, calls down into the
 * mirror_ioctl code and then attempts to mdmn_ksend_message() to the master
 * node. As the handler for the choose_owner message needs to send another
 * ioctl through the metaioctl() entry point, any other use (by rpc.metad or
 * mdcommd checking on set ownership) will deadlock the system leading to
 * cluster reconfiguration timeouts and eventually a node or (at worst) a
 * cluster-wide panic
 */
static void
mirror_choose_owner_thread(md_mn_msg_chooseid_t	*msg)
{
	int		rval;
	md_mn_kresult_t	*kres;
	set_t		setno = MD_MIN2SET(msg->msg_chooseid_mnum);

	kres = kmem_alloc(sizeof (md_mn_kresult_t), KM_SLEEP);
	rval = mdmn_ksend_message(setno, MD_MN_MSG_CHOOSE_OWNER,
	    MD_MSGF_NO_BCAST | MD_MSGF_NO_LOG, 0, (char *)msg,
	    sizeof (md_mn_msg_chooseid_t), kres);
	if (!MDMN_KSEND_MSG_OK(rval, kres)) {
		mdmn_ksend_show_error(rval, kres, "CHOOSE OWNER");
		cmn_err(CE_WARN, "ksend_message failure: CHOOSE_OWNER");
	}

	kmem_free(kres, sizeof (md_mn_kresult_t));
	kmem_free(msg, sizeof (md_mn_msg_chooseid_t));
	thread_exit();
}

/*
 * mirror_owner_thread:
 * -------------------
 * Called to request an ownership change from a thread context. This issues
 * a mdmn_ksend_message() and then completes the appropriate ownership change
 * on successful completion of the message transport.
 * The originating application must poll for completion on the 'flags' member
 * of the MD_MN_MM_OWNER_STATUS ioctl() parameter block.
 * Success is marked by a return value of MD_MN_MM_RES_OK, Failure by
 * MD_MN_MM_RES_FAIL
 */
static void
mirror_owner_thread(md_mn_req_owner_t *ownp)
{
	int		rval;
	set_t		setno = MD_MIN2SET(ownp->mnum);
	mm_unit_t	*un = MD_UNIT(ownp->mnum);
	md_mn_kresult_t	*kresult;
	md_mps_t	*ps1;

	un->un_mirror_owner_status = 0;

	mutex_enter(&un->un_owner_mx);
	un->un_owner_state |= MM_MN_OWNER_SENT;
	mutex_exit(&un->un_owner_mx);

	kresult = kmem_alloc(sizeof (md_mn_kresult_t), KM_SLEEP);
	rval = mdmn_ksend_message(setno, MD_MN_MSG_REQUIRE_OWNER,
	    MD_MSGF_NO_LOG, 0, (char *)ownp, sizeof (md_mn_req_owner_t),
	    kresult);

	if (!MDMN_KSEND_MSG_OK(rval, kresult)) {
		/*
		 * Message transport layer failed. Return the failure code to
		 * the application.
		 */
		mdmn_ksend_show_error(rval, kresult, "CHANGE OWNER");
		mutex_enter(&un->un_owner_mx);
		un->un_owner_state &= ~(MM_MN_BECOME_OWNER|MM_MN_OWNER_SENT);
		mutex_exit(&un->un_owner_mx);
		un->un_mirror_owner_status =
		    MD_MN_MM_RESULT | MD_MN_MM_RES_FAIL;
	} else {
		/*
		 * Ownership change succeeded. Update in-core version of
		 * mirror owner.
		 */
		mutex_enter(&un->un_owner_mx);
		if (un->un_owner_state & MM_MN_BECOME_OWNER) {
			un->un_mirror_owner = md_mn_mynode_id;
			/* Sets node owner of un_rr_dirty record */
			if (un->un_rr_dirty_recid)
				(void) mddb_setowner(un->un_rr_dirty_recid,
				    md_mn_mynode_id);
			/*
			 * Release the block on the current resync region if it
			 * is blocked
			 */
			ps1 = un->un_rs_prev_overlap;
			if ((ps1 != NULL) &&
			    (ps1->ps_flags & MD_MPS_ON_OVERLAP))
				mirror_overlap_tree_remove(ps1);
		}

		un->un_owner_state &= ~(MM_MN_OWNER_SENT|MM_MN_BECOME_OWNER);
		mutex_exit(&un->un_owner_mx);
		un->un_mirror_owner_status =
		    MD_MN_MM_RESULT | MD_MN_MM_RES_OK;

		/* Restart the resync thread if it was previously blocked */
		if (un->un_rs_thread_flags & MD_RI_BLOCK_OWNER) {
			mutex_enter(&un->un_rs_thread_mx);
			un->un_rs_thread_flags &= ~MD_RI_BLOCK_OWNER;
			cv_signal(&un->un_rs_thread_cv);
			mutex_exit(&un->un_rs_thread_mx);
		}
	}
	kmem_free(kresult, sizeof (md_mn_kresult_t));
	kmem_free(ownp, sizeof (md_mn_req_owner_t));
	thread_exit();
}

/*
 * mirror_set_owner:
 * ----------------
 * Called to change the owner of a mirror to the specified node. If we
 * are not the owner of the mirror, we do nothing apart from update the in-core
 * ownership. It can also be used to choose a new owner for the resync of a
 * mirror, this case is specified by the flag MD_MN_MM_CHOOSE_OWNER, see below.
 *
 * The p->d.flags bitfield controls how subsequent ownership changes will be
 * handled:
 *	MD_MN_MM_SPAWN_THREAD
 *		a separate thread is created which emulates the behaviour of
 *		become_owner() [mirror.c]. This is needed when changing the
 *		ownership from user context as there needs to be a controlling
 *		kernel thread which updates the owner info on the originating
 *		node. Successful completion of the mdmn_ksend_message() means
 *		that the owner field can be changed.
 *
 *	MD_MN_MM_PREVENT_CHANGE
 *		Disallow any change of ownership once this ownership change has
 *		been processed. The only way of changing the owner away from
 *		the p->d.owner node specified in the call is to issue a request
 *		with MD_MN_MM_ALLOW_CHANGE set in the flags. Any request to
 *		become owner from a different node while the PREVENT_CHANGE
 *		is in operation will result in an EAGAIN return value.
 *		un->un_owner_state has MM_MN_PREVENT_CHANGE set.
 *
 *	MD_MN_MM_ALLOW_CHANGE
 *		Allow the owner to be changed by a subsequent request.
 *		un->un_owner_state has MM_MN_PREVENT_CHANGE cleared.
 *
 *	MD_MN_MM_CHOOSE_OWNER
 *		Choose a new owner for a mirror resync. In this case, the new
 *		owner argument is not used. The selection of a new owner
 *		is a round robin allocation using a resync owner count. This
 *		ioctl passes this value in a message to the master node
 *		which uses it to select a node from the node list and then
 *		sends it a message to become the owner.
 *
 * If we are the current owner, we must stop further i/o from being scheduled
 * and wait for any pending i/o to drain. We wait for any in-progress resync
 * bitmap updates to complete and we can then set the owner. If an update to
 * the resync bitmap is attempted after this we simply don't write this out to
 * disk until the ownership is restored.
 *
 * If we are the node that wants to become the owner we update the in-core
 * owner and return. The i/o that initiated the ownership change will complete
 * on successful return from this ioctl.
 *
 * Return Value:
 *	0		Success
 * 	EINVAL		Invalid unit referenced
 *	EAGAIN		Ownership couldn't be transferred away or change of
 *			ownership is prevented. Caller should retry later on.
 */
static int
mirror_set_owner(md_set_mmown_params_t *p, IOLOCK *lock)
{
	mdi_unit_t	*ui;
	mm_unit_t	*un;
	set_t		setno;

	if ((un = mirror_getun(p->d.mnum, &p->mde, RD_LOCK, lock)) == NULL)
		return (EINVAL);
	ui = MDI_UNIT(p->d.mnum);
	setno = MD_MIN2SET(p->d.mnum);
	if (!MD_MNSET_SETNO(setno)) {
		return (EINVAL);
	}

	/*
	 * If we are choosing a new resync owner, send a message to the master
	 * to make the choice.
	 */
	if (p->d.flags & MD_MN_MM_CHOOSE_OWNER) {
		/* Release ioctl lock before we call ksend_message() */
		md_ioctl_readerexit(lock);
		/* If we're resetting the owner pass the node id in */
		if (p->d.owner != MD_MN_MIRROR_UNOWNED) {
			return (mirror_choose_owner(un, &p->d));
		} else {
			return (mirror_choose_owner(un, NULL));
		}
	}

	/*
	 * Check for whether we have to spawn a thread to issue this request.
	 * If set we issue a mdmn_ksend_message() to cause the appropriate
	 * ownership change. On completion of this request the calling
	 * application _must_ poll the structure 'flags' field to determine the
	 * result of the request. All this is necessary until we have true
	 * multi-entrant ioctl support.
	 * If we are just clearing the owner, then MD_MN_MM_SPAWN_THREAD can
	 * be ignored.
	 */
	if ((p->d.flags & MD_MN_MM_SPAWN_THREAD) && (p->d.owner != 0)) {
		md_mn_req_owner_t	*ownp;
		ownp = kmem_zalloc(sizeof (md_mn_req_owner_t), KM_SLEEP);
		p->d.flags &= ~MD_MN_MM_SPAWN_THREAD;
		bcopy(&p->d, ownp, sizeof (md_mn_req_owner_t));
		if (thread_create(NULL, 0, mirror_owner_thread, (caddr_t)ownp,
		    0, &p0, TS_RUN, 60) == NULL) {
			kmem_free(ownp, sizeof (md_mn_req_owner_t));
			return (EFAULT);
		} else {
			return (0);
		}
	}

	/*
	 * If setting owner to NULL, this is being done because the owner has
	 * died and therefore we set OPT_NOT_DONE to ensure that the
	 * mirror is marked as "Needs Maintenance" and that an optimized
	 * resync will be done when we resync the mirror, Also clear the
	 * PREVENT_CHANGE flag and remove the last resync region from the
	 * overlap tree.
	 */
	if (p->d.owner == 0) {
		md_mps_t	*ps;
		int		i;

		md_ioctl_readerexit(lock);
		un = md_ioctl_writerlock(lock, ui);
		/*
		 * If the ABR capability is not set and the pass_num is non-zero
		 * there is need to perform an optimized resync
		 * Therefore set OPT_NOT_DONE, setup the resync_bm and set
		 * the submirrors as resync targets.
		 */
		if (!(ui->ui_tstate & MD_ABR_CAP) && un->un_pass_num) {
			MD_STATUS(un) |= MD_UN_OPT_NOT_DONE;

			(void) mddb_reread_rr(setno, un->un_rr_dirty_recid);
			bcopy((caddr_t)un->un_dirty_bm,
			    (caddr_t)un->un_resync_bm,
			    howmany(un->un_rrd_num, NBBY));
			for (i = 0; i < NMIRROR; i++) {
				if ((SUBMIRROR_IS_READABLE(un, i)) ||
				    SMS_BY_INDEX_IS(un, i,
				    SMS_OFFLINE_RESYNC))
					un->un_sm[i].sm_flags |=
					    MD_SM_RESYNC_TARGET;
			}
		}
		mutex_enter(&un->un_owner_mx);
		un->un_owner_state &= ~MD_MN_MM_PREVENT_CHANGE;
		mutex_exit(&un->un_owner_mx);
		ps = un->un_rs_prev_overlap;
		if ((ps != NULL) && (ps->ps_flags & MD_MPS_ON_OVERLAP)) {
			mirror_overlap_tree_remove(ps);
			ps->ps_firstblk = 0;
			ps->ps_lastblk = 0;
		}
		md_ioctl_writerexit(lock);
		un = md_ioctl_readerlock(lock, ui);
	}

	mutex_enter(&un->un_owner_mx);
	if (!(un->un_owner_state & MM_MN_BECOME_OWNER)) {
		/*
		 * If we are not trying to become owner ourselves check
		 * to see if we have to change the owner
		 */
		if (un->un_mirror_owner == p->d.owner) {
			/*
			 * No need to change owner,
			 * Clear/set PREVENT_CHANGE bit
			 */
			if (p->d.flags & MD_MN_MM_PREVENT_CHANGE) {
				un->un_owner_state |= MM_MN_PREVENT_CHANGE;
			} else if (p->d.flags & MD_MN_MM_ALLOW_CHANGE) {
				un->un_owner_state &= ~MM_MN_PREVENT_CHANGE;
			}
			mutex_exit(&un->un_owner_mx);
			return (0);
		}
	}

	/*
	 * Disallow ownership change if previously requested to. This can only
	 * be reset by issuing a request with MD_MN_MM_ALLOW_CHANGE set in the
	 * flags field.
	 */
	if ((un->un_owner_state & MM_MN_PREVENT_CHANGE) &&
	    !(p->d.flags & MD_MN_MM_ALLOW_CHANGE)) {
		mutex_exit(&un->un_owner_mx);
#ifdef DEBUG
		cmn_err(CE_WARN, "mirror_ioctl: Node %x attempted to become "
		    "owner while node %x has exclusive access to %s",
		    p->d.owner, un->un_mirror_owner, md_shortname(MD_SID(un)));
#endif
		return (EAGAIN);
	}
	if (p->d.owner == md_mn_mynode_id) {
		/*
		 * I'm becoming the mirror owner. Flag this so that the
		 * message sender can change the in-core owner when all
		 * nodes have processed this message
		 */
		un->un_owner_state &= ~MM_MN_OWNER_SENT;
		un->un_owner_state |= MM_MN_BECOME_OWNER;
		un->un_owner_state |= (p->d.flags & MD_MN_MM_PREVENT_CHANGE) ?
		    MM_MN_PREVENT_CHANGE : 0;
		un->un_owner_state &= (p->d.flags & MD_MN_MM_ALLOW_CHANGE) ?
		    ~MM_MN_PREVENT_CHANGE : ~0;

		mutex_exit(&un->un_owner_mx);
	} else if ((un->un_mirror_owner == md_mn_mynode_id) ||
	    un->un_owner_state & MM_MN_BECOME_OWNER) {
		mutex_exit(&un->un_owner_mx);

		/*
		 * I'm releasing ownership. Block and drain i/o. This also
		 * blocks until any in-progress resync record update completes.
		 */
		md_ioctl_readerexit(lock);
		un = md_ioctl_writerlock(lock, ui);
		/* Block the resync thread */
		mutex_enter(&un->un_rs_thread_mx);
		un->un_rs_thread_flags |= MD_RI_BLOCK_OWNER;
		mutex_exit(&un->un_rs_thread_mx);
		mutex_enter(&un->un_owner_mx);
		un->un_mirror_owner = p->d.owner;

		/* Sets node owner of un_rr_dirty record */
		if (un->un_rr_dirty_recid)
			(void) mddb_setowner(un->un_rr_dirty_recid, p->d.owner);
		un->un_owner_state &= ~MM_MN_BECOME_OWNER;
		un->un_owner_state |= (p->d.flags & MD_MN_MM_PREVENT_CHANGE) ?
		    MM_MN_PREVENT_CHANGE : 0;
		un->un_owner_state &= (p->d.flags & MD_MN_MM_ALLOW_CHANGE) ?
		    ~MM_MN_PREVENT_CHANGE : ~0;
		mutex_exit(&un->un_owner_mx);
		/*
		 * Allow further i/o to occur. Any write() from another node
		 * will now cause another ownership change to occur.
		 */
		md_ioctl_writerexit(lock);
	} else {
		/* Update the in-core mirror owner */
		un->un_mirror_owner = p->d.owner;
		/* Sets node owner of un_rr_dirty record */
		if (un->un_rr_dirty_recid)
			(void) mddb_setowner(un->un_rr_dirty_recid, p->d.owner);
		un->un_owner_state |= (p->d.flags & MD_MN_MM_PREVENT_CHANGE) ?
		    MM_MN_PREVENT_CHANGE : 0;
		un->un_owner_state &= (p->d.flags & MD_MN_MM_ALLOW_CHANGE) ?
		    ~MM_MN_PREVENT_CHANGE : ~0;
		mutex_exit(&un->un_owner_mx);
	}
	return (0);
}
/*
 * mirror_allocate_hotspare:
 * ------------------------
 * Called to allocate a hotspare for a failed component. This function is
 * called by the MD_MN_ALLOCATE_HOTSPARE ioctl.
 */
static int
mirror_allocate_hotspare(md_alloc_hotsp_params_t *p, IOLOCK *lockp)
{
	set_t		setno;
	mm_unit_t	*un;

#ifdef DEBUG
	if (mirror_debug_flag)
		printf("mirror_allocate_hotspare: mnum,sm,comp = %x, %x, %x\n",
		    p->mnum, p->sm, p->comp);
#endif

	if ((un = mirror_getun(p->mnum, &p->mde, WR_LOCK, lockp)) == NULL)
		return (EINVAL);

	/* This function is only valid for a multi-node set */
	setno = MD_MIN2SET(p->mnum);
	if (!MD_MNSET_SETNO(setno)) {
		return (EINVAL);
	}
	(void) check_comp_4_hotspares(un, p->sm, p->comp, MD_HOTSPARE_NO_XMIT,
	    p->hs_id, lockp);
	md_ioctl_writerexit(lockp);
	return (0);
}

/*
 * mirror_get_owner_status:
 * -----------------------
 * Return the status of a previously issued ioctl to change ownership. This is
 * required for soft-partition support as the request to change mirror owner
 * needs to be run from a separate daemon thread.
 *
 * Returns:
 *	0	Success (contents of un_mirror_owner_status placed in 'flags')
 *	EINVAL	Invalid unit
 */
static int
mirror_get_owner_status(md_mn_own_status_t *p, IOLOCK *lock)
{
	mm_unit_t	*un;
	set_t		setno;

	if ((un = mirror_getun(p->mnum, &p->mde, RD_LOCK, lock)) == NULL)
		return (EINVAL);

	setno = MD_MIN2SET(p->mnum);
	if (!MD_MNSET_SETNO(setno)) {
		return (EINVAL);
	}

	p->flags = un->un_mirror_owner_status;
	return (0);
}

/*
 * mirror_set_state:
 * ---------------
 * Called to set the state of the component of a submirror to the specified
 * value. This function is called by the MD_MN_SET_STATE ioctl.
 */
static int
mirror_set_state(md_set_state_params_t *p, IOLOCK *lockp)
{
	mm_unit_t		*un;
	mm_submirror_t		*sm;
	mm_submirror_ic_t	*smic;
	md_m_shared_t		*shared;
	set_t			setno;

#ifdef DEBUG
	if (mirror_debug_flag)
		printf("mirror_set_state: mnum,sm,comp,state, hs_id = %x, "
		    "%x, %x, %x %x\n", p->mnum, p->sm, p->comp,
		    p->state, p->hs_id);
#endif
	if ((un = mirror_getun(p->mnum, &p->mde, WR_LOCK, lockp)) == NULL)
		return (EINVAL);

	/* This function is only valid for a multi-node set */
	setno = MD_MIN2SET(p->mnum);
	if (!MD_MNSET_SETNO(setno)) {
		return (EINVAL);
	}
	sm = &un->un_sm[p->sm];
	smic = &un->un_smic[p->sm];

	/* Set state in component and update ms_flags */
	shared = (md_m_shared_t *)
	    (*(smic->sm_shared_by_indx))(sm->sm_dev, sm, p->comp);
	/*
	 * If a CS_ERRED state is being sent, verify that the sender
	 * has the same view of the component that this node currently has.
	 *
	 * There is a case where the sender was sending a CS_ERRED when a
	 * component was in error, but before the sender returns from
	 * ksend_message the component has been hotspared and resync'd.
	 *
	 * In this case, the hs_id will be different from the shared ms_hs_id,
	 * so the component has already been hotspared.  Just return in this
	 * case.
	 */
	if (p->state == CS_ERRED) {
		if (shared->ms_hs_id != p->hs_id) {
#ifdef DEBUG
			if (mirror_debug_flag) {
				printf("mirror_set_state: short circuit "
				    "hs_id=0x%x, ms_hs_id=0x%x\n",
				    p->hs_id, shared->ms_hs_id);
			}
#endif
			/* release the block on writes to the mirror */
			mirror_resume_writes(un);
			md_ioctl_writerexit(lockp);
			return (0);
		}
	}

	/*
	 * If the device is newly errored then make sure that it is
	 * closed. Closing the device allows for the RCM framework
	 * to unconfigure the device if required.
	 */
	if (!(shared->ms_state & CS_ERRED) && (p->state & CS_ERRED) &&
	    (shared->ms_flags & MDM_S_ISOPEN)) {
		void		(*get_dev)();
		ms_cd_info_t	cd;

		get_dev = (void (*)())md_get_named_service(sm->sm_dev, 0,
		    "get device", 0);
		(void) (*get_dev)(sm->sm_dev, sm, p->comp, &cd);

		md_layered_close(cd.cd_dev, MD_OFLG_NULL);
		shared->ms_flags &= ~MDM_S_ISOPEN;
	}

	shared->ms_state = p->state;
	uniqtime32(&shared->ms_timestamp);

	if (p->state == CS_ERRED) {
		shared->ms_flags |= MDM_S_NOWRITE;
	} else
		shared->ms_flags &= ~MDM_S_NOWRITE;

	shared->ms_flags &= ~MDM_S_IOERR;
	un->un_changecnt++;
	shared->ms_lasterrcnt = un->un_changecnt;

	/* Update state in submirror */
	mirror_set_sm_state(sm, smic, SMS_RUNNING, 0);
	/*
	 * Commit the state change to the metadb, only the master will write
	 * to disk
	 */
	mirror_commit(un, SMI2BIT(p->sm), 0);

	/* release the block on writes to the mirror */
	mirror_resume_writes(un);

	/* generate NOTIFY events for error state changes */
	if (p->state == CS_ERRED) {
		SE_NOTIFY(EC_SVM_STATE, ESC_SVM_ERRED, SVM_TAG_METADEVICE,
		    MD_UN2SET(un), MD_SID(un));
	} else if (p->state == CS_LAST_ERRED) {
		SE_NOTIFY(EC_SVM_STATE, ESC_SVM_LASTERRED, SVM_TAG_METADEVICE,
		    MD_UN2SET(un), MD_SID(un));
	}
	md_ioctl_writerexit(lockp);
	return (0);
}

/*
 * mirror_suspend_writes:
 * ---------------------
 * Called to suspend writes to a mirror region. The flag un_suspend_wr_flag is
 * tested in mirror_write_strategy, and if set all writes are blocked.
 * This function is called by the MD_MN_SUSPEND_WRITES ioctl.
 */
static int
mirror_suspend_writes(md_suspend_wr_params_t *p)
{
	set_t		setno;
	mm_unit_t	*un;

#ifdef DEBUG
	if (mirror_debug_flag)
		printf("mirror_suspend_writes: mnum = %x\n", p->mnum);
#endif
	if ((un = mirror_getun(p->mnum, &p->mde, NO_LOCK, NULL)) == NULL)
		return (EINVAL); /* No unit */

	/* This function is only valid for a multi-node set */
	setno = MD_MIN2SET(p->mnum);
	if (!MD_MNSET_SETNO(setno)) {
		return (EINVAL);
	}

	/*
	 * Mark the resync as blocked. This will stop any currently running
	 * thread and will prevent a new resync from attempting to perform
	 * i/o
	 */
	mutex_enter(&un->un_rs_thread_mx);
	un->un_rs_thread_flags |= MD_RI_BLOCK;
	mutex_exit(&un->un_rs_thread_mx);

	mutex_enter(&un->un_suspend_wr_mx);
	un->un_suspend_wr_flag = 1;
	mutex_exit(&un->un_suspend_wr_mx);

	return (0);
}

/*
 * mirror_set_capability:
 * ------------------------
 * Called to set or clear a capability for a mirror
 * called by the MD_MN_SET_CAP ioctl.
 */
static int
mirror_set_capability(md_mn_setcap_params_t *p, IOLOCK *lockp)
{
	set_t		setno;
	mm_unit_t	*un;
	mdi_unit_t	*ui;

#ifdef DEBUG
	if (mirror_debug_flag)
		printf("mirror_set_capability: mnum = %x\n", p->mnum);
#endif
	if ((un = mirror_getun(p->mnum, &p->mde, RD_LOCK, lockp)) == NULL)
		return (EINVAL);

	/* This function is only valid for a multi-node set */
	setno = MD_MIN2SET(p->mnum);
	if (!MD_MNSET_SETNO(setno)) {
		return (EINVAL);
	}
	ui = MDI_UNIT(p->mnum);

	if (p->sc_set & DKV_ABR_CAP) {
		ui->ui_tstate |= MD_ABR_CAP; /* Set ABR capability */
		/* Clear DRL and set owner to 0 if no resync active */
		mirror_process_unit_resync(un);
		if (!(un->c.un_status & MD_UN_RESYNC_ACTIVE)) {
			mutex_enter(&un->un_owner_mx);
			un->un_mirror_owner = 0;
			mutex_exit(&un->un_owner_mx);
		}
	} else {
		ui->ui_tstate &= ~MD_ABR_CAP; /* Clear ABR capability */
	}
	if (p->sc_set & DKV_DMR_CAP) {
		ui->ui_tstate |= MD_DMR_CAP; /* Set DMR capability */
	} else {
		ui->ui_tstate &= ~MD_DMR_CAP; /* Clear DMR capability */
	}
	return (0);
}

/*
 * mirror_choose_owner:
 * ------------------------
 * Called to choose an owner for a mirror resync. Can be called when starting
 * resync or by the MD_MN_SET_MM_OWNER ioctl with the MD_MN_MM_CHOOSE_OWNER flag
 * set. The ioctl is called with this flag set when we are in the cluster
 * reconfig and we wish to set a new owner for a resync whose owner has left
 * the cluster. We use a resync owner count to implement a round robin
 * allocation of resync owners. We send a message to the master including
 * this count and the message handler uses it to select an owner from the
 * nodelist and then sends a SET_MM_OWNER message to the chosen node to
 * become the owner.
 *
 * Input:
 *	un	- unit reference
 *	ownp	- owner information (if non-NULL)
 */
int
mirror_choose_owner(mm_unit_t *un, md_mn_req_owner_t *ownp)
{
	set_t		setno;
	md_mn_msg_chooseid_t	*msg;

	/* This function is only valid for a multi-node set */
	setno = MD_UN2SET(un);
	if (!MD_MNSET_SETNO(setno)) {
		return (EINVAL);
	}


#ifdef DEBUG
	if (mirror_debug_flag)
		printf("send choose owner message, mnum = %x,"
		    "rcnt = %d\n", MD_SID(un), md_set[setno].s_rcnt);
#endif

	/*
	 * setup message with current resync count
	 * and then increment the count. If we're called with a non-NULL
	 * owner then we are reestablishing the owner of the mirror. In this
	 * case we have to flag this to the message handler and set rcnt to
	 * the new owner node.
	 */
	msg = kmem_zalloc(sizeof (md_mn_msg_chooseid_t), KM_SLEEP);
	msg->msg_chooseid_mnum = MD_SID(un);
	if (ownp == NULL) {
		mutex_enter(&md_mx);
		msg->msg_chooseid_rcnt = md_set[setno].s_rcnt;
		md_set[setno].s_rcnt++;
		mutex_exit(&md_mx);
		msg->msg_chooseid_set_node = B_FALSE;
	} else {
		msg->msg_chooseid_rcnt = ownp->owner;
		msg->msg_chooseid_set_node = B_TRUE;
	}

	/*
	 * Spawn a thread to issue the ksend_message() call so that we can
	 * drop the ioctl lock hierarchy that is blocking further rpc.metad and
	 * commd set ownership checking.
	 */
	if (thread_create(NULL, 0, mirror_choose_owner_thread, (caddr_t)msg,
	    0, &p0, TS_RUN, 60) == NULL) {
		kmem_free(msg, sizeof (md_mn_msg_chooseid_t));
		return (EFAULT);
	} else {
		return (0);
	}
}

/*
 * mirror_get_status:
 * ----------------------------------
 * Called by nodes which are not the master node of the cluster. Obtains the
 * master abr state and the submirror status for each valid submirror of the
 * unit so that the status returned by metastat is consistent across the
 * cluster.
 * We update tstate for the mirror and both the sm_flag and the sm_state for
 * each submirror.
 *
 * Input:
 *	un	mirror to obtain status from
 *
 * Calling Convention:
 *	writerlock (either ioctl or unit) must be held
 */
void
mirror_get_status(mm_unit_t *un, IOLOCK *lockp)
{
	mm_submirror_t		*sm;
	int			smi;
	int			rval;
	md_mn_kresult_t		*kres;
	md_mn_msg_mir_state_t	msg;
	md_mn_msg_mir_state_res_t	*res;
	set_t			setno = MD_UN2SET(un);
	mdi_unit_t		*ui = MDI_UNIT(MD_SID(un));


	ASSERT(ui->ui_lock & MD_UL_WRITER);

	/*
	 * Get all of the information for the mirror.
	 */
	bzero(&msg, sizeof (msg));
	msg.mir_state_mnum = MD_SID(un);

	/*
	 * Must drop the writerlock over ksend_message since another
	 * thread on this node could be running a higher class message
	 * and be trying grab the readerlock.
	 *
	 * If we are in the context of an ioctl, drop the ioctl lock.
	 * lockp holds the list of locks held.
	 */
	if (lockp) {
		IOLOCK_RETURN_RELEASE(0, lockp);
	} else {
		md_unit_writerexit(ui);
	}

	kres = kmem_alloc(sizeof (md_mn_kresult_t), KM_SLEEP);
	rval = mdmn_ksend_message(setno, MD_MN_MSG_GET_MIRROR_STATE,
	    MD_MSGF_NO_BCAST | MD_MSGF_NO_LOG, 0, (char *)&msg,
	    sizeof (msg), kres);

	/* if the node hasn't yet joined, it's Ok. */
	if ((!MDMN_KSEND_MSG_OK(rval, kres)) &&
	    (kres->kmmr_comm_state != MDMNE_NOT_JOINED)) {
		mdmn_ksend_show_error(rval, kres, "GET_MIRROR_STATE");
		cmn_err(CE_WARN, "ksend_message failure: GET_MIRROR_STATE");
	}

	/* if dropped the lock previously, regain it */
	if (lockp) {
		IOLOCK_RETURN_REACQUIRE(lockp);
	} else {
		/*
		 * Reacquire dropped locks and update acquirecnts
		 * appropriately.
		 */
		(void) md_unit_writerlock(ui);
	}

	/*
	 * Check to see if we've got a believable amount of returned data.
	 * If not, we simply return as there is no usable information.
	 */
	if (kres->kmmr_res_size < sizeof (*res)) {
		cmn_err(CE_WARN, "GET_MIRROR_STATE: returned %d bytes, expected"
		    " %d\n", kres->kmmr_res_size, (int)sizeof (*res));
		kmem_free(kres, sizeof (md_mn_kresult_t));
		return;
	}

	/*
	 * Copy the results from the call back into our sm_state/sm_flags
	 */
	res = (md_mn_msg_mir_state_res_t *)kres->kmmr_res_data;
#ifdef DEBUG
	if (mirror_debug_flag)
		printf("mirror_get_status: %s\n", md_shortname(MD_SID(un)));
#endif
	for (smi = 0; smi < NMIRROR; smi++) {
		sm = &un->un_sm[smi];
#ifdef DEBUG
		if (mirror_debug_flag) {
			printf("curr state %4x, new state %4x\n", sm->sm_state,
			    res->sm_state[smi]);
			printf("curr_flags %4x, new flags %4x\n", sm->sm_flags,
			    res->sm_flags[smi]);
		}
#endif
		sm->sm_state = res->sm_state[smi];
		sm->sm_flags = res->sm_flags[smi];
	}

	/* Set ABR if set on the Master node */
	ui->ui_tstate |= (res->mir_tstate & MD_ABR_CAP);

	kmem_free(kres, sizeof (md_mn_kresult_t));
}

/*
 * mirror_get_mir_state:
 * -------------------
 * Obtain the ABR state of a mirror and the state of all submirrors from the
 * master node for the unit specified in sm_state->mnum.
 * Called by MD_MN_GET_MIRROR_STATE ioctl.
 */
static int
mirror_get_mir_state(md_mn_get_mir_state_t *p, IOLOCK *lockp)
{
	mm_unit_t	*un;
	set_t		setno;
	md_error_t	mde;

	mdclrerror(&mde);

	if ((un = mirror_getun(p->mnum, &mde, WR_LOCK, lockp)) == NULL) {
		return (EINVAL);
	}
	setno = MD_MIN2SET(p->mnum);
	if (!MD_MNSET_SETNO(setno)) {
		return (EINVAL);
	}

	/*
	 * We've now got a writerlock on the unit structure (so no-one can
	 * modify the incore values) and we'll now send the message to the
	 * master node. Since we're only called as part of a reconfig cycle
	 * we don't need to release the unit locks across the ksend_message as
	 * only the master node will process it, and we never send this to
	 * ourselves if we're the master.
	 */

	mirror_get_status(un, lockp);

	return (0);
}

static int
mirror_admin_ioctl(int cmd, void *data, int mode, IOLOCK *lockp)
{
	size_t	sz = 0;
	void	*d = NULL;
	int	err = 0;

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

		err = mirror_set(d, mode);
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

		err = mirror_get(d, mode, lockp);
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

		err = mirror_reset((md_i_reset_t *)d);
		break;
	}

	case MD_IOCSETSYNC:
	case MD_MN_SETSYNC:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (md_resync_ioctl_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = mirror_ioctl_resync((md_resync_ioctl_t *)d, lockp);
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

		err = mirror_get_resync((md_resync_ioctl_t *)d);
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

		err = comp_replace((replace_params_t *)d, lockp);
		break;
	}

	case MD_IOCOFFLINE:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (md_i_off_on_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = mirror_offline((md_i_off_on_t *)d, lockp);
		break;
	}

	case MD_IOCONLINE:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (md_i_off_on_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = mirror_online((md_i_off_on_t *)d, lockp);
		break;
	}

	case MD_IOCDETACH:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (md_detach_params_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = mirror_detach((md_detach_params_t *)d, lockp);
		break;
	}

	case MD_IOCATTACH:
	{

		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (md_att_struct_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = mirror_attach((md_att_struct_t *)d, lockp);
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

		err = mirror_getdevs(d, mode, lockp);
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

		err = mirror_grow(d, lockp);
		break;
	}

	case MD_IOCCHANGE:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (md_mirror_params_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = mirror_change((md_mirror_params_t *)d, lockp);
		break;
	}

	case MD_IOCPROBE_DEV:
	{
		md_probedev_impl_t	*p = NULL;
		md_probedev_t		*ph = NULL;
		daemon_queue_t		*hdr = NULL;
		int			i;
		size_t			sz2 = 0;

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

		ph = (struct md_probedev *)d;

		p->probe.nmdevs = ph->nmdevs;
		(void) strcpy(p->probe.test_name, ph->test_name);
		bcopy(&ph->md_driver, &(p->probe.md_driver),
		    sizeof (md_driver_t));

		if ((p->probe.nmdevs < 1) ||
		    (strstr(p->probe.test_name, "probe") == NULL)) {
			err = EINVAL;
			goto free_mem;
		}


		sz2 = sizeof (minor_t) * p->probe.nmdevs;
		p->probe.mnum_list = (uint64_t)(uintptr_t)kmem_alloc(sz2,
		    KM_SLEEP);

		if (ddi_copyin((void *)(uintptr_t)ph->mnum_list,
		    (void *)(uintptr_t)p->probe.mnum_list, sz2, mode)) {
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
			if ((uintptr_t)p->probe.mnum_list)
				kmem_free((void *)(uintptr_t)
				    p->probe.mnum_list, sz2);

			kmem_free(p, sizeof (md_probedev_impl_t));
		}
		break;
	}

	case MD_MN_SET_MM_OWNER:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (md_set_mmown_params_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		err = mirror_set_owner((md_set_mmown_params_t *)d, lockp);
		break;
	}

	case MD_MN_GET_MM_OWNER:
	{
		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (md_set_mmown_params_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		err = mirror_get_owner((md_set_mmown_params_t *)d, lockp);
		break;
	}

	case MD_MN_MM_OWNER_STATUS:
	{
		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (md_mn_own_status_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		err = mirror_get_owner_status((md_mn_own_status_t *)d, lockp);
		break;
	}

	case MD_MN_SET_STATE:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (md_set_state_params_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err  = mirror_set_state((md_set_state_params_t *)d, lockp);
		break;
	}

	case MD_MN_SUSPEND_WRITES:
	{
		if (! (mode & FREAD))
			return (EACCES);

		sz = sizeof (md_suspend_wr_params_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		err = mirror_suspend_writes((md_suspend_wr_params_t *)d);
		break;
	}

	case MD_MN_RESYNC:
	{
		sz = sizeof (md_mn_rs_params_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode) != 0) {
			err = EFAULT;
			break;
		}

		err = mirror_resync_message((md_mn_rs_params_t *)d, lockp);
		break;
	}

	case MD_MN_ALLOCATE_HOTSPARE:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (md_alloc_hotsp_params_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err  = mirror_allocate_hotspare((md_alloc_hotsp_params_t *)d,
		    lockp);
		break;
	}

	case MD_MN_POKE_HOTSPARES:
	{
		(void) poke_hotspares();
		break;
	}

	case MD_MN_SET_CAP:
	{
		if (! (mode & FWRITE))
			return (EACCES);

		sz = sizeof (md_mn_setcap_params_t);
		d = kmem_alloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err  = mirror_set_capability((md_mn_setcap_params_t *)d,
		    lockp);
		break;
	}

	case MD_MN_GET_MIRROR_STATE:
	{
		sz = sizeof (md_mn_get_mir_state_t);
		d = kmem_zalloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = mirror_get_mir_state((md_mn_get_mir_state_t *)d,
		    lockp);
		break;
	}

	case MD_MN_RR_DIRTY:
	{
		sz = sizeof (md_mn_rr_dirty_params_t);
		d = kmem_zalloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = mirror_set_dirty_rr((md_mn_rr_dirty_params_t *)d);
		break;
	}

	case MD_MN_RR_CLEAN:
	{
		md_mn_rr_clean_params_t tmp;

		/* get the first part of the structure to find the size */
		if (ddi_copyin(data, &tmp, sizeof (tmp), mode)) {
			err = EFAULT;
			break;
		}

		sz = MDMN_RR_CLEAN_PARAMS_SIZE(&tmp);
		d = kmem_zalloc(sz, KM_SLEEP);

		if (ddi_copyin(data, d, sz, mode)) {
			err = EFAULT;
			break;
		}

		err = mirror_set_clean_rr((md_mn_rr_clean_params_t *)d);
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

int
md_mirror_ioctl(
	dev_t		ddi_dev,
	int		cmd,
	void		*data,
	int		mode,
	IOLOCK		*lockp
)
{
	minor_t		mnum = getminor(ddi_dev);
	mm_unit_t	*un;
	int		err = 0;

	/* handle admin ioctls */
	if (mnum == MD_ADM_MINOR)
		return (mirror_admin_ioctl(cmd, data, mode, lockp));

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
		struct dk_cinfo	*p;

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

		if ((err = mirror_get_geom(un, p)) == 0) {
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

		if ((err = mirror_get_vtoc(un, vtoc)) != 0) {
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
			err = mirror_set_vtoc(un, vtoc);

		kmem_free(vtoc, sizeof (*vtoc));
		return (err);
	}

	case DKIOCGEXTVTOC:
	{
		struct extvtoc	*extvtoc;

		if (! (mode & FREAD))
			return (EACCES);

		extvtoc = kmem_zalloc(sizeof (*extvtoc), KM_SLEEP);

		if ((err = mirror_get_extvtoc(un, extvtoc)) != 0) {
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
			err = mirror_set_extvtoc(un, extvtoc);

		kmem_free(extvtoc, sizeof (*extvtoc));
		return (err);
	}

	case DKIOCGAPART:
	{
		struct dk_map	dmp;

		if ((err = mirror_get_cgapart(un, &dmp)) != 0) {
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

	case DKIOCGETVOLCAP:
	{
		volcap_t	vc;
		mdi_unit_t	*ui;

		/* Only valid for MN sets */
		if (!MD_MNSET_SETNO(MD_MIN2SET(mnum)))
			return (EINVAL);

		ui = MDI_UNIT(mnum);
		if (! (mode & FREAD))
			return (EACCES);

		vc.vc_info = DKV_ABR_CAP | DKV_DMR_CAP;
		vc.vc_set = 0;
		if (ui->ui_tstate & MD_ABR_CAP) {
			vc.vc_set |= DKV_ABR_CAP;
		}
		if (ddi_copyout(&vc, data, sizeof (volcap_t), mode))
			err = EFAULT;
		return (err);
	}

	case DKIOCSETVOLCAP:
	{
		volcap_t	vc;
		volcapset_t	volcap = 0;
		mdi_unit_t	*ui;

		/* Only valid for MN sets */
		if (!MD_MNSET_SETNO(MD_MIN2SET(mnum)))
			return (EINVAL);

		ui = MDI_UNIT(mnum);
		if (! (mode & FWRITE))
			return (EACCES);

		if (ddi_copyin(data, &vc, sizeof (volcap_t), mode))
			return (EFAULT);

		/* Not valid if a submirror is offline */
		if (un->c.un_status & MD_UN_OFFLINE_SM) {
			return (EINVAL);
		}
		if (ui->ui_tstate & MD_ABR_CAP)
			volcap |= DKV_ABR_CAP;
		/* Only send capability message if there is a change */
		if ((vc.vc_set & (DKV_ABR_CAP)) != volcap)
			err = mdmn_send_capability_message(mnum, vc, lockp);
		return (err);
	}

	case DKIOCDMR:
	{
		vol_directed_rd_t	*vdr;

#ifdef _MULTI_DATAMODEL
		vol_directed_rd32_t	*vdr32;
#endif	/* _MULTI_DATAMODEL */

		/* Only valid for MN sets */
		if (!MD_MNSET_SETNO(MD_MIN2SET(mnum)))
			return (EINVAL);

		vdr = kmem_zalloc(sizeof (vol_directed_rd_t), KM_NOSLEEP);
		if (vdr == NULL)
			return (ENOMEM);

#ifdef _MULTI_DATAMODEL
		vdr32 = kmem_zalloc(sizeof (vol_directed_rd32_t), KM_NOSLEEP);
		if (vdr32 == NULL) {
			kmem_free(vdr, sizeof (vol_directed_rd_t));
			return (ENOMEM);
		}

		switch (ddi_model_convert_from(mode & FMODELS)) {
		case DDI_MODEL_ILP32:
			/*
			 * If we're called from a higher-level driver we don't
			 * need to manipulate the data. Its already been done by
			 * the caller.
			 */
			if (!(mode & FKIOCTL)) {
				if (ddi_copyin(data, vdr32, sizeof (*vdr32),
				    mode)) {
					kmem_free(vdr, sizeof (*vdr));
					return (EFAULT);
				}
				vdr->vdr_flags = vdr32->vdr_flags;
				vdr->vdr_offset = vdr32->vdr_offset;
				vdr->vdr_nbytes = vdr32->vdr_nbytes;
				vdr->vdr_data =
				    (void *)(uintptr_t)vdr32->vdr_data;
				vdr->vdr_side = vdr32->vdr_side;
				break;
			}
			/* FALLTHROUGH */

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
#endif	/* _MULTI_DATAMODEL */

		err = mirror_directed_read(ddi_dev, vdr, mode);

		if (err == 0) {
#ifdef _MULTI_DATAMODEL
			switch (ddi_model_convert_from(mode & FMODELS)) {
			case DDI_MODEL_ILP32:
				if (!(mode & FKIOCTL)) {
					vdr32->vdr_flags = vdr->vdr_flags;
					vdr32->vdr_offset = vdr->vdr_offset;
					vdr32->vdr_side = vdr->vdr_side;
					vdr32->vdr_bytesread =
					    vdr->vdr_bytesread;
					bcopy(vdr->vdr_side_name,
					    vdr32->vdr_side_name,
					    sizeof (vdr32->vdr_side_name));

					if (ddi_copyout(vdr32, data,
					    sizeof (*vdr32), mode)) {
						err = EFAULT;
					}
					break;
				}
				/* FALLTHROUGH */

			case DDI_MODEL_NONE:
				if (ddi_copyout(vdr, data, sizeof (*vdr), mode))
					err = EFAULT;
				break;
			}
#else	/* ! _MULTI_DATAMODEL */
			if (ddi_copyout(vdr, data, sizeof (*vdr), mode))
				err = EFAULT;
#endif	/* _MULTI_DATAMODEL */
			if (vdr->vdr_flags &  DKV_DMR_ERROR)
				err = EIO;
		}

#ifdef _MULTI_DATAMODEL
		kmem_free(vdr32, sizeof (*vdr32));
#endif	/* _MULTI_DATAMODEL */

		kmem_free(vdr, sizeof (*vdr));

		return (err);
	}

	default:
		return (ENOTTY);
	}
}

/*
 * rename named service entry points and support functions
 */

/*
 * rename/exchange role swap functions
 *
 * most of these are handled by generic role swap functions
 */

/*
 * MDRNM_UPDATE_KIDS
 * rename/exchange of our child or grandchild
 */
void
mirror_renexch_update_kids(md_rendelta_t *delta, md_rentxn_t *rtxnp)
{
	mm_submirror_t		*sm;
	int			smi;

	ASSERT(rtxnp);
	ASSERT((MDRNOP_RENAME == rtxnp->op) || (rtxnp->op == MDRNOP_EXCHANGE));
	ASSERT(rtxnp->recids);
	ASSERT(delta);
	ASSERT(delta->unp);
	ASSERT(delta->old_role == MDRR_PARENT);
	ASSERT(delta->new_role == MDRR_PARENT);

	/*
	 * since our role isn't changing (parent->parent)
	 * one of our children must be changing
	 * find the child being modified, and update
	 * our notion of it
	 */
	for (smi = 0; smi < NMIRROR; smi++) {
		mm_unit_t *un = (mm_unit_t *)delta->unp;

		if (!SMS_BY_INDEX_IS(un, smi, SMS_INUSE)) {
			continue;
		}
		sm = &un->un_sm[smi];

		if (md_getminor(sm->sm_dev) == rtxnp->from.mnum) {
			sm->sm_dev = md_makedevice(md_major, rtxnp->to.mnum);
			sm->sm_key = rtxnp->to.key;
			break;
		}
	}

	md_store_recid(&rtxnp->rec_idx, rtxnp->recids, delta->unp);
}

/*
 * exchange down (self->child)
 */
void
mirror_exchange_self_update_from_down(
	md_rendelta_t	*delta,
	md_rentxn_t	*rtxnp
)
{
	int			smi;
	mm_submirror_t		*found;
	minor_t			from_min, to_min;
	sv_dev_t		sv;

	ASSERT(rtxnp);
	ASSERT(MDRNOP_EXCHANGE == rtxnp->op);
	ASSERT(rtxnp->recids);
	ASSERT(rtxnp->rec_idx >= 0);
	ASSERT(delta);
	ASSERT(delta->unp);
	ASSERT(delta->uip);
	ASSERT(delta->old_role == MDRR_SELF);
	ASSERT(delta->new_role == MDRR_CHILD);
	ASSERT(md_getminor(delta->dev) == rtxnp->from.mnum);

	from_min = rtxnp->from.mnum;
	to_min = rtxnp->to.mnum;

	/*
	 * self id changes in our own unit struct
	 */

	MD_SID(delta->unp) = to_min;

	/*
	 * parent identifier need not change
	 */

	/*
	 * point the set array pointers at the "new" unit and unit in-cores
	 * Note: the other half of this transfer is done in the "update_to"
	 * exchange named service.
	 */

	MDI_VOIDUNIT(to_min) = delta->uip;
	MD_VOIDUNIT(to_min) = delta->unp;

	/*
	 * transfer kstats
	 */

	delta->uip->ui_kstat = rtxnp->to.kstatp;

	/*
	 * the unit in-core reference to the get next link's id changes
	 */

	delta->uip->ui_link.ln_id = to_min;

	/*
	 * find the child whose identity we're assuming
	 */

	for (found = NULL, smi = 0; !found && smi < NMIRROR; smi++) {
		mm_submirror_t		*sm;
		mm_unit_t		*un = (mm_unit_t *)delta->unp;

		if (!SMS_BY_INDEX_IS(un, smi, SMS_INUSE)) {
			continue;
		}
		sm = &un->un_sm[smi];

		if (md_getminor(sm->sm_dev) == to_min) {
			found = sm;
		}
	}
	ASSERT(found);

	/*
	 * Update the sub-mirror's identity
	 */
	found->sm_dev = md_makedevice(md_major, rtxnp->from.mnum);
	sv.key = found->sm_key;

	ASSERT(rtxnp->from.key != MD_KEYWILD);
	ASSERT(rtxnp->from.key != MD_KEYBAD);

	found->sm_key = rtxnp->from.key;

	/*
	 * delete the key for the old sub-mirror from the name space
	 */

	sv.setno = MD_MIN2SET(from_min);
	md_rem_names(&sv, 1);

	/*
	 * and store the record id (from the unit struct) into recids
	 */

	md_store_recid(&rtxnp->rec_idx, rtxnp->recids, delta->unp);
}

/*
 * exchange down (parent->self)
 */
void
mirror_exchange_parent_update_to(
		md_rendelta_t	*delta,
		md_rentxn_t	*rtxnp
)
{
	int			smi;
	mm_submirror_t		*found;
	minor_t			from_min, to_min;
	sv_dev_t		sv;

	ASSERT(rtxnp);
	ASSERT(MDRNOP_EXCHANGE == rtxnp->op);
	ASSERT(rtxnp->recids);
	ASSERT(rtxnp->rec_idx >= 0);
	ASSERT(delta);
	ASSERT(delta->unp);
	ASSERT(delta->uip);
	ASSERT(delta->old_role == MDRR_PARENT);
	ASSERT(delta->new_role == MDRR_SELF);
	ASSERT(md_getminor(delta->dev) == rtxnp->to.mnum);

	from_min = rtxnp->from.mnum;
	to_min = rtxnp->to.mnum;

	/*
	 * self id changes in our own unit struct
	 */

	MD_SID(delta->unp) = from_min;

	/*
	 * parent identifier need not change
	 */

	/*
	 * point the set array pointers at the "new" unit and unit in-cores
	 * Note: the other half of this transfer is done in the "update_to"
	 * exchange named service.
	 */

	MDI_VOIDUNIT(from_min) = delta->uip;
	MD_VOIDUNIT(from_min) = delta->unp;

	/*
	 * transfer kstats
	 */

	delta->uip->ui_kstat = rtxnp->from.kstatp;

	/*
	 * the unit in-core reference to the get next link's id changes
	 */

	delta->uip->ui_link.ln_id = from_min;

	/*
	 * find the child whose identity we're assuming
	 */

	for (found = NULL, smi = 0; !found && smi < NMIRROR; smi++) {
		mm_submirror_t		*sm;
		mm_unit_t		*un = (mm_unit_t *)delta->unp;

		if (!SMS_BY_INDEX_IS(un, smi, SMS_INUSE)) {
			continue;
		}
		sm = &un->un_sm[smi];

		if (md_getminor(sm->sm_dev) == from_min) {
			found = sm;
		}
	}
	ASSERT(found);

	/*
	 * Update the sub-mirror's identity
	 */
	found->sm_dev = md_makedevice(md_major, rtxnp->to.mnum);
	sv.key = found->sm_key;

	ASSERT(rtxnp->to.key != MD_KEYWILD);
	ASSERT(rtxnp->to.key != MD_KEYBAD);

	found->sm_key = rtxnp->to.key;

	/*
	 * delete the key for the old sub-mirror from the name space
	 */

	sv.setno = MD_MIN2SET(to_min);
	md_rem_names(&sv, 1);

	/*
	 * and store the record id (from the unit struct) into recids
	 */

	md_store_recid(&rtxnp->rec_idx, rtxnp->recids, delta->unp);
}

/*
 * MDRNM_LIST_URKIDS: named svc entry point
 * all all delta entries appropriate for our children onto the
 * deltalist pointd to by dlpp
 */
int
mirror_rename_listkids(md_rendelta_t **dlpp, md_rentxn_t *rtxnp)
{
	minor_t			from_min, to_min;
	mm_unit_t		*from_un;
	md_rendelta_t		*new, *p;
	int			smi;
	int			n_children;
	mm_submirror_t		*sm;

	ASSERT(rtxnp);
	ASSERT(dlpp);
	ASSERT((rtxnp->op == MDRNOP_EXCHANGE) || (rtxnp->op == MDRNOP_RENAME));

	from_min = rtxnp->from.mnum;
	to_min = rtxnp->to.mnum;
	n_children = 0;

	if (!MDI_UNIT(from_min) || !(from_un = MD_UNIT(from_min))) {
		(void) mdmderror(&rtxnp->mde, MDE_UNIT_NOT_SETUP, from_min);
		return (-1);
	}

	for (p = *dlpp; p && p->next != NULL; p = p->next) {
		/* NULL */
	}

	for (smi = 0; smi < NMIRROR; smi++) {
		minor_t	child_min;

		if (!SMS_BY_INDEX_IS(from_un, smi, SMS_INUSE)) {
			continue;
		}

		sm = &from_un->un_sm[smi];
		child_min = md_getminor(sm->sm_dev);

		p = new = md_build_rendelta(MDRR_CHILD,
		    to_min == child_min? MDRR_SELF: MDRR_CHILD,
		    sm->sm_dev, p,
		    MD_UNIT(child_min), MDI_UNIT(child_min),
		    &rtxnp->mde);

		if (!new) {
			if (mdisok(&rtxnp->mde)) {
				(void) mdsyserror(&rtxnp->mde, ENOMEM);
			}
			return (-1);
		}
		++n_children;
	}

	return (n_children);
}

/*
 * support routine for MDRNM_CHECK
 */
static int
mirror_may_renexch_self(
	mm_unit_t	*un,
	mdi_unit_t	*ui,
	md_rentxn_t	*rtxnp)
{
	minor_t			 from_min;
	minor_t			 to_min;
	bool_t			 toplevel;
	bool_t			 related;
	int			 smi;
	mm_submirror_t		*sm;

	from_min = rtxnp->from.mnum;
	to_min = rtxnp->to.mnum;

	if (!un || !ui) {
		(void) mdmderror(&rtxnp->mde, MDE_RENAME_CONFIG_ERROR,
		    from_min);
		return (EINVAL);
	}

	ASSERT(MD_CAPAB(un) & MD_CAN_META_CHILD);
	if (!(MD_CAPAB(un) & MD_CAN_META_CHILD)) {
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
		/*
		 * check for a swap with our child
		 */
		for (smi = 0; smi < NMIRROR; smi++) {

			if (!SMS_BY_INDEX_IS(un, smi, SMS_INUSE)) {
				continue;
			}

			sm = &un->un_sm[smi];
			if (md_getminor(sm->sm_dev) == to_min) {
				related |= TRUE;
			}
		}
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
 * Named service entry point: MDRNM_CHECK
 */
intptr_t
mirror_rename_check(
	md_rendelta_t	*delta,
	md_rentxn_t	*rtxnp)
{
	mm_submirror_t		*sm;
	mm_submirror_ic_t	*smic;
	md_m_shared_t		*shared;
	int			ci;
	int			i;
	int			compcnt;
	mm_unit_t		*un;
	int			err = 0;

	ASSERT(delta);
	ASSERT(rtxnp);
	ASSERT(delta->unp);
	ASSERT(delta->uip);
	ASSERT((rtxnp->op == MDRNOP_RENAME) || (rtxnp->op == MDRNOP_EXCHANGE));

	if (!delta || !rtxnp || !delta->unp || !delta->uip) {
		(void) mdsyserror(&rtxnp->mde, EINVAL);
		return (EINVAL);
	}

	un = (mm_unit_t *)delta->unp;

	for (i = 0; i < NMIRROR; i++) {
		sm = &un->un_sm[i];
		smic = &un->un_smic[i];

		if (!SMS_IS(sm, SMS_INUSE))
			continue;

		ASSERT(smic->sm_get_component_count);
		if (!smic->sm_get_component_count) {
			(void) mdmderror(&rtxnp->mde, MDE_RENAME_CONFIG_ERROR,
			    md_getminor(delta->dev));
			return (ENXIO);
		}

		compcnt = (*(smic->sm_get_component_count))(sm->sm_dev, un);

		for (ci = 0; ci < compcnt; ci++) {

			ASSERT(smic->sm_shared_by_indx);
			if (!smic->sm_shared_by_indx) {
				(void) mdmderror(&rtxnp->mde,
				    MDE_RENAME_CONFIG_ERROR,
				    md_getminor(delta->dev));
				return (ENXIO);
			}

			shared = (md_m_shared_t *)(*(smic->sm_shared_by_indx))
			    (sm->sm_dev, sm, ci);

			ASSERT(shared);
			if (!shared) {
				(void) mdmderror(&rtxnp->mde,
				    MDE_RENAME_CONFIG_ERROR,
				    md_getminor(delta->dev));
				return (ENXIO);
			}

			if (shared->ms_hs_id != 0) {
				(void) mdmderror(&rtxnp->mde,
				    MDE_SM_FAILED_COMPS,
				    md_getminor(delta->dev));
				return (EIO);
			}

			switch (shared->ms_state) {
			case CS_OKAY:
				break;

			case CS_RESYNC:
				(void) mdmderror(&rtxnp->mde,
				    MDE_RESYNC_ACTIVE,
				    md_getminor(delta->dev));
				return (EBUSY);

			default:
				(void) mdmderror(&rtxnp->mde,
				    MDE_SM_FAILED_COMPS,
				    md_getminor(delta->dev));
				return (EINVAL);
			}

		}
	}

	/* self does additional checks */
	if (delta->old_role == MDRR_SELF) {
		err = mirror_may_renexch_self(un, delta->uip, rtxnp);
	}

	return (err);
}

/* end of rename/exchange */
