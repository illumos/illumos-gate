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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2010, Intel Corporation.
 * All rights reserved.
 */

/*
 * DR memory support routines.
 */

#include <sys/note.h>
#include <sys/debug.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/kmem.h>
#include <sys/kobj.h>
#include <sys/conf.h>
#include <sys/dditypes.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ddi_impldefs.h>
#include <sys/ndi_impldefs.h>
#include <sys/sysmacros.h>
#include <sys/machsystm.h>
#include <sys/promif.h>
#include <sys/lgrp.h>
#include <sys/mem_config.h>
#include <vm/seg_kmem.h>
#include <vm/page.h>

#include <sys/dr.h>
#include <sys/dr_util.h>
#include <sys/drmach.h>

extern struct memlist	*phys_install;

/* TODO: push this reference below drmach line */
extern int		kcage_on;

/* for the DR*INTERNAL_ERROR macros.  see sys/dr.h. */
static char *dr_ie_fmt = "dr_mem_acpi.c %d";

static void		dr_init_mem_unit_data(dr_mem_unit_t *mp);

/*
 * dr_mem_unit_t.sbm_flags
 */
#define	DR_MFLAG_RESERVED	0x01	/* mem unit reserved for delete */
#define	DR_MFLAG_SOURCE		0x02	/* source brd of copy/rename op */
#define	DR_MFLAG_TARGET		0x04	/* target brd of copy/rename op */
#define	DR_MFLAG_RELOWNER	0x20	/* memory release (delete) owner */
#define	DR_MFLAG_RELDONE	0x40	/* memory release (delete) done */

/* helper macros */
#define	_ptob64(p) ((uint64_t)(p) << PAGESHIFT)
#define	_b64top(b) ((pgcnt_t)((b) >> PAGESHIFT))

static struct memlist *
dr_get_memlist(dr_mem_unit_t *mp)
{
	struct memlist	*mlist = NULL;
	sbd_error_t	*err;
	static fn_t	f = "dr_get_memlist";

	PR_MEM("%s for %s...\n", f, mp->sbm_cm.sbdev_path);

	/*
	 * Return cached memlist, if present.
	 * This memlist will be present following an
	 * unconfigure (a.k.a: detach) of this memunit.
	 * It should only be used in the case were a configure
	 * is bringing this memunit back in without going
	 * through the disconnect and connect states.
	 */
	if (mp->sbm_mlist) {
		PR_MEM("%s: found cached memlist\n", f);

		mlist = memlist_dup(mp->sbm_mlist);
	} else {
		uint64_t basepa = _ptob64(mp->sbm_basepfn);

		/* attempt to construct a memlist using phys_install */

		/* round down to slice base address */
		basepa &= ~mp->sbm_alignment_mask;

		/* get a copy of phys_install to edit */
		memlist_read_lock();
		mlist = memlist_dup(phys_install);
		memlist_read_unlock();

		/* trim lower irrelevant span */
		if (mlist)
			mlist = memlist_del_span(mlist, 0ull, basepa);

		/* trim upper irrelevant span */
		if (mlist) {
			uint64_t endpa, toppa;

			toppa = mp->sbm_slice_top;
			endpa = _ptob64(physmax + 1);
			if (endpa > toppa)
				mlist = memlist_del_span(
				    mlist, toppa,
				    endpa - toppa);
		}

		if (mlist) {
			/* successfully built a memlist */
			PR_MEM("%s: derived memlist from phys_install\n", f);
		}

		/* if no mlist yet, try platform layer */
		if (!mlist) {
			err = drmach_mem_get_memlist(
			    mp->sbm_cm.sbdev_id, &mlist);
			if (err) {
				DRERR_SET_C(&mp->sbm_cm.sbdev_error, &err);
				mlist = NULL; /* paranoia */
			}
		}
	}

	PR_MEM("%s: memlist for %s\n", f, mp->sbm_cm.sbdev_path);
	PR_MEMLIST_DUMP(mlist);

	return (mlist);
}

/*ARGSUSED*/
void
dr_release_mem(dr_common_unit_t *cp)
{
}

void
dr_attach_mem(dr_handle_t *hp, dr_common_unit_t *cp)
{
	dr_mem_unit_t	*mp = (dr_mem_unit_t *)cp;
	struct memlist	*ml, *mc;
	sbd_error_t	*err;
	static fn_t	f = "dr_attach_mem";
	uint64_t	dr_physmax;

	PR_MEM("%s...\n", f);

	dr_lock_status(hp->h_bd);
	err = drmach_configure(cp->sbdev_id, 0);
	dr_unlock_status(hp->h_bd);
	if (err) {
		DRERR_SET_C(&cp->sbdev_error, &err);
		return;
	}

	ml = dr_get_memlist(mp);

	/* Skip memory with address above plat_dr_physmax or kpm_size */
	dr_physmax = plat_dr_physmax ? ptob(plat_dr_physmax) : UINT64_MAX;
	if (kpm_size < dr_physmax)
		dr_physmax = kpm_size;
	ml = memlist_del_span(ml, dr_physmax, UINT64_MAX - dr_physmax);

	for (mc = ml; mc; mc = mc->ml_next) {
		int		 rv;
		sbd_error_t	*err;

		rv = kphysm_add_memory_dynamic(
		    (pfn_t)btop(mc->ml_address),
		    (pgcnt_t)btop(mc->ml_size));
		if (rv != KPHYSM_OK) {
			/*
			 * translate kphysm error and
			 * store in devlist error
			 */
			switch (rv) {
			case KPHYSM_ERESOURCE:
				rv = ESBD_NOMEM;
				break;

			case KPHYSM_EFAULT:
				rv = ESBD_FAULT;
				break;

			default:
				rv = ESBD_INTERNAL;
				break;
			}

			if (rv == ESBD_INTERNAL) {
				DR_DEV_INTERNAL_ERROR(&mp->sbm_cm);
			} else
				dr_dev_err(CE_WARN, &mp->sbm_cm, rv);
			break;
		}

		err = drmach_mem_add_span(
		    mp->sbm_cm.sbdev_id, mc->ml_address, mc->ml_size);
		if (err) {
			DRERR_SET_C(&mp->sbm_cm.sbdev_error, &err);
			break;
		}
	}

	memlist_delete(ml);
	dr_init_mem_unit_data(mp);

	/* back out if configure failed */
	if (mp->sbm_cm.sbdev_error != NULL) {
		dr_lock_status(hp->h_bd);
		err = drmach_unconfigure(cp->sbdev_id, 0);
		if (err)
			sbd_err_clear(&err);
		dr_unlock_status(hp->h_bd);
	}
}

/*ARGSUSED*/
void
dr_detach_mem(dr_handle_t *hp, dr_common_unit_t *cp)
{
}

/*
 * This routine acts as a wrapper for kphysm_del_span_query in order to
 * support potential memory holes in a board's physical address space.
 * It calls kphysm_del_span_query for each node in a memlist and accumulates
 * the results in *mp.
 */
static int
dr_del_mlist_query(struct memlist *mlist, memquery_t *mp)
{
	int		 rv = 0;

	if (mlist == NULL)
		cmn_err(CE_WARN, "dr_del_mlist_query: mlist=NULL\n");

	mp->phys_pages = 0;
	mp->managed = 0;
	mp->nonrelocatable = 0;
	mp->first_nonrelocatable = 0;
	mp->last_nonrelocatable = 0;

	return (rv);
}

/*
 * NOTE: This routine is only partially smart about multiple
 *	 mem-units.  Need to make mem-status structure smart
 *	 about them also.
 */
int
dr_mem_status(dr_handle_t *hp, dr_devset_t devset, sbd_dev_stat_t *dsp)
{
	int		m, mix;
	memquery_t	mq;
	dr_board_t	*bp;
	dr_mem_unit_t	*mp;
	sbd_mem_stat_t	*msp;
	static fn_t	f = "dr_mem_status";

	bp = hp->h_bd;
	devset &= DR_DEVS_PRESENT(bp);

	for (m = mix = 0; m < MAX_MEM_UNITS_PER_BOARD; m++) {
		int		rv;
		sbd_error_t	*err;
		drmach_status_t	 pstat;
		dr_mem_unit_t	*p_mp;

		if (DEVSET_IN_SET(devset, SBD_COMP_MEM, m) == 0)
			continue;

		mp = dr_get_mem_unit(bp, m);

		if (mp->sbm_cm.sbdev_state == DR_STATE_EMPTY) {
			/* present, but not fully initialized */
			continue;
		}

		if (mp->sbm_cm.sbdev_id == (drmachid_t)0)
			continue;

		/* fetch platform status */
		err = drmach_status(mp->sbm_cm.sbdev_id, &pstat);
		if (err) {
			DRERR_SET_C(&mp->sbm_cm.sbdev_error, &err);
			continue;
		}

		msp = &dsp->d_mem;
		bzero((caddr_t)msp, sizeof (*msp));

		(void) strlcpy(msp->ms_cm.c_id.c_name, pstat.type,
		    sizeof (msp->ms_cm.c_id.c_name));
		msp->ms_cm.c_id.c_type = mp->sbm_cm.sbdev_type;
		msp->ms_cm.c_id.c_unit = mp->sbm_cm.sbdev_unum;
		msp->ms_cm.c_cond = mp->sbm_cm.sbdev_cond;
		msp->ms_cm.c_busy = mp->sbm_cm.sbdev_busy | pstat.busy;
		msp->ms_cm.c_time = mp->sbm_cm.sbdev_time;
		msp->ms_cm.c_ostate = mp->sbm_cm.sbdev_ostate;

		msp->ms_totpages = mp->sbm_npages;
		msp->ms_basepfn = mp->sbm_basepfn;
		msp->ms_pageslost = mp->sbm_pageslost;
		msp->ms_cage_enabled = kcage_on;

		if (mp->sbm_flags & DR_MFLAG_RESERVED)
			p_mp = mp->sbm_peer;
		else
			p_mp = NULL;

		if (p_mp == NULL) {
			msp->ms_peer_is_target = 0;
			msp->ms_peer_ap_id[0] = '\0';
		} else if (p_mp->sbm_flags & DR_MFLAG_RESERVED) {
			char *path = kmem_alloc(MAXPATHLEN, KM_SLEEP);
			char *minor;

			/*
			 * b_dip doesn't have to be held for ddi_pathname()
			 * because the board struct (dr_board_t) will be
			 * destroyed before b_dip detaches.
			 */
			(void) ddi_pathname(bp->b_dip, path);
			minor = strchr(p_mp->sbm_cm.sbdev_path, ':');

			(void) snprintf(msp->ms_peer_ap_id,
			    sizeof (msp->ms_peer_ap_id), "%s%s",
			    path, (minor == NULL) ? "" : minor);

			kmem_free(path, MAXPATHLEN);

			if (p_mp->sbm_flags & DR_MFLAG_TARGET)
				msp->ms_peer_is_target = 1;
		}

		/*
		 * kphysm_del_span_query can report non-reloc pages = total
		 * pages for memory that is not yet configured
		 */
		if (mp->sbm_cm.sbdev_state != DR_STATE_UNCONFIGURED) {
			struct memlist *ml;

			ml = dr_get_memlist(mp);
			rv = ml ? dr_del_mlist_query(ml, &mq) : -1;
			memlist_delete(ml);

			if (rv == KPHYSM_OK) {
				msp->ms_managed_pages = mq.managed;
				msp->ms_noreloc_pages = mq.nonrelocatable;
				msp->ms_noreloc_first =
				    mq.first_nonrelocatable;
				msp->ms_noreloc_last =
				    mq.last_nonrelocatable;
				msp->ms_cm.c_sflags = 0;
				if (mq.nonrelocatable &&
				    drmach_copy_rename_need_suspend(
				    mp->sbm_cm.sbdev_id)) {
					SBD_SET_SUSPEND(SBD_CMD_UNCONFIGURE,
					    msp->ms_cm.c_sflags);
				}
			} else {
				PR_MEM("%s: kphysm_del_span_query() = %d\n",
				    f, rv);
			}
		}

		/*
		 * Check source unit state during copy-rename
		 */
		if ((mp->sbm_flags & DR_MFLAG_SOURCE) &&
		    (mp->sbm_cm.sbdev_state == DR_STATE_UNREFERENCED ||
		    mp->sbm_cm.sbdev_state == DR_STATE_RELEASE))
			msp->ms_cm.c_ostate = SBD_STAT_CONFIGURED;

		mix++;
		dsp++;
	}

	return (mix);
}

/*ARGSUSED*/
int
dr_pre_attach_mem(dr_handle_t *hp, dr_common_unit_t **devlist, int devnum)
{
	int		err_flag = 0;
	int		d;
	sbd_error_t	*err;
	static fn_t	f = "dr_pre_attach_mem";

	PR_MEM("%s...\n", f);

	for (d = 0; d < devnum; d++) {
		dr_mem_unit_t	*mp = (dr_mem_unit_t *)devlist[d];
		dr_state_t	state;

		cmn_err(CE_CONT, "OS configure %s", mp->sbm_cm.sbdev_path);

		state = mp->sbm_cm.sbdev_state;
		switch (state) {
		case DR_STATE_UNCONFIGURED:
			PR_MEM("%s: recovering from UNCONFIG for %s\n",
			    f, mp->sbm_cm.sbdev_path);

			/* use memlist cached by dr_post_detach_mem_unit */
			ASSERT(mp->sbm_mlist != NULL);
			PR_MEM("%s: re-configuring cached memlist for %s:\n",
			    f, mp->sbm_cm.sbdev_path);
			PR_MEMLIST_DUMP(mp->sbm_mlist);

			/* kphysm del handle should be have been freed */
			ASSERT((mp->sbm_flags & DR_MFLAG_RELOWNER) == 0);

			/*FALLTHROUGH*/

		case DR_STATE_CONNECTED:
			PR_MEM("%s: reprogramming mem hardware on %s\n",
			    f, mp->sbm_cm.sbdev_bp->b_path);

			PR_MEM("%s: enabling %s\n",
			    f, mp->sbm_cm.sbdev_path);

			err = drmach_mem_enable(mp->sbm_cm.sbdev_id);
			if (err) {
				DRERR_SET_C(&mp->sbm_cm.sbdev_error, &err);
				err_flag = 1;
			}
			break;

		default:
			dr_dev_err(CE_WARN, &mp->sbm_cm, ESBD_STATE);
			err_flag = 1;
			break;
		}

		/* exit for loop if error encountered */
		if (err_flag)
			break;
	}

	return (err_flag ? -1 : 0);
}

/*ARGSUSED*/
int
dr_post_attach_mem(dr_handle_t *hp, dr_common_unit_t **devlist, int devnum)
{
	int		d;
	static fn_t	f = "dr_post_attach_mem";

	PR_MEM("%s...\n", f);

	for (d = 0; d < devnum; d++) {
		dr_mem_unit_t	*mp = (dr_mem_unit_t *)devlist[d];
		struct memlist	*mlist, *ml;

		mlist = dr_get_memlist(mp);

		/*
		 * Verify the memory really did successfully attach
		 * by checking for its existence in phys_install.
		 */
		memlist_read_lock();
		if (memlist_intersect(phys_install, mlist) == 0) {
			memlist_read_unlock();

			DR_DEV_INTERNAL_ERROR(&mp->sbm_cm);

			PR_MEM("%s: %s memlist not in phys_install",
			    f, mp->sbm_cm.sbdev_path);

			memlist_delete(mlist);
			continue;
		}
		memlist_read_unlock();

		for (ml = mlist; ml != NULL; ml = ml->ml_next) {
			sbd_error_t *err;

			err = drmach_mem_add_span(
			    mp->sbm_cm.sbdev_id,
			    ml->ml_address,
			    ml->ml_size);
			if (err)
				DRERR_SET_C(&mp->sbm_cm.sbdev_error, &err);
		}

		memlist_delete(mlist);

		/*
		 * Destroy cached memlist, if any.
		 * There will be a cached memlist in sbm_mlist if
		 * this board is being configured directly after
		 * an unconfigure.
		 * To support this transition, dr_post_detach_mem
		 * left a copy of the last known memlist in sbm_mlist.
		 * This memlist could differ from any derived from
		 * hardware if while this memunit was last configured
		 * the system detected and deleted bad pages from
		 * phys_install.  The location of those bad pages
		 * will be reflected in the cached memlist.
		 */
		if (mp->sbm_mlist) {
			memlist_delete(mp->sbm_mlist);
			mp->sbm_mlist = NULL;
		}
	}

	return (0);
}

/*ARGSUSED*/
int
dr_pre_detach_mem(dr_handle_t *hp, dr_common_unit_t **devlist, int devnum)
{
	return (-1);
}

/*ARGSUSED*/
int
dr_post_detach_mem(dr_handle_t *hp, dr_common_unit_t **devlist, int devnum)
{
	return (-1);
}

/*
 * Successful return from this function will have the memory
 * handle in bp->b_dev[..mem-unit...].sbm_memhandle allocated
 * and waiting.  This routine's job is to select the memory that
 * actually has to be released (detached) which may not necessarily
 * be the same memory node that came in in devlist[],
 * i.e. a copy-rename is needed.
 */
/*ARGSUSED*/
int
dr_pre_release_mem(dr_handle_t *hp, dr_common_unit_t **devlist, int devnum)
{
	return (-1);
}

/*ARGSUSED*/
void
dr_release_mem_done(dr_common_unit_t *cp)
{
}

/*ARGSUSED*/
int
dr_disconnect_mem(dr_mem_unit_t *mp)
{
	return (-1);
}

/*ARGSUSED*/
int
dr_cancel_mem(dr_mem_unit_t *s_mp)
{
	return (-1);
}

void
dr_init_mem_unit(dr_mem_unit_t *mp)
{
	dr_state_t	new_state;

	if (DR_DEV_IS_ATTACHED(&mp->sbm_cm)) {
		new_state = DR_STATE_CONFIGURED;
		mp->sbm_cm.sbdev_cond = SBD_COND_OK;
	} else if (DR_DEV_IS_PRESENT(&mp->sbm_cm)) {
		new_state = DR_STATE_CONNECTED;
		mp->sbm_cm.sbdev_cond = SBD_COND_OK;
	} else if (mp->sbm_cm.sbdev_id != (drmachid_t)0) {
		new_state = DR_STATE_OCCUPIED;
	} else {
		new_state = DR_STATE_EMPTY;
	}

	if (DR_DEV_IS_PRESENT(&mp->sbm_cm))
		dr_init_mem_unit_data(mp);

	/* delay transition until fully initialized */
	dr_device_transition(&mp->sbm_cm, new_state);
}

static void
dr_init_mem_unit_data(dr_mem_unit_t *mp)
{
	drmachid_t	id = mp->sbm_cm.sbdev_id;
	drmach_mem_info_t	minfo;
	sbd_error_t	*err;
	static fn_t	f = "dr_init_mem_unit_data";

	PR_MEM("%s...\n", f);

	/* a little sanity checking */
	ASSERT(mp->sbm_peer == NULL);
	ASSERT(mp->sbm_flags == 0);

	if (err = drmach_mem_get_info(id, &minfo)) {
		DRERR_SET_C(&mp->sbm_cm.sbdev_error, &err);
		return;
	}
	mp->sbm_basepfn = _b64top(minfo.mi_basepa);
	mp->sbm_npages = _b64top(minfo.mi_size);
	mp->sbm_alignment_mask = minfo.mi_alignment_mask;
	mp->sbm_slice_base = minfo.mi_slice_base;
	mp->sbm_slice_top = minfo.mi_slice_top;
	mp->sbm_slice_size = minfo.mi_slice_size;

	PR_MEM("%s: %s (basepfn = 0x%lx, npgs = %ld)\n",
	    f, mp->sbm_cm.sbdev_path, mp->sbm_basepfn, mp->sbm_npages);
}
