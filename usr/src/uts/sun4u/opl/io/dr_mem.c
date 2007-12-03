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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * DR memory support routines.
 */

#include <sys/note.h>
#include <sys/debug.h>
#include <sys/types.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/dditypes.h>
#include <sys/kmem.h>
#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ddi_impldefs.h>
#include <sys/ndi_impldefs.h>
#include <sys/sysmacros.h>
#include <sys/machsystm.h>
#include <sys/spitregs.h>
#include <sys/cpuvar.h>
#include <sys/promif.h>
#include <vm/seg_kmem.h>
#include <sys/lgrp.h>
#include <sys/platform_module.h>

#include <vm/page.h>

#include <sys/dr.h>
#include <sys/dr_util.h>
#include <sys/drmach.h>
#include <sys/kobj.h>

extern struct memlist	*phys_install;
extern vnode_t		*retired_pages;

/* TODO: push this reference below drmach line */
extern int		kcage_on;

/* for the DR*INTERNAL_ERROR macros.  see sys/dr.h. */
static char *dr_ie_fmt = "dr_mem.c %d";

typedef enum {
	DR_TP_INVALID = -1,
	DR_TP_SAME,
	DR_TP_LARGE,
	DR_TP_NONRELOC,
	DR_TP_FLOATING
} dr_target_pref_t;

static int		dr_post_detach_mem_unit(dr_mem_unit_t *mp);
static int		dr_reserve_mem_spans(memhandle_t *mhp,
				struct memlist *mlist);
static int		dr_select_mem_target(dr_handle_t *hp,
				dr_mem_unit_t *mp, struct memlist *ml);
static void		dr_init_mem_unit_data(dr_mem_unit_t *mp);
static struct memlist	*dr_memlist_del_retired_pages(struct memlist *ml);
static dr_target_pref_t	dr_get_target_preference(dr_handle_t *hp,
				dr_mem_unit_t *t_mp, dr_mem_unit_t *s_mp,
				struct memlist *s_ml, struct memlist *x_ml,
				struct memlist *b_ml);

static int		memlist_canfit(struct memlist *s_mlist,
				struct memlist *t_mlist);
static int		dr_del_mlist_query(struct memlist *mlist,
				memquery_t *mp);
static struct memlist	*dr_get_copy_mlist(struct memlist *s_ml,
				struct memlist *t_ml, dr_mem_unit_t *s_mp,
				dr_mem_unit_t *t_mp);
static struct memlist	*dr_get_nonreloc_mlist(struct memlist *s_ml,
				dr_mem_unit_t *s_mp);
static int		dr_memlist_canfit(struct memlist *s_mlist,
				struct memlist *t_mlist, dr_mem_unit_t *s_mp,
				dr_mem_unit_t *t_mp);

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
		basepa &= ~(mp->sbm_slice_size - 1);

		/* get a copy of phys_install to edit */
		memlist_read_lock();
		mlist = memlist_dup(phys_install);
		memlist_read_unlock();

		/* trim lower irrelevant span */
		if (mlist)
			mlist = memlist_del_span(mlist, 0ull, basepa);

		/* trim upper irrelevant span */
		if (mlist) {
			uint64_t endpa;

			basepa += mp->sbm_slice_size;
			endpa = _ptob64(physmax + 1);
			if (endpa > basepa)
				mlist = memlist_del_span(
				    mlist, basepa,
				    endpa - basepa);
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

typedef struct {
	kcondvar_t cond;
	kmutex_t lock;
	int error;
	int done;
} dr_release_mem_sync_t;

/*
 * Memory has been logically removed by the time this routine is called.
 */
static void
dr_mem_del_done(void *arg, int error)
{
	dr_release_mem_sync_t *ds = arg;

	mutex_enter(&ds->lock);
	ds->error = error;
	ds->done = 1;
	cv_signal(&ds->cond);
	mutex_exit(&ds->lock);
}

/*
 * When we reach here the memory being drained should have
 * already been reserved in dr_pre_release_mem().
 * Our only task here is to kick off the "drain" and wait
 * for it to finish.
 */
void
dr_release_mem(dr_common_unit_t *cp)
{
	dr_mem_unit_t	*mp = (dr_mem_unit_t *)cp;
	int		err;
	dr_release_mem_sync_t rms;
	static fn_t	f = "dr_release_mem";

	/* check that this memory unit has been reserved */
	if (!(mp->sbm_flags & DR_MFLAG_RELOWNER)) {
		DR_DEV_INTERNAL_ERROR(&mp->sbm_cm);
		return;
	}

	bzero((void *) &rms, sizeof (rms));

	mutex_init(&rms.lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&rms.cond, NULL, CV_DRIVER, NULL);

	mutex_enter(&rms.lock);
	err = kphysm_del_start(mp->sbm_memhandle,
	    dr_mem_del_done, (void *) &rms);
	if (err == KPHYSM_OK) {
		/* wait for completion or interrupt */
		while (!rms.done) {
			if (cv_wait_sig(&rms.cond, &rms.lock) == 0) {
				/* then there is a pending UNIX signal */
				(void) kphysm_del_cancel(mp->sbm_memhandle);

				/* wait for completion */
				while (!rms.done)
					cv_wait(&rms.cond, &rms.lock);
			}
		}
		/* get the result of the memory delete operation */
		err = rms.error;
	}
	mutex_exit(&rms.lock);

	cv_destroy(&rms.cond);
	mutex_destroy(&rms.lock);

	if (err != KPHYSM_OK) {
		int e_code;

		switch (err) {
			case KPHYSM_ENOWORK:
				e_code = ESBD_NOERROR;
				break;

			case KPHYSM_EHANDLE:
			case KPHYSM_ESEQUENCE:
				e_code = ESBD_INTERNAL;
				break;

			case KPHYSM_ENOTVIABLE:
				e_code = ESBD_MEM_NOTVIABLE;
				break;

			case KPHYSM_EREFUSED:
				e_code = ESBD_MEM_REFUSED;
				break;

			case KPHYSM_ENONRELOC:
				e_code = ESBD_MEM_NONRELOC;
				break;

			case KPHYSM_ECANCELLED:
				e_code = ESBD_MEM_CANCELLED;
				break;

			case KPHYSM_ERESOURCE:
				e_code = ESBD_MEMFAIL;
				break;

			default:
				cmn_err(CE_WARN,
				    "%s: unexpected kphysm error code %d,"
				    " id 0x%p",
				    f, err, mp->sbm_cm.sbdev_id);

				e_code = ESBD_IO;
				break;
		}

		if (e_code != ESBD_NOERROR) {
			dr_dev_err(CE_WARN, &mp->sbm_cm, e_code);
		}
	}
}

void
dr_attach_mem(dr_handle_t *hp, dr_common_unit_t *cp)
{
	_NOTE(ARGUNUSED(hp))

	dr_mem_unit_t	*mp = (dr_mem_unit_t *)cp;
	struct memlist	*ml, *mc;
	sbd_error_t	*err;
	static fn_t	f = "dr_attach_mem";

	PR_MEM("%s...\n", f);

	dr_lock_status(hp->h_bd);
	err = drmach_configure(cp->sbdev_id, 0);
	dr_unlock_status(hp->h_bd);
	if (err) {
		DRERR_SET_C(&cp->sbdev_error, &err);
		return;
	}

	ml = dr_get_memlist(mp);
	for (mc = ml; mc; mc = mc->next) {
		int		 rv;
		sbd_error_t	*err;

		rv = kphysm_add_memory_dynamic(
		    (pfn_t)(mc->address >> PAGESHIFT),
		    (pgcnt_t)(mc->size >> PAGESHIFT));
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
		    mp->sbm_cm.sbdev_id, mc->address, mc->size);
		if (err) {
			DRERR_SET_C(&mp->sbm_cm.sbdev_error, &err);
			break;
		}
	}

	memlist_delete(ml);

	/* back out if configure failed */
	if (mp->sbm_cm.sbdev_error != NULL) {
		dr_lock_status(hp->h_bd);
		err = drmach_unconfigure(cp->sbdev_id, 0);
		if (err)
			sbd_err_clear(&err);
		dr_unlock_status(hp->h_bd);
	}
}

static struct memlist *
dr_memlist_del_retired_pages(struct memlist *mlist)
{
	page_t		*pp;
	pfn_t		pfn;
	kmutex_t	*vphm;
	vnode_t		*vp = retired_pages;
	static fn_t	f = "dr_memlist_del_retired_pages";

	vphm = page_vnode_mutex(vp);
	mutex_enter(vphm);

	PR_MEM("%s\n", f);

	if ((pp = vp->v_pages) == NULL) {
		mutex_exit(vphm);
		return (mlist);
	}

	do {
		ASSERT(pp != NULL);
		ASSERT(pp->p_vnode == retired_pages);

		if (!page_try_reclaim_lock(pp, SE_SHARED, SE_RETIRED))
			continue;

		pfn = page_pptonum(pp);

		ASSERT((pp->p_offset >> PAGESHIFT) == pfn);
		/*
		 * Page retirement currently breaks large pages into PAGESIZE
		 * pages. If this changes, need to remove the assert and deal
		 * with different page sizes.
		 */
		ASSERT(pp->p_szc == 0);

		if (address_in_memlist(mlist, ptob(pfn), PAGESIZE)) {
			mlist = memlist_del_span(mlist, ptob(pfn), PAGESIZE);
			PR_MEM("deleted retired page 0x%lx (pfn 0x%lx) "
			    "from memlist\n", ptob(pfn), pfn);
		}

		page_unlock(pp);
	} while ((pp = pp->p_vpnext) != vp->v_pages);

	mutex_exit(vphm);

	return (mlist);
}

static int
dr_move_memory(dr_handle_t *hp, dr_mem_unit_t *s_mp, dr_mem_unit_t *t_mp)
{
	int		rv = -1;
	time_t		 copytime;
	drmachid_t	 cr_id;
	dr_sr_handle_t	*srhp = NULL;
	dr_board_t	*t_bp, *s_bp;
	struct memlist	*c_ml, *d_ml;
	sbd_error_t	*err;
	static fn_t	 f = "dr_move_memory";

	PR_MEM("%s: (INLINE) moving memory from %s to %s\n",
	    f,
	    s_mp->sbm_cm.sbdev_path,
	    t_mp->sbm_cm.sbdev_path);

	ASSERT(s_mp->sbm_flags & DR_MFLAG_SOURCE);
	ASSERT(s_mp->sbm_peer == t_mp);
	ASSERT(s_mp->sbm_mlist);

	ASSERT(t_mp->sbm_flags & DR_MFLAG_TARGET);
	ASSERT(t_mp->sbm_peer == s_mp);

	/*
	 * create a memlist of spans to copy by removing
	 * the spans that have been deleted, if any, from
	 * the full source board memlist.  s_mp->sbm_del_mlist
	 * will be NULL if there were no spans deleted from
	 * the source board.
	 */
	c_ml = memlist_dup(s_mp->sbm_mlist);
	d_ml = s_mp->sbm_del_mlist;
	while (d_ml != NULL) {
		c_ml = memlist_del_span(c_ml, d_ml->address, d_ml->size);
		d_ml = d_ml->next;
	}

	/*
	 * Remove retired pages from the copy list. The page content
	 * need not be copied since the pages are no longer in use.
	 */
	PR_MEM("%s: copy list before removing retired pages (if any):\n", f);
	PR_MEMLIST_DUMP(c_ml);

	c_ml = dr_memlist_del_retired_pages(c_ml);

	PR_MEM("%s: copy list after removing retired pages:\n", f);
	PR_MEMLIST_DUMP(c_ml);

	/*
	 * With parallel copy, it shouldn't make a difference which
	 * CPU is the actual master during copy-rename since all
	 * CPUs participate in the parallel copy anyway.
	 */
	affinity_set(CPU_CURRENT);

	err = drmach_copy_rename_init(
	    t_mp->sbm_cm.sbdev_id, s_mp->sbm_cm.sbdev_id, c_ml, &cr_id);
	if (err) {
		DRERR_SET_C(&s_mp->sbm_cm.sbdev_error, &err);
		affinity_clear();
		memlist_delete(c_ml);
		return (-1);
	}

	srhp = dr_get_sr_handle(hp);
	ASSERT(srhp);

	copytime = lbolt;

	/* Quiesce the OS.  */
	if (dr_suspend(srhp)) {
		cmn_err(CE_WARN, "%s: failed to quiesce OS"
		    " for copy-rename", f);

		err = drmach_copy_rename_fini(cr_id);
		if (err) {
			/*
			 * no error is expected since the program has
			 * not yet run.
			 */

			/* catch this in debug kernels */
			ASSERT(0);

			sbd_err_clear(&err);
		}

		/* suspend error reached via hp */
		s_mp->sbm_cm.sbdev_error = hp->h_err;
		hp->h_err = NULL;
		goto done;
	}

	drmach_copy_rename(cr_id);

	/* Resume the OS.  */
	dr_resume(srhp);

	copytime = lbolt - copytime;

	if (err = drmach_copy_rename_fini(cr_id))
		goto done;

	/*
	 * Rename memory for lgroup.
	 * Source and target board numbers are packaged in arg.
	 */
	s_bp = s_mp->sbm_cm.sbdev_bp;
	t_bp = t_mp->sbm_cm.sbdev_bp;

	lgrp_plat_config(LGRP_CONFIG_MEM_RENAME,
	    (uintptr_t)(s_bp->b_num | (t_bp->b_num << 16)));


	PR_MEM("%s: copy-rename elapsed time = %ld ticks (%ld secs)\n",
	    f, copytime, copytime / hz);

	rv = 0;
done:
	if (srhp)
		dr_release_sr_handle(srhp);
	if (err)
		DRERR_SET_C(&s_mp->sbm_cm.sbdev_error, &err);
	affinity_clear();

	return (rv);
}

/*
 * If detaching node contains memory that is "non-permanent"
 * then the memory adr's are simply cleared.  If the memory
 * is non-relocatable, then do a copy-rename.
 */
void
dr_detach_mem(dr_handle_t *hp, dr_common_unit_t *cp)
{
	int			rv = 0;
	dr_mem_unit_t		*s_mp = (dr_mem_unit_t *)cp;
	dr_mem_unit_t		*t_mp;
	dr_state_t		state;
	static fn_t		f = "dr_detach_mem";

	PR_MEM("%s...\n", f);

	/* lookup target mem unit and target board structure, if any */
	if (s_mp->sbm_flags & DR_MFLAG_SOURCE) {
		t_mp = s_mp->sbm_peer;
		ASSERT(t_mp != NULL);
		ASSERT(t_mp->sbm_peer == s_mp);
	} else {
		t_mp = NULL;
	}

	/* verify mem unit's state is UNREFERENCED */
	state = s_mp->sbm_cm.sbdev_state;
	if (state != DR_STATE_UNREFERENCED) {
		dr_dev_err(CE_IGNORE, &s_mp->sbm_cm, ESBD_STATE);
		return;
	}

	/* verify target mem unit's state is UNREFERENCED, if any */
	if (t_mp != NULL) {
		state = t_mp->sbm_cm.sbdev_state;
		if (state != DR_STATE_UNREFERENCED) {
			dr_dev_err(CE_IGNORE, &t_mp->sbm_cm, ESBD_STATE);
			return;
		}
	}

	/*
	 * If there is no target board (no copy/rename was needed), then
	 * we're done!
	 */
	if (t_mp == NULL) {
		sbd_error_t *err;
		/*
		 * Reprogram interconnect hardware and disable
		 * memory controllers for memory node that's going away.
		 */

		err = drmach_mem_disable(s_mp->sbm_cm.sbdev_id);
		if (err) {
			DRERR_SET_C(&s_mp->sbm_cm.sbdev_error, &err);
			rv = -1;
		}
	} else {
		rv = dr_move_memory(hp, s_mp, t_mp);
		PR_MEM("%s: %s memory COPY-RENAME (board %d -> %d)\n",
		    f,
		    rv ? "FAILED" : "COMPLETED",
		    s_mp->sbm_cm.sbdev_bp->b_num,
		    t_mp->sbm_cm.sbdev_bp->b_num);

		if (rv != 0)
			(void) dr_cancel_mem(s_mp);
	}

	if (rv == 0) {
		sbd_error_t *err;

		dr_lock_status(hp->h_bd);
		err = drmach_unconfigure(s_mp->sbm_cm.sbdev_id, 0);
		dr_unlock_status(hp->h_bd);
		if (err)
			sbd_err_clear(&err);
	}
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
	struct memlist	*ml;
	int		 rv = 0;


	if (mlist == NULL)
		cmn_err(CE_WARN, "dr_del_mlist_query: mlist=NULL\n");

	mp->phys_pages = 0;
	mp->managed = 0;
	mp->nonrelocatable = 0;
	mp->first_nonrelocatable = (pfn_t)-1;	/* XXX */
	mp->last_nonrelocatable = 0;

	for (ml = mlist; ml; ml = ml->next) {
		memquery_t mq;

		rv = kphysm_del_span_query(
		    _b64top(ml->address), _b64top(ml->size), &mq);
		if (rv)
			break;

		mp->phys_pages += mq.phys_pages;
		mp->managed += mq.managed;
		mp->nonrelocatable += mq.nonrelocatable;

		if (mq.nonrelocatable != 0) {
			if (mq.first_nonrelocatable < mp->first_nonrelocatable)
				mp->first_nonrelocatable =
				    mq.first_nonrelocatable;
			if (mq.last_nonrelocatable > mp->last_nonrelocatable)
				mp->last_nonrelocatable =
				    mq.last_nonrelocatable;
		}
	}

	if (mp->nonrelocatable == 0)
		mp->first_nonrelocatable = 0;	/* XXX */

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
	memdelstat_t	mdst;
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

		strncpy(msp->ms_cm.c_id.c_name, pstat.type,
		    sizeof (msp->ms_cm.c_id.c_name));
		msp->ms_cm.c_id.c_type = mp->sbm_cm.sbdev_type;
		msp->ms_cm.c_id.c_unit = SBD_NULL_UNIT;
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

			snprintf(msp->ms_peer_ap_id,
			    sizeof (msp->ms_peer_ap_id), "%s%s",
			    path, (minor == NULL) ? "" : minor);

			kmem_free(path, MAXPATHLEN);

			if (p_mp->sbm_flags & DR_MFLAG_TARGET)
				msp->ms_peer_is_target = 1;
		}

		if (mp->sbm_flags & DR_MFLAG_RELOWNER)
			rv = kphysm_del_status(mp->sbm_memhandle, &mdst);
		else
			rv = KPHYSM_EHANDLE;	/* force 'if' to fail */

		if (rv == KPHYSM_OK) {
			/*
			 * Any pages above managed is "free",
			 * i.e. it's collected.
			 */
			msp->ms_detpages += (uint_t)(mdst.collected +
			    mdst.phys_pages - mdst.managed);
		} else {
			/*
			 * If we're UNREFERENCED or UNCONFIGURED,
			 * then the number of detached pages is
			 * however many pages are on the board.
			 * I.e. detached = not in use by OS.
			 */
			switch (msp->ms_cm.c_ostate) {
			/*
			 * changed to use cfgadm states
			 *
			 * was:
			 *	case DR_STATE_UNREFERENCED:
			 *	case DR_STATE_UNCONFIGURED:
			 */
			case SBD_STAT_UNCONFIGURED:
				msp->ms_detpages = msp->ms_totpages;
				break;

			default:
				break;
			}
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
				if (mq.nonrelocatable) {
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

int
dr_pre_attach_mem(dr_handle_t *hp, dr_common_unit_t **devlist, int devnum)
{
	_NOTE(ARGUNUSED(hp))

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
			    f,
			    mp->sbm_cm.sbdev_path);

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

static void
dr_update_mc_memory()
{
	void		(*mc_update_mlist)(void);

	/*
	 * mc-opl is configured during drmach_mem_new but the memory
	 * has not been added to phys_install at that time.
	 * we must inform mc-opl to update the mlist after we
	 * attach or detach a system board.
	 */

	mc_update_mlist = (void (*)(void))
	    modgetsymvalue("opl_mc_update_mlist", 0);

	if (mc_update_mlist != NULL) {
		(*mc_update_mlist)();
	}
}

int
dr_post_attach_mem(dr_handle_t *hp, dr_common_unit_t **devlist, int devnum)
{
	_NOTE(ARGUNUSED(hp))

	int		d;
	static fn_t	f = "dr_post_attach_mem";

	PR_MEM("%s...\n", f);

	for (d = 0; d < devnum; d++) {
		dr_mem_unit_t	*mp = (dr_mem_unit_t *)devlist[d];
		struct memlist	*mlist, *ml;

		mlist = dr_get_memlist(mp);
		if (mlist == NULL) {
			/* OPL supports memoryless board */
			continue;
		}

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

		for (ml = mlist; ml != NULL; ml = ml->next) {
			sbd_error_t *err;

			err = drmach_mem_add_span(
			    mp->sbm_cm.sbdev_id,
			    ml->address,
			    ml->size);
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

	dr_update_mc_memory();

	return (0);
}

int
dr_pre_detach_mem(dr_handle_t *hp, dr_common_unit_t **devlist, int devnum)
{
	_NOTE(ARGUNUSED(hp))

	int d;

	for (d = 0; d < devnum; d++) {
		dr_mem_unit_t *mp = (dr_mem_unit_t *)devlist[d];

		cmn_err(CE_CONT, "OS unconfigure %s", mp->sbm_cm.sbdev_path);
	}

	return (0);
}

int
dr_post_detach_mem(dr_handle_t *hp, dr_common_unit_t **devlist, int devnum)
{
	_NOTE(ARGUNUSED(hp))

	int		d, rv;
	static fn_t	f = "dr_post_detach_mem";

	PR_MEM("%s...\n", f);

	rv = 0;
	for (d = 0; d < devnum; d++) {
		dr_mem_unit_t	*mp = (dr_mem_unit_t *)devlist[d];

		ASSERT(mp->sbm_cm.sbdev_bp == hp->h_bd);

		if (dr_post_detach_mem_unit(mp))
			rv = -1;
	}
	dr_update_mc_memory();

	return (rv);
}

static void
dr_add_memory_spans(dr_mem_unit_t *mp, struct memlist *ml)
{
	static fn_t	f = "dr_add_memory_spans";

	PR_MEM("%s...", f);
	PR_MEMLIST_DUMP(ml);

#ifdef DEBUG
	memlist_read_lock();
	if (memlist_intersect(phys_install, ml)) {
		PR_MEM("%s:WARNING: memlist intersects with phys_install\n", f);
	}
	memlist_read_unlock();
#endif

	for (; ml; ml = ml->next) {
		pfn_t		 base;
		pgcnt_t		 npgs;
		int		 rv;
		sbd_error_t	*err;

		base = _b64top(ml->address);
		npgs = _b64top(ml->size);

		rv = kphysm_add_memory_dynamic(base, npgs);

		err = drmach_mem_add_span(
		    mp->sbm_cm.sbdev_id,
		    ml->address,
		    ml->size);

		if (err)
			DRERR_SET_C(&mp->sbm_cm.sbdev_error, &err);

		if (rv != KPHYSM_OK) {
			cmn_err(CE_WARN, "%s:"
			    " unexpected kphysm_add_memory_dynamic"
			    " return value %d;"
			    " basepfn=0x%lx, npages=%ld\n",
			    f, rv, base, npgs);

			continue;
		}
	}
}

static int
memlist_touch(struct memlist *ml, uint64_t add)
{
	while (ml != NULL) {
		if ((add == ml->address) ||
		    (add == (ml->address + ml->size)))
			return (1);
		ml = ml->next;
	}
	return (0);
}

static sbd_error_t *
dr_process_excess_mlist(dr_mem_unit_t *s_mp,
	dr_mem_unit_t *t_mp, struct memlist *t_excess_mlist)
{
	struct memlist	*ml;
	sbd_error_t	*err;
	static fn_t	f = "dr_process_excess_mlist";
	uint64_t	new_pa, nbytes;
	int rv;

	err = NULL;

	/*
	 * After the small <-> big copy-rename,
	 * the original address space for the
	 * source board may have excess to be
	 * deleted. This is a case different
	 * from the big->small excess source
	 * memory case listed below.
	 * Remove s_mp->sbm_del_mlist from
	 * the kernel cage glist.
	 */
	for (ml = s_mp->sbm_del_mlist; ml;
	    ml = ml->next) {
		PR_MEM("%s: delete small<->big copy-"
		    "rename source excess memory", f);
		PR_MEMLIST_DUMP(ml);

		err = drmach_mem_del_span(
		    s_mp->sbm_cm.sbdev_id,
		    ml->address, ml->size);
		if (err)
			DRERR_SET_C(&s_mp->
			    sbm_cm.sbdev_error, &err);
		ASSERT(err == NULL);
	}

	PR_MEM("%s: adding back remaining portion"
	    " of %s, memlist:\n",
	    f, t_mp->sbm_cm.sbdev_path);
	PR_MEMLIST_DUMP(t_excess_mlist);

	for (ml = t_excess_mlist; ml; ml = ml->next) {
		struct memlist ml0;

		ml0.address = ml->address;
		ml0.size = ml->size;
		ml0.next = ml0.prev = NULL;

		/*
		 * If the memory object is 256 MB aligned (max page size
		 * on OPL, it will not be coalesced to the adjacent memory
		 * chunks.  The coalesce logic assumes contiguous page
		 * structures for contiguous memory and we hit panic.
		 * For anything less than 256 MB alignment, we have
		 * to make sure that it is not adjacent to anything.
		 * If the new chunk is adjacent to phys_install, we
		 * truncate it to 4MB boundary.  4 MB is somewhat
		 * arbitrary.  However we do not want to create
		 * very small segments because they can cause problem.
		 * The extreme case of 8K segment will fail
		 * kphysm_add_memory_dynamic(), e.g.
		 */
		if ((ml->address & (MH_MPSS_ALIGNMENT - 1)) ||
		    (ml->size & (MH_MPSS_ALIGNMENT - 1))) {

		memlist_read_lock();
		rv = memlist_touch(phys_install, ml0.address);
		memlist_read_unlock();

		if (rv) {
			new_pa = roundup(ml0.address + 1, MH_MIN_ALIGNMENT);
			nbytes = (new_pa -  ml0.address);
			if (nbytes >= ml0.size) {
				t_mp->sbm_dyn_segs =
				    memlist_del_span(t_mp->sbm_dyn_segs,
				    ml0.address, ml0.size);
				continue;
			}
			t_mp->sbm_dyn_segs =
			    memlist_del_span(t_mp->sbm_dyn_segs,
			    ml0.address, nbytes);
			ml0.size -= nbytes;
			ml0.address = new_pa;
		}

		if (ml0.size == 0) {
			continue;
		}

		memlist_read_lock();
		rv = memlist_touch(phys_install, ml0.address + ml0.size);
		memlist_read_unlock();

		if (rv) {
			new_pa = rounddown(ml0.address + ml0.size - 1,
			    MH_MIN_ALIGNMENT);
			nbytes = (ml0.address + ml0.size - new_pa);
			if (nbytes >= ml0.size) {
				t_mp->sbm_dyn_segs =
				    memlist_del_span(t_mp->sbm_dyn_segs,
				    ml0.address, ml0.size);
				continue;
			}
			t_mp->sbm_dyn_segs =
			    memlist_del_span(t_mp->sbm_dyn_segs,
			    new_pa, nbytes);
			ml0.size -= nbytes;
		}

		if (ml0.size > 0) {
			dr_add_memory_spans(s_mp, &ml0);
		}
		} else if (ml0.size > 0) {
			dr_add_memory_spans(s_mp, &ml0);
		}
	}
	memlist_delete(t_excess_mlist);
	return (err);
}

static int
dr_post_detach_mem_unit(dr_mem_unit_t *s_mp)
{
	uint64_t	sz = s_mp->sbm_slice_size;
	uint64_t	sm = sz - 1;
	/* old and new below refer to PAs before and after copy-rename */
	uint64_t	s_old_basepa, s_new_basepa;
	uint64_t	t_old_basepa, t_new_basepa;
	dr_mem_unit_t	*t_mp, *x_mp;
	drmach_mem_info_t	minfo;
	struct memlist	*ml;
	struct memlist	*t_excess_mlist;
	int		rv;
	int		s_excess_mem_deleted = 0;
	sbd_error_t	*err;
	static fn_t	f = "dr_post_detach_mem_unit";

	PR_MEM("%s...\n", f);

	/* s_mp->sbm_del_mlist could be NULL, meaning no deleted spans */
	PR_MEM("%s: %s: deleted memlist (EMPTY maybe okay):\n",
	    f, s_mp->sbm_cm.sbdev_path);
	PR_MEMLIST_DUMP(s_mp->sbm_del_mlist);

	/* sanity check */
	ASSERT(s_mp->sbm_del_mlist == NULL ||
	    (s_mp->sbm_flags & DR_MFLAG_RELDONE) != 0);

	if (s_mp->sbm_flags & DR_MFLAG_SOURCE) {
		t_mp = s_mp->sbm_peer;
		ASSERT(t_mp != NULL);
		ASSERT(t_mp->sbm_flags & DR_MFLAG_TARGET);
		ASSERT(t_mp->sbm_peer == s_mp);

		ASSERT(t_mp->sbm_flags & DR_MFLAG_RELDONE);
		ASSERT(t_mp->sbm_del_mlist);

		PR_MEM("%s: target %s: deleted memlist:\n",
		    f, t_mp->sbm_cm.sbdev_path);
		PR_MEMLIST_DUMP(t_mp->sbm_del_mlist);
	} else {
		/* this is no target unit */
		t_mp = NULL;
	}

	/*
	 * Verify the memory really did successfully detach
	 * by checking for its non-existence in phys_install.
	 */
	rv = 0;
	memlist_read_lock();
	if (s_mp->sbm_flags & DR_MFLAG_RELDONE) {
		x_mp = s_mp;
		rv = memlist_intersect(phys_install, x_mp->sbm_del_mlist);
	}
	if (rv == 0 && t_mp && (t_mp->sbm_flags & DR_MFLAG_RELDONE)) {
		x_mp = t_mp;
		rv = memlist_intersect(phys_install, x_mp->sbm_del_mlist);
	}
	memlist_read_unlock();

	if (rv) {
		/* error: memlist still in phys_install */
		DR_DEV_INTERNAL_ERROR(&x_mp->sbm_cm);
	}

	/*
	 * clean mem unit state and bail out if an error has been recorded.
	 */
	rv = 0;
	if (s_mp->sbm_cm.sbdev_error) {
		PR_MEM("%s: %s flags=%x", f,
		    s_mp->sbm_cm.sbdev_path, s_mp->sbm_flags);
		DR_DEV_CLR_UNREFERENCED(&s_mp->sbm_cm);
		DR_DEV_CLR_RELEASED(&s_mp->sbm_cm);
		dr_device_transition(&s_mp->sbm_cm, DR_STATE_CONFIGURED);
		rv = -1;
	}
	if (t_mp != NULL && t_mp->sbm_cm.sbdev_error != NULL) {
		PR_MEM("%s: %s flags=%x", f,
		    s_mp->sbm_cm.sbdev_path, s_mp->sbm_flags);
		DR_DEV_CLR_UNREFERENCED(&t_mp->sbm_cm);
		DR_DEV_CLR_RELEASED(&t_mp->sbm_cm);
		dr_device_transition(&t_mp->sbm_cm, DR_STATE_CONFIGURED);
		rv = -1;
	}
	if (rv)
		goto cleanup;

	s_old_basepa = _ptob64(s_mp->sbm_basepfn);
	err = drmach_mem_get_info(s_mp->sbm_cm.sbdev_id, &minfo);
	ASSERT(err == NULL);
	s_new_basepa = minfo.mi_basepa;

	PR_MEM("%s:s_old_basepa: 0x%lx\n", f, s_old_basepa);
	PR_MEM("%s:s_new_basepa: 0x%lx\n", f, s_new_basepa);

	if (t_mp != NULL) {
		struct memlist *s_copy_mlist;

		t_old_basepa = _ptob64(t_mp->sbm_basepfn);
		err = drmach_mem_get_info(t_mp->sbm_cm.sbdev_id, &minfo);
		ASSERT(err == NULL);
		t_new_basepa = minfo.mi_basepa;

		PR_MEM("%s:t_old_basepa: 0x%lx\n", f, t_old_basepa);
		PR_MEM("%s:t_new_basepa: 0x%lx\n", f, t_new_basepa);

		/*
		 * Construct copy list with original source addresses.
		 * Used to add back excess target mem.
		 */
		s_copy_mlist = memlist_dup(s_mp->sbm_mlist);
		for (ml = s_mp->sbm_del_mlist; ml; ml = ml->next) {
			s_copy_mlist = memlist_del_span(s_copy_mlist,
			    ml->address, ml->size);
		}

		PR_MEM("%s: source copy list:\n:", f);
		PR_MEMLIST_DUMP(s_copy_mlist);

		/*
		 * We had to swap mem-units, so update
		 * memlists accordingly with new base
		 * addresses.
		 */
		for (ml = t_mp->sbm_mlist; ml; ml = ml->next) {
			ml->address -= t_old_basepa;
			ml->address += t_new_basepa;
		}

		/*
		 * There is no need to explicitly rename the target delete
		 * memlist, because sbm_del_mlist and sbm_mlist always
		 * point to the same memlist for a copy/rename operation.
		 */
		ASSERT(t_mp->sbm_del_mlist == t_mp->sbm_mlist);

		PR_MEM("%s: renamed target memlist and delete memlist:\n", f);
		PR_MEMLIST_DUMP(t_mp->sbm_mlist);

		for (ml = s_mp->sbm_mlist; ml; ml = ml->next) {
			ml->address -= s_old_basepa;
			ml->address += s_new_basepa;
		}

		PR_MEM("%s: renamed source memlist:\n", f);
		PR_MEMLIST_DUMP(s_mp->sbm_mlist);
		PR_MEM("%s: source dyn seg memlist:\n", f);
		PR_MEMLIST_DUMP(s_mp->sbm_dyn_segs);

		/*
		 * Keep track of dynamically added segments
		 * since they cannot be split if we need to delete
		 * excess source memory later for this board.
		 */
		if (t_mp->sbm_dyn_segs)
			memlist_delete(t_mp->sbm_dyn_segs);
		t_mp->sbm_dyn_segs = s_mp->sbm_dyn_segs;
		s_mp->sbm_dyn_segs = NULL;

		/*
		 * Add back excess target memory.
		 * Subtract out the portion of the target memory
		 * node that was taken over by the source memory
		 * node.
		 */
		t_excess_mlist = memlist_dup(t_mp->sbm_mlist);
		for (ml = s_copy_mlist; ml; ml = ml->next) {
			t_excess_mlist =
			    memlist_del_span(t_excess_mlist,
			    ml->address, ml->size);
		}
		PR_MEM("%s: excess memlist:\n", f);
		PR_MEMLIST_DUMP(t_excess_mlist);

		/*
		 * Update dynamically added segs
		 */
		for (ml = s_mp->sbm_del_mlist; ml; ml = ml->next) {
			t_mp->sbm_dyn_segs =
			    memlist_del_span(t_mp->sbm_dyn_segs,
			    ml->address, ml->size);
		}
		for (ml = t_excess_mlist; ml; ml = ml->next) {
			t_mp->sbm_dyn_segs =
			    memlist_cat_span(t_mp->sbm_dyn_segs,
			    ml->address, ml->size);
		}
		PR_MEM("%s: %s: updated dynamic seg list:\n",
		    f, t_mp->sbm_cm.sbdev_path);
		PR_MEMLIST_DUMP(t_mp->sbm_dyn_segs);

		if (t_excess_mlist != NULL) {
			err = dr_process_excess_mlist(s_mp, t_mp,
			    t_excess_mlist);
			s_excess_mem_deleted = 1;
		}

		memlist_delete(s_copy_mlist);

#ifdef DEBUG
		/*
		 * s_mp->sbm_del_mlist may still needed
		 */
		PR_MEM("%s: source delete memeory flag %d",
		    f, s_excess_mem_deleted);
		PR_MEM("%s: source delete memlist", f);
		PR_MEMLIST_DUMP(s_mp->sbm_del_mlist);
#endif

	}

	if (t_mp != NULL) {
		/* delete target's entire address space */
		err = drmach_mem_del_span(
		    t_mp->sbm_cm.sbdev_id, t_old_basepa & ~ sm, sz);
		if (err)
			DRERR_SET_C(&t_mp->sbm_cm.sbdev_error, &err);
		ASSERT(err == NULL);

		/*
		 * After the copy/rename, the original address space
		 * for the source board (which is now located on the
		 * target board) may now have some excess to be deleted.
		 * Those excess memory on the source board are kept in
		 * source board's sbm_del_mlist
		 */
		for (ml = s_mp->sbm_del_mlist; !s_excess_mem_deleted && ml;
		    ml = ml->next) {
			PR_MEM("%s: delete source excess memory", f);
			PR_MEMLIST_DUMP(ml);

			err = drmach_mem_del_span(s_mp->sbm_cm.sbdev_id,
			    ml->address, ml->size);
			if (err)
				DRERR_SET_C(&s_mp->sbm_cm.sbdev_error, &err);
			ASSERT(err == NULL);
		}

	} else {
		/* delete board's entire address space */
		err = drmach_mem_del_span(s_mp->sbm_cm.sbdev_id,
		    s_old_basepa & ~ sm, sz);
		if (err)
			DRERR_SET_C(&s_mp->sbm_cm.sbdev_error, &err);
		ASSERT(err == NULL);
	}

cleanup:
	/* clean up target mem unit */
	if (t_mp != NULL) {
		memlist_delete(t_mp->sbm_del_mlist);
		/* no need to delete sbm_mlist, it shares sbm_del_mlist */

		t_mp->sbm_del_mlist = NULL;
		t_mp->sbm_mlist = NULL;
		t_mp->sbm_peer = NULL;
		t_mp->sbm_flags = 0;
		t_mp->sbm_cm.sbdev_busy = 0;
		dr_init_mem_unit_data(t_mp);

	}
	if (t_mp != NULL && t_mp->sbm_cm.sbdev_error == NULL) {
		/*
		 * now that copy/rename has completed, undo this
		 * work that was done in dr_release_mem_done.
		 */
		DR_DEV_CLR_UNREFERENCED(&t_mp->sbm_cm);
		DR_DEV_CLR_RELEASED(&t_mp->sbm_cm);
		dr_device_transition(&t_mp->sbm_cm, DR_STATE_CONFIGURED);
	}

	/*
	 * clean up (source) board's mem unit structure.
	 * NOTE: sbm_mlist is retained if no error has been record (in other
	 * words, when s_mp->sbm_cm.sbdev_error is NULL). This memlist is
	 * referred to elsewhere as the cached memlist.  The cached memlist
	 * is used to re-attach (configure back in) this memunit from the
	 * unconfigured state.  The memlist is retained because it may
	 * represent bad pages that were detected while the memory was
	 * configured into the OS.  The OS deletes bad pages from phys_install.
	 * Those deletes, if any, will be represented in the cached mlist.
	 */
	if (s_mp->sbm_del_mlist && s_mp->sbm_del_mlist != s_mp->sbm_mlist)
		memlist_delete(s_mp->sbm_del_mlist);

	if (s_mp->sbm_cm.sbdev_error && s_mp->sbm_mlist) {
		memlist_delete(s_mp->sbm_mlist);
		s_mp->sbm_mlist = NULL;
	}

	if (s_mp->sbm_dyn_segs != NULL && s_mp->sbm_cm.sbdev_error == 0) {
		memlist_delete(s_mp->sbm_dyn_segs);
		s_mp->sbm_dyn_segs = NULL;
	}

	s_mp->sbm_del_mlist = NULL;
	s_mp->sbm_peer = NULL;
	s_mp->sbm_flags = 0;
	s_mp->sbm_cm.sbdev_busy = 0;
	dr_init_mem_unit_data(s_mp);

	PR_MEM("%s: cached memlist for %s:", f, s_mp->sbm_cm.sbdev_path);
	PR_MEMLIST_DUMP(s_mp->sbm_mlist);

	return (0);
}

/*
 * Successful return from this function will have the memory
 * handle in bp->b_dev[..mem-unit...].sbm_memhandle allocated
 * and waiting.  This routine's job is to select the memory that
 * actually has to be released (detached) which may not necessarily
 * be the same memory node that came in in devlist[],
 * i.e. a copy-rename is needed.
 */
int
dr_pre_release_mem(dr_handle_t *hp, dr_common_unit_t **devlist, int devnum)
{
	int		d;
	int		err_flag = 0;
	static fn_t	f = "dr_pre_release_mem";

	PR_MEM("%s...\n", f);

	for (d = 0; d < devnum; d++) {
		dr_mem_unit_t	*mp = (dr_mem_unit_t *)devlist[d];
		int		rv;
		memquery_t	mq;
		struct memlist	*ml;

		if (mp->sbm_cm.sbdev_error) {
			err_flag = 1;
			continue;
		} else if (!kcage_on) {
			dr_dev_err(CE_WARN, &mp->sbm_cm, ESBD_KCAGE_OFF);
			err_flag = 1;
			continue;
		}

		if (mp->sbm_flags & DR_MFLAG_RESERVED) {
			/*
			 * Board is currently involved in a delete
			 * memory operation. Can't detach this guy until
			 * that operation completes.
			 */
			dr_dev_err(CE_WARN, &mp->sbm_cm, ESBD_INVAL);
			err_flag = 1;
			break;
		}

		/* flags should be clean at this time */
		ASSERT(mp->sbm_flags == 0);

		ASSERT(mp->sbm_mlist == NULL);
		ASSERT(mp->sbm_del_mlist == NULL);
		if (mp->sbm_mlist != NULL) {
			memlist_delete(mp->sbm_mlist);
			mp->sbm_mlist = NULL;
		}

		ml = dr_get_memlist(mp);
		if (ml == NULL) {
			err_flag = 1;
			PR_MEM("%s: no memlist found for %s\n",
			    f, mp->sbm_cm.sbdev_path);
			continue;
		}

		/*
		 * Check whether the detaching memory requires a
		 * copy-rename.
		 */
		ASSERT(mp->sbm_npages != 0);

		rv = dr_del_mlist_query(ml, &mq);
		if (rv != KPHYSM_OK) {
			memlist_delete(ml);
			DR_DEV_INTERNAL_ERROR(&mp->sbm_cm);
			err_flag = 1;
			break;
		}

		if (mq.nonrelocatable != 0) {
			if (!(dr_cmd_flags(hp) &
			    (SBD_FLAG_FORCE | SBD_FLAG_QUIESCE_OKAY))) {
				memlist_delete(ml);
				/* caller wasn't prompted for a suspend */
				dr_dev_err(CE_WARN, &mp->sbm_cm,
				    ESBD_QUIESCE_REQD);
				err_flag = 1;
				break;
			}
		}

		/* allocate a kphysm handle */
		rv = kphysm_del_gethandle(&mp->sbm_memhandle);
		if (rv != KPHYSM_OK) {
			memlist_delete(ml);

			DR_DEV_INTERNAL_ERROR(&mp->sbm_cm);
			err_flag = 1;
			break;
		}
		mp->sbm_flags |= DR_MFLAG_RELOWNER;

		if ((mq.nonrelocatable != 0) ||
		    dr_reserve_mem_spans(&mp->sbm_memhandle, ml)) {
			/*
			 * Either the detaching memory node contains
			 * non-reloc memory or we failed to reserve the
			 * detaching memory node (which did _not_ have
			 * any non-reloc memory, i.e. some non-reloc mem
			 * got onboard).
			 */

			if (dr_select_mem_target(hp, mp, ml)) {
				int rv;

				/*
				 * We had no luck locating a target
				 * memory node to be the recipient of
				 * the non-reloc memory on the node
				 * we're trying to detach.
				 * Clean up be disposing the mem handle
				 * and the mem list.
				 */
				rv = kphysm_del_release(mp->sbm_memhandle);
				if (rv != KPHYSM_OK) {
					/*
					 * can do nothing but complain
					 * and hope helpful for debug
					 */
					cmn_err(CE_WARN, "%s: unexpected"
					    " kphysm_del_release return"
					    " value %d",
					    f, rv);
				}
				mp->sbm_flags &= ~DR_MFLAG_RELOWNER;

				memlist_delete(ml);

				/* make sure sbm_flags is clean */
				ASSERT(mp->sbm_flags == 0);

				dr_dev_err(CE_WARN,
				    &mp->sbm_cm, ESBD_NO_TARGET);

				err_flag = 1;
				break;
			}

			/*
			 * ml is not memlist_delete'd here because
			 * it has been assigned to mp->sbm_mlist
			 * by dr_select_mem_target.
			 */
		} else {
			/* no target needed to detach this board */
			mp->sbm_flags |= DR_MFLAG_RESERVED;
			mp->sbm_peer = NULL;
			mp->sbm_del_mlist = ml;
			mp->sbm_mlist = ml;
			mp->sbm_cm.sbdev_busy = 1;
		}
#ifdef DEBUG
		ASSERT(mp->sbm_mlist != NULL);

		if (mp->sbm_flags & DR_MFLAG_SOURCE) {
			PR_MEM("%s: release of %s requires copy/rename;"
			    " selected target board %s\n",
			    f,
			    mp->sbm_cm.sbdev_path,
			    mp->sbm_peer->sbm_cm.sbdev_path);
		} else {
			PR_MEM("%s: copy/rename not required to release %s\n",
			    f, mp->sbm_cm.sbdev_path);
		}

		ASSERT(mp->sbm_flags & DR_MFLAG_RELOWNER);
		ASSERT(mp->sbm_flags & DR_MFLAG_RESERVED);
#endif
	}

	return (err_flag ? -1 : 0);
}

void
dr_release_mem_done(dr_common_unit_t *cp)
{
	dr_mem_unit_t	*s_mp = (dr_mem_unit_t *)cp;
	dr_mem_unit_t *t_mp, *mp;
	int		rv;
	static fn_t	f = "dr_release_mem_done";

	/*
	 * This unit will be flagged with DR_MFLAG_SOURCE, if it
	 * has a target unit.
	 */
	if (s_mp->sbm_flags & DR_MFLAG_SOURCE) {
		t_mp = s_mp->sbm_peer;
		ASSERT(t_mp != NULL);
		ASSERT(t_mp->sbm_peer == s_mp);
		ASSERT(t_mp->sbm_flags & DR_MFLAG_TARGET);
		ASSERT(t_mp->sbm_flags & DR_MFLAG_RESERVED);
	} else {
		/* this is no target unit */
		t_mp = NULL;
	}

	/* free delete handle */
	ASSERT(s_mp->sbm_flags & DR_MFLAG_RELOWNER);
	ASSERT(s_mp->sbm_flags & DR_MFLAG_RESERVED);
	rv = kphysm_del_release(s_mp->sbm_memhandle);
	if (rv != KPHYSM_OK) {
		/*
		 * can do nothing but complain
		 * and hope helpful for debug
		 */
		cmn_err(CE_WARN, "%s: unexpected kphysm_del_release"
		    " return value %d", f, rv);
	}
	s_mp->sbm_flags &= ~DR_MFLAG_RELOWNER;

	/*
	 * If an error was encountered during release, clean up
	 * the source (and target, if present) unit data.
	 */
/* XXX Can we know that sbdev_error was encountered during release? */
	if (s_mp->sbm_cm.sbdev_error != NULL) {

		if (t_mp != NULL) {
			ASSERT(t_mp->sbm_del_mlist == t_mp->sbm_mlist);
			t_mp->sbm_del_mlist = NULL;

			if (t_mp->sbm_mlist != NULL) {
				memlist_delete(t_mp->sbm_mlist);
				t_mp->sbm_mlist = NULL;
			}

			t_mp->sbm_peer = NULL;
			t_mp->sbm_flags = 0;
			t_mp->sbm_cm.sbdev_busy = 0;
		}

		if (s_mp->sbm_del_mlist != s_mp->sbm_mlist)
			memlist_delete(s_mp->sbm_del_mlist);
		s_mp->sbm_del_mlist = NULL;

		if (s_mp->sbm_mlist != NULL) {
			memlist_delete(s_mp->sbm_mlist);
			s_mp->sbm_mlist = NULL;
		}

		s_mp->sbm_peer = NULL;
		s_mp->sbm_flags = 0;
		s_mp->sbm_cm.sbdev_busy = 0;

		/* bail out */
		return;
	}

	DR_DEV_SET_RELEASED(&s_mp->sbm_cm);
	dr_device_transition(&s_mp->sbm_cm, DR_STATE_RELEASE);

	if (t_mp != NULL) {
		/*
		 * the kphysm delete operation that drained the source
		 * board also drained this target board.  Since the source
		 * board drain is now known to have succeeded, we know this
		 * target board is drained too.
		 *
		 * because DR_DEV_SET_RELEASED and dr_device_transition
		 * is done here, the dr_release_dev_done should not
		 * fail.
		 */
		DR_DEV_SET_RELEASED(&t_mp->sbm_cm);
		dr_device_transition(&t_mp->sbm_cm, DR_STATE_RELEASE);

		/*
		 * NOTE: do not transition target's board state,
		 * even if the mem-unit was the last configure
		 * unit of the board.  When copy/rename completes
		 * this mem-unit will transitioned back to
		 * the configured state.  In the meantime, the
		 * board's must remain as is.
		 */
	}

	/* if board(s) had deleted memory, verify it is gone */
	rv = 0;
	memlist_read_lock();
	if (s_mp->sbm_del_mlist != NULL) {
		mp = s_mp;
		rv = memlist_intersect(phys_install, mp->sbm_del_mlist);
	}
	if (rv == 0 && t_mp && t_mp->sbm_del_mlist != NULL) {
		mp = t_mp;
		rv = memlist_intersect(phys_install, mp->sbm_del_mlist);
	}
	memlist_read_unlock();
	if (rv) {
		cmn_err(CE_WARN, "%s: %smem-unit (%d.%d): "
		    "deleted memory still found in phys_install",
		    f,
		    (mp == t_mp ? "target " : ""),
		    mp->sbm_cm.sbdev_bp->b_num,
		    mp->sbm_cm.sbdev_unum);

		DR_DEV_INTERNAL_ERROR(&s_mp->sbm_cm);
		return;
	}

	s_mp->sbm_flags |= DR_MFLAG_RELDONE;
	if (t_mp != NULL)
		t_mp->sbm_flags |= DR_MFLAG_RELDONE;

	/* this should not fail */
	if (dr_release_dev_done(&s_mp->sbm_cm) != 0) {
		/* catch this in debug kernels */
		ASSERT(0);
		return;
	}

	PR_MEM("%s: marking %s release DONE\n",
	    f, s_mp->sbm_cm.sbdev_path);

	s_mp->sbm_cm.sbdev_ostate = SBD_STAT_UNCONFIGURED;

	if (t_mp != NULL) {
		/* should not fail */
		rv = dr_release_dev_done(&t_mp->sbm_cm);
		if (rv != 0) {
			/* catch this in debug kernels */
			ASSERT(0);
			return;
		}

		PR_MEM("%s: marking %s release DONE\n",
		    f, t_mp->sbm_cm.sbdev_path);

		t_mp->sbm_cm.sbdev_ostate = SBD_STAT_UNCONFIGURED;
	}
}

/*ARGSUSED*/
int
dr_disconnect_mem(dr_mem_unit_t *mp)
{
	static fn_t	f = "dr_disconnect_mem";
	update_membounds_t umb;

#ifdef DEBUG
	int state = mp->sbm_cm.sbdev_state;
	ASSERT(state == DR_STATE_CONNECTED ||
	    state == DR_STATE_UNCONFIGURED);
#endif

	PR_MEM("%s...\n", f);

	if (mp->sbm_del_mlist && mp->sbm_del_mlist != mp->sbm_mlist)
		memlist_delete(mp->sbm_del_mlist);
	mp->sbm_del_mlist = NULL;

	if (mp->sbm_mlist) {
		memlist_delete(mp->sbm_mlist);
		mp->sbm_mlist = NULL;
	}

	/*
	 * Remove memory from lgroup
	 * For now, only board info is required.
	 */
	umb.u_board = mp->sbm_cm.sbdev_bp->b_num;
	umb.u_base = (uint64_t)-1;
	umb.u_len = (uint64_t)-1;

	lgrp_plat_config(LGRP_CONFIG_MEM_DEL, (uintptr_t)&umb);

	return (0);
}

int
dr_cancel_mem(dr_mem_unit_t *s_mp)
{
	dr_mem_unit_t	*t_mp;
	dr_state_t	state;
	static fn_t	f = "dr_cancel_mem";

	state = s_mp->sbm_cm.sbdev_state;

	if (s_mp->sbm_flags & DR_MFLAG_TARGET) {
		/* must cancel source board, not target board */
		/* TODO: set error */
		return (-1);
	} else if (s_mp->sbm_flags & DR_MFLAG_SOURCE) {
		t_mp = s_mp->sbm_peer;
		ASSERT(t_mp != NULL);
		ASSERT(t_mp->sbm_peer == s_mp);

		/* must always match the source board's state */
		/* TODO: is this assertion correct? */
		ASSERT(t_mp->sbm_cm.sbdev_state == state);
	} else {
		/* this is no target unit */
		t_mp = NULL;
	}

	switch (state) {
	case DR_STATE_UNREFERENCED:	/* state set by dr_release_dev_done */
		ASSERT((s_mp->sbm_flags & DR_MFLAG_RELOWNER) == 0);

		if (t_mp != NULL && t_mp->sbm_del_mlist != NULL) {
			PR_MEM("%s: undoing target %s memory delete\n",
			    f, t_mp->sbm_cm.sbdev_path);
			dr_add_memory_spans(t_mp, t_mp->sbm_del_mlist);

			DR_DEV_CLR_UNREFERENCED(&t_mp->sbm_cm);
		}

		if (s_mp->sbm_del_mlist != NULL) {
			PR_MEM("%s: undoing %s memory delete\n",
			    f, s_mp->sbm_cm.sbdev_path);

			dr_add_memory_spans(s_mp, s_mp->sbm_del_mlist);
		}

		/*FALLTHROUGH*/

/* TODO: should no longer be possible to see the release state here */
	case DR_STATE_RELEASE:	/* state set by dr_release_mem_done */

		ASSERT((s_mp->sbm_flags & DR_MFLAG_RELOWNER) == 0);

		if (t_mp != NULL) {
			ASSERT(t_mp->sbm_del_mlist == t_mp->sbm_mlist);
			t_mp->sbm_del_mlist = NULL;

			if (t_mp->sbm_mlist != NULL) {
				memlist_delete(t_mp->sbm_mlist);
				t_mp->sbm_mlist = NULL;
			}

			t_mp->sbm_peer = NULL;
			t_mp->sbm_flags = 0;
			t_mp->sbm_cm.sbdev_busy = 0;
			dr_init_mem_unit_data(t_mp);

			DR_DEV_CLR_RELEASED(&t_mp->sbm_cm);

			dr_device_transition(
			    &t_mp->sbm_cm, DR_STATE_CONFIGURED);
		}

		if (s_mp->sbm_del_mlist != s_mp->sbm_mlist)
			memlist_delete(s_mp->sbm_del_mlist);
		s_mp->sbm_del_mlist = NULL;

		if (s_mp->sbm_mlist != NULL) {
			memlist_delete(s_mp->sbm_mlist);
			s_mp->sbm_mlist = NULL;
		}

		s_mp->sbm_peer = NULL;
		s_mp->sbm_flags = 0;
		s_mp->sbm_cm.sbdev_busy = 0;
		dr_init_mem_unit_data(s_mp);

		return (0);

	default:
		PR_MEM("%s: WARNING unexpected state (%d) for %s\n",
		    f, (int)state, s_mp->sbm_cm.sbdev_path);

		return (-1);
	}
	/*NOTREACHED*/
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
	update_membounds_t umb;

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
	mp->sbm_alignment_mask = _b64top(minfo.mi_alignment_mask);
	mp->sbm_slice_size = minfo.mi_slice_size;

	/*
	 * Add memory to lgroup
	 */
	umb.u_board = mp->sbm_cm.sbdev_bp->b_num;
	umb.u_base = (uint64_t)mp->sbm_basepfn << MMU_PAGESHIFT;
	umb.u_len = (uint64_t)mp->sbm_npages << MMU_PAGESHIFT;

	lgrp_plat_config(LGRP_CONFIG_MEM_ADD, (uintptr_t)&umb);

	PR_MEM("%s: %s (basepfn = 0x%lx, npgs = %ld)\n",
	    f, mp->sbm_cm.sbdev_path, mp->sbm_basepfn, mp->sbm_npages);
}

static int
dr_reserve_mem_spans(memhandle_t *mhp, struct memlist *ml)
{
	int		err;
	pfn_t		base;
	pgcnt_t		npgs;
	struct memlist	*mc;
	static fn_t	f = "dr_reserve_mem_spans";

	PR_MEM("%s...\n", f);

	/*
	 * Walk the supplied memlist scheduling each span for removal
	 * with kphysm_del_span.  It is possible that a span may intersect
	 * an area occupied by the cage.
	 */
	for (mc = ml; mc != NULL; mc = mc->next) {
		base = _b64top(mc->address);
		npgs = _b64top(mc->size);

		err = kphysm_del_span(*mhp, base, npgs);
		if (err != KPHYSM_OK) {
			cmn_err(CE_WARN, "%s memory reserve failed."
			    " unexpected kphysm_del_span return value %d;"
			    " basepfn=0x%lx npages=%ld",
			    f, err, base, npgs);

			return (-1);
		}
	}

	return (0);
}

#define	DR_SMT_NPREF_SETS	6
#define	DR_SMT_NUNITS_PER_SET	MAX_BOARDS * MAX_MEM_UNITS_PER_BOARD

/* debug counters */
int dr_smt_realigned;
int dr_smt_preference[DR_SMT_NPREF_SETS];

#ifdef DEBUG
uint_t dr_ignore_board; /* if bit[bnum-1] set, board won't be candidate */
#endif

/*
 * Find and reserve a copy/rename target board suitable for the
 * given source board.
 * All boards in the system are examined and categorized in relation to
 * their memory size versus the source board's memory size.  Order of
 * preference is:
 *	1st copy all source, source/target same size
 *	2nd copy all source, larger target
 * 	3rd copy nonrelocatable source span
 */
static int
dr_select_mem_target(dr_handle_t *hp,
	dr_mem_unit_t *s_mp, struct memlist *s_ml)
{
	dr_target_pref_t preference; /* lower value is higher preference */
	int		idx;
	dr_mem_unit_t	**sets;

	int		t_bd;
	int		t_unit;
	int		rv;
	dr_board_t	*s_bp, *t_bp;
	dr_mem_unit_t	*t_mp, *c_mp;
	struct memlist	*d_ml, *t_ml, *ml, *b_ml, *x_ml = NULL;
	memquery_t	s_mq = {0};
	static fn_t	f = "dr_select_mem_target";

	PR_MEM("%s...\n", f);

	ASSERT(s_ml != NULL);

	sets = GETSTRUCT(dr_mem_unit_t *, DR_SMT_NUNITS_PER_SET *
	    DR_SMT_NPREF_SETS);

	s_bp = hp->h_bd;
	/* calculate the offset into the slice of the last source board pfn */
	ASSERT(s_mp->sbm_npages != 0);

	/*
	 * Find non-relocatable span on source board.
	 */
	rv = kphysm_del_span_query(s_mp->sbm_basepfn, s_mp->sbm_npages, &s_mq);
	if (rv != KPHYSM_OK) {
		PR_MEM("%s: %s: unexpected kphysm_del_span_query"
		    " return value %d; basepfn 0x%lx, npages %ld\n",
		    f, s_mp->sbm_cm.sbdev_path, rv, s_mp->sbm_basepfn,
		    s_mp->sbm_npages);
		return (-1);
	}

	ASSERT(s_mq.phys_pages != 0);
	ASSERT(s_mq.nonrelocatable != 0);

	PR_MEM("%s: %s: nonrelocatable span (0x%lx..0x%lx)\n", f,
	    s_mp->sbm_cm.sbdev_path, s_mq.first_nonrelocatable,
	    s_mq.last_nonrelocatable);

	/* break down s_ml if it contains dynamic segments */
	b_ml = memlist_dup(s_ml);

	for (ml = s_mp->sbm_dyn_segs; ml; ml = ml->next) {
		b_ml = memlist_del_span(b_ml, ml->address, ml->size);
		b_ml = memlist_cat_span(b_ml, ml->address, ml->size);
	}


	/*
	 * Make one pass through all memory units on all boards
	 * and categorize them with respect to the source board.
	 */
	for (t_bd = 0; t_bd < MAX_BOARDS; t_bd++) {
		/*
		 * The board structs are a contiguous array
		 * so we take advantage of that to find the
		 * correct board struct pointer for a given
		 * board number.
		 */
		t_bp = dr_lookup_board(t_bd);

		/* source board can not be its own target */
		if (s_bp->b_num == t_bp->b_num)
			continue;

		for (t_unit = 0; t_unit < MAX_MEM_UNITS_PER_BOARD; t_unit++) {

			t_mp = dr_get_mem_unit(t_bp, t_unit);

			/* this memory node must be attached */
			if (!DR_DEV_IS_ATTACHED(&t_mp->sbm_cm))
				continue;

			/* source unit can not be its own target */
			if (s_mp == t_mp) {
				/* catch this is debug kernels */
				ASSERT(0);
				continue;
			}

			/*
			 * this memory node must not already be reserved
			 * by some other memory delete operation.
			 */
			if (t_mp->sbm_flags & DR_MFLAG_RESERVED)
				continue;

			/* get target board memlist */
			t_ml = dr_get_memlist(t_mp);
			if (t_ml == NULL) {
				cmn_err(CE_WARN, "%s: no memlist for"
				    " mem-unit %d, board %d", f,
				    t_mp->sbm_cm.sbdev_bp->b_num,
				    t_mp->sbm_cm.sbdev_unum);
				continue;
			}

			preference = dr_get_target_preference(hp, t_mp, s_mp,
			    t_ml, s_ml, b_ml);

			memlist_delete(t_ml);

			if (preference == DR_TP_INVALID)
				continue;

			dr_smt_preference[preference]++;

			/* calculate index to start of preference set */
			idx  = DR_SMT_NUNITS_PER_SET * preference;
			/* calculate offset to respective element */
			idx += t_bd * MAX_MEM_UNITS_PER_BOARD + t_unit;

			ASSERT(idx < DR_SMT_NUNITS_PER_SET * DR_SMT_NPREF_SETS);
			sets[idx] = t_mp;
		}
	}

	if (b_ml != NULL)
		memlist_delete(b_ml);

	/*
	 * NOTE: this would be a good place to sort each candidate
	 * set in to some desired order, e.g. memory size in ascending
	 * order.  Without an additional sorting step here, the order
	 * within a set is ascending board number order.
	 */

	c_mp = NULL;
	x_ml = NULL;
	t_ml = NULL;
	for (idx = 0; idx < DR_SMT_NUNITS_PER_SET * DR_SMT_NPREF_SETS; idx++) {
		memquery_t mq;

		preference = (dr_target_pref_t)(idx / DR_SMT_NUNITS_PER_SET);

		ASSERT(preference != DR_TP_INVALID);

		/* cleanup t_ml after previous pass */
		if (t_ml != NULL) {
			memlist_delete(t_ml);
			t_ml = NULL;
		}

		/* get candidate target board mem unit */
		t_mp = sets[idx];
		if (t_mp == NULL)
			continue;

		/* get target board memlist */
		t_ml = dr_get_memlist(t_mp);
		if (t_ml == NULL) {
			cmn_err(CE_WARN, "%s: no memlist for"
			    " mem-unit %d, board %d",
			    f,
			    t_mp->sbm_cm.sbdev_bp->b_num,
			    t_mp->sbm_cm.sbdev_unum);

			continue;
		}

		PR_MEM("%s: checking for no-reloc in %s, "
		    " basepfn=0x%lx, npages=%ld\n",
		    f,
		    t_mp->sbm_cm.sbdev_path,
		    t_mp->sbm_basepfn,
		    t_mp->sbm_npages);

		rv = dr_del_mlist_query(t_ml, &mq);
		if (rv != KPHYSM_OK) {
			PR_MEM("%s: kphysm_del_span_query:"
			    " unexpected return value %d\n", f, rv);

			continue;
		}

		if (mq.nonrelocatable != 0) {
			PR_MEM("%s: candidate %s has"
			    " nonrelocatable span [0x%lx..0x%lx]\n",
			    f,
			    t_mp->sbm_cm.sbdev_path,
			    mq.first_nonrelocatable,
			    mq.last_nonrelocatable);

			continue;
		}

#ifdef DEBUG
		/*
		 * This is a debug tool for excluding certain boards
		 * from being selected as a target board candidate.
		 * dr_ignore_board is only tested by this driver.
		 * It must be set with adb, obp, /etc/system or your
		 * favorite debugger.
		 */
		if (dr_ignore_board &
		    (1 << (t_mp->sbm_cm.sbdev_bp->b_num - 1))) {
			PR_MEM("%s: dr_ignore_board flag set,"
			    " ignoring %s as candidate\n",
			    f, t_mp->sbm_cm.sbdev_path);
			continue;
		}
#endif

		/*
		 * Reserve excess source board memory, if any.
		 *
		 * Only the nonrelocatable source span will be copied
		 * so schedule the rest of the source mem to be deleted.
		 */
		switch (preference) {
		case DR_TP_NONRELOC:
			/*
			 * Get source copy memlist and use it to construct
			 * delete memlist.
			 */
			d_ml = memlist_dup(s_ml);
			x_ml = dr_get_copy_mlist(s_ml, t_ml, s_mp, t_mp);

			/* XXX */
			ASSERT(d_ml != NULL);
			ASSERT(x_ml != NULL);

			for (ml = x_ml; ml != NULL; ml = ml->next) {
				d_ml = memlist_del_span(d_ml, ml->address,
				    ml->size);
			}

			PR_MEM("%s: %s: reserving src brd memlist:\n", f,
			    s_mp->sbm_cm.sbdev_path);
			PR_MEMLIST_DUMP(d_ml);

			/* reserve excess spans */
			if (dr_reserve_mem_spans(&s_mp->sbm_memhandle,
			    d_ml) != 0) {
				/* likely more non-reloc pages appeared */
				/* TODO: restart from top? */
				continue;
			}
			break;
		default:
			d_ml = NULL;
			break;
		}

		s_mp->sbm_flags |= DR_MFLAG_RESERVED;

		/*
		 * reserve all memory on target board.
		 * NOTE: source board's memhandle is used.
		 *
		 * If this succeeds (eq 0), then target selection is
		 * complete and all unwanted memory spans, both source and
		 * target, have been reserved.  Loop is terminated.
		 */
		if (dr_reserve_mem_spans(&s_mp->sbm_memhandle, t_ml) == 0) {
			PR_MEM("%s: %s: target board memory reserved\n",
			    f, t_mp->sbm_cm.sbdev_path);

			/* a candidate target board is now reserved */
			t_mp->sbm_flags |= DR_MFLAG_RESERVED;
			c_mp = t_mp;

			/* *** EXITING LOOP *** */
			break;
		}

		/* did not successfully reserve the target board. */
		PR_MEM("%s: could not reserve target %s\n",
		    f, t_mp->sbm_cm.sbdev_path);

		/*
		 * NOTE: an undo of the dr_reserve_mem_span work
		 * will happen automatically when the memhandle
		 * (s_mp->sbm_memhandle) is kphysm_del_release'd.
		 */

		s_mp->sbm_flags &= ~DR_MFLAG_RESERVED;
	}

	/* clean up after memlist editing logic */
	if (x_ml != NULL)
		memlist_delete(x_ml);

	FREESTRUCT(sets, dr_mem_unit_t *, DR_SMT_NUNITS_PER_SET *
	    DR_SMT_NPREF_SETS);

	/*
	 * c_mp will be NULL when the entire sets[] array
	 * has been searched without reserving a target board.
	 */
	if (c_mp == NULL) {
		PR_MEM("%s: %s: target selection failed.\n",
		    f, s_mp->sbm_cm.sbdev_path);

		if (t_ml != NULL)
			memlist_delete(t_ml);

		return (-1);
	}

	PR_MEM("%s: found target %s for source %s\n",
	    f,
	    c_mp->sbm_cm.sbdev_path,
	    s_mp->sbm_cm.sbdev_path);

	s_mp->sbm_peer = c_mp;
	s_mp->sbm_flags |= DR_MFLAG_SOURCE;
	s_mp->sbm_del_mlist = d_ml;	/* spans to be deleted, if any */
	s_mp->sbm_mlist = s_ml;
	s_mp->sbm_cm.sbdev_busy = 1;

	c_mp->sbm_peer = s_mp;
	c_mp->sbm_flags |= DR_MFLAG_TARGET;
	c_mp->sbm_del_mlist = t_ml;	/* spans to be deleted */
	c_mp->sbm_mlist = t_ml;
	c_mp->sbm_cm.sbdev_busy = 1;

	return (0);
}

/*
 * Returns target preference rank:
 *     -1 not a valid copy-rename target board
 *	0 copy all source, source/target same size
 *	1 copy all source, larger target
 * 	2 copy nonrelocatable source span
 */
static dr_target_pref_t
dr_get_target_preference(dr_handle_t *hp,
    dr_mem_unit_t *t_mp, dr_mem_unit_t *s_mp,
    struct memlist *t_ml, struct memlist *s_ml,
    struct memlist *b_ml)
{
	dr_target_pref_t preference;
	struct memlist *s_nonreloc_ml = NULL;
	drmachid_t t_id;
	static fn_t	f = "dr_get_target_preference";

	t_id = t_mp->sbm_cm.sbdev_bp->b_id;

	/*
	 * Can the entire source board be copied?
	 */
	if (dr_memlist_canfit(s_ml, t_ml, s_mp, t_mp)) {
		if (s_mp->sbm_npages == t_mp->sbm_npages)
			preference = DR_TP_SAME;	/* same size */
		else
			preference = DR_TP_LARGE;	/* larger target */
	} else {
		/*
		 * Entire source won't fit so try non-relocatable memory only
		 * (target aligned).
		 */
		s_nonreloc_ml = dr_get_nonreloc_mlist(b_ml, s_mp);
		if (s_nonreloc_ml == NULL) {
			PR_MEM("%s: dr_get_nonreloc_mlist failed\n", f);
			preference = DR_TP_INVALID;
		}
		if (dr_memlist_canfit(s_nonreloc_ml, t_ml, s_mp, t_mp))
			preference = DR_TP_NONRELOC;
		else
			preference = DR_TP_INVALID;
	}

	if (s_nonreloc_ml != NULL)
		memlist_delete(s_nonreloc_ml);

	/*
	 * Force floating board preference lower than all other boards
	 * if the force flag is present; otherwise disallow the board.
	 */
	if ((preference != DR_TP_INVALID) && drmach_board_is_floating(t_id)) {
		if (dr_cmd_flags(hp) & SBD_FLAG_FORCE)
			preference += DR_TP_FLOATING;
		else
			preference = DR_TP_INVALID;
	}

	PR_MEM("%s: %s preference=%d\n", f, t_mp->sbm_cm.sbdev_path,
	    preference);

	return (preference);
}

/*
 * Create a memlist representing the source memory that will be copied to
 * the target board.  The memory to be copied is the maximum amount that
 * will fit on the target board.
 */
static struct memlist *
dr_get_copy_mlist(struct memlist *s_mlist, struct memlist *t_mlist,
    dr_mem_unit_t *s_mp, dr_mem_unit_t *t_mp)
{
	struct memlist	*t_ml, *s_copy_ml, *s_del_ml, *ml, *x_ml;
	uint64_t	s_slice_mask, s_slice_base;
	uint64_t	t_slice_mask, t_slice_base;
	static fn_t	f = "dr_get_copy_mlist";

	ASSERT(s_mlist != NULL);
	ASSERT(t_mlist != NULL);
	ASSERT(t_mp->sbm_slice_size == s_mp->sbm_slice_size);

	s_slice_mask = s_mp->sbm_slice_size - 1;
	s_slice_base = s_mlist->address & ~s_slice_mask;

	t_slice_mask = t_mp->sbm_slice_size - 1;
	t_slice_base = t_mlist->address & ~t_slice_mask;

	t_ml = memlist_dup(t_mlist);
	s_del_ml = memlist_dup(s_mlist);
	s_copy_ml = memlist_dup(s_mlist);

	/* XXX */
	ASSERT(t_ml != NULL);
	ASSERT(s_del_ml != NULL);
	ASSERT(s_copy_ml != NULL);

	/*
	 * To construct the source copy memlist:
	 *
	 * The target memlist is converted to the post-rename
	 * source addresses.  This is the physical address range
	 * the target will have after the copy-rename.  Overlaying
	 * and deleting this from the current source memlist will
	 * give the source delete memlist.  The copy memlist is
	 * the reciprocal of the source delete memlist.
	 */
	for (ml = t_ml; ml != NULL; ml = ml->next) {
		/*
		 * Normalize relative to target slice base PA
		 * in order to preseve slice offsets.
		 */
		ml->address -= t_slice_base;
		/*
		 * Convert to source slice PA address.
		 */
		ml->address += s_slice_base;
	}

	for (ml = t_ml; ml != NULL; ml = ml->next) {
		s_del_ml = memlist_del_span(s_del_ml, ml->address, ml->size);
	}

	/*
	 * Expand the delete mlist to fully include any dynamic segments
	 * it intersects with.
	 */
	for (x_ml = NULL, ml = s_del_ml; ml != NULL; ml = ml->next) {
		uint64_t del_base = ml->address;
		uint64_t del_end = ml->address + ml->size;
		struct memlist *dyn;

		for (dyn = s_mp->sbm_dyn_segs; dyn != NULL; dyn = dyn->next) {
			uint64_t dyn_base = dyn->address;
			uint64_t dyn_end = dyn->address + dyn->size;

			if (del_base > dyn_base && del_base < dyn_end)
				del_base = dyn_base;

			if (del_end > dyn_base && del_end < dyn_end)
				del_end = dyn_end;
		}

		x_ml = memlist_cat_span(x_ml, del_base, del_end - del_base);
	}

	memlist_delete(s_del_ml);
	s_del_ml = x_ml;

	for (ml = s_del_ml; ml != NULL; ml = ml->next) {
		s_copy_ml = memlist_del_span(s_copy_ml, ml->address, ml->size);
	}

	PR_MEM("%s: source delete mlist\n", f);
	PR_MEMLIST_DUMP(s_del_ml);

	PR_MEM("%s: source copy mlist\n", f);
	PR_MEMLIST_DUMP(s_copy_ml);

	memlist_delete(t_ml);
	memlist_delete(s_del_ml);

	return (s_copy_ml);
}

/*
 * Scan the non-relocatable spans on the source memory
 * and construct a minimum mlist that includes all non-reloc
 * memory subject to target alignment, and dynamic segment
 * constraints where only whole dynamic segments may be deleted.
 */
static struct memlist *
dr_get_nonreloc_mlist(struct memlist *s_ml, dr_mem_unit_t *s_mp)
{
	struct memlist	*x_ml = NULL;
	struct memlist	*ml;
	static fn_t	f = "dr_get_nonreloc_mlist";

	PR_MEM("%s: checking for split of dyn seg list:\n", f);
	PR_MEMLIST_DUMP(s_mp->sbm_dyn_segs);

	for (ml = s_ml; ml; ml = ml->next) {
		int rv;
		uint64_t nr_base, nr_end;
		memquery_t mq;
		struct memlist *dyn;

		rv = kphysm_del_span_query(
		    _b64top(ml->address), _b64top(ml->size), &mq);
		if (rv) {
			memlist_delete(x_ml);
			return (NULL);
		}

		if (mq.nonrelocatable == 0)
			continue;

		PR_MEM("%s: non-reloc span: 0x%lx, 0x%lx (%lx, %lx)\n", f,
		    _ptob64(mq.first_nonrelocatable),
		    _ptob64(mq.last_nonrelocatable),
		    mq.first_nonrelocatable,
		    mq.last_nonrelocatable);

		/*
		 * Align the span at both ends to allow for possible
		 * cage expansion.
		 */
		nr_base = _ptob64(mq.first_nonrelocatable);
		nr_end = _ptob64(mq.last_nonrelocatable + 1);

		PR_MEM("%s: adjusted non-reloc span: 0x%lx, 0x%lx\n",
		    f, nr_base, nr_end);

		/*
		 * Expand the non-reloc span to fully include any
		 * dynamic segments it intersects with.
		 */
		for (dyn = s_mp->sbm_dyn_segs; dyn != NULL; dyn = dyn->next) {
			uint64_t dyn_base = dyn->address;
			uint64_t dyn_end = dyn->address + dyn->size;

			if (nr_base > dyn_base && nr_base < dyn_end)
				nr_base = dyn_base;

			if (nr_end > dyn_base && nr_end < dyn_end)
				nr_end = dyn_end;
		}

		x_ml = memlist_cat_span(x_ml, nr_base, nr_end - nr_base);
	}

	if (x_ml == NULL) {
		PR_MEM("%s: source didn't have any non-reloc pages!\n", f);
		return (NULL);
	}

	PR_MEM("%s: %s: edited source memlist:\n", f, s_mp->sbm_cm.sbdev_path);
	PR_MEMLIST_DUMP(x_ml);

	return (x_ml);
}

/*
 * Check if source memlist can fit in target memlist while maintaining
 * relative offsets within board.
 */
static int
dr_memlist_canfit(struct memlist *s_mlist, struct memlist *t_mlist,
    dr_mem_unit_t *s_mp, dr_mem_unit_t *t_mp)
{
	int		canfit = 0;
	struct memlist	*s_ml, *t_ml, *ml;
	uint64_t	s_slice_mask, t_slice_mask;
	static fn_t	f = "dr_mlist_canfit";

	s_ml = memlist_dup(s_mlist);
	t_ml = memlist_dup(t_mlist);

	if (s_ml == NULL || t_ml == NULL) {
		cmn_err(CE_WARN, "%s: memlist_dup failed\n", f);
		goto done;
	}

	s_slice_mask = s_mp->sbm_slice_size - 1;
	t_slice_mask = t_mp->sbm_slice_size - 1;

	/*
	 * Normalize to slice relative offsets.
	 */
	for (ml = s_ml; ml; ml = ml->next)
		ml->address &= s_slice_mask;

	for (ml = t_ml; ml; ml = ml->next)
		ml->address &= t_slice_mask;

	canfit = memlist_canfit(s_ml, t_ml);
done:
	memlist_delete(s_ml);
	memlist_delete(t_ml);

	return (canfit);
}

/*
 * Memlist support.
 */

/*
 * Determine whether the source memlist (s_mlist) will
 * fit into the target memlist (t_mlist) in terms of
 * size and holes.  Assumes the caller has normalized the
 * memlist physical addresses for comparison.
 */
static int
memlist_canfit(struct memlist *s_mlist, struct memlist *t_mlist)
{
	int		rv = 0;
	struct memlist	*s_ml, *t_ml;

	if ((s_mlist == NULL) || (t_mlist == NULL))
		return (0);

	s_ml = s_mlist;
	for (t_ml = t_mlist; t_ml && s_ml; t_ml = t_ml->next) {
		uint64_t	s_start, s_end;
		uint64_t	t_start, t_end;

		t_start = t_ml->address;
		t_end = t_start + t_ml->size;

		for (; s_ml; s_ml = s_ml->next) {
			s_start = s_ml->address;
			s_end = s_start + s_ml->size;

			if ((s_start < t_start) || (s_end > t_end))
				break;
		}
	}

	/*
	 * If we ran out of source memlist chunks that mean
	 * we found a home for all of them.
	 */
	if (s_ml == NULL)
		rv = 1;

	return (rv);
}
