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
 * Copyright 2019 Peter Tribble.
 */

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

extern struct memlist	*phys_install;

/* TODO: push this reference below drmach line */
extern int		kcage_on;

/* for the DR*INTERNAL_ERROR macros.  see sys/dr.h. */
static char *dr_ie_fmt = "dr_mem.c %d";

static int	dr_post_detach_mem_unit(dr_mem_unit_t *mp);
static int	dr_reserve_mem_spans(memhandle_t *mhp, struct memlist *mlist);
static int	dr_select_mem_target(dr_handle_t *hp, dr_mem_unit_t *mp,
    struct memlist *ml);
static void	dr_init_mem_unit_data(dr_mem_unit_t *mp);

static int 	memlist_canfit(struct memlist *s_mlist,
    struct memlist *t_mlist);

/*
 * dr_mem_unit_t.sbm_flags
 */
#define	DR_MFLAG_RESERVED	0x01	/* mem unit reserved for delete */
#define	DR_MFLAG_SOURCE		0x02	/* source brd of copy/rename op */
#define	DR_MFLAG_TARGET		0x04	/* target brd of copy/rename op */
#define	DR_MFLAG_MEMUPSIZE	0x08	/* move from big to small board */
#define	DR_MFLAG_MEMDOWNSIZE	0x10	/* move from small to big board */
#define	DR_MFLAG_MEMRESIZE	0x18	/* move to different size board */
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
				    mlist,
				    basepa,
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
	err = kphysm_del_start(mp->sbm_memhandle, dr_mem_del_done,
	    (void *) &rms);
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
			dr_dev_err(CE_IGNORE, &mp->sbm_cm, e_code);
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
	for (mc = ml; mc; mc = mc->ml_next) {
		int		 rv;
		sbd_error_t	*err;

		rv = kphysm_add_memory_dynamic(
		    (pfn_t)(mc->ml_address >> PAGESHIFT),
		    (pgcnt_t)(mc->ml_size >> PAGESHIFT));
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

	/* back out if configure failed */
	if (mp->sbm_cm.sbdev_error != NULL) {
		dr_lock_status(hp->h_bd);
		err = drmach_unconfigure(cp->sbdev_id,
		    DEVI_BRANCH_DESTROY);
		if (err)
			sbd_err_clear(&err);
		dr_unlock_status(hp->h_bd);
	}
}

#define	DR_SCRUB_VALUE	0x0d0e0a0d0b0e0e0fULL

static void
dr_mem_ecache_scrub(dr_mem_unit_t *mp, struct memlist *mlist)
{
#ifdef DEBUG
	clock_t		stime = ddi_get_lbolt();
#endif /* DEBUG */

	struct memlist	*ml;
	uint64_t	scrub_value = DR_SCRUB_VALUE;
	processorid_t	cpuid;
	static fn_t	f = "dr_mem_ecache_scrub";

	cpuid = drmach_mem_cpu_affinity(mp->sbm_cm.sbdev_id);
	affinity_set(cpuid);

	PR_MEM("%s: using proc %d, memlist...\n", f,
	    (cpuid == CPU_CURRENT) ? CPU->cpu_id : cpuid);
	PR_MEMLIST_DUMP(mlist);

	for (ml = mlist; ml; ml = ml->ml_next) {
		uint64_t	dst_pa;
		uint64_t	nbytes;

		/* calculate the destination physical address */
		dst_pa = ml->ml_address;
		if (ml->ml_address & PAGEOFFSET)
			cmn_err(CE_WARN,
			    "%s: address (0x%lx) not on "
			    "page boundary", f, ml->ml_address);

		nbytes = ml->ml_size;
		if (ml->ml_size & PAGEOFFSET)
			cmn_err(CE_WARN,
			    "%s: size (0x%lx) not on "
			    "page boundary", f, ml->ml_size);

		/*LINTED*/
		while (nbytes > 0) {
			/* write 64 bits to dst_pa */
			stdphys(dst_pa, scrub_value);

			/* increment/decrement by cacheline sizes */
			dst_pa += DRMACH_COHERENCY_UNIT;
			nbytes -= DRMACH_COHERENCY_UNIT;
		}
	}

	/*
	 * flush this cpu's ecache and take care to ensure
	 * that all of it's bus transactions have retired.
	 */
	drmach_cpu_flush_ecache_sync();

	affinity_clear();

#ifdef DEBUG
	stime = ddi_get_lbolt() - stime;
	PR_MEM("%s: scrub ticks = %ld (%ld secs)\n", f, stime, stime / hz);
#endif /* DEBUG */
}

static int
dr_move_memory(dr_handle_t *hp, dr_mem_unit_t *s_mp, dr_mem_unit_t *t_mp)
{
	time_t		 copytime;
	drmachid_t	 cr_id;
	dr_sr_handle_t	*srhp;
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
		c_ml = memlist_del_span(c_ml, d_ml->ml_address, d_ml->ml_size);
		d_ml = d_ml->ml_next;
	}

	affinity_set(drmach_mem_cpu_affinity(t_mp->sbm_cm.sbdev_id));

	err = drmach_copy_rename_init(
	    t_mp->sbm_cm.sbdev_id, _ptob64(t_mp->sbm_slice_offset),
	    s_mp->sbm_cm.sbdev_id, c_ml, &cr_id);
	if (err) {
		DRERR_SET_C(&s_mp->sbm_cm.sbdev_error, &err);
		affinity_clear();
		return (-1);
	}

	srhp = dr_get_sr_handle(hp);
	ASSERT(srhp);

	copytime = ddi_get_lbolt();

	/* Quiesce the OS.  */
	if (dr_suspend(srhp)) {
		cmn_err(CE_WARN, "%s: failed to quiesce OS"
		    " for copy-rename", f);

		dr_release_sr_handle(srhp);
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

		affinity_clear();
		return (-1);
	}

	/*
	 * Rename memory for lgroup.
	 * Source and target board numbers are packaged in arg.
	 */
	{
		dr_board_t	*t_bp, *s_bp;

		s_bp = s_mp->sbm_cm.sbdev_bp;
		t_bp = t_mp->sbm_cm.sbdev_bp;

		lgrp_plat_config(LGRP_CONFIG_MEM_RENAME,
		    (uintptr_t)(s_bp->b_num | (t_bp->b_num << 16)));
	}

	drmach_copy_rename(cr_id);

	/* Resume the OS.  */
	dr_resume(srhp);

	copytime = ddi_get_lbolt() - copytime;

	dr_release_sr_handle(srhp);
	err = drmach_copy_rename_fini(cr_id);
	if (err)
		DRERR_SET_C(&s_mp->sbm_cm.sbdev_error, &err);

	affinity_clear();

	PR_MEM("%s: copy-rename elapsed time = %ld ticks (%ld secs)\n",
	    f, copytime, copytime / hz);

	/* return -1 if dr_suspend or copy/rename recorded an error */
	return (err == NULL ? 0 : -1);
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
	 * Scrub deleted memory.  This will cause all cachelines
	 * referencing the memory to only be in the local cpu's
	 * ecache.
	 */
	if (s_mp->sbm_flags & DR_MFLAG_RELDONE) {
		/* no del mlist for src<=dst mem size copy/rename */
		if (s_mp->sbm_del_mlist)
			dr_mem_ecache_scrub(s_mp, s_mp->sbm_del_mlist);
	}
	if (t_mp != NULL && (t_mp->sbm_flags & DR_MFLAG_RELDONE)) {
		ASSERT(t_mp->sbm_del_mlist);
		dr_mem_ecache_scrub(t_mp, t_mp->sbm_del_mlist);
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
		err = drmach_unconfigure(s_mp->sbm_cm.sbdev_id,
		    DEVI_BRANCH_DESTROY);
		dr_unlock_status(hp->h_bd);
		if (err)
			sbd_err_clear(&err);
	}
}

/*
 * XXX workaround for certain lab configurations (see also starcat drmach.c)
 * Temporary code to get around observed incorrect results from
 * kphysm_del_span_query when the queried span contains address spans
 * not occupied by memory in between spans that do have memory.
 * This routine acts as a wrapper to kphysm_del_span_query.  It builds
 * a memlist from phys_install of spans that exist between base and
 * base + npages, inclusively.  Kphysm_del_span_query is called for each
 * node in the memlist with the results accumulated in *mp.
 */
static int
dr_del_span_query(pfn_t base, pgcnt_t npages, memquery_t *mp)
{
	uint64_t	 pa = _ptob64(base);
	uint64_t	 sm = ~ (137438953472ull - 1);
	uint64_t	 sa = pa & sm;
	struct memlist	*mlist, *ml;
	int		 rv;

	npages = npages; /* silence lint */
	memlist_read_lock();
	mlist = memlist_dup(phys_install);
	memlist_read_unlock();

again:
	for (ml = mlist; ml; ml = ml->ml_next) {
		if ((ml->ml_address & sm) != sa) {
			mlist = memlist_del_span(mlist,
			    ml->ml_address, ml->ml_size);
			goto again;
		}
	}

	mp->phys_pages = 0;
	mp->managed = 0;
	mp->nonrelocatable = 0;
	mp->first_nonrelocatable = (pfn_t)-1;	/* XXX */
	mp->last_nonrelocatable = 0;

	for (ml = mlist; ml; ml = ml->ml_next) {
		memquery_t mq;

		rv = kphysm_del_span_query(
		    _b64top(ml->ml_address), _b64top(ml->ml_size), &mq);
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

	memlist_delete(mlist);
	return (rv);
}

#define	kphysm_del_span_query dr_del_span_query

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

		(void) strncpy(msp->ms_cm.c_id.c_name, pstat.type,
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

			(void) snprintf(msp->ms_peer_ap_id,
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

			rv = kphysm_del_span_query(mp->sbm_basepfn,
			    mp->sbm_npages, &mq);

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
			dr_dev_err(CE_WARN, &mp->sbm_cm, ESBD_MEMFAIL);
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

/*
 * TODO: why is this call to dr_init_mem_unit_data here?
 * this has been done at discovery or connect time, so this is
 * probably redundant and unnecessary.
 */
		dr_init_mem_unit_data(mp);
	}

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

	for (; ml; ml = ml->ml_next) {
		pfn_t		 base;
		pgcnt_t		 npgs;
		int		 rv;
		sbd_error_t	*err;

		base = _b64top(ml->ml_address);
		npgs = _b64top(ml->ml_size);

		rv = kphysm_add_memory_dynamic(base, npgs);

		err = drmach_mem_add_span(
		    mp->sbm_cm.sbdev_id,
		    ml->ml_address,
		    ml->ml_size);

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
dr_post_detach_mem_unit(dr_mem_unit_t *s_mp)
{
	uint64_t	sz = s_mp->sbm_slice_size;
	uint64_t	sm = sz - 1;
	/* old and new below refer to PAs before and after copy-rename */
	uint64_t	s_old_basepa, s_new_basepa;
	uint64_t	t_old_basepa, t_new_basepa;
	uint64_t	t_new_smallsize = 0;
	dr_mem_unit_t	*t_mp, *x_mp;
	struct memlist	*ml;
	int		rv;
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
	err = drmach_mem_get_base_physaddr(s_mp->sbm_cm.sbdev_id,
	    &s_new_basepa);
	ASSERT(err == NULL);

	PR_MEM("%s:s_old_basepa: 0x%lx\n", f, s_old_basepa);
	PR_MEM("%s:s_new_basepa: 0x%lx\n", f, s_new_basepa);

	if (t_mp != NULL) {
		struct memlist *s_copy_mlist;

		t_old_basepa	= _ptob64(t_mp->sbm_basepfn);
		err = drmach_mem_get_base_physaddr(t_mp->sbm_cm.sbdev_id,
		    &t_new_basepa);
		ASSERT(err == NULL);

		PR_MEM("%s:t_old_basepa: 0x%lx\n", f, t_old_basepa);
		PR_MEM("%s:t_new_basepa: 0x%lx\n", f, t_new_basepa);

		/*
		 * Construct copy list with original source addresses.
		 * Used to add back excess target mem.
		 */
		s_copy_mlist = memlist_dup(s_mp->sbm_mlist);
		for (ml = s_mp->sbm_del_mlist; ml; ml = ml->ml_next) {
			s_copy_mlist = memlist_del_span(s_copy_mlist,
			    ml->ml_address, ml->ml_size);
		}

		PR_MEM("%s: source copy list:\n:", f);
		PR_MEMLIST_DUMP(s_copy_mlist);

		/*
		 * We had to swap mem-units, so update
		 * memlists accordingly with new base
		 * addresses.
		 */
		for (ml = t_mp->sbm_mlist; ml; ml = ml->ml_next) {
			ml->ml_address -= t_old_basepa;
			ml->ml_address += t_new_basepa;
		}

		/*
		 * There is no need to explicitly rename the target delete
		 * memlist, because sbm_del_mlist and sbm_mlist always
		 * point to the same memlist for a copy/rename operation.
		 */
		ASSERT(t_mp->sbm_del_mlist == t_mp->sbm_mlist);

		PR_MEM("%s: renamed target memlist and delete memlist:\n", f);
		PR_MEMLIST_DUMP(t_mp->sbm_mlist);

		for (ml = s_mp->sbm_mlist; ml; ml = ml->ml_next) {
			ml->ml_address -= s_old_basepa;
			ml->ml_address += s_new_basepa;
		}

		PR_MEM("%s: renamed source memlist:\n", f);
		PR_MEMLIST_DUMP(s_mp->sbm_mlist);

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
		 * If the target memory range with the new target base PA
		 * extends beyond the usable slice, prevent any "target excess"
		 * from being added back after this copy/rename and
		 * calculate the new smaller size of the target board
		 * to be set as part of target cleanup. The base + npages
		 * must only include the range of memory up to the end of
		 * this slice. This will only be used after a category 4
		 * large-to-small target type copy/rename - see comments
		 * in dr_select_mem_target.
		 */
		if (((t_new_basepa & sm) + _ptob64(t_mp->sbm_npages)) > sz) {
			t_new_smallsize = sz - (t_new_basepa & sm);
		}

		if (s_mp->sbm_flags & DR_MFLAG_MEMRESIZE &&
		    t_new_smallsize == 0) {
			struct memlist	*t_excess_mlist;

			/*
			 * Add back excess target memory.
			 * Subtract out the portion of the target memory
			 * node that was taken over by the source memory
			 * node.
			 */
			t_excess_mlist = memlist_dup(t_mp->sbm_mlist);
			for (ml = s_copy_mlist; ml; ml = ml->ml_next) {
				t_excess_mlist =
				    memlist_del_span(t_excess_mlist,
				    ml->ml_address, ml->ml_size);
			}

			/*
			 * Update dynamically added segs
			 */
			for (ml = s_mp->sbm_del_mlist; ml; ml = ml->ml_next) {
				t_mp->sbm_dyn_segs =
				    memlist_del_span(t_mp->sbm_dyn_segs,
				    ml->ml_address, ml->ml_size);
			}
			for (ml = t_excess_mlist; ml; ml = ml->ml_next) {
				t_mp->sbm_dyn_segs =
				    memlist_cat_span(t_mp->sbm_dyn_segs,
				    ml->ml_address, ml->ml_size);
			}
			PR_MEM("%s: %s: updated dynamic seg list:\n",
			    f, t_mp->sbm_cm.sbdev_path);
			PR_MEMLIST_DUMP(t_mp->sbm_dyn_segs);

			PR_MEM("%s: adding back remaining portion"
			    " of %s, memlist:\n",
			    f, t_mp->sbm_cm.sbdev_path);
			PR_MEMLIST_DUMP(t_excess_mlist);

			dr_add_memory_spans(s_mp, t_excess_mlist);
			memlist_delete(t_excess_mlist);
		}
		memlist_delete(s_copy_mlist);

#ifdef DEBUG
		/*
		 * Renaming s_mp->sbm_del_mlist is not necessary.  This
		 * list is not used beyond this point, and in fact, is
		 * disposed of at the end of this function.
		 */
		for (ml = s_mp->sbm_del_mlist; ml; ml = ml->ml_next) {
			ml->ml_address -= s_old_basepa;
			ml->ml_address += s_new_basepa;
		}

		PR_MEM("%s: renamed source delete memlist", f);
		PR_MEMLIST_DUMP(s_mp->sbm_del_mlist);
#endif

	}

	if (t_mp != NULL) {
		/* delete target's entire address space */
		err = drmach_mem_del_span(t_mp->sbm_cm.sbdev_id,
		    t_old_basepa & ~ sm, sz);
		if (err)
			DRERR_SET_C(&t_mp->sbm_cm.sbdev_error, &err);
		ASSERT(err == NULL);

		/*
		 * After the copy/rename, the original address space
		 * for the source board (which is now located on the
		 * target board) may now have some excess to be deleted.
		 * The amount is calculated by masking the slice
		 * info and keeping the slice offset from t_new_basepa.
		 */
		err = drmach_mem_del_span(s_mp->sbm_cm.sbdev_id,
		    s_old_basepa & ~ sm, t_new_basepa & sm);
		if (err)
			DRERR_SET_C(&s_mp->sbm_cm.sbdev_error, &err);
		ASSERT(err == NULL);

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

		/* reduce target size if new PAs go past end of usable slice */
		if (t_new_smallsize > 0) {
			t_mp->sbm_npages = _b64top(t_new_smallsize);
			PR_MEM("%s: target new size 0x%lx bytes\n",
			    f, t_new_smallsize);
		}
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

		/*
		 * Check whether the detaching memory requires a
		 * copy-rename.
		 */
		ASSERT(mp->sbm_npages != 0);
		rv = kphysm_del_span_query(mp->sbm_basepfn, mp->sbm_npages,
		    &mq);
		if (rv != KPHYSM_OK) {
			DR_DEV_INTERNAL_ERROR(&mp->sbm_cm);
			err_flag = 1;
			break;
		}

		if (mq.nonrelocatable != 0) {
			if (!(dr_cmd_flags(hp) &
			    (SBD_FLAG_FORCE | SBD_FLAG_QUIESCE_OKAY))) {
				/* caller wasn't prompted for a suspend */
				dr_dev_err(CE_WARN, &mp->sbm_cm,
				    ESBD_QUIESCE_REQD);
				err_flag = 1;
				break;
			}
		}

		/* flags should be clean at this time */
		ASSERT(mp->sbm_flags == 0);

		ASSERT(mp->sbm_mlist == NULL);		/* should be null */
		ASSERT(mp->sbm_del_mlist == NULL);	/* should be null */
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

				dr_dev_err(CE_WARN, &mp->sbm_cm,
				    ESBD_NO_TARGET);

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
		PR_MEM("%s: %s: error %d noted\n",
		    f,
		    s_mp->sbm_cm.sbdev_path,
		    s_mp->sbm_cm.sbdev_error->e_code);

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
	ASSERT(state == DR_STATE_CONNECTED || state == DR_STATE_UNCONFIGURED);
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

			dr_device_transition(&t_mp->sbm_cm,
			    DR_STATE_CONFIGURED);
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
	uint64_t	bytes;
	sbd_error_t	*err;
	static fn_t	f = "dr_init_mem_unit_data";
	update_membounds_t umb;

	PR_MEM("%s...\n", f);

	/* a little sanity checking */
	ASSERT(mp->sbm_peer == NULL);
	ASSERT(mp->sbm_flags == 0);

	/* get basepfn of mem unit */
	err = drmach_mem_get_base_physaddr(id, &bytes);
	if (err) {
		DRERR_SET_C(&mp->sbm_cm.sbdev_error, &err);
		mp->sbm_basepfn = (pfn_t)-1;
	} else
		mp->sbm_basepfn = _b64top(bytes);

	/* attempt to get number of pages from PDA */
	err = drmach_mem_get_size(id, &bytes);
	if (err) {
		DRERR_SET_C(&mp->sbm_cm.sbdev_error, &err);
		mp->sbm_npages = 0;
	} else
		mp->sbm_npages = _b64top(bytes);

	/* if didn't work, calculate using memlist */
	if (mp->sbm_npages == 0) {
		struct memlist	*ml, *mlist;
		/*
		 * Either we couldn't open the PDA or our
		 * PDA has garbage in it.  We must have the
		 * page count consistent and whatever the
		 * OS states has precedence over the PDA
		 * so let's check the kernel.
		 */
/* TODO: curious comment. it suggests pda query should happen if this fails */
		PR_MEM("%s: PDA query failed for npages."
		    " Checking memlist for %s\n",
		    f, mp->sbm_cm.sbdev_path);

		mlist = dr_get_memlist(mp);
		for (ml = mlist; ml; ml = ml->ml_next)
			mp->sbm_npages += btop(ml->ml_size);
		memlist_delete(mlist);
	}

	err = drmach_mem_get_alignment(id, &bytes);
	if (err) {
		DRERR_SET_C(&mp->sbm_cm.sbdev_error, &err);
		mp->sbm_alignment_mask = 0;
	} else
		mp->sbm_alignment_mask = _b64top(bytes);

	err = drmach_mem_get_slice_size(id, &bytes);
	if (err) {
		DRERR_SET_C(&mp->sbm_cm.sbdev_error, &err);
		mp->sbm_slice_size = 0; /* paranoia */
	} else
		mp->sbm_slice_size = bytes;

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
	for (mc = ml; mc != NULL; mc = mc->ml_next) {
		base = _b64top(mc->ml_address);
		npgs = _b64top(mc->ml_size);

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

/* debug counters */
int dr_smt_realigned;
int dr_smt_preference[4];

#ifdef DEBUG
uint_t dr_ignore_board; /* if bit[bnum-1] set, board won't be candidate */
#endif

/*
 * Find and reserve a copy/rename target board suitable for the
 * given source board.
 * All boards in the system are examined and categorized in relation to
 * their memory size versus the source board's memory size.  Order of
 * preference is:
 *	1st: board has same memory size
 * 	2nd: board has larger memory size
 *	3rd: board has smaller memory size
 *	4th: board has smaller memory size, available memory will be reduced.
 * Boards in category 3 and 4 will have their MC's reprogrammed to locate the
 * span to which the MC responds to address span that appropriately covers
 * the nonrelocatable span of the source board.
 */
static int
dr_select_mem_target(dr_handle_t *hp,
	dr_mem_unit_t *s_mp, struct memlist *s_ml)
{
	pgcnt_t		sz = _b64top(s_mp->sbm_slice_size);
	pgcnt_t		sm = sz - 1; /* mem_slice_mask */
	pfn_t		s_phi, t_phi;

	int		n_sets = 4; /* same, larger, smaller, clipped */
	int		preference; /* lower value is higher preference */
	int		n_units_per_set;
	int		idx;
	dr_mem_unit_t	**sets;

	int		t_bd;
	int		t_unit;
	int		rv;
	int		allow_src_memrange_modify;
	int		allow_targ_memrange_modify;
	drmachid_t	t_id;
	dr_board_t	*s_bp, *t_bp;
	dr_mem_unit_t	*t_mp, *c_mp;
	struct memlist	*d_ml, *t_ml, *x_ml;
	memquery_t	s_mq = {0};
	static fn_t	f = "dr_select_mem_target";

	PR_MEM("%s...\n", f);

	ASSERT(s_ml != NULL);

	n_units_per_set = MAX_BOARDS * MAX_MEM_UNITS_PER_BOARD;
	sets = GETSTRUCT(dr_mem_unit_t *, n_units_per_set * n_sets);

	s_bp = hp->h_bd;
	/* calculate the offset into the slice of the last source board pfn */
	ASSERT(s_mp->sbm_npages != 0);
	s_phi = (s_mp->sbm_basepfn + s_mp->sbm_npages - 1) & sm;

	allow_src_memrange_modify = drmach_allow_memrange_modify(s_bp->b_id);

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

			/*
			 * categorize the memory node
			 * If this is a smaller memory node, create a
			 * temporary, edited copy of the source board's
			 * memlist containing only the span of the non-
			 * relocatable pages.
			 */
			t_phi = (t_mp->sbm_basepfn + t_mp->sbm_npages - 1) & sm;
			t_id = t_mp->sbm_cm.sbdev_bp->b_id;
			allow_targ_memrange_modify =
			    drmach_allow_memrange_modify(t_id);
			if (t_mp->sbm_npages == s_mp->sbm_npages &&
			    t_phi == s_phi) {
				preference = 0;
				t_mp->sbm_slice_offset = 0;
			} else if (t_mp->sbm_npages > s_mp->sbm_npages &&
			    t_phi > s_phi) {
				/*
				 * Selecting this target will require modifying
				 * the source and/or target physical address
				 * ranges.  Skip if not supported by platform.
				 */
				if (!allow_src_memrange_modify ||
				    !allow_targ_memrange_modify) {
					PR_MEM("%s: skip target %s, memory "
					    "range relocation not supported "
					    "by platform\n", f,
					    t_mp->sbm_cm.sbdev_path);
					continue;
				}
				preference = 1;
				t_mp->sbm_slice_offset = 0;
			} else {
				pfn_t		pfn = 0;

				/*
				 * Selecting this target will require modifying
				 * the source and/or target physical address
				 * ranges.  Skip if not supported by platform.
				 */
				if (!allow_src_memrange_modify ||
				    !allow_targ_memrange_modify) {
					PR_MEM("%s: skip target %s, memory "
					    "range relocation not supported "
					    "by platform\n", f,
					    t_mp->sbm_cm.sbdev_path);
					continue;
				}

				/*
				 * Check if its mc can be programmed to relocate
				 * the active address range to match the
				 * nonrelocatable span of the source board.
				 */
				preference = 2;

				if (s_mq.phys_pages == 0) {
					/*
					 * find non-relocatable span on
					 * source board.
					 */
					rv = kphysm_del_span_query(
					    s_mp->sbm_basepfn,
					    s_mp->sbm_npages, &s_mq);
					if (rv != KPHYSM_OK) {
						PR_MEM("%s: %s: unexpected"
						    " kphysm_del_span_query"
						    " return value %d;"
						    " basepfn 0x%lx,"
						    " npages %ld\n",
						    f,
						    s_mp->sbm_cm.sbdev_path,
						    rv,
						    s_mp->sbm_basepfn,
						    s_mp->sbm_npages);

						/* paranoia */
						s_mq.phys_pages = 0;

						continue;
					}

					/* more paranoia */
					ASSERT(s_mq.phys_pages != 0);
					ASSERT(s_mq.nonrelocatable != 0);

					/*
					 * this should not happen
					 * if it does, it simply means that
					 * we can not proceed with qualifying
					 * this target candidate.
					 */
					if (s_mq.nonrelocatable == 0)
						continue;

					PR_MEM("%s: %s: nonrelocatable"
					    " span (0x%lx..0x%lx)\n",
					    f,
					    s_mp->sbm_cm.sbdev_path,
					    s_mq.first_nonrelocatable,
					    s_mq.last_nonrelocatable);
				}

				/*
				 * Round down the starting pfn of the
				 * nonrelocatable span on the source board
				 * to nearest programmable boundary possible
				 * with this target candidate.
				 */
				pfn = s_mq.first_nonrelocatable &
				    ~t_mp->sbm_alignment_mask;

				/* skip candidate if memory is too small */
				if (pfn + t_mp->sbm_npages <
				    s_mq.last_nonrelocatable)
					continue;

				/*
				 * reprogramming an mc to relocate its
				 * active address range means the beginning
				 * address to which the DIMMS respond will
				 * be somewhere above the slice boundary
				 * address.  The larger the size of memory
				 * on this unit, the more likely part of it
				 * will exist beyond the end of the slice.
				 * The portion of the memory that does is
				 * unavailable to the system until the mc
				 * reprogrammed to a more favorable base
				 * address.
				 * An attempt is made to avoid the loss by
				 * recalculating the mc base address relative
				 * to the end of the slice.  This may produce
				 * a more favorable result.  If not, we lower
				 * the board's preference rating so that it
				 * is one the last candidate boards to be
				 * considered.
				 */
				if ((pfn + t_mp->sbm_npages) & ~sm) {
					pfn_t p;

					ASSERT(sz >= t_mp->sbm_npages);

					/*
					 * calculate an alternative starting
					 * address relative to the end of the
					 * slice's address space.
					 */
					p = pfn & ~sm;
					p = p + (sz - t_mp->sbm_npages);
					p = p & ~t_mp->sbm_alignment_mask;

					if ((p > s_mq.first_nonrelocatable) ||
					    (p + t_mp->sbm_npages <
					    s_mq.last_nonrelocatable)) {

						/*
						 * alternative starting addr
						 * won't work. Lower preference
						 * rating of this board, since
						 * some number of pages will
						 * unavailable for use.
						 */
						preference = 3;
					} else {
						dr_smt_realigned++;
						pfn = p;
					}
				}

				/*
				 * translate calculated pfn to an offset
				 * relative to the slice boundary.  If the
				 * candidate board is selected, this offset
				 * will be used to calculate the values
				 * programmed into the mc.
				 */
				t_mp->sbm_slice_offset = pfn & sm;
				PR_MEM("%s: %s:"
				    "  proposed mc offset 0x%lx\n",
				    f,
				    t_mp->sbm_cm.sbdev_path,
				    t_mp->sbm_slice_offset);
			}

			dr_smt_preference[preference]++;

			/* calculate index to start of preference set */
			idx  = n_units_per_set * preference;
			/* calculate offset to respective element */
			idx += t_bd * MAX_MEM_UNITS_PER_BOARD + t_unit;

			ASSERT(idx < n_units_per_set * n_sets);
			sets[idx] = t_mp;
		}
	}

	/*
	 * NOTE: this would be a good place to sort each candidate
	 * set in to some desired order, e.g. memory size in ascending
	 * order.  Without an additional sorting step here, the order
	 * within a set is ascending board number order.
	 */

	c_mp = NULL;
	x_ml = NULL;
	t_ml = NULL;
	for (idx = 0; idx < n_units_per_set * n_sets; idx++) {
		memquery_t mq;

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

		/* get appropriate source board memlist */
		t_phi = (t_mp->sbm_basepfn + t_mp->sbm_npages - 1) & sm;
		if (t_mp->sbm_npages < s_mp->sbm_npages || t_phi < s_phi) {
			spgcnt_t excess;

			/*
			 * make a copy of the source board memlist
			 * then edit it to remove the spans that
			 * are outside the calculated span of
			 * [pfn..s_mq.last_nonrelocatable].
			 */
			if (x_ml != NULL)
				memlist_delete(x_ml);

			x_ml = memlist_dup(s_ml);
			if (x_ml == NULL) {
				PR_MEM("%s: memlist_dup failed\n", f);
				/* TODO: should abort */
				continue;
			}

			/* trim off lower portion */
			excess = t_mp->sbm_slice_offset -
			    (s_mp->sbm_basepfn & sm);

			if (excess > 0) {
				x_ml = memlist_del_span(
				    x_ml,
				    _ptob64(s_mp->sbm_basepfn),
				    _ptob64(excess));
			}
			ASSERT(x_ml);

			/*
			 * Since this candidate target board is smaller
			 * than the source board, s_mq must have been
			 * initialized in previous loop while processing
			 * this or some other candidate board.
			 * FIXME: this is weak.
			 */
			ASSERT(s_mq.phys_pages != 0);

			/* trim off upper portion */
			excess = (s_mp->sbm_basepfn + s_mp->sbm_npages)
			    - (s_mq.last_nonrelocatable + 1);
			if (excess > 0) {
				pfn_t p;

				p  = s_mq.last_nonrelocatable + 1;
				x_ml = memlist_del_span(
				    x_ml,
				    _ptob64(p),
				    _ptob64(excess));
			}

			PR_MEM("%s: %s: edited source memlist:\n",
			    f, s_mp->sbm_cm.sbdev_path);
			PR_MEMLIST_DUMP(x_ml);

#ifdef DEBUG
			/* sanity check memlist */
			d_ml = x_ml;
			while (d_ml->ml_next != NULL)
				d_ml = d_ml->ml_next;

			ASSERT(d_ml->ml_address + d_ml->ml_size ==
			    _ptob64(s_mq.last_nonrelocatable + 1));
#endif

			/*
			 * x_ml now describes only the portion of the
			 * source board that will be moved during the
			 * copy/rename operation.
			 */
			d_ml = x_ml;
		} else {
			/* use original memlist; all spans will be moved */
			d_ml = s_ml;
		}

		/* verify target can support source memory spans. */
		if (memlist_canfit(d_ml, t_ml) == 0) {
			PR_MEM("%s: source memlist won't"
			    " fit in target memlist\n", f);
			PR_MEM("%s: source memlist:\n", f);
			PR_MEMLIST_DUMP(d_ml);
			PR_MEM("%s: target memlist:\n", f);
			PR_MEMLIST_DUMP(t_ml);

			continue;
		}

		/* NOTE: the value of d_ml is not used beyond this point */

		PR_MEM("%s: checking for no-reloc in %s, "
		    " basepfn=0x%lx, npages=%ld\n",
		    f,
		    t_mp->sbm_cm.sbdev_path,
		    t_mp->sbm_basepfn,
		    t_mp->sbm_npages);

		rv = kphysm_del_span_query(
		    t_mp->sbm_basepfn, t_mp->sbm_npages, &mq);
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
		 * When the number of pages on the candidate target
		 * board is less than the number of pages on the source,
		 * then some spans (clearly) of the source board's address
		 * space will not be covered by physical memory after the
		 * copy/rename completes.  The following code block
		 * schedules those spans to be deleted.
		 */
		if (t_mp->sbm_npages < s_mp->sbm_npages || t_phi < s_phi) {
			pfn_t pfn;
			uint64_t s_del_pa;
			struct memlist *ml;

			d_ml = memlist_dup(s_ml);
			if (d_ml == NULL) {
				PR_MEM("%s: cant dup src brd memlist\n", f);
				/* TODO: should abort */
				continue;
			}

			/* calculate base pfn relative to target board */
			pfn  = s_mp->sbm_basepfn & ~sm;
			pfn += t_mp->sbm_slice_offset;

			/*
			 * cannot split dynamically added segment
			 */
			s_del_pa = _ptob64(pfn + t_mp->sbm_npages);
			PR_MEM("%s: proposed src delete pa=0x%lx\n", f,
			    s_del_pa);
			PR_MEM("%s: checking for split of dyn seg list:\n", f);
			PR_MEMLIST_DUMP(s_mp->sbm_dyn_segs);
			for (ml = s_mp->sbm_dyn_segs; ml; ml = ml->ml_next) {
				if (s_del_pa > ml->ml_address &&
				    s_del_pa < ml->ml_address + ml->ml_size) {
					s_del_pa = ml->ml_address;
					break;
				}
			}

			/* remove span that will reside on candidate board */
			d_ml = memlist_del_span(d_ml, _ptob64(pfn),
			    s_del_pa - _ptob64(pfn));

			PR_MEM("%s: %s: reserving src brd memlist:\n",
			    f, s_mp->sbm_cm.sbdev_path);
			PR_MEMLIST_DUMP(d_ml);

			/* reserve excess spans */
			if (dr_reserve_mem_spans(&s_mp->sbm_memhandle, d_ml)
			    != 0) {

				/* likely more non-reloc pages appeared */
				/* TODO: restart from top? */
				continue;
			}
		} else {
			/* no excess source board memory */
			d_ml = NULL;
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

	FREESTRUCT(sets, dr_mem_unit_t *, n_units_per_set * n_sets);

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

	s_mp->sbm_flags &= ~DR_MFLAG_MEMRESIZE;
	if (c_mp->sbm_npages > s_mp->sbm_npages) {
		s_mp->sbm_flags |= DR_MFLAG_MEMUPSIZE;
		PR_MEM("%s: upsize detected (source=%ld < target=%ld)\n",
		    f, s_mp->sbm_npages, c_mp->sbm_npages);
	} else if (c_mp->sbm_npages < s_mp->sbm_npages) {
		s_mp->sbm_flags |= DR_MFLAG_MEMDOWNSIZE;
		PR_MEM("%s: downsize detected (source=%ld > target=%ld)\n",
		    f, s_mp->sbm_npages, c_mp->sbm_npages);
	}

	return (0);
}

/*
 * Memlist support.
 */

/*
 * Determine whether the source memlist (s_mlist) will
 * fit into the target memlist (t_mlist) in terms of
 * size and holes (i.e. based on same relative base address).
 */
static int
memlist_canfit(struct memlist *s_mlist, struct memlist *t_mlist)
{
	int		rv = 0;
	uint64_t	s_basepa, t_basepa;
	struct memlist	*s_ml, *t_ml;

	if ((s_mlist == NULL) || (t_mlist == NULL))
		return (0);

	/*
	 * Base both memlists on common base address (0).
	 */
	s_basepa = s_mlist->ml_address;
	t_basepa = t_mlist->ml_address;

	for (s_ml = s_mlist; s_ml; s_ml = s_ml->ml_next)
		s_ml->ml_address -= s_basepa;

	for (t_ml = t_mlist; t_ml; t_ml = t_ml->ml_next)
		t_ml->ml_address -= t_basepa;

	s_ml = s_mlist;
	for (t_ml = t_mlist; t_ml && s_ml; t_ml = t_ml->ml_next) {
		uint64_t	s_start, s_end;
		uint64_t	t_start, t_end;

		t_start = t_ml->ml_address;
		t_end = t_start + t_ml->ml_size;

		for (; s_ml; s_ml = s_ml->ml_next) {
			s_start = s_ml->ml_address;
			s_end = s_start + s_ml->ml_size;

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

	/*
	 * Need to add base addresses back since memlists
	 * are probably in use by caller.
	 */
	for (s_ml = s_mlist; s_ml; s_ml = s_ml->ml_next)
		s_ml->ml_address += s_basepa;

	for (t_ml = t_mlist; t_ml; t_ml = t_ml->ml_next)
		t_ml->ml_address += t_basepa;

	return (rv);
}
