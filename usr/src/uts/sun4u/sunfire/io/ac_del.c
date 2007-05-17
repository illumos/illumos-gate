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

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/ddi_impldefs.h>
#include <sys/obpdefs.h>
#include <sys/errno.h>
#include <sys/kmem.h>
#include <sys/vmem.h>
#include <sys/debug.h>
#include <sys/sysmacros.h>
#include <sys/machsystm.h>
#include <sys/machparam.h>
#include <sys/modctl.h>
#include <sys/fhc.h>
#include <sys/ac.h>
#include <sys/vm.h>
#include <sys/cpu_module.h>
#include <vm/seg_kmem.h>
#include <vm/hat_sfmmu.h>
#include <sys/mem_config.h>
#include <sys/mem_cage.h>

extern ac_err_t ac_kpm_err_cvt(int);

int ac_del_clean = 0;

/*
 * Default timeout, in seconds, for delete.
 * Time is counted when no progress is being made.
 */
static int ac_del_timeout = 60;

#define	DEL_PAGESIZE	MMU_PAGESIZE

struct del_status {
	struct del_status *next;
	memhandle_t	handle;
	volatile int	its_done;
	int		done_error;
	kcondvar_t	ac_del_cv;
	int		del_timeout;
	int		del_noprogress;
	ac_err_t	cancel_code;
	timeout_id_t	to_id;
	pgcnt_t		last_collected;
};
static struct del_status *ac_del_list;
static kmutex_t ac_del_mutex;

static struct del_status *
ac_del_alloc_status()
{
	struct del_status *dsp;

	dsp = (struct del_status *)kmem_zalloc(sizeof (*dsp), KM_SLEEP);
	mutex_enter(&ac_del_mutex);
	dsp->next = ac_del_list;
	ac_del_list = dsp;
	mutex_exit(&ac_del_mutex);

	return (dsp);
}

static void
ac_del_free_status(struct del_status *dsp)
{
	struct del_status **dspp;

	mutex_enter(&ac_del_mutex);
	dspp = &ac_del_list;
	while (*dspp != NULL) {
		if (*dspp == dsp)
			break;
		dspp = &(*dspp)->next;
	}
	ASSERT(*dspp == dsp);
	if (*dspp == dsp) {
		*dspp = dsp->next;
	}
	mutex_exit(&ac_del_mutex);
	kmem_free((void *)dsp, sizeof (*dsp));
}

static void
del_comp(void *arg, int error)
{
	struct del_status *dsp;

	dsp = (struct del_status *)arg;
	mutex_enter(&ac_del_mutex);
#ifdef DEBUG
	{
		struct del_status *adsp;
		for (adsp = ac_del_list; adsp != NULL; adsp = adsp->next) {
			if (adsp == dsp)
				break;
		}
		ASSERT(adsp != NULL);
	}
#endif /* DEBUG */
	dsp->its_done = 1;
	dsp->done_error = error;
	cv_signal(&dsp->ac_del_cv);
	mutex_exit(&ac_del_mutex);
}

/*ARGSUSED*/
static void
del_to_scan(void *arg)
{
	struct del_status *dsp;
	int do_cancel;
	memdelstat_t dstat;
	int err;

	dsp = arg;

#ifdef DEBUG
	{
		struct del_status *adsp;

		mutex_enter(&ac_del_mutex);
		for (adsp = ac_del_list; adsp != NULL; adsp = adsp->next) {
			if (adsp == dsp)
				break;
		}
		ASSERT(adsp != NULL);
		mutex_exit(&ac_del_mutex);
	}
#endif /* DEBUG */
	do_cancel = 0;
	err = kphysm_del_status(dsp->handle, &dstat);
	mutex_enter(&ac_del_mutex);
	if (dsp->its_done) {
		mutex_exit(&ac_del_mutex);
		return;
	}
	if ((err == KPHYSM_OK) &&
	    (dsp->last_collected != dstat.collected)) {
		dsp->del_noprogress = 0;
		dsp->last_collected = dstat.collected;
	} else {
		dsp->del_noprogress++;
		if (dsp->del_noprogress >= dsp->del_timeout) {
			if (dsp->cancel_code == 0)
				dsp->cancel_code = AC_ERR_TIMEOUT;
			do_cancel = 1;
		}
	}
	if (!do_cancel)
		dsp->to_id = timeout(del_to_scan, arg, hz);
	else
		dsp->to_id = 0;
	mutex_exit(&ac_del_mutex);
	if (do_cancel)
		(void) kphysm_del_cancel(dsp->handle);
}

static void
del_to_start(struct del_status *dsp)
{
	if (dsp->del_timeout != 0)
		dsp->to_id = timeout(del_to_scan, dsp, hz);
}

static void
del_to_stop(struct del_status *dsp)
{
	timeout_id_t tid;

	while ((tid = dsp->to_id) != 0) {
		dsp->to_id = 0;
		mutex_exit(&ac_del_mutex);
		(void) untimeout(tid);
		mutex_enter(&ac_del_mutex);
	}
}

static int
ac_del_bank_add_span(
	memhandle_t handle,
	ac_cfga_pkt_t *pkt)
{
	uint64_t		decode;
	uint64_t		base_pa;
	uint64_t		bank_size;
	pfn_t			base;
	pgcnt_t			npgs;
	int			errs;
	int			ret;
	struct ac_soft_state	*asp = pkt->softsp;
	uint_t			ilv;

	/*
	 * Cannot delete interleaved banks at the moment.
	 */
	ilv = (pkt->bank == Bank0) ?
	    INTLV0(*asp->ac_memctl) : INTLV1(*asp->ac_memctl);
	if (ilv != 1) {
		AC_ERR_SET(pkt, AC_ERR_MEM_DEINTLV);
		return (EINVAL);
	}
	/*
	 * Determine the physical location of the selected bank
	 */
	decode = (pkt->bank == Bank0) ?
	    *asp->ac_memdecode0 : *asp->ac_memdecode1;
	base_pa = GRP_REALBASE(decode);
	bank_size = GRP_UK2SPAN(decode);

	base = base_pa >> PAGESHIFT;
	npgs = bank_size >> PAGESHIFT;

	/*
	 * Delete the pages from the cage growth list.
	 */
	ret = kcage_range_delete(base, npgs);
	if (ret != 0) {
		/* TODO: Should this be a separate error? */
		AC_ERR_SET(pkt, AC_ERR_KPM_NONRELOC);
		return (EINVAL);
	}

	/*
	 * Add to delete memory list.
	 */

	if ((errs = kphysm_del_span(handle, base, npgs)) != KPHYSM_OK) {
		AC_ERR_SET(pkt, ac_kpm_err_cvt(errs));
		/*
		 * Restore the pages to the cage growth list.
		 * TODO: We should not unconditionally add back
		 * if we conditionally add at memory add time.
		 */
		errs = kcage_range_add(base, npgs, KCAGE_DOWN);
		/* TODO: deal with error return. */
		if (errs != 0) {
			AC_ERR_SET(pkt, ac_kpm_err_cvt(errs));
			cmn_err(CE_NOTE, "ac_del_bank_add_span(): "
			    "board %d, bank %d, "
			    "kcage_range_add() returned %d",
			    pkt->softsp->board, pkt->bank, errs);
		}
		return (EINVAL);
	}
	return (0);
}

static void
ac_del_bank_add_cage(
	struct bd_list *del,
	enum ac_bank_id bank)
{
	uint64_t		decode;
	uint64_t		base_pa;
	uint64_t		bank_size;
	pfn_t			base;
	pgcnt_t			npgs;
	int			errs;
	struct ac_soft_state	*asp = (struct ac_soft_state *)(del->ac_softsp);

	/*
	 * Determine the physical location of the selected bank
	 */
	decode = (bank == Bank0) ? *asp->ac_memdecode0 : *asp->ac_memdecode1;
	base_pa = GRP_REALBASE(decode);
	bank_size = GRP_UK2SPAN(decode);

	base = base_pa >> PAGESHIFT;
	npgs = bank_size >> PAGESHIFT;

	/*
	 * Restore the pages to the cage growth list.
	 * TODO: We should not unconditionally add back
	 * if we conditionally add at memory add time.
	 */
	errs = kcage_range_add(base, npgs, KCAGE_DOWN);
	/* TODO: deal with error return. */
	if (errs != 0)
		cmn_err(CE_NOTE, "ac_del_bank_add_cage(): "
		    "board %d, bank %d, "
		    "kcage_range_add() returned %d",
		    del->sc.board, bank, errs);
}

static int
ac_del_bank_run(struct del_status *dsp, ac_cfga_pkt_t *pkt)
{
	int errs;

	dsp->its_done = 0;
	if ((errs = kphysm_del_start(dsp->handle, del_comp, (void *)dsp)) !=
	    KPHYSM_OK) {
		AC_ERR_SET(pkt, ac_kpm_err_cvt(errs));
		return (EINVAL);
	}
	/* Wait for it to complete. */
	mutex_enter(&ac_del_mutex);
	del_to_start(dsp);
	while (!dsp->its_done) {
		if (!cv_wait_sig(&dsp->ac_del_cv, &ac_del_mutex)) {
			if (dsp->cancel_code == 0)
				dsp->cancel_code = AC_ERR_INTR;
			mutex_exit(&ac_del_mutex);
			errs = kphysm_del_cancel(dsp->handle);
			mutex_enter(&ac_del_mutex);
			if (errs != KPHYSM_OK) {
				ASSERT(errs == KPHYSM_ENOTRUNNING);
			}
			break;
		}
	}
	/*
	 * If the loop exited due to a signal, we must continue to wait
	 * using cv_wait() as the signal is pending until syscall exit.
	 */
	while (!dsp->its_done) {
		cv_wait(&dsp->ac_del_cv, &ac_del_mutex);
	}
	if (dsp->done_error != KPHYSM_OK) {
		AC_ERR_SET(pkt, ac_kpm_err_cvt(dsp->done_error));
		if ((dsp->done_error == KPHYSM_ECANCELLED) ||
		    (dsp->done_error == KPHYSM_EREFUSED)) {
			errs = EINTR;
			if (dsp->cancel_code != 0) {
				AC_ERR_SET(pkt, dsp->cancel_code);
			}
		} else {
			errs = EINVAL;
		}
	} else
		errs = 0;
	del_to_stop(dsp);
	mutex_exit(&ac_del_mutex);

	return (errs);
}


/*
 * set the memory to known state for debugging
 */
static void
ac_bank_write_pattern(struct bd_list *del, enum ac_bank_id bank)
{
	uint64_t		decode;
	uint64_t		base_pa;
	uint64_t		limit_pa;
	uint64_t		bank_size;
	uint64_t		current_pa;
	caddr_t			base_va;
	caddr_t			fill_buf;
	struct ac_soft_state	*asp = (struct ac_soft_state *)(del->ac_softsp);
	int			linesize;

	/*
	 * Determine the physical location of the selected bank
	 */
	decode = (bank == Bank0) ? *asp->ac_memdecode0 : *asp->ac_memdecode1;
	base_pa = GRP_REALBASE(decode);
	bank_size = GRP_UK2SPAN(decode);
	limit_pa = base_pa + bank_size;
	linesize = cpunodes[CPU->cpu_id].ecache_linesize;

	/*
	 * We need a page_va and a fill buffer for this operation
	 */
	base_va = vmem_alloc(heap_arena, PAGESIZE, VM_SLEEP);
	fill_buf = kmem_zalloc(DEL_PAGESIZE, KM_SLEEP);
	{
		typedef uint32_t patt_t;
		patt_t *bf, *bfe, patt;

		bf = (patt_t *)fill_buf;
		bfe = (patt_t *)((char *)fill_buf + DEL_PAGESIZE);
		patt = 0xbeaddeed;
		while (bf < bfe)
			*bf++ = patt;
	}

	/*
	 * 'empty' the memory
	 */
	kpreempt_disable();
	for (current_pa = base_pa; current_pa < limit_pa;
	    current_pa += DEL_PAGESIZE) {

		/* map current pa */
		ac_mapin(current_pa, base_va);

		/* fill the target page */
		ac_blkcopy(fill_buf, base_va,
			DEL_PAGESIZE/linesize, linesize);

		/* tear down translation */
		ac_unmap(base_va);
	}
	kpreempt_enable();

	/*
	 * clean up temporary resources
	 */
	{
		/* Distinguish the fill buf from memory deleted! */
		typedef uint32_t patt_t;
		patt_t *bf, *bfe, patt;

		bf = (patt_t *)fill_buf;
		bfe = (patt_t *)((char *)fill_buf + DEL_PAGESIZE);
		patt = 0xbeadfeed;
		while (bf < bfe)
			*bf++ = patt;
	}
	kmem_free(fill_buf, DEL_PAGESIZE);
	vmem_free(heap_arena, base_va, PAGESIZE);
}

int
ac_del_memory(ac_cfga_pkt_t *pkt)
{
	struct bd_list *board;
	struct ac_mem_info *mem_info;
	int busy_set;
	struct del_status *dsp;
	memdelstat_t dstat;
	int retval;
	int r_errs;
	struct ac_soft_state *asp;

	if (!kcage_on) {
		static int cage_msg_done = 0;

		if (!cage_msg_done) {
			cage_msg_done = 1;
			cmn_err(CE_NOTE, "ac: memory delete"
			    " refused: cage is off");
		}
		AC_ERR_SET(pkt, ac_kpm_err_cvt(KPHYSM_ENONRELOC));
		return (EINVAL);
	}

	dsp = ac_del_alloc_status();
	if ((retval = kphysm_del_gethandle(&dsp->handle)) != KPHYSM_OK) {
		ac_del_free_status(dsp);
		AC_ERR_SET(pkt, ac_kpm_err_cvt(retval));
		return (EINVAL);
	}
	retval = 0;
	busy_set = 0;

	board = fhc_bdlist_lock(pkt->softsp->board);
	if (board == NULL || board->ac_softsp == NULL) {
		fhc_bdlist_unlock();
		AC_ERR_SET(pkt, AC_ERR_BD);
		retval = EINVAL;
		goto out;
	}
	ASSERT(pkt->softsp == board->ac_softsp);
	asp = pkt->softsp;

	/* verify the board is of the correct type */
	switch (board->sc.type) {
	case CPU_BOARD:
	case MEM_BOARD:
		break;
	default:
		fhc_bdlist_unlock();
		AC_ERR_SET(pkt, AC_ERR_BD_TYPE);
		retval = EINVAL;
		goto out;
	}

	/* verify the memory condition is acceptable */
	mem_info = &asp->bank[pkt->bank];
	if (!MEM_BOARD_VISIBLE(board) || mem_info->busy ||
	    fhc_bd_busy(pkt->softsp->board) ||
	    mem_info->rstate != SYSC_CFGA_RSTATE_CONNECTED ||
	    mem_info->ostate != SYSC_CFGA_OSTATE_CONFIGURED) {
		fhc_bdlist_unlock();
		AC_ERR_SET(pkt, AC_ERR_BD_STATE);
		retval = EINVAL;
		goto out;
	}

	if ((dsp->del_timeout = pkt->cmd_cfga.arg) == -1)
		dsp->del_timeout = ac_del_timeout;

	/*
	 * at this point, we have an available bank to del.
	 * mark it busy and initiate the del function.
	 */
	mem_info->busy = TRUE;
	fhc_bdlist_unlock();

	busy_set = 1;

	retval = ac_del_bank_add_span(dsp->handle, pkt);
out:
	if (retval != 0) {
		r_errs = kphysm_del_release(dsp->handle);
		ASSERT(r_errs == KPHYSM_OK);

		if (busy_set) {
			board = fhc_bdlist_lock(pkt->softsp->board);
			ASSERT(board != NULL && board->ac_softsp != NULL);

			ASSERT(board->sc.type == CPU_BOARD ||
			    board->sc.type == MEM_BOARD);
			ASSERT(asp ==
			    (struct ac_soft_state *)(board->ac_softsp));
			mem_info = &asp->bank[pkt->bank];
			ASSERT(mem_info->busy != FALSE);
			ASSERT(mem_info->ostate == SYSC_CFGA_OSTATE_CONFIGURED);
			mem_info->busy = FALSE;
			fhc_bdlist_unlock();
		}

		ac_del_free_status(dsp);
		return (retval);
	}

	(void) kphysm_del_status(dsp->handle, &dstat);

	retval = ac_del_bank_run(dsp, pkt);

	r_errs = kphysm_del_release(dsp->handle);
	ASSERT(r_errs == KPHYSM_OK);

	board = fhc_bdlist_lock(pkt->softsp->board);
	ASSERT(board != NULL && board->ac_softsp != NULL);

	ASSERT(board->sc.type == CPU_BOARD || board->sc.type == MEM_BOARD);
	ASSERT(asp == (struct ac_soft_state *)(board->ac_softsp));
	mem_info = &asp->bank[pkt->bank];
	ASSERT(mem_info->busy != FALSE);
	ASSERT(mem_info->ostate == SYSC_CFGA_OSTATE_CONFIGURED);
	mem_info->busy = FALSE;
	if (retval == 0) {
		mem_info->ostate = SYSC_CFGA_OSTATE_UNCONFIGURED;
		mem_info->status_change = ddi_get_time();

		if (ac_del_clean) {
			/* DEBUG - set memory to known state */
			ac_bank_write_pattern(board, pkt->bank);
		}
	} else {
		/*
		 * Restore the pages to the cage growth list.
		 */
		ac_del_bank_add_cage(board, pkt->bank);
	}
	fhc_bdlist_unlock();

	ac_del_free_status(dsp);

	return (retval);
}
