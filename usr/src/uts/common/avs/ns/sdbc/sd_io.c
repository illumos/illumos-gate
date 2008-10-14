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

#include <sys/types.h>
#include <sys/ksynch.h>
#include <sys/cmn_err.h>
#include <sys/kmem.h>
#include <sys/buf.h>
#include <sys/cred.h>
#include <sys/errno.h>
#include <sys/ddi.h>

#include <sys/nsc_thread.h>
#include <sys/nsctl/nsctl.h>

#include <sys/sdt.h>		/* dtrace is S10 or later */

#include "sd_bcache.h"
#include "sd_trace.h"
#include "sd_io.h"
#include "sd_bio.h"
#include "sd_misc.h"
#include "sd_ft.h"
#include "sd_pcu.h"

/*
 * dynamic memory support
 */
_dm_process_vars_t dynmem_processing_dm;
static int  sd_dealloc_flag_dm = NO_THREAD_DM;
static void _sd_dealloc_dm(void);
static int  _sd_entry_availability_dm(_sd_cctl_t *cc_ent, int *nodata);

extern void sdbc_requeue_dmchain(_sd_queue_t *, _sd_cctl_t *, int, int);
extern void sdbc_ins_dmqueue_front(_sd_queue_t *q, _sd_cctl_t *cc_ent);
extern void sdbc_remq_dmchain(_sd_queue_t *q, _sd_cctl_t *cc_ent);
extern void sdbc_requeue_head_dm_try(_sd_cctl_t *);
extern int sdbc_use_dmchain;
extern _sd_queue_t *sdbc_dm_queues;

kcondvar_t   _sd_flush_cv;
static volatile int _sd_flush_exit;

/* secret flush toggle flag for testing */
#ifdef DEBUG
int _sdbc_flush_flag = 1; /* 0 ==> noflushing, 1 ==> flush */
#endif

static int sdbc_flush_pageio;



/*
 * Forward declare all statics that are used before defined to enforce
 * parameter checking
 * Some (if not all) of these could be removed if the code were reordered
 */

static void _sd_flcent_ea(blind_t xcc_ent, nsc_off_t fba_pos,
    nsc_size_t fba_len, int error);
static void _sd_flclist_ea(blind_t xcc_ent, nsc_off_t fba_pos,
    nsc_size_t fba_len, int error);
static void _sd_process_reflush(_sd_cctl_t *cc_ent);
static void _sd_flush_thread(void);

int
_sdbc_flush_configure(void)
{
	_sd_flush_exit = 1;
	sdbc_flush_pageio = 0;
	return (nsc_create_process(
		(void (*)(void *))_sd_flush_thread, 0, TRUE));
}


void
_sdbc_flush_deconfigure(void)
{
	_sd_unblock(&_sd_flush_cv);
	_sd_flush_exit = 0;
}

static int
sdbc_alloc_static_cache(int reqblks)
{
	_sd_cctl_t *centry;
	_sd_cctl_t *next_centry;

	if (centry = sdbc_centry_alloc_blks(_CD_NOHASH, 0, reqblks,
		ALLOC_NOWAIT)) {
		/* release the blocks to the queue */
		while (centry) {
			next_centry = centry->cc_chain;
			_sd_centry_release(centry);
			centry = next_centry;
		}
		return (reqblks);
	}
	return (0);
}

int
_sdbc_dealloc_configure_dm(void)
{
	int rc = 0;
	int reqblks = MEGABYTE/BLK_SIZE(1); /* alloc in mb chunks */
	int i;
	int blk_groups; /* number of ~MB groups */
	int blks_remaining;
	int blks_allocd = 0;

	dynmem_processing_dm.alloc_ct = 0;
	dynmem_processing_dm.dealloc_ct = 0;

	if (sdbc_static_cache) { /* alloc all static cache memory here */
		dynmem_processing_dm.max_dyn_list = reqblks;

		blk_groups = CBLOCKS / reqblks;
		blks_remaining = CBLOCKS % reqblks;

		for (i = 0; i < blk_groups; ++i) {
			if (!sdbc_alloc_static_cache(reqblks))
				break;
			blks_allocd += reqblks;
		}
		DTRACE_PROBE2(_sdbc_dealloc_configure_dm1,
				int, i, int, blks_allocd);

		/* if successful then allocate any remaining blocks */
		if ((i == blk_groups) && blks_remaining)
			if (sdbc_alloc_static_cache(blks_remaining))
				blks_allocd += blks_remaining;

		DTRACE_PROBE2(_sdbc_dealloc_configure_dm2,
				int, i, int, blks_allocd);

		sd_dealloc_flag_dm = NO_THREAD_DM;

		if (blks_allocd < CBLOCKS) {
			cmn_err(CE_WARN, "Failed to allocate sdbc cache "
			    "memory.\n requested mem: %d MB; actual mem: %d MB",
			    CBLOCKS/reqblks, blks_allocd/reqblks);
			rc = ENOMEM;
		}


#ifdef DEBUG
		cmn_err(CE_NOTE, "sdbc(_sdbc_dealloc_configure_dm) %d bytes "
			"(%d cache blocks) allocated for static cache, "
			"block size %d", blks_allocd * BLK_SIZE(1), blks_allocd,
			BLK_SIZE(1));
#endif /* DEBUG */
	} else {
		sd_dealloc_flag_dm = PROCESS_CACHE_DM;
		rc = nsc_create_process((void (*)(void *))_sd_dealloc_dm, 0,
			TRUE);
		if (rc != 0)
			sd_dealloc_flag_dm = NO_THREAD_DM;
	}
	return (rc);
}

/*
 * sdbc_dealloc_dm_shutdown - deallocate cache memory.
 *
 * ARGUMENTS: none
 *
 * RETURNS: nothing
 *
 * USAGE:
 *	this function is intended for use after all i/o has stopped and all
 * 	other cache threads have terminated.  write cache resources, if any
 *	are released, except in the case of pinned data.
 */
static void
sdbc_dealloc_dm_shutdown()
{
	_sd_cctl_t *cc_ent;
	ss_centry_info_t *wctl;

	cc_ent = _sd_cctl[0];

	if (!cc_ent)
		return;

	do {
		if (cc_ent->cc_alloc_size_dm) {
			/* HOST or OTHER */

			if (cc_ent->cc_data)
				kmem_free(cc_ent->cc_data,
				    cc_ent->cc_alloc_size_dm);

			cc_ent->cc_alloc_size_dm = 0;

			dynmem_processing_dm.dealloc_ct++;

			DTRACE_PROBE2(sdbc_dealloc_dm_shutdown,
				char *, cc_ent->cc_data,
				int, cc_ent->cc_alloc_size_dm);
		}

		/* release safestore resource, if any. preserve pinned data */
		if (!(CENTRY_DIRTY(cc_ent)) && (wctl = cc_ent->cc_write)) {
			wctl->sc_flag = 0;
			wctl->sc_dirty = 0;

			SSOP_SETCENTRY(sdbc_safestore, wctl);
			SSOP_DEALLOCRESOURCE(sdbc_safestore, wctl->sc_res);
		}
		cc_ent = cc_ent->cc_link_list_dm;
	} while (cc_ent != _sd_cctl[0]);
}

void
_sdbc_dealloc_deconfigure_dm(void)
{
	int one_sec;

	if (sdbc_static_cache) {
		sdbc_dealloc_dm_shutdown();
		return;
	}

	if (sd_dealloc_flag_dm == NO_THREAD_DM)
		return;			/* thread never started */
	one_sec = HZ; /* drv_usectohz(1000000); */

	mutex_enter(&dynmem_processing_dm.thread_dm_lock);
	sd_dealloc_flag_dm = CACHE_SHUTDOWN_DM;
	cv_broadcast(&dynmem_processing_dm.thread_dm_cv);
	mutex_exit(&dynmem_processing_dm.thread_dm_lock);

	while (sd_dealloc_flag_dm != CACHE_THREAD_TERMINATED_DM)
		delay(one_sec);

	sd_dealloc_flag_dm = NO_THREAD_DM;
}

/*
 * This complicated - possibly overly complicated routine works as follows:
 * In general the routine sleeps a specified amount of time then wakes and
 * examines the entire centry list. If an entry is avail. it ages it by one
 * tick else it clears the aging flag completely. It then determines if the
 * centry has aged sufficiently to have its memory deallocated and for it to
 * be placed at the top of the lru.
 *
 * There are two deallocation schemes in place depending on whether the
 * centry is a standalone entry or it is a member of a host/parasite chain.
 *
 * The behavior for a standalone entry is as follows:
 * If the given centry is selected it will age normally however at full
 * aging it will only be placed at the head of the lru. It's memory will
 * not be deallocated until a further aging level has been reached. The
 * entries selected for this behavior are goverend by counting the number
 * of these holdovers in existence on each wakeup and and comparing it
 * to a specified percentage. This comparision is always one cycle out of
 * date and will float in the relative vicinity of the specified number.
 *
 * The behavior for a host/parasite chain is as follows:
 * The chain is examined. If all entries are fully aged the entire chain
 * is removed - ie mem is dealloc. from the host entry and all memory ref.
 * removed from the parasitic entries and each entry requeued on to the lru.
 *
 * There are three delay timeouts and two percentage levels specified. Timeout
 * level 1 is honored between 100% free and pcnt level 1. Timeout level 2 is
 * honored between pcnt level 1 and pcnt level 2, Timeout level 3 is
 * honored between pcnt level 2 and 0% free. In addition there exist an
 * accelerated
 * aging flag which mimics hysterisis behavior. If the available centrys fall
 * between pcnt1 and pcnt2 an 8 bit counter is switched on. The effect is to
 * keep the timer value at timer level 2 for 8 cycles even if the number
 * available cache entries drifts above pcnt1. If it falls below pcnt2 an
 * additional 8 bit counter is switched on. This causes the sleep timer to
 * remain at timer level 3 for at least 8 cycles even if it floats above
 * pcnt2 or even pcnt1. The effect of all this is to accelerate the release
 * of system resources under a heavy load.
 *
 * All of the footwork can be stubbed out by a judicious selection of values
 * for the times, aging counts and pcnts.
 *
 * All of these behavior parameters are adjustable on the fly via the kstat
 * mechanism. In addition there is a thread wakeup msg available through the
 * same mechanism.
 */

static void
_sd_dealloc_dm(void)
{
	int one_sec_tics, tic_delay;
	int sleep_tics_lvl1, sleep_tics_lvl2, sleep_tics_lvl3;
	int transition_lvl1, transition_lvl2;
	int host_cache_aging_ct, meta_cache_aging_ct, hold_cache_aging_ct;
	int max_holds_ct;
	int cache_aging_ct, hold_candidate, last_holds_ct;
	_sd_cctl_t *cc_ent, *next_ccentry, *cur_ent, *nxt_ent;
	ss_centry_info_t *wctl;
	int current_breakout_count, number_cache_entries;
	int dealloc;
	_dm_process_vars_t *ppvars;

	/* clock_t ticker; */
	unsigned long ticker;

	int write_dealloc; /* remove after debugging */

	ppvars = &dynmem_processing_dm;

	/* setup a one sec time var */
	one_sec_tics = HZ; /* drv_usectohz(1000000); */

	ppvars->history = 0;

	cc_ent = _sd_cctl[0];

	number_cache_entries = _sd_net_config.sn_cpages;

	last_holds_ct = 0;

	/*CONSTANTCONDITION*/
	while (1) {
		if (sd_dealloc_flag_dm == CACHE_SHUTDOWN_DM) {
			/* finished.  shutdown - get out */
			sdbc_dealloc_dm_shutdown(); /* free all memory */
			sd_dealloc_flag_dm = CACHE_THREAD_TERMINATED_DM;
			return;
		}

		/* has the world changed */

		/*
		 * get num cctl entries (%) below which different sleep
		 * rates kick in
		 */
		transition_lvl1 =
		    (ppvars->cache_aging_pcnt1*number_cache_entries) / 100;
		transition_lvl2 =
		    (ppvars->cache_aging_pcnt2*number_cache_entries) / 100;

		/* get sleep rates for each level */
		sleep_tics_lvl1 = ppvars->cache_aging_sec1 * one_sec_tics;
		sleep_tics_lvl2 = ppvars->cache_aging_sec2 * one_sec_tics;
		sleep_tics_lvl3 = ppvars->cache_aging_sec3 * one_sec_tics;

		/* get num of cycles for full normal aging */
		host_cache_aging_ct = ppvars->cache_aging_ct1;

		/* get num of cycles for full meta aging */
		meta_cache_aging_ct = ppvars->cache_aging_ct2;

		/* get num of cycles for full extended holdover aging */
		hold_cache_aging_ct = ppvars->cache_aging_ct3;

		/* get maximum holds count in % */
		max_holds_ct = (ppvars->max_holds_pcnt*number_cache_entries)
		    / 100;

		/* apply the delay */
		tic_delay = sleep_tics_lvl1;
		if (sd_dealloc_flag_dm == TIME_DELAY_LVL1)
			tic_delay = sleep_tics_lvl2;
		else
			if (sd_dealloc_flag_dm == TIME_DELAY_LVL2)
				tic_delay = sleep_tics_lvl3;

		(void) drv_getparm(LBOLT, &ticker);
		mutex_enter(&ppvars->thread_dm_lock);
		(void) cv_timedwait(&ppvars->thread_dm_cv,
		    &ppvars->thread_dm_lock, ticker+tic_delay);
		mutex_exit(&ppvars->thread_dm_lock);

		/* check for special directives on wakeup */
		if (ppvars->process_directive &
		    MAX_OUT_ACCEL_HIST_FLAG_DM) {
			ppvars->process_directive &=
			    ~MAX_OUT_ACCEL_HIST_FLAG_DM;
			ppvars->history =
			    (HISTORY_LVL1|HISTORY_LVL2);
		}

		/* Start of deallocation loop */
		current_breakout_count = 0;

		ppvars->nodatas = 0;
		write_dealloc = 0;
		ppvars->deallocs = 0;
		ppvars->candidates = 0;
		ppvars->hosts = 0;
		ppvars->pests = 0;
		ppvars->metas = 0;
		ppvars->holds = 0;
		ppvars->others = 0;
		ppvars->notavail = 0;

		while (sd_dealloc_flag_dm != CACHE_SHUTDOWN_DM &&
		    current_breakout_count < number_cache_entries) {

			next_ccentry = cc_ent->cc_link_list_dm;

			if (_sd_entry_availability_dm(cc_ent, &ppvars->nodatas)
			    == FALSE) {
				ppvars->notavail++;
				goto next_dealloc_entry;
			}

			cache_aging_ct = host_cache_aging_ct;
			hold_candidate = FALSE;
			if (cc_ent->cc_aging_dm & HOST_ENTRY_DM)
				ppvars->hosts++;
			else
				if (cc_ent->cc_aging_dm & PARASITIC_ENTRY_DM)
					ppvars->pests++;
			else
				if (cc_ent->cc_aging_dm & STICKY_METADATA_DM) {
					cache_aging_ct = meta_cache_aging_ct;
					ppvars->metas++;
				} else {
					if (last_holds_ct < max_holds_ct)
						hold_candidate = TRUE;
					ppvars->others++;
				}

			ppvars->candidates++;

			if ((cc_ent->cc_aging_dm & FINAL_AGING_DM) <
			    cache_aging_ct) {
				cc_ent->cc_aging_dm += FIRST_AGING_DM;
				CLEAR_CENTRY_PAGEIO(cc_ent);
				CLEAR_CENTRY_INUSE(cc_ent);
				goto next_dealloc_entry;
			}

			/* bonafide aged entry - examine its chain */
			dealloc = TRUE;
			cur_ent = cc_ent->cc_head_dm;
			while (cur_ent) {
				if (cur_ent == cc_ent)
					cur_ent->cc_aging_dm |= AVAIL_ENTRY_DM;
				else {
					if (_sd_entry_availability_dm(cur_ent,
					    0) == TRUE) {
						cur_ent->cc_aging_dm |=
						    AVAIL_ENTRY_DM;
						if ((cur_ent->cc_aging_dm &
						    FINAL_AGING_DM) <
						    cache_aging_ct)
							dealloc = FALSE;
					} else
						dealloc = FALSE;
				}

				cur_ent = cur_ent->cc_next_dm;
			}
			cur_ent = cc_ent->cc_head_dm;

			/* chain not fully free - free inuse for all entries */
			if (dealloc == FALSE) {
				while (cur_ent) {
					nxt_ent = cur_ent->cc_next_dm;

					if (cur_ent->cc_aging_dm &
					    AVAIL_ENTRY_DM) {
						cur_ent->cc_aging_dm &=
						    ~AVAIL_ENTRY_DM;
						CLEAR_CENTRY_PAGEIO(cur_ent);
						CLEAR_CENTRY_INUSE(cur_ent);
					}
					cur_ent = nxt_ent;
				}
			} else { /* OK - free memory */
				if (hold_candidate == TRUE &&
				    (cur_ent->cc_aging_dm & FINAL_AGING_DM) <
				    hold_cache_aging_ct) {
					ppvars->holds++;

					ASSERT(cur_ent == cc_ent);

					cc_ent->cc_aging_dm += FIRST_AGING_DM;

					cur_ent->cc_aging_dm &= ~AVAIL_ENTRY_DM;

					wctl = cur_ent->cc_write;

					CLEAR_CENTRY_PAGEIO(cur_ent);
					CLEAR_CENTRY_INUSE(cur_ent);

					if (wctl) {
						write_dealloc++;
						wctl->sc_flag = 0;
						wctl->sc_dirty = 0;
						SSOP_SETCENTRY(sdbc_safestore,
									wctl);
						SSOP_DEALLOCRESOURCE(
							sdbc_safestore,
							wctl->sc_res);
					}
					goto next_dealloc_entry;
				} /* if (hold_candidate == TRUE */

				while (cur_ent) {

					DTRACE_PROBE4(_sd_dealloc_dm,
					    _sd_cctl_t *, cur_ent,
					    int, CENTRY_CD(cur_ent),
					    int, CENTRY_BLK(cur_ent),
					    uint_t, cur_ent->cc_aging_dm);

					if ((cur_ent->cc_aging_dm
							& BAD_CHAIN_DM)) {
						(void) _sd_hash_delete(
						    (_sd_hash_hd_t *)cur_ent,
						    _sd_htable);

						nxt_ent = cur_ent->cc_next_dm;
						CLEAR_CENTRY_PAGEIO(cur_ent);
						CLEAR_CENTRY_INUSE(cur_ent);
						cur_ent = nxt_ent;
						continue;
					}

					ppvars->deallocs++;

					if (cur_ent->cc_alloc_size_dm) {
						int qidx;
						_sd_queue_t *q;

						/* HOST or OTHER */

						/* debugging */
						ppvars->dealloc_ct++;
						cur_ent->cc_dealloc_ct_dm++;
						kmem_free(cur_ent->cc_data,
						    cur_ent->cc_alloc_size_dm);

						/*
						 * remove from queue
						 * in preparation for putting
						 * on the 0 queue after
						 * memory is freed
						 */
						if (sdbc_use_dmchain) {

							qidx =
							    cur_ent->cc_cblocks;
							q = &sdbc_dm_queues
									[qidx];

							sdbc_remq_dmchain(q,
								    cur_ent);
						}
					}

					wctl = cur_ent->cc_write;
					cur_ent->cc_write = 0;
					cur_ent->cc_data = 0;
					cur_ent->cc_alloc_size_dm = 0;
					cur_ent->cc_head_dm = NULL;
					cur_ent->cc_aging_dm &=
					    ~(FINAL_AGING_DM | ENTRY_FIELD_DM |
					    CATAGORY_ENTRY_DM | AVAIL_ENTRY_DM |
					    PREFETCH_BUF_I | PREFETCH_BUF_E);

					(void) _sd_hash_delete(
					    (_sd_hash_hd_t *)cur_ent,
					    _sd_htable);
					cur_ent->cc_valid = 0;

					if (sdbc_use_dmchain) {
						_sd_queue_t *q;

						nxt_ent = cur_ent->cc_next_dm;

						cur_ent->cc_next_dm = NULL;

						CLEAR_CENTRY_PAGEIO(cur_ent);
						CLEAR_CENTRY_INUSE(cur_ent);

						q = &sdbc_dm_queues[0];
						sdbc_ins_dmqueue_front(q,
								    cur_ent);
					} else {
						_sd_requeue_head(cur_ent);

						nxt_ent = cur_ent->cc_next_dm;
						cur_ent->cc_next_dm = NULL;

						CLEAR_CENTRY_PAGEIO(cur_ent);
						CLEAR_CENTRY_INUSE(cur_ent);
					}

					cur_ent = nxt_ent;

					if (wctl) {
						write_dealloc++;
						wctl->sc_flag = 0;
						wctl->sc_dirty = 0;
						SSOP_SETCENTRY(sdbc_safestore,
							wctl);
						SSOP_DEALLOCRESOURCE(
							sdbc_safestore,
							wctl->sc_res);
					}
				} /* while (cur_ent) */
			} /* else OK - free memory */
next_dealloc_entry:
		current_breakout_count++;

		cc_ent = next_ccentry;
		}  /* while (entries) */

		if (ppvars->monitor_dynmem_process & RPT_DEALLOC_STATS1_DM) {
			cmn_err(CE_NOTE,
			    "notavl=%x, nodat=%x, cand=%x, hosts=%x,"
			    " pests=%x, metas=%x, holds=%x, others=%x,"
			    " deallo=%x",
			    ppvars->notavail, ppvars->nodatas,
			    ppvars->candidates, ppvars->hosts, ppvars->pests,
			    ppvars->metas, ppvars->holds, ppvars->others,
			    ppvars->deallocs);
		}

		if (ppvars->monitor_dynmem_process & RPT_DEALLOC_STATS2_DM) {
			cmn_err(CE_NOTE,
			    "hist=%x, gross a/d=%x %x", ppvars->history,
			    ppvars->alloc_ct, ppvars->dealloc_ct);
		}

		if (sd_dealloc_flag_dm == CACHE_SHUTDOWN_DM)
			continue;

		last_holds_ct = ppvars->holds;

		/* set the history flag which will govern the sleep rate */
		if (ppvars->nodatas > transition_lvl1) {
			/* upper - lots of virgin cctls */
			if (ppvars->history)
				ppvars->history >>= 1;
		} else {
			if (ppvars->nodatas > transition_lvl2) {
				/* middle - not so many virgin cctls */
				if (ppvars->history & (HISTORY_LVL1-1))
					ppvars->history >>= 1;
				else
					ppvars->history = HISTORY_LVL1;

			} else {
				/*
				 * appear to be running low - accelerate the
				 * aging to free more
				 */
				if (ppvars->history & HISTORY_LVL2)
					ppvars->history >>= 1;
				else
					ppvars->history =
					    (HISTORY_LVL1|HISTORY_LVL2);
			}
		}

		sd_dealloc_flag_dm = TIME_DELAY_LVL0;
		if (ppvars->history & HISTORY_LVL2)
			sd_dealloc_flag_dm = TIME_DELAY_LVL2;
		else
			if (ppvars->history & HISTORY_LVL1)
				sd_dealloc_flag_dm = TIME_DELAY_LVL1;

	} /* while (TRUE) */
}

int
_sd_entry_availability_dm(_sd_cctl_t *cc_ent, int *nodata)
{
	/*
	 * if using dmchaining return immediately and do not attempt
	 * to acquire the cc_ent if there is no memory associated with
	 * this cc_ent.
	 * this avoids conflicts for centrys on the 0 queue.
	 * see sdbc_get_dmchain()
	 */

	if ((sdbc_use_dmchain) && (cc_ent->cc_data == 0)) {

		if (nodata)
			(*nodata)++;

		DTRACE_PROBE(sdbc_availability_dm_end1);
		return (FALSE);
	}

	if ((SET_CENTRY_INUSE(cc_ent))) {

		DTRACE_PROBE(sdbc_availability_dm_end2);

		return (FALSE);
	}


	if ((SET_CENTRY_PAGEIO(cc_ent))) {

		CLEAR_CENTRY_INUSE(cc_ent);

		DTRACE_PROBE(sdbc_availability_dm_end3);

		return (FALSE);
	}

	/*
	 * we allow the QHEAD flag as it does not affect the availabilty
	 * of memory for aging
	 */
	if ((CENTRY_DIRTY(cc_ent)) || (CENTRY_IO_INPROGRESS(cc_ent)) ||
			(cc_ent->cc_flag & ~(CC_QHEAD)) ||
			cc_ent->cc_dirty_next || cc_ent->cc_dirty_link ||
			cc_ent->cc_data == 0) {

		cc_ent->cc_aging_dm &= ~FINAL_AGING_DM;
		if (nodata)
			if (cc_ent->cc_data == 0) {
				(*nodata)++;
		}

		CLEAR_CENTRY_PAGEIO(cc_ent);
		CLEAR_CENTRY_INUSE(cc_ent);

		DTRACE_PROBE(sdbc_availability_dm_end4);

		return (FALSE);
	}

	return (TRUE);
}

/*
 * function below to prohibit code movement by compiler
 * and avoid using spinlocks for syncronization
 */
static void
_sd_cc_iostatus_initiate(_sd_cctl_t *cc_ent)
{
	cc_ent->cc_iostatus = _SD_IO_INITIATE;
	sd_serialize();
}

/*
 * Yet another switch!
 * alloc mem and coalesce if at least this number of frags
 */
static int sdbc_coalesce_backend = 1;

/*
 * optimization for _sd_async_flclist()
 * called only if not doing pageio and sdbc_coalesce_backend > 0
 *
 * returns with pagio bit set in the centrys in list
 */
static unsigned char *
sdbc_alloc_io_mem(_sd_cctl_t *cc_ent, int first_dirty, int last_dirty)
{
	unsigned char *prev_addr = NULL;
	_sd_cctl_t *cc_ent_orig = cc_ent;
	int fba_len;
	int total_len_bytes = 0;
	unsigned char *start_addr = NULL; /* function return value */
	unsigned char *next_addr;
	int num_frags = 0;

	if (first_dirty && (!_SD_BMAP_ISFULL(first_dirty))) {
		WAIT_CENTRY_PAGEIO(cc_ent, sdbc_flush_pageio);

		fba_len = SDBC_LOOKUP_LEN(first_dirty);
		total_len_bytes += FBA_SIZE(fba_len);

		prev_addr = cc_ent->cc_data;
		cc_ent = cc_ent->cc_dirty_next;
	}

	while (cc_ent) {

		WAIT_CENTRY_PAGEIO(cc_ent, sdbc_flush_pageio);
		/* check for contiguity */
		if (prev_addr &&
			!((prev_addr + CACHE_BLOCK_SIZE) == cc_ent->cc_data))
			++num_frags;

		/* compute length */
		if (FULLY_DIRTY(cc_ent)) {
			total_len_bytes += CACHE_BLOCK_SIZE;
		} else {
			fba_len = SDBC_LOOKUP_LEN(last_dirty);
			total_len_bytes += FBA_SIZE(fba_len);
		}

		prev_addr = cc_ent->cc_data;
		cc_ent = cc_ent->cc_dirty_next;
	}

	if (num_frags >= sdbc_coalesce_backend) {
		/*
		 * TODO - determine metric for deciding
		 * whether to coalesce memory or do separate i/o's
		 */

		DTRACE_PROBE(sdbc_io_mem_kmem_start);

		if (start_addr = kmem_alloc(total_len_bytes, KM_NOSLEEP)) {
			int sblk, offset;

			cc_ent = cc_ent_orig;

			cc_ent->cc_anon_addr.sa_virt = start_addr;
			cc_ent->cc_anon_len = total_len_bytes;

			next_addr = start_addr;

			DTRACE_PROBE2(sdbc_io_mem_bcopy_start,
					int, num_frags,
					int, total_len_bytes);

			/* copy the first dirty piece */
			if (first_dirty && (!_SD_BMAP_ISFULL(first_dirty))) {

				fba_len = SDBC_LOOKUP_LEN(first_dirty);
				sblk = SDBC_LOOKUP_STPOS(first_dirty);
				offset = FBA_SIZE(sblk);

				bcopy(cc_ent->cc_data + offset, next_addr,
							FBA_SIZE(fba_len));
				cc_ent = cc_ent->cc_dirty_next;
				next_addr += FBA_SIZE(fba_len);
			}

			/* copy the rest of data */
			while (cc_ent) {
				if (FULLY_DIRTY(cc_ent)) {
					bcopy(cc_ent->cc_data, next_addr,
							CACHE_BLOCK_SIZE);
					next_addr += CACHE_BLOCK_SIZE;
				} else {
					fba_len = SDBC_LOOKUP_LEN(last_dirty);
					bcopy(cc_ent->cc_data, next_addr,
							FBA_SIZE(fba_len));
					next_addr += FBA_SIZE(fba_len);
				}

				cc_ent = cc_ent->cc_dirty_next;
			}

			DTRACE_PROBE(sdbc_io_mem_bcopy_end);
		}

		DTRACE_PROBE(sdbc_io_mem_kmem_end);
	}

	return (start_addr);
}

void
_sd_async_flclist(_sd_cctl_t *cclist, dev_t rdev)
{
	int flushed, i, cd;
	uint_t first_dirty, last_dirty;
	_sd_cctl_t *cc_ent, *cc_prev = NULL;
	struct buf *bp;
	int dblk, fba_len;
	int len;
	int toflush;
	int coalesce; /* convenience boolean */
	unsigned char *anon_mem = NULL;
	extern int sdbc_do_page;


	SDTRACE(ST_ENTER|SDF_FLCLIST, CENTRY_CD(cclist),
		0, BLK_TO_FBA_NUM(CENTRY_BLK(cclist)), 0, 0);

	coalesce = (!sdbc_do_page && sdbc_coalesce_backend);

	cc_ent = cclist;
	_sd_cc_iostatus_initiate(cc_ent);
	first_dirty = CENTRY_DIRTY(cc_ent);
	if (SDBC_IS_FRAGMENTED(first_dirty)) {
		cclist = cc_ent->cc_dirty_next;
		cc_ent->cc_dirty_next = NULL;
		_sd_async_flcent(cc_ent, rdev);
		cc_ent = cclist;
		first_dirty = 0;
	}

	toflush = 0;
	while (cc_ent->cc_dirty_next) {
		if (cc_ent->cc_iocount)
			SDALERT(SDF_FLCLIST, CENTRY_CD(cc_ent), 0,
				BLK_TO_FBA_NUM(CENTRY_BLK(cc_ent)),
				cc_ent->cc_iocount, 0);
		cc_prev = cc_ent;
		cc_ent = cc_ent->cc_dirty_next;
		toflush++;
	}
	_sd_cc_iostatus_initiate(cc_ent);
	last_dirty = CENTRY_DIRTY(cc_ent);
	if (SDBC_IS_FRAGMENTED(last_dirty)) {
		if (cc_prev)
			cc_prev->cc_dirty_next = NULL;
		_sd_async_flcent(cc_ent, rdev);
		last_dirty = 0;
	}
	else
		toflush++;

	if (toflush == 0)
		return;


	dblk = BLK_TO_FBA_NUM(CENTRY_BLK(cclist));
	if (first_dirty && (!_SD_BMAP_ISFULL(first_dirty)))
		dblk += SDBC_LOOKUP_STPOS(first_dirty);

	cd = CENTRY_CD(cclist);
	bp = sd_alloc_iob(rdev, dblk, toflush, B_WRITE);
	cc_ent = cclist;

	if (coalesce &&
		(anon_mem = sdbc_alloc_io_mem(cc_ent, first_dirty,
							last_dirty)))
		sd_add_fba(bp, &cc_ent->cc_anon_addr, 0,
				FBA_NUM(cc_ent->cc_anon_len));

	if (first_dirty && (!_SD_BMAP_ISFULL(first_dirty))) {
		cc_ent->cc_iocount = flushed = 1;

		/* pageio bit already set in sdbc_alloc_io_mem() above */
		if (!coalesce)
			WAIT_CENTRY_PAGEIO(cc_ent, sdbc_flush_pageio);

		fba_len = SDBC_LOOKUP_LEN(first_dirty);

		/* build buffer only if it was not done above */
		if (!anon_mem) {
			i = SDBC_LOOKUP_STPOS(first_dirty);
			sd_add_fba(bp, &cc_ent->cc_addr, i, fba_len);
			DATA_LOG(SDF_FLSHLIST, cc_ent, i, fba_len);

			DTRACE_PROBE4(_sd_async_flclist_data1,
			    int,
				BLK_TO_FBA_NUM(CENTRY_BLK(cc_ent)) + i,
			    int, fba_len,
			    char *,
				*(int64_t *)(cc_ent->cc_data + FBA_SIZE(i)),
			    char *,
				*(int64_t *)(cc_ent->cc_data +
				    FBA_SIZE(i + fba_len) - 8));
		}

		len = FBA_SIZE(fba_len);
		cc_ent = cc_ent->cc_dirty_next;
	} else {
		len = 0;
		flushed = 0;
	}
	while (cc_ent) {
		_sd_cc_iostatus_initiate(cc_ent);

		/* pageio bit already set in sdbc_alloc_io_mem() above */
		if (!coalesce)
			WAIT_CENTRY_PAGEIO(cc_ent, sdbc_flush_pageio);

		if (FULLY_DIRTY(cc_ent)) {
			flushed++;
			cc_ent->cc_iocount = 1;

			/* build buffer only if it was not done above */
			if (!anon_mem) {
				sd_add_fba(bp, &cc_ent->cc_addr, 0, BLK_FBAS);
				DATA_LOG(SDF_FLSHLIST, cc_ent, 0, BLK_FBAS);

				DTRACE_PROBE4(_sd_async_flclist_data2,
				    int,
					BLK_TO_FBA_NUM(CENTRY_BLK(cc_ent)),
				    int, BLK_FBAS,
				    char *,
					*(int64_t *)(cc_ent->cc_data),
				    char *,
					*(int64_t *)(cc_ent->cc_data +
					    FBA_SIZE(BLK_FBAS) - 8));
			}

			len += CACHE_BLOCK_SIZE;
		} else {
#if defined(_SD_DEBUG)
			/*
			 * consistency check.
			 */
			if (!last_dirty || cc_ent->cc_dirty_next ||
			    SDBC_IS_FRAGMENTED(last_dirty)) {
				SDALERT(SDF_FLCLIST, cd, 0,
				    BLK_TO_FBA_NUM(CENTRY_BLK(cc_ent)),
				    cc_ent->cc_dirty_next, last_dirty);
				cmn_err(CE_WARN,
				    "_sd_err: flclist: last_dirty %x next %x",
				    last_dirty, cc_ent->cc_dirty_next);
			}
#endif
			flushed++;
			cc_ent->cc_iocount = 1;

			fba_len = SDBC_LOOKUP_LEN(last_dirty);

			/* build buffer only if it was not done above */
			if (!anon_mem) {
				sd_add_fba(bp, &cc_ent->cc_addr, 0, fba_len);
				DATA_LOG(SDF_FLSHLIST, cc_ent, 0, fba_len);

				DTRACE_PROBE4(_sd_async_flclist_data3,
				    int,
					BLK_TO_FBA_NUM(CENTRY_BLK(cc_ent)),
				    int, fba_len,
				    char *,
					*(int64_t *)(cc_ent->cc_data),
				    char *,
					*(int64_t *)(cc_ent->cc_data +
					    FBA_SIZE(fba_len) - 8));
			}

			len += FBA_SIZE(fba_len);
		}
		cc_ent = cc_ent->cc_dirty_next;
	}

#ifdef DEBUG
	if (anon_mem)
		ASSERT(len == cclist->cc_anon_len);
#endif

	/* SDTRACE(ST_INFO|SDF_FLCLIST, cd, FBA_NUM(len), dblk, flushed, bp); */
	(void) sd_start_io(bp, _sd_cache_files[cd].cd_strategy,
	    _sd_flclist_ea, cclist);

	DISK_FBA_WRITE(cd, FBA_NUM(len));
	/* increment number of bytes destaged to disk */
	WRITE_DESTAGED(cd, FBA_NUM(len));

	_sd_enqueue_io_pending(cd, cclist);

	SDTRACE(ST_EXIT|SDF_FLCLIST, cd, FBA_NUM(len), dblk, flushed, 0);
}


void
_sd_enqueue_io_pending(int cd, _sd_cctl_t *cclist)
{
	_sd_cd_info_t *cdi;

	cdi = &(_sd_cache_files[cd]);
	if (cdi->cd_io_head == NULL)
		cdi->cd_io_head = cdi->cd_io_tail = cclist;
	else {
		cdi->cd_io_tail->cc_dirty_link = cclist;
		cdi->cd_io_tail = cclist;
	}
}



void
_sd_async_flcent(_sd_cctl_t *cc_ent, dev_t rdev)
{
	int dblk, len, sblk;
	int dirty;
	struct buf *bp;
	int cd;

	cd = CENTRY_CD(cc_ent);

	SDTRACE(ST_ENTER|SDF_FLCENT, cd, 0,
		BLK_TO_FBA_NUM(CENTRY_BLK(cc_ent)), 0, 0);
#if defined(_SD_DEBUG_PATTERN)
	check_write_consistency(cc_ent);
#endif
	if (cc_ent->cc_iocount)
		SDALERT(SDF_FLCENT, cd, 0,
			BLK_TO_FBA_NUM(CENTRY_BLK(cc_ent)),
			cc_ent->cc_iocount, 0);
	_sd_cc_iostatus_initiate(cc_ent);
	WAIT_CENTRY_PAGEIO(cc_ent, sdbc_flush_pageio);

	dirty = CENTRY_DIRTY(cc_ent);

	if (_SD_BMAP_ISFULL(dirty)) {
		cc_ent->cc_iocount = 1;
		dblk = BLK_TO_FBA_NUM(CENTRY_BLK(cc_ent));
		bp = sd_alloc_iob(rdev, dblk, 1, B_WRITE);
		sd_add_fba(bp, &cc_ent->cc_addr, 0, BLK_FBAS);
		DATA_LOG(SDF_FLSHENT, cc_ent, 0, BLK_FBAS);

		DTRACE_PROBE4(_sd_async_flcent_data1,
			int, BLK_TO_FBA_NUM(CENTRY_BLK(cc_ent)),
			int, BLK_FBAS,
			char *, *(int64_t *)(cc_ent->cc_data),
			char *, *(int64_t *)(cc_ent->cc_data +
				FBA_SIZE(BLK_FBAS) - 8));
		cc_ent->cc_iocount = 1;
		(void) sd_start_io(bp, _sd_cache_files[cd].cd_strategy,
		    _sd_flcent_ea, cc_ent);
		DISK_FBA_WRITE(cd, BLK_FBAS);
		/* increment number of bytes destaged to disk */
		WRITE_DESTAGED(cd, BLK_FBAS);
	} else {
		cc_ent->cc_iocount = SDBC_LOOKUP_DTCOUNT(dirty);

		while (dirty) {
			sblk = SDBC_LOOKUP_STPOS(dirty);
			len = SDBC_LOOKUP_LEN(dirty);
			SDBC_LOOKUP_MODIFY(dirty);

			dblk = BLK_TO_FBA_NUM(CENTRY_BLK(cc_ent)) + sblk;
			bp = sd_alloc_iob(rdev, dblk, 1, B_WRITE);
			sd_add_fba(bp, &cc_ent->cc_addr, sblk, len);
			DATA_LOG(SDF_FLSHENT, cc_ent, sblk, len);

			DTRACE_PROBE4(_sd_async_flcent_data2,
				int,
				    BLK_TO_FBA_NUM(CENTRY_BLK(cc_ent)) + sblk,
				int, len,
				char *,
				*(int64_t *)(cc_ent->cc_data +
					FBA_SIZE(sblk)),
				char *, *(int64_t *)
				    (cc_ent->cc_data +
					FBA_SIZE(sblk + len) - 8));

			/* SDTRACE(ST_INFO|SDF_FLCENT, cd, len, dblk, 0, bp); */

			(void) sd_start_io(bp, _sd_cache_files[cd].cd_strategy,
			    _sd_flcent_ea, cc_ent);
			DISK_FBA_WRITE(cd, len);
			/* increment number of bytes destaged to disk */
			WRITE_DESTAGED(cd, len);
		}
	}
	_sd_enqueue_io_pending(cd, cc_ent);

	SDTRACE(ST_EXIT|SDF_FLCENT, cd, 0, dblk, 0, 0);
}

static void
_sd_process_pending(int cd)
{
	_sd_cd_info_t *cdi;
	_sd_cctl_t *cc_ent, *cc_next;
	int dirty_enq;
	ss_centry_info_t *wctl;
	_sd_cctl_t *dirty_hd, **dirty_nxt;
	int sts, processed = 0;

	cdi = &(_sd_cache_files[cd]);

	SDTRACE(ST_ENTER|SDF_FLDONE, cd, 0,
		SDT_INV_BL, cdi->cd_info->sh_numio, 0);
process_loop:
	if (cdi->cd_io_head == NULL) {
		if (processed) {
			mutex_enter(&cdi->cd_lock);
			cdi->cd_info->sh_numio -= processed;
			mutex_exit(&cdi->cd_lock);
		}
		SDTRACE(ST_EXIT|SDF_FLDONE, cd, 0,
			SDT_INV_BL, cdi->cd_info->sh_numio, processed);
		return;
	}
	cc_ent = cdi->cd_io_head;
	if ((sts = cc_ent->cc_iostatus) == _SD_IO_INITIATE) {
		if (processed)  {
			mutex_enter(&cdi->cd_lock);
			cdi->cd_info->sh_numio -= processed;
			mutex_exit(&cdi->cd_lock);
		}
		SDTRACE(ST_EXIT|SDF_FLDONE, cd, 0,
			SDT_INV_BL, cdi->cd_info->sh_numio, processed);
		return;
	}
	LINTUSED(sts);
#if defined(_SD_DEBUG)
	if ((sts != _SD_IO_DONE) && (sts != _SD_IO_FAILED))
		SDALERT(SDF_FLDONE, cd, 0,
			BLK_TO_FBA_NUM(CENTRY_BLK(cc_ent)), 0, sts);
#endif

	if ((cdi->cd_io_head = cc_ent->cc_dirty_link) == NULL)
		cdi->cd_io_tail = NULL;

	cc_ent->cc_dirty_link = NULL;
	if (cc_ent->cc_iostatus == _SD_IO_FAILED &&
	    _sd_process_failure(cc_ent))
		goto process_loop;

	dirty_enq = 0;
	dirty_nxt = &(dirty_hd);

	DTRACE_PROBE1(_sd_process_pending_cd,
			int, cd);

	for (; cc_ent; cc_ent = cc_next) {

		DTRACE_PROBE1(_sd_process_pending_cc_ent,
				_sd_cctl_t *, cc_ent);
		processed++;
		cc_next = cc_ent->cc_dirty_next;
		cc_ent->cc_dirty_next = NULL;

		if (CENTRY_PINNED(cc_ent))
			_sd_process_reflush(cc_ent);

		/*
		 * Optimize for common case where block not inuse
		 * Grabbing cc_inuse is faster than cc_lock.
		 */
		if (SET_CENTRY_INUSE(cc_ent))
			goto must_lock;

		cc_ent->cc_iostatus = _SD_IO_NONE;
		if (CENTRY_DIRTY_PENDING(cc_ent)) {
			cc_ent->cc_flag &= ~CC_PEND_DIRTY;

			CLEAR_CENTRY_INUSE(cc_ent);
			if (dirty_enq)
				dirty_nxt = &((*dirty_nxt)->cc_dirty_link);
			(*dirty_nxt) = cc_ent;
			dirty_enq++;
			continue;
		}
		cc_ent->cc_dirty = 0;
		wctl = cc_ent->cc_write;
		cc_ent->cc_write = NULL;
		cc_ent->cc_flag &= ~(CC_PINNABLE);


		wctl->sc_dirty = 0;
		SSOP_SETCENTRY(sdbc_safestore, wctl);
		SSOP_DEALLOCRESOURCE(sdbc_safestore, wctl->sc_res);

		/*
		 * if this was a QHEAD cache block, then
		 * _sd_centry_release() did not requeue it as
		 * it was dirty.  Requeue it now.
		 */

		if (CENTRY_QHEAD(cc_ent))
			if (sdbc_use_dmchain) {

				/* attempt to que head */
				if (cc_ent->cc_alloc_size_dm) {

					sdbc_requeue_head_dm_try(cc_ent);
				}
			} else
				_sd_requeue_head(cc_ent);

		CLEAR_CENTRY_INUSE(cc_ent);
		continue;

		/*
		 * Block is inuse, must take cc_lock
		 * if DIRTY_PENDING, must re-issue
		 */
	must_lock:
		/* was FAST */
		mutex_enter(&cc_ent->cc_lock);
		cc_ent->cc_iostatus = _SD_IO_NONE;
		if (CENTRY_DIRTY_PENDING(cc_ent)) {
			cc_ent->cc_flag &= ~CC_PEND_DIRTY;
			/* was FAST */
			mutex_exit(&cc_ent->cc_lock);
			if (dirty_enq)
				dirty_nxt = &((*dirty_nxt)->cc_dirty_link);
			(*dirty_nxt) = cc_ent;
			dirty_enq++;
			continue;
		}
		/*
		 * clear dirty bits, if block no longer inuse release cc_write
		 */
		cc_ent->cc_dirty = 0;
		if (SET_CENTRY_INUSE(cc_ent) == 0) {

			wctl = cc_ent->cc_write;
			cc_ent->cc_write = NULL;
			cc_ent->cc_flag &= ~(CC_PINNABLE);
			/* was FAST */
			mutex_exit(&cc_ent->cc_lock);


			wctl->sc_dirty = 0;
			SSOP_SETCENTRY(sdbc_safestore, wctl);
			SSOP_DEALLOCRESOURCE(sdbc_safestore, wctl->sc_res);

			/*
			 * if this was a QHEAD cache block, then
			 * _sd_centry_release() did not requeue it as
			 * it was dirty.  Requeue it now.
			 */

			if (CENTRY_QHEAD(cc_ent))
				if (sdbc_use_dmchain) {

					/* attempt to que head */
					if (cc_ent->cc_alloc_size_dm) {
					    sdbc_requeue_head_dm_try(cc_ent);
					}
				} else
					_sd_requeue_head(cc_ent);
			CLEAR_CENTRY_INUSE(cc_ent);
		} else {
			/* was FAST */
			mutex_exit(&cc_ent->cc_lock);
		}
	}

	if (dirty_enq)
		_sd_enqueue_dirty_chain(cd, dirty_hd, (*dirty_nxt), dirty_enq);

	goto process_loop;
}


static void
_sd_flcent_ea(blind_t xcc_ent, nsc_off_t fba_pos, nsc_size_t fba_len, int error)
{
	_sd_cctl_t *cc_ent = (_sd_cctl_t *)xcc_ent;
	int cd;
	nsc_off_t dblk;

	_sd_cd_info_t *cdi;

	cd = CENTRY_CD(cc_ent);
	dblk = BLK_TO_FBA_NUM(CENTRY_BLK(cc_ent));
	cdi = &(_sd_cache_files[cd]);

	SDTRACE(ST_ENTER|SDF_FLCENT_EA, cd, 0, dblk, 2, (unsigned long)cc_ent);

	if (error) {
		if (cdi->cd_info->sh_failed == 0) {
			cdi->cd_info->sh_failed = 1;
			cmn_err(CE_WARN, "sdbc(_sd_flcent_ea) "
			    "Disk write failed cd %d (%s): err %d",
			    cd, cdi->cd_info->sh_filename, error);
		}
	}

	/* was FAST */
	mutex_enter(&cc_ent->cc_lock);
	if (--(cc_ent->cc_iocount) != 0) {
		/* more io's to complete before the cc_ent is done. */

		if (cc_ent->cc_iocount < 0) {
			/* was FAST */
			mutex_exit(&cc_ent->cc_lock);
			SDALERT(SDF_FLCENT_EA, cd, 0,
				dblk, cc_ent->cc_iocount, 0);
		} else {
			/* was FAST */
			mutex_exit(&cc_ent->cc_lock);
		}
		SDTRACE(ST_EXIT|SDF_FLCENT_EA, cd, 0, dblk, 2,
		    (unsigned long)cc_ent);

		DTRACE_PROBE(_sd_flcent_ea_end);
		return;
	}
	/* was FAST */
	mutex_exit(&cc_ent->cc_lock);

	DATA_LOG(SDF_FLEA, cc_ent, BLK_FBA_OFF(fba_pos), fba_len);

	DTRACE_PROBE4(_sd_flcent_ea_data,
	    uint64_t, ((uint64_t)
		BLK_TO_FBA_NUM(CENTRY_BLK(cc_ent) + BLK_FBA_OFF(fba_pos))),
	    uint64_t, (uint64_t)fba_len,
	    char *, *(int64_t *)
		(cc_ent->cc_data + FBA_SIZE(BLK_FBA_OFF(fba_pos))),
	    char *, *(int64_t *)(cc_ent->cc_data +
		FBA_SIZE(BLK_FBA_OFF(fba_pos) + fba_len) - 8));

	/*
	 * All io's are done for this cc_ent.
	 * Clear the pagelist io flag.
	 */
	CLEAR_CENTRY_PAGEIO(cc_ent);

	if (error)
		cc_ent->cc_iostatus = _SD_IO_FAILED;
	else
		cc_ent->cc_iostatus = _SD_IO_DONE;

	SDTRACE(ST_EXIT|SDF_FLCENT_EA, cd, 0, dblk, 2, (unsigned long)cc_ent);

}



static void
_sd_flclist_ea(blind_t xcc_ent, nsc_off_t fba_pos, nsc_size_t fba_len,
    int error)
{
	_sd_cctl_t *cc_ent = (_sd_cctl_t *)xcc_ent;
	_sd_cctl_t *first_cc = cc_ent;
	_sd_cd_info_t *cdi;
	int cd;
	nsc_off_t dblk;

	cd = CENTRY_CD(cc_ent);
	dblk = BLK_TO_FBA_NUM(CENTRY_BLK(cc_ent));
	cdi = &(_sd_cache_files[cd]);

	SDTRACE(ST_ENTER|SDF_FLCLIST_EA, cd, 0, dblk, 1, (unsigned long)cc_ent);

	if (error) {
		if (cdi->cd_info->sh_failed == 0) {
			cdi->cd_info->sh_failed = 1;
			cmn_err(CE_WARN, " sdbc(_sd_flclist_ea) "
			    "Disk write failed cd %d (%s): err %d",
			    cd, cdi->cd_info->sh_filename, error);
		}
	}
	/*
	 * Important: skip the first cc_ent in the list. Marking this will
	 * make the writer think the io is done,  though the rest of the
	 * chain have not been processed here. so mark the first cc_ent
	 * last. Optimization, so as not to use locks
	 */

	cc_ent = cc_ent->cc_dirty_next;
	while (cc_ent) {
		DTRACE_PROBE2(_sd_flclist_ea,
				_sd_cctl_t *, cc_ent,
				int, CENTRY_CD(cc_ent));

		if (cc_ent->cc_iocount != 1)
			SDALERT(SDF_FLCLIST_EA, cd, 0,
				BLK_TO_FBA_NUM(CENTRY_BLK(cc_ent)),
				cc_ent->cc_iocount, 0);
		cc_ent->cc_iocount = 0;

		/*
		 * Clear the pagelist io flag.
		 */
		CLEAR_CENTRY_PAGEIO(cc_ent);

		if (error)
			cc_ent->cc_iostatus = _SD_IO_FAILED;
		else
			cc_ent->cc_iostatus = _SD_IO_DONE;
		if (cc_ent->cc_dirty_next) {
			DATA_LOG(SDF_FLSTEA, cc_ent, 0, BLK_FBAS);

			DTRACE_PROBE4(_sd_flclist_ea_data1,
			    uint64_t,
				BLK_TO_FBA_NUM(CENTRY_BLK(cc_ent)),
			    int, BLK_FBAS,
			    char *, *(int64_t *)(cc_ent->cc_data),
			    char *, *(int64_t *)(cc_ent->cc_data +
				FBA_SIZE(BLK_FBAS) - 8));
		} else {
			DATA_LOG(SDF_FLSTEA, cc_ent, 0,
				BLK_FBA_OFF(fba_pos + fba_len));

			DTRACE_PROBE4(_sd_flclist_ea_data2,
			    uint64_t,
				(uint64_t)BLK_TO_FBA_NUM(CENTRY_BLK(cc_ent)),
			    uint64_t,
				(uint64_t)BLK_FBA_OFF(fba_pos + fba_len),
			    char *, *(int64_t *)(cc_ent->cc_data),
			    char *, *(int64_t *)(cc_ent->cc_data +
				FBA_SIZE(BLK_FBA_OFF(fba_pos + fba_len)) - 8));
		}

		cc_ent = cc_ent->cc_dirty_next;
	}

	/*
	 * Now process the first cc_ent in the list.
	 */
	cc_ent = first_cc;
	DATA_LOG(SDF_FLSTEA, cc_ent, BLK_FBA_OFF(fba_pos),
		BLK_FBAS - BLK_FBA_OFF(fba_pos));

	DTRACE_PROBE4(_sd_flclist_ea_data3,
		uint64_t, (uint64_t)fba_pos,
		int, BLK_FBAS - BLK_FBA_OFF(fba_pos),
		char *, *(int64_t *)(cc_ent->cc_data +
			FBA_SIZE(BLK_FBA_OFF(fba_pos))),
		char *, *(int64_t *)(cc_ent->cc_data +
			FBA_SIZE(BLK_FBA_OFF(fba_pos) +
			    BLK_FBAS - BLK_FBA_OFF(fba_pos)) - 8));

	cc_ent->cc_iocount = 0;

	if (cc_ent->cc_anon_addr.sa_virt) {
		kmem_free(cc_ent->cc_anon_addr.sa_virt, cc_ent->cc_anon_len);
		cc_ent->cc_anon_addr.sa_virt = NULL;
		cc_ent->cc_anon_len = 0;
	}

	/*
	 * Clear the pagelist io flag.
	 */
	CLEAR_CENTRY_PAGEIO(cc_ent);

	if (error)
		cc_ent->cc_iostatus = _SD_IO_FAILED;
	else
		cc_ent->cc_iostatus = _SD_IO_DONE;

	SDTRACE(ST_EXIT|SDF_FLCLIST_EA, cd, 0, dblk, 1, (unsigned long)cc_ent);
}


static void
_sd_mark_failed(_sd_cctl_t *cclist)
{
	_sd_cctl_t *cc_ent;
	int cd;

	cd = CENTRY_CD(cclist);
	cc_ent = cclist;
	while (cc_ent) {
		cc_ent->cc_iostatus = _SD_IO_FAILED;
		cc_ent = cc_ent->cc_dirty_next;
	}
	_sd_enqueue_io_pending(cd, cclist);
}



/*
 * Fail single chain of cache blocks, updating numfail/numio counts.
 * For dual-copy, log & clear PINNED, fall thru to regular processing.
 */
int
_sd_process_failure(_sd_cctl_t *cc_ent)
{
	int cd, num;
	_sd_cctl_t *cc_chain;
	_sd_cd_info_t *cdi;

	cd = CENTRY_CD(cc_ent);
	cdi = &(_sd_cache_files[cd]);

	cc_chain = cc_ent;

	if (!cdi->cd_global->sv_pinned) {
		cdi->cd_global->sv_pinned = _SD_SELF_HOST;
		SSOP_SETVOL(sdbc_safestore, cdi->cd_global);
	}

	for (num = 0; cc_ent; cc_ent = cc_ent->cc_dirty_next) {
		num++;
		/* was FAST */
		mutex_enter(&cc_ent->cc_lock);
		cc_ent->cc_flag |= (CC_PEND_DIRTY |
		    (CENTRY_PINNABLE(cc_ent) ? CC_PINNED : 0));
		if (cc_ent->cc_write) {
			cc_ent->cc_write->sc_flag = cc_ent->cc_flag;
			SSOP_SETCENTRY(sdbc_safestore, cc_ent->cc_write);
		}
		mutex_exit(&cc_ent->cc_lock);
		if (CENTRY_PINNED(cc_ent))
			nsc_pinned_data(cdi->cd_iodev,
			    BLK_TO_FBA_NUM(CENTRY_BLK(cc_ent)), BLK_FBAS);
	}

	/*
	 *  In normal processing we wouldn't need a lock here as all i/o
	 *  is single threaded by cd. However during failover blocks can
	 *  be failing from real i/o and as soon as the disk is marked bad
	 *  the failover code which is furiously cloning safe-store into
	 *  more blocks will short circuit to here (see _sd_ft_clone)
	 *  and two threads can be executing in here simultaneously.
	 */
	mutex_enter(&cdi->cd_lock);
	cc_chain->cc_dirty_link = cdi->cd_fail_head;
	cdi->cd_fail_head = cc_chain;
	cdi->cd_info->sh_numfail += num;
	cdi->cd_info->sh_numio   -= num;
	mutex_exit(&cdi->cd_lock);
	return (1);		/* blocks are failed */
}


static void
_sd_process_reflush(_sd_cctl_t *cc_ent)
{
	int cd;

	if (CENTRY_PINNABLE(cc_ent)) {
		cd = CENTRY_CD(cc_ent);
		nsc_unpinned_data(_sd_cache_files[cd].cd_iodev,
			BLK_TO_FBA_NUM(CENTRY_BLK(cc_ent)), BLK_FBAS);
	}

	/* was FAST */
	mutex_enter(&cc_ent->cc_lock);
	cc_ent->cc_flag &= ~CC_PINNED;
	/* was FAST */
	mutex_exit(&cc_ent->cc_lock);
}



/*
 * cd_write_thread -- flush dirty buffers.
 *
 * ARGUMENTS:
 *
 *  cd - cache descriptor
 *
 * USAGE:
 *  called by cd's writer thread, returns when no more entries
 *
 * NOTE: if sdbc is being shutdown (for powerfail) then we will
 * process pending i/o's but issue no more new ones.
 */
static int SD_LOOP_DELAY = 32;
#if !defined(m88k) && !defined(sun)
static int SD_WRITE_HIGH = 255;	/* cache blocks */
#endif

static void
cd_write_thread(int cd)
{
	_sd_cctl_t *cc_list, *dirty_head, *last_chain;
	_sd_cd_info_t *cdi;

	cdi = &(_sd_cache_files[cd]);
	if (!FILE_OPENED(cd)) {
		cdi->cd_writer = _SD_WRITER_NONE;
		return;
	}
	cdi->cd_writer = _SD_WRITER_RUNNING;

	_sd_process_pending(cd);

	if (_sdbc_shutdown_in_progress) {
		cdi->cd_write_inprogress = 0;
		cdi->cd_writer = _SD_WRITER_NONE;
		return;
	}
#if !defined(m88k) && !defined(sun)
	if (cdi->cd_info->sh_numio > SD_WRITE_HIGH) {
		/* let I/Os complete before issuing more */
		cdi->cd_writer = _SD_WRITER_NONE;
		return;
	}
#endif

#ifdef DEBUG
	if (!_sdbc_flush_flag) { /* hang the flusher for testing */
		cdi->cd_write_inprogress = 0;
		cdi->cd_writer = _SD_WRITER_NONE;
		return;
	}
#endif

	dirty_head = cdi->cd_dirty_head;
	if (dirty_head && (dirty_head != cdi->cd_lastchain_ptr ||
		++cdi->cd_info->sh_flushloop > SD_LOOP_DELAY)) {
		cdi->cd_info->sh_flushloop = 0;
		/* was FAST */
		mutex_enter(&cdi->cd_lock);
		if (SD_LOOP_DELAY == 0 ||
		    dirty_head == cdi->cd_lastchain_ptr) {
			last_chain = NULL;
			cdi->cd_dirty_head = NULL;
			cdi->cd_dirty_tail = NULL;
			cdi->cd_info->sh_numio += cdi->cd_info->sh_numdirty;
			cdi->cd_info->sh_numdirty = 0;
		} else
#if !defined(m88k) && !defined(sun)
		if (cdi->cd_info->sh_numdirty > SD_WRITE_HIGH) {
			int count = 0;
			for (last_chain = dirty_head; last_chain;
			    last_chain = last_chain->cc_dirty_next) count++;
			last_chain = dirty_head->cc_dirty_link;
			cdi->cd_dirty_head = last_chain;
			/* cdi->cd_dirty_tail is unchanged */
			cdi->cd_info->sh_numio += count;
			cdi->cd_info->sh_numdirty -= count;
		} else
#endif
		{
			last_chain = cdi->cd_lastchain_ptr;
			cdi->cd_dirty_head = last_chain;
			cdi->cd_dirty_tail = last_chain;
			cdi->cd_info->sh_numio += cdi->cd_info->sh_numdirty -
				cdi->cd_lastchain;
			cdi->cd_info->sh_numdirty = cdi->cd_lastchain;
		}
		/* was FAST */
		mutex_exit(&cdi->cd_lock);

		while (((cc_list = dirty_head) != NULL) &&
		    cc_list != last_chain) {
			dirty_head = cc_list->cc_dirty_link;
			cc_list->cc_dirty_link = NULL;
			if (cdi->cd_info->sh_failed)
				_sd_mark_failed(cc_list);
			else if (cc_list->cc_dirty_next == NULL)
				_sd_async_flcent(cc_list, cdi->cd_crdev);
			else
				_sd_async_flclist(cc_list, cdi->cd_crdev);
			cdi->cd_write_inprogress++;
		}
	}
	cdi->cd_write_inprogress = 0;
	cdi->cd_writer = _SD_WRITER_NONE;
}

/*
 * cd_writer -- spawn new writer if not running already
 *	called after enqueing the dirty blocks
 */
int
cd_writer(int cd)
{
	_sd_cd_info_t *cdi;
	nstset_t *tset = NULL;
	nsthread_t *t;

#if defined(_SD_USE_THREADS)
	tset = _sd_ioset;
#endif	/* _SD_USE_THREADS */

	cdi = &(_sd_cache_files[cd]);

	if (cdi->cd_writer)
		return (0);

	if (tset == NULL) {
		_sd_unblock(&_sd_flush_cv);
		return (0);
	}

	if (cdi->cd_writer || xmem_bu(_SD_WRITER_CREATE, &cdi->cd_writer))
		return (0);

	t = nst_create(tset, cd_write_thread, (blind_t)(unsigned long)cd, 0);
	if (t)
		return (1);

	cmn_err(CE_WARN, "sdbc(cd_writer) cd %d nst_create error", cd);
	cdi->cd_writer = _SD_WRITER_NONE;
	return (-1);
}

/*
 * _sd_ccent_rd - add appropriate parts of cc_ent to struct buf.
 *	optimized not to read dirty FBAs from disk.
 *
 * ARGUMENTS:
 *
 * cc_ent   - single cache block
 * wanted   - bitlist of FBAs that need to be read
 * bp	- struct buf to extend
 *
 * USAGE:
 *	Called for each dirty in a read I/O.
 *	The bp must be sized to allow for one entry per FBA that needs
 *	to be read (see _sd_doread()).
 */

void
_sd_ccent_rd(_sd_cctl_t *cc_ent, uint_t wanted, struct buf *bp)
{
	int index, offset = 0, size = 0;
	int state, state1 = -3;	/* state1 is previous state */
	sd_addr_t *addr = NULL;
	uint_t dirty;

	dirty  = CENTRY_DIRTY(cc_ent);
	for (index = 0; index < BLK_FBAS; index++) {
		if (!_SD_BIT_ISSET(wanted, index))
			continue;
		state = _SD_BIT_ISSET(dirty, index);
		if (state == state1) /* same state, expand size */
			size++;
		else {
			if (state1 != -3) /* not first FBA */
				sd_add_fba(bp, addr, offset, size);
			state1 = state;	/* new previous state */
			offset = index;
			size  = 1;
			if (state) {		/* dirty, don't overwrite */
				addr = NULL;
			} else {
				addr = &cc_ent->cc_addr;
			}
		}
	}
	if (state1 != -3)
		sd_add_fba(bp, addr, offset, size);
}



int _SD_WR_THRESHOLD = 1000;
static void
_sd_flush_thread(void)
{
	int cd;
	_sd_cd_info_t *cdi;
	_sd_shared_t *shi;
	int cnt;
	int short_sleep = 0;
	long tics;
	int waiting_for_idle = 0;
	int check_count = 0;
	int pending, last_pending;
	int SD_LONG_SLEEP_TICS, SD_SHORT_SLEEP_TICS;
	nstset_t *tset = NULL;
	nsthread_t *t;

#if defined(_SD_USE_THREADS)
	tset = _sd_ioset;
#endif	/* _SD_USE_THREADS */

	mutex_enter(&_sd_cache_lock);
	_sd_cache_dem_cnt++;
	mutex_exit(&_sd_cache_lock);

	/* .2 seconds */
	SD_LONG_SLEEP_TICS = drv_usectohz(200000);
	/* .02 seconds */
	SD_SHORT_SLEEP_TICS = drv_usectohz(20000);

	/* CONSTCOND */
	while (1) {
		if (_sd_flush_exit == 0) {
			/*
			 * wait until no i/o's pending (on two successive
			 * iterations) or we see no progress after
			 * GIVE_UP_WAITING total sleeps.
			 */
/* at most 5*128 ticks about 6 seconds of no progress */
#define	GIVE_UP_WAITING	128
			if (waiting_for_idle) {
				pending = _sd_pending_iobuf();
				/*LINTED*/
				if (pending == last_pending) {
					if (pending != 0)
						check_count++;
				} else
					check_count = 0;
				if ((last_pending == 0 && (pending == 0)) ||
				    (check_count == GIVE_UP_WAITING)) {
					mutex_enter(&_sd_cache_lock);
					_sd_cache_dem_cnt--;
					mutex_exit(&_sd_cache_lock);
					if (check_count == GIVE_UP_WAITING)
						cmn_err(CE_WARN,
						    "_sd_flush_thread "
						    "exiting with %d IOs "
						    "pending", pending);
					return;
				}
				last_pending = pending;
			} else {
				waiting_for_idle = 1;
				last_pending = _sd_pending_iobuf();
			}
		}

		/*
		 * Normally wakeup every SD_LONG_SLEEP_TICS to flush.
		 */

		if (!short_sleep) {
			ssioc_stats_t ss_stats;
			int rc;

			if ((rc = SSOP_CTL(sdbc_safestore, SSIOC_STATS,
					(uintptr_t)&ss_stats)) == 0) {

				if (ss_stats.wq_inq < _SD_WR_THRESHOLD)
					short_sleep = 1;
			} else {
				if (rc == SS_ERR)
					cmn_err(CE_WARN,
					    "sdbc(_sd_flush_thread)"
					    "cannot get safestore inq");
			}
		}

		if (short_sleep)
			tics = SD_SHORT_SLEEP_TICS;
		else
			tics = SD_LONG_SLEEP_TICS;

		_sd_timed_block(tics, &_sd_flush_cv);
		cd = 0;
		cnt = short_sleep = 0;
		for (; (cnt < _sd_cache_stats->st_loc_count) &&
			(cd < sdbc_max_devs); cd++) {
			cdi = &_sd_cache_files[cd];
			shi = cdi->cd_info;

			if (shi == NULL || (shi->sh_failed == 2))
				continue;

			if (!(shi->sh_alloc & CD_ALLOCATED) ||
			    !(shi->sh_flag & CD_ATTACHED))
				continue;
			cnt++;
			if (cdi->cd_writer)
				continue;
			if (!_SD_CD_WBLK_USED(cd)) {
				if (cdi->cd_failover == 2) {
					nsc_release(cdi->cd_rawfd);
					cdi->cd_failover = 0;
				}
				continue;
			}
			if (cdi->cd_writer ||
			    xmem_bu(_SD_WRITER_CREATE, &cdi->cd_writer))
				continue;

			t = NULL;
			if (tset) {
				t = nst_create(tset,
				    cd_write_thread, (blind_t)(unsigned long)cd,
				    0);
			}
			if (!t)
				cd_write_thread(cd);
		}
	}
}


#if defined(_SD_DEBUG_PATTERN)
check_write_consistency(cc_entry)
	_sd_cctl_t *cc_entry;
{
	int *data;
	nsc_off_t fba_pos;
	int i, dirty_bl;

	while (cc_entry) {
		dirty_bl = CENTRY_DIRTY(cc_entry);
		if (dirty_bl == 0) {
			cmn_err(CE_WARN, "check: no dirty");
		}
		data = (int *)cc_entry->cc_data;
		fba_pos = BLK_TO_FBA_NUM(CENTRY_BLK(cc_entry));

		for (i = 0; i < 8; i++, data += 128, fba_pos++) {
			if (dirty_bl & 1) {
				if (*((int *)(data + 2)) != fba_pos) {
					cmn_err(CE_WARN, "wr exp %" NSC_SZFMT
					    " got %x", fba_pos, *(data + 2));
				}
			}
			dirty_bl >>= 1;
		}
		cc_entry = cc_entry->cc_dirty_next;
	}
}

check_buf_consistency(handle, rw)
	_sd_buf_handle_t *handle;
	char *rw;
{
	_sd_bufvec_t *bvec1;
	int *data;
	nsc_off_t fpos;
	nsc_size_t fba_len, i;
	nsc_size_t len = 0;

	bvec1 = handle->bh_bufvec;
	fpos =  handle->bh_fba_pos;

	while (bvec1->bufaddr) {
		fba_len = FBA_NUM(bvec1->buflen);
		data = (int *)bvec1->bufaddr;
		for (i = 0; i < fba_len; i++, data += 128, fpos++) {
			len++;
			if (*(data+2) != fpos) {
				cmn_err(CE_WARN, "%s exp %" NSC_SZFMT " got %x",
					rw, fpos, *(data + 2));
			}
		}
		bvec1++;
	}
	if (handle->bh_fba_len != len) {
		cmn_err(CE_WARN, "len %" NSC_SZFMT " real %" NSC_SZFMT, len,
		    handle->bh_fba_len);
	}
}
#endif

int
_sdbc_wait_pending(void)
{
	int tries, pend, last;

	tries = 0;
	last  = _sd_pending_iobuf();
	while ((pend = _sd_pending_iobuf()) > 0) {
		if (pend == last) {
			if (++tries > 60) {
				return (pend);
			}
		} else {
			pend = last;
			tries = 0;
		}
		delay(HZ);
	}
	return (0);
}
