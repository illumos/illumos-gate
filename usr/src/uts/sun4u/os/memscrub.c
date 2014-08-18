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
 * sun4u Memory Scrubbing
 *
 * On detection of a correctable memory ECC error, the sun4u kernel
 * returns the corrected data to the requester and re-writes it
 * to memory (DRAM).  So if the correctable error was transient,
 * the read has effectively been cleaned (scrubbed) from memory.
 *
 * Scrubbing thus reduces the likelyhood that multiple transient errors
 * will occur in the same memory word, making uncorrectable errors due
 * to transients less likely.
 *
 * Thus is born the desire that every memory location be periodically
 * accessed.
 *
 * This file implements a memory scrubbing thread.  This scrubber
 * guarantees that all of physical memory is accessed periodically
 * (memscrub_period_sec -- 12 hours).
 *
 * It attempts to do this as unobtrusively as possible.  The thread
 * schedules itself to wake up at an interval such that if it reads
 * memscrub_span_pages (32MB) on each wakeup, it will read all of physical
 * memory in in memscrub_period_sec (12 hours).
 *
 * The scrubber uses the block load and prefetch hardware to read memory
 * @ 1300MB/s, so it reads spans of 32MB in 0.025 seconds.  Unlike the
 * original sun4d scrubber the sun4u scrubber does not read ahead if the
 * system is idle because we can read memory very efficently.
 *
 * The scrubber maintains a private copy of the phys_install memory list
 * to keep track of what memory should be scrubbed.
 *
 * The global routines memscrub_add_span() and memscrub_delete_span() are
 * used to add and delete from this list.  If hotplug memory is later
 * supported these two routines can be used to notify the scrubber of
 * memory configuration changes.
 *
 * The following parameters can be set via /etc/system
 *
 * memscrub_span_pages = MEMSCRUB_DFL_SPAN_PAGES (8MB)
 * memscrub_period_sec = MEMSCRUB_DFL_PERIOD_SEC (12 hours)
 * memscrub_thread_pri = MEMSCRUB_DFL_THREAD_PRI (MINCLSYSPRI)
 * memscrub_delay_start_sec = (5 minutes)
 * memscrub_verbose = (0)
 * memscrub_override_ticks = (1 tick)
 * disable_memscrub = (0)
 * pause_memscrub = (0)
 * read_all_memscrub = (0)
 *
 * The scrubber will print NOTICE messages of what it is doing if
 * "memscrub_verbose" is set.
 *
 * If the scrubber's sleep time calculation drops to zero ticks,
 * memscrub_override_ticks will be used as the sleep time instead. The
 * sleep time should only drop to zero on a system with over 131.84
 * terabytes of memory, or where the default scrubber parameters have
 * been adjusted. For example, reducing memscrub_span_pages or
 * memscrub_period_sec causes the sleep time to drop to zero with less
 * memory. Note that since the sleep time is calculated in clock ticks,
 * using hires clock ticks allows for more memory before the sleep time
 * becomes zero.
 *
 * The scrubber will exit (or never be started) if it finds the variable
 * "disable_memscrub" set.
 *
 * The scrubber will pause (not read memory) when "pause_memscrub"
 * is set.  It will check the state of pause_memscrub at each wakeup
 * period.  The scrubber will not make up for lost time.  If you
 * pause the scrubber for a prolonged period of time you can use
 * the "read_all_memscrub" switch (see below) to catch up. In addition,
 * pause_memscrub is used internally by the post memory DR callbacks.
 * It is set for the small period of time during which the callbacks
 * are executing. This ensures "memscrub_lock" will be released,
 * allowing the callbacks to finish.
 *
 * The scrubber will read all memory if "read_all_memscrub" is set.
 * The normal span read will also occur during the wakeup.
 *
 * MEMSCRUB_MIN_PAGES (32MB) is the minimum amount of memory a system
 * must have before we'll start the scrubber.
 *
 * MEMSCRUB_DFL_SPAN_PAGES (32MB) is based on the guess that 0.025 sec
 * is a "good" amount of minimum time for the thread to run at a time.
 *
 * MEMSCRUB_DFL_PERIOD_SEC (12 hours) is nearly a total guess --
 * twice the frequency the hardware folk estimated would be necessary.
 *
 * MEMSCRUB_DFL_THREAD_PRI (MINCLSYSPRI) is based on the assumption
 * that the scurbber should get its fair share of time (since it
 * is short).  At a priority of 0 the scrubber will be starved.
 */

#include <sys/systm.h>		/* timeout, types, t_lock */
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>	/* MIN */
#include <sys/memlist.h>	/* memlist */
#include <sys/mem_config.h>	/* memory add/delete */
#include <sys/kmem.h>		/* KMEM_NOSLEEP */
#include <sys/cpuvar.h>		/* ncpus_online */
#include <sys/debug.h>		/* ASSERTs */
#include <sys/machsystm.h>	/* lddphys */
#include <sys/cpu_module.h>	/* vtag_flushpage */
#include <sys/kstat.h>
#include <sys/atomic.h>		/* atomic_add_32 */

#include <vm/hat.h>
#include <vm/seg_kmem.h>
#include <vm/hat_sfmmu.h>	/* XXX FIXME - delete */

#include <sys/time.h>
#include <sys/callb.h>		/* CPR callback */
#include <sys/ontrap.h>

/*
 * Should really have paddr_t defined, but it is broken.  Use
 * ms_paddr_t in the meantime to make the code cleaner
 */
typedef uint64_t ms_paddr_t;

/*
 * Global Routines:
 */
int memscrub_add_span(pfn_t pfn, pgcnt_t pages);
int memscrub_delete_span(pfn_t pfn, pgcnt_t pages);
int memscrub_init(void);
void memscrub_induced_error(void);

/*
 * Global Data:
 */

/*
 * scrub if we have at least this many pages
 */
#define	MEMSCRUB_MIN_PAGES (32 * 1024 * 1024 / PAGESIZE)

/*
 * scan all of physical memory at least once every MEMSCRUB_PERIOD_SEC
 */
#define	MEMSCRUB_DFL_PERIOD_SEC	(12 * 60 * 60)	/* 12 hours */

/*
 * scan at least MEMSCRUB_DFL_SPAN_PAGES each iteration
 */
#define	MEMSCRUB_DFL_SPAN_PAGES	((32 * 1024 * 1024) / PAGESIZE)

/*
 * almost anything is higher priority than scrubbing
 */
#define	MEMSCRUB_DFL_THREAD_PRI	MINCLSYSPRI

/*
 * size used when scanning memory
 */
#define	MEMSCRUB_BLOCK_SIZE		256
#define	MEMSCRUB_BLOCK_SIZE_SHIFT	8 	/* log2(MEMSCRUB_BLOCK_SIZE) */
#define	MEMSCRUB_BLOCKS_PER_PAGE	(PAGESIZE >> MEMSCRUB_BLOCK_SIZE_SHIFT)

#define	MEMSCRUB_BPP4M		MMU_PAGESIZE4M >> MEMSCRUB_BLOCK_SIZE_SHIFT
#define	MEMSCRUB_BPP512K	MMU_PAGESIZE512K >> MEMSCRUB_BLOCK_SIZE_SHIFT
#define	MEMSCRUB_BPP64K		MMU_PAGESIZE64K >> MEMSCRUB_BLOCK_SIZE_SHIFT
#define	MEMSCRUB_BPP		MMU_PAGESIZE >> MEMSCRUB_BLOCK_SIZE_SHIFT

/*
 * This message indicates that we have exceeded the limitations of
 * the memscrubber. See the comments above regarding what would
 * cause the sleep time to become zero. In DEBUG mode, this message
 * is logged on the console and in the messages file. In non-DEBUG
 * mode, it is only logged in the messages file.
 */
#ifdef DEBUG
#define	MEMSCRUB_OVERRIDE_MSG	"Memory scrubber sleep time is zero " \
	"seconds, consuming entire CPU."
#else
#define	MEMSCRUB_OVERRIDE_MSG	"!Memory scrubber sleep time is zero " \
	"seconds, consuming entire CPU."
#endif /* DEBUG */

/*
 * we can patch these defaults in /etc/system if necessary
 */
uint_t disable_memscrub = 0;
uint_t pause_memscrub = 0;
uint_t read_all_memscrub = 0;
uint_t memscrub_verbose = 0;
uint_t memscrub_all_idle = 0;
uint_t memscrub_span_pages = MEMSCRUB_DFL_SPAN_PAGES;
uint_t memscrub_period_sec = MEMSCRUB_DFL_PERIOD_SEC;
uint_t memscrub_thread_pri = MEMSCRUB_DFL_THREAD_PRI;
uint_t memscrub_delay_start_sec = 5 * 60;
uint_t memscrub_override_ticks = 1;

/*
 * Static Routines
 */
static void memscrubber(void);
static void memscrub_cleanup(void);
static int memscrub_add_span_gen(pfn_t, pgcnt_t, struct memlist **, uint_t *);
static int memscrub_verify_span(ms_paddr_t *addrp, pgcnt_t *pagesp);
static void memscrub_scan(uint_t blks, ms_paddr_t src);

/*
 * Static Data
 */

static struct memlist *memscrub_memlist;
static uint_t memscrub_phys_pages;

static kcondvar_t memscrub_cv;
static kmutex_t memscrub_lock;
/*
 * memscrub_lock protects memscrub_memlist, interval_ticks, cprinfo, ...
 */
static void memscrub_init_mem_config(void);
static void memscrub_uninit_mem_config(void);

/*
 * Linked list of memscrub aware spans having retired pages.
 * Currently enabled only on sun4u USIII-based platforms.
 */
typedef struct memscrub_page_retire_span {
	ms_paddr_t				address;
	struct memscrub_page_retire_span	*next;
} memscrub_page_retire_span_t;

static memscrub_page_retire_span_t *memscrub_page_retire_span_list = NULL;

static void memscrub_page_retire_span_add(ms_paddr_t);
static void memscrub_page_retire_span_delete(ms_paddr_t);
static int memscrub_page_retire_span_search(ms_paddr_t);
static void memscrub_page_retire_span_list_update(void);

/*
 * add_to_page_retire_list: Set by cpu_async_log_err() routine
 * by calling memscrub_induced_error() when CE/UE occurs on a retired
 * page due to memscrub reading.  Cleared by memscrub after updating
 * global page retire span list.  Piggybacking on protection of
 * memscrub_lock, which is held during set and clear.
 * Note: When cpu_async_log_err() calls memscrub_induced_error(), it is running
 * on softint context, which gets fired on a cpu memscrub thread currently
 * running.  Memscrub thread has affinity set during memscrub_read(), hence
 * migration to new cpu not expected.
 */
static int add_to_page_retire_list = 0;

/*
 * Keep track of some interesting statistics
 */
static struct memscrub_kstats {
	kstat_named_t	done_early;	/* ahead of schedule */
	kstat_named_t	early_sec;	/* by cumulative num secs */
	kstat_named_t	done_late;	/* behind schedule */
	kstat_named_t	late_sec;	/* by cumulative num secs */
	kstat_named_t	interval_ticks;	/* num ticks between intervals */
	kstat_named_t	force_run;	/* forced to run, non-timeout */
	kstat_named_t	errors_found;	/* num errors found by memscrub */
} memscrub_counts = {
	{ "done_early",		KSTAT_DATA_UINT32 },
	{ "early_sec", 		KSTAT_DATA_UINT32 },
	{ "done_late", 		KSTAT_DATA_UINT32 },
	{ "late_sec",		KSTAT_DATA_UINT32 },
	{ "interval_ticks",	KSTAT_DATA_UINT32 },
	{ "force_run",		KSTAT_DATA_UINT32 },
	{ "errors_found",	KSTAT_DATA_UINT32 },
};

#define	MEMSCRUB_STAT_INC(stat)	memscrub_counts.stat.value.ui32++
#define	MEMSCRUB_STAT_SET(stat, val) memscrub_counts.stat.value.ui32 = (val)
#define	MEMSCRUB_STAT_NINC(stat, val) memscrub_counts.stat.value.ui32 += (val)

static struct kstat *memscrub_ksp = (struct kstat *)NULL;

static timeout_id_t memscrub_tid = 0;	/* keep track of timeout id */

/*
 * create memscrub_memlist from phys_install list
 * initialize locks, set memscrub_phys_pages.
 */
int
memscrub_init(void)
{
	struct memlist *src;

	/*
	 * only startup the scrubber if we have a minimum
	 * number of pages
	 */
	if (physinstalled >= MEMSCRUB_MIN_PAGES) {

		/*
		 * initialize locks
		 */
		mutex_init(&memscrub_lock, NULL, MUTEX_DRIVER, NULL);
		cv_init(&memscrub_cv, NULL, CV_DRIVER, NULL);

		/*
		 * copy phys_install to memscrub_memlist
		 */
		for (src = phys_install; src; src = src->ml_next) {
			if (memscrub_add_span(
			    (pfn_t)(src->ml_address >> PAGESHIFT),
			    (pgcnt_t)(src->ml_size >> PAGESHIFT))) {
				memscrub_cleanup();
				return (-1);
			}
		}

		/*
		 * initialize kstats
		 */
		memscrub_ksp = kstat_create("unix", 0, "memscrub_kstat",
		    "misc", KSTAT_TYPE_NAMED,
		    sizeof (memscrub_counts) / sizeof (kstat_named_t),
		    KSTAT_FLAG_VIRTUAL | KSTAT_FLAG_WRITABLE);

		if (memscrub_ksp) {
			memscrub_ksp->ks_data = (void *)&memscrub_counts;
			kstat_install(memscrub_ksp);
		} else {
			cmn_err(CE_NOTE, "Memscrubber cannot create kstats\n");
		}

		/*
		 * create memscrubber thread
		 */
		(void) thread_create(NULL, 0, (void (*)())memscrubber,
		    NULL, 0, &p0, TS_RUN, memscrub_thread_pri);

		/*
		 * We don't want call backs changing the list
		 * if there is no thread running. We do not
		 * attempt to deal with stopping/starting scrubbing
		 * on memory size changes.
		 */
		memscrub_init_mem_config();
	}

	return (0);
}

static void
memscrub_cleanup(void)
{
	memscrub_uninit_mem_config();
	while (memscrub_memlist) {
		(void) memscrub_delete_span(
		    (pfn_t)(memscrub_memlist->ml_address >> PAGESHIFT),
		    (pgcnt_t)(memscrub_memlist->ml_size >> PAGESHIFT));
	}
	if (memscrub_ksp)
		kstat_delete(memscrub_ksp);
	cv_destroy(&memscrub_cv);
	mutex_destroy(&memscrub_lock);
}

#ifdef MEMSCRUB_DEBUG
static void
memscrub_printmemlist(char *title, struct memlist *listp)
{
	struct memlist *list;

	cmn_err(CE_CONT, "%s:\n", title);

	for (list = listp; list; list = list->ml_next) {
		cmn_err(CE_CONT, "addr = 0x%llx, size = 0x%llx\n",
		    list->ml_address, list->ml_size);
	}
}
#endif /* MEMSCRUB_DEBUG */

/* ARGSUSED */
static void
memscrub_wakeup(void *c)
{
	/*
	 * grab mutex to guarantee that our wakeup call
	 * arrives after we go to sleep -- so we can't sleep forever.
	 */
	mutex_enter(&memscrub_lock);
	cv_signal(&memscrub_cv);
	mutex_exit(&memscrub_lock);
}

/*
 * provide an interface external to the memscrubber
 * which will force the memscrub thread to run vs.
 * waiting for the timeout, if one is set
 */
void
memscrub_run(void)
{
	MEMSCRUB_STAT_INC(force_run);
	if (memscrub_tid) {
		(void) untimeout(memscrub_tid);
		memscrub_wakeup((void *)NULL);
	}
}

/*
 * this calculation doesn't account for the time
 * that the actual scan consumes -- so we'd fall
 * slightly behind schedule with this interval.
 * It's very small.
 */

static uint_t
compute_interval_ticks(void)
{
	/*
	 * We use msp_safe mpp_safe below to insure somebody
	 * doesn't set memscrub_span_pages or memscrub_phys_pages
	 * to 0 on us.
	 */
	static uint_t msp_safe, mpp_safe;
	static uint_t interval_ticks, period_ticks;
	msp_safe = memscrub_span_pages;
	mpp_safe = memscrub_phys_pages;

	period_ticks = memscrub_period_sec * hz;
	interval_ticks = period_ticks;

	ASSERT(mutex_owned(&memscrub_lock));

	if ((msp_safe != 0) && (mpp_safe != 0)) {
		if (memscrub_phys_pages <= msp_safe) {
			interval_ticks = period_ticks;
		} else {
			interval_ticks = (period_ticks /
			    (mpp_safe / msp_safe));
		}
	}
	return (interval_ticks);
}

void
memscrubber(void)
{
	ms_paddr_t address, addr;
	time_t deadline;
	pgcnt_t pages;
	uint_t reached_end = 1;
	uint_t paused_message = 0;
	uint_t interval_ticks = 0;
	uint_t sleep_warn_printed = 0;
	callb_cpr_t cprinfo;

	/*
	 * notify CPR of our existence
	 */
	CALLB_CPR_INIT(&cprinfo, &memscrub_lock, callb_generic_cpr, "memscrub");

	mutex_enter(&memscrub_lock);

	if (memscrub_memlist == NULL) {
		cmn_err(CE_WARN, "memscrub_memlist not initialized.");
		goto memscrub_exit;
	}

	address = memscrub_memlist->ml_address;

	deadline = gethrestime_sec() + memscrub_delay_start_sec;

	for (;;) {
		if (disable_memscrub)
			break;

		/*
		 * compute interval_ticks
		 */
		interval_ticks = compute_interval_ticks();

		/*
		 * If the calculated sleep time is zero, and pause_memscrub
		 * has been set, make sure we sleep so that another thread
		 * can acquire memscrub_lock.
		 */
		if (interval_ticks == 0 && pause_memscrub) {
			interval_ticks = hz;
		}

		/*
		 * And as a fail safe, under normal non-paused operation, do
		 * not allow the sleep time to be zero.
		 */
		if (interval_ticks == 0) {
			interval_ticks = memscrub_override_ticks;
			if (!sleep_warn_printed) {
				cmn_err(CE_NOTE, MEMSCRUB_OVERRIDE_MSG);
				sleep_warn_printed = 1;
			}
		}

		MEMSCRUB_STAT_SET(interval_ticks, interval_ticks);

		/*
		 * Did we just reach the end of memory? If we are at the
		 * end of memory, delay end of memory processing until
		 * pause_memscrub is not set.
		 */
		if (reached_end && !pause_memscrub) {
			time_t now = gethrestime_sec();

			if (now >= deadline) {
				MEMSCRUB_STAT_INC(done_late);
				MEMSCRUB_STAT_NINC(late_sec, now - deadline);
				/*
				 * past deadline, start right away
				 */
				interval_ticks = 0;

				deadline = now + memscrub_period_sec;
			} else {
				/*
				 * we finished ahead of schedule.
				 * wait till previous deadline before re-start.
				 */
				interval_ticks = (deadline - now) * hz;
				MEMSCRUB_STAT_INC(done_early);
				MEMSCRUB_STAT_NINC(early_sec, deadline - now);
				deadline += memscrub_period_sec;
			}
			reached_end = 0;
			sleep_warn_printed = 0;
		}

		if (interval_ticks != 0) {
			/*
			 * it is safe from our standpoint for CPR to
			 * suspend the system
			 */
			CALLB_CPR_SAFE_BEGIN(&cprinfo);

			/*
			 * hit the snooze bar
			 */
			memscrub_tid = timeout(memscrub_wakeup, NULL,
			    interval_ticks);

			/*
			 * go to sleep
			 */
			cv_wait(&memscrub_cv, &memscrub_lock);

			/*
			 * at this point, no timeout should be set
			 */
			memscrub_tid = 0;

			/*
			 * we need to goto work and will be modifying
			 * our internal state and mapping/unmapping
			 * TTEs
			 */
			CALLB_CPR_SAFE_END(&cprinfo, &memscrub_lock);
		}


		if (memscrub_phys_pages == 0) {
			cmn_err(CE_WARN, "Memory scrubber has 0 pages to read");
			goto memscrub_exit;
		}

		if (!pause_memscrub) {
			if (paused_message) {
				paused_message = 0;
				if (memscrub_verbose)
					cmn_err(CE_NOTE, "Memory scrubber "
					    "resuming");
			}

			if (read_all_memscrub) {
				if (memscrub_verbose)
					cmn_err(CE_NOTE, "Memory scrubber "
					    "reading all memory per request");

				addr = memscrub_memlist->ml_address;
				reached_end = 0;
				while (!reached_end) {
					if (disable_memscrub)
						break;
					pages = memscrub_phys_pages;
					reached_end = memscrub_verify_span(
					    &addr, &pages);
					memscrub_scan(pages *
					    MEMSCRUB_BLOCKS_PER_PAGE, addr);
					addr += ((uint64_t)pages * PAGESIZE);
				}
				read_all_memscrub = 0;
			}

			/*
			 * read 1 span
			 */
			pages = memscrub_span_pages;

			if (disable_memscrub)
				break;

			/*
			 * determine physical address range
			 */
			reached_end = memscrub_verify_span(&address,
			    &pages);

			memscrub_scan(pages * MEMSCRUB_BLOCKS_PER_PAGE,
			    address);

			address += ((uint64_t)pages * PAGESIZE);
		}

		if (pause_memscrub && !paused_message) {
			paused_message = 1;
			if (memscrub_verbose)
				cmn_err(CE_NOTE, "Memory scrubber paused");
		}
	}

memscrub_exit:
	cmn_err(CE_NOTE, "Memory scrubber exiting");
	CALLB_CPR_EXIT(&cprinfo);
	memscrub_cleanup();
	thread_exit();
	/* NOTREACHED */
}

/*
 * condition address and size
 * such that they span legal physical addresses.
 *
 * when appropriate, address will be rounded up to start of next
 * struct memlist, and pages will be rounded down to the end of the
 * memlist size.
 *
 * returns 1 if reached end of list, else returns 0.
 */
static int
memscrub_verify_span(ms_paddr_t *addrp, pgcnt_t *pagesp)
{
	struct memlist *mlp;
	ms_paddr_t address = *addrp;
	uint64_t bytes = (uint64_t)*pagesp * PAGESIZE;
	uint64_t bytes_remaining;
	int reached_end = 0;

	ASSERT(mutex_owned(&memscrub_lock));

	/*
	 * find memlist struct that contains addrp
	 * assumes memlist is sorted by ascending address.
	 */
	for (mlp = memscrub_memlist; mlp != NULL; mlp = mlp->ml_next) {
		/*
		 * if before this chunk, round up to beginning
		 */
		if (address < mlp->ml_address) {
			address = mlp->ml_address;
			break;
		}
		/*
		 * if before end of chunk, then we found it
		 */
		if (address < (mlp->ml_address + mlp->ml_size))
			break;

		/* else go to next struct memlist */
	}
	/*
	 * if we hit end of list, start at beginning
	 */
	if (mlp == NULL) {
		mlp = memscrub_memlist;
		address = mlp->ml_address;
	}

	/*
	 * now we have legal address, and its mlp, condition bytes
	 */
	bytes_remaining = (mlp->ml_address + mlp->ml_size) - address;

	if (bytes > bytes_remaining)
		bytes = bytes_remaining;

	/*
	 * will this span take us to end of list?
	 */
	if ((mlp->ml_next == NULL) &&
	    ((mlp->ml_address + mlp->ml_size) == (address + bytes)))
		reached_end = 1;

	/* return values */
	*addrp = address;
	*pagesp = bytes / PAGESIZE;

	return (reached_end);
}

/*
 * add a span to the memscrub list
 * add to memscrub_phys_pages
 */
int
memscrub_add_span(pfn_t pfn, pgcnt_t pages)
{
#ifdef MEMSCRUB_DEBUG
	ms_paddr_t address = (ms_paddr_t)pfn << PAGESHIFT;
	uint64_t bytes = (uint64_t)pages << PAGESHIFT;
#endif /* MEMSCRUB_DEBUG */

	int retval;

	mutex_enter(&memscrub_lock);

#ifdef MEMSCRUB_DEBUG
	memscrub_printmemlist("memscrub_memlist before", memscrub_memlist);
	cmn_err(CE_CONT, "memscrub_phys_pages: 0x%x\n", memscrub_phys_pages);
	cmn_err(CE_CONT, "memscrub_add_span: address: 0x%llx"
	    " size: 0x%llx\n", address, bytes);
#endif /* MEMSCRUB_DEBUG */

	retval = memscrub_add_span_gen(pfn, pages, &memscrub_memlist,
	    &memscrub_phys_pages);

#ifdef MEMSCRUB_DEBUG
	memscrub_printmemlist("memscrub_memlist after", memscrub_memlist);
	cmn_err(CE_CONT, "memscrub_phys_pages: 0x%x\n", memscrub_phys_pages);
#endif /* MEMSCRUB_DEBUG */

	mutex_exit(&memscrub_lock);

	return (retval);
}

static int
memscrub_add_span_gen(
	pfn_t pfn,
	pgcnt_t pages,
	struct memlist **list,
	uint_t *npgs)
{
	ms_paddr_t address = (ms_paddr_t)pfn << PAGESHIFT;
	uint64_t bytes = (uint64_t)pages << PAGESHIFT;
	struct memlist *dst;
	struct memlist *prev, *next;
	int retval = 0;

	/*
	 * allocate a new struct memlist
	 */

	dst = (struct memlist *)
	    kmem_alloc(sizeof (struct memlist), KM_NOSLEEP);

	if (dst == NULL) {
		retval = -1;
		goto add_done;
	}

	dst->ml_address = address;
	dst->ml_size = bytes;

	/*
	 * first insert
	 */
	if (*list == NULL) {
		dst->ml_prev = NULL;
		dst->ml_next = NULL;
		*list = dst;

		goto add_done;
	}

	/*
	 * insert into sorted list
	 */
	for (prev = NULL, next = *list;
	    next != NULL;
	    prev = next, next = next->ml_next) {
		if (address > (next->ml_address + next->ml_size))
			continue;

		/*
		 * else insert here
		 */

		/*
		 * prepend to next
		 */
		if ((address + bytes) == next->ml_address) {
			kmem_free(dst, sizeof (struct memlist));

			next->ml_address = address;
			next->ml_size += bytes;

			goto add_done;
		}

		/*
		 * append to next
		 */
		if (address == (next->ml_address + next->ml_size)) {
			kmem_free(dst, sizeof (struct memlist));

			if (next->ml_next) {
				/*
				 * don't overlap with next->ml_next
				 */
				if ((address + bytes) >
				    next->ml_next->ml_address) {
					retval = -1;
					goto add_done;
				}
				/*
				 * concatenate next and next->ml_next
				 */
				if ((address + bytes) ==
				    next->ml_next->ml_address) {
					struct memlist *mlp = next->ml_next;

					if (next == *list)
						*list = next->ml_next;

					mlp->ml_address = next->ml_address;
					mlp->ml_size += next->ml_size;
					mlp->ml_size += bytes;

					if (next->ml_prev)
						next->ml_prev->ml_next = mlp;
					mlp->ml_prev = next->ml_prev;

					kmem_free(next,
					    sizeof (struct memlist));
					goto add_done;
				}
			}

			next->ml_size += bytes;

			goto add_done;
		}

		/* don't overlap with next */
		if ((address + bytes) > next->ml_address) {
			retval = -1;
			kmem_free(dst, sizeof (struct memlist));
			goto add_done;
		}

		/*
		 * insert before next
		 */
		dst->ml_prev = prev;
		dst->ml_next = next;
		next->ml_prev = dst;
		if (prev == NULL) {
			*list = dst;
		} else {
			prev->ml_next = dst;
		}
		goto add_done;
	}	/* end for */

	/*
	 * end of list, prev is valid and next is NULL
	 */
	prev->ml_next = dst;
	dst->ml_prev = prev;
	dst->ml_next = NULL;

add_done:

	if (retval != -1)
		*npgs += pages;

	return (retval);
}

/*
 * delete a span from the memscrub list
 * subtract from memscrub_phys_pages
 */
int
memscrub_delete_span(pfn_t pfn, pgcnt_t pages)
{
	ms_paddr_t address = (ms_paddr_t)pfn << PAGESHIFT;
	uint64_t bytes = (uint64_t)pages << PAGESHIFT;
	struct memlist *dst, *next;
	int retval = 0;

	mutex_enter(&memscrub_lock);

#ifdef MEMSCRUB_DEBUG
	memscrub_printmemlist("memscrub_memlist Before", memscrub_memlist);
	cmn_err(CE_CONT, "memscrub_phys_pages: 0x%x\n", memscrub_phys_pages);
	cmn_err(CE_CONT, "memscrub_delete_span: 0x%llx 0x%llx\n",
	    address, bytes);
#endif /* MEMSCRUB_DEBUG */

	/*
	 * find struct memlist containing page
	 */
	for (next = memscrub_memlist; next != NULL; next = next->ml_next) {
		if ((address >= next->ml_address) &&
		    (address < next->ml_address + next->ml_size))
			break;
	}

	/*
	 * if start address not in list
	 */
	if (next == NULL) {
		retval = -1;
		goto delete_done;
	}

	/*
	 * error if size goes off end of this struct memlist
	 */
	if (address + bytes > next->ml_address + next->ml_size) {
		retval = -1;
		goto delete_done;
	}

	/*
	 * pages at beginning of struct memlist
	 */
	if (address == next->ml_address) {
		/*
		 * if start & size match, delete from list
		 */
		if (bytes == next->ml_size) {
			if (next == memscrub_memlist)
				memscrub_memlist = next->ml_next;
			if (next->ml_prev != NULL)
				next->ml_prev->ml_next = next->ml_next;
			if (next->ml_next != NULL)
				next->ml_next->ml_prev = next->ml_prev;

			kmem_free(next, sizeof (struct memlist));
		} else {
		/*
		 * increment start address by bytes
		 */
			next->ml_address += bytes;
			next->ml_size -= bytes;
		}
		goto delete_done;
	}

	/*
	 * pages at end of struct memlist
	 */
	if (address + bytes == next->ml_address + next->ml_size) {
		/*
		 * decrement size by bytes
		 */
		next->ml_size -= bytes;
		goto delete_done;
	}

	/*
	 * delete a span in the middle of the struct memlist
	 */
	{
		/*
		 * create a new struct memlist
		 */
		dst = (struct memlist *)
		    kmem_alloc(sizeof (struct memlist), KM_NOSLEEP);

		if (dst == NULL) {
			retval = -1;
			goto delete_done;
		}

		/*
		 * existing struct memlist gets address
		 * and size up to pfn
		 */
		dst->ml_address = address + bytes;
		dst->ml_size =
		    (next->ml_address + next->ml_size) - dst->ml_address;
		next->ml_size = address - next->ml_address;

		/*
		 * new struct memlist gets address starting
		 * after pfn, until end
		 */

		/*
		 * link in new memlist after old
		 */
		dst->ml_next = next->ml_next;
		dst->ml_prev = next;

		if (next->ml_next != NULL)
			next->ml_next->ml_prev = dst;
		next->ml_next = dst;
	}

delete_done:
	if (retval != -1) {
		memscrub_phys_pages -= pages;
		if (memscrub_phys_pages == 0)
			disable_memscrub = 1;
	}

#ifdef MEMSCRUB_DEBUG
	memscrub_printmemlist("memscrub_memlist After", memscrub_memlist);
	cmn_err(CE_CONT, "memscrub_phys_pages: 0x%x\n", memscrub_phys_pages);
#endif /* MEMSCRUB_DEBUG */

	mutex_exit(&memscrub_lock);
	return (retval);
}

static void
memscrub_scan(uint_t blks, ms_paddr_t src)
{
	uint_t 		psz, bpp, pgsread;
	pfn_t		pfn;
	ms_paddr_t	pa;
	caddr_t		va;
	on_trap_data_t	otd;
	int		scan_mmu_pagesize = 0;
	int		retired_pages = 0;

	extern void memscrub_read(caddr_t src, uint_t blks);

	ASSERT(mutex_owned(&memscrub_lock));

	pgsread = 0;
	pa = src;

	if (memscrub_page_retire_span_list != NULL) {
		if (memscrub_page_retire_span_search(src)) {
			/* retired pages in current span */
			scan_mmu_pagesize = 1;
		}
	}

#ifdef MEMSCRUB_DEBUG
	cmn_err(CE_NOTE, "scan_mmu_pagesize = %d\n" scan_mmu_pagesize);
#endif /* MEMSCRUB_DEBUG */

	while (blks != 0) {
		/* Ensure the PA is properly aligned */
		if (((pa & MMU_PAGEMASK4M) == pa) &&
		    (blks >= MEMSCRUB_BPP4M)) {
			psz = MMU_PAGESIZE4M;
			bpp = MEMSCRUB_BPP4M;
		} else if (((pa & MMU_PAGEMASK512K) == pa) &&
		    (blks >= MEMSCRUB_BPP512K)) {
			psz = MMU_PAGESIZE512K;
			bpp = MEMSCRUB_BPP512K;
		} else if (((pa & MMU_PAGEMASK64K) == pa) &&
		    (blks >= MEMSCRUB_BPP64K)) {
			psz = MMU_PAGESIZE64K;
			bpp = MEMSCRUB_BPP64K;
		} else if ((pa & MMU_PAGEMASK) == pa) {
			psz = MMU_PAGESIZE;
			bpp = MEMSCRUB_BPP;
		} else {
			if (memscrub_verbose) {
				cmn_err(CE_NOTE, "Memory scrubber ignoring "
				    "non-page aligned block starting at 0x%"
				    PRIx64, src);
			}
			return;
		}
		if (blks < bpp) bpp = blks;

#ifdef MEMSCRUB_DEBUG
		cmn_err(CE_NOTE, "Going to run psz=%x, "
		    "bpp=%x pa=%llx\n", psz, bpp, pa);
#endif /* MEMSCRUB_DEBUG */

		/*
		 * MEMSCRUBBASE is a 4MB aligned page in the
		 * kernel so that we can quickly map the PA
		 * to a VA for the block loads performed in
		 * memscrub_read.
		 */
		pfn = mmu_btop(pa);
		va = (caddr_t)MEMSCRUBBASE;
		hat_devload(kas.a_hat, va, psz, pfn, PROT_READ,
		    HAT_LOAD_NOCONSIST | HAT_LOAD_LOCK);

		/*
		 * Can't allow the memscrubber to migrate across CPUs as
		 * we need to know whether CEEN is enabled for the current
		 * CPU to enable us to scrub the memory. Don't use
		 * kpreempt_disable as the time we take to scan a span (even
		 * without cpu_check_ce having to manually cpu_check_block)
		 * is too long to hold a higher priority thread (eg, RT)
		 * off cpu.
		 */
		thread_affinity_set(curthread, CPU_CURRENT);

		/*
		 * Protect read scrub from async faults.  For now, we simply
		 * maintain a count of such faults caught.
		 */

		if (!on_trap(&otd, OT_DATA_EC) && !scan_mmu_pagesize) {
			memscrub_read(va, bpp);
			/*
			 * Check if CEs require logging
			 */
			cpu_check_ce(SCRUBBER_CEEN_CHECK,
			    (uint64_t)pa, va, psz);
			no_trap();
			thread_affinity_clear(curthread);
		} else {
			no_trap();
			thread_affinity_clear(curthread);

			/*
			 * Got an async error..
			 * Try rescanning it at MMU_PAGESIZE
			 * granularity if we were trying to
			 * read at a larger page size.
			 * This is to ensure we continue to
			 * scan the rest of the span.
			 * OR scanning MMU_PAGESIZE granularity to avoid
			 * reading retired pages memory when scan_mmu_pagesize
			 * is set.
			 */
			if (psz > MMU_PAGESIZE || scan_mmu_pagesize) {
				caddr_t vaddr = va;
				ms_paddr_t paddr = pa;
				int tmp = 0;
				for (; tmp < bpp; tmp += MEMSCRUB_BPP) {
					/* Don't scrub retired pages */
					if (page_retire_check(paddr, NULL)
					    == 0) {
						vaddr += MMU_PAGESIZE;
						paddr += MMU_PAGESIZE;
						retired_pages++;
						continue;
					}
					thread_affinity_set(curthread,
					    CPU_CURRENT);
					if (!on_trap(&otd, OT_DATA_EC)) {
						memscrub_read(vaddr,
						    MEMSCRUB_BPP);
						cpu_check_ce(
						    SCRUBBER_CEEN_CHECK,
						    (uint64_t)paddr, vaddr,
						    MMU_PAGESIZE);
						no_trap();
					} else {
						no_trap();
						MEMSCRUB_STAT_INC(errors_found);
					}
					thread_affinity_clear(curthread);
					vaddr += MMU_PAGESIZE;
					paddr += MMU_PAGESIZE;
				}
			}
		}
		hat_unload(kas.a_hat, va, psz, HAT_UNLOAD_UNLOCK);

		blks -= bpp;
		pa += psz;
		pgsread++;
	}

	/*
	 * If just finished scrubbing MMU_PAGESIZE at a time, but no retired
	 * pages found so delete span from global list.
	 */
	if (scan_mmu_pagesize && retired_pages == 0)
		memscrub_page_retire_span_delete(src);

	/*
	 * Encountered CE/UE on a retired page during memscrub read of current
	 * span.  Adding span to global list to enable avoid reading further.
	 */
	if (add_to_page_retire_list) {
		if (!memscrub_page_retire_span_search(src))
			memscrub_page_retire_span_add(src);
		add_to_page_retire_list = 0;
	}

	if (memscrub_verbose) {
		cmn_err(CE_NOTE, "Memory scrubber read 0x%x pages starting "
		    "at 0x%" PRIx64, pgsread, src);
	}
}

/*
 * Called by cpu_async_log_err() when memscrub read causes
 * CE/UE on a retired page.
 */
void
memscrub_induced_error(void)
{
	add_to_page_retire_list = 1;
}

/*
 * Called by page_retire() when toxic pages cannot be retired
 * immediately and are scheduled for retire.  Memscrubber stops
 * scrubbing them to avoid further CE/UEs.
 */
void
memscrub_notify(ms_paddr_t pa)
{
	mutex_enter(&memscrub_lock);
	if (!memscrub_page_retire_span_search(pa))
		memscrub_page_retire_span_add(pa);
	mutex_exit(&memscrub_lock);
}

/*
 * Called by memscrub_scan() and memscrub_notify().
 * pa: physical address of span with CE/UE, add to global list.
 */
static void
memscrub_page_retire_span_add(ms_paddr_t pa)
{
	memscrub_page_retire_span_t *new_span;

	new_span = (memscrub_page_retire_span_t *)
	    kmem_zalloc(sizeof (memscrub_page_retire_span_t), KM_NOSLEEP);

	if (new_span == NULL) {
#ifdef MEMSCRUB_DEBUG
		cmn_err(CE_NOTE, "failed to allocate new span - span with"
		    " retired page/s not tracked.\n");
#endif /* MEMSCRUB_DEBUG */
		return;
	}

	new_span->address = pa;
	new_span->next = memscrub_page_retire_span_list;
	memscrub_page_retire_span_list = new_span;
}

/*
 * Called by memscrub_scan().
 * pa: physical address of span to be removed from global list.
 */
static void
memscrub_page_retire_span_delete(ms_paddr_t pa)
{
	memscrub_page_retire_span_t *prev_span, *next_span;

	prev_span = memscrub_page_retire_span_list;
	next_span = memscrub_page_retire_span_list->next;

	if (pa == prev_span->address) {
		memscrub_page_retire_span_list = next_span;
		kmem_free(prev_span, sizeof (memscrub_page_retire_span_t));
		return;
	}

	while (next_span) {
		if (pa == next_span->address) {
			prev_span->next = next_span->next;
			kmem_free(next_span,
			    sizeof (memscrub_page_retire_span_t));
			return;
		}
		prev_span = next_span;
		next_span = next_span->next;
	}
}

/*
 * Called by memscrub_scan() and memscrub_notify().
 * pa: physical address of span to be searched in global list.
 */
static int
memscrub_page_retire_span_search(ms_paddr_t pa)
{
	memscrub_page_retire_span_t *next_span = memscrub_page_retire_span_list;

	while (next_span) {
		if (pa == next_span->address)
			return (1);
		next_span = next_span->next;
	}
	return (0);
}

/*
 * Called from new_memscrub() as a result of memory delete.
 * Using page_numtopp_nolock() to determine if we have valid PA.
 */
static void
memscrub_page_retire_span_list_update(void)
{
	memscrub_page_retire_span_t *prev, *cur, *next;

	if (memscrub_page_retire_span_list == NULL)
		return;

	prev = cur = memscrub_page_retire_span_list;
	next = cur->next;

	while (cur) {
		if (page_numtopp_nolock(mmu_btop(cur->address)) == NULL) {
			if (cur == memscrub_page_retire_span_list) {
				memscrub_page_retire_span_list = next;
				kmem_free(cur,
				    sizeof (memscrub_page_retire_span_t));
				prev = cur = memscrub_page_retire_span_list;
			} else {
				prev->next = cur->next;
				kmem_free(cur,
				    sizeof (memscrub_page_retire_span_t));
				cur = next;
			}
		} else {
			prev = cur;
			cur = next;
		}
		if (cur != NULL)
			next = cur->next;
	}
}

/*
 * The memory add/delete callback mechanism does not pass in the
 * page ranges. The phys_install list has been updated though, so
 * create a new scrub list from it.
 */

static int
new_memscrub(int update_page_retire_list)
{
	struct memlist *src, *list, *old_list;
	uint_t npgs;

	/*
	 * copy phys_install to memscrub_memlist
	 */
	list = NULL;
	npgs = 0;
	memlist_read_lock();
	for (src = phys_install; src; src = src->ml_next) {
		if (memscrub_add_span_gen((pfn_t)(src->ml_address >> PAGESHIFT),
		    (pgcnt_t)(src->ml_size >> PAGESHIFT), &list, &npgs)) {
			memlist_read_unlock();
			while (list) {
				struct memlist *el;

				el = list;
				list = list->ml_next;
				kmem_free(el, sizeof (struct memlist));
			}
			return (-1);
		}
	}
	memlist_read_unlock();

	mutex_enter(&memscrub_lock);
	memscrub_phys_pages = npgs;
	old_list = memscrub_memlist;
	memscrub_memlist = list;

	if (update_page_retire_list)
		memscrub_page_retire_span_list_update();

	mutex_exit(&memscrub_lock);

	while (old_list) {
		struct memlist *el;

		el = old_list;
		old_list = old_list->ml_next;
		kmem_free(el, sizeof (struct memlist));
	}

	return (0);
}

/*ARGSUSED*/
static void
memscrub_mem_config_post_add(
	void *arg,
	pgcnt_t delta_pages)
{
	/*
	 * We increment pause_memscrub before entering new_memscrub(). This
	 * will force the memscrubber to sleep, allowing the DR callback
	 * thread to acquire memscrub_lock in new_memscrub(). The use of
	 * atomic_add_32() allows concurrent memory DR operations to use the
	 * callbacks safely.
	 */
	atomic_inc_32(&pause_memscrub);
	ASSERT(pause_memscrub != 0);

	/*
	 * "Don't care" if we are not scrubbing new memory.
	 */
	(void) new_memscrub(0);		/* retain page retire list */

	/* Restore the pause setting. */
	atomic_dec_32(&pause_memscrub);
}

/*ARGSUSED*/
static int
memscrub_mem_config_pre_del(
	void *arg,
	pgcnt_t delta_pages)
{
	/* Nothing to do. */
	return (0);
}

/*ARGSUSED*/
static void
memscrub_mem_config_post_del(
	void *arg,
	pgcnt_t delta_pages,
	int cancelled)
{
	/*
	 * We increment pause_memscrub before entering new_memscrub(). This
	 * will force the memscrubber to sleep, allowing the DR callback
	 * thread to acquire memscrub_lock in new_memscrub(). The use of
	 * atomic_add_32() allows concurrent memory DR operations to use the
	 * callbacks safely.
	 */
	atomic_inc_32(&pause_memscrub);
	ASSERT(pause_memscrub != 0);

	/*
	 * Must stop scrubbing deleted memory as it may be disconnected.
	 */
	if (new_memscrub(1)) {	/* update page retire list */
		disable_memscrub = 1;
	}

	/* Restore the pause setting. */
	atomic_dec_32(&pause_memscrub);
}

static kphysm_setup_vector_t memscrub_mem_config_vec = {
	KPHYSM_SETUP_VECTOR_VERSION,
	memscrub_mem_config_post_add,
	memscrub_mem_config_pre_del,
	memscrub_mem_config_post_del,
};

static void
memscrub_init_mem_config()
{
	int ret;

	ret = kphysm_setup_func_register(&memscrub_mem_config_vec,
	    (void *)NULL);
	ASSERT(ret == 0);
}

static void
memscrub_uninit_mem_config()
{
	/* This call is OK if the register call was not done. */
	kphysm_setup_func_unregister(&memscrub_mem_config_vec, (void *)NULL);
}
