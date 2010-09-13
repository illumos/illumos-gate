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
 * i86pc Memory Scrubbing
 *
 * On detection of a correctable memory ECC error, the i86pc hardware
 * returns the corrected data to the requester and may re-write it
 * to memory (DRAM or NVRAM). Machines which do not re-write this to
 * memory should add an NMI handler to correct and rewrite.
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
 * memscrub_span_pages (4MB) on each wakeup, it will read all of physical
 * memory in in memscrub_period_sec (12 hours).
 *
 * The scrubber uses the REP LODS so it reads 4MB in 0.15 secs (on P5-200).
 * When it completes a span, if all the CPUs are idle, it reads another span.
 * Typically it soaks up idle time this way to reach its deadline early
 * -- and sleeps until the next period begins.
 *
 * Maximal Cost Estimate:  8GB @ xxMB/s = xxx seconds spent in 640 wakeups
 * that run for 0.15 seconds at intervals of 67 seconds.
 *
 * In practice, the scrubber finds enough idle time to finish in a few
 * minutes, and sleeps until its 12 hour deadline.
 *
 * The scrubber maintains a private copy of the phys_install memory list
 * to keep track of what memory should be scrubbed.
 *
 * The following parameters can be set via /etc/system
 *
 * memscrub_span_pages = MEMSCRUB_DFL_SPAN_PAGES (4MB)
 * memscrub_period_sec = MEMSCRUB_DFL_PERIOD_SEC (12 hours)
 * memscrub_thread_pri = MEMSCRUB_DFL_THREAD_PRI (0)
 * memscrub_delay_start_sec = (10 seconds)
 * disable_memscrub = (0)
 *
 * the scrubber will exit (or never be started) if it finds the variable
 * "disable_memscrub" set.
 *
 * MEMSCRUB_DFL_SPAN_PAGES  is based on the guess that 0.15 sec
 * is a "good" amount of minimum time for the thread to run at a time.
 *
 * MEMSCRUB_DFL_PERIOD_SEC (12 hours) is nearly a total guess --
 * twice the frequency the hardware folk estimated would be necessary.
 *
 * MEMSCRUB_DFL_THREAD_PRI (0) is based on the assumption that nearly
 * any other use of the system should be higher priority than scrubbing.
 */

#include <sys/types.h>
#include <sys/systm.h>		/* timeout, types, t_lock */
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>	/* MIN */
#include <sys/memlist.h>	/* memlist */
#include <sys/kmem.h>		/* KMEM_NOSLEEP */
#include <sys/cpuvar.h>		/* ncpus_online */
#include <sys/debug.h>		/* ASSERTs */
#include <sys/vmem.h>
#include <sys/mman.h>
#include <vm/seg_kmem.h>
#include <vm/seg_kpm.h>
#include <vm/hat_i86.h>
#include <sys/callb.h>		/* CPR callback */

static caddr_t	memscrub_window;
static hat_mempte_t memscrub_pte;

/*
 * Global Data:
 */
/*
 * scan all of physical memory at least once every MEMSCRUB_PERIOD_SEC
 */
#define	MEMSCRUB_DFL_PERIOD_SEC	(12 * 60 * 60)	/* 12 hours */

/*
 * start only if at least MEMSCRUB_MIN_PAGES in system
 */
#define	MEMSCRUB_MIN_PAGES	((32 * 1024 * 1024) / PAGESIZE)

/*
 * scan at least MEMSCRUB_DFL_SPAN_PAGES each iteration
 */
#define	MEMSCRUB_DFL_SPAN_PAGES	((4 * 1024 * 1024) / PAGESIZE)

/*
 * almost anything is higher priority than scrubbing
 */
#define	MEMSCRUB_DFL_THREAD_PRI	0

/*
 * we can patch these defaults in /etc/system if necessary
 */
uint_t disable_memscrub = 0;
static uint_t disable_memscrub_quietly = 0;
pgcnt_t memscrub_min_pages = MEMSCRUB_MIN_PAGES;
pgcnt_t memscrub_span_pages = MEMSCRUB_DFL_SPAN_PAGES;
time_t memscrub_period_sec = MEMSCRUB_DFL_PERIOD_SEC;
uint_t memscrub_thread_pri = MEMSCRUB_DFL_THREAD_PRI;
time_t memscrub_delay_start_sec = 10;

/*
 * Static Routines
 */
static void memscrubber(void);
static int system_is_idle(void);
static int memscrub_add_span(uint64_t, uint64_t);

/*
 * Static Data
 */
static struct memlist *memscrub_memlist;
static uint_t memscrub_phys_pages;

static kcondvar_t memscrub_cv;
static kmutex_t memscrub_lock;

/*
 * memscrub_lock protects memscrub_memlist
 */
uint_t memscrub_scans_done;

uint_t memscrub_done_early;
uint_t memscrub_early_sec;

uint_t memscrub_done_late;
time_t memscrub_late_sec;

/*
 * create memscrub_memlist from phys_install list
 * initialize locks, set memscrub_phys_pages.
 */
void
memscrub_init()
{
	struct memlist *src;

	if (physmem < memscrub_min_pages)
		return;

	if (!kpm_enable) {
		memscrub_window = vmem_alloc(heap_arena, PAGESIZE, VM_SLEEP);
		memscrub_pte = hat_mempte_setup(memscrub_window);
	}

	/*
	 * copy phys_install to memscrub_memlist
	 */
	for (src = phys_install; src; src = src->ml_next) {
		if (memscrub_add_span(src->ml_address, src->ml_size)) {
			cmn_err(CE_WARN,
			    "Software memory scrubber failed to initialize\n");
			return;
		}
	}

	mutex_init(&memscrub_lock, NULL, MUTEX_DRIVER, NULL);
	cv_init(&memscrub_cv, NULL, CV_DRIVER, NULL);

	/*
	 * create memscrubber thread
	 */
	(void) thread_create(NULL, 0, (void (*)())memscrubber, NULL, 0, &p0,
	    TS_RUN, memscrub_thread_pri);
}

/*
 * Function to cause the software memscrubber to exit quietly if the
 * platform support has located a hardware scrubber and enabled it.
 */
void
memscrub_disable(void)
{
	disable_memscrub_quietly = 1;
}

#ifdef MEMSCRUB_DEBUG
static void
memscrub_printmemlist(char *title, struct memlist *listp)
{
	struct memlist *list;

	cmn_err(CE_CONT, "%s:\n", title);

	for (list = listp; list; list = list->next) {
		cmn_err(CE_CONT, "addr = 0x%llx, size = 0x%llx\n",
		    list->address, list->size);
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
 * this calculation doesn't account for the time that the actual scan
 * consumes -- so we'd fall slightly behind schedule with this
 * interval_sec.  but the idle loop optimization below usually makes us
 * come in way ahead of schedule.
 */
static int
compute_interval_sec()
{
	if (memscrub_phys_pages <= memscrub_span_pages)
		return (memscrub_period_sec);
	else
		return (memscrub_period_sec/
		    (memscrub_phys_pages/memscrub_span_pages));
}

static void
memscrubber()
{
	time_t deadline;
	uint64_t mlp_last_addr;
	uint64_t mlp_next_addr;
	int reached_end = 1;
	time_t interval_sec = 0;
	struct memlist *mlp;

	extern void scan_memory(caddr_t, size_t);
	callb_cpr_t cprinfo;

	/*
	 * notify CPR of our existence
	 */
	CALLB_CPR_INIT(&cprinfo, &memscrub_lock, callb_generic_cpr, "memscrub");

	if (memscrub_memlist == NULL) {
		cmn_err(CE_WARN, "memscrub_memlist not initialized.");
		goto memscrub_exit;
	}

	mlp = memscrub_memlist;
	mlp_next_addr = mlp->ml_address;
	mlp_last_addr = mlp->ml_address + mlp->ml_size;

	deadline = gethrestime_sec() + memscrub_delay_start_sec;

	for (;;) {
		if (disable_memscrub || disable_memscrub_quietly)
			break;

		mutex_enter(&memscrub_lock);

		/*
		 * did we just reach the end of memory?
		 */
		if (reached_end) {
			time_t now = gethrestime_sec();

			if (now >= deadline) {
				memscrub_done_late++;
				memscrub_late_sec += (now - deadline);
				/*
				 * past deadline, start right away
				 */
				interval_sec = 0;

				deadline = now + memscrub_period_sec;
			} else {
				/*
				 * we finished ahead of schedule.
				 * wait till previous dealine before re-start.
				 */
				interval_sec = deadline - now;
				memscrub_done_early++;
				memscrub_early_sec += interval_sec;
				deadline += memscrub_period_sec;
			}
		} else {
			interval_sec = compute_interval_sec();
		}

		/*
		 * it is safe from our standpoint for CPR to
		 * suspend the system
		 */
		CALLB_CPR_SAFE_BEGIN(&cprinfo);

		/*
		 * hit the snooze bar
		 */
		(void) timeout(memscrub_wakeup, NULL, interval_sec * hz);

		/*
		 * go to sleep
		 */
		cv_wait(&memscrub_cv, &memscrub_lock);

		/* we need to goto work */
		CALLB_CPR_SAFE_END(&cprinfo, &memscrub_lock);

		mutex_exit(&memscrub_lock);

		do {
			pgcnt_t pages = memscrub_span_pages;
			uint64_t address = mlp_next_addr;

			if (disable_memscrub || disable_memscrub_quietly)
				break;

			mutex_enter(&memscrub_lock);

			/*
			 * Make sure we don't try to scan beyond the end of
			 * the current memlist.  If we would, then resize
			 * our scan target for this iteration, and prepare
			 * to read the next memlist entry on the next
			 * iteration.
			 */
			reached_end = 0;
			if (address + mmu_ptob(pages) >= mlp_last_addr) {
				pages = mmu_btop(mlp_last_addr - address);
				mlp = mlp->ml_next;
				if (mlp == NULL) {
					reached_end = 1;
					mlp = memscrub_memlist;
				}
				mlp_next_addr = mlp->ml_address;
				mlp_last_addr = mlp->ml_address + mlp->ml_size;
			} else {
				mlp_next_addr += mmu_ptob(pages);
			}

			mutex_exit(&memscrub_lock);

			while (pages--) {
				pfn_t pfn = btop(address);

				/*
				 * Without segkpm, the memscrubber cannot
				 * be allowed to migrate across CPUs, as
				 * the CPU-specific mapping of
				 * memscrub_window would be incorrect.
				 * With segkpm, switching CPUs is legal, but
				 * inefficient.  We don't use
				 * kpreempt_disable as it might hold a
				 * higher priority thread (eg, RT) too long
				 * off CPU.
				 */
				thread_affinity_set(curthread, CPU_CURRENT);
				if (kpm_enable)
					memscrub_window = hat_kpm_pfn2va(pfn);
				else
					hat_mempte_remap(pfn, memscrub_window,
					    memscrub_pte,
					    PROT_READ, HAT_LOAD_NOCONSIST);

				scan_memory(memscrub_window, PAGESIZE);

				thread_affinity_clear(curthread);
				address += MMU_PAGESIZE;
			}

			memscrub_scans_done++;
		} while (!reached_end && system_is_idle());
	}

memscrub_exit:

	if (!disable_memscrub_quietly)
		cmn_err(CE_NOTE, "Software memory scrubber exiting.");
	/*
	 * We are about to bail, but don't have the memscrub_lock,
	 * and it is needed for CALLB_CPR_EXIT.
	 */
	mutex_enter(&memscrub_lock);
	CALLB_CPR_EXIT(&cprinfo);

	cv_destroy(&memscrub_cv);

	thread_exit();
}


/*
 * return 1 if we're MP and all the other CPUs are idle
 */
static int
system_is_idle()
{
	int cpu_id;
	int found = 0;

	if (1 == ncpus_online)
		return (0);

	for (cpu_id = 0; cpu_id < NCPU; ++cpu_id) {
		if (!cpu[cpu_id])
			continue;

		found++;

		if (cpu[cpu_id]->cpu_thread != cpu[cpu_id]->cpu_idle_thread) {
			if (CPU->cpu_id == cpu_id &&
			    CPU->cpu_disp->disp_nrunnable == 0)
				continue;
			return (0);
		}

		if (found == ncpus)
			break;
	}
	return (1);
}

/*
 * add a span to the memscrub list
 */
static int
memscrub_add_span(uint64_t start, uint64_t bytes)
{
	struct memlist *dst;
	struct memlist *prev, *next;
	uint64_t end = start + bytes - 1;
	int retval = 0;

	mutex_enter(&memscrub_lock);

#ifdef MEMSCRUB_DEBUG
	memscrub_printmemlist("memscrub_memlist before", memscrub_memlist);
	cmn_err(CE_CONT, "memscrub_phys_pages: 0x%x\n", memscrub_phys_pages);
	cmn_err(CE_CONT, "memscrub_add_span: address: 0x%llx"
	    " size: 0x%llx\n", start, bytes);
#endif /* MEMSCRUB_DEBUG */

	/*
	 * Scan through the list to find the proper place to install it.
	 */
	prev = NULL;
	next = memscrub_memlist;
	while (next) {
		uint64_t ns = next->ml_address;
		uint64_t ne = next->ml_address + next->ml_size - 1;

		/*
		 * If this span overlaps with an existing span, then
		 * something has gone horribly wrong with the phys_install
		 * list.  In fact, I'm surprised we made it this far.
		 */
		if ((start >= ns && start <= ne) || (end >= ns && end <= ne) ||
		    (start < ns && end > ne))
			panic("memscrub found overlapping memory ranges "
			    "(0x%p-0x%p) and (0x%p-0x%p)",
			    (void *)(uintptr_t)start, (void *)(uintptr_t)end,
			    (void *)(uintptr_t)ns, (void *)(uintptr_t)ne);

		/*
		 * New span can be appended to an existing one.
		 */
		if (start == ne + 1) {
			next->ml_size += bytes;
			goto add_done;
		}

		/*
		 * New span can be prepended to an existing one.
		 */
		if (end + 1 == ns) {
			next->ml_size += bytes;
			next->ml_address = start;
			goto add_done;
		}

		/*
		 * If the next span has a higher start address than the new
		 * one, then we have found the right spot for our
		 * insertion.
		 */
		if (ns > start)
			break;

		prev = next;
		next = next->ml_next;
	}

	/*
	 * allocate a new struct memlist
	 */
	dst = kmem_alloc(sizeof (struct memlist), KM_NOSLEEP);
	if (dst == NULL) {
		retval = -1;
		goto add_done;
	}
	dst->ml_address = start;
	dst->ml_size = bytes;
	dst->ml_prev = prev;
	dst->ml_next = next;

	if (prev)
		prev->ml_next = dst;
	else
		memscrub_memlist = dst;

	if (next)
		next->ml_prev = dst;

add_done:

	if (retval != -1)
		memscrub_phys_pages += mmu_btop(bytes);

#ifdef MEMSCRUB_DEBUG
	memscrub_printmemlist("memscrub_memlist after", memscrub_memlist);
	cmn_err(CE_CONT, "memscrub_phys_pages: 0x%x\n", memscrub_phys_pages);
#endif /* MEMSCRUB_DEBUG */

	mutex_exit(&memscrub_lock);
	return (retval);
}
