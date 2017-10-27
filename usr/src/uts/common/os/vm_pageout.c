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
 * Copyright 2017 Joyent, Inc.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#include <sys/types.h>
#include <sys/t_lock.h>
#include <sys/param.h>
#include <sys/buf.h>
#include <sys/uio.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/mman.h>
#include <sys/cred.h>
#include <sys/vnode.h>
#include <sys/vm.h>
#include <sys/vmparam.h>
#include <sys/vtrace.h>
#include <sys/cmn_err.h>
#include <sys/cpuvar.h>
#include <sys/user.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/callb.h>
#include <sys/tnf_probe.h>
#include <sys/mem_cage.h>
#include <sys/time.h>
#include <sys/zone.h>

#include <vm/hat.h>
#include <vm/as.h>
#include <vm/seg.h>
#include <vm/page.h>
#include <vm/pvn.h>
#include <vm/seg_kmem.h>

static int checkpage(page_t *, int);

/*
 * The following parameters control operation of the page replacement
 * algorithm.  They are initialized to 0, and then computed at boot time
 * based on the size of the system.  If they are patched non-zero in
 * a loaded vmunix they are left alone and may thus be changed per system
 * using mdb on the loaded system.
 */
pgcnt_t		slowscan = 0;
pgcnt_t		fastscan = 0;

static pgcnt_t	handspreadpages = 0;
static int	loopfraction = 2;
static pgcnt_t	looppages;
/* See comment below describing 4% and 80% */
static int	min_percent_cpu = 4;
static int	max_percent_cpu = 80;
static pgcnt_t	maxfastscan = 0;
static pgcnt_t	maxslowscan = 100;

pgcnt_t	maxpgio = 0;
pgcnt_t	minfree = 0;
pgcnt_t	desfree = 0;
pgcnt_t	lotsfree = 0;
pgcnt_t	needfree = 0;
pgcnt_t	throttlefree = 0;
pgcnt_t	pageout_reserve = 0;

pgcnt_t	deficit;
pgcnt_t	nscan;
pgcnt_t	desscan;

uint64_t zone_cap_scan;
clock_t	zone_pageout_ticks;	/* tunable to change zone pagescan ticks */

/*
 * Values for min_pageout_ticks, max_pageout_ticks and pageout_ticks
 * are the number of ticks in each wakeup cycle that gives the
 * equivalent of some underlying %CPU duty cycle.
 *
 * For example, when RATETOSCHEDPAGING is 4 (the default), then schedpaging()
 * will run 4 times/sec to update pageout scanning parameters and kickoff
 * the pageout_scanner() thread if necessary.
 *
 * Given hz is 100, min_pageout_ticks will be set to 1 (1% of a CPU). When
 * pageout_ticks is set to min_pageout_ticks, then the total CPU time consumed
 * by the scanner in a 1 second interval is 4% of a CPU (RATETOSCHEDPAGING * 1).
 *
 * Given hz is 100, max_pageout_ticks will be set to 20 (20% of a CPU). When
 * pageout_ticks is set to max_pageout_ticks, then the total CPU time consumed
 * by the scanner in a 1 second interval is 80% of a CPU
 * (RATETOSCHEDPAGING * 20). There is no point making max_pageout_ticks >25
 * since schedpaging() runs RATETOSCHEDPAGING (4) times/sec.
 *
 * If hz is 1000, then min_pageout_ticks will be 10 and max_pageout_ticks
 * will be 200, so the CPU percentages are the same as when hz is 100.
 *
 * min_pageout_ticks:
 *     ticks/wakeup equivalent of min_percent_cpu.
 *
 * max_pageout_ticks:
 *     ticks/wakeup equivalent of max_percent_cpu.
 *
 * pageout_ticks:
 *     Number of clock ticks budgeted for each wakeup cycle.
 *     Computed each time around by schedpaging().
 *     Varies between min_pageout_ticks .. max_pageout_ticks,
 *     depending on memory pressure or zones over their cap.
 *
 * pageout_lbolt:
 *     Timestamp of the last time pageout_scanner woke up and started
 *     (or resumed) scanning for not recently referenced pages.
 */

static clock_t	min_pageout_ticks;
static clock_t	max_pageout_ticks;
static clock_t	pageout_ticks;
static clock_t	pageout_lbolt;

static uint_t	reset_hands;

#define	PAGES_POLL_MASK	1023

/*
 * pageout_sample_lim:
 *     The limit on the number of samples needed to establish a value
 *     for new pageout parameters, fastscan, slowscan, and handspreadpages.
 *
 * pageout_sample_cnt:
 *     Current sample number.  Once the sample gets large enough,
 *     set new values for handspreadpages, fastscan and slowscan.
 *
 * pageout_sample_pages:
 *     The accumulated number of pages scanned during sampling.
 *
 * pageout_sample_etime:
 *     The accumulated number of nanoseconds for the sample.
 *
 * pageout_rate:
 *     Rate in pages/second, computed at the end of sampling.
 *
 * pageout_new_spread:
 *     The new value to use for maxfastscan and (perhaps) handspreadpages.
 *     Intended to be the number pages that can be scanned per sec using ~10%
 *     of a CPU. Calculated after enough samples have been taken.
 *     pageout_rate / 10
 */

typedef hrtime_t hrrate_t;

static uint_t	pageout_sample_lim = 4;
static uint_t	pageout_sample_cnt = 0;
static pgcnt_t	pageout_sample_pages = 0;
static hrrate_t	pageout_rate = 0;
static pgcnt_t	pageout_new_spread = 0;

static clock_t	pageout_cycle_ticks;
static hrtime_t	sample_start, sample_end;
static hrtime_t	pageout_sample_etime = 0;

/* True if page scanner is first starting up */
#define	PAGE_SCAN_STARTUP	(pageout_sample_cnt < pageout_sample_lim)

/*
 * Record number of times a pageout_scanner wakeup cycle finished because it
 * timed out (exceeded its CPU budget), rather than because it visited
 * its budgeted number of pages. This is only done when scanning under low
 * free memory conditions, not when scanning for zones over their cap.
 */
uint64_t pageout_timeouts = 0;

#ifdef VM_STATS
static struct pageoutvmstats_str {
	ulong_t	checkpage[3];
} pageoutvmstats;
#endif /* VM_STATS */

/*
 * Threads waiting for free memory use this condition variable and lock until
 * memory becomes available.
 */
kmutex_t	memavail_lock;
kcondvar_t	memavail_cv;

/*
 * The size of the clock loop.
 */
#define	LOOPPAGES	total_pages

/*
 * Local boolean to control scanning when zones are over their cap. Avoids
 * accessing the zone_num_over_cap variable except within schedpaging(), which
 * only runs periodically. This is here only to reduce our access to
 * zone_num_over_cap, since it is already accessed a lot during paging, and
 * the page scanner accesses the zones_over variable on each page during a
 * scan. There is no lock needed for zone_num_over_cap since schedpaging()
 * doesn't modify the variable, it only cares if the variable is 0 or non-0.
 */
static boolean_t zones_over = B_FALSE;

/*
 * Set up the paging constants for the page scanner clock-hand algorithm.
 * Called at startup after the system is initialized and the amount of memory
 * and number of paging devices is known. Called again once PAGE_SCAN_STARTUP
 * is true after the scanner has collected enough samples.
 *
 * Will also be called after a memory dynamic reconfiguration operation.
 *
 * lotsfree is 1/64 of memory, but at least 512K (ha!).
 * desfree is 1/2 of lotsfree.
 * minfree is 1/2 of desfree.
 */
void
setupclock(int recalc)
{

	static spgcnt_t init_lfree, init_dfree, init_mfree;
	static spgcnt_t init_tfree, init_preserve, init_mpgio;
	static spgcnt_t init_mfscan, init_fscan, init_sscan, init_hspages;

	looppages = LOOPPAGES;

	/*
	 * setupclock can be called to recalculate the paging
	 * parameters in the case of dynamic reconfiguration of memory.
	 * So to make sure we make the proper calculations, if such a
	 * situation should arise, we save away the initial values
	 * of each parameter so we can recall them when needed. This
	 * way we don't lose the settings an admin might have made
	 * through the /etc/system file.
	 */

	if (!recalc) {
		init_lfree = lotsfree;
		init_dfree = desfree;
		init_mfree = minfree;
		init_tfree = throttlefree;
		init_preserve = pageout_reserve;
		init_mpgio = maxpgio;
		init_mfscan = maxfastscan;
		init_fscan = fastscan;
		init_sscan = slowscan;
		init_hspages = handspreadpages;
	}

	/*
	 * Set up thresholds for paging:
	 */

	/*
	 * Lotsfree is threshold where paging daemon turns on.
	 */
	if (init_lfree == 0 || init_lfree >= looppages)
		lotsfree = MAX(looppages / 64, btop(512 * 1024));
	else
		lotsfree = init_lfree;

	/*
	 * Desfree is amount of memory desired free.
	 * If less than this for extended period, start swapping.
	 */
	if (init_dfree == 0 || init_dfree >= lotsfree)
		desfree = lotsfree / 2;
	else
		desfree = init_dfree;

	/*
	 * Minfree is minimal amount of free memory which is tolerable.
	 */
	if (init_mfree == 0 || init_mfree >= desfree)
		minfree = desfree / 2;
	else
		minfree = init_mfree;

	/*
	 * Throttlefree is the point at which we start throttling
	 * PG_WAIT requests until enough memory becomes available.
	 */
	if (init_tfree == 0 || init_tfree >= desfree)
		throttlefree = minfree;
	else
		throttlefree = init_tfree;

	/*
	 * Pageout_reserve is the number of pages that we keep in
	 * stock for pageout's own use.  Having a few such pages
	 * provides insurance against system deadlock due to
	 * pageout needing pages.  When freemem < pageout_reserve,
	 * non-blocking allocations are denied to any threads
	 * other than pageout and sched.  (At some point we might
	 * want to consider a per-thread flag like T_PUSHING_PAGES
	 * to indicate that a thread is part of the page-pushing
	 * dance (e.g. an interrupt thread) and thus is entitled
	 * to the same special dispensation we accord pageout.)
	 */
	if (init_preserve == 0 || init_preserve >= throttlefree)
		pageout_reserve = throttlefree / 2;
	else
		pageout_reserve = init_preserve;

	/*
	 * Maxpgio thresholds how much paging is acceptable.
	 * This figures that 2/3 busy on an arm is all that is
	 * tolerable for paging.  We assume one operation per disk rev.
	 *
	 * XXX - Does not account for multiple swap devices.
	 */
	if (init_mpgio == 0)
		maxpgio = (DISKRPM * 2) / 3;
	else
		maxpgio = init_mpgio;

	/*
	 * When the system is in a low memory state, the page scan rate varies
	 * between fastscan and slowscan based on the amount of free memory
	 * available. When only zones are over their memory cap, the scan rate
	 * is always fastscan.
	 *
	 * The fastscan rate should be set based on the number pages that can
	 * be scanned per sec using ~10% of a CPU. Since this value depends on
	 * the processor, MMU, Ghz etc., it must be determined dynamically.
	 *
	 * When the scanner first starts up, fastscan will be set to 0 and
	 * maxfastscan will be set to MAXHANDSPREADPAGES (64MB, in pages).
	 * However, once the scanner has collected enough samples, then fastscan
	 * is set to be the smaller of 1/2 of memory (looppages / loopfraction)
	 * or maxfastscan (which is set from pageout_new_spread). Thus,
	 * MAXHANDSPREADPAGES is irrelevant after the scanner is fully
	 * initialized.
	 *
	 * pageout_new_spread is calculated when the scanner first starts
	 * running. During this initial sampling period the nscan_limit
	 * is set to the total_pages of system memory. Thus, the scanner could
	 * theoretically scan all of memory in one pass. However, each sample
	 * is also limited by the %CPU budget. This is controlled by
	 * pageout_ticks which is set in schedpaging(). During the sampling
	 * period, pageout_ticks is set to max_pageout_ticks. This tick value
	 * is derived from the max_percent_cpu (80%) described above. On a
	 * system with more than a small amount of memory (~8GB), the scanner's
	 * %CPU will be the limiting factor in calculating pageout_new_spread.
	 *
	 * At the end of the sampling period, the pageout_rate indicates how
	 * many pages could be scanned per second. The pageout_new_spread is
	 * then set to be 1/10th of that (i.e. approximating 10% of a CPU).
	 * Of course, this value could still be more than the physical memory
	 * on the system. If so, fastscan is set to 1/2 of memory, as
	 * mentioned above.
	 *
	 * All of this leads up to the setting of handspreadpages, which is
	 * set to fastscan. This is the distance, in pages, between the front
	 * and back hands during scanning. It will dictate which pages will
	 * be considered "hot" on the backhand and which pages will be "cold"
	 * and reclaimed
	 *
	 * If the scanner is limited by desscan, then at the highest rate it
	 * will scan up to fastscan/RATETOSCHEDPAGING pages per cycle. If the
	 * scanner is limited by the %CPU, then at the highest rate (20% of a
	 * CPU per cycle) the number of pages scanned could be much less.
	 *
	 * Thus, if the scanner is limited by desscan, then the handspreadpages
	 * setting means 1sec between the front and back hands, but if the
	 * scanner is limited by %CPU, it could be several seconds between the
	 * two hands.
	 *
	 * The basic assumption is that at the worst case, stealing pages
	 * not accessed within 1 sec seems reasonable and ensures that active
	 * user processes don't thrash. This is especially true when the system
	 * is in a low memory state.
	 *
	 * There are some additional factors to consider for the case of
	 * scanning when zones are over their cap. In this situation it is
	 * also likely that the machine will have a large physical memory which
	 * will take many seconds to fully scan (due to the %CPU and desscan
	 * limits per cycle). It is probable that there will be few (or 0)
	 * pages attributed to these zones in any single scanning cycle. The
	 * result is that reclaiming enough pages for these zones might take
	 * several additional seconds (this is generally not a problem since
	 * the zone physical cap is just a soft cap).
	 *
	 * This is similar to the typical multi-processor situation in which
	 * pageout is often unable to maintain the minimum paging thresholds
	 * under heavy load due to the fact that user processes running on
	 * other CPU's can be dirtying memory at a much faster pace than
	 * pageout can find pages to free.
	 *
	 * One potential approach to address both of these cases is to enable
	 * more than one CPU to run the page scanner, in such a manner that the
	 * various clock hands don't overlap. However, this also makes it more
	 * difficult to determine the values for fastscan, slowscan and
	 * handspreadpages. This is left as a future enhancement, if necessary.
	 *
	 * When free memory falls just below lotsfree, the scan rate goes from
	 * 0 to slowscan (i.e., the page scanner starts running).  This
	 * transition needs to be smooth and is achieved by ensuring that
	 * pageout scans a small number of pages to satisfy the transient
	 * memory demand.  This is set to not exceed 100 pages/sec (25 per
	 * wakeup) since scanning that many pages has no noticible impact
	 * on system performance.
	 *
	 * The swapper is currently used to free up memory when pageout is
	 * unable to meet memory demands. It does this by swapping out entire
	 * processes. In addition to freeing up memory, swapping also reduces
	 * the demand for memory because the swapped out processes cannot
	 * run, and thereby consume memory. However, this is a pathological
	 * state and performance will generally be considered unacceptable.
	 */
	if (init_mfscan == 0) {
		if (pageout_new_spread != 0)
			maxfastscan = pageout_new_spread;
		else
			maxfastscan = MAXHANDSPREADPAGES;
	} else {
		maxfastscan = init_mfscan;
	}
	if (init_fscan == 0) {
		fastscan = MIN(looppages / loopfraction, maxfastscan);
	} else {
		fastscan = init_fscan;
		if (fastscan > looppages / loopfraction)
			fastscan = looppages / loopfraction;
	}

	/*
	 * Set slow scan time to 1/10 the fast scan time, but
	 * not to exceed maxslowscan.
	 */
	if (init_sscan == 0)
		slowscan = MIN(fastscan / 10, maxslowscan);
	else
		slowscan = init_sscan;
	if (slowscan > fastscan / 2)
		slowscan = fastscan / 2;

	/*
	 * Handspreadpages is distance (in pages) between front and back
	 * pageout daemon hands.  The amount of time to reclaim a page
	 * once pageout examines it increases with this distance and
	 * decreases as the scan rate rises. It must be < the amount
	 * of pageable memory.
	 *
	 * Since pageout is limited to the %CPU per cycle, setting
	 * handspreadpages to be "fastscan" results in the front hand being
	 * a few secs (varies based on the processor speed) ahead of the back
	 * hand at fastscan rates.
	 *
	 * As a result, user processes have a much better chance of
	 * referencing their pages before the back hand examines them.
	 * This also significantly lowers the number of reclaims from
	 * the freelist since pageout does not end up freeing pages which
	 * may be referenced a sec later.
	 */
	if (init_hspages == 0)
		handspreadpages = fastscan;
	else
		handspreadpages = init_hspages;

	/*
	 * Make sure that back hand follows front hand by at least
	 * 1/RATETOSCHEDPAGING seconds.  Without this test, it is possible
	 * for the back hand to look at a page during the same wakeup of
	 * the pageout daemon in which the front hand cleared its ref bit.
	 */
	if (handspreadpages >= looppages)
		handspreadpages = looppages - 1;

	/*
	 * If we have been called to recalculate the parameters,
	 * set a flag to re-evaluate the clock hand pointers.
	 */
	if (recalc)
		reset_hands = 1;
}

/*
 * Pageout scheduling.
 *
 * Schedpaging controls the rate at which the page out daemon runs by
 * setting the global variables nscan and desscan RATETOSCHEDPAGING
 * times a second.  Nscan records the number of pages pageout has examined
 * in its current pass; schedpaging resets this value to zero each time
 * it runs.  Desscan records the number of pages pageout should examine
 * in its next pass; schedpaging sets this value based on the amount of
 * currently available memory.
 */

#define	RATETOSCHEDPAGING	4		/* times/second */

/* held while pageout_scanner or schedpaging running */
static kmutex_t	pageout_mutex;

/*
 * Pool of available async pageout putpage requests.
 */
static struct async_reqs *push_req;
static struct async_reqs *req_freelist;	/* available req structs */
static struct async_reqs *push_list;	/* pending reqs */
static kmutex_t push_lock;		/* protects req pool */
static kcondvar_t push_cv;

static int async_list_size = 256;	/* number of async request structs */

static void pageout_scanner(void);

/*
 * If a page is being shared more than "po_share" times
 * then leave it alone- don't page it out.
 */
#define	MIN_PO_SHARE	(8)
#define	MAX_PO_SHARE	((MIN_PO_SHARE) << 24)
ulong_t	po_share = MIN_PO_SHARE;

/*
 * Schedule rate for paging.
 * Rate is linear interpolation between
 * slowscan with lotsfree and fastscan when out of memory.
 */
static void
schedpaging(void *arg)
{
	spgcnt_t vavail;

	if (freemem < lotsfree + needfree + kmem_reapahead)
		kmem_reap();

	if (freemem < lotsfree + needfree)
		seg_preap();

	if (kcage_on && (kcage_freemem < kcage_desfree || kcage_needfree))
		kcage_cageout_wakeup();

	if (mutex_tryenter(&pageout_mutex)) {
		/* pageout_scanner() is not currently running */
		nscan = 0;
		vavail = freemem - deficit;
		if (pageout_new_spread != 0)
			vavail -= needfree;
		if (vavail < 0)
			vavail = 0;
		if (vavail > lotsfree)
			vavail = lotsfree;

		/*
		 * Fix for 1161438 (CRS SPR# 73922).  All variables
		 * in the original calculation for desscan were 32 bit signed
		 * ints.  As freemem approaches 0x0 on a system with 1 Gig or
		 * more of memory, the calculation can overflow.  When this
		 * happens, desscan becomes negative and pageout_scanner()
		 * stops paging out.
		 */
		if ((needfree) && (pageout_new_spread == 0)) {
			/*
			 * If we've not yet collected enough samples to
			 * calculate a spread, kick into high gear anytime
			 * needfree is non-zero. Note that desscan will not be
			 * the limiting factor for systems with larger memory;
			 * the %CPU will limit the scan. That will also be
			 * maxed out below.
			 */
			desscan = fastscan / RATETOSCHEDPAGING;
		} else {
			/*
			 * Once we've calculated a spread based on system
			 * memory and usage, just treat needfree as another
			 * form of deficit.
			 */
			spgcnt_t faststmp, slowstmp, result;

			slowstmp = slowscan * vavail;
			faststmp = fastscan * (lotsfree - vavail);
			result = (slowstmp + faststmp) /
			    nz(lotsfree) / RATETOSCHEDPAGING;
			desscan = (pgcnt_t)result;
		}

		/*
		 * If we've not yet collected enough samples to calculate a
		 * spread, also kick %CPU to the max.
		 */
		if (pageout_new_spread == 0) {
			pageout_ticks = max_pageout_ticks;
		} else {
			pageout_ticks = min_pageout_ticks +
			    (lotsfree - vavail) *
			    (max_pageout_ticks - min_pageout_ticks) /
			    nz(lotsfree);
		}
		zones_over = B_FALSE;

		if (freemem < lotsfree + needfree || PAGE_SCAN_STARTUP) {
			DTRACE_PROBE(schedpage__wake__low);
			cv_signal(&proc_pageout->p_cv);

		} else if (zone_num_over_cap > 0) {
			/* One or more zones are over their cap. */

			/* No page limit */
			desscan = total_pages;

			/*
			 * Increase the scanning CPU% to the max. This implies
			 * 80% of one CPU/sec if the scanner can run each
			 * opportunity. Can also be tuned via setting
			 * zone_pageout_ticks in /etc/system or with mdb.
			 */
			pageout_ticks = (zone_pageout_ticks != 0) ?
			    zone_pageout_ticks : max_pageout_ticks;

			zones_over = B_TRUE;
			zone_cap_scan++;

			DTRACE_PROBE(schedpage__wake__zone);
			cv_signal(&proc_pageout->p_cv);

		} else {
			/*
			 * There are enough free pages, no need to
			 * kick the scanner thread.  And next time
			 * around, keep more of the `highly shared'
			 * pages.
			 */
			cv_signal_pageout();
			if (po_share > MIN_PO_SHARE) {
				po_share >>= 1;
			}
		}
		mutex_exit(&pageout_mutex);
	}

	/*
	 * Signal threads waiting for available memory.
	 * NOTE: usually we need to grab memavail_lock before cv_broadcast, but
	 * in this case it is not needed - the waiters will be waken up during
	 * the next invocation of this function.
	 */
	if (kmem_avail() > 0)
		cv_broadcast(&memavail_cv);

	(void) timeout(schedpaging, arg, hz / RATETOSCHEDPAGING);
}

pgcnt_t		pushes;
ulong_t		push_list_size;		/* # of requests on pageout queue */

#define	FRONT	1
#define	BACK	2

int dopageout = 1;	/* /etc/system tunable to disable page reclamation */

/*
 * The page out daemon, which runs as process 2.
 *
 * Page out occurs when either:
 * a) there is less than lotsfree pages,
 * b) there are one or more zones over their physical memory cap.
 *
 * The daemon treats physical memory as a circular array of pages and scans the
 * pages using a 'two-handed clock' algorithm. The front hand moves through
 * the pages, clearing the reference bit. The back hand travels a distance
 * (handspreadpages) behind the front hand, freeing the pages that have not
 * been referenced in the time since the front hand passed. If modified, they
 * are first written to their backing store before being freed.
 *
 * As long as there are at least lotsfree pages, or no zones over their cap,
 * then this process is not run. When the scanner is running for case (a),
 * all pages are considered for pageout. For case (b), only pages belonging to
 * a zone over its cap will be considered for pageout.
 *
 * There are 2 threads that act on behalf of the pageout process.
 * One thread scans pages (pageout_scanner) and frees them up if
 * they don't require any VOP_PUTPAGE operation. If a page must be
 * written back to its backing store, the request is put on a list
 * and the other (pageout) thread is signaled. The pageout thread
 * grabs VOP_PUTPAGE requests from the list, and processes them.
 * Some filesystems may require resources for the VOP_PUTPAGE
 * operations (like memory) and hence can block the pageout
 * thread, but the scanner thread can still operate. There is still
 * no guarantee that memory deadlocks cannot occur.
 *
 * The pageout_scanner parameters are determined in schedpaging().
 */
void
pageout()
{
	struct async_reqs *arg;
	pri_t pageout_pri;
	int i;
	pgcnt_t max_pushes;
	callb_cpr_t cprinfo;

	proc_pageout = ttoproc(curthread);
	proc_pageout->p_cstime = 0;
	proc_pageout->p_stime =  0;
	proc_pageout->p_cutime =  0;
	proc_pageout->p_utime = 0;
	bcopy("pageout", PTOU(curproc)->u_psargs, 8);
	bcopy("pageout", PTOU(curproc)->u_comm, 7);

	/*
	 * Create pageout scanner thread
	 */
	mutex_init(&pageout_mutex, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&push_lock, NULL, MUTEX_DEFAULT, NULL);

	/*
	 * Allocate and initialize the async request structures
	 * for pageout.
	 */
	push_req = (struct async_reqs *)
	    kmem_zalloc(async_list_size * sizeof (struct async_reqs), KM_SLEEP);

	req_freelist = push_req;
	for (i = 0; i < async_list_size - 1; i++)
		push_req[i].a_next = &push_req[i + 1];

	pageout_pri = curthread->t_pri;

	/* Create the pageout scanner thread. */
	(void) lwp_kernel_create(proc_pageout, pageout_scanner, NULL, TS_RUN,
	    pageout_pri - 1);

	/*
	 * kick off pageout scheduler.
	 */
	schedpaging(NULL);

	/*
	 * Create kernel cage thread.
	 * The kernel cage thread is started under the pageout process
	 * to take advantage of the less restricted page allocation
	 * in page_create_throttle().
	 */
	kcage_cageout_init();

	/*
	 * Limit pushes to avoid saturating pageout devices.
	 */
	max_pushes = maxpgio / RATETOSCHEDPAGING;
	CALLB_CPR_INIT(&cprinfo, &push_lock, callb_generic_cpr, "pageout");

	for (;;) {
		mutex_enter(&push_lock);

		while ((arg = push_list) == NULL || pushes > max_pushes) {
			CALLB_CPR_SAFE_BEGIN(&cprinfo);
			cv_wait(&push_cv, &push_lock);
			pushes = 0;
			CALLB_CPR_SAFE_END(&cprinfo, &push_lock);
		}
		push_list = arg->a_next;
		arg->a_next = NULL;
		mutex_exit(&push_lock);

		DTRACE_PROBE(pageout__push);
		if (VOP_PUTPAGE(arg->a_vp, (offset_t)arg->a_off,
		    arg->a_len, arg->a_flags, arg->a_cred, NULL) == 0) {
			pushes++;
		}

		/* vp held by checkpage() */
		VN_RELE(arg->a_vp);

		mutex_enter(&push_lock);
		arg->a_next = req_freelist;	/* back on freelist */
		req_freelist = arg;
		push_list_size--;
		mutex_exit(&push_lock);
	}
}

/*
 * Kernel thread that scans pages looking for ones to free
 */
static void
pageout_scanner(void)
{
	struct page *fronthand, *backhand;
	uint_t count;
	callb_cpr_t cprinfo;
	pgcnt_t	nscan_limit;
	pgcnt_t	pcount;

	CALLB_CPR_INIT(&cprinfo, &pageout_mutex, callb_generic_cpr, "poscan");
	mutex_enter(&pageout_mutex);

	/*
	 * The restart case does not attempt to point the hands at roughly
	 * the right point on the assumption that after one circuit things
	 * will have settled down - and restarts shouldn't be that often.
	 */

	/*
	 * Set the two clock hands to be separated by a reasonable amount,
	 * but no more than 360 degrees apart.
	 */
	backhand = page_first();
	if (handspreadpages >= total_pages)
		fronthand = page_nextn(backhand, total_pages - 1);
	else
		fronthand = page_nextn(backhand, handspreadpages);

	min_pageout_ticks = MAX(1,
	    ((hz * min_percent_cpu) / 100) / RATETOSCHEDPAGING);
	max_pageout_ticks = MAX(min_pageout_ticks,
	    ((hz * max_percent_cpu) / 100) / RATETOSCHEDPAGING);

loop:
	cv_signal_pageout();

	CALLB_CPR_SAFE_BEGIN(&cprinfo);
	cv_wait(&proc_pageout->p_cv, &pageout_mutex);
	CALLB_CPR_SAFE_END(&cprinfo, &pageout_mutex);

	if (!dopageout)
		goto loop;

	if (reset_hands) {
		reset_hands = 0;

		backhand = page_first();
		if (handspreadpages >= total_pages)
			fronthand = page_nextn(backhand, total_pages - 1);
		else
			fronthand = page_nextn(backhand, handspreadpages);
	}

	CPU_STATS_ADDQ(CPU, vm, pgrrun, 1);
	count = 0;

	/* Kernel probe */
	TNF_PROBE_2(pageout_scan_start, "vm pagedaemon", /* CSTYLED */,
	    tnf_ulong, pages_free, freemem, tnf_ulong, pages_needed, needfree);

	pcount = 0;
	if (PAGE_SCAN_STARTUP) {
		nscan_limit = total_pages;
	} else {
		nscan_limit = desscan;
	}

	DTRACE_PROBE1(pageout__start, pgcnt_t, nscan_limit);

	pageout_lbolt = ddi_get_lbolt();
	sample_start = gethrtime();

	/*
	 * Scan the appropriate number of pages for a single duty cycle.
	 * Only scan while at least one of these is true:
	 * 1) one or more zones is over its cap
	 * 2) there is not enough free memory
	 * 3) during page scan startup when determining sample data
	 */
	while (nscan < nscan_limit &&
	    (zones_over ||
	    freemem < lotsfree + needfree ||
	    PAGE_SCAN_STARTUP)) {
		int rvfront, rvback;

		DTRACE_PROBE1(pageout__loop, pgcnt_t, pcount);

		/*
		 * Check to see if we have exceeded our %CPU budget
		 * for this wakeup, but not on every single page visited,
		 * just every once in a while.
		 */
		if ((pcount & PAGES_POLL_MASK) == PAGES_POLL_MASK) {
			pageout_cycle_ticks = ddi_get_lbolt() - pageout_lbolt;
			if (pageout_cycle_ticks >= pageout_ticks) {
				/*
				 * This is where we normally break out of the
				 * loop when scanning zones or sampling.
				 */
				if (!zones_over) {
					++pageout_timeouts;
				}
				DTRACE_PROBE(pageout__timeout);
				break;
			}
		}

		/*
		 * If checkpage manages to add a page to the free list,
		 * we give ourselves another couple of trips around memory.
		 */
		if ((rvfront = checkpage(fronthand, FRONT)) == 1)
			count = 0;
		if ((rvback = checkpage(backhand, BACK)) == 1)
			count = 0;

		++pcount;

		/*
		 * protected by pageout_mutex instead of cpu_stat_lock
		 */
		CPU_STATS_ADDQ(CPU, vm, scan, 1);

		/*
		 * Don't include ineligible pages in the number scanned.
		 */
		if (rvfront != -1 || rvback != -1)
			nscan++;

		backhand = page_next(backhand);

		/*
		 * backhand update and wraparound check are done separately
		 * because lint barks when it finds an empty "if" body
		 */

		if ((fronthand = page_next(fronthand)) == page_first())	{
			DTRACE_PROBE(pageout__wrap__front);

			/*
			 * protected by pageout_mutex instead of cpu_stat_lock
			 */
			CPU_STATS_ADDQ(CPU, vm, rev, 1);

			/*
			 * If scanning because the system is low on memory,
			 * then when we wraparound memory we want to try to
			 * reclaim more pages.
			 * If scanning only because zones are over their cap,
			 * then wrapping is common and we simply keep going.
			 */
			if (freemem < lotsfree + needfree && ++count > 1) {
				/*
				 * The system is low on memory.
				 * Extremely unlikely, but it happens.
				 * We went around memory at least once
				 * and didn't reclaim enough.
				 * If we are still skipping `highly shared'
				 * pages, skip fewer of them.  Otherwise,
				 * give up till the next clock tick.
				 */
				if (po_share < MAX_PO_SHARE) {
					po_share <<= 1;
				} else {
					/*
					 * Really a "goto loop", but if someone
					 * is tracing or TNF_PROBE_ing, hit
					 * those probes first.
					 */
					break;
				}
			}
		}
	}

	sample_end = gethrtime();

	DTRACE_PROBE2(pageout__loop__end, pgcnt_t, pcount, uint_t, count);

	/* Kernel probe */
	TNF_PROBE_2(pageout_scan_end, "vm pagedaemon", /* CSTYLED */,
	    tnf_ulong, pages_scanned, nscan, tnf_ulong, pages_free, freemem);

	/*
	 * The following two blocks are only relevant when the scanner is
	 * first started up. After the scanner runs for a while, neither of
	 * the conditions will ever be true again.
	 */
	if (PAGE_SCAN_STARTUP) {
		pageout_sample_pages += pcount;
		pageout_sample_etime += sample_end - sample_start;
		++pageout_sample_cnt;

	} else if (pageout_new_spread == 0) {
		/*
		 * We have run enough samples, set the spread.
		 */
		pageout_rate = (hrrate_t)pageout_sample_pages *
		    (hrrate_t)(NANOSEC) / pageout_sample_etime;
		pageout_new_spread = pageout_rate / 10;
		setupclock(1);
	}

	goto loop;
}

/*
 * Look at the page at hand.  If it is locked (e.g., for physical i/o),
 * system (u., page table) or free, then leave it alone.  Otherwise,
 * if we are running the front hand, turn off the page's reference bit.
 * If running the back hand, check whether the page has been reclaimed.
 * If not, free the page, pushing it to disk first if necessary.
 *
 * Return values:
 *	-1 if the page is not a candidate at all,
 *	 0 if not freed, or
 *	 1 if we freed it.
 */
static int
checkpage(struct page *pp, int whichhand)
{
	int ppattr;
	int isfs = 0;
	int isexec = 0;
	int pagesync_flag;
	zoneid_t zid = ALL_ZONES;

	/*
	 * Skip pages:
	 * 	- associated with the kernel vnode since
	 *	    they are always "exclusively" locked.
	 *	- that are free
	 *	- that are shared more than po_share'd times
	 *	- its already locked
	 *
	 * NOTE:  These optimizations assume that reads are atomic.
	 */

	if (PP_ISKAS(pp) || PAGE_LOCKED(pp) || PP_ISFREE(pp) ||
	    pp->p_lckcnt != 0 || pp->p_cowcnt != 0 ||
	    hat_page_checkshare(pp, po_share)) {
		return (-1);
	}

	if (!page_trylock(pp, SE_EXCL)) {
		/*
		 * Skip the page if we can't acquire the "exclusive" lock.
		 */
		return (-1);
	} else if (PP_ISFREE(pp)) {
		/*
		 * It became free between the above check and our actually
		 * locking the page.  Oh, well there will be other pages.
		 */
		page_unlock(pp);
		return (-1);
	}

	/*
	 * Reject pages that cannot be freed. The page_struct_lock
	 * need not be acquired to examine these
	 * fields since the page has an "exclusive" lock.
	 */
	if (pp->p_lckcnt != 0 || pp->p_cowcnt != 0) {
		page_unlock(pp);
		return (-1);
	}

	if (zones_over) {
		ASSERT(pp->p_zoneid == ALL_ZONES ||
		    pp->p_zoneid >= 0 && pp->p_zoneid <= MAX_ZONEID);
		if (pp->p_zoneid == ALL_ZONES ||
		    zone_pcap_data[pp->p_zoneid].zpcap_over == 0) {
			/*
			 * Cross-zone shared page, or zone not over it's cap.
			 * Leave the page alone.
			 */
			page_unlock(pp);
			return (-1);
		}
		zid = pp->p_zoneid;
	}

	/*
	 * Maintain statistics for what we are freeing
	 */

	if (pp->p_vnode != NULL) {
		if (pp->p_vnode->v_flag & VVMEXEC)
			isexec = 1;

		if (!IS_SWAPFSVP(pp->p_vnode))
			isfs = 1;
	}

	/*
	 * Turn off REF and MOD bits with the front hand.
	 * The back hand examines the REF bit and always considers
	 * SHARED pages as referenced.
	 */
	if (whichhand == FRONT)
		pagesync_flag = HAT_SYNC_ZERORM;
	else
		pagesync_flag = HAT_SYNC_DONTZERO | HAT_SYNC_STOPON_REF |
		    HAT_SYNC_STOPON_SHARED;

	ppattr = hat_pagesync(pp, pagesync_flag);

recheck:
	/*
	 * If page is referenced; fronthand makes unreferenced and reclaimable.
	 * For the backhand, a process referenced the page since the front hand
	 * went by, so it's not a candidate for freeing up.
	 */
	if (ppattr & P_REF) {
		DTRACE_PROBE2(pageout__isref, page_t *, pp, int, whichhand);
		if (whichhand == FRONT) {
			hat_clrref(pp);
		}
		page_unlock(pp);
		return (0);
	}

	/*
	 * This page is not referenced, so it must be reclaimable and we can
	 * add it to the free list. This can be done by either hand.
	 */

	VM_STAT_ADD(pageoutvmstats.checkpage[0]);

	/*
	 * If large page, attempt to demote it. If successfully demoted,
	 * retry the checkpage.
	 */
	if (pp->p_szc != 0) {
		if (!page_try_demote_pages(pp)) {
			VM_STAT_ADD(pageoutvmstats.checkpage[1]);
			page_unlock(pp);
			return (-1);
		}
		ASSERT(pp->p_szc == 0);
		VM_STAT_ADD(pageoutvmstats.checkpage[2]);
		/*
		 * since page_try_demote_pages() could have unloaded some
		 * mappings it makes sense to reload ppattr.
		 */
		ppattr = hat_page_getattr(pp, P_MOD | P_REF);
	}

	/*
	 * If the page is currently dirty, we have to arrange
	 * to have it cleaned before it can be freed.
	 *
	 * XXX - ASSERT(pp->p_vnode != NULL);
	 */
	if ((ppattr & P_MOD) && pp->p_vnode) {
		struct vnode *vp = pp->p_vnode;
		u_offset_t offset = pp->p_offset;

		/*
		 * Note: There is no possibility to test for process being
		 * swapped out or about to exit since we can't get back to
		 * process(es) from the page.
		 */

		/*
		 * Hold the vnode before releasing the page lock to
		 * prevent it from being freed and re-used by some
		 * other thread.
		 */
		VN_HOLD(vp);
		page_unlock(pp);

		/*
		 * Queue i/o request for the pageout thread.
		 */
		if (!queue_io_request(vp, offset)) {
			VN_RELE(vp);
			return (0);
		}
		if (isfs) {
			zone_pageout_stat(zid, ZPO_DIRTY);
		} else {
			zone_pageout_stat(zid, ZPO_ANONDIRTY);
		}
		return (1);
	}

	/*
	 * Now we unload all the translations,
	 * and put the page back on to the free list.
	 * If the page was used (referenced or modified) after
	 * the pagesync but before it was unloaded we catch it
	 * and handle the page properly.
	 */
	DTRACE_PROBE2(pageout__free, page_t *, pp, int, whichhand);
	(void) hat_pageunload(pp, HAT_FORCE_PGUNLOAD);
	ppattr = hat_page_getattr(pp, P_MOD | P_REF);
	if ((ppattr & P_REF) || ((ppattr & P_MOD) && pp->p_vnode))
		goto recheck;

	/*LINTED: constant in conditional context*/
	VN_DISPOSE(pp, B_FREE, 0, kcred);

	CPU_STATS_ADD_K(vm, dfree, 1);

	if (isfs) {
		if (isexec) {
			CPU_STATS_ADD_K(vm, execfree, 1);
		} else {
			CPU_STATS_ADD_K(vm, fsfree, 1);
		}
		zone_pageout_stat(zid, ZPO_FS);
	} else {
		CPU_STATS_ADD_K(vm, anonfree, 1);
		zone_pageout_stat(zid, ZPO_ANON);
	}

	return (1);		/* freed a page! */
}

/*
 * Queue async i/o request from pageout_scanner and segment swapout
 * routines on one common list.  This ensures that pageout devices (swap)
 * are not saturated by pageout_scanner or swapout requests.
 * The pageout thread empties this list by initiating i/o operations.
 */
int
queue_io_request(vnode_t *vp, u_offset_t off)
{
	struct async_reqs *arg;

	/*
	 * If we cannot allocate an async request struct,
	 * skip this page.
	 */
	mutex_enter(&push_lock);
	if ((arg = req_freelist) == NULL) {
		mutex_exit(&push_lock);
		return (0);
	}
	req_freelist = arg->a_next;		/* adjust freelist */
	push_list_size++;

	arg->a_vp = vp;
	arg->a_off = off;
	arg->a_len = PAGESIZE;
	arg->a_flags = B_ASYNC | B_FREE;
	arg->a_cred = kcred;		/* always held */

	/*
	 * Add to list of pending write requests.
	 */
	arg->a_next = push_list;
	push_list = arg;

	if (req_freelist == NULL) {
		/*
		 * No free async requests left. The lock is held so we
		 * might as well signal the pusher thread now.
		 */
		cv_signal(&push_cv);
	}
	mutex_exit(&push_lock);
	return (1);
}

/*
 * Wakeup pageout to initiate i/o if push_list is not empty.
 */
void
cv_signal_pageout()
{
	if (push_list != NULL) {
		mutex_enter(&push_lock);
		cv_signal(&push_cv);
		mutex_exit(&push_lock);
	}
}
