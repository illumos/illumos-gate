/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * Page Retire - Big Theory Statement.
 *
 * This file handles removing sections of faulty memory from use when the
 * user land FMA Diagnosis Engine requests that a page be removed or when
 * a CE or UE is detected by the hardware.
 *
 * In the bad old days, the kernel side of Page Retire did a lot of the work
 * on its own. Now, with the DE keeping track of errors, the kernel side is
 * rather simple minded on most platforms.
 *
 * Errors are all reflected to the DE, and after digesting the error and
 * looking at all previously reported errors, the DE decides what should
 * be done about the current error. If the DE wants a particular page to
 * be retired, then the kernel page retire code is invoked via an ioctl.
 * On non-FMA platforms, the ue_drain and ce_drain paths ends up calling
 * page retire to handle the error. Since page retire is just a simple
 * mechanism it doesn't need to differentiate between the different callers.
 *
 * The p_toxic field in the page_t is used to indicate which errors have
 * occurred and what action has been taken on a given page. Because errors are
 * reported without regard to the locked state of a page, no locks are used
 * to SET the error bits in p_toxic. However, in order to clear the error
 * bits, the page_t must be held exclusively locked.
 *
 * When page_retire() is called, it must be able to acquire locks, sleep, etc.
 * It must not be called from high-level interrupt context.
 *
 * Depending on how the requested page is being used at the time of the retire
 * request (and on the availability of sufficient system resources), the page
 * may be retired immediately, or just marked for retirement later. For
 * example, locked pages are marked, while free pages are retired. Multiple
 * requests may be made to retire the same page, although there is no need
 * to: once the p_toxic flags are set, the page will be retired as soon as it
 * can be exclusively locked.
 *
 * The retire mechanism is driven centrally out of page_unlock(). To expedite
 * the retirement of pages, further requests for SE_SHARED locks are denied
 * as long as a page retirement is pending. In addition, as long as pages are
 * pending retirement a background thread runs periodically trying to retire
 * those pages. Pages which could not be retired while the system is running
 * are scrubbed prior to rebooting to avoid latent errors on the next boot.
 *
 * Single CE pages and UE pages without persistent errors are scrubbed and
 * returned to service. Recidivist pages, as well as FMA-directed requests
 * for retirement, result in the page being taken out of service. Once the
 * decision is made to take a page out of service, the page is cleared, hashed
 * onto the retired_pages vnode, marked as retired, and it is unlocked.  No
 * other requesters (except for unretire) are allowed to lock retired pages.
 *
 * The public routines return (sadly) 0 if they worked and a non-zero error
 * value if something went wrong. This is done for the ioctl side of the
 * world to allow errors to be reflected all the way out to user land. The
 * non-zero values are explained in comments atop each function.
 */

/*
 * Things to fix:
 *
 * 	1. Cleanup SE_EWANTED.  Since we're aggressive about trying to retire
 *	pages, we can use page_retire_pp() to replace SE_EWANTED and all
 *	the special delete_memory_thread() code just goes away.
 *
 * 	2. Trying to retire non-relocatable kvp pages may result in a
 *      quagmire. This is because seg_kmem() no longer keeps its pages locked,
 *      and calls page_lookup() in the free path; since kvp pages are modified
 *      and don't have a usable backing store, page_retire() can't do anything
 *      with them, and we'll keep denying the lock to seg_kmem_free() in a
 *      vicious cycle. To prevent that, we don't deny locks to kvp pages, and
 *      hence only call page_retire_pp() from page_unlock() in the free path.
 *      Since most kernel pages are indefinitely held anyway, and don't
 *      participate in I/O, this is of little consequence.
 *
 *      3. Low memory situations will be interesting. If we don't have
 *      enough memory for page_relocate() to succeed, we won't be able to
 *      retire dirty pages; nobody will be able to push them out to disk
 *      either, since we aggressively deny the page lock. We could change
 *      fsflush so it can recognize this situation, grab the lock, and push
 *      the page out, where we'll catch it in the free path and retire it.
 *
 *	4. Beware of places that have code like this in them:
 *
 *		if (! page_tryupgrade(pp)) {
 *			page_unlock(pp);
 *			while (! page_lock(pp, SE_EXCL, NULL, P_RECLAIM)) {
 *				/ *NOTHING* /
 *			}
 *		}
 *		page_free(pp);
 *
 *	The problem is that pp can change identity right after the
 *	page_unlock() call.  In particular, page_retire() can step in
 *	there, change pp's identity, and hash pp onto the retired_vnode.
 *
 *	Of course, other functions besides page_retire() can have the
 *	same effect. A kmem reader can waltz by, set up a mapping to the
 *	page, and then unlock the page. Page_free() will then go castors
 *	up. So if anybody is doing this, it's already a bug.
 *
 *      5. mdboot()'s call into page_retire_hunt() should probably be
 *      moved lower. Where the call is made now, we can get into trouble
 *      by scrubbing a kernel page that is then accessed later.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mman.h>
#include <sys/vnode.h>
#include <sys/cmn_err.h>
#include <sys/ksynch.h>
#include <sys/thread.h>
#include <sys/disp.h>
#include <sys/ontrap.h>
#include <sys/vmsystm.h>
#include <sys/mem_config.h>
#include <sys/atomic.h>
#include <sys/callb.h>
#include <vm/page.h>
#include <vm/vm_dep.h>
#include <vm/as.h>
#include <vm/hat.h>

/*
 * vnode for all pages which are retired from the VM system;
 */
vnode_t *retired_pages;

/*
 * Background thread that wakes up periodically to try to retire pending
 * pages. This prevents threads from becoming blocked indefinitely in
 * page_lookup() or some other routine should the page(s) they are waiting
 * on become eligible for social security.
 */
static void page_retire_thread(void);
static kthread_t *pr_thread_id;
static kcondvar_t pr_cv;
static kmutex_t pr_thread_mutex;
static clock_t pr_thread_shortwait;
static clock_t pr_thread_longwait;

/*
 * Make a list of all of the pages that have been marked for retirement
 * but are not yet retired.  At system shutdown, we will scrub all of the
 * pages in the list in case there are outstanding UEs.  Then, we
 * cross-check this list against the number of pages that are yet to be
 * retired, and if we find inconsistencies, we scan every page_t in the
 * whole system looking for any pages that need to be scrubbed for UEs.
 * The background thread also uses this queue to determine which pages
 * it should keep trying to retire.
 */
#ifdef	DEBUG
#define	PR_PENDING_QMAX	32
#else	/* DEBUG */
#define	PR_PENDING_QMAX	256
#endif	/* DEBUG */
page_t		*pr_pending_q[PR_PENDING_QMAX];
kmutex_t	pr_q_mutex;

/*
 * Page retire global kstats
 */
struct page_retire_kstat {
	kstat_named_t	pr_retired;
	kstat_named_t	pr_requested;
	kstat_named_t	pr_requested_free;
	kstat_named_t	pr_enqueue_fail;
	kstat_named_t	pr_dequeue_fail;
	kstat_named_t	pr_pending;
	kstat_named_t	pr_failed;
	kstat_named_t	pr_failed_kernel;
	kstat_named_t	pr_limit;
	kstat_named_t	pr_limit_exceeded;
	kstat_named_t	pr_fma;
	kstat_named_t	pr_mce;
	kstat_named_t	pr_ue;
	kstat_named_t	pr_ue_cleared_retire;
	kstat_named_t	pr_ue_cleared_free;
	kstat_named_t	pr_ue_persistent;
	kstat_named_t	pr_unretired;
};

static struct page_retire_kstat page_retire_kstat = {
	{ "pages_retired",		KSTAT_DATA_UINT64},
	{ "pages_retire_request",	KSTAT_DATA_UINT64},
	{ "pages_retire_request_free",	KSTAT_DATA_UINT64},
	{ "pages_notenqueued", 		KSTAT_DATA_UINT64},
	{ "pages_notdequeued", 		KSTAT_DATA_UINT64},
	{ "pages_pending", 		KSTAT_DATA_UINT64},
	{ "pages_deferred",		KSTAT_DATA_UINT64},
	{ "pages_deferred_kernel",	KSTAT_DATA_UINT64},
	{ "pages_limit",		KSTAT_DATA_UINT64},
	{ "pages_limit_exceeded",	KSTAT_DATA_UINT64},
	{ "pages_fma",			KSTAT_DATA_UINT64},
	{ "pages_multiple_ce",		KSTAT_DATA_UINT64},
	{ "pages_ue",			KSTAT_DATA_UINT64},
	{ "pages_ue_cleared_retired",	KSTAT_DATA_UINT64},
	{ "pages_ue_cleared_freed",	KSTAT_DATA_UINT64},
	{ "pages_ue_persistent",	KSTAT_DATA_UINT64},
	{ "pages_unretired",		KSTAT_DATA_UINT64},
};

static kstat_t  *page_retire_ksp = NULL;

#define	PR_INCR_KSTAT(stat)	\
	atomic_add_64(&(page_retire_kstat.stat.value.ui64), 1)
#define	PR_DECR_KSTAT(stat)	\
	atomic_add_64(&(page_retire_kstat.stat.value.ui64), -1)

#define	PR_KSTAT_RETIRED_CE	(page_retire_kstat.pr_mce.value.ui64)
#define	PR_KSTAT_RETIRED_FMA	(page_retire_kstat.pr_fma.value.ui64)
#define	PR_KSTAT_RETIRED_NOTUE	(PR_KSTAT_RETIRED_CE + PR_KSTAT_RETIRED_FMA)
#define	PR_KSTAT_PENDING	(page_retire_kstat.pr_pending.value.ui64)
#define	PR_KSTAT_EQFAIL		(page_retire_kstat.pr_enqueue_fail.value.ui64)
#define	PR_KSTAT_DQFAIL		(page_retire_kstat.pr_dequeue_fail.value.ui64)

/*
 * Limit the number of multiple CE page retires.
 * The default is 0.1% of physmem, or 1 in 1000 pages. This is set in
 * basis points, where 100 basis points equals one percent.
 */
#define	MCE_BPT	10
uint64_t	max_pages_retired_bps = MCE_BPT;
#define	PAGE_RETIRE_LIMIT	((physmem * max_pages_retired_bps) / 10000)

/*
 * Control over the verbosity of page retirement.
 *
 * When set to zero (the default), no messages will be printed.
 * When set to one, summary messages will be printed.
 * When set > one, all messages will be printed.
 *
 * A value of one will trigger detailed messages for retirement operations,
 * and is intended as a platform tunable for processors where FMA's DE does
 * not run (e.g., spitfire). Values > one are intended for debugging only.
 */
int page_retire_messages = 0;

/*
 * Control whether or not we return scrubbed UE pages to service.
 * By default we do not since FMA wants to run its diagnostics first
 * and then ask us to unretire the page if it passes. Non-FMA platforms
 * may set this to zero so we will only retire recidivist pages. It should
 * not be changed by the user.
 */
int page_retire_first_ue = 1;

/*
 * Master enable for page retire. This prevents a CE or UE early in boot
 * from trying to retire a page before page_retire_init() has finished
 * setting things up. This is internal only and is not a tunable!
 */
static int pr_enable = 0;

extern struct vnode kvp;

#ifdef	DEBUG
struct page_retire_debug {
	int prd_dup;
	int prd_noaction;
	int prd_queued;
	int prd_notqueued;
	int prd_dequeue;
	int prd_top;
	int prd_locked;
	int prd_reloc;
	int prd_relocfail;
	int prd_mod;
	int prd_mod_late;
	int prd_kern;
	int prd_free;
	int prd_noreclaim;
	int prd_hashout;
	int prd_fma;
	int prd_uescrubbed;
	int prd_uenotscrubbed;
	int prd_mce;
	int prd_prlocked;
	int prd_prnotlocked;
	int prd_prretired;
	int prd_ulocked;
	int prd_unotretired;
	int prd_udestroy;
	int prd_uhashout;
	int prd_uunretired;
	int prd_unotlocked;
	int prd_checkhit;
	int prd_checkmiss;
	int prd_tctop;
	int prd_tclocked;
	int prd_hunt;
	int prd_dohunt;
	int prd_earlyhunt;
	int prd_latehunt;
	int prd_nofreedemote;
	int prd_nodemote;
	int prd_demoted;
} pr_debug;

#define	PR_DEBUG(foo)	((pr_debug.foo)++)

/*
 * A type histogram. We record the incidence of the various toxic
 * flag combinations along with the interesting page attributes. The
 * goal is to get as many combinations as we can while driving all
 * pr_debug values nonzero (indicating we've exercised all possible
 * code paths across all possible page types). Not all combinations
 * will make sense -- e.g. PRT_MOD|PRT_KERNEL.
 *
 * pr_type offset bit encoding (when examining with a debugger):
 *
 *    PRT_NAMED  - 0x4
 *    PRT_KERNEL - 0x8
 *    PRT_FREE   - 0x10
 *    PRT_MOD    - 0x20
 *    PRT_FMA    - 0x0
 *    PRT_MCE    - 0x40
 *    PRT_UE     - 0x80
 */

#define	PRT_NAMED	0x01
#define	PRT_KERNEL	0x02
#define	PRT_FREE	0x04
#define	PRT_MOD		0x08
#define	PRT_FMA		0x00	/* yes, this is not a mistake */
#define	PRT_MCE		0x10
#define	PRT_UE		0x20
#define	PRT_ALL		0x3F

int pr_types[PRT_ALL+1];

#define	PR_TYPES(pp)	{			\
	int whichtype = 0;			\
	if (pp->p_vnode)			\
		whichtype |= PRT_NAMED;		\
	if (PP_ISKVP(pp))			\
		whichtype |= PRT_KERNEL;	\
	if (PP_ISFREE(pp))			\
		whichtype |= PRT_FREE;		\
	if (hat_ismod(pp))			\
		whichtype |= PRT_MOD;		\
	if (pp->p_toxic & PR_UE)		\
		whichtype |= PRT_UE;		\
	if (pp->p_toxic & PR_MCE)		\
		whichtype |= PRT_MCE;		\
	pr_types[whichtype]++;			\
}

int recl_calls;
int recl_mtbf = 3;
int reloc_calls;
int reloc_mtbf = 7;
int pr_calls;
int pr_mtbf = 15;

#define	MTBF(v, f)	(((++(v)) & (f)) != (f))

#else	/* DEBUG */

#define	PR_DEBUG(foo)	/* nothing */
#define	PR_TYPES(foo)	/* nothing */
#define	MTBF(v, f)	(1)

#endif	/* DEBUG */

/*
 * page_retire_done() - completion processing
 *
 * Used by the page_retire code for common completion processing.
 * It keeps track of how many times a given result has happened,
 * and writes out an occasional message.
 *
 * May be called with a NULL pp (PRD_INVALID_PA case).
 */
#define	PRD_INVALID_KEY		-1
#define	PRD_SUCCESS		0
#define	PRD_PENDING		1
#define	PRD_FAILED		2
#define	PRD_DUPLICATE		3
#define	PRD_INVALID_PA		4
#define	PRD_LIMIT		5
#define	PRD_UE_SCRUBBED		6
#define	PRD_UNR_SUCCESS		7
#define	PRD_UNR_CANTLOCK	8
#define	PRD_UNR_NOT		9

typedef struct page_retire_op {
	int	pr_key;		/* one of the PRD_* defines from above */
	int	pr_count;	/* How many times this has happened */
	int	pr_retval;	/* return value */
	int	pr_msglvl;	/* message level - when to print */
	char	*pr_message;	/* Cryptic message for field service */
} page_retire_op_t;

static page_retire_op_t page_retire_ops[] = {
	/* key			count	retval	msglvl	message */
	{PRD_SUCCESS,		0,	0,	1,
		"Page 0x%08x.%08x removed from service"},
	{PRD_PENDING,		0,	EAGAIN,	2,
		"Page 0x%08x.%08x will be retired on free"},
	{PRD_FAILED,		0,	EAGAIN,	0, NULL},
	{PRD_DUPLICATE,		0,	EBUSY,	2,
		"Page 0x%08x.%08x already retired"},
	{PRD_INVALID_PA,	0,	EINVAL, 2,
		"PA 0x%08x.%08x is not a relocatable page"},
	{PRD_LIMIT,		0,	0,	1,
		"Page 0x%08x.%08x not retired due to limit exceeded"},
	{PRD_UE_SCRUBBED,	0,	0,	1,
		"Previously reported error on page 0x%08x.%08x cleared"},
	{PRD_UNR_SUCCESS,	0,	0,	1,
		"Page 0x%08x.%08x returned to service"},
	{PRD_UNR_CANTLOCK,	0,	EAGAIN,	2,
		"Page 0x%08x.%08x could not be unretired"},
	{PRD_UNR_NOT,		0,	EBADF,	2,
		"Page 0x%08x.%08x is not retired"},
	{PRD_INVALID_KEY,	0,	0,	0, NULL} /* MUST BE LAST! */
};

/*
 * print a message if page_retire_messages is true.
 */
#define	PR_MESSAGE(debuglvl, msglvl, msg, pa)				\
{									\
	uint64_t p = (uint64_t)pa;					\
	if (page_retire_messages >= msglvl && msg != NULL) {		\
		cmn_err(debuglvl, msg,					\
		    (uint32_t)(p >> 32), (uint32_t)p);			\
	}								\
}

/*
 * Note that multiple bits may be set in a single settoxic operation.
 * May be called without the page locked.
 */
void
page_settoxic(page_t *pp, uchar_t bits)
{
	atomic_or_8(&pp->p_toxic, bits);
}

/*
 * Note that multiple bits may cleared in a single clrtoxic operation.
 * Must be called with the page exclusively locked.
 */
void
page_clrtoxic(page_t *pp, uchar_t bits)
{
	ASSERT(PAGE_EXCL(pp));
	atomic_and_8(&pp->p_toxic, ~bits);
}

/*
 * Prints any page retire messages to the user, and decides what
 * error code is appropriate for the condition reported.
 */
static int
page_retire_done(page_t *pp, int code)
{
	page_retire_op_t *prop;
	uint64_t	pa = 0;
	int		i;

	if (pp != NULL) {
		pa = mmu_ptob(pp->p_pagenum);
	}

	prop = NULL;
	for (i = 0; page_retire_ops[i].pr_key != PRD_INVALID_KEY; i++) {
		if (page_retire_ops[i].pr_key == code) {
			prop = &page_retire_ops[i];
			break;
		}
	}

#ifdef	DEBUG
	if (page_retire_ops[i].pr_key == PRD_INVALID_KEY) {
		cmn_err(CE_PANIC, "page_retire_done: Invalid opcode %d", code);
	}
#endif

	ASSERT(prop->pr_key == code);

	prop->pr_count++;

	PR_MESSAGE(CE_NOTE, prop->pr_msglvl, prop->pr_message, pa);
	if (pp != NULL) {
		page_settoxic(pp, PR_MSG);
	}

	return (prop->pr_retval);
}

/*
 * On a reboot, our friend mdboot() wants to clear up any PP_PR_REQ() pages
 * that we were not able to retire. On large machines, walking the complete
 * page_t array and looking at every page_t takes too long. So, as a page is
 * marked toxic, we track it using a list that can be processed at reboot
 * time.  page_retire_enqueue() will do its best to try to avoid duplicate
 * entries, but if we get too many errors at once the queue can overflow,
 * in which case we will end up walking every page_t as a last resort.
 * The background thread also makes use of this queue to find which pages
 * are pending retirement.
 */
static void
page_retire_enqueue(page_t *pp)
{
	int	nslot = -1;
	int	i;

	mutex_enter(&pr_q_mutex);

	/*
	 * Check to make sure retire hasn't already dequeued it.
	 * In the meantime if the page was cleaned up, no need
	 * to enqueue it.
	 */
	if (PP_RETIRED(pp) || pp->p_toxic == 0) {
		mutex_exit(&pr_q_mutex);
		PR_DEBUG(prd_noaction);
		return;
	}

	for (i = 0; i < PR_PENDING_QMAX; i++) {
		if (pr_pending_q[i] == pp) {
			mutex_exit(&pr_q_mutex);
			PR_DEBUG(prd_dup);
			return;
		} else if (nslot == -1 && pr_pending_q[i] == NULL) {
			nslot = i;
		}
	}

	PR_INCR_KSTAT(pr_pending);

	if (nslot != -1) {
		pr_pending_q[nslot] = pp;
		PR_DEBUG(prd_queued);
	} else {
		PR_INCR_KSTAT(pr_enqueue_fail);
		PR_DEBUG(prd_notqueued);
	}
	mutex_exit(&pr_q_mutex);
}

static void
page_retire_dequeue(page_t *pp)
{
	int i;

	mutex_enter(&pr_q_mutex);

	for (i = 0; i < PR_PENDING_QMAX; i++) {
		if (pr_pending_q[i] == pp) {
			pr_pending_q[i] = NULL;
			break;
		}
	}

	if (i == PR_PENDING_QMAX) {
		PR_INCR_KSTAT(pr_dequeue_fail);
	}

	PR_DECR_KSTAT(pr_pending);
	PR_DEBUG(prd_dequeue);

	mutex_exit(&pr_q_mutex);
}

/*
 * Act like page_destroy(), but instead of freeing the page, hash it onto
 * the retired_pages vnode, and mark it retired.
 *
 * For fun, we try to scrub the page until it's squeaky clean.
 * availrmem is adjusted here.
 */
static void
page_retire_destroy(page_t *pp)
{
	u_offset_t off = (u_offset_t)((uintptr_t)pp);

	ASSERT(PAGE_EXCL(pp));
	ASSERT(!PP_ISFREE(pp));
	ASSERT(pp->p_szc == 0);
	ASSERT(!hat_page_is_mapped(pp));
	ASSERT(!pp->p_vnode);

	page_clr_all_props(pp);
	pagescrub(pp, 0, MMU_PAGESIZE);

	pp->p_next = NULL;
	pp->p_prev = NULL;
	if (page_hashin(pp, retired_pages, off, NULL) == 0) {
		cmn_err(CE_PANIC, "retired page %p hashin failed", (void *)pp);
	}

	page_settoxic(pp, PR_RETIRED);
	page_clrtoxic(pp, PR_BUSY);
	page_retire_dequeue(pp);
	PR_INCR_KSTAT(pr_retired);

	if (pp->p_toxic & PR_FMA) {
		PR_INCR_KSTAT(pr_fma);
	} else if (pp->p_toxic & PR_UE) {
		PR_INCR_KSTAT(pr_ue);
	} else {
		PR_INCR_KSTAT(pr_mce);
	}

	mutex_enter(&freemem_lock);
	availrmem--;
	mutex_exit(&freemem_lock);

	page_unlock(pp);
}

/*
 * Check whether the number of pages which have been retired already exceeds
 * the maximum allowable percentage of memory which may be retired.
 *
 * Returns 1 if the limit has been exceeded.
 */
static int
page_retire_limit(void)
{
	if (PR_KSTAT_RETIRED_NOTUE >= (uint64_t)PAGE_RETIRE_LIMIT) {
		PR_INCR_KSTAT(pr_limit_exceeded);
		return (1);
	}

	return (0);
}

#define	MSG_DM	"Data Mismatch occurred at PA 0x%08x.%08x"		\
	"[ 0x%x != 0x%x ] while attempting to clear previously "	\
	"reported error; page removed from service"

#define	MSG_UE	"Uncorrectable Error occurred at PA 0x%08x.%08x while "	\
	"attempting to clear previously reported error; page removed "	\
	"from service"

/*
 * Attempt to clear a UE from a page.
 * Returns 1 if the error has been successfully cleared.
 */
static int
page_clear_transient_ue(page_t *pp)
{
	caddr_t		kaddr;
	uint8_t		rb, wb;
	uint64_t	pa;
	uint32_t	pa_hi, pa_lo;
	on_trap_data_t	otd;
	int		errors = 0;
	int		i;

	ASSERT(PAGE_EXCL(pp));
	ASSERT(PP_PR_REQ(pp));
	ASSERT(pp->p_szc == 0);
	ASSERT(!hat_page_is_mapped(pp));

	/*
	 * Clear the page and attempt to clear the UE.  If we trap
	 * on the next access to the page, we know the UE has recurred.
	 */
	pagescrub(pp, 0, PAGESIZE);

	/*
	 * Map the page and write a bunch of bit patterns to compare
	 * what we wrote with what we read back.  This isn't a perfect
	 * test but it should be good enough to catch most of the
	 * recurring UEs. If this fails to catch a recurrent UE, we'll
	 * retire the page the next time we see a UE on the page.
	 */
	kaddr = ppmapin(pp, PROT_READ|PROT_WRITE, (caddr_t)-1);

	pa = ptob((uint64_t)page_pptonum(pp));
	pa_hi = (uint32_t)(pa >> 32);
	pa_lo = (uint32_t)pa;

	/*
	 * Fill the page with each (0x00 - 0xFF] bit pattern, flushing
	 * the cache in between reading and writing.  We do this under
	 * on_trap() protection to avoid recursion.
	 */
	if (on_trap(&otd, OT_DATA_EC)) {
		PR_MESSAGE(CE_WARN, 1, MSG_UE, pa);
		errors = 1;
	} else {
		for (wb = 0xff; wb > 0; wb--) {
			for (i = 0; i < PAGESIZE; i++) {
				kaddr[i] = wb;
			}

			sync_data_memory(kaddr, PAGESIZE);

			for (i = 0; i < PAGESIZE; i++) {
				rb = kaddr[i];
				if (rb != wb) {
					/*
					 * We had a mismatch without a trap.
					 * Uh-oh. Something is really wrong
					 * with this system.
					 */
					if (page_retire_messages) {
						cmn_err(CE_WARN, MSG_DM,
						    pa_hi, pa_lo, rb, wb);
					}
					errors = 1;
					goto out;	/* double break */
				}
			}
		}
	}
out:
	no_trap();
	ppmapout(kaddr);

	return (errors ? 0 : 1);
}

/*
 * Try to clear a page_t with a single UE. If the UE was transient, it is
 * returned to service, and we return 1. Otherwise we return 0 meaning
 * that further processing is required to retire the page.
 */
static int
page_retire_transient_ue(page_t *pp)
{
	ASSERT(PAGE_EXCL(pp));
	ASSERT(!hat_page_is_mapped(pp));

	/*
	 * If this page is a repeat offender, retire him under the
	 * "two strikes and you're out" rule. The caller is responsible
	 * for scrubbing the page to try to clear the error.
	 */
	if (pp->p_toxic & PR_UE_SCRUBBED) {
		PR_INCR_KSTAT(pr_ue_persistent);
		return (0);
	}

	if (page_clear_transient_ue(pp)) {
		/*
		 * We set the PR_SCRUBBED_UE bit; if we ever see this
		 * page again, we will retire it, no questions asked.
		 */
		page_settoxic(pp, PR_UE_SCRUBBED);

		if (page_retire_first_ue) {
			PR_INCR_KSTAT(pr_ue_cleared_retire);
			return (0);
		} else {
			PR_INCR_KSTAT(pr_ue_cleared_free);

			page_clrtoxic(pp, PR_UE | PR_MCE | PR_MSG | PR_BUSY);
			page_retire_dequeue(pp);

			/* LINTED: CONSTCOND */
			VN_DISPOSE(pp, B_FREE, 1, kcred);
			return (1);
		}
	}

	PR_INCR_KSTAT(pr_ue_persistent);
	return (0);
}

/*
 * Update the statistics dynamically when our kstat is read.
 */
static int
page_retire_kstat_update(kstat_t *ksp, int rw)
{
	struct page_retire_kstat *pr;

	if (ksp == NULL)
	    return (EINVAL);

	switch (rw) {

	case KSTAT_READ:
		pr = (struct page_retire_kstat *)ksp->ks_data;
		ASSERT(pr == &page_retire_kstat);
		pr->pr_limit.value.ui64 = PAGE_RETIRE_LIMIT;
		return (0);

	case KSTAT_WRITE:
		return (EACCES);

	default:
		return (EINVAL);
	}
	/*NOTREACHED*/
}

/*
 * Initialize the page retire mechanism:
 *
 *   - Establish the correctable error retire limit.
 *   - Initialize locks.
 *   - Build the retired_pages vnode.
 *   - Set up the kstats.
 *   - Fire off the background thread.
 *   - Tell page_tryretire() it's OK to start retiring pages.
 */
void
page_retire_init(void)
{
	const fs_operation_def_t retired_vnodeops_template[] = {NULL, NULL};
	struct vnodeops *vops;

	const uint_t page_retire_ndata =
	    sizeof (page_retire_kstat) / sizeof (kstat_named_t);

	ASSERT(page_retire_ksp == NULL);

	if (max_pages_retired_bps <= 0) {
		max_pages_retired_bps = MCE_BPT;
	}

	mutex_init(&pr_q_mutex, NULL, MUTEX_DEFAULT, NULL);

	retired_pages = vn_alloc(KM_SLEEP);
	if (vn_make_ops("retired_pages", retired_vnodeops_template, &vops)) {
		cmn_err(CE_PANIC,
		    "page_retired_init: can't make retired vnodeops");
	}
	vn_setops(retired_pages, vops);

	if ((page_retire_ksp = kstat_create("unix", 0, "page_retire",
	    "misc", KSTAT_TYPE_NAMED, page_retire_ndata,
	    KSTAT_FLAG_VIRTUAL)) == NULL) {
		cmn_err(CE_WARN, "kstat_create for page_retire failed");
	} else {
		page_retire_ksp->ks_data = (void *)&page_retire_kstat;
		page_retire_ksp->ks_update = page_retire_kstat_update;
		kstat_install(page_retire_ksp);
	}

	pr_thread_shortwait = 23 * hz;
	pr_thread_longwait = 1201 * hz;
	mutex_init(&pr_thread_mutex, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&pr_cv, NULL, CV_DEFAULT, NULL);
	pr_thread_id = thread_create(NULL, 0, page_retire_thread, NULL, 0, &p0,
	    TS_RUN, minclsyspri);

	pr_enable = 1;
}

/*
 * page_retire_hunt() callback for the retire thread.
 */
static void
page_retire_thread_cb(page_t *pp)
{
	PR_DEBUG(prd_tctop);
	if (!PP_ISKVP(pp) && page_trylock(pp, SE_EXCL)) {
		PR_DEBUG(prd_tclocked);
		page_unlock(pp);
	}
}

/*
 * page_retire_hunt() callback for mdboot().
 *
 * It is necessary to scrub any failing pages prior to reboot in order to
 * prevent a latent error trap from occurring on the next boot.
 */
void
page_retire_mdboot_cb(page_t *pp)
{
	/*
	 * Don't scrub the kernel, since we might still need it, unless
	 * we have UEs on the page, in which case we have nothing to lose.
	 */
	if (!PP_ISKVP(pp) || PP_TOXIC(pp)) {
		pp->p_selock = -1;	/* pacify ASSERTs */
		PP_CLRFREE(pp);
		pagescrub(pp, 0, PAGESIZE);
		pp->p_selock = 0;
	}
	pp->p_toxic = 0;
}

/*
 * Hunt down any pages in the system that have not yet been retired, invoking
 * the provided callback function on each of them.
 */
void
page_retire_hunt(void (*callback)(page_t *))
{
	page_t *pp;
	page_t *first;
	uint64_t tbr, found;
	int i;

	PR_DEBUG(prd_hunt);

	if (PR_KSTAT_PENDING == 0) {
		return;
	}

	PR_DEBUG(prd_dohunt);

	found = 0;
	mutex_enter(&pr_q_mutex);

	tbr = PR_KSTAT_PENDING;

	for (i = 0; i < PR_PENDING_QMAX; i++) {
		if ((pp = pr_pending_q[i]) != NULL) {
			mutex_exit(&pr_q_mutex);
			callback(pp);
			mutex_enter(&pr_q_mutex);
			found++;
		}
	}

	if (PR_KSTAT_EQFAIL == PR_KSTAT_DQFAIL && found == tbr) {
		mutex_exit(&pr_q_mutex);
		PR_DEBUG(prd_earlyhunt);
		return;
	}
	mutex_exit(&pr_q_mutex);

	PR_DEBUG(prd_latehunt);

	/*
	 * We've lost track of a page somewhere. Hunt it down.
	 */
	memsegs_lock(0);
	pp = first = page_first();
	do {
		if (PP_PR_REQ(pp)) {
			callback(pp);
			if (++found == tbr) {
				break;	/* got 'em all */
			}
		}
	} while ((pp = page_next(pp)) != first);
	memsegs_unlock(0);
}

/*
 * The page_retire_thread loops forever, looking to see if there are
 * pages still waiting to be retired.
 */
static void
page_retire_thread(void)
{
	callb_cpr_t c;

	CALLB_CPR_INIT(&c, &pr_thread_mutex, callb_generic_cpr, "page_retire");

	mutex_enter(&pr_thread_mutex);
	for (;;) {
		if (pr_enable && PR_KSTAT_PENDING) {
			kmem_reap();
			seg_preap();
			page_retire_hunt(page_retire_thread_cb);
			CALLB_CPR_SAFE_BEGIN(&c);
			(void) cv_timedwait(&pr_cv, &pr_thread_mutex,
			    lbolt + pr_thread_shortwait);
			CALLB_CPR_SAFE_END(&c, &pr_thread_mutex);
		} else {
			CALLB_CPR_SAFE_BEGIN(&c);
			(void) cv_timedwait(&pr_cv, &pr_thread_mutex,
			    lbolt + pr_thread_longwait);
			CALLB_CPR_SAFE_END(&c, &pr_thread_mutex);
		}
	}
	/*NOTREACHED*/
}

/*
 * page_retire_pp() decides what to do with a failing page.
 *
 * When we get a free page (e.g. the scrubber or in the free path) life is
 * nice because the page is clean and marked free -- those always retire
 * nicely. From there we go by order of difficulty. If the page has data,
 * we attempt to relocate its contents to a suitable replacement page. If
 * that does not succeed, we look to see if it is clean. If after all of
 * this we have a clean, unmapped page (which we usually do!), we retire it.
 * If the page is not clean, we still process it regardless on a UE; for
 * CEs or FMA requests, we fail leaving the page in service. The page will
 * eventually be tried again later. We always return with the page unlocked
 * since we are called from page_unlock().
 *
 * We don't call panic or do anything fancy down in here. Our boss the DE
 * gets paid handsomely to do his job of figuring out what to do when errors
 * occur. We just do what he tells us to do.
 */
static int
page_retire_pp(page_t *pp)
{
	int		toxic;

	ASSERT(PAGE_EXCL(pp));
	ASSERT(pp->p_iolock_state == 0);
	ASSERT(pp->p_szc == 0);

	PR_DEBUG(prd_top);
	PR_TYPES(pp);

	toxic = pp->p_toxic;
	ASSERT(toxic & PR_REASONS);

	if ((toxic & (PR_FMA | PR_MCE)) && !(toxic & PR_UE) &&
	    page_retire_limit()) {
		page_clrtoxic(pp, PR_FMA | PR_MCE | PR_MSG | PR_BUSY);
		page_retire_dequeue(pp);
		page_unlock(pp);
		return (page_retire_done(pp, PRD_LIMIT));
	}

	if (PP_ISFREE(pp)) {
		PR_DEBUG(prd_free);
		if (!MTBF(recl_calls, recl_mtbf) || !page_reclaim(pp, NULL)) {
			PR_DEBUG(prd_noreclaim);
			PR_INCR_KSTAT(pr_failed);
			page_unlock(pp);
			return (page_retire_done(pp, PRD_FAILED));
		}
	}

	if ((toxic & PR_UE) == 0 && pp->p_vnode && !PP_ISFREE(pp) &&
	    !PP_ISNORELOCKERNEL(pp) && MTBF(reloc_calls, reloc_mtbf)) {
		page_t *newpp;
		spgcnt_t count;

		/*
		 * If we can relocate the page, great! newpp will go
		 * on without us, and everything is fine.  Regardless
		 * of whether the relocation succeeds, we are still
		 * going to take `pp' around back and shoot it.
		 */
		newpp = NULL;
		if (page_relocate(&pp, &newpp, 0, 0, &count, NULL) == 0) {
			PR_DEBUG(prd_reloc);
			page_unlock(newpp);
			ASSERT(hat_page_getattr(pp, P_MOD) == 0);
		} else {
			PR_DEBUG(prd_relocfail);
		}
	}

	if (hat_ismod(pp)) {
		PR_DEBUG(prd_mod);
		PR_INCR_KSTAT(pr_failed);
		page_unlock(pp);
		return (page_retire_done(pp, PRD_FAILED));
	}

	if (PP_ISKVP(pp)) {
		PR_DEBUG(prd_kern);
		PR_INCR_KSTAT(pr_failed_kernel);
		page_unlock(pp);
		return (page_retire_done(pp, PRD_FAILED));
	}

	if (pp->p_lckcnt || pp->p_cowcnt) {
		PR_DEBUG(prd_locked);
		PR_INCR_KSTAT(pr_failed);
		page_unlock(pp);
		return (page_retire_done(pp, PRD_FAILED));
	}

	(void) hat_pageunload(pp, HAT_FORCE_PGUNLOAD);
	ASSERT(!PP_ISFREE(pp));
	ASSERT(!hat_page_is_mapped(pp));

	/*
	 * If the page is modified, and was not relocated; we can't
	 * retire it without dropping data on the floor. We have to
	 * recheck after unloading since the dirty bit could have been
	 * set since we last checked.
	 */
	if (hat_ismod(pp)) {
		PR_DEBUG(prd_mod_late);
		PR_INCR_KSTAT(pr_failed);
		page_unlock(pp);
		return (page_retire_done(pp, PRD_FAILED));
	}

	if (pp->p_vnode) {
		PR_DEBUG(prd_hashout);
		page_hashout(pp, NULL);
	}
	ASSERT(!pp->p_vnode);

	/*
	 * The problem page is locked, demoted, unmapped, not free,
	 * hashed out, and not COW or mlocked (whew!).
	 *
	 * Now we select our ammunition, take it around back, and shoot it.
	 */
	if (toxic & PR_UE) {
		if (page_retire_transient_ue(pp)) {
			PR_DEBUG(prd_uescrubbed);
			return (page_retire_done(pp, PRD_UE_SCRUBBED));
		} else {
			PR_DEBUG(prd_uenotscrubbed);
			page_retire_destroy(pp);
			return (page_retire_done(pp, PRD_SUCCESS));
		}
	} else if (toxic & PR_FMA) {
		PR_DEBUG(prd_fma);
		page_retire_destroy(pp);
		return (page_retire_done(pp, PRD_SUCCESS));
	} else if (toxic & PR_MCE) {
		PR_DEBUG(prd_mce);
		page_retire_destroy(pp);
		return (page_retire_done(pp, PRD_SUCCESS));
	}
	panic("page_retire_pp: bad toxic flags %d", toxic);
	/*NOTREACHED*/
}

/*
 * Try to retire a page when we stumble onto it in the page lock routines.
 */
void
page_tryretire(page_t *pp)
{
	ASSERT(PAGE_EXCL(pp));

	if (!pr_enable) {
		page_unlock(pp);
		return;
	}

	/*
	 * If the page is a big page, try to break it up.
	 *
	 * If there are other bad pages besides `pp', they will be
	 * recursively retired for us thanks to a bit of magic.
	 * If the page is a small page with errors, try to retire it.
	 */
	if (pp->p_szc > 0) {
		if (PP_ISFREE(pp) && !page_try_demote_free_pages(pp)) {
			page_unlock(pp);
			PR_DEBUG(prd_nofreedemote);
			return;
		} else if (!page_try_demote_pages(pp)) {
			page_unlock(pp);
			PR_DEBUG(prd_nodemote);
			return;
		}
		PR_DEBUG(prd_demoted);
		page_unlock(pp);
	} else {
		(void) page_retire_pp(pp);
	}
}

/*
 * page_retire() - the front door in to retire a page.
 *
 * Ideally, page_retire() would instantly retire the requested page.
 * Unfortunately, some pages are locked or otherwise tied up and cannot be
 * retired right away. To deal with that, bits are set in p_toxic of the
 * page_t. An attempt is made to lock the page; if the attempt is successful,
 * we instantly unlock the page counting on page_unlock() to notice p_toxic
 * is nonzero and to call back into page_retire_pp(). Success is determined
 * by looking to see whether the page has been retired once it has been
 * unlocked.
 *
 * Returns:
 *
 *   - 0 on success,
 *   - EINVAL when the PA is whacko,
 *   - EBUSY if the page is already retired, or
 *   - EAGAIN if the page could not be _immediately_ retired.
 */
int
page_retire(uint64_t pa, uchar_t reason)
{
	page_t	*pp;

	ASSERT(reason & PR_REASONS);		/* there must be a reason */
	ASSERT(!(reason & ~PR_REASONS));	/* but no other bits */

	pp = page_numtopp_nolock(mmu_btop(pa));
	if (pp == NULL) {
		PR_MESSAGE(CE_WARN, 1, "Cannot schedule clearing of error on"
		    " page 0x%08x.%08x; page is not relocatable memory", pa);
		return (page_retire_done(pp, PRD_INVALID_PA));
	}
	if (PP_RETIRED(pp)) {
		return (page_retire_done(pp, PRD_DUPLICATE));
	}

	if (reason & PR_UE) {
		PR_MESSAGE(CE_NOTE, 1, "Scheduling clearing of error on"
		    " page 0x%08x.%08x", pa);
	} else {
		PR_MESSAGE(CE_NOTE, 1, "Scheduling removal of"
		    " page 0x%08x.%08x", pa);
	}
	page_settoxic(pp, reason);
	page_retire_enqueue(pp);

	/*
	 * And now for some magic.
	 *
	 * We marked this page toxic up above.  All there is left to do is
	 * to try to lock the page and then unlock it.  The page lock routines
	 * will intercept the page and retire it if they can.  If the page
	 * cannot be locked, 's okay -- page_unlock() will eventually get it,
	 * or the background thread, until then the lock routines will deny
	 * further locks on it.
	 */
	if (MTBF(pr_calls, pr_mtbf) && page_trylock(pp, SE_EXCL)) {
		PR_DEBUG(prd_prlocked);
		page_unlock(pp);
	} else {
		PR_DEBUG(prd_prnotlocked);
	}

	if (PP_RETIRED(pp)) {
		PR_DEBUG(prd_prretired);
		return (0);
	} else {
		cv_signal(&pr_cv);
		PR_INCR_KSTAT(pr_failed);

		if (pp->p_toxic & PR_MSG) {
			return (page_retire_done(pp, PRD_FAILED));
		} else {
			return (page_retire_done(pp, PRD_PENDING));
		}
	}
}

/*
 * Take a retired page off the retired-pages vnode and clear the toxic flags.
 * If "free" is nonzero, lock it and put it back on the freelist. If "free"
 * is zero, the caller already holds SE_EXCL lock so we simply unretire it
 * and don't do anything else with it.
 *
 * Any unretire messages are printed from this routine.
 *
 * Returns 0 if page pp was unretired; else an error code.
 */
int
page_unretire_pp(page_t *pp, int free)
{
	/*
	 * To be retired, a page has to be hashed onto the retired_pages vnode
	 * and have PR_RETIRED set in p_toxic.
	 */
	if (free == 0 || page_try_reclaim_lock(pp, SE_EXCL, SE_RETIRED)) {
		ASSERT(PAGE_EXCL(pp));
		PR_DEBUG(prd_ulocked);
		if (!PP_RETIRED(pp)) {
			PR_DEBUG(prd_unotretired);
			page_unlock(pp);
			return (page_retire_done(pp, PRD_UNR_NOT));
		}

		PR_MESSAGE(CE_NOTE, 1, "unretiring retired"
		    " page 0x%08x.%08x", mmu_ptob(pp->p_pagenum));
		if (pp->p_toxic & PR_FMA) {
			PR_DECR_KSTAT(pr_fma);
		} else if (pp->p_toxic & PR_UE) {
			PR_DECR_KSTAT(pr_ue);
		} else {
			PR_DECR_KSTAT(pr_mce);
		}
		page_clrtoxic(pp, PR_ALLFLAGS);

		if (free) {
			PR_DEBUG(prd_udestroy);
			page_destroy(pp, 0);
		} else {
			PR_DEBUG(prd_uhashout);
			page_hashout(pp, NULL);
		}

		mutex_enter(&freemem_lock);
		availrmem++;
		mutex_exit(&freemem_lock);

		PR_DEBUG(prd_uunretired);
		PR_DECR_KSTAT(pr_retired);
		PR_INCR_KSTAT(pr_unretired);
		return (page_retire_done(pp, PRD_UNR_SUCCESS));
	}
	PR_DEBUG(prd_unotlocked);
	return (page_retire_done(pp, PRD_UNR_CANTLOCK));
}

/*
 * Return a page to service by moving it from the retired_pages vnode
 * onto the freelist.
 *
 * Called from mmioctl_page_retire() on behalf of the FMA DE.
 *
 * Returns:
 *
 *   - 0 if the page is unretired,
 *   - EAGAIN if the pp can not be locked,
 *   - EINVAL if the PA is whacko, and
 *   - EBADF if the pp is not retired.
 */
int
page_unretire(uint64_t pa)
{
	page_t	*pp;

	pp = page_numtopp_nolock(mmu_btop(pa));
	if (pp == NULL) {
		return (page_retire_done(pp, PRD_INVALID_PA));
	}

	return (page_unretire_pp(pp, 1));
}

/*
 * Test a page to see if it is retired. If errors is non-NULL, the toxic
 * bits of the page are returned. Returns 0 on success, error code on failure.
 */
int
page_retire_check_pp(page_t *pp, uint64_t *errors)
{
	int rc;

	if (PP_RETIRED(pp)) {
		PR_DEBUG(prd_checkhit);
		rc = 0;
	} else {
		PR_DEBUG(prd_checkmiss);
		rc = EAGAIN;
	}

	/*
	 * We have magically arranged the bit values returned to fmd(1M)
	 * to line up with the FMA, MCE, and UE bits of the page_t.
	 */
	if (errors) {
		uint64_t toxic = (uint64_t)(pp->p_toxic & PR_ERRMASK);
		if (toxic & PR_UE_SCRUBBED) {
			toxic &= ~PR_UE_SCRUBBED;
			toxic |= PR_UE;
		}
		*errors = toxic;
	}

	return (rc);
}

/*
 * Test to see if the page_t for a given PA is retired, and return the
 * hardware errors we have seen on the page if requested.
 *
 * Called from mmioctl_page_retire on behalf of the FMA DE.
 *
 * Returns:
 *
 *   - 0 if the page is retired,
 *   - EAGAIN if it is not, and
 *   - EINVAL if the PA is whacko.
 */
int
page_retire_check(uint64_t pa, uint64_t *errors)
{
	page_t	*pp;

	if (errors) {
		*errors = 0;
	}

	pp = page_numtopp_nolock(mmu_btop(pa));
	if (pp == NULL) {
		return (page_retire_done(pp, PRD_INVALID_PA));
	}

	return (page_retire_check_pp(pp, errors));
}

/*
 * Page retire self-test. For now, it always returns 0.
 */
int
page_retire_test(void)
{
	page_t *first, *pp, *cpp, *cpp2, *lpp;

	/*
	 * Tests the corner case where a large page can't be retired
	 * because one of the constituent pages is locked. We mark
	 * one page to be retired and try to retire it, and mark the
	 * other page to be retired but don't try to retire it, so
	 * that page_unlock() in the failure path will recurse and try
	 * to retire THAT page. This is the worst possible situation
	 * we can get ourselves into.
	 */
	memsegs_lock(0);
	pp = first = page_first();
	do {
		if (pp->p_szc && PP_PAGEROOT(pp) == pp) {
			cpp = pp + 1;
			lpp = PP_ISFREE(pp)? pp : pp + 2;
			cpp2 = pp + 3;
			if (!page_trylock(lpp, pp == lpp? SE_EXCL : SE_SHARED))
				continue;
			if (!page_trylock(cpp, SE_EXCL)) {
				page_unlock(lpp);
				continue;
			}
			page_settoxic(cpp, PR_FMA | PR_BUSY);
			page_settoxic(cpp2, PR_FMA);
			page_tryretire(cpp);	/* will fail */
			page_unlock(lpp);
			(void) page_retire(cpp->p_pagenum, PR_FMA);
			(void) page_retire(cpp2->p_pagenum, PR_FMA);
		}
	} while ((pp = page_next(pp)) != first);
	memsegs_unlock(0);

	return (0);
}
