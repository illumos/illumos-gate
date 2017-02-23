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
 * Copyright (c) 2016 by Delphix. All rights reserved.
 */

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
 * UE pages without persistent errors are scrubbed and returned to service.
 * Recidivist pages, as well as FMA-directed requests for retirement, result
 * in the page being taken out of service. Once the decision is made to take
 * a page out of service, the page is cleared, hashed onto the retired_pages
 * vnode, marked as retired, and it is unlocked.  No other requesters (except
 * for unretire) are allowed to lock retired pages.
 *
 * The public routines return (sadly) 0 if they worked and a non-zero error
 * value if something went wrong. This is done for the ioctl side of the
 * world to allow errors to be reflected all the way out to user land. The
 * non-zero values are explained in comments atop each function.
 */

/*
 * Things to fix:
 *
 * 	1. Trying to retire non-relocatable kvp pages may result in a
 *      quagmire. This is because seg_kmem() no longer keeps its pages locked,
 *      and calls page_lookup() in the free path; since kvp pages are modified
 *      and don't have a usable backing store, page_retire() can't do anything
 *      with them, and we'll keep denying the lock to seg_kmem_free() in a
 *      vicious cycle. To prevent that, we don't deny locks to kvp pages, and
 *      hence only try to retire a page from page_unlock() in the free path.
 *      Since most kernel pages are indefinitely held anyway, and don't
 *      participate in I/O, this is of little consequence.
 *
 *      2. Low memory situations will be interesting. If we don't have
 *      enough memory for page_relocate() to succeed, we won't be able to
 *      retire dirty pages; nobody will be able to push them out to disk
 *      either, since we aggressively deny the page lock. We could change
 *      fsflush so it can recognize this situation, grab the lock, and push
 *      the page out, where we'll catch it in the free path and retire it.
 *
 *	3. Beware of places that have code like this in them:
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
 *      4. mdboot()'s call into page_retire_mdboot() should probably be
 *      moved lower. Where the call is made now, we can get into trouble
 *      by scrubbing a kernel page that is then accessed later.
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mman.h>
#include <sys/vnode.h>
#include <sys/vfs_opreg.h>
#include <sys/cmn_err.h>
#include <sys/ksynch.h>
#include <sys/thread.h>
#include <sys/disp.h>
#include <sys/ontrap.h>
#include <sys/vmsystm.h>
#include <sys/mem_config.h>
#include <sys/atomic.h>
#include <sys/callb.h>
#include <sys/kobj.h>
#include <vm/page.h>
#include <vm/vm_dep.h>
#include <vm/as.h>
#include <vm/hat.h>
#include <vm/seg_kmem.h>

/*
 * vnode for all pages which are retired from the VM system;
 */
vnode_t *retired_pages;

static int page_retire_pp_finish(page_t *, void *, uint_t);

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
	kstat_named_t	pr_pending_kas;
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
	{ "pages_pending_kas", 		KSTAT_DATA_UINT64},
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
	atomic_inc_64(&(page_retire_kstat.stat.value.ui64))
#define	PR_DECR_KSTAT(stat)	\
	atomic_dec_64(&(page_retire_kstat.stat.value.ui64))

#define	PR_KSTAT_RETIRED_CE	(page_retire_kstat.pr_mce.value.ui64)
#define	PR_KSTAT_RETIRED_FMA	(page_retire_kstat.pr_fma.value.ui64)
#define	PR_KSTAT_RETIRED_NOTUE	(PR_KSTAT_RETIRED_CE + PR_KSTAT_RETIRED_FMA)
#define	PR_KSTAT_PENDING	(page_retire_kstat.pr_pending.value.ui64)
#define	PR_KSTAT_PENDING_KAS	(page_retire_kstat.pr_pending_kas.value.ui64)
#define	PR_KSTAT_EQFAIL		(page_retire_kstat.pr_enqueue_fail.value.ui64)
#define	PR_KSTAT_DQFAIL		(page_retire_kstat.pr_dequeue_fail.value.ui64)

/*
 * page retire kstats to list all retired pages
 */
static int pr_list_kstat_update(kstat_t *ksp, int rw);
static int pr_list_kstat_snapshot(kstat_t *ksp, void *buf, int rw);
kmutex_t pr_list_kstat_mutex;

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

static void (*memscrub_notify_func)(uint64_t);

#ifdef	DEBUG
struct page_retire_debug {
	int prd_dup1;
	int prd_dup2;
	int prd_qdup;
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
	int prd_checkmiss_pend;
	int prd_checkmiss_noerr;
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
	if (PP_ISKAS(pp))			\
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
	{PRD_DUPLICATE,		0,	EIO,	2,
		"Page 0x%08x.%08x already retired or pending"},
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
	{PRD_UNR_NOT,		0,	EIO,	2,
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
 * Must be called with the page exclusively locked to prevent races which
 * may attempt to retire a page without any toxic bits set.
 * Note that the PR_CAPTURE bit can be cleared without the exclusive lock
 * being held as there is a separate mutex which protects that bit.
 */
void
page_clrtoxic(page_t *pp, uchar_t bits)
{
	ASSERT((bits & PR_CAPTURE) || PAGE_EXCL(pp));
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
		pa = mmu_ptob((uint64_t)pp->p_pagenum);
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
	 * Disable preemption to prevent the off chance that
	 * we migrate while in the middle of running through
	 * the bit pattern and run on a different processor
	 * than what we started on.
	 */
	kpreempt_disable();

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
	kpreempt_enable();
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
	 * If this page is a repeat offender, retire it under the
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

			page_clrtoxic(pp, PR_UE | PR_MCE | PR_MSG);

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

static int
pr_list_kstat_update(kstat_t *ksp, int rw)
{
	uint_t count;
	page_t *pp;
	kmutex_t *vphm;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	vphm = page_vnode_mutex(retired_pages);
	mutex_enter(vphm);
	/* Needs to be under a lock so that for loop will work right */
	if (retired_pages->v_pages == NULL) {
		mutex_exit(vphm);
		ksp->ks_ndata = 0;
		ksp->ks_data_size = 0;
		return (0);
	}

	count = 1;
	for (pp = retired_pages->v_pages->p_vpnext;
	    pp != retired_pages->v_pages; pp = pp->p_vpnext) {
		count++;
	}
	mutex_exit(vphm);

	ksp->ks_ndata = count;
	ksp->ks_data_size = count * 2 * sizeof (uint64_t);

	return (0);
}

/*
 * all spans will be pagesize and no coalescing will be done with the
 * list produced.
 */
static int
pr_list_kstat_snapshot(kstat_t *ksp, void *buf, int rw)
{
	kmutex_t *vphm;
	page_t *pp;
	struct memunit {
		uint64_t address;
		uint64_t size;
	} *kspmem;

	if (rw == KSTAT_WRITE)
		return (EACCES);

	ksp->ks_snaptime = gethrtime();

	kspmem = (struct memunit *)buf;

	vphm = page_vnode_mutex(retired_pages);
	mutex_enter(vphm);
	pp = retired_pages->v_pages;
	if (((caddr_t)kspmem >= (caddr_t)buf + ksp->ks_data_size) ||
	    (pp == NULL)) {
		mutex_exit(vphm);
		return (0);
	}
	kspmem->address = ptob(pp->p_pagenum);
	kspmem->size = PAGESIZE;
	kspmem++;
	for (pp = pp->p_vpnext; pp != retired_pages->v_pages;
	    pp = pp->p_vpnext, kspmem++) {
		if ((caddr_t)kspmem >= (caddr_t)buf + ksp->ks_data_size)
			break;
		kspmem->address = ptob(pp->p_pagenum);
		kspmem->size = PAGESIZE;
	}
	mutex_exit(vphm);

	return (0);
}

/*
 * page_retire_pend_count -- helper function for page_capture_thread,
 * returns the number of pages pending retirement.
 */
uint64_t
page_retire_pend_count(void)
{
	return (PR_KSTAT_PENDING);
}

uint64_t
page_retire_pend_kas_count(void)
{
	return (PR_KSTAT_PENDING_KAS);
}

void
page_retire_incr_pend_count(void *datap)
{
	PR_INCR_KSTAT(pr_pending);

	if ((datap == &kvp) || (datap == &zvp)) {
		PR_INCR_KSTAT(pr_pending_kas);
	}
}

void
page_retire_decr_pend_count(void *datap)
{
	PR_DECR_KSTAT(pr_pending);

	if ((datap == &kvp) || (datap == &zvp)) {
		PR_DECR_KSTAT(pr_pending_kas);
	}
}

/*
 * Initialize the page retire mechanism:
 *
 *   - Establish the correctable error retire limit.
 *   - Initialize locks.
 *   - Build the retired_pages vnode.
 *   - Set up the kstats.
 *   - Fire off the background thread.
 *   - Tell page_retire() it's OK to start retiring pages.
 */
void
page_retire_init(void)
{
	const fs_operation_def_t retired_vnodeops_template[] = {
		{ NULL, NULL }
	};
	struct vnodeops *vops;
	kstat_t *ksp;

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

	mutex_init(&pr_list_kstat_mutex, NULL, MUTEX_DEFAULT, NULL);
	ksp = kstat_create("unix", 0, "page_retire_list", "misc",
	    KSTAT_TYPE_RAW, 0, KSTAT_FLAG_VAR_SIZE | KSTAT_FLAG_VIRTUAL);
	if (ksp != NULL) {
		ksp->ks_update = pr_list_kstat_update;
		ksp->ks_snapshot = pr_list_kstat_snapshot;
		ksp->ks_lock = &pr_list_kstat_mutex;
		kstat_install(ksp);
	}

	memscrub_notify_func =
	    (void(*)(uint64_t))kobj_getsymvalue("memscrub_notify", 0);

	page_capture_register_callback(PC_RETIRE, -1, page_retire_pp_finish);
	pr_enable = 1;
}

/*
 * page_retire_hunt() callback for the retire thread.
 */
static void
page_retire_thread_cb(page_t *pp)
{
	PR_DEBUG(prd_tctop);
	if (!PP_ISKAS(pp) && page_trylock(pp, SE_EXCL)) {
		PR_DEBUG(prd_tclocked);
		page_unlock(pp);
	}
}

/*
 * Callback used by page_trycapture() to finish off retiring a page.
 * The page has already been cleaned and we've been given sole access to
 * it.
 * Always returns 0 to indicate that callback succeded as the callback never
 * fails to finish retiring the given page.
 */
/*ARGSUSED*/
static int
page_retire_pp_finish(page_t *pp, void *notused, uint_t flags)
{
	int		toxic;

	ASSERT(PAGE_EXCL(pp));
	ASSERT(pp->p_iolock_state == 0);
	ASSERT(pp->p_szc == 0);

	toxic = pp->p_toxic;

	/*
	 * The problem page is locked, demoted, unmapped, not free,
	 * hashed out, and not COW or mlocked (whew!).
	 *
	 * Now we select our ammunition, take it around back, and shoot it.
	 */
	if (toxic & PR_UE) {
ue_error:
		if (page_retire_transient_ue(pp)) {
			PR_DEBUG(prd_uescrubbed);
			(void) page_retire_done(pp, PRD_UE_SCRUBBED);
		} else {
			PR_DEBUG(prd_uenotscrubbed);
			page_retire_destroy(pp);
			(void) page_retire_done(pp, PRD_SUCCESS);
		}
		return (0);
	} else if (toxic & PR_FMA) {
		PR_DEBUG(prd_fma);
		page_retire_destroy(pp);
		(void) page_retire_done(pp, PRD_SUCCESS);
		return (0);
	} else if (toxic & PR_MCE) {
		PR_DEBUG(prd_mce);
		page_retire_destroy(pp);
		(void) page_retire_done(pp, PRD_SUCCESS);
		return (0);
	}

	/*
	 * When page_retire_first_ue is set to zero and a UE occurs which is
	 * transient, it's possible that we clear some flags set by a second
	 * UE error on the page which occurs while the first is currently being
	 * handled and thus we need to handle the case where none of the above
	 * are set.  In this instance, PR_UE_SCRUBBED should be set and thus
	 * we should execute the UE code above.
	 */
	if (toxic & PR_UE_SCRUBBED) {
		goto ue_error;
	}

	/*
	 * It's impossible to get here.
	 */
	panic("bad toxic flags 0x%x in page_retire_pp_finish\n", toxic);
	return (0);
}

/*
 * page_retire() - the front door in to retire a page.
 *
 * Ideally, page_retire() would instantly retire the requested page.
 * Unfortunately, some pages are locked or otherwise tied up and cannot be
 * retired right away.  We use the page capture logic to deal with this
 * situation as it will continuously try to retire the page in the background
 * if the first attempt fails.  Success is determined by looking to see whether
 * the page has been retired after the page_trycapture() attempt.
 *
 * Returns:
 *
 *   - 0 on success,
 *   - EINVAL when the PA is whacko,
 *   - EIO if the page is already retired or already pending retirement, or
 *   - EAGAIN if the page could not be _immediately_ retired but is pending.
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
		PR_DEBUG(prd_dup1);
		return (page_retire_done(pp, PRD_DUPLICATE));
	}

	if (memscrub_notify_func != NULL) {
		(void) memscrub_notify_func(pa);
	}

	if ((reason & PR_UE) && !PP_TOXIC(pp)) {
		PR_MESSAGE(CE_NOTE, 1, "Scheduling clearing of error on"
		    " page 0x%08x.%08x", pa);
	} else if (PP_PR_REQ(pp)) {
		PR_DEBUG(prd_dup2);
		return (page_retire_done(pp, PRD_DUPLICATE));
	} else {
		PR_MESSAGE(CE_NOTE, 1, "Scheduling removal of"
		    " page 0x%08x.%08x", pa);
	}

	/* Avoid setting toxic bits in the first place */
	if ((reason & (PR_FMA | PR_MCE)) && !(reason & PR_UE) &&
	    page_retire_limit()) {
		return (page_retire_done(pp, PRD_LIMIT));
	}

	if (MTBF(pr_calls, pr_mtbf)) {
		page_settoxic(pp, reason);
		if (page_trycapture(pp, 0, CAPTURE_RETIRE, pp->p_vnode) == 0) {
			PR_DEBUG(prd_prlocked);
		} else {
			PR_DEBUG(prd_prnotlocked);
		}
	} else {
		PR_DEBUG(prd_prnotlocked);
	}

	if (PP_RETIRED(pp)) {
		PR_DEBUG(prd_prretired);
		return (0);
	} else {
		cv_signal(&pc_cv);
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
 *
 * If flags is:
 *	PR_UNR_FREE - lock the page, clear the toxic flags and free it
 *	    to the freelist.
 *	PR_UNR_TEMP - lock the page, unretire it, leave the toxic
 *	    bits set as is and return it to the caller.
 *	PR_UNR_CLEAN - page is SE_EXCL locked, unretire it, clear the
 *	    toxic flags and return it to caller as is.
 */
int
page_unretire_pp(page_t *pp, int flags)
{
	/*
	 * To be retired, a page has to be hashed onto the retired_pages vnode
	 * and have PR_RETIRED set in p_toxic.
	 */
	if (flags == PR_UNR_CLEAN ||
	    page_try_reclaim_lock(pp, SE_EXCL, SE_RETIRED)) {
		ASSERT(PAGE_EXCL(pp));
		PR_DEBUG(prd_ulocked);
		if (!PP_RETIRED(pp)) {
			PR_DEBUG(prd_unotretired);
			page_unlock(pp);
			return (page_retire_done(pp, PRD_UNR_NOT));
		}

		PR_MESSAGE(CE_NOTE, 1, "unretiring retired"
		    " page 0x%08x.%08x", mmu_ptob((uint64_t)pp->p_pagenum));
		if (pp->p_toxic & PR_FMA) {
			PR_DECR_KSTAT(pr_fma);
		} else if (pp->p_toxic & PR_UE) {
			PR_DECR_KSTAT(pr_ue);
		} else {
			PR_DECR_KSTAT(pr_mce);
		}

		if (flags == PR_UNR_TEMP)
			page_clrtoxic(pp, PR_RETIRED);
		else
			page_clrtoxic(pp, PR_TOXICFLAGS);

		if (flags == PR_UNR_FREE) {
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
 *   - EIO if the pp is not retired.
 */
int
page_unretire(uint64_t pa)
{
	page_t	*pp;

	pp = page_numtopp_nolock(mmu_btop(pa));
	if (pp == NULL) {
		return (page_retire_done(pp, PRD_INVALID_PA));
	}

	return (page_unretire_pp(pp, PR_UNR_FREE));
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
	} else if (PP_PR_REQ(pp)) {
		PR_DEBUG(prd_checkmiss_pend);
		rc = EAGAIN;
	} else {
		PR_DEBUG(prd_checkmiss_noerr);
		rc = EIO;
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
 *   - EIO if the page is not retired and has no errors,
 *   - EAGAIN if the page is not retired but is pending; and
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

			/* fails */
			(void) page_retire(ptob(cpp->p_pagenum), PR_FMA);

			page_unlock(lpp);
			page_unlock(cpp);
			(void) page_retire(ptob(cpp->p_pagenum), PR_FMA);
			(void) page_retire(ptob(cpp2->p_pagenum), PR_FMA);
		}
	} while ((pp = page_next(pp)) != first);
	memsegs_unlock(0);

	return (0);
}
