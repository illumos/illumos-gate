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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/kmem.h>
#include <sys/atomic.h>
#include <sys/bitmap.h>
#include <sys/machparam.h>
#include <sys/machsystm.h>
#include <sys/mman.h>
#include <sys/systm.h>
#include <sys/cpuvar.h>
#include <sys/thread.h>
#include <sys/proc.h>
#include <sys/cpu.h>
#include <sys/kmem.h>
#include <sys/disp.h>
#include <sys/vmem.h>
#include <sys/vmsystm.h>
#include <sys/promif.h>
#include <sys/var.h>
#include <sys/x86_archext.h>
#include <sys/bootconf.h>
#include <sys/dumphdr.h>
#include <vm/seg_kmem.h>
#include <vm/seg_kpm.h>
#include <vm/hat.h>
#include <vm/hat_i86.h>
#include <sys/cmn_err.h>

kmem_cache_t *htable_cache;
extern cpuset_t khat_cpuset;

/*
 * The variable htable_reserve_amount, rather than HTABLE_RESERVE_AMOUNT,
 * is used in order to facilitate testing of the htable_steal() code.
 * By resetting htable_reserve_amount to a lower value, we can force
 * stealing to occur.  The reserve amount is a guess to get us through boot.
 */
#define	HTABLE_RESERVE_AMOUNT	(200)
uint_t htable_reserve_amount = HTABLE_RESERVE_AMOUNT;
kmutex_t htable_reserve_mutex;
uint_t htable_reserve_cnt;
htable_t *htable_reserve_pool;

/*
 * Used to hand test htable_steal().
 */
#ifdef DEBUG
ulong_t force_steal = 0;
ulong_t ptable_cnt = 0;
#endif

/*
 * This variable is so that we can tune this via /etc/system
 * Any value works, but a power of two <= mmu.ptes_per_table is best.
 */
uint_t htable_steal_passes = 8;

/*
 * mutex stuff for access to htable hash
 */
#define	NUM_HTABLE_MUTEX 128
kmutex_t htable_mutex[NUM_HTABLE_MUTEX];
#define	HTABLE_MUTEX_HASH(h) ((h) & (NUM_HTABLE_MUTEX - 1))

#define	HTABLE_ENTER(h)	mutex_enter(&htable_mutex[HTABLE_MUTEX_HASH(h)]);
#define	HTABLE_EXIT(h)	mutex_exit(&htable_mutex[HTABLE_MUTEX_HASH(h)]);

/*
 * forward declarations
 */
static void link_ptp(htable_t *higher, htable_t *new, uintptr_t vaddr);
static void unlink_ptp(htable_t *higher, htable_t *old, uintptr_t vaddr);
static void htable_free(htable_t *ht);
static x86pte_t *x86pte_access_pagetable(htable_t *ht);
static void x86pte_release_pagetable(htable_t *ht);
static x86pte_t x86pte_cas(htable_t *ht, uint_t entry, x86pte_t old,
	x86pte_t new);

/*
 * Address used for kernel page tables. See ptable_alloc() below.
 */
uintptr_t ptable_va = 0;
size_t	ptable_sz = 2 * MMU_PAGESIZE;

/*
 * A counter to track if we are stealing or reaping htables. When non-zero
 * htable_free() will directly free htables (either to the reserve or kmem)
 * instead of putting them in a hat's htable cache.
 */
uint32_t htable_dont_cache = 0;

/*
 * Track the number of active pagetables, so we can know how many to reap
 */
static uint32_t active_ptables = 0;

/*
 * Allocate a memory page for a hardware page table.
 *
 * The pages allocated for page tables are currently gotten in a hacked up
 * way. It works for now, but really needs to be fixed up a bit.
 *
 * During boot: The boot loader controls physical memory allocation via
 * boot_alloc(). To avoid conflict with vmem, we just do boot_alloc()s with
 * addresses less than kernelbase. These addresses are ignored when we take
 * over mappings from the boot loader.
 *
 * Post-boot: we currently use page_create_va() on the kvp with fake offsets,
 * segments and virt address. This is pretty bogus, but was copied from the
 * old hat_i86.c code. A better approach would be to have a custom
 * page_get_physical() interface that can specify either mnode random or
 * mnode local and takes a page from whatever color has the MOST available -
 * this would have a minimal impact on page coloring.
 *
 * For now the htable pointer in ht is only used to compute a unique vnode
 * offset for the page.
 */
static void
ptable_alloc(htable_t *ht)
{
	pfn_t pfn;
	page_t *pp;
	u_offset_t offset;
	static struct seg tmpseg;
	static int first_time = 1;

	/*
	 * Allocating the associated hardware page table is very different
	 * before boot has finished.  We get a physical page to from boot
	 * w/o eating up any kernel address space.
	 */
	ht->ht_pfn = PFN_INVALID;
	atomic_add_32(&active_ptables, 1);

	if (use_boot_reserve) {
		ASSERT(ptable_va != 0);

		/*
		 * Allocate, then demap the ptable_va, so that we're
		 * sure there exist page table entries for the addresses
		 */
		if (first_time) {
			first_time = 0;
			if ((uintptr_t)BOP_ALLOC(bootops, (caddr_t)ptable_va,
			    ptable_sz, BO_NO_ALIGN) != ptable_va)
				panic("BOP_ALLOC failed");

			hat_boot_demap(ptable_va);
			hat_boot_demap(ptable_va + MMU_PAGESIZE);
		}

		pfn = ((uintptr_t)BOP_EALLOC(bootops, 0, MMU_PAGESIZE,
		    BO_NO_ALIGN, BOPF_X86_ALLOC_PHYS)) >> MMU_PAGESHIFT;
		if (page_resv(1, KM_NOSLEEP) == 0)
			panic("page_resv() failed in ptable alloc");

		pp = page_numtopp_nolock(pfn);
		ASSERT(pp != NULL);
		if (pp->p_szc != 0)
			page_boot_demote(pp);
		pp = page_numtopp(pfn, SE_EXCL);
		ASSERT(pp != NULL);

	} else {
		/*
		 * Post boot get a page for the table.
		 *
		 * The first check is to see if there is memory in
		 * the system. If we drop to throttlefree, then fail
		 * the ptable_alloc() and let the stealing code kick in.
		 * Note that we have to do this test here, since the test in
		 * page_create_throttle() would let the NOSLEEP allocation
		 * go through and deplete the page reserves.
		 *
		 * The !NOMEMWAIT() lets pageout, fsflush, etc. skip this check.
		 */
		if (!NOMEMWAIT() && freemem <= throttlefree + 1)
			return;

#ifdef DEBUG
		/*
		 * This code makes htable_ steal() easier to test. By setting
		 * force_steal we force pagetable allocations to fall
		 * into the stealing code. Roughly 1 in ever "force_steal"
		 * page table allocations will fail.
		 */
		if (ht->ht_hat != kas.a_hat && force_steal > 1 &&
		    ++ptable_cnt > force_steal) {
			ptable_cnt = 0;
			return;
		}
#endif /* DEBUG */

		/*
		 * This code is temporary, so don't review too critically.
		 * I'm awaiting a new phys page allocator from Kit -- Joe
		 *
		 * We need assign an offset for the page to call
		 * page_create_va. To avoid conflicts with other pages,
		 * we get creative with the offset.
		 * for 32 bits, we pic an offset > 4Gig
		 * for 64 bits, pic an offset somewhere in the VA hole.
		 */
		offset = (uintptr_t)ht - kernelbase;
		offset <<= MMU_PAGESHIFT;
#if defined(__amd64)
		offset += mmu.hole_start;	/* something in VA hole */
#else
		offset += 1ULL << 40;		/* something > 4 Gig */
#endif

		if (page_resv(1, KM_NOSLEEP) == 0)
			return;

#ifdef DEBUG
		pp = page_exists(&kvp, offset);
		if (pp != NULL)
			panic("ptable already exists %p", pp);
#endif
		pp = page_create_va(&kvp, offset, MMU_PAGESIZE,
		    PG_EXCL | PG_NORELOC, &tmpseg,
		    (void *)((uintptr_t)ht << MMU_PAGESHIFT));
		if (pp == NULL)
			return;
		page_io_unlock(pp);
		page_hashout(pp, NULL);
		pfn = pp->p_pagenum;
	}
	page_downgrade(pp);
	ASSERT(PAGE_SHARED(pp));

	if (pfn == PFN_INVALID)
		panic("ptable_alloc(): Invalid PFN!!");
	ht->ht_pfn = pfn;
	HATSTAT_INC(hs_ptable_allocs);
}

/*
 * Free an htable's associated page table page.  See the comments
 * for ptable_alloc().
 */
static void
ptable_free(htable_t *ht)
{
	pfn_t pfn = ht->ht_pfn;
	page_t *pp;

	/*
	 * need to destroy the page used for the pagetable
	 */
	ASSERT(pfn != PFN_INVALID);
	HATSTAT_INC(hs_ptable_frees);
	atomic_add_32(&active_ptables, -1);
	pp = page_numtopp_nolock(pfn);
	if (pp == NULL)
		panic("ptable_free(): no page for pfn!");
	ASSERT(PAGE_SHARED(pp));
	ASSERT(pfn == pp->p_pagenum);

	/*
	 * Get an exclusive lock, might have to wait for a kmem reader.
	 */
	if (!page_tryupgrade(pp)) {
		page_unlock(pp);
		/*
		 * RFE: we could change this to not loop forever
		 * George Cameron had some idea on how to do that.
		 * For now looping works - it's just like sfmmu.
		 */
		while (!page_lock(pp, SE_EXCL, (kmutex_t *)NULL, P_RECLAIM))
			continue;
	}
	page_free(pp, 1);
	page_unresv(1);
	ht->ht_pfn = PFN_INVALID;
}

/*
 * Put one htable on the reserve list.
 */
static void
htable_put_reserve(htable_t *ht)
{
	ht->ht_hat = NULL;		/* no longer tied to a hat */
	ASSERT(ht->ht_pfn == PFN_INVALID);
	HATSTAT_INC(hs_htable_rputs);
	mutex_enter(&htable_reserve_mutex);
	ht->ht_next = htable_reserve_pool;
	htable_reserve_pool = ht;
	++htable_reserve_cnt;
	mutex_exit(&htable_reserve_mutex);
}

/*
 * Take one htable from the reserve.
 */
static htable_t *
htable_get_reserve(void)
{
	htable_t *ht = NULL;

	mutex_enter(&htable_reserve_mutex);
	if (htable_reserve_cnt != 0) {
		ht = htable_reserve_pool;
		ASSERT(ht != NULL);
		ASSERT(ht->ht_pfn == PFN_INVALID);
		htable_reserve_pool = ht->ht_next;
		--htable_reserve_cnt;
		HATSTAT_INC(hs_htable_rgets);
	}
	mutex_exit(&htable_reserve_mutex);
	return (ht);
}

/*
 * Allocate initial htables with page tables and put them on the kernel hat's
 * cache list.
 */
void
htable_initial_reserve(uint_t count)
{
	htable_t *ht;
	hat_t *hat = kas.a_hat;

	count += HTABLE_RESERVE_AMOUNT;
	while (count > 0) {
		ht = kmem_cache_alloc(htable_cache, KM_NOSLEEP);
		ASSERT(ht != NULL);

		ASSERT(use_boot_reserve);
		ht->ht_hat = kas.a_hat;	/* so htable_free() works */
		ht->ht_flags = 0;	/* so x86pte_zero works */
		ptable_alloc(ht);
		if (ht->ht_pfn == PFN_INVALID)
			panic("ptable_alloc() failed");

		x86pte_zero(ht, 0, mmu.ptes_per_table);

		ht->ht_next = hat->hat_ht_cached;
		hat->hat_ht_cached = ht;
		--count;
	}
}

/*
 * Readjust the reserves after a thread finishes using them.
 *
 * The first time this is called post boot, we'll also clear out the
 * extra boot htables that were put in the kernel hat's cache list.
 */
void
htable_adjust_reserve()
{
	static int first_time = 1;
	htable_t *ht;

	ASSERT(curthread != hat_reserves_thread);

	/*
	 * The first time this is called after we can steal, we free up the
	 * the kernel's cache htable list. It has lots of extra htable/page
	 * tables that were allocated for boot up.
	 */
	if (first_time) {
		first_time = 0;
		while ((ht = kas.a_hat->hat_ht_cached) != NULL) {
			kas.a_hat->hat_ht_cached = ht->ht_next;
			ASSERT(ht->ht_hat == kas.a_hat);
			ptable_free(ht);
			htable_put_reserve(ht);
		}
		return;
	}

	/*
	 * Free any excess htables in the reserve list
	 */
	while (htable_reserve_cnt > htable_reserve_amount) {
		ht = htable_get_reserve();
		if (ht == NULL)
			return;
		ASSERT(ht->ht_pfn == PFN_INVALID);
		kmem_cache_free(htable_cache, ht);
	}
}


/*
 * This routine steals htables from user processes for htable_alloc() or
 * for htable_reap().
 */
static htable_t *
htable_steal(uint_t cnt)
{
	hat_t		*hat = kas.a_hat;	/* list starts with khat */
	htable_t	*list = NULL;
	htable_t	*ht;
	htable_t	*higher;
	uint_t		h;
	uint_t		h_start;
	static uint_t	h_seed = 0;
	uint_t		e;
	uintptr_t	va;
	x86pte_t	pte;
	uint_t		stolen = 0;
	uint_t		pass;
	uint_t		threshold;

	/*
	 * Limit htable_steal_passes to something reasonable
	 */
	if (htable_steal_passes == 0)
		htable_steal_passes = 1;
	if (htable_steal_passes > mmu.ptes_per_table)
		htable_steal_passes = mmu.ptes_per_table;

	/*
	 * Loop through all user hats. The 1st pass takes cached htables that
	 * aren't in use. The later passes steal by removing mappings, too.
	 */
	atomic_add_32(&htable_dont_cache, 1);
	for (pass = 0; pass <= htable_steal_passes && stolen < cnt; ++pass) {
		threshold = pass * mmu.ptes_per_table / htable_steal_passes;
		hat = kas.a_hat;
		for (;;) {

			/*
			 * Clear the victim flag and move to next hat
			 */
			mutex_enter(&hat_list_lock);
			if (hat != kas.a_hat) {
				hat->hat_flags &= ~HAT_VICTIM;
				cv_broadcast(&hat_list_cv);
			}
			hat = hat->hat_next;

			/*
			 * Skip any hat that is already being stolen from.
			 *
			 * We skip SHARED hats, as these are dummy
			 * hats that host ISM shared page tables.
			 *
			 * We also skip if HAT_FREEING because hat_pte_unmap()
			 * won't zero out the PTE's. That would lead to hitting
			 * stale PTEs either here or under hat_unload() when we
			 * steal and unload the same page table in competing
			 * threads.
			 */
			while (hat != NULL &&
			    (hat->hat_flags &
			    (HAT_VICTIM | HAT_SHARED | HAT_FREEING)) != 0)
				hat = hat->hat_next;

			if (hat == NULL) {
				mutex_exit(&hat_list_lock);
				break;
			}

			/*
			 * Are we finished?
			 */
			if (stolen == cnt) {
				/*
				 * Try to spread the pain of stealing,
				 * move victim HAT to the end of the HAT list.
				 */
				if (pass >= 1 && cnt == 1 &&
				    kas.a_hat->hat_prev != hat) {

					/* unlink victim hat */
					if (hat->hat_prev)
						hat->hat_prev->hat_next =
						    hat->hat_next;
					else
						kas.a_hat->hat_next =
						    hat->hat_next;
					if (hat->hat_next)
						hat->hat_next->hat_prev =
						    hat->hat_prev;
					else
						kas.a_hat->hat_prev =
						    hat->hat_prev;


					/* relink at end of hat list */
					hat->hat_next = NULL;
					hat->hat_prev = kas.a_hat->hat_prev;
					if (hat->hat_prev)
						hat->hat_prev->hat_next = hat;
					else
						kas.a_hat->hat_next = hat;
					kas.a_hat->hat_prev = hat;

				}

				mutex_exit(&hat_list_lock);
				break;
			}

			/*
			 * Mark the HAT as a stealing victim.
			 */
			hat->hat_flags |= HAT_VICTIM;
			mutex_exit(&hat_list_lock);

			/*
			 * Take any htables from the hat's cached "free" list.
			 */
			hat_enter(hat);
			while ((ht = hat->hat_ht_cached) != NULL &&
			    stolen < cnt) {
				hat->hat_ht_cached = ht->ht_next;
				ht->ht_next = list;
				list = ht;
				++stolen;
			}
			hat_exit(hat);

			/*
			 * Don't steal on first pass.
			 */
			if (pass == 0 || stolen == cnt)
				continue;

			/*
			 * Search the active htables for one to steal.
			 * Start at a different hash bucket every time to
			 * help spread the pain of stealing.
			 */
			h = h_start = h_seed++ % hat->hat_num_hash;
			do {
				higher = NULL;
				HTABLE_ENTER(h);
				for (ht = hat->hat_ht_hash[h]; ht;
				    ht = ht->ht_next) {

					/*
					 * Can we rule out reaping?
					 */
					if (ht->ht_busy != 0 ||
					    (ht->ht_flags & HTABLE_SHARED_PFN)||
					    ht->ht_level > 0 ||
					    ht->ht_valid_cnt > threshold ||
					    ht->ht_lock_cnt != 0)
						continue;

					/*
					 * Increment busy so the htable can't
					 * disappear. We drop the htable mutex
					 * to avoid deadlocks with
					 * hat_pageunload() and the hment mutex
					 * while we call hat_pte_unmap()
					 */
					++ht->ht_busy;
					HTABLE_EXIT(h);

					/*
					 * Try stealing.
					 * - unload and invalidate all PTEs
					 */
					for (e = 0, va = ht->ht_vaddr;
					    e < ht->ht_num_ptes &&
					    ht->ht_valid_cnt > 0 &&
					    ht->ht_busy == 1 &&
					    ht->ht_lock_cnt == 0;
					    ++e, va += MMU_PAGESIZE) {
						pte = x86pte_get(ht, e);
						if (!PTE_ISVALID(pte))
							continue;
						hat_pte_unmap(ht, e,
						    HAT_UNLOAD, pte, NULL);
					}

					/*
					 * Reacquire htable lock. If we didn't
					 * remove all mappings in the table,
					 * or another thread added a new mapping
					 * behind us, give up on this table.
					 */
					HTABLE_ENTER(h);
					if (ht->ht_busy != 1 ||
					    ht->ht_valid_cnt != 0 ||
					    ht->ht_lock_cnt != 0) {
						--ht->ht_busy;
						continue;
					}

					/*
					 * Steal it and unlink the page table.
					 */
					higher = ht->ht_parent;
					unlink_ptp(higher, ht, ht->ht_vaddr);

					/*
					 * remove from the hash list
					 */
					if (ht->ht_next)
						ht->ht_next->ht_prev =
						    ht->ht_prev;

					if (ht->ht_prev) {
						ht->ht_prev->ht_next =
						    ht->ht_next;
					} else {
						ASSERT(hat->hat_ht_hash[h] ==
						    ht);
						hat->hat_ht_hash[h] =
						    ht->ht_next;
					}

					/*
					 * Break to outer loop to release the
					 * higher (ht_parent) pagtable. This
					 * spreads out the pain caused by
					 * pagefaults.
					 */
					ht->ht_next = list;
					list = ht;
					++stolen;
					break;
				}
				HTABLE_EXIT(h);
				if (higher != NULL)
					htable_release(higher);
				if (++h == hat->hat_num_hash)
					h = 0;
			} while (stolen < cnt && h != h_start);
		}
	}
	atomic_add_32(&htable_dont_cache, -1);
	return (list);
}


/*
 * This is invoked from kmem when the system is low on memory.  We try
 * to free hments, htables, and ptables to improve the memory situation.
 */
/*ARGSUSED*/
static void
htable_reap(void *handle)
{
	uint_t		reap_cnt;
	htable_t	*list;
	htable_t	*ht;

	HATSTAT_INC(hs_reap_attempts);
	if (!can_steal_post_boot)
		return;

	/*
	 * Try to reap 5% of the page tables bounded by a maximum of
	 * 5% of physmem and a minimum of 10.
	 */
	reap_cnt = MIN(MAX(physmem / 20, active_ptables / 20), 10);

	/*
	 * Let htable_steal() do the work, we just call htable_free()
	 */
	list = htable_steal(reap_cnt);
	while ((ht = list) != NULL) {
		list = ht->ht_next;
		HATSTAT_INC(hs_reaped);
		htable_free(ht);
	}

	/*
	 * Free up excess reserves
	 */
	htable_adjust_reserve();
	hment_adjust_reserve();
}

/*
 * allocate an htable, stealing one or using the reserve if necessary
 */
static htable_t *
htable_alloc(
	hat_t		*hat,
	uintptr_t	vaddr,
	level_t		level,
	htable_t	*shared)
{
	htable_t	*ht = NULL;
	uint_t		is_vlp;
	uint_t		is_bare = 0;
	uint_t		need_to_zero = 1;
	int		kmflags = (can_steal_post_boot ? KM_NOSLEEP : KM_SLEEP);

	if (level < 0 || level > TOP_LEVEL(hat))
		panic("htable_alloc(): level %d out of range\n", level);

	is_vlp = (hat->hat_flags & HAT_VLP) && level == VLP_LEVEL;
	if (is_vlp || shared != NULL)
		is_bare = 1;

	/*
	 * First reuse a cached htable from the hat_ht_cached field, this
	 * avoids unnecessary trips through kmem/page allocators. This is also
	 * what happens during use_boot_reserve.
	 */
	if (hat->hat_ht_cached != NULL && !is_bare) {
		hat_enter(hat);
		ht = hat->hat_ht_cached;
		if (ht != NULL) {
			hat->hat_ht_cached = ht->ht_next;
			need_to_zero = 0;
			/* XX64 ASSERT() they're all zero somehow */
			ASSERT(ht->ht_pfn != PFN_INVALID);
		}
		hat_exit(hat);
	}

	if (ht == NULL) {
		ASSERT(!use_boot_reserve);
		/*
		 * When allocating for hat_memload_arena, we use the reserve.
		 * Also use reserves if we are in a panic().
		 */
		if (curthread == hat_reserves_thread || panicstr != NULL) {
			ASSERT(panicstr != NULL || !is_bare);
			ASSERT(panicstr != NULL ||
			    curthread == hat_reserves_thread);
			ht = htable_get_reserve();
		} else {
			/*
			 * Donate successful htable allocations to the reserve.
			 */
			for (;;) {
				ASSERT(curthread != hat_reserves_thread);
				ht = kmem_cache_alloc(htable_cache, kmflags);
				if (ht == NULL)
					break;
				ht->ht_pfn = PFN_INVALID;
				if (curthread == hat_reserves_thread ||
				    panicstr != NULL ||
				    htable_reserve_cnt >= htable_reserve_amount)
					break;
				htable_put_reserve(ht);
			}
		}

		/*
		 * allocate a page for the hardware page table if needed
		 */
		if (ht != NULL && !is_bare) {
			ht->ht_hat = hat;
			ptable_alloc(ht);
			if (ht->ht_pfn == PFN_INVALID) {
				kmem_cache_free(htable_cache, ht);
				ht = NULL;
			}
		}
	}

	/*
	 * If allocations failed, kick off a kmem_reap() and resort to
	 * htable steal(). We may spin here if the system is very low on
	 * memory. If the kernel itself has consumed all memory and kmem_reap()
	 * can't free up anything, then we'll really get stuck here.
	 * That should only happen in a system where the administrator has
	 * misconfigured VM parameters via /etc/system.
	 */
	while (ht == NULL && can_steal_post_boot) {
		kmem_reap();
		ht = htable_steal(1);
		HATSTAT_INC(hs_steals);

		/*
		 * If we stole for a bare htable, release the pagetable page.
		 */
		if (ht != NULL && is_bare)
			ptable_free(ht);
	}

	/*
	 * All attempts to allocate or steal failed. This should only happen
	 * if we run out of memory during boot, due perhaps to a huge
	 * boot_archive. At this point there's no way to continue.
	 */
	if (ht == NULL)
		panic("htable_alloc(): couldn't steal\n");

	/*
	 * Shared page tables have all entries locked and entries may not
	 * be added or deleted.
	 */
	ht->ht_flags = 0;
	if (shared != NULL) {
		ASSERT(level == 0);
		ASSERT(shared->ht_valid_cnt > 0);
		ht->ht_flags |= HTABLE_SHARED_PFN;
		ht->ht_pfn = shared->ht_pfn;
		ht->ht_lock_cnt = 0;
		ht->ht_valid_cnt = 0;		/* updated in hat_share() */
		ht->ht_shares = shared;
		need_to_zero = 0;
	} else {
		ht->ht_shares = NULL;
		ht->ht_lock_cnt = 0;
		ht->ht_valid_cnt = 0;
	}

	/*
	 * setup flags, etc. for VLP htables
	 */
	if (is_vlp) {
		ht->ht_flags |= HTABLE_VLP;
		ht->ht_num_ptes = VLP_NUM_PTES;
		ASSERT(ht->ht_pfn == PFN_INVALID);
		need_to_zero = 0;
	} else if (level == mmu.max_level) {
		ht->ht_num_ptes = mmu.top_level_count;
	} else {
		ht->ht_num_ptes = mmu.ptes_per_table;
	}

	/*
	 * fill in the htable
	 */
	ht->ht_hat = hat;
	ht->ht_parent = NULL;
	ht->ht_vaddr = vaddr;
	ht->ht_level = level;
	ht->ht_busy = 1;
	ht->ht_next = NULL;
	ht->ht_prev = NULL;

	/*
	 * Zero out any freshly allocated page table
	 */
	if (need_to_zero)
		x86pte_zero(ht, 0, mmu.ptes_per_table);
	return (ht);
}

/*
 * Free up an htable, either to a hat's cached list, the reserves or
 * back to kmem.
 */
static void
htable_free(htable_t *ht)
{
	hat_t *hat = ht->ht_hat;

	/*
	 * If the process isn't exiting, cache the free htable in the hat
	 * structure. We always do this for the boot reserve. We don't
	 * do this if the hat is exiting or we are stealing/reaping htables.
	 */
	if (hat != NULL &&
	    !(ht->ht_flags & HTABLE_SHARED_PFN) &&
	    (use_boot_reserve ||
	    (!(hat->hat_flags & HAT_FREEING) && !htable_dont_cache))) {
		ASSERT((ht->ht_flags & HTABLE_VLP) == 0);
		ASSERT(ht->ht_pfn != PFN_INVALID);
		hat_enter(hat);
		ht->ht_next = hat->hat_ht_cached;
		hat->hat_ht_cached = ht;
		hat_exit(hat);
		return;
	}

	/*
	 * If we have a hardware page table, free it.
	 * We don't free page tables that are accessed by sharing someone else.
	 */
	if (ht->ht_flags & HTABLE_SHARED_PFN) {
		ASSERT(ht->ht_pfn != PFN_INVALID);
		ht->ht_pfn = PFN_INVALID;
	} else if (!(ht->ht_flags & HTABLE_VLP)) {
		ptable_free(ht);
	}

	/*
	 * If we are the thread using the reserves, put free htables
	 * into reserves.
	 */
	if (curthread == hat_reserves_thread ||
	    htable_reserve_cnt < htable_reserve_amount)
		htable_put_reserve(ht);
	else
		kmem_cache_free(htable_cache, ht);
}


/*
 * This is called when a hat is being destroyed or swapped out. We reap all
 * the remaining htables in the hat cache. If destroying all left over
 * htables are also destroyed.
 *
 * We also don't need to invalidate any of the PTPs nor do any demapping.
 */
void
htable_purge_hat(hat_t *hat)
{
	htable_t *ht;
	int h;

	/*
	 * Purge the htable cache if just reaping.
	 */
	if (!(hat->hat_flags & HAT_FREEING)) {
		atomic_add_32(&htable_dont_cache, 1);
		for (;;) {
			hat_enter(hat);
			ht = hat->hat_ht_cached;
			if (ht == NULL) {
				hat_exit(hat);
				break;
			}
			hat->hat_ht_cached = ht->ht_next;
			hat_exit(hat);
			htable_free(ht);
		}
		atomic_add_32(&htable_dont_cache, -1);
		return;
	}

	/*
	 * if freeing, no locking is needed
	 */
	while ((ht = hat->hat_ht_cached) != NULL) {
		hat->hat_ht_cached = ht->ht_next;
		htable_free(ht);
	}

	/*
	 * walk thru the htable hash table and free all the htables in it.
	 */
	for (h = 0; h < hat->hat_num_hash; ++h) {
		while ((ht = hat->hat_ht_hash[h]) != NULL) {
			if (ht->ht_next)
				ht->ht_next->ht_prev = ht->ht_prev;

			if (ht->ht_prev) {
				ht->ht_prev->ht_next = ht->ht_next;
			} else {
				ASSERT(hat->hat_ht_hash[h] == ht);
				hat->hat_ht_hash[h] = ht->ht_next;
			}
			htable_free(ht);
		}
	}
}

/*
 * Unlink an entry for a table at vaddr and level out of the existing table
 * one level higher. We are always holding the HASH_ENTER() when doing this.
 */
static void
unlink_ptp(htable_t *higher, htable_t *old, uintptr_t vaddr)
{
	uint_t		entry = htable_va2entry(vaddr, higher);
	x86pte_t	expect = MAKEPTP(old->ht_pfn, old->ht_level);
	x86pte_t	found;

	ASSERT(higher->ht_busy > 0);
	ASSERT(higher->ht_valid_cnt > 0);
	ASSERT(old->ht_valid_cnt == 0);
	found = x86pte_cas(higher, entry, expect, 0);
	if (found != expect)
		panic("Bad PTP found=" FMT_PTE ", expected=" FMT_PTE,
		    found, expect);
	HTABLE_DEC(higher->ht_valid_cnt);
}

/*
 * Link an entry for a new table at vaddr and level into the existing table
 * one level higher. We are always holding the HASH_ENTER() when doing this.
 */
static void
link_ptp(htable_t *higher, htable_t *new, uintptr_t vaddr)
{
	uint_t		entry = htable_va2entry(vaddr, higher);
	x86pte_t	newptp = MAKEPTP(new->ht_pfn, new->ht_level);
	x86pte_t	found;

	ASSERT(higher->ht_busy > 0);

	ASSERT(new->ht_level != mmu.max_level);

	HTABLE_INC(higher->ht_valid_cnt);

	found = x86pte_cas(higher, entry, 0, newptp);
	if ((found & ~PT_REF) != 0)
		panic("HAT: ptp not 0, found=" FMT_PTE, found);
}

/*
 * Release of an htable.
 *
 * During process exit, some empty page tables are not unlinked - hat_free_end()
 * cleans them up. Upper level pagetable (mmu.max_page_level and higher) are
 * only released during hat_free_end() or by htable_steal(). We always
 * release SHARED page tables.
 */
void
htable_release(htable_t *ht)
{
	uint_t		hashval;
	htable_t	*shared;
	htable_t	*higher;
	hat_t		*hat;
	uintptr_t	va;
	level_t		level;

	while (ht != NULL) {
		shared = NULL;
		for (;;) {
			hat = ht->ht_hat;
			va = ht->ht_vaddr;
			level = ht->ht_level;
			hashval = HTABLE_HASH(hat, va, level);

			/*
			 * The common case is that this isn't the last use of
			 * an htable so we don't want to free the htable.
			 */
			HTABLE_ENTER(hashval);
			ASSERT(ht->ht_lock_cnt == 0 || ht->ht_valid_cnt > 0);
			ASSERT(ht->ht_valid_cnt >= 0);
			ASSERT(ht->ht_busy > 0);
			if (ht->ht_valid_cnt > 0)
				break;
			if (ht->ht_busy > 1)
				break;

			/*
			 * we always release empty shared htables
			 */
			if (!(ht->ht_flags & HTABLE_SHARED_PFN)) {

				/*
				 * don't release if in address space tear down
				 */
				if (hat->hat_flags & HAT_FREEING)
					break;

				/*
				 * At and above max_page_level, free if it's for
				 * a boot-time kernel mapping below kernelbase.
				 */
				if (level >= mmu.max_page_level &&
				    (hat != kas.a_hat || va >= kernelbase))
					break;
			}

			/*
			 * remember if we destroy an htable that shares its PFN
			 * from elsewhere
			 */
			if (ht->ht_flags & HTABLE_SHARED_PFN) {
				ASSERT(ht->ht_level == 0);
				ASSERT(shared == NULL);
				shared = ht->ht_shares;
				HATSTAT_INC(hs_htable_unshared);
			}

			/*
			 * Handle release of a table and freeing the htable_t.
			 * Unlink it from the table higher (ie. ht_parent).
			 */
			ASSERT(ht->ht_lock_cnt == 0);
			higher = ht->ht_parent;
			ASSERT(higher != NULL);

			/*
			 * Unlink the pagetable.
			 */
			unlink_ptp(higher, ht, va);

			/*
			 * When any top level VLP page table entry changes, we
			 * must issue a reload of cr3 on all processors.
			 */
			if ((hat->hat_flags & HAT_VLP) &&
			    level == VLP_LEVEL - 1)
				hat_demap(hat, DEMAP_ALL_ADDR);

			/*
			 * remove this htable from its hash list
			 */
			if (ht->ht_next)
				ht->ht_next->ht_prev = ht->ht_prev;

			if (ht->ht_prev) {
				ht->ht_prev->ht_next = ht->ht_next;
			} else {
				ASSERT(hat->hat_ht_hash[hashval] == ht);
				hat->hat_ht_hash[hashval] = ht->ht_next;
			}
			HTABLE_EXIT(hashval);
			htable_free(ht);
			ht = higher;
		}

		ASSERT(ht->ht_busy >= 1);
		--ht->ht_busy;
		HTABLE_EXIT(hashval);

		/*
		 * If we released a shared htable, do a release on the htable
		 * from which it shared
		 */
		ht = shared;
	}
}

/*
 * Find the htable for the pagetable at the given level for the given address.
 * If found acquires a hold that eventually needs to be htable_release()d
 */
htable_t *
htable_lookup(hat_t *hat, uintptr_t vaddr, level_t level)
{
	uintptr_t	base;
	uint_t		hashval;
	htable_t	*ht = NULL;

	ASSERT(level >= 0);
	ASSERT(level <= TOP_LEVEL(hat));

	if (level == TOP_LEVEL(hat))
		base = 0;
	else
		base = vaddr & LEVEL_MASK(level + 1);

	hashval = HTABLE_HASH(hat, base, level);
	HTABLE_ENTER(hashval);
	for (ht = hat->hat_ht_hash[hashval]; ht; ht = ht->ht_next) {
		if (ht->ht_hat == hat &&
		    ht->ht_vaddr == base &&
		    ht->ht_level == level)
			break;
	}
	if (ht)
		++ht->ht_busy;

	HTABLE_EXIT(hashval);
	return (ht);
}

/*
 * Acquires a hold on a known htable (from a locked hment entry).
 */
void
htable_acquire(htable_t *ht)
{
	hat_t		*hat = ht->ht_hat;
	level_t		level = ht->ht_level;
	uintptr_t	base = ht->ht_vaddr;
	uint_t		hashval = HTABLE_HASH(hat, base, level);

	HTABLE_ENTER(hashval);
#ifdef DEBUG
	/*
	 * make sure the htable is there
	 */
	{
		htable_t	*h;

		for (h = hat->hat_ht_hash[hashval];
		    h && h != ht;
		    h = h->ht_next)
			;
		ASSERT(h == ht);
	}
#endif /* DEBUG */
	++ht->ht_busy;
	HTABLE_EXIT(hashval);
}

/*
 * Find the htable for the pagetable at the given level for the given address.
 * If found acquires a hold that eventually needs to be htable_release()d
 * If not found the table is created.
 *
 * Since we can't hold a hash table mutex during allocation, we have to
 * drop it and redo the search on a create. Then we may have to free the newly
 * allocated htable if another thread raced in and created it ahead of us.
 */
htable_t *
htable_create(
	hat_t		*hat,
	uintptr_t	vaddr,
	level_t		level,
	htable_t	*shared)
{
	uint_t		h;
	level_t		l;
	uintptr_t	base;
	htable_t	*ht;
	htable_t	*higher = NULL;
	htable_t	*new = NULL;

	if (level < 0 || level > TOP_LEVEL(hat))
		panic("htable_create(): level %d out of range\n", level);

	/*
	 * Create the page tables in top down order.
	 */
	for (l = TOP_LEVEL(hat); l >= level; --l) {
		new = NULL;
		if (l == TOP_LEVEL(hat))
			base = 0;
		else
			base = vaddr & LEVEL_MASK(l + 1);

		h = HTABLE_HASH(hat, base, l);
try_again:
		/*
		 * look up the htable at this level
		 */
		HTABLE_ENTER(h);
		if (l == TOP_LEVEL(hat)) {
			ht = hat->hat_htable;
		} else {
			for (ht = hat->hat_ht_hash[h]; ht; ht = ht->ht_next) {
				ASSERT(ht->ht_hat == hat);
				if (ht->ht_vaddr == base &&
				    ht->ht_level == l)
					break;
			}
		}

		/*
		 * if we found the htable, increment its busy cnt
		 * and if we had allocated a new htable, free it.
		 */
		if (ht != NULL) {
			/*
			 * If we find a pre-existing shared table, it must
			 * share from the same place.
			 */
			if (l == level && shared && ht->ht_shares &&
			    ht->ht_shares != shared) {
				panic("htable shared from wrong place "
				    "found htable=%p shared=%p", ht, shared);
			}
			++ht->ht_busy;
			HTABLE_EXIT(h);
			if (new)
				htable_free(new);
			if (higher != NULL)
				htable_release(higher);
			higher = ht;

		/*
		 * if we didn't find it on the first search
		 * allocate a new one and search again
		 */
		} else if (new == NULL) {
			HTABLE_EXIT(h);
			new = htable_alloc(hat, base, l,
			    l == level ? shared : NULL);
			goto try_again;

		/*
		 * 2nd search and still not there, use "new" table
		 * Link new table into higher, when not at top level.
		 */
		} else {
			ht = new;
			if (higher != NULL) {
				link_ptp(higher, ht, base);
				ht->ht_parent = higher;

				/*
				 * When any top level VLP page table changes,
				 * we must reload cr3 on all processors.
				 */
#ifdef __i386
				if (mmu.pae_hat &&
#else /* !__i386 */
				if ((hat->hat_flags & HAT_VLP) &&
#endif /* __i386 */
				    l == VLP_LEVEL - 1)
					hat_demap(hat, DEMAP_ALL_ADDR);
			}
			ht->ht_next = hat->hat_ht_hash[h];
			ASSERT(ht->ht_prev == NULL);
			if (hat->hat_ht_hash[h])
				hat->hat_ht_hash[h]->ht_prev = ht;
			hat->hat_ht_hash[h] = ht;
			HTABLE_EXIT(h);

			/*
			 * Note we don't do htable_release(higher).
			 * That happens recursively when "new" is removed by
			 * htable_release() or htable_steal().
			 */
			higher = ht;

			/*
			 * If we just created a new shared page table we
			 * increment the shared htable's busy count, so that
			 * it can't be the victim of a steal even if it's empty.
			 */
			if (l == level && shared) {
				(void) htable_lookup(shared->ht_hat,
				    shared->ht_vaddr, shared->ht_level);
				HATSTAT_INC(hs_htable_shared);
			}
		}
	}

	return (ht);
}

/*
 * Walk through a given htable looking for the first valid entry.  This
 * routine takes both a starting and ending address.  The starting address
 * is required to be within the htable provided by the caller, but there is
 * no such restriction on the ending address.
 *
 * If the routine finds a valid entry in the htable (at or beyond the
 * starting address), the PTE (and its address) will be returned.
 * This PTE may correspond to either a page or a pagetable - it is the
 * caller's responsibility to determine which.  If no valid entry is
 * found, 0 (and invalid PTE) and the next unexamined address will be
 * returned.
 *
 * The loop has been carefully coded for optimization.
 */
static x86pte_t
htable_scan(htable_t *ht, uintptr_t *vap, uintptr_t eaddr)
{
	uint_t e;
	x86pte_t found_pte = (x86pte_t)0;
	char *pte_ptr;
	char *end_pte_ptr;
	int l = ht->ht_level;
	uintptr_t va = *vap & LEVEL_MASK(l);
	size_t pgsize = LEVEL_SIZE(l);

	ASSERT(va >= ht->ht_vaddr);
	ASSERT(va <= HTABLE_LAST_PAGE(ht));

	/*
	 * Compute the starting index and ending virtual address
	 */
	e = htable_va2entry(va, ht);

	/*
	 * The following page table scan code knows that the valid
	 * bit of a PTE is in the lowest byte AND that x86 is little endian!!
	 */
	pte_ptr = (char *)x86pte_access_pagetable(ht);
	end_pte_ptr = pte_ptr + (ht->ht_num_ptes << mmu.pte_size_shift);
	pte_ptr += e << mmu.pte_size_shift;
	while (!PTE_ISVALID(*pte_ptr)) {
		va += pgsize;
		if (va >= eaddr)
			break;
		pte_ptr += mmu.pte_size;
		ASSERT(pte_ptr <= end_pte_ptr);
		if (pte_ptr == end_pte_ptr)
			break;
	}

	/*
	 * if we found a valid PTE, load the entire PTE
	 */
	if (va < eaddr && pte_ptr != end_pte_ptr) {
		if (mmu.pae_hat) {
			ATOMIC_LOAD64((x86pte_t *)pte_ptr, found_pte);
		} else {
			found_pte = *(x86pte32_t *)pte_ptr;
		}
	}
	x86pte_release_pagetable(ht);

#if defined(__amd64)
	/*
	 * deal with VA hole on amd64
	 */
	if (l == mmu.max_level && va >= mmu.hole_start && va <= mmu.hole_end)
		va = mmu.hole_end + va - mmu.hole_start;
#endif /* __amd64 */

	*vap = va;
	return (found_pte);
}

/*
 * Find the address and htable for the first populated translation at or
 * above the given virtual address.  The caller may also specify an upper
 * limit to the address range to search.  Uses level information to quickly
 * skip unpopulated sections of virtual address spaces.
 *
 * If not found returns NULL. When found, returns the htable and virt addr
 * and has a hold on the htable.
 */
x86pte_t
htable_walk(
	struct hat *hat,
	htable_t **htp,
	uintptr_t *vaddr,
	uintptr_t eaddr)
{
	uintptr_t va = *vaddr;
	htable_t *ht;
	htable_t *prev = *htp;
	level_t l;
	level_t max_mapped_level;
	x86pte_t pte;

	ASSERT(eaddr > va);

	/*
	 * If this is a user address, then we know we need not look beyond
	 * kernelbase.
	 */
	ASSERT(hat == kas.a_hat || eaddr <= kernelbase ||
	    eaddr == HTABLE_WALK_TO_END);
	if (hat != kas.a_hat && eaddr == HTABLE_WALK_TO_END)
		eaddr = kernelbase;

	/*
	 * If we're coming in with a previous page table, search it first
	 * without doing an htable_lookup(), this should be frequent.
	 */
	if (prev) {
		ASSERT(prev->ht_busy > 0);
		ASSERT(prev->ht_vaddr <= va);
		l = prev->ht_level;
		if (va <= HTABLE_LAST_PAGE(prev)) {
			pte = htable_scan(prev, &va, eaddr);

			if (PTE_ISPAGE(pte, l)) {
				*vaddr = va;
				*htp = prev;
				return (pte);
			}
		}

		/*
		 * We found nothing in the htable provided by the caller,
		 * so fall through and do the full search
		 */
		htable_release(prev);
	}

	/*
	 * Find the level of the largest pagesize used by this HAT.
	 */
	max_mapped_level = 0;
	for (l = 1; l <= mmu.max_page_level; ++l)
		if (hat->hat_pages_mapped[l] != 0)
			max_mapped_level = l;

	while (va < eaddr && va >= *vaddr) {
		ASSERT(!IN_VA_HOLE(va));

		/*
		 *  Find lowest table with any entry for given address.
		 */
		for (l = 0; l <= TOP_LEVEL(hat); ++l) {
			ht = htable_lookup(hat, va, l);
			if (ht != NULL) {
				pte = htable_scan(ht, &va, eaddr);
				if (PTE_ISPAGE(pte, l)) {
					*vaddr = va;
					*htp = ht;
					return (pte);
				}
				htable_release(ht);
				break;
			}

			/*
			 * The ht is never NULL at the top level since
			 * the top level htable is created in hat_alloc().
			 */
			ASSERT(l < TOP_LEVEL(hat));

			/*
			 * No htable covers the address. If there is no
			 * larger page size that could cover it, we
			 * skip to the start of the next page table.
			 */
			if (l >= max_mapped_level) {
				va = NEXT_ENTRY_VA(va, l + 1);
				break;
			}
		}
	}

	*vaddr = 0;
	*htp = NULL;
	return (0);
}

/*
 * Find the htable and page table entry index of the given virtual address
 * with pagesize at or below given level.
 * If not found returns NULL. When found, returns the htable, sets
 * entry, and has a hold on the htable.
 */
htable_t *
htable_getpte(
	struct hat *hat,
	uintptr_t vaddr,
	uint_t *entry,
	x86pte_t *pte,
	level_t level)
{
	htable_t	*ht;
	level_t		l;
	uint_t		e;

	ASSERT(level <= mmu.max_page_level);

	for (l = 0; l <= level; ++l) {
		ht = htable_lookup(hat, vaddr, l);
		if (ht == NULL)
			continue;
		e = htable_va2entry(vaddr, ht);
		if (entry != NULL)
			*entry = e;
		if (pte != NULL)
			*pte = x86pte_get(ht, e);
		return (ht);
	}
	return (NULL);
}

/*
 * Find the htable and page table entry index of the given virtual address.
 * There must be a valid page mapped at the given address.
 * If not found returns NULL. When found, returns the htable, sets
 * entry, and has a hold on the htable.
 */
htable_t *
htable_getpage(struct hat *hat, uintptr_t vaddr, uint_t *entry)
{
	htable_t	*ht;
	uint_t		e;
	x86pte_t	pte;

	ht = htable_getpte(hat, vaddr, &e, &pte, mmu.max_page_level);
	if (ht == NULL)
		return (NULL);

	if (entry)
		*entry = e;

	if (PTE_ISPAGE(pte, ht->ht_level))
		return (ht);
	htable_release(ht);
	return (NULL);
}


void
htable_init()
{
	/*
	 * To save on kernel VA usage, we avoid debug information in 32 bit
	 * kernels.
	 */
#if defined(__amd64)
	int	kmem_flags = KMC_NOHASH;
#elif defined(__i386)
	int	kmem_flags = KMC_NOHASH | KMC_NODEBUG;
#endif

	/*
	 * initialize kmem caches
	 */
	htable_cache = kmem_cache_create("htable_t",
	    sizeof (htable_t), 0, NULL, NULL,
	    htable_reap, NULL, hat_memload_arena, kmem_flags);
}

/*
 * get the pte index for the virtual address in the given htable's pagetable
 */
uint_t
htable_va2entry(uintptr_t va, htable_t *ht)
{
	level_t	l = ht->ht_level;

	ASSERT(va >= ht->ht_vaddr);
	ASSERT(va <= HTABLE_LAST_PAGE(ht));
	return ((va >> LEVEL_SHIFT(l)) & (ht->ht_num_ptes - 1));
}

/*
 * Given an htable and the index of a pte in it, return the virtual address
 * of the page.
 */
uintptr_t
htable_e2va(htable_t *ht, uint_t entry)
{
	level_t	l = ht->ht_level;
	uintptr_t va;

	ASSERT(entry < ht->ht_num_ptes);
	va = ht->ht_vaddr + ((uintptr_t)entry << LEVEL_SHIFT(l));

	/*
	 * Need to skip over any VA hole in top level table
	 */
#if defined(__amd64)
	if (ht->ht_level == mmu.max_level && va >= mmu.hole_start)
		va += ((mmu.hole_end - mmu.hole_start) + 1);
#endif

	return (va);
}

/*
 * The code uses compare and swap instructions to read/write PTE's to
 * avoid atomicity problems, since PTEs can be 8 bytes on 32 bit systems.
 * Again this can be optimized on 64 bit systems, since aligned load/store
 * will naturally be atomic.
 *
 * The combination of using kpreempt_disable()/_enable() and the hci_mutex
 * are used to ensure that an interrupt won't overwrite a temporary mapping
 * while it's in use. If an interrupt thread tries to access a PTE, it will
 * yield briefly back to the pinned thread which holds the cpu's hci_mutex.
 */

static struct hat_cpu_info init_hci;	/* used for cpu 0 */

/*
 * Initialize a CPU private window for mapping page tables.
 * There will be 3 total pages of addressing needed:
 *
 *	1 for r/w access to pagetables
 *	1 for r access when copying pagetables (hat_alloc)
 *	1 that will map the PTEs for the 1st 2, so we can access them quickly
 *
 * We use vmem_xalloc() to get a correct alignment so that only one
 * hat_mempte_setup() is needed.
 */
void
x86pte_cpu_init(cpu_t *cpu, void *pages)
{
	struct hat_cpu_info *hci;
	caddr_t va;

	/*
	 * We can't use kmem_alloc/vmem_alloc for the 1st CPU, as this is
	 * called before we've activated our own HAT
	 */
	if (pages != NULL) {
		hci = &init_hci;
		va = pages;
	} else {
		hci = kmem_alloc(sizeof (struct hat_cpu_info), KM_SLEEP);
		va = vmem_xalloc(heap_arena, 3 * MMU_PAGESIZE, MMU_PAGESIZE, 0,
		    LEVEL_SIZE(1), NULL, NULL, VM_SLEEP);
	}
	mutex_init(&hci->hci_mutex, NULL, MUTEX_DEFAULT, NULL);

	/*
	 * If we are using segkpm, then there is no need for any of the
	 * mempte support.  We can access the desired memory through a kpm
	 * mapping rather than setting up a temporary mempte mapping.
	 */
	if (kpm_enable == 0) {
		hci->hci_mapped_pfn = PFN_INVALID;

		hci->hci_kernel_pte =
		    hat_mempte_kern_setup(va, va + (2 * MMU_PAGESIZE));
		hci->hci_pagetable_va = (void *)va;
	}

	cpu->cpu_hat_info = hci;
}

/*
 * Macro to establish temporary mappings for x86pte_XXX routines.
 */
#define	X86PTE_REMAP(addr, pte, index, perm, pfn)	{		\
		x86pte_t t;						\
									\
		t = MAKEPTE((pfn), 0) | (perm) | mmu.pt_global | mmu.pt_nx;\
		if (mmu.pae_hat)					\
			pte[index] = t;					\
		else							\
			((x86pte32_t *)(pte))[index] = t;		\
		mmu_tlbflush_entry((caddr_t)(addr));			\
}

/*
 * Disable preemption and establish a mapping to the pagetable with the
 * given pfn. This is optimized for there case where it's the same
 * pfn as we last used referenced from this CPU.
 */
static x86pte_t *
x86pte_access_pagetable(htable_t *ht)
{
	pfn_t pfn;
	struct hat_cpu_info *hci;

	/*
	 * VLP pagetables are contained in the hat_t
	 */
	if (ht->ht_flags & HTABLE_VLP)
		return (ht->ht_hat->hat_vlp_ptes);

	/*
	 * During early boot, use hat_boot_remap() of a page table adddress.
	 */
	pfn = ht->ht_pfn;
	ASSERT(pfn != PFN_INVALID);
	if (kpm_enable)
		return ((x86pte_t *)hat_kpm_pfn2va(pfn));

	if (!khat_running) {
		(void) hat_boot_remap(ptable_va, pfn);
		return ((x86pte_t *)ptable_va);
	}

	/*
	 * Normally, disable preemption and grab the CPU's hci_mutex
	 */
	kpreempt_disable();
	hci = CPU->cpu_hat_info;
	ASSERT(hci != NULL);
	mutex_enter(&hci->hci_mutex);
	if (hci->hci_mapped_pfn != pfn) {
		/*
		 * The current mapping doesn't already point to this page.
		 * Update the CPU specific pagetable mapping to map the pfn.
		 */
		X86PTE_REMAP(hci->hci_pagetable_va, hci->hci_kernel_pte, 0,
		    PT_WRITABLE, pfn);
		hci->hci_mapped_pfn = pfn;
	}
	return (hci->hci_pagetable_va);
}

/*
 * Release access to a page table.
 */
static void
x86pte_release_pagetable(htable_t *ht)
{
	struct hat_cpu_info *hci;

	if (kpm_enable)
		return;

	/*
	 * nothing to do for VLP htables
	 */
	if (ht->ht_flags & HTABLE_VLP)
		return;

	/*
	 * During boot-up hat_kern_setup(), erase the boot loader remapping.
	 */
	if (!khat_running) {
		hat_boot_demap(ptable_va);
		return;
	}

	/*
	 * Normal Operation: drop the CPU's hci_mutex and restore preemption
	 */
	hci = CPU->cpu_hat_info;
	ASSERT(hci != NULL);
	mutex_exit(&hci->hci_mutex);
	kpreempt_enable();
}

/*
 * Atomic retrieval of a pagetable entry
 */
x86pte_t
x86pte_get(htable_t *ht, uint_t entry)
{
	x86pte_t	pte;
	x86pte32_t	*pte32p;
	x86pte_t	*ptep;

	/*
	 * Be careful that loading PAE entries in 32 bit kernel is atomic.
	 */
	ptep = x86pte_access_pagetable(ht);
	if (mmu.pae_hat) {
		ATOMIC_LOAD64(ptep + entry, pte);
	} else {
		pte32p = (x86pte32_t *)ptep;
		pte = pte32p[entry];
	}
	x86pte_release_pagetable(ht);
	return (pte);
}

/*
 * Atomic unconditional set of a page table entry, it returns the previous
 * value.
 */
x86pte_t
x86pte_set(htable_t *ht, uint_t entry, x86pte_t new, void *ptr)
{
	x86pte_t	old;
	x86pte_t	prev, n;
	x86pte_t	*ptep;
	x86pte32_t	*pte32p;
	x86pte32_t	n32, p32;

	ASSERT(!(ht->ht_flags & HTABLE_SHARED_PFN));
	if (ptr == NULL) {
		ptep = x86pte_access_pagetable(ht);
		ptep = (void *)((caddr_t)ptep + (entry << mmu.pte_size_shift));
	} else {
		ptep = ptr;
	}

	if (mmu.pae_hat) {
		for (;;) {
			prev = *ptep;
			n = new;
			/*
			 * prevent potential data loss by preserving the MOD
			 * bit if set in the current PTE and the pfns are the
			 * same. For example, segmap can reissue a read-only
			 * hat_memload on top of a dirty page.
			 */
			if (PTE_ISVALID(prev) && PTE2PFN(prev, ht->ht_level) ==
			    PTE2PFN(n, ht->ht_level)) {
				n |= prev & (PT_REF | PT_MOD);
			}
			if (prev == n) {
				old = new;
				break;
			}
			old = cas64(ptep, prev, n);
			if (old == prev)
				break;
		}
	} else {
		pte32p = (x86pte32_t *)ptep;
		for (;;) {
			p32 = *pte32p;
			n32 = new;
			if (PTE_ISVALID(p32) && PTE2PFN(p32, ht->ht_level) ==
			    PTE2PFN(n32, ht->ht_level)) {
				n32 |= p32 & (PT_REF | PT_MOD);
			}
			if (p32 == n32) {
				old = new;
				break;
			}
			old = cas32(pte32p, p32, n32);
			if (old == p32)
				break;
		}
	}
	if (ptr == NULL)
		x86pte_release_pagetable(ht);
	return (old);
}

/*
 * Atomic compare and swap of a page table entry.
 */
static x86pte_t
x86pte_cas(htable_t *ht, uint_t entry, x86pte_t old, x86pte_t new)
{
	x86pte_t	pte;
	x86pte_t	*ptep;
	x86pte32_t	pte32, o32, n32;
	x86pte32_t	*pte32p;

	ASSERT(!(ht->ht_flags & HTABLE_SHARED_PFN));
	ptep = x86pte_access_pagetable(ht);
	if (mmu.pae_hat) {
		pte = cas64(&ptep[entry], old, new);
	} else {
		o32 = old;
		n32 = new;
		pte32p = (x86pte32_t *)ptep;
		pte32 = cas32(&pte32p[entry], o32, n32);
		pte = pte32;
	}
	x86pte_release_pagetable(ht);

	return (pte);
}

/*
 * data structure for cross call information
 */
typedef struct xcall_info {
	x86pte_t	xi_pte;
	x86pte_t	xi_old;
	x86pte_t	*xi_pteptr;
	pfn_t		xi_pfn;
	processorid_t	xi_cpuid;
	level_t		xi_level;
	xc_func_t	xi_func;
} xcall_info_t;

/*
 * Cross call service function to atomically invalidate a PTE and flush TLBs
 */
/*ARGSUSED*/
static int
x86pte_inval_func(xc_arg_t a1, xc_arg_t a2, xc_arg_t a3)
{
	xcall_info_t	*xi = (xcall_info_t *)a1;
	caddr_t		addr = (caddr_t)a2;

	/*
	 * Only the initiating cpu invalidates the page table entry.
	 * It returns the previous PTE value to the caller.
	 */
	if (CPU->cpu_id == xi->xi_cpuid) {
		x86pte_t	*ptep = xi->xi_pteptr;
		pfn_t		pfn = xi->xi_pfn;
		level_t		level = xi->xi_level;
		x86pte_t	old;
		x86pte_t	prev;
		x86pte32_t	*pte32p;
		x86pte32_t	p32;

		if (mmu.pae_hat) {
			for (;;) {
				prev = *ptep;
				if (PTE2PFN(prev, level) != pfn)
					break;
				old = cas64(ptep, prev, 0);
				if (old == prev)
					break;
			}
		} else {
			pte32p = (x86pte32_t *)ptep;
			for (;;) {
				p32 = *pte32p;
				if (PTE2PFN(p32, level) != pfn)
					break;
				old = cas32(pte32p, p32, 0);
				if (old == p32)
					break;
			}
			prev = p32;
		}
		xi->xi_pte = prev;
	}

	/*
	 * For a normal address, we just flush one page mapping
	 * Otherwise reload cr3 to effect a complete TLB flush.
	 *
	 * Note we don't reload VLP pte's -- this assume we never have a
	 * large page size at VLP_LEVEL for VLP processes.
	 */
	if ((uintptr_t)addr != DEMAP_ALL_ADDR) {
		mmu_tlbflush_entry(addr);
	} else {
		reload_cr3();
	}
	return (0);
}

/*
 * Cross call service function to atomically change a PTE and flush TLBs
 */
/*ARGSUSED*/
static int
x86pte_update_func(xc_arg_t a1, xc_arg_t a2, xc_arg_t a3)
{
	xcall_info_t	*xi = (xcall_info_t *)a1;
	caddr_t		addr = (caddr_t)a2;

	/*
	 * Only the initiating cpu changes the page table entry.
	 * It returns the previous PTE value to the caller.
	 */
	if (CPU->cpu_id == xi->xi_cpuid) {
		x86pte_t	*ptep = xi->xi_pteptr;
		x86pte_t	new = xi->xi_pte;
		x86pte_t	old = xi->xi_old;
		x86pte_t	prev;

		if (mmu.pae_hat) {
			prev = cas64(ptep, old, new);
		} else {
			x86pte32_t o32 = old;
			x86pte32_t n32 = new;
			x86pte32_t *pte32p = (x86pte32_t *)ptep;
			prev = cas32(pte32p, o32, n32);
		}

		xi->xi_pte = prev;
	}

	/*
	 * Flush the TLB entry
	 */
	if ((uintptr_t)addr != DEMAP_ALL_ADDR)
		mmu_tlbflush_entry(addr);
	else
		reload_cr3();
	return (0);
}

/*
 * Use cross calls to change a page table entry and invalidate TLBs.
 */
void
x86pte_xcall(hat_t *hat, xcall_info_t *xi, uintptr_t addr)
{
	cpuset_t	cpus;

	/*
	 * Given the current implementation of hat_share(), doing a
	 * hat_pageunload() on a shared page table requries invalidating
	 * all user TLB entries on all CPUs.
	 */
	if (hat->hat_flags & HAT_SHARED) {
		hat = kas.a_hat;
		addr = DEMAP_ALL_ADDR;
	}

	/*
	 * Use a cross call to do the invalidations.
	 * Note the current CPU always has to be in the cross call CPU set.
	 */
	kpreempt_disable();
	xi->xi_cpuid = CPU->cpu_id;
	CPUSET_ZERO(cpus);
	if (hat == kas.a_hat) {
		CPUSET_OR(cpus, khat_cpuset);
	} else {
		mutex_enter(&hat->hat_switch_mutex);
		CPUSET_OR(cpus, hat->hat_cpus);
		CPUSET_ADD(cpus, CPU->cpu_id);
	}

	/*
	 * Use a cross call to modify the page table entry and invalidate TLBs.
	 * If we're panic'ing, don't bother with the cross call.
	 * Note the panicstr check isn't bullet proof and the panic system
	 * ought to be made tighter.
	 */
	if (panicstr == NULL)
		xc_wait_sync((xc_arg_t)xi, addr, NULL, X_CALL_HIPRI,
			    cpus, xi->xi_func);
	else
		(void) xi->xi_func((xc_arg_t)xi, (xc_arg_t)addr, NULL);
	if (hat != kas.a_hat)
		mutex_exit(&hat->hat_switch_mutex);
	kpreempt_enable();
}

/*
 * Invalidate a page table entry if it currently maps the given pfn.
 * This returns the previous value of the PTE.
 */
x86pte_t
x86pte_invalidate_pfn(htable_t *ht, uint_t entry, pfn_t pfn, void *pte_ptr)
{
	xcall_info_t	xi;
	x86pte_t	*ptep;
	hat_t		*hat;
	uintptr_t	addr;

	ASSERT(!(ht->ht_flags & HTABLE_SHARED_PFN));
	if (pte_ptr != NULL) {
		ptep = pte_ptr;
	} else {
		ptep = x86pte_access_pagetable(ht);
		ptep = (void *)((caddr_t)ptep + (entry << mmu.pte_size_shift));
	}

	/*
	 * Fill in the structure used by the cross call function to do the
	 * invalidation.
	 */
	xi.xi_pte = 0;
	xi.xi_pteptr = ptep;
	xi.xi_pfn = pfn;
	xi.xi_level = ht->ht_level;
	xi.xi_func = x86pte_inval_func;
	ASSERT(xi.xi_level != VLP_LEVEL);

	hat = ht->ht_hat;
	addr = htable_e2va(ht, entry);

	x86pte_xcall(hat, &xi, addr);

	if (pte_ptr == NULL)
		x86pte_release_pagetable(ht);
	return (xi.xi_pte);
}

/*
 * update a PTE and invalidate any stale TLB entries.
 */
x86pte_t
x86pte_update(htable_t *ht, uint_t entry, x86pte_t expected, x86pte_t new)
{
	xcall_info_t	xi;
	x86pte_t	*ptep;
	hat_t		*hat;
	uintptr_t	addr;

	ASSERT(!(ht->ht_flags & HTABLE_SHARED_PFN));
	ptep = x86pte_access_pagetable(ht);
	ptep = (void *)((caddr_t)ptep + (entry << mmu.pte_size_shift));

	/*
	 * Fill in the structure used by the cross call function to do the
	 * invalidation.
	 */
	xi.xi_pte = new;
	xi.xi_old = expected;
	xi.xi_pteptr = ptep;
	xi.xi_func = x86pte_update_func;

	hat = ht->ht_hat;
	addr = htable_e2va(ht, entry);

	x86pte_xcall(hat, &xi, addr);

	x86pte_release_pagetable(ht);
	return (xi.xi_pte);
}

/*
 * Copy page tables - this is just a little more complicated than the
 * previous routines. Note that it's also not atomic! It also is never
 * used for VLP pagetables.
 */
void
x86pte_copy(htable_t *src, htable_t *dest, uint_t entry, uint_t count)
{
	struct hat_cpu_info *hci;
	caddr_t	src_va;
	caddr_t dst_va;
	size_t size;

	ASSERT(khat_running);
	ASSERT(!(dest->ht_flags & HTABLE_VLP));
	ASSERT(!(src->ht_flags & HTABLE_VLP));
	ASSERT(!(src->ht_flags & HTABLE_SHARED_PFN));
	ASSERT(!(dest->ht_flags & HTABLE_SHARED_PFN));

	/*
	 * Acquire access to the CPU pagetable window for the destination.
	 */
	dst_va = (caddr_t)x86pte_access_pagetable(dest);
	if (kpm_enable) {
		src_va = (caddr_t)x86pte_access_pagetable(src);
	} else {
		hci = CPU->cpu_hat_info;

		/*
		 * Finish defining the src pagetable mapping
		 */
		src_va = dst_va + MMU_PAGESIZE;
		X86PTE_REMAP(src_va, hci->hci_kernel_pte, 1, 0, src->ht_pfn);
	}

	/*
	 * now do the copy
	 */

	dst_va += entry << mmu.pte_size_shift;
	src_va += entry << mmu.pte_size_shift;
	size = count << mmu.pte_size_shift;
	bcopy(src_va, dst_va, size);

	x86pte_release_pagetable(dest);
}

/*
 * Zero page table entries - Note this doesn't use atomic stores!
 */
void
x86pte_zero(htable_t *dest, uint_t entry, uint_t count)
{
	caddr_t dst_va;
	x86pte_t *p;
	x86pte32_t *p32;
	size_t size;
	extern void hat_pte_zero(void *, size_t);

	/*
	 * Map in the page table to be zeroed.
	 */
	ASSERT(!(dest->ht_flags & HTABLE_SHARED_PFN));
	ASSERT(!(dest->ht_flags & HTABLE_VLP));
	dst_va = (caddr_t)x86pte_access_pagetable(dest);
	dst_va += entry << mmu.pte_size_shift;
	size = count << mmu.pte_size_shift;
	if (x86_feature & X86_SSE2) {
		hat_pte_zero(dst_va, size);
	} else if (khat_running) {
		bzero(dst_va, size);
	} else {
		/*
		 * Can't just use bzero during boot because it checks the
		 * address against kernelbase. Instead just use a zero loop.
		 */
		if (mmu.pae_hat) {
			p = (x86pte_t *)dst_va;
			while (count-- > 0)
				*p++ = 0;
		} else {
			p32 = (x86pte32_t *)dst_va;
			while (count-- > 0)
				*p32++ = 0;
		}
	}
	x86pte_release_pagetable(dest);
}

/*
 * Called to ensure that all pagetables are in the system dump
 */
void
hat_dump(void)
{
	hat_t *hat;
	uint_t h;
	htable_t *ht;

	/*
	 * Dump all page tables
	 */
	for (hat = kas.a_hat; hat != NULL; hat = hat->hat_next) {
		for (h = 0; h < hat->hat_num_hash; ++h) {
			for (ht = hat->hat_ht_hash[h]; ht; ht = ht->ht_next) {
				if ((ht->ht_flags & HTABLE_VLP) == 0)
					dump_page(ht->ht_pfn);
			}
		}
	}
}
