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
 *
 * Copyright 2018 Joyent, Inc.
 */

#include <sys/t_lock.h>
#include <sys/memlist.h>
#include <sys/cpuvar.h>
#include <sys/vmem.h>
#include <sys/mman.h>
#include <sys/vm.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/debug.h>
#include <sys/vm_machparam.h>
#include <sys/tss.h>
#include <sys/vnode.h>
#include <vm/hat.h>
#include <vm/anon.h>
#include <vm/as.h>
#include <vm/page.h>
#include <vm/seg.h>
#include <vm/seg_kmem.h>
#include <vm/seg_map.h>
#include <vm/hat_i86.h>
#include <sys/promif.h>
#include <sys/x86_archext.h>
#include <sys/systm.h>
#include <sys/archsystm.h>
#include <sys/sunddi.h>
#include <sys/ddidmareq.h>
#include <sys/controlregs.h>
#include <sys/reboot.h>
#include <sys/kdi.h>
#include <sys/bootconf.h>
#include <sys/bootsvcs.h>
#include <sys/bootinfo.h>
#include <vm/kboot_mmu.h>

#ifdef __xpv
#include <sys/hypervisor.h>
#endif

#define	ON_USER_HAT(cpu) \
	((cpu)->cpu_m.mcpu_current_hat != NULL && \
	(cpu)->cpu_m.mcpu_current_hat != kas.a_hat)

/*
 * Flag is not set early in boot. Once it is set we are no longer
 * using boot's page tables.
 */
uint_t khat_running = 0;

/*
 * This procedure is callable only while the boot loader is in charge of the
 * MMU. It assumes that PA == VA for page table pointers.  It doesn't live in
 * kboot_mmu.c since it's used from common code.
 */
pfn_t
va_to_pfn(void *vaddr)
{
	uintptr_t	des_va = ALIGN2PAGE(vaddr);
	uintptr_t	va = des_va;
	size_t		len;
	uint_t		prot;
	pfn_t		pfn;

	if (khat_running)
		panic("va_to_pfn(): called too late\n");

	if (kbm_probe(&va, &len, &pfn, &prot) == 0)
		return (PFN_INVALID);
	if (va > des_va)
		return (PFN_INVALID);
	if (va < des_va)
		pfn += mmu_btop(des_va - va);
	return (pfn);
}

/*
 * Initialize a special area in the kernel that always holds some PTEs for
 * faster performance. This always holds segmap's PTEs.
 * In the 32 bit kernel this maps the kernel heap too.
 */
void
hat_kmap_init(uintptr_t base, size_t len)
{
	uintptr_t map_addr;	/* base rounded down to large page size */
	uintptr_t map_eaddr;	/* base + len rounded up */
	size_t map_len;
	caddr_t ptes;		/* mapping area in kernel for kmap ptes */
	size_t window_size;	/* size of mapping area for ptes */
	ulong_t htable_cnt;	/* # of page tables to cover map_len */
	ulong_t i;
	htable_t *ht;
	uintptr_t va;

	/*
	 * We have to map in an area that matches an entire page table.
	 * The PTEs are large page aligned to avoid spurious pagefaults
	 * on the hypervisor.
	 */
	map_addr = base & LEVEL_MASK(1);
	map_eaddr = (base + len + LEVEL_SIZE(1) - 1) & LEVEL_MASK(1);
	map_len = map_eaddr - map_addr;
	window_size = mmu_btop(map_len) * mmu.pte_size;
	window_size = (window_size + LEVEL_SIZE(1)) & LEVEL_MASK(1);
	htable_cnt = map_len >> LEVEL_SHIFT(1);

	/*
	 * allocate vmem for the kmap_ptes
	 */
	ptes = vmem_xalloc(heap_arena, window_size, LEVEL_SIZE(1), 0,
	    0, NULL, NULL, VM_SLEEP);
	mmu.kmap_htables =
	    kmem_alloc(htable_cnt * sizeof (htable_t *), KM_SLEEP);

	/*
	 * Map the page tables that cover kmap into the allocated range.
	 * Note we don't ever htable_release() the kmap page tables - they
	 * can't ever be stolen, freed, etc.
	 */
	for (va = map_addr, i = 0; i < htable_cnt; va += LEVEL_SIZE(1), ++i) {
		ht = htable_create(kas.a_hat, va, 0, NULL);
		if (ht == NULL)
			panic("hat_kmap_init: ht == NULL");
		mmu.kmap_htables[i] = ht;

		hat_devload(kas.a_hat, ptes + i * MMU_PAGESIZE,
		    MMU_PAGESIZE, ht->ht_pfn,
#ifdef __xpv
		    PROT_READ | HAT_NOSYNC | HAT_UNORDERED_OK,
#else
		    PROT_READ | PROT_WRITE | HAT_NOSYNC | HAT_UNORDERED_OK,
#endif
		    HAT_LOAD | HAT_LOAD_NOCONSIST);
	}

	/*
	 * set information in mmu to activate handling of kmap
	 */
	mmu.kmap_addr = map_addr;
	mmu.kmap_eaddr = map_eaddr;
	mmu.kmap_ptes = (x86pte_t *)ptes;
}

extern caddr_t	kpm_vbase;
extern size_t	kpm_size;

#ifdef __xpv
/*
 * Create the initial segkpm mappings for the hypervisor. To avoid having
 * to deal with page tables being read only, we make all mappings
 * read only at first.
 */
static void
xen_kpm_create(paddr_t paddr, level_t lvl)
{
	ulong_t pg_off;

	for (pg_off = 0; pg_off < LEVEL_SIZE(lvl); pg_off += MMU_PAGESIZE) {
		kbm_map((uintptr_t)kpm_vbase + paddr, (paddr_t)0, 0, 1);
		kbm_read_only((uintptr_t)kpm_vbase + paddr + pg_off,
		    paddr + pg_off);
	}
}

/*
 * Try to make all kpm mappings writable. Failures are ok, as those
 * are just pagetable, GDT, etc. pages.
 */
static void
xen_kpm_finish_init(void)
{
	pfn_t gdtpfn = mmu_btop(CPU->cpu_m.mcpu_gdtpa);
	pfn_t pfn;
	page_t *pp;

	for (pfn = 0; pfn < mfn_count; ++pfn) {
		/*
		 * skip gdt
		 */
		if (pfn == gdtpfn)
			continue;

		/*
		 * p_index is a hint that this is a pagetable
		 */
		pp = page_numtopp_nolock(pfn);
		if (pp && pp->p_index) {
			pp->p_index = 0;
			continue;
		}
		(void) xen_kpm_page(pfn, PT_VALID | PT_WRITABLE);
	}
}
#endif

/*
 * Routine to pre-allocate data structures for hat_kern_setup(). It computes
 * how many pagetables it needs by walking the boot loader's page tables.
 */
/*ARGSUSED*/
void
hat_kern_alloc(
	caddr_t	segmap_base,
	size_t	segmap_size,
	caddr_t	ekernelheap)
{
	uintptr_t	last_va = (uintptr_t)-1;	/* catch 1st time */
	uintptr_t	va = 0;
	size_t		size;
	pfn_t		pfn;
	uint_t		prot;
	uint_t		table_cnt = 1;
	uint_t		mapping_cnt;
	level_t		start_level;
	level_t		l;
	struct memlist	*pmem;
	level_t		lpagel = mmu.max_page_level;
	uint64_t	paddr;
	int64_t		psize;
	int		nwindows;

	if (kpm_size > 0) {
		/*
		 * Create the kpm page tables.  When running on the
		 * hypervisor these are made read/only at first.
		 * Later we'll add write permission where possible.
		 */
		for (pmem = phys_install; pmem; pmem = pmem->ml_next) {
			paddr = pmem->ml_address;
			psize = pmem->ml_size;
			while (psize >= MMU_PAGESIZE) {
				/* find the largest page size */
				for (l = lpagel; l > 0; l--) {
					if ((paddr & LEVEL_OFFSET(l)) == 0 &&
					    psize > LEVEL_SIZE(l))
						break;
				}

#if defined(__xpv)
				/*
				 * Create read/only mappings to avoid
				 * conflicting with pagetable usage
				 */
				xen_kpm_create(paddr, l);
#else
				kbm_map((uintptr_t)kpm_vbase + paddr, paddr,
				    l, 1);
#endif
				paddr += LEVEL_SIZE(l);
				psize -= LEVEL_SIZE(l);
			}
		}
	}

	/*
	 * If this machine doesn't have a kpm segment, we need to allocate
	 * a small number of 'windows' which can be used to map pagetables.
	 */
	nwindows = (kpm_size == 0) ? 2 * NCPU : 0;

#if defined(__xpv)
	/*
	 * On a hypervisor, these windows are also used by the xpv_panic
	 * code, where we need one window for each level of the pagetable
	 * hierarchy.
	 */
	nwindows = MAX(nwindows, mmu.max_level);
#endif

	if (nwindows != 0) {
		/*
		 * Create the page windows and 1 page of VA in
		 * which we map the PTEs of those windows.
		 */
		mmu.pwin_base = vmem_xalloc(heap_arena, nwindows * MMU_PAGESIZE,
		    LEVEL_SIZE(1), 0, 0, NULL, NULL, VM_SLEEP);
		ASSERT(nwindows <= MMU_PAGESIZE / mmu.pte_size);
		mmu.pwin_pte_va = vmem_xalloc(heap_arena, MMU_PAGESIZE,
		    MMU_PAGESIZE, 0, 0, NULL, NULL, VM_SLEEP);

		/*
		 * Find/Create the page table window mappings.
		 */
		paddr = 0;
		(void) find_pte((uintptr_t)mmu.pwin_base, &paddr, 0, 0);
		ASSERT(paddr != 0);
		ASSERT((paddr & MMU_PAGEOFFSET) == 0);
		mmu.pwin_pte_pa = paddr;
#ifdef __xpv
		(void) find_pte((uintptr_t)mmu.pwin_pte_va, NULL, 0, 0);
		kbm_read_only((uintptr_t)mmu.pwin_pte_va, mmu.pwin_pte_pa);
#else
		kbm_map((uintptr_t)mmu.pwin_pte_va, mmu.pwin_pte_pa, 0, 1);
#endif
	}

	/*
	 * Walk the boot loader's page tables and figure out
	 * how many tables and page mappings there will be.
	 */
	while (kbm_probe(&va, &size, &pfn, &prot) != 0) {
		/*
		 * At each level, if the last_va falls into a new htable,
		 * increment table_cnt. We can stop at the 1st level where
		 * they are in the same htable.
		 */
		start_level = 0;
		while (start_level <= mmu.max_page_level) {
			if (size == LEVEL_SIZE(start_level))
				break;
			start_level++;
		}

		for (l = start_level; l < mmu.max_level; ++l) {
			if (va >> LEVEL_SHIFT(l + 1) ==
			    last_va >> LEVEL_SHIFT(l + 1))
				break;
			++table_cnt;
		}
		last_va = va;
		l = (start_level == 0) ? 1 : start_level;
		va = (va & LEVEL_MASK(l)) + LEVEL_SIZE(l);
	}

	/*
	 * Besides the boot loader mappings, we're going to fill in
	 * the entire top level page table for the kernel. Make sure there's
	 * enough reserve for that too.
	 */
	table_cnt += mmu.top_level_count - ((kernelbase >>
	    LEVEL_SHIFT(mmu.max_level)) & (mmu.top_level_count - 1));

	/*
	 * Add 1/4 more into table_cnt for extra slop.  The unused
	 * slop is freed back when we htable_adjust_reserve() later.
	 */
	table_cnt += table_cnt >> 2;

	/*
	 * We only need mapping entries (hments) for shared pages.
	 * This should be far, far fewer than the total possible,
	 * We'll allocate enough for 1/16 of all possible PTEs.
	 */
	mapping_cnt = (table_cnt * mmu.ptes_per_table) >> 4;

	/*
	 * Now create the initial htable/hment reserves
	 */
	htable_initial_reserve(table_cnt);
	hment_reserve(mapping_cnt);
	x86pte_cpu_init(CPU);
}


/*
 * This routine handles the work of creating the kernel's initial mappings
 * by deciphering the mappings in the page tables created by the boot program.
 *
 * We maintain large page mappings, but only to a level 1 pagesize.
 * The boot loader can only add new mappings once this function starts.
 * In particular it can not change the pagesize used for any existing
 * mappings or this code breaks!
 */

void
hat_kern_setup(void)
{
	/*
	 * Attach htables to the existing pagetables
	 */
	/* BEGIN CSTYLED */
	htable_attach(kas.a_hat, 0, mmu.max_level, NULL,
#ifdef __xpv
	    mmu_btop(xen_info->pt_base - ONE_GIG));
#else
	    mmu_btop(getcr3_pa()));
#endif
	/* END CSTYLED */

#if defined(__xpv)
	/*
	 * Try to make the kpm mappings r/w. Failures here are OK, as
	 * it's probably just a pagetable
	 */
	xen_kpm_finish_init();
#endif

	/*
	 * The kernel HAT is now officially open for business.
	 */
	khat_running = 1;

	CPUSET_ATOMIC_ADD(kas.a_hat->hat_cpus, CPU->cpu_id);
	CPU->cpu_current_hat = kas.a_hat;
}

#ifndef __xpv

/*
 * Note that the INVPCID_ALL* variants can be used even in the !PCIDE case, but
 * INVPCID_ADDR isn't.
 */
static void
invpcid(uint64_t type, uint64_t pcid, uintptr_t addr)
{
	ulong_t	flag;
	uint64_t cr4;

	if (x86_use_invpcid == 1) {
		ASSERT(is_x86_feature(x86_featureset, X86FSET_INVPCID));
		invpcid_insn(type, pcid, addr);
		return;
	}

	switch (type) {
	case INVPCID_ALL_GLOBAL:
		flag = intr_clear();
		cr4 = getcr4();
		setcr4(cr4 & ~(ulong_t)CR4_PGE);
		setcr4(cr4 | CR4_PGE);
		intr_restore(flag);
		break;

	case INVPCID_ALL_NONGLOBAL:
		if (!(getcr4() & CR4_PCIDE)) {
			reload_cr3();
		} else {
			flag = intr_clear();
			cr4 = getcr4();
			setcr4(cr4 & ~(ulong_t)CR4_PGE);
			setcr4(cr4 | CR4_PGE);
			intr_restore(flag);
		}
		break;

	case INVPCID_ADDR:
		if (pcid == PCID_USER) {
			flag = intr_clear();
			ASSERT(addr < kernelbase);
			ASSERT(ON_USER_HAT(CPU));
			ASSERT(CPU->cpu_m.mcpu_kpti.kf_user_cr3 != 0);
			tr_mmu_flush_user_range(addr, MMU_PAGESIZE,
			    MMU_PAGESIZE, CPU->cpu_m.mcpu_kpti.kf_user_cr3);
			intr_restore(flag);
		} else {
			mmu_invlpg((caddr_t)addr);
		}
		break;

	default:
		panic("unsupported invpcid(%lu)", type);
		break;
	}
}

/*
 * Flush one kernel mapping.
 *
 * We want to assert on kernel space here mainly for reasoning about the PCIDE
 * case: namely, this flush should never need to flush a non-current PCID
 * mapping.  This presumes we never have reason to flush the kernel regions
 * available to PCID_USER (the trampolines and so on).  It also relies on
 * PCID_KERNEL == PCID_NONE.
 */
void
mmu_flush_tlb_kpage(uintptr_t va)
{
	ASSERT(va >= kernelbase);
	ASSERT(getpcid() == PCID_KERNEL);
	mmu_invlpg((caddr_t)va);
}

/*
 * Flush one mapping: local CPU version of hat_tlb_inval().
 *
 * If this is a userspace address in the PCIDE case, we need two invalidations,
 * one for any potentially stale PCID_USER mapping, as well as any established
 * while in the kernel.
 */
void
mmu_flush_tlb_page(uintptr_t va)
{
	ASSERT(getpcid() == PCID_KERNEL);

	if (va >= kernelbase) {
		mmu_flush_tlb_kpage(va);
		return;
	}

	if (!(getcr4() & CR4_PCIDE)) {
		mmu_invlpg((caddr_t)va);
		return;
	}

	/*
	 * Yes, kas will need to flush below kernelspace, at least during boot.
	 * But there's no PCID_USER context.
	 */
	if (ON_USER_HAT(CPU))
		invpcid(INVPCID_ADDR, PCID_USER, va);
	invpcid(INVPCID_ADDR, PCID_KERNEL, va);
}

static void
mmu_flush_tlb_range(uintptr_t addr, size_t len, size_t pgsz)
{
	EQUIV(addr < kernelbase, (addr + len - 1) < kernelbase);
	ASSERT(len > 0);
	ASSERT(pgsz != 0);

	if (!(getcr4() & CR4_PCIDE) || x86_use_invpcid == 1) {
		for (uintptr_t va = addr; va < (addr + len); va += pgsz)
			mmu_flush_tlb_page(va);
		return;
	}

	/*
	 * As an emulated invpcid() in the PCIDE case requires jumping
	 * cr3s, we batch the invalidations.  We should only need to flush the
	 * user range if we're on a user-space HAT.
	 */
	if (addr < kernelbase && ON_USER_HAT(CPU)) {
		ulong_t flag = intr_clear();
		ASSERT(CPU->cpu_m.mcpu_kpti.kf_user_cr3 != 0);
		tr_mmu_flush_user_range(addr, len, pgsz,
		    CPU->cpu_m.mcpu_kpti.kf_user_cr3);
		intr_restore(flag);
	}

	for (uintptr_t va = addr; va < (addr + len); va += pgsz)
		mmu_invlpg((caddr_t)va);
}

/*
 * MMU TLB (and PT cache) flushing on this CPU.
 *
 * FLUSH_TLB_ALL: invalidate everything, all PCIDs, all PT_GLOBAL.
 * FLUSH_TLB_NONGLOBAL: invalidate all PCIDs, excluding PT_GLOBAL
 * FLUSH_TLB_RANGE: invalidate the given range, including PCID_USER
 * mappings as appropriate.  If using invpcid, PT_GLOBAL mappings are not
 * invalidated.
 */
void
mmu_flush_tlb(flush_tlb_type_t type, tlb_range_t *range)
{
	ASSERT(getpcid() == PCID_KERNEL);

	switch (type) {
	case FLUSH_TLB_ALL:
		ASSERT(range == NULL);
		invpcid(INVPCID_ALL_GLOBAL, 0, 0);
		break;

	case FLUSH_TLB_NONGLOBAL:
		ASSERT(range == NULL);
		invpcid(INVPCID_ALL_NONGLOBAL, 0, 0);
		break;

	case FLUSH_TLB_RANGE: {
		mmu_flush_tlb_range(range->tr_va, TLB_RANGE_LEN(range),
		    LEVEL_SIZE(range->tr_level));
		break;
	}

	default:
		panic("invalid call mmu_flush_tlb(%d)", type);
		break;
	}
}

#endif /* ! __xpv */
