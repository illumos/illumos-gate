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

caddr_t
i86devmap(pfn_t pf, pgcnt_t pgcnt, uint_t prot)
{
	caddr_t addr;
	caddr_t addr1;
	page_t *pp;

	addr1 = addr = vmem_alloc(heap_arena, mmu_ptob(pgcnt), VM_SLEEP);

	for (; pgcnt != 0; addr += MMU_PAGESIZE, ++pf, --pgcnt) {
		pp = page_numtopp_nolock(pf);
		if (pp == NULL) {
			hat_devload(kas.a_hat, addr, MMU_PAGESIZE, pf,
			    prot | HAT_NOSYNC, HAT_LOAD_LOCK);
		} else {
			hat_memload(kas.a_hat, addr, pp,
			    prot | HAT_NOSYNC, HAT_LOAD_LOCK);
		}
	}

	return (addr1);
}

/*
 * This routine is like page_numtopp, but accepts only free pages, which
 * it allocates (unfrees) and returns with the exclusive lock held.
 * It is used by machdep.c/dma_init() to find contiguous free pages.
 */
page_t *
page_numtopp_alloc(pfn_t pfnum)
{
	page_t *pp;

retry:
	pp = page_numtopp_nolock(pfnum);
	if (pp == NULL) {
		return (NULL);
	}

	if (!page_trylock(pp, SE_EXCL)) {
		return (NULL);
	}

	if (page_pptonum(pp) != pfnum) {
		page_unlock(pp);
		goto retry;
	}

	if (!PP_ISFREE(pp)) {
		page_unlock(pp);
		return (NULL);
	}
	if (pp->p_szc) {
		page_demote_free_pages(pp);
		page_unlock(pp);
		goto retry;
	}

	/* If associated with a vnode, destroy mappings */

	if (pp->p_vnode) {

		page_destroy_free(pp);

		if (!page_lock(pp, SE_EXCL, (kmutex_t *)NULL, P_NO_RECLAIM)) {
			return (NULL);
		}

		if (page_pptonum(pp) != pfnum) {
			page_unlock(pp);
			goto retry;
		}
	}

	if (!PP_ISFREE(pp) || !page_reclaim(pp, (kmutex_t *)NULL)) {
		page_unlock(pp);
		return (NULL);
	}

	return (pp);
}

/*
 * The boot loader doesn't use PAE page tables for 32 bit platforms
 * so the definitions in hat_pte for LEVEL_SHIFT, etc. don't apply.
 */
#if defined(__i386)	/* 32 bit boot loader */

#define	BOOT_TOP_LEVEL	1
#define	BOOT_PTES_PER_TABLE 1024
#define	BOOT_PADDR	0xfffff000
static uint_t boot_shift[] = {12, 22};

#elif defined(__amd64)	/* 64 bit boot loader */

#define	BOOT_TOP_LEVEL	3
#define	BOOT_PTES_PER_TABLE 512
static uint_t boot_shift[] = {12, 21, 30, 39};
#define	BOOT_PADDR	PT_PADDR	/* boot won't use PAT, so this is ok */

#endif	/* __amd64 */

#define	BOOT_SHIFT(l)	(boot_shift[l])
#define	BOOT_SZ(l)	((size_t)1 << BOOT_SHIFT(l))
#define	BOOT_OFFSET(l)	(BOOT_SZ(l) - 1)
#define	BOOT_MASK(l)	(~BOOT_OFFSET(l))

/*
 * Flag is not set early in boot. Once it is set we are no longer
 * using boot's page tables.
 */
uint_t khat_running = 0;


/*
 * Probe the boot loader's page tables to find the first mapping
 * including va (or higher) and return non-zero if one is found.
 * va is updated to the starting address and len to the pagesize.
 * pp will be set to point to the 1st page_t of the mapped page(s).
 *
 * Note that if va is in the middle of a large page, the returned va
 * will be less than what was asked for.
 *
 * This works by walking the actual page table's currently in use
 * and rooted at control register 3. This code has the following fundamental
 * assumptions:
 *	- In 32 bit mode the boot loader never uses PAE, so the size/type
 *	  of boot pte_t is compatibile with uintptr_t
 *	- The 64 bit mode boot loader has enabled NX bit usage
 *	- The pagetables allocated by boot have identity mappings, ie.
 *	  Virtual address == Physical address
 */
int
hat_boot_probe(uintptr_t *va, size_t *len, pfn_t *pfn, uint_t *prot)
{
	uintptr_t	probe_va;
	uint_t		entry;
	uintptr_t	*top_ptable;
	uintptr_t	*ptable;
	level_t		l = BOOT_TOP_LEVEL;

	*len = 0;
	*pfn = PFN_INVALID;
	*prot = 0;
	probe_va = *va;
	top_ptable = (uintptr_t *)(getcr3() & MMU_PAGEMASK);
restart_new_va:
	l = BOOT_TOP_LEVEL;
	ptable = top_ptable;
	for (;;) {
		if (IN_VA_HOLE(probe_va))
			probe_va = mmu.hole_end;

		/*
		 * If we don't have a valid PTP/PTE at this level
		 * then we can bump VA by this level's pagesize and try again.
		 * When the probe_va wraps around, we are done.
		 */
		entry = (probe_va >> BOOT_SHIFT(l)) & (BOOT_PTES_PER_TABLE - 1);
		if (!PTE_ISVALID(ptable[entry])) {
			probe_va = (probe_va & BOOT_MASK(l)) + BOOT_SZ(l);
			if (probe_va <= *va)
				return (0);
			goto restart_new_va;
		}

		/*
		 * If this entry is a pointer to a lower level page table
		 * go down to it.
		 */
		if (!PTE_ISPAGE(ptable[entry], l)) {
			ASSERT(l > 0);
			--l;
			ptable = (uintptr_t *)(ptable[entry] & MMU_PAGEMASK);
			continue;
		}

		/*
		 * We found a boot level page table entry
		 */
		*len = BOOT_SZ(l);
		*va = probe_va & ~(*len - 1);
		*pfn = mmu_btop(ptable[entry] & BOOT_PADDR);


		*prot = PROT_READ | PROT_EXEC;
		if (PTE_GET(ptable[entry], PT_WRITABLE))
			*prot |= PROT_WRITE;

		/*
		 * pt_nx is cleared if processor doesn't support NX bit
		 */
		if (PTE_GET(ptable[entry], mmu.pt_nx))
			*prot &= ~PROT_EXEC;

		return (1);
	}
}


/*
 * Destroy a boot loader page table 4K mapping.
 * See hat_boot_probe() for assumptions.
 */
void
hat_boot_demap(uintptr_t va)
{
	uintptr_t	*ptable;
	level_t		level = BOOT_TOP_LEVEL;
	uint_t		entry;

	/*
	 * Walk down the page tables, which are 1 to 1 mapped, to the
	 * desired mapping.
	 */
	ptable = (uintptr_t *)(getcr3() & MMU_PAGEMASK);
	for (level = BOOT_TOP_LEVEL; ; --level) {

		entry = (va >> BOOT_SHIFT(level)) & (BOOT_PTES_PER_TABLE - 1);

		if (!PTE_ISVALID(ptable[entry]))
			panic("hat_boot_demap(): no pte at desired addr");

		if (level == 0)
			break;

		if (PTE_ISPAGE(ptable[entry], level))
			panic("hat_boot_demap(): large page at va");

		ptable = (uintptr_t *)(ptable[entry] & MMU_PAGEMASK);
	}

	/*
	 * We found a boot level page table entry, invalidate it
	 */
	ptable[entry] = 0;
	mmu_tlbflush_entry((caddr_t)va);
}


/*
 * Change a boot loader page table 4K mapping.
 * Returns the pfn of the old mapping.
 * See hat_boot_probe() for assumptions.
 */
pfn_t
hat_boot_remap(uintptr_t va, pfn_t pfn)
{
	uintptr_t	*ptable;
	level_t		level = BOOT_TOP_LEVEL;
	pfn_t		old_pfn;
	uint_t		entry;

	/*
	 * Walk down the page tables, which are 1 to 1 mapped, to the
	 * desired mapping.
	 */
	ptable = (uintptr_t *)(getcr3() & MMU_PAGEMASK);
	for (level = BOOT_TOP_LEVEL; ; --level) {

		entry = (va >> BOOT_SHIFT(level)) & (BOOT_PTES_PER_TABLE - 1);

		if (level == 0)
			break;

		if (!PTE_ISVALID(ptable[entry]))
			panic("hat_boot_remap(): no pte at desired addr");

		if (PTE_ISPAGE(ptable[entry], level))
			panic("hat_boot_remap(): large page at va");

		ptable = (uintptr_t *)(ptable[entry] & MMU_PAGEMASK);
	}

	/*
	 * We found a boot level page table entry, change it and return
	 * the old pfn. Assume full permissions.
	 */
	old_pfn = mmu_btop(ptable[entry] & BOOT_PADDR);
	ptable[entry] = mmu_ptob((uintptr_t)pfn) | PT_VALID | PT_WRITABLE;
	mmu_tlbflush_entry((caddr_t)va);
	return (old_pfn);
}

/*
 * This procedure is callable only while the boot loader is in charge
 * of the MMU. It assumes that PA == VA for page table pointers.
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

	if (hat_boot_probe(&va, &len, &pfn, &prot) == 0)
		return (PFN_INVALID);
	if (va > des_va)
		return (PFN_INVALID);
	if (va < des_va)
		pfn += mmu_btop(des_va - va);
	return (pfn);
}

/*
 * Routine to pre-allocate any htable's and hments that should be needed in
 * hat_kern_setup(). It computes how many pagetables it needs by walking the
 * boot loader's page tables.
 */
void
hat_kern_alloc()
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
	extern pgcnt_t	npages;
	extern pgcnt_t	boot_npages;

	/*
	 * Walk the boot loader's page tables and figure out
	 * how many tables and page mappings there will be.
	 */
	while (hat_boot_probe(&va, &size, &pfn, &prot) != 0) {
		/*
		 * At each level, if the last_va falls into a new htable,
		 * increment table_cnt. We can stop at the 1st level where
		 * they are in the same htable.
		 */
		if (size == MMU_PAGESIZE)
			start_level = 0;
		else
			start_level = 1;

		for (l = start_level; l < mmu.max_level; ++l) {
			if (va >> LEVEL_SHIFT(l + 1) ==
			    last_va >> LEVEL_SHIFT(l + 1))
				break;
			++table_cnt;
		}
		last_va = va;
		va += size;
	}

	/*
	 * Besides the boot loader mappings, we're going to fill in
	 * the entire top level page table for the kernel. Make sure there's
	 * enough reserve for that too.
	 */
	table_cnt += mmu.top_level_count - ((kernelbase >>
	    LEVEL_SHIFT(mmu.max_level)) & (mmu.top_level_count - 1));

	/*
	 * If we still have pages that need page_t's created for them, then
	 * make sure we create the pagetables needed to map them in.
	 *
	 * (yes.  We need pagetables to map the page_t's for the unmapped
	 * pages.  We also need pagetables to map the vmem structures
	 * allocated to support the VA range into which they are mapped.
	 * Does your head hurt yet?)
	 */
	if (boot_npages < npages) {
		pgcnt_t pages;
		pgcnt_t ptables;

		/*
		 * Number of pages needed for all the new pages_ts.  This
		 * assumes that they will all be mapped consecutively.
		 */
		pages = (npages - boot_npages) / sizeof (page_t);

		/*
		 * Number of level 0 pagetables needed to map these pages.
		 * The '+1' is to handle the likely case that the address
		 * range doesn't align with a pagetable boundary.
		 */
		ptables = pages / mmu.ptes_per_table + 1;

		/*
		 * We also add in some extra to account for the higher level
		 * pagetables and for the vmem structures that get
		 * allocated along the way.
		 */
		table_cnt += (ptables * 3);
	}

#if defined(__i386)
	/*
	 * The 32 bit PAE hat allocates tables one level below the top when
	 * kernelbase isn't 1 Gig aligned. We'll just be sloppy and allocate
	 * a bunch more to the reserve. Any unused will be returned later.
	 * Note we've already counted these mappings, just not the extra
	 * pagetables.
	 */
	if (mmu.pae_hat != 0 && (kernelbase & LEVEL_OFFSET(mmu.max_level)) != 0)
		table_cnt += mmu.ptes_per_table -
		    ((kernelbase & LEVEL_OFFSET(mmu.max_level)) >>
		    LEVEL_SHIFT(mmu.max_level - 1));
#endif

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
}

extern void enable_pae(uintptr_t);
extern void setup_121_andcall();

/*
 * We need to setup a 1:1 (virtual to physical) mapping for the
 * page containing enable_pae() in the new kernel hat.
 */
void
activate_pae(void *pages)
{
#if defined(__amd64)
	int turning_on_pae = 0;		/* it's already on */
#elif defined(__i386)
	pfn_t pfn;
	uintptr_t va_1to1;
	htable_t *ht;
	uint_t entry;
	int turning_on_pae = mmu.pae_hat;
#endif

	if (!turning_on_pae) {
		/*
		 * Finish setup for x86pte_access_pagetable()
		 */
		x86pte_cpu_init(CPU, pages);

		/*
		 * switch off of boot's page tables onto the ones we've built
		 */
		setcr3(MAKECR3(kas.a_hat->hat_htable->ht_pfn));
		khat_running = 1;
		return;
	}

#if defined(__i386)
	if (PFN_ABOVE4G(kas.a_hat->hat_htable->ht_pfn))
		panic("cr3 value would be > 4G on 32 bit PAE");

	/*
	 * find the htable containing the physical address that would be
	 * an identity mapping for enable_pae, save the current pte,
	 * then fill in the identity mapping
	 */
	pfn = va_to_pfn((void *)enable_pae);

	if (pfn == PFN_INVALID)
		panic("activate_pae(): va_to_pfn(enable_pae) failed");
	va_1to1 = mmu_ptob(pfn) +
	    ((uintptr_t)(void *)enable_pae & MMU_PAGEOFFSET);

	ht = htable_create(kas.a_hat, va_1to1, 0, NULL);

	if (ht == NULL || ht->ht_level != 0)
		panic("no htable va %p pfn %lx", (void *)va_1to1, pfn);
	entry = htable_va2entry(va_1to1, ht);
	if (x86pte_get(ht, entry) != 0)
		panic("pte used at va %p", (void *)va_1to1);
	(void) x86pte_set(ht, entry, MAKEPTE(pfn, 0) | PT_WRITABLE, NULL);

	/*
	 * Finish setup for x86pte_access_pagetable(), this has to be
	 * done after the last reference to a newly built page table and
	 * before switching to the newly built pagetables.
	 */
	x86pte_cpu_init(CPU, pages);

	/*
	 * now switch to kernel hat activating PAE
	 */
	setup_121_andcall(enable_pae, MAKECR3(kas.a_hat->hat_htable->ht_pfn));
	khat_running = 1;

	/*
	 * release the mapping we used for the kernel hat
	 */
	(void) x86pte_set(ht, entry, 0, NULL);
	mmu_tlbflush_entry((caddr_t)va_1to1);
	htable_release(ht);
#endif /* __i386 */
}


/*
 * Function to set the EFER.NXE bit if we want to use No eXecute.
 * Note that since this is called from manually relocated code from
 * mpcore.s, we have to use an indirect call with set_nxe_func.
 * This is due to the "call" instruction always being PC relative,
 * unless you go through an indirect pointer in memory.
 */
static void
set_nxe(void)
{
	uint64_t efer;

	if (mmu.pt_nx == 0)
		return;

	/*
	 * AMD64 EFER is model specific register #0xc0000080 and NXE is bit 11
	 */
	(void) rdmsr(MSR_AMD_EFER, &efer);
	efer |= AMD_EFER_NXE;
	wrmsr(MSR_AMD_EFER, &efer);
}

void (*set_nxe_func)(void) = set_nxe;

/*
 * This routine handles the work of creating the kernel's initial mappings
 * by deciphering the mappings in the page tables created by the boot program.
 *
 * We maintain large page mappings, but only to a level 1 pagesize.
 * The boot loader can only add new mappings once this function starts.
 * In particular it can not change the pagesize used for any existing
 * mappings or this code breaks!
 */

uint_t	hks_debug = 0;
#define	HKS_DBG		if (hks_debug) prom_printf

void
hat_kern_setup(void)
{
	uintptr_t	last_va;
	uintptr_t	va;
	size_t		last_size;
	size_t		size;
	uint_t		last_prot = 0;
	uint_t		prot;
	pfn_t		last_pfn = PFN_INVALID;
	pfn_t		pfn;
	pgcnt_t		cnt = 0;
	void		*pages;

	/*
	 * activate AMD processor NX bit support
	 */
	if (mmu.pt_nx != 0)
		set_nxe();

	/*
	 * Allocate 3 initial page addresses for x86pte_cpu_init().
	 */
	pages = vmem_xalloc(heap_arena, 3 * MMU_PAGESIZE, MMU_PAGESIZE, 0,
	    LEVEL_SIZE(1), NULL, NULL, VM_SLEEP);

	/*
	 * next allocate the kernel hat's top level
	 */
	kas.a_hat->hat_htable =
	    htable_create(kas.a_hat, 0, mmu.max_level, NULL);

	/*
	 * Now walk through the address space copying all the page mappings.
	 */
	va = 0;
	last_va = 1;	/* so va doesn't match on the 1st page */
	last_size = 0;
	cnt = 0;
#ifdef	DEBUG
	HKS_DBG("    Start VA  /  PERM  / PFN  / # Mappings\n");
#endif
	while (hat_boot_probe(&va, &size, &pfn, &prot) != 0) {

		if (va == last_va + (last_size * cnt) &&
		    pfn == last_pfn + ((va - last_va) >> PAGESHIFT) &&
		    last_prot == prot &&
		    last_size == size) {
			++cnt;
		} else {
			if (cnt) {
#ifdef DEBUG
				HKS_DBG("    %p", (void *)last_va);
				HKS_DBG(last_size > MMU_PAGESIZE ?
				    "  / L" : "  / -");
				HKS_DBG(last_prot & PROT_READ ? " R" : " -");
				HKS_DBG(last_prot & PROT_WRITE ? "W" : "-");
				HKS_DBG(last_prot & PROT_EXEC ? "X" : "-");
				HKS_DBG("  /  %lx", last_pfn);
				HKS_DBG("  /  %ld\n", cnt);
				if (va != last_va + (last_size * cnt))
					HKS_DBG("----skip----\n");
#endif /* DEBUG */
				hati_kern_setup_load(last_va, last_size,
				    last_pfn, cnt, last_prot);
			}
			last_va = va;
			last_size = size;
			last_pfn = pfn;
			last_prot = prot;
			cnt = 1;
		}
		va += size;
	}

	if (cnt != 0) {
#ifdef DEBUG
		HKS_DBG("    %p", (void *)last_va);
		HKS_DBG(last_size > MMU_PAGESIZE ? "  / L" : "  / -");
		HKS_DBG(last_prot & PROT_READ ? " R" : " -");
		HKS_DBG(last_prot & PROT_WRITE ? "W" : "-");
		HKS_DBG(last_prot & PROT_EXEC ? "X" : "-");
		HKS_DBG("  /  %lx", last_pfn);
		HKS_DBG("  /  %ld\n", cnt);
#endif
		hati_kern_setup_load(last_va, last_size, last_pfn, cnt,
		    last_prot);
	}

#if defined(__i386)
	CPU->cpu_tss->tss_cr3 = dftss0.tss_cr3 =
	    MAKECR3(kas.a_hat->hat_htable->ht_pfn);
#endif /* __i386 */

	/*
	 * Now switch cr3 to the newly built page tables. This includes
	 * turning on PAE for 32 bit if necessary.
	 */
	activate_pae(pages);

	CPUSET_ATOMIC_ADD(kas.a_hat->hat_cpus, CPU->cpu_id);
	CPU->cpu_current_hat = kas.a_hat;
}
