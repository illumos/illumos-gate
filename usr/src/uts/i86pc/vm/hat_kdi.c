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

/*
 * HAT interfaces used by the kernel debugger to interact with the VM system.
 * These interfaces are invoked when the world is stopped.  As such, no blocking
 * operations may be performed.
 */

#include <sys/cpuvar.h>
#include <sys/kdi_impl.h>
#include <sys/errno.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/mman.h>
#include <sys/bootconf.h>
#include <sys/cmn_err.h>
#include <vm/seg_kmem.h>
#include <vm/hat_i86.h>
#if defined(__xpv)
#include <sys/hypervisor.h>
#endif
#include <sys/bootinfo.h>
#include <vm/kboot_mmu.h>
#include <sys/machsystm.h>

/*
 * The debugger needs direct access to the PTE of one page table entry
 * in order to implement vtop and physical read/writes
 */
static uintptr_t hat_kdi_page = 0;	/* vaddr for phsical page accesses */
static uint_t use_kbm = 1;
uint_t hat_kdi_use_pae;			/* if 0, use x86pte32_t for pte type */

#if !defined(__xpv)
static x86pte_t *hat_kdi_pte = NULL;	/* vaddr of pte for hat_kdi_page */
#endif

/*
 * Get the address for remapping physical pages during boot
 */
void
hat_boot_kdi_init(void)
{
	hat_kdi_page = (uintptr_t)kbm_push(0);	/* first call gets address... */
}

/*
 * Switch to using a page in the kernel's va range for physical memory access.
 * We need to allocate a virtual page, then permanently map in the page that
 * contains the PTE to it.
 */
void
hat_kdi_init(void)
{
	/*LINTED:set but not used in function*/
	htable_t *ht;

	/*
	 * Get an kernel page VA to use for phys mem access. Then make sure
	 * the VA has a page table.
	 */
	hat_kdi_use_pae = mmu.pae_hat;
	hat_kdi_page = (uintptr_t)vmem_alloc(heap_arena, PAGESIZE, VM_SLEEP);
	ht = htable_create(kas.a_hat, hat_kdi_page, 0, NULL);
	use_kbm = 0;

#ifndef __xpv
	/*
	 * Get an address at which to put the pagetable and devload it.
	 */
	hat_kdi_pte = vmem_xalloc(heap_arena, MMU_PAGESIZE, MMU_PAGESIZE, 0,
	    0, NULL, NULL, VM_SLEEP);
	hat_devload(kas.a_hat, (caddr_t)hat_kdi_pte, MMU_PAGESIZE, ht->ht_pfn,
	    PROT_READ | PROT_WRITE | HAT_NOSYNC | HAT_UNORDERED_OK,
	    HAT_LOAD | HAT_LOAD_NOCONSIST);
	hat_kdi_pte =
	    PT_INDEX_PTR(hat_kdi_pte, htable_va2entry(hat_kdi_page, ht));

	HTABLE_INC(ht->ht_valid_cnt);
	htable_release(ht);
#endif
}

#ifdef __xpv

/*
 * translate machine address to physical address
 */
static uint64_t
kdi_ptom(uint64_t pa)
{
	extern pfn_t *mfn_list;
	ulong_t mfn = mfn_list[mmu_btop(pa)];

	return (pfn_to_pa(mfn) | (pa & MMU_PAGEOFFSET));
}

/*
 * This is like mfn_to_pfn(), but we can't use ontrap() from kmdb.
 * Instead we let the fault happen and kmdb deals with it.
 */
static uint64_t
kdi_mtop(uint64_t ma)
{
	pfn_t pfn;
	mfn_t mfn = ma >> MMU_PAGESHIFT;

	if (HYPERVISOR_memory_op(XENMEM_maximum_ram_page, NULL) < mfn)
		return (ma | PFN_IS_FOREIGN_MFN);

	pfn = mfn_to_pfn_mapping[mfn];
	if (pfn >= mfn_count || pfn_to_mfn(pfn) != mfn)
		return (ma | PFN_IS_FOREIGN_MFN);
	return (pfn_to_pa(pfn) | (ma & MMU_PAGEOFFSET));
}

#else
#define	kdi_mtop(m)	(m)
#define	kdi_ptom(p)	(p)
#endif

/*ARGSUSED*/
int
kdi_vtop(uintptr_t va, uint64_t *pap)
{
	uintptr_t vaddr = va;
	size_t	len;
	pfn_t	pfn;
	uint_t	prot;
	int	level;
	x86pte_t pte;
	int	index;

	/*
	 * if the mmu struct isn't relevant yet, we need to probe
	 * the boot loader's pagetables.
	 */
	if (!khat_running) {
		if (kbm_probe(&vaddr, &len, &pfn, &prot) == 0)
			return (ENOENT);
		if (vaddr > va)
			return (ENOENT);
		if (vaddr < va)
			pfn += mmu_btop(va - vaddr);
		*pap = pfn_to_pa(pfn) + (vaddr & MMU_PAGEOFFSET);
		return (0);
	}

	/*
	 * We can't go through normal hat routines, so we'll use
	 * kdi_pread() to walk the page tables
	 */
#if defined(__xpv)
	*pap = pfn_to_pa(CPU->cpu_current_hat->hat_htable->ht_pfn);
#else
	*pap = getcr3() & MMU_PAGEMASK;
#endif
	for (level = mmu.max_level; ; --level) {
		index = (va >> LEVEL_SHIFT(level)) & (mmu.ptes_per_table - 1);
		*pap += index << mmu.pte_size_shift;
		pte = 0;
		if (kdi_pread((caddr_t)&pte, mmu.pte_size, *pap, &len) != 0)
			return (ENOENT);
		if (pte == 0)
			return (ENOENT);
		if (level > 0 && level <= mmu.max_page_level &&
		    (pte & PT_PAGESIZE)) {
			*pap = kdi_mtop(pte & PT_PADDR_LGPG);
			break;
		} else {
			*pap = kdi_mtop(pte & PT_PADDR);
			if (level == 0)
				break;
		}
	}
	*pap += va & LEVEL_OFFSET(level);
	return (0);
}

static int
kdi_prw(caddr_t buf, size_t nbytes, uint64_t pa, size_t *ncopiedp, int doread)
{
	size_t	ncopied = 0;
	off_t	pgoff;
	size_t	sz;
	caddr_t	va;
	caddr_t	from;
	caddr_t	to;
	x86pte_t pte;

	/*
	 * if this is called before any initialization - fail
	 */
	if (hat_kdi_page == 0)
		return (EAGAIN);

	while (nbytes > 0) {
		/*
		 * figure out the addresses and construct a minimal PTE
		 */
		pgoff = pa & MMU_PAGEOFFSET;
		sz = MIN(nbytes, MMU_PAGESIZE - pgoff);
		va = (caddr_t)hat_kdi_page + pgoff;
		pte = kdi_ptom(mmu_ptob(mmu_btop(pa))) | PT_VALID;
		if (doread) {
			from = va;
			to = buf;
		} else {
			PTE_SET(pte, PT_WRITABLE);
			from = buf;
			to = va;
		}

		/*
		 * map the physical page
		 */
		if (use_kbm)
			(void) kbm_push(pa);
#if defined(__xpv)
		else
			(void) HYPERVISOR_update_va_mapping(
			    (uintptr_t)va, pte, UVMF_INVLPG);
#else
		else if (hat_kdi_use_pae)
			*hat_kdi_pte = pte;
		else
			*(x86pte32_t *)hat_kdi_pte = pte;
		mmu_tlbflush_entry((caddr_t)hat_kdi_page);
#endif

		bcopy(from, to, sz);

		/*
		 * erase the mapping
		 */
		if (use_kbm)
			kbm_pop();
#if defined(__xpv)
		else
			(void) HYPERVISOR_update_va_mapping(
			    (uintptr_t)va, 0, UVMF_INVLPG);
#else
		else if (hat_kdi_use_pae)
			*hat_kdi_pte = 0;
		else
			*(x86pte32_t *)hat_kdi_pte = 0;
		mmu_tlbflush_entry((caddr_t)hat_kdi_page);
#endif

		buf += sz;
		pa += sz;
		nbytes -= sz;
		ncopied += sz;
	}

	if (ncopied == 0)
		return (ENOENT);

	*ncopiedp = ncopied;
	return (0);
}

int
kdi_pread(caddr_t buf, size_t nbytes, uint64_t addr, size_t *ncopiedp)
{
	return (kdi_prw(buf, nbytes, addr, ncopiedp, 1));
}

int
kdi_pwrite(caddr_t buf, size_t nbytes, uint64_t addr, size_t *ncopiedp)
{
	return (kdi_prw(buf, nbytes, addr, ncopiedp, 0));
}


/*
 * Return the number of bytes, relative to the beginning of a given range, that
 * are non-toxic (can be read from and written to with relative impunity).
 */
/*ARGSUSED*/
size_t
kdi_range_is_nontoxic(uintptr_t va, size_t sz, int write)
{
#if defined(__amd64)
	extern uintptr_t toxic_addr;
	extern size_t	toxic_size;

	/*
	 * Check 64 bit toxic range.
	 */
	if (toxic_addr != 0 &&
	    va + sz >= toxic_addr &&
	    va < toxic_addr + toxic_size)
		return (va < toxic_addr ? toxic_addr - va : 0);

	/*
	 * avoid any Virtual Address hole
	 */
	if (va + sz >= hole_start && va < hole_end)
		return (va < hole_start ? hole_start - va : 0);

	return (sz);

#elif defined(__i386)
	extern void *device_arena_contains(void *, size_t, size_t *);
	uintptr_t v;

	v = (uintptr_t)device_arena_contains((void *)va, sz, NULL);
	if (v == 0)
		return (sz);
	else if (v <= va)
		return (0);
	else
		return (v - va);

#endif	/* __i386 */
}
