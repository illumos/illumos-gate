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

#include <sys/mach_mmu.h>
#include <sys/machsystm.h>
#include <sys/cmn_err.h>
#include <sys/promif.h>
#include <sys/hypervisor.h>
#include <sys/bootconf.h>
#include <sys/ontrap.h>
#include <sys/rwlock.h>
#include <sys/sysmacros.h>
#include <vm/seg_kmem.h>
#include <vm/kboot_mmu.h>
#include <vm/hat_pte.h>
#include <vm/hat.h>
#include <vm/htable.h>
#include <vm/hat_i86.h>

start_info_t *xen_info;
ulong_t mfn_count;
mfn_t *mfn_list;
mfn_t *mfn_list_pages;		/* pages that make a table of mfn's */
				/* that make up the pa_to_ma table */
mfn_t *mfn_list_pages_page;	/* page of mfn's for mfn_list_pages */
mfn_t cached_max_mfn;
uintptr_t xen_virt_start;
pfn_t *mfn_to_pfn_mapping;
caddr_t xb_addr;		/* virtual addr for the store_mfn page */


/*
 * We need to prevent migration or suspension of a domU while it's
 * manipulating MFN values, as the MFN values will spontaneously
 * change. The next 4 routines provide a mechanism for that.
 * The basic idea is to use reader/writer mutex, readers are any thread
 * that is manipulating MFNs. Only the thread which is going to actually call
 * HYPERVISOR_suspend() will become a writer.
 *
 * Since various places need to manipulate MFNs and also call the HAT,
 * we track if a thread acquires reader status and allow it to recursively
 * do so again. This prevents deadlocks if a migration request
 * is started and waits for some reader, but then the previous reader needs
 * to call into the HAT.
 */
#define	NUM_M2P_LOCKS 128
static struct {
	krwlock_t m2p_rwlock;
	char m2p_pad[64 - sizeof (krwlock_t)];	/* 64 byte cache line size */
} m2p_lock[NUM_M2P_LOCKS];

#define	XM2P_HASH	((uintptr_t)curthread->t_tid & (NUM_M2P_LOCKS - 1))

void
xen_block_migrate(void)
{
	if (!DOMAIN_IS_INITDOMAIN(xen_info) &&
	    ++curthread->t_xpvcntr == 1)
		rw_enter(&m2p_lock[XM2P_HASH].m2p_rwlock, RW_READER);
}

void
xen_allow_migrate(void)
{
	if (!DOMAIN_IS_INITDOMAIN(xen_info) &&
	    --curthread->t_xpvcntr == 0)
		rw_exit(&m2p_lock[XM2P_HASH].m2p_rwlock);
}

void
xen_start_migrate(void)
{
	int i;

	ASSERT(curthread->t_xpvcntr == 0);
	++curthread->t_xpvcntr; /* this allows calls into HAT */
	for (i = 0; i < NUM_M2P_LOCKS; ++i)
		rw_enter(&m2p_lock[i].m2p_rwlock, RW_WRITER);
}

void
xen_end_migrate(void)
{
	int i;

	for (i = 0; i < NUM_M2P_LOCKS; ++i)
		rw_exit(&m2p_lock[i].m2p_rwlock);
	ASSERT(curthread->t_xpvcntr == 1);
	--curthread->t_xpvcntr;
}

/*ARGSUSED*/
void
set_pteval(paddr_t table, uint_t index, uint_t level, x86pte_t pteval)
{
	mmu_update_t t;
	maddr_t mtable = pa_to_ma(table);
	int retcnt;

	t.ptr = (mtable + index * pte_size) | MMU_NORMAL_PT_UPDATE;
	t.val = pteval;
	if (HYPERVISOR_mmu_update(&t, 1, &retcnt, DOMID_SELF) || retcnt != 1)
		bop_panic("HYPERVISOR_mmu_update() failed");
}

/*
 * The start_info_t and mfn_list are initially mapped in low "boot" memory.
 * Each has a page aligned address and size. We relocate them up into the
 * kernel's normal address space at this point in time. We also create
 * the arrays that let the hypervisor suspend/resume a domain.
 */
void
xen_relocate_start_info(void)
{
	maddr_t mach_addr;
	size_t sz;
	size_t sz2;
	offset_t off;
	uintptr_t addr;
	uintptr_t old;
	int i, j;

	/*
	 * In dom0, we have to account for the console_info structure
	 * which might immediately follow the start_info in memory.
	 */
	sz = sizeof (start_info_t);
	if (DOMAIN_IS_INITDOMAIN(xen_info) &&
	    xen_info->console.dom0.info_off >= sizeof (start_info_t)) {
		sz += xen_info->console.dom0.info_off - sizeof (start_info_t) +
		    xen_info->console.dom0.info_size;
	}
	sz = P2ROUNDUP(sz, MMU_PAGESIZE);
	addr = (uintptr_t)vmem_alloc(heap_arena, sz, VM_SLEEP);
	for (off = 0; off < sz; off += MMU_PAGESIZE) {
		mach_addr = pa_to_ma(pfn_to_pa(va_to_pfn(
		    (caddr_t)xen_info + off)));
		kbm_map_ma(mach_addr + off, addr + off, 0);
	}
	boot_mapin((caddr_t)addr, sz);
	old = (uintptr_t)xen_info;
	xen_info = (start_info_t *)addr;
	for (off = 0; off < sz; off += MMU_PAGESIZE)
		kbm_unmap(old + off);

	/*
	 * Relocate the mfn_list, any number of pages.
	 */
	sz = P2ROUNDUP(mfn_count * sizeof (mfn_t), MMU_PAGESIZE);
	addr = (uintptr_t)vmem_xalloc(heap_arena, sz, MMU_PAGESIZE, 0,
	    0, 0, 0, VM_SLEEP);
	for (off = 0; off < sz; off += MMU_PAGESIZE) {
		mach_addr =
		    pa_to_ma(pfn_to_pa(va_to_pfn((caddr_t)mfn_list + off)));
		kbm_map_ma(mach_addr, addr + off, 0);
	}
	boot_mapin((caddr_t)addr, sz);
	old = (uintptr_t)mfn_list;
	mfn_list = (mfn_t *)addr;
	xen_info->mfn_list = (mfn_t)addr;
	for (off = 0; off < sz; off += MMU_PAGESIZE)
		kbm_unmap(old + off);

	/*
	 * Create the lists of mfn_list pages needed by suspend/resume.
	 * Note we skip this for domain 0 as it can't suspend/resume.
	 */
	if (!DOMAIN_IS_INITDOMAIN(xen_info)) {
		sz2 = P2ROUNDUP(mmu_btop(sz) * sizeof (mfn_t), MMU_PAGESIZE);
		mfn_list_pages = kmem_zalloc(sz2, VM_SLEEP);
		mfn_list_pages_page = kmem_zalloc(MMU_PAGESIZE, VM_SLEEP);
		i = 0;
		for (off = 0; off < sz; off += MMU_PAGESIZE) {
			j = mmu_btop(off);
			if (((j * sizeof (mfn_t)) & MMU_PAGEOFFSET) == 0) {
				mfn_list_pages_page[i++] =
				    pfn_to_mfn(va_to_pfn(&mfn_list_pages[j]));
			}
			mfn_list_pages[j] =
			    pfn_to_mfn(va_to_pfn((caddr_t)mfn_list + off));
		}
		HYPERVISOR_shared_info->arch.pfn_to_mfn_frame_list_list =
		    pfn_to_mfn(va_to_pfn(mfn_list_pages_page));
		HYPERVISOR_shared_info->arch.max_pfn = xen_info->nr_pages;
	}

	/*
	 * Remap the shared info (for I/O) into high memory, too.
	 */
	sz = MMU_PAGESIZE;
	addr = (uintptr_t)vmem_alloc(heap_arena, sz, VM_SLEEP);
	kbm_map_ma(xen_info->shared_info, addr, 0);
	/* shared info has no PFN so don't do: boot_mapin((caddr_t)addr, sz) */
	old = (uintptr_t)HYPERVISOR_shared_info;
	HYPERVISOR_shared_info = (void *)addr;
	kbm_unmap(old);

	/*
	 * Remap the console info into high memory, too.
	 */
	if (!DOMAIN_IS_INITDOMAIN(xen_info)) {
		sz = MMU_PAGESIZE;
		addr = (uintptr_t)vmem_alloc(heap_arena, sz, VM_SLEEP);
		kbm_map_ma(pfn_to_pa(xen_info->console.domU.mfn), addr, 0);
		boot_mapin((caddr_t)addr, sz);
		old = (uintptr_t)HYPERVISOR_console_page;
		HYPERVISOR_console_page = (void *)addr;
		kbm_unmap(old);
	} else {
		HYPERVISOR_console_page = NULL;
	}

	/*
	 * On domUs we need to have the xenbus page (store_mfn) mapped into
	 * the kernel. This is referenced as xb_addr.
	 */
	if (!DOMAIN_IS_INITDOMAIN(xen_info)) {
		xb_addr = vmem_alloc(heap_arena, MMU_PAGESIZE, VM_SLEEP);
		kbm_map_ma(mfn_to_ma(xen_info->store_mfn),
		    (uintptr_t)xb_addr, 0);
		boot_mapin(xb_addr, MMU_PAGESIZE);
	}
}

/*
 * Generate the pfn value to use for a foreign mfn.
 */
pfn_t
xen_assign_pfn(mfn_t mfn)
{
	pfn_t pfn;

#ifdef DEBUG
	/*
	 * make sure this MFN isn't in our list of MFNs
	 */
	on_trap_data_t otd;
	uint_t	on_trap_ready = (t0.t_stk != NULL);

	if (on_trap_ready) {
		if (on_trap(&otd, OT_DATA_ACCESS) == 0) {
			pfn = mfn_to_pfn_mapping[mfn];
			if (pfn < mfn_count && mfn_list[pfn] == mfn)
				panic("xen_assign_pfn() mfn belongs to us");
		}
		no_trap();
	}
#endif /* DEBUG */

	if (mfn == MFN_INVALID)
		panic("xen_assign_pfn(MFN_INVALID) not allowed");
	pfn = (pfn_t)mfn | PFN_IS_FOREIGN_MFN;
	if (pfn == mfn)
		panic("xen_assign_pfn(mfn) PFN_IS_FOREIGN_MFN bit already set");
	return (pfn);
}

void
xen_release_pfn(pfn_t pfn)
{
	if (pfn == PFN_INVALID)
		panic("xen_release_pfn(PFN_INVALID) not allowed");
	if ((pfn & PFN_IS_FOREIGN_MFN) == 0)
		panic("mfn high bit not set");
}

uint_t
pfn_is_foreign(pfn_t pfn)
{
	if (pfn == PFN_INVALID)
		return (0);
	return ((pfn & PFN_IS_FOREIGN_MFN) != 0);
}

pfn_t
pte2pfn(x86pte_t pte, level_t l)
{
	mfn_t mfn = PTE2MFN(pte, l);

	if ((pte & PT_SOFTWARE) >= PT_FOREIGN)
		return ((pfn_t)mfn | PFN_IS_FOREIGN_MFN);
	return (mfn_to_pfn(mfn));
}

mfn_t
pfn_to_mfn(pfn_t pfn)
{
	if (pfn == PFN_INVALID)
		panic("pfn_to_mfn(PFN_INVALID) not allowed");

	if (pfn & PFN_IS_FOREIGN_MFN)
		return (pfn & ~PFN_IS_FOREIGN_MFN);

	if (pfn >= mfn_count)
		panic("pfn_to_mfn(): illegal PFN 0x%lx", pfn);

	return (mfn_list[pfn]);
}

/*
 * This routine translates an MFN back into the corresponding PFN value.
 * It has to be careful since the mfn_to_pfn_mapping[] might fault
 * as that table is sparse. It also has to check for non-faulting, but out of
 * range that exceed the table.
 */
pfn_t
mfn_to_pfn(mfn_t mfn)
{
	pfn_t pfn;
	on_trap_data_t otd;
	uint_t	on_trap_ready = (t0.t_stk != NULL);

	/*
	 * Cleared at a suspend or migrate
	 */
	if (cached_max_mfn == 0)
		cached_max_mfn =
		    HYPERVISOR_memory_op(XENMEM_maximum_ram_page, NULL);

	if (cached_max_mfn < mfn)
		return ((pfn_t)mfn | PFN_IS_FOREIGN_MFN);

	if (on_trap_ready && on_trap(&otd, OT_DATA_ACCESS)) {
		pfn = (pfn_t)mfn | PFN_IS_FOREIGN_MFN;
	} else {
		pfn = mfn_to_pfn_mapping[mfn];

		if (pfn == PFN_INVALID || pfn >= mfn_count ||
		    pfn_to_mfn(pfn) != mfn)
			pfn = (pfn_t)mfn | PFN_IS_FOREIGN_MFN;
	}

	if (on_trap_ready)
		no_trap();

	/*
	 * If khat_running is set then we should be checking
	 * in domUs that migration is blocked while using the
	 * mfn_to_pfn_mapping[] table.
	 */
	ASSERT(!khat_running || DOMAIN_IS_INITDOMAIN(xen_info) ||
	    rw_read_held(&m2p_lock[XM2P_HASH].m2p_rwlock));

	return (pfn);
}

/*
 * From a pseudo-physical address, find the corresponding machine address.
 */
maddr_t
pa_to_ma(paddr_t pa)
{
	mfn_t mfn = pfn_to_mfn(mmu_btop(pa));

	if (mfn == MFN_INVALID)
		panic("pa_to_ma() got MFN_INVALID");
	return (mfn_to_ma(mfn) + (pa & MMU_PAGEOFFSET));
}

/*
 * From a machine address, find the corresponding pseudo-physical address.
 */
paddr_t
ma_to_pa(maddr_t ma)
{
	pfn_t pfn = mfn_to_pfn(mmu_btop(ma));

	if (pfn == PFN_INVALID)
		panic("ma_to_pa() got PFN_INVALID");
	return (pfn_to_pa(pfn) + (ma & MMU_PAGEOFFSET));
}

/*
 * When calling reassign_pfn(), the page must be (at least) read locked
 * to make sure swrand does not try to grab it.
 */
#ifdef DEBUG
#define	CHECK_PAGE_LOCK(pfn)	{			\
	page_t *pp = page_numtopp_nolock(pfn);		\
	if ((pp != NULL) && (!PAGE_LOCKED(pp))) {	\
		panic("reassign_pfn() called with unlocked page (pfn 0x%lx)", \
		    pfn);				\
	}						\
}
#else	/* DEBUG */
#define	CHECK_PAGE_LOCK(pfn)
#endif	/* DEBUG */

/*
 * Reassign a new machine page to back a physical address.
 */
void
reassign_pfn(pfn_t pfn, mfn_t mfn)
{
	int mmu_update_return;
	mmu_update_t t;
	extern void update_contig_pfnlist(pfn_t, mfn_t, mfn_t);

	ASSERT(pfn != PFN_INVALID);
	ASSERT(!pfn_is_foreign(pfn));

	ASSERT(pfn < mfn_count);
	update_contig_pfnlist(pfn, mfn_list[pfn], mfn);
	if (mfn == MFN_INVALID) {
		CHECK_PAGE_LOCK(pfn);
		if (kpm_vbase != NULL && xen_kpm_page(pfn, 0) < 0)
			panic("reassign_pfn(): failed to remove kpm mapping");
		mfn_list[pfn] = mfn;
		return;
	}

	/*
	 * Verify that previously given away pages are still page locked.
	 */
	if (mfn_list[pfn] == MFN_INVALID) {
		CHECK_PAGE_LOCK(pfn);
	}
	mfn_list[pfn] = mfn;

	t.ptr = mfn_to_ma(mfn) | MMU_MACHPHYS_UPDATE;
	t.val = pfn;

	if (HYPERVISOR_mmu_update(&t, 1, &mmu_update_return, DOMID_SELF))
		panic("HYPERVISOR_mmu_update() failed");
	ASSERT(mmu_update_return == 1);

	if (kpm_vbase != NULL && xen_kpm_page(pfn, PT_VALID | PT_WRITABLE) < 0)
		panic("reassign_pfn(): failed to enable kpm mapping");
}

/*
 * XXPV code to work around problems with GNTTABOP_map_grant_ref
 * Hopefully we can remove this when GNTTABOP_map_grant_ref is fixed.
 */
void
xen_fix_foreign(uint64_t va)
{
	uintptr_t v = va;
	htable_t *ht;
	uint_t entry;
	x86pte_t pte;

	/*
	 * Look up the PTE for VA. If it is not marked foreign,
	 * add the appropriate soft bits and reinstall the new PTE.
	 */
	ht = htable_getpage(kas.a_hat, v, &entry);
	if (ht == NULL) {
		panic("xen_fix_foreign(va=0x%p) htable not found", (void *)v);
		return;
	}
	pte = x86pte_get(ht, entry);
	if ((pte & PT_SOFTWARE) < PT_FOREIGN) {
		pte |= PT_FOREIGN;
		if (HYPERVISOR_update_va_mapping(v, pte, UVMF_NONE) != 0)
			panic("xen_fix_foreign(va=0x%p) failed, pte=" FMT_PTE,
			    (void *)v, pte);
	}
	htable_release(ht);
}
