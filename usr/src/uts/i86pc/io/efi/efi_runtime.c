/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright 2026 Argo Technology East
 */

/*
 * Free-standing amd64 page-table builder for the efi(4D) driver.
 *
 * The UEFI Runtime Services entry pointers in the EFI System Table
 * hold physical addresses: when SetVirtualAddressMap() has not been
 * called, calling RT->GetVariable() requires the CPU to find that
 * code at its physical address through the active CR3.  Adding such
 * 1:1 mappings to the regular kernel page table would intrude on the
 * user portion of every process, so we keep them in a separate PML4
 * that is loaded only across the firmware call.
 *
 * efi_pt_create() allocates a fresh PML4 and copies entries 256..511
 * from the kernel's current CR3, so any kernel virtual address (code,
 * stacks, data) keeps resolving identically.  efi_pt_map() walks (and
 * grows) the PDPT/PD/PT levels to install identity mappings for the
 * EfiRuntimeServicesCode/Data ranges.
 *
 * Pages used to back the PML4/PDPT/PD/PT levels are tracked on a
 * per-table list so efi_pt_destroy() can hand every one back to kmem.
 * No global locking: an efi_pt_t is created and freed under the
 * driver soft-state lock.
 */

#include <sys/archsystm.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/efi.h>
#include <sys/kfpu.h>
#include <sys/kmem.h>
#include <sys/list.h>
#include <sys/mach_mmu.h>
#include <sys/mman.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/types.h>
#include <sys/smp_impldefs.h>
#include <vm/as.h>
#include <vm/hat.h>
#include <vm/seg_kmem.h>

#include <vm/hat_pte.h>

#include <sys/efi_runtime.h>

/*
 * One physical page used somewhere in the PML4/PDPT/PD/PT hierarchy.
 */
typedef struct efi_pt_page {
	list_node_t	pp_link;
	caddr_t		pp_va;
	paddr_t		pp_pa;
} efi_pt_page_t;

struct efi_pt {
	list_t		ept_pages;	/* tracks every PT-level page */
	caddr_t		ept_pml4_va;	/* writable kernel mapping */
	paddr_t		ept_pml4_pa;	/* CR3 value */
};

/*
 * Number of 64-bit entries per page-table level.  Hard-coded for
 * amd64 4-level paging since the driver is i86pc-only.
 */
#define	EFI_PT_ENTRIES		512U

/*
 * Translate a guest 1:1 physical address into the index at each
 * level of the walk.
 */
#define	EFI_PML4_IDX(pa)	(((pa) >> 39) & 0x1ff)
#define	EFI_PDPT_IDX(pa)	(((pa) >> 30) & 0x1ff)
#define	EFI_PD_IDX(pa)		(((pa) >> 21) & 0x1ff)
#define	EFI_PT_IDX(pa)		(((pa) >> 12) & 0x1ff)

/*
 * PTE permission bits applied to interior (PML4/PDPT/PD) entries.  At
 * a leaf the caller supplies finer-grained flags.
 */
#define	EFI_PTP_FLAGS		(PT_VALID | PT_WRITABLE)

static efi_pt_page_t *
efi_pt_page_alloc(efi_pt_t *pt)
{
	efi_pt_page_t *pp;
	caddr_t va;

	va = kmem_zalloc(PAGESIZE, KM_SLEEP);
	if (!IS_P2ALIGNED((uintptr_t)va, PAGESIZE)) {
		/*
		 * kmem_zalloc(PAGESIZE) is page-aligned in practice, but
		 * if a future kmem change ever broke that assumption an
		 * unaligned root would silently corrupt CR3, so refuse
		 * loudly.
		 */
		cmn_err(CE_WARN, "efi: kmem returned unaligned page %p",
		    (void *)va);
		kmem_free(va, PAGESIZE);
		return (NULL);
	}

	pp = kmem_zalloc(sizeof (*pp), KM_SLEEP);
	pp->pp_va = va;
	pp->pp_pa = mmu_ptob(hat_getpfnum(kas.a_hat, va));
	list_insert_tail(&pt->ept_pages, pp);
	return (pp);
}

/*
 * Find the writable VA we have for an interior PT page given its
 * physical address.  Linear scan is fine: a UEFI runtime memory map
 * with at most a few dozen ranges requires only a handful of
 * interior pages.
 */
static caddr_t
efi_pt_pa_to_va(efi_pt_t *pt, paddr_t pa)
{
	efi_pt_page_t *pp;

	for (pp = list_head(&pt->ept_pages); pp != NULL;
	    pp = list_next(&pt->ept_pages, pp)) {
		if (pp->pp_pa == pa)
			return (pp->pp_va);
	}
	return (NULL);
}

/*
 * Make sure the next-level page exists below *parentp[idx], allocating
 * it if necessary, and return its writable VA.
 */
static int
efi_pt_walk_one(efi_pt_t *pt, uint64_t *parent_va, uint_t idx, caddr_t *nextp)
{
	uint64_t entry = parent_va[idx];
	caddr_t next_va;

	if (entry & PT_VALID) {
		next_va = efi_pt_pa_to_va(pt, entry & MMU_PAGEMASK);
		if (next_va == NULL)
			return (ENXIO);
	} else {
		efi_pt_page_t *pp = efi_pt_page_alloc(pt);
		if (pp == NULL)
			return (ENOMEM);
		parent_va[idx] = (pp->pp_pa & MMU_PAGEMASK) | EFI_PTP_FLAGS;
		next_va = pp->pp_va;
	}

	*nextp = next_va;
	return (0);
}

int
efi_pt_create(efi_pt_t **ptp)
{
	efi_pt_t *pt;
	efi_pt_page_t *root;
	caddr_t cur_pml4_va;
	paddr_t cur_pml4_pa;
	uint64_t *src, *dst;

	pt = kmem_zalloc(sizeof (*pt), KM_SLEEP);
	list_create(&pt->ept_pages, sizeof (efi_pt_page_t),
	    offsetof(efi_pt_page_t, pp_link));

	root = efi_pt_page_alloc(pt);
	if (root == NULL) {
		efi_pt_destroy(pt);
		return (ENOMEM);
	}
	pt->ept_pml4_va = root->pp_va;
	pt->ept_pml4_pa = root->pp_pa;

	/*
	 * Copy the kernel half of the current PML4 so kernel addresses
	 * stay reachable after we load CR3.  CR3 always carries a valid
	 * PML4 here because we are running with normal kernel mappings.
	 */
	cur_pml4_pa = getcr3_pa();
	cur_pml4_va = psm_map_phys_new(cur_pml4_pa, PAGESIZE, PROT_READ);
	if (cur_pml4_va == NULL) {
		efi_pt_destroy(pt);
		return (ENOMEM);
	}

	src = (uint64_t *)cur_pml4_va;
	dst = (uint64_t *)pt->ept_pml4_va;
	for (uint_t i = EFI_PT_ENTRIES / 2; i < EFI_PT_ENTRIES; i++)
		dst[i] = src[i];

	psm_unmap_phys(cur_pml4_va, PAGESIZE);

	*ptp = pt;
	return (0);
}

void
efi_pt_destroy(efi_pt_t *pt)
{
	efi_pt_page_t *pp;

	if (pt == NULL)
		return;

	while ((pp = list_remove_head(&pt->ept_pages)) != NULL) {
		kmem_free(pp->pp_va, PAGESIZE);
		kmem_free(pp, sizeof (*pp));
	}
	list_destroy(&pt->ept_pages);
	kmem_free(pt, sizeof (*pt));
}

int
efi_pt_map(efi_pt_t *pt, paddr_t pa, size_t size, uint64_t flags)
{
	paddr_t end;
	int rc;

	if (pt == NULL || size == 0)
		return (EINVAL);

	end = P2ROUNDUP(pa + size, PAGESIZE);
	pa = P2ALIGN(pa, PAGESIZE);

	while (pa < end) {
		caddr_t pdpt_va, pd_va, pt_va;
		uint64_t *pml4 = (uint64_t *)pt->ept_pml4_va;
		uint64_t *pdpt, *pd, *pt_l;

		rc = efi_pt_walk_one(pt, pml4, EFI_PML4_IDX(pa), &pdpt_va);
		if (rc != 0)
			return (rc);
		pdpt = (uint64_t *)pdpt_va;

		rc = efi_pt_walk_one(pt, pdpt, EFI_PDPT_IDX(pa), &pd_va);
		if (rc != 0)
			return (rc);
		pd = (uint64_t *)pd_va;

		rc = efi_pt_walk_one(pt, pd, EFI_PD_IDX(pa), &pt_va);
		if (rc != 0)
			return (rc);
		pt_l = (uint64_t *)pt_va;

		pt_l[EFI_PT_IDX(pa)] = (pa & MMU_PAGEMASK) | PT_VALID | flags;
		pa += PAGESIZE;
	}

	return (0);
}

paddr_t
efi_pt_root_pa(const efi_pt_t *pt)
{
	return (pt->ept_pml4_pa);
}

/*
 * Switch CR3 to the alternate page table and invoke a Runtime Services
 * function pointer.  Interrupts are masked and the FPU is claimed for
 * kernel use across the call: UEFI is allowed to touch SSE/AVX state,
 * and any interrupt handler dispatched while CR3 points at the alt
 * table would lack the user portion of the address space.
 *
 * Inline so the compiler keeps everything between the CR3 load and
 * restore on a small, predictable body of code mapped by the kernel
 * half of both page tables.
 */
static inline EFI_STATUS
efi_call_dispatch(efi_pt_t *pt, EFI_STATUS (*invoke)(void *), void *cookie)
{
	ulong_t saved_cr3;
	ulong_t saved_flags;
	EFI_STATUS status;

	/*
	 * KFPU_NO_STATE requires the caller to suppress preemption for the
	 * full duration of the kernel FPU window: kernel_fpu_begin() asserts
	 * curthread->t_preempt > 0 and would not otherwise notice a swtch.
	 * If the thread were to migrate between begin and end, swtch() would
	 * see T_KFPU still set and panic.
	 */
	kpreempt_disable();
	kernel_fpu_begin(NULL, KFPU_NO_STATE);
	saved_flags = intr_clear();
	saved_cr3 = getcr3();

	setcr3((ulong_t)efi_pt_root_pa(pt));
	status = invoke(cookie);
	setcr3(saved_cr3);

	intr_restore(saved_flags);
	kernel_fpu_end(NULL, KFPU_NO_STATE);
	kpreempt_enable();

	return (status);
}

struct efi_get_variable_args {
	EFI_GET_VARIABLE	getvar;
	CHAR16			*name;
	EFI_GUID		*vendor;
	uint32_t		*attrib;
	UINTN			*datasize;
	void			*data;
};

static EFI_STATUS
efi_invoke_get_variable(void *cookie)
{
	struct efi_get_variable_args *a = cookie;

	return (a->getvar(a->name, a->vendor, a->attrib, a->datasize, a->data));
}

EFI_STATUS
efi_call_get_variable(efi_pt_t *pt, efi_runtime_services_t *rs,
    CHAR16 *name, EFI_GUID *vendor, uint32_t *attrib, UINTN *datasize,
    void *data)
{
	struct efi_get_variable_args args;

	args.getvar = rs->rs_get_variable;
	args.name = name;
	args.vendor = vendor;
	args.attrib = attrib;
	args.datasize = datasize;
	args.data = data;

	return (efi_call_dispatch(pt, efi_invoke_get_variable, &args));
}

struct efi_get_next_args {
	EFI_GET_NEXT_VARIABLE_NAME	getnext;
	UINTN				*namesize;
	CHAR16				*name;
	EFI_GUID			*vendor;
};

static EFI_STATUS
efi_invoke_get_next(void *cookie)
{
	struct efi_get_next_args *a = cookie;

	return (a->getnext(a->namesize, a->name, a->vendor));
}

EFI_STATUS
efi_call_get_next_variable_name(efi_pt_t *pt, efi_runtime_services_t *rs,
    UINTN *namesize, CHAR16 *name, EFI_GUID *vendor)
{
	struct efi_get_next_args args;

	args.getnext = rs->rs_get_next_variable_name;
	args.namesize = namesize;
	args.name = name;
	args.vendor = vendor;

	return (efi_call_dispatch(pt, efi_invoke_get_next, &args));
}

struct efi_set_variable_args {
	EFI_SET_VARIABLE	setvar;
	CHAR16			*name;
	EFI_GUID		*vendor;
	uint32_t		attrib;
	UINTN			datasize;
	void			*data;
};

static EFI_STATUS
efi_invoke_set_variable(void *cookie)
{
	struct efi_set_variable_args *a = cookie;

	return (a->setvar(a->name, a->vendor, a->attrib, a->datasize, a->data));
}

EFI_STATUS
efi_call_set_variable(efi_pt_t *pt, efi_runtime_services_t *rs,
    CHAR16 *name, EFI_GUID *vendor, uint32_t attrib, UINTN datasize,
    void *data)
{
	struct efi_set_variable_args args;

	args.setvar = rs->rs_set_variable;
	args.name = name;
	args.vendor = vendor;
	args.attrib = attrib;
	args.datasize = datasize;
	args.data = data;

	return (efi_call_dispatch(pt, efi_invoke_set_variable, &args));
}

int
efi_pt_apply_mmap(efi_pt_t *pt, uint_t *nrangesp)
{
	uchar_t *map = NULL;
	uint_t maplen = 0;
	int descsize;
	uint_t mapped = 0;
	int rc = 0;

	if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, "efi-mmap", &map, &maplen) != DDI_PROP_SUCCESS)
		return (ENOENT);

	descsize = ddi_prop_get_int(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, "efi-mmap-descsize", 0);
	if (descsize < (int)sizeof (EFI_MEMORY_DESCRIPTOR) ||
	    maplen == 0 || (maplen % descsize) != 0) {
		ddi_prop_free(map);
		return (EINVAL);
	}

	for (uint_t off = 0; off < maplen; off += descsize) {
		EFI_MEMORY_DESCRIPTOR *d = (EFI_MEMORY_DESCRIPTOR *)(map + off);
		uint64_t flags;

		if ((d->Attribute & EFI_MEMORY_RUNTIME) == 0)
			continue;

		/*
		 * Code ranges need execute, data ranges need write.
		 * Anything that came in with EFI_MEMORY_XP keeps NX.
		 * If the firmware did not advertise NX support
		 * (mmu.pt_nx == 0) the PT_NX bit is harmless: the CPU
		 * ignores it.
		 */
		flags = PT_WRITABLE;
		if (d->Type == EfiRuntimeServicesData ||
		    (d->Attribute & EFI_MEMORY_XP) != 0)
			flags |= mmu.pt_nx;

		/*
		 * Regions that are not write-back capable -- runtime MMIO
		 * tagged UC/WC/WT -- must be mapped uncached, or firmware
		 * accesses could see stale data or hang.  UC is a safe
		 * superset for UC/WC/WT and runtime MMIO is not performance
		 * sensitive; normal write-back RAM keeps the default mapping.
		 */
		if ((d->Attribute & EFI_MEMORY_WB) == 0)
			flags |= PT_NOCACHE;

		rc = efi_pt_map(pt, (paddr_t)d->PhysicalStart,
		    (size_t)(d->NumberOfPages * PAGESIZE), flags);
		if (rc != 0)
			break;
		mapped++;
	}

	ddi_prop_free(map);

	if (nrangesp != NULL)
		*nrangesp = mapped;
	return (rc);
}
