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
 * Copyright (c) 2009, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#include <sys/systm.h>
#include <sys/pci_cfgacc.h>
#include <sys/pci_cfgspace.h>
#include <sys/pci_cfgspace_impl.h>
#include <sys/sunddi.h>
#include <sys/sysmacros.h>
#include <sys/x86_archext.h>
#include <sys/pci.h>
#include <sys/cmn_err.h>
#include <vm/hat_i86.h>
#include <vm/seg_kmem.h>
#include <vm/kboot_mmu.h>

#define	PCIE_CFG_SPACE_SIZE	(PCI_CONF_HDR_SIZE << 4)
#define	PCI_BDF_BUS(bdf)	((((uint16_t)bdf) & 0xff00) >> 8)
#define	PCI_BDF_DEV(bdf)	((((uint16_t)bdf) & 0xf8) >> 3)
#define	PCI_BDF_FUNC(bdf)	(((uint16_t)bdf) & 0x7)

/* patchable variables */
volatile boolean_t pci_cfgacc_force_io = B_FALSE;

extern uintptr_t alloc_vaddr(size_t, paddr_t);

void pci_cfgacc_acc(pci_cfgacc_req_t *);

boolean_t pci_cfgacc_find_workaround(uint16_t);
/*
 * IS_P2ALIGNED() is used to make sure offset is 'size'-aligned, so
 * it's guaranteed that the access will not cross 4k page boundary.
 * Thus only 1 page is allocated for all config space access, and the
 * virtual address of that page is cached in pci_cfgacc_virt_base.
 */
static caddr_t pci_cfgacc_virt_base = NULL;

static caddr_t
pci_cfgacc_map(paddr_t phys_addr)
{
#ifdef __xpv
	phys_addr = pfn_to_pa(xen_assign_pfn(mmu_btop(phys_addr))) |
	    (phys_addr & MMU_PAGEOFFSET);
#endif
	if (khat_running) {
		pfn_t pfn = mmu_btop(phys_addr);
		/*
		 * pci_cfgacc_virt_base may hold address left from early
		 * boot, which points to low mem. Realloc virtual address
		 * in kernel space since it's already late in boot now.
		 * Note: no need to unmap first, clear_boot_mappings() will
		 * do that for us.
		 */
		if (pci_cfgacc_virt_base < (caddr_t)kernelbase)
			pci_cfgacc_virt_base = vmem_alloc(heap_arena,
			    MMU_PAGESIZE, VM_SLEEP);

		hat_devload(kas.a_hat, pci_cfgacc_virt_base,
		    MMU_PAGESIZE, pfn, PROT_READ | PROT_WRITE |
		    HAT_STRICTORDER, HAT_LOAD_LOCK);
	} else {
		paddr_t	pa_base = P2ALIGN(phys_addr, MMU_PAGESIZE);

		if (pci_cfgacc_virt_base == NULL)
			pci_cfgacc_virt_base =
			    (caddr_t)alloc_vaddr(MMU_PAGESIZE, MMU_PAGESIZE);

		kbm_map((uintptr_t)pci_cfgacc_virt_base, pa_base, 0, 0);
	}

	return (pci_cfgacc_virt_base + (phys_addr & MMU_PAGEOFFSET));
}

static void
pci_cfgacc_unmap()
{
	if (khat_running)
		hat_unload(kas.a_hat, pci_cfgacc_virt_base, MMU_PAGESIZE,
		    HAT_UNLOAD_UNLOCK);
}

static void
pci_cfgacc_io(pci_cfgacc_req_t *req)
{
	uint8_t bus, dev, func;
	uint16_t ioacc_offset;	/* 4K config access with IO ECS */

	bus = PCI_BDF_BUS(req->bdf);
	dev = PCI_BDF_DEV(req->bdf);
	func = PCI_BDF_FUNC(req->bdf);
	ioacc_offset = req->offset;

	switch (req->size) {
	case 1:
		if (req->write)
			(*pci_putb_func)(bus, dev, func,
			    ioacc_offset, VAL8(req));
		else
			VAL8(req) = (*pci_getb_func)(bus, dev, func,
			    ioacc_offset);
		break;
	case 2:
		if (req->write)
			(*pci_putw_func)(bus, dev, func,
			    ioacc_offset, VAL16(req));
		else
			VAL16(req) = (*pci_getw_func)(bus, dev, func,
			    ioacc_offset);
		break;
	case 4:
		if (req->write)
			(*pci_putl_func)(bus, dev, func,
			    ioacc_offset, VAL32(req));
		else
			VAL32(req) = (*pci_getl_func)(bus, dev, func,
			    ioacc_offset);
		break;
	case 8:
		if (req->write) {
			(*pci_putl_func)(bus, dev, func,
			    ioacc_offset, VAL64(req) & 0xffffffff);
			(*pci_putl_func)(bus, dev, func,
			    ioacc_offset + 4, VAL64(req) >> 32);
		} else {
			VAL64(req) = (*pci_getl_func)(bus, dev, func,
			    ioacc_offset);
			VAL64(req) |= (uint64_t)(*pci_getl_func)(bus, dev, func,
			    ioacc_offset + 4) << 32;
		}
		break;
	}
}

static void
pci_cfgacc_mmio(pci_cfgacc_req_t *req)
{
	caddr_t vaddr;
	paddr_t paddr;

	paddr = (paddr_t)req->bdf << 12;
	paddr += mcfg_mem_base + req->offset;

	mutex_enter(&pcicfg_mmio_mutex);
	vaddr = pci_cfgacc_map(paddr);

	switch (req->size) {
	case 1:
		if (req->write)
			*((uint8_t *)vaddr) = VAL8(req);
		else
			VAL8(req) = *((uint8_t *)vaddr);
		break;
	case 2:
		if (req->write)
			*((uint16_t *)vaddr) = VAL16(req);
		else
			VAL16(req) = *((uint16_t *)vaddr);
		break;
	case 4:
		if (req->write)
			*((uint32_t *)vaddr) = VAL32(req);
		else
			VAL32(req) = *((uint32_t *)vaddr);
		break;
	case 8:
		if (req->write)
			*((uint64_t *)vaddr) = VAL64(req);
		else
			VAL64(req) = *((uint64_t *)vaddr);
		break;
	}
	pci_cfgacc_unmap();
	mutex_exit(&pcicfg_mmio_mutex);
}

static boolean_t
pci_cfgacc_valid(pci_cfgacc_req_t *req, uint16_t cfgspc_size)
{
	int sz = req->size;

	if (IS_P2ALIGNED(req->offset, sz) &&
	    (req->offset + sz - 1 < cfgspc_size) &&
	    ((sz & 0xf) && ISP2(sz)))
		return (B_TRUE);

	cmn_err(CE_WARN, "illegal PCI request: offset = %x, size = %d",
	    req->offset, sz);
	return (B_FALSE);
}

void
pci_cfgacc_check_io(pci_cfgacc_req_t *req)
{
	uint8_t bus;

	bus = PCI_BDF_BUS(req->bdf);

	if (pci_cfgacc_force_io || (mcfg_mem_base == NULL) ||
	    (bus < mcfg_bus_start) || (bus > mcfg_bus_end) ||
	    pci_cfgacc_find_workaround(req->bdf))
		req->ioacc = B_TRUE;
}

void
pci_cfgacc_acc(pci_cfgacc_req_t *req)
{
	extern uint_t pci_iocfg_max_offset;

	if (!req->write)
		VAL64(req) = (uint64_t)-1;

	pci_cfgacc_check_io(req);

	if (req->ioacc) {
		if (pci_cfgacc_valid(req, pci_iocfg_max_offset + 1))
			pci_cfgacc_io(req);
	} else {
		if (pci_cfgacc_valid(req, PCIE_CFG_SPACE_SIZE))
			pci_cfgacc_mmio(req);
	}
}

typedef	struct cfgacc_bus_range {
	struct cfgacc_bus_range *next;
	uint16_t bdf;
	uchar_t	secbus;
	uchar_t	subbus;
} cfgacc_bus_range_t;

cfgacc_bus_range_t *pci_cfgacc_bus_head = NULL;

#define	BUS_INSERT(prev, el) \
	el->next = *prev; \
	*prev = el;

#define	BUS_REMOVE(prev, el) \
	*prev = el->next;

/*
 * This function is only supposed to be called in device tree setup time,
 * thus no lock is needed.
 */
void
pci_cfgacc_add_workaround(uint16_t bdf, uchar_t secbus, uchar_t subbus)
{
	cfgacc_bus_range_t	*entry;

	entry = kmem_zalloc(sizeof (cfgacc_bus_range_t), KM_SLEEP);
	entry->bdf = bdf;
	entry->secbus = secbus;
	entry->subbus = subbus;
	BUS_INSERT(&pci_cfgacc_bus_head, entry);
}

boolean_t
pci_cfgacc_find_workaround(uint16_t bdf)
{
	cfgacc_bus_range_t	*entry;
	uchar_t			bus;

	for (entry = pci_cfgacc_bus_head; entry != NULL;
	    entry = entry->next) {
		if (bdf == entry->bdf) {
			/* found a device which is known to be broken */
			return (B_TRUE);
		}

		bus = PCI_BDF_BUS(bdf);
		if ((bus != 0) && (bus >= entry->secbus) &&
		    (bus <= entry->subbus)) {
			/*
			 * found a device whose parent/grandparent is
			 * known to be broken.
			 */
			return (B_TRUE);
		}
	}

	return (B_FALSE);
}
