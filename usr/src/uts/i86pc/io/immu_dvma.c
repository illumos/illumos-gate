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
 * Portions Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * Copyright (c) 2009, Intel Corporation.
 * All rights reserved.
 */

/*
 * DVMA code
 * This file contains Intel IOMMU code that deals with DVMA
 * i.e. DMA remapping.
 */

#include <sys/sysmacros.h>
#include <sys/pcie.h>
#include <sys/pci_cfgspace.h>
#include <vm/hat_i86.h>
#include <sys/memlist.h>
#include <sys/acpi/acpi.h>
#include <sys/acpica.h>
#include <sys/modhash.h>
#include <sys/immu.h>

#undef	TEST

/*
 * Macros based on PCI spec
 */
#define	IMMU_PCI_REV2CLASS(r)   ((r) >> 8)  /* classcode from revid */
#define	IMMU_PCI_CLASS2BASE(c)  ((c) >> 16) /* baseclass from classcode */
#define	IMMU_PCI_CLASS2SUB(c)   (((c) >> 8) & 0xff); /* classcode */

#define	IMMU_CONTIG_PADDR(d, p) \
	((d).dck_paddr && ((d).dck_paddr + IMMU_PAGESIZE) == (p))

typedef struct dvma_arg {
	immu_t *dva_immu;
	dev_info_t *dva_rdip;
	dev_info_t *dva_ddip;
	domain_t *dva_domain;
	int dva_level;
	immu_flags_t dva_flags;
	list_t *dva_list;
	int dva_error;
} dvma_arg_t;

static domain_t *domain_create(immu_t *immu, dev_info_t *ddip,
    dev_info_t *rdip, immu_flags_t immu_flags);
static immu_devi_t *create_immu_devi(dev_info_t *rdip, int bus,
    int dev, int func, immu_flags_t immu_flags);
static void destroy_immu_devi(immu_devi_t *immu_devi);
static void dvma_map(immu_t *immu, domain_t *domain, uint64_t sdvma,
    uint64_t spaddr, uint64_t npages, dev_info_t *rdip,
    immu_flags_t immu_flags);
extern struct memlist  *phys_install;



/* static Globals */

/*
 * Used to setup DMA objects (memory regions)
 * for DMA reads by IOMMU units
 */
static ddi_dma_attr_t immu_dma_attr = {
	DMA_ATTR_V0,
	0U,
	0xffffffffU,
	0xffffffffU,
	MMU_PAGESIZE, /* MMU page aligned */
	0x1,
	0x1,
	0xffffffffU,
	0xffffffffU,
	1,
	4,
	0
};

static ddi_device_acc_attr_t immu_acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};


/* globals private to this file */
static kmutex_t immu_domain_lock;
static list_t immu_unity_domain_list;
static list_t immu_xlate_domain_list;

/* structure used to store idx into each level of the page tables */
typedef struct xlate {
	int xlt_level;
	uint_t xlt_idx;
	pgtable_t *xlt_pgtable;
} xlate_t;

/* 0 is reserved by Vt-d spec. Solaris reserves 1 */
#define	IMMU_UNITY_DID   1

static mod_hash_t *bdf_domain_hash;

static domain_t *
bdf_domain_lookup(immu_devi_t *immu_devi)
{
	domain_t *domain;
	int16_t seg = immu_devi->imd_seg;
	int16_t bus = immu_devi->imd_bus;
	int16_t devfunc = immu_devi->imd_devfunc;
	uintptr_t bdf = (seg << 16 | bus << 8 | devfunc);

	if (seg < 0 || bus < 0 || devfunc < 0) {
		return (NULL);
	}

	domain = NULL;
	if (mod_hash_find(bdf_domain_hash,
	    (void *)bdf, (void *)&domain) == 0) {
		ASSERT(domain);
		ASSERT(domain->dom_did > 0);
		return (domain);
	} else {
		return (NULL);
	}
}

static void
bdf_domain_insert(immu_devi_t *immu_devi, domain_t *domain)
{
	int16_t seg = immu_devi->imd_seg;
	int16_t bus = immu_devi->imd_bus;
	int16_t devfunc = immu_devi->imd_devfunc;
	uintptr_t bdf = (seg << 16 | bus << 8 | devfunc);
	int r;

	if (seg < 0 || bus < 0 || devfunc < 0) {
		return;
	}

	r = mod_hash_insert(bdf_domain_hash, (void *)bdf, (void *)domain);
	ASSERT(r != MH_ERR_DUPLICATE);
	ASSERT(r == 0);
}

static int
match_lpc(dev_info_t *pdip, void *arg)
{
	immu_devi_t *immu_devi;
	dvma_arg_t *dvap = (dvma_arg_t *)arg;

	ASSERT(dvap->dva_error == DDI_FAILURE);
	ASSERT(dvap->dva_ddip == NULL);
	ASSERT(dvap->dva_list);

	if (list_is_empty(dvap->dva_list)) {
		return (DDI_WALK_TERMINATE);
	}

	immu_devi = list_head(dvap->dva_list);
	for (; immu_devi; immu_devi = list_next(dvap->dva_list,
	    immu_devi)) {
		ASSERT(immu_devi->imd_dip);
		if (immu_devi->imd_dip == pdip) {
			dvap->dva_ddip = pdip;
			dvap->dva_error = DDI_SUCCESS;
			return (DDI_WALK_TERMINATE);
		}
	}

	return (DDI_WALK_CONTINUE);
}

static void
immu_devi_set_spclist(dev_info_t *dip, immu_t *immu)
{
	list_t *spclist = NULL;
	immu_devi_t *immu_devi;

	ASSERT(MUTEX_HELD(&(DEVI(dip)->devi_lock)));

	immu_devi = IMMU_DEVI(dip);
	if (immu_devi->imd_display == B_TRUE) {
		spclist = &(immu->immu_dvma_gfx_list);
	} else if (immu_devi->imd_lpc == B_TRUE) {
		spclist = &(immu->immu_dvma_lpc_list);
	}

	if (spclist) {
		mutex_enter(&(immu->immu_lock));
		list_insert_head(spclist, immu_devi);
		mutex_exit(&(immu->immu_lock));
	}
}

/*
 * Set the immu_devi struct in the immu_devi field of a devinfo node
 */
int
immu_devi_set(dev_info_t *dip, immu_flags_t immu_flags)
{
	int bus, dev, func;
	immu_devi_t *new_imd;
	immu_devi_t *immu_devi;

	ASSERT(root_devinfo);
	ASSERT(dip);
	ASSERT(dip != root_devinfo);

	immu_devi = immu_devi_get(dip);
	if (immu_devi != NULL) {
		return (DDI_SUCCESS);
	}

	bus = dev = func = -1;

	/*
	 * Assume a new immu_devi struct is needed
	 */
	if (!DEVI_IS_PCI(dip) || acpica_get_bdf(dip, &bus, &dev, &func) != 0) {
		/*
		 * No BDF. Set bus = -1 to indicate this.
		 * We still need to create a immu_devi struct
		 * though
		 */
		bus = -1;
		dev = 0;
		func = 0;
	}

	new_imd = create_immu_devi(dip, bus, dev, func, immu_flags);
	if (new_imd  == NULL) {
		ddi_err(DER_WARN, dip, "Failed to create immu_devi "
		    "structure");
		return (DDI_FAILURE);
	}

	/*
	 * Check if some other thread allocated a immu_devi while we
	 * didn't own the lock.
	 */
	mutex_enter(&(DEVI(dip)->devi_lock));
	if (IMMU_DEVI(dip) == NULL) {
		IMMU_DEVI_SET(dip, new_imd);
	} else {
		destroy_immu_devi(new_imd);
	}
	mutex_exit(&(DEVI(dip)->devi_lock));

	return (DDI_SUCCESS);
}

static dev_info_t *
get_lpc_devinfo(immu_t *immu, dev_info_t *rdip, immu_flags_t immu_flags)
{
	dvma_arg_t dvarg = {0};
	dvarg.dva_list = &(immu->immu_dvma_lpc_list);
	dvarg.dva_rdip = rdip;
	dvarg.dva_error = DDI_FAILURE;

	if (immu_walk_ancestor(rdip, NULL, match_lpc,
	    &dvarg, NULL, immu_flags) != DDI_SUCCESS) {
		ddi_err(DER_MODE, rdip, "Could not walk ancestors to "
		    "find lpc_devinfo for ISA device");
		return (NULL);
	}

	if (dvarg.dva_error != DDI_SUCCESS || dvarg.dva_ddip == NULL) {
		ddi_err(DER_MODE, rdip, "Could not find lpc_devinfo for "
		    "ISA device");
		return (NULL);
	}

	return (dvarg.dva_ddip);
}

static dev_info_t *
get_gfx_devinfo(dev_info_t *rdip)
{
	immu_t *immu;
	immu_devi_t *immu_devi;
	list_t *list_gfx;

	/*
	 * The GFX device may not be on the same IMMU unit as "agpgart"
	 * so search globally
	 */
	immu_devi = NULL;
	immu = list_head(&immu_list);
	for (; immu; immu = list_next(&immu_list, immu)) {
		list_gfx = &(immu->immu_dvma_gfx_list);
		if (!list_is_empty(list_gfx)) {
			immu_devi = list_head(list_gfx);
			break;
		}
	}

	if (immu_devi == NULL) {
		ddi_err(DER_WARN, rdip, "IMMU: No GFX device. "
		    "Cannot redirect agpgart",
		    ddi_node_name(immu_devi->imd_dip));
		return (NULL);
	}

	/* list is not empty we checked above */
	ASSERT(immu_devi);
	ASSERT(immu_devi->imd_dip);

	ddi_err(DER_LOG, rdip, "IMMU: GFX redirect to %s",
	    ddi_node_name(immu_devi->imd_dip));

	return (immu_devi->imd_dip);
}

static immu_flags_t
dma_to_immu_flags(struct ddi_dma_req *dmareq)
{
	immu_flags_t flags = 0;

	if (dmareq->dmar_fp == DDI_DMA_SLEEP) {
		flags |= IMMU_FLAGS_SLEEP;
	} else {
		flags |= IMMU_FLAGS_NOSLEEP;
	}

	/*
	 * Read and write flags need to be reversed.
	 * DMA_READ means read from device and write
	 * to memory. So DMA read means DVMA write.
	 */
	if (dmareq->dmar_flags & DDI_DMA_READ)
		flags |= IMMU_FLAGS_WRITE;

	if (dmareq->dmar_flags & DDI_DMA_WRITE)
		flags |= IMMU_FLAGS_READ;

#ifdef BUGGY_DRIVERS
	/*
	 * Some buggy drivers specify neither READ or WRITE
	 * For such drivers set both read and write permissions
	 */
	if ((dmareq->dmar_flags & (DDI_DMA_READ | DDI_DMA_WRITE)) == 0) {
		flags |= (IMMU_FLAGS_READ | IMMU_FLAGS_WRITE);
	}
#endif

	return (flags);
}

/*
 * pgtable_alloc()
 *	alloc a IOMMU pgtable structure.
 *	This same struct is used for root and context tables as well.
 *	This routine allocs the f/ollowing:
 *	- a pgtable_t struct
 *	- a HW page which holds PTEs/entries which is accesssed by HW
 *        so we set up DMA for this page
 *	- a SW page which is only for our bookeeping
 *        (for example to  hold pointers to the next level pgtable).
 *        So a simple kmem_alloc suffices
 */
static pgtable_t *
pgtable_alloc(immu_t *immu, domain_t *domain, immu_flags_t immu_flags)
{
	size_t actual_size = 0;
	pgtable_t *pgtable;
	int (*dmafp)(caddr_t);
	caddr_t vaddr;
	int kmflags;

	/* TO DO cache freed pgtables as it is expensive to create em */
	ASSERT(immu);

	kmflags = (immu_flags & IMMU_FLAGS_NOSLEEP) ?
	    KM_NOSLEEP : KM_SLEEP;

	dmafp = (immu_flags & IMMU_FLAGS_NOSLEEP) ?
	    DDI_DMA_DONTWAIT : DDI_DMA_SLEEP;

	pgtable = kmem_zalloc(sizeof (pgtable_t), kmflags);
	if (pgtable == NULL) {
		return (NULL);
	}

	pgtable->swpg_next_array = kmem_zalloc(IMMU_PAGESIZE, kmflags);
	if (pgtable->swpg_next_array == NULL) {
		kmem_free(pgtable, sizeof (pgtable_t));
		return (NULL);
	}

	ASSERT(root_devinfo);
	if (ddi_dma_alloc_handle(root_devinfo, &immu_dma_attr,
	    dmafp, NULL, &pgtable->hwpg_dmahdl) != DDI_SUCCESS) {
		kmem_free(pgtable->swpg_next_array, IMMU_PAGESIZE);
		kmem_free(pgtable, sizeof (pgtable_t));
		return (NULL);
	}

	if (ddi_dma_mem_alloc(pgtable->hwpg_dmahdl, IMMU_PAGESIZE,
	    &immu_acc_attr, DDI_DMA_CONSISTENT | IOMEM_DATA_UNCACHED,
	    dmafp, NULL, &vaddr, &actual_size,
	    &pgtable->hwpg_memhdl) != DDI_SUCCESS) {
		ddi_dma_free_handle(&pgtable->hwpg_dmahdl);
		kmem_free((void *)(pgtable->swpg_next_array),
		    IMMU_PAGESIZE);
		kmem_free(pgtable, sizeof (pgtable_t));
		return (NULL);
	}

	/*
	 * Memory allocation failure. Maybe a temporary condition
	 * so return error rather than panic, so we can try again
	 */
	if (actual_size < IMMU_PAGESIZE) {
		ddi_dma_mem_free(&pgtable->hwpg_memhdl);
		ddi_dma_free_handle(&pgtable->hwpg_dmahdl);
		kmem_free((void *)(pgtable->swpg_next_array),
		    IMMU_PAGESIZE);
		kmem_free(pgtable, sizeof (pgtable_t));
		return (NULL);
	}

	pgtable->hwpg_paddr = pfn_to_pa(hat_getpfnum(kas.a_hat, vaddr));
	pgtable->hwpg_vaddr = vaddr;

	bzero(pgtable->hwpg_vaddr, IMMU_PAGESIZE);

	/* Use immu directly as domain may be NULL, cant use dom_immu field */
	immu_regs_cpu_flush(immu, pgtable->hwpg_vaddr, IMMU_PAGESIZE);

	rw_init(&(pgtable->swpg_rwlock), NULL, RW_DEFAULT, NULL);

	if (domain) {
		rw_enter(&(domain->dom_pgtable_rwlock), RW_WRITER);
		list_insert_head(&(domain->dom_pglist), pgtable);
		rw_exit(&(domain->dom_pgtable_rwlock));
	}

	return (pgtable);
}

static void
pgtable_free(immu_t *immu, pgtable_t *pgtable, domain_t *domain)
{
	ASSERT(immu);
	ASSERT(pgtable);

	if (domain) {
		rw_enter(&(domain->dom_pgtable_rwlock), RW_WRITER);
		list_remove(&(domain->dom_pglist), pgtable);
		rw_exit(&(domain->dom_pgtable_rwlock));
	}

	/* destroy will panic if lock is held. */
	rw_destroy(&(pgtable->swpg_rwlock));

	/* Zero out the HW page being freed to catch errors */
	bzero(pgtable->hwpg_vaddr, IMMU_PAGESIZE);
	immu_regs_cpu_flush(immu, pgtable->hwpg_vaddr, IMMU_PAGESIZE);
	ddi_dma_mem_free(&pgtable->hwpg_memhdl);
	ddi_dma_free_handle(&pgtable->hwpg_dmahdl);
	/* don't zero out the soft pages for debugging */
	if (pgtable->swpg_next_array)
		kmem_free((void *)(pgtable->swpg_next_array), IMMU_PAGESIZE);
	kmem_free(pgtable, sizeof (pgtable_t));
}

/*
 * Function to identify a display device from the PCI class code
 */
static boolean_t
device_is_display(uint_t classcode)
{
	static uint_t disp_classes[] = {
		0x000100,
		0x030000,
		0x030001
	};
	int i, nclasses = sizeof (disp_classes) / sizeof (uint_t);

	for (i = 0; i < nclasses; i++) {
		if (classcode == disp_classes[i])
			return (B_TRUE);
	}
	return (B_FALSE);
}

/*
 * Function that determines if device is PCIEX and/or PCIEX bridge
 */
static boolean_t
device_is_pciex(
	uchar_t bus, uchar_t dev, uchar_t func, boolean_t *is_pcib)
{
	ushort_t cap;
	ushort_t capsp;
	ushort_t cap_count = PCI_CAP_MAX_PTR;
	ushort_t status;
	boolean_t is_pciex = B_FALSE;

	*is_pcib = B_FALSE;

	status = pci_getw_func(bus, dev, func, PCI_CONF_STAT);
	if (!(status & PCI_STAT_CAP))
		return (B_FALSE);

	capsp = pci_getb_func(bus, dev, func, PCI_CONF_CAP_PTR);
	while (cap_count-- && capsp >= PCI_CAP_PTR_OFF) {
		capsp &= PCI_CAP_PTR_MASK;
		cap = pci_getb_func(bus, dev, func, capsp);

		if (cap == PCI_CAP_ID_PCI_E) {
			status = pci_getw_func(bus, dev, func, capsp + 2);
			/*
			 * See section 7.8.2 of PCI-Express Base Spec v1.0a
			 * for Device/Port Type.
			 * PCIE_PCIECAP_DEV_TYPE_PCIE2PCI implies that the
			 * device is a PCIE2PCI bridge
			 */
			*is_pcib =
			    ((status & PCIE_PCIECAP_DEV_TYPE_MASK) ==
			    PCIE_PCIECAP_DEV_TYPE_PCIE2PCI) ? B_TRUE : B_FALSE;
			is_pciex = B_TRUE;
		}

		capsp = (*pci_getb_func)(bus, dev, func,
		    capsp + PCI_CAP_NEXT_PTR);
	}

	return (is_pciex);
}


/*
 * immu_dvma_get_immu()
 *   get the immu unit structure for a dev_info node
 */
immu_t *
immu_dvma_get_immu(dev_info_t *dip, immu_flags_t immu_flags)
{
	immu_devi_t *immu_devi;
	immu_t *immu;

	/*
	 * check if immu unit was already found earlier.
	 * If yes, then it will be stashed in immu_devi struct.
	 */
	immu_devi = immu_devi_get(dip);
	if (immu_devi == NULL) {
		if (immu_devi_set(dip, immu_flags) != DDI_SUCCESS) {
			/*
			 * May fail because of low memory. Return error rather
			 * than panic as we want driver to rey again later
			 */
			ddi_err(DER_PANIC, dip, "immu_dvma_get_immu: "
			    "No immu_devi structure");
			/*NOTREACHED*/
		}
		immu_devi = immu_devi_get(dip);
		ASSERT(immu_devi);
	}

	mutex_enter(&(DEVI(dip)->devi_lock));
	if (immu_devi->imd_immu) {
		immu = immu_devi->imd_immu;
		mutex_exit(&(DEVI(dip)->devi_lock));
		return (immu);
	}
	mutex_exit(&(DEVI(dip)->devi_lock));

	immu = immu_dmar_get_immu(dip);
	if (immu == NULL) {
		ddi_err(DER_PANIC, dip, "immu_dvma_get_immu: "
		    "Cannot find immu_t for device");
		/*NOTREACHED*/
	}

	/*
	 * Check if some other thread found immu
	 * while lock was not held
	 */
	immu_devi = immu_devi_get(dip);
	/* immu_devi should be present as we found it earlier */
	if (immu_devi == NULL) {
		ddi_err(DER_PANIC, dip,
		    "immu_dvma_get_immu: No immu_devi structure");
		/*NOTREACHED*/
	}

	mutex_enter(&(DEVI(dip)->devi_lock));
	if (immu_devi->imd_immu == NULL) {
		/* nobody else set it, so we should do it */
		immu_devi->imd_immu = immu;
		immu_devi_set_spclist(dip, immu);
	} else {
		/*
		 * if some other thread got immu before
		 * us, it should get the same results
		 */
		if (immu_devi->imd_immu != immu) {
			ddi_err(DER_PANIC, dip, "Multiple "
			    "immu units found for device. Expected (%p), "
			    "actual (%p)", (void *)immu,
			    (void *)immu_devi->imd_immu);
			mutex_exit(&(DEVI(dip)->devi_lock));
			/*NOTREACHED*/
		}
	}
	mutex_exit(&(DEVI(dip)->devi_lock));

	return (immu);
}


/* ############################# IMMU_DEVI code ############################ */

/*
 * Allocate a immu_devi structure and initialize it
 */
static immu_devi_t *
create_immu_devi(dev_info_t *rdip, int bus, int dev, int func,
    immu_flags_t immu_flags)
{
	uchar_t baseclass, subclass;
	uint_t classcode, revclass;
	immu_devi_t *immu_devi;
	boolean_t pciex = B_FALSE;
	int kmflags;
	boolean_t is_pcib = B_FALSE;

	/* bus ==  -1 indicate non-PCI device (no BDF) */
	ASSERT(bus == -1 || bus >= 0);
	ASSERT(dev >= 0);
	ASSERT(func >= 0);

	kmflags = (immu_flags & IMMU_FLAGS_NOSLEEP) ? KM_NOSLEEP : KM_SLEEP;
	immu_devi = kmem_zalloc(sizeof (immu_devi_t), kmflags);
	if (immu_devi == NULL) {
		ddi_err(DER_WARN, rdip, "Failed to allocate memory for "
		    "Intel IOMMU immu_devi structure");
		return (NULL);
	}
	immu_devi->imd_dip = rdip;
	immu_devi->imd_seg = 0; /* Currently seg can only be 0 */
	immu_devi->imd_bus = bus;
	immu_devi->imd_pcib_type = IMMU_PCIB_BAD;

	if (bus == -1) {
		immu_devi->imd_pcib_type = IMMU_PCIB_NOBDF;
		return (immu_devi);
	}

	immu_devi->imd_devfunc = IMMU_PCI_DEVFUNC(dev, func);
	immu_devi->imd_sec = 0;
	immu_devi->imd_sub = 0;

	revclass = pci_getl_func(bus, dev, func, PCI_CONF_REVID);

	classcode = IMMU_PCI_REV2CLASS(revclass);
	baseclass = IMMU_PCI_CLASS2BASE(classcode);
	subclass = IMMU_PCI_CLASS2SUB(classcode);

	if (baseclass == PCI_CLASS_BRIDGE && subclass == PCI_BRIDGE_PCI) {

		immu_devi->imd_sec = pci_getb_func(bus, dev, func,
		    PCI_BCNF_SECBUS);
		immu_devi->imd_sub = pci_getb_func(bus, dev, func,
		    PCI_BCNF_SUBBUS);

		pciex = device_is_pciex(bus, dev, func, &is_pcib);
		if (pciex  == B_TRUE && is_pcib == B_TRUE) {
			immu_devi->imd_pcib_type = IMMU_PCIB_PCIE_PCI;
		} else if (pciex == B_TRUE) {
			immu_devi->imd_pcib_type = IMMU_PCIB_PCIE_PCIE;
		} else {
			immu_devi->imd_pcib_type = IMMU_PCIB_PCI_PCI;
		}
	} else {
		immu_devi->imd_pcib_type = IMMU_PCIB_ENDPOINT;
	}

	/* check for certain special devices */
	immu_devi->imd_display = device_is_display(classcode);

	immu_devi->imd_lpc = ((baseclass == PCI_CLASS_BRIDGE) &&
	    (subclass == PCI_BRIDGE_ISA)) ? B_TRUE : B_FALSE;

	immu_devi->imd_domain = NULL;

	return (immu_devi);
}

static void
destroy_immu_devi(immu_devi_t *immu_devi)
{
	kmem_free(immu_devi, sizeof (immu_devi_t));
}

static domain_t *
immu_devi_domain(dev_info_t *rdip, dev_info_t **ddipp)
{
	immu_devi_t *immu_devi;
	domain_t *domain;
	dev_info_t *ddip;

	ASSERT(rdip);
	ASSERT(ddipp);

	*ddipp = NULL;

	immu_devi = immu_devi_get(rdip);
	if (immu_devi == NULL) {
		return (NULL);
	}

	mutex_enter(&(DEVI(rdip)->devi_lock));
	domain = immu_devi->imd_domain;
	ddip = immu_devi->imd_ddip;
	mutex_exit(&(DEVI(rdip)->devi_lock));

	if (domain) {
		ASSERT(domain->dom_did > 0);
		ASSERT(ddip);
		*ddipp = ddip;
	}

	return (domain);

}

/* ############################# END IMMU_DEVI code ######################## */
/* ############################# DOMAIN code ############################### */

/*
 * This routine always succeeds
 */
static int
did_alloc(immu_t *immu, dev_info_t *rdip,
    dev_info_t *ddip, immu_flags_t immu_flags)
{
	int did;

	ASSERT(immu);
	ASSERT(rdip);
	ASSERT(rdip != root_devinfo);

	did = (uintptr_t)vmem_alloc(immu->immu_did_arena, 1,
	    (immu_flags & IMMU_FLAGS_NOSLEEP) ? VM_NOSLEEP : VM_SLEEP);

	if (did == 0) {
		ASSERT(immu->immu_unity_domain);
		ASSERT(immu->immu_unity_domain->dom_did > 0);
		ddi_err(DER_WARN, rdip, "device domain-id alloc error"
		    " domain-device: %s%d. immu unit is %s. Using "
		    "unity domain with domain-id (%d)",
		    ddi_driver_name(ddip), ddi_get_instance(ddip),
		    immu->immu_name, immu->immu_unity_domain->dom_did);
		did = immu->immu_unity_domain->dom_did;
	}

	return (did);
}

static int
get_branch_domain(dev_info_t *pdip, void *arg)
{
	immu_devi_t *immu_devi;
	domain_t *domain;
	dev_info_t *ddip;
	immu_t *immu;
	dvma_arg_t *dvp = (dvma_arg_t *)arg;

	ASSERT(pdip);
	ASSERT(dvp);
	ASSERT(dvp->dva_rdip);

	/*
	 * The field dvp->dva_rdip is a work-in-progress
	 * and gets updated as we walk up the ancestor
	 * tree. The final ddip is set only when we reach
	 * the top of the tree. So the dvp->dva_ddip field cannot
	 * be relied on until we reach the top of the field.
	 */

	/* immu_devi may not be set. */
	immu_devi = immu_devi_get(pdip);
	if (immu_devi == NULL) {
		if (immu_devi_set(pdip, dvp->dva_flags) != DDI_SUCCESS) {
			dvp->dva_error = DDI_FAILURE;
			return (DDI_WALK_TERMINATE);
		}
	}

	immu_devi = immu_devi_get(pdip);
	ASSERT(immu_devi);
	immu = immu_devi->imd_immu;
	if (immu == NULL) {
		immu = immu_dvma_get_immu(pdip, dvp->dva_flags);
		ASSERT(immu);
	}

	/*
	 * If we encounter a PCIE_PCIE bridge *ANCESTOR* we need to
	 * terminate the walk (since the device under the PCIE bridge
	 * is a PCIE device and has an independent entry in the
	 * root/context table)
	 */
	if (dvp->dva_rdip != pdip &&
	    immu_devi->imd_pcib_type == IMMU_PCIB_PCIE_PCIE) {
		return (DDI_WALK_TERMINATE);
	}

	/*
	 * In order to be a domain-dim, it must be a PCI device i.e.
	 * must have valid BDF. This also eliminates the root complex.
	 */
	if (immu_devi->imd_pcib_type != IMMU_PCIB_BAD &&
	    immu_devi->imd_pcib_type != IMMU_PCIB_NOBDF) {
		ASSERT(immu_devi->imd_bus >= 0);
		ASSERT(immu_devi->imd_devfunc >= 0);
		dvp->dva_ddip = pdip;
	}

	if (immu_devi->imd_display == B_TRUE ||
	    (dvp->dva_flags & IMMU_FLAGS_UNITY)) {
		dvp->dva_domain = immu->immu_unity_domain;
		/* continue walking to find ddip */
		return (DDI_WALK_CONTINUE);
	}

	mutex_enter(&(DEVI(pdip)->devi_lock));
	domain = immu_devi->imd_domain;
	ddip = immu_devi->imd_ddip;
	mutex_exit(&(DEVI(pdip)->devi_lock));

	if (domain && ddip) {
		/* if domain is set, it must be the same */
		if (dvp->dva_domain) {
			ASSERT(domain == dvp->dva_domain);
		}
		dvp->dva_domain = domain;
		dvp->dva_ddip = ddip;
		return (DDI_WALK_TERMINATE);
	}

	/* immu_devi either has both set or both clear */
	ASSERT(domain == NULL);
	ASSERT(ddip == NULL);

	/* Domain may already be set, continue walking so that ddip gets set */
	if (dvp->dva_domain) {
		return (DDI_WALK_CONTINUE);
	}

	/* domain is not set in either immu_devi or dvp */
	domain = bdf_domain_lookup(immu_devi);
	if (domain == NULL) {
		return (DDI_WALK_CONTINUE);
	}

	/* ok, the BDF hash had a domain for this BDF. */

	/* Grab lock again to check if something else set immu_devi fields */
	mutex_enter(&(DEVI(pdip)->devi_lock));
	if (immu_devi->imd_domain != NULL) {
		ASSERT(immu_devi->imd_domain == domain);
		dvp->dva_domain = domain;
	} else {
		dvp->dva_domain = domain;
	}
	mutex_exit(&(DEVI(pdip)->devi_lock));

	/*
	 * walk upwards until the topmost PCI bridge is found
	 */
	return (DDI_WALK_CONTINUE);
}

static void
map_unity_domain(domain_t *domain)
{
	struct memlist *mp;
	uint64_t start;
	uint64_t npages;

	ASSERT(domain);
	ASSERT(domain->dom_did == IMMU_UNITY_DID);

	/*
	 * We call into routines that grab the lock so we should
	 * not be called with the lock held. This does not matter
	 * much since, no else has a reference to this domain
	 */
	ASSERT(!rw_lock_held(&(domain->dom_pgtable_rwlock)));

	/*
	 * UNITY arenas are a mirror of the physical memory
	 * installed on the system.
	 */

#ifdef BUGGY_DRIVERS
	/*
	 * Dont skip page0. Some broken HW/FW access it.
	 */
	dvma_map(domain->dom_immu, domain, 0, 0, 1, NULL,
	    IMMU_FLAGS_READ | IMMU_FLAGS_WRITE | IMMU_FLAGS_PAGE1);
#endif

	memlist_read_lock();

	mp = phys_install;

	if (mp->ml_address == 0) {
		/* since we already mapped page1 above */
		start = IMMU_PAGESIZE;
	} else {
		start = mp->ml_address;
	}
	npages = mp->ml_size/IMMU_PAGESIZE + 1;

	dvma_map(domain->dom_immu, domain, start, start, npages, NULL,
	    IMMU_FLAGS_READ | IMMU_FLAGS_WRITE);

	ddi_err(DER_LOG, NULL, "IMMU: mapping PHYS span [0x%" PRIx64
	    " - 0x%" PRIx64 "]", start, start + mp->ml_size);

	mp = mp->ml_next;
	while (mp) {
		ddi_err(DER_LOG, NULL, "IMMU: mapping PHYS span [0x%" PRIx64
		    " - 0x%" PRIx64 "]", mp->ml_address,
		    mp->ml_address + mp->ml_size);

		start = mp->ml_address;
		npages = mp->ml_size/IMMU_PAGESIZE + 1;

		dvma_map(domain->dom_immu, domain, start, start,
		    npages, NULL, IMMU_FLAGS_READ | IMMU_FLAGS_WRITE);

		mp = mp->ml_next;
	}

	mp = bios_rsvd;
	while (mp) {
		ddi_err(DER_LOG, NULL, "IMMU: mapping PHYS span [0x%" PRIx64
		    " - 0x%" PRIx64 "]", mp->ml_address,
		    mp->ml_address + mp->ml_size);

		start = mp->ml_address;
		npages = mp->ml_size/IMMU_PAGESIZE + 1;

		dvma_map(domain->dom_immu, domain, start, start,
		    npages, NULL, IMMU_FLAGS_READ | IMMU_FLAGS_WRITE);

		mp = mp->ml_next;
	}

	memlist_read_unlock();
}

/*
 * create_xlate_arena()
 * 	Create the dvma arena for a domain with translation
 *	mapping
 */
static void
create_xlate_arena(immu_t *immu, domain_t *domain,
    dev_info_t *rdip, immu_flags_t immu_flags)
{
	char *arena_name;
	struct memlist *mp;
	int vmem_flags;
	uint64_t start;
	uint_t mgaw;
	uint64_t size;
	uint64_t maxaddr;
	void *vmem_ret;

	arena_name = domain->dom_dvma_arena_name;

	/* Note, don't do sizeof (arena_name) - it is just a pointer */
	(void) snprintf(arena_name,
	    sizeof (domain->dom_dvma_arena_name),
	    "%s-domain-%d-xlate-DVMA-arena", immu->immu_name,
	    domain->dom_did);

	vmem_flags = (immu_flags & IMMU_FLAGS_NOSLEEP) ? VM_NOSLEEP : VM_SLEEP;

	/*
	 * No one else has access to this domain.
	 * So no domain locks needed
	 */
	ASSERT(!rw_lock_held(&(domain->dom_pgtable_rwlock)));

	/* Restrict mgaddr (max guest addr) to MGAW */
	mgaw = IMMU_CAP_MGAW(immu->immu_regs_cap);

	/*
	 * To ensure we avoid ioapic and PCI MMIO ranges we just
	 * use the physical memory address range of the system as the
	 * range
	 * Implementing above causes graphics device to barf on
	 * Lenovo X301 hence the toggle switch immu_mmio_safe.
	 */
	maxaddr = ((uint64_t)1 << mgaw);

	if (immu_mmio_safe == B_FALSE) {

		start = MMU_PAGESIZE;
		size = maxaddr - start;

		ddi_err(DER_VERB, rdip,
		    "%s: Creating dvma vmem arena [0x%" PRIx64
		    " - 0x%" PRIx64 "]", arena_name, start, start + size);

		ASSERT(domain->dom_dvma_arena == NULL);

		/*
		 * We always allocate in quanta of IMMU_PAGESIZE
		 */
		domain->dom_dvma_arena = vmem_create(arena_name,
		    (void *)(uintptr_t)start,	/* start addr */
		    size,			/* size */
		    IMMU_PAGESIZE,		/* quantum */
		    NULL,			/* afunc */
		    NULL,			/* ffunc */
		    NULL,			/* source */
		    0,				/* qcache_max */
		    vmem_flags);

		if (domain->dom_dvma_arena == NULL) {
			ddi_err(DER_PANIC, rdip,
			    "Failed to allocate DVMA arena(%s) "
			    "for domain ID (%d)", arena_name, domain->dom_did);
			/*NOTREACHED*/
		}

	} else {

		memlist_read_lock();

		mp = phys_install;

		if (mp->ml_address == 0)
			start = MMU_PAGESIZE;
		else
			start = mp->ml_address;

		if (start + mp->ml_size > maxaddr)
			size = maxaddr - start;
		else
			size = mp->ml_size;

		ddi_err(DER_VERB, rdip,
		    "%s: Creating dvma vmem arena [0x%" PRIx64
		    " - 0x%" PRIx64 "]", arena_name, start, start + size);

		ASSERT(domain->dom_dvma_arena == NULL);

		/*
		 * We always allocate in quanta of IMMU_PAGESIZE
		 */
		domain->dom_dvma_arena = vmem_create(arena_name,
		    (void *)(uintptr_t)start,	/* start addr */
		    size,			/* size */
		    IMMU_PAGESIZE,		/* quantum */
		    NULL,			/* afunc */
		    NULL,			/* ffunc */
		    NULL,			/* source */
		    0,				/* qcache_max */
		    vmem_flags);

		if (domain->dom_dvma_arena == NULL) {
			ddi_err(DER_PANIC, rdip,
			    "Failed to allocate DVMA arena(%s) "
			    "for domain ID (%d)", arena_name, domain->dom_did);
			/*NOTREACHED*/
		}

		mp = mp->ml_next;
		while (mp) {

			if (mp->ml_address == 0)
				start = MMU_PAGESIZE;
			else
				start = mp->ml_address;

			if (start + mp->ml_size > maxaddr)
				size = maxaddr - start;
			else
				size = mp->ml_size;

			ddi_err(DER_VERB, rdip,
			    "%s: Adding dvma vmem span [0x%" PRIx64
			    " - 0x%" PRIx64 "]", arena_name, start,
			    start + size);

			vmem_ret = vmem_add(domain->dom_dvma_arena,
			    (void *)(uintptr_t)start, size,  vmem_flags);

			if (vmem_ret == NULL) {
				ddi_err(DER_PANIC, rdip,
				    "Failed to allocate DVMA arena(%s) "
				    "for domain ID (%d)",
				    arena_name, domain->dom_did);
				/*NOTREACHED*/
			}

			mp = mp->ml_next;
		}
		memlist_read_unlock();
	}
}

/* ################################### DOMAIN CODE ######################### */

/*
 * Set the domain and domain-dip for a dip
 */
static void
set_domain(
	dev_info_t *dip,
	dev_info_t *ddip,
	domain_t *domain)
{
	immu_devi_t *immu_devi;
	domain_t *fdomain;
	dev_info_t *fddip;

	ASSERT(dip);
	ASSERT(ddip);
	ASSERT(domain);
	ASSERT(domain->dom_did > 0); /* must be an initialized domain */

	immu_devi = immu_devi_get(dip);
	ASSERT(immu_devi);

	mutex_enter(&(DEVI(dip)->devi_lock));
	fddip = immu_devi->imd_ddip;
	fdomain = immu_devi->imd_domain;

	if (fddip) {
		ASSERT(fddip == ddip);
	} else {
		immu_devi->imd_ddip = ddip;
	}

	if (fdomain) {
		ASSERT(fdomain == domain);
	} else {
		immu_devi->imd_domain = domain;
	}
	mutex_exit(&(DEVI(dip)->devi_lock));
}

/*
 * device_domain()
 * 	Get domain for a device. The domain may be global in which case it
 *	is shared between all IOMMU units. Due to potential AGAW differences
 *      between IOMMU units, such global domains *have to be* UNITY mapping
 *      domains. Alternatively, the domain may be local to a IOMMU unit.
 *	Local domains may be shared or immu_devi, although the
 *      scope of sharing
 *	is restricted to devices controlled by the IOMMU unit to
 *      which the domain
 *	belongs. If shared, they (currently) have to be UNITY domains. If
 *      immu_devi a domain may be either UNITY or translation (XLATE) domain.
 */
static domain_t *
device_domain(dev_info_t *rdip, dev_info_t **ddipp, immu_flags_t immu_flags)
{
	dev_info_t *ddip; /* topmost dip in domain i.e. domain owner */
	dev_info_t *edip; /* effective dip used for finding domain */
	immu_t *immu;
	domain_t *domain;
	dvma_arg_t dvarg = {0};
	int level;

	ASSERT(rdip);

	*ddipp = NULL;

	/*
	 * Check if the domain is already set. This is usually true
	 * if this is not the first DVMA transaction.
	 */
	ddip = NULL;
	domain = immu_devi_domain(rdip, &ddip);
	if (domain) {
		ASSERT(domain->dom_did > 0);
		ASSERT(ddip);
		*ddipp = ddip;
		return (domain);
	}

	immu = immu_dvma_get_immu(rdip, immu_flags);
	if (immu == NULL) {
		/*
		 * possible that there is no IOMMU unit for this device
		 * - BIOS bugs are one example.
		 */
		return (NULL);
	}

	/*
	 * Some devices need to be redirected
	 */
	edip = rdip;

	/*
	 * for isa devices attached under lpc
	 */
	if (strcmp(ddi_node_name(ddi_get_parent(rdip)), "isa") == 0) {
		edip = get_lpc_devinfo(immu, rdip, immu_flags);
	}

	/*
	 * for gart, use the real graphic devinfo
	 */
	if (strcmp(ddi_node_name(rdip), "agpgart") == 0) {
		edip = get_gfx_devinfo(rdip);
	}

	if (edip == NULL) {
		ddi_err(DER_MODE, rdip, "IMMU redirect failed");
		return (NULL);
	}

	dvarg.dva_rdip = edip;
	dvarg.dva_ddip = NULL;
	dvarg.dva_domain = NULL;
	dvarg.dva_flags = immu_flags;
	level = 0;
	if (immu_walk_ancestor(edip, NULL, get_branch_domain,
	    &dvarg, &level, immu_flags) != DDI_SUCCESS) {
		/*
		 * maybe low memory. return error,
		 * so driver tries again later
		 */
		return (NULL);
	}

	/* should have walked at least 1 dip (i.e. edip) */
	ASSERT(level > 0);

	ddip = dvarg.dva_ddip;	/* must be present */
	domain = dvarg.dva_domain;	/* may be NULL */

	/*
	 * We may find the domain during our ancestor walk on any one of our
	 * ancestor dips, If the domain is found then the domain-dip
	 * (i.e. ddip) will also be found in the same immu_devi struct.
	 * The domain-dip is the highest ancestor dip which shares the
	 * same domain with edip.
	 * The domain may or may not be found, but the domain dip must
	 * be found.
	 */
	if (ddip == NULL) {
		ddi_err(DER_MODE, rdip, "Cannot find domain dip for device. "
		    "Effective dip (%s%d)", ddi_driver_name(edip),
		    ddi_get_instance(edip));
		return (NULL);
	}

	/*
	 * Did we find a domain ?
	 */
	if (domain) {
		goto found;
	}

	/* nope, so allocate */
	domain = domain_create(immu, ddip, rdip, immu_flags);
	if (domain == NULL) {
		return (NULL);
	}
	ASSERT(domain->dom_did > 0);

	/*FALLTHROUGH*/
found:
	/*
	 * We know *domain *is* the right domain, so panic if
	 * another domain is set for either the request-dip or
	 * effective dip.
	 */
	set_domain(ddip, ddip, domain);
	set_domain(edip, ddip, domain);
	set_domain(rdip, ddip, domain);

	*ddipp = ddip;
	return (domain);
}

static void
create_unity_domain(immu_t *immu)
{
	domain_t *domain;

	/* 0 is reserved by Vt-d */
	/*LINTED*/
	ASSERT(IMMU_UNITY_DID > 0);

	/* domain created during boot and always use sleep flag */
	domain = kmem_zalloc(sizeof (domain_t), KM_SLEEP);

	rw_init(&(domain->dom_pgtable_rwlock), NULL, RW_DEFAULT, NULL);
	list_create(&(domain->dom_pglist), sizeof (pgtable_t),
	    offsetof(pgtable_t, swpg_domain_node));

	domain->dom_did = IMMU_UNITY_DID;
	domain->dom_maptype = IMMU_MAPTYPE_UNITY;

	domain->dom_immu = immu;
	immu->immu_unity_domain = domain;

	/*
	 * Setup the domain's initial page table
	 * should never fail.
	 */
	domain->dom_pgtable_root = pgtable_alloc(immu, domain,
	    IMMU_FLAGS_SLEEP);

	ASSERT(domain->dom_pgtable_root);

	map_unity_domain(domain);

	/*
	 * put it on the system-wide UNITY domain list
	 */
	mutex_enter(&(immu_domain_lock));
	list_insert_tail(&immu_unity_domain_list, domain);
	mutex_exit(&(immu_domain_lock));
}

/*
 * ddip is the domain-dip - the topmost dip in a domain
 * rdip is the requesting-dip - the device which is
 * requesting DVMA setup
 * if domain is a non-shared domain rdip == ddip
 */
static domain_t *
domain_create(immu_t *immu, dev_info_t *ddip, dev_info_t *rdip,
    immu_flags_t immu_flags)
{
	int kmflags;
	domain_t *domain;
	char mod_hash_name[128];
	immu_devi_t *immu_devi;
	int did;

	ASSERT(immu);
	ASSERT(ddip);

	immu_devi = immu_devi_get(rdip);

	ASSERT(immu_devi);

	/*
	 * First allocate a domainid.
	 * This routine will never fail, since if we run out
	 * of domains the unity domain will be allocated.
	 */
	did = did_alloc(immu, rdip, ddip, immu_flags);
	ASSERT(did > 0);
	if (did == IMMU_UNITY_DID) {
		/* domain overflow */
		ASSERT(immu->immu_unity_domain);
		return (immu->immu_unity_domain);
	}

	kmflags = (immu_flags & IMMU_FLAGS_NOSLEEP) ? KM_NOSLEEP : KM_SLEEP;
	domain = kmem_zalloc(sizeof (domain_t), kmflags);
	if (domain == NULL) {
		ddi_err(DER_PANIC, rdip, "Failed to alloc DVMA domain "
		    "structure for device. IOMMU unit: %s", immu->immu_name);
		/*NOTREACHED*/
	}

	rw_init(&(domain->dom_pgtable_rwlock), NULL, RW_DEFAULT, NULL);
	list_create(&(domain->dom_pglist), sizeof (pgtable_t),
	    offsetof(pgtable_t, swpg_domain_node));

	(void) snprintf(mod_hash_name, sizeof (mod_hash_name),
	    "immu%s-domain%d-pava-hash", immu->immu_name, did);

	domain->dom_did = did;
	domain->dom_immu = immu;
	domain->dom_maptype = IMMU_MAPTYPE_XLATE;

	/*
	 * Create xlate DVMA arena for this domain.
	 */
	create_xlate_arena(immu, domain, rdip, immu_flags);

	/*
	 * Setup the domain's initial page table
	 */
	domain->dom_pgtable_root = pgtable_alloc(immu, domain, immu_flags);
	if (domain->dom_pgtable_root == NULL) {
		ddi_err(DER_PANIC, rdip, "Failed to alloc root "
		    "pgtable for domain (%d). IOMMU unit: %s",
		    domain->dom_did, immu->immu_name);
		/*NOTREACHED*/
	}

	/*
	 * Since this is a immu unit-specific domain, put it on
	 * the per-immu domain list.
	 */
	mutex_enter(&(immu->immu_lock));
	list_insert_head(&immu->immu_domain_list, domain);
	mutex_exit(&(immu->immu_lock));

	/*
	 * Also put it on the system-wide xlate domain list
	 */
	mutex_enter(&(immu_domain_lock));
	list_insert_head(&immu_xlate_domain_list, domain);
	mutex_exit(&(immu_domain_lock));

	bdf_domain_insert(immu_devi, domain);

#ifdef BUGGY_DRIVERS
	/*
	 * Map page0. Some broken HW/FW access it.
	 */
	dvma_map(domain->dom_immu, domain, 0, 0, 1, NULL,
	    IMMU_FLAGS_READ | IMMU_FLAGS_WRITE | IMMU_FLAGS_PAGE1);
#endif

	return (domain);
}

/*
 * Create domainid arena.
 * Domainid 0 is reserved by Vt-d spec and cannot be used by
 * system software.
 * Domainid 1 is reserved by solaris and used for *all* of the following:
 *	as the "uninitialized" domain - For devices not yet controlled
 *	by Solaris
 *	as the "unity" domain - For devices that will always belong
 *	to the unity domain
 *	as the "overflow" domain - Used for any new device after we
 *	run out of domains
 * All of the above domains map into a single domain with
 * domainid 1 and UNITY DVMA mapping
 * Each IMMU unity has its own unity/uninit/overflow domain
 */
static void
did_init(immu_t *immu)
{
	(void) snprintf(immu->immu_did_arena_name,
	    sizeof (immu->immu_did_arena_name),
	    "%s_domainid_arena", immu->immu_name);

	ddi_err(DER_VERB, NULL, "%s: Creating domainid arena %s",
	    immu->immu_name, immu->immu_did_arena_name);

	immu->immu_did_arena = vmem_create(
	    immu->immu_did_arena_name,
	    (void *)(uintptr_t)(IMMU_UNITY_DID + 1),   /* start addr */
	    immu->immu_max_domains - IMMU_UNITY_DID,
	    1,				/* quantum */
	    NULL,			/* afunc */
	    NULL,			/* ffunc */
	    NULL,			/* source */
	    0,				/* qcache_max */
	    VM_SLEEP);

	/* Even with SLEEP flag, vmem_create() can fail */
	if (immu->immu_did_arena == NULL) {
		ddi_err(DER_PANIC, NULL, "%s: Failed to create Intel "
		    "IOMMU domainid allocator: %s", immu->immu_name,
		    immu->immu_did_arena_name);
	}
}

/* #########################  CONTEXT CODE ################################# */

static void
context_set(immu_t *immu, domain_t *domain, pgtable_t *root_table,
    int bus, int devfunc)
{
	pgtable_t *context;
	pgtable_t *pgtable_root;
	pgtable_t *unity_pgtable_root;
	hw_rce_t *hw_rent;
	hw_rce_t *hw_cent;
	hw_rce_t *ctxp;

	ASSERT(rw_write_held(&(immu->immu_ctx_rwlock)));

	ASSERT(immu);
	ASSERT(domain);
	ASSERT(root_table);
	ASSERT(bus >= 0);
	ASSERT(devfunc >= 0);
	ASSERT(domain->dom_pgtable_root);

	ctxp = (hw_rce_t *)(root_table->swpg_next_array);
	context = *(pgtable_t **)(ctxp + bus);
	hw_rent = (hw_rce_t *)(root_table->hwpg_vaddr) + bus;
	if (ROOT_GET_P(hw_rent)) {
		ASSERT(ROOT_GET_CONT(hw_rent) == context->hwpg_paddr);
	} else {
		ROOT_SET_CONT(hw_rent, context->hwpg_paddr);
		ROOT_SET_P(hw_rent);
		immu_regs_cpu_flush(immu, (caddr_t)hw_rent, sizeof (hw_rce_t));
	}
	hw_cent = (hw_rce_t *)(context->hwpg_vaddr) + devfunc;

	pgtable_root = domain->dom_pgtable_root;
	unity_pgtable_root = immu->immu_unity_domain->dom_pgtable_root;
	if (CONT_GET_AVAIL(hw_cent) == IMMU_CONT_UNINITED) {
		ASSERT(CONT_GET_P(hw_cent));
		ASSERT(CONT_GET_DID(hw_cent) ==
		    immu->immu_unity_domain->dom_did);
		ASSERT(CONT_GET_AW(hw_cent) == immu->immu_dvma_agaw);
		ASSERT(CONT_GET_TTYPE(hw_cent) == TTYPE_XLATE_ONLY);
		ASSERT(CONT_GET_ASR(hw_cent) ==
		    unity_pgtable_root->hwpg_paddr);

		/* need to disable context entry before reprogramming it */
		bzero(hw_cent, sizeof (hw_rce_t));

		/* flush caches */
		immu_regs_cpu_flush(immu, (caddr_t)hw_cent, sizeof (hw_rce_t));
		ASSERT(rw_write_held(&(immu->immu_ctx_rwlock)));
		immu_regs_context_flush(immu, 0, 0,
		    immu->immu_unity_domain->dom_did, CONTEXT_DSI);
		immu_regs_context_flush(immu, 0, 0, domain->dom_did,
		    CONTEXT_DSI);
		immu_regs_iotlb_flush(immu, immu->immu_unity_domain->dom_did,
		    0, 0, TLB_IVA_WHOLE, IOTLB_DSI);
		immu_regs_iotlb_flush(immu, domain->dom_did, 0, 0,
		    TLB_IVA_WHOLE, IOTLB_DSI);
		immu_regs_wbf_flush(immu);

		CONT_SET_AVAIL(hw_cent, IMMU_CONT_INITED);
		CONT_SET_DID(hw_cent, domain->dom_did);
		CONT_SET_AW(hw_cent, immu->immu_dvma_agaw);
		CONT_SET_ASR(hw_cent, pgtable_root->hwpg_paddr);
		/*LINTED*/
		CONT_SET_TTYPE(hw_cent, TTYPE_XLATE_ONLY);
		CONT_SET_P(hw_cent);
		immu_regs_cpu_flush(immu, (caddr_t)hw_cent, sizeof (hw_rce_t));
	} else {
		ASSERT(CONT_GET_AVAIL(hw_cent) == IMMU_CONT_INITED);
		ASSERT(CONT_GET_P(hw_cent));
		ASSERT(CONT_GET_DID(hw_cent) == domain->dom_did);
		ASSERT(CONT_GET_AW(hw_cent) == immu->immu_dvma_agaw);
		ASSERT(CONT_GET_TTYPE(hw_cent) == TTYPE_XLATE_ONLY);
		ASSERT(CONT_GET_ASR(hw_cent) == pgtable_root->hwpg_paddr);
	}
}

static pgtable_t *
context_create(immu_t *immu)
{
	int	bus;
	int	devfunc;
	pgtable_t *root_table;
	pgtable_t *context;
	pgtable_t *pgtable_root;
	hw_rce_t *ctxp;
	hw_rce_t *hw_rent;
	hw_rce_t *hw_cent;

	/* Allocate a zeroed root table (4K 256b entries) */
	root_table = pgtable_alloc(immu, NULL, IMMU_FLAGS_SLEEP);

	/*
	 * Setup context tables for all possible root table entries.
	 * Start out with unity domains for all entries.
	 */
	ctxp = (hw_rce_t *)(root_table->swpg_next_array);
	hw_rent = (hw_rce_t *)(root_table->hwpg_vaddr);
	for (bus = 0; bus < IMMU_ROOT_NUM; bus++, ctxp++, hw_rent++) {
		context = pgtable_alloc(immu, NULL, IMMU_FLAGS_SLEEP);
		ASSERT(ROOT_GET_P(hw_rent) == 0);
		ROOT_SET_P(hw_rent);
		ROOT_SET_CONT(hw_rent, context->hwpg_paddr);
		hw_cent = (hw_rce_t *)(context->hwpg_vaddr);
		for (devfunc = 0; devfunc < IMMU_CONT_NUM;
		    devfunc++, hw_cent++) {
			ASSERT(CONT_GET_P(hw_cent) == 0);
			pgtable_root =
			    immu->immu_unity_domain->dom_pgtable_root;
			CONT_SET_DID(hw_cent,
			    immu->immu_unity_domain->dom_did);
			CONT_SET_AW(hw_cent, immu->immu_dvma_agaw);
			CONT_SET_ASR(hw_cent, pgtable_root->hwpg_paddr);
			/*LINTED*/
			CONT_SET_TTYPE(hw_cent, TTYPE_XLATE_ONLY);
			CONT_SET_AVAIL(hw_cent, IMMU_CONT_UNINITED);
			CONT_SET_P(hw_cent);
		}
		immu_regs_cpu_flush(immu, context->hwpg_vaddr, IMMU_PAGESIZE);
		*((pgtable_t **)ctxp) = context;
	}
	immu_regs_cpu_flush(immu, root_table->hwpg_vaddr, IMMU_PAGESIZE);

	return (root_table);
}

/*
 * Called during rootnex attach, so no locks needed
 */
static void
context_init(immu_t *immu)
{
	ASSERT(immu);
	ASSERT(immu->immu_ctx_root == NULL);

	rw_init(&(immu->immu_ctx_rwlock), NULL, RW_DEFAULT, NULL);

	immu_regs_wbf_flush(immu);

	immu->immu_ctx_root = context_create(immu);

	immu_regs_set_root_table(immu);

	rw_enter(&(immu->immu_ctx_rwlock), RW_WRITER);
	immu_regs_context_flush(immu, 0, 0, 0, CONTEXT_GLOBAL);
	rw_exit(&(immu->immu_ctx_rwlock));
	immu_regs_iotlb_flush(immu, 0, 0, 0, 0, IOTLB_GLOBAL);
	immu_regs_wbf_flush(immu);
}


/*
 * Find top pcib
 */
static int
find_top_pcib(dev_info_t *dip, void *arg)
{
	immu_devi_t *immu_devi;
	dev_info_t **pcibdipp = (dev_info_t **)arg;

	ASSERT(dip);

	immu_devi = immu_devi_get(dip);
	ASSERT(immu_devi);

	if (immu_devi->imd_pcib_type == IMMU_PCIB_PCI_PCI) {
		*pcibdipp = dip;
	}

	return (DDI_WALK_CONTINUE);
}

static int
immu_context_update(immu_t *immu, domain_t *domain, dev_info_t *ddip,
    dev_info_t *rdip, immu_flags_t immu_flags)
{
	immu_devi_t *r_immu_devi;
	immu_devi_t *d_immu_devi;
	int r_bus;
	int d_bus;
	int r_devfunc;
	int d_devfunc;
	immu_pcib_t d_pcib_type;
	immu_pcib_t r_pcib_type;
	dev_info_t *pcibdip;

	if (ddip == NULL || rdip == NULL ||
	    ddip == root_devinfo || rdip == root_devinfo) {
		ddi_err(DER_MODE, rdip, "immu_contexts_update: domain-dip or "
		    "request-dip are NULL or are root devinfo");
		return (DDI_FAILURE);
	}

	/*
	 * We need to set the context fields
	 * based on what type of device rdip and ddip are.
	 * To do that we need the immu_devi field.
	 * Set the immu_devi field (if not already set)
	 */
	if (immu_devi_set(ddip, immu_flags) == DDI_FAILURE) {
		ddi_err(DER_MODE, rdip,
		    "immu_context_update: failed to set immu_devi for ddip");
		return (DDI_FAILURE);
	}

	if (immu_devi_set(rdip, immu_flags) == DDI_FAILURE) {
		ddi_err(DER_MODE, rdip,
		    "immu_context_update: failed to set immu_devi for rdip");
		return (DDI_FAILURE);
	}

	d_immu_devi = immu_devi_get(ddip);
	r_immu_devi = immu_devi_get(rdip);
	ASSERT(r_immu_devi);
	ASSERT(d_immu_devi);

	d_bus = d_immu_devi->imd_bus;
	d_devfunc = d_immu_devi->imd_devfunc;
	d_pcib_type = d_immu_devi->imd_pcib_type;
	r_bus = r_immu_devi->imd_bus;
	r_devfunc = r_immu_devi->imd_devfunc;
	r_pcib_type = r_immu_devi->imd_pcib_type;

	ASSERT(d_bus >= 0);

	rw_enter(&(immu->immu_ctx_rwlock), RW_WRITER);
	if (rdip == ddip) {
		ASSERT(d_pcib_type == IMMU_PCIB_ENDPOINT ||
		    d_pcib_type == IMMU_PCIB_PCIE_PCIE);
		ASSERT(r_bus >= 0);
		ASSERT(r_devfunc >= 0);
		/* rdip is a PCIE device. set context for it only */
		context_set(immu, domain, immu->immu_ctx_root, r_bus,
		    r_devfunc);
#ifdef BUGGY_DRIVERS
	} else if (r_immu_devi == d_immu_devi) {
#ifdef TEST
		ddi_err(DER_WARN, rdip, "Driver bug: Devices 0x%lx and "
		    "0x%lx are identical", rdip, ddip);
#endif
		ASSERT(d_pcib_type == IMMU_PCIB_ENDPOINT);
		ASSERT(r_bus >= 0);
		ASSERT(r_devfunc >= 0);
		/* rdip is a PCIE device. set context for it only */
		context_set(immu, domain, immu->immu_ctx_root, r_bus,
		    r_devfunc);
#endif
	} else if (d_pcib_type == IMMU_PCIB_PCIE_PCI) {
		/*
		 * ddip is a PCIE_PCI bridge. Set context for ddip's
		 * secondary bus. If rdip is on ddip's secondary
		 * bus, set context for rdip. Else, set context
		 * for rdip's PCI bridge on ddip's secondary bus.
		 */
		context_set(immu, domain, immu->immu_ctx_root,
		    d_immu_devi->imd_sec, 0);
		if (d_immu_devi->imd_sec == r_bus) {
			context_set(immu, domain, immu->immu_ctx_root,
			    r_bus, r_devfunc);
		} else {
			pcibdip = NULL;
			if (immu_walk_ancestor(rdip, ddip, find_top_pcib,
			    &pcibdip, NULL, immu_flags) == DDI_SUCCESS &&
			    pcibdip != NULL) {
				ASSERT(pcibdip);
				r_immu_devi = immu_devi_get(pcibdip);
				ASSERT(d_immu_devi);
				ASSERT(d_immu_devi->imd_pcib_type ==
				    IMMU_PCIB_PCI_PCI);
				r_bus = r_immu_devi->imd_bus;
				r_devfunc = r_immu_devi->imd_devfunc;
				context_set(immu, domain, immu->immu_ctx_root,
				    r_bus, r_devfunc);
			} else {
				ddi_err(DER_PANIC, rdip, "Failed to find PCI "
				    " bridge for PCI device");
				/*NOTREACHED*/
			}
		}
	} else if (d_pcib_type == IMMU_PCIB_PCI_PCI) {
		context_set(immu, domain, immu->immu_ctx_root, d_bus,
		    d_devfunc);
	} else if (d_pcib_type == IMMU_PCIB_ENDPOINT) {
		ASSERT(r_pcib_type == IMMU_PCIB_NOBDF);
		/*
		 * ddip is a PCIE device which has a non-PCI device under it
		 * i.e. it is a PCI-nonPCI bridge. Example: pciicde-ata
		 */
		context_set(immu, domain, immu->immu_ctx_root, d_bus,
		    d_devfunc);
	} else {
		ddi_err(DER_PANIC, rdip, "unknown device type. Cannot "
		    "set IMMU context.");
		/*NOTREACHED*/
	}
	rw_exit(&(immu->immu_ctx_rwlock));

	/* XXX do we need a membar_producer() here */
	return (DDI_SUCCESS);
}

/* ##################### END CONTEXT CODE ################################## */
/* ##################### MAPPING CODE ################################## */


static boolean_t
PDTE_check(immu_t *immu, hw_pdte_t pdte, pgtable_t *next, paddr_t paddr,
    dev_info_t *rdip, immu_flags_t immu_flags)
{
	if (immu_flags & IMMU_FLAGS_PAGE1) {
		ASSERT(paddr == 0);
	} else {
		ASSERT((next == NULL) ^ (paddr == 0));
	}

	/* The PDTE must be set i.e. present bit is set */
	if (!PDTE_P(pdte)) {
		ddi_err(DER_MODE, rdip, "No present flag");
		return (B_FALSE);
	}

	/*
	 * Just assert to check most significant system software field
	 * (PDTE_SW4) as it is same as present bit and we
	 * checked that above
	 */
	ASSERT(PDTE_SW4(pdte));

	/*
	 * TM field should be clear if not reserved.
	 * non-leaf is always reserved
	 */
	if (next == NULL && immu_regs_is_TM_reserved(immu) == B_FALSE) {
		if (PDTE_TM(pdte)) {
			ddi_err(DER_MODE, rdip, "TM flag set");
			return (B_FALSE);
		}
	}

	/*
	 * The SW3 field is not used and must be clear
	 */
	if (PDTE_SW3(pdte)) {
		ddi_err(DER_MODE, rdip, "SW3 set");
		return (B_FALSE);
	}

	/*
	 * PFN (for PTE) or next level pgtable-paddr (for PDE) must be set
	 */
	if (next == NULL) {
		ASSERT(paddr % IMMU_PAGESIZE == 0);
		if (PDTE_PADDR(pdte) != paddr) {
			ddi_err(DER_MODE, rdip,
			    "PTE paddr mismatch: %lx != %lx",
			    PDTE_PADDR(pdte), paddr);
			return (B_FALSE);
		}
	} else {
		if (PDTE_PADDR(pdte) != next->hwpg_paddr) {
			ddi_err(DER_MODE, rdip,
			    "PDE paddr mismatch: %lx != %lx",
			    PDTE_PADDR(pdte), next->hwpg_paddr);
			return (B_FALSE);
		}
	}

	/*
	 * SNP field should be clear if not reserved.
	 * non-leaf is always reserved
	 */
	if (next == NULL && immu_regs_is_SNP_reserved(immu) == B_FALSE) {
		if (PDTE_SNP(pdte)) {
			ddi_err(DER_MODE, rdip, "SNP set");
			return (B_FALSE);
		}
	}

	/* second field available for system software should be clear */
	if (PDTE_SW2(pdte)) {
		ddi_err(DER_MODE, rdip, "SW2 set");
		return (B_FALSE);
	}

	/* Super pages field should be clear */
	if (PDTE_SP(pdte)) {
		ddi_err(DER_MODE, rdip, "SP set");
		return (B_FALSE);
	}

	/*
	 * least significant field available for
	 * system software should be clear
	 */
	if (PDTE_SW1(pdte)) {
		ddi_err(DER_MODE, rdip, "SW1 set");
		return (B_FALSE);
	}

	if ((immu_flags & IMMU_FLAGS_READ) && !PDTE_READ(pdte)) {
		ddi_err(DER_MODE, rdip, "READ not set");
		return (B_FALSE);
	}

	if ((immu_flags & IMMU_FLAGS_WRITE) && !PDTE_WRITE(pdte)) {
		ddi_err(DER_MODE, rdip, "WRITE not set");
		return (B_FALSE);
	}

	return (B_TRUE);
}
/*ARGSUSED*/
static void
PTE_clear_one(immu_t *immu, domain_t *domain, xlate_t *xlate, uint64_t dvma,
    dev_info_t *rdip)
{
	hw_pdte_t *hwp;
	pgtable_t *pgtable;
	int idx;
	hw_pdte_t pte;

	ASSERT(xlate->xlt_level == 1);

	idx = xlate->xlt_idx;
	pgtable = xlate->xlt_pgtable;

	ASSERT(dvma % IMMU_PAGESIZE == 0);
	ASSERT(pgtable);
	ASSERT(idx <= IMMU_PGTABLE_MAXIDX);

	/*
	 * since we are clearing PTEs, lock the
	 * page table write mode
	 */
	rw_enter(&(pgtable->swpg_rwlock), RW_WRITER);

	/*
	 * We are at the leaf - next level array must be NULL
	 */
	ASSERT(pgtable->swpg_next_array == NULL);

	hwp = (hw_pdte_t *)(pgtable->hwpg_vaddr) + idx;

	pte = *hwp;
	/* Cannot clear a HW PTE that is aleady clear */
	ASSERT(PDTE_P(pte));
	PDTE_CLEAR_P(pte);
	*hwp = pte;

	/* flush writes to HW PTE table */
	immu_regs_cpu_flush(immu, (caddr_t)hwp, sizeof (hw_pdte_t));

	rw_exit(&(xlate->xlt_pgtable->swpg_rwlock));
}

/*ARGSUSED*/
static void
xlate_setup(immu_t *immu, uint64_t dvma, xlate_t *xlate,
    int nlevels, dev_info_t *rdip)
{
	int level;
	uint64_t offbits;

	/* level 0 is never used. Sanity check */
	ASSERT(xlate->xlt_level == 0);
	ASSERT(xlate->xlt_idx == 0);
	ASSERT(xlate->xlt_pgtable == NULL);
	ASSERT(dvma % IMMU_PAGESIZE == 0);

	/*
	 * Skip the first 12 bits which is the offset into
	 * 4K PFN (phys page frame based on IMMU_PAGESIZE)
	 */
	offbits = dvma >> IMMU_PAGESHIFT;

	/* skip to level 1 i.e. leaf PTE */
	for (level = 1, xlate++; level <= nlevels; level++, xlate++) {
		xlate->xlt_level = level;
		xlate->xlt_idx = (offbits & IMMU_PGTABLE_LEVEL_MASK);
		ASSERT(xlate->xlt_idx <= IMMU_PGTABLE_MAXIDX);
		xlate->xlt_pgtable = NULL;
		offbits >>= IMMU_PGTABLE_LEVEL_STRIDE;
	}
}

/*
 * Read the pgtables
 */
static void
PDE_lookup(immu_t *immu, domain_t *domain, xlate_t *xlate, int nlevels,
    dev_info_t *rdip)
{
	pgtable_t *pgtable;
	pgtable_t *next;
	hw_pdte_t pde;
	uint_t idx;

	/* xlate should be at level 0 */
	ASSERT(xlate->xlt_level == 0);
	ASSERT(xlate->xlt_idx == 0);

	/* start with highest level pgtable i.e. root */
	xlate += nlevels;
	ASSERT(xlate->xlt_level == nlevels);

	if (xlate->xlt_pgtable == NULL) {
		xlate->xlt_pgtable = domain->dom_pgtable_root;
	}

	for (; xlate->xlt_level > 1; xlate--) {

		idx = xlate->xlt_idx;
		pgtable = xlate->xlt_pgtable;

		ASSERT(pgtable);
		ASSERT(idx <= IMMU_PGTABLE_MAXIDX);

		if ((xlate - 1)->xlt_pgtable) {
			continue;
		}

		/* xlate's leafier level is not set, set it now */

		/* Lock the pgtable in read mode */
		rw_enter(&(pgtable->swpg_rwlock), RW_READER);

		/*
		 * since we are unmapping, the pgtable should
		 * already point to a leafier pgtable.
		 */
		next = *(pgtable->swpg_next_array + idx);
		ASSERT(next);

		pde = *((hw_pdte_t *)(pgtable->hwpg_vaddr) + idx);

		ASSERT(PDTE_check(immu, pde, next, 0, rdip, 0) == B_TRUE);

		(xlate - 1)->xlt_pgtable = next;

		rw_exit(&(pgtable->swpg_rwlock));
	}
}

static void
PTE_set_one(immu_t *immu, hw_pdte_t *hwp, paddr_t paddr,
    dev_info_t *rdip, immu_flags_t immu_flags)
{
	hw_pdte_t pte;

	pte = *hwp;

	if (PDTE_P(pte)) {
		if (PDTE_PADDR(pte) != paddr) {
			ddi_err(DER_MODE, rdip, "PTE paddr %lx != paddr %lx",
			    PDTE_PADDR(pte), paddr);
		}
		goto out;
	}


	/* Don't touch SW4. It is the present field */

	/* clear TM field if not reserved */
	if (immu_regs_is_TM_reserved(immu) == B_FALSE) {
		PDTE_CLEAR_TM(pte);
	}

	/* Clear 3rd field for system software  - not used */
	PDTE_CLEAR_SW3(pte);

	/* Set paddr */
	ASSERT(paddr % IMMU_PAGESIZE == 0);
	PDTE_CLEAR_PADDR(pte);
	PDTE_SET_PADDR(pte, paddr);

	/*  clear SNP field if not reserved. */
	if (immu_regs_is_SNP_reserved(immu) == B_FALSE) {
		PDTE_CLEAR_SNP(pte);
	}

	/* Clear SW2 field available for software */
	PDTE_CLEAR_SW2(pte);

	/* SP is don't care for PTEs. Clear it for cleanliness */
	PDTE_CLEAR_SP(pte);

	/* Clear SW1 field available for software */
	PDTE_CLEAR_SW1(pte);

	/*
	 * Now that we are done writing the PTE
	 * set the "present" flag. Note this present
	 * flag is a bit in the PDE/PTE that the
	 * spec says is available for system software.
	 * This is an implementation detail of Solaris
	 * bare-metal Intel IOMMU.
	 * The present field in a PDE/PTE is not defined
	 * by the Vt-d spec
	 */

	PDTE_SET_P(pte);

out:
	if (immu_flags & IMMU_FLAGS_READ)
		PDTE_SET_READ(pte);
	if (immu_flags & IMMU_FLAGS_WRITE)
		PDTE_SET_WRITE(pte);

#ifdef BUGGY_DRIVERS
	PDTE_SET_READ(pte);
	PDTE_SET_WRITE(pte);
#endif

	*hwp = pte;
}

/*ARGSUSED*/
static void
PTE_set_all(immu_t *immu, domain_t *domain, xlate_t *xlate,
    uint64_t *dvma_ptr, paddr_t *paddr_ptr, uint64_t *npages_ptr,
    dev_info_t *rdip, immu_flags_t immu_flags)
{
	paddr_t paddr;
	uint64_t npages;
	uint64_t dvma;
	pgtable_t *pgtable;
	hw_pdte_t *hwp;
	hw_pdte_t *shwp;
	int idx;

	ASSERT(xlate->xlt_level == 1);

	pgtable = xlate->xlt_pgtable;
	idx = xlate->xlt_idx;

	ASSERT(idx <= IMMU_PGTABLE_MAXIDX);
	ASSERT(pgtable);

	dvma = *dvma_ptr;
	paddr = *paddr_ptr;
	npages = *npages_ptr;

	ASSERT(paddr || (immu_flags & IMMU_FLAGS_PAGE1));
	ASSERT(dvma || (immu_flags & IMMU_FLAGS_PAGE1));
	ASSERT(npages);

	/*
	 * since we are setting PTEs, lock the page table in
	 * write mode
	 */
	rw_enter(&(pgtable->swpg_rwlock), RW_WRITER);

	/*
	 * we are at the leaf pgtable - no further levels.
	 * The next_array field should be NULL.
	 */
	ASSERT(pgtable->swpg_next_array == NULL);

	shwp = (hw_pdte_t *)(pgtable->hwpg_vaddr) + idx;

	hwp = shwp;
	for (; npages > 0 && idx <= IMMU_PGTABLE_MAXIDX; idx++, hwp++) {

		PTE_set_one(immu, hwp, paddr, rdip, immu_flags);

		ASSERT(PDTE_check(immu, *hwp, NULL, paddr, rdip, immu_flags)
		    == B_TRUE);

		paddr += IMMU_PAGESIZE;
		dvma += IMMU_PAGESIZE;
		npages--;
	}

	/* flush writes to HW PTE table */
	immu_regs_cpu_flush(immu, (caddr_t)shwp, (hwp - shwp) *
	    sizeof (hw_pdte_t));

	*dvma_ptr = dvma;
	*paddr_ptr = paddr;
	*npages_ptr = npages;
	xlate->xlt_idx = idx;

	rw_exit(&(pgtable->swpg_rwlock));
}

/*ARGSUSED*/
static void
PDE_set_one(immu_t *immu, hw_pdte_t *hwp, pgtable_t *next,
    dev_info_t *rdip, immu_flags_t immu_flags)
{
	hw_pdte_t pde;

	pde = *hwp;

	/* if PDE is already set, make sure it is correct */
	if (PDTE_P(pde)) {
		ASSERT(PDTE_PADDR(pde) == next->hwpg_paddr);
		goto out;
	}

	/* Dont touch SW4, it is the present bit */

	/* don't touch TM field it is reserved for PDEs */

	/* 3rd field available for system software is not used */
	PDTE_CLEAR_SW3(pde);

	/* Set next level pgtable-paddr for PDE */
	ASSERT(next->hwpg_paddr % IMMU_PAGESIZE == 0);
	PDTE_CLEAR_PADDR(pde);
	PDTE_SET_PADDR(pde, next->hwpg_paddr);

	/* don't touch SNP field it is reserved for PDEs */

	/* Clear second field available for system software */
	PDTE_CLEAR_SW2(pde);

	/* No super pages for PDEs */
	PDTE_CLEAR_SP(pde);

	/* Clear SW1 for software */
	PDTE_CLEAR_SW1(pde);

	/*
	 * Now that we are done writing the PDE
	 * set the "present" flag. Note this present
	 * flag is a bit in the PDE/PTE that the
	 * spec says is available for system software.
	 * This is an implementation detail of Solaris
	 * base-metal Intel IOMMU.
	 * The present field in a PDE/PTE is not defined
	 * by the Vt-d spec
	 */
out:

	if (immu_flags & IMMU_FLAGS_READ)
		PDTE_SET_READ(pde);
	if (immu_flags & IMMU_FLAGS_WRITE)
		PDTE_SET_WRITE(pde);

#ifdef  BUGGY_DRIVERS
	PDTE_SET_READ(pde);
	PDTE_SET_WRITE(pde);
#endif

	PDTE_SET_P(pde);

	*hwp = pde;

	immu_regs_cpu_flush(immu, (caddr_t)hwp, sizeof (hw_pdte_t));
}

/*
 * Used to set PDEs
 */
static void
PDE_set_all(immu_t *immu, domain_t *domain, xlate_t *xlate, int nlevels,
    dev_info_t *rdip, immu_flags_t immu_flags)
{
	pgtable_t *pgtable;
	pgtable_t *new;
	pgtable_t *next;
	hw_pdte_t *hwp;
	int level;
	uint_t idx;

	/* xlate should be at level 0 */
	ASSERT(xlate->xlt_level == 0);
	ASSERT(xlate->xlt_idx == 0);

	/* start with highest level pgtable i.e. root */
	xlate += nlevels;
	ASSERT(xlate->xlt_level == nlevels);

	new = NULL;
	xlate->xlt_pgtable = domain->dom_pgtable_root;
	for (level = nlevels; level > 1; level--, xlate--) {

		ASSERT(xlate->xlt_level == level);

		idx = xlate->xlt_idx;
		pgtable = xlate->xlt_pgtable;

		ASSERT(pgtable);
		ASSERT(idx <= IMMU_PGTABLE_MAXIDX);

		/* speculative alloc */
		if (new == NULL) {
			new = pgtable_alloc(immu, domain, immu_flags);
			if (new == NULL) {
				ddi_err(DER_PANIC, rdip, "pgtable alloc err");
			}

		}

		/* Alway lock the pgtable in write mode */
		rw_enter(&(pgtable->swpg_rwlock), RW_WRITER);

		hwp = (hw_pdte_t *)(pgtable->hwpg_vaddr) + idx;

		ASSERT(pgtable->swpg_next_array);

		next = (pgtable->swpg_next_array)[idx];

		/*
		 * check if leafier level already has a pgtable
		 * if yes, verify
		 */
		if (next == NULL) {
			next = new;
			new = NULL;
			if (level == 2) {
				/* leaf cannot have next_array */
				kmem_free(next->swpg_next_array,
				    IMMU_PAGESIZE);
				next->swpg_next_array = NULL;
			}
			(pgtable->swpg_next_array)[idx] = next;
			PDE_set_one(immu, hwp, next, rdip, immu_flags);
		} else {
			hw_pdte_t pde = *hwp;

			if (immu_flags & IMMU_FLAGS_READ)
				PDTE_SET_READ(pde);
			if (immu_flags & IMMU_FLAGS_WRITE)
				PDTE_SET_WRITE(pde);

#ifdef  BUGGY_DRIVERS
/* If buggy driver we already set permission READ+WRITE so nothing to do */
#endif

			*hwp = pde;
		}

		ASSERT(PDTE_check(immu, *hwp, next, 0, rdip, immu_flags)
		    == B_TRUE);

		(xlate - 1)->xlt_pgtable = next;

		rw_exit(&(pgtable->swpg_rwlock));
	}

	if (new) {
		pgtable_free(immu, new, domain);
	}
}

/*
 * dvma_map()
 *     map a contiguous range of DVMA pages
 *
 *     immu: IOMMU unit for which we are generating DVMA cookies
 *   domain: domain
 *    sdvma: Starting dvma
 *   spaddr: Starting paddr
 *   npages: Number of pages
 *     rdip: requesting device
 *     immu_flags: flags
 */
static void
dvma_map(immu_t *immu, domain_t *domain, uint64_t sdvma, uint64_t spaddr,
    uint64_t npages, dev_info_t *rdip, immu_flags_t immu_flags)
{
	uint64_t dvma;
	paddr_t paddr;
	uint64_t n;
	int nlevels = immu->immu_dvma_nlevels;
	xlate_t xlate[IMMU_PGTABLE_MAX_LEVELS + 1] = {0};

	ASSERT(nlevels <= IMMU_PGTABLE_MAX_LEVELS);
	ASSERT(spaddr % IMMU_PAGESIZE == 0);
	ASSERT(sdvma % IMMU_PAGESIZE == 0);
	ASSERT(npages);

	n = npages;
	dvma = sdvma;
	paddr = spaddr;

	while (n > 0) {
		xlate_setup(immu, dvma, xlate, nlevels, rdip);

		/* Lookup or allocate PGDIRs and PGTABLEs if necessary */
		PDE_set_all(immu, domain, xlate, nlevels, rdip, immu_flags);

		/* set all matching ptes that fit into this leaf pgtable */
		PTE_set_all(immu, domain, &xlate[1], &dvma, &paddr, &n, rdip,
		    immu_flags);
	}
}

/*
 * dvma_unmap()
 *   unmap a range of DVMAs
 *
 * immu: IOMMU unit state
 * domain: domain for requesting device
 * ddip: domain-dip
 * dvma: starting DVMA
 * npages: Number of IMMU pages to be unmapped
 * rdip: requesting device
 */
static void
dvma_unmap(immu_t *immu, domain_t *domain, uint64_t dvma, uint64_t snpages,
    dev_info_t *rdip)
{
	int nlevels = immu->immu_dvma_nlevels;
	xlate_t xlate[IMMU_PGTABLE_MAX_LEVELS + 1] = {0};
	uint64_t npages;

	ASSERT(nlevels <= IMMU_PGTABLE_MAX_LEVELS);
	ASSERT(dvma != 0);
	ASSERT(dvma % IMMU_PAGESIZE == 0);
	ASSERT(snpages);

	for (npages = snpages; npages > 0; npages--) {
		/* setup the xlate array */
		xlate_setup(immu, dvma, xlate, nlevels, rdip);

		/* just lookup existing pgtables. Should never fail */
		PDE_lookup(immu, domain, xlate, nlevels, rdip);

		/* XXX should be more efficient - batch clear */
		PTE_clear_one(immu, domain, &xlate[1], dvma, rdip);

		dvma += IMMU_PAGESIZE;
	}
}

static uint64_t
dvma_alloc(ddi_dma_impl_t *hp, domain_t *domain, uint_t npages)
{
	ddi_dma_attr_t *dma_attr;
	uint64_t dvma;
	size_t xsize, align, nocross;
	uint64_t minaddr, maxaddr;

	ASSERT(domain->dom_maptype != IMMU_MAPTYPE_UNITY);

	/* shotcuts */
	dma_attr = &(hp->dmai_attr);

	/* parameters */
	xsize = npages * IMMU_PAGESIZE;
	align = MAX((size_t)(dma_attr->dma_attr_align), IMMU_PAGESIZE);
	nocross = (size_t)(dma_attr->dma_attr_seg + 1);
	minaddr = dma_attr->dma_attr_addr_lo;
	maxaddr = dma_attr->dma_attr_addr_hi + 1;

	/* handle the rollover cases */
	if (maxaddr < dma_attr->dma_attr_addr_hi) {
		maxaddr = dma_attr->dma_attr_addr_hi;
	}

	/*
	 * allocate from vmem arena.
	 */
	dvma = (uint64_t)(uintptr_t)vmem_xalloc(domain->dom_dvma_arena,
	    xsize, align, 0, nocross, (void *)(uintptr_t)minaddr,
	    (void *)(uintptr_t)maxaddr, VM_NOSLEEP);

	ASSERT(dvma);
	ASSERT(dvma >= minaddr);
	ASSERT(dvma + xsize - 1 < maxaddr);

	return (dvma);
}

static void
dvma_free(domain_t *domain, uint64_t dvma, uint64_t npages)
{
	uint64_t size = npages * IMMU_PAGESIZE;

	ASSERT(domain);
	ASSERT(domain->dom_did > 0);
	ASSERT(dvma);
	ASSERT(npages);

	if (domain->dom_maptype != IMMU_MAPTYPE_XLATE) {
		ASSERT(domain->dom_maptype == IMMU_MAPTYPE_UNITY);
		return;
	}

	vmem_free(domain->dom_dvma_arena, (void *)(uintptr_t)dvma, size);
}
/*ARGSUSED*/
static void
cookie_free(rootnex_dma_t *dma, immu_t *immu, domain_t *domain,
    dev_info_t *ddip, dev_info_t *rdip)
{
	int i;
	uint64_t dvma;
	uint64_t npages;
	dvcookie_t  *dvcookies = dma->dp_dvcookies;
	uint64_t dvmax =  dma->dp_dvmax;

	ASSERT(dma->dp_max_cookies);
	ASSERT(dma->dp_max_dcookies);
	ASSERT(dma->dp_dvmax < dma->dp_max_cookies);
	ASSERT(dma->dp_dmax < dma->dp_max_dcookies);

	for (i = 0; i <= dvmax; i++) {
		dvma = dvcookies[i].dvck_dvma;
		npages = dvcookies[i].dvck_npages;
		dvma_unmap(immu, domain, dvma, npages, rdip);
		dvma_free(domain, dvma, npages);
	}

	kmem_free(dma->dp_dvcookies, sizeof (dvcookie_t) * dma->dp_max_cookies);
	dma->dp_dvcookies = NULL;
	kmem_free(dma->dp_dcookies, sizeof (dcookie_t) * dma->dp_max_dcookies);
	dma->dp_dcookies = NULL;
	if (dma->dp_need_to_free_cookie == B_TRUE) {
		kmem_free(dma->dp_cookies, sizeof (ddi_dma_cookie_t) *
		    dma->dp_max_cookies);
		dma->dp_dcookies = NULL;
		dma->dp_need_to_free_cookie = B_FALSE;
	}

	dma->dp_max_cookies = 0;
	dma->dp_max_dcookies = 0;
	dma->dp_cookie_size = 0;
	dma->dp_dvmax = 0;
	dma->dp_dmax = 0;
}

/*
 * cookie_alloc()
 */
static int
cookie_alloc(rootnex_dma_t *dma, struct ddi_dma_req *dmareq,
    ddi_dma_attr_t *attr, uint_t prealloc)
{
	int kmflag;
	rootnex_sglinfo_t *sinfo = &(dma->dp_sglinfo);
	dvcookie_t *dvcookies = dma->dp_dvcookies;
	dcookie_t *dcookies = dma->dp_dcookies;
	ddi_dma_cookie_t *cookies = dma->dp_cookies;
	uint64_t max_cookies;
	uint64_t max_dcookies;
	uint64_t cookie_size;

	/* we need to allocate new array */
	if (dmareq->dmar_fp == DDI_DMA_SLEEP) {
		kmflag =  KM_SLEEP;
	} else {
		kmflag =  KM_NOSLEEP;
	}

	/*
	 * XXX make sure cookies size doen't exceed sinfo->si_max_cookie_size;
	 */

	/*
	 * figure out the rough estimate of array size
	 * At a minimum, each cookie must hold 1 page.
	 * At a maximum, it cannot exceed dma_attr_sgllen
	 */
	max_dcookies = dmareq->dmar_object.dmao_size + IMMU_PAGEOFFSET;
	max_dcookies /= IMMU_PAGESIZE;
	max_dcookies++;
	max_cookies = MIN(max_dcookies, attr->dma_attr_sgllen);

	/* allocate the dvma cookie array */
	dvcookies = kmem_zalloc(sizeof (dvcookie_t) * max_cookies, kmflag);
	if (dvcookies == NULL) {
		return (DDI_FAILURE);
	}

	/* allocate the "phys" cookie array */
	dcookies = kmem_zalloc(sizeof (dcookie_t) * max_dcookies, kmflag);
	if (dcookies == NULL) {
		kmem_free(dvcookies, sizeof (dvcookie_t) * max_cookies);
		dvcookies = NULL;
		return (DDI_FAILURE);
	}

	/* allocate the "real" cookie array  - the one given to users */
	cookie_size = sizeof (ddi_dma_cookie_t) * max_cookies;
	if (max_cookies > prealloc) {
		cookies = kmem_zalloc(cookie_size, kmflag);
		if (cookies == NULL) {
			kmem_free(dvcookies, sizeof (dvcookie_t) *
			    max_cookies);
			kmem_free(dcookies, sizeof (dcookie_t) *
			    max_dcookies);
			goto fail;
		}
		dma->dp_need_to_free_cookie = B_TRUE;
	} else {
		/* the preallocated buffer fits this size */
		cookies = (ddi_dma_cookie_t *)dma->dp_prealloc_buffer;
		bzero(cookies, sizeof (ddi_dma_cookie_t) * max_cookies);
		dma->dp_need_to_free_cookie = B_FALSE;
	}

	dma->dp_dvcookies = dvcookies;
	dma->dp_dcookies = dcookies;
	dma->dp_cookies = cookies;
	dma->dp_cookie_size = cookie_size;
	dma->dp_max_cookies = max_cookies;
	dma->dp_max_dcookies = max_dcookies;
	dma->dp_dvmax = 0;
	dma->dp_dmax = 0;

	sinfo->si_max_pages = dma->dp_max_cookies;

	return (DDI_SUCCESS);

fail:
	dma->dp_dvcookies = NULL;
	dma->dp_dcookies = NULL;
	dma->dp_cookies = NULL;
	dma->dp_cookie_size = 0;
	dma->dp_max_cookies = 0;
	dma->dp_max_dcookies = 0;
	dma->dp_dvmax = 0;
	dma->dp_dmax = 0;
	dma->dp_need_to_free_cookie = B_FALSE;
	sinfo->si_max_pages = 0;
	return (DDI_FAILURE);
}

/*ARGSUSED*/
static void
cookie_update(domain_t *domain, rootnex_dma_t *dma, paddr_t paddr,
    int64_t psize, uint64_t maxseg)
{
	dvcookie_t *dvcookies = dma->dp_dvcookies;
	dcookie_t *dcookies = dma->dp_dcookies;
	ddi_dma_cookie_t *cookies = dma->dp_cookies;
	uint64_t dvmax = dma->dp_dvmax;
	uint64_t dmax = dma->dp_dmax;

	ASSERT(dvmax < dma->dp_max_cookies);
	ASSERT(dmax < dma->dp_max_dcookies);

	paddr &= IMMU_PAGEMASK;

	ASSERT(paddr);
	ASSERT(psize);
	ASSERT(maxseg);

	/*
	 * check to see if this page would put us
	 * over the max cookie size
	 */
	if (cookies[dvmax].dmac_size + psize > maxseg) {
		dvcookies[dvmax].dvck_eidx = dmax;
		dvmax++;    /* use the next dvcookie */
		dmax++;    /* also mean we use the next dcookie */
		dvcookies[dvmax].dvck_sidx = dmax;

		ASSERT(dvmax < dma->dp_max_cookies);
		ASSERT(dmax < dma->dp_max_dcookies);
	}

	/*
	 * If the cookie is mapped or empty
	 */
	if (dvcookies[dvmax].dvck_dvma != 0 ||
	    dvcookies[dvmax].dvck_npages == 0) {
		/* if mapped, we need a new empty one */
		if (dvcookies[dvmax].dvck_dvma != 0) {
			dvcookies[dvmax].dvck_eidx = dmax;
			dvmax++;
			dmax++;
			dvcookies[dvmax].dvck_sidx = dma->dp_dmax;
			ASSERT(dvmax < dma->dp_max_cookies);
			ASSERT(dmax < dma->dp_max_dcookies);
		}

		/* ok, we have an empty cookie */
		ASSERT(cookies[dvmax].dmac_size == 0);
		ASSERT(dvcookies[dvmax].dvck_dvma == 0);
		ASSERT(dvcookies[dvmax].dvck_npages
		    == 0);
		ASSERT(dcookies[dmax].dck_paddr == 0);
		ASSERT(dcookies[dmax].dck_npages == 0);

		dvcookies[dvmax].dvck_dvma = 0;
		dvcookies[dvmax].dvck_npages = 1;
		dcookies[dmax].dck_paddr = paddr;
		dcookies[dmax].dck_npages = 1;
		cookies[dvmax].dmac_size = psize;
	} else {
		/* Unmapped cookie but not empty. Add to it */
		cookies[dma->dp_dvmax].dmac_size += psize;
		ASSERT(dvcookies[dma->dp_dvmax].dvck_dvma == 0);
		dvcookies[dma->dp_dvmax].dvck_npages++;
		ASSERT(dcookies[dmax].dck_paddr != 0);
		ASSERT(dcookies[dmax].dck_npages != 0);

		/* Check if this paddr is contiguous */
		if (IMMU_CONTIG_PADDR(dcookies[dmax], paddr)) {
			dcookies[dmax].dck_npages++;
		} else {
			/* No, we need a new dcookie */
			dmax++;
			ASSERT(dcookies[dmax].dck_paddr == 0);
			ASSERT(dcookies[dmax].dck_npages == 0);
			dcookies[dmax].dck_paddr = paddr;
			dcookies[dmax].dck_npages = 1;
		}
	}

	dma->dp_dvmax = dvmax;
	dma->dp_dmax = dmax;
}

static void
cookie_finalize(ddi_dma_impl_t *hp, immu_t *immu, domain_t *domain,
    dev_info_t *rdip, immu_flags_t immu_flags)
{
	int i;
	int j;
	rootnex_dma_t *dma = (rootnex_dma_t *)hp->dmai_private;
	dvcookie_t *dvcookies = dma->dp_dvcookies;
	dcookie_t *dcookies = dma->dp_dcookies;
	ddi_dma_cookie_t *cookies = dma->dp_cookies;
	paddr_t paddr;
	uint64_t npages;
	uint64_t dvma;

	for (i = 0; i <= dma->dp_dvmax; i++) {
		/* Finish up the last cookie */
		if (i == dma->dp_dvmax) {
			dvcookies[i].dvck_eidx = dma->dp_dmax;
		}
		if ((dvma = dvcookies[i].dvck_dvma) != 0) {
			cookies[i].dmac_laddress = dvma;
			ASSERT(cookies[i].dmac_size != 0);
			cookies[i].dmac_type = 0;
			for (j = dvcookies[i].dvck_sidx;
			    j <= dvcookies[i].dvck_eidx; j++) {
				ASSERT(dcookies[j].dck_paddr != 0);
				ASSERT(dcookies[j].dck_npages != 0);
			}
			continue;
		}

		dvma = dvma_alloc(hp, domain, dvcookies[i].dvck_npages);

		dvcookies[i].dvck_dvma = dvma;

		/* Set "real" cookies addr, cookie size already set */
		cookies[i].dmac_laddress = dvma;
		ASSERT(cookies[i].dmac_size != 0);
		cookies[i].dmac_type = 0;

		for (j = dvcookies[i].dvck_sidx;
		    j <= dvcookies[i].dvck_eidx; j++) {

			paddr = dcookies[j].dck_paddr;
			npages = dcookies[j].dck_npages;

			ASSERT(paddr);
			ASSERT(npages);

			dvma_map(immu, domain, dvma, paddr, npages,
			    rdip, immu_flags);
			dvma += npages * IMMU_PAGESIZE;
		}
	}
}

/*
 * cookie_create()
 */
static int
cookie_create(ddi_dma_impl_t *hp, struct ddi_dma_req *dmareq,
    ddi_dma_attr_t *a, immu_t *immu, domain_t *domain, dev_info_t *rdip,
    uint_t prealloc_count, immu_flags_t immu_flags)
{

	ddi_dma_atyp_t buftype;
	uint64_t offset;
	page_t **pparray;
	uint64_t paddr;
	uint_t psize;
	uint_t size;
	uint64_t maxseg;
	caddr_t vaddr;
	uint_t pcnt;
	page_t *page;
	rootnex_sglinfo_t *sglinfo;
	ddi_dma_obj_t *dmar_object;
	rootnex_dma_t *dma;

	dma = (rootnex_dma_t *)hp->dmai_private;
	sglinfo = &(dma->dp_sglinfo);
	dmar_object = &(dmareq->dmar_object);
	maxseg = sglinfo->si_max_cookie_size;
	pparray = dmar_object->dmao_obj.virt_obj.v_priv;
	vaddr = dmar_object->dmao_obj.virt_obj.v_addr;
	buftype = dmar_object->dmao_type;
	size = dmar_object->dmao_size;

	/*
	 * Allocate cookie, dvcookie and dcookie
	 */
	if (cookie_alloc(dma, dmareq, a, prealloc_count) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	hp->dmai_cookie = dma->dp_cookies;

	pcnt = 0;

	/* retrieve paddr, psize, offset from dmareq */
	if (buftype == DMA_OTYP_PAGES) {
		page = dmar_object->dmao_obj.pp_obj.pp_pp;
		ASSERT(!PP_ISFREE(page) && PAGE_LOCKED(page));
		offset =  dmar_object->dmao_obj.pp_obj.pp_offset &
		    MMU_PAGEOFFSET;
		paddr = pfn_to_pa(page->p_pagenum) + offset;
		psize = MIN((MMU_PAGESIZE - offset), size);
		sglinfo->si_asp = NULL;
		page = page->p_next;
	} else {
		ASSERT((buftype == DMA_OTYP_VADDR) ||
		    (buftype == DMA_OTYP_BUFVADDR));
		sglinfo->si_asp = dmar_object->dmao_obj.virt_obj.v_as;
		if (sglinfo->si_asp == NULL) {
			sglinfo->si_asp = &kas;
		}
		offset = (uintptr_t)vaddr & MMU_PAGEOFFSET;
		if (pparray != NULL) {
			ASSERT(!PP_ISFREE(pparray[pcnt]));
			paddr = pfn_to_pa(pparray[pcnt]->p_pagenum) + offset;
			psize = MIN((MMU_PAGESIZE - offset), size);
			pcnt++;
		} else {
			paddr = pfn_to_pa(hat_getpfnum(sglinfo->si_asp->a_hat,
			    vaddr)) + offset;
			psize = MIN(size, (MMU_PAGESIZE - offset));
			vaddr += psize;
		}
	}

	/* save the iommu page offset */
	sglinfo->si_buf_offset = offset & IMMU_PAGEOFFSET;

	/*
	 * setup dvcookie and dcookie for [paddr, paddr+psize)
	 */
	cookie_update(domain, dma, paddr, psize, maxseg);

	size -= psize;
	while (size > 0) {
		/* get the size for this page (i.e. partial or full page) */
		psize = MIN(size, MMU_PAGESIZE);
		if (buftype == DMA_OTYP_PAGES) {
			/* get the paddr from the page_t */
			ASSERT(!PP_ISFREE(page) && PAGE_LOCKED(page));
			paddr = pfn_to_pa(page->p_pagenum);
			page = page->p_next;
		} else if (pparray != NULL) {
			/* index into the array of page_t's to get the paddr */
			ASSERT(!PP_ISFREE(pparray[pcnt]));
			paddr = pfn_to_pa(pparray[pcnt]->p_pagenum);
			pcnt++;
		} else {
			/* call into the VM to get the paddr */
			paddr = pfn_to_pa(hat_getpfnum
			    (sglinfo->si_asp->a_hat, vaddr));
			vaddr += psize;
		}
		/*
		 * set dvcookie and dcookie for [paddr, paddr+psize)
		 */
		cookie_update(domain, dma, paddr, psize, maxseg);
		size -= psize;
	}

	cookie_finalize(hp, immu, domain, rdip, immu_flags);

	/* take account in the offset into the first page */
	dma->dp_cookies[0].dmac_laddress += sglinfo->si_buf_offset;

	/* save away how many cookies we have */
	sglinfo->si_sgl_size = dma->dp_dvmax + 1;

	return (DDI_SUCCESS);
}

/* ############################# Functions exported ######################## */

/*
 * setup the DVMA subsystem
 * this code runs only for the first IOMMU unit
 */
void
immu_dvma_setup(list_t *listp)
{
	immu_t *immu;
	uint_t kval;
	size_t nchains;

	/* locks */
	mutex_init(&immu_domain_lock, NULL, MUTEX_DEFAULT, NULL);

	/* Create lists */
	list_create(&immu_unity_domain_list, sizeof (domain_t),
	    offsetof(domain_t, dom_maptype_node));
	list_create(&immu_xlate_domain_list, sizeof (domain_t),
	    offsetof(domain_t, dom_maptype_node));

	/* Setup BDF domain hash */
	nchains = 0xff;
	kval = mod_hash_iddata_gen(nchains);

	bdf_domain_hash = mod_hash_create_extended("BDF-DOMAIN_HASH",
	    nchains, mod_hash_null_keydtor, mod_hash_null_valdtor,
	    mod_hash_byid, (void *)(uintptr_t)kval, mod_hash_idkey_cmp,
	    KM_NOSLEEP);
	ASSERT(bdf_domain_hash);

	immu = list_head(listp);
	for (; immu; immu = list_next(listp, immu)) {
		create_unity_domain(immu);
		did_init(immu);
		context_init(immu);
		immu->immu_dvma_setup = B_TRUE;
	}
}

/*
 * Startup up one DVMA unit
 */
void
immu_dvma_startup(immu_t *immu)
{
	ASSERT(immu);
	ASSERT(immu->immu_dvma_running == B_FALSE);

	if (immu_gfxdvma_enable == B_FALSE &&
	    immu->immu_dvma_gfx_only == B_TRUE) {
		return;
	}

	/*
	 * DVMA will start once IOMMU is "running"
	 */
	ASSERT(immu->immu_dvma_running == B_FALSE);
	immu->immu_dvma_running = B_TRUE;
}

/*
 * immu_dvma_physmem_update()
 *       called when the installed memory on a
 *       system increases, to expand domain DVMA
 *       for domains with UNITY mapping
 */
void
immu_dvma_physmem_update(uint64_t addr, uint64_t size)
{
	uint64_t start;
	uint64_t npages;
	domain_t *domain;

	/*
	 * Just walk the system-wide list of domains with
	 * UNITY mapping. Both the list of *all* domains
	 * and *UNITY* domains is protected by the same
	 * single lock
	 */
	mutex_enter(&immu_domain_lock);
	domain = list_head(&immu_unity_domain_list);
	for (; domain; domain = list_next(&immu_unity_domain_list, domain)) {

		/* There is no vmem_arena for unity domains. Just map it */
		ddi_err(DER_LOG, NULL, "IMMU: unity-domain: Adding map "
		    "[0x%" PRIx64 " - 0x%" PRIx64 "]", addr, addr + size);

		start = IMMU_ROUNDOWN(addr);
		npages = (IMMU_ROUNDUP(size) / IMMU_PAGESIZE) + 1;

		dvma_map(domain->dom_immu, domain, start, start,
		    npages, NULL, IMMU_FLAGS_READ | IMMU_FLAGS_WRITE);

	}
	mutex_exit(&immu_domain_lock);
}

int
immu_dvma_map(ddi_dma_impl_t *hp, struct ddi_dma_req *dmareq, memrng_t *mrng,
    uint_t prealloc_count, dev_info_t *rdip, immu_flags_t immu_flags)
{
	ddi_dma_attr_t *attr;
	dev_info_t *ddip;
	domain_t *domain;
	immu_t *immu;
	int r = DDI_FAILURE;

	ASSERT(immu_enable == B_TRUE);
	ASSERT(immu_running == B_TRUE || !(immu_flags & IMMU_FLAGS_DMAHDL));
	ASSERT(hp || !(immu_flags & IMMU_FLAGS_DMAHDL));

	/*
	 * Intel IOMMU will only be turned on if IOMMU
	 * page size is a multiple of IOMMU page size
	 */

	/*LINTED*/
	ASSERT(MMU_PAGESIZE % IMMU_PAGESIZE == 0);

	/* Can only do DVMA if dip is attached */
	if (rdip == NULL) {
		ddi_err(DER_PANIC, rdip, "DVMA map: No device specified");
		/*NOTREACHED*/
	}

	immu_flags |= dma_to_immu_flags(dmareq);


	/*
	 * Setup DVMA domain for the device. This does
	 * work only the first time we do DVMA for a
	 * device.
	 */
	ddip = NULL;
	domain = device_domain(rdip, &ddip, immu_flags);
	if (domain == NULL) {
		ASSERT(ddip == NULL);
		ddi_err(DER_MODE, rdip, "Intel IOMMU setup failed for device");
		return (DDI_DMA_NORESOURCES);
	}

	/*
	 * If a domain is found, we must also have a domain dip
	 * which is the topmost ancestor dip of rdip that shares
	 * the same domain with rdip.
	 */
	if (domain->dom_did == 0 || ddip == NULL) {
		ddi_err(DER_MODE, rdip, "domain did 0(%d) or ddip NULL(%p)",
		    domain->dom_did, ddip);
		return (DDI_DMA_NORESOURCES);
	}

	immu = domain->dom_immu;
	ASSERT(immu);
	if (domain->dom_did == IMMU_UNITY_DID) {
		ASSERT(domain == immu->immu_unity_domain);

		/* mapping already done. Let rootnex create cookies */
		r = DDI_DMA_USE_PHYSICAL;
	} else  if (immu_flags & IMMU_FLAGS_DMAHDL) {

		/* if we have a DMA handle, the IOMMUs must be running */
		ASSERT(immu->immu_regs_running == B_TRUE);
		ASSERT(immu->immu_dvma_running == B_TRUE);

		attr = &hp->dmai_attr;
		if (attr == NULL) {
			ddi_err(DER_PANIC, rdip,
			    "DMA handle (%p): NULL attr", hp);
			/*NOTREACHED*/
		}
		if (cookie_create(hp, dmareq, attr, immu, domain, rdip,
		    prealloc_count, immu_flags) != DDI_SUCCESS) {
			ddi_err(DER_MODE, rdip, "dvcookie_alloc: failed");
			return (DDI_DMA_NORESOURCES);
		}

		/* flush write buffer */
		immu_regs_wbf_flush(immu);
		r = DDI_DMA_MAPPED;
	} else if (immu_flags & IMMU_FLAGS_MEMRNG) {
		dvma_map(immu, domain, mrng->mrng_start, mrng->mrng_start,
		    mrng->mrng_npages, rdip, immu_flags);
		r = DDI_DMA_MAPPED;
	} else {
		ddi_err(DER_PANIC, rdip, "invalid flags for immu_dvma_map()");
		/*NOTREACHED*/
	}

	/*
	 * Update the root and context entries
	 */
	if (immu_context_update(immu, domain, ddip, rdip, immu_flags)
	    != DDI_SUCCESS) {
		ddi_err(DER_MODE, rdip, "DVMA map: context update failed");
		return (DDI_DMA_NORESOURCES);
	}

	/* flush caches */
	rw_enter(&(immu->immu_ctx_rwlock), RW_WRITER);
	immu_regs_context_flush(immu, 0, 0, domain->dom_did, CONTEXT_DSI);
	rw_exit(&(immu->immu_ctx_rwlock));
	immu_regs_iotlb_flush(immu, domain->dom_did, 0, 0, TLB_IVA_WHOLE,
	    IOTLB_DSI);
	immu_regs_wbf_flush(immu);

	return (r);
}

int
immu_dvma_unmap(ddi_dma_impl_t *hp, dev_info_t *rdip)
{
	ddi_dma_attr_t *attr;
	rootnex_dma_t *dma;
	domain_t *domain;
	immu_t *immu;
	dev_info_t *ddip;
	immu_flags_t immu_flags;

	ASSERT(immu_enable == B_TRUE);
	ASSERT(immu_running == B_TRUE);
	ASSERT(hp);

	/*
	 * Intel IOMMU will only be turned on if IOMMU
	 * page size is same as MMU page size
	 */
	/*LINTED*/
	ASSERT(MMU_PAGESIZE == IMMU_PAGESIZE);

	/* rdip need not be attached */
	if (rdip == NULL) {
		ddi_err(DER_PANIC, rdip, "DVMA unmap: No device specified");
		return (DDI_DMA_NORESOURCES);
	}

	/*
	 * Get the device domain, this should always
	 * succeed since there had to be a domain to
	 * setup DVMA.
	 */
	dma = (rootnex_dma_t *)hp->dmai_private;
	attr = &hp->dmai_attr;
	if (attr == NULL) {
		ddi_err(DER_PANIC, rdip, "DMA handle (%p) has NULL attr", hp);
		/*NOTREACHED*/
	}
	immu_flags = dma->dp_sleep_flags;

	ddip = NULL;
	domain = device_domain(rdip, &ddip, immu_flags);
	if (domain == NULL || domain->dom_did == 0 || ddip == NULL) {
		ddi_err(DER_MODE, rdip, "Attempt to unmap DVMA for "
		    "a device without domain or with an uninitialized "
		    "domain");
		return (DDI_DMA_NORESOURCES);
	}

	/*
	 * immu must be set in the domain.
	 */
	immu = domain->dom_immu;
	ASSERT(immu);
	if (domain->dom_did == IMMU_UNITY_DID) {
		ASSERT(domain == immu->immu_unity_domain);
		/*
		 * domain is unity, nothing to do here, let the rootnex
		 * code free the cookies.
		 */
		return (DDI_DMA_USE_PHYSICAL);
	}

	dma = hp->dmai_private;
	if (dma == NULL) {
		ddi_err(DER_PANIC, rdip, "DVMA unmap: DMA handle (%p) has "
		    "no private dma structure", hp);
		/*NOTREACHED*/
	}

	/* free all cookies */
	cookie_free(dma, immu, domain, ddip, rdip);

	/* flush caches */
	rw_enter(&(immu->immu_ctx_rwlock), RW_WRITER);
	immu_regs_context_flush(immu, 0, 0, domain->dom_did, CONTEXT_DSI);
	rw_exit(&(immu->immu_ctx_rwlock));
	immu_regs_iotlb_flush(immu, domain->dom_did, 0, 0, TLB_IVA_WHOLE,
	    IOTLB_DSI);
	immu_regs_wbf_flush(immu);

	return (DDI_SUCCESS);
}

immu_devi_t *
immu_devi_get(dev_info_t *rdip)
{
	immu_devi_t *immu_devi;

	mutex_enter(&DEVI(rdip)->devi_lock);
	immu_devi = DEVI(rdip)->devi_iommu;
	mutex_exit(&DEVI(rdip)->devi_lock);

	return (immu_devi);
}
