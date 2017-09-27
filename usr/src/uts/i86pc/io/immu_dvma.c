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
 * Portions Copyright (c) 2010, Oracle and/or its affiliates.
 * All rights reserved.
 */
/*
 * Copyright (c) 2009, Intel Corporation.
 * All rights reserved.
 */
/*
 * Copyright 2012 Garrett D'Amore <garrett@damore.org>.  All rights reserved.
 * Copyright 2017 Joyent, Inc.
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
#include <sys/x86_archext.h>
#include <sys/archsystm.h>

#undef	TEST

/*
 * Macros based on PCI spec
 */
#define	IMMU_PCI_REV2CLASS(r)   ((r) >> 8)  /* classcode from revid */
#define	IMMU_PCI_CLASS2BASE(c)  ((c) >> 16) /* baseclass from classcode */
#define	IMMU_PCI_CLASS2SUB(c)   (((c) >> 8) & 0xff); /* classcode */

#define	IMMU_CONTIG_PADDR(d, p) \
	((d).dck_paddr && ((d).dck_paddr + (d).dck_npages * IMMU_PAGESIZE) \
	    == (p))

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
static boolean_t dvma_map(domain_t *domain, uint64_t sdvma,
    uint64_t nvpages, immu_dcookie_t *dcookies, int dcount, dev_info_t *rdip,
    immu_flags_t immu_flags);

/* Extern globals */
extern struct memlist  *phys_install;

/*
 * iommulib interface functions.
 */
static int immu_probe(iommulib_handle_t unitp, dev_info_t *dip);
static int immu_allochdl(iommulib_handle_t handle,
    dev_info_t *dip, dev_info_t *rdip, ddi_dma_attr_t *attr,
    int (*waitfp)(caddr_t), caddr_t arg, ddi_dma_handle_t *dma_handlep);
static int immu_freehdl(iommulib_handle_t handle,
    dev_info_t *dip, dev_info_t *rdip, ddi_dma_handle_t dma_handle);
static int immu_bindhdl(iommulib_handle_t handle, dev_info_t *dip,
    dev_info_t *rdip, ddi_dma_handle_t dma_handle, struct ddi_dma_req *dma_req,
    ddi_dma_cookie_t *cookiep, uint_t *ccountp);
static int immu_unbindhdl(iommulib_handle_t handle,
    dev_info_t *dip, dev_info_t *rdip, ddi_dma_handle_t dma_handle);
static int immu_sync(iommulib_handle_t handle, dev_info_t *dip,
    dev_info_t *rdip, ddi_dma_handle_t dma_handle, off_t off, size_t len,
    uint_t cachefl);
static int immu_win(iommulib_handle_t handle, dev_info_t *dip,
    dev_info_t *rdip, ddi_dma_handle_t dma_handle, uint_t win,
    off_t *offp, size_t *lenp, ddi_dma_cookie_t *cookiep, uint_t *ccountp);
static int immu_mapobject(iommulib_handle_t handle, dev_info_t *dip,
    dev_info_t *rdip, ddi_dma_handle_t dma_handle,
    struct ddi_dma_req *dmareq, ddi_dma_obj_t *dmao);
static int immu_unmapobject(iommulib_handle_t handle, dev_info_t *dip,
    dev_info_t *rdip, ddi_dma_handle_t dma_handle, ddi_dma_obj_t *dmao);

/* static Globals */

/*
 * Used to setup DMA objects (memory regions)
 * for DMA reads by IOMMU units
 */
static ddi_dma_attr_t immu_dma_attr = {
	DMA_ATTR_V0,
	0U,
	0xffffffffffffffffULL,
	0xffffffffU,
	MMU_PAGESIZE, /* MMU page aligned */
	0x1,
	0x1,
	0xffffffffU,
	0xffffffffffffffffULL,
	1,
	4,
	0
};

static ddi_device_acc_attr_t immu_acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

struct iommulib_ops immulib_ops = {
	IOMMU_OPS_VERSION,
	INTEL_IOMMU,
	"Intel IOMMU",
	NULL,
	immu_probe,
	immu_allochdl,
	immu_freehdl,
	immu_bindhdl,
	immu_unbindhdl,
	immu_sync,
	immu_win,
	immu_mapobject,
	immu_unmapobject,
};

/*
 * Fake physical address range used to set up initial prealloc mappings.
 * This memory is never actually accessed. It is mapped read-only,
 * and is overwritten as soon as the first DMA bind operation is
 * performed. Since 0 is a special case, just start at the 2nd
 * physical page.
 */

static immu_dcookie_t immu_precookie = { MMU_PAGESIZE, IMMU_NPREPTES };

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

int immu_use_alh;
int immu_use_tm;

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

	if (seg < 0 || bus < 0 || devfunc < 0) {
		return;
	}

	(void) mod_hash_insert(bdf_domain_hash, (void *)bdf, (void *)domain);
}

static int
match_lpc(dev_info_t *pdip, void *arg)
{
	immu_devi_t *immu_devi;
	dvma_arg_t *dvap = (dvma_arg_t *)arg;

	if (list_is_empty(dvap->dva_list)) {
		return (DDI_WALK_TERMINATE);
	}

	immu_devi = list_head(dvap->dva_list);
	for (; immu_devi; immu_devi = list_next(dvap->dva_list,
	    immu_devi)) {
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
	 * The GFX device may not be on the same iommu unit as "agpgart"
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
		ddi_err(DER_WARN, rdip, "iommu: No GFX device. "
		    "Cannot redirect agpgart");
		return (NULL);
	}

	ddi_err(DER_LOG, rdip, "iommu: GFX redirect to %s",
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

#ifdef BUGGY_DRIVERS

	flags |= (IMMU_FLAGS_READ | IMMU_FLAGS_WRITE);

#else
	/*
	 * Read and write flags need to be reversed.
	 * DMA_READ means read from device and write
	 * to memory. So DMA read means DVMA write.
	 */
	if (dmareq->dmar_flags & DDI_DMA_READ)
		flags |= IMMU_FLAGS_WRITE;

	if (dmareq->dmar_flags & DDI_DMA_WRITE)
		flags |= IMMU_FLAGS_READ;

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

/*ARGSUSED*/
int
pgtable_ctor(void *buf, void *arg, int kmflag)
{
	size_t actual_size = 0;
	pgtable_t *pgtable;
	int (*dmafp)(caddr_t);
	caddr_t vaddr;
	void *next;
	uint_t flags;
	immu_t *immu = arg;

	pgtable = (pgtable_t *)buf;

	dmafp = (kmflag & KM_NOSLEEP) ? DDI_DMA_DONTWAIT : DDI_DMA_SLEEP;

	next = kmem_zalloc(IMMU_PAGESIZE, kmflag);
	if (next == NULL) {
		return (-1);
	}

	if (ddi_dma_alloc_handle(root_devinfo, &immu_dma_attr,
	    dmafp, NULL, &pgtable->hwpg_dmahdl) != DDI_SUCCESS) {
		kmem_free(next, IMMU_PAGESIZE);
		return (-1);
	}

	flags = DDI_DMA_CONSISTENT;
	if (!immu->immu_dvma_coherent)
		flags |= IOMEM_DATA_UC_WR_COMBINE;

	if (ddi_dma_mem_alloc(pgtable->hwpg_dmahdl, IMMU_PAGESIZE,
	    &immu_acc_attr, flags,
	    dmafp, NULL, &vaddr, &actual_size,
	    &pgtable->hwpg_memhdl) != DDI_SUCCESS) {
		ddi_dma_free_handle(&pgtable->hwpg_dmahdl);
		kmem_free(next, IMMU_PAGESIZE);
		return (-1);
	}

	/*
	 * Memory allocation failure. Maybe a temporary condition
	 * so return error rather than panic, so we can try again
	 */
	if (actual_size < IMMU_PAGESIZE) {
		ddi_dma_mem_free(&pgtable->hwpg_memhdl);
		ddi_dma_free_handle(&pgtable->hwpg_dmahdl);
		kmem_free(next, IMMU_PAGESIZE);
		return (-1);
	}

	pgtable->hwpg_paddr = pfn_to_pa(hat_getpfnum(kas.a_hat, vaddr));
	pgtable->hwpg_vaddr = vaddr;
	pgtable->swpg_next_array = next;

	rw_init(&(pgtable->swpg_rwlock), NULL, RW_DEFAULT, NULL);

	return (0);
}

/*ARGSUSED*/
void
pgtable_dtor(void *buf, void *arg)
{
	pgtable_t *pgtable;

	pgtable = (pgtable_t *)buf;

	/* destroy will panic if lock is held. */
	rw_destroy(&(pgtable->swpg_rwlock));

	ddi_dma_mem_free(&pgtable->hwpg_memhdl);
	ddi_dma_free_handle(&pgtable->hwpg_dmahdl);
	kmem_free(pgtable->swpg_next_array, IMMU_PAGESIZE);
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
pgtable_alloc(immu_t *immu, immu_flags_t immu_flags)
{
	pgtable_t *pgtable;
	int kmflags;

	kmflags = (immu_flags & IMMU_FLAGS_NOSLEEP) ? KM_NOSLEEP : KM_SLEEP;

	pgtable = kmem_cache_alloc(immu->immu_pgtable_cache, kmflags);
	if (pgtable == NULL) {
		return (NULL);
	}
	return (pgtable);
}

static void
pgtable_zero(pgtable_t *pgtable)
{
	bzero(pgtable->hwpg_vaddr, IMMU_PAGESIZE);
	bzero(pgtable->swpg_next_array, IMMU_PAGESIZE);
}

static void
pgtable_free(immu_t *immu, pgtable_t *pgtable)
{
	kmem_cache_free(immu->immu_pgtable_cache, pgtable);
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

static boolean_t
device_use_premap(uint_t classcode)
{
	if (IMMU_PCI_CLASS2BASE(classcode) == PCI_CLASS_NET)
		return (B_TRUE);
	return (B_FALSE);
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
	immu_devi->imd_use_premap = device_use_premap(classcode);

	immu_devi->imd_domain = NULL;

	immu_devi->imd_dvma_flags = immu_global_dvma_flags;

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

	*ddipp = NULL;

	immu_devi = immu_devi_get(rdip);
	if (immu_devi == NULL) {
		return (NULL);
	}

	mutex_enter(&(DEVI(rdip)->devi_lock));
	domain = immu_devi->imd_domain;
	ddip = immu_devi->imd_ddip;
	mutex_exit(&(DEVI(rdip)->devi_lock));

	if (domain)
		*ddipp = ddip;

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

	did = (uintptr_t)vmem_alloc(immu->immu_did_arena, 1,
	    (immu_flags & IMMU_FLAGS_NOSLEEP) ? VM_NOSLEEP : VM_SLEEP);

	if (did == 0) {
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
	immu = immu_devi->imd_immu;
	if (immu == NULL)
		immu = immu_dvma_get_immu(pdip, dvp->dva_flags);

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
	immu_dcookie_t dcookies[1] = {0};
	int dcount = 0;

	/*
	 * UNITY arenas are a mirror of the physical memory
	 * installed on the system.
	 */

#ifdef BUGGY_DRIVERS
	/*
	 * Dont skip page0. Some broken HW/FW access it.
	 */
	dcookies[0].dck_paddr = 0;
	dcookies[0].dck_npages = 1;
	dcount = 1;
	(void) dvma_map(domain, 0, 1, dcookies, dcount, NULL,
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

	dcookies[0].dck_paddr = start;
	dcookies[0].dck_npages = npages;
	dcount = 1;
	(void) dvma_map(domain, start, npages, dcookies,
	    dcount, NULL, IMMU_FLAGS_READ | IMMU_FLAGS_WRITE);

	ddi_err(DER_LOG, domain->dom_dip, "iommu: mapping PHYS span [0x%" PRIx64
	    " - 0x%" PRIx64 "]", start, start + mp->ml_size);

	mp = mp->ml_next;
	while (mp) {
		ddi_err(DER_LOG, domain->dom_dip,
		    "iommu: mapping PHYS span [0x%" PRIx64 " - 0x%" PRIx64 "]",
		    mp->ml_address, mp->ml_address + mp->ml_size);

		start = mp->ml_address;
		npages = mp->ml_size/IMMU_PAGESIZE + 1;

		dcookies[0].dck_paddr = start;
		dcookies[0].dck_npages = npages;
		dcount = 1;
		(void) dvma_map(domain, start, npages,
		    dcookies, dcount, NULL, IMMU_FLAGS_READ | IMMU_FLAGS_WRITE);
		mp = mp->ml_next;
	}

	mp = bios_rsvd;
	while (mp) {
		ddi_err(DER_LOG, domain->dom_dip,
		    "iommu: mapping PHYS span [0x%" PRIx64 " - 0x%" PRIx64 "]",
		    mp->ml_address, mp->ml_address + mp->ml_size);

		start = mp->ml_address;
		npages = mp->ml_size/IMMU_PAGESIZE + 1;

		dcookies[0].dck_paddr = start;
		dcookies[0].dck_npages = npages;
		dcount = 1;
		(void) dvma_map(domain, start, npages,
		    dcookies, dcount, NULL, IMMU_FLAGS_READ | IMMU_FLAGS_WRITE);

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

	/* Restrict mgaddr (max guest addr) to MGAW */
	mgaw = IMMU_CAP_MGAW(immu->immu_regs_cap);

	/*
	 * To ensure we avoid ioapic and PCI MMIO ranges we just
	 * use the physical memory address range of the system as the
	 * range
	 */
	maxaddr = ((uint64_t)1 << mgaw);

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
	    "iommu: %s: Creating dvma vmem arena [0x%" PRIx64
	    " - 0x%" PRIx64 "]", arena_name, start, start + size);

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
		    "iommu: %s: Adding dvma vmem span [0x%" PRIx64
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

	immu_devi = immu_devi_get(dip);

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
	immu_t *immu;
	domain_t *domain;
	dvma_arg_t dvarg = {0};
	int level;

	*ddipp = NULL;

	/*
	 * Check if the domain is already set. This is usually true
	 * if this is not the first DVMA transaction.
	 */
	ddip = NULL;
	domain = immu_devi_domain(rdip, &ddip);
	if (domain) {
		*ddipp = ddip;
		return (domain);
	}

	immu = immu_dvma_get_immu(rdip, immu_flags);
	if (immu == NULL) {
		/*
		 * possible that there is no IOMMU unit for this device
		 * - BIOS bugs are one example.
		 */
		ddi_err(DER_WARN, rdip, "No iommu unit found for device");
		return (NULL);
	}

	immu_flags |= immu_devi_get(rdip)->imd_dvma_flags;

	dvarg.dva_rdip = rdip;
	dvarg.dva_ddip = NULL;
	dvarg.dva_domain = NULL;
	dvarg.dva_flags = immu_flags;
	level = 0;
	if (immu_walk_ancestor(rdip, NULL, get_branch_domain,
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
		ddi_err(DER_MODE, rdip, "Cannot find domain dip for device.");
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

	/*FALLTHROUGH*/
found:
	/*
	 * We know *domain *is* the right domain, so panic if
	 * another domain is set for either the request-dip or
	 * effective dip.
	 */
	set_domain(ddip, ddip, domain);
	set_domain(rdip, ddip, domain);

	*ddipp = ddip;
	return (domain);
}

static void
create_unity_domain(immu_t *immu)
{
	domain_t *domain;

	/* domain created during boot and always use sleep flag */
	domain = kmem_zalloc(sizeof (domain_t), KM_SLEEP);

	rw_init(&(domain->dom_pgtable_rwlock), NULL, RW_DEFAULT, NULL);

	domain->dom_did = IMMU_UNITY_DID;
	domain->dom_maptype = IMMU_MAPTYPE_UNITY;

	domain->dom_immu = immu;
	immu->immu_unity_domain = domain;

	/*
	 * Setup the domain's initial page table
	 * should never fail.
	 */
	domain->dom_pgtable_root = pgtable_alloc(immu, IMMU_FLAGS_SLEEP);
	pgtable_zero(domain->dom_pgtable_root);

	/*
	 * Only map all physical memory in to the unity domain
	 * if passthrough is not supported. If it is supported,
	 * passthrough is set in the context entry instead.
	 */
	if (!IMMU_ECAP_GET_PT(immu->immu_regs_excap))
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
	immu_dcookie_t dcookies[1] = {0};
	int dcount = 0;

	immu_devi = immu_devi_get(rdip);

	/*
	 * First allocate a domainid.
	 * This routine will never fail, since if we run out
	 * of domains the unity domain will be allocated.
	 */
	did = did_alloc(immu, rdip, ddip, immu_flags);
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

	(void) snprintf(mod_hash_name, sizeof (mod_hash_name),
	    "immu%s-domain%d-pava-hash", immu->immu_name, did);

	domain->dom_did = did;
	domain->dom_immu = immu;
	domain->dom_maptype = IMMU_MAPTYPE_XLATE;
	domain->dom_dip = ddip;

	/*
	 * Create xlate DVMA arena for this domain.
	 */
	create_xlate_arena(immu, domain, rdip, immu_flags);

	/*
	 * Setup the domain's initial page table
	 */
	domain->dom_pgtable_root = pgtable_alloc(immu, immu_flags);
	if (domain->dom_pgtable_root == NULL) {
		ddi_err(DER_PANIC, rdip, "Failed to alloc root "
		    "pgtable for domain (%d). IOMMU unit: %s",
		    domain->dom_did, immu->immu_name);
		/*NOTREACHED*/
	}
	pgtable_zero(domain->dom_pgtable_root);

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
	dcookies[0].dck_paddr = 0;
	dcookies[0].dck_npages = 1;
	dcount = 1;
	(void) dvma_map(domain, 0, 1, dcookies, dcount, NULL,
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

	ddi_err(DER_VERB, immu->immu_dip, "creating domainid arena %s",
	    immu->immu_did_arena_name);

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
	hw_rce_t *hw_rent;
	hw_rce_t *hw_cent;
	hw_rce_t *ctxp;
	int sid;
	krw_t rwtype;
	boolean_t fill_root;
	boolean_t fill_ctx;

	pgtable_root = domain->dom_pgtable_root;

	ctxp = (hw_rce_t *)(root_table->swpg_next_array);
	context = *(pgtable_t **)(ctxp + bus);
	hw_rent = (hw_rce_t *)(root_table->hwpg_vaddr) + bus;

	fill_root = B_FALSE;
	fill_ctx = B_FALSE;

	/* Check the most common case first with reader lock */
	rw_enter(&(immu->immu_ctx_rwlock), RW_READER);
	rwtype = RW_READER;
again:
	if (ROOT_GET_P(hw_rent)) {
		hw_cent = (hw_rce_t *)(context->hwpg_vaddr) + devfunc;
		if (CONT_GET_AVAIL(hw_cent) == IMMU_CONT_INITED) {
			rw_exit(&(immu->immu_ctx_rwlock));
			return;
		} else {
			fill_ctx = B_TRUE;
		}
	} else {
		fill_root = B_TRUE;
		fill_ctx = B_TRUE;
	}

	if (rwtype == RW_READER &&
	    rw_tryupgrade(&(immu->immu_ctx_rwlock)) == 0) {
		rw_exit(&(immu->immu_ctx_rwlock));
		rw_enter(&(immu->immu_ctx_rwlock), RW_WRITER);
		rwtype = RW_WRITER;
		goto again;
	}
	rwtype = RW_WRITER;

	if (fill_root == B_TRUE) {
		ROOT_SET_CONT(hw_rent, context->hwpg_paddr);
		ROOT_SET_P(hw_rent);
		immu_regs_cpu_flush(immu, (caddr_t)hw_rent, sizeof (hw_rce_t));
	}

	if (fill_ctx == B_TRUE) {
		hw_cent = (hw_rce_t *)(context->hwpg_vaddr) + devfunc;
		/* need to disable context entry before reprogramming it */
		bzero(hw_cent, sizeof (hw_rce_t));

		/* flush caches */
		immu_regs_cpu_flush(immu, (caddr_t)hw_cent, sizeof (hw_rce_t));

		sid = ((bus << 8) | devfunc);
		immu_flush_context_fsi(immu, 0, sid, domain->dom_did,
		    &immu->immu_ctx_inv_wait);

		CONT_SET_AVAIL(hw_cent, IMMU_CONT_INITED);
		CONT_SET_DID(hw_cent, domain->dom_did);
		CONT_SET_AW(hw_cent, immu->immu_dvma_agaw);
		CONT_SET_ASR(hw_cent, pgtable_root->hwpg_paddr);
		if (domain->dom_did == IMMU_UNITY_DID &&
		    IMMU_ECAP_GET_PT(immu->immu_regs_excap))
			CONT_SET_TTYPE(hw_cent, TTYPE_PASSTHRU);
		else
			/*LINTED*/
			CONT_SET_TTYPE(hw_cent, TTYPE_XLATE_ONLY);
		CONT_SET_P(hw_cent);
		if (IMMU_ECAP_GET_CH(immu->immu_regs_excap)) {
			CONT_SET_EH(hw_cent);
			if (immu_use_alh)
				CONT_SET_ALH(hw_cent);
		}
		immu_regs_cpu_flush(immu, (caddr_t)hw_cent, sizeof (hw_rce_t));
	}
	rw_exit(&(immu->immu_ctx_rwlock));
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
	root_table = pgtable_alloc(immu, IMMU_FLAGS_SLEEP);
	pgtable_zero(root_table);

	/*
	 * Setup context tables for all possible root table entries.
	 * Start out with unity domains for all entries.
	 */
	ctxp = (hw_rce_t *)(root_table->swpg_next_array);
	hw_rent = (hw_rce_t *)(root_table->hwpg_vaddr);
	for (bus = 0; bus < IMMU_ROOT_NUM; bus++, ctxp++, hw_rent++) {
		context = pgtable_alloc(immu, IMMU_FLAGS_SLEEP);
		pgtable_zero(context);
		ROOT_SET_P(hw_rent);
		ROOT_SET_CONT(hw_rent, context->hwpg_paddr);
		hw_cent = (hw_rce_t *)(context->hwpg_vaddr);
		for (devfunc = 0; devfunc < IMMU_CONT_NUM;
		    devfunc++, hw_cent++) {
			pgtable_root =
			    immu->immu_unity_domain->dom_pgtable_root;
			CONT_SET_DID(hw_cent,
			    immu->immu_unity_domain->dom_did);
			CONT_SET_AW(hw_cent, immu->immu_dvma_agaw);
			CONT_SET_ASR(hw_cent, pgtable_root->hwpg_paddr);
			if (IMMU_ECAP_GET_PT(immu->immu_regs_excap))
				CONT_SET_TTYPE(hw_cent, TTYPE_PASSTHRU);
			else
				/*LINTED*/
				CONT_SET_TTYPE(hw_cent, TTYPE_XLATE_ONLY);
			CONT_SET_AVAIL(hw_cent, IMMU_CONT_UNINITED);
			CONT_SET_P(hw_cent);
		}
		immu_regs_cpu_flush(immu, context->hwpg_vaddr, IMMU_PAGESIZE);
		*((pgtable_t **)ctxp) = context;
	}

	return (root_table);
}

/*
 * Called during rootnex attach, so no locks needed
 */
static void
context_init(immu_t *immu)
{
	rw_init(&(immu->immu_ctx_rwlock), NULL, RW_DEFAULT, NULL);

	immu_init_inv_wait(&immu->immu_ctx_inv_wait, "ctxglobal", B_TRUE);

	immu_regs_wbf_flush(immu);

	immu->immu_ctx_root = context_create(immu);

	immu_regs_set_root_table(immu);

	rw_enter(&(immu->immu_ctx_rwlock), RW_WRITER);
	immu_flush_context_gbl(immu, &immu->immu_ctx_inv_wait);
	immu_flush_iotlb_gbl(immu, &immu->immu_ctx_inv_wait);
	rw_exit(&(immu->immu_ctx_rwlock));
}


/*
 * Find top pcib
 */
static int
find_top_pcib(dev_info_t *dip, void *arg)
{
	immu_devi_t *immu_devi;
	dev_info_t **pcibdipp = (dev_info_t **)arg;

	immu_devi = immu_devi_get(dip);

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

	d_bus = d_immu_devi->imd_bus;
	d_devfunc = d_immu_devi->imd_devfunc;
	d_pcib_type = d_immu_devi->imd_pcib_type;
	r_bus = r_immu_devi->imd_bus;
	r_devfunc = r_immu_devi->imd_devfunc;

	if (rdip == ddip) {
		/* rdip is a PCIE device. set context for it only */
		context_set(immu, domain, immu->immu_ctx_root, r_bus,
		    r_devfunc);
#ifdef BUGGY_DRIVERS
	} else if (r_immu_devi == d_immu_devi) {
#ifdef TEST
		ddi_err(DER_WARN, rdip, "Driver bug: Devices 0x%lx and "
		    "0x%lx are identical", rdip, ddip);
#endif
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
				r_immu_devi = immu_devi_get(pcibdip);
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
		/*
		 * ddip is a PCIE device which has a non-PCI device under it
		 * i.e. it is a PCI-nonPCI bridge. Example: pciicde-ata
		 */
		context_set(immu, domain, immu->immu_ctx_root, d_bus,
		    d_devfunc);
	} else {
		ddi_err(DER_PANIC, rdip, "unknown device type. Cannot "
		    "set iommu context.");
		/*NOTREACHED*/
	}

	/* XXX do we need a membar_producer() here */
	return (DDI_SUCCESS);
}

/* ##################### END CONTEXT CODE ################################## */
/* ##################### MAPPING CODE ################################## */


#ifdef DEBUG
static boolean_t
PDTE_check(immu_t *immu, hw_pdte_t pdte, pgtable_t *next, paddr_t paddr,
    dev_info_t *rdip, immu_flags_t immu_flags)
{
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
	if (next == NULL && immu->immu_TM_reserved == B_FALSE) {
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
	if (next == NULL && immu->immu_SNP_reserved == B_FALSE) {
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
#endif

/*ARGSUSED*/
static void
PTE_clear_all(immu_t *immu, domain_t *domain, xlate_t *xlate,
    uint64_t *dvma_ptr, uint64_t *npages_ptr, dev_info_t *rdip)
{
	uint64_t npages;
	uint64_t dvma;
	pgtable_t *pgtable;
	hw_pdte_t *hwp;
	hw_pdte_t *shwp;
	int idx;

	pgtable = xlate->xlt_pgtable;
	idx = xlate->xlt_idx;

	dvma = *dvma_ptr;
	npages = *npages_ptr;

	/*
	 * since a caller gets a unique dvma for a physical address,
	 * no other concurrent thread will be writing to the same
	 * PTE even if it has the same paddr. So no locks needed.
	 */
	shwp = (hw_pdte_t *)(pgtable->hwpg_vaddr) + idx;

	hwp = shwp;
	for (; npages > 0 && idx <= IMMU_PGTABLE_MAXIDX; idx++, hwp++) {
		PDTE_CLEAR_P(*hwp);
		dvma += IMMU_PAGESIZE;
		npages--;
	}

	*dvma_ptr = dvma;
	*npages_ptr = npages;

	xlate->xlt_idx = idx;
}

static void
xlate_setup(uint64_t dvma, xlate_t *xlate, int nlevels)
{
	int level;
	uint64_t offbits;

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
static boolean_t
PDE_lookup(domain_t *domain, xlate_t *xlate, int nlevels)
{
	pgtable_t *pgtable;
	pgtable_t *next;
	uint_t idx;

	/* start with highest level pgtable i.e. root */
	xlate += nlevels;

	if (xlate->xlt_pgtable == NULL) {
		xlate->xlt_pgtable = domain->dom_pgtable_root;
	}

	for (; xlate->xlt_level > 1; xlate--) {
		idx = xlate->xlt_idx;
		pgtable = xlate->xlt_pgtable;

		if ((xlate - 1)->xlt_pgtable) {
			continue;
		}

		/* Lock the pgtable in read mode */
		rw_enter(&(pgtable->swpg_rwlock), RW_READER);

		/*
		 * since we are unmapping, the pgtable should
		 * already point to a leafier pgtable.
		 */
		next = *(pgtable->swpg_next_array + idx);
		(xlate - 1)->xlt_pgtable = next;
		rw_exit(&(pgtable->swpg_rwlock));
		if (next == NULL)
			return (B_FALSE);
	}

	return (B_TRUE);
}

static void
immu_fault_walk(void *arg, void *base, size_t len)
{
	uint64_t dvma, start;

	dvma = *(uint64_t *)arg;
	start = (uint64_t)(uintptr_t)base;

	if (dvma >= start && dvma < (start + len)) {
		ddi_err(DER_WARN, NULL,
		    "faulting DVMA address is in vmem arena "
		    "(%" PRIx64 "-%" PRIx64 ")",
		    start, start + len);
		*(uint64_t *)arg = ~0ULL;
	}
}

void
immu_print_fault_info(uint_t sid, uint64_t dvma)
{
	int nlevels;
	xlate_t xlate[IMMU_PGTABLE_MAX_LEVELS + 1] = {0};
	xlate_t *xlatep;
	hw_pdte_t pte;
	domain_t *domain;
	immu_t *immu;
	uint64_t dvma_arg;

	if (mod_hash_find(bdf_domain_hash,
	    (void *)(uintptr_t)sid, (void *)&domain) != 0) {
		ddi_err(DER_WARN, NULL,
		    "no domain for faulting SID %08x", sid);
		return;
	}

	immu = domain->dom_immu;

	dvma_arg = dvma;
	vmem_walk(domain->dom_dvma_arena, VMEM_ALLOC, immu_fault_walk,
	    (void *)&dvma_arg);
	if (dvma_arg != ~0ULL)
		ddi_err(DER_WARN, domain->dom_dip,
		    "faulting DVMA address is not in vmem arena");

	nlevels = immu->immu_dvma_nlevels;
	xlate_setup(dvma, xlate, nlevels);

	if (!PDE_lookup(domain, xlate, nlevels)) {
		ddi_err(DER_WARN, domain->dom_dip,
		    "pte not found in domid %d for faulting addr %" PRIx64,
		    domain->dom_did, dvma);
		return;
	}

	xlatep = &xlate[1];
	pte = *((hw_pdte_t *)
	    (xlatep->xlt_pgtable->hwpg_vaddr) + xlatep->xlt_idx);

	ddi_err(DER_WARN, domain->dom_dip,
	    "domid %d pte: %" PRIx64 "(paddr %" PRIx64 ")", domain->dom_did,
	    (unsigned long long)pte, (unsigned long long)PDTE_PADDR(pte));
}

/*ARGSUSED*/
static void
PTE_set_one(immu_t *immu, hw_pdte_t *hwp, paddr_t paddr,
    dev_info_t *rdip, immu_flags_t immu_flags)
{
	hw_pdte_t pte;

#ifndef DEBUG
	pte = immu->immu_ptemask;
	PDTE_SET_PADDR(pte, paddr);
#else
	pte = *hwp;

	if (PDTE_P(pte)) {
		if (PDTE_PADDR(pte) != paddr) {
			ddi_err(DER_MODE, rdip, "PTE paddr %lx != paddr %lx",
			    PDTE_PADDR(pte), paddr);
		}
#ifdef BUGGY_DRIVERS
		return;
#else
		goto out;
#endif
	}

	/* clear TM field if not reserved */
	if (immu->immu_TM_reserved == B_FALSE) {
		PDTE_CLEAR_TM(pte);
	}

	/* Clear 3rd field for system software  - not used */
	PDTE_CLEAR_SW3(pte);

	/* Set paddr */
	ASSERT(paddr % IMMU_PAGESIZE == 0);
	PDTE_CLEAR_PADDR(pte);
	PDTE_SET_PADDR(pte, paddr);

	/*  clear SNP field if not reserved. */
	if (immu->immu_SNP_reserved == B_FALSE) {
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

	pte |= immu->immu_ptemask;

out:
#endif /* DEBUG */
#ifdef BUGGY_DRIVERS
	PDTE_SET_READ(pte);
	PDTE_SET_WRITE(pte);
#else
	if (immu_flags & IMMU_FLAGS_READ)
		PDTE_SET_READ(pte);
	if (immu_flags & IMMU_FLAGS_WRITE)
		PDTE_SET_WRITE(pte);
#endif /* BUGGY_DRIVERS */

	*hwp = pte;
}

/*ARGSUSED*/
static void
PTE_set_all(immu_t *immu, domain_t *domain, xlate_t *xlate,
    uint64_t *dvma_ptr, uint64_t *nvpages_ptr, immu_dcookie_t *dcookies,
    int dcount, dev_info_t *rdip, immu_flags_t immu_flags)
{
	paddr_t paddr;
	uint64_t nvpages;
	uint64_t nppages;
	uint64_t dvma;
	pgtable_t *pgtable;
	hw_pdte_t *hwp;
	hw_pdte_t *shwp;
	int idx, nset;
	int j;

	pgtable = xlate->xlt_pgtable;
	idx = xlate->xlt_idx;

	dvma = *dvma_ptr;
	nvpages = *nvpages_ptr;

	/*
	 * since a caller gets a unique dvma for a physical address,
	 * no other concurrent thread will be writing to the same
	 * PTE even if it has the same paddr. So no locks needed.
	 */
	shwp = (hw_pdte_t *)(pgtable->hwpg_vaddr) + idx;

	hwp = shwp;
	for (j = dcount - 1; j >= 0; j--) {
		if (nvpages <= dcookies[j].dck_npages)
			break;
		nvpages -= dcookies[j].dck_npages;
	}

	VERIFY(j >= 0);
	nppages = nvpages;
	paddr = dcookies[j].dck_paddr +
	    (dcookies[j].dck_npages - nppages) * IMMU_PAGESIZE;

	nvpages = *nvpages_ptr;
	nset = 0;
	for (; nvpages > 0 && idx <= IMMU_PGTABLE_MAXIDX; idx++, hwp++) {
		PTE_set_one(immu, hwp, paddr, rdip, immu_flags);
		nset++;

		ASSERT(PDTE_check(immu, *hwp, NULL, paddr, rdip, immu_flags)
		    == B_TRUE);
		nppages--;
		nvpages--;
		paddr += IMMU_PAGESIZE;
		dvma += IMMU_PAGESIZE;

		if (nppages == 0) {
			j++;
		}

		if (j == dcount)
			break;

		if (nppages == 0) {
			nppages = dcookies[j].dck_npages;
			paddr = dcookies[j].dck_paddr;
		}
	}

	if (nvpages) {
		*dvma_ptr = dvma;
		*nvpages_ptr = nvpages;
	} else {
		*dvma_ptr = 0;
		*nvpages_ptr = 0;
	}

	xlate->xlt_idx = idx;
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
#ifdef BUGGY_DRIVERS
		return;
#else
		goto out;
#endif
	}

	/* Dont touch SW4, it is the present bit */

	/* don't touch TM field it is reserved for PDEs */

	/* 3rd field available for system software is not used */
	PDTE_CLEAR_SW3(pde);

	/* Set next level pgtable-paddr for PDE */
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
#ifdef  BUGGY_DRIVERS
	PDTE_SET_READ(pde);
	PDTE_SET_WRITE(pde);
#else
	if (immu_flags & IMMU_FLAGS_READ)
		PDTE_SET_READ(pde);
	if (immu_flags & IMMU_FLAGS_WRITE)
		PDTE_SET_WRITE(pde);
#endif

	PDTE_SET_P(pde);

	*hwp = pde;
}

/*
 * Used to set PDEs
 */
static boolean_t
PDE_set_all(immu_t *immu, domain_t *domain, xlate_t *xlate, int nlevels,
    dev_info_t *rdip, immu_flags_t immu_flags)
{
	pgtable_t *pgtable;
	pgtable_t *new;
	pgtable_t *next;
	hw_pdte_t *hwp;
	int level;
	uint_t idx;
	krw_t rwtype;
	boolean_t set = B_FALSE;

	/* start with highest level pgtable i.e. root */
	xlate += nlevels;

	new = NULL;
	xlate->xlt_pgtable = domain->dom_pgtable_root;
	for (level = nlevels; level > 1; level--, xlate--) {
		idx = xlate->xlt_idx;
		pgtable = xlate->xlt_pgtable;

		/* Lock the pgtable in READ mode first */
		rw_enter(&(pgtable->swpg_rwlock), RW_READER);
		rwtype = RW_READER;
again:
		hwp = (hw_pdte_t *)(pgtable->hwpg_vaddr) + idx;
		next = (pgtable->swpg_next_array)[idx];

		/*
		 * check if leafier level already has a pgtable
		 * if yes, verify
		 */
		if (next == NULL) {
			if (new == NULL) {

				IMMU_DPROBE2(immu__pdp__alloc, dev_info_t *,
				    rdip, int, level);

				new = pgtable_alloc(immu, immu_flags);
				if (new == NULL) {
					ddi_err(DER_PANIC, rdip,
					    "pgtable alloc err");
				}
				pgtable_zero(new);
			}

			/* Change to a write lock */
			if (rwtype == RW_READER &&
			    rw_tryupgrade(&(pgtable->swpg_rwlock)) == 0) {
				rw_exit(&(pgtable->swpg_rwlock));
				rw_enter(&(pgtable->swpg_rwlock), RW_WRITER);
				rwtype = RW_WRITER;
				goto again;
			}
			rwtype = RW_WRITER;
			next = new;
			(pgtable->swpg_next_array)[idx] = next;
			new = NULL;
			PDE_set_one(immu, hwp, next, rdip, immu_flags);
			set = B_TRUE;
			rw_downgrade(&(pgtable->swpg_rwlock));
			rwtype = RW_READER;
		}
#ifndef  BUGGY_DRIVERS
		else {
			hw_pdte_t pde = *hwp;

			/*
			 * If buggy driver we already set permission
			 * READ+WRITE so nothing to do for that case
			 * XXX Check that read writer perms change before
			 * actually setting perms. Also need to hold lock
			 */
			if (immu_flags & IMMU_FLAGS_READ)
				PDTE_SET_READ(pde);
			if (immu_flags & IMMU_FLAGS_WRITE)
				PDTE_SET_WRITE(pde);

			*hwp = pde;
		}
#endif

		ASSERT(PDTE_check(immu, *hwp, next, 0, rdip, immu_flags)
		    == B_TRUE);

		(xlate - 1)->xlt_pgtable = next;
		rw_exit(&(pgtable->swpg_rwlock));
	}

	if (new) {
		pgtable_free(immu, new);
	}

	return (set);
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
static boolean_t
dvma_map(domain_t *domain, uint64_t sdvma, uint64_t snvpages,
    immu_dcookie_t *dcookies, int dcount, dev_info_t *rdip,
    immu_flags_t immu_flags)
{
	uint64_t dvma;
	uint64_t n;
	immu_t *immu = domain->dom_immu;
	int nlevels = immu->immu_dvma_nlevels;
	xlate_t xlate[IMMU_PGTABLE_MAX_LEVELS + 1] = {0};
	boolean_t pde_set = B_FALSE;

	n = snvpages;
	dvma = sdvma;

	while (n > 0) {
		xlate_setup(dvma, xlate, nlevels);

		/* Lookup or allocate PGDIRs and PGTABLEs if necessary */
		if (PDE_set_all(immu, domain, xlate, nlevels, rdip, immu_flags)
		    == B_TRUE) {
			pde_set = B_TRUE;
		}

		/* set all matching ptes that fit into this leaf pgtable */
		PTE_set_all(immu, domain, &xlate[1], &dvma, &n, dcookies,
		    dcount, rdip, immu_flags);
	}

	return (pde_set);
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
dvma_unmap(domain_t *domain, uint64_t sdvma, uint64_t snpages,
    dev_info_t *rdip)
{
	immu_t *immu = domain->dom_immu;
	int nlevels = immu->immu_dvma_nlevels;
	xlate_t xlate[IMMU_PGTABLE_MAX_LEVELS + 1] = {0};
	uint64_t n;
	uint64_t dvma;

	dvma = sdvma;
	n = snpages;

	while (n > 0) {
		/* setup the xlate array */
		xlate_setup(dvma, xlate, nlevels);

		/* just lookup existing pgtables. Should never fail */
		if (!PDE_lookup(domain, xlate, nlevels))
			ddi_err(DER_PANIC, rdip,
			    "PTE not found for addr %" PRIx64,
			    (unsigned long long)dvma);

		/* clear all matching ptes that fit into this leaf pgtable */
		PTE_clear_all(immu, domain, &xlate[1], &dvma, &n, rdip);
	}

	/* No need to flush IOTLB after unmap */
}

static uint64_t
dvma_alloc(domain_t *domain, ddi_dma_attr_t *dma_attr, uint_t npages, int kmf)
{
	uint64_t dvma;
	size_t xsize, align;
	uint64_t minaddr, maxaddr;

	/* parameters */
	xsize = npages * IMMU_PAGESIZE;
	align = MAX((size_t)(dma_attr->dma_attr_align), IMMU_PAGESIZE);
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
	    xsize, align, 0, 0, (void *)(uintptr_t)minaddr,
	    (void *)(uintptr_t)maxaddr, kmf);

	return (dvma);
}

static void
dvma_prealloc(dev_info_t *rdip, immu_hdl_priv_t *ihp, ddi_dma_attr_t *dma_attr)
{
	int nlevels;
	xlate_t xlate[IMMU_PGTABLE_MAX_LEVELS + 1] = {0}, *xlp;
	uint64_t dvma, n;
	size_t xsize, align;
	uint64_t minaddr, maxaddr, dmamax;
	int on, npte, pindex;
	hw_pdte_t *shwp;
	immu_t *immu;
	domain_t *domain;

	/* parameters */
	domain = IMMU_DEVI(rdip)->imd_domain;
	immu = domain->dom_immu;
	nlevels = immu->immu_dvma_nlevels;
	xsize = IMMU_NPREPTES * IMMU_PAGESIZE;
	align = MAX((size_t)(dma_attr->dma_attr_align), IMMU_PAGESIZE);
	minaddr = dma_attr->dma_attr_addr_lo;
	if (dma_attr->dma_attr_flags & _DDI_DMA_BOUNCE_ON_SEG)
		dmamax = dma_attr->dma_attr_seg;
	else
		dmamax = dma_attr->dma_attr_addr_hi;
	maxaddr = dmamax + 1;

	if (maxaddr < dmamax)
		maxaddr = dmamax;

	dvma = (uint64_t)(uintptr_t)vmem_xalloc(domain->dom_dvma_arena,
	    xsize, align, 0, dma_attr->dma_attr_seg + 1,
	    (void *)(uintptr_t)minaddr, (void *)(uintptr_t)maxaddr, VM_NOSLEEP);

	ihp->ihp_predvma = dvma;
	ihp->ihp_npremapped = 0;
	if (dvma == 0)
		return;

	n = IMMU_NPREPTES;
	pindex = 0;

	/*
	 * Set up a mapping at address 0, just so that all PDPs get allocated
	 * now. Although this initial mapping should never be used,
	 * explicitly set it to read-only, just to be safe.
	 */
	while (n > 0) {
		xlate_setup(dvma, xlate, nlevels);

		(void) PDE_set_all(immu, domain, xlate, nlevels, rdip,
		    IMMU_FLAGS_READ | IMMU_FLAGS_WRITE);

		xlp = &xlate[1];
		shwp = (hw_pdte_t *)(xlp->xlt_pgtable->hwpg_vaddr)
		    + xlp->xlt_idx;
		on = n;

		PTE_set_all(immu, domain, xlp, &dvma, &n, &immu_precookie,
		    1, rdip, IMMU_FLAGS_READ);

		npte = on - n;

		while (npte > 0) {
			ihp->ihp_preptes[pindex++] = shwp;
#ifdef BUGGY_DRIVERS
			PDTE_CLEAR_WRITE(*shwp);
#endif
			shwp++;
			npte--;
		}
	}
}

static void
dvma_prefree(dev_info_t *rdip, immu_hdl_priv_t *ihp)
{
	domain_t *domain;

	domain = IMMU_DEVI(rdip)->imd_domain;

	if (ihp->ihp_predvma != 0) {
		dvma_unmap(domain, ihp->ihp_predvma, IMMU_NPREPTES, rdip);
		vmem_free(domain->dom_dvma_arena,
		    (void *)(uintptr_t)ihp->ihp_predvma,
		    IMMU_NPREPTES * IMMU_PAGESIZE);
	}
}

static void
dvma_free(domain_t *domain, uint64_t dvma, uint64_t npages)
{
	uint64_t size = npages * IMMU_PAGESIZE;

	if (domain->dom_maptype != IMMU_MAPTYPE_XLATE)
		return;

	vmem_free(domain->dom_dvma_arena, (void *)(uintptr_t)dvma, size);
}

static int
immu_map_dvmaseg(dev_info_t *rdip, ddi_dma_handle_t handle,
    immu_hdl_priv_t *ihp, struct ddi_dma_req *dmareq,
    ddi_dma_obj_t *dma_out)
{
	domain_t *domain;
	immu_t *immu;
	immu_flags_t immu_flags;
	ddi_dma_atyp_t buftype;
	ddi_dma_obj_t *dmar_object;
	ddi_dma_attr_t *attrp;
	uint64_t offset, paddr, dvma, sdvma, rwmask;
	size_t npages, npgalloc;
	uint_t psize, size, pcnt, dmax;
	page_t **pparray;
	caddr_t vaddr;
	page_t *page;
	struct as *vas;
	immu_dcookie_t *dcookies;
	int pde_set;

	domain = IMMU_DEVI(rdip)->imd_domain;
	immu = domain->dom_immu;
	immu_flags = dma_to_immu_flags(dmareq);

	attrp = &((ddi_dma_impl_t *)handle)->dmai_attr;

	dmar_object = &dmareq->dmar_object;
	pparray = dmar_object->dmao_obj.virt_obj.v_priv;
	vaddr = dmar_object->dmao_obj.virt_obj.v_addr;
	buftype = dmar_object->dmao_type;
	size = dmar_object->dmao_size;

	IMMU_DPROBE3(immu__map__dvma, dev_info_t *, rdip, ddi_dma_atyp_t,
	    buftype, uint_t, size);

	dcookies = &ihp->ihp_dcookies[0];

	pcnt = dmax = 0;

	/* retrieve paddr, psize, offset from dmareq */
	if (buftype == DMA_OTYP_PAGES) {
		page = dmar_object->dmao_obj.pp_obj.pp_pp;
		offset =  dmar_object->dmao_obj.pp_obj.pp_offset &
		    MMU_PAGEOFFSET;
		paddr = pfn_to_pa(page->p_pagenum) + offset;
		psize = MIN((MMU_PAGESIZE - offset), size);
		page = page->p_next;
		vas = dmar_object->dmao_obj.virt_obj.v_as;
	} else {
		if (vas == NULL) {
			vas = &kas;
		}
		offset = (uintptr_t)vaddr & MMU_PAGEOFFSET;
		if (pparray != NULL) {
			paddr = pfn_to_pa(pparray[pcnt]->p_pagenum) + offset;
			psize = MIN((MMU_PAGESIZE - offset), size);
			pcnt++;
		} else {
			paddr = pfn_to_pa(hat_getpfnum(vas->a_hat,
			    vaddr)) + offset;
			psize = MIN(size, (MMU_PAGESIZE - offset));
			vaddr += psize;
		}
	}

	npgalloc = IMMU_BTOPR(size + offset);

	if (npgalloc <= IMMU_NPREPTES && ihp->ihp_predvma != 0) {
#ifdef BUGGY_DRIVERS
		rwmask = PDTE_MASK_R | PDTE_MASK_W | immu->immu_ptemask;
#else
		rwmask = immu->immu_ptemask;
		if (immu_flags & IMMU_FLAGS_READ)
			rwmask |= PDTE_MASK_R;
		if (immu_flags & IMMU_FLAGS_WRITE)
			rwmask |= PDTE_MASK_W;
#endif
#ifdef DEBUG
		rwmask |= PDTE_MASK_P;
#endif
		sdvma = ihp->ihp_predvma;
		ihp->ihp_npremapped = npgalloc;
		*ihp->ihp_preptes[0] =
		    PDTE_PADDR(paddr & ~MMU_PAGEOFFSET) | rwmask;
	} else {
		ihp->ihp_npremapped = 0;
		sdvma = dvma_alloc(domain, attrp, npgalloc,
		    dmareq->dmar_fp == DDI_DMA_SLEEP ? VM_SLEEP : VM_NOSLEEP);
		if (sdvma == 0)
			return (DDI_DMA_NORESOURCES);

		dcookies[0].dck_paddr = (paddr & ~MMU_PAGEOFFSET);
		dcookies[0].dck_npages = 1;
	}

	IMMU_DPROBE3(immu__dvma__alloc, dev_info_t *, rdip, uint64_t, npgalloc,
	    uint64_t, sdvma);

	dvma = sdvma;
	pde_set = 0;
	npages = 1;
	size -= psize;
	while (size > 0) {
		/* get the size for this page (i.e. partial or full page) */
		psize = MIN(size, MMU_PAGESIZE);
		if (buftype == DMA_OTYP_PAGES) {
			/* get the paddr from the page_t */
			paddr = pfn_to_pa(page->p_pagenum);
			page = page->p_next;
		} else if (pparray != NULL) {
			/* index into the array of page_t's to get the paddr */
			paddr = pfn_to_pa(pparray[pcnt]->p_pagenum);
			pcnt++;
		} else {
			/* call into the VM to get the paddr */
			paddr = pfn_to_pa(hat_getpfnum(vas->a_hat, vaddr));
			vaddr += psize;
		}

		if (ihp->ihp_npremapped > 0) {
			*ihp->ihp_preptes[npages] =
			    PDTE_PADDR(paddr) | rwmask;
		} else if (IMMU_CONTIG_PADDR(dcookies[dmax], paddr)) {
			dcookies[dmax].dck_npages++;
		} else {
			/* No, we need a new dcookie */
			if (dmax == (IMMU_NDCK - 1)) {
				/*
				 * Ran out of dcookies. Map them now.
				 */
				if (dvma_map(domain, dvma,
				    npages, dcookies, dmax + 1, rdip,
				    immu_flags))
					pde_set++;

				IMMU_DPROBE4(immu__dvmamap__early,
				    dev_info_t *, rdip, uint64_t, dvma,
				    uint_t, npages, uint_t, dmax+1);

				dvma += (npages << IMMU_PAGESHIFT);
				npages = 0;
				dmax = 0;
			} else {
				dmax++;
			}
			dcookies[dmax].dck_paddr = paddr;
			dcookies[dmax].dck_npages = 1;
		}
		size -= psize;
		if (npages != 0)
			npages++;
	}

	/*
	 * Finish up, mapping all, or all of the remaining,
	 * physical memory ranges.
	 */
	if (ihp->ihp_npremapped == 0 && npages > 0) {
		IMMU_DPROBE4(immu__dvmamap__late, dev_info_t *, rdip, \
		    uint64_t, dvma, uint_t, npages, uint_t, dmax+1);

		if (dvma_map(domain, dvma, npages, dcookies,
		    dmax + 1, rdip, immu_flags))
			pde_set++;
	}

	/* Invalidate the IOTLB */
	immu_flush_iotlb_psi(immu, domain->dom_did, sdvma, npgalloc,
	    pde_set > 0 ? TLB_IVA_WHOLE : TLB_IVA_LEAF,
	    &ihp->ihp_inv_wait);

	ihp->ihp_ndvseg = 1;
	ihp->ihp_dvseg[0].dvs_start = sdvma;
	ihp->ihp_dvseg[0].dvs_len = dmar_object->dmao_size;

	dma_out->dmao_size = dmar_object->dmao_size;
	dma_out->dmao_obj.dvma_obj.dv_off = offset & IMMU_PAGEOFFSET;
	dma_out->dmao_obj.dvma_obj.dv_nseg = 1;
	dma_out->dmao_obj.dvma_obj.dv_seg = &ihp->ihp_dvseg[0];
	dma_out->dmao_type = DMA_OTYP_DVADDR;

	return (DDI_DMA_MAPPED);
}

static int
immu_unmap_dvmaseg(dev_info_t *rdip, ddi_dma_obj_t *dmao)
{
	uint64_t dvma, npages;
	domain_t *domain;
	struct dvmaseg *dvs;

	domain = IMMU_DEVI(rdip)->imd_domain;
	dvs = dmao->dmao_obj.dvma_obj.dv_seg;

	dvma = dvs[0].dvs_start;
	npages = IMMU_BTOPR(dvs[0].dvs_len + dmao->dmao_obj.dvma_obj.dv_off);

#ifdef DEBUG
	/* Unmap only in DEBUG mode */
	dvma_unmap(domain, dvma, npages, rdip);
#endif
	dvma_free(domain, dvma, npages);

	IMMU_DPROBE3(immu__dvma__free, dev_info_t *, rdip, uint_t, npages,
	    uint64_t, dvma);

#ifdef DEBUG
	/*
	 * In the DEBUG case, the unmap was actually done,
	 * but an IOTLB flush was not done. So, an explicit
	 * write back flush is needed.
	 */
	immu_regs_wbf_flush(domain->dom_immu);
#endif

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
	if (immu_gfxdvma_enable == B_FALSE &&
	    immu->immu_dvma_gfx_only == B_TRUE) {
		return;
	}

	/*
	 * DVMA will start once IOMMU is "running"
	 */
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
	int dcount;
	immu_dcookie_t dcookies[1] = {0};
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
		/*
		 * Nothing to do if the IOMMU supports passthrough.
		 */
		if (IMMU_ECAP_GET_PT(domain->dom_immu->immu_regs_excap))
			continue;

		/* There is no vmem_arena for unity domains. Just map it */
		ddi_err(DER_LOG, domain->dom_dip,
		    "iommu: unity-domain: Adding map "
		    "[0x%" PRIx64 " - 0x%" PRIx64 "]", addr, addr + size);

		start = IMMU_ROUNDOWN(addr);
		npages = (IMMU_ROUNDUP(size) / IMMU_PAGESIZE) + 1;

		dcookies[0].dck_paddr = start;
		dcookies[0].dck_npages = npages;
		dcount = 1;
		(void) dvma_map(domain, start, npages,
		    dcookies, dcount, NULL, IMMU_FLAGS_READ | IMMU_FLAGS_WRITE);

	}
	mutex_exit(&immu_domain_lock);
}

int
immu_dvma_device_setup(dev_info_t *rdip, immu_flags_t immu_flags)
{
	dev_info_t *ddip, *odip;
	immu_t *immu;
	domain_t *domain;

	odip = rdip;

	immu = immu_dvma_get_immu(rdip, immu_flags);
	if (immu == NULL) {
		/*
		 * possible that there is no IOMMU unit for this device
		 * - BIOS bugs are one example.
		 */
		ddi_err(DER_WARN, rdip, "No iommu unit found for device");
		return (DDI_DMA_NORESOURCES);
	}

	/*
	 * redirect isa devices attached under lpc to lpc dip
	 */
	if (strcmp(ddi_node_name(ddi_get_parent(rdip)), "isa") == 0) {
		rdip = get_lpc_devinfo(immu, rdip, immu_flags);
		if (rdip == NULL) {
			ddi_err(DER_PANIC, rdip, "iommu redirect failed");
			/*NOTREACHED*/
		}
	}

	/* Reset immu, as redirection can change IMMU */
	immu = NULL;

	/*
	 * for gart, redirect to the real graphic devinfo
	 */
	if (strcmp(ddi_node_name(rdip), "agpgart") == 0) {
		rdip = get_gfx_devinfo(rdip);
		if (rdip == NULL) {
			ddi_err(DER_PANIC, rdip, "iommu redirect failed");
			/*NOTREACHED*/
		}
	}

	/*
	 * Setup DVMA domain for the device. This does
	 * work only the first time we do DVMA for a
	 * device.
	 */
	ddip = NULL;
	domain = device_domain(rdip, &ddip, immu_flags);
	if (domain == NULL) {
		ddi_err(DER_MODE, rdip, "Intel IOMMU setup failed for device");
		return (DDI_DMA_NORESOURCES);
	}

	immu = domain->dom_immu;

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

	if (odip != rdip)
		set_domain(odip, ddip, domain);

	/*
	 * Update the root and context entries
	 */
	if (immu_context_update(immu, domain, ddip, rdip, immu_flags)
	    != DDI_SUCCESS) {
		ddi_err(DER_MODE, rdip, "DVMA map: context update failed");
		return (DDI_DMA_NORESOURCES);
	}

	return (DDI_SUCCESS);
}

int
immu_map_memrange(dev_info_t *rdip, memrng_t *mrng)
{
	immu_dcookie_t dcookies[1] = {0};
	boolean_t pde_set;
	immu_t *immu;
	domain_t *domain;
	immu_inv_wait_t iw;

	dcookies[0].dck_paddr = mrng->mrng_start;
	dcookies[0].dck_npages = mrng->mrng_npages;

	domain = IMMU_DEVI(rdip)->imd_domain;
	immu = domain->dom_immu;

	pde_set = dvma_map(domain, mrng->mrng_start,
	    mrng->mrng_npages, dcookies, 1, rdip,
	    IMMU_FLAGS_READ | IMMU_FLAGS_WRITE);

	immu_init_inv_wait(&iw, "memrange", B_TRUE);

	immu_flush_iotlb_psi(immu, domain->dom_did, mrng->mrng_start,
	    mrng->mrng_npages, pde_set == B_TRUE ?
	    TLB_IVA_WHOLE : TLB_IVA_LEAF, &iw);

	return (DDI_SUCCESS);
}

immu_devi_t *
immu_devi_get(dev_info_t *rdip)
{
	immu_devi_t *immu_devi;
	volatile uintptr_t *vptr = (uintptr_t *)&(DEVI(rdip)->devi_iommu);

	/* Just want atomic reads. No need for lock */
	immu_devi = (immu_devi_t *)(uintptr_t)atomic_or_64_nv((uint64_t *)vptr,
	    0);
	return (immu_devi);
}

/*ARGSUSED*/
int
immu_hdl_priv_ctor(void *buf, void *arg, int kmf)
{
	immu_hdl_priv_t *ihp;

	ihp = buf;
	immu_init_inv_wait(&ihp->ihp_inv_wait, "dmahandle", B_FALSE);

	return (0);
}

/*
 * iommulib interface functions
 */
static int
immu_probe(iommulib_handle_t handle, dev_info_t *dip)
{
	immu_devi_t *immu_devi;
	int ret;

	if (!immu_enable)
		return (DDI_FAILURE);

	/*
	 * Make sure the device has all the IOMMU structures
	 * initialized. If this device goes through an IOMMU
	 * unit (e.g. this probe function returns success),
	 * this will be called at most N times, with N being
	 * the number of IOMMUs in the system.
	 *
	 * After that, when iommulib_nex_open succeeds,
	 * we can always assume that this device has all
	 * the structures initialized. IOMMU_USED(dip) will
	 * be true. There is no need to find the controlling
	 * IOMMU/domain again.
	 */
	ret = immu_dvma_device_setup(dip, IMMU_FLAGS_NOSLEEP);
	if (ret != DDI_SUCCESS)
		return (ret);

	immu_devi = IMMU_DEVI(dip);

	/*
	 * For unity domains, there is no need to call in to
	 * the IOMMU code.
	 */
	if (immu_devi->imd_domain->dom_did == IMMU_UNITY_DID)
		return (DDI_FAILURE);

	if (immu_devi->imd_immu->immu_dip == iommulib_iommu_getdip(handle))
		return (DDI_SUCCESS);

	return (DDI_FAILURE);
}

/*ARGSUSED*/
static int
immu_allochdl(iommulib_handle_t handle,
    dev_info_t *dip, dev_info_t *rdip, ddi_dma_attr_t *attr,
    int (*waitfp)(caddr_t), caddr_t arg, ddi_dma_handle_t *dma_handlep)
{
	int ret;
	immu_hdl_priv_t *ihp;
	immu_t *immu;

	ret = iommulib_iommu_dma_allochdl(dip, rdip, attr, waitfp,
	    arg, dma_handlep);
	if (ret == DDI_SUCCESS) {
		immu = IMMU_DEVI(rdip)->imd_immu;

		ihp = kmem_cache_alloc(immu->immu_hdl_cache,
		    waitfp == DDI_DMA_SLEEP ? KM_SLEEP : KM_NOSLEEP);
		if (ihp == NULL) {
			(void) iommulib_iommu_dma_freehdl(dip, rdip,
			    *dma_handlep);
			return (DDI_DMA_NORESOURCES);
		}

		if (IMMU_DEVI(rdip)->imd_use_premap)
			dvma_prealloc(rdip, ihp, attr);
		else {
			ihp->ihp_npremapped = 0;
			ihp->ihp_predvma = 0;
		}
		ret = iommulib_iommu_dmahdl_setprivate(dip, rdip, *dma_handlep,
		    ihp);
	}
	return (ret);
}

/*ARGSUSED*/
static int
immu_freehdl(iommulib_handle_t handle,
    dev_info_t *dip, dev_info_t *rdip, ddi_dma_handle_t dma_handle)
{
	immu_hdl_priv_t *ihp;

	ihp = iommulib_iommu_dmahdl_getprivate(dip, rdip, dma_handle);
	if (ihp != NULL) {
		if (IMMU_DEVI(rdip)->imd_use_premap)
			dvma_prefree(rdip, ihp);
		kmem_cache_free(IMMU_DEVI(rdip)->imd_immu->immu_hdl_cache, ihp);
	}

	return (iommulib_iommu_dma_freehdl(dip, rdip, dma_handle));
}


/*ARGSUSED*/
static int
immu_bindhdl(iommulib_handle_t handle, dev_info_t *dip,
    dev_info_t *rdip, ddi_dma_handle_t dma_handle,
    struct ddi_dma_req *dma_req, ddi_dma_cookie_t *cookiep,
    uint_t *ccountp)
{
	int ret;
	immu_hdl_priv_t *ihp;

	ret = iommulib_iommu_dma_bindhdl(dip, rdip, dma_handle,
	    dma_req, cookiep, ccountp);

	if (ret == DDI_DMA_MAPPED) {
		ihp = iommulib_iommu_dmahdl_getprivate(dip, rdip, dma_handle);
		immu_flush_wait(IMMU_DEVI(rdip)->imd_immu, &ihp->ihp_inv_wait);
	}

	return (ret);
}

/*ARGSUSED*/
static int
immu_unbindhdl(iommulib_handle_t handle,
    dev_info_t *dip, dev_info_t *rdip, ddi_dma_handle_t dma_handle)
{
	return (iommulib_iommu_dma_unbindhdl(dip, rdip, dma_handle));
}

/*ARGSUSED*/
static int
immu_sync(iommulib_handle_t handle, dev_info_t *dip,
    dev_info_t *rdip, ddi_dma_handle_t dma_handle, off_t off,
    size_t len, uint_t cachefl)
{
	return (iommulib_iommu_dma_sync(dip, rdip, dma_handle, off, len,
	    cachefl));
}

/*ARGSUSED*/
static int
immu_win(iommulib_handle_t handle, dev_info_t *dip,
    dev_info_t *rdip, ddi_dma_handle_t dma_handle, uint_t win,
    off_t *offp, size_t *lenp, ddi_dma_cookie_t *cookiep,
    uint_t *ccountp)
{
	return (iommulib_iommu_dma_win(dip, rdip, dma_handle, win, offp,
	    lenp, cookiep, ccountp));
}

/*ARGSUSED*/
static int
immu_mapobject(iommulib_handle_t handle, dev_info_t *dip,
    dev_info_t *rdip, ddi_dma_handle_t dma_handle,
    struct ddi_dma_req *dmareq, ddi_dma_obj_t *dmao)
{
	immu_hdl_priv_t *ihp;

	ihp = iommulib_iommu_dmahdl_getprivate(dip, rdip, dma_handle);

	return (immu_map_dvmaseg(rdip, dma_handle, ihp, dmareq, dmao));
}

/*ARGSUSED*/
static int
immu_unmapobject(iommulib_handle_t handle, dev_info_t *dip,
    dev_info_t *rdip, ddi_dma_handle_t dma_handle, ddi_dma_obj_t *dmao)
{
	immu_hdl_priv_t *ihp;

	ihp = iommulib_iommu_dmahdl_getprivate(dip, rdip, dma_handle);
	if (ihp->ihp_npremapped > 0)
		return (DDI_SUCCESS);
	return (immu_unmap_dvmaseg(rdip, dmao));
}
