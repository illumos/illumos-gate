/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* BEGIN CSTYLED */
/**
 * \file drm_pci.h
 * \brief PCI consistent, DMA-accessible memory functions.
 *
 * \author Eric Anholt <anholt@FreeBSD.org>
 */

/*-
 * Copyright 2003 Eric Anholt.
 * All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice (including the next
 * paragraph) shall be included in all copies or substantial portions of the
 * Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
 * AUTHOR BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/**********************************************************************/
/** \name PCI memory */
/*@{*/
/* END CSTYLED */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "drmP.h"
#include <vm/seg_kmem.h>

#define	PCI_DEVICE(x)	(((x)>>11) & 0x1f)
#define	PCI_FUNCTION(x)	(((x) & 0x700) >> 8)
#define	PCI_BUS(x)	(((x) & 0xff0000) >> 16)

typedef struct drm_pci_resource {
	uint_t	regnum;
	unsigned long offset;
	unsigned long size;
} drm_pci_resource_t;

int
pci_get_info(drm_device_t *softstate, int *bus, int *slot, int *func)
{
	int *regs_list;
	uint_t nregs = 0;

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, softstate->dip,
	    DDI_PROP_DONTPASS, "reg", (int **)&regs_list, &nregs)
	    != DDI_PROP_SUCCESS) {
		DRM_ERROR("pci_get_info: get pci function bus device failed");
		goto error;
	}
	*bus  = (int)PCI_BUS(regs_list[0]);
	*slot = (int)PCI_DEVICE(regs_list[0]);
	*func = (int)PCI_FUNCTION(regs_list[0]);

	if (nregs > 0) {
		ddi_prop_free(regs_list);
	}
	return (DDI_SUCCESS);
error:
	if (nregs > 0) {
		ddi_prop_free(regs_list);
	}
	return (DDI_FAILURE);
}

int
pci_get_irq(drm_device_t *statep)
{
	int irq;

	extern int drm_supp_get_irq(void *);

	irq = ddi_prop_get_int(DDI_DEV_T_ANY,
	    statep->dip, DDI_PROP_DONTPASS, "interrupts", -1);

	if (irq > 0) {
		irq = drm_supp_get_irq(statep->drm_handle);
	}

	return (irq);
}

int
pci_get_vendor(drm_device_t *statep)
{
	int vendorid;

	vendorid = ddi_prop_get_int(DDI_DEV_T_ANY,
	    statep->dip, DDI_PROP_DONTPASS, "vendor-id", 0);

	return (vendorid);
}

int
pci_get_device(drm_device_t *statep)
{
	int deviceid;

	deviceid = ddi_prop_get_int(DDI_DEV_T_ANY,
	    statep->dip, DDI_PROP_DONTPASS, "device-id", 0);

	return (deviceid);
}

void
drm_core_ioremap(struct drm_local_map *map, drm_device_t *dev)
{
	if ((map->type == _DRM_AGP) && dev->agp) {
		/*
		 * During AGP mapping initialization, we map AGP aperture
		 * into kernel space. So, when we access the memory which
		 * managed by agp gart in kernel space, we have to go
		 * through two-level address translation: kernel virtual
		 * address --> aperture address --> physical address. For
		 * improving this, here in opensourced code, agp_remap()
		 * gets invoking to dispose the mapping between agp aperture
		 * and kernel space, and directly map the actual physical
		 * memory which is allocated to agp gart to kernel space.
		 * After that, access to physical memory managed by agp gart
		 * hardware in kernel space doesn't go through agp hardware,
		 * it will be: kernel virtual ---> physical address.
		 * Obviously, it is more efficient. But in solaris operating
		 * system, the ioctl AGPIOC_ALLOCATE of apggart driver does
		 * not return physical address. We are unable to create the
		 * direct mapping between kernel space and agp memory. So,
		 * we remove the calling to agp_remap().
		 */
		DRM_DEBUG("drm_core_ioremap: skipping agp_remap\n");
	} else {
		(void) drm_ioremap(dev, map);

	}
}

/*ARGSUSED*/
void
drm_core_ioremapfree(struct drm_local_map *map, drm_device_t *dev)
{
	if (map->type != _DRM_AGP) {
		if (map->handle && map->size)
			drm_ioremapfree(map);
	} else {
		/*
		 * Refer to the comments in drm_core_ioremap() where we removed
		 * the calling to agp_remap(), correspondingly, we remove the
		 * calling to agp_remap_free(dev, map);
		 */
		DRM_DEBUG("drm_core_ioremap: skipping agp_remap_free\n");
	}
}

struct drm_local_map *
drm_core_findmap(drm_device_t *dev, unsigned long handle)
{
	drm_local_map_t *map;

	DRM_SPINLOCK_ASSERT(&dev->dev_lock);

/*
 * For the time being, we compare the low 32 bit only,
 * We will hash handle to 32-bit to solve this issue later.
 */
	TAILQ_FOREACH(map, &dev->maplist, link) {
		if ((((unsigned long)map->handle) & 0x00000000ffffffff)
		    == (handle & 0x00000000ffffffff))
			return (map);
	}

	return (NULL);
}

/*
 * pci_alloc_consistent()
 */
static ddi_dma_attr_t	hw_dma_attr = {
		DMA_ATTR_V0,		/* version */
		0,			/* addr_lo */
		0xffffffff,	/* addr_hi */
		0xffffffff,	/* count_max */
		4096, 			/* alignment */
		0xfff,			/* burstsize */
		1,			/* minxfer */
		0xffffffff,		/* maxxfer */
		0xffffffff,		/* seg */
		1,			/* sgllen */
		4,			/* granular */
		0			/* flags */
};

static ddi_device_acc_attr_t hw_acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};


void *
drm_pci_alloc(drm_device_t *dev, size_t size,
    size_t align,  dma_addr_t maxaddr, int segments)
{
	drm_dma_handle_t	*dmah;
	uint_t	count;
	int ret = DDI_FAILURE;

	/* allocat continous physical memory for hw status page */
	if (align == 0)
		hw_dma_attr.dma_attr_align =  1;
	else
		hw_dma_attr.dma_attr_align = align;

	hw_dma_attr.dma_attr_addr_hi = maxaddr;
	hw_dma_attr.dma_attr_sgllen = segments;

	dmah = kmem_zalloc(sizeof (drm_dma_handle_t), KM_SLEEP);
	if (ret = ddi_dma_alloc_handle(dev->dip, &hw_dma_attr,
	    DDI_DMA_SLEEP, NULL, &dmah->dma_hdl)) {
		DRM_ERROR("drm_pci_alloc:ddi_dma_alloc_handle failed\n");
		goto err3;
	}

	if (ret = ddi_dma_mem_alloc(dmah->dma_hdl, size, &hw_acc_attr,
	    DDI_DMA_CONSISTENT | IOMEM_DATA_UNCACHED,
	    DDI_DMA_SLEEP, NULL, (caddr_t *)&dmah->vaddr,
	    &dmah->real_sz, &dmah->acc_hdl)) {
		DRM_ERROR("drm_pci_alloc: ddi_dma_mem_alloc failed\n");
		goto err2;
	}

	ret = ddi_dma_addr_bind_handle(dmah->dma_hdl, NULL,
	    (caddr_t)dmah->vaddr, dmah->real_sz,
	    DDI_DMA_RDWR|DDI_DMA_CONSISTENT,
	    DDI_DMA_SLEEP, NULL, &dmah->cookie,  &count);
	if (ret != DDI_DMA_MAPPED) {
		DRM_ERROR("drm_pci_alloc: alloc phys memory failed");
		goto err1;
	}

	if (count > segments) {
		(void) ddi_dma_unbind_handle(dmah->dma_hdl);
		goto err1;
	}

	dmah->cookie_num = count;
	if (count == 1)
		dmah->paddr = dmah->cookie.dmac_address;

	return (dmah);

err1:
	ddi_dma_mem_free(&dmah->acc_hdl);
err2:
	ddi_dma_free_handle(&dmah->dma_hdl);
err3:
	kmem_free(dmah, sizeof (*dmah));
	return (NULL);
}

/*
 * pci_free_consistent()
 */
/*ARGSUSED*/
void
drm_pci_free(drm_device_t *dev, drm_dma_handle_t *dmah)
{
	ASSERT(dmah != NULL);
	(void) ddi_dma_unbind_handle(dmah->dma_hdl);
	ddi_dma_mem_free(&dmah->acc_hdl);
	ddi_dma_free_handle(&dmah->dma_hdl);
	kmem_free(dmah, sizeof (drm_dma_handle_t));
}

int
do_get_pci_res(drm_device_t *dev, drm_pci_resource_t *resp)
{
	int length;
	pci_regspec_t	*regs;

	if (ddi_getlongprop(
	    DDI_DEV_T_ANY, dev->dip, DDI_PROP_DONTPASS,
	    "assigned-addresses", (caddr_t)&regs, &length) !=
	    DDI_PROP_SUCCESS) {
		DRM_ERROR("do_get_pci_res: ddi_getlongprop failed!\n");
		return (EFAULT);
	}
	resp->offset =
	    (unsigned long)regs[resp->regnum].pci_phys_low;
	resp->size =
	    (unsigned long)regs[resp->regnum].pci_size_low;
	kmem_free(regs, (size_t)length);

	return (0);
}

/*ARGSUSED*/
unsigned long
drm_get_resource_start(drm_device_t *softstate, unsigned int regnum)
{
	drm_pci_resource_t res;
	int ret;

	res.regnum = regnum;

	ret = do_get_pci_res(softstate, &res);

	if (ret != 0) {
		DRM_ERROR("drm_get_resource_start: ioctl failed");
		return (0);
	}

	return (res.offset);

}

/*ARGSUSED*/
unsigned long
drm_get_resource_len(drm_device_t *softstate, unsigned int regnum)
{
	drm_pci_resource_t res;
	int ret;

	res.regnum = regnum;

	ret = do_get_pci_res(softstate, &res);

	if (ret != 0) {
		DRM_ERROR("drm_get_resource_len: ioctl failed");
		return (0);
	}

	return (res.size);
}
