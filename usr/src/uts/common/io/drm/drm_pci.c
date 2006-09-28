/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
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

#define	PCI_DEVICE(x)	(((x)>>11) & 0x1f)
#define	PCI_FUNCTION(x)	(((x) & 0x700) >> 8)
#define	PCI_BUS(x)	(((x) & 0xff0000) >> 16)

/* Device info struct */
typedef struct drm_device_info {
	uint16_t	drm_venid;	/* drm devcie's vendor id */
	uint16_t	drm_devid;	/* drm device's device id */
	uint8_t		drm_irq;	/* drm device's interrupt line */
} drm_device_info_t;

typedef struct drm_pci_resource {
	uint_t	regnum;
	unsigned long offset;
	unsigned long size;
} drm_pci_resource_t;

/* Get IRQ line */
static int device_get_info(drm_device_info_t *data, ddi_acc_handle_t pch)
{
	uint8_t irq;

	if (!pch)
		return (DRM_ERR(EINVAL));

	data->drm_venid =
	    pci_config_get16(pch, PCI_CONF_VENID);
	data->drm_devid =
	    pci_config_get16(pch, PCI_CONF_DEVID);
	irq = pci_config_get8(pch, PCI_CONF_IPIN);
	DRM_DEBUG("!drm: device_get_info: \
	    venid is %x, devid is %x,irq is %x \n",
	    data->drm_venid, data->drm_devid, irq);

	if (irq)
		irq = pci_config_get8(pch, PCI_CONF_ILINE);
	data->drm_irq = irq;

	return (0);
}

int
pci_get_info(drm_softstate_t *softstate, int *bus, int *slot, int *func)
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
pci_get_irq(drm_softstate_t *softstate)
{
	drm_device_info_t drm_info;
	int ret;

	bzero(&drm_info, sizeof (drm_device_info_t));
	ret = device_get_info(&drm_info, softstate->pci_cfg_hdl);
	if (ret)
		return (-1);

	return (drm_info.drm_irq);
}

int
pci_get_vendor(drm_softstate_t *softstate)
{
	drm_device_info_t drm_info;
	int ret;

	bzero(&drm_info, sizeof (drm_device_info_t));

	ret = device_get_info(&drm_info, softstate->pci_cfg_hdl);
	if (ret)
		return (DDI_FAILURE);

	return (drm_info.drm_venid);
}

int
pci_get_device(drm_softstate_t *softstate)
{
	drm_device_info_t drm_info;
	int ret;

	bzero(&drm_info, sizeof (drm_device_info_t));

	ret = device_get_info(&drm_info, softstate->pci_cfg_hdl);
	if (ret)
		return (DDI_FAILURE);

	return (drm_info.drm_devid);

}

void
agp_remap(struct drm_softstate *softstate, struct drm_local_map *map)
{
	DRM_DEBUG(
	    "agp_remap: map->handle:%lx map->offset %llx, map->size %lx\n",
	    (unsigned long)map->handle, map->offset.off,
	    (unsigned long)map->size);

	map->handle = (void *)((softstate->agp_umem_kvaddr) +
	    (unsigned long)(map->offset.off - softstate->agp->base));
	map->dev_addr = (caddr_t)map->handle;
	DRM_DEBUG("agp_remap: map->dev_addr is %lx",
	    (unsigned long) map->dev_addr);

}

/*ARGSUSED*/
void
agp_remap_free(struct drm_softstate *softstate, struct drm_local_map *map)
{}

void
drm_core_ioremap(struct drm_local_map *map, struct drm_softstate *softstate)
{
	if (map->type != _DRM_AGP_UMEM) {
		(void) drm_ioremap(softstate, map);
	} else {
		(void) agp_remap(softstate, map);
	}
}

void
drm_core_ioremapfree(struct drm_local_map *map, struct drm_softstate *softstate)
{
	if (map->type != _DRM_AGP_UMEM) {
		if (map->handle && map->size)
			drm_ioremapfree(map);
	} else {
		(void) agp_remap_free(softstate, map);
	}
}

struct drm_local_map *
drm_core_findmap(struct drm_softstate *dev, unsigned long offset)
{
	drm_local_map_t *map;

	DRM_SPINLOCK_ASSERT(&dev->dev_lock);
	TAILQ_FOREACH(map, &dev->maplist, link) {
		if ((unsigned long)map->offset.off == offset)
			return (map);
	}
	return (NULL);
}

/*
 * pci_alloc_consistent()
 */

static ddi_dma_attr_t hw_dma_attr = {
	DMA_ATTR_V0,
	(unsigned long long)0,
	(unsigned long long)0xffffffff,
	(unsigned long long)0xffffffff,
	(unsigned long long)4096,
	1,
	1,
	(unsigned long long)0xffffffff,
	(unsigned long long)0xffffffff,
	1,
	4,
	0
};

static ddi_device_acc_attr_t hw_acc_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC
};

void *
drm_pci_alloc(drm_softstate_t *dev, uint32_t size,
		    dma_addr_t *physaddr)
{
	int ret = DDI_FAILURE;
	uint32_t num_cookies;
	ddi_dma_cookie_t cookie;

	/* allocat continous physical memory for hw status page */
	hw_dma_attr.dma_attr_sgllen = 1;

	if (ret = ddi_dma_alloc_handle(dev->dip,
	    &hw_dma_attr,
	    DDI_DMA_SLEEP,
	    NULL, &dev->hw_dma_handle)) {
		DRM_ERROR("drm_pci_alloc:ddi_dma_alloc_handle failed\n");
		goto err3;
	}

	if (ret = ddi_dma_mem_alloc(dev->hw_dma_handle,
				size,
				&hw_acc_attr,
				DDI_DMA_CONSISTENT,
				DDI_DMA_SLEEP, NULL,
				&dev->hw_vbase,
				&dev->hw_size,
				&dev->hw_dma_acc_handle)) {
		DRM_ERROR("drm_pci_alloc: ddi_dma_mem_alloc failed\n");
		goto err2;
	}

	ret = ddi_dma_addr_bind_handle(dev->hw_dma_handle,
			NULL, dev->hw_vbase,
			size,
			DDI_DMA_RDWR|DDI_DMA_CONSISTENT,
			DDI_DMA_SLEEP, NULL,
			&cookie,  &num_cookies);
	dev->hw_pbase = cookie.dmac_address;

	if ((ret != DDI_DMA_MAPPED) || (num_cookies != 1)) {
		if (num_cookies > 1)
			(void) ddi_dma_unbind_handle(dev->hw_dma_handle);
		DRM_ERROR("drm_pci_alloc: alloc contiguous phys memory failed");
		goto err1;
	}
	*physaddr = dev->hw_pbase;
	return (dev->hw_vbase);

err1:
	ddi_dma_mem_free(&dev->hw_dma_acc_handle);
	dev->hw_dma_acc_handle = NULL;
err2:
	ddi_dma_free_handle(&dev->hw_dma_handle);
	dev->hw_dma_handle = NULL;
err3:
	dev->hw_pbase = 0;
	dev->hw_vbase = 0;
	dev->hw_size = 0;
	*physaddr = NULL;
	return (NULL);
}

/*
 * pci_free_consistent()
 */
/*ARGSUSED*/
void
drm_pci_free(drm_softstate_t *dev)
{
	if (dev->hw_dma_handle == NULL)
		return;
	(void) ddi_dma_unbind_handle(dev->hw_dma_handle);
	ddi_dma_mem_free(&dev->hw_dma_acc_handle);
	dev->hw_dma_acc_handle = NULL;
	ddi_dma_free_handle(&dev->hw_dma_handle);
	dev->hw_dma_handle = NULL;
	dev->hw_pbase = NULL;
	dev->hw_vbase = NULL;
	dev->hw_size = 0;


}

int
do_get_pci_res(drm_softstate_t *softstate, drm_pci_resource_t *resp)
{
	int length;
	pci_regspec_t	*regs;

	if (ddi_getlongprop(
	    DDI_DEV_T_ANY, softstate->dip, DDI_PROP_DONTPASS,
	    "assigned-addresses", (caddr_t)&regs, &length) !=
	    DDI_PROP_SUCCESS) {
		DRM_ERROR("do_get_pci_res: ddi_getlongprop failed!\n");
		return (DRM_ERR(EFAULT));
	}
	resp->offset =
	    (unsigned long)regs[resp->regnum].pci_phys_low;
	resp->size =
	    (unsigned long)regs[resp->regnum].pci_size_low;
	kmem_free(regs, (size_t)length);

	return (DDI_SUCCESS);
}

/*ARGSUSED*/
unsigned long
drm_get_resource_start(drm_softstate_t *softstate, unsigned int regnum)
{
	drm_pci_resource_t res;
	int ret;

	res.regnum = regnum;

	ret = do_get_pci_res(softstate, &res);

	if (ret != DDI_SUCCESS) {
		DRM_ERROR(
			"drm_get_resource_start: "
			"DRM_GET_PCI_RESOURCE ioctl failed");
		return (0);
	}

	return (res.offset);

}

/*ARGSUSED*/
unsigned long
drm_get_resource_len(drm_softstate_t *softstate, unsigned int regnum)
{
	drm_pci_resource_t res;
	int ret;

	res.regnum = regnum;

	ret = do_get_pci_res(softstate, &res);

	if (ret != DDI_SUCCESS) {
		DRM_ERROR(
			"drm_get_resource_len: "
			"DRM_GET_PCI_RESOURCE ioctl failed");
		return (0);
	}

	return (res.size);
}
