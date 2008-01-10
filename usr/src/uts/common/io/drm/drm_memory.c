/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * drm_memory.h -- Memory management wrappers for DRM -*- linux-c -*-
 * Created: Thu Feb  4 14:00:34 1999 by faith@valinux.com
 */
/*
 * Copyright 1999 Precision Insight, Inc., Cedar Park, Texas.
 * Copyright 2000 VA Linux Systems, Inc., Sunnyvale, California.
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
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
 * VA LINUX SYSTEMS AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors:
 *    Rickard E. (Rik) Faith <faith@valinux.com>
 *    Gareth Hughes <gareth@valinux.com>
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "drmP.h"

/* Device memory access structure */
typedef struct drm_device_iomap {
	uint_t			physical;	/* physical address */
	uint_t			size;		/* size of mapping */
	uint_t			drm_regnum;	/* register number */
	caddr_t			drm_base;	/* kernel virtual address */
	ddi_acc_handle_t	drm_handle; 	/* data access handle */
} drm_device_iomap_t;

void
drm_mem_init(void)
{
}

void
drm_mem_uninit(void)
{
}

/*ARGSUSED*/
void *
drm_alloc(size_t size, int area)
{
	return (kmem_zalloc(1 * size, KM_NOSLEEP));
}

/*ARGSUSED*/
void *
drm_calloc(size_t nmemb, size_t size, int area)
{
	return (kmem_zalloc(size * nmemb, KM_NOSLEEP));
}

/*ARGSUSED*/
void *
drm_realloc(void *oldpt, size_t oldsize, size_t size, int area)
{
	void *pt;

	pt = kmem_zalloc(1 * size, KM_NOSLEEP);
	if (pt == NULL) {
		DRM_ERROR("pt is NULL strange");
		return (NULL);
	}
	if (oldpt && oldsize) {
		bcopy(pt, oldpt, oldsize);
		kmem_free(oldpt, oldsize);
	}
	return (pt);
}

/*ARGSUSED*/
void
drm_free(void *pt, size_t size, int area)
{
	kmem_free(pt, size);
}

/*ARGSUSED*/
int
drm_get_pci_index_reg(dev_info_t *devi, uint_t physical, uint_t size,
    off_t *off)
{
	int		length;
	pci_regspec_t	*regs;
	int		n_reg, i;
	int		regnum;
	uint_t		base, regsize;

	regnum = -1;

	if (ddi_dev_nregs(devi, &n_reg) == DDI_FAILURE) {
		DRM_ERROR("drm_get_pci_index_reg:ddi_dev_nregs failed\n");
		n_reg = 0;
		return (-1);
	}

	if (ddi_getlongprop(DDI_DEV_T_ANY, devi, DDI_PROP_DONTPASS,
	    "assigned-addresses", (caddr_t)&regs, &length) !=
	    DDI_PROP_SUCCESS) {
		DRM_ERROR("drm_get_pci_index_reg: ddi_getlongprop failed!\n");
		goto error;
	}

	for (i = 0; i < n_reg; i ++) {
		base = (uint_t)regs[i].pci_phys_low;
		regsize = (uint_t)regs[i].pci_size_low;
		if ((uint_t)physical >= base &&
		    (uint_t)physical < (base + regsize)) {
			regnum = i + 1;
			*off = (off_t)(physical - base);
			break;
		}
	}
	kmem_free(regs, (size_t)length);
	return (regnum);
error:
	kmem_free(regs, (size_t)length);
	return (-1);
}

/* data access attributes structure for register access */
static ddi_device_acc_attr_t dev_attr = {
	DDI_DEVICE_ATTR_V0,
	DDI_NEVERSWAP_ACC,
	DDI_STRICTORDER_ACC,
};

int
do_ioremap(dev_info_t *devi, drm_device_iomap_t *iomap)
{
	int regnum;
	off_t offset;
	int ret;

	regnum =  drm_get_pci_index_reg(devi, iomap->physical,
	    iomap->size, &offset);
	if (regnum < 0) {
		DRM_ERROR("do_ioremap: can not find regster entry,"
		    " start=0x%x, size=0x%x", iomap->physical, iomap->size);
		return (ENXIO);
	}

	iomap->drm_regnum = regnum;

	ret = ddi_regs_map_setup(devi, iomap->drm_regnum,
	    (caddr_t *)&(iomap->drm_base), (offset_t)offset,
	    (offset_t)iomap->size, &dev_attr, &iomap->drm_handle);
	if (ret < 0) {
		DRM_ERROR("do_ioremap: failed to map regs: regno=%d,"
		    " offset=0x%x", regnum, offset);
		iomap->drm_handle = NULL;
		return (EFAULT);
	}

	return (0);
}

int
drm_ioremap(drm_device_t *softstate, drm_local_map_t *map)
{
	drm_device_iomap_t iomap;
	int ret;

	DRM_DEBUG("drm_ioremap called\n");

	bzero(&iomap, sizeof (drm_device_iomap_t));
	iomap.physical = map->offset;
	iomap.size = map->size;
	ret = do_ioremap(softstate->dip, &iomap);

	if (ret) {
		DRM_ERROR("drm_ioremap: failed, physaddr=0x%x, size=0x%x",
		    map->offset, map->size);
		return (ret);
	}

	/* ddi_acc_handle_t */
	map->dev_handle = iomap.drm_handle;
	map->handle = (void *)iomap.drm_base;
	map->dev_addr = iomap.drm_base;

	DRM_DEBUG(
	    "map->handle is %p map->dev_addr is %lx",
	    (void *)map->handle, (unsigned long)map->dev_addr);

	return (0);
}

void
drm_ioremapfree(drm_local_map_t *map)
{
	if (map->dev_handle == NULL) {
		DRM_ERROR("drm_ioremapfree: handle is NULL");
		return;
	}
	ddi_regs_map_free(&map->dev_handle);
}
