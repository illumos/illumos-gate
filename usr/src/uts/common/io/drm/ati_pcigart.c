/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */
/*
 * ati_pcigart.h -- ATI PCI GART support -*- linux-c -*-
 * Created: Wed Dec 13 21:52:19 2000 by gareth@valinux.com
 */
/*
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
 * PRECISION INSIGHT AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 *
 * Authors:
 *   Gareth Hughes <gareth@valinux.com>
 *
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "drmP.h"

#define	ATI_PCIGART_PAGE_SIZE		4096	/* PCI GART page size */
#define	ATI_MAX_PCIGART_PAGES		8192	/* 32 MB aperture, 4K pages */
#define	ATI_PCIGART_TABLE_SIZE		32768

int
drm_ati_pcigart_init(drm_device_t *dev, drm_ati_pcigart_info *gart_info)
{
	unsigned long pages;
	drm_sg_mem_t *entry;
	drm_dma_handle_t *dmah;
	u32 *pci_gart = NULL, page_base;
	int i, j, k;
	int	pagenum;
	size_t	bulksize;

	entry = dev->sg;
	if (entry == NULL) {
		DRM_ERROR("no scatter/gather memory!\n");
		return (0);
	}

	if (gart_info->gart_table_location == DRM_ATI_GART_MAIN) {
		/* GART table in system memory */
		entry->dmah_gart = drm_pci_alloc(dev, ATI_PCIGART_TABLE_SIZE, 0,
		    0xfffffffful, 1);
		if (entry->dmah_gart == NULL) {
			DRM_ERROR("cannot allocate PCI GART table!\n");
			return (0);
		}
		gart_info->addr = (void *)entry->dmah_gart->vaddr;
		gart_info->bus_addr = entry->dmah_gart->paddr;
		pci_gart = (u32 *)entry->dmah_gart->vaddr;
	} else {
		/* GART table in framebuffer memory */
		pci_gart = gart_info->addr;
	}

	pages = DRM_MIN(entry->pages, ATI_MAX_PCIGART_PAGES);
	bzero(pci_gart, ATI_PCIGART_TABLE_SIZE);
	ASSERT(PAGE_SIZE >= ATI_PCIGART_PAGE_SIZE);

	dmah = entry->dmah_sg;
	pagenum = 0;
	for (i = 0; i < dmah->cookie_num; i++) {
		bulksize = dmah->cookie.dmac_size;
		for (k = 0; k < bulksize / PAGE_SIZE; k++) {
			entry->busaddr[pagenum] =
			    dmah->cookie.dmac_address + k * PAGE_SIZE;
			page_base =  (u32) entry->busaddr[pagenum];
			if (pagenum ++ == pages)
				goto out;
			for (j = 0; j < (PAGE_SIZE / ATI_PCIGART_PAGE_SIZE);
			    j++) {
				if (gart_info->is_pcie)
					*pci_gart = (page_base >> 8) | 0xc;
				else
					*pci_gart = page_base;
				pci_gart++;
				page_base += ATI_PCIGART_PAGE_SIZE;
			}
		}
		ddi_dma_nextcookie(dmah->dma_hdl, &dmah->cookie);
	}

out:
	if (gart_info->gart_table_location == DRM_ATI_GART_MAIN) {
		(void) ddi_dma_sync(entry->dmah_gart->dma_hdl, 0,
		    entry->dmah_gart->real_sz, DDI_DMA_SYNC_FORDEV);
	}

	return (1);
}

/*ARGSUSED*/
extern int
drm_ati_pcigart_cleanup(drm_device_t *dev, drm_ati_pcigart_info *gart_info)
{
	drm_dma_handle_t	*dmah;

	if (dev->sg == NULL) {
		DRM_ERROR("no scatter/gather memory!\n");
		return (0);
	}
	dmah = dev->sg->dmah_gart;
	dev->sg->dmah_gart = NULL;
	if (dmah)
		drm_pci_free(dev, dmah);
	return (1);
}
