/* BEGIN CSTYLED */

/*
 * i915_drv.c -- Intel i915 driver -*- linux-c -*-
 * Created: Wed Feb 14 17:10:04 2001 by gareth@valinux.com
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
 * VA LINUX SYSTEMS AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
 * OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
 * ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 *
 * Authors:
 *    Gareth Hughes <gareth@valinux.com>
 *
 */

/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "drmP.h"
#include "drm.h"
#include "i915_drm.h"
#include "i915_drv.h"
#include "drm_pciids.h"

#define	i915_max_ioctl  15

/* drv_PCI_IDs comes from drm_pciids.h, generated from drm_pciids.txt. */
static drm_pci_id_list_t i915_pciidlist[] = {
	i915_PCI_IDS
};

drm_ioctl_desc_t i915_ioctls[i915_max_ioctl];

extern drm_ioctl_desc_t drm_ioctls[];
extern void i915_init_ioctl_arrays(void);
extern uint_t i915_driver_irq_handler(caddr_t);
extern int drm_get_pci_index_reg(dev_info_t *devi, uint_t physical,
    uint_t size, off_t *off);

static void i915_configure(drm_device_t *dev)
{
	i915_init_ioctl_arrays();

	dev->dev_priv_size		= 1;	/* No dev_priv */

	dev->irq_preinstall		= i915_driver_irq_preinstall;
	dev->irq_postinstall		= i915_driver_irq_postinstall;
	dev->irq_uninstall		= i915_driver_irq_uninstall;
	dev->irq_handler 		= i915_driver_irq_handler;

	dev->driver_ioctls		= i915_ioctls;
	dev->max_driver_ioctl		= i915_max_ioctl;

	dev->driver_name		= DRIVER_NAME;
	dev->driver_desc		= DRIVER_DESC;
	dev->driver_date		= DRIVER_DATE;
	dev->driver_major		= DRIVER_MAJOR;
	dev->driver_minor		= DRIVER_MINOR;
	dev->driver_patchlevel		= DRIVER_PATCHLEVEL;

	dev->use_agp			= 0;
	dev->use_irq			= 1;
}

extern int
i915_open(dev_t *dev, int openflags, int otyp, cred_t *credp,
    struct drm_softstate *softc)
{
	int minor;
	struct minordev *mp, *newp;
	int cloneminor, cleanpass;

	if (softc == NULL) {
		DRM_ERROR("i915_open: NULL soft state");
		return (ENXIO);
	}

	if (softc->drm_supported == DRM_UNSUPPORT) {
		if (drm_probe(softc, i915_pciidlist) !=
		    DDI_SUCCESS) {
			DRM_ERROR("i915_open: "
			    "DRM current don't support this graphics card");
			return (ENXIO);
		}
		softc->drm_supported = DRM_SUPPORT;

	}

	minor = (getminor(*dev));

	newp = kmem_zalloc(sizeof (struct minordev), KM_SLEEP);

	mutex_enter(&softc->dev_lock);

	for (cloneminor = minor; ; cloneminor += 1) {
		cleanpass = 1;
		for (mp = softc->minordevs; mp != NULL; mp = mp->next) {
			if (mp->cloneminor == cloneminor) {
				cleanpass = 0;
				break;
			}
		}
		if (cleanpass) {
			goto gotminor;
		}
	}

gotminor:
	newp->next = softc->minordevs;
	newp->cloneminor = cloneminor;
	softc->minordevs = newp;
	softc->cloneopens++;
	mutex_exit(&softc->dev_lock);

	*dev = makedevice(getmajor(*dev), cloneminor);

	return (drm_open(softc, dev, openflags, otyp, credp));

}

extern int
i915_close(dev_t dev, int flag, int otyp, cred_t *credp,
    struct drm_softstate *softc)
{
	struct minordev *lastp, *mp;
	int minor;
	DRMFILE filp = (void *)(uintptr_t)(DRM_CURRENTPID);
	drm_i915_private_t *dev_priv;
	struct mem_block *block, **heap;

	block = NULL;
	heap = NULL;
	dev_priv = NULL;

	if (softc == NULL) {
		DRM_ERROR("i915_close: NULL soft state");
		return (ENXIO);
	}

	dev_priv = softc->dev_private;

	if (dev_priv) {
		heap = get_heap(dev_priv, I915_MEM_REGION_AGP);
		if (heap == NULL || *heap == NULL)
			return DRM_ERR(EFAULT);

		block = find_block_by_proc(*heap, filp);
		if (block != NULL)
		{
			mark_block(softc, block, 0);
			free_block(block);
		}
	}

	if ((minor = getminor(dev)) < 0) {
		return (ENXIO);
	}

	mutex_enter(&softc->dev_lock);

	lastp = NULL;
	for (mp = softc->minordevs; mp != NULL; mp = mp->next) {
		if (mp->cloneminor == minor) {
			if (lastp == NULL) {
				softc->minordevs = mp->next;
			} else {
				lastp->next = mp->next;
			}

			softc->cloneopens--;
			(void) kmem_free(mp, sizeof (struct minordev));
			break;
		} else {
			lastp = mp;
		}
	}

	mutex_exit(&softc->dev_lock);

	return (drm_close(softc, dev, flag, otyp, credp));
}

int
i915_ioctl(dev_t kdev, int cmd, intptr_t intarg, int flags, cred_t *credp,
    int *rvalp, struct drm_softstate *dev)
{
	int retcode = ENXIO;
	drm_ioctl_desc_t *ioctl;
	drm_ioctl_t *func;
	int nr = DRM_IOCTL_NR(cmd);
	drm_file_t *priv;
	DRMFILE filp;

	DRM_LOCK();
	priv = drm_find_file_by_proc(dev, credp);
	DRM_UNLOCK();
	if (priv == NULL) {
		DRM_ERROR("i915_ioctl : can't find authenticator");
		return (EINVAL);
	}

	atomic_inc_32(&dev->counts[_DRM_STAT_IOCTLS]);
	++priv->ioctl_count;

	ioctl = &drm_ioctls[nr];
	/* It's not a core DRM ioctl, try driver-specific. */
	if (ioctl->func == NULL && nr >= DRM_COMMAND_BASE) {
		/* The array entries begin at DRM_COMMAND_BASE ioctl nr */
		nr -= DRM_COMMAND_BASE;
		if (nr > dev->max_driver_ioctl) {
			DRM_ERROR("Bad driver ioctl number, 0x%x (of 0x%x)",
			    nr, dev->max_driver_ioctl);
			return (EINVAL);
		}
		ioctl = &dev->driver_ioctls[nr];
	}

	func = ioctl->func;
	if ((ioctl->root_only && !DRM_SUSER(credp)) || (ioctl->auth_needed &&
	    !priv->authenticated))
		return (EACCES);

	if (func == NULL) {
		DRM_ERROR("i915_ioctl: no function ");
		return (EINVAL);
	}
	filp = (void *)(uintptr_t)(DRM_CURRENTPID);
	retcode = func(kdev, dev, intarg, flags, credp, rvalp, filp);

	return (retcode);
}

/*ARGSUSED*/
int
i915_devmap(dev_t kdev, devmap_cookie_t cookie, offset_t offset, size_t len,
    size_t *maplen, uint_t model, struct drm_softstate *dev,
    ddi_device_acc_attr_t *accattrp)
{
	drm_local_map_t *map;
	offset_t koff;
	size_t length;
	int ret;

	if (dev == NULL) {
		DRM_ERROR("i915_devmap: NULL soft state");
		return (EINVAL);
	}

	DRM_LOCK();
	TAILQ_FOREACH(map, &dev->maplist, link) {
		DRM_DEBUG("i915_devmap: offset is 0x%llx map->offset is 0x%llx",
		    offset, map->offset);
		/*
		 * use low 32-bit to search only, since 32-bit user app is
		 * incapable of passing in 64-bit offset when doing mmap.
		 */
		if ((u_offset_t)(unsigned int)offset >=  map->offset.off &&
		    (u_offset_t)(unsigned int)offset
		    	< (u_offset_t)map->offset.off + map->size)
			break;
	}

	if (map == NULL) {
		DRM_UNLOCK();
		DRM_ERROR("can't find map\n");
		return (-1);
	}
	if (map->flags&_DRM_RESTRICTED) {
		DRM_UNLOCK();
		DRM_ERROR("restricted map\n");
		return (-1);
	}

	DRM_UNLOCK();

	switch (map->type) {
	case _DRM_FRAME_BUFFER:
	case _DRM_REGISTERS:
	case _DRM_AGP:
		{
			int	err;
			int	regno;
			off_t	regoff;

			regno = drm_get_pci_index_reg(dev->dip,
			    offset, (uint_t)len, &regoff);

			err = devmap_devmem_setup(cookie, dev->dip, NULL,
			    regno, (offset_t)regoff, len, PROT_ALL,
			    0, accattrp);
			if (err != 0) {
				*maplen = 0;
				DRM_ERROR("i915_devmap: devmap failed");
				return (err);
			}
			*maplen = len;
			return (err);
		}

	case _DRM_SHM:
		{
			DRM_DEBUG("i915_devmap: map type is _DRM_SHM");
			if (map->drm_umem_cookie == NULL) {
				DRM_ERROR("i915_devmap: "
				    "Fatal error! sarea_cookie is NULL");
				return (EINVAL);
			}
			koff = 0;
			length = ptob(btopr(map->size));
			ret = devmap_umem_setup(cookie, dev->dip, NULL,
			    map->drm_umem_cookie, koff, length,
			    PROT_ALL, DEVMAP_DEFAULTS, NULL);
			if (ret != 0) {
				*maplen = 0;
				return (ret);
			}
			*maplen = length;

			return (DDI_SUCCESS);
		}
	default:
		return (DDI_FAILURE);
	}
}

int
i915_attach(dev_info_t *dip,
    ddi_attach_cmd_t cmd,
    struct drm_softstate **drm_softcp,
    ddi_acc_handle_t pci_cfg_hdl,
    minor_t minor)
{
	int instance;
	drm_softstate_t *softc;
	int ret;
	char buf[80];

	if (cmd != DDI_ATTACH) {
		DRM_ERROR(
		    "i915_attach: only attach op supported");
		return (DDI_FAILURE);
	}

	softc = (drm_softstate_t *)
	    kmem_zalloc(sizeof (drm_softstate_t), KM_SLEEP);

	softc->dip = dip;
	softc->pci_cfg_hdl = pci_cfg_hdl;
	softc->drm_supported = DRM_UNSUPPORT;
	i915_configure(softc);

	/* call common attach code */
	ret = drm_attach(softc);
	if (ret != DDI_SUCCESS) {
		DRM_ERROR(
		    "i915_attach: drm attach ops failed");
		goto err1;
	}

	/* create minor node for DRM access */
	instance = ddi_get_instance(dip);

	(void) sprintf(buf, "%s%d", DRM_DEVNODE, instance);
	if (ddi_create_minor_node(dip, buf, S_IFCHR,
	    minor, DDI_NT_DISPLAY_DRM, 0)) {
		DRM_ERROR("i915_attach: create minor node failed");
		goto err2;
	}

	*drm_softcp = softc;

	return (DDI_SUCCESS);
err2:
	ddi_remove_minor_node(dip, DRM_DEVNODE);
err1:
	kmem_free(softc, sizeof (drm_softstate_t));
	*drm_softcp = NULL;
	return (DDI_FAILURE);

}

int
i915_detach(dev_info_t *dip, ddi_detach_cmd_t cmd,
    drm_softstate_t **drm_softcp)
{
	drm_softstate_t *softc = *drm_softcp;

	if (cmd != DDI_DETACH)
		return (DDI_FAILURE);

	(void) drm_detach(softc);

	ddi_remove_minor_node(dip, DRM_DEVNODE);
	kmem_free(softc, sizeof (drm_softstate_t));
	*drm_softcp = NULL;

	return (DDI_SUCCESS);
}
