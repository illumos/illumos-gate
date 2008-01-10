/*
 * drm_drv.h -- Generic driver template -*- linux-c -*-
 * Created: Thu Nov 23 03:10:50 2000 by gareth@valinux.com
 */
/*
 * Copyright 1999, 2000 Precision Insight, Inc., Cedar Park, Texas.
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

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "drmP.h"
#include "drm.h"
#include "drm_sarea.h"

int drm_debug_flag = 1;

#define	DRIVER_IOCTL_COUNT	256
drm_ioctl_desc_t drm_ioctls[DRIVER_IOCTL_COUNT];

void
drm_set_ioctl_desc(int n, drm_ioctl_t *func, int auth_needed,
    int root_only, char *desc)
{
	drm_ioctls[n].func = func;
	drm_ioctls[n].auth_needed = auth_needed;
	drm_ioctls[n].root_only = root_only;
	drm_ioctls[n].desc = desc;
}

void
drm_init_ioctl_arrays(void)
{
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_VERSION),
	    drm_version, 0, 0, "drm_version");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_GET_UNIQUE),
	    drm_getunique, 0, 0, "drm_getunique");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_GET_MAGIC),
	    drm_getmagic, 0, 0, "drm_getmagic");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_IRQ_BUSID),
	    drm_irq_by_busid, 0, 1, "drm_irq_by_busid");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_GET_MAP),
	    drm_getmap, 0, 0, "drm_getmap");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_GET_CLIENT),
	    drm_getclient, 0, 0, "drm_getclient");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_GET_STATS),
	    drm_getstats, 0, 0, "drm_getstats");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_SET_VERSION),
	    drm_setversion, 0, 1, "drm_setversion");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_SET_UNIQUE),
	    drm_setunique, 1, 1, "drm_setunique");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_BLOCK),
	    drm_noop, 1, 1, "drm_ioctl_block");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_UNBLOCK),
	    drm_noop, 1, 1, "DRM_IOCTL_UNBLOCK");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_AUTH_MAGIC),
	    drm_authmagic, 1, 1, "drm_authmagic");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_ADD_MAP),
	    drm_addmap_ioctl, 1, 1, "drm_addmap_ioctl");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_RM_MAP),
	    drm_rmmap_ioctl, 1, 1, "drm_rmmap_ioctl");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_SET_SAREA_CTX),
	    drm_setsareactx, 1, 1, "drm_setsareactx");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_GET_SAREA_CTX),
	    drm_getsareactx, 1, 0, "drm_getsareactx");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_ADD_CTX),
	    drm_addctx, 1, 1, "drm_addctx");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_RM_CTX),
	    drm_rmctx, 1, 1, "drm_rmctx");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_MOD_CTX),
	    drm_modctx, 1, 1, "drm_modctx");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_GET_CTX),
	    drm_getctx,  1, 0, "drm_getctx");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_SWITCH_CTX),
	    drm_switchctx, 1, 1, "drm_switchctx");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_NEW_CTX),
	    drm_newctx, 1, 1, "drm_newctx");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_RES_CTX),
	    drm_resctx, 1, 0, "drm_resctx");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_ADD_DRAW),
	    drm_adddraw, 1, 1, "drm_adddraw");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_RM_DRAW),
	    drm_rmdraw, 1, 1, "drm_rmdraw");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_LOCK),
	    drm_lock, 1, 0, "drm_lock");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_UNLOCK),
	    drm_unlock, 1, 0, "drm_unlock");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_FINISH),
	    drm_noop, 1, 0, "drm_noop");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_ADD_BUFS),
	    drm_addbufs_ioctl, 1, 1, "drm_addbufs_ioctl");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_MARK_BUFS),
	    drm_markbufs, 1, 1, "drm_markbufs");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_INFO_BUFS),
	    drm_infobufs, 1, 0, "drm_infobufs");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_MAP_BUFS),
	    drm_mapbufs, 1, 0, "drm_mapbufs");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_FREE_BUFS),
	    drm_freebufs, 1, 0, "drm_freebufs");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_DMA),
	    drm_dma, 1, 0, "drm_dma");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_CONTROL),
	    drm_control, 1, 1, "drm_control");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_AGP_ACQUIRE),
	    drm_agp_acquire, 1, 1, "drm_agp_acquire");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_AGP_RELEASE),
	    drm_agp_release, 1, 1, "drm_agp_release");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_AGP_ENABLE),
	    drm_agp_enable, 1, 1, "drm_agp_enable");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_AGP_INFO),
	    drm_agp_info, 1, 0, "drm_agp_info");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_AGP_ALLOC),
	    drm_agp_alloc, 1, 1, "drm_agp_alloc");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_AGP_FREE),
	    drm_agp_free, 1, 1, "drm_agp_free");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_AGP_BIND),
	    drm_agp_bind, 1, 1, "drm_agp_bind");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_AGP_UNBIND),
	    drm_agp_unbind, 1, 1, "drm_agp_unbind");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_SG_ALLOC),
	    drm_sg_alloc, 1, 1, "drm_sg_alloc");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_SG_FREE),
	    drm_sg_free, 1, 1, "drm_sg_free");
	drm_set_ioctl_desc(DRM_IOCTL_NR(DRM_IOCTL_WAIT_VBLANK),
	    drm_wait_vblank, 0, 0, "drm_wait_vblank");
}


const char *
drm_find_description(int vendor, int device, drm_pci_id_list_t *idlist)
{
	int i = 0;
	for (i = 0; idlist[i].vendor != 0; i++) {
	if ((idlist[i].vendor == vendor) &&
	    (idlist[i].device == device)) {
			return (idlist[i].name);
		}
	}
	return ((char *)NULL);
}

static int
drm_firstopen(drm_device_t *dev)
{
	int i;
	int retval;
	drm_local_map_t *map;

	/* prebuild the SAREA */
	retval = drm_addmap(dev, 0, SAREA_MAX, _DRM_SHM,
	    _DRM_CONTAINS_LOCK, &map);
	if (retval != 0) {
		DRM_ERROR("firstopen: failed to prebuild SAREA");
		return (retval);
	}

	if (dev->driver->use_agp) {
		DRM_DEBUG("drm_firstopen: use_agp=%d", dev->driver->use_agp);
		if (drm_device_is_agp(dev))
			dev->agp = drm_agp_init(dev);
		if (dev->driver->require_agp && dev->agp == NULL) {
			DRM_ERROR("couldn't initialize AGP");
			return (EIO);
		}
	}

	if (dev->driver->firstopen)
		retval = dev->driver->firstopen(dev);

	if (retval != 0) {
		DRM_ERROR("drm_firstopen: driver-specific firstopen failed");
		return (retval);
	}

	dev->buf_use = 0;

	if (dev->driver->use_dma) {
		i = drm_dma_setup(dev);
		if (i != 0)
			return (i);
	}
	dev->counters  = 6;
	dev->types[0]  = _DRM_STAT_LOCK;
	dev->types[1]  = _DRM_STAT_OPENS;
	dev->types[2]  = _DRM_STAT_CLOSES;
	dev->types[3]  = _DRM_STAT_IOCTLS;
	dev->types[4]  = _DRM_STAT_LOCKS;
	dev->types[5]  = _DRM_STAT_UNLOCKS;

	for (i = 0; i < DRM_ARRAY_SIZE(dev->counts); i++)
		*(&dev->counts[i]) = 0;

	for (i = 0; i < DRM_HASH_SIZE; i++) {
		dev->magiclist[i].head = NULL;
		dev->magiclist[i].tail = NULL;
	}

	dev->irq_enabled	= 0;
	dev->context_flag	= 0;
	dev->last_context	= 0;
	dev->if_version		= 0;

	return (0);
}

/* Free resources associated with the DRM on the last close. */
static int
drm_lastclose(drm_device_t *dev)
{
	drm_magic_entry_t *pt, *next;
	drm_local_map_t *map, *mapsave;
	int i;

	DRM_SPINLOCK_ASSERT(&dev->dev_lock);

	if (dev->driver->lastclose != NULL)
		dev->driver->lastclose(dev);

	if (dev->irq_enabled)
		(void) drm_irq_uninstall(dev);

	if (dev->unique) {
		drm_free(dev->unique, dev->unique_len + 1, DRM_MEM_DRIVER);
		dev->unique = NULL;
		dev->unique_len = 0;
	}

	/* Clear pid list */
	for (i = 0; i < DRM_HASH_SIZE; i++) {
		for (pt = dev->magiclist[i].head; pt; pt = next) {
			next = pt->next;
			drm_free(pt, sizeof (*pt), DRM_MEM_MAGIC);
		}
		dev->magiclist[i].head = dev->magiclist[i].tail = NULL;
	}

	/* Clear AGP information */
	if (dev->agp) {
		drm_agp_mem_t *entry;
		drm_agp_mem_t *nexte;

		/*
		 * Remove AGP resources, but leave dev->agp
		 * intact until drm_cleanup is called.
		 */
		for (entry = dev->agp->memory; entry; entry = nexte) {
			nexte = entry->next;
			if (entry->bound)
				(void) drm_agp_unbind_memory(
				    (unsigned long)entry->handle, dev);
			(void) drm_agp_free_memory(entry->handle);
			drm_free(entry, sizeof (*entry), DRM_MEM_AGPLISTS);
		}
		dev->agp->memory = NULL;

		if (dev->agp->acquired)
			(void) drm_agp_do_release(dev);

		dev->agp->acquired = 0;
		dev->agp->enabled  = 0;
		drm_agp_fini(dev);
	}

	if (dev->sg != NULL) {
		drm_sg_mem_t *entry;
		entry = dev->sg;
		dev->sg = NULL;
		drm_sg_cleanup(dev, entry);
	}


	/* Clean up maps that weren't set up by the driver. */
	TAILQ_FOREACH_SAFE(map, &dev->maplist, link, mapsave) {
		if (!map->kernel_owned)
			drm_rmmap(dev, map);
	}

	drm_dma_takedown(dev);
	if (dev->lock.hw_lock) {
		dev->lock.hw_lock = NULL; /* SHM removed */
		dev->lock.filp = NULL;

		mutex_enter(&(dev->lock.lock_mutex));
		cv_broadcast(&(dev->lock.lock_cv));
		mutex_exit(&(dev->lock.lock_mutex));
	}

	return (0);
}

static int
drm_load(drm_device_t *dev)
{
	int retcode;

	cv_init(&(dev->lock.lock_cv), NULL, CV_DRIVER, NULL);
	mutex_init(&(dev->lock.lock_mutex), NULL, MUTEX_DRIVER, NULL);
	mutex_init(&(dev->dev_lock), NULL, MUTEX_DRIVER, NULL);
	mutex_init(&dev->drw_lock, NULL, MUTEX_DRIVER, NULL);

	dev->pci_vendor = pci_get_vendor(dev);
	dev->pci_device = pci_get_device(dev);

	dev->cloneopens = 0;
	dev->minordevs = NULL;
	TAILQ_INIT(&dev->maplist);

	TAILQ_INIT(&dev->files);
	if (dev->driver->load != NULL) {
		retcode = dev->driver->load(dev, 0);
		if (retcode != 0) {
			DRM_ERROR("drm_load: failed\n");
			goto error;
		}
	}

	retcode = drm_ctxbitmap_init(dev);
	if (retcode != 0) {
		DRM_ERROR("drm_load: Cannot allocate memory for ctx bitmap");
		goto error;
	}

	if (drm_init_kstats(dev)) {
		DRM_ERROR("drm_attach => drm_load: init kstats error");
		retcode = EFAULT;
		goto error;
	}

	DRM_INFO("!drm: Initialized %s %d.%d.%d %s ",
	    dev->driver->driver_name,
	    dev->driver->driver_major,
	    dev->driver->driver_minor,
	    dev->driver->driver_patchlevel,
	    dev->driver->driver_date);
	return (0);

error:
	DRM_LOCK();
	(void) drm_lastclose(dev);
	DRM_UNLOCK();
	cv_destroy(&(dev->lock.lock_cv));
	mutex_destroy(&(dev->lock.lock_mutex));
	mutex_destroy(&(dev->dev_lock));
	mutex_destroy(&dev->drw_lock);

	return (retcode);
}

/* called when cleanup this module */
static void
drm_unload(drm_device_t *dev)
{
	drm_local_map_t *map;

	drm_ctxbitmap_cleanup(dev);

	DRM_LOCK();
	(void) drm_lastclose(dev);
	DRM_UNLOCK();

	while ((map = TAILQ_FIRST(&dev->maplist)) != NULL) {
		drm_rmmap(dev, map);
	}

	if (dev->driver->unload != NULL)
		dev->driver->unload(dev);

	drm_mem_uninit();
	cv_destroy(&dev->lock.lock_cv);
	mutex_destroy(&dev->lock.lock_mutex);
	mutex_destroy(&dev->dev_lock);
	mutex_destroy(&dev->drw_lock);
}


/*ARGSUSED*/
int
drm_open(drm_device_t *dev, dev_t *kdev, int openflags,
    int otyp, cred_t *credp)
{
	int retcode;

	retcode = drm_open_helper(dev, openflags, otyp, credp);

	if (!retcode) {
		atomic_inc_32(&dev->counts[_DRM_STAT_OPENS]);
		DRM_LOCK();
		if (!dev->open_count ++)
			retcode = drm_firstopen(dev);
		DRM_UNLOCK();
	}

	return (retcode);
}

/*ARGSUSED*/
int
drm_close(drm_device_t *dev, dev_t kdev, int flag, int otyp,
    cred_t *credp)
{
	drm_file_t *fpriv;
	int retcode = 0;

	DRM_DEBUG("drm_close: open_count = %d", dev->open_count);

	DRM_LOCK();
	fpriv = drm_find_file_by_proc(dev, credp);
	if (!fpriv) {
		DRM_UNLOCK();
		DRM_ERROR("drm_close: can't find authenticator");
		return (EACCES);
	}

	if (--fpriv->refs != 0)
		goto done;

	if (dev->driver->preclose != NULL)
		dev->driver->preclose(dev, fpriv);

	/*
	 * Begin inline drm_release
	 */
	DRM_DEBUG("drm_close :pid = %d , open_count = %d",
	    DRM_CURRENTPID, dev->open_count);

	if (dev->lock.hw_lock &&
	    _DRM_LOCK_IS_HELD(dev->lock.hw_lock->lock) &&
	    dev->lock.filp == fpriv) {
		DRM_DEBUG("Process %d dead, freeing lock for context %d",
		    DRM_CURRENTPID,
		    _DRM_LOCKING_CONTEXT(dev->lock.hw_lock->lock));
		if (dev->driver->reclaim_buffers_locked != NULL)
			dev->driver->reclaim_buffers_locked(dev, fpriv);
		(void) drm_lock_free(dev, &dev->lock.hw_lock->lock,
		    _DRM_LOCKING_CONTEXT(dev->lock.hw_lock->lock));
	} else if (dev->driver->reclaim_buffers_locked != NULL &&
	    dev->lock.hw_lock != NULL) {
		DRM_ERROR("drm_close: "
		    "retake lock not implemented yet");
	}

	if (dev->driver->use_dma)
		drm_reclaim_buffers(dev, fpriv);


	if (dev->driver->postclose != NULL)
		dev->driver->postclose(dev, fpriv);
	TAILQ_REMOVE(&dev->files, fpriv, link);
	drm_free(fpriv, sizeof (*fpriv), DRM_MEM_FILES);

done:
	atomic_inc_32(&dev->counts[_DRM_STAT_CLOSES]);

	if (--dev->open_count == 0) {
		retcode = drm_lastclose(dev);
	}
	DRM_UNLOCK();

	return (retcode);
}

int
drm_attach(drm_device_t *dev)
{
	drm_init_ioctl_arrays();
	return (drm_load(dev));
}

int
drm_detach(drm_device_t *dev)
{
	drm_unload(dev);
	drm_fini_kstats(dev);
	return (DDI_SUCCESS);
}

static int
drm_get_businfo(drm_device_t *dev)
{
	dev->irq = pci_get_irq(dev);
	if (dev->irq == -1) {
		DRM_ERROR("drm_get_businfo: get irq error");
		return (DDI_FAILURE);
	}
	/* XXX Fix domain number (alpha hoses) */
	dev->pci_domain = 0;
	if (pci_get_info(dev, &dev->pci_bus,
	    &dev->pci_slot, &dev->pci_func) != DDI_SUCCESS) {
		DRM_ERROR("drm_get_businfo: get bus slot func error ");
		return (DDI_FAILURE);
	}
	DRM_DEBUG("drm_get_businfo: pci bus: %d, pci slot :%d pci func %d",
	    dev->pci_bus, dev->pci_slot, dev->pci_func);
	return (DDI_SUCCESS);
}

int
drm_probe(drm_device_t *dev, drm_pci_id_list_t *idlist)
{
	const char *s = NULL;
	int vendor, device;

	vendor = pci_get_vendor(dev);
	device = pci_get_device(dev);

	s = drm_find_description(vendor, device, idlist);
	if (s != NULL) {
		dev->desc = s;
		if (drm_get_businfo(dev) != DDI_SUCCESS) {
			DRM_ERROR("drm_probe: drm get bus info error");
			return (DDI_FAILURE);
		}
		return (DDI_SUCCESS);
	}
	return (DDI_FAILURE);
}
