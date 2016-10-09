/*
 * Copyright (c) 2009, Intel Corporation.
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
 * THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * Authors:
 *    Eric Anholt <eric@anholt.net>
 *
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <vm/anon.h>
#include <vm/seg_kmem.h>
#include <vm/seg_kp.h>
#include <vm/seg_map.h>
#include <sys/fcntl.h>
#include <sys/vnode.h>
#include <sys/file.h>
#include <sys/bitmap.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/gfx_private.h>
#include "drmP.h"
#include "drm.h"

/*
 * @file drm_gem.c
 *
 * This file provides some of the base ioctls and library routines for
 * the graphics memory manager implemented by each device driver.
 *
 * Because various devices have different requirements in terms of
 * synchronization and migration strategies, implementing that is left up to
 * the driver, and all that the general API provides should be generic --
 * allocating objects, reading/writing data with the cpu, freeing objects.
 * Even there, platform-dependent optimizations for reading/writing data with
 * the CPU mean we'll likely hook those out to driver-specific calls.  However,
 * the DRI2 implementation wants to have at least allocate/mmap be generic.
 *
 * The goal was to have swap-backed object allocation managed through
 * struct file.  However, file descriptors as handles to a struct file have
 * two major failings:
 * - Process limits prevent more than 1024 or so being used at a time by
 *   default.
 * - Inability to allocate high fds will aggravate the X Server's select()
 *   handling, and likely that of many GL client applications as well.
 *
 * This led to a plan of using our own integer IDs(called handles, following
 * DRM terminology) to mimic fds, and implement the fd syscalls we need as
 * ioctls.  The objects themselves will still include the struct file so
 * that we can transition to fds if the required kernel infrastructure shows
 * up at a later date, and as our interface with shmfs for memory allocation.
 */

void
idr_list_init(struct idr_list  *head)
{
	struct idr_list  *entry;
	/* HASH for accelerate */
	entry = kmem_zalloc(DRM_GEM_OBJIDR_HASHNODE
	    * sizeof (struct idr_list), KM_SLEEP);
	head->next = entry;
	for (int i = 0; i < DRM_GEM_OBJIDR_HASHNODE; i++) {
		INIT_LIST_HEAD(&entry[i]);
	}
}

int
idr_list_get_new_above(struct idr_list	*head,
			struct drm_gem_object *obj,
			int *handlep)
{
	struct idr_list  *entry;
	int key;
	entry = kmem_zalloc(sizeof (*entry), KM_SLEEP);
	key = obj->name % DRM_GEM_OBJIDR_HASHNODE;
	list_add(entry, &head->next[key], NULL);
	entry->obj = obj;
	entry->handle = obj->name;
	*handlep = obj->name;
	return (0);
}

struct drm_gem_object *
idr_list_find(struct idr_list  *head,
		uint32_t	name)
{
	struct idr_list  *entry;
	int key;
	key = name % DRM_GEM_OBJIDR_HASHNODE;

	list_for_each(entry, &head->next[key]) {
		if (entry->handle == name)
			return (entry->obj);
	}
	return (NULL);
}

int
idr_list_remove(struct idr_list  *head,
		uint32_t	name)
{
	struct idr_list  *entry, *temp;
	int key;
	key = name % DRM_GEM_OBJIDR_HASHNODE;
	list_for_each_safe(entry, temp, &head->next[key]) {
		if (entry->handle == name) {
			list_del(entry);
			kmem_free(entry, sizeof (*entry));
			return (0);
		}
	}
	DRM_ERROR("Failed to remove the object %d", name);
	return (-1);
}

void
idr_list_free(struct idr_list  *head)
{
	struct idr_list  *entry, *temp;
	for (int key = 0; key < DRM_GEM_OBJIDR_HASHNODE; key++) {
		list_for_each_safe(entry, temp, &head->next[key]) {
			list_del(entry);
			kmem_free(entry, sizeof (*entry));
		}
	}
	kmem_free(head->next,
	    DRM_GEM_OBJIDR_HASHNODE * sizeof (struct idr_list));
	head->next = NULL;
}

int
idr_list_empty(struct idr_list  *head)
{
	int empty;
	for (int key = 0; key < DRM_GEM_OBJIDR_HASHNODE; key++) {
		empty = list_empty(&(head)->next[key]);
		if (!empty)
			return (empty);
	}
	return (1);
}

static	uint32_t	shfile_name = 0;
#define	SHFILE_NAME_MAX	0xffffffff

/*
 * will be set to 1 for 32 bit x86 systems only, in startup.c
 */
extern int	segkp_fromheap;
extern ulong_t *segkp_bitmap;

void
drm_gem_object_reference(struct drm_gem_object *obj)
{
	atomic_inc(&obj->refcount);
}

void
drm_gem_object_unreference(struct drm_gem_object *obj)
{
	if (obj == NULL)
		return;

	atomic_sub(1, &obj->refcount);
	if (obj->refcount == 0)
		drm_gem_object_free(obj);
}

void
drm_gem_object_handle_reference(struct drm_gem_object *obj)
{
	drm_gem_object_reference(obj);
	atomic_inc(&obj->handlecount);
}

void
drm_gem_object_handle_unreference(struct drm_gem_object *obj)
{
	if (obj == NULL)
		return;

	/*
	 * Must bump handle count first as this may be the last
	 * ref, in which case the object would disappear before we
	 * checked for a name
	 */
	atomic_sub(1, &obj->handlecount);
	if (obj->handlecount == 0)
		drm_gem_object_handle_free(obj);
	drm_gem_object_unreference(obj);
}

/*
 * Initialize the GEM device fields
 */

int
drm_gem_init(struct drm_device *dev)
{
	mutex_init(&dev->object_name_lock, NULL, MUTEX_DRIVER, NULL);
	idr_list_init(&dev->object_name_idr);

	atomic_set(&dev->object_count, 0);
	atomic_set(&dev->object_memory, 0);
	atomic_set(&dev->pin_count, 0);
	atomic_set(&dev->pin_memory, 0);
	atomic_set(&dev->gtt_count, 0);
	atomic_set(&dev->gtt_memory, 0);
	return (0);
}

/*
 * Allocate a GEM object of the specified size with shmfs backing store
 */
struct drm_gem_object *
drm_gem_object_alloc(struct drm_device *dev, size_t size)
{
	static ddi_dma_attr_t dma_attr = {
		DMA_ATTR_V0,
		0U,				/* dma_attr_addr_lo */
		0xffffffffU,			/* dma_attr_addr_hi */
		0xffffffffU,			/* dma_attr_count_max */
		4096,				/* dma_attr_align */
		0x1fffU,			/* dma_attr_burstsizes */
		1,				/* dma_attr_minxfer */
		0xffffffffU,			/* dma_attr_maxxfer */
		0xffffffffU,			/* dma_attr_seg */
		1,				/* dma_attr_sgllen, variable */
		4,				/* dma_attr_granular */
		0				/* dma_attr_flags */
	};
	static ddi_device_acc_attr_t acc_attr = {
		DDI_DEVICE_ATTR_V0,
		DDI_NEVERSWAP_ACC,
		DDI_MERGING_OK_ACC
	};
	struct drm_gem_object *obj;
	ddi_dma_cookie_t cookie;
	uint_t cookie_cnt;
	drm_local_map_t *map;

	pgcnt_t real_pgcnt, pgcnt = btopr(size);
	uint32_t paddr, cookie_end;
	int i, n;

	obj = kmem_zalloc(sizeof (struct drm_gem_object), KM_NOSLEEP);
	if (obj == NULL)
		return (NULL);

	obj->dev = dev;
	obj->flink = 0;
	obj->size = size;

	if (shfile_name == SHFILE_NAME_MAX) {
		DRM_ERROR("No name space for object");
		goto err1;
	} else {
		obj->name = ++shfile_name;
	}

	dma_attr.dma_attr_sgllen = (int)pgcnt;

	if (ddi_dma_alloc_handle(dev->dip, &dma_attr,
	    DDI_DMA_DONTWAIT, NULL, &obj->dma_hdl)) {
		DRM_ERROR("drm_gem_object_alloc: "
		    "ddi_dma_alloc_handle failed");
		goto err1;
	}
	if (ddi_dma_mem_alloc(obj->dma_hdl, ptob(pgcnt), &acc_attr,
	    IOMEM_DATA_UC_WR_COMBINE, DDI_DMA_DONTWAIT, NULL,
	    &obj->kaddr, &obj->real_size, &obj->acc_hdl)) {
		DRM_ERROR("drm_gem_object_alloc: "
		    "ddi_dma_mem_alloc failed");
		goto err2;
	}
	if (ddi_dma_addr_bind_handle(obj->dma_hdl, NULL,
	    obj->kaddr, obj->real_size, DDI_DMA_RDWR,
	    DDI_DMA_DONTWAIT, NULL, &cookie, &cookie_cnt)
	    != DDI_DMA_MAPPED) {
		DRM_ERROR("drm_gem_object_alloc: "
		    "ddi_dma_addr_bind_handle failed");
		goto err3;
	}

	real_pgcnt = btopr(obj->real_size);

	obj->pfnarray = kmem_zalloc(real_pgcnt * sizeof (pfn_t), KM_NOSLEEP);
	if (obj->pfnarray == NULL) {
		goto err4;
	}
	for (n = 0, i = 1; ; i++) {
		for (paddr = cookie.dmac_address,
		    cookie_end = cookie.dmac_address + cookie.dmac_size;
		    paddr < cookie_end;
		    paddr += PAGESIZE) {
			obj->pfnarray[n++] = btop(paddr);
			if (n >= real_pgcnt)
				goto addmap;
		}
		if (i >= cookie_cnt)
			break;
		ddi_dma_nextcookie(obj->dma_hdl, &cookie);
	}

addmap:
	map = drm_alloc(sizeof (struct drm_local_map), DRM_MEM_MAPS);
	if (map == NULL) {
		goto err5;
	}

	map->handle = obj;
	map->offset = (uintptr_t)map->handle;
	map->offset &= 0xffffffffUL;
	map->dev_addr = map->handle;
	map->size = obj->real_size;
	map->type = _DRM_TTM;
	map->flags = _DRM_WRITE_COMBINING | _DRM_REMOVABLE;
	map->drm_umem_cookie =
	    gfxp_umem_cookie_init(obj->kaddr, obj->real_size);
	if (map->drm_umem_cookie == NULL) {
		goto err6;
	}

	obj->map = map;

	atomic_set(&obj->refcount, 1);
	atomic_set(&obj->handlecount, 1);
	if (dev->driver->gem_init_object != NULL &&
	    dev->driver->gem_init_object(obj) != 0) {
		goto err7;
	}
	atomic_inc(&dev->object_count);
	atomic_add(obj->size, &dev->object_memory);

	return (obj);

err7:
	gfxp_umem_cookie_destroy(map->drm_umem_cookie);
err6:
	drm_free(map, sizeof (struct drm_local_map), DRM_MEM_MAPS);
err5:
	kmem_free(obj->pfnarray, real_pgcnt * sizeof (pfn_t));
err4:
	(void) ddi_dma_unbind_handle(obj->dma_hdl);
err3:
	ddi_dma_mem_free(&obj->acc_hdl);
err2:
	ddi_dma_free_handle(&obj->dma_hdl);
err1:
	kmem_free(obj, sizeof (struct drm_gem_object));

	return (NULL);
}

/*
 * Removes the mapping from handle to filp for this object.
 */
static int
drm_gem_handle_delete(struct drm_file *filp, int handle)
{
	struct drm_device *dev;
	struct drm_gem_object *obj;
	int err;
	/*
	 * This is gross. The idr system doesn't let us try a delete and
	 * return an error code.  It just spews if you fail at deleting.
	 * So, we have to grab a lock around finding the object and then
	 * doing the delete on it and dropping the refcount, or the user
	 * could race us to double-decrement the refcount and cause a
	 * use-after-free later.  Given the frequency of our handle lookups,
	 * we may want to use ida for number allocation and a hash table
	 * for the pointers, anyway.
	 */
	spin_lock(&filp->table_lock);

	/* Check if we currently have a reference on the object */
	obj = idr_list_find(&filp->object_idr, handle);
	if (obj == NULL) {
		spin_unlock(&filp->table_lock);
		DRM_ERROR("obj %d is not in tne list, failed to close", handle);
		return (EINVAL);
	}
	dev = obj->dev;

	/* Release reference and decrement refcount. */
	err = idr_list_remove(&filp->object_idr, handle);
	if (err == -1)
		DRM_ERROR("%s", __func__);

	spin_unlock(&filp->table_lock);

	spin_lock(&dev->struct_mutex);
	drm_gem_object_handle_unreference(obj);
	spin_unlock(&dev->struct_mutex);
	return (0);
}

/*
 * Create a handle for this object. This adds a handle reference
 * to the object, which includes a regular reference count. Callers
 * will likely want to dereference the object afterwards.
 */
int
drm_gem_handle_create(struct drm_file *file_priv,
		    struct drm_gem_object *obj,
		    int *handlep)
{
	int	ret;

	/*
	 * Get the user-visible handle using idr.
	 */
again:
	/* ensure there is space available to allocate a handle */

	/* do the allocation under our spinlock */
	spin_lock(&file_priv->table_lock);
	ret = idr_list_get_new_above(&file_priv->object_idr, obj, handlep);
	spin_unlock(&file_priv->table_lock);
	if (ret == -EAGAIN)
		goto again;

	if (ret != 0) {
		DRM_ERROR("Failed to create handle");
		return (ret);
	}

	drm_gem_object_handle_reference(obj);
	return (0);
}

/* Returns a reference to the object named by the handle. */
struct drm_gem_object *
drm_gem_object_lookup(struct drm_file *filp,
			    int handle)
{
	struct drm_gem_object *obj;

	spin_lock(&filp->table_lock);

	/* Check if we currently have a reference on the object */
	obj = idr_list_find(&filp->object_idr, handle);
		if (obj == NULL) {
			spin_unlock(&filp->table_lock);
			DRM_ERROR("object_lookup failed, handle %d", handle);
			return (NULL);
		}

	drm_gem_object_reference(obj);

	spin_unlock(&filp->table_lock);

	return (obj);
}

/*
 * Releases the handle to an mm object.
 */
/*ARGSUSED*/
int
drm_gem_close_ioctl(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	struct drm_gem_close args;
	int ret;

	if (!(dev->driver->use_gem == 1))
		return (ENODEV);

	DRM_COPYFROM_WITH_RETURN(&args,
	    (void *)data, sizeof (args));

	ret = drm_gem_handle_delete(fpriv, args.handle);

	return (ret);
}

/*
 * Create a global name for an object, returning the name.
 *
 * Note that the name does not hold a reference; when the object
 * is freed, the name goes away.
 */
/*ARGSUSED*/
int
drm_gem_flink_ioctl(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	struct drm_gem_flink args;
	struct drm_gem_object *obj;
	int ret, handle;

	if (!(dev->driver->use_gem == 1))
		return (ENODEV);

	DRM_COPYFROM_WITH_RETURN(&args,
	    (void *)data, sizeof (args));
	obj = drm_gem_object_lookup(fpriv, args.handle);
	if (obj == NULL)
		return (EINVAL);
	handle = args.handle;
	spin_lock(&dev->object_name_lock);
	if (!obj->flink) {
		/* only creat a node in object_name_idr, no update anything */
		ret = idr_list_get_new_above(&dev->object_name_idr,
		    obj, &handle);
		obj->flink = obj->name;
		/* Allocate a reference for the name table.  */
		drm_gem_object_reference(obj);
	}
	/*
	 * Leave the reference from the lookup around as the
	 * name table now holds one
	 */
	args.name = obj->name;

	spin_unlock(&dev->object_name_lock);
	ret = DRM_COPY_TO_USER((void *) data, &args, sizeof (args));
	if (ret != 0)
		DRM_ERROR(" gem flink error! %d", ret);

	spin_lock(&dev->struct_mutex);
	drm_gem_object_unreference(obj);
	spin_unlock(&dev->struct_mutex);

	return (ret);
}

/*
 * Open an object using the global name, returning a handle and the size.
 *
 * This handle (of course) holds a reference to the object, so the object
 * will not go away until the handle is deleted.
 */
/*ARGSUSED*/
int
drm_gem_open_ioctl(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	struct drm_gem_open args;
	struct drm_gem_object *obj;
	int ret;
	int handle;

	if (!(dev->driver->use_gem == 1)) {
		DRM_ERROR("Not support GEM");
		return (ENODEV);
	}
	DRM_COPYFROM_WITH_RETURN(&args,
	    (void *) data, sizeof (args));

	spin_lock(&dev->object_name_lock);

	obj = idr_list_find(&dev->object_name_idr, args.name);

	if (obj)
		drm_gem_object_reference(obj);
	spin_unlock(&dev->object_name_lock);
	if (!obj) {
		DRM_ERROR("Can't find the obj %d", args.name);
		return (ENOENT);
	}

	ret = drm_gem_handle_create(fpriv, obj, &handle);
	spin_lock(&dev->struct_mutex);
	drm_gem_object_unreference(obj);
	spin_unlock(&dev->struct_mutex);

	args.handle = args.name;
	args.size = obj->size;

	ret = DRM_COPY_TO_USER((void *) data, &args, sizeof (args));
	if (ret != 0)
		DRM_ERROR(" gem open error! %d", ret);
	return (ret);
}

/*
 * Called at device open time, sets up the structure for handling refcounting
 * of mm objects.
 */
void
drm_gem_open(struct drm_file *file_private)
{
	idr_list_init(&file_private->object_idr);
	mutex_init(&file_private->table_lock, NULL, MUTEX_DRIVER, NULL);
}

/*
 * Called at device close to release the file's
 * handle references on objects.
 */
static void
drm_gem_object_release_handle(struct drm_gem_object *obj)
{
	drm_gem_object_handle_unreference(obj);
}

/*
 * Called at close time when the filp is going away.
 *
 * Releases any remaining references on objects by this filp.
 */
void
drm_gem_release(struct drm_device *dev, struct drm_file *file_private)
{
	struct idr_list  *entry;
	spin_lock(&dev->struct_mutex);

	idr_list_for_each(entry, &file_private->object_idr)
	    drm_gem_object_release_handle(entry->obj);

	idr_list_free(&file_private->object_idr);
	spin_unlock(&dev->struct_mutex);

}

/*
 * Called after the last reference to the object has been lost.
 *
 * Frees the object
 */
void
drm_gem_object_free(struct drm_gem_object *obj)
{
	struct drm_device *dev = obj->dev;
	struct drm_local_map *map = obj->map;

	if (dev->driver->gem_free_object != NULL)
		dev->driver->gem_free_object(obj);

	gfxp_umem_cookie_destroy(map->drm_umem_cookie);
	drm_free(map, sizeof (struct drm_local_map), DRM_MEM_MAPS);

	kmem_free(obj->pfnarray, btopr(obj->real_size) * sizeof (pfn_t));

	(void) ddi_dma_unbind_handle(obj->dma_hdl);
	ddi_dma_mem_free(&obj->acc_hdl);
	ddi_dma_free_handle(&obj->dma_hdl);

	atomic_dec(&dev->object_count);
	atomic_sub(obj->size, &dev->object_memory);
	kmem_free(obj, sizeof (struct drm_gem_object));
}

/*
 * Called after the last handle to the object has been closed
 *
 * Removes any name for the object. Note that this must be
 * called before drm_gem_object_free or we'll be touching
 * freed memory
 */
void
drm_gem_object_handle_free(struct drm_gem_object *obj)
{
	int err;
	struct drm_device *dev = obj->dev;
	/* Remove any name for this object */
	spin_lock(&dev->object_name_lock);
	if (obj->flink) {
		err = idr_list_remove(&dev->object_name_idr, obj->name);
		if (err == -1)
			DRM_ERROR("%s", __func__);
		obj->flink = 0;
		spin_unlock(&dev->object_name_lock);
		/*
		 * The object name held a reference to this object, drop
		 * that now.
		 */
		drm_gem_object_unreference(obj);
	} else

		spin_unlock(&dev->object_name_lock);

}
