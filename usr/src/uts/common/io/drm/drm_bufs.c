/*
 * drm_bufs.h -- Generic buffer template -*- linux-c -*-
 * Created: Thu Nov 23 03:10:50 2000 by gareth@valinux.com
 */
/*
 * Copyright 1999, 2000 Precision Insight, Inc., Cedar Park, Texas.
 * Copyright 2000 VA Linux Systems, Inc., Sunnyvale, California.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "drmP.h"
#include <sys/gfx_private.h>
#include "drm_io32.h"


#define	PAGE_MASK	(PAGE_SIZE-1)
#define	round_page(x)	(((x) + PAGE_MASK) & ~PAGE_MASK)

/*
 * Compute order.  Can be made faster.
 */
int
drm_order(unsigned long size)
{
	int order = 0;
	unsigned long tmp = size;

	while (tmp >>= 1)
		order ++;

	if (size & ~(1 << order))
		++order;

	return (order);
}

static inline drm_local_map_t *
drm_find_map(drm_device_t *dev, u_offset_t offset, int type)
{
	drm_local_map_t		*map;

	TAILQ_FOREACH(map, &dev->maplist, link) {
		if ((map->type == type) && ((map->offset == offset) ||
		    (map->flags == _DRM_CONTAINS_LOCK) &&
		    (map->type == _DRM_SHM)))
			return (map);
	}

	return (NULL);
}

int drm_addmap(drm_device_t *dev, unsigned long offset,
    unsigned long size, drm_map_type_t type,
    drm_map_flags_t flags, drm_local_map_t **map_ptr)
{
	drm_local_map_t *map;
	caddr_t		kva;
	int		retval;

	/*
	 * Only allow shared memory to be removable since we only keep
	 * enough book keeping information about shared memory to allow
	 * for removal when processes fork.
	 */
	if ((flags & _DRM_REMOVABLE) && type != _DRM_SHM)
		return (EINVAL);
	if ((offset & PAGE_MASK) || (size & PAGE_MASK))
		return (EINVAL);
	if (offset + size < offset)
		return (EINVAL);

	/*
	 * Check if this is just another version of a kernel-allocated
	 * map, and just hand that back if so.
	 */
	map = drm_find_map(dev, offset, type);
	if (map != NULL) {
		goto done;
	}

	/*
	 * Allocate a new map structure, fill it in, and do any
	 * type-specific initialization necessary.
	 */
	map = drm_alloc(sizeof (*map), DRM_MEM_MAPS);
	if (!map)
		return (ENOMEM);

	map->offset = offset;
	map->size = size;
	map->type = type;
	map->flags = flags;

	switch (map->type) {
	case _DRM_REGISTERS:
	case _DRM_FRAME_BUFFER:
		retval = drm_ioremap(dev, map);
		if (retval)
			return (retval);
		break;

	case _DRM_SHM:
		/*
		 * ddi_umem_alloc() grants page-aligned memory. We needn't
		 * handle alignment issue here.
		 */
		map->handle = ddi_umem_alloc(map->size,
		    DDI_UMEM_NOSLEEP, &map->drm_umem_cookie);
		if (!map->handle) {
			DRM_ERROR("drm_addmap: ddi_umem_alloc failed");
			drm_free(map, sizeof (*map), DRM_MEM_MAPS);
			return (ENOMEM);
		}
		/*
		 * record only low 32-bit of this handle, since 32-bit
		 * user app is incapable of passing in 64bit offset when
		 * doing mmap.
		 */
		map->offset = (uintptr_t)map->handle;
		map->offset &= 0xffffffffUL;
		if (map->flags & _DRM_CONTAINS_LOCK) {
			/* Prevent a 2nd X Server from creating a 2nd lock */
			if (dev->lock.hw_lock != NULL) {
				ddi_umem_free(map->drm_umem_cookie);
				drm_free(map, sizeof (*map), DRM_MEM_MAPS);
				return (EBUSY);
			}
			dev->lock.hw_lock = map->handle; /* Pointer to lock */
		}
		map->dev_addr = map->handle;
		break;
	case _DRM_SCATTER_GATHER:
		if (!dev->sg) {
			drm_free(map, sizeof (*map), DRM_MEM_MAPS);
			return (EINVAL);
		}
		map->offset += (uintptr_t)dev->sg->virtual;
		map->handle = (void *)(uintptr_t)map->offset;
		map->dev_addr = dev->sg->virtual;
		map->dev_handle = dev->sg->dmah_sg->acc_hdl;
		break;

	case _DRM_CONSISTENT:
		DRM_ERROR("%d DRM_AGP_CONSISTENT", __LINE__);
		return (ENOTSUP);
	case _DRM_AGP:
		map->offset += dev->agp->base;
		kva = gfxp_map_kernel_space(map->offset, map->size,
		    GFXP_MEMORY_WRITECOMBINED);
		if (kva == 0) {
			drm_free(map, sizeof (*map), DRM_MEM_MAPS);
			cmn_err(CE_WARN,
			    "drm_addmap: failed to map AGP aperture");
			return (ENOMEM);
		}
		map->handle = (void *)(uintptr_t)kva;
		map->dev_addr = kva;
		break;
	default:
		drm_free(map, sizeof (*map), DRM_MEM_MAPS);
		return (EINVAL);
	}

	TAILQ_INSERT_TAIL(&dev->maplist, map, link);

done:
	/* Jumped to, with lock held, when a kernel map is found. */
	*map_ptr = map;

	return (0);
}

/*ARGSUSED*/
int
drm_addmap_ioctl(DRM_IOCTL_ARGS)
{
	drm_map_t request;
	drm_local_map_t *map;
	int err;
	DRM_DEVICE;

#ifdef	_MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_map_32_t request32;
		DRM_COPYFROM_WITH_RETURN(&request32,
		    (void *)data, sizeof (request32));
		request.offset = request32.offset;
		request.size = request32.size;
		request.type = request32.type;
		request.flags = request32.flags;
		request.mtrr = request32.mtrr;
	} else
#endif
		DRM_COPYFROM_WITH_RETURN(&request,
		    (void *)data, sizeof (request));

	err = drm_addmap(dev, request.offset, request.size, request.type,
	    request.flags, &map);

	if (err != 0)
		return (err);

	request.offset = map->offset;
	request.size = map->size;
	request.type = map->type;
	request.flags = map->flags;
	request.mtrr   = map->mtrr;
	request.handle = (uintptr_t)map->handle;

#ifdef	_MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_map_32_t request32;
		request32.offset = request.offset;
		request32.size = (uint32_t)request.size;
		request32.type = request.type;
		request32.flags = request.flags;
		request32.handle = request.handle;
		request32.mtrr = request.mtrr;
		DRM_COPYTO_WITH_RETURN((void *)data,
		    &request32, sizeof (request32));
	} else
#endif
		DRM_COPYTO_WITH_RETURN((void *)data,
		    &request, sizeof (request));

	return (0);
}

void
drm_rmmap(drm_device_t *dev, drm_local_map_t *map)
{
	DRM_SPINLOCK_ASSERT(&dev->dev_lock);

	TAILQ_REMOVE(&dev->maplist, map, link);

	switch (map->type) {
	case _DRM_REGISTERS:
		drm_ioremapfree(map);
		break;
		/* FALLTHROUGH */
	case _DRM_FRAME_BUFFER:
		drm_ioremapfree(map);
		break;
	case _DRM_SHM:
		ddi_umem_free(map->drm_umem_cookie);
		break;
	case _DRM_AGP:
		/*
		 * we mapped AGP aperture into kernel space in drm_addmap,
		 * here, unmap them and release kernel virtual address space
		 */
		gfxp_unmap_kernel_space(map->dev_addr, map->size);
		break;

	case _DRM_SCATTER_GATHER:
		break;
	case _DRM_CONSISTENT:
		break;
	default:
		break;
	}

	drm_free(map, sizeof (*map), DRM_MEM_MAPS);
}

/*
 * Remove a map private from list and deallocate resources if the
 * mapping isn't in use.
 */
/*ARGSUSED*/
int
drm_rmmap_ioctl(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_local_map_t *map;
	drm_map_t request;

#ifdef	_MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_map_32_t request32;
		DRM_COPYFROM_WITH_RETURN(&request32,
		    (void *)data, sizeof (drm_map_32_t));
		request.offset = request32.offset;
		request.size = request32.size;
		request.type = request32.type;
		request.flags = request32.flags;
		request.handle = request32.handle;
		request.mtrr = request32.mtrr;
	} else
#endif
		DRM_COPYFROM_WITH_RETURN(&request,
		    (void *)data, sizeof (request));

	DRM_LOCK();
	TAILQ_FOREACH(map, &dev->maplist, link) {
	if (((uintptr_t)map->handle == (request.handle & 0xffffffff)) &&
	    (map->flags & _DRM_REMOVABLE))
			break;
	}

	/* No match found. */
	if (map == NULL) {
		DRM_UNLOCK();
		return (EINVAL);
	}

	drm_rmmap(dev, map);
	DRM_UNLOCK();

	return (0);
}

/*ARGSUSED*/
static void
drm_cleanup_buf_error(drm_device_t *dev, drm_buf_entry_t *entry)
{
	int i;

	if (entry->seg_count) {
		for (i = 0; i < entry->seg_count; i++) {
			if (entry->seglist[i]) {
				DRM_ERROR(
				    "drm_cleanup_buf_error: not implemented");
			}
		}
		drm_free(entry->seglist,
		    entry->seg_count *
		    sizeof (*entry->seglist), DRM_MEM_SEGS);
		entry->seg_count = 0;
	}

	if (entry->buf_count) {
		for (i = 0; i < entry->buf_count; i++) {
			if (entry->buflist[i].dev_private) {
				drm_free(entry->buflist[i].dev_private,
				    entry->buflist[i].dev_priv_size,
				    DRM_MEM_BUFS);
			}
		}
		drm_free(entry->buflist,
		    entry->buf_count *
		    sizeof (*entry->buflist), DRM_MEM_BUFS);
		entry->buflist = NULL;
		entry->buf_count = 0;
	}
}

/*ARGSUSED*/
int
drm_markbufs(DRM_IOCTL_ARGS)
{
	DRM_DEBUG("drm_markbufs");
	return (EINVAL);
}

/*ARGSUSED*/
int
drm_infobufs(DRM_IOCTL_ARGS)
{
	DRM_DEBUG("drm_infobufs");
	return (EINVAL);
}

static int
drm_do_addbufs_agp(drm_device_t *dev, drm_buf_desc_t *request)
{
	drm_device_dma_t *dma = dev->dma;
	drm_buf_entry_t *entry;
	drm_buf_t **temp_buflist;
	drm_buf_t *buf;
	unsigned long offset;
	unsigned long agp_offset;
	int count;
	int order;
	int size;
	int alignment;
	int page_order;
	int byte_count;
	int i;

	if (!dma)
		return (EINVAL);

	count = request->count;
	order = drm_order(request->size);
	size = 1 << order;

	alignment  = (request->flags & _DRM_PAGE_ALIGN)
	    ? round_page(size) : size;
	page_order = order - PAGE_SHIFT > 0 ? order - PAGE_SHIFT : 0;

	byte_count = 0;
	agp_offset = dev->agp->base + request->agp_start;

	entry = &dma->bufs[order];

	/* No more than one allocation per order */
	if (entry->buf_count) {
		return (ENOMEM);
	}

	entry->buflist = drm_alloc(count * sizeof (*entry->buflist),
	    DRM_MEM_BUFS);
	if (!entry->buflist) {
		return (ENOMEM);
	}
	entry->buf_size = size;
	entry->page_order = page_order;

	offset = 0;

	while (entry->buf_count < count) {
		buf		= &entry->buflist[entry->buf_count];
		buf->idx	= dma->buf_count + entry->buf_count;
		buf->total	= alignment;
		buf->order	= order;
		buf->used	= 0;

		buf->offset	= (dma->byte_count + offset);
		buf->bus_address = agp_offset + offset;
		buf->address	= (void *)(agp_offset + offset);
		buf->next	= NULL;
		buf->pending	= 0;
		buf->filp	= NULL;

		buf->dev_priv_size = dev->driver->buf_priv_size;
		buf->dev_private = drm_alloc(buf->dev_priv_size, DRM_MEM_BUFS);
		if (buf->dev_private == NULL) {
			/* Set count correctly so we free the proper amount. */
			entry->buf_count = count;
			drm_cleanup_buf_error(dev, entry);
			return (ENOMEM);
		}

		offset += alignment;
		entry->buf_count++;
		byte_count += PAGE_SIZE << page_order;
	}

	temp_buflist = drm_alloc(
	    (dma->buf_count + entry->buf_count) * sizeof (*dma->buflist),
	    DRM_MEM_BUFS);

	if (temp_buflist == NULL) {
		/* Free the entry because it isn't valid */
		drm_cleanup_buf_error(dev, entry);
		DRM_ERROR(" temp_buflist is NULL");
		return (ENOMEM);
	}

	bcopy(temp_buflist, dma->buflist,
	    dma->buf_count * sizeof (*dma->buflist));
	kmem_free(dma->buflist, dma->buf_count *sizeof (*dma->buflist));
	dma->buflist = temp_buflist;

	for (i = 0; i < entry->buf_count; i++) {
		dma->buflist[i + dma->buf_count] = &entry->buflist[i];
	}

	dma->buf_count += entry->buf_count;
	dma->byte_count += byte_count;
	dma->seg_count += entry->seg_count;
	dma->page_count += byte_count >> PAGE_SHIFT;

	request->count = entry->buf_count;
	request->size = size;

	dma->flags = _DRM_DMA_USE_AGP;

	return (0);
}

static int
drm_do_addbufs_sg(drm_device_t *dev, drm_buf_desc_t *request)
{
	drm_device_dma_t *dma = dev->dma;
	drm_buf_entry_t *entry;
	drm_buf_t *buf;
	unsigned long offset;
	unsigned long agp_offset;
	int count;
	int order;
	int size;
	int alignment;
	int page_order;
	int byte_count;
	int i;
	drm_buf_t **temp_buflist;

	count = request->count;
	order = drm_order(request->size);
	size = 1 << order;

	alignment  = (request->flags & _DRM_PAGE_ALIGN)
	    ? round_page(size) : size;
	page_order = order - PAGE_SHIFT > 0 ? order - PAGE_SHIFT : 0;

	byte_count = 0;
	agp_offset = request->agp_start;
	entry = &dma->bufs[order];

	entry->buflist = drm_alloc(count * sizeof (*entry->buflist),
	    DRM_MEM_BUFS);
	if (entry->buflist == NULL)
		return (ENOMEM);

	entry->buf_size = size;
	entry->page_order = page_order;

	offset = 0;

	while (entry->buf_count < count) {
		buf		= &entry->buflist[entry->buf_count];
		buf->idx	= dma->buf_count + entry->buf_count;
		buf->total	= alignment;
		buf->order	= order;
		buf->used	= 0;

		buf->offset	= (dma->byte_count + offset);
		buf->bus_address = agp_offset + offset;
		buf->address = (void *)(agp_offset + offset + dev->sg->handle);
		buf->next	= NULL;
		buf->pending	= 0;
		buf->filp	= NULL;

		buf->dev_priv_size = dev->driver->buf_priv_size;
		buf->dev_private = drm_alloc(buf->dev_priv_size,
		    DRM_MEM_BUFS);
		if (buf->dev_private == NULL) {
			/* Set count correctly so we free the proper amount. */
			entry->buf_count = count;
			drm_cleanup_buf_error(dev, entry);
			return (ENOMEM);
		}

		offset += alignment;
		entry->buf_count++;
		byte_count += PAGE_SIZE << page_order;
	}

	temp_buflist = drm_realloc(dma->buflist,
	    dma->buf_count * sizeof (*dma->buflist),
	    (dma->buf_count + entry->buf_count)
	    * sizeof (*dma->buflist), DRM_MEM_BUFS);
	if (!temp_buflist) {
		drm_cleanup_buf_error(dev, entry);
		return (ENOMEM);
	}
	dma->buflist = temp_buflist;

	for (i = 0; i < entry->buf_count; i++) {
		dma->buflist[i + dma->buf_count] = &entry->buflist[i];
	}

	dma->buf_count += entry->buf_count;
	dma->byte_count += byte_count;
	request->count = entry->buf_count;
	request->size = size;
	dma->flags = _DRM_DMA_USE_SG;

	return (0);
}

int
drm_addbufs_agp(drm_device_t *dev, drm_buf_desc_t *request)
{
	int order, ret;

	DRM_SPINLOCK(&dev->dma_lock);

	if (request->count < 0 || request->count > 4096) {
		DRM_SPINLOCK(&dev->dma_lock);
		return (EINVAL);
	}

	order = drm_order(request->size);
	if (order < DRM_MIN_ORDER || order > DRM_MAX_ORDER) {
		DRM_SPINLOCK(&dev->dma_lock);
		return (EINVAL);
	}

	/* No more allocations after first buffer-using ioctl. */
	if (dev->buf_use != 0) {
		DRM_SPINUNLOCK(&dev->dma_lock);
		return (EBUSY);
	}
	/* No more than one allocation per order */
	if (dev->dma->bufs[order].buf_count != 0) {
		DRM_SPINUNLOCK(&dev->dma_lock);
		return (ENOMEM);
	}

	ret = drm_do_addbufs_agp(dev, request);

	DRM_SPINUNLOCK(&dev->dma_lock);

	return (ret);
}

int
drm_addbufs_sg(drm_device_t *dev, drm_buf_desc_t *request)
{
	int order, ret;

	DRM_SPINLOCK(&dev->dma_lock);

	if (request->count < 0 || request->count > 4096) {
		DRM_SPINUNLOCK(&dev->dma_lock);
		return (EINVAL);
	}

	order = drm_order(request->size);
	if (order < DRM_MIN_ORDER || order > DRM_MAX_ORDER) {
		DRM_SPINUNLOCK(&dev->dma_lock);
		return (EINVAL);
	}

	/* No more allocations after first buffer-using ioctl. */
	if (dev->buf_use != 0) {
		DRM_SPINUNLOCK(&dev->dma_lock);
		return (EBUSY);
	}

	/* No more than one allocation per order */
	if (dev->dma->bufs[order].buf_count != 0) {
		DRM_SPINUNLOCK(&dev->dma_lock);
		return (ENOMEM);
	}

	ret = drm_do_addbufs_sg(dev, request);
	DRM_SPINUNLOCK(&dev->dma_lock);
	return (ret);
}

/*ARGSUSED*/
int
drm_addbufs_ioctl(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_buf_desc_t request;
	int err;

#ifdef	_MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_buf_desc_32_t request32;
		DRM_COPYFROM_WITH_RETURN(&request32,
		    (void *)data, sizeof (request32));
		request.count = request32.count;
		request.size = request32.size;
		request.low_mark = request32.low_mark;
		request.high_mark = request32.high_mark;
		request.flags = request32.flags;
		request.agp_start = request32.agp_start;
	} else
#endif
		DRM_COPYFROM_WITH_RETURN(&request,
		    (void *)data, sizeof (request));

	if (request.flags & _DRM_AGP_BUFFER)
		err = drm_addbufs_agp(dev, &request);
	else if (request.flags & _DRM_SG_BUFFER)
		err = drm_addbufs_sg(dev, &request);

#ifdef	_MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_buf_desc_32_t request32;
		request32.count = request.count;
		request32.size = request.size;
		request32.low_mark = request.low_mark;
		request32.high_mark = request.high_mark;
		request32.flags = request.flags;
		request32.agp_start = (uint32_t)request.agp_start;
		DRM_COPYTO_WITH_RETURN((void *)data,
		    &request32, sizeof (request32));
	} else
#endif
		DRM_COPYTO_WITH_RETURN((void *)data,
		    &request, sizeof (request));

	return (err);
}

/*ARGSUSED*/
int
drm_freebufs(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_device_dma_t *dma = dev->dma;
	drm_buf_free_t request;
	int i;
	int idx;
	drm_buf_t *buf;
	int retcode = 0;

#ifdef	_MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_buf_free_32_t request32;
		DRM_COPYFROM_WITH_RETURN(&request32,
		    (void*)data, sizeof (request32));
		request.count = request32.count;
		request.list = (int *)(uintptr_t)request32.list;
	} else
#endif
		DRM_COPYFROM_WITH_RETURN(&request,
		    (void *)data, sizeof (request));

	for (i = 0; i < request.count; i++) {
		if (DRM_COPY_FROM_USER(&idx, &request.list[i], sizeof (idx))) {
			retcode = EFAULT;
			break;
		}
		if (idx < 0 || idx >= dma->buf_count) {
			DRM_ERROR("drm_freebufs: Index %d (of %d max)\n",
			    idx, dma->buf_count - 1);
			retcode = EINVAL;
			break;
		}
		buf = dma->buflist[idx];
		if (buf->filp != fpriv) {
			DRM_ERROR(
			    "drm_freebufs: process %d not owning the buffer.\n",
			    DRM_CURRENTPID);
			retcode = EINVAL;
			break;
		}
		drm_free_buffer(dev, buf);
	}

	return (retcode);
}

#ifdef _LP64
extern caddr_t smmap64(caddr_t, size_t, int, int, int, off_t);
#define	drm_smmap	smmap64
#else
#if defined(_SYSCALL32_IMPL) || defined(_ILP32)
extern caddr_t smmap32(caddr32_t, size32_t, int, int, int, off32_t);
#define	drm_smmap smmap32
#else
#error "No define for _LP64, _SYSCALL32_IMPL or _ILP32"
#endif
#endif


/*ARGSUSED*/
int
drm_mapbufs(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_buf_map_t request;
	const int zero = 0;
	unsigned long	vaddr;
	unsigned long address;
	drm_device_dma_t *dma = dev->dma;
	uint_t	size;
	uint_t	foff;
	int		ret_tmp;
	int 	i;

#ifdef	_MULTI_DATAMODEL
	drm_buf_map_32_t request32;
	drm_buf_pub_32_t	*list32;
	uint_t		address32;

	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		DRM_COPYFROM_WITH_RETURN(&request32,
		    (void *)data, sizeof (request32));
		request.count = request32.count;
		request.virtual = (void *)(uintptr_t)request32.virtual;
		request.list = (drm_buf_pub_t *)(uintptr_t)request32.list;
		request.fd = request32.fd;
	} else
#endif
		DRM_COPYFROM_WITH_RETURN(&request,
		    (void *)data, sizeof (request));

	dev->buf_use++;

	if (request.count < dma->buf_count)
		goto done;

	if ((dev->driver->use_agp && (dma->flags & _DRM_DMA_USE_AGP)) ||
	    (dev->driver->use_sg && (dma->flags & _DRM_DMA_USE_SG))) {
		drm_local_map_t *map = dev->agp_buffer_map;
		if (map == NULL)
			return (EINVAL);
		size = round_page(map->size);
		foff = (uintptr_t)map->handle;
	} else {
		size = round_page(dma->byte_count);
		foff = 0;
	}
	request.virtual = drm_smmap(NULL, size, PROT_READ | PROT_WRITE,
	    MAP_SHARED, request.fd, foff);
	if (request.virtual == NULL) {
		DRM_ERROR("drm_mapbufs: request.virtual is NULL");
		return (EINVAL);
	}

	vaddr = (unsigned long) request.virtual;
#ifdef	_MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		list32 = (drm_buf_pub_32_t *)(uintptr_t)request32.list;
		for (i = 0; i < dma->buf_count; i++) {
			if (DRM_COPY_TO_USER(&list32[i].idx,
			    &dma->buflist[i]->idx, sizeof (list32[0].idx))) {
				return (EFAULT);
			}
			if (DRM_COPY_TO_USER(&list32[i].total,
			    &dma->buflist[i]->total,
			    sizeof (list32[0].total))) {
				return (EFAULT);
			}
			if (DRM_COPY_TO_USER(&list32[i].used,
			    &zero, sizeof (zero))) {
				return (EFAULT);
			}
			address32 = vaddr + dma->buflist[i]->offset; /* *** */
			ret_tmp = DRM_COPY_TO_USER(&list32[i].address,
			    &address32, sizeof (list32[0].address));
			if (ret_tmp)
				return (EFAULT);
		}
		goto done;
	}
#endif

	ASSERT(ddi_model_convert_from(mode & FMODELS) != DDI_MODEL_ILP32);
	for (i = 0; i < dma->buf_count; i++) {
		if (DRM_COPY_TO_USER(&request.list[i].idx,
		    &dma->buflist[i]->idx, sizeof (request.list[0].idx))) {
			return (EFAULT);
		}
		if (DRM_COPY_TO_USER(&request.list[i].total,
		    &dma->buflist[i]->total, sizeof (request.list[0].total))) {
			return (EFAULT);
		}
		if (DRM_COPY_TO_USER(&request.list[i].used, &zero,
		    sizeof (zero))) {
			return (EFAULT);
		}
		address = vaddr + dma->buflist[i]->offset; /* *** */

		ret_tmp = DRM_COPY_TO_USER(&request.list[i].address,
		    &address, sizeof (address));
		if (ret_tmp) {
			return (EFAULT);
		}
	}

done:
#ifdef	_MULTI_DATAMODEL
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		request32.count = dma->buf_count;
		request32.virtual = (caddr32_t)(uintptr_t)request.virtual;
		DRM_COPYTO_WITH_RETURN((void *)data,
		    &request32, sizeof (request32));
	} else {
#endif
		request.count = dma->buf_count;
		DRM_COPYTO_WITH_RETURN((void *)data,
		    &request, sizeof (request));
#ifdef	_MULTI_DATAMODEL
	}
#endif
	return (0);
}
