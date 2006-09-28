/*
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * drm_bufs.h -- Generic buffer template -*- linux-c -*-
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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "drmP.h"

#define	PAGE_MASK	(PAGE_SIZE-1)
#define	round_page(x)	(((x) + PAGE_MASK) & ~PAGE_MASK)

/*
 * Compute order.  Can be made faster.
 */
int
drm_order(unsigned long size)
{
	int order;
	unsigned long tmp;

	for (order = 0, tmp = size; tmp >>= 1; ++order);

	if (size & ~(1 << order))
		++order;

	return (order);
}


int
drm_addmap(drm_device_t *dev, unsigned long long offset, unsigned long size,
    drm_map_type_t type, drm_map_flags_t flags, drm_local_map_t **map_ptr)
{
	drm_local_map_t *map;

	DRM_DEBUG("drm_addmap: offset = 0x%08llx, size = 0x%08lx, type = %d\n",
	    offset, size, type);

	if (!(dev->flags & (FREAD|FWRITE)))
		return (DRM_ERR(EACCES)); /* Require read/write */

	/*
	 * Only allow shared memory to be removable since we only keep enough
	 * book keeping information about shared memory to allow for removal
	 * when processes fork.
	 */
	if ((flags & _DRM_REMOVABLE) && type != _DRM_SHM)
		return (DRM_ERR(EINVAL));
	if ((offset & PAGE_MASK) || (size & PAGE_MASK))
		return (DRM_ERR(EINVAL));
	if (offset + size < offset)
		return (DRM_ERR(EINVAL));

	/*
	 * Check if this is just another version of a kernel-allocated map, and
	 * just hand that back if so.
	 */
	if (type == _DRM_REGISTERS || type == _DRM_FRAME_BUFFER ||
	    type == _DRM_SHM) {
		DRM_LOCK();
		TAILQ_FOREACH(map, &dev->maplist, link) {
			if (map->type == type &&
			    map->offset.off == (u_offset_t)offset) {
				map->size = size;
				DRM_DEBUG("drm_addmap: Found kernel map %d\n",
						type);
				goto done;
			}
		}
		DRM_UNLOCK();
	}

	/*
	 * Allocate a new map structure, fill it in, and do any type-specific
	 * initialization necessary.
	 */
	map = drm_alloc(sizeof (*map), DRM_MEM_MAPS);
	if (!map)
		return (DRM_ERR(ENOMEM));

	map->offset.off = (u_offset_t)offset;
	map->size = size;
	map->type = type;
	map->flags = flags;

	DRM_DEBUG("drm_addmap: map->type = %x", map->type);
	DRM_DEBUG("drm_addmap: map->size = %lx", map->size);
	DRM_DEBUG("drm_addmap: map->offset.off = %llx", map->offset.off);
	switch (map->type) {
	case _DRM_REGISTERS:
		DRM_DEBUG("drm_addmap: map the Registers");
		(void) drm_ioremap(dev, map);
		if (!(map->flags & _DRM_WRITE_COMBINING))
			break;
		/* FALLTHROUGH */
	case _DRM_FRAME_BUFFER:
		(void) drm_ioremap(dev, map);
		break;
	case _DRM_SHM:
		map->handle = ddi_umem_alloc(map->size, DDI_UMEM_NOSLEEP,
				&map->drm_umem_cookie);
		DRM_DEBUG("drm_addmap: size=0x%lx drm_order(size)=%d "
			"handle=0x%p\n",
			(unsigned long) map->size,
			drm_order(map->size), map->handle);
		if (!map->handle) {
			DRM_ERROR("drm_addmap: ddi_umem_alloc failed");
			ddi_umem_free(map->drm_umem_cookie);
			drm_free(map, sizeof (*map), DRM_MEM_MAPS);
			return (DRM_ERR(ENOMEM));
		}
		/*
		 * record only low 32-bit of this handle, since 32-bit user
		 * app is incapable of passing in 64bit offset when doing mmap.
		 */
		map->offset.ptr = map->handle;
		map->offset.off &= 0xffffffffUL;
		DRM_DEBUG("drm_addmap: offset=0x%llx", map->offset);
		if (map->flags & _DRM_CONTAINS_LOCK) {
			/* Prevent a 2nd X Server from creating a 2nd lock */
			DRM_LOCK();
			if (dev->lock.hw_lock != NULL) {
				DRM_UNLOCK();
				ddi_umem_free(map->drm_umem_cookie);
				drm_free(map, sizeof (*map), DRM_MEM_MAPS);
				return (DRM_ERR(EBUSY));
			}
			DRM_DEBUG("drm_addmap: map shm to hw_lock");
			dev->lock.hw_lock = map->handle; /* Pointer to lock */
			DRM_UNLOCK();
		}
		break;
	case _DRM_SCATTER_GATHER:
		if (!dev->sg) {
			drm_free(map, sizeof (*map), DRM_MEM_MAPS);
			return (DRM_ERR(EINVAL));
		}
		map->offset.off = map->offset.off + dev->sg->handle;
		map->drm_umem_cookie = dev->sg->sg_umem_cookie;
		break;
	case _DRM_CONSISTENT:
		break;
	case _DRM_AGP:
		break;
	case _DRM_AGP_UMEM:
		map->offset.off += dev->agp->base;
		break;
	default:
		drm_free(map, sizeof (*map), DRM_MEM_MAPS);
		return (DRM_ERR(EINVAL));
	}

	DRM_LOCK();
	TAILQ_INSERT_TAIL(&dev->maplist, map, link);

done:
	/* Jumped to, with lock held, when a kernel map is found. */
	DRM_UNLOCK();

	DRM_DEBUG("drm_addmap: Added map %d 0x%llx/0x%x\n",
		map->type, map->offset, map->size);

	*map_ptr = map;
	TAILQ_FOREACH(map, &dev->maplist, link) {
		DRM_DEBUG("type=%x, offset=%llx, size=%x",
			map->type, map->offset, map->size);
	}

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

	if (!(dev->flags & (FREAD|FWRITE)))
		return (DRM_ERR(EACCES)); /* Require read/write */

	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_map32_t request32;
		DRM_COPY_FROM_USER_IOCTL(request32,
			(drm_map32_t *)data,
			sizeof (drm_map32_t));
		request.offset = request32.offset;
		request.size = request32.size;
		request.type = request32.type;
		request.flags = request32.flags;
		request.handle = request32.handle;
		request.mtrr = request32.mtrr;
	} else
		DRM_COPY_FROM_USER_IOCTL(request, (drm_map_t *)data,
			sizeof (drm_map_t));

	DRM_DEBUG("drm_addmap: request.offset=%llx, request.size=%lx,"
	    "request.type=%x", request.offset, request.size, request.type);
	err = drm_addmap(dev, request.offset, request.size, request.type,
	    request.flags, &map);

	if (err != 0)
		return (err);

	request.offset = map->offset.off;
	request.size = map->size;
	request.type = map->type;
	request.flags = map->flags;
	request.mtrr   = map->mtrr;
	request.handle = (unsigned long long)(uintptr_t)map->handle;

	if (request.type != _DRM_SHM) {
		request.handle = request.offset;
	}

	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_map32_t request32;
		request32.offset = request.offset;
		request32.size = request.size;
		request32.type = request.type;
		request32.flags = request.flags;
		request32.handle = request.handle;
		request32.mtrr = request.mtrr;
		DRM_COPY_TO_USER_IOCTL((drm_map32_t *)data,
			request32,
			sizeof (drm_map32_t));
	} else
		DRM_COPY_TO_USER_IOCTL((drm_map_t *)data, request,
		    sizeof (drm_map_t));

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
 *  Remove a map private from list and deallocate resources if the mapping
 * isn't in use.
 */
/*ARGSUSED*/
int
drm_rmmap_ioctl(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_local_map_t *map;
	drm_map_t request;

	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_map32_t request32;
		DRM_COPY_FROM_USER_IOCTL(request32,
			(drm_map32_t *)data,
			sizeof (drm_map32_t));
		request.offset = request32.offset;
		request.size = request32.size;
		request.type = request32.type;
		request.flags = request32.flags;
		request.handle = request32.handle;
		request.mtrr = request32.mtrr;
	} else
		DRM_COPY_FROM_USER_IOCTL(request, (drm_map_t *)data,
		    sizeof (request));

	DRM_LOCK();
	TAILQ_FOREACH(map, &dev->maplist, link) {
		if (((unsigned long long)(uintptr_t)map->handle ==
			request.handle) &&
			(map->flags & _DRM_REMOVABLE))
			break;
	}

	/* No match found. */
	if (map == NULL) {
		DRM_UNLOCK();
		return (DRM_ERR(EINVAL));
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
		entry->buf_count = 0;
	}
}

/*ARGSUSED*/
int
drm_markbufs(DRM_IOCTL_ARGS)
{
	DRM_DEBUG("drm_markbufs");
	return (DRM_ERR(EINVAL));
}

/*ARGSUSED*/
int
drm_infobufs(DRM_IOCTL_ARGS)
{
	DRM_DEBUG("drm_infobufs");
	return (DRM_ERR(EINVAL));
}

static int
drm_do_addbufs_agp(drm_device_t *dev, drm_buf_desc_t *request)
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
	int total;
	int byte_count;
	int i;
	drm_buf_t **temp_buflist;

	if (!dma)
		return (DRM_ERR(EINVAL));

	count = request->count;
	order = drm_order(request->size);
	size = 1 << order;

	alignment  = (request->flags & _DRM_PAGE_ALIGN)
		? round_page(size) : size;
	page_order = order - PAGE_SHIFT > 0 ? order - PAGE_SHIFT : 0;
	total = PAGE_SIZE << page_order;

	byte_count = 0;
	agp_offset = dev->agp->base + request->agp_start;

	DRM_DEBUG("drm_do_addbufs_agp: count:      %d\n",  count);
	DRM_DEBUG("drm_do_addbufs_agp: order:      %d\n",  order);
	DRM_DEBUG("drm_do_addbufs_agp: size:       %d\n",  size);
	DRM_DEBUG("drm_do_addbufs_agp: agp_offset: 0x%lx\n", agp_offset);
	DRM_DEBUG("drm_do_addbufs_agp: alignment:  %d\n",  alignment);
	DRM_DEBUG("drm_do_addbufs_agp: page_order: %d\n",  page_order);
	DRM_DEBUG("drm_do_addbufs_agp: total:      %d\n",  total);

	entry = &dma->bufs[order];

	entry->buflist = drm_alloc(count * sizeof (*entry->buflist),
	    DRM_MEM_BUFS);
	if (!entry->buflist) {
		return (DRM_ERR(ENOMEM));
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

		buf->dev_priv_size = dev->dev_priv_size;
		buf->dev_private = drm_alloc(count * sizeof (*entry->buflist),
				DRM_MEM_BUFS);
		if (buf->dev_private == NULL) {
			/* Set count correctly so we free the proper amount. */
			entry->buf_count = count;
			drm_cleanup_buf_error(dev, entry);
			return (DRM_ERR(ENOMEM));
		}

		offset += alignment;
		entry->buf_count++;
		byte_count += PAGE_SIZE << page_order;
	}

	DRM_DEBUG("drm_do_addbufs_agp: byte_count: %d\n", byte_count);

	temp_buflist = drm_alloc(
	    (dma->buf_count + entry->buf_count) * sizeof (*dma->buflist),
	    DRM_MEM_BUFS);

	if (temp_buflist == NULL) {
		/* Free the entry because it isn't valid */
		drm_cleanup_buf_error(dev, entry);
		DRM_ERROR(" temp_buflist is NULL");
		return (DRM_ERR(ENOMEM));
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

	DRM_DEBUG("drm_do_addbufs_agp: dma->buf_count : %d\n", dma->buf_count);
	DRM_DEBUG("drm_do_addbufs_agp: entry->buf_count : %d\n",
	    entry->buf_count);

	request->count = entry->buf_count;
	request->size = size;

	dma->flags = _DRM_DMA_USE_AGP;

	DRM_DEBUG("drm_do_addbufs_agp: add bufs succesfful.");
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
	int total;
	int byte_count;
	int i;
	drm_buf_t **temp_buflist;

	count = request->count;
	order = drm_order(request->size);
	size = 1 << order;

	alignment  = (request->flags & _DRM_PAGE_ALIGN)
		? round_page(size) : size;
	page_order = order - PAGE_SHIFT > 0 ? order - PAGE_SHIFT : 0;
	total = PAGE_SIZE << page_order;

	byte_count = 0;
	agp_offset = request->agp_start;

	DRM_DEBUG("count:      %d\n",  count);
	DRM_DEBUG("order:      %d\n",  order);
	DRM_DEBUG("size:       %d\n",  size);
	DRM_DEBUG("agp_offset: %ld\n", agp_offset);
	DRM_DEBUG("alignment:  %d\n",  alignment);
	DRM_DEBUG("page_order: %d\n",  page_order);
	DRM_DEBUG("total:      %d\n",  total);

	entry = &dma->bufs[order];

	entry->buflist = drm_alloc(count * sizeof (*entry->buflist),
	    DRM_MEM_BUFS);
	if (entry->buflist == NULL)
		return (DRM_ERR(ENOMEM));

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

		buf->dev_priv_size = dev->dev_priv_size;
		buf->dev_private = drm_alloc(buf->dev_priv_size,
		    DRM_MEM_BUFS);
		if (buf->dev_private == NULL) {
			/* Set count correctly so we free the proper amount. */
			entry->buf_count = count;
			drm_cleanup_buf_error(dev, entry);
			return (DRM_ERR(ENOMEM));
		}

		DRM_DEBUG("drm_do_addbufs_sg: buffer %d @ %p\n",
		    entry->buf_count, buf->address);
		offset += alignment;
		entry->buf_count++;
		byte_count += PAGE_SIZE << page_order;
	}
	DRM_DEBUG("drm_do_addbufs_sg: byte_count %d\n", byte_count);

	temp_buflist = drm_realloc(dma->buflist,
	    dma->buf_count * sizeof (*dma->buflist),
	    (dma->buf_count + entry->buf_count)
	    * sizeof (*dma->buflist), DRM_MEM_BUFS);
	if (!temp_buflist) {
		drm_cleanup_buf_error(dev, entry);
		return (DRM_ERR(ENOMEM));
	}
	dma->buflist = temp_buflist;

	for (i = 0; i < entry->buf_count; i++) {
		dma->buflist[i + dma->buf_count] = &entry->buflist[i];
	}

	dma->buf_count += entry->buf_count;
	dma->byte_count += byte_count;

	DRM_DEBUG("drm_do_addbufs_sg: dma->buf_count: %d\n", dma->buf_count);
	DRM_DEBUG("drm_do_addbufs_sg: entry->buf_count: %d\n",
	    entry->buf_count);
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
		return (DRM_ERR(EINVAL));
	}

	order = drm_order(request->size);
	if (order < DRM_MIN_ORDER || order > DRM_MAX_ORDER) {
		DRM_SPINLOCK(&dev->dma_lock);
		return (DRM_ERR(EINVAL));
	}

	/* No more allocations after first buffer-using ioctl. */
	if (dev->buf_use != 0) {
		DRM_SPINUNLOCK(&dev->dma_lock);
		return (DRM_ERR(EBUSY));
	}
	/* No more than one allocation per order */
	if (dev->dma->bufs[order].buf_count != 0) {
		DRM_SPINUNLOCK(&dev->dma_lock);
		return (DRM_ERR(ENOMEM));
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
		return (DRM_ERR(EINVAL));
	}

	order = drm_order(request->size);
	if (order < DRM_MIN_ORDER || order > DRM_MAX_ORDER) {
		DRM_SPINUNLOCK(&dev->dma_lock);
		return (DRM_ERR(EINVAL));
	}

	/* No more allocations after first buffer-using ioctl. */
	if (dev->buf_use != 0) {
		DRM_SPINUNLOCK(&dev->dma_lock);
		return (DRM_ERR(EBUSY));
	}

	/* No more than one allocation per order */
	if (dev->dma->bufs[order].buf_count != 0) {
		DRM_SPINUNLOCK(&dev->dma_lock);
		return (DRM_ERR(ENOMEM));
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

	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_buf_desc32_t request32;
		DRM_COPY_FROM_USER_IOCTL(request32,
			(drm_buf_desc32_t *)data,
			sizeof (drm_buf_desc32_t));
		request.count = request32.count;
		request.size = request32.size;
		request.low_mark = request32.low_mark;
		request.high_mark = request32.high_mark;
		request.flags = request32.flags;
		request.agp_start = request32.agp_start;
	} else
		DRM_COPY_FROM_USER_IOCTL(request, (drm_buf_desc_t *)data,
			sizeof (request));

	if (request.flags & _DRM_AGP_BUFFER)
		err = drm_addbufs_agp(dev, &request);
	else if (request.flags & _DRM_SG_BUFFER)
		err = drm_addbufs_sg(dev, &request);

	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_buf_desc32_t request32;
		request32.count = request.count;
		request32.size = request.size;
		request32.low_mark = request.low_mark;
		request32.high_mark = request.high_mark;
		request32.flags = request.flags;
		request32.agp_start = request.agp_start;
		DRM_COPY_TO_USER_IOCTL((drm_buf_desc32_t *)data,
			request32,
			sizeof (drm_buf_desc32_t));
	} else
		DRM_COPY_TO_USER_IOCTL((drm_buf_desc_t *)data, request,
			sizeof (request));

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

	DRM_DEBUG("drm_freebufs: ");
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_buf_free32_t request32;
		DRM_COPY_FROM_USER_IOCTL(request32,
			(drm_buf_free32_t *)data,
			sizeof (drm_buf_free32_t));
		request.count = request32.count;
		request.list = (int __user *)(uintptr_t)request32.list;
	} else
		DRM_COPY_FROM_USER_IOCTL(request, (drm_buf_free_t *)data,
			sizeof (request));

	for (i = 0; i < request.count; i++) {
		if (DRM_COPY_FROM_USER(&idx, &request.list[i], sizeof (idx))) {
			retcode = DRM_ERR(EFAULT);
			break;
		}
		if (idx < 0 || idx >= dma->buf_count) {
			DRM_ERROR("drm_freebufs: Index %d (of %d max)\n",
			    idx, dma->buf_count - 1);
			retcode = DRM_ERR(EINVAL);
			break;
		}
		buf = dma->buflist[idx];
		if (buf->filp != filp) {
			DRM_ERROR(
			    "drm_freebufs: process %d not owning the buffer.\n",
			    DRM_CURRENTPID);
			retcode = DRM_ERR(EINVAL);
			break;
		}
		drm_free_buffer(dev, buf);
	}

	return (retcode);
}

/*ARGSUSED*/
int
drm_mapbufs(DRM_IOCTL_ARGS)
{
	DRM_DEVICE;
	drm_buf_map_t request;
	int i;
	int retcode = 0;
	const int zero = 0;
	unsigned long vaddr;
	unsigned long address;
	drm_device_dma_t *dma = dev->dma;
	int ret_tmp;

	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_buf_map32_t request32;
		DRM_COPY_FROM_USER_IOCTL(request32,
			(drm_buf_map32_t *)data,
			sizeof (drm_buf_map32_t));
		request.count = request32.count;
		request.virtual = (void __user *)(uintptr_t)request32.virtual;
		request.list = (drm_buf_pub_t __user *)
			(uintptr_t)request32.list;
	} else
		DRM_COPY_FROM_USER_IOCTL(request, (drm_buf_map_t *)data,
			sizeof (request));

	dev->buf_use++;

	if (request.count < dma->buf_count)
		goto done;

	if (request.virtual == NULL) {
		DRM_ERROR("drm_mapbufs: request.virtual is NULL");
		return (DRM_ERR(EINVAL));
	}
	vaddr = (unsigned long) request.virtual;

	for (i = 0; i < dma->buf_count; i++) {
		if (DRM_COPY_TO_USER(&request.list[i].idx,
		    &dma->buflist[i]->idx, sizeof (request.list[0].idx))) {
			retcode = EFAULT;
			goto done;
		}
		if (DRM_COPY_TO_USER(&request.list[i].total,
		    &dma->buflist[i]->total, sizeof (request.list[0].total))) {
			retcode = EFAULT;
			goto done;
		}
		if (DRM_COPY_TO_USER(&request.list[i].used, &zero,
		    sizeof (zero))) {
			retcode = EFAULT;
			goto done;
		}
		address = vaddr + dma->buflist[i]->offset; /* *** */

		if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
			caddr32_t address32;
			address32 = address;
			ret_tmp = DRM_COPY_TO_USER(&request.list[i].address,
				&address32,
				sizeof (caddr32_t));
		} else
			ret_tmp = DRM_COPY_TO_USER(&request.list[i].address,
				&address, sizeof (address));

		if (ret_tmp) {
			retcode = EFAULT;
			goto done;
		}
	}

done:
	request.count = dma->buf_count;
	DRM_DEBUG("drm_mapbufs: %d buffers, retcode = %d\n",
	    request.count, retcode);
	if (ddi_model_convert_from(mode & FMODELS) == DDI_MODEL_ILP32) {
		drm_buf_map32_t request32;
		request32.count = request.count;
		request32.virtual = (caddr32_t)(uintptr_t)request.virtual;
		request32.list = (caddr32_t)(uintptr_t)request.list;
		DRM_COPY_TO_USER_IOCTL((drm_buf_map32_t *)data,
			request32, sizeof (drm_buf_map32_t));
	} else
		DRM_COPY_TO_USER_IOCTL((drm_buf_map_t *)data, request,
			sizeof (request));

	return (DRM_ERR(retcode));
}
