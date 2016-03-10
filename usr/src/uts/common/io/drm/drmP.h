/*
 * drmP.h -- Private header for Direct Rendering Manager -*- linux-c -*-
 * Created: Mon Jan  4 10:05:05 1999 by faith@precisioninsight.com
 */
/*
 * Copyright 1999 Precision Insight, Inc., Cedar Park, Texas.
 * Copyright 2000 VA Linux Systems, Inc., Sunnyvale, California.
 * Copyright (c) 2009, Intel Corporation.
 * All rights reserved.
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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_DRMP_H
#define	_DRMP_H

#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <sys/cmn_err.h>
#include <sys/varargs.h>
#include <sys/pci.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunldi.h>
#include <sys/pmem.h>
#include <sys/agpgart.h>
#include <sys/time.h>
#include <sys/sysmacros.h>
#include "drm_atomic.h"
#include "drm.h"
#include "queue.h"
#include "drm_linux_list.h"

#ifndef __inline__
#define	__inline__	inline
#endif

#if !defined(__FUNCTION__)
#if defined(C99)
#define	__FUNCTION__ __func__
#else
#define	__FUNCTION__	" "
#endif
#endif

/* DRM space units */
#define	DRM_PAGE_SHIFT			PAGESHIFT
#define	DRM_PAGE_SIZE			(1 << DRM_PAGE_SHIFT)
#define	DRM_PAGE_OFFSET			(DRM_PAGE_SIZE - 1)
#define	DRM_PAGE_MASK			~(DRM_PAGE_SIZE - 1)
#define	DRM_MB2PAGES(x)			((x) << 8)
#define	DRM_PAGES2BYTES(x)		((x) << DRM_PAGE_SHIFT)
#define	DRM_BYTES2PAGES(x)		((x) >> DRM_PAGE_SHIFT)
#define	DRM_PAGES2KB(x)			((x) << 2)
#define	DRM_ALIGNED(offset)		(((offset) & DRM_PAGE_OFFSET) == 0)

#define	PAGE_SHIFT			DRM_PAGE_SHIFT
#define	PAGE_SIZE			DRM_PAGE_SIZE

#define	DRM_MAX_INSTANCES	8
#define	DRM_DEVNODE		"drm"
#define	DRM_UNOPENED		0
#define	DRM_OPENED		1

#define	DRM_HASH_SIZE		16 /* Size of key hash table */
#define	DRM_KERNEL_CONTEXT	0  /* Change drm_resctx if changed */
#define	DRM_RESERVED_CONTEXTS	1  /* Change drm_resctx if changed */

#define	DRM_MEM_DMA	   0
#define	DRM_MEM_SAREA	   1
#define	DRM_MEM_DRIVER	   2
#define	DRM_MEM_MAGIC	   3
#define	DRM_MEM_IOCTLS	   4
#define	DRM_MEM_MAPS	   5
#define	DRM_MEM_BUFS	   6
#define	DRM_MEM_SEGS	   7
#define	DRM_MEM_PAGES	   8
#define	DRM_MEM_FILES	  9
#define	DRM_MEM_QUEUES	  10
#define	DRM_MEM_CMDS	  11
#define	DRM_MEM_MAPPINGS  12
#define	DRM_MEM_BUFLISTS  13
#define	DRM_MEM_DRMLISTS  14
#define	DRM_MEM_TOTALDRM  15
#define	DRM_MEM_BOUNDDRM  16
#define	DRM_MEM_CTXBITMAP 17
#define	DRM_MEM_STUB	  18
#define	DRM_MEM_SGLISTS	  19
#define	DRM_MEM_AGPLISTS  20
#define	DRM_MEM_CTXLIST   21
#define	DRM_MEM_MM		22
#define	DRM_MEM_HASHTAB		23
#define	DRM_MEM_OBJECTS		24

#define	DRM_MAX_CTXBITMAP (PAGE_SIZE * 8)
#define	DRM_MAP_HASH_OFFSET 0x10000000
#define	DRM_MAP_HASH_ORDER 12
#define	DRM_OBJECT_HASH_ORDER 12
#define	DRM_FILE_PAGE_OFFSET_START ((0xFFFFFFFFUL >> PAGE_SHIFT) + 1)
#define	DRM_FILE_PAGE_OFFSET_SIZE ((0xFFFFFFFFUL >> PAGE_SHIFT) * 16)
#define	DRM_MM_INIT_MAX_PAGES 256


/* Internal types and structures */
#define	DRM_ARRAY_SIZE(x) (sizeof (x) / sizeof (x[0]))
#define	DRM_MIN(a, b) ((a) < (b) ? (a) : (b))
#define	DRM_MAX(a, b) ((a) > (b) ? (a) : (b))

#define	DRM_IF_VERSION(maj, min) (maj << 16 | min)

#define	__OS_HAS_AGP	1

#define	DRM_DEV_MOD	(S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP)
#define	DRM_DEV_UID	0
#define	DRM_DEV_GID	0

#define	DRM_CURRENTPID		ddi_get_pid()
#define	DRM_SPINLOCK(l)		mutex_enter(l)
#define	DRM_SPINUNLOCK(u)	mutex_exit(u)
#define	DRM_SPINLOCK_ASSERT(l)
#define	DRM_LOCK()	mutex_enter(&dev->dev_lock)
#define	DRM_UNLOCK()	mutex_exit(&dev->dev_lock)
#define	DRM_LOCK_OWNED()	ASSERT(mutex_owned(&dev->dev_lock))
#define	spin_lock_irqsave(l, flag)		mutex_enter(l)
#define	spin_unlock_irqrestore(u, flag) mutex_exit(u)
#define	spin_lock(l)	mutex_enter(l)
#define	spin_unlock(u)	mutex_exit(u)


#define	DRM_UDELAY(sec)  delay(drv_usectohz(sec *1000))
#define	DRM_MEMORYBARRIER()

typedef	struct drm_file		drm_file_t;
typedef struct drm_device	drm_device_t;
typedef struct drm_driver_info drm_driver_t;

#define	DRM_DEVICE	drm_device_t *dev = dev1
#define	DRM_IOCTL_ARGS	\
	drm_device_t *dev1, intptr_t data, drm_file_t *fpriv, int mode

#define	DRM_COPYFROM_WITH_RETURN(dest, src, size)	\
	if (ddi_copyin((src), (dest), (size), 0)) {	\
		DRM_ERROR("%s: copy from user failed", __func__);	\
		return (EFAULT);	\
	}

#define	DRM_COPYTO_WITH_RETURN(dest, src, size)	\
	if (ddi_copyout((src), (dest), (size), 0)) {	\
		DRM_ERROR("%s: copy to user failed", __func__);	\
		return (EFAULT);	\
	}

#define	DRM_COPY_FROM_USER(dest, src, size) \
	ddi_copyin((src), (dest), (size), 0) /* flag for src */

#define	DRM_COPY_TO_USER(dest, src, size) \
	ddi_copyout((src), (dest), (size), 0) /* flags for dest */

#define	DRM_COPY_FROM_USER_UNCHECKED(arg1, arg2, arg3)  \
	ddi_copyin((arg2), (arg1), (arg3), 0)

#define	DRM_COPY_TO_USER_UNCHECKED(arg1, arg2, arg3)        \
	ddi_copyout((arg2), arg1, arg3, 0)

#define	DRM_READ8(map, offset) \
	*(volatile uint8_t *)((uintptr_t)((map)->dev_addr) + (offset))
#define	DRM_READ16(map, offset) \
	*(volatile uint16_t *)((uintptr_t)((map)->dev_addr) + (offset))
#define	DRM_READ32(map, offset) \
	*(volatile uint32_t *)((uintptr_t)((map)->dev_addr) + (offset))
#define	DRM_WRITE8(map, offset, val) \
	*(volatile uint8_t *)((uintptr_t)((map)->dev_addr) + (offset)) = (val)
#define	DRM_WRITE16(map, offset, val) \
	*(volatile uint16_t *)((uintptr_t)((map)->dev_addr) + (offset)) = (val)
#define	DRM_WRITE32(map, offset, val) \
	*(volatile uint32_t *)((uintptr_t)((map)->dev_addr) + (offset)) = (val)

typedef struct drm_wait_queue {
	kcondvar_t	cv;
	kmutex_t	lock;
}wait_queue_head_t;

#define	DRM_INIT_WAITQUEUE(q, pri)	\
{ \
	mutex_init(&(q)->lock, NULL, MUTEX_DRIVER, pri); \
	cv_init(&(q)->cv, NULL, CV_DRIVER, NULL);	\
}

#define	DRM_FINI_WAITQUEUE(q)	\
{ \
	mutex_destroy(&(q)->lock);	\
	cv_destroy(&(q)->cv);	\
}

#define	DRM_WAKEUP(q)	\
{ \
	mutex_enter(&(q)->lock); \
	cv_broadcast(&(q)->cv);	\
	mutex_exit(&(q)->lock);	\
}

#define	jiffies	ddi_get_lbolt()

#define	DRM_WAIT_ON(ret, q, timeout, condition)  			\
	mutex_enter(&(q)->lock);					\
	while (!(condition)) {						\
		ret = cv_reltimedwait_sig(&(q)->cv, &(q)->lock, timeout,\
		    TR_CLOCK_TICK);					\
		if (ret == -1) {					\
			ret = EBUSY;					\
			break;						\
		} else if (ret == 0) {					\
			ret = EINTR;  					\
			break; 						\
		} else { 						\
			ret = 0; 					\
		} 							\
	} 								\
	mutex_exit(&(q)->lock);

#define	DRM_WAIT(ret, q, condition)  \
mutex_enter(&(q)->lock);	\
if (!(condition)) {	\
	ret = cv_timedwait_sig(&(q)->cv, &(q)->lock, jiffies + 30 * DRM_HZ); \
	if (ret == -1) {				\
		/* gfx maybe hang */	\
		if (!(condition)) 	\
			ret = -2;	\
	} else {	\
		ret = 0;	\
	}	\
} \
mutex_exit(&(q)->lock);


#define	DRM_GETSAREA()  					\
{                                				\
	drm_local_map_t *map;					\
	DRM_SPINLOCK_ASSERT(&dev->dev_lock);			\
	TAILQ_FOREACH(map, &dev->maplist, link) {		\
		if (map->type == _DRM_SHM &&			\
			map->flags & _DRM_CONTAINS_LOCK) {	\
			dev_priv->sarea = map;			\
			break;					\
		}						\
	}							\
}

#define	LOCK_TEST_WITH_RETURN(dev, fpriv)				\
	if (!_DRM_LOCK_IS_HELD(dev->lock.hw_lock->lock) ||		\
	    dev->lock.filp != fpriv) {					\
		DRM_DEBUG("%s called without lock held", __func__);	\
		return (EINVAL);	\
	}

#define	DRM_IRQ_ARGS	caddr_t arg
#define	IRQ_HANDLED		DDI_INTR_CLAIMED
#define	IRQ_NONE		DDI_INTR_UNCLAIMED

enum {
	DRM_IS_NOT_AGP,
	DRM_IS_AGP,
	DRM_MIGHT_BE_AGP
};

/* Capabilities taken from src/sys/dev/pci/pcireg.h. */
#ifndef PCIY_AGP
#define	PCIY_AGP		0x02
#endif

#ifndef PCIY_EXPRESS
#define	PCIY_EXPRESS		0x10
#endif

#define	PAGE_ALIGN(addr)	(((addr) + DRM_PAGE_SIZE - 1) & DRM_PAGE_MASK)
#define	DRM_SUSER(p)		(crgetsgid(p) == 0 || crgetsuid(p) == 0)

#define	DRM_GEM_OBJIDR_HASHNODE	1024
#define	idr_list_for_each(entry, head) \
	for (int key = 0; key < DRM_GEM_OBJIDR_HASHNODE; key++) \
		list_for_each(entry, &(head)->next[key])

/*
 * wait for 400 milliseconds
 */
#define	DRM_HZ			drv_usectohz(400000)

typedef unsigned long dma_addr_t;
typedef uint64_t	u64;
typedef uint32_t	u32;
typedef uint16_t	u16;
typedef uint8_t		u8;
typedef uint_t		irqreturn_t;

#define	DRM_SUPPORT	1
#define	DRM_UNSUPPORT	0

#define	__OS_HAS_AGP	1

typedef struct drm_pci_id_list
{
	int vendor;
	int device;
	long driver_private;
	char *name;
} drm_pci_id_list_t;

#define	DRM_AUTH	0x1
#define	DRM_MASTER	0x2
#define	DRM_ROOT_ONLY	0x4
typedef int drm_ioctl_t(DRM_IOCTL_ARGS);
typedef struct drm_ioctl_desc {
	int	(*func)(DRM_IOCTL_ARGS);
	int	flags;
} drm_ioctl_desc_t;

typedef struct drm_magic_entry {
	drm_magic_t		magic;
	struct drm_file		*priv;
	struct drm_magic_entry	*next;
} drm_magic_entry_t;

typedef struct drm_magic_head {
	struct drm_magic_entry *head;
	struct drm_magic_entry *tail;
} drm_magic_head_t;

typedef struct drm_buf {
	int		idx;		/* Index into master buflist */
	int		total;		/* Buffer size */
	int		order;		/* log-base-2(total) */
	int		used;		/* Amount of buffer in use (for DMA) */
	unsigned long	offset;		/* Byte offset (used internally) */
	void		*address;	/* Address of buffer */
	unsigned long	bus_address;	/* Bus address of buffer */
	struct drm_buf	*next;		/* Kernel-only: used for free list */
	volatile int	pending;	/* On hardware DMA queue */
	drm_file_t		*filp;
				/* Uniq. identifier of holding process */
	int		context;	/* Kernel queue for this buffer */
	enum {
		DRM_LIST_NONE	 = 0,
		DRM_LIST_FREE	 = 1,
		DRM_LIST_WAIT	 = 2,
		DRM_LIST_PEND	 = 3,
		DRM_LIST_PRIO	 = 4,
		DRM_LIST_RECLAIM = 5
	}		list;		/* Which list we're on */

	int		dev_priv_size;	/* Size of buffer private stoarge */
	void		*dev_private;	/* Per-buffer private storage */
} drm_buf_t;

typedef struct drm_freelist {
	int		  initialized;	/* Freelist in use		*/
	uint32_t	  count;	/* Number of free buffers	*/
	drm_buf_t	  *next;	/* End pointer			*/

	int		  low_mark;	/* Low water mark		*/
	int		  high_mark;	/* High water mark		*/
} drm_freelist_t;

typedef struct drm_buf_entry {
	int		  buf_size;
	int		  buf_count;
	drm_buf_t	  *buflist;
	int		  seg_count;
	int		  page_order;

	uint32_t	  *seglist;
	unsigned long	  *seglist_bus;

	drm_freelist_t	  freelist;
} drm_buf_entry_t;

typedef TAILQ_HEAD(drm_file_list, drm_file) drm_file_list_t;

/* BEGIN CSTYLED */
typedef struct drm_local_map {
	unsigned long	offset;  /*  Physical address (0 for SAREA)	*/
	unsigned long	size;	 /* Physical size (bytes)		*/
	drm_map_type_t	type;	 /* Type of memory mapped		*/
	drm_map_flags_t flags;	 /* Flags				*/
	void		*handle; /* User-space: "Handle" to pass to mmap */
				 /* Kernel-space: kernel-virtual address */
	int		mtrr;	 /* Boolean: MTRR used 			*/
				 /* Private data			*/
	int		rid;	 /* PCI resource ID for bus_space 	*/
	int		kernel_owned; /* Boolean: 1= initmapped, 0= addmapped */
	caddr_t		dev_addr;	  /* base device address 	*/
	ddi_acc_handle_t  dev_handle;	  /* The data access handle 	*/
	ddi_umem_cookie_t drm_umem_cookie; /* For SAREA alloc and free  */
	TAILQ_ENTRY(drm_local_map) link;
} drm_local_map_t;
/* END CSTYLED */

/*
 * This structure defines the drm_mm memory object, which will be used by the
 * DRM for its buffer objects.
 */
struct drm_gem_object {
	/* Reference count of this object */
	atomic_t refcount;

	/* Handle count of this object. Each handle also holds a reference */
	atomic_t handlecount;

	/* Related drm device */
	struct drm_device *dev;

	int flink;
	/*
	 * Size of the object, in bytes.  Immutable over the object's
	 * lifetime.
	 */
	size_t size;

	/*
	 * Global name for this object, starts at 1. 0 means unnamed.
	 * Access is covered by the object_name_lock in the related drm_device
	 */
	int name;

	/*
	 * Memory domains. These monitor which caches contain read/write data
	 * related to the object. When transitioning from one set of domains
	 * to another, the driver is called to ensure that caches are suitably
	 * flushed and invalidated
	 */
	uint32_t read_domains;
	uint32_t write_domain;

	/*
	 * While validating an exec operation, the
	 * new read/write domain values are computed here.
	 * They will be transferred to the above values
	 * at the point that any cache flushing occurs
	 */
	uint32_t pending_read_domains;
	uint32_t pending_write_domain;

	void *driver_private;

	drm_local_map_t *map;
	ddi_dma_handle_t dma_hdl;
	ddi_acc_handle_t acc_hdl;
	caddr_t kaddr;
	size_t real_size;	/* real size of memory */
	pfn_t *pfnarray;
};

struct idr_list {
	struct idr_list *next, *prev;
	struct drm_gem_object *obj;
	uint32_t	handle;
	caddr_t	contain_ptr;
};

struct drm_file {
	TAILQ_ENTRY(drm_file) link;
	int		  authenticated;
	int		  master;
	int		  minor;
	pid_t		  pid;
	uid_t		  uid;
	int		  refs;
	drm_magic_t	  magic;
	unsigned long	  ioctl_count;
	void		 *driver_priv;
	/* Mapping of mm object handles to object pointers. */
	struct idr_list object_idr;
	/* Lock for synchronization of access to object_idr. */
	kmutex_t table_lock;

	dev_t dev;
	cred_t *credp;
};

typedef struct drm_lock_data {
	drm_hw_lock_t	*hw_lock;	/* Hardware lock		*/
	drm_file_t	*filp;
	/* Uniq. identifier of holding process */
	kcondvar_t	lock_cv;	/* lock queue - SOLARIS Specific */
	kmutex_t	lock_mutex;	/* lock - SOLARIS Specific */
	unsigned long	lock_time;	/* Time of last lock in clock ticks */
} drm_lock_data_t;

/*
 * This structure, in drm_device_t, is always initialized while the device
 * is open.  dev->dma_lock protects the incrementing of dev->buf_use, which
 * when set marks that no further bufs may be allocated until device teardown
 * occurs (when the last open of the device has closed).  The high/low
 * watermarks of bufs are only touched by the X Server, and thus not
 * concurrently accessed, so no locking is needed.
 */
typedef struct drm_device_dma {
	drm_buf_entry_t	bufs[DRM_MAX_ORDER+1];
	int		buf_count;
	drm_buf_t	**buflist;	/* Vector of pointers info bufs	   */
	int		seg_count;
	int		page_count;
	unsigned long	*pagelist;
	unsigned long	byte_count;
	enum {
		_DRM_DMA_USE_AGP = 0x01,
		_DRM_DMA_USE_SG  = 0x02
	} flags;
} drm_device_dma_t;

typedef struct drm_agp_mem {
	void		*handle;
	unsigned long	bound; /* address */
	int		pages;
	caddr_t		phys_addr;
	struct drm_agp_mem *prev;
	struct drm_agp_mem *next;
} drm_agp_mem_t;

typedef struct drm_agp_head {
	agp_info_t	agp_info;
	const char	*chipset;
	drm_agp_mem_t	*memory;
	unsigned long	mode;
	int		enabled;
	int		acquired;
	unsigned long	base;
	int		mtrr;
	int		cant_use_aperture;
	unsigned long	page_mask;
	ldi_ident_t	agpgart_li;
	ldi_handle_t	agpgart_lh;
} drm_agp_head_t;


typedef struct drm_dma_handle {
	ddi_dma_handle_t	dma_hdl;
	ddi_acc_handle_t	acc_hdl;
	ddi_dma_cookie_t	cookie;
	uint_t		cookie_num;
	uintptr_t		vaddr;   /* virtual addr */
	uintptr_t		paddr;   /* physical addr */
	size_t		real_sz; /* real size of memory */
} drm_dma_handle_t;

typedef struct drm_sg_mem {
	unsigned long	handle;
	void		*virtual;
	int		pages;
	dma_addr_t  	*busaddr;
	ddi_umem_cookie_t	*umem_cookie;
	drm_dma_handle_t	*dmah_sg;
	drm_dma_handle_t	*dmah_gart; /* Handle to PCI memory */
} drm_sg_mem_t;

/*
 * Generic memory manager structs
 */

struct drm_mm_node {
	struct list_head fl_entry;
	struct list_head ml_entry;
	int free;
	unsigned long start;
	unsigned long size;
	struct drm_mm *mm;
	void *private;
};

struct drm_mm {
	struct list_head fl_entry;
	struct list_head ml_entry;
};

typedef TAILQ_HEAD(drm_map_list, drm_local_map) drm_map_list_t;

typedef TAILQ_HEAD(drm_vbl_sig_list, drm_vbl_sig) drm_vbl_sig_list_t;
typedef struct drm_vbl_sig {
	TAILQ_ENTRY(drm_vbl_sig) link;
	unsigned int	sequence;
	int		signo;
	int		pid;
} drm_vbl_sig_t;


/* used for clone device */
typedef TAILQ_HEAD(drm_cminor_list, drm_cminor) drm_cminor_list_t;
typedef struct drm_cminor {
	TAILQ_ENTRY(drm_cminor) link;
	drm_file_t		*fpriv;
	int			minor;
} drm_cminor_t;

/* location of GART table */
#define	DRM_ATI_GART_MAIN	1
#define	DRM_ATI_GART_FB		2

typedef struct ati_pcigart_info {
	int gart_table_location;
	int is_pcie;
	void *addr;
	dma_addr_t bus_addr;
	drm_local_map_t mapping;
} drm_ati_pcigart_info;

/* DRM device structure */
struct drm_device;
struct drm_driver_info {
	int (*load)(struct drm_device *, unsigned long);
	int (*firstopen)(struct drm_device *);
	int (*open)(struct drm_device *, drm_file_t *);
	void (*preclose)(struct drm_device *, drm_file_t *);
	void (*postclose)(struct drm_device *, drm_file_t *);
	void (*lastclose)(struct drm_device *);
	int (*unload)(struct drm_device *);
	void (*reclaim_buffers_locked)(struct drm_device *, drm_file_t *);
	int (*presetup)(struct drm_device *);
	int (*postsetup)(struct drm_device *);
	int (*open_helper)(struct drm_device *, drm_file_t *);
	void (*free_filp_priv)(struct drm_device *, drm_file_t *);
	void (*release)(struct drm_device *, void *);
	int (*dma_ioctl)(DRM_IOCTL_ARGS);
	void (*dma_ready)(struct drm_device *);
	int (*dma_quiescent)(struct drm_device *);
	int (*dma_flush_block_and_flush)(struct drm_device *,
			int, drm_lock_flags_t);
	int (*dma_flush_unblock)(struct drm_device *, int,
					drm_lock_flags_t);
	int (*context_ctor)(struct drm_device *, int);
	int (*context_dtor)(struct drm_device *, int);
	int (*kernel_context_switch)(struct drm_device *, int, int);
	int (*kernel_context_switch_unlock)(struct drm_device *);
	int (*device_is_agp) (struct drm_device *);
	int (*irq_preinstall)(struct drm_device *);
	void (*irq_postinstall)(struct drm_device *);
	void (*irq_uninstall)(struct drm_device *dev);
	uint_t (*irq_handler)(DRM_IRQ_ARGS);
	int (*vblank_wait)(struct drm_device *, unsigned int *);
	int (*vblank_wait2)(struct drm_device *, unsigned int *);
	/* added for intel minimized vblank */
	u32 (*get_vblank_counter)(struct drm_device *dev, int crtc);
	int (*enable_vblank)(struct drm_device *dev, int crtc);
	void (*disable_vblank)(struct drm_device *dev, int crtc);

	/*
	 * Driver-specific constructor for drm_gem_objects, to set up
	 * obj->driver_private.
	 *
	 * Returns 0 on success.
	 */
	int (*gem_init_object) (struct drm_gem_object *obj);
	void (*gem_free_object) (struct drm_gem_object *obj);


	drm_ioctl_desc_t *driver_ioctls;
	int	max_driver_ioctl;

	int	buf_priv_size;
	int	driver_major;
	int	driver_minor;
	int	driver_patchlevel;
	const char *driver_name;	/* Simple driver name		   */
	const char *driver_desc;	/* Longer driver name		   */
	const char *driver_date;	/* Date of last major changes.	   */

	unsigned use_agp :1;
	unsigned require_agp :1;
	unsigned use_sg :1;
	unsigned use_dma :1;
	unsigned use_pci_dma :1;
	unsigned use_dma_queue :1;
	unsigned use_irq :1;
	unsigned use_vbl_irq :1;
	unsigned use_vbl_irq2 :1;
	unsigned use_mtrr :1;
	unsigned use_gem;
};

/*
 * hardware-specific code needs to initialize mutexes which
 * can be used in interrupt context, so they need to know
 * the interrupt priority. Interrupt cookie in drm_device
 * structure is the intr_block field.
 */
#define	DRM_INTR_PRI(dev) \
	DDI_INTR_PRI((dev)->intr_block)

struct drm_device {
	drm_driver_t	*driver;
	drm_cminor_list_t	minordevs;
	dev_info_t *dip;
	void	*drm_handle;
	int drm_supported;
	const char *desc; /* current driver description */
	kmutex_t *irq_mutex;
	kcondvar_t *irq_cv;

	ddi_iblock_cookie_t intr_block;
	uint32_t	pci_device;	/* PCI device id */
	uint32_t	pci_vendor;
	char		*unique;	/* Unique identifier: e.g., busid  */
	int		unique_len;	/* Length of unique field	   */
	int		if_version;	/* Highest interface version set */
	int		flags;	/* Flags to open(2)		   */

	/* Locks */
	kmutex_t	vbl_lock;	/* protects vblank operations */
	kmutex_t	dma_lock;	/* protects dev->dma */
	kmutex_t	irq_lock;	/* protects irq condition checks */
	kmutex_t	dev_lock;	/* protects everything else */
	drm_lock_data_t   lock;		/* Information on hardware lock    */
	kmutex_t	struct_mutex;	/* < For others	*/

	/* Usage Counters */
	int		  open_count;	/* Outstanding files open	   */
	int		  buf_use;	/* Buffers in use -- cannot alloc  */

	/* Performance counters */
	unsigned long	  counters;
	drm_stat_type_t	  types[15];
	uint32_t	  counts[15];

	/* Authentication */
	drm_file_list_t   files;
	drm_magic_head_t  magiclist[DRM_HASH_SIZE];

	/* Linked list of mappable regions. Protected by dev_lock */
	drm_map_list_t	  maplist;

	drm_local_map_t	  **context_sareas;
	int		  max_context;

	/* DMA queues (contexts) */
	drm_device_dma_t  *dma;		/* Optional pointer for DMA support */

	/* Context support */
	int		  irq;		/* Interrupt used by board	   */
	int		  irq_enabled;	/* True if the irq handler is enabled */
	int		  pci_domain;
	int		  pci_bus;
	int		  pci_slot;
	int		  pci_func;
	atomic_t	  context_flag;	/* Context swapping flag	   */
	int		  last_context;	/* Last current context		   */

	/* Only used for Radeon */
	atomic_t	vbl_received;
	atomic_t	vbl_received2;

	drm_vbl_sig_list_t vbl_sig_list;
	drm_vbl_sig_list_t vbl_sig_list2;
	/*
	 * At load time, disabling the vblank interrupt won't be allowed since
	 * old clients may not call the modeset ioctl and therefore misbehave.
	 * Once the modeset ioctl *has* been called though, we can safely
	 * disable them when unused.
	 */
	int vblank_disable_allowed;

	wait_queue_head_t	vbl_queue;	/* vbl wait channel */
	/* vbl wait channel array */
	wait_queue_head_t	*vbl_queues;

	/* number of VBLANK interrupts */
	/* (driver must alloc the right number of counters) */
	atomic_t	  *_vblank_count;
	/* signal list to send on VBLANK */
	struct drm_vbl_sig_list *vbl_sigs;

	/* number of signals pending on all crtcs */
	atomic_t	  vbl_signal_pending;
	/* number of users of vblank interrupts per crtc */
	atomic_t	  *vblank_refcount;
	/* protected by dev->vbl_lock, used for wraparound handling */
	u32		  *last_vblank;
	/* so we don't call enable more than */
	atomic_t	  *vblank_enabled;
	/* Display driver is setting mode */
	int		*vblank_inmodeset;
	/* Don't wait while crtc is likely disabled */
	int		*vblank_suspend;
	/* size of vblank counter register */
	u32		max_vblank_count;
	int		num_crtcs;
	kmutex_t	tasklet_lock;
	void (*locked_tasklet_func)(struct drm_device *dev);

	pid_t		  buf_pgid;
	drm_agp_head_t    *agp;
	drm_sg_mem_t	  *sg;  /* Scatter gather memory */
	uint32_t	  *ctx_bitmap;
	void		  *dev_private;
	unsigned int	  agp_buffer_token;
	drm_local_map_t   *agp_buffer_map;

	kstat_t		  *asoft_ksp; /* kstat support */

	/* name Drawable information */
	kmutex_t	drw_lock;
	unsigned int drw_bitfield_length;
	u32 *drw_bitfield;
	unsigned int drw_info_length;
	drm_drawable_info_t **drw_info;

	/* \name GEM information */
	/* @{ */
	kmutex_t object_name_lock;
	struct idr_list	object_name_idr;
	atomic_t object_count;
	atomic_t object_memory;
	atomic_t pin_count;
	atomic_t pin_memory;
	atomic_t gtt_count;
	atomic_t gtt_memory;
	uint32_t gtt_total;
	uint32_t invalidate_domains;	/* domains pending invalidation */
	uint32_t flush_domains;	/* domains pending flush */
	/* @} */

	/*
	 * Saving S3 context
	 */
	void		  *s3_private;
};

/* Memory management support (drm_memory.c) */
void	drm_mem_init(void);
void	drm_mem_uninit(void);
void	*drm_alloc(size_t, int);
void	*drm_calloc(size_t, size_t, int);
void	*drm_realloc(void *, size_t, size_t, int);
void	drm_free(void *, size_t, int);
int 	drm_ioremap(drm_device_t *, drm_local_map_t *);
void	drm_ioremapfree(drm_local_map_t *);

void drm_core_ioremap(struct drm_local_map *, struct drm_device *);
void drm_core_ioremapfree(struct drm_local_map *, struct drm_device *);

void drm_pci_free(drm_device_t *, drm_dma_handle_t *);
void *drm_pci_alloc(drm_device_t *, size_t, size_t, dma_addr_t, int);

struct drm_local_map *drm_core_findmap(struct drm_device *, unsigned long);

int	drm_context_switch(drm_device_t *, int, int);
int	drm_context_switch_complete(drm_device_t *, int);
int	drm_ctxbitmap_init(drm_device_t *);
void	drm_ctxbitmap_cleanup(drm_device_t *);
void	drm_ctxbitmap_free(drm_device_t *, int);
int	drm_ctxbitmap_next(drm_device_t *);

/* Locking IOCTL support (drm_lock.c) */
int	drm_lock_take(drm_lock_data_t *, unsigned int);
int	drm_lock_transfer(drm_device_t *,
			drm_lock_data_t *, unsigned int);
int	drm_lock_free(drm_device_t *,
		    volatile unsigned int *, unsigned int);

/* Buffer management support (drm_bufs.c) */
unsigned long drm_get_resource_start(drm_device_t *, unsigned int);
unsigned long drm_get_resource_len(drm_device_t *, unsigned int);
int	drm_initmap(drm_device_t *, unsigned long, unsigned long,
    unsigned int, int, int);
void	drm_rmmap(drm_device_t *, drm_local_map_t *);
int	drm_addmap(drm_device_t *, unsigned long, unsigned long,
    drm_map_type_t, drm_map_flags_t, drm_local_map_t **);
int	drm_order(unsigned long);

/* DMA support (drm_dma.c) */
int	drm_dma_setup(drm_device_t *);
void	drm_dma_takedown(drm_device_t *);
void	drm_free_buffer(drm_device_t *, drm_buf_t *);
void	drm_reclaim_buffers(drm_device_t *, drm_file_t *);
#define	drm_core_reclaim_buffers	drm_reclaim_buffers

/* IRQ support (drm_irq.c) */
int	drm_irq_install(drm_device_t *);
int	drm_irq_uninstall(drm_device_t *);
uint_t	drm_irq_handler(DRM_IRQ_ARGS);
void	drm_driver_irq_preinstall(drm_device_t *);
void	drm_driver_irq_postinstall(drm_device_t *);
void	drm_driver_irq_uninstall(drm_device_t *);
int	drm_vblank_wait(drm_device_t *, unsigned int *);
void	drm_vbl_send_signals(drm_device_t *);
void    drm_handle_vblank(struct drm_device *dev, int crtc);
u32	drm_vblank_count(struct drm_device *dev, int crtc);
int	drm_vblank_get(struct drm_device *dev, int crtc);
void	drm_vblank_put(struct drm_device *dev, int crtc);
int	drm_vblank_init(struct drm_device *dev, int num_crtcs);
void	drm_vblank_cleanup(struct drm_device *dev);
int    drm_modeset_ctl(DRM_IOCTL_ARGS);

/* AGP/GART support (drm_agpsupport.c) */
int	drm_device_is_agp(drm_device_t *);
int 	drm_device_is_pcie(drm_device_t *);
drm_agp_head_t *drm_agp_init(drm_device_t *);
void	drm_agp_fini(drm_device_t *);
int 	drm_agp_do_release(drm_device_t *);
void	*drm_agp_allocate_memory(size_t pages,
	    uint32_t type, drm_device_t *dev);
int	drm_agp_free_memory(agp_allocate_t *handle, drm_device_t *dev);
int	drm_agp_bind_memory(unsigned int, uint32_t, drm_device_t *);
int	drm_agp_unbind_memory(unsigned long, drm_device_t *);
int	drm_agp_bind_pages(drm_device_t *dev,
		    pfn_t *pages,
		    unsigned long num_pages,
		    uint32_t gtt_offset);
int	drm_agp_unbind_pages(drm_device_t *dev,
		    unsigned long num_pages,
		    uint32_t gtt_offset,
		    uint32_t type);
void drm_agp_chipset_flush(struct drm_device *dev);
void drm_agp_rebind(struct drm_device *dev);

/* kstat support (drm_kstats.c) */
int	drm_init_kstats(drm_device_t *);
void	drm_fini_kstats(drm_device_t *);

/* Scatter Gather Support (drm_scatter.c) */
void	drm_sg_cleanup(drm_device_t *, drm_sg_mem_t *);

/* ATI PCIGART support (ati_pcigart.c) */
int	drm_ati_pcigart_init(drm_device_t *, drm_ati_pcigart_info *);
int	drm_ati_pcigart_cleanup(drm_device_t *, drm_ati_pcigart_info *);

/* Locking IOCTL support (drm_drv.c) */
int	drm_lock(DRM_IOCTL_ARGS);
int	drm_unlock(DRM_IOCTL_ARGS);
int	drm_version(DRM_IOCTL_ARGS);
int	drm_setversion(DRM_IOCTL_ARGS);
/* Cache management (drm_cache.c) */
void drm_clflush_pages(caddr_t *pages, unsigned long num_pages);

/* Misc. IOCTL support (drm_ioctl.c) */
int	drm_irq_by_busid(DRM_IOCTL_ARGS);
int	drm_getunique(DRM_IOCTL_ARGS);
int	drm_setunique(DRM_IOCTL_ARGS);
int	drm_getmap(DRM_IOCTL_ARGS);
int	drm_getclient(DRM_IOCTL_ARGS);
int	drm_getstats(DRM_IOCTL_ARGS);
int	drm_noop(DRM_IOCTL_ARGS);

/* Context IOCTL support (drm_context.c) */
int	drm_resctx(DRM_IOCTL_ARGS);
int	drm_addctx(DRM_IOCTL_ARGS);
int	drm_modctx(DRM_IOCTL_ARGS);
int	drm_getctx(DRM_IOCTL_ARGS);
int	drm_switchctx(DRM_IOCTL_ARGS);
int	drm_newctx(DRM_IOCTL_ARGS);
int	drm_rmctx(DRM_IOCTL_ARGS);
int	drm_setsareactx(DRM_IOCTL_ARGS);
int	drm_getsareactx(DRM_IOCTL_ARGS);

/* Drawable IOCTL support (drm_drawable.c) */
int	drm_adddraw(DRM_IOCTL_ARGS);
int	drm_rmdraw(DRM_IOCTL_ARGS);
int	drm_update_draw(DRM_IOCTL_ARGS);

/* Authentication IOCTL support (drm_auth.c) */
int	drm_getmagic(DRM_IOCTL_ARGS);
int	drm_authmagic(DRM_IOCTL_ARGS);
int	drm_remove_magic(drm_device_t *, drm_magic_t);
drm_file_t	*drm_find_file(drm_device_t *, drm_magic_t);
/* Buffer management support (drm_bufs.c) */
int	drm_addmap_ioctl(DRM_IOCTL_ARGS);
int	drm_rmmap_ioctl(DRM_IOCTL_ARGS);
int	drm_addbufs_ioctl(DRM_IOCTL_ARGS);
int	drm_infobufs(DRM_IOCTL_ARGS);
int	drm_markbufs(DRM_IOCTL_ARGS);
int	drm_freebufs(DRM_IOCTL_ARGS);
int	drm_mapbufs(DRM_IOCTL_ARGS);

/* DMA support (drm_dma.c) */
int	drm_dma(DRM_IOCTL_ARGS);

/* IRQ support (drm_irq.c) */
int	drm_control(DRM_IOCTL_ARGS);
int	drm_wait_vblank(DRM_IOCTL_ARGS);

/* AGP/GART support (drm_agpsupport.c) */
int	drm_agp_acquire(DRM_IOCTL_ARGS);
int	drm_agp_release(DRM_IOCTL_ARGS);
int	drm_agp_enable(DRM_IOCTL_ARGS);
int	drm_agp_info(DRM_IOCTL_ARGS);
int	drm_agp_alloc(DRM_IOCTL_ARGS);
int	drm_agp_free(DRM_IOCTL_ARGS);
int	drm_agp_unbind(DRM_IOCTL_ARGS);
int	drm_agp_bind(DRM_IOCTL_ARGS);

/* Scatter Gather Support (drm_scatter.c) */
int	drm_sg_alloc(DRM_IOCTL_ARGS);
int	drm_sg_free(DRM_IOCTL_ARGS);

/*	drm_mm.c	*/
struct drm_mm_node *drm_mm_get_block(struct drm_mm_node *parent,
				    unsigned long size, unsigned alignment);
struct drm_mm_node *drm_mm_search_free(const struct drm_mm *mm,
				    unsigned long size,
				    unsigned alignment, int best_match);

extern void drm_mm_clean_ml(const struct drm_mm *mm);
extern int drm_debug_flag;

/* We add function to support DRM_DEBUG,DRM_ERROR,DRM_INFO */
extern void drm_debug(const char *fmt, ...);
extern void drm_error(const char *fmt, ...);
extern void drm_info(const char *fmt, ...);

#ifdef DEBUG
#define	DRM_DEBUG		if (drm_debug_flag >= 2) drm_debug
#define	DRM_INFO		if (drm_debug_flag >= 1) drm_info
#else
#define	DRM_DEBUG(...)
#define	DRM_INFO(...)
#endif

#define	DRM_ERROR		drm_error


#define	MAX_INSTNUMS 16

extern int drm_dev_to_instance(dev_t);
extern int drm_dev_to_minor(dev_t);
extern void *drm_supp_register(dev_info_t *, drm_device_t *);
extern int drm_supp_unregister(void *);

extern int drm_open(drm_device_t *, drm_cminor_t *, int, int, cred_t *);
extern int drm_close(drm_device_t *, int, int, int, cred_t *);
extern int drm_attach(drm_device_t *);
extern int drm_detach(drm_device_t *);
extern int drm_probe(drm_device_t *, drm_pci_id_list_t *);

extern int drm_pci_init(drm_device_t *);
extern void drm_pci_end(drm_device_t *);
extern int pci_get_info(drm_device_t *, int *, int *, int *);
extern int pci_get_irq(drm_device_t *);
extern int pci_get_vendor(drm_device_t *);
extern int pci_get_device(drm_device_t *);

extern struct drm_drawable_info *drm_get_drawable_info(drm_device_t *,
							drm_drawable_t);
/* File Operations helpers (drm_fops.c) */
extern drm_file_t *drm_find_file_by_proc(drm_device_t *, cred_t *);
extern drm_cminor_t *drm_find_file_by_minor(drm_device_t *, int);
extern int drm_open_helper(drm_device_t *, drm_cminor_t *, int, int,
    cred_t *);

/* Graphics Execution Manager library functions (drm_gem.c) */
int drm_gem_init(struct drm_device *dev);
void drm_gem_object_free(struct drm_gem_object *obj);
struct drm_gem_object *drm_gem_object_alloc(struct drm_device *dev,
					    size_t size);
void drm_gem_object_handle_free(struct drm_gem_object *obj);

void drm_gem_object_reference(struct drm_gem_object *obj);
void drm_gem_object_unreference(struct drm_gem_object *obj);

int drm_gem_handle_create(struct drm_file *file_priv,
			    struct drm_gem_object *obj,
			    int *handlep);
void drm_gem_object_handle_reference(struct drm_gem_object *obj);

void drm_gem_object_handle_unreference(struct drm_gem_object *obj);

struct drm_gem_object *drm_gem_object_lookup(struct drm_file *filp,
					    int handle);
int drm_gem_close_ioctl(DRM_IOCTL_ARGS);
int drm_gem_flink_ioctl(DRM_IOCTL_ARGS);
int drm_gem_open_ioctl(DRM_IOCTL_ARGS);
void drm_gem_open(struct drm_file *file_private);
void drm_gem_release(struct drm_device *dev, struct drm_file *file_private);


#endif	/* _DRMP_H */
