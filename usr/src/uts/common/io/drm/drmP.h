/*
 * drmP.h -- Private header for Direct Rendering Manager -*- linux-c -*-
 * Created: Mon Jan  4 10:05:05 1999 by faith@precisioninsight.com
 */
/*
 * Copyright 1999 Precision Insight, Inc., Cedar Park, Texas.
 * Copyright 2000 VA Linux Systems, Inc., Sunnyvale, California.
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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _DRMP_H
#define	_DRMP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include <sys/atomic.h>
#include "drm_atomic.h"
#include "drm.h"
#include "queue.h"
#include "drm_linux_list.h"
#include <sys/agpgart.h>


#ifdef NOPID
#undef NOPID
#endif

#if !defined(__FUNCTION__) && defined(C99)
#define	__FUNCTION__ __func__
#else
#define	__FUNCTION__	" "
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

#define	DRM_MAX_INSTANCES	1
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

#define	DRM_MAX_CTXBITMAP (PAGE_SIZE * 8)

/* Internal types and structures */
#define	DRM_ARRAY_SIZE(x) (sizeof (x) / sizeof (x[0]))
#define	DRM_MIN(a, b) ((a) < (b) ? (a) : (b))
#define	DRM_MAX(a, b) ((a) > (b) ? (a) : (b))

#define	DRM_IF_VERSION(maj, min) (maj << 16 | min)

#define	__OS_HAS_AGP	1

#define	DRM_DEV_MOD	(S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP)
#define	DRM_DEV_UID	0
#define	DRM_DEV_GID	0

#define	wait_queue_head_t kcondvar_t
#define	DRM_WAKEUP(w)	cv_broadcast(w)
#define	DRM_WAKEUP_INT(w)
#define	DRM_INIT_WAITQUEUE(queue)	cv_init(queue, NULL, CV_DRIVER, NULL)

#define	DRM_CURPROC
#define	DRM_CURRENTPID		ddi_get_pid()
#define	DRM_SPINLOCK(l)		mutex_enter(l)
#define	DRM_SPINUNLOCK(u)	mutex_exit(u)
#define	DRM_SPINLOCK_ASSERT(l)
#define	DRM_LOCK()	mutex_enter(&dev->dev_lock)
#define	DRM_UNLOCK()	mutex_exit(&dev->dev_lock)
#define	spin_lock_irqsave(l, flag)	mutex_enter(l)
#define	spin_unlock_irqrestore(u, flag)	mutex_exit(u)
#define	spin_lock(l)		mutex_enter(l)
#define	spin_unlock(u)		mutex_exit(u)

#define	DRM_UDELAY(sec)  delay(drv_usectohz(sec * 1000))
#define	DRM_MEMORYBARRIER()

#define	drm_device drm_softstate
typedef struct drm_softstate drm_device_t;
typedef struct drm_softstate drm_softstate_t;

#define	DRM_IOCTL_ARGS	dev_t kdev, drm_softstate_t *dev1, intptr_t data, \
	int mode, cred_t *credp, int *rvalp, DRMFILE filp

#define	DRM_COPY_FROM_USER_IOCTL(arg1, arg2, arg3) \
	if (ddi_copyin(arg2, &arg1, arg3, mode) != DDI_SUCCESS) \
		return EFAULT

/* Other copying of data to kernel space */
#define	DRM_COPY_FROM_USER(arg1, arg2, arg3) \
	ddi_copyin(arg2, arg1, arg3, mode)
/* Other copying of data from kernel space */
#define	DRM_COPY_TO_USER(arg1, arg2, arg3)              \
	ddi_copyout(arg2, arg1, arg3, mode)

#define	DRM_COPY_FROM_USER_UNCHECKED(arg1, arg2, arg3)  \
	ddi_copyin((arg2), arg1, arg3, mode)

/* For data going from the kernel through the ioctl argument */
#define	DRM_COPY_TO_USER_IOCTL(arg1, arg2, arg3)        \
	if (ddi_copyout(&arg2, arg1, arg3, mode) != DDI_SUCCESS)          \
		return EFAULT

#define	DRM_DEVICE	drm_softstate_t *dev = dev1

#define	DRM_READ8(map, offset) \
	ddi_get8((map)->dev_handle, \
		(void *)((char *)((map)->dev_addr) + (offset)))
#define	DRM_READ16(map, offset) \
	ddi_get16((map)->dev_handle, \
		(void *)((char *)((map)->dev_addr) + (offset)))
#define	DRM_READ32(map, offset) \
	ddi_get32((map)->dev_handle, \
		(void *)((char *)((map)->dev_addr) + (offset)))
#define	DRM_WRITE8(map, offset, val) \
	ddi_put8((map)->dev_handle, \
		(void *)((char *)((map)->dev_addr) + (offset)), (val))
#define	DRM_WRITE16(map, offset, val) \
	ddi_put16((map)->dev_handle, \
		(void *)((char *)((map)->dev_addr) + (offset)), (val))
#define	DRM_WRITE32(map, offset, val) \
	ddi_put32((map)->dev_handle, \
		(void *)((char *)((map)->dev_addr) + (offset)), (val))

#define	DRM_WAIT_ON(ret, cv, timeout, condition)  \
mutex_enter(&dev->irq_lock);					\
for (; ; ) {                       				\
	if (!(condition)) {					\
		DRM_DEBUG("i915_irq: cv will wait");		\
		ret = cv_timedwait_sig(&cv, &dev->irq_lock,	\
		    jiffies + timeout);				\
		if (ret < 0) {					\
			ret = DRM_ERR(EINTR);				\
			break;					\
		}						\
	}                                                       \
	else {							\
		ret = 0;					\
		break;						\
	}							\
}                                                               \
mutex_exit(&dev->irq_lock);

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

#define	LOCK_TEST_WITH_RETURN(dev, filp)				\
	if (!_DRM_LOCK_IS_HELD(dev->lock.hw_lock->lock) ||		\
	    dev->lock.filp != filp) {					\
		DRM_ERROR("%s called without lock held\n",	\
			__FUNCTION__);					\
		return (EINVAL);					\
	}

/*
 * Currently our DRMFILE (filp) is a void * which is actually the pid
 * of the current process.  It should be a per-open unique pointer, but
 * code for that is not yet written
 */
#define	DRMFILE			void *
#define	DRM_IRQ_ARGS		caddr_t arg
#define	IRQ_HANDLED		DDI_INTR_CLAIMED
#define	IRQ_NONE		DDI_INTR_UNCLAIMED

#define	PAGE_ALIGN(addr)	(((addr) + DRM_PAGE_SIZE - 1) & DRM_PAGE_MASK)
#define	jiffies			ddi_get_lbolt()
#define	DRM_SUSER(p)		(crgetgid(p) == 0 || crgetuid(p) == 0)

/*
 * wait for 400 miliseconds
 */
#define	DRM_HZ			drv_usectohz(400000)

#define	DRM_ERR(v)		(v)

#define	DRM_GET_PRIV_WITH_RETURN(filp_priv, filp)

typedef unsigned long dma_addr_t;
typedef uint64_t	u64;
typedef uint32_t	u32;
typedef uint8_t		u8;
typedef uint16_t	u16;
typedef uint_t		irqreturn_t;

#define	DRM_SUPPORT	1
#define	DRM_UNSUPPORT	0

#define	__OS_HAS_AGP	1

#define	__offsetof(type, field) ((size_t)(&((type *)0)->field))
#define	offsetof(type, field)   __offsetof(type, field)

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
	int	auth_needed;
	int	root_only;
	char	*desc;
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
	DRMFILE		filp;
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
};

typedef struct drm_lock_data {
	drm_hw_lock_t	*hw_lock;	/* Hardware lock		*/
	DRMFILE		filp;
	/* Uniq. identifier of holding process */
	kcondvar_t	lock_cv;	/* lock queue - SOLARIS Specific */
	kmutex_t	lock_mutex;	/* lock - SOLARIS Specific */
	unsigned long	lock_time;	/* Time of last lock in jiffies */
} drm_lock_data_t;

/*
 * This structure, in drm_softstate_t, is always initialized while the device
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
	unsigned int	key;
	unsigned long	bound; /* address */
	int		pages;
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
} drm_agp_head_t;

typedef struct drm_sg_mem {
	unsigned long   handle;
	caddr_t		virtual;
	int		pages;
	dma_addr_t	*busaddr;
	ddi_umem_cookie_t	sg_umem_cookie;
	ddi_dma_handle_t	sg_dma_hdl;
	ddi_dma_cookie_t	sg_dma_cookie;
	uint_t			sg_cookie_num;


} drm_sg_mem_t;

typedef TAILQ_HEAD(drm_map_list, drm_local_map) drm_map_list_t;

/* BEGIN CSTYLED */
typedef union drm_off {
	u_offset_t	off;
	void *		ptr;
} drm_off_t;
typedef struct drm_local_map {
	drm_off_t	offset;	 /* Physical address (0 for SAREA)	*/
	unsigned int	size;	 /* Physical size (bytes)		*/
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
	ddi_umem_cookie_t drm_umem_cookie; /* For SAREA alloc and free 	*/
	TAILQ_ENTRY(drm_local_map) link;
} drm_local_map_t;
/* END CSTYLED */

TAILQ_HEAD(drm_vbl_sig_list, drm_vbl_sig);
typedef struct drm_vbl_sig {
	TAILQ_ENTRY(drm_vbl_sig) link;
	unsigned int	sequence;
	int		signo;
	int		pid;
} drm_vbl_sig_t;

typedef struct drm_file drm_file_t;

/* used for clone device */
struct minordev {
	struct minordev *next;
	int cloneminor;
};

/* DRM softstate structure */
struct drm_softstate {
	int cloneopens;
	struct minordev *minordevs;
	dev_info_t *dip;
	ldi_ident_t drm_li;
	ldi_ident_t agpgart_li;
	ldi_handle_t vgatext_hdl;
	ldi_handle_t agpgart_hdl;
	ddi_acc_handle_t pci_cfg_hdl;
	int drm_supported;
	const char *desc; /* current driver description */

	ddi_iblock_cookie_t intr_block;
	/* workaround */
	/* the agp umem kernel virtual address, for radeon */
	unsigned long agp_umem_kvaddr;

	/* For alloc consitent physical address */
	ddi_dma_handle_t hw_dma_handle;	    /* For hardware status page */
	ddi_acc_handle_t hw_dma_acc_handle; /* For hardware status page */
	uint64_t	 hw_pbase;	    /* hw status page phys. address */
	caddr_t		 hw_vbase;	    /* hw status page ker. virt. add. */
	size_t		 hw_size;	    /* hw status page size */

	/* Beginning of driver-config section */
	int	(*load)(struct drm_softstate *, unsigned long flags);
	int	(*firstopen)(struct drm_softstate *);
	int	(*open)(struct drm_softstate *, drm_file_t *);
	void	(*preclose)(struct drm_softstate *, void *);
	void	(*postclose)(struct drm_softstate *, drm_file_t *);
	void	(*lastclose)(struct drm_softstate *);
	int	(*unload)(struct drm_softstate *);
	void	(*reclaim_buffers_locked)(struct drm_softstate *, void *filp);
	int	(*presetup)(struct drm_softstate *);
	int	(*postsetup)(struct drm_softstate *);
	int	(*open_helper)(struct drm_softstate *, drm_file_t *);
	void	(*free_filp_priv)(struct drm_softstate *, drm_file_t *);
	void	(*release)(struct drm_softstate *, void *filp);
	int	(*dma_ioctl)(DRM_IOCTL_ARGS);
	void	(*dma_ready)(struct drm_softstate *);
	int	(*dma_quiescent)(struct drm_softstate *);
	int	(*dma_flush_block_and_flush)(struct drm_softstate *,
						int context,
						drm_lock_flags_t flags);
	int	(*dma_flush_unblock)(struct drm_softstate *, int context,
					drm_lock_flags_t flags);
	int	(*context_ctor)(struct drm_softstate *dev, int context);
	int	(*context_dtor)(struct drm_softstate *dev, int context);
	int	(*kernel_context_switch)(struct drm_softstate *dev, int old,
					int new);
	int	(*kernel_context_switch_unlock)(struct drm_softstate *dev);
	void	(*irq_preinstall)(struct drm_softstate *);
	void	(*irq_postinstall)(struct drm_softstate *);
	void	(*irq_uninstall)(struct drm_softstate *dev);
	uint_t	(*irq_handler)(DRM_IRQ_ARGS);
	int	(*vblank_wait)(struct drm_softstate *dev,
				unsigned int *sequence);

	drm_ioctl_desc_t *driver_ioctls;
	int	max_driver_ioctl;

	int	dev_priv_size;

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
	unsigned use_mtrr :1;
	/* End of driver-config section */
	uint32_t pci_device;		/* PCI device id */
	uint32_t pci_vendor;		/* PCI vendor id */

	char		  *unique;	/* Unique identifier: e.g., busid  */
	int		  unique_len;	/* Length of unique field	   */
	int		  if_version;	/* Highest interface version set */
	int		  flags;	/* Flags to open(2)		   */

	/* Locks */
	kmutex_t	  dma_lock;	/* protects dev->dma */
	kmutex_t	  irq_lock;	/* protects irq condition checks */
	kmutex_t	  dev_lock;	/* protects everything else */
	drm_lock_data_t   lock;		/* Information on hardware lock    */

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
	wait_queue_head_t vbl_queue;	/* vbl wait channel */
	atomic_t	  vbl_received;
	atomic_t	  vbl_received2;
	kmutex_t	  tasklet_lock;
	void (*locked_tasklet_func)(struct drm_softstate *dev);

	pid_t		  buf_pgid;
	drm_agp_head_t    *agp;
	drm_sg_mem_t	  *sg;  /* Scatter gather memory */
	uint32_t	  *ctx_bitmap;
	void		  *dev_private;
	unsigned int	  agp_buffer_token;
	drm_local_map_t   *agp_buffer_map;

	kstat_t		  *asoft_ksp; /* kstat support */

	/* name Drawable information */
	kmutex_t drw_lock;
};


/* We add function to support DRM_DEBUG,DRM_ERROR,DRM_INFO */
extern void drm_debug(const char *fmt, ...);
extern void drm_error(const char *fmt, ...);
extern void drm_info(const char *fmt, ...);

/* Memory management support (drm_memory.c) */
extern	void	drm_mem_init(void);
extern	void	drm_mem_uninit(void);
extern	void	*drm_alloc(size_t size, int area);
extern	void	*drm_calloc(size_t nmemb, size_t size, int area);
extern	void	*drm_realloc(void *oldpt, size_t oldsize,
				size_t size, int area);
extern	void	drm_free(void *pt, size_t size, int area);
extern	int 	drm_ioremap(drm_softstate_t *, drm_local_map_t *);
extern	void	drm_ioremapfree(drm_local_map_t *map);

extern	void drm_core_ioremap(struct drm_local_map *, struct drm_softstate *);
extern	void drm_core_ioremapfree(struct drm_local_map *,
				struct drm_softstate *);

extern	void drm_pci_free(drm_softstate_t *);
extern	void *drm_pci_alloc(drm_softstate_t *, uint32_t, dma_addr_t *);

extern	struct drm_local_map *drm_core_findmap(struct drm_softstate *,
					unsigned long);

extern	int	drm_context_switch(drm_softstate_t *dev, int old, int new);
extern	int	drm_context_switch_complete(drm_softstate_t *dev, int new);
extern	int	drm_ctxbitmap_init(drm_softstate_t *dev);
extern	void	drm_ctxbitmap_cleanup(drm_softstate_t *dev);
extern	void	drm_ctxbitmap_free(drm_softstate_t *dev, int ctx_handle);
extern	int	drm_ctxbitmap_next(drm_softstate_t *dev);

/* Locking IOCTL support (drm_lock.c) */
extern	int	drm_lock_take(volatile unsigned int *lock,
				unsigned int context);
extern	int	drm_lock_transfer(drm_softstate_t *dev,
					volatile unsigned int *lock,
					unsigned int context);
extern	int	drm_lock_free(drm_softstate_t *dev,
				    volatile unsigned int *lock,
				    unsigned int context);

/* Buffer management support (drm_bufs.c) */
extern	unsigned long drm_get_resource_start(drm_softstate_t *dev,
		unsigned int resource);
extern	unsigned long drm_get_resource_len(drm_softstate_t *dev,
		unsigned int resource);
extern	int	drm_initmap(drm_softstate_t *dev, unsigned long start,
	unsigned long len, unsigned int resource, int type, int flags);
extern	void	drm_rmmap(drm_softstate_t *dev, drm_local_map_t *map);
extern	int	drm_addmap(drm_device_t *softstate, unsigned long long offset,
	unsigned long size, drm_map_type_t type, drm_map_flags_t flags,
	drm_local_map_t **map_ptr);
extern	int	drm_order(unsigned long size);

/* DMA support (drm_dma.c) */
extern	int	drm_dma_setup(drm_softstate_t *dev);
extern	void	drm_dma_takedown(drm_softstate_t *dev);
extern	void	drm_free_buffer(drm_softstate_t *dev, drm_buf_t *buf);
extern	void	drm_reclaim_buffers(drm_softstate_t *dev, DRMFILE filp);
/* IRQ support (drm_irq.c) */
extern	int	drm_irq_install(drm_softstate_t *dev);
extern	int	drm_irq_uninstall(drm_softstate_t *dev);
extern	uint_t	drm_irq_handler(DRM_IRQ_ARGS);
extern	void	drm_driver_irq_preinstall(drm_softstate_t *dev);
extern	void	drm_driver_irq_postinstall(drm_softstate_t *dev);
extern	void	drm_driver_irq_uninstall(drm_softstate_t *dev);
extern	int	drm_vblank_wait(drm_softstate_t *dev, unsigned int *vbl_seq);
extern	void	drm_vbl_send_signals(drm_softstate_t *dev);
extern	void 	drm_locked_tasklet(drm_device_t *dev,
				void(*func)(drm_device_t *));

/* AGP/GART support (drm_agpsupport.c) */
extern	int	drm_device_is_agp(drm_softstate_t *dev);
extern	int 	drm_device_is_pcie(drm_softstate_t *dev);
extern	drm_agp_head_t	*drm_agp_init();
extern	void	drm_agp_uninit(drm_agp_head_t *);
extern	int 	drm_agp_do_release(drm_softstate_t *);
extern	void	*drm_agp_allocate_memory(size_t pages, uint32_t type);
extern	int	drm_agp_free_memory(void *handle);
extern	int	drm_agp_bind_memory(unsigned int, uint32_t, drm_device_t *);
extern	int	drm_agp_unbind_memory(unsigned long, uint32_t, drm_device_t *);

/* kstat support (drm_kstats.c) */
extern	int	drm_init_kstats(drm_softstate_t *sc);
extern	void	drm_fini_kstats(drm_softstate_t *sc);

/* Scatter Gather Support (drm_scatter.c) */
extern	void	drm_sg_cleanup(drm_sg_mem_t *entry);

/* ATI PCIGART support (ati_pcigart.c) */
extern	int	drm_ati_pcigart_init(drm_softstate_t *dev, unsigned long *addr,
			    unsigned long *bus_addr, int is_pcie);
extern	int	drm_ati_pcigart_cleanup(drm_softstate_t *dev,
			unsigned long addr, unsigned long bus_addr);

/* Locking IOCTL support (drm_drv.c) */
extern	int	drm_lock(DRM_IOCTL_ARGS);
extern	int	drm_unlock(DRM_IOCTL_ARGS);
extern	int	drm_version(DRM_IOCTL_ARGS);
extern	int	drm_setversion(DRM_IOCTL_ARGS);

/* Misc. IOCTL support (drm_ioctl.c) */
extern	int	drm_irq_by_busid(DRM_IOCTL_ARGS);
extern	int	drm_getunique(DRM_IOCTL_ARGS);
extern	int	drm_setunique(DRM_IOCTL_ARGS);
extern	int	drm_getmap(DRM_IOCTL_ARGS);
extern	int	drm_getclient(DRM_IOCTL_ARGS);
extern	int	drm_getstats(DRM_IOCTL_ARGS);
extern	int	drm_noop(DRM_IOCTL_ARGS);

/* Context IOCTL support (drm_context.c) */
extern	int	drm_resctx(DRM_IOCTL_ARGS);
extern	int	drm_addctx(DRM_IOCTL_ARGS);
extern	int	drm_modctx(DRM_IOCTL_ARGS);
extern	int	drm_getctx(DRM_IOCTL_ARGS);
extern	int	drm_switchctx(DRM_IOCTL_ARGS);
extern	int	drm_newctx(DRM_IOCTL_ARGS);
extern	int	drm_rmctx(DRM_IOCTL_ARGS);
extern	int	drm_setsareactx(DRM_IOCTL_ARGS);
extern	int	drm_getsareactx(DRM_IOCTL_ARGS);

/* Drawable IOCTL support (drm_drawable.c) */
extern	int	drm_adddraw(DRM_IOCTL_ARGS);
extern	int	drm_rmdraw(DRM_IOCTL_ARGS);

/* Authentication IOCTL support (drm_auth.c) */
extern	int	drm_getmagic(DRM_IOCTL_ARGS);
extern	int	drm_authmagic(DRM_IOCTL_ARGS);
extern	int	drm_remove_magic(drm_device_t *dev, drm_magic_t magic);
extern	drm_file_t	*drm_find_file(drm_device_t *dev, drm_magic_t magic);
/* Buffer management support (drm_bufs.c) */
extern	int	drm_addmap_ioctl(DRM_IOCTL_ARGS);
extern	int	drm_rmmap_ioctl(DRM_IOCTL_ARGS);
extern	int	drm_addbufs_ioctl(DRM_IOCTL_ARGS);
extern	int	drm_infobufs(DRM_IOCTL_ARGS);
extern	int	drm_markbufs(DRM_IOCTL_ARGS);
extern	int	drm_freebufs(DRM_IOCTL_ARGS);
extern	int	drm_mapbufs(DRM_IOCTL_ARGS);

/* DMA support (drm_dma.c) */
extern	int	drm_dma(DRM_IOCTL_ARGS);

/* IRQ support (drm_irq.c) */
extern	int	drm_control(DRM_IOCTL_ARGS);
extern	int	drm_wait_vblank(DRM_IOCTL_ARGS);

/* AGP/GART support (drm_agpsupport.c) */
extern	int	drm_agp_acquire(DRM_IOCTL_ARGS);
extern	int	drm_agp_release(DRM_IOCTL_ARGS);
extern	int	drm_agp_enable(DRM_IOCTL_ARGS);
extern	int	drm_agp_info(DRM_IOCTL_ARGS);
extern	int	drm_agp_alloc(DRM_IOCTL_ARGS);
extern	int	drm_agp_free(DRM_IOCTL_ARGS);
extern	int	drm_agp_unbind(DRM_IOCTL_ARGS);
extern	int	drm_agp_bind(DRM_IOCTL_ARGS);

/* Scatter Gather Support (drm_scatter.c) */
extern	int	drm_sg_alloc(DRM_IOCTL_ARGS);
extern	int	drm_sg_free(DRM_IOCTL_ARGS);

extern int drm_debug_flag;
#define	DRM_DEBUG		if (drm_debug_flag >= 2) drm_debug
#define	DRM_ERROR		drm_error
#define	DRM_INFO		if (drm_debug_flag >= 1) drm_info

#define	MAX_INSTNUMS 16

extern int drm_open(drm_softstate_t *, dev_t *, int, int, cred_t *);
extern int drm_close(drm_softstate_t *, dev_t, int, int, cred_t *);
extern int drm_attach(drm_softstate_t *);
extern int drm_detach(drm_softstate_t *);
extern int drm_probe(drm_softstate_t *, drm_pci_id_list_t *);

extern int drm_pci_init(drm_softstate_t *);
extern void drm_pci_end(drm_softstate_t *);
extern int pci_get_info(drm_softstate_t *, int *, int *, int *);
extern int pci_get_irq(drm_softstate_t *);
extern int pci_get_vendor(drm_softstate_t *);
extern int pci_get_device(drm_softstate_t *);

void drm_set_ioctl_desc(int, drm_ioctl_t *, int, int, char *);

extern drm_drawable_info_t *drm_get_drawable_info(drm_device_t *,
			drm_drawable_t);

/* File Operations helpers (drm_fops.c) */
extern drm_file_t *drm_find_file_by_proc(drm_softstate_t *, cred_t *);
extern int drm_open_helper(drm_softstate_t *, int, int, cred_t *);

#endif /* _DRMP_H */
