/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright (c) 1996, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SYS_DDIDEVMAP_H
#define	_SYS_DDIDEVMAP_H

#ifdef	__cplusplus
extern "C" {
#endif

#ifdef	_KERNEL

#include <sys/mman.h>

struct devmap_info {
	size_t	length;		/* and this length */
	size_t	page_size;	/* pte page size selected by framework */
	size_t	offset;		/* optimal page size based on this offset */
	ushort_t valid_flag;	/* flag to indicate the validity of data */
	uchar_t	byte_order;	/* the  endian characteristics of the mapping */

	/*
	 * describes  order in which the CPU will reference data.
	 */
	uchar_t	data_order;
};

typedef void * ddi_umem_cookie_t;

/*
 * umem callback function vector for drivers
 *
 * NOTE: IMPORTANT!  When umem_lockmemory is called with a valid
 * umem_callback_ops and DDI_UMEMLOCK_LONGTERM set, the 'cleanup'
 * callback function may be called AFTER a call to ddi_umem_lock.
 * It is the users responsibility to make sure that ddi_umem_lock is
 * called ONLY once for each ddi_umem_lock/umem_lockmemory cookie.
 */
#define	UMEM_CALLBACK_VERSION 1
struct umem_callback_ops {
	int	cbo_umem_callback_version;	/* version number */
	void (*cbo_umem_lock_cleanup)(ddi_umem_cookie_t *);
};

struct ddi_umem_cookie {
	size_t	size;	/* size of allocation */
	caddr_t	cvaddr;	/* cookie virtual address. */
			/* KMEM - kvaddr returned from ddi_umem_alloc() */
			/* For LOCKEDUMEM - user address of backing store */
			/* For TRASH_UMEM - unused */
	kmutex_t	lock;
	uint_t		type;	/* see below for umem_cookie types */
	/*
	 * Following 4 members are used for UMEM_LOCKED cookie type
	 */
	page_t		**pparray;	/* shadow list from as_pagelock */
	void		*procp;		/* user process owning backing store */
	struct as	*asp;		/* as ptr for use by ddi_umem_unlock */
	enum seg_rw	s_flags;	/* flags used during pagelock/fault */
	/*
	 * locked indicates underlying memory locked for KMEM_PAGEABLE
	 * locked is a count of for how many pages this has been locked
	 */
	uint_t		locked;
	struct umem_callback_ops callbacks;
	/*
	 * cook_refcnt used in UMEM_LOCKED type
	 */
	ulong_t		cook_refcnt;	/* cookie reference count */
	struct ddi_umem_cookie *unl_forw;   /* list ptr for unlock cookies */
	ulong_t		upd_max_lock_rctl;  /* track max-locked mem rctl? */
};

typedef struct as *ddi_as_handle_t;


/*
 * type of umem_cookie:
 *    pageable memory allocated from segkp segment driver
 *    non-pageable memory allocated from kmem_getpages()
 *    locked umem allocated from ddi_umem_lock
 *    trash umem maps all user virtual addresses to a common trash page
 */
#define	KMEM_PAGEABLE		0x100	/* un-locked kernel memory */
#define	KMEM_NON_PAGEABLE	0x200	/* locked kernel memeory */
#define	UMEM_LOCKED		0x400	/* locked user process memeory */
#define	UMEM_TRASH		0x800	/* trash page mapping */

typedef struct __devmap_pmem_cookie *devmap_pmem_cookie_t;

typedef void *devmap_cookie_t;

struct devmap_callback_ctl {
	int	devmap_rev;		/* devmap_callback_ctl version number */
	int	(*devmap_map)(devmap_cookie_t dhp, dev_t dev, uint_t flags,
				offset_t off, size_t len, void **pvtp);
	int	(*devmap_access)(devmap_cookie_t dhp, void *pvtp, offset_t off,
				size_t len, uint_t type, uint_t rw);
	int	(*devmap_dup)(devmap_cookie_t dhp, void *pvtp,
				devmap_cookie_t new_dhp, void **new_pvtp);
	void	(*devmap_unmap)(devmap_cookie_t dhp, void *pvtp, offset_t off,
				size_t len, devmap_cookie_t new_dhp1,
				void **new_pvtp1, devmap_cookie_t new_dhp2,
				void **new_pvtp2);
};

struct devmap_softlock {
	ulong_t		id;	/* handle grouping id */
	dev_t		dev; /* Device to which we are mapping */
	struct		devmap_softlock	*next;
	kmutex_t	lock;
	kcondvar_t	cv;
	int		refcnt;	/* Number of threads with mappings */
	ssize_t		softlocked;
};

struct devmap_ctx {
	ulong_t		id; /* handle grouping id */
	dev_info_t	*dip; /* Device info struct for tracing context */
	struct devmap_ctx *next;
	kmutex_t	lock;
	kcondvar_t	cv;
	int		refcnt; /* Number of threads with mappings */
	uint_t		oncpu; /* this context is running on a cpu */
	timeout_id_t	timeout; /* Timeout ID */
};

/*
 * Fault information passed to the driver fault handling routine.
 * The DEVMAP_LOCK and DEVMAP_UNLOCK are used by software
 * to lock and unlock pages for physical I/O.
 */
enum devmap_fault_type {
	DEVMAP_ACCESS,		/* invalid page */
	DEVMAP_PROT,		/* protection fault */
	DEVMAP_LOCK,		/* software requested locking */
	DEVMAP_UNLOCK		/* software requested unlocking */
};

/*
 * seg_rw gives the access type for a fault operation
 */
enum devmap_rw {
	DEVMAP_OTHER,		/* unknown or not touched */
	DEVMAP_READ,		/* read access attempted */
	DEVMAP_WRITE,		/* write access attempted */
	DEVMAP_EXEC,		/* execution access attempted */
	DEVMAP_CREATE		/* create if page doesn't exist */
};

typedef struct devmap_handle {

	/*
	 * physical offset at the beginning of mapping.
	 */
	offset_t	dh_roff;

	/*
	 * user offset at the beginning of mapping.
	 */
	offset_t	dh_uoff;
	size_t		dh_len;		/* length of mapping */
	dev_t		dh_dev;		/* dev_t for this mapping */
	caddr_t		dh_cvaddr;  /* cookie virtual address */
	caddr_t		dh_uvaddr;  /* user address within dh_seg */

	/*
	 * Lock protects fields that can change during remap
	 * dh_roff, dh_cookie, dh_flags, dh_mmulevel, dh_maxprot,
	 * dh_pfn, dh_hat_attr
	 */
	kmutex_t	dh_lock;

	/*
	 * to sync. faults for remap and unlocked kvaddr.
	 */
	struct seg		*dh_seg; /* segment created for this mapping */
	void			*dh_pvtp; /* device mapping private data */
	struct devmap_handle	*dh_next;
	struct devmap_softlock	*dh_softlock;
	struct devmap_ctx	*dh_ctx;
	ddi_umem_cookie_t	dh_cookie;	/* kmem cookie */
	devmap_pmem_cookie_t	dh_pcookie;	/* pmem cookie */

	/*
	 * protection flag possible for attempted mapping.
	 */
	uint_t		dh_prot;

	/*
	 * Current maximum protection flag for attempted mapping.
	 * This controls how dh_prot can be changed in segdev_setprot
	 * See dh_orig_maxprot below also
	 */
	uint_t		dh_maxprot;

	/*
	 * mmu level corresponds to the Max page size can be use for
	 * the mapping.
	 */
	uint_t		dh_mmulevel;
	uint_t		dh_flags;   /* see defines below */
	pfn_t		dh_pfn;		/* pfn corresponds to dh_reg_off */
	uint_t		dh_hat_attr;
	clock_t		dh_timeout_length;
	struct devmap_callback_ctl dh_callbackops;

	/*
	 * orig_maxprot is what the original mmap set maxprot to.
	 * This is never modified once it is setup during mmap(2)
	 * This is different from the current dh_maxprot which can
	 * be changed in devmap_*_setup/remap
	 */
	uint_t		dh_orig_maxprot;
} devmap_handle_t;

#endif	/* _KERNEL */

/*
 * define for devmap_rev
 */
#define	DEVMAP_OPS_REV 1

/*
 * defines for devmap_*_setup flag, called by drivers
 */
#define	DEVMAP_DEFAULTS			0x00
#define	DEVMAP_MAPPING_INVALID		0x01 	/* mapping is invalid */
#define	DEVMAP_ALLOW_REMAP		0x02	/* allow remap */
#define	DEVMAP_USE_PAGESIZE		0x04	/* use pagesize for mmu load */

/* flags used by drivers */
#define	DEVMAP_SETUP_FLAGS	\
	(DEVMAP_MAPPING_INVALID | DEVMAP_ALLOW_REMAP | DEVMAP_USE_PAGESIZE)

/*
 * defines for dh_flags, these are used internally in devmap
 */
#define	DEVMAP_SETUP_DONE		0x100	/* mapping setup is done */
#define	DEVMAP_LOCK_INITED		0x200	/* locks are initailized */
#define	DEVMAP_LOCKED			0x800	/* dhp is locked. */
#define	DEVMAP_FLAG_LARGE		0x1000  /* cal. optimal pgsize */

/*
 * Flags to pass to ddi_umem_alloc and ddi_umem_iosetup
 */
#define	DDI_UMEM_SLEEP		0x0
#define	DDI_UMEM_NOSLEEP	0x01
#define	DDI_UMEM_PAGEABLE	0x02
#define	DDI_UMEM_TRASH		0x04

/*
 * Flags to pass to ddi_umem_lock to indicate expected access pattern
 * DDI_UMEMLOCK_READ implies the memory being locked will be read
 * (e.g., data read from memory is written out to the disk or network)
 * DDI_UMEMLOCK_WRITE implies the memory being locked will be written
 * (e.g., data from the disk or network is written to memory)
 * Both flags may be set in the call to ddi_umem_lock,
 * Note that this corresponds to the VM subsystem definition of read/write
 * and also correspond to the prots set in devmap
 * When doing I/O, B_READ/B_WRITE are used which have exactly the opposite
 * meaning. Be careful when using it both for I/O and devmap
 *
 *
 */
#define	DDI_UMEMLOCK_READ	0x01
#define	DDI_UMEMLOCK_WRITE	0x02

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DDIDEVMAP_H */
