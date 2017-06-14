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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved	*/

/*
 * University Copyright- Copyright (c) 1982, 1986, 1988
 * The Regents of the University of California
 * All Rights Reserved
 *
 * University Acknowledgment- Portions of this document are derived from
 * software developed by the University of California, Berkeley, and its
 * contributors.
 */

#ifndef	_VM_SEG_DEV_H
#define	_VM_SEG_DEV_H

#ifdef	__cplusplus
extern "C" {
#endif

struct proc;

/*
 * Structure whose pointer is passed to the segdev_create routine
 */
struct segdev_crargs {
	offset_t	offset;		/* starting offset */
	int	(*mapfunc)(dev_t dev, off_t off, int prot); /* map function */
	dev_t	dev;		/* device number */
	uchar_t	type;		/* type of sharing done */
	uchar_t	prot;		/* protection */
	uchar_t	maxprot;	/* maximum protection */
	uint_t	hat_attr;	/* hat attr */
	uint_t	hat_flags;	/* currently, hat_flags is used ONLY for */
				/* HAT_LOAD_NOCONSIST; in future, it can be */
				/* expanded to include any flags that are */
				/* not already part of hat_attr */
	void    *devmap_data;   /* devmap_handle private data */
};

/*
 * (Semi) private data maintained by the seg_dev driver per segment mapping
 *
 * The segment lock is necessary to protect fields that are modified
 * when the "read" version of the address space lock is held.  This lock
 * is not needed when the segment operation has the "write" version of
 * the address space lock (it would be redundant).
 *
 * The following fields in segdev_data are read-only when the address
 * space is "read" locked, and don't require the segment lock:
 *
 *	vp
 *	offset
 *	mapfunc
 *	maxprot
 */
struct	segdev_data {
	offset_t	offset;		/* device offset for start of mapping */
	krwlock_t	lock;		/* protects segdev_data */
	int	(*mapfunc)(dev_t dev, off_t off, int prot);
	struct	vnode *vp;	/* vnode associated with device */
	uchar_t	pageprot;	/* true if per page protections present */
	uchar_t	prot;		/* current segment prot if pageprot == 0 */
	uchar_t	maxprot;	/* maximum segment protections */
	uchar_t	type;		/* type of sharing done */
	struct	vpage *vpage;	/* per-page information, if needed */
	uint_t	hat_attr;	/* hat attr - pass to attr in hat_devload */
	uint_t	hat_flags;	/* set HAT_LOAD_NOCONSIST flag in hat_devload */
				/* see comments above in segdev_crargs */
	size_t	softlockcnt;	/* # of SOFTLOCKED in seg */
	void    *devmap_data;   /* devmap_handle private data */
};

/* Direct physical-userland mapping, without occupying kernel address space */
#define	DEVMAP_PMEM_COOKIE	((ddi_umem_cookie_t)0x2)

/*
 * pmem_cookie:
 * Records physical memory pages to be exported to userland.
 */
struct devmap_pmem_cookie {
	pgcnt_t	dp_npages;		/* number of allocated mem pages */
	page_t  **dp_pparray;		/* pages allocated for this cookie */
	vnode_t *dp_vnp;		/* vnode associated with this cookie */
	proc_t *dp_proc;		/* proc ptr for resource control */
};

#ifdef _KERNEL

/*
 * Mappings of /dev/null come from segdev and have no mapping type.
 */

#define	SEG_IS_DEVNULL_MAPPING(seg)	\
	((seg)->s_ops == &segdev_ops &&	\
	((SEGOP_GETTYPE(seg, (seg)->s_base) & (MAP_SHARED | MAP_PRIVATE)) == 0))

extern void segdev_init(void);

extern int segdev_create(struct seg *, void *);

extern int segdev_copyto(struct seg *, caddr_t, const void *, void *, size_t);
extern int segdev_copyfrom(struct seg *, caddr_t, const void *, void *, size_t);
extern struct seg_ops segdev_ops;

#endif	/* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif	/* _VM_SEG_DEV_H */
