/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_FSSNAP_H
#define	_SYS_FSSNAP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/sysmacros.h>
#include <sys/devops.h>

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/buf.h>
#include <sys/taskq.h>
#include <sys/fs/ufs_inode.h>

/* snapshot backend interfaces, macros, and data structures */

#if defined(_KERNEL)

/*
 * defines for the number of threads used to handle tasks, the maximum
 * number of chunks in memory at a time, and the maximum number of tasks to
 * allow before the taskqs start throttling. MAXTASKS should be greater than
 * or equal to MAX_MEM_CHUNKS.
 */
#define	FSSNAP_TASKQ_THREADS	(2)
#define	FSSNAP_MAX_MEM_CHUNKS	(32)
#define	FSSNAP_TASKQ_MAXTASKS	(FSSNAP_MAX_MEM_CHUNKS)

/*
 * It is assumed that a chunk is a multiple of a disk sector so that
 * the chunk size can be reduced before using it as a conversion
 * factor.  Therefore the number of chunks on a file system will
 * always be less than the number of blocks it occupies, and these
 * conversions will not overflow. (do not convert to bytes first!)
 */

typedef unsigned long long	chunknumber_t;

/* disk blocks to snapshot chunks */
#define	dbtocowchunk(cmap, dblkno) ((dblkno) / \
	((cmap)->cmap_chunksz >> DEV_BSHIFT))

/* snapshot chunks to disk blocks */
#define	cowchunktodb(cmap, cowchunk) ((cowchunk) * \
	((cmap)->cmap_chunksz >> DEV_BSHIFT))

/*
 * A snapshot_id is the shared structure between the snapshot driver
 * and the file system.
 */
typedef struct snapshot_id {
	struct snapshot_id	*sid_next;	/* next snapshot in list */
	krwlock_t		sid_rwlock;	/* protects enable/disable */
	struct cow_info		*sid_cowinfo;	/* pointer to cow state */
	uint_t			sid_snapnumber;	/* snapshot number */
	uint_t			sid_flags;	/* general flags */
	struct vnode		*sid_fvp;	/* root vnode to snapshot */
} snapshot_id_t;

/* snapshot_id flags */
#define	SID_DISABLED	(0x01)	/* this snapshot has been disabled */
#define	SID_DISABLING	(0x02)	/* this snapshot is being disabled */
#define	SID_BLOCK_BUSY	(0x04)	/* snapshot block driver is attached */
#define	SID_CHAR_BUSY	(0x08)	/* snapshot character driver is attached */
#define	SID_CREATING	(0x10)	/* snapshot is being created */
#define	SID_DELETE	(0x20)	/* error condition found, delete snapshot */

/* true if snapshot device is open */
#define	SID_BUSY(sidp)	(((sidp)->sid_flags & SID_BLOCK_BUSY) || \
	((sidp)->sid_flags & SID_CHAR_BUSY))

/* true if snapshot can not be used */
#define	SID_INACTIVE(sidp)	(((sidp)->sid_flags & SID_DISABLED) || \
	((sidp)->sid_flags & SID_DISABLING) || \
	((sidp)->sid_flags & SID_CREATING) || \
	((sidp)->sid_flags & SID_DELETE) || \
	((sidp)->sid_cowinfo == NULL))

/* true if snapshot can be reused now */
#define	SID_AVAILABLE(sidp)	(!SID_BUSY(sidp) && \
	((sidp)->sid_flags & SID_DISABLED))

/*
 * The cow_map keeps track of all translations, and two bitmaps to
 * determine whether the chunk is eligible for translation, and if so
 * whether or not it already has a translation.  The candidate bitmap
 * is read-only and does not require a lock, the hastrans bitmap and
 * the translation table are protected by the cmap_rwlock.
 */
typedef struct cow_map {
	krwlock_t	cmap_rwlock;	/* protects this structure */
	ksema_t		cmap_throttle_sem; /* used to throttle writes */
	uint32_t	cmap_waiters;	/* semaphore waiters */
	uint_t		cmap_chunksz;	/* granularity of COW operations */
	chunknumber_t	cmap_chunksperbf; /* chunks in max backing file */
	chunknumber_t	cmap_nchunks;	/* number of chunks in backing file */
	u_offset_t	cmap_maxsize;	/* max bytes allowed (0 is no limit) */
	size_t		cmap_bmsize;	/* size of bitmaps (in bytes) */
	caddr_t		cmap_candidate;	/* 1 = block is a candidate for COW */
	caddr_t		cmap_hastrans;	/* 1 = an entry exists in the table */
	struct cow_map_node	*cmap_table;	/* translation table */
} cow_map_t;

/*
 * The cow_map_node keeps track of chunks that are still in memory.
 */

typedef struct cow_map_node {
	struct cow_map_node	*cmn_next;
	struct cow_map_node	*cmn_prev;
	struct snapshot_id	*cmn_sid;	/* backpointer to snapshot */
	chunknumber_t		cmn_chunk;	/* original chunk number */
	caddr_t			cmn_buf;	/* the data itself */
	int			release_sem;	/* flag to release */
						/* cmap_throttle_sem */
} cow_map_node_t;

/*
 * The cow_info structure holds basic snapshot state information. It is
 * mostly read-only once the snapshot is created so no locking is required.
 * The exception is cow_nextchunk, which is ever-increasing and updated with
 * atomic_add(). This structure is allocated dynamically, and creation and
 * deletion of the snapshot is protected by the snapshot_mutex variable.
 */
typedef struct cow_info {
	int		cow_backcount;	/* number of backing files */
	vnode_t		**cow_backfile_array; /* array of backing files */
	u_offset_t	cow_backfile_sz;	/* max size of a backfile */
	taskq_t		*cow_taskq;	/* task queue for async writes */
	struct kstat	*cow_kstat_mntpt;	/* kstat for mount point */
	struct kstat	*cow_kstat_bfname;	/* kstat for backing file */
	struct kstat	*cow_kstat_num;	/* named numeric kstats */
	struct cow_map	cow_map;	/* block translation table */
} cow_info_t;

/* kstat information */
struct cow_kstat_num {
	kstat_named_t	ckn_state;	/* state of the snapshot device */
	kstat_named_t	ckn_bfsize;	/* sum of sizes of backing files */
	kstat_named_t	ckn_maxsize;	/* maximum backing file size */
	kstat_named_t	ckn_createtime;	/* snapshot creation time */
	kstat_named_t	ckn_chunksize;	/* chunk size */
};

/* ckn_state values */
#define	COWSTATE_CREATING	(0)	/* snapshot being created */
#define	COWSTATE_IDLE		(1)	/* snapshot exists, but not open */
#define	COWSTATE_ACTIVE		(2)	/* snapshot open */
#define	COWSTATE_DISABLED	(3)	/* snapshot deleted (pending close) */

extern	uint_t	bypass_snapshot_throttle_key;

#endif /* _KERNEL */

#ifdef	__cplusplus
}
#endif

#endif /* _SYS_FSSNAP_H */
