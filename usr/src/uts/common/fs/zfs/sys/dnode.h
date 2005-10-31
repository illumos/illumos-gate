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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_SYS_DNODE_H
#define	_SYS_DNODE_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/zfs_context.h>
#include <sys/avl.h>
#include <sys/spa.h>
#include <sys/txg.h>
#include <sys/refcount.h>
#include <sys/dmu_zfetch.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Flags.
 */
#define	DNODE_MUST_BE_ALLOCATED	1
#define	DNODE_MUST_BE_FREE	2

/*
 * Fixed constants.
 */
#define	DNODE_SHIFT		9	/* 512 bytes */
#define	DN_MIN_INDBLKSHIFT	10	/* 1k */
#define	DN_MAX_INDBLKSHIFT	14	/* 16k */
#define	DNODE_BLOCK_SHIFT	14	/* 16k */
#define	DNODE_CORE_SIZE		64	/* 64 bytes for dnode sans blkptrs */
#define	DN_MAX_OBJECT_SHIFT	48	/* 256 trillion (zfs_fid_t limit) */
#define	DN_MAX_OFFSET_SHIFT	64	/* 2^64 bytes in a dnode */

/*
 * Derived constants.
 */
#define	DNODE_SIZE	(1 << DNODE_SHIFT)
#define	DN_MAX_NBLKPTR	((DNODE_SIZE - DNODE_CORE_SIZE) >> SPA_BLKPTRSHIFT)
#define	DN_MAX_BONUSLEN	(DNODE_SIZE - DNODE_CORE_SIZE - (1 << SPA_BLKPTRSHIFT))

#define	DNODES_PER_BLOCK_SHIFT	(DNODE_BLOCK_SHIFT - DNODE_SHIFT)
#define	DNODES_PER_BLOCK	(1ULL << DNODES_PER_BLOCK_SHIFT)
#define	DNODES_PER_LEVEL_SHIFT	(DN_MAX_INDBLKSHIFT - SPA_BLKPTRSHIFT)

#define	DN_META_DNODE_LEVELS	\
	(1 + (DN_MAX_OBJECT_SHIFT - DNODE_SHIFT + SPA_BLKPTRSHIFT -	\
	DNODES_PER_BLOCK_SHIFT) / DNODES_PER_LEVEL_SHIFT)

/* The +2 here is a cheesy way to round up */
#define	DN_MAX_LEVELS	(2 + ((DN_MAX_OFFSET_SHIFT - SPA_MINBLOCKSHIFT) / \
	(DN_MIN_INDBLKSHIFT - SPA_BLKPTRSHIFT)))

#define	DN_MAX_OBJECT		\
	((uint64_t)DN_MAX_NBLKPTR << (DNODES_PER_BLOCK_SHIFT +	\
	(DN_META_DNODE_LEVELS - 1) * DNODES_PER_LEVEL_SHIFT))

#define	DN_BONUS(dnp)	((void*)((dnp)->dn_bonus + \
	(((dnp)->dn_nblkptr - 1) * sizeof (blkptr_t))))

#define	EPB(blkshift, typeshift)	(1 << (blkshift - typeshift))

struct dmu_buf_impl;
struct objset_impl;
struct zio;

enum dnode_dirtycontext {
	DN_UNDIRTIED,
	DN_DIRTY_OPEN,
	DN_DIRTY_SYNC
};

typedef struct dnode_phys {
	uint8_t dn_type;		/* dmu_object_type_t */
	uint8_t dn_indblkshift;		/* ln2(indirect block size) */
	uint8_t dn_nlevels;		/* 1=dn_blkptr->data blocks */
	uint8_t dn_nblkptr;		/* length of dn_blkptr */
	uint8_t dn_bonustype;		/* type of data in bonus buffer */
	uint8_t	dn_checksum;		/* ZIO_CHECKSUM type */
	uint8_t	dn_compress;		/* ZIO_COMPRESS type */
	uint8_t dn_pad1[1];
	uint16_t dn_datablkszsec;	/* data block size in 512b sectors */
	uint16_t dn_bonuslen;		/* length of dn_bonus */
	uint8_t dn_pad2[4];

	/* accounting is protected by dn_dirty_mtx */
	uint64_t dn_maxblkid;		/* largest allocated block ID */
	uint64_t dn_secphys;		/* 512b sectors of disk space used */

	uint64_t dn_pad3[4];

	blkptr_t dn_blkptr[1];
	uint8_t dn_bonus[DN_MAX_BONUSLEN];
} dnode_phys_t;

typedef struct dnode {
	/*
	 * lock ordering:
	 *
	 * db_mtx > dn_dirty_mtx
	 * 	dbuf_syncdone
	 *
	 * dn_struct_rwlock/r > dn_dirty_mtx
	 * 	dmu_object_info
	 *
	 * dn_struct_rwlock/r > db_mtx > dn_dirty_mtx
	 * 	dbuf_dirty
	 * 	dbuf_setdirty
	 *
	 * dn_struct_rwlock/w > db_mtx > dn_mtx
	 * 	dnode_increase_indirection -> dbuf_find
	 * 	dbuf_hold_impl
	 * 	dnode_set_bonus
	 *
	 * dn_struct_rwlock/w > dn_mtx
	 * 	dnode_increase_indirection
	 *
	 * dn_dirty_mtx > dn_mtx
	 * 	dnode_buf_pageout
	 *
	 * db_mtx > dn_mtx
	 * 	dbuf_create
	 */

	/*
	 * dn_struct_rwlock protects the structure of the dnode.
	 * In particular, it protects the number of levels of indirection.
	 */
	krwlock_t dn_struct_rwlock;

	/*
	 * Our link on dataset's dd_dnodes list.
	 * Protected by dd_accounting_mtx.
	 */
	list_node_t dn_link;

	/* immutable: */
	struct objset_impl *dn_objset;
	uint64_t dn_object;
	struct dmu_buf_impl *dn_dbuf;
	dnode_phys_t *dn_phys; /* pointer into dn->dn_dbuf->db.db_data */

	/*
	 * Copies of stuff in dn_phys.  They're valid here even before
	 * the dnode is first synced.
	 */
	dmu_object_type_t dn_type;	/* object type (immutable) */
	uint8_t dn_bonustype;		/* bonus type (immutable) */
	uint16_t dn_bonuslen;		/* bonus length (immutable) */
	uint8_t dn_nblkptr;		/* number of blkptrs (immutable) */
	uint8_t dn_datablkshift;	/* zero if blksz not power of 2! */
	uint32_t dn_datablksz;		/* in bytes */
	uint16_t dn_datablkszsec;	/* in 512b sectors */

	uint8_t dn_checksum;		/* ZIO_CHECKSUM type */
	uint8_t dn_compress;		/* ZIO_COMPRESS type */

	/*
	 * The following are kept up-to-date in the *open* context, the syncing
	 * context should only pay attention to the dn_next_* values.
	 */
	uint8_t dn_nlevels;
	uint8_t dn_indblkshift;

	uint8_t dn_next_nlevels[TXG_SIZE];
	uint8_t dn_next_indblkshift[TXG_SIZE];

	/* protected by os_lock: */
	uint32_t dn_dirtyblksz[TXG_SIZE];	/* dirty block size in bytes */
	list_node_t dn_dirty_link[TXG_SIZE];	/* next on dataset's dirty */

	/* protected by dn_mtx: */
	kmutex_t dn_mtx;
	list_t dn_dirty_dbufs[TXG_SIZE];
	uint64_t dn_maxblkid;
	avl_tree_t dn_ranges[TXG_SIZE];
	uint64_t dn_allocated_txg;
	uint64_t dn_free_txg;
	uint64_t dn_assigned_txg;
	struct dmu_tx *dn_assigned_tx;		/* if only one tx cares */
	kcondvar_t dn_notxholds;
	enum dnode_dirtycontext dn_dirtyctx;
	uint8_t *dn_dirtyctx_firstset;		/* dbg: contents meaningless */

	/* protected by own devices */
	refcount_t dn_tx_holds;
	refcount_t dn_holds;

	kmutex_t dn_dbufs_mtx;
	list_t dn_dbufs;		/* linked list of descendent dbuf_t's */
	kcondvar_t dn_evicted;		/* a child dbuf has been evicted */

	/*
	 * Performance hack: whenever we have a hold on the bonus buffer of a
	 * ZAP object, we will also have a hold on db0.  This will keep the
	 * meta-data for a micro-zap object cached as long as the znode for the
	 * object is in the znode cache.
	 */
	struct dmu_buf_impl *dn_db0;

	/* holds prefetch structure */
	struct zfetch	dn_zfetch;
} dnode_t;

typedef struct free_range {
	avl_node_t fr_node;
	uint64_t fr_blkid;
	uint64_t fr_nblks;
} free_range_t;

dnode_t *dnode_special_open(struct objset_impl *dd, dnode_phys_t *dnp,
    uint64_t object);
void dnode_special_close(dnode_t *dn);

dnode_t *dnode_hold(struct objset_impl *dd, uint64_t object, void *ref);
dnode_t *dnode_hold_impl(struct objset_impl *dd, uint64_t object, int flag,
    void *ref);
void dnode_add_ref(dnode_t *dn, void *ref);
void dnode_rele(dnode_t *dn, void *ref);
void dnode_setdirty(dnode_t *dn, dmu_tx_t *tx);
int dnode_sync(dnode_t *dn, int level, struct zio *zio, dmu_tx_t *tx);
void dnode_allocate(dnode_t *dn, dmu_object_type_t ot, int blocksize, int ibs,
    dmu_object_type_t bonustype, int bonuslen, dmu_tx_t *tx);
void dnode_reallocate(dnode_t *dn, dmu_object_type_t ot, int blocksize,
    dmu_object_type_t bonustype, int bonuslen, dmu_tx_t *tx);
void dnode_free(dnode_t *dn, dmu_tx_t *tx);
void dnode_byteswap(dnode_phys_t *dnp);
void dnode_buf_byteswap(void *buf, size_t size);
void dnode_verify(dnode_t *dn);
int dnode_set_blksz(dnode_t *dn, uint64_t size, int ibs, dmu_tx_t *tx);
uint64_t dnode_current_max_length(dnode_t *dn);
uint64_t dnode_max_nonzero_offset(dnode_t *dn);
void dnode_free_range(dnode_t *dn, uint64_t off, uint64_t len, dmu_tx_t *tx);
void dnode_clear_range(dnode_t *dn, uint64_t blkid,
    uint64_t nblks, dmu_tx_t *tx);
void dnode_diduse_space(dnode_t *dn, int64_t space);
void dnode_willuse_space(dnode_t *dn, int64_t space, dmu_tx_t *tx);
void dnode_new_blkid(dnode_t *dn, uint64_t blkid, dmu_tx_t *tx);
uint64_t dnode_block_freed(dnode_t *dn, uint64_t blkid);
void dnode_init(void);
void dnode_fini(void);
int dnode_next_offset(dnode_t *dn, boolean_t hole, uint64_t *off, int minlvl,
    uint64_t blkfill);

#ifdef ZFS_DEBUG

/*
 * There should be a ## between the string literal and fmt, to make it
 * clear that we're joining two strings together, but that piece of shit
 * gcc doesn't support that preprocessor token.
 */
#define	dprintf_dnode(dn, fmt, ...) do { \
	if (zfs_flags & ZFS_DEBUG_DPRINTF) { \
	char __db_buf[32]; \
	uint64_t __db_obj = (dn)->dn_object; \
	if (__db_obj == DMU_META_DNODE_OBJECT) \
		(void) strcpy(__db_buf, "mdn"); \
	else \
		(void) snprintf(__db_buf, sizeof (__db_buf), "%lld", \
		    (u_longlong_t)__db_obj);\
	dprintf_ds((dn)->dn_objset->os_dsl_dataset, "obj=%s " fmt, \
	    __db_buf, __VA_ARGS__); \
	} \
_NOTE(CONSTCOND) } while (0)

#else

#define	dprintf_dnode(db, fmt, ...)

#endif

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_DNODE_H */
