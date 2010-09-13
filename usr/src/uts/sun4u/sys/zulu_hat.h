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
 * Copyright 2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	__ZULU_HAT_INCL__
#define	__ZULU_HAT_INCL__

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

#define	ZULU_TTE8K		0
#define	ZULU_TTE64K		1
#define	ZULU_TTE512K		2
#define	ZULU_TTE4M		3
#define	ZULUM_MAX_PG_SIZES	4

#define	ZULU_CTX_MASK		0x1fff

#ifndef _ASM

#include <sys/types.h>
#include <sys/atomic.h>
#include <vm/xhat.h>
#include <sys/avl.h>


#define	ZULU_HAT_BP_SHIFT		13
#define	ZULU_HAT_SZ_SHIFT(sz)		((sz) * 3)
#define	ZULU_HAT_NUM_PGS(sz)		(1<<ZULU_HAT_SZ_SHIFT(sz))
#define	ZULU_HAT_PGSHIFT(s)		(ZULU_HAT_BP_SHIFT + \
					ZULU_HAT_SZ_SHIFT(s))
#define	ZULU_HAT_PGSZ(s)		((uint64_t)1<<ZULU_HAT_PGSHIFT(s))
#define	ZULU_HAT_PGOFFSET(s)		(ZULU_HAT_PGSZ(s) - 1)
#define	ZULU_HAT_PGMASK(s)		(~ZULU_HAT_PGOFFSET((uint64_t)s))
#define	ZULU_HAT_PGADDR(a, s)		((uintptr_t)(a) & ZULU_HAT_PGMASK(s))
#define	ZULU_HAT_PGADDROFF(a, s)	((uintptr_t)(a) & ZULU_HAT_PGOFFSET(s))
#define	ZULU_HAT_PGDIFF(a, s)		(ZULU_HAT_PGSZ(s) - \
					ZULU_HAT_PGADDROFF(a, s))

#define	ZULU_HAT_PFN_MASK(sz)		((1 << ZULU_HAT_SZ_SHIFT(sz)) - 1)
#define	ZULU_HAT_ADJ_PFN(ttep, vaddr) \
	((ttep->zulu_tte_pfn & ~ZULU_HAT_PFN_MASK(ttep->zulu_tte_size)) | \
	(((uintptr_t)vaddr >> ZULU_HAT_BP_SHIFT) & \
	ZULU_HAT_PFN_MASK(ttep->zulu_tte_size)))

/*
 * zulu_ctx_tab is an array of pointers to zulu hat structures.
 * since the addresses are 8 byte aligned we use bit 0 as a lock flag.
 * This will synchronize TL1 access to the tsb and the mappings.
 */

#define	ZULU_CTX_LOCK	0x1

#define	ZULU_CTX_LOCK_INIT(c)		zulu_ctx_tab[c] = NULL
#define	ZULU_CTX_IS_FREE(c)		(zulu_ctx_tab[c] == NULL)
#define	ZULU_CTX_SET_HAT(c, h) 		zulu_ctx_tab[c] = h

#define	ZULU_CTX_GET_HAT(c)	(struct zulu_hat *)((uint64_t) \
				    zulu_ctx_tab[c] & ~ZULU_CTX_LOCK)

struct zulu_tag {
	uint64_t	zulu_tag_page:51;	/* [63:13] vpage */
};

struct zulu_tte {
	union {
		struct zulu_tag zulu_tte_tag;
		uint64_t 	zulu_tte_addr;
	} un;
	uint_t	zulu_tte_valid  :1;
	uint_t	zulu_tte_perm   :1;
	uint_t	zulu_tte_size   :3;
	uint_t	zulu_tte_locked :1;
	uint_t	zulu_tte_pfn;
};

/*
 * zulu hat stores its list of translation in a hash table.
 * TODO: size this table. 256 buckets may be too small.
 */
#define	ZULU_HASH_TBL_NUM  0x100
#define	ZULU_HASH_TBL_MASK (ZULU_HASH_TBL_NUM - 1)
#define	ZULU_HASH_TBL_SHIFT(_s) (ZULU_HAT_BP_SHIFT + (3 * _s))
#define	ZULU_HASH_TBL_SZ  (ZULU_HASH_TBL_NUM * sizeof (struct zulu_hat_blk *))
#define	ZULU_MAP_HASH_VAL(_v, _s) (((_v) >> ZULU_HASH_TBL_SHIFT(_s)) & \
							ZULU_HASH_TBL_MASK)
#define	ZULU_MAP_HASH_HEAD(_zh, _v, _s) \
		(_zh->hash_tbl[ZULU_MAP_HASH_VAL(_v, _s)])

/*
 *
 * TODO: need finalize the number of entries in the TSB
 * 32K tsb entries caused us to never get a tsb miss that didn't cause
 * a page fault.
 *
 * Reducing TSB_NUM to 512 entries caused tsb_miss > tsb_hit
 * in a yoyo run.
 */
#define	ZULU_TSB_NUM		4096
#define	ZULU_TSB_SZ		(ZULU_TSB_NUM * sizeof (struct zulu_tte))
#define	ZULU_TSB_HASH(a, ts, s)	(((uintptr_t)(a) >> ZULU_HAT_PGSHIFT(ts)) & \
					(s-1))

#define	ZULU_VADDR(tag)		(tag & ~ZULU_CTX_MASK)
#define	ZULU_TTE_TO_PAGE(a)	a.un.zulu_tte_tag.zulu_tag_page


struct zulu_hat_blk {
	struct zulu_hat_blk	*zulu_hash_next;
	struct zulu_hat_blk	*zulu_hash_prev;
	struct zulu_shadow_blk  *zulu_shadow_blk;
	struct zulu_tte		zulu_hat_blk_tte;
};

#define	zulu_hat_blk_vaddr	zulu_hat_blk_tte.un.zulu_tte_addr
#define	zulu_hat_blk_pfn	zulu_hat_blk_tte.zulu_tte_pfn
#define	zulu_hat_blk_page	ZULU_TTE_TO_PAGE(zulu_hat_blk_tte)
#define	zulu_hat_blk_perm	zulu_hat_blk_tte.zulu_tte_perm
#define	zulu_hat_blk_size	zulu_hat_blk_tte.zulu_tte_size
#define	zulu_hat_blk_valid	zulu_hat_blk_tte.zulu_tte_valid

/*
 * for fast lookups by address, len we use an avl list to shadow occupied
 * 4Mb regions that have mappings.
 */
#define	ZULU_SHADOW_BLK_RANGE 0x400000
#define	ZULU_SHADOW_BLK_MASK (~(ZULU_SHADOW_BLK_RANGE - 1))

struct zulu_shadow_blk {
	avl_node_t	link;		/* must be at beginning of struct */
	uint64_t	ivaddr;		/* base address of this node */
	uint64_t	ref_count;
	uint64_t	min_addr;
	uint64_t	max_addr;
};
#define	ZULU_SHADOW_BLK_LINK_OFFSET (0)

struct zulu_hat {
	struct xhat		zulu_xhat;
	kmutex_t		lock;
	avl_tree_t		shadow_tree;
	char			magic;	    /* =42 to mark our data for mdb */
	unsigned		in_fault  : 1;
	unsigned		freed	  : 1;
	unsigned		map8k	  : 1;
	unsigned		map64k	  : 1;
	unsigned		map512k	  : 1;
	unsigned		map4m	  : 1;
	short			zulu_ctx;
	unsigned short		zulu_tsb_size;	/* TODO why not a constant? */
	struct zulu_hat_blk	**hash_tbl;
	struct zulu_tte 	*zulu_tsb;
	struct zulu_shadow_blk	*sblk_last;	/* last sblk looked up */
	uint64_t		fault_ivaddr_last; /* last translation loaded */
	caddr_t			vaddr_max;
	hrtime_t		last_used;
	void			*zdev;
};

#define	ZULU_HAT2AS(h)	((h)->zulu_xhat.xhat_as)

/*
 * Assembly language function for TSB lookups
 */
uint64_t zulu_hat_tsb_lookup_tl0(struct zulu_hat *zhat, caddr_t vaddr);

/*
 * zuluvm's interface to zulu_hat
 */

int zulu_hat_load(struct zulu_hat *zhat, caddr_t vaddr, enum seg_rw rw, int *);

int zulu_hat_init();
int zulu_hat_destroy();
int zulu_hat_attach(void *arg);
int zulu_hat_detach(void *arg);
struct zulu_hat *zulu_hat_proc_attach(struct as *as, void *zdev);
void zulu_hat_proc_detach(struct zulu_hat *zhat);

void zulu_hat_validate_ctx(struct zulu_hat *zhat);
void zulu_hat_terminate(struct zulu_hat *zhat);

#endif /* _ASM */

#ifdef	__cplusplus
}
#endif

#endif	/* __ZULU_HAT_INCL__ */
