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

#ifndef _SYS_SPA_H
#define	_SYS_SPA_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/avl.h>
#include <sys/zfs_context.h>
#include <sys/nvpair.h>
#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/fs/zfs.h>

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Forward references that lots of things need.
 */
typedef struct spa spa_t;
typedef struct vdev vdev_t;
typedef struct metaslab metaslab_t;
typedef struct zilog zilog_t;
typedef struct traverse_handle traverse_handle_t;
struct dsl_pool;

/*
 * General-purpose 32-bit and 64-bit bitfield encodings.
 */
#define	BF32_DECODE(x, low, len)	P2PHASE((x) >> (low), 1U << (len))
#define	BF64_DECODE(x, low, len)	P2PHASE((x) >> (low), 1ULL << (len))
#define	BF32_ENCODE(x, low, len)	(P2PHASE((x), 1U << (len)) << (low))
#define	BF64_ENCODE(x, low, len)	(P2PHASE((x), 1ULL << (len)) << (low))

#define	BF32_GET(x, low, len)		BF32_DECODE(x, low, len)
#define	BF64_GET(x, low, len)		BF64_DECODE(x, low, len)

#define	BF32_SET(x, low, len, val)	\
	((x) ^= BF32_ENCODE((x >> low) ^ val, low, len))
#define	BF64_SET(x, low, len, val)	\
	((x) ^= BF64_ENCODE((x >> low) ^ val, low, len))

#define	BF32_GET_SB(x, low, len, shift, bias)	\
	((BF32_GET(x, low, len) + (bias)) << (shift))
#define	BF64_GET_SB(x, low, len, shift, bias)	\
	((BF64_GET(x, low, len) + (bias)) << (shift))

#define	BF32_SET_SB(x, low, len, shift, bias, val)	\
	BF32_SET(x, low, len, ((val) >> (shift)) - (bias))
#define	BF64_SET_SB(x, low, len, shift, bias, val)	\
	BF64_SET(x, low, len, ((val) >> (shift)) - (bias))

/*
 * We currently support nine block sizes, from 512 bytes to 128K.
 * We could go higher, but the benefits are near-zero and the cost
 * of COWing a giant block to modify one byte would become excessive.
 */
#define	SPA_MINBLOCKSHIFT	9
#define	SPA_MAXBLOCKSHIFT	17
#define	SPA_MINBLOCKSIZE	(1ULL << SPA_MINBLOCKSHIFT)
#define	SPA_MAXBLOCKSIZE	(1ULL << SPA_MAXBLOCKSHIFT)

#define	SPA_BLOCKSIZES		(SPA_MAXBLOCKSHIFT - SPA_MINBLOCKSHIFT + 1)

/*
 * The DVA size encodings for LSIZE and PSIZE support blocks up to 32MB.
 * The ASIZE encoding should be at least 64 times larger (6 more bits)
 * to support up to 4-way RAID-Z mirror mode with worst-case gang block
 * overhead, three DVAs per bp, plus one more bit in case we do anything
 * else that expands the ASIZE.
 */
#define	SPA_LSIZEBITS		16	/* LSIZE up to 32M (2^16 * 512)	*/
#define	SPA_PSIZEBITS		16	/* PSIZE up to 32M (2^16 * 512)	*/
#define	SPA_ASIZEBITS		24	/* ASIZE up to 64 times larger	*/

/*
 * All SPA data is represented by 128-bit data virtual addresses (DVAs).
 * The members of the dva_t should be considered opaque outside the SPA.
 */
typedef struct dva {
	uint64_t	dva_word[2];
} dva_t;

/*
 * Each block has a 256-bit checksum -- strong enough for cryptographic hashes.
 */
typedef struct zio_cksum {
	uint64_t	zc_word[4];
} zio_cksum_t;

/*
 * Each block is described by its DVAs, time of birth, checksum, etc.
 * The word-by-word, bit-by-bit layout of the blkptr is as follows:
 *
 *	64	56	48	40	32	24	16	8	0
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * 0	|		vdev1		| GRID  |	  ASIZE		|
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * 1	|G|			 offset1				|
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * 2	|		vdev2		| GRID  |	  ASIZE		|
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * 3	|G|			 offset2				|
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * 4	|		vdev3		| GRID  |	  ASIZE		|
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * 5	|G|			 offset3				|
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * 6	|E| lvl | type	| cksum | comp	|     PSIZE	|     LSIZE	|
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * 7	|			padding					|
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * 8	|			padding					|
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * 9	|			padding					|
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * a	|			birth txg				|
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * b	|			fill count				|
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * c	|			checksum[0]				|
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * d	|			checksum[1]				|
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * e	|			checksum[2]				|
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 * f	|			checksum[3]				|
 *	+-------+-------+-------+-------+-------+-------+-------+-------+
 *
 * Legend:
 *
 * vdev		virtual device ID
 * offset	offset into virtual device
 * LSIZE	logical size
 * PSIZE	physical size (after compression)
 * ASIZE	allocated size (including RAID-Z parity and gang block headers)
 * GRID		RAID-Z layout information (reserved for future use)
 * cksum	checksum function
 * comp		compression function
 * G		gang block indicator
 * E		endianness
 * type		DMU object type
 * lvl		level of indirection
 * birth txg	transaction group in which the block was born
 * fill count	number of non-zero blocks under this bp
 * checksum[4]	256-bit checksum of the data this bp describes
 */
typedef struct blkptr {
	dva_t		blk_dva[3];	/* 128-bit Data Virtual Address	*/
	uint64_t	blk_prop;	/* size, compression, type, etc	*/
	uint64_t	blk_pad[3];	/* Extra space for the future	*/
	uint64_t	blk_birth;	/* transaction group at birth	*/
	uint64_t	blk_fill;	/* fill count			*/
	zio_cksum_t	blk_cksum;	/* 256-bit checksum		*/
} blkptr_t;

#define	SPA_BLKPTRSHIFT	7		/* blkptr_t is 128 bytes	*/
#define	SPA_DVAS_PER_BP	3		/* Number of DVAs in a bp	*/

/*
 * Macros to get and set fields in a bp or DVA.
 */
#define	DVA_GET_ASIZE(dva)	\
	BF64_GET_SB((dva)->dva_word[0], 0, 24, SPA_MINBLOCKSHIFT, 0)
#define	DVA_SET_ASIZE(dva, x)	\
	BF64_SET_SB((dva)->dva_word[0], 0, 24, SPA_MINBLOCKSHIFT, 0, x)

#define	DVA_GET_GRID(dva)	BF64_GET((dva)->dva_word[0], 24, 8)
#define	DVA_SET_GRID(dva, x)	BF64_SET((dva)->dva_word[0], 24, 8, x)

#define	DVA_GET_VDEV(dva)	BF64_GET((dva)->dva_word[0], 32, 32)
#define	DVA_SET_VDEV(dva, x)	BF64_SET((dva)->dva_word[0], 32, 32, x)

#define	DVA_GET_OFFSET(dva)	\
	BF64_GET_SB((dva)->dva_word[1], 0, 63, SPA_MINBLOCKSHIFT, 0)
#define	DVA_SET_OFFSET(dva, x)	\
	BF64_SET_SB((dva)->dva_word[1], 0, 63, SPA_MINBLOCKSHIFT, 0, x)

#define	DVA_GET_GANG(dva)	BF64_GET((dva)->dva_word[1], 63, 1)
#define	DVA_SET_GANG(dva, x)	BF64_SET((dva)->dva_word[1], 63, 1, x)

#define	BP_GET_LSIZE(bp)	\
	(BP_IS_HOLE(bp) ? 0 : \
	BF64_GET_SB((bp)->blk_prop, 0, 16, SPA_MINBLOCKSHIFT, 1))
#define	BP_SET_LSIZE(bp, x)	\
	BF64_SET_SB((bp)->blk_prop, 0, 16, SPA_MINBLOCKSHIFT, 1, x)

#define	BP_GET_PSIZE(bp)	\
	BF64_GET_SB((bp)->blk_prop, 16, 16, SPA_MINBLOCKSHIFT, 1)
#define	BP_SET_PSIZE(bp, x)	\
	BF64_SET_SB((bp)->blk_prop, 16, 16, SPA_MINBLOCKSHIFT, 1, x)

#define	BP_GET_COMPRESS(bp)	BF64_GET((bp)->blk_prop, 32, 8)
#define	BP_SET_COMPRESS(bp, x)	BF64_SET((bp)->blk_prop, 32, 8, x)

#define	BP_GET_CHECKSUM(bp)	BF64_GET((bp)->blk_prop, 40, 8)
#define	BP_SET_CHECKSUM(bp, x)	BF64_SET((bp)->blk_prop, 40, 8, x)

#define	BP_GET_TYPE(bp)		BF64_GET((bp)->blk_prop, 48, 8)
#define	BP_SET_TYPE(bp, x)	BF64_SET((bp)->blk_prop, 48, 8, x)

#define	BP_GET_LEVEL(bp)	BF64_GET((bp)->blk_prop, 56, 5)
#define	BP_SET_LEVEL(bp, x)	BF64_SET((bp)->blk_prop, 56, 5, x)

#define	BP_GET_BYTEORDER(bp)	(0 - BF64_GET((bp)->blk_prop, 63, 1))
#define	BP_SET_BYTEORDER(bp, x)	BF64_SET((bp)->blk_prop, 63, 1, x)

#define	BP_GET_ASIZE(bp)	\
	(DVA_GET_ASIZE(&(bp)->blk_dva[0]) + DVA_GET_ASIZE(&(bp)->blk_dva[1]) + \
	DVA_GET_ASIZE(&(bp)->blk_dva[2]))

#define	DVA_EQUAL(dva1, dva2)	\
	((dva1)->dva_word[1] == (dva2)->dva_word[1] && \
	(dva1)->dva_word[0] == (dva2)->dva_word[0])

#define	DVA_IS_VALID(dva)	(DVA_GET_ASIZE(dva) != 0)

#define	ZIO_SET_CHECKSUM(zcp, w0, w1, w2, w3)	\
{						\
	(zcp)->zc_word[0] = w0;			\
	(zcp)->zc_word[1] = w1;			\
	(zcp)->zc_word[2] = w2;			\
	(zcp)->zc_word[3] = w3;			\
}

#define	BP_IS_HOLE(bp)		((bp)->blk_birth == 0)

#define	BP_IDENTITY(bp)		(&(bp)->blk_dva[0])

#define	BP_ZERO(bp)				\
{						\
	(bp)->blk_dva[0].dva_word[0] = 0;	\
	(bp)->blk_dva[0].dva_word[1] = 0;	\
	(bp)->blk_dva[1].dva_word[0] = 0;	\
	(bp)->blk_dva[1].dva_word[1] = 0;	\
	(bp)->blk_dva[2].dva_word[0] = 0;	\
	(bp)->blk_dva[2].dva_word[1] = 0;	\
	(bp)->blk_prop = 0;			\
	(bp)->blk_pad[0] = 0;			\
	(bp)->blk_pad[1] = 0;			\
	(bp)->blk_pad[2] = 0;			\
	(bp)->blk_birth = 0;			\
	(bp)->blk_fill = 0;			\
	ZIO_SET_CHECKSUM(&(bp)->blk_cksum, 0, 0, 0, 0);	\
}

/*
 * Note: the byteorder is either 0 or -1, both of which are palindromes.
 * This simplifies the endianness handling a bit.
 */
#ifdef _BIG_ENDIAN
#define	ZFS_HOST_BYTEORDER	(0ULL)
#else
#define	ZFS_HOST_BYTEORDER	(-1ULL)
#endif

#define	BP_SHOULD_BYTESWAP(bp)	(BP_GET_BYTEORDER(bp) != ZFS_HOST_BYTEORDER)

#define	BP_SPRINTF_LEN	256

#include <sys/dmu.h>

/*
 * Routines found in spa.c
 */

/* state manipulation functions */
extern int spa_open(const char *pool, spa_t **, void *tag);
extern int spa_get_stats(const char *pool, nvlist_t **config);
extern int spa_create(const char *pool, nvlist_t *config, char *altroot);
extern int spa_import(const char *pool, nvlist_t *config, char *altroot);
extern nvlist_t *spa_tryimport(nvlist_t *tryconfig);
extern int spa_destroy(char *pool);
extern int spa_export(char *pool);

/* device manipulation */
extern int spa_vdev_add(spa_t *spa, nvlist_t *nvroot);
extern int spa_vdev_add_unlocked(spa_t *spa, nvlist_t *nvroot);
extern int spa_vdev_attach(spa_t *spa, const char *path, nvlist_t *nvroot,
    int replacing);
extern int spa_vdev_detach(spa_t *spa, const char *path, uint64_t guid,
    int replace_done);
extern void spa_vdev_replace_done(spa_t *spa);

/* scrubbing */
extern int spa_scrub(spa_t *spa, pool_scrub_type_t type, boolean_t force);
extern void spa_scrub_suspend(spa_t *spa);
extern void spa_scrub_resume(spa_t *spa);
extern void spa_scrub_restart(spa_t *spa, uint64_t txg);

/* spa syncing */
extern void spa_sync(spa_t *spa, uint64_t txg); /* only for DMU use */
extern void spa_sync_allpools(void);

/*
 * SPA configuration functions in spa_config.c
 */
extern void spa_config_sync(void);
extern void spa_config_load(void);
extern nvlist_t *spa_all_configs(uint64_t *);
extern void spa_config_set(spa_t *spa, nvlist_t *config);
extern nvlist_t *spa_config_generate(spa_t *spa, vdev_t *vd, uint64_t txg,
    int getstats);

/*
 * Miscellaneous SPA routines in spa_misc.c
 */

/* Namespace manipulation */
extern spa_t *spa_lookup(const char *name);
extern spa_t *spa_add(const char *name);
extern void spa_remove(spa_t *spa);
extern spa_t *spa_next(spa_t *prev);

/* Refcount functions */
extern void spa_open_ref(spa_t *spa, void *tag);
extern void spa_close(spa_t *spa, void *tag);
extern boolean_t spa_refcount_zero(spa_t *spa);

/* Pool configuration lock */
extern void spa_config_enter(spa_t *spa, krw_t rw);
extern void spa_config_exit(spa_t *spa);
extern boolean_t spa_config_held(spa_t *spa, krw_t rw);

/* Pool vdev add/remove lock */
extern uint64_t spa_vdev_enter(spa_t *spa);
extern int spa_vdev_exit(spa_t *spa, vdev_t *vd, uint64_t txg, int error);

/* Accessor functions */
extern krwlock_t *spa_traverse_rwlock(spa_t *spa);
extern int spa_traverse_wanted(spa_t *spa);
extern struct dsl_pool *spa_get_dsl(spa_t *spa);
extern blkptr_t *spa_get_rootblkptr(spa_t *spa);
extern void spa_set_rootblkptr(spa_t *spa, const blkptr_t *bp);
extern void spa_altroot(spa_t *, char *, size_t);
extern int spa_sync_pass(spa_t *spa);
extern char *spa_name(spa_t *spa);
extern uint64_t spa_guid(spa_t *spa);
extern uint64_t spa_last_synced_txg(spa_t *spa);
extern uint64_t spa_first_txg(spa_t *spa);
extern int spa_state(spa_t *spa);
extern uint64_t spa_freeze_txg(spa_t *spa);
struct metaslab_class;
extern struct metaslab_class *spa_metaslab_class_select(spa_t *spa);
extern uint64_t spa_get_alloc(spa_t *spa);
extern uint64_t spa_get_space(spa_t *spa);
extern uint64_t spa_get_asize(spa_t *spa, uint64_t lsize);
extern int spa_busy(void);

/* Miscellaneous support routines */
extern int spa_rename(const char *oldname, const char *newname);
extern boolean_t spa_guid_exists(uint64_t pool_guid, uint64_t device_guid);
extern char *spa_strdup(const char *);
extern void spa_strfree(char *);
extern uint64_t spa_get_random(uint64_t range);
extern void sprintf_blkptr(char *buf, int len, blkptr_t *bp);
extern void spa_freeze(spa_t *spa);
extern void spa_evict_all(void);

/* Initialization and termination */
extern void spa_init(int flags);
extern void spa_fini(void);

#ifdef ZFS_DEBUG
#define	dprintf_bp(bp, fmt, ...) do {			\
	if (zfs_flags & ZFS_DEBUG_DPRINTF) { 		\
	char __blkbuf[BP_SPRINTF_LEN];			\
	sprintf_blkptr(__blkbuf, BP_SPRINTF_LEN, (bp));	\
	dprintf(fmt " %s\n", __VA_ARGS__, __blkbuf);	\
	} \
_NOTE(CONSTCOND) } while (0)
#else
#define	dprintf_bp(bp, fmt, ...)
#endif

extern int spa_mode;			/* mode, e.g. FREAD | FWRITE */

#ifdef	__cplusplus
}
#endif

#endif	/* _SYS_SPA_H */
