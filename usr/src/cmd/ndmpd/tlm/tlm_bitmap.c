/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * BSD 3 Clause License
 *
 * Copyright (c) 2007, The Storage Networking Industry Association.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 	- Redistributions of source code must retain the above copyright
 *	  notice, this list of conditions and the following disclaimer.
 *
 * 	- Redistributions in binary form must reproduce the above copyright
 *	  notice, this list of conditions and the following disclaimer in
 *	  the documentation and/or other materials provided with the
 *	  distribution.
 *
 *	- Neither the name of The Storage Networking Industry Association (SNIA)
 *	  nor the names of its contributors may be used to endorse or promote
 *	  products derived from this software without specific prior written
 *	  permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */
#include <sys/types.h>
#include <sys/queue.h>
#include <bitmap.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <tlm.h>


/*
 * Hash table size.
 */
#define	BMAP_HASH_SIZE		64


/*
 * Maximum number of chunk that can be cached.
 */
#define	BMAP_CHUNK_MAX		128


/*
 * Size of bitmap table.
 */
#define	BMAP_MAX	256


/*
 * Bit_MAP Word SIZE.  This should be equal to 'sizeof (int)'.
 */
#define	BMAP_WSIZE	(sizeof (int))


/*
 * Bit_MAP Bit Per Word.
 */
#define	BMAP_BPW	(BMAP_WSIZE * 8)
#define	BMAP_BPW_SHIFT	5
#define	BMAP_BPW_MASK	(~(~0 << BMAP_BPW_SHIFT))


/*
 * Chunk of bit map in each node.
 */
#define	BMAP_CHUNK_WORDS	1024
#define	BMAP_CHUNK_BYTES	(BMAP_CHUNK_WORDS * BMAP_WSIZE)
#define	BMAP_CHUNK_BITS		(BMAP_CHUNK_WORDS * BMAP_BPW)
#define	BMAP_CHUNK_NO(p)	((p) / BMAP_CHUNK_BITS)
#define	BMAP_CHUNK_OFF(p)	(BMAP_CHUNK_NO(p) * BMAP_CHUNK_BITS)


/*
 * Bitmap flags.
 */
#define	BMAP_BINIT_ONES	0x00000001 /* initial value of bits is 1 */
#define	BMAP_INUSE	0x00000002 /* slot is in use */


/*
 * Macros of bitmap flags.
 */
#define	BMAP_SET_FLAGS(b, f)	((b)->bm_flags |= (f))
#define	BMAP_UNSET_FLAGS(b, f)	((b)->bm_flags &= ~(f))

#define	BMAP_IS_INIT_ONES(b)	((b)->bm_flags & BMAP_BINIT_ONES)
#define	BMAP_IS_INUSE(b)	((b)->bm_flags & BMAP_INUSE)


#define	HASH(p)		(((p) / BMAP_CHUNK_BITS) % BMAP_HASH_SIZE)

/*
 * Calculate the memory size in bytes needed for the specified length
 * of bitmap.
 */
#define	ROUNDUP(n, d)	(((n) + (d) - 1) / (d))
#define	MEM_LEN(l)	(ROUNDUP((l), BMAP_BPW) * BMAP_WSIZE)


/*
 * Chunk flags.
 */
#define	BMAP_CSET_DIRTY(cp)	(cp)->c_flags |= BMAP_CDIRTY
#define	BMAP_CDIRTY	0x00000001 /* the chunk is dirty */


/*
 * Macros on chunk flags.
 */
#define	BMAP_CIS_DIRTY(cp)	((cp)->c_flags & BMAP_CDIRTY)


/*
 * When loading a bitmap chunk, if it is new set the bitmap
 * can be set according to the initial value of bits.
 * Otherwise, it should be loaded from the file.
 */
#define	BMAP_NEW_CHUNK		1
#define	BMAP_OLD_CHUNK		0

/*
 * Each chunk holds the followin information:
 *  - A flag showing the status of the chunk, like being ditry or not.
 *  - Its offset in bits from the beginning of the vector.
 *  - Its length in bits.
 *  - Its memory length in use in bytes.
 *  - The bitmap vector.
 *
 *  In addition to the above information, each chunk can be on two lists:
 *  one the hash list, the other LRU list.  The hash list is a MRU list,
 *  meaning the MRU entry is at the head of the list.
 *
 *  All the chunks are in the LRU list. When a chunk is needed and there is
 *  no more room for allocating chunks, the first entry of this list is
 *  reclaimed.
 */
typedef struct dbmap_chunk {
	TAILQ_ENTRY(dbmap_chunk) c_hash;
	TAILQ_ENTRY(dbmap_chunk) c_lru;
	uint_t c_flags;
	u_quad_t c_off;
	uint_t c_clen;
	uint_t c_mlen;
	uint_t *c_bmp;
} dbmap_chunk_t;


TAILQ_HEAD(dbmap_list, dbmap_chunk);
typedef struct dbmap_list dbmap_list_t;


typedef struct dbitmap {
	char *bm_fname;
	int bm_fd;
	uint_t bm_flags;
	u_quad_t bm_len; /* bitmap length */
	uint_t bm_cmax; /* maximum number of cached chunks */
	uint_t bm_ccur; /* current number of cached chunks */
	dbmap_list_t bm_hash[BMAP_HASH_SIZE]; /* MRU hash table */
	dbmap_list_t bm_lru; /* LRU list */
} dbitmap_t;

/*
 * Disk bitmap table.  Upon allocating a dbitmap, one slot
 * of this table will be used.
 */
static dbitmap_t dbitmap[BMAP_MAX];


/*
 * Each chunk holds the followin information:
 *  - Its offset in bits from the beginning of the vector.
 *  - Its length in bits.
 *  - Its memory length in use in bytes.
 *  - The bitmap vector.
 *
 *  In addition to the above information, each chunk can be on a list:
 *  one the hash list.  The hash list is a MRU list,  meaning that the
 *  MRU entry is at the head of the list.
 */
typedef struct bmap_chunk {
	TAILQ_ENTRY(bmap_chunk) c_hash;
	u_quad_t c_off;
	uint_t c_clen;
	uint_t c_mlen;
	uint_t *c_bmp;
} bmap_chunk_t;


TAILQ_HEAD(bmap_list, bmap_chunk);
typedef struct bmap_list bmap_list_t;


typedef struct bitmap {
	uint_t bm_flags;
	u_quad_t bm_len; /* bitmap length */
	uint_t bm_cmax; /* maximum number of cached chunks */
	uint_t bm_ccur; /* current number of cached chunks */
	bmap_list_t bm_hash[BMAP_HASH_SIZE]; /* MRU hash table */
} bitmap_t;


/*
 * Statistics gathering structure.
 */
typedef struct bitmap_stats {
	ulong_t bs_alloc_cnt;
	ulong_t bs_alloc_size;
	ulong_t bs_free_cnt;
	ulong_t bs_set_applied;
	ulong_t bs_unset_applied;
	ulong_t bs_cache_hit;
	ulong_t bs_cache_miss;
	ulong_t bs_chunk_new;
	ulong_t bs_chunk_flush;
	ulong_t bs_chunk_reclaim;
	u_quad_t bs_get;
	u_quad_t bs_get_bits;
	u_quad_t bs_set;
	u_quad_t bs_set_bits;
	u_quad_t bs_unset;
	u_quad_t bs_unset_bits;
} bitmap_stats_t;


/*
 * Disk bitmap table.  Upon allocating a bitmap, one slot
 * of this table will be used.
 */
static bitmap_t bitmap[BMAP_MAX];


/*
 * Global instance of statistics variable.
 */
bitmap_stats_t bitmap_stats;


/*
 * bmd2bmp
 *
 * Convert bitmap descriptor to bitmap pointer.
 */
static bitmap_t *
bmd2bmp(int bmd)
{
	if (bmd < 0 || bmd >= BMAP_MAX)
		return (NULL);

	return (&bitmap[bmd]);
}


/*
 * bmd_alloc
 *
 * Allocate a bitmap descriptor.  Sets the INUSE flag of the slot.
 */
static int
bmd_alloc(void)
{
	int i;
	bitmap_t *bmp;

	bmp = bitmap;
	for (i = 0; i < BMAP_MAX; bmp++, i++)
		if (!BMAP_IS_INUSE(bmp)) {
			BMAP_SET_FLAGS(bmp, BMAP_INUSE);
			return (i);
		}

	return (-1);
}


/*
 * bmd_free
 *
 * Free a bitmap descriptor.  Clears the INUSE flag of the slot.
 */
static void
bmd_free(int bmd)
{
	bitmap_t *bmp;

	bmp = bmd2bmp(bmd);
	if (bmp)
		BMAP_UNSET_FLAGS(bmp, BMAP_INUSE);
}


/*
 * bmp_set
 *
 * Generic function to set bit in a chunk.  This can set or unset the
 * specified bit.
 */
static inline int
bmp_set(bmap_chunk_t *cp, u_quad_t bn, uint_t *vp)
{
	int rv;
	uint_t mask;
	uint_t *ip;
	uint_t v;

	bn -= cp->c_off;
	if (bn < cp->c_clen) {
		mask = 1 <<(bn & BMAP_BPW_MASK);
		ip = &cp->c_bmp[bn >> BMAP_BPW_SHIFT];
		v = (*vp <<(bn & BMAP_BPW_MASK)) & mask;
		*ip = (*ip & ~mask) | v;
		rv = 0;
	} else
		rv = -ERANGE;

	return (rv);
}


/*
 * bmp_get
 *
 * Generic function to get bit in a chunk.
 */
static inline int
bmp_get(bmap_chunk_t *cp, u_quad_t bn)
{
	int rv;
	uint_t bit;

	bn -= cp->c_off;
	if (bn < cp->c_clen) {
		bit = 1 <<(bn & BMAP_BPW_MASK);
		rv = (cp->c_bmp[bn >> BMAP_BPW_SHIFT] & bit) != 0;
	} else
		rv = -ERANGE;

	return (rv);
}


/*
 * bm_chuck_setup
 *
 * Set up the properties of the new chunk and position it in the hash list.
 */
static bmap_chunk_t *
bm_chunk_setup(bitmap_t *bmp, bmap_chunk_t *cp, u_quad_t bn)
{
	int h;
	u_quad_t off, l;
	uint_t cl, ml;
	bmap_list_t *hp;

	off = BMAP_CHUNK_OFF(bn);
	l = bmp->bm_len - off;
	if (l >= BMAP_CHUNK_BITS) {
		cl = BMAP_CHUNK_BITS;
		ml = BMAP_CHUNK_BYTES;
	} else {
		cl = l;
		ml = MEM_LEN(l);
	}

	if (BMAP_IS_INIT_ONES(bmp))
		(void) memset(cp->c_bmp, 0xff, ml);
	else
		(void) memset(cp->c_bmp, 0x00, ml);

	h = HASH(bn);
	hp = &bmp->bm_hash[h];

	TAILQ_INSERT_HEAD(hp, cp, c_hash);
	cp->c_off = off;
	cp->c_clen = cl;
	cp->c_mlen = ml;
	return (cp);
}


/*
 * bm_chunk_new
 *
 * Create a new chunk and keep track of memory used.
 */
static bmap_chunk_t *
bm_chunk_new(bitmap_t *bmp, u_quad_t bn)
{
	bmap_chunk_t *cp;

	bitmap_stats.bs_chunk_new++;

	cp = ndmp_malloc(sizeof (bmap_chunk_t));
	if (cp) {
		cp->c_bmp = ndmp_malloc(sizeof (uint_t) * BMAP_CHUNK_WORDS);
		if (!cp->c_bmp) {
			free(cp);
			cp = NULL;
		} else {
			(void) bm_chunk_setup(bmp, cp, bn);
			bmp->bm_ccur++;
		}
	}

	return (cp);
}


/*
 * bm_chunk_alloc
 *
 * Allocate a chunk and return it.  If the cache for the chunks is not
 * fully used, a new chunk is created.
 */
static bmap_chunk_t *
bm_chunk_alloc(bitmap_t *bmp, u_quad_t bn)
{
	bmap_chunk_t *cp;

	if (bmp->bm_ccur < bmp->bm_cmax)
		cp = bm_chunk_new(bmp, bn);
	else
		cp = NULL;

	return (cp);
}


/*
 * hash_free
 *
 * Free all chunks on the hash list.
 */
void
hash_free(bmap_list_t *hp)
{
	bmap_chunk_t *cp;

	if (!hp)
		return;

	while (!TAILQ_EMPTY(hp)) {
		cp = TAILQ_FIRST(hp);
		TAILQ_REMOVE(hp, cp, c_hash);
		free(cp->c_bmp);
		free(cp);
	}
}


/*
 * bm_chunks_free
 *
 * Release the memory allocated for the chunks.
 */
static void
bm_chunks_free(bmap_list_t *hp)
{
	int i;

	for (i = 0; i < BMAP_HASH_SIZE; hp++, i++)
		hash_free(hp);
}


/*
 * bm_chunk_repositions
 *
 * Re-position the chunk in the MRU hash table.
 */
static void
bm_chunk_reposition(bitmap_t *bmp, bmap_list_t *hp, bmap_chunk_t *cp)
{
	if (!bmp || !hp || !cp)
		return;

	if (TAILQ_FIRST(hp) != cp) {
		TAILQ_REMOVE(hp, cp, c_hash);
		TAILQ_INSERT_HEAD(hp, cp, c_hash);
	}
}


/*
 * bm_chunk_find
 *
 * Find and return the chunks which holds the specified bit. Allocate
 * the chunk if necessary and re-position it in the hash table lists.
 */
static bmap_chunk_t *
bm_chunk_find(bitmap_t *bmp, u_quad_t bn)
{
	int h;
	bmap_chunk_t *cp;
	bmap_list_t *hp;

	if (!bmp)
		return (NULL);

	h = HASH(bn);
	hp = &bmp->bm_hash[h];
	TAILQ_FOREACH(cp, hp, c_hash) {
		if (bn >= cp->c_off && bn < (cp->c_off + cp->c_clen)) {
			bitmap_stats.bs_cache_hit++;

			bm_chunk_reposition(bmp, hp, cp);
			return (cp);
		}
	}

	bitmap_stats.bs_cache_miss++;

	return (bm_chunk_alloc(bmp, bn));
}


/*
 * bmp_setval
 *
 * Set a range of bits in the bitmap specified by the vector.
 */
static int
bmp_setval(bitmap_t *bmp, bm_iovec_t *vp)
{
	int rv;
	u_quad_t cl;
	u_quad_t bn;
	u_quad_t max;
	bmap_chunk_t *cp;

	bn = vp->bmv_base;
	max = bn + vp->bmv_len;
	if (bn >= bmp->bm_len || max > bmp->bm_len)
		return (-EINVAL);

	if (*vp->bmv_val) {
		bitmap_stats.bs_set++;
		bitmap_stats.bs_set_bits += vp->bmv_len;
	} else {
		bitmap_stats.bs_unset++;
		bitmap_stats.bs_unset_bits += vp->bmv_len;
	}

	do {
		cp = bm_chunk_find(bmp, bn);
		if (!cp)
			return (-ERANGE);

		for (cl = cp->c_off + cp->c_clen; bn < cl && bn < max; bn++) {
			rv = bmp_set(cp, bn, vp->bmv_val);
			if (rv != 0)
				return (rv);
		}
	} while (bn < max);

	return (0);
}


/*
 * bmp_getval
 *
 * Get a range of bits in the bitmap specified by the vector.
 */
static int
bmp_getval(bitmap_t *bmp, bm_iovec_t *vp)
{
	uint_t cnt;
	uint_t *ip;
	int rv;
	u_quad_t cl;
	u_quad_t bn;
	u_quad_t max;
	bmap_chunk_t *cp;

	bn = vp->bmv_base;
	max = bn + vp->bmv_len;
	if (bn >= bmp->bm_len || max > bmp->bm_len)
		return (-EINVAL);

	bitmap_stats.bs_get++;
	bitmap_stats.bs_get_bits += 1;

	cnt = 0;
	ip = vp->bmv_val;
	*ip = 0;
	do {
		cp = bm_chunk_find(bmp, bn);
		if (!cp)
			return (-ERANGE);

		for (cl = cp->c_off + cp->c_clen; bn < cl && bn < max; bn++) {
			rv = bmp_get(cp, bn);
			if (rv < 0)
				return (rv);

			*ip |= rv << cnt;
			if (++cnt >= BMAP_BPW) {
				*++ip = 0;
				cnt = 0;
			}
		}
	} while (bn < max);

	return (0);
}


/*
 * hash_init
 *
 * Initialize the hash table lists head.
 */
static void
hash_init(bmap_list_t *hp)
{
	int i;

	for (i = 0; i < BMAP_HASH_SIZE; hp++, i++) {
		TAILQ_INIT(hp);
	}
}


/*
 * bm_alloc
 *
 * Allocate a bit map and return a handle to it.
 *
 * The hash table list are empty at this point. They are allocated
 * on demand.
 */
int
bm_alloc(u_quad_t len, int set)
{
	int bmd;
	bitmap_t *bmp;

	if (len == 0)
		return (-1);

	bmd = bmd_alloc();
	if (bmd < 0)
		return (bmd);

	bmp = bmd2bmp(bmd);
	bitmap_stats.bs_alloc_cnt++;
	bitmap_stats.bs_alloc_size += len;

	if (set)
		BMAP_SET_FLAGS(bmp, BMAP_BINIT_ONES);
	else
		BMAP_UNSET_FLAGS(bmp, BMAP_BINIT_ONES);
	bmp->bm_len = len;
	bmp->bm_ccur = 0;
	bmp->bm_cmax = BMAP_CHUNK_MAX;
	hash_init(bmp->bm_hash);

	return (bmd);
}


/*
 * bm_free
 *
 * Free memory allocated for the bitmap.
 */
int
bm_free(int bmd)
{
	int rv;
	bitmap_t *bmp;

	bmp = bmd2bmp(bmd);
	if (bmp && BMAP_IS_INUSE(bmp)) {
		bitmap_stats.bs_free_cnt++;

		bm_chunks_free(bmp->bm_hash);
		bmd_free(bmd);
		rv = 0;
	} else
		rv = -1;

	return (rv);
}


/*
 * bm_getiov
 *
 * Get bits specified by the array of vectors.
 */
int
bm_getiov(int bmd, bm_io_t *iop)
{
	int i;
	int rv;
	bm_iovec_t *vp;
	bitmap_t *bmp;

	if (!iop)
		rv = -EINVAL;
	else if (!(bmp = bmd2bmp(bmd)))
		rv = -EINVAL;
	else if (iop->bmio_iovcnt <= 0)
		rv = -EINVAL;
	else {
		rv = 0;
		vp = iop->bmio_iov;
		for (i = 0; i < iop->bmio_iovcnt; vp++, i++) {
			if (!vp)
				return (-EINVAL);
			rv |= bmp_getval(bmp, vp);
		}
	}

	return (rv);
}


/*
 * bm_setiov
 *
 * Set bits specified by the array of vectors.
 */
int
bm_setiov(int bmd, bm_io_t *iop)
{
	int i;
	int rv;
	bm_iovec_t *vp;
	bitmap_t *bmp;

	if (!iop)
		rv = -EINVAL;
	else if (!(bmp = bmd2bmp(bmd)))
		rv = -EINVAL;
	else if (iop->bmio_iovcnt <= 0)
		rv = -EINVAL;
	else if (!iop->bmio_iov)
		rv = -EINVAL;
	else {
		rv = 0;
		vp = iop->bmio_iov;
		for (i = 0; i < iop->bmio_iovcnt; vp++, i++)
			rv |= bmp_setval(bmp, vp);
	}

	return (rv);
}


/*
 * bmd2dbmp
 *
 * Convert bitmap descriptor to bitmap pointer.
 */
static dbitmap_t *
bmd2dbmp(int bmd)
{
	if (bmd < 0 || bmd >= BMAP_MAX)
		return (NULL);

	return (&dbitmap[bmd]);
}


/*
 * dbmp2bmd
 *
 * Convert bitmap pointer to bitmap descriptor.
 */
static int
dbmp2bmd(dbitmap_t *bmp)
{
	int bmd;

	bmd = bmp - dbitmap;
	if (bmd < 0 || bmd >= BMAP_MAX)
		bmd = -1;

	return (bmd);
}

/*
 * dbmd_alloc
 *
 * Allocate a bitmap descriptor.
 * Sets the INUSE flag of the slot.
 */
static int
dbmd_alloc(void)
{
	int i;
	dbitmap_t *bmp;

	bmp = dbitmap;
	for (i = 0; i < BMAP_MAX; bmp++, i++)
		if (!BMAP_IS_INUSE(bmp)) {
			BMAP_SET_FLAGS(bmp, BMAP_INUSE);
			return (i);
		}

	return (-1);
}


/*
 * dbmd_free
 *
 * Free a bitmap descriptor.
 * Clears the INUSE flag of the slot.
 */
static void
dbmd_free(int bmd)
{
	dbitmap_t *bmp;

	bmp = bmd2dbmp(bmd);
	if (bmp)
		BMAP_UNSET_FLAGS(bmp, BMAP_INUSE);
}


/*
 * dbmp_set
 *
 * Generic function to set bit in a chunk.  This can
 * set or unset the specified bit.
 */
static inline int
dbmp_set(dbmap_chunk_t *cp, u_quad_t bn, uint_t *vp)
{
	int rv;
	uint_t mask;
	uint_t *ip;
	uint_t v;

	bn -= cp->c_off;
	if (bn < cp->c_clen) {
		mask = 1 <<(bn & BMAP_BPW_MASK);
		ip = &cp->c_bmp[bn >> BMAP_BPW_SHIFT];
		v = (*vp <<(bn & BMAP_BPW_MASK)) & mask;
		*ip = (*ip & ~mask) | v;
		BMAP_CSET_DIRTY(cp);
		rv = 0;
	} else
		rv = -ERANGE;

	return (rv);
}


/*
 * dbmp_getlen
 *
 * Get length of the bitmap.
 */
static u_quad_t
dbmp_getlen(dbitmap_t *bmp)
{
	return (bmp ? bmp->bm_len : 0LL);
}


/*
 * dbmp_get
 *
 * Generic function to get bit in a chunk.
 */
static inline int
dbmp_get(dbmap_chunk_t *cp, u_quad_t bn)
{
	int rv;
	uint_t bit;

	bn -= cp->c_off;
	if (bn < cp->c_clen) {
		bit = 1 <<(bn & BMAP_BPW_MASK);
		rv = (cp->c_bmp[bn >> BMAP_BPW_SHIFT] & bit) != 0;
	} else
		rv = -ERANGE;

	return (rv);
}


/*
 * dbm_chunk_seek
 *
 * Seek in the file where the chunk is saved or should be saved.
 */
static int
dbm_chunk_seek(dbitmap_t *bmp, u_quad_t bn)
{
	int rv;
	off_t off;

	if (!bmp)
		rv = -1;
	else {
		off = BMAP_CHUNK_NO(bn) * BMAP_CHUNK_BYTES;
		rv = (lseek(bmp->bm_fd, off, SEEK_SET) != off) ? -1 : 0;
	}

	return (rv);
}


/*
 * dbm_chunk_flush
 *
 * Save a chunk to file.
 */
static int
dbm_chunk_flush(dbitmap_t *bmp, dbmap_chunk_t *cp)
{
	int rv;

	bitmap_stats.bs_chunk_flush++;
	if (!bmp || !cp)
		rv = -1;
	else if (dbm_chunk_seek(bmp, cp->c_off) != 0)
		rv = -1;
	else if (write(bmp->bm_fd, cp->c_bmp, cp->c_mlen) != cp->c_mlen)
		rv = -1;
	else
		rv = 0;

	return (rv);
}


/*
 * dbm_chunk_load
 *
 * Load a chunk from a file.  If the chunk is a new one,
 * instead of reading from the disk, the memory for the
 * chunk is set to either all zeros or to all ones.
 * Otherwise, if the chunk is not a new one, it's read
 * from the disk.
 *
 * The new chunk is positioned in the LRU and hash table
 * after its data is ready.
 */
static dbmap_chunk_t *
dbm_chunk_load(dbitmap_t *bmp, dbmap_chunk_t *cp, u_quad_t bn, int new)
{
	int h;
	u_quad_t off, l;
	uint_t cl, ml;
	dbmap_list_t *hp;

	off = BMAP_CHUNK_OFF(bn);
	l = bmp->bm_len - off;
	if (l >= BMAP_CHUNK_BITS) {
		cl = BMAP_CHUNK_BITS;
		ml = BMAP_CHUNK_BYTES;
	} else {
		cl = l;
		ml = MEM_LEN(l);
	}

	if (new == BMAP_NEW_CHUNK) {
		if (BMAP_IS_INIT_ONES(bmp))
			(void) memset(cp->c_bmp, 0xff, ml);
		else
			(void) memset(cp->c_bmp, 0x00, ml);
	} else { /* BMAP_OLD_CHUNK */
		if (dbm_chunk_seek(bmp, bn) != 0)
			cp = NULL;
		else if (read(bmp->bm_fd, cp->c_bmp, ml) != ml)
			cp = NULL;
	}

	if (cp) {
		TAILQ_INSERT_TAIL(&bmp->bm_lru, cp, c_lru);
		h = HASH(bn);
		hp = &bmp->bm_hash[h];
		TAILQ_INSERT_HEAD(hp, cp, c_hash);
		cp->c_flags = 0;
		cp->c_off = off;
		cp->c_clen = cl;
		cp->c_mlen = ml;
	}

	return (cp);
}


/*
 * dbm_chunk_new
 *
 * Create a new chunk and keep track of memory used.
 */
static dbmap_chunk_t *
dbm_chunk_new(dbitmap_t *bmp, u_quad_t bn)
{
	dbmap_chunk_t *cp;

	bitmap_stats.bs_chunk_new++;
	cp = ndmp_malloc(sizeof (dbmap_chunk_t));
	if (cp) {
		cp->c_bmp = ndmp_malloc(sizeof (uint_t) * BMAP_CHUNK_WORDS);
		if (!cp->c_bmp) {
			free(cp);
			cp = NULL;
		} else if (!dbm_chunk_load(bmp, cp, bn, BMAP_NEW_CHUNK)) {
			free(cp->c_bmp);
			free(cp);
			cp = NULL;
		} else
			bmp->bm_ccur++;
	}

	return (cp);
}


/*
 * dbm_chunk_alloc
 *
 * Allocate a chunk and return it.  If the cache for the
 * chunks is not fully used, a new chunk is created.
 * Otherwise, the first chunk from the LRU list is reclaimed,
 * loaded and returned.
 */
static dbmap_chunk_t *
dbm_chunk_alloc(dbitmap_t *bmp, u_quad_t bn)
{
	int h;
	dbmap_list_t *hp;
	dbmap_chunk_t *cp;

	if (bmp->bm_ccur < bmp->bm_cmax)
		return (dbm_chunk_new(bmp, bn));

	bitmap_stats.bs_chunk_reclaim++;

	cp = TAILQ_FIRST(&bmp->bm_lru);
	if (BMAP_CIS_DIRTY(cp))
		(void) dbm_chunk_flush(bmp, cp);

	TAILQ_REMOVE(&bmp->bm_lru, cp, c_lru);
	h = HASH(cp->c_off);
	hp = &bmp->bm_hash[h];
	TAILQ_REMOVE(hp, cp, c_hash);
	return (dbm_chunk_load(bmp, cp, bn, BMAP_OLD_CHUNK));
}


/*
 * dbm_chunks_free
 *
 * Release the memory allocated for the chunks.
 */
static void
dbm_chunks_free(dbitmap_t *bmp)
{
	dbmap_list_t *headp;
	dbmap_chunk_t *cp;

	if (!bmp)
		return;

	headp = &bmp->bm_lru;
	if (!headp)
		return;

	while (!TAILQ_EMPTY(headp)) {
		cp = TAILQ_FIRST(headp);
		TAILQ_REMOVE(headp, cp, c_lru);
		free(cp->c_bmp);
		free(cp);
	}
}


/*
 * dbm_chunk_reposition
 *
 * Re-position the chunk in the LRU and the hash table.
 */
static void
dbm_chunk_reposition(dbitmap_t *bmp, dbmap_list_t *hp, dbmap_chunk_t *cp)
{
	if (bmp && hp && cp) {
		TAILQ_REMOVE(&bmp->bm_lru, cp, c_lru);
		TAILQ_INSERT_TAIL(&bmp->bm_lru, cp, c_lru);
		if (TAILQ_FIRST(hp) != cp) {
			TAILQ_REMOVE(hp, cp, c_hash);
			TAILQ_INSERT_HEAD(hp, cp, c_hash);
		}
	}
}


/*
 * dbm_chunk_find
 *
 * Find and return the chunks which holds the specified bit.
 * Allocate the chunk if necessary and re-position it in the
 * LRU and hash table lists.
 */
static dbmap_chunk_t *
dbm_chunk_find(dbitmap_t *bmp, u_quad_t bn)
{
	int h;
	dbmap_chunk_t *cp;
	dbmap_list_t *hp;

	if (!bmp)
		return (NULL);

	h = HASH(bn);
	hp = &bmp->bm_hash[h];
	TAILQ_FOREACH(cp, hp, c_hash) {
		if (bn >= cp->c_off && bn < (cp->c_off + cp->c_clen)) {
			bitmap_stats.bs_cache_hit++;

			dbm_chunk_reposition(bmp, hp, cp);
			return (cp);
		}
	}

	bitmap_stats.bs_cache_miss++;

	return (dbm_chunk_alloc(bmp, bn));
}


/*
 * dbmp_setval
 *
 * Set a range of bits in the bitmap specified by the
 * vector.
 */
static int
dbmp_setval(dbitmap_t *bmp, bm_iovec_t *vp)
{
	int rv;
	u_quad_t cl;
	u_quad_t bn;
	u_quad_t max;
	dbmap_chunk_t *cp;

	bn = vp->bmv_base;
	max = bn + vp->bmv_len;
	if (bn >= bmp->bm_len || max > bmp->bm_len)
		return (-EINVAL);

	if (*vp->bmv_val) {
		bitmap_stats.bs_set++;
		bitmap_stats.bs_set_bits += vp->bmv_len;
	} else {
		bitmap_stats.bs_unset++;
		bitmap_stats.bs_unset_bits += vp->bmv_len;
	}

	do {
		cp = dbm_chunk_find(bmp, bn);
		if (!cp)
			return (-ERANGE);

		for (cl = cp->c_off + cp->c_clen; bn < cl && bn < max; bn++) {
			rv = dbmp_set(cp, bn, vp->bmv_val);
			if (rv != 0)
				return (rv);
		}
	} while (bn < max);

	return (0);
}


/*
 * dbmp_getval
 *
 * Get a range of bits in the bitmap specified by the
 * vector.
 */
static int
dbmp_getval(dbitmap_t *bmp, bm_iovec_t *vp)
{
	uint_t cnt;
	uint_t *ip;
	int rv;
	u_quad_t cl;
	u_quad_t bn;
	u_quad_t max;
	dbmap_chunk_t *cp;

	bn = vp->bmv_base;
	max = bn + vp->bmv_len;
	if (bn >= bmp->bm_len || max > bmp->bm_len)
		return (-EINVAL);

	bitmap_stats.bs_get++;
	bitmap_stats.bs_get_bits += 1;

	cnt = 0;
	ip = vp->bmv_val;
	*ip = 0;
	do {
		cp = dbm_chunk_find(bmp, bn);
		if (!cp)
			return (-ERANGE);

		for (cl = cp->c_off + cp->c_clen; bn < cl && bn < max; bn++) {
			rv = dbmp_get(cp, bn);
			if (rv < 0)
				return (rv);

			*ip |= rv << cnt;
			if (++cnt >= BMAP_BPW) {
				*++ip = 0;
				cnt = 0;
			}
		}
	} while (bn < max);

	return (0);
}


/*
 * dbyte_apply_ifset
 *
 * Apply the function on the set bits of the specified word.
 */
static int
dbyte_apply_ifset(dbitmap_t *bmp, u_quad_t off, uint_t b, int(*fp)(),
    void *arg)
{
	int bmd;
	int rv;
	u_quad_t l;

	rv = 0;
	l = dbmp_getlen(bmp);
	bmd = dbmp2bmd(bmp);
	for (; b && off < l; off++) {
		if (b & 1) {
			bitmap_stats.bs_set_applied++;

			if ((rv = (*fp)(bmd, off, arg)))
				break;
		}
		b >>= 1;
	}

	return (rv);
}


/*
 * dbm_chunk_apply_ifset
 *
 * Apply the function on the set bits of the specified chunk.
 */
static int
dbm_chunk_apply_ifset(dbitmap_t *bmp, dbmap_chunk_t *cp, int(*fp)(),
    void *arg)
{
	int rv;
	uint_t *bp;
	uint_t i, m;
	u_quad_t q;

	rv = 0;
	bp = cp->c_bmp;
	q = cp->c_off;
	m = cp->c_mlen / BMAP_WSIZE;
	for (i = 0; i < m; q += BMAP_BPW, bp++, i++)
		if (*bp) {
			rv = dbyte_apply_ifset(bmp, q, *bp, fp, arg);
			if (rv != 0)
				break;
		}

	return (rv);
}


/*
 * swfile_trunc
 *
 * Truncate the rest of the swap file.
 */
static int
swfile_trunc(int fd)
{
	int rv;
	off_t off;

	/*
	 * Get the current offset and truncate whatever is
	 * after this point.
	 */
	rv = 0;
	if ((off = lseek(fd, 0, SEEK_CUR)) < 0)
		rv = -1;
	else if (ftruncate(fd, off) != 0)
		rv = -1;

	return (rv);
}


/*
 * swfile_init
 *
 * Initialize the swap file.  The necessary disk space is
 * reserved by writing to the swap file for swapping the
 * chunks in/out of the file.
 */
static int
swfile_init(int fd, u_quad_t len, int set)
{
	u_quad_t i, n;
	uint_t cl, ml;
	uint_t buf[BMAP_CHUNK_WORDS];

	(void) memset(buf, set ? 0xff : 0x00, BMAP_CHUNK_BYTES);
	n = len / BMAP_CHUNK_BITS;
	for (i = 0; i < n; i++)
		if (write(fd, buf, BMAP_CHUNK_BYTES) != BMAP_CHUNK_BYTES)
			return (-1);

	cl = (uint_t)(len % BMAP_CHUNK_BITS);
	ml = MEM_LEN(cl);
	if (write(fd, buf, ml) != ml)
		return (-1);

	return (swfile_trunc(fd));
}


/*
 * dbm_alloc
 *
 * Allocate a bit map and return a handle to it.
 *
 * The swap file is created if it does not exist.
 * The file is truncated if it exists and is larger
 * than needed amount.
 *
 * The hash table and LRU list are empty at this point.
 * They are allocated and/or loaded on-demand.
 */
int
dbm_alloc(char *fname, u_quad_t len, int set)
{
	int fd;
	int bmd;
	dbitmap_t *bmp;

	if (!fname || !*fname || !len)
		return (-1);

	/*
	 * When allocating bitmap, make sure there is enough
	 * disk space by allocating needed disk space, for
	 * writing back the dirty chunks when swaping them out.
	 */
	bmd = dbmd_alloc();
	if (bmd < 0)
		return (bmd);

	bmp = bmd2dbmp(bmd);
	if ((fd = open(fname, O_RDWR|O_CREAT, 0600)) < 0)
		bmd = -1;
	else if (swfile_init(fd, len, set) < 0) {
		bmd = -1;
		(void) close(fd);
		(void) unlink(fname);
		dbmd_free(bmd);
		bmd = -1;
	} else if (!(bmp->bm_fname = strdup(fname))) {
		(void) close(fd);
		(void) unlink(fname);
		dbmd_free(bmd);
		bmd = -1;
	} else {
		bitmap_stats.bs_alloc_cnt++;
		bitmap_stats.bs_alloc_size += len;

		bmp->bm_fd = fd;
		if (set)
			BMAP_SET_FLAGS(bmp, BMAP_BINIT_ONES);
		else
			BMAP_UNSET_FLAGS(bmp, BMAP_BINIT_ONES);
		bmp->bm_len = len;
		bmp->bm_ccur = 0;
		bmp->bm_cmax = BMAP_CHUNK_MAX;
		TAILQ_INIT(&bmp->bm_lru);
		hash_init((bmap_list_t *)bmp->bm_hash);
	}

	return (bmd);
}


/*
 * dbm_free
 *
 * Free memory allocated for the bitmap and remove its swap file.
 */
int
dbm_free(int bmd)
{
	int rv;
	dbitmap_t *bmp;

	bmp = bmd2dbmp(bmd);
	if (bmp && BMAP_IS_INUSE(bmp)) {
		bitmap_stats.bs_free_cnt++;

		dbm_chunks_free(bmp);
		(void) close(bmp->bm_fd);
		(void) unlink(bmp->bm_fname);
		free(bmp->bm_fname);
		dbmd_free(bmd);
		rv = 0;
	} else
		rv = -1;

	return (rv);
}


/*
 * dbm_getlen
 *
 * Return length of the bitmap.
 */
u_quad_t
dbm_getlen(int bmd)
{
	dbitmap_t *bmp;

	bmp = bmd2dbmp(bmd);
	return (dbmp_getlen(bmp));
}


/*
 * dbm_set
 *
 * Set a range of bits.
 */
int
dbm_set(int bmd, u_quad_t start, u_quad_t len, uint_t val)
{
	bm_io_t io;
	bm_iovec_t iov;

	iov.bmv_base = start;
	iov.bmv_len = len;
	iov.bmv_val = &val;
	io.bmio_iovcnt = 1;
	io.bmio_iov = &iov;

	return (dbm_setiov(bmd, &io));
}


/*
 * dbm_getiov
 *
 * Get bits specified by the array of vectors.
 */
int
dbm_getiov(int bmd, bm_io_t *iop)
{
	int i;
	int rv;
	bm_iovec_t *vp;
	dbitmap_t *bmp;

	if (!iop)
		rv = -EINVAL;
	else if (!(bmp = bmd2dbmp(bmd)))
		rv = -EINVAL;
	else if (iop->bmio_iovcnt <= 0)
		rv = -EINVAL;
	else {
		rv = 0;
		vp = iop->bmio_iov;
		for (i = 0; i < iop->bmio_iovcnt; vp++, i++) {
			if (!vp)
				return (-EINVAL);
			rv |= dbmp_getval(bmp, vp);
		}
	}

	return (rv);
}


/*
 * dbm_setiov
 *
 * Set bits specified by the array of vectors.
 */
int
dbm_setiov(int bmd, bm_io_t *iop)
{
	int i;
	int rv;
	bm_iovec_t *vp;
	dbitmap_t *bmp;

	if (!iop)
		rv = -EINVAL;
	else if (!(bmp = bmd2dbmp(bmd)))
		rv = -EINVAL;
	else if (iop->bmio_iovcnt <= 0)
		rv = -EINVAL;
	else if (!iop->bmio_iov)
		rv = -EINVAL;
	else {
		rv = 0;
		vp = iop->bmio_iov;
		for (i = 0; i < iop->bmio_iovcnt; vp++, i++)
			rv |= dbmp_setval(bmp, vp);
	}

	return (rv);
}


/*
 * dbm_apply_ifset
 *
 * Call the callback function for each set bit in the bitmap and
 * pass the 'arg' and bit number as its argument.
 */
int
dbm_apply_ifset(int bmd, int(*fp)(), void *arg)
{
	int rv;
	u_quad_t q;
	dbitmap_t *bmp;
	dbmap_chunk_t *cp;

	bmp = bmd2dbmp(bmd);
	if (!bmp || !fp)
		return (-EINVAL);

	rv = 0;
	for (q = 0; q < bmp->bm_len; q += BMAP_CHUNK_BITS) {
		cp = dbm_chunk_find(bmp, q);
		if (!cp) {
			rv = -ERANGE;
			break;
		}

		rv = dbm_chunk_apply_ifset(bmp, cp, fp, arg);
		if (rv != 0)
			break;
	}

	return (rv);
}


/*
 * bm_set
 *
 * Set a range of bits.
 */
int
bm_set(int bmd, u_quad_t start, u_quad_t len, uint_t val)
{
	bm_io_t io;
	bm_iovec_t iov;

	iov.bmv_base = start;
	iov.bmv_len = len;
	iov.bmv_val = &val;
	io.bmio_iovcnt = 1;
	io.bmio_iov = &iov;

	return (bm_setiov(bmd, &io));
}


/*
 * bm_get
 *
 * Get a range of bits.
 */
int
bm_get(int bmd, u_quad_t start, u_quad_t len, uint_t *buf)
{
	bm_io_t io;
	bm_iovec_t iov;

	iov.bmv_base = start;
	iov.bmv_len = len;
	iov.bmv_val = buf;
	io.bmio_iovcnt = 1;
	io.bmio_iov = &iov;

	return (bm_getiov(bmd, &io));
}


/*
 * bm_getone
 *
 * Get only one bit.
 */
int
bm_getone(int bmd, u_quad_t bitnum)
{
	uint_t i;

	if (bm_get(bmd, bitnum, 1, &i) == 0)
		return (i ? 1 : 0);

	return (0);
}


/*
 * dbm_get
 *
 * Get a range of bits.
 */
int
dbm_get(int bmd, u_quad_t start, u_quad_t len, uint_t *buf)
{
	bm_io_t io;
	bm_iovec_t iov;

	iov.bmv_base = start;
	iov.bmv_len = len;
	iov.bmv_val = buf;
	io.bmio_iovcnt = 1;
	io.bmio_iov = &iov;

	return (dbm_getiov(bmd, &io));
}


/*
 * dbm_getone
 *
 * Get only one bit.
 */
int
dbm_getone(int bmd, u_quad_t bitnum)
{
	uint_t i;

	if (dbm_get(bmd, bitnum, 1, &i) == 0)
		return (i ? 1 : 0);

	return (0);
}
