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

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * DVA-based Adjustable Relpacement Cache
 *
 * While much of the theory of operation and algorithms used here
 * are based on the self-tuning, low overhead replacement cache
 * presented by Megiddo and Modha at FAST 2003, there are some
 * significant differences:
 *
 * 1. The Megiddo and Modha model assumes any page is evictable.
 * Pages in its cache cannot be "locked" into memory.  This makes
 * the eviction algorithm simple: evict the last page in the list.
 * This also make the performance characteristics easy to reason
 * about.  Our cache is not so simple.  At any given moment, some
 * subset of the blocks in the cache are un-evictable because we
 * have handed out a reference to them.  Blocks are only evictable
 * when there are no external references active.  This makes
 * eviction far more problematic:  we choose to evict the evictable
 * blocks that are the "lowest" in the list.
 *
 * There are times when it is not possible to evict the requested
 * space.  In these circumstances we are unable to adjust the cache
 * size.  To prevent the cache growing unbounded at these times we
 * implement a "cache throttle" that slowes the flow of new data
 * into the cache until we can make space avaiable.
 *
 * 2. The Megiddo and Modha model assumes a fixed cache size.
 * Pages are evicted when the cache is full and there is a cache
 * miss.  Our model has a variable sized cache.  It grows with
 * high use, but also tries to react to memory preasure from the
 * operating system: decreasing its size when system memory is
 * tight.
 *
 * 3. The Megiddo and Modha model assumes a fixed page size. All
 * elements of the cache are therefor exactly the same size.  So
 * when adjusting the cache size following a cache miss, its simply
 * a matter of choosing a single page to evict.  In our model, we
 * have variable sized cache blocks (rangeing from 512 bytes to
 * 128K bytes).  We therefor choose a set of blocks to evict to make
 * space for a cache miss that approximates as closely as possible
 * the space used by the new block.
 *
 * See also:  "ARC: A Self-Tuning, Low Overhead Replacement Cache"
 * by N. Megiddo & D. Modha, FAST 2003
 */

/*
 * The locking model:
 *
 * A new reference to a cache buffer can be obtained in two
 * ways: 1) via a hash table lookup using the DVA as a key,
 * or 2) via one of the ARC lists.  The arc_read() inerface
 * uses method 1, while the internal arc algorithms for
 * adjusting the cache use method 2.  We therefor provide two
 * types of locks: 1) the hash table lock array, and 2) the
 * arc list locks.
 *
 * Buffers do not have their own mutexs, rather they rely on the
 * hash table mutexs for the bulk of their protection (i.e. most
 * fields in the arc_buf_hdr_t are protected by these mutexs).
 *
 * buf_hash_find() returns the appropriate mutex (held) when it
 * locates the requested buffer in the hash table.  It returns
 * NULL for the mutex if the buffer was not in the table.
 *
 * buf_hash_remove() expects the appropriate hash mutex to be
 * already held before it is invoked.
 *
 * Each arc state also has a mutex which is used to protect the
 * buffer list associated with the state.  When attempting to
 * obtain a hash table lock while holding an arc list lock you
 * must use: mutex_tryenter() to avoid deadlock.  Also note that
 * the "top" state mutex must be held before the "bot" state mutex.
 *
 * Note that the majority of the performance stats are manipulated
 * with atomic operations.
 */

#include <sys/spa.h>
#include <sys/zio.h>
#include <sys/zfs_context.h>
#include <sys/arc.h>
#include <sys/refcount.h>
#ifdef _KERNEL
#include <sys/vmsystm.h>
#include <vm/anon.h>
#include <sys/fs/swapnode.h>
#endif
#include <sys/callb.h>

static kmutex_t		arc_reclaim_thr_lock;
static kcondvar_t	arc_reclaim_thr_cv;	/* used to signal reclaim thr */
static uint8_t		arc_thread_exit;

typedef enum arc_reclaim_strategy {
	ARC_RECLAIM_AGGR,		/* Aggressive reclaim strategy */
	ARC_RECLAIM_CONS		/* Conservative reclaim strategy */
} arc_reclaim_strategy_t;

/* number of seconds before growing cache again */
static int		arc_grow_retry = 60;

static kmutex_t arc_reclaim_lock;
static int arc_dead;

/*
 * Note that buffers can be on one of 5 states:
 *	ARC_anon	- anonymous (discussed below)
 *	ARC_mru_top	- recently used, currently cached
 *	ARC_mru_bot	- recentely used, no longer in cache
 *	ARC_mfu_top	- frequently used, currently cached
 *	ARC_mfu_bot	- frequently used, no longer in cache
 * When there are no active references to the buffer, they
 * are linked onto one of the lists in arc.  These are the
 * only buffers that can be evicted or deleted.
 *
 * Anonymous buffers are buffers that are not associated with
 * a DVA.  These are buffers that hold dirty block copies
 * before they are written to stable storage.  By definition,
 * they are "ref'd" and are considered part of arc_mru_top
 * that cannot be freed.  Generally, they will aquire a DVA
 * as they are written and migrate onto the arc_mru_top list.
 */

typedef struct arc_state {
	list_t	list;	/* linked list of evictable buffer in state */
	uint64_t lsize;	/* total size of buffers in the linked list */
	uint64_t size;	/* total size of all buffers in this state */
	uint64_t hits;
	kmutex_t mtx;
} arc_state_t;

/* The 5 states: */
static arc_state_t ARC_anon;
static arc_state_t ARC_mru_top;
static arc_state_t ARC_mru_bot;
static arc_state_t ARC_mfu_top;
static arc_state_t ARC_mfu_bot;

static struct arc {
	arc_state_t 	*anon;
	arc_state_t	*mru_top;
	arc_state_t	*mru_bot;
	arc_state_t	*mfu_top;
	arc_state_t	*mfu_bot;
	uint64_t	size;		/* Actual total arc size */
	uint64_t	p;		/* Target size (in bytes) of mru_top */
	uint64_t	c;		/* Target size of cache (in bytes) */
	uint64_t	c_min;		/* Minimum target cache size */
	uint64_t	c_max;		/* Maximum target cache size */
	uint64_t	incr;		/* Size by which to increment arc.c */
	int64_t		size_check;

	/* performance stats */
	uint64_t	hits;
	uint64_t	misses;
	uint64_t	deleted;
	uint64_t	skipped;
	uint64_t	hash_elements;
	uint64_t	hash_elements_max;
	uint64_t	hash_collisions;
	uint64_t	hash_chains;
	uint32_t	hash_chain_max;

	int		no_grow;	/* Don't try to grow cache size */
} arc;

/* Default amount to grow arc.incr */
static int64_t arc_incr_size = 1024;

/* > 0 ==> time to increment arc.c */
static int64_t arc_size_check_default = -1000;

static uint64_t arc_tempreserve;

typedef struct arc_callback arc_callback_t;

struct arc_callback {
	arc_done_func_t		*acb_done;
	void			*acb_private;
	arc_byteswap_func_t	*acb_byteswap;
	arc_buf_t		*acb_buf;
	zio_t			*acb_zio_dummy;
	arc_callback_t		*acb_next;
};

struct arc_buf_hdr {
	/* immutable */
	uint64_t		b_size;
	spa_t			*b_spa;

	/* protected by hash lock */
	dva_t			b_dva;
	uint64_t		b_birth;
	uint64_t		b_cksum0;

	arc_buf_hdr_t		*b_hash_next;
	arc_buf_t		*b_buf;
	uint32_t		b_flags;

	kcondvar_t		b_cv;
	arc_callback_t		*b_acb;

	/* protected by arc state mutex */
	arc_state_t		*b_state;
	list_node_t		b_arc_node;

	/* updated atomically */
	clock_t			b_arc_access;

	/* self protecting */
	refcount_t		b_refcnt;
};

/*
 * Private ARC flags.  These flags are private ARC only flags that will show up
 * in b_flags in the arc_hdr_buf_t.  Some flags are publicly declared, and can
 * be passed in as arc_flags in things like arc_read.  However, these flags
 * should never be passed and should only be set by ARC code.  When adding new
 * public flags, make sure not to smash the private ones.
 */

#define	ARC_IO_IN_PROGRESS	(1 << 10)	/* I/O in progress for buf */
#define	ARC_IO_ERROR		(1 << 11)	/* I/O failed for buf */
#define	ARC_FREED_IN_READ	(1 << 12)	/* buf freed while in read */

#define	HDR_IO_IN_PROGRESS(hdr)	((hdr)->b_flags & ARC_IO_IN_PROGRESS)
#define	HDR_IO_ERROR(hdr)	((hdr)->b_flags & ARC_IO_ERROR)
#define	HDR_FREED_IN_READ(hdr)	((hdr)->b_flags & ARC_FREED_IN_READ)

/*
 * Hash table routines
 */

#define	HT_LOCK_PAD	64

struct ht_lock {
	kmutex_t	ht_lock;
#ifdef _KERNEL
	unsigned char	pad[(HT_LOCK_PAD - sizeof (kmutex_t))];
#endif
};

#define	BUF_LOCKS 256
typedef struct buf_hash_table {
	uint64_t ht_mask;
	arc_buf_hdr_t **ht_table;
	struct ht_lock ht_locks[BUF_LOCKS];
} buf_hash_table_t;

static buf_hash_table_t buf_hash_table;

#define	BUF_HASH_INDEX(spa, dva, birth) \
	(buf_hash(spa, dva, birth) & buf_hash_table.ht_mask)
#define	BUF_HASH_LOCK_NTRY(idx) (buf_hash_table.ht_locks[idx & (BUF_LOCKS-1)])
#define	BUF_HASH_LOCK(idx)	(&(BUF_HASH_LOCK_NTRY(idx).ht_lock))
#define	HDR_LOCK(buf) \
	(BUF_HASH_LOCK(BUF_HASH_INDEX(buf->b_spa, &buf->b_dva, buf->b_birth)))

uint64_t zfs_crc64_table[256];

static uint64_t
buf_hash(spa_t *spa, dva_t *dva, uint64_t birth)
{
	uintptr_t spav = (uintptr_t)spa;
	uint8_t *vdva = (uint8_t *)dva;
	uint64_t crc = -1ULL;
	int i;

	ASSERT(zfs_crc64_table[128] == ZFS_CRC64_POLY);

	for (i = 0; i < sizeof (dva_t); i++)
		crc = (crc >> 8) ^ zfs_crc64_table[(crc ^ vdva[i]) & 0xFF];

	crc ^= (spav>>8) ^ birth;

	return (crc);
}

#define	BUF_EMPTY(buf)						\
	((buf)->b_dva.dva_word[0] == 0 &&			\
	(buf)->b_dva.dva_word[1] == 0 &&			\
	(buf)->b_birth == 0)

#define	BUF_EQUAL(spa, dva, birth, buf)				\
	((buf)->b_dva.dva_word[0] == (dva)->dva_word[0]) &&	\
	((buf)->b_dva.dva_word[1] == (dva)->dva_word[1]) &&	\
	((buf)->b_birth == birth) && ((buf)->b_spa == spa)

static arc_buf_hdr_t *
buf_hash_find(spa_t *spa, dva_t *dva, uint64_t birth, kmutex_t **lockp)
{
	uint64_t idx = BUF_HASH_INDEX(spa, dva, birth);
	kmutex_t *hash_lock = BUF_HASH_LOCK(idx);
	arc_buf_hdr_t *buf;

	mutex_enter(hash_lock);
	for (buf = buf_hash_table.ht_table[idx]; buf != NULL;
	    buf = buf->b_hash_next) {
		if (BUF_EQUAL(spa, dva, birth, buf)) {
			*lockp = hash_lock;
			return (buf);
		}
	}
	mutex_exit(hash_lock);
	*lockp = NULL;
	return (NULL);
}

/*
 * Insert an entry into the hash table.  If there is already an element
 * equal to elem in the hash table, then the already existing element
 * will be returned and the new element will not be inserted.
 * Otherwise returns NULL.
 */
static arc_buf_hdr_t *fbufs[4]; /* XXX to find 6341326 */
static kthread_t *fbufs_lastthread;
static arc_buf_hdr_t *
buf_hash_insert(arc_buf_hdr_t *buf, kmutex_t **lockp)
{
	uint64_t idx = BUF_HASH_INDEX(buf->b_spa, &buf->b_dva, buf->b_birth);
	kmutex_t *hash_lock = BUF_HASH_LOCK(idx);
	arc_buf_hdr_t *fbuf;
	uint32_t max, i;

	fbufs_lastthread = curthread;
	*lockp = hash_lock;
	mutex_enter(hash_lock);
	for (fbuf = buf_hash_table.ht_table[idx], i = 0; fbuf != NULL;
	    fbuf = fbuf->b_hash_next, i++) {
		if (i < sizeof (fbufs) / sizeof (fbufs[0]))
			fbufs[i] = fbuf;
		if (BUF_EQUAL(buf->b_spa, &buf->b_dva, buf->b_birth, fbuf))
			return (fbuf);
	}

	buf->b_hash_next = buf_hash_table.ht_table[idx];
	buf_hash_table.ht_table[idx] = buf;

	/* collect some hash table performance data */
	if (i > 0) {
		atomic_add_64(&arc.hash_collisions, 1);
		if (i == 1)
			atomic_add_64(&arc.hash_chains, 1);
	}
	while (i > (max = arc.hash_chain_max) &&
	    max != atomic_cas_32(&arc.hash_chain_max, max, i)) {
		continue;
	}
	atomic_add_64(&arc.hash_elements, 1);
	if (arc.hash_elements > arc.hash_elements_max)
		atomic_add_64(&arc.hash_elements_max, 1);

	return (NULL);
}

static void
buf_hash_remove(arc_buf_hdr_t *buf)
{
	arc_buf_hdr_t *fbuf, **bufp;
	uint64_t idx = BUF_HASH_INDEX(buf->b_spa, &buf->b_dva, buf->b_birth);

	ASSERT(MUTEX_HELD(BUF_HASH_LOCK(idx)));

	bufp = &buf_hash_table.ht_table[idx];
	while ((fbuf = *bufp) != buf) {
		ASSERT(fbuf != NULL);
		bufp = &fbuf->b_hash_next;
	}
	*bufp = buf->b_hash_next;
	buf->b_hash_next = NULL;

	/* collect some hash table performance data */
	atomic_add_64(&arc.hash_elements, -1);
	if (buf_hash_table.ht_table[idx] &&
	    buf_hash_table.ht_table[idx]->b_hash_next == NULL)
		atomic_add_64(&arc.hash_chains, -1);
}

/*
 * Global data structures and functions for the buf kmem cache.
 */
static kmem_cache_t *hdr_cache;
static kmem_cache_t *buf_cache;

static void
buf_fini(void)
{
	int i;

	kmem_free(buf_hash_table.ht_table,
	    (buf_hash_table.ht_mask + 1) * sizeof (void *));
	for (i = 0; i < BUF_LOCKS; i++)
		mutex_destroy(&buf_hash_table.ht_locks[i].ht_lock);
	kmem_cache_destroy(hdr_cache);
	kmem_cache_destroy(buf_cache);
}

/*
 * Constructor callback - called when the cache is empty
 * and a new buf is requested.
 */
/* ARGSUSED */
static int
hdr_cons(void *vbuf, void *unused, int kmflag)
{
	arc_buf_hdr_t *buf = vbuf;

	bzero(buf, sizeof (arc_buf_hdr_t));
	refcount_create(&buf->b_refcnt);
	cv_init(&buf->b_cv, NULL, CV_DEFAULT, NULL);
	return (0);
}

/*
 * Destructor callback - called when a cached buf is
 * no longer required.
 */
/* ARGSUSED */
static void
hdr_dest(void *vbuf, void *unused)
{
	arc_buf_hdr_t *buf = vbuf;

	refcount_destroy(&buf->b_refcnt);
	cv_destroy(&buf->b_cv);
}

void arc_kmem_reclaim(void);

/*
 * Reclaim callback -- invoked when memory is low.
 */
/* ARGSUSED */
static void
hdr_recl(void *unused)
{
	dprintf("hdr_recl called\n");
	arc_kmem_reclaim();
}

static void
buf_init(void)
{
	uint64_t *ct;
	uint64_t hsize = 1ULL << 10;
	int i, j;

	/*
	 * The hash table is big enough to fill all of physical memory
	 * with an average 4k block size.  The table will take up
	 * totalmem*sizeof(void*)/4k bytes (eg. 2MB/GB with 8-byte
	 * pointers).
	 */
	while (hsize * 4096 < physmem * PAGESIZE)
		hsize <<= 1;

	buf_hash_table.ht_mask = hsize - 1;
	buf_hash_table.ht_table = kmem_zalloc(hsize * sizeof (void*), KM_SLEEP);

	hdr_cache = kmem_cache_create("arc_buf_hdr_t", sizeof (arc_buf_hdr_t),
	    0, hdr_cons, hdr_dest, hdr_recl, NULL, NULL, 0);
	buf_cache = kmem_cache_create("arc_buf_t", sizeof (arc_buf_t),
	    0, NULL, NULL, NULL, NULL, NULL, 0);

	for (i = 0; i < 256; i++)
		for (ct = zfs_crc64_table + i, *ct = i, j = 8; j > 0; j--)
			*ct = (*ct >> 1) ^ (-(*ct & 1) & ZFS_CRC64_POLY);

	for (i = 0; i < BUF_LOCKS; i++) {
		mutex_init(&buf_hash_table.ht_locks[i].ht_lock,
		    NULL, MUTEX_DEFAULT, NULL);
	}
}

#define	ARC_MINTIME	(hz>>4) /* 62 ms */

#define	ARC_TAG		(void *)0x05201962

static void
add_reference(arc_buf_hdr_t *ab, kmutex_t *hash_lock, void *tag)
{
	ASSERT(MUTEX_HELD(hash_lock));

	if ((refcount_add(&ab->b_refcnt, tag) == 1) &&
	    (ab->b_state != arc.anon)) {

		ASSERT(!MUTEX_HELD(&ab->b_state->mtx));
		mutex_enter(&ab->b_state->mtx);
		ASSERT(!refcount_is_zero(&ab->b_refcnt));
		ASSERT(list_link_active(&ab->b_arc_node));
		list_remove(&ab->b_state->list, ab);
		ASSERT3U(ab->b_state->lsize, >=, ab->b_size);
		ab->b_state->lsize -= ab->b_size;
		mutex_exit(&ab->b_state->mtx);
	}
}

static int
remove_reference(arc_buf_hdr_t *ab, kmutex_t *hash_lock, void *tag)
{
	int cnt;

	ASSERT(MUTEX_HELD(hash_lock));

	if (((cnt = refcount_remove(&ab->b_refcnt, tag)) == 0) &&
	    (ab->b_state != arc.anon)) {

		ASSERT(!MUTEX_HELD(&ab->b_state->mtx));
		mutex_enter(&ab->b_state->mtx);
		ASSERT(!list_link_active(&ab->b_arc_node));
		list_insert_head(&ab->b_state->list, ab);
		ASSERT(ab->b_buf != NULL);
		ab->b_state->lsize += ab->b_size;
		mutex_exit(&ab->b_state->mtx);
	}
	return (cnt);
}

/*
 * Move the supplied buffer to the indicated state.  The mutex
 * for the buffer must be held by the caller.
 */
static void
arc_change_state(arc_state_t *new_state, arc_buf_hdr_t *ab,
    kmutex_t *hash_lock)
{
	arc_buf_t *buf;

	ASSERT(MUTEX_HELD(hash_lock));

	/*
	 * If this buffer is evictable, transfer it from the
	 * old state list to the new state list.
	 */
	if (refcount_is_zero(&ab->b_refcnt)) {
		if (ab->b_state != arc.anon) {
			int drop_mutex = FALSE;

			if (!MUTEX_HELD(&ab->b_state->mtx)) {
				mutex_enter(&ab->b_state->mtx);
				drop_mutex = TRUE;
			}
			ASSERT(list_link_active(&ab->b_arc_node));
			list_remove(&ab->b_state->list, ab);
			ASSERT3U(ab->b_state->lsize, >=, ab->b_size);
			ab->b_state->lsize -= ab->b_size;
			if (drop_mutex)
				mutex_exit(&ab->b_state->mtx);
		}
		if (new_state != arc.anon) {
			int drop_mutex = FALSE;

			if (!MUTEX_HELD(&new_state->mtx)) {
				mutex_enter(&new_state->mtx);
				drop_mutex = TRUE;
			}
			list_insert_head(&new_state->list, ab);
			ASSERT(ab->b_buf != NULL);
			new_state->lsize += ab->b_size;
			if (drop_mutex)
				mutex_exit(&new_state->mtx);
		}
	}

	ASSERT(!BUF_EMPTY(ab));
	if (new_state == arc.anon && ab->b_state != arc.anon) {
		buf_hash_remove(ab);
	}

	/*
	 * If this buffer isn't being transferred to the MRU-top
	 * state, it's safe to clear its prefetch flag
	 */
	if ((new_state != arc.mru_top) && (new_state != arc.mru_bot)) {
		ab->b_flags &= ~ARC_PREFETCH;
	}

	buf = ab->b_buf;
	if (buf == NULL) {
		ASSERT3U(ab->b_state->size, >=, ab->b_size);
		atomic_add_64(&ab->b_state->size, -ab->b_size);
		/* we should only be here if we are deleting state */
		ASSERT(new_state == arc.anon &&
		    (ab->b_state == arc.mru_bot || ab->b_state == arc.mfu_bot));
	} else while (buf) {
		ASSERT3U(ab->b_state->size, >=, ab->b_size);
		atomic_add_64(&ab->b_state->size, -ab->b_size);
		atomic_add_64(&new_state->size, ab->b_size);
		buf = buf->b_next;
	}
	ab->b_state = new_state;
}

arc_buf_t *
arc_buf_alloc(spa_t *spa, int size, void *tag)
{
	arc_buf_hdr_t *hdr;
	arc_buf_t *buf;

	ASSERT3U(size, >, 0);
	hdr = kmem_cache_alloc(hdr_cache, KM_SLEEP);
	ASSERT(BUF_EMPTY(hdr));
	hdr->b_size = size;
	hdr->b_spa = spa;
	hdr->b_state = arc.anon;
	hdr->b_arc_access = 0;
	buf = kmem_cache_alloc(buf_cache, KM_SLEEP);
	buf->b_hdr = hdr;
	buf->b_next = NULL;
	buf->b_data = zio_buf_alloc(size);
	hdr->b_buf = buf;
	hdr->b_flags = 0;
	ASSERT(refcount_is_zero(&hdr->b_refcnt));
	(void) refcount_add(&hdr->b_refcnt, tag);

	atomic_add_64(&arc.size, size);
	atomic_add_64(&arc.anon->size, size);

	return (buf);
}

static void
arc_hdr_free(arc_buf_hdr_t *hdr)
{
	ASSERT(refcount_is_zero(&hdr->b_refcnt));
	ASSERT3P(hdr->b_state, ==, arc.anon);

	if (!BUF_EMPTY(hdr)) {
		/*
		 * We can be called with an arc state lock held,
		 * so we can't hold a hash lock here.
		 * ASSERT(not in hash table)
		 */
		ASSERT(!HDR_IO_IN_PROGRESS(hdr));
		bzero(&hdr->b_dva, sizeof (dva_t));
		hdr->b_birth = 0;
		hdr->b_cksum0 = 0;
	}
	if (hdr->b_buf) {
		arc_buf_t *buf = hdr->b_buf;

		ASSERT3U(hdr->b_size, >, 0);
		zio_buf_free(buf->b_data, hdr->b_size);
		atomic_add_64(&arc.size, -hdr->b_size);
		ASSERT3U(arc.anon->size, >=, hdr->b_size);
		atomic_add_64(&arc.anon->size, -hdr->b_size);
		ASSERT3P(buf->b_next, ==, NULL);
		kmem_cache_free(buf_cache, buf);
		hdr->b_buf = NULL;
	}
	ASSERT(!list_link_active(&hdr->b_arc_node));
	ASSERT3P(hdr->b_hash_next, ==, NULL);
	ASSERT3P(hdr->b_acb, ==, NULL);
	kmem_cache_free(hdr_cache, hdr);
}

void
arc_buf_free(arc_buf_t *buf, void *tag)
{
	arc_buf_hdr_t *hdr = buf->b_hdr;
	kmutex_t *hash_lock = HDR_LOCK(hdr);
	int freeable;

	mutex_enter(hash_lock);
	if (remove_reference(hdr, hash_lock, tag) > 0) {
		arc_buf_t **bufp = &hdr->b_buf;
		arc_state_t *state = hdr->b_state;
		uint64_t size = hdr->b_size;

		ASSERT(hdr->b_state != arc.anon || HDR_IO_ERROR(hdr));
		while (*bufp != buf) {
			ASSERT(*bufp);
			bufp = &(*bufp)->b_next;
		}
		*bufp = buf->b_next;
		mutex_exit(hash_lock);
		zio_buf_free(buf->b_data, size);
		atomic_add_64(&arc.size, -size);
		kmem_cache_free(buf_cache, buf);
		ASSERT3U(state->size, >=, size);
		atomic_add_64(&state->size, -size);
		return;
	}

	/* don't free buffers that are in the middle of an async write */
	freeable = (hdr->b_state == arc.anon && hdr->b_acb == NULL);
	mutex_exit(hash_lock);

	if (freeable)
		arc_hdr_free(hdr);
}

int
arc_buf_size(arc_buf_t *buf)
{
	return (buf->b_hdr->b_size);
}

/*
 * Evict buffers from list until we've removed the specified number of
 * bytes.  Move the removed buffers to the appropriate evict state.
 */
static uint64_t
arc_evict_state(arc_state_t *state, int64_t bytes)
{
	arc_state_t *evicted_state;
	uint64_t bytes_evicted = 0;
	arc_buf_hdr_t *ab, *ab_prev;
	kmutex_t *hash_lock;

	ASSERT(state == arc.mru_top || state == arc.mfu_top);

	if (state == arc.mru_top)
		evicted_state = arc.mru_bot;
	else
		evicted_state = arc.mfu_bot;

	mutex_enter(&state->mtx);
	mutex_enter(&evicted_state->mtx);

	for (ab = list_tail(&state->list); ab; ab = ab_prev) {
		ab_prev = list_prev(&state->list, ab);
		hash_lock = HDR_LOCK(ab);
		if (mutex_tryenter(hash_lock)) {
			ASSERT3U(refcount_count(&ab->b_refcnt), ==, 0);
			arc_change_state(evicted_state, ab, hash_lock);
			zio_buf_free(ab->b_buf->b_data, ab->b_size);
			atomic_add_64(&arc.size, -ab->b_size);
			ASSERT3P(ab->b_buf->b_next, ==, NULL);
			kmem_cache_free(buf_cache, ab->b_buf);
			ab->b_buf = NULL;
			DTRACE_PROBE1(arc__evict, arc_buf_hdr_t *, ab);
			bytes_evicted += ab->b_size;
			mutex_exit(hash_lock);
			if (bytes_evicted >= bytes)
				break;
		} else {
			atomic_add_64(&arc.skipped, 1);
		}
	}
	mutex_exit(&evicted_state->mtx);
	mutex_exit(&state->mtx);

	if (bytes_evicted < bytes)
		dprintf("only evicted %lld bytes from %x",
		    (longlong_t)bytes_evicted, state);

	return (bytes_evicted);
}

/*
 * Remove buffers from list until we've removed the specified number of
 * bytes.  Destroy the buffers that are removed.
 */
static void
arc_delete_state(arc_state_t *state, int64_t bytes)
{
	uint_t bufs_skipped = 0;
	uint64_t bytes_deleted = 0;
	arc_buf_hdr_t *ab, *ab_prev;
	kmutex_t *hash_lock;

top:
	mutex_enter(&state->mtx);
	for (ab = list_tail(&state->list); ab; ab = ab_prev) {
		ab_prev = list_prev(&state->list, ab);
		hash_lock = HDR_LOCK(ab);
		if (mutex_tryenter(hash_lock)) {
			arc_change_state(arc.anon, ab, hash_lock);
			mutex_exit(hash_lock);
			atomic_add_64(&arc.deleted, 1);
			DTRACE_PROBE1(arc__delete, arc_buf_hdr_t *, ab);
			bytes_deleted += ab->b_size;
			arc_hdr_free(ab);
			if (bytes >= 0 && bytes_deleted >= bytes)
				break;
		} else {
			if (bytes < 0) {
				mutex_exit(&state->mtx);
				mutex_enter(hash_lock);
				mutex_exit(hash_lock);
				goto top;
			}
			bufs_skipped += 1;
		}
	}
	mutex_exit(&state->mtx);

	if (bufs_skipped) {
		atomic_add_64(&arc.skipped, bufs_skipped);
		ASSERT(bytes >= 0);
	}

	if (bytes_deleted < bytes)
		dprintf("only deleted %lld bytes from %p",
		    (longlong_t)bytes_deleted, state);
}

static void
arc_adjust(void)
{
	int64_t top_sz, mru_over, arc_over;

	top_sz = arc.anon->size + arc.mru_top->size;

	if (top_sz > arc.p && arc.mru_top->lsize > 0) {
		int64_t toevict = MIN(arc.mru_top->lsize, top_sz-arc.p);
		(void) arc_evict_state(arc.mru_top, toevict);
		top_sz = arc.anon->size + arc.mru_top->size;
	}

	mru_over = top_sz + arc.mru_bot->size - arc.c;

	if (mru_over > 0) {
		if (arc.mru_bot->lsize > 0) {
			int64_t todelete = MIN(arc.mru_bot->lsize, mru_over);
			arc_delete_state(arc.mru_bot, todelete);
		}
	}

	if ((arc_over = arc.size - arc.c) > 0) {
		int64_t table_over;

		if (arc.mfu_top->lsize > 0) {
			int64_t toevict = MIN(arc.mfu_top->lsize, arc_over);
			(void) arc_evict_state(arc.mfu_top, toevict);
		}

		table_over = arc.size + arc.mru_bot->lsize + arc.mfu_bot->lsize
		    - arc.c*2;

		if (table_over > 0 && arc.mfu_bot->lsize > 0) {
			int64_t todelete = MIN(arc.mfu_bot->lsize, table_over);
			arc_delete_state(arc.mfu_bot, todelete);
		}
	}
}

/*
 * Flush all *evictable* data from the cache.
 * NOTE: this will not touch "active" (i.e. referenced) data.
 */
void
arc_flush(void)
{
	arc_delete_state(arc.mru_top, -1);
	arc_delete_state(arc.mfu_top, -1);

	arc_delete_state(arc.mru_bot, -1);
	arc_delete_state(arc.mfu_bot, -1);
}

void
arc_kmem_reclaim(void)
{
	/* Remove 6.25% */
	/*
	 * We need arc_reclaim_lock because we don't want multiple
	 * threads trying to reclaim concurrently.
	 */

	/*
	 * umem calls the reclaim func when we destroy the buf cache,
	 * which is after we do arc_fini().  So we set a flag to prevent
	 * accessing the destroyed mutexes and lists.
	 */
	if (arc_dead)
		return;

	mutex_enter(&arc_reclaim_lock);

	atomic_add_64(&arc.c, -(arc.c >> 4));
	if (arc.c < arc.c_min)
		arc.c = arc.c_min;
	atomic_add_64(&arc.p, -(arc.p >> 4));

	arc_adjust();

	/* Cool it for a while */
	arc.incr = 0;
	arc.size_check = arc_size_check_default << 3;

	mutex_exit(&arc_reclaim_lock);
}

static int
arc_reclaim_needed(void)
{
	uint64_t extra;

#ifdef _KERNEL
	/*
	 * take 'desfree' extra pages, so we reclaim sooner, rather than later
	 */
	extra = desfree;

	/*
	 * check that we're out of range of the pageout scanner.  It starts to
	 * schedule paging if freemem is less than lotsfree and needfree.
	 * lotsfree is the high-water mark for pageout, and needfree is the
	 * number of needed free pages.  We add extra pages here to make sure
	 * the scanner doesn't start up while we're freeing memory.
	 */
	if (freemem < lotsfree + needfree + extra)
		return (1);

	/*
	 * check to make sure that swapfs has enough space so that anon
	 * reservations can still succeeed. anon_resvmem() checks that the
	 * availrmem is greater than swapfs_minfree, and the number of reserved
	 * swap pages.  We also add a bit of extra here just to prevent
	 * circumstances from getting really dire.
	 */
	if (availrmem < swapfs_minfree + swapfs_reserve + extra)
		return (1);

	/*
	 * If we're on an i386 platform, it's possible that we'll exhaust the
	 * kernel heap space before we ever run out of available physical
	 * memory.  Most checks of the size of the heap_area compare against
	 * tune.t_minarmem, which is the minimum available real memory that we
	 * can have in the system.  However, this is generally fixed at 25 pages
	 * which is so low that it's useless.  In this comparison, we seek to
	 * calculate the total heap-size, and reclaim if more than 3/4ths of the
	 * heap is allocated.  (Or, in the caclulation, if less than 1/4th is
	 * free)
	 */
#if defined(__i386)
	if (btop(vmem_size(heap_arena, VMEM_FREE)) <
	    (btop(vmem_size(heap_arena, VMEM_FREE | VMEM_ALLOC)) >> 2))
		return (1);
#endif

#else
	if (spa_get_random(100) == 0)
		return (1);
#endif
	return (0);
}

static void
arc_kmem_reap_now(arc_reclaim_strategy_t strat)
{
	size_t			i;
	kmem_cache_t		*prev_cache = NULL;
	extern kmem_cache_t	*zio_buf_cache[];

	/*
	 * an agressive reclamation will shrink the cache size as well as reap
	 * free kmem buffers.  The arc_kmem_reclaim function is called when the
	 * header-cache is reaped, so we only reap the header cache if we're
	 * performing an agressive reclaim.  If we're not, just clean the kmem
	 * buffer caches.
	 */
	if (strat == ARC_RECLAIM_AGGR)
		kmem_cache_reap_now(hdr_cache);

	kmem_cache_reap_now(buf_cache);

	for (i = 0; i < SPA_MAXBLOCKSIZE >> SPA_MINBLOCKSHIFT; i++) {
		if (zio_buf_cache[i] != prev_cache) {
			prev_cache = zio_buf_cache[i];
			kmem_cache_reap_now(zio_buf_cache[i]);
		}
	}
}

static void
arc_reclaim_thread(void)
{
	clock_t			growtime = 0;
	arc_reclaim_strategy_t	last_reclaim = ARC_RECLAIM_CONS;
	callb_cpr_t		cpr;

	CALLB_CPR_INIT(&cpr, &arc_reclaim_thr_lock, callb_generic_cpr, FTAG);

	mutex_enter(&arc_reclaim_thr_lock);
	while (arc_thread_exit == 0) {
		if (arc_reclaim_needed()) {

			if (arc.no_grow) {
				if (last_reclaim == ARC_RECLAIM_CONS) {
					last_reclaim = ARC_RECLAIM_AGGR;
				} else {
					last_reclaim = ARC_RECLAIM_CONS;
				}
			} else {
				arc.no_grow = TRUE;
				last_reclaim = ARC_RECLAIM_AGGR;
				membar_producer();
			}

			/* reset the growth delay for every reclaim */
			growtime = lbolt + (arc_grow_retry * hz);

			arc_kmem_reap_now(last_reclaim);

		} else if ((growtime > 0) && ((growtime - lbolt) <= 0)) {
			arc.no_grow = FALSE;
		}

		/* block until needed, or one second, whichever is shorter */
		CALLB_CPR_SAFE_BEGIN(&cpr);
		(void) cv_timedwait(&arc_reclaim_thr_cv,
		    &arc_reclaim_thr_lock, (lbolt + hz));
		CALLB_CPR_SAFE_END(&cpr, &arc_reclaim_thr_lock);
	}

	arc_thread_exit = 0;
	cv_broadcast(&arc_reclaim_thr_cv);
	CALLB_CPR_EXIT(&cpr);		/* drops arc_reclaim_thr_lock */
	thread_exit();
}

static void
arc_try_grow(int64_t bytes)
{
	/*
	 * If we're within (2 * maxblocksize) bytes of the target
	 * cache size, increment the target cache size
	 */
	atomic_add_64((uint64_t *)&arc.size_check, 1);

	if (arc_reclaim_needed()) {
		cv_signal(&arc_reclaim_thr_cv);
		return;
	}

	if (arc.no_grow)
		return;

	/*
	 * return true if we successfully grow, or if there's enough space that
	 * we don't have to grow.  Above, we return false if we can't grow, or
	 * if we shouldn't because a reclaim is in progress.
	 */
	if ((arc.c - arc.size) <= (2ULL << SPA_MAXBLOCKSHIFT)) {
		if (arc.size_check > 0) {
			arc.size_check = arc_size_check_default;
			atomic_add_64(&arc.incr, arc_incr_size);
		}
		atomic_add_64(&arc.c, MIN(bytes, arc.incr));
		if (arc.c > arc.c_max)
			arc.c = arc.c_max;
		else
			atomic_add_64(&arc.p, MIN(bytes, arc.incr));
	} else if (arc.size > arc.c) {
		if (arc.size_check > 0) {
			arc.size_check = arc_size_check_default;
			atomic_add_64(&arc.incr, arc_incr_size);
		}
		atomic_add_64(&arc.c, MIN(bytes, arc.incr));
		if (arc.c > arc.c_max)
			arc.c = arc.c_max;
		else
			atomic_add_64(&arc.p, MIN(bytes, arc.incr));
	}
}

/*
 * check if the cache has reached its limits and eviction is required prior to
 * insert.  In this situation, we want to evict if no_grow is set Otherwise, the
 * cache is either big enough that we can insert, or a arc_try_grow will result
 * in more space being made available.
 */

static int
arc_evict_needed()
{

	if (arc_reclaim_needed())
		return (1);

	if (arc.no_grow || (arc.c > arc.c_max) || (arc.size > arc.c))
		return (1);

	return (0);
}

/*
 * The state, supplied as the first argument, is going to have something
 * inserted on its behalf. So, determine which cache must be victimized to
 * satisfy an insertion for this state.  We have the following cases:
 *
 * 1. Insert for MRU, p > sizeof(arc.anon + arc.mru_top) ->
 * In this situation if we're out of space, but the resident size of the MFU is
 * under the limit, victimize the MFU cache to satisfy this insertion request.
 *
 * 2. Insert for MRU, p <= sizeof(arc.anon + arc.mru_top) ->
 * Here, we've used up all of the available space for the MRU, so we need to
 * evict from our own cache instead.  Evict from the set of resident MRU
 * entries.
 *
 * 3. Insert for MFU (c - p) > sizeof(arc.mfu_top) ->
 * c minus p represents the MFU space in the cache, since p is the size of the
 * cache that is dedicated to the MRU.  In this situation there's still space on
 * the MFU side, so the MRU side needs to be victimized.
 *
 * 4. Insert for MFU (c - p) < sizeof(arc.mfu_top) ->
 * MFU's resident set is consuming more space than it has been allotted.  In
 * this situation, we must victimize our own cache, the MFU, for this insertion.
 */
static void
arc_evict_for_state(arc_state_t *state, uint64_t bytes)
{
	uint64_t	mru_used;
	uint64_t	mfu_space;
	uint64_t	evicted;

	ASSERT(state == arc.mru_top || state == arc.mfu_top);

	if (state == arc.mru_top) {
		mru_used = arc.anon->size + arc.mru_top->size;
		if (arc.p > mru_used) {
			/* case 1 */
			evicted = arc_evict_state(arc.mfu_top, bytes);
			if (evicted < bytes) {
				arc_adjust();
			}
		} else {
			/* case 2 */
			evicted = arc_evict_state(arc.mru_top, bytes);
			if (evicted < bytes) {
				arc_adjust();
			}
		}
	} else {
		/* MFU_top case */
		mfu_space = arc.c - arc.p;
		if (mfu_space > arc.mfu_top->size) {
			/* case 3 */
			evicted = arc_evict_state(arc.mru_top, bytes);
			if (evicted < bytes) {
				arc_adjust();
			}
		} else {
			/* case 4 */
			evicted = arc_evict_state(arc.mfu_top, bytes);
			if (evicted < bytes) {
				arc_adjust();
			}
		}
	}
}

/*
 * This routine is called whenever a buffer is accessed.
 */
static void
arc_access(arc_buf_hdr_t *buf, kmutex_t *hash_lock)
{
	int		blksz, mult;

	ASSERT(MUTEX_HELD(hash_lock));

	blksz = buf->b_size;

	if (buf->b_state == arc.anon) {
		/*
		 * This buffer is not in the cache, and does not
		 * appear in our "ghost" list.  Add the new buffer
		 * to the MRU state.
		 */

		arc_try_grow(blksz);
		if (arc_evict_needed()) {
			arc_evict_for_state(arc.mru_top, blksz);
		}

		ASSERT(buf->b_arc_access == 0);
		buf->b_arc_access = lbolt;
		DTRACE_PROBE1(new_state__mru_top, arc_buf_hdr_t *,
		    buf);
		arc_change_state(arc.mru_top, buf, hash_lock);

		/*
		 * If we are using less than 2/3 of our total target
		 * cache size, bump up the target size for the MRU
		 * list.
		 */
		if (arc.size < arc.c*2/3) {
			arc.p = arc.anon->size + arc.mru_top->size + arc.c/6;
		}

	} else if (buf->b_state == arc.mru_top) {
		/*
		 * If this buffer is in the MRU-top state and has the prefetch
		 * flag, the first read was actually part of a prefetch.  In
		 * this situation, we simply want to clear the flag and return.
		 * A subsequent access should bump this into the MFU state.
		 */
		if ((buf->b_flags & ARC_PREFETCH) != 0) {
			buf->b_flags &= ~ARC_PREFETCH;
			atomic_add_64(&arc.mru_top->hits, 1);
			return;
		}

		/*
		 * This buffer has been "accessed" only once so far,
		 * but it is still in the cache. Move it to the MFU
		 * state.
		 */
		if (lbolt > buf->b_arc_access + ARC_MINTIME) {
			/*
			 * More than 125ms have passed since we
			 * instantiated this buffer.  Move it to the
			 * most frequently used state.
			 */
			buf->b_arc_access = lbolt;
			DTRACE_PROBE1(new_state__mfu_top,
			    arc_buf_hdr_t *, buf);
			arc_change_state(arc.mfu_top, buf, hash_lock);
		}
		atomic_add_64(&arc.mru_top->hits, 1);
	} else if (buf->b_state == arc.mru_bot) {
		arc_state_t	*new_state;
		/*
		 * This buffer has been "accessed" recently, but
		 * was evicted from the cache.  Move it to the
		 * MFU state.
		 */

		if (buf->b_flags & ARC_PREFETCH) {
			new_state = arc.mru_top;
			DTRACE_PROBE1(new_state__mru_top,
			    arc_buf_hdr_t *, buf);
		} else {
			new_state = arc.mfu_top;
			DTRACE_PROBE1(new_state__mfu_top,
			    arc_buf_hdr_t *, buf);
		}

		arc_try_grow(blksz);
		if (arc_evict_needed()) {
			arc_evict_for_state(new_state, blksz);
		}

		/* Bump up the target size of the MRU list */
		mult = ((arc.mru_bot->size >= arc.mfu_bot->size) ?
		    1 : (arc.mfu_bot->size/arc.mru_bot->size));
		arc.p = MIN(arc.c, arc.p + blksz * mult);

		buf->b_arc_access = lbolt;
		arc_change_state(new_state, buf, hash_lock);

		atomic_add_64(&arc.mru_bot->hits, 1);
	} else if (buf->b_state == arc.mfu_top) {
		/*
		 * This buffer has been accessed more than once and is
		 * still in the cache.  Keep it in the MFU state.
		 *
		 * NOTE: the add_reference() that occurred when we did
		 * the arc_read() should have kicked this off the list,
		 * so even if it was a prefetch, it will be put back at
		 * the head of the list when we remove_reference().
		 */
		atomic_add_64(&arc.mfu_top->hits, 1);
	} else if (buf->b_state == arc.mfu_bot) {
		/*
		 * This buffer has been accessed more than once but has
		 * been evicted from the cache.  Move it back to the
		 * MFU state.
		 */

		arc_try_grow(blksz);
		if (arc_evict_needed()) {
			arc_evict_for_state(arc.mfu_top, blksz);
		}

		/* Bump up the target size for the MFU list */
		mult = ((arc.mfu_bot->size >= arc.mru_bot->size) ?
		    1 : (arc.mru_bot->size/arc.mfu_bot->size));
		arc.p = MAX(0, (int64_t)arc.p - blksz * mult);

		buf->b_arc_access = lbolt;
		DTRACE_PROBE1(new_state__mfu_top,
		    arc_buf_hdr_t *, buf);
		arc_change_state(arc.mfu_top, buf, hash_lock);

		atomic_add_64(&arc.mfu_bot->hits, 1);
	} else {
		ASSERT(!"invalid arc state");
	}

}

/* a generic arc_done_func_t which you can use */
/* ARGSUSED */
void
arc_bcopy_func(zio_t *zio, arc_buf_t *buf, void *arg)
{
	bcopy(buf->b_data, arg, buf->b_hdr->b_size);
	arc_buf_free(buf, arg);
}

/* a generic arc_done_func_t which you can use */
void
arc_getbuf_func(zio_t *zio, arc_buf_t *buf, void *arg)
{
	arc_buf_t **bufp = arg;
	if (zio && zio->io_error) {
		arc_buf_free(buf, arg);
		*bufp = NULL;
	} else {
		*bufp = buf;
	}
}

static void
arc_read_done(zio_t *zio)
{
	arc_buf_hdr_t	*hdr;
	arc_buf_t	*buf;
	arc_buf_t	*abuf;	/* buffer we're assigning to callback */
	kmutex_t	*hash_lock;
	arc_callback_t	*callback_list, *acb;
	int		freeable = FALSE;

	buf = zio->io_private;
	hdr = buf->b_hdr;

	if (!HDR_FREED_IN_READ(hdr)) {
		arc_buf_hdr_t *found;

		found = buf_hash_find(zio->io_spa, &hdr->b_dva, hdr->b_birth,
		    &hash_lock);

		/*
		 * Buffer was inserted into hash-table and removed from lists
		 * prior to starting I/O.  We should find this header, since
		 * it's in the hash table, and it should be legit since it's
		 * not possible to evict it during the I/O.
		 */

		ASSERT(found);
		ASSERT(DVA_EQUAL(&hdr->b_dva, BP_IDENTITY(zio->io_bp)));
	}

	/* byteswap if necessary */
	callback_list = hdr->b_acb;
	ASSERT(callback_list != NULL);
	if (BP_SHOULD_BYTESWAP(zio->io_bp) && callback_list->acb_byteswap)
		callback_list->acb_byteswap(buf->b_data, hdr->b_size);

	/* create copies of the data buffer for the callers */
	abuf = buf;
	for (acb = callback_list; acb; acb = acb->acb_next) {
		if (acb->acb_done) {
			if (abuf == NULL) {
				abuf = kmem_cache_alloc(buf_cache, KM_SLEEP);
				abuf->b_data = zio_buf_alloc(hdr->b_size);
				atomic_add_64(&arc.size, hdr->b_size);
				bcopy(buf->b_data, abuf->b_data, hdr->b_size);
				abuf->b_hdr = hdr;
				abuf->b_next = hdr->b_buf;
				hdr->b_buf = abuf;
				atomic_add_64(&hdr->b_state->size, hdr->b_size);
			}
			acb->acb_buf = abuf;
			abuf = NULL;
		} else {
			/*
			 * The caller did not provide a callback function.
			 * In this case, we should just remove the reference.
			 */
			if (HDR_FREED_IN_READ(hdr)) {
				ASSERT3P(hdr->b_state, ==, arc.anon);
				(void) refcount_remove(&hdr->b_refcnt,
				    acb->acb_private);
			} else {
				(void) remove_reference(hdr, hash_lock,
				    acb->acb_private);
			}
		}
	}
	hdr->b_acb = NULL;
	hdr->b_flags &= ~ARC_IO_IN_PROGRESS;

	ASSERT(refcount_is_zero(&hdr->b_refcnt) || callback_list != NULL);

	if (zio->io_error != 0) {
		hdr->b_flags |= ARC_IO_ERROR;
		if (hdr->b_state != arc.anon)
			arc_change_state(arc.anon, hdr, hash_lock);
		freeable = refcount_is_zero(&hdr->b_refcnt);
	}

	if (!HDR_FREED_IN_READ(hdr)) {
		/*
		 * Only call arc_access on anonymous buffers.  This is because
		 * if we've issued an I/O for an evicted buffer, we've already
		 * called arc_access (to prevent any simultaneous readers from
		 * getting confused).
		 */
		if (zio->io_error == 0 && hdr->b_state == arc.anon)
			arc_access(hdr, hash_lock);
		mutex_exit(hash_lock);
	} else {
		/*
		 * This block was freed while we waited for the read to
		 * complete.  It has been removed from the hash table and
		 * moved to the anonymous state (so that it won't show up
		 * in the cache).
		 */
		ASSERT3P(hdr->b_state, ==, arc.anon);
		freeable = refcount_is_zero(&hdr->b_refcnt);
	}

	cv_broadcast(&hdr->b_cv);

	/* execute each callback and free its structure */
	while ((acb = callback_list) != NULL) {
		if (acb->acb_done)
			acb->acb_done(zio, acb->acb_buf, acb->acb_private);

		if (acb->acb_zio_dummy != NULL) {
			acb->acb_zio_dummy->io_error = zio->io_error;
			zio_nowait(acb->acb_zio_dummy);
		}

		callback_list = acb->acb_next;
		kmem_free(acb, sizeof (arc_callback_t));
	}

	if (freeable)
		arc_hdr_free(hdr);
}

/*
 * "Read" the block block at the specified DVA (in bp) via the
 * cache.  If the block is found in the cache, invoke the provided
 * callback immediately and return.  Note that the `zio' parameter
 * in the callback will be NULL in this case, since no IO was
 * required.  If the block is not in the cache pass the read request
 * on to the spa with a substitute callback function, so that the
 * requested block will be added to the cache.
 *
 * If a read request arrives for a block that has a read in-progress,
 * either wait for the in-progress read to complete (and return the
 * results); or, if this is a read with a "done" func, add a record
 * to the read to invoke the "done" func when the read completes,
 * and return; or just return.
 *
 * arc_read_done() will invoke all the requested "done" functions
 * for readers of this block.
 */
int
arc_read(zio_t *pio, spa_t *spa, blkptr_t *bp, arc_byteswap_func_t *swap,
    arc_done_func_t *done, void *private, int priority, int flags,
    uint32_t arc_flags)
{
	arc_buf_hdr_t *hdr;
	arc_buf_t *buf;
	kmutex_t *hash_lock;
	zio_t	*rzio;

top:
	hdr = buf_hash_find(spa, BP_IDENTITY(bp), bp->blk_birth, &hash_lock);
	if (hdr && hdr->b_buf) {

		ASSERT((hdr->b_state == arc.mru_top) ||
		    (hdr->b_state == arc.mfu_top) ||
		    ((hdr->b_state == arc.anon) &&
		    (HDR_IO_IN_PROGRESS(hdr))));

		if (HDR_IO_IN_PROGRESS(hdr)) {

			if ((arc_flags & ARC_NOWAIT) && done) {
				arc_callback_t	*acb = NULL;

				acb = kmem_zalloc(sizeof (arc_callback_t),
				    KM_SLEEP);
				acb->acb_done = done;
				acb->acb_private = private;
				acb->acb_byteswap = swap;
				if (pio != NULL)
					acb->acb_zio_dummy = zio_null(pio,
					    spa, NULL, NULL, flags);

				ASSERT(acb->acb_done != NULL);
				acb->acb_next = hdr->b_acb;
				hdr->b_acb = acb;
				add_reference(hdr, hash_lock, private);
				mutex_exit(hash_lock);
				return (0);
			} else if (arc_flags & ARC_WAIT) {
				cv_wait(&hdr->b_cv, hash_lock);
				mutex_exit(hash_lock);
				goto top;
			}

			mutex_exit(hash_lock);
			return (0);
		}

		/*
		 * If there is already a reference on this block, create
		 * a new copy of the data so that we will be guaranteed
		 * that arc_release() will always succeed.
		 */

		if (done)
			add_reference(hdr, hash_lock, private);
		if (done && refcount_count(&hdr->b_refcnt) > 1) {
			buf = kmem_cache_alloc(buf_cache, KM_SLEEP);
			buf->b_data = zio_buf_alloc(hdr->b_size);
			ASSERT3U(refcount_count(&hdr->b_refcnt), >, 1);
			atomic_add_64(&arc.size, hdr->b_size);
			bcopy(hdr->b_buf->b_data, buf->b_data, hdr->b_size);
			buf->b_hdr = hdr;
			buf->b_next = hdr->b_buf;
			hdr->b_buf = buf;
			atomic_add_64(&hdr->b_state->size, hdr->b_size);
		} else {
			buf = hdr->b_buf;
		}
		DTRACE_PROBE1(arc__hit, arc_buf_hdr_t *, hdr);
		arc_access(hdr, hash_lock);
		mutex_exit(hash_lock);
		atomic_add_64(&arc.hits, 1);
		if (done)
			done(NULL, buf, private);
	} else {
		uint64_t size = BP_GET_LSIZE(bp);
		arc_callback_t	*acb;

		if (hdr == NULL) {
			/* this block is not in the cache */
			arc_buf_hdr_t	*exists;

			buf = arc_buf_alloc(spa, size, private);
			hdr = buf->b_hdr;
			hdr->b_dva = *BP_IDENTITY(bp);
			hdr->b_birth = bp->blk_birth;
			hdr->b_cksum0 = bp->blk_cksum.zc_word[0];
			exists = buf_hash_insert(hdr, &hash_lock);
			if (exists) {
				/* somebody beat us to the hash insert */
				mutex_exit(hash_lock);
				bzero(&hdr->b_dva, sizeof (dva_t));
				hdr->b_birth = 0;
				hdr->b_cksum0 = 0;
				arc_buf_free(buf, private);
				goto top; /* restart the IO request */
			}

		} else {
			/* this block is in the ghost cache */
			ASSERT((hdr->b_state == arc.mru_bot) ||
			    (hdr->b_state == arc.mfu_bot));
			add_reference(hdr, hash_lock, private);

			buf = kmem_cache_alloc(buf_cache, KM_SLEEP);
			buf->b_data = zio_buf_alloc(hdr->b_size);
			atomic_add_64(&arc.size, hdr->b_size);
			ASSERT(!HDR_IO_IN_PROGRESS(hdr));
			ASSERT3U(refcount_count(&hdr->b_refcnt), ==, 1);
			buf->b_hdr = hdr;
			buf->b_next = NULL;
			hdr->b_buf = buf;
		}

		acb = kmem_zalloc(sizeof (arc_callback_t), KM_SLEEP);
		acb->acb_done = done;
		acb->acb_private = private;
		acb->acb_byteswap = swap;

		ASSERT(hdr->b_acb == NULL);
		hdr->b_acb = acb;

		/*
		 * If this DVA is part of a prefetch, mark the buf
		 * header with the prefetch flag
		 */
		if (arc_flags & ARC_PREFETCH)
			hdr->b_flags |= ARC_PREFETCH;
		hdr->b_flags |= ARC_IO_IN_PROGRESS;

		/*
		 * If the buffer has been evicted, migrate it to a present state
		 * before issuing the I/O.  Once we drop the hash-table lock,
		 * the header will be marked as I/O in progress and have an
		 * attached buffer.  At this point, anybody who finds this
		 * buffer ought to notice that it's legit but has a pending I/O.
		 */

		if ((hdr->b_state == arc.mru_bot) ||
		    (hdr->b_state == arc.mfu_bot))
			arc_access(hdr, hash_lock);

		mutex_exit(hash_lock);

		ASSERT3U(hdr->b_size, ==, size);
		DTRACE_PROBE2(arc__miss, blkptr_t *, bp,
		    uint64_t, size);
		atomic_add_64(&arc.misses, 1);
		rzio = zio_read(pio, spa, bp, buf->b_data, size,
		    arc_read_done, buf, priority, flags);

		if (arc_flags & ARC_WAIT)
			return (zio_wait(rzio));

		ASSERT(arc_flags & ARC_NOWAIT);
		zio_nowait(rzio);
	}
	return (0);
}

/*
 * arc_read() variant to support pool traversal.  If the block is already
 * in the ARC, make a copy of it; otherwise, the caller will do the I/O.
 * The idea is that we don't want pool traversal filling up memory, but
 * if the ARC already has the data anyway, we shouldn't pay for the I/O.
 */
int
arc_tryread(spa_t *spa, blkptr_t *bp, void *data)
{
	arc_buf_hdr_t *hdr;
	kmutex_t *hash_mtx;
	int rc = 0;

	hdr = buf_hash_find(spa, BP_IDENTITY(bp), bp->blk_birth, &hash_mtx);

	if (hdr && hdr->b_buf && !HDR_IO_IN_PROGRESS(hdr))
		bcopy(hdr->b_buf->b_data, data, hdr->b_size);
	else
		rc = ENOENT;

	if (hash_mtx)
		mutex_exit(hash_mtx);

	return (rc);
}

/*
 * Release this buffer from the cache.  This must be done
 * after a read and prior to modifying the buffer contents.
 * If the buffer has more than one reference, we must make
 * make a new hdr for the buffer.
 */
void
arc_release(arc_buf_t *buf, void *tag)
{
	arc_buf_hdr_t *hdr = buf->b_hdr;
	kmutex_t *hash_lock = HDR_LOCK(hdr);

	/* this buffer is not on any list */
	ASSERT(refcount_count(&hdr->b_refcnt) > 0);

	if (hdr->b_state == arc.anon) {
		/* this buffer is already released */
		ASSERT3U(refcount_count(&hdr->b_refcnt), ==, 1);
		ASSERT(BUF_EMPTY(hdr));
		return;
	}

	mutex_enter(hash_lock);

	if (refcount_count(&hdr->b_refcnt) > 1) {
		arc_buf_hdr_t *nhdr;
		arc_buf_t **bufp;
		uint64_t blksz = hdr->b_size;
		spa_t *spa = hdr->b_spa;

		/*
		 * Pull the data off of this buf and attach it to
		 * a new anonymous buf.
		 */
		bufp = &hdr->b_buf;
		while (*bufp != buf) {
			ASSERT(*bufp);
			bufp = &(*bufp)->b_next;
		}
		*bufp = (*bufp)->b_next;
		(void) refcount_remove(&hdr->b_refcnt, tag);
		ASSERT3U(hdr->b_state->size, >=, hdr->b_size);
		atomic_add_64(&hdr->b_state->size, -hdr->b_size);
		mutex_exit(hash_lock);

		nhdr = kmem_cache_alloc(hdr_cache, KM_SLEEP);
		nhdr->b_size = blksz;
		nhdr->b_spa = spa;
		nhdr->b_buf = buf;
		nhdr->b_state = arc.anon;
		nhdr->b_arc_access = 0;
		nhdr->b_flags = 0;
		buf->b_hdr = nhdr;
		buf->b_next = NULL;
		(void) refcount_add(&nhdr->b_refcnt, tag);
		atomic_add_64(&arc.anon->size, blksz);

		hdr = nhdr;
	} else {
		ASSERT(!list_link_active(&hdr->b_arc_node));
		ASSERT(!HDR_IO_IN_PROGRESS(hdr));
		arc_change_state(arc.anon, hdr, hash_lock);
		hdr->b_arc_access = 0;
		mutex_exit(hash_lock);
		bzero(&hdr->b_dva, sizeof (dva_t));
		hdr->b_birth = 0;
		hdr->b_cksum0 = 0;
	}
}

int
arc_released(arc_buf_t *buf)
{
	return (buf->b_hdr->b_state == arc.anon);
}

static void
arc_write_done(zio_t *zio)
{
	arc_buf_t *buf;
	arc_buf_hdr_t *hdr;
	arc_callback_t *acb;

	buf = zio->io_private;
	hdr = buf->b_hdr;
	acb = hdr->b_acb;
	hdr->b_acb = NULL;

	/* this buffer is on no lists and is not in the hash table */
	ASSERT3P(hdr->b_state, ==, arc.anon);

	hdr->b_dva = *BP_IDENTITY(zio->io_bp);
	hdr->b_birth = zio->io_bp->blk_birth;
	hdr->b_cksum0 = zio->io_bp->blk_cksum.zc_word[0];
	/* clear the "in-write" flag */
	hdr->b_hash_next = NULL;
	/* This write may be all-zero */
	if (!BUF_EMPTY(hdr)) {
		arc_buf_hdr_t *exists;
		kmutex_t *hash_lock;

		exists = buf_hash_insert(hdr, &hash_lock);
		if (exists) {
			/*
			 * This can only happen if we overwrite for
			 * sync-to-convergence, because we remove
			 * buffers from the hash table when we arc_free().
			 */
			ASSERT(DVA_EQUAL(BP_IDENTITY(&zio->io_bp_orig),
			    BP_IDENTITY(zio->io_bp)));
			ASSERT3U(zio->io_bp_orig.blk_birth, ==,
			    zio->io_bp->blk_birth);

			ASSERT(refcount_is_zero(&exists->b_refcnt));
			arc_change_state(arc.anon, exists, hash_lock);
			mutex_exit(hash_lock);
			arc_hdr_free(exists);
			exists = buf_hash_insert(hdr, &hash_lock);
			ASSERT3P(exists, ==, NULL);
		}
		arc_access(hdr, hash_lock);
		mutex_exit(hash_lock);
	}
	if (acb && acb->acb_done) {
		ASSERT(!refcount_is_zero(&hdr->b_refcnt));
		acb->acb_done(zio, buf, acb->acb_private);
	}

	if (acb)
		kmem_free(acb, sizeof (arc_callback_t));
}

int
arc_write(zio_t *pio, spa_t *spa, int checksum, int compress,
    uint64_t txg, blkptr_t *bp, arc_buf_t *buf,
    arc_done_func_t *done, void *private, int priority, int flags,
    uint32_t arc_flags)
{
	arc_buf_hdr_t *hdr = buf->b_hdr;
	arc_callback_t	*acb;
	zio_t	*rzio;

	/* this is a private buffer - no locking required */
	ASSERT3P(hdr->b_state, ==, arc.anon);
	ASSERT(BUF_EMPTY(hdr));
	ASSERT(!HDR_IO_ERROR(hdr));
	acb = kmem_zalloc(sizeof (arc_callback_t), KM_SLEEP);
	acb->acb_done = done;
	acb->acb_private = private;
	acb->acb_byteswap = (arc_byteswap_func_t *)-1;
	hdr->b_acb = acb;
	rzio = zio_write(pio, spa, checksum, compress, txg, bp,
	    buf->b_data, hdr->b_size, arc_write_done, buf, priority, flags);

	if (arc_flags & ARC_WAIT)
		return (zio_wait(rzio));

	ASSERT(arc_flags & ARC_NOWAIT);
	zio_nowait(rzio);

	return (0);
}

int
arc_free(zio_t *pio, spa_t *spa, uint64_t txg, blkptr_t *bp,
    zio_done_func_t *done, void *private, uint32_t arc_flags)
{
	arc_buf_hdr_t *ab;
	kmutex_t *hash_lock;
	zio_t	*zio;

	/*
	 * If this buffer is in the cache, release it, so it
	 * can be re-used.
	 */
	ab = buf_hash_find(spa, BP_IDENTITY(bp), bp->blk_birth, &hash_lock);
	if (ab != NULL) {
		/*
		 * The checksum of blocks to free is not always
		 * preserved (eg. on the deadlist).  However, if it is
		 * nonzero, it should match what we have in the cache.
		 */
		ASSERT(bp->blk_cksum.zc_word[0] == 0 ||
		    ab->b_cksum0 == bp->blk_cksum.zc_word[0]);
		arc_change_state(arc.anon, ab, hash_lock);
		if (refcount_is_zero(&ab->b_refcnt)) {
			mutex_exit(hash_lock);
			arc_hdr_free(ab);
			atomic_add_64(&arc.deleted, 1);
		} else {
			ASSERT3U(refcount_count(&ab->b_refcnt), ==, 1);
			if (HDR_IO_IN_PROGRESS(ab))
				ab->b_flags |= ARC_FREED_IN_READ;
			ab->b_arc_access = 0;
			bzero(&ab->b_dva, sizeof (dva_t));
			ab->b_birth = 0;
			ab->b_cksum0 = 0;
			mutex_exit(hash_lock);
		}
	}

	zio = zio_free(pio, spa, txg, bp, done, private);

	if (arc_flags & ARC_WAIT)
		return (zio_wait(zio));

	ASSERT(arc_flags & ARC_NOWAIT);
	zio_nowait(zio);

	return (0);
}

void
arc_tempreserve_clear(uint64_t tempreserve)
{
	atomic_add_64(&arc_tempreserve, -tempreserve);
	ASSERT((int64_t)arc_tempreserve >= 0);
}

int
arc_tempreserve_space(uint64_t tempreserve)
{
#ifdef ZFS_DEBUG
	/*
	 * Once in a while, fail for no reason.  Everything should cope.
	 */
	if (spa_get_random(10000) == 0) {
		dprintf("forcing random failure\n");
		return (ERESTART);
	}
#endif
	/*
	 * XXX This is kind of hacky.  The limit should be adjusted
	 * dynamically to keep the time to sync a dataset fixed (around
	 * 1-5 seconds?).
	 * Maybe should have some sort of locking?  If two requests come
	 * in concurrently, we might let them both succeed, when one of
	 * them should fail.  Not a huge deal.
	 */

	ASSERT3U(tempreserve, <, arc.c/4); /* otherwise we'll loop forever */

	if (arc_tempreserve + tempreserve + arc.anon->size > arc.c / 4) {
		dprintf("failing, arc_tempreserve=%lluK anon=%lluK "
		    "tempreserve=%lluK arc.c=%lluK\n",
		    arc_tempreserve>>10, arc.anon->lsize>>10,
		    tempreserve>>10, arc.c>>10);
		return (ERESTART);
	}
	atomic_add_64(&arc_tempreserve, tempreserve);
	return (0);
}

void
arc_init(void)
{
	mutex_init(&arc_reclaim_lock, NULL, MUTEX_DEFAULT, NULL);
	mutex_init(&arc_reclaim_thr_lock, NULL, MUTEX_DEFAULT, NULL);
	cv_init(&arc_reclaim_thr_cv, NULL, CV_DEFAULT, NULL);

	/* Start out with 1/8 of all memory */
	arc.c = physmem * PAGESIZE / 8;

#ifdef _KERNEL
	/*
	 * On architectures where the physical memory can be larger
	 * than the addressable space (intel in 32-bit mode), we may
	 * need to limit the cache to 1/8 of VM size.
	 */
	arc.c = MIN(arc.c, vmem_size(heap_arena, VMEM_ALLOC | VMEM_FREE) / 8);
#endif

	/* use at least 1/32 of all memory, or 32MB, whichever is more */
	arc.c_min = MAX(arc.c / 4, 64<<20);
	/* use at most 3/4 of all memory, or all but 1GB, whichever is more */
	if (arc.c * 8 >= 1<<30)
		arc.c_max = (arc.c * 8) - (1<<30);
	else
		arc.c_max = arc.c_min;
	arc.c_max = MAX(arc.c * 6, arc.c_max);
	arc.c = arc.c_max;
	arc.p = (arc.c >> 1);

	/* if kmem_flags are set, lets try to use less memory */
	if (kmem_debugging())
		arc.c = arc.c / 2;
	if (arc.c < arc.c_min)
		arc.c = arc.c_min;

	arc.anon = &ARC_anon;
	arc.mru_top = &ARC_mru_top;
	arc.mru_bot = &ARC_mru_bot;
	arc.mfu_top = &ARC_mfu_top;
	arc.mfu_bot = &ARC_mfu_bot;

	list_create(&arc.mru_top->list, sizeof (arc_buf_hdr_t),
	    offsetof(arc_buf_hdr_t, b_arc_node));
	list_create(&arc.mru_bot->list, sizeof (arc_buf_hdr_t),
	    offsetof(arc_buf_hdr_t, b_arc_node));
	list_create(&arc.mfu_top->list, sizeof (arc_buf_hdr_t),
	    offsetof(arc_buf_hdr_t, b_arc_node));
	list_create(&arc.mfu_bot->list, sizeof (arc_buf_hdr_t),
	    offsetof(arc_buf_hdr_t, b_arc_node));

	buf_init();

	arc_thread_exit = 0;

	(void) thread_create(NULL, 0, arc_reclaim_thread, NULL, 0, &p0,
	    TS_RUN, minclsyspri);
}

void
arc_fini(void)
{
	mutex_enter(&arc_reclaim_thr_lock);
	arc_thread_exit = 1;
	while (arc_thread_exit != 0)
		cv_wait(&arc_reclaim_thr_cv, &arc_reclaim_thr_lock);
	mutex_exit(&arc_reclaim_thr_lock);

	arc_flush();

	arc_dead = TRUE;

	mutex_destroy(&arc_reclaim_lock);
	mutex_destroy(&arc_reclaim_thr_lock);
	cv_destroy(&arc_reclaim_thr_cv);

	list_destroy(&arc.mru_top->list);
	list_destroy(&arc.mru_bot->list);
	list_destroy(&arc.mfu_top->list);
	list_destroy(&arc.mfu_bot->list);

	buf_fini();
}
