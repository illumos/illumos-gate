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

#include <mtmalloc.h>
#include "mtmalloc_impl.h"
#include <unistd.h>
#include <synch.h>
#include <thread.h>
#include <pthread.h>
#include <stdio.h>
#include <limits.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <sys/param.h>
#include <sys/sysmacros.h>

/*
 * To turn on the asserts just compile -DDEBUG
 */

#ifndef	DEBUG
#define	NDEBUG
#endif

#include <assert.h>

/*
 * The MT hot malloc implementation contained herein is designed to be
 * plug-compatible with the libc version of malloc. It is not intended
 * to replace that implementation until we decide that it is ok to break
 * customer apps (Solaris 3.0).
 *
 * For requests up to 2^^16, the allocator initializes itself into NCPUS
 * worth of chains of caches. When a memory request is made, the calling thread
 * is vectored into one of NCPUS worth of caches.  The LWP id gives us a cheap,
 * contention-reducing index to use, eventually, this should be replaced with
 * the actual CPU sequence number, when an interface to get it is available.
 *
 * Once the thread is vectored into one of the list of caches the real
 * allocation of the memory begins. The size is determined to figure out which
 * bucket the allocation should be satisfied from. The management of free
 * buckets is done via a bitmask. A free bucket is represented by a 1. The
 * first free bit represents the first free bucket. The position of the bit,
 * represents the position of the bucket in the arena.
 *
 * When the memory from the arena is handed out, the address of the cache
 * control structure is written in the word preceeding the returned memory.
 * This cache control address is used during free() to mark the buffer free
 * in the cache control structure.
 *
 * When all available memory in a cache has been depleted, a new chunk of memory
 * is allocated via sbrk(). The new cache is allocated from this chunk of memory
 * and initialized in the function create_cache(). New caches are installed at
 * the front of a singly linked list of the same size memory pools. This helps
 * to ensure that there will tend to be available memory in the beginning of the
 * list.
 *
 * Long linked lists hurt performance. To decrease this effect, there is a
 * tunable, requestsize, that bumps up the sbrk allocation size and thus
 * increases the number of available blocks within an arena.  We also keep
 * a "hint" for each cache list, which is the last cache in the list allocated
 * from.  This lowers the cost of searching if there are a lot of fully
 * allocated blocks at the front of the list.
 *
 * For requests greater than 2^^16 (oversize allocations), there are two pieces
 * of overhead. There is the OVERHEAD used to hold the cache addr
 * (&oversize_list), plus an oversize_t structure to further describe the block.
 *
 * The oversize list is kept as defragmented as possible by coalescing
 * freed oversized allocations with adjacent neighbors.
 *
 * Addresses handed out are stored in a hash table, and are aligned on
 * MTMALLOC_MIN_ALIGN-byte boundaries at both ends. Request sizes are rounded-up
 * where necessary in order to achieve this. This eases the implementation of
 * MTDEBUGPATTERN and MTINITPATTERN, particularly where coalescing occurs.
 *
 * A memalign allocation takes memalign header overhead.  There's two
 * types of memalign headers distinguished by MTMALLOC_MEMALIGN_MAGIC
 * and MTMALLOC_MEMALIGN_MIN_MAGIC.  When the size of memory taken to
 * get to the aligned address from malloc'ed address is the minimum size
 * OVERHEAD, we create a header taking only one OVERHEAD space with magic
 * number MTMALLOC_MEMALIGN_MIN_MAGIC, and we know by subtracting OVERHEAD
 * from memaligned address, we can get to the malloc'ed address. Otherwise,
 * we create a memalign header taking two OVERHEAD space, one stores
 * MTMALLOC_MEMALIGN_MAGIC magic number, the other one points back to the
 * malloc'ed address.
 */

#if defined(__i386) || defined(__amd64)
#include <arpa/inet.h>	/* for htonl() */
#endif

static void * morecore(size_t);
static void create_cache(cache_t *, size_t bufsize, uint_t hunks);
static void * malloc_internal(size_t, percpu_t *);
static void * oversize(size_t);
static oversize_t *find_oversize(size_t);
static void add_oversize(oversize_t *);
static void copy_pattern(uint32_t, void *, size_t);
static void * verify_pattern(uint32_t, void *, size_t);
static void reinit_cpu_list(void);
static void reinit_cache(cache_t *);
static void free_oversize(oversize_t *);
static oversize_t *oversize_header_alloc(uintptr_t, size_t);

/*
 * oversize hash table stuff
 */
#define	NUM_BUCKETS	67	/* must be prime */
#define	HASH_OVERSIZE(caddr)	((uintptr_t)(caddr) % NUM_BUCKETS)
oversize_t *ovsz_hashtab[NUM_BUCKETS];

#define	ALIGN(x, a)	((((uintptr_t)(x) + ((uintptr_t)(a) - 1)) \
			& ~((uintptr_t)(a) - 1)))

/* need this to deal with little endianess of x86 */
#if defined(__i386) || defined(__amd64)
#define	FLIP_EM(x)	htonl((x))
#else
#define	FLIP_EM(x)	(x)
#endif

#define	INSERT_ONLY			0
#define	COALESCE_LEFT			0x00000001
#define	COALESCE_RIGHT			0x00000002
#define	COALESCE_WITH_BOTH_SIDES	(COALESCE_LEFT | COALESCE_RIGHT)

#define	OVERHEAD	8	/* size needed to write cache addr */
#define	HUNKSIZE	8192	/* just a multiplier */

#define	MAX_CACHED_SHIFT	16	/* 64K is the max cached size */
#define	MAX_CACHED		(1 << MAX_CACHED_SHIFT)
#define	MIN_CACHED_SHIFT	4	/* smaller requests rounded up */
#define	MTMALLOC_MIN_ALIGN	8	/* min guaranteed alignment */

/* maximum size before overflow */
#define	MAX_MTMALLOC	(SIZE_MAX - (SIZE_MAX % MTMALLOC_MIN_ALIGN) \
			- OVSZ_HEADER_SIZE)

#define	NUM_CACHES	(MAX_CACHED_SHIFT - MIN_CACHED_SHIFT + 1)
#define	CACHELIST_SIZE	ALIGN(NUM_CACHES * sizeof (cache_head_t), \
    CACHE_COHERENCY_UNIT)

#define	MINSIZE		9	/* for requestsize, tunable */
#define	MAXSIZE		256	/* arbitrary, big enough, for requestsize */

#define	FREEPATTERN	0xdeadbeef /* debug fill pattern for free buf */
#define	INITPATTERN	0xbaddcafe /* debug fill pattern for new buf */

#define	misaligned(p)	((unsigned)(p) & (sizeof (int) - 1))
#define	IS_OVERSIZE(x, y)	(((x) < (y)) && (((x) > MAX_CACHED)? 1 : 0))

static long requestsize = MINSIZE; /* 9 pages per cache; tunable; 9 is min */

static uint_t cpu_mask;
static curcpu_func curcpu;

static int32_t debugopt;
static int32_t reinit;

static percpu_t *cpu_list;
static oversize_t oversize_list;
static mutex_t oversize_lock = DEFAULTMUTEX;

static int ncpus = 0;

#define	MTMALLOC_OVERSIZE_MAGIC		((uintptr_t)&oversize_list)
#define	MTMALLOC_MEMALIGN_MAGIC		((uintptr_t)&oversize_list + 1)
#define	MTMALLOC_MEMALIGN_MIN_MAGIC	((uintptr_t)&oversize_list + 2)

/*
 * We require allocations handed out to be aligned on MTMALLOC_MIN_ALIGN-byte
 * boundaries. We round up sizeof (oversize_t) (when necessary) to ensure that
 * this is achieved.
 */
#define	OVSZ_SIZE		(ALIGN(sizeof (oversize_t), MTMALLOC_MIN_ALIGN))
#define	OVSZ_HEADER_SIZE	(OVSZ_SIZE + OVERHEAD)

/*
 * memalign header takes 2 OVERHEAD space.  One for memalign magic, and the
 * other one points back to the start address of originally allocated space.
 */
#define	MEMALIGN_HEADER_SIZE	2 * OVERHEAD
#define	MEMALIGN_HEADER_ALLOC(x, shift, malloc_addr)\
	if (shift == OVERHEAD)\
		*((uintptr_t *)((caddr_t)x - OVERHEAD)) = \
			MTMALLOC_MEMALIGN_MIN_MAGIC; \
	else {\
		*((uintptr_t *)((caddr_t)x - OVERHEAD)) = \
			MTMALLOC_MEMALIGN_MAGIC; \
		*((uintptr_t *)((caddr_t)x - 2 * OVERHEAD)) = \
			(uintptr_t)malloc_addr; \
	}

/*
 * Add big to the oversize hash table at the head of the relevant bucket.
 */
static void
insert_hash(oversize_t *big)
{
	caddr_t ret = big->addr;
	int bucket = HASH_OVERSIZE(ret);

	assert(MUTEX_HELD(&oversize_lock));
	big->hash_next = ovsz_hashtab[bucket];
	ovsz_hashtab[bucket] = big;
}

void *
malloc(size_t bytes)
{
	percpu_t *list_rotor;
	uint_t	list_index;

	if (bytes > MAX_CACHED)
		return (oversize(bytes));

	list_index = (curcpu() & cpu_mask);

	list_rotor = &cpu_list[list_index];

	return (malloc_internal(bytes, list_rotor));
}

void *
realloc(void * ptr, size_t bytes)
{
	void *new, *data_ptr;
	cache_t *cacheptr;
	caddr_t mem;
	size_t shift = 0;

	if (ptr == NULL)
		return (malloc(bytes));

	if (bytes == 0) {
		free(ptr);
		return (NULL);
	}

	data_ptr = ptr;
	mem = (caddr_t)ptr - OVERHEAD;

	/*
	 * Optimization possibility :
	 *	p = malloc(64);
	 *	q = realloc(p, 64);
	 * q can be same as p.
	 * Apply this optimization for the normal
	 * sized caches for now.
	 */
	if (*(uintptr_t *)mem < MTMALLOC_OVERSIZE_MAGIC ||
	    *(uintptr_t *)mem > MTMALLOC_MEMALIGN_MIN_MAGIC) {
		cacheptr = (cache_t *)*(uintptr_t *)mem;
		if (bytes <= (cacheptr->mt_size - OVERHEAD))
			return (ptr);
	}

	new = malloc(bytes);

	if (new == NULL)
		return (NULL);

	/*
	 * If new == ptr, ptr has previously been freed. Passing a freed pointer
	 * to realloc() is not allowed - unless the caller specifically states
	 * otherwise, in which case we must avoid freeing ptr (ie new) before we
	 * return new. There is (obviously) no requirement to memcpy() ptr to
	 * new before we return.
	 */
	if (new == ptr) {
		if (!(debugopt & MTDOUBLEFREE))
			abort();
		return (new);
	}

	if (*(uintptr_t *)mem == MTMALLOC_MEMALIGN_MAGIC) {
		mem -= OVERHEAD;
		ptr = (void *)*(uintptr_t *)mem;
		mem = (caddr_t)ptr - OVERHEAD;
		shift = (size_t)((uintptr_t)data_ptr - (uintptr_t)ptr);
	} else if (*(uintptr_t *)mem == MTMALLOC_MEMALIGN_MIN_MAGIC) {
		ptr = (void *) mem;
		mem -= OVERHEAD;
		shift = OVERHEAD;
	}

	if (*(uintptr_t *)mem == MTMALLOC_OVERSIZE_MAGIC) {
		oversize_t *old;

		old = (oversize_t *)(mem - OVSZ_SIZE);
		(void) memcpy(new, data_ptr, MIN(bytes, old->size - shift));
		free(ptr);
		return (new);
	}

	cacheptr = (cache_t *)*(uintptr_t *)mem;

	(void) memcpy(new, data_ptr,
	    MIN(cacheptr->mt_size - OVERHEAD - shift, bytes));
	free(ptr);

	return (new);
}

void *
calloc(size_t nelem, size_t bytes)
{
	void * ptr;
	size_t size;

	if (nelem == 0 || bytes == 0) {
		size = 0;
	} else {
		size = nelem * bytes;

		/* check for overflow */
		if ((size / nelem) != bytes) {
			errno = ENOMEM;
			return (NULL);
		}
	}

	ptr = malloc(size);
	if (ptr == NULL)
		return (NULL);
	(void) memset(ptr, 0, size);

	return (ptr);
}

void
free(void * ptr)
{
	cache_t *cacheptr;
	caddr_t mem;
	int32_t i;
	caddr_t freeblocks;
	uintptr_t offset;
	uchar_t mask;
	int32_t which_bit, num_bytes;

	if (ptr == NULL)
		return;

	mem = (caddr_t)ptr - OVERHEAD;

	if (*(uintptr_t *)mem == MTMALLOC_MEMALIGN_MAGIC) {
		mem -= OVERHEAD;
		ptr = (void *)*(uintptr_t *)mem;
		mem = (caddr_t)ptr - OVERHEAD;
	} else if (*(uintptr_t *)mem == MTMALLOC_MEMALIGN_MIN_MAGIC) {
		ptr = (void *) mem;
		mem -= OVERHEAD;
	}

	if (*(uintptr_t *)mem == MTMALLOC_OVERSIZE_MAGIC) {
		oversize_t *big, **opp;
		int bucket;

		big = (oversize_t *)(mem - OVSZ_SIZE);
		(void) mutex_lock(&oversize_lock);

		bucket = HASH_OVERSIZE(big->addr);
		for (opp = &ovsz_hashtab[bucket]; *opp != NULL;
		    opp = &(*opp)->hash_next)
			if (*opp == big)
				break;

		if (*opp == NULL) {
			if (!(debugopt & MTDOUBLEFREE))
				abort();
			(void) mutex_unlock(&oversize_lock);
			return;
		}

		*opp = big->hash_next;	/* remove big from the hash table */
		big->hash_next = NULL;

		if (debugopt & MTDEBUGPATTERN)
			copy_pattern(FREEPATTERN, ptr, big->size);
		add_oversize(big);
		(void) mutex_unlock(&oversize_lock);
		return;
	}

	cacheptr = (cache_t *)*(uintptr_t *)mem;
	freeblocks = cacheptr->mt_freelist;

	/*
	 * This is the distance measured in bits into the arena.
	 * The value of offset is in bytes but there is a 1-1 correlation
	 * between distance into the arena and distance into the
	 * freelist bitmask.
	 */
	offset = mem - cacheptr->mt_arena;

	/*
	 * i is total number of bits to offset into freelist bitmask.
	 */

	i = offset / cacheptr->mt_size;

	num_bytes = i >> 3;

	/*
	 * which_bit is the bit offset into the byte in the freelist.
	 * if our freelist bitmask looks like 0xf3 and we are freeing
	 * block 5 (ie: the 6th block) our mask will be 0xf7 after
	 * the free. Things go left to right that's why the mask is 0x80
	 * and not 0x01.
	 */
	which_bit = i - (num_bytes << 3);

	mask = 0x80 >> which_bit;

	freeblocks += num_bytes;

	if (debugopt & MTDEBUGPATTERN)
		copy_pattern(FREEPATTERN, ptr, cacheptr->mt_size - OVERHEAD);

	(void) mutex_lock(&cacheptr->mt_cache_lock);

	if (*freeblocks & mask) {
		if (!(debugopt & MTDOUBLEFREE))
			abort();
	} else {
		*freeblocks |= mask;
		cacheptr->mt_nfree++;
	}

	(void) mutex_unlock(&cacheptr->mt_cache_lock);
}

void *
memalign(size_t alignment, size_t size)
{
	size_t alloc_size;
	uintptr_t offset;
	void *alloc_buf;
	void *ret_buf;

	if (size == 0 || alignment == 0 || misaligned(alignment) ||
	    (alignment & (alignment - 1)) != 0) {
		errno = EINVAL;
		return (NULL);
	}

	/* <= MTMALLOC_MIN_ALIGN, malloc can provide directly */
	if (alignment <= MTMALLOC_MIN_ALIGN)
		return (malloc(size));

	alloc_size = size + alignment - MTMALLOC_MIN_ALIGN;

	if (alloc_size < size) { /* overflow */
		errno = ENOMEM;
		return (NULL);
	}

	alloc_buf = malloc(alloc_size);

	if (alloc_buf == NULL)
		/* malloc sets errno */
		return (NULL);

	/*
	 * If alloc_size > MAX_CACHED, malloc() will have returned a multiple of
	 * MTMALLOC_MIN_ALIGN, having rounded-up alloc_size if necessary. Since
	 * we will use alloc_size to return the excess fragments to the free
	 * list, we also round-up alloc_size if necessary.
	 */
	if ((alloc_size > MAX_CACHED) &&
	    (alloc_size & (MTMALLOC_MIN_ALIGN - 1)))
		alloc_size = ALIGN(alloc_size, MTMALLOC_MIN_ALIGN);

	if ((offset = (uintptr_t)alloc_buf & (alignment - 1)) == 0) {
		/* aligned correctly */

		size_t frag_size = alloc_size -
		    (size + MTMALLOC_MIN_ALIGN + OVSZ_HEADER_SIZE);

		/*
		 * If the leftover piece of the memory > MAX_CACHED,
		 * split off the piece and return it back to the freelist.
		 */
		if (IS_OVERSIZE(frag_size, alloc_size)) {
			oversize_t *orig, *tail;
			uintptr_t taddr;
			size_t data_size;
			taddr = ALIGN((uintptr_t)alloc_buf + size,
			    MTMALLOC_MIN_ALIGN);
			data_size = taddr - (uintptr_t)alloc_buf;
			orig = (oversize_t *)((uintptr_t)alloc_buf -
			    OVSZ_HEADER_SIZE);
			frag_size = orig->size - data_size -
			    OVSZ_HEADER_SIZE;
			orig->size = data_size;
			tail = oversize_header_alloc(taddr, frag_size);
			free_oversize(tail);
		}
		ret_buf = alloc_buf;
	} else {
		uchar_t	oversize_bits = 0;
		size_t	head_sz, data_sz, tail_sz;
		uintptr_t ret_addr, taddr, shift, tshift;
		oversize_t *orig, *tail, *big;
		size_t tsize;

		/* needs to be aligned */
		shift = alignment - offset;

		assert(shift >= MTMALLOC_MIN_ALIGN);

		ret_addr = ((uintptr_t)alloc_buf + shift);
		ret_buf = (void *)ret_addr;

		if (alloc_size <= MAX_CACHED) {
			MEMALIGN_HEADER_ALLOC(ret_addr, shift, alloc_buf);
			return (ret_buf);
		}

		/*
		 * Only check for the fragments when the memory is allocted
		 * from oversize_list.  Split off a fragment and return it
		 * to the oversize freelist when it's > MAX_CACHED.
		 */

		head_sz = shift - MAX(MEMALIGN_HEADER_SIZE, OVSZ_HEADER_SIZE);

		tail_sz = alloc_size -
		    (shift + size + MTMALLOC_MIN_ALIGN + OVSZ_HEADER_SIZE);

		oversize_bits |= IS_OVERSIZE(head_sz, alloc_size) |
		    IS_OVERSIZE(size, alloc_size) << DATA_SHIFT |
		    IS_OVERSIZE(tail_sz, alloc_size) << TAIL_SHIFT;

		switch (oversize_bits) {
			case NONE_OVERSIZE:
			case DATA_OVERSIZE:
				MEMALIGN_HEADER_ALLOC(ret_addr, shift,
				    alloc_buf);
				break;
			case HEAD_OVERSIZE:
				/*
				 * If we can extend data > MAX_CACHED and have
				 * head still > MAX_CACHED, we split head-end
				 * as the case of head-end and data oversized,
				 * otherwise just create memalign header.
				 */
				tsize = (shift + size) - (MAX_CACHED + 8 +
				    MTMALLOC_MIN_ALIGN + OVSZ_HEADER_SIZE);

				if (!IS_OVERSIZE(tsize, alloc_size)) {
					MEMALIGN_HEADER_ALLOC(ret_addr, shift,
					    alloc_buf);
					break;
				} else {
					tsize += OVSZ_HEADER_SIZE;
					taddr = ALIGN((uintptr_t)alloc_buf +
					    tsize, MTMALLOC_MIN_ALIGN);
					tshift = ret_addr - taddr;
					MEMALIGN_HEADER_ALLOC(ret_addr, tshift,
					    taddr);
					ret_addr = taddr;
					shift = ret_addr - (uintptr_t)alloc_buf;
				}
				/* FALLTHROUGH */
			case HEAD_AND_DATA_OVERSIZE:
				/*
				 * Split off the head fragment and
				 * return it back to oversize freelist.
				 * Create oversize header for the piece
				 * of (data + tail fragment).
				 */
				orig = (oversize_t *)((uintptr_t)alloc_buf -
				    OVSZ_HEADER_SIZE);
				big = oversize_header_alloc(ret_addr -
				    OVSZ_HEADER_SIZE, (orig->size - shift));
				(void) mutex_lock(&oversize_lock);
				insert_hash(big);
				(void) mutex_unlock(&oversize_lock);
				orig->size = shift - OVSZ_HEADER_SIZE;

				/* free up the head fragment */
				free_oversize(orig);
				break;
			case TAIL_OVERSIZE:
				/*
				 * If we can extend data > MAX_CACHED and have
				 * tail-end still > MAX_CACHED, we split tail
				 * end, otherwise just create memalign header.
				 */
				orig = (oversize_t *)((uintptr_t)alloc_buf -
				    OVSZ_HEADER_SIZE);
				tsize =  orig->size - (MAX_CACHED + 8 +
				    shift + OVSZ_HEADER_SIZE +
				    MTMALLOC_MIN_ALIGN);
				if (!IS_OVERSIZE(tsize, alloc_size)) {
					MEMALIGN_HEADER_ALLOC(ret_addr, shift,
					    alloc_buf);
					break;
				} else {
					size = MAX_CACHED + 8;
				}
				/* FALLTHROUGH */
			case DATA_AND_TAIL_OVERSIZE:
				/*
				 * Split off the tail fragment and
				 * return it back to oversize freelist.
				 * Create memalign header and adjust
				 * the size for the piece of
				 * (head fragment + data).
				 */
				taddr = ALIGN(ret_addr + size,
				    MTMALLOC_MIN_ALIGN);
				data_sz = (size_t)(taddr -
				    (uintptr_t)alloc_buf);
				orig = (oversize_t *)((uintptr_t)alloc_buf -
				    OVSZ_HEADER_SIZE);
				tsize = orig->size - data_sz;
				orig->size = data_sz;
				MEMALIGN_HEADER_ALLOC(ret_buf, shift,
				    alloc_buf);
				tsize -= OVSZ_HEADER_SIZE;
				tail = oversize_header_alloc(taddr,  tsize);
				free_oversize(tail);
				break;
			case HEAD_AND_TAIL_OVERSIZE:
				/*
				 * Split off the head fragment.
				 * We try to free up tail-end when we can
				 * extend data size to (MAX_CACHED + 8)
				 * and remain tail-end oversized.
				 * The bottom line is all split pieces
				 * should be oversize in size.
				 */
				orig = (oversize_t *)((uintptr_t)alloc_buf -
				    OVSZ_HEADER_SIZE);
				tsize =  orig->size - (MAX_CACHED + 8 +
				    OVSZ_HEADER_SIZE + shift +
				    MTMALLOC_MIN_ALIGN);

				if (!IS_OVERSIZE(tsize, alloc_size)) {
					/*
					 * If the chunk is not big enough
					 * to make both data and tail oversize
					 * we just keep them as one piece.
					 */
					big = oversize_header_alloc(ret_addr -
					    OVSZ_HEADER_SIZE,
					    orig->size - shift);
					(void) mutex_lock(&oversize_lock);
					insert_hash(big);
					(void) mutex_unlock(&oversize_lock);
					orig->size = shift - OVSZ_HEADER_SIZE;
					free_oversize(orig);
					break;
				} else {
					/*
					 * extend data size > MAX_CACHED
					 * and handle it as head, data, tail
					 * are all oversized.
					 */
					size = MAX_CACHED + 8;
				}
				/* FALLTHROUGH */
			case ALL_OVERSIZE:
				/*
				 * split off the head and tail fragments,
				 * return them back to the oversize freelist.
				 * Alloc oversize header for data seg.
				 */
				orig = (oversize_t *)((uintptr_t)alloc_buf -
				    OVSZ_HEADER_SIZE);
				tsize = orig->size;
				orig->size = shift - OVSZ_HEADER_SIZE;
				free_oversize(orig);

				taddr = ALIGN(ret_addr + size,
				    MTMALLOC_MIN_ALIGN);
				data_sz = taddr - ret_addr;
				assert(tsize > (shift + data_sz +
				    OVSZ_HEADER_SIZE));
				tail_sz = tsize -
				    (shift + data_sz + OVSZ_HEADER_SIZE);

				/* create oversize header for data seg */
				big = oversize_header_alloc(ret_addr -
				    OVSZ_HEADER_SIZE, data_sz);
				(void) mutex_lock(&oversize_lock);
				insert_hash(big);
				(void) mutex_unlock(&oversize_lock);

				/* create oversize header for tail fragment */
				tail = oversize_header_alloc(taddr, tail_sz);
				free_oversize(tail);
				break;
			default:
				/* should not reach here */
				assert(0);
		}
	}
	return (ret_buf);
}


void *
valloc(size_t size)
{
	static unsigned pagesize;

	if (size == 0)
		return (NULL);

	if (!pagesize)
		pagesize = sysconf(_SC_PAGESIZE);

	return (memalign(pagesize, size));
}

void
mallocctl(int cmd, long value)
{
	switch (cmd) {

	case MTDEBUGPATTERN:
		/*
		 * Reinitialize free blocks in case malloc() is called prior
		 * to mallocctl().
		 */
		if (value && !(debugopt & cmd)) {
			reinit++;
			debugopt |= cmd;
			reinit_cpu_list();
		}
		/*FALLTHRU*/
	case MTDOUBLEFREE:
	case MTINITBUFFER:
		if (value)
			debugopt |= cmd;
		else
			debugopt &= ~cmd;
		break;
	case MTCHUNKSIZE:
		if (value >= MINSIZE && value <= MAXSIZE)
			requestsize = value;
		break;
	default:
		break;
	}
}

/*
 * Initialization function, called from the init section of the library.
 * No locking is required here because we are single-threaded during
 * library initialization.
 */
static void
setup_caches(void)
{
	uintptr_t oldbrk;
	uintptr_t newbrk;

	size_t cache_space_needed;
	size_t padding;

	curcpu_func new_curcpu;
	uint_t new_cpu_mask;
	percpu_t *new_cpu_list;

	uint_t i, j;
	uintptr_t list_addr;

	/*
	 * Get a decent "current cpu identifier", to be used to reduce
	 * contention.  Eventually, this should be replaced by an interface
	 * to get the actual CPU sequence number in libthread/liblwp.
	 */
	new_curcpu = (curcpu_func)thr_self;
	if ((ncpus = 2 * sysconf(_SC_NPROCESSORS_CONF)) <= 0)
		ncpus = 4; /* decent default value */

	/* round ncpus up to a power of 2 */
	while (ncpus & (ncpus - 1))
		ncpus++;

	new_cpu_mask = ncpus - 1;	/* create the cpu mask */

	/*
	 * We now do some magic with the brk.  What we want to get in the
	 * end is a bunch of well-aligned stuff in a big initial allocation.
	 * Along the way, we do sanity checks to make sure no one else has
	 * touched the brk (which shouldn't happen, but it's always good to
	 * check)
	 *
	 * First, make sure sbrk is sane, and store the current brk in oldbrk.
	 */
	oldbrk = (uintptr_t)sbrk(0);
	if ((void *)oldbrk == (void *)-1)
		abort();	/* sbrk is broken -- we're doomed. */

	/*
	 * Now, align the brk to a multiple of CACHE_COHERENCY_UNIT, so that
	 * the percpu structures and cache lists will be properly aligned.
	 *
	 *   2.  All hunks will be page-aligned, assuming HUNKSIZE >= PAGESIZE,
	 *	so they can be paged out individually.
	 */
	newbrk = ALIGN(oldbrk, CACHE_COHERENCY_UNIT);
	if (newbrk != oldbrk && (uintptr_t)sbrk(newbrk - oldbrk) != oldbrk)
		abort();	/* sbrk is broken -- we're doomed. */

	/*
	 * For each cpu, there is one percpu_t and a list of caches
	 */
	cache_space_needed = ncpus * (sizeof (percpu_t) + CACHELIST_SIZE);

	new_cpu_list = (percpu_t *)sbrk(cache_space_needed);

	if (new_cpu_list == (percpu_t *)-1 ||
	    (uintptr_t)new_cpu_list != newbrk)
		abort();	/* sbrk is broken -- we're doomed. */

	/*
	 * Finally, align the brk to HUNKSIZE so that all hunks are
	 * page-aligned, to avoid edge-effects.
	 */

	newbrk = (uintptr_t)new_cpu_list + cache_space_needed;

	padding = ALIGN(newbrk, HUNKSIZE) - newbrk;

	if (padding > 0 && (uintptr_t)sbrk(padding) != newbrk)
		abort();	/* sbrk is broken -- we're doomed. */

	list_addr = ((uintptr_t)new_cpu_list + (sizeof (percpu_t) * ncpus));

	/* initialize the percpu list */
	for (i = 0; i < ncpus; i++) {
		new_cpu_list[i].mt_caches = (cache_head_t *)list_addr;
		for (j = 0; j < NUM_CACHES; j++) {
			new_cpu_list[i].mt_caches[j].mt_cache = NULL;
			new_cpu_list[i].mt_caches[j].mt_hint = NULL;
		}

		(void) mutex_init(&new_cpu_list[i].mt_parent_lock,
		    USYNC_THREAD, NULL);

		/* get the correct cache list alignment */
		list_addr += CACHELIST_SIZE;
	}

	/*
	 * Initialize oversize listhead
	 */
	oversize_list.next_bysize = &oversize_list;
	oversize_list.prev_bysize = &oversize_list;
	oversize_list.next_byaddr = &oversize_list;
	oversize_list.prev_byaddr = &oversize_list;
	oversize_list.addr = NULL;
	oversize_list.size = 0;		/* sentinal */

	/*
	 * Now install the global variables.
	 */
	curcpu = new_curcpu;
	cpu_mask = new_cpu_mask;
	cpu_list = new_cpu_list;
}

static void
create_cache(cache_t *cp, size_t size, uint_t chunksize)
{
	long nblocks;

	(void) mutex_init(&cp->mt_cache_lock, USYNC_THREAD, NULL);
	cp->mt_size = size;
	cp->mt_freelist = ((caddr_t)cp + sizeof (cache_t));
	cp->mt_span = chunksize * HUNKSIZE - sizeof (cache_t);
	cp->mt_hunks = chunksize;
	/*
	 * rough calculation. We will need to adjust later.
	 */
	nblocks = cp->mt_span / cp->mt_size;
	nblocks >>= 3;
	if (nblocks == 0) { /* less than 8 free blocks in this pool */
		int32_t numblocks = 0;
		long i = cp->mt_span;
		size_t sub = cp->mt_size;
		uchar_t mask = 0;

		while (i > sub) {
			numblocks++;
			i -= sub;
		}
		nblocks = numblocks;
		cp->mt_arena = (caddr_t)ALIGN(cp->mt_freelist + 8, 8);
		cp->mt_nfree = numblocks;
		while (numblocks--) {
			mask |= 0x80 >> numblocks;
		}
		*(cp->mt_freelist) = mask;
	} else {
		cp->mt_arena = (caddr_t)ALIGN((caddr_t)cp->mt_freelist +
		    nblocks, 32);
		/* recompute nblocks */
		nblocks = (uintptr_t)((caddr_t)cp->mt_freelist +
		    cp->mt_span - cp->mt_arena) / cp->mt_size;
		cp->mt_nfree = ((nblocks >> 3) << 3);
		/* Set everything to free */
		(void) memset(cp->mt_freelist, 0xff, nblocks >> 3);
	}

	if (debugopt & MTDEBUGPATTERN)
		copy_pattern(FREEPATTERN, cp->mt_arena, cp->mt_size * nblocks);

	cp->mt_next = NULL;
}

static void
reinit_cpu_list(void)
{
	oversize_t *wp = oversize_list.next_bysize;
	percpu_t *cpuptr;
	cache_t *thiscache;
	cache_head_t *cachehead;

	/* Reinitialize free oversize blocks. */
	(void) mutex_lock(&oversize_lock);
	if (debugopt & MTDEBUGPATTERN)
		for (; wp != &oversize_list; wp = wp->next_bysize)
			copy_pattern(FREEPATTERN, wp->addr, wp->size);
	(void) mutex_unlock(&oversize_lock);

	/* Reinitialize free blocks. */
	for (cpuptr = &cpu_list[0]; cpuptr < &cpu_list[ncpus]; cpuptr++) {
		(void) mutex_lock(&cpuptr->mt_parent_lock);
		for (cachehead = &cpuptr->mt_caches[0]; cachehead <
		    &cpuptr->mt_caches[NUM_CACHES]; cachehead++) {
			for (thiscache = cachehead->mt_cache; thiscache != NULL;
			    thiscache = thiscache->mt_next) {
				(void) mutex_lock(&thiscache->mt_cache_lock);
				if (thiscache->mt_nfree == 0) {
					(void) mutex_unlock(
					    &thiscache->mt_cache_lock);
					continue;
				}
				if (thiscache != NULL)
					reinit_cache(thiscache);
				(void) mutex_unlock(&thiscache->mt_cache_lock);
			}
		}
		(void) mutex_unlock(&cpuptr->mt_parent_lock);
	}
	reinit = 0;
}

static void
reinit_cache(cache_t *thiscache)
{
	uint32_t *freeblocks; /* not a uintptr_t on purpose */
	int32_t i, n;
	caddr_t ret;

	freeblocks = (uint32_t *)thiscache->mt_freelist;
	while (freeblocks < (uint32_t *)thiscache->mt_arena) {
		if (*freeblocks & 0xffffffff) {
			for (i = 0; i < 32; i++) {
				if (FLIP_EM(*freeblocks) & (0x80000000 >> i)) {
					n = (uintptr_t)(((freeblocks -
					    (uint32_t *)thiscache->mt_freelist)
					    << 5) + i) * thiscache->mt_size;
					ret = thiscache->mt_arena + n;
					ret += OVERHEAD;
					copy_pattern(FREEPATTERN, ret,
					    thiscache->mt_size);
				}
			}
		}
		freeblocks++;
	}
}

static void *
malloc_internal(size_t size, percpu_t *cpuptr)
{
	cache_head_t *cachehead;
	cache_t *thiscache, *hintcache;
	int32_t i, n, logsz, bucket;
	uint32_t index;
	uint32_t *freeblocks; /* not a uintptr_t on purpose */
	caddr_t ret;

	logsz = MIN_CACHED_SHIFT;

	while (size > (1 << logsz))
		logsz++;

	bucket = logsz - MIN_CACHED_SHIFT;

	(void) mutex_lock(&cpuptr->mt_parent_lock);

	/*
	 * Find a cache of the appropriate size with free buffers.
	 *
	 * We don't need to lock each cache as we check their mt_nfree count,
	 * since:
	 *	1.  We are only looking for caches with mt_nfree > 0.  If a
	 *	   free happens during our search, it will increment mt_nfree,
	 *	   which will not effect the test.
	 *	2.  Allocations can decrement mt_nfree, but they can't happen
	 *	   as long as we hold mt_parent_lock.
	 */

	cachehead = &cpuptr->mt_caches[bucket];

	/* Search through the list, starting at the mt_hint */
	thiscache = cachehead->mt_hint;

	while (thiscache != NULL && thiscache->mt_nfree == 0)
		thiscache = thiscache->mt_next;

	if (thiscache == NULL) {
		/* wrap around -- search up to the hint */
		thiscache = cachehead->mt_cache;
		hintcache = cachehead->mt_hint;

		while (thiscache != NULL && thiscache != hintcache &&
		    thiscache->mt_nfree == 0)
			thiscache = thiscache->mt_next;

		if (thiscache == hintcache)
			thiscache = NULL;
	}


	if (thiscache == NULL) { /* there are no free caches */
		int32_t thisrequest = requestsize;
		int32_t buffer_size = (1 << logsz) + OVERHEAD;

		thiscache = (cache_t *)morecore(thisrequest * HUNKSIZE);

		if (thiscache == (cache_t *)-1) {
			(void) mutex_unlock(&cpuptr->mt_parent_lock);
			errno = EAGAIN;
			return (NULL);
		}
		create_cache(thiscache, buffer_size, thisrequest);

		/* link in the new block at the beginning of the list */
		thiscache->mt_next = cachehead->mt_cache;
		cachehead->mt_cache = thiscache;
	}

	/* update the hint to the cache we found or created */
	cachehead->mt_hint = thiscache;

	/* thiscache now points to a cache with available space */
	(void) mutex_lock(&thiscache->mt_cache_lock);

	freeblocks = (uint32_t *)thiscache->mt_freelist;
	while (freeblocks < (uint32_t *)thiscache->mt_arena) {
		if (*freeblocks & 0xffffffff)
			break;
		freeblocks++;
		if (freeblocks < (uint32_t *)thiscache->mt_arena &&
		    *freeblocks & 0xffffffff)
			break;
		freeblocks++;
		if (freeblocks < (uint32_t *)thiscache->mt_arena &&
		    *freeblocks & 0xffffffff)
			break;
		freeblocks++;
		if (freeblocks < (uint32_t *)thiscache->mt_arena &&
		    *freeblocks & 0xffffffff)
			break;
		freeblocks++;
	}

	/*
	 * the offset from mt_freelist to freeblocks is the offset into
	 * the arena. Be sure to include the offset into freeblocks
	 * of the bitmask. n is the offset.
	 */
	for (i = 0; i < 32; ) {
		if (FLIP_EM(*freeblocks) & (0x80000000 >> i++))
			break;
		if (FLIP_EM(*freeblocks) & (0x80000000 >> i++))
			break;
		if (FLIP_EM(*freeblocks) & (0x80000000 >> i++))
			break;
		if (FLIP_EM(*freeblocks) & (0x80000000 >> i++))
			break;
	}
	index = 0x80000000 >> --i;


	*freeblocks &= FLIP_EM(~index);

	thiscache->mt_nfree--;

	(void) mutex_unlock(&thiscache->mt_cache_lock);
	(void) mutex_unlock(&cpuptr->mt_parent_lock);

	n = (uintptr_t)(((freeblocks - (uint32_t *)thiscache->mt_freelist) << 5)
	    + i) * thiscache->mt_size;
	/*
	 * Now you have the offset in n, you've changed the free mask
	 * in the freelist. Nothing left to do but find the block
	 * in the arena and put the value of thiscache in the word
	 * ahead of the handed out address and return the memory
	 * back to the user.
	 */
	ret = thiscache->mt_arena + n;

	/* Store the cache addr for this buf. Makes free go fast. */
	*(uintptr_t *)ret = (uintptr_t)thiscache;

	/*
	 * This assert makes sure we don't hand out memory that is not
	 * owned by this cache.
	 */
	assert(ret + thiscache->mt_size <= thiscache->mt_freelist +
	    thiscache->mt_span);

	ret += OVERHEAD;

	assert(((uintptr_t)ret & 7) == 0); /* are we 8 byte aligned */

	if (reinit == 0 && (debugopt & MTDEBUGPATTERN))
		if (verify_pattern(FREEPATTERN, ret, size))
			abort();	/* reference after free */

	if (debugopt & MTINITBUFFER)
		copy_pattern(INITPATTERN, ret, size);
	return ((void *)ret);
}

static void *
morecore(size_t bytes)
{
	void * ret;

	if (bytes > LONG_MAX) {
		intptr_t wad;
		/*
		 * The request size is too big. We need to do this in
		 * chunks. Sbrk only takes an int for an arg.
		 */
		if (bytes == ULONG_MAX)
			return ((void *)-1);

		ret = sbrk(0);
		wad = LONG_MAX;
		while (wad > 0) {
			if (sbrk(wad) == (void *)-1) {
				if (ret != sbrk(0))
					(void) sbrk(-LONG_MAX);
				return ((void *)-1);
			}
			bytes -= LONG_MAX;
			wad = bytes;
		}
	} else
		ret = sbrk(bytes);

	return (ret);
}


static void *
oversize(size_t size)
{
	caddr_t ret;
	oversize_t *big;

	/* make sure we will not overflow */
	if (size > MAX_MTMALLOC) {
		errno = ENOMEM;
		return (NULL);
	}

	/*
	 * Since we ensure every address we hand back is
	 * MTMALLOC_MIN_ALIGN-byte aligned, ALIGNing size ensures that the
	 * memory handed out is MTMALLOC_MIN_ALIGN-byte aligned at both ends.
	 * This eases the implementation of MTDEBUGPATTERN and MTINITPATTERN,
	 * particularly where coalescing occurs.
	 */
	size = ALIGN(size, MTMALLOC_MIN_ALIGN);

	/*
	 * The idea with the global lock is that we are sure to
	 * block in the kernel anyway since given an oversize alloc
	 * we are sure to have to call morecore();
	 */
	(void) mutex_lock(&oversize_lock);

	if ((big = find_oversize(size)) != NULL) {
		if (reinit == 0 && (debugopt & MTDEBUGPATTERN))
			if (verify_pattern(FREEPATTERN, big->addr, size))
				abort();	/* reference after free */
	} else {
		/* Get more 8-byte aligned memory from heap */
		ret = morecore(size + OVSZ_HEADER_SIZE);
		if (ret == (caddr_t)-1) {
			(void) mutex_unlock(&oversize_lock);
			errno = ENOMEM;
			return (NULL);
		}
		big = oversize_header_alloc((uintptr_t)ret, size);
	}
	ret = big->addr;

	insert_hash(big);

	if (debugopt & MTINITBUFFER)
		copy_pattern(INITPATTERN, ret, size);

	(void) mutex_unlock(&oversize_lock);
	assert(((uintptr_t)ret & 7) == 0); /* are we 8 byte aligned */
	return ((void *)ret);
}

static void
insert_oversize(oversize_t *op, oversize_t *nx)
{
	oversize_t *sp;

	/* locate correct insertion point in size-ordered list */
	for (sp = oversize_list.next_bysize;
	    sp != &oversize_list && (op->size > sp->size);
	    sp = sp->next_bysize)
		;

	/* link into size-ordered list */
	op->next_bysize = sp;
	op->prev_bysize = sp->prev_bysize;
	op->prev_bysize->next_bysize = op;
	op->next_bysize->prev_bysize = op;

	/*
	 * link item into address-ordered list
	 * (caller provides insertion point as an optimization)
	 */
	op->next_byaddr = nx;
	op->prev_byaddr = nx->prev_byaddr;
	op->prev_byaddr->next_byaddr = op;
	op->next_byaddr->prev_byaddr = op;

}

static void
unlink_oversize(oversize_t *lp)
{
	/* unlink from address list */
	lp->prev_byaddr->next_byaddr = lp->next_byaddr;
	lp->next_byaddr->prev_byaddr = lp->prev_byaddr;

	/* unlink from size list */
	lp->prev_bysize->next_bysize = lp->next_bysize;
	lp->next_bysize->prev_bysize = lp->prev_bysize;
}

static void
position_oversize_by_size(oversize_t *op)
{
	oversize_t *sp;

	if (op->size > op->next_bysize->size ||
	    op->size < op->prev_bysize->size) {

		/* unlink from size list */
		op->prev_bysize->next_bysize = op->next_bysize;
		op->next_bysize->prev_bysize = op->prev_bysize;

		/* locate correct insertion point in size-ordered list */
		for (sp = oversize_list.next_bysize;
		    sp != &oversize_list && (op->size > sp->size);
		    sp = sp->next_bysize)
			;

		/* link into size-ordered list */
		op->next_bysize = sp;
		op->prev_bysize = sp->prev_bysize;
		op->prev_bysize->next_bysize = op;
		op->next_bysize->prev_bysize = op;
	}
}

static void
add_oversize(oversize_t *lp)
{
	int merge_flags = INSERT_ONLY;
	oversize_t *nx;  	/* ptr to item right of insertion point */
	oversize_t *pv;  	/* ptr to item left of insertion point */
	uint_t size_lp, size_pv, size_nx;
	uintptr_t endp_lp, endp_pv, endp_nx;

	/*
	 * Locate insertion point in address-ordered list
	 */

	for (nx = oversize_list.next_byaddr;
	    nx != &oversize_list && (lp->addr > nx->addr);
	    nx = nx->next_byaddr)
		;

	/*
	 * Determine how to add chunk to oversize freelist
	 */

	size_lp = OVSZ_HEADER_SIZE + lp->size;
	endp_lp = ALIGN((uintptr_t)lp + size_lp, MTMALLOC_MIN_ALIGN);
	size_lp = endp_lp - (uintptr_t)lp;

	pv = nx->prev_byaddr;

	if (pv->size) {

		size_pv = OVSZ_HEADER_SIZE + pv->size;
		endp_pv = ALIGN((uintptr_t)pv + size_pv,
		    MTMALLOC_MIN_ALIGN);
		size_pv = endp_pv - (uintptr_t)pv;

		/* Check for adjacency with left chunk */
		if ((uintptr_t)lp == endp_pv)
			merge_flags |= COALESCE_LEFT;
	}

	if (nx->size) {

		/* Check for adjacency with right chunk */
		if ((uintptr_t)nx == endp_lp) {
			size_nx = OVSZ_HEADER_SIZE + nx->size;
			endp_nx = ALIGN((uintptr_t)nx + size_nx,
			    MTMALLOC_MIN_ALIGN);
			size_nx = endp_nx - (uintptr_t)nx;
			merge_flags |= COALESCE_RIGHT;
		}
	}

	/*
	 * If MTDEBUGPATTERN==1, lp->addr will have been overwritten with
	 * FREEPATTERN for lp->size bytes. If we can merge, the oversize
	 * header(s) that will also become part of the memory available for
	 * reallocation (ie lp and/or nx) must also be overwritten with
	 * FREEPATTERN or we will SIGABRT when this memory is next reallocated.
	 */
	switch (merge_flags) {

	case INSERT_ONLY:		/* Coalescing not possible */
		insert_oversize(lp, nx);
		break;
	case COALESCE_LEFT:
		pv->size += size_lp;
		position_oversize_by_size(pv);
		if (debugopt & MTDEBUGPATTERN)
			copy_pattern(FREEPATTERN, lp, OVSZ_HEADER_SIZE);
		break;
	case COALESCE_RIGHT:
		unlink_oversize(nx);
		lp->size += size_nx;
		insert_oversize(lp, pv->next_byaddr);
		if (debugopt & MTDEBUGPATTERN)
			copy_pattern(FREEPATTERN, nx, OVSZ_HEADER_SIZE);
		break;
	case COALESCE_WITH_BOTH_SIDES:	/* Merge (with right) to the left */
		pv->size += size_lp + size_nx;
		unlink_oversize(nx);
		position_oversize_by_size(pv);
		if (debugopt & MTDEBUGPATTERN) {
			copy_pattern(FREEPATTERN, lp, OVSZ_HEADER_SIZE);
			copy_pattern(FREEPATTERN, nx, OVSZ_HEADER_SIZE);
		}
		break;
	}
}

/*
 * Find memory on our list that is at least size big. If we find a block that is
 * big enough, we break it up and return the associated oversize_t struct back
 * to the calling client. Any leftover piece of that block is returned to the
 * freelist.
 */
static oversize_t *
find_oversize(size_t size)
{
	oversize_t *wp = oversize_list.next_bysize;
	while (wp != &oversize_list && size > wp->size)
		wp = wp->next_bysize;

	if (wp == &oversize_list) /* empty list or nothing big enough */
		return (NULL);
	/* breaking up a chunk of memory */
	if ((long)((wp->size - (size + OVSZ_HEADER_SIZE + MTMALLOC_MIN_ALIGN)))
	    > MAX_CACHED) {
		caddr_t off;
		oversize_t *np;
		size_t osize;
		off = (caddr_t)ALIGN(wp->addr + size,
		    MTMALLOC_MIN_ALIGN);
		osize = wp->size;
		wp->size = (size_t)(off - wp->addr);
		np = oversize_header_alloc((uintptr_t)off,
		    osize - (wp->size + OVSZ_HEADER_SIZE));
		if ((long)np->size < 0)
			abort();
		unlink_oversize(wp);
		add_oversize(np);
	} else {
		unlink_oversize(wp);
	}
	return (wp);
}

static void
copy_pattern(uint32_t pattern, void *buf_arg, size_t size)
{
	uint32_t *bufend = (uint32_t *)((char *)buf_arg + size);
	uint32_t *buf = buf_arg;

	while (buf < bufend - 3) {
		buf[3] = buf[2] = buf[1] = buf[0] = pattern;
		buf += 4;
	}
	while (buf < bufend)
		*buf++ = pattern;
}

static void *
verify_pattern(uint32_t pattern, void *buf_arg, size_t size)
{
	uint32_t *bufend = (uint32_t *)((char *)buf_arg + size);
	uint32_t *buf;

	for (buf = buf_arg; buf < bufend; buf++)
		if (*buf != pattern)
			return (buf);
	return (NULL);
}

static void
free_oversize(oversize_t *ovp)
{
	assert(((uintptr_t)ovp->addr & 7) == 0); /* are we 8 byte aligned */
	assert(ovp->size > MAX_CACHED);

	ovp->next_bysize = ovp->prev_bysize = NULL;
	ovp->next_byaddr = ovp->prev_byaddr = NULL;
	(void) mutex_lock(&oversize_lock);
	add_oversize(ovp);
	(void) mutex_unlock(&oversize_lock);
}

static oversize_t *
oversize_header_alloc(uintptr_t mem, size_t size)
{
	oversize_t *ovsz_hdr;

	assert(size > MAX_CACHED);

	ovsz_hdr = (oversize_t *)mem;
	ovsz_hdr->prev_bysize = NULL;
	ovsz_hdr->next_bysize = NULL;
	ovsz_hdr->prev_byaddr = NULL;
	ovsz_hdr->next_byaddr = NULL;
	ovsz_hdr->hash_next = NULL;
	ovsz_hdr->size = size;
	mem += OVSZ_SIZE;
	*(uintptr_t *)mem = MTMALLOC_OVERSIZE_MAGIC;
	mem += OVERHEAD;
	assert(((uintptr_t)mem & 7) == 0); /* are we 8 byte aligned */
	ovsz_hdr->addr = (caddr_t)mem;
	return (ovsz_hdr);
}

static void
malloc_prepare()
{
	percpu_t *cpuptr;
	cache_head_t *cachehead;
	cache_t *thiscache;

	(void) mutex_lock(&oversize_lock);
	for (cpuptr = &cpu_list[0]; cpuptr < &cpu_list[ncpus]; cpuptr++) {
		(void) mutex_lock(&cpuptr->mt_parent_lock);
		for (cachehead = &cpuptr->mt_caches[0];
		    cachehead < &cpuptr->mt_caches[NUM_CACHES];
		    cachehead++) {
			for (thiscache = cachehead->mt_cache;
			    thiscache != NULL;
			    thiscache = thiscache->mt_next) {
				(void) mutex_lock(
				    &thiscache->mt_cache_lock);
			}
		}
	}
}

static void
malloc_release()
{
	percpu_t *cpuptr;
	cache_head_t *cachehead;
	cache_t *thiscache;

	for (cpuptr = &cpu_list[ncpus - 1]; cpuptr >= &cpu_list[0]; cpuptr--) {
		for (cachehead = &cpuptr->mt_caches[NUM_CACHES - 1];
		    cachehead >= &cpuptr->mt_caches[0];
		    cachehead--) {
			for (thiscache = cachehead->mt_cache;
			    thiscache != NULL;
			    thiscache = thiscache->mt_next) {
				(void) mutex_unlock(
				    &thiscache->mt_cache_lock);
			}
		}
		(void) mutex_unlock(&cpuptr->mt_parent_lock);
	}
	(void) mutex_unlock(&oversize_lock);
}

#pragma init(malloc_init)
static void
malloc_init(void)
{
	/*
	 * This works in the init section for this library
	 * because setup_caches() doesn't call anything in libc
	 * that calls malloc().  If it did, disaster would ensue.
	 *
	 * For this to work properly, this library must be the first
	 * one to have its init section called (after libc) by the
	 * dynamic linker.  If some other library's init section
	 * ran first and called malloc(), disaster would ensue.
	 * Because this is an interposer library for malloc(), the
	 * dynamic linker arranges for its init section to run first.
	 */
	(void) setup_caches();

	(void) pthread_atfork(malloc_prepare, malloc_release, malloc_release);
}
