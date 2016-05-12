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
 * Copyright (c) 2000, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright (c) 2015, Joyent, Inc.  All rights reserved.
 */

#include "lint.h"
#include "thr_uberdata.h"
#include <sys/syscall.h>

extern long __systemcall6(sysret_t *, int, ...);

/*
 * This is a small and simple power of two memory allocator that is
 * used internally by libc.  Allocations are fast and memory is never
 * returned to the system, except for allocations of 64 Kbytes and larger,
 * which are simply mmap()ed and munmap()ed as needed.  Smaller allocations
 * (minimum size is 64 bytes) are obtained from mmap() of 64K chunks
 * broken up into unit allocations and maintained on free lists.
 * The interface requires the caller to keep track of the size of an
 * allocated block and to pass that size back when freeing a block.
 *
 * This allocator is called during initialization, from code called
 * from the dynamic linker, so it must not call anything that might
 * re-invoke the dynamic linker to resolve a symbol.  That is,
 * it must only call functions that are wholly private to libc.
 *
 * Also, this allocator must be unique across all link maps
 * because pointers returned by lmalloc() are stored in the
 * thread structure, which is constant across all link maps.
 *
 * Memory blocks returned by lmalloc() are initialized to zero.
 */

#define	MINSIZE		64	/* (1 << MINSHIFT) */
#define	MINSHIFT	6
#define	CHUNKSIZE	(64 * 1024)

/*
 * bucketnum	allocation size
 * 0		64
 * 1		128
 * 2		256
 * 3		512
 * 4		1024
 * 5		2048
 * 6		4096
 * 7		8192
 * 8		16384
 * 9		32768
 */

/*
 * See "thr_uberdata.h" for the definition of bucket_t.
 * The 10 (NBUCKETS) buckets are allocated in uberdata.
 */

/*
 * Performance hack:
 *
 * On the very first lmalloc(), before any memory has been allocated,
 * mmap() a 24K block of memory and carve out six 2K chunks, each
 * of which is subdivided for the initial allocations from buckets
 * 0, 1, 2, 3, 4 and 5, giving them initial numbers of elements
 * 32, 16, 8, 4, 2 and 1, respectively.  The remaining 12K is cut
 * into one 4K buffer for bucket 6 and one 8K buffer for bucket 7.
 *
 * This results in almost all simple single-threaded processes,
 * such as those employed in the kenbus test suite, having to
 * allocate only this one 24K block during their lifetimes.
 */

#define	SUBCHUNKSIZE	2048
#define	BASE_SIZE	(24 * 1024)

static void
initial_allocation(bucket_t *bp)	/* &__uberdata.bucket[0] */
{
	sysret_t rval;
	void *ptr;
	size_t size;
	size_t n;
	int bucketnum;
	void *base;

	/*
	 * We do this seemingly obtuse call to __systemcall6(SYS_mmap)
	 * instead of simply calling mmap() directly because, if the
	 * mmap() system call fails, we must make sure that __cerror()
	 * is not called, because that would call ___errno()
	 * which would dereference curthread and, because we are very
	 * early in libc initialization, curthread is NULL and we would
	 * draw a hard-to-debug SIGSEGV core dump, or worse.
	 * We opt to give a thread panic message instead.
	 */
	if (__systemcall6(&rval, SYS_mmap, CHUNKSIZE, BASE_SIZE,
	    PROT_READ | PROT_WRITE | PROT_EXEC,
	    _MAP_NEW | MAP_PRIVATE | MAP_ANON | MAP_ALIGN, -1L, (off_t)0) != 0)
		thr_panic("initial allocation failed; swap space exhausted?");
	base = (void *)rval.sys_rval1;

	for (bucketnum = 0; bucketnum < 6; bucketnum++, bp++) {
		size = (size_t)MINSIZE << bucketnum;
		n = SUBCHUNKSIZE / size;
		ptr = (void *)((caddr_t)base + bucketnum * SUBCHUNKSIZE);

		ASSERT(bp->free_list == NULL);
		bp->free_list = ptr;
		while (--n != 0) {
			void *next = (void *)((caddr_t)ptr + size);
			*(void **)ptr = next;
			ptr = next;
		}
		*(void **)ptr = NULL;
	}

	ptr = (void *)((caddr_t)base + bucketnum * SUBCHUNKSIZE);
	ASSERT(bp->free_list == NULL);
	bp->free_list = ptr;

	ptr = (void *)((caddr_t)ptr + 2 * SUBCHUNKSIZE);
	bp++;
	ASSERT(bp->free_list == NULL);
	bp->free_list = ptr;

	ASSERT(((caddr_t)ptr - (caddr_t)base + 4 * SUBCHUNKSIZE) == BASE_SIZE);
}

/*
 * This highbit code is the same as the code in fls_impl().
 * We inline it here for speed.
 */
static int
getbucketnum(size_t size)
{
	int highbit = 1;

	if (size-- <= MINSIZE)
		return (0);

#ifdef _LP64
	if (size & 0xffffffff00000000ul)
		highbit += 32, size >>= 32;
#endif
	if (size & 0xffff0000)
		highbit += 16, size >>= 16;
	if (size & 0xff00)
		highbit += 8, size >>= 8;
	if (size & 0xf0)
		highbit += 4, size >>= 4;
	if (size & 0xc)
		highbit += 2, size >>= 2;
	if (size & 0x2)
		highbit += 1;

	ASSERT(highbit > MINSHIFT);
	return (highbit - MINSHIFT);
}

void *
lmalloc(size_t size)
{
	int bucketnum = getbucketnum(size);
	ulwp_t *self;
	uberdata_t *udp;
	bucket_t *bp;
	void *ptr;

	/*
	 * ulwp_t structures must be allocated from a rwx mapping since it
	 * is a normal data object _and_ it contains instructions that are
	 * executed for user-land DTrace tracing with the fasttrap provider.
	 */
	int prot = PROT_READ | PROT_WRITE | PROT_EXEC;

	/* round size up to the proper power of 2 */
	size = (size_t)MINSIZE << bucketnum;

	if (bucketnum >= NBUCKETS) {
		/* mmap() allocates memory already set to zero */
		ptr = mmap((void *)CHUNKSIZE, size, prot,
		    MAP_PRIVATE|MAP_ANON|MAP_ALIGN, -1, (off_t)0);
		if (ptr == MAP_FAILED)
			ptr = NULL;
		return (ptr);
	}

	if ((self = __curthread()) == NULL)
		udp = &__uberdata;
	else
		udp = self->ul_uberdata;

	if (udp->bucket_init == 0) {
		ASSERT(udp->nthreads == 0);
		initial_allocation(udp->bucket);
		udp->bucket_init = 1;
	}

	bp = &udp->bucket[bucketnum];
	if (self != NULL)
		lmutex_lock(&bp->bucket_lock);

	if ((ptr = bp->free_list) == NULL) {
		size_t bsize;
		size_t n;

		/*
		 * Double the number of chunks mmap()ed each time,
		 * in case of large numbers of allocations.
		 */
		if (bp->chunks == 0)
			bp->chunks = 1;
		else
			bp->chunks <<= 1;
		for (;;) {
			bsize = CHUNKSIZE * bp->chunks;
			n = bsize / size;
			ptr = mmap((void *)CHUNKSIZE, bsize, prot,
			    MAP_PRIVATE|MAP_ANON|MAP_ALIGN, -1, (off_t)0);
			if (ptr != MAP_FAILED)
				break;
			/* try a smaller chunk allocation */
			if ((bp->chunks >>= 1) == 0) {
				if (self != NULL)
					lmutex_unlock(&bp->bucket_lock);
				return (NULL);
			}
		}
		bp->free_list = ptr;
		while (--n != 0) {
			void *next = (void *)((caddr_t)ptr + size);
			*(void **)ptr = next;
			ptr = next;
		}
		*(void **)ptr = NULL;
		ptr = bp->free_list;
	}
	bp->free_list = *(void **)ptr;
	if (self != NULL)
		lmutex_unlock(&bp->bucket_lock);
	/*
	 * We maintain the free list already zeroed except for the pointer
	 * stored at the head of the block (mmap() allocates memory already
	 * set to zero), so all we have to do is zero out the pointer.
	 */
	*(void **)ptr = NULL;
	return (ptr);
}

void
lfree(void *ptr, size_t size)
{
	int bucketnum = getbucketnum(size);
	ulwp_t *self;
	bucket_t *bp;

	/* round size up to the proper power of 2 */
	size = (size_t)MINSIZE << bucketnum;

	if (bucketnum >= NBUCKETS) {
		/* see comment below */
		if (((uintptr_t)ptr & (CHUNKSIZE - 1)) != 0)
			goto bad;
		(void) munmap(ptr, size);
		return;
	}

	/*
	 * If the low order bits are not all zero as expected, then panic.
	 * This can be caused by an application calling, for example,
	 * pthread_attr_destroy() without having first called
	 * pthread_attr_init() (thereby passing uninitialized data
	 * to pthread_attr_destroy() who then calls lfree() with
	 * the uninitialized data).
	 */
	if (((uintptr_t)ptr & (size - 1)) != 0)
		goto bad;

	/*
	 * Zeroing the memory here saves time later when reallocating it.
	 */
	(void) memset(ptr, 0, size);

	if ((self = __curthread()) == NULL)
		bp = &__uberdata.bucket[bucketnum];
	else {
		bp = &self->ul_uberdata->bucket[bucketnum];
		lmutex_lock(&bp->bucket_lock);
	}
	*(void **)ptr = bp->free_list;
	bp->free_list = ptr;
	if (self != NULL)
		lmutex_unlock(&bp->bucket_lock);
	return;

bad:
	thr_panic("lfree() called with a misaligned pointer");
}

/*
 * The following functions can be used internally to libc
 * to make memory allocations in the style of malloc()/free()
 * (where the size of the allocation is not remembered by the caller)
 * but which are safe to use within critical sections, that is,
 * sections of code bounded by enter_critical()/exit_critical(),
 * lmutex_lock()/lmutex_unlock() or lrw_rdlock()/lrw_wrlock()/lrw_unlock().
 *
 * These functions must never be used to allocate memory that is
 * passed out of libc, for example by strdup(), because it is a
 * fatal error to free() an object allocated by libc_malloc().
 * Such objects can only be freed by calling libc_free().
 */

#ifdef	_LP64
#define	ALIGNMENT	16
#else
#define	ALIGNMENT	8
#endif

typedef union {
	size_t	private_size;
	char	private_align[ALIGNMENT];
} private_header_t;

void *
libc_malloc(size_t size)
{
	private_header_t *ptr;

	size = (size_t)MINSIZE << getbucketnum(size + sizeof (*ptr));
	if ((ptr = lmalloc(size)) == NULL)
		return (NULL);
	ptr->private_size = size;
	return (ptr + 1);
}

void *
libc_realloc(void *old, size_t size)
{
	private_header_t *ptr;
	void *new;

	size = (size_t)MINSIZE << getbucketnum(size + sizeof (*ptr));
	if ((ptr = lmalloc(size)) == NULL)
		return (NULL);
	ptr->private_size = size;
	new = ptr + 1;
	if (old != NULL) {
		ptr = (private_header_t *)old - 1;
		if (size >= ptr->private_size)
			size = ptr->private_size;
		(void) memcpy(new, old, size - sizeof (*ptr));
		lfree(ptr, ptr->private_size);
	}
	return (new);
}

void
libc_free(void *p)
{
	private_header_t *ptr;

	if (p) {
		ptr = (private_header_t *)p - 1;
		lfree(ptr, ptr->private_size);
	}
}

char *
libc_strdup(const char *s1)
{
	char *s2 = libc_malloc(strlen(s1) + 1);

	if (s2)
		(void) strcpy(s2, s1);
	return (s2);
}
