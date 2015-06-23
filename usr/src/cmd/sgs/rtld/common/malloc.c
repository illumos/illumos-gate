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

/*
 *	Copyright (c) 1988 AT&T
 *	  All Rights Reserved
 */

/*
 * Simplified version of malloc(), calloc() and free(), to be linked with
 * utilities that use [s]brk() and do not define their own version of the
 * routines.
 * The algorithm maps /dev/zero to get extra memory space.
 * Each call to mmap() creates a page. The pages are linked in a list.
 * Each page is divided in blocks. There is at least one block in a page.
 * New memory chunks are allocated on a first-fit basis.
 * Freed blocks are joined in larger blocks. Free pages are unmapped.
 */

#include	<stdlib.h>
#include	<sys/types.h>
#include	<sys/mman.h>
#include	<sys/debug.h>
#include	<memory.h>
#include	"_rtld.h"
#include	"msg.h"

struct block {
	size_t		size;		/* Space available for user */
	struct page	*page;		/* Backwards reference to page */
	int		status;
	struct block	*next;
	void *		memstart[1];
};

struct page {
	size_t		size;		/* Total page size (incl. header) */
	struct page	*next;
	struct block	block[1];
};

#define	FREE	0
#define	BUSY	1

#define	HDR_BLOCK	(sizeof (struct block) - sizeof (void *))
#define	HDR_PAGE	(sizeof (struct page) - sizeof (void *))

static struct page	*memstart;

#if	DEBUG
/*
 * When built for debugging, scribble a pattern over newly allocated and
 * freed memory.
 */
#define	NEWMEM		0
#define	FREMEM		1

/* LINTED */
const ulong_t	patterns[] = {
	(ulong_t)0xbaddcafebaddcafeULL, (ulong_t)0xdeadbeefdeadbeefULL
};

static void
scribble(ulong_t *membgn, int pattern, size_t size)
{
	size_t	memsize = size / sizeof (ulong_t);

	while (memsize--) {
		if (pattern == FREMEM)
			ASSERT(*membgn != patterns[pattern]);
		*membgn++ = patterns[pattern];
	}
}
#endif

/*
 * Defragmentation
 */
void
defrag()
{
	struct page	*page;
	Aliste		idx;

	for (APLIST_TRAVERSE(free_alp, idx, page)) {
		struct block	*block;

		for (block = page->block; block; block = block->next) {
			struct block	*block2;

			if (block->status == BUSY)
				continue;
			for (block2 = block->next; block2 &&
			    block2->status == FREE; block2 = block2->next) {
				block->next = block2->next;
				block->size += block2->size + HDR_BLOCK;
			}
		}

		/*
		 * If a page becomes free, leave it, and save the unmapping
		 * expense, as we'll probably come back and reclaim the page
		 * for later malloc activity.
		 *
		 * Free the defrag index.
		 */
		aplist_delete(free_alp, &idx);
	}
}

static void
split(struct block *block, size_t size)
{
	if (block->size > size + sizeof (struct block)) {
		struct block	*newblock;
		/* LINTED */
		newblock = (struct block *)
		    ((char *)block + HDR_BLOCK + size);
		newblock->next = block->next;
		block->next = newblock;
		newblock->status = FREE;
		newblock->page = block->page;
		newblock->size = block->size - size - HDR_BLOCK;
		block->size = size;
	}
}

#include <stdio.h>

/*
 * Replace both malloc() and lmalloc() (libc's private memory allocator).
 * They are both private here.
 */
#pragma weak lmalloc = malloc
void *
malloc(size_t size)
{
	struct block	*block;
	struct page	*page;

	size = S_DROUND(size);

	/*
	 * Try to locate necessary space
	 */
	for (page = memstart; page; page = page->next) {
		for (block = page->block; block; block = block->next) {
			if ((block->status == FREE) && (block->size >= size))
				goto found;
		}
	}
found:
	/*
	 * Need to allocate a new page
	 */
	if (!page) {
		size_t	totsize = size + HDR_PAGE;
		size_t	totpage = S_ROUND(totsize, syspagsz);

		if ((page = dz_map(0, 0, totpage,
		    PROT_READ | PROT_WRITE | PROT_EXEC,
		    MAP_PRIVATE)) == MAP_FAILED)
			return (0);

		page->next = memstart;
		memstart = page;
		page->size = totpage;
		block = page->block;
		block->next = 0;
		block->status = FREE;
		block->size = totpage - HDR_PAGE;
		block->page = page;
	}

	split(block, size);
#if	DEBUG
	scribble((ulong_t *)&block->memstart, NEWMEM, block->size);
#endif
	block->status = BUSY;
	return (&block->memstart);
}

void *
calloc(size_t num, size_t size)
{
	void *	mp;
	size_t	total;

	if (num == 0 || size == 0) {
		total = 0;
	} else {
		total = num * size;

		/* check for overflow */
		if ((total / num) != size) {
			errno = ENOMEM;
			return (NULL);
		}
	}

	if ((mp = malloc(total)) == NULL)
		return (NULL);
	(void) memset(mp, 0, total);
	return (mp);
}

void *
realloc(void *ptr, size_t size)
{
	struct block	*block;
	size_t		osize;
	void *		newptr;

	if (ptr == NULL)
		return (malloc(size));

	/* LINTED */
	block = (struct block *)((char *)ptr - HDR_BLOCK);
	size = S_DROUND(size);
	osize = block->size;

	/*
	 * Join block with next one if it is free
	 */
	if (block->next && block->next->status == FREE) {
		block->size += block->next->size + HDR_BLOCK;
		block->next = block->next->next;
	}

	if (size <= block->size) {
		split(block, size);
#if	DEBUG
		if (block->size > osize)
			scribble((ulong_t *)((char *)ptr + osize), NEWMEM,
			    (block->size - osize));
#endif
		return (ptr);
	}

	if ((newptr = malloc(size)) == NULL)
		return (NULL);
	(void) memcpy(newptr, ptr, osize);
	block->status = FREE;

	/*
	 * Add the free block to the free APlist for later defragmentation.
	 * However, this addition can only be achieved if there is room on the
	 * free APlist.  The APlist can't be allowed to grow, as the growth
	 * requires a realloc(), which would recurse back here, resulting in an
	 * infinite loop.  If the free APlist is full, defrag() now.  This
	 * defragmentation might not be able to collapse any free space, but
	 * the free APlist will be cleared as part of the processing, ensuring
	 * room for the addition.
	 */
	if (free_alp && (aplist_nitems(free_alp) >= aplist_arritems(free_alp)))
		defrag();
	(void) aplist_test(&free_alp, block->page, AL_CNT_FREELIST);
	return (newptr);
}

/*
 * Replace both free() and lfree() (libc's private memory allocator).
 * They are both private here.
 */
void
free(void *ptr)
{
	struct block	*block;

	if (ptr == NULL)
		return;

	/* LINTED */
	block = (struct block *)((char *)ptr - HDR_BLOCK);
	block->status = FREE;
#if	DEBUG
	scribble((ulong_t *)&block->memstart, FREMEM, block->size);
#endif
	(void) aplist_test(&free_alp, block->page, AL_CNT_FREELIST);
}

/* ARGSUSED1 */
void
lfree(void *ptr, size_t size)
{
	free(ptr);
}

/*
 * We can use any memory after ld.so.1's .bss up until the next page boundary
 * as allocatable memory.
 */
void
addfree(void *ptr, size_t bytes)
{
	struct block	*block;
	struct page	*page;

	if (bytes <= sizeof (struct page))
		return;
	page = ptr;
	page->next = memstart;
	memstart = page;
	page->size = bytes;
	block = page->block;
	block->next = 0;
	block->status = FREE;
	block->size = bytes - HDR_PAGE;
	block->page = page;
}
