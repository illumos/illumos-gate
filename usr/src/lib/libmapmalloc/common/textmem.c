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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*	Copyright (c) 1984, 1986, 1987, 1988, 1989 AT&T	*/
/*	  All Rights Reserved  	*/

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>


/*
 * Simplified version of malloc(), free() and realloc(), to be linked with
 * utilities that use [s]brk() and do not define their own version of the
 * routines.
 *
 * The algorithm used to get extra memory space by mmap'ing /dev/zero. This
 * breaks if the application closes the open descriptor, so now it uses
 * mmap's MAP_ANON feature.
 *
 * Each call to mmap() creates a page. The pages are linked in a list.
 * Each page is divided in blocks. There is at least one block in a page.
 * New memory chunks are allocated on a first-fit basis.
 * Freed blocks are joined in larger blocks. Free pages are unmapped.
 */
#include <stdlib.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <thread.h>
#include <pthread.h>
#include <synch.h>
#include <string.h>

static mutex_t lock = DEFAULTMUTEX;

struct block {
	size_t size;		/* Space available for user */
	struct page *page;	/* Backwards reference to page */
	int status;
	struct block *next;
	void *memstart[1];
};

struct page {
	size_t size;		/* Total page size (incl. header) */
	struct page *next;
	struct block block[1];
};

#define	FREE	0
#define	BUSY	1

#define	HDR_BLOCK	(sizeof (struct block) - sizeof (void *))
#define	HDR_PAGE	(sizeof (struct page) - sizeof (void *))
#define	MINSZ		sizeof (double)

/* for convenience */
#ifndef	NULL
#define	NULL		(0)
#endif

struct page *memstart;
static int pagesize;
static void defrag(struct page *);
static void split(struct block *,  size_t);
static void *malloc_unlocked(size_t);
static size_t align(size_t, int);

void *
malloc(size_t size)
{
	void *retval;
	(void) mutex_lock(&lock);
	retval = malloc_unlocked(size);
	(void) mutex_unlock(&lock);
	return (retval);
}


static void *
malloc_unlocked(size_t size)
{
	struct block *block;
	struct page *page;

	if (pagesize == 0)
		pagesize = (int)sysconf(_SC_PAGESIZE);

	size = align(size, MINSZ);

	/*
	 * Try to locate necessary space
	 */
	for (page = memstart; page; page = page->next) {
		for (block = page->block; block; block = block->next) {
			if (block->status == FREE && block->size >= size)
				goto found;
		}
	}
found:

	/*
	 * Need to allocate a new page
	 */
	if (!page) {
		size_t totsize = size + HDR_PAGE;
		size_t totpage = align(totsize, pagesize);

		if ((page = (struct page *)mmap(0, totpage,
		    PROT_READ|PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0))
		    == MAP_FAILED)
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

	block->status = BUSY;
	return (&block->memstart);
}

void *
realloc(void *ptr, size_t size)
{
	struct block *block;
	size_t osize;
	void *newptr;

	(void) mutex_lock(&lock);
	if (ptr == NULL) {
		newptr = malloc_unlocked(size);
		(void) mutex_unlock(&lock);
		return (newptr);
	}
	block = (struct block *)((char *)ptr - HDR_BLOCK);
	size = align(size, MINSZ);
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
		(void) mutex_unlock(&lock);
		return (ptr);
	}

	newptr = malloc_unlocked(size);
	(void) memcpy(newptr, ptr, osize);
	block->status = FREE;
	defrag(block->page);
	(void) mutex_unlock(&lock);
	return (newptr);
}

void
free(void *ptr)
{
	struct block *block;

	(void) mutex_lock(&lock);
	if (ptr == NULL) {
		(void) mutex_unlock(&lock);
		return;
	}
	block = (struct block *)((char *)ptr - HDR_BLOCK);
	block->status = FREE;

	defrag(block->page);
	(void) mutex_unlock(&lock);
}

/*
 * Align size on an appropriate boundary
 */
static size_t
align(size_t size, int bound)
{
	if (size < bound)
		return ((size_t)bound);
	else
		return (size + bound - 1 - (size + bound - 1) % bound);
}

static void
split(struct block *block, size_t size)
{
	if (block->size > size + sizeof (struct block)) {
		struct block *newblock;
		newblock = (struct block *)((char *)block + HDR_BLOCK + size);
		newblock->next = block->next;
		block->next = newblock;
		newblock->status = FREE;
		newblock->page = block->page;
		newblock->size = block->size - size - HDR_BLOCK;
		block->size = size;
	}
}

/*
 * Defragmentation
 */
static void
defrag(struct page *page)
{
	struct block *block;

	for (block = page->block; block; block = block->next) {
		struct block *block2;

		if (block->status == BUSY)
			continue;
		for (block2 = block->next; block2 && block2->status == FREE;
		    block2 = block2->next) {
			block->next = block2->next;
			block->size += block2->size + HDR_BLOCK;
		}
	}

	/*
	 * Free page
	 */
	if (page->block->size == page->size - HDR_PAGE) {
		if (page == memstart)
			memstart = page->next;
		else {
			struct page *page2;
			for (page2 = memstart; page2->next;
			    page2 = page2->next) {
				if (page2->next == page) {
					page2->next = page->next;
					break;
				}
			}
		}
		(void) munmap((caddr_t)page, page->size);
	}
}

static void
malloc_prepare()
{
	(void) mutex_lock(&lock);
}

static void
malloc_release()
{
	(void) mutex_unlock(&lock);
}

#pragma init(malloc_init)
static void
malloc_init(void)
{
	(void) pthread_atfork(malloc_prepare, malloc_release, malloc_release);
}
