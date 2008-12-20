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

/*
 * XXX This stuff should be in usr/src/common, to be shared by boot
 * code, kernel DR, and busra stuff.
 *
 * NOTE: We are only using the next-> link. The prev-> link is
 *	not used in the implementation.
 */
#include <sys/types.h>
#include <sys/memlist.h>
#include <sys/kmem.h>
#include <sys/cmn_err.h>
#include <sys/pci_impl.h>
#include <sys/debug.h>

extern int pci_boot_debug;
#define	dprintf if (pci_boot_debug) printf

void
memlist_dump(struct memlist *listp)
{
	dprintf("memlist 0x%p content", (void *)listp);
	while (listp) {
		dprintf("(0x%x%x, 0x%x%x)",
		    (int)(listp->address >> 32), (int)listp->address,
		    (int)(listp->size >> 32), (int)listp->size);
		listp = listp->next;
	}
}

struct memlist *
memlist_alloc()
{
	return ((struct memlist *)kmem_zalloc(sizeof (struct memlist),
	    KM_SLEEP));
}

void
memlist_free(struct memlist *buf)
{
	kmem_free(buf, sizeof (struct memlist));
}

void
memlist_free_all(struct memlist **list)
{
	struct memlist  *next, *buf;

	next = *list;
	while (next) {
		buf = next;
		next = buf->next;
		kmem_free(buf, sizeof (struct memlist));
	}
	*list = 0;
}

/* insert in the order of addresses */
void
memlist_insert(struct memlist **listp, uint64_t addr, uint64_t size)
{
	int merge_left, merge_right;
	struct memlist *entry;
	struct memlist *prev = 0, *next;

	/* find the location in list */
	next = *listp;
	while (next && next->address < addr) {
		prev = next;
		next = prev->next;
	}

	merge_left = (prev && addr == prev->address + prev->size);
	merge_right = (next && addr + size == next->address);
	if (merge_left && merge_right) {
		prev->size += size + next->size;
		prev->next = next->next;
		memlist_free(next);
		return;
	}

	if (merge_left) {
		prev->size += size;
		return;
	}

	if (merge_right) {
		next->address = addr;
		next->size += size;
		return;
	}

	entry = memlist_alloc();
	entry->address = addr;
	entry->size = size;
	if (prev == 0) {
		entry->next = *listp;
		*listp = entry;
	} else {
		entry->next = next;
		prev->next = entry;
	}
}

/*
 * Delete memlist entries, assuming list sorted by address
 */

#define	MIN(a, b)	((a) < (b) ? (a) : (b))
#define	MAX(a, b)	((a) > (b) ? (a) : (b))
#define	IN_RANGE(a, b, e) ((a) >= (b) && (a) <= (e))

int
memlist_remove(struct memlist **listp, uint64_t addr, uint64_t size)
{
	struct memlist *prev = 0;
	struct memlist *chunk;
	uint64_t rem_begin, rem_end;
	uint64_t chunk_begin, chunk_end;
	int begin_in_chunk, end_in_chunk;


	/* ignore removal of zero-length item */
	if (size == 0)
		return (0);

	/* also inherently ignore a zero-length list */
	rem_begin = addr;
	rem_end = addr + size - 1;
	chunk = *listp;
	while (chunk) {
		chunk_begin = chunk->address;
		chunk_end = chunk->address + chunk->size - 1;
		begin_in_chunk = IN_RANGE(rem_begin, chunk_begin, chunk_end);
		end_in_chunk = IN_RANGE(rem_end, chunk_begin, chunk_end);

		if (rem_begin <= chunk_begin && rem_end >= chunk_end) {
			struct memlist *delete_chunk;

			/* spans entire chunk - delete chunk */
			delete_chunk = chunk;
			if (prev == 0)
				chunk = *listp = chunk->next;
			else
				chunk = prev->next = chunk->next;

			memlist_free(delete_chunk);
			/* skip to start of while-loop */
			continue;
		} else if (begin_in_chunk && end_in_chunk &&
		    chunk_begin != rem_begin && chunk_end != rem_end) {
			struct memlist *new;
			/* split chunk */
			new = memlist_alloc();
			new->address = rem_end + 1;
			new->size = chunk_end - new->address + 1;
			chunk->size = rem_begin - chunk_begin;
			new->next = chunk->next;
			chunk->next = new;
			/* done - break out of while-loop */
			break;
		} else if (begin_in_chunk || end_in_chunk) {
			/* trim chunk */
			chunk->size -= MIN(chunk_end, rem_end) -
			    MAX(chunk_begin, rem_begin) + 1;
			if (rem_begin <= chunk_begin) {
				chunk->address = rem_end + 1;
				break;
			}
			/* fall-through to next chunk */
		}
		prev = chunk;
		chunk = chunk->next;
	}

	return (0);
}

/*
 * find and claim a memory chunk of given size, first fit
 */
uint64_t
memlist_find(struct memlist **listp, uint64_t size, int align)
{
	uint64_t delta, total_size;
	uint64_t paddr;
	struct memlist *prev = 0, *next;

	/* find the chunk with sufficient size */
	next = *listp;
	while (next) {
		delta = next->address & ((align != 0) ? (align - 1) : 0);
		if (delta != 0)
			total_size = size + align - delta;
		else
			total_size = size; /* the addr is already aligned */
		if (next->size >= total_size)
			break;
		prev = next;
		next = prev->next;
	}

	if (next == 0)
		return (0);	/* Not found */

	paddr = next->address;
	if (delta)
		paddr += align - delta;
	(void) memlist_remove(listp, paddr, size);

	return (paddr);
}

/*
 * find and claim a memory chunk of given size, starting
 * at a specified address
 */
uint64_t
memlist_find_with_startaddr(struct memlist **listp, uint64_t address,
    uint64_t size, int align)
{
	uint64_t delta, total_size;
	uint64_t paddr;
	struct memlist *next;

	/* find the chunk starting at 'address' */
	next = *listp;
	while (next && (next->address != address)) {
		next = next->next;
	}
	if (next == 0)
		return (0);	/* Not found */

	delta = next->address & ((align != 0) ? (align - 1) : 0);
	if (delta != 0)
		total_size = size + align - delta;
	else
		total_size = size;	/* the addr is already aligned */
	if (next->size < total_size)
		return (0);	/* unsufficient size */

	paddr = next->address;
	if (delta)
		paddr += align - delta;
	(void) memlist_remove(listp, paddr, size);

	return (paddr);
}

/*
 * Merge memlist src into memlist dest
 */
void
memlist_merge(struct memlist **src, struct memlist **dest)
{
	struct memlist *head, *prev;

	head = *src;
	while (head) {
		memlist_insert(dest, head->address, head->size);
		prev = head;
		head = head->next;
		memlist_free(prev);
	}
	*src = 0;
}

/*
 * Make a copy of memlist
 */
struct memlist *
memlist_dup(struct memlist *listp)
{
	struct memlist *head = 0, *prev = 0;

	while (listp) {
		struct memlist *entry = memlist_alloc();
		entry->address = listp->address;
		entry->size = listp->size;
		entry->next = 0;
		if (prev)
			prev->next = entry;
		else
			head = entry;
		prev = entry;
		listp = listp->next;
	}

	return (head);
}

int
memlist_count(struct memlist *listp)
{
	int count = 0;
	while (listp) {
		count++;
		listp = listp->next;
	}

	return (count);
}
