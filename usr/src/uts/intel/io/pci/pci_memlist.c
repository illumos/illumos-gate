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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 * Copyright 2020 OmniOS Community Edition (OmniOSce) Association.
 * Copyright 2024 Oxide Computer Company
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

int pci_memlist_debug;
#define	dprintf if (pci_memlist_debug) printf

void
pci_memlist_dump(struct memlist *listp)
{
	dprintf("memlist 0x%p content: ", (void *)listp);
	while (listp) {
		dprintf("(0x%lx, 0x%lx) ",
		    listp->ml_address, listp->ml_size);
		listp = listp->ml_next;
	}
	dprintf("\n");
}

struct memlist *
pci_memlist_alloc()
{
	return ((struct memlist *)kmem_zalloc(sizeof (struct memlist),
	    KM_SLEEP));
}

void
pci_memlist_free(struct memlist *buf)
{
	kmem_free(buf, sizeof (struct memlist));
}

void
pci_memlist_free_all(struct memlist **list)
{
	struct memlist  *next, *buf;

	next = *list;
	while (next) {
		buf = next;
		next = buf->ml_next;
		kmem_free(buf, sizeof (struct memlist));
	}
	*list = 0;
}

/* insert in the order of addresses */
void
pci_memlist_insert(struct memlist **listp, uint64_t addr, uint64_t size)
{
	int merge_left, merge_right;
	struct memlist *entry;
	struct memlist *prev = 0, *next;

	/* find the location in list */
	next = *listp;
	while (next && next->ml_address <= addr) {
		/*
		 * Drop if this entry already exists, in whole
		 * or in part
		 */
		if (next->ml_address <= addr &&
		    next->ml_address + next->ml_size >= addr + size) {
			/* next already contains this entire element; drop */
			return;
		}

		/* Is this a "grow block size" request? */
		if (next->ml_address == addr) {
			break;
		}
		prev = next;
		next = prev->ml_next;
	}

	merge_left = (prev && addr == prev->ml_address + prev->ml_size);
	merge_right = (next && addr + size == next->ml_address);
	if (merge_left && merge_right) {
		prev->ml_size += size + next->ml_size;
		prev->ml_next = next->ml_next;
		pci_memlist_free(next);
		return;
	}

	if (merge_left) {
		prev->ml_size += size;
		return;
	}

	if (merge_right) {
		next->ml_address = addr;
		next->ml_size += size;
		return;
	}

	entry = pci_memlist_alloc();
	entry->ml_address = addr;
	entry->ml_size = size;
	if (prev == 0) {
		entry->ml_next = *listp;
		*listp = entry;
	} else {
		entry->ml_next = next;
		prev->ml_next = entry;
	}
}

/*
 * Delete memlist entries, assuming list sorted by address
 */

#define	MIN(a, b)	((a) < (b) ? (a) : (b))
#define	MAX(a, b)	((a) > (b) ? (a) : (b))
#define	IN_RANGE(a, b, e) ((a) >= (b) && (a) <= (e))

int
pci_memlist_remove(struct memlist **listp, uint64_t addr, uint64_t size)
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
		chunk_begin = chunk->ml_address;
		chunk_end = chunk->ml_address + chunk->ml_size - 1;
		begin_in_chunk = IN_RANGE(rem_begin, chunk_begin, chunk_end);
		end_in_chunk = IN_RANGE(rem_end, chunk_begin, chunk_end);

		if (rem_begin <= chunk_begin && rem_end >= chunk_end) {
			struct memlist *delete_chunk;

			/* spans entire chunk - delete chunk */
			delete_chunk = chunk;
			if (prev == 0)
				chunk = *listp = chunk->ml_next;
			else
				chunk = prev->ml_next = chunk->ml_next;

			pci_memlist_free(delete_chunk);
			/* skip to start of while-loop */
			continue;
		} else if (begin_in_chunk && end_in_chunk &&
		    chunk_begin != rem_begin && chunk_end != rem_end) {
			struct memlist *new;
			/* split chunk */
			new = pci_memlist_alloc();
			new->ml_address = rem_end + 1;
			new->ml_size = chunk_end - new->ml_address + 1;
			chunk->ml_size = rem_begin - chunk_begin;
			new->ml_next = chunk->ml_next;
			chunk->ml_next = new;
			/* done - break out of while-loop */
			break;
		} else if (begin_in_chunk || end_in_chunk) {
			/* trim chunk */
			chunk->ml_size -= MIN(chunk_end, rem_end) -
			    MAX(chunk_begin, rem_begin) + 1;
			if (rem_begin <= chunk_begin) {
				chunk->ml_address = rem_end + 1;
				break;
			}
			/* fall-through to next chunk */
		}
		prev = chunk;
		chunk = chunk->ml_next;
	}

	return (0);
}

/*
 * find and claim a memory chunk of given size, first fit
 */
uint64_t
pci_memlist_find(struct memlist **listp, uint64_t size, int align)
{
	uint64_t delta, total_size;
	uint64_t paddr;
	struct memlist *prev = 0, *next;

	/* find the chunk with sufficient size */
	next = *listp;
	while (next) {
		delta = next->ml_address & ((align != 0) ? (align - 1) : 0);
		if (delta != 0)
			total_size = size + align - delta;
		else
			total_size = size; /* the addr is already aligned */
		if (next->ml_size >= total_size)
			break;
		prev = next;
		next = prev->ml_next;
	}

	if (next == 0)
		return (0);	/* Not found */

	paddr = next->ml_address;
	if (delta)
		paddr += align - delta;
	(void) pci_memlist_remove(listp, paddr, size);

	return (paddr);
}

/*
 * find and claim a memory chunk of given size, starting
 * at a specified address
 */
uint64_t
pci_memlist_find_with_startaddr(struct memlist **listp, uint64_t address,
    uint64_t size, int align)
{
	uint64_t delta, total_size;
	uint64_t paddr;
	struct memlist *next;

	/* find the chunk starting at 'address' */
	next = *listp;
	while (next && (next->ml_address != address)) {
		next = next->ml_next;
	}
	if (next == 0)
		return (0);	/* Not found */

	delta = next->ml_address & ((align != 0) ? (align - 1) : 0);
	if (delta != 0)
		total_size = size + align - delta;
	else
		total_size = size;	/* the addr is already aligned */
	if (next->ml_size < total_size)
		return (0);	/* unsufficient size */

	paddr = next->ml_address;
	if (delta)
		paddr += align - delta;
	(void) pci_memlist_remove(listp, paddr, size);

	return (paddr);
}

/*
 * Subsume memlist src into memlist dest
 */
void
pci_memlist_subsume(struct memlist **src, struct memlist **dest)
{
	struct memlist *head, *prev;

	head = *src;
	while (head) {
		pci_memlist_insert(dest, head->ml_address, head->ml_size);
		prev = head;
		head = head->ml_next;
		pci_memlist_free(prev);
	}
	*src = 0;
}

/*
 * Merge memlist src into memlist dest; don't destroy src
 */
void
pci_memlist_merge(struct memlist **src, struct memlist **dest)
{
	struct memlist *p;

	p = *src;
	while (p) {
		pci_memlist_insert(dest, p->ml_address, p->ml_size);
		p = p->ml_next;
	}
}

/*
 * Make a copy of memlist
 */
struct memlist *
pci_memlist_dup(struct memlist *listp)
{
	struct memlist *head = 0, *prev = 0;

	while (listp) {
		struct memlist *entry = pci_memlist_alloc();
		entry->ml_address = listp->ml_address;
		entry->ml_size = listp->ml_size;
		entry->ml_next = 0;
		if (prev)
			prev->ml_next = entry;
		else
			head = entry;
		prev = entry;
		listp = listp->ml_next;
	}

	return (head);
}

int
pci_memlist_count(struct memlist *listp)
{
	int count = 0;
	while (listp) {
		count++;
		listp = listp->ml_next;
	}

	return (count);
}
