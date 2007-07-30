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
 * Copyright 2001-2003 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file manages the CMMU entries for the Wildcat RSM driver.  It keeps
 * track of which entries can be used for large pages, which entries are
 * free.  It also keeps the CMMU entries on each WCI in sync, by providing
 * generic CMMU read/write interfaces which it applies to each WCI.
 */

#include <sys/types.h>

#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/errno.h>
#include <sys/debug.h>
#include <sys/wci_regs.h>
#include <sys/wci_offsets.h>

#include <sys/wrsm_cmmu.h>
#include <sys/wrsm_config.h>
#include <sys/wrsm_nc.h> /* For wci_ids_t */

/*
 * The following macros define a DPRINTF macro which can be used to enable
 * or disable various levels of logging for this module.
 */
#ifdef DEBUG

#define	CMMUDBG		0x1
#define	CMMUWARN	0x2
#define	CMMUERR		0x4
#define	CMMUTRACE	0x8
static uint_t cmmu_debug = CMMUERR;

#define	DPRINTF(a, b) { if (cmmu_debug & a) wrsmdprintf b; }

#else /* DEBUG */

#define	DPRINTF(a, b) { }

#endif /* DEBUG */

#define	ERR(s)	DPRINTF(CMMUERR, (CE_WARN, s))
#define	WARN(s)	DPRINTF(CMMUWARN, (CE_WARN, s))
#define	NOTE(s)	DPRINTF(CMMUDBG, (CE_NOTE, s))
#define	DTRC(s)	DPRINTF(CMMUTRACE, (CE_NOTE, s))

#define	CMMU_SUCCESS	0
#define	RANGE_SIZE(start, end)	((end) - (start) + 1)
/*
 * Local types, constants and macros
 */

/*
 * A cmmu index is 21 bits (up to 2 million entries, with 16MB SRAM).
 * Each NcSlice can export either large pages or small pages.
 *
 * A single small page ncslice can export all 21 million pages. To go
 * from cmmu entry to ncslice offset for small pages, just shift the
 * cmmu index left 13 bits.
 *
 * Each large page ncslice can export 4096 entries of 4MB each. The
 * large page CMMU indices are defined as follows:
 *      index<11:0> = ncslice offset<33:22>
 *      index<14:12> = ncslice<2:0>
 *	index<20:15> = 0
 * Since the lower three bits of the ncslice are used to discriminate between
 * large page ncslice entries, only 8 large page ncslices can be exported
 * (actually, more can be exported, but they would share CMMU entries, so
 * there's no value in exporting more than 8).
 */

#define	MAX_LARGE_NCSLICES	8
#define	MAX_FREE_LISTS		(1 + MAX_LARGE_NCSLICES)
#define	FIRST_CMMU_ENTRY	2	/* 0 and 1 are special-cases */
/* large ncslice can export 4096 pgs, minus pages 0 and 1 which are special */
#define	MAX_PAGES_LARGE_SLICE	(0x1000 - FIRST_CMMU_ENTRY)
#define	LOW_3_BITS		0x7
#define	MAX_LARGE_PAGE_INDEX	0x7fff
#define	CESR_PAGE		0
#define	WRITELOCKOUT_PAGE	1

/* Constants for cluster_members_bits */
static const uint64_t MEMBERS_PER_REGISTER = 64;
static const uint64_t ONE_BIT = 0x1;

/* Constants for ncslice_config bits */
static const uint64_t SLICES_PER_REGISTER = 32;
static const uint64_t BITS_PER_SLICE = 2;
static const uint64_t TWO_BITS = 0x3;

/*
 * The free_region structure defines a range of free CMMU entries (i.e.,
 * a start and an end). It is designed to be an element of a doubly
 * linked list to track free CMMU entries.
 */
typedef struct free_region_struct {
	wrsm_cmmu_index_t start;
	wrsm_cmmu_index_t end;
	struct free_region_struct *prev;
	struct free_region_struct *next;
} free_region_t;

/*
 * The free_list_t contains a linked list of free regions and the
 * ncslice that these CMMU entries belong to. It also includes a mutex,
 * used whenever the linked list is being modified/traversed.
 */
typedef struct {
	kmutex_t mutex;
	ncslice_t ncslice;
	wrsm_cmmu_page_size_t page_size;
	free_region_t *list;
} free_list_t;

/* Set of free pages for absolute alloc */
#define	NUM_COMM_PAGES	WRSM_MAX_CNODES /* One per remote cnode */
#define	COMM_MASKS	WRSMMASKS(NUM_COMM_PAGES, 32)
typedef struct {
	uint32_t	b[COMM_MASKS];
} comm_bitmask_t;

/* Structure to keep track of which WCIs belong to us */
typedef struct wci_handle_struct
{
	lcwci_handle_t wci_handle;
	struct wci_handle_struct *next;
	struct wci_handle_struct *prev;
} wci_handle_t;

/* State structure for the CMMU allocator */
struct wrsm_cmmu_alloc {
	kmutex_t mutex;
	free_list_t free_lists[MAX_FREE_LISTS];
	unsigned num_free_lists;
	wrsm_cmmu_index_t max_entries;
	wrsm_cmmu_index_t num_free_entries;
	kcondvar_t resource_cv;
	wci_handle_t *wci_list;
	comm_bitmask_t comm_pages;
};

/*
 * Local Functions
 */
static void cmmu_attributes(wrsm_network_t *);

/* Converts an ncslice/offset to a CMMU index */
static wrsm_cmmu_index_t
offset_to_index(free_list_t *head, wrsm_cmmu_offset_t offset)
{
	uint64_t off = (uint64_t)offset;
	wrsm_cmmu_index_t index;

	ASSERT(head);
	if (head->page_size == CMMU_PAGE_SIZE_SMALL) {
		index = ((off >> 13) & 0x1fffff);
	} else {
		index = ((head->ncslice & 0x7) << 12) |
			((off >> 22) & 0x0fff);
	}
	return (index);
}

/* Converts a CMMU index to an ncslice offset */
static wrsm_cmmu_offset_t
index_to_offset(free_list_t *head, wrsm_cmmu_index_t index)
{
	wrsm_cmmu_offset_t offset;
	uint64_t idx = (uint64_t)index;

	ASSERT(head);

	if (head->page_size == CMMU_PAGE_SIZE_SMALL) {
		offset = (caddr_t)(idx << 13);
	} else {
		offset = (caddr_t)((idx & 0xfff) << 22);
	}
	return (offset);
}

/* Converts large page ncslice to starting CMMU entry */
static wrsm_cmmu_index_t
ncslice_to_start(ncslice_t ncslice)
{
	unsigned start = ((ncslice & 0x7) << 12) + FIRST_CMMU_ENTRY;
	return (start);
}

/* Converts large page ncslice to starting CMMU entry */
static wrsm_cmmu_index_t
ncslice_to_end(ncslice_t ncslice)
{
	unsigned start = ncslice_to_start(ncslice);
	return (start + MAX_PAGES_LARGE_SLICE - 1);
}

/* Converts an index to an ncslice */
static free_list_t *
IndexToFreeList(wrsm_cmmu_alloc_t *cmmu, wrsm_cmmu_index_t index)
{
	unsigned i;
	ASSERT(cmmu);

	/* If only lower 15 bits are set, this could be a large page */
	if (index <= MAX_LARGE_PAGE_INDEX) {
		/* Look for large ncslices with matching lower 3 bits */
		for (i = 0; i < cmmu->num_free_lists; i++) {
			ncslice_t ncslice = cmmu->free_lists[i].ncslice;
			wrsm_cmmu_index_t start = ncslice_to_start(ncslice);
			wrsm_cmmu_index_t end = ncslice_to_end(ncslice);
			if (start <= index && index <= end) {
				return (&cmmu->free_lists[i]);
			}
		}
	}
	/* We didn't find a large page ncslice, so use first small ncslice */
	for (i = 0; i < cmmu->num_free_lists; i++) {
		if (cmmu->free_lists[i].page_size == CMMU_PAGE_SIZE_SMALL) {
			return (&cmmu->free_lists[i]);
		}
	}
	/* No ncslice was found */
	return (NULL);
}

/* Copies the wci_cluster_members_bits registers from one WCI to another */
static void
clustermember_copy(lcwci_handle_t dest, lcwci_handle_t src)
{
	uint_t i;
	uint64_t reg;
	uint64_t offset = ADDR_WCI_CLUSTER_MEMBERS_BITS;
	DTRC("clustermember_copy");

	for (i = 0; i < ENTRIES_WCI_CLUSTER_MEMBERS_BITS; i++) {
		wrsm_lc_csr_read(src, offset, &reg);
		wrsm_lc_csr_write(dest, offset, reg);
		offset += STRIDE_WCI_CLUSTER_MEMBERS_BITS;
	}
}

/* Copies the wci_ncslice_config_array registers from one WCI to another */
static void
ncsliceconfig_copy(lcwci_handle_t dest, lcwci_handle_t src)
{
	uint_t i;
	uint64_t reg;
	uint64_t offset = ADDR_WCI_NC_SLICE_CONFIG_ARRAY;
	DTRC("ncsliceconfig_copy");

	for (i = 0; i < ENTRIES_WCI_NC_SLICE_CONFIG_ARRAY; i++) {
		wrsm_lc_csr_read(src, offset, &reg);
		wrsm_lc_csr_write(dest, offset, reg);
		offset += STRIDE_WCI_NC_SLICE_CONFIG_ARRAY;
	}
}

/*
 * Functions to manipulate a free region structure
 */

#ifdef DEBUG
/* Prints a region */
static void
region_print(char *msg, free_region_t *region)
{
	ASSERT(region);

	DPRINTF(CMMUDBG, (CE_NOTE,
		"%s 0x%p: start=%u, end=%u, next=0x%p, prev=0x%p",
		msg, (void *)region, region->start, region->end,
		(void *)region->next, (void *)region->prev));
}
#endif /* DEBUG */

#ifdef DEBUG
/* Returns the size of a region, i.e., the number of pages in the region */
static unsigned
region_size(free_region_t *region)
{
	ASSERT(region);
	return (RANGE_SIZE(region->start, region->end));
}
#endif

/* Creates a free region (from start to end), in the list 'head' */
static void
region_create(free_list_t *head, free_region_t *after,
	wrsm_cmmu_index_t start, wrsm_cmmu_index_t end)
{
	free_region_t *p = kmem_zalloc(sizeof (free_region_t), KM_SLEEP);
	DPRINTF(CMMUTRACE, (CE_NOTE, "region_create(start=%u, end=%u)",
	    start, end));
	ASSERT(head);
	ASSERT(mutex_owned(&head->mutex));
	ASSERT(p);

	p->start = start;
	p->end = end;
	p->prev = after;
	/* If after is NULL, adding to head of list */
	if (after == NULL) {
		p->next = head->list;
		head->list = p;
	} else {
		p->next = after->next;
		after->next = p;
	}
	if (p->next) {
		(p->next)->prev = p;
	}
}

/* Deletes a region from a free list, and frees its memory */
static void
region_delete(free_list_t *head, free_region_t *region)
{
	DTRC("region_delete");
	ASSERT(head);
	ASSERT(mutex_owned(&head->mutex));
	ASSERT(region);

	/* If this is first region in list, update head to point around it */
	if (region->prev == NULL) {
		head->list = region->next;
	} else {
		(region->prev)->next = region->next;
	}
	if (region->next) {
		(region->next)->prev = region->prev;
	}
	kmem_free(region, sizeof (free_region_t));
}

/*
 * The following function allows you to allocate a range of items from
 * a given region. Assumes the start and end are within the region. If
 * necessary, it will split the region, or delete it.
 */
static int
region_alloc(free_list_t *head, free_region_t *region,
	wrsm_cmmu_index_t start, wrsm_cmmu_index_t end)
{
	int retval = CMMU_SUCCESS;
	DPRINTF(CMMUTRACE, (CE_NOTE, "region_alloc(start=%u, end=%u)",
	    start, end));
	ASSERT(head);
	ASSERT(region);
	ASSERT(start <= end);
	ASSERT(mutex_owned(&head->mutex));

	/* Check that range is inclusive */
	if (start < region->start || end > region->end) {
		WARN("region_alloc: invalid args");
		retval = EINVAL;
	} else if (start == region->start && end == region->end) {
		/* A perfect fit, remove the region */
		region_delete(head, region);
	} else if (start == region->start) {
		/* Removing from the front of the region */
		region->start = end + 1;
	} else if (end == region->end) {
		/* Removing from the end of the region */
		region->end = start - 1;
	} else {
		/* Removing from the middle, must create new region */
		region_create(head, region, end + 1, region->end);
		/* Now "shrink" old region */
		region->end = start - 1;
	}
	return (retval);
}

/*
 * Functions to manipulate a free list
 */
#ifdef DEBUG
/* Traverses a list, print all its regions */
static void
/* LINTED: static unused: list_print (E_STATIC_UNUSED) */
list_print(free_list_t *head)
{
	free_region_t *p;
	ASSERT(head);
	ASSERT(mutex_owned(&head->mutex));

	DPRINTF(CMMUDBG, (CE_NOTE, "  ncslice = 0x%02X", head->ncslice));
	for (p = head->list; p; p = p->next) {
		region_print("    region:", p);
	}
}
#endif /* DEBUG */

#ifdef DEBUG
/* Traverses a list, checking the pointers */
static void
/* LINTED: static unused: list_check (E_STATIC_UNUSED) */
list_check(free_list_t *head)
{
	free_region_t *p;
	boolean_t ok = B_TRUE;
	ASSERT(head);
	ASSERT(mutex_owned(&head->mutex));

	for (p = head->list; p; p = p->next) {
		if (p->end < p->start) {
			DPRINTF(CMMUDBG, (CE_WARN, "p->end=%u >= p->start=%u",
			    p->end, p->start));
			ok = B_FALSE;
			break;
		}
		if (p->next) {
			if (p->end >= p->next->start) {
				DPRINTF(CMMUDBG, (CE_WARN,
				    "p->end=%u < p->next->start=%u",
				    p->end, p->next->start));
				ok = B_FALSE;
				break;
			}
			if (p->next->prev != p) {
				DPRINTF(CMMUDBG, (CE_WARN,
				    "p->next->prev=%p != p=%p",
				    (void *)p->next->prev, (void *)p));
				ok = B_FALSE;
				break;
			}
		}
	}
	if (!ok) {
		list_print(head);
	}
}
#endif /* DEBUG */

#ifdef DEBUG
/*
 * Returns the size of the list, i.e., the free pages in all regions
 * You must already own the mutex
 */
static unsigned
list_size(free_list_t *head)
{
	free_region_t *p;
	unsigned size = 0;
	ASSERT(head);
	ASSERT(mutex_owned(&head->mutex));

	list_check(head);
	for (p = head->list; p; p = p->next) {
		size += region_size(p);
	}
	return (size);
}
#endif

/* Initializes the given ncslice free list */
static void
list_init(free_list_t *head, ncslice_t ncslice_num,
		wrsm_cmmu_page_size_t page_size)
{
	DPRINTF(CMMUTRACE, (CE_CONT, "list_init ncslice %d\n", ncslice_num));
	ASSERT(head);

	mutex_init(&head->mutex, NULL, MUTEX_DRIVER, NULL);
	head->ncslice = ncslice_num;
	head->page_size = page_size;
	head->list = NULL;
}

/* Deletes all regions in the list */
static void
list_delete(free_list_t *head)
{
	DTRC("list_delete");
	ASSERT(head);
	ASSERT(mutex_owned(&head->mutex));
	while (head->list) {
		region_delete(head, head->list);
	}
}

/* Destroys the given ncslice free list */
static void
list_fini(free_list_t *head)
{
	DTRC("list_fini");
	ASSERT(head);
	mutex_enter(&head->mutex);
	list_delete(head);
	mutex_exit(&head->mutex);
	mutex_destroy(&head->mutex);
}

/*
 * Allocates a page at the given index.
 * Returns ENOMEM if the index was already allocated.
 */
static int
list_absolute_alloc(free_list_t *head, wrsm_cmmu_index_t start,
		unsigned count)
{
	int retval = ENOMEM;
	free_region_t *p;
	wrsm_cmmu_index_t end = start + count - 1;
#ifdef DEBUG
	unsigned old_size, new_size; /* To check for free page leaks */
#endif /* DEBUG */

	DTRC("list_absolute_alloc");
	ASSERT(head);

	mutex_enter(&head->mutex);
#ifdef DEBUG
	old_size = list_size(head);
#endif /* DEBUG */
	for (p = head->list; p; p = p->next) {
		if (p->start <= start && start <= p->end) {
			/* Starts somewhere within this region */
			retval = region_alloc(head, p, start, end);
			break;
		}
	}
	if (p == NULL) {
		DPRINTF(CMMUWARN, (CE_WARN, "list_absolute_alloc: "
		    "region [%d, %d] already allocated", start, end));
		retval = ENOMEM;
	}

#ifdef DEBUG
	/* Make sure we aren't leaking any pages */
	new_size = list_size(head);
	if (retval == 0) {
		ASSERT(old_size == new_size + count);
	} else {
		ASSERT(old_size == new_size);
	}
#endif /* DEBUG */

	mutex_exit(&head->mutex);
	return (retval);
}

/*
 * Allocates a range of entries with the best fit available. If it can't
 * allocate all the requested pages, it will respond with the number
 * of entries actually allocated. Returns ENOMEM if there aren't any
 * entries left.
 */
static int
list_best_alloc(free_list_t *head, unsigned desired_num,
		wrsm_cmmu_tuple_t *tuple)
{
	int retval = ENOMEM;
	free_region_t *p;
	free_region_t *best_region = NULL;
	unsigned best_diff = UINT_MAX;
	free_region_t *biggest_region = NULL;
	unsigned biggest_count = 0;
#ifdef DEBUG
	unsigned old_size, new_size; /* To check for free page leaks */
#endif /* DEBUG */

	DPRINTF(CMMUTRACE, (CE_NOTE, "list_best_alloc(num=%u)", desired_num));
	ASSERT(head);

	mutex_enter(&head->mutex);
#ifdef DEBUG
	old_size = list_size(head);
#endif /* DEBUG */
	for (p = head->list; p; p = p->next) {
		unsigned count = RANGE_SIZE(p->start, p->end);

		if (count == desired_num) {
			/* An exact match, can't beat that! */
			best_region = p;
			break;
		} else if (count > desired_num) {
			/* This range is too big, look for best fit */
			unsigned diff = count - desired_num;
			if (diff < best_diff) {
				best_region = p;
				best_diff = diff;
			}
		} else {
			/* Remember biggest, in case we don't fit anywhere */
			if (count > biggest_count) {
				biggest_region = p;
				biggest_count = count;
			}
		}
	}
	if (best_region != NULL) {
		/* We found a region at least large enough */
		tuple->index = best_region->start;
		tuple->count = desired_num;
		tuple->ncslice = head->ncslice;
		tuple->offset = index_to_offset(head, tuple->index);
		retval = region_alloc(head, best_region, best_region->start,
				best_region->start + desired_num - 1);
	} else if (biggest_region != NULL) {
		/* None were big enough, so just use the biggest region */
		tuple->index = biggest_region->start;
		tuple->count = RANGE_SIZE(biggest_region->start,
					biggest_region->end);
		tuple->ncslice = head->ncslice;
		tuple->offset = index_to_offset(head, tuple->index);
		region_delete(head, biggest_region);
		retval = CMMU_SUCCESS;
	}

#ifdef DEBUG
	/* Make sure we aren't leaking any pages */
	new_size = list_size(head);
	if (retval == 0) {
		ASSERT(old_size == new_size + tuple->count);
	} else {
		ASSERT(old_size == new_size);
	}
#endif /* DEBUG */

	mutex_exit(&head->mutex);

	return (retval);
}

/* Frees a region to a free list. Returns EINVAL if region wasn't allocated */
static int
list_free(free_list_t *head, wrsm_cmmu_index_t start,
		wrsm_cmmu_index_t end)
{
	free_region_t *p;
	int retval = CMMU_SUCCESS;
#ifdef DEBUG
	unsigned old_size, new_size; /* To check for free page leaks */
#endif /* DEBUG */

	DPRINTF(CMMUTRACE, (CE_NOTE, "list_free(start=%u, end=%u)",
	    start, end));
	ASSERT(head);

	mutex_enter(&head->mutex);
#ifdef DEBUG
	old_size = list_size(head);
#endif /* DEBUG */
	if (head->list == NULL) {
		region_create(head, NULL, start, end);
	} else for (p = head->list; p; p = p->next) {
		/* Make sure the region being freed isn't already free */
		ASSERT(!(p->start <= start && start <= p->end));
		ASSERT(!(p->start <= end && end <= p->end));
		if (p->end == start - 1) {
			/* Region is contiguous at end of this region */
			p->end = end;
			/* Check to see if we can merge with next region */
			if (p->next && (p->next)->start == end + 1) {
				p->end = (p->next)->end;
				region_delete(head, p->next);
			}
			break;
		} else if (p->start > end) {
			/* We over shot */
			if (p->start == end + 1) {
				/* See if it fits just before this region */
				p->start = start;
			} else {
				/* Need to insert new region in list */
				region_create(head, p->prev, start, end);
			}
			break;
		} else if (p->next == NULL) {
			/* We're at the end of the line */
			region_create(head, p, start, end);
			break;
		}
	}

#ifdef DEBUG
	/* Make sure we aren't leaking any pages */
	new_size = list_size(head);
	if (retval == 0) {
		ASSERT(old_size == new_size - RANGE_SIZE(start, end));
	} else {
		ASSERT(old_size == new_size);
	}
#endif /* DEBUG */

	mutex_exit(&head->mutex);
	return (retval);
}


static unsigned
cmmu_free(wrsm_network_t *net, unsigned ntuples,
			wrsm_cmmu_tuple_t *tuples)
{
	wrsm_cmmu_alloc_t *cmmu;
	unsigned i, n;

	DTRC("cmmu_free");
	ASSERT(net);
	cmmu = net->cmmu;
	ASSERT(cmmu);
	ASSERT(MUTEX_HELD(&cmmu->mutex));

	ASSERT(tuples);
	ASSERT(ntuples > 0);

	n = 0;
	for (i = 0; i < ntuples; i++) {
		wrsm_cmmu_index_t end;
		/*
		 * Don't trust ncslice provided by user. We may have
		 * allocated small pages from large page free list,
		 * so we'd want to free them back to the right list,
		 * so use index to find correct free list.
		 */
		free_list_t *head =
			IndexToFreeList(cmmu, tuples[i].index);
		ASSERT(head);

		end = tuples[i].index + tuples[i].count - 1;
		n += tuples[i].count;
		(void) list_free(head, tuples[i].index, end);
	}
	cv_broadcast(&cmmu->resource_cv);
	return (n);
}


/*
 * Allocates a region from a specific ncslice, specified by head.
 * Attempts a best-fit allocation. This function can be used iteratively on
 * each available ncslice when searching for an ncslice to allocate entries
 * from.
 */
static void
ncslice_alloc(free_list_t *head, wrsm_cmmu_tuple_t *tuples,
		unsigned *nentries, unsigned *ntuples, unsigned availtuples)
{
	ASSERT(head);
	DPRINTF(CMMUTRACE, (CE_NOTE, "ncslice_alloc(ncslice=%u, nentries=%u)",
	    head->ncslice, *nentries));

	/* Allocate from this ncslice until we're done or, or it's drained */
	while (*nentries > 0 &&
	    *ntuples < availtuples &&
	    list_best_alloc(head, *nentries, &tuples[*ntuples]) == 0) {
		*nentries -= tuples[*ntuples].count;
		(*ntuples)++;
	}
}

/* Adds a WCI to the linked list */
static void
wci_add(wrsm_cmmu_alloc_t *cmmu, lcwci_handle_t wci, boolean_t replicate)
{
	wci_handle_t *p;
	wci_handle_t *newp;
	DTRC("wci_add");
	ASSERT(cmmu);

	newp = kmem_zalloc(sizeof (wci_handle_t), KM_SLEEP);
	ASSERT(newp);

	mutex_enter(&cmmu->mutex);

	/* Make sure the WCI doesn't already exist */
	for (p = cmmu->wci_list; p; p = p->next) {
		if (p->wci_handle == wci) {
			WARN("wci_add: WCI already exists");
			mutex_exit(&cmmu->mutex);
			kmem_free(newp, sizeof (wci_handle_t));
			return;
		}
	}
	/* Check if we need to replicate, and if we have ANY other WCIs */
	if (replicate && cmmu->wci_list) {
		lcwci_handle_t master = cmmu->wci_list->wci_handle;
		unsigned index;
		unsigned i;
		free_region_t *p[MAX_FREE_LISTS];

		/* First, replicate the ncslice array */
		ncsliceconfig_copy(wci, master);

		/* Now, replicate the cluster members bits registers */
		clustermember_copy(wci, master);

		/*
		 * Next, the CMMU. Initialize an array of pointers for all
		 * free lists. We'll walk the free lists, and skip all free
		 * entries -- there's no need to copy free (i.e., unused)
		 * CMMU entries, and there should be a lot of them!
		 */
		for (i = 0; i < cmmu->num_free_lists; i++) {
			p[i] = cmmu->free_lists[i].list;
		}
		/* Walk the CMMU array from start to finish */
		for (index = 0; index < cmmu->max_entries; index++) {
			boolean_t in_use = B_TRUE;
			/* First, check if this index is on free list */
			for (i = 0; i < cmmu->num_free_lists; i++) {
				if (p[i] && (p[i]->start == index)) {
					/* On a free list, so not in use */
					in_use = B_FALSE;
					/* Skip over rest of pages in region */
					index = p[i]->end;
					/* Get next region for this list */
					p[i] = p[i]->next;
					break;
				}
			}
			if (in_use) {
				/* Not free, so make copy */
				wrsm_cmmu_t entry;
				wrsm_lc_cmmu_read(master, &entry, index);
				wrsm_lc_cmmu_update(wci, &entry, index,
						CMMU_UPDATE_ALL);
			}
		}
	}

	/* Add it to the list */
	newp->wci_handle = wci;
	newp->next = cmmu->wci_list;
	newp->prev = NULL;
	if (newp->next) {
		(newp->next)->prev = newp;
	}
	cmmu->wci_list = newp;

	mutex_exit(&cmmu->mutex);
}

/* Initializes free list structures once we have WCIs */
static void
init_free_lists(wrsm_cmmu_alloc_t *cmmu)
{
	unsigned i;
	wrsm_cmmu_index_t start;
	wrsm_cmmu_index_t end;
	DTRC("init_free_lists");

	ASSERT(cmmu);
	ASSERT(cmmu->num_free_lists > 0);
	ASSERT(cmmu->max_entries > 0);

	/* First, allocate all non-comm pages to the small page ncslice */
	start = NUM_COMM_PAGES;
	end = cmmu->max_entries - 1;
	(void) list_free(&cmmu->free_lists[0], start, end);

	/* Mark all comm pages as free (zero) */
	WRSMSET_ZERO(cmmu->comm_pages);
	/* Then allocate the CESR and write lockout pages */
	WRSMSET_ADD(cmmu->comm_pages, CESR_PAGE);
	WRSMSET_ADD(cmmu->comm_pages, WRITELOCKOUT_PAGE);

	/* For each large page ncslice, move pages from small ncslice */
	for (i = 1; i < cmmu->num_free_lists; i++) {
		ncslice_t ncslice = cmmu->free_lists[i].ncslice;
		wrsm_cmmu_index_t start = ncslice_to_start(ncslice);
		wrsm_cmmu_index_t end = ncslice_to_end(ncslice);
		unsigned count = end - start + 1;

		/* Allocate these pages away from small page free list */
		/* LINTED */
		if (list_absolute_alloc(&cmmu->free_lists[0], start, count)) {
			ASSERT(0);
		}

		/* Free these pages to the large page free list */
		(void) list_free(&cmmu->free_lists[i], start, end);
	}
#ifdef DEBUG
	for (i = 0; i < cmmu->num_free_lists; i++) {
		mutex_enter(&cmmu->free_lists[i].mutex);
		list_print(&cmmu->free_lists[i]);
		mutex_exit(&cmmu->free_lists[i].mutex);
	}
#endif /* DEBUG */
}

/* Calculates CMMU-based attributes */
static void
cmmu_attributes(wrsm_network_t *net)
{
	wrsm_cmmu_alloc_t *cmmu;
	uint64_t num_large_ncslices;
	uint64_t num_large_pages;
	uint64_t num_small_pages;

	DTRC("wrsm_cmmu_attributes");
	ASSERT(net);
	cmmu = net->cmmu;
	ASSERT(cmmu);

	if (cmmu->num_free_lists == 0 || cmmu->max_entries == 0) {
		net->attr.attr_max_export_segments = 0;
		net->attr.attr_tot_export_segment_size = 0;
		net->attr.attr_max_export_segment_size = 0;
	} else {
		num_large_ncslices = cmmu->num_free_lists - 1;
		num_large_pages = num_large_ncslices * MAX_PAGES_LARGE_SLICE;
		num_small_pages = cmmu->max_entries - num_large_pages;

		net->attr.attr_max_export_segments = cmmu->max_entries;
		net->attr.attr_tot_export_segment_size =
			num_large_pages * CMMU_LARGE_PAGE_SIZE +
			num_small_pages * CMMU_SMALL_PAGE_SIZE;
		net->attr.attr_max_export_segment_size =
			net->attr.attr_tot_export_segment_size;
	}
}

/*
 * API Functions. See wrsm_cmmu.h for function descriptions.
 */
void
wrsm_cmmu_init(wrsm_network_t *net, unsigned nwcis, wci_ids_t wcis[])
{
	unsigned i;
	wrsm_cmmu_alloc_t *cmmu;
	DTRC("wrsm_cmmu_init");

	ASSERT(net);
	ASSERT(net->cmmu == NULL);

	net->cmmu = kmem_zalloc(sizeof (wrsm_cmmu_alloc_t), KM_SLEEP);
	ASSERT(net->cmmu);
	cmmu = net->cmmu;

	mutex_init(&cmmu->mutex, NULL, MUTEX_DRIVER, NULL);
	cv_init(&cmmu->resource_cv, NULL, CV_DEFAULT, NULL);
	cmmu->max_entries = (nwcis > 0)?UINT_MAX:0;
	cmmu->wci_list = NULL;

	for (i = 0; i < nwcis; i++) {
		int n = 0;
		n = wrsm_lc_num_cmmu_entries_get(wcis[i].lcwci);
		/* Our max will be the smallest of all WCIs */
		if (n < cmmu->max_entries) {
			cmmu->max_entries = n;
		}
		/* Add this WCI to our linked list */
		wci_add(cmmu, wcis[i].lcwci, B_FALSE);
	}
	DPRINTF(CMMUDBG, (CE_NOTE, "cmmu_init: max_entries = %u",
			cmmu->max_entries));
	cmmu->num_free_entries = cmmu->max_entries;

	/*
	 * Build Empty Free Lists
	 */
	/* Make sure there is a small page ncslice */
	ASSERT(net->exported_ncslices.id[0] != 0);
	list_init(&cmmu->free_lists[0], net->exported_ncslices.id[0],
			CMMU_PAGE_SIZE_SMALL);
	cmmu->num_free_lists++;

	/* For each large page ncslice, move pages from small ncslice */
	for (i = 1; i < WRSM_NODE_NCSLICES; i++) {
		ncslice_t ncslice = net->exported_ncslices.id[i];
		if (ncslice == 0)
			continue;
		/* Create new list for this ncslice */
		list_init(&cmmu->free_lists[cmmu->num_free_lists], ncslice,
			CMMU_PAGE_SIZE_LARGE);
		cmmu->num_free_lists++;
	}
	/* If there are real WCIs, populate free lists */
	if (nwcis > 0) {
		init_free_lists(cmmu);
	}
	cmmu_attributes(net);
}

void
wrsm_cmmu_fini(wrsm_network_t *net)
{
	unsigned i;
	wrsm_cmmu_alloc_t *cmmu;

	DTRC("wrsm_cmmu_fini");
	ASSERT(net);
	cmmu = net->cmmu;
	ASSERT(cmmu);

	while (cmmu->wci_list) {
		(void) wrsm_cmmu_delwci(net, (cmmu->wci_list)->wci_handle);
	}
	mutex_enter(&cmmu->mutex);
	for (i = 0; i < cmmu->num_free_lists; i++) {
		list_fini(&cmmu->free_lists[i]);
	}
	cmmu->num_free_lists = 0;
	cv_destroy(&cmmu->resource_cv);
	mutex_exit(&cmmu->mutex);
	mutex_destroy(&cmmu->mutex);
	kmem_free(net->cmmu, sizeof (wrsm_cmmu_alloc_t));
	net->cmmu = NULL;
}

int
wrsm_cmmu_newwci(wrsm_network_t *net, lcwci_handle_t wci)
{
	wrsm_cmmu_alloc_t *cmmu;
	int retval = CMMU_SUCCESS;

	DTRC("wrsm_cmmu_newwci");
	ASSERT(net);
	cmmu = net->cmmu;
	ASSERT(cmmu);

	/* If this is the first WCI, initialize free lists */
	if (cmmu->wci_list == NULL) {
		cmmu->max_entries = wrsm_lc_num_cmmu_entries_get(wci);
		init_free_lists(cmmu);
	}

	/* Make sure the WCI has enough SRAM */
	if (wrsm_lc_num_cmmu_entries_get(wci) < cmmu->max_entries) {
		return (ENOMEM);
	}
	wci_add(cmmu, wci, B_TRUE);

	/* Update attributes */
	cmmu_attributes(net);

	return (retval);
}

int
wrsm_cmmu_delwci(wrsm_network_t *net, lcwci_handle_t wci)
{
	wrsm_cmmu_alloc_t *cmmu;
	wci_handle_t *p;
	unsigned i;
	int retval = EINVAL;

	DTRC("wrsm_cmmu_delwci");
	ASSERT(net);
	cmmu = net->cmmu;
	ASSERT(cmmu);

	mutex_enter(&cmmu->mutex);
	for (p = cmmu->wci_list; p; p = p->next) {
		if (p->wci_handle == wci) {
			if (p->prev) {
				(p->prev)->next = p->next;
			} else {
				cmmu->wci_list = p->next;
			}
			if (p->next) {
				(p->next)->prev = p->prev;
			}
			kmem_free(p, sizeof (wci_handle_t));
			retval = CMMU_SUCCESS;
			break;
		}
	}
	/* If this was the last WCI, delete all free lists */
	if (cmmu->wci_list == NULL) {
		for (i = 0; i < cmmu->num_free_lists; i++) {
			mutex_enter(&cmmu->free_lists[i].mutex);
			list_delete(&cmmu->free_lists[i]);
			mutex_exit(&cmmu->free_lists[i].mutex);
		}
		cmmu->max_entries = 0;
	}
	/* Update attributes */
	cmmu_attributes(net);

	mutex_exit(&cmmu->mutex);

	return (retval);
}

int
wrsm_cmmu_alloc(wrsm_network_t *net, wrsm_cmmu_page_size_t page_size,
	unsigned nentries, wrsm_cmmu_tuple_t **tuples, unsigned *ntuples,
	boolean_t sleep)
{
	int retval = CMMU_SUCCESS;
	unsigned i, n;
	int availtuples = nentries + 1; /* Make availtuples large */
	size_t tmp_size = availtuples * sizeof (wrsm_cmmu_tuple_t);
	wrsm_cmmu_tuple_t *tmp_tuples = kmem_zalloc(tmp_size,
	    KM_SLEEP);
	wrsm_cmmu_alloc_t *cmmu;

	DPRINTF(CMMUTRACE, (CE_NOTE, "wrsm_cmmu_alloc(size=%s, nentries=%u)",
	    (page_size == CMMU_PAGE_SIZE_SMALL)?"SMALL":"LARGE", nentries));
	ASSERT(net);
	cmmu = net->cmmu;
	ASSERT(cmmu);

	mutex_enter(&cmmu->mutex);
	/*
	 * For each free list (ncslice) of the right size, try a
	 * best-fit alloc from that ncslice's free list, until we
	 * either run out of free lists, succeed in allocating
	 * enough entries, or run out of tuples to store results.
	 */
retry:
	n = nentries;
	*ntuples = 0;
	*tuples = NULL;
	for (i = 0; i < cmmu->num_free_lists &&
	    n > 0 &&
	    *ntuples < availtuples; i++) {
		/* If wrong page size, bail */
		if (cmmu->free_lists[i].page_size != page_size) {
			continue;
		}
		ncslice_alloc(&cmmu->free_lists[i], tmp_tuples,
		    &n, ntuples, availtuples);
	}
	/*
	 * If we didn't allocate all the entries requested, and
	 * there's still free tuples, and we were allocating small
	 * pages, let's steal from the large page ncslices.
	 */
	if (n > 0 && *ntuples < availtuples &&
	    page_size == CMMU_PAGE_SIZE_SMALL) {
		for (i = 1; i < cmmu->num_free_lists; i++) {
			free_list_t *head = &cmmu->free_lists[i];
			ASSERT(head->page_size == CMMU_PAGE_SIZE_LARGE);
			ncslice_alloc(head, tmp_tuples, &n,
			    ntuples, availtuples);
		}
	}
	if (n > 0) {
		/*
		 * we failed, so free up any cmmu entries we
		 * allocated
		 */
		if (*ntuples > 0)
			(void) cmmu_free(net, *ntuples, tmp_tuples);

		if (*ntuples == availtuples) {
			retval = ENOSPC;
		} else {
			if (sleep) {
				retval = cv_wait_sig(
					&cmmu->resource_cv,
					    &cmmu->mutex);
				if (retval > 0) {
					retval = CMMU_SUCCESS;
					goto retry;
				} else {
					/* got a signal */
					retval = EINTR;
				}
			} else {
				retval = EAGAIN;
			}
		}
		mutex_exit(&cmmu->mutex);
		*ntuples = 0;
	} else {
		/* copy the data to the output array */

		size_t size = *ntuples * sizeof (wrsm_cmmu_tuple_t);

		cmmu->num_free_entries -= nentries;
		mutex_exit(&cmmu->mutex);
		*tuples =  kmem_zalloc(size, KM_SLEEP);
		bcopy(tmp_tuples, *tuples, size);

	}
	kmem_free(tmp_tuples, tmp_size);

#ifdef DEBUG
	if (retval == CMMU_SUCCESS) {
		int i;
		for (i = 0; i < *ntuples; i++) {
			DPRINTF(CMMUTRACE, (CE_NOTE, "alloced tuple %d "
			    "ncslice %d count %d offset 0x%p index %d\n",
			    i,
			    (*tuples)[i].ncslice,
			    (*tuples)[i].count,
			    (void *)(*tuples)[i].offset,
			    (*tuples)[i].index));
		}
	}
#endif
	return (retval);
}

void
wrsm_cmmu_free(wrsm_network_t *net, unsigned ntuples,
			wrsm_cmmu_tuple_t *tuples)
{
	wrsm_cmmu_alloc_t *cmmu = net->cmmu;
	unsigned nentries;
	DTRC("wrsm_cmmu_free");

	if (tuples == NULL)
		return;
#ifdef DEBUG
	{
		int i;
		for (i = 0; i < ntuples; i++) {
			DPRINTF(CMMUTRACE, (CE_NOTE, "freeing tuple %d "
			    "ncslice %d count %d offset 0x%p index %d\n",
			    i,
			    tuples[i].ncslice,
			    tuples[i].count,
			    (void *)tuples[i].offset,
			    tuples[i].index));
		}
	}
#endif

	mutex_enter(&cmmu->mutex);
	nentries = cmmu_free(net, ntuples, tuples);
	cmmu->num_free_entries += nentries;
	kmem_free(tuples, ntuples * sizeof (wrsm_cmmu_tuple_t));
	mutex_exit(&cmmu->mutex);
}

int
wrsm_cmmu_comm_alloc(wrsm_network_t *net, ncslice_t ncslice,
			wrsm_cmmu_offset_t offset, wrsm_cmmu_tuple_t *tuple)
{
	int retval = CMMU_SUCCESS;
	wrsm_cmmu_alloc_t *cmmu;
	wrsm_cmmu_index_t index;

	DPRINTF(CMMUTRACE, (CE_WARN,
	    "wrsm_cmmu_comm_alloc(ncslice=0x%x, offset=0x%p)",
	    ncslice, (void *)offset));
	ASSERT(net);
	cmmu = net->cmmu;
	ASSERT(cmmu);

	/* Make sure user requested small page ncslice */
	if (ncslice != cmmu->free_lists[0].ncslice) {
		WARN("wrsm_cmmu_comm_alloc: Must use small pages");
		return (EINVAL);
	}
	index = offset_to_index(&cmmu->free_lists[0], offset);
	ASSERT(index_to_offset(&cmmu->free_lists[0], index) == offset);
	if (index >= NUM_COMM_PAGES) {
		WARN("wrsm_cmmu_comm_alloc: index out of range");
		return (EINVAL);
	}

	/* If page isn't already allocated, allocate it */
	mutex_enter(&cmmu->mutex);
	if (WRSM_IN_SET(cmmu->comm_pages, index)) {
		retval = ENOMEM;
	} else {
		WRSMSET_ADD(cmmu->comm_pages, index);
		tuple->ncslice = ncslice;
		tuple->offset = offset;
		tuple->index = index;
		tuple->count = 1;
		cmmu->num_free_entries--;
		retval = CMMU_SUCCESS;
	}
	mutex_exit(&cmmu->mutex);

	return (retval);
}

void
wrsm_cmmu_comm_free(wrsm_network_t *net, wrsm_cmmu_tuple_t *tuple)
{
	wrsm_cmmu_alloc_t *cmmu;

	DPRINTF(CMMUTRACE, (CE_NOTE, "wrsm_cmmu_comm_free(index=%u)",
	    tuple->index));
	ASSERT(net);
	cmmu = net->cmmu;
	ASSERT(cmmu);
	ASSERT(tuple->index >= FIRST_CMMU_ENTRY);
	ASSERT(tuple->index < NUM_COMM_PAGES);
	ASSERT(tuple->ncslice == cmmu->free_lists[0].ncslice);

	mutex_enter(&cmmu->mutex);
	ASSERT(WRSM_IN_SET(cmmu->comm_pages, tuple->index));
	WRSMSET_DEL(cmmu->comm_pages, tuple->index);
	cmmu->num_free_entries++;
	mutex_exit(&cmmu->mutex);
}

void
wrsm_cmmu_update(wrsm_network_t *net, wrsm_cmmu_t *entry,
	wrsm_cmmu_index_t index, wrsm_cmmu_flags_t flags)
{
	wci_handle_t *p;
	wrsm_cmmu_alloc_t *cmmu;

	DPRINTF(CMMUTRACE, (CE_NOTE, "wrsm_cmmu_update index %d", index));
	ASSERT(net);
	cmmu = net->cmmu;
	ASSERT(cmmu);

	mutex_enter(&cmmu->mutex);
	for (p = cmmu->wci_list; p; p = p->next) {
		wrsm_lc_cmmu_update(p->wci_handle, entry,
		    index, flags);
	}
	mutex_exit(&cmmu->mutex);
}

void
wrsm_cmmu_read(wrsm_network_t *net, wrsm_cmmu_t *entry,
		wrsm_cmmu_index_t index)
{
	wrsm_cmmu_alloc_t *cmmu;

	DTRC("wrsm_cmmu_read");
	ASSERT(net);
	cmmu = net->cmmu;
	ASSERT(cmmu);

	mutex_enter(&cmmu->mutex);
	ASSERT(cmmu->wci_list);
	/* If there are WCIs, just use the first WCI on our list */
	wrsm_lc_cmmu_read(cmmu->wci_list->wci_handle, entry, index);
	mutex_exit(&cmmu->mutex);
}

/*
 * Cluster members bits functions
 */
void
wrsm_clustermember_add(wrsm_network_t *net, cnodeid_t cnode)
{
	/*
	 * The wci_cluster_members_bits is an array of 4 64-bit registers,
	 * spaced out by some stride. Need to calculate which of the 4
	 * entries to modify, which position within the entry to modify,
	 * and the offset of the entry for the request to LC.
	 */
	const uint64_t entry = cnode / MEMBERS_PER_REGISTER;
	const uint64_t position = cnode % MEMBERS_PER_REGISTER;
	const uint64_t offset = ADDR_WCI_CLUSTER_MEMBERS_BITS +
		(entry * STRIDE_WCI_CLUSTER_MEMBERS_BITS);
	uint64_t members;
	wci_handle_t *wci;
	wrsm_cmmu_alloc_t *cmmu;

	DPRINTF(CMMUTRACE, (CE_NOTE, "wrsm_clustermember_add(%u)", cnode));
	ASSERT(net);
	cmmu = net->cmmu;
	ASSERT(cmmu);

	mutex_enter(&cmmu->mutex);
	/* If there are no WCIs, just return */
	if (cmmu->wci_list == NULL) {
		mutex_exit(&cmmu->mutex);
		return;
	}
	wrsm_lc_csr_read(cmmu->wci_list->wci_handle, offset, &members);
	members |= ONE_BIT << position;

	for (wci = cmmu->wci_list; wci; wci = wci->next) {
		wrsm_lc_csr_write(wci->wci_handle, offset, members);
	}
	mutex_exit(&cmmu->mutex);
}

void
wrsm_clustermember_delete(wrsm_network_t *net, cnodeid_t cnode)
{
	/*
	 * The wci_cluster_members_bits is an array of 4 64-bit registers,
	 * spaced out by some stride. Need to calculate which of the 4
	 * entries to modify, which position within the entry to modify,
	 * and the offset of the entry for the request to LC.
	 */
	const uint64_t entry = cnode / MEMBERS_PER_REGISTER;
	const uint64_t position = cnode % MEMBERS_PER_REGISTER;
	const uint64_t offset = ADDR_WCI_CLUSTER_MEMBERS_BITS +
		(entry * STRIDE_WCI_CLUSTER_MEMBERS_BITS);
	uint64_t members;
	wci_handle_t *wci;
	wrsm_cmmu_alloc_t *cmmu;

	DPRINTF(CMMUTRACE, (CE_NOTE, "wrsm_clustermember_delete(%u)", cnode));
	ASSERT(net);
	cmmu = net->cmmu;
	ASSERT(cmmu);

	mutex_enter(&cmmu->mutex);
	/* If there are no WCIs, just return */
	if (cmmu->wci_list == NULL) {
		mutex_exit(&cmmu->mutex);
		return;
	}
	wrsm_lc_csr_read(cmmu->wci_list->wci_handle, offset, &members);
	members &= ~(ONE_BIT << position);
	for (wci = cmmu->wci_list; wci; wci = wci->next) {
		wrsm_lc_csr_write(wci->wci_handle, offset, members);
	}
	mutex_exit(&cmmu->mutex);
}

void
wrsm_clustermember_list(wrsm_network_t *net,  cnode_bitmask_t *cnodes)
{
	uint_t i;
	uint_t j;
	wrsm_cmmu_alloc_t *cmmu = net->cmmu;

	DTRC("wrsm_clustermember_list");
	ASSERT(net);
	cmmu = net->cmmu;
	ASSERT(cmmu);

	WRSMSET_ZERO(*cnodes);
	mutex_enter(&cmmu->mutex);
	/* If there are no WCIs, just return */
	if (cmmu->wci_list == NULL) {
		mutex_exit(&cmmu->mutex);
		return;
	}

	/* Loop for each of the array entries... */
	for (i = 0; i < ENTRIES_WCI_CLUSTER_MEMBERS_BITS; i++) {
		uint64_t members;
		uint64_t mask = ONE_BIT;
		uint64_t offset = ADDR_WCI_CLUSTER_MEMBERS_BITS +
			(i * STRIDE_WCI_CLUSTER_MEMBERS_BITS);

		wrsm_lc_csr_read(cmmu->wci_list->wci_handle,
		    offset, &members);

		/* Loop for each bit in the array... */
		for (j = 0; j < MEMBERS_PER_REGISTER; j++) {
			if (members & mask) {
				WRSMSET_ADD(*cnodes,
				    j + i * MEMBERS_PER_REGISTER);
			}
			mask = mask << 1;
		}
	}
	mutex_exit(&cmmu->mutex);
}

/*
 * ncslice config array functions
 */
void
wrsm_ncsliceconfig_set(wrsm_network_t *net, ncslice_t ncslice,
			wrsm_ncslice_mode_t mode)
{
	/*
	 * The wci_nc_slice_config_array is an 8 entry array with 64-bits
	 * per entry. Each entry has 2-bits per ncslice. Need to determine
	 * which entry to modify, the starting position within the entry
	 * for this ncslice, and the register offset. Also need to create
	 * masks to isolate the two bits being set by mode.
	 */
	const uint64_t entry = ncslice / SLICES_PER_REGISTER;
	const uint64_t position = (ncslice % SLICES_PER_REGISTER) *
		BITS_PER_SLICE;
	const uint64_t offset = ADDR_WCI_NC_SLICE_CONFIG_ARRAY +
		(entry * STRIDE_WCI_NC_SLICE_CONFIG_ARRAY);
	/* Mask has two zeros where bits go, all other bits are 1 */
	const uint64_t mask = ~(TWO_BITS << position);
	/* Make sure only 2 bits are set! Also, cast to 64-bits */
	const uint64_t mode64 = mode & TWO_BITS;
	uint64_t config;
	wci_handle_t *wci;
	wrsm_cmmu_alloc_t *cmmu;

	DPRINTF(CMMUTRACE, (CE_NOTE,
	    "wrsm_ncsliceconfig_set(ncslice=%u, mode=%u)", ncslice, mode));
	ASSERT(net);
	cmmu = net->cmmu;
	ASSERT(cmmu);

	mutex_enter(&cmmu->mutex);
	/* If there are no WCIs, just return */
	if (cmmu->wci_list == NULL) {
		WARN("NO WCIS!!!!!");
		mutex_exit(&cmmu->mutex);
		return;
	}
	wrsm_lc_csr_read(cmmu->wci_list->wci_handle,
	    offset, &config);
	config = (config & mask) | (mode64 << position);
	for (wci = cmmu->wci_list; wci; wci = wci->next) {
		wrsm_lc_csr_write(wci->wci_handle, offset, config);
	}
	mutex_exit(&cmmu->mutex);
}

wrsm_ncslice_mode_t
wrsm_ncsliceconfig_get(wrsm_network_t *net, ncslice_t ncslice)
{
	/*
	 * The wci_nc_slice_config_array is an 8 entry array with 64-bits
	 * per entry. Each entry has 2-bits per ncslice. Need to determine
	 * which entry to modify, the starting position within the entry
	 * for this ncslice, and the register offset.
	 */
	const uint64_t entry = ncslice / SLICES_PER_REGISTER;
	const uint64_t position = (ncslice % SLICES_PER_REGISTER) *
		BITS_PER_SLICE;
	const uint64_t offset = ADDR_WCI_NC_SLICE_CONFIG_ARRAY +
		(entry * STRIDE_WCI_NC_SLICE_CONFIG_ARRAY);
	wrsm_ncslice_mode_t mode = ncslice_invalid;
	uint64_t config;
	wrsm_cmmu_alloc_t *cmmu;

	DTRC("wrsm_ncsliceconfig_get");
	ASSERT(net);
	cmmu = net->cmmu;
	ASSERT(cmmu);

	mutex_enter(&cmmu->mutex);
	/* If there are no WCIs, just return */
	if (cmmu->wci_list == NULL) {
		mutex_exit(&cmmu->mutex);
		return (ncslice_invalid);
	}
	wrsm_lc_csr_read(cmmu->wci_list->wci_handle, offset, &config);
	mode = (config >> position) & TWO_BITS;
	mutex_exit(&cmmu->mutex);
	return (mode);
}

wrsm_cmmu_index_t
wrsm_cmmu_num_free(wrsm_network_t *net)
{
	ASSERT(net);
	return (net->cmmu->num_free_entries);
}
