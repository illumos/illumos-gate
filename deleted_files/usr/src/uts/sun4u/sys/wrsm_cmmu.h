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
 * Copyright (c) 2001 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _WRSM_CMMU_H
#define	_WRSM_CMMU_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/wrsm_config.h>
#include <sys/wrsm_lc.h>
#include <sys/wrsm_nc.h>

#ifdef	__cplusplus
extern "C" {
#endif

typedef uint32_t wrsm_cmmu_index_t;
typedef caddr_t wrsm_cmmu_offset_t;

typedef wrsm_ncslice_mode_t wrsm_cmmu_page_size_t;
#define	CMMU_PAGE_SIZE_SMALL ncslice_small_page
#define	CMMU_PAGE_SIZE_LARGE ncslice_large_page

#define	CMMU_SMALL_PAGE_SIZE	0x00002000	/* 8K Bytes */
#define	CMMU_SMALL_PAGE_MASK	0x00001fff
#define	CMMU_SMALL_PAGE_SHIFT	13
#define	CMMU_LARGE_PAGE_SIZE	0x00400000	/* 4M Bytes */
#define	CMMU_LARGE_PAGE_MASK	0x003fffff
#define	CMMU_LARGE_PAGE_SHIFT	22

#define	CMMU_NCSLICE_SHIFT	34
#define	CMMU_NCSLICE_OFFSET_MASK ((uint64_t)0x3ffffffff)
#define	CMMU_PADDR2NCSLICE(pa)	(((pa) >> CMMU_NCSLICE_SHIFT) & 0xff)
#define	CMMU_PADDR2OFFSET(pa)	((pa) & CMMU_NCSLICE_OFFSET_MASK)

/*
 * Structure defining the <ncslice, index, count> tuple.
 */
struct wrsm_cmmu_tuple {
	ncslice_t ncslice;
	wrsm_cmmu_offset_t offset;
	wrsm_cmmu_index_t index;
	unsigned  count;
};

/*
 * Initializes the CMMU allocator, including providing an initialial list
 * of WCIs. This initial list is used to determine the max CMMU entries
 * for this instance of the CMMU allocator.
 */
void wrsm_cmmu_init(wrsm_network_t *, unsigned nwcis, struct wci_ids wcis[]);

/*
 * Destroys the CMMU allocator and frees any data structures.
 */
void wrsm_cmmu_fini(wrsm_network_t *);

/*
 * Informs the CMMU allocator of a new WCI. Returns non-zero if the
 * new WCI doesn't support a large enough CMMU.
 */
int wrsm_cmmu_newwci(wrsm_network_t *, lcwci_handle_t);

/*
 * Informs the CMMU allocator that a WCI is no longer part of this
 * RSM controller.
 */
int wrsm_cmmu_delwci(wrsm_network_t *, lcwci_handle_t);

/*
 * Allocates a range of entries, and allocates and returns a buffer containing
 * the tuples describing the CMMU entries and the ncslice they map to. The
 * caller frees the CMMU entries AND the buffer by calling wrsm_cmmu_free.
 * Arguments:
 *   net - Pointer to this network.
 *   page_size - Desired page size, small or large.
 *   nentries - The number of CMMU entries being requested.
 *   tuples - An array of tuples allocated by the function. The memory will
 *       be freed in wrsm_cmmu_free.
 *   ntuples - The number of tuples actually written by this function.
 * Returns: ENOMEM if there aren't enough free CMMU entries for the request.
 */
int wrsm_cmmu_alloc(wrsm_network_t *net, wrsm_cmmu_page_size_t page_size,
    unsigned nentries, wrsm_cmmu_tuple_t **tuples, unsigned *ntuples,
    boolean_t sleep);

/*
 * Frees a range of entries allocated with wrsm_cmmu_alloc(). The tuples
 * pointer must be the unaltered buffer allocated in wrsm_cmmu_alloc. This
 * function will free the CMMU entries and free the tuples buffer.
 */
void wrsm_cmmu_free(wrsm_network_t *, unsigned ntuples,
    wrsm_cmmu_tuple_t *tuples);

/*
 * Allocates a CMMU entry for driver communication at a specific
 * ncslice/offset. Unlike wrsm_cmmu_alloc, this function does not
 * allocate any memory -- the caller must provide a single tuple
 * buffer where the result is placed. CMMU entries allocated
 * with this function must be freed by wrsm_cmmu_comm_free.
 * Arguments:
 *   net - Pointer to this network.
 *   ncslice - Desired ncslice.
 *   offset - Desired offset.
 *   tuple - Returned value indicating ncslice/offset/index/count. The ncslice
 *	and offset will match the values passed in, and the count will be 1.
 */
int wrsm_cmmu_comm_alloc(wrsm_network_t *net, ncslice_t ncslice,
    wrsm_cmmu_offset_t offset, wrsm_cmmu_tuple_t *tuple);


/*
 * Frees a single cmmu entry allocated by wrsm_cmmu_comm_alloc(). Since
 * wrsm_cmmu_comm_alloc does not allocate memory, this function does not
 * free the memory pointed to by tuple.
 */
void wrsm_cmmu_comm_free(wrsm_network_t *net, wrsm_cmmu_tuple_t *tuple);

/*
 * Writes an entry, only updating the fields specified by the flags
 * parameter. Does not check to make sure the CMMU entry has been allocated.
 */
void wrsm_cmmu_update(wrsm_network_t *, wrsm_cmmu_t *entry,
	wrsm_cmmu_index_t index, wrsm_cmmu_flags_t);

/*
 * Reads a CMMU entry, uses an arbitrary WCI.
 */
void wrsm_cmmu_read(wrsm_network_t *, wrsm_cmmu_t *entry, wrsm_cmmu_index_t);

/*
 * Other RSM controller-wide register functions. These don't specifically
 * modify the CMMU, but act across all WCIs, like the CMMU manipulation
 * functions do.
 */

/*
 * Sets the bit for a particular cnode in the cluster member bits of
 * all WCIs associated with this RSM network.
 */
void wrsm_clustermember_add(wrsm_network_t *, cnodeid_t cnode);

/*
 * Clears the bit for a particular cnode in the clsuter member bits of
 * all WCIs associated with this RSM network.
 */
void wrsm_clustermember_delete(wrsm_network_t *, cnodeid_t cnode);

/*
 * Returns a list of all cnode bits set in the cluster member bits register.
 * Uses a specific WCI's cluster_member_bits register, but all WCIs should
 * have the same setting.
 */
void wrsm_clustermember_list(wrsm_network_t *,  cnode_bitmask_t *);

/*
 * Sets the mode of a particular ncslice in the wci_nc_slice_config_array.
 */
void wrsm_ncsliceconfig_set(wrsm_network_t *, ncslice_t ncslice,
			wrsm_ncslice_mode_t mode);
/*
 * Returns the mode of the given ncslice.
 */
wrsm_ncslice_mode_t wrsm_ncsliceconfig_get(wrsm_network_t *, ncslice_t);

/*
 * Returns the number of free cmmu entires
 */
wrsm_cmmu_index_t wrsm_cmmu_num_free(wrsm_network_t *);

#ifdef	__cplusplus
}
#endif

#endif /* _WRSM_CMMU_H */
