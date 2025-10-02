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
 * Copyright 1999-2002 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * s1394_addr.c
 *    1394 Address Space Routines
 *    Implements all the routines necessary for alloc/free and lookup
 *    of the 1394 address space
 */

#include <sys/conf.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/1394/t1394.h>
#include <sys/1394/s1394.h>
#include <sys/1394/h1394.h>
#include <sys/1394/ieee1394.h>

static s1394_addr_space_blk_t *s1394_free_list_search(s1394_hal_t *hal,
    uint64_t addr);

static s1394_addr_space_blk_t *s1394_free_list_find(s1394_hal_t *hal,
    uint32_t type, uint32_t length);

static s1394_addr_space_blk_t *s1394_free_list_delete(s1394_hal_t *hal,
    s1394_addr_space_blk_t *del_blk);

static void s1394_used_tree_insert(s1394_hal_t *hal, s1394_addr_space_blk_t *x);

static void s1394_tree_insert(s1394_addr_space_blk_t **root,
    s1394_addr_space_blk_t *z);

static s1394_addr_space_blk_t *s1394_tree_search(s1394_addr_space_blk_t *x,
    uint64_t address);

static void s1394_used_tree_delete_fixup(s1394_addr_space_blk_t **root,
    s1394_addr_space_blk_t *p, s1394_addr_space_blk_t *x,
    s1394_addr_space_blk_t *w, int side_of_x);

static void s1394_left_rotate(s1394_addr_space_blk_t **root,
    s1394_addr_space_blk_t *x);

static void s1394_right_rotate(s1394_addr_space_blk_t **root,
    s1394_addr_space_blk_t *x);

static s1394_addr_space_blk_t *s1394_tree_minimum(s1394_addr_space_blk_t *x);

static s1394_addr_space_blk_t *s1394_tree_successor(s1394_addr_space_blk_t *x);

/*
 * s1394_request_addr_blk()
 *    is called when a target driver is requesting a block of 1394 Address
 *    Space of a particular type without regard for its exact location.  It
 *    searches the free list for a block that's big enough and of the specified
 *    type, and it inserts it into the used tree.
 */
int
s1394_request_addr_blk(s1394_hal_t *hal, t1394_alloc_addr_t *addr_allocp)
{
	s1394_addr_space_blk_t	*curr_blk;
	s1394_addr_space_blk_t	*new_blk;
	uint64_t		amount_free;

	ASSERT(hal != NULL);

	/* Lock the address space "free" list */
	mutex_enter(&hal->addr_space_free_mutex);

	curr_blk = s1394_free_list_find(hal, addr_allocp->aa_type,
	    addr_allocp->aa_length);
	if (curr_blk == NULL) {
		/* Unlock the address space "free" list */
		mutex_exit(&hal->addr_space_free_mutex);

		return (DDI_FAILURE);
	}

	amount_free = (curr_blk->addr_hi - curr_blk->addr_lo) + 1;
	/* Does it fit exact? */
	if (amount_free == addr_allocp->aa_length) {
		/* Take it out of the "free" list */
		curr_blk = s1394_free_list_delete(hal, curr_blk);

		/* Unlock the address space "free" list */
		mutex_exit(&hal->addr_space_free_mutex);

		curr_blk->addr_enable = addr_allocp->aa_enable;
		curr_blk->kmem_bufp = addr_allocp->aa_kmem_bufp;
		curr_blk->addr_arg = addr_allocp->aa_arg;
		curr_blk->addr_events = addr_allocp->aa_evts;

		addr_allocp->aa_address = curr_blk->addr_lo;
		addr_allocp->aa_hdl = (t1394_addr_handle_t)curr_blk;

		/* Put it into the "used" tree */
		s1394_used_tree_insert(hal, curr_blk);

		s1394_addr_alloc_kstat(hal, addr_allocp->aa_address);

		return (DDI_SUCCESS);

	} else {
		/* Needs to be broken up */
		new_blk = (s1394_addr_space_blk_t *)
		    kmem_zalloc(sizeof (s1394_addr_space_blk_t), KM_NOSLEEP);
		if (new_blk == NULL) {
			/* Unlock the address space "free" list */
			mutex_exit(&hal->addr_space_free_mutex);
			return (DDI_FAILURE);
		}

		new_blk->addr_lo = curr_blk->addr_lo;
		new_blk->addr_hi = curr_blk->addr_lo +
		    (addr_allocp->aa_length - 1);
		new_blk->addr_type = curr_blk->addr_type;
		new_blk->addr_enable = addr_allocp->aa_enable;
		new_blk->kmem_bufp = addr_allocp->aa_kmem_bufp;
		new_blk->addr_arg = addr_allocp->aa_arg;
		new_blk->addr_events = addr_allocp->aa_evts;

		curr_blk->addr_lo = new_blk->addr_hi + 1;

		addr_allocp->aa_address = new_blk->addr_lo;
		addr_allocp->aa_hdl = (t1394_addr_handle_t)new_blk;

		/* Unlock the address space "free" list */
		mutex_exit(&hal->addr_space_free_mutex);

		/* Put it into the "used" tree */
		s1394_used_tree_insert(hal, new_blk);

		s1394_addr_alloc_kstat(hal, addr_allocp->aa_address);

		return (DDI_SUCCESS);
	}
}

/*
 * s1394_claim_addr_blk()
 *    is called when a target driver is requesting a block of 1394 Address
 *    Space with a specific address.  If the block containing that address
 *    is not in the free list, or if the block is too small, then
 *    s1394_claim_addr_blk() returns failure.  If the block is found,
 *    however, it is inserted into the used tree.
 */
int
s1394_claim_addr_blk(s1394_hal_t *hal, t1394_alloc_addr_t *addr_allocp)
{
	s1394_addr_space_blk_t	*curr_blk;
	s1394_addr_space_blk_t	*new_blk;
	s1394_addr_space_blk_t	*middle_blk;
	uint64_t		upper_bound;

	ASSERT(hal != NULL);

	/* Lock the address space "free" list */
	mutex_enter(&hal->addr_space_free_mutex);

	/* Find the block in the "free" list */
	curr_blk = s1394_free_list_search(hal, addr_allocp->aa_address);

	/* If it wasn't found, it isn't free... */
	if (curr_blk == NULL) {
		/* Unlock the address space free list */
		mutex_exit(&hal->addr_space_free_mutex);

		return (DDI_FAILURE);
	}

	/* Does the request fit in the block? */
	upper_bound = (addr_allocp->aa_address + addr_allocp->aa_length) - 1;
	if ((upper_bound >= curr_blk->addr_lo) &&
	    (upper_bound <= curr_blk->addr_hi)) {

		/* How does the requested range fit in the current range? */
		if (addr_allocp->aa_address == curr_blk->addr_lo) {
			if (upper_bound == curr_blk->addr_hi) {
				/* Exact fit */

				/* Take it out of the "free" list */
				curr_blk = s1394_free_list_delete(hal,
				    curr_blk);

				/* Unlock the address space "free" list */
				mutex_exit(&hal->addr_space_free_mutex);

				curr_blk->addr_enable = addr_allocp->aa_enable;
				curr_blk->kmem_bufp = addr_allocp->aa_kmem_bufp;
				curr_blk->addr_arg = addr_allocp->aa_arg;
				curr_blk->addr_events = addr_allocp->aa_evts;

				addr_allocp->aa_hdl =
				    (t1394_addr_handle_t)curr_blk;

				/* Put it into the "used" tree */
				s1394_used_tree_insert(hal, curr_blk);

				s1394_addr_alloc_kstat(hal,
				    addr_allocp->aa_address);

				return (DDI_SUCCESS);

			} else {
				/* If space is reserved, must claim it all */
				if (curr_blk->addr_reserved == ADDR_RESERVED) {
					goto claim_error;
				}

				/* Front part of range */
				new_blk = (s1394_addr_space_blk_t *)
				    kmem_zalloc(sizeof (s1394_addr_space_blk_t),
				    KM_NOSLEEP);
				if (new_blk == NULL) {
					/* Unlock the addr space "free" list */
					mutex_exit(&hal->addr_space_free_mutex);
					return (DDI_FAILURE);
				}

				new_blk->addr_lo = curr_blk->addr_lo;
				new_blk->addr_hi = upper_bound;
				new_blk->addr_type = curr_blk->addr_type;
				new_blk->addr_enable = addr_allocp->aa_enable;
				new_blk->kmem_bufp = addr_allocp->aa_kmem_bufp;
				new_blk->addr_arg = addr_allocp->aa_arg;
				new_blk->addr_events = addr_allocp->aa_evts;

				curr_blk->addr_lo = new_blk->addr_hi + 1;

				addr_allocp->aa_hdl =
				    (t1394_addr_handle_t)new_blk;

				/* Unlock the address space free list */
				mutex_exit(&hal->addr_space_free_mutex);

				/* Put it into the "used" tree */
				s1394_used_tree_insert(hal, new_blk);

				s1394_addr_alloc_kstat(hal,
				    addr_allocp->aa_address);

				return (DDI_SUCCESS);
			}

		} else {
			if (upper_bound == curr_blk->addr_hi) {
				/* If space is reserved, must claim it all */
				if (curr_blk->addr_reserved == ADDR_RESERVED) {
					goto claim_error;
				}

				/* End part of range */
				new_blk = (s1394_addr_space_blk_t *)
				    kmem_zalloc(sizeof (s1394_addr_space_blk_t),
				    KM_NOSLEEP);
				if (new_blk == NULL) {
					/* Unlock the addr space "free" list */
					mutex_exit(&hal->addr_space_free_mutex);
					return (DDI_FAILURE);
				}

				new_blk->addr_lo = addr_allocp->aa_address;
				new_blk->addr_hi = upper_bound;
				new_blk->addr_type = curr_blk->addr_type;
				new_blk->addr_enable = addr_allocp->aa_enable;
				new_blk->kmem_bufp = addr_allocp->aa_kmem_bufp;
				new_blk->addr_arg = addr_allocp->aa_arg;
				new_blk->addr_events = addr_allocp->aa_evts;

				curr_blk->addr_hi = addr_allocp->aa_address - 1;

				addr_allocp->aa_hdl =
				    (t1394_addr_handle_t)new_blk;

				/* Unlock the address space free list */
				mutex_exit(&hal->addr_space_free_mutex);

				/* Put it into the "used" tree */
				s1394_used_tree_insert(hal, new_blk);

				s1394_addr_alloc_kstat(hal,
				    addr_allocp->aa_address);

				return (DDI_SUCCESS);

			} else {
				/* If space is reserved, must claim it all */
				if (curr_blk->addr_reserved == ADDR_RESERVED) {
					goto claim_error;
				}

				/* Middle part of range */
				new_blk = (s1394_addr_space_blk_t *)
				    kmem_zalloc(sizeof (s1394_addr_space_blk_t),
				    KM_NOSLEEP);
				if (new_blk == NULL) {
					/* Unlock the addr space "free" list */
					mutex_exit(&hal->addr_space_free_mutex);
					return (DDI_FAILURE);
				}

				middle_blk = (s1394_addr_space_blk_t *)
				    kmem_zalloc(sizeof (s1394_addr_space_blk_t),
				    KM_NOSLEEP);
				if (middle_blk == NULL) {
					/* Unlock the addr space "free" list */
					mutex_exit(&hal->addr_space_free_mutex);
					kmem_free(new_blk,
					    sizeof (s1394_addr_space_blk_t));
					return (DDI_FAILURE);
				}

				middle_blk->addr_lo = addr_allocp->aa_address;
				middle_blk->addr_hi = upper_bound;
				new_blk->addr_lo = upper_bound + 1;
				new_blk->addr_hi = curr_blk->addr_hi;

				new_blk->addr_type = curr_blk->addr_type;

				middle_blk->addr_type = curr_blk->addr_type;
				middle_blk->addr_enable =
				    addr_allocp->aa_enable;
				middle_blk->kmem_bufp =
				    addr_allocp->aa_kmem_bufp;
				middle_blk->addr_arg = addr_allocp->aa_arg;
				middle_blk->addr_events = addr_allocp->aa_evts;

				curr_blk->addr_hi = addr_allocp->aa_address - 1;

				addr_allocp->aa_hdl =
				    (t1394_addr_handle_t)middle_blk;

				/* Put part back into the "free" tree */
				s1394_free_list_insert(hal, new_blk);

				/* Unlock the address space free list */
				mutex_exit(&hal->addr_space_free_mutex);

				/* Put it into the "used" tree */
				s1394_used_tree_insert(hal, middle_blk);

				s1394_addr_alloc_kstat(hal,
				    addr_allocp->aa_address);

				return (DDI_SUCCESS);
			}
		}
	}

claim_error:
	/* Unlock the address space free list */
	mutex_exit(&hal->addr_space_free_mutex);

	return (DDI_FAILURE);
}

/*
 * s1394_free_addr_blk()
 *    An opposite of s1394_claim_addr_blk(): takes the address block
 *    out of the "used" tree and puts it into the "free" tree.
 */
int
s1394_free_addr_blk(s1394_hal_t *hal, s1394_addr_space_blk_t *blk)
{
	/* Lock the address space "free" list */
	mutex_enter(&hal->addr_space_free_mutex);

	/* Take it out of the "used" tree */
	blk = s1394_used_tree_delete(hal, blk);

	if (blk == NULL) {
		/* Unlock the address space "free" list */
		mutex_exit(&hal->addr_space_free_mutex);
		return (DDI_FAILURE);
	}

	/* Put it into the "free" tree */
	s1394_free_list_insert(hal, blk);

	/* Unlock the address space "free" list */
	mutex_exit(&hal->addr_space_free_mutex);

	return (DDI_SUCCESS);
}

/*
 * s1394_reserve_addr_blk()
 *    is similar to s1394_claim_addr_blk(), with the difference being that
 *    after the address block is found, it is marked as "reserved" rather
 *    than inserted into the used tree.  Blocks of data that are marked
 *    "reserved" cannot be unintentionally allocated by a target, they must
 *    be specifically requested by specifying the exact address and size of
 *    the "reserved" block.
 */
int
s1394_reserve_addr_blk(s1394_hal_t *hal, t1394_alloc_addr_t *addr_allocp)
{
	s1394_addr_space_blk_t	*curr_blk;
	s1394_addr_space_blk_t	*new_blk;
	s1394_addr_space_blk_t	*middle_blk;
	uint64_t		upper_bound;

	ASSERT(hal != NULL);

	/* Lock the address space "free" list */
	mutex_enter(&hal->addr_space_free_mutex);

	/* Find the block in the "free" list */
	curr_blk = s1394_free_list_search(hal, addr_allocp->aa_address);
	/* If it wasn't found, it isn't free... */
	if (curr_blk == NULL) {
		/* Unlock the address space free list */
		mutex_exit(&hal->addr_space_free_mutex);

		return (DDI_FAILURE);
	}

	/* Is this block already reserved? */
	if (curr_blk->addr_reserved == ADDR_RESERVED) {
		/* Unlock the address space free list */
		mutex_exit(&hal->addr_space_free_mutex);

		return (DDI_FAILURE);
	}

	/* Does the request fit in the block? */
	upper_bound = (addr_allocp->aa_address + addr_allocp->aa_length) - 1;
	if ((upper_bound >= curr_blk->addr_lo) &&
	    (upper_bound <= curr_blk->addr_hi)) {

		/* How does the requested range fit in the current range? */
		if (addr_allocp->aa_address == curr_blk->addr_lo) {
			if (upper_bound == curr_blk->addr_hi) {
				/* Exact fit */
				curr_blk->addr_reserved = ADDR_RESERVED;

				/* Unlock the address space "free" list */
				mutex_exit(&hal->addr_space_free_mutex);

				return (DDI_SUCCESS);

			} else {
				/* Front part of range */
				new_blk = (s1394_addr_space_blk_t *)
				    kmem_zalloc(sizeof (s1394_addr_space_blk_t),
				    KM_NOSLEEP);
				if (new_blk == NULL) {
					/* Unlock the addr space "free" list */
					mutex_exit(&hal->addr_space_free_mutex);
					return (DDI_FAILURE);
				}

				new_blk->addr_lo = curr_blk->addr_lo;
				new_blk->addr_hi = upper_bound;
				new_blk->addr_type = curr_blk->addr_type;
				new_blk->addr_reserved = ADDR_RESERVED;

				curr_blk->addr_lo = new_blk->addr_hi + 1;

				/* Put it back into the "free" list */
				s1394_free_list_insert(hal, new_blk);

				/* Unlock the address space free list */
				mutex_exit(&hal->addr_space_free_mutex);

				return (DDI_SUCCESS);
			}

		} else {
			if (upper_bound == curr_blk->addr_hi) {
				/* End part of range */
				new_blk = (s1394_addr_space_blk_t *)
				    kmem_zalloc(sizeof (s1394_addr_space_blk_t),
				    KM_NOSLEEP);
				if (new_blk == NULL) {
					/* Unlock the addr space "free" list */
					mutex_exit(&hal->addr_space_free_mutex);
					return (DDI_FAILURE);
				}

				new_blk->addr_lo = addr_allocp->aa_address;
				new_blk->addr_hi = upper_bound;
				new_blk->addr_type = curr_blk->addr_type;
				new_blk->addr_reserved = ADDR_RESERVED;

				curr_blk->addr_hi = addr_allocp->aa_address - 1;

				/* Put it back into the "free" list */
				s1394_free_list_insert(hal, new_blk);

				/* Unlock the address space free list */
				mutex_exit(&hal->addr_space_free_mutex);

				return (DDI_SUCCESS);

			} else {
				/* Middle part of range */
				new_blk = (s1394_addr_space_blk_t *)
				    kmem_zalloc(sizeof (s1394_addr_space_blk_t),
				    KM_NOSLEEP);
				if (new_blk == NULL) {
					/* Unlock the addr space "free" list */
					mutex_exit(&hal->addr_space_free_mutex);
					return (DDI_FAILURE);
				}

				middle_blk = (s1394_addr_space_blk_t *)
				    kmem_zalloc(sizeof (s1394_addr_space_blk_t),
				    KM_NOSLEEP);
				if (middle_blk == NULL) {
					/* Unlock the addr space "free" list */
					mutex_exit(&hal->addr_space_free_mutex);
					kmem_free(new_blk,
					    sizeof (s1394_addr_space_blk_t));
					return (DDI_FAILURE);
				}

				middle_blk->addr_lo = addr_allocp->aa_address;
				middle_blk->addr_hi = upper_bound;
				new_blk->addr_lo = upper_bound + 1;
				new_blk->addr_hi = curr_blk->addr_hi;

				new_blk->addr_type = curr_blk->addr_type;

				middle_blk->addr_type = curr_blk->addr_type;
				middle_blk->addr_reserved = ADDR_RESERVED;

				curr_blk->addr_hi = addr_allocp->aa_address - 1;

				/* Put pieces back into the "free" list */
				s1394_free_list_insert(hal, middle_blk);
				s1394_free_list_insert(hal, new_blk);

				/* Unlock the address space free list */
				mutex_exit(&hal->addr_space_free_mutex);

				return (DDI_SUCCESS);
			}
		}
	}

	/* Unlock the address space free list */
	mutex_exit(&hal->addr_space_free_mutex);

	return (DDI_FAILURE);
}

/*
 * s1394_init_addr_space()
 *    is called in the HAL attach routine - h1394_attach() - to setup the
 *    initial address space with the appropriate ranges, etc.  At attach,
 *    the HAL specifies not only the type and bounds for each kind of 1394
 *    address space, but also a list of the blocks that are to be marked
 *    "reserved".  Prior to marking the "reserved" ranges the local hosts
 *    CSR registers are allocated/setup in s1394_setup_CSR_space().
 */
int
s1394_init_addr_space(s1394_hal_t *hal)
{
	s1394_addr_space_blk_t	*addr_blk;
	t1394_alloc_addr_t	addr_alloc;
	h1394_addr_map_t	*addr_map;
	h1394_addr_map_t	*resv_map;
	uint_t			num_blks;
	uint64_t		lo;
	uint64_t		hi;
	int			i;
	int			ret;

	/* Setup Address Space */
	mutex_init(&hal->addr_space_free_mutex,
	    NULL, MUTEX_DRIVER, NULL);
	mutex_init(&hal->addr_space_used_mutex,
	    NULL, MUTEX_DRIVER, hal->halinfo.hw_interrupt);

	/* Set address space to NULL (empty) */
	hal->addr_space_free_list = NULL;
	hal->addr_space_used_tree = NULL;

	/* Initialize the 1394 Address Space from HAL's description */
	num_blks = hal->halinfo.addr_map_num_entries;
	addr_map = hal->halinfo.addr_map;

	/* Lock the address space free list */
	mutex_enter(&hal->addr_space_free_mutex);

	/* Default to NO posted write space */
	hal->posted_write_addr_lo = ADDR_LO_INVALID;
	hal->posted_write_addr_hi = ADDR_HI_INVALID;

	/* Default to NO physical space */
	hal->physical_addr_lo = ADDR_LO_INVALID;
	hal->physical_addr_hi = ADDR_HI_INVALID;

	/* Default to NO CSR space */
	hal->csr_addr_lo = ADDR_LO_INVALID;
	hal->csr_addr_hi = ADDR_HI_INVALID;

	/* Default to NO normal space */
	hal->normal_addr_lo = ADDR_LO_INVALID;
	hal->normal_addr_hi = ADDR_HI_INVALID;

	for (i = 0; i < num_blks; i++) {
		if (addr_map[i].length == 0)
			continue;
		addr_blk = kmem_zalloc(sizeof (s1394_addr_space_blk_t),
		    KM_SLEEP);
		addr_blk->addr_lo = addr_map[i].address;
		addr_blk->addr_hi =
		    (addr_blk->addr_lo + addr_map[i].length) - 1;

		switch (addr_map[i].addr_type) {
		case H1394_ADDR_POSTED_WRITE:
			addr_blk->addr_type = T1394_ADDR_POSTED_WRITE;
			hal->posted_write_addr_lo = addr_blk->addr_lo;
			hal->posted_write_addr_hi = addr_blk->addr_hi;
			break;

		case H1394_ADDR_NORMAL:
			addr_blk->addr_type = T1394_ADDR_NORMAL;
			hal->normal_addr_lo = addr_blk->addr_lo;
			hal->normal_addr_hi = addr_blk->addr_hi;
			break;

		case H1394_ADDR_CSR:
			addr_blk->addr_type = T1394_ADDR_CSR;
			hal->csr_addr_lo = addr_blk->addr_lo;
			hal->csr_addr_hi = addr_blk->addr_hi;
			break;

		case H1394_ADDR_PHYSICAL:
			addr_blk->addr_type = T1394_ADDR_FIXED;
			hal->physical_addr_lo = addr_blk->addr_lo;
			hal->physical_addr_hi = addr_blk->addr_hi;
			break;

		default:
			/* Unlock the address space free list */
			mutex_exit(&hal->addr_space_free_mutex);
			s1394_destroy_addr_space(hal);
			return (DDI_FAILURE);
		}
		s1394_free_list_insert(hal, addr_blk);
	}

	/* Unlock the address space free list */
	mutex_exit(&hal->addr_space_free_mutex);

	/* Setup the necessary CSR space */
	if (s1394_setup_CSR_space(hal) != DDI_SUCCESS) {
		s1394_destroy_addr_space(hal);
		return (DDI_FAILURE);
	}


	/* Handle all the HAL's reserved spaces */
	num_blks = hal->halinfo.resv_map_num_entries;
	resv_map = hal->halinfo.resv_map;

	for (i = 0; i < num_blks; i++) {
		/* Can't reserve physical addresses */
		lo = resv_map[i].address;
		hi = (lo + resv_map[i].length) - 1;
		if ((lo >= hal->physical_addr_lo) &&
		    (hi <= hal->physical_addr_hi)) {
			s1394_destroy_addr_space(hal);
			return (DDI_FAILURE);
		}

		addr_alloc.aa_address = resv_map[i].address;
		addr_alloc.aa_length = resv_map[i].length;
		ret = s1394_reserve_addr_blk(hal, &addr_alloc);
		if (ret != DDI_SUCCESS) {
			s1394_destroy_addr_space(hal);
			return (DDI_FAILURE);
		}
	}

	return (DDI_SUCCESS);
}

/*
 * s1394_destroy_addr_space()
 *    is necessary for h1394_detach().  It undoes all the work that
 *    s1394_init_addr_space() had setup and more.  By pulling everything out
 *    of the used tree and free list and then freeing the structures,
 *    mutexes, and (if necessary) any backing store memory, the 1394 address
 *    space is completely dismantled.
 */
void
s1394_destroy_addr_space(s1394_hal_t *hal)
{
	s1394_addr_space_blk_t	*addr_blk;
	s1394_addr_space_blk_t	*next_blk;
	uint64_t		lo;
	uint64_t		hi;
	uint_t			length;

	/* Lock the address space "used" tree */
	mutex_enter(&hal->addr_space_used_mutex);

	addr_blk = hal->addr_space_used_tree;

	while (addr_blk != NULL) {
		if (addr_blk->asb_left != NULL) {
			addr_blk = addr_blk->asb_left;
		} else if (addr_blk->asb_right != NULL) {
			addr_blk = addr_blk->asb_right;
		} else {
			/* Free any of our own backing store (if necessary) */
			if ((addr_blk->free_kmem_bufp == B_TRUE) &&
			    (addr_blk->kmem_bufp != NULL)) {
				lo = addr_blk->addr_lo;
				hi = addr_blk->addr_hi;
				length = (uint_t)((hi - lo) + 1);
				kmem_free((void *)addr_blk->kmem_bufp, length);
			}

			next_blk = addr_blk->asb_parent;

			/* Free the s1394_addr_space_blk_t structure */
			kmem_free((void *)addr_blk,
			    sizeof (s1394_addr_space_blk_t));

			if (next_blk != NULL) {
				if (next_blk->asb_left != NULL)
					next_blk->asb_left = NULL;
				else
					next_blk->asb_right = NULL;
			}

			addr_blk = next_blk;
		}
	}

	/* Unlock and destroy the address space "used" tree */
	mutex_exit(&hal->addr_space_used_mutex);
	mutex_destroy(&hal->addr_space_used_mutex);

	/* Lock the address space "free" list */
	mutex_enter(&hal->addr_space_free_mutex);

	addr_blk = hal->addr_space_free_list;

	while (addr_blk != NULL) {
		next_blk = addr_blk->asb_right;

		/* Free the s1394_addr_space_blk_t structure */
		kmem_free((void *)addr_blk, sizeof (s1394_addr_space_blk_t));
		addr_blk = next_blk;
	}

	/* Unlock & destroy the address space "free" list */
	mutex_exit(&hal->addr_space_free_mutex);
	mutex_destroy(&hal->addr_space_free_mutex);
}

/*
 * s1394_free_list_insert()
 *    takes an s1394_addr_space_blk_t and inserts it into the free list in the
 *    appropriate place.  It will concatenate into a single structure on the
 *    list any two neighboring blocks that can be joined (same type,
 *    consecutive addresses, neither is "reserved", etc.)
 */
void
s1394_free_list_insert(s1394_hal_t *hal, s1394_addr_space_blk_t *new_blk)
{
	s1394_addr_space_blk_t	*curr_blk;
	s1394_addr_space_blk_t	*left_blk;
	s1394_addr_space_blk_t	*right_blk;

	ASSERT(MUTEX_HELD(&hal->addr_space_free_mutex));

	/* Start at the head of the "free" list */
	curr_blk = hal->addr_space_free_list;

	if (curr_blk != NULL)
		left_blk = curr_blk->asb_left;
	else
		left_blk = NULL;

	while (curr_blk != NULL) {
		if (new_blk->addr_lo < curr_blk->addr_lo)
			break;
		/* Go to the next element in the list */
		left_blk = curr_blk;
		curr_blk = curr_blk->asb_right;
	}

	new_blk->asb_left = left_blk;
	new_blk->asb_right = curr_blk;

	if (left_blk != NULL)
		left_blk->asb_right = new_blk;
	else
		hal->addr_space_free_list = new_blk;

	if (curr_blk != NULL)
		curr_blk->asb_left = new_blk;

	right_blk = new_blk->asb_right;
	left_blk = new_blk->asb_left;

	/* Can we merge with block to the left? */
	if ((left_blk != NULL) &&
	    (new_blk->addr_type == left_blk->addr_type) &&
	    (new_blk->addr_reserved != ADDR_RESERVED) &&
	    (left_blk->addr_reserved != ADDR_RESERVED) &&
	    (new_blk->addr_lo == left_blk->addr_hi + 1)) {

		new_blk->addr_lo = left_blk->addr_lo;
		new_blk->asb_left = left_blk->asb_left;

		if (left_blk->asb_left != NULL)
			left_blk->asb_left->asb_right = new_blk;
		if (hal->addr_space_free_list == left_blk)
			hal->addr_space_free_list = new_blk;
		kmem_free((void *)left_blk, sizeof (s1394_addr_space_blk_t));
	}

	/* Can we merge with block to the right? */
	if ((right_blk != NULL) &&
	    (new_blk->addr_type == right_blk->addr_type) &&
	    (new_blk->addr_reserved != ADDR_RESERVED) &&
	    (right_blk->addr_reserved != ADDR_RESERVED) &&
	    (new_blk->addr_hi + 1 == right_blk->addr_lo)) {

		new_blk->addr_hi = right_blk->addr_hi;
		new_blk->asb_right = right_blk->asb_right;

		if (right_blk->asb_right != NULL)
			right_blk->asb_right->asb_left = new_blk;
		kmem_free((void *)right_blk, sizeof (s1394_addr_space_blk_t));
	}

	new_blk->addr_enable = 0;
	new_blk->kmem_bufp = NULL;
	new_blk->addr_arg = NULL;
}

/*
 * s1394_free_list_search()
 *    attempts to find a block in the free list that contains the address
 *    specified.  If none is found, it returns NULL.
 */
static s1394_addr_space_blk_t *
s1394_free_list_search(s1394_hal_t *hal, uint64_t addr)
{
	s1394_addr_space_blk_t	*curr_blk;

	ASSERT(MUTEX_HELD(&hal->addr_space_free_mutex));

	/* Start at the head of the list */
	curr_blk = hal->addr_space_free_list;
	while (curr_blk != NULL) {
		if ((addr >= curr_blk->addr_lo) && (addr <= curr_blk->addr_hi))
			break;
		else
			curr_blk = curr_blk->asb_right;
	}

	return (curr_blk);
}

/*
 * s1394_free_list_find()
 *    attempts to find a block in the free list that is of the specified
 *    type and size.  It will ignore any blocks marked "reserved".
 */
static s1394_addr_space_blk_t *
s1394_free_list_find(s1394_hal_t *hal, uint32_t type, uint32_t length)
{
	s1394_addr_space_blk_t	*curr_blk;
	uint64_t		size;

	ASSERT(MUTEX_HELD(&hal->addr_space_free_mutex));

	/* Start at the head of the list */
	curr_blk = hal->addr_space_free_list;

	while (curr_blk != NULL) {
		/* Find block of right "type" - that isn't "reserved" */
		if ((curr_blk->addr_type == type) &&
		    (curr_blk->addr_reserved != ADDR_RESERVED)) {

			/* CSR allocs above IEEE1394_UCSR_RESERVED_BOUNDARY */
			if ((type == T1394_ADDR_CSR) &&
			    (curr_blk->addr_lo <
				IEEE1394_UCSR_RESERVED_BOUNDARY)) {
				curr_blk = curr_blk->asb_right;
				continue;
			}

			size = (curr_blk->addr_hi - curr_blk->addr_lo) + 1;
			if (size >= (uint64_t)length)
				break;
		}
		curr_blk = curr_blk->asb_right;
	}

	return (curr_blk);
}

/*
 * s1394_free_list_delete()
 *    will remove the block pointed to by del_blk from the free list.
 *    Typically, this is done so that it may be inserted into the used tree.
 */
static s1394_addr_space_blk_t *
s1394_free_list_delete(s1394_hal_t *hal, s1394_addr_space_blk_t *del_blk)
{
	s1394_addr_space_blk_t	*left_blk;
	s1394_addr_space_blk_t	*right_blk;

	ASSERT(MUTEX_HELD(&hal->addr_space_free_mutex));

	left_blk = del_blk->asb_left;
	right_blk = del_blk->asb_right;

	del_blk->asb_left = NULL;
	del_blk->asb_right = NULL;

	if (left_blk != NULL)
		left_blk->asb_right = right_blk;
	else
		hal->addr_space_free_list = right_blk;

	if (right_blk != NULL)
		right_blk->asb_left = left_blk;

	return (del_blk);
}

/*
 * s1394_used_tree_insert()
 *    is used to insert a 1394 address block that has been removed from the
 *    free list into the used tree.  In the used tree it will be possible
 *    to search for a given address when an AR request arrives.  Since the
 *    used tree is implemented as a red-black tree, the insertion is done
 *    with s1394_tree_insert() which does a simple binary tree insertion.
 *    It is then followed by cleanup of links and red-black coloring.  This
 *    particulat implementation of the red-black tree is modified from code
 *    included in "Introduction to Algorithms" - Cormen, Leiserson, and Rivest,
 *    pp. 263 - 277.
 */
static void
s1394_used_tree_insert(s1394_hal_t *hal, s1394_addr_space_blk_t *x)
{
	s1394_addr_space_blk_t	*y;
	s1394_addr_space_blk_t	**root;

	/* Lock the "used" tree */
	mutex_enter(&hal->addr_space_used_mutex);

	/* Get the head of the "used" tree */
	root = &hal->addr_space_used_tree;

	s1394_tree_insert(root, x);

	x->asb_color = RED;
	while ((x != *root) && (x->asb_parent->asb_color == RED)) {
		/* Is x's parent the "left-child" or the "right-child"? */
		if (x->asb_parent == x->asb_parent->asb_parent->asb_left) {
			/* Left-child, set y to the sibling */
			y = x->asb_parent->asb_parent->asb_right;
			if ((y != NULL) && (y->asb_color == RED)) {
				x->asb_parent->asb_color = BLACK;
				y->asb_color = BLACK;
				x->asb_parent->asb_parent->asb_color = RED;
				x = x->asb_parent->asb_parent;

			} else {
				if (x == x->asb_parent->asb_right) {
					x = x->asb_parent;
					s1394_left_rotate(root, x);
				}
				x->asb_parent->asb_color = BLACK;
				x->asb_parent->asb_parent->asb_color = RED;
				s1394_right_rotate(root,
				    x->asb_parent->asb_parent);
			}

		} else {
			/* Right-child, set y to the sibling */
			y = x->asb_parent->asb_parent->asb_left;
			if ((y != NULL) && (y->asb_color == RED)) {
				x->asb_parent->asb_color = BLACK;
				y->asb_color = BLACK;
				x->asb_parent->asb_parent->asb_color = RED;
				x = x->asb_parent->asb_parent;

			} else {
				if (x == x->asb_parent->asb_left) {
					x = x->asb_parent;
					s1394_right_rotate(root, x);
				}
				x->asb_parent->asb_color = BLACK;
				x->asb_parent->asb_parent->asb_color = RED;
				s1394_left_rotate(root,
				    x->asb_parent->asb_parent);
			}
		}
	}

	(*root)->asb_color = BLACK;

	/* Unlock the "used" tree */
	mutex_exit(&hal->addr_space_used_mutex);
}

/*
 * s1394_tree_insert()
 *    is a "helper" function for s1394_used_tree_insert().  It inserts an
 *    address block into a binary tree (red-black tree), and
 *    s1394_used_tree_insert() then cleans up the links and colorings, etc.
 */
static void
s1394_tree_insert(s1394_addr_space_blk_t **root, s1394_addr_space_blk_t *z)
{
	s1394_addr_space_blk_t	*y = NULL;
	s1394_addr_space_blk_t	*x = *root;

	while (x != NULL) {
		y = x;
		if (z->addr_lo < x->addr_lo)
			x = x->asb_left;
		else
			x = x->asb_right;
	}

	z->asb_parent = y;
	z->asb_right = NULL;
	z->asb_left = NULL;

	if (y == NULL)
		*root = z;
	else if (z->addr_lo < y->addr_lo)
		y->asb_left = z;
	else
		y->asb_right = z;
}

/*
 * s1394_used_tree_search()
 *    is called when an AR request arrives.  By calling s1394_tree_search()
 *    with the destination address, it can quickly find a block for that
 *    address (if one exists in the used tree) and return a pointer to it.
 */
s1394_addr_space_blk_t *
s1394_used_tree_search(s1394_hal_t *hal, uint64_t addr)
{
	s1394_addr_space_blk_t *curr_blk;

	ASSERT(MUTEX_HELD(&hal->addr_space_used_mutex));

	/* Search the HAL's "used" tree for this address */
	curr_blk = s1394_tree_search(hal->addr_space_used_tree, addr);

	return (curr_blk);
}

/*
 * s1394_tree_search()
 *    is a "helper" function for s1394_used_tree_search().  It implements a
 *    typical binary tree search with the address as the search key.
 */
static s1394_addr_space_blk_t *
s1394_tree_search(s1394_addr_space_blk_t *x, uint64_t address)
{
	while (x != NULL) {
		if (x->addr_lo > address)
			x = x->asb_left;
		else if (x->addr_hi < address)
			x = x->asb_right;
		else
			break;
	}

	return (x);
}

/*
 * s1394_used_tree_delete()
 *    is used to remove an address block from the used tree.  This is
 *    necessary when address spaces are freed.  The removal is accomplished
 *    in two steps, the removal done by this function and the cleanup done
 *    by s1394_used_tree_delete_fixup().
 */
s1394_addr_space_blk_t *
s1394_used_tree_delete(s1394_hal_t *hal, s1394_addr_space_blk_t *z)
{
	s1394_addr_space_blk_t	*y;
	s1394_addr_space_blk_t	*x;
	s1394_addr_space_blk_t	*w;
	s1394_addr_space_blk_t	*p;
	s1394_addr_space_blk_t	**root;
	int			old_color;
	int			side_of_x;

	/* Lock the "used" tree */
	mutex_enter(&hal->addr_space_used_mutex);

	/* Get the head of the "used" tree */
	root = &hal->addr_space_used_tree;

	if ((z->asb_left == NULL) || (z->asb_right == NULL))
		y = z;
	else
		y = s1394_tree_successor(z);

	if (y->asb_parent == z)
		p = y;
	else
		p = y->asb_parent;

	if (y->asb_left != NULL) {
		x = y->asb_left;
		if ((y != *root) && (y == y->asb_parent->asb_left)) {
			w = y->asb_parent->asb_right;
			side_of_x = LEFT;
		}

		if ((y != *root) && (y == y->asb_parent->asb_right)) {
			w = y->asb_parent->asb_left;
			side_of_x = RIGHT;
		}

	} else {
		x = y->asb_right;
		if ((y != *root) && (y == y->asb_parent->asb_left)) {
			w = y->asb_parent->asb_right;
			side_of_x = LEFT;
		}

		if ((y != *root) && (y == y->asb_parent->asb_right)) {
			w = y->asb_parent->asb_left;
			side_of_x = RIGHT;
		}

	}

	if (x != NULL)
		x->asb_parent = y->asb_parent;

	if (y->asb_parent == NULL)
		*root = x;
	else if (y == y->asb_parent->asb_left)
		y->asb_parent->asb_left = x;
	else
		y->asb_parent->asb_right = x;

	old_color = y->asb_color;

	/* Substitute the y-node for the z-node (deleted) */
	if (y != z) {
		y->asb_color = z->asb_color;
		y->asb_parent = z->asb_parent;
		if (z->asb_parent != NULL) {
			if (z->asb_parent->asb_left == z)
				z->asb_parent->asb_left = y;
			if (z->asb_parent->asb_right == z)
				z->asb_parent->asb_right = y;
		}

		y->asb_left = z->asb_left;
		if (z->asb_left != NULL)
			z->asb_left->asb_parent = y;
		y->asb_right = z->asb_right;
		if (z->asb_right != NULL)
			z->asb_right->asb_parent = y;

		if (z == *root)
			*root = y;
	}

	z->asb_parent = NULL;
	z->asb_right = NULL;
	z->asb_left = NULL;

	if (old_color == BLACK)
		s1394_used_tree_delete_fixup(root, p, x, w, side_of_x);

	/* Unlock the "used" tree */
	mutex_exit(&hal->addr_space_used_mutex);

	return (z);
}

/*
 * s1394_used_tree_delete_fixup()
 *    is the "helper" function for s1394_used_tree_delete().  It is used to
 *    cleanup/enforce the red-black coloring in the tree.
 */
static void
s1394_used_tree_delete_fixup(s1394_addr_space_blk_t **root,
    s1394_addr_space_blk_t *p, s1394_addr_space_blk_t *x,
    s1394_addr_space_blk_t *w, int side_of_x)
{
	boolean_t	first_time;

	first_time = B_TRUE;
	while ((x != *root) && ((x == NULL) || (x->asb_color == BLACK))) {
		if (((first_time == B_TRUE) && (side_of_x == LEFT)) ||
		    ((first_time == B_FALSE) && (x == p->asb_left))) {

			if (first_time != B_TRUE)
				w = p->asb_right;

			if ((w != NULL) && (w->asb_color == RED)) {
				w->asb_color = BLACK;
				p->asb_color = RED;
				s1394_left_rotate(root, p);
				w = p->asb_right;
			}

			if (w == NULL) {
				x = p;
				p = p->asb_parent;
				first_time = B_FALSE;

			} else if (((w->asb_left == NULL) ||
			    (w->asb_left->asb_color == BLACK)) &&
			    ((w->asb_right == NULL) ||
			    (w->asb_right->asb_color == BLACK))) {
				w->asb_color = RED;
				x = p;
				p = p->asb_parent;
				first_time = B_FALSE;

			} else {
				if ((w->asb_right == NULL) ||
				    (w->asb_right->asb_color == BLACK)) {
					w->asb_left->asb_color = BLACK;
					w->asb_color = RED;
					s1394_right_rotate(root, w);
					w = p->asb_right;
				}

				w->asb_color = p->asb_color;
				p->asb_color = BLACK;
				if (w->asb_right != NULL)
					w->asb_right->asb_color = BLACK;
				s1394_left_rotate(root, p);
				x = *root;
				first_time = B_FALSE;
			}

		} else {
			if (first_time == B_FALSE)
				w = p->asb_left;

			if ((w != NULL) && (w->asb_color == RED)) {
				w->asb_color = BLACK;
				p->asb_color = RED;
				s1394_right_rotate(root, p);
				w = p->asb_left;
			}

			if (w == NULL) {
				x = p;
				p = p->asb_parent;
				first_time = B_FALSE;

			} else if (((w->asb_left == NULL) ||
			    (w->asb_left->asb_color == BLACK)) &&
			    ((w->asb_right == NULL) ||
			    (w->asb_right->asb_color == BLACK))) {
				w->asb_color = RED;
				x = p;
				p = p->asb_parent;
				first_time = B_FALSE;

			} else {
				if ((w->asb_left == NULL) ||
				    (w->asb_left->asb_color == BLACK)) {

					w->asb_right->asb_color = BLACK;
					w->asb_color = RED;
					s1394_left_rotate(root, w);
					w = p->asb_left;
				}

				w->asb_color = p->asb_color;
				p->asb_color = BLACK;
				if (w->asb_left != NULL)
					w->asb_left->asb_color = BLACK;
				s1394_right_rotate(root, p);
				x = *root;
				first_time = B_FALSE;
			}
		}
	}
	if (x != NULL)
		x->asb_color = BLACK;
}

/*
 * s1394_left_rotate()
 *    is necessary with a red-black tree to help maintain the coloring in the
 *    tree as items are inserted and removed.  Its operation, the opposite of
 *    s1394_right_rotate(), is a fundamental operation on the red-black tree.
 */
static void
s1394_left_rotate(s1394_addr_space_blk_t **root, s1394_addr_space_blk_t *x)
{
	s1394_addr_space_blk_t	*y;

	y = x->asb_right;
	x->asb_right = y->asb_left;

	if (y->asb_left != NULL)
		y->asb_left->asb_parent = x;

	y->asb_parent = x->asb_parent;
	if (x->asb_parent == NULL)
		*root = y;
	else if (x == x->asb_parent->asb_left)
		x->asb_parent->asb_left = y;
	else
		x->asb_parent->asb_right = y;

	y->asb_left = x;
	x->asb_parent = y;
}

/*
 * s1394_right_rotate()
 *    is necessary with a red-black tree to help maintain the coloring in the
 *    tree as items are inserted and removed.  Its operation, the opposite of
 *    s1394_left_rotate(), is a fundamental operation on the red-black tree.
 */
static void
s1394_right_rotate(s1394_addr_space_blk_t **root, s1394_addr_space_blk_t *x)
{
	s1394_addr_space_blk_t	*y;

	y = x->asb_left;
	x->asb_left = y->asb_right;

	if (y->asb_right != NULL)
		y->asb_right->asb_parent = x;

	y->asb_parent = x->asb_parent;
	if (x->asb_parent == NULL)
		*root = y;
	else if (x == x->asb_parent->asb_right)
		x->asb_parent->asb_right = y;
	else
		x->asb_parent->asb_left = y;

	y->asb_right = x;
	x->asb_parent = y;
}

/*
 * s1394_tree_minimum()
 *    is used to find the smallest key in a binary tree.
 */
static s1394_addr_space_blk_t *
s1394_tree_minimum(s1394_addr_space_blk_t *x)
{
	while (x->asb_left != NULL)
		x = x->asb_left;

	return (x);
}

/*
 * s1394_tree_successor()
 *    is used to find the next largest key is a binary tree, given a starting
 *    point.
 */
static s1394_addr_space_blk_t *
s1394_tree_successor(s1394_addr_space_blk_t *x)
{
	s1394_addr_space_blk_t	*y;

	if (x->asb_right != NULL) {
		y = s1394_tree_minimum(x->asb_right);

		return (y);
	}

	y = x->asb_parent;
	while ((y != NULL) && (x == y->asb_right)) {
		x = y;
		y = y->asb_parent;
	}

	return (y);
}

/*
 * s1394_is_posted_write()
 *    returns a B_TRUE if the given address is in the "posted write" range
 *    of the given HAL's 1394 address space and B_FALSE if it isn't.
 */
boolean_t
s1394_is_posted_write(s1394_hal_t *hal, uint64_t addr)
{
	addr = addr & IEEE1394_ADDR_OFFSET_MASK;

	if ((addr >= hal->posted_write_addr_lo) &&
	    (addr <= hal->posted_write_addr_hi))
		return (B_TRUE);
	else
		return (B_FALSE);
}

/*
 * s1394_is_physical_addr()
 *    returns a B_TRUE if the given address is in the "physical" range of
 *    the given HAL's 1394 address space and B_FALSE if it isn't.
 */
boolean_t
s1394_is_physical_addr(s1394_hal_t *hal, uint64_t addr)
{
	addr = addr & IEEE1394_ADDR_OFFSET_MASK;

	if ((addr >= hal->physical_addr_lo) &&
	    (addr <= hal->physical_addr_hi))
		return (B_TRUE);
	else
		return (B_FALSE);
}

/*
 * s1394_is_csr_addr()
 *    returns a B_TRUE if the given address is in the "CSR" range of the
 *    given HAL's 1394 address space and B_FALSE if it isn't.
 */
boolean_t
s1394_is_csr_addr(s1394_hal_t *hal, uint64_t addr)
{
	addr = addr & IEEE1394_ADDR_OFFSET_MASK;

	if ((addr >= hal->csr_addr_lo) &&
	    (addr <= hal->csr_addr_hi))
		return (B_TRUE);
	else
		return (B_FALSE);
}

/*
 * s1394_is_normal_addr()
 *    returns a B_TRUE if the given address is in the "normal" range of
 *    the given HAL's 1394 address space and B_FALSE if it isn't.
 */
boolean_t
s1394_is_normal_addr(s1394_hal_t *hal, uint64_t addr)
{
	addr = addr & IEEE1394_ADDR_OFFSET_MASK;

	if ((addr >= hal->normal_addr_lo) &&
	    (addr <= hal->normal_addr_hi))
		return (B_TRUE);
	else
		return (B_FALSE);
}
