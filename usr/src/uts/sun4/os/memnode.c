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
 */

#include <sys/systm.h>
#include <sys/platform_module.h>
#include <sys/sysmacros.h>
#include <sys/atomic.h>
#include <sys/memlist.h>
#include <sys/memnode.h>
#include <vm/vm_dep.h>

int max_mem_nodes = 1;		/* max memory nodes on this system */

struct mem_node_conf mem_node_config[MAX_MEM_NODES];
int mem_node_pfn_shift;
/*
 * num_memnodes should be updated atomically and always >=
 * the number of bits in memnodes_mask or the algorithm may fail.
 */
uint16_t num_memnodes;
mnodeset_t memnodes_mask; /* assumes 8*(sizeof(mnodeset_t)) >= MAX_MEM_NODES */

/*
 * If set, mem_node_physalign should be a power of two, and
 * should reflect the minimum address alignment of each node.
 */
uint64_t mem_node_physalign;

/*
 * Platform hooks we will need.
 */

#pragma weak plat_build_mem_nodes
#pragma weak plat_slice_add
#pragma weak plat_slice_del

/*
 * Adjust the memnode config after a DR operation.
 *
 * It is rather tricky to do these updates since we can't
 * protect the memnode structures with locks, so we must
 * be mindful of the order in which updates and reads to
 * these values can occur.
 */
void
mem_node_add_slice(pfn_t start, pfn_t end)
{
	int mnode;
	mnodeset_t newmask, oldmask;

	/*
	 * DR will pass us the first pfn that is allocatable.
	 * We need to round down to get the real start of
	 * the slice.
	 */
	if (mem_node_physalign) {
		start &= ~(btop(mem_node_physalign) - 1);
		end = roundup(end, btop(mem_node_physalign)) - 1;
	}

	mnode = PFN_2_MEM_NODE(start);
	ASSERT(mnode < max_mem_nodes);

	if (atomic_cas_32((uint32_t *)&mem_node_config[mnode].exists, 0, 1)) {
		/*
		 * Add slice to existing node.
		 */
		if (start < mem_node_config[mnode].physbase)
			mem_node_config[mnode].physbase = start;
		if (end > mem_node_config[mnode].physmax)
			mem_node_config[mnode].physmax = end;
	} else {
		mem_node_config[mnode].physbase = start;
		mem_node_config[mnode].physmax = end;
		atomic_inc_16(&num_memnodes);
		do {
			oldmask = memnodes_mask;
			newmask = memnodes_mask | (1ull << mnode);
		} while (atomic_cas_64(&memnodes_mask, oldmask, newmask) !=
			 oldmask);
	}
	/*
	 * Let the common lgrp framework know about the new memory
	 */
	lgrp_config(LGRP_CONFIG_MEM_ADD, mnode, MEM_NODE_2_LGRPHAND(mnode));
}

/*
 * Remove a PFN range from a memnode.  On some platforms,
 * the memnode will be created with physbase at the first
 * allocatable PFN, but later deleted with the MC slice
 * base address converted to a PFN, in which case we need
 * to assume physbase and up.
 */
void
mem_node_del_slice(pfn_t start, pfn_t end)
{
	int mnode;
	pgcnt_t delta_pgcnt, node_size;
	mnodeset_t omask, nmask;

	if (mem_node_physalign) {
		start &= ~(btop(mem_node_physalign) - 1);
		end = roundup(end, btop(mem_node_physalign)) - 1;
	}
	mnode = PFN_2_MEM_NODE(start);

	ASSERT(mnode < max_mem_nodes);
	ASSERT(mem_node_config[mnode].exists == 1);

	delta_pgcnt = end - start;
	node_size = mem_node_config[mnode].physmax -
	    mem_node_config[mnode].physbase;

	if (node_size > delta_pgcnt) {
		/*
		 * Subtract the slice from the memnode.
		 */
		if (start <= mem_node_config[mnode].physbase)
			mem_node_config[mnode].physbase = end + 1;
		ASSERT(end <= mem_node_config[mnode].physmax);
		if (end == mem_node_config[mnode].physmax)
			mem_node_config[mnode].physmax = start - 1;
	} else {

		/*
		 * Let the common lgrp framework know the mnode is
		 * leaving
		 */
		lgrp_config(LGRP_CONFIG_MEM_DEL, mnode,
		    MEM_NODE_2_LGRPHAND(mnode));

		/*
		 * Delete the whole node.
		 */
		ASSERT(MNODE_PGCNT(mnode) == 0);
		do {
			omask = memnodes_mask;
			nmask = omask & ~(1ull << mnode);
		} while (atomic_cas_64(&memnodes_mask, omask, nmask) != omask);
		atomic_dec_16(&num_memnodes);
		mem_node_config[mnode].exists = 0;
	}
}

void
mem_node_add_range(pfn_t start, pfn_t end)
{
	if (&plat_slice_add != NULL)
		plat_slice_add(start, end);
	else
		mem_node_add_slice(start, end);
}

void
mem_node_del_range(pfn_t start, pfn_t end)
{
	if (&plat_slice_del != NULL)
		plat_slice_del(start, end);
	else
		mem_node_del_slice(start, end);
}

void
startup_build_mem_nodes(prom_memlist_t *list, size_t nelems)
{
	size_t	elem;
	pfn_t	basepfn;
	pgcnt_t	npgs;

	/* LINTED: ASSERT will always true or false */
	ASSERT(NBBY * sizeof (mnodeset_t) >= max_mem_nodes);

	if (&plat_build_mem_nodes != NULL) {
		plat_build_mem_nodes(list, nelems);
	} else {
		/*
		 * Boot install lists are arranged <addr, len>, ...
		 */
		for (elem = 0; elem < nelems; list++, elem++) {
			basepfn = btop(list->addr);
			npgs = btop(list->size);
			mem_node_add_range(basepfn, basepfn + npgs - 1);
		}
	}
}

/*
 * Allocate an unassigned memnode.
 */
int
mem_node_alloc()
{
	int mnode;
	mnodeset_t newmask, oldmask;

	/*
	 * Find an unused memnode.  Update it atomically to prevent
	 * a first time memnode creation race.
	 */
	for (mnode = 0; mnode < max_mem_nodes; mnode++)
		if (atomic_cas_32((uint32_t *)&mem_node_config[mnode].exists,
		    0, 1) == 0)
			break;

	if (mnode >= max_mem_nodes)
			panic("Out of free memnodes\n");

	mem_node_config[mnode].physbase = (uint64_t)-1;
	mem_node_config[mnode].physmax = 0;
	atomic_inc_16(&num_memnodes);
	do {
		oldmask = memnodes_mask;
		newmask = memnodes_mask | (1ull << mnode);
	} while (atomic_cas_64(&memnodes_mask, oldmask, newmask) != oldmask);

	return (mnode);
}

/*
 * Find the intersection between a memnode and a memlist
 * and returns the number of pages that overlap.
 *
 * Grab the memlist lock to protect the list from DR operations.
 */
pgcnt_t
mem_node_memlist_pages(int mnode, struct memlist *mlist)
{
	pfn_t		base, end;
	pfn_t		cur_base, cur_end;
	pgcnt_t		npgs = 0;
	pgcnt_t		pages;
	struct memlist	*pmem;

	if (&plat_mem_node_intersect_range != NULL) {
		memlist_read_lock();

		for (pmem = mlist; pmem; pmem = pmem->ml_next) {
			plat_mem_node_intersect_range(btop(pmem->ml_address),
			    btop(pmem->ml_size), mnode, &pages);
			npgs += pages;
		}

		memlist_read_unlock();
		return (npgs);
	}

	base = mem_node_config[mnode].physbase;
	end = mem_node_config[mnode].physmax;

	memlist_read_lock();

	for (pmem = mlist; pmem; pmem = pmem->ml_next) {
		cur_base = btop(pmem->ml_address);
		cur_end = cur_base + btop(pmem->ml_size) - 1;
		if (end < cur_base || base > cur_end)
			continue;
		npgs = npgs + (MIN(cur_end, end) -
		    MAX(cur_base, base)) + 1;
	}

	memlist_read_unlock();

	return (npgs);
}

/*
 * Find MIN(physbase) and MAX(physmax) over all mnodes
 *
 * Called during startup and DR to find hpm_counters limits when
 * interleaved_mnodes is set.
 * NOTE: there is a race condition with DR if it tries to change more than
 * one mnode in parallel. Sizing shared hpm_counters depends on finding the
 * min(physbase) and max(physmax) across all mnodes. Therefore, the caller of
 * page_ctrs_adjust must ensure that mem_node_config does not change while it
 * is running.
 */
void
mem_node_max_range(pfn_t *basep, pfn_t *maxp)
{
	int mnode;
	pfn_t max = 0;
	pfn_t base = (pfn_t)-1;

	for (mnode = 0; mnode < max_mem_nodes; mnode++) {
		if (mem_node_config[mnode].exists == 0)
			continue;
		if (max < mem_node_config[mnode].physmax)
			max = mem_node_config[mnode].physmax;
		if (base > mem_node_config[mnode].physbase)
			base = mem_node_config[mnode].physbase;
	}
	ASSERT(base != (pfn_t)-1 && max != 0);
	*basep = base;
	*maxp = max;
}
