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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/machsystm.h>
#include <sys/machparam.h>
#include <sys/cmn_err.h>
#include <sys/stat.h>
#include <sys/mach_descrip.h>
#include <sys/memnode.h>
#include <sys/mdesc.h>
#include <sys/mpo.h>
#include <vm/vm_dep.h>
#include <vm/hat_sfmmu.h>
#include <sys/promif.h>

/*
 * MPO and the sun4v memory representation
 * ---------------------------------------
 *
 * Latency groups are defined in the sun4v achitecture by memory-latency-group
 * nodes in the Machine Description, as specified in FWARC/2007/260.  These
 * tie together cpu nodes and mblock nodes, and contain mask and match
 * properties that identify the portion of an mblock that belongs to the
 * lgroup.  Mask and match are defined in the Physical Address (PA) space,
 * but an mblock defines Real Addresses (RA).  To translate, the mblock
 * includes the property address-congruence-offset, hereafter referred to as
 * ra_to_pa.  A real address ra is a member of an lgroup if
 *
 *	(ra + mblock.ra_to_pa) & lgroup.mask == lgroup.match
 *
 * The MD is traversed, and information on all mblocks is kept in the array
 * mpo_mblock[].  Information on all CPUs, including which lgroup they map
 * to, is kept in the array mpo_cpu[].
 *
 * This implementation makes (and verifies) the simplifying assumption that
 * the mask bits are the same for all defined lgroups, and that all 1 bits in
 * the mask are contiguous.  Thus the number of lgroups is bounded by the
 * number of possible mask values, and the lgrp_handle_t is defined as the
 * mask value, shifted right to eliminate the 0 bit positions in mask.  The
 * masks and values are also referred to as "home bits" in the code.
 *
 * A mem_node is defined to be 1:1 with an lgrp_handle_t, thus each lgroup
 * has exactly 1 mem_node, and plat_pfn_to_mem_node() must find the mblock
 * containing a pfn, apply the mblock's ra_to_pa adjustment, and extract the
 * home bits.  This yields the mem_node.
 *
 * Interfaces
 * ----------
 *
 * This file exports the following entry points:
 *
 * plat_lgrp_init()
 * plat_build_mem_nodes()
 * plat_lgrp_cpu_to_hand()
 * plat_lgrp_latency()
 * plat_pfn_to_mem_node()
 *	These implement the usual platform lgroup interfaces.
 *
 * plat_rapfn_to_papfn()
 *	Recover the PA page coloring bits from an RA.
 *
 * plat_mem_node_iterator_init()
 *	Initialize an iterator to efficiently step through pages in a mem_node.
 *
 * plat_mem_node_intersect_range()
 *	Find the intersection with a mem_node.
 */

int	sun4v_mpo_enable = 1;
int	sun4v_mpo_debug = 0;
char	sun4v_mpo_status[256] = "";

/* Save CPU info from the MD and associate CPUs with lgroups */
static	struct cpu_md mpo_cpu[NCPU];

/* Save lgroup info from the MD */
#define	MAX_MD_LGROUPS 32
static	struct	lgrp_md mpo_lgroup[MAX_MD_LGROUPS];
static	int	n_lgrpnodes = 0;
static	int	n_locality_groups = 0;
static	int	max_locality_groups = 0;

/* Save mblocks from the MD */
#define	SMALL_MBLOCKS_COUNT	8
static 	struct	mblock_md *mpo_mblock;
static	struct 	mblock_md small_mpo_mblocks[SMALL_MBLOCKS_COUNT];
static	int	n_mblocks = 0;

/* Save mem_node stripes calculate from mblocks and lgroups. */
static mem_stripe_t *mem_stripes;
static	mem_stripe_t small_mem_stripes[SMALL_MBLOCKS_COUNT * MAX_MEM_NODES];
static	int 	mstripesz = 0;
static	int	n_mem_stripes = 0;
static	pfn_t	mnode_stride;	/* distance between stripes, start to start */
static	int	stripe_shift;	/* stride/stripes expressed as a shift */
static	pfn_t	mnode_pages;	/* mem_node stripe width */

/* Save home mask and shift used to calculate lgrp_handle_t values */
static	uint64_t home_mask = 0;
static	pfn_t	home_mask_pfn = 0;
static	int	home_mask_shift = 0;
static	uint_t	home_mask_pfn_shift = 0;

/* Save lowest and highest latencies found across all lgroups */
static	int	lower_latency = 0;
static	int	higher_latency = 0;

static	pfn_t	base_ra_to_pa_pfn = 0;	/* ra_to_pa for single mblock memory */

static	int	valid_pages(md_t *md, mde_cookie_t cpu0);
static	int	unique_home_mem_lg_count(uint64_t mem_lg_homeset);
static	int	fix_interleave(void);

/* Debug support */
#if defined(DEBUG) && !defined(lint)
#define	MPO_DEBUG(args...) if (sun4v_mpo_debug) printf(args)
#else
#define	MPO_DEBUG(...)
#endif	/* DEBUG */

/* Record status message, viewable from mdb */
#define	MPO_STATUS(args...) {						      \
	(void) snprintf(sun4v_mpo_status, sizeof (sun4v_mpo_status), args);   \
	MPO_DEBUG(sun4v_mpo_status);					      \
}

/*
 * Routine to read a uint64_t from a given md
 */
static	int64_t
get_int(md_t md, mde_cookie_t node, char *propname, uint64_t *val)
{
	int err = md_get_prop_val(md, node, propname, val);
	return (err);
}

static int
mblock_cmp(const void *a, const void *b)
{
	struct mblock_md *m1 = (struct mblock_md *)a;
	struct mblock_md *m2 = (struct mblock_md *)b;

	if (m1->base < m2->base)
		return (-1);
	else if (m1->base == m2->base)
		return (0);
	else
		return (1);
}

static void
mblock_sort(struct mblock_md *mblocks, int n)
{
	extern void qsort(void *, size_t, size_t,
	    int (*)(const void *, const void *));

	qsort(mblocks, n, sizeof (mblocks[0]), mblock_cmp);
}

static void
mpo_update_tunables(void)
{
	int i, ncpu_min;

	/*
	 * lgrp_expand_proc_thresh is the minimum load on the lgroups
	 * this process is currently running on before considering
	 *  expanding threads to another lgroup.
	 *
	 * lgrp_expand_proc_diff determines how much less the remote lgroup
	 *  must be loaded before expanding to it.
	 *
	 * On sun4v CMT processors, threads share a core pipeline, and
	 * at less than 100% utilization, best throughput is obtained by
	 * spreading threads across more cores, even if some are in a
	 * different lgroup.  Spread threads to a new lgroup if the
	 * current group is more than 50% loaded.  Because of virtualization,
	 * lgroups may have different numbers of CPUs, but the tunables
	 * apply to all lgroups, so find the smallest lgroup and compute
	 * 50% loading.
	 */

	ncpu_min = NCPU;
	for (i = 0; i < n_lgrpnodes; i++) {
		int ncpu = mpo_lgroup[i].ncpu;
		if (ncpu != 0 && ncpu < ncpu_min)
			ncpu_min = ncpu;
	}
	lgrp_expand_proc_thresh = ncpu_min * lgrp_loadavg_max_effect / 2;

	/* new home may only be half as loaded as the existing home to use it */
	lgrp_expand_proc_diff = lgrp_expand_proc_thresh / 2;

	lgrp_loadavg_tolerance = lgrp_loadavg_max_effect;
}

static mde_cookie_t
cpuid_to_cpunode(md_t *md, int cpuid)
{
	mde_cookie_t    rootnode, foundnode, *cpunodes;
	uint64_t	cpuid_prop;
	int 	n_cpunodes, i;

	if (md == NULL)
		return (MDE_INVAL_ELEM_COOKIE);

	rootnode = md_root_node(md);
	if (rootnode == MDE_INVAL_ELEM_COOKIE)
		return (MDE_INVAL_ELEM_COOKIE);

	n_cpunodes = md_alloc_scan_dag(md, rootnode, PROP_LG_CPU,
	    "fwd", &cpunodes);
	if (n_cpunodes <= 0 || n_cpunodes > NCPU)
		goto cpuid_fail;

	for (i = 0; i < n_cpunodes; i++) {
		if (md_get_prop_val(md, cpunodes[i], PROP_LG_CPU_ID,
		    &cpuid_prop))
			break;
		if (cpuid_prop == (uint64_t)cpuid) {
			foundnode = cpunodes[i];
			md_free_scan_dag(md, &cpunodes);
			return (foundnode);
		}
	}
cpuid_fail:
	if (n_cpunodes > 0)
		md_free_scan_dag(md, &cpunodes);
	return (MDE_INVAL_ELEM_COOKIE);
}

static int
mpo_cpu_to_lgroup(md_t *md, mde_cookie_t cpunode)
{
	mde_cookie_t *nodes;
	uint64_t latency, lowest_latency;
	uint64_t address_match, lowest_address_match;
	int n_lgroups, j, result = 0;

	/* Find lgroup nodes reachable from this cpu */
	n_lgroups = md_alloc_scan_dag(md, cpunode, PROP_LG_MEM_LG,
	    "fwd", &nodes);

	lowest_latency = ~(0UL);

	/* Find the lgroup node with the smallest latency */
	for (j = 0; j < n_lgroups; j++) {
		result = get_int(md, nodes[j], PROP_LG_LATENCY,
		    &latency);
		result |= get_int(md, nodes[j], PROP_LG_MATCH,
		    &address_match);
		if (result != 0) {
			j = -1;
			goto to_lgrp_done;
		}
		if (latency < lowest_latency) {
			lowest_latency = latency;
			lowest_address_match = address_match;
		}
	}
	for (j = 0; j < n_lgrpnodes; j++) {
		if ((mpo_lgroup[j].latency == lowest_latency) &&
		    (mpo_lgroup[j].addr_match == lowest_address_match))
			break;
	}
	if (j == n_lgrpnodes)
		j = -1;

to_lgrp_done:
	if (n_lgroups > 0)
		md_free_scan_dag(md, &nodes);
	return (j);
}

/* Called when DR'ing in a CPU */
void
mpo_cpu_add(int cpuid)
{
	md_t *md;
	mde_cookie_t cpunode;

	int i;

	if (n_lgrpnodes <= 0)
		return;

	md = md_get_handle();

	if (md == NULL)
		goto add_fail;

	cpunode = cpuid_to_cpunode(md, cpuid);
	if (cpunode == MDE_INVAL_ELEM_COOKIE)
		goto add_fail;

	i = mpo_cpu_to_lgroup(md, cpunode);
	if (i == -1)
		goto add_fail;

	mpo_cpu[cpuid].lgrp_index = i;
	mpo_cpu[cpuid].home = mpo_lgroup[i].addr_match >> home_mask_shift;
	mpo_lgroup[i].ncpu++;
	mpo_update_tunables();
	(void) md_fini_handle(md);
	return;
add_fail:
	panic("mpo_cpu_add: Cannot read MD");
}

/* Called when DR'ing out a CPU */
void
mpo_cpu_remove(int cpuid)
{
	int i;

	if (n_lgrpnodes <= 0)
		return;

	i = mpo_cpu[cpuid].lgrp_index;
	mpo_lgroup[i].ncpu--;
	mpo_cpu[cpuid].home = 0;
	mpo_cpu[cpuid].lgrp_index = -1;
	mpo_update_tunables();
}

/*
 *
 * Traverse the MD to determine:
 *
 *  Number of CPU nodes, lgrp_nodes, and mblocks
 *  Then for each lgrp_node, obtain the appropriate data.
 *  For each CPU, determine its home locality and store it.
 *  For each mblock, retrieve its data and store it.
 */
static	int
lgrp_traverse(md_t *md)
{
	mde_cookie_t root, *cpunodes, *lgrpnodes, *nodes, *mblocknodes;
	uint64_t i, j, k, o, n_nodes;
	uint64_t mem_lg_homeset = 0;
	int ret_val = 0;
	int result = 0;
	int n_cpunodes = 0;
	int sub_page_fix;
	int mblocksz = 0;
	size_t allocsz;

	n_nodes = md_node_count(md);

	if (n_nodes <= 0) {
		MPO_STATUS("lgrp_traverse: No nodes in node count\n");
		ret_val = -1;
		goto fail;
	}

	root = md_root_node(md);

	if (root == MDE_INVAL_ELEM_COOKIE) {
		MPO_STATUS("lgrp_traverse: Root node is missing\n");
		ret_val = -1;
		goto fail;
	}

	/*
	 * Build the Memory Nodes.  Do this before any possibility of
	 * bailing from this routine so we obtain ra_to_pa (needed for page
	 * coloring) even when there are no lgroups defined.
	 */

	n_mblocks = md_alloc_scan_dag(md, root, PROP_LG_MBLOCK,
	    "fwd", &mblocknodes);

	if (n_mblocks <= 0) {
		MPO_STATUS("lgrp_traverse: No mblock "
		    "nodes detected in Machine Descriptor\n");
		n_mblocks = 0;
		ret_val = -1;
		goto fail;
	}
	/*
	 * If we have a small number of mblocks we will use the space
	 * that we preallocated. Otherwise, we will dynamically
	 * allocate the space
	 */
	mblocksz = n_mblocks * sizeof (struct mblock_md);
	mstripesz = MAX_MEM_NODES * n_mblocks * sizeof (mem_stripe_t);

	if (n_mblocks <= SMALL_MBLOCKS_COUNT) {
		mpo_mblock = &small_mpo_mblocks[0];
		mem_stripes = &small_mem_stripes[0];
	} else {
		allocsz = mmu_ptob(mmu_btopr(mblocksz + mstripesz));
	/* Ensure that we dont request more space than reserved */
		if (allocsz > MPOBUF_SIZE) {
			MPO_STATUS("lgrp_traverse: Insufficient space "
			    "for mblock structures \n");
			ret_val = -1;
			n_mblocks = 0;
			goto fail;
		}
		mpo_mblock = (struct mblock_md *)
		    prom_alloc((caddr_t)MPOBUF_BASE, allocsz, PAGESIZE);
		if (mpo_mblock != (struct mblock_md *)MPOBUF_BASE) {
			MPO_STATUS("lgrp_traverse: Cannot allocate space "
			    "for mblocks \n");
			ret_val = -1;
			n_mblocks = 0;
			goto fail;
		}
		mpo_heap32_buf = (caddr_t)MPOBUF_BASE;
		mpo_heap32_bufsz = MPOBUF_SIZE;

		mem_stripes = (mem_stripe_t *)(mpo_mblock + n_mblocks);
	}
	for (i = 0; i < n_mblocks; i++) {
		mpo_mblock[i].node = mblocknodes[i];

		/* Without a base or size value we will fail */
		result = get_int(md, mblocknodes[i], PROP_LG_BASE,
		    &mpo_mblock[i].base);
		if (result < 0) {
			MPO_STATUS("lgrp_traverse: "
			    "PROP_LG_BASE is missing\n");
			n_mblocks = 0;
			ret_val = -1;
			goto fail;
		}

		result = get_int(md, mblocknodes[i], PROP_LG_SIZE,
		    &mpo_mblock[i].size);
		if (result < 0) {
			MPO_STATUS("lgrp_traverse: "
			    "PROP_LG_SIZE is missing\n");
			n_mblocks = 0;
			ret_val = -1;
			goto fail;
		}

		result = get_int(md, mblocknodes[i],
		    PROP_LG_RA_PA_OFFSET, &mpo_mblock[i].ra_to_pa);

		/* If we don't have an ra_pa_offset, just set it to 0 */
		if (result < 0)
			mpo_mblock[i].ra_to_pa = 0;

		MPO_DEBUG("mblock[%ld]: base = %lx, size = %lx, "
		    "ra_to_pa = %lx\n", i,
		    mpo_mblock[i].base,
		    mpo_mblock[i].size,
		    mpo_mblock[i].ra_to_pa);
	}

	/* Must sort mblocks by address for mem_node_iterator_init() */
	mblock_sort(mpo_mblock, n_mblocks);

	base_ra_to_pa_pfn = btop(mpo_mblock[0].ra_to_pa);

	/* Page coloring hook is required so we can iterate through mnodes */
	if (&page_next_pfn_for_color_cpu == NULL) {
		MPO_STATUS("lgrp_traverse: No page coloring support\n");
		ret_val = -1;
		goto fail;
	}

	/* Global enable for mpo */
	if (sun4v_mpo_enable == 0) {
		MPO_STATUS("lgrp_traverse: MPO feature is not enabled\n");
		ret_val = -1;
		goto fail;
	}

	n_lgrpnodes = md_alloc_scan_dag(md, root, PROP_LG_MEM_LG,
	    "fwd", &lgrpnodes);

	if (n_lgrpnodes <= 0 || n_lgrpnodes >= MAX_MD_LGROUPS) {
		MPO_STATUS("lgrp_traverse: No Lgroups\n");
		ret_val = -1;
		goto fail;
	}

	n_cpunodes = md_alloc_scan_dag(md, root, PROP_LG_CPU, "fwd", &cpunodes);

	if (n_cpunodes <= 0 || n_cpunodes > NCPU) {
		MPO_STATUS("lgrp_traverse: No CPU nodes detected "
		    "in MD\n");
		ret_val = -1;
		goto fail;
	}

	MPO_DEBUG("lgrp_traverse: Node Count: %ld\n", n_nodes);
	MPO_DEBUG("lgrp_traverse: md: %p\n", md);
	MPO_DEBUG("lgrp_traverse: root: %lx\n", root);
	MPO_DEBUG("lgrp_traverse: mem_lgs: %d\n", n_lgrpnodes);
	MPO_DEBUG("lgrp_traverse: cpus: %d\n", n_cpunodes);
	MPO_DEBUG("lgrp_traverse: mblocks: %d\n", n_mblocks);

	for (i = 0; i < n_lgrpnodes; i++) {
		mpo_lgroup[i].node = lgrpnodes[i];
		mpo_lgroup[i].id = i;
		mpo_lgroup[i].ncpu = 0;
		result = get_int(md, lgrpnodes[i], PROP_LG_MASK,
		    &mpo_lgroup[i].addr_mask);
		result |= get_int(md, lgrpnodes[i], PROP_LG_MATCH,
		    &mpo_lgroup[i].addr_match);

		/*
		 * If either the mask or match properties are missing, set to 0
		 */
		if (result < 0) {
			mpo_lgroup[i].addr_mask = 0;
			mpo_lgroup[i].addr_match = 0;
		}

		/* Set latency to 0 if property not present */

		result = get_int(md, lgrpnodes[i], PROP_LG_LATENCY,
		    &mpo_lgroup[i].latency);
		if (result < 0)
			mpo_lgroup[i].latency = 0;
	}

	/*
	 * Sub-page level interleave is not yet supported.  Check for it,
	 * and remove sub-page interleaved lgroups from mpo_lgroup and
	 * n_lgrpnodes.  If no lgroups are left, return.
	 */

	sub_page_fix = fix_interleave();
	if (n_lgrpnodes == 0) {
		ret_val = -1;
		goto fail;
	}

	/* Ensure that all of the addr_mask values are the same */

	for (i = 0; i < n_lgrpnodes; i++) {
		if (mpo_lgroup[0].addr_mask != mpo_lgroup[i].addr_mask) {
			MPO_STATUS("lgrp_traverse: "
			    "addr_mask values are not the same\n");
			ret_val = -1;
			goto fail;
		}
	}

	/*
	 * Ensure that all lgrp nodes see all the mblocks. However, if
	 * sub-page interleave is being fixed, they do not, so skip
	 * the check.
	 */

	if (sub_page_fix == 0) {
		for (i = 0; i < n_lgrpnodes; i++) {
			j = md_alloc_scan_dag(md, mpo_lgroup[i].node,
			    PROP_LG_MBLOCK, "fwd", &nodes);
			md_free_scan_dag(md, &nodes);
			if (j != n_mblocks) {
				MPO_STATUS("lgrp_traverse: "
				    "sub-page interleave is being fixed\n");
				ret_val = -1;
				goto fail;
			}
		}
	}

	/*
	 * Use the address mask from the first lgroup node
	 * to establish our home_mask.
	 */
	home_mask = mpo_lgroup[0].addr_mask;
	home_mask_pfn = btop(home_mask);
	home_mask_shift = lowbit(home_mask) - 1;
	home_mask_pfn_shift = home_mask_shift - PAGESHIFT;
	mnode_pages = btop(1ULL << home_mask_shift);

	/*
	 * How many values are possible in home mask?  Assume the mask
	 * bits are contiguous.
	 */
	max_locality_groups =
	    1 << highbit(home_mask_pfn >> home_mask_pfn_shift);

	/* Now verify the home mask bits are contiguous */

	if (max_locality_groups - 1 != home_mask_pfn >> home_mask_pfn_shift) {
		MPO_STATUS("lgrp_traverse: "
		    "home mask bits are not contiguous\n");
		ret_val = -1;
		goto fail;
	}

	/* Record all of the home bits */

	for (i = 0; i < n_lgrpnodes; i++) {
		HOMESET_ADD(mem_lg_homeset,
		    mpo_lgroup[i].addr_match >> home_mask_shift);
	}

	/* Count the number different "home"  mem_lg's we've discovered */

	n_locality_groups = unique_home_mem_lg_count(mem_lg_homeset);

	/* If we have only 1 locality group then we can exit */
	if (n_locality_groups == 1) {
		MPO_STATUS("lgrp_traverse: n_locality_groups == 1\n");
		ret_val = -1;
		goto fail;
	}

	/*
	 * Set the latencies.  A CPU's lgroup is defined by the lowest
	 * latency found.  All other memory is considered remote, and the
	 * remote latency is represented by the highest latency found.
	 * Thus hierarchical lgroups, if any, are approximated by a
	 * two level scheme.
	 *
	 * The Solaris MPO framework by convention wants to see latencies
	 * in units of nano-sec/10. In the MD, the units are defined to be
	 * pico-seconds.
	 */

	lower_latency = mpo_lgroup[0].latency;
	higher_latency = mpo_lgroup[0].latency;

	for (i = 1; i < n_lgrpnodes; i++) {
		if (mpo_lgroup[i].latency < lower_latency) {
			lower_latency = mpo_lgroup[i].latency;
		}
		if (mpo_lgroup[i].latency > higher_latency) {
			higher_latency = mpo_lgroup[i].latency;
		}
	}
	lower_latency /= 10000;
	higher_latency /= 10000;

	/* Clear our CPU data */

	for (i = 0; i < NCPU; i++) {
		mpo_cpu[i].home = 0;
		mpo_cpu[i].lgrp_index = -1;
	}

	/* Build the CPU nodes */
	for (i = 0; i < n_cpunodes; i++) {

		/* Read in the lgroup nodes */
		result = get_int(md, cpunodes[i], PROP_LG_CPU_ID, &k);
		if (result < 0) {
			MPO_STATUS("lgrp_traverse: PROP_LG_CPU_ID missing\n");
			ret_val = -1;
			goto fail;
		}

		o = mpo_cpu_to_lgroup(md, cpunodes[i]);
		if (o == -1) {
			ret_val = -1;
			goto fail;
		}
		mpo_cpu[k].lgrp_index = o;
		mpo_cpu[k].home = mpo_lgroup[o].addr_match >> home_mask_shift;
		mpo_lgroup[o].ncpu++;
	}
	/* Validate that no large pages cross mnode boundaries. */
	if (valid_pages(md, cpunodes[0]) == 0) {
		ret_val = -1;
		goto fail;
	}

fail:
	/* MD cookies are no longer valid; ensure they are not used again. */
	for (i = 0; i < n_mblocks; i++)
		mpo_mblock[i].node = MDE_INVAL_ELEM_COOKIE;
	for (i = 0; i < n_lgrpnodes; i++)
		mpo_lgroup[i].node = MDE_INVAL_ELEM_COOKIE;

	if (n_cpunodes > 0)
		md_free_scan_dag(md, &cpunodes);
	if (n_lgrpnodes > 0)
		md_free_scan_dag(md, &lgrpnodes);
	if (n_mblocks > 0)
		md_free_scan_dag(md, &mblocknodes);
	else
		panic("lgrp_traverse: No memory blocks found");

	if (ret_val == 0)
		MPO_STATUS("MPO feature is enabled.\n");

	return (ret_val);
}

/*
 *  Determine the number of unique mem_lg's present in our system
 */
static	int
unique_home_mem_lg_count(uint64_t mem_lg_homeset)
{
	int homeid;
	int count = 0;

	/*
	 * Scan the "home" bits of the mem_lgs, count
	 * the number that are unique.
	 */

	for (homeid = 0; homeid < NLGRPS_MAX; homeid++) {
		if (MEM_LG_ISMEMBER(mem_lg_homeset, homeid)) {
			count++;
		}
	}

	MPO_DEBUG("unique_home_mem_lg_count: homeset %lx\n",
	    mem_lg_homeset);
	MPO_DEBUG("unique_home_mem_lg_count: count: %d\n", count);

	/* Default must be at least one */
	if (count == 0)
		count = 1;

	return (count);
}

/*
 * Platform specific lgroup initialization
 */
void
plat_lgrp_init(void)
{
	md_t *md;
	int rc;

	/* Get the Machine Descriptor handle */

	md = md_get_handle();

	/* If not, we cannot continue */

	if (md == NULL) {
		panic("cannot access machine descriptor\n");
	} else {
		rc = lgrp_traverse(md);
		(void) md_fini_handle(md);
	}

	/*
	 * If we can't process the MD for lgroups then at least let the
	 * system try to boot.  Assume we have one lgroup so that
	 * when plat_build_mem_nodes is called, it will attempt to init
	 * an mnode based on the supplied memory segment.
	 */

	if (rc == -1) {
		home_mask_pfn = 0;
		max_locality_groups = 1;
		n_locality_groups = 1;
		return;
	}

	mem_node_pfn_shift = 0;
	mem_node_physalign = 0;

	/* Use lgroup-aware TSB allocations */
	tsb_lgrp_affinity = 1;

	/* Require that a home lgroup have some memory to be chosen */
	lgrp_mem_free_thresh = 1;

	/* Standard home-on-next-touch policy */
	lgrp_mem_policy_root = LGRP_MEM_POLICY_NEXT;

	/* Disable option to choose root lgroup if all leaf lgroups are busy */
	lgrp_load_thresh = UINT32_MAX;

	mpo_update_tunables();
}

/*
 *  Helper routine for debugging calls to mem_node_add_slice()
 */
static	void
mpo_mem_node_add_slice(pfn_t basepfn, pfn_t endpfn)
{
#if defined(DEBUG) && !defined(lint)
	static int slice_count = 0;

	slice_count++;
	MPO_DEBUG("mem_add_slice(%d): basepfn: %lx  endpfn: %lx\n",
	    slice_count, basepfn, endpfn);
#endif
	mem_node_add_slice(basepfn, endpfn);
}

/*
 *  Helper routine for debugging calls to plat_assign_lgrphand_to_mem_node()
 */
static	void
mpo_plat_assign_lgrphand_to_mem_node(lgrp_handle_t plathand, int mnode)
{
	MPO_DEBUG("plat_assign_to_mem_nodes: lgroup home %ld,"
	    "mnode index: %d\n", plathand, mnode);
	plat_assign_lgrphand_to_mem_node(plathand, mnode);
}

/*
 * plat_build_mem_nodes()
 *
 * Define the mem_nodes based on the modified boot memory list,
 * or based on info read from the MD in plat_lgrp_init().
 *
 * When the home mask lies in the middle of the address bits (as it does on
 * Victoria Falls), then the memory in one mem_node is no longer contiguous;
 * it is striped across an mblock in a repeating pattern of contiguous memory
 * followed by a gap.  The stripe width is the size of the contiguous piece.
 * The stride is the distance from the start of one contiguous piece to the
 * start of the next.  The gap is thus stride - stripe_width.
 *
 * The stripe of an mnode that falls within an mblock is described by the type
 * mem_stripe_t, and there is one mem_stripe_t per mnode per mblock.  The
 * mem_stripe_t's are kept in a global array mem_stripes[].  The index into
 * this array is predetermined.  The mem_stripe_t that describes mnode m
 * within mpo_mblock[i] is stored at
 *	 mem_stripes[ m + i * max_locality_groups ]
 *
 * max_locality_groups is the total number of possible locality groups,
 * as defined by the size of the home mask, even if the memory assigned
 * to the domain is small and does not cover all the lgroups.  Thus some
 * mem_stripe_t's may be empty.
 *
 * The members of mem_stripe_t are:
 *	physbase: First valid page in mem_node in the corresponding mblock
 *	physmax: Last valid page in mem_node in mblock
 *	offset:  The full stripe width starts at physbase - offset.
 *	    Thus if offset is non-zero, this mem_node starts in the middle
 *	    of a stripe width, and the second full stripe starts at
 *	    physbase - offset + stride.  (even though physmax may fall in the
 *	    middle of a stripe width, we do not save the ending fragment size
 *	    in this data structure.)
 *	exists: Set to 1 if the mblock has memory in this mem_node stripe.
 *
 *	The stripe width is kept in the global mnode_pages.
 *	The stride is kept in the global mnode_stride.
 *	All the above use pfn's as the unit.
 *
 * As an example, the memory layout for a domain with 2 mblocks and 4
 * mem_nodes 0,1,2,3 could look like this:
 *
 *	123012301230 ...	012301230123 ...
 *	  mblock 0		  mblock 1
 */

void
plat_build_mem_nodes(prom_memlist_t *list, size_t nelems)
{
	lgrp_handle_t lgrphand, lgrp_start;
	int i, mnode, elem;
	uint64_t offset, stripe_end, base, len, end, ra_to_pa, stride;
	uint64_t stripe, frag, remove;
	mem_stripe_t *ms;

	/* Pre-reserve space for plat_assign_lgrphand_to_mem_node */
	max_mem_nodes = max_locality_groups;

	/* Check for non-MPO sun4v platforms */
	if (n_locality_groups <= 1) {
		mpo_plat_assign_lgrphand_to_mem_node(LGRP_DEFAULT_HANDLE, 0);
		for (elem = 0; elem < nelems; list++, elem++) {
			base = list->addr;
			len = list->size;

			mpo_mem_node_add_slice(btop(base),
			    btop(base + len - 1));
		}
		mem_node_pfn_shift = 0;
		mem_node_physalign = 0;
		n_mem_stripes = 0;
		if (n_mblocks == 1)
			return;
	}

	bzero(mem_stripes, mstripesz);
	stripe = ptob(mnode_pages);
	stride = max_locality_groups * stripe;

	/* Save commonly used values in globals */
	mnode_stride = btop(stride);
	n_mem_stripes = max_locality_groups * n_mblocks;
	stripe_shift = highbit(max_locality_groups) - 1;

	for (i = 0; i < n_mblocks; i++) {
		mpo_mblock[i].mnode_mask = (mnodeset_t)0;
		base = mpo_mblock[i].base;
		end = mpo_mblock[i].base + mpo_mblock[i].size;
		ra_to_pa = mpo_mblock[i].ra_to_pa;
		mpo_mblock[i].base_pfn = btop(base);
		mpo_mblock[i].end_pfn = btop(end - 1);

		/* Find the offset from the prev stripe boundary in PA space. */
		offset = (base + ra_to_pa) & (stripe - 1);

		/* Set the next stripe boundary. */
		stripe_end = base - offset + stripe;

		lgrp_start = (((base + ra_to_pa) & home_mask) >>
		    home_mask_shift);
		lgrphand = lgrp_start;

		/*
		 * Loop over all lgroups covered by the mblock, creating a
		 * stripe for each.  Stop when lgrp_start is visited again.
		 */
		do {
			/* mblock may not span all lgroups */
			if (base >= end)
				break;

			mnode = lgrphand;
			ASSERT(mnode < max_mem_nodes);
			mpo_mblock[i].mnode_mask |= (mnodeset_t)1 << mnode;

			/*
			 * Calculate the size of the fragment that does not
			 * belong to the mnode in the last partial stride.
			 */
			frag = (end - (base - offset)) & (stride - 1);
			if (frag == 0) {
				/* remove the gap */
				remove = stride - stripe;
			} else if (frag < stripe) {
				/* fragment fits in stripe; keep it all */
				remove = 0;
			} else {
				/* fragment is large; trim after whole stripe */
				remove = frag - stripe;
			}

			ms = &mem_stripes[i * max_locality_groups + mnode];
			ms->physbase = btop(base);
			ms->physmax = btop(end - 1 - remove);
			ms->offset = btop(offset);
			ms->exists = 1;

			/*
			 * If we have only 1 lgroup and multiple mblocks,
			 * then we have already established our lgrp handle
			 * to mem_node and mem_node_config values above.
			 */
			if (n_locality_groups > 1) {
				mpo_plat_assign_lgrphand_to_mem_node(lgrphand,
				    mnode);
				mpo_mem_node_add_slice(ms->physbase,
				    ms->physmax);
			}
			base = stripe_end;
			stripe_end += stripe;
			offset = 0;
			lgrphand = (((base + ra_to_pa) & home_mask) >>
			    home_mask_shift);
		} while (lgrphand != lgrp_start);
	}

	/*
	 * Indicate to vm_pagelist that the hpm_counters array
	 * should be shared because the ranges overlap.
	 */
	if (max_mem_nodes > 1) {
		interleaved_mnodes = 1;
	}
}

/*
 * Return the locality group value for the supplied processor
 */
lgrp_handle_t
plat_lgrp_cpu_to_hand(processorid_t id)
{
	if (n_locality_groups > 1) {
		return ((lgrp_handle_t)mpo_cpu[(int)id].home);
	} else {
		return ((lgrp_handle_t)LGRP_DEFAULT_HANDLE); /* Default */
	}
}

int
plat_lgrp_latency(lgrp_handle_t from, lgrp_handle_t to)
{
	/*
	 * Return min remote latency when there are more than two lgroups
	 * (root and child) and getting latency between two different lgroups
	 * or root is involved.
	 */
	if (lgrp_optimizations() && (from != to ||
	    from == LGRP_DEFAULT_HANDLE || to == LGRP_DEFAULT_HANDLE)) {
		return ((int)higher_latency);
	} else {
		return ((int)lower_latency);
	}
}

int
plat_pfn_to_mem_node(pfn_t pfn)
{
	int i, mnode;
	pfn_t ra_to_pa_pfn;
	struct mblock_md *mb;

	if (n_locality_groups <= 1)
		return (0);

	/*
	 * The mnode is defined to be 1:1 with the lgroup handle, which
	 * is taken from from the home bits.  Find the mblock in which
	 * the pfn falls to get the ra_to_pa adjustment, and extract
	 * the home bits.
	 */
	mb = &mpo_mblock[0];
	for (i = 0; i < n_mblocks; i++) {
		if (pfn >= mb->base_pfn && pfn <= mb->end_pfn) {
			ra_to_pa_pfn = btop(mb->ra_to_pa);
			mnode = (((pfn + ra_to_pa_pfn) & home_mask_pfn) >>
			    home_mask_pfn_shift);
			ASSERT(mnode < max_mem_nodes);
			return (mnode);
		}
		mb++;
	}

	panic("plat_pfn_to_mem_node() failed to find mblock: pfn=%lx\n", pfn);
	return (pfn);
}

/*
 * plat_rapfn_to_papfn
 *
 * Convert a pfn in RA space to a pfn in PA space, in which the page coloring
 * and home mask bits are correct.  The upper bits do not necessarily
 * match the actual PA, however.
 */
pfn_t
plat_rapfn_to_papfn(pfn_t pfn)
{
	int i;
	pfn_t ra_to_pa_pfn;
	struct mblock_md *mb;

	ASSERT(n_mblocks > 0);
	if (n_mblocks == 1)
		return (pfn + base_ra_to_pa_pfn);

	/*
	 * Find the mblock in which the pfn falls
	 * in order to get the ra_to_pa adjustment.
	 */
	for (mb = &mpo_mblock[0], i = 0; i < n_mblocks; i++, mb++) {
		if (pfn <= mb->end_pfn && pfn >= mb->base_pfn) {
			ra_to_pa_pfn = btop(mb->ra_to_pa);
			return (pfn + ra_to_pa_pfn);
		}
	}

	panic("plat_rapfn_to_papfn() failed to find mblock: pfn=%lx\n", pfn);
	return (pfn);
}

/*
 * plat_mem_node_iterator_init()
 *	Initialize cookie to iterate over pfn's in an mnode.  There is
 *	no additional iterator function.  The caller uses the info from
 *	the iterator structure directly.
 *
 *	pfn: starting pfn.
 * 	mnode: desired mnode.
 *	init: set to 1 for full init, 0 for continuation
 *
 *	Returns the appropriate starting pfn for the iteration
 *	the same as the input pfn if it falls in an mblock.
 *	Returns the (pfn_t)-1 value if the input pfn lies past
 *	the last valid mnode pfn.
 */
pfn_t
plat_mem_node_iterator_init(pfn_t pfn, int mnode,
    mem_node_iterator_t *it, int init)
{
	int i;
	struct mblock_md *mblock;
	pfn_t base, end;

	ASSERT(it != NULL);
	ASSERT(mnode >= 0 && mnode < max_mem_nodes);
	ASSERT(n_mblocks > 0);

	if (init) {
		it->mi_last_mblock = 0;
		it->mi_init = 1;
	}

	/* Check if mpo is not enabled and we only have one mblock */
	if (n_locality_groups == 1 && n_mblocks == 1) {
		it->mi_mnode = mnode;
		it->mi_ra_to_pa = base_ra_to_pa_pfn;
		it->mi_mnode_pfn_mask = 0;
		it->mi_mnode_pfn_shift = 0;
		it->mi_mnode_mask = 0;
		it->mi_mblock_base = mem_node_config[mnode].physbase;
		it->mi_mblock_end = mem_node_config[mnode].physmax;
		if (pfn < it->mi_mblock_base)
			pfn = it->mi_mblock_base;
		else if (pfn > it->mi_mblock_end)
			pfn = (pfn_t)-1;
		return (pfn);
	}

	/*
	 * Find mblock that contains pfn, or first mblock after pfn,
	 * else pfn is out of bounds, so use the last mblock.
	 * mblocks are sorted in ascending address order.
	 */
	ASSERT(it->mi_last_mblock < n_mblocks);
	ASSERT(init == 1 || pfn > mpo_mblock[it->mi_last_mblock].end_pfn);
	i = init ? 0 : it->mi_last_mblock + 1;
	if (i == n_mblocks)
		return ((pfn_t)-1);

	for (; i < n_mblocks; i++) {
		if ((mpo_mblock[i].mnode_mask & ((mnodeset_t)1 << mnode)) &&
		    (pfn <= mpo_mblock[i].end_pfn))
			break;
	}
	if (i == n_mblocks) {
		it->mi_last_mblock = i - 1;
		return ((pfn_t)-1);
	}
	it->mi_last_mblock = i;

	/*
	 * Memory stripes are defined if there is more than one locality
	 * group, so use the stripe bounds.  Otherwise use mblock bounds.
	 */
	mblock = &mpo_mblock[i];
	if (n_mem_stripes > 0) {
		mem_stripe_t *ms =
		    &mem_stripes[i * max_locality_groups + mnode];
		base = ms->physbase;
		end = ms->physmax;
	} else {
		ASSERT(mnode == 0);
		base = mblock->base_pfn;
		end = mblock->end_pfn;
	}

	it->mi_mnode = mnode;
	it->mi_ra_to_pa = btop(mblock->ra_to_pa);
	it->mi_mblock_base = base;
	it->mi_mblock_end = end;
	it->mi_mnode_pfn_mask = home_mask_pfn;	/* is 0 for non-MPO case */
	it->mi_mnode_pfn_shift = home_mask_pfn_shift;
	it->mi_mnode_mask = max_locality_groups - 1;
	if (pfn < base)
		pfn = base;
	else if (pfn > end)
		pfn = (pfn_t)-1;
	return (pfn);
}

/*
 * plat_mem_node_intersect_range()
 *
 * Find the intersection between a memnode and a range of pfn's.
 */
void
plat_mem_node_intersect_range(pfn_t test_base, pgcnt_t test_len,
    int mnode, pgcnt_t *npages_out)
{
	pfn_t offset, len, hole, base, end, test_end, frag;
	pfn_t nearest;
	mem_stripe_t *ms;
	int i, npages;

	*npages_out = 0;

	if (!mem_node_config[mnode].exists || test_len == 0)
		return;

	base = mem_node_config[mnode].physbase;
	end = mem_node_config[mnode].physmax;

	test_end = test_base + test_len - 1;
	if (end < test_base || base > test_end)
		return;

	if (n_locality_groups == 1) {
		*npages_out = MIN(test_end, end) - MAX(test_base, base) + 1;
		return;
	}

	hole = mnode_stride - mnode_pages;
	npages = 0;

	/*
	 * Iterate over all the stripes for this mnode (one per mblock),
	 * find the intersection with each, and accumulate the intersections.
	 *
	 * Determing the intersection with a stripe is tricky.  If base or end
	 * fall outside the mem_node bounds, round them to physbase/physmax of
	 * mem_node.  If base or end fall in a gap, round them to start of
	 * nearest stripe.  If they fall within a stripe, keep base or end,
	 * but calculate the fragment size that should be excluded from the
	 * stripe.  Calculate how many strides fall in the adjusted range,
	 * multiply by stripe width, and add the start and end fragments.
	 */

	for (i = mnode; i < n_mem_stripes; i += max_locality_groups) {
		ms = &mem_stripes[i];
		if (ms->exists &&
		    test_base <= (end = ms->physmax) &&
		    test_end >= (base = ms->physbase)) {

			offset = ms->offset;

			if (test_base > base) {
				/* Round test_base to next multiple of stride */
				len = P2ROUNDUP(test_base - (base - offset),
				    mnode_stride);
				nearest = base - offset + len;
				/*
				 * Compute distance from test_base to the
				 * stride boundary to see if test_base falls
				 * in the stripe or in the hole.
				 */
				if (nearest - test_base > hole) {
					/*
					 * test_base lies in stripe,
					 * and offset should be excluded.
					 */
					offset = test_base -
					    (nearest - mnode_stride);
					base = test_base;
				} else {
					/* round up to next stripe start */
					offset = 0;
					base = nearest;
					if (base > end)
						continue;
				}

			}

			if (test_end < end)
				end = test_end;
			end++;		/* adjust to an exclusive bound */

			/* Round end to next multiple of stride */
			len = P2ROUNDUP(end - (base - offset), mnode_stride);
			nearest = (base - offset) + len;
			if (nearest - end <= hole) {
				/* end falls in hole, use entire last stripe */
				frag = 0;
			} else {
				/* end falls in stripe, compute fragment */
				frag = nearest - hole - end;
			}

			len = (len >> stripe_shift) - offset - frag;
			npages += len;
		}
	}

	*npages_out = npages;
}

/*
 * valid_pages()
 *
 * Return 1 if pages are valid and do not cross mnode boundaries
 * (which would break page free list assumptions), and 0 otherwise.
 */

#define	MNODE(pa)	\
	((btop(pa) & home_mask_pfn) >> home_mask_pfn_shift)

static int
valid_pages(md_t *md, mde_cookie_t cpu0)
{
	int i, max_szc;
	uint64_t last_page_base, szc_mask;
	uint64_t max_page_len, max_coalesce_len;
	struct mblock_md *mb = mpo_mblock;

	/*
	 * Find the smaller of the largest page possible and supported.
	 * mmu_exported_pagesize_mask is not yet initialized, so read
	 * it from the MD.  Apply minimal fixups in case of broken MDs
	 * to get a sane mask.
	 */

	if (md_get_prop_val(md, cpu0, "mmu-page-size-list", &szc_mask))
		szc_mask = 0;
	szc_mask |=  (1 << TTE4M);	/* largest in sun4v default support */
	max_szc = highbit(szc_mask) - 1;
	if (max_szc > TTE256M)
		max_szc = TTE256M;
	max_page_len = TTEBYTES(max_szc);

	/*
	 * Page coalescing code coalesces all sizes up to 256M on sun4v, even
	 * if mmu-page-size-list does not contain it, so 256M pages must fall
	 * within one mnode to use MPO.
	 */
	max_coalesce_len = TTEBYTES(TTE256M);
	ASSERT(max_coalesce_len >= max_page_len);

	if (ptob(mnode_pages) < max_coalesce_len) {
		MPO_STATUS("Page too large; MPO disabled: page = %lx, "
		    "mnode slice = %lx\n", max_coalesce_len, ptob(mnode_pages));
		return (0);
	}

	for (i = 0; i < n_mblocks; i++) {
		uint64_t base = mb->base;
		uint64_t end = mb->base + mb->size - 1;
		uint64_t ra_to_pa = mb->ra_to_pa;

		/*
		 * If mblock is smaller than the max page size, then
		 * RA = PA mod MAXPAGE is not guaranteed, but it must
		 * not span mnodes.
		 */
		if (mb->size < max_page_len) {
			if (MNODE(base + ra_to_pa) != MNODE(end + ra_to_pa)) {
				MPO_STATUS("Small mblock spans mnodes; "
				    "MPO disabled: base = %lx, end = %lx, "
				    "ra2pa = %lx\n", base, end, ra_to_pa);
				return (0);
			}
		} else {
			/* Verify RA = PA mod MAXPAGE, using coalesce size */
			uint64_t pa_base = base + ra_to_pa;
			if ((base & (max_coalesce_len - 1)) !=
			    (pa_base & (max_coalesce_len - 1))) {
				MPO_STATUS("bad page alignment; MPO disabled: "
				    "ra = %lx, pa = %lx, pagelen = %lx\n",
				    base, pa_base, max_coalesce_len);
				return (0);
			}
		}

		/*
		 * Find start of last large page in mblock in RA space.
		 * If page extends into the next mblock, verify the
		 * mnode does not change.
		 */
		last_page_base = P2ALIGN(end, max_coalesce_len);
		if (i + 1 < n_mblocks &&
		    last_page_base + max_coalesce_len > mb[1].base &&
		    MNODE(last_page_base + ra_to_pa) !=
		    MNODE(mb[1].base + mb[1].ra_to_pa)) {
			MPO_STATUS("Large page spans mblocks; MPO disabled: "
			    "end = %lx, ra2pa = %lx, base = %lx, ra2pa = %lx, "
			    "pagelen = %lx\n", end, ra_to_pa, mb[1].base,
			    mb[1].ra_to_pa, max_coalesce_len);
			return (0);
		}

		mb++;
	}
	return (1);
}


/*
 * fix_interleave() - Find lgroups with sub-page sized memory interleave,
 * if any, and remove them.  This yields a config where the "coarse
 * grained" lgroups cover all of memory, even though part of that memory
 * is fine grain interleaved and does not deliver a purely local memory
 * latency.
 *
 * This function reads and modifies the globals:
 *	mpo_lgroup[], n_lgrpnodes
 *
 * Returns 1 if lgroup nodes were removed, 0 otherwise.
 */

static int
fix_interleave(void)
{
	int i, j;
	uint64_t mask = 0;

	j = 0;
	for (i = 0; i < n_lgrpnodes; i++) {
		if ((mpo_lgroup[i].addr_mask & PAGEOFFSET) != 0) {
			/* remove this lgroup */
			mask = mpo_lgroup[i].addr_mask;
		} else {
			mpo_lgroup[j++] = mpo_lgroup[i];
		}
	}
	n_lgrpnodes = j;

	if (mask != 0)
		MPO_STATUS("sub-page interleave %lx found; "
		    "removing lgroup.\n", mask);

	return (mask != 0);
}
