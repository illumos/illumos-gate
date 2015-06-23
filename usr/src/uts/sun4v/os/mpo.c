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
#include <vm/page.h>
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
 *
 * plat_slice_add()
 * plat_slice_del()
 *	Platform hooks to add/delete a pfn range.
 *
 * Internal Organization
 * ---------------------
 *
 * A number of routines are used both boot/DR code which (re)build
 * appropriate MPO structures.
 *
 * mblock_alloc()
 *	Allocate memory for mblocks and stripes as
 *	appropriate for boot or memory DR.
 *
 * mblock_free()
 *	Free memory allocated by mblock_alloc.
 *
 * mblock_update()
 *	Build mblocks based on mblock nodes read from the MD.
 *
 * mblock_update_add()
 *	Rebuild mblocks after a memory DR add operation.
 *
 * mblock_update_del()
 *	Rebuild mblocks after a memory DR delete operation.
 *
 * mblock_install()
 *	Install mblocks as the new configuration.
 *
 * mstripe_update()
 *	Build stripes based on mblocks.
 *
 * mnode_update()
 *	Call memnode layer to add/del a pfn range, based on stripes.
 *
 * The platform interfaces allocate all memory required for the
 * particualar update first, block access to the MPO structures
 * while they are updated, and free old structures after the update.
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
static	int	szc_mask0 = 0;

/* Save mblocks from the MD */
#define	SMALL_MBLOCKS_COUNT	8
static 	struct	mblock_md *mpo_mblock;
static	struct 	mblock_md small_mpo_mblocks[SMALL_MBLOCKS_COUNT];
static	int	n_mblocks = 0;

/* Save mem_node stripes calculate from mblocks and lgroups. */
static mem_stripe_t *mem_stripes;
static	mem_stripe_t small_mem_stripes[SMALL_MBLOCKS_COUNT * MAX_MEM_NODES];
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
static	int	mpo_genid;		/* config gen; updated by mem DR */
static	mpo_config_t mpo_config;	/* current mblocks and stripes */

typedef enum { U_ADD, U_ADD_ALL, U_DEL } update_t;

static	int	valid_pages(md_t *md, mde_cookie_t cpu0);
static	int	unique_home_mem_lg_count(uint64_t mem_lg_homeset);
static	int	fix_interleave(void);

static int  mblock_alloc(mpo_config_t *, update_t, int nmblocks);
static void mblock_install(mpo_config_t *);
static void mblock_free(mpo_config_t *);
static void mblock_update(mpo_config_t *, md_t, mde_cookie_t *mblocknodes);
static void mblock_update_add(mpo_config_t *);
static void mblock_update_del(mpo_config_t *, mpo_config_t *, pfn_t, pfn_t);
static void mstripe_update(mpo_config_t *);
static void mnode_update(mpo_config_t *, pfn_t, pfn_t, update_t);

/* Debug support */
#if defined(DEBUG) && !defined(lint)
#define	VALIDATE_SLICE(base, end) { 					\
	ASSERT(IS_P2ALIGNED(ptob(base), TTEBYTES(TTE256M)));		\
	ASSERT(IS_P2ALIGNED(ptob(end - base + 1), TTEBYTES(TTE256M)));	\
}
#define	MPO_DEBUG(args...) if (sun4v_mpo_debug) printf(args)
#else
#define	VALIDATE_SLICE(base, end)
#define	MPO_DEBUG(...)
#endif	/* DEBUG */

/* Record status message, viewable from mdb */
#define	MPO_STATUS(args...) {						      \
	(void) snprintf(sun4v_mpo_status, sizeof (sun4v_mpo_status), args);   \
	MPO_DEBUG(sun4v_mpo_status);					      \
}

/*
 * The MPO locks are to protect the MPO metadata while that
 * information is updated as a result of a memory DR operation.
 * The read lock must be acquired to read the metadata and the
 * write locks must be acquired to update it.
 */
#define	mpo_rd_lock	kpreempt_disable
#define	mpo_rd_unlock	kpreempt_enable

static void
mpo_wr_lock()
{
	mutex_enter(&cpu_lock);
	pause_cpus(NULL, NULL);
	mutex_exit(&cpu_lock);
}

static void
mpo_wr_unlock()
{
	mutex_enter(&cpu_lock);
	start_cpus();
	mutex_exit(&cpu_lock);
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
mpo_cpu_add(md_t *md, int cpuid)
{
	mde_cookie_t cpunode;

	int i;

	if (n_lgrpnodes <= 0)
		return;

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

static mde_cookie_t
md_get_root(md_t *md)
{
	mde_cookie_t root = MDE_INVAL_ELEM_COOKIE;
	int n_nodes;

	n_nodes = md_node_count(md);

	if (n_nodes <= 0) {
		MPO_STATUS("md_get_root: No nodes in node count\n");
		return (root);
	}

	root = md_root_node(md);

	if (root == MDE_INVAL_ELEM_COOKIE) {
		MPO_STATUS("md_get_root: Root node is missing\n");
		return (root);
	}

	MPO_DEBUG("md_get_root: Node Count: %d\n", n_nodes);
	MPO_DEBUG("md_get_root: md: %p\n", md);
	MPO_DEBUG("md_get_root: root: %lx\n", root);
done:
	return (root);
}

static int
lgrp_update(md_t *md, mde_cookie_t root)
{
	int i, j, result;
	int ret_val = 0;
	int sub_page_fix;
	mde_cookie_t *nodes, *lgrpnodes;

	n_lgrpnodes = md_alloc_scan_dag(md, root, PROP_LG_MEM_LG,
	    "fwd", &lgrpnodes);

	if (n_lgrpnodes <= 0 || n_lgrpnodes >= MAX_MD_LGROUPS) {
		MPO_STATUS("lgrp_update: No Lgroups\n");
		ret_val = -1;
		goto fail;
	}

	MPO_DEBUG("lgrp_update: mem_lgs: %d\n", n_lgrpnodes);

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
			MPO_STATUS("lgrp_update: "
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
				MPO_STATUS("lgrp_update: "
				    "sub-page interleave is being fixed\n");
				ret_val = -1;
				goto fail;
			}
		}
	}
fail:
	if (n_lgrpnodes > 0) {
		md_free_scan_dag(md, &lgrpnodes);
		for (i = 0; i < n_lgrpnodes; i++)
			mpo_lgroup[i].node = MDE_INVAL_ELEM_COOKIE;
	}

	return (ret_val);
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
	mde_cookie_t root, *cpunodes, *mblocknodes;
	int o;
	uint64_t i, k, stripe, stride;
	uint64_t mem_lg_homeset = 0;
	int ret_val = 0;
	int result = 0;
	int n_cpunodes = 0;
	mpo_config_t new_config;

	if ((root = md_get_root(md)) == MDE_INVAL_ELEM_COOKIE) {
		ret_val = -1;
		goto fail;
	}

	n_mblocks = md_alloc_scan_dag(md, root, PROP_LG_MBLOCK, "fwd",
	    &mblocknodes);
	if (n_mblocks <= 0) {
		MPO_STATUS("lgrp_traverse: No mblock nodes detected in Machine "
		    "Descriptor\n");
		ret_val = -1;
		goto fail;
	}

	/*
	 * Build the Memory Nodes.  Do this before any possibility of
	 * bailing from this routine so we obtain ra_to_pa (needed for page
	 * coloring) even when there are no lgroups defined.
	 */
	if (mblock_alloc(&new_config, U_ADD_ALL, n_mblocks) < 0) {
		ret_val = -1;
		goto fail;
	}

	mblock_update(&new_config, md, mblocknodes);
	mblock_install(&new_config);

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

	n_cpunodes = md_alloc_scan_dag(md, root, PROP_LG_CPU, "fwd", &cpunodes);

	if (n_cpunodes <= 0 || n_cpunodes > NCPU) {
		MPO_STATUS("lgrp_traverse: No CPU nodes detected "
		    "in MD\n");
		ret_val = -1;
		goto fail;
	}

	MPO_DEBUG("lgrp_traverse: cpus: %d\n", n_cpunodes);

	if ((ret_val = lgrp_update(md, root)) == -1)
		goto fail;

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

	stripe_shift = highbit(max_locality_groups) - 1;
	stripe = ptob(mnode_pages);
	stride = max_locality_groups * stripe;
	mnode_stride = btop(stride);

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
	if (n_cpunodes > 0)
		md_free_scan_dag(md, &cpunodes);
	if (n_mblocks > 0)
		md_free_scan_dag(md, &mblocknodes);
	else
		panic("lgrp_traverse: No memory blocks found");

	if (ret_val == 0) {
		MPO_STATUS("MPO feature is enabled.\n");
	} else
		sun4v_mpo_enable = 0;	/* set this for DR */

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

static	void
mpo_mem_node_del_slice(pfn_t basepfn, pfn_t endpfn)
{
#if defined(DEBUG) && !defined(lint)
	static int slice_count = 0;

	slice_count++;
	MPO_DEBUG("mem_del_slice(%d): basepfn: %lx  endpfn: %lx\n",
	    slice_count, basepfn, endpfn);
#endif
	mem_node_del_slice(basepfn, endpfn);
}

/*
 *  Helper routine for debugging calls to plat_assign_lgrphand_to_mem_node()
 */
static	void
mpo_plat_assign_lgrphand_to_mem_node(lgrp_handle_t plathand, int mnode)
{
	MPO_DEBUG("plat_assign_to_mem_nodes: lgroup home %ld, "
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

/*ARGSUSED*/
void
plat_build_mem_nodes(prom_memlist_t *list, size_t nelems)
{
	int elem;
	uint64_t base, len;

	/* Pre-reserve space for plat_assign_lgrphand_to_mem_node */
	max_mem_nodes = max_locality_groups;

	mstripe_update(&mpo_config);

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
	} else
		mnode_update(&mpo_config, 0, 0, U_ADD_ALL);

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
	lgrp_handle_t lgrphand;

	mpo_rd_lock();
	if (n_locality_groups > 1) {
		lgrphand = (lgrp_handle_t)mpo_cpu[(int)id].home;
	} else {
		lgrphand = (lgrp_handle_t)LGRP_DEFAULT_HANDLE; /* Default */
	}
	mpo_rd_unlock();

	return (lgrphand);
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
	mpo_rd_lock();
	mb = &mpo_mblock[0];
	for (i = 0; i < n_mblocks; i++) {
		if (pfn >= mb->base_pfn && pfn <= mb->end_pfn) {
			ra_to_pa_pfn = btop(mb->ra_to_pa);
			mnode = (((pfn + ra_to_pa_pfn) & home_mask_pfn) >>
			    home_mask_pfn_shift);
			ASSERT(mnode < max_mem_nodes);
			mpo_rd_unlock();
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
	mpo_rd_lock();
	for (mb = &mpo_mblock[0], i = 0; i < n_mblocks; i++, mb++) {
		if (pfn <= mb->end_pfn && pfn >= mb->base_pfn) {
			ra_to_pa_pfn = btop(mb->ra_to_pa);
			mpo_rd_unlock();
			return (pfn + ra_to_pa_pfn);
		}
	}

	panic("plat_rapfn_to_papfn() failed to find mblock: pfn=%lx\n", pfn);
	return (pfn);
}

/*
 * plat_mem_node_iterator_init()
 *      Initialize cookie "it" to iterate over pfn's in an mnode.  There is
 *      no additional iterator function.  The caller uses the info from
 *      the iterator structure directly.
 *
 *      pfn: starting pfn.
 *      mnode: desired mnode.
 *	szc: desired page size.
 *      init:
 *          if 1, start a new traversal, initialize "it", find first
 *              mblock containing pfn, and return its starting pfn
 *              within the mnode.
 *          if 0, continue the previous traversal using passed-in data
 *              from "it", advance to the next mblock, and return its
 *              starting pfn within the mnode.
 *      it: returns readonly data to the caller; see below.
 *
 *	The input pfn must be aligned for the page size szc.
 *
 *      Returns: starting pfn for the iteration for the mnode/mblock,
 *	    which is aligned according to the page size,
 *          or returns (pfn_t)(-1) if the input pfn lies past the last
 *          valid pfn of the mnode.
 *      Returns misc values in the "it" struct that allows the caller
 *          to advance the pfn within an mblock using address arithmetic;
 *          see definition of mem_node_iterator_t in vm_dep.h.
 *          When the caller calculates a pfn that is greater than the
 *          returned value it->mi_mblock_end, the caller should again
 *          call plat_mem_node_iterator_init, passing init=0.
 *
 *          The last mblock in continuation case may be invalid because
 *          of memory DR.  To detect this situation mi_genid is checked
 *          against mpo_genid which is incremented after a memory DR
 *          operation.  See also plat_slice_add()/plat_slice_del().
 */
pfn_t
plat_mem_node_iterator_init(pfn_t pfn, int mnode, uchar_t szc,
    mem_node_iterator_t *it, int init)
{
	int i;
	pgcnt_t szcpgcnt = PNUM_SIZE(szc);
	struct mblock_md *mblock;
	pfn_t base, end;
	mem_stripe_t *ms;
	uint64_t szcpagesize;

	ASSERT(it != NULL);
	ASSERT(mnode >= 0 && mnode < max_mem_nodes);
	ASSERT(n_mblocks > 0);
	ASSERT(P2PHASE(pfn, szcpgcnt) == 0);

	mpo_rd_lock();

	if (init || (it->mi_genid != mpo_genid)) {
		it->mi_genid = mpo_genid;
		it->mi_last_mblock = 0;
		it->mi_init = 1;
	}

	/* Check if mpo is not enabled and we only have one mblock */
	if (n_locality_groups == 1 && n_mblocks == 1) {
		if (P2PHASE(base_ra_to_pa_pfn, szcpgcnt)) {
			pfn = (pfn_t)-1;
			goto done;
		}
		it->mi_mnode = mnode;
		it->mi_ra_to_pa = base_ra_to_pa_pfn;
		it->mi_mnode_pfn_mask = 0;
		it->mi_mnode_pfn_shift = 0;
		it->mi_mnode_mask = 0;
		it->mi_mblock_base = mem_node_config[mnode].physbase;
		it->mi_mblock_end = mem_node_config[mnode].physmax;
		if (pfn < it->mi_mblock_base)
			pfn = P2ROUNDUP(it->mi_mblock_base, szcpgcnt);
		if ((pfn + szcpgcnt - 1) > it->mi_mblock_end)
			pfn = (pfn_t)-1;
		goto done;
	}

	/* init=1 means begin iterator, init=0 means continue */
	if (init == 1) {
		i = 0;
	} else {
		ASSERT(it->mi_last_mblock < n_mblocks);
		i = it->mi_last_mblock;
		ASSERT(pfn >
		    mem_stripes[i * max_locality_groups + mnode].physmax);
		if (++i == n_mblocks) {
			pfn = (pfn_t)-1;
			goto done;
		}
	}

	/*
	 * Find mblock that contains pfn for mnode's stripe, or first such an
	 * mblock after pfn, else pfn is out of bound and we'll return -1.
	 * mblocks and stripes are sorted in ascending address order.
	 */
	szcpagesize = szcpgcnt << PAGESHIFT;
	for (; i < n_mblocks; i++) {
		if (P2PHASE(mpo_mblock[i].ra_to_pa, szcpagesize))
			continue;
		ms = &mem_stripes[i * max_locality_groups + mnode];
		if (ms->exists && (pfn + szcpgcnt - 1) <= ms->physmax &&
		    (P2ROUNDUP(ms->physbase, szcpgcnt) + szcpgcnt - 1) <=
		    ms->physmax)
			break;
	}
	if (i == n_mblocks) {
		it->mi_last_mblock = i - 1;
		pfn = (pfn_t)-1;
		goto done;
	}

	it->mi_last_mblock = i;

	mblock = &mpo_mblock[i];
	base = ms->physbase;
	end = ms->physmax;

	it->mi_mnode = mnode;
	it->mi_ra_to_pa = btop(mblock->ra_to_pa);
	it->mi_mblock_base = base;
	it->mi_mblock_end = end;
	it->mi_mnode_pfn_mask = home_mask_pfn;	/* is 0 for non-MPO case */
	it->mi_mnode_pfn_shift = home_mask_pfn_shift;
	it->mi_mnode_mask = max_locality_groups - 1;
	if (pfn < base) {
		pfn = P2ROUNDUP(base, szcpgcnt);
		ASSERT(pfn + szcpgcnt - 1 <= end);
	}
	ASSERT((pfn + szcpgcnt - 1) <= mpo_mblock[i].end_pfn);
done:
	mpo_rd_unlock();
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

	mpo_rd_lock();
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
	mpo_rd_unlock();
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

	if (cpu0 == NULL)
		szc_mask = szc_mask0;
	else {
		if (md_get_prop_val(md, cpu0, "mmu-page-size-list", &szc_mask))
			szc_mask = 0;
		/* largest in sun4v default support */
		szc_mask |=  (1 << TTE4M);
		szc_mask0 = szc_mask;
	}
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

/*
 * mblock_alloc
 *
 * Allocate memory for mblock an stripe arrays from either static or
 * dynamic space depending on utype, and return the result in mc.
 * Returns 0 on success and -1 on error.
 */

static int
mblock_alloc(mpo_config_t *mc, update_t utype, int nmblocks)
{
	mblock_md_t *mb = NULL;
	mem_stripe_t *ms = NULL;
	int nstripes = MAX_MEM_NODES * nmblocks;
	size_t mblocksz = nmblocks * sizeof (struct mblock_md);
	size_t mstripesz = nstripes * sizeof (mem_stripe_t);
	size_t allocsz = mmu_ptob(mmu_btopr(mblocksz + mstripesz));

	/*
	 * Allocate space for mblocks and mstripes.
	 *
	 * For DR allocations, just use kmem_alloc(), and set
	 * mc_alloc_sz to indicate it was used.
	 *
	 * For boot allocation:
	 * If we have a small number of mblocks we will use the space
	 * that we preallocated. Otherwise, we will dynamically
	 * allocate the space from the prom and map it to the
	 * reserved VA at MPOBUF_BASE.
	 */

	if (utype == U_ADD || utype == U_DEL) {
		mb = (struct mblock_md *)kmem_zalloc(allocsz, KM_SLEEP);
		ms = (mem_stripe_t *)(mb + nmblocks);
		mc->mc_alloc_sz = allocsz;
	} else if (nmblocks <= SMALL_MBLOCKS_COUNT) {
		mb = &small_mpo_mblocks[0];
		ms = &small_mem_stripes[0];
		mc->mc_alloc_sz = 0;
	} else {
		/* Ensure that we dont request more space than reserved */
		if (allocsz > MPOBUF_SIZE) {
			MPO_STATUS("mblock_alloc: Insufficient space "
			    "for mblock structures \n");
			return (-1);
		}
		mb = (struct mblock_md *)
		    prom_alloc((caddr_t)MPOBUF_BASE, allocsz, PAGESIZE);
		if (mb != (struct mblock_md *)MPOBUF_BASE) {
			MPO_STATUS("mblock_alloc: Cannot allocate space "
			    "for mblocks \n");
			return (-1);
		}
		mpo_heap32_buf = (caddr_t)MPOBUF_BASE;
		mpo_heap32_bufsz = MPOBUF_SIZE;
		ms = (mem_stripe_t *)(mb + nmblocks);
		mc->mc_alloc_sz = 0;
	}
	mc->mc_mblocks = mb;
	mc->mc_stripes = ms;
	mc->mc_nmblocks = nmblocks;
	mc->mc_nstripes = nstripes;
	MPO_DEBUG("mblock_alloc: mblocks: %d\n", nmblocks);
	return (0);
}

/*
 * mblock_free
 *
 * Free memory in mc that was allocated by mblock_alloc.
 */

static void
mblock_free(mpo_config_t *mc)
{
	if (mc->mc_alloc_sz > 0) {
		ASSERT(mc->mc_mblocks != mpo_mblock);
		kmem_free((caddr_t)mc->mc_mblocks, mc->mc_alloc_sz);
	}
	bzero(mc, sizeof (*mc));
}

/*
 * mblock_install
 *
 * Install mblock config passed in mc as the global configuration.
 * May only be called at boot or while holding mpo_wr_lock.
 */

static void
mblock_install(mpo_config_t *mc)
{
	mpo_mblock = mc->mc_mblocks;
	n_mblocks = mc->mc_nmblocks;
	mem_stripes = mc->mc_stripes;
	n_mem_stripes = mc->mc_nstripes;
	base_ra_to_pa_pfn = btop(mc->mc_mblocks[0].ra_to_pa);
	mpo_config = *mc;
}

/*
 * mblock_update
 *
 * Traverse mblocknodes, read the mblock properties from the MD, and
 * save the mblocks in mc.
 */

static void
mblock_update(mpo_config_t *mc, md_t md, mde_cookie_t *mblocknodes)
{
	uint64_t i, j;
	int result = 0;
	mblock_md_t *mblock = mc->mc_mblocks;

	for (i = 0, j = 0; j < mc->mc_nmblocks; j++) {

		/* Without a base or size value we will fail */
		result = get_int(md, mblocknodes[j], PROP_LG_BASE,
		    &mblock[i].base);
		if (result < 0) {
			MPO_STATUS("mblock_update: "
			    "PROP_LG_BASE is missing\n");
			mc->mc_nmblocks = 0;
			return;
		}

		result = get_int(md, mblocknodes[j], PROP_LG_SIZE,
		    &mblock[i].size);
		if (result < 0) {
			MPO_STATUS("mblock_update: "
			    "PROP_LG_SIZE is missing\n");
			mc->mc_nmblocks = 0;
			return;
		}

		result = get_int(md, mblocknodes[j],
		    PROP_LG_RA_PA_OFFSET, &mblock[i].ra_to_pa);

		/* If we don't have an ra_pa_offset, just set it to 0 */
		if (result < 0)
			mblock[i].ra_to_pa = 0;

		MPO_DEBUG("mblock[%ld]: base = %lx, size = %lx, "
		    "ra_to_pa = %lx\n", i,
		    mblock[i].base,
		    mblock[i].size,
		    mblock[i].ra_to_pa);

		/* check for unsupportable values of base and size */
		if (mblock[i].base > mblock[i].base + mblock[i].size) {
			MPO_STATUS("mblock_update: "
			    "PROP_LG_BASE+PROP_LG_SIZE is invalid: "
			    "base = %lx, size = %lx\n",
			    mblock[i].base, mblock[i].size);
			mc->mc_nmblocks = 0;
			return;
		}

		/* eliminate size==0 blocks */
		if (mblock[i].size != 0) {
			uint64_t base = mblock[i].base;
			uint64_t end = base + mblock[i].size;
			ASSERT(end > base);
			mblock[i].base_pfn = btop(base);
			mblock[i].end_pfn = btop(end - 1);
			i++;
		}
	}

	if (i == 0) {
		MPO_STATUS("mblock_update: "
		    "No non-empty mblock nodes were found "
		    "in the Machine Descriptor\n");
		mc->mc_nmblocks = 0;
		return;
	}
	ASSERT(i <= mc->mc_nmblocks);
	mc->mc_nmblocks = i;

	/* Must sort mblocks by address for mem_node_iterator_init() */
	mblock_sort(mblock, mc->mc_nmblocks);
}

/*
 * mblock_update_add
 *
 * Update mblock config after a memory DR add.  The added range is not
 * needed, as we read *all* mblock nodes from the MD.  Save the mblocks
 * in mc.
 */

static void
mblock_update_add(mpo_config_t *mc)
{
	md_t *md;
	mde_cookie_t root, *mblocknodes;
	int nmblocks = 0;

	if ((md = md_get_handle()) == NULL) {
		MPO_STATUS("Cannot access Machine Descriptor\n");
		goto error;
	}

	if ((root = md_get_root(md)) == MDE_INVAL_ELEM_COOKIE)
		goto error;

	nmblocks = md_alloc_scan_dag(md, root, PROP_LG_MBLOCK, "fwd",
	    &mblocknodes);
	if (nmblocks <= 0) {
		MPO_STATUS("No mblock nodes detected in Machine Descriptor\n");
		goto error;
	}

	if (mblock_alloc(mc, U_ADD, nmblocks) < 0)
		goto error;

	mblock_update(mc, md, mblocknodes);
	md_free_scan_dag(md, &mblocknodes);
	(void) md_fini_handle(md);
	return;
error:
	panic("mblock_update_add: cannot process mblocks from MD.\n");
}

/*
 * mblock_update_del
 *
 * Update mblocks after a memory DR deletion of the range (ubase, uend).
 * Allocate a new mblock config, copy old config to the new, modify the new
 * mblocks to reflect the deletion.   The new mblocks are returned in
 * mc_new and are not yet installed as the active config.
 */

static void
mblock_update_del(mpo_config_t *mc_new, mpo_config_t *mc_old, pfn_t ubase,
    pfn_t uend)
{
	int i, j;
	pfn_t base, end;
	mblock_md_t *mblock;
	int nmblocks = mc_old->mc_nmblocks;

	MPO_DEBUG("mblock_update_del(0x%lx, 0x%lx)\n", ubase, uend);

	/*
	 * Allocate mblocks in mc_new and copy the old to the new.
	 * Allocate one extra in case the deletion splits an mblock.
	 */
	if (mblock_alloc(mc_new, U_DEL, nmblocks + 1) < 0)
		return;
	mblock = mc_new->mc_mblocks;
	bcopy(mc_old->mc_mblocks, mblock, nmblocks * sizeof (mblock_md_t));

	/*
	 * Find the mblock containing the deleted range and adjust it in
	 * the new config.
	 */
	for (i = 0; i < nmblocks; i++) {

		base = btop(mblock[i].base);
		end = base + btop(mblock[i].size) - 1;

		/*
		 * Adjust the mblock based on the subset that was deleted.
		 *
		 * If the entire mblk was deleted, compact the table.
		 *
		 * If the middle of the mblk was deleted, extend
		 * the table.  Space for the new slot was already
		 * allocated.
		 *
		 * The memory to be deleted is a mblock or a subset of
		 * and does not span multiple mblocks.
		 */
		if (base == ubase && end == uend) {
			for (j = i; j < nmblocks - 1; j++)
				mblock[j] = mblock[j + 1];
			nmblocks--;
			bzero(&mblock[nmblocks], sizeof (*mblock));
			break;
		} else if (base < ubase && end > uend) {
			for (j = nmblocks - 1; j >= i; j--)
				mblock[j + 1] = mblock[j];
			mblock[i].size = ptob(ubase - base);
			mblock[i].end_pfn = ubase - 1;
			mblock[i + 1].base = ptob(uend + 1);
			mblock[i + 1].size = ptob(end - uend);
			mblock[i + 1].base_pfn = uend + 1;
			nmblocks++;
			break;
		} else if (base == ubase) {
			MPO_DEBUG("mblock_update_del: shrink>"
			    " i=%d base=0x%lx end=0x%lx", i, base, end);
			mblock[i].base = ptob(uend + 1);
			mblock[i].size -= ptob(uend - ubase + 1);
			base = uend + 1;
			mblock[i].base_pfn = base;
			mblock[i].end_pfn = end;
			MPO_DEBUG(" nbase=0x%lx nend=0x%lx\n", base, end);
			break;
		} else if (end == uend) {
			MPO_DEBUG("mblock_update_del: shrink<"
			    " i=%d base=0x%lx end=0x%lx", i, base, end);
			mblock[i].size -= ptob(uend - ubase + 1);
			end = ubase - 1;
			mblock[i].base_pfn = base;
			mblock[i].end_pfn = end;
			MPO_DEBUG(" nbase=0x%lx nend=0x%lx\n", base, end);
			break;
		}
	}
	mc_new->mc_nmblocks = nmblocks;
	ASSERT(end > base);
}

/*
 * mstripe_update
 *
 * Read mblocks from mc and update mstripes in mc
 */

static void
mstripe_update(mpo_config_t *mc)
{
	lgrp_handle_t lgrphand, lgrp_start;
	int i, mnode;
	uint64_t offset, stripe_end, base, end, ra_to_pa, stride;
	uint64_t stripe, frag, remove;
	mem_stripe_t *ms;
	mblock_md_t *mblock = mc->mc_mblocks;
	int nmblocks = mc->mc_nmblocks;
	int mstripesz = MAX_MEM_NODES * nmblocks * sizeof (mem_stripe_t);

	/* Check for non-MPO sun4v platforms or memory DR removal */
	if (n_locality_groups <= 1) {
		ASSERT(n_locality_groups == 1);
		ASSERT(max_locality_groups == 1 && max_mem_nodes == 1);

		if (nmblocks == 1) {
			mc->mc_nstripes = 0;
		} else {
			mc->mc_nstripes = nmblocks;
			bzero(mc->mc_stripes, mstripesz);
			for (i = 0; i < nmblocks; i++) {
				mc->mc_stripes[i].exists = 1;
				mc->mc_stripes[i].physbase = mblock[i].base_pfn;
				mc->mc_stripes[i].physmax = mblock[i].end_pfn;
			}
		}
		return;
	}

	bzero(mc->mc_stripes, mstripesz);
	mc->mc_nstripes = max_locality_groups * nmblocks;
	stripe = ptob(mnode_pages);
	stride = max_locality_groups * stripe;

	for (i = 0; i < nmblocks; i++) {
		base = mblock[i].base;
		end = base + mblock[i].size;
		ra_to_pa = mblock[i].ra_to_pa;

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

			ms = &mc->mc_stripes[i * max_locality_groups + mnode];
			ms->physbase = btop(base);
			ms->physmax = btop(end - 1 - remove);
			ms->offset = btop(offset);
			ms->exists = 1;

			base = stripe_end;
			stripe_end += stripe;
			offset = 0;
			lgrphand = (((base + ra_to_pa) & home_mask) >>
			    home_mask_shift);
		} while (lgrphand != lgrp_start);
	}
}

#define	INTERSECT(a, b, c, d)				\
	if (((a) >= (c) && (a) <= (d)) ||		\
	    ((c) >= (a) && (c) <= (b))) {		\
		(c) = MAX((a), (c));			\
		(d) = MIN((b), (d));			\
	} else {					\
		ASSERT((a) >= (d) || (b) <= (c));	\
		continue;				\
	}						\

/*
 * mnode_update
 *
 * Read stripes from mc and update mnode extents.  The mnode extents are
 * part of the live configuration, so this can only be done at boot time
 * or while holding the mpo_wr_lock.
 */

static void
mnode_update(mpo_config_t *mc, pfn_t ubase, pfn_t uend, update_t utype)
{
	int i, j, mnode, found;
	pfn_t base, end;
	mem_stripe_t *ms;

	MPO_DEBUG("mnode_udpate: basepfn: %lx  endpfn: %lx\n", ubase, uend);

	if (n_locality_groups <= 1 && mc->mc_nmblocks == 1) {
		if (utype == U_ADD)
			mpo_mem_node_add_slice(ubase, uend);
		else if (utype == U_DEL)
			mpo_mem_node_del_slice(ubase, uend);
		else
			panic("mnode update: %d: invalid\n", utype);
		return;
	}

	found = 0;
	for (i = 0; i < mc->mc_nmblocks; i++) {
		for (mnode = 0; mnode < max_locality_groups; mnode++) {

			j = i * max_locality_groups + mnode;
			ms = &mc->mc_stripes[j];
			if (!ms->exists)
				continue;

			base = ms->physbase;
			end = ms->physmax;

			/*
			 * Look for the mstripes intersecting this slice.
			 *
			 * The mstripe and slice pairs may not be equal
			 * if a subset of a mblock is added/deleted.
			 */
			switch (utype) {
			case U_ADD:
				INTERSECT(ubase, uend, base, end);
				/*FALLTHROUGH*/
			case U_ADD_ALL:
				if (n_locality_groups > 1)
					mpo_plat_assign_lgrphand_to_mem_node(
					    mnode, mnode);
				mpo_mem_node_add_slice(base, end);
				break;
			case U_DEL:
				INTERSECT(ubase, uend, base, end);
				mpo_mem_node_del_slice(base, end);
				break;
			default:
				panic("mnode_update: %d: invalid\n", utype);
				break;
			}

			found++;
		}
	}

	if (!found)
		panic("mnode_update: mstripe not found");

#ifdef	DEBUG
	if (utype == U_ADD_ALL || utype == U_DEL)
		return;
	found = 0;
	for (i = 0; i < max_mem_nodes; i++) {
		if (!mem_node_config[i].exists)
			continue;
		if (ubase >= mem_node_config[i].physbase &&
		    ubase <= mem_node_config[i].physmax)
			found |= 1;
		if (uend >= mem_node_config[i].physbase &&
		    uend <= mem_node_config[i].physmax)
			found |= 2;
	}
	ASSERT(found == 3);
	{
		pfn_t minpfn, maxpfn;

		mem_node_max_range(&minpfn, &maxpfn);
		ASSERT(minpfn <= ubase);
		ASSERT(maxpfn >= uend);
	}
#endif
}

/*
 * Plat_slice_add()/plat_slice_del() are the platform hooks
 * for adding/deleting a pfn range to/from the system.
 *
 * Platform_slice_add() is used for both boot/DR cases.
 *
 * - Zeus has already added the mblocks to the MD, so read the updated
 *   MD and allocate all data structures required to manage the new memory
 *   configuration.
 *
 * - Recompute the stripes which are derived from the mblocks.
 *
 * - Update (expand) the mnode extents and install the modified mblocks as
 *   the new mpo config.  This must be done while holding the mpo_wr_lock
 *   to guarantee that no other threads access the mpo meta-data.
 *
 * - Unlock MPO data structures; the new config is live.  Free the old config.
 *
 * Plat_slice_del() is used for DR only.
 *
 * - Zeus has not yet modified the MD to reflect the deletion, so copy
 *   the old mpo mblocks and delete the range from the copy.
 *
 * - Recompute the stripes which are derived from the mblocks.
 *
 * - Update (shrink) the mnode extents and install the modified mblocks as
 *   the new mpo config.  This must be done while holding the mpo_wr_lock
 *   to guarantee that no other threads access the mpo meta-data.
 *
 * - Unlock MPO data structures; the new config is live.  Free the old config.
 */

void
plat_slice_add(pfn_t base, pfn_t end)
{
	mpo_config_t old_config = mpo_config;
	mpo_config_t new_config;

	VALIDATE_SLICE(base, end);
	mblock_update_add(&new_config);
	mstripe_update(&new_config);
	mpo_wr_lock();
	mblock_install(&new_config);
	/* Use new config to add all ranges for mnode_update */
	mnode_update(&new_config, base, end, U_ADD);
	mpo_genid++;
	mpo_wr_unlock();
	mblock_free(&old_config);
}

void
plat_slice_del(pfn_t base, pfn_t end)
{
	mpo_config_t old_config = mpo_config;
	mpo_config_t new_config;

	VALIDATE_SLICE(base, end);
	mblock_update_del(&new_config, &old_config, base, end);
	mstripe_update(&new_config);
	mpo_wr_lock();
	/* Use old config to find deleted range for mnode_update */
	mnode_update(&old_config, base, end, U_DEL);
	mblock_install(&new_config);
	mpo_genid++;
	mpo_wr_unlock();
	mblock_free(&old_config);
}
