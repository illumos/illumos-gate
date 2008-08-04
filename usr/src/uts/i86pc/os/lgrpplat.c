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

#pragma ident	"%Z%%M%	%I%	%E% SMI"


/*
 * LOCALITY GROUP (LGROUP) PLATFORM SUPPORT FOR X86/AMD64 PLATFORMS
 * ================================================================
 * Multiprocessor AMD and Intel systems may have Non Uniform Memory Access
 * (NUMA).  A NUMA machine consists of one or more "nodes" that each consist of
 * one or more CPUs and some local memory.  The CPUs in each node can access
 * the memory in the other nodes but at a higher latency than accessing their
 * local memory.  Typically, a system with only one node has Uniform Memory
 * Access (UMA), but it may be possible to have a one node system that has
 * some global memory outside of the node which is higher latency.
 *
 * Module Description
 * ------------------
 * This module provides a platform interface for determining which CPUs and
 * which memory (and how much) are in a NUMA node and how far each node is from
 * each other.  The interface is used by the Virtual Memory (VM) system and the
 * common lgroup framework.  The VM system uses the plat_*() routines to fill
 * in its memory node (memnode) array with the physical address range spanned
 * by each NUMA node to know which memory belongs to which node, so it can
 * build and manage a physical page free list for each NUMA node and allocate
 * local memory from each node as needed.  The common lgroup framework uses the
 * exported lgrp_plat_*() routines to figure out which CPUs and memory belong
 * to each node (leaf lgroup) and how far each node is from each other, so it
 * can build the latency (lgroup) topology for the machine in order to optimize
 * for locality.  Also, an lgroup platform handle instead of lgroups are used
 * in the interface with this module, so this module shouldn't need to know
 * anything about lgroups.  Instead, it just needs to know which CPUs, memory,
 * etc. are in each NUMA node, how far each node is from each other, and to use
 * a unique lgroup platform handle to refer to each node through the interface.
 *
 * Determining NUMA Configuration
 * ------------------------------
 * By default, this module will try to determine the NUMA configuration of the
 * machine by reading the ACPI System Resource Affinity Table (SRAT) and System
 * Locality Information Table (SLIT).  The SRAT contains info to tell which
 * CPUs and memory are local to a given proximity domain (NUMA node).  The SLIT
 * is a matrix that gives the distance between each system locality (which is
 * a NUMA node and should correspond to proximity domains in the SRAT).  For
 * more details on the SRAT and SLIT, please refer to an ACPI 3.0 or newer
 * specification.
 *
 * If the SRAT doesn't exist on a system with AMD Opteron processors, we
 * examine registers in PCI configuration space to determine how many nodes are
 * in the system and which CPUs and memory are in each node.
 * do while booting the kernel.
 *
 * NOTE: Using these PCI configuration space registers to determine this
 *       locality info is not guaranteed to work or be compatible across all
 *	 Opteron processor families.
 *
 * If the SLIT does not exist or look right, the kernel will probe to determine
 * the distance between nodes as long as the NUMA CPU and memory configuration
 * has been determined (see lgrp_plat_probe() for details).
 *
 * Data Structures
 * ---------------
 * The main data structures used by this code are the following:
 *
 * - lgrp_plat_cpu_node[]		CPU to node ID mapping table indexed by
 *					CPU ID (only used for SRAT)
 *
 * - lgrp_plat_lat_stats.latencies[][]	Table of latencies between same and
 *					different nodes indexed by node ID
 *
 * - lgrp_plat_node_cnt			Number of NUMA nodes in system
 *
 * - lgrp_plat_node_domain[]		Node ID to proximity domain ID mapping
 *					table indexed by node ID (only used
 *					for SRAT)
 *
 * - lgrp_plat_node_memory[]		Table with physical address range for
 *					each node indexed by node ID
 *
 * The code is implemented to make the following always be true:
 *
 *	lgroup platform handle == node ID == memnode ID
 *
 * Moreover, it allows for the proximity domain ID to be equal to all of the
 * above as long as the proximity domains IDs are numbered from 0 to <number of
 * nodes - 1>.  This is done by hashing each proximity domain ID into the range
 * from 0 to <number of nodes - 1>.  Then proximity ID N will hash into node ID
 * N and proximity domain ID N will be entered into lgrp_plat_node_domain[N]
 * and be assigned node ID N.  If the proximity domain IDs aren't numbered
 * from 0 to <number of nodes - 1>, then hashing the proximity domain IDs into
 * lgrp_plat_node_domain[] will still work for assigning proximity domain IDs
 * to node IDs.  However, the proximity domain IDs may not map to the
 * equivalent node ID since we want to keep the node IDs numbered from 0 to
 * <number of nodes - 1> to minimize cost of searching and potentially space.
 */


#include <sys/archsystm.h>	/* for {in,out}{b,w,l}() */
#include <sys/bootconf.h>
#include <sys/cmn_err.h>
#include <sys/controlregs.h>
#include <sys/cpupart.h>
#include <sys/cpuvar.h>
#include <sys/lgrp.h>
#include <sys/machsystm.h>
#include <sys/memlist.h>
#include <sys/memnode.h>
#include <sys/mman.h>
#include <sys/pci_cfgspace.h>
#include <sys/pci_impl.h>
#include <sys/param.h>
#include <sys/pghw.h>
#include <sys/promif.h>		/* for prom_printf() */
#include <sys/sysmacros.h>
#include <sys/systm.h>
#include <sys/thread.h>
#include <sys/types.h>
#include <sys/var.h>
#include <sys/x86_archext.h>	/* for x86_feature and X86_AMD */
#include <vm/hat_i86.h>
#include <vm/seg_kmem.h>
#include <vm/vm_dep.h>

#include "acpi_fw.h"		/* for SRAT and SLIT */


#define	MAX_NODES		8
#define	NLGRP			(MAX_NODES * (MAX_NODES - 1) + 1)

/*
 * Constants for configuring probing
 */
#define	LGRP_PLAT_PROBE_NROUNDS		64	/* default laps for probing */
#define	LGRP_PLAT_PROBE_NSAMPLES	1	/* default samples to take */
#define	LGRP_PLAT_PROBE_NREADS		256	/* number of vendor ID reads */

/*
 * Flags for probing
 */
#define	LGRP_PLAT_PROBE_ENABLE		0x1	/* enable probing */
#define	LGRP_PLAT_PROBE_PGCPY		0x2	/* probe using page copy */
#define	LGRP_PLAT_PROBE_VENDOR		0x4	/* probe vendor ID register */

/*
 * Hash proximity domain ID into node to domain mapping table using to minimize
 * span of entries used
 */
#define	NODE_DOMAIN_HASH(domain, node_cnt)	((domain) % node_cnt)


/*
 * CPU to node ID mapping structure (only used with SRAT)
 */
typedef	struct cpu_node_map {
	int		exists;
	uint_t		node;
	uint32_t	apicid;
	uint32_t	prox_domain;
} cpu_node_map_t;

/*
 * Latency statistics
 */
typedef struct lgrp_plat_latency_stats {
	hrtime_t	latencies[MAX_NODES][MAX_NODES];
	hrtime_t	latency_max;
	hrtime_t	latency_min;
} lgrp_plat_latency_stats_t;

/*
 * Memory configuration for probing
 */
typedef struct lgrp_plat_probe_mem_config {
	size_t	probe_memsize;		/* how much memory to probe per node */
	caddr_t	probe_va[MAX_NODES];	/* where memory mapped for probing */
	pfn_t	probe_pfn[MAX_NODES];	/* physical pages to map for probing */
} lgrp_plat_probe_mem_config_t;

/*
 * Statistics kept for probing
 */
typedef struct lgrp_plat_probe_stats {
	hrtime_t	flush_cost;
	hrtime_t	probe_cost;
	hrtime_t	probe_cost_total;
	hrtime_t	probe_error_code;
	hrtime_t	probe_errors[MAX_NODES][MAX_NODES];
	int		probe_suspect[MAX_NODES][MAX_NODES];
	hrtime_t	probe_max[MAX_NODES][MAX_NODES];
	hrtime_t	probe_min[MAX_NODES][MAX_NODES];
} lgrp_plat_probe_stats_t;

/*
 * Node to proximity domain ID mapping structure (only used with SRAT)
 */
typedef	struct node_domain_map {
	int		exists;
	uint32_t	prox_domain;
} node_domain_map_t;

/*
 * Node ID and starting and ending page for physical memory in node
 */
typedef	struct node_phys_addr_map {
	pfn_t		start;
	pfn_t		end;
	int		exists;
	uint32_t	prox_domain;
} node_phys_addr_map_t;

/*
 * Number of CPUs for which we got APIC IDs
 */
static int				lgrp_plat_apic_ncpus = 0;

/*
 * CPU to node ID mapping table (only used for SRAT)
 */
static cpu_node_map_t			lgrp_plat_cpu_node[NCPU];

/*
 * Latency statistics
 */
lgrp_plat_latency_stats_t		lgrp_plat_lat_stats;

/*
 * Whether memory is interleaved across nodes causing MPO to be disabled
 */
static int				lgrp_plat_mem_intrlv = 0;

/*
 * Node ID to proximity domain ID mapping table (only used for SRAT)
 */
static node_domain_map_t		lgrp_plat_node_domain[MAX_NODES];

/*
 * Physical address range for memory in each node
 */
static node_phys_addr_map_t		lgrp_plat_node_memory[MAX_NODES];

/*
 * Statistics gotten from probing
 */
static lgrp_plat_probe_stats_t		lgrp_plat_probe_stats;

/*
 * Memory configuration for probing
 */
static lgrp_plat_probe_mem_config_t	lgrp_plat_probe_mem_config;

/*
 * Error code from processing ACPI SRAT
 */
static int				lgrp_plat_srat_error = 0;

/*
 * Error code from processing ACPI SLIT
 */
static int				lgrp_plat_slit_error = 0;

/*
 * Allocate lgroup array statically
 */
static lgrp_t				lgrp_space[NLGRP];
static int				nlgrps_alloc;


/*
 * Number of nodes in system
 */
uint_t			lgrp_plat_node_cnt = 1;

/*
 * Configuration Parameters for Probing
 * - lgrp_plat_probe_flags	Flags to specify enabling probing, probe
 *				operation, etc.
 * - lgrp_plat_probe_nrounds	How many rounds of probing to do
 * - lgrp_plat_probe_nsamples	Number of samples to take when probing each
 *				node
 * - lgrp_plat_probe_nreads	Number of times to read vendor ID from
 *				Northbridge for each probe
 */
uint_t			lgrp_plat_probe_flags = 0;
int			lgrp_plat_probe_nrounds = LGRP_PLAT_PROBE_NROUNDS;
int			lgrp_plat_probe_nsamples = LGRP_PLAT_PROBE_NSAMPLES;
int			lgrp_plat_probe_nreads = LGRP_PLAT_PROBE_NREADS;

/*
 * Enable use of ACPI System Resource Affinity Table (SRAT) and System
 * Locality Information Table (SLIT)
 */
int			lgrp_plat_srat_enable = 1;
int			lgrp_plat_slit_enable = 1;

/*
 * Static array to hold lgroup statistics
 */
struct lgrp_stats	lgrp_stats[NLGRP];


/*
 * Forward declarations of platform interface routines
 */
void		plat_build_mem_nodes(struct memlist *list);

int		plat_lgrphand_to_mem_node(lgrp_handle_t hand);

lgrp_handle_t	plat_mem_node_to_lgrphand(int mnode);

int		plat_mnode_xcheck(pfn_t pfncnt);

int		plat_pfn_to_mem_node(pfn_t pfn);

/*
 * Forward declarations of lgroup platform interface routines
 */
lgrp_t		*lgrp_plat_alloc(lgrp_id_t lgrpid);

void		lgrp_plat_config(lgrp_config_flag_t flag, uintptr_t arg);

lgrp_handle_t	lgrp_plat_cpu_to_hand(processorid_t id);

void		lgrp_plat_init(void);

int		lgrp_plat_latency(lgrp_handle_t from, lgrp_handle_t to);

void		lgrp_plat_main_init(void);

int		lgrp_plat_max_lgrps(void);

pgcnt_t		lgrp_plat_mem_size(lgrp_handle_t plathand,
    lgrp_mem_query_t query);

lgrp_handle_t	lgrp_plat_pfn_to_hand(pfn_t pfn);

void		lgrp_plat_probe(void);

lgrp_handle_t	lgrp_plat_root_hand(void);


/*
 * Forward declarations of local routines
 */
static int	is_opteron(void);

static int	lgrp_plat_cpu_node_update(node_domain_map_t *node_domain,
    int node_cnt, cpu_node_map_t *cpu_node, int nentries, uint32_t apicid,
    uint32_t domain);

static int	lgrp_plat_cpu_to_node(cpu_t *cp, cpu_node_map_t *cpu_node);

static int	lgrp_plat_domain_to_node(node_domain_map_t *node_domain,
    int node_cnt, uint32_t domain);

static void	lgrp_plat_latency_adjust(node_phys_addr_map_t *node_memory,
    lgrp_plat_latency_stats_t *lat_stats,
    lgrp_plat_probe_stats_t *probe_stats);

static int	lgrp_plat_latency_verify(node_phys_addr_map_t *node_memory,
    lgrp_plat_latency_stats_t *lat_stats);

static pgcnt_t	lgrp_plat_mem_size_default(lgrp_handle_t, lgrp_mem_query_t);

static int	lgrp_plat_node_domain_update(node_domain_map_t *node_domain,
    int node_cnt, uint32_t domain);

static int	lgrp_plat_node_memory_update(node_domain_map_t *node_domain,
    int node_cnt, node_phys_addr_map_t *node_memory, uint64_t start,
    uint64_t end, uint32_t domain);

static hrtime_t	lgrp_plat_probe_time(int to, cpu_node_map_t *cpu_node,
    lgrp_plat_probe_mem_config_t *probe_mem_config,
    lgrp_plat_latency_stats_t *lat_stats,
    lgrp_plat_probe_stats_t *probe_stats);

static int	lgrp_plat_process_cpu_apicids(cpu_node_map_t *cpu_node);

static int	lgrp_plat_process_slit(struct slit *tp, uint_t node_cnt,
    node_phys_addr_map_t *node_memory, lgrp_plat_latency_stats_t *lat_stats);

static int	lgrp_plat_process_srat(struct srat *tp,
    node_domain_map_t *node_domain, cpu_node_map_t *cpu_node, int cpu_count,
    node_phys_addr_map_t *node_memory);

static int	lgrp_plat_srat_domains(struct srat *tp);

static void	lgrp_plat_2level_setup(node_phys_addr_map_t *node_memory,
    lgrp_plat_latency_stats_t *lat_stats);

static void	opt_get_numa_config(uint_t *node_cnt, int *mem_intrlv,
    node_phys_addr_map_t *node_memory);

static hrtime_t	opt_probe_vendor(int dest_node, int nreads);


/*
 * PLATFORM INTERFACE ROUTINES
 */

/*
 * Configure memory nodes for machines with more than one node (ie NUMA)
 */
void
plat_build_mem_nodes(struct memlist *list)
{
	pfn_t		cur_start;	/* start addr of subrange */
	pfn_t		cur_end;	/* end addr of subrange */
	pfn_t		start;		/* start addr of whole range */
	pfn_t		end;		/* end addr of whole range */

	/*
	 * Boot install lists are arranged <addr, len>, ...
	 */
	while (list) {
		int	node;

		start = list->address >> PAGESHIFT;
		end = (list->address + list->size - 1) >> PAGESHIFT;

		if (start > physmax) {
			list = list->next;
			continue;
		}
		if (end > physmax)
			end = physmax;

		/*
		 * When there is only one memnode, just add memory to memnode
		 */
		if (max_mem_nodes == 1) {
			mem_node_add_slice(start, end);
			list = list->next;
			continue;
		}

		/*
		 * mem_node_add_slice() expects to get a memory range that
		 * is within one memnode, so need to split any memory range
		 * that spans multiple memnodes into subranges that are each
		 * contained within one memnode when feeding them to
		 * mem_node_add_slice()
		 */
		cur_start = start;
		do {
			node = plat_pfn_to_mem_node(cur_start);

			/*
			 * Panic if DRAM address map registers or SRAT say
			 * memory in node doesn't exist or address from
			 * boot installed memory list entry isn't in this node.
			 * This shouldn't happen and rest of code can't deal
			 * with this if it does.
			 */
			if (node < 0 || node >= lgrp_plat_node_cnt ||
			    !lgrp_plat_node_memory[node].exists ||
			    cur_start < lgrp_plat_node_memory[node].start ||
			    cur_start > lgrp_plat_node_memory[node].end) {
				cmn_err(CE_PANIC, "Don't know which memnode "
				    "to add installed memory address 0x%lx\n",
				    cur_start);
			}

			/*
			 * End of current subrange should not span memnodes
			 */
			cur_end = end;
			if (lgrp_plat_node_memory[node].exists &&
			    cur_end > lgrp_plat_node_memory[node].end)
				cur_end = lgrp_plat_node_memory[node].end;

			mem_node_add_slice(cur_start, cur_end);

			/*
			 * Next subrange starts after end of current one
			 */
			cur_start = cur_end + 1;
		} while (cur_end < end);

		list = list->next;
	}
	mem_node_physalign = 0;
	mem_node_pfn_shift = 0;
}


int
plat_lgrphand_to_mem_node(lgrp_handle_t hand)
{
	if (max_mem_nodes == 1)
		return (0);

	return ((int)hand);
}


/*
 * plat_mnode_xcheck: checks the node memory ranges to see if there is a pfncnt
 * range of pages aligned on pfncnt that crosses an node boundary. Returns 1 if
 * a crossing is found and returns 0 otherwise.
 */
int
plat_mnode_xcheck(pfn_t pfncnt)
{
	int	node, prevnode = -1, basenode;
	pfn_t	ea, sa;

	for (node = 0; node < lgrp_plat_node_cnt; node++) {

		if (lgrp_plat_node_memory[node].exists == 0)
			continue;

		if (prevnode == -1) {
			prevnode = node;
			basenode = node;
			continue;
		}

		/* assume x86 node pfn ranges are in increasing order */
		ASSERT(lgrp_plat_node_memory[node].start >
		    lgrp_plat_node_memory[prevnode].end);

		/*
		 * continue if the starting address of node is not contiguous
		 * with the previous node.
		 */

		if (lgrp_plat_node_memory[node].start !=
		    (lgrp_plat_node_memory[prevnode].end + 1)) {
			basenode = node;
			prevnode = node;
			continue;
		}

		/* check if the starting address of node is pfncnt aligned */
		if ((lgrp_plat_node_memory[node].start & (pfncnt - 1)) != 0) {

			/*
			 * at this point, node starts at an unaligned boundary
			 * and is contiguous with the previous node(s) to
			 * basenode. Check if there is an aligned contiguous
			 * range of length pfncnt that crosses this boundary.
			 */

			sa = P2ALIGN(lgrp_plat_node_memory[prevnode].end,
			    pfncnt);
			ea = P2ROUNDUP((lgrp_plat_node_memory[node].start),
			    pfncnt);

			ASSERT((ea - sa) == pfncnt);
			if (sa >= lgrp_plat_node_memory[basenode].start &&
			    ea <= (lgrp_plat_node_memory[node].end + 1))
				return (1);
		}
		prevnode = node;
	}
	return (0);
}


lgrp_handle_t
plat_mem_node_to_lgrphand(int mnode)
{
	if (max_mem_nodes == 1)
		return (LGRP_DEFAULT_HANDLE);

	return ((lgrp_handle_t)mnode);
}


int
plat_pfn_to_mem_node(pfn_t pfn)
{
	int	node;

	if (max_mem_nodes == 1)
		return (0);

	for (node = 0; node < lgrp_plat_node_cnt; node++) {
		/*
		 * Skip nodes with no memory
		 */
		if (!lgrp_plat_node_memory[node].exists)
			continue;

		if (pfn >= lgrp_plat_node_memory[node].start &&
		    pfn <= lgrp_plat_node_memory[node].end)
			return (node);
	}

	/*
	 * Didn't find memnode where this PFN lives which should never happen
	 */
	ASSERT(node < lgrp_plat_node_cnt);
	return (-1);
}


/*
 * LGROUP PLATFORM INTERFACE ROUTINES
 */

/*
 * Allocate additional space for an lgroup.
 */
/* ARGSUSED */
lgrp_t *
lgrp_plat_alloc(lgrp_id_t lgrpid)
{
	lgrp_t *lgrp;

	lgrp = &lgrp_space[nlgrps_alloc++];
	if (lgrpid >= NLGRP || nlgrps_alloc > NLGRP)
		return (NULL);
	return (lgrp);
}


/*
 * Platform handling for (re)configuration changes
 */
/* ARGSUSED */
void
lgrp_plat_config(lgrp_config_flag_t flag, uintptr_t arg)
{
}


/*
 * Return the platform handle for the lgroup containing the given CPU
 */
/* ARGSUSED */
lgrp_handle_t
lgrp_plat_cpu_to_hand(processorid_t id)
{
	lgrp_handle_t	hand;

	if (lgrp_plat_node_cnt == 1)
		return (LGRP_DEFAULT_HANDLE);

	hand = (lgrp_handle_t)lgrp_plat_cpu_to_node(cpu[id],
	    lgrp_plat_cpu_node);

	ASSERT(hand != (lgrp_handle_t)-1);
	if (hand == (lgrp_handle_t)-1)
		return (LGRP_NULL_HANDLE);

	return (hand);
}


/*
 * Platform-specific initialization of lgroups
 */
void
lgrp_plat_init(void)
{
#if defined(__xpv)
	/*
	 * XXPV	For now, the hypervisor treats all memory equally.
	 */
	lgrp_plat_node_cnt = max_mem_nodes = 1;
#else	/* __xpv */
	uint_t	probe_op;

	/*
	 * Initialize as a UMA machine
	 */
	if (lgrp_topo_ht_limit() == 1) {
		lgrp_plat_node_cnt = max_mem_nodes = 1;
		return;
	}

	/*
	 * Read boot property with CPU to APIC ID mapping table/array and fill
	 * in CPU to node ID mapping table with APIC ID for each CPU
	 */
	lgrp_plat_apic_ncpus =
	    lgrp_plat_process_cpu_apicids(lgrp_plat_cpu_node);

	/*
	 * Determine which CPUs and memory are local to each other and number
	 * of NUMA nodes by reading ACPI System Resource Affinity Table (SRAT)
	 */
	if (lgrp_plat_apic_ncpus > 0) {
		int	retval;

		retval = lgrp_plat_process_srat(srat_ptr,
		    lgrp_plat_node_domain, lgrp_plat_cpu_node,
		    lgrp_plat_apic_ncpus, lgrp_plat_node_memory);
		if (retval <= 0) {
			lgrp_plat_srat_error = retval;
			lgrp_plat_node_cnt = 1;
		} else {
			lgrp_plat_srat_error = 0;
			lgrp_plat_node_cnt = retval;
		}
	}

	/*
	 * Try to use PCI config space registers on Opteron if there's an error
	 * processing CPU to APIC ID mapping or SRAT
	 */
	if ((lgrp_plat_apic_ncpus <= 0 || lgrp_plat_srat_error != 0) &&
	    is_opteron())
		opt_get_numa_config(&lgrp_plat_node_cnt, &lgrp_plat_mem_intrlv,
		    lgrp_plat_node_memory);

	/*
	 * Don't bother to setup system for multiple lgroups and only use one
	 * memory node when memory is interleaved between any nodes or there is
	 * only one NUMA node
	 *
	 * NOTE: May need to change this for Dynamic Reconfiguration (DR)
	 *	 when and if it happens for x86/x64
	 */
	if (lgrp_plat_mem_intrlv || lgrp_plat_node_cnt == 1) {
		lgrp_plat_node_cnt = max_mem_nodes = 1;
		(void) lgrp_topo_ht_limit_set(1);
		return;
	}

	/*
	 * Leaf lgroups on x86/x64 architectures contain one physical
	 * processor chip. Tune lgrp_expand_proc_thresh and
	 * lgrp_expand_proc_diff so that lgrp_choose() will spread
	 * things out aggressively.
	 */
	lgrp_expand_proc_thresh = LGRP_LOADAVG_THREAD_MAX / 2;
	lgrp_expand_proc_diff = 0;

	/*
	 * There should be one memnode (physical page free list(s)) for
	 * each node
	 */
	max_mem_nodes = lgrp_plat_node_cnt;

	/*
	 * Initialize min and max latency before reading SLIT or probing
	 */
	lgrp_plat_lat_stats.latency_min = -1;
	lgrp_plat_lat_stats.latency_max = 0;

	/*
	 * Determine how far each NUMA node is from each other by
	 * reading ACPI System Locality Information Table (SLIT) if it
	 * exists
	 */
	lgrp_plat_slit_error = lgrp_plat_process_slit(slit_ptr,
	    lgrp_plat_node_cnt, lgrp_plat_node_memory,
	    &lgrp_plat_lat_stats);
	if (lgrp_plat_slit_error == 0)
		return;

	/*
	 * Probe to determine latency between NUMA nodes when SLIT
	 * doesn't exist or make sense
	 */
	lgrp_plat_probe_flags |= LGRP_PLAT_PROBE_ENABLE;

	/*
	 * Specify whether to probe using vendor ID register or page copy
	 * if hasn't been specified already or is overspecified
	 */
	probe_op = lgrp_plat_probe_flags &
	    (LGRP_PLAT_PROBE_PGCPY|LGRP_PLAT_PROBE_VENDOR);

	if (probe_op == 0 ||
	    probe_op == (LGRP_PLAT_PROBE_PGCPY|LGRP_PLAT_PROBE_VENDOR)) {
		lgrp_plat_probe_flags &=
		    ~(LGRP_PLAT_PROBE_PGCPY|LGRP_PLAT_PROBE_VENDOR);
		if (is_opteron())
			lgrp_plat_probe_flags |=
			    LGRP_PLAT_PROBE_VENDOR;
		else
			lgrp_plat_probe_flags |= LGRP_PLAT_PROBE_PGCPY;
	}

	/*
	 * Probing errors can mess up the lgroup topology and
	 * force us fall back to a 2 level lgroup topology.
	 * Here we bound how tall the lgroup topology can grow
	 * in hopes of avoiding any anamolies in probing from
	 * messing up the lgroup topology by limiting the
	 * accuracy of the latency topology.
	 *
	 * Assume that nodes will at least be configured in a
	 * ring, so limit height of lgroup topology to be less
	 * than number of nodes on a system with 4 or more
	 * nodes
	 */
	if (lgrp_plat_node_cnt >= 4 && lgrp_topo_ht_limit() ==
	    lgrp_topo_ht_limit_default())
		(void) lgrp_topo_ht_limit_set(lgrp_plat_node_cnt - 1);
#endif	/* __xpv */
}


/*
 * Return latency between "from" and "to" lgroups
 *
 * This latency number can only be used for relative comparison
 * between lgroups on the running system, cannot be used across platforms,
 * and may not reflect the actual latency.  It is platform and implementation
 * specific, so platform gets to decide its value.  It would be nice if the
 * number was at least proportional to make comparisons more meaningful though.
 */
/* ARGSUSED */
int
lgrp_plat_latency(lgrp_handle_t from, lgrp_handle_t to)
{
	lgrp_handle_t	src, dest;
	int		node;

	if (max_mem_nodes == 1)
		return (0);

	/*
	 * Return max latency for root lgroup
	 */
	if (from == LGRP_DEFAULT_HANDLE || to == LGRP_DEFAULT_HANDLE)
		return (lgrp_plat_lat_stats.latency_max);

	src = from;
	dest = to;

	/*
	 * Return 0 for nodes (lgroup platform handles) out of range
	 */
	if (src < 0 || src >= MAX_NODES || dest < 0 || dest >= MAX_NODES)
		return (0);

	/*
	 * Probe from current CPU if its lgroup latencies haven't been set yet
	 * and we are trying to get latency from current CPU to some node
	 */
	node = lgrp_plat_cpu_to_node(CPU, lgrp_plat_cpu_node);
	ASSERT(node >= 0 && node < lgrp_plat_node_cnt);
	if (lgrp_plat_lat_stats.latencies[src][src] == 0 && node == src)
		lgrp_plat_probe();

	return (lgrp_plat_lat_stats.latencies[src][dest]);
}


/*
 * Platform-specific initialization
 */
void
lgrp_plat_main_init(void)
{
	int	curnode;
	int	ht_limit;
	int	i;

	/*
	 * Print a notice that MPO is disabled when memory is interleaved
	 * across nodes....Would do this when it is discovered, but can't
	 * because it happens way too early during boot....
	 */
	if (lgrp_plat_mem_intrlv)
		cmn_err(CE_NOTE,
		    "MPO disabled because memory is interleaved\n");

	/*
	 * Don't bother to do any probing if it is disabled, there is only one
	 * node, or the height of the lgroup topology less than or equal to 2
	 */
	ht_limit = lgrp_topo_ht_limit();
	if (!(lgrp_plat_probe_flags & LGRP_PLAT_PROBE_ENABLE) ||
	    max_mem_nodes == 1 || ht_limit <= 2) {
		/*
		 * Setup lgroup latencies for 2 level lgroup topology
		 * (ie. local and remote only) if they haven't been set yet
		 */
		if (ht_limit == 2 && lgrp_plat_lat_stats.latency_min == -1 &&
		    lgrp_plat_lat_stats.latency_max == 0)
			lgrp_plat_2level_setup(lgrp_plat_node_memory,
			    &lgrp_plat_lat_stats);
		return;
	}

	if (lgrp_plat_probe_flags & LGRP_PLAT_PROBE_VENDOR) {
		/*
		 * Should have been able to probe from CPU 0 when it was added
		 * to lgroup hierarchy, but may not have been able to then
		 * because it happens so early in boot that gethrtime() hasn't
		 * been initialized.  (:-(
		 */
		curnode = lgrp_plat_cpu_to_node(CPU, lgrp_plat_cpu_node);
		ASSERT(curnode >= 0 && curnode < lgrp_plat_node_cnt);
		if (lgrp_plat_lat_stats.latencies[curnode][curnode] == 0)
			lgrp_plat_probe();

		return;
	}

	/*
	 * When probing memory, use one page for every sample to determine
	 * lgroup topology and taking multiple samples
	 */
	if (lgrp_plat_probe_mem_config.probe_memsize == 0)
		lgrp_plat_probe_mem_config.probe_memsize = PAGESIZE *
		    lgrp_plat_probe_nsamples;

	/*
	 * Map memory in each node needed for probing to determine latency
	 * topology
	 */
	for (i = 0; i < lgrp_plat_node_cnt; i++) {
		int	mnode;

		/*
		 * Skip this node and leave its probe page NULL
		 * if it doesn't have any memory
		 */
		mnode = plat_lgrphand_to_mem_node((lgrp_handle_t)i);
		if (!mem_node_config[mnode].exists) {
			lgrp_plat_probe_mem_config.probe_va[i] = NULL;
			continue;
		}

		/*
		 * Allocate one kernel virtual page
		 */
		lgrp_plat_probe_mem_config.probe_va[i] = vmem_alloc(heap_arena,
		    lgrp_plat_probe_mem_config.probe_memsize, VM_NOSLEEP);
		if (lgrp_plat_probe_mem_config.probe_va[i] == NULL) {
			cmn_err(CE_WARN,
			    "lgrp_plat_main_init: couldn't allocate memory");
			return;
		}

		/*
		 * Get PFN for first page in each node
		 */
		lgrp_plat_probe_mem_config.probe_pfn[i] =
		    mem_node_config[mnode].physbase;

		/*
		 * Map virtual page to first page in node
		 */
		hat_devload(kas.a_hat, lgrp_plat_probe_mem_config.probe_va[i],
		    lgrp_plat_probe_mem_config.probe_memsize,
		    lgrp_plat_probe_mem_config.probe_pfn[i],
		    PROT_READ | PROT_WRITE | HAT_PLAT_NOCACHE,
		    HAT_LOAD_NOCONSIST);
	}

	/*
	 * Probe from current CPU
	 */
	lgrp_plat_probe();
}


/*
 * Return the maximum number of lgrps supported by the platform.
 * Before lgrp topology is known it returns an estimate based on the number of
 * nodes. Once topology is known it returns the actual maximim number of lgrps
 * created. Since x86/x64 doesn't support Dynamic Reconfiguration (DR) and
 * dynamic addition of new nodes, this number may not grow during system
 * lifetime (yet).
 */
int
lgrp_plat_max_lgrps(void)
{
	return (lgrp_topo_initialized ?
	    lgrp_alloc_max + 1 :
	    lgrp_plat_node_cnt * (lgrp_plat_node_cnt - 1) + 1);
}


/*
 * Return the number of free pages in an lgroup.
 *
 * For query of LGRP_MEM_SIZE_FREE, return the number of base pagesize
 * pages on freelists.  For query of LGRP_MEM_SIZE_AVAIL, return the
 * number of allocatable base pagesize pages corresponding to the
 * lgroup (e.g. do not include page_t's, BOP_ALLOC()'ed memory, ..)
 * For query of LGRP_MEM_SIZE_INSTALL, return the amount of physical
 * memory installed, regardless of whether or not it's usable.
 */
pgcnt_t
lgrp_plat_mem_size(lgrp_handle_t plathand, lgrp_mem_query_t query)
{
	int	mnode;
	pgcnt_t npgs = (pgcnt_t)0;
	extern struct memlist *phys_avail;
	extern struct memlist *phys_install;


	if (plathand == LGRP_DEFAULT_HANDLE)
		return (lgrp_plat_mem_size_default(plathand, query));

	if (plathand != LGRP_NULL_HANDLE) {
		mnode = plat_lgrphand_to_mem_node(plathand);
		if (mnode >= 0 && mem_node_config[mnode].exists) {
			switch (query) {
			case LGRP_MEM_SIZE_FREE:
				npgs = MNODE_PGCNT(mnode);
				break;
			case LGRP_MEM_SIZE_AVAIL:
				npgs = mem_node_memlist_pages(mnode,
				    phys_avail);
				break;
			case LGRP_MEM_SIZE_INSTALL:
				npgs = mem_node_memlist_pages(mnode,
				    phys_install);
				break;
			default:
				break;
			}
		}
	}
	return (npgs);
}


/*
 * Return the platform handle of the lgroup that contains the physical memory
 * corresponding to the given page frame number
 */
/* ARGSUSED */
lgrp_handle_t
lgrp_plat_pfn_to_hand(pfn_t pfn)
{
	int	mnode;

	if (max_mem_nodes == 1)
		return (LGRP_DEFAULT_HANDLE);

	if (pfn > physmax)
		return (LGRP_NULL_HANDLE);

	mnode = plat_pfn_to_mem_node(pfn);
	if (mnode < 0)
		return (LGRP_NULL_HANDLE);

	return (MEM_NODE_2_LGRPHAND(mnode));
}


/*
 * Probe memory in each node from current CPU to determine latency topology
 *
 * The probing code will probe the vendor ID register on the Northbridge of
 * Opteron processors and probe memory for other processors by default.
 *
 * Since probing is inherently error prone, the code takes laps across all the
 * nodes probing from each node to each of the other nodes some number of
 * times.  Furthermore, each node is probed some number of times before moving
 * onto the next one during each lap.  The minimum latency gotten between nodes
 * is kept as the latency between the nodes.
 *
 * After all that,  the probe times are adjusted by normalizing values that are
 * close to each other and local latencies are made the same.  Lastly, the
 * latencies are verified to make sure that certain conditions are met (eg.
 * local < remote, latency(a, b) == latency(b, a), etc.).
 *
 * If any of the conditions aren't met, the code will export a NUMA
 * configuration with the local CPUs and memory given by the SRAT or PCI config
 * space registers and one remote memory latency since it can't tell exactly
 * how far each node is from each other.
 */
void
lgrp_plat_probe(void)
{
	int				from;
	int				i;
	lgrp_plat_latency_stats_t	*lat_stats;
	hrtime_t			probe_time;
	int				to;

	if (!(lgrp_plat_probe_flags & LGRP_PLAT_PROBE_ENABLE) ||
	    max_mem_nodes == 1 || lgrp_topo_ht_limit() <= 2)
		return;

	/*
	 * Determine ID of node containing current CPU
	 */
	from = lgrp_plat_cpu_to_node(CPU, lgrp_plat_cpu_node);
	ASSERT(from >= 0 && from < lgrp_plat_node_cnt);
	if (srat_ptr && lgrp_plat_srat_enable && !lgrp_plat_srat_error)
		ASSERT(lgrp_plat_node_domain[from].exists);

	/*
	 * Don't need to probe if got times already
	 */
	lat_stats = &lgrp_plat_lat_stats;
	if (lat_stats->latencies[from][from] != 0)
		return;

	/*
	 * Read vendor ID in Northbridge or read and write page(s)
	 * in each node from current CPU and remember how long it takes,
	 * so we can build latency topology of machine later.
	 * This should approximate the memory latency between each node.
	 */
	for (i = 0; i < lgrp_plat_probe_nrounds; i++) {
		for (to = 0; to < lgrp_plat_node_cnt; to++) {
			/*
			 * Get probe time and bail out if can't get it yet
			 */
			probe_time = lgrp_plat_probe_time(to,
			    lgrp_plat_cpu_node, &lgrp_plat_probe_mem_config,
			    &lgrp_plat_lat_stats, &lgrp_plat_probe_stats);
			if (probe_time == 0)
				return;

			/*
			 * Keep lowest probe time as latency between nodes
			 */
			if (lat_stats->latencies[from][to] == 0 ||
			    probe_time < lat_stats->latencies[from][to])
				lat_stats->latencies[from][to] = probe_time;

			/*
			 * Update overall minimum and maximum probe times
			 * across all nodes
			 */
			if (probe_time < lat_stats->latency_min ||
			    lat_stats->latency_min == -1)
				lat_stats->latency_min = probe_time;
			if (probe_time > lat_stats->latency_max)
				lat_stats->latency_max = probe_time;
		}
	}

	/*
	 * - Fix up latencies such that local latencies are same,
	 *   latency(i, j) == latency(j, i), etc. (if possible)
	 *
	 * - Verify that latencies look ok
	 *
	 * - Fallback to just optimizing for local and remote if
	 *   latencies didn't look right
	 */
	lgrp_plat_latency_adjust(lgrp_plat_node_memory, &lgrp_plat_lat_stats,
	    &lgrp_plat_probe_stats);
	lgrp_plat_probe_stats.probe_error_code =
	    lgrp_plat_latency_verify(lgrp_plat_node_memory,
	    &lgrp_plat_lat_stats);
	if (lgrp_plat_probe_stats.probe_error_code)
		lgrp_plat_2level_setup(lgrp_plat_node_memory,
		    &lgrp_plat_lat_stats);
}


/*
 * Return platform handle for root lgroup
 */
lgrp_handle_t
lgrp_plat_root_hand(void)
{
	return (LGRP_DEFAULT_HANDLE);
}


/*
 * INTERNAL ROUTINES
 */


/*
 * Update CPU to node mapping for given CPU and proximity domain (and returns
 * negative numbers for errors and positive ones for success)
 */
static int
lgrp_plat_cpu_node_update(node_domain_map_t *node_domain, int node_cnt,
    cpu_node_map_t *cpu_node, int nentries, uint32_t apicid, uint32_t domain)
{
	uint_t	i;
	int	node;

	/*
	 * Get node number for proximity domain
	 */
	node = lgrp_plat_domain_to_node(node_domain, node_cnt, domain);
	if (node == -1) {
		node = lgrp_plat_node_domain_update(node_domain, node_cnt,
		    domain);
		if (node == -1)
			return (-1);
	}

	/*
	 * Search for entry with given APIC ID and fill in its node and
	 * proximity domain IDs (if they haven't been set already)
	 */
	for (i = 0; i < nentries; i++) {
		/*
		 * Skip nonexistent entries and ones without matching APIC ID
		 */
		if (!cpu_node[i].exists || cpu_node[i].apicid != apicid)
			continue;

		/*
		 * Just return if entry completely and correctly filled in
		 * already
		 */
		if (cpu_node[i].prox_domain == domain &&
		    cpu_node[i].node == node)
			return (1);

		/*
		 * Fill in node and proximity domain IDs
		 */
		cpu_node[i].prox_domain = domain;
		cpu_node[i].node = node;

		return (0);
	}

	/*
	 * Return error when entry for APIC ID wasn't found in table
	 */
	return (-2);
}


/*
 * Get node ID for given CPU
 */
static int
lgrp_plat_cpu_to_node(cpu_t *cp, cpu_node_map_t *cpu_node)
{
	processorid_t	cpuid;

	if (cp == NULL)
		return (-1);

	cpuid = cp->cpu_id;
	if (cpuid < 0 || cpuid >= max_ncpus)
		return (-1);

	/*
	 * SRAT doesn't exist, isn't enabled, or there was an error processing
	 * it, so return chip ID for Opteron and -1 otherwise.
	 */
	if (srat_ptr == NULL || !lgrp_plat_srat_enable ||
	    lgrp_plat_srat_error) {
		if (is_opteron())
			return (pg_plat_hw_instance_id(cp, PGHW_CHIP));
		return (-1);
	}

	/*
	 * Return -1 when CPU to node ID mapping entry doesn't exist for given
	 * CPU
	 */
	if (!cpu_node[cpuid].exists)
		return (-1);

	return (cpu_node[cpuid].node);
}


/*
 * Return node number for given proximity domain/system locality
 */
static int
lgrp_plat_domain_to_node(node_domain_map_t *node_domain, int node_cnt,
    uint32_t domain)
{
	uint_t	node;
	uint_t	start;

	/*
	 * Hash proximity domain ID into node to domain mapping table (array),
	 * search for entry with matching proximity domain ID, and return index
	 * of matching entry as node ID.
	 */
	node = start = NODE_DOMAIN_HASH(domain, node_cnt);
	do {
		if (node_domain[node].prox_domain == domain &&
		    node_domain[node].exists)
			return (node);
		node = NODE_DOMAIN_HASH(node + 1, node_cnt);
	} while (node != start);
	return (-1);
}


/*
 * Latencies must be within 1/(2**LGRP_LAT_TOLERANCE_SHIFT) of each other to
 * be considered same
 */
#define	LGRP_LAT_TOLERANCE_SHIFT	4

int	lgrp_plat_probe_lt_shift = LGRP_LAT_TOLERANCE_SHIFT;


/*
 * Adjust latencies between nodes to be symmetric, normalize latencies between
 * any nodes that are within some tolerance to be same, and make local
 * latencies be same
 */
static void
lgrp_plat_latency_adjust(node_phys_addr_map_t *node_memory,
    lgrp_plat_latency_stats_t *lat_stats, lgrp_plat_probe_stats_t *probe_stats)
{
	int				i;
	int				j;
	int				k;
	int				l;
	u_longlong_t			max;
	u_longlong_t			min;
	u_longlong_t			t;
	u_longlong_t			t1;
	u_longlong_t			t2;
	const lgrp_config_flag_t	cflag = LGRP_CONFIG_LAT_CHANGE_ALL;
	int				lat_corrected[MAX_NODES][MAX_NODES];

	/*
	 * Nothing to do when this is an UMA machine or don't have args needed
	 */
	if (max_mem_nodes == 1)
		return;

	ASSERT(node_memory != NULL && lat_stats != NULL &&
	    probe_stats != NULL);

	/*
	 * Make sure that latencies are symmetric between any two nodes
	 * (ie. latency(node0, node1) == latency(node1, node0))
	 */
	for (i = 0; i < lgrp_plat_node_cnt; i++) {
		if (!node_memory[i].exists)
			continue;

		for (j = 0; j < lgrp_plat_node_cnt; j++) {
			if (!node_memory[j].exists)
				continue;

			t1 = lat_stats->latencies[i][j];
			t2 = lat_stats->latencies[j][i];

			if (t1 == 0 || t2 == 0 || t1 == t2)
				continue;

			/*
			 * Latencies should be same
			 * - Use minimum of two latencies which should be same
			 * - Track suspect probe times not within tolerance of
			 *   min value
			 * - Remember how much values are corrected by
			 */
			if (t1 > t2) {
				t = t2;
				probe_stats->probe_errors[i][j] += t1 - t2;
				if (t1 - t2 > t2 >> lgrp_plat_probe_lt_shift) {
					probe_stats->probe_suspect[i][j]++;
					probe_stats->probe_suspect[j][i]++;
				}
			} else if (t2 > t1) {
				t = t1;
				probe_stats->probe_errors[j][i] += t2 - t1;
				if (t2 - t1 > t1 >> lgrp_plat_probe_lt_shift) {
					probe_stats->probe_suspect[i][j]++;
					probe_stats->probe_suspect[j][i]++;
				}
			}

			lat_stats->latencies[i][j] =
			    lat_stats->latencies[j][i] = t;
			lgrp_config(cflag, t1, t);
			lgrp_config(cflag, t2, t);
		}
	}

	/*
	 * Keep track of which latencies get corrected
	 */
	for (i = 0; i < MAX_NODES; i++)
		for (j = 0; j < MAX_NODES; j++)
			lat_corrected[i][j] = 0;

	/*
	 * For every two nodes, see whether there is another pair of nodes which
	 * are about the same distance apart and make the latencies be the same
	 * if they are close enough together
	 */
	for (i = 0; i < lgrp_plat_node_cnt; i++) {
		if (!node_memory[i].exists)
			continue;
		for (j = 0; j < lgrp_plat_node_cnt; j++) {
			if (!node_memory[j].exists)
				continue;
			/*
			 * Pick one pair of nodes (i, j)
			 * and get latency between them
			 */
			t1 = lat_stats->latencies[i][j];

			/*
			 * Skip this pair of nodes if there isn't a latency
			 * for it yet
			 */
			if (t1 == 0)
				continue;

			for (k = 0; k < lgrp_plat_node_cnt; k++) {
				if (!node_memory[k].exists)
					continue;
				for (l = 0; l < lgrp_plat_node_cnt; l++) {
					if (!node_memory[l].exists)
						continue;
					/*
					 * Pick another pair of nodes (k, l)
					 * not same as (i, j) and get latency
					 * between them
					 */
					if (k == i && l == j)
						continue;

					t2 = lat_stats->latencies[k][l];

					/*
					 * Skip this pair of nodes if there
					 * isn't a latency for it yet
					 */

					if (t2 == 0)
						continue;

					/*
					 * Skip nodes (k, l) if they already
					 * have same latency as (i, j) or
					 * their latency isn't close enough to
					 * be considered/made the same
					 */
					if (t1 == t2 || (t1 > t2 && t1 - t2 >
					    t1 >> lgrp_plat_probe_lt_shift) ||
					    (t2 > t1 && t2 - t1 >
					    t2 >> lgrp_plat_probe_lt_shift))
						continue;

					/*
					 * Make latency(i, j) same as
					 * latency(k, l), try to use latency
					 * that has been adjusted already to get
					 * more consistency (if possible), and
					 * remember which latencies were
					 * adjusted for next time
					 */
					if (lat_corrected[i][j]) {
						t = t1;
						lgrp_config(cflag, t2, t);
						t2 = t;
					} else if (lat_corrected[k][l]) {
						t = t2;
						lgrp_config(cflag, t1, t);
						t1 = t;
					} else {
						if (t1 > t2)
							t = t2;
						else
							t = t1;
						lgrp_config(cflag, t1, t);
						lgrp_config(cflag, t2, t);
						t1 = t2 = t;
					}

					lat_stats->latencies[i][j] =
					    lat_stats->latencies[k][l] = t;

					lat_corrected[i][j] =
					    lat_corrected[k][l] = 1;
				}
			}
		}
	}

	/*
	 * Local latencies should be same
	 * - Find min and max local latencies
	 * - Make all local latencies be minimum
	 */
	min = -1;
	max = 0;
	for (i = 0; i < lgrp_plat_node_cnt; i++) {
		if (!node_memory[i].exists)
			continue;
		t = lat_stats->latencies[i][i];
		if (t == 0)
			continue;
		if (min == -1 || t < min)
			min = t;
		if (t > max)
			max = t;
	}
	if (min != max) {
		for (i = 0; i < lgrp_plat_node_cnt; i++) {
			int	local;

			if (!node_memory[i].exists)
				continue;

			local = lat_stats->latencies[i][i];
			if (local == 0)
				continue;

			/*
			 * Track suspect probe times that aren't within
			 * tolerance of minimum local latency and how much
			 * probe times are corrected by
			 */
			if (local - min > min >> lgrp_plat_probe_lt_shift)
				probe_stats->probe_suspect[i][i]++;

			probe_stats->probe_errors[i][i] += local - min;

			/*
			 * Make local latencies be minimum
			 */
			lgrp_config(LGRP_CONFIG_LAT_CHANGE, i, min);
			lat_stats->latencies[i][i] = min;
		}
	}

	/*
	 * Determine max probe time again since just adjusted latencies
	 */
	lat_stats->latency_max = 0;
	for (i = 0; i < lgrp_plat_node_cnt; i++) {
		if (!node_memory[i].exists)
			continue;
		for (j = 0; j < lgrp_plat_node_cnt; j++) {
			if (!node_memory[j].exists)
				continue;
			t = lat_stats->latencies[i][j];
			if (t > lat_stats->latency_max)
				lat_stats->latency_max = t;
		}
	}
}


/*
 * Verify following about latencies between nodes:
 *
 * - Latencies should be symmetric (ie. latency(a, b) == latency(b, a))
 * - Local latencies same
 * - Local < remote
 * - Number of latencies seen is reasonable
 * - Number of occurrences of a given latency should be more than 1
 *
 * Returns:
 *	0	Success
 *	-1	Not symmetric
 *	-2	Local latencies not same
 *	-3	Local >= remote
 */
static int
lgrp_plat_latency_verify(node_phys_addr_map_t *node_memory,
    lgrp_plat_latency_stats_t *lat_stats)
{
	int				i;
	int				j;
	u_longlong_t			t1;
	u_longlong_t			t2;

	ASSERT(node_memory != NULL && lat_stats != NULL);

	/*
	 * Nothing to do when this is an UMA machine, lgroup topology is
	 * limited to 2 levels, or there aren't any probe times yet
	 */
	if (max_mem_nodes == 1 || lgrp_topo_levels < 2 ||
	    lat_stats->latencies[0][0] == 0)
		return (0);

	/*
	 * Make sure that latencies are symmetric between any two nodes
	 * (ie. latency(node0, node1) == latency(node1, node0))
	 */
	for (i = 0; i < lgrp_plat_node_cnt; i++) {
		if (!node_memory[i].exists)
			continue;
		for (j = 0; j < lgrp_plat_node_cnt; j++) {
			if (!node_memory[j].exists)
				continue;
			t1 = lat_stats->latencies[i][j];
			t2 = lat_stats->latencies[j][i];

			if (t1 == 0 || t2 == 0 || t1 == t2)
				continue;

			return (-1);
		}
	}

	/*
	 * Local latencies should be same
	 */
	t1 = lat_stats->latencies[0][0];
	for (i = 1; i < lgrp_plat_node_cnt; i++) {
		if (!node_memory[i].exists)
			continue;

		t2 = lat_stats->latencies[i][i];
		if (t2 == 0)
			continue;

		if (t1 == 0) {
			t1 = t2;
			continue;
		}

		if (t1 != t2)
			return (-2);
	}

	/*
	 * Local latencies should be less than remote
	 */
	if (t1) {
		for (i = 0; i < lgrp_plat_node_cnt; i++) {
			if (!node_memory[i].exists)
				continue;
			for (j = 0; j < lgrp_plat_node_cnt; j++) {
				if (!node_memory[j].exists)
					continue;
				t2 = lat_stats->latencies[i][j];
				if (i == j || t2 == 0)
					continue;

				if (t1 >= t2)
					return (-3);
			}
		}
	}

	return (0);
}


/*
 * Return the number of free, allocatable, or installed
 * pages in an lgroup
 * This is a copy of the MAX_MEM_NODES == 1 version of the routine
 * used when MPO is disabled (i.e. single lgroup) or this is the root lgroup
 */
/* ARGSUSED */
static pgcnt_t
lgrp_plat_mem_size_default(lgrp_handle_t lgrphand, lgrp_mem_query_t query)
{
	struct memlist *mlist;
	pgcnt_t npgs = 0;
	extern struct memlist *phys_avail;
	extern struct memlist *phys_install;

	switch (query) {
	case LGRP_MEM_SIZE_FREE:
		return ((pgcnt_t)freemem);
	case LGRP_MEM_SIZE_AVAIL:
		memlist_read_lock();
		for (mlist = phys_avail; mlist; mlist = mlist->next)
			npgs += btop(mlist->size);
		memlist_read_unlock();
		return (npgs);
	case LGRP_MEM_SIZE_INSTALL:
		memlist_read_lock();
		for (mlist = phys_install; mlist; mlist = mlist->next)
			npgs += btop(mlist->size);
		memlist_read_unlock();
		return (npgs);
	default:
		return ((pgcnt_t)0);
	}
}


/*
 * Update node to proximity domain mappings for given domain and return node ID
 */
static int
lgrp_plat_node_domain_update(node_domain_map_t *node_domain, int node_cnt,
    uint32_t domain)
{
	uint_t	node;
	uint_t	start;

	/*
	 * Hash proximity domain ID into node to domain mapping table (array)
	 * and add entry for it into first non-existent or matching entry found
	 */
	node = start = NODE_DOMAIN_HASH(domain, node_cnt);
	do {
		/*
		 * Entry doesn't exist yet, so create one for this proximity
		 * domain and return node ID which is index into mapping table.
		 */
		if (!node_domain[node].exists) {
			node_domain[node].exists = 1;
			node_domain[node].prox_domain = domain;
			return (node);
		}

		/*
		 * Entry exists for this proximity domain already, so just
		 * return node ID (index into table).
		 */
		if (node_domain[node].prox_domain == domain)
			return (node);
		node = NODE_DOMAIN_HASH(node + 1, node_cnt);
	} while (node != start);

	/*
	 * Ran out of supported number of entries which shouldn't happen....
	 */
	ASSERT(node != start);
	return (-1);
}


/*
 * Update node memory information for given proximity domain with specified
 * starting and ending physical address range (and return positive numbers for
 * success and negative ones for errors)
 */
static int
lgrp_plat_node_memory_update(node_domain_map_t *node_domain, int node_cnt,
    node_phys_addr_map_t *node_memory, uint64_t start, uint64_t end,
    uint32_t domain)
{
	int	node;

	/*
	 * Get node number for proximity domain
	 */
	node = lgrp_plat_domain_to_node(node_domain, node_cnt, domain);
	if (node == -1) {
		node = lgrp_plat_node_domain_update(node_domain, node_cnt,
		    domain);
		if (node == -1)
			return (-1);
	}

	/*
	 * Create entry in table for node if it doesn't exist
	 */
	if (!node_memory[node].exists) {
		node_memory[node].exists = 1;
		node_memory[node].start = btop(start);
		node_memory[node].end = btop(end);
		node_memory[node].prox_domain = domain;
		return (0);
	}

	/*
	 * Entry already exists for this proximity domain
	 *
	 * There may be more than one SRAT memory entry for a domain, so we may
	 * need to update existing start or end address for the node.
	 */
	if (node_memory[node].prox_domain == domain) {
		if (btop(start) < node_memory[node].start)
			node_memory[node].start = btop(start);
		if (btop(end) > node_memory[node].end)
			node_memory[node].end = btop(end);
		return (1);
	}
	return (-2);
}


/*
 * Return time needed to probe from current CPU to memory in given node
 */
static hrtime_t
lgrp_plat_probe_time(int to, cpu_node_map_t *cpu_node,
    lgrp_plat_probe_mem_config_t *probe_mem_config,
    lgrp_plat_latency_stats_t *lat_stats, lgrp_plat_probe_stats_t *probe_stats)
{
	caddr_t			buf;
	hrtime_t		elapsed;
	hrtime_t		end;
	int			from;
	int			i;
	int			ipl;
	hrtime_t		max;
	hrtime_t		min;
	hrtime_t		start;
	extern int		use_sse_pagecopy;

	/*
	 * Determine ID of node containing current CPU
	 */
	from = lgrp_plat_cpu_to_node(CPU, cpu_node);
	ASSERT(from >= 0 && from < lgrp_plat_node_cnt);

	/*
	 * Do common work for probing main memory
	 */
	if (lgrp_plat_probe_flags & LGRP_PLAT_PROBE_PGCPY) {
		/*
		 * Skip probing any nodes without memory and
		 * set probe time to 0
		 */
		if (probe_mem_config->probe_va[to] == NULL) {
			lat_stats->latencies[from][to] = 0;
			return (0);
		}

		/*
		 * Invalidate caches once instead of once every sample
		 * which should cut cost of probing by a lot
		 */
		probe_stats->flush_cost = gethrtime();
		invalidate_cache();
		probe_stats->flush_cost = gethrtime() -
		    probe_stats->flush_cost;
		probe_stats->probe_cost_total += probe_stats->flush_cost;
	}

	/*
	 * Probe from current CPU to given memory using specified operation
	 * and take specified number of samples
	 */
	max = 0;
	min = -1;
	for (i = 0; i < lgrp_plat_probe_nsamples; i++) {
		probe_stats->probe_cost = gethrtime();

		/*
		 * Can't measure probe time if gethrtime() isn't working yet
		 */
		if (probe_stats->probe_cost == 0 && gethrtime() == 0)
			return (0);

		if (lgrp_plat_probe_flags & LGRP_PLAT_PROBE_VENDOR) {
			/*
			 * Measure how long it takes to read vendor ID from
			 * Northbridge
			 */
			elapsed = opt_probe_vendor(to, lgrp_plat_probe_nreads);
		} else {
			/*
			 * Measure how long it takes to copy page
			 * on top of itself
			 */
			buf = probe_mem_config->probe_va[to] + (i * PAGESIZE);

			kpreempt_disable();
			ipl = splhigh();
			start = gethrtime();
			if (use_sse_pagecopy)
				hwblkpagecopy(buf, buf);
			else
				bcopy(buf, buf, PAGESIZE);
			end = gethrtime();
			elapsed = end - start;
			splx(ipl);
			kpreempt_enable();
		}

		probe_stats->probe_cost = gethrtime() -
		    probe_stats->probe_cost;
		probe_stats->probe_cost_total += probe_stats->probe_cost;

		if (min == -1 || elapsed < min)
			min = elapsed;
		if (elapsed > max)
			max = elapsed;
	}

	/*
	 * Update minimum and maximum probe times between
	 * these two nodes
	 */
	if (min < probe_stats->probe_min[from][to] ||
	    probe_stats->probe_min[from][to] == 0)
		probe_stats->probe_min[from][to] = min;

	if (max > probe_stats->probe_max[from][to])
		probe_stats->probe_max[from][to] = max;

	return (min);
}


/*
 * Read boot property with CPU to APIC ID array, fill in CPU to node ID
 * mapping table with APIC ID for each CPU, and return number of CPU APIC IDs.
 *
 * NOTE: This code assumes that CPU IDs are assigned in order that they appear
 *       in in cpu_apicid_array boot property which is based on and follows
 *	 same ordering as processor list in ACPI MADT.  If the code in
 *	 usr/src/uts/i86pc/io/pcplusmp/apic.c that reads MADT and assigns
 *	 CPU IDs ever changes, then this code will need to change too....
 */
static int
lgrp_plat_process_cpu_apicids(cpu_node_map_t *cpu_node)
{
	int	boot_prop_len;
	char	*boot_prop_name = BP_CPU_APICID_ARRAY;
	uint8_t	cpu_apicid_array[UINT8_MAX + 1];
	int	i;
	int	n;

	/*
	 * Nothing to do when no array to fill in or not enough CPUs
	 */
	if (cpu_node == NULL)
		return (-1);

	/*
	 * Check length of property value
	 */
	boot_prop_len = BOP_GETPROPLEN(bootops, boot_prop_name);
	if (boot_prop_len <= 0 || boot_prop_len > sizeof (cpu_apicid_array))
		return (-2);

	/*
	 * Calculate number of entries in array and return when there's just
	 * one CPU since that's not very interesting for NUMA
	 */
	n = boot_prop_len / sizeof (uint8_t);
	if (n == 1)
		return (-3);

	/*
	 * Get CPU to APIC ID property value
	 */
	if (BOP_GETPROP(bootops, boot_prop_name, cpu_apicid_array) < 0)
		return (-4);

	/*
	 * Fill in CPU to node ID mapping table with APIC ID for each CPU
	 */
	for (i = 0; i < n; i++) {
		cpu_node[i].exists = 1;
		cpu_node[i].apicid = cpu_apicid_array[i];
	}

	/*
	 * Return number of CPUs based on number of APIC IDs
	 */
	return (n);
}


/*
 * Read ACPI System Locality Information Table (SLIT) to determine how far each
 * NUMA node is from each other
 */
static int
lgrp_plat_process_slit(struct slit *tp, uint_t node_cnt,
    node_phys_addr_map_t *node_memory, lgrp_plat_latency_stats_t *lat_stats)
{
	int		i;
	int		j;
	int		localities;
	hrtime_t	max;
	hrtime_t	min;
	int		retval;
	uint8_t		*slit_entries;

	if (tp == NULL || !lgrp_plat_slit_enable)
		return (1);

	if (lat_stats == NULL)
		return (2);

	localities = tp->number;
	if (localities != node_cnt)
		return (3);

	min = lat_stats->latency_min;
	max = lat_stats->latency_max;

	/*
	 * Fill in latency matrix based on SLIT entries
	 */
	slit_entries = tp->entry;
	for (i = 0; i < localities; i++) {
		for (j = 0; j < localities; j++) {
			uint8_t	latency;

			latency = slit_entries[(i * localities) + j];
			lat_stats->latencies[i][j] = latency;
			if (latency < min || min == -1)
				min = latency;
			if (latency > max)
				max = latency;
		}
	}

	/*
	 * Verify that latencies/distances given in SLIT look reasonable
	 */
	retval = lgrp_plat_latency_verify(node_memory, lat_stats);

	if (retval) {
		/*
		 * Reinitialize (zero) latency table since SLIT doesn't look
		 * right
		 */
		for (i = 0; i < localities; i++) {
			for (j = 0; j < localities; j++)
				lat_stats->latencies[i][j] = 0;
		}
	} else {
		/*
		 * Update min and max latencies seen since SLIT looks valid
		 */
		lat_stats->latency_min = min;
		lat_stats->latency_max = max;
	}

	return (retval);
}


/*
 * Read ACPI System Resource Affinity Table (SRAT) to determine which CPUs
 * and memory are local to each other in the same NUMA node and return number
 * of nodes
 */
static int
lgrp_plat_process_srat(struct srat *tp, node_domain_map_t *node_domain,
    cpu_node_map_t *cpu_node, int cpu_count, node_phys_addr_map_t *node_memory)
{
	struct srat_item	*srat_end;
	int			i;
	struct srat_item	*item;
	int			node_cnt;
	int			proc_entry_count;

	/*
	 * Nothing to do when no SRAT or disabled
	 */
	if (tp == NULL || !lgrp_plat_srat_enable)
		return (-1);

	/*
	 * Determine number of nodes by counting number of proximity domains in
	 * SRAT and return if number of nodes is 1 or less since don't need to
	 * read SRAT then
	 */
	node_cnt = lgrp_plat_srat_domains(tp);
	if (node_cnt == 1)
		return (1);
	else if (node_cnt <= 0)
		return (-2);

	/*
	 * Walk through SRAT, examining each CPU and memory entry to determine
	 * which CPUs and memory belong to which node.
	 */
	item = tp->list;
	srat_end = (struct srat_item *)(tp->hdr.len + (uintptr_t)tp);
	proc_entry_count = 0;
	while (item < srat_end) {
		uint32_t	apic_id;
		uint32_t	domain;
		uint64_t	end;
		uint64_t	length;
		uint64_t	start;

		switch (item->type) {
		case SRAT_PROCESSOR:	/* CPU entry */
			if (!(item->i.p.flags & SRAT_ENABLED) ||
			    cpu_node == NULL)
				break;

			/*
			 * Calculate domain (node) ID and fill in APIC ID to
			 * domain/node mapping table
			 */
			domain = item->i.p.domain1;
			for (i = 0; i < 3; i++) {
				domain += item->i.p.domain2[i] <<
				    ((i + 1) * 8);
			}
			apic_id = item->i.p.apic_id;

			if (lgrp_plat_cpu_node_update(node_domain, node_cnt,
			    cpu_node, cpu_count, apic_id, domain) < 0)
				return (-3);

			proc_entry_count++;
			break;

		case SRAT_MEMORY:	/* memory entry */
			if (!(item->i.m.flags & SRAT_ENABLED) ||
			    node_memory == NULL)
				break;

			/*
			 * Get domain (node) ID and fill in domain/node
			 * to memory mapping table
			 */
			domain = item->i.m.domain;
			start = item->i.m.base_addr;
			length = item->i.m.len;
			end = start + length - 1;

			if (lgrp_plat_node_memory_update(node_domain, node_cnt,
			    node_memory, start, end, domain) < 0)
				return (-4);
			break;
		case SRAT_X2APIC:	/* x2apic CPU entry */
			if (!(item->i.xp.flags & SRAT_ENABLED) ||
			    cpu_node == NULL)
				break;

			/*
			 * Calculate domain (node) ID and fill in APIC ID to
			 * domain/node mapping table
			 */
			domain = item->i.xp.domain;
			apic_id = item->i.xp.x2apic_id;

			if (lgrp_plat_cpu_node_update(node_domain, node_cnt,
			    cpu_node, cpu_count, apic_id, domain) < 0)
				return (-3);

			proc_entry_count++;
			break;

		default:
			break;
		}

		item = (struct srat_item *)((uintptr_t)item + item->len);
	}

	/*
	 * Should have seen at least as many SRAT processor entries as CPUs
	 */
	if (proc_entry_count < cpu_count)
		return (-5);

	return (node_cnt);
}


/*
 * Return number of proximity domains given in ACPI SRAT
 */
static int
lgrp_plat_srat_domains(struct srat *tp)
{
	int			domain_cnt;
	struct srat_item	*end;
	int			i;
	struct srat_item	*item;
	node_domain_map_t	node_domain[MAX_NODES];


	if (tp == NULL || !lgrp_plat_srat_enable)
		return (1);

	/*
	 * Walk through SRAT, examining each CPU and memory entry to determine
	 * proximity domain ID for each.
	 */
	domain_cnt = 0;
	item = tp->list;
	end = (struct srat_item *)(tp->hdr.len + (uintptr_t)tp);
	bzero(node_domain, MAX_NODES * sizeof (node_domain_map_t));
	while (item < end) {
		uint32_t	domain;
		boolean_t	overflow;
		uint_t		start;

		switch (item->type) {
		case SRAT_PROCESSOR:	/* CPU entry */
			if (!(item->i.p.flags & SRAT_ENABLED))
				break;
			domain = item->i.p.domain1;
			for (i = 0; i < 3; i++) {
				domain += item->i.p.domain2[i] <<
				    ((i + 1) * 8);
			}
			break;

		case SRAT_MEMORY:	/* memory entry */
			if (!(item->i.m.flags & SRAT_ENABLED))
				break;
			domain = item->i.m.domain;
			break;

		case SRAT_X2APIC:	/* x2apic CPU entry */
			if (!(item->i.xp.flags & SRAT_ENABLED))
				break;
			domain = item->i.xp.domain;
			break;

		default:
			break;
		}

		/*
		 * Count and keep track of which proximity domain IDs seen
		 */
		start = i = domain % MAX_NODES;
		overflow = B_TRUE;
		do {
			/*
			 * Create entry for proximity domain and increment
			 * count when no entry exists where proximity domain
			 * hashed
			 */
			if (!node_domain[i].exists) {
				node_domain[i].exists = 1;
				node_domain[i].prox_domain = domain;
				domain_cnt++;
				overflow = B_FALSE;
				break;
			}

			/*
			 * Nothing to do when proximity domain seen already
			 * and its entry exists
			 */
			if (node_domain[i].prox_domain == domain) {
				overflow = B_FALSE;
				break;
			}

			/*
			 * Entry exists where proximity domain hashed, but for
			 * different proximity domain so keep search for empty
			 * slot to put it or matching entry whichever comes
			 * first.
			 */
			i = (i + 1) % MAX_NODES;
		} while (i != start);

		/*
		 * Didn't find empty or matching entry which means have more
		 * proximity domains than supported nodes (:-(
		 */
		ASSERT(overflow != B_TRUE);
		if (overflow == B_TRUE)
			return (-1);

		item = (struct srat_item *)((uintptr_t)item + item->len);
	}
	return (domain_cnt);
}


/*
 * Set lgroup latencies for 2 level lgroup topology
 */
static void
lgrp_plat_2level_setup(node_phys_addr_map_t *node_memory,
    lgrp_plat_latency_stats_t *lat_stats)
{
	int	i;

	ASSERT(node_memory != NULL && lat_stats != NULL);

	if (lgrp_plat_node_cnt >= 4)
		cmn_err(CE_NOTE,
		    "MPO only optimizing for local and remote\n");
	for (i = 0; i < lgrp_plat_node_cnt; i++) {
		int	j;

		if (!node_memory[i].exists)
			continue;
		for (j = 0; j < lgrp_plat_node_cnt; j++) {
			if (!node_memory[j].exists)
				continue;
			if (i == j)
				lat_stats->latencies[i][j] = 2;
			else
				lat_stats->latencies[i][j] = 3;
		}
	}
	lat_stats->latency_min = 2;
	lat_stats->latency_max = 3;
	lgrp_config(LGRP_CONFIG_FLATTEN, 2, 0);
}


/*
 * The following Opteron specific constants, macros, types, and routines define
 * PCI configuration space registers and how to read them to determine the NUMA
 * configuration of *supported* Opteron processors.  They provide the same
 * information that may be gotten from the ACPI System Resource Affinity Table
 * (SRAT) if it exists on the machine of interest.
 *
 * The AMD BIOS and Kernel Developer's Guide (BKDG) for the processor family
 * of interest describes all of these registers and their contents.  The main
 * registers used by this code to determine the NUMA configuration of the
 * machine are the node ID register for the number of NUMA nodes and the DRAM
 * address map registers for the physical address range of each node.
 *
 * NOTE: The format and how to determine the NUMA configuration using PCI
 *	 config space registers may change or may not be supported in future
 *	 Opteron processor families.
 */

/*
 * How many bits to shift Opteron DRAM Address Map base and limit registers
 * to get actual value
 */
#define	OPT_DRAMADDR_HI_LSHIFT_ADDR	40	/* shift left for address */
#define	OPT_DRAMADDR_LO_LSHIFT_ADDR	8	/* shift left for address */

#define	OPT_DRAMADDR_HI_MASK_ADDR	0x000000FF /* address bits 47-40 */
#define	OPT_DRAMADDR_LO_MASK_ADDR	0xFFFF0000 /* address bits 39-24 */

#define	OPT_DRAMADDR_LO_MASK_OFF	0xFFFFFF /* offset for address */

/*
 * Macros to derive addresses from Opteron DRAM Address Map registers
 */
#define	OPT_DRAMADDR_HI(reg) \
	(((u_longlong_t)reg & OPT_DRAMADDR_HI_MASK_ADDR) << \
	    OPT_DRAMADDR_HI_LSHIFT_ADDR)

#define	OPT_DRAMADDR_LO(reg) \
	(((u_longlong_t)reg & OPT_DRAMADDR_LO_MASK_ADDR) << \
	    OPT_DRAMADDR_LO_LSHIFT_ADDR)

#define	OPT_DRAMADDR(high, low) \
	(OPT_DRAMADDR_HI(high) | OPT_DRAMADDR_LO(low))

/*
 * Bit masks defining what's in Opteron DRAM Address Map base register
 */
#define	OPT_DRAMBASE_LO_MASK_RE		0x1	/* read enable */
#define	OPT_DRAMBASE_LO_MASK_WE		0x2	/* write enable */
#define	OPT_DRAMBASE_LO_MASK_INTRLVEN	0x700	/* interleave */

/*
 * Bit masks defining what's in Opteron DRAM Address Map limit register
 */
#define	OPT_DRAMLIMIT_LO_MASK_DSTNODE	0x7		/* destination node */
#define	OPT_DRAMLIMIT_LO_MASK_INTRLVSEL	0x700		/* interleave select */


/*
 * Opteron Node ID register in PCI configuration space contains
 * number of nodes in system, etc. for Opteron K8.  The following
 * constants and macros define its contents, structure, and access.
 */

/*
 * Bit masks defining what's in Opteron Node ID register
 */
#define	OPT_NODE_MASK_ID	0x7	/* node ID */
#define	OPT_NODE_MASK_CNT	0x70	/* node count */
#define	OPT_NODE_MASK_IONODE	0x700	/* Hypertransport I/O hub node ID */
#define	OPT_NODE_MASK_LCKNODE	0x7000	/* lock controller node ID */
#define	OPT_NODE_MASK_CPUCNT	0xF0000	/* CPUs in system (0 means 1 CPU)  */

/*
 * How many bits in Opteron Node ID register to shift right to get actual value
 */
#define	OPT_NODE_RSHIFT_CNT	0x4	/* shift right for node count value */

/*
 * Macros to get values from Opteron Node ID register
 */
#define	OPT_NODE_CNT(reg) \
	((reg & OPT_NODE_MASK_CNT) >> OPT_NODE_RSHIFT_CNT)

/*
 * Macro to setup PCI Extended Configuration Space (ECS) address to give to
 * "in/out" instructions
 *
 * NOTE: Should only be used in lgrp_plat_init() before MMIO setup because any
 *	 other uses should just do MMIO to access PCI ECS.
 *	 Must enable special bit in Northbridge Configuration Register on
 *	 Greyhound for extended CF8 space access to be able to access PCI ECS
 *	 using "in/out" instructions and restore special bit after done
 *	 accessing PCI ECS.
 */
#define	OPT_PCI_ECS_ADDR(bus, device, function, reg) \
	(PCI_CONE | (((bus) & 0xff) << 16) | (((device & 0x1f)) << 11)  | \
	    (((function) & 0x7) << 8) | ((reg) & 0xfc) | \
	    ((((reg) >> 8) & 0xf) << 24))

/*
 * PCI configuration space registers accessed by specifying
 * a bus, device, function, and offset.  The following constants
 * define the values needed to access Opteron K8 configuration
 * info to determine its node topology
 */

#define	OPT_PCS_BUS_CONFIG	0	/* Hypertransport config space bus */

/*
 * Opteron PCI configuration space register function values
 */
#define	OPT_PCS_FUNC_HT		0	/* Hypertransport configuration */
#define	OPT_PCS_FUNC_ADDRMAP	1	/* Address map configuration */
#define	OPT_PCS_FUNC_DRAM	2	/* DRAM configuration */
#define	OPT_PCS_FUNC_MISC	3	/* Miscellaneous configuration */

/*
 * PCI Configuration Space register offsets
 */
#define	OPT_PCS_OFF_VENDOR	0x0	/* device/vendor ID register */
#define	OPT_PCS_OFF_DRAMBASE_HI	0x140	/* DRAM Base register (node 0) */
#define	OPT_PCS_OFF_DRAMBASE_LO	0x40	/* DRAM Base register (node 0) */
#define	OPT_PCS_OFF_NODEID	0x60	/* Node ID register */

/*
 * Opteron PCI Configuration Space device IDs for nodes
 */
#define	OPT_PCS_DEV_NODE0		24	/* device number for node 0 */


/*
 * Opteron DRAM address map gives base and limit for physical memory in a node
 */
typedef	struct opt_dram_addr_map {
	uint32_t	base_hi;
	uint32_t	base_lo;
	uint32_t	limit_hi;
	uint32_t	limit_lo;
} opt_dram_addr_map_t;


/*
 * Supported AMD processor families
 */
#define	AMD_FAMILY_HAMMER	15
#define	AMD_FAMILY_GREYHOUND	16

/*
 * Whether to have is_opteron() return 1 even when processor isn't supported
 */
uint_t	is_opteron_override = 0;

/*
 * AMD processor family for current CPU
 */
uint_t	opt_family = 0;


/*
 * Determine whether we're running on a supported AMD Opteron since reading
 * node count and DRAM address map registers may have different format or
 * may not be supported across processor families
 */
static int
is_opteron(void)
{

	if (x86_vendor != X86_VENDOR_AMD)
		return (0);

	opt_family = cpuid_getfamily(CPU);
	if (opt_family == AMD_FAMILY_HAMMER ||
	    opt_family == AMD_FAMILY_GREYHOUND || is_opteron_override)
		return (1);
	else
		return (0);
}


/*
 * Determine NUMA configuration for Opteron from registers that live in PCI
 * configuration space
 */
static void
opt_get_numa_config(uint_t *node_cnt, int *mem_intrlv,
    node_phys_addr_map_t *node_memory)
{
	uint_t				bus;
	uint_t				dev;
	struct opt_dram_addr_map	dram_map[MAX_NODES];
	uint_t				node;
	uint_t				node_info[MAX_NODES];
	uint_t				off_hi;
	uint_t				off_lo;
	uint64_t			nb_cfg_reg;

	/*
	 * Read configuration registers from PCI configuration space to
	 * determine node information, which memory is in each node, etc.
	 *
	 * Write to PCI configuration space address register to specify
	 * which configuration register to read and read/write PCI
	 * configuration space data register to get/set contents
	 */
	bus = OPT_PCS_BUS_CONFIG;
	dev = OPT_PCS_DEV_NODE0;
	off_hi = OPT_PCS_OFF_DRAMBASE_HI;
	off_lo = OPT_PCS_OFF_DRAMBASE_LO;

	/*
	 * Read node ID register for node 0 to get node count
	 */
	node_info[0] = pci_getl_func(bus, dev, OPT_PCS_FUNC_HT,
	    OPT_PCS_OFF_NODEID);
	*node_cnt = OPT_NODE_CNT(node_info[0]) + 1;

	/*
	 * If number of nodes is more than maximum supported, then set node
	 * count to 1 and treat system as UMA instead of NUMA.
	 */
	if (*node_cnt > MAX_NODES) {
		*node_cnt = 1;
		return;
	}

	/*
	 * For Greyhound, PCI Extended Configuration Space must be enabled to
	 * read high DRAM address map base and limit registers
	 */
	if (opt_family == AMD_FAMILY_GREYHOUND) {
		nb_cfg_reg = rdmsr(MSR_AMD_NB_CFG);
		if ((nb_cfg_reg & AMD_GH_NB_CFG_EN_ECS) == 0)
			wrmsr(MSR_AMD_NB_CFG,
			    nb_cfg_reg | AMD_GH_NB_CFG_EN_ECS);
	}

	for (node = 0; node < *node_cnt; node++) {
		uint32_t	base_hi;
		uint32_t	base_lo;
		uint32_t	limit_hi;
		uint32_t	limit_lo;

		/*
		 * Read node ID register (except for node 0 which we just read)
		 */
		if (node > 0) {
			node_info[node] = pci_getl_func(bus, dev,
			    OPT_PCS_FUNC_HT, OPT_PCS_OFF_NODEID);
		}

		/*
		 * Read DRAM base and limit registers which specify
		 * physical memory range of each node
		 */
		if (opt_family != AMD_FAMILY_GREYHOUND)
			base_hi = 0;
		else {
			outl(PCI_CONFADD, OPT_PCI_ECS_ADDR(bus, dev,
			    OPT_PCS_FUNC_ADDRMAP, off_hi));
			base_hi = dram_map[node].base_hi =
			    inl(PCI_CONFDATA);
		}
		base_lo = dram_map[node].base_lo = pci_getl_func(bus, dev,
		    OPT_PCS_FUNC_ADDRMAP, off_lo);

		if ((dram_map[node].base_lo & OPT_DRAMBASE_LO_MASK_INTRLVEN) &&
		    mem_intrlv)
			*mem_intrlv = *mem_intrlv + 1;

		off_hi += 4;	/* high limit register offset */
		if (opt_family != AMD_FAMILY_GREYHOUND)
			limit_hi = 0;
		else {
			outl(PCI_CONFADD, OPT_PCI_ECS_ADDR(bus, dev,
			    OPT_PCS_FUNC_ADDRMAP, off_hi));
			limit_hi = dram_map[node].limit_hi =
			    inl(PCI_CONFDATA);
		}

		off_lo += 4;	/* low limit register offset */
		limit_lo = dram_map[node].limit_lo = pci_getl_func(bus,
		    dev, OPT_PCS_FUNC_ADDRMAP, off_lo);

		/*
		 * Increment device number to next node and register offsets
		 * for DRAM base register of next node
		 */
		off_hi += 4;
		off_lo += 4;
		dev++;

		/*
		 * Both read and write enable bits must be enabled in DRAM
		 * address map base register for physical memory to exist in
		 * node
		 */
		if ((base_lo & OPT_DRAMBASE_LO_MASK_RE) == 0 ||
		    (base_lo & OPT_DRAMBASE_LO_MASK_WE) == 0) {
			/*
			 * Mark node memory as non-existent and set start and
			 * end addresses to be same in node_memory[]
			 */
			node_memory[node].exists = 0;
			node_memory[node].start = node_memory[node].end =
			    (pfn_t)-1;
			continue;
		}

		/*
		 * Mark node memory as existing and remember physical address
		 * range of each node for use later
		 */
		node_memory[node].exists = 1;

		node_memory[node].start = btop(OPT_DRAMADDR(base_hi, base_lo));

		node_memory[node].end = btop(OPT_DRAMADDR(limit_hi, limit_lo) |
		    OPT_DRAMADDR_LO_MASK_OFF);
	}

	/*
	 * Restore PCI Extended Configuration Space enable bit
	 */
	if (opt_family == AMD_FAMILY_GREYHOUND) {
		if ((nb_cfg_reg & AMD_GH_NB_CFG_EN_ECS) == 0)
			wrmsr(MSR_AMD_NB_CFG, nb_cfg_reg);
	}
}


/*
 * Return average amount of time to read vendor ID register on Northbridge
 * N times on specified destination node from current CPU
 */
static hrtime_t
opt_probe_vendor(int dest_node, int nreads)
{
	int		cnt;
	uint_t		dev;
	/* LINTED: set but not used in function */
	volatile uint_t	dev_vendor;
	hrtime_t	elapsed;
	hrtime_t	end;
	int		ipl;
	hrtime_t	start;

	dev = OPT_PCS_DEV_NODE0 + dest_node;
	kpreempt_disable();
	ipl = spl8();
	outl(PCI_CONFADD, PCI_CADDR1(0, dev, OPT_PCS_FUNC_DRAM,
	    OPT_PCS_OFF_VENDOR));
	start = gethrtime();
	for (cnt = 0; cnt < nreads; cnt++)
		dev_vendor = inl(PCI_CONFDATA);
	end = gethrtime();
	elapsed = (end - start) / nreads;
	splx(ipl);
	kpreempt_enable();
	return (elapsed);
}
