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


#include <sys/archsystm.h>	/* for {in,out}{b,w,l}() */
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
#include <sys/systm.h>
#include <sys/thread.h>
#include <sys/types.h>
#include <sys/var.h>
#include <sys/x86_archext.h>	/* for x86_feature and X86_AMD */
#include <vm/hat_i86.h>
#include <vm/seg_kmem.h>
#include <vm/vm_dep.h>


/*
 * lgroup platform support for x86 platforms.
 */

#define	MAX_NODES		8
#define	NLGRP			(MAX_NODES * (MAX_NODES - 1) + 1)

#define	LGRP_PLAT_CPU_TO_NODE(cpu) (pg_plat_hw_instance_id(cpu, PGHW_CHIP))

#define	LGRP_PLAT_PROBE_NROUNDS		64	/* default laps for probing */
#define	LGRP_PLAT_PROBE_NSAMPLES	1	/* default samples to take */
#define	LGRP_PLAT_PROBE_NREADS		256	/* number of vendor ID reads */

/*
 * Multiprocessor Opteron machines have Non Uniform Memory Access (NUMA).
 *
 * Until this code supports reading System Resource Affinity Table (SRAT),
 * we need to examine registers in PCI configuration space to determine how
 * many nodes are in the system and which CPUs and memory are in each node.
 * This could be determined by probing all memory from each CPU, but that is
 * too expensive to do while booting the kernel.
 *
 * NOTE: Using these PCI configuration space registers to determine this
 *       locality info is not guaranteed to work on future generations of
 *	 Opteron processor.
 */

/*
 * Opteron DRAM Address Map in PCI configuration space gives base and limit
 * of physical memory in each node.  The following constants and macros define
 * their contents, structure, and access.
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
 * Bookkeeping for latencies seen during probing (used for verification)
 */
typedef	struct lgrp_plat_latency_acct {
	hrtime_t	la_value;	/* latency value */
	int		la_count;	/* occurrences */
} lgrp_plat_latency_acct_t;


/*
 * Choices for probing to determine lgroup topology
 */
typedef	enum lgrp_plat_probe_op {
	LGRP_PLAT_PROBE_PGCPY,		/* Use page copy */
	LGRP_PLAT_PROBE_VENDOR		/* Read vendor ID on Northbridge */
} lgrp_plat_probe_op_t;


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
 * Starting and ending page for physical memory in node
 */
typedef	struct phys_addr_map {
	pfn_t	start;
	pfn_t	end;
	int	exists;
} phys_addr_map_t;


/*
 * Opteron DRAM address map for each node
 */
struct opt_dram_addr_map	opt_dram_map[MAX_NODES];

/*
 * Node ID register contents for each node
 */
uint_t				opt_node_info[MAX_NODES];

/*
 * Whether memory is interleaved across nodes causing MPO to be disabled
 */
int			lgrp_plat_mem_intrlv = 0;

/*
 * Number of nodes in system
 */
uint_t			lgrp_plat_node_cnt = 1;

/*
 * Physical address range for memory in each node
 */
phys_addr_map_t		lgrp_plat_node_memory[MAX_NODES];

/*
 * Probe costs (individual and total) and flush cost
 */
hrtime_t		lgrp_plat_flush_cost = 0;
hrtime_t		lgrp_plat_probe_cost = 0;
hrtime_t		lgrp_plat_probe_cost_total = 0;

/*
 * Error code for latency adjustment and verification
 */
int			lgrp_plat_probe_error_code = 0;

/*
 * How much latencies were off from minimum values gotten
 */
hrtime_t		lgrp_plat_probe_errors[MAX_NODES][MAX_NODES];

/*
 * Unique probe latencies and number of occurrences of each
 */
lgrp_plat_latency_acct_t	lgrp_plat_probe_lat_acct[MAX_NODES];

/*
 * Size of memory buffer in each node for probing
 */
size_t			lgrp_plat_probe_memsize = 0;

/*
 * Virtual address of page in each node for probing
 */
caddr_t			lgrp_plat_probe_memory[MAX_NODES];

/*
 * Number of unique latencies in probe times
 */
int			lgrp_plat_probe_nlatencies = 0;

/*
 * How many rounds of probing to do
 */
int			lgrp_plat_probe_nrounds = LGRP_PLAT_PROBE_NROUNDS;

/*
 * Number of samples to take when probing each node
 */
int			lgrp_plat_probe_nsamples = LGRP_PLAT_PROBE_NSAMPLES;

/*
 * Number of times to read vendor ID from Northbridge for each probe.
 */
int			lgrp_plat_probe_nreads = LGRP_PLAT_PROBE_NREADS;

/*
 * How to probe to determine lgroup topology
 */
lgrp_plat_probe_op_t	lgrp_plat_probe_op = LGRP_PLAT_PROBE_VENDOR;

/*
 * PFN of page in each node for probing
 */
pfn_t			lgrp_plat_probe_pfn[MAX_NODES];

/*
 * Whether probe time was suspect (ie. not within tolerance of value that it
 * should match)
 */
int			lgrp_plat_probe_suspect[MAX_NODES][MAX_NODES];

/*
 * How long it takes to access memory from each node
 */
hrtime_t		lgrp_plat_probe_times[MAX_NODES][MAX_NODES];

/*
 * Min and max node memory probe times seen
 */
hrtime_t		lgrp_plat_probe_time_max = 0;
hrtime_t		lgrp_plat_probe_time_min = -1;
hrtime_t		lgrp_plat_probe_max[MAX_NODES][MAX_NODES];
hrtime_t		lgrp_plat_probe_min[MAX_NODES][MAX_NODES];


/*
 * Allocate lgrp and lgrp stat arrays statically.
 */
static lgrp_t	lgrp_space[NLGRP];
static int	nlgrps_alloc;

struct lgrp_stats lgrp_stats[NLGRP];

/*
 * Supported AMD processor families
 */
#define	AMD_FAMILY_HAMMER	15
#define	AMD_FAMILY_GREYHOUND	16

/*
 * Whether to have is_opteron() return 1 even when processor isn't
 * supported
 */
uint_t	is_opteron_override = 0;

/*
 * AMD processor family for current CPU
 */
uint_t	opt_family = 0;

uint_t	opt_probe_func = OPT_PCS_FUNC_DRAM;


/*
 * Determine whether we're running on a supported AMD Opteron since reading
 * node count and DRAM address map registers may have different format or
 * may not be supported in future processor families
 */
int
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

int
plat_lgrphand_to_mem_node(lgrp_handle_t hand)
{
	if (max_mem_nodes == 1)
		return (0);

	return ((int)hand);
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

	ASSERT(node < lgrp_plat_node_cnt);
	return (-1);
}

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
	uint_t		bus;
	uint_t		dev;
	uint_t		node;
	uint_t		off_hi;
	uint_t		off_lo;
	uint64_t	nb_cfg_reg;

	extern lgrp_load_t	lgrp_expand_proc_thresh;
	extern lgrp_load_t	lgrp_expand_proc_diff;

	/*
	 * Initialize as a UMA machine if this isn't an Opteron
	 */
	if (!is_opteron() || lgrp_topo_ht_limit() == 1) {
		lgrp_plat_node_cnt = max_mem_nodes = 1;
		return;
	}

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
	opt_node_info[0] = pci_getl_func(bus, dev, OPT_PCS_FUNC_HT,
	    OPT_PCS_OFF_NODEID);
	lgrp_plat_node_cnt = OPT_NODE_CNT(opt_node_info[0]) + 1;

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

	for (node = 0; node < lgrp_plat_node_cnt; node++) {
		uint32_t	base_hi;
		uint32_t	base_lo;
		uint32_t	limit_hi;
		uint32_t	limit_lo;

		/*
		 * Read node ID register (except for node 0 which we just read)
		 */
		if (node > 0) {
			opt_node_info[node] = pci_getl_func(bus, dev,
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
			base_hi = opt_dram_map[node].base_hi =
			    inl(PCI_CONFDATA);
		}
		base_lo = opt_dram_map[node].base_lo = pci_getl_func(bus, dev,
		    OPT_PCS_FUNC_ADDRMAP, off_lo);

		if (opt_dram_map[node].base_lo & OPT_DRAMBASE_LO_MASK_INTRLVEN)
			lgrp_plat_mem_intrlv++;

		off_hi += 4;	/* high limit register offset */
		if (opt_family != AMD_FAMILY_GREYHOUND)
			limit_hi = 0;
		else {
			outl(PCI_CONFADD, OPT_PCI_ECS_ADDR(bus, dev,
			    OPT_PCS_FUNC_ADDRMAP, off_hi));
			limit_hi = opt_dram_map[node].limit_hi =
			    inl(PCI_CONFDATA);
		}

		off_lo += 4;	/* low limit register offset */
		limit_lo = opt_dram_map[node].limit_lo = pci_getl_func(bus,
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
			 * end addresses to be same in lgrp_plat_node_memory[]
			 */
			lgrp_plat_node_memory[node].exists = 0;
			lgrp_plat_node_memory[node].start =
			    lgrp_plat_node_memory[node].end = (pfn_t)-1;
			continue;
		}

		/*
		 * Get PFN for first page in each node,
		 * so we can probe memory to determine latency topology
		 */
		lgrp_plat_probe_pfn[node] =
		    btop(OPT_DRAMADDR(base_hi, base_lo));

		/*
		 * Mark node memory as existing and remember physical address
		 * range of each node for use later
		 */
		lgrp_plat_node_memory[node].exists = 1;

		lgrp_plat_node_memory[node].start =
		    btop(OPT_DRAMADDR(base_hi, base_lo));

		lgrp_plat_node_memory[node].end =
		    btop(OPT_DRAMADDR(limit_hi, limit_lo) |
		    OPT_DRAMADDR_LO_MASK_OFF);
	}

	/*
	 * Restore PCI Extended Configuration Space enable bit
	 */
	if (opt_family == AMD_FAMILY_GREYHOUND) {
		if ((nb_cfg_reg & AMD_GH_NB_CFG_EN_ECS) == 0)
			wrmsr(MSR_AMD_NB_CFG, nb_cfg_reg);
	}

	/*
	 * Only use one memory node if memory is interleaved between any nodes
	 */
	if (lgrp_plat_mem_intrlv) {
		lgrp_plat_node_cnt = max_mem_nodes = 1;
		(void) lgrp_topo_ht_limit_set(1);
	} else {
		max_mem_nodes = lgrp_plat_node_cnt;

		/*
		 * Probing errors can mess up the lgroup topology and force us
		 * fall back to a 2 level lgroup topology.  Here we bound how
		 * tall the lgroup topology can grow in hopes of avoiding any
		 * anamolies in probing from messing up the lgroup topology
		 * by limiting the accuracy of the latency topology.
		 *
		 * Assume that nodes will at least be configured in a ring,
		 * so limit height of lgroup topology to be less than number
		 * of nodes on a system with 4 or more nodes
		 */
		if (lgrp_plat_node_cnt >= 4 &&
		    lgrp_topo_ht_limit() == lgrp_topo_ht_limit_default())
			(void) lgrp_topo_ht_limit_set(lgrp_plat_node_cnt - 1);
	}

	/*
	 * Lgroups on Opteron architectures have but a single physical
	 * processor. Tune lgrp_expand_proc_thresh and lgrp_expand_proc_diff
	 * so that lgrp_choose() will spread things out aggressively.
	 */
	lgrp_expand_proc_thresh = LGRP_LOADAVG_THREAD_MAX / 2;
	lgrp_expand_proc_diff = 0;
#endif	/* __xpv */
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
lgrp_plat_latency_adjust(void)
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
	 * Nothing to do when this is an UMA machine
	 */
	if (max_mem_nodes == 1)
		return;

	/*
	 * Make sure that latencies are symmetric between any two nodes
	 * (ie. latency(node0, node1) == latency(node1, node0))
	 */
	for (i = 0; i < lgrp_plat_node_cnt; i++)
		for (j = 0; j < lgrp_plat_node_cnt; j++) {
			t1 = lgrp_plat_probe_times[i][j];
			t2 = lgrp_plat_probe_times[j][i];

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
				lgrp_plat_probe_errors[i][j] += t1 - t2;
				if (t1 - t2 > t2 >> lgrp_plat_probe_lt_shift) {
					lgrp_plat_probe_suspect[i][j]++;
					lgrp_plat_probe_suspect[j][i]++;
				}
			} else if (t2 > t1) {
				t = t1;
				lgrp_plat_probe_errors[j][i] += t2 - t1;
				if (t2 - t1 > t1 >> lgrp_plat_probe_lt_shift) {
					lgrp_plat_probe_suspect[i][j]++;
					lgrp_plat_probe_suspect[j][i]++;
				}
			}

			lgrp_plat_probe_times[i][j] =
			    lgrp_plat_probe_times[j][i] = t;
			lgrp_config(cflag, t1, t);
			lgrp_config(cflag, t2, t);
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
	for (i = 0; i < lgrp_plat_node_cnt; i++)
		for (j = 0; j < lgrp_plat_node_cnt; j++) {
			/*
			 * Pick one pair of nodes (i, j)
			 * and get latency between them
			 */
			t1 = lgrp_plat_probe_times[i][j];

			/*
			 * Skip this pair of nodes if there isn't a latency
			 * for it yet
			 */
			if (t1 == 0)
				continue;

			for (k = 0; k < lgrp_plat_node_cnt; k++)
				for (l = 0; l < lgrp_plat_node_cnt; l++) {
					/*
					 * Pick another pair of nodes (k, l)
					 * not same as (i, j) and get latency
					 * between them
					 */
					if (k == i && l == j)
						continue;

					t2 = lgrp_plat_probe_times[k][l];

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

					lgrp_plat_probe_times[i][j] =
					    lgrp_plat_probe_times[k][l] = t;

					lat_corrected[i][j] =
					    lat_corrected[k][l] = 1;
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
		t = lgrp_plat_probe_times[i][i];
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

			local = lgrp_plat_probe_times[i][i];
			if (local == 0)
				continue;

			/*
			 * Track suspect probe times that aren't within
			 * tolerance of minimum local latency and how much
			 * probe times are corrected by
			 */
			if (local - min > min >> lgrp_plat_probe_lt_shift)
				lgrp_plat_probe_suspect[i][i]++;

			lgrp_plat_probe_errors[i][i] += local - min;

			/*
			 * Make local latencies be minimum
			 */
			lgrp_config(LGRP_CONFIG_LAT_CHANGE, i, min);
			lgrp_plat_probe_times[i][i] = min;
		}
	}

	/*
	 * Determine max probe time again since just adjusted latencies
	 */
	lgrp_plat_probe_time_max = 0;
	for (i = 0; i < lgrp_plat_node_cnt; i++)
		for (j = 0; j < lgrp_plat_node_cnt; j++) {
			t = lgrp_plat_probe_times[i][j];
			if (t > lgrp_plat_probe_time_max)
				lgrp_plat_probe_time_max = t;
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
 *	-4	Wrong number of latencies
 *	-5	Not enough occurrences of given latency
 */
static int
lgrp_plat_latency_verify(void)
{
	int				i;
	int				j;
	lgrp_plat_latency_acct_t	*l;
	int				probed;
	u_longlong_t			t1;
	u_longlong_t			t2;

	/*
	 * Nothing to do when this is an UMA machine, lgroup topology is
	 * limited to 2 levels, or there aren't any probe times yet
	 */
	if (max_mem_nodes == 1 || lgrp_topo_levels < 2 ||
	    (lgrp_plat_probe_time_max == 0 && lgrp_plat_probe_time_min == -1))
		return (0);

	/*
	 * Make sure that latencies are symmetric between any two nodes
	 * (ie. latency(node0, node1) == latency(node1, node0))
	 */
	for (i = 0; i < lgrp_plat_node_cnt; i++)
		for (j = 0; j < lgrp_plat_node_cnt; j++) {
			t1 = lgrp_plat_probe_times[i][j];
			t2 = lgrp_plat_probe_times[j][i];

			if (t1 == 0 || t2 == 0 || t1 == t2)
				continue;

			return (-1);
		}

	/*
	 * Local latencies should be same
	 */
	t1 = lgrp_plat_probe_times[0][0];
	for (i = 1; i < lgrp_plat_node_cnt; i++) {
		t2 = lgrp_plat_probe_times[i][i];
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
		for (i = 0; i < lgrp_plat_node_cnt; i++)
			for (j = 0; j < lgrp_plat_node_cnt; j++) {
				t2 = lgrp_plat_probe_times[i][j];
				if (i == j || t2 == 0)
					continue;

				if (t1 >= t2)
					return (-3);
			}
	}

	/*
	 * Rest of checks are not very useful for machines with less than
	 * 4 nodes (which means less than 3 latencies on Opteron)
	 */
	if (lgrp_plat_node_cnt < 4)
		return (0);

	/*
	 * Need to see whether done probing in order to verify number of
	 * latencies are correct
	 */
	probed = 0;
	for (i = 0; i < lgrp_plat_node_cnt; i++)
		if (lgrp_plat_probe_times[i][i])
			probed++;

	if (probed != lgrp_plat_node_cnt)
		return (0);

	/*
	 * Determine number of unique latencies seen in probe times,
	 * their values, and number of occurrences of each
	 */
	lgrp_plat_probe_nlatencies = 0;
	bzero(lgrp_plat_probe_lat_acct,
	    MAX_NODES * sizeof (lgrp_plat_latency_acct_t));
	for (i = 0; i < lgrp_plat_node_cnt; i++) {
		for (j = 0; j < lgrp_plat_node_cnt; j++) {
			int	k;

			/*
			 * Look at each probe time
			 */
			t1 = lgrp_plat_probe_times[i][j];
			if (t1 == 0)
				continue;

			/*
			 * Account for unique latencies
			 */
			for (k = 0; k < lgrp_plat_node_cnt; k++) {
				l = &lgrp_plat_probe_lat_acct[k];
				if (t1 == l->la_value) {
					/*
					 * Increment number of occurrences
					 * if seen before
					 */
					l->la_count++;
					break;
				} else if (l->la_value == 0) {
					/*
					 * Record latency if haven't seen before
					 */
					l->la_value = t1;
					l->la_count++;
					lgrp_plat_probe_nlatencies++;
					break;
				}
			}
		}
	}

	/*
	 * Number of latencies should be relative to number of
	 * nodes in system:
	 * - Same as nodes when nodes <= 2
	 * - Less than nodes when nodes > 2
	 * - Greater than 2 when nodes >= 4
	 */
	if ((lgrp_plat_node_cnt <= 2 &&
	    lgrp_plat_probe_nlatencies != lgrp_plat_node_cnt) ||
	    (lgrp_plat_node_cnt > 2 &&
	    lgrp_plat_probe_nlatencies >= lgrp_plat_node_cnt) ||
	    (lgrp_plat_node_cnt >= 4 && lgrp_topo_levels >= 3 &&
	    lgrp_plat_probe_nlatencies <= 2))
		return (-4);

	/*
	 * There should be more than one occurrence of every latency
	 * as long as probing is complete
	 */
	for (i = 0; i < lgrp_plat_probe_nlatencies; i++) {
		l = &lgrp_plat_probe_lat_acct[i];
		if (l->la_count <= 1)
			return (-5);
	}
	return (0);
}


/*
 * Set lgroup latencies for 2 level lgroup topology
 */
static void
lgrp_plat_2level_setup(void)
{
	int	i;

	if (lgrp_plat_node_cnt >= 4)
		cmn_err(CE_NOTE,
		    "MPO only optimizing for local and remote\n");
	for (i = 0; i < lgrp_plat_node_cnt; i++) {
		int	j;

		for (j = 0; j < lgrp_plat_node_cnt; j++) {
			if (i == j)
				lgrp_plat_probe_times[i][j] = 2;
			else
				lgrp_plat_probe_times[i][j] = 3;
		}
	}
	lgrp_plat_probe_time_min = 2;
	lgrp_plat_probe_time_max = 3;
	lgrp_config(LGRP_CONFIG_FLATTEN, 2, 0);
}


/*
 * Return time needed to probe from current CPU to memory in given node
 */
static hrtime_t
lgrp_plat_probe_time(int to)
{
	caddr_t		buf;
	uint_t		dev;
	/* LINTED: set but not used in function */
	volatile uint_t	dev_vendor;
	hrtime_t	elapsed;
	hrtime_t	end;
	int		from;
	int		i;
	int		ipl;
	hrtime_t	max;
	hrtime_t	min;
	hrtime_t	start;
	int		cnt;
	extern int	use_sse_pagecopy;

	/*
	 * Determine ID of node containing current CPU
	 */
	from = LGRP_PLAT_CPU_TO_NODE(CPU);

	/*
	 * Do common work for probing main memory
	 */
	if (lgrp_plat_probe_op == LGRP_PLAT_PROBE_PGCPY) {
		/*
		 * Skip probing any nodes without memory and
		 * set probe time to 0
		 */
		if (lgrp_plat_probe_memory[to] == NULL) {
			lgrp_plat_probe_times[from][to] = 0;
			return (0);
		}

		/*
		 * Invalidate caches once instead of once every sample
		 * which should cut cost of probing by a lot
		 */
		lgrp_plat_flush_cost = gethrtime();
		invalidate_cache();
		lgrp_plat_flush_cost = gethrtime() - lgrp_plat_flush_cost;
		lgrp_plat_probe_cost_total += lgrp_plat_flush_cost;
	}

	/*
	 * Probe from current CPU to given memory using specified operation
	 * and take specified number of samples
	 */
	max = 0;
	min = -1;
	for (i = 0; i < lgrp_plat_probe_nsamples; i++) {
		lgrp_plat_probe_cost = gethrtime();

		/*
		 * Can't measure probe time if gethrtime() isn't working yet
		 */
		if (lgrp_plat_probe_cost == 0 && gethrtime() == 0)
			return (0);

		switch (lgrp_plat_probe_op) {

		case LGRP_PLAT_PROBE_PGCPY:
		default:
			/*
			 * Measure how long it takes to copy page
			 * on top of itself
			 */
			buf = lgrp_plat_probe_memory[to] + (i * PAGESIZE);

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
			break;

		case LGRP_PLAT_PROBE_VENDOR:
			/*
			 * Measure how long it takes to read vendor ID from
			 * Northbridge
			 */
			dev = OPT_PCS_DEV_NODE0 + to;
			kpreempt_disable();
			ipl = spl8();
			outl(PCI_CONFADD, PCI_CADDR1(0, dev, opt_probe_func,
			    OPT_PCS_OFF_VENDOR));
			start = gethrtime();
			for (cnt = 0; cnt < lgrp_plat_probe_nreads; cnt++)
				dev_vendor = inl(PCI_CONFDATA);
			end = gethrtime();
			elapsed = (end - start) / lgrp_plat_probe_nreads;
			splx(ipl);
			kpreempt_enable();
			break;
		}

		lgrp_plat_probe_cost = gethrtime() - lgrp_plat_probe_cost;
		lgrp_plat_probe_cost_total += lgrp_plat_probe_cost;

		if (min == -1 || elapsed < min)
			min = elapsed;
		if (elapsed > max)
			max = elapsed;
	}

	/*
	 * Update minimum and maximum probe times between
	 * these two nodes
	 */
	if (min < lgrp_plat_probe_min[from][to] ||
	    lgrp_plat_probe_min[from][to] == 0)
		lgrp_plat_probe_min[from][to] = min;

	if (max > lgrp_plat_probe_max[from][to])
		lgrp_plat_probe_max[from][to] = max;

	return (min);
}


/*
 * Probe memory in each node from current CPU to determine latency topology
 */
void
lgrp_plat_probe(void)
{
	int		from;
	int		i;
	hrtime_t	probe_time;
	int		to;

	if (max_mem_nodes == 1 || lgrp_topo_ht_limit() <= 2)
		return;

	/*
	 * Determine ID of node containing current CPU
	 */
	from = LGRP_PLAT_CPU_TO_NODE(CPU);

	/*
	 * Don't need to probe if got times already
	 */
	if (lgrp_plat_probe_times[from][from] != 0)
		return;

	/*
	 * Read vendor ID in Northbridge or read and write page(s)
	 * in each node from current CPU and remember how long it takes,
	 * so we can build latency topology of machine later.
	 * This should approximate the memory latency between each node.
	 */
	for (i = 0; i < lgrp_plat_probe_nrounds; i++)
		for (to = 0; to < lgrp_plat_node_cnt; to++) {
			/*
			 * Get probe time and bail out if can't get it yet
			 */
			probe_time = lgrp_plat_probe_time(to);
			if (probe_time == 0)
				return;

			/*
			 * Keep lowest probe time as latency between nodes
			 */
			if (lgrp_plat_probe_times[from][to] == 0 ||
			    probe_time < lgrp_plat_probe_times[from][to])
				lgrp_plat_probe_times[from][to] = probe_time;

			/*
			 * Update overall minimum and maximum probe times
			 * across all nodes
			 */
			if (probe_time < lgrp_plat_probe_time_min ||
			    lgrp_plat_probe_time_min == -1)
				lgrp_plat_probe_time_min = probe_time;
			if (probe_time > lgrp_plat_probe_time_max)
				lgrp_plat_probe_time_max = probe_time;
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
	lgrp_plat_latency_adjust();
	lgrp_plat_probe_error_code = lgrp_plat_latency_verify();
	if (lgrp_plat_probe_error_code)
		lgrp_plat_2level_setup();
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
	 * Don't bother to do any probing if there is only one node or the
	 * height of the lgroup topology less than or equal to 2
	 */
	ht_limit = lgrp_topo_ht_limit();
	if (max_mem_nodes == 1 || ht_limit <= 2) {
		/*
		 * Setup lgroup latencies for 2 level lgroup topology
		 * (ie. local and remote only) if they haven't been set yet
		 */
		if (ht_limit == 2 && lgrp_plat_probe_time_min == -1 &&
		    lgrp_plat_probe_time_max == 0)
			lgrp_plat_2level_setup();
		return;
	}

	if (lgrp_plat_probe_op == LGRP_PLAT_PROBE_VENDOR) {
		/*
		 * Should have been able to probe from CPU 0 when it was added
		 * to lgroup hierarchy, but may not have been able to then
		 * because it happens so early in boot that gethrtime() hasn't
		 * been initialized.  (:-(
		 */
		curnode = LGRP_PLAT_CPU_TO_NODE(CPU);
		if (lgrp_plat_probe_times[curnode][curnode] == 0)
			lgrp_plat_probe();

		return;
	}

	/*
	 * When probing memory, use one page for every sample to determine
	 * lgroup topology and taking multiple samples
	 */
	if (lgrp_plat_probe_memsize == 0)
		lgrp_plat_probe_memsize = PAGESIZE *
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
			lgrp_plat_probe_memory[i] = NULL;
			continue;
		}

		/*
		 * Allocate one kernel virtual page
		 */
		lgrp_plat_probe_memory[i] = vmem_alloc(heap_arena,
		    lgrp_plat_probe_memsize, VM_NOSLEEP);
		if (lgrp_plat_probe_memory[i] == NULL) {
			cmn_err(CE_WARN,
			    "lgrp_plat_main_init: couldn't allocate memory");
			return;
		}

		/*
		 * Map virtual page to first page in node
		 */
		hat_devload(kas.a_hat, lgrp_plat_probe_memory[i],
		    lgrp_plat_probe_memsize,
		    lgrp_plat_probe_pfn[i],
		    PROT_READ | PROT_WRITE | HAT_PLAT_NOCACHE,
		    HAT_LOAD_NOCONSIST);
	}

	/*
	 * Probe from current CPU
	 */
	lgrp_plat_probe();
}

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
	if (lgrp_plat_node_cnt == 1)
		return (LGRP_DEFAULT_HANDLE);

	return ((lgrp_handle_t)LGRP_PLAT_CPU_TO_NODE(cpu[id]));
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
 * Return the maximum number of lgrps supported by the platform.
 * Before lgrp topology is known it returns an estimate based on the number of
 * nodes. Once topology is known it returns the actual maximim number of lgrps
 * created. Since x86 doesn't support dynamic addition of new nodes, this number
 * may not grow during system lifetime.
 */
int
lgrp_plat_max_lgrps()
{
	return (lgrp_topo_initialized ?
	    lgrp_alloc_max + 1 :
	    lgrp_plat_node_cnt * (lgrp_plat_node_cnt - 1) + 1);
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

	if (max_mem_nodes == 1)
		return (0);

	/*
	 * Return max latency for root lgroup
	 */
	if (from == LGRP_DEFAULT_HANDLE || to == LGRP_DEFAULT_HANDLE)
		return (lgrp_plat_probe_time_max);

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
	if (lgrp_plat_probe_times[src][src] == 0 &&
	    LGRP_PLAT_CPU_TO_NODE(CPU) == src)
		lgrp_plat_probe();

	return (lgrp_plat_probe_times[src][dest]);
}

/*
 * Return platform handle for root lgroup
 */
lgrp_handle_t
lgrp_plat_root_hand(void)
{
	return (LGRP_DEFAULT_HANDLE);
}
