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

#include <sys/time.h>
#include <sys/cpuvar.h>
#include <sys/dditypes.h>
#include <sys/ddipropdefs.h>
#include <sys/ddi_impldefs.h>
#include <sys/sunddi.h>
#include <sys/esunddi.h>
#include <sys/sunndi.h>
#include <sys/platform_module.h>
#include <sys/errno.h>
#include <sys/conf.h>
#include <sys/modctl.h>
#include <sys/promif.h>
#include <sys/promimpl.h>
#include <sys/prom_plat.h>
#include <sys/cmn_err.h>
#include <sys/sysmacros.h>
#include <sys/mem_cage.h>
#include <sys/kobj.h>
#include <sys/utsname.h>
#include <sys/cpu_sgnblk_defs.h>
#include <sys/atomic.h>
#include <sys/kdi_impl.h>

#include <sys/sgsbbc.h>
#include <sys/sgsbbc_iosram.h>
#include <sys/sgsbbc_iosram_priv.h>
#include <sys/sgsbbc_mailbox.h>
#include <sys/sgsgn.h>
#include <sys/sgcn.h>
#include <sys/serengeti.h>
#include <sys/sgfrutypes.h>
#include <sys/machsystm.h>
#include <sys/sbd_ioctl.h>
#include <sys/sbd.h>
#include <sys/sbdp_mem.h>

#include <sys/memnode.h>
#include <vm/vm_dep.h>
#include <vm/page.h>

#include <sys/cheetahregs.h>
#include <sys/plat_ecc_unum.h>
#include <sys/plat_ecc_dimm.h>

#include <sys/lgrp.h>

static int sg_debug = 0;

#ifdef DEBUG
#define	DCMNERR if (sg_debug) cmn_err
#else
#define	DCMNERR
#endif

int (*p2get_mem_unum)(int, uint64_t, char *, int, int *);

/* local functions */
static void cpu_sgn_update(ushort_t sgn, uchar_t state,
    uchar_t sub_state, int cpuid);


/*
 * Local data.
 *
 * iosram_write_ptr is a pointer to iosram_write().  Because of
 * kernel dynamic linking, we can't get to the function by name,
 * but we can look up its address, and store it in this variable
 * instead.
 *
 * We include the extern for iosram_write() here not because we call
 * it, but to force compilation errors if its prototype doesn't
 * match the prototype of iosram_write_ptr.
 *
 * The same issues apply to iosram_read() and iosram_read_ptr.
 */
/*CSTYLED*/
extern int   iosram_write     (int, uint32_t, caddr_t, uint32_t);
static int (*iosram_write_ptr)(int, uint32_t, caddr_t, uint32_t) = NULL;
/*CSTYLED*/
extern int   iosram_read     (int, uint32_t, caddr_t, uint32_t);
static int (*iosram_read_ptr)(int, uint32_t, caddr_t, uint32_t) = NULL;


/*
 * Variable to indicate if the date should be obtained from the SC or not.
 */
int todsg_use_sc = FALSE;	/* set the false at the beginning */

/*
 * Preallocation of spare tsb's for DR
 *
 * We don't allocate spares for Wildcat since TSBs should come
 * out of memory local to the node.
 */
#define	IOMMU_PER_SCHIZO	2
int serengeti_tsb_spares = (SG_MAX_IO_BDS * SG_SCHIZO_PER_IO_BD *
	IOMMU_PER_SCHIZO);

/*
 * sg_max_ncpus is the maximum number of CPUs supported on Serengeti.
 * sg_max_ncpus is set to be smaller than NCPU to reduce the amount of
 * memory the logs take up until we have a dynamic log memory allocation
 * solution.
 */
int sg_max_ncpus = (24 * 2);    /* (max # of processors * # of cores/proc) */

/*
 * variables to control mailbox message timeouts.
 * These can be patched via /etc/system or mdb.
 */
int	sbbc_mbox_default_timeout = MBOX_DEFAULT_TIMEOUT;
int	sbbc_mbox_min_timeout = MBOX_MIN_TIMEOUT;

/* cached 'chosen' node_id */
pnode_t chosen_nodeid = (pnode_t)0;

static void (*sg_ecc_taskq_func)(sbbc_ecc_mbox_t *) = NULL;
static int (*sg_ecc_mbox_func)(sbbc_ecc_mbox_t *) = NULL;

/*
 * Table that maps memory slices to a specific memnode.
 */
int slice_to_memnode[SG_MAX_SLICE];

plat_dimm_sid_board_t	domain_dimm_sids[SG_MAX_CPU_BDS];


int
set_platform_tsb_spares()
{
	return (MIN(serengeti_tsb_spares, MAX_UPA));
}

#pragma weak mmu_init_large_pages

void
set_platform_defaults(void)
{
	extern int watchdog_enable;
	extern uint64_t xc_tick_limit_scale;
	extern void mmu_init_large_pages(size_t);

#ifdef DEBUG
	char *todsg_name = "todsg";
	ce_verbose_memory = 2;
	ce_verbose_other = 2;
#endif /* DEBUG */

	watchdog_enable = TRUE;
	watchdog_available = TRUE;

	cpu_sgn_func = cpu_sgn_update;

#ifdef DEBUG
	/* tod_module_name should be set to "todsg" from OBP property */
	if (tod_module_name && (strcmp(tod_module_name, todsg_name) == 0))
		prom_printf("Using todsg driver\n");
	else {
		prom_printf("Force using todsg driver\n");
		tod_module_name = todsg_name;
	}
#endif /* DEBUG */

	/* Serengeti does not support forthdebug */
	forthdebug_supported = 0;


	/*
	 * Some DR operations require the system to be sync paused.
	 * Sync pause on Serengeti could potentially take up to 4
	 * seconds to complete depending on the load on the SC.  To
	 * avoid send_mond panics during such operations, we need to
	 * increase xc_tick_limit to a larger value on Serengeti by
	 * setting xc_tick_limit_scale to 5.
	 */
	xc_tick_limit_scale = 5;

	if ((mmu_page_sizes == max_mmu_page_sizes) &&
	    (mmu_ism_pagesize != DEFAULT_ISM_PAGESIZE)) {
		if (&mmu_init_large_pages)
			mmu_init_large_pages(mmu_ism_pagesize);
	}
}

void
load_platform_modules(void)
{
	if (modload("misc", "pcihp") < 0) {
		cmn_err(CE_NOTE, "pcihp driver failed to load");
	}
}

/*ARGSUSED*/
int
plat_cpu_poweron(struct cpu *cp)
{
	int (*serengeti_cpu_poweron)(struct cpu *) = NULL;

	serengeti_cpu_poweron =
	    (int (*)(struct cpu *))modgetsymvalue("sbdp_cpu_poweron", 0);

	if (serengeti_cpu_poweron == NULL)
		return (ENOTSUP);
	else
		return ((serengeti_cpu_poweron)(cp));
}

/*ARGSUSED*/
int
plat_cpu_poweroff(struct cpu *cp)
{
	int (*serengeti_cpu_poweroff)(struct cpu *) = NULL;

	serengeti_cpu_poweroff =
	    (int (*)(struct cpu *))modgetsymvalue("sbdp_cpu_poweroff", 0);

	if (serengeti_cpu_poweroff == NULL)
		return (ENOTSUP);
	else
		return ((serengeti_cpu_poweroff)(cp));
}

#ifdef DEBUG
pgcnt_t serengeti_cage_size_limit;
#endif

/* Preferred minimum cage size (expressed in pages)... for DR */
pgcnt_t serengeti_minimum_cage_size = 0;

void
set_platform_cage_params(void)
{
	extern pgcnt_t total_pages;
	extern struct memlist *phys_avail;

	if (kernel_cage_enable) {
		pgcnt_t preferred_cage_size;

		preferred_cage_size =
		    MAX(serengeti_minimum_cage_size, total_pages / 256);
#ifdef DEBUG
		if (serengeti_cage_size_limit)
			preferred_cage_size = serengeti_cage_size_limit;
#endif
		/*
		 * Post copies obp into the lowest slice.  This requires the
		 * cage to grow upwards
		 */
		kcage_range_init(phys_avail, KCAGE_UP, preferred_cage_size);
	}

	kcage_startup_dir = KCAGE_UP;

	/* Only note when the cage is off since it should always be on. */
	if (!kcage_on)
		cmn_err(CE_NOTE, "!DR Kernel Cage is DISABLED");
}

#define	ALIGN(x, a)	((a) == 0 ? (uint64_t)(x) : \
	(((uint64_t)(x) + (uint64_t)(a) - 1l) & ~((uint64_t)(a) - 1l)))

void
update_mem_bounds(int brd, uint64_t base, uint64_t sz)
{
	uint64_t	end;
	int		mnode;

	end = base + sz - 1;

	/*
	 * First see if this board already has a memnode associated
	 * with it.  If not, see if this slice has a memnode.  This
	 * covers the cases where a single slice covers multiple
	 * boards (cross-board interleaving) and where a single
	 * board has multiple slices (1+GB DIMMs).
	 */
	if ((mnode = plat_lgrphand_to_mem_node(brd)) == -1) {
		if ((mnode = slice_to_memnode[PA_2_SLICE(base)]) == -1)
			mnode = mem_node_alloc();
		plat_assign_lgrphand_to_mem_node(brd, mnode);
	}

	/*
	 * Align base at 16GB boundary
	 */
	base = ALIGN(base, (1ul << PA_SLICE_SHIFT));

	while (base < end) {
		slice_to_memnode[PA_2_SLICE(base)] = mnode;
		base += (1ul << PA_SLICE_SHIFT);
	}
}

/*
 * Dynamically detect memory slices in the system by decoding
 * the cpu memory decoder registers at boot time.
 */
void
plat_fill_mc(pnode_t nodeid)
{
	uint64_t	mc_addr, mask;
	uint64_t	mc_decode[SG_MAX_BANKS_PER_MC];
	uint64_t	base, size;
	uint32_t	regs[4];
	int		len;
	int		local_mc;
	int		portid;
	int		boardid;
	int		i;

	if ((prom_getprop(nodeid, "portid", (caddr_t)&portid) < 0) ||
	    (portid == -1))
		return;

	/*
	 * Decode the board number from the MC portid
	 */
	boardid = SG_PORTID_TO_BOARD_NUM(portid);

	/*
	 * The "reg" property returns 4 32-bit values. The first two are
	 * combined to form a 64-bit address.  The second two are for a
	 * 64-bit size, but we don't actually need to look at that value.
	 */
	len = prom_getproplen(nodeid, "reg");
	if (len != (sizeof (uint32_t) * 4)) {
		prom_printf("Warning: malformed 'reg' property\n");
		return;
	}
	if (prom_getprop(nodeid, "reg", (caddr_t)regs) < 0)
		return;
	mc_addr = ((uint64_t)regs[0]) << 32;
	mc_addr |= (uint64_t)regs[1];

	/*
	 * Figure out whether the memory controller we are examining
	 * belongs to this CPU or a different one.
	 */
	if (portid == cpunodes[CPU->cpu_id].portid)
		local_mc = 1;
	else
		local_mc = 0;

	for (i = 0; i < SG_MAX_BANKS_PER_MC; i++) {
		mask = SG_REG_2_OFFSET(i);

		/*
		 * If the memory controller is local to this CPU, we use
		 * the special ASI to read the decode registers.
		 * Otherwise, we load the values from a magic address in
		 * I/O space.
		 */
		if (local_mc)
			mc_decode[i] = lddmcdecode(mask & MC_OFFSET_MASK);
		else
			mc_decode[i] = lddphysio((mc_addr | mask));

		if (mc_decode[i] >> MC_VALID_SHIFT) {
			/*
			 * The memory decode register is a bitmask field,
			 * so we can decode that into both a base and
			 * a span.
			 */
			base = MC_BASE(mc_decode[i]) << PHYS2UM_SHIFT;
			size = MC_UK2SPAN(mc_decode[i]);
			update_mem_bounds(boardid, base, size);
		}
	}
}

/*
 * This routine is run midway through the boot process.  By the time we get
 * here, we know about all the active CPU boards in the system, and we have
 * extracted information about each board's memory from the memory
 * controllers.  We have also figured out which ranges of memory will be
 * assigned to which memnodes, so we walk the slice table to build the table
 * of memnodes.
 */
/* ARGSUSED */
void
plat_build_mem_nodes(prom_memlist_t *list, size_t  nelems)
{
	int	slice;
	pfn_t	basepfn;
	pgcnt_t	npgs;

	mem_node_pfn_shift = PFN_SLICE_SHIFT;
	mem_node_physalign = (1ull << PA_SLICE_SHIFT);

	for (slice = 0; slice < SG_MAX_SLICE; slice++) {
		if (slice_to_memnode[slice] == -1)
			continue;
		basepfn = (uint64_t)slice << PFN_SLICE_SHIFT;
		npgs = 1ull << PFN_SLICE_SHIFT;
		mem_node_add_slice(basepfn, basepfn + npgs - 1);
	}
}

int
plat_pfn_to_mem_node(pfn_t pfn)
{
	int node;

	node = slice_to_memnode[PFN_2_SLICE(pfn)];

	return (node);
}

/*
 * Serengeti support for lgroups.
 *
 * On Serengeti, an lgroup platform handle == board number.
 *
 * Mappings between lgroup handles and memnodes are managed
 * in addition to mappings between memory slices and memnodes
 * to support cross-board interleaving as well as multiple
 * slices per board (e.g. >1GB DIMMs). The initial mapping
 * of memnodes to lgroup handles is determined at boot time.
 * A DR addition of memory adds a new mapping. A DR copy-rename
 * swaps mappings.
 */

/*
 * Macro for extracting the board number from the CPU id
 */
#define	CPUID_TO_BOARD(id)	(((id) >> 2) & 0x7)

/*
 * Return the platform handle for the lgroup containing the given CPU
 *
 * For Serengeti, lgroup platform handle == board number
 */
lgrp_handle_t
plat_lgrp_cpu_to_hand(processorid_t id)
{
	return (CPUID_TO_BOARD(id));
}

/*
 * Platform specific lgroup initialization
 */
void
plat_lgrp_init(void)
{
	int i;
	extern uint32_t lgrp_expand_proc_thresh;
	extern uint32_t lgrp_expand_proc_diff;

	/*
	 * Initialize lookup tables to invalid values so we catch
	 * any illegal use of them.
	 */
	for (i = 0; i < SG_MAX_SLICE; i++) {
		slice_to_memnode[i] = -1;
	}

	/*
	 * Set tuneables for Serengeti architecture
	 *
	 * lgrp_expand_proc_thresh is the minimum load on the lgroups
	 * this process is currently running on before considering
	 * expanding threads to another lgroup.
	 *
	 * lgrp_expand_proc_diff determines how much less the remote lgroup
	 * must be loaded before expanding to it.
	 *
	 * Bandwidth is maximized on Serengeti by spreading load across
	 * the machine. The impact to inter-thread communication isn't
	 * too costly since remote latencies are relatively low.  These
	 * values equate to one CPU's load and so attempt to spread the
	 * load out across as many lgroups as possible one CPU at a time.
	 */
	lgrp_expand_proc_thresh = LGRP_LOADAVG_THREAD_MAX;
	lgrp_expand_proc_diff = LGRP_LOADAVG_THREAD_MAX;
}

/*
 * Platform notification of lgroup (re)configuration changes
 */
/*ARGSUSED*/
void
plat_lgrp_config(lgrp_config_flag_t evt, uintptr_t arg)
{
	update_membounds_t	*umb;
	lgrp_config_mem_rename_t lmr;
	lgrp_handle_t		shand, thand;
	int			snode, tnode;

	switch (evt) {

	case LGRP_CONFIG_MEM_ADD:
		umb = (update_membounds_t *)arg;
		update_mem_bounds(umb->u_board, umb->u_base, umb->u_len);

		break;

	case LGRP_CONFIG_MEM_DEL:
		/* We don't have to do anything */
		break;

	case LGRP_CONFIG_MEM_RENAME:
		/*
		 * During a DR copy-rename operation, all of the memory
		 * on one board is moved to another board -- but the
		 * addresses/pfns and memnodes don't change. This means
		 * the memory has changed locations without changing identity.
		 *
		 * Source is where we are copying from and target is where we
		 * are copying to.  After source memnode is copied to target
		 * memnode, the physical addresses of the target memnode are
		 * renamed to match what the source memnode had.  Then target
		 * memnode can be removed and source memnode can take its
		 * place.
		 *
		 * To do this, swap the lgroup handle to memnode mappings for
		 * the boards, so target lgroup will have source memnode and
		 * source lgroup will have empty target memnode which is where
		 * its memory will go (if any is added to it later).
		 *
		 * Then source memnode needs to be removed from its lgroup
		 * and added to the target lgroup where the memory was living
		 * but under a different name/memnode.  The memory was in the
		 * target memnode and now lives in the source memnode with
		 * different physical addresses even though it is the same
		 * memory.
		 */
		shand = arg & 0xffff;
		thand = (arg & 0xffff0000) >> 16;
		snode = plat_lgrphand_to_mem_node(shand);
		tnode = plat_lgrphand_to_mem_node(thand);

		plat_assign_lgrphand_to_mem_node(thand, snode);
		plat_assign_lgrphand_to_mem_node(shand, tnode);

		/*
		 * Remove source memnode of copy rename from its lgroup
		 * and add it to its new target lgroup
		 */
		lmr.lmem_rename_from = shand;
		lmr.lmem_rename_to = thand;

		lgrp_config(LGRP_CONFIG_MEM_RENAME, (uintptr_t)snode,
		    (uintptr_t)&lmr);

		break;

	default:
		break;
	}
}

/*
 * Return latency between "from" and "to" lgroups
 *
 * This latency number can only be used for relative comparison
 * between lgroups on the running system, cannot be used across platforms,
 * and may not reflect the actual latency.  It is platform and implementation
 * specific, so platform gets to decide its value.  It would be nice if the
 * number was at least proportional to make comparisons more meaningful though.
 * NOTE: The numbers below are supposed to be load latencies for uncached
 * memory divided by 10.
 */
int
plat_lgrp_latency(lgrp_handle_t from, lgrp_handle_t to)
{
	/*
	 * Return min remote latency when there are more than two lgroups
	 * (root and child) and getting latency between two different lgroups
	 * or root is involved
	 */
	if (lgrp_optimizations() && (from != to ||
	    from == LGRP_DEFAULT_HANDLE || to == LGRP_DEFAULT_HANDLE))
		return (28);
	else
		return (23);
}

/* ARGSUSED */
void
plat_freelist_process(int mnode)
{
}

/*
 * Find dip for chosen IOSRAM
 */
dev_info_t *
find_chosen_dip(void)
{
	dev_info_t	*dip;
	char		master_sbbc[MAXNAMELEN];
	pnode_t		nodeid;
	uint_t		tunnel;

	/*
	 * find the /chosen SBBC node, prom interface will handle errors
	 */
	nodeid = prom_chosennode();

	/*
	 * get the 'iosram' property from the /chosen node
	 */
	if (prom_getprop(nodeid, IOSRAM_CHOSEN_PROP, (caddr_t)&tunnel) <= 0) {
		SBBC_ERR(CE_PANIC, "No iosram property found! \n");
	}

	if (prom_phandle_to_path((phandle_t)tunnel, master_sbbc,
	    sizeof (master_sbbc)) < 0) {
		SBBC_ERR1(CE_PANIC, "prom_phandle_to_path(%d) failed\n",
		    tunnel);
	}

	chosen_nodeid = nodeid;

	/*
	 * load and attach the sgsbbc driver.
	 * This will also attach all the sgsbbc driver instances
	 */
	if (i_ddi_attach_hw_nodes("sgsbbc") != DDI_SUCCESS) {
		cmn_err(CE_WARN, "sgsbbc failed to load\n");
	}

	/* translate a path name to a dev_info_t */
	dip = e_ddi_hold_devi_by_path(master_sbbc, 0);
	if ((dip == NULL) || (ddi_get_nodeid(dip) != tunnel)) {
		cmn_err(CE_PANIC, "i_ddi_path_to_devi(%x) failed for SBBC\n",
		    tunnel);
	}

	/* make sure devi_ref is ZERO */
	ndi_rele_devi(dip);

	DCMNERR(CE_CONT, "Chosen IOSRAM is at %s \n", master_sbbc);

	return (dip);
}

void
load_platform_drivers(void)
{
	int ret;

	/*
	 * Load and attach the mc-us3 memory driver.
	 */
	if (i_ddi_attach_hw_nodes("mc-us3") != DDI_SUCCESS)
		cmn_err(CE_WARN, "mc-us3 failed to load");
	else
		(void) ddi_hold_driver(ddi_name_to_major("mc-us3"));

	/*
	 * Initialize the chosen IOSRAM before its clients
	 * are loaded.
	 */
	(void) find_chosen_dip();

	/*
	 * Ideally, we'd do this in set_platform_defaults(), but
	 * at that point it's too early to look up symbols.
	 */
	iosram_write_ptr = (int (*)(int, uint32_t, caddr_t, uint32_t))
	    modgetsymvalue("iosram_write", 0);

	if (iosram_write_ptr == NULL) {
		DCMNERR(CE_WARN, "load_platform_defaults: iosram_write()"
		    " not found; signatures will not be updated\n");
	} else {
		/*
		 * The iosram read ptr is only needed if we can actually
		 * write CPU signatures, so only bother setting it if we
		 * set a valid write pointer, above.
		 */
		iosram_read_ptr = (int (*)(int, uint32_t, caddr_t, uint32_t))
		    modgetsymvalue("iosram_read", 0);

		if (iosram_read_ptr == NULL)
			DCMNERR(CE_WARN, "load_platform_defaults: iosram_read()"
			    " not found\n");
	}

	/*
	 * Set todsg_use_sc to TRUE so that we will be getting date
	 * from the SC.
	 */
	todsg_use_sc = TRUE;

	/*
	 * Now is a good time to activate hardware watchdog (if one exists).
	 */
	mutex_enter(&tod_lock);
	if (watchdog_enable)
		ret = tod_ops.tod_set_watchdog_timer(watchdog_timeout_seconds);
	mutex_exit(&tod_lock);
	if (ret != 0)
		printf("Hardware watchdog enabled\n");

	/*
	 * Load and attach the schizo pci bus nexus driver.
	 */
	if (i_ddi_attach_hw_nodes("pcisch") != DDI_SUCCESS)
		cmn_err(CE_WARN, "pcisch failed to load");

	plat_ecc_init();
}

/*
 * No platform drivers on this platform
 */
char *platform_module_list[] = {
	(char *)0
};

/*ARGSUSED*/
void
plat_tod_fault(enum tod_fault_type tod_bad)
{
}
int
plat_max_boards()
{
	return (SG_MAX_BDS);
}
int
plat_max_io_units_per_board()
{
	return (SG_MAX_IO_PER_BD);
}
int
plat_max_cmp_units_per_board()
{
	return (SG_MAX_CMPS_PER_BD);
}
int
plat_max_cpu_units_per_board()
{
	return (SG_MAX_CPUS_PER_BD);
}

int
plat_max_mc_units_per_board()
{
	return (SG_MAX_CMPS_PER_BD); /* each CPU die has a memory controller */
}

int
plat_max_mem_units_per_board()
{
	return (SG_MAX_MEM_PER_BD);
}

int
plat_max_cpumem_boards(void)
{
	return (SG_MAX_CPU_BDS);
}

int
set_platform_max_ncpus(void)
{
	return (sg_max_ncpus);
}

void
plat_dmv_params(uint_t *hwint, uint_t *swint)
{
	*hwint = MAX_UPA;
	*swint = 0;
}

/*
 * Our nodename has been set, pass it along to the SC.
 */
void
plat_nodename_set(void)
{
	sbbc_msg_t	req;	/* request */
	sbbc_msg_t	resp;	/* response */
	int		rv;	/* return value from call to mbox */
	struct nodename_info {
		int32_t	namelen;
		char	nodename[_SYS_NMLN];
	} nni;
	int (*sg_mbox)(sbbc_msg_t *, sbbc_msg_t *, time_t) = NULL;

	/*
	 * find the symbol for the mailbox routine
	 */
	sg_mbox = (int (*)(sbbc_msg_t *, sbbc_msg_t *, time_t))
	    modgetsymvalue("sbbc_mbox_request_response", 0);

	if (sg_mbox == NULL) {
		cmn_err(CE_NOTE, "!plat_nodename_set: sg_mbox not found\n");
		return;
	}

	/*
	 * construct the message telling the SC our nodename
	 */
	(void) strcpy(nni.nodename, utsname.nodename);
	nni.namelen = (int32_t)strlen(nni.nodename);

	req.msg_type.type = INFO_MBOX;
	req.msg_type.sub_type = INFO_MBOX_NODENAME;
	req.msg_status = 0;
	req.msg_len = (int)(nni.namelen + sizeof (nni.namelen));
	req.msg_bytes = 0;
	req.msg_buf = (caddr_t)&nni;
	req.msg_data[0] = 0;
	req.msg_data[1] = 0;

	/*
	 * initialize the response back from the SC
	 */
	resp.msg_type.type = INFO_MBOX;
	resp.msg_type.sub_type = INFO_MBOX_NODENAME;
	resp.msg_status = 0;
	resp.msg_len = 0;
	resp.msg_bytes = 0;
	resp.msg_buf = (caddr_t)0;
	resp.msg_data[0] = 0;
	resp.msg_data[1] = 0;

	/*
	 * ship it and check for success
	 */
	rv = (sg_mbox)(&req, &resp, sbbc_mbox_default_timeout);

	if (rv != 0) {
		cmn_err(CE_NOTE, "!plat_nodename_set: sg_mbox retval %d\n", rv);
	} else if (resp.msg_status != 0) {
		cmn_err(CE_NOTE, "!plat_nodename_set: msg_status %d\n",
		    resp.msg_status);
	} else {
		DCMNERR(CE_NOTE, "!plat_nodename_set was successful\n");

		/*
		 * It is necessary to exchange the capability bitmap
		 * with SC before sending any ecc error information and
		 * indictment. We are calling the plat_ecc_capability_send()
		 * here just after sending the nodename successfully.
		 */
		rv = plat_ecc_capability_send();
		if (rv == 0) {
			DCMNERR(CE_NOTE, "!plat_ecc_capability_send was"
			    " successful\n");
		}
	}
}

/*
 * flag to allow users switch between using OBP's
 * prom_get_unum() and mc-us3 driver's p2get_mem_unum()
 * (for main memory errors only).
 */
int sg_use_prom_get_unum = 0;

/*
 * Debugging flag: set to 1 to call into obp for get_unum, or set it to 0
 * to call into the unum cache system.  This is the E$ equivalent of
 * sg_use_prom_get_unum.
 */
int sg_use_prom_ecache_unum = 0;

/* used for logging ECC errors to the SC */
#define	SG_MEMORY_ECC	1
#define	SG_ECACHE_ECC	2
#define	SG_UNKNOWN_ECC	(-1)

/*
 * plat_get_mem_unum() generates a string identifying either the
 * memory or E$ DIMM(s) during error logging. Depending on whether
 * the error is E$ or memory related, the appropriate support
 * routine is called to assist in the string generation.
 *
 * - For main memory errors we can use the mc-us3 drivers p2getunum()
 *   (or prom_get_unum() for debugging purposes).
 *
 * - For E$ errors we call sg_get_ecacheunum() to generate the unum (or
 *   prom_serengeti_get_ecacheunum() for debugging purposes).
 */

static int
sg_prom_get_unum(int synd_code, uint64_t paddr, char *buf, int buflen,
    int *lenp)
{
	if ((prom_get_unum(synd_code, (unsigned long long)paddr,
	    buf, buflen, lenp)) != 0)
		return (EIO);
	else if (*lenp <= 1)
		return (EINVAL);
	else
		return (0);
}

/*ARGSUSED*/
int
plat_get_mem_unum(int synd_code, uint64_t flt_addr, int flt_bus_id,
    int flt_in_memory, ushort_t flt_status, char *buf, int buflen, int *lenp)
{
	/*
	 * unum_func will either point to the memory drivers p2get_mem_unum()
	 * or to prom_get_unum() for memory errors.
	 */
	int (*unum_func)(int synd_code, uint64_t paddr, char *buf,
	    int buflen, int *lenp) = p2get_mem_unum;

	/*
	 * check if it's a Memory or an Ecache error.
	 */
	if (flt_in_memory) {
		/*
		 * It's a main memory error.
		 *
		 * For debugging we allow the user to switch between
		 * using OBP's get_unum and the memory driver's get_unum
		 * so we create a pointer to the functions and switch
		 * depending on the sg_use_prom_get_unum flag.
		 */
		if (sg_use_prom_get_unum) {
			DCMNERR(CE_NOTE, "Using prom_get_unum from OBP");
			return (sg_prom_get_unum(synd_code,
			    P2ALIGN(flt_addr, 8), buf, buflen, lenp));
		} else if (unum_func != NULL) {
			return (unum_func(synd_code, P2ALIGN(flt_addr, 8),
			    buf, buflen, lenp));
		} else {
			return (ENOTSUP);
		}
	} else if (flt_status & ECC_ECACHE) {
		/*
		 * It's an E$ error.
		 */
		if (sg_use_prom_ecache_unum) {
			/*
			 * We call to OBP to handle this.
			 */
			DCMNERR(CE_NOTE,
			    "Using prom_serengeti_get_ecacheunum from OBP");
			if (prom_serengeti_get_ecacheunum(flt_bus_id,
			    P2ALIGN(flt_addr, 8), buf, buflen, lenp) != 0) {
				return (EIO);
			}
		} else {
			return (sg_get_ecacheunum(flt_bus_id, flt_addr,
			    buf, buflen, lenp));
		}
	} else {
		return (ENOTSUP);
	}

	return (0);
}

/*
 * This platform hook gets called from mc_add_mem_unum_label() in the mc-us3
 * driver giving each platform the opportunity to add platform
 * specific label information to the unum for ECC error logging purposes.
 */
void
plat_add_mem_unum_label(char *unum, int mcid, int bank, int dimm)
{
	char	new_unum[UNUM_NAMLEN] = "";
	int	node = SG_PORTID_TO_NODEID(mcid);
	int	board = SG_CPU_BD_PORTID_TO_BD_NUM(mcid);
	int	position = SG_PORTID_TO_CPU_POSN(mcid);

	/*
	 * The mc-us3 driver deals with logical banks but for unum
	 * purposes we need to use physical banks so that the correct
	 * dimm can be physically located. Logical banks 0 and 2
	 * make up physical bank 0. Logical banks 1 and 3 make up
	 * physical bank 1. Here we do the necessary conversion.
	 */
	bank = (bank % 2);

	if (dimm == -1) {
		SG_SET_FRU_NAME_NODE(new_unum, node);
		SG_SET_FRU_NAME_CPU_BOARD(new_unum, board);
		SG_SET_FRU_NAME_MODULE(new_unum, position);
		SG_SET_FRU_NAME_BANK(new_unum, bank);

	} else {
		SG_SET_FRU_NAME_NODE(new_unum, node);
		SG_SET_FRU_NAME_CPU_BOARD(new_unum, board);
		SG_SET_FRU_NAME_MODULE(new_unum, position);
		SG_SET_FRU_NAME_BANK(new_unum, bank);
		SG_SET_FRU_NAME_DIMM(new_unum, dimm);

		strcat(new_unum, " ");
		strcat(new_unum, unum);
	}

	strcpy(unum, new_unum);
}

int
plat_get_cpu_unum(int cpuid, char *buf, int buflen, int *lenp)
{
	int	node = SG_PORTID_TO_NODEID(cpuid);
	int	board = SG_CPU_BD_PORTID_TO_BD_NUM(cpuid);

	if (snprintf(buf, buflen, "/N%d/%s%d", node,
	    SG_HPU_TYPE_CPU_BOARD_ID, board) >= buflen) {
		return (ENOSPC);
	} else {
		*lenp = strlen(buf);
		return (0);
	}
}

/*
 * We log all ECC events to the SC so we send a mailbox
 * message to the SC passing it the relevant data.
 * ECC mailbox messages are sent via a taskq mechanism to
 * prevent impaired system performance during ECC floods.
 * Indictments have already passed through a taskq, so they
 * are not queued here.
 */
int
plat_send_ecc_mailbox_msg(plat_ecc_message_type_t msg_type, void *datap)
{
	sbbc_ecc_mbox_t	*msgp;
	size_t		msg_size;
	uint16_t	msg_subtype;
	int		sleep_flag, log_error;

	if (sg_ecc_taskq_func == NULL) {
		sg_ecc_taskq_func = (void (*)(sbbc_ecc_mbox_t *))
		    modgetsymvalue("sbbc_mbox_queue_ecc_event", 0);
		if (sg_ecc_taskq_func == NULL) {
			cmn_err(CE_NOTE, "!plat_send_ecc_mailbox_msg: "
			    "sbbc_mbox_queue_ecc_event not found");
			return (ENODEV);
		}
	}
	if (sg_ecc_mbox_func == NULL) {
		sg_ecc_mbox_func = (int (*)(sbbc_ecc_mbox_t *))
		    modgetsymvalue("sbbc_mbox_ecc_output", 0);
		if (sg_ecc_mbox_func == NULL) {
			cmn_err(CE_NOTE, "!plat_send_ecc_mailbox_msg: "
			    "sbbc_mbox_ecc_output not found");
			return (ENODEV);
		}
	}

	/*
	 * Initialize the request and response structures
	 */
	switch (msg_type) {
	case PLAT_ECC_ERROR_MESSAGE:
		msg_subtype = INFO_MBOX_ERROR_ECC;
		msg_size = sizeof (plat_ecc_error_data_t);
		sleep_flag = KM_NOSLEEP;
		log_error = 1;
		break;
	case PLAT_ECC_ERROR2_MESSAGE:
		msg_subtype = INFO_MBOX_ECC;
		msg_size = sizeof (plat_ecc_error2_data_t);
		sleep_flag = KM_NOSLEEP;
		log_error = 1;
		break;
	case PLAT_ECC_INDICTMENT_MESSAGE:
		msg_subtype = INFO_MBOX_ERROR_INDICT;
		msg_size = sizeof (plat_ecc_indictment_data_t);
		sleep_flag = KM_SLEEP;
		log_error = 0;
		break;
	case PLAT_ECC_INDICTMENT2_MESSAGE:
		msg_subtype = INFO_MBOX_ECC;
		msg_size = sizeof (plat_ecc_indictment2_data_t);
		sleep_flag = KM_SLEEP;
		log_error = 0;
		break;
	case PLAT_ECC_CAPABILITY_MESSAGE:
		msg_subtype = INFO_MBOX_ECC_CAP;
		msg_size = sizeof (plat_capability_data_t) +
		    strlen(utsname.release) + strlen(utsname.version) + 2;
		sleep_flag = KM_SLEEP;
		log_error = 0;
		break;
	case PLAT_ECC_DIMM_SID_MESSAGE:
		msg_subtype = INFO_MBOX_ECC;
		msg_size = sizeof (plat_dimm_sid_request_data_t);
		sleep_flag = KM_SLEEP;
		log_error = 0;
		break;
	default:
		return (EINVAL);
	}

	msgp = (sbbc_ecc_mbox_t	*)kmem_zalloc(sizeof (sbbc_ecc_mbox_t),
	    sleep_flag);
	if (msgp == NULL) {
		cmn_err(CE_NOTE, "!plat_send_ecc_mailbox_msg: "
		    "unable to allocate sbbc_ecc_mbox");
		return (ENOMEM);
	}

	msgp->ecc_log_error = log_error;

	msgp->ecc_req.msg_type.type = INFO_MBOX;
	msgp->ecc_req.msg_type.sub_type = msg_subtype;
	msgp->ecc_req.msg_status = 0;
	msgp->ecc_req.msg_len = (int)msg_size;
	msgp->ecc_req.msg_bytes = 0;
	msgp->ecc_req.msg_buf = (caddr_t)kmem_zalloc(msg_size, sleep_flag);
	msgp->ecc_req.msg_data[0] = 0;
	msgp->ecc_req.msg_data[1] = 0;

	if (msgp->ecc_req.msg_buf == NULL) {
		cmn_err(CE_NOTE, "!plat_send_ecc_mailbox_msg: "
		    "unable to allocate request msg_buf");
		kmem_free((void *)msgp, sizeof (sbbc_ecc_mbox_t));
		return (ENOMEM);
	}
	bcopy(datap, (void *)msgp->ecc_req.msg_buf, msg_size);

	/*
	 * initialize the response back from the SC
	 */
	msgp->ecc_resp.msg_type.type = INFO_MBOX;
	msgp->ecc_resp.msg_type.sub_type = msg_subtype;
	msgp->ecc_resp.msg_status = 0;
	msgp->ecc_resp.msg_len = 0;
	msgp->ecc_resp.msg_bytes = 0;
	msgp->ecc_resp.msg_buf = NULL;
	msgp->ecc_resp.msg_data[0] = 0;
	msgp->ecc_resp.msg_data[1] = 0;

	switch (msg_type) {
	case PLAT_ECC_ERROR_MESSAGE:
	case PLAT_ECC_ERROR2_MESSAGE:
		/*
		 * For Error Messages, we go through a taskq.
		 * Queue up the message for processing
		 */
		(*sg_ecc_taskq_func)(msgp);
		return (0);

	case PLAT_ECC_CAPABILITY_MESSAGE:
		/*
		 * For indictment and capability messages, we've already gone
		 * through the taskq, so we can call the mailbox routine
		 * directly.  Find the symbol for the routine that sends
		 * the mailbox msg
		 */
		msgp->ecc_resp.msg_len = (int)msg_size;
		msgp->ecc_resp.msg_buf = (caddr_t)kmem_zalloc(msg_size,
		    sleep_flag);
		/* FALLTHRU */

	case PLAT_ECC_INDICTMENT_MESSAGE:
	case PLAT_ECC_INDICTMENT2_MESSAGE:
		return ((*sg_ecc_mbox_func)(msgp));

	case PLAT_ECC_DIMM_SID_MESSAGE:
		msgp->ecc_resp.msg_len = sizeof (plat_dimm_sid_board_data_t);
		msgp->ecc_resp.msg_buf = (caddr_t)kmem_zalloc(
		    sizeof (plat_dimm_sid_board_data_t), sleep_flag);
		return ((*sg_ecc_mbox_func)(msgp));

	default:
		ASSERT(0);
		return (EINVAL);
	}
}

/*
 * m is redundant on serengeti as the multiplier is always 4
 */
/*ARGSUSED*/
int
plat_make_fru_cpuid(int sb, int m, int proc)
{
	return (MAKE_CPUID(sb, proc));
}

/*
 * board number for a given proc
 */
int
plat_make_fru_boardnum(int proc)
{
	return (SG_CPU_BD_PORTID_TO_BD_NUM(proc));
}

static
void
cpu_sgn_update(ushort_t sig, uchar_t state, uchar_t sub_state, int cpuid)
{
	uint32_t signature = CPU_SIG_BLD(sig, state, sub_state);
	sig_state_t current_sgn;
	int i;

	if (iosram_write_ptr == NULL) {
		/*
		 * If the IOSRAM write pointer isn't set, we won't be able
		 * to write signatures to ANYTHING, so we may as well just
		 * write out an error message (if desired) and exit this
		 * routine now...
		 */
		DCMNERR(CE_WARN,
		    "cpu_sgn_update: iosram_write() not found;"
		    " cannot write signature 0x%x for CPU(s) or domain\n",
		    signature);
		return;
	}


	/*
	 * Differentiate a panic reboot from a non-panic reboot in the
	 * setting of the substate of the signature.
	 *
	 * If the new substate is REBOOT and we're rebooting due to a panic,
	 * then set the new substate to a special value indicating a panic
	 * reboot, SIGSUBST_PANIC_REBOOT.
	 *
	 * A panic reboot is detected by a current (previous) domain signature
	 * state of SIGST_EXIT, and a new signature substate of SIGSUBST_REBOOT.
	 * The domain signature state SIGST_EXIT is used as the panic flow
	 * progresses.
	 *
	 * At the end of the panic flow, the reboot occurs but we should now
	 * one that was involuntary, something that may be quite useful to know
	 * at OBP level.
	 */
	if (sub_state == SIGSUBST_REBOOT) {
		if (iosram_read_ptr == NULL) {
			DCMNERR(CE_WARN,
			    "cpu_sgn_update: iosram_read() not found;"
			    " could not check current domain signature\n");
		} else {
			(void) (*iosram_read_ptr)(SBBC_SIGBLCK_KEY,
			    SG_SGNBLK_DOMAINSIG_OFFSET,
			    (char *)&current_sgn, sizeof (current_sgn));
			if (current_sgn.state_t.state == SIGST_EXIT)
				signature = CPU_SIG_BLD(sig, state,
				    SIGSUBST_PANIC_REBOOT);
		}
	}

	/*
	 * cpuid == -1 indicates that the operation applies to all cpus.
	 */
	if (cpuid >= 0) {
		(void) (*iosram_write_ptr)(SBBC_SIGBLCK_KEY,
		    SG_SGNBLK_CPUSIG_OFFSET(cpuid), (char *)&signature,
		    sizeof (signature));
	} else {
		for (i = 0; i < NCPU; i++) {
			if (cpu[i] == NULL || !(cpu[i]->cpu_flags &
			    (CPU_EXISTS|CPU_QUIESCED))) {
				continue;
			}
			(void) (*iosram_write_ptr)(SBBC_SIGBLCK_KEY,
			    SG_SGNBLK_CPUSIG_OFFSET(i), (char *)&signature,
			    sizeof (signature));
		}
	}

	if (state == SIGST_OFFLINE || state == SIGST_DETACHED) {
		return;
	}

	(void) (*iosram_write_ptr)(SBBC_SIGBLCK_KEY,
	    SG_SGNBLK_DOMAINSIG_OFFSET, (char *)&signature,
	    sizeof (signature));
}

void
startup_platform(void)
{
	/* set per-platform constants for mutex backoff */
	mutex_backoff_base = 1;
	mutex_cap_factor = 32;
}

/*
 * A routine to convert a number (represented as a string) to
 * the integer value it represents.
 */

static int
isdigit(int ch)
{
	return (ch >= '0' && ch <= '9');
}

#define	isspace(c)	((c) == ' ' || (c) == '\t' || (c) == '\n')

static int
strtoi(char *p, char **pos)
{
	int n;
	int c, neg = 0;

	if (!isdigit(c = *p)) {
		while (isspace(c))
			c = *++p;
		switch (c) {
			case '-':
				neg++;
				/* FALLTHROUGH */
			case '+':
			c = *++p;
		}
		if (!isdigit(c)) {
			if (pos != NULL)
				*pos = p;
			return (0);
		}
	}
	for (n = '0' - c; isdigit(c = *++p); ) {
		n *= 10; /* two steps to avoid unnecessary overflow */
		n += '0' - c; /* accum neg to avoid surprises at MAX */
	}
	if (pos != NULL)
		*pos = p;
	return (neg ? n : -n);
}

/*
 * Get the three parts of the Serengeti PROM version.
 * Used for feature readiness tests.
 *
 * Return 0 if version extracted successfully, -1 otherwise.
 */

int
sg_get_prom_version(int *sysp, int *intfp, int *bldp)
{
	int plen;
	char vers[512];
	static pnode_t node;
	static char version[] = "version";
	char *verp, *ep;

	node = prom_finddevice("/openprom");
	if (node == OBP_BADNODE)
		return (-1);

	plen = prom_getproplen(node, version);
	if (plen <= 0 || plen >= sizeof (vers))
		return (-1);
	(void) prom_getprop(node, version, vers);
	vers[plen] = '\0';

	/* Make sure it's an OBP flashprom */
	if (vers[0] != 'O' && vers[1] != 'B' && vers[2] != 'P') {
		cmn_err(CE_WARN, "sg_get_prom_version: "
		    "unknown <version> string in </openprom>\n");
		return (-1);
	}
	verp = &vers[4];

	*sysp = strtoi(verp, &ep);
	if (ep == verp || *ep != '.')
		return (-1);
	verp = ep + 1;

	*intfp = strtoi(verp, &ep);
	if (ep == verp || *ep != '.')
		return (-1);
	verp = ep + 1;

	*bldp = strtoi(verp, &ep);
	if (ep == verp || (*ep != '\0' && !isspace(*ep)))
		return (-1);
	return (0);
}

/*
 * Return 0 if system board Dynamic Reconfiguration
 * is supported by the firmware, -1 otherwise.
 */
int
sg_prom_sb_dr_check(void)
{
	static int prom_res = 1;

	if (prom_res == 1) {
		int sys, intf, bld;
		int rv;

		rv = sg_get_prom_version(&sys, &intf, &bld);
		if (rv == 0 && sys == 5 &&
		    (intf >= 12 || (intf == 11 && bld >= 200))) {
			prom_res = 0;
		} else {
			prom_res = -1;
		}
	}
	return (prom_res);
}

/*
 * Return 0 if cPCI Dynamic Reconfiguration
 * is supported by the firmware, -1 otherwise.
 */
int
sg_prom_cpci_dr_check(void)
{
	/*
	 * The version check is currently the same as for
	 * system boards. Since the two DR sub-systems are
	 * independent, this could change.
	 */
	return (sg_prom_sb_dr_check());
}

/*
 * KDI functions - used by the in-situ kernel debugger (kmdb) to perform
 * platform-specific operations.  These functions execute when the world is
 * stopped, and as such cannot make any blocking calls, hold locks, etc.
 * promif functions are a special case, and may be used.
 */

/*
 * Our implementation of this KDI op updates the CPU signature in the system
 * controller.  Note that we set the signature to OBP_SIG, rather than DBG_SIG.
 * The Forth words we execute will, among other things, transform our OBP_SIG
 * into DBG_SIG.  They won't function properly if we try to use DBG_SIG.
 */
static void
sg_system_claim(void)
{
	prom_interpret("sigb-sig! my-sigb-sig!", OBP_SIG, OBP_SIG, 0, 0, 0);
}

static void
sg_system_release(void)
{
	prom_interpret("sigb-sig! my-sigb-sig!", OS_SIG, OS_SIG, 0, 0, 0);
}

static void
sg_console_claim(void)
{
	prom_serengeti_set_console_input(SGCN_OBP_STR);
}

static void
sg_console_release(void)
{
	prom_serengeti_set_console_input(SGCN_CLNT_STR);
}

void
plat_kdi_init(kdi_t *kdi)
{
	kdi->pkdi_system_claim = sg_system_claim;
	kdi->pkdi_system_release = sg_system_release;
	kdi->pkdi_console_claim = sg_console_claim;
	kdi->pkdi_console_release = sg_console_release;
}
