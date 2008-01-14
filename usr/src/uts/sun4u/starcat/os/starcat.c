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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/sunddi.h>
#include <sys/esunddi.h>
#include <sys/sunndi.h>
#include <sys/modctl.h>
#include <sys/promif.h>
#include <sys/machparam.h>
#include <sys/kobj.h>
#include <sys/cpuvar.h>
#include <sys/mem_cage.h>
#include <sys/promif.h>
#include <sys/promimpl.h>
#include <sys/platform_module.h>
#include <sys/errno.h>
#include <sys/cpu_sgnblk_defs.h>
#include <sys/iosramio.h>
#include <sys/domaind.h>
#include <sys/starcat.h>
#include <sys/machsystm.h>
#include <sys/bootconf.h>
#include <sys/memnode.h>
#include <vm/vm_dep.h>
#include <vm/page.h>
#include <sys/cheetahregs.h>
#include <sys/plat_ecc_unum.h>
#include <sys/plat_ecc_dimm.h>
#include <sys/lgrp.h>
#include <sys/dr.h>
#include <sys/post/scat_dcd.h>
#include <sys/kdi_impl.h>
#include <sys/iosramreg.h>
#include <sys/iosramvar.h>
#include <sys/mc-us3.h>

/* Preallocation of spare tsb's for DR */
int starcat_tsb_spares = STARCAT_SPARE_TSB_MAX;

/* Set the maximum number of slot0 + slot1 boards. .. for DR */
int starcat_boards = STARCAT_BDSET_MAX * STARCAT_BDSET_SLOT_MAX;

/* Maximum number of cpus per board... for DR */
int starcat_cpu_per_board = MAX(STARCAT_SLOT0_CPU_MAX, STARCAT_SLOT1_CPU_MAX);

/* Maximum number of mem-units per board... for DR */
int starcat_mem_per_board = MAX(STARCAT_SLOT0_MEM_MAX, STARCAT_SLOT1_MEM_MAX);

/* Maximum number of io-units (buses) per board... for DR */
int starcat_io_per_board = 2 * MAX(STARCAT_SLOT0_IO_MAX, STARCAT_SLOT1_IO_MAX);

/* Preferred minimum cage size (expressed in pages)... for DR */
pgcnt_t starcat_startup_cage_size = 0;

/* Platform specific function to get unum information */
int (*p2get_mem_unum)(int, uint64_t, char *, int, int *);

/* Memory for fcode claims.  16k times # maximum possible schizos */
#define	EFCODE_SIZE	(STARCAT_BDSET_MAX * 4 * 0x4000)
int efcode_size = EFCODE_SIZE;

void sgn_update_all_cpus(ushort_t, uchar_t, uchar_t);

/*
 * The IOSRAM driver is loaded in load_platform_drivers() any cpu signature
 * usage prior to that time will have not have a function to call.
 */
static int (*iosram_rdp)(uint32_t key, uint32_t off, uint32_t len,
	    caddr_t dptr) = prom_starcat_iosram_read;
static int (*iosram_wrp)(uint32_t key, uint32_t off, uint32_t len,
	    caddr_t dptr) = prom_starcat_iosram_write;

plat_dimm_sid_board_t	domain_dimm_sids[STARCAT_BDSET_MAX];

/*
 * set_platform_max_ncpus should return the maximum number of CPUs that the
 * platform supports.  This function is called from check_cpus() to set the
 * value of max_ncpus [see PSARC 1997/165 CPU Dynamic Reconfiguration].
 * Data elements which are allocated based upon max_ncpus are all accessed
 * via cpu_seqid and not physical IDs.  Previously, the value of max_ncpus
 * was being set to the largest physical ID, which led to boot problems on
 * systems with less than 1.25GB of memory.
 */

int
set_platform_max_ncpus(void)
{
	int n;

	/*
	 * Convert number of slot0 + slot1 boards to number of expander brds
	 * and constrain the value to an architecturally plausible range
	 */
	n = MAX(starcat_boards, STARCAT_BDSET_MIN * STARCAT_BDSET_SLOT_MAX);
	n = MIN(n, STARCAT_BDSET_MAX * STARCAT_BDSET_SLOT_MAX);
	n = (n + STARCAT_BDSET_SLOT_MAX - 1) / STARCAT_BDSET_SLOT_MAX;

	/* return maximum number of cpus possible on N expander boards */
	return (n * STARCAT_BDSET_CPU_MAX - STARCAT_SLOT1_CPU_MAX);
}

int
set_platform_tsb_spares()
{
	return (MIN(starcat_tsb_spares, MAX_UPA));
}

#pragma weak mmu_init_large_pages

void
set_platform_defaults(void)
{
	extern char *tod_module_name;
	extern int ts_dispatch_extended;
	extern void cpu_sgn_update(ushort_t, uchar_t, uchar_t, int);
	extern int tsb_lgrp_affinity;
	extern int segkmem_reloc;
	extern void mmu_init_large_pages(size_t);
	extern int ncpunode;	/* number of CPUs detected by OBP */

#ifdef DEBUG
	ce_verbose_memory = 2;
	ce_verbose_other = 2;
#endif

	/* Set the CPU signature function pointer */
	cpu_sgn_func = cpu_sgn_update;

	/* Set appropriate tod module for starcat */
	ASSERT(tod_module_name == NULL);
	tod_module_name = "todstarcat";

	/*
	 * Use the alternate TS dispatch table, which is better
	 * tuned for large servers.
	 */
	if (ts_dispatch_extended == -1)
		ts_dispatch_extended = 1;

	/*
	 * Use lgroup-aware TSB allocations on this platform,
	 * since they are a considerable performance win.
	 */
	tsb_lgrp_affinity = 1;

	if ((mmu_page_sizes == max_mmu_page_sizes) &&
	    (mmu_ism_pagesize != DEFAULT_ISM_PAGESIZE)) {
		if (&mmu_init_large_pages)
			mmu_init_large_pages(mmu_ism_pagesize);
	}

	/*
	 * KPR (kernel page relocation) is supported on this platform.
	 */
	if (hat_kpr_enabled && kernel_cage_enable && ncpunode >= 32) {
		segkmem_reloc = 1;
		cmn_err(CE_NOTE, "!Kernel Page Relocation is ENABLED");
	} else {
		cmn_err(CE_NOTE, "!Kernel Page Relocation is DISABLED");
	}
}

#ifdef DEBUG
pgcnt_t starcat_cage_size_limit;
#endif

void
set_platform_cage_params(void)
{
	extern pgcnt_t total_pages;
	extern struct memlist *phys_avail;

	if (kernel_cage_enable) {
		pgcnt_t preferred_cage_size;

		preferred_cage_size =
		    MAX(starcat_startup_cage_size, total_pages / 256);

#ifdef DEBUG
		if (starcat_cage_size_limit)
			preferred_cage_size = starcat_cage_size_limit;
#endif
		/*
		 * Note: we are assuming that post has load the
		 * whole show in to the high end of memory. Having
		 * taken this leap, we copy the whole of phys_avail
		 * the glist and arrange for the cage to grow
		 * downward (descending pfns).
		 */
		kcage_range_init(phys_avail, KCAGE_DOWN, preferred_cage_size);
	}

	if (kcage_on)
		cmn_err(CE_NOTE, "!DR Kernel Cage is ENABLED");
	else
		cmn_err(CE_NOTE, "!DR Kernel Cage is DISABLED");
}

void
load_platform_modules(void)
{
	if (modload("misc", "pcihp") < 0) {
		cmn_err(CE_NOTE, "pcihp driver failed to load");
	}
}

/*
 * Starcat does not support power control of CPUs from the OS.
 */
/*ARGSUSED*/
int
plat_cpu_poweron(struct cpu *cp)
{
	int (*starcat_cpu_poweron)(struct cpu *) = NULL;

	starcat_cpu_poweron =
	    (int (*)(struct cpu *))kobj_getsymvalue("drmach_cpu_poweron", 0);

	if (starcat_cpu_poweron == NULL)
		return (ENOTSUP);
	else
		return ((starcat_cpu_poweron)(cp));
}

/*ARGSUSED*/
int
plat_cpu_poweroff(struct cpu *cp)
{
	int (*starcat_cpu_poweroff)(struct cpu *) = NULL;

	starcat_cpu_poweroff =
	    (int (*)(struct cpu *))kobj_getsymvalue("drmach_cpu_poweroff", 0);

	if (starcat_cpu_poweroff == NULL)
		return (ENOTSUP);
	else
		return ((starcat_cpu_poweroff)(cp));
}

/*
 * The following are currently private to Starcat DR
 */
int
plat_max_boards()
{
	return (starcat_boards);
}

int
plat_max_cpu_units_per_board()
{
	return (starcat_cpu_per_board);
}

int
plat_max_mc_units_per_board()
{
	return (starcat_mem_per_board); /* each CPU has a memory controller */
}

int
plat_max_mem_units_per_board()
{
	return (starcat_mem_per_board);
}

int
plat_max_io_units_per_board()
{
	return (starcat_io_per_board);
}

int
plat_max_cpumem_boards(void)
{
	return (STARCAT_BDSET_MAX);
}

int
plat_pfn_to_mem_node(pfn_t pfn)
{
	return (pfn >> mem_node_pfn_shift);
}

#define	STARCAT_MC_MEMBOARD_SHIFT 37	/* Boards on 128BG boundary */

/* ARGSUSED */
void
plat_build_mem_nodes(prom_memlist_t *list, size_t nelems)
{
	size_t	elem;
	pfn_t	basepfn;
	pgcnt_t	npgs;

	/*
	 * Starcat mem slices are always aligned on a 128GB boundary,
	 * fixed, and limited to one slice per expander due to design
	 * of the centerplane ASICs.
	 */
	mem_node_pfn_shift = STARCAT_MC_MEMBOARD_SHIFT - MMU_PAGESHIFT;
	mem_node_physalign = 0;

	/*
	 * Boot install lists are arranged <addr, len>, <addr, len>, ...
	 */
	for (elem = 0; elem < nelems; list++, elem++) {
		basepfn = btop(list->addr);
		npgs = btop(list->size);
		mem_node_add_slice(basepfn, basepfn + npgs - 1);
	}
}

/*
 * Find the CPU associated with a slice at boot-time.
 */
void
plat_fill_mc(pnode_t nodeid)
{
	int		len;
	uint64_t	mc_addr, mask;
	uint64_t	mc_decode[MAX_BANKS_PER_MC];
	uint32_t	regs[4];
	int		local_mc;
	int		portid;
	int		expnum;
	int		i;

	/*
	 * Memory address decoding registers
	 * (see Chap 9 of SPARCV9 JSP-1 US-III implementation)
	 */
	const uint64_t	mc_decode_addr[MAX_BANKS_PER_MC] = {
		0x400028, 0x400010, 0x400018, 0x400020
	};

	/*
	 * Starcat memory controller portid == global CPU id
	 */
	if ((prom_getprop(nodeid, "portid", (caddr_t)&portid) < 0) ||
	    (portid == -1))
		return;

	expnum = STARCAT_CPUID_TO_EXPANDER(portid);

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
	 * belongs to this CPU/CMP or a different one.
	 */
	if (portid == cpunodes[CPU->cpu_id].portid)
		local_mc = 1;
	else
		local_mc = 0;

	for (i = 0; i < MAX_BANKS_PER_MC; i++) {

		mask = mc_decode_addr[i];

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
			uint64_t base = MC_BASE(mc_decode[i]) << PHYS2UM_SHIFT;
			int sliceid = (base >> STARCAT_MC_MEMBOARD_SHIFT);

			if (sliceid < max_mem_nodes) {
				/*
				 * Establish start-of-day mappings of
				 * lgroup platform handles to memnodes.
				 * Handle == Expander Number
				 * Memnode == Fixed 128GB Slice
				 */
				plat_assign_lgrphand_to_mem_node(expnum,
				    sliceid);
			}
		}
	}
}

/*
 * Starcat support for lgroups.
 *
 * On Starcat, an lgroup platform handle == expander number.
 * For split-slot configurations (e.g. slot 0 and slot 1 boards
 * in different domains) an MCPU board has only remote memory.
 *
 * The centerplane logic provides fixed 128GB memory slices
 * each of which map to a memnode.  The initial mapping of
 * memnodes to lgroup handles is determined at boot time.
 * A DR addition of memory adds a new mapping. A DR copy-rename
 * swaps mappings.
 */

/*
 * Convert board number to expander number.
 */
#define	BOARDNUM_2_EXPANDER(b)	(b >> 1)

/*
 * Return the number of boards configured with NULL LPA.
 */
static int
check_for_null_lpa(void)
{
	gdcd_t	*gdcd;
	uint_t	exp, nlpa;

	/*
	 * Read GDCD from IOSRAM.
	 * If this fails indicate a NULL LPA condition.
	 */
	if ((gdcd = kmem_zalloc(sizeof (gdcd_t), KM_NOSLEEP)) == NULL)
		return (EXP_COUNT+1);

	if ((*iosram_rdp)(GDCD_MAGIC, 0, sizeof (gdcd_t), (caddr_t)gdcd) ||
	    (gdcd->h.dcd_magic != GDCD_MAGIC) ||
	    (gdcd->h.dcd_version != DCD_VERSION)) {
		kmem_free(gdcd, sizeof (gdcd_t));
		cmn_err(CE_WARN, "check_for_null_lpa: failed to access GDCD\n");
		return (EXP_COUNT+2);
	}

	/*
	 * Check for NULL LPAs on all slot 0 boards in domain
	 * (i.e. in all expanders marked good for this domain).
	 */
	nlpa = 0;
	for (exp = 0; exp < EXP_COUNT; exp++) {
		if (RSV_GOOD(gdcd->dcd_slot[exp][0].l1ss_rsv) &&
		    (gdcd->dcd_slot[exp][0].l1ss_flags &
		    L1SSFLG_THIS_L1_NULL_PROC_LPA))
			nlpa++;
	}

	kmem_free(gdcd, sizeof (gdcd_t));
	return (nlpa);
}

/*
 * Return the platform handle for the lgroup containing the given CPU
 *
 * For Starcat, lgroup platform handle == expander.
 */

extern int mpo_disabled;
extern lgrp_handle_t lgrp_default_handle;
int null_lpa_boards = -1;

lgrp_handle_t
plat_lgrp_cpu_to_hand(processorid_t id)
{
	lgrp_handle_t		plathand;

	plathand = STARCAT_CPUID_TO_EXPANDER(id);

	/*
	 * Return the real platform handle for the CPU until
	 * such time as we know that MPO should be disabled.
	 * At that point, we set the "mpo_disabled" flag to true,
	 * and from that point on, return the default handle.
	 *
	 * By the time we know that MPO should be disabled, the
	 * first CPU will have already been added to a leaf
	 * lgroup, but that's ok. The common lgroup code will
	 * double check that the boot CPU is in the correct place,
	 * and in the case where mpo should be disabled, will move
	 * it to the root if necessary.
	 */
	if (mpo_disabled) {
		/* If MPO is disabled, return the default (UMA) handle */
		plathand = lgrp_default_handle;
	} else {
		if (null_lpa_boards > 0) {
			/* Determine if MPO should be disabled */
			mpo_disabled = 1;
			plathand = lgrp_default_handle;
		}
	}
	return (plathand);
}

/*
 * Platform specific lgroup initialization
 */
void
plat_lgrp_init(void)
{
	extern uint32_t lgrp_expand_proc_thresh;
	extern uint32_t lgrp_expand_proc_diff;

	/*
	 * Set tuneables for Starcat architecture
	 *
	 * lgrp_expand_proc_thresh is the minimum load on the lgroups
	 * this process is currently running on before considering
	 * expanding threads to another lgroup.
	 *
	 * lgrp_expand_proc_diff determines how much less the remote lgroup
	 * must be loaded before expanding to it.
	 *
	 * Since remote latencies can be costly, attempt to keep 3 threads
	 * within the same lgroup before expanding to the next lgroup.
	 */
	lgrp_expand_proc_thresh = LGRP_LOADAVG_THREAD_MAX * 3;
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
	int			sbd, tbd;
	lgrp_handle_t		hand, shand, thand;
	int			mnode, snode, tnode;

	if (mpo_disabled)
		return;

	switch (evt) {

	case LGRP_CONFIG_MEM_ADD:
		/*
		 * Establish the lgroup handle to memnode translation.
		 */
		umb = (update_membounds_t *)arg;

		hand = BOARDNUM_2_EXPANDER(umb->u_board);
		mnode = plat_pfn_to_mem_node(umb->u_base >> MMU_PAGESHIFT);
		plat_assign_lgrphand_to_mem_node(hand, mnode);

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
		sbd = arg & 0xffff;
		tbd = (arg & 0xffff0000) >> 16;
		shand = BOARDNUM_2_EXPANDER(sbd);
		thand = BOARDNUM_2_EXPANDER(tbd);
		snode = plat_lgrphand_to_mem_node(shand);
		tnode = plat_lgrphand_to_mem_node(thand);

		plat_assign_lgrphand_to_mem_node(thand, snode);
		plat_assign_lgrphand_to_mem_node(shand, tnode);

		lmr.lmem_rename_from = shand;
		lmr.lmem_rename_to = thand;

		/*
		 * Remove source memnode of copy rename from its lgroup
		 * and add it to its new target lgroup
		 */
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
		return (48);
	else
		return (28);
}

/*
 * Return platform handle for root lgroup
 */
lgrp_handle_t
plat_lgrp_root_hand(void)
{
	if (mpo_disabled)
		return (lgrp_default_handle);

	return (LGRP_DEFAULT_HANDLE);
}

/* ARGSUSED */
void
plat_freelist_process(int mnode)
{
}

void
load_platform_drivers(void)
{
	uint_t		tunnel;
	pnode_t		nodeid;
	dev_info_t	*chosen_devi;
	char		chosen_iosram[MAXNAMELEN];

	/*
	 * Get /chosen node - that's where the tunnel property is
	 */
	nodeid = prom_chosennode();

	/*
	 * Get the iosram property from the chosen node.
	 */
	if (prom_getprop(nodeid, IOSRAM_CHOSEN_PROP, (caddr_t)&tunnel) <= 0) {
		prom_printf("Unable to get iosram property\n");
		cmn_err(CE_PANIC, "Unable to get iosram property\n");
	}

	if (prom_phandle_to_path((phandle_t)tunnel, chosen_iosram,
	    sizeof (chosen_iosram)) < 0) {
		(void) prom_printf("prom_phandle_to_path(0x%x) failed\n",
		    tunnel);
		cmn_err(CE_PANIC, "prom_phandle_to_path(0x%x) failed\n",
		    tunnel);
	}

	/*
	 * Attach all driver instances along the iosram's device path
	 */
	if (i_ddi_attach_hw_nodes("iosram") != DDI_SUCCESS) {
		cmn_err(CE_WARN, "IOSRAM failed to load\n");
	}

	if ((chosen_devi = e_ddi_hold_devi_by_path(chosen_iosram, 0)) == NULL) {
		(void) prom_printf("e_ddi_hold_devi_by_path(%s) failed\n",
		    chosen_iosram);
		cmn_err(CE_PANIC, "e_ddi_hold_devi_by_path(%s) failed\n",
		    chosen_iosram);
	}
	ndi_rele_devi(chosen_devi);

	/*
	 * iosram driver is now loaded so we need to set our read and
	 * write pointers.
	 */
	iosram_rdp = (int (*)(uint32_t, uint32_t, uint32_t, caddr_t))
	    modgetsymvalue("iosram_rd", 0);
	iosram_wrp = (int (*)(uint32_t, uint32_t, uint32_t, caddr_t))
	    modgetsymvalue("iosram_wr", 0);

	/*
	 * Need to check for null proc LPA after IOSRAM driver is loaded
	 * and before multiple lgroups created (when start_other_cpus() called)
	 */
	null_lpa_boards = check_for_null_lpa();

	/* load and attach the axq driver */
	if (i_ddi_attach_hw_nodes("axq") != DDI_SUCCESS) {
		cmn_err(CE_WARN, "AXQ failed to load\n");
	}

	/* load Starcat Solaris Mailbox Client driver */
	if (modload("misc", "scosmb") < 0) {
		cmn_err(CE_WARN, "SCOSMB failed to load\n");
	}

	/* load the DR driver */
	if (i_ddi_attach_hw_nodes("dr") != DDI_SUCCESS) {
		cmn_err(CE_WARN, "dr failed to load");
	}

	/*
	 * Load the mc-us3 memory driver.
	 */
	if (i_ddi_attach_hw_nodes("mc-us3") != DDI_SUCCESS)
		cmn_err(CE_WARN, "mc-us3 failed to load");
	else
		(void) ddi_hold_driver(ddi_name_to_major("mc-us3"));

	/* Load the schizo pci bus nexus driver. */
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

/*
 * Update the signature(s) in the IOSRAM's domain data section.
 */
void
cpu_sgn_update(ushort_t sgn, uchar_t state, uchar_t sub_state, int cpuid)
{
	sig_state_t new_sgn;
	sig_state_t current_sgn;

	/*
	 * If the substate is REBOOT, then check for panic flow
	 */
	if (sub_state == SIGSUBST_REBOOT) {
		(*iosram_rdp)(DOMD_MAGIC, DOMD_DSTATE_OFFSET,
		    sizeof (sig_state_t), (caddr_t)&current_sgn);
		if (current_sgn.state_t.state == SIGST_EXIT)
			sub_state = SIGSUBST_PANIC_REBOOT;
	}

	/*
	 * cpuid == -1 indicates that the operation applies to all cpus.
	 */
	if (cpuid < 0) {
		sgn_update_all_cpus(sgn, state, sub_state);
		return;
	}

	new_sgn.signature = CPU_SIG_BLD(sgn, state, sub_state);
	(*iosram_wrp)(DOMD_MAGIC,
	    DOMD_CPUSIGS_OFFSET + cpuid * sizeof (sig_state_t),
	    sizeof (sig_state_t), (caddr_t)&new_sgn);

	/*
	 * Under certain conditions we don't update the signature
	 * of the domain_state.
	 */
	if ((sgn == OS_SIG) &&
	    ((state == SIGST_OFFLINE) || (state == SIGST_DETACHED)))
		return;
	(*iosram_wrp)(DOMD_MAGIC, DOMD_DSTATE_OFFSET, sizeof (sig_state_t),
	    (caddr_t)&new_sgn);
}

/*
 * Update the signature(s) in the IOSRAM's domain data section for all CPUs.
 */
void
sgn_update_all_cpus(ushort_t sgn, uchar_t state, uchar_t sub_state)
{
	sig_state_t new_sgn;
	int i = 0;

	new_sgn.signature = CPU_SIG_BLD(sgn, state, sub_state);

	/*
	 * First update the domain_state signature
	 */
	(*iosram_wrp)(DOMD_MAGIC, DOMD_DSTATE_OFFSET, sizeof (sig_state_t),
	    (caddr_t)&new_sgn);

	for (i = 0; i < NCPU; i++) {
		if (cpu[i] != NULL && (cpu[i]->cpu_flags &
		    (CPU_EXISTS|CPU_QUIESCED))) {
			(*iosram_wrp)(DOMD_MAGIC,
			    DOMD_CPUSIGS_OFFSET + i * sizeof (sig_state_t),
			    sizeof (sig_state_t), (caddr_t)&new_sgn);
		}
	}
}

ushort_t
get_cpu_sgn(int cpuid)
{
	sig_state_t cpu_sgn;

	(*iosram_rdp)(DOMD_MAGIC,
	    DOMD_CPUSIGS_OFFSET + cpuid * sizeof (sig_state_t),
	    sizeof (sig_state_t), (caddr_t)&cpu_sgn);

	return (cpu_sgn.state_t.sig);
}

uchar_t
get_cpu_sgn_state(int cpuid)
{
	sig_state_t cpu_sgn;

	(*iosram_rdp)(DOMD_MAGIC,
	    DOMD_CPUSIGS_OFFSET + cpuid * sizeof (sig_state_t),
	    sizeof (sig_state_t), (caddr_t)&cpu_sgn);

	return (cpu_sgn.state_t.state);
}


/*
 * Type of argument passed into plat_get_ecache_cpu via ddi_walk_devs
 * for matching on specific CPU node in device tree
 */

typedef struct {
	char		*jnum;	/* output, kmem_alloc'd	if successful */
	int		cpuid;	/* input, to match cpuid/portid/upa-portid */
	uint_t		dimm;	/* input, index into ecache-dimm-label */
} plat_ecache_cpu_arg_t;


/*
 * plat_get_ecache_cpu is called repeatedly by ddi_walk_devs with pointers
 * to device tree nodes (dip) and to a plat_ecache_cpu_arg_t structure (arg).
 * Returning DDI_WALK_CONTINUE tells ddi_walk_devs to keep going, returning
 * DDI_WALK_TERMINATE ends the walk.  When the node for the specific CPU
 * being searched for is found, the walk is done.  But before returning to
 * ddi_walk_devs and plat_get_ecacheunum, we grab this CPU's ecache-dimm-label
 * property and set the jnum member of the plat_ecache_cpu_arg_t structure to
 * point to the label corresponding to this specific ecache DIMM.  It is up
 * to plat_get_ecacheunum to kmem_free this string.
 */

static int
plat_get_ecache_cpu(dev_info_t *dip, void *arg)
{
	char			*devtype;
	plat_ecache_cpu_arg_t	*cpuarg;
	char			**dimm_labels;
	uint_t			numlabels;
	int			portid;

	/*
	 * Check device_type, must be "cpu"
	 */

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "device_type", &devtype) != DDI_PROP_SUCCESS)
		return (DDI_WALK_CONTINUE);

	if (strcmp(devtype, "cpu")) {
		ddi_prop_free((void *)devtype);
		return (DDI_WALK_CONTINUE);
	}

	ddi_prop_free((void *)devtype);

	/*
	 * Check cpuid, portid, upa-portid (in that order), must
	 * match the cpuid being sought
	 */

	portid = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "cpuid", -1);

	if (portid == -1)
		portid = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "portid", -1);

	if (portid == -1)
		portid = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS, "upa-portid", -1);

	cpuarg = (plat_ecache_cpu_arg_t *)arg;

	if (portid != cpuarg->cpuid)
		return (DDI_WALK_CONTINUE);

	/*
	 * Found the right CPU, fetch ecache-dimm-label property
	 */

	if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "ecache-dimm-label", &dimm_labels, &numlabels)
	    != DDI_PROP_SUCCESS) {
#ifdef	DEBUG
		cmn_err(CE_NOTE, "cpuid=%d missing ecache-dimm-label property",
		    portid);
#endif	/* DEBUG */
		return (DDI_WALK_TERMINATE);
	}

	if (cpuarg->dimm < numlabels) {
		cpuarg->jnum = kmem_alloc(strlen(dimm_labels[cpuarg->dimm]) + 1,
		    KM_SLEEP);
		if (cpuarg->jnum != (char *)NULL)
			(void) strcpy(cpuarg->jnum, dimm_labels[cpuarg->dimm]);
#ifdef	DEBUG
		else
			cmn_err(CE_WARN,
			    "cannot kmem_alloc for ecache dimm label");
#endif	/* DEBUG */
	}

	ddi_prop_free((void *)dimm_labels);
	return (DDI_WALK_TERMINATE);
}


/*
 * Bit 4 of physical address indicates ecache 0 or 1
 */

#define	ECACHE_DIMM_MASK	0x10

/*
 * plat_get_ecacheunum is called to generate the unum for an ecache error.
 * After some initialization, nearly all of the work is done by ddi_walk_devs
 * and plat_get_ecache_cpu.
 */

int
plat_get_ecacheunum(int cpuid, unsigned long long physaddr, char *buf,
		    int buflen, int *ustrlen)
{
	plat_ecache_cpu_arg_t	findcpu;
	uint_t	expander, slot, proc;

	findcpu.jnum = (char *)NULL;
	findcpu.cpuid = cpuid;

	/*
	 * Bit 4 of physaddr equal 0 maps to E0 and 1 maps to E1
	 * except for Panther and Jaguar where it indicates the reverse
	 */
	if (IS_PANTHER(cpunodes[CPU->cpu_id].implementation) ||
	    IS_JAGUAR(cpunodes[CPU->cpu_id].implementation))
		findcpu.dimm =  (physaddr & ECACHE_DIMM_MASK) ? 0 : 1;
	else
		findcpu.dimm =  (physaddr & ECACHE_DIMM_MASK) ? 1 : 0;

	/*
	 * Walk the device tree, find this specific CPU, and get the label
	 * for this ecache, returned here in findcpu.jnum
	 */

	ddi_walk_devs(ddi_root_node(), plat_get_ecache_cpu, (void *)&findcpu);

	if (findcpu.jnum == (char *)NULL)
		return (-1);

	expander = STARCAT_CPUID_TO_EXPANDER(cpuid);
	slot = STARCAT_CPUID_TO_BOARDSLOT(cpuid);

	/*
	 * STARCAT_CPUID_TO_PORTID clears the CoreID bit so that
	 * STARCAT_CPUID_TO_AGENT will return a physical proc (0 - 3).
	 */
	proc = STARCAT_CPUID_TO_AGENT(STARCAT_CPUID_TO_PORTID(cpuid));

	/*
	 * NOTE: Any modifications to the snprintf() call below will require
	 * changing plat_log_fruid_error() as well!
	 */
	(void) snprintf(buf, buflen, "%s%u/P%u/E%u J%s", (slot ? "IO" : "SB"),
	    expander, proc, findcpu.dimm, findcpu.jnum);

	*ustrlen = strlen(buf);

	kmem_free(findcpu.jnum, strlen(findcpu.jnum) + 1);

	return (0);
}

/*ARGSUSED*/
int
plat_get_mem_unum(int synd_code, uint64_t flt_addr, int flt_bus_id,
    int flt_in_memory, ushort_t flt_status, char *buf, int buflen, int *lenp)
{
	int ret;

	/*
	 * check if it's a Memory or an Ecache error.
	 */
	if (flt_in_memory) {
		if (p2get_mem_unum != NULL) {
			return (p2get_mem_unum(synd_code, P2ALIGN(flt_addr, 8),
			    buf, buflen, lenp));
		} else {
			return (ENOTSUP);
		}
	} else if (flt_status & ECC_ECACHE) {
		if ((ret = plat_get_ecacheunum(flt_bus_id,
		    P2ALIGN(flt_addr, 8), buf, buflen, lenp)) != 0)
			return (EIO);
	} else {
		return (ENOTSUP);
	}

	return (ret);
}

static int (*ecc_mailbox_msg_func)(plat_ecc_message_type_t, void *) = NULL;

/*
 * To keep OS mailbox handling localized, all we do is forward the call to the
 * scosmb module (if it is available).
 */
int
plat_send_ecc_mailbox_msg(plat_ecc_message_type_t msg_type, void *datap)
{
	/*
	 * find the symbol for the mailbox sender routine in the scosmb module
	 */
	if (ecc_mailbox_msg_func == NULL)
		ecc_mailbox_msg_func = (int (*)(plat_ecc_message_type_t,
		    void *))modgetsymvalue("scosmb_log_ecc_error", 0);

	/*
	 * If the symbol was found, call it.  Otherwise, there is not much
	 * else we can do and console messages will have to suffice.
	 */
	if (ecc_mailbox_msg_func)
		return ((*ecc_mailbox_msg_func)(msg_type, datap));
	else
		return (ENODEV);
}

int
plat_make_fru_cpuid(int sb, int m, int proc)
{
	return (MAKE_CPUID(sb, m, proc));
}

/*
 * board number for a given proc
 */
int
plat_make_fru_boardnum(int proc)
{
	return (STARCAT_CPUID_TO_EXPANDER(proc));
}

/*
 * This platform hook gets called from mc_add_mem_unum_label() in the mc-us3
 * driver giving each platform the opportunity to add platform
 * specific label information to the unum for ECC error logging purposes.
 */
void
plat_add_mem_unum_label(char *unum, int mcid, int bank, int dimm)
{
	char	new_unum[UNUM_NAMLEN];
	uint_t	expander = STARCAT_CPUID_TO_EXPANDER(mcid);
	uint_t	slot = STARCAT_CPUID_TO_BOARDSLOT(mcid);

	/*
	 * STARCAT_CPUID_TO_PORTID clears the CoreID bit so that
	 * STARCAT_CPUID_TO_AGENT will return a physical proc (0 - 3).
	 */
	uint_t	proc = STARCAT_CPUID_TO_AGENT(STARCAT_CPUID_TO_PORTID(mcid));

	/*
	 * NOTE: Any modifications to the two sprintf() calls below will
	 * require changing plat_log_fruid_error() as well!
	 */
	if (dimm == -1)
		(void) snprintf(new_unum, UNUM_NAMLEN, "%s%u/P%u/B%d %s",
		    (slot ? "IO" : "SB"), expander, proc, (bank & 0x1), unum);
	else
		(void) snprintf(new_unum, UNUM_NAMLEN, "%s%u/P%u/B%d/D%d %s",
		    (slot ? "IO" : "SB"), expander,
		    proc, (bank & 0x1), (dimm & 0x3), unum);

	(void) strcpy(unum, new_unum);
}

int
plat_get_cpu_unum(int cpuid, char *buf, int buflen, int *lenp)
{
	int	expander = STARCAT_CPUID_TO_EXPANDER(cpuid);
	int	slot = STARCAT_CPUID_TO_BOARDSLOT(cpuid);

	if (snprintf(buf, buflen, "%s%d", (slot ? "IO" : "SB"), expander)
	    >= buflen) {
		return (ENOSPC);
	} else {
		*lenp = strlen(buf);
		return (0);
	}
}

/*
 * This routine is used by the data bearing mondo (DMV) initialization
 * routine to determine the number of hardware and software DMV interrupts
 * that a platform supports.
 */
void
plat_dmv_params(uint_t *hwint, uint_t *swint)
{
	*hwint = STARCAT_DMV_HWINT;
	*swint = 0;
}

/*
 * If provided, this function will be called whenever the nodename is updated.
 * To keep OS mailbox handling localized, all we do is forward the call to the
 * scosmb module (if it is available).
 */
void
plat_nodename_set(void)
{
	void (*nodename_update_func)(uint64_t) = NULL;

	/*
	 * find the symbol for the nodename update routine in the scosmb module
	 */
	nodename_update_func = (void (*)(uint64_t))
	    modgetsymvalue("scosmb_update_nodename", 0);

	/*
	 * If the symbol was found, call it.  Otherwise, log a note (but not to
	 * the console).
	 */
	if (nodename_update_func != NULL) {
		nodename_update_func(0);
	} else {
		cmn_err(CE_NOTE,
		    "!plat_nodename_set: scosmb_update_nodename not found\n");
	}
}

caddr_t	efcode_vaddr = NULL;
caddr_t efcode_paddr = NULL;
/*
 * Preallocate enough memory for fcode claims.
 */

caddr_t
efcode_alloc(caddr_t alloc_base)
{
	caddr_t efcode_alloc_base = (caddr_t)roundup((uintptr_t)alloc_base,
	    MMU_PAGESIZE);
	caddr_t vaddr;

	/*
	 * allocate the physical memory schizo fcode.
	 */
	if ((vaddr = (caddr_t)BOP_ALLOC(bootops, efcode_alloc_base,
	    efcode_size, MMU_PAGESIZE)) == NULL)
		cmn_err(CE_PANIC, "Cannot allocate Efcode Memory");

	efcode_vaddr = vaddr;

	return (efcode_alloc_base + efcode_size);
}

caddr_t
plat_startup_memlist(caddr_t alloc_base)
{
	caddr_t tmp_alloc_base;

	tmp_alloc_base = efcode_alloc(alloc_base);
	tmp_alloc_base = (caddr_t)roundup((uintptr_t)tmp_alloc_base,
	    ecache_alignsize);
	return (tmp_alloc_base);
}

/*
 * This is a helper function to determine if a given
 * node should be considered for a dr operation according
 * to predefined dr names. This is accomplished using
 * a function defined in drmach module. The drmach module
 * owns the definition of dr allowable names.
 * Formal Parameter: The name of a device node.
 * Expected Return Value: -1, device node name does not map to a valid dr name.
 *               A value greater or equal to 0, name is valid.
 */
int
starcat_dr_name(char *name)
{
	int (*drmach_name2type)(char *) = NULL;

	/* Get a pointer to helper function in the dramch module. */
	drmach_name2type =
	    (int (*)(char *))kobj_getsymvalue("drmach_name2type_idx", 0);

	if (drmach_name2type == NULL)
		return (-1);

	return ((*drmach_name2type)(name));
}

void
startup_platform(void)
{
	/* set per platform constants for mutex backoff */
	mutex_backoff_base = 2;
	mutex_cap_factor = 64;
}

/*
 * KDI functions - used by the in-situ kernel debugger (kmdb) to perform
 * platform-specific operations.  These functions execute when the world is
 * stopped, and as such cannot make any blocking calls, hold locks, etc.
 * promif functions are a special case, and may be used.
 */

static void
starcat_system_claim(void)
{
	prom_interpret("sigb-sig! my-sigb-sig!", OBP_SIG, OBP_SIG, 0, 0, 0);
}

static void
starcat_system_release(void)
{
	prom_interpret("sigb-sig! my-sigb-sig!", OS_SIG, OS_SIG, 0, 0, 0);
}

void
plat_kdi_init(kdi_t *kdi)
{
	kdi->pkdi_system_claim = starcat_system_claim;
	kdi->pkdi_system_release = starcat_system_release;
}

/*
 * This function returns 1 if large pages for kernel heap are supported
 * and 0 otherwise.
 *
 * Currently we disable lp kmem support if kpr is going to be enabled
 * because in the case of large pages hat_add_callback()/hat_delete_callback()
 * cause network performance degradation
 */
int
plat_lpkmem_is_supported(void)
{
	extern int segkmem_reloc;

	if (hat_kpr_enabled && kernel_cage_enable &&
	    (ncpunode >= 32 || segkmem_reloc == 1))
		return (0);

	return (1);
}
