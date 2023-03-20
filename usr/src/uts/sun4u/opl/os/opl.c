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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

/*
 * Copyright 2023 Oxide Computer Company
 */

#include <sys/cpuvar.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/promif.h>
#include <sys/platform_module.h>
#include <sys/cmn_err.h>
#include <sys/errno.h>
#include <sys/machsystm.h>
#include <sys/bootconf.h>
#include <sys/nvpair.h>
#include <sys/kobj.h>
#include <sys/mem_cage.h>
#include <sys/opl.h>
#include <sys/scfd/scfostoescf.h>
#include <sys/cpu_sgnblk_defs.h>
#include <sys/utsname.h>
#include <sys/ddi.h>
#include <sys/sunndi.h>
#include <sys/lgrp.h>
#include <sys/memnode.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/cpu.h>
#include <sys/dumphdr.h>
#include <vm/vm_dep.h>

int (*opl_get_mem_unum)(int, uint64_t, char *, int, int *);
int (*opl_get_mem_sid)(char *unum, char *buf, int buflen, int *lenp);
int (*opl_get_mem_offset)(uint64_t paddr, uint64_t *offp);
int (*opl_get_mem_addr)(char *unum, char *sid,
    uint64_t offset, uint64_t *paddr);

/* Memory for fcode claims.  16k times # maximum possible IO units */
#define	EFCODE_SIZE	(OPL_MAX_BOARDS * OPL_MAX_IO_UNITS_PER_BOARD * 0x4000)
int efcode_size = EFCODE_SIZE;

#define	OPL_MC_MEMBOARD_SHIFT 38	/* Boards on 256BG boundary */

/* Set the maximum number of boards for DR */
int opl_boards = OPL_MAX_BOARDS;

void sgn_update_all_cpus(ushort_t, uchar_t, uchar_t);

extern int tsb_lgrp_affinity;

int opl_tsb_spares = (OPL_MAX_BOARDS) * (OPL_MAX_PCICH_UNITS_PER_BOARD) *
	(OPL_MAX_TSBS_PER_PCICH);

pgcnt_t opl_startup_cage_size = 0;

/*
 * The length of the delay in seconds in communication with XSCF after
 * which the warning message will be logged.
 */
uint_t	xscf_connect_delay = 60 * 15;

static opl_model_info_t opl_models[] = {
	{ "FF1", OPL_MAX_BOARDS_FF1, FF1, STD_DISPATCH_TABLE },
	{ "FF2", OPL_MAX_BOARDS_FF2, FF2, STD_DISPATCH_TABLE },
	{ "DC1", OPL_MAX_BOARDS_DC1, DC1, STD_DISPATCH_TABLE },
	{ "DC2", OPL_MAX_BOARDS_DC2, DC2, EXT_DISPATCH_TABLE },
	{ "DC3", OPL_MAX_BOARDS_DC3, DC3, EXT_DISPATCH_TABLE },
	{ "IKKAKU", OPL_MAX_BOARDS_IKKAKU, IKKAKU, STD_DISPATCH_TABLE },
};
static	int	opl_num_models = sizeof (opl_models)/sizeof (opl_model_info_t);

/*
 * opl_cur_model
 */
static	opl_model_info_t *opl_cur_model = NULL;

static struct memlist *opl_memlist_per_board(struct memlist *ml);
static void post_xscf_msg(char *, int);
static void pass2xscf_thread();

/*
 * Note FF/DC out-of-order instruction engine takes only a
 * single cycle to execute each spin loop
 * for comparison, Panther takes 6 cycles for same loop
 * OPL_BOFF_SPIN = base spin loop, roughly one memory reference time
 * OPL_BOFF_TM = approx nsec for OPL sleep instruction (1600 for OPL-C)
 * OPL_BOFF_SLEEP = approx number of SPIN iterations to equal one sleep
 * OPL_BOFF_MAX_SCALE - scaling factor for max backoff based on active cpus
 * Listed values tuned for 2.15GHz to 2.64GHz systems
 * Value may change for future systems
 */
#define	OPL_BOFF_SPIN 7
#define	OPL_BOFF_SLEEP 4
#define	OPL_BOFF_TM 1600
#define	OPL_BOFF_MAX_SCALE 8

#define	OPL_CLOCK_TICK_THRESHOLD	128
#define	OPL_CLOCK_TICK_NCPUS		64

extern int	clock_tick_threshold;
extern int	clock_tick_ncpus;

int
set_platform_max_ncpus(void)
{
	return (OPL_MAX_CPU_PER_BOARD * OPL_MAX_BOARDS);
}

int
set_platform_tsb_spares(void)
{
	return (MIN(opl_tsb_spares, MAX_UPA));
}

static void
set_model_info()
{
	extern int ts_dispatch_extended;
	char	name[MAXSYSNAME];
	int	i;

	/*
	 * Get model name from the root node.
	 *
	 * We are using the prom device tree since, at this point,
	 * the Solaris device tree is not yet setup.
	 */
	(void) prom_getprop(prom_rootnode(), "model", (caddr_t)name);

	for (i = 0; i < opl_num_models; i++) {
		if (strncmp(name, opl_models[i].model_name, MAXSYSNAME) == 0) {
			opl_cur_model = &opl_models[i];
			break;
		}
	}

	/*
	 * If model not matched, it's an unknown model.
	 * Just return.  It will default to standard dispatch tables.
	 */
	if (i == opl_num_models)
		return;

	if ((opl_cur_model->model_cmds & EXT_DISPATCH_TABLE) &&
	    (ts_dispatch_extended == -1)) {
		/*
		 * Based on a platform model, select a dispatch table.
		 * Only DC2 and DC3 systems uses the alternate/extended
		 * TS dispatch table.
		 * IKKAKU, FF1, FF2 and DC1 systems use standard dispatch
		 * tables.
		 */
		ts_dispatch_extended = 1;
	}

}

static void
set_max_mmu_ctxdoms()
{
	extern uint_t	max_mmu_ctxdoms;
	int		max_boards;

	/*
	 * From the model, get the maximum number of boards
	 * supported and set the value accordingly. If the model
	 * could not be determined or recognized, we assume the max value.
	 */
	if (opl_cur_model == NULL)
		max_boards = OPL_MAX_BOARDS;
	else
		max_boards = opl_cur_model->model_max_boards;

	/*
	 * On OPL, cores and MMUs are one-to-one.
	 */
	max_mmu_ctxdoms = OPL_MAX_CORE_UNITS_PER_BOARD * max_boards;
}

#pragma weak mmu_init_large_pages

void
set_platform_defaults(void)
{
	extern char *tod_module_name;
	extern void cpu_sgn_update(ushort_t, uchar_t, uchar_t, int);
	extern void mmu_init_large_pages(size_t);

	/* Set the CPU signature function pointer */
	cpu_sgn_func = cpu_sgn_update;

	/* Set appropriate tod module for OPL platform */
	ASSERT(tod_module_name == NULL);
	tod_module_name = "todopl";

	if ((mmu_page_sizes == max_mmu_page_sizes) &&
	    (mmu_ism_pagesize != DEFAULT_ISM_PAGESIZE)) {
		if (&mmu_init_large_pages)
			mmu_init_large_pages(mmu_ism_pagesize);
	}

	tsb_lgrp_affinity = 1;

	set_max_mmu_ctxdoms();

	/* set OPL threshold for compressed dumps */
	dump_plat_mincpu_default = DUMP_PLAT_SUN4U_OPL_MINCPU;
}

/*
 * Convert logical a board number to a physical one.
 */

#define	LSBPROP		"board#"
#define	PSBPROP		"physical-board#"

int
opl_get_physical_board(int id)
{
	dev_info_t	*root_dip, *dip = NULL;
	char		*dname = NULL;

	pnode_t		pnode;
	char		pname[MAXSYSNAME] = {0};

	int		lsb_id;	/* Logical System Board ID */
	int		psb_id;	/* Physical System Board ID */


	/*
	 * This function is called on early stage of bootup when the
	 * kernel device tree is not initialized yet, and also
	 * later on when the device tree is up. We want to try
	 * the fast track first.
	 */
	root_dip = ddi_root_node();
	if (root_dip) {
		/* Get from devinfo node */
		ndi_devi_enter(root_dip);
		for (dip = ddi_get_child(root_dip); dip;
		    dip = ddi_get_next_sibling(dip)) {

			dname = ddi_node_name(dip);
			if (strncmp(dname, "pseudo-mc", 9) != 0)
				continue;

			if ((lsb_id = (int)ddi_getprop(DDI_DEV_T_ANY, dip,
			    DDI_PROP_DONTPASS, LSBPROP, -1)) == -1)
				continue;

			if (id == lsb_id) {
				if ((psb_id = (int)ddi_getprop(DDI_DEV_T_ANY,
				    dip, DDI_PROP_DONTPASS, PSBPROP, -1))
				    == -1) {
					ndi_devi_exit(root_dip);
					return (-1);
				} else {
					ndi_devi_exit(root_dip);
					return (psb_id);
				}
			}
		}
		ndi_devi_exit(root_dip);
	}

	/*
	 * We do not have the kernel device tree, or we did not
	 * find the node for some reason (let's say the kernel
	 * device tree was modified), let's try the OBP tree.
	 */
	pnode = prom_rootnode();
	for (pnode = prom_childnode(pnode); pnode;
	    pnode = prom_nextnode(pnode)) {

		if ((prom_getprop(pnode, "name", (caddr_t)pname) == -1) ||
		    (strncmp(pname, "pseudo-mc", 9) != 0))
			continue;

		if (prom_getprop(pnode, LSBPROP, (caddr_t)&lsb_id) == -1)
			continue;

		if (id == lsb_id) {
			if (prom_getprop(pnode, PSBPROP,
			    (caddr_t)&psb_id) == -1) {
				return (-1);
			} else {
				return (psb_id);
			}
		}
	}

	return (-1);
}

/*
 * For OPL it's possible that memory from two or more successive boards
 * will be contiguous across the boards, and therefore represented as a
 * single chunk.
 * This function splits such chunks down the board boundaries.
 */
static struct memlist *
opl_memlist_per_board(struct memlist *ml)
{
	uint64_t ssize, low, high, boundary;
	struct memlist *head, *tail, *new;

	ssize = (1ull << OPL_MC_MEMBOARD_SHIFT);

	head = tail = NULL;

	for (; ml; ml = ml->ml_next) {
		low  = (uint64_t)ml->ml_address;
		high = low+(uint64_t)(ml->ml_size);
		while (low < high) {
			boundary = roundup(low+1, ssize);
			boundary = MIN(high, boundary);
			new = kmem_zalloc(sizeof (struct memlist), KM_SLEEP);
			new->ml_address = low;
			new->ml_size = boundary - low;
			if (head == NULL)
				head = new;
			if (tail) {
				tail->ml_next = new;
				new->ml_prev = tail;
			}
			tail = new;
			low = boundary;
		}
	}
	return (head);
}

void
set_platform_cage_params(void)
{
	extern pgcnt_t total_pages;
	extern struct memlist *phys_avail;
	struct memlist *ml, *tml;

	if (kernel_cage_enable) {
		pgcnt_t preferred_cage_size;

		preferred_cage_size = MAX(opl_startup_cage_size,
		    total_pages / 256);

		ml = opl_memlist_per_board(phys_avail);

		/*
		 * Note: we are assuming that post has load the
		 * whole show in to the high end of memory. Having
		 * taken this leap, we copy the whole of phys_avail
		 * the glist and arrange for the cage to grow
		 * downward (descending pfns).
		 */
		kcage_range_init(ml, KCAGE_DOWN, preferred_cage_size);

		/* free the memlist */
		do {
			tml = ml->ml_next;
			kmem_free(ml, sizeof (struct memlist));
			ml = tml;
		} while (ml != NULL);
	}

	if (kcage_on)
		cmn_err(CE_NOTE, "!DR Kernel Cage is ENABLED");
	else
		cmn_err(CE_NOTE, "!DR Kernel Cage is DISABLED");
}

/*ARGSUSED*/
int
plat_cpu_poweron(struct cpu *cp)
{
	int (*opl_cpu_poweron)(struct cpu *) = NULL;

	opl_cpu_poweron =
	    (int (*)(struct cpu *))kobj_getsymvalue("drmach_cpu_poweron", 0);

	if (opl_cpu_poweron == NULL)
		return (ENOTSUP);
	else
		return ((opl_cpu_poweron)(cp));

}

/*ARGSUSED*/
int
plat_cpu_poweroff(struct cpu *cp)
{
	int (*opl_cpu_poweroff)(struct cpu *) = NULL;

	opl_cpu_poweroff =
	    (int (*)(struct cpu *))kobj_getsymvalue("drmach_cpu_poweroff", 0);

	if (opl_cpu_poweroff == NULL)
		return (ENOTSUP);
	else
		return ((opl_cpu_poweroff)(cp));

}

int
plat_max_boards(void)
{
	/*
	 * If the model cannot be determined, default to the max value.
	 * Otherwise, Ikkaku model only supports 1 system board.
	 */
	if ((opl_cur_model != NULL) && (opl_cur_model->model_type == IKKAKU))
		return (OPL_MAX_BOARDS_IKKAKU);
	else
		return (OPL_MAX_BOARDS);
}

int
plat_max_cpu_units_per_board(void)
{
	return (OPL_MAX_CPU_PER_BOARD);
}

int
plat_max_mem_units_per_board(void)
{
	return (OPL_MAX_MEM_UNITS_PER_BOARD);
}

int
plat_max_io_units_per_board(void)
{
	return (OPL_MAX_IO_UNITS_PER_BOARD);
}

int
plat_max_cmp_units_per_board(void)
{
	return (OPL_MAX_CMP_UNITS_PER_BOARD);
}

int
plat_max_core_units_per_board(void)
{
	return (OPL_MAX_CORE_UNITS_PER_BOARD);
}

int
plat_pfn_to_mem_node(pfn_t pfn)
{
	return (pfn >> mem_node_pfn_shift);
}

/* ARGSUSED */
void
plat_build_mem_nodes(prom_memlist_t *list, size_t nelems)
{
	size_t	elem;
	pfn_t	basepfn;
	pgcnt_t	npgs;
	uint64_t	boundary, ssize;
	uint64_t	low, high;

	/*
	 * OPL mem slices are always aligned on a 256GB boundary.
	 */
	mem_node_pfn_shift = OPL_MC_MEMBOARD_SHIFT - MMU_PAGESHIFT;
	mem_node_physalign = 0;

	/*
	 * Boot install lists are arranged <addr, len>, <addr, len>, ...
	 */
	ssize = (1ull << OPL_MC_MEMBOARD_SHIFT);
	for (elem = 0; elem < nelems; list++, elem++) {
		low  = list->addr;
		high = low + list->size;
		while (low < high) {
			boundary = roundup(low+1, ssize);
			boundary = MIN(high, boundary);
			basepfn = btop(low);
			npgs = btop(boundary - low);
			mem_node_add_slice(basepfn, basepfn + npgs - 1);
			low = boundary;
		}
	}
}

/*
 * Find the CPU associated with a slice at boot-time.
 */
void
plat_fill_mc(pnode_t nodeid)
{
	int board;
	int memnode;
	struct {
		uint64_t	addr;
		uint64_t	size;
	} mem_range;

	if (prom_getprop(nodeid, "board#", (caddr_t)&board) < 0) {
		panic("Can not find board# property in mc node %x", nodeid);
	}
	if (prom_getprop(nodeid, "sb-mem-ranges", (caddr_t)&mem_range) < 0) {
		panic("Can not find sb-mem-ranges property in mc node %x",
		    nodeid);
	}
	memnode = mem_range.addr >> OPL_MC_MEMBOARD_SHIFT;
	plat_assign_lgrphand_to_mem_node(board, memnode);
}

/*
 * Return the platform handle for the lgroup containing the given CPU
 *
 * For OPL, lgroup platform handle == board #.
 */

extern int mpo_disabled;
extern lgrp_handle_t lgrp_default_handle;

lgrp_handle_t
plat_lgrp_cpu_to_hand(processorid_t id)
{
	lgrp_handle_t plathand;

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
	} else
		plathand = (lgrp_handle_t)LSB_ID(id);
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
	const uint_t m = LGRP_LOADAVG_THREAD_MAX;

	/*
	 * Set tuneables for the OPL architecture
	 *
	 * lgrp_expand_proc_thresh is the threshold load on the set of
	 * lgroups a process is currently using on before considering
	 * adding another lgroup to the set.  For Oly-C and Jupiter
	 * systems, there are four sockets per lgroup. Setting
	 * lgrp_expand_proc_thresh to add lgroups when the load reaches
	 * four threads will spread the load when it exceeds one thread
	 * per socket, optimizing memory bandwidth and L2 cache space.
	 *
	 * lgrp_expand_proc_diff determines how much less another lgroup
	 * must be loaded before shifting the start location of a thread
	 * to it.
	 *
	 * lgrp_loadavg_tolerance is the threshold where two lgroups are
	 * considered to have different loads.  It is set to be less than
	 * 1% so that even a small residual load will be considered different
	 * from no residual load.
	 *
	 * We note loadavg values are not precise.
	 * Every 1/10 of a second loadavg values are reduced by 5%.
	 * This adjustment can come in the middle of the lgroup selection
	 * process, and for larger parallel apps with many threads can
	 * frequently occur between the start of the second thread
	 * placement and the finish of the last thread placement.
	 * We also must be careful to not use too small of a threshold
	 * since the cumulative decay for 1 second idle time is 40%.
	 * That is, the residual load from completed threads will still
	 * be 60% one second after the proc goes idle or 8% after 5 seconds.
	 *
	 * To allow for lag time in loadavg calculations
	 * remote thresh = 3.75 * LGRP_LOADAVG_THREAD_MAX
	 * local thresh  = 0.75 * LGRP_LOADAVG_THREAD_MAX
	 * tolerance	 = 0.0078 * LGRP_LOADAVG_THREAD_MAX
	 *
	 * The load placement algorithms consider LGRP_LOADAVG_THREAD_MAX
	 * as the equivalent of a load of 1. To make the code more compact,
	 * we set m = LGRP_LOADAVG_THREAD_MAX.
	 */
	lgrp_expand_proc_thresh = (m * 3) + (m >> 1) + (m >> 2);
	lgrp_expand_proc_diff = (m >> 1) + (m >> 2);
	lgrp_loadavg_tolerance = (m >> 7);
}

/*
 * Platform notification of lgroup (re)configuration changes
 */
/*ARGSUSED*/
void
plat_lgrp_config(lgrp_config_flag_t evt, uintptr_t arg)
{
	update_membounds_t *umb;
	lgrp_config_mem_rename_t lmr;
	int sbd, tbd;
	lgrp_handle_t hand, shand, thand;
	int mnode, snode, tnode;
	pfn_t start, end;

	if (mpo_disabled)
		return;

	switch (evt) {

	case LGRP_CONFIG_MEM_ADD:
		/*
		 * Establish the lgroup handle to memnode translation.
		 */
		umb = (update_membounds_t *)arg;

		hand = umb->u_board;
		mnode = plat_pfn_to_mem_node(umb->u_base >> MMU_PAGESHIFT);
		plat_assign_lgrphand_to_mem_node(hand, mnode);

		break;

	case LGRP_CONFIG_MEM_DEL:
		/*
		 * Special handling for possible memory holes.
		 */
		umb = (update_membounds_t *)arg;
		hand = umb->u_board;
		if ((mnode = plat_lgrphand_to_mem_node(hand)) != -1) {
			if (mem_node_config[mnode].exists) {
				start = mem_node_config[mnode].physbase;
				end = mem_node_config[mnode].physmax;
				mem_node_del_slice(start, end);
			}
		}

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
		shand = sbd;
		thand = tbd;
		snode = plat_lgrphand_to_mem_node(shand);
		tnode = plat_lgrphand_to_mem_node(thand);

		/*
		 * Special handling for possible memory holes.
		 */
		if (tnode != -1 && mem_node_config[tnode].exists) {
			start = mem_node_config[tnode].physbase;
			end = mem_node_config[tnode].physmax;
			mem_node_del_slice(start, end);
		}

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
 *
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
		return (42);
	else
		return (35);
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

/*ARGSUSED*/
void
plat_freelist_process(int mnode)
{
}

void
load_platform_drivers(void)
{
	(void) i_ddi_attach_pseudo_node("dr");
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

/*ARGSUSED*/
void
cpu_sgn_update(ushort_t sgn, uchar_t state, uchar_t sub_state, int cpuid)
{
	static void (*scf_panic_callback)(int);
	static void (*scf_shutdown_callback)(int);

	/*
	 * This is for notifing system panic/shutdown to SCF.
	 * In case of shutdown and panic, SCF call back
	 * function should be called.
	 *  <SCF call back functions>
	 *   scf_panic_callb()   : panicsys()->panic_quiesce_hw()
	 *   scf_shutdown_callb(): halt() or power_down() or reboot_machine()
	 * cpuid should be -1 and state should be SIGST_EXIT.
	 */
	if (state == SIGST_EXIT && cpuid == -1) {

		/*
		 * find the symbol for the SCF panic callback routine in driver
		 */
		if (scf_panic_callback == NULL)
			scf_panic_callback = (void (*)(int))
			    modgetsymvalue("scf_panic_callb", 0);
		if (scf_shutdown_callback == NULL)
			scf_shutdown_callback = (void (*)(int))
			    modgetsymvalue("scf_shutdown_callb", 0);

		switch (sub_state) {
		case SIGSUBST_PANIC:
			if (scf_panic_callback == NULL) {
				cmn_err(CE_NOTE, "!cpu_sgn_update: "
				    "scf_panic_callb not found\n");
				return;
			}
			scf_panic_callback(SIGSUBST_PANIC);
			break;

		case SIGSUBST_HALT:
			if (scf_shutdown_callback == NULL) {
				cmn_err(CE_NOTE, "!cpu_sgn_update: "
				    "scf_shutdown_callb not found\n");
				return;
			}
			scf_shutdown_callback(SIGSUBST_HALT);
			break;

		case SIGSUBST_ENVIRON:
			if (scf_shutdown_callback == NULL) {
				cmn_err(CE_NOTE, "!cpu_sgn_update: "
				    "scf_shutdown_callb not found\n");
				return;
			}
			scf_shutdown_callback(SIGSUBST_ENVIRON);
			break;

		case SIGSUBST_REBOOT:
			if (scf_shutdown_callback == NULL) {
				cmn_err(CE_NOTE, "!cpu_sgn_update: "
				    "scf_shutdown_callb not found\n");
				return;
			}
			scf_shutdown_callback(SIGSUBST_REBOOT);
			break;
		}
	}
}

/*ARGSUSED*/
int
plat_get_mem_unum(int synd_code, uint64_t flt_addr, int flt_bus_id,
    int flt_in_memory, ushort_t flt_status,
    char *buf, int buflen, int *lenp)
{
	/*
	 * check if it's a Memory error.
	 */
	if (flt_in_memory) {
		if (opl_get_mem_unum != NULL) {
			return (opl_get_mem_unum(synd_code, flt_addr, buf,
			    buflen, lenp));
		} else {
			return (ENOTSUP);
		}
	} else {
		return (ENOTSUP);
	}
}

/*ARGSUSED*/
int
plat_get_cpu_unum(int cpuid, char *buf, int buflen, int *lenp)
{
	int	ret = 0;
	int	sb;
	int	plen;

	sb = opl_get_physical_board(LSB_ID(cpuid));
	if (sb == -1) {
		return (ENXIO);
	}

	/*
	 * opl_cur_model is assigned here
	 */
	if (opl_cur_model == NULL) {
		set_model_info();

		/*
		 * if not matched, return
		 */
		if (opl_cur_model == NULL)
			return (ENODEV);
	}

	ASSERT((opl_cur_model - opl_models) == (opl_cur_model->model_type));

	switch (opl_cur_model->model_type) {
	case FF1:
		plen = snprintf(buf, buflen, "/%s/CPUM%d", "MBU_A",
		    CHIP_ID(cpuid) / 2);
		break;

	case FF2:
		plen = snprintf(buf, buflen, "/%s/CPUM%d", "MBU_B",
		    (CHIP_ID(cpuid) / 2) + (sb * 2));
		break;

	case DC1:
	case DC2:
	case DC3:
		plen = snprintf(buf, buflen, "/%s%02d/CPUM%d", "CMU", sb,
		    CHIP_ID(cpuid));
		break;

	case IKKAKU:
		plen = snprintf(buf, buflen, "/%s", "MBU_A");
		break;

	default:
		/* This should never happen */
		return (ENODEV);
	}

	if (plen >= buflen) {
		ret = ENOSPC;
	} else {
		if (lenp)
			*lenp = strlen(buf);
	}
	return (ret);
}

void
plat_nodename_set(void)
{
	post_xscf_msg((char *)&utsname, sizeof (struct utsname));
}

caddr_t	efcode_vaddr = NULL;

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
	 * allocate the physical memory for the Oberon fcode.
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
	tmp_alloc_base =
	    (caddr_t)roundup((uintptr_t)tmp_alloc_base, ecache_alignsize);
	return (tmp_alloc_base);
}

/* need to forward declare these */
static void plat_lock_delay(uint_t);

void
startup_platform(void)
{
	if (clock_tick_threshold == 0)
		clock_tick_threshold = OPL_CLOCK_TICK_THRESHOLD;
	if (clock_tick_ncpus == 0)
		clock_tick_ncpus = OPL_CLOCK_TICK_NCPUS;
	mutex_lock_delay = plat_lock_delay;
	mutex_cap_factor = OPL_BOFF_MAX_SCALE;
}

static uint_t
get_mmu_id(processorid_t cpuid)
{
	int pb = opl_get_physical_board(LSB_ID(cpuid));

	if (pb == -1) {
		cmn_err(CE_PANIC,
		    "opl_get_physical_board failed (cpu %d LSB %u)",
		    cpuid, LSB_ID(cpuid));
	}
	return (pb * OPL_MAX_COREID_PER_BOARD) + (CHIP_ID(cpuid) *
	    OPL_MAX_COREID_PER_CMP) + CORE_ID(cpuid);
}

void
plat_cpuid_to_mmu_ctx_info(processorid_t cpuid, mmu_ctx_info_t *info)
{
	int	impl;

	impl = cpunodes[cpuid].implementation;
	if (IS_OLYMPUS_C(impl) || IS_JUPITER(impl)) {
		info->mmu_idx = get_mmu_id(cpuid);
		info->mmu_nctxs = 8192;
	} else {
		cmn_err(CE_PANIC, "Unknown processor %d", impl);
	}
}

int
plat_get_mem_sid(char *unum, char *buf, int buflen, int *lenp)
{
	if (opl_get_mem_sid == NULL) {
		return (ENOTSUP);
	}
	return (opl_get_mem_sid(unum, buf, buflen, lenp));
}

int
plat_get_mem_offset(uint64_t paddr, uint64_t *offp)
{
	if (opl_get_mem_offset == NULL) {
		return (ENOTSUP);
	}
	return (opl_get_mem_offset(paddr, offp));
}

int
plat_get_mem_addr(char *unum, char *sid, uint64_t offset, uint64_t *addrp)
{
	if (opl_get_mem_addr == NULL) {
		return (ENOTSUP);
	}
	return (opl_get_mem_addr(unum, sid, offset, addrp));
}

void
plat_lock_delay(uint_t backoff)
{
	int i;
	uint_t cnt, remcnt;
	int ctr;
	hrtime_t delay_start, rem_delay;
	/*
	 * Platform specific lock delay code for OPL
	 *
	 * Using staged linear increases in the delay.
	 * The sleep instruction is the preferred method of delay,
	 * but is too large of granularity for the initial backoff.
	 */

	if (backoff < 100) {
		/*
		 * If desired backoff is long enough,
		 * use sleep for most of it
		 */
		for (cnt = backoff;
		    cnt >= OPL_BOFF_SLEEP;
		    cnt -= OPL_BOFF_SLEEP) {
			cpu_smt_pause();
		}
		/*
		 * spin for small remainder of backoff
		 */
		for (ctr = cnt * OPL_BOFF_SPIN; ctr; ctr--) {
			mutex_delay_default();
		}
	} else {
		/* backoff is large.  Fill it by sleeping */
		delay_start = gethrtime_waitfree();
		cnt = backoff / OPL_BOFF_SLEEP;
		/*
		 * use sleep instructions for delay
		 */
		for (i = 0; i < cnt; i++) {
			cpu_smt_pause();
		}

		/*
		 * Note: if the other strand executes a sleep instruction,
		 * then the sleep ends immediately with a minimum time of
		 * 42 clocks.  We check gethrtime to insure we have
		 * waited long enough.  And we include both a short
		 * spin loop and a sleep for repeated delay times.
		 */

		rem_delay = gethrtime_waitfree() - delay_start;
		while (rem_delay < cnt * OPL_BOFF_TM) {
			remcnt = cnt - (rem_delay / OPL_BOFF_TM);
			for (i = 0; i < remcnt; i++) {
				cpu_smt_pause();
				for (ctr = OPL_BOFF_SPIN; ctr; ctr--) {
					mutex_delay_default();
				}
			}
			rem_delay = gethrtime_waitfree() - delay_start;
		}
	}
}

/*
 * The following code implements asynchronous call to XSCF to setup the
 * domain node name.
 */

#define	FREE_MSG(m)		kmem_free((m), NM_LEN((m)->len))

/*
 * The following three macros define the all operations on the request
 * list we are using here, and hide the details of the list
 * implementation from the code.
 */
#define	PUSH(m) \
	{ \
		(m)->next = ctl_msg.head; \
		(m)->prev = NULL; \
		if ((m)->next != NULL) \
			(m)->next->prev = (m); \
		ctl_msg.head = (m); \
	}

#define	REMOVE(m) \
	{ \
		if ((m)->prev != NULL) \
			(m)->prev->next = (m)->next; \
		else \
			ctl_msg.head = (m)->next; \
		if ((m)->next != NULL) \
			(m)->next->prev = (m)->prev; \
	}

#define	FREE_THE_TAIL(head) \
	{ \
		nm_msg_t *n_msg, *m; \
		m = (head)->next; \
		(head)->next = NULL; \
		while (m != NULL) { \
			n_msg = m->next; \
			FREE_MSG(m); \
			m = n_msg; \
		} \
	}

#define	SCF_PUTINFO(f, s, p) \
	f(KEY_ESCF, 0x01, 0, s, p)

#define	PASS2XSCF(m, r)	((r = SCF_PUTINFO(ctl_msg.scf_service_function, \
					    (m)->len, (m)->data)) == 0)

/*
 * The value of the following macro loosely depends on the
 * value of the "device busy" timeout used in the SCF driver.
 * (See pass2xscf_thread()).
 */
#define	SCF_DEVBUSY_DELAY	10

/*
 * The default number of attempts to contact the scf driver
 * if we cannot fetch any information about the timeout value
 * it uses.
 */

#define	REPEATS		4

typedef struct nm_msg {
	struct nm_msg *next;
	struct nm_msg *prev;
	int len;
	char data[1];
} nm_msg_t;

#define	NM_LEN(len)		(sizeof (nm_msg_t) + (len) - 1)

static struct ctlmsg {
	nm_msg_t	*head;
	nm_msg_t	*now_serving;
	kmutex_t	nm_lock;
	kthread_t	*nmt;
	int		cnt;
	int (*scf_service_function)(uint32_t, uint8_t,
				    uint32_t, uint32_t, void *);
} ctl_msg;

static void
post_xscf_msg(char *dp, int len)
{
	nm_msg_t *msg;

	msg = (nm_msg_t *)kmem_zalloc(NM_LEN(len), KM_SLEEP);

	bcopy(dp, msg->data, len);
	msg->len = len;

	mutex_enter(&ctl_msg.nm_lock);
	if (ctl_msg.nmt == NULL) {
		ctl_msg.nmt =  thread_create(NULL, 0, pass2xscf_thread,
		    NULL, 0, &p0, TS_RUN, minclsyspri);
	}

	PUSH(msg);
	ctl_msg.cnt++;
	mutex_exit(&ctl_msg.nm_lock);
}

static void
pass2xscf_thread()
{
	nm_msg_t *msg;
	int ret;
	uint_t i, msg_sent, xscf_driver_delay;
	static uint_t repeat_cnt;
	uint_t *scf_wait_cnt;

	mutex_enter(&ctl_msg.nm_lock);

	/*
	 * Find the address of the SCF put routine if it's not done yet.
	 */
	if (ctl_msg.scf_service_function == NULL) {
		if ((ctl_msg.scf_service_function =
		    (int (*)(uint32_t, uint8_t, uint32_t, uint32_t, void *))
		    modgetsymvalue("scf_service_putinfo", 0)) == NULL) {
			cmn_err(CE_NOTE, "pass2xscf_thread: "
			    "scf_service_putinfo not found\n");
			ctl_msg.nmt = NULL;
			mutex_exit(&ctl_msg.nm_lock);
			return;
		}
	}

	/*
	 * Calculate the number of attempts to connect XSCF based on the
	 * scf driver delay (which is
	 * SCF_DEVBUSY_DELAY*scf_online_wait_rcnt seconds) and the value
	 * of xscf_connect_delay (the total number of seconds to wait
	 * till xscf get ready.)
	 */
	if (repeat_cnt == 0) {
		if ((scf_wait_cnt =
		    (uint_t *)
		    modgetsymvalue("scf_online_wait_rcnt", 0)) == NULL) {
			repeat_cnt = REPEATS;
		} else {

			xscf_driver_delay = *scf_wait_cnt *
			    SCF_DEVBUSY_DELAY;
			repeat_cnt = (xscf_connect_delay/xscf_driver_delay) + 1;
		}
	}

	while (ctl_msg.cnt != 0) {

		/*
		 * Take the very last request from the queue,
		 */
		ctl_msg.now_serving = ctl_msg.head;
		ASSERT(ctl_msg.now_serving != NULL);

		/*
		 * and discard all the others if any.
		 */
		FREE_THE_TAIL(ctl_msg.now_serving);
		ctl_msg.cnt = 1;
		mutex_exit(&ctl_msg.nm_lock);

		/*
		 * Pass the name to XSCF. Note please, we do not hold the
		 * mutex while we are doing this.
		 */
		msg_sent = 0;
		for (i = 0; i < repeat_cnt; i++) {
			if (PASS2XSCF(ctl_msg.now_serving, ret)) {
				msg_sent = 1;
				break;
			} else {
				if (ret != EBUSY) {
					cmn_err(CE_NOTE, "pass2xscf_thread:"
					    " unexpected return code"
					    " from scf_service_putinfo():"
					    " %d\n", ret);
				}
			}
		}

		if (msg_sent) {

			/*
			 * Remove the request from the list
			 */
			mutex_enter(&ctl_msg.nm_lock);
			msg = ctl_msg.now_serving;
			ctl_msg.now_serving = NULL;
			REMOVE(msg);
			ctl_msg.cnt--;
			mutex_exit(&ctl_msg.nm_lock);
			FREE_MSG(msg);
		} else {

			/*
			 * If while we have tried to communicate with
			 * XSCF there were any other requests we are
			 * going to drop this one and take the latest
			 * one.  Otherwise we will try to pass this one
			 * again.
			 */
			cmn_err(CE_NOTE,
			    "pass2xscf_thread: "
			    "scf_service_putinfo "
			    "not responding\n");
		}
		mutex_enter(&ctl_msg.nm_lock);
	}

	/*
	 * The request queue is empty, exit.
	 */
	ctl_msg.nmt = NULL;
	mutex_exit(&ctl_msg.nm_lock);
}
