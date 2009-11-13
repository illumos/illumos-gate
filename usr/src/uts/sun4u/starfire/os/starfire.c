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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sysmacros.h>
#include <sys/sunddi.h>
#include <sys/modctl.h>
#include <sys/promif.h>
#include <sys/machparam.h>
#include <sys/kobj.h>
#include <sys/mem_cage.h>
#include <sys/starfire.h>

#include <sys/platform_module.h>
#include <sys/errno.h>
#include <vm/page.h>
#include <vm/hat_sfmmu.h>
#include <sys/memnode.h>
#include <vm/vm_dep.h>
#include <sys/cpu_sgnblk_defs.h>
#include <sys/cpu_sgn.h>
#include <sys/kdi_impl.h>
#include <sys/clock_impl.h>

extern cpu_sgnblk_t *cpu_sgnblkp[];

/* Preallocation of spare tsb's for DR - none for now */
int starfire_tsb_spares = STARFIRE_MAX_BOARDS << 1;

/* Set the maximum number of boards... for DR */
int starfire_boards = STARFIRE_MAX_BOARDS;

/* Maximum number of cpus per board... for DR */
int starfire_cpu_per_board = 4;

/* Maximum number of mem-units per board... for DR */
int starfire_mem_per_board = 1;

/* Maximum number of io-units (buses) per board... for DR */
int starfire_io_per_board = 2;

/* Preferred minimum cage size (expressed in pages)... for DR */
pgcnt_t starfire_startup_cage_size = 0;

void sgn_update_all_cpus(ushort_t, uchar_t, uchar_t);

int
set_platform_max_ncpus(void)
{
	starfire_boards = MIN(starfire_boards, STARFIRE_MAX_BOARDS);

	if (starfire_boards < 1)
		starfire_boards = 1;

	return (starfire_boards * starfire_cpu_per_board);
}

void
startup_platform(void)
{
}

int
set_platform_tsb_spares()
{
	return (MIN(starfire_tsb_spares, MAX_UPA));
}

void
set_platform_defaults(void)
{
	extern char *tod_module_name;
	extern int ts_dispatch_extended;
	extern void cpu_sgn_update(ushort_t, uchar_t, uchar_t, int);

	uint32_t	revlevel;
	char		buf[20];

#ifdef DEBUG
	ce_verbose_memory = 2;
	ce_verbose_other = 2;
#endif

	/*
	 * Check to see if we have the right firmware
	 * We simply do a prom_test to see if
	 * "SUNW,UE10000-prom-version" interface exist.
	 */
	if (prom_test("SUNW,UE10000-prom-version") != 0) {
		halt("Firmware upgrade is required to boot this OS!");
	} else {
		/*
		 * Versions 5 to 50 and 150 or above  can support this OS
		 */
		sprintf(buf, "cpu-prom-version swap l!");
		prom_interpret(buf, (uintptr_t)&revlevel, 0, 0, 0, 0);
		if ((revlevel < 5) || ((revlevel > 50) && (revlevel < 150)))
			halt("Firmware upgrade is required to boot this OS!");
	}

	/* Set the CPU signature function pointer */
	cpu_sgn_func = cpu_sgn_update;

	/* Set appropriate tod module for starfire */
	ASSERT(tod_module_name == NULL);
	tod_module_name = "todstarfire";

	/*
	 * Use the alternate TS dispatch table, which is better
	 * tuned for large servers.
	 */
	if (ts_dispatch_extended == -1) /* use platform default */
		ts_dispatch_extended = 1;
}

#ifdef DEBUG
pgcnt_t starfire_cage_size_limit;
#endif

void
set_platform_cage_params(void)
{
	extern pgcnt_t total_pages;
	extern struct memlist *phys_avail;

	if (kernel_cage_enable) {
		pgcnt_t preferred_cage_size;

		preferred_cage_size =
		    MAX(starfire_startup_cage_size, total_pages / 256);

#ifdef DEBUG
		if (starfire_cage_size_limit)
			preferred_cage_size = starfire_cage_size_limit;
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
load_platform_drivers(void)
{
	/* load the NGDR driver */
	if (i_ddi_attach_pseudo_node("ngdr") == NULL) {
		cmn_err(CE_WARN, "ngdr failed to load");
	}
}

/*
 * Starfire does not support power control of CPUs from the OS.
 */
/*ARGSUSED*/
int
plat_cpu_poweron(struct cpu *cp)
{
	int (*starfire_cpu_poweron)(struct cpu *) = NULL;

	starfire_cpu_poweron =
	    (int (*)(struct cpu *))kobj_getsymvalue("drmach_cpu_poweron", 0);

	if (starfire_cpu_poweron == NULL)
		return (ENOTSUP);
	else
		return ((starfire_cpu_poweron)(cp));
}

/*ARGSUSED*/
int
plat_cpu_poweroff(struct cpu *cp)
{
	int (*starfire_cpu_poweroff)(struct cpu *) = NULL;

	starfire_cpu_poweroff =
	    (int (*)(struct cpu *))kobj_getsymvalue("drmach_cpu_poweroff", 0);

	if (starfire_cpu_poweroff == NULL)
		return (ENOTSUP);
	else
		return ((starfire_cpu_poweroff)(cp));
}

void
plat_dmv_params(uint_t *hwint, uint_t *swint)
{
	*hwint = STARFIRE_DMV_HWINT;
	*swint = 0;
}

/*
 * The following our currently private to Starfire DR
 */
int
plat_max_boards()
{
	return (starfire_boards);
}

int
plat_max_cpu_units_per_board()
{
	return (starfire_cpu_per_board);
}

int
plat_max_mem_units_per_board()
{
	return (starfire_mem_per_board);
}

int
plat_max_io_units_per_board()
{
	return (starfire_io_per_board);
}


/*
 * This index is used to associate a given pfn to a place on the freelist.
 * This results in dispersing pfn assignment over all the boards in the
 * system.
 * Choose the index randomly to prevent clustering pages of different
 * colors on the same board.
 */
static uint_t random_idx(int ubound);

#define	PFN_2_LBN(pfn)	(((pfn) >> (STARFIRE_MC_MEMBOARD_SHIFT - PAGESHIFT)) % \
			STARFIRE_MAX_BOARDS)

void
plat_freelist_process(int mnode)
{
	page_t		*page, **freelist;
	page_t		*bdlist[STARFIRE_MAX_BOARDS];
	page_t		 **sortlist[STARFIRE_MAX_BOARDS];
	uint32_t	idx, idy, size, color, max_color, lbn;
	uint32_t	bd_flags, bd_cnt, result, bds;
	kmutex_t	*pcm;
	int 		mtype;

	/* for each page size */
	for (mtype = 0; mtype < MAX_MEM_TYPES; mtype++) {
		for (size = 0; size < mmu_page_sizes; size++) {

			/*
			 * Compute the maximum # of phys colors based on
			 * page size.
			 */
			max_color = page_get_pagecolors(size);

			/* for each color */
			for (color = 0; color < max_color; color++) {

				bd_cnt = 0;
				bd_flags = 0;
				for (idx = 0; idx < STARFIRE_MAX_BOARDS;
				    idx++) {
					bdlist[idx] = NULL;
					sortlist[idx] = NULL;
				}

				/* find freelist */
				freelist = &PAGE_FREELISTS(mnode, size,
				    color, mtype);

				if (*freelist == NULL)
					continue;

				/* acquire locks */
				pcm = PC_BIN_MUTEX(mnode, color, PG_FREE_LIST);
				mutex_enter(pcm);

				/*
				 * read freelist & sort pages by logical
				 * board number
				 */
				/* grab pages till last one. */
				while (*freelist) {
					page = *freelist;
					result = page_trylock(page, SE_EXCL);

					ASSERT(result);

					/* Delete from freelist */
					if (size != 0) {
						page_vpsub(freelist, page);
					} else {
						mach_page_sub(freelist, page);
					}

					/* detect the lbn */
					lbn = PFN_2_LBN(page->p_pagenum);

					/* add to bdlist[lbn] */
					if (size != 0) {
						page_vpadd(&bdlist[lbn], page);
					} else {
						mach_page_add(&bdlist[lbn],
						    page);
					}

					/* if lbn new */
					if ((bd_flags & (1 << lbn)) == 0) {
						bd_flags |= (1 << lbn);
						bd_cnt++;
					}
					page_unlock(page);
				}

				/*
				 * Make the sortlist so
				 * bd_cnt choices show up
				 */
				bds = 0;
				for (idx = 0; idx < STARFIRE_MAX_BOARDS;
				    idx++) {
					if (bdlist[idx])
						sortlist[bds++] = &bdlist[idx];
				}

				/*
				 * Set random start.
				 */
				(void) random_idx(-color);

				/*
				 * now rebuild the freelist by shuffling
				 * pages from bd lists
				 */
				while (bd_cnt) {

					/*
					 * get "random" index between 0 &
					 * bd_cnt
					 */

					ASSERT(bd_cnt &&
					    (bd_cnt < STARFIRE_MAX_BOARDS+1));

					idx = random_idx(bd_cnt);

					page = *sortlist[idx];
					result = page_trylock(page, SE_EXCL);

					ASSERT(result);

					/* Delete from sort_list */
					/*  & Append to freelist */
					/* Big pages use vp_add - 8k don't */
					if (size != 0) {
						page_vpsub(sortlist[idx], page);
						page_vpadd(freelist, page);
					} else {
						mach_page_sub(sortlist[idx],
						    page);
						mach_page_add(freelist, page);
					}

					/* needed for indexing tmp lists */
					lbn = PFN_2_LBN(page->p_pagenum);

					/*
					 * if this was the last page on this
					 * list?
					 */
					if (*sortlist[idx] == NULL) {

						/* have to find brd list */

						/* idx is lbn? -- No! */
						/* sortlist, brdlist */
						/*  have diff indexs */
						bd_flags &= ~(1 << lbn);
						--bd_cnt;

						/*
						 * redo the sortlist so only
						 * bd_cnt choices show up
						 */
						bds = 0;
						for (idy = 0;
						    idy < STARFIRE_MAX_BOARDS;
						    idy++) {
							if (bdlist[idy]) {
								sortlist[bds++]
								/* CSTYLED */
								= &bdlist[idy];
							}
						}
					}
					page_unlock(page);
				}
				mutex_exit(pcm);
			}
		}
	}
}

/*
 * If ubound > 0, will return an int between 0 & ubound
 * If ubound < 0, will set "random seed"
 */
static uint_t
random_idx(int ubound)
{
	static int idx = 0;

	if (ubound > 0) {
		idx = (idx + 1) % ubound;
		return (idx);
	}
	idx = -ubound;
	return (0);
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
 * Update signature block and the signature ring buffer of a given cpu_id.
 */
void
cpu_sgn_update(ushort_t sgn, uchar_t state, uchar_t sub_state, int cpuid)
{
	uchar_t idx;
	cpu_sgnblk_t *cpu_sgnblkptr;

	/*
	 * cpuid == -1 indicates that the operation applies to all cpus.
	 */
	if (cpuid < 0) {
		sgn_update_all_cpus(sgn, state, sub_state);
		return;
	}

	if (cpu_sgnblkp[cpuid] == NULL)
		return;

	cpu_sgnblkptr = cpu_sgnblkp[cpuid];

	/*
	 *  Map new generic cpu states to older Starfire states.
	 */
	switch (state) {
	case SIGST_OFFLINE:
		state = SIGBST_OFFLINE;
		break;
	case SIGST_RESUME_INPROGRESS:
		state = SIGBST_RESUME_INPROGRESS;
		break;
	case SIGST_QUIESCE_INPROGRESS:
		state = SIGBST_QUIESCE_INPROGRESS;
		break;
	case SIGST_QUIESCED:
		state = SIGBST_QUIESCED;
		break;
	case SIGST_EXIT:
		switch (sub_state) {
		case SIGSUBST_DEBUG:
			state = SIGBST_RUN;
			sub_state = EXIT_NULL;
			break;
		case SIGSUBST_PANIC_CONT:
			state = SIGBST_RUN;
			sub_state = EXIT_PANIC2;
			break;
		case SIGSUBST_DUMP:
			state = SIGBST_EXIT;
			sub_state = EXIT_PANIC2;
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	cpu_sgnblkptr->sigb_signature.state_t.sig = sgn;
	cpu_sgnblkptr->sigb_signature.state_t.state = state;
	cpu_sgnblkptr->sigb_signature.state_t.sub_state = sub_state;

	/* Update the ring buffer */
	idx = cpu_sgnblkptr->sigb_ringbuf.wr_ptr;
	cpu_sgnblkptr->sigb_ringbuf.ringbuf[idx].state_t.sig = sgn;
	cpu_sgnblkptr->sigb_ringbuf.ringbuf[idx].state_t.state = state;
	cpu_sgnblkptr->sigb_ringbuf.ringbuf[idx].state_t.sub_state = sub_state;
	cpu_sgnblkptr->sigb_ringbuf.wr_ptr += 1;
	cpu_sgnblkptr->sigb_ringbuf.wr_ptr &= RB_IDX_MASK;
}

/*
 * Update signature block and the signature ring buffer of all CPUs.
 */
void
sgn_update_all_cpus(ushort_t sgn, uchar_t state, uchar_t sub_state)
{
	int i = 0;
	uchar_t cpu_state;
	uchar_t cpu_sub_state;

	for (i = 0; i < NCPU; i++) {
		cpu_sgnblk_t *sblkp;

		sblkp = cpu_sgnblkp[i];
		cpu_sub_state = sub_state;

		if ((sblkp != NULL) && (cpu[i] != NULL && (cpu[i]->cpu_flags &
		    (CPU_EXISTS|CPU_QUIESCED)))) {

			if (sub_state == EXIT_REBOOT) {
				cpu_sub_state =
				    sblkp->sigb_signature.state_t.sub_state;

				if ((cpu_sub_state == EXIT_PANIC1) ||
				    (cpu_sub_state == EXIT_PANIC2))
					cpu_sub_state = EXIT_PANIC_REBOOT;
				else
					cpu_sub_state = EXIT_REBOOT;
			}

			/*
			 * If we get here from an OBP sync after watchdog,
			 * we need to retain the watchdog sync state so that
			 * hostmon knows what's going on.  So if we're in
			 * watchdog we don't update the state.
			 */

			cpu_state = sblkp->sigb_signature.state_t.state;
			if (cpu_state == SIGBST_WATCHDOG_SYNC)
				cpu_sgn_update(sgn, SIGBST_WATCHDOG_SYNC,
				    cpu_sub_state, i);
			else if (cpu_state == SIGBST_REDMODE_SYNC)
				cpu_sgn_update(sgn, SIGBST_REDMODE_SYNC,
				    cpu_sub_state, i);
			else
				cpu_sgn_update(sgn, state, cpu_sub_state, i);
		}
	}
}

int
cpu_sgn_exists(int cpuid)
{
	return (cpu_sgnblkp[cpuid] != NULL);
}

ushort_t
get_cpu_sgn(int cpuid)
{
	if (cpu_sgnblkp[cpuid] == NULL)
		return ((ushort_t)-1);

	return (cpu_sgnblkp[cpuid]->sigb_signature.state_t.sig);
}

uchar_t
get_cpu_sgn_state(int cpuid)
{
	if (cpu_sgnblkp[cpuid] == NULL)
		return ((uchar_t)-1);

	return (cpu_sgnblkp[cpuid]->sigb_signature.state_t.state);
}

/*
 * KDI functions - used by the in-situ kernel debugger (kmdb) to perform
 * platform-specific operations.  These functions execute when the world is
 * stopped, and as such cannot make any blocking calls, hold locks, etc.
 * promif functions are a special case, and may be used.
 */

static void
starfire_system_claim(void)
{
	lbolt_debug_entry();

	prom_interpret("sigb-sig! my-sigb-sig!", OBP_SIG, OBP_SIG, 0, 0, 0);
}

static void
starfire_system_release(void)
{
	prom_interpret("sigb-sig! my-sigb-sig!", OS_SIG, OS_SIG, 0, 0, 0);

	lbolt_debug_return();
}

void
plat_kdi_init(kdi_t *kdi)
{
	kdi->pkdi_system_claim = starfire_system_claim;
	kdi->pkdi_system_release = starfire_system_release;
}
