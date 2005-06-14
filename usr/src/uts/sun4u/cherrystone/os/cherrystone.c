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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/sunddi.h>
#include <sys/esunddi.h>
#include <sys/sunndi.h>
#include <sys/ddi.h>
#include <sys/modctl.h>
#include <sys/sysmacros.h>
#include <sys/note.h>

#include <sys/platform_module.h>
#include <sys/errno.h>
#include <sys/i2c/clients/i2c_client.h>
#include <sys/cherrystone.h>
#include <sys/machsystm.h>
#include <sys/promif.h>
#include <vm/page.h>
#include <sys/memnode.h>
#include <vm/vm_dep.h>

/* Cherrystone Keyswitch Information */
#define	CHERRY_KEY_POLL_PORT	3
#define	CHERRY_KEY_POLL_BIT	2
#define	CHERRY_KEY_POLL_INTVL	10

#define	SHARED_PCF8584_PATH "/pci@9,700000/ebus@1/i2c@1,2e/nvram@4,a4"
static dev_info_t *shared_pcf8584_dip;
static kmutex_t cherry_pcf8584_mutex;

static	boolean_t	key_locked_bit;
static	clock_t		keypoll_timeout_hz;

/*
 * For software memory interleaving support.
 */
static void update_mem_bounds(int, int, int, uint64_t, uint64_t);

static uint64_t
slice_table[CHERRYSTONE_SBD_SLOTS][CHERRYSTONE_CPUS_PER_BOARD]
		[CHERRYSTONE_BANKS_PER_MC][2];

#define	SLICE_PA	0
#define	SLICE_SPAN	1

/* Function prototypes */
int (*p2get_mem_unum)(int, uint64_t, char *, int, int *);

int (*cherry_ssc050_get_port_bit) (dev_info_t *, int, int, uint8_t *, int);
extern	void (*abort_seq_handler)();

static	int cherry_dev_search(dev_info_t *, void *);
static	void keyswitch_poll(void *);
static	void cherry_abort_seq_handler(char *msg);

/* Function definitions from this point forward. */

int
set_platform_tsb_spares()
{
	return (0);
}

void
startup_platform(void)
{
	/*
	 * Disable an active h/w watchdog timer
	 * upon exit to OBP.
	 */
	extern int disable_watchdog_on_exit;
	disable_watchdog_on_exit = 1;

	mutex_init(&cherry_pcf8584_mutex, NULL, NULL, NULL);
}

#pragma weak mmu_init_large_pages

void
set_platform_defaults(void)
{
	extern void mmu_init_large_pages(size_t);

	if ((mmu_page_sizes == max_mmu_page_sizes) &&
	    (mmu_ism_pagesize != MMU_PAGESIZE32M)) {
		if (&mmu_init_large_pages)
			mmu_init_large_pages(mmu_ism_pagesize);
	}
}

void
load_platform_modules(void)
{
	if (modload("drv", "pmc") < 0) {
		cmn_err(CE_NOTE, "pmc driver failed to load");
	}
}

void
load_platform_drivers(void)
{
	char		**drv;
	dev_info_t	*i2cnexus_dip;
	dev_info_t	*keysw_dip = NULL;

	static char	*boot_time_drivers[] = {
		"todds1287",
		"mc-us3",
		"ssc050",
		NULL
	};

	for (drv = boot_time_drivers; *drv; drv++) {
		if (i_ddi_attach_hw_nodes(*drv) != DDI_SUCCESS)
			cmn_err(CE_WARN, "Failed to install \"%s\" driver.",
				*drv);
	}

	/*
	 * mc-us3 and ssc050 must stay loaded for plat_get_mem_unum()
	 * and keyswitch_poll()
	 */
	(void) ddi_hold_driver(ddi_name_to_major("mc-us3"));
	(void) ddi_hold_driver(ddi_name_to_major("ssc050"));

	/* Gain access into the ssc050_get_port function */
	cherry_ssc050_get_port_bit = (int (*) (dev_info_t *, int, int,
		uint8_t *, int)) modgetsymvalue("ssc050_get_port_bit", 0);
	if (cherry_ssc050_get_port_bit == NULL) {
		cmn_err(CE_WARN, "cannot find ssc050_get_port_bit");
		return;
	}

	e_ddi_walk_driver("i2c-ssc050", cherry_dev_search, (void *)&keysw_dip);
	ASSERT(keysw_dip != NULL);

	keypoll_timeout_hz = drv_usectohz(10 * MICROSEC);
	keyswitch_poll(keysw_dip);
	abort_seq_handler = cherry_abort_seq_handler;

	/*
	 * Figure out which pcf8584_dip is shared with OBP for the nvram
	 * device, so the lock can be acquired.
	 */

	i2cnexus_dip = e_ddi_hold_devi_by_path(SHARED_PCF8584_PATH, 0);

	ASSERT(i2cnexus_dip != NULL);
	shared_pcf8584_dip = ddi_get_parent(i2cnexus_dip);

	ndi_hold_devi(shared_pcf8584_dip);
	ndi_rele_devi(i2cnexus_dip);
}

static int
cherry_dev_search(dev_info_t *dip, void *arg)
{
	int		*dev_regs; /* Info about where the device is. */
	uint_t		len;
	int		err;

	if (strcmp(ddi_binding_name(dip), "i2c-ssc050") != 0)
		return (DDI_WALK_CONTINUE);

	err = ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
		DDI_PROP_DONTPASS, "reg", &dev_regs, &len);
	if (err != DDI_PROP_SUCCESS) {
		return (DDI_WALK_CONTINUE);
	}
	/*
	 * regs[0] contains the bus number and regs[1]
	 * contains the device address of the i2c device.
	 * 0x82 is the device address of the i2c device
	 * from which  the key switch position is read.
	 */
	if (dev_regs[0] == 0 && dev_regs[1] == 0x82) {
		*((dev_info_t **)arg) = dip;
		ddi_prop_free(dev_regs);
		return (DDI_WALK_TERMINATE);
	}
	ddi_prop_free(dev_regs);
	return (DDI_WALK_CONTINUE);
}

static void
keyswitch_poll(void *arg)
{
	dev_info_t	*dip = arg;
	uchar_t	port_byte;
	int	port = CHERRY_KEY_POLL_PORT;
	int	bit = CHERRY_KEY_POLL_BIT;
	int	err;

	err = cherry_ssc050_get_port_bit(dip, port, bit,
		&port_byte, I2C_NOSLEEP);
	if (err != 0) {
		return;
	}

	key_locked_bit = (boolean_t)((port_byte & 0x1));
	timeout(keyswitch_poll, (caddr_t)dip, keypoll_timeout_hz);
}

static void
cherry_abort_seq_handler(char *msg)
{
	if (key_locked_bit == 0)
		cmn_err(CE_CONT, "KEY in LOCKED position, "
			"ignoring debug enter sequence");
	else  {
		debug_enter(msg);
	}
}


/*ARGSUSED*/
int
plat_cpu_poweron(struct cpu *cp)
{
	return (ENOTSUP);	/* not supported on this platform */
}

/*ARGSUSED*/
int
plat_cpu_poweroff(struct cpu *cp)
{
	return (ENOTSUP);	/* not supported on this platform */
}

/*
 * Given a pfn, return the board and beginning/end of the page's
 * memory controller's address range.
 */
static int
plat_discover_slice(pfn_t pfn, pfn_t *first, pfn_t *last)
{
	int bd, cpu, bank;

	for (bd = 0; bd < CHERRYSTONE_SBD_SLOTS; bd++) {
		for (cpu = 0; cpu < CHERRYSTONE_CPUS_PER_BOARD; cpu++) {
			for (bank = 0; bank < CHERRYSTONE_BANKS_PER_MC;
				bank++) {
				uint64_t *slice = slice_table[bd][cpu][bank];
				uint64_t base = btop(slice[SLICE_PA]);
				uint64_t len = btop(slice[SLICE_SPAN]);
				if (len && pfn >= base && pfn < (base + len)) {
					*first = base;
					*last = base + len - 1;
					return (bd);
				}
			}
		}
	}
	panic("plat_discover_slice: no slice for pfn 0x%lx\n", pfn);
	/* NOTREACHED */
}

/*
 * This index is used to associate a given pfn to a place on the freelist.
 * This results in dispersing pfn assignment over all the boards in the
 * system.
 * Choose the index randomly to prevent clustering pages of different
 * colors on the same board.
 */
static uint_t random_idx(int ubound);

/*
 * Theory of operation:
 *	- When the system walks the prom tree, it calls the platform
 *	  function plat_fill_mc() for each memory-controller node found
 *	  in map_wellknown().
 *	- The plat_fill_mc() function interrogates the memory controller
 *	  to find out if it controls memory.  If it does, the physical
 *	  address and span are recorded in a lookup table.
 *	- During VM init, the VM calls plat_freelist_process() to shuffle
 *	  the page freelists.  This is done after the page freelists are
 *	  coalesced, but before the system goes live, since we need to be
 *	  able to get the exclusive lock on all the pages.
 *	- plat_freelist_process() removes all pages from the freelists,
 *	  and sorts them out into per-board freelists.  It does this by
 *	  using the lookup table that was built earlier.  It then
 *	  round-robins across the per-board freelists and frees each page,
 *	  leaving an even distribution of pages across the system.
 */
void
plat_freelist_process(int mnode)
{
	page_t		*page, **freelist;
	page_t		*bdlist[CHERRYSTONE_SBD_SLOTS];
	page_t		**sortlist[CHERRYSTONE_SBD_SLOTS];
	uint32_t	idx, idy, size, color, max_color, lbn;
	uint32_t	bd_flags, bd_cnt, result, bds;
	pfn_t		slice_start, slice_end, pfn;
	kmutex_t	*pcm;
	int		mtype;

	/*
	 * Sort through freelists one memory type and size at a time.
	 */
	for (mtype = 0; mtype < MAX_MEM_TYPES; mtype++) {
		for (size = 0; size < mmu_page_sizes; size++) {
			/*
			 * Compute the maximum # of phys colors based on
			 * page size.
			 */
			max_color = page_get_pagecolors(size);

			/*
			 * Sort through freelists one color at a time.
			 */
			for (color = 0; color < max_color; color++) {
				bd_cnt = 0;
				bd_flags = 0;
				slice_start = (pfn_t)-1;
				slice_end = (pfn_t)-1;

				for (idx = 0; idx < CHERRYSTONE_SBD_SLOTS;
					idx++) {
					bdlist[idx] = NULL;
					sortlist[idx] = NULL;
				}

				freelist = &PAGE_FREELISTS(mnode, size,
				    color, mtype);

				if (*freelist == NULL)
					continue;

				/*
				 * Acquire per-color freelist lock.
				 */
				pcm = PC_BIN_MUTEX(mnode, color, PG_FREE_LIST);
				mutex_enter(pcm);

				/*
				 * Go through freelist, sorting pages out
				 * into per-board lists.
				 */
				while (*freelist) {
					page = *freelist;
					result = page_trylock(page, SE_EXCL);
					ASSERT(result);

					/*
					 * Delete from freelist.
					 */
					if (size != 0) {
						page_vpsub(freelist, page);
					} else {
						mach_page_sub(freelist, page);
					}

					pfn = page->p_pagenum;
					if (pfn < slice_start ||
					    pfn > slice_end)
						lbn = plat_discover_slice(pfn,
						    &slice_start, &slice_end);

					/*
					 * Add to per-board list.
					 */
					if (size != 0) {
						page_vpadd(&bdlist[lbn], page);
					} else {
						mach_page_add(&bdlist[lbn],
						    page);
					}

					/*
					 * Seen this board yet?
					 */
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
				for (idx = 0; idx < CHERRYSTONE_SBD_SLOTS;
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
					    (bd_cnt < CHERRYSTONE_SBD_SLOTS+1));

					idx = random_idx(bd_cnt);

					page = *sortlist[idx];
					result = page_trylock(page, SE_EXCL);
					ASSERT(result);

					/*
					 * Delete from sort list and add
					 * to freelist.
					 */
					if (size != 0) {
						page_vpsub(sortlist[idx], page);
						page_vpadd(freelist, page);
					} else {
						mach_page_sub(sortlist[idx],
						    page);
						mach_page_add(freelist, page);
					}

					pfn = page->p_pagenum;
					if (pfn < slice_start ||
					    pfn > slice_end)
						lbn = plat_discover_slice(pfn,
						    &slice_start, &slice_end);

					/*
					 * Is this the last page this list?
					 */
					if (*sortlist[idx] == NULL) {
						bd_flags &= ~(1 << lbn);
						--bd_cnt;

						/*
						 * redo the sortlist so only
						 * bd_cnt choices show up
						 */
						bds = 0;
						for (idy = 0;
						    idy < CHERRYSTONE_SBD_SLOTS;
						    idy++) {
							if (bdlist[idy]) {
							    sortlist[bds++]
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
 * Called for each board/cpu/PA range detected in plat_fill_mc().
 */
static void
update_mem_bounds(int boardid, int cpuid, int bankid,
	uint64_t base, uint64_t size)
{
	slice_table[boardid][cpuid][bankid][SLICE_PA] = base;
	slice_table[boardid][cpuid][bankid][SLICE_SPAN] = size;
}

/*
 * Dynamically detect memory slices in the system by decoding
 * the cpu memory decoder registers at boot time.
 */
void
plat_fill_mc(dnode_t nodeid)
{
	uint64_t	mc_addr, saf_addr;
	uint64_t	mc_decode[CHERRYSTONE_BANKS_PER_MC];
	uint64_t	base, size;
	uint64_t	saf_mask;
	uint64_t	offset;
	uint32_t	regs[4];
	int		len;
	int		local_mc;
	int		portid;
	int		boardid;
	int		cpuid;
	int		i;

	if ((prom_getprop(nodeid, "portid", (caddr_t)&portid) < 0) ||
	    (portid == -1))
		return;

	/*
	 * Decode the board number from the MC portid.  Assumes
	 * portid == safari agentid.
	 */
	boardid = CHERRYSTONE_GETSLOT(portid);
	cpuid = CHERRYSTONE_GETSID(portid);

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
	saf_addr = lddsafaddr(8);
	saf_mask = (uint64_t)SAF_MASK;
	if ((mc_addr & saf_mask) == saf_addr)
		local_mc = 1;
	else
		local_mc = 0;

	for (i = 0; i < CHERRYSTONE_BANKS_PER_MC; i++) {
		/*
		 * Memory decode masks are at offsets 0x10 - 0x28.
		 */
		offset = 0x10 + (i << 3);

		/*
		 * If the memory controller is local to this CPU, we use
		 * the special ASI to read the decode registers.
		 * Otherwise, we load the values from a magic address in
		 * I/O space.
		 */
		if (local_mc)
			mc_decode[i] = lddmcdecode(offset);
		else
			mc_decode[i] = lddphysio(mc_addr | offset);

		/*
		 * If the upper bit is set, we have a valid mask
		 */
		if ((int64_t)mc_decode[i] < 0) {
			/*
			 * The memory decode register is a bitmask field,
			 * so we can decode that into both a base and
			 * a span.
			 */
			base = MC_BASE(mc_decode[i]) << PHYS2UM_SHIFT;
			size = MC_UK2SPAN(mc_decode[i]);
			update_mem_bounds(boardid, cpuid, i, base, size);
		}
	}
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
int
plat_get_mem_unum(int synd_code, uint64_t flt_addr, int flt_bus_id,
    int flt_in_memory, ushort_t flt_status, char *buf, int buflen, int *lenp)
{
	if (flt_in_memory && (p2get_mem_unum != NULL))
		return (p2get_mem_unum(synd_code, P2ALIGN(flt_addr, 8),
			buf, buflen, lenp));
	else
		return (ENOTSUP);
}

/*
 * This platform hook gets called from mc_add_mem_unum_label() in the mc-us3
 * driver giving each platform the opportunity to add platform
 * specific label information to the unum for ECC error logging purposes.
 */
void
plat_add_mem_unum_label(char *unum, int mcid, int bank, int dimm)
{
	_NOTE(ARGUNUSED(bank, dimm))

	char board = CHERRYSTONE_GETSLOT_LABEL(mcid);
	char old_unum[UNUM_NAMLEN];

	strcpy(old_unum, unum);
	snprintf(unum, UNUM_NAMLEN, "Slot %c: %s", board, old_unum);
}

int
plat_get_cpu_unum(int cpuid, char *buf, int buflen, int *lenp)
{
	char board = CHERRYSTONE_GETSLOT_LABEL(cpuid);

	if (snprintf(buf, buflen, "Slot %c", board) >= buflen) {
		return (ENOSPC);
	} else {
		*lenp = strlen(buf);
		return (0);
	}
}

/*
 * Cherrystone's BBC pcf8584 controller is used by both OBP and the OS's i2c
 * drivers.  The 'eeprom' command executes OBP code to handle property requests.
 * If eeprom didn't do this, or if the controllers were partitioned so that all
 * devices on a given controller were driven by either OBP or the OS, this
 * wouldn't be necessary.
 *
 * Note that getprop doesn't have the same issue as it reads from cached
 * memory in OBP.
 */

/*
 * Common locking enter code
 */
void
plat_setprop_enter(void)
{
	mutex_enter(&cherry_pcf8584_mutex);
}

/*
 * Common locking exit code
 */
void
plat_setprop_exit(void)
{
	mutex_exit(&cherry_pcf8584_mutex);
}

/*
 * Called by pcf8584 driver
 */
void
plat_shared_i2c_enter(dev_info_t *i2cnexus_dip)
{
	if (i2cnexus_dip == shared_pcf8584_dip) {
		plat_setprop_enter();
	}
}

/*
 * Called by pcf8584 driver
 */
void
plat_shared_i2c_exit(dev_info_t *i2cnexus_dip)
{
	if (i2cnexus_dip == shared_pcf8584_dip) {
		plat_setprop_exit();
	}
}
