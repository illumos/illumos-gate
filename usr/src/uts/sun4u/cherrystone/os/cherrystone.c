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
 * Table that maps memory slices to a specific memnode.
 */
int slice_to_memnode[CHERRYSTONE_MAX_SLICE];

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

	mutex_init(&cherry_pcf8584_mutex, NULL, MUTEX_ADAPTIVE, NULL);
}

#pragma weak mmu_init_large_pages

void
set_platform_defaults(void)
{
	extern void mmu_init_large_pages(size_t);

	if ((mmu_page_sizes == max_mmu_page_sizes) &&
	    (mmu_ism_pagesize != DEFAULT_ISM_PAGESIZE)) {
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

	/*
	 * prevent detach of i2c-ssc050
	 */
	e_ddi_hold_devi(keysw_dip);

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
		cmn_err(CE_WARN, "keyswitch polling disabled: "
		    "errno=%d while reading ssc050", err);
		return;
	}

	key_locked_bit = (boolean_t)((port_byte & 0x1));
	(void) timeout(keyswitch_poll, (caddr_t)dip, keypoll_timeout_hz);
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

/*ARGSUSED*/
void
plat_freelist_process(int mnode)
{
}

/*
 * Called for each board/cpu/PA range detected in plat_fill_mc().
 */
static void
update_mem_bounds(int boardid, int cpuid, int bankid,
    uint64_t base, uint64_t size)
{
	uint64_t	end;
	int		mnode;

	slice_table[boardid][cpuid][bankid][SLICE_PA] = base;
	slice_table[boardid][cpuid][bankid][SLICE_SPAN] = size;

	end = base + size - 1;

	/*
	 * First see if this board already has a memnode associated
	 * with it.  If not, see if this slice has a memnode.  This
	 * covers the cases where a single slice covers multiple
	 * boards (cross-board interleaving) and where a single
	 * board has multiple slices (1+GB DIMMs).
	 */
	if ((mnode = plat_lgrphand_to_mem_node(boardid)) == -1) {
		if ((mnode = slice_to_memnode[PA_2_SLICE(base)]) == -1)
			mnode = mem_node_alloc();

		ASSERT(mnode >= 0);
		ASSERT(mnode < MAX_MEM_NODES);
		plat_assign_lgrphand_to_mem_node(boardid, mnode);
	}

	base = P2ALIGN(base, (1ul << PA_SLICE_SHIFT));

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
	pgcnt_t npgs;

	mem_node_pfn_shift = PFN_SLICE_SHIFT;
	mem_node_physalign = (1ull << PA_SLICE_SHIFT);
	npgs = 1ull << PFN_SLICE_SHIFT;

	for (slice = 0; slice < CHERRYSTONE_MAX_SLICE; slice++) {
		if (slice_to_memnode[slice] == -1)
			continue;
		basepfn = (uint64_t)slice << PFN_SLICE_SHIFT;
		mem_node_add_slice(basepfn, basepfn + npgs - 1);
	}
}



/*
 * Cherrystone support for lgroups.
 *
 * On Cherrystone, an lgroup platform handle == slot number.
 *
 * Mappings between lgroup handles and memnodes are managed
 * in addition to mappings between memory slices and memnodes
 * to support cross-board interleaving as well as multiple
 * slices per board (e.g. >1GB DIMMs). The initial mapping
 * of memnodes to lgroup handles is determined at boot time.
 */

int
plat_pfn_to_mem_node(pfn_t pfn)
{
	return (slice_to_memnode[PFN_2_SLICE(pfn)]);
}

/*
 * Return the platform handle for the lgroup containing the given CPU
 *
 * For Cherrystone, lgroup platform handle == slot/board number
 */
lgrp_handle_t
plat_lgrp_cpu_to_hand(processorid_t id)
{
	return (CHERRYSTONE_GETSLOT(id));
}

/*
 * Platform specific lgroup initialization
 */
void
plat_lgrp_init(void)
{
	int i;

	/*
	 * Initialize lookup tables to invalid values so we catch
	 * any illegal use of them.
	 */
	for (i = 0; i < CHERRYSTONE_MAX_SLICE; i++) {
		slice_to_memnode[i] = -1;
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
		return (21);
	else
		return (19);
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

	(void) strcpy(old_unum, unum);
	(void) snprintf(unum, UNUM_NAMLEN, "Slot %c: %s", board, old_unum);
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
