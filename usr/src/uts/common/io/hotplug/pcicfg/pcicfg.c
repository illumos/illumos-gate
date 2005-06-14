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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *     PCI configurator (pcicfg)
 */

#include <sys/isa_defs.h>

#include <sys/conf.h>
#include <sys/kmem.h>
#include <sys/debug.h>
#include <sys/modctl.h>
#include <sys/autoconf.h>

#include <sys/hwconf.h>
#include <sys/ddi_impldefs.h>

#include <sys/pci.h>

#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/hotplug/pci/pcicfg.h>

#include <sys/ndi_impldefs.h>

/*
 * The following macro enables hack to differentiate QFE device from a
 * Freshchoice and hence assigned different drivers which are  written
 * for the same silicon..Yikes.
 */
#if defined(__sparc)
#define	_EFCODE_WORKAROUND
#endif

/*
 * ************************************************************************
 * *** Implementation specific local data structures/definitions.	***
 * ************************************************************************
 */

static	int	pcicfg_start_devno = 0;	/* for Debug only */

#define	PCICFG_MAX_DEVICE 32
#define	PCICFG_MAX_FUNCTION 8
#define	PCICFG_MAX_REGISTER 64

#define	PCICFG_NODEVICE 42
#define	PCICFG_NOMEMORY 43
#define	PCICFG_NOMULTI	44

#define	PCICFG_HIADDR(n) ((uint32_t)(((uint64_t)(n) & 0xFFFFFFFF00000000)>> 32))
#define	PCICFG_LOADDR(n) ((uint32_t)((uint64_t)(n) & 0x00000000FFFFFFFF))
#define	PCICFG_LADDR(lo, hi)	(((uint64_t)(hi) << 32) | (uint32_t)(lo))

#define	PCICFG_HIWORD(n) ((uint16_t)(((uint32_t)(n) & 0xFFFF0000)>> 16))
#define	PCICFG_LOWORD(n) ((uint16_t)((uint32_t)(n) & 0x0000FFFF))
#define	PCICFG_HIBYTE(n) ((uint8_t)(((uint16_t)(n) & 0xFF00)>> 8))
#define	PCICFG_LOBYTE(n) ((uint8_t)((uint16_t)(n) & 0x00FF))

#define	PCICFG_ROUND_UP(addr, gran) ((uintptr_t)((gran+addr-1)&(~(gran-1))))
#define	PCICFG_ROUND_DOWN(addr, gran) ((uintptr_t)((addr) & ~(gran-1)))

#define	PCICFG_MEMGRAN 0x100000
#define	PCICFG_IOGRAN 0x1000
#define	PCICFG_4GIG_LIMIT 0xFFFFFFFFUL

#define	PCICFG_MEM_MULT 4
#define	PCICFG_IO_MULT 4
#define	PCICFG_RANGE_LEN 2 /* Number of range entries */

/*
 * The following typedef is used to represent a
 * 1275 "bus-range" property of a PCI Bus node.
 * DAF - should be in generic include file...
 */

typedef struct pcicfg_bus_range {
	uint32_t lo;
	uint32_t hi;
} pcicfg_bus_range_t;

typedef struct pcicfg_range {

	uint32_t child_hi;
	uint32_t child_mid;
	uint32_t child_lo;
	uint32_t parent_hi;
	uint32_t parent_mid;
	uint32_t parent_lo;
	uint32_t size_hi;
	uint32_t size_lo;

} pcicfg_range_t;

typedef struct hole hole_t;

struct hole {
	uint64_t	start;
	uint64_t	len;
	hole_t		*next;
};

typedef struct pcicfg_phdl pcicfg_phdl_t;

struct pcicfg_phdl {

	dev_info_t	*dip;		/* Associated with the attach point */
	pcicfg_phdl_t	*next;

	uint64_t	memory_base;	/* Memory base for this attach point */
	uint64_t	memory_last;
	uint64_t	memory_len;
	uint32_t	io_base;	/* I/O base for this attach point */
	uint32_t	io_last;
	uint32_t	io_len;

	int		error;
	uint_t		highest_bus;	/* Highest bus seen on the probe */

	hole_t		mem_hole;	/* Memory hole linked list. */
	hole_t		io_hole;	/* IO hole linked list */

	ndi_ra_request_t mem_req;	/* allocator request for memory */
	ndi_ra_request_t io_req;	/* allocator request for I/O */
};

struct pcicfg_standard_prop_entry {
    uchar_t *name;
    uint_t  config_offset;
    uint_t  size;
};


struct pcicfg_name_entry {
    uint32_t class_code;
    char  *name;
};

struct pcicfg_find_ctrl {
	uint_t		device;
	uint_t		function;
	dev_info_t	*dip;
};

/*
 * List of Indirect Config Map Devices. At least the intent of the
 * design is to look for a device in this list during the configure
 * operation, and if the device is listed here, then it is a nontransparent
 * bridge, hence load the driver and avail the config map services from
 * the driver. Class and Subclass should be as defined in the PCI specs
 * ie. class is 0x6, and subclass is 0x9.
 */
static struct {
	uint8_t		mem_range_bar_offset;
	uint8_t		io_range_bar_offset;
	uint8_t		prefetch_mem_range_bar_offset;
} pcicfg_indirect_map_devs[] = {
	PCI_CONF_BASE3, PCI_CONF_BASE2, PCI_CONF_BASE3,
	0,	0,	0,
};

#define	PCICFG_MAKE_REG_HIGH(busnum, devnum, funcnum, register)\
	(\
	((ulong_t)(busnum & 0xff) << 16)    |\
	((ulong_t)(devnum & 0x1f) << 11)    |\
	((ulong_t)(funcnum & 0x7) <<  8)    |\
	((ulong_t)(register & 0x3f)))

/*
 * debug macros:
 */
#if	defined(DEBUG)
extern void prom_printf(const char *, ...);

/*
 * Following values are defined for this debug flag.
 *
 * 1 = dump configuration header only.
 * 2 = dump generic debug data only (no config header dumped)
 * 3 = dump everything (both 1 and 2)
 */
int pcicfg_debug = 0;

static void debug(char *, uintptr_t, uintptr_t,
	uintptr_t, uintptr_t, uintptr_t);

#define	DEBUG0(fmt)\
	debug(fmt, 0, 0, 0, 0, 0);
#define	DEBUG1(fmt, a1)\
	debug(fmt, (uintptr_t)(a1), 0, 0, 0, 0);
#define	DEBUG2(fmt, a1, a2)\
	debug(fmt, (uintptr_t)(a1), (uintptr_t)(a2), 0, 0, 0);
#define	DEBUG3(fmt, a1, a2, a3)\
	debug(fmt, (uintptr_t)(a1), (uintptr_t)(a2),\
		(uintptr_t)(a3), 0, 0);
#define	DEBUG4(fmt, a1, a2, a3, a4)\
	debug(fmt, (uintptr_t)(a1), (uintptr_t)(a2),\
		(uintptr_t)(a3), (uintptr_t)(a4), 0);
#else
#define	DEBUG0(fmt)
#define	DEBUG1(fmt, a1)
#define	DEBUG2(fmt, a1, a2)
#define	DEBUG3(fmt, a1, a2, a3)
#define	DEBUG4(fmt, a1, a2, a3, a4)
#endif

/*
 * forward declarations for routines defined in this module (called here)
 */

static int pcicfg_add_config_reg(dev_info_t *,
	uint_t, uint_t, uint_t);
static int pcicfg_probe_children(dev_info_t *, uint_t, uint_t, uint_t);
static int pcicfg_match_dev(dev_info_t *, void *);
static dev_info_t *pcicfg_devi_find(dev_info_t *, uint_t, uint_t);
static pcicfg_phdl_t *pcicfg_find_phdl(dev_info_t *);
static pcicfg_phdl_t *pcicfg_create_phdl(dev_info_t *);
static int pcicfg_destroy_phdl(dev_info_t *);
static int pcicfg_sum_resources(dev_info_t *, void *);
static int pcicfg_allocate_chunk(dev_info_t *);
static int pcicfg_program_ap(dev_info_t *);
static int pcicfg_device_assign(dev_info_t *);
static int pcicfg_bridge_assign(dev_info_t *, void *);
static int pcicfg_free_resources(dev_info_t *);
static void pcicfg_setup_bridge(pcicfg_phdl_t *, ddi_acc_handle_t);
static void pcicfg_update_bridge(pcicfg_phdl_t *, ddi_acc_handle_t);
static int pcicfg_update_assigned_prop(dev_info_t *, pci_regspec_t *);
static void pcicfg_device_on(ddi_acc_handle_t);
static void pcicfg_device_off(ddi_acc_handle_t);
static int pcicfg_set_busnode_props(dev_info_t *);
static int pcicfg_free_bridge_resources(dev_info_t *);
static int pcicfg_free_device_resources(dev_info_t *);
static int pcicfg_teardown_device(dev_info_t *);
static void pcicfg_reparent_node(dev_info_t *, dev_info_t *);
static int pcicfg_config_setup(dev_info_t *, ddi_acc_handle_t *);
static void pcicfg_config_teardown(ddi_acc_handle_t *);
static void pcicfg_get_mem(pcicfg_phdl_t *, uint32_t, uint64_t *);
static void pcicfg_get_io(pcicfg_phdl_t *, uint32_t, uint32_t *);
static int pcicfg_update_ranges_prop(dev_info_t *, pcicfg_range_t *);
static uint_t pcicfg_configure_ntbridge(dev_info_t *, uint_t, uint_t);
static uint_t pcicfg_ntbridge_child(dev_info_t *);
static int pcicfg_indirect_map(dev_info_t *dip);
static uint_t pcicfg_get_ntbridge_child_range(dev_info_t *, uint64_t *,
				uint64_t *, uint_t);
static int pcicfg_is_ntbridge(dev_info_t *);
static int pcicfg_ntbridge_allocate_resources(dev_info_t *);
static int pcicfg_ntbridge_configure_done(dev_info_t *);
static int pcicfg_ntbridge_program_child(dev_info_t *);
static uint_t pcicfg_ntbridge_unconfigure(dev_info_t *);
static int pcicfg_ntbridge_unconfigure_child(dev_info_t *, uint_t);
static void pcicfg_free_hole(hole_t *);
static uint64_t pcicfg_alloc_hole(hole_t *, uint64_t *, uint32_t);

#ifdef DEBUG
static void pcicfg_dump_common_config(ddi_acc_handle_t config_handle);
static void pcicfg_dump_device_config(ddi_acc_handle_t);
static void pcicfg_dump_bridge_config(ddi_acc_handle_t config_handle);
static uint64_t pcicfg_unused_space(hole_t *, uint32_t *);

#define	PCICFG_DUMP_COMMON_CONFIG(hdl) (void)pcicfg_dump_common_config(hdl)
#define	PCICFG_DUMP_DEVICE_CONFIG(hdl) (void)pcicfg_dump_device_config(hdl)
#define	PCICFG_DUMP_BRIDGE_CONFIG(hdl) (void)pcicfg_dump_bridge_config(hdl)
#else
#define	PCICFG_DUMP_COMMON_CONFIG(handle)
#define	PCICFG_DUMP_DEVICE_CONFIG(handle)
#define	PCICFG_DUMP_BRIDGE_CONFIG(handle)
#endif
#ifdef	_EFCODE_WORKAROUND
static int pcicfg_update_ethernet(dev_info_t *, void *);
static int pcicfg_match_ethernet(dev_info_t *, void *);
static void pcicfg_fix_ethernet(dev_info_t *);
static int pcicfg_fcode_name(dev_info_t *, ddi_acc_handle_t, char *);
static int pcicfg_fcode_compatible(dev_info_t *, ddi_acc_handle_t, char *);
static int pcicfg_alarm_card(dev_info_t *dip);
static int pcicfg_create_ac_child(dev_info_t *dip);
#endif

static kmutex_t pcicfg_list_mutex; /* Protects the probe handle list */
static pcicfg_phdl_t *pcicfg_phdl_list = NULL;

#ifndef _DONT_USE_1275_GENERIC_NAMES
/*
 * Class code table
 */
static struct pcicfg_name_entry pcicfg_class_lookup [] = {

	{ 0x001, "display" },
	{ 0x100, "scsi" },
	{ 0x101, "ide" },
	{ 0x102, "fdc" },
	{ 0x103, "ipi" },
	{ 0x104, "raid" },
	{ 0x200, "ethernet" },
	{ 0x201, "token-ring" },
	{ 0x202, "fddi" },
	{ 0x203, "atm" },
	{ 0x300, "display" },
	{ 0x400, "video" },
	{ 0x401, "sound" },
	{ 0x500, "memory" },
	{ 0x501, "flash" },
	{ 0x600, "host" },
	{ 0x601, "isa" },
	{ 0x602, "eisa" },
	{ 0x603, "mca" },
	{ 0x604, "pci" },
	{ 0x605, "pcmcia" },
	{ 0x606, "nubus" },
	{ 0x607, "cardbus" },
	{ 0x609, "pci" },
	{ 0x700, "serial" },
	{ 0x701, "parallel" },
	{ 0x800, "interrupt-controller" },
	{ 0x801, "dma-controller" },
	{ 0x802, "timer" },
	{ 0x803, "rtc" },
	{ 0x900, "keyboard" },
	{ 0x901, "pen" },
	{ 0x902, "mouse" },
	{ 0xa00, "dock" },
	{ 0xb00, "cpu" },
	{ 0xc00, "firewire" },
	{ 0xc01, "access-bus" },
	{ 0xc02, "ssa" },
	{ 0xc03, "usb" },
	{ 0xc04, "fibre-channel" },
	{ 0, 0 }
};
#endif /* _DONT_USE_1275_GENERIC_NAMES */

/*
 * Module control operations
 */

extern struct mod_ops mod_miscops;

static struct modlmisc modlmisc = {
	&mod_miscops, /* Type of module */
	"PCI configurator %I%"
};

static struct modlinkage modlinkage = {
	MODREV_1, (void *)&modlmisc, NULL
};


#ifdef DEBUG

static void
pcicfg_dump_common_config(ddi_acc_handle_t config_handle)
{
	if ((pcicfg_debug & 1) == 0)
		return;
	prom_printf(" Vendor ID   = [0x%x]\n",
		pci_config_get16(config_handle, PCI_CONF_VENID));
	prom_printf(" Device ID   = [0x%x]\n",
		pci_config_get16(config_handle, PCI_CONF_DEVID));
	prom_printf(" Command REG = [0x%x]\n",
		pci_config_get16(config_handle, PCI_CONF_COMM));
	prom_printf(" Status  REG = [0x%x]\n",
		pci_config_get16(config_handle, PCI_CONF_STAT));
	prom_printf(" Revision ID = [0x%x]\n",
		pci_config_get8(config_handle, PCI_CONF_REVID));
	prom_printf(" Prog Class  = [0x%x]\n",
		pci_config_get8(config_handle, PCI_CONF_PROGCLASS));
	prom_printf(" Dev Class   = [0x%x]\n",
		pci_config_get8(config_handle, PCI_CONF_SUBCLASS));
	prom_printf(" Base Class  = [0x%x]\n",
		pci_config_get8(config_handle, PCI_CONF_BASCLASS));
	prom_printf(" Device ID   = [0x%x]\n",
		pci_config_get8(config_handle, PCI_CONF_CACHE_LINESZ));
	prom_printf(" Header Type = [0x%x]\n",
		pci_config_get8(config_handle, PCI_CONF_HEADER));
	prom_printf(" BIST        = [0x%x]\n",
		pci_config_get8(config_handle, PCI_CONF_BIST));
	prom_printf(" BASE 0      = [0x%x]\n",
		pci_config_get32(config_handle, PCI_CONF_BASE0));
	prom_printf(" BASE 1      = [0x%x]\n",
		pci_config_get32(config_handle, PCI_CONF_BASE1));

}

static void
pcicfg_dump_device_config(ddi_acc_handle_t config_handle)
{
	if ((pcicfg_debug & 1) == 0)
		return;
	pcicfg_dump_common_config(config_handle);

	prom_printf(" BASE 2      = [0x%x]\n",
		pci_config_get32(config_handle, PCI_CONF_BASE2));
	prom_printf(" BASE 3      = [0x%x]\n",
		pci_config_get32(config_handle, PCI_CONF_BASE3));
	prom_printf(" BASE 4      = [0x%x]\n",
		pci_config_get32(config_handle, PCI_CONF_BASE4));
	prom_printf(" BASE 5      = [0x%x]\n",
		pci_config_get32(config_handle, PCI_CONF_BASE5));
	prom_printf(" Cardbus CIS = [0x%x]\n",
		pci_config_get32(config_handle, PCI_CONF_CIS));
	prom_printf(" Sub VID     = [0x%x]\n",
		pci_config_get16(config_handle, PCI_CONF_SUBVENID));
	prom_printf(" Sub SID     = [0x%x]\n",
		pci_config_get16(config_handle, PCI_CONF_SUBSYSID));
	prom_printf(" ROM         = [0x%x]\n",
		pci_config_get32(config_handle, PCI_CONF_ROM));
	prom_printf(" I Line      = [0x%x]\n",
		pci_config_get8(config_handle, PCI_CONF_ILINE));
	prom_printf(" I Pin       = [0x%x]\n",
		pci_config_get8(config_handle, PCI_CONF_IPIN));
	prom_printf(" Max Grant   = [0x%x]\n",
		pci_config_get8(config_handle, PCI_CONF_MIN_G));
	prom_printf(" Max Latent  = [0x%x]\n",
		pci_config_get8(config_handle, PCI_CONF_MAX_L));
}

static void
pcicfg_dump_bridge_config(ddi_acc_handle_t config_handle)
{
	if ((pcicfg_debug & 1) == 0)
		return;
	pcicfg_dump_common_config(config_handle);

	prom_printf("........................................\n");

	prom_printf(" Pri Bus     = [0x%x]\n",
		pci_config_get8(config_handle, PCI_BCNF_PRIBUS));
	prom_printf(" Sec Bus     = [0x%x]\n",
		pci_config_get8(config_handle, PCI_BCNF_SECBUS));
	prom_printf(" Sub Bus     = [0x%x]\n",
		pci_config_get8(config_handle, PCI_BCNF_SUBBUS));
	prom_printf(" Latency     = [0x%x]\n",
		pci_config_get8(config_handle, PCI_BCNF_LATENCY_TIMER));
	prom_printf(" I/O Base LO = [0x%x]\n",
		pci_config_get8(config_handle, PCI_BCNF_IO_BASE_LOW));
	prom_printf(" I/O Lim LO  = [0x%x]\n",
		pci_config_get8(config_handle, PCI_BCNF_IO_LIMIT_LOW));
	prom_printf(" Sec. Status = [0x%x]\n",
		pci_config_get16(config_handle, PCI_BCNF_SEC_STATUS));
	prom_printf(" Mem Base    = [0x%x]\n",
		pci_config_get16(config_handle, PCI_BCNF_MEM_BASE));
	prom_printf(" Mem Limit   = [0x%x]\n",
		pci_config_get16(config_handle, PCI_BCNF_MEM_LIMIT));
	prom_printf(" PF Mem Base = [0x%x]\n",
		pci_config_get16(config_handle, PCI_BCNF_PF_BASE_LOW));
	prom_printf(" PF Mem Lim  = [0x%x]\n",
		pci_config_get16(config_handle, PCI_BCNF_PF_LIMIT_LOW));
	prom_printf(" PF Base HI  = [0x%x]\n",
		pci_config_get32(config_handle, PCI_BCNF_PF_BASE_HIGH));
	prom_printf(" PF Lim  HI  = [0x%x]\n",
		pci_config_get32(config_handle, PCI_BCNF_PF_LIMIT_HIGH));
	prom_printf(" I/O Base HI = [0x%x]\n",
		pci_config_get16(config_handle, PCI_BCNF_IO_BASE_HI));
	prom_printf(" I/O Lim HI  = [0x%x]\n",
		pci_config_get16(config_handle, PCI_BCNF_IO_LIMIT_HI));
	prom_printf(" ROM addr    = [0x%x]\n",
		pci_config_get32(config_handle, PCI_BCNF_ROM));
	prom_printf(" Intr Line   = [0x%x]\n",
		pci_config_get8(config_handle, PCI_BCNF_ILINE));
	prom_printf(" Intr Pin    = [0x%x]\n",
		pci_config_get8(config_handle, PCI_BCNF_IPIN));
	prom_printf(" Bridge Ctrl = [0x%x]\n",
		pci_config_get16(config_handle, PCI_BCNF_BCNTRL));
}
#endif

int
_init()
{
	DEBUG0(" PCI configurator installed\n");
	mutex_init(&pcicfg_list_mutex, NULL, MUTEX_DRIVER, NULL);
	return (mod_install(&modlinkage));
}

int
_fini(void)
{
	int error;

	error = mod_remove(&modlinkage);
	if (error != 0) {
		return (error);
	}
	mutex_destroy(&pcicfg_list_mutex);
	return (0);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * In the following functions ndi_devi_enter() without holding the
 * parent dip is sufficient. This is because  pci dr is driven through
 * opens on the nexus which is in the device tree path above the node
 * being operated on, and implicitly held due to the open.
 */

/*
 * This entry point is called to configure a device (and
 * all its children) on the given bus. It is called when
 * a new device is added to the PCI domain.  This routine
 * will create the device tree and program the devices
 * registers.
 */

int
pcicfg_configure(dev_info_t *devi, uint_t device)
{
	uint_t bus;
	int len;
	int func;
	dev_info_t *new_device;
	dev_info_t *attach_point;
	pcicfg_bus_range_t pci_bus_range;
	int rv;
	int circ;

	/*
	 * Start probing at the device specified in "device" on the
	 * "bus" specified.
	 */
	len = sizeof (pcicfg_bus_range_t);
	if (ddi_getlongprop_buf(DDI_DEV_T_NONE, devi, 0, "bus-range",
	    (caddr_t)&pci_bus_range, &len) != DDI_SUCCESS) {
		DEBUG0("no bus-range property\n");
		return (PCICFG_FAILURE);
	}

	bus = pci_bus_range.lo; /* primary bus number of this bus node */

	ndi_devi_alloc_sleep(devi, "hp_attachment",
		(dnode_t)DEVI_SID_NODEID, &attach_point);

	ndi_devi_enter(devi, &circ);
	for (func = 0; func < PCICFG_MAX_FUNCTION; func++) {

		DEBUG3("Configuring [0x%x][0x%x][0x%x]\n", bus, device, func);

		switch (rv = pcicfg_probe_children(attach_point,
			bus, device, func)) {
			case PCICFG_FAILURE:
				DEBUG2("configure failed: "
				"bus [0x%x] device [0x%x]\n",
					bus, device);
				goto cleanup;
			case PCICFG_NODEVICE:
				DEBUG3("no device : bus "
				"[0x%x] slot [0x%x] func [0x%x]\n",
					bus, device, func);
				break;
			default:
				DEBUG3("configure: bus => [%d] "
				"slot => [%d] func => [%d]\n",
					bus, device, func);
			break;
		}

		if (rv != PCICFG_SUCCESS)
			break;

		if ((new_device = pcicfg_devi_find(attach_point,
			device, func)) == NULL) {
			DEBUG0("Did'nt find device node just created\n");
			goto cleanup;
		}

		if (pcicfg_program_ap(new_device) == PCICFG_FAILURE) {
			DEBUG0("Failed to program devices\n");
			goto cleanup;
		}

		/*
		 * Reparent the subtree from pcicfg_probe_children
		 */
		(void) pcicfg_reparent_node(new_device, devi);

		/*
		 * Up until now, we have detected a non transparent bridge
		 * (ntbridge) as a part of the generic probe code and
		 * configured only one configuration
		 * header which is the side facing the host bus.
		 * Now, configure the other side and create children.
		 *
		 * In order to make the process simpler, lets load the device
		 * driver for the non transparent bridge as this is a
		 * Solaris bundled driver, and use its configuration map
		 * services rather than programming it here.
		 * If the driver is not bundled into Solaris, it must be
		 * first loaded and configured before performing any
		 * hotplug operations.
		 *
		 * This not only makes the code here simpler but also more
		 * generic.
		 *
		 * So here we go.
		 */

		/*
		 * check if this is a bridge in nontransparent mode
		 */
		if (pcicfg_is_ntbridge(new_device) != DDI_FAILURE) {

			int rc;

			DEBUG0("pcicfg: Found nontransparent bridge.\n");

			rc = pcicfg_configure_ntbridge(new_device, bus, device);
			if (rc == PCICFG_FAILURE)
				goto cleanup;
		}
#ifdef	_EFCODE_WORKAROUND
		(void) pcicfg_fix_ethernet(new_device);
#endif
	}

	(void) ndi_devi_free(attach_point);
	ndi_devi_exit(devi, circ);

	if (func == 0)
		return (PCICFG_FAILURE);	/* probe failed */
	else
		return (PCICFG_SUCCESS);

cleanup:
	/*
	 * Clean up a partially created "probe state" tree.
	 * There are no resources allocated to the in the
	 * probe state.
	 */

	for (func = 0; func < PCICFG_MAX_FUNCTION; func++) {
		if ((new_device = pcicfg_devi_find(devi,
			device, func)) == NULL) {
			DEBUG0("No more devices to clean up\n");
			break;
		}

		DEBUG2("Cleaning up device [0x%x] function [0x%x]\n",
			device, func);
		/*
		 * If this was a bridge device it will have a
		 * probe handle - if not, no harm in calling this.
		 */
		(void) pcicfg_destroy_phdl(new_device);
		/*
		 * This will free up the node
		 */
		(void) ndi_devi_offline(new_device, NDI_DEVI_REMOVE);
	}

	(void) ndi_devi_free(attach_point);
	ndi_devi_exit(devi, circ);

	return (PCICFG_FAILURE);
}

/*
 * configure the child nodes of ntbridge. new_device points to ntbridge itself
 */
/*ARGSUSED*/
static uint_t
pcicfg_configure_ntbridge(dev_info_t *new_device, uint_t bus, uint_t device)
{
	int bus_range[2], rc = PCICFG_FAILURE, rc1, max_devs = 0;
	int			devno;
	dev_info_t		*new_ntbridgechild;
	ddi_acc_handle_t	config_handle;
	uint16_t		vid;
	uint64_t		next_bus;
	uint64_t		blen;
	ndi_ra_request_t	req;

	/*
	 * If we need to do indirect config, lets create a property here
	 * to let the child conf map routine know that it has to
	 * go through the DDI calls, and not assume the devices are
	 * mapped directly under the host.
	 */
	if ((rc = ndi_prop_update_int(DDI_DEV_T_NONE, new_device,
		PCICFG_DEV_CONF_MAP_PROP, (int)DDI_SUCCESS))
						!= DDI_SUCCESS) {

		DEBUG0("Cannot create indirect conf map property.\n");
		return ((int)PCICFG_FAILURE);
	}

	/* create Bus node properties for ntbridge. */
	if (pcicfg_set_busnode_props(new_device) != PCICFG_SUCCESS) {
		DEBUG0("Failed to set busnode props\n");
		return (rc);
	}

	/* For now: Lets only support one layer of child */
	bzero((caddr_t)&req, sizeof (ndi_ra_request_t));
	req.ra_len = 1;
	if (ndi_ra_alloc(ddi_get_parent(new_device), &req,
		&next_bus, &blen, NDI_RA_TYPE_PCI_BUSNUM,
		NDI_RA_PASS) != NDI_SUCCESS) {
		DEBUG0("ntbridge: Failed to get a bus number\n");
		return (rc);
	}

	DEBUG1("ntbridge bus range start  ->[%d]\n", next_bus);

	/*
	 * Following will change, as we detect more bridges
	 * on the way.
	 */
	bus_range[0] = (int)next_bus;
	bus_range[1] = (int)next_bus;

	if (ndi_prop_update_int_array(DDI_DEV_T_NONE, new_device,
		"bus-range", bus_range, 2) != DDI_SUCCESS) {
		DEBUG0("Cannot set ntbridge bus-range property");
		return (rc);
	}

	/*
	 * The other interface (away from the host) will be
	 * initialized by the nexus driver when it loads.
	 * We just have to set the registers and the nexus driver
	 * figures out the rest.
	 */

	/*
	 * finally, lets load and attach the driver
	 * before configuring children of ntbridge.
	 */
	rc = ndi_devi_online(new_device, NDI_ONLINE_ATTACH|NDI_CONFIG);
	if (rc != NDI_SUCCESS) {
		cmn_err(CE_WARN,
		"pcicfg: Fail:cant load nontransparent bridgd driver..\n");
		rc = PCICFG_FAILURE;
		return (rc);
	}
	DEBUG0("pcicfg: Success loading nontransparent bridge nexus driver..");

	/* Now set aside pci resources for our children. */
	if (pcicfg_ntbridge_allocate_resources(new_device) !=
				PCICFG_SUCCESS) {
		max_devs = 0;
		rc = PCICFG_FAILURE;
	} else
		max_devs = PCICFG_MAX_DEVICE;

	/* Probe devices on 2nd bus */
	for (devno = pcicfg_start_devno; devno < max_devs; devno++) {

		ndi_devi_alloc_sleep(new_device, DEVI_PSEUDO_NEXNAME,
		    (dnode_t)DEVI_SID_NODEID, &new_ntbridgechild);

		if (pcicfg_add_config_reg(new_ntbridgechild, next_bus, devno, 0)
					!= DDI_PROP_SUCCESS) {
			cmn_err(CE_WARN,
				"Failed to add conf reg for ntbridge child.\n");
			(void) ndi_devi_free(new_ntbridgechild);
			rc = PCICFG_FAILURE;
			break;
		}

		if (pci_config_setup(new_ntbridgechild, &config_handle)
					!= DDI_SUCCESS) {
			cmn_err(CE_WARN,
				"Cannot map ntbridge child %x\n", devno);
			(void) ndi_devi_free(new_ntbridgechild);
			rc = PCICFG_FAILURE;
			break;
		}

		/*
		 * See if there is any PCI HW at this location
		 * by reading the Vendor ID.  If it returns with 0xffff
		 * then there is no hardware at this location.
		 */
		vid = pci_config_get16(config_handle, PCI_CONF_VENID);

		pci_config_teardown(&config_handle);
		(void) ndi_devi_free(new_ntbridgechild);
		if (vid	== 0xffff)
			continue;

		/* Lets fake attachments points for each child, */
		if (pcicfg_configure(new_device, devno) != PCICFG_SUCCESS) {
			int old_dev = pcicfg_start_devno;

			cmn_err(CE_WARN,
			"Error configuring ntbridge child dev=%d\n", devno);

			rc = PCICFG_FAILURE;
			while (old_dev != devno) {
				if (pcicfg_ntbridge_unconfigure_child(
					new_device, old_dev) == PCICFG_FAILURE)

					cmn_err(CE_WARN,
					"Unconfig Error ntbridge child "
					"dev=%d\n", old_dev);
				old_dev++;
			}
			break;
		}
	} /* devno loop */
	DEBUG1("ntbridge: finish probing 2nd bus, rc=%d\n", rc);

	if (rc != PCICFG_FAILURE)
		rc = pcicfg_ntbridge_configure_done(new_device);
	else {
		pcicfg_phdl_t *entry = pcicfg_find_phdl(new_device);
		uint_t			*bus;
		int			k;

		if (ddi_getlongprop(DDI_DEV_T_ANY, new_device,
			DDI_PROP_DONTPASS, "bus-range", (caddr_t)&bus,
			&k) != DDI_PROP_SUCCESS) {
			DEBUG0("Failed to read bus-range property\n");
			rc = PCICFG_FAILURE;
			return (rc);
		}

		DEBUG2("Need to free bus [%d] range [%d]\n",
			bus[0], bus[1] - bus[0] + 1);

		if (ndi_ra_free(ddi_get_parent(new_device),
			(uint64_t)bus[0], (uint64_t)(bus[1] - bus[0] + 1),
			NDI_RA_TYPE_PCI_BUSNUM, NDI_RA_PASS) != NDI_SUCCESS) {
			DEBUG0("Failed to free a bus number\n");
			rc = PCICFG_FAILURE;
			return (rc);
		}

		/*
		 * Since no memory allocations are done for non transparent
		 * bridges (but instead we just set the handle with the
		 * already allocated memory, we just need to reset the
		 * following values before calling the destroy_phdl()
		 * function next, otherwise the it will try to free
		 * memory allocated as in case of a transparent bridge.
		 */
		entry->memory_len = 0;
		entry->io_len = 0;
		/* the following will free hole data. */
		(void) pcicfg_destroy_phdl(new_device);
	}

	/*
	 * Unload driver just in case child configure failed!
	 */
	rc1 = ndi_devi_offline(new_device, 0);
	DEBUG1("pcicfg: now unloading the ntbridge driver. rc1=%d\n", rc1);
	if (rc1 != NDI_SUCCESS) {
		cmn_err(CE_WARN,
		"pcicfg: cant unload ntbridge driver..children.\n");
		rc = PCICFG_FAILURE;
	}

	return (rc);
}

static int
pcicfg_ntbridge_allocate_resources(dev_info_t *dip)
{
	pcicfg_phdl_t		*phdl;
	ndi_ra_request_t	*mem_request;
	ndi_ra_request_t	*io_request;
	uint64_t		boundbase, boundlen;

	phdl = pcicfg_find_phdl(dip);
	ASSERT(phdl);

	mem_request = &phdl->mem_req;
	io_request  = &phdl->io_req;

	phdl->error = PCICFG_SUCCESS;

	/* Set Memory space handle for ntbridge */
	if (pcicfg_get_ntbridge_child_range(dip, &boundbase, &boundlen,
			PCI_BASE_SPACE_MEM) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
			"ntbridge: Mem resource information failure\n");
		phdl->memory_len  = 0;
		return (PCICFG_FAILURE);
	}
	mem_request->ra_boundbase = boundbase;
	mem_request->ra_boundlen = boundbase + boundlen;
	mem_request->ra_len = boundlen;
	mem_request->ra_align_mask =
		PCICFG_MEMGRAN - 1; /* 1M alignment on memory space */
	mem_request->ra_flags |= NDI_RA_ALLOC_BOUNDED;

	/*
	 * mem_request->ra_len =
	 * PCICFG_ROUND_UP(mem_request->ra_len, PCICFG_MEMGRAN);
	 */

	phdl->memory_base = phdl->memory_last = boundbase;
	phdl->memory_len  = boundlen;
	phdl->mem_hole.start = phdl->memory_base;
	phdl->mem_hole.len = mem_request->ra_len;
	phdl->mem_hole.next = (hole_t *)NULL;

	DEBUG2("AP requested [0x%llx], needs [0x%llx] bytes of memory\n",
		boundlen, mem_request->ra_len);

	/* Set IO space handle for ntbridge */
	if (pcicfg_get_ntbridge_child_range(dip, &boundbase, &boundlen,
			PCI_BASE_SPACE_IO) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "ntbridge: IO resource information failure\n");
		phdl->io_len  = 0;
		return (PCICFG_FAILURE);
	}
	io_request->ra_len = boundlen;
	io_request->ra_align_mask =
		PCICFG_IOGRAN - 1;   /* 4K alignment on I/O space */
	io_request->ra_boundbase = boundbase;
	io_request->ra_boundlen = boundbase + boundlen;
	io_request->ra_flags |= NDI_RA_ALLOC_BOUNDED;

	/*
	 * io_request->ra_len =
	 * PCICFG_ROUND_UP(io_request->ra_len, PCICFG_IOGRAN);
	 */

	phdl->io_base = phdl->io_last = (uint32_t)boundbase;
	phdl->io_len  = (uint32_t)boundlen;
	phdl->io_hole.start = phdl->io_base;
	phdl->io_hole.len = io_request->ra_len;
	phdl->io_hole.next = (hole_t *)NULL;

	DEBUG2("AP requested [0x%llx], needs [0x%llx] bytes of IO\n",
		boundlen, io_request->ra_len);

	DEBUG2("MEMORY BASE = [0x%x] length [0x%x]\n",
		phdl->memory_base, phdl->memory_len);
	DEBUG2("IO     BASE = [0x%x] length [0x%x]\n",
		phdl->io_base, phdl->io_len);

	return (PCICFG_SUCCESS);
}

static int
pcicfg_ntbridge_configure_done(dev_info_t *dip)
{
	pcicfg_range_t range[PCICFG_RANGE_LEN];
	pcicfg_phdl_t		*entry;
	uint_t			len;
	pcicfg_bus_range_t	bus_range;
	int			new_bus_range[2];

	DEBUG1("Configuring children for %llx\n", dip);

	entry = pcicfg_find_phdl(dip);
	ASSERT(entry);

	bzero((caddr_t)range,
		sizeof (pcicfg_range_t) * PCICFG_RANGE_LEN);
	range[1].child_hi = range[1].parent_hi |=
		(PCI_REG_REL_M | PCI_ADDR_MEM32);
	range[1].child_lo = range[1].parent_lo = (uint32_t)entry->memory_base;

	range[0].child_hi = range[0].parent_hi |=
		(PCI_REG_REL_M | PCI_ADDR_IO);
	range[0].child_lo = range[0].parent_lo = (uint32_t)entry->io_base;

	len = sizeof (pcicfg_bus_range_t);
	if (ddi_getlongprop_buf(DDI_DEV_T_NONE, dip, DDI_PROP_DONTPASS,
		"bus-range", (caddr_t)&bus_range, (int *)&len) != DDI_SUCCESS) {
		DEBUG0("no bus-range property\n");
		return (PCICFG_FAILURE);
	}

	new_bus_range[0] = bus_range.lo;	/* primary bus number */
	if (entry->highest_bus) {	/* secondary bus number */
		if (entry->highest_bus < bus_range.lo) {
			cmn_err(CE_WARN,
				"ntbridge bus range invalid !(%d,%d)\n",
					bus_range.lo, entry->highest_bus);
			new_bus_range[1] = bus_range.lo + entry->highest_bus;
		}
		else
			new_bus_range[1] = entry->highest_bus;
	}
	else
		new_bus_range[1] = bus_range.hi;

	DEBUG2("ntbridge: bus range lo=%x, hi=%x\n",
				new_bus_range[0], new_bus_range[1]);

	if (ndi_prop_update_int_array(DDI_DEV_T_NONE, dip,
			"bus-range", new_bus_range, 2) != DDI_SUCCESS) {
		DEBUG0("Failed to set bus-range property");
		entry->error = PCICFG_FAILURE;
		return (PCICFG_FAILURE);
	}

#ifdef DEBUG
	{
		uint64_t	unused;
		unused = pcicfg_unused_space(&entry->io_hole, &len);
		DEBUG2("ntbridge: Unused IO space %llx bytes over %d holes\n",
							unused, len);
	}
#endif

	range[0].size_lo = entry->io_len;
	if (pcicfg_update_ranges_prop(dip, &range[0])) {
		DEBUG0("Failed to update ranges (i/o)\n");
		entry->error = PCICFG_FAILURE;
		return (PCICFG_FAILURE);
	}

#ifdef DEBUG
	{
		uint64_t	unused;
		unused = pcicfg_unused_space(&entry->mem_hole, &len);
		DEBUG2("ntbridge: Unused Mem space %llx bytes over %d holes\n",
							unused, len);
	}
#endif

	range[1].size_lo = entry->memory_len;
	if (pcicfg_update_ranges_prop(dip, &range[1])) {
		DEBUG0("Failed to update ranges (memory)\n");
		entry->error = PCICFG_FAILURE;
		return (PCICFG_FAILURE);
	}

	return (PCICFG_SUCCESS);
}

static int
pcicfg_ntbridge_program_child(dev_info_t *dip)
{
	pcicfg_phdl_t		*entry;
	int			rc = PCICFG_SUCCESS;
	dev_info_t	*anode = dip;

	/* Find the attachment point node */
	while ((anode != NULL) && (strcmp(ddi_binding_name(anode),
		"hp_attachment") != 0)) {
		anode = ddi_get_parent(anode);
	}

	if (anode == NULL) {
		DEBUG0("ntbridge child tree not in PROBE state\n");
		return (PCICFG_FAILURE);
	}
	entry = pcicfg_find_phdl(ddi_get_parent(anode));
	ASSERT(entry);

	if (pcicfg_bridge_assign(dip, entry) == DDI_WALK_TERMINATE) {
		cmn_err(CE_WARN,
			"ntbridge: Error assigning range for child %s\n",
				ddi_get_name(dip));
		rc = PCICFG_FAILURE;
	}
	return (rc);
}

static int
pcicfg_ntbridge_unconfigure_child(dev_info_t *new_device, uint_t devno)
{

	dev_info_t	*new_ntbridgechild;
	int 		len, bus;
	uint16_t	vid;
	ddi_acc_handle_t	config_handle;
	pcicfg_bus_range_t pci_bus_range;

	len = sizeof (pcicfg_bus_range_t);
	if (ddi_getlongprop_buf(DDI_DEV_T_NONE, new_device, DDI_PROP_DONTPASS,
		"bus-range", (caddr_t)&pci_bus_range, &len) != DDI_SUCCESS) {
		DEBUG0("no bus-range property\n");
		return (PCICFG_FAILURE);
	}

	bus = pci_bus_range.lo; /* primary bus number of this bus node */

	ndi_devi_alloc_sleep(new_device, DEVI_PSEUDO_NEXNAME,
	    (dnode_t)DEVI_SID_NODEID, &new_ntbridgechild);

	if (pcicfg_add_config_reg(new_ntbridgechild, bus, devno, 0)
				!= DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN,
		"Unconfigure: Failed to add conf reg prop for ntbridge "
			"child.\n");
		(void) ndi_devi_free(new_ntbridgechild);
		return (PCICFG_FAILURE);
	}

	if (pci_config_setup(new_ntbridgechild, &config_handle)
							!= DDI_SUCCESS) {
		cmn_err(CE_WARN,
			"pcicfg: Cannot map ntbridge child %x\n", devno);
		(void) ndi_devi_free(new_ntbridgechild);
		return (PCICFG_FAILURE);
	}

	/*
	 * See if there is any PCI HW at this location
	 * by reading the Vendor ID.  If it returns with 0xffff
	 * then there is no hardware at this location.
	 */
	vid = pci_config_get16(config_handle, PCI_CONF_VENID);

	pci_config_teardown(&config_handle);
	(void) ndi_devi_free(new_ntbridgechild);
	if (vid	== 0xffff)
		return (PCICFG_NODEVICE);

	return (pcicfg_unconfigure(new_device, devno));
}

static uint_t
pcicfg_ntbridge_unconfigure(dev_info_t *dip)
{
	pcicfg_phdl_t *entry = pcicfg_find_phdl(dip);
	uint_t			*bus;
	int			k, rc = DDI_FAILURE;

	if (ddi_getlongprop(DDI_DEV_T_ANY, dip,
			DDI_PROP_DONTPASS, "bus-range", (caddr_t)&bus,
			&k) != DDI_PROP_SUCCESS) {
		DEBUG0("ntbridge: Failed to read bus-range property\n");
		return (rc);
	}

	DEBUG2("ntbridge: Need to free bus [%d] range [%d]\n",
		bus[0], bus[1] - bus[0] + 1);

	if (ndi_ra_free(ddi_get_parent(dip),
		(uint64_t)bus[0], (uint64_t)(bus[1] - bus[0] + 1),
		NDI_RA_TYPE_PCI_BUSNUM, NDI_RA_PASS) != NDI_SUCCESS) {
		DEBUG0("ntbridge: Failed to free a bus number\n");
		kmem_free(bus, k);
		return (rc);
	}

	/*
	 * Since our resources will be freed at the parent level,
	 * just reset these values.
	 */
	entry->memory_len = 0;
	entry->io_len = 0;

	kmem_free(bus, k);

	/* the following will also free hole data. */
	return (pcicfg_destroy_phdl(dip));

}

static int
pcicfg_is_ntbridge(dev_info_t *dip)
{
	ddi_acc_handle_t	config_handle;
	uint8_t		class, subclass;
	int		rc = DDI_SUCCESS;

	if (pci_config_setup(dip, &config_handle) != DDI_SUCCESS) {
		cmn_err(CE_WARN,
			"pcicfg: cannot map config space, to get map type\n");
		return (DDI_FAILURE);
	}
	class = pci_config_get8(config_handle, PCI_CONF_BASCLASS);
	subclass = pci_config_get8(config_handle, PCI_CONF_SUBCLASS);

	/* check for class=6, subclass=9, for non transparent bridges.  */
	if ((class != PCI_CLASS_BRIDGE) || (subclass != PCI_BRIDGE_STBRIDGE))
		rc = DDI_FAILURE;

	DEBUG3("pcicfg: checking device %x,%x for indirect map. rc=%d\n",
			pci_config_get16(config_handle, PCI_CONF_VENID),
			pci_config_get16(config_handle, PCI_CONF_DEVID),
			rc);
	pci_config_teardown(&config_handle);
	return (rc);
}

static uint_t
pcicfg_ntbridge_child(dev_info_t *dip)
{
	int 		len, val, rc = DDI_FAILURE;
	dev_info_t	*anode = dip;

	/*
	 * Find the attachment point node
	 */
	while ((anode != NULL) && (strcmp(ddi_binding_name(anode),
		"hp_attachment") != 0)) {
		anode = ddi_get_parent(anode);
	}

	if (anode == NULL) {
		DEBUG0("ntbridge child tree not in PROBE state\n");
		return (rc);
	}
	len = sizeof (int);
	if (ddi_getlongprop_buf(DDI_DEV_T_NONE, ddi_get_parent(anode),
		DDI_PROP_DONTPASS, PCICFG_DEV_CONF_MAP_PROP, (caddr_t)&val,
			&len) != DDI_SUCCESS) {

		DEBUG1("ntbridge child: no \"%s\" property\n",
					PCICFG_DEV_CONF_MAP_PROP);
		return (rc);
	}
	DEBUG0("ntbridge child: success\n");
	return (DDI_SUCCESS);
}

/*
 * this function is called only for SPARC platforms, where we may have
 * a mix n' match of direct vs indirectly mapped configuration space.
 * On x86, this function does not get called. We always return TRUE
 * via a macro for x86.
 */
/*ARGSUSED*/
static int
pcicfg_indirect_map(dev_info_t *dip)
{
#if defined(__sparc)
	int rc = DDI_FAILURE;

	if (ddi_getprop(DDI_DEV_T_ANY, ddi_get_parent(dip), DDI_PROP_DONTPASS,
			PCICFG_DEV_CONF_MAP_PROP, DDI_FAILURE) != DDI_FAILURE)
		rc = DDI_SUCCESS;
	else
		if (ddi_getprop(DDI_DEV_T_ANY, ddi_get_parent(dip),
		    DDI_PROP_DONTPASS, PCICFG_BUS_CONF_MAP_PROP,
		    DDI_FAILURE) != DDI_FAILURE)
			rc = DDI_SUCCESS;

	return (rc);
#else
	return (DDI_SUCCESS);
#endif
}

static uint_t
pcicfg_get_ntbridge_child_range(dev_info_t *dip, uint64_t *boundbase,
				uint64_t *boundlen, uint_t space_type)
{
	int		length, found = DDI_FAILURE, acount, i, ibridge;
	pci_regspec_t	*assigned;

	if ((ibridge = pcicfg_is_ntbridge(dip)) == DDI_FAILURE)
		return (found);

	if (ddi_getlongprop(DDI_DEV_T_ANY, dip,
		DDI_PROP_DONTPASS, "assigned-addresses", (caddr_t)&assigned,
			&length) != DDI_PROP_SUCCESS) {
		DEBUG1("Failed to get assigned-addresses property %llx\n", dip);
		return (found);
	}
	DEBUG1("pcicfg: ntbridge child range: dip = %s\n",
					ddi_driver_name(dip));

	acount = length / sizeof (pci_regspec_t);

	for (i = 0; i < acount; i++) {
		if ((PCI_REG_REG_G(assigned[i].pci_phys_hi)
		== pcicfg_indirect_map_devs[ibridge].mem_range_bar_offset) &&
				(space_type == PCI_BASE_SPACE_MEM)) {
			found = DDI_SUCCESS;
			break;
		} else {
			if ((PCI_REG_REG_G(assigned[i].pci_phys_hi)
		== pcicfg_indirect_map_devs[ibridge].io_range_bar_offset) &&
					(space_type == PCI_BASE_SPACE_IO)) {
				found = DDI_SUCCESS;
				break;
			}
		}
	}
	DEBUG3("pcicfg: ntbridge child range: space=%x, base=%lx, len=%lx\n",
		space_type, assigned[i].pci_phys_low, assigned[i].pci_size_low);

	if (found == DDI_SUCCESS)  {
		*boundbase = assigned[i].pci_phys_low;
		*boundlen = assigned[i].pci_size_low;
	}

	kmem_free(assigned, length);
	return (found);
}

/*
 * This will turn  resources allocated by pcicfg_configure()
 * and remove the device tree from the attachment point
 * and below.  The routine assumes the devices have their
 * drivers detached.
 */
int
pcicfg_unconfigure(dev_info_t *devi, uint_t device)
{
	dev_info_t *child_dip;
	int func;
	int i;

	/*
	 * Cycle through devices to make sure none are busy.
	 * If a single device is busy fail the whole unconfigure.
	 */
	for (func = 0; func < PCICFG_MAX_FUNCTION; func++) {
		if ((child_dip = pcicfg_devi_find(devi, device, func)) == NULL)
			break;

		if (ndi_devi_offline(child_dip, NDI_UNCONFIG) == NDI_SUCCESS)
				continue;
		/*
		 * Device function is busy. Before returning we have to
		 * put all functions back online which were taken
		 * offline during the process.
		 */
		DEBUG2("Device [0x%x] function [%x] is busy\n", device, func);
		for (i = 0; i < func; i++) {
		    if ((child_dip = pcicfg_devi_find(devi, device, i))
			== NULL) {
			DEBUG0("No more devices to put back on line!!\n");
			/*
			 * Made it through all functions
			 */
			break;
		    }
		    if (ndi_devi_online(child_dip, NDI_CONFIG) != NDI_SUCCESS) {
			DEBUG0("Failed to put back devices state\n");
			return (PCICFG_FAILURE);
		    }
		}
		return (PCICFG_FAILURE);
	}

	/*
	 * Now, tear down all devinfo nodes for this AP.
	 */
	for (func = 0; func < PCICFG_MAX_FUNCTION; func++) {
		if ((child_dip = pcicfg_devi_find(devi,
			device, func)) == NULL) {
			DEBUG0("No more devices to tear down!\n");
			break;
		}

		DEBUG2("Tearing down device [0x%x] function [0x%x]\n",
			device, func);

		if (pcicfg_is_ntbridge(child_dip) != DDI_FAILURE)
			if (pcicfg_ntbridge_unconfigure(child_dip) !=
					PCICFG_SUCCESS) {
				cmn_err(CE_WARN,
					"ntbridge: unconfigure failed\n");
				return (PCICFG_FAILURE);
			}

		if (pcicfg_teardown_device(child_dip) != PCICFG_SUCCESS) {
			DEBUG2("Failed to tear down device [0x%x]"
			"function [0x%x]\n",
				device, func);
			return (PCICFG_FAILURE);
		}
	}
	return (PCICFG_SUCCESS);
}

static int
pcicfg_teardown_device(dev_info_t *dip)
{
	/*
	 * Free up resources associated with 'dip'
	 */

	if (pcicfg_free_resources(dip) != PCICFG_SUCCESS) {
		DEBUG0("Failed to free resources\n");
		return (PCICFG_FAILURE);
	}

	/*
	 * The framework provides this routine which can
	 * tear down a sub-tree.
	 */
	if (ndi_devi_offline(dip, NDI_DEVI_REMOVE) != NDI_SUCCESS) {
		DEBUG0("Failed to offline and remove node\n");
		return (PCICFG_FAILURE);
	}

	return (PCICFG_SUCCESS);
}

/*
 * BEGIN GENERIC SUPPORT ROUTINES
 */
static pcicfg_phdl_t *
pcicfg_find_phdl(dev_info_t *dip)
{
	pcicfg_phdl_t *entry;
	mutex_enter(&pcicfg_list_mutex);
	for (entry = pcicfg_phdl_list; entry != NULL; entry = entry->next) {
		if (entry->dip == dip) {
			mutex_exit(&pcicfg_list_mutex);
			return (entry);
		}
	}
	mutex_exit(&pcicfg_list_mutex);

	/*
	 * Did'nt find entry - create one
	 */
	return (pcicfg_create_phdl(dip));
}

static pcicfg_phdl_t *
pcicfg_create_phdl(dev_info_t *dip)
{
	pcicfg_phdl_t *new;

	new = (pcicfg_phdl_t *)kmem_zalloc(sizeof (pcicfg_phdl_t),
		KM_SLEEP);

	new->dip = dip;
	mutex_enter(&pcicfg_list_mutex);
	new->next = pcicfg_phdl_list;
	pcicfg_phdl_list = new;
	mutex_exit(&pcicfg_list_mutex);

	return (new);
}

static int
pcicfg_destroy_phdl(dev_info_t *dip)
{
	pcicfg_phdl_t *entry;
	pcicfg_phdl_t *follow = NULL;

	mutex_enter(&pcicfg_list_mutex);
	for (entry = pcicfg_phdl_list; entry != NULL; follow = entry,
		entry = entry->next) {
		if (entry->dip == dip) {
			if (entry == pcicfg_phdl_list) {
				pcicfg_phdl_list = entry->next;
			} else {
				follow->next = entry->next;
			}
			/*
			 * If this entry has any allocated memory
			 * or IO space associated with it, that
			 * must be freed up.
			 */
			if (entry->memory_len > 0) {
				(void) ndi_ra_free(ddi_get_parent(dip),
					entry->memory_base,
					entry->memory_len,
					NDI_RA_TYPE_MEM, NDI_RA_PASS);
			}
			pcicfg_free_hole(&entry->mem_hole);

			if (entry->io_len > 0) {
				(void) ndi_ra_free(ddi_get_parent(dip),
					entry->io_base,
					entry->io_len,
					NDI_RA_TYPE_IO, NDI_RA_PASS);
			}
			pcicfg_free_hole(&entry->io_hole);

			/*
			 * Destroy this entry
			 */
			kmem_free((caddr_t)entry, sizeof (pcicfg_phdl_t));
			mutex_exit(&pcicfg_list_mutex);
			return (PCICFG_SUCCESS);
		}
	}
	mutex_exit(&pcicfg_list_mutex);
	/*
	 * Did'nt find the entry
	 */
	return (PCICFG_FAILURE);
}

static int
pcicfg_program_ap(dev_info_t *dip)
{
	pcicfg_phdl_t *phdl;
	uint8_t header_type;
	ddi_acc_handle_t handle;
	pcicfg_phdl_t *entry;

	if (pcicfg_config_setup(dip, &handle) != DDI_SUCCESS) {
		DEBUG0("Failed to map config space!\n");
		return (PCICFG_FAILURE);

	}

	header_type = pci_config_get8(handle, PCI_CONF_HEADER);

	(void) pcicfg_config_teardown(&handle);

	if ((header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_PPB) {

		if (pcicfg_allocate_chunk(dip) != PCICFG_SUCCESS) {
			DEBUG0("Not enough memory to hotplug\n");
			(void) pcicfg_destroy_phdl(dip);
			return (PCICFG_FAILURE);
		}

		phdl = pcicfg_find_phdl(dip);
		ASSERT(phdl);

		(void) pcicfg_bridge_assign(dip, (void *)phdl);

		if (phdl->error != PCICFG_SUCCESS) {
			DEBUG0("Problem assigning bridge\n");
			(void) pcicfg_destroy_phdl(dip);
			return (phdl->error);
		}

		/*
		 * Successfully allocated and assigned
		 * memory.  Set the memory and IO length
		 * to zero so when the handle is freed up
		 * it will not de-allocate assigned resources.
		 */
		entry = (pcicfg_phdl_t *)phdl;

		entry->memory_len = entry->io_len = 0;

		/*
		 * Free up the "entry" structure.
		 */
		(void) pcicfg_destroy_phdl(dip);

	} else {
		if (pcicfg_device_assign(dip) != PCICFG_SUCCESS) {
			return (PCICFG_FAILURE);
		}
	}
	return (PCICFG_SUCCESS);
}

static int
pcicfg_bridge_assign(dev_info_t *dip, void *hdl)
{
	ddi_acc_handle_t handle;
	pci_regspec_t *reg;
	int length;
	int rcount;
	int i;
	int offset;
	uint64_t mem_answer;
	uint32_t io_answer;
	int count;
	uint8_t header_type;
	pcicfg_range_t range[PCICFG_RANGE_LEN];
	int bus_range[2];
	uint64_t mem_residual;
	uint64_t io_residual;

	pcicfg_phdl_t *entry = (pcicfg_phdl_t *)hdl;

	DEBUG1("bridge assign: assigning addresses to %s\n",
					ddi_get_name(dip));

	entry->error = PCICFG_SUCCESS;

	if (entry == NULL) {
		DEBUG0("Failed to get entry\n");
		entry->error = PCICFG_FAILURE;
		return (DDI_WALK_TERMINATE);
	}

	if (pcicfg_config_setup(dip, &handle)
					!= DDI_SUCCESS) {
		DEBUG0("Failed to map config space!\n");
		entry->error = PCICFG_FAILURE;
		return (DDI_WALK_TERMINATE);
	}

	header_type = pci_config_get8(handle, PCI_CONF_HEADER);

	if ((header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_PPB) {

		bzero((caddr_t)range,
			sizeof (pcicfg_range_t) * PCICFG_RANGE_LEN);

		(void) pcicfg_setup_bridge(entry, handle);

		range[0].child_hi = range[0].parent_hi |=
			(PCI_REG_REL_M | PCI_ADDR_IO);
		range[0].child_lo = range[0].parent_lo =
			entry->io_last;
		range[1].child_hi = range[1].parent_hi |=
			(PCI_REG_REL_M | PCI_ADDR_MEM32);
		range[1].child_lo = range[1].parent_lo =
			entry->memory_last;

		ndi_devi_enter(dip, &count);
		ddi_walk_devs(ddi_get_child(dip),
			pcicfg_bridge_assign, (void *)entry);
		ndi_devi_exit(dip, count);

		(void) pcicfg_update_bridge(entry, handle);

		bus_range[0] = pci_config_get8(handle, PCI_BCNF_SECBUS);
		bus_range[1] = pci_config_get8(handle, PCI_BCNF_SUBBUS);

		if (ndi_prop_update_int_array(DDI_DEV_T_NONE, dip,
				"bus-range", bus_range, 2) != DDI_SUCCESS) {
			DEBUG0("Failed to set bus-range property");
			entry->error = PCICFG_FAILURE;
			return (DDI_WALK_TERMINATE);
		}

		/*
		 * Put back memory and I/O space not allocated
		 * under the bridge.
		 */
		mem_residual = entry->memory_len -
			(entry->memory_last - entry->memory_base);
		if (mem_residual > 0) {
			(void) ndi_ra_free(ddi_get_parent(dip),
				entry->memory_last,
				mem_residual,
				NDI_RA_TYPE_MEM, NDI_RA_PASS);
		}

		io_residual = entry->io_len -
			(entry->io_last - entry->io_base);
		if (io_residual > 0) {
			(void) ndi_ra_free(ddi_get_parent(dip),
				entry->io_last,
				io_residual,
				NDI_RA_TYPE_IO, NDI_RA_PASS);
		}

		if (entry->io_len > 0) {
			range[0].size_lo = entry->io_last - entry->io_base;
			if (pcicfg_update_ranges_prop(dip, &range[0])) {
				DEBUG0("Failed to update ranges (i/o)\n");
				entry->error = PCICFG_FAILURE;
				return (DDI_WALK_TERMINATE);
			}
		}
		if (entry->memory_len > 0) {
			range[1].size_lo =
				entry->memory_last - entry->memory_base;
			if (pcicfg_update_ranges_prop(dip, &range[1])) {
				DEBUG0("Failed to update ranges (memory)\n");
				entry->error = PCICFG_FAILURE;
				return (DDI_WALK_TERMINATE);
			}
		}

		(void) pcicfg_device_on(handle);

		PCICFG_DUMP_BRIDGE_CONFIG(handle);

		return (DDI_WALK_PRUNECHILD);
	}

	/*
	 * If there is an interrupt pin set program
	 * interrupt line with default values.
	 */
	if (pci_config_get8(handle, PCI_CONF_IPIN)) {
		pci_config_put8(handle, PCI_CONF_ILINE, 0xf);
	}

	/*
	 * A single device (under a bridge).
	 * For each "reg" property with a length, allocate memory
	 * and program the base registers.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, dip,
		DDI_PROP_DONTPASS, "reg", (caddr_t)&reg,
		&length) != DDI_PROP_SUCCESS) {
		DEBUG0("Failed to read reg property\n");
		entry->error = PCICFG_FAILURE;
		return (DDI_WALK_TERMINATE);
	}

	rcount = length / sizeof (pci_regspec_t);
	offset = PCI_CONF_BASE0;
	for (i = 0; i < rcount; i++) {
		if ((reg[i].pci_size_low != 0)||
			(reg[i].pci_size_hi != 0)) {

			offset = PCI_REG_REG_G(reg[i].pci_phys_hi);

			switch (PCI_REG_ADDR_G(reg[i].pci_phys_hi)) {
			case PCI_REG_ADDR_G(PCI_ADDR_MEM64):

				(void) pcicfg_get_mem(entry,
				reg[i].pci_size_low, &mem_answer);
				pci_config_put64(handle, offset, mem_answer);
				DEBUG2("REGISTER off %x (64)LO ----> [0x%x]\n",
					offset,
					pci_config_get32(handle, offset));
				DEBUG2("REGISTER off %x (64)HI ----> [0x%x]\n",
					offset + 4,
					pci_config_get32(handle, offset + 4));

				reg[i].pci_phys_low = PCICFG_HIADDR(mem_answer);
				reg[i].pci_phys_mid  =
					PCICFG_LOADDR(mem_answer);

				break;

			case PCI_REG_ADDR_G(PCI_ADDR_MEM32):
				/* allocate memory space from the allocator */

				(void) pcicfg_get_mem(entry,
					reg[i].pci_size_low, &mem_answer);
				pci_config_put32(handle,
					offset, (uint32_t)mem_answer);

				DEBUG2("REGISTER off %x(32)LO ----> [0x%x]\n",
					offset,
					pci_config_get32(handle, offset));

				reg[i].pci_phys_low = (uint32_t)mem_answer;

				break;
			case PCI_REG_ADDR_G(PCI_ADDR_IO):
				/* allocate I/O space from the allocator */

				(void) pcicfg_get_io(entry,
					reg[i].pci_size_low, &io_answer);
				pci_config_put32(handle, offset, io_answer);

				DEBUG2("REGISTER off %x (I/O)LO ----> [0x%x]\n",
					offset,
					pci_config_get32(handle, offset));

				reg[i].pci_phys_low = io_answer;

				break;
			default:
				DEBUG0("Unknown register type\n");
				kmem_free(reg, length);
				(void) pcicfg_config_teardown(&handle);
				entry->error = PCICFG_FAILURE;
				return (DDI_WALK_TERMINATE);
			} /* switch */

			/*
			 * Now that memory locations are assigned,
			 * update the assigned address property.
			 */
			if (pcicfg_update_assigned_prop(dip,
				&reg[i]) != PCICFG_SUCCESS) {
				kmem_free(reg, length);
				(void) pcicfg_config_teardown(&handle);
				entry->error = PCICFG_FAILURE;
				return (DDI_WALK_TERMINATE);
			}
		}
	}
	(void) pcicfg_device_on(handle);

	PCICFG_DUMP_DEVICE_CONFIG(handle);

	(void) pcicfg_config_teardown(&handle);
	kmem_free((caddr_t)reg, length);
	return (DDI_WALK_CONTINUE);
}

static int
pcicfg_device_assign(dev_info_t *dip)
{
	ddi_acc_handle_t	handle;
	pci_regspec_t		*reg;
	int			length;
	int			rcount;
	int			i;
	int			offset;
	ndi_ra_request_t	request;
	uint64_t		answer;
	uint64_t		alen;


	DEBUG1("%llx now under configuration\n", dip);

	/* request.ra_len = PCICFG_ROUND_UP(request.ra_len, PCICFG_IOGRAN); */
	if (pcicfg_ntbridge_child(dip) == DDI_SUCCESS) {

		return (pcicfg_ntbridge_program_child(dip));
	}
	/*
	 * XXX Failure here should be noted
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, dip,
		DDI_PROP_DONTPASS, "reg", (caddr_t)&reg,
		&length) != DDI_PROP_SUCCESS) {
		DEBUG0("Failed to read reg property\n");
		return (PCICFG_FAILURE);
	}

	if (pcicfg_config_setup(dip, &handle) != DDI_SUCCESS) {
		DEBUG0("Failed to map config space!\n");
		return (PCICFG_FAILURE);
	}

	/*
	 * A single device
	 *
	 * For each "reg" property with a length, allocate memory
	 * and program the base registers.
	 */

	/*
	 * If there is an interrupt pin set program
	 * interrupt line with default values.
	 */
	if (pci_config_get8(handle, PCI_CONF_IPIN)) {
		pci_config_put8(handle, PCI_CONF_ILINE, 0xf);
	}

	bzero((caddr_t)&request, sizeof (ndi_ra_request_t));

	request.ra_flags |= NDI_RA_ALIGN_SIZE;
	request.ra_boundbase = 0;
	request.ra_boundlen = PCICFG_4GIG_LIMIT;

	rcount = length / sizeof (pci_regspec_t);
	offset = PCI_CONF_BASE0;
	for (i = 0; i < rcount; i++) {
		if ((reg[i].pci_size_low != 0)||
			(reg[i].pci_size_hi != 0)) {

			offset = PCI_REG_REG_G(reg[i].pci_phys_hi);
			request.ra_len = reg[i].pci_size_low;

			switch (PCI_REG_ADDR_G(reg[i].pci_phys_hi)) {
			case PCI_REG_ADDR_G(PCI_ADDR_MEM64):
				request.ra_flags ^= NDI_RA_ALLOC_BOUNDED;
				/* allocate memory space from the allocator */
				if (ndi_ra_alloc(ddi_get_parent(dip),
					&request, &answer, &alen,
					NDI_RA_TYPE_MEM, NDI_RA_PASS)
							!= NDI_SUCCESS) {
					DEBUG0("Failed to allocate 64b mem\n");
					kmem_free(reg, length);
					(void) pcicfg_config_teardown(&handle);
					return (PCICFG_FAILURE);
				}
				DEBUG3("64 addr = [0x%x.%x] len [0x%x]\n",
					PCICFG_HIADDR(answer),
					PCICFG_LOADDR(answer),
					alen);
				/* program the low word */
				pci_config_put32(handle,
					offset, PCICFG_LOADDR(answer));

				/* program the high word with value zero */
				pci_config_put32(handle, offset + 4,
					PCICFG_HIADDR(answer));

				reg[i].pci_phys_low = PCICFG_LOADDR(answer);
				reg[i].pci_phys_mid = PCICFG_HIADDR(answer);

				offset += 8;
				break;

			case PCI_REG_ADDR_G(PCI_ADDR_MEM32):
				request.ra_flags |= NDI_RA_ALLOC_BOUNDED;
				/* allocate memory space from the allocator */
				if (ndi_ra_alloc(ddi_get_parent(dip),
					&request, &answer, &alen,
					NDI_RA_TYPE_MEM, NDI_RA_PASS)
							!= NDI_SUCCESS) {
					DEBUG0("Failed to allocate 32b mem\n");
					kmem_free(reg, length);
					(void) pcicfg_config_teardown(&handle);
					return (PCICFG_FAILURE);
				}
				DEBUG3("32 addr = [0x%x.%x] len [0x%x]\n",
					PCICFG_HIADDR(answer),
					PCICFG_LOADDR(answer),
					alen);
				/* program the low word */
				pci_config_put32(handle,
					offset, PCICFG_LOADDR(answer));

				reg[i].pci_phys_low = PCICFG_LOADDR(answer);

				offset += 4;
				break;
			case PCI_REG_ADDR_G(PCI_ADDR_IO):
				/* allocate I/O space from the allocator */
				request.ra_flags |= NDI_RA_ALLOC_BOUNDED;
				if (ndi_ra_alloc(ddi_get_parent(dip),
					&request, &answer, &alen,
					NDI_RA_TYPE_IO, NDI_RA_PASS)
							!= NDI_SUCCESS) {
					DEBUG0("Failed to allocate I/O\n");
					kmem_free(reg, length);
					(void) pcicfg_config_teardown(&handle);
					return (PCICFG_FAILURE);
				}
				DEBUG3("I/O addr = [0x%x.%x] len [0x%x]\n",
					PCICFG_HIADDR(answer),
					PCICFG_LOADDR(answer),
					alen);
				pci_config_put32(handle,
					offset, PCICFG_LOADDR(answer));

				reg[i].pci_phys_low = PCICFG_LOADDR(answer);

				offset += 4;
				break;
			default:
				DEBUG0("Unknown register type\n");
				kmem_free(reg, length);
				(void) pcicfg_config_teardown(&handle);
				return (PCICFG_FAILURE);
			} /* switch */

			/*
			 * Now that memory locations are assigned,
			 * update the assigned address property.
			 */

			if (pcicfg_update_assigned_prop(dip,
				&reg[i]) != PCICFG_SUCCESS) {
				kmem_free(reg, length);
				(void) pcicfg_config_teardown(&handle);
				return (PCICFG_FAILURE);
			}
		}
	}

	(void) pcicfg_device_on(handle);
	kmem_free(reg, length);

	PCICFG_DUMP_DEVICE_CONFIG(handle);

	(void) pcicfg_config_teardown(&handle);
	return (PCICFG_SUCCESS);
}

/*
 * The "dip" passed to this routine is assumed to be
 * the device at the attachment point. Currently it is
 * assumed to be a bridge.
 */
static int
pcicfg_allocate_chunk(dev_info_t *dip)
{
	pcicfg_phdl_t		*phdl;
	ndi_ra_request_t	*mem_request;
	ndi_ra_request_t	*io_request;
	uint64_t		mem_answer;
	uint64_t		io_answer;
	uint64_t		alen;
	dev_info_t		*parent;
	int			circular;

	/*
	 * This should not find an existing entry - so
	 * it will create a new one.
	 */
	phdl = pcicfg_find_phdl(dip);
	ASSERT(phdl);

	mem_request = &phdl->mem_req;
	io_request  = &phdl->io_req;

	/*
	 * From this point in the tree - walk the devices,
	 * The function passed in will read and "sum" up
	 * the memory and I/O requirements and put them in
	 * structure "phdl".
	 */
	if ((parent = ddi_get_parent(dip)) != NULL)
		ndi_devi_enter(parent, &circular);
	ddi_walk_devs(dip, pcicfg_sum_resources, (void *)phdl);
	if (parent)
		ndi_devi_exit(parent, circular);

	if (phdl->error != PCICFG_SUCCESS) {
		DEBUG0("Failure summing resources\n");
		return (phdl->error);
	}

	/*
	 * Call into the memory allocator with the request.
	 * Record the addresses returned in the phdl
	 */
	DEBUG1("AP requires [0x%x] bytes of memory space\n",
		mem_request->ra_len);
	DEBUG1("AP requires [0x%x] bytes of I/O    space\n",
		io_request->ra_len);

	mem_request->ra_align_mask =
		PCICFG_MEMGRAN - 1; /* 1M alignment on memory space */
	io_request->ra_align_mask =
		PCICFG_IOGRAN - 1;   /* 4K alignment on I/O space */
	io_request->ra_boundbase = 0;
	io_request->ra_boundlen = PCICFG_4GIG_LIMIT;
	io_request->ra_flags |= NDI_RA_ALLOC_BOUNDED;

	mem_request->ra_len =
		PCICFG_ROUND_UP(mem_request->ra_len, PCICFG_MEMGRAN);

	io_request->ra_len =
		PCICFG_ROUND_UP(io_request->ra_len, PCICFG_IOGRAN);

	/*
	 * Check if the Bridge is a child of
	 * ntbridge, If yes, then allocate IO space from the hole allocated
	 * to the bridge. ndi_ra_alloc should not be called in such
	 * cases.
	 */
	if (pcicfg_ntbridge_child(dip) == DDI_SUCCESS) {
		pcicfg_phdl_t		*pphdl;

		pphdl = pcicfg_find_phdl(ddi_get_parent(dip));
		ASSERT(phdl);
		mem_answer = pcicfg_alloc_hole(&pphdl->mem_hole,
				&pphdl->memory_last, mem_request->ra_len);
		if (mem_answer == 0) {
			DEBUG0("Failed to allocate Memory hole\n");
			return (PCICFG_FAILURE);
		}
		alen = mem_request->ra_len;
	} else
		if (ndi_ra_alloc(ddi_get_parent(dip),
			mem_request, &mem_answer, &alen,
				NDI_RA_TYPE_MEM, NDI_RA_PASS) != NDI_SUCCESS) {
			DEBUG0("Failed to allocate memory\n");
			return (PCICFG_FAILURE);
		}

	phdl->memory_base = phdl->memory_last = mem_answer;
	phdl->memory_len  = alen;

	phdl->mem_hole.start = phdl->memory_base;
	phdl->mem_hole.len = phdl->memory_len;
	phdl->mem_hole.next = (hole_t *)NULL;

	/*
	 * Check if the Bridge is a child of
	 * ntbridge, If yes, then allocate IO space from the hole allocated
	 * to the bridge. ndi_ra_alloc should not be called in such
	 * cases.
	 */
	if (pcicfg_ntbridge_child(dip) == DDI_SUCCESS) {
		pcicfg_phdl_t		*pphdl;
		uint64_t		io_last;

		pphdl = pcicfg_find_phdl(ddi_get_parent(dip));
		ASSERT(phdl);
		io_last = pphdl->io_last;
		io_answer = pcicfg_alloc_hole(&pphdl->io_hole,
				&io_last, io_request->ra_len);
		if (io_answer == 0) {
			DEBUG0("Failed to allocate IO hole\n");
			return (PCICFG_FAILURE);
		}
		pphdl->io_last = io_last;
		alen = io_request->ra_len;
	} else
		if (ndi_ra_alloc(ddi_get_parent(dip), io_request, &io_answer,
			&alen, NDI_RA_TYPE_IO, NDI_RA_PASS) != NDI_SUCCESS) {

			DEBUG0("Failed to allocate I/O space\n");
			(void) ndi_ra_free(ddi_get_parent(dip), mem_answer,
				alen, NDI_RA_TYPE_MEM, NDI_RA_PASS);
			phdl->memory_len = phdl->io_len = 0;
			return (PCICFG_FAILURE);
		}

	phdl->io_base = phdl->io_last = (uint32_t)io_answer;
	phdl->io_len  = (uint32_t)alen;

	phdl->io_hole.start = phdl->io_base;
	phdl->io_hole.len = phdl->io_len;
	phdl->io_hole.next = (hole_t *)NULL;

	DEBUG2("MEMORY BASE = [0x%x] length [0x%x]\n",
		phdl->memory_base, phdl->memory_len);
	DEBUG2("IO     BASE = [0x%x] length [0x%x]\n",
		phdl->io_base, phdl->io_len);

	return (PCICFG_SUCCESS);
}

#ifdef	DEBUG
/*
 * This function is useful in debug mode, where we can measure how
 * much memory was wasted/unallocated in bridge device's domain.
 */
static uint64_t
pcicfg_unused_space(hole_t *hole, uint32_t *hole_count)
{
	uint64_t len = 0;
	uint32_t count = 0;

	do {
		len += hole->len;
		hole = hole->next;
		count++;
	} while (hole);
	*hole_count = count;
	return (len);
}
#endif

/*
 * This function frees data structures that hold the hole information
 * which are allocated in pcicfg_alloc_hole(). This is not freeing
 * any memory allocated through NDI calls.
 */
static void
pcicfg_free_hole(hole_t *addr_hole)
{
	hole_t *nhole, *hole = addr_hole->next;

	while (hole) {
		nhole = hole->next;
		kmem_free(hole, sizeof (hole_t));
		hole = nhole;
	}
}

static uint64_t
pcicfg_alloc_hole(hole_t *addr_hole, uint64_t *alast, uint32_t length)
{
	uint64_t actual_hole_start, ostart, olen;
	hole_t	*hole = addr_hole, *thole, *nhole;

	do {
		actual_hole_start = PCICFG_ROUND_UP(hole->start, length);
		if (((actual_hole_start - hole->start) + length) <= hole->len) {
			DEBUG3("hole found. start %llx, len %llx, req=%x\n",
				hole->start, hole->len, length);
			ostart = hole->start;
			olen = hole->len;
			/* current hole parameters adjust */
			if ((actual_hole_start - hole->start) == 0) {
				hole->start += length;
				hole->len -= length;
				if (hole->start > *alast)
					*alast = hole->start;
			} else {
				hole->len = actual_hole_start - hole->start;
				nhole = (hole_t *)kmem_zalloc(sizeof (hole_t),
								KM_SLEEP);
				nhole->start = actual_hole_start + length;
				nhole->len = (ostart + olen) - nhole->start;
				nhole->next = NULL;
				thole = hole->next;
				hole->next = nhole;
				nhole->next = thole;
				if (nhole->start > *alast)
					*alast = nhole->start;
				DEBUG2("put new hole to %llx, %llx\n",
					nhole->start, nhole->len);
			}
			DEBUG2("adjust current hole to %llx, %llx\n",
					hole->start, hole->len);
			break;
		}
		actual_hole_start = 0;
		hole = hole->next;
	} while (hole);

	DEBUG1("return hole at %llx\n", actual_hole_start);
	return (actual_hole_start);
}

static void
pcicfg_get_mem(pcicfg_phdl_t *entry,
	uint32_t length, uint64_t *ans)
{
	uint64_t new_mem;

	/* See if there is a hole, that can hold this request. */
	new_mem = pcicfg_alloc_hole(&entry->mem_hole, &entry->memory_last,
								length);
	if (new_mem) {	/* if non-zero, found a hole. */
		if (ans != NULL)
			*ans = new_mem;
	} else
		cmn_err(CE_WARN, "No %u bytes memory window for %s\n",
					length, ddi_get_name(entry->dip));
}

static void
pcicfg_get_io(pcicfg_phdl_t *entry,
	uint32_t length, uint32_t *ans)
{
	uint32_t new_io;
	uint64_t io_last;

	/*
	 * See if there is a hole, that can hold this request.
	 * Pass 64 bit parameters and then truncate to 32 bit.
	 */
	io_last = entry->io_last;
	new_io = (uint32_t)pcicfg_alloc_hole(&entry->io_hole, &io_last, length);
	if (new_io) {	/* if non-zero, found a hole. */
		entry->io_last = (uint32_t)io_last;
		if (ans != NULL)
			*ans = new_io;
	} else
		cmn_err(CE_WARN, "No %u bytes IO space window for %s\n",
					length, ddi_get_name(entry->dip));
}

static int
pcicfg_sum_resources(dev_info_t *dip, void *hdl)
{
	pcicfg_phdl_t *entry = (pcicfg_phdl_t *)hdl;
	pci_regspec_t *pci_rp;
	int length;
	int rcount;
	int i;
	ndi_ra_request_t *mem_request;
	ndi_ra_request_t *io_request;
	uint8_t header_type;
	ddi_acc_handle_t handle;

	entry->error = PCICFG_SUCCESS;

	mem_request = &entry->mem_req;
	io_request =  &entry->io_req;

	if (pcicfg_config_setup(dip, &handle) != DDI_SUCCESS) {
		DEBUG0("Failed to map config space!\n");
		entry->error = PCICFG_FAILURE;
		return (DDI_WALK_TERMINATE);
	}

	header_type = pci_config_get8(handle, PCI_CONF_HEADER);

	/*
	 * If its a bridge - just record the highest bus seen
	 */
	if ((header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_PPB) {

		if (entry->highest_bus < pci_config_get8(handle,
			PCI_BCNF_SECBUS)) {
			entry->highest_bus =
				pci_config_get8(handle, PCI_BCNF_SECBUS);
		}

		(void) pcicfg_config_teardown(&handle);
		entry->error = PCICFG_FAILURE;
		return (DDI_WALK_CONTINUE);
	} else {
		if (ddi_getlongprop(DDI_DEV_T_ANY, dip,
			DDI_PROP_DONTPASS, "reg", (caddr_t)&pci_rp,
			&length) != DDI_PROP_SUCCESS) {
			/*
			 * If one node in (the subtree of nodes)
			 * doesn't have a "reg" property fail the
			 * allocation.
			 */
			entry->memory_len = 0;
			entry->io_len = 0;
			entry->error = PCICFG_FAILURE;
			return (DDI_WALK_TERMINATE);
		}
		/*
		 * For each "reg" property with a length, add that to the
		 * total memory (or I/O) to allocate.
		 */
		rcount = length / sizeof (pci_regspec_t);

		for (i = 0; i < rcount; i++) {

			switch (PCI_REG_ADDR_G(pci_rp[i].pci_phys_hi)) {

			case PCI_REG_ADDR_G(PCI_ADDR_MEM32):
				mem_request->ra_len =
				pci_rp[i].pci_size_low +
				PCICFG_ROUND_UP(mem_request->ra_len,
				pci_rp[i].pci_size_low);
				DEBUG1("ADDING 32 --->0x%x\n",
					pci_rp[i].pci_size_low);

			break;
			case PCI_REG_ADDR_G(PCI_ADDR_MEM64):
				mem_request->ra_len =
				pci_rp[i].pci_size_low +
				PCICFG_ROUND_UP(mem_request->ra_len,
				pci_rp[i].pci_size_low);
				DEBUG1("ADDING 64 --->0x%x\n",
					pci_rp[i].pci_size_low);

			break;
			case PCI_REG_ADDR_G(PCI_ADDR_IO):
				io_request->ra_len =
				pci_rp[i].pci_size_low +
				PCICFG_ROUND_UP(io_request->ra_len,
				pci_rp[i].pci_size_low);
				DEBUG1("ADDING I/O --->0x%x\n",
					pci_rp[i].pci_size_low);
			break;
			default:
			    /* Config space register - not included */
			break;
			}
		}

		/*
		 * free the memory allocated by ddi_getlongprop
		 */
		kmem_free(pci_rp, length);

		/*
		 * continue the walk to the next sibling to sum memory
		 */

		(void) pcicfg_config_teardown(&handle);

		return (DDI_WALK_CONTINUE);
	}
}

static int
pcicfg_free_bridge_resources(dev_info_t *dip)
{
	pcicfg_range_t		*ranges;
	uint_t			*bus;
	int			k;
	int			length;
	int			i;


	if (ddi_getlongprop(DDI_DEV_T_ANY, dip,
		DDI_PROP_DONTPASS, "ranges", (caddr_t)&ranges,
		&length) != DDI_PROP_SUCCESS) {
		DEBUG0("Failed to read ranges property\n");
		return (PCICFG_FAILURE);
	}

	for (i = 0; i < length / sizeof (pcicfg_range_t); i++) {
		if (ranges[i].size_lo != 0 ||
			ranges[i].size_hi != 0) {
			switch (ranges[i].parent_hi & PCI_REG_ADDR_M) {
				case PCI_ADDR_IO:
					DEBUG2("Free I/O    "
					"base/length = [0x%x]/[0x%x]\n",
						ranges[i].child_lo,
						ranges[i].size_lo);
					if (ndi_ra_free(ddi_get_parent(dip),
						(uint64_t)ranges[i].child_lo,
						(uint64_t)ranges[i].size_lo,
						NDI_RA_TYPE_IO, NDI_RA_PASS)
						!= NDI_SUCCESS) {
						DEBUG0("Trouble freeing "
						"PCI i/o space\n");
						kmem_free(ranges, length);
						return (PCICFG_FAILURE);
					}
				break;
				case PCI_ADDR_MEM32:
				case PCI_ADDR_MEM64:
					DEBUG3("Free Memory base/length = "
					"[0x%x.%x]/[0x%x]\n",
						ranges[i].child_mid,
						ranges[i].child_lo,
						ranges[i].size_lo)
					if (ndi_ra_free(ddi_get_parent(dip),
						PCICFG_LADDR(ranges[i].child_lo,
						ranges[i].child_mid),
						(uint64_t)ranges[i].size_lo,
						NDI_RA_TYPE_MEM, NDI_RA_PASS)
						!= NDI_SUCCESS) {
						DEBUG0("Trouble freeing "
						"PCI memory space\n");
						kmem_free(ranges, length);
						return (PCICFG_FAILURE);
					}
				break;
				default:
					DEBUG0("Unknown memory space\n");
				break;
			}
		}
	}

	kmem_free(ranges, length);

	if (ddi_getlongprop(DDI_DEV_T_ANY, dip,
		DDI_PROP_DONTPASS, "bus-range", (caddr_t)&bus,
		&k) != DDI_PROP_SUCCESS) {
		DEBUG0("Failed to read bus-range property\n");
		return (PCICFG_FAILURE);
	}

	DEBUG2("Need to free bus [%d] range [%d]\n",
		bus[0], bus[1] - bus[0] + 1);

	if (ndi_ra_free(ddi_get_parent(dip),
		(uint64_t)bus[0], (uint64_t)(bus[1] - bus[0] + 1),
		NDI_RA_TYPE_PCI_BUSNUM, NDI_RA_PASS) != NDI_SUCCESS) {
		DEBUG0("Failed to free a bus number\n");
		return (PCICFG_FAILURE);
	}
	return (PCICFG_SUCCESS);
}

static int
pcicfg_free_device_resources(dev_info_t *dip)
{
	pci_regspec_t *assigned;

	int length;
	int acount;
	int i;

	if (ddi_getlongprop(DDI_DEV_T_ANY, dip,
		DDI_PROP_DONTPASS, "assigned-addresses", (caddr_t)&assigned,
		&length) != DDI_PROP_SUCCESS) {
		DEBUG0("Failed to read assigned-addresses property\n");
		return (PCICFG_FAILURE);
	}

	/*
	 * For each "assigned-addresses" property entry with a length,
	 * call the memory allocation routines to return the
	 * resource.
	 */
	acount = length / sizeof (pci_regspec_t);
	for (i = 0; i < acount; i++) {
		/*
		 * Free the resource if the size of it is not zero.
		 */
		if ((assigned[i].pci_size_low != 0)||
			(assigned[i].pci_size_hi != 0)) {
			switch (PCI_REG_ADDR_G(assigned[i].pci_phys_hi)) {
			case PCI_REG_ADDR_G(PCI_ADDR_MEM32):
				/*
				 * Check the assigned address for zero.
				 * (Workaround for Devconf (x86) bug to
				 * skip bogus entry for ROM base address
				 * register. If the assigned address is
				 * zero then ignore the entry
				 * (see bugid 4281306)).
				 */
				if (assigned[i].pci_phys_low == 0)
					break; /* ignore the entry */

				if (ndi_ra_free(ddi_get_parent(dip),
				(uint64_t)assigned[i].pci_phys_low,
				(uint64_t)assigned[i].pci_size_low,
				NDI_RA_TYPE_MEM, NDI_RA_PASS) != NDI_SUCCESS) {
				DEBUG0("Trouble freeing "
				"PCI memory space\n");
				return (PCICFG_FAILURE);
				}

				DEBUG3("Returned 0x%x of 32 bit MEM space"
				" @ 0x%x from register 0x%x\n",
					assigned[i].pci_size_low,
					assigned[i].pci_phys_low,
					PCI_REG_REG_G(assigned[i].pci_phys_hi));

			break;
			case PCI_REG_ADDR_G(PCI_ADDR_MEM64):
				if (ndi_ra_free(ddi_get_parent(dip),
				PCICFG_LADDR(assigned[i].pci_phys_low,
				assigned[i].pci_phys_mid),
				(uint64_t)assigned[i].pci_size_low,
				NDI_RA_TYPE_MEM, NDI_RA_PASS) != NDI_SUCCESS) {
				DEBUG0("Trouble freeing "
				"PCI memory space\n");
				return (PCICFG_FAILURE);
				}

				DEBUG4("Returned 0x%x of 64 bit MEM space"
				" @ 0x%x.%x from register 0x%x\n",
					assigned[i].pci_size_low,
					assigned[i].pci_phys_mid,
					assigned[i].pci_phys_low,
					PCI_REG_REG_G(assigned[i].pci_phys_hi));

			break;
			case PCI_REG_ADDR_G(PCI_ADDR_IO):
				if (ndi_ra_free(ddi_get_parent(dip),
				(uint64_t)assigned[i].pci_phys_low,
				(uint64_t)assigned[i].pci_size_low,
				NDI_RA_TYPE_IO, NDI_RA_PASS) != NDI_SUCCESS) {
				DEBUG0("Trouble freeing "
				"PCI IO space\n");
				return (PCICFG_FAILURE);
				}
				DEBUG3("Returned 0x%x of IO space @ 0x%x"
				" from register 0x%x\n",
					assigned[i].pci_size_low,
					assigned[i].pci_phys_low,
					PCI_REG_REG_G(assigned[i].pci_phys_hi));
			break;
			default:
				DEBUG0("Unknown register type\n");
				kmem_free(assigned, length);
				return (PCICFG_FAILURE);
			} /* switch */
		}
	}
	kmem_free(assigned, length);
	return (PCICFG_SUCCESS);
}

static int
pcicfg_free_resources(dev_info_t *dip)
{
	ddi_acc_handle_t handle;
	uint8_t header_type;

	if (pci_config_setup(dip, &handle) != DDI_SUCCESS) {
		DEBUG0("Failed to map config space!\n");
		return (PCICFG_FAILURE);
	}

	header_type = pci_config_get8(handle, PCI_CONF_HEADER);

	(void) pci_config_teardown(&handle);

	/*
	 * A different algorithm is used for bridges and leaf devices.
	 */
	if ((header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_PPB) {
		if (pcicfg_free_bridge_resources(dip) != PCICFG_SUCCESS) {
			DEBUG0("Failed freeing up bridge resources\n");
			return (PCICFG_FAILURE);
		}
	} else {
		if (pcicfg_free_device_resources(dip) != PCICFG_SUCCESS) {
			DEBUG0("Failed freeing up device resources\n");
			return (PCICFG_FAILURE);
		}
	}

	return (PCICFG_SUCCESS);
}

#ifndef _DONT_USE_1275_GENERIC_NAMES
static char *
pcicfg_get_class_name(uint32_t classcode)
{
	struct pcicfg_name_entry *ptr;

	for (ptr = &pcicfg_class_lookup[0]; ptr->name != NULL; ptr++) {
		if (ptr->class_code == classcode) {
			return (ptr->name);
		}
	}
	return (NULL);
}
#endif /* _DONT_USE_1275_GENERIC_NAMES */

static dev_info_t *
pcicfg_devi_find(dev_info_t *dip, uint_t device, uint_t function)
{
	struct pcicfg_find_ctrl ctrl;
	int count;

	ctrl.device = device;
	ctrl.function = function;
	ctrl.dip = NULL;

	ndi_devi_enter(dip, &count);
	ddi_walk_devs(ddi_get_child(dip), pcicfg_match_dev, (void *)&ctrl);
	ndi_devi_exit(dip, count);

	return (ctrl.dip);
}

static int
pcicfg_match_dev(dev_info_t *dip, void *hdl)
{
	struct pcicfg_find_ctrl *ctrl = (struct pcicfg_find_ctrl *)hdl;
	pci_regspec_t *pci_rp;
	int length;
	int pci_dev;
	int pci_func;

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip,
		DDI_PROP_DONTPASS, "reg", (int **)&pci_rp,
		(uint_t *)&length) != DDI_PROP_SUCCESS) {
		ctrl->dip = NULL;
		return (DDI_WALK_TERMINATE);
	}

	/* get the PCI device address info */
	pci_dev = PCI_REG_DEV_G(pci_rp->pci_phys_hi);
	pci_func = PCI_REG_FUNC_G(pci_rp->pci_phys_hi);

	/*
	 * free the memory allocated by ddi_prop_lookup_int_array
	 */
	ddi_prop_free(pci_rp);


	if ((pci_dev == ctrl->device) && (pci_func == ctrl->function)) {
		/* found the match for the specified device address */
		ctrl->dip = dip;
		return (DDI_WALK_TERMINATE);
	}

	/*
	 * continue the walk to the next sibling to look for a match.
	 */
	return (DDI_WALK_PRUNECHILD);
}

static int
pcicfg_update_assigned_prop(dev_info_t *dip, pci_regspec_t *newone)
{
	int		alen;
	pci_regspec_t	*assigned;
	caddr_t		newreg;
	uint_t		status;

	status = ddi_getlongprop(DDI_DEV_T_NONE, dip, DDI_PROP_DONTPASS,
		"assigned-addresses", (caddr_t)&assigned, &alen);
	switch (status) {
		case DDI_PROP_SUCCESS:
		break;
		case DDI_PROP_NO_MEMORY:
			DEBUG0("no memory for assigned-addresses property\n");
			return (PCICFG_FAILURE);
		default:
			(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip,
			"assigned-addresses", (int *)newone,
				sizeof (*newone)/sizeof (int));
			return (PCICFG_SUCCESS);
	}

	/*
	 * Allocate memory for the existing
	 * assigned-addresses(s) plus one and then
	 * build it.
	 */

	newreg = kmem_zalloc(alen+sizeof (*newone), KM_SLEEP);

	bcopy(assigned, newreg, alen);
	bcopy(newone, newreg + alen, sizeof (*newone));

	/*
	 * Write out the new "assigned-addresses" spec
	 */
	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip,
		"assigned-addresses", (int *)newreg,
		(alen + sizeof (*newone))/sizeof (int));

	kmem_free((caddr_t)newreg, alen+sizeof (*newone));
	kmem_free(assigned, alen);

	return (PCICFG_SUCCESS);
}

static int
pcicfg_update_ranges_prop(dev_info_t *dip, pcicfg_range_t *addition)
{
	int		rlen;
	pcicfg_range_t	*ranges;
	caddr_t		newreg;
	uint_t		status;

	status = ddi_getlongprop(DDI_DEV_T_NONE,
		dip, DDI_PROP_DONTPASS, "ranges", (caddr_t)&ranges, &rlen);


	switch (status) {
		case DDI_PROP_SUCCESS:
		break;
		case DDI_PROP_NO_MEMORY:
			DEBUG0("ranges present, but unable to get memory\n");
			return (PCICFG_FAILURE);
		default:
			DEBUG0("no ranges property - creating one\n");
			if (ndi_prop_update_int_array(DDI_DEV_T_NONE,
				dip, "ranges", (int *)addition,
				sizeof (pcicfg_range_t)/sizeof (int))
				!= DDI_SUCCESS) {
				DEBUG0("Did'nt create ranges property\n");
				return (PCICFG_FAILURE);
			}
			return (PCICFG_SUCCESS);
	}

	/*
	 * Allocate memory for the existing reg(s) plus one and then
	 * build it.
	 */
	newreg = kmem_zalloc(rlen+sizeof (pcicfg_range_t), KM_SLEEP);

	bcopy(ranges, newreg, rlen);
	bcopy(addition, newreg + rlen, sizeof (pcicfg_range_t));

	/*
	 * Write out the new "ranges" property
	 */
	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE,
		dip, "ranges", (int *)newreg,
		(rlen + sizeof (pcicfg_range_t))/sizeof (int));

	kmem_free((caddr_t)newreg, rlen+sizeof (pcicfg_range_t));

	kmem_free((caddr_t)ranges, rlen);

	return (PCICFG_SUCCESS);
}

static int
pcicfg_update_reg_prop(dev_info_t *dip, uint32_t regvalue, uint_t reg_offset)
{
	int		rlen;
	pci_regspec_t	*reg;
	caddr_t		newreg;
	uint32_t	hiword;
	pci_regspec_t	addition;
	uint32_t	size;
	uint_t		status;

	status = ddi_getlongprop(DDI_DEV_T_NONE,
		dip, DDI_PROP_DONTPASS, "reg", (caddr_t)&reg, &rlen);

	switch (status) {
		case DDI_PROP_SUCCESS:
		break;
		case DDI_PROP_NO_MEMORY:
			DEBUG0("reg present, but unable to get memory\n");
			return (PCICFG_FAILURE);
		default:
			DEBUG0("no reg property\n");
			return (PCICFG_FAILURE);
	}

	/*
	 * Allocate memory for the existing reg(s) plus one and then
	 * build it.
	 */
	newreg = kmem_zalloc(rlen+sizeof (pci_regspec_t), KM_SLEEP);

	/*
	 * Build the regspec, then add it to the existing one(s)
	 */

	hiword = PCICFG_MAKE_REG_HIGH(PCI_REG_BUS_G(reg->pci_phys_hi),
	    PCI_REG_DEV_G(reg->pci_phys_hi),
	    PCI_REG_FUNC_G(reg->pci_phys_hi), reg_offset);

	if (reg_offset == PCI_CONF_ROM) {
		size = (~(PCI_BASE_ROM_ADDR_M & regvalue))+1;
		hiword |= PCI_ADDR_MEM32;
	} else {
		size = (~(PCI_BASE_M_ADDR_M & regvalue))+1;

		if ((PCI_BASE_SPACE_M & regvalue) == PCI_BASE_SPACE_MEM) {
			if ((PCI_BASE_TYPE_M & regvalue) == PCI_BASE_TYPE_MEM) {
				hiword |= PCI_ADDR_MEM32;
			} else if ((PCI_BASE_TYPE_M & regvalue)
				== PCI_BASE_TYPE_ALL) {
				hiword |= PCI_ADDR_MEM64;
			}
		} else {
			hiword |= PCI_ADDR_IO;
		}
	}

	addition.pci_phys_hi = hiword;
	addition.pci_phys_mid = 0;
	addition.pci_phys_low = 0;
	addition.pci_size_hi = 0;
	addition.pci_size_low = size;

	bcopy(reg, newreg, rlen);
	bcopy(&addition, newreg + rlen, sizeof (pci_regspec_t));

	/*
	 * Write out the new "reg" property
	 */
	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE,
		dip, "reg", (int *)newreg,
		(rlen + sizeof (pci_regspec_t))/sizeof (int));

	kmem_free((caddr_t)newreg, rlen+sizeof (pci_regspec_t));
	kmem_free((caddr_t)reg, rlen);

	return (PCICFG_SUCCESS);
}

static void
pcicfg_device_on(ddi_acc_handle_t config_handle)
{
	/*
	 * Enable memory, IO, and bus mastership
	 * XXX should we enable parity, SERR#,
	 * fast back-to-back, and addr. stepping?
	 */
	pci_config_put16(config_handle, PCI_CONF_COMM,
		pci_config_get16(config_handle, PCI_CONF_COMM) | 0x7);
}

static void
pcicfg_device_off(ddi_acc_handle_t config_handle)
{
	/*
	 * Disable I/O and memory traffic through the bridge
	 */
	pci_config_put16(config_handle, PCI_CONF_COMM, 0x0);
}

/*
 * Setup the basic 1275 properties based on information found in the config
 * header of the PCI device
 */
static int
pcicfg_set_standard_props(dev_info_t *dip, ddi_acc_handle_t config_handle)
{
	int ret;
	uint16_t val;
	uint32_t wordval;
	uint8_t byteval;

	/* These two exists only for non-bridges */
	if ((pci_config_get8(config_handle,
		PCI_CONF_HEADER) & PCI_HEADER_TYPE_M) == PCI_HEADER_ZERO) {
		byteval = pci_config_get8(config_handle, PCI_CONF_MIN_G);
		if ((ret = ndi_prop_update_int(DDI_DEV_T_NONE, dip,
			"min-grant", byteval)) != DDI_SUCCESS) {
			return (ret);
		}

		byteval = pci_config_get8(config_handle, PCI_CONF_MAX_L);
		if ((ret = ndi_prop_update_int(DDI_DEV_T_NONE, dip,
			"max-latency", byteval)) != DDI_SUCCESS) {
			return (ret);
		}
	}

	/*
	 * These should always exist and have the value of the
	 * corresponding register value
	 */
	val = pci_config_get16(config_handle, PCI_CONF_VENID);

	if ((ret = ndi_prop_update_int(DDI_DEV_T_NONE, dip,
				"vendor-id", val)) != DDI_SUCCESS) {
		return (ret);
	}
	val = pci_config_get16(config_handle, PCI_CONF_DEVID);
	if ((ret = ndi_prop_update_int(DDI_DEV_T_NONE, dip,
				"device-id", val)) != DDI_SUCCESS) {
		return (ret);
	}
	byteval = pci_config_get8(config_handle, PCI_CONF_REVID);
	if ((ret = ndi_prop_update_int(DDI_DEV_T_NONE, dip,
				"revision-id", byteval)) != DDI_SUCCESS) {
		return (ret);
	}

	wordval = (pci_config_get16(config_handle, PCI_CONF_SUBCLASS)<< 8) |
		(pci_config_get8(config_handle, PCI_CONF_PROGCLASS));

	if ((ret = ndi_prop_update_int(DDI_DEV_T_NONE, dip,
				"class-code", wordval)) != DDI_SUCCESS) {
		return (ret);
	}
	val = (pci_config_get16(config_handle,
		PCI_CONF_STAT) & PCI_STAT_DEVSELT);
	if ((ret = ndi_prop_update_int(DDI_DEV_T_NONE, dip,
				"devsel-speed", val)) != DDI_SUCCESS) {
		return (ret);
	}

	/*
	 * The next three are bits set in the status register.  The property is
	 * present (but with no value other than its own existence) if the bit
	 * is set, non-existent otherwise
	 */
	if (pci_config_get16(config_handle, PCI_CONF_STAT) & PCI_STAT_FBBC) {
		if ((ret = ndi_prop_update_int(DDI_DEV_T_NONE, dip,
				"fast-back-to-back", 0)) != DDI_SUCCESS) {
			return (ret);
		}
	}
	if (pci_config_get16(config_handle, PCI_CONF_STAT) & PCI_STAT_66MHZ) {
		if ((ret = ndi_prop_update_int(DDI_DEV_T_NONE, dip,
				"66mhz-capable", 0)) != DDI_SUCCESS) {
			return (ret);
		}
	}
	if (pci_config_get16(config_handle, PCI_CONF_STAT) & PCI_STAT_UDF) {
		if ((ret = ndi_prop_update_int(DDI_DEV_T_NONE, dip,
				"udf-supported", 0)) != DDI_SUCCESS) {
			return (ret);
		}
	}

	/*
	 * These next three are optional and are not present
	 * if the corresponding register is zero.  If the value
	 * is non-zero then the property exists with the value
	 * of the register.
	 */
	if ((val = pci_config_get16(config_handle,
		PCI_CONF_SUBVENID)) != 0) {
		if ((ret = ndi_prop_update_int(DDI_DEV_T_NONE, dip,
				"subsystem-vendor-id", val)) != DDI_SUCCESS) {
			return (ret);
		}
	}
	if ((val = pci_config_get16(config_handle,
		PCI_CONF_SUBSYSID)) != 0) {
		if ((ret = ndi_prop_update_int(DDI_DEV_T_NONE, dip,
				"subsystem-id", val)) != DDI_SUCCESS) {
			return (ret);
		}
	}
	if ((val = pci_config_get16(config_handle,
		PCI_CONF_CACHE_LINESZ)) != 0) {
		if ((ret = ndi_prop_update_int(DDI_DEV_T_NONE, dip,
				"cache-line-size", val)) != DDI_SUCCESS) {
			return (ret);
		}
	}

	/*
	 * If the Interrupt Pin register is non-zero then the
	 * interrupts property exists
	 */
	if ((byteval = pci_config_get8(config_handle, PCI_CONF_IPIN)) != 0) {
		/*
		 * If interrupt pin is non-zero,
		 * record the interrupt line used
		 */
		if ((ret = ndi_prop_update_int(DDI_DEV_T_NONE, dip,
				"interrupts", byteval)) != DDI_SUCCESS) {
			return (ret);
		}
	}
	return (PCICFG_SUCCESS);
}
static int
pcicfg_set_busnode_props(dev_info_t *dip)
{
	int ret;

	if ((ret = ndi_prop_update_string(DDI_DEV_T_NONE, dip,
				"device_type", "pci")) != DDI_SUCCESS) {
		return (ret);
	}
	if ((ret = ndi_prop_update_int(DDI_DEV_T_NONE, dip,
				"#address-cells", 3)) != DDI_SUCCESS) {
		return (ret);
	}
	if ((ret = ndi_prop_update_int(DDI_DEV_T_NONE, dip,
				"#size-cells", 2)) != DDI_SUCCESS) {
		return (ret);
	}
	return (PCICFG_SUCCESS);
}

static int
pcicfg_set_childnode_props(dev_info_t *dip, ddi_acc_handle_t config_handle)
{

	int		ret;
#ifndef _DONT_USE_1275_GENERIC_NAMES
	uint32_t	wordval;
#endif
	char		*name;
	char		buffer[64];
	uint32_t	classcode;
	char		*compat[8];
	int		i;
	int		n;
	uint16_t		sub_vid, sub_sid;
#ifdef _EFCODE_WORKAROUND
	char		nmbuffer[32];
#endif
	/*
	 * NOTE: These are for both a child and PCI-PCI bridge node
	 */
#ifndef _DONT_USE_1275_GENERIC_NAMES
	wordval = (pci_config_get16(config_handle, PCI_CONF_SUBCLASS)<< 8) |
		(pci_config_get8(config_handle, PCI_CONF_PROGCLASS));
#endif

	sub_vid = pci_config_get16(config_handle, PCI_CONF_SUBVENID),
	sub_sid = pci_config_get16(config_handle, PCI_CONF_SUBSYSID);
	if (pci_config_get16(config_handle, PCI_CONF_SUBSYSID) != 0) {
		(void) sprintf(buffer, "pci%x,%x", sub_vid, sub_sid);
	} else {
		(void) sprintf(buffer, "pci%x,%x",
			pci_config_get16(config_handle, PCI_CONF_VENID),
			pci_config_get16(config_handle, PCI_CONF_DEVID));
	}

	/*
	 * In some environments, trying to use "generic" 1275 names is
	 * not the convention.  In those cases use the name as created
	 * above.  In all the rest of the cases, check to see if there
	 * is a generic name first.
	 */
#ifdef _DONT_USE_1275_GENERIC_NAMES
	name = buffer;
#else
	if ((name = pcicfg_get_class_name(wordval>>8)) == NULL) {
		/*
		 * Set name to the above fabricated name
		 */
		name = buffer;
	}
#endif
#ifdef _EFCODE_WORKAROUND
	if (pcicfg_fcode_name(dip, config_handle, nmbuffer) ==
								DDI_SUCCESS)
		name = nmbuffer;
#endif

	/*
	 * The node name field needs to be filled in with the name
	 */
	if (ndi_devi_set_nodename(dip, name, 0) != NDI_SUCCESS) {
		DEBUG0("Failed to set nodename for node\n");
		return (PCICFG_FAILURE);
	}

	/*
	 * Create the compatible property as an array of pointers
	 * to strings.  Start with the buffer created above.
	 */
	n = 0;
#ifdef _EFCODE_WORKAROUND
	if (pcicfg_fcode_compatible(dip, config_handle, nmbuffer) ==
								DDI_SUCCESS) {
		compat[n] = kmem_alloc(strlen(nmbuffer) + 1, KM_SLEEP);
		(void) strcpy(compat[n++], nmbuffer);
	}
#endif
	compat[n] = kmem_alloc(strlen(buffer) + 1, KM_SLEEP);
	(void) strcpy(compat[n++], buffer);

	/*
	 * Add in the VendorID/DeviceID compatible name.
	 */
	(void) sprintf(buffer, "pci%x,%x",
		pci_config_get16(config_handle, PCI_CONF_VENID),
		pci_config_get16(config_handle, PCI_CONF_DEVID));

	compat[n] = kmem_alloc(strlen(buffer) + 1, KM_SLEEP);
	(void) strcpy(compat[n++], buffer);

	classcode = (pci_config_get16(config_handle, PCI_CONF_SUBCLASS)<< 8) |
		(pci_config_get8(config_handle, PCI_CONF_PROGCLASS));

	/*
	 * Add in the Classcode
	 */
	(void) sprintf(buffer, "pciclass,%06x", classcode);
	compat[n] = kmem_alloc(strlen(buffer) + 1, KM_SLEEP);
	(void) strcpy(compat[n++], buffer);

	if ((ret = ndi_prop_update_string_array(DDI_DEV_T_NONE, dip,
		"compatible", (char **)compat, n)) != DDI_SUCCESS) {
		return (ret);
	}

	for (i = 0; i < n; i++) {
		kmem_free(compat[i], strlen(compat[i]) + 1);
	}

	return (PCICFG_SUCCESS);
}

/*
 * Program the bus numbers into the bridge
 */
static void
pcicfg_set_bus_numbers(ddi_acc_handle_t config_handle,
uint_t primary, uint_t secondary)
{
	/*
	 * Primary bus#
	 */
	pci_config_put8(config_handle, PCI_BCNF_PRIBUS, primary);

	/*
	 * Secondary bus#
	 */
	pci_config_put8(config_handle, PCI_BCNF_SECBUS, secondary);

	/*
	 * Set the subordinate bus number to ff in order to pass through any
	 * type 1 cycle with a bus number higher than the secondary bus#
	 */
	pci_config_put8(config_handle, PCI_BCNF_SUBBUS, 0xFF);
}

/*
 * Put bridge registers into initial state
 */
static void
pcicfg_setup_bridge(pcicfg_phdl_t *entry,
	ddi_acc_handle_t handle)
{
	/*
	 * The highest bus seen during probing is the max-subordinate bus
	 */
	pci_config_put8(handle, PCI_BCNF_SUBBUS, entry->highest_bus);

	/*
	 * Reset the secondary bus
	 */
	pci_config_put16(handle, PCI_BCNF_BCNTRL,
		pci_config_get16(handle, PCI_BCNF_BCNTRL) | 0x40);
	pci_config_put16(handle, PCI_BCNF_BCNTRL,
		pci_config_get16(handle, PCI_BCNF_BCNTRL) & ~0x40);

	/*
	 * Program the memory base register with the
	 * start of the memory range
	 */
	pci_config_put16(handle, PCI_BCNF_MEM_BASE,
		PCICFG_HIWORD(PCICFG_LOADDR(entry->memory_last)));

	/*
	 * Program the I/O base register with the start of the I/O range
	 */
	pci_config_put8(handle, PCI_BCNF_IO_BASE_LOW,
		PCICFG_HIBYTE(PCICFG_LOWORD(PCICFG_LOADDR(entry->io_last))));
	pci_config_put16(handle, PCI_BCNF_IO_BASE_HI,
		PCICFG_HIWORD(PCICFG_LOADDR(entry->io_last)));

	/*
	 * Clear status bits
	 */
	pci_config_put16(handle, PCI_BCNF_SEC_STATUS, 0xffff);

	/*
	 * Turn off prefetchable range
	 */
	pci_config_put32(handle, PCI_BCNF_PF_BASE_LOW, 0x0000ffff);
	pci_config_put32(handle, PCI_BCNF_PF_BASE_HIGH, 0xffffffff);
	pci_config_put32(handle, PCI_BCNF_PF_LIMIT_HIGH, 0x0);

	/*
	 * Needs to be set to this value
	 */
	pci_config_put8(handle, PCI_CONF_ILINE, 0xf);
}

static void
pcicfg_update_bridge(pcicfg_phdl_t *entry,
	ddi_acc_handle_t handle)
{
	uint_t length;

	/*
	 * Program the memory limit register with the end of the memory range
	 */

	DEBUG1("DOWN ROUNDED ===>[0x%x]\n",
		PCICFG_ROUND_DOWN(entry->memory_last,
		PCICFG_MEMGRAN));

	pci_config_put16(handle, PCI_BCNF_MEM_LIMIT,
		PCICFG_HIWORD(PCICFG_LOADDR(
		PCICFG_ROUND_DOWN(entry->memory_last,
			PCICFG_MEMGRAN))));
	/*
	 * Since this is a bridge, the rest of this range will
	 * be responded to by the bridge.  We have to round up
	 * so no other device claims it.
	 */
	if ((length = (PCICFG_ROUND_UP(entry->memory_last,
		PCICFG_MEMGRAN) - entry->memory_last)) > 0) {
		(void) pcicfg_get_mem(entry, length, NULL);
		DEBUG1("Added [0x%x]at the top of "
		"the bridge (mem)\n", length);
	}

	/*
	 * Program the I/O limit register with the end of the I/O range
	 */
	pci_config_put8(handle, PCI_BCNF_IO_LIMIT_LOW,
		PCICFG_HIBYTE(PCICFG_LOWORD(
		PCICFG_LOADDR(PCICFG_ROUND_DOWN(entry->io_last,
			PCICFG_IOGRAN)))));

	pci_config_put16(handle, PCI_BCNF_IO_LIMIT_HI,
		PCICFG_HIWORD(PCICFG_LOADDR(PCICFG_ROUND_DOWN(entry->io_last,
		PCICFG_IOGRAN))));

	/*
	 * Same as above for I/O space. Since this is a
	 * bridge, the rest of this range will be responded
	 * to by the bridge.  We have to round up so no
	 * other device claims it.
	 */
	if ((length = (PCICFG_ROUND_UP(entry->io_last,
		PCICFG_IOGRAN) - entry->io_last)) > 0) {
		(void) pcicfg_get_io(entry, length, NULL);
		DEBUG1("Added [0x%x]at the top of "
		"the bridge (I/O)\n",  length);
	}
}

static int
pcicfg_probe_children(dev_info_t *parent, uint_t bus,
	uint_t device, uint_t func)
{
	dev_info_t		*new_child;
	ddi_acc_handle_t	config_handle;
	uint8_t			header_type;

	int			i, j;
	ndi_ra_request_t	req;
	uint64_t		next_bus;
	uint64_t		blen;
	uint32_t		request;
	uint_t			new_bus;
	int			ret;
	int			circ;

	/*
	 * This node will be put immediately below
	 * "parent". Allocate a blank device node.  It will either
	 * be filled in or freed up based on further probing.
	 */

	ndi_devi_enter(parent, &circ);
	ndi_devi_alloc_sleep(parent, DEVI_PSEUDO_NEXNAME,
		(dnode_t)DEVI_SID_NODEID, &new_child);

	if (pcicfg_add_config_reg(new_child, bus,
		device, func) != DDI_SUCCESS) {
		DEBUG0("pcicfg_probe_children():"
		"Failed to add candidate REG\n");
		goto failedchild;
	}

	if ((ret = pcicfg_config_setup(new_child, &config_handle))
		!= PCICFG_SUCCESS) {
		if (ret == PCICFG_NODEVICE) {
			(void) ndi_devi_free(new_child);
			ndi_devi_exit(parent, circ);
			return (ret);
		}
		DEBUG0("pcicfg_probe_children():"
		"Failed to setup config space\n");
		goto failedconfig;
	}

	/*
	 * As soon as we have access to config space,
	 * turn off device. It will get turned on
	 * later (after memory is assigned).
	 */
	(void) pcicfg_device_off(config_handle);

	/*
	 * Set 1275 properties common to all devices
	 */
	if (pcicfg_set_standard_props(new_child,
		config_handle) != PCICFG_SUCCESS) {
		DEBUG0("Failed to set standard properties\n");
		goto failedchild;
	}

	/*
	 * Child node properties  NOTE: Both for PCI-PCI bridge and child node
	 */
	if (pcicfg_set_childnode_props(new_child,
		config_handle) != PCICFG_SUCCESS) {
		goto failedchild;
	}

	header_type = pci_config_get8(config_handle, PCI_CONF_HEADER);

	/*
	 * If this is not a multi-function card only probe function zero.
	 */
	if (!(header_type & PCI_HEADER_MULTI) && (func != 0)) {

		(void) pcicfg_config_teardown(&config_handle);
		(void) ndi_devi_free(new_child);
		ndi_devi_exit(parent, circ);
		return (PCICFG_NODEVICE);
	}

	if ((header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_PPB) {

		DEBUG3("--Bridge found bus [0x%x] device"
			"[0x%x] func [0x%x]\n", bus, device, func);

		/*
		 * Get next bus in sequence and program device.
		 * XXX There might have to be slot specific
		 * ranges taken care of here.
		 */
		bzero((caddr_t)&req, sizeof (ndi_ra_request_t));
		req.ra_len = 1;
		if (ndi_ra_alloc(ddi_get_parent(new_child), &req,
			&next_bus, &blen, NDI_RA_TYPE_PCI_BUSNUM,
			NDI_RA_PASS) != NDI_SUCCESS) {
			DEBUG0("Failed to get a bus number\n");
			goto failedchild;
		}
		new_bus = next_bus;

		DEBUG1("NEW bus found  ->[%d]\n", new_bus);

		(void) pcicfg_set_bus_numbers(config_handle,
			bus, new_bus);
		/*
		 * Set bus properties
		 */
		if (pcicfg_set_busnode_props(new_child) != PCICFG_SUCCESS) {
			DEBUG0("Failed to set busnode props\n");
			goto failedchild;
		}

		/*
		 * Probe all children devices
		 */
		for (i = 0; i < PCICFG_MAX_DEVICE; i++) {
			for (j = 0; j < PCICFG_MAX_FUNCTION; j++) {
				if (pcicfg_probe_children(new_child,
					new_bus, i, j) ==
							PCICFG_FAILURE) {
					DEBUG3("Failed to configure bus "
					"[0x%x] device [0x%x] func [0x%x]\n",
						new_bus, i, j);
					goto failedchild;
				}
			}
		}

	} else {

		DEBUG3("--Leaf device found bus [0x%x] device"
			"[0x%x] func [0x%x]\n",
				bus, device, func);

		i = PCI_CONF_BASE0;

		while (i <= PCI_CONF_BASE5) {

			pci_config_put32(config_handle, i, 0xffffffff);

			request = pci_config_get32(config_handle, i);
			/*
			 * If its a zero length, don't do
			 * any programming.
			 */
			if (request != 0) {
				/*
				 * Add to the "reg" property
				 */
				if (pcicfg_update_reg_prop(new_child,
					request, i) != PCICFG_SUCCESS) {
					goto failedchild;
				}
			} else {
				DEBUG1("BASE register [0x%x] asks for "
				"[0x0]=[0x0](32)\n", i);
				i += 4;
				continue;
			}

			/*
			 * Increment by eight if it is 64 bit address space
			 */
			if ((PCI_BASE_TYPE_M & request) == PCI_BASE_TYPE_ALL) {
				DEBUG3("BASE register [0x%x] asks for "
				"[0x%x]=[0x%x] (64)\n",
					i, request,
					(~(PCI_BASE_M_ADDR_M & request))+1)
				i += 8;
			} else {
				DEBUG3("BASE register [0x%x] asks for "
				"[0x%x]=[0x%x](32)\n",
					i, request,
					(~(PCI_BASE_M_ADDR_M & request))+1)
				i += 4;
			}
		}

		/*
		 * Get the ROM size and create register for it
		 */
		pci_config_put32(config_handle, PCI_CONF_ROM, 0xfffffffe);

		request = pci_config_get32(config_handle, PCI_CONF_ROM);
		/*
		 * If its a zero length, don't do
		 * any programming.
		 */

		if (request != 0) {
			DEBUG3("BASE register [0x%x] asks for [0x%x]=[0x%x]\n",
				PCI_CONF_ROM, request,
				(~(PCI_BASE_ROM_ADDR_M & request))+1);
			/*
			 * Add to the "reg" property
			 */
			if (pcicfg_update_reg_prop(new_child,
				request, PCI_CONF_ROM) != PCICFG_SUCCESS) {
				goto failedchild;
			}
		}
	}

	(void) pcicfg_config_teardown(&config_handle);

	/*
	 * Attach the child to its parent
	 */
	(void) i_ndi_config_node(new_child, DS_LINKED, 0);
	ndi_devi_exit(parent, circ);

	return (PCICFG_SUCCESS);

failedchild:
	/*
	 * XXX check if it should be taken offline (if online)
	 */
	(void) pcicfg_config_teardown(&config_handle);

failedconfig:

	(void) ndi_devi_free(new_child);
	ndi_devi_exit(parent, circ);

	return (PCICFG_FAILURE);
}

/*
 * Make "parent" be the parent of the "child" dip
 */
static void
pcicfg_reparent_node(dev_info_t *child, dev_info_t *parent)
{
	int circ;
	dev_info_t *opdip;

	ASSERT(i_ddi_node_state(child) <= DS_LINKED);
	/*
	 * Unlink node from tree before reparenting
	 */
	opdip = ddi_get_parent(child);
	ndi_devi_enter(opdip, &circ);
	(void) i_ndi_unconfig_node(child, DS_PROTO, 0);
	ndi_devi_exit(opdip, circ);

	DEVI(child)->devi_parent = DEVI(parent);
	DEVI(child)->devi_bus_ctl = DEVI(parent);
	(void) ndi_devi_bind_driver(child, 0);
}

/*
 * Return PCICFG_SUCCESS if device exists at the specified address.
 * Return PCICFG_NODEVICE is no device exists at the specified address.
 *
 */
int
pcicfg_config_setup(dev_info_t *dip, ddi_acc_handle_t *handle)
{
	caddr_t	cfgaddr;
	ddi_device_acc_attr_t attr;
	dev_info_t *anode;
	int status;
	int		rlen;
	pci_regspec_t	*reg;
	int		ret = DDI_SUCCESS;
	int16_t		tmp;
	/*
	 * flags = PCICFG_CONF_INDIRECT_MAP if configuration space is indirectly
	 * mapped, otherwise it is 0. "flags" is introduced in support of any
	 * non transparent bridges, where configuration space is indirectly
	 * mapped.
	 */
	int	flags = 0;

	/*
	 * Get the pci register spec from the node
	 */
	status = ddi_getlongprop(DDI_DEV_T_NONE,
		dip, DDI_PROP_DONTPASS, "reg", (caddr_t)&reg, &rlen);

	switch (status) {
		case DDI_PROP_SUCCESS:
		break;
		case DDI_PROP_NO_MEMORY:
			DEBUG0("reg present, but unable to get memory\n");
			return (PCICFG_FAILURE);
		default:
			DEBUG0("no reg property\n");
			return (PCICFG_FAILURE);
	}

	anode = dip;

	/*
	 * Find the attachment point node
	 */
	while ((anode != NULL) && (strcmp(ddi_binding_name(anode),
		"hp_attachment") != 0)) {
		anode = ddi_get_parent(anode);
	}

	if (anode == NULL) {
		DEBUG0("Tree not in PROBE state\n");
		kmem_free((caddr_t)reg, rlen);
		return (PCICFG_FAILURE);
	}

	if (ndi_prop_update_int_array(DDI_DEV_T_NONE, anode,
				    "reg", (int *)reg, 5)) {
		DEBUG0("Failed to update reg property...\n");
		kmem_free((caddr_t)reg, rlen);
		return (PCICFG_FAILURE);
	}

	if (pcicfg_indirect_map(anode) == DDI_SUCCESS)
		flags |= PCICFG_CONF_INDIRECT_MAP;

	DEBUG3("conf_map: flags = %d, dip=%llx, anode=%llx\n",
						flags, dip, anode);

	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	if (ddi_regs_map_setup(anode, 0, &cfgaddr,
		0, 0, &attr, handle) != DDI_SUCCESS) {
		DEBUG0("Failed to setup registers\n");
		kmem_free((caddr_t)reg, rlen);
		return (PCICFG_FAILURE);
	}

	if (flags & PCICFG_CONF_INDIRECT_MAP) {
		/*
		 * need to use DDI interfaces as the conf space is
		 * cannot be directly accessed by the host.
		 */
		tmp = (int16_t)ddi_get16(*handle, (uint16_t *)cfgaddr);
	} else {
		ret = ddi_peek16(anode, (int16_t *)cfgaddr, &tmp);
	}
	if (ret == DDI_SUCCESS) {
		if ((tmp == (int16_t)0xffff) || (tmp == -1)) {
			DEBUG1("NO DEVICEFOUND, read %x\n", tmp);
			ret = PCICFG_NODEVICE;
		} else {
			DEBUG1("DEVICEFOUND, read %x\n", tmp);
			ret = PCICFG_SUCCESS;

		}
	} else {
		DEBUG0("ddi_peek failed, must be NODEVICE\n");
		ret = PCICFG_NODEVICE;
	}

	if (ret == PCICFG_NODEVICE)
		ddi_regs_map_free(handle);
	kmem_free((caddr_t)reg, rlen);

	return (ret);

}

static void
pcicfg_config_teardown(ddi_acc_handle_t *handle)
{
	(void) ddi_regs_map_free(handle);
}

static int
pcicfg_add_config_reg(dev_info_t *dip,
	uint_t bus, uint_t device, uint_t func)
{
	int reg[10] = { PCI_ADDR_CONFIG, 0, 0, 0, 0};

	reg[0] = PCICFG_MAKE_REG_HIGH(bus, device, func, 0);

	return (ndi_prop_update_int_array(DDI_DEV_T_NONE, dip,
		"reg", reg, 5));
}

#ifdef DEBUG
static void
debug(char *fmt, uintptr_t a1, uintptr_t a2, uintptr_t a3,
	uintptr_t a4, uintptr_t a5)
{
	if (pcicfg_debug > 1) {
		prom_printf("pcicfg: ");
		prom_printf(fmt, a1, a2, a3, a4, a5);
	}
}
#endif

#ifdef _EFCODE_WORKAROUND
static int
pcicfg_update_ethernet(dev_info_t *dip, void *hdl)
{
	char *string = (char *)hdl;
	uint_t length;
	int *vendor_id;
	int *device_id;

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY,
		dip, DDI_PROP_DONTPASS,
		"vendor-id", &vendor_id,
		&length) != DDI_PROP_SUCCESS) {
		return (DDI_WALK_TERMINATE);
	}

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY,
		dip, DDI_PROP_DONTPASS,
		"device-id", &device_id,
		&length) != DDI_PROP_SUCCESS) {
		ddi_prop_free(vendor_id);
		return (DDI_WALK_TERMINATE);
	}

	/*
	 * Change the name of the "ethernet" node appropriately
	 */
	if (*vendor_id == 0x108e && *device_id == 0x1001) {
		(void) ndi_devi_set_nodename(dip, string, 0);
	}

	/*
	 * free the memory allocated by ddi_prop_lookup_int_array
	 */
	ddi_prop_free(vendor_id);
	ddi_prop_free(device_id);

	/*
	 * continue the walk to the next sibling
	 */
	return (DDI_WALK_CONTINUE);
}

static int
pcicfg_match_ethernet(dev_info_t *dip, void *hdl)
{
	int *count = (int *)hdl;
	uint_t length;
	int *vendor_id;
	int *device_id;

	length = 0;
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY,
		dip, DDI_PROP_DONTPASS,
		"vendor-id", &vendor_id,
		&length) != DDI_PROP_SUCCESS) {
		*count = 0;
		return (DDI_WALK_TERMINATE);
	}

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY,
		dip, DDI_PROP_DONTPASS,
		"device-id", &device_id,
		&length) != DDI_PROP_SUCCESS) {
		*count = 0;
		ddi_prop_free(vendor_id);
		return (DDI_WALK_TERMINATE);
	}

	/*
	 * Keep a running tally of ethernet devices found.
	 */
	if (*vendor_id == 0x108e &&
		(*device_id == 0x1001)) {
		*count += 1;
	}

	/*
	 * free the memory allocated by ddi_prop_lookup_int_array
	 */
	ddi_prop_free(vendor_id);
	ddi_prop_free(device_id);

	/*
	 * continue the walk to the next sibling
	 */
	return (DDI_WALK_CONTINUE);
}

static void
pcicfg_fix_ethernet(dev_info_t *dip)
{
	int number;
	static char buffer[16];
	dev_info_t *parent;
	int circular;

	number = 0;
	/*
	 * Walk the device nodes below the attach point
	 * and count the number of ethernet devices.
	 */
	if ((parent = ddi_get_parent(dip)) != NULL)
		ndi_devi_enter(parent, &circular);
	ddi_walk_devs(dip, pcicfg_match_ethernet, (void *)&number);
	if (parent)
		ndi_devi_exit(parent, circular);

	if (number > 1) {
		(void) strncpy(buffer, "SUNW,qfe", 8);
	} else if (number) {
		(void) strncpy(buffer, "SUNW,hme", 8);
	} else {
		return;
	}

	if (parent)
		ndi_devi_enter(parent, &circular);
	ddi_walk_devs(dip, pcicfg_update_ethernet, (void *)buffer);
	if (parent)
		ndi_devi_exit(parent, circular);
}

/*
 * Called from pcicfg_set_childnode_props(), this functions returns
 * the value of FCode "name" property for a list of FCode devices
 * that we support currently, whose name property is not as per the 1275
 * PCI bindings.
 * Up until the FCode interpreter is available, any special hacks for a
 * a given node may have to be put here.
 */
/*ARGSUSED*/
static int
pcicfg_fcode_name(dev_info_t *dip, ddi_acc_handle_t config_handle, char *buffer)
{
	uint16_t sub_vid, sub_sid, vid, did;
	dev_info_t *pdip;
	int rc = DDI_FAILURE;

	vid = pci_config_get16(config_handle, PCI_CONF_VENID),
	did = pci_config_get16(config_handle, PCI_CONF_DEVID);
	sub_vid = pci_config_get16(config_handle, PCI_CONF_SUBVENID),
	sub_sid = pci_config_get16(config_handle, PCI_CONF_SUBSYSID);

	/*
	 * If the driver binding is based on subsystem vendor id and
	 * subsystem Id via the 'name' property, then place the
	 * binding entry here and set rc=DDI_SUCCESS so that we do
	 * not proceed to the next switch loop.
	 */
	switch (sub_sid | (sub_vid << 16)) {
		default:
			break;
	}
	if (rc == DDI_SUCCESS)
		return (rc);

	/*
	 * If we got here, then the driver binding is based on vendor id and
	 * device Id via the 'name' property. So place the
	 * binding entry here and set rc=DDI_SUCCESS.
	 */
	switch (did | (vid << 16)) {
		case 0x10772200:
			(void) strcpy(buffer, "SUNW,qlc");
			rc = DDI_SUCCESS;
			break;
		case 0x108e1001:
			/* default name is hme, change later to qfe if reqd. */
			(void) strcpy(buffer, "SUNW,hme");
			rc = DDI_SUCCESS;
			break;
		case 0x10771020:
			(void) strcpy(buffer, "SUNW,isptwo");
			rc = DDI_SUCCESS;
			break;
		case 0x108e1000:
			pdip = ddi_get_parent(ddi_get_parent(dip));

			if ((ddi_root_node() != ddi_get_parent(pdip)) &&
				(ddi_root_node() !=
				ddi_get_parent(ddi_get_parent(pdip)))) {
				if (pcicfg_alarm_card(pdip) == DDI_SUCCESS) {
					if (pcicfg_create_ac_child(dip)
							== DDI_SUCCESS) {
						(void) strcpy(buffer, "ebus");
						rc = DDI_SUCCESS;
					}
				}
			}
			break;
		case 0x108e7777:
			/* ATM device is SUNW,ma */
			(void) strcpy(buffer, "SUNW,ma");
			rc = DDI_SUCCESS;
			break;
		default:
			break;
	}
	return (rc);
}
/*
 * Called from pcicfg_set_childnode_props(), this functions returns
 * the value of FCode "compatible" property for a list of FCode devices
 * that we support currently, whose compatible property is not as per the 1275
 * PCI bindings.
 * Up until the FCode interpreter is available, any special workarounds for a
 * a given node may have to be put here.
 */
/*ARGSUSED*/
static int
pcicfg_fcode_compatible(dev_info_t *dip, ddi_acc_handle_t config_handle,
			char *buffer)
{
	uint16_t sub_vid, sub_sid, vid, did;
	dev_info_t *pdip;
	int rc = DDI_FAILURE;

	vid = pci_config_get16(config_handle, PCI_CONF_VENID),
	did = pci_config_get16(config_handle, PCI_CONF_DEVID);
	sub_vid = pci_config_get16(config_handle, PCI_CONF_SUBVENID),
	sub_sid = pci_config_get16(config_handle, PCI_CONF_SUBSYSID);

	/*
	 * If the driver binding is based on subsystem vendor id and
	 * subsystem Id via the 'compatible' property, then place the
	 * binding entry here and set rc=DDI_SUCCESS so that we do
	 * not proceed to the next switch loop.
	 */
	switch (sub_sid | (sub_vid << 16)) {
		default:
			break;
	}
	if (rc == DDI_SUCCESS)
		return (rc);

	/*
	 * If we got here, then the driver binding is based on vendor id and
	 * device Id via the 'compatible' property. So place the
	 * binding entry here and set rc=DDI_SUCCESS.
	 */
	switch (did | (vid << 16)) {
		case 0x108e1000:
			pdip = ddi_get_parent(ddi_get_parent(dip));

			if ((ddi_root_node() != ddi_get_parent(pdip)) &&
				(ddi_root_node() !=
				ddi_get_parent(ddi_get_parent(pdip)))) {
				if (pcicfg_alarm_card(pdip) == DDI_SUCCESS) {
					(void) strcpy(buffer, "acebus");
					rc = DDI_SUCCESS;
				}
			}
			break;
		default:
			break;
	}
	return (rc);
}

static int
pcicfg_alarm_card(dev_info_t *dip)
{
	uint16_t sub_vid, sub_sid;
	int rc = DDI_FAILURE;
	ddi_acc_handle_t config_handle;

	if (pci_config_setup(dip, &config_handle) != DDI_SUCCESS)
		return (DDI_FAILURE);
	sub_vid = pci_config_get16(config_handle, PCI_CONF_SUBVENID),
	sub_sid = pci_config_get16(config_handle, PCI_CONF_SUBSYSID);
	if ((sub_vid == 0x108e) && (sub_sid == 0x6722))
		rc = DDI_SUCCESS;
	pci_config_teardown(&config_handle);
	return (rc);
}

static int
pcicfg_create_ac_child(dev_info_t *dip)
{
	dev_info_t	*cdip;
	char		*compat[1];

	ndi_devi_alloc_sleep(dip, "se", (dnode_t)DEVI_SID_NODEID, &cdip);
	compat[0] = kmem_alloc(strlen("acse") + 1, KM_SLEEP);
	(void) strcpy(compat[0], "acse");
	if (ndi_prop_update_string_array(DDI_DEV_T_NONE, cdip,
		"compatible", (char **)compat, 1) != DDI_SUCCESS) {

		DEBUG0("pcicfg: Failed to set ac child compatibles\n");
		(void) ndi_devi_free(cdip);
		return (DDI_FAILURE);
	}
	kmem_free(compat[0], strlen("acse") + 1);
	(void) i_ndi_config_node(cdip, DS_LINKED, 0);
	return (DDI_SUCCESS);
}
#endif /* _EFCODE_WORKAROUND */
