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
/*
 * Copyright (c)  * Copyright (c) 2001 Tadpole Technology plc
 * All rights reserved.
 * From "@(#)pcicfg.c   1.31    99/06/18 SMI"
 */

/*
 * Copyright 2023 Oxide Computer Company
 */

/*
 * Cardbus configurator
 */

#include <sys/ddi.h>
#include <sys/sunndi.h>
#include <sys/ndi_impldefs.h>

#include <sys/pci.h>
#include <sys/ebus.h>
#include <sys/hotplug/hpctrl.h>
#include <sys/hotplug/pci/pcicfg.h>

#include <sys/pctypes.h>
#include <sys/pcmcia.h>
#include <sys/sservice.h>

#include <sys/isa_defs.h>

#include <sys/note.h>

#include <sys/ethernet.h>

#include "cardbus.h"
#include "cardbus_parse.h"
#include "cardbus_cfg.h"

/*
 * ************************************************************************
 * *** Implementation specific local data structures/definitions.       ***
 * ************************************************************************
 */

#define	PCICFG_MAX_DEVICE 32
#define	PCICFG_MAX_FUNCTION 8

static uint32_t pcicfg_max_device = PCICFG_MAX_DEVICE;
static uint32_t pcicfg_max_function = PCICFG_MAX_FUNCTION;

#define	PCICFG_NODEVICE 42
#define	PCICFG_NOMEMORY 43
#define	PCICFG_NOMULTI  44

#define	PCICFG_HIADDR(n) ((uint32_t)(((uint64_t)(n) & 0xFFFFFFFF00000000)>> 32))
#define	PCICFG_LOADDR(n) ((uint32_t)((uint64_t)(n) & 0x00000000FFFFFFFF))
#define	PCICFG_LADDR(lo, hi)    (((uint64_t)(hi) << 32) | (uint32_t)(lo))

#define	PCICFG_HIWORD(n) ((uint16_t)(((uint32_t)(n) & 0xFFFF0000)>> 16))
#define	PCICFG_LOWORD(n) ((uint16_t)((uint32_t)(n) & 0x0000FFFF))
#define	PCICFG_HIBYTE(n) ((uint8_t)(((uint16_t)(n) & 0xFF00)>> 8))
#define	PCICFG_LOBYTE(n) ((uint8_t)((uint16_t)(n) & 0x00FF))

#define	PCICFG_ROUND_UP(addr, gran) ((uintptr_t)((gran+addr-1)&(~(gran-1))))
#define	PCICFG_ROUND_DOWN(addr, gran) ((uintptr_t)((addr) & ~(gran-1)))

#define	PCICFG_MEMGRAN 0x100000
#define	PCICFG_IOGRAN 0x1000
#define	PCICFG_4GIG_LIMIT 0xFFFFFFFFUL
#define	CBCFG_MEMGRAN 0x1000
#define	CBCFG_IOGRAN 0x4

#define	PCICFG_MEM_MULT 4
#define	PCICFG_IO_MULT 4
#define	PCICFG_RANGE_LEN 2 /* Number of range entries */

/*
 * ISA node declaration structure.
 */
struct isa_node {
	char	*name;
	char	*compatible[5];
	char	*type;
	char	*model;
	uint16_t	reg;
	uint16_t	span;
};

struct cardbus_name_entry {
	uint32_t class_code;
	char  *name;
	int pil;
};

struct cardbus_find_ctrl {
	uint_t		bus;
	uint_t		device;
	uint_t		function;
	dev_info_t	*dip;
};

#define	PCICFG_MAKE_REG_HIGH(busnum, devnum, funcnum, register)\
	(\
	((ulong_t)(busnum & 0xff) << 16)    |\
	((ulong_t)(devnum & 0x1f) << 11)    |\
	((ulong_t)(funcnum & 0x7) <<  8)    |\
	((ulong_t)(register & 0x3f)))

typedef struct cardbus_phdl cardbus_phdl_t;

struct cardbus_phdl {

	dev_info_t	*dip;	/* Associated with the attach point */
	dev_info_t	*res_dip; /* dip from which io/mem is allocated */
	cardbus_phdl_t  *next;

	uint64_t	memory_base;    /* Memory base for this attach point */
	uint64_t	memory_last;
	uint64_t	memory_len;
	uint32_t	memory_gran;
	uint32_t	io_base;	/* I/O base for this attach point */
	uint32_t	io_last;
	uint32_t	io_len;
	uint32_t	io_gran;

	int	error;
	uint_t	highest_bus;    /* Highest bus seen on the probe */
	ndi_ra_request_t mem_req;	/* allocator request for memory */
	ndi_ra_request_t io_req;	/* allocator request for I/O */
};

typedef struct {
	dev_info_t  *dip;	/* Associated with the attach point */
	ddi_acc_handle_t handle;    /* open handle on parent PCI config space */
	uint32_t    io_base;	/* I/O base for this attach point */
	int	io_decode_reg;
} isa_phdl_t;


/*
 * forward declarations for routines defined in this module (called here)
 */
static cardbus_phdl_t *cardbus_find_phdl(dev_info_t *dip);
static cardbus_phdl_t *cardbus_create_phdl(dev_info_t *dip);
static int cardbus_destroy_phdl(dev_info_t *dip);
static int cardbus_program_ap(dev_info_t *);
static void cardbus_topbridge_assign(dev_info_t *, cardbus_phdl_t *);
static int cardbus_bridge_ranges(dev_info_t *, cardbus_phdl_t *,
			ddi_acc_handle_t);
static int cardbus_bridge_assign(dev_info_t *, void *);
static int cardbus_isa_bridge_ranges(dev_info_t *dip, cardbus_phdl_t *entry,
			ddi_acc_handle_t handle);
static int cardbus_add_isa_reg(dev_info_t *, void *);
static int cardbus_allocate_chunk(dev_info_t *, uint8_t, uint8_t);
static int cardbus_free_chunk(dev_info_t *);
static void cardbus_setup_bridge(dev_info_t *, cardbus_phdl_t *,
			ddi_acc_handle_t);
static void cardbus_update_bridge(dev_info_t *, cardbus_phdl_t *,
			ddi_acc_handle_t);
static void cardbus_get_mem(dev_info_t *, cardbus_phdl_t *, uint32_t,
			uint64_t *);
static void cardbus_get_io(dev_info_t *, cardbus_phdl_t *, uint32_t,
			uint32_t *);
static int cardbus_sum_resources(dev_info_t *, void *);
static int cardbus_free_bridge_resources(dev_info_t *);
static int cardbus_free_device_resources(dev_info_t *);
static int cardbus_free_resources(dev_info_t *);
static int cardbus_probe_bridge(cbus_t *, dev_info_t *, uint_t,
			uint_t, uint_t);
static int cardbus_probe_children(cbus_t *, dev_info_t *, uint_t, uint_t,
			uint_t, uint8_t *);
static int cardbus_add_config_reg(dev_info_t *, uint_t, uint_t, uint_t);
static int cardbus_add_isa_node(cbus_t *, dev_info_t *, struct isa_node *);
static int cardbus_config_setup(dev_info_t *, ddi_acc_handle_t *);
static void cardbus_config_teardown(ddi_acc_handle_t *);
static void cardbus_reparent_children(dev_info_t *, dev_info_t *);
static int cardbus_update_assigned_prop(dev_info_t *, pci_regspec_t *);
static int cardbus_update_available_prop(dev_info_t *, uint32_t,
			uint64_t, uint64_t);
static int cardbus_update_ranges_prop(dev_info_t *, cardbus_range_t *);
static int cardbus_update_reg_prop(dev_info_t *dip, uint32_t regvalue,
			uint_t reg_offset);
static int cardbus_set_standard_props(dev_info_t *parent, dev_info_t *dip,
			ddi_acc_handle_t config_handle);
static int cardbus_set_isa_props(dev_info_t *parent, dev_info_t *dip,
			char *name, char *compat[]);
static int cardbus_set_busnode_props(dev_info_t *);
static int cardbus_set_busnode_isaprops(dev_info_t *);
static int cardbus_set_childnode_props(dev_info_t *dip,
			ddi_acc_handle_t config_handle);
static void cardbus_set_bus_numbers(ddi_acc_handle_t config_handle,
			uint_t primary, uint_t secondary);
static void enable_pci_isa_bridge(dev_info_t *dip,
			ddi_acc_handle_t config_handle);
static void enable_pci_pci_bridge(dev_info_t *dip,
			ddi_acc_handle_t config_handle);
static void enable_cardbus_bridge(dev_info_t *dip,
			ddi_acc_handle_t config_handle);
static void disable_pci_pci_bridge(dev_info_t *dip,
			ddi_acc_handle_t config_handle);
static void disable_cardbus_bridge(dev_info_t *dip,
			ddi_acc_handle_t config_handle);
static void enable_cardbus_device(dev_info_t *, ddi_acc_handle_t);
static void disable_cardbus_device(ddi_acc_handle_t config_handle);
static void cardbus_force_boolprop(dev_info_t *dip, char *pname);
static void cardbus_force_intprop(dev_info_t *dip, char *pname,
			int *pval, int len);
static void cardbus_force_stringprop(dev_info_t *dip, char *pname,
			char *pval);
static void split_addr(char *, int *, int *);
#ifdef DEBUG
static void cardbus_dump_common_config(ddi_acc_handle_t config_handle);
static void cardbus_dump_device_config(ddi_acc_handle_t config_handle);
static void cardbus_dump_bridge_config(ddi_acc_handle_t config_handle,
			uint8_t header_type);
static void cardbus_dump_config(ddi_acc_handle_t config_handle);
static void cardbus_dump_reg(dev_info_t *dip, const pci_regspec_t *regspec,
			int nelems);
#endif

static cardbus_phdl_t *cardbus_phdl_list = NULL;

static struct cardbus_name_entry cardbus_class_lookup [] = {
	{ 0x001, "display", 9 },
	{ 0x100, "scsi", 4 },
	{ 0x101, "ide", 4 },
	{ 0x102, "fdc", 4 },
	{ 0x103, "ipi", 4 },
	{ 0x104, "raid", 4 },
	{ 0x200, "ethernet", 6 },
	{ 0x201, "token-ring", 6 },
	{ 0x202, "fddi", 6 },
	{ 0x203, "atm", 6 },
	{ 0x300, "display", 9 },    /* VGA card */
	{ 0x380, "display", 9 },    /* other - for the Raptor Card */
	{ 0x400, "video", 11 },
	{ 0x401, "sound", 11 },
	{ 0x500, "memory", 11 },
	{ 0x501, "flash", 11 },
	{ 0x600, "host", 11 },
	{ 0x601, "isa", 11 },
	{ 0x602, "eisa", 11 },
	{ 0x603, "mca", 11 },
	{ 0x604, "pci", 11 },
	{ 0x605, "pcmcia", 11 },
	{ 0x606, "nubus", 11 },
	{ 0x607, "cardbus", 11 },
	{ 0x680, NULL, 8 },
	{ 0x700, "serial", 11 },
	{ 0x701, "parallel", 6 },
	{ 0x800, "interrupt-controller", 3 },
	{ 0x801, "dma-controller", 3 },
	{ 0x802, "timer", 3 },
	{ 0x803, "rtc", 3 },
	{ 0x900, "keyboard", 8 },
	{ 0x901, "pen", 8 },
	{ 0x902, "mouse", 8 },
	{ 0xa00, "dock", 1 },
	{ 0xb00, "cpu", 1 },
	{ 0xc00, "firewire", 9 },
	{ 0xc01, "access-bus", 4 },
	{ 0xc02, "ssa", 4 },
	{ 0xc03, "usb", 9 },
	{ 0xc04, "fibre-channel", 6 },
	{ 0, 0 }
};

#ifndef _DONT_USE_1275_GENERIC_NAMES
static char *cardbus_get_class_name(uint32_t classcode);
#endif /* _DONT_USE_1275_GENERIC_NAMES */

/*
 * Reprogram ILINE with default value only if BIOS doesn't program it
 */
int
cardbus_validate_iline(dev_info_t *dip, ddi_acc_handle_t handle)
{
	uint8_t intline = 0xff;

	if (pci_config_get8(handle, PCI_CONF_IPIN)) {
	intline = pci_config_get8(handle, PCI_CONF_ILINE);
	if ((intline == 0) || (intline == 0xff)) {
		intline = ddi_getprop(DDI_DEV_T_ANY, dip,
			DDI_PROP_CANSLEEP|DDI_PROP_DONTPASS,
			"interrupt-line", 0xff);
		if (intline == (uint8_t)0xff) {
			intline = ddi_getprop(DDI_DEV_T_ANY,
				ddi_get_parent(dip),
				DDI_PROP_CANSLEEP /* |DDI_PROP_DONTPASS */,
				"interrupt-line", 0xb);
		}

		pci_config_put8(handle, PCI_CONF_ILINE, intline);
	}
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
		"interrupt-line", intline);
	}
	return (intline);
}

/*
 * This entry point is called to configure a device (and
 * all its children) on the given bus. It is called when
 * a new device is added to the PCI domain.  This routine
 * will create the device tree and program the devices
 * registers.
 */
int
cardbus_configure(cbus_t *cbp)
{
	uint_t bus;
	int cardbus_dev, func;
	dev_info_t *attach_point;

	cardbus_err(cbp->cb_dip, 6, "cardbus_configure ()\n");

	bus = cardbus_primary_busno(cbp->cb_dip);

	if (ndi_devi_alloc(cbp->cb_dip, DEVI_PSEUDO_NEXNAME,
	    (pnode_t)DEVI_SID_NODEID,
	    &attach_point) != NDI_SUCCESS) {
		cardbus_err(cbp->cb_dip, 1,
		    "cardbus_configure(): Failed to alloc probe node\n");
		return (PCICFG_FAILURE);
	}

	/*
	 * Node name marks this node as the "attachment point".
	 */
	if (ndi_devi_set_nodename(attach_point,
	    "hp_attachment", 0) != NDI_SUCCESS) {
	    cardbus_err(cbp->cb_dip, 1,
		    "Failed to set nodename for attachment node\n");
		(void) ndi_devi_free(attach_point);
		return (PCICFG_FAILURE);
	}

	cardbus_err(ddi_get_parent(attach_point), 8,
	    "Set bus type to cardbus\n");
	(void) ddi_prop_update_string(DDI_DEV_T_NONE,
	    ddi_get_parent(attach_point), PCM_DEVICETYPE,
	    "cardbus");

	split_addr(ddi_get_name_addr(cbp->cb_dip), &cardbus_dev, &func);

	cardbus_err(attach_point, 8,
	    "Configuring [0x%x][0x%x][0x%x]\n", bus, cardbus_dev, func);

	switch (cardbus_probe_bridge(cbp, attach_point,
	    bus, cardbus_dev, func)) {
	case PCICFG_FAILURE:
		cardbus_err(cbp->cb_dip, 4,
		    "configure failed: bus [0x%x] slot [0x%x] func [0x%x]\n",
		    bus, cardbus_dev, func);
		goto cleanup;
	case PCICFG_NODEVICE:
		cardbus_err(cbp->cb_dip, 4,
		    "no device: bus [0x%x] slot [0x%x] func [0x%x]\n",
		    bus, cardbus_dev, func);
		goto cleanup;
	default:
		cardbus_err(cbp->cb_dip, 9,
		    "configure: bus => [%d] slot => [%d] func => [%d]\n",
		    bus, cardbus_dev, func);
		break;
	}

	if (cardbus_program_ap(cbp->cb_dip) == PCICFG_SUCCESS) {
		(void) cardbus_reparent_children(attach_point, cbp->cb_dip);
		(void) ndi_devi_free(attach_point);
		cbp->cb_nex_ops->enable_intr(cbp->cb_dip);
		return (PCICFG_SUCCESS);
	}

	cardbus_err(cbp->cb_dip, 1, "Failed to program devices\n");

cleanup:
	/*
	 * Clean up a partially created "probe state" tree.
	 * There are no resources allocated to the in the
	 * probe state.
	 */

	cardbus_err(cbp->cb_dip, 6,
	    "Look up device [0x%x] function [0x%x] to clean up\n",
	    cardbus_dev, func);

	cardbus_err(cbp->cb_dip, 6,
	    "Cleaning up device [0x%x] function [0x%x]\n",
	    cardbus_dev, func);

	/*
	 * If this was a bridge device it will have a
	 * probe handle - if not, no harm in calling this.
	 */
	(void) cardbus_destroy_phdl(cbp->cb_dip);

	if (ddi_get_child(attach_point)) {
		/*
		 * This will free up the node
		 */
		(void) ndi_devi_offline(ddi_get_child(attach_point),
		    NDI_UNCONFIG|NDI_DEVI_REMOVE);
	}
	(void) ndi_devi_free(attach_point);

	return (PCICFG_FAILURE);
}

int
cardbus_unconfigure(cbus_t *cbp)
{
	ddi_acc_handle_t config_handle;
	dev_info_t *dip = cbp->cb_dip;

	cbp->cb_nex_ops->disable_intr(dip);
	if (pci_config_setup(dip, &config_handle) == DDI_SUCCESS) {
		disable_cardbus_bridge(dip, config_handle);
		(void) pci_config_teardown(&config_handle);
	} else {
		cardbus_err(dip, 1,
		    "cardbus_unconfigure(): Failed to setup config space\n");
	}

	(void) cardbus_free_chunk(dip);
	cardbus_err(dip, 6,
	    "cardbus_unconfigure: calling cardbus_free_bridge_resources\n");
	(void) cardbus_free_bridge_resources(dip);

	return (PCICFG_SUCCESS);
}

int
cardbus_teardown_device(dev_info_t *dip)
{
	/*
	 * Free up resources associated with 'dip'
	 */

	if (cardbus_free_resources(dip) != PCICFG_SUCCESS) {
		cardbus_err(dip, 1,
		    "cardbus_teardown_device: Failed to free resources\n");
		return (PCICFG_FAILURE);
	}

	if (ndi_devi_offline(dip, NDI_DEVI_REMOVE) != NDI_SUCCESS) {
		cardbus_err(dip, 1,
		    "cardbus_teardown_device: "
		    "Failed to offline and remove node\n");
		return (PCICFG_FAILURE);
	}

	return (PCICFG_SUCCESS);
}

/*
 * Get the primary pci bus number. This should be the lowest number
 * in the bus-range property of our parent.
 */
int
cardbus_primary_busno(dev_info_t *dip)
{
	int	len, rval;
	char	bus_type[16] = "(unknown)";
	dev_info_t *par = ddi_get_parent(dip);
	cardbus_bus_range_t *bus_range;

	ASSERT(strcmp(ddi_driver_name(dip), "pcic") == 0);
	len = sizeof (bus_type);
	if ((ddi_prop_op(DDI_DEV_T_ANY, par, PROP_LEN_AND_VAL_BUF,
	    DDI_PROP_CANSLEEP | DDI_PROP_DONTPASS,
	    "device_type",
	    (caddr_t)&bus_type, &len) == DDI_SUCCESS)) {
		ASSERT((strcmp(bus_type, "pci") == 0) ||
		    (strcmp(bus_type, "cardbus") == 0));
		if (ddi_getlongprop(DDI_DEV_T_ANY, par, 0, "bus-range",
		    (caddr_t)&bus_range, &len) == DDI_PROP_SUCCESS) {
			cardbus_err(dip, 9,
			    "cardbus_primary_busno: bus range is %d to %d\n",
			    bus_range->lo, bus_range->hi);
			rval = (int)bus_range->lo;
			kmem_free((caddr_t)bus_range, len);
			return (rval);
		}
	}

	cardbus_err(dip, 2,
	    "cardbus_primary_busno: Not a pci device or no bus-range\n");
	return (-1);
}

static cardbus_phdl_t *
cardbus_find_phdl(dev_info_t *dip)
{
	cardbus_phdl_t *entry;

	mutex_enter(&cardbus_list_mutex);
	for (entry = cardbus_phdl_list; entry != NULL; entry = entry->next) {
		if (entry->dip == dip) {
			mutex_exit(&cardbus_list_mutex);
			return (entry);
		}
	}
	mutex_exit(&cardbus_list_mutex);

	/*
	 * Did'nt find entry - create one
	 */
	return (cardbus_create_phdl(dip));
}

static cardbus_phdl_t *
cardbus_create_phdl(dev_info_t *dip)
{
	cardbus_phdl_t *new;

	new = (cardbus_phdl_t *)kmem_zalloc(sizeof (cardbus_phdl_t), KM_SLEEP);

	new->dip = dip;
	new->io_gran = CBCFG_IOGRAN;
	new->memory_gran = CBCFG_MEMGRAN;
	mutex_enter(&cardbus_list_mutex);
	new->next = cardbus_phdl_list;
	cardbus_phdl_list = new;
	mutex_exit(&cardbus_list_mutex);

	return (new);
}

static int
cardbus_destroy_phdl(dev_info_t *dip)
{
	cardbus_phdl_t *entry;
	cardbus_phdl_t *follow = NULL;
	ra_return_t	res;

	mutex_enter(&cardbus_list_mutex);
	for (entry = cardbus_phdl_list; entry != NULL; follow = entry,
	    entry = entry->next) {
		if (entry->dip == dip) {
			if (entry == cardbus_phdl_list) {
				cardbus_phdl_list = entry->next;
			} else {
				follow->next = entry->next;
			}
			/*
			 * If this entry has any allocated memory
			 * or IO space associated with it, that
			 * must be freed up.
			 */
			if (entry->memory_len > 0) {
				res.ra_addr_lo = entry->memory_base;
				res.ra_len = entry->memory_len;
				(void) pcmcia_free_mem(entry->res_dip, &res);
#ifdef  _LP64
				cardbus_err(dip, 8,
				    "cardbus_destroy_phdl: "
				    "MEMORY BASE = [0x%lx] length [0x%lx]\n",
				    entry->memory_base, entry->memory_len);
#else
				cardbus_err(dip, 8,
				    "cardbus_destroy_phdl: "
				    "MEMORY BASE = [0x%llx] length [0x%llx]\n",
				    entry->memory_base, entry->memory_len);
#endif
			}
			if (entry->io_len > 0) {
				res.ra_addr_lo = entry->io_base;
				res.ra_len = entry->io_len;
				(void) pcmcia_free_io(entry->res_dip, &res);
				cardbus_err(dip, 8,
				    "cardbus_destroy_phdl: "
				    "IO BASE = [0x%x] length [0x%x]\n",
				    entry->io_base, entry->io_len);
			}
			/*
			 * Destroy this entry
			 */
			kmem_free((caddr_t)entry, sizeof (cardbus_phdl_t));
			mutex_exit(&cardbus_list_mutex);
			return (PCICFG_SUCCESS);
		}
	}

	mutex_exit(&cardbus_list_mutex);

	/*
	 * Didn't find the entry
	 */
	return (PCICFG_FAILURE);
}

static int
cardbus_program_ap(dev_info_t *dip)
{
	cardbus_phdl_t *phdl;
	uint8_t header_type, sec_bus;
	ddi_acc_handle_t handle;

	if (pci_config_setup(dip, &handle) != DDI_SUCCESS) {
		cardbus_err(dip, 1,
		    "cardbus_program_ap: Failed to map config space!\n");
		return (PCICFG_FAILURE);
	}

	header_type = pci_config_get8(handle, PCI_CONF_HEADER);
	sec_bus = pci_config_get8(handle, PCI_BCNF_SECBUS);

	cardbus_err(dip, 6,
	    "cardbus_program_ap (header_type=0x%x)\n", header_type);
	(void) pci_config_teardown(&handle);

	/*
	 * Header type two is PCI to Cardbus bridge, see page 43 of the
	 * CL-PD6832 data sheet
	 */
	switch (header_type & PCI_HEADER_TYPE_M) {
	case PCI_HEADER_CARDBUS:
		cardbus_err(dip, 8,
		    "cardbus_program_ap calling cardbus_allocate_chunk\n");
		if (cardbus_allocate_chunk(dip,
		    header_type & PCI_HEADER_TYPE_M,
		    sec_bus) != PCICFG_SUCCESS) {
			cardbus_err(dip, 1,
			    "cardbus_program_ap: "
			    "Not enough memory to hotplug\n");
			(void) cardbus_destroy_phdl(dip);
			return (PCICFG_FAILURE);
		}

		cardbus_err(dip, 8,
		    "cardbus_program_ap calling cardbus_find_phdl\n");
		phdl = cardbus_find_phdl(dip);
		ASSERT(phdl);

		if (phdl == NULL) {
			cardbus_err(dip, 1, "cardbus_find_phdl failed\n");
			return (PCICFG_FAILURE);
		}
		phdl->error = PCICFG_SUCCESS;
		cardbus_err(dip, 8,
		    "cardbus_program_ap calling cardbus_topbridge_assign\n");
		cardbus_topbridge_assign(dip, phdl);

		if (phdl->error != PCICFG_SUCCESS) {
			cardbus_err(dip, 1, "Problem assigning bridge\n");
			(void) cardbus_destroy_phdl(dip);
			return (phdl->error);
		}
		break;

	default:
		return (PCICFG_FAILURE);
	}

	return (PCICFG_SUCCESS);
}

static void
cardbus_topbridge_assign(dev_info_t *dip, cardbus_phdl_t *entry)
{
	ddi_acc_handle_t handle;
	uint8_t header_type;

	cardbus_err(dip, 6, "cardbus_topbridge_assign\n");

	if (pci_config_setup(dip, &handle) != DDI_SUCCESS) {
		cardbus_err(dip, 1,
		    "cardbus_topbridge_bridge_assign: "
		    "Failed to map config space!\n");
		return;
	}

	header_type = pci_config_get8(handle,
	    PCI_CONF_HEADER) & PCI_HEADER_TYPE_M;

	/* cardbus bridge is the same as PCI-PCI bridge */
	ASSERT((header_type == PCI_HEADER_PPB) ||
	    (header_type == PCI_HEADER_CARDBUS));

	(void) cardbus_bridge_ranges(dip, entry, handle);

	(void) pci_config_teardown(&handle);
}

static int
cardbus_bridge_ranges(dev_info_t *dip, cardbus_phdl_t *entry,
			ddi_acc_handle_t handle)
{
	cardbus_range_t range[PCICFG_RANGE_LEN];
	int bus_range[2];
	int i;

	cardbus_err(dip, 8, "cardbus_bridge_ranges\n");

	bzero((caddr_t)range, sizeof (cardbus_range_t) * PCICFG_RANGE_LEN);

	(void) cardbus_setup_bridge(dip, entry, handle);

	range[0].child_hi = range[0].parent_hi |= (PCI_REG_REL_M | PCI_ADDR_IO);
	range[0].child_lo = range[0].parent_lo = entry->io_last;
	range[1].child_hi = range[1].parent_hi |= (PCI_REG_REL_M |
						PCI_ADDR_MEM32);
	range[1].child_lo = range[1].parent_lo = entry->memory_last;

	ndi_devi_enter(dip);
	ddi_walk_devs(ddi_get_child(dip), cardbus_bridge_assign, (void *)entry);
	ndi_devi_exit(dip);

	(void) cardbus_update_bridge(dip, entry, handle);

	bus_range[0] = pci_config_get8(handle, PCI_BCNF_SECBUS);
	bus_range[1] = pci_config_get8(handle, PCI_BCNF_SUBBUS);

	cardbus_err(dip, 8,
	    "Set up bus-range property to %u->%u\n",
	    bus_range[0], bus_range[1]);

	if ((i = ndi_prop_update_int_array(DDI_DEV_T_NONE, dip,
	    "bus-range",
	    bus_range, 2)) != DDI_SUCCESS) {

		if (i == DDI_PROP_NOT_FOUND) {
			cardbus_err(dip, 8,
			    "Create bus-range property, %u->%u\n",
			    bus_range[0], bus_range[1]);
			i = ddi_prop_create(DDI_DEV_T_NONE, dip,
			    DDI_PROP_CANSLEEP,
			    "bus-range", (caddr_t)bus_range,
			    sizeof (bus_range));
		}

		if (i != DDI_PROP_SUCCESS) {
			cardbus_err(dip, 1,
			    "Failed to set bus-range property, %u->%u (%d)\n",
			    bus_range[0], bus_range[1], i);
			entry->error = PCICFG_FAILURE;
			return (DDI_WALK_TERMINATE);
		}
	}

	if (entry->io_len > 0) {
		range[0].size_lo = entry->io_last - entry->io_base;
		if (cardbus_update_ranges_prop(dip, &range[0])) {
			cardbus_err(dip, 1, "Failed to update ranges (i/o)\n");
			entry->error = PCICFG_FAILURE;
			return (DDI_WALK_TERMINATE);
		}
	}
	if (entry->memory_len > 0) {
		range[1].size_lo = entry->memory_last - entry->memory_base;
		if (cardbus_update_ranges_prop(dip, &range[1])) {
			cardbus_err(dip, 1,
			    "Failed to update ranges (memory)\n");
			entry->error = PCICFG_FAILURE;
			return (DDI_WALK_TERMINATE);
		}
	}

	return (DDI_WALK_PRUNECHILD);
}
static int
cardbus_bridge_assign(dev_info_t *dip, void *hdl)
{
	ddi_acc_handle_t handle;
	pci_regspec_t *reg;
	int length;
	int rcount;
	int i;
	int offset;
	uint64_t mem_answer;
	uint32_t io_answer, request;
	uint8_t header_type, base_class;
	cardbus_phdl_t *entry = (cardbus_phdl_t *)hdl;

	/*
	 * Ignore the attachment point and pcs.
	 */
	if (strcmp(ddi_binding_name(dip), "hp_attachment") == 0 ||
	    strcmp(ddi_binding_name(dip), "pcs") == 0) {
		cardbus_err(dip, 8, "cardbus_bridge_assign: Ignoring\n");
		return (DDI_WALK_CONTINUE);
	}


	cardbus_err(dip, 6, "cardbus_bridge_assign\n");

	if (entry == NULL) {
		cardbus_err(dip, 1, "Failed to get entry\n");
		return (DDI_WALK_TERMINATE);
	}
	if (cardbus_config_setup(dip, &handle) != DDI_SUCCESS) {
		cardbus_err(dip, 1,
		    "cardbus_bridge_assign: Failed to map config space!\n");
		entry->error = PCICFG_FAILURE;
		return (DDI_WALK_TERMINATE);
	}

	header_type = pci_config_get8(handle, PCI_CONF_HEADER) &
		PCI_HEADER_TYPE_M;
	base_class = pci_config_get8(handle, PCI_CONF_BASCLASS);

	/*
	 * This function is not called for the top bridge and we are
	 * not enumerating down a further cardbus interface yet!
	 */
	if (base_class == PCI_CLASS_BRIDGE) {
		uint8_t	sub_class;

		sub_class = pci_config_get8(handle, PCI_CONF_SUBCLASS);

		switch (sub_class) {
		case PCI_BRIDGE_PCI:
			if (header_type == PCI_HEADER_PPB) {
				i = cardbus_bridge_ranges(dip, entry, handle);
				(void) cardbus_config_teardown(&handle);
				return (i);
			}
			goto bad_device;

		case PCI_BRIDGE_ISA:
			i = cardbus_isa_bridge_ranges(dip, entry, handle);
			(void) cardbus_config_teardown(&handle);
			return (i);

		case PCI_BRIDGE_CARDBUS:
			/*
			 * Fall through, there should be at least one register
			 * set for this.
			 */
			break;

		case PCI_BRIDGE_OTHER:
		default:
			break;
		}
	}

#ifdef sparc
	/*
	 * If there is an interrupt pin set program
	 * interrupt line with default values.
	 */
	if (pci_config_get8(handle, PCI_CONF_IPIN)) {
	    pci_config_put8(handle, PCI_CONF_ILINE, 0xf);
	}
#else
	(void) cardbus_validate_iline(dip, handle);
#endif

	/*
	 * A single device (under a bridge).
	 * For each "reg" property with a length, allocate memory
	 * and program the base registers.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "reg", (caddr_t)&reg,
	    &length) != DDI_PROP_SUCCESS) {
		cardbus_err(dip, 1, "Failed to read reg property\n");
		entry->error = PCICFG_FAILURE;
		(void) cardbus_config_teardown(&handle);
		return (DDI_WALK_TERMINATE);
	}

	rcount = length / sizeof (pci_regspec_t);
	cardbus_err(dip, 9, "rcount = %d\n", rcount);

	for (i = 0; i < rcount; i++) {
		if ((reg[i].pci_size_low != 0) || (reg[i].pci_size_hi != 0)) {
			offset = PCI_REG_REG_G(reg[i].pci_phys_hi);
			switch (PCI_REG_ADDR_G(reg[i].pci_phys_hi)) {
			case PCI_REG_ADDR_G(PCI_ADDR_MEM64):

				(void) cardbus_get_mem(ddi_get_parent(dip),
				    entry, reg[i].pci_size_low, &mem_answer);
				ASSERT(!PCICFG_HIADDR(mem_answer));
				pci_config_put32(handle, offset,
				    PCICFG_LOADDR(mem_answer));
				pci_config_put32(handle, offset + 4,
				    PCICFG_HIADDR(mem_answer));
				cardbus_err(dip, 8,
				    "REGISTER (64)LO [0x%x] ----> [0x%02x]\n",
				    pci_config_get32(handle, offset), offset);
				cardbus_err(dip, 8,
				    "REGISTER (64)HI [0x%x] ----> [0x%02x]\n",
				    pci_config_get32(handle, offset+4),
					offset+4);
				reg[i].pci_phys_low = PCICFG_HIADDR(mem_answer);
				reg[i].pci_phys_mid = PCICFG_LOADDR(mem_answer);
				break;

			case PCI_REG_ADDR_G(PCI_ADDR_MEM32):
				/* allocate memory space from the allocator */

				(void) cardbus_get_mem(ddi_get_parent(dip),
				    entry, reg[i].pci_size_low, &mem_answer);
				pci_config_put32(handle, offset, 0xffffffff);
				request = pci_config_get32(handle, offset);

				pci_config_put32(handle, offset,
				    (uint32_t)mem_answer);
				reg[i].pci_phys_low = (uint32_t)mem_answer;
				reg[i].pci_phys_mid = 0;
				if (((PCI_BASE_TYPE_M & request) ==
					PCI_BASE_TYPE_ALL) &&
				    ((PCI_BASE_SPACE_M & request) ==
					PCI_BASE_SPACE_MEM)) {
					cardbus_err(dip, 8,
					    "REGISTER (64)LO [0x%x] ----> "
					    "[0x%02x]\n",
					    pci_config_get32(handle, offset),
						offset);
					    pci_config_put32(handle,
						offset + 4, 0);
					cardbus_err(dip, 8,
					    "REGISTER (64)HI [0x%x] ----> "
					    "[0x%02x]\n",
					    pci_config_get32(handle, offset+4),
						offset+4);
				} else {
					cardbus_err(dip, 8,
					    "REGISTER (32)LO [0x%x] ----> "
					    "[0x%02x]\n",
					    pci_config_get32(handle, offset),
					    offset);
				}
				break;

			case PCI_REG_ADDR_G(PCI_ADDR_IO):
				/* allocate I/O space from the allocator */

				(void) cardbus_get_io(ddi_get_parent(dip),
				    entry, reg[i].pci_size_low, &io_answer);
				pci_config_put32(handle, offset, io_answer);
				cardbus_err(dip, 8,
				    "REGISTER (I/O)LO [0x%x] ----> [0x%02x]\n",
				    pci_config_get32(handle, offset), offset);
				reg[i].pci_phys_low = io_answer;
				break;

			default:
				cardbus_err(dip, 1, "Unknown register type\n");
				kmem_free(reg, length);
				(void) cardbus_config_teardown(&handle);
				entry->error = PCICFG_FAILURE;
				return (DDI_WALK_TERMINATE);
			} /* switch */

			/*
			 * Now that memory locations are assigned,
			 * update the assigned address property.
			 */
			if (cardbus_update_assigned_prop(dip,
			    &reg[i]) != PCICFG_SUCCESS) {
				kmem_free(reg, length);
				(void) cardbus_config_teardown(&handle);
				entry->error = PCICFG_FAILURE;
				return (DDI_WALK_TERMINATE);
			}
		}
	}
	kmem_free(reg, length);
	enable_cardbus_device(dip, handle);
#ifdef CARDBUS_DEBUG
	if (cardbus_debug >= 9) {
		cardbus_dump_config(handle);
	}
#endif
bad_device:
	(void) cardbus_config_teardown(&handle);
	return (DDI_WALK_CONTINUE);
}

static int
cardbus_isa_bridge_ranges(dev_info_t *dip, cardbus_phdl_t *entry,
			ddi_acc_handle_t handle)
{
	struct ebus_pci_rangespec range;
	pci_regspec_t *reg;
	int length;
	int rcount;
	uint32_t io_answer = 0xffffffff;
	isa_phdl_t isa_phdl;
	int i;

	cardbus_err(dip, 8, "cardbus_isa_bridge_ranges\n");

	bzero((caddr_t)&range, sizeof (range));

#ifdef sparc
	/*
	 * If there is an interrupt pin set program
	 * interrupt line with default values.
	 */
	if (pci_config_get8(handle, PCI_CONF_IPIN)) {
	    pci_config_put8(handle, PCI_CONF_ILINE, 0xf);
	}
#else
	(void) cardbus_validate_iline(dip, handle);
#endif

	/*
	 * For each "reg" property with a length, allocate memory.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "reg", (caddr_t)&reg,
	    &length) != DDI_PROP_SUCCESS) {
		cardbus_err(dip, 1, "Failed to read reg property\n");
		entry->error = PCICFG_FAILURE;
		return (DDI_WALK_TERMINATE);
	}

	rcount = length / sizeof (pci_regspec_t);

	for (i = 0; i < rcount; i++) {
		if ((reg[i].pci_size_low != 0) || (reg[i].pci_size_hi != 0)) {
			switch (PCI_REG_ADDR_G(reg[i].pci_phys_hi)) {
			case PCI_REG_ADDR_G(PCI_ADDR_IO):
				/* allocate I/O space from the allocator */

				(void) cardbus_get_io(ddi_get_parent(dip),
				    entry, reg[i].pci_size_low, &io_answer);
				cardbus_err(dip, 8,
				    "ISA (I/O)LO ----> [0x%x]\n", io_answer);
				reg[i].pci_phys_low = io_answer;
				range.phys_hi = 0;
				range.phys_low = io_answer;
				range.par_phys_hi = reg[i].pci_phys_hi |
						PCI_REG_REL_M;
				range.par_phys_low = reg[i].pci_phys_low;
				range.par_phys_mid = reg[i].pci_phys_mid;
				range.rng_size = reg[i].pci_size_low;
				i = rcount;
				break;

			default:
				cardbus_err(dip, 1, "Unknown register type\n");
				kmem_free(reg, length);
				(void) cardbus_config_teardown(&handle);
				entry->error = PCICFG_FAILURE;
				return (DDI_WALK_TERMINATE);
			} /* switch */
		}
	}
	kmem_free(reg, length);

	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE,
	    dip, "ranges", (int *)&range,
	    sizeof (range)/sizeof (int));
	if (io_answer != 0xffffffff) {
		isa_phdl.dip = dip;
		isa_phdl.handle = handle;
		isa_phdl.io_base = io_answer;
		isa_phdl.io_decode_reg = 0x58; /* Pos decoded IO space 0 reg */
		/* i_ndi_block_device_tree_changes(&count); */
		ndi_devi_enter(dip);
		ddi_walk_devs(ddi_get_child(dip),
			cardbus_add_isa_reg, (void *)&isa_phdl);
		/* i_ndi_allow_device_tree_changes(count); */
		ndi_devi_exit(dip);
	}
	return (DDI_WALK_PRUNECHILD);
}

/*
 * This is specific to ITE8888 chip.
 */
static int
cardbus_add_isa_reg(dev_info_t *dip, void *arg)
{
	uint32_t	io_reg = 0;
	int		length;
	uint32_t	reg[3], *breg;
	isa_phdl_t	*phdl;
	uint8_t		sz;

	phdl = (isa_phdl_t *)arg;
	cardbus_err(dip, 6,
	    "cardbus_add_isa_reg, base 0x%x\n", phdl->io_base);

	if (ddi_getlongprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "basereg", (caddr_t)&breg,
	    &length) != DDI_PROP_SUCCESS) {
		return (DDI_WALK_CONTINUE);
	}

	if ((length / sizeof (reg)) < 1) {
		kmem_free(breg, length);
		return (DDI_WALK_CONTINUE);
	}

	/*
	 * Add the "reg" property.
	 */
	reg[0] = 0;
	reg[1] = breg[1] + phdl->io_base;
	reg[2] = breg[2];

	/*
	 * Generate the postive IO decode register setting.
	 */
	for (sz = 0; sz < 8; sz++)
		if ((1<<sz) >= breg[2]) {
			io_reg = breg[1]
			    | (1uL <<31) /* Enable */
			    | (2uL <<29) /* Medium speed */
			    | (1uL <<28) /* Aliase enable, */
					/* Don't care A[15:10] */
			    | (sz<<24); /* Size code */
			break;
		}

	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip,
	    "reg", (int *)reg, 3);
	(void) ndi_prop_remove(DDI_DEV_T_NONE, dip, "basereg");

	if (io_reg) {
		pci_config_put32(phdl->handle, phdl->io_decode_reg, io_reg);
		cardbus_err(dip, 6,
		    "cardbus_add_isa_reg: I/O decode reg (0x%x) set to 0x%x\n",
		    phdl->io_decode_reg,
		    pci_config_get32(phdl->handle, phdl->io_decode_reg));
		phdl->io_decode_reg += sizeof (io_reg);
	} else
		cardbus_err(dip, 1,
		    "cardbus_add_isa_reg: register size (0x%x) too large\n",
		    breg[2]);
	kmem_free(breg, length);
	return (DDI_WALK_CONTINUE);
}

/*
 * In case we want to ensure that some space is allocated to the
 * device tree below the cardbus bridge.
 * This is only necessary if there is a device that needs to allocate
 * resource below us. This can happen if there is another cardbus/PCMCIA
 * bridge downstream.
 */
static uint32_t cardbus_min_spare_mem = 0;
static uint32_t cardbus_min_spare_io = 0;

/*
 * The "dip" passed to this routine is assumed to be
 * the device at the attachment point. Currently it is
 * assumed to be a bridge.
 */
static int
cardbus_allocate_chunk(dev_info_t *dip, uint8_t type, uint8_t sec_bus)
{
	cardbus_phdl_t		*phdl;
	ndi_ra_request_t	*mem_request;
	ndi_ra_request_t	*io_request;
	ra_return_t		res;

	/*
	 * This should not find an existing entry - so
	 * it will create a new one.
	 */
	phdl = cardbus_find_phdl(dip);
	ASSERT(phdl);

	mem_request = &phdl->mem_req;
	io_request  = &phdl->io_req;

	/*
	 * Set highest_bus here.
	 * Otherwise if we don't find another bridge
	 * this never gets set.
	 */
	phdl->highest_bus = sec_bus;

	/*
	 * From this point in the tree - walk the devices,
	 * The function passed in will read and "sum" up
	 * the memory and I/O requirements and put them in
	 * structure "phdl".
	 */
	phdl->error = PCICFG_SUCCESS;
	ndi_devi_enter(dip);
	ddi_walk_devs(ddi_get_child(dip), cardbus_sum_resources, (void *)phdl);
	ndi_devi_exit(dip);

	if (phdl->error != PCICFG_SUCCESS) {
		cmn_err(CE_WARN, "Failure summing resources\n");
		return (phdl->error);
	}

	/*
	 * Call into the memory allocator with the request.
	 * Record the addresses returned in the phdl
	 */
#ifdef  _LP64
	cardbus_err(dip, 8,
	    "AP requires [0x%lx] bytes of memory space, alligned 0x%x\n",
	    mem_request->ra_len, phdl->memory_gran);
	cardbus_err(dip, 8,
	    "AP requires [0x%lx] bytes of I/O space, alligned 0x%x\n",
	    io_request->ra_len, phdl->io_gran);
#else
	cardbus_err(dip, 8,
	    "AP requires [0x%llx] bytes of memory space, alligned 0x%x\n",
	    mem_request->ra_len, phdl->memory_gran);
	cardbus_err(dip, 8,
	    "AP requires [0x%llx] bytes of I/O space, alligned 0x%x\n",
	    io_request->ra_len, phdl->io_gran);
#endif

	ASSERT(type == PCI_HEADER_CARDBUS);

	mem_request->ra_align_mask = phdl->memory_gran - 1;
	io_request->ra_align_mask = phdl->io_gran - 1;
	phdl->res_dip = (dev_info_t *)-1;

	mem_request->ra_len += cardbus_min_spare_mem;
	if (mem_request->ra_len) {
		mem_request->ra_len = PCICFG_ROUND_UP(
					mem_request->ra_len,
					phdl->memory_gran);
#ifdef _LP64
		cardbus_err(dip, 8,
		    "cardbus_allocate_chunk: ndi_ra_alloc 0x%lx bytes\n",
		    mem_request->ra_len);
#else
		cardbus_err(dip, 8,
		    "cardbus_allocate_chunk: ndi_ra_alloc 0x%llx bytes\n",
		    mem_request->ra_len);
#endif

		if (pcmcia_alloc_mem(dip, mem_request, &res,
		    &phdl->res_dip) != NDI_SUCCESS) {
			cmn_err(CE_WARN, "Failed to allocate memory for %s\n",
				ddi_driver_name(dip));
			return (PCICFG_FAILURE);
		}

		phdl->memory_base = phdl->memory_last = res.ra_addr_lo;
		phdl->memory_len = res.ra_len;
	}

	io_request->ra_len += cardbus_min_spare_io;
	if (io_request->ra_len) {

#if defined(__x86)
		io_request->ra_boundbase = 0x1000;
		io_request->ra_boundlen = 0xefff;
#else
		io_request->ra_boundbase = 0;
		io_request->ra_boundlen = PCICFG_4GIG_LIMIT;
#endif
		io_request->ra_flags |= NDI_RA_ALLOC_BOUNDED;
		io_request->ra_len = PCICFG_ROUND_UP(io_request->ra_len,
				phdl->io_gran);
		io_request->ra_align_mask = max(PCICFG_IOGRAN,
				phdl->io_gran) - 1;

		if (pcmcia_alloc_io(dip, io_request, &res,
		    &phdl->res_dip) != NDI_SUCCESS) {
			cmn_err(CE_WARN, "Failed to allocate I/O space "
				"for %s\n", ddi_driver_name(dip));
			if (mem_request->ra_len) {
				res.ra_addr_lo = phdl->memory_base;
				res.ra_len = phdl->memory_len;
				(void) pcmcia_free_mem(phdl->res_dip, &res);
				phdl->memory_len = phdl->io_len = 0;
			}
			return (PCICFG_FAILURE);
		}

		phdl->io_base = phdl->io_last = (uint32_t)res.ra_addr_lo;
		phdl->io_len  = (uint32_t)res.ra_len;
	}

#ifdef  _LP64
	cardbus_err(dip, 6,
	    "MEMORY BASE = [0x%lx] length [0x%lx]\n",
	    phdl->memory_base, phdl->memory_len);
#else
	cardbus_err(dip, 6,
	    "MEMORY BASE = [0x%llx] length [0x%llx]\n",
	    phdl->memory_base, phdl->memory_len);
#endif
	cardbus_err(dip, 6,
	    "IO BASE = [0x%x] length [0x%x]\n",
	    phdl->io_base, phdl->io_len);

	return (PCICFG_SUCCESS);
}

static int
cardbus_free_chunk(dev_info_t *dip)
{
	uint_t	*bus;
	int	k;

	cardbus_err(dip, 6, "cardbus_free_chunk\n");

	(void) cardbus_destroy_phdl(dip);

	if (ddi_getlongprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "bus-range", (caddr_t)&bus,
	    &k) != DDI_PROP_SUCCESS) {
		cardbus_err(dip, 1,
		    "cardbus_free_chunk: Failed to read bus-range property\n");
		return (PCICFG_FAILURE);
	}

	cardbus_err(dip, 6,
	    "cardbus_free_chunk: Freeing bus [%d] range [%d]\n",
	    bus[0], bus[1] - bus[0] + 1);

	if (ndi_ra_free(dip,
	    (uint64_t)bus[0], (uint64_t)(bus[1] - bus[0] + 1),
	    NDI_RA_TYPE_PCI_BUSNUM, NDI_RA_PASS) != NDI_SUCCESS) {
		cardbus_err(dip, 1,
		    "cardbus_free_chunk: Failed to free bus numbers\n");

		kmem_free(bus, k);
		return (PCICFG_FAILURE);
	}

	kmem_free(bus, k);
	return (PCICFG_SUCCESS);
}

/*
 * Put bridge registers into initial state
 */
static void
cardbus_setup_bridge(dev_info_t *dip, cardbus_phdl_t *entry,
		ddi_acc_handle_t handle)
{
	uint8_t header_type = pci_config_get8(handle, PCI_CONF_HEADER);

#ifdef _LP64
	cardbus_err(NULL, 6,
	    "cardbus_setup_bridge: "
	    "highest bus %d, mem_last 0x%lx, io_last 0x%x\n",
	    entry->highest_bus, entry->memory_last, entry->io_last);
#else
	cardbus_err(NULL, 6,
	    "cardbus_setup_bridge: "
	    "highest bus %d, mem_last 0x%llx, io_last 0x%x\n",
	    entry->highest_bus, entry->memory_last, entry->io_last);
#endif

	if ((header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_PPB) {
		uint32_t uval;

		/*
		 * The highest bus seen during probing is
		 * the max-subordinate bus
		 */
		pci_config_put8(handle, PCI_BCNF_SUBBUS, entry->highest_bus);

		uval = PCICFG_ROUND_UP(entry->memory_last, PCICFG_MEMGRAN);
		if (uval != entry->memory_last) {
#ifdef _LP64
			cardbus_err(dip, 8,
			    "Adding [0x%lx] before bridge (mem)\n",
			    uval - entry->memory_last);
#else
			cardbus_err(dip, 8,
			    "Adding [0x%llx] before bridge (mem)\n",
			    uval - entry->memory_last);
#endif
			(void) cardbus_get_mem(ddi_get_parent(dip), entry,
			    uval - entry->memory_last, NULL);
		}

		/*
		 * Program the memory base register with the
		 * start of the memory range
		 */
#ifdef _LP64
		cardbus_err(NULL, 8,
		    "store 0x%x(0x%lx) in pci bridge memory base register\n",
		    PCICFG_HIWORD(PCICFG_LOADDR(uval)),
		    entry->memory_last);
#else
		cardbus_err(NULL, 8,
		    "store 0x%x(0x%llx) in pci bridge memory base register\n",
		    PCICFG_HIWORD(PCICFG_LOADDR(uval)),
		    entry->memory_last);
#endif
		pci_config_put16(handle, PCI_BCNF_MEM_BASE,
		    PCICFG_HIWORD(PCICFG_LOADDR(uval)));

		uval = PCICFG_ROUND_UP(entry->io_last, PCICFG_IOGRAN);
		if (uval != entry->io_last) {
			cardbus_err(dip, 8,
			    "Adding [0x%x] before bridge (I/O)\n",
			    uval - entry->io_last);
			(void) cardbus_get_io(ddi_get_parent(dip), entry,
			    uval - entry->io_last, NULL);
		}
		cardbus_err(NULL, 8,
		    "store 0x%02x/0x%04x(0x%x) in "
		    "pci bridge I/O hi/low base register\n",
		    PCICFG_HIWORD(PCICFG_LOADDR(uval)),
		    PCICFG_HIBYTE(PCICFG_LOWORD(PCICFG_LOADDR(uval))),
		    entry->io_last);
		/*
		 * Program the I/O base register with the start of the I/O range
		 */
		pci_config_put8(handle, PCI_BCNF_IO_BASE_LOW,
		    PCICFG_HIBYTE(PCICFG_LOWORD(PCICFG_LOADDR(uval))));

		pci_config_put16(handle, PCI_BCNF_IO_BASE_HI,
		    PCICFG_HIWORD(PCICFG_LOADDR(uval)));

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

#ifdef sparc
		/*
		 * If there is an interrupt pin set program
		 * interrupt line with default values.
		 */
		if (pci_config_get8(handle, PCI_CONF_IPIN)) {
		    pci_config_put8(handle, PCI_CONF_ILINE, 0xf);
		}
#else
		(void) cardbus_validate_iline(dip, handle);
#endif


	} else if ((header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_CARDBUS) {

		/*
		 * The highest bus seen during probing is
		 * the max-subordinate bus
		 */
		pci_config_put8(handle, PCI_CBUS_SUB_BUS_NO,
		    entry->highest_bus);

		/*
		 * Program the memory base register with the
		 * start of the memory range
		 */
#ifdef _LP64
		cardbus_err(NULL, 8,
		    "store 0x%x(0x%lx) in "
		    "cardbus memory base register 0, len 0x%lx\n",
		    PCICFG_LOADDR(entry->memory_last), entry->memory_last,
		    entry->memory_len);
#else
		cardbus_err(NULL, 8,
		    "store 0x%x(0x%llx) in "
		    "cardbus memory base register 0, len 0x%llx\n",
		    PCICFG_LOADDR(entry->memory_last), entry->memory_last,
		    entry->memory_len);
#endif

		pci_config_put32(handle, PCI_CBUS_MEM_BASE0,
		    PCICFG_LOADDR(entry->memory_last));

		/*
		 * Program the I/O base register with the start of the I/O range
		 */
		cardbus_err(NULL, 8,
		    "store 0x%x in cb IO base register 0 len 0x%x\n",
		    PCICFG_LOADDR(entry->io_last),
		    entry->io_len);

		pci_config_put32(handle, PCI_CBUS_IO_BASE0,
		    PCICFG_LOADDR(entry->io_last));

		/*
		 * Clear status bits
		 */
		pci_config_put16(handle, PCI_CBUS_SEC_STATUS, 0xffff);

#ifdef sparc
		/*
		 * If there is an interrupt pin set program
		 * interrupt line with default values.
		 */
		if (pci_config_get8(handle, PCI_CONF_IPIN)) {
		    pci_config_put8(handle, PCI_CONF_ILINE, 0xf);
		}
#else
		(void) cardbus_validate_iline(dip, handle);
#endif


		/*
		 * LATER: use these registers
		 */
		pci_config_put32(handle, PCI_CBUS_MEM_BASE1, 0);
		pci_config_put32(handle, PCI_CBUS_MEM_LIMIT1, 0);
		pci_config_put32(handle, PCI_CBUS_IO_BASE1, 0);
		pci_config_put32(handle, PCI_CBUS_IO_LIMIT1, 0);
	} else {
		cmn_err(CE_WARN, "header type 0x%x, probably unknown bridge\n",
		    header_type & PCI_HEADER_TYPE_M);
	}

	cardbus_err(NULL, 7, "cardbus_setup_bridge complete\n");
}

static void
cardbus_update_bridge(dev_info_t *dip, cardbus_phdl_t *entry,
		ddi_acc_handle_t handle)
{
	uint_t length;
	uint16_t word16 = pci_config_get16(handle, PCI_CONF_COMM);
	const	uint8_t header_type = pci_config_get8(handle, PCI_CONF_HEADER)
			& PCI_HEADER_TYPE_M;
	uint32_t bridge_gran;
	uint64_t rlval;

	if (header_type == PCI_HEADER_CARDBUS)
		bridge_gran = CBCFG_MEMGRAN;
	else
		bridge_gran = PCICFG_MEMGRAN;

	/*
	 * Program the memory limit register with the end of the memory range
	 */
#ifdef _LP64
	cardbus_err(dip, 6,
	    "cardbus_update_bridge: Mem base 0x%lx len 0x%lx "
	    "last 0x%lx gran 0x%x gran end 0x%lx\n",
	    entry->memory_base, entry->memory_len,
	    entry->memory_last, entry->memory_gran,
	    PCICFG_ROUND_UP(entry->memory_last, entry->memory_gran));
#else
	cardbus_err(dip, 6,
	    "cardbus_update_bridge: Mem base 0x%llx len 0x%llx "
	    "last 0x%llx gran 0x%x gran end 0x%lx\n",
	    entry->memory_base, entry->memory_len,
	    entry->memory_last, entry->memory_gran,
	    PCICFG_ROUND_UP(entry->memory_last, entry->memory_gran));
#endif
	/*
	 * Since this is a bridge, the rest of this range will
	 * be responded to by the bridge.  We have to round up
	 * so no other device claims it.
	 */
	length = PCICFG_ROUND_UP(entry->memory_last + cardbus_min_spare_mem,
	    bridge_gran) - entry->memory_last;

	if (length > 0) {
		/*
		 * This is to allow space that isn't actually being used by
		 * anything to be allocated by devices such as a downstream
		 * PCMCIA controller.
		 */
		(void) cardbus_get_mem(dip, entry, length, NULL);
		cardbus_err(dip, 8,
		    "Added [0x%x] at the top of the bridge (mem)\n", length);
	}

	if (entry->memory_len) {
		if (header_type == PCI_HEADER_CARDBUS) {
			rlval = PCICFG_ROUND_DOWN(entry->memory_last - 1,
			    CBCFG_MEMGRAN);
#ifdef _LP64
			cardbus_err(dip, 8,
			    "store 0x%x(0x%lx) in memory limit register 0\n",
			    PCICFG_LOADDR(rlval), rlval);
#else
			cardbus_err(dip, 8,
			    "store 0x%x(0x%llx) in memory limit register 0\n",
			    PCICFG_LOADDR(rlval), rlval);
#endif
			pci_config_put32(handle, PCI_CBUS_MEM_LIMIT0,
			    PCICFG_LOADDR(rlval));
		} else {
			rlval = PCICFG_ROUND_DOWN(entry->memory_last - 1,
			    PCICFG_MEMGRAN);
#ifdef _LP64
			cardbus_err(dip, 8,
			    "store 0x%x(0x%lx) in memory limit register\n",
			    PCICFG_HIWORD(PCICFG_LOADDR(rlval)),
			    rlval);
#else
			cardbus_err(dip, 8,
			    "store 0x%x(0x%llx) in memory limit register\n",
			    PCICFG_HIWORD(PCICFG_LOADDR(rlval)),
			    rlval);
#endif
			pci_config_put16(handle, PCI_BCNF_MEM_LIMIT,
			    PCICFG_HIWORD(PCICFG_LOADDR(rlval)));
		}
		word16 |= PCI_COMM_MAE;
	}

	cardbus_err(dip, 6,
	    "cardbus_update_bridge: I/O base 0x%x len 0x%x last 0x%x "
	    "gran 0x%x gran_end 0x%lx\n",
	    entry->io_base, entry->io_len, entry->io_last, entry->io_gran,
	    PCICFG_ROUND_UP(entry->io_last, entry->io_gran));

	if (header_type == PCI_HEADER_CARDBUS)
		bridge_gran = CBCFG_IOGRAN;
	else
		bridge_gran = PCICFG_IOGRAN;

	/*
	 * Same as above for I/O space. Since this is a
	 * bridge, the rest of this range will be responded
	 * to by the bridge.  We have to round up so no
	 * other device claims it.
	 */
	length = PCICFG_ROUND_UP(entry->io_last + cardbus_min_spare_io,
	    bridge_gran) - entry->io_last;
	if (length > 0) {
		(void) cardbus_get_io(dip, entry, length, NULL);
		cardbus_err(dip, 8,
		    "Added [0x%x] at the top of the bridge (I/O)\n",  length);
	}

	/*
	 * Program the I/O limit register with the end of the I/O range
	 */
	if (entry->io_len) {
		if (header_type == PCI_HEADER_CARDBUS) {
			rlval = PCICFG_ROUND_DOWN(entry->io_last - 1,
			    CBCFG_IOGRAN);
#ifdef _LP64
			cardbus_err(dip, 8,
			    "store 0x%lx in IO limit register 0\n", rlval);
#else
			cardbus_err(dip, 8,
			    "store 0x%llx in IO limit register 0\n", rlval);
#endif
			pci_config_put32(handle, PCI_CBUS_IO_LIMIT0, rlval);
		} else {
			rlval = PCICFG_ROUND_DOWN(entry->io_last - 1,
			    PCICFG_IOGRAN);
#ifdef _LP64
			cardbus_err(dip, 8,
			    "store 0x%x/0x%x(0x%lx) in "
			    "IO limit low/hi register\n",
			    PCICFG_HIBYTE(PCICFG_LOWORD(PCICFG_LOADDR(rlval))),
			    PCICFG_HIWORD(PCICFG_LOADDR(rlval)),
			    rlval);
#else
			cardbus_err(dip, 8,
			    "store 0x%x/0x%x(0x%llx) in "
			    "IO limit low/hi register\n",
			    PCICFG_HIBYTE(PCICFG_LOWORD(PCICFG_LOADDR(rlval))),
			    PCICFG_HIWORD(PCICFG_LOADDR(rlval)),
			    rlval);
#endif

			pci_config_put8(handle, PCI_BCNF_IO_LIMIT_LOW,
			    PCICFG_HIBYTE(PCICFG_LOWORD(PCICFG_LOADDR(rlval))));
			pci_config_put16(handle, PCI_BCNF_IO_LIMIT_HI,
			    PCICFG_HIWORD(PCICFG_LOADDR(rlval)));
		}
		word16 |= PCI_COMM_IO;
	}

	pci_config_put16(handle, PCI_CONF_COMM, word16);
}

static void
cardbus_get_mem(dev_info_t *dip, cardbus_phdl_t *entry,
		uint32_t length, uint64_t *ans)
{
	uint32_t hole;

#ifdef  _LP64
	cardbus_err(NULL, 6,
	    "cardbus_get_mem: memory_last 0x%lx, length 0x%x, "
	    "memory_base 0x%lx, memory_len 0x%lx ans=0x%p\n",
	    entry->memory_last, length,
	    entry->memory_base, entry->memory_len, (void *) ans);
#else
	cardbus_err(NULL, 6,
	    "cardbus_get_mem: memory_last 0x%llx, length 0x%x, "
	    "memory_base 0x%llx, memory_len 0x%llx ans=0x%p\n",
	    entry->memory_last, length,
	    entry->memory_base, entry->memory_len, (void *) ans);
#endif

	if (ans) {
		/*
		 * Round up the request to the "size" boundary
		 */
		hole = PCICFG_ROUND_UP(entry->memory_last, length)
			- entry->memory_last;
		if (hole != 0) {
			(void) cardbus_update_available_prop(dip,
			    PCI_ADDR_MEM32,
			    entry->memory_last,
			    (uint64_t)hole);
			entry->memory_last += hole;

#ifdef  _LP64
			cardbus_err(NULL, 6,
			    "cardbus_get_mem: "
			    "rounded memory_last up by 0x%x to 0x%lx, ",
			    hole, entry->memory_last);
#else
			cardbus_err(NULL, 6,
			    "cardbus_get_mem: "
			    "rounded memory_last up by 0x%x to 0x%llx, ",
			    hole, entry->memory_last);
#endif
		}
	} else
		(void) cardbus_update_available_prop(dip, PCI_ADDR_MEM32,
			entry->memory_last,
			(uint64_t)length);

	/*
	 * These routines should parcel out the memory
	 * completely.  There should never be a case of
	 * over running the bounds.
	 */
	if ((entry->memory_last + length) >
	    (entry->memory_base + entry->memory_len))
#ifdef  _LP64
		cardbus_err(NULL, 1,
		    "cardbus_get_mem: assert will fail %ld <= %ld,"
		    "(0x%lx + 0x%x) <= (0x%lx + 0x%lx)\n",
#else
		cardbus_err(NULL, 1,
		    "cardbus_get_mem: assert will fail %lld <= %lld, "
		    "(0x%llx + 0x%x) <= (0x%llx + 0x%llx)\n",
#endif
		    entry->memory_last + length,
		    entry->memory_base + entry->memory_len,
		    entry->memory_last,
		    length,
		    entry->memory_base,
		    entry->memory_len);

	ASSERT((entry->memory_last + length) <=
	(entry->memory_base + entry->memory_len));
	/*
	 * If ans is NULL don't return anything,
	 * they are just asking to reserve the memory.
	 */
	if (ans != NULL)
		*ans = entry->memory_last;

	/*
	 * Increment to the next location
	 */
	entry->memory_last += length;
}

static void
cardbus_get_io(dev_info_t *dip, cardbus_phdl_t *entry,
		uint32_t length, uint32_t *ans)
{
	uint32_t	hole;

	cardbus_err(NULL, 6,
	    "cardbus_get_io: io_last 0x%x, length 0x%x, "
	    "io_base 0x%x, io_len 0x%x ans=0x%p\n",
	    entry->io_last, length,
	    entry->io_base, entry->io_len, (void *) ans);

	if (ans) {
		/*
		 * Round up the request to the "size" boundary
		 */
		hole = PCICFG_ROUND_UP(entry->io_last, length) - entry->io_last;
		if (hole != 0) {
			(void) cardbus_update_available_prop(dip, PCI_ADDR_IO,
			    (uint64_t)entry->io_last,
			    (uint64_t)hole);
			entry->io_last += hole;

			cardbus_err(NULL, 6,
			    "cardbus_get_io: "
			    "rounded io_last up by 0x%x to 0x%x, ",
			    hole, entry->io_last);
		}
	} else
		(void) cardbus_update_available_prop(dip, PCI_ADDR_IO,
		    (uint64_t)entry->io_last,
		    (uint64_t)length);
	/*
	 * These routines should parcel out the memory
	 * completely.  There should never be a case of
	 * over running the bounds.
	 */
	ASSERT((entry->io_last + length) <=
	    (entry->io_base + entry->io_len));

	/*
	 * If ans is NULL don't return anything,
	 * they are just asking to reserve the memory.
	 */
	if (ans != NULL)
		*ans = entry->io_last;

	/*
	 * Increment to the next location
	 */
	entry->io_last += length;
}

static int
cardbus_sum_resources(dev_info_t *dip, void *hdl)
{
	cardbus_phdl_t *entry = (cardbus_phdl_t *)hdl;
	pci_regspec_t *pci_rp;
	int length;
	int rcount;
	int i, ret;
	ndi_ra_request_t *mem_request;
	ndi_ra_request_t *io_request;
	uint8_t header_type, base_class;
	ddi_acc_handle_t handle;

	/*
	 * Ignore the attachment point and pcs.
	 */
	if (strcmp(ddi_binding_name(dip), "hp_attachment") == 0 ||
	    strcmp(ddi_binding_name(dip), "pcs") == 0) {
		cardbus_err(dip, 8, "cardbus_sum_resources: Ignoring\n");
		return (DDI_WALK_CONTINUE);
	}

	mem_request = &entry->mem_req;
	io_request =  &entry->io_req;

	if (cardbus_config_setup(dip, &handle) != DDI_SUCCESS) {
		cardbus_err(dip, 1,
		    "cardbus_sum_resources: Failed to map config space!\n");
		entry->error = PCICFG_FAILURE;
		return (DDI_WALK_TERMINATE);
	}

	ret = DDI_WALK_CONTINUE;
	header_type = pci_config_get8(handle, PCI_CONF_HEADER);
	base_class = pci_config_get8(handle, PCI_CONF_BASCLASS);

	/*
	 * If its a bridge - just record the highest bus seen
	 */
	if (base_class == PCI_CLASS_BRIDGE) {
		uint8_t	sub_class;

		sub_class = pci_config_get8(handle, PCI_CONF_SUBCLASS);

		switch (sub_class) {
		case PCI_BRIDGE_PCI:
			if ((header_type & PCI_HEADER_TYPE_M)
			    == PCI_HEADER_PPB) {

				if (entry->highest_bus < pci_config_get8(handle,
				    PCI_BCNF_SECBUS)) {
					entry->highest_bus = pci_config_get8(
					    handle, PCI_BCNF_SECBUS);
				}

				(void) cardbus_config_teardown(&handle);
#if defined(CARDBUS_DEBUG)
				if (mem_request->ra_len !=
				    PCICFG_ROUND_UP(mem_request->ra_len,
				    PCICFG_MEMGRAN)) {

#ifdef _LP64
					cardbus_err(dip, 8,
					    "Pre-align [0x%lx] to PCI bridge "
					    "memory gran "
					    "[0x%lx] -> [0x%lx]\n",
					    PCICFG_ROUND_UP(mem_request->ra_len,
						PCICFG_MEMGRAN) -
						mem_request->ra_len,
					    mem_request->ra_len,
					    PCICFG_ROUND_UP(mem_request->ra_len,
						PCICFG_MEMGRAN));
#else
					cardbus_err(dip, 8,
					    "Pre-align [0x%llx] to PCI bridge "
					    "memory gran "
					    "[0x%llx] -> [0x%lx]\n",
					    PCICFG_ROUND_UP(mem_request->ra_len,
						PCICFG_MEMGRAN) -
						mem_request->ra_len,
					    mem_request->ra_len,
					    PCICFG_ROUND_UP(mem_request->ra_len,
						PCICFG_MEMGRAN));
#endif
				}

				if (io_request->ra_len !=
				    PCICFG_ROUND_UP(io_request->ra_len,
				    PCICFG_IOGRAN)) {

#ifdef _LP64
					cardbus_err(dip, 8,
					    "Pre-align [0x%lx] to PCI bridge "
					    "I/O gran "
					    "[0x%lx] -> [0x%lx]\n",
					    PCICFG_ROUND_UP(io_request->ra_len,
						PCICFG_IOGRAN) -
						io_request->ra_len,
					    io_request->ra_len,
					    PCICFG_ROUND_UP(io_request->ra_len,
						PCICFG_IOGRAN));
#else
					cardbus_err(dip, 8,
					    "Pre-align [0x%llx] to PCI bridge "
					    "I/O gran "
					    "[0x%llx] -> [0x%lx]\n",
					    PCICFG_ROUND_UP(io_request->ra_len,
						PCICFG_IOGRAN) -
						io_request->ra_len,
					    io_request->ra_len,
					    PCICFG_ROUND_UP(io_request->ra_len,
						PCICFG_IOGRAN));
#endif
				}

#endif
				mem_request->ra_len = PCICFG_ROUND_UP(
							mem_request->ra_len,
							PCICFG_MEMGRAN);
				io_request->ra_len = PCICFG_ROUND_UP(
							io_request->ra_len,
							PCICFG_IOGRAN);
				if (entry->memory_gran < PCICFG_MEMGRAN)
					entry->memory_gran = PCICFG_MEMGRAN;
				if (entry->io_gran < PCICFG_IOGRAN)
					entry->io_gran = PCICFG_IOGRAN;
				ddi_walk_devs(ddi_get_child(dip),
				    cardbus_sum_resources,
				    (void *)entry);
#if defined(CARDBUS_DEBUG)
				if (mem_request->ra_len !=
				    PCICFG_ROUND_UP(mem_request->ra_len +
				    cardbus_min_spare_mem, PCICFG_MEMGRAN)) {

#ifdef _LP64
					cardbus_err(dip, 8,
					    "Post-align [0x%lx] to PCI bridge "
					    "memory gran "
					    "[0x%lx] -> [0x%lx]\n",
					    PCICFG_ROUND_UP(
						mem_request->ra_len +
						cardbus_min_spare_mem,
						PCICFG_MEMGRAN) -
						mem_request->ra_len,
					    mem_request->ra_len,
					    PCICFG_ROUND_UP(mem_request->ra_len
						+ cardbus_min_spare_mem,
						PCICFG_MEMGRAN));
#else
					cardbus_err(dip, 8,
					    "Post-align [0x%llx] to PCI bridge "
					    "memory gran "
					    "[0x%llx] -> [0x%lx]\n",
					    PCICFG_ROUND_UP(
						mem_request->ra_len +
						cardbus_min_spare_mem,
						PCICFG_MEMGRAN) -
						mem_request->ra_len,
					    mem_request->ra_len,
					    PCICFG_ROUND_UP(mem_request->ra_len
						+ cardbus_min_spare_mem,
						PCICFG_MEMGRAN));
#endif
				}

				if (io_request->ra_len !=
				    PCICFG_ROUND_UP(io_request->ra_len +
				    cardbus_min_spare_io,
				    PCICFG_IOGRAN)) {

#ifdef _LP64
					cardbus_err(dip, 8,
					    "Post-align [0x%lx] to PCI bridge "
					    "I/O gran "
					    "[0x%lx] -> [0x%lx]\n",
					    PCICFG_ROUND_UP(io_request->ra_len +
						cardbus_min_spare_io,
						PCICFG_IOGRAN) -
						io_request->ra_len,
					    io_request->ra_len,
					    PCICFG_ROUND_UP(io_request->ra_len +
						cardbus_min_spare_io,
						PCICFG_IOGRAN));
#else
					cardbus_err(dip, 8,
					    "Post-align [0x%llx] to PCI bridge "
					    "I/O gran "
					    "[0x%llx] -> [0x%lx]\n",
					    PCICFG_ROUND_UP(io_request->ra_len +
						cardbus_min_spare_io,
						PCICFG_IOGRAN) -
						io_request->ra_len,
					    io_request->ra_len,
					    PCICFG_ROUND_UP(io_request->ra_len +
						cardbus_min_spare_io,
						PCICFG_IOGRAN));
#endif
				}
#endif
				mem_request->ra_len = PCICFG_ROUND_UP(
						mem_request->ra_len +
						    cardbus_min_spare_mem,
						PCICFG_MEMGRAN);
				io_request->ra_len = PCICFG_ROUND_UP(
						io_request->ra_len +
						    cardbus_min_spare_io,
						PCICFG_IOGRAN);
			}
			return (DDI_WALK_PRUNECHILD);

		case PCI_BRIDGE_CARDBUS:
			/*
			 * Cardbus has I/O registers.
			 */
			break;

		case PCI_BRIDGE_ISA:
			/*
			 * All the registers requirements for ISA
			 * are stored in the reg structure of the bridge.
			 * Children of ISA are not of type PCI
			 * so must not come through here because
			 * cardbus_config_setup() will fail.
			 */
			ret = DDI_WALK_PRUNECHILD;
			break;

		default:
			/*
			 * Treat other bridges as leaf nodes.
			 */
			break;
		}
	}

	if (ddi_getlongprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "reg", (caddr_t)&pci_rp,
	    &length) != DDI_PROP_SUCCESS) {
		/*
		 * If one node in (the subtree of nodes)
		 * does'nt have a "reg" property fail the
		 * allocation.
		 */
		entry->memory_len = 0;
		entry->io_len = 0;
		entry->error = PCICFG_FAILURE;
		(void) cardbus_config_teardown(&handle);
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

			cardbus_err(dip, 8,
			    "ADDING 32 --->0x%x for BAR@0x%x\n",
			    pci_rp[i].pci_size_low,
			    PCI_REG_REG_G(pci_rp[i].pci_phys_hi));
			/*
			 * the granualarity needs to be the larger of
			 * the maximum amount of memory that we're going to
			 * ask for, and the PCI-PCI bridge granularity (1M)
			 */
			if (pci_rp[i].pci_size_low > entry->memory_gran)
				entry->memory_gran = pci_rp[i].pci_size_low;
			break;

		case PCI_REG_ADDR_G(PCI_ADDR_MEM64):
			mem_request->ra_len =
				pci_rp[i].pci_size_low +
				PCICFG_ROUND_UP(mem_request->ra_len,
					pci_rp[i].pci_size_low);
			cardbus_err(dip, 8,
			    "ADDING 64 --->0x%x for BAR@0x%x\n",
			    pci_rp[i].pci_size_low,
			    PCI_REG_REG_G(pci_rp[i].pci_phys_hi));

			if (pci_rp[i].pci_size_low > entry->memory_gran)
				entry->memory_gran = pci_rp[i].pci_size_low;
			break;

		case PCI_REG_ADDR_G(PCI_ADDR_IO):
			io_request->ra_len =
				pci_rp[i].pci_size_low +
				PCICFG_ROUND_UP(io_request->ra_len,
					pci_rp[i].pci_size_low);
			cardbus_err(dip, 8,
			    "ADDING I/O --->0x%x for BAR@0x%x\n",
			    pci_rp[i].pci_size_low,
			    PCI_REG_REG_G(pci_rp[i].pci_phys_hi));

			if (pci_rp[i].pci_size_low > entry->io_gran)
				entry->io_gran = pci_rp[i].pci_size_low;
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

	(void) cardbus_config_teardown(&handle);

#ifdef  _LP64
	cardbus_err(dip, 8,
	    "Memory 0x%lx bytes, I/O 0x%lx bytes, "
	    "Memgran 0x%x, IOgran 0x%x\n",
	    mem_request->ra_len, io_request->ra_len,
	    entry->memory_gran, entry->io_gran);
#else
	cardbus_err(dip, 8,
	    "Memory 0x%llx bytes, I/O 0x%llx bytes, "
	    "Memgran 0x%x, IOgran 0x%x\n",
	    mem_request->ra_len, io_request->ra_len,
	    entry->memory_gran, entry->io_gran);
#endif

	return (ret);
}

/*
 * Free resources allocated to a bridge.
 * Note that this routine does not call ndi_ra_free() to actually
 * free memory/IO/Bus. This is done as a single chunk for the entire
 * device tree in cardbus_free_chunk().
 */
static int
cardbus_free_bridge_resources(dev_info_t *dip)
{
	cardbus_range_t	*ranges;
	uint_t		*bus;
	int		k;
	int		length;
	int		i;

	cardbus_err(dip, 6, "cardbus_free_bridge_resources\n");

	if (ddi_getlongprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "ranges", (caddr_t)&ranges,
	    &length) == DDI_PROP_SUCCESS) {
		for (i = 0; i < length / sizeof (cardbus_range_t); i++) {
			if (ranges[i].size_lo != 0 || ranges[i].size_hi != 0) {
				switch (ranges[i].parent_hi & PCI_REG_ADDR_M) {
				case PCI_ADDR_IO:
					cardbus_err(dip, 6,
					    "Need to Free I/O    "
					    "base/length = [0x%x]/[0x%x]\n",
					    ranges[i].child_lo,
					    ranges[i].size_lo);
					break;

				case PCI_ADDR_MEM32:
				case PCI_ADDR_MEM64:
					cardbus_err(dip, 6,
					    "Need to Free Memory base/length = "
					    "[0x%x.%x]/[0x%x]\n",
					    ranges[i].child_mid,
					    ranges[i].child_lo,
					    ranges[i].size_lo);
					break;

				default:
					cardbus_err(dip, 6,
					    "Unknown memory space\n");
					break;
				}
			}
		}

		kmem_free(ranges, length);
		(void) ndi_prop_remove(DDI_DEV_T_NONE, dip, "ranges");
	} else {
		cardbus_err(dip, 8,
		    "cardbus_free_bridge_resources: Failed"
		    "to read ranges property\n");
	}

	if (ddi_getlongprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "bus-range", (caddr_t)&bus,
	    &k) != DDI_PROP_SUCCESS) {
		cardbus_err(dip, 6, "Failed to read bus-range property\n");
		return (PCICFG_FAILURE);
	}

	cardbus_err(dip, 6,
	    "Need to free bus [%d] range [%d]\n",
	    bus[0], bus[1] - bus[0] + 1);
	kmem_free(bus, k);
	(void) ndi_prop_remove(DDI_DEV_T_NONE, dip, "available");
	(void) ndi_prop_remove(DDI_DEV_T_NONE, dip, "bus-range");

	return (PCICFG_SUCCESS);
}

static int
cardbus_free_device_resources(dev_info_t *dip)
{
	pci_regspec_t *assigned;

	int length;
	int acount;
	int i;

	if (ddi_getlongprop(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "assigned-addresses",
	    (caddr_t)&assigned,
	    &length) != DDI_PROP_SUCCESS) {
		cardbus_err(dip, 1,
		    "Failed to read assigned-addresses property\n");
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
				cardbus_err(dip, 6,
				    "Need to return 0x%x of 32 bit MEM space"
				    " @ 0x%x from register 0x%x\n",
				    assigned[i].pci_size_low,
				    assigned[i].pci_phys_low,
				    PCI_REG_REG_G(assigned[i].pci_phys_hi));

				break;

			case PCI_REG_ADDR_G(PCI_ADDR_MEM64):
				cardbus_err(dip, 6,
				    "Need to return 0x%x of 64 bit MEM space"
				    " @ 0x%x.%x from register 0x%x\n",
				    assigned[i].pci_size_low,
				    assigned[i].pci_phys_mid,
				    assigned[i].pci_phys_low,
				    PCI_REG_REG_G(assigned[i].pci_phys_hi));

				break;

			case PCI_REG_ADDR_G(PCI_ADDR_IO):
				cardbus_err(dip, 6,
				    "Need to return 0x%x of IO space @ 0x%x"
				    " from register 0x%x\n",
				    assigned[i].pci_size_low,
				    assigned[i].pci_phys_low,
				    PCI_REG_REG_G(assigned[i].pci_phys_hi));
				break;

			default:
				cardbus_err(dip, 1, "Unknown register type\n");
				kmem_free(assigned, length);
				return (PCICFG_FAILURE);
			} /* switch */
		}
	}
	kmem_free(assigned, length);
	return (PCICFG_SUCCESS);
}

static int
cardbus_free_resources(dev_info_t *dip)
{
	uint32_t classcode;

	classcode = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
				"class-code", -1);
	/*
	 * A different algorithim is used for bridges and leaf devices.
	 */
	if (classcode != -1) {
		classcode = ((uint_t)classcode & 0xffff00) >> 8;
		if (classcode == 0x604 || classcode == 0x607) {
			if (cardbus_free_bridge_resources(dip)
			    != PCICFG_SUCCESS) {
				cardbus_err(dip, 1,
				    "Failed freeing up bridge resources\n");
				return (PCICFG_FAILURE);
			}
			return (PCICFG_SUCCESS);
		}
	}

	if (cardbus_free_device_resources(dip) != PCICFG_SUCCESS) {
		cardbus_err(dip, 1, "Failed freeing up device resources\n");
		return (PCICFG_FAILURE);
	}
	return (PCICFG_SUCCESS);
}

static int
cardbus_probe_bridge(cbus_t *cbp, dev_info_t *attpt, uint_t bus,
			uint_t device, uint_t func)
{
	/* Declairations */
	cardbus_bus_range_t	*bus_range;
	int			i, j;
	uint8_t			header_type;
	ddi_acc_handle_t	config_handle;
	ndi_ra_request_t	req;
	uint_t			new_bus;
	uint64_t		blen;
	uint64_t		next_bus;

	cardbus_err(cbp->cb_dip, 6,
	    "cardbus_probe_bridge bus %d device %d func %d\n",
	    bus, device, func);

	ndi_devi_enter(cbp->cb_dip);
	if (pci_config_setup(cbp->cb_dip, &config_handle) != DDI_SUCCESS) {

		cardbus_err(cbp->cb_dip, 1,
		    "cardbus_probe_bridge(): Failed to setup config space\n");

		ndi_devi_exit(cbp->cb_dip);
		return (PCICFG_FAILURE);
	}

	header_type = pci_config_get8(config_handle, PCI_CONF_HEADER);

	/*
	 * As soon as we have access to config space, check device
	 * is a bridge.
	 */
	if ((header_type & PCI_HEADER_TYPE_M) != PCI_HEADER_CARDBUS)
		goto failed;

	cardbus_err(cbp->cb_dip, 8,
	    "---Vendor ID = [0x%04x]\n",
	    pci_config_get16(config_handle, PCI_CONF_VENID));
	cardbus_err(cbp->cb_dip, 8,
	    "---Device ID = [0x%04x]\n",
	    pci_config_get16(config_handle, PCI_CONF_DEVID));

	/* say what type of header */
	cardbus_err(cbp->cb_dip, 8,
	    "--%s bridge found root bus [0x%x] device [0x%x] func [0x%x]\n",
	    ((header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_PPB) ?
		"PCI-PCI" : "Cardbus",
	    bus, device, func);

	if (ddi_getlongprop(DDI_DEV_T_ANY, cbp->cb_dip, 0, "bus-range",
	    (caddr_t)&bus_range, &i) != DDI_PROP_SUCCESS)
		cardbus_err(cbp->cb_dip, 1,
		    "No bus-range property seems to have been set up\n");
	else {
		cardbus_err(cbp->cb_dip, 8,
		    "allowable bus range is %u->%u\n",
		    bus_range->lo, bus_range->hi);
		kmem_free((caddr_t)bus_range, i);
	}

	/*
	 * Get next bus in sequence and program device.
	 */
	bzero((caddr_t)&req, sizeof (ndi_ra_request_t));
	req.ra_len = 1;

	if (ndi_ra_alloc(cbp->cb_dip, &req,
	    &next_bus, &blen, NDI_RA_TYPE_PCI_BUSNUM,
	    NDI_RA_PASS) != NDI_SUCCESS) {
		cmn_err(CE_WARN, "Failed to get a bus number\n");
		goto failed;
	}

	new_bus = next_bus;
	cardbus_err(cbp->cb_dip, 8,
	    "NEW bus found [%u]->[%u]\n", bus, new_bus);

	(void) cardbus_set_bus_numbers(config_handle, bus, new_bus);

	/* Enable it all */
	enable_cardbus_bridge(cbp->cb_dip, config_handle);

	/*
	 * Probe all children devices
	 */
	for (i = 0; i < pcicfg_max_device; i++)
		for (j = 0; j < pcicfg_max_function; j++)
			switch (cardbus_probe_children(cbp, attpt, new_bus, i,
			    j, &header_type)) {

			case PCICFG_FAILURE:
				cardbus_err(cbp->cb_dip, 1,
				    "Failed to configure bus "
				    "[0x%x] device [0x%x] func [0x%x]\n",
				    new_bus, i, j);
				disable_cardbus_bridge(cbp->cb_dip,
				    config_handle);
				goto failed;

			case PCICFG_NODEVICE:
				/*
				 * if there's no function 0
				 * there's no point in probing other
				 * functions
				 */
				if (j != 0)
					break;
				/* FALLTHROUGH */
			case PCICFG_NOMULTI:
				j = pcicfg_max_function;
				break;

			default:
				break;
			}

	(void) pci_config_teardown(&config_handle);
	(void) i_ndi_config_node(attpt, DS_LINKED, 0);
	ndi_devi_exit(cbp->cb_dip);

	return (PCICFG_SUCCESS);

failed:
	(void) pci_config_teardown(&config_handle);
	ndi_devi_exit(cbp->cb_dip);

	return (PCICFG_FAILURE);
}

static struct isa_node isa_nodes[] = {
	{"dummy", {NULL, NULL, NULL, NULL, NULL}, "serial", "", 0x4e, 0x2}
};

static int
cardbus_probe_children(cbus_t *cbp, dev_info_t *parent, uint_t bus,
			uint_t device, uint_t func, uint8_t *header_type)
{
	dev_info_t		*new_child;
	ddi_acc_handle_t	config_handle;
	int			i, j;
	ndi_ra_request_t	req;
	uint64_t		next_bus;
	uint64_t		blen;
	uint32_t		request;
	uint8_t			base_class;
	uint_t			new_bus;
	int			ret;

	cardbus_err(parent, 6,
	    "cardbus_probe_children bus %d device %d func %d\n",
	    bus, device, func);

	/*
	 * This node will be put immediately below
	 * "parent". Allocate a blank device node.  It will either
	 * be filled in or freed up based on further probing.
	 */

	ndi_devi_enter(parent);

	if (ndi_devi_alloc(parent, DEVI_PSEUDO_NEXNAME,
	    (pnode_t)DEVI_SID_NODEID,
	    &new_child) != NDI_SUCCESS) {
		cardbus_err(parent, 1,
		    "cardbus_probe_children(): Failed to alloc child node\n");
		ndi_devi_exit(parent);
		return (PCICFG_FAILURE);
	}

	if (cardbus_add_config_reg(new_child, bus,
	    device, func) != DDI_SUCCESS) {
		cardbus_err(parent, 1,
		    "cardbus_probe_children(): Failed to add candidate REG\n");
		goto failedconfig;
	}

	if ((ret = cardbus_config_setup(new_child, &config_handle))
	    != PCICFG_SUCCESS) {

		if (ret == PCICFG_NODEVICE) {
			(void) ndi_devi_free(new_child);
			return (ret);
		}
		cardbus_err(parent, 1,
		    "cardbus_probe_children(): Failed to setup config space\n");

		goto failedconfig;
	}

	base_class = pci_config_get8(config_handle, PCI_CONF_BASCLASS);

	if (func == 0) {
		/*
		 * Preserve the header type from function 0.
		 * Additional functions may not preserve the PCI_HEADER_MULTI
		 * bit.
		 */
		*header_type = pci_config_get8(config_handle, PCI_CONF_HEADER);
	} else if (!(*header_type & PCI_HEADER_MULTI) ||
		    ((*header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_PPB) ||
		    (base_class == PCI_CLASS_BRIDGE)) {

		(void) cardbus_config_teardown(&config_handle);
		(void) ndi_devi_free(new_child);
		return (PCICFG_NOMULTI);
	}

	/*
	 * As soon as we have access to config space,
	 * turn off device. It will get turned on
	 * later (after memory is assigned).
	 * not if it's a cardbus device. It may be OK to leave
	 * it on - try LATER
	 */
	disable_cardbus_device(config_handle);

	/*
	 * Set 1275 properties common to all devices
	 */
	if (cardbus_set_standard_props(parent, new_child,
	    config_handle) != PCICFG_SUCCESS) {
		cardbus_err(parent, 1, "Failed to set standard properties\n");
		goto failedchild;
	}

	/*
	 * Child node properties  NOTE: Both for PCI-PCI bridge and child node
	 */
	if (cardbus_set_childnode_props(new_child,
	    config_handle) != PCICFG_SUCCESS) {
		goto failedchild;
	}

	cardbus_err(parent, 8,
	    "---Vendor ID = [0x%04x]\n",
	    pci_config_get16(config_handle, PCI_CONF_VENID));
	cardbus_err(parent, 8,
	    "---Device ID = [0x%04x]\n",
	    pci_config_get16(config_handle, PCI_CONF_DEVID));

	if (base_class == PCI_CLASS_BRIDGE) {
		uint8_t	sub_class;

		sub_class = pci_config_get8(config_handle, PCI_CONF_SUBCLASS);

		switch (sub_class) {
		case PCI_BRIDGE_PCI:
			if ((*header_type & PCI_HEADER_TYPE_M)
			    == PCI_HEADER_PPB) {
				cardbus_bus_range_t *bus_range;
				int k;

				/* say what type of header */
				cardbus_err(parent, 8,
				    "-- Found PCI-PCI bridge @ "
				    " bus [0x%x] device [0x%x] func [0x%x]\n",
				    bus, device, func);

				if (ddi_getlongprop(DDI_DEV_T_ANY,
				    new_child, 0, "bus-range",
				    (caddr_t)&bus_range,
				    &k) != DDI_PROP_SUCCESS)
					cardbus_err(new_child, 1,
					    "No bus-range property"
					    " seems to have been set up\n");
				else {
					cardbus_err(new_child, 8,
					    "allowable bus range is %u->%u\n",
					    bus_range->lo, bus_range->hi);
					kmem_free((caddr_t)bus_range, k);
				}

				/*
				 * Get next bus in sequence and program device.
				 */
				bzero((caddr_t)&req, sizeof (ndi_ra_request_t));
				req.ra_len = 1;

				if (ndi_ra_alloc(new_child, &req,
				    &next_bus, &blen,
				    NDI_RA_TYPE_PCI_BUSNUM,
				    NDI_RA_PASS) != NDI_SUCCESS) {
					cmn_err(CE_WARN,
					    "Failed to get a bus number\n");
					goto failedchild;
				}

				new_bus = next_bus;

				cardbus_err(new_child, 8,
				    "NEW bus found [%u]->[%u]\n", bus, new_bus);

				/* Enable it all */
				enable_pci_pci_bridge(new_child, config_handle);
				(void) cardbus_set_bus_numbers(config_handle,
				    bus, new_bus);

#if defined(CARDBUS_DEBUG)
				if (cardbus_debug >= 9) {
					cardbus_dump_config(config_handle);
				}
#endif

				/*
				 * Set bus properties
				 */
				if (cardbus_set_busnode_props(new_child)
				    != PCICFG_SUCCESS) {
					cardbus_err(new_child, 1,
					    "Failed to set busnode props\n");
					disable_pci_pci_bridge(new_child,
					    config_handle);
					goto failedchild;
				}

				/*
				 * Probe all children devices
				 */
				for (i = 0; i < pcicfg_max_device; i++)
					for (j = 0; j < pcicfg_max_function;
					    j++)
						switch (cardbus_probe_children(
						    cbp,
						    new_child,
						    new_bus, i,
						    j, header_type)) {
						case PCICFG_FAILURE:
							cardbus_err(parent, 1,
							    "Failed to "
							    "configure "
							    "bus [0x%x] "
							    "device [0x%x] "
							    "func [0x%x]\n",
							    new_bus, i, j);
							disable_pci_pci_bridge(
								new_child,
								config_handle);
							goto failedchild;

						case PCICFG_NODEVICE:
							/*
							 * if there's no
							 * function 0
							 * there's no point in
							 * probing other
							 * functions
							 */
							if (j != 0)
								break;
							/* FALLTHROUGH */
						case PCICFG_NOMULTI:
							j = pcicfg_max_function;
							break;

						default:
							break;
						}
			}
			break;

		case PCI_BRIDGE_CARDBUS:
			cardbus_err(parent, 8,
			    "--Found Cardbus bridge @ "
			    "bus [0x%x] device [0x%x] func [0x%x]\n",
			    bus, device, func);
			pci_config_put32(config_handle,
			    PCI_CONF_BASE0, 0xffffffff);

			request = pci_config_get32(config_handle,
			    PCI_CONF_BASE0);

			/*
			 * If its a zero length, don't do
			 * any programming.
			 */
			if (request != 0) {
				if (request == (uint32_t)0xffffffff) {
					cmn_err(CE_WARN,
					    "cardbus_probe_children: "
					    "can't access device");
					goto failedchild;
				}
				/*
				 * Add to the "reg" property
				 */
				if (cardbus_update_reg_prop(new_child,
				    request,
				    PCI_CONF_BASE0) != PCICFG_SUCCESS) {
					goto failedchild;
				}
				cardbus_err(parent, 8,
				    "BASE register [0x%x] asks for "
				    "[0x%x]=[0x%x](32)\n",
				    PCI_CONF_BASE0, request,
				    (~(PCI_BASE_M_ADDR_M & request))+1);
			}
			break;

		case PCI_BRIDGE_ISA:
			cardbus_err(parent, 8,
			    "--Found ISA bridge @ "
			    "bus [0x%x] device [0x%x] func [0x%x]\n",
			    bus, device, func);
			enable_pci_isa_bridge(new_child, config_handle);

#if defined(CARDBUS_DEBUG)
			if (cardbus_debug >= 4) {
				cardbus_dump_common_config(config_handle);
				cardbus_err(NULL, 1,
				    " DDMA SlvCh0 = [0x%04x]        "
				    "DDMA SlvCh1 = [0x%04x]\n",
				    pci_config_get16(config_handle, 0x40),
				    pci_config_get16(config_handle, 0x42));
				cardbus_err(NULL, 1,
				    " DDMA SlvCh2 = [0x%04x]        "
				    "DDMA SlvCh3 = [0x%04x]\n",
				    pci_config_get16(config_handle, 0x44),
				    pci_config_get16(config_handle, 0x46));
				cardbus_err(NULL, 1,
				    " DDMA SlvCh5 = [0x%04x]        "
				    "DDMA SlvCh6 = [0x%04x]\n",
				    pci_config_get16(config_handle, 0x4a),
				    pci_config_get16(config_handle, 0x4c));
				cardbus_err(NULL, 1,
				    " DDMA SlvCh7 = [0x%04x]        "
				    "Misc Cntrl  = [0x%02x]\n",
				    pci_config_get16(config_handle, 0x4e),
				    pci_config_get8(config_handle, 0x57));
				cardbus_err(NULL, 1,
				    " DMA Cntl    = [0x%02x]          "
				    "DMA TyF Tim = [0x%02x]\n",
				    pci_config_get8(config_handle, 0x48),
				    pci_config_get8(config_handle, 0x49));
				cardbus_err(NULL, 1,
				    " TimCntrl    = [0x%02x]          "
				    "MTOP        = [0x%02x]\n",
				    pci_config_get8(config_handle, 0x50),
				    pci_config_get8(config_handle, 0x51));
				cardbus_err(NULL, 1,
				    " MDMA Access = [0x%02x]          "
				    "ROMCS       = [0x%02x]\n",
				    pci_config_get8(config_handle, 0x52),
				    pci_config_get8(config_handle, 0x53));
				cardbus_err(NULL, 1,
				    " Dscrd Tmr   = [0x%02x]          "
				    "Retry Tmr   = [0x%02x]\n",
				    pci_config_get8(config_handle, 0x55),
				    pci_config_get8(config_handle, 0x54));
				cardbus_err(NULL, 1,
				    " I/O Spc 0   = [0x%08x]    "
				    "I/O Spc 1   = [0x%08x]\n",
				    pci_config_get32(config_handle, 0x58),
				    pci_config_get32(config_handle, 0x5c));
				cardbus_err(NULL, 1,
				    " I/O Spc 2   = [0x%08x]    "
				    "I/O Spc 3   = [0x%08x]\n",
				    pci_config_get32(config_handle, 0x60),
				    pci_config_get32(config_handle, 0x64));
				cardbus_err(NULL, 1,
				    " I/O Spc 4   = [0x%08x]    "
				    "I/O Spc 5   = [0x%08x]\n",
				    pci_config_get32(config_handle, 0x68),
				    pci_config_get32(config_handle, 0x6c));
				cardbus_err(NULL, 1,
				    " Mem Spc 0   = [0x%08x]    "
				    "Mem Spc 1   = [0x%08x]\n",
				    pci_config_get32(config_handle, 0x70),
				    pci_config_get32(config_handle, 0x74));
				cardbus_err(NULL, 1,
				    " Mem Spc 2   = [0x%08x]    "
				    "Mem Spc 3   = [0x%08x]\n",
				    pci_config_get32(config_handle, 0x78),
				    pci_config_get32(config_handle, 0x7c));
			}
#endif
			/*
			 * Set bus properties
			 */
			if (cardbus_set_busnode_isaprops(new_child)
			    != PCICFG_SUCCESS) {
				cardbus_err(new_child, 1,
				    "Failed to set busnode props\n");
				disable_cardbus_device(config_handle);
				goto failedchild;
			}

			/*
			 * Add to the "reg" property.
			 * Simply grab 1K of I/O space.
			 */
			if (cardbus_update_reg_prop(new_child,
			    0xfffffc00 | PCI_BASE_SPACE_IO,
			    PCI_CONF_BASE0) != PCICFG_SUCCESS) {
				goto failedchild;
			}

			/*
			 * Probe all potential children devices.
			 */
			for (i = 0;
			    i < sizeof (isa_nodes) / sizeof (isa_nodes[0]);
			    i++)
				switch (cardbus_add_isa_node(cbp, new_child,
				    &isa_nodes[i])) {
				case PCICFG_FAILURE:
					cardbus_err(parent, 1,
					    "Failed to configure isa bus\n");
					disable_cardbus_device(config_handle);
					goto failedchild;

				case PCICFG_NODEVICE:
					continue;
				}

			break;

		case PCI_BRIDGE_OTHER:
		default:
			cardbus_err(parent, 8,
			    "--Found unknown bridge, subclass 0x%x @ "
			    "bus [0x%x] device [0x%x] func [0x%x]\n",
			    sub_class, bus, device, func);
			goto leaf_node;
		}
	} else {
		cardbus_err(parent, 8,
		    "--Leaf device found "
		    "bus [0x%x] device [0x%x] func [0x%x]\n",
		    bus, device, func);
		/*
		 * Ethernet devices.
		 */
		if (strcmp(ddi_binding_name(new_child), "ethernet") == 0) {
			extern int localetheraddr(struct ether_addr *,
			    struct ether_addr *);
			uchar_t mac[6];

			cardbus_force_stringprop(new_child,
			    "device_type", "network");

			if (localetheraddr(NULL, (struct ether_addr *)mac)) {
				(void) ddi_prop_create(DDI_DEV_T_NONE,
				    new_child,
				    DDI_PROP_CANSLEEP, "local-mac-address",
				    (caddr_t)mac, 6);
			}
		}
leaf_node:
		if (cbp->cb_dsp) {
			struct cb_deviceset_props *cdsp = cbp->cb_dsp;
			uint16_t venid = pci_config_get16(config_handle,
						PCI_CONF_VENID);
			uint16_t devid = pci_config_get16(config_handle,
						PCI_CONF_DEVID);
			ddi_prop_t *propp;

			for (cdsp = cbp->cb_dsp; cdsp; cdsp = cdsp->next) {
				if (cdsp->binding_name &&
				    strcmp(ddi_binding_name(new_child),
				    cdsp->binding_name))
					continue;
				if (cdsp->venid && (cdsp->venid != venid))
					continue;
				if (cdsp->devid && (cdsp->devid != devid))
					continue;
				if (cdsp->nodename) {
					if (ndi_devi_set_nodename(new_child,
					    cdsp->nodename,
					    0) != NDI_SUCCESS)
						cardbus_err(new_child, 1,
						    "Failed to set nodename\n");
				}
				for (propp = cdsp->prop_list; propp;
				    propp = propp->prop_next) {
					switch (propp->prop_flags) {
					case DDI_PROP_TYPE_INT:
						cardbus_force_intprop(
						    new_child,
						    propp->prop_name,
						    (int *)propp->prop_val,
						    propp->prop_len);
						break;
					case DDI_PROP_TYPE_STRING:
						cardbus_force_stringprop(
						    new_child,
						    propp->prop_name,
						    (char *)propp->prop_val);
						break;
					case DDI_PROP_TYPE_ANY:
						cardbus_force_boolprop(
						    new_child,
						    propp->prop_name);
						break;
					}
				}
			}
		}

#if defined(CARDBUS_DEBUG)
		if (cardbus_debug >= 9) {
			cardbus_dump_config(config_handle);
		}
#endif

		i = PCI_CONF_BASE0;

		while (i <= PCI_CONF_BASE5) {
			pci_config_put32(config_handle, i, 0xffffffff);

			request = pci_config_get32(config_handle, i);

			/*
			 * If its a zero length, don't do
			 * any programming.
			 */
			if (request != 0) {
				if (request == (uint32_t)0xffffffff) {
					cmn_err(CE_WARN,
					    "cardbus_probe_children: "
					    "can't access device");
					goto failedchild;
				}
				/*
				 * Add to the "reg" property
				 */
				if (cardbus_update_reg_prop(new_child,
				    request, i) != PCICFG_SUCCESS) {
					goto failedchild;
				}
			} else {
				cardbus_err(parent, 8, "All memory found\n");
				break;
			}

			/*
			 * Increment by eight if it is 64 bit address space
			 * only if memory space
			 */
			if (((PCI_BASE_TYPE_M & request)
				== PCI_BASE_TYPE_ALL) &&
			    ((PCI_BASE_SPACE_M & request)
				== PCI_BASE_SPACE_MEM)) {
				cardbus_err(parent, 8,
				    "BASE register [0x%x] asks for "
				    "[0x%x]=[0x%x] (64)\n",
				    i, request,
				    (~(PCI_BASE_M_ADDR_M & request))+1);
				i += 8;
			} else {
				cardbus_err(parent, 8,
				    "BASE register [0x%x] asks for "
				    "[0x%x]=[0x%x](32)\n",
				    i, request,
				    (~(PCI_BASE_M_ADDR_M & request))+1);
				i += 4;
			}
		}

		/*
		 * Get the ROM size and create register for it
		 */
		pci_config_put32(config_handle, PCI_CONF_ROM, 0xffffffff);

		request = pci_config_get32(config_handle, PCI_CONF_ROM);
		/*
		 * If its a zero length, don't do
		 * any programming.
		 */

		if (request != 0) {
			cardbus_err(parent, 9,
			    "BASE register [0x%x] asks for "
			    "[0x%x]=[0x%x] (ROM)\n",
			    PCI_CONF_ROM, request,
			    (~(PCI_BASE_ROM_ADDR_M & request))+1);
			/*
			 * Add to the "reg" property
			 */
			if (cardbus_update_reg_prop(new_child,
			    request,
			    PCI_CONF_ROM) != PCICFG_SUCCESS) {
				goto failedchild;
			}
		}
	}

	(void) cardbus_config_teardown(&config_handle);

	/*
	 * Attach the child to its parent
	 */
	(void) i_ndi_config_node(new_child, DS_LINKED, 0);
	ndi_devi_exit(parent);

	return (PCICFG_SUCCESS);
failedchild:
	/*
	 * check if it should be taken offline (if online)
	 */
	(void) cardbus_config_teardown(&config_handle);

failedconfig:

	(void) ndi_devi_free(new_child);
	ndi_devi_exit(parent);

	return (PCICFG_FAILURE);
}

static int
cardbus_add_config_reg(dev_info_t *dip,
		uint_t bus, uint_t device, uint_t func)
{
	int reg[10] = { PCI_ADDR_CONFIG, 0, 0, 0, 0};

	reg[0] = PCICFG_MAKE_REG_HIGH(bus, device, func, 0);

	return (ndi_prop_update_int_array(DDI_DEV_T_NONE, dip,
	    "reg", reg, 5));
}

static int
cardbus_add_isa_node(cbus_t *cbp, dev_info_t *parent, struct isa_node *node)
{
	dev_info_t		*new_child;
	int			ret;
	uint32_t		reg[3];

	_NOTE(ARGUNUSED(cbp))

	cardbus_err(parent, 6, "cardbus_add_isa_node\n");

	/*
	 * This node will be put immediately below
	 * "parent". Allocate a blank device node.
	 */
	if (ndi_devi_alloc(parent, DEVI_PSEUDO_NEXNAME,
	    (pnode_t)DEVI_SID_NODEID,
	    &new_child) != NDI_SUCCESS) {
		cardbus_err(parent, 1,
		    "cardbus_add_isa_child(): Failed to alloc child node\n");
		return (PCICFG_FAILURE);
	}

	/*
	 * Set properties common to ISA devices
	 */
	if (cardbus_set_isa_props(parent, new_child, node->name,
	    node->compatible) != PCICFG_SUCCESS) {
		cardbus_err(parent, 1, "Failed to set ISA properties\n");
		goto failed;
	}

	cardbus_err(new_child, 8, "--Leaf ISA device\n");

	/*
	 * Add the "reg" property.
	 */
	reg[0] = 0;
	reg[1] = node->reg;
	reg[2] = node->span;

	ret = ndi_prop_update_int_array(DDI_DEV_T_NONE, new_child,
	    "basereg", (int *)reg, 3);
	if (ret != DDI_SUCCESS)
		goto failed;

	(void) i_ndi_config_node(new_child, DS_LINKED, 0);

	return (PCICFG_SUCCESS);

failed:
	(void) ndi_devi_free(new_child);

	return (PCICFG_FAILURE);
}

static int
cardbus_config_setup(dev_info_t *dip, ddi_acc_handle_t *handle)
{
	caddr_t		cfgaddr;
	ddi_device_acc_attr_t	attr;
	dev_info_t	*anode;
	int	status;
	int	rlen;
	pci_regspec_t	*reg;
	int		ret;
#ifdef sparc
	int16_t		val;
#endif

	cardbus_err(dip, 10,
	    "cardbus_config_setup(dip=0x%p)\n", (void *) dip);

	/*
	 * Get the pci register spec from the node
	 */
	status = ddi_getlongprop(DDI_DEV_T_NONE,
	    dip, DDI_PROP_DONTPASS, "reg",
	    (caddr_t)&reg, &rlen);

	cardbus_err(dip, 10,
	    "cardbus_config_setup, reg = 0x%p\n", (void *) reg);

	switch (status) {
	case DDI_PROP_SUCCESS:
		break;
	case DDI_PROP_NO_MEMORY:
		cardbus_err(dip, 1, "reg present, but unable to get memory\n");
		return (PCICFG_FAILURE);
	default:
		cardbus_err(dip, 1, "no reg property\n");
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
		cardbus_err(dip, 1, "Tree not in PROBE state\n");
		kmem_free((caddr_t)reg, rlen);
		return (PCICFG_FAILURE);
	}

	if ((ret = ndi_prop_update_int_array(DDI_DEV_T_NONE, anode,
	    "reg", (int *)reg, 5)) != 0) {
		cardbus_err(dip, 1,
		    "Failed to update reg property, error code %d\n", ret);
		kmem_free((caddr_t)reg, rlen);
		return (PCICFG_FAILURE);
	}

	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	if (ddi_regs_map_setup(anode, 0, &cfgaddr,
	    0, /* PCI_CONF_HDR_SIZE */
	    0,
	    &attr, handle) != DDI_SUCCESS) {
		cardbus_err(dip, 1,
		    "Failed to setup registers for [0x%x][0x%x][0x%x]\n",
		    PCI_REG_BUS_G(reg->pci_phys_hi),
		    PCI_REG_DEV_G(reg->pci_phys_hi),
		    PCI_REG_FUNC_G(reg->pci_phys_hi));
		kmem_free((caddr_t)reg, rlen);
		return (PCICFG_FAILURE);
	}

	cardbus_err(dip, 9,
	    "PROBING =>->->->->->-> [0x%x][0x%x][0x%x] 0x%x 0x%p\n",
	    PCI_REG_BUS_G(reg->pci_phys_hi),
	    PCI_REG_DEV_G(reg->pci_phys_hi),
	    PCI_REG_FUNC_G(reg->pci_phys_hi),
	    reg->pci_phys_hi, (void *) cfgaddr);

	/*
	 * must do peek16 otherwise the system crashes when probing
	 * a non zero function on a non-multi-function card.
	 */
#ifdef sparc
	if (ddi_peek16(anode, (int16_t *)cfgaddr, &val) != DDI_SUCCESS) {
		cardbus_err(dip, 8,
		    "cardbus_config_setup peek failed\n");
		ret = PCICFG_NODEVICE;
	} else if (ddi_get16(*handle, (uint16_t *)cfgaddr) == 0xffff) {
		cardbus_err(dip, 8,
		    "cardbus_config_setup PCICFG_NODEVICE\n");
		ret = PCICFG_NODEVICE;
#elif defined(__x86)
	if (ddi_get16(*handle, (uint16_t *)cfgaddr) == 0xffff) {
		cardbus_err(dip, 8,
		    "cardbus_config_setup PCICFG_NODEVICE\n");
		ret = PCICFG_NODEVICE;
#endif
	} else {
		cardbus_err(dip, 1,
		    "cardbus_config_setup found device at:[0x%x][0x%x][0x%x]\n",
		    PCI_REG_BUS_G(reg->pci_phys_hi),
		    PCI_REG_DEV_G(reg->pci_phys_hi),
		    PCI_REG_FUNC_G(reg->pci_phys_hi));

		ret = PCICFG_SUCCESS;
	}

	kmem_free((caddr_t)reg, rlen);
	if (ret != PCICFG_SUCCESS) {
		cardbus_config_teardown(handle);
	}

	cardbus_err(dip, 7,
	    "cardbus_config_setup returning %d\n", ret);

	return (ret);
}

static void
cardbus_config_teardown(ddi_acc_handle_t *handle)
{
	(void) ddi_regs_map_free(handle);
}

static void
cardbus_reparent_children(dev_info_t *dip, dev_info_t *parent)
{
	dev_info_t *child;

	while (child = ddi_get_child(dip)) {
		ASSERT(i_ddi_node_state(child) <= DS_LINKED);
		/*
		 * Unlink node from tree before reparenting
		 */
		ndi_devi_enter(dip);
		(void) i_ndi_unconfig_node(child, DS_PROTO, 0);
		ndi_devi_exit(dip);
		DEVI(child)->devi_parent = DEVI(parent);
		DEVI(child)->devi_bus_ctl = DEVI(parent);
		ndi_devi_enter(parent);
		(void) i_ndi_config_node(child, DS_LINKED, 0);
		ndi_devi_exit(parent);
	}
}

static int
cardbus_update_assigned_prop(dev_info_t *dip, pci_regspec_t *newone)
{
	int		alen;
	pci_regspec_t	*assigned;
	caddr_t		newreg;
	uint_t		status;

	status = ddi_getlongprop(DDI_DEV_T_NONE, dip, DDI_PROP_DONTPASS,
	    "assigned-addresses", (caddr_t)&assigned, &alen);
	switch (status) {
	case DDI_PROP_SUCCESS:
		cardbus_err(dip, 5,
		    "cardbus_update_assigned_prop: found prop len %d\n",
		    alen);
		/*
		 * Allocate memory for the existing
		 * assigned-addresses(s) plus one and then
		 * build it.
		 */
		newreg = kmem_zalloc(alen+sizeof (*newone), KM_SLEEP);

		bcopy(assigned, newreg, alen);
		bcopy(newone, newreg + alen, sizeof (*newone));
		break;

	case DDI_PROP_NO_MEMORY:
		cardbus_err(dip, 1,
		    "no memory for assigned-addresses property\n");
		return (PCICFG_FAILURE);

	default:
		cardbus_err(dip, 5,
		    "cardbus_update_assigned_prop: creating prop\n");
		alen = 0;
		newreg = (caddr_t)newone;
		break;
	}

	/*
	 * Write out the new "assigned-addresses" spec
	 */
	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip,
	    "assigned-addresses", (int *)newreg,
	    (alen + sizeof (*newone))/sizeof (int));

	if (status == DDI_PROP_SUCCESS)
		kmem_free((caddr_t)newreg, alen+sizeof (*newone));

	if (alen)
		kmem_free(assigned, alen);

	return (PCICFG_SUCCESS);
}

static int
cardbus_update_available_prop(dev_info_t *dip, uint32_t hi_type,
				uint64_t base, uint64_t size)
{
	int		alen, rlen;
	pci_regspec_t	*available, *reg;
	pci_regspec_t	addition;
	caddr_t		newreg;
	uint_t		status;

	cardbus_err(dip, 6, "cardbus_update_available_prop\n");

	status = ddi_getlongprop(DDI_DEV_T_NONE, dip, DDI_PROP_DONTPASS,
	    "reg", (caddr_t)&reg, &rlen);

	switch (status) {
	case DDI_PROP_SUCCESS:
		break;
	case DDI_PROP_NO_MEMORY:
		cardbus_err(dip, 1, "reg present, but unable to get memory\n");
		return (PCICFG_FAILURE);
	default:
		cardbus_err(dip, 1, "no reg property\n");
		return (PCICFG_FAILURE);
	}

	status = ddi_getlongprop(DDI_DEV_T_NONE, dip, DDI_PROP_DONTPASS,
	    "available", (caddr_t)&available, &alen);
	switch (status) {
	case DDI_PROP_SUCCESS:
		break;
	case DDI_PROP_NO_MEMORY:
		cardbus_err(dip, 1, "no memory for available property\n");
		kmem_free((caddr_t)reg, rlen);
		return (PCICFG_FAILURE);
	default:
		alen = 0;
	}

	/*
	 * Allocate memory for the existing
	 * available(s) plus one and then
	 * build it.
	 */
	newreg = kmem_zalloc(alen + sizeof (pci_regspec_t), KM_SLEEP);

	/*
	 * Build the regspec, then add it to the existing one(s)
	 */
	addition.pci_phys_hi = hi_type |
	    PCICFG_MAKE_REG_HIGH(PCI_REG_BUS_G(reg->pci_phys_hi),
	    PCI_REG_DEV_G(reg->pci_phys_hi),
	    PCI_REG_FUNC_G(reg->pci_phys_hi), 0);

	addition.pci_phys_mid = (uint32_t)((base>>32) & 0xffffffff);
	addition.pci_phys_low = (uint32_t)(base & 0xffffffff);
	addition.pci_size_hi = (uint32_t)((size>>32) & 0xffffffff);
	addition.pci_size_low = (uint32_t)(size & 0xffffffff);

#ifdef DEBUG
	cardbus_dump_reg(dip, &addition, 1);
#endif

	if (alen)
		bcopy(available, newreg, alen);
	bcopy(&addition, newreg + alen, sizeof (pci_regspec_t));

	/*
	 * Write out the new "available" spec
	 */
	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip,
	    "available", (int *)newreg,
	    (alen + sizeof (pci_regspec_t))/sizeof (int));

	if (alen)
		kmem_free((caddr_t)available, alen);
	kmem_free((caddr_t)reg, rlen);
	kmem_free((caddr_t)newreg, alen + sizeof (pci_regspec_t));

	return (PCICFG_SUCCESS);
}

static int
cardbus_update_ranges_prop(dev_info_t *dip, cardbus_range_t *addition)
{
	int		rlen;
	cardbus_range_t	*ranges;
	caddr_t		newreg;
	uint_t		status;
#if defined(CARDBUS_DEBUG)
	int	i, nrange;
	const cardbus_range_t	*nr;
#endif

	cardbus_err(dip, 6, "cardbus_update_ranges_prop\n");

	status = ddi_getlongprop(DDI_DEV_T_NONE,
	    dip, DDI_PROP_DONTPASS, "ranges",
	    (caddr_t)&ranges, &rlen);

	switch (status) {
	case DDI_PROP_SUCCESS:
		break;
	case DDI_PROP_NO_MEMORY:
		cardbus_err(dip, 1,
		    "ranges present, but unable to get memory\n");
		return (PCICFG_FAILURE);
	default:
		cardbus_err(dip, 8, "no ranges property - creating one\n");
		if (ndi_prop_update_int_array(DDI_DEV_T_NONE,
		    dip, "ranges", (int *)addition,
		    sizeof (cardbus_range_t)/sizeof (int))
		    != DDI_SUCCESS) {
			cardbus_err(dip, 1, "Did'nt create ranges property\n");
			return (PCICFG_FAILURE);
		}
		return (PCICFG_SUCCESS);
	}

	/*
	 * Allocate memory for the existing reg(s) plus one and then
	 * build it.
	 */
	newreg = kmem_zalloc(rlen+sizeof (cardbus_range_t), KM_SLEEP);

	bcopy(ranges, newreg, rlen);
	bcopy(addition, newreg + rlen, sizeof (cardbus_range_t));

	/*
	 * Write out the new "ranges" property
	 */
	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE,
	    dip, "ranges", (int *)newreg,
	    (rlen + sizeof (cardbus_range_t))/sizeof (int));

#if defined(CARDBUS_DEBUG)
	cardbus_err(dip, 8, "cardbus_update_ranges_prop ranges property:\n");

	nrange = rlen / sizeof (cardbus_range_t);
	nr = (cardbus_range_t *)newreg;
	for (i = 0; i <= nrange; i++) {
		/* nrange is one higher for new entry */
		cardbus_err(dip, 9,
		    "\trange parent addr 0x%x.0x%x.0x%x "
		    "child addr 0x%x.0x%x.0x%x size 0x%x.0x%x\n",
		    nr->parent_hi,
		    nr->parent_mid, nr->parent_lo,
		    nr->child_hi,
		    nr->child_mid, nr->child_lo,
		    nr->size_hi, nr->size_lo);
		nr++;
	}
#endif

	kmem_free((caddr_t)newreg, rlen+sizeof (cardbus_range_t));
	kmem_free((caddr_t)ranges, rlen);

	return (PCICFG_SUCCESS);
}

static int
cardbus_update_reg_prop(dev_info_t *dip, uint32_t regvalue, uint_t reg_offset)
{
	int	rlen;
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
		cardbus_err(dip, 1, "reg present, but unable to get memory\n");
		return (PCICFG_FAILURE);
	default:
		cardbus_err(dip, 1, "no reg property\n");
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
			PCI_REG_FUNC_G(reg->pci_phys_hi),
			reg_offset);

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
				/*
				 * This is a 64 bit PCI memory space.
				 * It needs to be allocated as 32 bit
				 * for bus map purposes.
				 */
				hiword |= PCI_ADDR_MEM32;
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

	cardbus_err(dip, 8,
	    "cardbus_update_reg_prop, phys_hi 0x%08x,"
	    " phys_mid 0x%08x, phys_low 0x%08x, size_hi 0x%08x,"
	    " size_low 0x%08x\n", hiword, 0, 0, 0, size);

	bcopy(reg, newreg, rlen);
	bcopy(&addition, newreg + rlen, sizeof (pci_regspec_t));

	/*
	 * Write out the new "reg" property
	 */
	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE,
	    dip, "reg", (int *)newreg,
	    (rlen + sizeof (pci_regspec_t))/sizeof (int));

	kmem_free((caddr_t)reg, rlen);
	kmem_free((caddr_t)newreg, rlen+sizeof (pci_regspec_t));

	return (PCICFG_SUCCESS);
}

/*
 * Setup the basic 1275 properties based on information found in the config
 * header of the PCI device
 */
static int
cardbus_set_standard_props(dev_info_t *parent, dev_info_t *dip,
			ddi_acc_handle_t config_handle)
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
			cardbus_err(dip, 1, "Failed to sent min-grant\n");
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

	/*
	 * according to section 6.2.1 of revision 2 of the PCI local
	 * bus specification - 0FFFFh is an invalid value for the vendor ID
	 */
	if (val == 0xffff) {
		cardbus_err(dip, 1, "Illegal vendor-id 0x%x\n", val);
		return (PCICFG_FAILURE);
	}
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
	    PCI_CONF_STAT) & PCI_STAT_DEVSELT) >> 9;
	if ((ret = ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "devsel-speed", val)) != DDI_SUCCESS) {
		return (ret);
	}

	/*
	 * The next three are bits set in the status register.  The property is
	 * present (but with no value other than its own existence) if the bit
	 * is set, non-existent otherwise
	 */
	if (ddi_prop_exists(DDI_DEV_T_ANY, parent, DDI_PROP_DONTPASS,
	    "fast-back-to-back") &&
	    pci_config_get16(config_handle, PCI_CONF_STAT) & PCI_STAT_FBBC) {

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

	/* look in the correct place for header type 2 */
	byteval = pci_config_get8(config_handle, PCI_CONF_HEADER);
	if ((byteval & PCI_HEADER_TYPE_M) == PCI_HEADER_TWO) {
		if ((val = pci_config_get16(config_handle,
		    PCI_CBUS_SUBVENID)) != 0) {
			if ((ret = ndi_prop_update_int(DDI_DEV_T_NONE, dip,
			    "subsystem-vendor-id", val)) != DDI_SUCCESS) {
				return (ret);
			}
		}
		if ((val = pci_config_get16(config_handle,
		    PCI_CBUS_SUBSYSID)) != 0) {
			if ((ret = ndi_prop_update_int(DDI_DEV_T_NONE, dip,
			    "subsystem-id", val)) != DDI_SUCCESS) {
				return (ret);
			}
		}
	} else {
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
	}

	if ((val = pci_config_get8(config_handle,
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
		cardbus_err(dip, 8, "Adding interrupts property\n");
		if ((ret = ndi_prop_update_int(DDI_DEV_T_NONE, dip,
		    "interrupts", byteval)) != DDI_SUCCESS) {
			return (ret);
		}
	}
	return (PCICFG_SUCCESS);
}

/*
 * Setup the basic properties required by the ISA node.
 */
static int
cardbus_set_isa_props(dev_info_t *parent, dev_info_t *dip,
			char *name, char *compat[])
{
	int ret, n;

	_NOTE(ARGUNUSED(parent))

	cardbus_err(dip, 8, "Adding interrupts property\n");
	if ((ret = ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "interrupts", 1)) != DDI_SUCCESS) {
		return (ret);
	}

	/*
	 * The node name field needs to be filled in with the name
	 */
	if (ndi_devi_set_nodename(dip, name, 0) != NDI_SUCCESS) {
		cardbus_err(dip, 1, "Failed to set nodename for node\n");
		return (PCICFG_FAILURE);
	}

	/*
	 * Create the compatible property as an array of pointers
	 * to strings.  Start with the buffer created above.
	 */
	n = 0;
	while (compat[n] != NULL)
		n++;

	if (n != 0)
		if ((ret = ndi_prop_update_string_array(DDI_DEV_T_NONE, dip,
		    "compatible", compat, n)) != DDI_SUCCESS)
			return (ret);

	return (PCICFG_SUCCESS);
}

static int
cardbus_set_busnode_props(dev_info_t *dip)
{
	cardbus_err(dip, 6, "cardbus_set_busnode_props\n");

	cardbus_force_stringprop(dip, "device_type", "pci");

	if (ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "#address-cells", 3) != DDI_SUCCESS) {
		cardbus_err(dip, 4, "Failed to set #address-cells\n");
	}
	if (ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "#size-cells", 2) != DDI_SUCCESS) {
		cardbus_err(dip, 4, "Failed to set #size-cells\n");
	}
	return (PCICFG_SUCCESS);
}

static int
cardbus_set_busnode_isaprops(dev_info_t *dip)
{
	cardbus_err(dip, 6, "cardbus_set_busnode_props\n");

	cardbus_force_stringprop(dip, "device_type", "isa");

	if (ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "#address-cells", 2) != DDI_SUCCESS) {
		cardbus_err(dip, 4, "Failed to set #address-cells\n");
	}
	if (ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "#size-cells", 1) != DDI_SUCCESS) {
		cardbus_err(dip, 4, "Failed to set #size-cells\n");
	}
	return (PCICFG_SUCCESS);
}

/*
 * Use cb%x,%x rather than pci%x,%x so that we can use specific cardbus
 * drivers in /etc/driver_aliases if required
 */
static int
cardbus_set_childnode_props(dev_info_t *dip, ddi_acc_handle_t config_handle)
{
	int		ret;
#ifndef _DONT_USE_1275_GENERIC_NAMES
	uint32_t	wordval;
#endif
	char		*name;
	char		buffer[64];
	uint32_t	classcode;
	char		*compat[8];
	int		i, n;
	uint16_t	subsysid, subvenid, devid, venid;
	uint8_t		header_type;

	/*
	 * NOTE: These are for both a child and PCI-PCI bridge node
	 */
#ifndef _DONT_USE_1275_GENERIC_NAMES
	wordval = (pci_config_get16(config_handle, PCI_CONF_SUBCLASS)<< 8) |
	    (pci_config_get8(config_handle, PCI_CONF_PROGCLASS));
#endif

	/* Cardbus support */
	venid = pci_config_get16(config_handle, PCI_CONF_VENID);
	devid = pci_config_get16(config_handle, PCI_CONF_DEVID);

	header_type = pci_config_get8(config_handle, PCI_CONF_HEADER);
	if ((header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_TWO) {
		subvenid = pci_config_get16(config_handle, PCI_CBUS_SUBVENID);
		subsysid = pci_config_get16(config_handle, PCI_CBUS_SUBSYSID);
	} else {
		subvenid = pci_config_get16(config_handle, PCI_CONF_SUBVENID);
		subsysid = pci_config_get16(config_handle, PCI_CONF_SUBSYSID);
	}

	if (subsysid != 0) {
		(void) sprintf(buffer, "pci%x,%x", subvenid, subsysid);
	} else {
		(void) sprintf(buffer, "pci%x,%x", venid, devid);
	}

	cardbus_err(dip, 8, "Childname is %s\n", buffer);

	/*
	 * In some environments, trying to use "generic" 1275 names is
	 * not the convention.  In those cases use the name as created
	 * above.  In all the rest of the cases, check to see if there
	 * is a generic name first.
	 */
#ifdef _DONT_USE_1275_GENERIC_NAMES
	name = buffer;
#else
	if ((name = cardbus_get_class_name(wordval>>8)) == NULL) {
		/*
		 * Set name to the above fabricated name
		 */
		name = buffer;
	}

	cardbus_err(dip, 8, "Set nodename to %s\n", name);
#endif

	/*
	 * The node name field needs to be filled in with the name
	 */
	if (ndi_devi_set_nodename(dip, name, 0) != NDI_SUCCESS) {
		cardbus_err(dip, 1, "Failed to set nodename for node\n");
		return (PCICFG_FAILURE);
	}

	/*
	 * Create the compatible property as an array of pointers
	 * to strings.  Start with the cb name.
	 */
	n = 0;

	if (subsysid != 0) {
		(void) sprintf(buffer, "cb%x,%x", subvenid, subsysid);
	} else {
		(void) sprintf(buffer, "cb%x,%x", venid, devid);
	}

	compat[n] = kmem_alloc(strlen(buffer) + 1, KM_SLEEP);
	(void) strcpy(compat[n++], buffer);

	if (subsysid != 0) {
		/*
		 * Add subsys numbers as pci compatible.
		 */
		(void) sprintf(buffer, "pci%x,%x", subvenid, subsysid);
		compat[n] = kmem_alloc(strlen(buffer) + 1, KM_SLEEP);
		(void) strcpy(compat[n++], buffer);
	}

	/*
	 * Add in the VendorID/DeviceID compatible name.
	 */
	(void) sprintf(buffer, "pci%x,%x", venid, devid);

	compat[n] = kmem_alloc(strlen(buffer) + 1, KM_SLEEP);
	(void) strcpy(compat[n++], buffer);

	classcode = (pci_config_get16(config_handle, PCI_CONF_SUBCLASS)<< 8) |
	    (pci_config_get8(config_handle, PCI_CONF_PROGCLASS));

	/*
	 * Add in the Classcode
	 */
	(void) sprintf(buffer, "pciclass,%06x", classcode);

	cardbus_err(dip, 8, "class code %s\n", buffer);

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
cardbus_set_bus_numbers(ddi_acc_handle_t config_handle,
			uint_t primary, uint_t secondary)
{
	cardbus_err(NULL, 8,
	    "cardbus_set_bus_numbers [%d->%d]\n", primary, secondary);

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
	 * Note that this is reduced once the probe is complete in the
	 * cardbus_setup_bridge() function.
	 */
	pci_config_put8(config_handle, PCI_BCNF_SUBBUS, 0xFF);
}

static void
enable_pci_isa_bridge(dev_info_t *dip, ddi_acc_handle_t config_handle)
{
	uint16_t comm, stat;

	stat = pci_config_get16(config_handle, PCI_CONF_STAT);
	comm = pci_config_get16(config_handle, PCI_CONF_COMM);

	/*
	 * Enable memory, IO, bus mastership and error detection.
	 */
	comm |= (PCI_COMM_ME | PCI_COMM_MAE | PCI_COMM_IO |
	    PCI_COMM_PARITY_DETECT | PCI_COMM_SERR_ENABLE);
	if (ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "fast-back-to-back"))
		comm |= PCI_COMM_BACK2BACK_ENAB;
	pci_config_put16(config_handle, PCI_CONF_COMM, comm);
	cardbus_err(NULL, 8,
	    "enable_pci_isa_bridge stat 0x%04x comm 0x%04x\n", stat, comm);

	/*
	 * ITE8888 Specific registers.
	 */
	pci_config_put8(config_handle, 0x50, 0x00); /* Timing Control */
	pci_config_put8(config_handle, 0x52, 0x00); /* Master DMA Access */
	pci_config_put8(config_handle, 0x53, 0x01); /* ROMCS */
}

static void
enable_pci_pci_bridge(dev_info_t *dip, ddi_acc_handle_t config_handle)
{
	uint16_t comm, stat, bctrl;

	stat = pci_config_get16(config_handle, PCI_CONF_STAT);
	comm = pci_config_get16(config_handle, PCI_CONF_COMM);
	bctrl = pci_config_get16(config_handle, PCI_CBUS_BRIDGE_CTRL);

	comm &= ~(PCI_COMM_IO | PCI_COMM_MAE);
	comm |= (PCI_COMM_ME | PCI_COMM_PARITY_DETECT | PCI_COMM_SERR_ENABLE);

	/*
	 * Enable back to back.
	 */
	if (stat & PCI_STAT_FBBC)
		comm |= PCI_COMM_BACK2BACK_ENAB;

	pci_config_put16(config_handle, PCI_CONF_COMM, comm);

	/*
	 * Reset the sub-ordinate bus.
	 */
	if (!(bctrl & PCI_BCNF_BCNTRL_RESET))
		pci_config_put16(config_handle, PCI_CBUS_BRIDGE_CTRL,
			bctrl | PCI_BCNF_BCNTRL_RESET);
	else
		bctrl &= ~PCI_BCNF_BCNTRL_RESET;

	/*
	 * Enable error reporting.
	 */
	bctrl |= (PCI_BCNF_BCNTRL_PARITY_ENABLE | PCI_BCNF_BCNTRL_SERR_ENABLE |
	    PCI_BCNF_BCNTRL_MAST_AB_MODE);

	/*
	 * Enable back to back on secondary bus.
	 */
	if (stat & PCI_STAT_FBBC)
		bctrl |= PCI_BCNF_BCNTRL_B2B_ENAB;

	pci_config_put16(config_handle, PCI_CBUS_BRIDGE_CTRL, bctrl);
	cardbus_err(dip, 8,
	    "enable_pci_pci_bridge stat 0x%04x comm 0x%04x bctrl 0x%04x\n",
	    stat, comm, bctrl);
}

static int	cardbus_reset_wait = 20;

static void
enable_cardbus_bridge(dev_info_t *dip, ddi_acc_handle_t config_handle)
{
	uint16_t comm, stat, bctrl;

	stat = pci_config_get16(config_handle, PCI_CONF_STAT);
	comm = pci_config_get16(config_handle, PCI_CONF_COMM);
	bctrl = pci_config_get16(config_handle, PCI_CBUS_BRIDGE_CTRL);

	/*
	 * Don't mess with the command register on the cardbus bridge
	 * itself. This should have been done when it's parent
	 * did the setup. Some devices *require* certain things to
	 * disabled, this can be done using the "command-preserve"
	 * property and if we mess with it here it breaks that.
	 *
	 * comm |= (PCI_COMM_ME | PCI_COMM_PARITY_DETECT |
	 *	PCI_COMM_SERR_ENABLE);
	 */

	/*
	 * Reset the sub-ordinate bus.
	 */
	if (!(bctrl & PCI_BCNF_BCNTRL_RESET))
		pci_config_put16(config_handle, PCI_CBUS_BRIDGE_CTRL,
			bctrl | PCI_BCNF_BCNTRL_RESET);
	else
		bctrl &= ~PCI_BCNF_BCNTRL_RESET;

	/*
	 * Turn off pre-fetch.
	 */
	bctrl &= ~(CB_BCNF_BCNTRL_MEM0_PREF | CB_BCNF_BCNTRL_MEM1_PREF |
	    PCI_BCNF_BCNTRL_PARITY_ENABLE | PCI_BCNF_BCNTRL_SERR_ENABLE);

	/*
	 * Enable error reporting.
	 */
	bctrl |= (PCI_BCNF_BCNTRL_MAST_AB_MODE | CB_BCNF_BCNTRL_WRITE_POST);
	if (comm & PCI_COMM_PARITY_DETECT)
		bctrl |= PCI_BCNF_BCNTRL_PARITY_ENABLE;
	if (comm & PCI_COMM_SERR_ENABLE)
		bctrl |= PCI_BCNF_BCNTRL_SERR_ENABLE;

	pci_config_put16(config_handle, PCI_CBUS_BRIDGE_CTRL, bctrl);
	pci_config_put8(config_handle, PCI_CBUS_LATENCY_TIMER,
	    cardbus_latency_timer);

	pci_config_put16(config_handle, PCI_CONF_STAT, stat);
	pci_config_put16(config_handle, PCI_CONF_COMM, comm);

	cardbus_err(dip, 8,
	    "enable_cardbus_bridge() stat 0x%04x comm 0x%04x bctrl 0x%04x\n",
	    stat, comm, bctrl);

	/* after resetting the bridge, wait for everything to stablize */
	delay(drv_usectohz(cardbus_reset_wait * 1000));

}

static void
disable_pci_pci_bridge(dev_info_t *dip, ddi_acc_handle_t config_handle)
{
	uint16_t comm, bctrl;

	comm = pci_config_get16(config_handle, PCI_CONF_COMM);
	bctrl = pci_config_get16(config_handle, PCI_CBUS_BRIDGE_CTRL);

	/*
	 * Turn off subordinate bus access.
	 */
	pci_config_put8(config_handle, PCI_BCNF_SECBUS, 0);
	pci_config_put8(config_handle, PCI_BCNF_SUBBUS, 0);

	/*
	 * Disable error reporting.
	 */
	bctrl &= ~(PCI_BCNF_BCNTRL_PARITY_ENABLE | PCI_BCNF_BCNTRL_SERR_ENABLE |
	    PCI_BCNF_BCNTRL_MAST_AB_MODE);
	comm = 0;

	pci_config_put16(config_handle, PCI_CONF_COMM, comm);
	pci_config_put16(config_handle, PCI_CBUS_BRIDGE_CTRL, bctrl);

	cardbus_err(dip, 6,
	    "disable_pci_pci_bridge() stat 0x%04x comm 0x%04x bctrl 0x%04x\n",
	    pci_config_get16(config_handle, PCI_CONF_STAT), comm, bctrl);
}

static void
disable_cardbus_bridge(dev_info_t *dip, ddi_acc_handle_t config_handle)
{
	uint16_t comm, bctrl;

	comm = pci_config_get16(config_handle, PCI_CONF_COMM);
	bctrl = pci_config_get16(config_handle, PCI_CBUS_BRIDGE_CTRL);

	/*
	 * Turn off subordinate bus access.
	 */
	pci_config_put8(config_handle, PCI_BCNF_SECBUS, 0);
	pci_config_put8(config_handle, PCI_BCNF_SUBBUS, 0);

	/*
	 * Disable error reporting.
	 */
	bctrl &= ~(PCI_BCNF_BCNTRL_PARITY_ENABLE | PCI_BCNF_BCNTRL_SERR_ENABLE |
	    PCI_BCNF_BCNTRL_MAST_AB_MODE);

	pci_config_put32(config_handle, PCI_CBUS_MEM_LIMIT0, 0);
	pci_config_put32(config_handle, PCI_CBUS_MEM_BASE0, 0);
	pci_config_put32(config_handle, PCI_CBUS_IO_LIMIT0, 0);
	pci_config_put32(config_handle, PCI_CBUS_IO_BASE0, 0);
	pci_config_put16(config_handle, PCI_CONF_COMM, comm);
	pci_config_put16(config_handle, PCI_CBUS_BRIDGE_CTRL, bctrl);

	cardbus_err(dip, 6,
	    "disable_cardbus_bridge() stat 0x%04x comm 0x%04x bctrl 0x%04x\n",
	    pci_config_get16(config_handle, PCI_CONF_STAT), comm, bctrl);
}

static void
enable_cardbus_device(dev_info_t *dip, ddi_acc_handle_t config_handle)
{
	uint16_t comm, stat;

	stat = pci_config_get16(config_handle, PCI_CONF_STAT);
	comm = pci_config_get16(config_handle, PCI_CONF_COMM);

	/*
	 * Enable memory, IO, bus mastership and error detection.
	 */
	comm |= (PCI_COMM_ME | PCI_COMM_MAE | PCI_COMM_IO |
	    PCI_COMM_PARITY_DETECT | PCI_COMM_SERR_ENABLE);
	if (ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "fast-back-to-back"))
		comm |= PCI_COMM_BACK2BACK_ENAB;
	pci_config_put16(config_handle, PCI_CONF_COMM, comm);
	cardbus_err(NULL, 8,
	    "enable_cardbus_device stat 0x%04x comm 0x%04x\n", stat, comm);
}

static void
disable_cardbus_device(ddi_acc_handle_t config_handle)
{
	cardbus_err(NULL, 8, "disable_cardbus_device\n");

	/*
	 * Turn off everything in the command register.
	 */
	pci_config_put16(config_handle, PCI_CONF_COMM, 0x0);
}

#ifndef _DONT_USE_1275_GENERIC_NAMES
static char *
cardbus_get_class_name(uint32_t classcode)
{
	struct cardbus_name_entry *ptr;

	for (ptr = &cardbus_class_lookup[0]; ptr->name != NULL; ptr++) {
		if (ptr->class_code == classcode) {
			return (ptr->name);
		}
	}
	return (NULL);
}
#endif /* _DONT_USE_1275_GENERIC_NAMES */

static void
cardbus_force_boolprop(dev_info_t *dip, char *pname)
{
	int ret;

	if ((ret = ndi_prop_create_boolean(DDI_DEV_T_NONE, dip,
	    pname)) != DDI_SUCCESS) {
		if (ret == DDI_PROP_NOT_FOUND)
			if (ddi_prop_create(DDI_DEV_T_NONE, dip,
			    DDI_PROP_CANSLEEP, pname,
			    (caddr_t)NULL, 0) != DDI_SUCCESS)
				cardbus_err(dip, 4,
				    "Failed to set boolean property "
				    "\"%s\"\n", pname);
	}
}

static void
cardbus_force_intprop(dev_info_t *dip, char *pname, int *pval, int len)
{
	int ret;

	if ((ret = ndi_prop_update_int_array(DDI_DEV_T_NONE, dip,
	    pname, pval, len)) != DDI_SUCCESS) {
		if (ret == DDI_PROP_NOT_FOUND)
			if (ddi_prop_create(DDI_DEV_T_NONE, dip,
			    DDI_PROP_CANSLEEP, pname,
			    (caddr_t)pval, len*sizeof (int))
			    != DDI_SUCCESS)
				cardbus_err(dip, 4,
				    "Failed to set int property \"%s\"\n",
				    pname);
	}
}

static void
cardbus_force_stringprop(dev_info_t *dip, char *pname, char *pval)
{
	int ret;

	if ((ret = ndi_prop_update_string(DDI_DEV_T_NONE, dip,
	    pname, pval)) != DDI_SUCCESS) {
		if (ret == DDI_PROP_NOT_FOUND)
			if (ddi_prop_create(DDI_DEV_T_NONE, dip,
			    DDI_PROP_CANSLEEP, pname,
			    pval, strlen(pval) + 1) != DDI_SUCCESS)
				cardbus_err(dip, 4,
				    "Failed to set string property "
				    "\"%s\" to \"%s\"\n",
				    pname, pval);
	}
}

static void
split_addr(char *naddr, int *dev, int *func)
{
	char	c;
	int	*ip = dev;

	*dev = 0;
	*func = 0;

	while (c = *naddr++) {
		if (c == ',') {
			ip = func;
			continue;
		}
		if (c >= '0' && c <= '9') {
			*ip = (*ip * 16) + (c - '0');
		} else if (c >= 'a' && c <= 'f') {
			*ip = (*ip * 16) + 10 + (c - 'a');
		} else
			break;
	}
}

#ifdef DEBUG
static void
cardbus_dump_common_config(ddi_acc_handle_t config_handle)
{
	cardbus_err(NULL, 1,
	    " Vendor ID   = [0x%04x]        "
	    "Device ID   = [0x%04x]\n",
	    pci_config_get16(config_handle, PCI_CONF_VENID),
	    pci_config_get16(config_handle, PCI_CONF_DEVID));
	cardbus_err(NULL, 1,
	    " Command REG = [0x%04x]        "
	    "Status  REG = [0x%04x]\n",
	    pci_config_get16(config_handle, PCI_CONF_COMM),
	    pci_config_get16(config_handle, PCI_CONF_STAT));
	cardbus_err(NULL, 1,
	    " Revision ID = [0x%02x]          "
	    "Prog Class  = [0x%02x]\n",
	    pci_config_get8(config_handle, PCI_CONF_REVID),
	    pci_config_get8(config_handle, PCI_CONF_PROGCLASS));
	cardbus_err(NULL, 1,
	    " Dev Class   = [0x%02x]          "
	    "Base Class  = [0x%02x]\n",
	    pci_config_get8(config_handle, PCI_CONF_SUBCLASS),
	    pci_config_get8(config_handle, PCI_CONF_BASCLASS));
	cardbus_err(NULL, 1,
	    " Cache LnSz  = [0x%02x]          "
	    "Latency Tmr = [0x%02x]\n",
	    pci_config_get8(config_handle, PCI_CONF_CACHE_LINESZ),
	    pci_config_get8(config_handle, PCI_CONF_LATENCY_TIMER));
	cardbus_err(NULL, 1,
	    " Header Type = [0x%02x]          "
	    "BIST        = [0x%02x]\n",
	    pci_config_get8(config_handle, PCI_CONF_HEADER),
	    pci_config_get8(config_handle, PCI_CONF_BIST));
}

static void
cardbus_dump_device_config(ddi_acc_handle_t config_handle)
{
	cardbus_dump_common_config(config_handle);

	cardbus_err(NULL, 1,
	    " BASE 0      = [0x%08x]	BASE 1      = [0x%08x]\n",
	    pci_config_get32(config_handle, PCI_CONF_BASE0),
	    pci_config_get32(config_handle, PCI_CONF_BASE1));
	cardbus_err(NULL, 1,
	    " BASE 2      = [0x%08x]	BASE 3      = [0x%08x]\n",
	    pci_config_get32(config_handle, PCI_CONF_BASE2),
	    pci_config_get32(config_handle, PCI_CONF_BASE3));
	cardbus_err(NULL, 1,
	    " BASE 4      = [0x%08x]	BASE 5      = [0x%08x]\n",
	    pci_config_get32(config_handle, PCI_CONF_BASE4),
	    pci_config_get32(config_handle, PCI_CONF_BASE5));
	cardbus_err(NULL, 1,
	    " Cardbus CIS = [0x%08x]	ROM         = [0x%08x]\n",
	    pci_config_get32(config_handle, PCI_CONF_CIS),
	    pci_config_get32(config_handle, PCI_CONF_ROM));
	cardbus_err(NULL, 1,
	    " Sub VID     = [0x%04x]	Sub SID     = [0x%04x]\n",
	    pci_config_get16(config_handle, PCI_CONF_SUBVENID),
	    pci_config_get16(config_handle, PCI_CONF_SUBSYSID));
	cardbus_err(NULL, 1,
	    " I Line      = [0x%02x]	I Pin       = [0x%02x]\n",
	    pci_config_get8(config_handle, PCI_CONF_ILINE),
	    pci_config_get8(config_handle, PCI_CONF_IPIN));
	cardbus_err(NULL, 1,
	    " Max Grant   = [0x%02x]	Max Latent  = [0x%02x]\n",
	    pci_config_get8(config_handle, PCI_CONF_MIN_G),
	    pci_config_get8(config_handle, PCI_CONF_MAX_L));
}

static void
cardbus_dump_bridge_config(ddi_acc_handle_t config_handle,
			uint8_t header_type)
{
	if (header_type == PCI_HEADER_PPB) {
		cardbus_dump_common_config(config_handle);
		cardbus_err(NULL, 1,
		    "........................................\n");
	} else {
		cardbus_dump_common_config(config_handle);
		cardbus_err(NULL, 1,
		    " Mem Base    = [0x%08x]	CBus Status = [0x%04x]\n",
		    pci_config_get32(config_handle, PCI_CBUS_SOCK_REG),
		    pci_config_get16(config_handle, PCI_CBUS_SEC_STATUS));
	}

	cardbus_err(NULL, 1,
	    " Pri Bus	= [0x%02x]		Sec Bus	= [0x%02x]\n",
	    pci_config_get8(config_handle, PCI_BCNF_PRIBUS),
	    pci_config_get8(config_handle, PCI_BCNF_SECBUS));
	cardbus_err(NULL, 1,
	    " Sub Bus     = [0x%02x]		Sec Latency = [0x%02x]\n",
	    pci_config_get8(config_handle, PCI_BCNF_SUBBUS),
	    pci_config_get8(config_handle, PCI_BCNF_LATENCY_TIMER));

	switch (header_type) {
	case PCI_HEADER_PPB:
		cardbus_err(NULL, 1,
		    " I/O Base LO = [0x%02x]	I/O Lim LO  = [0x%02x]\n",
		    pci_config_get8(config_handle, PCI_BCNF_IO_BASE_LOW),
		    pci_config_get8(config_handle, PCI_BCNF_IO_LIMIT_LOW));
		cardbus_err(NULL, 1,
		    " Sec. Status = [0x%04x]\n",
		    pci_config_get16(config_handle, PCI_BCNF_SEC_STATUS));
		cardbus_err(NULL, 1,
		    " Mem Base    = [0x%04x]	Mem Limit   = [0x%04x]\n",
		    pci_config_get16(config_handle, PCI_BCNF_MEM_BASE),
		    pci_config_get16(config_handle, PCI_BCNF_MEM_LIMIT));
		cardbus_err(NULL, 1,
		    " PF Mem Base = [0x%04x]	PF Mem Lim  = [0x%04x]\n",
		    pci_config_get16(config_handle, PCI_BCNF_PF_BASE_LOW),
		    pci_config_get16(config_handle, PCI_BCNF_PF_LIMIT_LOW));
		cardbus_err(NULL, 1,
		    " PF Base HI  = [0x%08x]	PF Lim  HI  = [0x%08x]\n",
		    pci_config_get32(config_handle, PCI_BCNF_PF_BASE_HIGH),
		    pci_config_get32(config_handle, PCI_BCNF_PF_LIMIT_HIGH));
		cardbus_err(NULL, 1,
		    " I/O Base HI = [0x%04x]	I/O Lim HI  = [0x%04x]\n",
		    pci_config_get16(config_handle, PCI_BCNF_IO_BASE_HI),
		    pci_config_get16(config_handle, PCI_BCNF_IO_LIMIT_HI));
		cardbus_err(NULL, 1,
		    " ROM addr    = [0x%08x]\n",
		    pci_config_get32(config_handle, PCI_BCNF_ROM));
		break;
	case PCI_HEADER_CARDBUS:
		cardbus_err(NULL, 1,
		    " Mem Base 0  = [0x%08x]	Mem Limit 0 = [0x%08x]\n",
		    pci_config_get32(config_handle, PCI_CBUS_MEM_BASE0),
		    pci_config_get32(config_handle, PCI_CBUS_MEM_LIMIT0));
		cardbus_err(NULL, 1,
		    " Mem Base 1  = [0x%08x]	Mem Limit 1 = [0x%08x]\n",
		    pci_config_get32(config_handle, PCI_CBUS_MEM_BASE1),
		    pci_config_get32(config_handle, PCI_CBUS_MEM_LIMIT1));
		cardbus_err(NULL, 1,
		    " IO Base 0   = [0x%08x]	IO Limit 0  = [0x%08x]\n",
		    pci_config_get32(config_handle, PCI_CBUS_IO_BASE0),
		    pci_config_get32(config_handle, PCI_CBUS_IO_LIMIT0));
		cardbus_err(NULL, 1,
		    " IO Base 1   = [0x%08x]	IO Limit 1  = [0x%08x]\n",
		    pci_config_get32(config_handle, PCI_CBUS_IO_BASE1),
		    pci_config_get32(config_handle, PCI_CBUS_IO_LIMIT1));
		break;
	}
	cardbus_err(NULL, 1,
	    " Intr Line   = [0x%02x]		Intr Pin    = [0x%02x]\n",
	    pci_config_get8(config_handle, PCI_BCNF_ILINE),
	    pci_config_get8(config_handle, PCI_BCNF_IPIN));
	cardbus_err(NULL, 1,
	    " Bridge Ctrl = [0x%04x]\n",
	    pci_config_get16(config_handle, PCI_BCNF_BCNTRL));

	switch (header_type) {
	case PCI_HEADER_CARDBUS:
		cardbus_err(NULL, 1,
		    " Sub VID     = [0x%04x]	Sub SID     = [0x%04x]\n",
		    pci_config_get16(config_handle, PCI_CBUS_SUBVENID),
		    pci_config_get16(config_handle, PCI_CBUS_SUBSYSID));
		/* LATER: TI1250 only */
		cardbus_err(NULL, 1,
		    " Sys Control = [0x%08x]\n",
		    pci_config_get32(config_handle, 0x80));
	}
}

static void
cardbus_dump_config(ddi_acc_handle_t config_handle)
{
	uint8_t header_type = pci_config_get8(config_handle,
	    PCI_CONF_HEADER) & PCI_HEADER_TYPE_M;

	if (header_type == PCI_HEADER_PPB || header_type == PCI_HEADER_CARDBUS)
		cardbus_dump_bridge_config(config_handle, header_type);
	else
		cardbus_dump_device_config(config_handle);
}

static void
cardbus_dump_reg(dev_info_t *dip, const pci_regspec_t *regspec, int nelems)
{
	/* int rlen = nelems * sizeof(pci_regspec_t); */

	cardbus_err(dip, 6,
	    "cardbus_dump_reg: \"reg\" has %d elements\n", nelems);

#if defined(CARDBUS_DEBUG)
	if (cardbus_debug >= 1) {
		int	i;
		uint32_t *regs = (uint32_t *)regspec;

		for (i = 0; i < nelems; i++) {

			cardbus_err(NULL, 6,
			    "\t%d:%08x %08x %08x %08x %08x\n",
			    i, regs[0], regs[1], regs[2], regs[3], regs[4]);
		}
	}
#endif
}

#endif

#if defined(CARDBUS_DEBUG)
void
cardbus_dump_children(dev_info_t *dip, int level)
{
	dev_info_t *next;

	cardbus_err(dip, 1,
	    "\t%d: %s: 0x%p\n", level, ddi_node_name(dip), (void *) dip);
	for (next = ddi_get_child(dip); next;
	    next = ddi_get_next_sibling(next))
		cardbus_dump_children(next, level + 1);
}

void
cardbus_dump_family_tree(dev_info_t *dip)
{
	cardbus_err(dip, 1, "0x%p family tree:\n", (void *) dip);
	cardbus_dump_children(dip, 1);
}
#endif
