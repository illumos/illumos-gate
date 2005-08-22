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

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/sunndi.h>
#include <sys/pci.h>
#include <sys/pci_impl.h>
#include <sys/pci_cfgspace.h>
#include <sys/memlist.h>
#include <sys/bootconf.h>
#include "mps_table.h"
#include "../../../../common/pci/pci_strings.h"

#define	pci_getb	(*pci_getb_func)
#define	pci_getw	(*pci_getw_func)
#define	pci_getl	(*pci_getl_func)
#define	pci_putb	(*pci_putb_func)
#define	pci_putw	(*pci_putw_func)
#define	pci_putl	(*pci_putl_func)
#define	dcmn_err	if (pci_boot_debug) cmn_err

#define	CONFIG_INFO	0
#define	CONFIG_UPDATE	1
#define	CONFIG_NEW	2
#define	COMPAT_BUFSIZE	256

extern int pci_bios_nbus;
static uchar_t max_dev_pci = 32;	/* PCI standard */
int pci_boot_debug = 0;
extern struct memlist *find_bus_res(int, int);

/*
 * Module prototypes
 */
static void enumerate_bus_devs(uchar_t bus, int config_op);
static void create_root_bus_dip(uchar_t bus);
static dev_info_t *new_func_pci(uchar_t, uchar_t, uchar_t, uchar_t,
    ushort_t, int);
static void add_compatible(dev_info_t *, ushort_t, ushort_t,
    ushort_t, ushort_t, uchar_t, uint_t);
static int add_reg_props(dev_info_t *, uchar_t, uchar_t, uchar_t, int, int);
static void add_ppb_props(dev_info_t *, uchar_t, uchar_t, uchar_t);
static void add_model_prop(dev_info_t *, uint_t);
static void add_bus_range_prop(int);
static void add_ppb_ranges_prop(int);
static void add_bus_available_prop(int);
static void alloc_res_array();

/*
 * Enumerate all PCI devices
 */
void
pci_setup_tree()
{
	uchar_t i, root_bus_addr = 0;

	alloc_res_array();
	for (i = 0; i <= pci_bios_nbus; i++) {
		pci_bus_res[i].par_bus = (uchar_t)-1;
		pci_bus_res[i].root_addr = (uchar_t)-1;
		pci_bus_res[i].sub_bus = i;
	}

	pci_bus_res[0].root_addr = root_bus_addr++;
	create_root_bus_dip(0);
	enumerate_bus_devs(0, CONFIG_INFO);

	/*
	 * Now enumerate peer busses
	 *
	 * We loop till pci_bios_nbus. On most systems, there is
	 * one more bus at the high end, which implements the ISA
	 * compatibility bus. We don't care about that.
	 *
	 * Note: In the old (bootconf) enumeration, the peer bus
	 *	address did not use the bus number, and there were
	 *	too many peer busses created. The root_bus_addr is
	 *	used to maintain the old peer bus address assignment.
	 *	However, we stop enumerating phantom peers with no
	 *	device below.
	 */
	for (i = 1; i <= pci_bios_nbus; i++) {
		if (pci_bus_res[i].dip == NULL) {
			pci_bus_res[i].root_addr = root_bus_addr++;
		}
		enumerate_bus_devs(i, CONFIG_INFO);
	}

	/* add bus-range property for root/peer bus nodes */
	for (i = 0; i <= pci_bios_nbus; i++) {
		if (pci_bus_res[i].par_bus == (uchar_t)-1)
			add_bus_range_prop(i);
	}
}

void
pci_reprogram(void)
{
	int i, pci_reconfig = 1;
	char *onoff;

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, ddi_root_node(),
	    DDI_PROP_DONTPASS, "pci-reprog", &onoff) == DDI_SUCCESS) {
		if (strcmp(onoff, "off") == 0) {
			pci_reconfig = 0;
			cmn_err(CE_NOTE, "pci device reprogramming disabled");
		}
		ddi_prop_free(onoff);
	}

	for (i = 0; i <= pci_bios_nbus; i++) {
		/* configure devices not configured by bios */
		if (pci_reconfig)
			enumerate_bus_devs(i, CONFIG_NEW);
		/* All dev programmed, so we can create available prop */
		add_bus_available_prop(i);
	}
}

/*
 * Create top-level bus dips, i.e. /pci@0,0, /pci@1,0...
 */
static void
create_root_bus_dip(uchar_t bus)
{
	int pci_regs[] = {0, 0, 0};
	dev_info_t *dip;

	ASSERT(pci_bus_res[bus].par_bus == (uchar_t)-1);

	ndi_devi_alloc_sleep(ddi_root_node(), "pci",
	    (dnode_t)DEVI_SID_NODEID, &dip);
	(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip,
	    "device_type", "pci");
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "#address-cells", 3);
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "#size-cells", 2);
	pci_regs[0] = pci_bus_res[bus].root_addr;
	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip,
	    "reg", (int *)pci_regs, 3);

	(void) ndi_devi_bind_driver(dip, 0);
	pci_bus_res[bus].dip = dip;
	pci_bus_res[bus].pmem_space = find_bus_res(bus, PREFETCH_TYPE);
	pci_bus_res[bus].mem_space = find_bus_res(bus, MEM_TYPE);
	pci_bus_res[bus].io_ports = find_bus_res(bus, IO_TYPE);

	if (bus != 0)
		return;

	/*
	 * Special treatment of bus 0:
	 * If no resource from MPSPEC/HRT, copy pcimem from boot
	 * and make io space the entire range. There is no difference
	 * between prefetchable memory or not.
	 */
	if (pci_bus_res[0].mem_space == NULL)
		pci_bus_res[0].mem_space =
		    memlist_dup(bootops->boot_mem->pcimem);
	if (pci_bus_res[0].io_ports == NULL)
		memlist_insert(&pci_bus_res[0].io_ports, 0, 0x10000);
}

/*
 * For any fixed configuration (often compatability) pci devices
 * and those with their own expansion rom, create device nodes
 * to hold the already configured device details.
 */
void
enumerate_bus_devs(uchar_t bus, int config_op)
{
	uchar_t dev, func, nfunc, header;
	ushort_t venid;
	dev_info_t *dip;
	struct pci_devfunc {
		struct pci_devfunc *next;
		dev_info_t *dip;
		uchar_t bus;
		uchar_t dev;
		uchar_t func;
	} *devlist = NULL, *entry;

	if (config_op == CONFIG_NEW) {
		dcmn_err(CE_NOTE, "configuring pci bus 0x%x", bus);
	} else
		dcmn_err(CE_NOTE, "enumerating pci bus 0x%x", bus);

	for (dev = 0; dev < max_dev_pci; dev++) {
		nfunc = 1;
		for (func = 0; func < nfunc; func++) {
			int configured;

			dcmn_err(CE_NOTE, "probing dev 0x%x, func 0x%x",
			    dev, func);

			venid = pci_getw(bus, dev, func, PCI_CONF_VENID);
			if ((venid == 0xffff) || (venid == 0)) {
				/* no function at this address */
				continue;
			}

			configured = pci_getw(bus, dev, func, PCI_CONF_COMM) &
			    (PCI_COMM_IO | PCI_COMM_MAE);
			if ((!configured && config_op != CONFIG_NEW) ||
			    (configured && config_op != CONFIG_INFO))
				continue;

			header = pci_getb(bus, dev, func, PCI_CONF_HEADER);
			if (header == 0xff) {
				continue; /* illegal value */
			}

			/*
			 * according to some mail from Microsoft posted
			 * to the pci-drivers alias, their only requirement
			 * for a multifunction device is for the 1st
			 * function to have to PCI_HEADER_MULTI bit set.
			 */
			if ((func == 0) && (header & PCI_HEADER_MULTI)) {
				nfunc = 8;
			}
			dip = new_func_pci(bus, dev, func, header, venid,
			    config_op);
			/*
			 * If dip isn't null, reprogram the device later.
			 * This only happens for CONFIG_INFO case.
			 */
			if (dip) {
				entry = kmem_alloc(sizeof (*entry), KM_SLEEP);
				entry->dip = dip;
				entry->dev = dev;
				entry->func = func;
				entry->next = devlist;
				devlist = entry;
			}
		}
	}

	if (config_op == CONFIG_NEW) {
		devlist = (struct pci_devfunc *)pci_bus_res[bus].privdata;
		while (devlist) {
			entry = devlist;
			devlist = entry->next;
			cmn_err(CE_NOTE,
			    "!reprogram pci device [%d/%d/%d] (%s)",
			    bus, entry->dev, entry->func,
			    ddi_driver_name(entry->dip));
			(void) add_reg_props(entry->dip, bus, entry->dev,
			    entry->func, CONFIG_UPDATE, 0);
			kmem_free(entry, sizeof (*entry));
		}
		pci_bus_res[bus].privdata = NULL;
	} else {
		pci_bus_res[bus].privdata = devlist;
	}
}

static int
check_pciide_prop(uchar_t revid, ushort_t venid, ushort_t devid,
    ushort_t subvenid, ushort_t subdevid)
{
	static int prop_exist = -1;
	static char *pciide_str;
	char compat[32];

	if (prop_exist == -1) {
		prop_exist = (ddi_prop_lookup_string(DDI_DEV_T_ANY,
		    ddi_root_node(), DDI_PROP_DONTPASS, "pci-ide",
		    &pciide_str) == DDI_SUCCESS);
	}

	if (!prop_exist)
		return (0);

	/* compare property value against various forms of compatible */
	if (subvenid) {
		(void) snprintf(compat, sizeof (compat), "pci%x,%x.%x.%x.%x",
		    venid, devid, subvenid, subdevid, revid);
		if (strcmp(pciide_str, compat) == 0)
			return (1);

		(void) snprintf(compat, sizeof (compat), "pci%x,%x.%x.%x",
		    venid, devid, subvenid, subdevid);
		if (strcmp(pciide_str, compat) == 0)
			return (1);

		(void) snprintf(compat, sizeof (compat), "pci%x,%x",
		    subvenid, subdevid);
		if (strcmp(pciide_str, compat) == 0)
			return (1);
	}
	(void) snprintf(compat, sizeof (compat), "pci%x,%x.%x",
	    venid, devid, revid);
	if (strcmp(pciide_str, compat) == 0)
		return (1);

	(void) snprintf(compat, sizeof (compat), "pci%x,%x", venid, devid);
	if (strcmp(pciide_str, compat) == 0)
		return (1);

	return (0);
}

static int
is_pciide(uchar_t basecl, uchar_t subcl, uchar_t revid,
    ushort_t venid, ushort_t devid, ushort_t subvenid, ushort_t subdevid)
{
	struct ide_table {	/* table for PCI_MASS_OTHER */
		ushort_t venid;
		ushort_t devid;
	} *entry;

	/* XXX SATA devices: need a way to add dynamically */
	static struct ide_table ide_other[] = {
		{0x1095, 0x3112},
		{0x1095, 0x3114},
		{0x1095, 0x3512},
		{0, 0}
	};

	if (basecl != PCI_CLASS_MASS)
		return (0);

	if (subcl == PCI_MASS_IDE) {
		return (1);
	}

	if (subcl != PCI_MASS_OTHER && subcl != PCI_MASS_SATA) {
		return (0);
	}

	entry = &ide_other[0];
	while (entry->venid) {
		if (entry->venid == venid && entry->devid == devid)
			return (1);
		entry++;
	}
	return (check_pciide_prop(revid, venid, devid, subvenid, subdevid));
}

static int
is_display(uint_t classcode)
{
	static uint_t disp_classes[] = {
		0x000100,
		0x030000,
		0x030001
	};
	int i, nclasses = sizeof (disp_classes) / sizeof (uint_t);

	for (i = 0; i < nclasses; i++) {
		if (classcode == disp_classes[i])
			return (1);
	}
	return (0);
}

static dev_info_t *
new_func_pci(uchar_t bus, uchar_t dev, uchar_t func, uchar_t header,
    ushort_t vendorid, int config_op)
{
	char nodename[32], unitaddr[5];
	dev_info_t *dip;
	uchar_t basecl, subcl, intr, revid;
	ushort_t subvenid, subdevid, status;
	uint_t classcode, revclass;
	int reprogram = 0, pciide;
	int power[2] = {1, 1};

	ushort_t deviceid = pci_getw(bus, dev, func, PCI_CONF_DEVID);

	switch (header & PCI_HEADER_TYPE_M) {
	case PCI_HEADER_ZERO:
		subvenid = pci_getw(bus, dev, func, PCI_CONF_SUBVENID);
		subdevid = pci_getw(bus, dev, func, PCI_CONF_SUBSYSID);
		break;
	case PCI_HEADER_CARDBUS:
		subvenid = pci_getw(bus, dev, func, PCI_CBUS_SUBVENID);
		subdevid = pci_getw(bus, dev, func, PCI_CBUS_SUBSYSID);
		break;
	default:
		subvenid = 0;
		subdevid = 0;
		break;
	}

	/* XXX should be use generic names? derive from class? */
	revclass = pci_getl(bus, dev, func, PCI_CONF_REVID);
	classcode = revclass >> 8;
	revid = revclass & 0xff;

	/* figure out if this is pci-ide */
	basecl = classcode >> 16;
	subcl = (classcode >> 8) & 0xff;
	pciide = is_pciide(basecl, subcl, revid, vendorid, deviceid,
	    subvenid, subdevid);

	if (pciide)
		(void) snprintf(nodename, sizeof (nodename), "pci-ide");
	else if (is_display(classcode))
		(void) snprintf(nodename, sizeof (nodename), "display");
	else if (subvenid != 0)
		(void) snprintf(nodename, sizeof (nodename),
		    "pci%x,%x", subvenid, subdevid);
	else
		(void) snprintf(nodename, sizeof (nodename),
		    "pci%x,%x", vendorid, deviceid);

	/* make sure parent bus dip has been created */
	if (pci_bus_res[bus].dip == NULL) {
		create_root_bus_dip(bus);
	}

	ndi_devi_alloc_sleep(pci_bus_res[bus].dip, nodename,
	    DEVI_SID_NODEID, &dip);

	/* add properties */
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip, "device-id", deviceid);
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip, "vendor-id", vendorid);
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip, "revision-id", revid);
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "class-code", classcode);
	if (func == 0)
		(void) snprintf(unitaddr, sizeof (unitaddr), "%x", dev);
	else
		(void) snprintf(unitaddr, sizeof (unitaddr),
		    "%x,%x", dev, func);
	(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip,
	    "unit-address", unitaddr);

	/* add special stuff for header type */
	if ((header & PCI_HEADER_TYPE_M) == PCI_HEADER_ZERO) {
		uchar_t mingrant = pci_getb(bus, dev, func, PCI_CONF_MIN_G);
		uchar_t maxlatency = pci_getb(bus, dev, func, PCI_CONF_MAX_L);

		if (subvenid != 0) {
			(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
			    "subsystem-id", subdevid);
			(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
			    "subsystem-vendor-id", subvenid);
		}
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
		    "min-grant", mingrant);
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
		    "max-latency", maxlatency);
	}

	/* interrupt, record if not 0 */
	intr = pci_getb(bus, dev, func, PCI_CONF_IPIN);
	if (intr != 0)
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
		    "interrupts", intr);

	/*
	 * Add support for 133 mhz pci eventually
	 */
	status = pci_getw(bus, dev, func, PCI_CONF_STAT);

	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "devsel-speed", (status & PCI_STAT_DEVSELT) >> 9);
	if (status & PCI_STAT_FBBC)
		(void) ndi_prop_create_boolean(DDI_DEV_T_NONE, dip,
		    "fast-back-to-back");
	if (status & PCI_STAT_66MHZ)
		(void) ndi_prop_create_boolean(DDI_DEV_T_NONE, dip,
		    "66mhz-capable");
	if (status & PCI_STAT_UDF)
		(void) ndi_prop_create_boolean(DDI_DEV_T_NONE, dip,
		    "udf-supported");

	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip,
	    "power-consumption", power, 2);

	if ((basecl == PCI_CLASS_BRIDGE) && (subcl == PCI_BRIDGE_PCI)) {
		add_ppb_props(dip, bus, dev, func);
	}

	add_model_prop(dip, classcode);
	add_compatible(dip, subvenid, subdevid, vendorid, deviceid,
	    revid, classcode);
	reprogram = add_reg_props(dip, bus, dev, func, config_op, pciide);
	(void) ndi_devi_bind_driver(dip, 0);

	/* special handling for pci-ide */
	if (pciide) {
		dev_info_t *cdip;

		/*
		 * Create properties specified by P1275 Working Group
		 * Proposal #414 Version 1
		 */
		(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip,
		    "device_type", "pci-ide");
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
		    "#address-cells", 1);
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
		    "#size-cells", 0);

		/* allocate two child nodes */
		ndi_devi_alloc_sleep(dip, "ide",
		    (dnode_t)DEVI_SID_NODEID, &cdip);
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, cdip,
		    "reg", 0);
		(void) ndi_devi_bind_driver(cdip, 0);
		ndi_devi_alloc_sleep(dip, "ide",
		    (dnode_t)DEVI_SID_NODEID, &cdip);
		(void) ndi_prop_update_int(DDI_DEV_T_NONE, cdip,
		    "reg", 1);
		(void) ndi_devi_bind_driver(cdip, 0);

		reprogram = 0;	/* don't reprogram pci-ide bridge */
	}

	if (reprogram)
		return (dip);
	return (NULL);
}

/*
 * Set the compatible property to a value compliant with
 * rev 2.1 of the IEEE1275 PCI binding.
 *
 *   pciVVVV,DDDD.SSSS.ssss.RR	(0)
 *   pciVVVV,DDDD.SSSS.ssss	(1)
 *   pciSSSS,ssss		(2)
 *   pciVVVV,DDDD.RR		(3)
 *   pciVVVV,DDDD		(4)
 *   pciclass,CCSSPP		(5)
 *   pciclass,CCSS		(6)
 *
 * The Subsystem (SSSS) forms are not inserted if
 * subsystem-vendor-id is 0.
 *
 * Set with setprop and \x00 between each
 * to generate the encoded string array form.
 */
void
add_compatible(dev_info_t *dip, ushort_t subvenid, ushort_t subdevid,
    ushort_t vendorid, ushort_t deviceid, uchar_t revid, uint_t classcode)
{
	int i, size;
	char *compat[7];
	char *buf, *curr;

#define	COMPAT_BUFSIZE	256
	i = 0;
	size = COMPAT_BUFSIZE;
	curr = buf = kmem_alloc(size, KM_SLEEP);

	if (subvenid) {
		compat[i++] = curr;	/* form 0 */
		(void) snprintf(curr, size, "pci%x,%x.%x.%x.%x",
		    vendorid, deviceid, subvenid, subdevid, revid);
		size -= strlen(curr) + 1;
		curr += strlen(curr) + 1;

		compat[i++] = curr;	/* form 1 */
		(void) snprintf(curr, size, "pci%x,%x.%x.%x",
		    vendorid, deviceid, subvenid, subdevid);
		size -= strlen(curr) + 1;
		curr += strlen(curr) + 1;

		compat[i++] = curr;	/* form 2 */
		(void) snprintf(curr, size, "pci%x,%x",
		    subvenid, subdevid);
		size -= strlen(curr) + 1;
		curr += strlen(curr) + 1;
	}
	compat[i++] = curr;	/* form 3 */
	(void) snprintf(curr, size, "pci%x,%x.%x", vendorid, deviceid, revid);
	size -= strlen(curr) + 1;
	curr += strlen(curr) + 1;

	compat[i++] = curr;	/* form 4 */
	(void) snprintf(curr, size, "pci%x,%x", vendorid, deviceid);
	size -= strlen(curr) + 1;
	curr += strlen(curr) + 1;

	compat[i++] = curr;	/* form 5 */
	(void) snprintf(curr, size, "pciclass,%06x", classcode);
	size -= strlen(curr) + 1;
	curr += strlen(curr) + 1;

	compat[i++] = curr;	/* form 6 */
	(void) snprintf(curr, size, "pciclass,%04x", (classcode >> 8));

	(void) ndi_prop_update_string_array(DDI_DEV_T_NONE, dip,
	    "compatible", compat, i);
	kmem_free(buf, COMPAT_BUFSIZE);
}

/*
 * Adjust the reg properties for a dual channel PCI-IDE device.
 *
 * NOTE: don't do anything that changes the order of the hard-decodes
 * and programmed BARs. The kernel driver depends on these values
 * being in this order regardless of whether they're for a 'native'
 * mode BAR or not.
 */
/*
 * config info for pci-ide devices
 */
static struct {
	uchar_t  native_mask;	/* 0 == 'compatibility' mode, 1 == native */
	uchar_t  bar_offset;	/* offset for alt status register */
	ushort_t addr;		/* compatibility mode base address */
	ushort_t length;	/* number of ports for this BAR */
} pciide_bar[] = {
	{ 0x01, 0, 0x1f0, 8 },	/* primary lower BAR */
	{ 0x01, 2, 0x3f6, 1 },	/* primary upper BAR */
	{ 0x04, 0, 0x170, 8 },	/* secondary lower BAR */
	{ 0x04, 2, 0x376, 1 }	/* secondary upper BAR */
};

static int
pciIdeAdjustBAR(uchar_t progcl, int index, uint_t *basep, uint_t *lenp)
{
	int hard_decode = 0;

	/*
	 * Adjust the base and len for the BARs of the PCI-IDE
	 * device's primary and secondary controllers. The first
	 * two BARs are for the primary controller and the next
	 * two BARs are for the secondary controller. The fifth
	 * and sixth bars are never adjusted.
	 */
	if (index >= 0 && index <= 3) {
		*lenp = pciide_bar[index].length;

		if (progcl & pciide_bar[index].native_mask) {
			*basep += pciide_bar[index].bar_offset;
		} else {
			*basep = pciide_bar[index].addr;
			hard_decode = 1;
		}
	}

	/*
	 * if either base or len is zero make certain both are zero
	 */
	if (*basep == 0 || *lenp == 0) {
		*basep = 0;
		*lenp = 0;
		hard_decode = 0;
	}

	return (hard_decode);
}


/*
 * Add the "reg" and "assigned-addresses" property
 */
static int
add_reg_props(dev_info_t *dip, uchar_t bus, uchar_t dev, uchar_t func,
    int config_op, int pciide)
{
	uchar_t baseclass, subclass, progclass, header;
	ushort_t bar_sz;
	uint_t value = 0, len, devloc;
	uint_t base, base_hi, type;
	ushort_t offset, end;
	int max_basereg, j, reprogram = 0;
	uint_t phys_hi;
	struct memlist **io_res, **mres, **mem_res, **pmem_res;

	pci_regspec_t regs[16] = {{0}};
	pci_regspec_t assigned[15] = {{0}};
	int nreg, nasgn, configured, enable = 0;

	io_res = &pci_bus_res[bus].io_ports;
	mem_res = &pci_bus_res[bus].mem_space;
	if (bus == 0)	/* for bus 0, there is only mem_space */
		pmem_res = mem_res;
	else
		pmem_res = &pci_bus_res[bus].pmem_space;

	devloc = (uint_t)bus << 16 | (uint_t)dev << 11 | (uint_t)func << 8;
	regs[0].pci_phys_hi = devloc;
	nreg = 1;	/* rest of regs[0] is all zero */
	nasgn = 0;

	baseclass = pci_getb(bus, dev, func, PCI_CONF_BASCLASS);
	subclass = pci_getb(bus, dev, func, PCI_CONF_SUBCLASS);
	progclass = pci_getb(bus, dev, func, PCI_CONF_PROGCLASS);
	header = pci_getb(bus, dev, func, PCI_CONF_HEADER) & PCI_HEADER_TYPE_M;
	configured = pci_getw(bus, dev, func, PCI_CONF_COMM) &
	    (PCI_COMM_IO | PCI_COMM_MAE);
	ASSERT(configured || config_op == CONFIG_NEW);

	switch (header) {
	case PCI_HEADER_ZERO:
		max_basereg = PCI_BASE_NUM;
		break;
	case PCI_HEADER_PPB:
		max_basereg = PCI_BCNF_BASE_NUM;
		break;
	case PCI_HEADER_CARDBUS:
		max_basereg = PCI_CBUS_BASE_NUM;
		break;
	default:
		max_basereg = 0;
		break;
	}

	/*
	 * Create the register property by saving the current
	 * value of the base register.  Disable memory/io, then
	 * write 0xffffffff to the base register.  Read the
	 * value back to determine the required size of the
	 * address space.  Restore the base register
	 * contents.
	 */
	end = PCI_CONF_BASE0 + max_basereg * sizeof (uint_t);
	for (j = 0, offset = PCI_CONF_BASE0; offset < end;
	    j++, offset += bar_sz) {
		int hard_decode = 0;

		/* determine the size of the address space */
		base = pci_getl(bus, dev, func, offset);
		pci_putl(bus, dev, func, offset, 0xffffffff);
		value = pci_getl(bus, dev, func, offset);
		pci_putl(bus, dev, func, offset, base);

		/* construct phys hi,med.lo, size hi, lo */
		if ((pciide && j < 4) || (base & PCI_BASE_SPACE_IO)) {
			/* i/o space */
			bar_sz = PCI_BAR_SZ_32;
			value &= PCI_BASE_IO_ADDR_M;
			len = ((value ^ (value-1)) + 1) >> 1;

			/* XXX Adjust first 4 IDE registers */
			if (pciide) {
				if (subclass != PCI_MASS_IDE)
					progclass = (PCI_IDE_IF_NATIVE_PRI |
					    PCI_IDE_IF_NATIVE_SEC);
				hard_decode = pciIdeAdjustBAR(progclass, j,
				    &base, &len);
			} else if (value == 0) {
				/* skip base regs with size of 0 */
				continue;
			}

			regs[nreg].pci_size_low =
			    assigned[nasgn].pci_size_low = len;
			if (!hard_decode) {
				regs[nreg].pci_phys_hi =
				    (PCI_ADDR_IO | devloc) + offset;
			} else {
				regs[nreg].pci_phys_hi =
				    (PCI_RELOCAT_B | PCI_ADDR_IO | devloc) +
				    offset;
				regs[nreg].pci_phys_low =
				    base & PCI_BASE_IO_ADDR_M;
			}
			assigned[nasgn].pci_phys_hi =
			    (PCI_RELOCAT_B | PCI_ADDR_IO | devloc) + offset;
			type = base & (~PCI_BASE_IO_ADDR_M);
			base &= PCI_BASE_IO_ADDR_M;

			/*
			 * first pass - gather what's there
			 * update/second pass - adjust/allocate regions
			 *	config - allocate regions
			 */
			if (config_op == CONFIG_INFO) {	/* first pass */
				/* take out of the resource map of the bus */
				if (*io_res && base != 0)
					(void) memlist_remove(io_res,
					    (uint64_t)base, (uint64_t)len);
				else if (*io_res)
					reprogram = 1;
			} else if (*io_res && base == 0) {
				base = (uint_t)memlist_find(io_res,
				    (uint64_t)len, (uint64_t)0x400);
				if (base != 0) {
					/* XXX need to worry about 64-bit? */
					pci_putl(bus, dev, func, offset,
					    base | type);
					base = pci_getl(bus, dev, func, offset);
					base &= PCI_BASE_IO_ADDR_M;
				}
				if (base == 0) {
					cmn_err(CE_WARN, "failed to program"
					    " IO space 0x%x for [%d/%d/%d]",
					    len, bus, dev, func);
				} else
					enable = 1;
			}
			assigned[nasgn].pci_phys_low = base;
			nreg++, nasgn++;

		} else {
			/* memory space */
			if ((base & PCI_BASE_TYPE_M) == PCI_BASE_TYPE_ALL) {
				bar_sz = PCI_BAR_SZ_64;
				base_hi = pci_getl(bus, dev, func, offset + 4);
				phys_hi = PCI_ADDR_MEM64;
			} else {
				bar_sz = PCI_BAR_SZ_32;
				base_hi = 0;
				phys_hi = PCI_ADDR_MEM32;
			}

			/* skip base regs with size of 0 */
			value &= PCI_BASE_M_ADDR_M;

			if (value == 0) {
				continue;
			}
			len = ((value ^ (value-1)) + 1) >> 1;
			regs[nreg].pci_size_low =
			    assigned[nasgn].pci_size_low = len;

			phys_hi |= (devloc | offset);
			if (base & PCI_BASE_PREF_M) {
				mres = pmem_res;
				phys_hi |= PCI_PREFETCH_B;
			} else {
				mres = mem_res;
			}
			regs[nreg].pci_phys_hi =
			    assigned[nasgn].pci_phys_hi = phys_hi;
			assigned[nasgn].pci_phys_hi |= PCI_RELOCAT_B;
			assigned[nasgn].pci_phys_mid = base_hi;
			type = base & ~PCI_BASE_M_ADDR_M;
			base &= PCI_BASE_M_ADDR_M;

			if (config_op == CONFIG_INFO) {
				/* take out of the resource map of the bus */
				if (*mres && base != 0) {
					(void) memlist_remove(mres,
					    (uint64_t)base, (uint64_t)len);
				} else if (*mres)
					reprogram = 1;
			} else if (*mres && base == 0) {
				base = (uint_t)memlist_find(mres,
				    (uint64_t)len, (uint64_t)0x1000);
				if (base != NULL) {
					pci_putl(bus, dev, func, offset,
					    base | type);
					base = pci_getl(bus, dev, func, offset);
					base &= PCI_BASE_M_ADDR_M;
				}

				if (base == 0) {
					cmn_err(CE_WARN, "failed to program "
					    "mem space 0x%x for [%d/%d/%d]",
					    len, bus, dev, func);
				} else
					enable = 1;
			}
			assigned[nasgn].pci_phys_low = base;
			nreg++, nasgn++;
		}
	}
	switch (header) {
	case PCI_HEADER_ZERO:
		offset = PCI_CONF_ROM;
		break;
	case PCI_HEADER_PPB:
		offset = PCI_BCNF_ROM;
		break;
	default: /* including PCI_HEADER_CARDBUS */
		goto done;
	}

	/*
	 * Add the expansion rom memory space
	 * Determine the size of the ROM base reg; don't write reserved bits
	 * ROM isn't in the PCI memory space.
	 */
	base = pci_getl(bus, dev, func, offset);
	pci_putl(bus, dev, func, offset, PCI_BASE_ROM_ADDR_M);
	value = pci_getl(bus, dev, func, offset);
	pci_putl(bus, dev, func, offset, base);
	value &= PCI_BASE_ROM_ADDR_M;

	if (value != 0) {
		regs[nreg].pci_phys_hi = (PCI_ADDR_MEM32 | devloc) + offset;
		assigned[nasgn].pci_phys_hi = (PCI_RELOCAT_B |
		    PCI_ADDR_MEM32 | devloc) + offset;
		base &= PCI_BASE_ROM_ADDR_M;
		assigned[nasgn].pci_phys_low = base;
		len = ((value ^ (value-1)) + 1) >> 1;
		regs[nreg].pci_size_low = assigned[nasgn].pci_size_low = len;
		nreg++, nasgn++;
		/* take it out of the memory resource */
		if (*mem_res && base != 0)
			(void) memlist_remove(mem_res,
			    (uint64_t)base, (uint64_t)len);
	}

	/*
	 * The following are ISA resources. There are not part
	 * of the PCI local bus resources. So don't attempt to
	 * do resource accounting against PCI.
	 */

	/* add the three hard-decode, aliased address spaces for VGA */
	if ((baseclass == PCI_CLASS_DISPLAY && subclass == PCI_DISPLAY_VGA) ||
	    (baseclass == PCI_CLASS_NONE && subclass == PCI_NONE_VGA)) {

		/* VGA hard decode 0x3b0-0x3bb */
		regs[nreg].pci_phys_hi = assigned[nasgn].pci_phys_hi =
		    (PCI_RELOCAT_B | PCI_ALIAS_B | PCI_ADDR_IO | devloc);
		regs[nreg].pci_phys_low = assigned[nasgn].pci_phys_low = 0x3b0;
		regs[nreg].pci_size_low = assigned[nasgn].pci_size_low = 0xc;
		nreg++, nasgn++;

		/* VGA hard decode 0x3c0-0x3df */
		regs[nreg].pci_phys_hi = assigned[nasgn].pci_phys_hi =
		    (PCI_RELOCAT_B | PCI_ALIAS_B | PCI_ADDR_IO | devloc);
		regs[nreg].pci_phys_low = assigned[nasgn].pci_phys_low = 0x3c0;
		regs[nreg].pci_size_low = assigned[nasgn].pci_size_low = 0x20;
		nreg++, nasgn++;

		/* Video memory */
		regs[nreg].pci_phys_hi = assigned[nasgn].pci_phys_hi =
		    (PCI_RELOCAT_B | PCI_ADDR_MEM32 | devloc);
		regs[nreg].pci_phys_low =
		    assigned[nasgn].pci_phys_low = 0xa0000;
		regs[nreg].pci_size_low =
		    assigned[nasgn].pci_size_low = 0x20000;
		nreg++, nasgn++;
	}

	/* add the hard-decode, aliased address spaces for 8514 */
	if ((baseclass == PCI_CLASS_DISPLAY) &&
		(subclass == PCI_DISPLAY_VGA) &&
		(progclass & PCI_DISPLAY_IF_8514)) {

		/* hard decode 0x2e8 */
		regs[nreg].pci_phys_hi = assigned[nasgn].pci_phys_hi =
		    (PCI_RELOCAT_B | PCI_ALIAS_B | PCI_ADDR_IO | devloc);
		regs[nreg].pci_phys_low = assigned[nasgn].pci_phys_low = 0x2e8;
		regs[nreg].pci_size_low = assigned[nasgn].pci_size_low = 0x1;
		nreg++, nasgn++;

		/* hard decode 0x2ea-0x2ef */
		regs[nreg].pci_phys_hi = assigned[nasgn].pci_phys_hi =
		    (PCI_RELOCAT_B | PCI_ALIAS_B | PCI_ADDR_IO | devloc);
		regs[nreg].pci_phys_low = assigned[nasgn].pci_phys_low = 0x2ea;
		regs[nreg].pci_size_low = assigned[nasgn].pci_size_low = 0x6;
		nreg++, nasgn++;
	}

done:
	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip, "reg",
	    (int *)regs, nreg * sizeof (pci_regspec_t) / sizeof (int));
	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip,
	    "assigned-addresses",
	    (int *)assigned, nasgn * sizeof (pci_regspec_t) / sizeof (int));
	if (config_op == CONFIG_NEW && enable) {
		cmn_err(CE_NOTE,
		    "!enable PCI device [%d/%d/%d]", bus, dev, func);
		pci_putw(bus, dev, func, PCI_CONF_COMM,
		    pci_getw(bus, dev, func, PCI_CONF_COMM) | 0x7);
	}
	return (reprogram);
}

static void
add_ppb_props(dev_info_t *dip, uchar_t bus, uchar_t dev, uchar_t func)
{
	int i;
	uint_t val, io_range[2], mem_range[2], pmem_range[2];
	uchar_t secbus = pci_getb(bus, dev, func, PCI_BCNF_SECBUS);
	uchar_t subbus = pci_getb(bus, dev, func, PCI_BCNF_SUBBUS);
	ASSERT(secbus <= subbus);

	/*
	 * Some BIOSes lie about max pci busses, we allow for
	 * such mistakes here
	 */
	if (subbus > pci_bios_nbus) {
		pci_bios_nbus = subbus;
		alloc_res_array();
	}

	ASSERT(pci_bus_res[secbus].dip == NULL);
	pci_bus_res[secbus].dip = dip;
	pci_bus_res[secbus].par_bus = bus;

	/* setup bus number hierarchy */
	pci_bus_res[secbus].sub_bus = subbus;
	if (subbus > pci_bus_res[bus].sub_bus)
		pci_bus_res[bus].sub_bus = subbus;
	for (i = secbus + 1; i <= subbus; i++)
		pci_bus_res[i].par_bus = bus;

	(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip,
	    "device_type", "pci");
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "#address-cells", 3);
	(void) ndi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "#size-cells", 2);
	/* XXX need slot names */

	/*
	 * According to PPB spec, the base register should be programmed
	 * with a value bigger than the limit register when there are
	 * no resources available. This applies to io, memory, and
	 * prefetchable memory.
	 */
	/* io range */
	val = (uint_t)pci_getb(bus, dev, func, PCI_BCNF_IO_BASE_LOW);
	io_range[0] = ((val & 0xf0) << 8);
	val = (uint_t)pci_getb(bus, dev, func, PCI_BCNF_IO_LIMIT_LOW);
	io_range[1]  = ((val & 0xf0) << 8) | 0xFFF;
	if (io_range[0] != 0 && io_range[0] < io_range[1]) {
		memlist_insert(&pci_bus_res[secbus].io_ports,
		    (uint64_t)io_range[0],
		    (uint64_t)(io_range[1] - io_range[0] + 1));
		if (pci_bus_res[bus].io_ports != NULL) {
			(void) memlist_remove(&pci_bus_res[bus].io_ports,
			    (uint64_t)io_range[0],
			    (uint64_t)(io_range[1] - io_range[0] + 1));
		}
		dcmn_err(CE_NOTE, "bus %d io-range: 0x%x-%x",
		    secbus, io_range[0], io_range[1]);
		/* if 32-bit supported, make sure upper bits are not set */
		if ((val & 0xf) == 1 &&
		    pci_getw(bus, dev, func, PCI_BCNF_IO_BASE_HI)) {
			cmn_err(CE_NOTE, "unsupported 32-bit IO address on"
			    " pci-pci bridge [%d/%d/%d]", bus, dev, func);
		}
	}

	/* mem range */
	val = (uint_t)pci_getw(bus, dev, func, PCI_BCNF_MEM_BASE);
	mem_range[0] = ((val & 0xFFF0) << 16);
	val = (uint_t)pci_getw(bus, dev, func, PCI_BCNF_MEM_LIMIT);
	mem_range[1] = ((val & 0xFFF0) << 16) | 0xFFFFF;
	if (mem_range[0] != 0 && mem_range[0] < mem_range[1]) {
		memlist_insert(&pci_bus_res[secbus].mem_space,
		    (uint64_t)mem_range[0],
		    (uint64_t)(mem_range[1] - mem_range[0] + 1));
		/* remove from parent resouce list */
		if (pci_bus_res[bus].mem_space != NULL) {
			(void) memlist_remove(&pci_bus_res[bus].mem_space,
			    (uint64_t)mem_range[0],
			    (uint64_t)(mem_range[1] - mem_range[0] + 1));
		}
		dcmn_err(CE_NOTE, "bus %d mem-range: 0x%x-%x",
		    secbus, mem_range[0], mem_range[1]);
	}

	/* prefetchable memory range */
	val = (uint_t)pci_getw(bus, dev, func, PCI_BCNF_PF_BASE_LOW);
	pmem_range[0] = ((val & 0xFFF0) << 16);
	val = (uint_t)pci_getw(bus, dev, func, PCI_BCNF_PF_LIMIT_LOW);
	pmem_range[1] = ((val & 0xFFF0) << 16) | 0xFFFFF;
	if (pmem_range[0] != 0 && pmem_range[0] < pmem_range[1]) {
		memlist_insert(&pci_bus_res[secbus].pmem_space,
		    (uint64_t)pmem_range[0],
		    (uint64_t)(pmem_range[1] - pmem_range[0] + 1));
		if (pci_bus_res[bus].pmem_space != NULL) {
			(void) memlist_remove(&pci_bus_res[bus].pmem_space,
			    (uint64_t)pmem_range[0],
			    (uint64_t)(pmem_range[1] - pmem_range[0] + 1));
		}
		dcmn_err(CE_NOTE, "bus %d pmem-range: 0x%x-%x",
		    secbus, pmem_range[0], pmem_range[1]);
		/* if 64-bit supported, make sure upper bits are not set */
		if ((val & 0xf) == 1 &&
		    pci_getl(bus, dev, func, PCI_BCNF_PF_BASE_HIGH)) {
			cmn_err(CE_NOTE, "unsupported 64-bit prefetch memory on"
			    " pci-pci bridge [%d/%d/%d]", bus, dev, func);
		}
	}

	add_bus_range_prop(secbus);
	add_ppb_ranges_prop(secbus);
}

extern const struct pci_class_strings_s class_pci[];
extern int class_pci_items;

static void
add_model_prop(dev_info_t *dip, uint_t classcode)
{
	const char *desc;
	int i;
	uchar_t baseclass = classcode >> 16;
	uchar_t subclass = (classcode >> 8) & 0xff;
	uchar_t progclass = classcode & 0xff;

	if ((baseclass == PCI_CLASS_MASS) && (subclass == PCI_MASS_IDE)) {
		desc = "IDE controller";
	} else {
		for (desc = 0, i = 0; i < class_pci_items; i++) {
			if ((baseclass == class_pci[i].base_class) &&
			    (subclass == class_pci[i].sub_class) &&
			    (progclass == class_pci[i].prog_class)) {
				desc = class_pci[i].actual_desc;
				break;
			}
		}
		if (i == class_pci_items)
			desc = "Unknown class of pci/pnpbios device";
	}

	(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip, "model",
	    (char *)desc);
}

static void
add_bus_range_prop(int bus)
{
	int bus_range[2];

	if (pci_bus_res[bus].dip == NULL)
		return;
	bus_range[0] = bus;
	bus_range[1] = pci_bus_res[bus].sub_bus;
	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, pci_bus_res[bus].dip,
	    "bus-range", (int *)bus_range, 2);
}

/* this should be in some header file, shared with pcicfg */
struct pcicfg_range {
	uint32_t child_hi;
	uint32_t child_mid;
	uint32_t child_lo;
	uint32_t parent_hi;
	uint32_t parent_mid;
	uint32_t parent_lo;
	uint32_t size_hi;
	uint32_t size_lo;
};

static int
memlist_to_range(struct pcicfg_range *rp, struct memlist *entry, int type)
{
	if (entry == NULL)
		return (0);

	/* assume 32-bit addresses */
	rp->child_hi = rp->parent_hi = type;
	rp->child_mid = rp->parent_mid = 0;
	rp->child_lo = rp->parent_lo = (uint32_t)entry->address;
	rp->size_hi = 0;
	rp->size_lo = (uint32_t)entry->size;
	return (1);
}

static void
add_ppb_ranges_prop(int bus)
{
	int i = 0;
	struct pcicfg_range *rp;

	rp = kmem_alloc(3 * sizeof (*rp), KM_SLEEP);

	i = memlist_to_range(&rp[0], pci_bus_res[bus].io_ports,
	    PCI_ADDR_IO | PCI_REG_REL_M);
	i += memlist_to_range(&rp[i], pci_bus_res[bus].mem_space,
	    PCI_ADDR_MEM32 | PCI_REG_REL_M);
	i += memlist_to_range(&rp[i], pci_bus_res[bus].pmem_space,
	    PCI_ADDR_MEM32 | PCI_REG_REL_M | PCI_REG_PF_M);

	if (i != 0)
		(void) ndi_prop_update_int_array(DDI_DEV_T_NONE,
		    pci_bus_res[bus].dip, "ranges", (int *)rp,
		    i * sizeof (struct pcicfg_range) / sizeof (int));
	kmem_free(rp, 3 * sizeof (*rp));
}

static int
memlist_to_spec(struct pci_phys_spec *sp, struct memlist *list, int type)
{
	int i = 0;

	while (list) {
		/* assume 32-bit addresses */
		sp->pci_phys_hi = type;
		sp->pci_phys_mid = 0;
		sp->pci_phys_low = (uint32_t)list->address;
		sp->pci_size_hi = 0;
		sp->pci_size_low = (uint32_t)list->size;

		list = list->next;
		sp++, i++;
	}
	return (i);
}

static void
add_bus_available_prop(int bus)
{
	int i, count;
	struct pci_phys_spec *sp;

	count = memlist_count(pci_bus_res[bus].io_ports) +
	    memlist_count(pci_bus_res[bus].mem_space) +
	    memlist_count(pci_bus_res[bus].pmem_space);

	if (count == 0)		/* nothing available */
		return;

	sp = kmem_alloc(count * sizeof (*sp), KM_SLEEP);
	i = memlist_to_spec(&sp[0], pci_bus_res[bus].io_ports,
	    PCI_ADDR_IO | PCI_REG_REL_M);
	i += memlist_to_spec(&sp[i], pci_bus_res[bus].mem_space,
	    PCI_ADDR_MEM32 | PCI_REG_REL_M);
	i += memlist_to_spec(&sp[i], pci_bus_res[bus].pmem_space,
	    PCI_ADDR_MEM32 | PCI_REG_REL_M | PCI_REG_PF_M);
	ASSERT(i == count);

	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, pci_bus_res[bus].dip,
	    "available", (int *)sp,
	    i * sizeof (struct pci_phys_spec) / sizeof (int));
	kmem_free(sp, count * sizeof (*sp));
}

static void
alloc_res_array(void)
{
	static int array_max = 0;
	int old_max;
	void *old_res;

	if (array_max > pci_bios_nbus + 1)
		return;	/* array is big enough */

	old_max = array_max;
	old_res = pci_bus_res;

	if (array_max == 0)
		array_max = 16;	/* start with a reasonable number */

	while (array_max < pci_bios_nbus + 1)
		array_max <<= 1;
	pci_bus_res = (struct pci_bus_resource *)kmem_zalloc(
	    array_max * sizeof (struct pci_bus_resource), KM_SLEEP);

	if (old_res) {	/* copy content and free old array */
		bcopy(old_res, pci_bus_res,
		    old_max * sizeof (struct pci_bus_resource));
		kmem_free(old_res, old_max * sizeof (struct pci_bus_resource));
	}
}
