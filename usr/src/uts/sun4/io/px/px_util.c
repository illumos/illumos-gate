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
 * PCI nexus utility routines:
 *	property and config routines for attach()
 *	reg/intr/range/assigned-address property routines for bus_map()
 *	init_child()
 *	fault handling
 */

#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/async.h>
#include <sys/sysmacros.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ddi_impldefs.h>
#include "px_obj.h"
#include "pcie_pwr.h"

/*LINTLIBRARY*/

/*
 * px_get_props
 *
 * This function is called from the attach routine to get the key
 * properties of the pci nodes.
 *
 * used by: px_attach()
 *
 * return value: DDI_FAILURE on failure
 */
int
px_get_props(px_t *px_p, dev_info_t *dip)
{
	int i, no_of_intrs;

	/*
	 * Get the bus-ranges property.
	 */
	i = sizeof (px_p->px_bus_range);
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "bus-range", (caddr_t)&px_p->px_bus_range, &i) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: no bus-range property\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		return (DDI_FAILURE);
	}
	DBG(DBG_ATTACH, dip, "get_px_properties: bus-range (%x,%x)\n",
	    px_p->px_bus_range.lo, px_p->px_bus_range.hi);

	/*
	 * Get the interrupts property.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "interrupts", (caddr_t)&px_p->px_inos,
	    &px_p->px_inos_len) != DDI_SUCCESS) {

		cmn_err(CE_WARN, "%s%d: no interrupts property\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		return (DDI_FAILURE);
	}

	/*
	 * figure out number of interrupts in the "interrupts" property
	 * and convert them all into ino.
	 */
	i = ddi_getprop(DDI_DEV_T_ANY, dip, 0, "#interrupt-cells", 1);
	i = CELLS_1275_TO_BYTES(i);
	no_of_intrs = px_p->px_inos_len / i;
	for (i = 0; i < no_of_intrs; i++)
		px_p->px_inos[i] = px_p->px_inos[i] & 0x3F;

	/*
	 * Get the ranges property.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS, "ranges",
	    (caddr_t)&px_p->px_ranges_p, &px_p->px_ranges_length) !=
	    DDI_SUCCESS) {

		cmn_err(CE_WARN, "%s%d: no ranges property\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		kmem_free(px_p->px_inos, px_p->px_inos_len);
		return (DDI_FAILURE);
	}

	return (DDI_SUCCESS);
}

/*
 * px_free_props:
 *
 * This routine frees the memory used to cache the "interrupts"
 * and "ranges" properties of the pci bus device node.
 *
 * used by: px_detach()
 *
 * return value: none
 */
void
px_free_props(px_t *px_p)
{
	kmem_free(px_p->px_inos, px_p->px_inos_len);
	kmem_free(px_p->px_ranges_p, px_p->px_ranges_length);
}

/*
 * px_reloc_reg
 *
 * If the "reg" entry (*px_rp) is relocatable, lookup "assigned-addresses"
 * property to fetch corresponding relocated address.
 *
 * used by: px_map()
 *
 * return value:
 *
 *	DDI_SUCCESS		- on success
 *	DDI_ME_INVAL		- regspec is invalid
 */
int
px_reloc_reg(dev_info_t *dip, dev_info_t *rdip, px_t *px_p,
	pci_regspec_t *rp)
{
	int assign_len, assign_entries, i;
	pci_regspec_t *assign_p;
	uint32_t phys_hi = rp->pci_phys_hi;
	uint32_t space_type = phys_hi & PCI_REG_ADDR_M;	/* 28-bit */

	DBG(DBG_MAP | DBG_CONT, dip, "\tpx_reloc_reg fr: %x.%x.%x %x.%x\n",
	    rp->pci_phys_hi, rp->pci_phys_mid, rp->pci_phys_low,
	    rp->pci_size_hi, rp->pci_size_low);

	if (space_type == PCI_ADDR_CONFIG || phys_hi & PCI_RELOCAT_B)
		return (DDI_SUCCESS);

	/*
	 * Hot plug will be taken care of later
	 * if (px_p->hotplug_capable == B_FALSE)
	 */
	{
		uint32_t bus = PCI_REG_BUS_G(phys_hi);
		if (bus < px_p->px_bus_range.lo ||
		    bus > px_p->px_bus_range.hi) {
			DBG(DBG_MAP | DBG_CONT, dip, "bad bus# (%x)\n", bus);
			return (DDI_ME_INVAL);
		}
	}

	i = ddi_getlongprop(DDI_DEV_T_ANY, rdip, DDI_PROP_DONTPASS,
	    "assigned-addresses", (caddr_t)&assign_p, &assign_len);
	if (i) {
		DBG(DBG_MAP | DBG_CONT, dip, "%s%d: assigned-addresses %d\n",
		    ddi_driver_name(rdip), ddi_get_instance(rdip), i);
		return (DDI_ME_INVAL);
	}

	assign_entries = assign_len / sizeof (pci_regspec_t);
	for (i = 0; i < assign_entries; i++, assign_p++) {
		uint32_t assign_type = assign_p->pci_phys_hi & PCI_REG_ADDR_M;
		uint32_t assign_addr = PCI_REG_BDFR_G(assign_p->pci_phys_hi);

		if (PCI_REG_BDFR_G(phys_hi) != assign_addr)
			continue;
		if (space_type == assign_type) { /* exact match */
			rp->pci_phys_low += assign_p->pci_phys_low;
			if (space_type == PCI_ADDR_MEM64)
				rp->pci_phys_mid += assign_p->pci_phys_mid;
			break;
		}
		if (space_type == PCI_ADDR_MEM64 &&
		    assign_type == PCI_ADDR_MEM32) {
			rp->pci_phys_low += assign_p->pci_phys_low;
			rp->pci_phys_hi ^= PCI_ADDR_MEM64 ^ PCI_ADDR_MEM32;
			break;
		}
	}
	kmem_free(assign_p - i, assign_len);
	DBG(DBG_MAP | DBG_CONT, dip, "\tpx_reloc_reg to: %x.%x.%x %x.%x <%d>\n",
	    rp->pci_phys_hi, rp->pci_phys_mid, rp->pci_phys_low,
	    rp->pci_size_hi, rp->pci_size_low, i);
	return (i < assign_entries ? DDI_SUCCESS : DDI_ME_INVAL);
}

/*
 * use "ranges" to translate relocated pci regspec into parent space
 */
int
px_xlate_reg(px_t *px_p, pci_regspec_t *px_rp, struct regspec *new_rp)
{
	int n;
	px_ranges_t *rng_p = px_p->px_ranges_p;
	int rng_n = px_p->px_ranges_length / sizeof (px_ranges_t);
	uint32_t space_type = PCI_REG_ADDR_G(px_rp->pci_phys_hi);
	uint64_t reg_begin, reg_end, reg_sz;
	uint64_t rng_begin, rng_end, rng_sz;
	uint64_t addr;

	reg_begin = (uint64_t)px_rp->pci_phys_mid << 32 | px_rp->pci_phys_low;
	reg_sz = (uint64_t)px_rp->pci_size_hi << 32 | px_rp->pci_size_low;
	if (space_type == PCI_REG_ADDR_G(PCI_ADDR_CONFIG)) {
		if (reg_begin > PCI_CONF_HDR_SIZE)
			return (DDI_ME_INVAL);
		reg_sz = reg_sz ? MIN(reg_sz, PCI_CONF_HDR_SIZE) :
		    PCI_CONF_HDR_SIZE;
		reg_begin += px_rp->pci_phys_hi << 4;
	}
	reg_end = reg_begin + reg_sz - 1;

	for (n = 0; n < rng_n; n++, rng_p++) {
		if (space_type != PCI_REG_ADDR_G(rng_p->child_high))
			continue;	/* not the same space type */

		rng_begin = (uint64_t)rng_p->child_mid << 32 | rng_p->child_low;
		rng_sz = (uint64_t)rng_p->size_high << 32 | rng_p->size_low;
		if (space_type == PCI_REG_ADDR_G(PCI_ADDR_CONFIG))
			rng_begin += rng_p->child_high;

		rng_end = rng_begin + rng_sz - 1;
		if (reg_begin >= rng_begin && reg_end <= rng_end)
			break;
	}
	if (n >= rng_n)
		return (DDI_ME_REGSPEC_RANGE);

	addr = reg_begin - rng_begin + ((uint64_t)rng_p->parent_high << 32 |
	    rng_p->parent_low);
	new_rp->regspec_addr = (uint32_t)addr;
	new_rp->regspec_bustype = (uint32_t)(addr >> 32);
	new_rp->regspec_size = (uint32_t)reg_sz;
	DBG(DBG_MAP | DBG_CONT, px_p->px_dip,
	    "\tpx_xlate_reg: entry %d new_rp %x.%x %x\n",
	    n, new_rp->regspec_bustype, new_rp->regspec_addr, reg_sz);

	return (DDI_SUCCESS);
}

/*
 * px_report_dev
 *
 * This function is called from our control ops routine on a
 * DDI_CTLOPS_REPORTDEV request.
 *
 * The display format is
 *
 *	<name><inst> at <pname><pinst> device <dev> function <func>
 *
 * where
 *
 *	<name>		this device's name property
 *	<inst>		this device's instance number
 *	<name>		parent device's name property
 *	<inst>		parent device's instance number
 *	<dev>		this device's device number
 *	<func>		this device's function number
 */
int
px_report_dev(dev_info_t *dip)
{
	if (dip == (dev_info_t *)0)
		return (DDI_FAILURE);
	cmn_err(CE_CONT, "?PCI Express-device: %s@%s, %s%d\n",
	    ddi_node_name(dip), ddi_get_name_addr(dip),
	    ddi_driver_name(dip),
	    ddi_get_instance(dip));
	return (DDI_SUCCESS);
}


/*
 * reg property for pcimem nodes that covers the entire address
 * space for the node:  config, io, or memory.
 */
pci_regspec_t pci_pcimem_reg[3] =
{
	{PCI_ADDR_CONFIG,			0, 0, 0, 0x800000	},
	{(uint_t)(PCI_ADDR_IO|PCI_RELOCAT_B),	0, 0, 0, PX_IO_SIZE	},
	{(uint_t)(PCI_ADDR_MEM32|PCI_RELOCAT_B), 0, 0, 0, PX_MEM_SIZE	}
};

/*
 * px_name_child
 *
 * This function is called from init_child to name a node. It is
 * also passed as a callback for node merging functions.
 *
 * return value: DDI_SUCCESS, DDI_FAILURE
 */
static int
px_name_child(dev_info_t *child, char *name, int namelen)
{
	pci_regspec_t *pci_rp;
	int reglen;
	uint_t func;
	char **unit_addr;
	uint_t n;

	/*
	 * Set the address portion of the node name based on
	 * unit-address property, if it exists.
	 * The interpretation of the unit-address is DD[,F]
	 * where DD is the device id and F is the function.
	 */
	if (ddi_prop_lookup_string_array(DDI_DEV_T_ANY, child,
	    DDI_PROP_DONTPASS, "unit-address", &unit_addr, &n) ==
	    DDI_PROP_SUCCESS) {
		if (n != 1 || *unit_addr == NULL || **unit_addr == 0) {
			cmn_err(CE_WARN, "unit-address property in %s.conf"
			    " not well-formed", ddi_driver_name(child));
			ddi_prop_free(unit_addr);
			return (DDI_FAILURE);
		}
		(void) snprintf(name, namelen, "%s", *unit_addr);
		ddi_prop_free(unit_addr);
		return (DDI_SUCCESS);
	}

	/*
	 * The unit-address property is does not exist. Set the address
	 * portion of the node name based on the function and device number.
	 */
	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
	    "reg", (int **)&pci_rp, (uint_t *)&reglen) == DDI_SUCCESS) {
		if (((reglen * sizeof (int)) % sizeof (pci_regspec_t)) != 0) {
			cmn_err(CE_WARN, "reg property not well-formed");
			return (DDI_FAILURE);
		}

		func = PCI_REG_FUNC_G(pci_rp[0].pci_phys_hi);
		if (func != 0)
			(void) snprintf(name, namelen, "%x,%x",
			    PCI_REG_DEV_G(pci_rp[0].pci_phys_hi), func);
		else
			(void) snprintf(name, namelen, "%x",
			    PCI_REG_DEV_G(pci_rp[0].pci_phys_hi));
		ddi_prop_free(pci_rp);
		return (DDI_SUCCESS);
	}

	cmn_err(CE_WARN, "cannot name pci child '%s'", ddi_node_name(child));
	return (DDI_FAILURE);
}

int
px_uninit_child(px_t *px_p, dev_info_t *child)
{
	DBG(DBG_INIT_CLD, px_p->px_dip,
	    "DDI_CTLOPS_UNINITCHILD: arg=%s%d\n",
	    ddi_driver_name(child), ddi_get_instance(child));

	ddi_set_name_addr(child, NULL);
	ddi_remove_minor_node(child, NULL);

	/*
	 * XXX Clear parent private data used as a flag to disable
	 * iommu BDF protection
	 */
	if ((intptr_t)ddi_get_parent_data(child) == 1)
		ddi_set_parent_data(child, NULL);

	impl_rem_dev_props(child);

	DBG(DBG_PWR, ddi_get_parent(child), "\n\n");

	pcie_uninitchild(child);

	return (DDI_SUCCESS);
}

/*
 * px_init_child
 *
 * This function is called from our control ops routine on a
 * DDI_CTLOPS_INITCHILD request.  It builds and sets the device's
 * parent private data area.
 *
 * used by: pci_ctlops()
 *
 * return value: none
 */
int
px_init_child(px_t *px_p, dev_info_t *child)
{
	dev_info_t	*parent_dip = px_p->px_dip;
	pci_regspec_t	*pci_rp;
	char		name[10];
	int		i, no_config;
	intptr_t	ppd = NULL;

	/*
	 * The following is a special case for pcimem nodes.
	 * For these nodes we create a reg property with a
	 * single entry that covers the entire address space
	 * for the node (config, io or memory).
	 */
	if (strcmp(ddi_driver_name(child), "pcimem") == 0) {
		(void) ddi_prop_create(DDI_DEV_T_NONE, child,
		    DDI_PROP_CANSLEEP, "reg", (caddr_t)pci_pcimem_reg,
		    sizeof (pci_pcimem_reg));
		ddi_set_name_addr(child, "0");
		ddi_set_parent_data(child, NULL);
		return (DDI_SUCCESS);
	}

	/*
	 * Check whether the node has config space or is a hard decode
	 * node (possibly created by a driver.conf file).
	 */
	no_config = ddi_prop_get_int(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
	    "no-config", 0);

	/*
	 * XXX set ppd to 1 to disable iommu BDF protection
	 * It relies on unused parent private data for PCI devices.
	 */
	if (ddi_prop_exists(DDI_DEV_T_NONE, child, DDI_PROP_DONTPASS,
	    "dvma-share"))
		ppd = 1;

	/*
	 * Pseudo nodes indicate a prototype node with per-instance
	 * properties to be merged into the real h/w device node.
	 * However, do not merge if the no-config property is set
	 * (see PSARC 2000/088).
	 */
	if ((ndi_dev_is_persistent_node(child) == 0) && (no_config == 0)) {
		extern int pci_allow_pseudo_children;

		if (ddi_getlongprop(DDI_DEV_T_ANY, child,
		    DDI_PROP_DONTPASS, "reg", (caddr_t)&pci_rp, &i) ==
		    DDI_SUCCESS) {
			cmn_err(CE_WARN, "cannot merge prototype from %s.conf",
			    ddi_driver_name(child));
			kmem_free(pci_rp, i);
			return (DDI_NOT_WELL_FORMED);
		}
		/*
		 * Name the child
		 */
		if (px_name_child(child, name, 10) != DDI_SUCCESS)
			return (DDI_FAILURE);

		ddi_set_name_addr(child, name);
		ddi_set_parent_data(child, (void *)ppd);

		/*
		 * Try to merge the properties from this prototype
		 * node into real h/w nodes.
		 */
		if (ndi_merge_node(child, px_name_child) == DDI_SUCCESS) {
			/*
			 * Merged ok - return failure to remove the node.
			 */
			ddi_set_name_addr(child, NULL);
			return (DDI_FAILURE);
		}

		/* workaround for ddivs to run under PCI */
		if (pci_allow_pseudo_children)
			return (DDI_SUCCESS);

		cmn_err(CE_WARN, "!%s@%s: %s.conf properties not merged",
		    ddi_driver_name(child), ddi_get_name_addr(child),
		    ddi_driver_name(child));
		ddi_set_name_addr(child, NULL);
		return (DDI_NOT_WELL_FORMED);
	}

	if (px_name_child(child, name, 10) != DDI_SUCCESS)
		return (DDI_FAILURE);
	ddi_set_name_addr(child, name);

	if (no_config != 0) {
		/*
		 * There is no config space so there's nothing more to do.
		 */
		return (DDI_SUCCESS);
	}

	if (pcie_pm_hold(parent_dip) != DDI_SUCCESS) {
		DBG(DBG_PWR, parent_dip,
		    "INITCHILD: px_pm_hold failed\n");
		return (DDI_FAILURE);
	}
	/* Any return of DDI_FAILURE after this must call px_pm_release */

	/*
	 * If configuration registers were previously saved by
	 * child (before it went to D3), then let the child do the
	 * restore to set up the config regs as it'll first need to
	 * power the device out of D3.
	 */
	if (ddi_prop_exists(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
	    "config-regs-saved-by-child") == 1) {
		DBG(DBG_PWR, child,
		    "INITCHILD: config regs to be restored by child\n");

		return (DDI_SUCCESS);
	}

	DBG(DBG_PWR, parent_dip,
	    "INITCHILD: config regs setup for %s@%s\n",
	    ddi_node_name(child), ddi_get_name_addr(child));

	ddi_set_parent_data(child, (void *)ppd);
	if (pcie_init_bus(child))
		(void) pcie_initchild(child);

	/*
	 * Handle chip specific init-child tasks.
	 */
	pcie_pm_release(parent_dip);

	return (DDI_SUCCESS);
}

/*
 * px_get_reg_set_size
 *
 * Given a dev info pointer to a pci child and a register number, this
 * routine returns the size element of that reg set property.
 *
 * used by: pci_ctlops() - DDI_CTLOPS_REGSIZE
 *
 * return value: size of reg set on success, 0 on error
 */
off_t
px_get_reg_set_size(dev_info_t *child, int rnumber)
{
	pci_regspec_t *pci_rp;
	off_t size = 0;
	int i;

	if (rnumber < 0)
		return (0);

	/*
	 * Get the reg property for the device.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS, "reg",
	    (caddr_t)&pci_rp, &i) != DDI_SUCCESS)
		return (0);

	if (rnumber >= (i / (int)sizeof (pci_regspec_t)))
		goto done;

	size = pci_rp[rnumber].pci_size_low |
	    ((uint64_t)pci_rp[rnumber].pci_size_hi << 32);
done:
	kmem_free(pci_rp, i);
	return (size);
}


/*
 * px_get_nreg_set
 *
 * Given a dev info pointer to a pci child, this routine returns the
 * number of sets in its "reg" property.
 *
 * used by: pci_ctlops() - DDI_CTLOPS_NREGS
 *
 * return value: # of reg sets on success, zero on error
 */
uint_t
px_get_nreg_set(dev_info_t *child)
{
	pci_regspec_t *pci_rp;
	int i, n;

	/*
	 * Get the reg property for the device.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS, "reg",
	    (caddr_t)&pci_rp, &i) != DDI_SUCCESS)
		return (0);

	n = i / (int)sizeof (pci_regspec_t);
	kmem_free(pci_rp, i);
	return (n);
}


/*
 * px_get_nintr
 *
 * Given a dev info pointer to a pci child, this routine returns the
 * number of items in its "interrupts" property.
 *
 * used by: pci_ctlops() - DDI_CTLOPS_NREGS
 *
 * return value: # of interrupts on success, zero on error
 */
uint_t
px_get_nintr(dev_info_t *child)
{
	int *pci_ip;
	int i, n;

	if (ddi_getlongprop(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
	    "interrupts", (caddr_t)&pci_ip, &i) != DDI_SUCCESS)
		return (0);

	n = i / (int)sizeof (uint_t);
	kmem_free(pci_ip, i);
	return (n);
}

uint64_t
px_get_cfg_pabase(px_t *px_p)
{
	int i;
	px_ranges_t *rangep = px_p->px_ranges_p;
	int nrange = px_p->px_ranges_length / sizeof (px_ranges_t);
	uint32_t cfg_space_type = PCI_REG_ADDR_G(PCI_ADDR_CONFIG);

	ASSERT(cfg_space_type == 0);

	for (i = 0; i < nrange; i++, rangep++) {
		if (PCI_REG_ADDR_G(rangep->child_high) == cfg_space_type)
			break;
	}

	if (i >= nrange)
		cmn_err(CE_PANIC, "no cfg space in px(%p) ranges prop.\n",
		    px_p);

	return (((uint64_t)rangep->parent_high << 32) | rangep->parent_low);
}

/*
 * decodes standard PCI config space 16bit error status reg
 */
int
px_log_cfg_err(dev_info_t *dip, ushort_t status_reg, char *err_msg)
{
	int nerr = ddi_get_instance(dip); /* temp for instance */
	uint64_t perr_fatal = px_perr_fatal & (1 << nerr);
	uint64_t serr_fatal = px_serr_fatal & (1 << nerr);
	nerr = 0;

	if ((status_reg & PCI_STAT_PERROR) && perr_fatal)
		nerr++;
	if ((status_reg & PCI_STAT_S_SYSERR) && serr_fatal)
		nerr++;
	if (status_reg & PCI_STAT_R_MAST_AB)
		nerr++;
	if ((status_reg & PCI_STAT_S_PERROR) && perr_fatal)
		nerr++;

	cmn_err(CE_WARN, "%s%d: %sPCI Express config space CSR=0x%b",
	    ddi_driver_name(dip), ddi_get_instance(dip), err_msg,
	    (uint32_t)status_reg, PX_STATUS_BITS);

	return (nerr);
}
