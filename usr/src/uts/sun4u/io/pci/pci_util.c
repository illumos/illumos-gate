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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
#include <sys/fm/protocol.h>
#include <sys/fm/io/pci.h>
#include <sys/fm/util.h>
#include <sys/ddi_impldefs.h>
#include <sys/pci/pci_obj.h>

/*LINTLIBRARY*/

/*
 * get_pci_properties
 *
 * This function is called from the attach routine to get the key
 * properties of the pci nodes.
 *
 * used by: pci_attach()
 *
 * return value: DDI_FAILURE on failure
 */
int
get_pci_properties(pci_t *pci_p, dev_info_t *dip)
{
	int i;

	/*
	 * Get the device's port id.
	 */
	if ((pci_p->pci_id = (uint32_t)pci_get_portid(dip)) == -1u) {
		cmn_err(CE_WARN, "%s%d: no portid property\n",
			ddi_driver_name(dip), ddi_get_instance(dip));
		return (DDI_FAILURE);
	}

	/*
	 * Get the bus-ranges property.
	 */
	i = sizeof (pci_p->pci_bus_range);
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "bus-range", (caddr_t)&pci_p->pci_bus_range, &i) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: no bus-range property\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		return (DDI_FAILURE);
	}
	DEBUG2(DBG_ATTACH, dip, "get_pci_properties: bus-range (%x,%x)\n",
		pci_p->pci_bus_range.lo, pci_p->pci_bus_range.hi);

	/*
	 * disable streaming cache if necessary, this must be done
	 * before PBM is configured.
	 */
	if (ddi_prop_exists(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
			"no-streaming-cache")) {
		pci_stream_buf_enable = 0;
		pci_stream_buf_exists = 0;
	}

	/*
	 * Get the ranges property.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS, "ranges",
		(caddr_t)&pci_p->pci_ranges, &pci_p->pci_ranges_length) !=
		DDI_SUCCESS) {

		cmn_err(CE_WARN, "%s%d: no ranges property\n",
			ddi_driver_name(dip), ddi_get_instance(dip));
		return (DDI_FAILURE);
	}
	pci_fix_ranges(pci_p->pci_ranges,
		pci_p->pci_ranges_length / sizeof (pci_ranges_t));

	/*
	 * Determine the number upa slot interrupts.
	 */
	pci_p->pci_numproxy = pci_get_numproxy(pci_p->pci_dip);
	DEBUG1(DBG_ATTACH, dip, "get_pci_properties: numproxy=%d\n",
	    pci_p->pci_numproxy);

	pci_p->pci_thermal_interrupt =
		ddi_getprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
				"thermal-interrupt", -1);
	DEBUG1(DBG_ATTACH, dip, "get_pci_properties: thermal_interrupt=%d\n",
	    pci_p->pci_thermal_interrupt);
	return (DDI_SUCCESS);
}

/*
 * free_pci_properties:
 *
 * This routine frees the memory used to cache the
 * "ranges" properties of the pci bus device node.
 *
 * used by: pci_detach()
 *
 * return value: none
 */
void
free_pci_properties(pci_t *pci_p)
{
	kmem_free(pci_p->pci_ranges, pci_p->pci_ranges_length);
}

/*
 * pci_reloc_reg
 *
 * If the "reg" entry (*pci_rp) is relocatable, lookup "assigned-addresses"
 * property to fetch corresponding relocated address.
 *
 * used by: pci_map()
 *
 * return value:
 *
 *	DDI_SUCCESS		- on success
 *	DDI_ME_INVAL		- regspec is invalid
 */
int
pci_reloc_reg(dev_info_t *dip, dev_info_t *rdip, pci_t *pci_p,
	pci_regspec_t *rp)
{
	int assign_len, assign_entries, i;
	pci_regspec_t *assign_p;
	register uint32_t phys_hi = rp->pci_phys_hi;

	DEBUG5(DBG_MAP | DBG_CONT, dip, "\tpci_reloc_reg fr: %x.%x.%x %x.%x\n",
		rp->pci_phys_hi, rp->pci_phys_mid, rp->pci_phys_low,
		rp->pci_size_hi, rp->pci_size_low);

	if ((phys_hi & PCI_RELOCAT_B) || !(phys_hi & PCI_ADDR_MASK))
		return (DDI_SUCCESS);

	/* phys_mid must be 0 regardless space type. */
	if (rp->pci_phys_mid != 0 || rp->pci_size_hi != 0) {
		DEBUG0(DBG_MAP | DBG_CONT, pci_p->pci_dip,
			"phys_mid or size_hi not 0\n");
		return (DDI_ME_INVAL);
	}

	if (ddi_getlongprop(DDI_DEV_T_ANY, rdip, DDI_PROP_DONTPASS,
		"assigned-addresses", (caddr_t)&assign_p, &assign_len))
		return (DDI_ME_INVAL);

	assign_entries = assign_len / sizeof (pci_regspec_t);
	for (i = 0; i < assign_entries; i++, assign_p++) {
		uint32_t space_type = phys_hi & PCI_REG_ADDR_M;
		uint32_t assign_type = assign_p->pci_phys_hi & PCI_REG_ADDR_M;
		uint32_t assign_addr = PCI_REG_BDFR_G(assign_p->pci_phys_hi);

		if (PCI_REG_BDFR_G(phys_hi) != assign_addr)
			continue;
		if (space_type == assign_type) { /* exact match */
			rp->pci_phys_low += assign_p->pci_phys_low;
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
	DEBUG5(DBG_MAP | DBG_CONT, dip, "\tpci_reloc_reg to: %x.%x.%x %x.%x\n",
		rp->pci_phys_hi, rp->pci_phys_mid, rp->pci_phys_low,
		rp->pci_size_hi, rp->pci_size_low);
	return (i < assign_entries ? DDI_SUCCESS : DDI_ME_INVAL);
}

/*
 * use "ranges" to translate relocated pci regspec into parent space
 */
int
pci_xlate_reg(pci_t *pci_p, pci_regspec_t *pci_rp, struct regspec *new_rp)
{
	int n;
	pci_ranges_t *rng_p = pci_p->pci_ranges;
	int rng_n = pci_p->pci_ranges_length / sizeof (pci_ranges_t);

	uint32_t space_type = PCI_REG_ADDR_G(pci_rp->pci_phys_hi);
	uint32_t reg_end, reg_begin = pci_rp->pci_phys_low;
	uint32_t sz = pci_rp->pci_size_low;

	uint32_t rng_begin, rng_end;

	if (space_type == PCI_REG_ADDR_G(PCI_ADDR_CONFIG)) {
		if (reg_begin > PCI_CONF_HDR_SIZE)
			return (DDI_ME_INVAL);
		sz = sz ? MIN(sz, PCI_CONF_HDR_SIZE) : PCI_CONF_HDR_SIZE;
		reg_begin += pci_rp->pci_phys_hi;
	}
	reg_end = reg_begin + sz - 1;

	for (n = 0; n < rng_n; n++, rng_p++) {
		if (space_type != PCI_REG_ADDR_G(rng_p->child_high))
			continue;	/* not the same space type */

		rng_begin = rng_p->child_low;
		if (space_type == PCI_REG_ADDR_G(PCI_ADDR_CONFIG))
			rng_begin += rng_p->child_high;

		rng_end = rng_begin + rng_p->size_low - 1;
		if (reg_begin >= rng_begin && reg_end <= rng_end)
			break;
	}
	if (n >= rng_n)
		return (DDI_ME_REGSPEC_RANGE);

	new_rp->regspec_addr = reg_begin - rng_begin + rng_p->parent_low;
	new_rp->regspec_bustype = rng_p->parent_high;
	new_rp->regspec_size = sz;
	DEBUG4(DBG_MAP | DBG_CONT, pci_p->pci_dip,
		"\tpci_xlate_reg: entry %d new_rp %x.%x %x\n",
		n, new_rp->regspec_bustype, new_rp->regspec_addr, sz);

	return (DDI_SUCCESS);
}


/*
 * report_dev
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
report_dev(dev_info_t *dip)
{
	if (dip == (dev_info_t *)0)
		return (DDI_FAILURE);
	cmn_err(CE_CONT, "?PCI-device: %s@%s, %s%d\n",
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
	{(uint_t)(PCI_ADDR_IO|PCI_RELOCAT_B),	0, 0, 0, PCI_IO_SIZE	},
	{(uint_t)(PCI_ADDR_MEM32|PCI_RELOCAT_B), 0, 0, 0, PCI_MEM_SIZE	}
};

/*
 * name_child
 *
 * This function is called from init_child to name a node. It is
 * also passed as a callback for node merging functions.
 *
 * return value: DDI_SUCCESS, DDI_FAILURE
 */
static int
name_child(dev_info_t *child, char *name, int namelen)
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
uninit_child(pci_t *pci_p, dev_info_t *child)
{
	DEBUG2(DBG_CTLOPS, pci_p->pci_dip,
	    "DDI_CTLOPS_UNINITCHILD: arg=%s%d\n",
	    ddi_driver_name(child), ddi_get_instance(child));


	(void) pm_uninit_child(child);

	ddi_set_name_addr(child, NULL);
	ddi_remove_minor_node(child, NULL);
	impl_rem_dev_props(child);

	DEBUG0(DBG_PWR, ddi_get_parent(child), "\n\n");

	/*
	 * Handle chip specific post-uninit-child tasks.
	 */
	pci_post_uninit_child(pci_p);

	return (DDI_SUCCESS);
}

/*
 * init_child
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
init_child(pci_t *pci_p, dev_info_t *child)
{
	pci_regspec_t *pci_rp;
	char name[10];
	ddi_acc_handle_t config_handle;
	uint16_t command_preserve, command;
	uint8_t bcr;
	uint8_t header_type, min_gnt;
	uint16_t latency_timer;
	uint_t n;
	int i, no_config;

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
		if (name_child(child, name, 10) != DDI_SUCCESS)
			return (DDI_FAILURE);

		ddi_set_name_addr(child, name);
		ddi_set_parent_data(child, NULL);

		/*
		 * Try to merge the properties from this prototype
		 * node into real h/w nodes.
		 */
		if (ndi_merge_node(child, name_child) == DDI_SUCCESS) {
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

	if (name_child(child, name, 10) != DDI_SUCCESS)
		return (DDI_FAILURE);
	ddi_set_name_addr(child, name);

	if (no_config != 0) {
		/*
		 * There is no config space so there's nothing more to do.
		 */
		return (DDI_SUCCESS);
	}

	if (pm_init_child(child) != DDI_SUCCESS)
		return (DDI_FAILURE);


	/*
	 * If configuration registers were previously saved by
	 * child (before it went to D3), then let the child do the
	 * restore to set up the config regs as it'll first need to
	 * power the device out of D3.
	 */
	if (ddi_prop_exists(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
	    "config-regs-saved-by-child") == 1) {
		DEBUG0(DBG_PWR, child,
		    "INITCHILD: config regs to be restored by child\n");

		return (DDI_SUCCESS);
	}

	DEBUG2(DBG_PWR, ddi_get_parent(child),
	    "INITCHILD: config regs setup for %s@%s\n",
	    ddi_node_name(child), ddi_get_name_addr(child));

	/*
	 * Map the child configuration space to for initialization.
	 * We assume the obp will do the following in the devices
	 * config space:
	 *
	 *	Set the latency-timer register to values appropriate
	 *	for the devices on the bus (based on other devices
	 *	MIN_GNT and MAX_LAT registers.
	 *
	 *	Set the fast back-to-back enable bit in the command
	 *	register if it's supported and all devices on the bus
	 *	have the capability.
	 *
	 */
	if (pci_config_setup(child, &config_handle) != DDI_SUCCESS) {
		(void) pm_uninit_child(child);
		ddi_set_name_addr(child, NULL);

		return (DDI_FAILURE);
	}

	/*
	 * Determine the configuration header type.
	 */
	header_type = pci_config_get8(config_handle, PCI_CONF_HEADER);
	DEBUG2(DBG_INIT_CLD, pci_p->pci_dip, "%s: header_type=%x\n",
	    ddi_driver_name(child), header_type);

	/*
	 * Support for "command-preserve" property.  Note that we
	 * add PCI_COMM_BACK2BACK_ENAB to the bits to be preserved
	 * since the obp will set this if the device supports and
	 * all targets on the same bus support it.  Since psycho
	 * doesn't support PCI_COMM_BACK2BACK_ENAB, it will never
	 * be set.  This is just here in case future revs do support
	 * PCI_COMM_BACK2BACK_ENAB.
	 */
	command_preserve =
	    ddi_prop_get_int(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
		"command-preserve", 0);
	DEBUG2(DBG_INIT_CLD, pci_p->pci_dip, "%s: command-preserve=%x\n",
	    ddi_driver_name(child), command_preserve);
	command = pci_config_get16(config_handle, PCI_CONF_COMM);
	command &= (command_preserve | PCI_COMM_BACK2BACK_ENAB);
	command |= (pci_command_default & ~command_preserve);
	pci_config_put16(config_handle, PCI_CONF_COMM, command);
	command = pci_config_get16(config_handle, PCI_CONF_COMM);
	DEBUG2(DBG_INIT_CLD, pci_p->pci_dip, "%s: command=%x\n",
	    ddi_driver_name(child),
	    pci_config_get16(config_handle, PCI_CONF_COMM));

	/*
	 * If the device has a bus control register then program it
	 * based on the settings in the command register.
	 */
	if ((header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_ONE) {
		bcr = pci_config_get8(config_handle, PCI_BCNF_BCNTRL);
		if (pci_command_default & PCI_COMM_PARITY_DETECT)
			bcr |= PCI_BCNF_BCNTRL_PARITY_ENABLE;
		if (pci_command_default & PCI_COMM_SERR_ENABLE)
			bcr |= PCI_BCNF_BCNTRL_SERR_ENABLE;
		bcr |= PCI_BCNF_BCNTRL_MAST_AB_MODE;
		pci_config_put8(config_handle, PCI_BCNF_BCNTRL, bcr);
	}

	/*
	 * Initialize cache-line-size configuration register if needed.
	 */
	if (pci_set_cache_line_size_register &&
	    ddi_getprop(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
		"cache-line-size", 0) == 0) {

		pci_config_put8(config_handle, PCI_CONF_CACHE_LINESZ,
		    PCI_CACHE_LINE_SIZE);
		n = pci_config_get8(config_handle, PCI_CONF_CACHE_LINESZ);
		if (n != 0)
			(void) ndi_prop_update_int(DDI_DEV_T_NONE, child,
			    "cache-line-size", n);
	}

	/*
	 * Initialize latency timer registers if needed.
	 */
	if (pci_set_latency_timer_register &&
	    ddi_getprop(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
		"latency-timer", 0) == 0) {

		latency_timer = pci_latency_timer;
		if ((header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_ONE) {
			pci_config_put8(config_handle, PCI_BCNF_LATENCY_TIMER,
			    latency_timer);
		} else {
			min_gnt = pci_config_get8(config_handle,
			    PCI_CONF_MIN_G);
			DEBUG2(DBG_INIT_CLD, pci_p->pci_dip, "%s: min_gnt=%x\n",
			    ddi_driver_name(child), min_gnt);
			if (min_gnt != 0) {
				switch (pci_p->pci_pbm_p->pbm_speed) {
				case PBM_SPEED_33MHZ:
					latency_timer = min_gnt * 8;
					break;
				case PBM_SPEED_66MHZ:
					latency_timer = min_gnt * 4;
					break;
				}
			}
		}
		latency_timer = MIN(latency_timer, 0xff);
		pci_config_put8(config_handle, PCI_CONF_LATENCY_TIMER,
		    latency_timer);
		n = pci_config_get8(config_handle, PCI_CONF_LATENCY_TIMER);
		if (n != 0)
			(void) ndi_prop_update_int(DDI_DEV_T_NONE, child,
			    "latency-timer", n);
	}

	pci_config_teardown(&config_handle);

	/*
	 * Handle chip specific init-child tasks.
	 */
	pci_post_init_child(pci_p, child);

	return (DDI_SUCCESS);
}

/*
 * get_nreg_set
 *
 * Given a dev info pointer to a pci child, this routine returns the
 * number of sets in its "reg" property.
 *
 * used by: pci_ctlops() - DDI_CTLOPS_NREGS
 *
 * return value: # of reg sets on success, zero on error
 */
uint_t
get_nreg_set(dev_info_t *child)
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
 * get_nintr
 *
 * Given a dev info pointer to a pci child, this routine returns the
 * number of items in its "interrupts" property.
 *
 * used by: pci_ctlops() - DDI_CTLOPS_NREGS
 *
 * return value: # of interrupts on success, zero on error
 */
uint_t
get_nintr(dev_info_t *child)
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
pci_get_cfg_pabase(pci_t *pci_p)
{
	int i;
	pci_ranges_t *rangep = pci_p->pci_ranges;
	int nrange = pci_p->pci_ranges_length / sizeof (pci_ranges_t);
	uint32_t cfg_space_type = PCI_REG_ADDR_G(PCI_ADDR_CONFIG);

	ASSERT(cfg_space_type == 0);

	for (i = 0; i < nrange; i++, rangep++) {
		if (PCI_REG_ADDR_G(rangep->child_high) == cfg_space_type)
			break;
	}

	if (i >= nrange)
		cmn_err(CE_PANIC, "no cfg space in pci(%p) ranges prop.\n",
			(void *)pci_p);

	return (((uint64_t)rangep->parent_high << 32) | rangep->parent_low);
}

int
pci_cfg_report(dev_info_t *dip, ddi_fm_error_t *derr, pci_errstate_t *pci_err_p,
	int caller, uint32_t prierr)
{
	int fatal = 0;
	int nonfatal = 0;
	int i;

	ASSERT(dip);

	derr->fme_ena = derr->fme_ena ? derr->fme_ena :
	    fm_ena_generate(0, FM_ENA_FMT1);

	for (i = 0; pci_err_tbl[i].err_class != NULL; i++) {
		if (pci_err_p->pci_cfg_stat & pci_err_tbl[i].reg_bit) {
			char buf[FM_MAX_CLASS];

			(void) snprintf(buf, FM_MAX_CLASS, "%s.%s",
					PCI_ERROR_SUBCLASS,
					pci_err_tbl[i].err_class);
			ddi_fm_ereport_post(dip, buf, derr->fme_ena,
			    DDI_NOSLEEP, FM_VERSION, DATA_TYPE_UINT8, 0,
			    PCI_CONFIG_STATUS, DATA_TYPE_UINT16,
			    pci_err_p->pci_cfg_stat,
			    PCI_CONFIG_COMMAND, DATA_TYPE_UINT16,
			    pci_err_p->pci_cfg_comm,
			    PCI_PA, DATA_TYPE_UINT64,
			    pci_err_p->pci_pa,
			    NULL);

			switch (pci_err_tbl[i].reg_bit) {
			case PCI_STAT_S_SYSERR:
				/*
				 * address parity error on dma - treat as fatal
				 */
				fatal++;
				break;
			case PCI_STAT_R_MAST_AB:
			case PCI_STAT_R_TARG_AB:
			case PCI_STAT_S_PERROR:
				if (prierr) {
					/*
					 * piow case are already handled in
					 * pbm_afsr_report()
					 */
					break;
				}
				if (caller != PCI_TRAP_CALL) {
					/*
					 * if we haven't come from trap handler
					 * we won't have an address
					 */
					fatal++;
					break;
				}

				/*
				 * queue target ereport - use return from
				 * pci_lookup_handle() to determine if sync
				 * or async
				 */
				nonfatal++;
				pci_target_enqueue(derr->fme_ena,
				    pci_err_tbl[i].terr_class,
				    PCI_ERROR_SUBCLASS,
				    (uint64_t)derr->fme_bus_specific);
				break;
			default:
				/*
				 * dpe on dma write or ta on dma
				 */
				nonfatal++;
				break;
			}
		}
	}

	if (fatal)
		return (DDI_FM_FATAL);
	else if (nonfatal)
		return (DDI_FM_NONFATAL);

	return (DDI_FM_OK);
}

void
pci_child_cfg_save(dev_info_t *dip)
{
	dev_info_t *cdip;
	int ret = DDI_SUCCESS;

	/*
	 * Save the state of the configuration headers of child
	 * nodes.
	 */

	for (cdip = ddi_get_child(dip); cdip != NULL;
	    cdip = ddi_get_next_sibling(cdip)) {

		/*
		 * Not interested in children who are not already
		 * init'ed.  They will be set up in init_child().
		 */
		if (i_ddi_node_state(cdip) < DS_INITIALIZED) {
			DEBUG2(DBG_DETACH, dip, "DDI_SUSPEND: skipping "
			    "%s%d not in CF1\n", ddi_driver_name(cdip),
			    ddi_get_instance(cdip));

			continue;
		}

		/*
		 * Only save config registers if not already saved by child.
		 */
		if (ddi_prop_exists(DDI_DEV_T_ANY, cdip, DDI_PROP_DONTPASS,
		    SAVED_CONFIG_REGS) == 1) {

			continue;
		}

		/*
		 * The nexus needs to save config registers.  Create a property
		 * so it knows to restore on resume.
		 */
		ret = ndi_prop_create_boolean(DDI_DEV_T_NONE, cdip,
		    "nexus-saved-config-regs");

		if (ret != DDI_PROP_SUCCESS) {
			cmn_err(CE_WARN, "%s%d can't update prop %s",
			    ddi_driver_name(cdip), ddi_get_instance(cdip),
			    "nexus-saved-config-regs");
		}

		(void) pci_save_config_regs(cdip);
	}
}

void
pci_child_cfg_restore(dev_info_t *dip)
{
	dev_info_t *cdip;

	/*
	 * Restore config registers for children that did not save
	 * their own registers.  Children pwr states are UNKNOWN after
	 * a resume since it is possible for the PM framework to call
	 * resume without an actual power cycle. (ie if suspend fails).
	 */
	for (cdip = ddi_get_child(dip); cdip != NULL;
	    cdip = ddi_get_next_sibling(cdip)) {

		/*
		 * Not interested in children who are not already
		 * init'ed.  They will be set up by init_child().
		 */
		if (i_ddi_node_state(cdip) < DS_INITIALIZED) {
			DEBUG2(DBG_DETACH, dip,
			    "DDI_RESUME: skipping %s%d not in CF1\n",
			    ddi_driver_name(cdip), ddi_get_instance(cdip));
			continue;
		}

		/*
		 * Only restore config registers if saved by nexus.
		 */
		if (ddi_prop_exists(DDI_DEV_T_ANY, cdip, DDI_PROP_DONTPASS,
		    "nexus-saved-config-regs") == 1) {
			(void) pci_restore_config_regs(cdip);

			DEBUG2(DBG_PWR, dip,
			    "DDI_RESUME: nexus restoring %s%d config regs\n",
			    ddi_driver_name(cdip), ddi_get_instance(cdip));

			if (ndi_prop_remove(DDI_DEV_T_NONE, cdip,
			    "nexus-saved-config-regs") != DDI_PROP_SUCCESS) {
				cmn_err(CE_WARN, "%s%d can't remove prop %s",
				    ddi_driver_name(cdip),
				    ddi_get_instance(cdip),
				    "nexus-saved-config-regs");
			}
		}
	}
}
