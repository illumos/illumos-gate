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

/*
 * CMU-CH nexus utility routines:
 *	property and config routines for attach()
 *	reg/intr/range/assigned-address property routines for bus_map()
 *	init_child()
 *	fault handling
 *	debug functions
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
#include <sys/pcicmu/pcicmu.h>
#include <sys/promif.h>

/*
 * get_pcmu_properties
 *
 * This function is called from the attach routine to get the key
 * properties of the pci nodes.
 *
 * used by: pcmu_attach()
 *
 * return value: DDI_FAILURE on failure
 */
int
get_pcmu_properties(pcmu_t *pcmu_p, dev_info_t *dip)
{
	int i;

	/*
	 * Get the device's port id.
	 */
	if ((pcmu_p->pcmu_id = (uint32_t)pcmu_get_portid(dip)) == -1u) {
		cmn_err(CE_WARN, "%s%d: no portid property\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		return (DDI_FAILURE);
	}

	/*
	 * Get the bus-ranges property.
	 */
	i = sizeof (pcmu_p->pcmu_bus_range);
	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "bus-range", (caddr_t)&pcmu_p->pcmu_bus_range, &i) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: no bus-range property\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		return (DDI_FAILURE);
	}
	PCMU_DBG2(PCMU_DBG_ATTACH, dip,
	    "get_pcmu_properties: bus-range (%x,%x)\n",
	    pcmu_p->pcmu_bus_range.lo, pcmu_p->pcmu_bus_range.hi);

	/*
	 * Get the ranges property.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS, "ranges",
	    (caddr_t)&pcmu_p->pcmu_ranges, &pcmu_p->pcmu_ranges_length) !=
	    DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d: no ranges property\n",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		return (DDI_FAILURE);
	}
	pcmu_fix_ranges(pcmu_p->pcmu_ranges,
	    pcmu_p->pcmu_ranges_length / sizeof (pcmu_ranges_t));

	/*
	 * Determine the number upa slot interrupts.
	 */
	pcmu_p->pcmu_numproxy = pcmu_get_numproxy(pcmu_p->pcmu_dip);
	PCMU_DBG1(PCMU_DBG_ATTACH, dip, "get_pcmu_properties: numproxy=%d\n",
	    pcmu_p->pcmu_numproxy);
	return (DDI_SUCCESS);
}

/*
 * free_pcmu_properties:
 *
 * This routine frees the memory used to cache the
 * "ranges" properties of the pci bus device node.
 *
 * used by: pcmu_detach()
 *
 * return value: none
 */
void
free_pcmu_properties(pcmu_t *pcmu_p)
{
	kmem_free(pcmu_p->pcmu_ranges, pcmu_p->pcmu_ranges_length);
}

/*
 * pcmu_reloc_reg
 *
 * If the "reg" entry (*pcmu_rp) is relocatable, lookup "assigned-addresses"
 * property to fetch corresponding relocated address.
 *
 * used by: pcmu_map()
 *
 * return value:
 *
 *	DDI_SUCCESS		- on success
 *	DDI_ME_INVAL		- regspec is invalid
 */
int
pcmu_reloc_reg(dev_info_t *dip, dev_info_t *rdip, pcmu_t *pcmu_p,
	pci_regspec_t *rp)
{
	int assign_len, assign_entries, i;
	pci_regspec_t *assign_p;
	register uint32_t phys_hi = rp->pci_phys_hi;
	register uint32_t mask = PCI_REG_ADDR_M | PCI_CONF_ADDR_MASK;
	register uint32_t phys_addr = phys_hi & mask;

	PCMU_DBG5(PCMU_DBG_MAP | PCMU_DBG_CONT, dip,
	    "\tpcmu_reloc_reg fr: %x.%x.%x %x.%x\n",
	    rp->pci_phys_hi, rp->pci_phys_mid, rp->pci_phys_low,
	    rp->pci_size_hi, rp->pci_size_low);

	if ((phys_hi & PCI_RELOCAT_B) || !(phys_hi & PCI_ADDR_MASK)) {
		return (DDI_SUCCESS);
	}

	/* phys_mid must be 0 regardless space type. XXX-64 bit mem space */
	if (rp->pci_phys_mid != 0 || rp->pci_size_hi != 0) {
		PCMU_DBG0(PCMU_DBG_MAP | PCMU_DBG_CONT, pcmu_p->pcmu_dip,
		    "phys_mid or size_hi not 0\n");
		return (DDI_ME_INVAL);
	}

	if (ddi_getlongprop(DDI_DEV_T_ANY, rdip, DDI_PROP_DONTPASS,
	    "assigned-addresses", (caddr_t)&assign_p, &assign_len)) {
		return (DDI_ME_INVAL);
	}

	assign_entries = assign_len / sizeof (pci_regspec_t);
	for (i = 0; i < assign_entries; i++, assign_p++) {
		if ((assign_p->pci_phys_hi & mask) == phys_addr) {
			rp->pci_phys_low += assign_p->pci_phys_low;
			break;
		}
	}
	kmem_free(assign_p - i, assign_len);
	PCMU_DBG5(PCMU_DBG_MAP | PCMU_DBG_CONT, dip,
	    "\tpcmu_reloc_reg to: %x.%x.%x %x.%x\n",
	    rp->pci_phys_hi, rp->pci_phys_mid, rp->pci_phys_low,
	    rp->pci_size_hi, rp->pci_size_low);
	return (i < assign_entries ? DDI_SUCCESS : DDI_ME_INVAL);
}

/*
 * use "ranges" to translate relocated pci regspec into parent space
 */
int
pcmu_xlate_reg(pcmu_t *pcmu_p, pci_regspec_t *pcmu_rp, struct regspec *new_rp)
{
	int n;
	pcmu_ranges_t *rng_p = pcmu_p->pcmu_ranges;
	int rng_n = pcmu_p->pcmu_ranges_length / sizeof (pcmu_ranges_t);

	uint32_t space_type = PCI_REG_ADDR_G(pcmu_rp->pci_phys_hi);
	uint32_t reg_end, reg_begin = pcmu_rp->pci_phys_low;
	uint32_t sz = pcmu_rp->pci_size_low;

	uint32_t rng_begin, rng_end;

	if (space_type == PCI_REG_ADDR_G(PCI_ADDR_CONFIG)) {
		if (reg_begin > PCI_CONF_HDR_SIZE) {
			return (DDI_ME_INVAL);
		}
		sz = sz ? MIN(sz, PCI_CONF_HDR_SIZE) : PCI_CONF_HDR_SIZE;
		reg_begin += pcmu_rp->pci_phys_hi;
	}
	reg_end = reg_begin + sz - 1;

	for (n = 0; n < rng_n; n++, rng_p++) {
		if (space_type != PCI_REG_ADDR_G(rng_p->child_high)) {
			continue;	/* not the same space type */
		}

		rng_begin = rng_p->child_low;
		if (space_type == PCI_REG_ADDR_G(PCI_ADDR_CONFIG)) {
			rng_begin += rng_p->child_high;
		}
		rng_end = rng_begin + rng_p->size_low - 1;
		if (reg_begin >= rng_begin && reg_end <= rng_end) {
			break;
		}
	}
	if (n >= rng_n) {
		return (DDI_ME_REGSPEC_RANGE);
	}

	new_rp->regspec_addr = reg_begin - rng_begin + rng_p->parent_low;
	new_rp->regspec_bustype = rng_p->parent_high;
	new_rp->regspec_size = sz;
	PCMU_DBG4(PCMU_DBG_MAP | PCMU_DBG_CONT, pcmu_p->pcmu_dip,
	    "\tpcmu_xlate_reg: entry %d new_rp %x.%x %x\n",
	    n, new_rp->regspec_bustype, new_rp->regspec_addr, sz);
	return (DDI_SUCCESS);
}


/*
 * pcmu_report_dev
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
pcmu_report_dev(dev_info_t *dip)
{
	if (dip == (dev_info_t *)0) {
		return (DDI_FAILURE);
	}
	cmn_err(CE_CONT, "?PCI-device: %s@%s, %s%d\n", ddi_node_name(dip),
	    ddi_get_name_addr(dip), ddi_driver_name(dip),
	    ddi_get_instance(dip));
	return (DDI_SUCCESS);
}

/*
 * name_child
 *
 * This function is called from pcmu_init_child to name a node. It is
 * also passed as a callback for node merging functions.
 *
 * return value: DDI_SUCCESS, DDI_FAILURE
 */
static int
name_child(dev_info_t *child, char *name, int namelen)
{
	pci_regspec_t *pcmu_rp;
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
	    "reg", (int **)&pcmu_rp, (uint_t *)&reglen) == DDI_SUCCESS) {
		if (((reglen * sizeof (int)) % sizeof (pci_regspec_t)) != 0) {
			cmn_err(CE_WARN, "reg property not well-formed");
			return (DDI_FAILURE);
		}

		func = PCI_REG_FUNC_G(pcmu_rp[0].pci_phys_hi);
		if (func != 0) {
			(void) snprintf(name, namelen, "%x,%x",
			    PCI_REG_DEV_G(pcmu_rp[0].pci_phys_hi), func);
		} else {
			(void) snprintf(name, namelen, "%x",
			    PCI_REG_DEV_G(pcmu_rp[0].pci_phys_hi));
		}
		ddi_prop_free(pcmu_rp);
		return (DDI_SUCCESS);
	}
	cmn_err(CE_WARN, "cannot name pci child '%s'", ddi_node_name(child));
	return (DDI_FAILURE);
}

int
pcmu_uninit_child(pcmu_t *pcmu_p, dev_info_t *child)
{
	PCMU_DBG2(PCMU_DBG_CTLOPS, pcmu_p->pcmu_dip,
	    "DDI_CTLOPS_UNINITCHILD: arg=%s%d\n",
	    ddi_driver_name(child), ddi_get_instance(child));

	ddi_set_name_addr(child, NULL);
	ddi_remove_minor_node(child, NULL);
	impl_rem_dev_props(child);

	PCMU_DBG0(PCMU_DBG_PWR, ddi_get_parent(child), "\n\n");
	return (DDI_SUCCESS);
}

/*
 * pcmu_init_child
 *
 * This function is called from our control ops routine on a
 * DDI_CTLOPS_INITCHILD request.  It builds and sets the device's
 * parent private data area.
 *
 * used by: pcmu_ctlops()
 *
 * return value: none
 */
int
pcmu_init_child(pcmu_t *pcmu_p, dev_info_t *child)
{
	char name[10];
	ddi_acc_handle_t config_handle;
	uint8_t bcr;
	uint8_t header_type;

	if (name_child(child, name, 10) != DDI_SUCCESS)
		return (DDI_FAILURE);
	ddi_set_name_addr(child, name);

	PCMU_DBG2(PCMU_DBG_PWR, ddi_get_parent(child),
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
		ddi_set_name_addr(child, NULL);
		return (DDI_FAILURE);
	}

	/*
	 * Determine the configuration header type.
	 */
	header_type = pci_config_get8(config_handle, PCI_CONF_HEADER);
	PCMU_DBG2(PCMU_DBG_INIT_CLD, pcmu_p->pcmu_dip, "%s: header_type=%x\n",
	    ddi_driver_name(child), header_type);

	/*
	 * If the device has a bus control register then program it
	 * based on the settings in the command register.
	 */
	if ((header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_ONE) {
		bcr = pci_config_get8(config_handle, PCI_BCNF_BCNTRL);
		if (pcmu_command_default & PCI_COMM_PARITY_DETECT)
			bcr |= PCI_BCNF_BCNTRL_PARITY_ENABLE;
		if (pcmu_command_default & PCI_COMM_SERR_ENABLE)
			bcr |= PCI_BCNF_BCNTRL_SERR_ENABLE;
		bcr |= PCI_BCNF_BCNTRL_MAST_AB_MODE;
		pci_config_put8(config_handle, PCI_BCNF_BCNTRL, bcr);
	}

	pci_config_teardown(&config_handle);
	return (DDI_SUCCESS);
}

/*
 * pcmu_get_reg_set_size
 *
 * Given a dev info pointer to a pci child and a register number, this
 * routine returns the size element of that reg set property.
 *
 * used by: pcmu_ctlops() - DDI_CTLOPS_REGSIZE
 *
 * return value: size of reg set on success, zero on error
 */
off_t
pcmu_get_reg_set_size(dev_info_t *child, int rnumber)
{
	pci_regspec_t *pcmu_rp;
	off_t size;
	int i;

	if (rnumber < 0) {
		return (0);
	}

	/*
	 * Get the reg property for the device.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS, "reg",
	    (caddr_t)&pcmu_rp, &i) != DDI_SUCCESS) {
		return (0);
	}

	if (rnumber >= (i / (int)sizeof (pci_regspec_t))) {
		kmem_free(pcmu_rp, i);
		return (0);
	}

	size = pcmu_rp[rnumber].pci_size_low |
	    ((uint64_t)pcmu_rp[rnumber].pci_size_hi << 32);
	kmem_free(pcmu_rp, i);
	return (size);
}


/*
 * pcmu_get_nreg_set
 *
 * Given a dev info pointer to a pci child, this routine returns the
 * number of sets in its "reg" property.
 *
 * used by: pcmu_ctlops() - DDI_CTLOPS_NREGS
 *
 * return value: # of reg sets on success, zero on error
 */
uint_t
pcmu_get_nreg_set(dev_info_t *child)
{
	pci_regspec_t *pcmu_rp;
	int i, n;

	/*
	 * Get the reg property for the device.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS, "reg",
	    (caddr_t)&pcmu_rp, &i) != DDI_SUCCESS) {
		return (0);
	}
	n = i / (int)sizeof (pci_regspec_t);
	kmem_free(pcmu_rp, i);
	return (n);
}

int
pcmu_cfg_report(dev_info_t *dip, ddi_fm_error_t *derr,
    pcmu_errstate_t *pcmu_err_p, int caller, uint32_t prierr)
{
	int fatal = 0;
	int nonfatal = 0;
	int i;
	pcmu_t *pcmu_p;
	int instance = ddi_get_instance(dip);

	ASSERT(dip);

	pcmu_p = get_pcmu_soft_state(instance);

	derr->fme_ena = derr->fme_ena ? derr->fme_ena :
	    fm_ena_generate(0, FM_ENA_FMT1);

	for (i = 0; pci_err_tbl[i].err_class != NULL; i++) {
		if (pcmu_err_p->pcmu_cfg_stat & pci_err_tbl[i].reg_bit) {
			char buf[FM_MAX_CLASS];
			char *aux_msg = NULL;

			switch (pci_err_tbl[i].reg_bit) {
			case PCI_STAT_R_MAST_AB:
				aux_msg = "Recieved Master Abort";
				/* LINTED fallthrough on case statement */
			case PCI_STAT_R_TARG_AB:
				if (aux_msg != NULL)
					aux_msg = "Recieved Target Abort";
				if (prierr) {
					/*
					 * piow case are already handled in
					 * pcmu_pbm_afsr_report()
					 */
					break;
				}
				if (caller != PCI_TRAP_CALL) {
					/*
					 * if we haven't come from trap handler
					 * we won't have an address
					 */
					fatal++;
				}
				break;
			default:
				/*
				 * dpe on dma write or ta on dma
				 */
				nonfatal++;
				break;
			}
			(void) snprintf(buf, FM_MAX_CLASS, "%s %s: %s %s",
			    (pcmu_p->pcmu_pcbm_p)->pcbm_nameinst_str,
			    (pcmu_p->pcmu_pcbm_p)->pcbm_nameaddr_str,
			    "PCI config space:", aux_msg);
			cmn_err(CE_WARN, "%s %s=0x%p", buf, "pbm-csr",
			    (void *)(pcmu_p->pcmu_pcbm_p)->pcbm_ctrl_reg);
		}
	}

	if (fatal)
		return (DDI_FM_FATAL);
	else if (nonfatal)
		return (DDI_FM_NONFATAL);

	return (DDI_FM_OK);
}

void
pcmu_child_cfg_save(dev_info_t *dip)
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
		 * init'ed.  They will be set up in pcmu_init_child().
		 */
		if (i_ddi_node_state(cdip) < DS_INITIALIZED) {
			PCMU_DBG2(PCMU_DBG_DETACH, dip, "DDI_SUSPEND: skipping "
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
pcmu_child_cfg_restore(dev_info_t *dip)
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
		 * init'ed.  They will be set up by pcmu_init_child().
		 */
		if (i_ddi_node_state(cdip) < DS_INITIALIZED) {
			PCMU_DBG2(PCMU_DBG_DETACH, dip,
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

			PCMU_DBG2(PCMU_DBG_PWR, dip,
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

#ifdef DEBUG
extern uint64_t pcmu_debug_flags;

pcmu_dflag_to_str_t pcmu_dflag_strings [] = {
	{PCMU_DBG_ATTACH,	"pcmu_attach"},
	{PCMU_DBG_DETACH,	"pcmu_detach"},
	{PCMU_DBG_MAP,		"pcmu_map"},
	{PCMU_DBG_A_INTX,	"pcmu_add_intx"},
	{PCMU_DBG_R_INTX,	"pcmu_rem_intx"},
	{PCMU_DBG_INIT_CLD,	"pcmu_init_child"},
	{PCMU_DBG_CTLOPS,	"pcmu_ctlops"},
	{PCMU_DBG_INTR,		"pcmu_intr_wrapper"},
	{PCMU_DBG_ERR_INTR,	"pcmu_pbm_error_intr"},
	{PCMU_DBG_BUS_FAULT,	"pcmu_fault"},
	{PCMU_DBG_IB,		"pcmu_ib"},
	{PCMU_DBG_CB,		"pcmu_cb"},
	{PCMU_DBG_PBM,		"pcmu_pbm"},
	{PCMU_DBG_OPEN,		"pcmu_open"},
	{PCMU_DBG_CLOSE,	"pcmu_close"},
	{PCMU_DBG_IOCTL,	"pcmu_ioctl"},
	{PCMU_DBG_PWR,		"pcmu_pwr"}
};

void
pcmu_debug(uint64_t flag, dev_info_t *dip, char *fmt,
	uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5)
{
	char *s = "pcmu unknown";
	uint_t cont = 0;
	int i;
	int no_rec = (sizeof (pcmu_dflag_strings) /
	    sizeof (pcmu_dflag_to_str_t));

	if (flag & PCMU_DBG_CONT) {
		flag &= ~PCMU_DBG_CONT;
		cont = 1;
	}
	if ((pcmu_debug_flags & flag) == flag) {
		for (i = 0; i < no_rec; i++) {
			if (pcmu_dflag_strings[i].flag == flag) {
				s = pcmu_dflag_strings[i].string;
				break;
			}
		}
		if (s && cont == 0) {
			prom_printf("%s(%d): %s: ", ddi_driver_name(dip),
			    ddi_get_instance(dip), s);
		}
		prom_printf(fmt, a1, a2, a3, a4, a5);
	}
}
#endif
