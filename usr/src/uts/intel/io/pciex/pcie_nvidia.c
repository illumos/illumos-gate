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
 * Copyright (c) 2005, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2023 Oxide Computer Company
 */

/*
 *	Library file that has code for PCIe booting
 */

#include <sys/conf.h>
#include <sys/pci.h>
#include <sys/sunndi.h>
#include <sys/pcie.h>
#include <sys/pcie_impl.h>
#include <sys/pci_cfgspace.h>
#include <io/pciex/pcie_nvidia.h>

/*
 * PCI Configuration (Nvidia chipsets, PCIe) related library functions
 */

/* Globals */
extern int pci_boot_debug;

extern uint64_t mcfg_mem_base;

boolean_t
check_if_device_is_pciex(dev_info_t *cdip, uchar_t bus, uchar_t dev,
    uchar_t func, boolean_t *slot_valid, ushort_t *slot_number,
    ushort_t *is_pci_bridge)
{
	boolean_t found_pciex = B_FALSE;
	ushort_t cap;
	ushort_t capsp;
	ushort_t cap_count = PCI_CAP_MAX_PTR;
	ushort_t status;
	uint32_t slot_cap;

	*slot_valid = B_FALSE;

	status = (*pci_getw_func)(bus, dev, func, PCI_CONF_STAT);
	if (!(status & PCI_STAT_CAP))
		return (B_FALSE);

	capsp = (*pci_getb_func)(bus, dev, func, PCI_CONF_CAP_PTR);
	while (cap_count-- && capsp >= PCI_CAP_PTR_OFF) {
		capsp &= PCI_CAP_PTR_MASK;
		cap = (*pci_getb_func)(bus, dev, func, capsp);

		if (cap == PCI_CAP_ID_PCI_E) {
#ifdef	DEBUG
			if (pci_boot_debug)
				cmn_err(CE_CONT, "PCI-Express (%x,%x,%x) "
				    "capability found\n", bus, dev, func);
#endif	/* DEBUG */

			status = (*pci_getw_func)(bus, dev, func, capsp + 2);
			/*
			 * See section 7.8.2 of PCI-Express Base Spec v1.0a
			 * for Device/Port Type.
			 * PCIE_PCIECAP_DEV_TYPE_PCIE2PCI implies that the
			 * device is a PCIe2PCI bridge
			 */
			*is_pci_bridge =
			    ((status & PCIE_PCIECAP_DEV_TYPE_MASK) ==
			    PCIE_PCIECAP_DEV_TYPE_PCIE2PCI) ? 1 : 0;

			/*
			 * Check for "Slot  Implemented" bit
			 * PCIE_PCIECAP_SLOT_IMPL implies that.
			 */
			if (status & PCIE_PCIECAP_SLOT_IMPL) {
				/* offset 14h is Slot Cap Register */
				slot_cap = (*pci_getl_func)(bus, dev, func,
				    capsp + PCIE_SLOTCAP);
				*slot_valid = B_TRUE;
				*slot_number =
				    PCIE_SLOTCAP_PHY_SLOT_NUM(slot_cap);

				/* Is PCI Express HotPlug capability set? */
				if (cdip &&
				    (slot_cap & PCIE_SLOTCAP_HP_CAPABLE)) {
					(void) ndi_prop_update_int(
					    DDI_DEV_T_NONE, cdip,
					    "pci-hotplug-type",
					    INBAND_HPC_PCIE);
				}
			}

			found_pciex = B_TRUE;
		}

		if (cdip && (cap == PCI_CAP_ID_PCI_HOTPLUG)) {
			(void) ndi_prop_update_int(DDI_DEV_T_NONE, cdip,
			    "pci-hotplug-type", INBAND_HPC_SHPC);
		}

		capsp = (*pci_getb_func)(bus, dev, func,
		    capsp + PCI_CAP_NEXT_PTR);
	}

	return (found_pciex);
}


/*
 * scan all buses, devices, functions to look for any
 * PCI-Express device in the system.
 * If found, return B_TRUE else B_FALSE
 */
boolean_t
look_for_any_pciex_device(uchar_t bus)
{
	uchar_t dev, func;
	uchar_t nfunc, header;
	ushort_t venid, slot_num, is_pci_bridge = 0;
	boolean_t slot_valid;

	for (dev = 0; dev < 32; dev++) {
		nfunc = 1;
		for (func = 0; func < nfunc; func++) {
#ifdef	DEBUG
			if (pci_boot_debug)
				cmn_err(CE_NOTE, "pciex dev 0x%x, func 0x%x",
				    dev, func);
#endif	/* DEBUG */

			venid = (*pci_getw_func)(bus, dev, func,
			    PCI_CONF_VENID);
			/* no function at this address */
			if ((venid == 0xffff) || (venid == 0))
				continue;

			header = (*pci_getb_func)(bus, dev, func,
			    PCI_CONF_HEADER);
			if (header == 0xff)
				continue; /* illegal value */

			/*
			 * according to some mail from Microsoft posted to
			 * the pci-drivers alias, their only requirement for
			 * a multifunction device is for the 1st function to
			 * have to PCI_HEADER_MULTI bit set.
			 */
			if ((func == 0) && (header & PCI_HEADER_MULTI))
				nfunc = 8;

			if (check_if_device_is_pciex(NULL, bus, dev, func,
			    &slot_valid, &slot_num, &is_pci_bridge) == B_TRUE)
				return (B_TRUE);
		} /* end of func */
	} /* end of dev */

	return (B_FALSE);
}

boolean_t
create_pcie_root_bus(uchar_t bus, dev_info_t *dip)
{
	/*
	 * Currently this is being hard-coded.
	 * We need to figure out if the root bus does indeed
	 * have PCI-Ex in the path by looking for MCFG in
	 * the ACPI tables
	 */
	if (look_for_any_pciex_device(bus) == B_FALSE)
		return (B_FALSE);

#ifdef	DEBUG
	if (pci_boot_debug)
		cmn_err(CE_CONT, "Found PCI-Ex in the system\n");
#endif	/* DEBUG */
	(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip,
	    "device_type", "pciex");
	(void) ndi_prop_update_string(DDI_DEV_T_NONE, dip,
	    "compatible", "pciex_root_complex");

	pcie_rc_init_bus(dip);

	return (B_TRUE);
}


/*
 * add_nvidia_isa_bridge_props():
 *	To enable native hotplug; we need to map in two I/O BARs
 *	from ISA bridge's config space
 *
 * NOTE: For now, this function is only used for Nvidia's CrushK 8-04 chipsets.
 */
void
add_nvidia_isa_bridge_props(dev_info_t *dip, uchar_t bus, uchar_t dev,
    uchar_t func)
{
	uint_t devloc, base;
	pci_regspec_t regs[2] = {{0}};
	pci_regspec_t assigned[2] = {{0}};

	devloc = PCI_REG_MAKE_BDFR(bus, dev, func, 0);
	regs[0].pci_phys_hi = devloc;

	/* System Control BAR i/o space */
	base = (*pci_getl_func)(bus, dev, func,
	    NVIDIA_CK804_ISA_SYSCTRL_BAR_OFF);
	regs[0].pci_size_low = assigned[0].pci_size_low = PCI_CONF_HDR_SIZE;
	assigned[0].pci_phys_hi = regs[0].pci_phys_hi = (PCI_RELOCAT_B |
	    PCI_ADDR_IO | devloc | NVIDIA_CK804_ISA_SYSCTRL_BAR_OFF);
	assigned[0].pci_phys_low = regs[0].pci_phys_low =
	    base & PCI_BASE_IO_ADDR_M;

	/* Analog BAR i/o space */
	base = (*pci_getl_func)(bus, dev, func,
	    NVIDIA_CK804_ISA_ANALOG_BAR_OFF);
	regs[1].pci_size_low = assigned[1].pci_size_low = PCI_CONF_HDR_SIZE;
	assigned[1].pci_phys_hi = regs[1].pci_phys_hi = (PCI_RELOCAT_B |
	    PCI_ADDR_IO | devloc | NVIDIA_CK804_ISA_ANALOG_BAR_OFF);
	assigned[1].pci_phys_low = regs[1].pci_phys_low =
	    base & PCI_BASE_IO_ADDR_M;

	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip, "reg",
	    (int *)regs, 2 * sizeof (pci_regspec_t) / sizeof (int));
	(void) ndi_prop_update_int_array(DDI_DEV_T_NONE, dip,
	    "assigned-addresses",
	    (int *)assigned, 2 * sizeof (pci_regspec_t) / sizeof (int));
}
