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
 * Copyright 2015 Joyent, Inc.
 */

/*
 *	Library file that has miscellaneous support for npe(7d)
 */

#include <sys/conf.h>
#include <sys/pci.h>
#include <sys/sunndi.h>
#include <sys/acpi/acpi.h>
#include <sys/acpi/acpi_pci.h>
#include <sys/acpica.h>
#include <sys/pci_cap.h>
#include <sys/pcie_impl.h>
#include <sys/x86_archext.h>
#include <io/pciex/pcie_nvidia.h>
#include <io/pciex/pcie_nb5000.h>
#include <sys/pci_cfgacc_x86.h>
#include <sys/cpuvar.h>

/*
 * Prototype declaration
 */
void	npe_query_acpi_mcfg(dev_info_t *dip);
void	npe_ck804_fix_aer_ptr(ddi_acc_handle_t cfg_hdl);
int	npe_disable_empty_bridges_workaround(dev_info_t *child);
void	npe_nvidia_error_workaround(ddi_acc_handle_t cfg_hdl);
void	npe_intel_error_workaround(ddi_acc_handle_t cfg_hdl);
boolean_t npe_is_child_pci(dev_info_t *dip);
int	npe_enable_htmsi(ddi_acc_handle_t cfg_hdl);
void	npe_enable_htmsi_children(dev_info_t *dip);

int	npe_enable_htmsi_flag = 1;

extern uint32_t npe_aer_uce_mask;

/*
 * Query the MCFG table using ACPI.  If MCFG is found, setup the 'ecfg'
 * property accordingly.  If no table is found, the property remains unset; the
 * system will not make use of memory-mapped access to PCI Express
 * configuration space.
 */
void
npe_query_acpi_mcfg(dev_info_t *dip)
{
	MCFG_TABLE *mcfgp;
	CFG_BASE_ADDR_ALLOC *cfg_baap;
	char *cfg_baa_endp;
	int64_t ecfginfo[4];

	/* Query the MCFG table using ACPI */
	if (AcpiGetTable(ACPI_SIG_MCFG, 1,
	    (ACPI_TABLE_HEADER **)&mcfgp) == AE_OK) {

		cfg_baap = (CFG_BASE_ADDR_ALLOC *)mcfgp->CfgBaseAddrAllocList;
		cfg_baa_endp = ((char *)mcfgp) + mcfgp->Length;

		while ((char *)cfg_baap < cfg_baa_endp) {
			if (cfg_baap->base_addr != (uint64_t)0 &&
			    cfg_baap->segment == 0) {
				/*
				 * Set up the 'ecfg' property to hold
				 * base_addr, segment, and first/last bus.
				 * We only do the first entry that maps
				 * segment 0; nonzero segments are not yet
				 * known, or handled.  If they appear,
				 * we'll need to figure out which bus node
				 * should have which entry by examining the
				 * ACPI _SEG method on each bus node.
				 */
				ecfginfo[0] = cfg_baap->base_addr;
				ecfginfo[1] = cfg_baap->segment;
				ecfginfo[2] = cfg_baap->start_bno;
				ecfginfo[3] = cfg_baap->end_bno;
				(void) ndi_prop_update_int64_array(
				    DDI_DEV_T_NONE, dip, "ecfg",
				    ecfginfo, 4);
				break;
			}
			cfg_baap++;
		}
	}
}

/*
 * Enable reporting of AER capability next pointer.
 * This needs to be done only for CK8-04 devices
 * by setting NV_XVR_VEND_CYA1 (offset 0xf40) bit 13
 * NOTE: BIOS is disabling this, it needs to be enabled temporarily
 */
void
npe_ck804_fix_aer_ptr(ddi_acc_handle_t cfg_hdl)
{
	ushort_t cya1;

	if ((pci_config_get16(cfg_hdl, PCI_CONF_VENID) == NVIDIA_VENDOR_ID) &&
	    (pci_config_get16(cfg_hdl, PCI_CONF_DEVID) ==
	    NVIDIA_CK804_DEVICE_ID) &&
	    (pci_config_get8(cfg_hdl, PCI_CONF_REVID) >=
	    NVIDIA_CK804_AER_VALID_REVID)) {
		cya1 =  pci_config_get16(cfg_hdl, NVIDIA_CK804_VEND_CYA1_OFF);
		if (!(cya1 & ~NVIDIA_CK804_VEND_CYA1_ERPT_MASK))
			(void) pci_config_put16(cfg_hdl,
			    NVIDIA_CK804_VEND_CYA1_OFF,
			    cya1 | NVIDIA_CK804_VEND_CYA1_ERPT_VAL);
	}
}

/*
 * If the bridge is empty, disable it
 */
int
npe_disable_empty_bridges_workaround(dev_info_t *child)
{
	/*
	 * Do not bind drivers to empty bridges.
	 * Fail above, if the bridge is found to be hotplug capable
	 */
	if (ddi_driver_major(child) == ddi_name_to_major("pcieb") &&
	    ddi_get_child(child) == NULL &&
	    ddi_prop_get_int(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
	    "pci-hotplug-type", INBAND_HPC_NONE) == INBAND_HPC_NONE)
		return (1);

	return (0);
}

void
npe_nvidia_error_workaround(ddi_acc_handle_t cfg_hdl) {
	uint32_t regs;
	uint16_t vendor_id = pci_config_get16(cfg_hdl, PCI_CONF_VENID);
	uint16_t dev_id = pci_config_get16(cfg_hdl, PCI_CONF_DEVID);

	if ((vendor_id == NVIDIA_VENDOR_ID) && NVIDIA_PCIE_RC_DEV_ID(dev_id)) {
		/* Disable ECRC for all devices */
		regs = pcie_get_aer_uce_mask() | npe_aer_uce_mask |
		    PCIE_AER_UCE_ECRC;
		pcie_set_aer_uce_mask(regs);

		/*
		 * Turn full scan on since the Error Source ID register may not
		 * have the correct ID.
		 */
		pcie_force_fullscan();
	}
}

void
npe_intel_error_workaround(ddi_acc_handle_t cfg_hdl) {
	uint32_t regs;
	uint16_t vendor_id = pci_config_get16(cfg_hdl, PCI_CONF_VENID);
	uint16_t dev_id = pci_config_get16(cfg_hdl, PCI_CONF_DEVID);

	if (vendor_id == INTEL_VENDOR_ID) {
		/*
		 * Due to an errata in Intel's ESB2 southbridge, all ECRCs
		 * generation/checking need to be disabled.  There is a
		 * workaround by setting a proprietary bit in the ESB2, but it
		 * is not well documented or understood.  If that bit is set in
		 * the future, then ECRC generation/checking should be enabled
		 * again.
		 *
		 * Disable ECRC generation/checking by masking ECRC in the AER
		 * UE Mask.  The pcie misc module would then automatically
		 * disable ECRC generation/checking in the AER Control register.
		 */
		regs = pcie_get_aer_uce_mask() | PCIE_AER_UCE_ECRC;
		pcie_set_aer_uce_mask(regs);

		if (INTEL_NB5500_PCIE_DEV_ID(dev_id) ||
		    INTEL_NB5520_PCIE_DEV_ID(dev_id)) {
			/*
			 * Turn full scan on since the Error Source ID register
			 * may not have the correct ID. See Intel 5520 and
			 * Intel 5500 Chipsets errata #34 and #54 in the August
			 * 2009 specification update, document number
			 * 321329-006.
			 */
			pcie_force_fullscan();
		}
	}
}

/*
 * Check's if this child is a PCI device.
 * Child is a PCI device if:
 * parent has a dev_type of "pci"
 * -and-
 * child does not have a dev_type of "pciex"
 *
 * If the parent is not of dev_type "pci", then assume it is "pciex" and all
 * children should support using PCIe style MMCFG access.
 *
 * If parent's dev_type is "pci" and child is "pciex", then also enable using
 * PCIe style MMCFG access.  This covers the case where NPE is "pci" and a PCIe
 * RP is beneath.
 */
boolean_t
npe_child_is_pci(dev_info_t *dip) {
	char *dev_type;
	boolean_t parent_is_pci, child_is_pciex;

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, ddi_get_parent(dip),
	    DDI_PROP_DONTPASS, "device_type", &dev_type) ==
	    DDI_PROP_SUCCESS) {
		parent_is_pci = (strcmp(dev_type, "pci") == 0);
		ddi_prop_free(dev_type);
	} else {
		parent_is_pci = B_FALSE;
	}

	if (ddi_prop_lookup_string(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "device_type", &dev_type) == DDI_PROP_SUCCESS) {
		child_is_pciex = (strcmp(dev_type, "pciex") == 0);
		ddi_prop_free(dev_type);
	} else {
		child_is_pciex = B_FALSE;
	}

	return (parent_is_pci && !child_is_pciex);
}

/*
 * Checks to see if MMCFG is supported.
 * Returns: TRUE if MMCFG is supported, FALSE if not.
 *
 * If a device is attached to a parent whose "dev_type" is "pciex",
 * the device will support MMCFG access.  Otherwise, use legacy IOCFG access.
 *
 * Enable Legacy PCI config space access for AMD K8 north bridges.
 *	Host bridge: AMD HyperTransport Technology Configuration
 *	Host bridge: AMD Address Map
 *	Host bridge: AMD DRAM Controller
 *	Host bridge: AMD Miscellaneous Control
 * These devices do not support MMCFG access.
 */
boolean_t
npe_is_mmcfg_supported(dev_info_t *dip)
{
	int vendor_id, device_id;

	vendor_id = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "vendor-id", -1);
	device_id = ddi_prop_get_int(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "device-id", -1);

	return !(npe_child_is_pci(dip) ||
	    IS_BAD_AMD_NTBRIDGE(vendor_id, device_id));
}

int
npe_enable_htmsi(ddi_acc_handle_t cfg_hdl)
{
	uint16_t ptr;
	uint16_t reg;

	if (pci_htcap_locate(cfg_hdl, PCI_HTCAP_TYPE_MASK,
	    PCI_HTCAP_MSIMAP_TYPE, &ptr) != DDI_SUCCESS)
		return (DDI_FAILURE);

	reg = pci_config_get16(cfg_hdl, ptr + PCI_CAP_ID_REGS_OFF);
	reg |= PCI_HTCAP_MSIMAP_ENABLE;

	pci_config_put16(cfg_hdl, ptr + PCI_CAP_ID_REGS_OFF, reg);
	return (DDI_SUCCESS);
}

void
npe_enable_htmsi_children(dev_info_t *dip)
{
	dev_info_t *cdip = ddi_get_child(dip);
	ddi_acc_handle_t cfg_hdl;

	if (!npe_enable_htmsi_flag)
		return;

	/*
	 * Hypertransport MSI remapping only applies to AMD CPUs using
	 * Hypertransport (K8 and above) and not other platforms with non-AMD
	 * CPUs that may be using Hypertransport internally in the chipset(s)
	 */
	if (!(cpuid_getvendor(CPU) == X86_VENDOR_AMD &&
	    cpuid_getfamily(CPU) >= 0xf))
		return;

	for (; cdip != NULL; cdip = ddi_get_next_sibling(cdip)) {
		if (pci_config_setup(cdip, &cfg_hdl) != DDI_SUCCESS) {
			cmn_err(CE_NOTE, "!npe_enable_htmsi_children: "
			    "pci_config_setup failed for %s",
			    ddi_node_name(cdip));
			return;
		}

		(void) npe_enable_htmsi(cfg_hdl);
		pci_config_teardown(&cfg_hdl);
	}
}

/*
 * save config regs for HyperTransport devices without drivers of classes:
 * memory controller and hostbridge
 */
int
npe_save_htconfig_children(dev_info_t *dip)
{
	dev_info_t *cdip = ddi_get_child(dip);
	ddi_acc_handle_t cfg_hdl;
	uint16_t ptr;
	int rval = DDI_SUCCESS;
	uint8_t cl, scl;

	for (; cdip != NULL; cdip = ddi_get_next_sibling(cdip)) {
		if (ddi_driver_major(cdip) != DDI_MAJOR_T_NONE)
			continue;

		if (pci_config_setup(cdip, &cfg_hdl) != DDI_SUCCESS)
			return (DDI_FAILURE);

		cl = pci_config_get8(cfg_hdl, PCI_CONF_BASCLASS);
		scl = pci_config_get8(cfg_hdl, PCI_CONF_SUBCLASS);

		if (((cl == PCI_CLASS_MEM && scl == PCI_MEM_RAM) ||
		    (cl == PCI_CLASS_BRIDGE && scl == PCI_BRIDGE_HOST)) &&
		    pci_htcap_locate(cfg_hdl, 0, 0, &ptr) == DDI_SUCCESS) {

			if (pci_save_config_regs(cdip) != DDI_SUCCESS) {
				cmn_err(CE_WARN, "Failed to save HT config "
				    "regs for %s\n", ddi_node_name(cdip));
				rval = DDI_FAILURE;

			} else if (ddi_prop_update_int(DDI_DEV_T_NONE, cdip,
			    "htconfig-saved", 1) != DDI_SUCCESS) {
				cmn_err(CE_WARN, "Failed to set htconfig-saved "
				    "property for %s\n", ddi_node_name(cdip));
				rval = DDI_FAILURE;
			}
		}

		pci_config_teardown(&cfg_hdl);
	}

	return (rval);
}

int
npe_restore_htconfig_children(dev_info_t *dip)
{
	dev_info_t *cdip = ddi_get_child(dip);
	int rval = DDI_SUCCESS;

	for (; cdip != NULL; cdip = ddi_get_next_sibling(cdip)) {
		if (ddi_prop_get_int(DDI_DEV_T_ANY, cdip, DDI_PROP_DONTPASS,
		    "htconfig-saved", 0) == 0)
			continue;

		if (pci_restore_config_regs(cdip) != DDI_SUCCESS) {
			cmn_err(CE_WARN, "Failed to restore HT config "
			    "regs for %s\n", ddi_node_name(cdip));
			rval = DDI_FAILURE;
		}
	}

	return (rval);
}
