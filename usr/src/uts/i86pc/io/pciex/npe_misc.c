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
#include <io/pciex/pcie_nvidia.h>
#include <io/pciex/pcie_nb5000.h>

/*
 * Prototype declaration
 */
void	npe_query_acpi_mcfg(dev_info_t *dip);
void	npe_ck804_fix_aer_ptr(ddi_acc_handle_t cfg_hdl);
int	npe_disable_empty_bridges_workaround(dev_info_t *child);
void	npe_nvidia_error_mask(ddi_acc_handle_t cfg_hdl);
void	npe_intel_error_mask(ddi_acc_handle_t cfg_hdl);

/*
 * Default ecfga base address
 */
int64_t npe_default_ecfga_base = 0xE0000000;

extern uint32_t	npe_aer_uce_mask;
extern boolean_t pcie_full_scan;

/*
 * Query the MCFG table using ACPI.  If MCFG is found, setup the
 * 'ecfga-base-address' (Enhanced Configuration Access base address)
 * property accordingly.  Otherwise, set the value of the property
 * to the default value.
 */
void
npe_query_acpi_mcfg(dev_info_t *dip)
{
	MCFG_TABLE *mcfgp;
	CFG_BASE_ADDR_ALLOC *cfg_baap;
	char *cfg_baa_endp;
	uint64_t ecfga_base;

	/* Query the MCFG table using ACPI */
	if (AcpiGetTable(ACPI_SIG_MCFG, 1, (ACPI_TABLE_HEADER **)&mcfgp) ==
	    AE_OK) {

		cfg_baap = (CFG_BASE_ADDR_ALLOC *)mcfgp->CfgBaseAddrAllocList;
		cfg_baa_endp = ((char *)mcfgp) + mcfgp->Length;

		while ((char *)cfg_baap < cfg_baa_endp) {
			ecfga_base = cfg_baap->base_addr;
			if (ecfga_base != (uint64_t)0) {
				/*
				 * Setup the 'ecfga-base-address' property to
				 * the base_addr found in the MCFG and return.
				 */
				(void) ndi_prop_update_int64(DDI_DEV_T_NONE,
				    dip, "ecfga-base-address", ecfga_base);
				return;
			}
			cfg_baap++;
		}
	}
	/*
	 * If MCFG is not found or ecfga_base is not found in MCFG table,
	 * set the 'ecfga-base-address' property to the default value.
	 */
	(void) ndi_prop_update_int64(DDI_DEV_T_NONE, dip,
	    "ecfga-base-address", npe_default_ecfga_base);
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
	if (ddi_driver_major(child) == ddi_name_to_major("pcie_pci") &&
	    ddi_get_child(child) == NULL &&
	    ddi_prop_get_int(DDI_DEV_T_ANY, child, DDI_PROP_DONTPASS,
	    "pci-hotplug-type", INBAND_HPC_NONE) == INBAND_HPC_NONE)
		return (1);

	return (0);
}

void
npe_nvidia_error_mask(ddi_acc_handle_t cfg_hdl) {
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
		pcie_full_scan = B_TRUE;
	}
}

void
npe_intel_error_mask(ddi_acc_handle_t cfg_hdl) {
	uint32_t regs;
	uint16_t vendor_id = pci_config_get16(cfg_hdl, PCI_CONF_VENID);

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
	}
}
