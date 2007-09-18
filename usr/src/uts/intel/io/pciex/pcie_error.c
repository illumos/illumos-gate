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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 *	Library file that has code for PCIe error handling
 */

#include <sys/conf.h>
#include <sys/sysmacros.h>
#include <sys/kmem.h>
#include <sys/modctl.h>
#include <sys/pci.h>
#include <sys/pci_impl.h>
#include <sys/sunndi.h>
#include <sys/pcie.h>
#include <sys/pcie_impl.h>
#include <sys/promif.h>
#include <io/pciex/pcie_error.h>
#include <io/pciex/pcie_nvidia.h>

extern uint32_t pcie_expected_ue_mask;

#ifdef  DEBUG
uint_t	pcie_error_debug_flags = 0;
#define	PCIE_ERROR_DBG		pcie_error_dbg

static void	pcie_error_dbg(char *fmt, ...);
#else   /* DEBUG */
#define	PCIE_ERROR_DBG		0 &&
#endif  /* DEBUG */

/* Variables to control error settings */


/* Device Command Register */
ushort_t	pcie_command_default = \
		    PCI_COMM_SERR_ENABLE | \
		    PCI_COMM_WAIT_CYC_ENAB | \
		    PCI_COMM_PARITY_DETECT | \
		    PCI_COMM_ME | \
		    PCI_COMM_MAE | \
		    PCI_COMM_IO;

/* PCI-Express Device Control Register */
ushort_t	pcie_device_ctrl_default = \
		    PCIE_DEVCTL_CE_REPORTING_EN | \
		    PCIE_DEVCTL_NFE_REPORTING_EN | \
		    PCIE_DEVCTL_FE_REPORTING_EN | \
		    PCIE_DEVCTL_UR_REPORTING_EN | \
		    PCIE_DEVCTL_RO_EN;

/* PCI-Express AER Root Control Register */
#if defined(__xpv)
ushort_t	pcie_root_ctrl_default = \
		    PCIE_ROOTCTL_SYS_ERR_ON_NFE_EN | \
		    PCIE_ROOTCTL_SYS_ERR_ON_FE_EN;
#else
ushort_t	pcie_root_ctrl_default = \
		    PCIE_ROOTCTL_SYS_ERR_ON_CE_EN | \
		    PCIE_ROOTCTL_SYS_ERR_ON_NFE_EN | \
		    PCIE_ROOTCTL_SYS_ERR_ON_FE_EN;
#endif  /* __xpv */

/* PCI-Express Root Error Command Register */
ushort_t	pcie_root_error_cmd_default = \
		    PCIE_AER_RE_CMD_CE_REP_EN | \
		    PCIE_AER_RE_CMD_NFE_REP_EN | \
		    PCIE_AER_RE_CMD_FE_REP_EN;

/*
 * PCI-Express related masks (AER only)
 * Can be defined to mask off certain types of AER errors
 * By default all are set to 0; as no errors are masked
 */
uint32_t	pcie_aer_uce_mask = PCIE_AER_UCE_UC;
uint32_t	pcie_aer_ce_mask = 0;
uint32_t	pcie_aer_suce_mask = PCIE_AER_SUCE_RCVD_MA;

/*
 * PCI-Express related severity (AER only)
 * Used to set the severity levels of errors detected by devices on the PCI
 * Express fabric, which in turn results in either a fatal or nonfatal error
 * message to the root complex.  A set bit (1) indictates a fatal error, an
 * unset one is nonfatal.  For more information refer to the PCI Express Base
 * Specification and the PCI Express to PCI/PCI-X Bridge Specification.
 * default values are set below:
 */
uint32_t	pcie_aer_uce_severity = PCIE_AER_UCE_MTLP | PCIE_AER_UCE_RO | \
    PCIE_AER_UCE_FCP | PCIE_AER_UCE_SD | PCIE_AER_UCE_DLP | \
    PCIE_AER_UCE_TRAINING;
uint32_t	pcie_aer_suce_severity = PCIE_AER_SUCE_SERR_ASSERT | \
    PCIE_AER_SUCE_UC_ADDR_ERR | PCIE_AER_SUCE_UC_ATTR_ERR | \
    PCIE_AER_SUCE_USC_MSG_DATA_ERR;

/*
 * By default, error handling is enabled
 * Enable error handling flags. There are two flags
 *	pcie_error_disable_flag	: disable AER, Baseline error handling, SERR
 *		default value = 0	(do not disable error handling)
 *				1	(disable all error handling)
 *
 *	pcie_serr_disable_flag	: disable SERR only (in RCR and command reg)
 *		default value = 1	(disable SERR bits)
 *				0	(enable SERR handling)
 *
 *	pcie_aer_disable_flag	: disable AER only
 *		default value = 1	(disable AER bits)
 *				0	(enable AER handling)
 *
 * NOTE: pci_serr_disable_flag is a subset of pcie_error_disable_flag
 * If pcie_error_disable_flag is set; then pcie_serr_disable_flag is ignored
 * Above is also true for pcie_aer_disable_flag
 */
uint32_t	pcie_error_disable_flag = 0;
uint32_t	pcie_serr_disable_flag = 1;
uint32_t	pcie_aer_disable_flag = 0;

/*
 * Function prototypes
 */
static void	pcie_error_clear_errors(ddi_acc_handle_t, uint16_t,
		    uint16_t, uint16_t);
static void	pcie_check_io_mem_range(ddi_acc_handle_t, boolean_t *,
		    boolean_t *);
static uint16_t pcie_error_find_cap_reg(ddi_acc_handle_t, uint8_t);
static uint16_t	pcie_error_find_ext_aer_capid(ddi_acc_handle_t);
static void	pcie_nvidia_error_init(dev_info_t *, ddi_acc_handle_t,
		    uint16_t, uint16_t);
static void	pcie_nvidia_error_fini(ddi_acc_handle_t, uint16_t, uint16_t);

/*
 * modload support
 */

struct modlmisc modlmisc	= {
	&mod_miscops,	/* Type	of module */
	"PCI Express Error Support %I%"
};

struct modlinkage modlinkage = {
	MODREV_1, (void	*)&modlmisc, NULL
};

int
_init(void)
{
	return (mod_install(&modlinkage));
}

int
_fini()
{
	return (mod_remove(&modlinkage));
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * PCI-Express error initialization.
 */

/*
 * Enable generic pci-express interrupts and error handling.
 */
int
pcie_error_enable(dev_info_t *cdip, ddi_acc_handle_t cfg_hdl)
{
	uint8_t		header_type;
	uint8_t		bcr;
	uint16_t	command_reg, status_reg;
	uint16_t	cap_ptr = 0;
	uint16_t	aer_ptr = 0;
	uint16_t	device_ctl;
	uint16_t	dev_type = 0;
	uint16_t	vendor_id, device_id;
	uint32_t	aer_reg;
	uint32_t	uce_mask = pcie_aer_uce_mask;
	boolean_t	empty_io_range = B_FALSE;
	boolean_t	empty_mem_range = B_FALSE;

	/*
	 * flag to turn this off
	 */
	if (pcie_error_disable_flag)
		return (DDI_SUCCESS);

	/* Determine the configuration header type */
	header_type = pci_config_get8(cfg_hdl, PCI_CONF_HEADER);
	PCIE_ERROR_DBG("%s: header_type=%x\n",
	    ddi_driver_name(cdip), header_type);

	/* Look for PCIe capability */
	cap_ptr = pcie_error_find_cap_reg(cfg_hdl, PCI_CAP_ID_PCI_E);
	if (cap_ptr != PCI_CAP_NEXT_PTR_NULL) {	/* PCIe found */
		aer_ptr = pcie_error_find_ext_aer_capid(cfg_hdl);
		if (aer_ptr != PCI_CAP_NEXT_PTR_NULL)
			(void) ndi_prop_update_int(DDI_DEV_T_NONE, cdip,
			    "pcie-aer-pointer", aer_ptr);
		dev_type = pci_config_get16(cfg_hdl, cap_ptr +
		    PCIE_PCIECAP) & PCIE_PCIECAP_DEV_TYPE_MASK;
	}

	/* Setup the device's command register */
	status_reg = pci_config_get16(cfg_hdl, PCI_CONF_STAT);
	pci_config_put16(cfg_hdl, PCI_CONF_STAT, status_reg);
	command_reg = pci_config_get16(cfg_hdl, PCI_CONF_COMM);
	if (pcie_serr_disable_flag && cap_ptr != PCI_CAP_NEXT_PTR_NULL) {
		pcie_command_default &= ~PCI_COMM_SERR_ENABLE;
		/* shouldn't happen; just in case */
		if (command_reg & PCI_COMM_SERR_ENABLE)
			command_reg &= ~PCI_COMM_SERR_ENABLE;
	}
	/* Check io and mem ranges for empty bridges */
	pcie_check_io_mem_range(cfg_hdl, &empty_io_range, &empty_mem_range);
	if ((empty_io_range == B_TRUE) &&
	    (pcie_command_default & PCI_COMM_IO)) {
		pcie_command_default &= ~PCI_COMM_IO;
		PCIE_ERROR_DBG("%s: No I/O range found\n",
		    ddi_driver_name(cdip));
	}
	if ((empty_mem_range == B_TRUE) &&
	    (pcie_command_default & PCI_COMM_MAE)) {
		pcie_command_default &= ~PCI_COMM_MAE;
		PCIE_ERROR_DBG("%s: No Mem range found\n",
		    ddi_driver_name(cdip));
	}
	command_reg |= pcie_command_default;
	pci_config_put16(cfg_hdl, PCI_CONF_COMM, command_reg);

	PCIE_ERROR_DBG("%s: command=%x\n", ddi_driver_name(cdip),
	    pci_config_get16(cfg_hdl, PCI_CONF_COMM));

	/*
	 * If the device has a bus control register then program it
	 * based on the settings in the command register.
	 */
	if ((header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_ONE) {
		status_reg = pci_config_get16(cfg_hdl, PCI_BCNF_SEC_STATUS);
		pci_config_put16(cfg_hdl, PCI_BCNF_SEC_STATUS, status_reg);
		bcr = pci_config_get8(cfg_hdl, PCI_BCNF_BCNTRL);
		if (pcie_command_default & PCI_COMM_PARITY_DETECT)
			bcr |= PCI_BCNF_BCNTRL_PARITY_ENABLE;
		if (pcie_command_default & PCI_COMM_SERR_ENABLE) {
			if (pcie_serr_disable_flag &&
			    cap_ptr != PCI_CAP_NEXT_PTR_NULL &&
			    dev_type == PCIE_PCIECAP_DEV_TYPE_ROOT)
				bcr &= ~PCI_BCNF_BCNTRL_SERR_ENABLE;
			else
				bcr |= PCI_BCNF_BCNTRL_SERR_ENABLE;
		}

		/* Always clear Master Abort Mode bit */
		bcr &= ~PCI_BCNF_BCNTRL_MAST_AB_MODE;
		pci_config_put8(cfg_hdl, PCI_BCNF_BCNTRL, bcr);
	}

	/*
	 * Clear any pending errors
	 */
	pcie_error_clear_errors(cfg_hdl, cap_ptr, aer_ptr, dev_type);

	/* No PCIe; just return */
	if (cap_ptr == PCI_CAP_NEXT_PTR_NULL)
		return (DDI_SUCCESS);

	/*
	 * Enable PCI-Express Baseline Error Handling
	 */
	device_ctl = pci_config_get16(cfg_hdl, cap_ptr + PCIE_DEVCTL);
	device_ctl |= pcie_device_ctrl_default;

	/*
	 * Disable UR for any non-RBER enabled leaf PCIe device,
	 * bridge or switch devices.
	 */
	if ((dev_type == PCIE_PCIECAP_DEV_TYPE_PCIE_DEV ||
	    dev_type == PCIE_PCIECAP_DEV_TYPE_UP ||
	    dev_type == PCIE_PCIECAP_DEV_TYPE_DOWN ||
	    dev_type == PCIE_PCIECAP_DEV_TYPE_PCIE2PCI) &&
	    ((pci_config_get16(cfg_hdl, cap_ptr + PCIE_DEVCAP) &
	    PCIE_DEVCAP_ROLE_BASED_ERR_REP) !=
	    PCIE_DEVCAP_ROLE_BASED_ERR_REP))
		device_ctl &= ~PCIE_DEVCTL_UR_REPORTING_EN;

	/*
	 * Disable AER for CK8-04 devices with revid < 0xA3
	 */
	vendor_id = pci_config_get16(cfg_hdl, PCI_CONF_VENID);
	device_id = pci_config_get16(cfg_hdl, PCI_CONF_DEVID);
	if ((vendor_id == NVIDIA_VENDOR_ID) &&
	    (device_id == NVIDIA_CK804_DEVICE_ID) &&
	    (pci_config_get8(cfg_hdl, PCI_CONF_REVID) <
	    NVIDIA_CK804_AER_VALID_REVID)) {
		aer_ptr = PCIE_EXT_CAP_NEXT_PTR_NULL;
	}

	/*
	 * For Nvidia chipset, call pcie_nvidia_error_init().
	 *
	 * For non-Nvidia Root Ports, disable UR for all child devices by
	 * changing the default ue mask (for AER devices) and the default
	 * device control value (for non-AER device).
	 */
	if ((vendor_id == NVIDIA_VENDOR_ID) && NVIDIA_PCIE_RC_DEV_ID(device_id))
		pcie_nvidia_error_init(cdip, cfg_hdl, cap_ptr, aer_ptr);
	else if (dev_type == PCIE_PCIECAP_DEV_TYPE_ROOT) {
		pcie_expected_ue_mask |= PCIE_AER_UCE_UR;
		pcie_device_ctrl_default &= ~PCIE_DEVCTL_UR_REPORTING_EN;
		device_ctl &= ~PCIE_DEVCTL_UR_REPORTING_EN;
	}

	pci_config_put16(cfg_hdl, cap_ptr + PCIE_DEVCTL, device_ctl);

	PCIE_ERROR_DBG("%s: device control=0x%x->0x%x\n",
	    ddi_driver_name(cdip), device_ctl,
	    pci_config_get16(cfg_hdl, cap_ptr + PCIE_DEVCTL));

	/*
	 * Enable PCI-Express Advanced Error Handling if Exists
	 */
	if (aer_ptr == PCIE_EXT_CAP_NEXT_PTR_NULL)
		return (DDI_SUCCESS);


	if (pcie_aer_disable_flag)
		return (DDI_SUCCESS);

	/* Disable PTLP/ECRC (or mask these two) for Switches */
	if (dev_type == PCIE_PCIECAP_DEV_TYPE_UP ||
	    dev_type == PCIE_PCIECAP_DEV_TYPE_DOWN)
		uce_mask |= (PCIE_AER_UCE_PTLP | PCIE_AER_UCE_ECRC);

	/* Set Uncorrectable error severity */
	aer_reg = pci_config_get32(cfg_hdl, aer_ptr + PCIE_AER_UCE_SERV);
	pci_config_put32(cfg_hdl, aer_ptr + PCIE_AER_UCE_SERV,
	    pcie_aer_uce_severity);
	PCIE_ERROR_DBG("%s: AER UCE severity=0x%x->0x%x\n",
	    ddi_driver_name(cdip), aer_reg, pci_config_get32(cfg_hdl,
	    aer_ptr + PCIE_AER_UCE_SERV));

	/* Enable Uncorrectable errors */
	aer_reg = pci_config_get32(cfg_hdl, aer_ptr + PCIE_AER_UCE_MASK);
	pci_config_put32(cfg_hdl, aer_ptr + PCIE_AER_UCE_MASK,
	    aer_reg | uce_mask);
	PCIE_ERROR_DBG("%s: AER UCE mask=0x%x->0x%x\n", ddi_driver_name(cdip),
	    aer_reg, pci_config_get32(cfg_hdl, aer_ptr + PCIE_AER_UCE_MASK));

	/* Enable Correctable errors */
	aer_reg = pci_config_get32(cfg_hdl, aer_ptr + PCIE_AER_CE_MASK);
	pci_config_put32(cfg_hdl, aer_ptr + PCIE_AER_CE_MASK,
	    aer_reg | pcie_aer_ce_mask);
	PCIE_ERROR_DBG("%s: AER CE mask=0x%x->0x%x\n", ddi_driver_name(cdip),
	    aer_reg, pci_config_get32(cfg_hdl, aer_ptr + PCIE_AER_CE_MASK));

	/*
	 * Enable Secondary Uncorrectable errors if this is a bridge
	 */
	if (!(dev_type == PCIE_PCIECAP_DEV_TYPE_PCIE2PCI))
		return (DDI_SUCCESS);

	/* Set Secondary Uncorrectable error severity */
	aer_reg = pci_config_get32(cfg_hdl, aer_ptr + PCIE_AER_SUCE_SERV);
	pci_config_put32(cfg_hdl, aer_ptr + PCIE_AER_SUCE_SERV,
	    pcie_aer_suce_severity);
	PCIE_ERROR_DBG("%s: AER SUCE severity=0x%x->0x%x\n",
	    ddi_driver_name(cdip), aer_reg,
	    pci_config_get32(cfg_hdl, aer_ptr + PCIE_AER_SUCE_SERV));

	/*
	 * Enable secondary bus errors
	 */
	aer_reg = pci_config_get32(cfg_hdl, aer_ptr + PCIE_AER_SUCE_MASK);
	pci_config_put32(cfg_hdl, aer_ptr + PCIE_AER_SUCE_MASK,
	    aer_reg | pcie_aer_suce_mask);
	PCIE_ERROR_DBG("%s: AER SUCE mask=0x%x->0x%x\n",
	    ddi_driver_name(cdip), aer_reg,
	    pci_config_get32(cfg_hdl, aer_ptr + PCIE_AER_SUCE_MASK));

	return (DDI_SUCCESS);
}


static void
pcie_check_io_mem_range(ddi_acc_handle_t cfg_hdl, boolean_t *empty_io_range,
    boolean_t *empty_mem_range)
{
	uint8_t	class, subclass;
	uint_t	val;

	class = pci_config_get8(cfg_hdl, PCI_CONF_BASCLASS);
	subclass = pci_config_get8(cfg_hdl, PCI_CONF_SUBCLASS);

	if ((class == PCI_CLASS_BRIDGE) && (subclass == PCI_BRIDGE_PCI)) {
		val = (((uint_t)pci_config_get8(cfg_hdl, PCI_BCNF_IO_BASE_LOW) &
		    0xf0) << 8);
		/*
		 * Assuming that a zero based io_range[0] implies an
		 * invalid I/O range.  Likewise for mem_range[0].
		 */
		if (val == 0)
			*empty_io_range = B_TRUE;
		val = (((uint_t)pci_config_get16(cfg_hdl, PCI_BCNF_MEM_BASE) &
		    0xfff0) << 16);
		if (val == 0)
			*empty_mem_range = B_TRUE;
	}
}

/* ARGSUSED */
static void
pcie_nvidia_error_init(dev_info_t *child, ddi_acc_handle_t cfg_hdl,
    uint16_t cap_ptr, uint16_t aer_ptr)
{
	uint16_t	rc_ctl;

	/* Program SERR_FORWARD bit in NV_XVR_INTR_BCR */
	rc_ctl = pci_config_get16(cfg_hdl, NVIDIA_INTR_BCR_OFF + 0x2);
	pci_config_put16(cfg_hdl, NVIDIA_INTR_BCR_OFF + 0x2,
	    rc_ctl | NVIDIA_INTR_BCR_SERR_FORWARD_BIT);
	PCIE_ERROR_DBG("%s: PCIe NV_XVR_INTR_BCR=0x%x->0x%x\n",
	    ddi_driver_name(child), rc_ctl,
	    pci_config_get16(cfg_hdl, NVIDIA_INTR_BCR_OFF + 0x2));

#if defined(__xpv)
	/*
	 * When we're booted under the hypervisor we won't receive MSI's, so
	 * to ensure that uncorrectable errors aren't ignored we set the
	 * SERR_FAT and SERR_NONFAT bits in the Root Control Register.
	 */
	rc_ctl = pci_config_get16(cfg_hdl, cap_ptr + PCIE_ROOTCTL);
	pci_config_put16(cfg_hdl, cap_ptr + PCIE_ROOTCTL,
	    rc_ctl | pcie_root_ctrl_default);
	PCIE_ERROR_DBG("%s: PCIe Root Control Register=0x%x->0x%x\n",
	    ddi_driver_name(child), rc_ctl,
	    pci_config_get16(cfg_hdl, cap_ptr + PCIE_ROOTCTL));
#else
	rc_ctl = pci_config_get16(cfg_hdl, cap_ptr + PCIE_ROOTCTL);
	pci_config_put16(cfg_hdl, cap_ptr + PCIE_ROOTCTL,
	    pcie_serr_disable_flag ? (rc_ctl & ~pcie_root_ctrl_default) :
	    (rc_ctl | pcie_root_ctrl_default));
	PCIE_ERROR_DBG("%s: PCIe Root Control Register=0x%x->0x%x\n",
	    ddi_driver_name(child), rc_ctl,
	    pci_config_get16(cfg_hdl, cap_ptr + PCIE_ROOTCTL));

	/* Root Error Command Register */
	if (!aer_ptr || pcie_aer_disable_flag)
		return;

	rc_ctl = pci_config_get16(cfg_hdl, aer_ptr + PCIE_AER_RE_CMD);
	pci_config_put16(cfg_hdl, aer_ptr + PCIE_AER_RE_CMD,
	    rc_ctl | pcie_root_error_cmd_default);
	PCIE_ERROR_DBG("%s: PCIe AER Root Error Command "
	    "Register=0x%x->0x%x\n", ddi_driver_name(child), rc_ctl,
	    pci_config_get16(cfg_hdl, aer_ptr + PCIE_AER_RE_CMD));

	/* Also enable ECRC checking */
	rc_ctl = pci_config_get16(cfg_hdl, aer_ptr + PCIE_AER_CTL);
	if (rc_ctl & PCIE_AER_CTL_ECRC_GEN_CAP)
		rc_ctl |= PCIE_AER_CTL_ECRC_GEN_ENA;
	if (rc_ctl & PCIE_AER_CTL_ECRC_CHECK_CAP)
		rc_ctl |= PCIE_AER_CTL_ECRC_CHECK_ENA;
	pci_config_put16(cfg_hdl, aer_ptr + PCIE_AER_CTL, rc_ctl);
#endif  /* __xpv */
}

/*
 * Disable generic pci-express interrupts and error handling.
 */
void
pcie_error_disable(dev_info_t *cdip, ddi_acc_handle_t cfg_hdl)
{
	uint16_t	cap_ptr, aer_ptr;
	uint16_t	dev_type;
	uint8_t		header_type;
	uint8_t		bcr;
	uint16_t	command_reg, status_reg;
	uint16_t	vendor_id, device_id;

	if (pcie_error_disable_flag)
		return;

	/* Determine the configuration header type */
	header_type = pci_config_get8(cfg_hdl, PCI_CONF_HEADER);
	status_reg = pci_config_get16(cfg_hdl, PCI_CONF_STAT);
	pci_config_put16(cfg_hdl, PCI_CONF_STAT, status_reg);

	/* Clear the device's command register (SERR and PARITY detect) */
	command_reg = pci_config_get16(cfg_hdl, PCI_CONF_COMM);
	if (pcie_serr_disable_flag || (command_reg & PCI_COMM_SERR_ENABLE))
		command_reg &= ~PCI_COMM_SERR_ENABLE;
	command_reg &= ~PCI_COMM_PARITY_DETECT;
	pci_config_put16(cfg_hdl, PCI_CONF_COMM, command_reg);

	/*
	 * If the device has a bus control register then clear
	 * SERR, Master Abort and Parity detect
	 */
	if ((header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_ONE) {
		status_reg = pci_config_get16(cfg_hdl, PCI_BCNF_SEC_STATUS);
		pci_config_put16(cfg_hdl, PCI_BCNF_SEC_STATUS, status_reg);
		bcr = pci_config_get8(cfg_hdl, PCI_BCNF_BCNTRL);
		if (pcie_command_default & PCI_COMM_PARITY_DETECT)
			bcr &= ~PCI_BCNF_BCNTRL_PARITY_ENABLE;
		if ((pcie_command_default & PCI_COMM_SERR_ENABLE) ||
		    (pcie_serr_disable_flag))
			bcr &= ~PCI_BCNF_BCNTRL_SERR_ENABLE;
		bcr &= ~PCI_BCNF_BCNTRL_MAST_AB_MODE;
		pci_config_put8(cfg_hdl, PCI_BCNF_BCNTRL, bcr);
	}

	cap_ptr = pcie_error_find_cap_reg(cfg_hdl, PCI_CAP_ID_PCI_E);
	if (cap_ptr == PCI_CAP_NEXT_PTR_NULL)
		return;

	/* Disable PCI-Express Baseline Error Handling */
	pci_config_put16(cfg_hdl, cap_ptr + PCIE_DEVCTL, 0x0);

	aer_ptr = ddi_prop_get_int(DDI_DEV_T_ANY, cdip, DDI_PROP_DONTPASS,
	    "pcie-aer-pointer", PCIE_EXT_CAP_NEXT_PTR_NULL);

	/*
	 * Disable AER for CK8-04 devices with revid < 0xA3
	 */
	vendor_id = pci_config_get16(cfg_hdl, PCI_CONF_VENID);
	device_id = pci_config_get16(cfg_hdl, PCI_CONF_DEVID);
	if ((vendor_id == NVIDIA_VENDOR_ID) &&
	    (device_id == NVIDIA_CK804_DEVICE_ID) &&
	    (pci_config_get8(cfg_hdl, PCI_CONF_REVID) <
	    NVIDIA_CK804_AER_VALID_REVID)) {
		aer_ptr = PCIE_EXT_CAP_NEXT_PTR_NULL;
	}

	/*
	 * Only disable these set of errors for CK8-04/IO-4 devices
	 */
	if ((vendor_id == NVIDIA_VENDOR_ID) && NVIDIA_PCIE_RC_DEV_ID(device_id))
		pcie_nvidia_error_fini(cfg_hdl, cap_ptr, aer_ptr);

	if (aer_ptr == PCIE_EXT_CAP_NEXT_PTR_NULL)
		return;

	/* Disable AER bits */
	if (!pcie_aer_disable_flag) {
		/* Disable Uncorrectable errors */
		pci_config_put32(cfg_hdl, aer_ptr + PCIE_AER_UCE_MASK,
		    PCIE_AER_UCE_BITS);

		/* Disable Correctable errors */
		pci_config_put32(cfg_hdl,
		    aer_ptr + PCIE_AER_CE_MASK, PCIE_AER_CE_BITS);

		/* Disable Secondary Uncorrectable errors if this is a bridge */
		dev_type = pci_config_get16(cfg_hdl, cap_ptr + PCIE_PCIECAP) &
		    PCIE_PCIECAP_DEV_TYPE_MASK;
		if (!(dev_type == PCIE_PCIECAP_DEV_TYPE_PCIE2PCI))
			return;

		pci_config_put32(cfg_hdl, aer_ptr + PCIE_AER_SUCE_MASK,
		    PCIE_AER_SUCE_BITS);
	}
}


static void
pcie_nvidia_error_fini(ddi_acc_handle_t cfg_hdl, uint16_t cap_ptr,
    uint16_t aer_ptr)
{
	uint16_t	rc_ctl;

	if (!pcie_serr_disable_flag) {
		rc_ctl = pci_config_get16(cfg_hdl, cap_ptr + PCIE_ROOTCTL);
		rc_ctl &= ~pcie_root_ctrl_default;
		pci_config_put16(cfg_hdl, cap_ptr + PCIE_ROOTCTL, rc_ctl);
	}

	/* Root Error Command Register */
	if (aer_ptr && !pcie_aer_disable_flag) {
		rc_ctl = pci_config_get16(cfg_hdl, aer_ptr + PCIE_AER_RE_CMD);
		rc_ctl &= ~pcie_root_error_cmd_default;
		pci_config_put16(cfg_hdl, aer_ptr + PCIE_AER_RE_CMD, rc_ctl);

		/* Disable ECRC checking */
		rc_ctl = pci_config_get16(cfg_hdl, aer_ptr + PCIE_AER_CTL);
		if (rc_ctl & PCIE_AER_CTL_ECRC_GEN_CAP)
			rc_ctl &= ~PCIE_AER_CTL_ECRC_GEN_ENA;
		if (rc_ctl & PCIE_AER_CTL_ECRC_CHECK_CAP)
			rc_ctl &= ~PCIE_AER_CTL_ECRC_CHECK_ENA;
		pci_config_put16(cfg_hdl, aer_ptr + PCIE_AER_CTL, rc_ctl);
	}
}

/*
 * Clear any pending errors
 */
static void
pcie_error_clear_errors(ddi_acc_handle_t cfg_hdl, uint16_t cap_ptr,
    uint16_t aer_ptr, uint16_t dev_type)
{
	uint16_t	device_sts;

	/* 1. clear the Advanced PCIe Errors */
	if (cap_ptr && aer_ptr) {
		pci_config_put32(cfg_hdl, aer_ptr + PCIE_AER_CE_STS, -1);
		pci_config_put32(cfg_hdl, aer_ptr + PCIE_AER_UCE_STS, -1);
		if (dev_type == PCIE_PCIECAP_DEV_TYPE_PCIE2PCI)
			pci_config_put32(cfg_hdl,
			    aer_ptr + PCIE_AER_SUCE_STS, -1);
	}

	/* 2. clear the PCIe Errors */
	if (cap_ptr) {
		device_sts = pci_config_get16(cfg_hdl, cap_ptr + PCIE_DEVSTS);
		pci_config_put16(cfg_hdl, cap_ptr + PCIE_DEVSTS, device_sts);
	}

	/* 3. clear the Legacy PCI Errors */
	device_sts = pci_config_get16(cfg_hdl, PCI_CONF_STAT);
	pci_config_put16(cfg_hdl, PCI_CONF_STAT, device_sts);
	if (dev_type == PCIE_PCIECAP_DEV_TYPE_PCIE2PCI) {
		device_sts = pci_config_get16(cfg_hdl, PCI_BCNF_SEC_STATUS);
		pci_config_put16(cfg_hdl, PCI_BCNF_SEC_STATUS, device_sts);
	}
}


/*
 * Helper Function to traverse the pci-express config space looking
 * for the pci-express capability id pointer.
 */
static uint16_t
pcie_error_find_cap_reg(ddi_acc_handle_t cfg_hdl, uint8_t cap_id)
{
	uint16_t	caps_ptr, cap;
	ushort_t	status;

	/*
	 * Check if capabilities list is supported.  If not then it is a PCI
	 * device.
	 */
	status = pci_config_get16(cfg_hdl, PCI_CONF_STAT);
	if (status == 0xff || !((status & PCI_STAT_CAP)))
		return (PCI_CAP_NEXT_PTR_NULL);

	caps_ptr = P2ALIGN(pci_config_get8(cfg_hdl, PCI_CONF_CAP_PTR), 4);
	while (caps_ptr && caps_ptr >= PCI_CAP_PTR_OFF) {
		caps_ptr &= PCI_CAP_PTR_MASK;
		cap = pci_config_get8(cfg_hdl, caps_ptr);
		if (cap == cap_id) {
			break;
		} else if (cap == 0xff)
			return (PCI_CAP_NEXT_PTR_NULL);

		caps_ptr = P2ALIGN(pci_config_get8(cfg_hdl,
		    (caps_ptr + PCI_CAP_NEXT_PTR)), 4);
	}

	return (caps_ptr);
}

/*
 * Helper Function to traverse the pci-express extended config space looking
 * for the pci-express capability id pointer.
 */
static uint16_t
pcie_error_find_ext_aer_capid(ddi_acc_handle_t cfg_hdl)
{
	uint32_t	hdr, hdr_next_ptr, hdr_cap_id;
	uint16_t	offset = P2ALIGN(PCIE_EXT_CAP, 4);

	hdr = pci_config_get32(cfg_hdl, offset);
	hdr_next_ptr = (hdr >> PCIE_EXT_CAP_NEXT_PTR_SHIFT) &
	    PCIE_EXT_CAP_NEXT_PTR_MASK;
	hdr_cap_id = (hdr >> PCIE_EXT_CAP_ID_SHIFT) & PCIE_EXT_CAP_ID_MASK;

	while ((hdr_next_ptr != PCIE_EXT_CAP_NEXT_PTR_NULL) &&
	    (hdr_cap_id != PCIE_EXT_CAP_ID_AER)) {
		offset = P2ALIGN(hdr_next_ptr, 4);
		hdr = pci_config_get32(cfg_hdl, offset);
		hdr_next_ptr = (hdr >> PCIE_EXT_CAP_NEXT_PTR_SHIFT) &
		    PCIE_EXT_CAP_NEXT_PTR_MASK;
		hdr_cap_id = (hdr >> PCIE_EXT_CAP_ID_SHIFT) &
		    PCIE_EXT_CAP_ID_MASK;
	}

	if (hdr_cap_id == PCIE_EXT_CAP_ID_AER)
		return (P2ALIGN(offset, 4));

	return (PCIE_EXT_CAP_NEXT_PTR_NULL);
}

#ifdef	DEBUG
static void
pcie_error_dbg(char *fmt, ...)
{
	va_list ap;

	if (!pcie_error_debug_flags)
		return;

	va_start(ap, fmt);
	prom_vprintf(fmt, ap);
	va_end(ap);
}
#endif	/* DEBUG */
