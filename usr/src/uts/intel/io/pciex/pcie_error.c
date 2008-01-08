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
#include <io/pciex/pcie_nb5000.h>

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
#define	PCIE_DEVCTL_ERR_ALL \
	(PCIE_DEVCTL_CE_REPORTING_EN | \
	PCIE_DEVCTL_NFE_REPORTING_EN | \
	PCIE_DEVCTL_FE_REPORTING_EN | \
	PCIE_DEVCTL_UR_REPORTING_EN)

ushort_t	pcie_device_ctrl_default = \
		    PCIE_DEVCTL_ERR_ALL | PCIE_DEVCTL_RO_EN;


/* PCI-Express Root Control Register */
#define	PCIE_ROOTCTL_SYS_ERR_ALL \
	(PCIE_ROOTCTL_SYS_ERR_ON_CE_EN | \
	PCIE_ROOTCTL_SYS_ERR_ON_NFE_EN | \
	PCIE_ROOTCTL_SYS_ERR_ON_FE_EN)

ushort_t	pcie_root_ctrl_default = \
		    PCIE_ROOTCTL_SYS_ERR_ON_NFE_EN | \
		    PCIE_ROOTCTL_SYS_ERR_ON_FE_EN;


/* PCI-Express AER Root Error Command Register */
#define	PCIE_AER_RE_CMD_ERR_ALL \
	(PCIE_AER_RE_CMD_CE_REP_EN | \
	PCIE_AER_RE_CMD_NFE_REP_EN | \
	PCIE_AER_RE_CMD_FE_REP_EN)

ushort_t	pcie_root_error_cmd_default = PCIE_AER_RE_CMD_ERR_ALL;


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
 *	pcie_serr_disable_flag	: disable all error reporting via SERR for
 *				: PCIE root ports in the absence of AER
 *		default value = 0	(disable SERR)
 *				1	(enable SERR)
 *
 *	pcie_aer_disable_flag	: disable AER only (simulates absent AER)
 *		default value = 0	(enable AER handling)
 *				1	(disable AER bits)
 *
 * NOTE: pci_serr_disable_flag is a subset of pcie_error_disable_flag
 * If pcie_error_disable_flag is set; then pcie_serr_disable_flag is ignored
 * Above is also true for pcie_aer_disable_flag
 */
uint32_t	pcie_error_disable_flag = 0;
uint32_t	pcie_serr_disable_flag = 0;
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
static void	pcie_rc_error_init(dev_info_t *, ddi_acc_handle_t,
    uint16_t, uint16_t);
static void	pcie_rc_error_fini(ddi_acc_handle_t, uint16_t, uint16_t);


/*
 * bridge interrupt handling
 */

/*
 * root port/chipset MSI control
 * the values for pcie_bridge_msi_flag must be ordered as follows
 *
 * PCIE_BRIDGE_INTR_DISABLE = disable all interrupts
 * PCIE_BRIDGE_MSI_DISABLE = only use fixed interrupts
 * PCIE_BRIDGE_MSI_ENABLE = use MSI for supported chipsets if hardware enabled
 * PCIE_BRIDGE_MSI_ENABLE_ON = enable hardware MSI for supported chipsets
 * PCIE_BRIDGE_MSI_ENABLE_ALL = use MSI for all chipsets
 */
#define	PCIE_BRIDGE_INTR_DISABLE	-1
#define	PCIE_BRIDGE_MSI_DISABLE		0
#define	PCIE_BRIDGE_MSI_ENABLE		1
#define	PCIE_BRIDGE_MSI_ENABLE_ON	2
#define	PCIE_BRIDGE_MSI_ENABLE_ALL	3

int pcie_bridge_msi_flag = PCIE_BRIDGE_MSI_ENABLE;

/* enable MSI for switches and other non-root-complex bridges */
int pcie_bridge_msi_nonrc_flag = 0;

/* enable bridge to interrupt when it recieves a PME message */
int pcie_bridge_enable_pme = 0;


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
		aer_ptr = pcie_aer_disable_flag ?
		    PCIE_EXT_CAP_NEXT_PTR_NULL :
		    pcie_error_find_ext_aer_capid(cfg_hdl);

		if (aer_ptr != PCIE_EXT_CAP_NEXT_PTR_NULL)
			(void) ndi_prop_update_int(DDI_DEV_T_NONE, cdip,
			    "pcie-aer-pointer", aer_ptr);

		dev_type = pci_config_get16(cfg_hdl, cap_ptr +
		    PCIE_PCIECAP) & PCIE_PCIECAP_DEV_TYPE_MASK;
	}

	/* Setup the device's command register */
	status_reg = pci_config_get16(cfg_hdl, PCI_CONF_STAT);
	pci_config_put16(cfg_hdl, PCI_CONF_STAT, status_reg);

	command_reg = pci_config_get16(cfg_hdl, PCI_CONF_COMM);
	command_reg |= pcie_command_default;

	/*
	 * when to disable SERR:
	 * - AER present (any PCIE device) to allow finer grained control
	 * - root port without AER and pcie_serr_disable_flag is set
	 */
	if (aer_ptr != PCIE_EXT_CAP_NEXT_PTR_NULL ||
	    (dev_type == PCIE_PCIECAP_DEV_TYPE_ROOT &&
	    pcie_serr_disable_flag))
		command_reg &= ~PCI_COMM_SERR_ENABLE;

	/* Check io and mem ranges for empty bridges */
	pcie_check_io_mem_range(cfg_hdl, &empty_io_range, &empty_mem_range);
	if (empty_io_range == B_TRUE) {
		command_reg &= ~PCI_COMM_IO;
		PCIE_ERROR_DBG("%s: No I/O range found\n",
		    ddi_driver_name(cdip));
	}
	if (empty_mem_range == B_TRUE) {
		command_reg &= ~PCI_COMM_MAE;
		PCIE_ERROR_DBG("%s: No Mem range found\n",
		    ddi_driver_name(cdip));
	}
	pci_config_put16(cfg_hdl, PCI_CONF_COMM, command_reg);

	PCIE_ERROR_DBG("%s: command=%x\n", ddi_driver_name(cdip),
	    pci_config_get16(cfg_hdl, PCI_CONF_COMM));

	/*
	 * For PCI bridges:
	 * If the device has a bus control register then program it
	 * based on the settings in the command register.
	 *
	 * For PCIE bridges:
	 * Always enable PERR detection and SERR foward, unless:
	 * - root port without AER and pcie_serr_disable_flag is set
	 */
	if ((header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_ONE) {
		status_reg = pci_config_get16(cfg_hdl, PCI_BCNF_SEC_STATUS);
		pci_config_put16(cfg_hdl, PCI_BCNF_SEC_STATUS, status_reg);

		bcr = pci_config_get8(cfg_hdl, PCI_BCNF_BCNTRL);
		if (cap_ptr != PCI_CAP_NEXT_PTR_NULL) {
			if (dev_type == PCIE_PCIECAP_DEV_TYPE_ROOT &&
			    aer_ptr == PCIE_EXT_CAP_NEXT_PTR_NULL &&
			    pcie_serr_disable_flag) {
				bcr &= ~(PCI_BCNF_BCNTRL_PARITY_ENABLE |
				    PCI_BCNF_BCNTRL_SERR_ENABLE);
			} else {
				bcr |= (PCI_BCNF_BCNTRL_PARITY_ENABLE |
				    PCI_BCNF_BCNTRL_SERR_ENABLE);
			}
		} else {
			if (command_reg & PCI_COMM_PARITY_DETECT)
				bcr |= PCI_BCNF_BCNTRL_PARITY_ENABLE;
			if (command_reg & PCI_COMM_SERR_ENABLE)
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

	if (dev_type == PCIE_PCIECAP_DEV_TYPE_ROOT) {
		pcie_rc_error_init(cdip, cfg_hdl, cap_ptr, aer_ptr);

		/*
		 * without AER, disable UR for all child devices by
		 * changing the default ue mask (for AER devices) and the
		 * default device control value (for non-AER device).
		 */
		if (aer_ptr == PCIE_EXT_CAP_NEXT_PTR_NULL) {
			pcie_expected_ue_mask |= PCIE_AER_UCE_UR;
			pcie_device_ctrl_default &=
			    ~PCIE_DEVCTL_UR_REPORTING_EN;
			device_ctl &= ~PCIE_DEVCTL_UR_REPORTING_EN;
		}
	}

	pci_config_put16(cfg_hdl, cap_ptr + PCIE_DEVCTL, device_ctl);

	PCIE_ERROR_DBG("%s: device control=0x%x\n",
	    ddi_driver_name(cdip),
	    pci_config_get16(cfg_hdl, cap_ptr + PCIE_DEVCTL));

	/*
	 * Enable PCI-Express Advanced Error Handling if Exists
	 */
	if (aer_ptr == PCIE_EXT_CAP_NEXT_PTR_NULL)
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
pcie_rc_error_init(dev_info_t *child, ddi_acc_handle_t cfg_hdl,
    uint16_t cap_ptr, uint16_t aer_ptr)
{
	uint16_t	rc_ctl;

	rc_ctl = pci_config_get16(cfg_hdl, cap_ptr + PCIE_ROOTCTL);
	rc_ctl &= ~PCIE_ROOTCTL_SYS_ERR_ON_CE_EN;
	rc_ctl |= pcie_root_ctrl_default;

	/*
	 * if AER is present or pcie_serr_disable_flag is set,
	 * then disable SERR; otherwise allow it in the root control reg
	 */
	if (aer_ptr != PCIE_EXT_CAP_NEXT_PTR_NULL || pcie_serr_disable_flag)
		rc_ctl &= ~PCIE_ROOTCTL_SYS_ERR_ALL;

	pci_config_put16(cfg_hdl, cap_ptr + PCIE_ROOTCTL, rc_ctl);

	PCIE_ERROR_DBG("%s: PCIe Root Control Register=0x%x->0x%x\n",
	    ddi_driver_name(child), rc_ctl,
	    pci_config_get16(cfg_hdl, cap_ptr + PCIE_ROOTCTL));


	/* Root Error Command Register */
	if (aer_ptr == PCIE_EXT_CAP_NEXT_PTR_NULL)
		return;

	/* enable interrupt generation */
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
	uint16_t	command_reg, status_reg, devctl_reg;

	if (pcie_error_disable_flag)
		return;

	/* Determine the configuration header type */
	header_type = pci_config_get8(cfg_hdl, PCI_CONF_HEADER);
	status_reg = pci_config_get16(cfg_hdl, PCI_CONF_STAT);
	pci_config_put16(cfg_hdl, PCI_CONF_STAT, status_reg);

	cap_ptr = pcie_error_find_cap_reg(cfg_hdl, PCI_CAP_ID_PCI_E);
	dev_type = pci_config_get16(cfg_hdl, cap_ptr + PCIE_PCIECAP) &
	    PCIE_PCIECAP_DEV_TYPE_MASK;

	command_reg = pci_config_get16(cfg_hdl, PCI_CONF_COMM);

	/*
	 * If the device has a bus control register then clear
	 * SERR, Master Abort and Parity detect
	 */
	if ((header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_ONE) {
		status_reg = pci_config_get16(cfg_hdl, PCI_BCNF_SEC_STATUS);
		pci_config_put16(cfg_hdl, PCI_BCNF_SEC_STATUS, status_reg);

		bcr = pci_config_get8(cfg_hdl, PCI_BCNF_BCNTRL);
		if (cap_ptr != PCI_CAP_NEXT_PTR_NULL) {
			bcr &= ~(PCI_BCNF_BCNTRL_PARITY_ENABLE |
			    PCI_BCNF_BCNTRL_SERR_ENABLE);
		} else {
			if (command_reg & PCI_COMM_PARITY_DETECT)
				bcr &= ~PCI_BCNF_BCNTRL_PARITY_ENABLE;
			if (command_reg & PCI_COMM_SERR_ENABLE)
				bcr &= ~PCI_BCNF_BCNTRL_SERR_ENABLE;
		}
		pci_config_put8(cfg_hdl, PCI_BCNF_BCNTRL, bcr);
	}

	/* Clear the device's command register */
	command_reg &= ~pcie_command_default;
	pci_config_put16(cfg_hdl, PCI_CONF_COMM, command_reg);

	if (cap_ptr == PCI_CAP_NEXT_PTR_NULL)
		return;

	/* Disable PCI-Express Baseline Error Handling */
	devctl_reg = pci_config_get16(cfg_hdl, cap_ptr + PCIE_DEVCTL);
	devctl_reg &= ~pcie_device_ctrl_default;
	pci_config_put16(cfg_hdl, cap_ptr + PCIE_DEVCTL, devctl_reg);

	aer_ptr = ddi_prop_get_int(DDI_DEV_T_ANY, cdip, DDI_PROP_DONTPASS,
	    "pcie-aer-pointer", PCIE_EXT_CAP_NEXT_PTR_NULL);

	if (dev_type == PCIE_PCIECAP_DEV_TYPE_ROOT)
		pcie_rc_error_fini(cfg_hdl, cap_ptr, aer_ptr);

	if (aer_ptr == PCIE_EXT_CAP_NEXT_PTR_NULL)
		return;

	/* Disable AER bits */

	/* Disable Uncorrectable errors */
	pci_config_put32(cfg_hdl, aer_ptr + PCIE_AER_UCE_MASK,
	    PCIE_AER_UCE_BITS);

	/* Disable Correctable errors */
	pci_config_put32(cfg_hdl,
	    aer_ptr + PCIE_AER_CE_MASK, PCIE_AER_CE_BITS);

	/* Disable Secondary Uncorrectable errors if this is a bridge */
	if (!(dev_type == PCIE_PCIECAP_DEV_TYPE_PCIE2PCI))
		return;

	pci_config_put32(cfg_hdl, aer_ptr + PCIE_AER_SUCE_MASK,
	    PCIE_AER_SUCE_BITS);
}


static void
pcie_rc_error_fini(ddi_acc_handle_t cfg_hdl, uint16_t cap_ptr,
    uint16_t aer_ptr)
{
	uint16_t	rc_ctl;

	rc_ctl = pci_config_get16(cfg_hdl, cap_ptr + PCIE_ROOTCTL);
	rc_ctl &= ~pcie_root_ctrl_default;
	pci_config_put16(cfg_hdl, cap_ptr + PCIE_ROOTCTL, rc_ctl);

	/* Root Error Command Register */
	if (aer_ptr != PCIE_EXT_CAP_NEXT_PTR_NULL) {
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


/*
 * Determine interrupt type support for this bridge and configure bridge
 * to support the returned interrupt type, if any configuration is required
 */
int
pcie_bridge_intr_type(pcie_bridge_intr_state_t *istatep, int *itype_p)
{
	int itype;
	dev_info_t *dip = istatep->dip;
	ddi_acc_handle_t cfghdl = istatep->cfghdl;
	int port_type = istatep->port_type;
	uint16_t venid, devid;
	uint8_t revid;

	/*
	 * General interrupt type support
	 */
	if (ddi_intr_get_supported_types(dip, &itype) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (!(itype & (DDI_INTR_TYPE_MSI | DDI_INTR_TYPE_FIXED)))
		return (DDI_FAILURE);

	if (itype & DDI_INTR_TYPE_MSI) {
		/*
		 * Allow MSIs for root ports and non-root-ports if their
		 * corresponding flags are set
		 */
		if ((port_type == PCIE_PCIECAP_DEV_TYPE_ROOT &&
		    pcie_bridge_msi_flag >= PCIE_BRIDGE_MSI_ENABLE) ||

		    (port_type != PCIE_PCIECAP_DEV_TYPE_ROOT &&
		    pcie_bridge_msi_nonrc_flag > 0)) {

			itype = DDI_INTR_TYPE_MSI;
		} else
			itype = DDI_INTR_TYPE_FIXED;
	}

	if (itype == DDI_INTR_TYPE_FIXED)
		goto DONE;


	/*
	 * Non-root-complex bridge interrupt type support:
	 * Assume that nothing special needs to be done
	 */
	if (port_type != PCIE_PCIECAP_DEV_TYPE_ROOT)
		goto DONE;


	/*
	 * Chipset interrupt type support:
	 * MSIs need further evaluation because it turns out that even if
	 * the bridge reports MSI capability, there can be chipset specific
	 * settings that control how interrupts will be delivered for certain
	 * interrupt sources.
	 */
	itype = DDI_INTR_TYPE_FIXED;

	venid = pci_config_get16(cfghdl, PCI_CONF_VENID);
	devid = pci_config_get16(cfghdl, PCI_CONF_DEVID);
	revid = pci_config_get8(cfghdl, PCI_CONF_REVID);

	/*
	 * Intel 5000 series
	 */
	if (venid == INTEL_VENDOR_ID && INTEL_5000_PCIE_DEV_ID(devid)) {
		itype = DDI_INTR_TYPE_MSI;
		goto DONE;
	}

	/*
	 * Intel 7300
	 */
	if (venid == INTEL_VENDOR_ID && INTEL_7300_PCIE_DEV_ID(devid)) {
		uint32_t pexctrl, pexctrl3;

		pexctrl = pci_config_get32(cfghdl, INTEL_7300_PEXCTRL);
		pexctrl3 = pci_config_get32(cfghdl, INTEL_7300_PEXCTRL3);

		if (pcie_bridge_msi_flag >= PCIE_BRIDGE_MSI_ENABLE_ON) {
			pexctrl |=
			    (INTEL_7300_PEXCTRL_MSINFAT |
			    INTEL_7300_PEXCTRL_MSICOR |
			    INTEL_7300_PEXCTRL_HPINB);

			pexctrl3 |= INTEL_7300_PEXCTRL3_MSIRAS;

			pci_config_put32(cfghdl, INTEL_7300_PEXCTRL,
			    pexctrl);
			pci_config_put32(cfghdl, INTEL_7300_PEXCTRL3,
			    pexctrl3);

			/* paranoia: verify */
			pexctrl = pci_config_get32(cfghdl,
			    INTEL_7300_PEXCTRL);
			pexctrl3 = pci_config_get32(cfghdl,
			    INTEL_7300_PEXCTRL3);
		}

		if ((pexctrl &
		    (INTEL_7300_PEXCTRL_MSINFAT |
		    INTEL_7300_PEXCTRL_MSICOR)) &&
		    (pexctrl3 & INTEL_7300_PEXCTRL3_MSIRAS))
			itype = DDI_INTR_TYPE_MSI;

		goto DONE;
	}

	/*
	 * Allow MSI for Nvidia chipsets except for:
	 * CK804 or IO4 (same devids as CK804) with rev below A3
	 */
	if (venid == NVIDIA_VENDOR_ID && devid != NVIDIA_CK804_DEVICE_ID) {
		itype = DDI_INTR_TYPE_MSI;
		goto DONE;
	}

	if (venid == NVIDIA_VENDOR_ID && devid == NVIDIA_CK804_DEVICE_ID &&
	    revid >= NVIDIA_CK804_AER_VALID_REVID) {
		itype = DDI_INTR_TYPE_MSI;
		goto DONE;
	}

DONE:
	if (port_type == PCIE_PCIECAP_DEV_TYPE_ROOT &&
	    pcie_bridge_msi_flag >= PCIE_BRIDGE_MSI_ENABLE_ALL)
		itype = DDI_INTR_TYPE_MSI;

	*itype_p = itype;
	return (DDI_SUCCESS);
}


/*
 * Note: only valid on root ports
 */
void
pcie_bridge_pme_intr_disable(ddi_acc_handle_t cfghdl, int pcie_loc)
{
	uint16_t rootctl;

	rootctl = pci_config_get16(cfghdl, pcie_loc + PCIE_ROOTCTL);
	rootctl &= ~PCIE_ROOTCTL_PME_INTERRUPT_EN;
	pci_config_put16(cfghdl, pcie_loc + PCIE_ROOTCTL, rootctl);
}

void
pcie_bridge_pme_intr_enable(ddi_acc_handle_t cfghdl, int pcie_loc)
{
	uint16_t rootctl;

	rootctl = pci_config_get16(cfghdl, pcie_loc + PCIE_ROOTCTL);
	rootctl |= PCIE_ROOTCTL_PME_INTERRUPT_EN;
	pci_config_put16(cfghdl, pcie_loc + PCIE_ROOTCTL, rootctl);
}


void
pcie_bridge_pme_disable(pcie_bridge_intr_state_t *istatep)
{
	ddi_acc_handle_t cfghdl = istatep->cfghdl;
	int pcie_loc = istatep->pcie_loc;
	uint32_t val;

	if (istatep->port_type != PCIE_PCIECAP_DEV_TYPE_ROOT)
		return;

	if (pcie_loc == 0)
		return;

	pcie_bridge_pme_intr_disable(cfghdl, pcie_loc);

	val = pci_config_get32(cfghdl, pcie_loc + PCIE_ROOTSTS);
	pci_config_put32(cfghdl, pcie_loc + PCIE_ROOTSTS, val);
}


/*
 * re-initialize bridge after a resume
 */
int
pcie_bridge_intr_reinit(pcie_bridge_intr_state_t *istatep)
{
	dev_info_t *dip = istatep->dip;
	int itype, rv;
	int ret = DDI_SUCCESS;

	int inst = ddi_get_instance(dip);
	const char *drvnm = ddi_driver_name(dip);

	rv = pcie_bridge_intr_type(istatep, &itype);
	if (rv != DDI_SUCCESS && rv != DDI_ENOTSUP) {
		PCIE_ERROR_DBG("%s%d: intr type reinitialization failed\n",
		    drvnm, inst);
		ret = DDI_FAILURE;
		goto OUT;
	}

OUT:
	return (ret);
}


/*
 * Initialize interrupts; returns:
 * - DDI_SUCCESS on success
 * - DDI_ENOTSUP if interrupts are not supported for this bridge
 * - DDI_FAILURE if interrupts are supported but failed initialization
 */
int
pcie_bridge_intr_init(pcie_bridge_intr_state_t *istatep,
    ddi_intr_handler_t intr_handler)
{
	dev_info_t *dip = istatep->dip;
	ddi_acc_handle_t cfghdl = istatep->cfghdl;
	int aer_loc;
	int pcie_loc;
	int inband_hpc;
	int port_type;

	int i, rv, itype, iwant, igot, icap;
	int *isrc_tab;
	uint32_t inum;
	int retry = 0;

	int inst = ddi_get_instance(dip);
	const char *drvnm = ddi_driver_name(dip);

	ASSERT(istatep->dip != NULL);
	ASSERT(istatep->cfghdl != NULL);

	if (pcie_bridge_msi_flag == PCIE_BRIDGE_INTR_DISABLE) {
		uint16_t val;

		PCIE_ERROR_DBG("%s%d: disabling interrupts\n", drvnm, inst);
		val = pci_config_get16(cfghdl, PCI_CONF_COMM);
		val |= PCI_COMM_INTX_DISABLE;
		pci_config_put16(cfghdl, PCI_CONF_COMM, val);
	}

	/*
	 * Get cap locations and other relevant PCIE info
	 */
	pcie_loc = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "pcie-capid-pointer", 0);
	aer_loc = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "pcie-aer-pointer", 0);
	inband_hpc = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "pci-hotplug-type", INBAND_HPC_NONE);
	port_type = pci_config_get16(cfghdl, pcie_loc + PCIE_PCIECAP) &
	    PCIE_PCIECAP_DEV_TYPE_MASK;

	if (pcie_loc < PCI_CAP_PTR_OFF || pcie_loc >= PCIE_EXT_CAP) {
		PCIE_ERROR_DBG("%s%d: invalid PCIE cap offset\n", drvnm, inst);
		return (DDI_FAILURE);
	}
	if (aer_loc < PCIE_EXT_CAP || aer_loc >= 0xffff) {
		PCIE_ERROR_DBG("%s%d: invalid AER cap offset\n", drvnm, inst);
		return (DDI_FAILURE);
	}

	istatep->aer_loc = aer_loc;
	istatep->pcie_loc = pcie_loc;
	istatep->inband_hpc = inband_hpc;
	istatep->port_type = port_type;


	/*
	 * We only support fixed and MSI interrupts on bridges that are
	 * hotpluggable or root ports with AER
	 */
	if ((port_type != PCIE_PCIECAP_DEV_TYPE_ROOT &&
	    inband_hpc != INBAND_HPC_PCIE) ||
	    (port_type == PCIE_PCIECAP_DEV_TYPE_ROOT && aer_loc == 0))
		return (DDI_ENOTSUP);

	PCIE_ERROR_DBG("%s%d: adding interrupts\n", drvnm, inst);

	if (pcie_bridge_intr_type(istatep, &itype) != DDI_SUCCESS) {
		PCIE_ERROR_DBG("%s%d: pcie_intr_type() failed\n", drvnm, inst);
		return (DDI_FAILURE);
	}

RETRY:
	if (itype == DDI_INTR_TYPE_FIXED) {
		uint8_t ipin;

		ipin = pci_config_get8(cfghdl, PCI_BCNF_IPIN);
		if (ipin == 0 || ipin == 0xff) {
			PCIE_ERROR_DBG("%s%d: invalid IPIN for fixed intr\n",
			    drvnm, inst);
			return (DDI_FAILURE);
		}
	}
	istatep->itype = itype;

	PCIE_ERROR_DBG("%s%d: supported intr type 0x%x\n", drvnm, inst, itype);


	/*
	 * Get the max number of intrs requested and allocate handler
	 * table for that amount
	 */
	rv = ddi_intr_get_nintrs(dip, itype, &iwant);
	if (rv != DDI_SUCCESS || iwant == 0) {
		PCIE_ERROR_DBG("%s%d: ddi_intr_get_nintrs() "
		    "failed or returned 0 interrupts\n", drvnm, inst);
		return (DDI_FAILURE);
	}
	istatep->iwant = iwant;

	ASSERT(itype != DDI_INTR_TYPE_FIXED ||
	    (itype == DDI_INTR_TYPE_FIXED && iwant == 1));

	istatep->ihdl_tab =
	    kmem_zalloc(iwant * sizeof (ddi_intr_handle_t), KM_SLEEP);
	istatep->iflags |= PCIE_BRIDGE_INTR_INIT_HTABLE;


	/*
	 * If the bridge wants more than one (MSI), but we cannot allocate
	 * exactly that much, we fall back to using only one.  If we cannot
	 * get any MSI then we fall back to using fixed intrs.  However,
	 * for Nvidia bridges, if we cannot get the exact requested amount
	 * of MSIs, we must use fixed intrs due to some chipset limitations
	 * (MCP55 errata and potentially other NV chipsets).
	 */
	rv = ddi_intr_alloc(dip, istatep->ihdl_tab, itype, 0, iwant,
	    &igot, DDI_INTR_ALLOC_STRICT);

	if (!retry && rv != DDI_SUCCESS && iwant > 1) {
		if (pci_config_get16(cfghdl, PCI_CONF_VENID) ==
		    NVIDIA_VENDOR_ID) {
			pcie_bridge_intr_fini(istatep);
			itype = DDI_INTR_TYPE_FIXED;

			PCIE_ERROR_DBG("%s%d: retrying allocation for NVIDIA "
			    "bridge with FIXED intr type\n", drvnm, inst);
			retry = 1;
			goto RETRY;
		} else {
			PCIE_ERROR_DBG("%s%d: retrying allocation with "
			    "one MSI\n", drvnm, inst);
			rv = ddi_intr_alloc(dip, istatep->ihdl_tab, itype,
			    0, 1, &igot, DDI_INTR_ALLOC_STRICT);
		}
	}

	if (!retry && rv != DDI_SUCCESS && itype != DDI_INTR_TYPE_FIXED) {
		pcie_bridge_intr_fini(istatep);
		itype = DDI_INTR_TYPE_FIXED;

		PCIE_ERROR_DBG("%s%d: retrying allocation with "
		    "FIXED intr type\n", drvnm, inst);
		retry = 1;
		goto RETRY;
	}

	if (rv != DDI_SUCCESS) {
		PCIE_ERROR_DBG("%s%d: could not allocate interrupts\n",
		    drvnm, inst);
		goto FAIL;
	}
	istatep->igot = igot;
	istatep->iflags |= PCIE_BRIDGE_INTR_INIT_ALLOC;

	ASSERT(igot == 1 || igot == iwant);
	PCIE_ERROR_DBG("%s%d: bridge supports %d intrs; allocated %d "
	    "of type 0x%x\n", drvnm, inst, iwant, igot, itype);


	/*
	 * Map interrupt sources to multiple MSIs or a single MSI/fixed intr
	 * There are 3 possible interrupt sources we recognize:
	 * - hotplug (PCIE cap)
	 * - power (PCIE cap; root port)
	 * - error (AER cap; root port)
	 * Note that error interrupts only apply to root ports with AER.
	 * Non-root port devices with or without AER will report errors by
	 * sending error messages to the root port which will interrupt on
	 * their behalf.  We report this to FMA who determines which
	 * device originated the error by checking the error logs in the
	 * root port AER cap.  FMA can then check the originating device's
	 * error status registers and invoke its driver's error handler if
	 * registered.
	 */
	isrc_tab = kmem_zalloc(igot * sizeof (int), KM_SLEEP);
	istatep->isrc_tab = isrc_tab;
	istatep->iflags |= PCIE_BRIDGE_INTR_INIT_ISRCTAB;

	/*
	 * hotplug and PME interrupts
	 * both share the same vector
	 */
	if (pcie_loc != 0) {
		inum = 0;

		if (itype == DDI_INTR_TYPE_MSI) {
			inum = pci_config_get16(cfghdl,
			    pcie_loc + PCIE_PCIECAP);
			if (inum == 0xffff) {
				PCIE_ERROR_DBG("%s%d: invalid PCIE cap "
				    "register\n", drvnm, inst);
				goto FAIL;
			}

			inum = (inum >> PCIE_PCIECAP_INT_MSG_NUM_SHIFT) &
			    PCIE_PCIECAP_INT_MSG_NUM_MASK;
			if (inum >= igot) {
				PCIE_ERROR_DBG("%s%d: MSI number %d in "
				    "PCIE cap > max allocated\n",
				    drvnm, inst, inum);
				goto FAIL;
			}
		}

		if (inband_hpc == INBAND_HPC_PCIE) {
			isrc_tab[inum] |= PCIE_BRIDGE_INTR_SRC_HP;

			PCIE_ERROR_DBG("%s%d: HP intr on inum %d\n",
			    drvnm, inst, inum);
		}

		/*
		 * PME interrupts should always remained disabled and
		 * only enabled after we add our interrupt handler, if we
		 * decide to support it.  PMEs pending while it is disabled
		 * will trigger an interrupt when enabled.
		 *
		 * Note that PMEs could be delivered either through ACPI or
		 * directly via the bridge interrupt on some platforms, so
		 * a method of determining which mode to use is required
		 * before supporting PCIE PME in general, much like
		 * determining PCIE hotplug mode (native vs acpi).
		 */
		if (port_type == PCIE_PCIECAP_DEV_TYPE_ROOT) {
			pcie_bridge_pme_intr_disable(cfghdl, pcie_loc);

			if (pcie_bridge_enable_pme) {
				isrc_tab[inum] |= PCIE_BRIDGE_INTR_SRC_PME;

				PCIE_ERROR_DBG("%s%d: PME intr on inum %d\n",
				    drvnm, inst, inum);
			}
		}
	}

	/*
	 * error reporting interrupts
	 */
	if (aer_loc != 0 &&
	    port_type == PCIE_PCIECAP_DEV_TYPE_ROOT) {
		inum = 0;

		if (itype == DDI_INTR_TYPE_MSI) {
			inum = pci_config_get32(cfghdl,
			    aer_loc + PCIE_AER_RE_STS);
			if (inum == 0xffffffff) {
				PCIE_ERROR_DBG("%s%d: invalid "
				    "root error status register in AER cap\n",
				    drvnm, inst);
				goto FAIL;
			}

			inum = (inum >> PCIE_AER_RE_STS_MSG_NUM_SHIFT) &
			    PCIE_AER_RE_STS_MSG_NUM_MASK;
			if (inum >= igot) {
				PCIE_ERROR_DBG("%s%d: MSI number %d in "
				    "AER cap > max allocated\n",
				    drvnm, inst, inum);
				goto FAIL;
			}
		}

		isrc_tab[inum] |= PCIE_BRIDGE_INTR_SRC_AER;

		PCIE_ERROR_DBG("%s%d: AER intr on inum %d\n",
		    drvnm, inst, inum);
	}


	/*
	 * Add handler using second arg to identify which interrupt
	 */
	for (i = 0; i < igot; i++) {
		rv = ddi_intr_add_handler(istatep->ihdl_tab[i], intr_handler,
		    (caddr_t)istatep, (caddr_t)(uintptr_t)i);

		if (rv != DDI_SUCCESS) {
			PCIE_ERROR_DBG("%s%d: ddi_intr_add_handler() "
			    "failed on inum %d\n", drvnm, inst, i);
			break;
		}
		PCIE_ERROR_DBG("%s%d: isrc_tab[%d] = 0x%x\n",
		    drvnm, inst, i, isrc_tab[i]);
	}
	if (rv != DDI_SUCCESS) {
		while (--i >= 0)
			(void) ddi_intr_remove_handler(istatep->ihdl_tab[i]);
		goto FAIL;
	}
	istatep->iflags |= PCIE_BRIDGE_INTR_INIT_HANDLER;


	/*
	 * Get interrupt priority and initialize mutex
	 */
	if (ddi_intr_get_pri(istatep->ihdl_tab[0], &istatep->ipri) !=
	    DDI_SUCCESS) {
		PCIE_ERROR_DBG("%s%d: ddi_intr_get_pri() failed\n",
		    drvnm, inst);
		goto FAIL;
	}
	mutex_init(&istatep->ilock, NULL, MUTEX_DRIVER,
	    DDI_INTR_PRI(istatep->ipri));
	istatep->iflags |= PCIE_BRIDGE_INTR_INIT_MUTEX;


	/*
	 * Enable interrupts
	 */
	if (ddi_intr_get_cap(istatep->ihdl_tab[0], &icap) != DDI_SUCCESS) {
		PCIE_ERROR_DBG("%s%d: ddi_intr_get_cap() failed\n",
		    drvnm, inst);
		goto FAIL;
	}
	if (icap & DDI_INTR_FLAG_BLOCK) {
		if (ddi_intr_block_enable(istatep->ihdl_tab, igot) !=
		    DDI_SUCCESS) {
			PCIE_ERROR_DBG("%s%d: ddi_intr_block_enable() failed\n",
			    drvnm, inst);
			goto FAIL;
		}
		istatep->iflags |= PCIE_BRIDGE_INTR_INIT_BLOCK;

	} else {
		for (i = 0; i < igot; i++) {
			if (ddi_intr_enable(istatep->ihdl_tab[i]) !=
			    DDI_SUCCESS) {
				PCIE_ERROR_DBG("%s%d: ddi_intr_enable() "
				    "failed on inum %d\n", drvnm, inst, i);
				goto FAIL;
			}
		}
	}
	istatep->iflags |= PCIE_BRIDGE_INTR_INIT_ENABLE;


	/*
	 * Post interrupt enabled work; enable interrupt sources
	 * - PME; see NOTE above regarding PMEs
	 */
	if (pcie_bridge_enable_pme && pcie_loc != 0 &&
	    port_type == PCIE_PCIECAP_DEV_TYPE_ROOT) {
		PCIE_ERROR_DBG("%s%d: enabling PME interrupt\n", drvnm, inst);
		pcie_bridge_pme_intr_enable(cfghdl, pcie_loc);
	}

	return (DDI_SUCCESS);
	/*NOTREACHED*/

FAIL:
	pcie_bridge_intr_fini(istatep);
	return (DDI_FAILURE);
}


void
pcie_bridge_intr_fini(pcie_bridge_intr_state_t *istatep)
{
	int x;
	int count = istatep->iwant;
	int flags = istatep->iflags;

	if (istatep->dip == NULL || istatep->cfghdl == NULL)
		return;

	pcie_bridge_pme_disable(istatep);

	if ((flags & PCIE_BRIDGE_INTR_INIT_ENABLE) &&
	    (flags & PCIE_BRIDGE_INTR_INIT_BLOCK)) {
		(void) ddi_intr_block_disable(istatep->ihdl_tab, count);
		flags &= ~(PCIE_BRIDGE_INTR_INIT_ENABLE |
		    PCIE_BRIDGE_INTR_INIT_BLOCK);
	}

	if (flags & PCIE_BRIDGE_INTR_INIT_MUTEX)
		mutex_destroy(&istatep->ilock);

	for (x = 0; x < count; x++) {
		if (flags & PCIE_BRIDGE_INTR_INIT_ENABLE)
			(void) ddi_intr_disable(istatep->ihdl_tab[x]);

		if (flags & PCIE_BRIDGE_INTR_INIT_HANDLER)
			(void) ddi_intr_remove_handler(istatep->ihdl_tab[x]);

		if (flags & PCIE_BRIDGE_INTR_INIT_ALLOC)
			(void) ddi_intr_free(istatep->ihdl_tab[x]);
	}

	flags &= ~(PCIE_BRIDGE_INTR_INIT_ENABLE |
	    PCIE_BRIDGE_INTR_INIT_HANDLER |
	    PCIE_BRIDGE_INTR_INIT_ALLOC | PCIE_BRIDGE_INTR_INIT_MUTEX);

	if (flags & PCIE_BRIDGE_INTR_INIT_HTABLE)
		kmem_free(istatep->ihdl_tab,
		    istatep->iwant * sizeof (ddi_intr_handle_t));

	flags &= ~PCIE_BRIDGE_INTR_INIT_HTABLE;

	if (flags & PCIE_BRIDGE_INTR_INIT_ISRCTAB)
		kmem_free(istatep->isrc_tab, istatep->igot * sizeof (int));

	flags &= ~PCIE_BRIDGE_INTR_INIT_ISRCTAB;

	istatep->iflags &= flags;
}


int
pcie_bridge_is_link_disabled(dev_info_t *dip, ddi_acc_handle_t cfghdl)
{
	int pcie_loc;

	pcie_loc = ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "pcie-capid-pointer", 0);

	if (pcie_loc >= PCI_CAP_PTR_OFF && pcie_loc < 0xff) {
		if (pci_config_get16(cfghdl, pcie_loc + PCIE_LINKCTL) &
		    PCIE_LINKCTL_LINK_DISABLE)
			return (1);
	}
	return (0);
}


#ifdef	DEBUG
static void
pcie_error_dbg(char *fmt, ...)
{
	va_list ap;

	if (!pcie_error_debug_flags)
		return;

	va_start(ap, fmt);
	vprintf(fmt, ap);
	va_end(ap);
}
#endif	/* DEBUG */
