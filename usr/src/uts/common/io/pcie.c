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

#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/promif.h>
#include <sys/disp.h>
#include <sys/pcie.h>
#include <sys/pci_cap.h>
#include <sys/pcie_impl.h>

static void pcie_init_pfd(dev_info_t *);
static void pcie_fini_pfd(dev_info_t *);

#ifdef	DEBUG
uint_t pcie_debug_flags = 0;

static void pcie_print_bus(pcie_bus_t *bus_p);

#define	PCIE_DBG pcie_dbg
/* Common Debugging shortcuts */
#define	PCIE_DBG_CFG(dip, bus_p, name, sz, off, org) \
	PCIE_DBG("%s:%d:(0x%x) %s(0x%x) 0x%x -> 0x%x\n", ddi_node_name(dip), \
	    ddi_get_instance(dip), bus_p->bus_bdf, name, off, org, \
	    PCIE_GET(sz, bus_p, off))
#define	PCIE_DBG_CAP(dip, bus_p, name, sz, off, org) \
	PCIE_DBG("%s:%d:(0x%x) %s(0x%x) 0x%x -> 0x%x\n", ddi_node_name(dip), \
	    ddi_get_instance(dip), bus_p->bus_bdf, name, off, org, \
	    PCIE_CAP_GET(sz, bus_p, off))
#define	PCIE_DBG_AER(dip, bus_p, name, sz, off, org) \
	PCIE_DBG("%s:%d:(0x%x) %s(0x%x) 0x%x -> 0x%x\n", ddi_node_name(dip), \
	    ddi_get_instance(dip), bus_p->bus_bdf, name, off, org, \
	    PCIE_AER_GET(sz, bus_p, off))

static void pcie_dbg(char *fmt, ...);

#else	/* DEBUG */

#define	PCIE_DBG_CFG 0 &&
#define	PCIE_DBG 0 &&
#define	PCIE_DBG_CAP 0 &&
#define	PCIE_DBG_AER 0 &&

#endif	/* DEBUG */

int pcie_intel_error_disable = 1;

/* Variable to control default PCI-Express config settings */
ushort_t pcie_command_default =
    PCI_COMM_SERR_ENABLE |
    PCI_COMM_WAIT_CYC_ENAB |
    PCI_COMM_PARITY_DETECT |
    PCI_COMM_ME |
    PCI_COMM_MAE |
    PCI_COMM_IO;

/* xxx_fw are bits that are controlled by FW and should not be modified */
ushort_t pcie_command_default_fw =
    PCI_COMM_SPEC_CYC |
    PCI_COMM_MEMWR_INVAL |
    PCI_COMM_PALETTE_SNOOP |
    PCI_COMM_WAIT_CYC_ENAB |
    0xF800; /* Reserved Bits */

ushort_t pcie_bdg_command_default_fw =
    PCI_BCNF_BCNTRL_ISA_ENABLE |
    PCI_BCNF_BCNTRL_VGA_ENABLE |
    0xF000; /* Reserved Bits */

/* PCI-Express Base error defaults */
ushort_t pcie_base_err_default =
    PCIE_DEVCTL_CE_REPORTING_EN |
    PCIE_DEVCTL_NFE_REPORTING_EN |
    PCIE_DEVCTL_FE_REPORTING_EN |
    PCIE_DEVCTL_UR_REPORTING_EN;

/* PCI-Express Device Control Register */
uint16_t pcie_devctl_default =
    PCIE_DEVCTL_RO_EN |
    PCIE_DEVCTL_MAX_PAYLOAD_128 |
    PCIE_DEVCTL_MAX_READ_REQ_512;

/* PCI-Express AER Root Control Register */
#define	PCIE_ROOT_SYS_ERR	(PCIE_ROOTCTL_SYS_ERR_ON_CE_EN | \
				PCIE_ROOTCTL_SYS_ERR_ON_NFE_EN | \
				PCIE_ROOTCTL_SYS_ERR_ON_FE_EN)

#if defined(__xpv)
ushort_t pcie_root_ctrl_default =
    PCIE_ROOTCTL_SYS_ERR_ON_NFE_EN |
    PCIE_ROOTCTL_SYS_ERR_ON_FE_EN;
#else
ushort_t pcie_root_ctrl_default =
    PCIE_ROOTCTL_SYS_ERR_ON_CE_EN |
    PCIE_ROOTCTL_SYS_ERR_ON_NFE_EN |
    PCIE_ROOTCTL_SYS_ERR_ON_FE_EN;
#endif /* __xpv */

/* PCI-Express Root Error Command Register */
ushort_t pcie_root_error_cmd_default =
    PCIE_AER_RE_CMD_CE_REP_EN |
    PCIE_AER_RE_CMD_NFE_REP_EN |
    PCIE_AER_RE_CMD_FE_REP_EN;

/* ECRC settings in the PCIe AER Control Register */
uint32_t pcie_ecrc_value =
    PCIE_AER_CTL_ECRC_GEN_ENA |
    PCIE_AER_CTL_ECRC_CHECK_ENA;

/*
 * If a particular platform wants to disable certain errors such as UR/MA,
 * instead of using #defines have the platform's PCIe Root Complex driver set
 * these masks using the pcie_get_XXX_mask and pcie_set_XXX_mask functions.  For
 * x86 the closest thing to a PCIe root complex driver is NPE.  For SPARC the
 * closest PCIe root complex driver is PX.
 *
 * pcie_serr_disable_flag : disable SERR only (in RCR and command reg) x86
 * systems may want to disable SERR in general.  For root ports, enabling SERR
 * causes NMIs which are not handled and results in a watchdog timeout error.
 */
uint32_t pcie_aer_uce_mask = 0;		/* AER UE Mask */
uint32_t pcie_aer_ce_mask = 0;		/* AER CE Mask */
uint32_t pcie_aer_suce_mask = 0;	/* AER Secondary UE Mask */
uint32_t pcie_serr_disable_flag = 0;	/* Disable SERR */

/* Default severities needed for eversholt.  Error handling doesn't care */
uint32_t pcie_aer_uce_severity = PCIE_AER_UCE_MTLP | PCIE_AER_UCE_RO | \
    PCIE_AER_UCE_FCP | PCIE_AER_UCE_SD | PCIE_AER_UCE_DLP | \
    PCIE_AER_UCE_TRAINING;
uint32_t pcie_aer_suce_severity = PCIE_AER_SUCE_SERR_ASSERT | \
    PCIE_AER_SUCE_UC_ADDR_ERR | PCIE_AER_SUCE_UC_ATTR_ERR | \
    PCIE_AER_SUCE_USC_MSG_DATA_ERR;

/*
 * modload support
 */
extern struct mod_ops mod_miscops;
struct modlmisc modlmisc	= {
	&mod_miscops,	/* Type	of module */
	"PCIE: PCI Express Architecture %I%"
};

struct modlinkage modlinkage = {
	MODREV_1,
	(void	*)&modlmisc,
	NULL
};

/*
 * Global Variables needed for a non-atomic version of ddi_fm_ereport_post.
 * Currently used to send the pci.fabric ereports whose payload depends on the
 * type of PCI device it is being sent for.
 */
char		*pcie_nv_buf;
nv_alloc_t	*pcie_nvap;
nvlist_t	*pcie_nvl;

int
_init(void)
{
	int rval;

	pcie_nv_buf = kmem_alloc(ERPT_DATA_SZ, KM_SLEEP);
	pcie_nvap = fm_nva_xcreate(pcie_nv_buf, ERPT_DATA_SZ);
	pcie_nvl = fm_nvlist_create(pcie_nvap);

	rval = mod_install(&modlinkage);
	return (rval);
}

int
_fini()
{
	int		rval;

	fm_nvlist_destroy(pcie_nvl, FM_NVA_RETAIN);
	fm_nva_xdestroy(pcie_nvap);
	kmem_free(pcie_nv_buf, ERPT_DATA_SZ);

	rval = mod_remove(&modlinkage);
	return (rval);
}

int
_info(struct modinfo *modinfop)
{
	return (mod_info(&modlinkage, modinfop));
}

/*
 * PCI-Express child device initialization.
 * This function enables generic pci-express interrupts and error
 * handling.
 *
 * @param pdip		root dip (root nexus's dip)
 * @param cdip		child's dip (device's dip)
 * @return		DDI_SUCCESS or DDI_FAILURE
 */
/* ARGSUSED */
int
pcie_initchild(dev_info_t *cdip)
{
	uint16_t		tmp16, reg16;
	pcie_bus_t		*bus_p;

	bus_p = PCIE_DIP2BUS(cdip);
	if (bus_p == NULL) {
		PCIE_DBG("%s: BUS not found.\n",
		    ddi_driver_name(cdip));

		return (DDI_FAILURE);
	}

	/* Clear the device's status register */
	reg16 = PCIE_GET(16, bus_p, PCI_CONF_STAT);
	PCIE_PUT(16, bus_p, PCI_CONF_STAT, reg16);

	/* Setup the device's command register */
	reg16 = PCIE_GET(16, bus_p, PCI_CONF_COMM);
	tmp16 = (reg16 & pcie_command_default_fw) | pcie_command_default;
	if (pcie_serr_disable_flag && PCIE_IS_PCIE(bus_p))
		tmp16 &= ~PCI_COMM_SERR_ENABLE;

	PCIE_PUT(16, bus_p, PCI_CONF_COMM, tmp16);
	PCIE_DBG_CFG(cdip, bus_p, "COMMAND", 16, PCI_CONF_COMM, reg16);

	/*
	 * If the device has a bus control register then program it
	 * based on the settings in the command register.
	 */
	if (PCIE_IS_BDG(bus_p)) {
		/* Clear the device's secondary status register */
		reg16 = PCIE_GET(16, bus_p, PCI_BCNF_SEC_STATUS);
		PCIE_PUT(16, bus_p, PCI_BCNF_SEC_STATUS, reg16);

		/* Setup the device's secondary command register */
		reg16 = PCIE_GET(16, bus_p, PCI_BCNF_BCNTRL);
		tmp16 = (reg16 & pcie_bdg_command_default_fw);
		tmp16 |= PCI_BCNF_BCNTRL_SERR_ENABLE;
		if (pcie_command_default & PCI_COMM_PARITY_DETECT)
			tmp16 |= PCI_BCNF_BCNTRL_PARITY_ENABLE;

		/*
		 * Enable Master Abort Mode only if URs have not been masked.
		 * For PCI and PCIe-PCI bridges, enabling this bit causes a
		 * Master Aborts/UR to be forwarded as a UR/TA or SERR.  If this
		 * bit is masked, posted requests are dropped and non-posted
		 * requests are returned with -1.
		 */
		if (pcie_aer_uce_mask & PCIE_AER_UCE_UR)
			tmp16 &= ~PCI_BCNF_BCNTRL_MAST_AB_MODE;
		else
			tmp16 |= PCI_BCNF_BCNTRL_MAST_AB_MODE;
		PCIE_PUT(16, bus_p, PCI_BCNF_BCNTRL, tmp16);
		PCIE_DBG_CFG(cdip, bus_p, "SEC CMD", 16, PCI_BCNF_BCNTRL,
		    reg16);
	}

	if (PCIE_IS_PCIE(bus_p)) {
		/* Setup PCIe device control register */
		reg16 = PCIE_CAP_GET(16, bus_p, PCIE_DEVCTL);
		tmp16 = pcie_devctl_default;
		PCIE_CAP_PUT(16, bus_p, PCIE_DEVCTL, tmp16);
		PCIE_DBG_CAP(cdip, bus_p, "DEVCTL", 16, PCIE_DEVCTL, reg16);

		/* Enable PCIe errors */
		pcie_enable_errors(cdip);
	}

	return (DDI_SUCCESS);
}

#define	PCIE_ZALLOC(data) kmem_zalloc(sizeof (data), KM_SLEEP)
static void
pcie_init_pfd(dev_info_t *dip)
{
	pf_data_t	*pfd_p = PCIE_ZALLOC(pf_data_t);
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);

	PCIE_DIP2PFD(dip) = pfd_p;

	pfd_p->pe_bus_p = bus_p;
	pfd_p->pe_severity_flags = 0;
	pfd_p->pe_lock = B_FALSE;
	pfd_p->pe_valid = B_FALSE;

	/* Allocate the root fault struct for both RC and RP */
	if (PCIE_IS_ROOT(bus_p))
		PCIE_ROOT_FAULT(pfd_p) = PCIE_ZALLOC(pf_root_fault_t);

	PCI_ERR_REG(pfd_p) = PCIE_ZALLOC(pf_pci_err_regs_t);

	if (PCIE_IS_BDG(bus_p))
		PCI_BDG_ERR_REG(pfd_p) = PCIE_ZALLOC(pf_pci_bdg_err_regs_t);

	if (PCIE_IS_PCIE(bus_p)) {
		PCIE_ERR_REG(pfd_p) = PCIE_ZALLOC(pf_pcie_err_regs_t);

		if (PCIE_IS_RP(bus_p))
			PCIE_RP_REG(pfd_p) =
			    PCIE_ZALLOC(pf_pcie_rp_err_regs_t);

		PCIE_ADV_REG(pfd_p) = PCIE_ZALLOC(pf_pcie_adv_err_regs_t);

		if (PCIE_IS_RP(bus_p))
			PCIE_ADV_RP_REG(pfd_p) =
			    PCIE_ZALLOC(pf_pcie_adv_rp_err_regs_t);
		else if (PCIE_IS_PCIE_BDG(bus_p))
			PCIE_ADV_BDG_REG(pfd_p) =
			    PCIE_ZALLOC(pf_pcie_adv_bdg_err_regs_t);

		if (PCIE_IS_PCIE_BDG(bus_p) && PCIE_IS_PCIX(bus_p)) {
			PCIX_BDG_ERR_REG(pfd_p) =
			    PCIE_ZALLOC(pf_pcix_bdg_err_regs_t);

			if (PCIX_ECC_VERSION_CHECK(bus_p)) {
				PCIX_BDG_ECC_REG(pfd_p, 0) =
				    PCIE_ZALLOC(pf_pcix_ecc_regs_t);
				PCIX_BDG_ECC_REG(pfd_p, 1) =
				    PCIE_ZALLOC(pf_pcix_ecc_regs_t);
			}
		}
	} else if (PCIE_IS_PCIX(bus_p)) {
		if (PCIE_IS_BDG(bus_p)) {
			PCIX_BDG_ERR_REG(pfd_p) =
			    PCIE_ZALLOC(pf_pcix_bdg_err_regs_t);

			if (PCIX_ECC_VERSION_CHECK(bus_p)) {
				PCIX_BDG_ECC_REG(pfd_p, 0) =
				    PCIE_ZALLOC(pf_pcix_ecc_regs_t);
				PCIX_BDG_ECC_REG(pfd_p, 1) =
				    PCIE_ZALLOC(pf_pcix_ecc_regs_t);
			}
		} else {
			PCIX_ERR_REG(pfd_p) = PCIE_ZALLOC(pf_pcix_err_regs_t);

			if (PCIX_ECC_VERSION_CHECK(bus_p))
				PCIX_ECC_REG(pfd_p) =
				    PCIE_ZALLOC(pf_pcix_ecc_regs_t);
		}
	}
}

static void
pcie_fini_pfd(dev_info_t *dip)
{
	pf_data_t	*pfd_p = PCIE_DIP2PFD(dip);
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);

	if (PCIE_IS_PCIE(bus_p)) {
		if (PCIE_IS_PCIE_BDG(bus_p) && PCIE_IS_PCIX(bus_p)) {
			if (PCIX_ECC_VERSION_CHECK(bus_p)) {
				kmem_free(PCIX_BDG_ECC_REG(pfd_p, 0),
				    sizeof (pf_pcix_ecc_regs_t));
				kmem_free(PCIX_BDG_ECC_REG(pfd_p, 1),
				    sizeof (pf_pcix_ecc_regs_t));
			}

			kmem_free(PCIX_BDG_ERR_REG(pfd_p),
			    sizeof (pf_pcix_bdg_err_regs_t));
		}

		if (PCIE_IS_RP(bus_p))
			kmem_free(PCIE_ADV_RP_REG(pfd_p),
			    sizeof (pf_pcie_adv_rp_err_regs_t));
		else if (PCIE_IS_PCIE_BDG(bus_p))
			kmem_free(PCIE_ADV_BDG_REG(pfd_p),
			    sizeof (pf_pcie_adv_bdg_err_regs_t));

		kmem_free(PCIE_ADV_REG(pfd_p),
		    sizeof (pf_pcie_adv_err_regs_t));

		if (PCIE_IS_RP(bus_p))
			kmem_free(PCIE_RP_REG(pfd_p),
			    sizeof (pf_pcie_rp_err_regs_t));

		kmem_free(PCIE_ERR_REG(pfd_p), sizeof (pf_pcie_err_regs_t));
	} else if (PCIE_IS_PCIX(bus_p)) {
		if (PCIE_IS_BDG(bus_p)) {
			if (PCIX_ECC_VERSION_CHECK(bus_p)) {
				kmem_free(PCIX_BDG_ECC_REG(pfd_p, 0),
				    sizeof (pf_pcix_ecc_regs_t));
				kmem_free(PCIX_BDG_ECC_REG(pfd_p, 1),
				    sizeof (pf_pcix_ecc_regs_t));
			}

			kmem_free(PCIX_BDG_ERR_REG(pfd_p),
			    sizeof (pf_pcix_bdg_err_regs_t));
		} else {
			if (PCIX_ECC_VERSION_CHECK(bus_p))
				kmem_free(PCIX_ECC_REG(pfd_p),
				    sizeof (pf_pcix_ecc_regs_t));

			kmem_free(PCIX_ERR_REG(pfd_p),
			    sizeof (pf_pcix_err_regs_t));
		}
	}

	if (PCIE_IS_BDG(bus_p))
		kmem_free(PCI_BDG_ERR_REG(pfd_p),
		    sizeof (pf_pci_bdg_err_regs_t));

	kmem_free(PCI_ERR_REG(pfd_p), sizeof (pf_pci_err_regs_t));

	if (PCIE_IS_ROOT(bus_p))
		kmem_free(PCIE_ROOT_FAULT(pfd_p), sizeof (pf_root_fault_t));

	kmem_free(PCIE_DIP2PFD(dip), sizeof (pf_data_t));

	PCIE_DIP2PFD(dip) = NULL;
}


/*
 * Special functions to allocate pf_data_t's for PCIe root complexes.
 * Note: Root Complex not Root Port
 */
void
pcie_rc_init_pfd(dev_info_t *dip, pf_data_t *pfd_p)
{
	pfd_p->pe_bus_p = PCIE_DIP2DOWNBUS(dip);
	pfd_p->pe_severity_flags = 0;
	pfd_p->pe_lock = B_FALSE;
	pfd_p->pe_valid = B_FALSE;

	PCIE_ROOT_FAULT(pfd_p) = PCIE_ZALLOC(pf_root_fault_t);
	PCI_ERR_REG(pfd_p) = PCIE_ZALLOC(pf_pci_err_regs_t);
	PCI_BDG_ERR_REG(pfd_p) = PCIE_ZALLOC(pf_pci_bdg_err_regs_t);
	PCIE_ERR_REG(pfd_p) = PCIE_ZALLOC(pf_pcie_err_regs_t);
	PCIE_RP_REG(pfd_p) = PCIE_ZALLOC(pf_pcie_rp_err_regs_t);
	PCIE_ADV_REG(pfd_p) = PCIE_ZALLOC(pf_pcie_adv_err_regs_t);
	PCIE_ADV_RP_REG(pfd_p) = PCIE_ZALLOC(pf_pcie_adv_rp_err_regs_t);

	PCIE_ADV_REG(pfd_p)->pcie_ue_sev = pcie_aer_uce_severity;
}

void
pcie_rc_fini_pfd(pf_data_t *pfd_p)
{
	kmem_free(PCIE_ADV_RP_REG(pfd_p), sizeof (pf_pcie_adv_rp_err_regs_t));
	kmem_free(PCIE_ADV_REG(pfd_p), sizeof (pf_pcie_adv_err_regs_t));
	kmem_free(PCIE_RP_REG(pfd_p), sizeof (pf_pcie_rp_err_regs_t));
	kmem_free(PCIE_ERR_REG(pfd_p), sizeof (pf_pcie_err_regs_t));
	kmem_free(PCI_BDG_ERR_REG(pfd_p), sizeof (pf_pci_bdg_err_regs_t));
	kmem_free(PCI_ERR_REG(pfd_p), sizeof (pf_pci_err_regs_t));
	kmem_free(PCIE_ROOT_FAULT(pfd_p), sizeof (pf_root_fault_t));
}

void
pcie_rc_init_bus(dev_info_t *dip)
{
	pcie_bus_t *bus_p;

	bus_p = (pcie_bus_t *)kmem_zalloc(sizeof (pcie_bus_t), KM_SLEEP);
	bus_p->bus_dip = dip;
	bus_p->bus_dev_type = PCIE_PCIECAP_DEV_TYPE_RC_PSEUDO;
	bus_p->bus_hdr_type = PCI_HEADER_ONE;

	/* Fake that there are AER logs */
	bus_p->bus_aer_off = (uint16_t)-1;

	/* Needed only for handle lookup */
	bus_p->bus_fm_flags |= PF_FM_READY;

	ndi_set_bus_private(dip, B_FALSE, DEVI_PORT_TYPE_PCI, bus_p);
}

void
pcie_rc_fini_bus(dev_info_t *dip)
{
	pcie_bus_t *bus_p = (pcie_bus_t *)ndi_get_bus_private(dip, B_FALSE);
	ndi_set_bus_private(dip, B_FALSE, NULL, NULL);
	kmem_free(bus_p, sizeof (pcie_bus_t));
}

/*
 * Initialize PCIe Bus Private Data
 *
 * PCIe Bus Private Data contains commonly used PCI/PCIe information and offsets
 * to key registers.
 */
pcie_bus_t *
pcie_init_bus(dev_info_t *cdip)
{
	pcie_bus_t		*bus_p = 0;
	ddi_acc_handle_t	eh = NULL;
	int			range_size;
	dev_info_t		*pdip;

	ASSERT(PCIE_DIP2UPBUS(cdip) == NULL);

	/* allocate memory for pcie bus data */
	bus_p = kmem_zalloc(sizeof (pcie_bus_t), KM_SLEEP);


	/* Set back pointer to dip */
	bus_p->bus_dip = cdip;

	/* Create an config access special to error handling */
	if (pci_config_setup(cdip, &eh) != DDI_SUCCESS) {
		goto fail;
	}
	bus_p->bus_cfg_hdl = eh;
	bus_p->bus_fm_flags = 0;

	/* get device's bus/dev/function number */
	if (pcie_get_bdf_from_dip(cdip, &bus_p->bus_bdf) != DDI_SUCCESS)
		goto fail;

	/* Save the Vendor Id Device Id */
	bus_p->bus_dev_ven_id = PCIE_GET(32, bus_p, PCI_CONF_VENID);
	bus_p->bus_rev_id = PCIE_GET(8, bus_p, PCI_CONF_REVID);

	/* Save the Header Type */
	bus_p->bus_hdr_type = PCIE_GET(8, bus_p, PCI_CONF_HEADER);
	bus_p->bus_hdr_type &= PCI_HEADER_TYPE_M;
	bus_p->bus_pcie2pci_secbus = ddi_prop_get_int(DDI_DEV_T_ANY, cdip, 0,
	    "pcie2pci-sec-bus", 0);

	/* Figure out the device type and all the relavant capability offsets */
	if ((PCI_CAP_LOCATE(eh, PCI_CAP_ID_PCI_E, &bus_p->bus_pcie_off))
	    != DDI_FAILURE) {
		bus_p->bus_dev_type = PCI_CAP_GET16(eh, NULL,
		    bus_p->bus_pcie_off, PCIE_PCIECAP) &
		    PCIE_PCIECAP_DEV_TYPE_MASK;

		if (PCI_CAP_LOCATE(eh, PCI_CAP_XCFG_SPC(PCIE_EXT_CAP_ID_AER),
		    &bus_p->bus_aer_off) != DDI_SUCCESS)
			bus_p->bus_aer_off = NULL;
	} else {
		bus_p->bus_pcie_off = NULL;
		bus_p->bus_dev_type = PCIE_PCIECAP_DEV_TYPE_PCI_DEV;
	}

	if ((PCI_CAP_LOCATE(eh, PCI_CAP_ID_PCIX, &bus_p->bus_pcix_off))
	    != DDI_FAILURE) {
		if (PCIE_IS_BDG(bus_p))
			bus_p->bus_ecc_ver = PCIX_CAP_GET(16, bus_p,
			    PCI_PCIX_SEC_STATUS) & PCI_PCIX_VER_MASK;
		else
			bus_p->bus_ecc_ver = PCIX_CAP_GET(16, bus_p,
			    PCI_PCIX_COMMAND) & PCI_PCIX_VER_MASK;
	} else {
		bus_p->bus_pcix_off = NULL;
		bus_p->bus_ecc_ver = NULL;
	}

	/* Save the Range information if device is a switch/bridge */
	if (PCIE_IS_BDG(bus_p)) {
		/* get "bus_range" property */
		range_size = sizeof (pci_bus_range_t);
		if (ddi_getlongprop_buf(DDI_DEV_T_ANY, cdip, DDI_PROP_DONTPASS,
		    "bus-range", (caddr_t)&bus_p->bus_bus_range, &range_size)
		    != DDI_PROP_SUCCESS)
			goto fail;

		/* get secondary bus number */
		bus_p->bus_bdg_secbus = PCIE_GET(8, bus_p, PCI_BCNF_SECBUS);

		/* Get "ranges" property */
		if (ddi_getlongprop(DDI_DEV_T_ANY, cdip, DDI_PROP_DONTPASS,
		    "ranges", (caddr_t)&bus_p->bus_addr_ranges,
		    &bus_p->bus_addr_entries) != DDI_PROP_SUCCESS)
			bus_p->bus_addr_entries = 0;
		bus_p->bus_addr_entries /= sizeof (ppb_ranges_t);
	}

	/* save "assigned-addresses" property array, ignore failues */
	if (ddi_getlongprop(DDI_DEV_T_ANY, cdip, DDI_PROP_DONTPASS,
	    "assigned-addresses", (caddr_t)&bus_p->bus_assigned_addr,
	    &bus_p->bus_assigned_entries) == DDI_PROP_SUCCESS)
		bus_p->bus_assigned_entries /= sizeof (pci_regspec_t);
	else
		bus_p->bus_assigned_entries = 0;

	/* save RP dip and RP bdf */
	if (PCIE_IS_RP(bus_p)) {
		bus_p->bus_rp_dip = cdip;
		bus_p->bus_rp_bdf = bus_p->bus_bdf;
	} else {
		for (pdip = ddi_get_parent(cdip); pdip;
		    pdip = ddi_get_parent(pdip)) {
			pcie_bus_t *parent_bus_p = PCIE_DIP2BUS(pdip);

			/*
			 * When debugging be aware that some NVIDIA x86
			 * architectures have 2 nodes for each RP, One at Bus
			 * 0x0 and one at Bus 0x80.  The requester is from Bus
			 * 0x80
			 */
			if (PCIE_IS_ROOT(parent_bus_p)) {
				bus_p->bus_rp_dip = pdip;
				bus_p->bus_rp_bdf = parent_bus_p->bus_bdf;
				break;
			}
		}
	}

	ndi_set_bus_private(cdip, B_TRUE, DEVI_PORT_TYPE_PCI, (void *)bus_p);

	pcie_init_pfd(cdip);

	PCIE_DBG("Add %s(dip 0x%p, bdf 0x%x, secbus 0x%x)\n",
	    ddi_driver_name(cdip), (void *)cdip, bus_p->bus_bdf,
	    bus_p->bus_bdg_secbus);
#ifdef DEBUG
	pcie_print_bus(bus_p);
#endif

	return (bus_p);
fail:
	cmn_err(CE_WARN, "PCIE init err info failed BDF 0x%x\n",
	    bus_p->bus_bdf);
	if (eh)
		pci_config_teardown(&eh);
	kmem_free(bus_p, sizeof (pcie_bus_t));
	return (NULL);
}

int
pcie_postattach_child(dev_info_t *cdip)
{
	pcie_bus_t *bus_p = PCIE_DIP2BUS(cdip);

	if (!bus_p)
		return (DDI_FAILURE);

	return (pcie_enable_ce(cdip));
}

/*
 * PCI-Express child device de-initialization.
 * This function disables generic pci-express interrupts and error
 * handling.
 */
void
pcie_uninitchild(dev_info_t *cdip)
{
	pcie_disable_errors(cdip);
	pcie_fini_bus(cdip);
}

void
pcie_fini_bus(dev_info_t *cdip)
{
	pcie_bus_t	*bus_p;

	pcie_fini_pfd(cdip);

	bus_p = PCIE_DIP2UPBUS(cdip);
	ASSERT(bus_p);
	pci_config_teardown(&bus_p->bus_cfg_hdl);
	ndi_set_bus_private(cdip, B_TRUE, NULL, NULL);
	kmem_free(bus_p->bus_assigned_addr,
	    (sizeof (pci_regspec_t) * bus_p->bus_assigned_entries));
	kmem_free(bus_p->bus_addr_ranges,
	    (sizeof (ppb_ranges_t) * bus_p->bus_addr_entries));

	kmem_free(bus_p, sizeof (pcie_bus_t));
}

void
pcie_enable_errors(dev_info_t *dip)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);
	uint16_t	reg16, tmp16;
	uint32_t	reg32, tmp32;

	ASSERT(bus_p);

	/*
	 * Clear any pending errors
	 */
	pcie_clear_errors(dip);

	if (!PCIE_IS_PCIE(bus_p))
		return;

	/*
	 * Enable Baseline Error Handling but leave CE reporting off (poweron
	 * default).
	 */
	if ((reg16 = PCIE_CAP_GET(16, bus_p, PCIE_DEVCTL)) !=
	    PCI_CAP_EINVAL16) {
		tmp16 = pcie_devctl_default | (pcie_base_err_default &
		    (~PCIE_DEVCTL_CE_REPORTING_EN));
		PCIE_CAP_PUT(16, bus_p, PCIE_DEVCTL, tmp16);
		PCIE_DBG_CAP(dip, bus_p, "DEVCTL", 16, PCIE_DEVCTL, reg16);
	}

	/* Enable Root Port Baseline Error Receiving */
	if (PCIE_IS_ROOT(bus_p) &&
	    (reg16 = PCIE_CAP_GET(16, bus_p, PCIE_ROOTCTL)) !=
	    PCI_CAP_EINVAL16) {

#if defined(__xpv)
		/*
		 * When we're booted under the hypervisor we won't receive
		 * MSI's, so to ensure that uncorrectable errors aren't ignored
		 * we set the SERR_FAT and SERR_NONFAT bits in the Root Control
		 * Register.
		 */
		tmp16 = pcie_root_ctrl_default;
#else
		tmp16 = pcie_serr_disable_flag ?
		    (pcie_root_ctrl_default & ~PCIE_ROOT_SYS_ERR) :
		    pcie_root_ctrl_default;
#endif /* __xpv */
		PCIE_CAP_PUT(16, bus_p, PCIE_ROOTCTL, tmp16);
		PCIE_DBG_CAP(dip, bus_p, "ROOT DEVCTL", 16, PCIE_ROOTCTL,
		    reg16);
	}

	/*
	 * Enable PCI-Express Advanced Error Handling if Exists
	 */
	if (!PCIE_HAS_AER(bus_p))
		return;

	/* Set Uncorrectable Severity */
	if ((reg32 = PCIE_AER_GET(32, bus_p, PCIE_AER_UCE_SERV)) !=
	    PCI_CAP_EINVAL32) {
		tmp32 = pcie_aer_uce_severity;

		PCIE_AER_PUT(32, bus_p, PCIE_AER_UCE_SERV, tmp32);
		PCIE_DBG_AER(dip, bus_p, "AER UCE SEV", 32, PCIE_AER_UCE_SERV,
		    reg32);
	}

	/* Enable Uncorrectable errors */
	if ((reg32 = PCIE_AER_GET(32, bus_p, PCIE_AER_UCE_MASK)) !=
	    PCI_CAP_EINVAL32) {
		tmp32 = pcie_aer_uce_mask;

		PCIE_AER_PUT(32, bus_p, PCIE_AER_UCE_MASK, tmp32);
		PCIE_DBG_AER(dip, bus_p, "AER UCE MASK", 32, PCIE_AER_UCE_MASK,
		    reg32);
	}

	/* x86 doesn't do this except for RC */
	/* Enable ECRC generation and checking */
	if ((reg32 = PCIE_AER_GET(32, bus_p, PCIE_AER_CTL)) !=
	    PCI_CAP_EINVAL32) {
		tmp32 = reg32 | pcie_ecrc_value;
		PCIE_AER_PUT(32, bus_p, PCIE_AER_CTL, tmp32);
		PCIE_DBG_AER(dip, bus_p, "AER CTL", 32, PCIE_AER_CTL, reg32);
	}

	/* Enable Secondary Uncorrectable errors if this is a bridge */
	if (!PCIE_IS_PCIE_BDG(bus_p))
		goto root;

	/* Set Uncorrectable Severity */
	if ((reg32 = PCIE_AER_GET(32, bus_p, PCIE_AER_SUCE_SERV)) !=
	    PCI_CAP_EINVAL32) {
		tmp32 = pcie_aer_suce_severity;

		PCIE_AER_PUT(32, bus_p, PCIE_AER_SUCE_SERV, tmp32);
		PCIE_DBG_AER(dip, bus_p, "AER SUCE SEV", 32, PCIE_AER_SUCE_SERV,
		    reg32);
	}

	if ((reg32 = PCIE_AER_GET(32, bus_p, PCIE_AER_SUCE_MASK)) !=
	    PCI_CAP_EINVAL32) {
		PCIE_AER_PUT(32, bus_p, PCIE_AER_SUCE_MASK, pcie_aer_suce_mask);
		PCIE_DBG_AER(dip, bus_p, "AER SUCE MASK", 32,
		    PCIE_AER_SUCE_MASK, reg32);
	}

root:
	/*
	 * Enable Root Control this is a Root device
	 */
	if (!PCIE_IS_ROOT(bus_p))
		return;

#if !defined(__xpv)
	if ((reg16 = PCIE_AER_GET(16, bus_p, PCIE_AER_RE_CMD)) !=
	    PCI_CAP_EINVAL16) {
		PCIE_AER_PUT(16, bus_p, PCIE_AER_RE_CMD,
		    pcie_root_error_cmd_default);
		PCIE_DBG_AER(dip, bus_p, "AER Root Err Cmd", 16,
		    PCIE_AER_RE_CMD, reg16);
	}
#endif /* __xpv */
}

/*
 * This function is used for enabling CE reporting and setting the AER CE mask.
 * When called from outside the pcie module it should always be preceded by
 * a call to pcie_enable_errors.
 */
int
pcie_enable_ce(dev_info_t *dip)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);
	uint16_t	device_sts, device_ctl;
	uint32_t	tmp_pcie_aer_ce_mask;

	if (!PCIE_IS_PCIE(bus_p))
		return (DDI_SUCCESS);

	/*
	 * The "pcie_ce_mask" property is used to control both the CE reporting
	 * enable field in the device control register and the AER CE mask. We
	 * leave CE reporting disabled if pcie_ce_mask is set to -1.
	 */

	tmp_pcie_aer_ce_mask = (uint32_t)ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "pcie_ce_mask", pcie_aer_ce_mask);

	if (tmp_pcie_aer_ce_mask == (uint32_t)-1) {
		/*
		 * Nothing to do since CE reporting has already been disabled.
		 */
		return (DDI_SUCCESS);
	}

	if (PCIE_HAS_AER(bus_p)) {
		/* Enable AER CE */
		PCIE_AER_PUT(32, bus_p, PCIE_AER_CE_MASK, tmp_pcie_aer_ce_mask);
		PCIE_DBG_AER(dip, bus_p, "AER CE MASK", 32, PCIE_AER_CE_MASK,
		    0);

		/* Clear any pending AER CE errors */
		PCIE_AER_PUT(32, bus_p, PCIE_AER_CE_STS, -1);
	}

	/* clear any pending CE errors */
	if ((device_sts = PCIE_CAP_GET(16, bus_p, PCIE_DEVSTS)) !=
	    PCI_CAP_EINVAL16)
		PCIE_CAP_PUT(16, bus_p, PCIE_DEVSTS,
		    device_sts & (~PCIE_DEVSTS_CE_DETECTED));

	/* Enable CE reporting */
	device_ctl = PCIE_CAP_GET(16, bus_p, PCIE_DEVCTL);
	PCIE_CAP_PUT(16, bus_p, PCIE_DEVCTL,
	    (device_ctl & (~PCIE_DEVCTL_ERR_MASK)) | pcie_base_err_default);
	PCIE_DBG_CAP(dip, bus_p, "DEVCTL", 16, PCIE_DEVCTL, device_ctl);

	return (DDI_SUCCESS);
}

/* ARGSUSED */
void
pcie_disable_errors(dev_info_t *dip)
{
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);
	uint16_t	device_ctl;
	uint32_t	aer_reg;

	if (!PCIE_IS_PCIE(bus_p))
		return;

	/*
	 * Disable PCI-Express Baseline Error Handling
	 */
	device_ctl = PCIE_CAP_GET(16, bus_p, PCIE_DEVCTL);
	device_ctl &= ~PCIE_DEVCTL_ERR_MASK;
	PCIE_CAP_PUT(16, bus_p, PCIE_DEVCTL, device_ctl);

	/*
	 * Disable PCI-Express Advanced Error Handling if Exists
	 */
	if (!PCIE_HAS_AER(bus_p))
		goto root;

	/* Disable Uncorrectable errors */
	PCIE_AER_PUT(32, bus_p, PCIE_AER_UCE_MASK, PCIE_AER_UCE_BITS);

	/* Disable Correctable errors */
	PCIE_AER_PUT(32, bus_p, PCIE_AER_CE_MASK, PCIE_AER_CE_BITS);

	/* Disable ECRC generation and checking */
	if ((aer_reg = PCIE_AER_GET(32, bus_p, PCIE_AER_CTL)) !=
	    PCI_CAP_EINVAL32) {
		aer_reg &= ~(PCIE_AER_CTL_ECRC_GEN_ENA |
		    PCIE_AER_CTL_ECRC_CHECK_ENA);

		PCIE_AER_PUT(32, bus_p, PCIE_AER_CTL, aer_reg);
	}
	/*
	 * Disable Secondary Uncorrectable errors if this is a bridge
	 */
	if (!PCIE_IS_PCIE_BDG(bus_p))
		goto root;

	PCIE_AER_PUT(32, bus_p, PCIE_AER_SUCE_MASK, PCIE_AER_SUCE_BITS);

root:
	/*
	 * disable Root Control this is a Root device
	 */
	if (!PCIE_IS_ROOT(bus_p))
		return;

	if (!pcie_serr_disable_flag) {
		device_ctl = PCIE_CAP_GET(16, bus_p, PCIE_ROOTCTL);
		device_ctl &= ~PCIE_ROOT_SYS_ERR;
		PCIE_CAP_PUT(16, bus_p, PCIE_ROOTCTL, device_ctl);
	}

	if (!PCIE_HAS_AER(bus_p))
		return;

	if ((device_ctl = PCIE_CAP_GET(16, bus_p, PCIE_AER_RE_CMD)) !=
	    PCI_CAP_EINVAL16) {
		device_ctl &= ~pcie_root_error_cmd_default;
		PCIE_CAP_PUT(16, bus_p, PCIE_AER_RE_CMD, device_ctl);
	}
}

/*
 * Extract bdf from "reg" property.
 */
int
pcie_get_bdf_from_dip(dev_info_t *dip, pcie_req_id_t *bdf)
{
	pci_regspec_t	*regspec;
	int		reglen;

	if (ddi_prop_lookup_int_array(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "reg", (int **)&regspec, (uint_t *)&reglen) != DDI_SUCCESS)
		return (DDI_FAILURE);

	if (reglen < (sizeof (pci_regspec_t) / sizeof (int))) {
		ddi_prop_free(regspec);
		return (DDI_FAILURE);
	}

	/* Get phys_hi from first element.  All have same bdf. */
	*bdf = (regspec->pci_phys_hi & (PCI_REG_BDFR_M ^ PCI_REG_REG_M)) >> 8;

	ddi_prop_free(regspec);
	return (DDI_SUCCESS);
}

dev_info_t *
pcie_get_my_childs_dip(dev_info_t *dip, dev_info_t *rdip)
{
	dev_info_t *cdip = rdip;

	for (; ddi_get_parent(cdip) != dip; cdip = ddi_get_parent(cdip))
		;

	return (cdip);
}

uint32_t
pcie_get_bdf_for_dma_xfer(dev_info_t *dip, dev_info_t *rdip)
{
	dev_info_t *cdip;

	/*
	 * As part of the probing, the PCI fcode interpreter may setup a DMA
	 * request if a given card has a fcode on it using dip and rdip of the
	 * AP (attachment point) i.e, dip and rdip of px/px_pci driver. In this
	 * case, return zero for the bdf since we cannot get to the bdf value
	 * of the actual device which will be initiating this DMA.
	 */
	if (rdip == dip)
		return (0);

	cdip = pcie_get_my_childs_dip(dip, rdip);

	/*
	 * For a given rdip, return the bdf value of dip's (px or px_pci)
	 * immediate child or secondary bus-id if dip is a PCIe2PCI bridge.
	 *
	 * XXX - For now, return bdf value of zero for all PCI and PCI-X devices
	 * since this needs more work.
	 */
	return (PCI_GET_PCIE2PCI_SECBUS(cdip) ? 0 : PCI_GET_BDF(cdip));
}

uint32_t
pcie_get_aer_uce_mask() {
	return (pcie_aer_uce_mask);
}
uint32_t
pcie_get_aer_ce_mask() {
	return (pcie_aer_ce_mask);
}
uint32_t
pcie_get_aer_suce_mask() {
	return (pcie_aer_suce_mask);
}
uint32_t
pcie_get_serr_mask() {
	return (pcie_serr_disable_flag);
}

void
pcie_set_aer_uce_mask(uint32_t mask) {
	pcie_aer_uce_mask = mask;
	if (mask & PCIE_AER_UCE_UR)
		pcie_base_err_default &= ~PCIE_DEVCTL_UR_REPORTING_EN;
	else
		pcie_base_err_default |= PCIE_DEVCTL_UR_REPORTING_EN;

	if (mask & PCIE_AER_UCE_ECRC)
		pcie_ecrc_value = 0;
}

void
pcie_set_aer_ce_mask(uint32_t mask) {
	pcie_aer_ce_mask = mask;
}
void
pcie_set_aer_suce_mask(uint32_t mask) {
	pcie_aer_suce_mask = mask;
}
void
pcie_set_serr_mask(uint32_t mask) {
	pcie_serr_disable_flag = mask;
}

/*
 * Is the rdip a child of dip.	Used for checking certain CTLOPS from bubbling
 * up erronously.  Ex.	ISA ctlops to a PCI-PCI Bridge.
 */
boolean_t
pcie_is_child(dev_info_t *dip, dev_info_t *rdip)
{
	dev_info_t	*cdip = ddi_get_child(dip);
	for (; cdip; cdip = ddi_get_next_sibling(cdip))
		if (cdip == rdip)
			break;
	return (cdip != NULL);
}

boolean_t
pcie_is_link_disabled(dev_info_t *dip)
{
	pcie_bus_t *bus_p = PCIE_DIP2BUS(dip);

	if (PCIE_IS_PCIE(bus_p)) {
		if (PCIE_CAP_GET(16, bus_p, PCIE_LINKCTL) &
		    PCIE_LINKCTL_LINK_DISABLE)
			return (B_TRUE);
	}
	return (B_FALSE);
}

#ifdef	DEBUG

static void
pcie_print_bus(pcie_bus_t *bus_p)
{
	pcie_dbg("\tbus_dip = 0x%p\n", bus_p->bus_dip);
	pcie_dbg("\tbus_fm_flags = 0x%x\n", bus_p->bus_fm_flags);

	pcie_dbg("\tbus_bdf = 0x%x\n", bus_p->bus_bdf);
	pcie_dbg("\tbus_dev_ven_id = 0x%x\n", bus_p->bus_dev_ven_id);
	pcie_dbg("\tbus_rev_id = 0x%x\n", bus_p->bus_rev_id);
	pcie_dbg("\tbus_hdr_type = 0x%x\n", bus_p->bus_hdr_type);
	pcie_dbg("\tbus_dev_type = 0x%x\n", bus_p->bus_dev_type);
	pcie_dbg("\tbus_bdg_secbus = 0x%x\n", bus_p->bus_bdg_secbus);
	pcie_dbg("\tbus_pcie_off = 0x%x\n", bus_p->bus_pcie_off);
	pcie_dbg("\tbus_aer_off = 0x%x\n", bus_p->bus_aer_off);
	pcie_dbg("\tbus_pcix_off = 0x%x\n", bus_p->bus_pcix_off);
	pcie_dbg("\tbus_ecc_ver = 0x%x\n", bus_p->bus_ecc_ver);
}

/*
 * For debugging purposes set pcie_dbg_print != 0 to see printf messages
 * during interrupt.
 *
 * When a proper solution is in place this code will disappear.
 * Potential solutions are:
 * o circular buffers
 * o taskq to print at lower pil
 */
int pcie_dbg_print = 0;
static void
pcie_dbg(char *fmt, ...)
{
	va_list ap;

	if (!pcie_debug_flags) {
		return;
	}
	va_start(ap, fmt);
	if (servicing_interrupt()) {
		if (pcie_dbg_print) {
			prom_vprintf(fmt, ap);
		}
	} else {
		prom_vprintf(fmt, ap);
	}
	va_end(ap);
}
#endif	/* DEBUG */
