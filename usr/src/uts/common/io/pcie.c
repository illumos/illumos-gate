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

dev_info_t *pcie_get_my_childs_dip(dev_info_t *dip, dev_info_t *rdip);
uint32_t pcie_get_bdf_for_dma_xfer(dev_info_t *dip, dev_info_t *rdip);

#ifdef	DEBUG
uint_t pcie_debug_flags = 0;

#define	PCIE_DBG pcie_dbg
static void pcie_dbg(char *fmt, ...);

#else	/* DEBUG */

#define	PCIE_DBG 0 &&

#endif	/* DEBUG */

/* Variable to control default PCI-Express config settings */
ushort_t pcie_command_default = PCI_COMM_SERR_ENABLE |
				PCI_COMM_WAIT_CYC_ENAB |
				PCI_COMM_PARITY_DETECT |
				PCI_COMM_ME |
				PCI_COMM_MAE |
				PCI_COMM_IO;
ushort_t pcie_base_err_default = PCIE_DEVCTL_CE_REPORTING_EN |
				PCIE_DEVCTL_NFE_REPORTING_EN |
				PCIE_DEVCTL_FE_REPORTING_EN |
				PCIE_DEVCTL_UR_REPORTING_EN;

uint32_t pcie_devctl_default = PCIE_DEVCTL_RO_EN |
				PCIE_DEVCTL_MAX_PAYLOAD_128 |
				PCIE_DEVCTL_MAX_READ_REQ_512;
uint32_t pcie_aer_uce_mask = 0;
uint32_t pcie_aer_ce_mask = 0;
uint32_t pcie_aer_suce_mask = 0;

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

int
_init(void)
{
	int rval;

	rval = mod_install(&modlinkage);
	return (rval);
}

int
_fini()
{
	int		rval;

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
	uint8_t			header_type;
	uint8_t			bcr;
	uint16_t		command_reg, status_reg;
	pcie_ppd_t		*ppd_p;
	ddi_acc_handle_t	eh;

	ppd_p = pcie_init_ppd(cdip);
	if (ppd_p == NULL)
		return (DDI_FAILURE);

	eh = ppd_p->ppd_cfg_hdl;

	/* setup the device's command register */
	header_type = ppd_p->ppd_hdr_type;
	status_reg = pci_config_get16(eh, PCI_CONF_STAT);
	pci_config_put16(eh, PCI_CONF_STAT, status_reg);
	command_reg = pci_config_get16(eh, PCI_CONF_COMM);
	command_reg |= pcie_command_default;
	pci_config_put16(eh, PCI_CONF_COMM, command_reg);

	PCIE_DBG("pcie_initchild: %s(dip 0x%p), header_type=%x, "
	    "command=%x\n", ddi_driver_name(cdip), (void *)cdip,
	    header_type, pci_config_get16(eh, PCI_CONF_COMM));

	/*
	 * If the device has a bus control register then program it
	 * based on the settings in the command register.
	 */
	if (header_type == PCI_HEADER_ONE) {
		status_reg = pci_config_get16(eh,
		    PCI_BCNF_SEC_STATUS);
		pci_config_put16(eh, PCI_BCNF_SEC_STATUS,
		    status_reg);
		bcr = pci_config_get8(eh, PCI_BCNF_BCNTRL);
		if (pcie_command_default & PCI_COMM_PARITY_DETECT)
			bcr |= PCI_BCNF_BCNTRL_PARITY_ENABLE;
		if (pcie_command_default & PCI_COMM_SERR_ENABLE)
			bcr |= PCI_BCNF_BCNTRL_SERR_ENABLE;
		bcr |= PCI_BCNF_BCNTRL_MAST_AB_MODE;
		pci_config_put8(eh, PCI_BCNF_BCNTRL, bcr);
	}

	if (ppd_p->ppd_pcie_off)
		pcie_enable_errors(cdip, eh);

	return (DDI_SUCCESS);
}

/* Initialize PCIe Parent Private Data */
pcie_ppd_t *
pcie_init_ppd(dev_info_t *cdip)
{
	pcie_ppd_t		*ppd_p = 0;
	ddi_acc_handle_t	eh;
	int			range_size;

	/* allocate memory for pcie parent data */
	ppd_p = kmem_zalloc(sizeof (pcie_ppd_t), KM_SLEEP);

	/* Create an config access special to error handling */
	if (pci_config_setup(cdip, &eh) != DDI_SUCCESS) {
		kmem_free(ppd_p, sizeof (pcie_ppd_t));
		return (NULL);
	}
	ppd_p->ppd_cfg_hdl = eh;

	/* get device's bus/dev/function number */
	if (pcie_get_bdf_from_dip(cdip, &ppd_p->ppd_bdf) != DDI_SUCCESS)
		goto fail;

	/* Save the Vendor Id Device Id */
	ppd_p->ppd_dev_ven_id = pci_config_get32(eh, PCI_CONF_VENID);

	/* Save the Header Type */
	ppd_p->ppd_hdr_type = pci_config_get8(eh, PCI_CONF_HEADER);
	ppd_p->ppd_hdr_type &= PCI_HEADER_TYPE_M;
	ppd_p->ppd_pcie2pci_secbus = ddi_prop_get_int(DDI_DEV_T_ANY, cdip, 0,
	    "pcie2pci-sec-bus", 0);

	/* Save the Range information if device is a switch/bridge */
	if (ppd_p->ppd_hdr_type == PCI_HEADER_ONE) {
		/* get "bus_range" property */
		range_size = sizeof (pci_bus_range_t);
		if (ddi_getlongprop_buf(DDI_DEV_T_ANY, cdip, DDI_PROP_DONTPASS,
		    "bus-range", (caddr_t)&ppd_p->ppd_bus_range, &range_size)
		    != DDI_PROP_SUCCESS)
			goto fail;

		/* get secondary bus number */
		ppd_p->ppd_bdg_secbus = pci_config_get8(eh, PCI_BCNF_SECBUS);

		/* Get "ranges" property */
		if (ddi_getlongprop(DDI_DEV_T_ANY, cdip, DDI_PROP_DONTPASS,
		    "ranges", (caddr_t)&ppd_p->ppd_addr_ranges,
		    &ppd_p->ppd_addr_entries) != DDI_PROP_SUCCESS)
			ppd_p->ppd_addr_entries = 0;
		ppd_p->ppd_addr_entries /= sizeof (ppb_ranges_t);
	}

	/* save "assigned-addresses" property array, ignore failues */
	if (ddi_getlongprop(DDI_DEV_T_ANY, cdip, DDI_PROP_DONTPASS,
	    "assigned-addresses", (caddr_t)&ppd_p->ppd_assigned_addr,
	    &ppd_p->ppd_assigned_entries) == DDI_PROP_SUCCESS)
		ppd_p->ppd_assigned_entries /= sizeof (pci_regspec_t);
	else
		ppd_p->ppd_assigned_entries = 0;

	if ((PCI_CAP_LOCATE(eh, PCI_CAP_ID_PCI_E, &ppd_p->ppd_pcie_off))
		!= DDI_FAILURE) {
		ppd_p->ppd_dev_type = PCI_CAP_GET16(eh, NULL,
		    ppd_p->ppd_pcie_off, PCIE_PCIECAP) &
		    PCIE_PCIECAP_DEV_TYPE_MASK;

		if (PCI_CAP_LOCATE(eh, PCI_CAP_XCFG_SPC(PCIE_EXT_CAP_ID_AER),
			&ppd_p->ppd_aer_off) != DDI_SUCCESS)
			ppd_p->ppd_aer_off = NULL;
	} else {
		ppd_p->ppd_pcie_off = NULL;
		ppd_p->ppd_dev_type = PCIE_PCIECAP_DEV_TYPE_PCI_DEV;
	}

	ppd_p->ppd_dip = cdip;
	ppd_p->ppd_fm_flags = 0;
	ddi_set_parent_data(cdip, (void *)ppd_p);

	PCIE_DBG("Add %s(dip 0x%p, bdf 0x%x, secbus 0x%x)\n",
	    ddi_driver_name(cdip), (void *)cdip, ppd_p->ppd_bdf,
	    ppd_p->ppd_bdg_secbus);

	return (ppd_p);
fail:
	cmn_err(CE_WARN, "PCIE init err info failed BDF 0x%x\n",
	    ppd_p->ppd_bdf);
	pci_config_teardown(&eh);
	kmem_free(ppd_p, sizeof (pcie_ppd_t));
	return (NULL);
}

int
pcie_postattach_child(dev_info_t *dip)
{
	ddi_acc_handle_t cfg_hdl;
	int rval = DDI_FAILURE;

	if (pci_config_setup(dip, &cfg_hdl) != DDI_SUCCESS)
		return (DDI_FAILURE);

	rval = pcie_enable_ce(dip, cfg_hdl);

	pci_config_teardown(&cfg_hdl);
	return (rval);
}

/*
 * PCI-Express child device de-initialization.
 * This function disables generic pci-express interrupts and error
 * handling.
 */
void
pcie_uninitchild(dev_info_t *cdip)
{
	pcie_ppd_t	*ppd_p;
	ppd_p = pcie_get_ppd(cdip);

	pcie_disable_errors(cdip, ppd_p->ppd_cfg_hdl);
	pcie_uninit_ppd(cdip);
}

void
pcie_uninit_ppd(dev_info_t *cdip)
{
	pcie_ppd_t	*ppd_p;

	ppd_p = pcie_get_ppd(cdip);
	ASSERT(ppd_p);
	pci_config_teardown(&ppd_p->ppd_cfg_hdl);
	kmem_free(ppd_p->ppd_assigned_addr,
	    (sizeof (pci_regspec_t) * ppd_p->ppd_assigned_entries));
	kmem_free(ppd_p->ppd_addr_ranges,
	    (sizeof (ppb_ranges_t) * ppd_p->ppd_addr_entries));

	kmem_free(ppd_p, sizeof (pcie_ppd_t));
	ddi_set_parent_data(cdip, NULL);
}

/* ARGSUSED */
void
pcie_clear_errors(dev_info_t *dip, ddi_acc_handle_t cfg_hdl)
{
	uint16_t		cap_ptr, aer_ptr, dev_type, device_sts;
	int			rval = DDI_FAILURE;

	/* 1. clear the Legacy PCI Errors */
	device_sts = pci_config_get16(cfg_hdl, PCI_CONF_STAT);
	pci_config_put16(cfg_hdl, PCI_CONF_STAT, device_sts);

	if ((PCI_CAP_LOCATE(cfg_hdl, PCI_CAP_ID_PCI_E, &cap_ptr)) ==
	    DDI_FAILURE)
		return;

	rval = PCI_CAP_LOCATE(cfg_hdl, PCI_CAP_XCFG_SPC
		(PCIE_EXT_CAP_ID_AER), &aer_ptr);
	dev_type = PCI_CAP_GET16(cfg_hdl, NULL, cap_ptr,
		PCIE_PCIECAP) & PCIE_PCIECAP_DEV_TYPE_MASK;

	/* 1.1 clear the Legacy PCI Secondary Bus Errors */
	if (dev_type == PCIE_PCIECAP_DEV_TYPE_PCIE2PCI) {
		device_sts = pci_config_get16(cfg_hdl,
		    PCI_BCNF_SEC_STATUS);
		pci_config_put16(cfg_hdl, PCI_BCNF_SEC_STATUS,
		    device_sts);
	}

	/*
	 * Clear any pending errors
	 */
	/* 2. clear the Advanced PCIe Errors */
	if (rval != DDI_FAILURE) {
		PCI_XCAP_PUT32(cfg_hdl, NULL, aer_ptr, PCIE_AER_CE_STS,
			-1);
		PCI_XCAP_PUT32(cfg_hdl, NULL, aer_ptr, PCIE_AER_UCE_STS,
			-1);

		if (dev_type == PCIE_PCIECAP_DEV_TYPE_PCI2PCIE) {
			PCI_XCAP_PUT32(cfg_hdl, NULL, aer_ptr,
				PCIE_AER_SUCE_STS, -1);
		}
	}

	/* 3. clear the PCIe Errors */
	if ((device_sts = PCI_CAP_GET16(cfg_hdl, NULL, cap_ptr,
		PCIE_DEVSTS)) != PCI_CAP_EINVAL16)
		PCI_CAP_PUT16(cfg_hdl, PCI_CAP_ID_PCI_E, cap_ptr,
			PCIE_DEVSTS, device_sts);
}

void
pcie_enable_errors(dev_info_t *dip, ddi_acc_handle_t cfg_hdl)
{
	uint16_t		cap_ptr, aer_ptr, dev_type, device_ctl;
	uint32_t		aer_reg;
	int			rval = DDI_FAILURE;

	/*
	 * Clear any pending errors
	 */
	pcie_clear_errors(dip, cfg_hdl);

	if ((PCI_CAP_LOCATE(cfg_hdl, PCI_CAP_ID_PCI_E, &cap_ptr))
		== DDI_FAILURE)
		return;

	rval = PCI_CAP_LOCATE(cfg_hdl, PCI_CAP_XCFG_SPC
		(PCIE_EXT_CAP_ID_AER), &aer_ptr);
	dev_type = PCI_CAP_GET16(cfg_hdl, NULL, cap_ptr, PCIE_PCIECAP) &
	    PCIE_PCIECAP_DEV_TYPE_MASK;

	/*
	 * Enable Baseline Error Handling but leave CE reporting off (poweron
	 * default).
	 */
	if ((device_ctl = PCI_CAP_GET16(cfg_hdl, NULL, cap_ptr,
		PCIE_DEVCTL)) != PCI_CAP_EINVAL16) {
		PCI_CAP_PUT16(cfg_hdl, NULL, cap_ptr, PCIE_DEVCTL,
			pcie_devctl_default | (pcie_base_err_default &
			(~PCIE_DEVCTL_CE_REPORTING_EN)));
		PCIE_DBG("%s%d: devctl 0x%x -> 0x%x\n", ddi_node_name(dip),
			ddi_get_instance(dip), device_ctl,
			PCI_CAP_GET16(cfg_hdl, NULL, cap_ptr,
			PCIE_DEVCTL));
	}

	/*
	 * Enable PCI-Express Advanced Error Handling if Exists
	 */
	if (rval == DDI_FAILURE) {
		return;
	}

	/* Enable Uncorrectable errors */
	if ((aer_reg = PCI_XCAP_GET32(cfg_hdl, NULL, aer_ptr,
		PCIE_AER_UCE_MASK)) != PCI_CAP_EINVAL32) {
		PCI_XCAP_PUT32(cfg_hdl, NULL, aer_ptr,
			PCIE_AER_UCE_MASK, pcie_aer_uce_mask);
		PCIE_DBG("%s: AER UCE=0x%x->0x%x\n", ddi_driver_name(dip),
			aer_reg, PCI_XCAP_GET32(cfg_hdl, NULL, aer_ptr,
			PCIE_AER_UCE_MASK));
	}

	/* Enable ECRC generation and checking */
	if ((aer_reg = PCI_XCAP_GET32(cfg_hdl, NULL, aer_ptr,
	    PCIE_AER_CTL)) != PCI_CAP_EINVAL32) {
		aer_reg |= (PCIE_AER_CTL_ECRC_GEN_ENA |
		    PCIE_AER_CTL_ECRC_CHECK_ENA);

		PCI_XCAP_PUT32(cfg_hdl, NULL, aer_ptr, PCIE_AER_CTL,
		    aer_reg);
	}

	/*
	 * Enable Secondary Uncorrectable errors if this is a bridge
	 */
	if (!(dev_type == PCIE_PCIECAP_DEV_TYPE_PCIE2PCI))
		return;

	/*
	 * Enable secondary bus errors
	 */
	if ((aer_reg = PCI_XCAP_GET32(cfg_hdl, NULL, aer_ptr,
		PCIE_AER_SUCE_MASK)) != PCI_CAP_EINVAL32) {
		PCI_XCAP_PUT32(cfg_hdl, NULL, aer_ptr, PCIE_AER_SUCE_MASK,
			pcie_aer_suce_mask);
		PCIE_DBG("%s: AER SUCE=0x%x->0x%x\n", ddi_driver_name(dip),
			aer_reg, PCI_XCAP_GET32(cfg_hdl,
			PCIE_EXT_CAP_ID_AER, aer_ptr, PCIE_AER_SUCE_MASK));
	}
}

/*
 * This function is used for enabling CE reporting and setting the AER CE mask.
 * When called from outside the pcie module it should always be preceded by
 * a call to pcie_enable_errors.
 */
int
pcie_enable_ce(dev_info_t *dip, ddi_acc_handle_t cfg_hdl)
{
	uint16_t	cap_ptr, aer_ptr, device_sts, device_ctl;
	uint32_t	tmp_pcie_aer_ce_mask;

	if ((PCI_CAP_LOCATE(cfg_hdl, PCI_CAP_ID_PCI_E, &cap_ptr))
	    == DDI_FAILURE)
		return (DDI_FAILURE);

	/*
	 * The "pcie_ce_mask" property is used to control both the CE reporting
	 * enable field in the device control register and the AER CE mask. We
	 * leave CE reporting disabled if pcie_ce_mask is set to -1.
	 */

	tmp_pcie_aer_ce_mask = (uint32_t)ddi_prop_get_int(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS, "pcie_ce_mask", pcie_aer_ce_mask);

	if (tmp_pcie_aer_ce_mask == -1) {
		/*
		 * Nothing to do since CE reporting has already been disabled.
		 */
		return (DDI_SUCCESS);
	}

	if (PCI_CAP_LOCATE(cfg_hdl, PCI_CAP_XCFG_SPC
	    (PCIE_EXT_CAP_ID_AER), &aer_ptr) != DDI_FAILURE) {
		/* Enable AER CE */
		PCI_XCAP_PUT32(cfg_hdl, PCIE_EXT_CAP_ID_AER,
		    aer_ptr, PCIE_AER_CE_MASK, tmp_pcie_aer_ce_mask);

		PCIE_DBG("%s: AER CE set to 0x%x\n",
		    ddi_driver_name(dip), PCI_XCAP_GET32(cfg_hdl, NULL,
		    aer_ptr, PCIE_AER_CE_MASK));

		/* Clear any pending AER CE errors */
		PCI_XCAP_PUT32(cfg_hdl, NULL, aer_ptr, PCIE_AER_CE_STS,
		    -1);
	}

	/* clear any pending CE errors */
	if ((device_sts = PCI_CAP_GET16(cfg_hdl, NULL, cap_ptr,
		PCIE_DEVSTS)) != PCI_CAP_EINVAL16)
		PCI_CAP_PUT16(cfg_hdl, PCI_CAP_ID_PCI_E, cap_ptr,
			PCIE_DEVSTS, device_sts & (~PCIE_DEVSTS_CE_DETECTED));

	/* Enable CE reporting */
	device_ctl = PCI_CAP_GET16(cfg_hdl, NULL, cap_ptr, PCIE_DEVCTL);
	PCI_CAP_PUT16(cfg_hdl, NULL, cap_ptr, PCIE_DEVCTL,
		(device_ctl & (~PCIE_DEVCTL_ERR_MASK)) | pcie_base_err_default);
	PCIE_DBG("%s%d: devctl 0x%x -> 0x%x\n", ddi_node_name(dip),
		ddi_get_instance(dip), device_ctl,
		PCI_CAP_GET16(cfg_hdl, NULL, cap_ptr, PCIE_DEVCTL));
	return (DDI_SUCCESS);
}

/* ARGSUSED */
void
pcie_disable_errors(dev_info_t *dip, ddi_acc_handle_t cfg_hdl)
{
	uint16_t		cap_ptr, aer_ptr, dev_type, device_ctl;
	uint32_t		aer_reg;
	int			rval = DDI_FAILURE;

	if ((PCI_CAP_LOCATE(cfg_hdl, PCI_CAP_ID_PCI_E, &cap_ptr))
			== DDI_FAILURE)
		return;

	rval = PCI_CAP_LOCATE(cfg_hdl, PCI_CAP_XCFG_SPC
		(PCIE_EXT_CAP_ID_AER), &aer_ptr);
	dev_type = PCI_CAP_GET16(cfg_hdl, NULL, cap_ptr,
		PCIE_PCIECAP) & PCIE_PCIECAP_DEV_TYPE_MASK;

	/*
	 * Disable PCI-Express Baseline Error Handling
	 */
	device_ctl = PCI_CAP_GET16(cfg_hdl, NULL, cap_ptr, PCIE_DEVCTL);
	device_ctl &= ~PCIE_DEVCTL_ERR_MASK;
	PCI_CAP_PUT16(cfg_hdl, NULL, cap_ptr, PCIE_DEVCTL, device_ctl);

	/*
	 * Disable PCI-Express Advanced Error Handling if Exists
	 */
	if (rval == DDI_FAILURE) {
		return;
	}

	/* Disable Uncorrectable errors */
	PCI_XCAP_PUT32(cfg_hdl, NULL, aer_ptr, PCIE_AER_UCE_MASK,
		PCIE_AER_UCE_BITS);

	/* Disable Correctable errors */
	PCI_XCAP_PUT32(cfg_hdl, NULL, aer_ptr, PCIE_AER_CE_MASK,
		PCIE_AER_CE_BITS);

	/* Disable ECRC generation and checking */
	if ((aer_reg = PCI_XCAP_GET32(cfg_hdl, NULL, aer_ptr,
	    PCIE_AER_CTL)) != PCI_CAP_EINVAL32) {
		aer_reg &= ~(PCIE_AER_CTL_ECRC_GEN_ENA |
		    PCIE_AER_CTL_ECRC_CHECK_ENA);

		PCI_XCAP_PUT32(cfg_hdl, NULL, aer_ptr, PCIE_AER_CTL,
		    aer_reg);
	}
	/*
	 * Disable Secondary Uncorrectable errors if this is a bridge
	 */
	if (!(dev_type == PCIE_PCIECAP_DEV_TYPE_PCIE2PCI))
		return;

	/*
	 * Disable secondary bus errors
	 */
	PCI_XCAP_PUT32(cfg_hdl, NULL, aer_ptr, PCIE_AER_SUCE_MASK,
		PCIE_AER_SUCE_BITS);
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

/*
 * Returns Parent Private Data for PCIe devices and PCI devices that are in PCIe
 * systems
 */
pcie_ppd_t *
pcie_get_ppd(dev_info_t *dip)
{
	return ((pcie_ppd_t *)ddi_get_parent_data(dip));
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

#ifdef	DEBUG
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
