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

#include <sys/sysmacros.h>
#include <sys/types.h>
#include <sys/kmem.h>
#include <sys/modctl.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/promif.h>		  /* prom_printf */
#include <sys/disp.h>		  /* prom_printf */
#include <sys/pcie.h>
#include <sys/pci_cap.h>
#include <sys/pcie_impl.h>
#include <sys/pci_impl.h>

static int pcie_get_bdf_from_dip(dev_info_t *dip, uint32_t *bdf);
dev_info_t *pcie_get_my_childs_dip(dev_info_t *dip, dev_info_t *rdip);

#ifdef  DEBUG
uint_t pcie_debug_flags = 0;

#define	PCIE_DBG pcie_dbg
static void pcie_dbg(char *fmt, ...);

#else   /* DEBUG */

#define	PCIE_DBG 0 &&

#endif  /* DEBUG */

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
	ddi_acc_handle_t	config_handle;
	uint8_t			header_type;
	uint8_t			bcr;
	uint16_t		command_reg, status_reg;
	uint16_t		cap_ptr;
	pci_parent_data_t	*pd_p;

	if (pci_config_setup(cdip, &config_handle) != DDI_SUCCESS)
		return (DDI_FAILURE);

	/* Allocate memory for pci parent data */
	pd_p = kmem_zalloc(sizeof (pci_parent_data_t), KM_SLEEP);

	/*
	 * Retrieve and save BDF and PCIE2PCI bridge's secondary bus
	 * information in the parent private data structure.
	 */
	if (pcie_get_bdf_from_dip(cdip, &pd_p->pci_bdf) != DDI_SUCCESS)
		goto fail;

	pd_p->pci_sec_bus = ddi_prop_get_int(DDI_DEV_T_ANY, cdip, 0,
	    "pcie2pci-sec-bus", 0);

	/*
	 * Determine the configuration header type.
	 */
	header_type = pci_config_get8(config_handle, PCI_CONF_HEADER);
	PCIE_DBG("%s: header_type=%x\n", ddi_driver_name(cdip), header_type);

	/*
	 * Setup the device's command register
	 */
	status_reg = pci_config_get16(config_handle, PCI_CONF_STAT);
	pci_config_put16(config_handle, PCI_CONF_STAT, status_reg);
	command_reg = pci_config_get16(config_handle, PCI_CONF_COMM);
	command_reg |= pcie_command_default;
	pci_config_put16(config_handle, PCI_CONF_COMM, command_reg);

	PCIE_DBG("%s: command=%x\n", ddi_driver_name(cdip),
	    pci_config_get16(config_handle, PCI_CONF_COMM));

	/*
	 * If the device has a bus control register then program it
	 * based on the settings in the command register.
	 */
	if ((header_type & PCI_HEADER_TYPE_M) == PCI_HEADER_ONE) {
		status_reg = pci_config_get16(config_handle,
		    PCI_BCNF_SEC_STATUS);
		pci_config_put16(config_handle, PCI_BCNF_SEC_STATUS,
		    status_reg);
		bcr = pci_config_get8(config_handle, PCI_BCNF_BCNTRL);
		if (pcie_command_default & PCI_COMM_PARITY_DETECT)
			bcr |= PCI_BCNF_BCNTRL_PARITY_ENABLE;
		if (pcie_command_default & PCI_COMM_SERR_ENABLE)
			bcr |= PCI_BCNF_BCNTRL_SERR_ENABLE;
		bcr |= PCI_BCNF_BCNTRL_MAST_AB_MODE;
		pci_config_put8(config_handle, PCI_BCNF_BCNTRL, bcr);
	}

	if ((PCI_CAP_LOCATE(config_handle, PCI_CAP_ID_PCI_E, &cap_ptr))
		!= DDI_FAILURE) {
		pcie_enable_errors(cdip, config_handle);

		pd_p->pci_phfun = (pci_config_get8(config_handle,
		    cap_ptr + PCIE_DEVCAP) & PCIE_DEVCAP_PHTM_FUNC_MASK) >> 3;
	}

	ddi_set_parent_data(cdip, (void *)pd_p);
	pci_config_teardown(&config_handle);
	return (DDI_SUCCESS);
fail:
	cmn_err(CE_WARN, "PCIE init child failed\n");
	kmem_free(pd_p, sizeof (pci_parent_data_t));
	pci_config_teardown(&config_handle);
	return (DDI_FAILURE);
}

int
pcie_postattach_child(dev_info_t *dip)
{
	ddi_acc_handle_t config_handle;
	int rval = DDI_FAILURE;

	if (pci_config_setup(dip, &config_handle) != DDI_SUCCESS)
		return (DDI_FAILURE);

	rval = pcie_enable_ce(dip, config_handle);

	pci_config_teardown(&config_handle);
	return (rval);
}

/*
 * PCI-Express child device de-initialization.
 * This function disables generic pci-express interrupts and error
 * handling.
 *
 * @param pdip		parent dip (root nexus's dip)
 * @param cdip		child's dip (device's dip)
 * @param arg		pcie private data
 */
/* ARGSUSED */
void
pcie_uninitchild(dev_info_t *cdip)
{
	ddi_acc_handle_t	config_handle;
	pci_parent_data_t	*pd_p;

	if (pd_p = ddi_get_parent_data(cdip)) {
		ddi_set_parent_data(cdip, NULL);
		kmem_free(pd_p, sizeof (pci_parent_data_t));
	}

	if (pci_config_setup(cdip, &config_handle) != DDI_SUCCESS)
		return;

	pcie_disable_errors(cdip, config_handle);

	pci_config_teardown(&config_handle);
}

/* ARGSUSED */
void
pcie_clear_errors(dev_info_t *dip, ddi_acc_handle_t config_handle)
{
	uint16_t		cap_ptr, aer_ptr, dev_type, device_sts;
	int			rval = DDI_FAILURE;

	/* 1. clear the Legacy PCI Errors */
	device_sts = pci_config_get16(config_handle, PCI_CONF_STAT);
	pci_config_put16(config_handle, PCI_CONF_STAT, device_sts);

	if ((PCI_CAP_LOCATE(config_handle, PCI_CAP_ID_PCI_E, &cap_ptr))
			== DDI_FAILURE)
		return;

	rval = PCI_CAP_LOCATE(config_handle, PCI_CAP_XCFG_SPC
		(PCIE_EXT_CAP_ID_AER), &aer_ptr);
	dev_type = PCI_CAP_GET16(config_handle, NULL, cap_ptr,
		PCIE_PCIECAP) & PCIE_PCIECAP_DEV_TYPE_MASK;

	/*
	 * Clear any pending errors
	 */
	/* 2. clear the Advanced PCIe Errors */
	if (rval != DDI_FAILURE) {
		PCI_XCAP_PUT32(config_handle, NULL, aer_ptr, PCIE_AER_CE_STS,
			-1);
		PCI_XCAP_PUT32(config_handle, NULL, aer_ptr, PCIE_AER_UCE_STS,
			-1);

		if (dev_type == PCIE_PCIECAP_DEV_TYPE_PCIE2PCI) {
			PCI_XCAP_PUT32(config_handle, NULL, aer_ptr,
				PCIE_AER_SUCE_STS, -1);
		}
	}

	/* 3. clear the PCIe Errors */
	if ((device_sts = PCI_CAP_GET16(config_handle, NULL, cap_ptr,
		PCIE_DEVSTS)) != PCI_CAP_EINVAL16)
		PCI_CAP_PUT16(config_handle, PCI_CAP_ID_PCI_E, cap_ptr,
			PCIE_DEVSTS, device_sts);

	if (dev_type == PCIE_PCIECAP_DEV_TYPE_PCIE2PCI) {
		device_sts = pci_config_get16(config_handle,
		    PCI_BCNF_SEC_STATUS);
		pci_config_put16(config_handle, PCI_BCNF_SEC_STATUS,
		    device_sts);
	}
}

void
pcie_enable_errors(dev_info_t *dip, ddi_acc_handle_t config_handle)
{
	uint16_t		cap_ptr, aer_ptr, dev_type, device_ctl;
	uint32_t		aer_reg;
	int			rval = DDI_FAILURE;

	/*
	 * Clear any pending errors
	 */
	pcie_clear_errors(dip, config_handle);

	if ((PCI_CAP_LOCATE(config_handle, PCI_CAP_ID_PCI_E, &cap_ptr))
		== DDI_FAILURE)
		return;

	rval = PCI_CAP_LOCATE(config_handle, PCI_CAP_XCFG_SPC
		(PCIE_EXT_CAP_ID_AER), &aer_ptr);
	dev_type = PCI_CAP_GET16(config_handle, NULL, cap_ptr,
		PCIE_PCIECAP) & PCIE_PCIECAP_DEV_TYPE_MASK;

	/*
	 * Enable Baseline Error Handling but leave CE reporting off (poweron
	 * default).
	 */
	if ((device_ctl = PCI_CAP_GET16(config_handle, NULL, cap_ptr,
		PCIE_DEVCTL)) != PCI_CAP_EINVAL16) {
		PCI_CAP_PUT16(config_handle, NULL, cap_ptr, PCIE_DEVCTL,
			pcie_devctl_default | (pcie_base_err_default &
			(~PCIE_DEVCTL_CE_REPORTING_EN)));
		PCIE_DBG("%s%d: devctl 0x%x -> 0x%x\n", ddi_node_name(dip),
			ddi_get_instance(dip), device_ctl,
			PCI_CAP_GET16(config_handle, NULL, cap_ptr,
			PCIE_DEVCTL));
	}

	/*
	 * Enable PCI-Express Advanced Error Handling if Exists
	 */
	if (rval == DDI_FAILURE) {
		return;
	}

	/* Enable Uncorrectable errors */
	if ((aer_reg = PCI_XCAP_GET32(config_handle, NULL, aer_ptr,
		PCIE_AER_UCE_MASK)) != PCI_CAP_EINVAL32) {
		PCI_XCAP_PUT32(config_handle, NULL, aer_ptr,
			PCIE_AER_UCE_MASK, pcie_aer_uce_mask);
		PCIE_DBG("%s: AER UCE=0x%x->0x%x\n", ddi_driver_name(dip),
			aer_reg, PCI_XCAP_GET32(config_handle, NULL, aer_ptr,
			PCIE_AER_UCE_MASK));
	}

	/* Enable ECRC generation and checking */
	if ((aer_reg = PCI_XCAP_GET32(config_handle, NULL, aer_ptr,
	    PCIE_AER_CTL)) != PCI_CAP_EINVAL32) {
		aer_reg |= (PCIE_AER_CTL_ECRC_GEN_ENA |
		    PCIE_AER_CTL_ECRC_CHECK_ENA);

		PCI_XCAP_PUT32(config_handle, NULL, aer_ptr, PCIE_AER_CTL,
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
	if ((aer_reg = PCI_XCAP_GET32(config_handle, NULL, aer_ptr,
		PCIE_AER_SUCE_MASK)) != PCI_CAP_EINVAL32) {
		PCI_XCAP_PUT32(config_handle, NULL, aer_ptr, PCIE_AER_SUCE_MASK,
			pcie_aer_suce_mask);
		PCIE_DBG("%s: AER SUCE=0x%x->0x%x\n", ddi_driver_name(dip),
			aer_reg, PCI_XCAP_GET32(config_handle,
			PCIE_EXT_CAP_ID_AER, aer_ptr, PCIE_AER_SUCE_MASK));
	}
}

/*
 * This function is used for enabling CE reporting and setting the AER CE mask.
 * When called from outside the pcie module it should always be preceded by
 * a call to pcie_enable_errors.
 */
int
pcie_enable_ce(dev_info_t *dip, ddi_acc_handle_t config_handle)
{
	uint16_t	cap_ptr, aer_ptr, device_sts, device_ctl;
	uint32_t	tmp_pcie_aer_ce_mask;

	if ((PCI_CAP_LOCATE(config_handle, PCI_CAP_ID_PCI_E, &cap_ptr))
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

	if (PCI_CAP_LOCATE(config_handle, PCI_CAP_XCFG_SPC
	    (PCIE_EXT_CAP_ID_AER), &aer_ptr) != DDI_FAILURE) {
		/* Enable AER CE */
		PCI_XCAP_PUT32(config_handle, PCIE_EXT_CAP_ID_AER,
		    aer_ptr, PCIE_AER_CE_MASK, tmp_pcie_aer_ce_mask);

		PCIE_DBG("%s: AER CE set to 0x%x\n",
		    ddi_driver_name(dip), PCI_XCAP_GET32(config_handle, NULL,
		    aer_ptr, PCIE_AER_CE_MASK));

		/* Clear any pending AER CE errors */
		PCI_XCAP_PUT32(config_handle, NULL, aer_ptr, PCIE_AER_CE_STS,
		    -1);
	}

	/* clear any pending CE errors */
	if ((device_sts = PCI_CAP_GET16(config_handle, NULL, cap_ptr,
		PCIE_DEVSTS)) != PCI_CAP_EINVAL16)
		PCI_CAP_PUT16(config_handle, PCI_CAP_ID_PCI_E, cap_ptr,
			PCIE_DEVSTS, device_sts & (~PCIE_DEVSTS_CE_DETECTED));

	/* Enable CE reporting */
	device_ctl = PCI_CAP_GET16(config_handle, NULL, cap_ptr, PCIE_DEVCTL);
	PCI_CAP_PUT16(config_handle, NULL, cap_ptr, PCIE_DEVCTL,
		(device_ctl & (~PCIE_DEVCTL_ERR_MASK)) | pcie_base_err_default);
	PCIE_DBG("%s%d: devctl 0x%x -> 0x%x\n", ddi_node_name(dip),
		ddi_get_instance(dip), device_ctl,
		PCI_CAP_GET16(config_handle, NULL, cap_ptr, PCIE_DEVCTL));
	return (DDI_SUCCESS);
}

/* ARGSUSED */
void
pcie_disable_errors(dev_info_t *dip, ddi_acc_handle_t config_handle)
{
	uint16_t		cap_ptr, aer_ptr, dev_type, device_ctl;
	uint32_t		aer_reg;
	int			rval = DDI_FAILURE;

	if ((PCI_CAP_LOCATE(config_handle, PCI_CAP_ID_PCI_E, &cap_ptr))
			== DDI_FAILURE)
		return;

	rval = PCI_CAP_LOCATE(config_handle, PCI_CAP_XCFG_SPC
		(PCIE_EXT_CAP_ID_AER), &aer_ptr);
	dev_type = PCI_CAP_GET16(config_handle, NULL, cap_ptr,
		PCIE_PCIECAP) & PCIE_PCIECAP_DEV_TYPE_MASK;

	/*
	 * Disable PCI-Express Baseline Error Handling
	 */
	device_ctl = PCI_CAP_GET16(config_handle, NULL, cap_ptr, PCIE_DEVCTL);
	device_ctl &= ~PCIE_DEVCTL_ERR_MASK;
	PCI_CAP_PUT16(config_handle, NULL, cap_ptr, PCIE_DEVCTL, device_ctl);

	/*
	 * Disable PCI-Express Advanced Error Handling if Exists
	 */
	if (rval == DDI_FAILURE) {
		return;
	}

	/* Disable Uncorrectable errors */
	PCI_XCAP_PUT32(config_handle, NULL, aer_ptr, PCIE_AER_UCE_MASK,
		PCIE_AER_UCE_BITS);

	/* Disable Correctable errors */
	PCI_XCAP_PUT32(config_handle, NULL, aer_ptr, PCIE_AER_CE_MASK,
		PCIE_AER_CE_BITS);

	/* Disable ECRC generation and checking */
	if ((aer_reg = PCI_XCAP_GET32(config_handle, NULL, aer_ptr,
	    PCIE_AER_CTL)) != PCI_CAP_EINVAL32) {
		aer_reg &= ~(PCIE_AER_CTL_ECRC_GEN_ENA |
		    PCIE_AER_CTL_ECRC_CHECK_ENA);

		PCI_XCAP_PUT32(config_handle, NULL, aer_ptr, PCIE_AER_CTL,
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
	PCI_XCAP_PUT32(config_handle, NULL, aer_ptr, PCIE_AER_SUCE_MASK,
		PCIE_AER_SUCE_BITS);
}

static int
pcie_get_bdf_from_dip(dev_info_t *dip, uint32_t *bdf)
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

#ifdef	DEBUG
/*
 * This is a temporary stop gap measure.
 * PX runs at PIL 14, which is higher than the clock's PIL.
 * As a results we cannot safely print while servicing interrupts using
 * cmn_err or prom_printf.
 *
 * For debugging purposes set px_dbg_print != 0 to see printf messages
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
