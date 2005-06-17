/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
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
#include <sys/pcie_impl.h>

static void 	pcie_enable_errors(dev_info_t *dip,
    ddi_acc_handle_t config_handle);
static void 	pcie_disable_errors(dev_info_t *dip,
    ddi_acc_handle_t config_handle);
static uint16_t pcie_find_cap_reg(ddi_acc_handle_t config_handle,
    uint8_t cap_id);
static uint16_t pcie_find_ext_cap_reg(ddi_acc_handle_t config_handle,
    uint16_t cap_id);

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
				PCIE_DEVCTL_UR_REPORTING_EN |
				PCIE_DEVCTL_RO_EN;
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
	uint16_t		command_reg;
	uint16_t		cap_ptr;

	if (pci_config_setup(cdip, &config_handle) != DDI_SUCCESS)
		return (DDI_FAILURE);

	/*
	 * Determine the configuration header type.
	 */
	header_type = pci_config_get8(config_handle, PCI_CONF_HEADER);
	PCIE_DBG("%s: header_type=%x\n", ddi_driver_name(cdip), header_type);

	/*
	 * Setup the device's command register
	 */
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
		bcr = pci_config_get8(config_handle, PCI_BCNF_BCNTRL);
		if (pcie_command_default & PCI_COMM_PARITY_DETECT)
			bcr |= PCI_BCNF_BCNTRL_PARITY_ENABLE;
		if (pcie_command_default & PCI_COMM_SERR_ENABLE)
			bcr |= PCI_BCNF_BCNTRL_SERR_ENABLE;
		bcr |= PCI_BCNF_BCNTRL_MAST_AB_MODE;
		pci_config_put8(config_handle, PCI_BCNF_BCNTRL, bcr);
	}

	cap_ptr = pcie_find_cap_reg(config_handle, PCI_CAP_ID_PCI_E);
	if (cap_ptr != PCI_CAP_NEXT_PTR_NULL)
		pcie_enable_errors(cdip, config_handle);

	return (DDI_SUCCESS);
fail:
	cmn_err(CE_WARN, "PCIE init child failed\n");
	return (DDI_FAILURE);
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

	if (pci_config_setup(cdip, &config_handle) != DDI_SUCCESS)
		return;

	pcie_disable_errors(cdip, config_handle);
}

static void
pcie_enable_errors(dev_info_t *dip, ddi_acc_handle_t config_handle)
{
	uint16_t		cap_ptr, aer_ptr;
	uint16_t		device_ctl, device_sts;
	uint16_t		dev_type;
	uint32_t		aer_reg;

	cap_ptr = pcie_find_cap_reg(config_handle, PCI_CAP_ID_PCI_E);
	if (cap_ptr != PCI_CAP_NEXT_PTR_NULL) {
		aer_ptr = pcie_find_ext_cap_reg(config_handle,
		    PCIE_EXT_CAP_ID_AER);
		dev_type = pci_config_get16(
			config_handle,
			cap_ptr + PCIE_PCIECAP) &
		    PCIE_PCIECAP_DEV_TYPE_MASK;
	} else {
		aer_ptr = PCIE_EXT_CAP_NEXT_PTR_NULL;
	}

	/*
	 * Clear any pending errors
	 */
	if (aer_ptr != PCIE_EXT_CAP_NEXT_PTR_NULL) {
		pci_config_put32(config_handle, aer_ptr + PCIE_AER_CE_STS, -1);
		pci_config_put32(config_handle, aer_ptr + PCIE_AER_UCE_STS, -1);
	}
	device_sts = pci_config_get16(config_handle,
	    cap_ptr + PCIE_DEVSTS);
	pci_config_put16(config_handle, cap_ptr + PCIE_DEVSTS,
	    device_sts);

	/*
	 * Enable PCI-Express Baseline Error Handling
	 */
	device_ctl = pci_config_get16(config_handle,
	    cap_ptr + PCIE_DEVCTL);
	pci_config_put16(config_handle, cap_ptr + PCIE_DEVCTL,
	    pcie_base_err_default);
	PCIE_DBG("%s: device control=0x%x->0x%x\n",
	    ddi_driver_name(dip), device_ctl,
	    pci_config_get16(config_handle, cap_ptr + PCIE_DEVCTL));

	/*
	 * Enable PCI-Express Advanced Error Handling if Exists
	 */
	if (aer_ptr == PCIE_EXT_CAP_NEXT_PTR_NULL) {
		return;
	}

	/* Enable Uncorrectable errors */
	aer_reg = pci_config_get32(config_handle, aer_ptr + PCIE_AER_UCE_MASK);
	pci_config_put32(config_handle, aer_ptr + PCIE_AER_UCE_MASK,
	    pcie_aer_uce_mask);
	PCIE_DBG("%s: AER UCE=0x%x->0x%x\n",
	    ddi_driver_name(dip), aer_reg,
	    pci_config_get32(config_handle, aer_ptr + PCIE_AER_UCE_MASK));

	/* Enable Correctable errors */
	aer_reg = pci_config_get32(config_handle, aer_ptr + PCIE_AER_CE_MASK);
	pci_config_put32(config_handle, aer_ptr + PCIE_AER_CE_MASK,
	    pcie_aer_ce_mask);
	PCIE_DBG("%s: AER CE=0x%x->0x%x\n",
	    ddi_driver_name(dip), aer_reg,
	    pci_config_get32(config_handle, aer_ptr + PCIE_AER_CE_MASK));

	/*
	 * Enable Secondary Uncorrectable errors if this is a bridge
	 */
	if (!(dev_type == PCIE_PCIECAP_DEV_TYPE_PCIE2PCI))
		return;

	/*
	 * Enable secondary bus errors
	 */
	aer_reg = pci_config_get32(config_handle, aer_ptr + PCIE_AER_SUCE_MASK);
	pci_config_put32(config_handle, aer_ptr + PCIE_AER_SUCE_MASK,
	    pcie_aer_suce_mask);
	PCIE_DBG("%s: AER SUCE=0x%x->0x%x\n",
	    ddi_driver_name(dip), aer_reg,
	    pci_config_get32(config_handle, aer_ptr + PCIE_AER_SUCE_MASK));
}

/* ARGSUSED */
static void
pcie_disable_errors(dev_info_t *dip, ddi_acc_handle_t config_handle)
{
	uint16_t		cap_ptr, aer_ptr;
	uint16_t		dev_type;

	cap_ptr = pcie_find_cap_reg(config_handle, PCI_CAP_ID_PCI_E);
	if (cap_ptr != PCI_CAP_NEXT_PTR_NULL) {
		aer_ptr = pcie_find_ext_cap_reg(config_handle,
		    PCIE_EXT_CAP_ID_AER);
		dev_type = pci_config_get16(
			config_handle,
			cap_ptr + PCIE_PCIECAP) &
		    PCIE_PCIECAP_DEV_TYPE_MASK;
	} else {
		aer_ptr = PCIE_EXT_CAP_NEXT_PTR_NULL;
	}

	/*
	 * Disable PCI-Express Baseline Error Handling
	 */
	pci_config_put16(config_handle, cap_ptr + PCIE_DEVCTL,
	    0x0);

	/*
	 * Disable PCI-Express Advanced Error Handling if Exists
	 */
	if (aer_ptr == PCIE_EXT_CAP_NEXT_PTR_NULL) {
		return;
	}

	/* Disable Uncorrectable errors */
	pci_config_put32(config_handle, aer_ptr + PCIE_AER_UCE_MASK,
	    PCIE_AER_UCE_BITS);

	/* Disable Correctable errors */
	pci_config_put32(config_handle, aer_ptr + PCIE_AER_CE_MASK,
	    PCIE_AER_CE_BITS);

	/*
	 * Disable Secondary Uncorrectable errors if this is a bridge
	 */
	if (!(dev_type == PCIE_PCIECAP_DEV_TYPE_PCIE2PCI))
		return;

	/*
	 * Disable secondary bus errors
	 */
	pci_config_put32(config_handle, aer_ptr + PCIE_AER_SUCE_MASK,
	    PCIE_AER_SUCE_BITS);
}

/*
 * Helper Function to traverse the pci-express config space looking
 * for the pci-express capability id pointer.
 *
 * @param config_handle	devices pci config space handler
 * @param cap_id	pci-express capability id function is looking for
 * @return		capability offset from base address or NULL if not
 *			found.
 */
static uint16_t
pcie_find_cap_reg(ddi_acc_handle_t config_handle, uint8_t cap_id)
{
	uint16_t	caps_ptr, cap;

	/*
	 * Check if capabilities list is supported.  If not then it is a PCI
	 * device.
	 */
	if (pci_config_get16(config_handle, PCI_CONF_STAT) & PCI_STAT_CAP) {
		caps_ptr = P2ALIGN(pci_config_get8(config_handle,
				PCI_CONF_CAP_PTR), 4);
	} else {
		caps_ptr = PCI_CAP_NEXT_PTR_NULL;
	}

	while (caps_ptr != PCI_CAP_NEXT_PTR_NULL) {
		if (caps_ptr < 0x40) {
			caps_ptr = PCI_CAP_NEXT_PTR_NULL;
			break;
		}

/* 		reg = pci_config_get32(config_handle, caps_ptr); */
/* 		cap = reg & 0xFF; */
		cap = pci_config_get8(config_handle, caps_ptr);

		if (cap == cap_id) {
			break;
		}

/* 		caps_ptr = (reg >> 8) & 0xFF; */
		caps_ptr = P2ALIGN(pci_config_get8(config_handle,
				(caps_ptr + PCI_CAP_NEXT_PTR)), 4);
	}

	return (caps_ptr);
}

/*
 * Helper Function to traverse the pci-express extended config space looking
 * for the pci-express capability id pointer.
 *
 * @param config_handle	devices pci config space handler
 * @param cap_id	pci-express capability id function is looking for
 * @return		capability offset from base address or NULL if not
 *			found.
 */
static uint16_t
pcie_find_ext_cap_reg(ddi_acc_handle_t config_handle, uint16_t cap_id)
{
	uint32_t	hdr, hdr_next_ptr, hdr_cap_id;
	uint16_t	offset = P2ALIGN(PCIE_EXT_CAP, 4);

	hdr = pci_config_get32(config_handle, offset);
	hdr_next_ptr = (hdr >> PCIE_EXT_CAP_NEXT_PTR_SHIFT) &
	    PCIE_EXT_CAP_NEXT_PTR_MASK;
	hdr_cap_id = (hdr >> PCIE_EXT_CAP_ID_SHIFT) &
	    PCIE_EXT_CAP_ID_MASK;

	while ((hdr_next_ptr != PCIE_EXT_CAP_NEXT_PTR_NULL) &&
	    (hdr_cap_id != cap_id)) {
		offset = P2ALIGN(hdr_next_ptr, 4);
		hdr = pci_config_get32(config_handle, offset);
		hdr_next_ptr = (hdr >> PCIE_EXT_CAP_NEXT_PTR_SHIFT) &
		    PCIE_EXT_CAP_NEXT_PTR_MASK;
		hdr_cap_id = (hdr >> PCIE_EXT_CAP_ID_SHIFT) &
		    PCIE_EXT_CAP_ID_MASK;
	}

	if (hdr_cap_id == cap_id)
		return (P2ALIGN(offset, 4));

	return (PCIE_EXT_CAP_NEXT_PTR_NULL);
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
