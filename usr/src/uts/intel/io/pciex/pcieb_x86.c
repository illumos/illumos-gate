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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 * Copyright 2019 Joyent, Inc.
 */

/* x86 specific code used by the pcieb driver */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/pcie.h>
#include <sys/pci_cap.h>
#include <sys/pcie_impl.h>
#include <sys/pcie_acpi.h>
#include <sys/hotplug/hpctrl.h>
#include <io/pciex/pcieb.h>
#include <io/pciex/pcie_nb5000.h>

/* Flag to turn off intel error handling workarounds */
int pcieb_intel_workaround_disable = 0;

void
pcieb_peekpoke_cb(dev_info_t *dip, ddi_fm_error_t *derr)
{
	pf_eh_enter(PCIE_DIP2BUS(dip));
	(void) pf_scan_fabric(dip, derr, NULL);
	pf_eh_exit(PCIE_DIP2BUS(dip));
}

void
pcieb_set_prot_scan(dev_info_t *dip, ddi_acc_impl_t *hdlp)
{
	pcieb_devstate_t *pcieb = ddi_get_soft_state(pcieb_state,
	    ddi_get_instance(dip));

	hdlp->ahi_err_mutexp = &pcieb->pcieb_err_mutex;
	hdlp->ahi_peekpoke_mutexp = &pcieb->pcieb_peek_poke_mutex;
	hdlp->ahi_scan_dip = dip;
	hdlp->ahi_scan = pcieb_peekpoke_cb;
}

int
pcieb_plat_peekpoke(dev_info_t *dip, dev_info_t *rdip, ddi_ctl_enum_t ctlop,
    void *arg, void *result)
{
	pcieb_devstate_t *pcieb = ddi_get_soft_state(pcieb_state,
	    ddi_get_instance(dip));

	if (!PCIE_IS_RP(PCIE_DIP2BUS(dip)))
		return (ddi_ctlops(dip, rdip, ctlop, arg, result));

	return (pci_peekpoke_check(dip, rdip, ctlop, arg, result,
	    ddi_ctlops, &pcieb->pcieb_err_mutex,
	    &pcieb->pcieb_peek_poke_mutex,
	    pcieb_peekpoke_cb));
}

/* x86 specific workarounds needed at the end of pcieb attach */
void
pcieb_plat_attach_workaround(dev_info_t *dip)
{
	/* Must apply workaround only after all initialization is done */
	pcieb_intel_error_workaround(dip);
	pcieb_intel_mps_workaround(dip);

}

/* Workarounds to enable error handling on certain Intel chipsets */
void
pcieb_intel_error_workaround(dev_info_t *dip)
{
	pcieb_devstate_t *pcieb = ddi_get_soft_state(pcieb_state,
	    ddi_get_instance(dip));

	pcieb_intel_serr_workaround(dip, pcieb->pcieb_no_aer_msi);
	pcieb_intel_rber_workaround(dip);
	pcieb_intel_sw_workaround(dip);
}

int
pcieb_plat_intr_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	return (i_ddi_intr_ops(dip, rdip, intr_op, hdlp, result));
}

/* shpc is not supported on x86 */
/*ARGSUSED*/
int
pcieb_plat_pcishpc_probe(dev_info_t *dip, ddi_acc_handle_t config_handle)
{
	return (DDI_FAILURE);
}

/*
 * Dummy functions to get around the fact that there's no shpc module on x86
 * today
 */
/*ARGSUSED*/
int
pcishpc_init(dev_info_t *dip)
{
	return (DDI_FAILURE);
}

/*ARGSUSED*/
int
pcishpc_uninit(dev_info_t *dip)
{
	return (DDI_FAILURE);
}

/*ARGSUSED*/
int
pcishpc_intr(dev_info_t *dip)
{
	return (DDI_INTR_UNCLAIMED);
}

/*ARGSUSED*/
boolean_t
pcieb_plat_pwr_disable(dev_info_t *dip)
{
	/* Always disable on x86 */
	return (B_TRUE);
}

boolean_t
pcieb_plat_msi_supported(dev_info_t *dip)
{
	pcie_bus_t *bus_p = PCIE_DIP2UPBUS(dip);
	uint16_t vendor_id, device_id;
	vendor_id = bus_p->bus_dev_ven_id & 0xFFFF;
	device_id = bus_p->bus_dev_ven_id >> 16;

	/*
	 * Intel ESB2 switches have a errata which prevents using MSIs
	 * for hotplug.
	 */
	return (((vendor_id == INTEL_VENDOR_ID) &&
	    INTEL_ESB2_SW_PCIE_DEV_ID(device_id)) ? B_FALSE : B_TRUE);
}

void
pcieb_plat_intr_attach(pcieb_devstate_t *pcieb)
{
	/*
	 *  _OSC initialization needs to be done before interrupts are
	 *  initialized.
	 */
	pcieb_init_osc(pcieb->pcieb_dip);
}

void
pcieb_plat_initchild(dev_info_t *child)
{
	struct ddi_parent_private_data *pdptr;
	if (ddi_getprop(DDI_DEV_T_NONE, child, DDI_PROP_DONTPASS, "interrupts",
	    -1) != -1) {
		pdptr = kmem_zalloc((sizeof (struct ddi_parent_private_data) +
		    sizeof (struct intrspec)), KM_SLEEP);
		pdptr->par_intr = (struct intrspec *)(pdptr + 1);
		pdptr->par_nintr = 1;
		ddi_set_parent_data(child, pdptr);
	} else
		ddi_set_parent_data(child, NULL);
}

void
pcieb_plat_uninitchild(dev_info_t *child)
{
	struct ddi_parent_private_data	*pdptr;

	if ((pdptr = ddi_get_parent_data(child)) != NULL)
		kmem_free(pdptr, (sizeof (*pdptr) + sizeof (struct intrspec)));

	ddi_set_parent_data(child, NULL);
}

/* _OSC related */
void
pcieb_init_osc(dev_info_t *devi)
{
	pcie_bus_t	*bus_p = PCIE_DIP2UPBUS(devi);
	uint32_t	osc_flags = OSC_CONTROL_PCIE_ADV_ERR;

	/*
	 * Call _OSC method for 2 reasons:
	 * 1. Hotplug: To determine if it is native or ACPI mode.
	 *
	 * 2. Error handling: Inform firmware that OS can support AER error
	 * handling. Currently we don't care for what the BIOS response was
	 * and instead setup interrupts for error handling as if it were
	 * supported.
	 *
	 * For hotpluggable slots the _OSC method has already been called as
	 * part of the hotplug initialization.
	 * For non-hotpluggable slots we need to call the _OSC method only for
	 * Root Ports (for AER support).
	 */
	if (!pcie_is_osc(devi) && PCIE_IS_RP(bus_p) && PCIE_HAS_AER(bus_p))
		(void) pcie_acpi_osc(devi, &osc_flags);
}

/*
 * Intel chip specific workarounds. Right now they're limited to the 5000, 5400
 * and 7300 series chipsets.
 */
typedef struct x86_error_reg {
	uint32_t	offset;
	uint_t		size;
	uint32_t	mask;
	uint32_t	value1;	/* Value for MSI case */
	uint32_t	value2; /* Value for machinecheck case */
} x86_error_reg_t;

typedef struct x86_error_tbl {
	uint16_t	vendor_id;
	uint16_t	device_id_low;
	uint16_t	device_id_high;
	uint8_t		rev_id_low;
	uint8_t		rev_id_high;
	x86_error_reg_t	*error_regs;
	int		error_regs_len;
} x86_error_tbl_t;

/*
 * Chipset and device specific settings that are required for error handling
 * (reporting, fowarding, and response at the RC) beyond the standard
 * registers in the PCIE and AER caps.
 *
 * The Northbridge Root Port settings also apply to the ESI port.  The ESI
 * port is a special leaf device but functions like a root port connected
 * to the Southbridge and receives all the onboard Southbridge errors
 * including those from Southbridge Root Ports.  However, this does not
 * include the Southbridge Switch Ports which act like normal switch ports
 * and is connected to the Northbridge through a separate link.
 *
 * PCIE errors from the ESB2 Southbridge RPs are simply fowarded to the ESI
 * port on the Northbridge.
 *
 * If MSIs don't work we want UEs (Fatal and Non-Fatal) to panic the system,
 * except for URs.  We do this by having the Root Ports respond with a System
 * Error and having that trigger a Machine Check (MCE).
 */

/*
 * 7300 Northbridge Root Ports
 */
static x86_error_reg_t intel_7300_rp_regs[] = {
	/* Command Register - Enable SERR */
	{0x4,   16, 0xFFFF,	0x0,	PCI_COMM_SERR_ENABLE},

	/* Root Control Register - SERR on NFE/FE */
	{0x88,  16, 0x0,	0x0,	PCIE_ROOTCTL_SYS_ERR_ON_NFE_EN |
					PCIE_ROOTCTL_SYS_ERR_ON_FE_EN},

	/* AER UE Mask - Mask UR */
	{0x108, 32, 0x0, PCIE_AER_UCE_UR, PCIE_AER_UCE_UR},

	/* PEXCTRL[21] check for certain malformed TLP types and MSI enable */
	{0x48,	32, 0xFFFFFFFF, 0xC0200000, 0x200000},
	/* PEXCTRL3[7]. MSI RAS error enable */
	{0x4D,	32, 0xFFFFFFFF, 0x1, 0x0},

	/* PEX_ERR_DOCMD[7:0] */
	{0x144,	8,  0x0,	0x0,	0xF0},

	/* EMASK_UNCOR_PEX[21:0] UE mask */
	{0x148,	32, 0x0, PCIE_AER_UCE_UR, PCIE_AER_UCE_UR},

	/* EMASK_RP_PEX[2:0] FE, UE, CE message detect mask */
	{0x150,	8,  0x0,	0x0,	0x1},
};
#define	INTEL_7300_RP_REGS_LEN \
	(sizeof (intel_7300_rp_regs) / sizeof (x86_error_reg_t))

/*
 * 5000 Northbridge Root Ports
 */
static x86_error_reg_t intel_5000_rp_regs[] = {
	/* Command Register - Enable SERR */
	{0x4,   16, 0xFFFF,	PCI_COMM_SERR_ENABLE,	PCI_COMM_SERR_ENABLE},

	/* Root Control Register - SERR on NFE/FE/CE */
	{0x88,  16, 0x0,	PCIE_ROOTCTL_SYS_ERR_ON_NFE_EN |
				PCIE_ROOTCTL_SYS_ERR_ON_FE_EN |
				PCIE_ROOTCTL_SYS_ERR_ON_CE_EN,
				PCIE_ROOTCTL_SYS_ERR_ON_NFE_EN |
				PCIE_ROOTCTL_SYS_ERR_ON_FE_EN},

	/* AER UE Mask - Mask UR */
	{0x108, 32, 0x0,	PCIE_AER_UCE_UR,	PCIE_AER_UCE_UR},

	/* PEXCTRL[21] check for certain malformed TLP type */
	{0x48,	32, 0xFFFFFFFF, 0xC0200000, 0x200000},
	/* PEXCTRL3[7]. MSI RAS error enable. */
	{0x4D,	32, 0xFFFFFFFF,	0x1,	0x0},

	/* PEX_ERR_DOCMD[7:0] */
	{0x144,	8,  0x0,	0x0,	0xF0},

	/* EMASK_UNCOR_PEX[21:0] UE mask */
	{0x148,	32, 0x0,	PCIE_AER_UCE_UR,	PCIE_AER_UCE_UR},

	/* EMASK_RP_PEX[2:0] FE, UE, CE message detect mask */
	{0x150,	8,  0x0,	0x0,	0x1},
};
#define	INTEL_5000_RP_REGS_LEN \
	(sizeof (intel_5000_rp_regs) / sizeof (x86_error_reg_t))

/*
 * 5400 Northbridge Root Ports.
 */
static x86_error_reg_t intel_5400_rp_regs[] = {
	/* Command Register - Enable SERR */
	{0x4,   16, 0xFFFF,	PCI_COMM_SERR_ENABLE, PCI_COMM_SERR_ENABLE},

	/* Root Control Register - SERR on NFE/FE */
	{0x88,  16, 0x0, PCIE_ROOTCTL_SYS_ERR_ON_NFE_EN |
			    PCIE_ROOTCTL_SYS_ERR_ON_FE_EN |
			    PCIE_ROOTCTL_SYS_ERR_ON_CE_EN,
			    PCIE_ROOTCTL_SYS_ERR_ON_NFE_EN |
			    PCIE_ROOTCTL_SYS_ERR_ON_FE_EN},

	/* AER UE Mask - Mask UR */
	{0x108, 32, 0x0,	PCIE_AER_UCE_UR,	PCIE_AER_UCE_UR},

	/* PEXCTRL[21] check for certain malformed TLP types */
	{0x48,	32, 0xFFFFFFFF,	0xC0200000, 0x200000},
	/* PEXCTRL3. MSI RAS error enable. */
	{0x4E,	8, 0x0,	0x1,	0x0},

	/* PEX_ERR_DOCMD[11:0] */
	{0x144,	16,  0x0,	0x0,	0xFF0},

	/* PEX_ERR_PIN_MASK[4:0] do not mask ERR[2:0] pins used by DOCMD */
	{0x146,	16,  0x0,	0x10,	0x10},

	/* EMASK_UNCOR_PEX[21:0] UE mask */
	{0x148,	32, 0x0,	PCIE_AER_UCE_UR,	PCIE_AER_UCE_UR},

	/* EMASK_RP_PEX[2:0] FE, UE, CE message detect mask */
	{0x150,	8,  0x0,	0x0,	0x1},
};
#define	INTEL_5400_RP_REGS_LEN \
	(sizeof (intel_5400_rp_regs) / sizeof (x86_error_reg_t))


/*
 * ESB2 Southbridge Root Ports
 */
static x86_error_reg_t intel_esb2_rp_regs[] = {
	/* Command Register - Enable SERR */
	{0x4,   16, 0xFFFF,	PCI_COMM_SERR_ENABLE,	PCI_COMM_SERR_ENABLE},

	/* Root Control Register - SERR on NFE/FE */
	{0x5c,  16, 0x0,	PCIE_ROOTCTL_SYS_ERR_ON_NFE_EN |
				PCIE_ROOTCTL_SYS_ERR_ON_FE_EN |
				PCIE_ROOTCTL_SYS_ERR_ON_CE_EN,
				PCIE_ROOTCTL_SYS_ERR_ON_NFE_EN |
				PCIE_ROOTCTL_SYS_ERR_ON_FE_EN},

	/* UEM[20:0] UE mask (write-once) */
	{0x148, 32, 0x0,	PCIE_AER_UCE_UR,	PCIE_AER_UCE_UR},
};
#define	INTEL_ESB2_RP_REGS_LEN \
	(sizeof (intel_esb2_rp_regs) / sizeof (x86_error_reg_t))


/*
 * ESB2 Southbridge Switch Ports
 */
static x86_error_reg_t intel_esb2_sw_regs[] = {
	/* Command Register - Enable SERR */
	{0x4,   16, 0xFFFF,	PCI_COMM_SERR_ENABLE,	PCI_COMM_SERR_ENABLE},

	/* AER UE Mask - Mask UR */
	{0x108, 32, 0x0,	PCIE_AER_UCE_UR,	PCIE_AER_UCE_UR},
};
#define	INTEL_ESB2_SW_REGS_LEN \
	(sizeof (intel_esb2_sw_regs) / sizeof (x86_error_reg_t))


x86_error_tbl_t x86_error_init_tbl[] = {
	/* Intel 7300: 3600 = ESI, 3604-360A = NB root ports */
	{0x8086, 0x3600, 0x3600, 0x0, 0xFF,
		intel_7300_rp_regs, INTEL_7300_RP_REGS_LEN},
	{0x8086, 0x3604, 0x360A, 0x0, 0xFF,
		intel_7300_rp_regs, INTEL_7300_RP_REGS_LEN},

	/* Intel 5000: 25C0, 25D0, 25D4, 25D8 = ESI */
	{0x8086, 0x25C0, 0x25C0, 0x0, 0xFF,
		intel_5000_rp_regs, INTEL_5000_RP_REGS_LEN},
	{0x8086, 0x25D0, 0x25D0, 0x0, 0xFF,
		intel_5000_rp_regs, INTEL_5000_RP_REGS_LEN},
	{0x8086, 0x25D4, 0x25D4, 0x0, 0xFF,
		intel_5000_rp_regs, INTEL_5000_RP_REGS_LEN},
	{0x8086, 0x25D8, 0x25D8, 0x0, 0xFF,
		intel_5000_rp_regs, INTEL_5000_RP_REGS_LEN},

	/* Intel 5000: 25E2-25E7 and 25F7-25FA = NB root ports */
	{0x8086, 0x25E2, 0x25E7, 0x0, 0xFF,
		intel_5000_rp_regs, INTEL_5000_RP_REGS_LEN},
	{0x8086, 0x25F7, 0x25FA, 0x0, 0xFF,
		intel_5000_rp_regs, INTEL_5000_RP_REGS_LEN},

	/* Intel 5400: 4000-4001, 4003 = ESI and 4021-4029 = NB root ports */
	{0x8086, 0x4000, 0x4001, 0x0, 0xFF,
		intel_5400_rp_regs, INTEL_5400_RP_REGS_LEN},
	{0x8086, 0x4003, 0x4003, 0x0, 0xFF,
		intel_5400_rp_regs, INTEL_5400_RP_REGS_LEN},
	{0x8086, 0x4021, 0x4029, 0x0, 0xFF,
		intel_5400_rp_regs, INTEL_5400_RP_REGS_LEN},

	/* Intel 631xESB/632xESB aka ESB2: 2690-2697 = SB root ports */
	{0x8086, 0x2690, 0x2697, 0x0, 0xFF,
		intel_esb2_rp_regs, INTEL_ESB2_RP_REGS_LEN},

	/* Intel Switches on esb2: 3500-3503, 3510-351B */
	{0x8086, 0x3500, 0x3503, 0x0, 0xFF,
		intel_esb2_sw_regs, INTEL_ESB2_SW_REGS_LEN},
	{0x8086, 0x3510, 0x351B, 0x0, 0xFF,
		intel_esb2_sw_regs, INTEL_ESB2_SW_REGS_LEN},

	/* XXX Intel PCIe-PCIx on esb2: 350C */
};
static int x86_error_init_tbl_len =
	sizeof (x86_error_init_tbl) / sizeof (x86_error_tbl_t);

/*
 * The main goal of this workaround is to set chipset specific settings if
 * MSIs happen to be enabled on this device. Otherwise make the system
 * Machine Check/Panic if an UE is detected in the fabric.
 */
void
pcieb_intel_serr_workaround(dev_info_t *dip, boolean_t mcheck)
{
	uint16_t		vid, did;
	uint8_t			rid;
	int			i, j;
	x86_error_tbl_t		*tbl;
	x86_error_reg_t		*reg;
	pcie_bus_t		*bus_p = PCIE_DIP2UPBUS(dip);
	ddi_acc_handle_t	cfg_hdl = bus_p->bus_cfg_hdl;
	uint16_t		bdf = bus_p->bus_bdf;

	if (pcieb_intel_workaround_disable)
		return;

	vid = bus_p->bus_dev_ven_id & 0xFFFF;
	did = bus_p->bus_dev_ven_id >> 16;
	rid = bus_p->bus_rev_id;

	PCIEB_DEBUG(DBG_ATTACH, dip, "VID:0x%x DID:0x%x RID:0x%x bdf=0x%x\n",
	    vid, did, rid, bdf);

	tbl = x86_error_init_tbl;
	for (i = 0; i < x86_error_init_tbl_len; i++, tbl++) {
		if (!((vid == tbl->vendor_id) &&
		    (did >= tbl->device_id_low) &&
		    (did <= tbl->device_id_high) &&
		    (rid >= tbl->rev_id_low) &&
		    (rid <= tbl->rev_id_high)))
			continue;

		if (mcheck && PCIE_IS_RP(bus_p))
			pcie_set_rber_fatal(dip, B_TRUE);

		reg = tbl->error_regs;
		for (j = 0; j < tbl->error_regs_len; j++, reg++) {
			uint32_t data = 0xDEADBEEF;
			uint32_t value = 0xDEADBEEF;
			switch (reg->size) {
			case 32:
				data = (uint32_t)pci_config_get32(cfg_hdl,
				    reg->offset);
				value = (mcheck ?
				    ((data & reg->mask) | reg->value2) :
				    ((data & reg->mask) | reg->value1));
				pci_config_put32(cfg_hdl, reg->offset, value);
				value = (uint32_t)pci_config_get32(cfg_hdl,
				    reg->offset);
				break;
			case 16:
				data = (uint32_t)pci_config_get16(cfg_hdl,
				    reg->offset);
				value = (mcheck ?
				    ((data & reg->mask) | reg->value2) :
				    ((data & reg->mask) | reg->value1));
				pci_config_put16(cfg_hdl, reg->offset,
				    (uint16_t)value);
				value = (uint32_t)pci_config_get16(cfg_hdl,
				    reg->offset);
				break;
			case 8:
				data = (uint32_t)pci_config_get8(cfg_hdl,
				    reg->offset);
				value = (mcheck ?
				    ((data & reg->mask) | reg->value2) :
				    ((data & reg->mask) | reg->value1));
				pci_config_put8(cfg_hdl, reg->offset,
				    (uint8_t)value);
				value = (uint32_t)pci_config_get8(cfg_hdl,
				    reg->offset);
				break;
			}

			PCIEB_DEBUG(DBG_ATTACH, dip, "bdf:%x mcheck:%d size:%d "
			    "off:0x%x mask:0x%x value:0x%x + orig:0x%x -> "
			    "0x%x\n", bdf, mcheck, reg->size, reg->offset,
			    reg->mask, (mcheck ?  reg->value2 : reg->value1),
			    data, value);
		}
	}
}

/*
 * For devices that support Role Base Errors, make several UE have a FATAL
 * severity.  That way a Fatal Message will be sent instead of a Correctable
 * Message.  Without full FMA support, CEs will be ignored.
 */
uint32_t pcieb_rber_sev = (PCIE_AER_UCE_TRAINING | PCIE_AER_UCE_DLP |
    PCIE_AER_UCE_SD | PCIE_AER_UCE_PTLP | PCIE_AER_UCE_FCP | PCIE_AER_UCE_TO |
    PCIE_AER_UCE_CA | PCIE_AER_UCE_RO | PCIE_AER_UCE_MTLP | PCIE_AER_UCE_ECRC);

void
pcieb_intel_rber_workaround(dev_info_t *dip)
{
	uint32_t rber;
	pcie_bus_t *bus_p = PCIE_DIP2UPBUS(dip);

	if (pcieb_intel_workaround_disable)
		return;

	/*
	 * Check Root Port's machinecheck setting to determine if this
	 * workaround is needed or not.
	 */
	if (!pcie_get_rber_fatal(dip))
		return;

	if (!PCIE_IS_PCIE(bus_p) || !PCIE_HAS_AER(bus_p))
		return;

	rber = PCIE_CAP_GET(16, bus_p, PCIE_DEVCAP) &
	    PCIE_DEVCAP_ROLE_BASED_ERR_REP;
	if (!rber)
		return;

	(void) PCIE_AER_PUT(32, bus_p, PCIE_AER_UCE_SERV, pcieb_rber_sev);
}

/*
 * The Intel 5000 Chipset has an errata that requires read completion
 * coalescing to be disabled if the Max Payload Size is set to 256 bytes.
 */
void
pcieb_intel_mps_workaround(dev_info_t *dip)
{
	uint16_t		vid, did;
	uint32_t		pexctrl;
	pcie_bus_t		*bus_p = PCIE_DIP2UPBUS(dip);

	vid = bus_p->bus_dev_ven_id & 0xFFFF;
	did = bus_p->bus_dev_ven_id >> 16;

	if ((vid == INTEL_VENDOR_ID) && (INTEL_NB5000_PCIE_DEV_ID(did) ||
	    INTEL_NB5100_PCIE_DEV_ID(did))) {

		pexctrl = pci_config_get32(bus_p->bus_cfg_hdl,
		    INTEL_NB5000_PEXCTRL_OFFSET);
		/*
		 * Turn off coalescing (bit 10)
		 */
		pexctrl &= ~INTEL_NB5000_PEXCTRL_COALESCE_EN;

		pci_config_put32(bus_p->bus_cfg_hdl,
		    INTEL_NB5000_PEXCTRL_OFFSET, pexctrl);
	}
}

/*
 * Workaround for certain switches regardless of platform
 */
void
pcieb_intel_sw_workaround(dev_info_t *dip)
{
	uint16_t		vid, regw;
	pcie_bus_t		*bus_p = PCIE_DIP2UPBUS(dip);
	ddi_acc_handle_t	cfg_hdl = bus_p->bus_cfg_hdl;

	if (pcieb_intel_workaround_disable)
		return;

	if (!PCIE_IS_SW(PCIE_DIP2BUS(dip)))
		return;

	vid = bus_p->bus_dev_ven_id & 0xFFFF;
	/*
	 * Intel and PLX switches require SERR in CMD reg to foward error
	 * messages, though this is not PCIE spec-compliant behavior.
	 * To prevent the switches themselves from reporting errors on URs
	 * when the CMD reg has SERR enabled (which is expected according to
	 * the PCIE spec) we rely on masking URs in the AER cap.
	 */
	if (vid == 0x8086 || vid == 0x10B5) {
		regw = pci_config_get16(cfg_hdl, PCI_CONF_COMM);
		pci_config_put16(cfg_hdl, PCI_CONF_COMM,
		    regw | PCI_COMM_SERR_ENABLE);
	}
}

int
pcieb_plat_ctlops(dev_info_t *rdip, ddi_ctl_enum_t ctlop, void *arg)
{
	struct detachspec *ds;
	struct attachspec *as;

	switch (ctlop) {
	case DDI_CTLOPS_DETACH:
		ds = (struct detachspec *)arg;
		switch (ds->when) {
		case DDI_POST:
			if (ds->cmd == DDI_SUSPEND) {
				if (pci_post_suspend(rdip) != DDI_SUCCESS)
					return (DDI_FAILURE);
			}
			break;
		default:
			break;
		}
		break;
	case DDI_CTLOPS_ATTACH:
		as = (struct attachspec *)arg;
		switch (as->when) {
		case DDI_PRE:
			if (as->cmd == DDI_RESUME) {
				if (pci_pre_resume(rdip) != DDI_SUCCESS)
					return (DDI_FAILURE);
			}
			break;
		case DDI_POST:
			/*
			 * For leaf devices supporting RBER and AER, we
			 * need to apply this workaround on them after
			 * attach to be notified of UEs that would
			 * otherwise be ignored as CEs on Intel chipsets
			 * currently
			 */
			pcieb_intel_rber_workaround(rdip);
			break;
		default:
			break;
		}
		break;
	default:
		break;
	}

	return (DDI_SUCCESS);
}
