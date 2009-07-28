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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* SPARC specific code used by the pcieb driver */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/kmem.h>
#include <sys/sysmacros.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/pcie.h>
#include <sys/pci_cap.h>
#include <sys/pcie_impl.h>
#include <io/pciex/pcieb.h>
#include "pcieb_plx.h"

/*LINTLIBRARY*/

/* PLX specific functions */
#ifdef	PX_PLX
static void plx_ro_disable(pcieb_devstate_t *pcieb);
#ifdef	PRINT_PLX_SEEPROM_CRC
static void pcieb_print_plx_seeprom_crc_data(pcieb_devstate_t *pcieb_p);
#endif /* PRINT_PLX_SEEPROM_CRC */
#endif /* PX_PLX */

int
pcieb_plat_peekpoke(dev_info_t *dip, dev_info_t *rdip, ddi_ctl_enum_t ctlop,
    void *arg, void *result)
{
	return (ddi_ctlops(dip, rdip, ctlop, arg, result));
}

/*ARGSUSED*/
void
pcieb_plat_attach_workaround(dev_info_t *dip)
{
}

int
pcieb_plat_intr_ops(dev_info_t *dip, dev_info_t *rdip, ddi_intr_op_t intr_op,
    ddi_intr_handle_impl_t *hdlp, void *result)
{
	dev_info_t	*cdip = rdip;
	pci_regspec_t	*pci_rp;
	int		reglen, len;
	uint32_t	d, intr;

	if ((intr_op == DDI_INTROP_SUPPORTED_TYPES) ||
	    (hdlp->ih_type != DDI_INTR_TYPE_FIXED))
		goto done;

	/*
	 * If the interrupt-map property is defined at this
	 * node, it will have performed the interrupt
	 * translation as part of the property, so no
	 * rotation needs to be done.
	 */
	if (ddi_getproplen(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS,
	    "interrupt-map", &len) == DDI_PROP_SUCCESS)
		goto done;

	cdip = pcie_get_my_childs_dip(dip, rdip);

	/*
	 * Use the devices reg property to determine its
	 * PCI bus number and device number.
	 */
	if (ddi_getlongprop(DDI_DEV_T_ANY, cdip, DDI_PROP_DONTPASS,
	    "reg", (caddr_t)&pci_rp, &reglen) != DDI_SUCCESS)
		return (DDI_FAILURE);

	intr = hdlp->ih_vector;

	/* spin the interrupt */
	d = PCI_REG_DEV_G(pci_rp[0].pci_phys_hi);
	if ((intr >= PCI_INTA) && (intr <= PCI_INTD))
		hdlp->ih_vector = ((intr - 1 + (d % 4)) % 4 + 1);
	else
		cmn_err(CE_WARN, "%s%d: %s: PCI intr=%x out of range",
		    ddi_driver_name(rdip), ddi_get_instance(rdip),
		    ddi_driver_name(dip), intr);

	kmem_free(pci_rp, reglen);

done:
	/* Pass up the request to our parent. */
	return (i_ddi_intr_ops(dip, rdip, intr_op, hdlp, result));
}

int
pcieb_plat_pcishpc_probe(dev_info_t *dip, ddi_acc_handle_t config_handle)
{
	uint16_t cap_ptr;
	if ((PCI_CAP_LOCATE(config_handle, PCI_CAP_ID_PCI_HOTPLUG, &cap_ptr)) !=
	    DDI_FAILURE) {
		return (DDI_SUCCESS);
	}

	return (DDI_FAILURE);
}

/*
 *  Disable PM on PLX. For PLX Transitioning one port on this switch to
 *  low power causes links on other ports on the same station to die.
 *  Due to PLX erratum #34, we can't allow the downstream device go to
 *  non-D0 state.
 */
boolean_t
pcieb_plat_pwr_disable(dev_info_t *dip)
{
	uint16_t vendor_id = (PCIE_DIP2UPBUS(dip)->bus_dev_ven_id) & 0xFFFF;
	return (IS_PLX_VENDORID(vendor_id) ? B_TRUE : B_FALSE);
}

/*ARGSUSED*/
boolean_t
pcieb_plat_msi_supported(dev_info_t *dip)
{
	return (B_TRUE);
}

/*ARGSUSED*/
void
pcieb_plat_intr_attach(pcieb_devstate_t *pcieb)
{
}

/*ARGSUSED*/
int
pcieb_plat_ctlops(dev_info_t *rdip, ddi_ctl_enum_t ctlop, void *arg)
{
	return (DDI_SUCCESS);
}

/*ARGSUSED*/
void
pcieb_plat_ioctl_hotplug(dev_info_t *dip, int rv, int cmd)
{
}

void
pcieb_plat_initchild(dev_info_t *child)
{
	intptr_t ppd = NULL;
	/*
	 * XXX set ppd to 1 to disable iommu BDF protection on SPARC.
	 * It relies on unused parent private data for PCI devices.
	 */
	if (ddi_prop_exists(DDI_DEV_T_NONE, child, DDI_PROP_DONTPASS,
	    "dvma-share"))
		ppd = 1;

	ddi_set_parent_data(child, (void *)ppd);
}

void
pcieb_plat_uninitchild(dev_info_t *child)
{
	/*
	 * XXX Clear parent private data used as a flag to disable
	 * iommu BDF protection
	 */
	if ((intptr_t)ddi_get_parent_data(child) == 1)
		ddi_set_parent_data(child, NULL);
}

#ifdef PX_PLX
/*
 * These are PLX specific workarounds needed during attach.
 */
void
pcieb_attach_plx_workarounds(pcieb_devstate_t *pcieb)
{
	dev_info_t	*dip = pcieb->pcieb_dip;
	pcie_bus_t	*bus_p = PCIE_DIP2BUS(dip);
	ddi_acc_handle_t	config_handle = bus_p->bus_cfg_hdl;
	uint_t		bus_num, primary, secondary;
	uint8_t		dev_type = bus_p->bus_dev_type;
	uint16_t	vendor_id = bus_p->bus_dev_ven_id & 0xFFFF;

	if (!IS_PLX_VENDORID(vendor_id))
		return;

	/*
	 * Due to a PLX HW bug we need to disable the receiver error CE on all
	 * ports. To this end we create a property "pcie_ce_mask" with value
	 * set to PCIE_AER_CE_RECEIVER_ERR. The pcie module will check for this
	 * property before setting the AER CE mask.
	 */
	(void) ddi_prop_update_int(DDI_DEV_T_NONE, dip,
	    "pcie_ce_mask", PCIE_AER_CE_RECEIVER_ERR);

	/*
	 * There is a bug in the PLX 8114 bridge, such that an 8-bit
	 * write to the secondary bus number register will corrupt an
	 * internal shadow copy of the primary bus number.  Reading
	 * out the registers and writing the same values back as
	 * 16-bits resolves the problem.  This bug was reported by
	 * PLX as errata #19.
	 */
	primary = pci_config_get8(config_handle, PCI_BCNF_PRIBUS);
	secondary = pci_config_get8(config_handle, PCI_BCNF_SECBUS);
	bus_num = (secondary << 8) | primary;
	pci_config_put16(config_handle, PCI_BCNF_PRIBUS, bus_num);

	/*
	 * Workaround for a race condition between hotplug
	 * initialization and actual MSI interrupt registration
	 * for hotplug functionality. The hotplug initialization
	 * generates an INTx interrupt for hotplug events and this
	 * INTx interrupt may interfere with shared leaf drivers
	 * using same INTx interrupt, which may eventually block
	 * the leaf drivers.
	 */
	if ((dev_type == PCIE_PCIECAP_DEV_TYPE_DOWN) ||
	    (dev_type == PCIE_PCIECAP_DEV_TYPE_ROOT) ||
	    (dev_type == PCIE_PCIECAP_DEV_TYPE_PCIE2PCI) ||
	    (dev_type == PCIE_PCIECAP_DEV_TYPE_PCI2PCIE)) {
		pci_config_put16(config_handle, PCI_CONF_COMM,
		    pci_config_get16(config_handle, PCI_CONF_COMM) |
		    PCI_COMM_INTX_DISABLE);
	}

	/*
	 * Disable PLX Special Relaxed Ordering
	 */
	plx_ro_disable(pcieb);

#ifdef	PRINT_PLX_SEEPROM_CRC
	/* check seeprom CRC to ensure the platform config is right */
	(void) pcieb_print_plx_seeprom_crc_data(pcieb);
#endif /* PRINT_PLX_SEEPROM_CRC */
}

/*
 * These are PLX specific workarounds called during child's initchild.
 */
int
pcieb_init_plx_workarounds(pcieb_devstate_t *pcieb, dev_info_t *child)
{
	int		i;
	int		result = DDI_FAILURE;
	uint16_t	reg = 0;
	ddi_acc_handle_t	config_handle;
	uint16_t	vendor_id =
	    (PCIE_DIP2UPBUS(pcieb->pcieb_dip))->bus_dev_ven_id & 0xFFFF;

	if (!IS_PLX_VENDORID(vendor_id))
		return (DDI_SUCCESS);

	/*
	 * Due to a PLX HW bug, a SW workaround to prevent the chip from
	 * wedging is needed.  SW just needs to tranfer 64 TLPs from
	 * the downstream port to the child device.
	 * The most benign way of doing this is to read the ID register
	 * 64 times.  This SW workaround should have minimum performance
	 * impact and shouldn't cause a problem for all other bridges
	 * and switches.
	 *
	 * The code needs to be written in a way to make sure it isn't
	 * optimized out.
	 */
	if (!pxb_tlp_count) {
		result = DDI_SUCCESS;
		goto done;
	}

	if (pci_config_setup(child, &config_handle) != DDI_SUCCESS) {
		result = DDI_FAILURE;
		goto done;
	}

	for (i = 0; i < pxb_tlp_count; i += 1)
		reg |= pci_config_get16(config_handle, PCI_CONF_VENID);

	if (PCIE_IS_PCIE_BDG(PCIE_DIP2BUS(pcieb->pcieb_dip)))
		pcieb_set_pci_perf_parameters(child, config_handle);

	pci_config_teardown(&config_handle);
	result = DDI_SUCCESS;
done:
	return (result);
}

/*
 * Disable PLX specific relaxed ordering mode.	Due to PLX
 * erratum #6, use of this mode with Cut-Through Cancellation
 * can result in dropped Completion type packets.
 *
 * Clear the Relaxed Ordering Mode on 8533 and 8548 switches.
 * To disable RO, clear bit 5 in offset 0x664, an undocumented
 * bit in the PLX spec, on Ports 0, 8 and 12.  Proprietary PLX
 * registers are normally accessible only via memspace from Port
 * 0.  If port 0 is attached go ahead and disable RO on Port 0,
 * 8 and 12, if they exist.
 */
static void
plx_ro_disable(pcieb_devstate_t *pcieb)
{
	pcie_bus_t		*bus_p = PCIE_DIP2BUS(pcieb->pcieb_dip);
	dev_info_t		*dip = pcieb->pcieb_dip;
	uint16_t		device_id = bus_p->bus_dev_ven_id >> 16;
	pci_regspec_t		*reg_spec, *addr_spec;
	int			rlen, alen;
	int			orig_rsize, new_rsize;
	uint_t			rnum, anum;
	ddi_device_acc_attr_t	attr;
	ddi_acc_handle_t	hdl;
	caddr_t			regsp;
	uint32_t		val, port_enable;
	char			*offset;
	char			*port_offset;

	if (!((device_id == PXB_DEVICE_PLX_8533) ||
	    (device_id == PXB_DEVICE_PLX_8548)))
		return;

	/* You can also only do this on Port 0 */
	val = PCIE_CAP_GET(32, bus_p, PCIE_LINKCAP);
	val = (val >> PCIE_LINKCAP_PORT_NUMBER_SHIFT) &
	    PCIE_LINKCAP_PORT_NUMBER_MASK;

	PCIEB_DEBUG(DBG_ATTACH, dip, "PLX RO Disable : bdf=0x%x port=%d\n",
	    bus_p->bus_bdf, val);

	if (val != 0)
		return;

	/*
	 * Read the reg property, but allocate extra space incase we need to add
	 * a new entry later.
	 */
	if (ddi_getproplen(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS, "reg",
	    &orig_rsize) != DDI_SUCCESS)
		return;

	new_rsize = orig_rsize + sizeof (pci_regspec_t);
	reg_spec = kmem_alloc(new_rsize, KM_SLEEP);

	if (ddi_getlongprop_buf(DDI_DEV_T_ANY, dip, DDI_PROP_DONTPASS, "reg",
	    (caddr_t)reg_spec, &orig_rsize) != DDI_SUCCESS)
		goto fail;

	/* Find the mem32 reg property */
	rlen = orig_rsize / sizeof (pci_regspec_t);
	for (rnum = 0; rnum < rlen; rnum++) {
		if ((reg_spec[rnum].pci_phys_hi & PCI_ADDR_MASK) ==
		    PCI_ADDR_MEM32)
			goto fix;
	}

	/*
	 * Mem32 reg property was not found.
	 * Look for it in assign-address property.
	 */
	addr_spec = bus_p->bus_assigned_addr;
	alen = bus_p->bus_assigned_entries;
	for (anum = 0; anum < alen; anum++) {
		if ((addr_spec[anum].pci_phys_hi & PCI_ADDR_MASK) ==
		    PCI_ADDR_MEM32)
			goto update;
	}

	/* Unable to find mem space assigned address, give up. */
	goto fail;

update:
	/*
	 * Add the mem32 access to the reg spec.
	 * Use the last entry which was previously allocated.
	 */
	reg_spec[rnum].pci_phys_hi = (addr_spec[anum].pci_phys_hi &
	    ~PCI_REG_REL_M);
	reg_spec[rnum].pci_phys_mid = 0;
	reg_spec[rnum].pci_phys_low = 0;
	reg_spec[rnum].pci_size_hi = addr_spec[anum].pci_size_hi;
	reg_spec[rnum].pci_size_low = addr_spec[anum].pci_size_low;

	/* Create the new reg_spec data and update the property */
	if (ddi_prop_update_int_array(DDI_DEV_T_NONE, dip, "reg",
	    (int *)reg_spec, (new_rsize / sizeof (int))) != DDI_SUCCESS)
		goto fail;

fix:
	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_endian_flags  = DDI_STRUCTURE_LE_ACC;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	if (ddi_regs_map_setup(dip, rnum, &regsp, 0, 0, &attr,
	    &hdl) != DDI_SUCCESS)
		goto fail;

	/* Grab register which shows which ports are enabled */
	offset = (char *)regsp + PLX_INGRESS_PORT_ENABLE;
	port_enable = ddi_get32(hdl, (uint32_t *)offset);

	if ((port_enable == 0xFFFFFFFF) || (port_enable == 0))
		goto done;

	offset = (char *)regsp + PLX_INGRESS_CONTROL_SHADOW;

	/* Disable RO on Port 0 */
	port_offset = 0x0 + offset;
	val = ddi_get32(hdl, (uint32_t *)port_offset);
	if (val & PLX_RO_MODE_BIT)
		val ^= PLX_RO_MODE_BIT;
	ddi_put32(hdl, (uint32_t *)port_offset, val);

	/* Disable RO on Port 8, but make sure its enabled */
	if (!(port_enable & (1 << 8)))
		goto port12;

	port_offset = (8 * 0x1000) + offset;
	val = ddi_get32(hdl, (uint32_t *)port_offset);
	if (val & PLX_RO_MODE_BIT)
		val ^= PLX_RO_MODE_BIT;
	ddi_put32(hdl, (uint32_t *)port_offset, val);

port12:
	/* Disable RO on Port 12, but make sure it exists */
	if (!(port_enable & (1 << 12)))
		goto done;

	port_offset = (12 * 0x1000) + offset;
	val = ddi_get32(hdl, (uint32_t *)port_offset);
	if (val & PLX_RO_MODE_BIT)
		val ^= PLX_RO_MODE_BIT;
	ddi_put32(hdl, (uint32_t *)port_offset, val);

	goto done;

done:
	ddi_regs_map_free(&hdl);
fail:
	kmem_free(reg_spec, new_rsize);
}

#ifdef	PRINT_PLX_SEEPROM_CRC
static void
pcieb_print_plx_seeprom_crc_data(pcieb_devstate_t *pcieb_p)
{
	ddi_acc_handle_t h;
	dev_info_t *dip = pcieb_p->pcieb_dip;
	uint16_t vendorid = (PCIE_DIP2BUS(dip)->bus_dev_ven_id) & 0xFFFF;
	int nregs;
	caddr_t mp;
	off_t bar_size;
	ddi_device_acc_attr_t mattr = {
		DDI_DEVICE_ATTR_V0,
		DDI_STRUCTURE_LE_ACC,
		DDI_STRICTORDER_ACC
	};
	uint32_t addr_reg_off = 0x260, data_reg_off = 0x264, data = 0x6BE4;

	if (vendorid != PXB_VENDOR_PLX)
		return;
	if (ddi_dev_nregs(dip, &nregs) != DDI_SUCCESS)
		return;
	if (nregs < 2)	/* check for CONF entry only, no BARs */
		return;
	if (ddi_dev_regsize(dip, 1, &bar_size) != DDI_SUCCESS)
		return;
	if (ddi_regs_map_setup(dip, 1, (caddr_t *)&mp, 0, bar_size,
	    &mattr, &h) != DDI_SUCCESS)
		return;
	ddi_put32(h, (uint32_t *)((uchar_t *)mp + addr_reg_off), data);
	delay(drv_usectohz(1000000));
	printf("%s#%d: EEPROM StatusReg = %x, CRC = %x\n",
	    ddi_driver_name(dip), ddi_get_instance(dip),
	    ddi_get32(h, (uint32_t *)((uchar_t *)mp + addr_reg_off)),
	    ddi_get32(h, (uint32_t *)((uchar_t *)mp + data_reg_off)));
#ifdef PLX_HOT_RESET_DISABLE
	/* prevent hot reset from propogating downstream. */
	data = ddi_get32(h, (uint32_t *)((uchar_t *)mp + 0x1DC));
	ddi_put32(h, (uint32_t *)((uchar_t *)mp + 0x1DC), data | 0x80000);
	delay(drv_usectohz(1000000));
	printf("%s#%d: EEPROM 0x1DC prewrite=%x postwrite=%x\n",
	    ddi_driver_name(dip), ddi_get_instance(dip), data,
	    ddi_get32(h, (uint32_t *)((uchar_t *)mp + 0x1DC)));
#endif /* PLX_HOT_RESET_DISABLE */
	ddi_regs_map_free(&h);
}
#endif /* PRINT_PLX_SEEPROM_CRC */
#endif /* PX_PLX */
