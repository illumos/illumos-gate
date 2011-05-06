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
 */

#include <sys/types.h>
#include <sys/sunndi.h>
#include <sys/sysmacros.h>
#include <sys/pci.h>
#include <sys/pcie.h>
#include <sys/pci_impl.h>
#include <sys/epm.h>

int	pci_enable_wakeup = 1;

int
pci_config_setup(dev_info_t *dip, ddi_acc_handle_t *handle)
{
	caddr_t	cfgaddr;
	ddi_device_acc_attr_t attr;

	attr.devacc_attr_version = DDI_DEVICE_ATTR_V0;
	attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;

	/* Check for fault management capabilities */
	if (DDI_FM_ACC_ERR_CAP(ddi_fm_capable(dip))) {
		attr.devacc_attr_version = DDI_DEVICE_ATTR_V1;
		attr.devacc_attr_access = DDI_FLAGERR_ACC;
	}

	return (ddi_regs_map_setup(dip, 0, &cfgaddr, 0, 0, &attr, handle));
}

void
pci_config_teardown(ddi_acc_handle_t *handle)
{
	ddi_regs_map_free(handle);
}

uint8_t
pci_config_get8(ddi_acc_handle_t handle, off_t offset)
{
	caddr_t	cfgaddr;
	ddi_acc_hdl_t *hp;

	hp = impl_acc_hdl_get(handle);
	cfgaddr = hp->ah_addr + offset;
	return (ddi_get8(handle, (uint8_t *)cfgaddr));
}

uint16_t
pci_config_get16(ddi_acc_handle_t handle, off_t offset)
{
	caddr_t	cfgaddr;
	ddi_acc_hdl_t *hp;

	hp = impl_acc_hdl_get(handle);
	cfgaddr = hp->ah_addr + offset;
	return (ddi_get16(handle, (uint16_t *)cfgaddr));
}

uint32_t
pci_config_get32(ddi_acc_handle_t handle, off_t offset)
{
	caddr_t	cfgaddr;
	ddi_acc_hdl_t *hp;

	hp = impl_acc_hdl_get(handle);
	cfgaddr = hp->ah_addr + offset;
	return (ddi_get32(handle, (uint32_t *)cfgaddr));
}

uint64_t
pci_config_get64(ddi_acc_handle_t handle, off_t offset)
{
	caddr_t	cfgaddr;
	ddi_acc_hdl_t *hp;

	hp = impl_acc_hdl_get(handle);
	cfgaddr = hp->ah_addr + offset;
	return (ddi_get64(handle, (uint64_t *)cfgaddr));
}

void
pci_config_put8(ddi_acc_handle_t handle, off_t offset, uint8_t value)
{
	caddr_t	cfgaddr;
	ddi_acc_hdl_t *hp;

	hp = impl_acc_hdl_get(handle);
	cfgaddr = hp->ah_addr + offset;
	ddi_put8(handle, (uint8_t *)cfgaddr, value);
}

void
pci_config_put16(ddi_acc_handle_t handle, off_t offset, uint16_t value)
{
	caddr_t	cfgaddr;
	ddi_acc_hdl_t *hp;

	hp = impl_acc_hdl_get(handle);
	cfgaddr = hp->ah_addr + offset;
	ddi_put16(handle, (uint16_t *)cfgaddr, value);
}

void
pci_config_put32(ddi_acc_handle_t handle, off_t offset, uint32_t value)
{
	caddr_t	cfgaddr;
	ddi_acc_hdl_t *hp;

	hp = impl_acc_hdl_get(handle);
	cfgaddr = hp->ah_addr + offset;
	ddi_put32(handle, (uint32_t *)cfgaddr, value);
}

void
pci_config_put64(ddi_acc_handle_t handle, off_t offset, uint64_t value)
{
	caddr_t	cfgaddr;
	ddi_acc_hdl_t *hp;

	hp = impl_acc_hdl_get(handle);
	cfgaddr = hp->ah_addr + offset;
	ddi_put64(handle, (uint64_t *)cfgaddr, value);
}

/*
 * We need to separate the old interfaces from the new ones and leave them
 * in here for a while. Previous versions of the OS defined the new interfaces
 * to the old interfaces. This way we can fix things up so that we can
 * eventually remove these interfaces.
 * e.g. A 3rd party module/driver using pci_config_get8 and built against S10
 * or earlier will actually have a reference to pci_config_getb in the binary.
 */
#ifdef _ILP32
uint8_t
pci_config_getb(ddi_acc_handle_t handle, off_t offset)
{
	caddr_t	cfgaddr;
	ddi_acc_hdl_t *hp;

	hp = impl_acc_hdl_get(handle);
	cfgaddr = hp->ah_addr + offset;
	return (ddi_get8(handle, (uint8_t *)cfgaddr));
}

uint16_t
pci_config_getw(ddi_acc_handle_t handle, off_t offset)
{
	caddr_t	cfgaddr;
	ddi_acc_hdl_t *hp;

	hp = impl_acc_hdl_get(handle);
	cfgaddr = hp->ah_addr + offset;
	return (ddi_get16(handle, (uint16_t *)cfgaddr));
}

uint32_t
pci_config_getl(ddi_acc_handle_t handle, off_t offset)
{
	caddr_t	cfgaddr;
	ddi_acc_hdl_t *hp;

	hp = impl_acc_hdl_get(handle);
	cfgaddr = hp->ah_addr + offset;
	return (ddi_get32(handle, (uint32_t *)cfgaddr));
}

uint64_t
pci_config_getll(ddi_acc_handle_t handle, off_t offset)
{
	caddr_t	cfgaddr;
	ddi_acc_hdl_t *hp;

	hp = impl_acc_hdl_get(handle);
	cfgaddr = hp->ah_addr + offset;
	return (ddi_get64(handle, (uint64_t *)cfgaddr));
}

void
pci_config_putb(ddi_acc_handle_t handle, off_t offset, uint8_t value)
{
	caddr_t	cfgaddr;
	ddi_acc_hdl_t *hp;

	hp = impl_acc_hdl_get(handle);
	cfgaddr = hp->ah_addr + offset;
	ddi_put8(handle, (uint8_t *)cfgaddr, value);
}

void
pci_config_putw(ddi_acc_handle_t handle, off_t offset, uint16_t value)
{
	caddr_t	cfgaddr;
	ddi_acc_hdl_t *hp;

	hp = impl_acc_hdl_get(handle);
	cfgaddr = hp->ah_addr + offset;
	ddi_put16(handle, (uint16_t *)cfgaddr, value);
}

void
pci_config_putl(ddi_acc_handle_t handle, off_t offset, uint32_t value)
{
	caddr_t	cfgaddr;
	ddi_acc_hdl_t *hp;

	hp = impl_acc_hdl_get(handle);
	cfgaddr = hp->ah_addr + offset;
	ddi_put32(handle, (uint32_t *)cfgaddr, value);
}

void
pci_config_putll(ddi_acc_handle_t handle, off_t offset, uint64_t value)
{
	caddr_t	cfgaddr;
	ddi_acc_hdl_t *hp;

	hp = impl_acc_hdl_get(handle);
	cfgaddr = hp->ah_addr + offset;
	ddi_put64(handle, (uint64_t *)cfgaddr, value);
}
#endif /* _ILP32 */

/*ARGSUSED*/
int
pci_report_pmcap(dev_info_t *dip, int cap, void *arg)
{
	return (DDI_SUCCESS);
}

/*
 * Note about saving and restoring config space.
 * PCI devices have only upto 256 bytes of config space while PCI Express
 * devices can have upto 4k config space. In case of PCI Express device,
 * we save all 4k config space and restore it even if it doesn't make use
 * of all 4k. But some devices don't respond to reads to non-existent
 * registers within the config space. To avoid any panics, we use ddi_peek
 * to do the reads. A bit mask is used to indicate which words of the
 * config space are accessible. While restoring the config space, only those
 * readable words are restored. We do all this in 32 bit size words.
 */
#define	INDEX_SHIFT		3
#define	BITMASK			0x7

static uint32_t pci_save_caps(ddi_acc_handle_t confhdl, uint32_t *regbuf,
    pci_cap_save_desc_t *cap_descp, uint32_t *ncapsp);
static void pci_restore_caps(ddi_acc_handle_t confhdl, uint32_t *regbuf,
    pci_cap_save_desc_t *cap_descp, uint32_t elements);
static uint32_t pci_generic_save(ddi_acc_handle_t confhdl, uint16_t cap_ptr,
    uint32_t *regbuf, uint32_t nwords);
static uint32_t pci_msi_save(ddi_acc_handle_t confhdl, uint16_t cap_ptr,
    uint32_t *regbuf, uint32_t notused);
static uint32_t pci_pcix_save(ddi_acc_handle_t confhdl, uint16_t cap_ptr,
    uint32_t *regbuf, uint32_t notused);
static uint32_t pci_pcie_save(ddi_acc_handle_t confhdl, uint16_t cap_ptr,
    uint32_t *regbuf, uint32_t notused);
static uint32_t pci_ht_addrmap_save(ddi_acc_handle_t confhdl, uint16_t cap_ptr,
    uint32_t *regbuf, uint32_t notused);
static uint32_t pci_ht_funcext_save(ddi_acc_handle_t confhdl, uint16_t cap_ptr,
    uint32_t *regbuf, uint32_t notused);
static void pci_fill_buf(ddi_acc_handle_t confhdl, uint16_t cap_ptr,
    uint32_t *regbuf, uint32_t nwords);
static uint32_t cap_walk_and_save(ddi_acc_handle_t confhdl, uint32_t *regbuf,
    pci_cap_save_desc_t *cap_descp, uint32_t *ncapsp, int xspace);
static void pci_pmcap_check(ddi_acc_handle_t confhdl, uint32_t *regbuf,
    uint16_t pmcap_offset);

/*
 * Table below specifies the number of registers to be saved for each PCI
 * capability. pci_generic_save saves the number of words specified in the
 * table. Any special considerations will be taken care by the capability
 * specific save function e.g. use pci_msi_save to save registers associated
 * with MSI capability. PCI_UNKNOWN_SIZE indicates that number of registers
 * to be saved is variable and will be determined by the specific save function.
 * Currently we save/restore all the registers associated with the capability
 * including read only registers. Regsiters are saved and restored in 32 bit
 * size words.
 */
static pci_cap_entry_t pci_cap_table[] = {
	{PCI_CAP_ID_PM, 0, 0, PCI_PMCAP_NDWORDS, pci_generic_save},
	{PCI_CAP_ID_AGP, 0, 0, PCI_AGP_NDWORDS, pci_generic_save},
	{PCI_CAP_ID_SLOT_ID, 0, 0, PCI_SLOTID_NDWORDS, pci_generic_save},
	{PCI_CAP_ID_MSI_X, 0, 0, PCI_MSIX_NDWORDS, pci_generic_save},
	{PCI_CAP_ID_MSI, 0, 0, PCI_CAP_SZUNKNOWN, pci_msi_save},
	{PCI_CAP_ID_PCIX, 0, 0, PCI_CAP_SZUNKNOWN, pci_pcix_save},
	{PCI_CAP_ID_PCI_E, 0, 0, PCI_CAP_SZUNKNOWN, pci_pcie_save},

	{PCI_CAP_ID_HT, PCI_HTCAP_SLPRI_TYPE, PCI_HTCAP_TYPE_SLHOST_MASK,
		PCI_HTCAP_SLPRI_NDWORDS, pci_generic_save},

	{PCI_CAP_ID_HT, PCI_HTCAP_HOSTSEC_TYPE, PCI_HTCAP_TYPE_SLHOST_MASK,
		PCI_HTCAP_HOSTSEC_NDWORDS, pci_generic_save},

	{PCI_CAP_ID_HT, PCI_HTCAP_INTCONF_TYPE, PCI_HTCAP_TYPE_MASK,
		PCI_HTCAP_INTCONF_NDWORDS, pci_generic_save},

	{PCI_CAP_ID_HT, PCI_HTCAP_REVID_TYPE, PCI_HTCAP_TYPE_MASK,
		PCI_HTCAP_REVID_NDWORDS, pci_generic_save},

	{PCI_CAP_ID_HT, PCI_HTCAP_UNITID_CLUMP_TYPE, PCI_HTCAP_TYPE_MASK,
		PCI_HTCAP_UNITID_CLUMP_NDWORDS, pci_generic_save},

	{PCI_CAP_ID_HT, PCI_HTCAP_ECFG_TYPE, PCI_HTCAP_TYPE_MASK,
		PCI_HTCAP_ECFG_NDWORDS, pci_generic_save},

	{PCI_CAP_ID_HT, PCI_HTCAP_ADDRMAP_TYPE, PCI_HTCAP_TYPE_MASK,
		PCI_CAP_SZUNKNOWN, pci_ht_addrmap_save},

	{PCI_CAP_ID_HT, PCI_HTCAP_MSIMAP_TYPE, PCI_HTCAP_TYPE_MASK,
		PCI_HTCAP_MSIMAP_NDWORDS, pci_generic_save},

	{PCI_CAP_ID_HT, PCI_HTCAP_DIRROUTE_TYPE, PCI_HTCAP_TYPE_MASK,
		PCI_HTCAP_DIRROUTE_NDWORDS, pci_generic_save},

	{PCI_CAP_ID_HT, PCI_HTCAP_VCSET_TYPE, PCI_HTCAP_TYPE_MASK,
		PCI_HTCAP_VCSET_NDWORDS, pci_generic_save},

	{PCI_CAP_ID_HT, PCI_HTCAP_RETRYMODE_TYPE, PCI_HTCAP_TYPE_MASK,
		PCI_HTCAP_RETRYMODE_NDWORDS, pci_generic_save},

	{PCI_CAP_ID_HT, PCI_HTCAP_GEN3_TYPE, PCI_HTCAP_TYPE_MASK,
		PCI_HTCAP_GEN3_NDWORDS, pci_generic_save},

	{PCI_CAP_ID_HT, PCI_HTCAP_FUNCEXT_TYPE, PCI_HTCAP_TYPE_MASK,
		PCI_CAP_SZUNKNOWN, pci_ht_funcext_save},

	{PCI_CAP_ID_HT, PCI_HTCAP_PM_TYPE, PCI_HTCAP_TYPE_MASK,
		PCI_HTCAP_PM_NDWORDS, pci_generic_save},

	/*
	 * {PCI_CAP_ID_cPCI_CRC, 0, NULL},
	 * {PCI_CAP_ID_VPD, 0, NULL},
	 * {PCI_CAP_ID_cPCI_HS, 0, NULL},
	 * {PCI_CAP_ID_PCI_HOTPLUG, 0, NULL},
	 * {PCI_CAP_ID_AGP_8X, 0, NULL},
	 * {PCI_CAP_ID_SECURE_DEV, 0, NULL},
	 */
	{PCI_CAP_NEXT_PTR_NULL, 0, NULL}
};


/*
 * Save the configuration registers for cdip as a property
 * so that it persists after detach/uninitchild.
 */
int
pci_save_config_regs(dev_info_t *dip)
{
	ddi_acc_handle_t confhdl;
	pci_config_header_state_t *chsp;
	pci_cap_save_desc_t *pci_cap_descp;
	int ret;
	uint32_t i, ncaps, nwords;
	uint32_t *regbuf, *p;
	uint8_t *maskbuf;
	size_t maskbufsz, regbufsz, capbufsz;
#ifdef __sparc
	ddi_acc_hdl_t *hp;
#else
	ddi_device_acc_attr_t attr;
	caddr_t cfgaddr;
#endif
	off_t offset = 0;
	uint8_t cap_ptr, cap_id;
	int pcie = 0;
	uint16_t status;

	PMD(PMD_SX, ("pci_save_config_regs %s:%d\n", ddi_driver_name(dip),
	    ddi_get_instance(dip)))

#ifdef __sparc
	if (pci_config_setup(dip, &confhdl) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d can't get config handle",
		    ddi_driver_name(dip), ddi_get_instance(dip));

		return (DDI_FAILURE);
	}
#else
	/* Set up cautious config access handle */
	attr.devacc_attr_version = DDI_DEVICE_ATTR_V1;
	attr.devacc_attr_endian_flags = DDI_STRUCTURE_LE_ACC;
	attr.devacc_attr_dataorder = DDI_STRICTORDER_ACC;
	attr.devacc_attr_access = DDI_CAUTIOUS_ACC;
	if (ddi_regs_map_setup(dip, 0, &cfgaddr, 0, 0, &attr, &confhdl)
	    != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d can't setup cautious config handle",
		    ddi_driver_name(dip), ddi_get_instance(dip));

		return (DDI_FAILURE);
	}
#endif

	/*
	 * Determine if it implements capabilities
	 */
	status = pci_config_get16(confhdl, PCI_CONF_STAT);
	if (!(status & 0x10)) {
		goto no_cap;
	}
	/*
	 * Determine if it is a pci express device. If it is, save entire
	 * 4k config space treating it as a array of 32 bit integers.
	 * If it is not, do it in a usual PCI way.
	 */
	cap_ptr = pci_config_get8(confhdl, PCI_BCNF_CAP_PTR);
	/*
	 * Walk the capabilities searching for pci express capability
	 */
	while (cap_ptr != PCI_CAP_NEXT_PTR_NULL) {
		cap_id = pci_config_get8(confhdl,
		    cap_ptr + PCI_CAP_ID);
		if (cap_id == PCI_CAP_ID_PCI_E) {
			pcie = 1;
			break;
		}
		cap_ptr = pci_config_get8(confhdl,
		    cap_ptr + PCI_CAP_NEXT_PTR);
	}
no_cap:
	if (pcie) {
		/* PCI express device. Can have data in all 4k space */
		regbuf = (uint32_t *)kmem_zalloc((size_t)PCIE_CONF_HDR_SIZE,
		    KM_SLEEP);
		p = regbuf;
		/*
		 * Allocate space for mask.
		 * mask size is 128 bytes (4096 / 4 / 8 )
		 */
		maskbufsz = (size_t)((PCIE_CONF_HDR_SIZE/ sizeof (uint32_t)) >>
		    INDEX_SHIFT);
		maskbuf = (uint8_t *)kmem_zalloc(maskbufsz, KM_SLEEP);
#ifdef __sparc
		hp = impl_acc_hdl_get(confhdl);
#endif
		for (i = 0; i < (PCIE_CONF_HDR_SIZE / sizeof (uint32_t)); i++) {
#ifdef __sparc
			ret = ddi_peek32(dip, (int32_t *)(hp->ah_addr + offset),
			    (int32_t *)p);
			if (ret == DDI_SUCCESS) {
#else
			/*
			 * ddi_peek doesn't work on x86, so we use cautious pci
			 * config access instead.
			 */
			*p = pci_config_get32(confhdl, offset);
			if (*p != -1) {
#endif
				/* it is readable register. set the bit */
				maskbuf[i >> INDEX_SHIFT] |=
				    (uint8_t)(1 << (i & BITMASK));
			}
			p++;
			offset += sizeof (uint32_t);
		}

		if ((ret = ndi_prop_update_byte_array(DDI_DEV_T_NONE, dip,
		    SAVED_CONFIG_REGS_MASK, (uchar_t *)maskbuf,
		    maskbufsz)) != DDI_PROP_SUCCESS) {
			cmn_err(CE_WARN, "couldn't create %s property while"
			    "saving config space for %s@%d\n",
			    SAVED_CONFIG_REGS_MASK, ddi_driver_name(dip),
			    ddi_get_instance(dip));
		} else if ((ret = ndi_prop_update_byte_array(DDI_DEV_T_NONE,
		    dip, SAVED_CONFIG_REGS, (uchar_t *)regbuf,
		    (size_t)PCIE_CONF_HDR_SIZE)) != DDI_PROP_SUCCESS) {
			(void) ddi_prop_remove(DDI_DEV_T_NONE, dip,
			    SAVED_CONFIG_REGS_MASK);
			cmn_err(CE_WARN, "%s%d can't update prop %s",
			    ddi_driver_name(dip), ddi_get_instance(dip),
			    SAVED_CONFIG_REGS);
		}

		kmem_free(maskbuf, (size_t)maskbufsz);
		kmem_free(regbuf, (size_t)PCIE_CONF_HDR_SIZE);
	} else {
		regbuf = (uint32_t *)kmem_zalloc((size_t)PCI_CONF_HDR_SIZE,
		    KM_SLEEP);
		chsp = (pci_config_header_state_t *)regbuf;

		chsp->chs_command = pci_config_get16(confhdl, PCI_CONF_COMM);
		chsp->chs_header_type =	pci_config_get8(confhdl,
		    PCI_CONF_HEADER);
		if ((chsp->chs_header_type & PCI_HEADER_TYPE_M) ==
		    PCI_HEADER_ONE)
			chsp->chs_bridge_control =
			    pci_config_get16(confhdl, PCI_BCNF_BCNTRL);
		chsp->chs_cache_line_size = pci_config_get8(confhdl,
		    PCI_CONF_CACHE_LINESZ);
		chsp->chs_latency_timer = pci_config_get8(confhdl,
		    PCI_CONF_LATENCY_TIMER);
		if ((chsp->chs_header_type & PCI_HEADER_TYPE_M) ==
		    PCI_HEADER_ONE) {
			chsp->chs_sec_latency_timer =
			    pci_config_get8(confhdl, PCI_BCNF_LATENCY_TIMER);
		}

		chsp->chs_base0 = pci_config_get32(confhdl, PCI_CONF_BASE0);
		chsp->chs_base1 = pci_config_get32(confhdl, PCI_CONF_BASE1);
		chsp->chs_base2 = pci_config_get32(confhdl, PCI_CONF_BASE2);
		chsp->chs_base3 = pci_config_get32(confhdl, PCI_CONF_BASE3);
		chsp->chs_base4 = pci_config_get32(confhdl, PCI_CONF_BASE4);
		chsp->chs_base5 = pci_config_get32(confhdl, PCI_CONF_BASE5);

		/*
		 * Allocate maximum space required for capability descriptions.
		 * The maximum number of capabilties saved is the number of
		 * capabilities listed in the pci_cap_table.
		 */
		ncaps = (sizeof (pci_cap_table) / sizeof (pci_cap_entry_t));
		capbufsz = ncaps * sizeof (pci_cap_save_desc_t);
		pci_cap_descp = (pci_cap_save_desc_t *)kmem_zalloc(
		    capbufsz, KM_SLEEP);
		p = (uint32_t *)((caddr_t)regbuf +
		    sizeof (pci_config_header_state_t));
		nwords = pci_save_caps(confhdl, p, pci_cap_descp, &ncaps);
		regbufsz = sizeof (pci_config_header_state_t) +
		    nwords * sizeof (uint32_t);

		if ((ret = ndi_prop_update_byte_array(DDI_DEV_T_NONE, dip,
		    SAVED_CONFIG_REGS, (uchar_t *)regbuf, regbufsz)) !=
		    DDI_PROP_SUCCESS) {
			cmn_err(CE_WARN, "%s%d can't update prop %s",
			    ddi_driver_name(dip), ddi_get_instance(dip),
			    SAVED_CONFIG_REGS);
		} else if (ncaps) {
			ret = ndi_prop_update_byte_array(DDI_DEV_T_NONE, dip,
			    SAVED_CONFIG_REGS_CAPINFO, (uchar_t *)pci_cap_descp,
			    ncaps * sizeof (pci_cap_save_desc_t));
			if (ret != DDI_PROP_SUCCESS)
				(void) ddi_prop_remove(DDI_DEV_T_NONE, dip,
				    SAVED_CONFIG_REGS);
		}
		kmem_free(regbuf, (size_t)PCI_CONF_HDR_SIZE);
		kmem_free(pci_cap_descp, capbufsz);
	}
	pci_config_teardown(&confhdl);

	if (ret != DDI_PROP_SUCCESS)
		return (DDI_FAILURE);

	return (DDI_SUCCESS);
}

/*
 * Saves registers associated with PCI capabilities.
 * Returns number of 32 bit words saved.
 * Number of capabilities saved is returned in ncapsp.
 */
static uint32_t
pci_save_caps(ddi_acc_handle_t confhdl, uint32_t *regbuf,
    pci_cap_save_desc_t *cap_descp, uint32_t *ncapsp)
{
	return (cap_walk_and_save(confhdl, regbuf, cap_descp, ncapsp, 0));
}

static uint32_t
cap_walk_and_save(ddi_acc_handle_t confhdl, uint32_t *regbuf,
    pci_cap_save_desc_t *cap_descp, uint32_t *ncapsp, int xspace)
{
	pci_cap_entry_t *pci_cap_entp;
	uint16_t cap_id, offset, status;
	uint32_t words_saved = 0, nwords = 0;
	uint16_t cap_ptr = PCI_CAP_NEXT_PTR_NULL;
	uint16_t cap_reg;

	*ncapsp = 0;

	/*
	 * Determine if it implements capabilities
	 */
	status = pci_config_get16(confhdl, PCI_CONF_STAT);
	if (!(status & 0x10)) {
		return (words_saved);
	}

	if (!xspace)
		cap_ptr = pci_config_get8(confhdl, PCI_BCNF_CAP_PTR);
	/*
	 * Walk the capabilities
	 */
	while (cap_ptr != PCI_CAP_NEXT_PTR_NULL) {
		cap_id = CAP_ID(confhdl, cap_ptr, xspace);

		/* Search for this cap id in our table */
		if (!xspace) {
			pci_cap_entp = pci_cap_table;
			cap_reg = pci_config_get16(confhdl,
			    cap_ptr + PCI_CAP_ID_REGS_OFF);
		}

		while (pci_cap_entp->cap_id != PCI_CAP_NEXT_PTR_NULL) {
			if (pci_cap_entp->cap_id == cap_id &&
			    (cap_reg & pci_cap_entp->cap_mask) ==
			    pci_cap_entp->cap_reg)
				break;

			pci_cap_entp++;
		}

		offset = cap_ptr;
		cap_ptr = NEXT_CAP(confhdl, cap_ptr, xspace);
		/*
		 * If this cap id is not found in the table, there is nothing
		 * to save.
		 */
		if (pci_cap_entp->cap_id == PCI_CAP_NEXT_PTR_NULL)
			continue;
		if (pci_cap_entp->cap_save_func) {
			if ((nwords = pci_cap_entp->cap_save_func(confhdl,
			    offset, regbuf, pci_cap_entp->cap_ndwords))) {
				cap_descp->cap_nregs = nwords;
				cap_descp->cap_offset = offset;
				cap_descp->cap_id = cap_id;
				regbuf += nwords;
				cap_descp++;
				words_saved += nwords;
				(*ncapsp)++;
			}
		}

	}
	return (words_saved);
}

static void
pci_fill_buf(ddi_acc_handle_t confhdl, uint16_t cap_ptr,
    uint32_t *regbuf, uint32_t nwords)
{
	int i;

	for (i = 0; i < nwords; i++) {
		*regbuf = pci_config_get32(confhdl, cap_ptr);
		regbuf++;
		cap_ptr += 4;
	}
}

static uint32_t
pci_generic_save(ddi_acc_handle_t confhdl, uint16_t cap_ptr, uint32_t *regbuf,
    uint32_t nwords)
{
	pci_fill_buf(confhdl, cap_ptr, regbuf, nwords);
	return (nwords);
}

/*ARGSUSED*/
static uint32_t
pci_msi_save(ddi_acc_handle_t confhdl, uint16_t cap_ptr, uint32_t *regbuf,
    uint32_t notused)
{
	uint32_t nwords = PCI_MSI_MIN_WORDS;
	uint16_t msi_ctrl;

	/* Figure out how many registers to be saved */
	msi_ctrl = pci_config_get16(confhdl, cap_ptr + PCI_MSI_CTRL);
	/* If 64 bit address capable add one word */
	if (msi_ctrl & PCI_MSI_64BIT_MASK)
		nwords++;
	/* If per vector masking capable, add two more words */
	if (msi_ctrl & PCI_MSI_PVM_MASK)
		nwords += 2;
	pci_fill_buf(confhdl, cap_ptr, regbuf, nwords);

	return (nwords);
}

/*ARGSUSED*/
static uint32_t
pci_pcix_save(ddi_acc_handle_t confhdl, uint16_t cap_ptr, uint32_t *regbuf,
    uint32_t notused)
{
	uint32_t nwords = PCI_PCIX_MIN_WORDS;
	uint16_t pcix_command;

	/* Figure out how many registers to be saved */
	pcix_command = pci_config_get16(confhdl, cap_ptr + PCI_PCIX_COMMAND);
	/* If it is version 1 or version 2, add 4 words */
	if (((pcix_command & PCI_PCIX_VER_MASK) == PCI_PCIX_VER_1) ||
	    ((pcix_command & PCI_PCIX_VER_MASK) == PCI_PCIX_VER_2))
		nwords += 4;
	pci_fill_buf(confhdl, cap_ptr, regbuf, nwords);

	return (nwords);
}

/*ARGSUSED*/
static uint32_t
pci_pcie_save(ddi_acc_handle_t confhdl, uint16_t cap_ptr, uint32_t *regbuf,
    uint32_t notused)
{
	return (0);
}

/*ARGSUSED*/
static uint32_t
pci_ht_addrmap_save(ddi_acc_handle_t confhdl, uint16_t cap_ptr,
    uint32_t *regbuf, uint32_t notused)
{
	uint32_t nwords = 0;
	uint16_t reg;

	reg = pci_config_get16(confhdl, cap_ptr + PCI_CAP_ID_REGS_OFF);

	switch ((reg & PCI_HTCAP_ADDRMAP_MAPTYPE_MASK) >>
	    PCI_HTCAP_ADDRMAP_MAPTYPE_SHIFT) {
	case PCI_HTCAP_ADDRMAP_40BIT_ID:
		/* HT3.1 spec, ch 7.7, 40-bit dma */
		nwords = 3 + ((reg & PCI_HTCAP_ADDRMAP_NUMMAP_MASK) * 2);
		break;
	case PCI_HTCAP_ADDRMAP_64BIT_ID:
		/* HT3.1 spec, ch 7.8, 64-bit dma */
		nwords = 4;
		break;
	default:
		nwords = 0;
	}

	pci_fill_buf(confhdl, cap_ptr, regbuf, nwords);
	return (nwords);
}

/*ARGSUSED*/
static uint32_t
pci_ht_funcext_save(ddi_acc_handle_t confhdl, uint16_t cap_ptr,
    uint32_t *regbuf, uint32_t notused)
{
	uint32_t nwords;
	uint16_t reg;

	reg = pci_config_get16(confhdl, cap_ptr + PCI_CAP_ID_REGS_OFF);

	/* HT3.1 spec, ch 7.17 */
	nwords = 1 + (reg & PCI_HTCAP_FUNCEXT_LEN_MASK);

	pci_fill_buf(confhdl, cap_ptr, regbuf, nwords);
	return (nwords);
}

static void
pci_pmcap_check(ddi_acc_handle_t confhdl, uint32_t *regbuf,
    uint16_t pmcap_offset)
{
	uint16_t pmcsr;
	uint16_t pmcsr_offset = pmcap_offset + PCI_PMCSR;
	uint32_t *saved_pmcsrp = (uint32_t *)((caddr_t)regbuf + PCI_PMCSR);

	/*
	 * Copy the power state bits from the PMCSR to our saved copy.
	 * This is to make sure that we don't change the D state when
	 * we restore config space of the device.
	 */
	pmcsr = pci_config_get16(confhdl, pmcsr_offset);
	(*saved_pmcsrp) &= ~PCI_PMCSR_STATE_MASK;
	(*saved_pmcsrp) |= (pmcsr & PCI_PMCSR_STATE_MASK);
}

static void
pci_restore_caps(ddi_acc_handle_t confhdl, uint32_t *regbuf,
    pci_cap_save_desc_t *cap_descp, uint32_t elements)
{
	int i, j;
	uint16_t offset;

	for (i = 0; i < (elements / sizeof (pci_cap_save_desc_t)); i++) {
		offset = cap_descp->cap_offset;
		if (cap_descp->cap_id == PCI_CAP_ID_PM)
			pci_pmcap_check(confhdl, regbuf, offset);
		for (j = 0; j < cap_descp->cap_nregs; j++) {
			pci_config_put32(confhdl, offset, *regbuf);
			regbuf++;
			offset += 4;
		}
		cap_descp++;
	}
}

/*
 * Restore config_regs from a single devinfo node.
 */
int
pci_restore_config_regs(dev_info_t *dip)
{
	ddi_acc_handle_t confhdl;
	pci_config_header_state_t *chs_p;
	pci_cap_save_desc_t *cap_descp;
	uint32_t elements, i;
	uint8_t *maskbuf;
	uint32_t *regbuf, *p;
	off_t offset = 0;

	if (pci_config_setup(dip, &confhdl) != DDI_SUCCESS) {
		cmn_err(CE_WARN, "%s%d can't get config handle",
		    ddi_driver_name(dip), ddi_get_instance(dip));
		return (DDI_FAILURE);
	}

	if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, SAVED_CONFIG_REGS_MASK,
	    (uchar_t **)&maskbuf, &elements) == DDI_PROP_SUCCESS) {

		if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, SAVED_CONFIG_REGS,
		    (uchar_t **)&regbuf, &elements) != DDI_PROP_SUCCESS) {
			goto restoreconfig_err;
		}
		ASSERT(elements == PCIE_CONF_HDR_SIZE);
		/* pcie device and has 4k config space saved */
		p = regbuf;
		for (i = 0; i < PCIE_CONF_HDR_SIZE / sizeof (uint32_t); i++) {
			/* If the word is readable then restore it */
			if (maskbuf[i >> INDEX_SHIFT] &
			    (uint8_t)(1 << (i & BITMASK)))
				pci_config_put32(confhdl, offset, *p);
			p++;
			offset += sizeof (uint32_t);
		}
		ddi_prop_free(regbuf);
		ddi_prop_free(maskbuf);
		if (ndi_prop_remove(DDI_DEV_T_NONE, dip,
		    SAVED_CONFIG_REGS_MASK) != DDI_PROP_SUCCESS) {
			cmn_err(CE_WARN, "%s%d can't remove prop %s",
			    ddi_driver_name(dip), ddi_get_instance(dip),
			    SAVED_CONFIG_REGS_MASK);
		}
	} else {
		if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM, SAVED_CONFIG_REGS,
		    (uchar_t **)&regbuf, &elements) != DDI_PROP_SUCCESS) {

			pci_config_teardown(&confhdl);
			return (DDI_SUCCESS);
		}

		chs_p = (pci_config_header_state_t *)regbuf;
		pci_config_put16(confhdl, PCI_CONF_COMM,
		    chs_p->chs_command);
		if ((chs_p->chs_header_type & PCI_HEADER_TYPE_M) ==
		    PCI_HEADER_ONE) {
			pci_config_put16(confhdl, PCI_BCNF_BCNTRL,
			    chs_p->chs_bridge_control);
		}
		pci_config_put8(confhdl, PCI_CONF_CACHE_LINESZ,
		    chs_p->chs_cache_line_size);
		pci_config_put8(confhdl, PCI_CONF_LATENCY_TIMER,
		    chs_p->chs_latency_timer);
		if ((chs_p->chs_header_type & PCI_HEADER_TYPE_M) ==
		    PCI_HEADER_ONE)
			pci_config_put8(confhdl, PCI_BCNF_LATENCY_TIMER,
			    chs_p->chs_sec_latency_timer);

		pci_config_put32(confhdl, PCI_CONF_BASE0, chs_p->chs_base0);
		pci_config_put32(confhdl, PCI_CONF_BASE1, chs_p->chs_base1);
		pci_config_put32(confhdl, PCI_CONF_BASE2, chs_p->chs_base2);
		pci_config_put32(confhdl, PCI_CONF_BASE3, chs_p->chs_base3);
		pci_config_put32(confhdl, PCI_CONF_BASE4, chs_p->chs_base4);
		pci_config_put32(confhdl, PCI_CONF_BASE5, chs_p->chs_base5);

		if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, dip,
		    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
		    SAVED_CONFIG_REGS_CAPINFO,
		    (uchar_t **)&cap_descp, &elements) == DDI_PROP_SUCCESS) {
			/*
			 * PCI capability related regsiters are saved.
			 * Restore them based on the description.
			 */
			p = (uint32_t *)((caddr_t)regbuf +
			    sizeof (pci_config_header_state_t));
			pci_restore_caps(confhdl, p, cap_descp, elements);
			ddi_prop_free(cap_descp);
		}

		ddi_prop_free(regbuf);
	}

	/*
	 * Make sure registers are flushed
	 */
	(void) pci_config_get32(confhdl, PCI_CONF_BASE5);


	if (ndi_prop_remove(DDI_DEV_T_NONE, dip, SAVED_CONFIG_REGS) !=
	    DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "%s%d can't remove prop %s",
		    ddi_driver_name(dip), ddi_get_instance(dip),
		    SAVED_CONFIG_REGS);
	}

	pci_config_teardown(&confhdl);

	return (DDI_SUCCESS);

restoreconfig_err:
	ddi_prop_free(maskbuf);
	if (ndi_prop_remove(DDI_DEV_T_NONE, dip, SAVED_CONFIG_REGS_MASK) !=
	    DDI_PROP_SUCCESS) {
		cmn_err(CE_WARN, "%s%d can't remove prop %s",
		    ddi_driver_name(dip), ddi_get_instance(dip),
		    SAVED_CONFIG_REGS_MASK);
	}
	pci_config_teardown(&confhdl);
	return (DDI_FAILURE);
}

/*ARGSUSED*/
static int
pci_lookup_pmcap(dev_info_t *dip, ddi_acc_handle_t conf_hdl,
	uint16_t *pmcap_offsetp)
{
	uint8_t cap_ptr;
	uint8_t cap_id;
	uint8_t header_type;
	uint16_t status;

	header_type = pci_config_get8(conf_hdl, PCI_CONF_HEADER);
	header_type &= PCI_HEADER_TYPE_M;

	/* we don't deal with bridges, etc here */
	if (header_type != PCI_HEADER_ZERO) {
		return (DDI_FAILURE);
	}

	status = pci_config_get16(conf_hdl, PCI_CONF_STAT);
	if ((status & PCI_STAT_CAP) == 0) {
		return (DDI_FAILURE);
	}

	cap_ptr = pci_config_get8(conf_hdl, PCI_CONF_CAP_PTR);

	/*
	 * Walk the capabilities searching for a PM entry.
	 */
	while (cap_ptr != PCI_CAP_NEXT_PTR_NULL) {
		cap_id = pci_config_get8(conf_hdl, cap_ptr + PCI_CAP_ID);
		if (cap_id == PCI_CAP_ID_PM) {
			break;
		}
		cap_ptr = pci_config_get8(conf_hdl,
		    cap_ptr + PCI_CAP_NEXT_PTR);
	}

	if (cap_ptr == PCI_CAP_NEXT_PTR_NULL) {
		return (DDI_FAILURE);
	}
	*pmcap_offsetp = cap_ptr;
	return (DDI_SUCCESS);
}

/*
 * Do common pci-specific suspend actions:
 *  - enable wakeup if appropriate for the device
 *  - put device in lowest D-state that supports wakeup, or D3 if none
 *  - turn off bus mastering in control register
 * For lack of per-dip storage (parent private date is pretty busy)
 * we use properties to store the necessary context
 * To avoid grotting through pci config space on every suspend,
 * we leave the prop in existence after resume, cause we know that
 * the detach framework code will dispose of it for us.
 */

typedef struct pci_pm_context {
	int		ppc_flags;
	uint16_t	ppc_cap_offset;	/* offset in config space to pm cap */
	uint16_t	ppc_pmcsr;	/* need this too */
	uint16_t	ppc_suspend_level;
} pci_pm_context_t;

#define	SAVED_PM_CONTEXT	"pci-pm-context"

/* values for ppc_flags	*/
#define	PPCF_NOPMCAP	1

/*
 * Handle pci-specific suspend processing
 *   PM CSR and PCI CMD are saved by pci_save_config_regs().
 *   If device can wake up system via PME, enable it to do so
 *   Set device power level to lowest that can generate PME, or D3 if none can
 *   Turn off bus master enable in pci command register
 */
#if defined(__x86)
extern int acpi_ddi_setwake(dev_info_t *dip, int level);
#endif

int
pci_post_suspend(dev_info_t *dip)
{
	pci_pm_context_t *p;
	uint16_t	pmcap, pmcsr, pcicmd;
	uint_t length;
	int ret;
	int fromprop = 1;	/* source of memory *p */
	ddi_acc_handle_t hdl;

	PMD(PMD_SX, ("pci_post_suspend %s:%d\n",
	    ddi_driver_name(dip), ddi_get_instance(dip)))

	if (pci_save_config_regs(dip) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	if (pci_config_setup(dip, &hdl) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    SAVED_PM_CONTEXT, (uchar_t **)&p, &length) != DDI_PROP_SUCCESS) {
		p = (pci_pm_context_t *)kmem_zalloc(sizeof (*p), KM_SLEEP);
		fromprop = 0;
		if (pci_lookup_pmcap(dip, hdl,
		    &p->ppc_cap_offset) != DDI_SUCCESS) {
			p->ppc_flags |= PPCF_NOPMCAP;
			ret = ndi_prop_update_byte_array(DDI_DEV_T_NONE, dip,
			    SAVED_PM_CONTEXT, (uchar_t *)p,
			    sizeof (pci_pm_context_t));
			if (ret != DDI_PROP_SUCCESS) {
				(void) ddi_prop_remove(DDI_DEV_T_NONE, dip,
				    SAVED_PM_CONTEXT);
				ret = DDI_FAILURE;
			} else {
				ret = DDI_SUCCESS;
			}
			goto done;
		}
		/*
		 * Upon suspend, set the power level to the lowest that can
		 * wake the system.  If none can, then set to lowest.
		 * XXX later we will need to check policy to see if this
		 * XXX device has had wakeup disabled
		 */
		pmcap = pci_config_get16(hdl, p->ppc_cap_offset + PCI_PMCAP);
		if ((pmcap & (PCI_PMCAP_D3COLD_PME | PCI_PMCAP_D3HOT_PME)) != 0)
			p->ppc_suspend_level =
			    (PCI_PMCSR_PME_EN | PCI_PMCSR_D3HOT);
		else if ((pmcap & PCI_PMCAP_D2_PME) != 0)
			p->ppc_suspend_level = PCI_PMCSR_PME_EN | PCI_PMCSR_D2;
		else if ((pmcap & PCI_PMCAP_D1_PME) != 0)
			p->ppc_suspend_level = PCI_PMCSR_PME_EN | PCI_PMCSR_D1;
		else if ((pmcap & PCI_PMCAP_D0_PME) != 0)
			p->ppc_suspend_level = PCI_PMCSR_PME_EN | PCI_PMCSR_D0;
		else
			p->ppc_suspend_level = PCI_PMCSR_D3HOT;

		/*
		 * we defer updating the property to catch the saved
		 * register values as well
		 */
	}
	/* If we set this in kmem_zalloc'd memory, we already returned above */
	if ((p->ppc_flags & PPCF_NOPMCAP) != 0) {
		goto done;
	}

	pmcsr = pci_config_get16(hdl, p->ppc_cap_offset + PCI_PMCSR);
	p->ppc_pmcsr = pmcsr;
	pmcsr &= (PCI_PMCSR_STATE_MASK);
	pmcsr |= (PCI_PMCSR_PME_STAT | p->ppc_suspend_level);

	/*
	 * Push out saved register values
	 */
	ret = ndi_prop_update_byte_array(DDI_DEV_T_NONE, dip, SAVED_PM_CONTEXT,
	    (uchar_t *)p, sizeof (pci_pm_context_t));
	if (ret == DDI_PROP_SUCCESS) {
		goto done;
	}
	/* Failed; put things back the way we found them */
	(void) pci_restore_config_regs(dip);
	if (fromprop)
		ddi_prop_free(p);
	else
		kmem_free(p, sizeof (*p));
	(void) ddi_prop_remove(DDI_DEV_T_NONE, dip, SAVED_PM_CONTEXT);
	pci_config_teardown(&hdl);
	return (DDI_FAILURE);

done:

	/*
	 * According to 8.2.2 of "PCI Bus Power Management Interface
	 * Specification Revision 1.2":
	 * "When placing a function into D3, the operating system software is
	 * required to disable I/O and memory space as well as bus mastering via
	 * the PCI Command register."
	 */

	pcicmd = pci_config_get16(hdl, PCI_CONF_COMM);
	pcicmd &= ~(PCI_COMM_ME|PCI_COMM_MAE|PCI_COMM_IO);
	pci_config_put16(hdl, PCI_CONF_COMM, pcicmd);


#if defined(__x86)
	if (pci_enable_wakeup &&
	    (p->ppc_suspend_level & PCI_PMCSR_PME_EN) != 0) {
		ret = acpi_ddi_setwake(dip, 3);

		if (ret) {
			PMD(PMD_SX, ("pci_post_suspend, setwake %s@%s rets "
			    "%x\n", PM_NAME(dip), PM_ADDR(dip), ret));
		}
	}
#endif

	if (p) {

		/*
		 * Some BIOS (e.g. Toshiba M10) expects pci-ide to be in D0
		 * state when we set SLP_EN, otherwise it takes 5 minutes for
		 * the BIOS to put the system into S3.
		 */
		if (strcmp(ddi_node_name(dip), "pci-ide") == 0) {
			pmcsr = 0;
		}

		/*
		 * pmcsr is the last write-operation to the device's PCI
		 * config space, because we found that there are
		 * some faulty devices whose PCI config space may not
		 * respond correctly once in D3 state.
		 */
		if ((p->ppc_flags & PPCF_NOPMCAP) == 0 && pci_enable_wakeup) {
			pci_config_put16(hdl, p->ppc_cap_offset + PCI_PMCSR,
			    PCI_PMCSR_PME_STAT);
			pci_config_put16(hdl, p->ppc_cap_offset + PCI_PMCSR,
			    pmcsr);
		}

		if (fromprop)
			ddi_prop_free(p);
		else
			kmem_free(p, sizeof (*p));
	}

	pci_config_teardown(&hdl);

	return (DDI_SUCCESS);
}

/*
 * The inverse of pci_post_suspend; handle pci-specific resume processing
 *   First, turn device back on, then restore config space.
 */

int
pci_pre_resume(dev_info_t *dip)
{
	ddi_acc_handle_t hdl;
	pci_pm_context_t *p;
	/* E_FUNC_SET_NOT_USED */
	uint16_t	pmcap, pmcsr;
	int flags;
	uint_t length;
	clock_t drv_usectohz(clock_t microsecs);

	PMD(PMD_SX, ("pci_pre_resume %s:%d\n", ddi_driver_name(dip),
	    ddi_get_instance(dip)))
	if (ddi_prop_lookup_byte_array(DDI_DEV_T_ANY, dip,
	    DDI_PROP_DONTPASS | DDI_PROP_NOTPROM,
	    SAVED_PM_CONTEXT, (uchar_t **)&p, &length) != DDI_PROP_SUCCESS) {
		return (DDI_FAILURE);
	}
	flags = p->ppc_flags;
	pmcap = p->ppc_cap_offset;
	pmcsr = p->ppc_pmcsr;

#if defined(__x86)
	/*
	 * Turn platform wake enable back off
	 */
	if (pci_enable_wakeup &&
	    (p->ppc_suspend_level & PCI_PMCSR_PME_EN) != 0) {
		int retval;

		retval = acpi_ddi_setwake(dip, 0);	/* 0 for now */
		if (retval) {
			PMD(PMD_SX, ("pci_pre_resume, setwake %s@%s rets "
			    "%x\n", PM_NAME(dip), PM_ADDR(dip), retval));
		}
	}
#endif

	ddi_prop_free(p);

	if ((flags & PPCF_NOPMCAP) != 0)
		goto done;

	if (pci_config_setup(dip, &hdl) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}
	pci_config_put16(hdl, pmcap + PCI_PMCSR, pmcsr);
	delay(drv_usectohz(10000));	/* PCI PM spec D3->D0 (10ms) */
	pci_config_teardown(&hdl);
done:
	(void) pci_restore_config_regs(dip);	/* fudges D-state! */
	return (DDI_SUCCESS);
}
