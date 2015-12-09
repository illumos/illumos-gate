/*
 * CDDL HEADER START
 *
 * Copyright(c) 2007-2009 Intel Corporation. All rights reserved.
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at:
 *	http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When using or redistributing this file, you may do so under the
 * License only. No other modification of this header is permitted.
 *
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */

/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms of the CDDL.
 */

#include "igb_sw.h"
#include "igb_debug.h"

igb_debug_t igb_debug = IGB_LOG_ERROR;

#ifdef IGB_DEBUG
extern ddi_device_acc_attr_t igb_regs_acc_attr;

void
pci_dump(void *arg)
{
	igb_t *igb = (igb_t *)arg;
	ddi_acc_handle_t handle;
	uint8_t cap_ptr;
	uint8_t next_ptr;
	uint32_t msix_bar;
	uint32_t msix_ctrl;
	uint32_t msix_tbl_sz;
	uint32_t tbl_offset;
	uint32_t tbl_bir;
	uint32_t pba_offset;
	uint32_t pba_bir;
	off_t offset;
	off_t mem_size;
	uintptr_t base;
	ddi_acc_handle_t acc_hdl;
	int i;

	handle = igb->osdep.cfg_handle;

	igb_log(igb, IGB_LOG_INFO, "Begin dump PCI config space");

	igb_log(igb, IGB_LOG_INFO,
	    "PCI_CONF_VENID:\t0x%x\n",
	    pci_config_get16(handle, PCI_CONF_VENID));
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_CONF_DEVID:\t0x%x\n",
	    pci_config_get16(handle, PCI_CONF_DEVID));
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_CONF_COMMAND:\t0x%x\n",
	    pci_config_get16(handle, PCI_CONF_COMM));
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_CONF_STATUS:\t0x%x\n",
	    pci_config_get16(handle, PCI_CONF_STAT));
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_CONF_REVID:\t0x%x\n",
	    pci_config_get8(handle, PCI_CONF_REVID));
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_CONF_PROG_CLASS:\t0x%x\n",
	    pci_config_get8(handle, PCI_CONF_PROGCLASS));
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_CONF_SUB_CLASS:\t0x%x\n",
	    pci_config_get8(handle, PCI_CONF_SUBCLASS));
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_CONF_BAS_CLASS:\t0x%x\n",
	    pci_config_get8(handle, PCI_CONF_BASCLASS));
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_CONF_CACHE_LINESZ:\t0x%x\n",
	    pci_config_get8(handle, PCI_CONF_CACHE_LINESZ));
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_CONF_LATENCY_TIMER:\t0x%x\n",
	    pci_config_get8(handle, PCI_CONF_LATENCY_TIMER));
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_CONF_HEADER_TYPE:\t0x%x\n",
	    pci_config_get8(handle, PCI_CONF_HEADER));
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_CONF_BIST:\t0x%x\n",
	    pci_config_get8(handle, PCI_CONF_BIST));
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_CONF_BASE0:\t0x%x\n",
	    pci_config_get32(handle, PCI_CONF_BASE0));
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_CONF_BASE1:\t0x%x\n",
	    pci_config_get32(handle, PCI_CONF_BASE1));
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_CONF_BASE2:\t0x%x\n",
	    pci_config_get32(handle, PCI_CONF_BASE2));

	/* MSI-X BAR */
	msix_bar = pci_config_get32(handle, PCI_CONF_BASE3);
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_CONF_BASE3:\t0x%x\n", msix_bar);

	igb_log(igb, IGB_LOG_INFO,
	    "PCI_CONF_BASE4:\t0x%x\n",
	    pci_config_get32(handle, PCI_CONF_BASE4));
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_CONF_BASE5:\t0x%x\n",
	    pci_config_get32(handle, PCI_CONF_BASE5));
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_CONF_CIS:\t0x%x\n",
	    pci_config_get32(handle, PCI_CONF_CIS));
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_CONF_SUBVENID:\t0x%x\n",
	    pci_config_get16(handle, PCI_CONF_SUBVENID));
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_CONF_SUBSYSID:\t0x%x\n",
	    pci_config_get16(handle, PCI_CONF_SUBSYSID));
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_CONF_ROM:\t0x%x\n",
	    pci_config_get32(handle, PCI_CONF_ROM));

	cap_ptr = pci_config_get8(handle, PCI_CONF_CAP_PTR);

	igb_log(igb, IGB_LOG_INFO,
	    "PCI_CONF_CAP_PTR:\t0x%x\n", cap_ptr);
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_CONF_ILINE:\t0x%x\n",
	    pci_config_get8(handle, PCI_CONF_ILINE));
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_CONF_IPIN:\t0x%x\n",
	    pci_config_get8(handle, PCI_CONF_IPIN));
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_CONF_MIN_G:\t0x%x\n",
	    pci_config_get8(handle, PCI_CONF_MIN_G));
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_CONF_MAX_L:\t0x%x\n",
	    pci_config_get8(handle, PCI_CONF_MAX_L));

	/* Power Management */
	offset = cap_ptr;

	igb_log(igb, IGB_LOG_INFO,
	    "PCI_PM_CAP_ID:\t0x%x\n",
	    pci_config_get8(handle, offset));

	next_ptr = pci_config_get8(handle, offset + 1);

	igb_log(igb, IGB_LOG_INFO,
	    "PCI_PM_NEXT_PTR:\t0x%x\n", next_ptr);
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_PM_CAP:\t0x%x\n",
	    pci_config_get16(handle, offset + PCI_PMCAP));
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_PM_CSR:\t0x%x\n",
	    pci_config_get16(handle, offset + PCI_PMCSR));
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_PM_CSR_BSE:\t0x%x\n",
	    pci_config_get8(handle, offset + PCI_PMCSR_BSE));
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_PM_DATA:\t0x%x\n",
	    pci_config_get8(handle, offset + PCI_PMDATA));

	/* MSI Configuration */
	offset = next_ptr;

	igb_log(igb, IGB_LOG_INFO,
	    "PCI_MSI_CAP_ID:\t0x%x\n",
	    pci_config_get8(handle, offset));

	next_ptr = pci_config_get8(handle, offset + 1);

	igb_log(igb, IGB_LOG_INFO,
	    "PCI_MSI_NEXT_PTR:\t0x%x\n", next_ptr);
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_MSI_CTRL:\t0x%x\n",
	    pci_config_get16(handle, offset + PCI_MSI_CTRL));
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_MSI_ADDR:\t0x%x\n",
	    pci_config_get32(handle, offset + PCI_MSI_ADDR_OFFSET));
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_MSI_ADDR_HI:\t0x%x\n",
	    pci_config_get32(handle, offset + 0x8));
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_MSI_DATA:\t0x%x\n",
	    pci_config_get16(handle, offset + 0xC));

	/* MSI-X Configuration */
	offset = next_ptr;

	igb_log(igb, IGB_LOG_INFO,
	    "PCI_MSIX_CAP_ID:\t0x%x\n",
	    pci_config_get8(handle, offset));

	next_ptr = pci_config_get8(handle, offset + 1);
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_MSIX_NEXT_PTR:\t0x%x\n", next_ptr);

	msix_ctrl = pci_config_get16(handle, offset + PCI_MSIX_CTRL);
	msix_tbl_sz = msix_ctrl & 0x7ff;
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_MSIX_CTRL:\t0x%x\n", msix_ctrl);

	tbl_offset = pci_config_get32(handle, offset + PCI_MSIX_TBL_OFFSET);
	tbl_bir = tbl_offset & PCI_MSIX_TBL_BIR_MASK;
	tbl_offset = tbl_offset & ~PCI_MSIX_TBL_BIR_MASK;
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_MSIX_TBL_OFFSET:\t0x%x\n", tbl_offset);
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_MSIX_TBL_BIR:\t0x%x\n", tbl_bir);

	pba_offset = pci_config_get32(handle, offset + PCI_MSIX_PBA_OFFSET);
	pba_bir = pba_offset & PCI_MSIX_PBA_BIR_MASK;
	pba_offset = pba_offset & ~PCI_MSIX_PBA_BIR_MASK;
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_MSIX_PBA_OFFSET:\t0x%x\n", pba_offset);
	igb_log(igb, IGB_LOG_INFO,
	    "PCI_MSIX_PBA_BIR:\t0x%x\n", pba_bir);

	/* PCI Express Configuration */
	offset = next_ptr;

	igb_log(igb, IGB_LOG_INFO,
	    "PCIE_CAP_ID:\t0x%x\n",
	    pci_config_get8(handle, offset + PCIE_CAP_ID));

	next_ptr = pci_config_get8(handle, offset + PCIE_CAP_NEXT_PTR);

	igb_log(igb, IGB_LOG_INFO,
	    "PCIE_CAP_NEXT_PTR:\t0x%x\n", next_ptr);
	igb_log(igb, IGB_LOG_INFO,
	    "PCIE_PCIECAP:\t0x%x\n",
	    pci_config_get16(handle, offset + PCIE_PCIECAP));
	igb_log(igb, IGB_LOG_INFO,
	    "PCIE_DEVCAP:\t0x%x\n",
	    pci_config_get32(handle, offset + PCIE_DEVCAP));
	igb_log(igb, IGB_LOG_INFO,
	    "PCIE_DEVCTL:\t0x%x\n",
	    pci_config_get16(handle, offset + PCIE_DEVCTL));
	igb_log(igb, IGB_LOG_INFO,
	    "PCIE_DEVSTS:\t0x%x\n",
	    pci_config_get16(handle, offset + PCIE_DEVSTS));
	igb_log(igb, IGB_LOG_INFO,
	    "PCIE_LINKCAP:\t0x%x\n",
	    pci_config_get32(handle, offset + PCIE_LINKCAP));
	igb_log(igb, IGB_LOG_INFO,
	    "PCIE_LINKCTL:\t0x%x\n",
	    pci_config_get16(handle, offset + PCIE_LINKCTL));
	igb_log(igb, IGB_LOG_INFO,
	    "PCIE_LINKSTS:\t0x%x\n",
	    pci_config_get16(handle, offset + PCIE_LINKSTS));

	/* MSI-X Memory Space */
	if (ddi_dev_regsize(igb->dip, IGB_ADAPTER_MSIXTAB, &mem_size) !=
	    DDI_SUCCESS) {
		igb_log(igb, IGB_LOG_INFO, "ddi_dev_regsize() failed");
		return;
	}

	if ((ddi_regs_map_setup(igb->dip, IGB_ADAPTER_MSIXTAB, (caddr_t *)&base,
	    0, mem_size, &igb_regs_acc_attr, &acc_hdl)) != DDI_SUCCESS) {
		igb_log(igb, IGB_LOG_INFO, "ddi_regs_map_setup() failed");
		return;
	}

	igb_log(igb, IGB_LOG_INFO, "MSI-X Memory Space: "
	    "(mem_size = %d, base = %x)", mem_size, base);

	for (i = 0; i <= msix_tbl_sz; i++) {
		igb_log(igb, IGB_LOG_INFO, "MSI-X Table Entry(%d):", i);
		igb_log(igb, IGB_LOG_INFO, "lo_addr:\t%x",
		    ddi_get32(acc_hdl,
		    (uint32_t *)(base + tbl_offset + (i * 16))));
		igb_log(igb, IGB_LOG_INFO, "up_addr:\t%x",
		    ddi_get32(acc_hdl,
		    (uint32_t *)(base + tbl_offset + (i * 16) + 4)));
		igb_log(igb, IGB_LOG_INFO, "msg_data:\t%x",
		    ddi_get32(acc_hdl,
		    (uint32_t *)(base + tbl_offset + (i * 16) + 8)));
		igb_log(igb, IGB_LOG_INFO, "vct_ctrl:\t%x",
		    ddi_get32(acc_hdl,
		    (uint32_t *)(base + tbl_offset + (i * 16) + 12)));
	}

	igb_log(igb, IGB_LOG_INFO, "MSI-X Pending Bits:\t%x",
	    ddi_get32(acc_hdl, (uint32_t *)(base + pba_offset)));

	ddi_regs_map_free(&acc_hdl);
}
#endif
