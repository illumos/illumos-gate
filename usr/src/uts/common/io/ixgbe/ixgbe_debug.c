/*
 * CDDL HEADER START
 *
 * Copyright(c) 2007-2009 Intel Corporation. All rights reserved.
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
 */

#include "ixgbe_sw.h"
#include "ixgbe_debug.h"

#ifdef IXGBE_DEBUG
extern ddi_device_acc_attr_t ixgbe_regs_acc_attr;

/*
 * Dump interrupt-related registers & structures
 */
void
ixgbe_dump_interrupt(void *adapter, char *tag)
{
	ixgbe_t *ixgbe = (ixgbe_t *)adapter;
	struct ixgbe_hw	*hw = &ixgbe->hw;
	ixgbe_intr_vector_t *vect;
	uint32_t ivar, reg, hw_index;
	int i, j;

	/*
	 * interrupt control registers
	 */
	ixgbe_log(ixgbe, "interrupt: %s\n", tag);
	ixgbe_log(ixgbe, "..eims: 0x%x\n", IXGBE_READ_REG(hw, IXGBE_EIMS));
	ixgbe_log(ixgbe, "..eimc: 0x%x\n", IXGBE_READ_REG(hw, IXGBE_EIMC));
	ixgbe_log(ixgbe, "..eiac: 0x%x\n", IXGBE_READ_REG(hw, IXGBE_EIAC));
	ixgbe_log(ixgbe, "..eiam: 0x%x\n", IXGBE_READ_REG(hw, IXGBE_EIAM));
	ixgbe_log(ixgbe, "..gpie: 0x%x\n", IXGBE_READ_REG(hw, IXGBE_GPIE));
	ixgbe_log(ixgbe, "otherflag: 0x%x\n", ixgbe->capab->other_intr);
	ixgbe_log(ixgbe, "eims_mask: 0x%x\n", ixgbe->eims);

	/* ivar: interrupt vector allocation registers */
	for (i = 0; i < IXGBE_IVAR_REG_NUM; i++) {
		if (ivar = IXGBE_READ_REG(hw, IXGBE_IVAR(i))) {
			ixgbe_log(ixgbe, "ivar[%d]: 0x%x\n", i, ivar);
		}
	}

	/* each allocated vector */
	for (i = 0; i < ixgbe->intr_cnt; i++) {
	vect =  &ixgbe->vect_map[i];
	ixgbe_log(ixgbe,
	    "vector %d  rx rings %d  tx rings %d  eitr: 0x%x\n",
	    i, vect->rxr_cnt, vect->txr_cnt,
	    IXGBE_READ_REG(hw, IXGBE_EITR(i)));

	/* for each rx ring bit set */
	j = bt_getlowbit(vect->rx_map, 0, (ixgbe->num_rx_rings - 1));
	while (j >= 0) {
		hw_index = ixgbe->rx_rings[j].hw_index;
		ixgbe_log(ixgbe, "rx %d  ivar %d  rxdctl: 0x%x  srrctl: 0x%x\n",
		    hw_index, IXGBE_IVAR_RX_QUEUE(hw_index),
		    IXGBE_READ_REG(hw, IXGBE_RXDCTL(hw_index)),
		    IXGBE_READ_REG(hw, IXGBE_SRRCTL(hw_index)));
		j = bt_getlowbit(vect->rx_map, (j + 1),
		    (ixgbe->num_rx_rings - 1));
	}

	/* for each tx ring bit set */
	j = bt_getlowbit(vect->tx_map, 0, (ixgbe->num_tx_rings - 1));
	while (j >= 0) {
		ixgbe_log(ixgbe, "tx %d  ivar %d  txdctl: 0x%x\n",
		    j, IXGBE_IVAR_TX_QUEUE(j),
		    IXGBE_READ_REG(hw, IXGBE_TXDCTL(j)));
		j = bt_getlowbit(vect->tx_map, (j + 1),
		    (ixgbe->num_tx_rings - 1));
	}
	}

	/* reta: RSS redirection table */
	for (i = 0; i < 32; i++) {
		ixgbe_log(ixgbe, "reta(%d): 0x%x\n",
		    i, IXGBE_READ_REG(hw, IXGBE_RETA(i)));
	}

	/* rssrk: RSS random key */
	for (i = 0; i < 10; i++) {
		ixgbe_log(ixgbe, "rssrk(%d): 0x%x\n",
		    i, IXGBE_READ_REG(hw, IXGBE_RSSRK(i)));
	}

	/* check ral/rah */
	ixgbe_log(ixgbe, "-- ral/rah --\n");
	for (i = 0; i < 16; i++) {
		if (reg = IXGBE_READ_REG(hw, IXGBE_RAL(i))) {
			ixgbe_log(ixgbe, "ral(%d): 0x%x  rah(%d): 0x%x\n",
			    i, reg, i, IXGBE_READ_REG(hw, IXGBE_RAH(i)));
		}
	}

	/* check mta */
	ixgbe_log(ixgbe, "-- mta --\n");
	for (i = 0; i < 128; i++) {
		if (reg = IXGBE_READ_REG(hw, IXGBE_MTA(i))) {
			ixgbe_log(ixgbe, "mta(%d): 0x%x\n", i, reg);
		}
	}

	/* check vfta */
	{
	uint32_t off = IXGBE_VFTA(0);
	ixgbe_log(ixgbe, "-- vfta --\n");
	for (i = 0; i < 640; i++) {
		if (reg = IXGBE_READ_REG(hw, off)) {
			ixgbe_log(ixgbe, "vfta(0x%x): 0x%x\n", off, reg);
		}
		off += 4;
	}
	}

	/* check mdef */
	ixgbe_log(ixgbe, "-- mdef --\n");
	for (i = 0; i < 8; i++) {
		if (reg = IXGBE_READ_REG(hw, IXGBE_MDEF(i))) {
			ixgbe_log(ixgbe, "mdef(%d): 0x%x\n", i, reg);
		}
	}
}

/*
 * Dump an ethernet address
 */
void
ixgbe_dump_addr(void *adapter, char *tag, const uint8_t *addr)
{
	ixgbe_t *ixgbe = (ixgbe_t *)adapter;
	char		form[25];

	(void) sprintf(form, "%02x:%02x:%02x:%02x:%02x:%02x",
	    *addr, *(addr + 1), *(addr + 2),
	    *(addr + 3), *(addr + 4), *(addr + 5));

	ixgbe_log(ixgbe, "%s %s\n", tag, form);
}

void
ixgbe_pci_dump(void *arg)
{
	ixgbe_t *ixgbe = (ixgbe_t *)arg;
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

	handle = ixgbe->osdep.cfg_handle;

	ixgbe_log(ixgbe, "Begin dump PCI config space");

	ixgbe_log(ixgbe,
	    "PCI_CONF_VENID:\t0x%x\n",
	    pci_config_get16(handle, PCI_CONF_VENID));
	ixgbe_log(ixgbe,
	    "PCI_CONF_DEVID:\t0x%x\n",
	    pci_config_get16(handle, PCI_CONF_DEVID));
	ixgbe_log(ixgbe,
	    "PCI_CONF_COMMAND:\t0x%x\n",
	    pci_config_get16(handle, PCI_CONF_COMM));
	ixgbe_log(ixgbe,
	    "PCI_CONF_STATUS:\t0x%x\n",
	    pci_config_get16(handle, PCI_CONF_STAT));
	ixgbe_log(ixgbe,
	    "PCI_CONF_REVID:\t0x%x\n",
	    pci_config_get8(handle, PCI_CONF_REVID));
	ixgbe_log(ixgbe,
	    "PCI_CONF_PROG_CLASS:\t0x%x\n",
	    pci_config_get8(handle, PCI_CONF_PROGCLASS));
	ixgbe_log(ixgbe,
	    "PCI_CONF_SUB_CLASS:\t0x%x\n",
	    pci_config_get8(handle, PCI_CONF_SUBCLASS));
	ixgbe_log(ixgbe,
	    "PCI_CONF_BAS_CLASS:\t0x%x\n",
	    pci_config_get8(handle, PCI_CONF_BASCLASS));
	ixgbe_log(ixgbe,
	    "PCI_CONF_CACHE_LINESZ:\t0x%x\n",
	    pci_config_get8(handle, PCI_CONF_CACHE_LINESZ));
	ixgbe_log(ixgbe,
	    "PCI_CONF_LATENCY_TIMER:\t0x%x\n",
	    pci_config_get8(handle, PCI_CONF_LATENCY_TIMER));
	ixgbe_log(ixgbe,
	    "PCI_CONF_HEADER_TYPE:\t0x%x\n",
	    pci_config_get8(handle, PCI_CONF_HEADER));
	ixgbe_log(ixgbe,
	    "PCI_CONF_BIST:\t0x%x\n",
	    pci_config_get8(handle, PCI_CONF_BIST));
	ixgbe_log(ixgbe,
	    "PCI_CONF_BASE0:\t0x%x\n",
	    pci_config_get32(handle, PCI_CONF_BASE0));
	ixgbe_log(ixgbe,
	    "PCI_CONF_BASE1:\t0x%x\n",
	    pci_config_get32(handle, PCI_CONF_BASE1));
	ixgbe_log(ixgbe,
	    "PCI_CONF_BASE2:\t0x%x\n",
	    pci_config_get32(handle, PCI_CONF_BASE2));

	/* MSI-X BAR */
	msix_bar = pci_config_get32(handle, PCI_CONF_BASE3);
	ixgbe_log(ixgbe,
	    "PCI_CONF_BASE3:\t0x%x\n", msix_bar);

	ixgbe_log(ixgbe,
	    "PCI_CONF_BASE4:\t0x%x\n",
	    pci_config_get32(handle, PCI_CONF_BASE4));
	ixgbe_log(ixgbe,
	    "PCI_CONF_BASE5:\t0x%x\n",
	    pci_config_get32(handle, PCI_CONF_BASE5));
	ixgbe_log(ixgbe,
	    "PCI_CONF_CIS:\t0x%x\n",
	    pci_config_get32(handle, PCI_CONF_CIS));
	ixgbe_log(ixgbe,
	    "PCI_CONF_SUBVENID:\t0x%x\n",
	    pci_config_get16(handle, PCI_CONF_SUBVENID));
	ixgbe_log(ixgbe,
	    "PCI_CONF_SUBSYSID:\t0x%x\n",
	    pci_config_get16(handle, PCI_CONF_SUBSYSID));
	ixgbe_log(ixgbe,
	    "PCI_CONF_ROM:\t0x%x\n",
	    pci_config_get32(handle, PCI_CONF_ROM));

	cap_ptr = pci_config_get8(handle, PCI_CONF_CAP_PTR);

	ixgbe_log(ixgbe,
	    "PCI_CONF_CAP_PTR:\t0x%x\n", cap_ptr);
	ixgbe_log(ixgbe,
	    "PCI_CONF_ILINE:\t0x%x\n",
	    pci_config_get8(handle, PCI_CONF_ILINE));
	ixgbe_log(ixgbe,
	    "PCI_CONF_IPIN:\t0x%x\n",
	    pci_config_get8(handle, PCI_CONF_IPIN));
	ixgbe_log(ixgbe,
	    "PCI_CONF_MIN_G:\t0x%x\n",
	    pci_config_get8(handle, PCI_CONF_MIN_G));
	ixgbe_log(ixgbe,
	    "PCI_CONF_MAX_L:\t0x%x\n",
	    pci_config_get8(handle, PCI_CONF_MAX_L));

	/* Power Management */
	offset = cap_ptr;

	ixgbe_log(ixgbe,
	    "PCI_PM_CAP_ID:\t0x%x\n",
	    pci_config_get8(handle, offset));

	next_ptr = pci_config_get8(handle, offset + 1);

	ixgbe_log(ixgbe,
	    "PCI_PM_NEXT_PTR:\t0x%x\n", next_ptr);
	ixgbe_log(ixgbe,
	    "PCI_PM_CAP:\t0x%x\n",
	    pci_config_get16(handle, offset + PCI_PMCAP));
	ixgbe_log(ixgbe,
	    "PCI_PM_CSR:\t0x%x\n",
	    pci_config_get16(handle, offset + PCI_PMCSR));
	ixgbe_log(ixgbe,
	    "PCI_PM_CSR_BSE:\t0x%x\n",
	    pci_config_get8(handle, offset + PCI_PMCSR_BSE));
	ixgbe_log(ixgbe,
	    "PCI_PM_DATA:\t0x%x\n",
	    pci_config_get8(handle, offset + PCI_PMDATA));

	/* MSI Configuration */
	offset = next_ptr;

	ixgbe_log(ixgbe,
	    "PCI_MSI_CAP_ID:\t0x%x\n",
	    pci_config_get8(handle, offset));

	next_ptr = pci_config_get8(handle, offset + 1);

	ixgbe_log(ixgbe,
	    "PCI_MSI_NEXT_PTR:\t0x%x\n", next_ptr);
	ixgbe_log(ixgbe,
	    "PCI_MSI_CTRL:\t0x%x\n",
	    pci_config_get16(handle, offset + PCI_MSI_CTRL));
	ixgbe_log(ixgbe,
	    "PCI_MSI_ADDR:\t0x%x\n",
	    pci_config_get32(handle, offset + PCI_MSI_ADDR_OFFSET));
	ixgbe_log(ixgbe,
	    "PCI_MSI_ADDR_HI:\t0x%x\n",
	    pci_config_get32(handle, offset + 0x8));
	ixgbe_log(ixgbe,
	    "PCI_MSI_DATA:\t0x%x\n",
	    pci_config_get16(handle, offset + 0xC));

	/* MSI-X Configuration */
	offset = next_ptr;

	ixgbe_log(ixgbe,
	    "PCI_MSIX_CAP_ID:\t0x%x\n",
	    pci_config_get8(handle, offset));

	next_ptr = pci_config_get8(handle, offset + 1);
	ixgbe_log(ixgbe,
	    "PCI_MSIX_NEXT_PTR:\t0x%x\n", next_ptr);

	msix_ctrl = pci_config_get16(handle, offset + PCI_MSIX_CTRL);
	msix_tbl_sz = msix_ctrl & 0x7ff;
	ixgbe_log(ixgbe,
	    "PCI_MSIX_CTRL:\t0x%x\n", msix_ctrl);

	tbl_offset = pci_config_get32(handle, offset + PCI_MSIX_TBL_OFFSET);
	tbl_bir = tbl_offset & PCI_MSIX_TBL_BIR_MASK;
	tbl_offset = tbl_offset & ~PCI_MSIX_TBL_BIR_MASK;
	ixgbe_log(ixgbe,
	    "PCI_MSIX_TBL_OFFSET:\t0x%x\n", tbl_offset);
	ixgbe_log(ixgbe,
	    "PCI_MSIX_TBL_BIR:\t0x%x\n", tbl_bir);

	pba_offset = pci_config_get32(handle, offset + PCI_MSIX_PBA_OFFSET);
	pba_bir = pba_offset & PCI_MSIX_PBA_BIR_MASK;
	pba_offset = pba_offset & ~PCI_MSIX_PBA_BIR_MASK;
	ixgbe_log(ixgbe,
	    "PCI_MSIX_PBA_OFFSET:\t0x%x\n", pba_offset);
	ixgbe_log(ixgbe,
	    "PCI_MSIX_PBA_BIR:\t0x%x\n", pba_bir);

	/* PCI Express Configuration */
	offset = next_ptr;

	ixgbe_log(ixgbe,
	    "PCIE_CAP_ID:\t0x%x\n",
	    pci_config_get8(handle, offset + PCIE_CAP_ID));

	next_ptr = pci_config_get8(handle, offset + PCIE_CAP_NEXT_PTR);

	ixgbe_log(ixgbe,
	    "PCIE_CAP_NEXT_PTR:\t0x%x\n", next_ptr);
	ixgbe_log(ixgbe,
	    "PCIE_PCIECAP:\t0x%x\n",
	    pci_config_get16(handle, offset + PCIE_PCIECAP));
	ixgbe_log(ixgbe,
	    "PCIE_DEVCAP:\t0x%x\n",
	    pci_config_get32(handle, offset + PCIE_DEVCAP));
	ixgbe_log(ixgbe,
	    "PCIE_DEVCTL:\t0x%x\n",
	    pci_config_get16(handle, offset + PCIE_DEVCTL));
	ixgbe_log(ixgbe,
	    "PCIE_DEVSTS:\t0x%x\n",
	    pci_config_get16(handle, offset + PCIE_DEVSTS));
	ixgbe_log(ixgbe,
	    "PCIE_LINKCAP:\t0x%x\n",
	    pci_config_get32(handle, offset + PCIE_LINKCAP));
	ixgbe_log(ixgbe,
	    "PCIE_LINKCTL:\t0x%x\n",
	    pci_config_get16(handle, offset + PCIE_LINKCTL));
	ixgbe_log(ixgbe,
	    "PCIE_LINKSTS:\t0x%x\n",
	    pci_config_get16(handle, offset + PCIE_LINKSTS));

	/* MSI-X Memory Space */
	if (ddi_dev_regsize(ixgbe->dip, 4, &mem_size) != DDI_SUCCESS) {
		ixgbe_log(ixgbe, "ddi_dev_regsize() failed");
		return;
	}

	if ((ddi_regs_map_setup(ixgbe->dip, 4, (caddr_t *)&base, 0, mem_size,
	    &ixgbe_regs_acc_attr, &acc_hdl)) != DDI_SUCCESS) {
		ixgbe_log(ixgbe, "ddi_regs_map_setup() failed");
		return;
	}

	ixgbe_log(ixgbe, "MSI-X Memory Space: (mem_size = %d, base = %x)",
	    mem_size, base);

	for (i = 0; i <= msix_tbl_sz; i++) {
		ixgbe_log(ixgbe, "MSI-X Table Entry(%d):", i);
		ixgbe_log(ixgbe, "lo_addr:\t%x",
		    ddi_get32(acc_hdl,
		    (uint32_t *)(base + tbl_offset + (i * 16))));
		ixgbe_log(ixgbe, "up_addr:\t%x",
		    ddi_get32(acc_hdl,
		    (uint32_t *)(base + tbl_offset + (i * 16) + 4)));
		ixgbe_log(ixgbe, "msg_data:\t%x",
		    ddi_get32(acc_hdl,
		    (uint32_t *)(base + tbl_offset + (i * 16) + 8)));
		ixgbe_log(ixgbe, "vct_ctrl:\t%x",
		    ddi_get32(acc_hdl,
		    (uint32_t *)(base + tbl_offset + (i * 16) + 12)));
	}

	ixgbe_log(ixgbe, "MSI-X Pending Bits:\t%x",
	    ddi_get32(acc_hdl, (uint32_t *)(base + pba_offset)));

	ddi_regs_map_free(&acc_hdl);
}

/*
 * Dump registers
 */
void
ixgbe_dump_regs(void *adapter)
{
	ixgbe_t *ixgbe = (ixgbe_t *)adapter;
	uint32_t reg_val, hw_index;
	struct ixgbe_hw *hw = &ixgbe->hw;
	int i;
	DEBUGFUNC("ixgbe_dump_regs");

	/* Dump basic's like CTRL, STATUS, CTRL_EXT. */
	ixgbe_log(ixgbe, "Basic IXGBE registers..");
	reg_val = IXGBE_READ_REG(hw, IXGBE_CTRL);
	ixgbe_log(ixgbe, "\tCTRL=%x\n", reg_val);
	reg_val = IXGBE_READ_REG(hw, IXGBE_STATUS);
	ixgbe_log(ixgbe, "\tSTATUS=%x\n", reg_val);
	reg_val = IXGBE_READ_REG(hw, IXGBE_CTRL_EXT);
	ixgbe_log(ixgbe, "\tCTRL_EXT=%x\n", reg_val);
	reg_val = IXGBE_READ_REG(hw, IXGBE_FCTRL);
	ixgbe_log(ixgbe, "\tFCTRL=%x\n", reg_val);

	/* Misc Interrupt regs */
	ixgbe_log(ixgbe, "Some IXGBE interrupt registers..");

	reg_val = IXGBE_READ_REG(hw, IXGBE_GPIE);
	ixgbe_log(ixgbe, "\tGPIE=%x\n", reg_val);

	reg_val = IXGBE_READ_REG(hw, IXGBE_IVAR(0));
	ixgbe_log(ixgbe, "\tIVAR(0)=%x\n", reg_val);

	reg_val = IXGBE_READ_REG(hw, IXGBE_IVAR_MISC);
	ixgbe_log(ixgbe, "\tIVAR_MISC=%x\n", reg_val);

	/* Dump RX related reg's */
	ixgbe_log(ixgbe, "Receive registers...");
	reg_val = IXGBE_READ_REG(hw, IXGBE_RXCTRL);
	ixgbe_log(ixgbe, "\tRXCTRL=%x\n", reg_val);
	for (i = 0; i < ixgbe->num_rx_rings; i++) {
		hw_index = ixgbe->rx_rings[i].hw_index;
		reg_val = IXGBE_READ_REG(hw, IXGBE_RXDCTL(hw_index));
		ixgbe_log(ixgbe, "\tRXDCTL(%d)=%x\n", hw_index, reg_val);
		reg_val = IXGBE_READ_REG(hw, IXGBE_SRRCTL(hw_index));
		ixgbe_log(ixgbe, "\tSRRCTL(%d)=%x\n", hw_index, reg_val);
	}
	reg_val = IXGBE_READ_REG(hw, IXGBE_RXCSUM);
	ixgbe_log(ixgbe, "\tRXCSUM=%x\n", reg_val);
	reg_val = IXGBE_READ_REG(hw, IXGBE_MRQC);
	ixgbe_log(ixgbe, "\tMRQC=%x\n", reg_val);
	reg_val = IXGBE_READ_REG(hw, IXGBE_RDRXCTL);
	ixgbe_log(ixgbe, "\tRDRXCTL=%x\n", reg_val);

	/* Dump TX related regs */
	ixgbe_log(ixgbe, "Some transmit registers..");
	reg_val = IXGBE_READ_REG(hw, IXGBE_DMATXCTL);
	ixgbe_log(ixgbe, "\tDMATXCTL=%x\n", reg_val);
	for (i = 0; i < ixgbe->num_tx_rings; i++) {
		reg_val = IXGBE_READ_REG(hw, IXGBE_TXDCTL(i));
		ixgbe_log(ixgbe, "\tTXDCTL(%d)=%x\n", i, reg_val);
		reg_val = IXGBE_READ_REG(hw, IXGBE_TDWBAL(i));
		ixgbe_log(ixgbe, "\tTDWBAL(%d)=%x\n", i, reg_val);
		reg_val = IXGBE_READ_REG(hw, IXGBE_TDWBAH(i));
		ixgbe_log(ixgbe, "\tTDWBAH(%d)=%x\n", i, reg_val);
		reg_val = IXGBE_READ_REG(hw, IXGBE_TXPBSIZE(i));
		ixgbe_log(ixgbe, "\tTXPBSIZE(%d)=%x\n", i, reg_val);
	}
}

#endif
