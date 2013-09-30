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

#include "e1000_osdep.h"
#include "e1000_api.h"

void
e1000_pci_set_mwi(struct e1000_hw *hw)
{
	uint16_t val = hw->bus.pci_cmd_word | CMD_MEM_WRT_INVALIDATE;

	e1000_write_pci_cfg(hw, PCI_COMMAND_REGISTER, &val);
}

void
e1000_pci_clear_mwi(struct e1000_hw *hw)
{
	uint16_t val = hw->bus.pci_cmd_word & ~CMD_MEM_WRT_INVALIDATE;

	e1000_write_pci_cfg(hw, PCI_COMMAND_REGISTER, &val);
}

void
e1000_write_pci_cfg(struct e1000_hw *hw, uint32_t reg, uint16_t *value)
{
	pci_config_put16(OS_DEP(hw)->cfg_handle, reg, *value);
}

void
e1000_read_pci_cfg(struct e1000_hw *hw, uint32_t reg, uint16_t *value)
{
	*value =
	    pci_config_get16(OS_DEP(hw)->cfg_handle, reg);
}

/*
 * Return the 16-bit value from pci-e config space at offset reg into the pci-e
 * capability block.  Note that this refers to the pci-e capability block in
 * standard pci config space, not the block in pci-e extended config space.
 */
int32_t
e1000_read_pcie_cap_reg(struct e1000_hw *hw, uint32_t reg, uint16_t *value)
{
	uint8_t pcie_id = PCI_CAP_ID_PCI_E;
	uint16_t pcie_cap;
	int32_t status;

	/* locate the pci-e capability block */
	status = pci_lcap_locate((OS_DEP(hw))->cfg_handle, pcie_id, &pcie_cap);
	if (status == DDI_SUCCESS) {

		/* read at given offset into block */
		*value = pci_config_get16(OS_DEP(hw)->cfg_handle,
		    (pcie_cap + reg));
	}

	return (status);
}

/*
 * Write the given 16-bit value to pci-e config space at offset reg into the
 * pci-e capability block.  Note that this refers to the pci-e capability block
 * in standard pci config space, not the block in pci-e extended config space.
 */
int32_t
e1000_write_pcie_cap_reg(struct e1000_hw *hw, uint32_t reg, uint16_t *value)
{
	uint8_t pcie_id = PCI_CAP_ID_PCI_E;
	uint16_t pcie_cap;
	int32_t status;

	/* locate the pci-e capability block */
	status = pci_lcap_locate(OS_DEP(hw)->cfg_handle, pcie_id, &pcie_cap);
	if (status == DDI_SUCCESS) {

		/* write at given offset into block */
		pci_config_put16(OS_DEP(hw)->cfg_handle,
		    (off_t)(pcie_cap + reg), *value);
	}

	return (status);
}

/*
 * e1000_rar_set_vmdq - Clear the RAR registers
 */
void
e1000_rar_clear(struct e1000_hw *hw, uint32_t index)
{

	uint32_t rar_high;

	/* Make the hardware the Address invalid by setting the clear bit */
	rar_high = ~E1000_RAH_AV;

	E1000_WRITE_REG_ARRAY(hw, E1000_RA, ((index << 1) + 1), rar_high);
	E1000_WRITE_FLUSH(hw);
}

/*
 * e1000_rar_set_vmdq - Set the RAR registers for VMDq
 */
void
e1000_rar_set_vmdq(struct e1000_hw *hw, const uint8_t *addr, uint32_t index,
	uint32_t vmdq_mode, uint8_t qsel)
{
	uint32_t rar_low, rar_high;

	/*
	 * NIC expects these in little endian so reverse the byte order
	 * from network order (big endian) to little endian.
	 */

	rar_low = ((uint32_t)addr[0] | ((uint32_t)addr[1] << 8) |
	    ((uint32_t)addr[2] << 16) | ((uint32_t)addr[3] << 24));

	rar_high = ((uint32_t)addr[4] | ((uint32_t)addr[5] << 8));

	/* Indicate to hardware the Address is Valid. */
	rar_high |= E1000_RAH_AV;

	/* Set que selector based on vmdq mode */
	switch (vmdq_mode) {
	default:
	case E1000_VMDQ_OFF:
		break;
	case E1000_VMDQ_MAC:
		rar_high |= (qsel << 18);
		break;
	case E1000_VMDQ_MAC_RSS:
		rar_high |= 1 << (18 + qsel);
		break;

	}

	/* write to receive address registers */
	E1000_WRITE_REG_ARRAY(hw, E1000_RA, (index << 1), rar_low);
	E1000_WRITE_REG_ARRAY(hw, E1000_RA, ((index << 1) + 1), rar_high);
	E1000_WRITE_FLUSH(hw);
}
