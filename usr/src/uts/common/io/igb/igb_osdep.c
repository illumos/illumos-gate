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
 * Copyright(c) 2007-2008 Intel Corporation. All rights reserved.
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "igb_osdep.h"
#include "igb_api.h"


s32
e1000_alloc_zeroed_dev_spec_struct(struct e1000_hw *hw, u32 size)
{
	hw->dev_spec = kmem_zalloc(size, KM_SLEEP);

	return (E1000_SUCCESS);
}

void
e1000_free_dev_spec_struct(struct e1000_hw *hw)
{
	if (hw->dev_spec == NULL)
		return;

	kmem_free(hw->dev_spec, hw->dev_spec_size);
	hw->dev_spec = NULL;
}

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
 * The real intent of this routine is to return the value from pci-e
 * config space at offset reg into the capability space.
 * ICH devices are "PCI Express"-ish.  They have a configuration space,
 * but do not contain PCI Express Capability registers, so this returns
 * the equivalent of "not supported"
 */
int32_t
e1000_read_pcie_cap_reg(struct e1000_hw *hw, uint32_t reg, uint16_t *value)
{
	*value = pci_config_get16(OS_DEP(hw)->cfg_handle,
	    PCI_EX_CONF_CAP + reg);

	return (0);
}

/*
 * Enables PCI-Express master access.
 *
 * hw: Struct containing variables accessed by shared code
 *
 * returns: - none.
 */
void
e1000_enable_pciex_master(struct e1000_hw *hw)
{
	uint32_t ctrl;

	if (hw->bus.type != e1000_bus_type_pci_express)
		return;

	ctrl = E1000_READ_REG(hw, E1000_CTRL);
	ctrl &= ~E1000_CTRL_GIO_MASTER_DISABLE;
	E1000_WRITE_REG(hw, E1000_CTRL, ctrl);
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
