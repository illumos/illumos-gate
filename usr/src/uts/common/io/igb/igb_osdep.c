/*
 * CDDL HEADER START
 *
 * Copyright(c) 2007-2008 Intel Corporation. All rights reserved.
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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms of the CDDL.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

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
