/*
 * This file is provided under a CDDLv1 license.  When using or
 * redistributing this file, you may do so under this license.
 * In redistributing this file this license must be included
 * and no other modification of this header file is permitted.
 *
 * CDDL LICENSE SUMMARY
 *
 * Copyright(c) 1999 - 2008 Intel Corporation. All rights reserved.
 *
 * The contents of this file are subject to the terms of Version
 * 1.0 of the Common Development and Distribution License (the "License").
 *
 * You should have received a copy of the License with this software.
 * You can obtain a copy of the License at
 *	http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */

/*
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms of the CDDLv1.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "e1000_osdep.h"
#include "e1000_api.h"


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
 * phy_spd_state - set smart-power-down (SPD) state
 *
 * This only acts on the 82541/47 family and the 82571/72 family.
 * For any others, return without doing anything.
 */
void
phy_spd_state(struct e1000_hw *hw, boolean_t enable)
{
	int32_t offset;		/* offset to register */
	uint16_t spd_bit;	/* bit to be set */
	uint16_t reg;		/* register contents */

	switch (hw->mac.type) {
	case e1000_82541:
	case e1000_82547:
	case e1000_82541_rev_2:
	case e1000_82547_rev_2:
		offset = IGP01E1000_GMII_FIFO;
		spd_bit = IGP01E1000_GMII_SPD;
		break;
	case e1000_82571:
	case e1000_82572:
		offset = IGP02E1000_PHY_POWER_MGMT;
		spd_bit = IGP02E1000_PM_SPD;
		break;
	default:
		return;		/* no action */
	}

	e1000_read_phy_reg(hw, offset, &reg);

	if (enable)
		reg |= spd_bit;		/* enable: set the spd bit */
	else
		reg &= ~spd_bit;	/* disable: clear the spd bit */

	e1000_write_phy_reg(hw, offset, reg);
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
 * e1000g_get_driver_control - tell manageability firmware that the driver
 * has control.
 */
void
e1000g_get_driver_control(struct e1000_hw *hw)
{
	uint32_t ctrl_ext;
	uint32_t swsm;

	/* tell manageability firmware the driver has taken over */
	switch (hw->mac.type) {
	case e1000_82573:
		swsm = E1000_READ_REG(hw, E1000_SWSM);
		E1000_WRITE_REG(hw, E1000_SWSM, swsm | E1000_SWSM_DRV_LOAD);
		break;
	case e1000_82571:
	case e1000_82572:
	case e1000_80003es2lan:
	case e1000_ich8lan:
	case e1000_ich9lan:
		ctrl_ext = E1000_READ_REG(hw, E1000_CTRL_EXT);
		E1000_WRITE_REG(hw, E1000_CTRL_EXT,
		    ctrl_ext | E1000_CTRL_EXT_DRV_LOAD);
		break;
	default:
		/* no manageability firmware: do nothing */
		break;
	}
}
