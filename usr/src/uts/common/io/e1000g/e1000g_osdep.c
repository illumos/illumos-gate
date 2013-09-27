/*
 * This file is provided under a CDDLv1 license.  When using or
 * redistributing this file, you may do so under this license.
 * In redistributing this file this license must be included
 * and no other modification of this header file is permitted.
 *
 * CDDL LICENSE SUMMARY
 *
 * Copyright(c) 1999 - 2009 Intel Corporation. All rights reserved.
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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
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
 * phy_spd_state - set smart-power-down (SPD) state
 *
 * This only acts on the silicon families that have the SPD feature.
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
	case e1000_82573:
	case e1000_82574:
	case e1000_82583:
		offset = IGP02E1000_PHY_POWER_MGMT;
		spd_bit = IGP02E1000_PM_SPD;
		break;
	default:
		return;		/* no action */
	}

	(void) e1000_read_phy_reg(hw, offset, &reg);

	if (enable)
		reg |= spd_bit;		/* enable: set the spd bit */
	else
		reg &= ~spd_bit;	/* disable: clear the spd bit */

	(void) e1000_write_phy_reg(hw, offset, reg);
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
 * For some hardware types, access to NVM & PHY need to be serialized by mutex.
 * The necessary mutexes will have been created by shared code.  Here we destroy
 * that mutexes for just the hardware types that need it.
 */
void
e1000_destroy_hw_mutex(struct e1000_hw *hw)
{
	struct e1000_dev_spec_ich8lan *dev_spec;

	switch (hw->mac.type) {
	case e1000_ich8lan:
	case e1000_ich9lan:
	case e1000_ich10lan:
	case e1000_pchlan:
		dev_spec = &hw->dev_spec.ich8lan;
		E1000_MUTEX_DESTROY(&dev_spec->nvm_mutex);
		E1000_MUTEX_DESTROY(&dev_spec->swflag_mutex);
		break;

	default:
		break;	/* no action */
	}
}
