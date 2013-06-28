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
 * Use is subject to license terms of the CDDLv1.
 */
#include "e1000_api.h"

/*
 * e1000_ttl_workaround_enabled_82541 - Returns current TTL workaround status
 * @hw: pointer to the HW structure
 *
 * Returns the current status of the TTL workaround, as to whether the
 * workaround is enabled or disabled.
 */
bool
e1000_ttl_workaround_enabled_82541(struct e1000_hw *hw)
{
	struct e1000_dev_spec_82541 *dev_spec = &hw->dev_spec._82541;
	bool state = false;

	DEBUGFUNC("e1000_ttl_workaround_enabled_82541");

	if ((hw->mac.type != e1000_82541) && (hw->mac.type != e1000_82547))
		goto out;

	state = dev_spec->ttl_workaround;

out:
	return (state);
}

/*
 * e1000_fifo_workaround_82547 - Workaround for Tx fifo failure
 * @hw: pointer to the HW structure
 * @length: length of next outgoing frame
 *
 * Returns: E1000_ERR_FIFO_WRAP if the next packet cannot be transmitted yet
 *	E1000_SUCCESS if the next packet can be transmitted
 *
 * Workaround for the 82547 Tx fifo failure.
 */
s32
e1000_fifo_workaround_82547(struct e1000_hw *hw, u16 length)
{
	struct e1000_dev_spec_82541 *dev_spec = &hw->dev_spec._82541;
	u32 tctl;
	s32 ret_val = E1000_SUCCESS;
	u16 fifo_pkt_len;

	DEBUGFUNC("e1000_fifo_workaround_82547");

	if (hw->mac.type != e1000_82547)
		goto out;

	/*
	 * Get the length as seen by the FIFO of the next real
	 * packet to be transmitted.
	 */
	fifo_pkt_len = E1000_ROUNDUP(length + E1000_FIFO_HDR_SIZE,
	    E1000_FIFO_GRANULARITY);

	if (fifo_pkt_len <= (E1000_FIFO_PAD_82547 + E1000_FIFO_HDR_SIZE))
		goto out;

	if ((dev_spec->tx_fifo_head + fifo_pkt_len) <
	    (dev_spec->tx_fifo_size + E1000_FIFO_PAD_82547))
		goto out;

	if (E1000_READ_REG(hw, E1000_TDT(0)) !=
	    E1000_READ_REG(hw, E1000_TDH(0))) {
		ret_val = -E1000_ERR_FIFO_WRAP;
		goto out;
	}

	if (E1000_READ_REG(hw, E1000_TDFT) != E1000_READ_REG(hw, E1000_TDFH)) {
		ret_val = -E1000_ERR_FIFO_WRAP;
		goto out;
	}

	if (E1000_READ_REG(hw, E1000_TDFTS) !=
	    E1000_READ_REG(hw, E1000_TDFHS)) {
		ret_val = -E1000_ERR_FIFO_WRAP;
		goto out;
	}

	/* Disable the tx unit to avoid further pointer movement */
	tctl = E1000_READ_REG(hw, E1000_TCTL);
	E1000_WRITE_REG(hw, E1000_TCTL, tctl & ~E1000_TCTL_EN);

	/* Reset the fifo pointers. */
	E1000_WRITE_REG(hw, E1000_TDFT, dev_spec->tx_fifo_start);
	E1000_WRITE_REG(hw, E1000_TDFH, dev_spec->tx_fifo_start);
	E1000_WRITE_REG(hw, E1000_TDFTS, dev_spec->tx_fifo_start);
	E1000_WRITE_REG(hw, E1000_TDFHS, dev_spec->tx_fifo_start);

	/* Re-enabling tx unit */
	E1000_WRITE_REG(hw, E1000_TCTL, tctl);
	E1000_WRITE_FLUSH(hw);

	dev_spec->tx_fifo_head = 0;

out:
	return (ret_val);
}

/*
 * e1000_update_tx_fifo_head - Update Tx fifo head pointer
 * @hw: pointer to the HW structure
 * @length: length of next outgoing frame
 *
 * Updates the SW calculated Tx FIFO head pointer.
 */
void
e1000_update_tx_fifo_head_82547(struct e1000_hw *hw, u32 length)
{
	struct e1000_dev_spec_82541 *dev_spec = &hw->dev_spec._82541;

	DEBUGFUNC("e1000_update_tx_fifo_head_82547");

	if (hw->mac.type != e1000_82547)
		return;

	dev_spec->tx_fifo_head += E1000_ROUNDUP(length + E1000_FIFO_HDR_SIZE,
	    E1000_FIFO_GRANULARITY);

	if (dev_spec->tx_fifo_head > dev_spec->tx_fifo_size)
		dev_spec->tx_fifo_head -= dev_spec->tx_fifo_size;
}

/*
 * e1000_set_ttl_workaround_state_82541 - Enable/Disables TTL workaround
 * @hw: pointer to the HW structure
 * @state: boolean to enable/disable TTL workaround
 *
 * For 82541 or 82547 only silicon, allows the driver to enable/disable the
 * TTL workaround.
 */
void
e1000_set_ttl_workaround_state_82541(struct e1000_hw *hw, bool state)
{
	struct e1000_dev_spec_82541 *dev_spec = &hw->dev_spec._82541;

	DEBUGFUNC("e1000_set_ttl_workaround_state_82541");

	if ((hw->mac.type != e1000_82541) && (hw->mac.type != e1000_82547))
		return;

	dev_spec->ttl_workaround = state;
}

/*
 * e1000_igp_ttl_workaround_82547 - Workaround for long TTL on 100HD hubs
 * @hw: pointer to the HW structure
 *
 * Returns: E1000_ERR_PHY if fail to read/write the PHY
 *          E1000_SUCCESS in any other case
 *
 * This function, specific to 82547 hardware only, needs to be called every
 * second.  It checks if a parallel detect fault has occurred.  If a fault
 * occurred, disable/enable the DSP reset mechanism up to 5 times (once per
 * second).  If link is established, stop the workaround and ensure the DSP
 * reset is enabled.
 */
s32
e1000_igp_ttl_workaround_82547(struct e1000_hw *hw)
{
	struct e1000_dev_spec_82541 *dev_spec = &hw->dev_spec._82541;
	s32 ret_val = E1000_SUCCESS;
	u16 phy_data = 0;
	u16 dsp_value = DSP_RESET_ENABLE;
	bool link;

	DEBUGFUNC("e1000_igp_ttl_workaround_82547");

	/* The workaround needed only for B-0 silicon HW */
	if ((hw->mac.type != e1000_82541) && (hw->mac.type != e1000_82547))
		goto out;

	if (!(e1000_ttl_workaround_enabled_82541(hw)))
		goto out;

	/* Check for link first */
	ret_val = e1000_phy_has_link_generic(hw, 1, 0, &link);
	if (ret_val)
		goto out;

	if (link) {
		/*
		 * If link is established during the workaround,
		 * the DSP mechanism must be enabled.
		 */
		if (dev_spec->dsp_reset_counter) {
			dev_spec->dsp_reset_counter = 0;
			dsp_value = DSP_RESET_ENABLE;
		} else {
			ret_val = E1000_SUCCESS;
			goto out;
		}
	} else {
		if (dev_spec->dsp_reset_counter == 0) {
			/*
			 * Workaround not activated,
			 * check if it needs activation
			 */
			ret_val = hw->phy.ops.read_reg(hw,
			    PHY_AUTONEG_EXP,
			    &phy_data);
			if (ret_val)
				goto out;
			/*
			 * Activate the workaround if there was a
			 * parallel detect fault
			 */
			if (phy_data & NWAY_ER_PAR_DETECT_FAULT) {
				dev_spec->dsp_reset_counter++;
			} else {
				ret_val = E1000_SUCCESS;
				goto out;
			}
		}

		/* After 5 times, stop the workaround */
		if (dev_spec->dsp_reset_counter > E1000_MAX_DSP_RESETS) {
			dev_spec->dsp_reset_counter = 0;
			dsp_value = DSP_RESET_ENABLE;
		} else {
			if (dev_spec->dsp_reset_counter) {
				dsp_value = (dev_spec->dsp_reset_counter & 1)
				    ? DSP_RESET_DISABLE
				    : DSP_RESET_ENABLE;
				dev_spec->dsp_reset_counter++;
			}
		}
	}

	ret_val =
	    hw->phy.ops.write_reg(hw, IGP01E1000_PHY_DSP_RESET, dsp_value);

out:
	return (ret_val);
}
