/*
 * CDDL HEADER START
 *
 * Copyright(c) 2007-2008 Intel Corporation. All rights reserved.
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at:
 *      http://www.opensolaris.org/os/licensing.
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

/* IntelVersion: 1.87 v2008-03-04 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "ixgbe_type.h"
#include "ixgbe_api.h"
#include "ixgbe_common.h"
#include "ixgbe_phy.h"


s32 ixgbe_init_ops_82598(struct ixgbe_hw *hw);
s32 ixgbe_get_link_capabilities_82598(struct ixgbe_hw *hw,
    ixgbe_link_speed *speed, bool *autoneg);
s32 ixgbe_get_copper_link_capabilities_82598(struct ixgbe_hw *hw,
    ixgbe_link_speed *speed, bool *autoneg);
enum ixgbe_media_type ixgbe_get_media_type_82598(struct ixgbe_hw *hw);
s32 ixgbe_setup_fc_82598(struct ixgbe_hw *hw, s32 packetbuf_num);
s32 ixgbe_setup_mac_link_82598(struct ixgbe_hw *hw);
s32 ixgbe_check_mac_link_82598(struct ixgbe_hw *hw,
    ixgbe_link_speed *speed, bool *link_up);
s32 ixgbe_setup_mac_link_speed_82598(struct ixgbe_hw *hw,
    ixgbe_link_speed speed, bool autoneg,
    bool autoneg_wait_to_complete);
s32 ixgbe_setup_copper_link_82598(struct ixgbe_hw *hw);
s32 ixgbe_setup_copper_link_speed_82598(struct ixgbe_hw *hw,
    ixgbe_link_speed speed, bool autoneg, bool autoneg_wait_to_complete);
s32 ixgbe_reset_hw_82598(struct ixgbe_hw *hw);
s32 ixgbe_set_vmdq_82598(struct ixgbe_hw *hw, u32 rar, u32 vmdq);
s32 ixgbe_blink_led_stop_82598(struct ixgbe_hw *hw, u32 index);
s32 ixgbe_blink_led_start_82598(struct ixgbe_hw *hw, u32 index);

/*
 * ixgbe_init_ops_82598 - Inits func ptrs and MAC type
 * @hw: pointer to hardware structure
 *
 * Initialize the function pointers and assign the MAC type for 82598.
 * Does not touch the hardware.
 */
s32
ixgbe_init_ops_82598(struct ixgbe_hw *hw)
{
	struct ixgbe_mac_info *mac = &hw->mac;

	(void) ixgbe_init_phy_ops_generic(hw);
	(void) ixgbe_init_ops_generic(hw);

	/* MAC */
	mac->ops.reset_hw = &ixgbe_reset_hw_82598;
	mac->ops.get_media_type = &ixgbe_get_media_type_82598;

	/* LEDs */
	mac->ops.blink_led_start = &ixgbe_blink_led_start_82598;
	mac->ops.blink_led_stop = &ixgbe_blink_led_stop_82598;

	/* RAR, Multicast, VLAN */
	mac->ops.set_vmdq = &ixgbe_set_vmdq_82598;

	/* Flow Control */
	mac->ops.setup_fc = &ixgbe_setup_fc_82598;


	/* Link */
	mac->ops.check_link = &ixgbe_check_mac_link_82598;
	if (mac->ops.get_media_type(hw) == ixgbe_media_type_copper) {
		mac->ops.setup_link = &ixgbe_setup_copper_link_82598;
		mac->ops.setup_link_speed =
		    &ixgbe_setup_copper_link_speed_82598;
		mac->ops.get_link_capabilities =
		    &ixgbe_get_copper_link_capabilities_82598;
	} else {
		mac->ops.setup_link = &ixgbe_setup_mac_link_82598;
		mac->ops.setup_link_speed = &ixgbe_setup_mac_link_speed_82598;
		mac->ops.get_link_capabilities =
		    &ixgbe_get_link_capabilities_82598;
	}

	mac->mcft_size = 128;
	mac->vft_size = 128;
	mac->num_rar_entries = 16;
	mac->max_tx_queues = 32;
	mac->max_rx_queues = 64;

	return (IXGBE_SUCCESS);
}

/*
 * ixgbe_get_link_capabilities_82598 - Determines link capabilities
 * @hw: pointer to hardware structure
 * @speed: pointer to link speed
 * @autoneg: boolean auto-negotiation value
 *
 * Determines the link capabilities by reading the AUTOC register.
 */
s32
ixgbe_get_link_capabilities_82598(struct ixgbe_hw *hw,
    ixgbe_link_speed *speed,
    bool *autoneg)
{
	s32 status = IXGBE_SUCCESS;
	s32 autoc_reg;

	autoc_reg = IXGBE_READ_REG(hw, IXGBE_AUTOC);

	if (hw->mac.link_settings_loaded) {
		autoc_reg &= ~IXGBE_AUTOC_LMS_ATTACH_TYPE;
		autoc_reg &= ~IXGBE_AUTOC_LMS_MASK;
		autoc_reg |= hw->mac.link_attach_type;
		autoc_reg |= hw->mac.link_mode_select;
	}

	switch (autoc_reg & IXGBE_AUTOC_LMS_MASK) {
	case IXGBE_AUTOC_LMS_1G_LINK_NO_AN:
		*speed = IXGBE_LINK_SPEED_1GB_FULL;
		*autoneg = FALSE;
		break;

	case IXGBE_AUTOC_LMS_10G_LINK_NO_AN:
		*speed = IXGBE_LINK_SPEED_10GB_FULL;
		*autoneg = FALSE;
		break;

	case IXGBE_AUTOC_LMS_1G_AN:
		*speed = IXGBE_LINK_SPEED_1GB_FULL;
		*autoneg = TRUE;
		break;

	case IXGBE_AUTOC_LMS_KX4_AN:
	case IXGBE_AUTOC_LMS_KX4_AN_1G_AN:
		*speed = IXGBE_LINK_SPEED_UNKNOWN;
		if (autoc_reg & IXGBE_AUTOC_KX4_SUPP)
			*speed |= IXGBE_LINK_SPEED_10GB_FULL;
		if (autoc_reg & IXGBE_AUTOC_KX_SUPP)
			*speed |= IXGBE_LINK_SPEED_1GB_FULL;
		*autoneg = TRUE;
		break;

	default:
		status = IXGBE_ERR_LINK_SETUP;
		break;
	}

	return (status);
}

/*
 * ixgbe_get_copper_link_capabilities_82598 - Determines link capabilities
 * @hw: pointer to hardware structure
 * @speed: pointer to link speed
 * @autoneg: boolean auto-negotiation value
 *
 * Determines the link capabilities by reading the AUTOC register.
 */
s32
ixgbe_get_copper_link_capabilities_82598(struct ixgbe_hw *hw,
    ixgbe_link_speed *speed,
    bool *autoneg)
{
	s32 status = IXGBE_ERR_LINK_SETUP;
	u16 speed_ability;

	*speed = 0;
	*autoneg = TRUE;

	status = hw->phy.ops.read_reg(hw, IXGBE_MDIO_PHY_SPEED_ABILITY,
	    IXGBE_MDIO_PMA_PMD_DEV_TYPE,
	    &speed_ability);

	if (status == IXGBE_SUCCESS) {
		if (speed_ability & IXGBE_MDIO_PHY_SPEED_10G)
			*speed |= IXGBE_LINK_SPEED_10GB_FULL;
		if (speed_ability & IXGBE_MDIO_PHY_SPEED_1G)
			*speed |= IXGBE_LINK_SPEED_1GB_FULL;
	}

	return (status);
}

/*
 * ixgbe_get_media_type_82598 - Determines media type
 * @hw: pointer to hardware structure
 *
 * Returns the media type (fiber, copper, backplane)
 */
enum ixgbe_media_type
ixgbe_get_media_type_82598(struct ixgbe_hw *hw)
{
	enum ixgbe_media_type media_type;

	/* Media type for I82598 is based on device ID */
	switch (hw->device_id) {
	case IXGBE_DEV_ID_82598AF_DUAL_PORT:
	case IXGBE_DEV_ID_82598AF_SINGLE_PORT:
	case IXGBE_DEV_ID_82598EB_CX4:
	case IXGBE_DEV_ID_82598_CX4_DUAL_PORT:
	case IXGBE_DEV_ID_82598EB_XF_LR:
		media_type = ixgbe_media_type_fiber;
		break;
	default:
		media_type = ixgbe_media_type_unknown;
		break;
	}

	return (media_type);
}

/*
 * ixgbe_setup_fc_82598 - Configure flow control settings
 * @hw: pointer to hardware structure
 * @packetbuf_num: packet buffer number (0-7)
 *
 * Configures the flow control settings based on SW configuration.  This
 * function is used for 802.3x flow control configuration only.
 */
s32
ixgbe_setup_fc_82598(struct ixgbe_hw *hw, s32 packetbuf_num)
{
	u32 frctl_reg;
	u32 rmcs_reg;

	if (packetbuf_num < 0 || packetbuf_num > 7) {
		DEBUGOUT1("Invalid packet buffer number [%d], expected range is"
		    " 0-7\n", packetbuf_num);
		ASSERT(0);
	}

	frctl_reg = IXGBE_READ_REG(hw, IXGBE_FCTRL);
	frctl_reg &= ~(IXGBE_FCTRL_RFCE | IXGBE_FCTRL_RPFCE);

	rmcs_reg = IXGBE_READ_REG(hw, IXGBE_RMCS);
	rmcs_reg &= ~(IXGBE_RMCS_TFCE_PRIORITY | IXGBE_RMCS_TFCE_802_3X);

	/*
	 * 10 gig parts do not have a word in the EEPROM to determine the
	 * default flow control setting, so we explicitly set it to full.
	 */
	if (hw->fc.type == ixgbe_fc_default)
		hw->fc.type = ixgbe_fc_full;

	/*
	 * We want to save off the original Flow Control configuration just in
	 * case we get disconnected and then reconnected into a different hub
	 * or switch with different Flow Control capabilities.
	 */
	hw->fc.original_type = hw->fc.type;

	/*
	 * The possible values of the "flow_control" parameter are:
	 * 0: Flow control is completely disabled
	 * 1: Rx flow control is enabled (we can receive pause frames but not
	 *    send pause frames).
	 * 2: Tx flow control is enabled (we can send pause frames but we do not
	 *    support receiving pause frames)
	 * 3: Both Rx and Tx flow control (symmetric) are enabled.
	 * other: Invalid.
	 */
	switch (hw->fc.type) {
	case ixgbe_fc_none:
		break;
	case ixgbe_fc_rx_pause:
		/*
		 * Rx Flow control is enabled,
		 * and Tx Flow control is disabled.
		 */
		frctl_reg |= IXGBE_FCTRL_RFCE;
		break;
	case ixgbe_fc_tx_pause:
		/*
		 * Tx Flow control is enabled, and Rx Flow control is disabled,
		 * by a software over-ride.
		 */
		rmcs_reg |= IXGBE_RMCS_TFCE_802_3X;
		break;
	case ixgbe_fc_full:
		/*
		 * Flow control (both Rx and Tx) is enabled by a software
		 * over-ride.
		 */
		frctl_reg |= IXGBE_FCTRL_RFCE;
		rmcs_reg |= IXGBE_RMCS_TFCE_802_3X;
		break;
	default:
		/* We should never get here.  The value should be 0-3. */
		DEBUGOUT("Flow control param set incorrectly\n");
		ASSERT(0);
		break;
	}

	/* Enable 802.3x based flow control settings. */
	IXGBE_WRITE_REG(hw, IXGBE_FCTRL, frctl_reg);
	IXGBE_WRITE_REG(hw, IXGBE_RMCS, rmcs_reg);

	/*
	 * Check for invalid software configuration, zeros are completely
	 * invalid for all parameters used past this point, and if we enable
	 * flow control with zero water marks, we blast flow control packets.
	 */
	if (!hw->fc.low_water || !hw->fc.high_water || !hw->fc.pause_time) {
		DEBUGOUT("Flow control structure initialized incorrectly\n");
		return (IXGBE_ERR_INVALID_LINK_SETTINGS);
	}

	/*
	 * We need to set up the Receive Threshold high and low water
	 * marks as well as (optionally) enabling the transmission of
	 * XON frames.
	 */
	if (hw->fc.type & ixgbe_fc_tx_pause) {
		if (hw->fc.send_xon) {
			IXGBE_WRITE_REG(hw, IXGBE_FCRTL(packetbuf_num),
			    (hw->fc.low_water | IXGBE_FCRTL_XONE));
		} else {
			IXGBE_WRITE_REG(hw, IXGBE_FCRTL(packetbuf_num),
			    hw->fc.low_water);
		}
		IXGBE_WRITE_REG(hw, IXGBE_FCRTH(packetbuf_num),
		    (hw->fc.high_water)|IXGBE_FCRTH_FCEN);
	}

	IXGBE_WRITE_REG(hw, IXGBE_FCTTV(0), hw->fc.pause_time);
	IXGBE_WRITE_REG(hw, IXGBE_FCRTV, (hw->fc.pause_time >> 1));

	return (IXGBE_SUCCESS);
}

/*
 * ixgbe_setup_mac_link_82598 - Configures MAC link settings
 * @hw: pointer to hardware structure
 *
 * Configures link settings based on values in the ixgbe_hw struct.
 * Restarts the link.  Performs autonegotiation if needed.
 */
s32
ixgbe_setup_mac_link_82598(struct ixgbe_hw *hw)
{
	u32 autoc_reg;
	u32 links_reg;
	u32 i;
	s32 status = IXGBE_SUCCESS;

	autoc_reg = IXGBE_READ_REG(hw, IXGBE_AUTOC);

	if (hw->mac.link_settings_loaded) {
		autoc_reg &= ~IXGBE_AUTOC_LMS_ATTACH_TYPE;
		autoc_reg &= ~IXGBE_AUTOC_LMS_MASK;
		autoc_reg |= hw->mac.link_attach_type;
		autoc_reg |= hw->mac.link_mode_select;

		IXGBE_WRITE_REG(hw, IXGBE_AUTOC, autoc_reg);
		IXGBE_WRITE_FLUSH(hw);
		msec_delay(50);
	}

	/* Restart link */
	autoc_reg |= IXGBE_AUTOC_AN_RESTART;
	IXGBE_WRITE_REG(hw, IXGBE_AUTOC, autoc_reg);

	/* Only poll for autoneg to complete if specified to do so */
	if (hw->phy.autoneg_wait_to_complete) {
		if (hw->mac.link_mode_select == IXGBE_AUTOC_LMS_KX4_AN ||
		    hw->mac.link_mode_select == IXGBE_AUTOC_LMS_KX4_AN_1G_AN) {
			links_reg = 0; /* Just in case Autoneg time = 0 */
			for (i = 0; i < IXGBE_AUTO_NEG_TIME; i++) {
				links_reg = IXGBE_READ_REG(hw, IXGBE_LINKS);
				if (links_reg & IXGBE_LINKS_KX_AN_COMP)
					break;
				msec_delay(100);
			}
			if (!(links_reg & IXGBE_LINKS_KX_AN_COMP)) {
				status = IXGBE_ERR_AUTONEG_NOT_COMPLETE;
				DEBUGOUT("Autonegotiation did not complete.\n");
			}
		}
	}

	/*
	 * We want to save off the original Flow Control configuration just in
	 * case we get disconnected and then reconnected into a different hub
	 * or switch with different Flow Control capabilities.
	 */
	hw->fc.original_type = hw->fc.type;
	(void) ixgbe_setup_fc_82598(hw, 0);

	/* Add delay to filter out noises during initial link setup */
	msec_delay(50);

	return (status);
}

/*
 * ixgbe_check_mac_link_82598 - Get link/speed status
 * @hw: pointer to hardware structure
 * @speed: pointer to link speed
 * @link_up: TRUE is link is up, FALSE otherwise
 *
 * Reads the links register to determine if link is up and the current speed
 */
s32
ixgbe_check_mac_link_82598(struct ixgbe_hw *hw, ixgbe_link_speed *speed,
    bool *link_up)
{
	u32 links_reg;

	links_reg = IXGBE_READ_REG(hw, IXGBE_LINKS);

	if (links_reg & IXGBE_LINKS_UP)
		*link_up = TRUE;
	else
		*link_up = FALSE;

	if (links_reg & IXGBE_LINKS_SPEED)
		*speed = IXGBE_LINK_SPEED_10GB_FULL;
	else
		*speed = IXGBE_LINK_SPEED_1GB_FULL;

	return (IXGBE_SUCCESS);
}


/*
 * ixgbe_setup_mac_link_speed_82598 - Set MAC link speed
 * @hw: pointer to hardware structure
 * @speed: new link speed
 * @autoneg: TRUE if auto-negotiation enabled
 * @autoneg_wait_to_complete: TRUE if waiting is needed to complete
 *
 * Set the link speed in the AUTOC register and restarts link.
 */
s32
ixgbe_setup_mac_link_speed_82598(struct ixgbe_hw *hw,
    ixgbe_link_speed speed, bool autoneg,
    bool autoneg_wait_to_complete)
{
	s32 status = IXGBE_SUCCESS;

	/* If speed is 10G, then check for CX4 or XAUI. */
	if ((speed == IXGBE_LINK_SPEED_10GB_FULL) &&
	    (!(hw->mac.link_attach_type & IXGBE_AUTOC_10G_KX4))) {
		hw->mac.link_mode_select = IXGBE_AUTOC_LMS_10G_LINK_NO_AN;
	} else if ((speed == IXGBE_LINK_SPEED_1GB_FULL) && (!autoneg)) {
		hw->mac.link_mode_select = IXGBE_AUTOC_LMS_1G_LINK_NO_AN;
	} else if (autoneg) {
		/* BX mode - Autonegotiate 1G */
		if (!(hw->mac.link_attach_type & IXGBE_AUTOC_1G_PMA_PMD))
			hw->mac.link_mode_select = IXGBE_AUTOC_LMS_1G_AN;
		else /* KX/KX4 mode */
			hw->mac.link_mode_select = IXGBE_AUTOC_LMS_KX4_AN_1G_AN;
	} else {
		status = IXGBE_ERR_LINK_SETUP;
	}

	if (status == IXGBE_SUCCESS) {
		hw->phy.autoneg_wait_to_complete = autoneg_wait_to_complete;

		hw->mac.link_settings_loaded = TRUE;
		/*
		 * Setup and restart the link based on the new values in
		 * ixgbe_hw This will write the AUTOC register based on the new
		 * stored values
		 */
		(void) ixgbe_setup_mac_link_82598(hw);
	}

	return (status);
}


/*
 * ixgbe_setup_copper_link_82598 - Setup copper link settings
 * @hw: pointer to hardware structure
 *
 * Configures link settings based on values in the ixgbe_hw struct.
 * Restarts the link.  Performs autonegotiation if needed.  Restart
 * phy and wait for autonegotiate to finish.  Then synchronize the
 * MAC and PHY.
 */
s32
ixgbe_setup_copper_link_82598(struct ixgbe_hw *hw)
{
	s32 status;

	/* Restart autonegotiation on PHY */
	status = hw->phy.ops.setup_link(hw);

	/* Set MAC to KX/KX4 autoneg, which defaults to Parallel detection */
	hw->mac.link_attach_type = (IXGBE_AUTOC_10G_KX4 | IXGBE_AUTOC_1G_KX);
	hw->mac.link_mode_select = IXGBE_AUTOC_LMS_KX4_AN;

	/* Set up MAC */
	(void) ixgbe_setup_mac_link_82598(hw);

	return (status);
}

/*
 * ixgbe_setup_copper_link_speed_82598 - Set the PHY autoneg advertised field
 * @hw: pointer to hardware structure
 * @speed: new link speed
 * @autoneg: TRUE if autonegotiation enabled
 * @autoneg_wait_to_complete: TRUE if waiting is needed to complete
 *
 * Sets the link speed in the AUTOC register in the MAC and restarts link.
 */
s32
ixgbe_setup_copper_link_speed_82598(struct ixgbe_hw *hw,
    ixgbe_link_speed speed,
    bool autoneg,
    bool autoneg_wait_to_complete)
{
	s32 status;

	/* Setup the PHY according to input speed */
	status = hw->phy.ops.setup_link_speed(hw, speed, autoneg,
	    autoneg_wait_to_complete);

	/* Set MAC to KX/KX4 autoneg, which defaults to Parallel detection */
	hw->mac.link_attach_type = (IXGBE_AUTOC_10G_KX4 | IXGBE_AUTOC_1G_KX);
	hw->mac.link_mode_select = IXGBE_AUTOC_LMS_KX4_AN;

	/* Set up MAC */
	(void) ixgbe_setup_mac_link_82598(hw);

	return (status);
}

/*
 * ixgbe_reset_hw_82598 - Performs hardware reset
 * @hw: pointer to hardware structure
 *
 * Resets the hardware by resetting the transmit and receive units, masks and
 * clears all interrupts, performing a PHY reset, and performing a link (MAC)
 * reset.
 */
s32
ixgbe_reset_hw_82598(struct ixgbe_hw *hw)
{
	s32 status = IXGBE_SUCCESS;
	u32 ctrl;
	u32 gheccr;
	u32 i;
	u32 autoc;
	u8  analog_val;

	/* Call adapter stop to disable tx/rx and clear interrupts */
	hw->mac.ops.stop_adapter(hw);

	/*
	 * Power up the Atlas Tx lanes if they are currently powered down.
	 * Atlas Tx lanes are powered down for MAC loopback tests, but
	 * they are not automatically restored on reset.
	 */
	hw->mac.ops.read_analog_reg8(hw, IXGBE_ATLAS_PDN_LPBK, &analog_val);
	if (analog_val & IXGBE_ATLAS_PDN_TX_REG_EN) {
		/* Enable Tx Atlas so packets can be transmitted again */
		hw->mac.ops.read_analog_reg8(hw, IXGBE_ATLAS_PDN_LPBK,
		    &analog_val);
		analog_val &= ~IXGBE_ATLAS_PDN_TX_REG_EN;
		hw->mac.ops.write_analog_reg8(hw, IXGBE_ATLAS_PDN_LPBK,
		    analog_val);

		hw->mac.ops.read_analog_reg8(hw, IXGBE_ATLAS_PDN_10G,
		    &analog_val);
		analog_val &= ~ IXGBE_ATLAS_PDN_TX_10G_QL_ALL;
		hw->mac.ops.write_analog_reg8(hw, IXGBE_ATLAS_PDN_10G,
		    analog_val);

		hw->mac.ops.read_analog_reg8(hw, IXGBE_ATLAS_PDN_1G,
		    &analog_val);
		analog_val &= ~IXGBE_ATLAS_PDN_TX_1G_QL_ALL;
		hw->mac.ops.write_analog_reg8(hw, IXGBE_ATLAS_PDN_1G,
		    analog_val);

		hw->mac.ops.read_analog_reg8(hw, IXGBE_ATLAS_PDN_AN,
		    &analog_val);
		analog_val &= ~IXGBE_ATLAS_PDN_TX_AN_QL_ALL;
		hw->mac.ops.write_analog_reg8(hw, IXGBE_ATLAS_PDN_AN,
		    analog_val);
	}

	/* Reset PHY */
	hw->phy.ops.reset(hw);

	/*
	 * Prevent the PCI-E bus from from hanging by disabling PCI-E master
	 * access and verify no pending requests before reset
	 */
	if (ixgbe_disable_pcie_master(hw) != IXGBE_SUCCESS) {
		status = IXGBE_ERR_MASTER_REQUESTS_PENDING;
		DEBUGOUT("PCI-E Master disable polling has failed.\n");
	}

	/*
	 * Issue global reset to the MAC.  This needs to be a SW reset.
	 * If link reset is used, it might reset the MAC when mng is using it
	 */
	ctrl = IXGBE_READ_REG(hw, IXGBE_CTRL);
	IXGBE_WRITE_REG(hw, IXGBE_CTRL, (ctrl | IXGBE_CTRL_RST));
	IXGBE_WRITE_FLUSH(hw);

	/* Poll for reset bit to self-clear indicating reset is complete */
	for (i = 0; i < 10; i++) {
		usec_delay(1);
		ctrl = IXGBE_READ_REG(hw, IXGBE_CTRL);
		if (!(ctrl & IXGBE_CTRL_RST))
			break;
	}
	if (ctrl & IXGBE_CTRL_RST) {
		status = IXGBE_ERR_RESET_FAILED;
		DEBUGOUT("Reset polling failed to complete.\n");
	}

	msec_delay(50);

	gheccr = IXGBE_READ_REG(hw, IXGBE_GHECCR);
	gheccr &= ~((1 << 21) | (1 << 18) | (1 << 9) | (1 << 6));
	IXGBE_WRITE_REG(hw, IXGBE_GHECCR, gheccr);

	/*
	 * AUTOC register which stores link settings gets cleared
	 * and reloaded from EEPROM after reset. We need to restore
	 * our stored value from init in case SW changed the attach
	 * type or speed.  If this is the first time and link settings
	 * have not been stored, store default settings from AUTOC.
	 */
	autoc = IXGBE_READ_REG(hw, IXGBE_AUTOC);
	if (hw->mac.link_settings_loaded) {
		autoc &= ~(IXGBE_AUTOC_LMS_ATTACH_TYPE);
		autoc &= ~(IXGBE_AUTOC_LMS_MASK);
		autoc |= hw->mac.link_attach_type;
		autoc |= hw->mac.link_mode_select;
		IXGBE_WRITE_REG(hw, IXGBE_AUTOC, autoc);
	} else {
		hw->mac.link_attach_type =
		    (autoc & IXGBE_AUTOC_LMS_ATTACH_TYPE);
		hw->mac.link_mode_select = (autoc & IXGBE_AUTOC_LMS_MASK);
		hw->mac.link_settings_loaded = TRUE;
	}

	/* Store the permanent mac address */
	hw->mac.ops.get_mac_addr(hw, hw->mac.perm_addr);

	return (status);
}

/*
 * ixgbe_set_vmdq_82598 - Associate a VMDq set index with a rx address
 * @hw: pointer to hardware struct
 * @rar: receive address register index to associate with a VMDq index
 * @vmdq: VMDq set index
 */
s32
ixgbe_set_vmdq_82598(struct ixgbe_hw *hw, u32 rar, u32 vmdq)
{
	u32 rar_high;

	rar_high = IXGBE_READ_REG(hw, IXGBE_RAH(rar));
	rar_high &= ~IXGBE_RAH_VIND_MASK;
	rar_high |= ((vmdq << IXGBE_RAH_VIND_SHIFT) & IXGBE_RAH_VIND_MASK);
	IXGBE_WRITE_REG(hw, IXGBE_RAH(rar), rar_high);
	return (IXGBE_SUCCESS);
}

/*
 * ixgbe_blink_led_start_82598 - Blink LED based on index.
 * @hw: pointer to hardware structure
 * @index: led number to blink
 */
s32
ixgbe_blink_led_start_82598(struct ixgbe_hw *hw, u32 index)
{
	ixgbe_link_speed speed = 0;
	bool link_up = 0;
	u32 autoc_reg = IXGBE_READ_REG(hw, IXGBE_AUTOC);
	u32 led_reg = IXGBE_READ_REG(hw, IXGBE_LEDCTL);

	/*
	 * Link must be up to auto-blink the LEDs on the 82598EB MAC;
	 * force it if link is down.
	 */
	hw->mac.ops.check_link(hw, &speed, &link_up);

	if (!link_up) {
		autoc_reg |= IXGBE_AUTOC_FLU;
		IXGBE_WRITE_REG(hw, IXGBE_AUTOC, autoc_reg);
		msec_delay(10);
	}

	led_reg &= ~IXGBE_LED_MODE_MASK(index);
	led_reg |= IXGBE_LED_BLINK(index);
	IXGBE_WRITE_REG(hw, IXGBE_LEDCTL, led_reg);
	IXGBE_WRITE_FLUSH(hw);

	return (IXGBE_SUCCESS);
}

/*
 * ixgbe_blink_led_stop_82598 - Stop blinking LED based on index.
 * @hw: pointer to hardware structure
 * @index: led number to stop blinking
 */
s32
ixgbe_blink_led_stop_82598(struct ixgbe_hw *hw, u32 index)
{
	u32 autoc_reg = IXGBE_READ_REG(hw, IXGBE_AUTOC);
	u32 led_reg = IXGBE_READ_REG(hw, IXGBE_LEDCTL);

	autoc_reg &= ~IXGBE_AUTOC_FLU;
	IXGBE_WRITE_REG(hw, IXGBE_AUTOC, autoc_reg);

	led_reg &= ~IXGBE_LED_MODE_MASK(index);
	led_reg &= ~IXGBE_LED_BLINK(index);
	IXGBE_WRITE_REG(hw, IXGBE_LEDCTL, led_reg);
	IXGBE_WRITE_FLUSH(hw);

	return (IXGBE_SUCCESS);
}
