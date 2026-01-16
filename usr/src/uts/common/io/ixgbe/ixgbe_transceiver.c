/*
 * This file and its contents are supplied under the terms of the
 * Common Development and Distribution License ("CDDL"), version 1.0.
 * You may only use this file in accordance with the terms of version
 * 1.0 of the CDDL.
 *
 * A full copy of the text of the CDDL should have accompanied this
 * source.  A copy of the CDDL is also available via the Internet at
 * http://www.illumos.org/license/CDDL.
 */

/*
 * Copyright (c) 2017, Joyent, Inc.
 * Copyright 2026 Oxide Computer Company
 */

/*
 * Routines to get access to the phy and transceiver that require routines and
 * definitions that aren't part of the common ixgbe API.
 */

#include "ixgbe_sw.h"
#include "ixgbe_phy.h"

/*
 * This is a table that maps various link types, speeds, and physical media
 * types together to something that can be used. We prefer to use the supported
 * physical layer types so we can attempt to abstract around the various PHY and
 * media types and try to create a single coherent place for these.
 */
typedef struct {
	uint64_t ipm_phys;
	uint32_t ipm_speed;
	mac_ether_media_t ipm_media;
} ixgbe_phys_map_t;

const ixgbe_phys_map_t ixgbe_phys_map[] = {
	/*
	 * First we lead off with all copper based speeds. Note, some of these
	 * may be used through an SFP or similar. SPEED_10 is listed here for
	 * completeness sake, as other drivers list them, though it is is hard
	 * to figure out how it is possible to get to 10 Mb/s because the X540 /
	 * X550 do not support 10BASE-T.
	 */
	{ IXGBE_PHYSICAL_LAYER_10GBASE_T, SPEED_10GB, ETHER_MEDIA_10GBASE_T },
	{ IXGBE_PHYSICAL_LAYER_10GBASE_T, SPEED_5GB, ETHER_MEDIA_5000BASE_T },
	{ IXGBE_PHYSICAL_LAYER_10GBASE_T, SPEED_2_5GB, ETHER_MEDIA_2500BASE_T },
	{ IXGBE_PHYSICAL_LAYER_10GBASE_T, SPEED_1GB, ETHER_MEDIA_1000BASE_T },
	{ IXGBE_PHYSICAL_LAYER_1000BASE_T, SPEED_1GB, ETHER_MEDIA_1000BASE_T },
	{ IXGBE_PHYSICAL_LAYER_10GBASE_T, SPEED_100, ETHER_MEDIA_100BASE_TX },
	{ IXGBE_PHYSICAL_LAYER_1000BASE_T, SPEED_100, ETHER_MEDIA_100BASE_TX },
	{ IXGBE_PHYSICAL_LAYER_100BASE_TX, SPEED_100, ETHER_MEDIA_100BASE_TX },
	{ IXGBE_PHYSICAL_LAYER_10GBASE_T, SPEED_10, ETHER_MEDIA_10BASE_T },
	{ IXGBE_PHYSICAL_LAYER_1000BASE_T, SPEED_10, ETHER_MEDIA_10BASE_T },
	{ IXGBE_PHYSICAL_LAYER_100BASE_TX, SPEED_10, ETHER_MEDIA_10BASE_T },
	{ IXGBE_PHYSICAL_LAYER_10BASE_T, SPEED_10, ETHER_MEDIA_10BASE_T },
	/*
	 * After this point we mostly are in backplane or SFP based formats. In
	 * general there is a 1:1 mapping between a physical ability and a
	 * speed. However, a few allow multiple speeds to be set and we have to
	 * derive this from the common code. Example of this nuance in
	 * particular are around KR/KX.
	 */
	{ IXGBE_PHYSICAL_LAYER_SFP_PLUS_CU, SPEED_10GB,
	    ETHER_MEDIA_10GBASE_CR },
	{ IXGBE_PHYSICAL_LAYER_10GBASE_LR, SPEED_10GB,
	    ETHER_MEDIA_10GBASE_LR },
	{ IXGBE_PHYSICAL_LAYER_10GBASE_LR, SPEED_1GB,
	    ETHER_MEDIA_1000BASE_LX },
	{ IXGBE_PHYSICAL_LAYER_10GBASE_LRM, SPEED_10GB,
	    ETHER_MEDIA_10GBASE_LRM },
	{ IXGBE_PHYSICAL_LAYER_10GBASE_LRM, SPEED_1GB,
	    ETHER_MEDIA_1000BASE_LX },
	{ IXGBE_PHYSICAL_LAYER_10GBASE_SR, SPEED_10GB,
	    ETHER_MEDIA_10GBASE_SR },
	{ IXGBE_PHYSICAL_LAYER_10GBASE_SR, SPEED_1GB,
	    ETHER_MEDIA_1000BASE_SX },
	{ IXGBE_PHYSICAL_LAYER_10GBASE_KX4, SPEED_10GB,
	    ETHER_MEDIA_10GBASE_KX4 },
	{ IXGBE_PHYSICAL_LAYER_10GBASE_KX4, SPEED_1GB,
	    ETHER_MEDIA_1000BASE_KX },
	{ IXGBE_PHYSICAL_LAYER_10GBASE_CX4, SPEED_10GB,
	    ETHER_MEDIA_10GBASE_CX4 },
	{ IXGBE_PHYSICAL_LAYER_1000BASE_KX, SPEED_1GB,
	    ETHER_MEDIA_1000BASE_KX },
	{ IXGBE_PHYSICAL_LAYER_1000BASE_BX, SPEED_1GB,
	    ETHER_MEDIA_1000BASE_BX },
	{ IXGBE_PHYSICAL_LAYER_10GBASE_KR, SPEED_10GB,
	    ETHER_MEDIA_10GBASE_KR },
	{ IXGBE_PHYSICAL_LAYER_10GBASE_KR, SPEED_2_5GB,
	    ETHER_MEDIA_2500BASE_KX },
	{ IXGBE_PHYSICAL_LAYER_10GBASE_XAUI, SPEED_10GB,
	    ETHER_MEDIA_10G_XAUI },
	{ IXGBE_PHYSICAL_LAYER_SFP_ACTIVE_DA, SPEED_10GB,
	    ETHER_MEDIA_10GBASE_ACC },
	{ IXGBE_PHYSICAL_LAYER_1000BASE_SX, SPEED_1GB,
	    ETHER_MEDIA_1000BASE_SX },
	{ IXGBE_PHYSICAL_LAYER_2500BASE_KX, SPEED_2_5GB,
	    ETHER_MEDIA_2500BASE_KX },
	{ IXGBE_PHYSICAL_LAYER_2500BASE_T, SPEED_2_5GB,
	    ETHER_MEDIA_2500BASE_T },
	{ IXGBE_PHYSICAL_LAYER_5000BASE_T, SPEED_5GB,
	    ETHER_MEDIA_5000BASE_T },
};

mac_ether_media_t
ixgbe_phy_to_media(ixgbe_t *ixgbe)
{
	struct ixgbe_hw *hw = &ixgbe->hw;

	ASSERT(MUTEX_HELD(&ixgbe->gen_lock));
	switch (hw->phy.media_type) {
	case ixgbe_media_type_copper:
	case ixgbe_media_type_fiber:
	case ixgbe_media_type_fiber_fixed:
	case ixgbe_media_type_fiber_qsfp:
	case ixgbe_media_type_backplane:
	case ixgbe_media_type_cx4:
	case ixgbe_media_type_da:
		for (size_t i = 0; i < ARRAY_SIZE(ixgbe_phys_map); i++) {
			const ixgbe_phys_map_t *map = &ixgbe_phys_map[i];
			if ((ixgbe->phys_supported & map->ipm_phys) != 0 &&
			    ixgbe->link_speed == map->ipm_speed) {
				return (map->ipm_media);
			}
		}

		if (ixgbe->link_state != LINK_STATE_DOWN) {
			return (ETHER_MEDIA_UNKNOWN);
		} else {
			return (ETHER_MEDIA_NONE);
		}
		break;
	/*
	 * We don't bother trying to make up anything for a VF.
	 */
	case ixgbe_media_type_virtual:
		return (ETHER_MEDIA_NONE);
	default:
		return (ETHER_MEDIA_UNKNOWN);
	}
}

static int
ixgbe_transceiver_is_8472(ixgbe_t *ixgbe, boolean_t *valp)
{
	int32_t ret;
	uint8_t rev, swap;
	struct ixgbe_hw *hw = &ixgbe->hw;

	ASSERT(MUTEX_HELD(&ixgbe->gen_lock));
	if (hw->phy.ops.read_i2c_eeprom == NULL)
		return (ENOTSUP);

	ret = hw->phy.ops.read_i2c_eeprom(hw, IXGBE_SFF_SFF_8472_COMP, &rev);
	if (ret != 0)
		return (EIO);

	ret = hw->phy.ops.read_i2c_eeprom(hw, IXGBE_SFF_SFF_8472_SWAP, &swap);
	if (ret != 0)
		return (EIO);

	if (swap & IXGBE_SFF_ADDRESSING_MODE) {
		ixgbe_log(ixgbe, "transceiver requires unsupported address "
		    "change for page 0xa2. Access will only be allowed to "
		    "page 0xa0.");
	}

	if (rev == IXGBE_SFF_SFF_8472_UNSUP ||
	    (swap & IXGBE_SFF_ADDRESSING_MODE)) {
		*valp = B_FALSE;
	} else {
		*valp = B_TRUE;
	}

	return (0);
}

/*
 * Note, we presume that the mac perimeter is held during these calls. As such,
 * we rely on that for guaranteeing that only one thread is calling the i2c
 * routines at any time.
 */
int
ixgbe_transceiver_info(void *arg, uint_t id, mac_transceiver_info_t *infop)
{
	ixgbe_t *ixgbe = arg;
	struct ixgbe_hw *hw = &ixgbe->hw;
	boolean_t present, usable;

	if (id != 0 || infop == NULL)
		return (EINVAL);

	mutex_enter(&ixgbe->gen_lock);
	if (ixgbe_get_media_type(&ixgbe->hw) == ixgbe_media_type_copper) {
		mutex_exit(&ixgbe->gen_lock);
		return (ENOTSUP);
	}

	/*
	 * Make sure we have the latest sfp information. This is especially
	 * important if the SFP is removed as that doesn't trigger interrupts in
	 * our current configuration.
	 */
	(void) hw->phy.ops.identify_sfp(hw);
	if (hw->phy.type == ixgbe_phy_none ||
	    (hw->phy.type == ixgbe_phy_unknown &&
	    hw->phy.sfp_type == ixgbe_sfp_type_not_present)) {
		present = B_FALSE;
		usable = B_FALSE;
	} else {
		present = B_TRUE;
		usable = hw->phy.type != ixgbe_phy_sfp_unsupported;
	}

	mutex_exit(&ixgbe->gen_lock);

	mac_transceiver_info_set_present(infop, present);
	mac_transceiver_info_set_usable(infop, usable);

	return (0);
}

/*
 * Note, we presume that the mac perimeter is held during these calls. As such,
 * we rely on that for guaranteeing that only one thread is calling the i2c
 * routines at any time.
 */
int
ixgbe_transceiver_read(void *arg, uint_t id, uint_t page, void *bp,
    size_t nbytes, off_t offset, size_t *nread)
{
	ixgbe_t *ixgbe = arg;
	struct ixgbe_hw *hw = &ixgbe->hw;
	uint8_t *buf = bp;
	size_t i;
	boolean_t is8472;

	if (id != 0 || buf == NULL || nbytes == 0 || nread == NULL ||
	    (page != 0xa0 && page != 0xa2) || offset < 0)
		return (EINVAL);

	/*
	 * Both supported pages have a length of 256 bytes, ensure nothing asks
	 * us to go beyond that.
	 */
	if (nbytes > 256 || offset >= 256 || (offset + nbytes > 256)) {
		return (EINVAL);
	}

	mutex_enter(&ixgbe->gen_lock);
	if (ixgbe_get_media_type(&ixgbe->hw) == ixgbe_media_type_copper) {
		mutex_exit(&ixgbe->gen_lock);
		return (ENOTSUP);
	}

	if (hw->phy.ops.read_i2c_eeprom == NULL) {
		mutex_exit(&ixgbe->gen_lock);
		return (ENOTSUP);
	}

	if (ixgbe_transceiver_is_8472(ixgbe, &is8472) != 0) {
		mutex_exit(&ixgbe->gen_lock);
		return (EIO);
	}

	if (!is8472 && page == 0xa2) {
		mutex_exit(&ixgbe->gen_lock);
		return (EINVAL);
	}

	for (i = 0; i < nbytes; i++, offset++, buf++) {
		int32_t ret;

		if (page == 0xa0) {
			ret = hw->phy.ops.read_i2c_eeprom(hw, offset, buf);
		} else {
			ret = hw->phy.ops.read_i2c_sff8472(hw, offset, buf);
		}
		if (ret != 0) {
			mutex_exit(&ixgbe->gen_lock);
			return (EIO);
		}
	}
	mutex_exit(&ixgbe->gen_lock);
	*nread = i;

	return (0);
}
