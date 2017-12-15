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
 */

/*
 * Routines to get access to the phy and transceiver that require routines and
 * definitions that aren't part of the common ixgbe API.
 */

#include "ixgbe_sw.h"
#include "ixgbe_phy.h"

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
