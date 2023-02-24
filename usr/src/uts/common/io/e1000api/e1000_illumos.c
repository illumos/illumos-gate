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
 * Copyright 2023 Oxide Computer Company
 */

/*
 * illumos additions to the e1000 common code for sharing between igb and
 * e1000g.
 */

#include "e1000_illumos.h"

/*
 * Attempt to map the internal link settings in the device to known media types.
 * This is a bit complicated because of how the common code abstracts some of
 * the PHY information. In particular, the link mode to the internal serdes does
 * not tell us much about how the external connectivity is designed. This makes
 * it hard to figure out if we are actually using backplane connectivity that
 * would operate in a KX or SGMII mode.
 */
mac_ether_media_t
e1000_link_to_media(struct e1000_hw *hw, uint32_t speed)
{
	/*
	 * If we enable 2.5G support for the i354 backplane, then we should go
	 * and update this case for 2.5G.
	 */
	switch (speed) {
	case SPEED_1000:
		switch (hw->phy.media_type) {
		case e1000_media_type_copper:
			return (ETHER_MEDIA_1000BASE_T);
		/*
		 * The internal serdes flag is often still used when
		 * communicating with fiber based media.
		 */
		case e1000_media_type_fiber:
		case e1000_media_type_internal_serdes:
			/*
			 * While the e1000api common code internally has logic
			 * to actually pull out the specific SFF identifier for
			 * this device, that is not easily accessible for us so
			 * we return this as a generic fiber case. Given the
			 * lack of updates to the common code, we may want to
			 * reasonably plumb this through in the future.
			 */
			return (ETHER_MEDIA_1000BASE_X);
		default:
			return (ETHER_MEDIA_UNKNOWN);
		}
		break;
	case SPEED_100:
		switch (hw->phy.media_type) {
		case e1000_media_type_copper:
			/*
			 * While there are standard bits in the PHY to indicate
			 * support for 100BASE-T2 and 100BASE-4 support, we have
			 * not seen any parts that suggest they actually support
			 * this in their datasheets. This is true as far back as
			 * the 82540 (which is derived from the 82542) whose
			 * datasheet covers all PCI and PCI-X controllers of a
			 * generation. It is also seemingly true for most newer
			 * controllers and PHYs. We've spot-checked the 82574,
			 * 82575, 82576, I350, I210, I211, and I217 datasheets.
			 * This leaves us fairly convinced it is safe to assume
			 * 100BASE-TX.
			 */
			return (ETHER_MEDIA_100BASE_TX);
		case e1000_media_type_fiber:
			return (ETHER_MEDIA_100BASE_FX);
		default:
			return (ETHER_MEDIA_UNKNOWN);
		}
	case SPEED_10:
		if (hw->phy.media_type == e1000_media_type_copper)
			return (ETHER_MEDIA_10BASE_T);
		return (ETHER_MEDIA_UNKNOWN);
	default:
		return (ETHER_MEDIA_NONE);
	}
}
