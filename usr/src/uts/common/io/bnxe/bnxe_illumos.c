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
 * Copyright 2023 Oxide Computer Company
 */

/*
 * illumos specific bnxe related functions.
 */

#include "bnxe.h"

/*
 * Try to figure out which phy we should be using at this time based on the
 * requested transceiver.
 */
static uint_t
bnxe_get_phy_id(um_device_t *um)
{
	if (um->lm_dev.params.link.num_phys <= 1)
		return (ELINK_INT_PHY);

	if (um->lm_dev.vars.link.link_up) {
		if ((um->lm_dev.vars.link.link_status &
		    LINK_STATUS_SERDES_LINK) &&
		    (um->lm_dev.params.link.phy[ELINK_EXT_PHY2].supported &
		    ELINK_SUPPORTED_FIBRE))
			return (ELINK_EXT_PHY2);
		return (ELINK_EXT_PHY1);
	} else {
		switch (elink_phy_selection(&um->lm_dev.params.link)) {
		case PORT_HW_CFG_PHY_SELECTION_HARDWARE_DEFAULT:
		case PORT_HW_CFG_PHY_SELECTION_FIRST_PHY:
		case PORT_HW_CFG_PHY_SELECTION_FIRST_PHY_PRIORITY:
			return (ELINK_EXT_PHY1);
		case PORT_HW_CFG_PHY_SELECTION_SECOND_PHY:
		case PORT_HW_CFG_PHY_SELECTION_SECOND_PHY_PRIORITY:
			return (ELINK_EXT_PHY2);
		/*
		 * The above hardware types are the only ones currently defined
		 * by the specification and common code. If we end up with an
		 * unknown value, then we default to what the hardware considers
		 * the default, which is PHY1.
		 */
		default:
			return (ELINK_EXT_PHY1);
		}
	}
}

/*
 * This media map table and structure is shared across the different pluggable
 * modules. The driver doesn't really look carefully at the difference between
 * the various multi-speed modules which is why for 10G based pieces we also
 * have lower speed based checks.
 */
typedef struct {
	uint32_t bmm_sfp;
	uint32_t bmm_speed;
	mac_ether_media_t bmm_media;
} bnxe_media_map_t;

static const bnxe_media_map_t bnxe_media_map[] = {
	{ ELINK_ETH_SFP_10GBASE_SR, 10000, ETHER_MEDIA_10GBASE_SR },
	{ ELINK_ETH_SFP_10GBASE_SR, 1000, ETHER_MEDIA_1000BASE_SX },
	{ ELINK_ETH_SFP_1GBASE_SX, 1000, ETHER_MEDIA_1000BASE_SX },
	{ ELINK_ETH_SFP_10GBASE_LR, 10000, ETHER_MEDIA_10GBASE_LR },
	{ ELINK_ETH_SFP_10GBASE_LR, 1000, ETHER_MEDIA_1000BASE_LX },
	{ ELINK_ETH_SFP_1GBASE_LX, 1000, ETHER_MEDIA_1000BASE_LX },
	{ ELINK_ETH_SFP_10GBASE_LRM, 10000, ETHER_MEDIA_10GBASE_LRM },
	{ ELINK_ETH_SFP_10GBASE_ER, 10000, ETHER_MEDIA_10GBASE_ER },
	{ ELINK_ETH_SFP_1GBASE_T, 1000, ETHER_MEDIA_1000BASE_T },
	{ ELINK_ETH_SFP_1GBASE_CX, 1000, ETHER_MEDIA_1000BASE_CX },
	{ ELINK_ETH_SFP_DAC, 10000, ETHER_MEDIA_10GBASE_CR },
	{ ELINK_ETH_SFP_ACC, 10000, ETHER_MEDIA_10GBASE_ACC },
};

mac_ether_media_t
bnxe_phy_to_media(um_device_t *um)
{
	uint_t phyid;
	struct elink_params *params;
	struct elink_phy *phy;
	mac_ether_media_t media = ETHER_MEDIA_UNKNOWN;

	BNXE_LOCK_ENTER_PHY(um);
	phyid = bnxe_get_phy_id(um);
	params = &um->lm_dev.params.link;
	phy = &params->phy[phyid];

	switch (phy->media_type) {
	/*
	 * Right now the driver does not ask the XFP i2c entity to determine the
	 * media information. If we encounter someone with an XFP device then we
	 * can add logic to the driver to cover proper detection, but otherwise
	 * it would fit into this same set of modes.
	 */
	case ELINK_ETH_PHY_SFPP_10G_FIBER:
	case ELINK_ETH_PHY_XFP_FIBER:
	case ELINK_ETH_PHY_DA_TWINAX:
	case ELINK_ETH_PHY_SFP_1G_FIBER:
		for (size_t i = 0; i < ARRAY_SIZE(bnxe_media_map); i++) {
			const bnxe_media_map_t *map = &bnxe_media_map[i];
			if (phy->sfp_media == map->bmm_sfp &&
			    um->props.link_speed == map->bmm_speed) {
				media = map->bmm_media;
				break;
			}
		}
		break;
	case ELINK_ETH_PHY_BASE_T:
		switch (um->props.link_speed) {
		case 10:
			media = ETHER_MEDIA_10BASE_T;
			break;
		case 100:
			media = ETHER_MEDIA_100BASE_TX;
			break;
		case 1000:
			media = ETHER_MEDIA_1000BASE_T;
			break;
		case 10000:
			media = ETHER_MEDIA_10GBASE_T;
			break;
		default:
			break;
		}
		break;
	case ELINK_ETH_PHY_KR:
		switch (um->props.link_speed) {
		case 1000:
			media = ETHER_MEDIA_1000BASE_KX;
			break;
		case 10000:
			media = ETHER_MEDIA_10GBASE_KR;
			break;
		default:
			break;
		}
		break;
	case ELINK_ETH_PHY_CX4:
		if (um->props.link_speed == 10000) {
			media = ETHER_MEDIA_10GBASE_CX4;
		}
		break;
	case ELINK_ETH_PHY_NOT_PRESENT:
		media = ETHER_MEDIA_NONE;
		break;
	case ELINK_ETH_PHY_UNSPECIFIED:
	default:
		media = ETHER_MEDIA_UNKNOWN;
		break;
	}

	BNXE_LOCK_EXIT_PHY(um);
	return (media);
}


static int
bnxe_transceiver_info(void *arg, uint_t id, mac_transceiver_info_t *infop)
{
	uint_t phyid;
	um_device_t *um = arg;
	struct elink_params *params;
	struct elink_phy *phy;
	boolean_t present = B_FALSE, usable = B_FALSE;
	elink_status_t ret;
	uint8_t buf;

	if (id != 0 || arg == NULL || infop == NULL)
		return (EINVAL);

	BNXE_LOCK_ENTER_PHY(um);
	phyid = bnxe_get_phy_id(um);
	params = &um->lm_dev.params.link;
	phy = &params->phy[phyid];

	switch (phy->media_type) {
	case ELINK_ETH_PHY_SFPP_10G_FIBER:
	case ELINK_ETH_PHY_DA_TWINAX:
	case ELINK_ETH_PHY_SFP_1G_FIBER:
		break;
	default:
		BNXE_LOCK_EXIT_PHY(um);
		return (ENOTSUP);
	}

	/*
	 * Right now, the core OS-independent code from QLogic doesn't quite
	 * track whether or not the phy is plugged in, though it easily could.
	 * As such, the best way to determine whether or not the phy is present
	 * is to see if we can read the first byte from page 0xa0. We expect to
	 * get an explicit timeout if the device isn't present. We'll propagate
	 * EIO on any other error as we're not in a good state to understand
	 * what happened.
	 */
	PHY_HW_LOCK(&um->lm_dev);
	ret = elink_read_sfp_module_eeprom(phy, params, 0xa0, 0, sizeof (buf),
	    &buf);
	PHY_HW_UNLOCK(&um->lm_dev);
	if (ret != ELINK_STATUS_OK && ret != ELINK_STATUS_TIMEOUT) {
		BNXE_LOCK_EXIT_PHY(um);
		return (EIO);
	}
	if (ret == ELINK_STATUS_OK) {
		present = B_TRUE;
		if ((phy->flags & ELINK_FLAGS_SFP_NOT_APPROVED) == 0)
			usable = B_TRUE;
	}
	BNXE_LOCK_EXIT_PHY(um);

	mac_transceiver_info_set_present(infop, present);
	mac_transceiver_info_set_usable(infop, usable);

	return (0);
}

static int
bnxe_transceiver_read(void *arg, uint_t id, uint_t page, void *bp,
    size_t nbytes, off_t offset, size_t *nread)
{
	uint_t phyid;
	um_device_t *um = arg;
	struct elink_phy *phy;
	struct elink_params *params;
	elink_status_t ret;

	if (id != 0 || bp == NULL || nbytes == 0 || nread == NULL ||
	    (page != 0xa0 && page != 0xa2) || offset < 0)
		return (EINVAL);

	/*
	 * Sanity check length params.
	 */
	if (nbytes > 256 || offset >= 256 || (offset + nbytes > 256)) {
		return (EINVAL);
	}

	BNXE_LOCK_ENTER_PHY(um);
	phyid = bnxe_get_phy_id(um);
	params = &um->lm_dev.params.link;
	phy = &um->lm_dev.params.link.phy[phyid];

	switch (phy->media_type) {
	case ELINK_ETH_PHY_SFPP_10G_FIBER:
	case ELINK_ETH_PHY_DA_TWINAX:
	case ELINK_ETH_PHY_SFP_1G_FIBER:
		break;
	default:
		BNXE_LOCK_EXIT_PHY(um);
		return (ENOTSUP);
	}

	PHY_HW_LOCK(&um->lm_dev);
	ret = elink_read_sfp_module_eeprom(phy, params, (uint8_t)page,
	    (uint16_t)offset, (uint16_t)nbytes, bp);
	PHY_HW_UNLOCK(&um->lm_dev);

	BNXE_LOCK_EXIT_PHY(um);

	switch (ret) {
	case ELINK_STATUS_OK:
		*nread = nbytes;
		return (0);
	case ELINK_OP_NOT_SUPPORTED:
		return (ENOTSUP);
	default:
		return (EIO);
	}
}

boolean_t
bnxe_fill_transceiver(um_device_t *um, void *arg)
{
	uint_t ntran = 1;
	mac_capab_transceiver_t *mct = arg;

	mct->mct_flags = 0;
	/*
	 * While there is nominally a dual-phy version of bnxe out there (see
	 * ELINK_DUAL_MEDIA and related macros), these haven't been seen in the
	 * wild. For now, only assume that we have a single phy.
	 */
	mct->mct_ntransceivers = 1;
	mct->mct_info = bnxe_transceiver_info;
	mct->mct_read = bnxe_transceiver_read;

	return (B_TRUE);
}
