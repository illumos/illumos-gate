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
	if (phy->media_type == ELINK_ETH_PHY_BASE_T) {
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

	if (phy->media_type == ELINK_ETH_PHY_BASE_T) {
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
