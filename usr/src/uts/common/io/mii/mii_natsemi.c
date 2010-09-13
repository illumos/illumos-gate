/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
 * or http://www.opensolaris.org/os/licensing.
 * See the License for the specific language governing permissions
 * and limitations under the License.
 *
 * When distributing Covered Code, include this CDDL HEADER in each
 * file and include the License file at usr/src/OPENSOLARIS.LICENSE.
 * If applicable, add the following below this CDDL HEADER, with the
 * fields enclosed by brackets "[]" replaced with your own identifying
 * information: Portions Copyright [yyyy] [name of copyright owner]
 *
 * CDDL HEADER END
 */
/*
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * MII overrides for National Semiconductor PHYs.
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/mii.h>
#include <sys/miiregs.h>
#include "miipriv.h"

static int
ns83840_reset(phy_handle_t *ph)
{
	/* first do an ordinary reset */
	if (phy_reset(ph) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/*
	 * As per INTEL "PRO/100B Adapter Software Technical Reference
	 * Manual", set bit 10 of MII register 23.  National
	 * Semiconductor documentation shows this as "reserved, write
	 * to as zero". We also set the "CIM_DIS" bit, also as
	 * requested by the PRO/100B doc, to disable the carrier
	 * integrity monitor.  (That should only ever be used by
	 * repeaters.)
	 *
	 * NetBSD also sets bit 8, without any explanation, so we'll
	 * follow suit.
	 */
	PHY_SET(ph, MII_VENDOR(7), (1<<10) | (1<<8) | (1<<5));
	return (DDI_SUCCESS);
}

boolean_t
phy_natsemi_probe(phy_handle_t *ph)
{
	/* We could even look at revA vs revC, etc. but there is no need. */
	if ((MII_PHY_MFG(ph->phy_id) != MII_OUI_NATIONAL_SEMI) &&
	    (MII_PHY_MFG(ph->phy_id) != MII_OUI_NATIONAL_SEMI_2)) {
		return (B_FALSE);
	}
	ph->phy_vendor = "National Semiconductor";

	switch (MII_PHY_MODEL(ph->phy_id)) {
	case MII_MODEL_NATIONAL_SEMI_DP83840:
		ph->phy_model = "DP83840";
		ph->phy_reset = ns83840_reset;
		return (B_TRUE);

	case MII_MODEL_NATIONAL_SEMI_DP83843:
		ph->phy_model = "DP83843";
		return (B_TRUE);

	case MII_MODEL_NATIONAL_SEMI_DP83847:
		ph->phy_model = "DP83847";
		return (B_TRUE);

	case MII_MODEL_NATIONAL_SEMI_DP83815:
		ph->phy_model = "DP83815";
		return (B_TRUE);
	}
	return (B_FALSE);
}
