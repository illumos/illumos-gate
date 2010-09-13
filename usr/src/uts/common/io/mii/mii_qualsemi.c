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
 * MII overrides for Quality Semiconductor PHYs.
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/mii.h>
#include <sys/miiregs.h>
#include "miipriv.h"

#define	QS_IMASK_REG		30
#define	QS_BTXPC		31
#define	QS_BTXPC_SCRAM_DIS	0x1

static int
qs6612_reset(phy_handle_t *ph)
{
	/* Ordinary reset. */
	if (phy_reset(ph) != DDI_SUCCESS) {
		return (DDI_FAILURE);
	}

	/* Disable QS6612 proprietary interrupts. */
	phy_write(ph, QS_IMASK_REG, 0);

	return (DDI_SUCCESS);
}

static int
qs6612_check(phy_handle_t *ph)
{
	link_state_t	link;
	int		rv;

	/*
	 * Apparently some *ancient* Synoptics 28115 firwmare has a bug that
	 * doesn't connect with certain devices.  While I'm fairly sure we
	 * could probably remove this workaround (for another vendor's bug!)
	 * at this point, it might crop up as a regression.
	 *
	 * Apparently, the workaround is to disable the scrambler for a bit
	 * once 100 Mbps link is achieved, and then reactivate.  This lets
	 * the busted switch work.  We only do it when first bringing up
	 * the 100 Mbps link.
	 *
	 * Yes, I resent having to do this.  But the code is carried over
	 * from old hme/qfe.  See 4071199 for details.
	 */
	link = ph->phy_link;

	rv = phy_check(ph);

	if ((ph->phy_link == LINK_STATE_UP) && (link != LINK_STATE_UP) &&
	    (ph->phy_speed == 100)) {
		uint16_t	val;
		val = phy_read(ph, QS_BTXPC);
		phy_write(ph, QS_BTXPC, val | QS_BTXPC_SCRAM_DIS);
		drv_usecwait(20);
		phy_write(ph, QS_BTXPC, val);
	}

	return (rv);
}

boolean_t
phy_qualsemi_probe(phy_handle_t *ph)
{
	if ((MII_PHY_MFG(ph->phy_id) == MII_OUI_QUALITY_SEMI) &&
	    (MII_PHY_MODEL(ph->phy_id) == MII_MODEL_QUALITY_SEMI_QS6612)) {
		ph->phy_vendor = "Quality Semiconductor";
		ph->phy_model = "QS6612";
		ph->phy_reset = qs6612_reset;
		ph->phy_check = qs6612_check;
		return (B_TRUE);
	}
	return (B_FALSE);
}
