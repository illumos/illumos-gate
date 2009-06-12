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
 * MII overrides for Intel PHYs.
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/cmn_err.h>
#include <sys/note.h>
#include <sys/mii.h>
#include <sys/miiregs.h>
#include "miipriv.h"

#define	MII_82555_SPCL_CONTROL	MII_VENDOR(1)
#define	I82555_AUTOPOL_DIS	(1<<4)

/*
 * The older 82555 code in iprb had a bunch of workarounds to deal
 * with chip errata surrounding (I believe) autonegotiation problems
 * with the 82555 and long cables.
 *
 * I can't find any evidence in current Linux, NetBSD, or FreeBSD
 * sources for the same kinds of workarounds for this PHY, so I'm
 * going to operate on the belief that these workarounds are simply
 * not necessary.  Without access to the errata for these parts, as
 * well as parts that exhibit the problems, I can't be certain that
 * such workarounds will work properly.  So I'm leaving them out for
 * now.  I believe that the errata were mostly problems for 10 Mbps
 * links which are very hard to find anymore, anyway.
 */

static int
i82555_start(phy_handle_t *ph)
{
	int rv;

	if ((rv = phy_start(ph)) != DDI_SUCCESS) {
		return (rv);
	}

	/*
	 * Apparently some devices have problem with 10 Mbps polarity and
	 * short cable lengths.  However, these days everyone should be using
	 * 100 Mbps, and rather than retain the extra legacy complexity
	 * here, I'm going to simply offer the choice to disable auto polarity.
	 *
	 * If autopolarity doesn't work for you, you have several choices:
	 *
	 * 1) Find a longer cable.
	 * 2) Upgrade to 100Mbps.
	 * 3) Disable the polarity check by setting AutoPolarity to 0.
	 *
	 * We also believe that 10BASE-T autopolarity may be harmful (because
	 * when used it can prevent use of a superior 100Mbps mode), so we
	 * disable autopolarity by default.
	 */
	if (phy_get_prop(ph, "AutoPolarity", 0) == 0) {
		/* disable autopolarity */
		PHY_SET(ph, MII_82555_SPCL_CONTROL, I82555_AUTOPOL_DIS);
	} else {
		/* enable basic autopolarity */
		PHY_CLR(ph, MII_82555_SPCL_CONTROL, I82555_AUTOPOL_DIS);
	}

	return (rv);
}

boolean_t
phy_intel_probe(phy_handle_t *ph)
{
	const char *model;

	if (MII_PHY_MFG(ph->phy_id) != MII_OUI_INTEL) {
		return (B_FALSE);
	}

	switch (MII_PHY_MODEL(ph->phy_id)) {
	case MII_MODEL_INTEL_82553_CSTEP:
		model = "82553 C-step";
		break;
	case MII_MODEL_INTEL_82555:
		ph->phy_start = i82555_start;
		model = "82555";
		break;
	case MII_MODEL_INTEL_82562_EH:
		model = "Intel 82562 EH";
		break;
	case MII_MODEL_INTEL_82562_ET:
		model = "Intel 82562 ET";
		break;
	case MII_MODEL_INTEL_82562_EM:
		model = "Intel 82562 EM";
		break;
	default:
		return (B_FALSE);
	}

	ph->phy_vendor = "Intel";
	ph->phy_model = model;

	return (B_TRUE);
}
