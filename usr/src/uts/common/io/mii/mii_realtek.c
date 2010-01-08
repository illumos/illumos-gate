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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * MII overrides for Cicada (now Vitesse) PHYs.
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/mii.h>
#include <sys/miiregs.h>
#include "miipriv.h"


/*
 * The Realtek 10/100 PHYs are mostly standard compliant, but they
 * lack a true vendor/device ID for the integrated PHY, and they don't
 * report the "detected" non-Nway link speed in the appropriate
 * registers.
 */
static int rtl8139_check(phy_handle_t *);
static int rtl8201_check(phy_handle_t *);

boolean_t
phy_realtek_probe(phy_handle_t *ph)
{
	if ((ph->phy_id == 0) &&
	    (strcmp(phy_get_driver(ph), "rtls") == 0)) {
		ph->phy_vendor = "Realtek";
		ph->phy_model = "Internal RTL8139";
		ph->phy_check = rtl8139_check;
		return (B_TRUE);
	} else if (ph->phy_id == 0x8201) {
		ph->phy_vendor = "Realtek";
		ph->phy_model = "RTL8201";
		ph->phy_check = rtl8201_check;
		return (B_TRUE);
	} else {
		return (B_FALSE);
	}
}

static int
rtl8139_check(phy_handle_t *ph)
{
	int		rv;
	uint16_t	s;

	rv = phy_check(ph);

	/*
	 * We possibly override settings, so that we can use the PHYs
	 * autodetected link speed if the partner isn't doing NWay.
	 */
	s = phy_read(ph, MII_VENDOR(0));
	if (s & (1 << 2)) {
		ph->phy_link = LINK_STATE_DOWN;
	} else {
		ph->phy_link = LINK_STATE_UP;
		if (s & (1 << 3)) {
			ph->phy_speed = 10;
		} else {
			ph->phy_speed = 100;
		}
	}

	return (rv);
}

static int
rtl8201_check(phy_handle_t *ph)
{
	int		rv;
	uint16_t	s;

	rv = phy_check(ph);

	/*
	 * We possibly override settings, so that we can use the PHYs
	 * autodetected link speed if the partner isn't doing NWay.
	 */
	s = phy_read(ph, MII_VENDOR(9));
	if (s & (1 << 0)) {
		ph->phy_link = LINK_STATE_UP;
		ph->phy_speed = 100;
	} else if (s & (1 << 1)) {
		ph->phy_link = LINK_STATE_UP;
		ph->phy_speed = 10;
	} else {
		ph->phy_link = LINK_STATE_DOWN;
	}

	return (rv);
}
