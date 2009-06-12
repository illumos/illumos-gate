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
 * MII overrides for Cicada (now Vitesse) PHYs.
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/mii.h>
#include <sys/miiregs.h>
#include "miipriv.h"

#define	MII_CICADA_BYPASS_CONTROL	MII_VENDOR(2)
#define	CICADA_125MHZ_CLOCK_ENABLE	0x0001

#define	MII_CICADA_10BASET_CONTROL	MII_VENDOR(6)
#define	MII_CICADA_DISABLE_ECHO_MODE	0x2000

#define	MII_CICADA_EXT_CONTROL		MII_VENDOR(7)
#define	MII_CICADA_MODE_SELECT_BITS 	0xf000
#define	MII_CICADA_MODE_SELECT_RGMII	0x1000
#define	MII_CICADA_POWER_SUPPLY_BITS	0x0e00
#define	MII_CICADA_POWER_SUPPLY_3_3V	0x0000
#define	MII_CICADA_POWER_SUPPLY_2_5V	0x0200

#define	MII_CICADA_AUXCTRL_STATUS	MII_VENDOR(12)
#define	MII_CICADA_PIN_PRORITY_SETTING	0x0004
#define	MII_CICADA_PIN_PRORITY_DEFAULT	0x0000

/*
 * The nge driver seems to do some rather specialized programming of
 * this PHY.  Specifically, it appears that the PHY is programmed for
 * 2.5 RGMII operation and the PIN_PRIOITY_SETTING is set for RGMII
 * interfaces.  For MII interfaces, the echo mode is disabled and the
 * 125MHz clock is disabled.
 *
 * It isn't immediately clear to me how to cleanly do this.  One could
 * probably argue that this particular PHY would never ever be used in
 * a strict MII setting, but I hate to make an incorrect assumption.
 *
 * For now, absent data sheets on this part, we're going just leave
 * the code for this in nge.
 *
 * If someone has data sheets and can "prove" that the architecture
 * works portably across drivers, revisiting this logic and adding code
 * to handle these PHYs would be cleaner.
 */
boolean_t
phy_cicada_probe(phy_handle_t *ph)
{
	switch (MII_PHY_MFG(ph->phy_id)) {
	case MII_OUI_CICADA:
	case MII_OUI_CICADA_2:
		switch (MII_PHY_MODEL(ph->phy_id)) {
		case MII_MODEL_CICADA_CS8201:
		case MII_MODEL_CICADA_CS8201A:
		case MII_MODEL_CICADA_CS8201B:
			ph->phy_vendor = "Cicada";
			ph->phy_model = "CS8201";
			return (B_TRUE);
		default:
			break;
		}
		break;

	default:
		break;
	}

	return (B_FALSE);
}
