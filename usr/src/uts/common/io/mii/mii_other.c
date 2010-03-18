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
 * MII overrides for other PHYs.
 */

#include <sys/types.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/mii.h>
#include <sys/miiregs.h>
#include "miipriv.h"

#define	OUI(MFG, VEND)	{ MII_OUI_##MFG, VEND }

static const struct {
	uint32_t	oui;
	const char	*vendor;
} other_vendors[] = {
	OUI(ALTIMA, "Altima Communications"),
	OUI(AMD, "Advanced Micro Devices"),
	OUI(AMD_2, "Advanced Micro Devices"),
	OUI(ATTANSIC, "Atheros/Attansic"),
	OUI(BROADCOM, "Broadcom Corporation"),
	OUI(BROADCOM_2, "Broadcom Corporation"),
	OUI(CICADA, "Cicada Semiconductor"),
	OUI(CICADA_2, "Cicada Semiconductor"),
	OUI(DAVICOM, "Davicom Semiconductor"),
	OUI(DAVICOM_2, "Davicom Semiconductor"),
	OUI(ICPLUS, "IC Plus Corp."),
	OUI(ICS, "Integrated Circuit Systems"),
	OUI(LUCENT, "Lucent Technologies"),
	OUI(INTEL, "Intel"),
	OUI(MARVELL, "Marvell Technology"),
	OUI(NATIONAL_SEMI, "National Semiconductor"),
	OUI(NATIONAL_SEMI_2, "National Semiconductor"),
	OUI(QUALITY_SEMI, "Quality Semiconductor"),
	OUI(QUALITY_SEMI_2, "Quality Semiconductor"),
	{ 0, NULL }
};

#define	ID(MFG, MODEL, DESC)	\
	{ MII_OUI_##MFG, MII_MODEL_##MFG##_##MODEL, DESC }
#define	IDN(MFG, N, MODEL, DESC)					\
	{ MII_OUI_##MFG##_##N, MII_MODEL_##MFG##_##MODEL, DESC }
static const struct {
	uint32_t	oui;
	uint32_t	model;
	const char	*desc;
} other_phys[] = {

	/*
	 * Altima phys are standard compliant.
	 * AMD Am79C874 and Am79C875 phys are work-alikes.
	 */
	ID(ALTIMA, AC101, "AC101/Am79C874"),
	ID(ALTIMA, AC101L, "AC101L"),
	ID(ALTIMA, AM79C875, "Am79C875"),

	/*
	 * AMD phys are pretty much standard.
	 */
	ID(AMD, AM79C901, "Am79C901"),
	ID(AMD, AM79C972, "Am79C792"),
	ID(AMD, AM79C973, "Am79C793"),
	IDN(AMD, 2, AM79C901, "Am79C901"),
	IDN(AMD, 2, AM79C972, "Am79C792"),
	IDN(AMD, 2, AM79C973, "Am79C793"),

	/*
	 * Davicom phys are standard compliant.
	 */
	ID(DAVICOM, DM9101, "DM9101"),
	ID(DAVICOM, DM9102, "DM9102"),
	ID(DAVICOM, DM9161, "DM9161"),
	IDN(DAVICOM, 2, DM9101, "DM9101"),
	IDN(DAVICOM, 2, DM9102, "DM9102"),

	/*
	 * IC Plus phy is standard compliant.
	 */
	ID(ICPLUS, IP101, "IP101"),

	/*
	 * ICS phys need double read (bits are latched), have some
	 * faster polling support, and support for automatic power down.
	 * The framework deals with the first, we don't need the second,
	 * and the third is set to default anyway, so we don't need to
	 * use any special handling.
	 */
	ID(ICS, ICS1889, "ICS1889"),
	ID(ICS, ICS1890, "ICS1890"),
	ID(ICS, ICS1892, "ICS1892"),
	ID(ICS, ICS1893, "ICS1893"),

	ID(LUCENT, LU6612, "LU6612"),

	{ 0, 0, NULL },
};

boolean_t
phy_other_probe(phy_handle_t *ph)
{
	uint32_t vid = MII_PHY_MFG(ph->phy_id);
	uint32_t pid = MII_PHY_MODEL(ph->phy_id);

	if ((ph->phy_id == 0) || (ph->phy_id == 0xffffffffU)) {
		/*
		 * IDs are technically optional, but all discrete PHYs
		 * should have them.
		 */
		ph->phy_vendor = "Internal";
		ph->phy_model = "PHY";
	}
	for (int i = 0; other_vendors[i].vendor; i++) {
		if (vid == other_vendors[i].oui) {
			ph->phy_vendor = other_vendors[i].vendor;

			for (int j = 0; other_phys[j].desc; j++) {
				if (vid == other_phys[j].oui &&
				    pid == other_phys[j].model) {
					ph->phy_model = other_phys[j].desc;
					return (B_TRUE);
				}
			}

			/* PHY from this vendor isn't known to us */
			return (B_FALSE);
		}
	}
	return (B_FALSE);
}
