/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright 2005 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * MAC Services Module
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/stream.h>
#include <sys/kstat.h>
#include <sys/mac.h>
#include <sys/mac_impl.h>

typedef struct i_mac_stat_info_s {
	enum mac_stat	msi_stat;
	char		*msi_name;
	uint_t		msi_type;
} i_mac_stat_info_t;

static i_mac_stat_info_t	i_mac_si[] = {
	{ MAC_STAT_IFSPEED, "ifspeed", KSTAT_DATA_UINT64 },
	{ MAC_STAT_MULTIRCV, "multircv", KSTAT_DATA_UINT32 },
	{ MAC_STAT_BRDCSTRCV, "brdcstrcv", KSTAT_DATA_UINT32 },
	{ MAC_STAT_MULTIXMT, "multixmt", KSTAT_DATA_UINT32 },
	{ MAC_STAT_BRDCSTXMT, "brdcstxmt", KSTAT_DATA_UINT32 },
	{ MAC_STAT_NORCVBUF, "norcvbuf", KSTAT_DATA_UINT32 },
	{ MAC_STAT_IERRORS, "ierrors", KSTAT_DATA_UINT32 },
	{ MAC_STAT_UNKNOWNS, "unknowns", KSTAT_DATA_UINT32 },
	{ MAC_STAT_NOXMTBUF, "noxmtbuf", KSTAT_DATA_UINT32 },
	{ MAC_STAT_OERRORS, "oerrors", KSTAT_DATA_UINT32 },
	{ MAC_STAT_COLLISIONS, "collisions", KSTAT_DATA_UINT32 },
	{ MAC_STAT_RBYTES, "rbytes", KSTAT_DATA_UINT32 },
	{ MAC_STAT_IPACKETS, "ipackets", KSTAT_DATA_UINT32 },
	{ MAC_STAT_OBYTES, "obytes", KSTAT_DATA_UINT32 },
	{ MAC_STAT_OPACKETS, "opackets", KSTAT_DATA_UINT32 },
	{ MAC_STAT_RBYTES, "rbytes64", KSTAT_DATA_UINT64 },
	{ MAC_STAT_IPACKETS, "ipackets64", KSTAT_DATA_UINT64 },
	{ MAC_STAT_OBYTES, "obytes64", KSTAT_DATA_UINT64 },
	{ MAC_STAT_OPACKETS, "opackets64", KSTAT_DATA_UINT64 },
	{ MAC_STAT_ALIGN_ERRORS, "align_errors", KSTAT_DATA_UINT32 },
	{ MAC_STAT_FCS_ERRORS, "fcs_errors", KSTAT_DATA_UINT32 },
	{ MAC_STAT_FIRST_COLLISIONS, "first_collsions", KSTAT_DATA_UINT32 },
	{ MAC_STAT_MULTI_COLLISIONS, "multi_collsions", KSTAT_DATA_UINT32 },
	{ MAC_STAT_SQE_ERRORS, "sqe_errors", KSTAT_DATA_UINT32 },
	{ MAC_STAT_DEFER_XMTS, "defer_xmts", KSTAT_DATA_UINT32 },
	{ MAC_STAT_TX_LATE_COLLISIONS, "tx_late_collsions", KSTAT_DATA_UINT32 },
	{ MAC_STAT_EX_COLLISIONS, "ex_collsions", KSTAT_DATA_UINT32 },
	{ MAC_STAT_MACXMT_ERRORS, "macxmt_errors", KSTAT_DATA_UINT32 },
	{ MAC_STAT_CARRIER_ERRORS, "carrier_errors", KSTAT_DATA_UINT32 },
	{ MAC_STAT_TOOLONG_ERRORS, "toolong_errors", KSTAT_DATA_UINT32 },
	{ MAC_STAT_MACRCV_ERRORS, "macrcv_errors", KSTAT_DATA_UINT32 },
	{ MAC_STAT_XCVR_ADDR, "xcvr_addr", KSTAT_DATA_UINT32 },
	{ MAC_STAT_XCVR_ID, "xcvr_id", KSTAT_DATA_UINT32 },
	{ MAC_STAT_XCVR_INUSE, "xcvr_inuse", KSTAT_DATA_UINT32 },
	{ MAC_STAT_CAP_1000FDX, "cap_1000fdx", KSTAT_DATA_UINT32 },
	{ MAC_STAT_CAP_1000HDX, "cap_1000hdx", KSTAT_DATA_UINT32 },
	{ MAC_STAT_CAP_100FDX, "cap_100fdx", KSTAT_DATA_UINT32 },
	{ MAC_STAT_CAP_100HDX, "cap_100hdx", KSTAT_DATA_UINT32 },
	{ MAC_STAT_CAP_10FDX, "cap_10fdx", KSTAT_DATA_UINT32 },
	{ MAC_STAT_CAP_10HDX, "cap_10hdx", KSTAT_DATA_UINT32 },
	{ MAC_STAT_CAP_ASMPAUSE, "cap_asmpause", KSTAT_DATA_UINT32 },
	{ MAC_STAT_CAP_PAUSE, "cap_pause", KSTAT_DATA_UINT32 },
	{ MAC_STAT_CAP_AUTONEG, "cap_autoneg", KSTAT_DATA_UINT32 },
	{ MAC_STAT_ADV_CAP_1000FDX, "adv_cap_1000fdx", KSTAT_DATA_UINT32 },
	{ MAC_STAT_ADV_CAP_1000HDX, "adv_cap_1000hdx", KSTAT_DATA_UINT32 },
	{ MAC_STAT_ADV_CAP_100FDX, "adv_cap_100fdx", KSTAT_DATA_UINT32 },
	{ MAC_STAT_ADV_CAP_100HDX, "adv_cap_100hdx", KSTAT_DATA_UINT32 },
	{ MAC_STAT_ADV_CAP_10FDX, "adv_cap_10fdx", KSTAT_DATA_UINT32 },
	{ MAC_STAT_ADV_CAP_10HDX, "adv_cap_10hdx", KSTAT_DATA_UINT32 },
	{ MAC_STAT_ADV_CAP_ASMPAUSE, "adv_cap_asmpause", KSTAT_DATA_UINT32 },
	{ MAC_STAT_ADV_CAP_PAUSE, "adv_cap_pause", KSTAT_DATA_UINT32 },
	{ MAC_STAT_ADV_CAP_AUTONEG, "adv_cap_autoneg", KSTAT_DATA_UINT32 },
	{ MAC_STAT_LP_CAP_1000FDX, "lp_cap_1000fdx", KSTAT_DATA_UINT32 },
	{ MAC_STAT_LP_CAP_1000HDX, "lp_cap_1000hdx", KSTAT_DATA_UINT32 },
	{ MAC_STAT_LP_CAP_100FDX, "lp_cap_100fdx", KSTAT_DATA_UINT32 },
	{ MAC_STAT_LP_CAP_100HDX, "lp_cap_100hdx", KSTAT_DATA_UINT32 },
	{ MAC_STAT_LP_CAP_10FDX, "lp_cap_10fdx", KSTAT_DATA_UINT32 },
	{ MAC_STAT_LP_CAP_10HDX, "lp_cap_10hdx", KSTAT_DATA_UINT32 },
	{ MAC_STAT_LP_CAP_ASMPAUSE, "lp_cap_asmpause", KSTAT_DATA_UINT32 },
	{ MAC_STAT_LP_CAP_PAUSE, "lp_cap_pause", KSTAT_DATA_UINT32 },
	{ MAC_STAT_LP_CAP_AUTONEG, "lp_cap_autoneg", KSTAT_DATA_UINT32 },
	{ MAC_STAT_LINK_ASMPAUSE, "link_asmpause", KSTAT_DATA_UINT32 },
	{ MAC_STAT_LINK_PAUSE, "link_pause", KSTAT_DATA_UINT32 },
	{ MAC_STAT_LINK_AUTONEG, "link_autoneg", KSTAT_DATA_UINT32 },
	{ MAC_STAT_LINK_DUPLEX, "link_duplex", KSTAT_DATA_UINT32 }
};

#define	STAT_INFO_COUNT	(sizeof (i_mac_si) / sizeof (i_mac_si[0]))

/*
 * Private functions.
 */

static int
i_mac_stat_update(kstat_t *ksp, int rw)
{
	mac_impl_t	*mip = ksp->ks_private;
	mac_t		*mp = mip->mi_mp;
	kstat_named_t	*knp;
	uint_t		i;
	uint64_t	val;

	if (rw != KSTAT_READ)
		return (EACCES);

	knp = ksp->ks_data;
	for (i = 0; i < STAT_INFO_COUNT; i++) {
		if (!(mp->m_info.mi_stat[i_mac_si[i].msi_stat]))
			continue;

		val = mac_stat_get((mac_handle_t)mip, i_mac_si[i].msi_stat);

		switch (i_mac_si[i].msi_type) {
		case KSTAT_DATA_UINT64:
			knp->value.ui64 = val;
			break;
		case KSTAT_DATA_UINT32:
			knp->value.ui32 = (uint32_t)val;
			break;
		default:
			ASSERT(B_FALSE);
			break;
		}

		knp++;
	}

	(knp++)->value.ui32 = mip->mi_link;
	(knp++)->value.ui32 = (mip->mi_link == LINK_STATE_UP);
	knp->value.ui32 = (mip->mi_devpromisc != 0);

	return (0);
}

/*
 * Exported functions.
 */

void
mac_stat_create(mac_impl_t *mip)
{
	mac_t		*mp = mip->mi_mp;
	kstat_t		*ksp;
	kstat_named_t	*knp;
	uint_t		i;
	uint_t		count;

	count = 0;
	for (i = 0; i < STAT_INFO_COUNT; i++) {
		if (mp->m_info.mi_stat[i_mac_si[i].msi_stat])
			count++;
	}

	if ((ksp = kstat_create(mip->mi_dev, mip->mi_port, mip->mi_name,
	    "mac", KSTAT_TYPE_NAMED, count + 3, 0)) == NULL)
		return;

	ksp->ks_update = i_mac_stat_update;
	ksp->ks_private = (void *)mip;
	mip->mi_ksp = ksp;

	knp = (kstat_named_t *)ksp->ks_data;
	for (i = 0; i < STAT_INFO_COUNT; i++) {
		if (!(mp->m_info.mi_stat[i_mac_si[i].msi_stat]))
			continue;

		kstat_named_init(knp, i_mac_si[i].msi_name,
		    i_mac_si[i].msi_type);
		knp++;
		--count;
	}
	ASSERT(count == 0);

	kstat_named_init(knp++, "link_state", KSTAT_DATA_UINT32);
	kstat_named_init(knp++, "link_up", KSTAT_DATA_UINT32);
	kstat_named_init(knp, "promisc", KSTAT_DATA_UINT32);

	kstat_install(ksp);
}

/*ARGSUSED*/
void
mac_stat_destroy(mac_impl_t *mip)
{
	kstat_delete(mip->mi_ksp);
	mip->mi_ksp = NULL;
}
