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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
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

#define	MAC_KSTAT_NAME	"mac"
#define	MAC_KSTAT_CLASS	"net"

static mac_stat_info_t	i_mac_si[] = {
	{ MAC_STAT_IFSPEED,	"ifspeed",	KSTAT_DATA_UINT64,	0 },
	{ MAC_STAT_MULTIRCV,	"multircv",	KSTAT_DATA_UINT32,	0 },
	{ MAC_STAT_BRDCSTRCV,	"brdcstrcv",	KSTAT_DATA_UINT32,	0 },
	{ MAC_STAT_MULTIXMT,	"multixmt",	KSTAT_DATA_UINT32,	0 },
	{ MAC_STAT_BRDCSTXMT,	"brdcstxmt",	KSTAT_DATA_UINT32,	0 },
	{ MAC_STAT_NORCVBUF,	"norcvbuf",	KSTAT_DATA_UINT32,	0 },
	{ MAC_STAT_IERRORS,	"ierrors",	KSTAT_DATA_UINT32,	0 },
	{ MAC_STAT_UNKNOWNS,	"unknowns",	KSTAT_DATA_UINT32,	0 },
	{ MAC_STAT_NOXMTBUF,	"noxmtbuf",	KSTAT_DATA_UINT32,	0 },
	{ MAC_STAT_OERRORS,	"oerrors",	KSTAT_DATA_UINT32,	0 },
	{ MAC_STAT_COLLISIONS,	"collisions",	KSTAT_DATA_UINT32,	0 },
	{ MAC_STAT_UNDERFLOWS,	"uflo",		KSTAT_DATA_UINT32,	0 },
	{ MAC_STAT_OVERFLOWS,	"oflo",		KSTAT_DATA_UINT32,	0 },
	{ MAC_STAT_RBYTES,	"rbytes",	KSTAT_DATA_UINT32,	0 },
	{ MAC_STAT_IPACKETS,	"ipackets",	KSTAT_DATA_UINT32,	0 },
	{ MAC_STAT_OBYTES,	"obytes",	KSTAT_DATA_UINT32,	0 },
	{ MAC_STAT_OPACKETS,	"opackets",	KSTAT_DATA_UINT32,	0 },
	{ MAC_STAT_RBYTES,	"rbytes64",	KSTAT_DATA_UINT64,	0 },
	{ MAC_STAT_IPACKETS,	"ipackets64",	KSTAT_DATA_UINT64,	0 },
	{ MAC_STAT_OBYTES,	"obytes64",	KSTAT_DATA_UINT64,	0 },
	{ MAC_STAT_OPACKETS,	"opackets64",	KSTAT_DATA_UINT64,	0 }
};

#define	MAC_NKSTAT \
	(sizeof (i_mac_si) / sizeof (mac_stat_info_t))

static mac_stat_info_t	i_mac_mod_si[] = {
	{ MAC_STAT_LINK_STATE,	"link_state",	KSTAT_DATA_UINT32,
	    (uint64_t)LINK_STATE_UNKNOWN },
	{ MAC_STAT_LINK_UP,	"link_up",	KSTAT_DATA_UINT32,	0 },
	{ MAC_STAT_PROMISC,	"promisc",	KSTAT_DATA_UINT32,	0 }
};

#define	MAC_MOD_NKSTAT \
	(sizeof (i_mac_mod_si) / sizeof (mac_stat_info_t))

#define	MAC_MOD_KSTAT_OFFSET	0
#define	MAC_KSTAT_OFFSET	MAC_MOD_KSTAT_OFFSET + MAC_MOD_NKSTAT
#define	MAC_TYPE_KSTAT_OFFSET	MAC_KSTAT_OFFSET + MAC_NKSTAT

/*
 * Private functions.
 */

static int
i_mac_stat_update(kstat_t *ksp, int rw)
{
	mac_impl_t	*mip = ksp->ks_private;
	kstat_named_t	*knp = ksp->ks_data;
	uint_t		i;
	uint64_t	val;
	mac_stat_info_t	*msi;
	uint_t		msi_index;

	if (rw != KSTAT_READ)
		return (EACCES);

	for (i = 0; i < mip->mi_kstat_count; i++, msi_index++) {
		if (i == MAC_MOD_KSTAT_OFFSET) {
			msi_index = 0;
			msi = i_mac_mod_si;
		} else if (i == MAC_KSTAT_OFFSET) {
			msi_index = 0;
			msi = i_mac_si;
		} else if (i == MAC_TYPE_KSTAT_OFFSET) {
			msi_index = 0;
			msi = mip->mi_type->mt_stats;
		}

		val = mac_stat_get((mac_handle_t)mip, msi[msi_index].msi_stat);
		switch (msi[msi_index].msi_type) {
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

	return (0);
}

static void
i_mac_kstat_init(kstat_named_t *knp, mac_stat_info_t *si, uint_t count)
{
	int i;
	for (i = 0; i < count; i++) {
		kstat_named_init(knp, si[i].msi_name, si[i].msi_type);
		knp++;
	}
}

/*
 * Exported functions.
 */

/*
 * Create the "mac" kstat.  The "mac" kstat is comprised of three kinds of
 * statistics: statistics maintained by the mac module itself, generic mac
 * statistics maintained by the driver, and MAC-type specific statistics
 * also maintained by the driver.
 */
void
mac_stat_create(mac_impl_t *mip)
{
	kstat_t		*ksp;
	kstat_named_t	*knp;
	uint_t		count;
	major_t		major = getmajor(mip->mi_phy_dev);

	count = MAC_MOD_NKSTAT + MAC_NKSTAT + mip->mi_type->mt_statcount;
	if (!GLDV3_DRV(major)) {
		ksp = kstat_create((const char *)ddi_major_to_name(major),
		    getminor(mip->mi_phy_dev) - 1, MAC_KSTAT_NAME,
		    MAC_KSTAT_CLASS, KSTAT_TYPE_NAMED, count, 0);
	} else {
		major = ddi_driver_major(mip->mi_dip);
		ksp = kstat_create((const char *)ddi_major_to_name(major),
		    mip->mi_minor - 1, MAC_KSTAT_NAME,
		    MAC_KSTAT_CLASS, KSTAT_TYPE_NAMED, count, 0);
	}
	if (ksp == NULL)
		return;

	ksp->ks_update = i_mac_stat_update;
	ksp->ks_private = mip;
	mip->mi_ksp = ksp;
	mip->mi_kstat_count = count;

	knp = (kstat_named_t *)ksp->ks_data;
	i_mac_kstat_init(knp, i_mac_mod_si, MAC_MOD_NKSTAT);
	knp += MAC_MOD_NKSTAT;
	i_mac_kstat_init(knp, i_mac_si, MAC_NKSTAT);
	if (mip->mi_type->mt_statcount > 0) {
		knp += MAC_NKSTAT;
		i_mac_kstat_init(knp, mip->mi_type->mt_stats,
		    mip->mi_type->mt_statcount);
	}

	kstat_install(ksp);
}

/*ARGSUSED*/
void
mac_stat_destroy(mac_impl_t *mip)
{
	if (mip->mi_ksp != NULL) {
		kstat_delete(mip->mi_ksp);
		mip->mi_ksp = NULL;
		mip->mi_kstat_count = 0;
	}
}

uint64_t
mac_stat_default(mac_impl_t *mip, uint_t stat)
{
	uint_t	stat_index;

	if (IS_MAC_STAT(stat)) {
		stat_index = stat - MAC_STAT_MIN;
		return (i_mac_si[stat_index].msi_default);
	}
	ASSERT(IS_MACTYPE_STAT(stat));
	stat_index = stat - MACTYPE_STAT_MIN;
	return (mip->mi_type->mt_stats[stat_index].msi_default);
}
