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

/*
 * Data-Link Services Module
 */

#include <sys/dld_impl.h>
#include <sys/mac_ether.h>

static mac_stat_info_t	i_dls_si[] = {
	{ MAC_STAT_IFSPEED, "ifspeed", KSTAT_DATA_UINT64, 0 },
	{ MAC_STAT_MULTIRCV, "multircv", KSTAT_DATA_UINT32, 0 },
	{ MAC_STAT_BRDCSTRCV, "brdcstrcv", KSTAT_DATA_UINT32, 0 },
	{ MAC_STAT_MULTIXMT, "multixmt", KSTAT_DATA_UINT32, 0 },
	{ MAC_STAT_BRDCSTXMT, "brdcstxmt", KSTAT_DATA_UINT32, 0 },
	{ MAC_STAT_NORCVBUF, "norcvbuf", KSTAT_DATA_UINT32, 0 },
	{ MAC_STAT_IERRORS, "ierrors", KSTAT_DATA_UINT32, 0 },
	{ MAC_STAT_NOXMTBUF, "noxmtbuf", KSTAT_DATA_UINT32, 0 },
	{ MAC_STAT_OERRORS, "oerrors", KSTAT_DATA_UINT32, 0 },
	{ MAC_STAT_COLLISIONS, "collisions", KSTAT_DATA_UINT32, 0 },
	{ MAC_STAT_RBYTES, "rbytes", KSTAT_DATA_UINT32, 0 },
	{ MAC_STAT_IPACKETS, "ipackets", KSTAT_DATA_UINT32, 0 },
	{ MAC_STAT_OBYTES, "obytes", KSTAT_DATA_UINT32, 0 },
	{ MAC_STAT_OPACKETS, "opackets", KSTAT_DATA_UINT32, 0 },
	{ MAC_STAT_RBYTES, "rbytes64", KSTAT_DATA_UINT64, 0 },
	{ MAC_STAT_IPACKETS, "ipackets64", KSTAT_DATA_UINT64, 0 },
	{ MAC_STAT_OBYTES, "obytes64", KSTAT_DATA_UINT64, 0 },
	{ MAC_STAT_OPACKETS, "opackets64", KSTAT_DATA_UINT64, 0 },
	{ MAC_STAT_LINK_STATE, "link_state", KSTAT_DATA_UINT32,
	    (uint64_t)LINK_STATE_UNKNOWN}
};

#define	STAT_INFO_COUNT	(sizeof (i_dls_si) / sizeof (i_dls_si[0]))

/*
 * Exported functions.
 */
int
dls_stat_update(kstat_t *ksp, dls_link_t *dlp, int rw)
{
	kstat_named_t	*knp;
	uint_t		i;
	uint64_t	val;

	if (rw != KSTAT_READ)
		return (EACCES);

	knp = (kstat_named_t *)ksp->ks_data;
	for (i = 0; i < STAT_INFO_COUNT; i++) {
		val = mac_stat_get(dlp->dl_mh, i_dls_si[i].msi_stat);

		switch (i_dls_si[i].msi_type) {
		case KSTAT_DATA_UINT64:
			knp->value.ui64 = val;
			break;
		case KSTAT_DATA_UINT32:
			knp->value.ui32 = (uint32_t)val;
			break;
		default:
			ASSERT(B_FALSE);
		}

		knp++;
	}

	/*
	 * Ethernet specific kstat "link_duplex"
	 */
	if (dlp->dl_mip->mi_nativemedia != DL_ETHER) {
		knp->value.ui32 = LINK_DUPLEX_UNKNOWN;
	} else {
		val = mac_stat_get(dlp->dl_mh, ETHER_STAT_LINK_DUPLEX);
		knp->value.ui32 = (uint32_t)val;
	}
	knp++;
	knp->value.ui32 = dlp->dl_unknowns;

	return (0);
}

int
dls_stat_create(const char *module, int instance, const char *name,
    int (*update)(struct kstat *, int), void *private, kstat_t **kspp)
{
	kstat_t		*ksp;
	kstat_named_t	*knp;
	uint_t		i;

	if ((ksp = kstat_create(module, instance, name, "net",
	    KSTAT_TYPE_NAMED, STAT_INFO_COUNT + 2, 0)) == NULL) {
		return (EINVAL);
	}

	ksp->ks_update = update;
	ksp->ks_private = private;

	knp = (kstat_named_t *)ksp->ks_data;
	for (i = 0; i < STAT_INFO_COUNT; i++) {
		kstat_named_init(knp, i_dls_si[i].msi_name,
		    i_dls_si[i].msi_type);
		knp++;
	}

	kstat_named_init(knp++, "link_duplex", KSTAT_DATA_UINT32);
	kstat_named_init(knp, "unknowns", KSTAT_DATA_UINT32);
	kstat_install(ksp);
	*kspp = ksp;
	return (0);
}
