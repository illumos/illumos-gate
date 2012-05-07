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
 * Copyright 2011 Joyent, Inc.  All rights reserved.
 */

/*
 * Data-Link Services Module
 */

#include <sys/dld_impl.h>
#include <sys/mac_ether.h>

/*
 * structure for link kstats
 */
typedef struct {
	kstat_named_t	dk_ifspeed;
	kstat_named_t	dk_multircv;
	kstat_named_t	dk_brdcstrcv;
	kstat_named_t	dk_multixmt;
	kstat_named_t	dk_brdcstxmt;
	kstat_named_t	dk_norcvbuf;
	kstat_named_t	dk_ierrors;
	kstat_named_t	dk_noxmtbuf;
	kstat_named_t	dk_oerrors;
	kstat_named_t	dk_collisions;
	kstat_named_t	dk_rbytes;
	kstat_named_t	dk_ipackets;
	kstat_named_t	dk_obytes;
	kstat_named_t	dk_opackets;
	kstat_named_t	dk_rbytes64;
	kstat_named_t	dk_ipackets64;
	kstat_named_t	dk_obytes64;
	kstat_named_t	dk_opackets64;
	kstat_named_t	dk_link_state;
	kstat_named_t	dk_link_duplex;
	kstat_named_t	dk_unknowns;
	kstat_named_t	dk_zonename;
} dls_kstat_t;

/*
 * Exported functions.
 */
int
dls_stat_update(kstat_t *ksp, dls_link_t *dlp, int rw)
{
	dls_kstat_t *dkp = ksp->ks_data;

	if (rw != KSTAT_READ)
		return (EACCES);

	dkp->dk_ifspeed.value.ui64 = mac_stat_get(dlp->dl_mh, MAC_STAT_IFSPEED);
	dkp->dk_multircv.value.ui32 = mac_stat_get(dlp->dl_mh,
	    MAC_STAT_MULTIRCV);
	dkp->dk_brdcstrcv.value.ui32 = mac_stat_get(dlp->dl_mh,
	    MAC_STAT_BRDCSTRCV);
	dkp->dk_multixmt.value.ui32 = mac_stat_get(dlp->dl_mh,
	    MAC_STAT_MULTIXMT);
	dkp->dk_brdcstxmt.value.ui32 = mac_stat_get(dlp->dl_mh,
	    MAC_STAT_BRDCSTXMT);
	dkp->dk_norcvbuf.value.ui32 = mac_stat_get(dlp->dl_mh,
	    MAC_STAT_NORCVBUF);
	dkp->dk_ierrors.value.ui32 = mac_stat_get(dlp->dl_mh, MAC_STAT_IERRORS);
	dkp->dk_noxmtbuf.value.ui32 = mac_stat_get(dlp->dl_mh,
	    MAC_STAT_NOXMTBUF);
	dkp->dk_oerrors.value.ui32 = mac_stat_get(dlp->dl_mh, MAC_STAT_OERRORS);
	dkp->dk_collisions.value.ui32 = mac_stat_get(dlp->dl_mh,
	    MAC_STAT_COLLISIONS);
	dkp->dk_rbytes.value.ui32 = mac_stat_get(dlp->dl_mh, MAC_STAT_RBYTES);
	dkp->dk_ipackets.value.ui32 = mac_stat_get(dlp->dl_mh,
	    MAC_STAT_IPACKETS);
	dkp->dk_obytes.value.ui32 = mac_stat_get(dlp->dl_mh, MAC_STAT_OBYTES);
	dkp->dk_opackets.value.ui32 = mac_stat_get(dlp->dl_mh,
	    MAC_STAT_OPACKETS);
	dkp->dk_rbytes64.value.ui64 = mac_stat_get(dlp->dl_mh, MAC_STAT_RBYTES);
	dkp->dk_ipackets64.value.ui64 = mac_stat_get(dlp->dl_mh,
	    MAC_STAT_IPACKETS);
	dkp->dk_obytes64.value.ui64 = mac_stat_get(dlp->dl_mh, MAC_STAT_OBYTES);
	dkp->dk_opackets64.value.ui64 = mac_stat_get(dlp->dl_mh,
	    MAC_STAT_OPACKETS);
	dkp->dk_link_state.value.ui32 = mac_stat_get(dlp->dl_mh,
	    MAC_STAT_LINK_STATE);

	/*
	 * Ethernet specific kstat "link_duplex"
	 */
	if (dlp->dl_mip->mi_nativemedia != DL_ETHER) {
		dkp->dk_link_duplex.value.ui32 = LINK_DUPLEX_UNKNOWN;
	} else {
		dkp->dk_link_duplex.value.ui32 =
		    (uint32_t)mac_stat_get(dlp->dl_mh, ETHER_STAT_LINK_DUPLEX);
	}

	dkp->dk_unknowns.value.ui32 = dlp->dl_unknowns;

	return (0);
}

int
dls_stat_create(const char *module, int instance, const char *name,
    zoneid_t zoneid, int (*update)(struct kstat *, int), void *private,
    kstat_t **kspp, zoneid_t newzoneid)
{
	kstat_t		*ksp;
	zone_t		*zone;
	dls_kstat_t	*dkp;

	if ((ksp = kstat_create_zone(module, instance, name, "net",
	    KSTAT_TYPE_NAMED, sizeof (dls_kstat_t) / sizeof (kstat_named_t),
	    KSTAT_FLAG_VIRTUAL, zoneid)) == NULL) {
		return (EINVAL);
	}

	ksp->ks_update = update;
	ksp->ks_private = private;
	dkp = ksp->ks_data = kmem_zalloc(sizeof (dls_kstat_t), KM_SLEEP);
	if ((zone = zone_find_by_id(newzoneid)) != NULL) {
		ksp->ks_data_size += strlen(zone->zone_name) + 1;
	}

	kstat_named_init(&dkp->dk_ifspeed, "ifspeed", KSTAT_DATA_UINT64);
	kstat_named_init(&dkp->dk_multircv, "multircv", KSTAT_DATA_UINT32);
	kstat_named_init(&dkp->dk_brdcstrcv, "brdcstrcv", KSTAT_DATA_UINT32);
	kstat_named_init(&dkp->dk_multixmt, "multixmt", KSTAT_DATA_UINT32);
	kstat_named_init(&dkp->dk_brdcstxmt, "brdcstxmt", KSTAT_DATA_UINT32);
	kstat_named_init(&dkp->dk_norcvbuf, "norcvbuf", KSTAT_DATA_UINT32);
	kstat_named_init(&dkp->dk_ierrors, "ierrors", KSTAT_DATA_UINT32);
	kstat_named_init(&dkp->dk_noxmtbuf, "noxmtbuf", KSTAT_DATA_UINT32);
	kstat_named_init(&dkp->dk_oerrors, "oerrors", KSTAT_DATA_UINT32);
	kstat_named_init(&dkp->dk_collisions, "collisions", KSTAT_DATA_UINT32);
	kstat_named_init(&dkp->dk_rbytes, "rbytes", KSTAT_DATA_UINT32);
	kstat_named_init(&dkp->dk_ipackets, "ipackets", KSTAT_DATA_UINT32);
	kstat_named_init(&dkp->dk_obytes, "obytes", KSTAT_DATA_UINT32);
	kstat_named_init(&dkp->dk_opackets, "opackets", KSTAT_DATA_UINT32);
	kstat_named_init(&dkp->dk_rbytes64, "rbytes64", KSTAT_DATA_UINT64);
	kstat_named_init(&dkp->dk_ipackets64, "ipackets64", KSTAT_DATA_UINT64);
	kstat_named_init(&dkp->dk_obytes64, "obytes64", KSTAT_DATA_UINT64);
	kstat_named_init(&dkp->dk_opackets64, "opackets64", KSTAT_DATA_UINT64);
	kstat_named_init(&dkp->dk_link_state, "link_state", KSTAT_DATA_UINT32);
	kstat_named_init(&dkp->dk_link_duplex, "link_duplex",
		    KSTAT_DATA_UINT32);
	kstat_named_init(&dkp->dk_unknowns, "unknowns", KSTAT_DATA_UINT32);
	kstat_named_init(&dkp->dk_zonename, "zonename", KSTAT_DATA_STRING);

	if (zone != NULL) {
		kstat_named_setstr(&dkp->dk_zonename, zone->zone_name);
		zone_rele(zone);
	}

	kstat_install(ksp);
	*kspp = ksp;
	return (0);
}

void
dls_stat_delete(kstat_t *ksp)
{
	void *data;
	if (ksp != NULL) {
		data = ksp->ks_data;
		kstat_delete(ksp);
		kmem_free(data, sizeof (dls_kstat_t));
	}
}
