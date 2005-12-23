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
 * Data-Link Services Module
 */

#include <sys/types.h>
#include <sys/sysmacros.h>
#include <sys/atomic.h>
#include <sys/kstat.h>
#include <sys/vlan.h>
#include <sys/mac.h>
#include <sys/ctype.h>
#include <sys/dls.h>
#include <sys/dls_impl.h>

typedef struct i_dls_stat_info_s {
	enum mac_stat	dsi_stat;
	char		*dsi_name;
	uint_t		dsi_type;
} i_mac_stat_info_t;

static i_mac_stat_info_t	i_dls_si[] = {
	{ MAC_STAT_IFSPEED, "ifspeed", KSTAT_DATA_UINT64 },
	{ MAC_STAT_MULTIRCV, "multircv", KSTAT_DATA_UINT32 },
	{ MAC_STAT_BRDCSTRCV, "brdcstrcv", KSTAT_DATA_UINT32 },
	{ MAC_STAT_MULTIXMT, "multixmt", KSTAT_DATA_UINT32 },
	{ MAC_STAT_BRDCSTXMT, "brdcstxmt", KSTAT_DATA_UINT32 },
	{ MAC_STAT_NORCVBUF, "norcvbuf", KSTAT_DATA_UINT32 },
	{ MAC_STAT_IERRORS, "ierrors", KSTAT_DATA_UINT32 },
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
	{ MAC_STAT_OPACKETS, "opackets64", KSTAT_DATA_UINT64 }
};

#define	STAT_INFO_COUNT	(sizeof (i_dls_si) / sizeof (i_dls_si[0]))

/*
 * Private functions.
 */

static int
i_dls_stat_update(kstat_t *ksp, int rw)
{
	dls_vlan_t	*dvp = ksp->ks_private;
	dls_link_t	*dlp = dvp->dv_dlp;
	kstat_named_t	*knp;
	uint_t		i;
	uint64_t	val;
	int		err;

	if (rw != KSTAT_READ)
		return (EACCES);

	if ((err = dls_mac_hold(dlp)) != 0)
		return (err);

	knp = (kstat_named_t *)ksp->ks_data;
	for (i = 0; i < STAT_INFO_COUNT; i++) {
		if (!(dlp->dl_mip->mi_stat[i_dls_si[i].dsi_stat]))
			continue;

		val = mac_stat_get(dlp->dl_mh, i_dls_si[i].dsi_stat);

		switch (i_dls_si[i].dsi_type) {
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

	knp->value.ui32 = dlp->dl_unknowns;
	dls_mac_rele(dlp);

	return (0);
}

/*
 * Exported functions.
 */

void
dls_mac_stat_create(dls_vlan_t *dvp)
{
	dls_link_t		*dlp = dvp->dv_dlp;
	char			module[IFNAMSIZ];
	uint_t			instance;
	kstat_t			*ksp;
	kstat_named_t		*knp;
	uint_t			i;
	uint_t			count;
	int			err;

	if (dls_mac_hold(dlp) != 0)
		return;

	count = 0;
	for (i = 0; i < STAT_INFO_COUNT; i++) {
		if (dlp->dl_mip->mi_stat[i_dls_si[i].dsi_stat])
			count++;
	}

	err = ddi_parse(dvp->dv_name, module, &instance);
	ASSERT(err == DDI_SUCCESS);

	if ((ksp = kstat_create(module, instance, NULL, "net",
	    KSTAT_TYPE_NAMED, count + 1, 0)) == NULL)
		goto done;

	ksp->ks_update = i_dls_stat_update;
	ksp->ks_private = (void *)dvp;
	dvp->dv_ksp = ksp;

	knp = (kstat_named_t *)ksp->ks_data;
	for (i = 0; i < STAT_INFO_COUNT; i++) {
		if (!(dlp->dl_mip->mi_stat[i_dls_si[i].dsi_stat]))
			continue;

		kstat_named_init(knp, i_dls_si[i].dsi_name,
		    i_dls_si[i].dsi_type);
		knp++;
		--count;
	}
	ASSERT(count == 0);

	kstat_named_init(knp, "unknowns", KSTAT_DATA_UINT32);

	kstat_install(ksp);
done:
	dls_mac_rele(dlp);
}

void
dls_mac_stat_destroy(dls_vlan_t *dvp)
{
	kstat_delete(dvp->dv_ksp);
	dvp->dv_ksp = NULL;
}
