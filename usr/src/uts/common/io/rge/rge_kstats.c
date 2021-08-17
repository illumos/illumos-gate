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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "rge.h"

#define	RGE_DBG		RGE_DBG_STATS	/* debug flag for this code	*/

/*
 * Local datatype for defining tables of (Offset, Name) pairs
 */
typedef struct {
	offset_t	index;
	char		*name;
} rge_ksindex_t;

static const rge_ksindex_t rge_driverinfo[] = {
	{ 0,		"rx_ring_addr"		},
	{ 1,		"rx_next"		},
	{ 2,		"rx_free"		},
	{ 3,		"rx_bcopy"		},
	{ 4,		"tx_ring_addr"		},
	{ 5,		"tx_next"		},
	{ 6,		"tx_free"		},
	{ 7,		"tx_flow"		},
	{ 8,		"resched_needed"	},
	{ 9,		"watchdog"		},
	{ 10,		"rx_config"		},
	{ 11,		"tx_config"		},
	{ 12,		"mac_ver"		},
	{ 13,		"phy_ver"		},
	{ 14,		"chip_reset"		},
	{ 15,		"phy_reset"		},
	{ 16,		"loop_mode"		},
	{ -1,		NULL			}
};

static int
rge_driverinfo_update(kstat_t *ksp, int flag)
{
	rge_t *rgep;
	kstat_named_t *knp;

	if (flag != KSTAT_READ)
		return (EACCES);

	rgep = ksp->ks_private;
	knp = ksp->ks_data;

	(knp++)->value.ui64 = rgep->dma_area_rxdesc.cookie.dmac_laddress;
	(knp++)->value.ui64 = rgep->rx_next;
	(knp++)->value.ui64 = rgep->rx_free;
	(knp++)->value.ui64 = rgep->rx_bcopy;
	(knp++)->value.ui64 = rgep->dma_area_txdesc.cookie.dmac_laddress;
	(knp++)->value.ui64 = rgep->tx_next;
	(knp++)->value.ui64 = rgep->tx_free;
	(knp++)->value.ui64 = rgep->tx_flow;
	(knp++)->value.ui64 = rgep->resched_needed;
	(knp++)->value.ui64 = rgep->watchdog;
	(knp++)->value.ui64 = rgep->chipid.rxconfig;
	(knp++)->value.ui64 = rgep->chipid.txconfig;
	(knp++)->value.ui64 = rgep->chipid.mac_ver;
	(knp++)->value.ui64 = rgep->chipid.phy_ver;
	(knp++)->value.ui64 = rgep->stats.chip_reset;
	(knp++)->value.ui64 = rgep->stats.phy_reset;
	(knp++)->value.ui64 = rgep->param_loop_mode;

	return (0);
}

static kstat_t *
rge_setup_named_kstat(rge_t *rgep, int instance, char *name,
    const rge_ksindex_t *ksip, size_t size, int (*update)(kstat_t *, int))
{
	kstat_t *ksp;
	kstat_named_t *knp;
	char *np;
	int type;

	size /= sizeof (rge_ksindex_t);
	ksp = kstat_create(RGE_DRIVER_NAME, instance, name, "net",
	    KSTAT_TYPE_NAMED, size-1, KSTAT_FLAG_PERSISTENT);
	if (ksp == NULL)
		return (NULL);

	ksp->ks_private = rgep;
	ksp->ks_update = update;
	for (knp = ksp->ks_data; (np = ksip->name) != NULL; ++knp, ++ksip) {
		switch (*np) {
		default:
			type = KSTAT_DATA_UINT64;
			break;
		case '%':
			np += 1;
			type = KSTAT_DATA_UINT32;
			break;
		case '$':
			np += 1;
			type = KSTAT_DATA_STRING;
			break;
		case '&':
			np += 1;
			type = KSTAT_DATA_CHAR;
			break;
		}
		kstat_named_init(knp, np, type);
	}
	kstat_install(ksp);

	return (ksp);
}

void
rge_init_kstats(rge_t *rgep, int instance)
{
	rgep->rge_kstats[RGE_KSTAT_DRIVER] = rge_setup_named_kstat(rgep,
	    instance, "driverinfo", rge_driverinfo,
	    sizeof (rge_driverinfo), rge_driverinfo_update);
}

void
rge_fini_kstats(rge_t *rgep)
{
	int i;

	for (i = RGE_KSTAT_COUNT; --i >= 0; )
		if (rgep->rge_kstats[i] != NULL) {
			kstat_delete(rgep->rge_kstats[i]);
		}
}

int
rge_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	rge_t *rgep = arg;
	rge_hw_stats_t *bstp;

	mutex_enter(rgep->genlock);
	rge_hw_stats_dump(rgep);
	mutex_exit(rgep->genlock);
	bstp = rgep->hw_stats;

	switch (stat) {
	case MAC_STAT_IFSPEED:
		*val = rgep->param_link_speed * 1000000ull;
		break;

	case MAC_STAT_MULTIRCV:
		*val = RGE_BSWAP_32(bstp->multi_rcv);
		break;

	case MAC_STAT_BRDCSTRCV:
		*val = RGE_BSWAP_64(bstp->brdcst_rcv);
		break;

	case MAC_STAT_NORCVBUF:
		*val = RGE_BSWAP_16(bstp->in_discards);
		break;

	case MAC_STAT_IERRORS:
		*val = RGE_BSWAP_32(bstp->rcv_err);
		break;

	case MAC_STAT_OERRORS:
		*val = RGE_BSWAP_64(bstp->xmt_err);
		break;

	case MAC_STAT_COLLISIONS:
		*val = RGE_BSWAP_32(bstp->xmt_1col + bstp->xmt_mcol);
		break;

	case MAC_STAT_RBYTES:
		*val = rgep->stats.rbytes;
		break;

	case MAC_STAT_IPACKETS:
		*val = RGE_BSWAP_64(bstp->rcv_ok);
		break;

	case MAC_STAT_OBYTES:
		*val = rgep->stats.obytes;
		break;

	case MAC_STAT_OPACKETS:
		*val = RGE_BSWAP_64(bstp->xmt_ok);
		break;

	case ETHER_STAT_ALIGN_ERRORS:
		*val = RGE_BSWAP_16(bstp->frame_err);
		break;

	case ETHER_STAT_FIRST_COLLISIONS:
		*val = RGE_BSWAP_32(bstp->xmt_1col);
		break;

	case ETHER_STAT_MULTI_COLLISIONS:
		*val = RGE_BSWAP_32(bstp->xmt_mcol);
		break;

	case ETHER_STAT_DEFER_XMTS:
		*val = rgep->stats.defer;
		break;

	case ETHER_STAT_XCVR_ADDR:
		*val = rgep->phy_mii_addr;
		break;

	case ETHER_STAT_XCVR_ID:
		mutex_enter(rgep->genlock);
		*val = rge_mii_get16(rgep, MII_PHYIDH);
		*val <<= 16;
		*val |= rge_mii_get16(rgep, MII_PHYIDL);
		mutex_exit(rgep->genlock);
		break;

	case ETHER_STAT_XCVR_INUSE:
		*val = XCVR_1000T;
		break;

	case ETHER_STAT_CAP_1000FDX:
		*val = 1;
		break;

	case ETHER_STAT_CAP_1000HDX:
		*val = 0;
		break;

	case ETHER_STAT_CAP_100FDX:
		*val = 1;
		break;

	case ETHER_STAT_CAP_100HDX:
		*val = 1;
		break;

	case ETHER_STAT_CAP_10FDX:
		*val = 1;
		break;

	case ETHER_STAT_CAP_10HDX:
		*val = 1;
		break;

	case ETHER_STAT_CAP_ASMPAUSE:
		*val = 1;
		break;

	case ETHER_STAT_CAP_PAUSE:
		*val = 1;
		break;

	case ETHER_STAT_CAP_AUTONEG:
		*val = 1;
		break;

	case ETHER_STAT_ADV_CAP_1000FDX:
		*val = rgep->param_adv_1000fdx;
		break;

	case ETHER_STAT_ADV_CAP_1000HDX:
		*val = rgep->param_adv_1000hdx;
		break;

	case ETHER_STAT_ADV_CAP_100FDX:
		*val = rgep->param_adv_100fdx;
		break;

	case ETHER_STAT_ADV_CAP_100HDX:
		*val = rgep->param_adv_100hdx;
		break;

	case ETHER_STAT_ADV_CAP_10FDX:
		*val = rgep->param_adv_10fdx;
		break;

	case ETHER_STAT_ADV_CAP_10HDX:
		*val = rgep->param_adv_10hdx;
		break;

	case ETHER_STAT_ADV_CAP_ASMPAUSE:
		*val = rgep->param_adv_asym_pause;
		break;

	case ETHER_STAT_ADV_CAP_PAUSE:
		*val = rgep->param_adv_pause;
		break;

	case ETHER_STAT_ADV_CAP_AUTONEG:
		*val = rgep->param_adv_autoneg;
		break;

	case ETHER_STAT_LINK_DUPLEX:
		*val = rgep->param_link_duplex;
		break;

	default:
		return (ENOTSUP);
	}

	return (0);
}
