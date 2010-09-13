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


#include "nge.h"

#undef	NGE_DBG
#define	NGE_DBG		NGE_DBG_STATS	/* debug flag for this code	*/

/*
 * Table of Hardware-defined Statistics Block Offsets and Names
 */
#define	KS_NAME(s)			{ KS_ ## s, #s }

const nge_ksindex_t nge_statistics[] = {

	KS_NAME(ifHOutOctets),
	KS_NAME(ifHOutZeroRetranCount),
	KS_NAME(ifHOutOneRetranCount),
	KS_NAME(ifHOutMoreRetranCount),
	KS_NAME(ifHOutColCount),
	KS_NAME(ifHOutFifoovCount),
	KS_NAME(ifHOutLOCCount),
	KS_NAME(ifHOutExDecCount),
	KS_NAME(ifHOutRetryCount),
	KS_NAME(ifHInFrameErrCount),
	KS_NAME(ifHInExtraOctErrCount),
	KS_NAME(ifHInLColErrCount),
	KS_NAME(ifHInOversizeErrCount),
	KS_NAME(ifHInFovErrCount),
	KS_NAME(ifHInFCSErrCount),
	KS_NAME(ifHInAlignErrCount),
	KS_NAME(ifHInLenErrCount),
	KS_NAME(ifHInUniPktsCount),
	KS_NAME(ifHInBroadPksCount),
	KS_NAME(ifHInMulPksCount),
	{ KS_STATS_SIZE, NULL }
};

/*
 * Local datatype for defining tables of (Offset, Name) pairs
 */
static int
nge_statistics_update(kstat_t *ksp, int flag)
{
	uint32_t regno;
	nge_t *ngep;
	nge_statistics_t *istp;
	nge_hw_statistics_t *hw_stp;
	kstat_named_t *knp;
	const nge_ksindex_t *ksip;

	if (flag != KSTAT_READ)
		return (EACCES);

	ngep = ksp->ks_private;
	istp = &ngep->statistics;
	hw_stp = &istp->hw_statistics;
	knp = ksp->ks_data;

	/*
	 * Transfer the statistics values from the hardware statistics regs
	 */
	for (ksip = nge_statistics; ksip->name != NULL; ++knp, ++ksip) {
		regno = KS_BASE + ksip->index * sizeof (uint32_t);
		hw_stp->a[ksip->index] += nge_reg_get32(ngep, regno);
		knp->value.ui64 = hw_stp->a[ksip->index];
	}

	return (0);
}


static const nge_ksindex_t nge_chipinfo[] = {
	{ 0,				"businfo"		},
	{ 1,				"command"		},
	{ 2,				"vendor_id"		},
	{ 3,				"device_id"		},
	{ 4,				"subsystem_vendor_id"	},
	{ 5,				"subsystem_device_id"	},
	{ 6,				"revision_id"		},
	{ 7,				"cache_line_size"	},
	{ 8,				"latency_timer"		},
	{ 9,				"phy_mode"		},
	{ 10,				"phy_id"		},
	{ 11,				"hw_mac_addr"		},
	{ 12,				"&bus_type"		},
	{ 13,				"&bus_speed"		},
	{ 14,				"&bus_size"		},
	{ -1,				NULL 			}
};

static const nge_ksindex_t nge_debuginfo[] = {
	{ 0,				"rx_realloc"		},
	{ 1,				"rx_realloc_fails"	},
	{ 2,				"rx_realloc_DMA_fails"	},
	{ 3,				"rx_realloc_MP_fails"	},
	{ 4,				"rx_rcfree"		},
	{ 5,				"context_switch"	},
	{ 6,				"ip_hsum_err"		},
	{ 7,				"tcp_hsum_err"		},
	{ 8,				"tc_next"		},
	{ 9,				"tx_next"		},
	{ 10,				"tx_free"		},
	{ 11,				"tx_flow"		},
	{ 12,				"rx_prod"		},
	{ 13,				"rx_hold"		},
	{ 14,				"rx_nobuf"		},
	{ 15,				"rx_err"		},
	{16,				"tx_err"		},
	{17,				"tx_stall"		},
	{ -1,				NULL 			}
};

static int
nge_chipinfo_update(kstat_t *ksp, int flag)
{
	nge_t *ngep;
	kstat_named_t *knp;
	chip_info_t *infop;

	if (flag != KSTAT_READ)
		return (EACCES);

	ngep = ksp->ks_private;
	infop = &ngep->chipinfo;
	knp = ksp->ks_data;

	(knp++)->value.ui64 = infop->businfo;
	(knp++)->value.ui64 = infop->command;
	(knp++)->value.ui64 = infop->vendor;
	(knp++)->value.ui64 = infop->device;
	(knp++)->value.ui64 = infop->subven;
	(knp++)->value.ui64 = infop->subdev;
	(knp++)->value.ui64 = infop->revision;
	(knp++)->value.ui64 = infop->clsize;
	(knp++)->value.ui64 = infop->latency;
	(knp++)->value.ui64 = ngep->phy_mode;
	(knp++)->value.ui64 = ngep->phy_id;
	(knp++)->value.ui64 = infop->hw_mac_addr;
	return (0);
}

static int
nge_debuginfo_update(kstat_t *ksp, int flag)
{
	nge_t *ngep;
	kstat_named_t *knp;
	nge_sw_statistics_t *sw_stp;

	if (flag != KSTAT_READ)
		return (EACCES);

	ngep = ksp->ks_private;
	sw_stp = &ngep->statistics.sw_statistics;
	knp = ksp->ks_data;

	(knp++)->value.ui64 = sw_stp->recv_realloc;
	(knp++)->value.ui64 = sw_stp->kmem_alloc_err;
	(knp++)->value.ui64 = sw_stp->dma_alloc_err;
	(knp++)->value.ui64 = sw_stp->mp_alloc_err;
	(knp++)->value.ui64 = sw_stp->recy_free;
	(knp++)->value.ui64 = sw_stp->load_context;
	(knp++)->value.ui64 = sw_stp->ip_hwsum_err;
	(knp++)->value.ui64 = sw_stp->tcp_hwsum_err;
	(knp++)->value.ui64 = ngep->send->tc_next;
	(knp++)->value.ui64 = ngep->send->tx_next;
	(knp++)->value.ui64 = ngep->send->tx_free;
	(knp++)->value.ui64 = ngep->send->tx_flow;
	(knp++)->value.ui64 = ngep->recv->prod_index;
	(knp++)->value.ui64 = ngep->buff->rx_hold;
	(knp++)->value.ui64 = sw_stp->rx_nobuffer;
	(knp++)->value.ui64 = sw_stp->rx_err;
	(knp++)->value.ui64 = sw_stp->tx_stop_err;
	(knp++)->value.ui64 = sw_stp->tx_stall;
	return (0);
}

static kstat_t *
nge_setup_named_kstat(nge_t *ngep, int instance, char *name,
	const nge_ksindex_t *ksip, size_t size, int (*update)(kstat_t *, int))
{
	kstat_t *ksp;
	kstat_named_t *knp;
	char *np;
	int type;

	size /= sizeof (nge_ksindex_t);
	ksp = kstat_create(NGE_DRIVER_NAME, instance, name, "net",
	    KSTAT_TYPE_NAMED, size-1, KSTAT_FLAG_PERSISTENT);
	if (ksp == NULL)
		return (NULL);

	ksp->ks_private = ngep;
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
			np ++;
			type = KSTAT_DATA_STRING;
			break;
		case '&':
			np ++;
			type = KSTAT_DATA_CHAR;
			break;
		}
		kstat_named_init(knp, np, type);
	}
	kstat_install(ksp);

	return (ksp);
}

void
nge_init_kstats(nge_t *ngep, int instance)
{
	NGE_TRACE(("nge_init_kstats($%p, %d)", (void *)ngep, instance));

	ngep->nge_kstats[NGE_KSTAT_STATS] = nge_setup_named_kstat(ngep,
	    instance, "statistics", nge_statistics,
	    sizeof (nge_statistics), nge_statistics_update);

	ngep->nge_kstats[NGE_KSTAT_CHIPID] = nge_setup_named_kstat(ngep,
	    instance, "chipinfo", nge_chipinfo,
	    sizeof (nge_chipinfo), nge_chipinfo_update);

	ngep->nge_kstats[NGE_KSTAT_DEBUG] = nge_setup_named_kstat(ngep,
	    instance, "driver-debug", nge_debuginfo,
	    sizeof (nge_debuginfo), nge_debuginfo_update);

}

void
nge_fini_kstats(nge_t *ngep)
{
	int i;

	NGE_TRACE(("nge_fini_kstats($%p)", (void *)ngep));
	for (i = NGE_KSTAT_COUNT;  --i >= 0; )
		if (ngep->nge_kstats[i] != NULL)
			kstat_delete(ngep->nge_kstats[i]);
}

int
nge_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	nge_t *ngep = arg;
	uint32_t regno;
	nge_statistics_t *nstp = &ngep->statistics;
	nge_hw_statistics_t *hw_stp = &nstp->hw_statistics;
	nge_sw_statistics_t *sw_stp = &nstp->sw_statistics;

	switch (stat) {
	case MAC_STAT_IFSPEED:
		*val = ngep->param_link_speed * 1000000ull;
		break;

	case MAC_STAT_MULTIRCV:
		regno = KS_BASE + KS_ifHInMulPksCount * sizeof (uint32_t);
		hw_stp->s.InMulPksCount += nge_reg_get32(ngep, regno);
		*val = hw_stp->s.InMulPksCount;
		break;

	case MAC_STAT_BRDCSTRCV:
		regno = KS_BASE +  KS_ifHInBroadPksCount * sizeof (uint32_t);
		hw_stp->s.InBroadPksCount += nge_reg_get32(ngep, regno);
		*val = hw_stp->s.InBroadPksCount;
		break;

	case MAC_STAT_NORCVBUF:
		*val = sw_stp->rx_nobuffer;
		break;

	case MAC_STAT_IERRORS:
		regno = KS_BASE + KS_ifHInFrameErrCount * sizeof (uint32_t);
		hw_stp->s.InFrameErrCount += nge_reg_get32(ngep, regno);
		regno = KS_BASE + KS_ifHInExtraOctErrCount * sizeof (uint32_t);
		hw_stp->s.InExtraOctErrCount += nge_reg_get32(ngep, regno);
		regno = KS_BASE + KS_ifHInLColErrCount * sizeof (uint32_t);
		hw_stp->s.InLColErrCount += nge_reg_get32(ngep, regno);
		regno = KS_BASE + KS_ifHInOversizeErrCount * sizeof (uint32_t);
		hw_stp->s.InOversizeErrCount += nge_reg_get32(ngep, regno);
		regno = KS_BASE + KS_ifHInFovErrCount * sizeof (uint32_t);
		hw_stp->s.InFovErrCount += nge_reg_get32(ngep, regno);
		regno = KS_BASE + KS_ifHInFCSErrCount * sizeof (uint32_t);
		hw_stp->s.InFCSErrCount += nge_reg_get32(ngep, regno);
		regno = KS_BASE + KS_ifHInAlignErrCount * sizeof (uint32_t);
		hw_stp->s.InAlignErrCount += nge_reg_get32(ngep, regno);
		regno = KS_BASE + KS_ifHInLenErrCount * sizeof (uint32_t);
		hw_stp->s.InLenErrCount += nge_reg_get32(ngep, regno);
		*val = hw_stp->s.InFrameErrCount +
		    hw_stp->s.InExtraOctErrCount +
		    hw_stp->s.InLColErrCount +
		    hw_stp->s.InOversizeErrCount +
		    hw_stp->s.InFovErrCount +
		    hw_stp->s.InFCSErrCount +
		    hw_stp->s.InAlignErrCount +
		    hw_stp->s.InLenErrCount;
		break;

	case MAC_STAT_OERRORS:
		regno = KS_BASE + KS_ifHOutFifoovCount * sizeof (uint32_t);
		hw_stp->s.OutFifoovCount += nge_reg_get32(ngep, regno);
		regno = KS_BASE + KS_ifHOutLOCCount * sizeof (uint32_t);
		hw_stp->s.OutLOCCount += nge_reg_get32(ngep, regno);
		regno = KS_BASE + KS_ifHOutExDecCount * sizeof (uint32_t);
		hw_stp->s.OutExDecCount += nge_reg_get32(ngep, regno);
		regno = KS_BASE + KS_ifHOutRetryCount * sizeof (uint32_t);
		hw_stp->s.OutRetryCount += nge_reg_get32(ngep, regno);
		*val = hw_stp->s.OutFifoovCount +
		    hw_stp->s.OutLOCCount +
		    hw_stp->s.OutExDecCount +
		    hw_stp->s.OutRetryCount;
		break;

	case MAC_STAT_COLLISIONS:
		regno = KS_BASE + KS_ifHOutColCount * sizeof (uint32_t);
		hw_stp->s.OutColCount += nge_reg_get32(ngep, regno);
		*val = hw_stp->s.OutColCount;
		break;

	case MAC_STAT_RBYTES:
		*val = sw_stp->rbytes;
		break;

	case MAC_STAT_IPACKETS:
		*val = sw_stp->recv_count;
		break;

	case MAC_STAT_OBYTES:
		*val = sw_stp->obytes;
		break;

	case MAC_STAT_OPACKETS:
		*val = sw_stp->xmit_count;
		break;

	case ETHER_STAT_ALIGN_ERRORS:
		regno = KS_BASE + KS_ifHInAlignErrCount * sizeof (uint32_t);
		hw_stp->s.InAlignErrCount += nge_reg_get32(ngep, regno);
		*val = hw_stp->s.InAlignErrCount;
		break;

	case ETHER_STAT_FCS_ERRORS:
		regno = KS_BASE + KS_ifHInFCSErrCount * sizeof (uint32_t);
		hw_stp->s.InFCSErrCount += nge_reg_get32(ngep, regno);
		*val = hw_stp->s.InFCSErrCount;
		break;

	case ETHER_STAT_FIRST_COLLISIONS:
		regno = KS_BASE + KS_ifHOutOneRetranCount * sizeof (uint32_t);
		hw_stp->s.OutOneRetranCount += nge_reg_get32(ngep, regno);
		*val = hw_stp->s.OutOneRetranCount;
		break;

	case ETHER_STAT_MULTI_COLLISIONS:
		regno = KS_BASE + KS_ifHOutMoreRetranCount * sizeof (uint32_t);
		hw_stp->s.OutMoreRetranCount += nge_reg_get32(ngep, regno);
		*val =  hw_stp->s.OutMoreRetranCount;
		break;

	case ETHER_STAT_DEFER_XMTS:
		regno = KS_BASE + KS_ifHOutExDecCount * sizeof (uint32_t);
		hw_stp->s.OutExDecCount += nge_reg_get32(ngep, regno);
		*val = hw_stp->s.OutExDecCount;
		break;

	case ETHER_STAT_TX_LATE_COLLISIONS:
		regno = KS_BASE + KS_ifHOutColCount * sizeof (uint32_t);
		hw_stp->s.OutColCount += nge_reg_get32(ngep, regno);
		*val = hw_stp->s.OutColCount;
		break;

	case ETHER_STAT_EX_COLLISIONS:
		regno = KS_BASE + KS_ifHOutOneRetranCount * sizeof (uint32_t);
		hw_stp->s.OutOneRetranCount += nge_reg_get32(ngep, regno);
		*val = hw_stp->s.OutOneRetranCount;
		break;

	case ETHER_STAT_CARRIER_ERRORS:
		regno = KS_BASE + KS_ifHOutLOCCount * sizeof (uint32_t);
		hw_stp->s.OutLOCCount += nge_reg_get32(ngep, regno);
		*val = hw_stp->s.OutLOCCount;
		break;

	case ETHER_STAT_TOOLONG_ERRORS:
		regno = KS_BASE + KS_ifHInOversizeErrCount * sizeof (uint32_t);
		hw_stp->s.InOversizeErrCount += nge_reg_get32(ngep, regno);
		*val = hw_stp->s.InOversizeErrCount;
		break;

	case ETHER_STAT_XCVR_ADDR:
		*val = ngep->phy_xmii_addr;
		break;

	case ETHER_STAT_XCVR_ID:
		*val = ngep->phy_id;
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
		*val = ngep->param_adv_1000fdx;
		break;

	case ETHER_STAT_ADV_CAP_1000HDX:
		*val = ngep->param_adv_1000hdx;
		break;

	case ETHER_STAT_ADV_CAP_100FDX:
		*val = ngep->param_adv_100fdx;
		break;

	case ETHER_STAT_ADV_CAP_100HDX:
		*val = ngep->param_adv_100hdx;
		break;

	case ETHER_STAT_ADV_CAP_10FDX:
		*val = ngep->param_adv_10fdx;
		break;

	case ETHER_STAT_ADV_CAP_10HDX:
		*val = ngep->param_adv_10hdx;
		break;

	case ETHER_STAT_ADV_CAP_ASMPAUSE:
		*val = ngep->param_adv_asym_pause;
		break;

	case ETHER_STAT_ADV_CAP_PAUSE:
		*val = ngep->param_adv_pause;
		break;

	case ETHER_STAT_ADV_CAP_AUTONEG:
		*val = ngep->param_adv_autoneg;
		break;

	case ETHER_STAT_LP_CAP_1000FDX:
		*val = ngep->param_lp_1000fdx;
		break;

	case ETHER_STAT_LP_CAP_1000HDX:
		*val = ngep->param_lp_1000hdx;
		break;

	case ETHER_STAT_LP_CAP_100FDX:
		*val = ngep->param_lp_100fdx;
		break;

	case ETHER_STAT_LP_CAP_100HDX:
		*val = ngep->param_lp_100hdx;
		break;

	case ETHER_STAT_LP_CAP_10FDX:
		*val = ngep->param_lp_10fdx;
		break;

	case ETHER_STAT_LP_CAP_10HDX:
		*val = ngep->param_lp_10hdx;
		break;

	case ETHER_STAT_LP_CAP_ASMPAUSE:
		*val = ngep->param_lp_asym_pause;
		break;

	case ETHER_STAT_LP_CAP_PAUSE:
		*val = ngep->param_lp_pause;
		break;

	case ETHER_STAT_LP_CAP_AUTONEG:
		*val = ngep->param_lp_autoneg;
		break;

	case ETHER_STAT_LINK_ASMPAUSE:
		*val = ngep->param_adv_asym_pause &&
		    ngep->param_lp_asym_pause &&
		    ngep->param_adv_pause != ngep->param_lp_pause;
		break;

	case ETHER_STAT_LINK_PAUSE:
		*val = ngep->param_link_rx_pause;
		break;

	case ETHER_STAT_LINK_AUTONEG:
		*val = ngep->param_link_autoneg;
		break;

	case ETHER_STAT_LINK_DUPLEX:
		*val = ngep->param_link_duplex;
		break;

	case ETHER_STAT_CAP_100T4:
	case ETHER_STAT_LP_CAP_100T4:
		*val = 0;
		break;

	default:
		return (ENOTSUP);
	}

	return (0);
}
