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
 * Copyright (c) 2010-2013, by Broadcom, Inc.
 * All Rights Reserved.
 */

/*
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include "bge_impl.h"

#define	BGE_DBG		BGE_DBG_STATS	/* debug flag for this code	*/

/*
 * Local datatype for defining tables of (Offset, Name) pairs
 */
typedef struct {
	offset_t	index;
	char		*name;
} bge_ksindex_t;


/*
 * Table of Hardware-defined Statistics Block Offsets and Names
 */
#define	KS_NAME(s)			{ KS_ ## s, #s }

static const bge_ksindex_t bge_statistics[] = {
	KS_NAME(ifHCInOctets),
	KS_NAME(etherStatsFragments),
	KS_NAME(ifHCInUcastPkts),
	KS_NAME(ifHCInMulticastPkts),
	KS_NAME(ifHCInBroadcastPkts),
	KS_NAME(dot3StatsFCSErrors),
	KS_NAME(dot3StatsAlignmentErrors),
	KS_NAME(xonPauseFramesReceived),
	KS_NAME(xoffPauseFramesReceived),
	KS_NAME(macControlFramesReceived),
	KS_NAME(xoffStateEntered),
	KS_NAME(dot3StatsFrameTooLongs),
	KS_NAME(etherStatsJabbers),
	KS_NAME(etherStatsUndersizePkts),
	KS_NAME(inRangeLengthError),
	KS_NAME(outRangeLengthError),
	KS_NAME(etherStatsPkts64Octets),
	KS_NAME(etherStatsPkts65to127Octets),
	KS_NAME(etherStatsPkts128to255Octets),
	KS_NAME(etherStatsPkts256to511Octets),
	KS_NAME(etherStatsPkts512to1023Octets),
	KS_NAME(etherStatsPkts1024to1518Octets),
	KS_NAME(etherStatsPkts1519to2047Octets),
	KS_NAME(etherStatsPkts2048to4095Octets),
	KS_NAME(etherStatsPkts4096to8191Octets),
	KS_NAME(etherStatsPkts8192to9022Octets),

	KS_NAME(ifHCOutOctets),
	KS_NAME(etherStatsCollisions),
	KS_NAME(outXonSent),
	KS_NAME(outXoffSent),
	KS_NAME(flowControlDone),
	KS_NAME(dot3StatsInternalMacTransmitErrors),
	KS_NAME(dot3StatsSingleCollisionFrames),
	KS_NAME(dot3StatsMultipleCollisionFrames),
	KS_NAME(dot3StatsDeferredTransmissions),
	KS_NAME(dot3StatsExcessiveCollisions),
	KS_NAME(dot3StatsLateCollisions),
	KS_NAME(dot3Collided2Times),
	KS_NAME(dot3Collided3Times),
	KS_NAME(dot3Collided4Times),
	KS_NAME(dot3Collided5Times),
	KS_NAME(dot3Collided6Times),
	KS_NAME(dot3Collided7Times),
	KS_NAME(dot3Collided8Times),
	KS_NAME(dot3Collided9Times),
	KS_NAME(dot3Collided10Times),
	KS_NAME(dot3Collided11Times),
	KS_NAME(dot3Collided12Times),
	KS_NAME(dot3Collided13Times),
	KS_NAME(dot3Collided14Times),
	KS_NAME(dot3Collided15Times),
	KS_NAME(ifHCOutUcastPkts),
	KS_NAME(ifHCOutMulticastPkts),
	KS_NAME(ifHCOutBroadcastPkts),
	KS_NAME(dot3StatsCarrierSenseErrors),
	KS_NAME(ifOutDiscards),
	KS_NAME(ifOutErrors),

	KS_NAME(COSIfHCInPkts_1),
	KS_NAME(COSIfHCInPkts_2),
	KS_NAME(COSIfHCInPkts_3),
	KS_NAME(COSIfHCInPkts_4),
	KS_NAME(COSIfHCInPkts_5),
	KS_NAME(COSIfHCInPkts_6),
	KS_NAME(COSIfHCInPkts_7),
	KS_NAME(COSIfHCInPkts_8),
	KS_NAME(COSIfHCInPkts_9),
	KS_NAME(COSIfHCInPkts_10),
	KS_NAME(COSIfHCInPkts_11),
	KS_NAME(COSIfHCInPkts_12),
	KS_NAME(COSIfHCInPkts_13),
	KS_NAME(COSIfHCInPkts_14),
	KS_NAME(COSIfHCInPkts_15),
	KS_NAME(COSIfHCInPkts_16),
	KS_NAME(COSFramesDroppedDueToFilters),
	KS_NAME(nicDmaWriteQueueFull),
	KS_NAME(nicDmaWriteHighPriQueueFull),
	KS_NAME(nicNoMoreRxBDs),
	KS_NAME(ifInDiscards),
	KS_NAME(ifInErrors),
	KS_NAME(nicRecvThresholdHit),

	KS_NAME(COSIfHCOutPkts_1),
	KS_NAME(COSIfHCOutPkts_2),
	KS_NAME(COSIfHCOutPkts_3),
	KS_NAME(COSIfHCOutPkts_4),
	KS_NAME(COSIfHCOutPkts_5),
	KS_NAME(COSIfHCOutPkts_6),
	KS_NAME(COSIfHCOutPkts_7),
	KS_NAME(COSIfHCOutPkts_8),
	KS_NAME(COSIfHCOutPkts_9),
	KS_NAME(COSIfHCOutPkts_10),
	KS_NAME(COSIfHCOutPkts_11),
	KS_NAME(COSIfHCOutPkts_12),
	KS_NAME(COSIfHCOutPkts_13),
	KS_NAME(COSIfHCOutPkts_14),
	KS_NAME(COSIfHCOutPkts_15),
	KS_NAME(COSIfHCOutPkts_16),
	KS_NAME(nicDmaReadQueueFull),
	KS_NAME(nicDmaReadHighPriQueueFull),
	KS_NAME(nicSendDataCompQueueFull),
	KS_NAME(nicRingSetSendProdIndex),
	KS_NAME(nicRingStatusUpdate),
	KS_NAME(nicInterrupts),
	KS_NAME(nicAvoidedInterrupts),
	KS_NAME(nicSendThresholdHit),

	{ KS_STATS_SIZE, NULL }
};

static const bge_ksindex_t bge_stat_val[] = {
	KS_NAME(ifHCOutOctets),
	KS_NAME(etherStatsCollisions),
	KS_NAME(outXonSent),
	KS_NAME(outXoffSent),
	KS_NAME(dot3StatsInternalMacTransmitErrors),
	KS_NAME(dot3StatsSingleCollisionFrames),
	KS_NAME(dot3StatsMultipleCollisionFrames),
	KS_NAME(dot3StatsDeferredTransmissions),
	KS_NAME(dot3StatsExcessiveCollisions),
	KS_NAME(dot3StatsLateCollisions),
	KS_NAME(ifHCOutUcastPkts),
	KS_NAME(ifHCOutMulticastPkts),
	KS_NAME(ifHCOutBroadcastPkts),
	KS_NAME(ifHCInOctets),
	KS_NAME(etherStatsFragments),
	KS_NAME(ifHCInUcastPkts),
	KS_NAME(ifHCInMulticastPkts),
	KS_NAME(ifHCInBroadcastPkts),
	KS_NAME(dot3StatsFCSErrors),
	KS_NAME(dot3StatsAlignmentErrors),
	KS_NAME(xonPauseFramesReceived),
	KS_NAME(xoffPauseFramesReceived),
	KS_NAME(macControlFramesReceived),
	KS_NAME(xoffStateEntered),
	KS_NAME(dot3StatsFrameTooLongs),
	KS_NAME(etherStatsJabbers),
	KS_NAME(etherStatsUndersizePkts),

	{ KS_STAT_REG_SIZE, NULL }
};

static int
bge_statistics_update(kstat_t *ksp, int flag)
{
	bge_t *bgep;
	bge_statistics_t *bstp;
	bge_statistics_reg_t *pstats;
	kstat_named_t *knp;
	const bge_ksindex_t *ksip;

	if (flag != KSTAT_READ)
		return (EACCES);

	bgep = ksp->ks_private;
	if (bgep->chipid.statistic_type == BGE_STAT_BLK)
		bstp = DMA_VPTR(bgep->statistics);

	knp = ksp->ks_data;

	/*
	 * Transfer the statistics values from the copy that the
	 * chip updates via DMA to the named-kstat structure.
	 *
	 * As above, we don't bother to sync or stop updates to the
	 * statistics, 'cos it doesn't really matter if they're a few
	 * microseconds out of date or less than 100% consistent ...
	 */
	if (bgep->chipid.statistic_type == BGE_STAT_BLK)
		for (ksip = bge_statistics; ksip->name != NULL; ++knp, ++ksip)
			knp->value.ui64 = bstp->a[ksip->index];
	else {
		pstats = bgep->pstats;
		(knp++)->value.ui64 = (uint64_t)(pstats->ifHCOutOctets);
		(knp++)->value.ui64 = (uint64_t)(pstats->etherStatsCollisions);
		(knp++)->value.ui64 = (uint64_t)(pstats->outXonSent);
		(knp++)->value.ui64 = (uint64_t)(pstats->outXoffSent);
		(knp++)->value.ui64 =
		    (uint64_t)(pstats->dot3StatsInternalMacTransmitErrors);
		(knp++)->value.ui64 =
		    (uint64_t)(pstats->dot3StatsSingleCollisionFrames);
		(knp++)->value.ui64 =
		    (uint64_t)(pstats->dot3StatsMultipleCollisionFrames);
		(knp++)->value.ui64 =
		    (uint64_t)(pstats->dot3StatsDeferredTransmissions);
		(knp++)->value.ui64 =
		    (uint64_t)(pstats->dot3StatsExcessiveCollisions);
		(knp++)->value.ui64 =
		    (uint64_t)(pstats->dot3StatsLateCollisions);
		(knp++)->value.ui64 = (uint64_t)(pstats->ifHCOutUcastPkts);
		(knp++)->value.ui64 = (uint64_t)(pstats->ifHCOutMulticastPkts);
		(knp++)->value.ui64 = (uint64_t)(pstats->ifHCOutBroadcastPkts);
		(knp++)->value.ui64 = (uint64_t)(pstats->ifHCInOctets);
		(knp++)->value.ui64 = (uint64_t)(pstats->etherStatsFragments);
		(knp++)->value.ui64 = (uint64_t)(pstats->ifHCInUcastPkts);
		(knp++)->value.ui64 = (uint64_t)(pstats->ifHCInMulticastPkts);
		(knp++)->value.ui64 = (uint64_t)(pstats->ifHCInBroadcastPkts);
		(knp++)->value.ui64 = (uint64_t)(pstats->dot3StatsFCSErrors);
		(knp++)->value.ui64 =
		    (uint64_t)(pstats->dot3StatsAlignmentErrors);
		(knp++)->value.ui64 =
		    (uint64_t)(pstats->xonPauseFramesReceived);
		(knp++)->value.ui64 =
		    (uint64_t)(pstats->xoffPauseFramesReceived);
		(knp++)->value.ui64 =
		    (uint64_t)(pstats->macControlFramesReceived);
		(knp++)->value.ui64 = (uint64_t)(pstats->xoffStateEntered);
		(knp++)->value.ui64 =
		    (uint64_t)(pstats->dot3StatsFrameTooLongs);
		(knp++)->value.ui64 = (uint64_t)(pstats->etherStatsJabbers);
		(knp++)->value.ui64 =
		    (uint64_t)(pstats->etherStatsUndersizePkts);
	}

	return (0);
}

static const bge_ksindex_t bge_chipid[] = {
	{ 0,				"asic_rev"		},
	{ 1,				"businfo"		},
	{ 2,				"command"		},

	{ 3,				"vendor_id"		},
	{ 4,				"device_id"		},
	{ 5,				"subsystem_vendor_id"	},
	{ 6,				"subsystem_device_id"	},
	{ 7,				"revision_id"		},
	{ 8,				"cache_line_size"	},
	{ 9,				"latency_timer"		},

	{ 10,				"flags"			},
	{ 11,				"chip_type"		},
	{ 12,				"mbuf_base"		},
	{ 13,				"mbuf_count"		},
	{ 14,				"hw_mac_addr"		},

	{ 15,				"&bus_type"		},
	{ 16,				"&bus_speed"		},
	{ 17,				"&bus_size"		},
	{ 18,				"&supported"		},
	{ 19,				"&interface"		},

	{ 20,				"nvtype"		},

	{ 21,				"asic_rev_prod_id"	},

	{ -1,				NULL 			}
};

static void
bge_set_char_kstat(kstat_named_t *knp, const char *s)
{
	(void) strncpy(knp->value.c, s, sizeof (knp->value.c));
}

static int
bge_chipid_update(kstat_t *ksp, int flag)
{
	bge_t *bgep;
	kstat_named_t *knp;
	uint64_t tmp;

	if (flag != KSTAT_READ)
		return (EACCES);

	bgep = ksp->ks_private;
	knp = ksp->ks_data;

	(knp++)->value.ui64 = bgep->chipid.asic_rev;
	(knp++)->value.ui64 = bgep->chipid.businfo;
	(knp++)->value.ui64 = bgep->chipid.command;

	(knp++)->value.ui64 = bgep->chipid.vendor;
	(knp++)->value.ui64 = bgep->chipid.device;
	(knp++)->value.ui64 = bgep->chipid.subven;
	(knp++)->value.ui64 = bgep->chipid.subdev;
	(knp++)->value.ui64 = bgep->chipid.revision;
	(knp++)->value.ui64 = bgep->chipid.clsize;
	(knp++)->value.ui64 = bgep->chipid.latency;

	(knp++)->value.ui64 = bgep->chipid.flags;
	(knp++)->value.ui64 = bgep->chipid.chip_label;
	(knp++)->value.ui64 = bgep->chipid.mbuf_base;
	(knp++)->value.ui64 = bgep->chipid.mbuf_length;
	(knp++)->value.ui64 = bgep->chipid.hw_mac_addr;

	/*
	 * Now we interpret some of the above into readable strings
	 */
	tmp = bgep->chipid.businfo;
	bge_set_char_kstat(knp++,
	    tmp & PCISTATE_BUS_IS_PCI ? "PCI" : "PCI-X");
	bge_set_char_kstat(knp++,
	    tmp & PCISTATE_BUS_IS_FAST ? "fast" : "normal");
	bge_set_char_kstat(knp++,
	    tmp & PCISTATE_BUS_IS_32_BIT ? "32 bit" : "64 bit");

	tmp = bgep->chipid.flags;
	bge_set_char_kstat(knp++,
	    tmp & CHIP_FLAG_SUPPORTED ? "yes" : "no");
	bge_set_char_kstat(knp++,
	    tmp & CHIP_FLAG_SERDES ? "serdes" : "copper");

	(knp++)->value.ui64 =
	    ((bgep->chipid.nvtype == BGE_NVTYPE_NONE) ||
	     (bgep->chipid.nvtype == BGE_NVTYPE_UNKNOWN)) ?
	    0 : bgep->chipid.nvtype;

	(knp++)->value.ui64 = bgep->chipid.asic_rev_prod_id;

	return (0);
}

static const bge_ksindex_t bge_driverinfo[] = {
	{ 0,				"rx_buff_addr"		},
	{ 1,				"tx_buff_addr"		},
	{ 2,				"rx_desc_addr"		},
	{ 3,				"tx_desc_addr"		},

	{ 4,				"tx_desc_free"		},
	{ 5,				"tx_array"		},
	{ 6,				"tc_next"		},
	{ 7,				"tx_next"		},
	{ 8,				"txfill_next"		},
	{ 9,				"txpkt_next"		},
	{ 10,				"tx_bufs"		},
	{ 11,				"tx_flow"		},
	{ 12,				"tx_resched_needed"	},
	{ 13,				"tx_resched"		},
	{ 14,				"tx_nobuf"		},
	{ 15,				"tx_nobd"		},
	{ 16,				"tx_block"		},
	{ 17,				"tx_alloc_fail"		},

	{ 18,				"watchdog"		},
	{ 19,				"chip_resets"		},
	{ 20,				"dma_misses"		},
	{ 21,				"update_misses"		},

	{ 22,				"misc_host_config"	},
	{ 23,				"dma_rw_control"	},
	{ 24,				"pci_bus_info"		},

	{ 25,				"buff_mgr_status"	},
	{ 26,				"rcv_init_status"	},

	{ -1,				NULL 			}
};

static int
bge_driverinfo_update(kstat_t *ksp, int flag)
{
	bge_t *bgep;
	kstat_named_t *knp;
	ddi_acc_handle_t handle;

	if (flag != KSTAT_READ)
		return (EACCES);

	bgep = ksp->ks_private;
	if (bgep->bge_chip_state == BGE_CHIP_FAULT)
		return (EIO);

	knp = ksp->ks_data;

	(knp++)->value.ui64 = bgep->rx_buff[0].cookie.dmac_laddress;
	(knp++)->value.ui64 = bgep->tx_buff[0].cookie.dmac_laddress;
	(knp++)->value.ui64 = bgep->rx_desc[0].cookie.dmac_laddress;
	(knp++)->value.ui64 = bgep->tx_desc.cookie.dmac_laddress;

	(knp++)->value.ui64 = bgep->send[0].tx_free;
	(knp++)->value.ui64 = bgep->send[0].tx_array;
	(knp++)->value.ui64 = bgep->send[0].tc_next;
	(knp++)->value.ui64 = bgep->send[0].tx_next;
	(knp++)->value.ui64 = bgep->send[0].txfill_next;
	(knp++)->value.ui64 = bgep->send[0].txpkt_next;
	(knp++)->value.ui64 = bgep->send[0].txbuf_pop_queue->count +
	    bgep->send[0].txbuf_push_queue->count;
	(knp++)->value.ui64 = bgep->send[0].tx_flow;
	(knp++)->value.ui64 = bgep->tx_resched_needed;
	(knp++)->value.ui64 = bgep->tx_resched;
	(knp++)->value.ui64 = bgep->send[0].tx_nobuf;
	(knp++)->value.ui64 = bgep->send[0].tx_nobd;
	(knp++)->value.ui64 = bgep->send[0].tx_block;
	(knp++)->value.ui64 = bgep->send[0].tx_alloc_fail;

	(knp++)->value.ui64 = bgep->watchdog;
	(knp++)->value.ui64 = bgep->chip_resets;
	(knp++)->value.ui64 = bgep->missed_dmas;
	(knp++)->value.ui64 = bgep->missed_updates;

	/*
	 * Hold the mutex while accessing the chip registers
	 * just in case the factotum is trying to reset it!
	 */
	handle = bgep->cfg_handle;
	mutex_enter(bgep->genlock);
	(knp++)->value.ui64 = pci_config_get32(handle, PCI_CONF_BGE_MHCR);
	(knp++)->value.ui64 = pci_config_get32(handle, PCI_CONF_BGE_PDRWCR);
	(knp++)->value.ui64 = pci_config_get32(handle, PCI_CONF_BGE_PCISTATE);
	if (bge_check_acc_handle(bgep, bgep->cfg_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_DEGRADED);
		mutex_exit(bgep->genlock);
		return (EIO);
	}

	(knp++)->value.ui64 = bge_reg_get32(bgep, BUFFER_MANAGER_STATUS_REG);
	(knp++)->value.ui64 = bge_reg_get32(bgep, RCV_INITIATOR_STATUS_REG);
	if (bge_check_acc_handle(bgep, bgep->io_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_DEGRADED);
		mutex_exit(bgep->genlock);
		return (EIO);
	}
	mutex_exit(bgep->genlock);

	return (0);
}

static const bge_ksindex_t bge_serdes[] = {
	{ 0,				"serdes_status"		},
	{ 1,				"serdes_advert"		},
	{ 2,				"serdes_lpadv"		},

	{ -1,				NULL }
};

static int
bge_serdes_update(kstat_t *ksp, int flag)
{
	bge_t *bgep;
	kstat_named_t *knp;

	if (flag != KSTAT_READ)
		return (EACCES);

	bgep = ksp->ks_private;
	knp = ksp->ks_data;

	(knp++)->value.ui64 = bgep->serdes_status;
	(knp++)->value.ui64 = bgep->serdes_advert;
	(knp++)->value.ui64 = bgep->serdes_lpadv;

	return (0);
}

static const bge_ksindex_t bge_phydata[] = {
	{ MII_CONTROL,			"mii_control"		},
	{ MII_STATUS,			"mii_status"		},
	{ MII_PHYIDH,			"phy_identifier"	},
	{ MII_AN_ADVERT,		"an_advert"		},
	{ MII_AN_LPABLE,		"an_lp_ability"		},
	{ MII_AN_EXPANSION,		"an_expansion"		},
	{ MII_AN_NXTPGLP,		"an_lp_nextpage"	},
	{ MII_MSCONTROL,		"gbit_control"		},
	{ MII_MSSTATUS,			"gbit_status"		},
	{ MII_EXTSTATUS,		"ieee_ext_status"	},
	{ MII_EXT_CONTROL,		"phy_ext_control"	},
	{ MII_EXT_STATUS,		"phy_ext_status"	},
	{ MII_RCV_ERR_COUNT,		"receive_error_count"	},
	{ MII_FALSE_CARR_COUNT,		"false_carrier_count"	},
	{ MII_RCV_NOT_OK_COUNT,		"receiver_not_ok_count"	},
	{ MII_AUX_CONTROL,		"aux_control"		},
	{ MII_AUX_STATUS,		"aux_status"		},
	{ MII_INTR_STATUS,		"intr_status"		},
	{ MII_INTR_MASK,		"intr_mask"		},
	{ MII_HCD_STATUS,		"hcd_status"		},
	{ EEE_MODE_REG,			"eee"			},

	{ -1,				NULL }
};

static int
bge_phydata_update(kstat_t *ksp, int flag)
{
	bge_t *bgep;
	kstat_named_t *knp;
	const bge_ksindex_t *ksip;

	if (flag != KSTAT_READ)
		return (EACCES);

	bgep = ksp->ks_private;
	if (bgep->bge_chip_state == BGE_CHIP_FAULT)
		return (EIO);

	knp = ksp->ks_data;

	/*
	 * Read the PHY registers & update the kstats ...
	 *
	 * We need to hold the mutex while performing MII reads, but
	 * we don't want to hold it across the entire sequence of reads.
	 * So we grab and release it on each iteration, 'cos it doesn't
	 * really matter if the kstats are less than 100% consistent ...
	 */
	for (ksip = bge_phydata; ksip->name != NULL; ++knp, ++ksip) {
		mutex_enter(bgep->genlock);
		switch (ksip->index) {
		case MII_STATUS:
			knp->value.ui64 = bgep->phy_gen_status;
			break;

		case MII_PHYIDH:
			knp->value.ui64 = bge_mii_get16(bgep, MII_PHYIDH);
			knp->value.ui64 <<= 16;
			knp->value.ui64 |= bge_mii_get16(bgep, MII_PHYIDL);
			break;

		case EEE_MODE_REG:
			knp->value.ui64 = 0;
			if (bgep->link_state == LINK_STATE_UP)
			{
				knp->value.ui64 =
				    (bge_reg_get32(bgep, EEE_MODE_REG) & 0x80) ?
				        1 : 0;
			}
			break;

		default:
			knp->value.ui64 = bge_mii_get16(bgep, ksip->index);
			break;
		}
		if (bge_check_acc_handle(bgep, bgep->io_handle) != DDI_FM_OK) {
			ddi_fm_service_impact(bgep->devinfo,
			    DDI_SERVICE_DEGRADED);
			mutex_exit(bgep->genlock);
			return (EIO);
		}
		mutex_exit(bgep->genlock);
	}

	return (0);
}

static kstat_t *
bge_setup_named_kstat(bge_t *bgep, int instance, char *name,
	const bge_ksindex_t *ksip, size_t size, int (*update)(kstat_t *, int))
{
	kstat_t *ksp;
	kstat_named_t *knp;
	char *np;
	int type;

	size /= sizeof (bge_ksindex_t);
	ksp = kstat_create(BGE_DRIVER_NAME, instance, name, "net",
	    KSTAT_TYPE_NAMED, size-1, 0);
	if (ksp == NULL)
		return (NULL);

	ksp->ks_private = bgep;
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
bge_init_kstats(bge_t *bgep, int instance)
{
	kstat_t *ksp;

	BGE_TRACE(("bge_init_kstats($%p, %d)", (void *)bgep, instance));

	if (bgep->chipid.statistic_type == BGE_STAT_BLK) {
		DMA_ZERO(bgep->statistics);
		bgep->bge_kstats[BGE_KSTAT_RAW] = ksp =
		    kstat_create(BGE_DRIVER_NAME, instance,
		    "raw_statistics", "net", KSTAT_TYPE_RAW,
		    sizeof (bge_statistics_t), KSTAT_FLAG_VIRTUAL);
		if (ksp != NULL) {
			ksp->ks_data = DMA_VPTR(bgep->statistics);
			kstat_install(ksp);
		}

		bgep->bge_kstats[BGE_KSTAT_STATS] = bge_setup_named_kstat(bgep,
		    instance, "statistics", bge_statistics,
		    sizeof (bge_statistics), bge_statistics_update);
	} else {
		bgep->bge_kstats[BGE_KSTAT_STATS] = bge_setup_named_kstat(bgep,
		    instance, "statistics", bge_stat_val,
		    sizeof (bge_stat_val), bge_statistics_update);
	}

	bgep->bge_kstats[BGE_KSTAT_CHIPID] = bge_setup_named_kstat(bgep,
	    instance, "chipid", bge_chipid,
	    sizeof (bge_chipid), bge_chipid_update);

	bgep->bge_kstats[BGE_KSTAT_DRIVER] = bge_setup_named_kstat(bgep,
	    instance, "driverinfo", bge_driverinfo,
	    sizeof (bge_driverinfo), bge_driverinfo_update);

	if (bgep->chipid.flags & CHIP_FLAG_SERDES)
		bgep->bge_kstats[BGE_KSTAT_PHYS] = bge_setup_named_kstat(bgep,
		    instance, "serdes", bge_serdes,
		    sizeof (bge_serdes), bge_serdes_update);
	else
		bgep->bge_kstats[BGE_KSTAT_PHYS] = bge_setup_named_kstat(bgep,
		    instance, "phydata", bge_phydata,
		    sizeof (bge_phydata), bge_phydata_update);

}

void
bge_fini_kstats(bge_t *bgep)
{
	int i;

	BGE_TRACE(("bge_fini_kstats($%p)", (void *)bgep));

	for (i = BGE_KSTAT_COUNT; --i >= 0; )
		if (bgep->bge_kstats[i] != NULL)
			kstat_delete(bgep->bge_kstats[i]);
}

int
bge_m_stat(void *arg, uint_t stat, uint64_t *val)
{
	bge_t *bgep = arg;
	bge_statistics_t *bstp;
	bge_statistics_reg_t *pstats;

	if (bgep->bge_chip_state != BGE_CHIP_RUNNING) {
		return (EINVAL);
	}

	if (bgep->chipid.statistic_type == BGE_STAT_BLK)
		bstp = DMA_VPTR(bgep->statistics);
	else {
		pstats = bgep->pstats;
		pstats->ifHCOutOctets +=
		    bge_reg_get32(bgep, STAT_IFHCOUT_OCTETS_REG);
		pstats->etherStatsCollisions +=
		    bge_reg_get32(bgep, STAT_ETHER_COLLIS_REG);
		pstats->outXonSent +=
		    bge_reg_get32(bgep, STAT_OUTXON_SENT_REG);
		pstats->outXoffSent +=
		    bge_reg_get32(bgep, STAT_OUTXOFF_SENT_REG);
		pstats->dot3StatsInternalMacTransmitErrors +=
		    bge_reg_get32(bgep, STAT_DOT3_INTMACTX_ERR_REG);
		pstats->dot3StatsSingleCollisionFrames +=
		    bge_reg_get32(bgep, STAT_DOT3_SCOLLI_FRAME_REG);
		pstats->dot3StatsMultipleCollisionFrames +=
		    bge_reg_get32(bgep, STAT_DOT3_MCOLLI_FRAME_REG);
		pstats->dot3StatsDeferredTransmissions +=
		    bge_reg_get32(bgep, STAT_DOT3_DEFERED_TX_REG);
		pstats->dot3StatsExcessiveCollisions +=
		    bge_reg_get32(bgep, STAT_DOT3_EXCE_COLLI_REG);
		pstats->dot3StatsLateCollisions +=
		    bge_reg_get32(bgep, STAT_DOT3_LATE_COLLI_REG);
		pstats->ifHCOutUcastPkts +=
		    bge_reg_get32(bgep, STAT_IFHCOUT_UPKGS_REG);
		pstats->ifHCOutMulticastPkts +=
		    bge_reg_get32(bgep, STAT_IFHCOUT_MPKGS_REG);
		pstats->ifHCOutBroadcastPkts +=
		    bge_reg_get32(bgep, STAT_IFHCOUT_BPKGS_REG);
		pstats->ifHCInOctets +=
		    bge_reg_get32(bgep, STAT_IFHCIN_OCTETS_REG);
		pstats->etherStatsFragments +=
		    bge_reg_get32(bgep, STAT_ETHER_FRAGMENT_REG);
		pstats->ifHCInUcastPkts +=
		    bge_reg_get32(bgep, STAT_IFHCIN_UPKGS_REG);
		pstats->ifHCInMulticastPkts +=
		    bge_reg_get32(bgep, STAT_IFHCIN_MPKGS_REG);
		pstats->ifHCInBroadcastPkts +=
		    bge_reg_get32(bgep, STAT_IFHCIN_BPKGS_REG);
		pstats->dot3StatsFCSErrors +=
		    bge_reg_get32(bgep, STAT_DOT3_FCS_ERR_REG);
		pstats->dot3StatsAlignmentErrors +=
		    bge_reg_get32(bgep, STAT_DOT3_ALIGN_ERR_REG);
		pstats->xonPauseFramesReceived +=
		    bge_reg_get32(bgep, STAT_XON_PAUSE_RX_REG);
		pstats->xoffPauseFramesReceived +=
		    bge_reg_get32(bgep, STAT_XOFF_PAUSE_RX_REG);
		pstats->macControlFramesReceived +=
		    bge_reg_get32(bgep, STAT_MAC_CTRL_RX_REG);
		pstats->xoffStateEntered +=
		    bge_reg_get32(bgep, STAT_XOFF_STATE_ENTER_REG);
		pstats->dot3StatsFrameTooLongs +=
		    bge_reg_get32(bgep, STAT_DOT3_FRAME_TOOLONG_REG);
		pstats->etherStatsJabbers +=
		    bge_reg_get32(bgep, STAT_ETHER_JABBERS_REG);
		pstats->etherStatsUndersizePkts +=
		    bge_reg_get32(bgep, STAT_ETHER_UNDERSIZE_REG);
		mutex_enter(bgep->genlock);
		if (bge_check_acc_handle(bgep, bgep->io_handle) != DDI_FM_OK) {
			ddi_fm_service_impact(bgep->devinfo,
			    DDI_SERVICE_UNAFFECTED);
		}
		mutex_exit(bgep->genlock);
	}

	switch (stat) {
	case MAC_STAT_IFSPEED:
		*val = (bgep->link_state != LINK_STATE_UNKNOWN) ?
		           (bgep->param_link_speed * 1000000ull) : 0;
		break;

	case MAC_STAT_MULTIRCV:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.ifHCInMulticastPkts;
		else
			*val = pstats->ifHCInMulticastPkts;
		break;

	case MAC_STAT_BRDCSTRCV:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.ifHCInBroadcastPkts;
		else
			*val = pstats->ifHCInBroadcastPkts;
		break;

	case MAC_STAT_MULTIXMT:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.ifHCOutMulticastPkts;
		else
			*val = pstats->ifHCOutMulticastPkts;
		break;

	case MAC_STAT_BRDCSTXMT:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.ifHCOutBroadcastPkts;
		else
			*val = pstats->ifHCOutBroadcastPkts;
		break;

	case MAC_STAT_NORCVBUF:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.ifInDiscards;
		else
			*val = 0;
		break;

	case MAC_STAT_IERRORS:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK) {
			*val = bstp->s.dot3StatsFCSErrors +
			    bstp->s.dot3StatsAlignmentErrors +
			    bstp->s.dot3StatsFrameTooLongs +
			    bstp->s.etherStatsUndersizePkts +
			    bstp->s.etherStatsJabbers;
		} else {
			*val = pstats->dot3StatsFCSErrors +
			    pstats->dot3StatsAlignmentErrors +
			    pstats->dot3StatsFrameTooLongs +
			    pstats->etherStatsUndersizePkts +
			    pstats->etherStatsJabbers;
		}
		break;

	case MAC_STAT_NOXMTBUF:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.ifOutDiscards;
		else
			*val = 0;
		break;

	case MAC_STAT_OERRORS:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.ifOutDiscards;
		else
			*val = 0;
		break;

	case MAC_STAT_COLLISIONS:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.etherStatsCollisions;
		else
			*val = pstats->etherStatsCollisions;
		break;

	case MAC_STAT_RBYTES:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.ifHCInOctets;
		else
			*val = pstats->ifHCInOctets;
		break;

	case MAC_STAT_IPACKETS:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.ifHCInUcastPkts +
			    bstp->s.ifHCInMulticastPkts +
			    bstp->s.ifHCInBroadcastPkts;
		else
			*val = pstats->ifHCInUcastPkts +
			    pstats->ifHCInMulticastPkts +
			    pstats->ifHCInBroadcastPkts;
		break;

	case MAC_STAT_OBYTES:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.ifHCOutOctets;
		else
			*val = pstats->ifHCOutOctets;
		break;

	case MAC_STAT_OPACKETS:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.ifHCOutUcastPkts +
			    bstp->s.ifHCOutMulticastPkts +
			    bstp->s.ifHCOutBroadcastPkts;
		else
			*val = pstats->ifHCOutUcastPkts +
			    pstats->ifHCOutMulticastPkts +
			    pstats->ifHCOutBroadcastPkts;
		break;

	case ETHER_STAT_ALIGN_ERRORS:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.dot3StatsAlignmentErrors;
		else
			*val = pstats->dot3StatsAlignmentErrors;
		break;

	case ETHER_STAT_FCS_ERRORS:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.dot3StatsFCSErrors;
		else
			*val = pstats->dot3StatsFCSErrors;
		break;

	case ETHER_STAT_FIRST_COLLISIONS:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.dot3StatsSingleCollisionFrames;
		else
			*val = pstats->dot3StatsSingleCollisionFrames;
		break;

	case ETHER_STAT_MULTI_COLLISIONS:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.dot3StatsMultipleCollisionFrames;
		else
			*val = pstats->dot3StatsMultipleCollisionFrames;
		break;

	case ETHER_STAT_DEFER_XMTS:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.dot3StatsDeferredTransmissions;
		else
			*val = pstats->dot3StatsDeferredTransmissions;
		break;

	case ETHER_STAT_TX_LATE_COLLISIONS:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.dot3StatsLateCollisions;
		else
			*val = pstats->dot3StatsLateCollisions;
		break;

	case ETHER_STAT_EX_COLLISIONS:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.dot3StatsExcessiveCollisions;
		else
			*val = pstats->dot3StatsExcessiveCollisions;
		break;

	case ETHER_STAT_MACXMT_ERRORS:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.dot3StatsInternalMacTransmitErrors;
		else
			*val = bgep->pstats->dot3StatsInternalMacTransmitErrors;
		break;

	case ETHER_STAT_CARRIER_ERRORS:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.dot3StatsCarrierSenseErrors;
		else
			*val = 0;
		break;

	case ETHER_STAT_TOOLONG_ERRORS:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.dot3StatsFrameTooLongs;
		else
			*val = pstats->dot3StatsFrameTooLongs;
		break;

#if (MAC_VERSION > 1)
	case ETHER_STAT_TOOSHORT_ERRORS:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.etherStatsUndersizePkts;
		else
			*val = pstats->etherStatsUndersizePkts;
		break;
#endif

	case ETHER_STAT_XCVR_ADDR:
		*val = bgep->phy_mii_addr;
		break;

	case ETHER_STAT_XCVR_ID:
		mutex_enter(bgep->genlock);
		*val = bge_mii_get16(bgep, MII_PHYIDH);
		*val <<= 16;
		*val |= bge_mii_get16(bgep, MII_PHYIDL);
		if (bge_check_acc_handle(bgep, bgep->io_handle) != DDI_FM_OK) {
			ddi_fm_service_impact(bgep->devinfo,
			    DDI_SERVICE_UNAFFECTED);
		}
		mutex_exit(bgep->genlock);
		break;

	case ETHER_STAT_XCVR_INUSE:
		if (bgep->chipid.flags & CHIP_FLAG_SERDES)
			*val = XCVR_1000X;
		else
			*val = XCVR_1000T;
		break;

	case ETHER_STAT_CAP_1000FDX:
		*val = 1;
		break;

	case ETHER_STAT_CAP_1000HDX:
		*val = 1;
		break;

	case ETHER_STAT_CAP_100FDX:
		if (bgep->chipid.flags & CHIP_FLAG_SERDES)
			*val = 0;
		else
			*val = 1;
		break;

	case ETHER_STAT_CAP_100HDX:
		if (bgep->chipid.flags & CHIP_FLAG_SERDES)
			*val = 0;
		else
			*val = 1;
		break;

	case ETHER_STAT_CAP_10FDX:
		if (bgep->chipid.flags & CHIP_FLAG_SERDES)
			*val = 0;
		else
			*val = 1;
		break;

	case ETHER_STAT_CAP_10HDX:
		if (bgep->chipid.flags & CHIP_FLAG_SERDES)
			*val = 0;
		else
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

#if (MAC_VERSION > 1)
	case ETHER_STAT_CAP_REMFAULT:
		*val = 1;
		break;
#endif

	case ETHER_STAT_ADV_CAP_1000FDX:
		*val = bgep->param_adv_1000fdx;
		break;

	case ETHER_STAT_ADV_CAP_1000HDX:
		*val = bgep->param_adv_1000hdx;
		break;

	case ETHER_STAT_ADV_CAP_100FDX:
		*val = bgep->param_adv_100fdx;
		break;

	case ETHER_STAT_ADV_CAP_100HDX:
		*val = bgep->param_adv_100hdx;
		break;

	case ETHER_STAT_ADV_CAP_10FDX:
		*val = bgep->param_adv_10fdx;
		break;

	case ETHER_STAT_ADV_CAP_10HDX:
		*val = bgep->param_adv_10hdx;
		break;

	case ETHER_STAT_ADV_CAP_ASMPAUSE:
		*val = bgep->param_adv_asym_pause;
		break;

	case ETHER_STAT_ADV_CAP_PAUSE:
		*val = bgep->param_adv_pause;
		break;

	case ETHER_STAT_ADV_CAP_AUTONEG:
		*val = bgep->param_adv_autoneg;
		break;

#if (MAC_VERSION > 1)
	case ETHER_STAT_ADV_REMFAULT:
		if (bgep->chipid.flags & CHIP_FLAG_SERDES)
			*val = 0;
		else {
			mutex_enter(bgep->genlock);
			*val = bge_mii_get16(bgep, MII_AN_ADVERT) &
			    MII_AN_ADVERT_REMFAULT ? 1 : 0;
			if (bge_check_acc_handle(bgep, bgep->io_handle) !=
			    DDI_FM_OK) {
				ddi_fm_service_impact(bgep->devinfo,
				    DDI_SERVICE_UNAFFECTED);
			}
			mutex_exit(bgep->genlock);
		}
		break;
#endif

	case ETHER_STAT_LP_CAP_1000FDX:
		*val = bgep->param_lp_1000fdx;
		break;

	case ETHER_STAT_LP_CAP_1000HDX:
		*val = bgep->param_lp_1000hdx;
		break;

	case ETHER_STAT_LP_CAP_100FDX:
		*val = bgep->param_lp_100fdx;
		break;

	case ETHER_STAT_LP_CAP_100HDX:
		*val = bgep->param_lp_100hdx;
		break;

	case ETHER_STAT_LP_CAP_10FDX:
		*val = bgep->param_lp_10fdx;
		break;

	case ETHER_STAT_LP_CAP_10HDX:
		*val = bgep->param_lp_10hdx;
		break;

	case ETHER_STAT_LP_CAP_ASMPAUSE:
		*val = bgep->param_lp_asym_pause;
		break;

	case ETHER_STAT_LP_CAP_PAUSE:
		*val = bgep->param_lp_pause;
		break;

	case ETHER_STAT_LP_CAP_AUTONEG:
		*val = bgep->param_lp_autoneg;
		break;

#if (MAC_VERSION > 1)
	case ETHER_STAT_LP_REMFAULT:
		if (bgep->chipid.flags & CHIP_FLAG_SERDES)
			*val = 0;
		else {
			mutex_enter(bgep->genlock);
			*val = bge_mii_get16(bgep, MII_AN_LPABLE) &
			    MII_AN_ADVERT_REMFAULT ? 1 : 0;
			if (bge_check_acc_handle(bgep, bgep->io_handle) !=
			    DDI_FM_OK) {
				ddi_fm_service_impact(bgep->devinfo,
				    DDI_SERVICE_UNAFFECTED);
			}
			mutex_exit(bgep->genlock);
		}
		break;
#endif

	case ETHER_STAT_LINK_ASMPAUSE:
		*val = bgep->param_adv_asym_pause &&
		    bgep->param_lp_asym_pause &&
		    bgep->param_adv_pause != bgep->param_lp_pause;
		break;

	case ETHER_STAT_LINK_PAUSE:
		*val = bgep->param_link_rx_pause;
		break;

	case ETHER_STAT_LINK_AUTONEG:
		*val = bgep->param_link_autoneg;
		break;

	case ETHER_STAT_LINK_DUPLEX:
		*val = (bgep->link_state != LINK_STATE_UNKNOWN) ?
		           bgep->param_link_duplex : LINK_DUPLEX_UNKNOWN;
		break;

	default:
		return (ENOTSUP);
	}

	return (0);
}

/*
 * Retrieve a value for one of the statistics for a particular rx ring
 */
int
bge_rx_ring_stat(mac_ring_driver_t rh, uint_t stat, uint64_t *val)
{
	recv_ring_t *rx_ring = (recv_ring_t *)rh;

	switch (stat) {
	case MAC_STAT_RBYTES:
		*val = rx_ring->rx_bytes;
		break;

	case MAC_STAT_IPACKETS:
		*val = rx_ring->rx_pkts;
		break;

	default:
		*val = 0;
		return (ENOTSUP);
	}

	return (0);
}
