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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include "bge_impl.h"

#define	BGE_DBG		BGE_DBG_STATS	/* debug flag for this code	*/

/*
 * Type of transceiver currently in use.  The IEEE 802.3 std aPhyType
 * enumerates the following set
 */
enum xcvr_type {
	XCVR_TYPE_UNDEFINED = 0,    /* 0 = undefined, or not yet known */
	XCVR_TYPE_NONE,		/* 1= MII present & nothing connected */
	XCVR_TYPE_10BASE_T,		/* 2 = 10 Mbps copper */
	XCVR_TYPE_100BASE_T4,	/* 3 = 10 Mbps copper */
	XCVR_TYPE_100BASE_X,	/* 4 = 100 Mbps copper */
	XCVR_TYPE_100BASE_T2,	/* 5 = 100 Mbps copper */
	XCVR_TYPE_1000BASE_X,	/* 6 = 1000 Mbps SerDes */
	XCVR_TYPE_1000BASE_T	/* 7 = 1000 Mbps copper */
};

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
		(knp++)->value.ui64 =
			(uint64_t)(bgep->stat_val.ifHCOutOctets);
		(knp++)->value.ui64 =
			(uint64_t)(bgep->stat_val.etherStatsCollisions);
		(knp++)->value.ui64 =
			(uint64_t)(bgep->stat_val.outXonSent);
		(knp++)->value.ui64 =
			(uint64_t)(bgep->stat_val.outXoffSent);
		(knp++)->value.ui64 =
			(uint64_t)(bgep->
				stat_val.dot3StatsInternalMacTransmitErrors);
		(knp++)->value.ui64 =
			(uint64_t)(bgep->
				stat_val.dot3StatsSingleCollisionFrames);
		(knp++)->value.ui64 =
			(uint64_t)(bgep->
				stat_val.dot3StatsMultipleCollisionFrames);
		(knp++)->value.ui64 =
			(uint64_t)(bgep->
				stat_val.dot3StatsDeferredTransmissions);
		(knp++)->value.ui64 =
			(uint64_t)(bgep->stat_val.dot3StatsExcessiveCollisions);
		(knp++)->value.ui64 =
			(uint64_t)(bgep->stat_val.dot3StatsLateCollisions);
		(knp++)->value.ui64 =
			(uint64_t)(bgep->stat_val.ifHCOutUcastPkts);
		(knp++)->value.ui64 =
			(uint64_t)(bgep->stat_val.ifHCOutMulticastPkts);
		(knp++)->value.ui64 =
			(uint64_t)(bgep->stat_val.ifHCOutBroadcastPkts);
		(knp++)->value.ui64 =
			(uint64_t)(bgep->stat_val.ifHCInOctets);
		(knp++)->value.ui64 =
			(uint64_t)(bgep->stat_val.etherStatsFragments);
		(knp++)->value.ui64 =
			(uint64_t)(bgep->stat_val.ifHCInUcastPkts);
		(knp++)->value.ui64 =
			(uint64_t)(bgep->stat_val.ifHCInMulticastPkts);
		(knp++)->value.ui64 =
			(uint64_t)(bgep->stat_val.ifHCInBroadcastPkts);
		(knp++)->value.ui64 =
			(uint64_t)(bgep->stat_val.dot3StatsFCSErrors);
		(knp++)->value.ui64 =
			(uint64_t)(bgep->stat_val.dot3StatsAlignmentErrors);
		(knp++)->value.ui64 =
			(uint64_t)(bgep->stat_val.xonPauseFramesReceived);
		(knp++)->value.ui64 =
			(uint64_t)(bgep->stat_val.xoffPauseFramesReceived);
		(knp++)->value.ui64 =
			(uint64_t)(bgep->stat_val.macControlFramesReceived);
		(knp++)->value.ui64 =
			(uint64_t)(bgep->stat_val.xoffStateEntered);
		(knp++)->value.ui64 =
			(uint64_t)(bgep->stat_val.dot3StatsFrameTooLongs);
		(knp++)->value.ui64 =
			(uint64_t)(bgep->stat_val.etherStatsJabbers);
		(knp++)->value.ui64 =
			(uint64_t)(bgep->stat_val.etherStatsUndersizePkts);
	}

	return (0);
}

static int
bge_params_update(kstat_t *ksp, int flag)
{
	bge_t *bgep;
	kstat_named_t *knp;
	int i;

	if (flag != KSTAT_READ)
		return (EACCES);

	bgep = ksp->ks_private;
	for (knp = ksp->ks_data, i = 0; i < PARAM_COUNT; ++knp, ++i)
		knp->value.ui64 = bgep->nd_params[i].ndp_val;

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

	return (0);
}

static const bge_ksindex_t bge_driverinfo[] = {
	{ 0,				"rx_buff_addr"		},
	{ 1,				"tx_buff_addr"		},
	{ 2,				"rx_desc_addr"		},
	{ 3,				"tx_desc_addr"		},

	{ 4,				"tx_desc_free"		},
	{ 5,				"resched_needed"	},
	{ 6,				"watchdog"		},
	{ 7,				"chip_resets"		},
	{ 8,				"dma_misses"		},

	{ 9,				"misc_host_config"	},
	{ 10,				"dma_rw_control"	},
	{ 11,				"pci_bus_info"		},

	{ 12,				"buff_mgr_status"	},
	{ 13,				"rcv_init_status"	},

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
	(knp++)->value.ui64 = bgep->resched_needed;
	(knp++)->value.ui64 = bgep->watchdog;
	(knp++)->value.ui64 = bgep->chip_resets;
	(knp++)->value.ui64 = bgep->missed_dmas;

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

static const bge_ksindex_t bge_mii_kstats[] = {
	{ 0,				"%xcvr_addr"		},
	{ 1,				"%xcvr_id"			},
	{ 2,				"%xcvr_inuse"		},

	{ 3,				"%cap_1000fdx"		},
	{ 4,				"%cap_1000hdx"		},
	{ 5,				"%cap_100fdx"		},
	{ 6,				"%cap_100hdx"		},
	{ 7,				"%cap_10fdx"		},
	{ 8,				"%cap_10hdx"		},
	{ 9,				"%cap_asmpause"		},
	{ 10,				"%cap_pause"		},
	{ 11,				"%cap_rem_fault"	},
	{ 12,				"%cap_autoneg"		},

	{ 13,				"%adv_cap_1000fdx"	},
	{ 14,				"%adv_cap_1000hdx"	},
	{ 15,				"%adv_cap_100fdx"	},
	{ 16,				"%adv_cap_100hdx"	},
	{ 17,				"%adv_cap_10fdx"	},
	{ 18,				"%adv_cap_10hdx"	},
	{ 19,				"%adv_cap_asmpause"	},
	{ 20,				"%adv_cap_pause"	},
	{ 21,				"%adv_rem_fault"	},
	{ 22,				"%adv_cap_autoneg"	},

	{ 23,				"%lp_cap_1000fdx"	},
	{ 24,				"%lp_cap_1000hdx"	},
	{ 25,				"%lp_cap_100fdx"	},
	{ 26,				"%lp_cap_100hdx"	},
	{ 27,				"%lp_cap_10fdx"		},
	{ 28,				"%lp_cap_10hdx"		},
	{ 29,				"%lp_cap_asmpause"	},
	{ 30,				"%lp_cap_pause"		},
	{ 31,				"%lp_rem_fault"		},
	{ 32,				"%lp_cap_autoneg"	},

	{ 33,				"%link_asmpause"	},
	{ 34,				"%link_pause"		},
	{ 35,				"%link_duplex"		},
	{ 36,				"%link_up"			},

	{ -1,				NULL 				}
};

/*
 * Derive and publish the standard "mii" kstats.
 *
 * The information required is somewhat scattered: some is already held
 * in driver softstate, some is available in the MII registers, and some
 * has to be computed from combinations of both ...
 */
static int
bge_mii_update(kstat_t *ksp, int flag)
{
	bge_t *bgep;
	kstat_named_t *knp;
	uint16_t anlpar;
	uint16_t anar;
	uint32_t xcvr_id;
	uint32_t xcvr_inuse;
	boolean_t asym_pause;

	if (flag != KSTAT_READ)
		return (EACCES);

	bgep = ksp->ks_private;
	if (bgep->bge_chip_state == BGE_CHIP_FAULT)
		return (EIO);

	knp = ksp->ks_data;

	/*
	 * Read all the relevant PHY registers
	 */
	mutex_enter(bgep->genlock);
	anlpar = bge_mii_get16(bgep, MII_AN_LPABLE);
	anar = bge_mii_get16(bgep, MII_AN_ADVERT);

	/*
	 * Derive PHY characterisation parameters
	 */
	xcvr_id = bge_mii_get16(bgep, MII_PHYIDH);
	xcvr_id <<= 16;
	xcvr_id |= bge_mii_get16(bgep, MII_PHYIDL);
	if (bge_check_acc_handle(bgep, bgep->io_handle) != DDI_FM_OK) {
		ddi_fm_service_impact(bgep->devinfo, DDI_SERVICE_DEGRADED);
		mutex_exit(bgep->genlock);
		return (EIO);
	}
	mutex_exit(bgep->genlock);

	switch (bgep->param_link_speed) {
	case 1000:
		if (bgep->chipid.flags & CHIP_FLAG_SERDES)
			xcvr_inuse = XCVR_TYPE_1000BASE_X;
		else
			xcvr_inuse = XCVR_TYPE_1000BASE_T;
		break;

	case 100:
		xcvr_inuse = XCVR_TYPE_100BASE_X;
		break;

	case 10:
		xcvr_inuse = XCVR_TYPE_10BASE_T;
		break;

	default:
		xcvr_inuse = XCVR_TYPE_UNDEFINED;
		break;
	}

	/*
	 * Other miscellaneous transformations ...
	 */
	asym_pause = bgep->param_link_rx_pause != bgep->param_link_tx_pause;

	/*
	 * All required values are now available; assign them to the
	 * actual kstats, in the sequence defined by the table above.
	 */
	(knp++)->value.ui32 = bgep->phy_mii_addr;
	(knp++)->value.ui32 = xcvr_id;
	(knp++)->value.ui32 = xcvr_inuse;

	/*
	 * Our capabilities
	 */
	(knp++)->value.ui32 = bgep->nd_params[PARAM_1000FDX_CAP].ndp_val;
	(knp++)->value.ui32 = bgep->nd_params[PARAM_1000HDX_CAP].ndp_val;
	(knp++)->value.ui32 = bgep->nd_params[PARAM_100FDX_CAP].ndp_val;
	(knp++)->value.ui32 = bgep->nd_params[PARAM_100HDX_CAP].ndp_val;
	(knp++)->value.ui32 = bgep->nd_params[PARAM_10FDX_CAP].ndp_val;
	(knp++)->value.ui32 = bgep->nd_params[PARAM_10HDX_CAP].ndp_val;
	(knp++)->value.ui32 = bgep->nd_params[PARAM_ASYM_PAUSE_CAP].ndp_val;
	(knp++)->value.ui32 = bgep->nd_params[PARAM_PAUSE_CAP].ndp_val;
	(knp++)->value.ui32 = B_TRUE;
	(knp++)->value.ui32 = bgep->nd_params[PARAM_AUTONEG_CAP].ndp_val;

	/*
	 * Our *advertised* capabilities
	 */
	(knp++)->value.ui32 = bgep->param_adv_1000fdx;
	(knp++)->value.ui32 = bgep->param_adv_1000hdx;
	(knp++)->value.ui32 = bgep->param_adv_100fdx;
	(knp++)->value.ui32 = bgep->param_adv_100hdx;
	(knp++)->value.ui32 = bgep->param_adv_10fdx;
	(knp++)->value.ui32 = bgep->param_adv_10hdx;
	(knp++)->value.ui32 = bgep->param_adv_asym_pause;
	(knp++)->value.ui32 = bgep->param_adv_pause;
	(knp++)->value.ui32 = (anar & MII_AN_ADVERT_REMFAULT) ? 1 : 0;
	(knp++)->value.ui32 = bgep->param_adv_autoneg;

	/*
	 * Link Partner's advertised capabilities
	 */
	(knp++)->value.ui32 = bgep->param_lp_1000fdx;
	(knp++)->value.ui32 = bgep->param_lp_1000hdx;
	(knp++)->value.ui32 = bgep->param_lp_100fdx;
	(knp++)->value.ui32 = bgep->param_lp_100hdx;
	(knp++)->value.ui32 = bgep->param_lp_10fdx;
	(knp++)->value.ui32 = bgep->param_lp_10hdx;
	(knp++)->value.ui32 = bgep->param_lp_asym_pause;
	(knp++)->value.ui32 = bgep->param_lp_pause;
	(knp++)->value.ui32 = (anlpar & MII_AN_ADVERT_REMFAULT) ? 1 : 0;
	(knp++)->value.ui32 = bgep->param_lp_autoneg;

	/*
	 * Current operating modes
	 */
	(knp++)->value.ui32 = asym_pause;
	(knp++)->value.ui32 = bgep->param_link_rx_pause;
	(knp++)->value.ui32 = bgep->param_link_duplex;
	(knp++)->value.ui32 = bgep->param_link_up;

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
	{ MII_AN_LPNXTPG,		"an_lp_nextpage"	},
	{ MII_1000BASE_T_CONTROL,	"gbit_control"		},
	{ MII_1000BASE_T_STATUS,	"gbit_status"		},
	{ MII_IEEE_EXT_STATUS,		"ieee_ext_status"	},
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
		KSTAT_TYPE_NAMED, size-1, KSTAT_FLAG_PERSISTENT);
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

/*
 * Create kstats corresponding to NDD parameters
 */
static kstat_t *
bge_setup_params_kstat(bge_t *bgep, int instance, char *name,
	int (*update)(kstat_t *, int))
{
	kstat_t *ksp;
	kstat_named_t *knp;
	int i;

	ksp = kstat_create(BGE_DRIVER_NAME, instance, name, "net",
		KSTAT_TYPE_NAMED, PARAM_COUNT, KSTAT_FLAG_PERSISTENT);
	if (ksp != NULL) {
		ksp->ks_private = bgep;
		ksp->ks_update = update;
		for (knp = ksp->ks_data, i = 0; i < PARAM_COUNT; ++knp, ++i)
			kstat_named_init(knp, bgep->nd_params[i].ndp_name+1,
				KSTAT_DATA_UINT64);
		kstat_install(ksp);
	}

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

	bgep->bge_kstats[BGE_KSTAT_MII] = bge_setup_named_kstat(bgep,
		instance, "mii", bge_mii_kstats,
		sizeof (bge_mii_kstats), bge_mii_update);

	if (bgep->chipid.flags & CHIP_FLAG_SERDES)
		bgep->bge_kstats[BGE_KSTAT_PHYS] = bge_setup_named_kstat(bgep,
			instance, "serdes", bge_serdes,
			sizeof (bge_serdes), bge_serdes_update);
	else
		bgep->bge_kstats[BGE_KSTAT_PHYS] = bge_setup_named_kstat(bgep,
			instance, "phydata", bge_phydata,
			sizeof (bge_phydata), bge_phydata_update);

	bgep->bge_kstats[BGE_KSTAT_PARAMS] = bge_setup_params_kstat(bgep,
		instance, "parameters", bge_params_update);
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

	if (bgep->bge_chip_state == BGE_CHIP_FAULT) {
		return (EINVAL);
	}

	/*
	 * The MII/GMII physical layer 802.3 stats are not supported by the
	 * bge optical interface.
	 */
	if ((bgep->chipid.flags & CHIP_FLAG_SERDES) && ETHER_STAT_ISMII(stat)) {
		return (ENOTSUP);
	}

	if (bgep->chipid.statistic_type == BGE_STAT_BLK)
		bstp = DMA_VPTR(bgep->statistics);
	else {
		bgep->stat_val.ifHCOutOctets +=
			bge_reg_get32(bgep, STAT_IFHCOUT_OCTETS_REG);
		bgep->stat_val.etherStatsCollisions +=
			bge_reg_get32(bgep, STAT_ETHER_COLLIS_REG);
		bgep->stat_val.outXonSent +=
			bge_reg_get32(bgep, STAT_OUTXON_SENT_REG);
		bgep->stat_val.outXoffSent +=
			bge_reg_get32(bgep, STAT_OUTXOFF_SENT_REG);
		bgep->stat_val.dot3StatsInternalMacTransmitErrors +=
			bge_reg_get32(bgep, STAT_DOT3_INTMACTX_ERR_REG);
		bgep->stat_val.dot3StatsSingleCollisionFrames +=
			bge_reg_get32(bgep, STAT_DOT3_SCOLLI_FRAME_REG);
		bgep->stat_val.dot3StatsMultipleCollisionFrames +=
			bge_reg_get32(bgep, STAT_DOT3_MCOLLI_FRAME_REG);
		bgep->stat_val.dot3StatsDeferredTransmissions +=
			bge_reg_get32(bgep, STAT_DOT3_DEFERED_TX_REG);
		bgep->stat_val.dot3StatsExcessiveCollisions +=
			bge_reg_get32(bgep, STAT_DOT3_EXCE_COLLI_REG);
		bgep->stat_val.dot3StatsLateCollisions +=
			bge_reg_get32(bgep, STAT_DOT3_LATE_COLLI_REG);
		bgep->stat_val.ifHCOutUcastPkts +=
			bge_reg_get32(bgep, STAT_IFHCOUT_UPKGS_REG);
		bgep->stat_val.ifHCOutMulticastPkts +=
			bge_reg_get32(bgep, STAT_IFHCOUT_MPKGS_REG);
		bgep->stat_val.ifHCOutBroadcastPkts +=
			bge_reg_get32(bgep, STAT_IFHCOUT_BPKGS_REG);
		bgep->stat_val.ifHCInOctets +=
			bge_reg_get32(bgep, STAT_IFHCIN_OCTETS_REG);
		bgep->stat_val.etherStatsFragments +=
			bge_reg_get32(bgep, STAT_ETHER_FRAGMENT_REG);
		bgep->stat_val.ifHCInUcastPkts +=
			bge_reg_get32(bgep, STAT_IFHCIN_UPKGS_REG);
		bgep->stat_val.ifHCInMulticastPkts +=
			bge_reg_get32(bgep, STAT_IFHCIN_MPKGS_REG);
		bgep->stat_val.ifHCInBroadcastPkts +=
			bge_reg_get32(bgep, STAT_IFHCIN_BPKGS_REG);
		bgep->stat_val.dot3StatsFCSErrors +=
			bge_reg_get32(bgep, STAT_DOT3_FCS_ERR_REG);
		bgep->stat_val.dot3StatsAlignmentErrors +=
			bge_reg_get32(bgep, STAT_DOT3_ALIGN_ERR_REG);
		bgep->stat_val.xonPauseFramesReceived +=
			bge_reg_get32(bgep, STAT_XON_PAUSE_RX_REG);
		bgep->stat_val.xoffPauseFramesReceived +=
			bge_reg_get32(bgep, STAT_XOFF_PAUSE_RX_REG);
		bgep->stat_val.macControlFramesReceived +=
			bge_reg_get32(bgep, STAT_MAC_CTRL_RX_REG);
		bgep->stat_val.xoffStateEntered +=
			bge_reg_get32(bgep, STAT_XOFF_STATE_ENTER_REG);
		bgep->stat_val.dot3StatsFrameTooLongs +=
			bge_reg_get32(bgep, STAT_DOT3_FRAME_TOOLONG_REG);
		bgep->stat_val.etherStatsJabbers +=
			bge_reg_get32(bgep, STAT_ETHER_JABBERS_REG);
		bgep->stat_val.etherStatsUndersizePkts +=
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
		*val = bgep->param_link_speed * 1000000ull;
		break;

	case MAC_STAT_MULTIRCV:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.ifHCInMulticastPkts;
		else
			*val = bgep->stat_val.ifHCInMulticastPkts;
		break;

	case MAC_STAT_BRDCSTRCV:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.ifHCInBroadcastPkts;
		else
			*val = bgep->stat_val.ifHCInBroadcastPkts;
		break;

	case MAC_STAT_MULTIXMT:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.ifHCOutMulticastPkts;
		else
			*val = bgep->stat_val.ifHCOutMulticastPkts;
		break;

	case MAC_STAT_BRDCSTXMT:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.ifHCOutBroadcastPkts;
		else
			*val = bgep->stat_val.ifHCOutBroadcastPkts;
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
			*val = bgep->stat_val.dot3StatsFCSErrors +
				bgep->stat_val.dot3StatsAlignmentErrors +
				bgep->stat_val.dot3StatsFrameTooLongs +
				bgep->stat_val.etherStatsUndersizePkts +
				bgep->stat_val.etherStatsJabbers;
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
			*val = bgep->stat_val.etherStatsCollisions;
		break;

	case MAC_STAT_RBYTES:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.ifHCInOctets;
		else
			*val = bgep->stat_val.ifHCInOctets;
		break;

	case MAC_STAT_IPACKETS:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.ifHCInUcastPkts +
			    bstp->s.ifHCInMulticastPkts +
			    bstp->s.ifHCInBroadcastPkts;
		else
			*val = bgep->stat_val.ifHCInUcastPkts +
			    bgep->stat_val.ifHCInMulticastPkts +
			    bgep->stat_val.ifHCInBroadcastPkts;
		break;

	case MAC_STAT_OBYTES:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.ifHCOutOctets;
		else
			*val = bgep->stat_val.ifHCOutOctets;
		break;

	case MAC_STAT_OPACKETS:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.ifHCOutUcastPkts +
			    bstp->s.ifHCOutMulticastPkts +
			    bstp->s.ifHCOutBroadcastPkts;
		else
			*val = bgep->stat_val.ifHCOutUcastPkts +
			    bgep->stat_val.ifHCOutMulticastPkts +
			    bgep->stat_val.ifHCOutBroadcastPkts;
		break;

	case ETHER_STAT_ALIGN_ERRORS:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.dot3StatsAlignmentErrors;
		else
			*val = bgep->stat_val.dot3StatsAlignmentErrors;
		break;

	case ETHER_STAT_FCS_ERRORS:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.dot3StatsFCSErrors;
		else
			*val = bgep->stat_val.dot3StatsFCSErrors;
		break;

	case ETHER_STAT_FIRST_COLLISIONS:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.dot3StatsSingleCollisionFrames;
		else
			*val = bgep->stat_val.dot3StatsSingleCollisionFrames;
		break;

	case ETHER_STAT_MULTI_COLLISIONS:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.dot3StatsMultipleCollisionFrames;
		else
			*val = bgep->stat_val.dot3StatsMultipleCollisionFrames;
		break;

	case ETHER_STAT_DEFER_XMTS:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.dot3StatsDeferredTransmissions;
		else
			*val = bgep->stat_val.dot3StatsDeferredTransmissions;
		break;

	case ETHER_STAT_TX_LATE_COLLISIONS:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.dot3StatsLateCollisions;
		else
			*val = bgep->stat_val.dot3StatsLateCollisions;
		break;

	case ETHER_STAT_EX_COLLISIONS:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.dot3StatsExcessiveCollisions;
		else
			*val = bgep->stat_val.dot3StatsExcessiveCollisions;
		break;

	case ETHER_STAT_MACXMT_ERRORS:
		if (bgep->chipid.statistic_type == BGE_STAT_BLK)
			*val = bstp->s.dot3StatsInternalMacTransmitErrors;
		else
			*val = bgep->
			    stat_val.dot3StatsInternalMacTransmitErrors;
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
			*val = bgep->stat_val.dot3StatsFrameTooLongs;
		break;

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
		*val = XCVR_1000T;
		break;

	case ETHER_STAT_CAP_1000FDX:
		*val = 1;
		break;

	case ETHER_STAT_CAP_1000HDX:
		*val = 1;
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
		*val = bgep->param_link_duplex;
		break;

	default:
		return (ENOTSUP);
	}

	return (0);
}
