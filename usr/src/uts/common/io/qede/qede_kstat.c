/*
* CDDL HEADER START
*
* The contents of this file are subject to the terms of the
* Common Development and Distribution License, v.1,  (the "License").
* You may not use this file except in compliance with the License.
*
* You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
* or http://opensource.org/licenses/CDDL-1.0.
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
* Copyright 2014-2017 Cavium, Inc. 
* The contents of this file are subject to the terms of the Common Development 
* and Distribution License, v.1,  (the "License").

* You may not use this file except in compliance with the License.

* You can obtain a copy of the License at available 
* at http://opensource.org/licenses/CDDL-1.0

* See the License for the specific language governing permissions and 
* limitations under the License.
*/


#include "qede.h"

typedef struct  _qede_kstat {
	kstat_named_t qede_hi;
	kstat_named_t qede_lo;
	kstat_named_t version;
	kstat_named_t versionFW;
	kstat_named_t versionMFW;
	kstat_named_t chipID;
	kstat_named_t chipName;
	kstat_named_t devBDF;
	kstat_named_t devID;
	kstat_named_t multiFunction;
	kstat_named_t multiFunctionVnics;
	kstat_named_t macAddr;
	kstat_named_t hwInitDone;
	kstat_named_t numVports;
	kstat_named_t vportID;
	kstat_named_t intrAlloc;
	kstat_named_t intrFired;
	kstat_named_t lroEnabled;
	kstat_named_t lsoEnabled;
	kstat_named_t jumboEnabled;
	kstat_named_t txTotalPkts;
	kstat_named_t txTotalBytes;
	kstat_named_t txTotalDiscards;
	kstat_named_t rxTotalPkts;
	kstat_named_t rxTotalBytes;
	kstat_named_t rxTotalDiscards;
	kstat_named_t allocbFailures;
} qede_kstat_t;

#define QEDE_KSTAT_SIZE (sizeof (qede_kstat_t) / sizeof (kstat_named_t))

typedef struct _qede_kstat_link {
	kstat_named_t vportID;
    	kstat_named_t uptime;
    	kstat_named_t mtuL2;
    	kstat_named_t speed;
    	kstat_named_t link;
    	kstat_named_t duplex;
    	kstat_named_t pauseRx;
    	kstat_named_t pauseTx;
} qede_kstat_link_t;

#define QEDE_KSTAT_LINK_SIZE \
	(sizeof (qede_kstat_link_t) / sizeof (kstat_named_t))

typedef struct _qede_kstat_intr {
	kstat_named_t intrAlloc;
	kstat_named_t intrFired;
    	kstat_named_t sb_00;
    	kstat_named_t sb_01;
    	kstat_named_t sb_02;
    	kstat_named_t sb_03;
    	kstat_named_t sb_04;
    	kstat_named_t sb_05;
    	kstat_named_t sb_06;
    	kstat_named_t sb_nc_00;
    	kstat_named_t sb_nc_01;
	kstat_named_t sb_nc_02;
    	kstat_named_t sb_nc_03;
    	kstat_named_t sb_nc_04;
    	kstat_named_t sb_nc_05;
    	kstat_named_t sb_nc_06;
    	kstat_named_t sb_poll_00;
    	kstat_named_t sb_poll_01;
    	kstat_named_t sb_poll_02;
    	kstat_named_t sb_poll_03;
    	kstat_named_t sb_poll_04;
    	kstat_named_t sb_poll_05;
    	kstat_named_t sb_poll_06;
    	kstat_named_t sb_poll_nc_00;
    	kstat_named_t sb_poll_nc_01;
    	kstat_named_t sb_poll_nc_02;
    	kstat_named_t sb_poll_nc_03;
    	kstat_named_t sb_poll_nc_04;
    	kstat_named_t sb_poll_nc_05;
    kstat_named_t sb_poll_nc_06;
} qede_kstat_intr_t;

#define QEDE_KSTAT_INTR_SIZE \
	(sizeof (qede_kstat_intr_t) / sizeof (kstat_named_t))

typedef struct _qede_kstat_vport_stats {
	kstat_named_t	rxUcastBytes;
	kstat_named_t   rxMcastBytes;	
	kstat_named_t   rxBcastBytes;	
	kstat_named_t	rxUcastPkts;
	kstat_named_t   rxMcastPkts;	
	kstat_named_t   rxBcastPkts;	
	kstat_named_t   txUcastBytes;
	kstat_named_t	txMcastBytes;
	kstat_named_t	txBcastBytes;
	kstat_named_t   txUcastPkts;
	kstat_named_t	txMcastPkts;
	kstat_named_t	txBcastPkts;
	kstat_named_t	rx64bytePkts;   	
	kstat_named_t   rx127bytePkts;	
	kstat_named_t   rx255bytePkts;
	kstat_named_t   rx511bytePkts;	
	kstat_named_t   rx1023bytePkts;	
	kstat_named_t   rx1518bytePkts;	
	kstat_named_t   rx1522bytePkts;	
	kstat_named_t   rx2047bytePkts;	
	kstat_named_t   rx4095bytePkts;	
	kstat_named_t   rx9216bytePkts;	
	kstat_named_t   rx16383bytePkts;	
	kstat_named_t   tx64bytePkts;
	kstat_named_t   tx64to127bytePkts;
	kstat_named_t   tx128to255bytePkts;
	kstat_named_t   tx256to511bytePkts;
	kstat_named_t   tx512to1023bytePkts;
	kstat_named_t   tx1024to1518bytePkts;
	kstat_named_t   tx1519to2047bytePkts;
	kstat_named_t   tx2048to4095bytePkts;
	kstat_named_t   tx4096to9216bytePkts;
	kstat_named_t   tx9217to16383bytePkts;
	kstat_named_t	rxMacCtrlFrames;
	kstat_named_t   rxPauseFrames;	
	kstat_named_t   txPauseFrames;	
	kstat_named_t   rxCRCerrors;
	kstat_named_t   rxAlignErrors;
	kstat_named_t   rxCarrierErrors;	
 	kstat_named_t	rxOversizeErrors;
	kstat_named_t   rxJabbers;
	kstat_named_t   rxUndersizePkts;	
	kstat_named_t   rxFragments;
	kstat_named_t   txLpiEntryCnt;
	kstat_named_t   txTotalCollisions;
	kstat_named_t   brbTruncates;
	kstat_named_t   noBuffDiscards;
	kstat_named_t   mftagFilterDiscards;
	kstat_named_t   macFilterDiscards;
	kstat_named_t   txErrDropPkts;
	kstat_named_t   coalescedPkts;
	kstat_named_t	coalescedEvents;
	kstat_named_t   coalescedAbortsNum;
	kstat_named_t	nonCoalescedPkts;
	kstat_named_t	coalescedBytes;
} qede_kstat_vport_stats_t;

#define QEDE_KSTAT_VPORT_STATS_SIZE \
	(sizeof (qede_kstat_vport_stats_t) / sizeof (kstat_named_t))

typedef struct _qede_kstat_rxq  {
	kstat_named_t rxqBdTotal;
    	kstat_named_t rxqBdLeft;
    	kstat_named_t rxqBdPageCnt;
    	kstat_named_t rxqBdsPerPage;
    	kstat_named_t rxqBdSize;
    	kstat_named_t rxqBdProdIdx;
    	kstat_named_t rxqBdConsIdx;
    	kstat_named_t rcqBdTotal;
    	kstat_named_t rcqBdLeft;
    	kstat_named_t rcqBdPageCnt;
    	kstat_named_t rcqBdsPerPage;
	kstat_named_t rcqBdSize;
    	kstat_named_t rcqBdProdIdx;
    	kstat_named_t rcqBdConsIdx;
    	kstat_named_t hwRcqConIdx;
    	kstat_named_t rxFreeDescs;
    	kstat_named_t rxActiveDescs;
    	kstat_named_t rxCopyPkts;
    	kstat_named_t rxDropPkts;
    	kstat_named_t rxBufUpInStack;
    	kstat_named_t rxLowWater;
    	kstat_named_t rxLowWaterCnt;
    	kstat_named_t inPollMode;
    	kstat_named_t rxPollCnt;
    	kstat_named_t intrDisableCnt;
    	kstat_named_t intrEnableCnt;
    	kstat_named_t genNumber;
    	kstat_named_t rxRegPkts;
    	kstat_named_t rxJumboPkts;
    	kstat_named_t rxLroPkts;
    	kstat_named_t rxRingTotalPkts;
    	kstat_named_t rxRingTotalBytes;
} qede_kstat_rxq_t;

#define QEDE_KSTAT_RXQ_SIZE \
	(sizeof (qede_kstat_rxq_t) / sizeof (kstat_named_t))

typedef struct _qede_kstat_txq {
	kstat_named_t txBdTotal;
    	kstat_named_t txBdLeft;
    	kstat_named_t txBdPageCnt;
    	kstat_named_t txBdsPerPage;
    	kstat_named_t txBdSize;
    	kstat_named_t hwTxqConIdx;
    	kstat_named_t txBdProdIdx;
    	kstat_named_t txBdConsIdx;
    	kstat_named_t txLowWater;
    	kstat_named_t txRingPause;
    	kstat_named_t txDropPkts;
    	kstat_named_t txCopyPkts;
    	kstat_named_t txBind;
    	kstat_named_t txBindFail;
    	kstat_named_t txPremapped;
    	kstat_named_t txPremappedFail;
    	kstat_named_t txTooManyCookies;
    	kstat_named_t txPullupPkts;
    	kstat_named_t txLsoPkts;
    	kstat_named_t txTooManyMblks;
    	kstat_named_t txMappedPkts;
    	kstat_named_t txJumboPkts;
    	kstat_named_t txRingTotalPkts;
    	kstat_named_t txRingTotalBytes;
} qede_kstat_txq_t;

#define  QEDE_KSTAT_TXQ_SIZE \
	(sizeof (qede_kstat_txq_t) / sizeof (kstat_named_t))


static int 
qede_kstat_update(kstat_t *kstats,
    int rw)
{

	qede_kstat_t *pStats = (qede_kstat_t *)kstats->ks_data;
	qede_t *qede = (qede_t *)kstats->ks_private;
	struct ecore_dev *edev = &qede->edev;
        qede_fastpath_t *fp = &qede->fp_array[0];
	qede_rx_ring_t *rx_ring;
	qede_tx_ring_t *tx_ring;
	int i, j;
	char buf[17];

	if (rw == KSTAT_WRITE) {
        	return EACCES;
	}

	mutex_enter(&qede->kstat_lock);

	snprintf(buf, sizeof (buf), "%16p", (void *)qede);
	strncpy(pStats->qede_hi.value.c, &buf[0], 8);
	pStats->qede_hi.value.c[8] = 0;
	strncpy(pStats->qede_lo.value.c, &buf[8], 8);
	pStats->qede_lo.value.c[8] = 0;


	strncpy(pStats->version.value.c,   
	    qede->version,   sizeof (pStats->version.value.c));
	strncpy(pStats->versionFW.value.c, 
	    qede->versionFW, sizeof (pStats->versionFW.value.c));
    	strncpy(pStats->versionMFW.value.c, 
	    qede->versionMFW, sizeof (pStats->versionMFW.value.c));

	strncpy(pStats->chipName.value.c, 
	    qede->chip_name, sizeof (pStats->chipName.value.c));
	strncpy(pStats->chipID.value.c,   
	    qede->chipID,   sizeof (pStats->chipID.value.c));

	strncpy(pStats->devBDF.value.c, 
	    qede->bus_dev_func,  sizeof (pStats->devBDF.value.c));
	strncpy(pStats->devID.value.c,  
	    qede->vendor_device, sizeof (pStats->devID.value.c));

	strncpy(pStats->multiFunction.value.c,
	    ((edev->mf_mode == ECORE_MF_DEFAULT)    ? "DEFAULT"  :
	    (edev->mf_mode == ECORE_MF_OVLAN)   ? "MF-OVLAN" : "Unknown"),
	    sizeof (pStats->multiFunction.value.c));

	pStats->multiFunctionVnics.value.ui64 = 0;

	snprintf(pStats->macAddr.value.c, 16, "%02x%02x%02x%02x%02x%02x",
	    qede->ether_addr[0],qede->ether_addr[1],
	    qede->ether_addr[2], qede->ether_addr[3],
	    qede->ether_addr[4],qede->ether_addr[5]);


	pStats->hwInitDone.value.ui64 = 
	    (qede->attach_resources & QEDE_ECORE_HW_INIT)? 1 :  0;
	  /*pStats->numVports.value.ui64 = 
	    p_hwfn->hw_info.resc_num[ECORE_VPORT]; */
	pStats->numVports.value.ui64 =  edev->num_hwfns;
	pStats->vportID.value.ui64 = qede->vport_params[0].vport_id;


	strncpy(pStats->intrAlloc.value.c, 
	    qede->intrAlloc, sizeof (pStats->intrAlloc.value.c));

	pStats->intrFired.value.ui64 = qede->intrFired;
	pStats->lroEnabled.value.ui64 = qede->lro_enable;
	pStats->lsoEnabled.value.ui64 = qede->lso_enable;
	pStats->jumboEnabled.value.ui64 = qede->jumbo_enable;

	qede->rxTotalPkts = 0;
	qede->rxTotalBytes = 0;
	qede->rxTotalDiscards = 0;
	qede->txTotalPkts = 0;
	qede->txTotalBytes = 0;
	qede->txTotalDiscards = 0;	
	qede->allocbFailures = 0;
	for (i = 0; i < qede->num_fp; i++, fp++) {
		rx_ring = fp->rx_ring;
		qede->rxTotalPkts += rx_ring->rx_pkt_cnt;
		qede->rxTotalBytes += rx_ring->rx_byte_cnt;
		qede->rxTotalDiscards += rx_ring->rx_drop_cnt;
		for (j = 0; j < qede->num_tc; j++) {
			tx_ring = fp->tx_ring[j];
			qede->txTotalPkts += tx_ring->tx_pkt_count;
			qede->txTotalBytes += tx_ring->tx_byte_count;
			qede->txTotalDiscards += tx_ring->tx_pkt_dropped;
		}
	}
	pStats->rxTotalPkts.value.ui64 = qede->rxTotalPkts;
	pStats->rxTotalBytes.value.ui64 = qede->rxTotalBytes;
	pStats->rxTotalDiscards.value.ui64 = qede->rxTotalDiscards;
	pStats->txTotalPkts.value.ui64 = qede->txTotalPkts;
	pStats->txTotalBytes.value.ui64 = qede->txTotalBytes;
	pStats->txTotalDiscards.value.ui64 = qede->txTotalDiscards;
	pStats->allocbFailures.value.ui64 = qede->allocbFailures;

       mutex_exit(&qede->kstat_lock);
       return (0);

}

static int
qede_kstat_link_update(kstat_t *kstats, int rw)
{
	qede_kstat_link_t *pStats = (qede_kstat_link_t *)kstats->ks_data;
	qede_t *qede = (qede_t *)kstats->ks_private;
	struct ecore_dev *edev = &qede->edev;

	if (rw == KSTAT_WRITE) {
		return EACCES;
	}
	mutex_enter(&qede->kstat_lock);
	
	pStats->vportID.value.ui64 = qede->vport_params[0].vport_id;
	pStats->uptime.value.ui64  = (qede->props.link_speed) ?
                                     (ddi_get_time() - qede->props.uptime) : 0;
	pStats->mtuL2.value.ui64   = qede->mtu;
	pStats->speed.value.ui64   = qede->props.link_speed;
	pStats->link.value.ui64    = qede->params.link_state;
	pStats->duplex.value.ui64  = qede->props.link_duplex;
	pStats->pauseRx.value.ui64 = qede->props.rx_pause;
	pStats->pauseTx.value.ui64 = qede->props.tx_pause;

	mutex_exit(&qede->kstat_lock);
	return (0);
}
	
static int
qede_kstat_intr_update(kstat_t *kstats, int rw)
{

	qede_kstat_intr_t * pStats = (qede_kstat_intr_t *)kstats->ks_data;
	qede_t *qede = (qede_t *)kstats->ks_private;
	struct ecore_dev *edev = &qede->edev;

	if (rw == KSTAT_WRITE) {
		return EACCES;
	}

	mutex_enter(&qede->kstat_lock);


	strncpy(pStats->intrAlloc.value.c, 
	    qede->intrAlloc, sizeof (pStats->intrAlloc.value.c));

	pStats->intrFired.value.ui64      = qede->intrFired;

	pStats->sb_00.value.ui64          = qede->intrSbCnt[0];
	pStats->sb_01.value.ui64          = qede->intrSbCnt[1];
	pStats->sb_02.value.ui64          = qede->intrSbCnt[2];
	pStats->sb_03.value.ui64          = qede->intrSbCnt[3];
	pStats->sb_04.value.ui64          = qede->intrSbCnt[4];
	pStats->sb_05.value.ui64          = qede->intrSbCnt[5];
	pStats->sb_06.value.ui64          = qede->intrSbCnt[6];

	pStats->sb_nc_00.value.ui64       = qede->intrSbNoChangeCnt[0];
	pStats->sb_nc_01.value.ui64       = qede->intrSbNoChangeCnt[1];
	pStats->sb_nc_02.value.ui64       = qede->intrSbNoChangeCnt[2];
	pStats->sb_nc_03.value.ui64       = qede->intrSbNoChangeCnt[3];
	pStats->sb_nc_04.value.ui64       = qede->intrSbNoChangeCnt[4];
	pStats->sb_nc_05.value.ui64       = qede->intrSbNoChangeCnt[5];
	pStats->sb_nc_06.value.ui64       = qede->intrSbNoChangeCnt[6];


	pStats->sb_poll_00.value.ui64     = qede->intrSbPollCnt[0];
	pStats->sb_poll_01.value.ui64     = qede->intrSbPollCnt[1];
	pStats->sb_poll_02.value.ui64     = qede->intrSbPollCnt[2];
	pStats->sb_poll_03.value.ui64     = qede->intrSbPollCnt[3];
	pStats->sb_poll_04.value.ui64     = qede->intrSbPollCnt[4];
	pStats->sb_poll_05.value.ui64     = qede->intrSbPollCnt[5];
	pStats->sb_poll_06.value.ui64     = qede->intrSbPollCnt[6];

	pStats->sb_poll_nc_00.value.ui64  = qede->intrSbPollNoChangeCnt[0];
	pStats->sb_poll_nc_01.value.ui64  = qede->intrSbPollNoChangeCnt[1];
	pStats->sb_poll_nc_02.value.ui64  = qede->intrSbPollNoChangeCnt[2];
	pStats->sb_poll_nc_03.value.ui64  = qede->intrSbPollNoChangeCnt[3];
	pStats->sb_poll_nc_04.value.ui64  = qede->intrSbPollNoChangeCnt[4];
	pStats->sb_poll_nc_05.value.ui64  = qede->intrSbPollNoChangeCnt[5];
	pStats->sb_poll_nc_06.value.ui64  = qede->intrSbPollNoChangeCnt[6];


    mutex_exit(&qede->kstat_lock); 

    return (0);
}

static int
qede_kstat_vport_stats_update(kstat_t *kstats, int rw)
{

	qede_kstat_vport_stats_t *pStats = 
	    (qede_kstat_vport_stats_t *)kstats->ks_data;
	qede_t *qede = (qede_t *)kstats->ks_private;
	struct ecore_dev * edev = &qede->edev;
	struct ecore_eth_stats vstats;
	

	if (rw == KSTAT_WRITE) {
		return EACCES;
	}


	mutex_enter(&qede->kstat_lock);
	
	memset(&vstats, 0, sizeof (struct ecore_eth_stats));
	if(qede->qede_state == QEDE_STATE_STARTED) {
		ecore_get_vport_stats(edev, &vstats);
		memcpy(&qede->save_stats, &vstats,
		    sizeof (struct ecore_eth_stats));
	}

	pStats->rxUcastBytes.value.ui64 = vstats.common.rx_ucast_bytes;
	pStats->rxMcastBytes.value.ui64 = vstats.common.rx_mcast_bytes;
	pStats->rxBcastBytes.value.ui64 = vstats.common.rx_bcast_bytes;
	pStats->rxUcastPkts.value.ui64 = vstats.common.rx_ucast_pkts;        
	pStats->rxMcastPkts.value.ui64 = vstats.common.rx_mcast_pkts;
	pStats->rxBcastPkts.value.ui64 = vstats.common.rx_bcast_pkts;
	pStats->txUcastBytes.value.ui64 = vstats.common.tx_ucast_bytes;
	pStats->txMcastBytes.value.ui64 = vstats.common.tx_mcast_bytes;
	pStats->txBcastBytes.value.ui64 = vstats.common.tx_bcast_bytes;
	pStats->txUcastPkts.value.ui64 = vstats.common.tx_ucast_pkts;        
	pStats->txMcastPkts.value.ui64 = vstats.common.tx_mcast_pkts;
	pStats->txBcastPkts.value.ui64 = vstats.common.tx_bcast_pkts;
	pStats->rx64bytePkts.value.ui64 = vstats.common.rx_64_byte_packets;
	pStats->rx127bytePkts.value.ui64 = 
	    vstats.common.rx_65_to_127_byte_packets;
	pStats->rx255bytePkts.value.ui64 = 
	    vstats.common.rx_128_to_255_byte_packets;
	pStats->rx511bytePkts.value.ui64 = 
	    vstats.common.rx_256_to_511_byte_packets;
	pStats->rx1023bytePkts.value.ui64 = 
	    vstats.common.rx_512_to_1023_byte_packets;
	pStats->rx1518bytePkts.value.ui64 = 
	    vstats.common.rx_1024_to_1518_byte_packets;
	pStats->rx1522bytePkts.value.ui64 = 
	    vstats.bb.rx_1519_to_1522_byte_packets;
	pStats->rx2047bytePkts.value.ui64 = 
	    vstats.bb.rx_1519_to_2047_byte_packets;
	pStats->rx4095bytePkts.value.ui64 = 
	    vstats.bb.rx_2048_to_4095_byte_packets;
	pStats->rx9216bytePkts.value.ui64 = 
	    vstats.bb.rx_4096_to_9216_byte_packets;
	pStats->rx16383bytePkts.value.ui64 = 
	    vstats.bb.rx_9217_to_16383_byte_packets;
	pStats->tx64bytePkts.value.ui64 = 
	    vstats.common.tx_64_byte_packets;
	pStats->tx64to127bytePkts.value.ui64 = 
	    vstats.common.tx_65_to_127_byte_packets;
	pStats->tx128to255bytePkts.value.ui64 = 
	    vstats.common.tx_128_to_255_byte_packets;
	pStats->tx256to511bytePkts.value.ui64 = 
	    vstats.common.tx_256_to_511_byte_packets;
	pStats->tx512to1023bytePkts.value.ui64 = 
	    vstats.common.tx_512_to_1023_byte_packets;
	pStats->tx1024to1518bytePkts.value.ui64 = 
	    vstats.common.tx_1024_to_1518_byte_packets;
	pStats->tx1519to2047bytePkts.value.ui64 = 
	    vstats.bb.tx_1519_to_2047_byte_packets;
	pStats->tx2048to4095bytePkts.value.ui64 = 
	    vstats.bb.tx_2048_to_4095_byte_packets;
	pStats->tx4096to9216bytePkts.value.ui64 = 
	    vstats.bb.tx_4096_to_9216_byte_packets;
	pStats->tx9217to16383bytePkts.value.ui64 = 
	    vstats.bb.tx_9217_to_16383_byte_packets;
	pStats->rxMacCtrlFrames.value.ui64 = 
	    vstats.common.rx_mac_crtl_frames;
	pStats->rxPauseFrames.value.ui64 = 
	    vstats.common.rx_pause_frames;
	pStats->txPauseFrames.value.ui64 = 
	    vstats.common.tx_pause_frames;
	pStats->rxCRCerrors.value.ui64 = 
	    vstats.common.rx_crc_errors;
	pStats->rxAlignErrors.value.ui64 = 
	    vstats.common.rx_align_errors;
	pStats->rxCarrierErrors.value.ui64 = 
	    vstats.common.rx_carrier_errors;
	pStats->rxOversizeErrors.value.ui64 = 
	    vstats.common.rx_oversize_packets;
	pStats->rxJabbers.value.ui64 = 
	    vstats.common.rx_jabbers;
	pStats->rxUndersizePkts.value.ui64 = 
	    vstats.common.rx_undersize_packets;
	pStats->rxFragments.value.ui64 = 
	    vstats.common.rx_fragments;
	pStats->txLpiEntryCnt.value.ui64 = 
	    vstats.bb.tx_lpi_entry_count;
	pStats->txTotalCollisions.value.ui64 = 
	    vstats.bb.tx_total_collisions;
	pStats->brbTruncates.value.ui64 = 
	    vstats.common.brb_truncates;
	pStats->noBuffDiscards.value.ui64 = 
	    vstats.common.no_buff_discards;
	pStats->mftagFilterDiscards.value.ui64 = 
	    vstats.common.mftag_filter_discards;
	pStats->macFilterDiscards.value.ui64 = 
	    vstats.common.mac_filter_discards;
	pStats->txErrDropPkts.value.ui64 = 
	    vstats.common.tx_err_drop_pkts;
	pStats->coalescedPkts.value.ui64 = 
	    vstats.common.tpa_coalesced_pkts;
	pStats->coalescedEvents.value.ui64 = 
	    vstats.common.tpa_coalesced_events;
	pStats->coalescedAbortsNum.value.ui64 = 
	    vstats.common.tpa_aborts_num;
	pStats->nonCoalescedPkts.value.ui64 = 
	    vstats.common.tpa_not_coalesced_pkts;
	pStats->coalescedBytes.value.ui64 = 
	    vstats.common.tpa_coalesced_bytes;

	mutex_exit(&qede->kstat_lock);

	return (0);
}

static int
qede_kstat_rxq_update(kstat_t *kstats, int rw)
{

	qede_kstat_rxq_t *pStats = (qede_kstat_rxq_t *)kstats->ks_data;
	KstatRingMap *pMap   = (KstatRingMap *)kstats->ks_private;
	qede_t *qede    = (qede_t *)pMap->qede;
	int idx    = pMap->idx;
	struct ecore_dev *edev = &qede->edev;
	qede_rx_ring_t *rx_ring = &qede->rx_array[idx];


	if (rw == KSTAT_WRITE) {
		return EACCES;
	}


	mutex_enter(&qede->kstat_lock);

	pStats->rxqBdTotal.value.ui64     = qede->rx_ring_size;
	pStats->rcqBdTotal.value.ui64  = qede->rx_ring_size;
	pStats->rxLowWater.value.ui64     = rx_ring->rx_low_buffer_threshold;

	if(qede->qede_state == QEDE_STATE_STARTED) {

	pStats->rxqBdLeft.value.ui64     = 
	    ecore_chain_get_elem_left(&rx_ring->rx_bd_ring);
	pStats->rxqBdPageCnt.value.ui64   = 
	    ECORE_CHAIN_PAGE_CNT(qede->rx_ring_size, 
	    sizeof (struct eth_rx_bd), ECORE_CHAIN_MODE_NEXT_PTR);
	pStats->rxqBdsPerPage.value.ui64  = 
	    ELEMS_PER_PAGE(sizeof (struct eth_rx_bd));
	pStats->rxqBdSize.value.ui64     = sizeof (struct eth_rx_bd);
	pStats->rxqBdProdIdx.value.ui64     = 
	    ecore_chain_get_prod_idx(&rx_ring->rx_bd_ring) & 
	    (rx_ring->qede->rx_ring_size - 1);
	pStats->rxqBdConsIdx.value.ui64     = 
	    ecore_chain_get_cons_idx(&rx_ring->rx_bd_ring) & 
	    (rx_ring->qede->rx_ring_size - 1);
	pStats->rcqBdLeft.value.ui64      = 
	    ecore_chain_get_elem_left(&rx_ring->rx_cqe_ring);
	pStats->rcqBdPageCnt.value.ui64   = 
	    ECORE_CHAIN_PAGE_CNT(qede->rx_ring_size, 
	    sizeof (union eth_rx_cqe), ECORE_CHAIN_MODE_PBL);
	pStats->rcqBdsPerPage.value.ui64  = 
	    ELEMS_PER_PAGE(sizeof (union eth_rx_cqe));
	pStats->rcqBdSize.value.ui64      = sizeof (union eth_rx_cqe);
	pStats->rcqBdProdIdx.value.ui64   = 
	    ecore_chain_get_prod_idx(&rx_ring->rx_cqe_ring) & 
	    (rx_ring->qede->rx_ring_size - 1);
	pStats->rcqBdConsIdx.value.ui64   = 
	    ecore_chain_get_cons_idx(&rx_ring->rx_cqe_ring) & 
	    (rx_ring->qede->rx_ring_size - 1);
	pStats->hwRcqConIdx.value.ui64    = 
	    (rx_ring->hw_cons_ptr != NULL) ? 
	    HOST_TO_LE_16(*rx_ring->hw_cons_ptr) & 
	    (rx_ring->qede->rx_ring_size - 1): 0;
	pStats->rxFreeDescs.value.ui64    = 
	    rx_ring->rx_buf_area->passive_buf_list.num_entries;
	pStats->rxActiveDescs.value.ui64  = 
	    rx_ring->rx_buf_area->active_buf_list.num_entries;
	pStats->rxBufUpInStack.value.ui64 = 
	    rx_ring->rx_buf_area->buf_upstream;
	pStats->rxCopyPkts.value.ui64       = 
	    rx_ring->rx_copy_cnt;
	pStats->rxDropPkts.value.ui64     = 
	    rx_ring->rx_drop_cnt;
	pStats->rxLowWaterCnt.value.ui64     = 
	    rx_ring->rx_low_water_cnt;
	pStats->inPollMode.value.ui64     = 
	    rx_ring->fp->disabled_by_poll;
	pStats->rxPollCnt.value.ui64      = 
	    rx_ring->rx_poll_cnt;;
	pStats->intrDisableCnt.value.ui64 = 
	    rx_ring->intrDisableCnt;
	pStats->intrEnableCnt.value.ui64  = 
	    rx_ring->intrEnableCnt;
	pStats->genNumber.value.ui64      = 
	    rx_ring->mr_gen_num;
	pStats->rxLroPkts.value.ui64    = 
	    rx_ring->rx_lro_pkt_cnt;
	pStats->rxRingTotalPkts.value.ui64    = 
	    rx_ring->rx_pkt_cnt;
	pStats->rxRingTotalBytes.value.ui64    = 
	    rx_ring->rx_byte_cnt;
	pStats->rxRegPkts.value.ui64    = 
	    rx_ring->rx_reg_pkt_cnt;
	pStats->rxJumboPkts.value.ui64    = 
	    rx_ring->rx_jumbo_pkt_cnt;

	} else {

	pStats->rxqBdLeft.value.ui64     = 0;
	pStats->rxqBdPageCnt.value.ui64   = 0;
	pStats->rxqBdsPerPage.value.ui64  = 0;
	pStats->rxqBdSize.value.ui64     = 0;
	pStats->rxqBdProdIdx.value.ui64     = 0;
	pStats->rxqBdConsIdx.value.ui64     = 0;
	pStats->rcqBdLeft.value.ui64      = 0;
	pStats->rcqBdPageCnt.value.ui64   = 0;
	pStats->rcqBdsPerPage.value.ui64  = 0;
	pStats->rcqBdSize.value.ui64      = 0;
	pStats->rcqBdProdIdx.value.ui64   = 0;
	pStats->rcqBdConsIdx.value.ui64   = 0;
	pStats->hwRcqConIdx.value.ui64    = 0;
	pStats->rxFreeDescs.value.ui64    = 0;
	pStats->rxActiveDescs.value.ui64  = 0;
	pStats->rxBufUpInStack.value.ui64 = 0;
	pStats->rxCopyPkts.value.ui64       = 0;
	pStats->rxDropPkts.value.ui64     = 0;
	pStats->rxLowWaterCnt.value.ui64     = 0;
	pStats->inPollMode.value.ui64     = 0;
	pStats->rxPollCnt.value.ui64      = 0;
	pStats->intrDisableCnt.value.ui64 = 0;
	pStats->intrEnableCnt.value.ui64  = 0;
	pStats->genNumber.value.ui64      = 0;
	pStats->rxLroPkts.value.ui64    = 0;
	pStats->rxRingTotalPkts.value.ui64  = 0;
	pStats->rxRingTotalBytes.value.ui64       = 0;
	pStats->rxRegPkts.value.ui64    = 0;
	pStats->rxJumboPkts.value.ui64  = 0;
	}

	mutex_exit(&qede->kstat_lock);
	return (0);
}
	

static int
qede_kstat_txq_update(kstat_t *kstats, int rw)
{

	qede_kstat_txq_t *pStats = (qede_kstat_txq_t *)kstats->ks_data;
	KstatRingMap *pMap   = (KstatRingMap *)kstats->ks_private;
	qede_t *qede    = (qede_t *)pMap->qede;
	int idx    = pMap->idx;
	struct ecore_dev * edev = &qede->edev;
	qede_tx_ring_t *tx_ring = &qede->tx_array[0][idx];


	if (rw == KSTAT_WRITE) {
        	return EACCES;
	}
	mutex_enter(&qede->kstat_lock);

	pStats->txBdTotal.value.ui64     =  qede->tx_ring_size;
	pStats->txBdSize.value.ui64 = sizeof (union eth_tx_bd_types);
	pStats->txLowWater.value.ui64    = qede->tx_recycle_threshold;

	if(qede->qede_state == QEDE_STATE_STARTED) {

	pStats->txBdLeft.value.ui64     = 
	    ecore_chain_get_elem_left(&tx_ring->tx_bd_ring);
	pStats->txBdPageCnt.value.ui64  = 
	    ECORE_CHAIN_PAGE_CNT(tx_ring->bd_ring_size, 
	    sizeof (union eth_tx_bd_types), ECORE_CHAIN_MODE_PBL);
	pStats->txBdsPerPage.value.ui64 = 
	    ELEMS_PER_PAGE(sizeof (union eth_tx_bd_types));
	pStats->hwTxqConIdx.value.ui64 = 
	    (tx_ring->hw_cons_ptr != NULL) ? 
	    HOST_TO_LE_16(*tx_ring->hw_cons_ptr) & TX_RING_MASK : 0;
	pStats->txBdProdIdx.value.ui64 = 
	    ecore_chain_get_prod_idx(&tx_ring->tx_bd_ring) & TX_RING_MASK;
	pStats->txBdConsIdx.value.ui64 = 
	    ecore_chain_get_cons_idx(&tx_ring->tx_bd_ring) & TX_RING_MASK;
 	pStats->txRingPause.value.ui64      = 
	    tx_ring->tx_ring_pause;
	pStats->txDropPkts.value.ui64    = tx_ring->tx_pkt_dropped;
	pStats->txCopyPkts.value.ui64      = tx_ring->tx_copy_count;
	pStats->txBind.value.ui64        = tx_ring->tx_bind_count;
	pStats->txBindFail.value.ui64    = tx_ring->tx_bind_fail;
	pStats->txPremapped.value.ui64      = tx_ring->tx_premap_count;
	pStats->txPremappedFail.value.ui64   = tx_ring->tx_premap_fail;
	pStats->txTooManyCookies.value.ui64   = tx_ring->tx_too_many_cookies;
	pStats->txPullupPkts.value.ui64   = tx_ring->tx_pullup_count;
	pStats->txLsoPkts.value.ui64   = tx_ring->tx_lso_pkt_count;
	pStats->txTooManyMblks.value.ui64   = tx_ring->tx_too_many_mblks;
	pStats->txMappedPkts.value.ui64   = tx_ring->tx_mapped_pkts;
	pStats->txRingTotalPkts.value.ui64    = tx_ring->tx_pkt_count;
	pStats->txRingTotalBytes.value.ui64    = tx_ring->tx_byte_count;
	pStats->txJumboPkts.value.ui64   = tx_ring->tx_jumbo_pkt_count;


  	} else {

	
	pStats->txBdLeft.value.ui64     = 0;
	pStats->txBdPageCnt.value.ui64     = 0;
	pStats->txBdsPerPage.value.ui64     = 0;
	pStats->hwTxqConIdx.value.ui64 = 0;
	pStats->txBdProdIdx.value.ui64   = 0;
	pStats->txBdConsIdx.value.ui64   = 0;
	pStats->txRingPause.value.ui64        = 0;
	pStats->txDropPkts.value.ui64    = 0;
	pStats->txCopyPkts.value.ui64      = 0;
	pStats->txBind.value.ui64        = 0; 
	pStats->txBindFail.value.ui64    = 0;
	pStats->txPremapped.value.ui64   = 0;
	pStats->txPremappedFail.value.ui64  = 0;
	pStats->txTooManyCookies.value.ui64  = 0;
	pStats->txPullupPkts.value.ui64   = 0;
	pStats->txLsoPkts.value.ui64   = 0;
	pStats->txTooManyMblks.value.ui64  = 0;
	pStats->txMappedPkts.value.ui64   = 0;
	pStats->txJumboPkts.value.ui64   = 0;
	pStats->txRingTotalPkts.value.ui64    = 0;
	pStats->txRingTotalBytes.value.ui64    = 0;
	}

	mutex_exit(&qede->kstat_lock);
	return (0);
}

boolean_t 
qede_kstat_init_rxq(qede_t *qede, int idx)
{

	char buf[32];

	qede_kstat_rxq_t *pStatsRxq;

#define QEDE_KSTAT_RXQ(f, t)  kstat_named_init(&pStatsRxq->f, #f, t)

	snprintf(buf, sizeof (buf), "rxq%d", idx);

	if ((qede->kstats_rxq[idx] = kstat_create("qede",
	    qede->instance,
	    buf,
	    "net",
	    KSTAT_TYPE_NAMED,
	    QEDE_KSTAT_RXQ_SIZE,
	    0)) == NULL)
	{
        	/*BnxeLogWarn(qede, "Failed to create rxq%d kstat", idx);*/
		cmn_err(CE_WARN, "Failed to create rxq%d kstat", idx);
        	return (B_FALSE);
	}
        pStatsRxq = (qede_kstat_rxq_t *)qede->kstats_rxq[idx]->ks_data;

	QEDE_KSTAT_RXQ(rxqBdTotal,     KSTAT_DATA_UINT64);
	QEDE_KSTAT_RXQ(rxqBdLeft,      KSTAT_DATA_UINT64);
	QEDE_KSTAT_RXQ(rxqBdPageCnt,   KSTAT_DATA_UINT64);
	QEDE_KSTAT_RXQ(rxqBdsPerPage,  KSTAT_DATA_UINT64);
	QEDE_KSTAT_RXQ(rxqBdSize,      KSTAT_DATA_UINT64);
	QEDE_KSTAT_RXQ(rxqBdProdIdx,   KSTAT_DATA_UINT64);
	QEDE_KSTAT_RXQ(rxqBdConsIdx,   KSTAT_DATA_UINT64);
	QEDE_KSTAT_RXQ(rcqBdTotal,     KSTAT_DATA_UINT64);
	QEDE_KSTAT_RXQ(rcqBdLeft,      KSTAT_DATA_UINT64);
	QEDE_KSTAT_RXQ(rcqBdPageCnt,   KSTAT_DATA_UINT64);
	QEDE_KSTAT_RXQ(rcqBdsPerPage,  KSTAT_DATA_UINT64);
	QEDE_KSTAT_RXQ(rcqBdSize,      KSTAT_DATA_UINT64);
	QEDE_KSTAT_RXQ(rcqBdProdIdx,   KSTAT_DATA_UINT64);
	QEDE_KSTAT_RXQ(rcqBdConsIdx,   KSTAT_DATA_UINT64);
	QEDE_KSTAT_RXQ(hwRcqConIdx,    KSTAT_DATA_UINT64);
	QEDE_KSTAT_RXQ(rxFreeDescs,    KSTAT_DATA_UINT64);
	QEDE_KSTAT_RXQ(rxActiveDescs,  KSTAT_DATA_UINT64);
	QEDE_KSTAT_RXQ(rxCopyPkts,       KSTAT_DATA_UINT64);
	QEDE_KSTAT_RXQ(rxDropPkts,     KSTAT_DATA_UINT64);
	QEDE_KSTAT_RXQ(rxBufUpInStack, KSTAT_DATA_UINT64);
	QEDE_KSTAT_RXQ(rxLowWater,     KSTAT_DATA_UINT64);
	QEDE_KSTAT_RXQ(rxLowWaterCnt,     KSTAT_DATA_UINT64);
	QEDE_KSTAT_RXQ(inPollMode,     KSTAT_DATA_UINT64);
	QEDE_KSTAT_RXQ(rxPollCnt,        KSTAT_DATA_UINT64);
	QEDE_KSTAT_RXQ(intrDisableCnt, KSTAT_DATA_UINT64);
	QEDE_KSTAT_RXQ(intrEnableCnt,  KSTAT_DATA_UINT64);
	QEDE_KSTAT_RXQ(genNumber,      KSTAT_DATA_UINT64);
	QEDE_KSTAT_RXQ(rxRegPkts,      KSTAT_DATA_UINT64);
	QEDE_KSTAT_RXQ(rxJumboPkts,      KSTAT_DATA_UINT64);
	QEDE_KSTAT_RXQ(rxLroPkts,      KSTAT_DATA_UINT64);
	QEDE_KSTAT_RXQ(rxRingTotalPkts,      KSTAT_DATA_UINT64);
	QEDE_KSTAT_RXQ(rxRingTotalBytes,      KSTAT_DATA_UINT64);


	qede->kstats_rxq_map[idx].idx = idx;
	qede->kstats_rxq_map[idx].qede = qede;

	qede->kstats_rxq[idx]->ks_update  = qede_kstat_rxq_update;
	qede->kstats_rxq[idx]->ks_private = (void *)&qede->kstats_rxq_map[idx];

	kstat_install(qede->kstats_rxq[idx]);

	return (B_TRUE);
}


boolean_t 
qede_kstat_init_txq(qede_t *qede, int idx)
{
	char buf[32];

	qede_kstat_txq_t *pStatsTxq;

#define QEDE_KSTAT_TXQ(f, t)  kstat_named_init(&pStatsTxq->f, #f, t)

	snprintf(buf, sizeof (buf), "txq%d", idx);

        if ((qede->kstats_txq[idx] = kstat_create("qede",
	    qede->instance,
	    buf,
	    "net",
	    KSTAT_TYPE_NAMED,
	    QEDE_KSTAT_TXQ_SIZE,
	    0)) == NULL)  {
        	/*BnxeLogWarn(qede, "Failed to create txq%d kstat", idx);*/
		cmn_err(CE_WARN, "Failed to create txq%d kstat", idx);
        	return (B_FALSE);
	}


	pStatsTxq = (qede_kstat_txq_t *)qede->kstats_txq[idx]->ks_data;	

	QEDE_KSTAT_TXQ(txBdTotal,     KSTAT_DATA_UINT64);
	QEDE_KSTAT_TXQ(txBdLeft,      KSTAT_DATA_UINT64);
	QEDE_KSTAT_TXQ(txBdPageCnt,   KSTAT_DATA_UINT64);
	QEDE_KSTAT_TXQ(txBdsPerPage,  KSTAT_DATA_UINT64);
	QEDE_KSTAT_TXQ(txBdSize,      KSTAT_DATA_UINT64);
	QEDE_KSTAT_TXQ(hwTxqConIdx,   KSTAT_DATA_UINT64);
	QEDE_KSTAT_TXQ(txBdProdIdx,   KSTAT_DATA_UINT64);
	QEDE_KSTAT_TXQ(txBdConsIdx,   KSTAT_DATA_UINT64);
	QEDE_KSTAT_TXQ(txLowWater,    KSTAT_DATA_UINT64);
	QEDE_KSTAT_TXQ(txDropPkts,    KSTAT_DATA_UINT64);
	QEDE_KSTAT_TXQ(txCopyPkts,      KSTAT_DATA_UINT64);
	QEDE_KSTAT_TXQ(txRingPause,        KSTAT_DATA_UINT64);
	QEDE_KSTAT_TXQ(txDropPkts,    KSTAT_DATA_UINT64);
	QEDE_KSTAT_TXQ(txBind,    KSTAT_DATA_UINT64);
	QEDE_KSTAT_TXQ(txBindFail,    KSTAT_DATA_UINT64);
	QEDE_KSTAT_TXQ(txPremapped,    KSTAT_DATA_UINT64);
	QEDE_KSTAT_TXQ(txPremappedFail,    KSTAT_DATA_UINT64);
	QEDE_KSTAT_TXQ(txTooManyCookies,    KSTAT_DATA_UINT64);
	QEDE_KSTAT_TXQ(txPullupPkts,    KSTAT_DATA_UINT64);
	QEDE_KSTAT_TXQ(txLsoPkts,    KSTAT_DATA_UINT64);
	QEDE_KSTAT_TXQ(txTooManyMblks,    KSTAT_DATA_UINT64);
	QEDE_KSTAT_TXQ(txMappedPkts,    KSTAT_DATA_UINT64);
	QEDE_KSTAT_TXQ(txJumboPkts,    KSTAT_DATA_UINT64);
	QEDE_KSTAT_TXQ(txRingTotalPkts,      KSTAT_DATA_UINT64);
	QEDE_KSTAT_TXQ(txRingTotalBytes,      KSTAT_DATA_UINT64);

	qede->kstats_txq_map[idx].idx = idx;
	qede->kstats_txq_map[idx].qede = qede;

	qede->kstats_txq[idx]->ks_update  = qede_kstat_txq_update;
	qede->kstats_txq[idx]->ks_private = (void *)&qede->kstats_txq_map[idx];

	kstat_install(qede->kstats_txq[idx]);

	return (B_TRUE);

}

boolean_t 
qede_kstat_init(qede_t *qede)
{
	qede_kstat_t *pStats;
	qede_kstat_link_t *pStatsLink;
	qede_kstat_intr_t *pStatsIntr;
	qede_kstat_vport_stats_t *pStatsVport;
	int i;

#define QEDE_KSTAT(f, t)            kstat_named_init(&pStats->f, #f, t)
#define QEDE_KSTAT_LINK(f, t)       kstat_named_init(&pStatsLink->f, #f, t)
#define QEDE_KSTAT_INTR(f, t)       kstat_named_init(&pStatsIntr->f, #f, t)
#define QEDE_KSTAT_VPORT(f,t)	    kstat_named_init(&pStatsVport->f, #f, t)


	if ((qede->kstats = kstat_create("qede",
	    qede->instance,
	    "stats",
	    "net",
	    KSTAT_TYPE_NAMED,
	    QEDE_KSTAT_SIZE,
	    0)) == NULL) {
        	/*QedeLogWarn(qede, "Failed to create kstat");*/
		cmn_err(CE_WARN, "Failed to create kstat");
        	return (B_FALSE);
	}

	pStats = (qede_kstat_t *)qede->kstats->ks_data;
	QEDE_KSTAT(qede_hi, KSTAT_DATA_CHAR);
	QEDE_KSTAT(qede_lo, KSTAT_DATA_CHAR);
	QEDE_KSTAT(version, KSTAT_DATA_CHAR);
	QEDE_KSTAT(versionFW, KSTAT_DATA_CHAR);
	QEDE_KSTAT(versionMFW, KSTAT_DATA_CHAR);
	QEDE_KSTAT(chipID, KSTAT_DATA_CHAR);
	QEDE_KSTAT(chipName, KSTAT_DATA_CHAR);
	QEDE_KSTAT(devBDF, KSTAT_DATA_CHAR);
	QEDE_KSTAT(devID, KSTAT_DATA_CHAR);
	QEDE_KSTAT(multiFunction, KSTAT_DATA_CHAR);
	QEDE_KSTAT(multiFunctionVnics, KSTAT_DATA_UINT64);
	QEDE_KSTAT(macAddr, KSTAT_DATA_CHAR);
	QEDE_KSTAT(hwInitDone, KSTAT_DATA_UINT64);
	QEDE_KSTAT(numVports, KSTAT_DATA_UINT64);
	QEDE_KSTAT(vportID, KSTAT_DATA_UINT64);
	QEDE_KSTAT(intrAlloc, KSTAT_DATA_CHAR);
	QEDE_KSTAT(intrFired, KSTAT_DATA_UINT64);
	QEDE_KSTAT(lroEnabled, KSTAT_DATA_UINT64);
	QEDE_KSTAT(lsoEnabled, KSTAT_DATA_UINT64);
	QEDE_KSTAT(jumboEnabled, KSTAT_DATA_UINT64);
	QEDE_KSTAT(txTotalPkts, KSTAT_DATA_UINT64);
	QEDE_KSTAT(txTotalBytes, KSTAT_DATA_UINT64);
	QEDE_KSTAT(txTotalDiscards, KSTAT_DATA_UINT64);
	QEDE_KSTAT(rxTotalPkts, KSTAT_DATA_UINT64);
	QEDE_KSTAT(rxTotalBytes, KSTAT_DATA_UINT64);
	QEDE_KSTAT(rxTotalDiscards, KSTAT_DATA_UINT64);
	QEDE_KSTAT(allocbFailures, KSTAT_DATA_UINT64);

	qede->kstats->ks_update  = qede_kstat_update;
	qede->kstats->ks_private = (void *)qede;

	kstat_install(qede->kstats);

	/****************************************************************/
	if ((qede->kstats_link = kstat_create("qede",
	    qede->instance,
	    "link",
	    "net",
	    KSTAT_TYPE_NAMED,
	    QEDE_KSTAT_LINK_SIZE,
	    0)) == NULL) {
        	/*BnxeLogWarn(qede, "Failed to create link kstat");*/
		cmn_err(CE_WARN, "Failed to create link kstat");
		qede_kstat_fini(qede);
        	return (B_FALSE);
	}

	pStatsLink = (qede_kstat_link_t *)qede->kstats_link->ks_data;

	QEDE_KSTAT_LINK(vportID, KSTAT_DATA_UINT64);
	QEDE_KSTAT_LINK(uptime,  KSTAT_DATA_UINT64);
	QEDE_KSTAT_LINK(mtuL2,   KSTAT_DATA_UINT64);
	QEDE_KSTAT_LINK(speed,   KSTAT_DATA_UINT64);
	QEDE_KSTAT_LINK(link,    KSTAT_DATA_UINT64);
	QEDE_KSTAT_LINK(duplex,  KSTAT_DATA_UINT64);
	QEDE_KSTAT_LINK(pauseRx, KSTAT_DATA_UINT64);
	QEDE_KSTAT_LINK(pauseTx, KSTAT_DATA_UINT64);

	qede->kstats_link->ks_update  = qede_kstat_link_update;
	qede->kstats_link->ks_private = (void *)qede;

	kstat_install(qede->kstats_link);

	/****************************************************************/

        if ((qede->kstats_intr = kstat_create("qede",
	    qede->instance,
	    "intr",
	    "net",
	    KSTAT_TYPE_NAMED,
	    QEDE_KSTAT_INTR_SIZE,
	    0)) == NULL) {
        	/*BnxeLogWarn(qede, "Failed to create intr kstat");*/
		cmn_err(CE_WARN, "Failed to create intr kstat");
		qede_kstat_fini(qede);
        	return (B_FALSE);
	}


	pStatsIntr = (qede_kstat_intr_t *)qede->kstats_intr->ks_data;

	QEDE_KSTAT_INTR(intrAlloc,      KSTAT_DATA_CHAR);
	QEDE_KSTAT_INTR(intrFired,      KSTAT_DATA_UINT64);
	QEDE_KSTAT_INTR(sb_00,          KSTAT_DATA_UINT64);
	QEDE_KSTAT_INTR(sb_01,          KSTAT_DATA_UINT64);
	QEDE_KSTAT_INTR(sb_02,          KSTAT_DATA_UINT64);
	QEDE_KSTAT_INTR(sb_03,          KSTAT_DATA_UINT64);
	QEDE_KSTAT_INTR(sb_04,          KSTAT_DATA_UINT64);
	QEDE_KSTAT_INTR(sb_05,          KSTAT_DATA_UINT64);
	QEDE_KSTAT_INTR(sb_06,          KSTAT_DATA_UINT64);
	QEDE_KSTAT_INTR(sb_nc_00,       KSTAT_DATA_UINT64);
	QEDE_KSTAT_INTR(sb_nc_01,       KSTAT_DATA_UINT64);
	QEDE_KSTAT_INTR(sb_nc_02,       KSTAT_DATA_UINT64);
	QEDE_KSTAT_INTR(sb_nc_03,       KSTAT_DATA_UINT64);
	QEDE_KSTAT_INTR(sb_nc_04,       KSTAT_DATA_UINT64);
	QEDE_KSTAT_INTR(sb_nc_05,       KSTAT_DATA_UINT64);
	QEDE_KSTAT_INTR(sb_nc_06,       KSTAT_DATA_UINT64);
	QEDE_KSTAT_INTR(sb_poll_00,     KSTAT_DATA_UINT64);
	QEDE_KSTAT_INTR(sb_poll_01,     KSTAT_DATA_UINT64);
    	QEDE_KSTAT_INTR(sb_poll_02,     KSTAT_DATA_UINT64);
	QEDE_KSTAT_INTR(sb_poll_03,     KSTAT_DATA_UINT64);
	QEDE_KSTAT_INTR(sb_poll_04,     KSTAT_DATA_UINT64);
    	QEDE_KSTAT_INTR(sb_poll_05,     KSTAT_DATA_UINT64);
    	QEDE_KSTAT_INTR(sb_poll_06,     KSTAT_DATA_UINT64);
	QEDE_KSTAT_INTR(sb_poll_nc_00,  KSTAT_DATA_UINT64);
    	QEDE_KSTAT_INTR(sb_poll_nc_01,  KSTAT_DATA_UINT64);
    	QEDE_KSTAT_INTR(sb_poll_nc_02,  KSTAT_DATA_UINT64);
    	QEDE_KSTAT_INTR(sb_poll_nc_03,  KSTAT_DATA_UINT64);
    	QEDE_KSTAT_INTR(sb_poll_nc_04,  KSTAT_DATA_UINT64);
    	QEDE_KSTAT_INTR(sb_poll_nc_05,  KSTAT_DATA_UINT64);
    	QEDE_KSTAT_INTR(sb_poll_nc_06,  KSTAT_DATA_UINT64);

	qede->kstats_intr->ks_update  = qede_kstat_intr_update;
    	qede->kstats_intr->ks_private = (void *)qede;

    	kstat_install(qede->kstats_intr);


/****************************************************************/

    	if ((qede->kstats_vport = kstat_create("qede",
	    qede->instance,
	    "L2Stats",
	    "net",
	    KSTAT_TYPE_NAMED,
	    QEDE_KSTAT_VPORT_STATS_SIZE,
	    0)) == NULL) {
        	/*BnxeLogWarn(qede, "Failed to create l2chip kstat");*/
		cmn_err(CE_WARN, "Failed to create L2Stats kstat");
		qede_kstat_fini(qede);
        	return (B_FALSE);
	}

	pStatsVport = (qede_kstat_vport_stats_t *)qede->kstats_vport->ks_data;

    	QEDE_KSTAT_VPORT(rxUcastBytes, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(rxMcastBytes, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(rxBcastBytes, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(rxUcastPkts, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(rxMcastPkts, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(rxBcastPkts, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(txUcastBytes, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(txMcastBytes, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(txBcastBytes, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(txUcastPkts, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(txMcastPkts, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(txBcastPkts, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(rx64bytePkts, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(rx127bytePkts, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(rx255bytePkts, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(rx511bytePkts, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(rx1023bytePkts, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(rx1518bytePkts, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(rx1518bytePkts, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(rx1522bytePkts, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(rx2047bytePkts, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(rx4095bytePkts, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(rx9216bytePkts, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(rx16383bytePkts, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(tx64bytePkts, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(tx64to127bytePkts, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(tx128to255bytePkts, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(tx256to511bytePkts, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(tx512to1023bytePkts, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(tx1024to1518bytePkts, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(tx1519to2047bytePkts, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(tx2048to4095bytePkts, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(tx4096to9216bytePkts, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(tx9217to16383bytePkts, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(rxMacCtrlFrames, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(rxPauseFrames, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(txPauseFrames, KSTAT_DATA_UINT64);
	QEDE_KSTAT_VPORT(rxCRCerrors, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(rxAlignErrors, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(rxCarrierErrors, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(rxOversizeErrors, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(rxJabbers, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(rxUndersizePkts, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(rxFragments, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(txLpiEntryCnt, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(txTotalCollisions, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(brbTruncates, KSTAT_DATA_UINT64);

    	QEDE_KSTAT_VPORT(noBuffDiscards, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(mftagFilterDiscards, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(macFilterDiscards, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(txErrDropPkts, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(coalescedPkts, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(coalescedEvents, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(coalescedAbortsNum, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(nonCoalescedPkts, KSTAT_DATA_UINT64);
    	QEDE_KSTAT_VPORT(coalescedBytes, KSTAT_DATA_UINT64);

    	qede->kstats_vport->ks_update  = qede_kstat_vport_stats_update;
    	qede->kstats_vport->ks_private = (void *)qede;

    	kstat_install(qede->kstats_vport);
    	for (i = 0; i < qede->num_fp; i++) {
		if(!qede_kstat_init_rxq(qede,i))
		{
			qede_kstat_fini(qede);
			return (B_FALSE);
		}
		if(!qede_kstat_init_txq(qede,i))
		{
			qede_kstat_fini(qede);
			return (B_FALSE);
		}
	
	}

	return (B_TRUE);

}

void 
qede_kstat_fini(qede_t *qede)
{
	int i;

	if(qede->kstats) {
		kstat_delete(qede->kstats);
		qede->kstats = NULL;
	}
	if(qede->kstats_link) {
		kstat_delete(qede->kstats_link);
		qede->kstats_link = NULL;
	}
	if(qede->kstats_intr) {
		kstat_delete(qede->kstats_intr);
		qede->kstats_intr = NULL;
	}
	if(qede->kstats_vport) {
		kstat_delete(qede->kstats_vport);
		qede->kstats_vport = NULL;
	}


	for (i = 0; i < qede->num_fp; i++) {
		if(qede->kstats_rxq[i]) {
			kstat_delete(qede->kstats_rxq[i]);
			qede->kstats_rxq[i] = NULL;
		}
		qede->kstats_rxq_map[i].idx = 0;
		qede->kstats_rxq_map[i].qede = NULL;
		if(qede->kstats_txq[i]) {
			kstat_delete(qede->kstats_txq[i]);
			qede->kstats_txq[i] = NULL;
		}
		qede->kstats_txq_map[i].idx = 0;
		qede->kstats_txq_map[i].qede = NULL;
	}
}
