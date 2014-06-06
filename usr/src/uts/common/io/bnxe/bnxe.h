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
 * Copyright 2014 QLogic Corporation
 * The contents of this file are subject to the terms of the
 * QLogic End User License (the "License").
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at
 * http://www.qlogic.com/Resources/Documents/DriverDownloadHelp/
 * QLogic_End_User_Software_License.txt
 * See the License for the specific language governing permissions
 * and limitations under the License.
 */

/*
 * Copyright (c) 2002, 2011, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef BNXE_H
#define BNXE_H

#include <sys/types.h>
#include <sys/stream.h>
#include <sys/stropts.h>
#include <sys/errno.h>
#include <sys/cred.h>
#include <sys/poll.h>
#include <sys/modctl.h>
#include <sys/mac.h>
#include <sys/mac_provider.h>
#include <sys/stat.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/sunndi.h>
#include <sys/ddifm.h>
#include <sys/fm/protocol.h>
#include <sys/fm/util.h>
#include <sys/fm/io/ddi.h>
#include <sys/pattr.h>
#include <sys/sysmacros.h>
#include <sys/ethernet.h>
//#include <sys/vlan.h>
#include <sys/strsun.h>
#include <sys/ksynch.h>
#include <sys/kstat.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/tcp.h>
#include <inet/common.h>
#include <inet/ip.h>
#include <inet/ip_if.h>
#include <sys/strsubr.h>
#include <sys/pci.h>
#include <sys/gld.h>

/*
 * This really ticks me off!  We use 'u' for naming unions
 * within structures.  Why is 'u' a reserved word!?!?!?
 * http://bugs.opensolaris.org/view_bug.do?bug_id=4340073
 * This undef has been moved to bnxe_debug.h.
 */
//#undef u

#include "version.h"
#include "debug.h"
#include "bcmtype.h"
#include "lm_defs.h"
#include "listq.h"
#include "lm5710.h"
#include "lm.h"
#include "bd_chain.h"
#if !defined(__SunOS_MDB)
#include "command.h"
#endif
#include "bnxe_binding.h"
#if !defined(DBG) && !defined(__SunOS_MDB)
#include "bnxe_debug.h" /* wasn't included by debug.h */
#endif

#ifndef VLAN_TAGSZ
#define VLAN_TAGSZ 4
#endif

#define BNXE_RINGS
#define RSS_ID_NONE -1

#define USER_OPTION_CKSUM_NONE     0x0
#define USER_OPTION_CKSUM_L3       0x1
#define USER_OPTION_CKSUM_L3_L4    0x2
#define USER_OPTION_CKSUM_DEFAULT  USER_OPTION_CKSUM_L3_L4

#define USER_OPTION_MTU_MIN      60
#define USER_OPTION_MTU_MAX      9216
#define USER_OPTION_MTU_DEFAULT  1500

#define USER_OPTION_NUM_RINGS_MIN         0
#define USER_OPTION_NUM_RINGS_MAX         MAX_RSS_CHAINS
#define USER_OPTION_NUM_RINGS_DEFAULT_MF  1
#define USER_OPTION_NUM_RINGS_DEFAULT_SF  4
#define USER_OPTION_NUM_RINGS_DEFAULT     0

#define USER_OPTION_RX_RING_GROUPS_MIN      1
#define USER_OPTION_RX_RING_GROUPS_MAX      1
#define USER_OPTION_RX_RING_GROUPS_DEFAULT  1

#define USER_OPTION_BDS_MIN         1
#define USER_OPTION_BDS_MAX         32767
#define USER_OPTION_RX_BDS_DEFAULT  1024
#define USER_OPTION_TX_BDS_DEFAULT  1024
#define USER_OPTION_MF_BDS_DIVISOR  4

#define USER_OPTION_INTR_COALESCE_MIN         10    /* usecs */
#define USER_OPTION_INTR_COALESCE_MAX         1000
#define USER_OPTION_INTR_COALESCE_RX_DEFAULT  20
#define USER_OPTION_INTR_COALESCE_TX_DEFAULT  40

#define USER_OPTION_TX_MAX_FREE_DEFAULT  32
#define USER_OPTION_RX_MAX_FREE_DEFAULT  32

//#define USER_OPTION_RX_DCOPY_THRESH_DEFAULT  0xffffffff
#define USER_OPTION_RX_DCOPY_THRESH_DEFAULT  128

//#define USER_OPTION_TX_DCOPY_THRESH_DEFAULT  0
#define USER_OPTION_TX_DCOPY_THRESH_DEFAULT  512

//#define BNXE_IP_MAXLEN   65535
#define BNXE_IP_MAXLEN   32768 /* 32768 = PAGESIZE * (BNXE_MAX_DMA_FRAGS_PER_PKT - 2 ) */
#define BNXE_OPTION_LEN  80    /* room for IP/TCP options (max 40 bytes each) */
#define BNXE_PKTHDR_LEN  (sizeof(struct ether_vlan_header) + sizeof(struct ip) + sizeof(struct tcphdr) + BNXE_OPTION_LEN)
#define BNXE_LSO_MAXLEN  (BNXE_IP_MAXLEN + sizeof(struct ether_vlan_header) - BNXE_PKTHDR_LEN) /* maximum payload */

#define BNXE_MAGIC          0x0feedead
#define BNXE_MEM_CHECK_LEN  16
#define BNXE_STR_SIZE       32

#define BNXEF_NAME "bnxef"

#define BNXE_FCOE(dev) ((um_device_t *)(dev))->do_fcoe

#ifdef __sparc
#define BNXE_DMA_ALIGNMENT  0x2000UL
#else
#define BNXE_DMA_ALIGNMENT  0x1000UL
#endif

/*
 * Adding a two byte offset to the receive buffer aligns the IP header on a
 * 16 byte boundary and it would put the TCP payload (assuming a 20 byte IP
 * header and 20 byte TCP header) on an 8 byte boundary.
 */
#define BNXE_DMA_RX_OFFSET 2

/*
 * The following two defines are used for defining limits on Tx packets.
 * BNXE_MAX_DMA_HANDLES_PER_PKT is the maximum number of DMA handles that are
 * pre-allocated for every Tx buffer descriptor.  These DMA handles are used
 * for mapping each mblk in the chain when not double copying the packet data
 * into the copy buffer.  BNXE_MAX_DMA_FRAGS_PER_PKT is based on the hardware
 * and represents the maximum number of fragments an outgoing packet can have.
 * Note that a single DMA handle can be comprised of multiple fragments which
 * is very likely with LSO.
 *
 * As seen below BNXE_MAX_DMA_FRAGS_PER_PKT is set to 10.  The actual firmware
 * limit is 13 but 10 is chosen specifically for the case of LSO packets that
 * are broken up across a long mblk chain.  The firmware utilizes a sliding
 * window on a packet's assigned buffer descriptors for LSO.  The window is 10
 * bds and each window (i.e. bds 1-10, 2-11, 3-12, etc), except the window
 * containing the last bd, must contains at least MSS bytes.  There are 'rare'
 * cases where a packet sent down by the stack will not satisfy this window
 * size requirement.  Therefore, setting the frag limit to 10 results in any
 * long chained packet (i.e. greater than 10 mblks), the trailing mblks will
 * get double copied into a single copy buffer and will be pointed to by the
 * last bd.  This simple change will ensure the sliding window requirement is
 * always satisfied.  Note, LSO packets with long mblk chains are a rare
 * occurance (nicdrv test01 can trigger it).
 */
#define BNXE_MAX_DMA_HANDLES_PER_PKT 11 /* go easy on DMA resources */
#define BNXE_MAX_DMA_FRAGS_PER_PKT   10 /* set BNXE_IP_MAXLEN above accordingly */
#define BNXE_MAX_DMA_SGLLEN          20 /* for partial dma mapping */

#define BNXE_PDWM_THRESHOLD  8

#define BNXE_TX_RESOURCES_NO_CREDIT      0x01
#define BNXE_TX_RESOURCES_NO_DESC        0x02
#define BNXE_TX_RESOURCES_NO_DRV_DMA_RES 0x04 /* Out of Tx DMA handles */
#define BNXE_TX_RESOURCES_NO_OS_DMA_RES  0x08 /* Unable to allocate DMA resources. (e.g. bind error) */
#define BNXE_TX_RESOURCES_TOO_MANY_FRAGS 0x10

#define BNXE_TX_GOODXMIT  0
#define BNXE_TX_LINKDOWN  1
#define BNXE_TX_DEFERPKT  2
#define BNXE_TX_HDWRFULL  3
#define BNXE_TX_PKTERROR  4

#define BNXE_ROUTE_RING_NONE     0
#define BNXE_ROUTE_RING_TCPUDP   1
#define BNXE_ROUTE_RING_DEST_MAC 2
#define BNXE_ROUTE_RING_MSG_PRIO 3

#undef BNXE_DEBUG_DMA_LIST

extern ddi_device_acc_attr_t bnxeAccessAttribBAR;
extern ddi_device_acc_attr_t bnxeAccessAttribBUF;

typedef struct _BnxeDevParams
{
    u32_t        fw_ver;

    u32_t        mtu[LM_CLI_IDX_MAX];

    u32_t        routeTxRingPolicy;
    u32_t        numRings;   /* number of rings */
    u32_t        numRxDesc[LM_CLI_IDX_MAX]; /* number of RX descriptors */
    u32_t        numTxDesc[LM_CLI_IDX_MAX]; /* number of TX descriptors */
    u32_t        maxRxFree;  /* max free allowed before posting back */
    u32_t        maxTxFree;  /* max free allowed before posting back */

    boolean_t    intrCoalesce;
    u32_t        intrRxPerSec;
    u32_t        intrTxPerSec;
    boolean_t    disableMsix;

    boolean_t    l2_fw_flow_ctrl;
    boolean_t    autogreeenEnable;

    u32_t        rxCopyThreshold;
    u32_t        txCopyThreshold;

    lm_rx_mask_t rx_filter_mask[LM_CLI_IDX_MAX];

    int          checksum;
    lm_offload_t enabled_oflds;

    boolean_t    lsoEnable;

    boolean_t    logEnable;

    boolean_t    fcoeEnable;

    boolean_t    linkRemoteFaultDetect;

    lm_status_t  lastIndLink;
    lm_medium_t  lastIndMedium;

    uint32_t     debug_level;
} BnxeDevParams;


typedef struct _BnxeLinkCfg
{
    boolean_t link_autoneg;
    boolean_t param_20000fdx;
    boolean_t param_10000fdx;
    boolean_t param_2500fdx;
    boolean_t param_1000fdx;
    boolean_t param_100fdx;
    boolean_t param_100hdx;
    boolean_t param_10fdx;
    boolean_t param_10hdx;
    boolean_t param_txpause;
    boolean_t param_rxpause;
} BnxeLinkCfg;


typedef struct _BnxePhyCfg
{
    BnxeLinkCfg lnkcfg;
    boolean_t   flow_autoneg;
    u32_t       supported[ELINK_LINK_CONFIG_SIZE];
    u32_t       phy_cfg_size;
} BnxePhyCfg;


typedef struct _BnxeProps
{
    u32_t             link_speed;
    boolean_t         link_duplex;
    boolean_t         link_txpause;
    boolean_t         link_rxpause;
    time_t            uptime;
} BnxeProps;


typedef struct _BnxeMemBlock
{
    d_list_entry_t link;
    u32_t          size;
    void *         pBuf;
    char           fileName[128];
    u32_t          fileLine;
} BnxeMemBlock;


typedef struct _BnxeMemDma
{
    d_list_entry_t   link;
    u32_t            size;
    void *           pDmaVirt;
    ddi_dma_handle_t dmaHandle;
    ddi_acc_handle_t dmaAccHandle;
    lm_address_t     physAddr;
    char             fileName[128];
    u32_t            fileLine;
} BnxeMemDma;


typedef struct _BnxeMemRegion
{
    d_list_entry_t   link;
    lm_address_t     baseAddr;
    u32_t            regNumber;
    offset_t         offset;
    u32_t            size;
    ddi_acc_handle_t regAccess;
    caddr_t          pRegAddr;
} BnxeMemRegion;


typedef struct _um_txpacket_t
{
    lm_packet_t      lm_pkt; /* must be the first entry */
    lm_pkt_tx_info_t tx_info;

    mblk_t *         pMblk;

    ddi_dma_handle_t cbDmaHandle;    /* cb = copy buffer */
    ddi_acc_handle_t cbDmaAccHandle;
    caddr_t          pCbBuf;
    lm_address_t     cbPhysAddr;

    u32_t            cbLength;
    u32_t            num_handles; /* number of handles used for pkt */
    ddi_dma_handle_t dmaHandles[BNXE_MAX_DMA_HANDLES_PER_PKT];

    lm_frag_list_t   frag_list;
    lm_frag_t        frag_list_buffer[BNXE_MAX_DMA_FRAGS_PER_PKT];
} um_txpacket_t;


typedef struct _TxQueue
{
    void *            pUM; /* backpointer to um_device_t */
    u32_t             idx; /* this ring's index */

    mac_ring_handle_t ringHandle;

    u32_t             desc_cnt;     /* number of Tx descriptors */

    u32_t             txFailed;
    u32_t             txDiscards;
    u32_t             txRecycle;
    u32_t             txCopied;
    u32_t             txBlocked;
    u32_t             txWait;
    u32_t             txLowWater;

    u32_t             thresh_pdwm;  /* low resource water marks */

    kmutex_t          txMutex;

    s_list_t          sentTxQ;      /* bds that have been sent and are ready to be freed */

    kmutex_t          freeTxDescMutex;
    s_list_t          freeTxDescQ;  /* bds that are free for use */

    s_list_t          waitTxDescQ;  /* bds that are setup and waiting for tx (lock w/ tx mutex) */

    u32_t             noTxCredits;
} TxQueue;


typedef struct _um_rxpacket_t
{
    lm_packet_t      lm_pkt; /* must be first entry */
    lm_pkt_rx_info_t rx_info;    
    u32_t            hash_value;

    frtn_t           freeRtn;
    void *           pUM; /* backpointer to um_device_t for free routine */
    int              idx; /* chain index used by the free routine */

    u32_t            signature;

    ddi_dma_handle_t dmaHandle;
    ddi_acc_handle_t dmaAccHandle;
} um_rxpacket_t;


typedef struct _RxQueue
{
    void *            pUM; /* backpointer to um_device_t */
    u32_t             idx; /* this ring's index */

    mac_ring_handle_t ringHandle;
    uint64_t          genNumber; /* set by mac and passed up in mac_ring_rx */

    volatile u32_t    inPollMode;
    u8_t              intrDisableCnt;
    u8_t              intrEnableCnt;
    u8_t              pollCnt;

    u32_t             rxDiscards;
    u32_t             rxCopied;
    u32_t             rxLowWater;
    u32_t             rxBufUpInStack;

    kmutex_t          rxMutex;

    kmutex_t          doneRxMutex;
    s_list_t          doneRxQ;  /* free bds that are ready to be posted */

    s_list_t          waitRxQ; /* packet waiting to be sent up */
} RxQueue;


typedef struct _RxQueueGroup
{
    void *             pUM; /* backpointer to um_device_t */
    u32_t              idx; /* this group's index */
    mac_group_handle_t groupHandle;
} RxQueueGroup;


typedef struct _KstatRingMap
{
    u32_t  idx;  /* ring index */
    void * pUM;  /* reference back to um_device_t */
} KstatRingMap;


typedef struct _BnxeFcoeState
{
    lm_fcoe_state_t lm_fcoe;
} BnxeFcoeState;


typedef struct _BnxeClientStats
{
    u32_t initWqeTx;
    u32_t initWqeTxErr;
    u32_t initCqeRx;
    u32_t initCqeRxErr;
    u32_t offloadConnWqeTx;
    u32_t offloadConnWqeTxErr;
    u32_t offloadConnCqeRx;
    u32_t offloadConnCqeRxErr;
    u32_t enableConnWqeTx;
    u32_t enableConnWqeTxErr;
    u32_t enableConnCqeRx;
    u32_t enableConnCqeRxErr;
    u32_t disableConnWqeTx;
    u32_t disableConnWqeTxErr;
    u32_t disableConnCqeRx;
    u32_t disableConnCqeRxErr;
    u32_t destroyConnWqeTx;
    u32_t destroyConnWqeTxErr;
    u32_t destroyConnCqeRx;
    u32_t destroyConnCqeRxErr;
    u32_t destroyWqeTx;
    u32_t destroyWqeTxErr;
    u32_t destroyCqeRx;
    u32_t destroyCqeRxErr;
    u32_t compRequestCqeRx;
    u32_t compRequestCqeRxErr;
    u32_t statWqeTx;
    u32_t statWqeTxErr;
    u32_t statCqeRx;
    u32_t statCqeRxErr;
} BnxeClientStats;


typedef struct _BnxeFcoeData
{
    dev_info_t *    pDev;
    BnxeBinding     bind;
    BnxeClientStats stats;
    BnxeWwnInfo     wwn;
} BnxeFcoeData;


typedef struct _BnxeIntrBlock
{
    int                 intrCount;
    int                 intrCapability;
    u32_t               intrPriority;
    u32_t               intrHandleBlockSize;
    ddi_intr_handle_t * pIntrHandleBlockAlloc;
    ddi_intr_handle_t * pIntrHandleBlock;
} BnxeIntrBlock;


typedef struct _BnxeWorkQueueInstance
{
    void *        pUM;

    char          taskqName[BNXE_STR_SIZE];
    ddi_taskq_t * pTaskq;
    kmutex_t      workQueueMutex;
    s_list_t      workQueue;

    u32_t         workItemQueued;
    u32_t         workItemError;
    u32_t         workItemComplete;
    u32_t         highWater;
} BnxeWorkQueueInstance;


typedef struct _BnxeWorkQueues
{
    BnxeWorkQueueInstance instq;  /* instant, single thread serialized */
    BnxeWorkQueueInstance delayq; /* delayed, multi thread not serialized */
} BnxeWorkQueues;


/* the following are used against the clientState variable in um_device_t */

#define CLIENT_FLG_DEVI  0x001
#define CLIENT_FLG_BIND  0x002
#define CLIENT_FLG_HW    0x004

#define CLIENT_DEVI(pUM, client) \
    ((pUM)->clientState[(client)] & CLIENT_FLG_DEVI)

#define CLIENT_HW(pUM, client) \
    ((pUM)->clientState[(client)] & CLIENT_FLG_HW)

#define CLIENT_BOUND(pUM, client) \
    (((client) == LM_CLI_IDX_NDIS)                      ? \
         ((pUM)->clientState[(client)] & CLIENT_FLG_HW) : \
         ((pUM)->clientState[(client)] & CLIENT_FLG_BIND))

#define CLIENT_DEVI_SET(pUM, client) \
    ((pUM)->clientState[(client)] |= CLIENT_FLG_DEVI)

#define CLIENT_DEVI_RESET(pUM, client) \
    ((pUM)->clientState[(client)] &= ~CLIENT_FLG_DEVI)

#define CLIENT_BIND_SET(pUM, client) \
    ((pUM)->clientState[(client)] |= CLIENT_FLG_BIND)

#define CLIENT_BIND_RESET(pUM, client) \
    ((pUM)->clientState[(client)] &= ~CLIENT_FLG_BIND)

#define CLIENT_HW_SET(pUM, client) \
    ((pUM)->clientState[(client)] |= CLIENT_FLG_HW)

#define CLIENT_HW_RESET(pUM, client) \
    ((pUM)->clientState[(client)] &= ~CLIENT_FLG_HW)


typedef struct _um_device
{
    lm_device_t           lm_dev;  /* must be the first element */

    u32_t                 magic;
    dev_info_t *          pDev;

    u32_t                 hwInitDone;
    u32_t                 chipStarted;
    u32_t                 clientState[LM_CLI_IDX_MAX];

    d_list_t              memBlockList;
    d_list_t              memDmaList;
    d_list_t              memRegionList;
#ifdef BNXE_DEBUG_DMA_LIST
    d_list_t              memDmaListSaved;
#endif

    int                   instance;
    char                  devName[BNXE_STR_SIZE];
    char                  version[BNXE_STR_SIZE];
    char                  versionLM[BNXE_STR_SIZE];
    char                  versionFW[BNXE_STR_SIZE];
    char                  versionBC[BNXE_STR_SIZE];
    char                  chipName[BNXE_STR_SIZE];
    char                  chipID[BNXE_STR_SIZE];
    char                  intrAlloc[BNXE_STR_SIZE];
    char                  bus_dev_func[BNXE_STR_SIZE];
    char                  vendor_device[BNXE_STR_SIZE];

    volatile u32_t        plumbed;

    ddi_acc_handle_t      pPciCfg;

    kmutex_t              intrMutex[MAX_RSS_CHAINS + 1];
    kmutex_t              intrFlipMutex[MAX_RSS_CHAINS + 1];
    kmutex_t              sbMutex[MAX_RSS_CHAINS + 1];
    kmutex_t              ethConMutex;
    kmutex_t              mcpMutex;
    kmutex_t              phyMutex;
    kmutex_t              indMutex;
    kmutex_t              cidMutex;
    kmutex_t              spqMutex;   /* slow path queue lock */
    kmutex_t              spReqMutex; /* slow path request manager lock */
    kmutex_t              rrReqMutex; /* ramrod request */
    kmutex_t              islesCtrlMutex;
    kmutex_t              toeMutex;
    kmutex_t              memMutex;
    kmutex_t              offloadMutex;
    kmutex_t              hwInitMutex;
    kmutex_t              gldMutex;
    krwlock_t             gldTxMutex;

    kmutex_t              timerMutex;
    volatile u32_t        timerEnabled;
    timeout_id_t          timerID;

    BnxeWorkQueues        workqs;

    BnxeMemDma *          statusBlocks[MAX_RSS_CHAINS + 1];
    volatile u32_t        intrEnabled;
    u64_t                 intrFired;
                          /* the arrays below = LM_SB_CNT() + 1 = 17 */
    u64_t                 intrSbCnt[MAX_RSS_CHAINS + 1];
    u64_t                 intrSbNoChangeCnt[MAX_RSS_CHAINS + 1];
    u64_t                 intrSbPollCnt[MAX_RSS_CHAINS + 1];
    u64_t                 intrSbPollNoChangeCnt[MAX_RSS_CHAINS + 1];

    int                   intrType;
    u32_t                 intrPriority;
    BnxeIntrBlock         defIntr;
    BnxeIntrBlock         rssIntr;
    BnxeIntrBlock         fcoeIntr;

    BnxeDevParams         devParams;
    mac_handle_t          pMac;
    mac_resource_handle_t macRxResourceHandles[MAX_ETH_REG_CONS];
    u8_t                  gldMac[ETHERNET_ADDRESS_SIZE];

    d_list_t              mcast_l2;
    d_list_t              mcast_fcoe;

    u32_t                 ucastTableLen; /* number of ucast addrs in the table */
#ifndef LM_MAX_UC_TABLE_SIZE
#define LM_MAX_UC_TABLE_SIZE 1 /* for now, fix needed to support multiple ucast addr */
#endif

    TxQueue               txq[MAX_ETH_CONS];
    RxQueue               rxq[MAX_ETH_CONS];
    RxQueueGroup          rxqGroup[USER_OPTION_RX_RING_GROUPS_MAX];
    u32_t                 rxBufSignature[LM_CLI_IDX_MAX];
    u32_t                 txMsgPullUp;

    BnxeProps             props;
    BnxePhyCfg            hwinit; /* gathered by BnxeCfgInit */
    BnxePhyCfg            curcfg; /* initialized from hwinit by BnxeCfgReset */
    BnxeLinkCfg           remote;
    u32_t                 phyInitialized;

    kstat_t *             kstats;
    kstat_t *             kstatsLink;
    kstat_t *             kstatsIntr;
    kstat_t *             kstatsL2Chip;
    kstat_t *             kstatsL2Driver;
    kstat_t *             kstatsL2Stats;
    kstat_t *             kstatsFcoe;
    kstat_t *             kstatsDcbx;
    kstat_t *             kstats_rxq[MAX_ETH_CONS];
    KstatRingMap          kstats_rxq_map[MAX_ETH_CONS];
    kstat_t *             kstats_txq[MAX_ETH_CONS];
    KstatRingMap          kstats_txq_map[MAX_ETH_CONS];
    kmutex_t              kstatMutex;

    int                   fmCapabilities; /* FMA capabilities */

    boolean_t              do_fcoe;
    BnxeFcoeData           fcoe;
    iscsi_info_block_hdr_t iscsiInfo;

} um_device_t;


/* mioc[ack|nak] return values from ioctl subroutines */
enum ioc_reply
{
    IOC_INVAL = -1,   /* bad, NAK with EINVAL */
    IOC_DONE,         /* OK, reply sent       */
    IOC_ACK,          /* OK, just send ACK    */
    IOC_REPLY,        /* OK, just send reply  */
    IOC_RESTART_ACK,  /* OK, restart & ACK    */
    IOC_RESTART_REPLY /* OK, restart & reply  */
};


#define BNXE_IOC_BASE ('X' << 8)
/* IOCTLs for get/set lldp and dcbx params */
#define GIOCBNXELLDP  (BNXE_IOC_BASE + 0)
#define GIOCBNXEDCBX  (BNXE_IOC_BASE + 1)
#define SIOCBNXEDCBX  (BNXE_IOC_BASE + 2)
/* IOCTLs for edebug and firmware upgrade */
#define GIOCBNXEREG   (BNXE_IOC_BASE + 3)
#define SIOCBNXEREG   (BNXE_IOC_BASE + 4)
#define GIOCBNXENVRM  (BNXE_IOC_BASE + 5)
#define SIOCBNXENVRM  (BNXE_IOC_BASE + 6)
#define GIOCBNXEPCI   (BNXE_IOC_BASE + 7)
#define GIOCBNXESTATS (BNXE_IOC_BASE + 8)

struct bnxe_reg_data
{
    u32_t offset;
    u32_t value;
};

struct bnxe_nvram_data
{
    u32_t offset;
    u32_t num_of_u32;
    u32_t value[1]; /* variable */
};


/* bnxe_cfg.c */
void BnxeCfgInit(um_device_t * pUM);
void BnxeCfgReset(um_device_t * pUM);

/* bnxe_mm.c */
void BnxeInitBdCnts(um_device_t * pUM,
                    int           cli_idx);

/* bnxe_gld.c */
boolean_t BnxeGldInit(um_device_t * pUM);
boolean_t BnxeGldFini(um_device_t * pUM);
void      BnxeGldLink(um_device_t * pUM,
                      link_state_t  state);

/* bnxe_hw.c */
boolean_t BnxeEstablishHwConn(um_device_t * pUM,
                              int           cid);
int       BnxeHwStartFCOE(um_device_t * pUM);
int       BnxeHwStartL2(um_device_t * pUM);
int       BnxeHwStartCore(um_device_t * pUM);
void      BnxeHwStopFCOE(um_device_t * pUM);
void      BnxeHwStopL2(um_device_t * pUM);
void      BnxeHwStopCore(um_device_t * pUM);
void      BnxeUpdatePhy(um_device_t * pUM);
int       BnxeMacAddress(um_device_t *   pUM,
                         int             cliIdx,
                         boolean_t       flag,
                         const uint8_t * pMacAddr);
int       BnxeMulticast(um_device_t *   pUM,
                        int             cliIdx,
                        boolean_t       flag,
                        const uint8_t * pMcastAddr,
                        boolean_t       hwSet);
int       BnxeRxMask(um_device_t * pUM,
                     int           cliIdx,
                     lm_rx_mask_t  mask);
int       BnxeHwResume(um_device_t * pUM);
int       BnxeHwSuspend(um_device_t * pUM);
#if (DEVO_REV > 3)
int       BnxeHwQuiesce(um_device_t * pUM);
#endif

/* bnxe_intr.c */
void      BnxeIntrIguSbEnable(um_device_t * pUM,
                              u32_t         idx,
                              boolean_t     fromISR);
void      BnxeIntrIguSbDisable(um_device_t * pUM,
                               u32_t         idx,
                               boolean_t     fromISR);
void      BnxePollRxRing(um_device_t * pUM,
                         u32_t         idx,
                         boolean_t *   pPktsRxed,
                         boolean_t *   pPktsTxed);
void      BnxePollRxRingFCOE(um_device_t * pUM);
int       BnxeIntrEnable(um_device_t * pUM);
void      BnxeIntrDisable(um_device_t * pUM);
boolean_t BnxeIntrInit(um_device_t * pUM);
void      BnxeIntrFini(um_device_t * pUM);

/* bnxe_kstat.c */
boolean_t BnxeKstatInit(um_device_t * pUM);
void      BnxeKstatFini(um_device_t * pUM);

/* bnxe_rr.c */
int BnxeRouteTxRing(um_device_t * pUM,
                    mblk_t *      pMblk);

/* bnxe_rx.c */
boolean_t BnxeWaitForPacketsFromClient(um_device_t * pUM,
                                      int            cliIdx);
mblk_t *  BnxeRxRingProcess(um_device_t * pUM,
                            int           idx,
                            boolean_t     polling,
                            int           numBytes);
void      BnxeRxPktsAbort(um_device_t * pUM,
                          int           cliIdx);
int       BnxeRxPktsInitPostBuffers(um_device_t * pUM,
                                    int           cliIdx);
int       BnxeRxPktsInit(um_device_t * pUM,
                         int           cliIdx);
void      BnxeRxPktsFini(um_device_t * pUM,
                         int           cliIdx);

/* bnxe_tx.c */
void BnxeTxPktsReclaim(um_device_t * pUM,
                       int           idx,
                       s_list_t *    pPktList);
void BnxeTxRingProcess(um_device_t * pUM,
                       int           idx);
int  BnxeTxSendMblk(um_device_t * pUM,
                    int           idx,
                    mblk_t *      pMblk,
                    u32_t         flags,
                    u16_t         vlan_tag);
void BnxeTxPktsAbort(um_device_t * pUM,
                     int           cliIdx);
int  BnxeTxPktsInit(um_device_t * pUM,
                    int           cliIdx);
void BnxeTxPktsFini(um_device_t * pUM,
                    int           cliIdx);

/* bnxe_timer.c */
void BnxeTimerStart(um_device_t * pUM);
void BnxeTimerStop(um_device_t * pUM);

/* bnxe_workq.c */
boolean_t BnxeWorkQueueInit(um_device_t * pUM);
void      BnxeWorkQueueWaitAndDestroy(um_device_t * pUM);
void      BnxeWorkQueueStartPending(um_device_t * pUM);
boolean_t BnxeWorkQueueAdd(um_device_t * pUM,
                           void (*pWorkCbk)(um_device_t *, void *, u32_t),
                           void * pWorkData,
                           u32_t  workDataLen);
boolean_t BnxeWorkQueueAddNoCopy(um_device_t * pUM,
                                 void (*pWorkCbk)(um_device_t *, void *),
                                 void * pWorkData);
boolean_t BnxeWorkQueueAddGeneric(um_device_t * pUM,
                                  void (*pWorkCbkGeneric)(um_device_t *));
boolean_t BnxeWorkQueueAddDelay(um_device_t * pUM,
                                void (*pWorkCbk)(um_device_t *, void *, u32_t),
                                void * pWorkData,
                                u32_t  workDataLen,
                                u32_t  delayMs);
boolean_t BnxeWorkQueueAddDelayNoCopy(um_device_t * pUM,
                                      void (*pWorkCbk)(um_device_t *, void *),
                                      void * pWorkData,
                                      u32_t  delayMs);
boolean_t BnxeWorkQueueAddDelayGeneric(um_device_t * pUM,
                                       void (*pWorkCbkGeneric)(um_device_t *),
                                       u32_t delayMs);

/* bnxe_fcoe.c */
boolean_t BnxeFcoeInitCqe(um_device_t *      pUM,
                          struct fcoe_kcqe * kcqe);
boolean_t BnxeFcoeOffloadConnCqe(um_device_t *      pUM,
                                 BnxeFcoeState *    pFcoeState,
                                 struct fcoe_kcqe * kcqe);
boolean_t BnxeFcoeEnableConnCqe(um_device_t *      pUM,
                                BnxeFcoeState *    pFcoeState,
                                struct fcoe_kcqe * kcqe);
boolean_t BnxeFcoeDisableConnCqe(um_device_t *      pUM,
                                 BnxeFcoeState *    pFcoeState,
                                 struct fcoe_kcqe * kcqe);
boolean_t BnxeFcoeDestroyConnCqe(um_device_t *      pUM,
                                 BnxeFcoeState *    pFcoeState,
                                 struct fcoe_kcqe * kcqe);
boolean_t BnxeFcoeDestroyCqe(um_device_t *      pUM,
                             struct fcoe_kcqe * kcqe);
boolean_t BnxeFcoeStatCqe(um_device_t *      pUM,
                          struct fcoe_kcqe * kcqe);
boolean_t BnxeFcoeCompRequestCqe(um_device_t *      pUM,
                                 struct fcoe_kcqe * kcqes,
                                 u32_t              num_kcqes);
boolean_t BnxeFcoePrvCtl(dev_info_t * pDev,
                         int          cmd,
                         void *       pData,
                         int          dataLen);
mblk_t *  BnxeFcoePrvTx(dev_info_t * pDev,
                        mblk_t *     pMblk,
                        u32_t        flags,
                        u16_t        vlan_tag);
boolean_t BnxeFcoePrvPoll(dev_info_t * pDev);
boolean_t BnxeFcoePrvSendWqes(dev_info_t * pDev,
                              void *       wqes[],
                              int          wqeCnt);
boolean_t BnxeFcoePrvMapMailboxq(dev_info_t *       pDev,
                                 u32_t              cid,
                                 void **            ppMap,
                                 ddi_acc_handle_t * pAccHandle);
boolean_t BnxeFcoePrvUnmapMailboxq(dev_info_t *     pDev,
                                   u32_t            cid,
                                   void *           pMap,
                                   ddi_acc_handle_t accHandle);
int       BnxeFcoeInit(um_device_t * pUM);
int       BnxeFcoeFini(um_device_t * pUM);
void      BnxeFcoeStartStop(um_device_t * pUM);

/* bnxe_main.c */
u8_t      BnxeInstance(void * pDev);
char *    BnxeDevName(void * pDev);
boolean_t BnxeProtoSupport(um_device_t * pUM, int proto);
boolean_t BnxeProtoFcoeAfex(um_device_t * pUM);
int       BnxeCheckAccHandle(ddi_acc_handle_t handle);
int       BnxeCheckDmaHandle(ddi_dma_handle_t handle);
void      BnxeFmErrorReport(um_device_t * pUM, char * detail);

extern kmutex_t bnxeLoaderMutex;
extern u32_t    bnxeNumPlumbed;

extern BnxeLinkCfg bnxeLinkCfg;

/* undefine this to help with dtrace analysis */
#define BNXE_LOCKS_INLINE

#ifdef BNXE_LOCKS_INLINE

#define BNXE_LOCK_ENTER_INTR(pUM, idx)      mutex_enter(&(pUM)->intrMutex[(idx)])
#define BNXE_LOCK_EXIT_INTR(pUM, idx)       mutex_exit(&(pUM)->intrMutex[(idx)])
#define BNXE_LOCK_ENTER_INTR_FLIP(pUM, idx) mutex_enter(&(pUM)->intrFlipMutex[(idx)])
#define BNXE_LOCK_EXIT_INTR_FLIP(pUM, idx)  mutex_exit(&(pUM)->intrFlipMutex[(idx)])
#define BNXE_LOCK_ENTER_TX(pUM, idx)        mutex_enter(&(pUM)->txq[(idx)].txMutex)
#define BNXE_LOCK_EXIT_TX(pUM, idx)         mutex_exit(&(pUM)->txq[(idx)].txMutex)
#define BNXE_LOCK_ENTER_FREETX(pUM, idx)    mutex_enter(&(pUM)->txq[(idx)].freeTxDescMutex)
#define BNXE_LOCK_EXIT_FREETX(pUM, idx)     mutex_exit(&(pUM)->txq[(idx)].freeTxDescMutex)
#define BNXE_LOCK_ENTER_RX(pUM, idx)        mutex_enter(&(pUM)->rxq[(idx)].rxMutex)
#define BNXE_LOCK_EXIT_RX(pUM, idx)         mutex_exit(&(pUM)->rxq[(idx)].rxMutex)
#define BNXE_LOCK_ENTER_DONERX(pUM, idx)    mutex_enter(&(pUM)->rxq[(idx)].doneRxMutex)
#define BNXE_LOCK_EXIT_DONERX(pUM, idx)     mutex_exit(&(pUM)->rxq[(idx)].doneRxMutex)
#define BNXE_LOCK_ENTER_SB(pUM, idx)        mutex_enter(&(pUM)->sbMutex[(idx)])
#define BNXE_LOCK_EXIT_SB(pUM, idx)         mutex_exit(&(pUM)->sbMutex[(idx)])
#define BNXE_LOCK_ENTER_ETH_CON(pUM)        mutex_enter(&(pUM)->ethConMutex)
#define BNXE_LOCK_EXIT_ETH_CON(pUM)         mutex_exit(&(pUM)->ethConMutex)
#define BNXE_LOCK_ENTER_MCP(pUM)            mutex_enter(&(pUM)->mcpMutex)
#define BNXE_LOCK_EXIT_MCP(pUM)             mutex_exit(&(pUM)->mcpMutex)
#define BNXE_LOCK_ENTER_PHY(pUM)            mutex_enter(&(pUM)->phyMutex)
#define BNXE_LOCK_EXIT_PHY(pUM)             mutex_exit(&(pUM)->phyMutex)
#define BNXE_LOCK_ENTER_IND(pUM)            mutex_enter(&(pUM)->indMutex)
#define BNXE_LOCK_EXIT_IND(pUM)             mutex_exit(&(pUM)->indMutex)
#define BNXE_LOCK_ENTER_CID(pUM)            mutex_enter(&(pUM)->cidMutex)
#define BNXE_LOCK_EXIT_CID(pUM)             mutex_exit(&(pUM)->cidMutex)
#define BNXE_LOCK_ENTER_SPQ(pUM)            mutex_enter(&(pUM)->spqMutex)
#define BNXE_LOCK_EXIT_SPQ(pUM)             mutex_exit(&(pUM)->spqMutex)
#define BNXE_LOCK_ENTER_SPREQ(pUM)          mutex_enter(&(pUM)->spReqMutex)
#define BNXE_LOCK_EXIT_SPREQ(pUM)           mutex_exit(&(pUM)->spReqMutex)
#define BNXE_LOCK_ENTER_RRREQ(pUM)          mutex_enter(&(pUM)->rrReqMutex)
#define BNXE_LOCK_EXIT_RRREQ(pUM)           mutex_exit(&(pUM)->rrReqMutex)
#define BNXE_LOCK_ENTER_ISLES_CONTROL(pUM)  mutex_enter(&(pUM)->islesCtrlMutex)
#define BNXE_LOCK_EXIT_ISLES_CONTROL(pUM)   mutex_exit(&(pUM)->islesCtrlMutex)
#define BNXE_LOCK_ENTER_TOE(pUM)            mutex_enter(&(pUM)->toeMutex)
#define BNXE_LOCK_EXIT_TOE(pUM)             mutex_exit(&(pUM)->toeMutex)
#define BNXE_LOCK_ENTER_MEM(pUM)            mutex_enter(&(pUM)->memMutex)
#define BNXE_LOCK_EXIT_MEM(pUM)             mutex_exit(&(pUM)->memMutex)
#define BNXE_LOCK_ENTER_OFFLOAD(pUM)        mutex_enter(&(pUM)->offloadMutex)
#define BNXE_LOCK_EXIT_OFFLOAD(pUM)         mutex_exit(&(pUM)->offloadMutex)
#define BNXE_LOCK_ENTER_HWINIT(pUM)         mutex_enter(&(pUM)->hwInitMutex)
#define BNXE_LOCK_EXIT_HWINIT(pUM)          mutex_exit(&(pUM)->hwInitMutex)
#define BNXE_LOCK_ENTER_GLD(pUM)            mutex_enter(&(pUM)->gldMutex)
#define BNXE_LOCK_EXIT_GLD(pUM)             mutex_exit(&(pUM)->gldMutex)
#define BNXE_LOCK_ENTER_GLDTX(pUM, rw)      rw_enter(&(pUM)->gldTxMutex, (rw))
#define BNXE_LOCK_EXIT_GLDTX(pUM)           rw_exit(&(pUM)->gldTxMutex)
#define BNXE_LOCK_ENTER_TIMER(pUM)          mutex_enter(&(pUM)->timerMutex)
#define BNXE_LOCK_EXIT_TIMER(pUM)           mutex_exit(&(pUM)->timerMutex)
#define BNXE_LOCK_ENTER_STATS(pUM)          mutex_enter(&(pUM)->kstatMutex)
#define BNXE_LOCK_EXIT_STATS(pUM)           mutex_exit(&(pUM)->kstatMutex)

#else /* not BNXE_LOCKS_INLINE */

void BNXE_LOCK_ENTER_INTR(um_device_t * pUM, int idx);
void BNXE_LOCK_EXIT_INTR(um_device_t * pUM, int idx);
void BNXE_LOCK_ENTER_INTR_FLIP(um_device_t * pUM, int idx);
void BNXE_LOCK_EXIT_INTR_FLIP(um_device_t * pUM, int idx);
void BNXE_LOCK_ENTER_TX(um_device_t * pUM, int idx);
void BNXE_LOCK_EXIT_TX(um_device_t * pUM, int idx);
void BNXE_LOCK_ENTER_FREETX(um_device_t * pUM, int idx);
void BNXE_LOCK_EXIT_FREETX(um_device_t * pUM, int idx);
void BNXE_LOCK_ENTER_RX(um_device_t * pUM, int idx);
void BNXE_LOCK_EXIT_RX(um_device_t * pUM, int idx);
void BNXE_LOCK_ENTER_DONERX(um_device_t * pUM, int idx);
void BNXE_LOCK_EXIT_DONERX(um_device_t * pUM, int idx);
void BNXE_LOCK_ENTER_SB(um_device_t * pUM, int idx);            
void BNXE_LOCK_EXIT_SB(um_device_t * pUM, int idx);
void BNXE_LOCK_ENTER_ETH_CON(um_device_t * pUM);            
void BNXE_LOCK_EXIT_ETH_CON(um_device_t * pUM);
void BNXE_LOCK_ENTER_MCP(um_device_t * pUM);
void BNXE_LOCK_EXIT_MCP(um_device_t * pUM);
void BNXE_LOCK_ENTER_PHY(um_device_t * pUM);
void BNXE_LOCK_EXIT_PHY(um_device_t * pUM);
void BNXE_LOCK_ENTER_IND(um_device_t * pUM);
void BNXE_LOCK_EXIT_IND(um_device_t * pUM);
void BNXE_LOCK_ENTER_CID(um_device_t * pUM);
void BNXE_LOCK_EXIT_CID(um_device_t * pUM);
void BNXE_LOCK_ENTER_SPQ(um_device_t * pUM);
void BNXE_LOCK_EXIT_SPQ(um_device_t * pUM);
void BNXE_LOCK_ENTER_SPREQ(um_device_t * pUM);
void BNXE_LOCK_EXIT_SPREQ(um_device_t * pUM);
void BNXE_LOCK_ENTER_RRREQ(um_device_t * pUM);
void BNXE_LOCK_EXIT_RRREQ(um_device_t * pUM);
void BNXE_LOCK_ENTER_ISLES_CONTROL(um_device_t * pUM);
void BNXE_LOCK_EXIT_ISLES_CONTROL(um_device_t * pUM);
void BNXE_LOCK_ENTER_MEM(um_device_t * pUM);
void BNXE_LOCK_EXIT_MEM(um_device_t * pUM);
void BNXE_LOCK_ENTER_GLD(um_device_t * pUM);
void BNXE_LOCK_EXIT_GLD(um_device_t * pUM);
void BNXE_LOCK_ENTER_GLDTX(um_device_t * pUM, krw_t rw);
void BNXE_LOCK_EXIT_GLDTX(um_device_t * pUM);
void BNXE_LOCK_ENTER_TIMER(um_device_t * pUM);
void BNXE_LOCK_EXIT_TIMER(um_device_t * pUM);
void BNXE_LOCK_ENTER_STATS(um_device_t * pUM);
void BNXE_LOCK_EXIT_STATS(um_device_t * pUM);

#endif /* BNXE_LOCKS_INLINE */

#define CATC_TRIGGER(lmdev, data) {            \
              REG_WR((lmdev), 0x2000, (data)); \
        }
#define CATC_TRIGGER_START(lmdev) CATC_TRIGGER((lmdev), 0xcafecafe)

void BnxeDumpMem(um_device_t * pUM,
                 char *        pTag,
                 u8_t *        pMem,
                 u32_t         len);
void BnxeDumpPkt(um_device_t * pUM,
                 char *        pTag,
                 mblk_t *      pMblk,
                 boolean_t     contents);

/* XXX yuck (beware return strings lengths with kstat and mdb) */

inline boolean_t BnxeIsClientBound(um_device_t * pUM)
{
    return (CLIENT_HW(pUM, LM_CLI_IDX_NDIS) ||
            CLIENT_BOUND(pUM, LM_CLI_IDX_FCOE));
}

inline char * BnxeClientsHw(um_device_t * pUM)
{
    if (CLIENT_HW(pUM, LM_CLI_IDX_NDIS) &&
        CLIENT_HW(pUM, LM_CLI_IDX_FCOE))      { return "L2,FCoE"; }
    else if (CLIENT_HW(pUM, LM_CLI_IDX_NDIS)) { return "L2"; }
    else if (CLIENT_HW(pUM, LM_CLI_IDX_FCOE)) { return "FCoE"; }
    else                                      { return "None"; }
}

inline char * BnxeClientsDevi(um_device_t * pUM)
{
    if (CLIENT_DEVI(pUM, LM_CLI_IDX_FCOE)) { return "FCoE"; }
    else                                   { return "None"; }
}

inline char * BnxeClientsBound(um_device_t * pUM)
{
    if (CLIENT_HW(pUM, LM_CLI_IDX_NDIS) &&
        CLIENT_BOUND(pUM, LM_CLI_IDX_FCOE))      { return "L2,FCoE"; }
    else if (CLIENT_HW(pUM, LM_CLI_IDX_NDIS))    { return "L2"; }
    else if (CLIENT_BOUND(pUM, LM_CLI_IDX_FCOE)) { return "FCoE"; }
    else                                         { return "None"; }
}

#endif /* BNXE_H */

