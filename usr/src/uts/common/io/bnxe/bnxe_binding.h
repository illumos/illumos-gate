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

#ifndef __BNXE_BINDING_H
#define __BNXE_BINDING_H

#include "bcmtype.h"
#include "mac_drv_info.h"

#define BNXE_BINDING_VERSION \
    ((MAJVERSION << 16) | (MINVERSION << 8) | (REVVERSION << 0))

/* cb_ioctl commands sent to bnxe */
#define BNXE_BIND_FCOE    0x0ead0001
#define BNXE_UNBIND_FCOE  0x0ead0002


/* default FCoE max exchanges is 4096 for SF and 2048 for MF */
#define FCOE_MAX_EXCHANGES_SF 4096
#define FCOE_MAX_EXCHANGES_MF 2048


#ifndef BNXE_FCOE_WWN_SIZE
#define BNXE_FCOE_WWN_SIZE 8
#endif

typedef struct bnxe_wwn_info
{
    uint32_t fcp_pwwn_provided;
    uint8_t  fcp_pwwn[BNXE_FCOE_WWN_SIZE];
    uint32_t fcp_nwwn_provided;
    uint8_t  fcp_nwwn[BNXE_FCOE_WWN_SIZE];
} BnxeWwnInfo;


#define FCOE_INFO_FLAG_FORCE_LOAD 0x1

#define FCOE_INFO_FLAG_MF_MODE_MASK 0x6 /* bits 2-3 */
#define FCOE_INFO_FLAG_MF_MODE_SF   0x0 /* single function */
#define FCOE_INFO_FLAG_MF_MODE_SD   0x2 /* switch dependent (vlan based) */
#define FCOE_INFO_FLAG_MF_MODE_SI   0x4 /* switch independent (mac based) */
#define FCOE_INFO_FLAG_MF_MODE_AFEX 0x6 /* switch dependent (afex based) */

#define FCOE_INFO_IS_MF_MODE_SF(flags) \
    (((flags) & FCOE_INFO_FLAG_MF_MODE_MASK) == FCOE_INFO_FLAG_MF_MODE_SF)
#define FCOE_INFO_IS_MF_MODE_SD(flags) \
    (((flags) & FCOE_INFO_FLAG_MF_MODE_MASK) == FCOE_INFO_FLAG_MF_MODE_SD)
#define FCOE_INFO_IS_MF_MODE_SI(flags) \
    (((flags) & FCOE_INFO_FLAG_MF_MODE_MASK) == FCOE_INFO_FLAG_MF_MODE_SI)
#define FCOE_INFO_IS_MF_MODE_AFEX(flags) \
    (((flags) & FCOE_INFO_FLAG_MF_MODE_MASK) == FCOE_INFO_FLAG_MF_MODE_AFEX)

typedef struct bnxe_fcoe_info
{
    u32_t       flags;
    u32_t       max_fcoe_conn;
    u32_t       max_fcoe_exchanges;
    BnxeWwnInfo wwn;
} BnxeFcoeInfo;


typedef struct bnxe_fcoe_caps
{
    struct fcoe_capabilities fcoe_caps;
} BnxeFcoeCaps;


/*
 * cli_ctl - misc control interface up to the client
 *
 *  cmd: CLI_CTL_LINK_UP   - link up event, no data passed
 *       CLI_CTL_LINK_DOWN - link down event, no data passed
 *       CLI_CTL_UNLOAD    - graceful unload event, no data passed
 *
 *  pData:    pointer to command data or NULL
 *
 *  dataLen:  length of command data or 0
 */
#define CLI_CTL_LINK_UP    1
#define CLI_CTL_LINK_DOWN  2
#define CLI_CTL_UNLOAD     3
typedef boolean_t (*cli_ctl)(dev_info_t * pDev,
                             int          cmd,
                             void *       pData,
                             int          dataLen);

typedef boolean_t (*cli_indicate_tx)(dev_info_t * pDev,
                                     mblk_t *     pMblk);

typedef boolean_t (*cli_indicate_rx)(dev_info_t * pDev,
                                     mblk_t *     pMblk);

typedef boolean_t (*cli_indicate_cqes)(dev_info_t * pDev,
                                       void *       cqes[],
                                       int          cqeCnt);


/*
 * prv_ctl - misc control interface down to the provider
 *
 *  cmd: PRV_CTL_GET_MAC_ADDR      - get MAC Address, pass data buffer to hold addr
 *       PRV_CTL_SET_MAC_ADDR      - set MAC Address, pass data buffer contains addr
 *       PRV_CTL_QUERY_PARAMS      - query related params, pass BnxeXXXInfo struct
 *       PRV_CTL_DISABLE_INTR      - disable interrupts, no data passed
 *       PRV_CTL_ENABLE_INTR       - enable interrupts, no data passed
 *       PRV_CTL_MBA_BOOT          - check if MBA performed network boot
 *       PRV_CTL_LINK_STATE        - query the link state, pass boolean buffer
 *       PRV_CTL_BOARD_TYPE        - query the board type, pass string buffer
 *       PRV_CTL_BOARD_SERNUM      - query the board's serial number, pass string buffer
 *       PRV_CTL_BOOTCODE_VERSION  - query the MFW bootcode version, pass string buffer
 *       PRV_CTL_REPORT_FCOE_STATS - report FCoE stats, pass filled in fcoe_stats_info_t
 *       PRV_CTL_SET_CAPS          - report FCoE capabilities, pass filled in BnxeFcoeCaps struct
 *
 *  pData:    pointer to command data or NULL
 *
 *  dataLen:  length of command data or 0
 *
 *  returns:  TRUE upon success, FALSE otherwise
 */
#define PRV_CTL_GET_MAC_ADDR      1
#define PRV_CTL_SET_MAC_ADDR      2
#define PRV_CTL_QUERY_PARAMS      3
#define PRV_CTL_DISABLE_INTR      4
#define PRV_CTL_ENABLE_INTR       5
#define PRV_CTL_MBA_BOOT          6
#define PRV_CTL_LINK_STATE        7
#define PRV_CTL_BOARD_TYPE        8
#define PRV_CTL_BOARD_SERNUM      9
#define PRV_CTL_BOOTCODE_VERSION  10
#define PRV_CTL_REPORT_FCOE_STATS 11
#define PRV_CTL_SET_CAPS          12
typedef boolean_t (*prv_ctl)(dev_info_t * pDev,
                             int          cmd,
                             void *       pData,
                             int          dataLen);

#define PRV_TX_VLAN_TAG  1
typedef mblk_t * (*prv_tx)(dev_info_t * pDev,
                           mblk_t *     pMblk,
                           u32_t        flags,
                           u16_t        vlan_tag);

typedef boolean_t (*prv_poll)(dev_info_t * pDev);

typedef boolean_t (*prv_send_wqes)(dev_info_t * pDev,
                                   void *       wqes[],
                                   int          wqeCnt);

typedef boolean_t (*prv_map_mailboxq)(dev_info_t *       pDev,
                                      u32_t              cid,
                                      void **            ppMap,
                                      ddi_acc_handle_t * pAccHandle);

typedef boolean_t (*prv_unmap_mailboxq)(dev_info_t *     pDev,
                                        u32_t            cid,
                                        void *           pMap,
                                        ddi_acc_handle_t accHandle);


typedef struct bnxe_binding
{
    u32_t              version;

    dev_info_t *       pCliDev; /* bnxe client */

    cli_ctl            cliCtl;
    cli_indicate_tx    cliIndicateTx;
    cli_indicate_rx    cliIndicateRx;
    cli_indicate_cqes  cliIndicateCqes;

    u32_t              numRxDescs;
    u32_t              numTxDescs;

    dev_info_t *       pPrvDev; /* bnxe */

    prv_ctl            prvCtl;
    prv_tx             prvTx;
    prv_poll           prvPoll;
    prv_send_wqes      prvSendWqes;
    prv_map_mailboxq   prvMapMailboxq;
    prv_unmap_mailboxq prvUnmapMailboxq;
} BnxeBinding;

#endif /* __BNXE_BINDING_H */

