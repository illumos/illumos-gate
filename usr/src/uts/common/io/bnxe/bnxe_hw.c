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

#include "bnxe.h"


#ifdef BNXE_DEBUG_DMA_LIST

static void BnxeVerifySavedDmaList(um_device_t * pUM)
{
    BnxeMemDma * pTmp;
    int i;

    BNXE_LOCK_ENTER_MEM(pUM);

    pTmp = (BnxeMemDma *)d_list_peek_head(&pUM->memDmaListSaved);
    while (pTmp)
    {
        BnxeLogWarn(pUM, "testing dma block %p / %p %d",
                    pTmp, pTmp->pDmaVirt, pTmp->size);
        for (i = 0; i < pTmp->size; i++)
        {
            if (((u8_t *)pTmp->pDmaVirt)[i] != 0x0)
            {
                BnxeDbgBreakMsg(pUM, "old dma block wacked %p (byte %i)",
                                pTmp, i);
            }
        }

        pTmp = (BnxeMemDma *)d_list_next_entry(&pTmp->link);
    }

    BNXE_LOCK_EXIT_MEM(pUM);
}

#endif /* BNXE_DEBUG_DMA_LIST */


static boolean_t BnxeRssEnable(um_device_t * pUM)
{
    #define BNXE_RSS_HASH_KEY_SIZE 40
    u8_t hashKey[BNXE_RSS_HASH_KEY_SIZE];
    #define BNXE_RSS_INDIRECTION_TABLE_SIZE 128 /* must be a power of 2 */
    u8_t indirectionTable[BNXE_RSS_INDIRECTION_TABLE_SIZE];
    lm_rss_hash_t hashType;
    int i, rc;

    if (!pUM->devParams.numRings)
    {
        return B_TRUE;
    }

    /* fill out the indirection table */
    for (i = 0; i < BNXE_RSS_INDIRECTION_TABLE_SIZE; i++)
    {
        indirectionTable[i] = (i % pUM->devParams.numRings);
    }

    /* seed the hash function with random data */
    random_get_pseudo_bytes(hashKey, BNXE_RSS_HASH_KEY_SIZE);

    hashType = (LM_RSS_HASH_IPV4     |
                LM_RSS_HASH_TCP_IPV4 |
                LM_RSS_HASH_IPV6     |
                LM_RSS_HASH_TCP_IPV6);

    rc = lm_enable_rss((lm_device_t *)pUM,
                       indirectionTable,
                       BNXE_RSS_INDIRECTION_TABLE_SIZE,
                       hashKey,
                       BNXE_RSS_HASH_KEY_SIZE,
                       hashType,
                       FALSE,
                       NULL);

    if (rc == LM_STATUS_PENDING)
    {
        if ((rc = lm_wait_config_rss_done(&pUM->lm_dev)) != LM_STATUS_SUCCESS)
        {
            BnxeLogWarn(pUM, "Failed to enable RSS from pending operation (%d)", rc);
            BnxeFmErrorReport(pUM, DDI_FM_DEVICE_NO_RESPONSE);
        }
    }
    else if (rc != LM_STATUS_SUCCESS)
    {
        BnxeLogWarn(pUM, "Failed to enable RSS (%d)", rc);
        BnxeFmErrorReport(pUM, DDI_FM_DEVICE_INVAL_STATE);
    }

    return (rc == LM_STATUS_SUCCESS) ? B_TRUE : B_FALSE;
}


static lm_status_t BnxeRssDisable(um_device_t * pUM)
{
    int rc;

    rc = lm_disable_rss((lm_device_t *)pUM, FALSE, NULL);

    if (rc == LM_STATUS_PENDING)
    {
        if ((rc = lm_wait_config_rss_done(&pUM->lm_dev)) != LM_STATUS_SUCCESS)
        {
            BnxeLogWarn(pUM, "Failed to disable RSS from pending operation (%d)", rc);
            BnxeFmErrorReport(pUM, DDI_FM_DEVICE_NO_RESPONSE);
        }
    }
    else if (rc != LM_STATUS_SUCCESS)
    {
        BnxeLogWarn(pUM, "Failed to disable RSS (%d)", rc);
        BnxeFmErrorReport(pUM, DDI_FM_DEVICE_INVAL_STATE);
    }

    return (rc == LM_STATUS_SUCCESS) ? B_TRUE : B_FALSE;
}


lm_medium_t BnxeHwReqPhyMediumSettings(um_device_t * pUM)
{
    lm_device_t * pLM = &pUM->lm_dev;
    lm_medium_t   medium = 0;
    char buf[128];
    int i;

    memset(pUM->hwinit.supported, 0, sizeof(pUM->hwinit.supported));

    switch (pLM->params.link.num_phys)
    {
    case 1:

        pUM->hwinit.supported[0] =
            pLM->params.link.phy[ELINK_INT_PHY].supported;
        pUM->hwinit.phy_cfg_size = 1;
        break;

    case 2:

        pUM->hwinit.supported[0] =
            pLM->params.link.phy[ELINK_EXT_PHY1].supported;
        pUM->hwinit.phy_cfg_size = 1;
        break;

    case 3:

        if (pLM->params.link.multi_phy_config &
            PORT_HW_CFG_PHY_SWAPPED_ENABLED)
        {
            pUM->hwinit.supported[1] =
                pLM->params.link.phy[ELINK_EXT_PHY1].supported;
            pUM->hwinit.supported[0] =
                pLM->params.link.phy[ELINK_EXT_PHY2].supported;
        }
        else
        {
            pUM->hwinit.supported[0] =
                pLM->params.link.phy[ELINK_EXT_PHY1].supported;
            pUM->hwinit.supported[1] =
                pLM->params.link.phy[ELINK_EXT_PHY2].supported;
        }

        pUM->hwinit.phy_cfg_size = 2;
        break;

    default:

        BnxeLogWarn(pUM, "Unexpected number of phys, check nvram config! (%d)",
                    pLM->params.link.num_phys);
        return 0;
    }

    for (i = 0; i < pUM->hwinit.phy_cfg_size; i++)
    {
        *buf = 0;
        snprintf(buf, sizeof(buf), "Phy %d supported:", i);

        if (!(pLM->params.link.speed_cap_mask[i] &
              PORT_HW_CFG_SPEED_CAPABILITY_D0_10M_HALF))
        {
            pUM->hwinit.supported[i] &= ~ELINK_SUPPORTED_10baseT_Half;
        }
        else
        {
            snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                     " 10M/half");
        }

        if (!(pLM->params.link.speed_cap_mask[i] &
              PORT_HW_CFG_SPEED_CAPABILITY_D0_10M_FULL))
        {
            pUM->hwinit.supported[i] &= ~ELINK_SUPPORTED_10baseT_Full;
        }
        else
        {
            snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                     " 10M/full");
        }

        if (!(pLM->params.link.speed_cap_mask[i] &
              PORT_HW_CFG_SPEED_CAPABILITY_D0_100M_HALF))
        {
            pUM->hwinit.supported[i] &= ~ELINK_SUPPORTED_100baseT_Half;
        }
        else
        {
            snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                     " 100M/half");
        }

        if (!(pLM->params.link.speed_cap_mask[i] &
              PORT_HW_CFG_SPEED_CAPABILITY_D0_100M_FULL))
        {
            pUM->hwinit.supported[i] &= ~ELINK_SUPPORTED_100baseT_Full;
        }
        else
        {
            snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                     " 100M/full");
        }

        if (!(pLM->params.link.speed_cap_mask[i] &
              PORT_HW_CFG_SPEED_CAPABILITY_D0_1G))
        {
            pUM->hwinit.supported[i] &= ~ELINK_SUPPORTED_1000baseT_Full;
        }
        else
        {
            snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                     " 1G");
        }

        if (!(pLM->params.link.speed_cap_mask[i] &
              PORT_HW_CFG_SPEED_CAPABILITY_D0_2_5G))
        {
            pUM->hwinit.supported[i] &= ~ELINK_SUPPORTED_2500baseX_Full;
        }
        else
        {
            snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                     " 2.5G");
        }

        if (!(pLM->params.link.speed_cap_mask[i] &
              PORT_HW_CFG_SPEED_CAPABILITY_D0_10G))
        {
            pUM->hwinit.supported[i] &= ~ELINK_SUPPORTED_10000baseT_Full;
        }
        else
        {
            snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                     " 10G");
        }

        if (!(pLM->params.link.speed_cap_mask[i] &
              PORT_HW_CFG_SPEED_CAPABILITY_D0_20G))
        {
            pUM->hwinit.supported[i] &= ~(ELINK_SUPPORTED_20000baseMLD2_Full |
                                          ELINK_SUPPORTED_20000baseKR2_Full);
        }
        else
        {
            snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                     " 20G");
        }

        BnxeLogInfo(pUM, buf);

        *buf = 0;
        snprintf(buf, sizeof(buf), "Phy %d link config:", i);

        switch ((uint32_t)pLM->hw_info.link_config[i] &
                PORT_FEATURE_CONNECTED_SWITCH_MASK)
        {
        case PORT_FEATURE_CON_SWITCH_1G_SWITCH:
            snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                     " switch/1G");
            break;
        case PORT_FEATURE_CON_SWITCH_10G_SWITCH:
            snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                     " switch/10G");
            break;
        case PORT_FEATURE_CON_SWITCH_AUTO_DETECT:
            snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                     " switch/auto");
            break;
        case PORT_FEATURE_CON_SWITCH_ONE_TIME_DETECT:
            snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                     " switch/once");
            break;
        default:
            snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                     " switch/unknown");
            break;
        }

        switch ((uint32_t)pLM->hw_info.link_config[i] &
                PORT_FEATURE_LINK_SPEED_MASK)
        {
        case PORT_FEATURE_LINK_SPEED_AUTO:
            snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                     " speed/auto");
            break;
        case PORT_FEATURE_LINK_SPEED_10M_FULL:
            snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                     " speed/10M/full");
            break;
        case PORT_FEATURE_LINK_SPEED_10M_HALF:
            snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                     " speed/10M/half");
            break;
        case PORT_FEATURE_LINK_SPEED_100M_HALF:
            snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                     " speed/100M/half");
            break;
        case PORT_FEATURE_LINK_SPEED_100M_FULL:
            snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                     " speed/100M/full");
            break;
        case PORT_FEATURE_LINK_SPEED_1G:
            snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                     " speed/1G");
            break;
        case PORT_FEATURE_LINK_SPEED_2_5G:
            snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                     " speed/2.5G");
            break;
        case PORT_FEATURE_LINK_SPEED_10G_CX4:
            snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                     " speed/10G");
            break;
        case PORT_FEATURE_LINK_SPEED_20G:
            snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                     " speed/20G");
            break;
        default:
            snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                     " speed/unknown");
            break;
        }

        switch ((uint32_t)pLM->hw_info.link_config[i] &
                PORT_FEATURE_FLOW_CONTROL_MASK)
        {
        case PORT_FEATURE_FLOW_CONTROL_AUTO:
            snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                     " flow/auto");
            break;
        case PORT_FEATURE_FLOW_CONTROL_TX:
            snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                     " flow/tx");
            break;
        case PORT_FEATURE_FLOW_CONTROL_RX:
            snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                     " flow/rx");
            break;
        case PORT_FEATURE_FLOW_CONTROL_BOTH:
            snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                     " flow/both");
            break;
        case PORT_FEATURE_FLOW_CONTROL_NONE:
            snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                     " flow/none");
            break;
        default:
            snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                     " flow/unknown");
            break;
        }

        BnxeLogInfo(pUM, buf);
    }

    for (i = 0; i < pUM->hwinit.phy_cfg_size; i++)
    {
        *buf = 0;
        snprintf(buf, sizeof(buf), "Requesting Phy %d speed:", i);

        if (pUM->curcfg.lnkcfg.param_10hdx)
        {
            if (((pLM->hw_info.link_config[i] &
                  PORT_FEATURE_LINK_SPEED_MASK) ==
                 PORT_FEATURE_LINK_SPEED_AUTO) ||
                ((pLM->hw_info.link_config[i] &
                  PORT_FEATURE_LINK_SPEED_MASK) ==
                 PORT_FEATURE_LINK_SPEED_10M_HALF))
            {
                medium |= (LM_MEDIUM_SPEED_10MBPS | LM_MEDIUM_HALF_DUPLEX);
                snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                         " 10M/half");
            }
            else
            {
                BnxeLogWarn(pUM, "Phy 10hdx requested but not supported");
            }
        }

        if (pUM->curcfg.lnkcfg.param_10fdx)
        {
            if (((pLM->hw_info.link_config[i] &
                  PORT_FEATURE_LINK_SPEED_MASK) ==
                 PORT_FEATURE_LINK_SPEED_AUTO) ||
                ((pLM->hw_info.link_config[i] &
                  PORT_FEATURE_LINK_SPEED_MASK) ==
                 PORT_FEATURE_LINK_SPEED_10M_FULL))
            {
                medium |= (LM_MEDIUM_SPEED_10MBPS | LM_MEDIUM_FULL_DUPLEX);
                snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                         " 10M/full");
            }
            else
            {
                BnxeLogWarn(pUM, "Phy 10fdx requested but not supported");
            }
        }

        if (pUM->curcfg.lnkcfg.param_100hdx)
        {
            if (((pLM->hw_info.link_config[i] &
                  PORT_FEATURE_LINK_SPEED_MASK) ==
                 PORT_FEATURE_LINK_SPEED_AUTO) ||
                ((pLM->hw_info.link_config[i] &
                  PORT_FEATURE_LINK_SPEED_MASK) ==
                 PORT_FEATURE_LINK_SPEED_100M_HALF))
            {
                medium |= (LM_MEDIUM_SPEED_100MBPS | LM_MEDIUM_HALF_DUPLEX);
                snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                         " 100M/half");
            }
            else
            {
                BnxeLogWarn(pUM, "Phy 100hdx requested but not supported");
            }
        }

        if (pUM->curcfg.lnkcfg.param_100fdx)
        {
            if (((pLM->hw_info.link_config[i] &
                  PORT_FEATURE_LINK_SPEED_MASK) ==
                 PORT_FEATURE_LINK_SPEED_AUTO) ||
                ((pLM->hw_info.link_config[i] &
                  PORT_FEATURE_LINK_SPEED_MASK) ==
                 PORT_FEATURE_LINK_SPEED_100M_FULL))
            {
                medium |= (LM_MEDIUM_SPEED_100MBPS | LM_MEDIUM_FULL_DUPLEX);
                snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                         " 100M/full");
            }
            else
            {
                BnxeLogWarn(pUM, "Phy 100fdx requested but not supported");
            }
        }

        if (pUM->curcfg.lnkcfg.param_1000fdx)
        {
            if (((pLM->hw_info.link_config[i] &
                  PORT_FEATURE_LINK_SPEED_MASK) ==
                 PORT_FEATURE_LINK_SPEED_AUTO) ||
                ((pLM->hw_info.link_config[i] &
                  PORT_FEATURE_LINK_SPEED_MASK) ==
                 PORT_FEATURE_LINK_SPEED_1G))
            {
                medium |= (LM_MEDIUM_SPEED_1000MBPS | LM_MEDIUM_FULL_DUPLEX);
                snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                         " 1G");
            }
            else
            {
                BnxeLogWarn(pUM, "Phy 1000fdx requested but not supported");
            }
        }

        if (pUM->curcfg.lnkcfg.param_10000fdx)
        {
            if (((pLM->hw_info.link_config[i] &
                  PORT_FEATURE_LINK_SPEED_MASK) ==
                 PORT_FEATURE_LINK_SPEED_AUTO) ||
                ((pLM->hw_info.link_config[i] &
                  PORT_FEATURE_LINK_SPEED_MASK) ==
                 PORT_FEATURE_LINK_SPEED_10G_CX4))
            {
                medium |= (LM_MEDIUM_SPEED_10GBPS | LM_MEDIUM_FULL_DUPLEX);
                snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                         " 10G");
            }
            else
            {
                BnxeLogWarn(pUM, "Phy 10000fdx requested but not supported");
            }
        }

        if (pUM->curcfg.lnkcfg.param_20000fdx)
        {
            if (((pLM->hw_info.link_config[i] &
                  PORT_FEATURE_LINK_SPEED_MASK) ==
                 PORT_FEATURE_LINK_SPEED_AUTO) ||
                ((pLM->hw_info.link_config[i] &
                  PORT_FEATURE_LINK_SPEED_MASK) ==
                 PORT_FEATURE_LINK_SPEED_20G))
            {
                medium |= (LM_MEDIUM_SPEED_20GBPS | LM_MEDIUM_FULL_DUPLEX);
                snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                         " 20G");
            }
            else
            {
                BnxeLogWarn(pUM, "Phy 20000fdx requested but not supported");
            }
        }

        if (pUM->curcfg.lnkcfg.link_autoneg)
        {
            if ((pLM->hw_info.link_config[i] &
                 PORT_FEATURE_LINK_SPEED_MASK) ==
                PORT_FEATURE_LINK_SPEED_AUTO)
            {
                if (medium)
                {
                    BnxeLogWarn(pUM, "Phy autoneg requested along with other speeds, ignoring others and forcing autoneg");
                }

                medium = LM_MEDIUM_SPEED_AUTONEG; /* 0x0000 */
                snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                         " auto");
            }
            else
            {
                BnxeLogWarn(pUM, "Phy autoneg requested but not supported");
            }
        }

        BnxeLogInfo(pUM, buf);
    }

    medium |= LM_MEDIUM_TYPE_XGXS;

    return medium;
}


lm_flow_control_t BnxeHwReqPhyFlowSettings(um_device_t * pUM)
{
    lm_device_t * pLM = &pUM->lm_dev;
    lm_flow_control_t flowctrl;
    char buf[128];
    int i;

    flowctrl = LM_FLOW_CONTROL_NONE;

    for (i = 0; i < pUM->hwinit.phy_cfg_size; i++)
    {
        *buf = 0;
        snprintf(buf, sizeof(buf), "Requesting Phy %d flow:", i);

        if (pUM->curcfg.lnkcfg.param_txpause)
        {
            if ((pLM->hw_info.link_config[i] &
                 PORT_FEATURE_FLOW_CONTROL_MASK) &
                PORT_FEATURE_FLOW_CONTROL_TX)
            {
                flowctrl |= LM_FLOW_CONTROL_TRANSMIT_PAUSE;
                snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                         " tx");
            }
            else
            {
                BnxeLogWarn(pUM, "Phy TX flow requested but not supported");
            }
        }

        if (pUM->curcfg.lnkcfg.param_rxpause)
        {
            if ((pLM->hw_info.link_config[i] &
                 PORT_FEATURE_FLOW_CONTROL_MASK) &
                PORT_FEATURE_FLOW_CONTROL_RX)
            {
                flowctrl |= LM_FLOW_CONTROL_RECEIVE_PAUSE;
                snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                         " rx");
            }
            else
            {
                BnxeLogWarn(pUM, "Phy RX flow requested but not supported");
            }
        }

        if (pUM->curcfg.flow_autoneg)
        {
            /*
             * This value can be or'ed with receive pause and transmit
             * pause.  If the auto-negotiation is disabled and the receive
             * pause and transmit pause bits are set, then flow control is
             * enabled regardless of link partner's flow control capability.
             * Otherwise, if this bit is set, then flow is negotiated with
             * the link partner.  Values 0x80000000 and 0x80000003 are
             * equivalent.
             */
            if ((pLM->hw_info.link_config[i] &
                 PORT_FEATURE_FLOW_CONTROL_MASK) ==
                PORT_FEATURE_FLOW_CONTROL_AUTO)
            {
                flowctrl |= LM_FLOW_CONTROL_AUTO_PAUSE;
                snprintf(buf + strlen(buf), (sizeof(buf) - strlen(buf)),
                         " auto");
            }
            else
            {
                BnxeLogWarn(pUM, "Phy Auto flow requested but not supported");
            }
        }

        BnxeLogInfo(pUM, buf);
    }

    return flowctrl;
}


void BnxeUpdatePhy(um_device_t * pUM)
{
    lm_device_t * pLM = &pUM->lm_dev;
    int rc;

    BNXE_LOCK_ENTER_PHY(pUM);

    pLM->params.req_medium    = BnxeHwReqPhyMediumSettings(pUM);
    pLM->params.flow_ctrl_cap = BnxeHwReqPhyFlowSettings(pUM);

    if (IS_PMF(&pUM->lm_dev))
    {
        lm_reset_link(pLM);
    }

    rc = lm_init_phy(pLM,
                     pLM->params.req_medium,
                     pLM->params.flow_ctrl_cap,
                     0 /* pLM->params.selective_autoneg */,
                     0 /* pLM->params.wire_speed */,
                     0);

    if (pUM->fmCapabilities &&
        BnxeCheckAccHandle(pLM->vars.reg_handle[BAR_0]) != DDI_FM_OK)
    {
        ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_DEGRADED);
    }

    if (rc == LM_STATUS_SUCCESS)
    {
        pUM->phyInitialized = B_TRUE;
    }
    else
    {
        BnxeLogWarn(pUM, "Failed to initialize the phy (%d)", rc);
        BnxeFmErrorReport(pUM, DDI_FM_DEVICE_INVAL_STATE);
    }

#if 0
    /*
     * This is problematic. For non-PMF functions the lm_niv_vif_set for
     * a link up will come very early and is queued for processing right
     * after lm_chip_start. Thereafter setting the loopback mode brings
     * the interface back down. Don't know if setting the loopback mode 
     * is even required when forcing it off. XXX
     */
    if (IS_MF_AFEX_MODE(&pUM->lm_dev))
    {
        lm_niv_set_loopback_mode(&pUM->lm_dev, FALSE);
    }
#endif

    BNXE_LOCK_EXIT_PHY(pUM);
}


/*
 * (flag) TRUE = add, FALSE = remove
 *
 * This function must be called with BNXE_LOCK_ENTER_HWINIT held because this
 * is shared between GLDv3 and FCoE entry points.
 */
int BnxeMacAddress(um_device_t *   pUM,
                   int             cliIdx,
                   boolean_t       flag,
                   const uint8_t * pMacAddr)
{
    int i, rc;

    if ((cliIdx != LM_CLI_IDX_NDIS) && (cliIdx != LM_CLI_IDX_FCOE))
    {
        return EINVAL;
    }

    BnxeLogDbg(pUM, "%s MAC address: %02x:%02x:%02x:%02x:%02x:%02x",
        (flag) ? "Adding" : "Removing",
        pMacAddr[0], pMacAddr[1], pMacAddr[2],
        pMacAddr[3], pMacAddr[4], pMacAddr[5]);

    rc = lm_set_mac_addr(&pUM->lm_dev,
                         (u8_t *)pMacAddr,
                         /* XXX */ LM_SET_CAM_NO_VLAN_FILTER,
                         LM_CLI_CID(&pUM->lm_dev, cliIdx),
                         NULL, flag, 0);

    if (rc == LM_STATUS_PENDING)
    {
        if ((rc = lm_wait_set_mac_done(&pUM->lm_dev,
                                       LM_CLI_CID(&pUM->lm_dev, cliIdx))) !=
            LM_STATUS_SUCCESS)
        {
            BnxeLogWarn(pUM, "Failed to %s MAC Address from pending operation (%d)",
                        (flag) ? "set" : "remove", rc);
            BnxeFmErrorReport(pUM, DDI_FM_DEVICE_NO_RESPONSE);
            return ENOMEM;
        }
    }
    else if ((rc != LM_STATUS_PENDING) && (rc != LM_STATUS_EXISTING_OBJECT))
    {
        BnxeLogWarn(pUM, "Failed to %s MAC Address (%d)",
                    (flag) ? "set" : "remove", rc);
        BnxeFmErrorReport(pUM, DDI_FM_DEVICE_INVAL_STATE);
        return ENOMEM;
    }

    return 0;
}


/*
 * This function is used to enable or disable multicast packet reception for
 * particular multicast addresses.  (flag) TRUE = add, FALSE = remove.
 *
 * This function must be called with BNXE_LOCK_ENTER_HWINIT held because this
 * is shared between GLDv3 and FCoE entry points.
 */

void BnxeMulticastE1(um_device_t * pUM,
                     int           cliIdx)
{
    if ((cliIdx != LM_CLI_IDX_NDIS) || !CHIP_IS_E1(&pUM->lm_dev))
    {
        return;
    }

    /* already holding BNXE_LOCK_ENTER_HWINIT */

    if (d_list_entry_cnt(&pUM->mcast_l2) > 64)
    {
        if (!(pUM->devParams.rx_filter_mask[LM_CLI_IDX_NDIS] &
              LM_RX_MASK_ACCEPT_ALL_MULTICAST))
        {
            BnxeLogInfo(pUM, "Turning ON the ALL_MCAST rx mask, number of multicast addressess is >64");

            pUM->devParams.rx_filter_mask[LM_CLI_IDX_NDIS] |=
                LM_RX_MASK_ACCEPT_ALL_MULTICAST;

            BnxeRxMask(pUM, LM_CLI_IDX_NDIS,
                       pUM->devParams.rx_filter_mask[LM_CLI_IDX_NDIS]);
        }
    }
    else
    {
        if (pUM->devParams.rx_filter_mask[LM_CLI_IDX_NDIS] &
            LM_RX_MASK_ACCEPT_ALL_MULTICAST)
        {
            BnxeLogInfo(pUM, "Turning OFF the ALL_MCAST rx mask, number of multicast addressess is <=64");

            pUM->devParams.rx_filter_mask[LM_CLI_IDX_NDIS] &=
                ~LM_RX_MASK_ACCEPT_ALL_MULTICAST;

            BnxeRxMask(pUM, LM_CLI_IDX_NDIS,
                       pUM->devParams.rx_filter_mask[LM_CLI_IDX_NDIS]);
        }
    }
}

int BnxeMulticast(um_device_t *   pUM,
                  int             cliIdx,
                  boolean_t       flag,
                  const uint8_t * pMcastAddr,
                  boolean_t       hwSet)
{
    struct ecore_mcast_list_elem * pTmp;
    d_list_t * mcastList;
    int i, rc;

    if ((cliIdx != LM_CLI_IDX_NDIS) && (cliIdx != LM_CLI_IDX_FCOE))
    {
        return EINVAL;
    }

    if (!pMcastAddr)
    {
        BnxeLogInfo(pUM, "Removing all multicast");
    }
    else
    {
        BnxeLogInfo(pUM, "%s multicast: %02x:%02x:%02x:%02x:%02x:%02x",
            (flag) ? "Adding" : "Removing",
            pMcastAddr[0], pMcastAddr[1], pMcastAddr[2],
            pMcastAddr[3], pMcastAddr[4], pMcastAddr[5]);
    }

    mcastList = (cliIdx == LM_CLI_IDX_NDIS) ? &pUM->mcast_l2 :
                                              &pUM->mcast_fcoe;

    if (flag && (pMcastAddr == NULL))
    {
        /* adding a new address that isn't specified...? */
        BnxeLogWarn(pUM, "ERROR: Multicast address not specified");
        return EINVAL;
    }
    else if (!flag && (pMcastAddr == NULL))
    {
        /* clear all multicast addresses */

        while (d_list_entry_cnt(mcastList))
        {
            pTmp = (struct ecore_mcast_list_elem *)d_list_pop_head(mcastList);
            kmem_free(pTmp, (sizeof(struct ecore_mcast_list_elem) +
                             ETHERNET_ADDRESS_SIZE));
        }

        if (!hwSet)
        {
            return 0;
        }

        rc = lm_set_mc_list(&pUM->lm_dev, mcastList, NULL, cliIdx);

        if (rc == LM_STATUS_PENDING)
        {
            if ((rc = lm_wait_set_mc_done(&pUM->lm_dev, cliIdx)) !=
                LM_STATUS_SUCCESS)
            {
                BnxeLogWarn(pUM, "Failed to clear Multicast Address table from pending operation (%d)", rc);
                BnxeFmErrorReport(pUM, DDI_FM_DEVICE_NO_RESPONSE);
                return ENOMEM;
            }
        }
        else if (rc != LM_STATUS_SUCCESS)
        {
            BnxeLogWarn(pUM, "Failed to clear Multicast Address table (%d)", rc);
            BnxeFmErrorReport(pUM, DDI_FM_DEVICE_INVAL_STATE);
            return ENOMEM;
        }

        BnxeMulticastE1(pUM, cliIdx);

        return 0;
    }

    /* check if this address already exists in the table */
    pTmp = (struct ecore_mcast_list_elem *)d_list_peek_head(mcastList);
    while (pTmp)
    {
        if (IS_ETH_ADDRESS_EQUAL(pMcastAddr, pTmp->mac))
        {
            break;
        }

        pTmp = (struct ecore_mcast_list_elem *)d_list_next_entry(D_LINK_CAST(pTmp));
    }

    if (flag)
    {
        /* only add the address if the table is empty or address not found */
        if (pTmp == NULL)
        {
            if ((pTmp = kmem_zalloc((sizeof(struct ecore_mcast_list_elem) +
                                     ETHERNET_ADDRESS_SIZE),
                                    KM_NOSLEEP)) == NULL)
            {
                BnxeLogWarn(pUM, "Failed to alloc Multicast Address node");
                return ENOMEM;
            }

            pTmp->mac = (u8_t *)pTmp + sizeof(struct ecore_mcast_list_elem);

            COPY_ETH_ADDRESS(pMcastAddr, pTmp->mac);

            d_list_push_head(mcastList, D_LINK_CAST(pTmp));
        }
    }
    else /* (!flag) */
    {
        if (pTmp == NULL)
        {
            /* the address isn't in the table */
            return ENXIO;
        }

        d_list_remove_entry(mcastList, D_LINK_CAST(pTmp));

        kmem_free(pTmp, (sizeof(struct ecore_mcast_list_elem) +
                         ETHERNET_ADDRESS_SIZE));
    }

    if (!hwSet)
    {
        return 0;
    }

    rc = lm_set_mc_list(&pUM->lm_dev, mcastList, NULL, cliIdx);

    if (rc == LM_STATUS_PENDING)
    {
        if ((rc = lm_wait_set_mc_done(&pUM->lm_dev, cliIdx)) !=
            LM_STATUS_SUCCESS)
        {
            BnxeLogWarn(pUM, "Failed to set Multicast Address table from pending operation (%d)", rc);
            BnxeFmErrorReport(pUM, DDI_FM_DEVICE_NO_RESPONSE);
            return ENOMEM;
        }
    }
    else if (rc != LM_STATUS_SUCCESS)
    {
        BnxeLogWarn(pUM, "Failed to set Multicast Address table (%d)", rc);
        BnxeFmErrorReport(pUM, DDI_FM_DEVICE_INVAL_STATE);
        return ENOMEM;
    }

    BnxeMulticastE1(pUM, cliIdx);

    return 0;
}


/*
 * This function must be called with BNXE_LOCK_ENTER_HWINIT held because this
 * is shared between GLDv3 and FCoE entry points.
 */
int BnxeRxMask(um_device_t * pUM,
               int           cliIdx,
               lm_rx_mask_t  mask)
{
    int rc;

    if ((cliIdx != LM_CLI_IDX_NDIS) && (cliIdx != LM_CLI_IDX_FCOE))
    {
        return EINVAL;
    }

    pUM->devParams.rx_filter_mask[cliIdx] = mask;

    rc = lm_set_rx_mask(&pUM->lm_dev,
                        LM_CLI_CID(&pUM->lm_dev, cliIdx), mask, NULL);

    if (rc == LM_STATUS_PENDING)
    {
        if ((rc =
             lm_wait_set_rx_mask_done(&pUM->lm_dev,
                                      LM_CLI_CID(&pUM->lm_dev, cliIdx))) !=
            LM_STATUS_SUCCESS)
        {
            BnxeLogWarn(pUM, "Failed to set Rx mask from pending operation (%d)", rc);
            BnxeFmErrorReport(pUM, DDI_FM_DEVICE_NO_RESPONSE);
            return ENOMEM;
        }
    }

    if (pUM->fmCapabilities &&
        BnxeCheckAccHandle(pUM->lm_dev.vars.reg_handle[BAR_0]) != DDI_FM_OK)
    {
        BnxeLogWarn(pUM, "DMA fault when setting Rx mask");
        ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_LOST);
        return ENOMEM;
    }

    if (rc != LM_STATUS_SUCCESS)
    {
        BnxeLogWarn(pUM, "Failed to set Rx mask (%d)", rc);
        BnxeFmErrorReport(pUM, DDI_FM_DEVICE_INVAL_STATE);
        return ENOMEM;
    }

    return 0;
}


boolean_t BnxeEstablishHwConn(um_device_t * pUM,
                              int           cid)
{
    lm_device_t * pLM = &pUM->lm_dev;
    lm_client_con_params_t cliParams;
    int sb_id;
    int rc;

    sb_id = lm_sb_id_from_chain(&pUM->lm_dev, cid);

    memset(&cliParams, 0, sizeof(cliParams));
    cliParams.mtu         = pUM->devParams.mtu[LM_CHAIN_IDX_CLI(pLM, cid)];
    //cliParams.lah_size    = pUM->devParams.mtu[LM_CHAIN_IDX_CLI(pLM, cid)];
    cliParams.lah_size    = 0;
    cliParams.num_rx_desc = pUM->devParams.numRxDesc[LM_CHAIN_IDX_CLI(pLM, cid)];
    cliParams.num_tx_desc = pUM->devParams.numTxDesc[LM_CHAIN_IDX_CLI(pLM, cid)];
    cliParams.attributes  = (LM_CLIENT_ATTRIBUTES_RX |
                             LM_CLIENT_ATTRIBUTES_TX |
                             LM_CLIENT_ATTRIBUTES_REG_CLI);

    BnxeLogDbg(pUM, "Setting up client for cid %d", cid);
    if (lm_setup_client_con_params(pLM, cid, &cliParams) != LM_STATUS_SUCCESS)
    {
        BnxeLogWarn(pUM, "Failed to setup client for cid %d", cid);
        return B_FALSE;
    }

    /*********************************************************/

    BnxeLogDbg(pUM, "Initializing client for cid %d", cid);
    rc = lm_init_chain_con(pLM, cid, TRUE);

    if (pUM->fmCapabilities &&
        BnxeCheckAccHandle(pUM->pPciCfg) != DDI_FM_OK)
    {
        ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_LOST);
        return B_FALSE;
    }

    if (pUM->fmCapabilities &&
        BnxeCheckAccHandle(pLM->vars.reg_handle[BAR_0]) != DDI_FM_OK)
    {
        ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_LOST);
        return B_FALSE;
    }

    if (rc != LM_STATUS_SUCCESS)
    {
        BnxeLogWarn(pUM, "Failed to initialize client for cid %d", cid);
        BnxeFmErrorReport(pUM, DDI_FM_DEVICE_INVAL_STATE);
        return B_FALSE;
    }

    /*********************************************************/

    BnxeLogDbg(pUM, "Establishing client for cid %d", cid);
    rc = lm_establish_eth_con(pLM, cid, sb_id,
                              pLM->params.l2_cli_con_params[cid].attributes);

    if (pUM->fmCapabilities &&
        BnxeCheckAccHandle(pUM->pPciCfg) != DDI_FM_OK)
    {
        ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_LOST);
        return B_FALSE;
    }

    if (pUM->fmCapabilities &&
        BnxeCheckAccHandle(pLM->vars.reg_handle[BAR_0]) != DDI_FM_OK)
    {
        ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_LOST);
        return B_FALSE;
    }

    if (rc != LM_STATUS_SUCCESS)
    {
        BnxeLogWarn(pUM, "Failed to establish client connection");
        BnxeFmErrorReport(pUM, DDI_FM_DEVICE_INVAL_STATE);
        return B_FALSE;
    }

    return B_TRUE;
}


int BnxeHwStartFCOE(um_device_t * pUM)
{
    lm_device_t * pLM = &pUM->lm_dev;
    int rc;

    if (!BNXE_FCOE(pUM))
    {
        BnxeDbgBreakMsg(pUM, "Inside BnxeHwStartFCOE and FCoE not supported!");
        return -1;
    }

    BNXE_LOCK_ENTER_HWINIT(pUM);

    BnxeLogInfo(pUM, "BnxeHwStartFCOE: Starting FCoE (clients %s)",
                BnxeClientsHw(pUM));

    if (BnxeHwStartCore(pUM))
    {
        goto BnxeHwStartFCOE_error;
    }

    if (!pUM->hwInitDone)
    {
        BnxeLogWarn(pUM, "BnxeHwStartFCOE: Failed, hardware not initialized (clients %s)",
                    BnxeClientsHw(pUM));
        goto BnxeHwStartFCOE_error;
    }

    /*********************************************************/

    BnxeLogDbg(pUM, "Allocating FCoE Resources");

    if (lm_fc_alloc_resc(&pUM->lm_dev) != LM_STATUS_SUCCESS)
    {
        BnxeLogWarn(pUM, "Failed to allocate FCoE resources");
        goto BnxeHwStartFCOE_error;
    }

    /*********************************************************/

    BnxeLogDbg(pUM, "Opening FCoE Ethernet Connection");

    pUM->lm_dev.ofld_info.state_blks[STATE_BLOCK_FCOE] =
        &pUM->lm_dev.fcoe_info.run_time.state_blk;

    if (!BnxeEstablishHwConn(pUM, FCOE_CID(pLM)))
    {
        goto BnxeHwStartFCOE_error;
    }

    /*********************************************************/

    BnxeLogDbg(pUM, "Initializing FCoE Tx Pkts");

    if (BnxeTxPktsInit(pUM, LM_CLI_IDX_FCOE))
    {
        BnxeLogWarn(pUM, "Failed to allocate FCoE Tx resources");
        goto BnxeHwStartFCOE_error;
    }

    /*********************************************************/

    BnxeLogDbg(pUM, "Initializing FCoE Rx Pkts");

    if (BnxeRxPktsInit(pUM, LM_CLI_IDX_FCOE))
    {
        BnxeLogWarn(pUM, "Failed to allocate FCoE Rx resources");
        goto BnxeHwStartFCOE_error;
    }

    if (BnxeRxPktsInitPostBuffers(pUM, LM_CLI_IDX_FCOE))
    {
        BnxeLogWarn(pUM, "Failed to post FCoE Rx buffers");
        goto BnxeHwStartFCOE_error;
    }

    /*********************************************************/

    BnxeLogDbg(pUM, "Setting FCoE MAC Address");

    if (BnxeMacAddress(pUM, LM_CLI_IDX_FCOE, B_TRUE,
                       pLM->hw_info.fcoe_mac_addr) < 0)
    {
        goto BnxeHwStartFCOE_error;
    }

    /*********************************************************/

    BnxeLogDbg(pUM, "Setting FCoE Multicast Addresses");

#define ALL_FCOE_MACS   (const uint8_t *)"\x01\x10\x18\x01\x00\x00"
#define ALL_ENODE_MACS  (const uint8_t *)"\x01\x10\x18\x01\x00\x01"

    if ((BnxeMulticast(pUM, LM_CLI_IDX_FCOE, B_TRUE, ALL_FCOE_MACS, B_FALSE) < 0) ||
        (BnxeMulticast(pUM, LM_CLI_IDX_FCOE, B_TRUE, ALL_ENODE_MACS, B_TRUE) < 0))
    {
        goto BnxeHwStartFCOE_error;
    }

    /*********************************************************/

    BnxeLogDbg(pUM, "Turning on FCoE Rx Mask");

    if (BnxeRxMask(pUM, LM_CLI_IDX_FCOE, (
                                          LM_RX_MASK_ACCEPT_UNICAST
                                      //| LM_RX_MASK_ACCEPT_ALL_MULTICAST
                                        | LM_RX_MASK_ACCEPT_MULTICAST
                                      //| LM_RX_MASK_ACCEPT_BROADCAST
                                      //| LM_RX_MASK_PROMISCUOUS_MODE
                                         )) < 0)
    {
        goto BnxeHwStartFCOE_error;
    }

    /*********************************************************/

    CLIENT_HW_SET(pUM, LM_CLI_IDX_FCOE);

    BnxeLogInfo(pUM, "BnxeHwStartFCOE: FCoE started (clients %s)",
                BnxeClientsHw(pUM));

    BNXE_LOCK_EXIT_HWINIT(pUM);
    return 0;

BnxeHwStartFCOE_error:

    BNXE_LOCK_EXIT_HWINIT(pUM);
    return -1;
}


int BnxeHwStartL2(um_device_t * pUM)
{
    lm_device_t * pLM = &pUM->lm_dev;
    int idx, rc;

    BNXE_LOCK_ENTER_HWINIT(pUM);

    BnxeLogInfo(pUM, "BnxeHwStartL2: Starting L2 (clients %s)",
                BnxeClientsHw(pUM));

    if (BnxeHwStartCore(pUM))
    {
        goto BnxeHwStartL2_error;
    }

    if (!pUM->hwInitDone)
    {
        BnxeLogWarn(pUM, "BnxeHwStartL2: Failed, hardware not initialized (clients %s)",
                    BnxeClientsHw(pUM));
        goto BnxeHwStartL2_error;
    }

    /*********************************************************/

    BnxeLogDbg(pUM, "Opening L2 Ethernet Connections (%d)",
               pLM->params.rss_chain_cnt);

    LM_FOREACH_RSS_IDX(pLM, idx)
    {
        if (!BnxeEstablishHwConn(pUM, idx))
        {
            goto BnxeHwStartL2_error;
        }
    }

    /*********************************************************/

    BnxeLogDbg(pUM, "Initializing Tx Pkts");

    if (BnxeTxPktsInit(pUM, LM_CLI_IDX_NDIS))
    {
        BnxeLogWarn(pUM, "Failed to allocate tx resources");
        goto BnxeHwStartL2_error;
    }

    /*********************************************************/

    BnxeLogDbg(pUM, "Initializing Rx Pkts");

    if (BnxeRxPktsInit(pUM, LM_CLI_IDX_NDIS))
    {
        BnxeLogWarn(pUM, "Failed to allocate L2 Rx resources");
        goto BnxeHwStartL2_error;
    }

    if (BnxeRxPktsInitPostBuffers(pUM, LM_CLI_IDX_NDIS))
    {
        BnxeLogWarn(pUM, "Failed to post L2 Rx buffers");
        goto BnxeHwStartL2_error;
    }

    /*********************************************************/

    BnxeLogDbg(pUM, "Enabling RSS");

    if (!BnxeRssEnable(pUM))
    {
        goto BnxeHwStartL2_error;
    }

    /*********************************************************/

    BnxeLogDbg(pUM, "Setting L2 MAC Address");

    /* use the hw programmed address (GLDv3 will overwrite if needed) */ 

    {
        u8_t zero_mac_addr[ETHERNET_ADDRESS_SIZE];
        memset(zero_mac_addr, 0, ETHERNET_ADDRESS_SIZE);

        if (IS_ETH_ADDRESS_EQUAL(pUM->gldMac, zero_mac_addr))
        {
            COPY_ETH_ADDRESS(pUM->lm_dev.hw_info.mac_addr,
                             pUM->lm_dev.params.mac_addr);
        }
        else
        {
            COPY_ETH_ADDRESS(pUM->gldMac,
                             pUM->lm_dev.params.mac_addr);
        }
    }

    if (BnxeMacAddress(pUM, LM_CLI_IDX_NDIS, B_TRUE,
                       pUM->lm_dev.params.mac_addr) < 0)
    {
        goto BnxeHwStartL2_error;
    }

    /*********************************************************/

    BnxeLogDbg(pUM, "Turning on L2 Rx Mask");

    if (BnxeRxMask(pUM, LM_CLI_IDX_NDIS, (
                                          LM_RX_MASK_ACCEPT_UNICAST
                                      //| LM_RX_MASK_ACCEPT_ALL_MULTICAST
                                        | LM_RX_MASK_ACCEPT_MULTICAST
                                        | LM_RX_MASK_ACCEPT_BROADCAST
                                      //| LM_RX_MASK_PROMISCUOUS_MODE
                                         )) < 0)
    {
        goto BnxeHwStartL2_error;
    }

    /*********************************************************/

    CLIENT_HW_SET(pUM, LM_CLI_IDX_NDIS);
    lm_mcp_indicate_client_bind(&pUM->lm_dev, LM_CLI_IDX_NDIS);

    BNXE_LOCK_EXIT_HWINIT(pUM);

    /*********************************************************/

    /*
     * Force a link update.  Another client might already be up in which case
     * the link status won't change during this plumb of the L2 client.
     */
    BnxeGldLink(pUM, (pUM->devParams.lastIndLink == LM_STATUS_LINK_ACTIVE) ?
                         LINK_STATE_UP : LINK_STATE_DOWN);

    BnxeLogInfo(pUM, "BnxeHwStartL2: L2 started (clients %s)",
                BnxeClientsHw(pUM));

    return 0;

BnxeHwStartL2_error:

    /* XXX Need cleanup! */

    BNXE_LOCK_EXIT_HWINIT(pUM);
    return -1;
}


/* Must be called with BNXE_LOCK_ENTER_HWINIT taken! */
int BnxeHwStartCore(um_device_t * pUM)
{
    lm_device_t * pLM = &pUM->lm_dev;
    int rc;

    if (pUM->hwInitDone)
    {
        /* already initialized */
        BnxeLogInfo(pUM, "BnxeHwStartCore: Hardware already initialized (clients %s)",
                    BnxeClientsHw(pUM));
        return 0;
    }

    BnxeLogInfo(pUM, "BnxeHwStartCore: Starting hardware (clients %s)",
                BnxeClientsHw(pUM));

    memset(&pLM->debug_info, 0, sizeof(pLM->debug_info));

    /*********************************************************/

    /* reset the configuration to the hardware default */
    BnxeCfgReset(pUM);

    pUM->phyInitialized = B_FALSE;

    /*********************************************************/

    BnxeLogDbg(pUM, "Allocating LM Resources");

    if (lm_alloc_resc(pLM) != LM_STATUS_SUCCESS)
    {
        BnxeLogWarn(pUM, "Failed to allocate resources");
        goto BnxeHwStartCore_error;
    }

    /*********************************************************/

    BnxeLogDbg(pUM, "Initializing BRCM Chip");

    rc = lm_chip_init(pLM);

    if (pUM->fmCapabilities &&
        BnxeCheckAccHandle(pUM->pPciCfg) != DDI_FM_OK)
    {
        ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_LOST);
        goto BnxeHwStartCore_error;
    }

    if (pUM->fmCapabilities &&
        BnxeCheckAccHandle(pLM->vars.reg_handle[BAR_0]) != DDI_FM_OK)
    {
        ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_LOST);
        goto BnxeHwStartCore_error;
    }

    if (rc != LM_STATUS_SUCCESS)
    {
        BnxeLogWarn(pUM, "Failed to initialize chip");
        BnxeFmErrorReport(pUM, DDI_FM_DEVICE_INVAL_STATE);
        goto BnxeHwStartCore_error;
    }

    /*********************************************************/

    BnxeLogDbg(pUM, "Enabling Interrupts");

    if (BnxeIntrEnable(pUM))
    {
        BnxeLogWarn(pUM, "Failed to enable interrupts");
        goto BnxeHwStartCore_error;
    }

    /*********************************************************/

    BnxeLogDbg(pUM, "Starting BRCM Chip");

    rc = lm_chip_start(pLM);

    if (pUM->fmCapabilities &&
        BnxeCheckAccHandle(pLM->vars.reg_handle[BAR_0]) != DDI_FM_OK)
    {
        ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_LOST);
        goto BnxeHwStartCore_error;
    }

    if (rc != LM_STATUS_SUCCESS)
    {
        BnxeLogWarn(pUM, "Failed to start chip");
        BnxeFmErrorReport(pUM, DDI_FM_DEVICE_INVAL_STATE);
        goto BnxeHwStartCore_error;
    }

    atomic_swap_32(&pUM->chipStarted, B_TRUE);

    /*********************************************************/

    BnxeLogDbg(pUM, "Activating pending WorkQ items");

    BnxeWorkQueueStartPending(pUM);

    /*********************************************************/

    BnxeLogDbg(pUM, "Initializing DCBX");

    lm_dcbx_init(pLM, B_FALSE); /* B_TRUE for hibernate */

    /*********************************************************/

    BnxeLogDbg(pUM, "Initializing Phy");

    BnxeUpdatePhy(pUM);

    /*********************************************************/

    BnxeLogDbg(pUM, "Starting Timer");

    BnxeTimerStart(pUM);

    /*********************************************************/

    atomic_swap_32(&pUM->hwInitDone, B_TRUE);

    BnxeLogInfo(pUM, "BnxeHwStartCore: Hardware started (clients %s)",
                BnxeClientsHw(pUM));

    return 0;

BnxeHwStartCore_error:

    return -1;
}


void BnxeHwStopFCOE(um_device_t * pUM)
{
    lm_device_t * pLM = &pUM->lm_dev;
    int rc;

    if (!BNXE_FCOE(pUM))
    {
        BnxeDbgBreakMsg(pUM, "Inside BnxeHwStopFCOE and FCoE not supported!");
        return;
    }

    BNXE_LOCK_ENTER_HWINIT(pUM);

    BnxeLogInfo(pUM, "BnxeHwStopFCOE: Stopping FCoE (clients %s)",
                BnxeClientsHw(pUM));

    CLIENT_HW_RESET(pUM, LM_CLI_IDX_FCOE);

    /*********************************************************/

    BnxeLogDbg(pUM, "Turning off FCoE RX Mask");

    BnxeRxMask(pUM, LM_CLI_IDX_FCOE, LM_RX_MASK_ACCEPT_NONE);

    /*********************************************************/

    BnxeLogDbg(pUM, "Clearing the FCoE Multicast Table");

    BnxeMulticast(pUM, LM_CLI_IDX_FCOE, B_FALSE, NULL, B_TRUE);

    /*********************************************************/

    BnxeLogDbg(pUM, "Closing FCoE Connection");

    if ((rc = lm_close_eth_con(pLM, FCOE_CID(pLM), B_TRUE)) !=
        LM_STATUS_SUCCESS)
    {
        BnxeLogWarn(pUM, "Failed to close FCoE conn %d (%d)",
                    FCOE_CID(pLM), rc);
        BnxeFmErrorReport(pUM, DDI_FM_DEVICE_INVAL_STATE);
    }

    /*********************************************************/

    BnxeLogDbg(pUM, "Aborting FCoE TX Chains");

    BnxeTxPktsAbort(pUM, LM_CLI_IDX_FCOE);

    /*********************************************************/

    BnxeLogDbg(pUM, "Aborting FCoE RX Chains");

    BnxeRxPktsAbort(pUM, LM_CLI_IDX_FCOE);

    /*********************************************************/

    BnxeLogDbg(pUM, "Cleaning up FCoE Tx Pkts");

    BnxeTxPktsFini(pUM, LM_CLI_IDX_FCOE);

    /*********************************************************/

    BnxeLogDbg(pUM, "Cleaning up FCoE Rx Pkts");

    BnxeRxPktsFini(pUM, LM_CLI_IDX_FCOE);

    /*********************************************************/

    BnxeLogDbg(pUM, "Clearing FCoE Resources");

    if ((rc = lm_fc_clear_resc(pLM)) != LM_STATUS_SUCCESS)
    {
        BnxeLogWarn(pUM, "Failed to clear FCoE resources (%d)\n", rc);
    }

    lm_cid_recycled_cb_deregister(pLM, FCOE_CONNECTION_TYPE);

    /*********************************************************/

    BnxeHwStopCore(pUM);

    /*********************************************************/

    BnxeLogInfo(pUM, "BnxeHwStopFCOE: FCoE stopped (clients %s)",
                BnxeClientsHw(pUM));

    BNXE_LOCK_EXIT_HWINIT(pUM);
}


void BnxeHwStopL2(um_device_t * pUM)
{
    lm_device_t * pLM = &pUM->lm_dev;
    int idx, rc;

    BNXE_LOCK_ENTER_HWINIT(pUM);

    BnxeLogInfo(pUM, "BnxeHwStopL2: Stopping L2 (clients %s)",
                BnxeClientsHw(pUM));

    lm_mcp_indicate_client_unbind(&pUM->lm_dev, LM_CLI_IDX_NDIS);
    CLIENT_HW_RESET(pUM, LM_CLI_IDX_NDIS);

    /*********************************************************/

    BnxeLogDbg(pUM, "Turning off L2 RX Mask");

    BnxeRxMask(pUM, LM_CLI_IDX_NDIS, LM_RX_MASK_ACCEPT_NONE);

    /*********************************************************/

    BnxeLogDbg(pUM, "Clearing the L2 MAC Address");

    /*
     * Reset the mac_addr to hw programmed default and then clear
     * it in the firmware.
     */
    {
        u8_t mac_to_delete[ETHERNET_ADDRESS_SIZE];
        COPY_ETH_ADDRESS(pUM->lm_dev.params.mac_addr,
                         mac_to_delete);

        COPY_ETH_ADDRESS(pUM->lm_dev.hw_info.mac_addr,
                         pUM->lm_dev.params.mac_addr);
        memset(pUM->gldMac, 0, ETHERNET_ADDRESS_SIZE);

#if 0
        BnxeMacAddress(pUM, LM_CLI_IDX_NDIS, B_FALSE, mac_to_delete);
#else
        BnxeLogInfo(pUM, "Removing all MAC addresses");

        if ((rc = lm_clear_all_mac_addr(pLM,
                                        LM_CLI_CID(&pUM->lm_dev,
                                                   LM_CLI_IDX_NDIS))) !=
            LM_STATUS_SUCCESS)
        {
            BnxeLogWarn(pUM, "Failed to delete all MAC addresses (%d)", rc);
            BnxeFmErrorReport(pUM, DDI_FM_DEVICE_INVAL_STATE);
        }
#endif
    }

    /*********************************************************/

    BnxeLogDbg(pUM, "Clearing the L2 Multicast Table");

    BnxeMulticast(pUM, LM_CLI_IDX_NDIS, B_FALSE, NULL, B_TRUE);

    /*********************************************************/

    BnxeLogDbg(pUM, "Disabling RSS");

    BnxeRssDisable(pUM);

    /*********************************************************/

    /*
     * In Solaris when RX traffic is accepted, the system might generate and
     * attempt to send some TX packets (from within gld_recv()!).  Claiming any
     * TX locks before this point would create a deadlock.  The ISR would be
     * waiting for a lock acquired here that would never be freed, since we
     * in-turn would be waiting for the ISR to finish here. Consequently, we
     * acquire the TX lock as soon as we know that no TX traffic is a result of
     * RX traffic.
     */
    BNXE_LOCK_ENTER_GLDTX(pUM, RW_WRITER);

    /*********************************************************/

    BnxeLogDbg(pUM, "Closing L2 Ethernet Connections (%d)",
               pLM->params.rss_chain_cnt);

    LM_FOREACH_RSS_IDX(pLM, idx)
    {
        if ((rc = lm_close_eth_con(pLM, idx, B_TRUE)) !=
            LM_STATUS_SUCCESS)
        {
            BnxeLogWarn(pUM, "Failed to close Ethernet conn on RSS %d (%d)",
                        idx, rc);
            BnxeFmErrorReport(pUM, DDI_FM_DEVICE_INVAL_STATE);
        }
    }

    /*********************************************************/

    BnxeLogDbg(pUM, "Aborting L2 Tx Chains");

    BnxeTxPktsAbort(pUM, LM_CLI_IDX_NDIS);

    /*********************************************************/

    BnxeLogDbg(pUM, "Aborting L2 Rx Chains");

    BnxeRxPktsAbort(pUM, LM_CLI_IDX_NDIS);

    /*********************************************************/

    BNXE_LOCK_EXIT_GLDTX(pUM);

    /*********************************************************/

    BnxeLogDbg(pUM, "Cleaning up L2 Tx Pkts");

    BnxeTxPktsFini(pUM, LM_CLI_IDX_NDIS);

    /*********************************************************/

    BnxeLogDbg(pUM, "Cleaning up L2 Rx Pkts");

    BnxeRxPktsFini(pUM, LM_CLI_IDX_NDIS);

    /*********************************************************/

    BnxeHwStopCore(pUM);

    /*********************************************************/

    BnxeLogInfo(pUM, "BnxeHwStopL2: L2 stopped (clients %s)",
                BnxeClientsHw(pUM));

    BNXE_LOCK_EXIT_HWINIT(pUM);
}


/* Must be called with BNXE_LOCK_ENTER_HWINIT taken! */
void BnxeHwStopCore(um_device_t * pUM)
{
    lm_device_t *  pLM = &pUM->lm_dev;
    BnxeMemBlock * pMemBlock;
    BnxeMemDma *   pMemDma;
    lm_address_t   physAddr;
    int rc;

    physAddr.as_ptr = NULL;

    if (!pUM->hwInitDone)
    {
        /* already finished? (should never get here) */
        BnxeLogWarn(pUM, "BnxeHwStopCore: Hardware already stopped (clients %s)",
                    BnxeClientsHw(pUM));
        return;
    }

    if (BnxeIsClientBound(pUM))
    {
        BnxeLogInfo(pUM, "BnxeHwStopCore: Hardware cannot be stopped (clients %s)",
                    BnxeClientsHw(pUM));
        return;
    }

    BnxeLogInfo(pUM, "BnxeHwStopCore: Stopping hardware (clients %s)",
                BnxeClientsHw(pUM));

    mm_indicate_link(pLM, LM_STATUS_LINK_DOWN, pUM->devParams.lastIndMedium);

    /*********************************************************/

    BnxeLogDbg(pUM, "Stopping Timer");

    BnxeTimerStop(pUM);

    /*********************************************************/

    BnxeLogDbg(pUM, "Stopping DCBX");

    lm_dcbx_free_resc(pLM);

    /*********************************************************/

    BnxeLogDbg(pUM, "Stopping BRCM Chip");

    rc = lm_chip_stop(pLM);

    if (pUM->fmCapabilities &&
        BnxeCheckAccHandle(pLM->vars.reg_handle[BAR_0]) != DDI_FM_OK)
    {
        ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_DEGRADED);
    }

    if (rc != LM_STATUS_SUCCESS)
    {
        BnxeFmErrorReport(pUM, DDI_FM_DEVICE_INVAL_STATE);
    }

    atomic_swap_32(&pUM->chipStarted, B_FALSE);

    /*********************************************************/

    BnxeLogDbg(pUM, "Disabling Interrupts");

    BnxeIntrDisable(pUM);

    /*********************************************************/

    BnxeLogDbg(pUM, "Resetting BRCM Chip");

    lm_chip_reset(pLM, LM_REASON_DRIVER_SHUTDOWN);

    pUM->phyInitialized = B_FALSE;

    if (pUM->fmCapabilities &&
        BnxeCheckAccHandle(pUM->pPciCfg) != DDI_FM_OK)
    {
        ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_DEGRADED);
    }

    if (pUM->fmCapabilities &&
        BnxeCheckAccHandle(pLM->vars.reg_handle[BAR_0]) != DDI_FM_OK)
    {
        ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_DEGRADED);
    }

    /*********************************************************/

    while (!d_list_is_empty(&pUM->memBlockList))
    {
        pMemBlock = (BnxeMemBlock *)d_list_peek_head(&pUM->memBlockList);
        mm_rt_free_mem(pLM,
                       ((char *)pMemBlock->pBuf + BNXE_MEM_CHECK_LEN),
                       (pMemBlock->size - (BNXE_MEM_CHECK_LEN * 2)),
                       LM_CLI_IDX_NDIS);
    }

#ifndef BNXE_DEBUG_DMA_LIST
    while (!d_list_is_empty(&pUM->memDmaList))
    {
        pMemDma = (BnxeMemDma *)d_list_peek_head(&pUM->memDmaList);
        mm_rt_free_phys_mem(pLM,
                            pMemDma->size,
                            pMemDma->pDmaVirt,
                            physAddr,
                            LM_CLI_IDX_NDIS);
    }
#else
    {
        BnxeMemDma * pTmp;
        int i;

        BNXE_LOCK_ENTER_MEM(pUM);

        pTmp = (BnxeMemDma *)d_list_peek_head(&pUM->memDmaList);
        while (pTmp)
        {
            for (i = 0; i < pTmp->size; i++)
            {
                ((u8_t *)pTmp->pDmaVirt)[i] = 0x0;
            }

            pTmp = (BnxeMemDma *)d_list_next_entry(&pTmp->link);
        }

        d_list_add_head(&pUM->memDmaListSaved, &pUM->memDmaList);
        d_list_clear(&pUM->memDmaList);

        BNXE_LOCK_EXIT_MEM(pUM);

        BnxeVerifySavedDmaList(pUM);
    }
#endif /* BNXE_DEBUG_DMA_LIST */

    atomic_swap_32(&pUM->hwInitDone, B_FALSE);

    BnxeLogInfo(pUM, "BnxeHwStopCore: Hardware stopped (clients %s)",
                BnxeClientsHw(pUM));
}


int BnxeHwResume(um_device_t * pUM)
{
    lm_device_t * pLM = &pUM->lm_dev;
    int rc;

    BnxeLogDbg(pUM, "Setting Power State");
    lm_set_power_state(pLM, LM_POWER_STATE_D0, LM_WAKE_UP_MODE_NONE, FALSE);

    /* XXX Do we need it? */
    BnxeLogDbg(pUM, "Enabling PCI DMA");
    lm_enable_pci_dma(pLM);

    if (pUM->fmCapabilities &&
        BnxeCheckAccHandle(pLM->vars.reg_handle[BAR_0]) != DDI_FM_OK)
    {
        ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_LOST);
        return -1;
    }

    if (!pUM->plumbed)
    {
        /* XXX
         * Won't work under new model with multiple clients. Need an
         * extra pause mechanism/layer for suspend and resume.
         */
        if (BnxeHwStartCore(pUM))
        {
            return -1;
        }

        atomic_swap_32(&pUM->plumbed, B_TRUE);
    }

    return 0;
}


int BnxeHwSuspend(um_device_t * pUM)
{
    lm_device_t * pLM = &pUM->lm_dev;

    lm_reset_set_inprogress(pLM);
    lm_reset_mask_attn(pLM);

    disable_blocks_attention(pLM);

    if (pUM->plumbed)
    {
        /* XXX
         * Won't work under new model with multiple clients. Need an
         * extra pause mechanism/layer for suspend and resume.
         */
        BnxeHwStopCore(pUM);
        atomic_swap_32(&pUM->plumbed, B_FALSE);
    }

    /* XXX proper lm_wake_up_mode_t when WOL supported */
    lm_set_d3_nwuf(pLM, LM_WAKE_UP_MODE_NONE);

    if (pUM->fmCapabilities &&
        BnxeCheckAccHandle(pUM->pPciCfg) != DDI_FM_OK)
    {
        ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_DEGRADED);
        return LM_STATUS_FAILURE;
    }

    if (pUM->fmCapabilities &&
        BnxeCheckAccHandle(pLM->vars.reg_handle[BAR_0]) != DDI_FM_OK)
    {
        ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_DEGRADED);
        return -1;
    }

    /* XXX proper lm_wake_up_mode_t when WOL supported */
    lm_set_d3_mpkt(pLM, LM_WAKE_UP_MODE_NONE);

    if (pUM->fmCapabilities &&
        BnxeCheckAccHandle(pLM->vars.reg_handle[BAR_0]) != DDI_FM_OK)
    {
        ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_DEGRADED);
        return -1;
    }

    /* XXX Do we need it? */
    BnxeLogDbg(pUM, "Disabling PCI DMA");
    lm_disable_pci_dma(pLM, TRUE);

    if (pUM->fmCapabilities &&
        BnxeCheckAccHandle(pLM->vars.reg_handle[BAR_0]) != DDI_FM_OK)
    {
        ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_DEGRADED);
        return -1;
    }

    return 0;
}


#if (DEVO_REV > 3)

/*
 * This is a non-blocking function to make sure no more interrupt and dma memory
 * access of this hardware. We don't have to free any resource here.
 */
int BnxeHwQuiesce(um_device_t * pUM)
{
    lm_device_t * pLM = &pUM->lm_dev;

    /* XXX temporary block until bnxef supports fast reboot... */
    if (CLIENT_BOUND(pUM, LM_CLI_IDX_FCOE))
    {
        BnxeLogWarn(pUM, "Unable to quiesce, FCoE is bound!");
        return -1;
    }

#if 0
    lm_chip_stop(pLM);
#endif

    lm_disable_int(pLM);

    lm_chip_reset(pLM, LM_REASON_DRIVER_SHUTDOWN);

    BnxeRxPktsAbort(pUM, LM_CLI_IDX_NDIS);
    BnxeTxPktsAbort(pUM, LM_CLI_IDX_NDIS);

    return 0;
}

#endif

