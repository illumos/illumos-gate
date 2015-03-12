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

/*
 * The interrupt status bit vector is as follows:
 *
 *   bit 0: default interrupt
 *
 * Single Mode:
 *
 *   bits 1-16:  Function 1 (RSS 0-15)
 *
 * Multi-Function Mode:
 *
 *   bits 1-4:   Virtual Function 1 (RSS 0-3)
 *   bits 5-8:   Virtual Function 2 (RSS 4-7)
 *   bits 9-12:  Virtual Function 3 (RSS 8-11)
 *   bits 13-16: Virtual Function 4 (RSS 12-15)
 *
 * While processing interrupts the programmatic index used for the default
 * status block is 16 and the RSS status blocks are shifted down one (i.e.
 * 0-15).
 *
 * Solaris defaults to 2 MSIX interrupts per function so only the default
 * interrupt plus one RSS interrupt is used.  This default behavior can be
 * modified via the /etc/system configuration file.
 */


static inline char * BnxeIntrTypeName(int intrType)
{
    return (intrType == DDI_INTR_TYPE_MSIX)  ? "MSIX"  :
           (intrType == DDI_INTR_TYPE_MSI)   ? "MSI"   :
           (intrType == DDI_INTR_TYPE_FIXED) ? "FIXED" :
                                               "UNKNOWN";
}


static void BnxeFindDmaHandles(um_device_t * pUM)
{
    lm_address_t physAddr;
    BnxeMemDma * pTmp;
    u32_t idx;

    BNXE_LOCK_ENTER_MEM(pUM);

    /* find the RSS status blocks */

    LM_FOREACH_SB_ID(&pUM->lm_dev, idx)
    {
        if (CHIP_IS_E1x(&pUM->lm_dev))
        {
            physAddr.as_u32.low =
                pUM->lm_dev.vars.status_blocks_arr[idx].hc_status_block_data.e1x_sb_data.common.host_sb_addr.lo;
            physAddr.as_u32.high =
                pUM->lm_dev.vars.status_blocks_arr[idx].hc_status_block_data.e1x_sb_data.common.host_sb_addr.hi;
        }
        else
        {
            physAddr.as_u32.low =
                pUM->lm_dev.vars.status_blocks_arr[idx].hc_status_block_data.e2_sb_data.common.host_sb_addr.lo;
            physAddr.as_u32.high =
                pUM->lm_dev.vars.status_blocks_arr[idx].hc_status_block_data.e2_sb_data.common.host_sb_addr.hi;
        }

        pTmp = (BnxeMemDma *)d_list_peek_head(&pUM->memDmaList);
        while (pTmp)
        {
            if (pTmp->physAddr.as_ptr == physAddr.as_ptr)
            {
                break;
            }

            pTmp = (BnxeMemDma *)d_list_next_entry(&pTmp->link);
        }

        if (pTmp == NULL)
        {
            BnxeLogWarn(pUM, "Failed to find DMA handle for RSS status block %d", idx);
        }

        pUM->statusBlocks[idx] = pTmp;
    }

    /* find the default status block */

    pTmp = (BnxeMemDma *)d_list_peek_head(&pUM->memDmaList);
    while (pTmp)
    {
        if (pTmp->physAddr.as_ptr ==
            pUM->lm_dev.vars.gen_sp_status_block.blk_phy_address.as_ptr)
        {
            break;
        }

        pTmp = (BnxeMemDma *)d_list_next_entry(&pTmp->link);
    }

    if (pTmp == NULL)
    {
        BnxeLogWarn(pUM, "Failed to find DMA handle for default status block");
    }

    pUM->statusBlocks[DEF_STATUS_BLOCK_IGU_INDEX] = pTmp;

    BNXE_LOCK_EXIT_MEM(pUM);
}


void BnxeIntrIguSbEnable(um_device_t * pUM,
                         u32_t         idx,
                         boolean_t     fromISR)
{
    RxQueue * pRxQ = &pUM->rxq[idx];
    u32_t igu_id = (FCOE_CID(&pUM->lm_dev) == idx) ?
                       LM_NON_RSS_SB(&pUM->lm_dev) : idx;

    BNXE_LOCK_ENTER_INTR_FLIP(pUM, igu_id);

    if (fromISR)
    {
        /*
         * If in an ISR and poll mode is ON then poll mode was flipped in the
         * ISR which can occur during Rx processing.  If this is the case then
         * don't do anything.  Only re-enable the IGU when poll mode is OFF.
         */
        if (!pRxQ->inPollMode)
        {
            lm_int_ack_sb_enable(&pUM->lm_dev, igu_id);
        }
    }
    else
    {
        if (!pRxQ->inPollMode)
        {
            /* Why are intrs getting enabled on the ring twice...? */
            cmn_err(CE_PANIC,
                    "%s: Ring %d, enable intrs and NOT in poll mode!",
                    BnxeDevName(pUM), igu_id);
        }

        atomic_swap_32(&pRxQ->inPollMode, B_FALSE);
        pRxQ->intrEnableCnt++;

        lm_int_ack_sb_enable(&pUM->lm_dev, igu_id);
    }

    BNXE_LOCK_EXIT_INTR_FLIP(pUM, igu_id);
}


void BnxeIntrIguSbDisable(um_device_t * pUM,
                          u32_t         idx,
                          boolean_t     fromISR)
{
    RxQueue * pRxQ = &pUM->rxq[idx];
    u32_t igu_id = (FCOE_CID(&pUM->lm_dev) == idx) ?
                       LM_NON_RSS_SB(&pUM->lm_dev) : idx;

    BNXE_LOCK_ENTER_INTR_FLIP(pUM, igu_id);

    if (fromISR)
    {
        /* we should never get here when in poll mode... */
        ASSERT(pRxQ->inPollMode == B_FALSE);
        lm_int_ack_sb_disable(&pUM->lm_dev, igu_id);
    }
    else
    {
        if (pRxQ->inPollMode)
        {
            /* Why are intrs getting disabled on the ring twice...? */
            cmn_err(CE_PANIC,
                    "%s: Ring %d, disable intrs and ALREADY in poll mode!",
                    BnxeDevName(pUM), igu_id);
        }

        /*
         * Note here that the interrupt can already be disabled if GLDv3
         * is disabling the interrupt under the context of an ISR.  This is
         * OK as the inPollMode flag will tell the ISR not to re-enable the
         * interrupt upon return.
         */

        lm_int_ack_sb_disable(&pUM->lm_dev, igu_id);

        atomic_swap_32(&pRxQ->inPollMode, B_TRUE);
        pRxQ->intrDisableCnt++;
    }

    BNXE_LOCK_EXIT_INTR_FLIP(pUM, igu_id);
}


static void BnxeServiceDefSbIntr(um_device_t * pUM,
                                 boolean_t *   pPktsRxed,
                                 boolean_t *   pPktsTxed)
{
    lm_device_t * pLM = (lm_device_t *)pUM;
    u32_t         activity_flg         = 0;
    u16_t         lcl_attn_bits        = 0;
    u16_t         lcl_attn_ack         = 0;
    u16_t         asserted_proc_grps   = 0;
    u16_t         deasserted_proc_grps = 0;

    *pPktsRxed = B_FALSE;
    *pPktsTxed = B_FALSE;

    BnxeLogDbg(pUM, "Default INTR: Handling default status block %d", DEF_STATUS_BLOCK_INDEX);

    ddi_dma_sync(pUM->statusBlocks[DEF_STATUS_BLOCK_IGU_INDEX]->dmaHandle,
                 0, 0, DDI_DMA_SYNC_FORKERNEL);

    if (pUM->fmCapabilities &&
        BnxeCheckDmaHandle(pUM->statusBlocks[DEF_STATUS_BLOCK_IGU_INDEX]->dmaHandle) != DDI_FM_OK)
    {
        ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_DEGRADED);
    }

    pUM->intrSbCnt[DEF_STATUS_BLOCK_IGU_INDEX]++;

    if (lm_is_def_sb_updated(pLM) == 0)
    {
        BnxeLogDbg(pUM, "Default INTR: No change in default status index so bail!");
        pUM->intrSbNoChangeCnt[DEF_STATUS_BLOCK_IGU_INDEX]++;

        if (pUM->fmCapabilities &&
            BnxeCheckAccHandle(pLM->vars.reg_handle[BAR_0]) != DDI_FM_OK)
        {
            ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_DEGRADED);
        }

        return;
    }

    /* get a local copy of the indices from the status block */
    lm_update_def_hc_indices(pLM, DEF_STATUS_BLOCK_INDEX, &activity_flg);

    BnxeDbgBreakIfFastPath(pUM, !(activity_flg & LM_DEF_EVENT_MASK));

    BnxeLogDbg(pUM, "Default INTR: processing events on sb: %x, events: 0x%x",
               DEF_STATUS_BLOCK_INDEX, activity_flg);

    if (activity_flg & LM_DEF_ATTN_ACTIVE)
    {
        /* Attentions! Usually these are bad things we don't want to see */

        lm_get_attn_info(pLM, &lcl_attn_bits, &lcl_attn_ack);

        // NOTE: in case the status index of the attention has changed
        // already (while processing), we could override with it our local
        // copy. However, this is not a must, since it will be caught at the
        // end of the loop with the call to lm_is_sb_updated(). In case the
        // dpc_loop_cnt has exhausted, no worry, since will get an interrupt
        // for that at a later time.

        // find out which lines are asserted/deasserted with account to
        // their states, ASSERT if necessary.
        GET_ATTN_CHNG_GROUPS(pLM, lcl_attn_bits, lcl_attn_ack,
                             &asserted_proc_grps, &deasserted_proc_grps);

        BnxeLogDbg(pUM, "Default INTR: asserted_proc_grps: 0x%x, deasserted_proc_grps:0x%x",
                   asserted_proc_grps, deasserted_proc_grps);

        if (asserted_proc_grps)
        {
            lm_handle_assertion_processing(pLM, asserted_proc_grps);

            if (pUM->fmCapabilities &&
                BnxeCheckAccHandle(pLM->vars.reg_handle[BAR_0]) != DDI_FM_OK)
            {
                ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_DEGRADED);
            }
        }

        // keep in mind that in the same round, it is possible that this
        // func will have processing to do regarding deassertion on bits
        // that are different than the ones processed earlier for assertion
        // processing.

        if (deasserted_proc_grps)
        {
            lm_handle_deassertion_processing(pLM, deasserted_proc_grps);

            if (pUM->fmCapabilities &&
                BnxeCheckAccHandle(pLM->vars.reg_handle[BAR_0]) != DDI_FM_OK)
            {
                ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_DEGRADED);
            }
        }
    }

    if (activity_flg & LM_DEF_USTORM_ACTIVE)
    {
        /* Check for L4 TOE/iSCSI/FCoE Rx completions. */

        if (lm_is_rx_completion(pLM, ISCSI_CID(pLM)))  
        {
            BnxeDbgBreakMsg(pUM, "Unknown iSCSI Rx completion!");
        }

        if (lm_is_rx_completion(pLM, FCOE_CID(pLM)))  
        {
            *pPktsRxed = B_TRUE;
        }
    }

    if (activity_flg & LM_DEF_CSTORM_ACTIVE)
    {
        if (lm_is_eq_completion(pLM))
        {
            lm_service_eq_intr(pLM);
        }

        if (lm_is_tx_completion(pLM, FWD_CID(pLM)))
        {
            /* XXX Possible? */
            *pPktsTxed = B_TRUE;
        }

        if (lm_is_tx_completion(pLM, ISCSI_CID(pLM)))
        {
            /* XXX iSCSI Tx. NO! */
            BnxeDbgBreakMsg(pUM, "Unknown iSCSI Tx completion!");
        }

        if (lm_is_tx_completion(pLM, FCOE_CID(pLM)))
        {
            *pPktsTxed = B_TRUE;
        }
    }
}


/*
 * This is the polling path for an individual Rx Ring.  Here we simply pull
 * any pending packets out of the hardware and put them into the wait queue.
 * Note that there might already be packets in the wait queue which is OK as
 * the caller will call BnxeRxRingProcess() next to process the queue.
 */
void BnxePollRxRing(um_device_t * pUM,
                    u32_t         idx,
                    boolean_t *   pPktsRxed,
                    boolean_t *   pPktsTxed)
{
    lm_device_t * pLM = (lm_device_t *)pUM;
    u32_t         activity_flg = 0;
    u8_t          drv_rss_id = (u8_t)idx;

    *pPktsRxed = B_FALSE;
    *pPktsTxed = B_FALSE;

    BnxeLogDbg(pUM, "Ring Poll: Handling status block sb_id:%d drv_rss_id:%d",
               idx, drv_rss_id);

    /* use drv_rss_id for mapping into status block array (from LM) */
    ddi_dma_sync(pUM->statusBlocks[drv_rss_id]->dmaHandle,
                 0, 0, DDI_DMA_SYNC_FORKERNEL);

    if (pUM->fmCapabilities &&
        BnxeCheckDmaHandle(pUM->statusBlocks[drv_rss_id]->dmaHandle) != DDI_FM_OK)
    {
        ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_DEGRADED);
    }

    pUM->intrSbPollCnt[drv_rss_id]++;

    if (lm_is_sb_updated(pLM, drv_rss_id) == 0)
    {
        BnxeLogDbg(pUM, "Ring Poll: No change in status index so bail!");
        pUM->intrSbPollNoChangeCnt[drv_rss_id]++;
        return;
    }

    /* get a local copy of the indices from the status block */
    lm_update_fp_hc_indices(pLM, drv_rss_id, &activity_flg, &drv_rss_id);

    BnxeDbgBreakIf(pUM, !(activity_flg & LM_NON_DEF_EVENT_MASK));

    BnxeLogDbg(pUM, "Ring Poll: processing events on sb: %x, events: 0x%x",
               drv_rss_id, activity_flg);

    if (activity_flg & LM_NON_DEF_USTORM_ACTIVE)
    {
        /* Rx Completions */
        if (lm_is_rx_completion(pLM, drv_rss_id))
        {
            *pPktsRxed = B_TRUE;
        }

        /* XXX Check for L4 TOE/FCoE Rx completions. NO! */
    }

    if (activity_flg & LM_NON_DEF_CSTORM_ACTIVE)
    {
        /* Tx completions */
        if (lm_is_tx_completion(pLM, drv_rss_id))
        {
            *pPktsTxed = B_TRUE;
        }

        /* XXX Check for L4 Tx and L5 EQ completions. NO! */
    }
}


/*
 * This is the polling path for the FCoE Ring.  Here we don't pull any
 * pending packets out of the hardware.  We only care about FCoE Fast Path
 * completions.  FCoE slow path L2 packets are processed via the default
 * status block not the LM_NON_RSS_SB.  In this path we're assuming that
 * the FCoE driver is performing a crashdump.
 */
void BnxePollRxRingFCOE(um_device_t * pUM)
{
    lm_device_t * pLM = (lm_device_t *)pUM;
    u32_t         activity_flg = 0;

    u8_t sb_id = LM_NON_RSS_SB(pLM);
    u8_t drv_rss_id = FCOE_CID(pLM);

    BnxeLogDbg(pUM, "Ring Poll FCoE: Handling status block sb_id:%d drv_rss_id:%d",
               sb_id, drv_rss_id);

    /* use sb_id for mapping into status block array (from LM) */
    ddi_dma_sync(pUM->statusBlocks[sb_id]->dmaHandle,
                 0, 0, DDI_DMA_SYNC_FORKERNEL);

    if (pUM->fmCapabilities &&
        BnxeCheckDmaHandle(pUM->statusBlocks[sb_id]->dmaHandle) != DDI_FM_OK)
    {
        ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_DEGRADED);
    }

    pUM->intrSbPollCnt[sb_id]++;

    if (lm_is_sb_updated(pLM, sb_id) == 0)
    {
        BnxeLogDbg(pUM, "Ring Poll FCoE: No change in status index so bail!");
        pUM->intrSbPollNoChangeCnt[sb_id]++;
        return;
    }

    /* get a local copy of the indices from the status block */
    lm_update_fp_hc_indices(pLM, sb_id, &activity_flg, &drv_rss_id);

    BnxeDbgBreakIf(pUM, !(activity_flg & LM_NON_DEF_EVENT_MASK));

    BnxeLogDbg(pUM, "Ring Poll FCoE: processing events on sb: %x, events: 0x%x",
               sb_id, activity_flg);

    if (activity_flg & LM_NON_DEF_USTORM_ACTIVE)
    {
        if (lm_fc_is_eq_completion(pLM, drv_rss_id))
        {
            lm_fc_service_eq_intr(pLM, drv_rss_id);
        }
    }
}


static void BnxeServiceSbIntr(um_device_t * pUM,
                              u8_t          sb_id,
                              boolean_t *   pPktsRxed,
                              boolean_t *   pPktsTxed)
{
    lm_device_t * pLM = (lm_device_t *)pUM;
    u32_t         activity_flg = 0;
    u8_t          drv_rss_id;

    *pPktsRxed = B_FALSE;
    *pPktsTxed = B_FALSE;

    drv_rss_id = lm_map_igu_sb_id_to_drv_rss(pLM, sb_id);

    BnxeLogDbg(pUM, "Ring INTR: Handling status block sb_id:%d drv_rss_id:%d",
               sb_id, drv_rss_id);

    /* use sb_id for mapping into status block array (from LM) */
    ddi_dma_sync(pUM->statusBlocks[sb_id]->dmaHandle,
                 0, 0, DDI_DMA_SYNC_FORKERNEL);

    if (pUM->fmCapabilities &&
        BnxeCheckDmaHandle(pUM->statusBlocks[sb_id]->dmaHandle) != DDI_FM_OK)
    {
        ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_DEGRADED);
    }

    pUM->intrSbCnt[sb_id]++;

    if (lm_is_sb_updated(pLM, sb_id) == 0)
    {
        BnxeLogDbg(pUM, "Ring INTR: No change in status index so bail!");
        pUM->intrSbNoChangeCnt[sb_id]++;
        return;
    }

    /*
     * get a local copy of the indices from the status block
     * XXX note that here drv_rss_id is assigned to the sb_id
     */
    lm_update_fp_hc_indices(pLM, sb_id, &activity_flg, &drv_rss_id);

    BnxeDbgBreakIf(pUM, !(activity_flg & LM_NON_DEF_EVENT_MASK));

    BnxeLogDbg(pUM, "Ring INTR: processing events on sb: %x, events: 0x%x",
               drv_rss_id, activity_flg);

    if (activity_flg & LM_NON_DEF_USTORM_ACTIVE)
    {
        /* Rx Completions */
        if (lm_is_rx_completion(pLM, drv_rss_id))
        {
            *pPktsRxed = B_TRUE;
        }

        if (lm_fc_is_eq_completion(pLM, drv_rss_id))
        {
            lm_fc_service_eq_intr(pLM, drv_rss_id);
        }

        /* XXX Check for ISCSI-OOO and L4 TOE Rx completions. NO! */
    }

    if (activity_flg & LM_NON_DEF_CSTORM_ACTIVE)
    {
        /* Tx completions */
        if (lm_is_tx_completion(pLM, drv_rss_id))
        {
            *pPktsTxed = B_TRUE;
        }

        /* XXX Check for L4 Tx and L5 EQ completions. NO! */

        /* L4 Tx completions */
        if (lm_toe_is_tx_completion(pLM, drv_rss_id))
        {
            BnxeDbgBreakMsg(pUM, "Unknown TOE Tx completion!");
        }

        /* L5 EQ completions */
        if (lm_sc_is_eq_completion(pLM, drv_rss_id))
        {
            BnxeDbgBreakMsg(pUM, "Unknown iSCSI EQ completion!");
            //lm_sc_service_eq_intr(pLM, drv_rss_id);
        }
    }
}


uint_t BnxeIntrISR(caddr_t arg1, caddr_t arg2)
{
    um_device_t *         pUM = (um_device_t *)arg1;
    lm_device_t *         pLM = &pUM->lm_dev;
    lm_interrupt_status_t intrStatus = 0;
    boolean_t             pktsRxed   = 0;
    boolean_t             pktsTxed   = 0;
    u32_t                 rss_id     = 0;
    int                   idx        = (int)(uintptr_t)arg2;

    BNXE_LOCK_ENTER_INTR(pUM, idx);

    if (!pUM->intrEnabled)
    {
        pLM->vars.dbg_intr_in_wrong_state++;

        BNXE_LOCK_EXIT_INTR(pUM, idx);
        return DDI_INTR_UNCLAIMED;
    }

    BnxeLogDbg(pUM, "-> BNXE INTA Interrupt <-");

    if (pLM->vars.enable_intr)
    {
        intrStatus = lm_get_interrupt_status(pLM);

        if (pUM->fmCapabilities &&
            BnxeCheckAccHandle(pLM->vars.reg_handle[BAR_0]) != DDI_FM_OK)
        {
            ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_DEGRADED);
        }

        if (intrStatus == 0)
        {
            pLM->vars.dbg_intr_zero_status++;

            BNXE_LOCK_EXIT_INTR(pUM, idx);
            return DDI_INTR_UNCLAIMED;
        }
    }
    else
    {
        pLM->vars.dbg_intr_in_disabled++;
        BnxeLogDbg(pUM, "INTA INTR: we got an interrupt when disabled");

        BNXE_LOCK_EXIT_INTR(pUM, idx);
        return DDI_INTR_CLAIMED;
    }

    atomic_add_64((volatile uint64_t *)&pUM->intrFired, 1);

    while (intrStatus)
    {
        if (intrStatus & 0x1)
        {
            if (rss_id == 0)
            {
                lm_int_ack_def_sb_disable(pLM);

                BnxeServiceDefSbIntr(pUM, &pktsRxed, &pktsTxed);

                /*
                 * Default sb only handles FCoE only right now.  If this changes
                 * BnxeServiceDefSbIntr will have to change to return which CIDs
                 * have packets pending.
                 */

                if (pktsTxed) BnxeTxRingProcess(pUM, FCOE_CID(pLM));
                if (pktsRxed) BnxeRxRingProcess(pUM, FCOE_CID(pLM), B_FALSE, 0);

                lm_sq_post_pending(pLM);

                lm_int_ack_def_sb_enable(pLM);
            }
            else
            {
                /*
                 * (rss_id - 1) is used because the non-default sbs are located
                 * in lm_device at indices 0-15.
                 */

                lm_int_ack_sb_disable(pLM, (rss_id - 1));

                BnxeServiceSbIntr(pUM, (rss_id - 1), &pktsRxed, &pktsTxed);

                if (pktsTxed) BnxeTxRingProcess(pUM, (rss_id - 1));
                if (pktsRxed) BnxeRxRingProcess(pUM, (rss_id - 1), B_FALSE, 0);

                lm_sq_post_pending(pLM);

                lm_int_ack_sb_enable(pLM, (rss_id - 1));
            }
        }

        intrStatus >>= 1;
        rss_id++;
    }

    BNXE_LOCK_EXIT_INTR(pUM, idx);

    return DDI_INTR_CLAIMED;
}


uint_t BnxeIntrMISR(caddr_t arg1, caddr_t arg2)
{
    um_device_t * pUM = (um_device_t *)arg1;
    lm_device_t * pLM = &pUM->lm_dev;
    boolean_t     pktsRxed = 0;
    boolean_t     pktsTxed = 0;
    int           sb_id    = (int)(uintptr_t)arg2;
    u32_t         idx;

    BNXE_LOCK_ENTER_INTR(pUM, sb_id);

    if (!pUM->intrEnabled)
    {
        pLM->vars.dbg_intr_in_wrong_state++;

        BNXE_LOCK_EXIT_INTR(pUM, sb_id);
        return DDI_INTR_UNCLAIMED;
    }

    BnxeLogDbg(pUM, "-> BNXE MSIX Interrupt SB %d <-", sb_id);

    if (!pLM->vars.enable_intr)
    {
        pLM->vars.dbg_intr_in_disabled++;
        BnxeLogDbg(pUM, "MISR INTR: we got an interrupt when disabled");

        BNXE_LOCK_EXIT_INTR(pUM, sb_id);
        return DDI_INTR_CLAIMED;
    }

    atomic_add_64((volatile uint64_t *)&pUM->intrFired, 1);

    if (sb_id == DEF_STATUS_BLOCK_IGU_INDEX)
    {
        lm_int_ack_def_sb_disable(pLM);

        BnxeServiceDefSbIntr(pUM, &pktsRxed, &pktsTxed);

        /*
         * Default sb only handles FCoE only right now.  If this changes
         * BnxeServiceDefSbIntr will have to change to return which CIDs
         * have packets pending.
         */

        if (pktsTxed) BnxeTxRingProcess(pUM, FCOE_CID(pLM));
	if (pktsRxed) BnxeRxRingProcess(pUM, FCOE_CID(pLM), FALSE, 0);

        lm_sq_post_pending(pLM);

        lm_int_ack_def_sb_enable(pLM);
    }
    else
    {
        /*
         * Note that polling is not allowed by GLDv3 on the LM_NON_RSS_SB when
         * overlapped with FCoE. This is enforced by the BnxeRxRingIntrEnable
         * and BnxeRxRingIntrDisable routines. The FCoE driver IS ALLOWED to
         * put the SB into poll mode. FCoE trumps GLDv3/L2 and it's assumed
         * the FCoE driver is performing a crashdump in this case.
         */

        idx = ((sb_id == LM_NON_RSS_SB(pLM)) &&
               CLIENT_BOUND(pUM, LM_CLI_IDX_FCOE) &&
               (pUM->rssIntr.intrCount == LM_MAX_RSS_CHAINS(&pUM->lm_dev))) ?
                   FCOE_CID(pLM) : sb_id;

        if (pUM->rxq[idx].inPollMode)
        {
            /* Shouldn't be here! */
            cmn_err(CE_PANIC,
                    "%s: Interupt on RSS/MSIX ring %d when in poll mode!",
                    BnxeDevName(pUM), idx);
        }

        /* accounts for poll mode */
        BnxeIntrIguSbDisable(pUM, idx, B_TRUE);

        BnxeServiceSbIntr(pUM, sb_id, &pktsRxed, &pktsTxed);
 
        if (pktsTxed) BnxeTxRingProcess(pUM, sb_id);
        if (pktsRxed) BnxeRxRingProcess(pUM, sb_id, B_FALSE, 0);

        lm_sq_post_pending(pLM);

        /* accounts for poll mode */
        BnxeIntrIguSbEnable(pUM, idx, B_TRUE);
    }

    BNXE_LOCK_EXIT_INTR(pUM, sb_id);

    return DDI_INTR_CLAIMED;
}


static int BnxeGetInterruptCount(dev_info_t * pDev, int type, int intrTypes)
{
    int nintrs = 0;

    if (intrTypes & type)
    {
        return (ddi_intr_get_nintrs(pDev, type, &nintrs) != DDI_SUCCESS) ?
               -1 : nintrs;
    }

    return -1;
}


static boolean_t BnxeIntrBlockAlloc(um_device_t *   pUM,
                                    int             intrInum,
                                    int             intrCnt,
                                    BnxeIntrBlock * pBlock)

{
    dev_info_t * pDev = pUM->pDev;
    int intrRequest;
    int intrActual;
    int rc, i;

    if ((pUM->intrType == DDI_INTR_TYPE_FIXED) && (intrCnt != 1))
    {
        return B_FALSE;
    }

    intrRequest = intrCnt;
    intrActual  = 0;

    /*
     * We need to allocate an interrupt block array of maximum size which is
     * MAX_RSS_CHAINS plus one for the default interrupt.  Even though we
     * won't allocate all of those handlers the "inum" value passed to
     * ddi_intr_alloc() determines the starting index where the handlers
     * will be allocated.  See the multi-function block offset documentation
     * at the top of this file.
     */
    pBlock->intrHandleBlockSize =
        ((MAX_RSS_CHAINS + 1) * sizeof(ddi_intr_handle_t));

    if ((pBlock->pIntrHandleBlockAlloc =
         (ddi_intr_handle_t *)kmem_zalloc(pBlock->intrHandleBlockSize,
                                          KM_SLEEP)) == NULL)
    {
        BnxeLogWarn(pUM, "Memory alloc failed for isr handle block (inum=%d)!",
                    intrInum);
        return B_FALSE;
    }

    if ((rc = ddi_intr_alloc(pDev,
                             pBlock->pIntrHandleBlockAlloc,
                             pUM->intrType,
                             intrInum,
                             intrRequest,
                             &intrActual,
                             DDI_INTR_ALLOC_NORMAL)) != DDI_SUCCESS)
    {
        BnxeLogWarn(pUM, "Failed to allocate isr handle block (%d) (inum=%d cnt=%d)!",
                    rc, intrInum, intrRequest);
        kmem_free(pBlock->pIntrHandleBlockAlloc, pBlock->intrHandleBlockSize);
        return B_FALSE;
    }

    /*
     * Point 'pIntrHandleBlock' to the starting interrupt index in the
     * allocated interrupt block array.  This is done so we can easily enable,
     * disable, free, etc the interrupts.  For 10u8 and beyond the inum value
     * is also used as an index into the interrupt block so we point
     * pIntrHandleBlock to the inum'th index.  For 10u7 and below all
     * interrupt allocations start at index 0 per block.
     */
#if 0

#ifdef DDI_INTR_IRM
    pBlock->pIntrHandleBlock =
        &pBlock->pIntrHandleBlockAlloc[intrInum];
#else
    pBlock->pIntrHandleBlock =
        &pBlock->pIntrHandleBlockAlloc[0];
#endif

#else

    if (pBlock->pIntrHandleBlockAlloc[0])
    {
        pBlock->pIntrHandleBlock =
            &pBlock->pIntrHandleBlockAlloc[0];
    }
    else
    {
        pBlock->pIntrHandleBlock =
            &pBlock->pIntrHandleBlockAlloc[intrInum];
    }

#endif

    if (intrRequest != intrActual)
    {
        BnxeLogWarn(pUM, "Failed to allocate desired isr count (%d/%d)!",
                    intrActual, intrRequest);

#if 0
        for (i = 0; i < intrActual; i++)
        {
            ddi_intr_free(pBlock->pIntrHandleBlock[i]);
        }

        kmem_free(pBlock->pIntrHandleBlockAlloc, pBlock->intrHandleBlockSize);
        return B_FALSE;
#else
        if (intrActual == 0)
        {
            kmem_free(pBlock->pIntrHandleBlockAlloc, pBlock->intrHandleBlockSize);
            return B_FALSE;
        }
#endif
    }

    pBlock->intrCount = intrActual;

    if ((rc = ddi_intr_get_cap(pBlock->pIntrHandleBlock[0],
                               &pBlock->intrCapability)) != DDI_SUCCESS)
    {
        BnxeLogWarn(pUM, "Failed to get isr capability (%d)!", rc);
        goto BnxeIntrBlockAlloc_fail;
    }

    if ((rc = ddi_intr_get_pri(pBlock->pIntrHandleBlock[0],
                               &pBlock->intrPriority)) != DDI_SUCCESS)
    {
        BnxeLogWarn(pUM, "Failed to get isr priority (%d)!", rc);
        goto BnxeIntrBlockAlloc_fail;
    }

    if (pBlock->intrPriority >= ddi_intr_get_hilevel_pri())
    {
        BnxeLogWarn(pUM, "Interrupt priority is too high!");
        goto BnxeIntrBlockAlloc_fail;
    }

    return B_TRUE;

BnxeIntrBlockAlloc_fail:

    for (i = 0; i < intrActual; i++)
    {
        ddi_intr_free(pBlock->pIntrHandleBlock[i]);
    }

    kmem_free(pBlock->pIntrHandleBlockAlloc, pBlock->intrHandleBlockSize);

    memset(pBlock, 0, sizeof(BnxeIntrBlock));

    return B_FALSE;
}


static void BnxeIntrBlockFree(um_device_t *   pUM,
                              BnxeIntrBlock * pBlock)

{
    int i;

    if (pBlock->intrCount == 0)
    {
        memset(pBlock, 0, sizeof(BnxeIntrBlock));
        return;
    }

    for (i = 0; i < pBlock->intrCount; i++)
    {
        ddi_intr_free(pBlock->pIntrHandleBlock[i]);
    }

    kmem_free(pBlock->pIntrHandleBlockAlloc, pBlock->intrHandleBlockSize);

    memset(pBlock, 0, sizeof(BnxeIntrBlock));
}


static boolean_t BnxeIntrAddHandlers(um_device_t * pUM)
{
    int rc, i, j;

    switch (pUM->intrType)
    {
    case DDI_INTR_TYPE_MSIX:

        if ((rc = ddi_intr_add_handler(
                      pUM->defIntr.pIntrHandleBlock[0],
                      BnxeIntrMISR,
                      (caddr_t)pUM,
                      (caddr_t)(uintptr_t)DEF_STATUS_BLOCK_IGU_INDEX)) !=
            DDI_SUCCESS)
        {
            BnxeLogWarn(pUM, "Failed to add the MSIX default isr handler (%d)", rc);
            return B_FALSE;
        }

        for (i = 0; i < pUM->rssIntr.intrCount; i++)
        {
            if ((rc = ddi_intr_add_handler(
                          pUM->rssIntr.pIntrHandleBlock[i],
                          BnxeIntrMISR,
                          (caddr_t)pUM,
                          (caddr_t)(uintptr_t)i)) !=
                DDI_SUCCESS)
            {
                BnxeLogWarn(pUM, "Failed to add the MSIX RSS isr handler %d (%d)",
                            (i + NDIS_CID(&pUM->lm_dev)), rc);

                ddi_intr_remove_handler(pUM->defIntr.pIntrHandleBlock[0]);

                for (j = 0; j < i; j++) /* unwind */
                {
                    ddi_intr_remove_handler(pUM->rssIntr.pIntrHandleBlock[j]);
                }

                return B_FALSE;
            }
        }

        /*
         * fcoeIntr.intrCount == 1 implies LM_NON_RSS_SB (last) status block
         * was allocated for FCoE and there was no overlap with the RSS
         * allocation.
         */
        if (pUM->fcoeIntr.intrCount == 1)
        {
            if ((rc = ddi_intr_add_handler(
                          pUM->fcoeIntr.pIntrHandleBlock[0],
                          BnxeIntrMISR,
                          (caddr_t)pUM,
                          (caddr_t)(uintptr_t)LM_NON_RSS_SB(&pUM->lm_dev))) !=
                DDI_SUCCESS)
            {
                BnxeLogWarn(pUM, "Failed to add the MSIX FCoE isr handler (%d)", rc);

                ddi_intr_remove_handler(pUM->defIntr.pIntrHandleBlock[0]);

                for (i = 0; i < pUM->rssIntr.intrCount; i++)
                {
                    ddi_intr_remove_handler(pUM->rssIntr.pIntrHandleBlock[i]);
                }

                return B_FALSE;
            }
        }

        break;

    case DDI_INTR_TYPE_FIXED:

        if ((rc = ddi_intr_add_handler(
                               pUM->defIntr.pIntrHandleBlock[0],
                               BnxeIntrISR,
                               (caddr_t)pUM,
                               (caddr_t)(uintptr_t)DEF_STATUS_BLOCK_IGU_INDEX)) !=
            DDI_SUCCESS)
        {
            BnxeLogWarn(pUM, "Failed to add the fixed default isr handler (%d)", rc);
            return B_FALSE;
        }

        break;

    default:

        BnxeLogWarn(pUM, "Failed to add isr handler (unsupported type %d)!",
                    pUM->intrType);
        return B_FALSE;
    }

    return B_TRUE;
}


static void BnxeIntrBlockRemoveHandler(um_device_t *   pUM,
                                       BnxeIntrBlock * pBlock)
{
    int i;

    (void)pUM;

    if (pBlock->intrCount == 0)
    {
        return;
    }

    for (i = 0; i < pBlock->intrCount; i++)
    {
        ddi_intr_remove_handler(pBlock->pIntrHandleBlock[i]);
    }
}


static boolean_t BnxeIntrBlockEnable(um_device_t *   pUM,
                                     BnxeIntrBlock * pBlock)
{
    int rc, i, j;

    if (pBlock->intrCount == 0)
    {
        return B_TRUE;
    }

    if (pBlock->intrCapability & DDI_INTR_FLAG_BLOCK)
    {
        if ((rc = ddi_intr_block_enable(pBlock->pIntrHandleBlock,
                                        pBlock->intrCount)) != DDI_SUCCESS)
        {
            BnxeLogWarn(pUM, "Failed to enable isr block (%d)", rc);
            return B_FALSE;
        }
    }
    else
    {
        for (i = 0; i < pBlock->intrCount; i++)
        {
            if ((rc = ddi_intr_enable(pBlock->pIntrHandleBlock[i])) !=
                DDI_SUCCESS)
            {
                BnxeLogWarn(pUM, "Failed to enable isr %d (%d)", i, rc);

                for (j = 0; j < i; j++) /* unwind */
                {
                    ddi_intr_disable(pBlock->pIntrHandleBlock[j]);
                }

                return B_FALSE;
            }
        }
    }

    return B_TRUE;
}


static void BnxeIntrBlockDisable(um_device_t *   pUM,
                                 BnxeIntrBlock * pBlock)
{
    int i;

    if (pBlock->intrCount == 0)
    {
        return;
    }

    if (pBlock->intrCapability & DDI_INTR_FLAG_BLOCK)
    {
        ddi_intr_block_disable(pBlock->pIntrHandleBlock, pBlock->intrCount);
    }
    else
    {
        for (i = 0; i < pBlock->intrCount; i++)
        {
            ddi_intr_disable(pBlock->pIntrHandleBlock[i]);
        }
    }
}


int BnxeIntrEnable(um_device_t * pUM)
{
    BnxeMemDma * pDma;
    int rc, i, j;

    atomic_swap_64((volatile uint64_t *)&pUM->intrFired, 0);

    for (i = 0; i < (MAX_RSS_CHAINS + 1); i++)
    {
        pUM->intrSbCnt[i]         = 0;
        pUM->intrSbNoChangeCnt[i] = 0;
    }

    /* get the DMA handles for quick access to the status blocks for sync */
    BnxeFindDmaHandles(pUM);

    /* Enable the default interrupt... */

    if (!BnxeIntrBlockEnable(pUM, &pUM->defIntr))
    {
        BnxeLogWarn(pUM, "Failed to enable the default interrupt");
        return -1;
    }

    /* Enable the FCoE interrupt... */

    if (!BnxeIntrBlockEnable(pUM, &pUM->fcoeIntr))
    {
        BnxeLogWarn(pUM, "Failed to enable the FCoE interrupt");
        BnxeIntrBlockDisable(pUM, &pUM->defIntr);
        return -1;
    }

    /* Enable the RSS interrupts... */

    if (!BnxeIntrBlockEnable(pUM, &pUM->rssIntr))
    {
        BnxeLogWarn(pUM, "Failed to enable the RSS interrupt");
        BnxeIntrBlockDisable(pUM, &pUM->defIntr);
        BnxeIntrBlockDisable(pUM, &pUM->fcoeIntr);
        return -1;
    }

    /* allow the hardware to generate interrupts */
    atomic_swap_32(&pUM->intrEnabled, B_TRUE);
    lm_enable_int(&pUM->lm_dev);

    if (pUM->fmCapabilities &&
        BnxeCheckAccHandle(pUM->lm_dev.vars.reg_handle[BAR_0]) != DDI_FM_OK)
    {
        ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_DEGRADED);
    }

/* XXX do not remove this... edavis */
drv_usecwait(1000000); /* :-( */

    return 0;
}


void BnxeIntrDisable(um_device_t * pUM)
{
    int rc, i;

    /* stop the device from generating any interrupts */
    lm_disable_int(&pUM->lm_dev);

    if (pUM->fmCapabilities &&
        BnxeCheckAccHandle(pUM->lm_dev.vars.reg_handle[BAR_0]) != DDI_FM_OK)
    {
        ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_DEGRADED);
    }

    atomic_swap_32(&pUM->intrEnabled, B_FALSE);

    /*
     * Ensure the ISR no longer touches the hardware by making sure the ISR
     * is not running or the current run completes.   Since interrupts were
     * disabled before here and intrEnabled is FALSE, we can be sure
     * interrupts will no longer be processed.
     */
    for (i = 0; i < (MAX_RSS_CHAINS + 1); i++)
    {
        BNXE_LOCK_ENTER_INTR(pUM, i);
        BNXE_LOCK_EXIT_INTR(pUM, i);
    }

    /* Disable the default interrupt... */

    BnxeIntrBlockDisable(pUM, &pUM->defIntr);

    /* Disable the FCoE interrupt... */

    BnxeIntrBlockDisable(pUM, &pUM->fcoeIntr);

    /* Disable the RSS interrupts... */

    BnxeIntrBlockDisable(pUM, &pUM->rssIntr);
}


boolean_t BnxeIntrInit(um_device_t * pUM)
{
    dev_info_t * pDev;
    int intrTypes = 0;
    int intrTotalAlloc = 0;
    int numMSIX, numMSI, numFIX;
    int rc, i;

    pDev = pUM->pDev;

    atomic_swap_32(&pUM->intrEnabled, B_FALSE);

    if ((rc = ddi_intr_get_supported_types(pDev, &intrTypes)) != DDI_SUCCESS)
    {
        BnxeLogWarn(pUM, "Failed to get supported interrupt types (%d)", rc);
        return B_FALSE;
    }

    numMSIX = BnxeGetInterruptCount(pDev, DDI_INTR_TYPE_MSIX, intrTypes);
    numMSI  = BnxeGetInterruptCount(pDev, DDI_INTR_TYPE_MSI, intrTypes);
    numFIX  = BnxeGetInterruptCount(pDev, DDI_INTR_TYPE_FIXED, intrTypes);

    if (numFIX <= 0)
    {
        BnxeLogWarn(pUM, "Fixed interrupt not supported!");
        return B_FALSE;
    }

    memset(&pUM->defIntr,  0, sizeof(BnxeIntrBlock));
    memset(&pUM->rssIntr,  0, sizeof(BnxeIntrBlock));
    memset(&pUM->fcoeIntr, 0, sizeof(BnxeIntrBlock));

    if (pUM->devParams.disableMsix)
    {
        BnxeLogInfo(pUM, "Forcing fixed level interrupts.");
        pUM->lm_dev.params.interrupt_mode = LM_INT_MODE_INTA;
        pUM->intrType                     = DDI_INTR_TYPE_FIXED;
    }
    else if (numMSIX > 0)
    {
        pUM->lm_dev.params.interrupt_mode = LM_INT_MODE_MIMD;
        pUM->intrType                     = DDI_INTR_TYPE_MSIX;
    }
    else /* numFIX */
    {
        pUM->lm_dev.params.interrupt_mode = LM_INT_MODE_INTA;
        pUM->intrType                     = DDI_INTR_TYPE_FIXED;
    }

    while (1)
    {
        /* allocate the default interrupt */

        if (!BnxeIntrBlockAlloc(pUM,
                                0,
                                1,
                                &pUM->defIntr))
        {
            BnxeLogWarn(pUM, "Failed to allocate default %s interrupt!",
                        BnxeIntrTypeName(pUM->intrType));
            goto BnxeIntrInit_alloc_fail;
        }

        intrTotalAlloc++;

        if (pUM->intrType == DDI_INTR_TYPE_FIXED)
        {
            /* only one interrupt allocated for fixed (default) */
            break;
        }

        if (BnxeProtoFcoeAfex(pUM))
        {
            pUM->devParams.numRings = 0;
        }
        else
        {
            /* allocate the RSS interrupts */

            while (pUM->devParams.numRings > 0)
            {
                if (!BnxeIntrBlockAlloc(pUM,
                                        (NDIS_CID(&pUM->lm_dev) + 1),
                                        pUM->devParams.numRings,
                                        &pUM->rssIntr))
                {
                    BnxeLogWarn(pUM, "Failed to allocate %d RSS %s interrupts!",
                                pUM->devParams.numRings,
                                BnxeIntrTypeName(pUM->intrType));
                    pUM->devParams.numRings >>= 1;
                    continue;
                }

                break;
            }

            if (pUM->devParams.numRings == 0)
            {
                BnxeIntrBlockFree(pUM, &pUM->defIntr);
                goto BnxeIntrInit_alloc_fail;
            }

            BnxeLogInfo(pUM, "Allocated %d RSS %s interrupts.",
                        pUM->rssIntr.intrCount,
                        BnxeIntrTypeName(pUM->intrType));

            intrTotalAlloc += pUM->rssIntr.intrCount; /* intrCount <= numRings */
        }

        /*
         * Allocate the FCoE interrupt only if all available status blocks
         * were not taken up by the RSS chains.  If they were then the last
         * status block (LM_NON_RSS_SB) is overloaded for both RSS and FCoE.
         */

        if (BNXE_FCOE(pUM))
        {
            if (pUM->rssIntr.intrCount < LM_MAX_RSS_CHAINS(&pUM->lm_dev))
            {
                if (!BnxeIntrBlockAlloc(pUM,
                                        (LM_NON_RSS_SB(&pUM->lm_dev) + 1),
                                        1,
                                        &pUM->fcoeIntr))
                {
                    BnxeLogWarn(pUM, "Failed to allocate FCoE %s interrupt!",
                                BnxeIntrTypeName(pUM->intrType));
                    BnxeIntrBlockFree(pUM, &pUM->defIntr);
                    BnxeIntrBlockFree(pUM, &pUM->rssIntr);
                    goto BnxeIntrInit_alloc_fail;
                }

                intrTotalAlloc++;
            }
            else
            {
                /* to be safe, sets fcoeIntr.intrCount to 0 */
                memset(&pUM->fcoeIntr, 0, sizeof(BnxeIntrBlock));
            }
        }

        break;

BnxeIntrInit_alloc_fail:

        if (pUM->intrType == DDI_INTR_TYPE_FIXED)
        {
            return B_FALSE;
        }

        /* fall back to fixed a retry allocation */
        intrTotalAlloc = 0;
        pUM->lm_dev.params.interrupt_mode = LM_INT_MODE_INTA;
        pUM->intrType                     = DDI_INTR_TYPE_FIXED;
    }

    if (pUM->intrType == DDI_INTR_TYPE_MSIX)
    {
        pUM->devParams.numRings          = pUM->rssIntr.intrCount;
        pUM->lm_dev.params.rss_chain_cnt = pUM->rssIntr.intrCount;
        pUM->lm_dev.params.tss_chain_cnt = pUM->rssIntr.intrCount;
    }
    else
    {
        /* fixed level (no rings)... */
        pUM->devParams.numRings          = 0;
        pUM->lm_dev.params.rss_chain_cnt = 1;
        pUM->lm_dev.params.tss_chain_cnt = 1;

        BnxeLogWarn(pUM, "Using Fixed Level Interrupts! (set ddi_msix_alloc_limit in /etc/system)");
    }

    BnxeLogInfo(pUM, "Interrupts (Supported - %d Fixed / %d MSI / %d MSIX) (Allocated - %d %s)",
                numFIX, numMSI, numMSIX, intrTotalAlloc, BnxeIntrTypeName(pUM->intrType));

    if (!BnxeIntrAddHandlers(pUM))
    {
        BnxeLogWarn(pUM, "Failed to add interrupts!");
        BnxeIntrBlockFree(pUM, &pUM->defIntr);
        BnxeIntrBlockFree(pUM, &pUM->fcoeIntr);
        BnxeIntrBlockFree(pUM, &pUM->rssIntr);
        return B_FALSE;
    }

    /* copy default priority and assume rest are the same (for mutex) */
    pUM->intrPriority = pUM->defIntr.intrPriority;

    return B_TRUE;
}


void BnxeIntrFini(um_device_t * pUM)
{
    int i;

    BnxeIntrBlockDisable(pUM, &pUM->defIntr);
    BnxeIntrBlockRemoveHandler(pUM, &pUM->defIntr);
    BnxeIntrBlockFree(pUM, &pUM->defIntr);

    BnxeIntrBlockDisable(pUM, &pUM->fcoeIntr);
    BnxeIntrBlockRemoveHandler(pUM, &pUM->fcoeIntr);
    BnxeIntrBlockFree(pUM, &pUM->fcoeIntr);

    BnxeIntrBlockDisable(pUM, &pUM->rssIntr);
    BnxeIntrBlockRemoveHandler(pUM, &pUM->rssIntr);
    BnxeIntrBlockFree(pUM, &pUM->rssIntr);
}

