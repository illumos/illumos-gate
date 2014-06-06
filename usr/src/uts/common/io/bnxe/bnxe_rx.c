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


ddi_dma_attr_t bnxeRxDmaAttrib =
{
    DMA_ATTR_V0,         /* dma_attr_version */
    0,                   /* dma_attr_addr_lo */
    0xffffffffffffffff,  /* dma_attr_addr_hi */
    0xffffffffffffffff,  /* dma_attr_count_max */
    BNXE_DMA_ALIGNMENT,  /* dma_attr_align */
    0xffffffff,          /* dma_attr_burstsizes */
    1,                   /* dma_attr_minxfer */
    0xffffffffffffffff,  /* dma_attr_maxxfer */
    0xffffffffffffffff,  /* dma_attr_seg */
    1,                   /* dma_attr_sgllen */
    1,                   /* dma_attr_granular */
    0,                   /* dma_attr_flags */
};


static void BnxeRxPostBuffers(um_device_t * pUM,
                              int           idx,
                              s_list_t *    pReclaimList)
{
    lm_rx_chain_t * pLmRxChain = &LM_RXQ(&pUM->lm_dev, idx);
    u32_t           returnedBytes = 0;
    lm_packet_t *   pLmPkt;

    /* return bytes from reclaimed list to LM */
    pLmPkt = (lm_packet_t *)s_list_peek_head(pReclaimList);
    while (pLmPkt)
    {
        returnedBytes += pLmPkt->size;
        pLmPkt = (lm_packet_t *)s_list_next_entry(&pLmPkt->link);
    }

    BNXE_LOCK_ENTER_RX(pUM, idx);

    if (pUM->rxq[idx].rxLowWater > s_list_entry_cnt(&pLmRxChain->active_descq))
    {
        pUM->rxq[idx].rxLowWater = s_list_entry_cnt(&pLmRxChain->active_descq);
    }

    lm_return_packet_bytes(&pUM->lm_dev, idx, returnedBytes);

    s_list_add_tail(&pLmRxChain->common.free_descq, pReclaimList);
    s_list_clear(pReclaimList);

#if 0
    /*
     * Don't post buffers if we don't have too many free buffers and there are a
     * lot of buffers already posted.
     */
    if (lm_bd_chain_avail_bds(&pLmRxChain->bd_chain) < 32)
    {
        BNXE_LOCK_EXIT_RX(pUM, idx);
        return;
    }

    /*
     * Don't post buffers if there aren't really that many to post yet.
     */
    if (s_list_entry_cnt(&pLmRxChain->common.free_descq) < 32)
    {
        BNXE_LOCK_EXIT_RX(pUM, idx);
        return;
    }
#endif

    lm_post_buffers(&pUM->lm_dev, idx, NULL, 0);

    BNXE_LOCK_EXIT_RX(pUM, idx);
}


static u32_t BnxeRxPktDescrSize(um_device_t * pUM)
{
    u32_t descSize;

    (void)pUM;

    descSize = sizeof(um_rxpacket_t) + SIZEOF_SIG;

    return ALIGN_VALUE_TO_WORD_BOUNDARY(descSize);
}


static void BnxeRxPktDescrFree(um_device_t *   pUM,
                               um_rxpacket_t * pRxPkt)
{
    u32_t descSize;
    caddr_t pMem;

    BnxeDbgBreakIfFastPath(pUM, SIG(pRxPkt) != L2PACKET_RX_SIG);

    descSize = BnxeRxPktDescrSize(pUM);
    pMem = (caddr_t)pRxPkt - SIZEOF_SIG;

    kmem_free(pMem, descSize);
}


static void BnxeRxPktFree(char * free_arg)
{
    um_rxpacket_t * pRxPkt = (um_rxpacket_t *)free_arg;
    um_device_t *   pUM    = (um_device_t *)pRxPkt->pUM;
    int             idx    = pRxPkt->idx;
    s_list_t        doneRxQ;

    if (pUM->magic != BNXE_MAGIC)
    {
        /*
         * Oh my!  The free_arg data got corrupted.  Log a message and leak this
         * packet.  We don't decrement the 'up in the stack count' since we
         * can't be sure this packet really was a packet we previously sent up.
         */
        BnxeLogWarn(NULL, "ERROR freeing packet - UM is invalid! (%p)", pRxPkt);
        return;
    }

    if (pUM->rxBufSignature[LM_CHAIN_IDX_CLI(&pUM->lm_dev, idx)] !=
        pRxPkt->signature)
    {
        /*
         * The stack is freeing a packet that was from a previous plumb of
         * the interface.
         */
        pRxPkt->lm_pkt.u1.rx.mem_phys[0].as_u64 = 0;
        pRxPkt->rx_info.mem_virt = NULL;
        pRxPkt->rx_info.mem_size = 0;

        ddi_dma_unbind_handle(pRxPkt->dmaHandle);
        ddi_dma_mem_free(&pRxPkt->dmaAccHandle);
        ddi_dma_free_handle(&pRxPkt->dmaHandle);

        BnxeRxPktDescrFree(pUM, pRxPkt);
    }
    else
    {
        s_list_clear(&doneRxQ);

        BNXE_LOCK_ENTER_DONERX(pUM, idx);

        s_list_push_tail(&pUM->rxq[idx].doneRxQ,
                         &((lm_packet_t *)pRxPkt)->link);

        /* post packets when a bunch are ready */
        if (s_list_entry_cnt(&pUM->rxq[idx].doneRxQ) >= pUM->devParams.maxRxFree)
        {
            doneRxQ = pUM->rxq[idx].doneRxQ;
            s_list_clear(&pUM->rxq[idx].doneRxQ);
        }

        BNXE_LOCK_EXIT_DONERX(pUM, idx);

        if (s_list_entry_cnt(&doneRxQ))
        {
            BnxeRxPostBuffers(pUM, idx, &doneRxQ);
        }
    }

    atomic_dec_32(&pUM->rxq[idx].rxBufUpInStack);
}


boolean_t BnxeWaitForPacketsFromClient(um_device_t * pUM,
                                       int           cliIdx)
{
    int i, idx, cnt=0, tot=0;

    switch (cliIdx)
    {
    case LM_CLI_IDX_FCOE:

        for (i = 0; i < 5; i++)
        {
            if ((cnt = pUM->rxq[FCOE_CID(&pUM->lm_dev)].rxBufUpInStack) == 0)
            {
                break;
            }

            /* twiddle our thumbs for one second */
            delay(drv_usectohz(1000000));
        }

        if (cnt)
        {
            BnxeLogWarn(pUM, "%d packets still held by FCoE (chain %d)!",
                        cnt, FCOE_CID(&pUM->lm_dev));
            return B_FALSE;
        }

        break;

    case LM_CLI_IDX_NDIS:

        tot = 0;

        LM_FOREACH_RSS_IDX(&pUM->lm_dev, idx)
        {
            for (i = 0; i < 5; i++)
            {
                if ((cnt = pUM->rxq[idx].rxBufUpInStack) == 0)
                {
                    break;
                }

                /* twiddle our thumbs for one second */
                delay(drv_usectohz(1000000));
            }

            tot += cnt;
        }

        if (tot)
        {
            BnxeLogWarn(pUM, "%d packets still held by the stack (chain %d)!",
                        tot, idx);
            return B_FALSE;
        }

        break;

    default:

        BnxeLogWarn(pUM, "ERROR: Invalid cliIdx for BnxeWaitForPacketsFromClient (%d)", cliIdx);
        break;
    }

    return B_TRUE;
}


/* numBytes is only valid when polling is TRUE */
mblk_t * BnxeRxRingProcess(um_device_t * pUM,
                           int           idx,
                           boolean_t     polling,
                           int           numBytes)
{
    RxQueue *       pRxQ;
    lm_rx_chain_t * pLmRxChain;
    u32_t           activeDescqCount;
    boolean_t       forceCopy;
    um_rxpacket_t * pRxPkt;
    lm_packet_t *   pLmPkt;
    u32_t           pktLen;
    boolean_t       dataCopied;
    u32_t           notCopiedCount;
    mblk_t *        pMblk;
    int             ofldFlags;
    mblk_t *        head = NULL;
    mblk_t *        tail = NULL;
    s_list_t        rxList;
    s_list_t        reclaimList;
    int             procBytes = 0;
    s_list_t        tmpList;
    sp_cqes_info    sp_cqes;
    u32_t           pktsRxed;

    pRxQ = &pUM->rxq[idx];

    s_list_clear(&tmpList);

    /* get the list of packets received */
    BNXE_LOCK_ENTER_RX(pUM, idx);

    pktsRxed = lm_get_packets_rcvd(&pUM->lm_dev, idx, &tmpList, &sp_cqes);

    /* grab any waiting packets */
    rxList = pRxQ->waitRxQ;
    s_list_clear(&pRxQ->waitRxQ);

    /* put any new packets at the end of the queue */
    s_list_add_tail(&rxList, &tmpList);

    BNXE_LOCK_EXIT_RX(pUM, idx);

    /* now complete the ramrods */
    lm_complete_ramrods(&pUM->lm_dev, &sp_cqes);

    if (s_list_entry_cnt(&rxList) == 0)
    {
        return NULL;
    }

    s_list_clear(&reclaimList);
    notCopiedCount = 0;

    pLmRxChain = &LM_RXQ(&pUM->lm_dev, idx);

    activeDescqCount = s_list_entry_cnt(&pLmRxChain->active_descq);

    forceCopy = (activeDescqCount <
                 (pUM->lm_dev.params.l2_rx_desc_cnt[LM_CHAIN_IDX_CLI(&pUM->lm_dev, idx)] >> 3));

    /* send the packets up the stack */
    while (1)
    {
        pRxPkt = (um_rxpacket_t *)s_list_pop_head(&rxList);
        if (pRxPkt == NULL)
        {
            break;
        }

        pLmPkt = &(pRxPkt->lm_pkt);

        if (pLmPkt->status != LM_STATUS_SUCCESS)
        {
            /* XXX increment error stat? */
            s_list_push_tail(&reclaimList, &pLmPkt->link);
            continue;
        }

        pktLen = pLmPkt->size;

        if (polling == TRUE)
        {
            /* When polling an rx ring we can only process up to numBytes */
            if ((procBytes + pktLen) <= numBytes)
            {
                /* continue to process this packet */
                procBytes += pktLen;
            }
            else
            {
                /* put this packet not processed back on the list (front) */
                s_list_push_head(&rxList, &pRxPkt->lm_pkt.link);
                break;
            }
        }

        (void)ddi_dma_sync(pRxPkt->dmaHandle,
                           0,
                           pktLen,
                           DDI_DMA_SYNC_FORKERNEL);

        if (pUM->fmCapabilities &&
            BnxeCheckDmaHandle(pRxPkt->dmaHandle) != DDI_FM_OK)
        {
            ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_DEGRADED);
        }

        dataCopied = B_FALSE;

        if (forceCopy ||
            (pUM->devParams.rxCopyThreshold &&
             (pktLen < pUM->devParams.rxCopyThreshold)))
        {
            if ((pMblk = allocb(pktLen, BPRI_MED)) == NULL)
            {
                pRxQ->rxDiscards++;
                s_list_push_tail(&reclaimList, &pLmPkt->link);
                continue;
            }

            /* copy the packet into the new mblk */
            bcopy((pRxPkt->rx_info.mem_virt + BNXE_DMA_RX_OFFSET),
                  pMblk->b_rptr, pktLen);
            pMblk->b_wptr = (pMblk->b_rptr + pktLen);
            dataCopied = B_TRUE;

            pRxQ->rxCopied++;

            goto BnxeRxRingProcess_sendup;
        }

        if ((activeDescqCount == 0) && (s_list_entry_cnt(&rxList) == 0))
        {
            /*
             * If the hardware is out of receive buffers and we are on the last
             * receive packet then drop the packet.  We do this because we might
             * not be able to allocate any new receive buffers before the ISR
             * completes.  If this happens, the driver will enter an infinite
             * interrupt loop where the hardware is requesting rx buffers the
             * driver cannot allocate.  To prevent a system livelock we leave
             * one buffer perpetually available.  Note that we do this after
             * giving the double copy code a chance to claim the packet.
             */

            /* FIXME
             * Make sure to add one more to the rx packet descriptor count
             * before allocating them.
             */

            pRxQ->rxDiscards++;
            s_list_push_tail(&reclaimList, &pLmPkt->link);
            continue;
        }

        /*
         * If we got here then the packet wasn't copied so we need to create a
         * new mblk_t which references the lm_packet_t buffer.
         */

        pRxPkt->freeRtn.free_func = BnxeRxPktFree;
        pRxPkt->freeRtn.free_arg  = (char *)pRxPkt;
        pRxPkt->pUM               = (void *)pUM;
        pRxPkt->idx               = idx;

        if ((pMblk = desballoc((pRxPkt->rx_info.mem_virt + BNXE_DMA_RX_OFFSET),
                               pktLen,
                               BPRI_MED,
                               &pRxPkt->freeRtn)) == NULL)
        {
            pRxQ->rxDiscards++;
            s_list_push_tail(&reclaimList, &pLmPkt->link);
            continue;
        }

        pMblk->b_wptr = (pMblk->b_rptr + pktLen);

BnxeRxRingProcess_sendup:

        /*
         * Check if the checksum was offloaded so we can pass the result to
         * the stack.
         */
        ofldFlags = 0;

        if ((pUM->devParams.enabled_oflds & LM_OFFLOAD_RX_IP_CKSUM) &&
            (pRxPkt->rx_info.flags & LM_RX_FLAG_IP_CKSUM_IS_GOOD))
        {
            ofldFlags |= HCK_IPV4_HDRCKSUM_OK;
        }

        if (((pUM->devParams.enabled_oflds & LM_OFFLOAD_RX_TCP_CKSUM) &&
             (pRxPkt->rx_info.flags & LM_RX_FLAG_TCP_CKSUM_IS_GOOD)) ||
            ((pUM->devParams.enabled_oflds & LM_OFFLOAD_RX_UDP_CKSUM) &&
             (pRxPkt->rx_info.flags & LM_RX_FLAG_UDP_CKSUM_IS_GOOD)))
        {
            ofldFlags |= HCK_FULLCKSUM_OK;
        }

        if (ofldFlags != 0)
        {
            mac_hcksum_set(pMblk, 0, 0, 0, 0, ofldFlags);
        }

        /*
         * If the packet data was copied into a new recieve buffer then put this
         * descriptor in a list to be reclaimed later.  If not, then increment a
         * counter so we can track how many of our descriptors are held by the
         * stack.
         */
        if (dataCopied == B_TRUE)
        {
            s_list_push_tail(&reclaimList, &pLmPkt->link);
        }
        else
        {
            notCopiedCount++;
        }

        if (head == NULL)
        {
            head = pMblk;
        }
        else
        {
            tail->b_next = pMblk;
        }

        tail         = pMblk;
        tail->b_next = NULL;

#if 0
        BnxeDumpPkt(pUM, 
                    (BNXE_FCOE(pUM) && (idx == FCOE_CID(&pUM->lm_dev))) ?
                        "<- FCoE L2 RX <-" : "<- L2 RX <-",
                    pMblk, B_TRUE);
#endif
    }

    if (head)
    {
        if (notCopiedCount)
        {
            /* track all non-copied packets that will be held by the stack */
            atomic_add_32(&pUM->rxq[idx].rxBufUpInStack, notCopiedCount);
        }

        /* pass the mblk chain up the stack */
        if (polling == FALSE)
        {

/* XXX NEED TO ADD STATS FOR RX PATH UPCALLS */

            if (BNXE_FCOE(pUM) && (idx == FCOE_CID(&pUM->lm_dev)))
            {
                /* XXX verify fcoe frees all packets on success or error */
                if (pUM->fcoe.pDev && pUM->fcoe.bind.cliIndicateRx)
                {
                    pUM->fcoe.bind.cliIndicateRx(pUM->fcoe.pDev, head);
                }
                else
                {
                    /* FCoE isn't bound?  Reclaim the chain... */
                    freemsgchain(head);
                    head = NULL;
                }
            }
            else
            {
#if defined(BNXE_RINGS) && (defined(__S11) || defined(__S12))
                mac_rx_ring(pUM->pMac,
                            pUM->rxq[idx].ringHandle,
                            head,
                            pUM->rxq[idx].genNumber);
#else
                mac_rx(pUM->pMac,
                       pUM->macRxResourceHandles[idx],
                       head);
#endif
            }
        }
    }

    if ((polling == TRUE) && s_list_entry_cnt(&rxList))
    {
        /* put the packets not processed back on the list (front) */
        BNXE_LOCK_ENTER_RX(pUM, idx);
        s_list_add_head(&pRxQ->waitRxQ, &rxList);
        BNXE_LOCK_EXIT_RX(pUM, idx);
    }

    if (s_list_entry_cnt(&reclaimList))
    {
        BnxeRxPostBuffers(pUM, idx, &reclaimList);
    }

    return (polling == TRUE) ? head : NULL;
}


/*
 * Dumping packets simply moves all packets from the waiting queue to the free
 * queue.  Note that the packets are not posted back to the LM.
 */
static void BnxeRxRingDump(um_device_t * pUM,
                           int           idx)
{
    s_list_t tmpList;

    BNXE_LOCK_ENTER_RX(pUM, idx);

    tmpList = pUM->rxq[idx].waitRxQ;
    s_list_clear(&pUM->rxq[idx].waitRxQ);

    s_list_add_tail(&LM_RXQ(&pUM->lm_dev, idx).common.free_descq, &tmpList);

    BNXE_LOCK_EXIT_RX(pUM, idx);
}


/*
 * Aborting packets stops all rx processing by dumping the currently waiting
 * packets and aborting all the rx descriptors currently posted in the LM.
 */
static void BnxeRxPktsAbortIdx(um_device_t * pUM,
                               int           idx)
{
    BnxeRxRingDump(pUM, idx);

    BNXE_LOCK_ENTER_RX(pUM, idx);
    lm_abort(&pUM->lm_dev, ABORT_OP_RX_CHAIN, idx);
    BNXE_LOCK_EXIT_RX(pUM, idx);
}


void BnxeRxPktsAbort(um_device_t * pUM,
                     int           cliIdx)
{
    int idx;

    switch (cliIdx)
    {
    case LM_CLI_IDX_FCOE:

        BnxeRxPktsAbortIdx(pUM, FCOE_CID(&pUM->lm_dev));
        break;

    case LM_CLI_IDX_NDIS:

        LM_FOREACH_RSS_IDX(&pUM->lm_dev, idx)
        {
            BnxeRxPktsAbortIdx(pUM, idx);
        }

        break;

    default:

        BnxeLogWarn(pUM, "ERROR: Invalid cliIdx for BnxeRxPktsAbort (%d)", cliIdx);
        break;
    }
}


static int BnxeRxBufAlloc(um_device_t *   pUM,
                          int             idx,
                          um_rxpacket_t * pRxPkt)
{
    ddi_dma_cookie_t cookie;
    u32_t            count;
    size_t           length;
    int rc;

    if ((rc = ddi_dma_alloc_handle(pUM->pDev,
                                   &bnxeRxDmaAttrib,
                                   DDI_DMA_DONTWAIT,
                                   NULL,
                                   &pRxPkt->dmaHandle)) != DDI_SUCCESS)
    {
        BnxeLogWarn(pUM, "Failed to alloc DMA handle for rx buffer");
        return -1;
    }

    pRxPkt->rx_info.mem_size = MAX_L2_CLI_BUFFER_SIZE(&pUM->lm_dev, idx);

    if ((rc = ddi_dma_mem_alloc(pRxPkt->dmaHandle,
                                pRxPkt->rx_info.mem_size,
                                &bnxeAccessAttribBUF,
                                DDI_DMA_STREAMING,
                                DDI_DMA_DONTWAIT,
                                NULL,
                                (caddr_t *)&pRxPkt->rx_info.mem_virt,
                                &length,
                                &pRxPkt->dmaAccHandle)) != DDI_SUCCESS)
    {
        BnxeLogWarn(pUM, "Failed to alloc DMA memory for rx buffer");
        ddi_dma_free_handle(&pRxPkt->dmaHandle);
        return -1;
    }

    if ((rc = ddi_dma_addr_bind_handle(pRxPkt->dmaHandle,
                                       NULL,
                                       (caddr_t)pRxPkt->rx_info.mem_virt,
                                       pRxPkt->rx_info.mem_size,
                                       DDI_DMA_READ | DDI_DMA_STREAMING,
                                       DDI_DMA_DONTWAIT,
                                       NULL,
                                       &cookie,
                                       &count)) != DDI_DMA_MAPPED)
    {
        BnxeLogWarn(pUM, "Failed to bind DMA address for rx buffer");
        ddi_dma_mem_free(&pRxPkt->dmaAccHandle);
        ddi_dma_free_handle(&pRxPkt->dmaHandle);
        return -1;
    }

    pRxPkt->lm_pkt.u1.rx.mem_phys[0].as_u64 = cookie.dmac_laddress;

    return 0;
}


static int BnxeRxPktsInitPostBuffersIdx(um_device_t * pUM,
                                        int           idx)
{
    BNXE_LOCK_ENTER_RX(pUM, idx);
    lm_post_buffers(&pUM->lm_dev, idx, NULL, 0);
    BNXE_LOCK_EXIT_RX(pUM, idx);

    return 0;
}


int BnxeRxPktsInitPostBuffers(um_device_t * pUM,
                              int           cliIdx)
{
    int idx;

    switch (cliIdx)
    {
    case LM_CLI_IDX_FCOE:

        BnxeRxPktsInitPostBuffersIdx(pUM, FCOE_CID(&pUM->lm_dev));
        break;

    case LM_CLI_IDX_NDIS:

        LM_FOREACH_RSS_IDX(&pUM->lm_dev, idx)
        {
            BnxeRxPktsInitPostBuffersIdx(pUM, idx);
        }

        break;

    default:

        BnxeLogWarn(pUM, "ERROR: Invalid cliIdx for BnxeRxPktsInit (%d)", cliIdx);
        break;
    }

    return 0;
}


static int BnxeRxPktsInitIdx(um_device_t * pUM,
                             int           idx)
{
    lm_device_t *   pLM = &pUM->lm_dev;
    lm_rx_chain_t * pLmRxChain;
    um_rxpacket_t * pRxPkt;
    lm_packet_t *   pLmPkt;
    u8_t *          pTmp;
    int postCnt, i;

    BNXE_LOCK_ENTER_RX(pUM, idx);

    pLmRxChain = &LM_RXQ(pLM, idx);

    s_list_clear(&pUM->rxq[idx].doneRxQ);
    pUM->rxq[idx].rxLowWater = pLM->params.l2_rx_desc_cnt[LM_CHAIN_IDX_CLI(pLM, idx)];
    pUM->rxq[idx].rxDiscards = 0;
    pUM->rxq[idx].rxCopied   = 0;

    s_list_clear(&pUM->rxq[idx].waitRxQ);

    /* allocate the packet descriptors */
    for (i = 0;
         i < pLM->params.l2_rx_desc_cnt[LM_CHAIN_IDX_CLI(pLM, idx)];
         i++)
    {
        if ((pTmp = kmem_zalloc(BnxeRxPktDescrSize(pUM),
                                KM_NOSLEEP)) == NULL)
        {
            BnxeLogWarn(pUM, "Failed to alloc an rx packet descriptor!!!");
            break; /* continue without error */
        }

        pRxPkt            = (um_rxpacket_t *)(pTmp + SIZEOF_SIG);
        SIG(pRxPkt)       = L2PACKET_RX_SIG;
        pRxPkt->signature = pUM->rxBufSignature[LM_CHAIN_IDX_CLI(pLM, idx)];

        pLmPkt                     = (lm_packet_t *)pRxPkt;
        pLmPkt->u1.rx.hash_val_ptr = &pRxPkt->hash_value;
        pLmPkt->l2pkt_rx_info      = &pRxPkt->rx_info;

        if (BnxeRxBufAlloc(pUM, idx, pRxPkt) != 0)
        {
            BnxeRxPktDescrFree(pUM, pRxPkt);
            break; /* continue without error */
        }

        s_list_push_tail(&pLmRxChain->common.free_descq, &pLmPkt->link);
    }

    postCnt = s_list_entry_cnt(&pLmRxChain->common.free_descq);

    if (postCnt != pLM->params.l2_rx_desc_cnt[LM_CHAIN_IDX_CLI(pLM, idx)])
    {
        BnxeLogWarn(pUM, "%d rx buffers requested and only %d allocated!!!",
                    pLM->params.l2_rx_desc_cnt[LM_CHAIN_IDX_CLI(pLM, idx)],
                    postCnt);
    }

    BNXE_LOCK_EXIT_RX(pUM, idx);

    return 0;
}


int BnxeRxPktsInit(um_device_t * pUM,
                   int           cliIdx)
{
    int idx;

    /* set the rx buffer signature for this plumb */
    atomic_swap_32(&pUM->rxBufSignature[cliIdx], (u32_t)ddi_get_time());

    switch (cliIdx)
    {
    case LM_CLI_IDX_FCOE:

        BnxeRxPktsInitIdx(pUM, FCOE_CID(&pUM->lm_dev));
        break;

    case LM_CLI_IDX_NDIS:

        LM_FOREACH_RSS_IDX(&pUM->lm_dev, idx)
        {
            BnxeRxPktsInitIdx(pUM, idx);
        }

        break;

    default:

        BnxeLogWarn(pUM, "ERROR: Invalid cliIdx for BnxeRxPktsInit (%d)", cliIdx);
        break;
    }

    return 0;
}


static void BnxeRxPktsFiniIdx(um_device_t * pUM,
                              int           idx)
{
    lm_rx_chain_t * pLmRxChain;
    um_rxpacket_t * pRxPkt;
    s_list_t        tmpList;

    pLmRxChain = &LM_RXQ(&pUM->lm_dev, idx);

    s_list_clear(&tmpList);

    BNXE_LOCK_ENTER_RX(pUM, idx);
    s_list_add_tail(&tmpList, &pLmRxChain->common.free_descq);
    s_list_clear(&pLmRxChain->common.free_descq);
    BNXE_LOCK_EXIT_RX(pUM, idx);

    BNXE_LOCK_ENTER_DONERX(pUM, idx);
    s_list_add_tail(&tmpList, &pUM->rxq[idx].doneRxQ);
    s_list_clear(&pUM->rxq[idx].doneRxQ);
    BNXE_LOCK_EXIT_DONERX(pUM, idx);

    if (s_list_entry_cnt(&tmpList) !=
        pUM->lm_dev.params.l2_rx_desc_cnt[LM_CHAIN_IDX_CLI(&pUM->lm_dev, idx)])
    {
        BnxeLogWarn(pUM, "WARNING Missing RX packets (idx:%d) (%lu / %d - %u in stack)",
                    idx, s_list_entry_cnt(&tmpList),
                    pUM->lm_dev.params.l2_rx_desc_cnt[LM_CHAIN_IDX_CLI(&pUM->lm_dev, idx)],
                    pUM->rxq[idx].rxBufUpInStack);
    }

    /*
     * Back out all the packets in the "available for hardware use" queue.
     * Free the buffers associated with the descriptors as we go.
     */
    while (1)
    {
        pRxPkt = (um_rxpacket_t *)s_list_pop_head(&tmpList);
        if (pRxPkt == NULL)
        {
            break;
        }

        pRxPkt->lm_pkt.u1.rx.mem_phys[0].as_u64 = 0;
        pRxPkt->rx_info.mem_virt = NULL;
        pRxPkt->rx_info.mem_size = 0;

        ddi_dma_unbind_handle(pRxPkt->dmaHandle);
        ddi_dma_mem_free(&pRxPkt->dmaAccHandle);
        ddi_dma_free_handle(&pRxPkt->dmaHandle);

        BnxeRxPktDescrFree(pUM, pRxPkt);
    }
}


void BnxeRxPktsFini(um_device_t * pUM,
                    int           cliIdx)
{
    int idx;

    /* reset the signature for this unplumb */
    atomic_swap_32(&pUM->rxBufSignature[cliIdx], 0);

    switch (cliIdx)
    {
    case LM_CLI_IDX_FCOE:

        BnxeRxPktsFiniIdx(pUM, FCOE_CID(&pUM->lm_dev));
        break;

    case LM_CLI_IDX_NDIS:

        LM_FOREACH_RSS_IDX(&pUM->lm_dev, idx)
        {
            BnxeRxPktsFiniIdx(pUM, idx);
        }

        break;

    default:

        BnxeLogWarn(pUM, "ERROR: Invalid cliIdx for BnxeRxPktsFini (%d)", cliIdx);
        break;
    }
}

