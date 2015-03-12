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

ddi_dma_attr_t bnxeTxDmaAttrib =
{
    DMA_ATTR_V0,                /* dma_attr_version */
    0,                          /* dma_attr_addr_lo */
    0xffffffffffffffff,         /* dma_attr_addr_hi */
    0xffffffffffffffff,         /* dma_attr_count_max */
    BNXE_DMA_ALIGNMENT,         /* dma_attr_align */
    0xffffffff,                 /* dma_attr_burstsizes */
    1,                          /* dma_attr_minxfer */
    0xffffffffffffffff,         /* dma_attr_maxxfer */
    0xffffffffffffffff,         /* dma_attr_seg */
    BNXE_MAX_DMA_SGLLEN,        /* dma_attr_sgllen */
    1,                          /* dma_attr_granular */
    0,                          /* dma_attr_flags */
};

ddi_dma_attr_t bnxeTxCbDmaAttrib =
{
    DMA_ATTR_V0,                /* dma_attr_version */
    0,                          /* dma_attr_addr_lo */
    0xffffffffffffffff,         /* dma_attr_addr_hi */
    0xffffffffffffffff,         /* dma_attr_count_max */
    BNXE_DMA_ALIGNMENT,         /* dma_attr_align */
    0xffffffff,                 /* dma_attr_burstsizes */
    1,                          /* dma_attr_minxfer */
    0xffffffffffffffff,         /* dma_attr_maxxfer */
    0xffffffffffffffff,         /* dma_attr_seg */
    1,                          /* dma_attr_sgllen */
    1,                          /* dma_attr_granular */
    0,                          /* dma_attr_flags */
};


static um_txpacket_t * BnxeTxPktAlloc(um_device_t * pUM, size_t size);


static inline void BnxeTxPktUnmap(um_txpacket_t * pTxPkt)
{
    int i;

    for (i = 0; i < pTxPkt->num_handles; i++)
    {
        ddi_dma_unbind_handle(pTxPkt->dmaHandles[i]);
    }

    pTxPkt->num_handles = 0;
}


static void BnxeTxPktsFree(um_txpacket_t * pTxPkt)
{
    int i;

    if (pTxPkt->num_handles > 0)
    {
        BnxeTxPktUnmap(pTxPkt);
    }

    if (pTxPkt->pMblk != NULL)
    {
        freemsg(pTxPkt->pMblk);
    }

    for (i = 0; i < BNXE_MAX_DMA_HANDLES_PER_PKT; i++)
    {
        ddi_dma_free_handle(&pTxPkt->dmaHandles[i]);
    }

    pTxPkt->pMblk         = NULL;
    pTxPkt->num_handles   = 0;
    pTxPkt->frag_list.cnt = 0;

    ddi_dma_unbind_handle(pTxPkt->cbDmaHandle);
    ddi_dma_mem_free(&pTxPkt->cbDmaAccHandle);
    ddi_dma_free_handle(&pTxPkt->cbDmaHandle);
    kmem_free(pTxPkt, sizeof(um_txpacket_t));
}


static void BnxeTxPktsFreeList(s_list_t * pPktList)
{
    um_txpacket_t * pTxPkt;

    while (!s_list_is_empty(pPktList))
    {
        pTxPkt = (um_txpacket_t *)s_list_pop_head(pPktList);
        BnxeTxPktsFree(pTxPkt);
    }
}


/*
 * Free the mblk and all frag mappings used by each packet in the list
 * and then put the entire list on the free queue for immediate use.
 */
void BnxeTxPktsReclaim(um_device_t * pUM,
                       int           idx,
                       s_list_t *    pPktList)
{
    um_txpacket_t * pTxPkt;

    if (s_list_entry_cnt(pPktList) == 0)
    {
        return;
    }

    for (pTxPkt = (um_txpacket_t *)s_list_peek_head(pPktList);
         pTxPkt;
         pTxPkt = (um_txpacket_t *)s_list_next_entry(&pTxPkt->lm_pkt.link))
    {
        if (pTxPkt->num_handles > 0)
        {
            BnxeTxPktUnmap(pTxPkt);
        }

        if (pTxPkt->pMblk != NULL)
        {
            freemsg(pTxPkt->pMblk);
            pTxPkt->pMblk = NULL;
        }
    }

    BNXE_LOCK_ENTER_FREETX(pUM, idx);
    s_list_add_tail(&pUM->txq[idx].freeTxDescQ, pPktList);
    BNXE_LOCK_EXIT_FREETX(pUM, idx);
}


/* Must be called with TX lock held!!! */
static int BnxeTxSendWaitingPkt(um_device_t * pUM,
                                int           idx)
{
    TxQueue *       pTxQ = &pUM->txq[idx];
    lm_device_t *   pLM = &pUM->lm_dev;
    lm_tx_chain_t * pLmTxChain;
    um_txpacket_t * pTxPkt;
    int rc;

    pLmTxChain = &pLM->tx_info.chain[idx];

    while (s_list_entry_cnt(&pTxQ->waitTxDescQ))
    {
        pTxPkt = (um_txpacket_t *)s_list_peek_head(&pTxQ->waitTxDescQ);

        if (pTxPkt->frag_list.cnt + 2 > pLmTxChain->bd_chain.bd_left)
        {
            return BNXE_TX_DEFERPKT;
        }

        pTxPkt = (um_txpacket_t *)s_list_pop_head(&pTxQ->waitTxDescQ);

        rc = lm_send_packet(pLM, idx, &pTxPkt->lm_pkt, &pTxPkt->frag_list);

        if (pUM->fmCapabilities &&
            BnxeCheckAccHandle(pLM->vars.reg_handle[BAR_0]) != DDI_FM_OK)
        {
            ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_DEGRADED);
        }

        if (rc != LM_STATUS_SUCCESS)
        {
            /*
             * Send failed (probably not enough BDs available)...
             * Put the packet back at the head of the wait queue.
             */
            pTxQ->txFailed++;
            s_list_push_head(&pTxQ->waitTxDescQ, &pTxPkt->lm_pkt.link);
            return BNXE_TX_DEFERPKT;
        }
    }

    return BNXE_TX_GOODXMIT;
}


void BnxeTxRingProcess(um_device_t * pUM,
                       int           idx)
{
    TxQueue *       pTxQ = &pUM->txq[idx];
    lm_device_t *   pLM = &pUM->lm_dev;
    lm_tx_chain_t * pLmTxChain;
    s_list_t        tmpList;
    u32_t           pktsTxed;
    int rc;

    s_list_clear(&tmpList);

    BNXE_LOCK_ENTER_TX(pUM, idx);

    pktsTxed = lm_get_packets_sent(&pUM->lm_dev, idx, &tmpList);

    if (pUM->fmCapabilities &&
        BnxeCheckAccHandle(pUM->lm_dev.vars.reg_handle[BAR_0]) != DDI_FM_OK)
    {
        ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_DEGRADED);
    }

    if ((pktsTxed + s_list_entry_cnt(&pTxQ->sentTxQ)) >=
        pUM->devParams.maxTxFree)
    {
        s_list_add_tail(&tmpList, &pTxQ->sentTxQ);
        s_list_clear(&pTxQ->sentTxQ);
    }
    else
    {
        s_list_add_tail(&pTxQ->sentTxQ, &tmpList);
        s_list_clear(&tmpList);
    }

    BNXE_LOCK_EXIT_TX(pUM, idx);

    if (s_list_entry_cnt(&tmpList))
    {
        BnxeTxPktsReclaim(pUM, idx, &tmpList);
    }

    if (pTxQ->noTxCredits == 0)
    {
        /* no need to notify the stack */
        return;
    }

    pLmTxChain = &pUM->lm_dev.tx_info.chain[idx];

    if (pTxQ->noTxCredits & BNXE_TX_RESOURCES_NO_CREDIT)
    {
        BNXE_LOCK_ENTER_TX(pUM, idx);
        rc = BnxeTxSendWaitingPkt(pUM, idx);
        BNXE_LOCK_EXIT_TX(pUM, idx);

        if ((rc == BNXE_TX_GOODXMIT) &&
            (pLmTxChain->bd_chain.bd_left >= BNXE_MAX_DMA_FRAGS_PER_PKT))
        {
            atomic_and_32(&pTxQ->noTxCredits, ~BNXE_TX_RESOURCES_NO_CREDIT);
        }
    }

    if ((pTxQ->noTxCredits & BNXE_TX_RESOURCES_NO_DESC) &&
        (s_list_entry_cnt(&pTxQ->freeTxDescQ) > pTxQ->thresh_pdwm))
    {
        atomic_and_32(&pTxQ->noTxCredits, ~BNXE_TX_RESOURCES_NO_DESC);
    }

    if (pTxQ->noTxCredits == 0)
    {
        if (idx == FCOE_CID(pLM))
        {
            BnxeLogInfo(pUM, "FCoE tx credit ok, no upcall!");
        }
        else
        {
            /* notify the stack that tx resources are now available */
#if defined(BNXE_RINGS) && (defined(__S11) || defined(__S12))
            mac_tx_ring_update(pUM->pMac, pTxQ->ringHandle);
#else
            mac_tx_update(pUM->pMac);
#endif
        }
    }
}


static inline int BnxeTxPktMapFrag(um_device_t *   pUM,
                                   um_txpacket_t * pTxPkt,
                                   mblk_t *        pMblk)
{
    ddi_dma_handle_t dmaHandle;
    ddi_dma_cookie_t cookie;
    lm_frag_t *      pFrag;
    boolean_t        partial;
    u32_t            bindLen;
    u32_t            count;
    int rc, i;

    if (pTxPkt->num_handles == BNXE_MAX_DMA_HANDLES_PER_PKT)
    {
        return BNXE_TX_RESOURCES_NO_OS_DMA_RES;
    }

    if (pTxPkt->frag_list.cnt >= BNXE_MAX_DMA_FRAGS_PER_PKT)
    {
        return BNXE_TX_RESOURCES_TOO_MANY_FRAGS;
    }

    dmaHandle = pTxPkt->dmaHandles[pTxPkt->num_handles];

    if ((rc = ddi_dma_addr_bind_handle(dmaHandle,
                                       NULL,
                                       (caddr_t)pMblk->b_rptr,
                                       (pMblk->b_wptr - pMblk->b_rptr),
                                       (DDI_DMA_WRITE | DDI_DMA_STREAMING),
                                       DDI_DMA_DONTWAIT,
                                       NULL,
                                       &cookie,
                                       &count)) != DDI_DMA_MAPPED)
    {
        BnxeLogWarn(pUM, "Failed to bind DMA address for tx packet (%d)", rc);
        return BNXE_TX_RESOURCES_NO_OS_DMA_RES;
    }

    /*
     * ddi_dma_addr_bind_handle() correctly returns an error if the physical
     * fragment count exceeds the maximum fragment count specified in the
     * ddi_dma_attrib structure for the current pMblk.  However, a packet can
     * span multiple mblk's.  The purpose of the check below is to make sure we
     * do not overflow our fragment count limit based on what has already been
     * mapped from this packet.
     */
    partial = ((pTxPkt->frag_list.cnt + count) >
               (pMblk->b_cont ? BNXE_MAX_DMA_FRAGS_PER_PKT - 1
                              : BNXE_MAX_DMA_FRAGS_PER_PKT));
    if (partial)
    {
        /*
         * Going to try a partial dma so (re)set count to the remaining number
         * of dma fragments that are available leaving one fragment at the end.
         */
        count = (BNXE_MAX_DMA_FRAGS_PER_PKT - 1 - pTxPkt->frag_list.cnt);
        if (count == 0)
        {
            /*
             * No more dma fragments are available.  This fragment was not
             * mapped and will be copied into the copy buffer along with the
             * rest of the packet data.
             */
            ddi_dma_unbind_handle(dmaHandle);
            return BNXE_TX_RESOURCES_TOO_MANY_FRAGS;
        }
    }

    pFrag = &pTxPkt->frag_list.frag_arr[pTxPkt->frag_list.cnt];
    pTxPkt->frag_list.cnt += count;

    /* map "count" dma fragments */

    bindLen = 0;
    for (i = 0; i < (count - 1); i++)
    {
        pFrag->addr.as_u64 = cookie.dmac_laddress;
        bindLen += pFrag->size = cookie.dmac_size;

        pFrag++;

        ddi_dma_nextcookie(dmaHandle, &cookie);
    }

    pFrag->addr.as_u64 = cookie.dmac_laddress;
    bindLen += pFrag->size = cookie.dmac_size;

    pTxPkt->num_handles++;

    if (partial)
    {
        /*
         * Move the mblk's read pointer past the data that was bound to a DMA
         * fragment.  Any remaining data will get copied into the copy buffer.
         */
        pMblk->b_rptr += bindLen;
        return BNXE_TX_RESOURCES_TOO_MANY_FRAGS;
    }

    return 0;
}


static int BnxeTxPktCopy(um_device_t *   pUM,
                         TxQueue *       pTxQ,
                         um_txpacket_t * pTxPkt)
{
    lm_frag_t * pCopyFrag = NULL;
    size_t      msgSize;
    size_t      copySize = 0;
    size_t      pktLen = 0;
    boolean_t   tryMap = B_TRUE;
    mblk_t *    pMblk;
    caddr_t     pTmp;
    int rc;

    /* Walk the chain to get the total pkt length... */
    for (pMblk = pTxPkt->pMblk; pMblk; pMblk = pMblk->b_cont)
    {
        pktLen += MBLKL(pMblk);
    }

    /*
     * If the packet length is under the tx copy threshold then copy
     * the all data into the copy buffer.
     */
    if (pktLen < pUM->devParams.txCopyThreshold)
    {
        ASSERT(pktLen <= pTxPkt->cbLength);

        pTmp = pTxPkt->pCbBuf;

        for (pMblk = pTxPkt->pMblk; pMblk; pMblk = pMblk->b_cont)
        {
            if ((msgSize = MBLKL(pMblk)) == 0)
            {
                continue;
            }

            bcopy(pMblk->b_rptr, pTmp, msgSize);
            pTmp += msgSize;
        }

        pCopyFrag              = &pTxPkt->frag_list.frag_arr[0];
        pCopyFrag->addr.as_u64 = pTxPkt->cbPhysAddr.as_u64;
        pCopyFrag->size        = pktLen;
        pTxPkt->frag_list.cnt++;

        copySize = pktLen;
        pTxQ->txCopied++;

        /* Done! */
        goto _BnxeTxPktCopy_DMA_SYNC_COPY_BUFFER;
    }

    /* Try to DMA map all the blocks... */

    for (pMblk = pTxPkt->pMblk; pMblk; pMblk = pMblk->b_cont)
    {
        if ((msgSize = MBLKL(pMblk)) == 0)
        {
            continue;
        }

        if (tryMap)
        {
            if (BnxeTxPktMapFrag(pUM, pTxPkt, pMblk) == 0)
            {
                /*
                 * The fragment was successfully mapped now move on to the
                 * next one.  Here we set pCopyFrag to NULL which represents
                 * a break of continuous data in the copy buffer.  If the
                 * packet header was copied the first fragment points to the
                 * beginning of the copy buffer.  Since this block was mapped
                 * any future blocks that have to be copied must be handled by
                 * a new fragment even though the fragment is pointed to the
                 * copied data in the copy buffer.
                 */
                pCopyFrag = NULL;
                continue;
            }
            else
            {
                /*
                 * The frament was not mapped or was partially mapped.  In
                 * either case we will no longer try to map the remaining
                 * blocks.  All remaining packet data is copied.
                 */
                tryMap = B_FALSE;
                msgSize = MBLKL(pMblk); /* new msgSize with partial binding */
            }
        }

#if 0
        if ((copySize + msgSize) > pTxPkt->cbLength)
        {
            /* remaining packet is too large (length more than copy buffer) */
            BnxeTxPktUnmap(pTxPkt);
            return -1;
        }
#else
        ASSERT((copySize + msgSize) <= pTxPkt->cbLength);
#endif

        bcopy(pMblk->b_rptr, (pTxPkt->pCbBuf + copySize), msgSize);

        /*
         * If pCopyFrag is already specified then simply update the copy size.
         * If not then set pCopyFrag to the next available fragment.
         */
        if (pCopyFrag)
        {
            pCopyFrag->size += msgSize;
        }
        else
        {
            ASSERT((pTxPkt->frag_list.cnt + 1) <= BNXE_MAX_DMA_FRAGS_PER_PKT);
            pCopyFrag              = &pTxPkt->frag_list.frag_arr[pTxPkt->frag_list.cnt++];
            pCopyFrag->size        = msgSize;
            pCopyFrag->addr.as_u64 = pTxPkt->cbPhysAddr.as_u64 + copySize;
        }

        /* update count of bytes in the copy buffer needed for DMA sync */
        copySize += msgSize;
    }

_BnxeTxPktCopy_DMA_SYNC_COPY_BUFFER:

    if (copySize > 0)
    {
        /* DMA sync the copy buffer before sending */

        rc = ddi_dma_sync(pTxPkt->cbDmaHandle, 0, copySize,
                          DDI_DMA_SYNC_FORDEV);

        if (pUM->fmCapabilities &&
            BnxeCheckDmaHandle(pTxPkt->cbDmaHandle) != DDI_FM_OK)
        {
            ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_DEGRADED);
        }

        if (rc != DDI_SUCCESS)
        {
            BnxeLogWarn(pUM, "(%d) Failed to dma sync tx copy (%p / %d)",
                        rc, pTxPkt, copySize);
        }
    }

    if (pTxPkt->num_handles == 0)
    {
        freemsg(pTxPkt->pMblk);
        pTxPkt->pMblk = NULL;
    }

    return 0;
}


/* this code is derived from that shown in RFC 1071 Section 4.1 */
static inline u16_t BnxeCalcCksum(void * start,
                                  u32_t  len,
                                  u16_t  prev_sum)
{
    u16_t * pword;
    u32_t   sum = 0;

    pword = (u16_t *)start;

    for ( ; len > 1; len -= 2, pword++)
    {
        /* the inner loop */
        sum += *pword;
    }

    /* add left-over byte, if any */
    if (len)
    {
        sum += (u16_t)(*((u8_t *)pword));
    }

    sum += prev_sum;

    /* fold 32-bit sum to 16 bits */
    while (sum >> 16)
    {
        sum = ((sum & 0xffff) + (sum >> 16));
    }

    return (u16_t)sum;
}


/*
 * Everest1 (i.e. 57710, 57711, 57711E) does not natively support UDP checksums
 * and does not know anything about the UDP header and where the checksum field
 * is located.  It only knows about TCP.  Therefore we "lie" to the hardware for
 * outgoing UDP packets w/ checksum offload.  Since the checksum field offset
 * for TCP is 16 bytes and for UDP it is 6 bytes we pass a pointer to the
 * hardware that is 10 bytes less than the start of the UDP header.  This allows
 * the hardware to write the checksum in the correct spot.  But the hardware
 * will compute a checksum which includes the last 10 bytes of the IP header.
 * To correct this we tweak the stack computed pseudo checksum by folding in the
 * calculation of the inverse checksum for those final 10 bytes of the IP
 * header.  This allows the correct checksum to be computed by the hardware.
 */

#define TCP_CS_OFFSET           16
#define UDP_CS_OFFSET           6
#define UDP_TCP_CS_OFFSET_DIFF  (TCP_CS_OFFSET - UDP_CS_OFFSET)

static inline u16_t BnxeUdpPseudoCsum(um_device_t * pUM,
                                      u8_t *        pUdpHdr,
                                      u8_t *        pIpHdr,
                                      u8_t          ipHdrLen)
{
    u32_t sum32;
    u16_t sum16;
    u16_t pseudo_cs;

    ASSERT(ipHdrLen >= UDP_TCP_CS_OFFSET_DIFF);

    /* calc cksum on last UDP_TCP_CS_OFFSET_DIFF bytes of ip header */
    sum16 = BnxeCalcCksum(&pIpHdr[ipHdrLen - UDP_TCP_CS_OFFSET_DIFF],
                          UDP_TCP_CS_OFFSET_DIFF, 0);

    /* substruct the calculated cksum from the udp pseudo cksum */
    pseudo_cs = (*((u16_t *)&pUdpHdr[6]));
    sum16     = ~sum16;
    sum32     = (pseudo_cs + sum16);

    /* fold 32-bit sum to 16 bits */
    while (sum32 >> 16)
    {
        sum32 = ((sum32 & 0xffff) + (sum32 >> 16));
    }

    return ntohs((u16_t)sum32);
}


static inline u16_t BnxeGetVlanTag(mblk_t * pMblk)
{
    ASSERT(MBLKL(pMblk) >= sizeof(struct ether_vlan_header));
    return GLD_VTAG_VID(ntohs(((struct ether_vlan_header *)pMblk->b_rptr)->ether_tci));
}


static inline int BnxeGetHdrInfo(um_device_t *   pUM,
                                 um_txpacket_t * pTxPkt)
{
    mblk_t *      pMblk;
    size_t        msgSize;
    uint32_t      csStart;
    uint32_t      csStuff;
    uint32_t      csFlags;
    uint32_t      lso;
    u8_t *        pL2Hdr;
    uint32_t      l2HdrLen;
    u8_t *        pL3Hdr;
    u32_t         l3HdrLen;
    u8_t *        pL4Hdr;
    u32_t         l4HdrLen;

    pMblk = pTxPkt->pMblk;
    msgSize = MBLKL(pMblk);

    /* At least the MAC header... */
#if 0
    if (msgSize < sizeof(struct ether_header))
    {
        BnxeLogWarn(pUM, "Invalid initial segment size in packet!");
        return -1;
    }
#else
    ASSERT(msgSize >= sizeof(struct ether_header));
#endif

    mac_hcksum_get(pMblk, &csStart, &csStuff, NULL, NULL, &csFlags);

    lso = DB_LSOFLAGS(pMblk) & HW_LSO;

    /* get the Ethernet header */
    pL2Hdr = (u8_t *)pMblk->b_rptr;

    /* grab the destination mac addr */
    memcpy(pTxPkt->tx_info.dst_mac_addr, pL2Hdr, 6);

    if (lso)
    {
        pTxPkt->tx_info.flags |= LM_TX_FLAG_TCP_LSO_FRAME;

        pTxPkt->tx_info.lso_mss = (u16_t)DB_LSOMSS(pMblk);
    }
    else if (!csFlags)
    {
        /* no offload requested, just check for VLAN */

        if (((struct ether_header *)pMblk->b_rptr)->ether_type ==
            htons(ETHERTYPE_VLAN))
        {
            pTxPkt->tx_info.vlan_tag = BnxeGetVlanTag(pMblk);
            pTxPkt->tx_info.flags |= LM_TX_FLAG_VLAN_TAG_EXISTS;
        }

        return 0;
    }

    if (((struct ether_header *)pL2Hdr)->ether_type == htons(ETHERTYPE_VLAN))
    {
        l2HdrLen = sizeof(struct ether_vlan_header);

        pTxPkt->tx_info.vlan_tag = BnxeGetVlanTag(pMblk);
        pTxPkt->tx_info.flags |= LM_TX_FLAG_VLAN_TAG_EXISTS;
    }
    else
    {
        l2HdrLen = sizeof(struct ether_header);
    }

    if (csFlags & HCK_IPV4_HDRCKSUM)
    {
        pTxPkt->tx_info.flags |= LM_TX_FLAG_COMPUTE_IP_CKSUM;
    }

    if (csFlags & HCK_PARTIALCKSUM)
    {
        pTxPkt->tx_info.flags |= LM_TX_FLAG_COMPUTE_TCP_UDP_CKSUM;

        l3HdrLen = csStart;
        l4HdrLen = (l2HdrLen + csStuff + sizeof(u16_t));

        /*
         * For TCP, here we ignore the urgent pointer and size of the
         * options.  We'll get that info later.
         */
    }
    else if (lso)
    {
        /* Solaris doesn't do LSO if there is option in the IP header. */
        l3HdrLen = sizeof(struct ip);
        l4HdrLen = (l2HdrLen + l3HdrLen + sizeof(struct tcphdr));
    }
    else
    {
        return 0;
    }

    if (msgSize >= l4HdrLen)
    {
        /* the header is in the first block */
        pL3Hdr = (pL2Hdr + l2HdrLen);
    }
    else
    {
        if ((msgSize <= l2HdrLen) && pMblk->b_cont &&
            ((msgSize + MBLKL(pMblk->b_cont)) >= l4HdrLen))
        {
            /* the header is in the second block */
            pL3Hdr = pMblk->b_cont->b_rptr + (l2HdrLen - msgSize);
        }
        else
        {
            /* do a pullup to make sure headers are in the first block */
            pUM->txMsgPullUp++;

            if ((pMblk = msgpullup(pMblk, l4HdrLen)) == NULL)
            {
                return -1;
            }

            freemsg(pTxPkt->pMblk);
            pTxPkt->pMblk = pMblk;

            pL3Hdr = (pMblk->b_rptr + l2HdrLen);
        }
    }

    /* must be IPv4 or IPv6 */
    ASSERT((pL3Hdr[0] & 0xf0) == 0x60 || (pL3Hdr[0] & 0xf0) == 0x40);

    if ((pL3Hdr[0] & 0xf0) == 0x60)
    {
        pTxPkt->tx_info.flags |= LM_TX_FLAG_IPV6_PACKET;
    }

    if (lso || ((csStuff - csStart) == TCP_CS_OFFSET))
    {
        /* get the TCP header */
        pL4Hdr   = (pL3Hdr + l3HdrLen);
        l4HdrLen = ((pL4Hdr[12] & 0xf0) >> 2);

        pTxPkt->tx_info.cs_any_offset     = 0;
        pTxPkt->tx_info.tcp_nonce_sum_bit = (pL4Hdr[12] & 0x1);
        pTxPkt->tx_info.tcp_pseudo_csum   = ntohs(*((u16_t *)&pL4Hdr[TCP_CS_OFFSET]));

        if (lso)
        {
            pTxPkt->tx_info.lso_ipid         = ntohs(*((u16_t *)&pL3Hdr[4]));
            pTxPkt->tx_info.lso_tcp_send_seq = ntohl(*((u32_t *)&pL4Hdr[4]));
            pTxPkt->tx_info.lso_tcp_flags    = pL4Hdr[13];
        }
    }
    else
    {
        ASSERT((csStuff - csStart) == UDP_CS_OFFSET);

        /* get the UDP header */
        pL4Hdr = pL3Hdr + l3HdrLen;

        l4HdrLen = sizeof(struct udphdr);

        pTxPkt->tx_info.cs_any_offset     = UDP_TCP_CS_OFFSET_DIFF;
        pTxPkt->tx_info.tcp_nonce_sum_bit = 0;
        pTxPkt->tx_info.tcp_pseudo_csum   =
            CHIP_IS_E1x(((lm_device_t *)pUM)) ?
                BnxeUdpPseudoCsum(pUM, pL4Hdr, pL3Hdr, l3HdrLen) :
                ntohs(*((u16_t *)&pL4Hdr[UDP_CS_OFFSET]));
    }

    pTxPkt->tx_info.lso_ip_hdr_len  = l3HdrLen;
    pTxPkt->tx_info.lso_tcp_hdr_len = l4HdrLen;

    return 0;
}


int BnxeTxSendMblk(um_device_t * pUM,
                   int           idx,
                   mblk_t *      pMblk,
                   u32_t         flags,
                   u16_t         vlan_tag)
{
    lm_device_t *   pLM = &pUM->lm_dev;
    TxQueue *       pTxQ = &pUM->txq[idx];
    lm_tx_chain_t * pLmTxChain;
    um_txpacket_t * pTxPkt;
    s_list_t        tmpList;
    u32_t           numPkts;
    int rc;

    BNXE_LOCK_ENTER_FREETX(pUM, idx);

    pTxPkt = (um_txpacket_t *)s_list_pop_head(&pTxQ->freeTxDescQ);

    if (pTxQ->txLowWater > s_list_entry_cnt(&pTxQ->freeTxDescQ))
    {
        pTxQ->txLowWater = s_list_entry_cnt(&pTxQ->freeTxDescQ);
    }

    BNXE_LOCK_EXIT_FREETX(pUM, idx);

    /* try to recycle if no more packet available */
    if (pTxPkt == NULL)
    {
        pTxQ->txRecycle++;

        s_list_clear(&tmpList);

        BNXE_LOCK_ENTER_TX(pUM, idx);
        numPkts = lm_get_packets_sent(pLM, idx, &tmpList);
        BNXE_LOCK_EXIT_TX(pUM, idx);

        if (pUM->fmCapabilities &&
            BnxeCheckAccHandle(pLM->vars.reg_handle[BAR_0]) != DDI_FM_OK)
        {
            ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_DEGRADED);
        }

        if (!numPkts)
        {
            atomic_or_32(&pTxQ->noTxCredits, BNXE_TX_RESOURCES_NO_DESC);
            pTxQ->txBlocked++;
            return BNXE_TX_HDWRFULL;
        }

        /* steal the first packet from the list before reclaiming */

        pTxPkt = (um_txpacket_t *)s_list_pop_head(&tmpList);

        if (pTxPkt->num_handles)
        {
            BnxeTxPktUnmap(pTxPkt);
        }

        if (pTxPkt->pMblk)
        {
            freemsg(pTxPkt->pMblk);
            pTxPkt->pMblk = NULL;
        }

        BnxeTxPktsReclaim(pUM, idx, &tmpList);
    }

    pTxPkt->lm_pkt.link.next = NULL;

    pTxPkt->tx_info.flags    = 0;
    pTxPkt->tx_info.vlan_tag = 0;
    pTxPkt->frag_list.cnt    = 0;
    pTxPkt->pMblk            = pMblk;

#if 0
    BnxeDumpPkt(pUM, 
                (BNXE_FCOE(pUM) && (idx == FCOE_CID(&pUM->lm_dev))) ?
                    "-> FCoE L2 TX ->" : "-> L2 TX ->",
                pMblk, B_TRUE);
#endif

    if (idx == FCOE_CID(pLM))
    {
        if (flags & PRV_TX_VLAN_TAG)
        {
            pTxPkt->tx_info.vlan_tag = vlan_tag;
            pTxPkt->tx_info.flags |= LM_TX_FLAG_INSERT_VLAN_TAG;
        }
    }
    else if (BnxeGetHdrInfo(pUM, pTxPkt))
    {
        goto BnxeTxSendMblk_fail;
    }

    if (BnxeTxPktCopy(pUM, pTxQ, pTxPkt))
    {
        goto BnxeTxSendMblk_fail;
    }

    /* Now try to send the packet... */

    pLmTxChain = &pLM->tx_info.chain[idx];

    BNXE_LOCK_ENTER_TX(pUM, idx);

    /* Try to reclaim sent packets if available BDs is lower than threshold */
    if (pLmTxChain->bd_chain.bd_left < BNXE_MAX_DMA_FRAGS_PER_PKT + 2)
    {
        pTxQ->txRecycle++;

        s_list_clear(&tmpList);

        numPkts = lm_get_packets_sent(pLM, idx, &tmpList);

        if (pUM->fmCapabilities &&
            BnxeCheckAccHandle(pLM->vars.reg_handle[BAR_0]) != DDI_FM_OK)
        {
            ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_DEGRADED);
        }

        if (numPkts)
        {
            BnxeTxPktsReclaim(pUM, idx, &tmpList);
        }
    }

    /*
     * If there are no packets currently waiting to be sent and there are enough
     * BDs available to satisfy this packet then send it now.
     */
    if (s_list_is_empty(&pTxQ->waitTxDescQ) &&
        (pLmTxChain->bd_chain.bd_left >= pTxPkt->frag_list.cnt + 2))
    {
        rc = lm_send_packet(pLM, idx, &pTxPkt->lm_pkt, &pTxPkt->frag_list);

        if (pUM->fmCapabilities &&
            BnxeCheckAccHandle(pLM->vars.reg_handle[BAR_0]) != DDI_FM_OK)
        {
            ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_DEGRADED);
        }

        if (pUM->fmCapabilities &&
            BnxeCheckAccHandle(pLM->vars.reg_handle[BAR_1]) != DDI_FM_OK)
        {
            ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_DEGRADED);
        }

        if (rc == LM_STATUS_SUCCESS)
        {
            /* send completely successfully */
            BNXE_LOCK_EXIT_TX(pUM, idx);
            return BNXE_TX_GOODXMIT;
        }

        /*
         * Send failed (probably not enough BDs available)...
         * Continue on with putting this packet on the wait queue.
         */
        pTxQ->txFailed++;
    }

#if 0
    BnxeLogWarn(pUM, "WAIT TX DESCQ %lu %d %d",
                s_list_entry_cnt(&pTxQ->waitTxDescQ),
                pLmTxChain->bd_chain.bd_left, pTxPkt->frag_list.cnt);
#endif

    /*
     * If we got here then there are other packets waiting to be sent or there
     * aren't enough BDs available.  In either case put this packet at the end
     * of the waiting queue.
     */
    s_list_push_tail(&pTxQ->waitTxDescQ, &pTxPkt->lm_pkt.link);

    pTxQ->txWait++;

    /*
     * If there appears to be a sufficient number of BDs available then make a
     * quick attempt to send as many waiting packets as possible.
     */
    if ((pLmTxChain->bd_chain.bd_left >= BNXE_MAX_DMA_FRAGS_PER_PKT) &&
        (BnxeTxSendWaitingPkt(pUM, idx) == BNXE_TX_GOODXMIT))
    {
        BNXE_LOCK_EXIT_TX(pUM, idx);
        return BNXE_TX_GOODXMIT;
    }

    /* Couldn't send anything! */
    atomic_or_32(&pTxQ->noTxCredits, BNXE_TX_RESOURCES_NO_CREDIT);
    pTxQ->txBlocked++;

    BNXE_LOCK_EXIT_TX(pUM, idx);

    return BNXE_TX_DEFERPKT;

BnxeTxSendMblk_fail:

    pTxQ->txDiscards++;

    ASSERT(pTxPkt != NULL);

    if (pTxPkt->pMblk)
    {
        freemsg(pTxPkt->pMblk);
        pTxPkt->pMblk = NULL;
    }

    BNXE_LOCK_ENTER_FREETX(pUM, idx);
    s_list_push_tail(&pTxQ->freeTxDescQ, &pTxPkt->lm_pkt.link);
    BNXE_LOCK_EXIT_FREETX(pUM, idx);

    /*
     * Yes GOODXMIT since mblk was free'd here and this triggers caller to
     * try and send the next packet in its chain.
     */
    return BNXE_TX_GOODXMIT;
}


static void BnxeTxPktsAbortIdx(um_device_t * pUM,
                               int           idx)
{
    s_list_t tmpList;

    BNXE_LOCK_ENTER_TX(pUM, idx);
    lm_abort(&pUM->lm_dev, ABORT_OP_INDICATE_TX_CHAIN, idx);
    tmpList = pUM->txq[idx].waitTxDescQ;
    s_list_clear(&pUM->txq[idx].waitTxDescQ);
    BNXE_LOCK_EXIT_TX(pUM, idx);

    BnxeTxPktsReclaim(pUM, idx, &tmpList);
}


void BnxeTxPktsAbort(um_device_t * pUM,
                     int           cliIdx)
{
    int idx;

    switch (cliIdx)
    {
    case LM_CLI_IDX_FCOE:

        BnxeTxPktsAbortIdx(pUM, FCOE_CID(&pUM->lm_dev));
        break;

    case LM_CLI_IDX_NDIS:

        LM_FOREACH_TSS_IDX(&pUM->lm_dev, idx)
        {
            BnxeTxPktsAbortIdx(pUM, idx);
        }

        break;

    default:

        BnxeLogWarn(pUM, "ERROR: Invalid cliIdx for BnxeTxPktsAbort (%d)", cliIdx);
        break;
    }
}


static um_txpacket_t * BnxeTxPktAlloc(um_device_t * pUM,
                                      size_t        size)
{
    um_txpacket_t *   pTxPkt;
    ddi_dma_cookie_t  cookie;
    u32_t             count;
    size_t            length;
    int rc, j;

    if ((pTxPkt = kmem_zalloc(sizeof(um_txpacket_t), KM_NOSLEEP)) == NULL)
    {
        return NULL;
    }

    pTxPkt->lm_pkt.l2pkt_tx_info = &pTxPkt->tx_info;

    if ((rc = ddi_dma_alloc_handle(pUM->pDev,
                                   &bnxeTxCbDmaAttrib,
                                   DDI_DMA_DONTWAIT,
                                   NULL,
                                   &pTxPkt->cbDmaHandle)) != DDI_SUCCESS)
    {
        BnxeLogWarn(pUM, "Failed to alloc DMA handle for Tx Desc (%d)", rc);
        kmem_free(pTxPkt, sizeof(um_txpacket_t));
        return NULL;
    }

    if ((rc = ddi_dma_mem_alloc(pTxPkt->cbDmaHandle,
                                size,
                                &bnxeAccessAttribBUF,
                                DDI_DMA_STREAMING,
                                DDI_DMA_DONTWAIT,
                                NULL,
                                &pTxPkt->pCbBuf,
                                &length,
                                &pTxPkt->cbDmaAccHandle)) != DDI_SUCCESS)
    {
        BnxeLogWarn(pUM, "Failed to alloc DMA memory for Tx Desc (%d)", rc);
        ddi_dma_free_handle(&pTxPkt->cbDmaHandle);
        kmem_free(pTxPkt, sizeof(um_txpacket_t));
        return NULL;
    }

    if ((rc = ddi_dma_addr_bind_handle(pTxPkt->cbDmaHandle,
                                       NULL,
                                       pTxPkt->pCbBuf,
                                       length,
                                       DDI_DMA_WRITE | DDI_DMA_STREAMING,
                                       DDI_DMA_DONTWAIT,
                                       NULL,
                                       &cookie,
                                       &count)) != DDI_DMA_MAPPED)
    {
        BnxeLogWarn(pUM, "Failed to bind DMA address for Tx Desc (%d)", rc);
        ddi_dma_mem_free(&pTxPkt->cbDmaAccHandle);
        ddi_dma_free_handle(&pTxPkt->cbDmaHandle);
        kmem_free(pTxPkt, sizeof(um_txpacket_t));
        return NULL;
    }

    pTxPkt->cbPhysAddr.as_u64 = cookie.dmac_laddress;

    for (j = 0; j < BNXE_MAX_DMA_HANDLES_PER_PKT; j++)
    {
        if ((rc = ddi_dma_alloc_handle(pUM->pDev,
                                       &bnxeTxDmaAttrib,
                                       DDI_DMA_DONTWAIT,
                                       NULL,
                                       &pTxPkt->dmaHandles[j])) !=
            DDI_SUCCESS)
        {
            BnxeLogWarn(pUM, "Failed to alloc DMA handles for Tx Pkt %d (%d)",
                        j, rc);

            for(--j; j >= 0; j--) /* unwind */
            {
                ddi_dma_free_handle(&pTxPkt->dmaHandles[j]);
            }

            ddi_dma_unbind_handle(pTxPkt->cbDmaHandle);
            ddi_dma_mem_free(&pTxPkt->cbDmaAccHandle);
            ddi_dma_free_handle(&pTxPkt->cbDmaHandle);
            kmem_free(pTxPkt, sizeof(um_txpacket_t));
            return NULL;
        }
    }

    ASSERT(pTxPkt->pMblk == NULL);
    ASSERT(pTxPkt->num_handles == 0);
    ASSERT(pTxPkt->frag_list.cnt == 0);
    pTxPkt->cbLength = size;

    return pTxPkt;
}


static int BnxeTxPktsInitIdx(um_device_t * pUM,
                             int           idx)
{
    lm_device_t *   pLM = &pUM->lm_dev;
    TxQueue *       pTxQ;
    um_txpacket_t * pTxPkt;
    s_list_t        tmpList;
    int i;

    pTxQ = &pUM->txq[idx];

    s_list_clear(&pTxQ->sentTxQ);
    s_list_clear(&pTxQ->freeTxDescQ);
    s_list_clear(&pTxQ->waitTxDescQ);

    pTxQ->desc_cnt    = pUM->devParams.numTxDesc[LM_CHAIN_IDX_CLI(pLM, idx)];
    pTxQ->txLowWater  = pUM->devParams.numTxDesc[LM_CHAIN_IDX_CLI(pLM, idx)];
    pTxQ->thresh_pdwm = BNXE_PDWM_THRESHOLD;
    pTxQ->txFailed    = 0;
    pTxQ->txDiscards  = 0;
    pTxQ->txRecycle   = 0;
    pTxQ->txCopied    = 0;
    pTxQ->txBlocked   = 0;
    pTxQ->txWait      = 0;

    if (pUM->devParams.lsoEnable)
    {
        for (i = 0; i < pTxQ->desc_cnt; i++)
        {
            pTxPkt = BnxeTxPktAlloc(pUM,
                                    (BNXE_IP_MAXLEN +
                                     sizeof(struct ether_vlan_header)));
            if (pTxPkt == NULL)
            {
                BnxeLogWarn(pUM, "Failed to allocate all Tx Descs for LSO (%d/%d allocated), LSO is disabled",
                            i, pTxQ->desc_cnt);

                /* free existing in freeTxDescQ... */

                BNXE_LOCK_ENTER_FREETX(pUM, idx);
                tmpList = pTxQ->freeTxDescQ;
                s_list_clear(&pTxQ->freeTxDescQ);
                BNXE_LOCK_EXIT_FREETX(pUM, idx);

                BnxeTxPktsFreeList(&tmpList);

                pUM->devParams.lsoEnable = 0; /* Disabling LSO! */

                break;
            }

            BNXE_LOCK_ENTER_FREETX(pUM, idx);
            s_list_push_tail(&pTxQ->freeTxDescQ, &pTxPkt->lm_pkt.link);
            BNXE_LOCK_EXIT_FREETX(pUM, idx);
        }
    }

    if (!pUM->devParams.lsoEnable)
    {
        for (i = 0; i < pTxQ->desc_cnt; i++)
        {
            pTxPkt = BnxeTxPktAlloc(pUM,
                                    (pUM->devParams.mtu[LM_CHAIN_IDX_CLI(pLM, idx)] +
                                     sizeof(struct ether_vlan_header)));
            if (pTxPkt == NULL)
            {
                BnxeLogWarn(pUM, "Failed to allocate all Tx Descs (%d/%d allocated)",
                            i, pTxQ->desc_cnt);

                /* free existing in freeTxDescQ... */

                BNXE_LOCK_ENTER_FREETX(pUM, idx);
                tmpList = pTxQ->freeTxDescQ;
                s_list_clear(&pTxQ->freeTxDescQ);
                BNXE_LOCK_EXIT_FREETX(pUM, idx);

                BnxeTxPktsFreeList(&tmpList);

                return -1;
            }

            BNXE_LOCK_ENTER_FREETX(pUM, idx);
            s_list_push_tail(&pTxQ->freeTxDescQ, &pTxPkt->lm_pkt.link);
            BNXE_LOCK_EXIT_FREETX(pUM, idx);
        }
    }

    return 0;
}


int BnxeTxPktsInit(um_device_t * pUM,
                   int           cliIdx)
{
    int idx, rc;

    switch (cliIdx)
    {
    case LM_CLI_IDX_FCOE:

        rc = BnxeTxPktsInitIdx(pUM, FCOE_CID(&pUM->lm_dev));
        break;

    case LM_CLI_IDX_NDIS:

        LM_FOREACH_TSS_IDX(&pUM->lm_dev, idx)
        {
            if ((rc = BnxeTxPktsInitIdx(pUM, idx)) < 0)
            {
                break;
            }
        }

        break;

    default:

        BnxeLogWarn(pUM, "ERROR: Invalid cliIdx for BnxeTxPktsFini (%d)", cliIdx);
        rc = -1;
        break;
    }

    return rc;
}


static void BnxeTxPktsFiniIdx(um_device_t * pUM,
                              int           idx)
{
    lm_device_t * pLM = &pUM->lm_dev;
    TxQueue *     pTxQ;
    s_list_t      tmpList;

    pTxQ = &pUM->txq[idx];

    BNXE_LOCK_ENTER_FREETX(pUM, idx);
    tmpList = pTxQ->freeTxDescQ;
    s_list_clear(&pTxQ->freeTxDescQ);
    BNXE_LOCK_EXIT_FREETX(pUM, idx);

    BNXE_LOCK_ENTER_TX(pUM, idx);
    s_list_add_tail(&tmpList, &pTxQ->sentTxQ);
    s_list_clear(&pTxQ->sentTxQ);
    BNXE_LOCK_EXIT_TX(pUM, idx);

    /* there could be more than originally allocated but less is bad */
    if (s_list_entry_cnt(&tmpList) <
        pUM->devParams.numTxDesc[LM_CHAIN_IDX_CLI(pLM, idx)])
    {
        BnxeLogWarn(pUM, "Missing TX descriptors (%lu / %d) (TxFail: %d)",
                    s_list_entry_cnt(&tmpList), pUM->devParams.numTxDesc,
                    pTxQ->txFailed);
    }

    BnxeTxPktsFreeList(&tmpList);
}


void BnxeTxPktsFini(um_device_t * pUM,
                    int           cliIdx)
{
    int idx;

    switch (cliIdx)
    {
    case LM_CLI_IDX_FCOE:

        BnxeTxPktsFiniIdx(pUM, FCOE_CID(&pUM->lm_dev));
        break;

    case LM_CLI_IDX_NDIS:

        LM_FOREACH_TSS_IDX(&pUM->lm_dev, idx)
        {
            BnxeTxPktsFiniIdx(pUM, idx);
        }

        break;

    default:

        BnxeLogWarn(pUM, "ERROR: Invalid cliIdx for BnxeTxPktsFini (%d)", cliIdx);
        break;
    }
}

