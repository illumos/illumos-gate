/*
 * Copyright 2014-2017 Cavium, Inc.
 * The contents of this file are subject to the terms of the Common Development
 * and Distribution License, v.1,  (the "License").
 *
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at available
 * at http://opensource.org/licenses/CDDL-1.0
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "lm5706.h"
#include <sys/crc32.h>

/*
 * When using "crc32" or "crc16" these initial CRC values must be given to
 * the respective function the first time it is called. The function can
 * then be called with the return value from the last call of the function
 * to generate a running CRC over multiple data blocks.
 * When the last data block has been processed using the "crc32" algorithm
 * the CRC value should be inverted to produce the final CRC value:
 * e.g. CRC = ~CRC
 */

#define startCRC32  (0xFFFFFFFF)    /* CRC initialised to all 1s */

/*
 * For the CRC-32 residual to be calculated correctly requires that the CRC
 * value is in memory little-endian due to the byte read, bit-ordering
 * nature of the algorithm.
 */
#define CRC32residual   (0xDEBB20E3)    /* good CRC-32 residual */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
static void
post_bd_buffer(
    lm_rx_chain_t *rxq,
    u64_t  phy_addr,
    u32_t bd_len)
{
    rx_bd_t *prod_bd;
    rx_bd_t *cur_bd;
    u16_t prod_idx;


    prod_bd = rxq->prod_bd;
    prod_idx = rxq->prod_idx;

    cur_bd = prod_bd;

    prod_bd++;
    prod_idx++;

    /* Check for the last bd on this BD page. */
    if((prod_idx & MAX_BD_PER_PAGE) == MAX_BD_PER_PAGE)
    {
        prod_idx++;
        prod_bd = *((rx_bd_t **) ((tx_bd_next_t *)
            prod_bd)->tx_bd_next_reserved);
    }

    cur_bd->rx_bd_haddr_lo = ((lm_u64_t *)&phy_addr)->as_u32.low;
    cur_bd->rx_bd_haddr_hi = ((lm_u64_t *)&phy_addr)->as_u32.high;
    cur_bd->rx_bd_len = bd_len;
    cur_bd->rx_bd_flags = (RX_BD_FLAGS_END | RX_BD_FLAGS_START);

    rxq->bd_left--;
    rxq->prod_idx = prod_idx;
    rxq->prod_bd = prod_bd;

} /* post_bd_buffer */

#ifndef LM_NON_LEGACY_MODE_SUPPORT
u32_t
lm_post_buffers(
    lm_device_t *pdev,
    u32_t chain_idx,
    lm_packet_t *packet)    /* optional. */
{
    lm_rx_chain_t *rxq;
    u32_t pkt_queued;
    rx_bd_t *cur_bd;
    u16_t cur_idx;

    rxq = &pdev->rx_info.chain[chain_idx];

    pkt_queued = 0;

    /* Make sure we have a bd left for posting a receive buffer. */
    if(packet)
    {
        DbgBreakIf(SIG(packet) != L2PACKET_RX_SIG);

        if(rxq->bd_left == 0)
        {
            s_list_push_tail(&rxq->free_descq, &packet->link);
            packet = NULL;
        }
    }
    else if(rxq->bd_left)
    {
        packet = (lm_packet_t *) s_list_pop_head(&rxq->free_descq);
    }

    while(packet)
    {
        cur_bd = rxq->prod_bd;
        cur_idx = rxq->prod_idx;
        #if DBG
        ((u32_t *) packet->u1.rx.mem_virt)[0] = 0;
        ((u32_t *) packet->u1.rx.mem_virt)[1] = 0;
        ((u32_t *) packet->u1.rx.mem_virt)[2] = 0;
        ((u32_t *) packet->u1.rx.mem_virt)[3] = 0;

        packet->u1.rx.dbg_bd = cur_bd;

        DbgBreakIf(SIG(packet) != L2PACKET_RX_SIG);
        #endif
        post_bd_buffer(
                rxq,
                packet->u1.rx.mem_phy.as_u64,
                packet->u1.rx.buf_size);
        rxq->prod_bseq += packet->u1.rx.buf_size;
        packet->u1.rx.next_bd_idx = rxq->prod_idx;

        /* Tag this bd for debugging.  The last nibble is the chain cid. */
        if(pdev->params.test_mode & TEST_MODE_RX_BD_TAGGING)
        {
            cur_bd->rx_bd_flags |= (u16_t)cur_idx << 4;     // put bd idx at the 12 msb of flags

            cur_bd->unused_0 = (u16_t) (rxq->cid_addr);
        }
        else
        {
            cur_bd->unused_0 = 0;
        }
        // Move on to next packet
        s_list_push_tail(&rxq->active_descq, &packet->link);
        pkt_queued++;

        if(rxq->bd_left == 0)
        {
            break;
        }

        packet = (lm_packet_t *) s_list_pop_head(&rxq->free_descq);
   }


    if(pkt_queued)
    {
        MBQ_WR16(
            pdev,
            GET_CID(rxq->cid_addr),
            OFFSETOF(l2_bd_chain_context_t, l2ctx_host_bdidx),
            rxq->prod_idx);

        MBQ_WR32(
            pdev,
            GET_CID(rxq->cid_addr),
            OFFSETOF(l2_bd_chain_context_t, l2ctx_host_bseq),
            rxq->prod_bseq);
    }

    return pkt_queued;
} /* lm_post_buffers */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC u32_t
get_packets_rcvd(
    struct _lm_device_t *pdev,
    lm_rx_chain_t *rxq,
    u16_t hw_con_idx,
    s_list_t *rcvd_list)
{
    l2_fhdr_t *rx_hdr;
    lm_packet_t *pkt;
    u32_t byte_cnt;
    u32_t pkt_cnt;

    pkt_cnt = 0;
    byte_cnt = 0;

    /* The consumer index may stop at the end of a page boundary.
     * In this case, we need to advance the next to the next one. */
    if((hw_con_idx & MAX_BD_PER_PAGE) == MAX_BD_PER_PAGE)
    {
        hw_con_idx++;
    }

    while(rxq->con_idx != hw_con_idx)
    {
        DbgBreakIf(S16_SUB(hw_con_idx, rxq->con_idx) <= 0);

        pkt = (lm_packet_t *) s_list_pop_head(&rxq->active_descq);

        DbgBreakIf(pkt == NULL);
        DbgBreakIf(SIG(pkt) != L2PACKET_RX_SIG);

        mm_flush_cache(
            pdev,
            pkt->u1.rx.mem_virt,
            pkt->u1.rx.mem_phy,
            pkt->u1.rx.buf_size,
            FLUSH_CACHE_AFTER_DMA_WRITE);

        rxq->bd_left++;

        /* Advance the rxq->con_idx to the start bd_idx of the next packet. */
        rxq->con_idx = pkt->u1.rx.next_bd_idx;

        rx_hdr = (l2_fhdr_t *) pkt->u1.rx.mem_virt;
        pkt->status = LM_STATUS_SUCCESS;
        pkt->size = rx_hdr->l2_fhdr_pkt_len - 4 /* CRC32 */;
        pkt->u1.rx.flags = 0;

        DbgBreakIf(
            (rx_hdr->l2_fhdr_status & L2_FHDR_STATUS_L2_VLAN_TAG) &&
            pdev->params.keep_vlan_tag &&
            (pkt->size < MIN_ETHERNET_PACKET_SIZE ||
            pkt->size > pdev->params.mtu+4));
        DbgBreakIf(
            (rx_hdr->l2_fhdr_status & L2_FHDR_STATUS_L2_VLAN_TAG) &&
            pdev->params.keep_vlan_tag == 0 &&
            (pkt->size < MIN_ETHERNET_PACKET_SIZE-4 ||
            pkt->size > pdev->params.mtu));
        DbgBreakIf(
            (rx_hdr->l2_fhdr_status & L2_FHDR_STATUS_L2_VLAN_TAG) == 0 &&
            (pkt->size < MIN_ETHERNET_PACKET_SIZE ||
            pkt->size > pdev->params.mtu));

        if(rx_hdr->l2_fhdr_status & L2_FHDR_STATUS_RSS_HASH)
        {
            pkt->u1.rx.flags |= LM_RX_FLAG_VALID_HASH_VALUE;
            pkt->u1.rx.hash_value = rx_hdr->l2_fhdr_hash;
        }

        if(rx_hdr->l2_fhdr_status & L2_FHDR_STATUS_L2_VLAN_TAG)
        {
            pkt->u1.rx.flags |= LM_RX_FLAG_VALID_VLAN_TAG;
            pkt->u1.rx.vlan_tag = rx_hdr->l2_fhdr_vlan_tag;
        }

        if(rx_hdr->l2_fhdr_status & L2_FHDR_STATUS_IP_DATAGRAM)
        {
            if(rx_hdr->l2_fhdr_errors & 0x40)
            {
                pkt->u1.rx.flags |= LM_RX_FLAG_IS_IPV6_DATAGRAM;
            }
            else
            {
                pkt->u1.rx.flags |= LM_RX_FLAG_IS_IPV4_DATAGRAM;
            }

            if(rx_hdr->l2_fhdr_errors & L2_FHDR_ERRORS_IP_BAD_XSUM)
            {
                pkt->u1.rx.ip_cksum = rx_hdr->l2_fhdr_ip_xsum;
            }
            else
            {
                pkt->u1.rx.ip_cksum = 0xffff;
            }
        }

        if(rx_hdr->l2_fhdr_status & L2_FHDR_STATUS_TCP_SEGMENT)
        {
            pkt->u1.rx.flags |= LM_RX_FLAG_IS_TCP_SEGMENT;

            if(rx_hdr->l2_fhdr_errors & L2_FHDR_ERRORS_TCP_BAD_XSUM)
            {
                pkt->u1.rx.tcp_or_udp_cksum = rx_hdr->l2_fhdr_tcp_udp_xsum;
            }
            else
            {
                pkt->u1.rx.tcp_or_udp_cksum = 0xffff;
            }
        }
        else if(rx_hdr->l2_fhdr_status & L2_FHDR_STATUS_UDP_DATAGRAM)
        {
            pkt->u1.rx.flags |= LM_RX_FLAG_IS_UDP_DATAGRAM;

            if(rx_hdr->l2_fhdr_errors & L2_FHDR_ERRORS_UDP_BAD_XSUM)
            {
                pkt->u1.rx.tcp_or_udp_cksum = rx_hdr->l2_fhdr_tcp_udp_xsum;
            }
            else
            {
                pkt->u1.rx.tcp_or_udp_cksum = 0xffff;
            }
        }

        if((rx_hdr->l2_fhdr_errors & (
            L2_FHDR_ERRORS_BAD_CRC |
            L2_FHDR_ERRORS_PHY_DECODE |
            L2_FHDR_ERRORS_ALIGNMENT |
            L2_FHDR_ERRORS_TOO_SHORT |
            L2_FHDR_ERRORS_GIANT_FRAME)) == 0)
        {
            if(pdev->params.test_mode & TEST_MODE_VERIFY_RX_CRC)
            {
		    uint32_t crc;
                // Offset for CRC depends if there is lookahead buffer
                // since L2 frame header could be in lookahead buffer
		    CRC32(crc, (u8_t *)(pkt->u1.rx.mem_virt + L2RX_FRAME_HDR_LEN),
                    rx_hdr->l2_fhdr_pkt_len, startCRC32, crc32_table);
		    if (crc != CRC32residual)
                {
                    TRIGGER(pdev, TEST_MODE_VERIFY_RX_CRC);

                    DbgBreakMsg("Bad CRC32 in rx packet.\n");

                    pkt->status = LM_STATUS_FAILURE;
                }
            }
        }
        else
        {
            if(!(pdev->rx_info.mask[rxq->idx] & LM_RX_MASK_ACCEPT_ERROR_PACKET))
            {
                pkt->status = LM_STATUS_FAILURE;
            }

            pdev->rx_info.stats.err++;

            if(rx_hdr->l2_fhdr_errors & L2_FHDR_ERRORS_BAD_CRC)
            {
                pdev->rx_info.stats.crc++;
            }

            if(rx_hdr->l2_fhdr_errors & L2_FHDR_ERRORS_PHY_DECODE)
            {
                pdev->rx_info.stats.phy_err++;
            }

            if(rx_hdr->l2_fhdr_errors & L2_FHDR_ERRORS_ALIGNMENT)
            {
                pdev->rx_info.stats.alignment++;
            }

            if(rx_hdr->l2_fhdr_errors & L2_FHDR_ERRORS_TOO_SHORT)
            {
                pdev->rx_info.stats.short_packet++;
            }

            if(rx_hdr->l2_fhdr_errors & L2_FHDR_ERRORS_GIANT_FRAME)
            {
                pdev->rx_info.stats.giant_packet++;
            }

            DbgBreakIf(
                rx_hdr->l2_fhdr_errors & ~(L2_FHDR_ERRORS_BAD_CRC |
                L2_FHDR_ERRORS_PHY_DECODE | L2_FHDR_ERRORS_ALIGNMENT |
                L2_FHDR_ERRORS_TOO_SHORT | L2_FHDR_ERRORS_GIANT_FRAME));
        }

        pkt_cnt++;
        byte_cnt += pkt->size;

        s_list_push_tail(rcvd_list, &pkt->link);
    }

    return pkt_cnt;
} /* get_packets_rcvd */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
u32_t
lm_get_packets_rcvd(
    struct _lm_device_t *pdev,
    u32_t qidx,
    u32_t con_idx,
    s_list_t *rcvd_list)
{
    lm_rx_chain_t *rxq;
    u16_t hw_con_idx;
    u32_t pkts_added;
    u32_t pkt_cnt;

    rxq = &pdev->rx_info.chain[qidx];

    if(con_idx)
    {
        hw_con_idx = con_idx & 0xffff;

        pkt_cnt = get_packets_rcvd(pdev, rxq, hw_con_idx, rcvd_list);
    }
    else
    {
        pkt_cnt = 0;

        for(; ;)
        {
            hw_con_idx = *rxq->hw_con_idx_ptr;

            pkts_added = get_packets_rcvd(pdev, rxq, hw_con_idx, rcvd_list);
            if(pkts_added == 0)
            {
                break;
            }

            pkt_cnt += pkts_added;
        }
    }

    return pkt_cnt;
} /* lm_get_packets_rcvd */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void
lm_service_rx_int(
    lm_device_t *pdev,
    u32_t chain_idx)
{
    lm_packet_t *pkt_arr[MAX_PACKETS_PER_INDICATION];
    lm_packet_t **pkt_arr_ptr;
    s_list_t rcvd_list;
    lm_packet_t *pkt;
    u32_t pkt_cnt;

    s_list_init(&rcvd_list, NULL, NULL, 0);

    (void) lm_get_packets_rcvd(pdev, chain_idx, 0, &rcvd_list);

    while(!s_list_is_empty(&rcvd_list))
    {
        pkt_arr_ptr = pkt_arr;

        for(pkt_cnt = 0; pkt_cnt < MAX_PACKETS_PER_INDICATION; pkt_cnt++)
        {
            pkt = (lm_packet_t *) s_list_pop_head(&rcvd_list);
            if(pkt == NULL)
            {
                break;
            }

            *pkt_arr_ptr = pkt;
            pkt_arr_ptr++;
        }

        mm_indicate_rx(pdev, chain_idx, pkt_arr, pkt_cnt);
    }
} /* lm_service_rx_int */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void
lm_recv_abort(
    struct _lm_device_t *pdev,
    u32_t idx)
{
    lm_rx_chain_t *rxq;
    lm_packet_t *pkt;

    DbgBreakIf(idx >= pdev->rx_info.num_rxq);

    rxq = &pdev->rx_info.chain[idx];

    for(; ;)
    {
        pkt = (lm_packet_t *) s_list_pop_head(&rxq->active_descq);
        if(pkt == NULL)
        {
            break;
        }

        pkt->status = LM_STATUS_ABORTED;
        rxq->bd_left++;
        pdev->rx_info.stats.aborted++;

        s_list_push_tail(&rxq->free_descq, &pkt->link);
    }
} /* lm_recv_abort */
#else /* LM_NON_LEGACY_MODE_SUPPORT */
/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
u32_t
lm_post_buffers(
    lm_device_t *pdev,
    u32_t chain_idx,
    lm_packet_t *packet,
    lm_frag_list_t *frags)
{
    lm_rx_chain_t *rxq;
    u32_t pkt_queued;
    rx_bd_t *cur_bd;
    u16_t cur_idx;
    lm_pkt_rx_info_t *pkt_info;
    lm_address_t mem_phy;

    rxq = &pdev->rx_info.chain[chain_idx];

    pkt_queued = 0;

    /* Make sure we have a bd left for posting a receive buffer. */
    if(packet)
    {
        if(rxq->vmq_lookahead_size && rxq->bd_left < 2)
        {
            return pkt_queued;
        }
        else if(rxq->bd_left == 0)
        {
            return pkt_queued;
        }

        pkt_info = packet->u1.rx.rx_pkt_info;

        cur_bd = rxq->prod_bd;
        cur_idx = rxq->prod_idx;
        #if DBG
        ((u32_t *) pkt_info->mem_virt)[0] = 0;
        ((u32_t *) pkt_info->mem_virt)[1] = 0;
        ((u32_t *) pkt_info->mem_virt)[2] = 0;
        ((u32_t *) pkt_info->mem_virt)[3] = 0;
        packet->u1.rx.dbg_bd = cur_bd;
        packet->u1.rx.dbg_bd1 = NULL;
        #endif
        if (rxq->vmq_lookahead_size)
        {
            // Break down 2 BDs for lookahead header support
            // We cannot allow odd number of BDs
            // The first BD must at least fit the L2 frame header
            DbgBreakIf(frags->cnt != 2);
            DbgBreakIf(frags->frag_arr[0].size < rxq->vmq_lookahead_size);

            post_bd_buffer(
                rxq,
                frags->frag_arr[0].addr.as_u64,
                frags->frag_arr[0].size);
            cur_bd->rx_bd_flags |= RX_BD_FLAGS_HEADERSPLIT;
            rxq->prod_bseq += frags->frag_arr[0].size;

            #if DBG
            packet->u1.rx.dbg_bd1 = rxq->prod_bd;
            #endif
            post_bd_buffer(
                rxq,
                frags->frag_arr[1].addr.as_u64,
                frags->frag_arr[1].size);
            rxq->prod_bseq += frags->frag_arr[1].size;
        }
        else
        {
            DbgBreakIf(frags->cnt != 1);
            post_bd_buffer(
                rxq,
                frags->frag_arr[0].addr.as_u64,
                frags->frag_arr[0].size);
            rxq->prod_bseq += frags->frag_arr[0].size;
            if(pdev->params.test_mode & TEST_MODE_RX_BD_TAGGING)
            {
                // put bd idx at the 12 msb of flags
                cur_bd->rx_bd_flags |= (u16_t)cur_idx << 4;
            }
        }

        packet->u1.rx.next_bd_idx = rxq->prod_idx;
        /* Tag this bd for debugging.  The last nibble is the chain cid. */
        if(pdev->params.test_mode & TEST_MODE_RX_BD_TAGGING)
        {
            cur_bd->unused_0 = (u16_t) (rxq->cid_addr);
        }
        else
        {
            cur_bd->unused_0 = 0;
        }

        // Move on to next packet
        s_list_push_tail(&rxq->active_descq, &packet->link);
        pkt_queued++;
    }

    return pkt_queued;
} /* lm_post_buffers */

/*******************************************************************************
 * DescriptionX_BD_FLAGS_HEADERSPLIT
 *
 * Return:
 ******************************************************************************/
void
lm_post_rx_bd(
    lm_device_t *pdev,
    lm_rx_chain_t *rxq
    )
{
    MBQ_WR16(
        pdev,
        GET_CID(rxq->cid_addr),
        OFFSETOF(l2_bd_chain_context_t, l2ctx_host_bdidx),
        rxq->prod_idx);

    MBQ_WR32(
        pdev,
        GET_CID(rxq->cid_addr),
        OFFSETOF(l2_bd_chain_context_t, l2ctx_host_bseq),
        rxq->prod_bseq);
}

/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC u32_t
get_packets_rcvd(
    struct _lm_device_t *pdev,
    lm_rx_chain_t *rxq,
    u16_t hw_con_idx,
    s_list_t *rcvd_list)
{
    l2_fhdr_t *rx_hdr;
    lm_packet_t *pkt;
    u32_t byte_cnt;
    u32_t pkt_cnt;
    lm_pkt_rx_info_t *pkt_info;
    u8_t l2_abort_packet = FALSE;

    pkt_cnt = 0;
    byte_cnt = 0;

    /* The consumer index may stop at the end of a page boundary.
     * In this case, we need to advance the next to the next one. */
    if((hw_con_idx & MAX_BD_PER_PAGE) == MAX_BD_PER_PAGE)
    {
        hw_con_idx++;
    }

    while(rxq->con_idx != hw_con_idx)
    {
        DbgBreakIf(S16_SUB(hw_con_idx, rxq->con_idx) <= 0);

        pkt = (lm_packet_t *) s_list_pop_head(&rxq->active_descq);

        DbgBreakIf(pkt == NULL);
        if(!pkt)
		{
			DbgBreakIf(!s_list_is_empty(&rxq->active_descq));
			break;
		}
        pkt_info = pkt->u1.rx.rx_pkt_info;

        //mm_flush_cache(
        //    pdev,
        //    pkt_info->mem_virt,
        //    pkt->sgl->Elements[0].Address,
        //    pkt_info->size,
        //    FLUSH_CACHE_AFTER_DMA_WRITE);

        // In case of Lookahead header support, each packet was split to 2 BDs
        rxq->bd_left += rxq->vmq_lookahead_size? 2 : 1;

        /* Advance the rxq->con_idx to the start bd_idx of the next packet. */
        rxq->con_idx = pkt->u1.rx.next_bd_idx;

        rx_hdr = (l2_fhdr_t *) pkt_info->mem_virt;
        if(l2_abort_packet == FALSE &&
           rx_hdr->l2_fhdr_pkt_len == 0)
        {
            DbgBreakIf(!(rx_hdr->l2_fhdr_errors & L2_FHDR_ERRORS_ABORT_PKT));
            // Set upon the first BD detecting L2_FHDR_ERRORS_ABORT_PKT
            l2_abort_packet = TRUE;
        }

        if(l2_abort_packet)
        {
            pkt->status = LM_STATUS_ABORTED;
            pkt_info->size = 0;
            pdev->rx_info.stats.aborted++;
        }
        else
        {
            pkt->status = LM_STATUS_SUCCESS;
            pkt_info->size = rx_hdr->l2_fhdr_pkt_len - 4 /* CRC32 */;
            pkt_info->flags = 0;

            DbgBreakIf(
                (rx_hdr->l2_fhdr_status & L2_FHDR_STATUS_L2_VLAN_TAG) &&
                pdev->params.keep_vlan_tag &&
                (pkt_info->size < MIN_ETHERNET_PACKET_SIZE ||
                pkt_info->size > pdev->params.mtu+4));
            DbgBreakIf(
                (rx_hdr->l2_fhdr_status & L2_FHDR_STATUS_L2_VLAN_TAG) &&
                pdev->params.keep_vlan_tag == 0 &&
                (pkt_info->size < MIN_ETHERNET_PACKET_SIZE-4 ||
                pkt_info->size > pdev->params.mtu));
            DbgBreakIf(
                (rx_hdr->l2_fhdr_status & L2_FHDR_STATUS_L2_VLAN_TAG) == 0 &&
                (pkt_info->size < MIN_ETHERNET_PACKET_SIZE ||
                pkt_info->size > pdev->params.mtu));

            if(rx_hdr->l2_fhdr_status & L2_FHDR_STATUS_RSS_HASH)
            {
                pkt_info->flags |= LM_RX_FLAG_VALID_HASH_VALUE;
                pkt->u1.rx.hash_value = rx_hdr->l2_fhdr_hash;
            }

            if(rx_hdr->l2_fhdr_status & L2_FHDR_STATUS_L2_VLAN_TAG)
            {
                pkt_info->flags |= LM_RX_FLAG_VALID_VLAN_TAG;
                pkt_info->vlan_tag = rx_hdr->l2_fhdr_vlan_tag;
            }

            if(rx_hdr->l2_fhdr_status & L2_FHDR_STATUS_IP_DATAGRAM)
            {
                if(rx_hdr->l2_fhdr_errors & 0x40)
                {
                    pkt_info->flags |= LM_RX_FLAG_IS_IPV6_DATAGRAM;
                }
                else
                {
                    pkt_info->flags |= LM_RX_FLAG_IS_IPV4_DATAGRAM;
                }

                if(rx_hdr->l2_fhdr_errors & L2_FHDR_ERRORS_IP_BAD_XSUM)
                {
                    pkt_info->flags |= LM_RX_FLAG_IP_CKSUM_IS_BAD;
                }
                else
                {
                    pkt_info->flags |= LM_RX_FLAG_IP_CKSUM_IS_GOOD;
                }
            }

            if(rx_hdr->l2_fhdr_status & L2_FHDR_STATUS_TCP_SEGMENT)
            {
                pkt_info->flags |= LM_RX_FLAG_IS_TCP_SEGMENT;

                if(rx_hdr->l2_fhdr_errors & L2_FHDR_ERRORS_TCP_BAD_XSUM)
                {
                    pkt_info->flags |= LM_RX_FLAG_TCP_CKSUM_IS_BAD;
                }
                else
                {
                    pkt_info->flags |= LM_RX_FLAG_TCP_CKSUM_IS_GOOD;
                }
            }
            else if(rx_hdr->l2_fhdr_status & L2_FHDR_STATUS_UDP_DATAGRAM)
            {
                pkt_info->flags |= LM_RX_FLAG_IS_UDP_DATAGRAM;

                if(rx_hdr->l2_fhdr_errors & L2_FHDR_ERRORS_UDP_BAD_XSUM)
                {
                    pkt_info->flags |= LM_RX_FLAG_UDP_CKSUM_IS_BAD;
                }
                else
                {
                    pkt_info->flags |= LM_RX_FLAG_UDP_CKSUM_IS_GOOD;
                }
            }

            if((rx_hdr->l2_fhdr_errors & (
                L2_FHDR_ERRORS_BAD_CRC |
                L2_FHDR_ERRORS_PHY_DECODE |
                L2_FHDR_ERRORS_ALIGNMENT |
                L2_FHDR_ERRORS_TOO_SHORT |
                L2_FHDR_ERRORS_GIANT_FRAME)) == 0)
            {
                if(pdev->params.test_mode & TEST_MODE_VERIFY_RX_CRC)
                {
			uint32_t crc;
                    // Offset for CRC depends if there is lookahead buffer
                    // since L2 frame header could be in lookahead buffer
			CRC32(crc, (u8_t *)pkt_info->mem_virt + L2RX_FRAME_HDR_LEN,
                        rx_hdr->l2_fhdr_pkt_len, startCRC32, crc32_table);
		    if (crc != CRC32residual)
                    {
                        TRIGGER(pdev, TEST_MODE_VERIFY_RX_CRC);

                        DbgBreakMsg("Bad CRC32 in rx packet.\n");

                        pkt->status = LM_STATUS_FAILURE;
                    }
                }
            }
            else
            {
                if(!(pdev->rx_info.mask[rxq->idx] & LM_RX_MASK_ACCEPT_ERROR_PACKET))
                {
                    pkt->status = LM_STATUS_FAILURE;
                }

                pdev->rx_info.stats.err++;

                if(rx_hdr->l2_fhdr_errors & L2_FHDR_ERRORS_BAD_CRC)
                {
                    pdev->rx_info.stats.crc++;
                }

                if(rx_hdr->l2_fhdr_errors & L2_FHDR_ERRORS_PHY_DECODE)
                {
                    pdev->rx_info.stats.phy_err++;
                }

                if(rx_hdr->l2_fhdr_errors & L2_FHDR_ERRORS_ALIGNMENT)
                {
                    pdev->rx_info.stats.alignment++;
                }

                if(rx_hdr->l2_fhdr_errors & L2_FHDR_ERRORS_TOO_SHORT)
                {
                    pdev->rx_info.stats.short_packet++;
                }

                if(rx_hdr->l2_fhdr_errors & L2_FHDR_ERRORS_GIANT_FRAME)
                {
                    pdev->rx_info.stats.giant_packet++;
                }

                DbgBreakIf(
                    rx_hdr->l2_fhdr_errors & ~(L2_FHDR_ERRORS_BAD_CRC |
                    L2_FHDR_ERRORS_PHY_DECODE | L2_FHDR_ERRORS_ALIGNMENT |
                    L2_FHDR_ERRORS_TOO_SHORT | L2_FHDR_ERRORS_GIANT_FRAME));
            }
        }
        pkt_cnt++;
        byte_cnt += pkt_info->size;

        s_list_push_tail(rcvd_list, &pkt->link);
    }

    return pkt_cnt;
} /* get_packets_rcvd */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
u32_t
lm_get_packets_rcvd(
    struct _lm_device_t *pdev,
    u32_t qidx,
    u32_t con_idx,
    s_list_t *rcvd_list)
{
    lm_rx_chain_t *rxq;
    u16_t hw_con_idx;
    u32_t pkts_added;
    u32_t pkt_cnt;

    rxq = &pdev->rx_info.chain[qidx];

    if(con_idx)
    {
        hw_con_idx = con_idx & 0xffff;

        pkt_cnt = get_packets_rcvd(pdev, rxq, hw_con_idx, rcvd_list);
    }
    else
    {
        pkt_cnt = 0;

        for(; ;)
        {
            hw_con_idx = *rxq->hw_con_idx_ptr;

            pkts_added = get_packets_rcvd(pdev, rxq, hw_con_idx, rcvd_list);
            if(pkts_added == 0)
            {
                break;
            }

            pkt_cnt += pkts_added;
        }
    }

    return pkt_cnt;
} /* lm_get_packets_rcvd */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void
lm_service_rx_int(
    lm_device_t *pdev,
    u32_t chain_idx)
{
    lm_packet_t *pkt_arr[MAX_PACKETS_PER_INDICATION];
    lm_packet_t **pkt_arr_ptr;
    s_list_t rcvd_list;
    lm_packet_t *pkt;
    u32_t pkt_cnt;

    s_list_init(&rcvd_list, NULL, NULL, 0);

    lm_get_packets_rcvd(pdev, chain_idx, 0, &rcvd_list);

    while(!s_list_is_empty(&rcvd_list))
    {
        pkt_arr_ptr = pkt_arr;

        for(pkt_cnt = 0; pkt_cnt < MAX_PACKETS_PER_INDICATION; pkt_cnt++)
        {
            pkt = (lm_packet_t *) s_list_pop_head(&rcvd_list);
            if(pkt == NULL)
            {
                break;
            }

            *pkt_arr_ptr = pkt;
            pkt_arr_ptr++;
        }

        mm_indicate_rx(pdev, chain_idx, pkt_arr, pkt_cnt, TRUE);
    }
} /* lm_service_rx_int */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void
lm_recv_abort(
    struct _lm_device_t *pdev,
    u32_t idx)
{
    lm_rx_chain_t *rxq;
    lm_packet_t *pkt;
    lm_packet_t *pkt_arr[MAX_PACKETS_PER_INDICATION];
    lm_packet_t **pkt_arr_ptr;
    u32_t pkt_cnt;

    rxq = &pdev->rx_info.chain[idx];

    while(!s_list_is_empty(&rxq->active_descq))
    {
        pkt_arr_ptr = pkt_arr;

        for(pkt_cnt = 0; pkt_cnt < MAX_PACKETS_PER_INDICATION; pkt_cnt++)
        {
            pkt = (lm_packet_t *) s_list_pop_head(&rxq->active_descq);
            if(pkt == NULL)
            {
                break;
            }

            pkt->status = LM_STATUS_ABORTED;
            // In case of Lookahead header support, each packet was split to 2 BDs
            rxq->bd_left += rxq->vmq_lookahead_size? 2 : 1;
            pdev->rx_info.stats.aborted++;

                *pkt_arr_ptr = pkt;
                pkt_arr_ptr++;
        }

        mm_indicate_rx(pdev, idx, pkt_arr, pkt_cnt, FALSE);
    }
} /* lm_recv_abort */

#endif /*LM_NON_LEGACY_MODE_SUPPORT*/
