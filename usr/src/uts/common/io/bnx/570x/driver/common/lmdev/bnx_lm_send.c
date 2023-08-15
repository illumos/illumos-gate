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


#ifndef LM_NON_LEGACY_MODE_SUPPORT
/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t
lm_send_packet(
    lm_device_t *pdev,
    u32_t chain_idx,
    lm_packet_t *packet,
    lm_frag_list_t *frags)
{
    u16_t lso_bd_reserved;
    u16_t ipv6_ext_len;
    lm_tx_chain_t *txq;
    tx_bd_t *start_bd;
    tx_bd_t *last_bd;
    tx_bd_t *prod_bd;
    lm_frag_t *frag;
    u16_t prod_idx;
    u32_t flags;
    u32_t cnt;

    txq = &pdev->tx_info.chain[chain_idx];

    if(packet == NULL)
    {
        // hardcode offset in case of L2_ONLY (e.g Solaris)
        u32_t cmd_offset = 34*sizeof(u32_t); //  == OFFSETOF(l4_context_t, l4ctx_cmd)
        MBQ_WR16(
            pdev,
            GET_CID(txq->cid_addr),
            cmd_offset +
                OFFSETOF(tcp_context_cmd_cell_te_t, ccell_tx_host_bidx),
            txq->prod_idx);
        MBQ_WR32(
            pdev,
            GET_CID(txq->cid_addr),
            cmd_offset +
                OFFSETOF(tcp_context_cmd_cell_te_t, ccell_tx_host_bseq),
            txq->prod_bseq);

        return LM_STATUS_SUCCESS;
    }

    #if DBG
    if(frags->cnt == 0)
    {
        DbgBreakMsg("zero frag_cnt\n");

        return LM_STATUS_INVALID_PARAMETER;
    }

    packet->u1.tx.dbg_start_bd = txq->prod_bd;
    packet->u1.tx.dbg_start_bd_idx = txq->prod_idx;
    packet->u1.tx.dbg_frag_cnt = (u16_t) frags->cnt;
    #endif

    last_bd = NULL;

    if(frags->cnt > txq->bd_left)
    {
        /* The caller should have done this check before calling this
         * routine. */
        DbgBreakMsg("No tx bd left.\n");

        return LM_STATUS_RESOURCE;
    }

    txq->bd_left -= (u16_t) frags->cnt;

    packet->size = 0;
    flags = 0;

    if(packet->u1.tx.flags & LM_TX_FLAG_INSERT_VLAN_TAG)
    {
        flags |= TX_BD_FLAGS_VLAN_TAG;
    }

    if((packet->u1.tx.flags & LM_TX_FLAG_TCP_LSO_FRAME) == 0)
    {
        if(packet->u1.tx.flags & LM_TX_FLAG_COMPUTE_IP_CKSUM)
        {
            flags |= TX_BD_FLAGS_IP_CKSUM;
            LM_INC64(&pdev->tx_info.stats.ip_cso_frames, 1);
        }

        if(packet->u1.tx.flags & LM_TX_FLAG_COMPUTE_TCP_UDP_CKSUM)
        {
            flags |= TX_BD_FLAGS_TCP_UDP_CKSUM;
            if(packet->u1.tx.flags & LM_TX_FLAG_IPV6_PACKET)
            {
                LM_INC64(&pdev->tx_info.stats.ipv6_tcp_udp_cso_frames, 1);
            }
            else
            {
                LM_INC64(&pdev->tx_info.stats.ipv4_tcp_udp_cso_frames, 1);
            }
        }
    }

    if(packet->u1.tx.flags & LM_TX_FLAG_DONT_COMPUTE_CRC)
    {
        flags |= TX_BD_FLAGS_DONT_GEN_CRC;
    }

    if(packet->u1.tx.flags & LM_TX_FLAG_TCP_LSO_FRAME)
    {
        if(packet->u1.tx.flags & LM_TX_FLAG_IPV6_PACKET)
        {
            /* TCP option length - bottom 4 bits of TX_BD_FLAGS_SW_OPTION_WORD
             *    in term of the number of 4-byte words.
             * IP header length - bits 1-2 of bd flag, the upper 2 bits of
             *    tx_bd_reserved, and the upper 1 bit of
             *    TX_BD_FLAGS_SW_OPTION_WORD will be used for IPV6 extension
             *    header length in term of 8-btye words.
             * TX_BD_FLAGS_SW_FLAGS bit will be used to indicate IPV6 LSO. */
            flags |= TX_BD_FLAGS_SW_FLAGS;

            if(packet->u1.tx.flags & LM_TX_FLAG_TCP_LSO_SNAP_FRAME)
            {
                flags |= TX_BD_FLAGS_SW_SNAP;
            }

            DbgBreakIf(packet->u1.tx.lso_tcp_hdr_len < 20 ||
                       packet->u1.tx.lso_tcp_hdr_len > 84 ||
                       packet->u1.tx.lso_tcp_hdr_len % 4);

            /* tcp option length in term of number of 32-bit word.  4 bits
             * are used for the number of words. */
            flags |= (packet->u1.tx.lso_tcp_hdr_len - 20) << 6;

            DbgBreakIf(packet->u1.tx.lso_ip_hdr_len < 20 ||
                       packet->u1.tx.lso_ip_hdr_len > 296 ||
                      (packet->u1.tx.lso_ip_hdr_len - 40) % 8);

            /* ipv6 extension header length.  6 bits are used for the number
             * of 64-bit words. */
            ipv6_ext_len = packet->u1.tx.lso_ip_hdr_len - 40;

            DbgBreakIf(ipv6_ext_len & 0x7);

            /* ext_len in number of 8-byte words. */
            ipv6_ext_len >>= 3;

            flags |= (ipv6_ext_len & 0x3) << 1;             /* bit 1-0 */

            lso_bd_reserved = packet->u1.tx.lso_mss;
            lso_bd_reserved |= (ipv6_ext_len & 0xc) << 12;  /* bit 3-2 */

            flags |= (ipv6_ext_len & 0x10) << 8;            /* bit 4  */

            DbgBreakIf(ipv6_ext_len >> 5);  /* bit 5 & high are invalid. */

            LM_INC64(&pdev->tx_info.stats.ipv6_lso_frames, 1);
        }
        else
        {
            flags |= TX_BD_FLAGS_SW_LSO;
            if(packet->u1.tx.flags & LM_TX_FLAG_TCP_LSO_SNAP_FRAME)
            {
                flags |= TX_BD_FLAGS_SW_SNAP;
            }

            DbgBreakIf(packet->u1.tx.lso_ip_hdr_len +
                packet->u1.tx.lso_tcp_hdr_len > 120);

            /* The size of IP and TCP options in term of 32-bit words. */
            flags |= (packet->u1.tx.lso_ip_hdr_len +
                packet->u1.tx.lso_tcp_hdr_len - 40) << 6;

            lso_bd_reserved = packet->u1.tx.lso_mss;

            LM_INC64(&pdev->tx_info.stats.ipv4_lso_frames, 1);
        }
    }
    else
    {
        lso_bd_reserved = 0;
    }

    start_bd = txq->prod_bd;
    frag = frags->frag_arr;

    /* Get the pointer to the current BD and its index. */
    prod_idx = txq->prod_idx;
    prod_bd = txq->prod_bd;

    /* This is the number of times we cross a BD page boundary for this
     * packet.  This and the bd_used value will give us the total number
     * of BD slots needed to send this packet which is used to determine
     * if a packet has been sent.  We only need this because unlike L2
     * completion, LSO completion does not end at a request boundary.
     * For example, if we had an LSO request that spans BD#100-120.  We
     * could get a transmit consumer index of 115. */
    packet->u1.tx.span_pages = 0;

    /* Initialize the bd's of this packet. */
    for(cnt = 0; cnt < frags->cnt; cnt++)
    {
        DbgBreakIf(frag->size >= 0x10000 || frag->size == 0);

        prod_bd->tx_bd_haddr_lo = frag->addr.as_u32.low;
        prod_bd->tx_bd_haddr_hi = frag->addr.as_u32.high;
        prod_bd->tx_bd_nbytes = (u16_t) frag->size;
        prod_bd->tx_bd_vlan_tag = packet->u1.tx.vlan_tag;
        prod_bd->tx_bd_flags = (u16_t) flags;

        if(packet->u1.tx.flags & LM_TX_FLAG_TCP_LSO_FRAME)
        {
            prod_bd->tx_bd_reserved = lso_bd_reserved;
        }
        else if(pdev->params.test_mode & TEST_MODE_TX_BD_TAGGING)
        {
            prod_bd->tx_bd_reserved = prod_idx & 0x0fff;
            prod_bd->tx_bd_reserved |= (u16_t) (GET_CID(txq->cid_addr) << 12);
        }

        packet->size += frag->size;

        last_bd = prod_bd;
        frag++;

        /* Advance to the next BD. */
        prod_bd++;
        prod_idx++;
        if((prod_idx & MAX_BD_PER_PAGE) == MAX_BD_PER_PAGE)
        {
            /* Only increment span_pages when this BDs for this request
             * cross a page boundary. */
            if(cnt+1 < frags->cnt)
            {
                packet->u1.tx.span_pages++;
            }

            prod_idx++;
            prod_bd = *((tx_bd_t **) ((tx_bd_next_t *)
                prod_bd)->tx_bd_next_reserved);
        }
    }

    /* Set the bd flags of the first and last BDs. */
    flags |= TX_BD_FLAGS_END;
    if(packet->u1.tx.flags & LM_TX_FLAG_COAL_NOW)
    {
        flags |= TX_BD_FLAGS_COAL_NOW;
    }

    last_bd->tx_bd_flags |= (u16_t) flags;
    start_bd->tx_bd_flags |= TX_BD_FLAGS_START;

    #if INCLUDE_OFLD_SUPPORT
    /* We need to do the padding for the catchup path. */
    if(chain_idx == pdev->tx_info.cu_idx &&
        packet->size < MIN_ETHERNET_PACKET_SIZE)
    {
        last_bd->tx_bd_nbytes +=
            (u16_t) (MIN_ETHERNET_PACKET_SIZE - packet->size);
        packet->size = MIN_ETHERNET_PACKET_SIZE;
    }
    #endif

    /* Save the number of BDs used.  Later we need to add this value back
     * to txq->bd_left when the packet is sent. */
    packet->u1.tx.bd_used = (u16_t) frags->cnt;

    packet->u1.tx.next_bd_idx = prod_idx;

    txq->prod_bd = prod_bd;
    txq->prod_idx = prod_idx;
    txq->prod_bseq += packet->size;
#if (DBG)
    if (chain_idx == pdev->tx_info.cu_idx)
    {
        DbgBreakIf(packet->size > pdev->params.mtu + 4);
    }
    else
    {
        DbgBreakIf(packet->size > pdev->params.mtu &&
            (flags & (TX_BD_FLAGS_SW_LSO | TX_BD_FLAGS_SW_FLAGS)) == 0);
    }
#endif
    s_list_push_tail(&txq->active_descq, &packet->link);

    if(!(packet->u1.tx.flags & LM_TX_FLAG_SKIP_MBQ_WRITE))
    {
        // hardcode offset in case of L2_ONLY (e.g Solaris)
        u32_t cmd_offset = 34*sizeof(u32_t); //  == OFFSETOF(l4_context_t, l4ctx_cmd)
        MBQ_WR16(
            pdev,
            GET_CID(txq->cid_addr),
            cmd_offset +
                OFFSETOF(tcp_context_cmd_cell_te_t, ccell_tx_host_bidx),
            txq->prod_idx);
        MBQ_WR32(
            pdev,
            GET_CID(txq->cid_addr),
            cmd_offset +
                OFFSETOF(tcp_context_cmd_cell_te_t, ccell_tx_host_bseq),
            txq->prod_bseq);
    }

    return LM_STATUS_SUCCESS;
} /* lm_send_packet */
#else
/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t
lm_send_packet(
    lm_device_t *pdev,
    u32_t chain_idx,
    lm_packet_t *packet,
    lm_frag_list_t *frags)
{
    u16_t lso_bd_reserved;
    u16_t ipv6_ext_len;
    lm_tx_chain_t *txq;
    tx_bd_t *start_bd;
    tx_bd_t *last_bd;
    tx_bd_t *prod_bd;
    lm_frag_t *frag;
    u16_t prod_idx;
    u32_t flags;
    u32_t cnt;
    lm_pkt_tx_info_t *pkt_info;

    txq = &pdev->tx_info.chain[chain_idx];

    if(packet == NULL)
    {
        // hardcode offset in case of L2_ONLY (e.g Solaris)
        u32_t cmd_offset = 34*sizeof(u32_t); //  == OFFSETOF(l4_context_t, l4ctx_cmd)
        MBQ_WR16(
            pdev,
            GET_CID(txq->cid_addr),
            cmd_offset +
                OFFSETOF(tcp_context_cmd_cell_te_t, ccell_tx_host_bidx),
            txq->prod_idx);
        if(pdev->vars.enable_cu_rate_limiter &&
           txq->idx == TX_CHAIN_IDX1)
        {
            REG_WR_IND(
                pdev,
                OFFSETOF(reg_space_t, com.com_scratch[0])+COM_HSI_OFFSETOFF(com_cu_host_bseq),
                txq->prod_bseq);
        }
        else
        {
        	MBQ_WR32(
            	pdev,
            	GET_CID(txq->cid_addr),
            	cmd_offset +
                OFFSETOF(tcp_context_cmd_cell_te_t, ccell_tx_host_bseq),
            	txq->prod_bseq);
        }

        return LM_STATUS_SUCCESS;
    }

    #if DBG
    if(frags->cnt == 0)
    {
        DbgBreakMsg("zero frag_cnt\n");

        return LM_STATUS_INVALID_PARAMETER;
    }

    packet->u1.tx.dbg_start_bd = txq->prod_bd;
    packet->u1.tx.dbg_start_bd_idx = txq->prod_idx;
    packet->u1.tx.dbg_frag_cnt = (u16_t) frags->cnt;
    #endif

    last_bd = NULL;

    if(frags->cnt > txq->bd_left)
    {
        /* The caller should have done this check before calling this
         * routine. */
        DbgBreakMsg("No tx bd left.\n");

        return LM_STATUS_RESOURCE;
    }

    txq->bd_left -= (u16_t) frags->cnt;

    pkt_info = packet->u1.tx.tx_pkt_info;
    packet->u1.tx.size = 0;
    flags = 0;

    if(pkt_info->flags & LM_TX_FLAG_INSERT_VLAN_TAG)
    {
        flags |= TX_BD_FLAGS_VLAN_TAG;
    }

    if((pkt_info->flags & LM_TX_FLAG_TCP_LSO_FRAME) == 0)
    {
        if(pkt_info->flags & LM_TX_FLAG_COMPUTE_IP_CKSUM)
        {
            flags |= TX_BD_FLAGS_IP_CKSUM;
            LM_INC64(&pdev->tx_info.stats.ip_cso_frames, 1);
        }

        if(pkt_info->flags & LM_TX_FLAG_COMPUTE_TCP_UDP_CKSUM)
        {
            flags |= TX_BD_FLAGS_TCP_UDP_CKSUM;
            if(pkt_info->flags & LM_TX_FLAG_IPV6_PACKET)
            {
                LM_INC64(&pdev->tx_info.stats.ipv6_tcp_udp_cso_frames, 1);
            }
            else
            {
                LM_INC64(&pdev->tx_info.stats.ipv4_tcp_udp_cso_frames, 1);
            }
        }
    }

    if(pkt_info->flags & LM_TX_FLAG_DONT_COMPUTE_CRC)
    {
        flags |= TX_BD_FLAGS_DONT_GEN_CRC;
    }

    if(pkt_info->flags & LM_TX_FLAG_TCP_LSO_FRAME)
    {
        if(pkt_info->flags & LM_TX_FLAG_IPV6_PACKET)
        {
            /* TCP option length - bottom 4 bits of TX_BD_FLAGS_SW_OPTION_WORD
             *    in term of the number of 4-byte words.
             * IP header length - bits 1-2 of bd flag, the upper 2 bits of
             *    tx_bd_reserved, and the upper 1 bit of
             *    TX_BD_FLAGS_SW_OPTION_WORD will be used for IPV6 extension
             *    header length in term of 8-btye words.
             * TX_BD_FLAGS_SW_FLAGS bit will be used to indicate IPV6 LSO. */
            flags |= TX_BD_FLAGS_SW_FLAGS;

            if(pkt_info->flags & LM_TX_FLAG_TCP_LSO_SNAP_FRAME)
            {
                flags |= TX_BD_FLAGS_SW_SNAP;
            }

            DbgBreakIf(pkt_info->lso_tcp_hdr_len < 20 ||
                       pkt_info->lso_tcp_hdr_len > 84 ||
                       pkt_info->lso_tcp_hdr_len % 4);

            /* tcp option length in term of number of 32-bit word.  4 bits
             * are used for the number of words. */
            flags |= (pkt_info->lso_tcp_hdr_len - 20) << 6;

            DbgBreakIf(pkt_info->lso_ip_hdr_len < 20 ||
                       pkt_info->lso_ip_hdr_len > 296 ||
                      (pkt_info->lso_ip_hdr_len - 40) % 8);

            /* ipv6 extension header length.  6 bits are used for the number
             * of 64-bit words. */
            ipv6_ext_len = pkt_info->lso_ip_hdr_len - 40;

            DbgBreakIf(ipv6_ext_len & 0x7);

            /* ext_len in number of 8-byte words. */
            ipv6_ext_len >>= 3;

            flags |= (ipv6_ext_len & 0x3) << 1;             /* bit 1-0 */

            lso_bd_reserved = pkt_info->lso_mss;
            lso_bd_reserved |= (ipv6_ext_len & 0xc) << 12;  /* bit 3-2 */

            flags |= (ipv6_ext_len & 0x10) << 8;            /* bit 4  */

            DbgBreakIf(ipv6_ext_len >> 5);  /* bit 5 & high are invalid. */

            LM_INC64(&pdev->tx_info.stats.ipv6_lso_frames, 1);
        }
        else
        {
            flags |= TX_BD_FLAGS_SW_LSO;
            if(pkt_info->flags & LM_TX_FLAG_TCP_LSO_SNAP_FRAME)
            {
                flags |= TX_BD_FLAGS_SW_SNAP;
            }

            DbgBreakIf(pkt_info->lso_ip_hdr_len +
                pkt_info->lso_tcp_hdr_len > 120);

            /* The size of IP and TCP options in term of 32-bit words. */
            flags |= (pkt_info->lso_ip_hdr_len +
                pkt_info->lso_tcp_hdr_len - 40) << 6;

            lso_bd_reserved = pkt_info->lso_mss;

            LM_INC64(&pdev->tx_info.stats.ipv4_lso_frames, 1);
        }
    }
    else
    {
        lso_bd_reserved = 0;
    }

    start_bd = txq->prod_bd;
    frag = frags->frag_arr;

    /* Get the pointer to the current BD and its index. */
    prod_idx = txq->prod_idx;
    prod_bd = txq->prod_bd;

    /* This is the number of times we cross a BD page boundary for this
     * packet.  This and the bd_used value will give us the total number
     * of BD slots needed to send this packet which is used to determine
     * if a packet has been sent.  We only need this because unlike L2
     * completion, LSO completion does not end at a request boundary.
     * For example, if we had an LSO request that spans BD#100-120.  We
     * could get a transmit consumer index of 115. */
    packet->u1.tx.span_pages = 0;

    /* Initialize the bd's of this packet. */
    for(cnt = 0; cnt < frags->cnt; cnt++)
    {
        DbgBreakIf(frag->size >= 0x10000 || frag->size == 0);

        prod_bd->tx_bd_haddr_lo = frag->addr.as_u32.low;
        prod_bd->tx_bd_haddr_hi = frag->addr.as_u32.high;
        prod_bd->tx_bd_nbytes = (u16_t) frag->size;
        prod_bd->tx_bd_vlan_tag = pkt_info->vlan_tag;
        prod_bd->tx_bd_flags = (u16_t) flags;

        if(pkt_info->flags & LM_TX_FLAG_TCP_LSO_FRAME)
        {
            prod_bd->tx_bd_reserved = lso_bd_reserved;
        }
        else if(pdev->params.test_mode & TEST_MODE_TX_BD_TAGGING)
        {
            prod_bd->tx_bd_reserved = prod_idx & 0x0fff;
            prod_bd->tx_bd_reserved |= (u16_t) (GET_CID(txq->cid_addr) << 12);
        }

        packet->u1.tx.size += frag->size;

        last_bd = prod_bd;
        frag++;

        /* Advance to the next BD. */
        prod_bd++;
        prod_idx++;
        if((prod_idx & MAX_BD_PER_PAGE) == MAX_BD_PER_PAGE)
        {
            /* Only increment span_pages when this BDs for this request
             * cross a page boundary. */
            if(cnt+1 < frags->cnt)
            {
                packet->u1.tx.span_pages++;
            }

            prod_idx++;
            prod_bd = *((tx_bd_t **) ((tx_bd_next_t *)
                prod_bd)->tx_bd_next_reserved);
        }
    }

    /* Set the bd flags of the first and last BDs. */
    flags |= TX_BD_FLAGS_END;
    if(pkt_info->flags & LM_TX_FLAG_COAL_NOW)
    {
        flags |= TX_BD_FLAGS_COAL_NOW;
    }

    last_bd->tx_bd_flags |= (u16_t) flags;
    start_bd->tx_bd_flags |= TX_BD_FLAGS_START;

    #if INCLUDE_OFLD_SUPPORT
    /* We need to do the padding for the catchup path. */
    if(chain_idx == pdev->tx_info.cu_idx &&
        packet->u1.tx.size < MIN_ETHERNET_PACKET_SIZE)
    {
        last_bd->tx_bd_nbytes +=
            (u16_t) (MIN_ETHERNET_PACKET_SIZE - packet->u1.tx.size);
        packet->u1.tx.size = MIN_ETHERNET_PACKET_SIZE;
    }
    #endif

    /* Save the number of BDs used.  Later we need to add this value back
     * to txq->bd_left when the packet is sent. */
    packet->u1.tx.bd_used = (u16_t) frags->cnt;

    packet->u1.tx.next_bd_idx = prod_idx;

    txq->prod_bd = prod_bd;
    txq->prod_idx = prod_idx;
    txq->prod_bseq += packet->u1.tx.size;
#if (DBG)
    if (chain_idx == pdev->tx_info.cu_idx)
    {
        DbgBreakIf(packet->u1.tx.size > pdev->params.mtu + 4);
    }
    else
    {
        DbgBreakIf(packet->u1.tx.size > pdev->params.mtu &&
            (flags & (TX_BD_FLAGS_SW_LSO | TX_BD_FLAGS_SW_FLAGS)) == 0);
    }
#endif
    s_list_push_tail(&txq->active_descq, &packet->link);

    if(!(pkt_info->flags & LM_TX_FLAG_SKIP_MBQ_WRITE))
    {
        // hardcode offset in case of L2_ONLY (e.g Solaris)
        u32_t cmd_offset = 34*sizeof(u32_t); //  == OFFSETOF(l4_context_t, l4ctx_cmd)
        MBQ_WR16(
            pdev,
            GET_CID(txq->cid_addr),
            cmd_offset +
                OFFSETOF(tcp_context_cmd_cell_te_t, ccell_tx_host_bidx),
            txq->prod_idx);
        if(pdev->vars.enable_cu_rate_limiter &&
           txq->idx == TX_CHAIN_IDX1)
        {
            REG_WR_IND(
                pdev,
                OFFSETOF(reg_space_t, com.com_scratch[0])+COM_HSI_OFFSETOFF(com_cu_host_bseq),
                txq->prod_bseq);
        }
        else
        {
        	MBQ_WR32(
            	pdev,
            	GET_CID(txq->cid_addr),
            	cmd_offset +
                OFFSETOF(tcp_context_cmd_cell_te_t, ccell_tx_host_bseq),
            	txq->prod_bseq);
        }
    }

    return LM_STATUS_SUCCESS;
} /* lm_send_packet */
#endif /* LM_NON_LEGACY_MODE_SUPPORT */


/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC u32_t
get_packets_sent(
    struct _lm_device_t *pdev,
    lm_tx_chain_t *txq,
    u16_t hw_con_idx,
    s_list_t *sent_list)
{
    lm_packet_t *pkt;
    u32_t pkt_cnt;

    /* The consumer index may stop at the end of a page boundary.
     * In this case, we need to advance the next to the next one. */
    if((hw_con_idx & MAX_BD_PER_PAGE) == MAX_BD_PER_PAGE)
    {
        hw_con_idx++;
    }

    pkt_cnt = 0;

    while(txq->con_idx != hw_con_idx)
    {
        DbgBreakIf(S16_SUB(hw_con_idx, txq->con_idx) <= 0);

        pkt = (lm_packet_t *) s_list_peek_head(&txq->active_descq);

        DbgBreakIf(pkt == NULL);

        if(!pkt)
		{
			DbgBreakIf(!s_list_is_empty(&txq->active_descq));
			break;
		}
        /* LSO requests may not complete at the request boundary.
         *
         * if(pkt->u1.tx.flags & LM_TX_FLAG_TCP_LSO_FRAME) */
        {
            if((u16_t) S16_SUB(hw_con_idx, txq->con_idx) <
                pkt->u1.tx.bd_used + pkt->u1.tx.span_pages)
            {
                break;
            }
        }

        #if DBG
        DbgBreakIf(pkt->u1.tx.dbg_start_bd_idx != txq->con_idx);

        /* Make sure hw_con_idx ends at an l2 packet boundary.  For LSO,
         * request, hw_con_idx may not end at the request boundary. */
        while(pkt)
        {
            if(S16_SUB(hw_con_idx, pkt->u1.tx.next_bd_idx) <= 0)
            {
                break;
            }

            pkt = (lm_packet_t *) s_list_next_entry(&pkt->link);
        }

        DbgBreakIf(pkt == NULL);

        /* catchup workaround.
         * DbgBreakIf(
         *    !(pkt->u1.tx.flags & LM_TX_FLAG_TCP_LSO_FRAME) &&
         *    (hw_con_idx != pkt->u1.tx.next_bd_idx)); */
        #endif

        pkt = (lm_packet_t *) s_list_pop_head(&txq->active_descq);

        /* Advance the txq->con_idx to the start bd_idx of the next packet. */
        txq->con_idx = pkt->u1.tx.next_bd_idx;

        pkt->status = LM_STATUS_SUCCESS;

        txq->bd_left += pkt->u1.tx.bd_used;

        s_list_push_tail(sent_list, &pkt->link);

        pkt_cnt++;
    }

    return pkt_cnt;
} /* get_packets_sent */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
u32_t
lm_get_packets_sent(
    struct _lm_device_t *pdev,
    u32_t qidx,
    u32_t con_idx,
    s_list_t *sent_list)
{
    lm_tx_chain_t *txq;
    u16_t hw_con_idx;
    u32_t pkts_added;
    u32_t pkt_cnt;

    txq = &pdev->tx_info.chain[qidx];

    if(con_idx)
    {
        hw_con_idx = con_idx & 0xffff;

        pkt_cnt = get_packets_sent(pdev, txq, hw_con_idx, sent_list);
    }
    else
    {
        pkt_cnt = 0;

        for(; ;)
        {
            hw_con_idx = *txq->hw_con_idx_ptr;

            pkts_added = get_packets_sent(pdev, txq, hw_con_idx, sent_list);
            if(pkts_added == 0)
            {
                break;
            }

            pkt_cnt += pkts_added;
        }
    }

    return pkt_cnt;
} /* lm_get_packets_sent */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void
lm_service_tx_int(
    lm_device_t *pdev,
    u32_t chain_idx)
{
    lm_packet_t *pkt_arr[MAX_PACKETS_PER_INDICATION];
    lm_packet_t **pkt_arr_ptr;
    s_list_t sent_list;
    lm_packet_t *pkt;
    u32_t pkt_cnt;

    s_list_init(&sent_list, NULL, NULL, 0);

    (void) lm_get_packets_sent(pdev, chain_idx, 0, &sent_list);

    while(!s_list_is_empty(&sent_list))
    {
        pkt_arr_ptr = pkt_arr;

        for(pkt_cnt = 0; pkt_cnt < MAX_PACKETS_PER_INDICATION; pkt_cnt++)
        {
            pkt = (lm_packet_t *) s_list_pop_head(&sent_list);
            if(pkt == NULL)
            {
                break;
            }

            *pkt_arr_ptr = pkt;
            pkt_arr_ptr++;
        }

        mm_indicate_tx(pdev, chain_idx, pkt_arr, pkt_cnt);
    }
} /* lm_service_tx_int */



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void
lm_send_abort(
    struct _lm_device_t *pdev,
    u32_t idx)
{
    lm_tx_chain_t *txq;
    lm_packet_t *pkt;

    DbgBreakIf(idx >= pdev->tx_info.num_txq);

    txq = &pdev->tx_info.chain[idx];

    for(; ;)
    {
        pkt = (lm_packet_t *) s_list_pop_head(&txq->active_descq);
        if(pkt == NULL)
        {
            break;
        }

        pkt->status = LM_STATUS_ABORTED;
        pdev->tx_info.stats.aborted++;
        txq->bd_left += pkt->u1.tx.bd_used;

        mm_indicate_tx(pdev, idx, &pkt, 1);
    }

    DbgBreakIf(txq->bd_left !=
        pdev->params.l2_tx_bd_page_cnt[txq->idx] * MAX_BD_PER_PAGE - 1);
} /* lm_send_abort */
