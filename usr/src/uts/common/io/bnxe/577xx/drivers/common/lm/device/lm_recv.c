#include "lm5710.h"
#include "command.h"
#include "bd_chain.h"
#include "ecore_common.h"
#include "mm.h"

#define OOO_CID_USTRORM_PROD_DIFF           (0x4000)

u8_t lm_is_rx_completion(lm_device_t *pdev, u8_t chain_idx)
{
    u8_t result               = FALSE;
    lm_rcq_chain_t *rcq_chain = &LM_RCQ(pdev, chain_idx);

    DbgBreakIf(!(pdev && rcq_chain));

    //the hw_con_idx_ptr of the rcq_chain points directly to the Rx index in the USTORM part of the non-default status block
    if (rcq_chain->hw_con_idx_ptr &&
        (mm_le16_to_cpu(*rcq_chain->hw_con_idx_ptr) !=
        lm_bd_chain_cons_idx(&rcq_chain->bd_chain)))
    {
        result = TRUE;
    }
    DbgMessage(pdev, INFORMi, "lm_is_rx_completion: result is:%s\n", result? "TRUE" : "FALSE");

    return result;
}

/*******************************************************************************
 * Description:
 *  set both rcq, rx bd and rx sge (if valid) prods
 * Return:
 ******************************************************************************/
static void FORCEINLINE lm_rx_set_prods( lm_device_t     *pdev,
                                         u16_t const     iro_prod_offset,
                                         lm_bd_chain_t   *rcq_chain_bd,
                                         lm_bd_chain_t   *rx_chain_bd,
                                         lm_bd_chain_t   *rx_chain_sge,
                                         const u32_t     chain_idx )
{
    lm_rx_chain_t*  rxq_chain           = &LM_RXQ(pdev, chain_idx);
    u32_t           val32               = 0;
    u64_t           val64               = 0;
    u16_t           val16_lo            = lm_bd_chain_prod_idx(rcq_chain_bd);
    u16_t           val16_hi            = lm_bd_chain_prod_idx(rx_chain_bd);
    u32_t const     ustorm_bar_offset   = (IS_CHANNEL_VFDEV(pdev)) ? VF_BAR0_USDM_QUEUES_OFFSET: BAR_USTRORM_INTMEM ;

    if(OOO_CID(pdev) == chain_idx)
    {
        DbgBreakIfFastPath( NULL != rx_chain_sge );
        DbgBreakIfFastPath(IS_CHANNEL_VFDEV(pdev));

        LM_INTMEM_WRITE16(PFDEV(pdev),
                          TSTORM_ISCSI_L2_ISCSI_OOO_PROD_OFFSET(FUNC_ID(pdev)),
                          rxq_chain->common.bd_prod_without_next,
                          BAR_TSTRORM_INTMEM);

        // Ugly FW solution OOO FW wants the
        val16_lo    += OOO_CID_USTRORM_PROD_DIFF;
        val16_hi    += OOO_CID_USTRORM_PROD_DIFF;
    }

    val32       = ((u32_t)(val16_hi << 16) | val16_lo);

    //notify the fw of the prod of the RCQ. No need to do that for the Rx bd chain.
    if( rx_chain_sge )
    {
        val64 = (((u64_t)lm_bd_chain_prod_idx(rx_chain_sge))<<32) | val32 ;

        LM_INTMEM_WRITE64(PFDEV(pdev),
                          iro_prod_offset,
                          val64,
                          ustorm_bar_offset);
    }
    else
    {
        LM_INTMEM_WRITE32(PFDEV(pdev),
                          iro_prod_offset,
                          val32,
                          ustorm_bar_offset);
    }
}
/*******************************************************************************
 * Description:
 *  rx_chain_bd always valid, rx_chain_sge valid only in case we are LAH enabled in this queue
 *  all if() checking will be always done on rx_chain_bd since it is always valid and sge should be consistent
 *  We verify it in case sge is valid
 *  all bd_xxx operations will be done on both
 * Return:
 ******************************************************************************/
u32_t
lm_post_buffers(
    lm_device_t *pdev,
    u32_t chain_idx,
    lm_packet_t *packet,/* optional. */
    u8_t const  is_tpa)
{
    lm_rx_chain_common_t*   rxq_chain_common    = NULL;
    lm_bd_chain_t*          rx_chain_bd         = NULL;
    lm_rx_chain_t*          rxq_chain           = NULL;
    lm_tpa_chain_t *        tpa_chain           = NULL;
    lm_bd_chain_t*          bd_chain_to_check   = NULL;
    lm_rcq_chain_t*         rcq_chain           = &LM_RCQ(pdev, chain_idx);
    lm_bd_chain_t*          rx_chain_sge        = NULL;
    u32_t                   pkt_queued          = 0;
    struct eth_rx_bd*       cur_bd              = NULL;
    struct eth_rx_sge*      cur_sge             = NULL;
    u32_t                   prod_bseq           = 0;
    u32_t                   rcq_prod_bseq       = 0;
    u16_t                   current_prod        = 0;
    u16_t                   active_entry        = 0;

    DbgMessage(pdev, INFORMl2 , "### lm_post_buffers\n");

    // Verify BD's consistent
    DbgBreakIfFastPath( rx_chain_sge && !lm_bd_chains_are_consistent( rx_chain_sge, rx_chain_bd ) );

    if(FALSE == is_tpa)
    {
        rxq_chain_common    = &LM_RXQ_COMMON(pdev, chain_idx);
        rx_chain_bd         = &LM_RXQ_CHAIN_BD(pdev, chain_idx);
        rx_chain_sge        = LM_RXQ_SGE_PTR_IF_VALID(pdev, chain_idx);
        rxq_chain           = &LM_RXQ(pdev, chain_idx);
        tpa_chain           = NULL;
        /* the assumption is that the number of cqes is less or equal to the corresponding rx bds,
           therefore if there no cqes left, break */
        bd_chain_to_check   = &rcq_chain->bd_chain;
    }
    else
    {
        rxq_chain_common    = &LM_TPA_COMMON(pdev, chain_idx);
        rx_chain_bd         = &LM_TPA_CHAIN_BD(pdev, chain_idx);
        rx_chain_sge        = NULL;
        rxq_chain           = NULL;
        tpa_chain           = &LM_TPA(pdev, chain_idx);
        // In TPA we don't add to the RCQ when posting buffers
        bd_chain_to_check   = rx_chain_bd;
    }
    /* Make sure we have a bd left for posting a receive buffer. */
    if(packet)
    {
        // Insert given packet.
        DbgBreakIfFastPath(SIG(packet) != L2PACKET_RX_SIG);

        if(lm_bd_chain_is_empty(bd_chain_to_check))
        {
            s_list_push_tail(&rxq_chain_common->free_descq, &packet->link);
            packet = NULL;
        }
    }
    else if(!lm_bd_chain_is_empty(bd_chain_to_check))
    {
        packet = (lm_packet_t *) s_list_pop_head(&rxq_chain_common->free_descq);
    }
    prod_bseq     = rxq_chain_common->prod_bseq;

    // In TPA we won't increment rcq_prod_bseq
    rcq_prod_bseq = rcq_chain->prod_bseq;

    while(packet)
    {

        current_prod = lm_bd_chain_prod_idx(rx_chain_bd);
        cur_bd  = lm_bd_chain_produce_bd(rx_chain_bd);
        rxq_chain_common->bd_prod_without_next++;
        cur_sge = rx_chain_sge ? lm_bd_chain_produce_bd(rx_chain_sge) : NULL;

        prod_bseq += packet->l2pkt_rx_info->mem_size;

        if(FALSE == is_tpa)
        {
            //take care of the RCQ related prod stuff.

            //update the prod of the RCQ only AFTER the Rx bd!
            rcq_prod_bseq += packet->l2pkt_rx_info->mem_size;

            /* These were actually produced before by fw, but we only produce them now to make sure they're synced with the rx-chain */
            lm_bd_chain_bd_produced(&rcq_chain->bd_chain);
        }

        packet->u1.rx.next_bd_idx = lm_bd_chain_prod_idx(rx_chain_bd);
#if L2_RX_BUF_SIG
        /* make sure signitures exist before and after the buffer */
        DbgBreakIfFastPath(SIG(packet->u1.rx.mem_virt - pdev->params.rcv_buffer_offset) != L2PACKET_RX_SIG);
        DbgBreakIfFastPath(END_SIG(packet->u1.rx.mem_virt, MAX_L2_CLI_BUFFER_SIZE(pdev, chain_idx)) != L2PACKET_RX_SIG);
#endif /* L2_RX_BUF_SIG */

        cur_bd->addr_lo  = mm_cpu_to_le32(packet->u1.rx.mem_phys[0].as_u32.low);
        cur_bd->addr_hi  = mm_cpu_to_le32(packet->u1.rx.mem_phys[0].as_u32.high);

        if( cur_sge )
        {
            cur_sge->addr_lo = mm_cpu_to_le32(packet->u1.rx.mem_phys[1].as_u32.low);
            cur_sge->addr_hi = mm_cpu_to_le32(packet->u1.rx.mem_phys[1].as_u32.high);
        }

        pkt_queued++;

        if(FALSE == is_tpa)
        {
            s_list_push_tail(&rxq_chain->active_descq, &packet->link);
        }
        else
        {
            // Active descriptor must sit in the same entry
            active_entry = LM_TPA_BD_ENTRY_TO_ACTIVE_ENTRY(pdev, chain_idx, current_prod);

            LM_TPA_ACTIVE_ENTRY_BOUNDARIES_VERIFY(pdev, chain_idx,active_entry);
            tpa_chain->sge_chain.active_descq_array[active_entry] = packet;
        }

        if(lm_bd_chain_is_empty(bd_chain_to_check))
            {
                break;
            }

        /* Make sure we have a bd left for posting a receive buffer. */
        packet = (lm_packet_t *) s_list_pop_head(&rxq_chain_common->free_descq);
    }

    rxq_chain_common->prod_bseq = prod_bseq;


    //update the prod of the RCQ only AFTER the Rx bd!
    // This code seems unnecessary maybe should be deleted.
    // Im TPA we won't increment rcq_prod_bseq
    rcq_chain->prod_bseq = rcq_prod_bseq;

    if(pkt_queued)
    {
        //notify the fw of the prod
        if(FALSE == is_tpa)
        {
            lm_rx_set_prods(pdev, rcq_chain->iro_prod_offset, &rcq_chain->bd_chain, rx_chain_bd, rx_chain_sge ,chain_idx);
        }
        else
        {
            lm_rx_set_prods(pdev, rcq_chain->iro_prod_offset, &rcq_chain->bd_chain, &LM_RXQ_CHAIN_BD(pdev, chain_idx), &LM_TPA_CHAIN_BD(pdev, chain_idx) ,chain_idx);
        }
    }

    DbgMessage(pdev, INFORMl2 , "lm_post_buffers - bd con: %d bd prod: %d \n",
                lm_bd_chain_cons_idx(rx_chain_bd),lm_bd_chain_prod_idx(rx_chain_bd));
    DbgMessage(pdev, INFORMl2 , "lm_post_buffers - cq con: %d cq prod: %d \n",
                lm_bd_chain_cons_idx(&rcq_chain->bd_chain) ,lm_bd_chain_prod_idx(&rcq_chain->bd_chain));

    return pkt_queued;
} /* lm_post_buffers */

/**
 * @description
 * Updates  tpa_chain->last_max_cons_sge if there is a new max.
 * Basic assumption is that is BD prod is always higher that BD
 * cons.
 * The minus will tell us who is closer to BD prod.
 * @param pdev
 * @param chain_idx
 * @param new_index
 *
 * @return STATIC void
 */
__inline STATIC void
lm_tpa_sge_update_last_max(IN       lm_device_t*  pdev,
                           IN const u32_t         chain_idx,
                           IN const u16_t         new_index)
{
    lm_tpa_sge_chain_t* sge_tpa_chain       = &LM_SGE_TPA_CHAIN(pdev, chain_idx);
    u16_t const         prod_idx            = lm_bd_chain_prod_idx(&LM_TPA_CHAIN_BD(pdev, chain_idx));
    u16_t const         prod_minus_new_sge  = prod_idx - new_index;
    u16_t const         prod_minus_saved    = prod_idx - sge_tpa_chain->last_max_con;

    if(prod_minus_new_sge < prod_minus_saved)
    {
        sge_tpa_chain->last_max_con = new_index;
    }

    /*
    Cyclic would have been a nicer sulotion, but adds a limitation on bd ring size that would be (2^15) instead of 2^16
    This limitation should be closed done when allocating the TPA BD chain
    DbgBreakIf(LM_TPA_CHAIN_BD_NUM_ELEM(_pdev, chain_idx) < (2^15) );
    if (CYCLIC_GT_16(sge_index, sge_tpa_chain->last_max_con))
        sge_tpa_chain->last_max_con = sge_index;
    */
}

/**
 * @description
 * The TPA sge consumer will be increments in 64 bit
 * resolutions.
 * @param pdev
 * @param chain_idx
 *
 * @return STATIC u32_t
 */
__inline STATIC void
lm_tpa_incr_sge_cons( IN        lm_device_t*    pdev,
                      IN const  u32_t           chain_idx,
                      IN const  u16_t           mask_entry_idx)
{
    lm_tpa_sge_chain_t* sge_tpa_chain   = &LM_SGE_TPA_CHAIN(pdev, chain_idx);
    lm_bd_chain_t*      bd_chain        = &LM_TPA_CHAIN_BD(pdev, chain_idx);
    u16_t               bd_entry        = 0;
    u16_t               active_entry    = 0;
    u16_t               i               = 0;

    bd_chain->cons_idx += BIT_VEC64_ELEM_SZ;

    DbgBreakIf(LM_TPA_MASK_LEN(pdev, chain_idx) <= mask_entry_idx);
    sge_tpa_chain->mask_array[mask_entry_idx] = BIT_VEC64_ELEM_ONE_MASK;

    // Make sure bds_per_page_mask is a power of 2 that is higher than 64
    DbgBreakIf(0 != (lm_bd_chain_bds_per_page(bd_chain) & BIT_VEC64_ELEM_MASK));
    DbgBreakIf(BIT_VEC64_ELEM_SZ >= lm_bd_chain_bds_per_page(bd_chain));

    if((lm_bd_chain_cons_idx(bd_chain) & lm_bd_chain_bds_per_page_mask(bd_chain)) == 0)
    {
        // Just closed a page must refer to page end entries
        lm_bd_chain_bds_consumed(bd_chain, (BIT_VEC64_ELEM_SZ - lm_bd_chain_bds_skip_eop(bd_chain)));

        /* clear page-end entries */
        for(i = 1; i <= lm_bd_chain_bds_skip_eop(bd_chain); i++ )
        {
            bd_entry = lm_bd_chain_cons_idx(bd_chain) - i;
            active_entry = LM_TPA_BD_ENTRY_TO_ACTIVE_ENTRY(pdev, chain_idx, bd_entry);
            LM_TPA_MASK_CLEAR_ACTIVE_BIT(pdev, chain_idx, active_entry);
        }
    }
    else
    {
        // Same page
        lm_bd_chain_bds_consumed(bd_chain, BIT_VEC64_ELEM_SZ);
    }
}
/**
 * @description
 * Handle TPA stop code.
 * @param pdev
 * @param rcvd_list -Global receive list
 * @param cqe
 * @param chain_idx
 * @param pkt_cnt
 * @param queue_index
 *
 * @return STATIC u32_t pkt_cnt number of packets. The number is
 *         an input parameter and packets add to the global list
 *         are add.
 */
STATIC u32_t
lm_tpa_stop( IN         lm_device_t*                pdev,
             INOUT      s_list_t*                   rcvd_list,
             IN const   struct eth_end_agg_rx_cqe*  cqe,
             IN const   u32_t                       chain_idx,
             IN         u32_t                       pkt_cnt,
             IN const   u8_t                        queue_index)
{
    lm_tpa_chain_t*     tpa_chain           = &LM_TPA(pdev, chain_idx);
    lm_tpa_sge_chain_t* sge_tpa_chain       = &LM_SGE_TPA_CHAIN(pdev, chain_idx);
    lm_bd_chain_t*      bd_chain            = &LM_TPA_CHAIN_BD(pdev, chain_idx);
    lm_packet_t*        pkt                 = tpa_chain->start_coales_bd[queue_index].packet;//Reads the TPA start coalesce array(PD_R)
    u32_t               sge_size            = mm_le16_to_cpu(cqe->pkt_len) - pkt->l2pkt_rx_info->size;
    u32_t const         sge_num_elem        = DIV_ROUND_UP_BITS(sge_size, LM_TPA_PAGE_BITS);
    u32_t               fw_sge_index        = 0;
    u16_t               active_entry        = 0;
    u16_t               first_max_set       = 0;
    u16_t               last_max_set        = 0;
    u16_t               i                   = 0;
    u8_t                b_force_first_enter = FALSE;
    u16_t               loop_cnt_dbg        = 0;
    const u32_t         lm_tpa_page_size    = LM_TPA_PAGE_SIZE;

    // Total packet size given in end aggregation must be larger than the size given in start aggregation.
    // The only case that the both size are equal is if stop aggregation doesn't contain data.
    DbgBreakIf( mm_le16_to_cpu(cqe->pkt_len) < pkt->l2pkt_rx_info->size);

    DbgBreakIf( TRUE != tpa_chain->start_coales_bd[queue_index].is_entry_used);
    tpa_chain->start_coales_bd[queue_index].is_entry_used = FALSE;

    // Indicate to upper layer this is a TPA packet
    SET_FLAGS(pkt->l2pkt_rx_info->flags ,LM_RX_FLAG_START_RSC_TPA);
    // Updates the TPA only fields from the CQE
    pkt->l2pkt_rx_info->total_packet_size   = mm_le16_to_cpu(cqe->pkt_len);
    pkt->l2pkt_rx_info->coal_seg_cnt        = mm_le16_to_cpu(cqe->num_of_coalesced_segs);
    pkt->l2pkt_rx_info->dup_ack_cnt         = cqe->pure_ack_count;
    pkt->l2pkt_rx_info->ts_delta            = mm_le32_to_cpu(cqe->timestamp_delta);

    /* make sure packet size is larger than header size */
    DbgBreakIfFastPath(pkt->l2pkt_rx_info->total_packet_size < MIN_ETHERNET_PACKET_SIZE);

    // Adds this packet descriptor to the global receive list (rcvd_list that is later indicated to miniport).
    s_list_push_tail(rcvd_list, &pkt->link);
    pkt_cnt++;

    ASSERT_STATIC(LM_TPA_MAX_AGG_SIZE == ARRSIZE(cqe->sgl_or_raw_data.sgl));
    DbgBreakIf(ARRSIZE(cqe->sgl_or_raw_data.sgl) < sge_num_elem);

    // If the TPA stop doesn't contain any new BDs.
    if(0 == sge_num_elem )
    {
        // Total packet size given in end aggregation must be equal to the size given in start aggregation.
        // if stop aggregation doesn't contain data.
        DbgBreakIf( mm_le16_to_cpu(cqe->pkt_len) != pkt->l2pkt_rx_info->size);

        return pkt_cnt;
    }

    for(fw_sge_index = 0; fw_sge_index < sge_num_elem; fw_sge_index++)
    {
        DbgBreakIf(ARRSIZE(cqe->sgl_or_raw_data.sgl) <= fw_sge_index);
        active_entry = LM_TPA_BD_ENTRY_TO_ACTIVE_ENTRY(pdev, chain_idx, mm_le16_to_cpu(cqe->sgl_or_raw_data.sgl[fw_sge_index]));

        LM_TPA_ACTIVE_ENTRY_BOUNDARIES_VERIFY(pdev, chain_idx, active_entry);
        pkt = tpa_chain->sge_chain.active_descq_array[active_entry];
        LM_TPA_MASK_CLEAR_ACTIVE_BIT(pdev, chain_idx, active_entry);

#if (DBG)
        /************start TPA debbug code******************************/
        tpa_chain->dbg_params.pck_ret_from_chip++;
        /************end TPA debbug code******************************/
#endif //(DBG)
        // For last SGE
        DbgBreakIf((fw_sge_index != (sge_num_elem - 1)) && (sge_size < LM_TPA_PAGE_SIZE ));
        pkt->l2pkt_rx_info->size = min(sge_size ,lm_tpa_page_size);
        s_list_push_tail(rcvd_list, &(pkt->link));
        pkt_cnt++;
        sge_size -= LM_TPA_PAGE_SIZE;
    }

#if defined(_NTDDK_)
//PreFast 28182 :Prefast reviewed and suppress this situation shouldn't occur.
#pragma warning (push)
#pragma warning( disable:6385 )
#endif // !_NTDDK_
    /* Here we assume that the last SGE index is the biggest  */
    lm_tpa_sge_update_last_max(pdev,
                              chain_idx,
                              mm_le16_to_cpu(cqe->sgl_or_raw_data.sgl[sge_num_elem -1]));

#if defined(_NTDDK_)
#pragma warning (pop)
#endif // !_NTDDK_
    // Find the first cosumer that is a candidate to free and the last.
    first_max_set = LM_TPA_BD_ENTRY_TO_MASK_ENTRY(pdev, chain_idx, lm_bd_chain_cons_idx(bd_chain));
    last_max_set  = LM_TPA_BD_ENTRY_TO_MASK_ENTRY(pdev, chain_idx, sge_tpa_chain->last_max_con);

    DbgBreakIf(0 != (lm_bd_chain_cons_idx(bd_chain) & BIT_VEC64_ELEM_MASK));
    /* If ring is full enter anyway*/
    if((last_max_set == first_max_set) && (lm_bd_chain_is_full(bd_chain)))
    {
        b_force_first_enter = TRUE;
    }
    /* Now update the cons */
    for (i = first_max_set;((i != last_max_set) || (TRUE == b_force_first_enter)); i = LM_TPA_MASK_NEXT_ELEM(pdev, chain_idx, i))
    {
        DbgBreakIf(LM_TPA_MASK_LEN(pdev, chain_idx) <= i);
        if (sge_tpa_chain->mask_array[i])
        {
            break;
        }
        b_force_first_enter = FALSE;

        lm_tpa_incr_sge_cons(pdev,
                             chain_idx,
                             i);
        loop_cnt_dbg++;
        DbgBreakIf(LM_TPA_MASK_LEN(pdev,chain_idx) < loop_cnt_dbg);
    }

    return pkt_cnt;
}
/**
 * @description
 * Handle TPA start code.
 * @param pdev
 * @param pkt
 * @param chain_idx
 * @param queue_index
 *
 * @return STATIC void
 */
__inline STATIC void
lm_tpa_start( IN        lm_device_t*    pdev,
              IN        lm_packet_t*    pkt,
              IN const  u32_t           chain_idx,
              IN const  u8_t            queue_index)
{
    lm_tpa_chain_t*   tpa_chain    = &LM_TPA(pdev, chain_idx);

    DbgBreakIf( FALSE != tpa_chain->start_coales_bd[queue_index].is_entry_used);

    tpa_chain->start_coales_bd[queue_index].is_entry_used   = TRUE;
    tpa_chain->start_coales_bd[queue_index].packet          = pkt;
}
/**
 * @description
 * Set TPA start known flags.
 * This is only an optimization to avoid known if's
 * @param pdev
 *
 * @return STATIC void
 */
__inline STATIC void
lm_tpa_start_flags_handle( IN       lm_device_t*                    pdev,
                           IN const struct eth_fast_path_rx_cqe*    cqe,
                           INOUT    lm_packet_t*                    pkt,
                           IN const u16_t                           parse_flags)
{
    // TPA is always(only) above IPV4 or IPV6.
    DbgBreakIf(FALSE ==
               ((GET_FLAGS_WITH_OFFSET(parse_flags,PARSING_FLAGS_OVER_ETHERNET_PROTOCOL,
                   PARSING_FLAGS_OVER_ETHERNET_PROTOCOL_SHIFT) == PRS_FLAG_OVERETH_IPV4) ||
                 (GET_FLAGS_WITH_OFFSET(parse_flags,PARSING_FLAGS_OVER_ETHERNET_PROTOCOL,
                   PARSING_FLAGS_OVER_ETHERNET_PROTOCOL_SHIFT) == PRS_FLAG_OVERETH_IPV6)));

    if(PRS_FLAG_OVERETH_IPV4 == GET_FLAGS_WITH_OFFSET(parse_flags,PARSING_FLAGS_OVER_ETHERNET_PROTOCOL,
         PARSING_FLAGS_OVER_ETHERNET_PROTOCOL_SHIFT))
    {
        SET_FLAGS(pkt->l2pkt_rx_info->flags, LM_RX_FLAG_IS_IPV4_DATAGRAM);

        DbgBreakIf(GET_FLAGS(cqe->status_flags, ETH_FAST_PATH_RX_CQE_IP_XSUM_NO_VALIDATION_FLG));
        // In IPV4 there is always a checksum
        // TPA ip cksum is always valid
        DbgBreakIf(GET_FLAGS(cqe->type_error_flags, ETH_FAST_PATH_RX_CQE_IP_BAD_XSUM_FLG));

        SET_FLAGS(pkt->l2pkt_rx_info->flags, LM_RX_FLAG_IP_CKSUM_IS_GOOD);
    }
    else
    {
        SET_FLAGS(pkt->l2pkt_rx_info->flags, LM_RX_FLAG_IS_IPV6_DATAGRAM);
        // In IPV6 there is no checksum
        DbgBreakIf(0 == GET_FLAGS(cqe->status_flags, ETH_FAST_PATH_RX_CQE_IP_XSUM_NO_VALIDATION_FLG));
    }


    // If there was a fagmentation it will be delivered by a regular BD (the TPA aggregation is stoped).
    DbgBreakIf( GET_FLAGS(parse_flags,PARSING_FLAGS_FRAGMENTATION_STATUS));
    /* check if TCP segment */
    // TPA is always above TCP.
    DbgBreakIf(PRS_FLAG_OVERIP_TCP != GET_FLAGS_WITH_OFFSET(parse_flags,PARSING_FLAGS_OVER_IP_PROTOCOL,
                                                            PARSING_FLAGS_OVER_IP_PROTOCOL_SHIFT));

    SET_FLAGS(pkt->l2pkt_rx_info->flags, LM_RX_FLAG_IS_TCP_SEGMENT);


    // TCP was checked before. TCP checksum must be done by FW in TPA.
    DbgBreakIf(GET_FLAGS(cqe->status_flags, ETH_FAST_PATH_RX_CQE_L4_XSUM_NO_VALIDATION_FLG));
    // TCP checksum must be valid in a successful TPA aggregation.
    DbgBreakIf(GET_FLAGS(cqe->type_error_flags, ETH_FAST_PATH_RX_CQE_L4_BAD_XSUM_FLG));

/* IN TPA tcp cksum is always validated */
/* valid tcp/udp cksum */
#define SHIFT_IS_GOOD  1
#define SHIFT_IS_BAD   2
    ASSERT_STATIC(LM_RX_FLAG_UDP_CKSUM_IS_GOOD == LM_RX_FLAG_IS_UDP_DATAGRAM << SHIFT_IS_GOOD);
    ASSERT_STATIC(LM_RX_FLAG_UDP_CKSUM_IS_BAD  == LM_RX_FLAG_IS_UDP_DATAGRAM << SHIFT_IS_BAD);
    ASSERT_STATIC(LM_RX_FLAG_TCP_CKSUM_IS_GOOD == LM_RX_FLAG_IS_TCP_SEGMENT  << SHIFT_IS_GOOD);
    ASSERT_STATIC(LM_RX_FLAG_TCP_CKSUM_IS_BAD  == LM_RX_FLAG_IS_TCP_SEGMENT  << SHIFT_IS_BAD);

    SET_FLAGS(pkt->l2pkt_rx_info->flags , ( GET_FLAGS(pkt->l2pkt_rx_info->flags, (LM_RX_FLAG_IS_TCP_SEGMENT)) << SHIFT_IS_GOOD ) );
}

/**
 * @description
 * Set regular flags.
 * This is only an optimization
 * @param pdev
 *
 * @return STATIC void
 */
STATIC void
lm_regular_flags_handle( IN         lm_device_t*    pdev,
                         IN const struct eth_fast_path_rx_cqe*    cqe,
                         INOUT      lm_packet_t*    pkt,
                         IN const   u16_t           parse_flags)
{
    /* check if IP datagram (either IPv4 or IPv6) */
    if(((GET_FLAGS(parse_flags,PARSING_FLAGS_OVER_ETHERNET_PROTOCOL) >>
        PARSING_FLAGS_OVER_ETHERNET_PROTOCOL_SHIFT) == PRS_FLAG_OVERETH_IPV4) ||
       ((GET_FLAGS(parse_flags,PARSING_FLAGS_OVER_ETHERNET_PROTOCOL) >>
        PARSING_FLAGS_OVER_ETHERNET_PROTOCOL_SHIFT) == PRS_FLAG_OVERETH_IPV6))
    {
        pkt->l2pkt_rx_info->flags  |=
            (GET_FLAGS(parse_flags,PARSING_FLAGS_OVER_ETHERNET_PROTOCOL) >>
             PARSING_FLAGS_OVER_ETHERNET_PROTOCOL_SHIFT) == PRS_FLAG_OVERETH_IPV4 ?
            LM_RX_FLAG_IS_IPV4_DATAGRAM :
            LM_RX_FLAG_IS_IPV6_DATAGRAM;
        if(!GET_FLAGS(cqe->status_flags, ETH_FAST_PATH_RX_CQE_IP_XSUM_NO_VALIDATION_FLG))
        {
            /* ip cksum validated */
            if GET_FLAGS(cqe->type_error_flags, ETH_FAST_PATH_RX_CQE_IP_BAD_XSUM_FLG)
            {
                /* invalid ip cksum */
                SET_FLAGS(pkt->l2pkt_rx_info->flags, LM_RX_FLAG_IP_CKSUM_IS_BAD);

                LM_COMMON_DRV_STATS_ATOMIC_INC_ETH(pdev, rx_ip_cs_error_count);
            }
            else
            {
                /* valid ip cksum */
                SET_FLAGS(pkt->l2pkt_rx_info->flags, LM_RX_FLAG_IP_CKSUM_IS_GOOD);
            }
        }
    }

    // TCP or UDP segment.
    if(!GET_FLAGS(parse_flags,PARSING_FLAGS_FRAGMENTATION_STATUS))
    {
        /* check if TCP segment */
        if((GET_FLAGS(parse_flags,PARSING_FLAGS_OVER_IP_PROTOCOL) >>
            PARSING_FLAGS_OVER_IP_PROTOCOL_SHIFT) == PRS_FLAG_OVERIP_TCP)
        {
            SET_FLAGS(pkt->l2pkt_rx_info->flags, LM_RX_FLAG_IS_TCP_SEGMENT);
            DbgMessage(pdev, INFORM, "--- TCP Packet --- \n");
        }
        /* check if UDP segment */
        else if((GET_FLAGS(parse_flags,PARSING_FLAGS_OVER_IP_PROTOCOL) >>
                 PARSING_FLAGS_OVER_IP_PROTOCOL_SHIFT) == PRS_FLAG_OVERIP_UDP)
        {
            SET_FLAGS(pkt->l2pkt_rx_info->flags , LM_RX_FLAG_IS_UDP_DATAGRAM);
            DbgMessage(pdev, INFORM, "--- UDP Packet --- \n");
        }
    }


    if( GET_FLAGS(pkt->l2pkt_rx_info->flags, (LM_RX_FLAG_IS_TCP_SEGMENT | LM_RX_FLAG_IS_UDP_DATAGRAM)) &&
       !GET_FLAGS(cqe->status_flags, ETH_FAST_PATH_RX_CQE_L4_XSUM_NO_VALIDATION_FLG))
    {
        ASSERT_STATIC(LM_RX_FLAG_UDP_CKSUM_IS_GOOD == LM_RX_FLAG_IS_UDP_DATAGRAM << SHIFT_IS_GOOD);
        ASSERT_STATIC(LM_RX_FLAG_UDP_CKSUM_IS_BAD  == LM_RX_FLAG_IS_UDP_DATAGRAM << SHIFT_IS_BAD);
        ASSERT_STATIC(LM_RX_FLAG_TCP_CKSUM_IS_GOOD == LM_RX_FLAG_IS_TCP_SEGMENT  << SHIFT_IS_GOOD);
        ASSERT_STATIC(LM_RX_FLAG_TCP_CKSUM_IS_BAD  == LM_RX_FLAG_IS_TCP_SEGMENT  << SHIFT_IS_BAD);

        DbgMessage(pdev, INFORM, "  Checksum validated.\n");

        /* tcp/udp cksum validated */
        if GET_FLAGS(cqe->type_error_flags, ETH_FAST_PATH_RX_CQE_L4_BAD_XSUM_FLG)
        {
            /* invalid tcp/udp cksum */
            SET_FLAGS(pkt->l2pkt_rx_info->flags , ( GET_FLAGS(pkt->l2pkt_rx_info->flags, (LM_RX_FLAG_IS_TCP_SEGMENT | LM_RX_FLAG_IS_UDP_DATAGRAM)) << SHIFT_IS_BAD ) );

            LM_COMMON_DRV_STATS_ATOMIC_INC_ETH(pdev, rx_tcp_cs_error_count);
            DbgMessage(pdev, INFORM, "  BAD checksum.\n");
        }
        else if (GET_FLAGS(pkt->l2pkt_rx_info->flags , LM_RX_FLAG_IP_CKSUM_IS_BAD))
        {
            /* invalid tcp/udp cksum due to invalid ip cksum */
            SET_FLAGS(pkt->l2pkt_rx_info->flags , ( GET_FLAGS(pkt->l2pkt_rx_info->flags, (LM_RX_FLAG_IS_TCP_SEGMENT | LM_RX_FLAG_IS_UDP_DATAGRAM)) << SHIFT_IS_BAD ) );
            DbgMessage(pdev, INFORM, "  BAD IP checksum\n");
        }
        else
        {
            /* valid tcp/udp cksum */
            SET_FLAGS(pkt->l2pkt_rx_info->flags , ( GET_FLAGS(pkt->l2pkt_rx_info->flags, (LM_RX_FLAG_IS_TCP_SEGMENT | LM_RX_FLAG_IS_UDP_DATAGRAM)) << SHIFT_IS_GOOD ) );
            DbgMessage(pdev, INFORM, "  GOOD checksum.\n");
        }
    }
    else
    {
        DbgMessage(pdev, INFORM, "  Checksum NOT validated.\n");
        /*Packets with invalid TCP options are reported with L4_XSUM_NO_VALIDATION due to HW limitation. In this case we assume that
          their checksum is OK.*/
        if(GET_FLAGS(pkt->l2pkt_rx_info->flags, (LM_RX_FLAG_IS_TCP_SEGMENT | LM_RX_FLAG_IS_UDP_DATAGRAM)) &&
           GET_FLAGS(cqe->status_flags, ETH_FAST_PATH_RX_CQE_L4_XSUM_NO_VALIDATION_FLG) &&
           GET_FLAGS(cqe->pars_flags.flags, PARSING_FLAGS_TCP_OPTIONS_EXIST))
        {
            DbgMessage(pdev, INFORM, "  TCP Options exist - forcing return value.\n");
            if(GET_FLAGS(pkt->l2pkt_rx_info->flags , LM_RX_FLAG_IP_CKSUM_IS_BAD))
            {
                DbgMessage(pdev, INFORM, "  IP checksum invalid - reporting BAD checksum.\n");
                SET_FLAGS(pkt->l2pkt_rx_info->flags , ( GET_FLAGS(pkt->l2pkt_rx_info->flags, (LM_RX_FLAG_IS_TCP_SEGMENT | LM_RX_FLAG_IS_UDP_DATAGRAM)) << SHIFT_IS_BAD ) );
            }
            else
            {
                DbgMessage(pdev, INFORM, "  IP checksum ok - reporting GOOD checksum.\n");
                SET_FLAGS(pkt->l2pkt_rx_info->flags , ( GET_FLAGS(pkt->l2pkt_rx_info->flags, (LM_RX_FLAG_IS_TCP_SEGMENT | LM_RX_FLAG_IS_UDP_DATAGRAM)) << SHIFT_IS_GOOD ) );
            }
        }
    }
}

__inline STATIC void
lm_recv_set_pkt_len( IN       lm_device_t*   pdev,
                     INOUT    lm_packet_t*   pkt,
                     IN const u16_t          pkt_len,
                     IN const u32_t          chain_idx)
{
    //changed, as we dont have fhdr infrastructure
    pkt->l2pkt_rx_info->size = pkt_len; //- 4; /* CRC32 */

    DbgMessage(pdev, VERBOSEl2, "pkt_size: %d\n",pkt->l2pkt_rx_info->size);
}

INLINE STATIC u32_t
calc_cksum(u16_t *hdr, u32_t len_in_bytes, u32_t sum)
{
    // len_in_bytes - the length in bytes of the header
    // sum - initial checksum
    while (len_in_bytes > 1)
    {
        sum += NTOH16(*hdr);
        len_in_bytes -= 2;
        hdr++;
    }

    /* add left-over byte, if any */
    if (len_in_bytes)
    {
        sum += ((NTOH16(*hdr)) & 0xFF00);
    }

    return sum;
}

INLINE STATIC u8_t
validate_cksum(u32_t sum)
{
    // len - the length in words of the header
    // returns true iff the checksum (already written in the headr) is valid

    // fold 32-bit sum to 16 bits
    while (sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return ((u16_t)(sum) == 0xffff);
}

INLINE STATIC u16_t
get_ip_hdr_len(u8_t *hdr)
{
    // returns the ip header length in bytes
    u16_t ip_hdr_len = 40; // ipv6 header length, we won't support ipv6 with extension header for now

    if ((hdr[0] & 0xf0) == 0x40)
    {
        // ipv4, the lower 4 bit of the 1st byte of ip header
        // contains the ip header length in unit of dword(32-bit)
        ip_hdr_len = ((hdr[0] & 0xf) << 2);
    }
    return ip_hdr_len;
}

INLINE void
encap_pkt_parsing(struct _lm_device_t *pdev,
                  lm_packet_t         *pkt)
{
    u16_t tmp, inner_ip_hdr_len, tcp_length;
    u32_t psuedo_cksum;
    u8_t *hdr;

    // encapsulated packet:
    // outer mac | outer ip | gre | inner mac | inner ip | tcp
    // minimum encapsultaed packet size is:
    // two mac headers + gre header size + tcp header size + two ipv4 headers
    if (pkt->l2pkt_rx_info->total_packet_size < (2*ETHERNET_PACKET_HEADER_SIZE + 2*20 + ETHERNET_GRE_SIZE + 20))
    {
        return;
    }


    // set hdr to the outer ip header
    hdr = pkt->l2pkt_rx_info->mem_virt + pdev->params.rcv_buffer_offset + ETHERNET_PACKET_HEADER_SIZE;
    if (pkt->l2pkt_rx_info->flags & LM_RX_FLAG_VALID_VLAN_TAG)
    {
        hdr += ETHERNET_VLAN_TAG_SIZE;
    }

    // in case this is not standard ETH packet (e.g. managment, or in general non ipv4/ipv6), it is for sure
    // not gre so we can end here
    // if outer header is ipv4, protocol is the nine'th octet
    // if outer header is ipv6, next header is the sixth octet
    if (!(((pkt->l2pkt_rx_info->flags & LM_RX_FLAG_IS_IPV4_DATAGRAM) && (hdr[9] == 0x2f)) ||
          ((pkt->l2pkt_rx_info->flags & LM_RX_FLAG_IS_IPV6_DATAGRAM) && (hdr[6] == 0x2f))))
    {
        // this is not encapsulated packet, no gre tunneling
		// on ipv6 we don't support extension header
        return;
    }

    // get the length of the outer ip header and set hdr to the gre header
    hdr += get_ip_hdr_len(hdr);

/* GRE header
   | Bits 0–4 | 5–7   | 8–12  | 13–15   | 16–31         |
   | C|0|K|S  | Recur | Flags | Version | Protocol Type |
   |           Checksum (optional)      | Reserved      |
   |           Key (optional)                           |
   |           Sequence Number (optional)               | */

    // check that:
    // checksum present bit is set to 0
    // key present bit is set to 1
    // sequence number present bit is set to 0
    // protocol type should be always equal to 0x6558 (for encapsulating ethernet packets in GRE)
    if (((hdr[0] & 0xb0) != 0x20) || (hdr[2] != 0x65) || (hdr[3] != 0x58))
    {
        return;
    }
    // set hdr to the inner mac header
    hdr += ETHERNET_GRE_SIZE;

    // The first two octets of the tag are the Tag Protocol Identifier (TPID) value of 0x8100.
    // This is located in the same place as the EtherType/Length field in untagged frames
    if ((hdr[12] == 0x81) && (hdr[13] == 0x00))
    {
        hdr += ETHERNET_VLAN_TAG_SIZE;
    }
    // set hdr to the inner ip header
    hdr += ETHERNET_PACKET_HEADER_SIZE;

    // get the length of the inner ip header
    inner_ip_hdr_len = get_ip_hdr_len(hdr);

    if ((hdr[0] & 0xf0) == 0x40)
    {
        // inner ip header is ipv4
        // if the ip header checksum of the outer header is ok than validate the ip checksum of the inner header
        if (pkt->l2pkt_rx_info->flags & LM_RX_FLAG_IP_CKSUM_IS_GOOD)
        {
            // validate the checksum
            if (!validate_cksum(calc_cksum((u16_t*)hdr, inner_ip_hdr_len, 0)))
            {
                SET_FLAGS(pkt->l2pkt_rx_info->flags, LM_RX_FLAG_IP_CKSUM_IS_BAD);
                RESET_FLAGS(pkt->l2pkt_rx_info->flags, LM_RX_FLAG_IP_CKSUM_IS_GOOD);
            }
        }
        // check if protocol field is tcp
        if (hdr[9] == 0x06)
        {
            // create the psuedo header
/* | Bit offset | 0–7    |    8–15  |    16–31   |
   |     0      |    Source address              |
   |    32      |  Destination address           |
   |    64      | Zeros  | Protocol | TCP length | */

            // adding 1 byte of zeros + protocol to the sum
            // and adding source and destination address
            psuedo_cksum = calc_cksum((u16_t*)&hdr[12], 8, 0x06);
            // calculate the tcp length
            mm_memcpy(&tmp, &hdr[2], sizeof(u16_t));
            tcp_length = NTOH16(tmp) - inner_ip_hdr_len;
            // the TCP length field is the length of the TCP header and data (measured in octets).
            psuedo_cksum += tcp_length;
        }
        else
        {
            // no tcp over ip
            return;
        }
    }
    else if ((hdr[0] & 0xf0) == 0x60)
    {
        // inner ip header is ipv6
        // check if next header field is tcp
        if (hdr[6] == 0x06)
        {
            // tcp over ipv6
            // create the psuedo header
/* | Bit offset | 0–7 | 8–15 | 16–23 |  24–31     |
   |     0      |     Source address              |
   |    32      |                                 |
   |    64      |                                 |
   |    96      |                                 |
   |   128      |   Destination address           |
   |   160      |                                 |
   |   192      |                                 |
   |   224      |                                 |
   |   256      |        TCP length               |
   |   288      |        Zeros       |Next header |*/

            // adding 3 byte of zeros + protocol to the sum
            // and adding source and destination address
            psuedo_cksum = calc_cksum((u16_t*)&hdr[8], 32, 0x06);
            // calculate the tcp length
            // in the ip header: the size of the payload in octets, including any extension headers
            mm_memcpy(&tmp, &hdr[4], sizeof(u16_t));
            // reduce the length of the extension headers
            tcp_length = NTOH16(tmp) - (inner_ip_hdr_len - 40);
            psuedo_cksum += tcp_length;
        }
        else
        {
            // no tcp over ip
            return;
        }
    }
    else
    {
        // no ipv4 or ipv6
        return;
    }
    // set hdr to the tcp header
    hdr += inner_ip_hdr_len;

    SET_FLAGS(pkt->l2pkt_rx_info->flags, LM_RX_FLAG_IS_TCP_SEGMENT);
    // claculate the checksum of the rest of the packet
    // validate the checksum
    if (validate_cksum(calc_cksum((u16_t*)hdr, tcp_length, psuedo_cksum)))
    {
        SET_FLAGS(pkt->l2pkt_rx_info->flags, LM_RX_FLAG_TCP_CKSUM_IS_GOOD);
        RESET_FLAGS(pkt->l2pkt_rx_info->flags, LM_RX_FLAG_TCP_CKSUM_IS_BAD);
    }
    else
    {
        SET_FLAGS(pkt->l2pkt_rx_info->flags, LM_RX_FLAG_TCP_CKSUM_IS_BAD);
        RESET_FLAGS(pkt->l2pkt_rx_info->flags, LM_RX_FLAG_TCP_CKSUM_IS_GOOD);
    }
}

/*******************************************************************************
 * Description:
 * Here the RCQ chain is the chain coordinated with the status block, that is,
 * the index in the status block describes the RCQ and NOT the rx_bd chain as in
 * the case of Teton. We run on the delta between the new consumer index of the RCQ
 * which we get from the sb and the old consumer index of the RCQ.
 * In cases of both slow and fast path, the consumer of the RCQ is always incremented.
 *
 * The assumption which we must stick to all the way is: RCQ and Rx bd chain
 * have the same size at all times! Otherwise, so help us Alan Bertkey!
 *
 * Return:
 ******************************************************************************/
u32_t
lm_get_packets_rcvd( struct _lm_device_t  *pdev,
                     u32_t const          chain_idx,
                     s_list_t             *rcvd_list,
                     struct _sp_cqes_info *sp_cqes)
{
    lm_rx_chain_t*          rxq_chain    = &LM_RXQ(pdev, chain_idx); //get a hold of the matching Rx bd chain according to index
    lm_rcq_chain_t*         rcq_chain    = &LM_RCQ(pdev, chain_idx); //get a hold of the matching RCQ chain according to index
    lm_bd_chain_t*          rx_chain_bd  = &LM_RXQ_CHAIN_BD(pdev, chain_idx);
    lm_bd_chain_t*          rx_chain_sge = LM_RXQ_SGE_PTR_IF_VALID(pdev, chain_idx);
    lm_tpa_chain_t*         tpa_chain    = &LM_TPA(pdev, chain_idx);
    union eth_rx_cqe*       cqe          = NULL;
    lm_packet_t*            pkt          = NULL;
    u32_t                   pkt_cnt      = 0;
    u16_t                   rx_old_idx   = 0;
    u16_t                   cq_new_idx   = 0;
    u16_t                   cq_old_idx   = 0;
    enum eth_rx_cqe_type    cqe_type     = MAX_ETH_RX_CQE_TYPE;

    DbgMessage(pdev, INFORMl2 , "lm_get_packets_rcvd inside!\n");

    /* make sure to zeroize the sp_cqes... */
    mm_mem_zero( sp_cqes, sizeof(struct _sp_cqes_info) );

    /* Get the new consumer idx.  The bd's between rcq_new_idx and rcq_old_idx
     * are bd's containing receive packets.
     */
    cq_new_idx = mm_le16_to_cpu(*(rcq_chain->hw_con_idx_ptr));

    /* The consumer index of the RCQ only, may stop at the end of a page boundary.  In
     * this case, we need to advance the next to the next one.
     * In here we do not increase the cons_bd as well! this is since we're dealing here
     * with the new cons index and not with the actual old one for which, as we progress, we
     * need to maintain the bd_cons as well.
     */
    if((cq_new_idx & lm_bd_chain_usable_bds_per_page(&rcq_chain->bd_chain)) == lm_bd_chain_usable_bds_per_page(&rcq_chain->bd_chain))
    {
        cq_new_idx+= lm_bd_chain_bds_skip_eop(&rcq_chain->bd_chain);
    }

    DbgBreakIfFastPath( rx_chain_sge && !lm_bd_chains_are_consistent( rx_chain_sge, rx_chain_bd ) );

    rx_old_idx = lm_bd_chain_cons_idx(rx_chain_bd);
    cq_old_idx = lm_bd_chain_cons_idx(&rcq_chain->bd_chain);

    //there is no change in the RCQ consumer index so exit!
    if (cq_old_idx == cq_new_idx)
    {
        DbgMessage(pdev, INFORMl2rx , "there is no change in the RCQ consumer index so exit!\n");
        return pkt_cnt;
    }

    while(cq_old_idx != cq_new_idx)
    {
        DbgBreakIfFastPath(S16_SUB(cq_new_idx, cq_old_idx) <= 0);
        //get hold of the cqe, and find out what it's type corresponds to
        cqe = (union eth_rx_cqe *)lm_bd_chain_consume_bd(&rcq_chain->bd_chain);
        DbgBreakIfFastPath(cqe == NULL);

        //update the cons of the RCQ and the bd_prod pointer of the RCQ as well!
        //this holds both for slow and fast path!
        cq_old_idx = lm_bd_chain_cons_idx(&rcq_chain->bd_chain);

        cqe_type = GET_FLAGS_WITH_OFFSET(cqe->ramrod_cqe.ramrod_type, COMMON_RAMROD_ETH_RX_CQE_TYPE, COMMON_RAMROD_ETH_RX_CQE_TYPE_SHIFT);
        DbgBreakIf(MAX_ETH_RX_CQE_TYPE <= cqe_type);

        //the cqe is a ramrod, so do the ramrod and recycle the cqe.
        //TODO: replace this with the #defines: 1- eth ramrod, 2- toe init ofld ramrod
        switch(cqe_type)
        {
        case RX_ETH_CQE_TYPE_ETH_RAMROD:
        {
            /* 13/08/08 NirV: bugbug, temp workaround for dpc watch dog bug,
             * ignore toe completions on L2 ring - initiate offload */
            if (cqe->ramrod_cqe.conn_type != TOE_CONNECTION_TYPE)
            {
                if (ERR_IF(sp_cqes->idx >= MAX_NUM_SPE))
                {
                    DbgBreakMsgFastPath("too many spe completed\n");
                    /* we shouldn't get here - there is something very wrong if we did... in this case we will risk
                     * completing the ramrods - even though we're holding a lock!!! */
                    /* bugbug... */
                    DbgBreakIfAll(sp_cqes->idx >= MAX_NUM_SPE);
                    return pkt_cnt;
                }
                mm_memcpy((void*)(&(sp_cqes->sp_cqe[sp_cqes->idx++])), (const void*)cqe, sizeof(*cqe));
            }

            //update the prod of the RCQ - by this, we recycled the CQE.
            lm_bd_chain_bd_produced(&rcq_chain->bd_chain);

#if 0
            //in case of ramrod, pop out the Rx bd and push it to the free descriptors list
            pkt = (lm_packet_t *) s_list_pop_head(&rxq_chain->active_descq);

            DbgBreakIfFastPath(pkt == NULL);

            s_list_push_tail( &LM_RXQ(pdev, chain_idx).free_descq,
                              &pkt->link);
#endif
            break;
        }
        case RX_ETH_CQE_TYPE_ETH_FASTPATH:
        case RX_ETH_CQE_TYPE_ETH_START_AGG: //Fall through case
        { //enter here in case the cqe is a fast path type (data)
            u16_t parse_flags = 0;

            DbgMessage(pdev, INFORMl2rx, "lm_get_packets_rcvd- it is fast path, func=%d\n", FUNC_ID(pdev));

            DbgBreakIf( (RX_ETH_CQE_TYPE_ETH_START_AGG == cqe_type)&&
                        (lm_tpa_state_disable == tpa_chain->state));

            pkt = (lm_packet_t *) s_list_pop_head(&rxq_chain->active_descq);
            parse_flags = mm_le16_to_cpu(cqe->fast_path_cqe.pars_flags.flags);

            DbgBreakIfFastPath( NULL == pkt );

#if DBG
            if CHK_NULL( pkt )
            {
                return 0;
            }
#endif // DBG

            DbgBreakIfFastPath(SIG(pkt) != L2PACKET_RX_SIG);

#if L2_RX_BUF_SIG
            /* make sure signitures exist before and after the buffer */
            DbgBreakIfFastPath(SIG(pkt->u1.rx.mem_virt - pdev->params.rcv_buffer_offset) != L2PACKET_RX_SIG);
            DbgBreakIfFastPath(END_SIG(pkt->u1.rx.mem_virt, MAX_L2_CLI_BUFFER_SIZE(pdev, chain_idx)) != L2PACKET_RX_SIG);
#endif /* L2_RX_BUF_SIG */

            lm_bd_chain_bds_consumed(rx_chain_bd, 1);
            if( rx_chain_sge )
            {
                lm_bd_chain_bds_consumed(rx_chain_sge, 1);
            }
#if defined(_NTDDK_)
//PreFast 28182 :Prefast reviewed and suppress this situation shouldn't occur.
#pragma warning (push)
#pragma warning( disable:28182 )
#endif // !_NTDDK_
            /* Advance the rx_old_idx to the start bd_idx of the next packet. */
            rx_old_idx = pkt->u1.rx.next_bd_idx;
            //cq_old_idx = pkt->u1.rx.next_bd_idx;

            CLEAR_FLAGS( pkt->l2pkt_rx_info->flags );


            if(RX_ETH_CQE_TYPE_ETH_START_AGG == cqe_type)
            {
                lm_recv_set_pkt_len(pdev, pkt, mm_le16_to_cpu(cqe->fast_path_cqe.len_on_bd), chain_idx);
                // total_packet_size is only known in stop_TPA

                DbgBreakIf(0 != cqe->fast_path_cqe.pkt_len_or_gro_seg_len);

                lm_tpa_start(pdev,
                             pkt,
                             chain_idx,
                             cqe->fast_path_cqe.queue_index);

                lm_tpa_start_flags_handle(pdev,
                                          &(cqe->fast_path_cqe),
                                          pkt,
                                          parse_flags);
            }
            else
            {
                lm_recv_set_pkt_len(pdev, pkt, mm_le16_to_cpu(cqe->fast_path_cqe.pkt_len_or_gro_seg_len), chain_idx);

                // In regular mode pkt->l2pkt_rx_info->size == pkt->l2pkt_rx_info->total_packet_size
                // We need total_packet_size for Dynamic HC in order not to ask a question there if we are RSC or regular flow.
                pkt->l2pkt_rx_info->total_packet_size = pkt->l2pkt_rx_info->size;

                /* make sure packet size if larger than header size and smaller than max packet size of the specific L2 client */
                DbgBreakIfFastPath((pkt->l2pkt_rx_info->total_packet_size < MIN_ETHERNET_PACKET_SIZE) || (pkt->l2pkt_rx_info->total_packet_size > MAX_CLI_PACKET_SIZE(pdev, chain_idx)));

                // ShayH:packet->size isn't useed anymore by windows we directly put the data on l2pkt_rx_info->size and l2pkt_rx_info->total_packet_size.
                // Need to ask if other UM clients use/need packet->size.
                pkt->size = pkt->l2pkt_rx_info->size;

                if(OOO_CID(pdev) == chain_idx)
                {
                    DbgBreakIfFastPath( ETH_FP_CQE_RAW != (GET_FLAGS( cqe->fast_path_cqe.type_error_flags, ETH_FAST_PATH_RX_CQE_SGL_RAW_SEL ) >>
                                                           ETH_FAST_PATH_RX_CQE_SGL_RAW_SEL_SHIFT));

                    //optimized
                    /* make sure packet size if larger than header size and smaller than max packet size of the specific L2 client */
                    // TODO_OOO - check with flag
                    ASSERT_STATIC( sizeof(pkt->u1.rx.sgl_or_raw_data.raw_data) == sizeof(cqe->fast_path_cqe.sgl_or_raw_data.raw_data) );
                    mm_memcpy( pkt->u1.rx.sgl_or_raw_data.raw_data, cqe->fast_path_cqe.sgl_or_raw_data.raw_data, sizeof(pkt->u1.rx.sgl_or_raw_data.raw_data) );
                }
                else
                {
                    DbgBreakIfFastPath( ETH_FP_CQE_REGULAR != (GET_FLAGS( cqe->fast_path_cqe.type_error_flags, ETH_FAST_PATH_RX_CQE_SGL_RAW_SEL )>>
                                                           ETH_FAST_PATH_RX_CQE_SGL_RAW_SEL_SHIFT)  ) ;
                }

                lm_regular_flags_handle(pdev,
                                        &(cqe->fast_path_cqe),
                                        pkt,
                                        parse_flags);

                if (GET_FLAGS(pdev->params.ofld_cap_to_ndis, LM_OFFLOAD_ENCAP_PACKET))
                {
                    // SW rx checksum for gre encapsulated packets
                    encap_pkt_parsing(pdev, pkt);
                }

                pkt_cnt++;
                s_list_push_tail(rcvd_list, &pkt->link);
            }

            if GET_FLAGS(cqe->fast_path_cqe.status_flags, ETH_FAST_PATH_RX_CQE_RSS_HASH_FLG)
            {
                SET_FLAGS(pkt->l2pkt_rx_info->flags, LM_RX_FLAG_VALID_HASH_VALUE );
                *pkt->u1.rx.hash_val_ptr = mm_le32_to_cpu(cqe->fast_path_cqe.rss_hash_result);
            }

            if(GET_FLAGS(parse_flags,PARSING_FLAGS_INNER_VLAN_EXIST))
            {
                u16_t vlan_tag = mm_le16_to_cpu(cqe->fast_path_cqe.vlan_tag);

                DbgMessage(pdev, INFORMl2, "vlan frame recieved: %x\n",vlan_tag);
                  /* fw always set ETH_FAST_PATH_RX_CQE_VLAN_TAG_FLG and pass vlan tag when
                     packet with vlan arrives but it remove the vlan from the packet only when
                     it configured to remove vlan using params.vlan_removal_enable
                  */
                  if ((!pdev->params.keep_vlan_tag) &&
                      ( OOO_CID(pdev) != chain_idx))
                  {
                      SET_FLAGS(pkt->l2pkt_rx_info->flags , LM_RX_FLAG_VALID_VLAN_TAG);
                      pkt->l2pkt_rx_info->vlan_tag = vlan_tag;
                      DbgMessage(pdev, INFORMl2rx, "vlan removed from frame: %x\n",vlan_tag);
                  }
            }

#if defined(_NTDDK_)
#pragma warning (pop)
#endif // !_NTDDK_
#if DBG
            if(GET_FLAGS(parse_flags,PARSING_FLAGS_FRAGMENTATION_STATUS))
            {
                LM_COMMON_DRV_STATS_ATOMIC_INC_ETH(pdev, rx_ipv4_frag_count);
            }
            if(GET_FLAGS(parse_flags,PARSING_FLAGS_LLC_SNAP))
            {
                LM_COMMON_DRV_STATS_ATOMIC_INC_ETH(pdev, rx_llc_snap_count);
            }
            if(GET_FLAGS(parse_flags,PARSING_FLAGS_IP_OPTIONS) &&
                GET_FLAGS(pkt->l2pkt_rx_info->flags ,LM_RX_FLAG_IS_IPV6_DATAGRAM))
            {
                LM_COMMON_DRV_STATS_ATOMIC_INC_ETH(pdev, rx_ipv6_ext_count);
            }
#endif // DBG

            /* We use to assert that if we got the PHY_DECODE_ERROR it was always a result of DROP_MAC_ERR, since we don't configure
             * DROP_MAC_ERR anymore, we don't expect this flag to ever be on.*/
            DbgBreakIfFastPath( GET_FLAGS(cqe->fast_path_cqe.type_error_flags, ETH_FAST_PATH_RX_CQE_PHY_DECODE_ERR_FLG) );

            DbgBreakIfFastPath(cqe->fast_path_cqe.type_error_flags &
                            ~(ETH_FAST_PATH_RX_CQE_TYPE |
                              ETH_FAST_PATH_RX_CQE_PHY_DECODE_ERR_FLG |
                              ETH_FAST_PATH_RX_CQE_IP_BAD_XSUM_FLG |
                              ETH_FAST_PATH_RX_CQE_L4_BAD_XSUM_FLG |
                              ETH_FAST_PATH_RX_CQE_SGL_RAW_SEL));


            break;
        }
        case RX_ETH_CQE_TYPE_ETH_STOP_AGG:
        {//TPA stop
            DbgBreakIf( lm_tpa_state_disable == tpa_chain->state);

            pkt_cnt = lm_tpa_stop(pdev,
                                  rcvd_list,
                                  &(cqe->end_agg_cqe),
                                  chain_idx,
                                  pkt_cnt,
                                  cqe->end_agg_cqe.queue_index);

            //update the prod of the RCQ - by this, we recycled the CQE.
            lm_bd_chain_bd_produced(&rcq_chain->bd_chain);
            break;
        }
        case MAX_ETH_RX_CQE_TYPE:
        default:
            {
                DbgBreakMsg("CQE type not supported");
            }

        }
    }

    // TODO: Move index update to a more suitable place
    rx_chain_bd->cons_idx = rx_old_idx;
    if( rx_chain_sge )
    {
        rx_chain_sge->cons_idx = rx_old_idx;
    }

    //notify the fw of the prod
    lm_rx_set_prods(pdev, rcq_chain->iro_prod_offset, &rcq_chain->bd_chain, rx_chain_bd, rx_chain_sge ,chain_idx);

    DbgMessage(pdev, INFORMl2rx, "lm_get_packets_rcvd- bd con: %d bd prod: %d \n",
                                lm_bd_chain_cons_idx(rx_chain_bd), lm_bd_chain_prod_idx(rx_chain_bd));
    DbgMessage(pdev, INFORMl2rx, "lm_get_packets_rcvd- cq con: %d cq prod: %d \n",
                                lm_bd_chain_cons_idx(&rcq_chain->bd_chain), lm_bd_chain_prod_idx(&rcq_chain->bd_chain));
    return pkt_cnt;
} /* lm_get_packets_rcvd */

lm_status_t lm_complete_ramrods(
    struct _lm_device_t *pdev,
    struct _sp_cqes_info *sp_cqes)
{
    u8_t idx;

    for (idx = 0; idx < sp_cqes->idx; idx++) {
        lm_eth_init_command_comp(pdev, &(sp_cqes->sp_cqe[idx].ramrod_cqe));
    }

    return LM_STATUS_SUCCESS;
}

/* called by um whenever packets are returned by client
   rxq lock is taken by caller */
void
lm_return_packet_bytes( struct _lm_device_t *pdev,
                        u32_t const          qidx,
                        u32_t const          returned_bytes)
{
    lm_rx_chain_t *rxq = &LM_RXQ(pdev, qidx);

    rxq->ret_bytes += returned_bytes;

    /* aggregate updates over PCI */

    /* HC_RET_BYTES_TH = min(l2_hc_threshold0 / 2 , 16KB) */
    #define HC_RET_BYTES_TH(pdev) (((pdev)->params.hc_threshold0[SM_RX_ID] < 32768) ? ((pdev)->params.hc_threshold0[SM_RX_ID] >> 1) : 16384)

    /* TODO: Future: Add #updatesTH = 20 */

    /* time to update fw ? */
    if(S32_SUB(rxq->ret_bytes, rxq->ret_bytes_last_fw_update + HC_RET_BYTES_TH(pdev)) >= 0)
    {
        /*
          !!DP
          The test below is to disable dynamic HC for the iSCSI chains
        */
        // TODO: VF dhc
        if (qidx < LM_MAX_RSS_CHAINS(pdev) && IS_PFDEV(pdev)) /* should be fine, if not, you can go for less robust case of != LM_CLI_RX_CHAIN_IDX(pdev, LM_CLI_IDX_ISCSI) */
        {
            /* There are HC_USTORM_SB_NUM_INDICES (4) index values for each SB to set and we're using the corresponding U indexes from the microcode consts */
            LM_INTMEM_WRITE32(PFDEV(pdev), rxq->hc_sb_info.iro_dhc_offset, rxq->ret_bytes, BAR_CSTRORM_INTMEM);
            rxq->ret_bytes_last_fw_update = rxq->ret_bytes;
        } else if (IS_VFDEV(pdev)) {
            VF_REG_WR(pdev, VF_BAR0_CSDM_QUEUES_OFFSET + rxq->hc_sb_info.iro_dhc_offset, rxq->ret_bytes);
            rxq->ret_bytes_last_fw_update = rxq->ret_bytes;
        }
    }
}

