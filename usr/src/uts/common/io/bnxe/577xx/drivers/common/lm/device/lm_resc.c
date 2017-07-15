/*******************************************************************************
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
 *
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
 *
 *
 * Module Description:
 *      This file contains functions that deal with resource allocation and setup
 *
 ******************************************************************************/
#include "lm5710.h"
#include "bd_chain.h"
#include "command.h"
#include "ecore_common.h"
#include "577xx_int_offsets.h"
#include "bcmtype.h"

// should be same as ceil (math.h) doesn't support u64_t
#define _ceil( _x_32, _divisor_32 ) ((_x_32 / _divisor_32) + ( (_x_32%_divisor_32) ? 1 : 0))

lm_status_t
lm_clear_chain_sb_cons_idx(
    IN struct _lm_device_t *pdev,
    IN u8_t sb_id,
    IN struct _lm_hc_sb_info_t *hc_sb_info,
    IN volatile u16_t ** hw_con_idx_ptr
    )
{
    u8_t  port       = 0;
    u8_t  func       = 0;
    u16_t rd_val     = 0xFFFF;
    u32_t rd_val_32  = 0xFFFFFFFF;
    u8_t  fw_sb_id   = 0;
    u8_t  sb_lock_id = 0;

    if (CHK_NULL(pdev) || CHK_NULL(hc_sb_info) || CHK_NULL(hw_con_idx_ptr))
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    if (IS_VFDEV(pdev))
    {
        return LM_STATUS_SUCCESS;
    }

    sb_lock_id = lm_sb_id_from_chain(pdev, sb_id);
    if (sb_lock_id == DEF_STATUS_BLOCK_INDEX)
    {
        sb_lock_id = DEF_STATUS_BLOCK_IGU_INDEX;
    }

    /* make sure that the sb is not during processing while we
     * clear the pointer */
    MM_ACQUIRE_SB_LOCK(pdev, sb_lock_id);

    *hw_con_idx_ptr = NULL;

    MM_RELEASE_SB_LOCK(pdev, sb_lock_id);

    if (lm_reset_is_inprogress(pdev))
    {
        return LM_STATUS_SUCCESS;
    }

    port = PORT_ID(pdev);
    func = FUNC_ID(pdev);
    fw_sb_id = LM_FW_SB_ID(pdev, sb_id);

    switch (hc_sb_info->hc_sb) {
    case STATUS_BLOCK_SP_SL_TYPE:
        LM_INTMEM_WRITE16(pdev, CSTORM_SP_HC_SYNC_LINE_INDEX_OFFSET(hc_sb_info->hc_index_value,func), 0, BAR_CSTRORM_INTMEM);
        LM_INTMEM_READ16(pdev, CSTORM_SP_HC_SYNC_LINE_INDEX_OFFSET(hc_sb_info->hc_index_value,func),  &rd_val, BAR_CSTRORM_INTMEM);
        DbgBreakIfAll(rd_val != 0);

        LM_INTMEM_WRITE16(pdev, (CSTORM_SP_STATUS_BLOCK_OFFSET(func) + OFFSETOF(struct hc_sp_status_block, index_values) + (hc_sb_info->hc_index_value * sizeof(u16_t))), 0, BAR_CSTRORM_INTMEM);
        LM_INTMEM_READ16 (pdev, (CSTORM_SP_STATUS_BLOCK_OFFSET(func) + OFFSETOF(struct hc_sp_status_block, index_values) + (hc_sb_info->hc_index_value * sizeof(u16_t))), &rd_val, BAR_CSTRORM_INTMEM);
        DbgBreakIfAll(rd_val != 0);
        break;
    case STATUS_BLOCK_NORMAL_SL_TYPE:
        if (!LM_SB_ID_VALID(pdev, sb_id))
        {
            return LM_STATUS_INVALID_PARAMETER;
        }
        LM_INTMEM_WRITE32(PFDEV(pdev), CSTORM_HC_SYNC_LINE_DHC_OFFSET(hc_sb_info->hc_index_value, fw_sb_id), 0, BAR_CSTRORM_INTMEM);
        LM_INTMEM_READ32(PFDEV(pdev), CSTORM_HC_SYNC_LINE_DHC_OFFSET(hc_sb_info->hc_index_value, fw_sb_id), &rd_val_32, BAR_CSTRORM_INTMEM);
        DbgBreakIfAll(rd_val_32 != 0);
        /* FALLTHROUGH */
    case STATUS_BLOCK_NORMAL_TYPE:
        if (CHIP_IS_E1x(PFDEV(pdev))) {
            LM_INTMEM_WRITE16(PFDEV(pdev), CSTORM_HC_SYNC_LINE_INDEX_E1X_OFFSET(hc_sb_info->hc_index_value, fw_sb_id), 0, BAR_CSTRORM_INTMEM);
            LM_INTMEM_READ16(PFDEV(pdev), CSTORM_HC_SYNC_LINE_INDEX_E1X_OFFSET(hc_sb_info->hc_index_value, fw_sb_id), &rd_val, BAR_CSTRORM_INTMEM);
        } else {
            LM_INTMEM_WRITE16(PFDEV(pdev), CSTORM_HC_SYNC_LINE_INDEX_E2_OFFSET(hc_sb_info->hc_index_value, fw_sb_id), 0, BAR_CSTRORM_INTMEM);
            LM_INTMEM_READ16(PFDEV(pdev), CSTORM_HC_SYNC_LINE_INDEX_E2_OFFSET(hc_sb_info->hc_index_value, fw_sb_id), &rd_val, BAR_CSTRORM_INTMEM);
        }
        DbgBreakIfAll(rd_val != 0);
        if (CHIP_IS_E1x(pdev)) {
            LM_INTMEM_WRITE16(PFDEV(pdev), (CSTORM_STATUS_BLOCK_OFFSET(fw_sb_id) + OFFSETOF(struct hc_status_block_e1x, index_values) + (hc_sb_info->hc_index_value * sizeof(u16_t))), 0, BAR_CSTRORM_INTMEM);
            LM_INTMEM_READ16 (PFDEV(pdev), (CSTORM_STATUS_BLOCK_OFFSET(fw_sb_id) + OFFSETOF(struct hc_status_block_e1x, index_values) + (hc_sb_info->hc_index_value * sizeof(u16_t))), &rd_val, BAR_CSTRORM_INTMEM);
        } else {
            LM_INTMEM_WRITE16(PFDEV(pdev), (CSTORM_STATUS_BLOCK_OFFSET(fw_sb_id) + OFFSETOF(struct hc_status_block_e2, index_values) + (hc_sb_info->hc_index_value * sizeof(u16_t))), 0, BAR_CSTRORM_INTMEM);
            LM_INTMEM_READ16 (PFDEV(pdev), (CSTORM_STATUS_BLOCK_OFFSET(fw_sb_id) + OFFSETOF(struct hc_status_block_e2, index_values) + (hc_sb_info->hc_index_value * sizeof(u16_t))), &rd_val, BAR_CSTRORM_INTMEM);

        }
        break;
    default:
        DbgMessage(NULL, FATAL, "Invalid hc_sb value: 0x%x.\n", hc_sb_info->hc_sb);
        DbgBreakIf(1);
    }
    /* We read from the same memory and verify that it's 0 to make sure that the value was written to the grc and was not delayed in the pci */
    DbgBreakIfAll(rd_val != 0);

    return LM_STATUS_SUCCESS;
}

/*
 * reset txq, rxq, rcq counters for L2 client connection
 *
 * assumption: the cid equals the chain idx
 */
/**
 * @Description:
 *   allocate given num of coalesce buffers, and queue them in the txq chain.
 *   1 buffer is allocated for LSO packets, and the rest are allocated with
 *   MTU size.
 * @Return:
 *   lm_status
*/
static lm_status_t
lm_allocate_coalesce_buffers(
    lm_device_t     *pdev,
    lm_tx_chain_t   *txq,
    u32_t           coalesce_buf_cnt,
    u32_t           cid)
{
    lm_coalesce_buffer_t *last_coalesce_buf = NULL;
    lm_coalesce_buffer_t *coalesce_buf      = NULL;
    lm_address_t         mem_phy            = {{0}};
    u8_t *               mem_virt           = NULL;
    u32_t                mem_left           = 0;
    u32_t                mem_size           = 0;
    u32_t                buf_size           = 0;
    u32_t                cnt                = 0;
    u8_t                 mm_cli_idx         = 0;

    /* check arguments */
    if(CHK_NULL(pdev) || CHK_NULL(txq))
    {
        return LM_STATUS_FAILURE;
    }

    DbgMessage(pdev, VERBOSEi | VERBOSEl2sp,
                "#lm_allocate_coalesce_buffers, coalesce_buf_cnt=%d\n",
                coalesce_buf_cnt);

    mm_cli_idx = cid_to_resource(pdev, cid); //!!DP mm_cli_idx_to_um_idx(LM_CHAIN_IDX_CLI(pdev, idx));

    if(coalesce_buf_cnt == 0)
    {
        return LM_STATUS_SUCCESS;
    }

    buf_size = MAX_L2_CLI_BUFFER_SIZE(pdev, cid);

    mem_size = coalesce_buf_cnt * sizeof(lm_coalesce_buffer_t);
    mem_virt = mm_alloc_mem(pdev,mem_size, mm_cli_idx);
    if(ERR_IF(!mem_virt))
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return LM_STATUS_RESOURCE;
    }
    mm_memset(mem_virt, 0, mem_size);

    /* Create a list of frame buffer descriptors. */
    coalesce_buf = (lm_coalesce_buffer_t *) mem_virt;
    for(cnt = 0; cnt < coalesce_buf_cnt; cnt++)
    {
        coalesce_buf->frags.cnt = 1;
        coalesce_buf->frags.size = 0; /* not in use */
        coalesce_buf->buf_size = buf_size;

        s_list_push_tail(
            &txq->coalesce_buf_list,
            &coalesce_buf->link);

        coalesce_buf++;
    }

    /* Have at least one coalesce buffer large enough to copy
     * an LSO frame. */
    coalesce_buf = (lm_coalesce_buffer_t *) s_list_peek_head(
        &txq->coalesce_buf_list);
    coalesce_buf->buf_size = 0x10000; /* TBD: consider apply change here for GSO */

    /* Determine the total memory for the coalesce buffers. */
    mem_left = 0;

    coalesce_buf = (lm_coalesce_buffer_t *) s_list_peek_head(
        &txq->coalesce_buf_list);
    while(coalesce_buf)
    {
        mem_left += coalesce_buf->buf_size;
        coalesce_buf = (lm_coalesce_buffer_t *) s_list_next_entry(
            &coalesce_buf->link);
    }

    mem_size = 0;

    /* Initialize all the descriptors to point to a buffer. */
    coalesce_buf = (lm_coalesce_buffer_t *) s_list_peek_head(
        &txq->coalesce_buf_list);
    while(coalesce_buf)
    {
        #define MAX_CONTIGUOUS_BLOCK            (64*1024)

        /* Allocate a small block of memory at a time. */
        if(mem_size == 0)
        {
            last_coalesce_buf = coalesce_buf;

            while(coalesce_buf)
            {
                mem_size += coalesce_buf->buf_size;
                if(mem_size >= MAX_CONTIGUOUS_BLOCK) /* TBD: consider apply change here for GSO */
                {
                    break;
                }

                coalesce_buf = (lm_coalesce_buffer_t *) s_list_next_entry(
                    &coalesce_buf->link);
            }

            mem_left -= mem_size;

            mem_virt = mm_alloc_phys_mem( pdev, mem_size, &mem_phy, 0, mm_cli_idx);
            if(ERR_IF(!mem_virt))
            {
                DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
                return LM_STATUS_RESOURCE;
            }
            mm_memset(mem_virt, 0, mem_size);

            coalesce_buf = last_coalesce_buf;
        }

        coalesce_buf->mem_virt = mem_virt;
        coalesce_buf->frags.frag_arr[0].addr = mem_phy;
        coalesce_buf->frags.frag_arr[0].size = 0; /* to be set later according to actual packet size */
        mem_size -= coalesce_buf->buf_size;

        /* Go to the next packet buffer. */
        mem_virt += coalesce_buf->buf_size;
        LM_INC64(&mem_phy, coalesce_buf->buf_size);

        coalesce_buf = (lm_coalesce_buffer_t *) s_list_next_entry(
            &coalesce_buf->link);
    }

    if(mem_left || mem_size)
    {
        DbgBreakMsg("Memory allocation out of sync\n");

        return LM_STATUS_FAILURE;
    }

    return LM_STATUS_SUCCESS;
} /* lm_allocate_coalesce_buffers */

lm_status_t
lm_alloc_txq(
    IN struct _lm_device_t *pdev,
    IN u32_t const          cid, /* chain id */
    IN u16_t const          page_cnt,
    IN u16_t const          coalesce_buf_cnt)
{
    lm_tx_chain_t *tx_chain   = NULL  ;
    u32_t const    mem_size   = page_cnt * LM_PAGE_SIZE;
    u8_t  mm_cli_idx      = 0 ;

    DbgMessage(pdev, INFORMi | INFORMl2sp, "#lm_alloc_txq, cid=%d, page_cnt=%d\n", cid, page_cnt);

    /* check arguments */
    if(CHK_NULL(pdev) ||
       ERR_IF((ARRSIZE(pdev->tx_info.chain) <= cid) || !page_cnt))
    {
        return LM_STATUS_FAILURE;
    }

    tx_chain = &LM_TXQ(pdev, cid);

    mm_cli_idx = cid_to_resource(pdev, cid);

    /* alloc the chain */

    tx_chain->bd_chain.bd_chain_virt =
        mm_alloc_phys_mem( pdev, mem_size, &tx_chain->bd_chain.bd_chain_phy, 0, mm_cli_idx);
    if(ERR_IF(!tx_chain->bd_chain.bd_chain_virt))
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return LM_STATUS_RESOURCE;
    }
    mm_mem_zero(tx_chain->bd_chain.bd_chain_virt, mem_size);

    tx_chain->bd_chain.page_cnt = page_cnt;

    s_list_init(&tx_chain->active_descq, NULL, NULL, 0);
    s_list_init(&tx_chain->coalesce_buf_list, NULL, NULL, 0);
    tx_chain->idx              = cid;
    tx_chain->coalesce_buf_cnt = coalesce_buf_cnt;

    return lm_allocate_coalesce_buffers(
        pdev,
        &LM_TXQ(pdev, cid),
        coalesce_buf_cnt,
        cid);

} /* lm_alloc_txq */

lm_status_t
lm_alloc_rxq(
    IN struct _lm_device_t *pdev,
    IN u32_t const          cid,
    IN u16_t const          page_cnt,
    IN u32_t const          desc_cnt)
{
    lm_rx_chain_t*     rxq_chain        = NULL;
    lm_bd_chain_t *    bd_chain         = NULL;
    lm_rxq_chain_idx_t rx_chain_idx_max = LM_RXQ_CHAIN_IDX_MAX;
    lm_rxq_chain_idx_t rx_chain_idx_cur = 0;
    u32_t const        mem_size         = page_cnt * LM_PAGE_SIZE;
    u8_t               mm_cli_idx       = 0 ;

    /* check arguments */
    if(CHK_NULL(pdev) ||
       ERR_IF((ARRSIZE(pdev->rx_info.rxq_chain) <= cid) || !page_cnt))
    {
        return LM_STATUS_FAILURE;
    }

    rxq_chain = &LM_RXQ(pdev, cid);

    DbgMessage(pdev, INFORMi, "#lm_alloc_rxq, cid=%d, page_cnt=%d, desc_cnt=%d\n",
                cid, page_cnt, desc_cnt);

    mm_cli_idx = cid_to_resource(pdev, cid);//!!DP mm_cli_idx_to_um_idx(LM_CHAIN_IDX_CLI(pdev, idx));

    s_list_init(&rxq_chain->common.free_descq, NULL, NULL, 0);
    s_list_init(&rxq_chain->active_descq, NULL, NULL, 0);
    rxq_chain->idx      = cid;
    rxq_chain->common.desc_cnt = desc_cnt;

    /* alloc the chain(s) */
    rx_chain_idx_max = LM_RXQ_IS_CHAIN_SGE_VALID( pdev, cid ) ? LM_RXQ_CHAIN_IDX_SGE : LM_RXQ_CHAIN_IDX_BD;

    for( rx_chain_idx_cur = 0; rx_chain_idx_cur <= rx_chain_idx_max; rx_chain_idx_cur++ )
    {
        bd_chain = &LM_RXQ_CHAIN( pdev, cid, rx_chain_idx_cur );

        bd_chain->bd_chain_virt =  mm_alloc_phys_mem( pdev, mem_size, &bd_chain->bd_chain_phy, 0, mm_cli_idx);
        if(ERR_IF(!bd_chain->bd_chain_virt))
        {
            DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
            return LM_STATUS_RESOURCE;
        }
        mm_mem_zero(bd_chain->bd_chain_virt, mem_size);

        bd_chain->page_cnt = page_cnt;
    }

    return LM_STATUS_SUCCESS;
} /* lm_alloc_rxq */

lm_status_t
lm_alloc_rcq(
    IN struct _lm_device_t *pdev,
    IN u32_t const          cid,
    IN u16_t const          page_cnt)
{
    lm_rcq_chain_t *rcq_chain = NULL;
    u32_t const mem_size      = page_cnt * LM_PAGE_SIZE;
    u8_t  mm_cli_idx      = 0 ;

    /* check arguments */
    if(CHK_NULL(pdev) ||
       ERR_IF((ARRSIZE(pdev->rx_info.rcq_chain) <= cid) || !page_cnt))
    {
        return LM_STATUS_FAILURE;
    }

    ASSERT_STATIC(sizeof(struct eth_rx_bd)*LM_RX_BD_CQ_SIZE_RATIO == sizeof(union eth_rx_cqe));
    ASSERT_STATIC(sizeof(struct eth_rx_bd) == sizeof(struct eth_rx_sge) );

    rcq_chain = &pdev->rx_info.rcq_chain[cid];

    DbgMessage(pdev, INFORMi | INFORMl2sp,
                "#lm_alloc_rcq, idx=%d, page_cnt=%d\n",
                cid, page_cnt);

    mm_cli_idx = cid_to_resource(pdev, cid);//!!DP mm_cli_idx_to_um_idx(LM_CHAIN_IDX_CLI(pdev, idx));

    /* alloc the chain */
    rcq_chain->bd_chain.bd_chain_virt =
        mm_alloc_phys_mem( pdev, mem_size, &rcq_chain->bd_chain.bd_chain_phy, 0, mm_cli_idx);

    if(ERR_IF(!rcq_chain->bd_chain.bd_chain_virt))
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return LM_STATUS_RESOURCE;
    }

    mm_mem_zero(rcq_chain->bd_chain.bd_chain_virt, mem_size);
    rcq_chain->bd_chain.page_cnt = page_cnt;

    return LM_STATUS_SUCCESS;
} /* lm_alloc_rcq */

/**
 * @description
 * Allocte TPA chain
 * @param pdev
 * @param cid -chain index.
 * @param page_cnt - Number of BD pages
 * @param desc_cnt - Number of descriptor counts
 * @param bds_per_page - Number of BDs per page.
 *
 * @return lm_status_t
 */
lm_status_t
lm_alloc_tpa_chain(
    IN struct _lm_device_t *pdev,
    IN u32_t const          cid,
    IN u16_t const          page_cnt,
    IN u32_t const          desc_cnt,
    IN u32_t const          bds_per_page)
{
    lm_tpa_chain_t*     tpa_chain   = NULL;
    lm_bd_chain_t *     bd_chain    = NULL;
    lm_tpa_sge_chain_t*    sge_chain   = NULL;
    u32_t               mem_size    = 0;
    u8_t                mm_cli_idx  = 0 ;

    /* check arguments */
    if(CHK_NULL(pdev) ||
       ERR_IF((ARRSIZE(pdev->rx_info.rxq_chain) <= cid) || !page_cnt))
    {
        return LM_STATUS_FAILURE;
    }

    tpa_chain = &LM_TPA(pdev, cid);
    bd_chain  = &LM_TPA_CHAIN_BD( pdev, cid );
    sge_chain = &LM_SGE_TPA_CHAIN( pdev, cid );

    DbgMessage(pdev, INFORMi, "#lm_alloc_tpa, cid=%d, page_cnt=%d, desc_cnt=%d\n",
                cid, page_cnt, desc_cnt);

    mm_cli_idx = cid_to_resource(pdev, cid);

    s_list_init(&tpa_chain->common.free_descq, NULL, NULL, 0);
    tpa_chain->common.desc_cnt = desc_cnt;

    /************ Alocate BD chain********************************/
    mem_size    = page_cnt * LM_PAGE_SIZE;
    bd_chain->bd_chain_virt =  mm_alloc_phys_mem( pdev, mem_size, &bd_chain->bd_chain_phy, 0, mm_cli_idx);
    if(ERR_IF(!bd_chain->bd_chain_virt))
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return LM_STATUS_RESOURCE;
    }
    mm_mem_zero(bd_chain->bd_chain_virt, mem_size);
    bd_chain->page_cnt = page_cnt;

    // The number of SGE bd entries
    sge_chain->size = page_cnt * bds_per_page;
    tpa_chain->state = lm_tpa_state_disable;

    /************ Alocate active descriptor array********************************/
    mem_size = LM_TPA_ACTIVE_DESCQ_ARRAY_ELEM(pdev,cid);
    mem_size *= sizeof(lm_packet_t *);
    sge_chain->active_descq_array = mm_alloc_mem(pdev, mem_size, mm_cli_idx);

    if(CHK_NULL(sge_chain->active_descq_array))
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return LM_STATUS_RESOURCE;
    }
    mm_mem_zero(sge_chain->active_descq_array, mem_size);

    /************ Alocate mask_array descriptor array********************************/
    ASSERT_STATIC(0 != BIT_VEC64_ELEM_SZ); //LM_TPA_MASK_LEN - divide by BIT_VEC64_ELEM_SZ
    mem_size = LM_TPA_MASK_LEN(pdev, cid);
    mem_size = mem_size * sizeof(u64_t);
    sge_chain->mask_array = mm_alloc_mem(pdev, mem_size, mm_cli_idx);

    if(CHK_NULL(sge_chain->mask_array))
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return LM_STATUS_RESOURCE;
    }
    mm_mem_zero(sge_chain->mask_array, mem_size);

    /************ Alocate TPA ramrod data********************************/
    mem_size = sizeof(struct tpa_update_ramrod_data);
    tpa_chain->ramrod_data_virt = mm_alloc_phys_mem(pdev, mem_size, &tpa_chain->ramrod_data_phys, 0, mm_cli_idx);

    if(CHK_NULL(tpa_chain->ramrod_data_virt))
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return LM_STATUS_RESOURCE ;
    }
    mm_mem_zero(tpa_chain->ramrod_data_virt, mem_size);

    return LM_STATUS_SUCCESS;
} /* lm_alloc_tpa */

lm_resource_idx_t cid_to_resource(lm_device_t *pdev, u32_t cid)
{
    lm_resource_idx_t resource;

    if (lm_chain_type_not_cos != lm_mp_get_chain_type(pdev, cid))
    {
        resource = LM_RESOURCE_NDIS;
    }
    else if (cid == ISCSI_CID(pdev))
    {
        resource = LM_RESOURCE_ISCSI;
    }
    else if (cid == FCOE_CID(pdev))
    {
        resource = LM_RESOURCE_FCOE;
    }
    else if (cid == FWD_CID(pdev))
    {
        resource = LM_RESOURCE_FWD;
    }
    else if (cid == OOO_CID(pdev))
    {
        resource = LM_RESOURCE_OOO;
    }
    else
    {
        resource = LM_RESOURCE_COMMON;
    }

    return resource;
}


lm_status_t
lm_setup_txq(
    IN struct _lm_device_t *pdev,
    IN u32_t                cid)
{
    lm_bd_chain_t *                         bd_chain = NULL;
    volatile struct hc_sp_status_block *    sp_sb = NULL;
    u16_t volatile *                        sb_indexes = NULL;
    u8_t                                    tx_sb_index_number =0;
    /* check arguments */
    if(CHK_NULL(pdev) ||
       ERR_IF((ARRSIZE(pdev->tx_info.chain) <= cid)))
    {
        return LM_STATUS_FAILURE;
    }
    DbgMessage(pdev, INFORMi|INFORMl2sp, "#lm_setup_txq, cid=%d\n",cid);

    sp_sb = lm_get_default_status_block(pdev);

    LM_TXQ(pdev, cid).prod_bseq = 0;
    LM_TXQ(pdev, cid).pkt_idx = 0;
    LM_TXQ(pdev, cid).coalesce_buf_used = 0;
    LM_TXQ(pdev, cid).lso_split_used = 0;

    bd_chain = &LM_TXQ(pdev, cid).bd_chain;
    lm_bd_chain_setup(pdev, bd_chain, bd_chain->bd_chain_virt, bd_chain->bd_chain_phy, bd_chain->page_cnt, sizeof(struct eth_tx_bd), /* is full? */0, TRUE);

    DbgMessage(pdev, INFORMi, "txq %d, bd_chain %p, bd_left %d\n",
        cid,
        LM_TXQ(pdev, cid).bd_chain.next_bd,
        LM_TXQ(pdev, cid).bd_chain.bd_left);

    DbgMessage(pdev, INFORMi, "   bd_chain_phy 0x%x%08x\n",
        LM_TXQ(pdev, cid).bd_chain.bd_chain_phy.as_u32.high,
        LM_TXQ(pdev, cid).bd_chain.bd_chain_phy.as_u32.low);

    mm_memset(&LM_TXQ(pdev, cid).eth_tx_prods.packets_prod, 0, sizeof(eth_tx_prod_t));

    if (cid == FWD_CID(pdev))
    {
        sp_sb->index_values[HC_SP_INDEX_ETH_FW_TX_CQ_CONS] = 0;
        LM_TXQ(pdev, cid).hw_con_idx_ptr =
            &(sp_sb->index_values[HC_SP_INDEX_ETH_FW_TX_CQ_CONS]);
        LM_TXQ(pdev, cid).hc_sb_info.hc_sb = STATUS_BLOCK_SP_SL_TYPE; // STATUS_BLOCK_SP_TYPE;
        LM_TXQ(pdev, cid).hc_sb_info.hc_index_value = HC_SP_INDEX_ETH_FW_TX_CQ_CONS;
        /* iro_dhc_offste not initialized on purpose --> not expected for FWD channel */
    }
    else if (cid == ISCSI_CID(pdev))
    {
        sp_sb->index_values[HC_SP_INDEX_ETH_ISCSI_CQ_CONS] = 0;
        LM_TXQ(pdev, cid).hw_con_idx_ptr = &(sp_sb->index_values[HC_SP_INDEX_ETH_ISCSI_CQ_CONS]);
        LM_TXQ(pdev, cid).hc_sb_info.hc_sb = STATUS_BLOCK_SP_SL_TYPE; //STATUS_BLOCK_SP_TYPE;
        LM_TXQ(pdev, cid).hc_sb_info.hc_index_value = HC_SP_INDEX_ETH_ISCSI_CQ_CONS;
        /* iro_dhc_offste not initialized on purpose --> not expected for FWD channel */
    }
    else if (cid == FCOE_CID(pdev))
    {
        sp_sb->index_values[HC_SP_INDEX_ETH_FCOE_CQ_CONS] = 0;
        LM_TXQ(pdev, cid).hw_con_idx_ptr =
            &(sp_sb->index_values[HC_SP_INDEX_ETH_FCOE_CQ_CONS]);
        LM_TXQ(pdev, cid).hc_sb_info.hc_sb = STATUS_BLOCK_SP_SL_TYPE; //STATUS_BLOCK_SP_TYPE;
        LM_TXQ(pdev, cid).hc_sb_info.hc_index_value = HC_SP_INDEX_ETH_FCOE_CQ_CONS;
        /* iro_dhc_offste not initialized on purpose --> not expected for FWD channel */
    }
    else if(cid == OOO_CID(pdev))
    {
        DbgBreakMsg("OOO doesn't have a txq");
        return LM_STATUS_FAILURE;
    }
    else
    {
        u32_t sb_id = RSS_ID_TO_SB_ID(CHAIN_TO_RSS_ID(pdev,cid));
        const u8_t byte_counter_id = CHIP_IS_E1x(pdev)? LM_FW_SB_ID(pdev, sb_id) : LM_FW_DHC_QZONE_ID(pdev, sb_id);

        // Assign the TX chain consumer pointer to the consumer index in the status block. TBD: rename HC_INDEX_C_ETH_TX_CQ_CONS as its inappropriate
        if( sb_id >= ARRSIZE(pdev->vars.status_blocks_arr) )
        {
            DbgBreakIf( sb_id >= ARRSIZE(pdev->vars.status_blocks_arr) ) ;
            return LM_STATUS_FAILURE ;
        }

        sb_indexes = lm_get_sb_indexes(pdev, (u8_t)sb_id);
        // This isn't realy cid it is the chain index
        tx_sb_index_number =
            lm_eth_tx_hc_cq_cons_cosx_from_chain(pdev, cid);

        sb_indexes[tx_sb_index_number] = 0;
        LM_TXQ(pdev, cid).hw_con_idx_ptr = sb_indexes + tx_sb_index_number;
        LM_TXQ(pdev, cid).hc_sb_info.hc_sb = STATUS_BLOCK_NORMAL_TYPE;
        LM_TXQ(pdev, cid).hc_sb_info.hc_index_value = tx_sb_index_number;
        if (IS_PFDEV(pdev))
        {
            LM_TXQ(pdev, cid).hc_sb_info.iro_dhc_offset = CSTORM_BYTE_COUNTER_OFFSET(byte_counter_id, tx_sb_index_number);
        }
        else
        {
            DbgMessage(pdev, FATAL, "Dhc not implemented for VF yet\n");
        }
    }

    return LM_STATUS_SUCCESS;
} /* lm_setup_txq */

lm_status_t lm_setup_rxq( IN struct _lm_device_t *pdev,
                          IN u32_t const          cid)
{
    lm_bd_chain_t * bd_chain = NULL;
    lm_rx_chain_t *    rxq_chain                             = NULL;
    lm_rxq_chain_idx_t rx_chain_idx_max                      = LM_RXQ_CHAIN_IDX_MAX;
    lm_rxq_chain_idx_t rx_chain_idx_cur                      = 0;
    static u8_t const  eth_rx_size_arr[LM_RXQ_CHAIN_IDX_MAX] = {sizeof(struct eth_rx_bd), sizeof(struct eth_rx_sge)};
    u32_t              sb_id                                 = RSS_ID_TO_SB_ID(CHAIN_TO_RSS_ID(pdev,cid));
    const u8_t         byte_counter_id                       = CHIP_IS_E1x(pdev)? LM_FW_SB_ID(pdev, sb_id) : LM_FW_DHC_QZONE_ID(pdev, sb_id);

    /* check arguments */
    if(CHK_NULL(pdev) ||
       ERR_IF((ARRSIZE(pdev->rx_info.rxq_chain) <= cid)))
    {
        return LM_STATUS_FAILURE;
    }

    DbgMessage(pdev, INFORMi|INFORMl2sp, "#lm_setup_rxq, cid=%d\n",cid);

    rxq_chain = &LM_RXQ(pdev, cid);

    rxq_chain->common.prod_bseq                = 0;
    rxq_chain->ret_bytes                = 0;
    rxq_chain->ret_bytes_last_fw_update = 0;
    rxq_chain->common.bd_prod_without_next     = 0;

    rx_chain_idx_max = LM_RXQ_IS_CHAIN_SGE_VALID( pdev, cid ) ? LM_RXQ_CHAIN_IDX_SGE : LM_RXQ_CHAIN_IDX_BD;

    for( rx_chain_idx_cur = 0; rx_chain_idx_cur <= rx_chain_idx_max; rx_chain_idx_cur++ )
    {
        bd_chain = &LM_RXQ_CHAIN( pdev, cid, rx_chain_idx_cur );

        lm_bd_chain_setup(pdev, bd_chain, bd_chain->bd_chain_virt, bd_chain->bd_chain_phy,bd_chain->page_cnt, eth_rx_size_arr[rx_chain_idx_cur], /* is full? */0, TRUE);

        DbgMessage(pdev, INFORMi, "rxq[%d] bd_chain[%d] %p, bd_left %d\n", cid,
                                                                            rx_chain_idx_cur,
                                                                            bd_chain->next_bd,
                                                                            bd_chain->bd_left);

        DbgMessage(pdev, INFORMi, "   bd_chain_phy[%d] 0x%x%08x\n", rx_chain_idx_cur,
                                                                     bd_chain->bd_chain_phy.as_u32.high,
                                                                     bd_chain->bd_chain_phy.as_u32.low);
    }

    /* We initilize the hc_sb_info here for completeness. The fw updates are actually done by rcq-chain, but the dynamic-host-coalescing based on rx-chain */
    rxq_chain->hc_sb_info.hc_sb = STATUS_BLOCK_NORMAL_SL_TYPE;
    rxq_chain->hc_sb_info.hc_index_value = HC_INDEX_ETH_RX_CQ_CONS;
    if (IS_PFDEV(pdev))
    {
        rxq_chain->hc_sb_info.iro_dhc_offset = CSTORM_BYTE_COUNTER_OFFSET(byte_counter_id, HC_INDEX_ETH_RX_CQ_CONS);
    }
    else
    {
        rxq_chain->hc_sb_info.iro_dhc_offset = sizeof(struct cstorm_queue_zone_data) * LM_FW_DHC_QZONE_ID(pdev, sb_id)
            + sizeof(u32_t) * HC_INDEX_ETH_RX_CQ_CONS;
        DbgMessage(pdev, WARN, "Dhc offset is 0x%x for VF Q Zone %d\n",rxq_chain->hc_sb_info.iro_dhc_offset,LM_FW_DHC_QZONE_ID(pdev, sb_id));
    }

    return LM_STATUS_SUCCESS;
} /* lm_setup_rxq */


lm_status_t
lm_setup_rcq( IN struct _lm_device_t *pdev,
              IN u32_t  const         cid)
{
    lm_bd_chain_t *                      bd_chain   = NULL;
    lm_rcq_chain_t *                     rcq_chain  = NULL;
    lm_rx_chain_t *                      rxq_chain  = NULL;
    volatile struct hc_sp_status_block * sp_sb      = NULL;
    u16_t volatile *                     sb_indexes = NULL;

    /* check arguments */
    if(CHK_NULL(pdev) ||
       ERR_IF((ARRSIZE(pdev->rx_info.rcq_chain) <= cid)))
    {
        return LM_STATUS_FAILURE;
    }

    rcq_chain = &LM_RCQ(pdev, cid);
    rxq_chain = &LM_RXQ(pdev, cid);

    DbgMessage(pdev, INFORMi|INFORMl2sp, "#lm_setup_rcq, cid=%d\n",cid);

    sp_sb = lm_get_default_status_block(pdev);

    rcq_chain->prod_bseq = 0;
    if (CHIP_IS_E1x(pdev))
    {
        rcq_chain->iro_prod_offset = USTORM_RX_PRODS_E1X_OFFSET(PORT_ID(pdev), LM_FW_CLI_ID(pdev, cid));
    }
    else
    {
        if (IS_VFDEV(pdev))
        {
            rcq_chain->iro_prod_offset = LM_FW_QZONE_ID(pdev, cid)*sizeof(struct ustorm_queue_zone_data);
            DbgMessage(pdev, FATAL, "iro_prod_offset for vf = %x...\n", rcq_chain->iro_prod_offset);
        }
    }

    //if(pdev->params.l2_rx_desc_cnt[0]) /* if removed. was not required */
    bd_chain = &rcq_chain->bd_chain;

    lm_bd_chain_setup(pdev, bd_chain, bd_chain->bd_chain_virt, bd_chain->bd_chain_phy,bd_chain->page_cnt, sizeof(union eth_rx_cqe), /* is full? */0, TRUE);

    //number of Bds left in the RCQ must be at least the same with its corresponding Rx chain.
    DbgBreakIf(lm_bd_chain_avail_bds(&rxq_chain->chain_arr[LM_RXQ_CHAIN_IDX_BD]) <= lm_bd_chain_avail_bds(&rcq_chain->bd_chain));

    if( LM_RXQ_IS_CHAIN_SGE_VALID(pdev, cid ) )
    {
        DbgBreakIf( !lm_bd_chains_are_consistent( &rxq_chain->chain_arr[LM_RXQ_CHAIN_IDX_BD], &rxq_chain->chain_arr[LM_RXQ_CHAIN_IDX_SGE]) );
    }

    DbgMessage(pdev, INFORMi, "rcq %d, bd_chain %p, bd_left %d\n", cid,
                                                                    rcq_chain->bd_chain.next_bd,
                                                                    rcq_chain->bd_chain.bd_left);
    DbgMessage(pdev, INFORMi, "   bd_chain_phy 0x%x%08x\n", rcq_chain->bd_chain.bd_chain_phy.as_u32.high,
                                                             rcq_chain->bd_chain.bd_chain_phy.as_u32.low);

    // Assign the RCQ chain consumer pointer to the consumer index in the status block.
    if (cid == ISCSI_CID(pdev))
    {
        if (CHIP_IS_E2E3(pdev)) {
            u8_t rel_cid = cid - LM_MAX_RSS_CHAINS(pdev);
            rcq_chain->iro_prod_offset = USTORM_RX_PRODS_E2_OFFSET(LM_FW_AUX_QZONE_ID(pdev, rel_cid));
        }
        sp_sb->index_values[HC_SP_INDEX_ETH_ISCSI_RX_CQ_CONS] = 0;
        rcq_chain->hw_con_idx_ptr                             = &(sp_sb->index_values[HC_SP_INDEX_ETH_ISCSI_RX_CQ_CONS]);
        rcq_chain->hc_sb_info.hc_sb                           = STATUS_BLOCK_SP_SL_TYPE;
        rcq_chain->hc_sb_info.hc_index_value                  = HC_SP_INDEX_ETH_ISCSI_RX_CQ_CONS;
    }
    else if (cid == FCOE_CID(pdev))
    {
        if (CHIP_IS_E2E3(pdev)) {
            u8_t rel_cid = cid - LM_MAX_RSS_CHAINS(pdev);
            rcq_chain->iro_prod_offset = USTORM_RX_PRODS_E2_OFFSET(LM_FW_AUX_QZONE_ID(pdev, rel_cid));
        }
        sp_sb->index_values[HC_SP_INDEX_ETH_FCOE_RX_CQ_CONS] = 0;
        rcq_chain->hw_con_idx_ptr                             = &(sp_sb->index_values[HC_SP_INDEX_ETH_FCOE_RX_CQ_CONS]);
        rcq_chain->hc_sb_info.hc_sb                           = STATUS_BLOCK_SP_SL_TYPE;
        rcq_chain->hc_sb_info.hc_index_value                  = HC_SP_INDEX_ETH_FCOE_RX_CQ_CONS;
    }
    else if (cid == OOO_CID(pdev))
    {
        // Any SB that isn't RSS share the same SB.
        // basically we will want the ISCSI OOO to work on the same SB that ISCSI works.(This does happen see the line above)
        // Even if we want to count on ISCSI and make sure we will work on the same SB:
        // 1.There is no promise on the order the ISCSI nminiport will call
        // ISCSI_KWQE_OPCODE_INIT1 (lm_sc_init inits pdev->iscsi_info.l5_eq_base_chain_idx) or
        // 2.OOO is general code that doesn't depend on a protocol (ISCSI).

        //TODO_OOO Ask Michal regarding E2 if we need LM_FW_SB_ID
        if (CHIP_IS_E2E3(pdev)) {
            u8_t rel_cid = cid - LM_MAX_RSS_CHAINS(pdev);
            rcq_chain->iro_prod_offset = USTORM_RX_PRODS_E2_OFFSET(LM_FW_AUX_QZONE_ID(pdev, rel_cid));
        }
        sp_sb->index_values[HC_SP_INDEX_ISCSI_OOO_RX_CONS]  = 0;
        rcq_chain->hw_con_idx_ptr                           = &(sp_sb->index_values[HC_SP_INDEX_ISCSI_OOO_RX_CONS]);
        rcq_chain->hc_sb_info.hc_sb                         = STATUS_BLOCK_SP_SL_TYPE;
        rcq_chain->hc_sb_info.hc_index_value                = HC_SP_INDEX_ISCSI_OOO_RX_CONS;
    }
    else /* NDIS */
    {
        u32_t sb_id = RSS_ID_TO_SB_ID(CHAIN_TO_RSS_ID(pdev,cid));
        const u8_t byte_counter_id = CHIP_IS_E1x(pdev)? LM_FW_SB_ID(pdev, sb_id) : LM_FW_DHC_QZONE_ID(pdev, sb_id);

        if (IS_PFDEV(pdev) && CHIP_IS_E2E3(pdev)) {
            rcq_chain->iro_prod_offset = USTORM_RX_PRODS_E2_OFFSET(LM_FW_DHC_QZONE_ID(pdev, sb_id));
        }
        if( sb_id >= ARRSIZE(pdev->vars.status_blocks_arr) )
        {
            DbgBreakIf( sb_id >= ARRSIZE(pdev->vars.status_blocks_arr) ) ;
            return LM_STATUS_FAILURE ;
        }

        sb_indexes = lm_get_sb_indexes(pdev, (u8_t)sb_id);
        sb_indexes[HC_INDEX_ETH_RX_CQ_CONS] = 0;
        rcq_chain->hw_con_idx_ptr = sb_indexes + HC_INDEX_ETH_RX_CQ_CONS;
        rcq_chain->hc_sb_info.hc_sb = STATUS_BLOCK_NORMAL_SL_TYPE;
        rcq_chain->hc_sb_info.hc_index_value = HC_INDEX_ETH_RX_CQ_CONS;
        if (IS_PFDEV(pdev))
        {
            rcq_chain->hc_sb_info.iro_dhc_offset = CSTORM_BYTE_COUNTER_OFFSET(byte_counter_id, HC_INDEX_ETH_RX_CQ_CONS);
        }
        else
        {
            DbgMessage(pdev, FATAL, "Dhc not implemented for VF yet\n");
        }
    }

    return LM_STATUS_SUCCESS;
} /* lm_setup_rcq */

lm_status_t
lm_setup_client_con_resc(
    IN struct _lm_device_t *pdev,
    IN u32_t cid
    )
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;

    if CHK_NULL(pdev)
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    if((GET_FLAGS(pdev->params.l2_cli_con_params[cid].attributes,LM_CLIENT_ATTRIBUTES_RX) &&
       (cid >= MAX_RX_CHAIN(pdev))) ||
        (GET_FLAGS(pdev->params.l2_cli_con_params[cid].attributes,LM_CLIENT_ATTRIBUTES_TX) &&
       (cid >= MAX_TX_CHAIN(pdev))))

    {
        DbgBreakMsg(" invalid chain ");
        return LM_STATUS_INVALID_PARAMETER;
    }

    if(GET_FLAGS(pdev->params.l2_cli_con_params[cid].attributes,LM_CLIENT_ATTRIBUTES_TX))
    {
        lm_status = lm_setup_txq(pdev, cid);
        if (lm_status != LM_STATUS_SUCCESS)
        {
            return lm_status;
        }
    }


    if(GET_FLAGS(pdev->params.l2_cli_con_params[cid].attributes,LM_CLIENT_ATTRIBUTES_RX))
    {
        lm_status = lm_setup_rxq(pdev, cid);
        if (lm_status != LM_STATUS_SUCCESS)
        {
            return lm_status;
        }

        lm_status = lm_setup_rcq(pdev, cid);
        if (lm_status != LM_STATUS_SUCCESS)
        {
            return lm_status;
        }
    }

    if(GET_FLAGS(pdev->params.l2_cli_con_params[cid].attributes,LM_CLIENT_ATTRIBUTES_TPA))
    {
        lm_status = lm_setup_tpa_chain(pdev, cid);
        if (lm_status != LM_STATUS_SUCCESS)
        {
            return lm_status;
        }
    }
    pdev->client_info[cid].last_set_rx_mask = 0;

    return LM_STATUS_SUCCESS;
}

/*
 * reset txq, rxq, rcq counters for L2 client connection
 *
 * assumption: the cid equals the chain idx
 */
lm_status_t lm_clear_eth_con_resc( IN struct _lm_device_t *pdev,
                                   IN u8_t const          cid )
{
    u8_t sb_id = lm_sb_id_from_chain(pdev, cid);
    u8_t max_eth_cid;
    if CHK_NULL(pdev)
    {
        return LM_STATUS_INVALID_PARAMETER;
    }
    if (MM_DCB_MP_L2_IS_ENABLE(pdev))
    {
        max_eth_cid = lm_mp_max_cos_chain_used(pdev);
    }
    else
    {
        max_eth_cid = MAX_RX_CHAIN(pdev);
    }
    if (cid >= max_eth_cid)
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    /* Set hw consumer index pointers to null, so we won't get rx/tx completion */
    /* for this connection, next time we'll load it                             */

    // Regardless the attributes we "clean' the TX status block

    if(GET_FLAGS(pdev->params.l2_cli_con_params[cid].attributes,LM_CLIENT_ATTRIBUTES_TX))
    {
        if (cid >= MAX_TX_CHAIN(pdev))
        {
            DbgBreakMsg(" Invalid TX chain index ");
            return LM_STATUS_INVALID_PARAMETER;
        }
        /* first set the hw consumer index pointers to null, and only then clear the pkt_idx value
         * to avoid a race when servicing interrupt at the same time */
        lm_clear_chain_sb_cons_idx(pdev, sb_id, &LM_TXQ(pdev, cid).hc_sb_info, &LM_TXQ(pdev, cid).hw_con_idx_ptr);
        LM_TXQ(pdev, cid).pkt_idx = 0;
    }

    if(GET_FLAGS(pdev->params.l2_cli_con_params[cid].attributes,LM_CLIENT_ATTRIBUTES_RX))
    {
        if (cid >= MAX_RX_CHAIN(pdev))
        {
            DbgBreakMsg(" Invalid RX chain index ");
            return LM_STATUS_INVALID_PARAMETER;
        }
        lm_clear_chain_sb_cons_idx(pdev, sb_id, &LM_RCQ(pdev, cid).hc_sb_info, &LM_RCQ(pdev, cid).hw_con_idx_ptr);
    }
    //s_list_init(&LM_RXQ(pdev, cid).active_descq, NULL, NULL, 0);
    //s_list_init(&LM_RXQ(pdev, cid).free_descq, NULL, NULL, 0);

    return LM_STATUS_SUCCESS;
}

lm_status_t
lm_alloc_chain_con_resc(
    IN struct _lm_device_t *pdev,
    IN u32_t        const   cid,
    IN lm_cli_idx_t const   lm_cli_idx
    )
{
    lm_status_t  lm_status = LM_STATUS_SUCCESS;
    u16_t   l2_rx_bd_page_cnt = 0;
    u16_t l2_tpa_bd_page_cnt = 0;
    u16_t bds_per_page = 0;

    if CHK_NULL(pdev)
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    if((GET_FLAGS(pdev->params.l2_cli_con_params[cid].attributes,LM_CLIENT_ATTRIBUTES_RX) &&
       (cid >= MAX_RX_CHAIN(pdev))) ||
        (GET_FLAGS(pdev->params.l2_cli_con_params[cid].attributes,LM_CLIENT_ATTRIBUTES_TX) &&
       (cid >= MAX_TX_CHAIN(pdev))))

    {
        DbgBreakMsg(" invalid chain ");
        return LM_STATUS_INVALID_PARAMETER;
    }

    if(GET_FLAGS(pdev->params.l2_cli_con_params[cid].attributes,LM_CLIENT_ATTRIBUTES_TX))
    {
        lm_status = lm_alloc_txq(pdev,
                                 cid,
                                 (u16_t)pdev->params.l2_tx_bd_page_cnt[lm_cli_idx],
                                 (u16_t)pdev->params.l2_tx_coal_buf_cnt[lm_cli_idx]);
        if (lm_status != LM_STATUS_SUCCESS)
        {
            return lm_status;
        }
    }

    if(GET_FLAGS(pdev->params.l2_cli_con_params[cid].attributes,LM_CLIENT_ATTRIBUTES_RX))
    {
        l2_rx_bd_page_cnt =_ceil( pdev->params.l2_cli_con_params[cid].num_rx_desc, 500 );
        lm_status = lm_alloc_rxq(pdev,
                                 cid,
                                 l2_rx_bd_page_cnt,
                                 pdev->params.l2_cli_con_params[cid].num_rx_desc);

        if (lm_status != LM_STATUS_SUCCESS)
        {
            return lm_status;
        }

        lm_status = lm_alloc_rcq(pdev,
                                 cid,
                                 (u16_t)l2_rx_bd_page_cnt * LM_RX_BD_CQ_SIZE_RATIO);
        if (lm_status != LM_STATUS_SUCCESS)
        {
            return lm_status;
        }
    }

    if(GET_FLAGS(pdev->params.l2_cli_con_params[cid].attributes,LM_CLIENT_ATTRIBUTES_TPA))
    {
        bds_per_page = BD_PER_PAGE(LM_TPA_BD_ELEN_SIZE);

        if ((0 == pdev->params.tpa_desc_cnt_per_chain) ||
            (!(POWER_OF_2(bds_per_page))))
        {
            DbgBreakMsg(" Illegal TPA params");
            return LM_STATUS_FAILURE;
        }
        l2_tpa_bd_page_cnt =_ceil( pdev->params.tpa_desc_cnt_per_chain,
                                  USABLE_BDS_PER_PAGE(LM_TPA_BD_ELEN_SIZE, TRUE));

        l2_tpa_bd_page_cnt = (u16_t)
            upper_align_power_of_2(l2_tpa_bd_page_cnt,
                                   sizeof(l2_tpa_bd_page_cnt) * BITS_PER_BYTE);

        lm_status = lm_alloc_tpa_chain(pdev,
                                       cid,
                                       l2_tpa_bd_page_cnt,
                                       pdev->params.tpa_desc_cnt_per_chain,
                                       bds_per_page);

        if (lm_status != LM_STATUS_SUCCESS)
        {
            return lm_status;
        }
    }
    return LM_STATUS_SUCCESS;
}

lm_status_t
lm_setup_client_con_params( IN struct _lm_device_t            *pdev,
                            IN u8_t const                      chain_idx,
                            IN struct _lm_client_con_params_t *cli_params )
{
    lm_rx_chain_t* rxq_chain = NULL;

    if (CHK_NULL(pdev) ||
        CHK_NULL(cli_params) ||
        ERR_IF((ARRSIZE(pdev->params.l2_cli_con_params) <= chain_idx) ||
               (CHIP_IS_E1H(pdev) && (chain_idx >= ETH_MAX_RX_CLIENTS_E1H)) || /* TODO E2 add IS_E2*/
               (CHIP_IS_E1(pdev) && (chain_idx >= ETH_MAX_RX_CLIENTS_E1)) ))
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    mm_memcpy(&pdev->params.l2_cli_con_params[chain_idx], cli_params, sizeof(struct _lm_client_con_params_t));


    if(GET_FLAGS(pdev->params.l2_cli_con_params[chain_idx].attributes,
                 LM_CLIENT_ATTRIBUTES_RX))
    {
        // update rxq_chain strucutre
        rxq_chain           = &LM_RXQ(pdev, chain_idx);
        rxq_chain->lah_size = pdev->params.l2_cli_con_params[chain_idx].lah_size;
    }

    return LM_STATUS_SUCCESS;
}

lm_status_t
lm_init_chain_con( IN struct _lm_device_t *pdev,
                    IN u8_t const          chain_idx,
                    IN u8_t const          b_alloc )
{
    lm_status_t  lm_status  = LM_STATUS_SUCCESS;
    u8_t         lm_cli_idx = LM_CHAIN_IDX_CLI(pdev, chain_idx); // FIXME!!!

    if (CHK_NULL(pdev) ||
        (LM_CLI_IDX_MAX <= lm_cli_idx))
    {
        DbgBreakMsg(" lm_init_client_con lm_cli_idx has an invalid value");
        return LM_STATUS_INVALID_PARAMETER;
    }

    if (b_alloc)
    {
        lm_status = lm_alloc_chain_con_resc(pdev, chain_idx, lm_cli_idx);

        if (lm_status != LM_STATUS_SUCCESS)
        {
            return lm_status;
        }

        if(GET_FLAGS(pdev->params.l2_cli_con_params[chain_idx].attributes,LM_CLIENT_ATTRIBUTES_RX))
        {
            /* On allocation, init the clients objects... do this only on allocation, on setup, we'll need
             * the info to reconfigure... */
            ecore_init_mac_obj(pdev,
                           &pdev->client_info[chain_idx].mac_obj,
                           LM_FW_CLI_ID(pdev, chain_idx),
                           chain_idx,
                           FUNC_ID(pdev),
                           LM_SLOWPATH(pdev, mac_rdata)[lm_cli_idx],
                           LM_SLOWPATH_PHYS(pdev, mac_rdata)[lm_cli_idx],
                           ECORE_FILTER_MAC_PENDING,
                           (unsigned long *)&pdev->client_info[chain_idx].sp_mac_state,
                           ECORE_OBJ_TYPE_RX_TX,
                           &pdev->slowpath_info.macs_pool);


            if (!CHIP_IS_E1(pdev))
            {
                ecore_init_vlan_mac_obj(pdev,
                                   &pdev->client_info[chain_idx].mac_vlan_obj,
                                   LM_FW_CLI_ID(pdev, chain_idx),
                                   chain_idx,
                                   FUNC_ID(pdev),
                                   LM_SLOWPATH(pdev, mac_rdata)[lm_cli_idx],
                                   LM_SLOWPATH_PHYS(pdev, mac_rdata)[lm_cli_idx],
                                   ECORE_FILTER_VLAN_MAC_PENDING,
                                   (unsigned long *)&pdev->client_info[chain_idx].sp_mac_state,
                                   ECORE_OBJ_TYPE_RX_TX,
                                   &pdev->slowpath_info.macs_pool,
                                   &pdev->slowpath_info.vlans_pool);

            }

            if (!CHIP_IS_E1x(pdev))
            {
                ecore_init_vlan_obj(pdev,
                                    &pdev->client_info[chain_idx].vlan_obj,
                                    LM_FW_CLI_ID(pdev, chain_idx),
                                    chain_idx,
                                    FUNC_ID(pdev),
                                    LM_SLOWPATH(pdev, mac_rdata)[lm_cli_idx],
                                    LM_SLOWPATH_PHYS(pdev, mac_rdata)[lm_cli_idx],
                                    ECORE_FILTER_VLAN_PENDING,
                                    (unsigned long *)&pdev->client_info[chain_idx].sp_mac_state,
                                    ECORE_OBJ_TYPE_RX_TX,
                                    &pdev->slowpath_info.vlans_pool);
            }
        }
    }


    lm_status = lm_setup_client_con_resc(pdev, chain_idx);

    return lm_status;
}

lm_status_t lm_alloc_sq(struct _lm_device_t *pdev)
{
    lm_sq_info_t * sq_info = &pdev->sq_info;

    sq_info->sq_chain.sq_chain_virt = mm_alloc_phys_mem( pdev,
                                                         LM_PAGE_SIZE,
                                                         (lm_address_t*)&(sq_info->sq_chain.bd_chain_phy),
                                                         0,
                                                         LM_CLI_IDX_MAX);

    if CHK_NULL(sq_info->sq_chain.sq_chain_virt)
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return LM_STATUS_RESOURCE ;
    }

    mm_mem_zero(sq_info->sq_chain.sq_chain_virt, LM_PAGE_SIZE);

    return LM_STATUS_SUCCESS;
}

lm_status_t lm_alloc_eq(struct _lm_device_t *pdev)
{
    lm_eq_chain_t *eq_chain = NULL;
    u32_t          mem_size = 0;
    u8_t  const    page_cnt = 1;


    /* check arguments */
    if(CHK_NULL(pdev))
    {
        return LM_STATUS_FAILURE;
    }

    DbgMessage(pdev, INFORMi | INFORMl2sp, "#lm_alloc_eq\n");

    mem_size = page_cnt * LM_PAGE_SIZE;
    eq_chain = &pdev->eq_info.eq_chain;


    /* alloc the chain */
    eq_chain->bd_chain.bd_chain_virt =
        mm_alloc_phys_mem( pdev, mem_size, &eq_chain->bd_chain.bd_chain_phy, 0, LM_CLI_IDX_MAX);

    if(ERR_IF(!eq_chain->bd_chain.bd_chain_virt))
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return LM_STATUS_RESOURCE;
    }

    mm_mem_zero(eq_chain->bd_chain.bd_chain_virt, mem_size);
    eq_chain->bd_chain.page_cnt = page_cnt;

    return LM_STATUS_SUCCESS;

}

lm_status_t lm_alloc_client_info(struct _lm_device_t *pdev)
{
    client_init_data_t  *client_init_data_virt                  = NULL;
    const u32_t mem_size_init                                   = sizeof(client_init_data_t);
    struct client_update_ramrod_data  *client_update_data_virt  = NULL;
    const u32_t mem_size_update                                 = sizeof(struct client_update_ramrod_data);
    u8_t i                                                      = 0;

    for (i = 0; i < ARRSIZE(pdev->client_info); i++)
    {
        //Init data
        client_init_data_virt = mm_alloc_phys_mem(pdev, mem_size_init, &pdev->client_info[i].client_init_data_phys, 0, LM_RESOURCE_COMMON);
        if CHK_NULL(client_init_data_virt)
        {
            DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
            return LM_STATUS_RESOURCE ;
        }

        mm_mem_zero(client_init_data_virt, mem_size_init);

        pdev->client_info[i].client_init_data_virt = client_init_data_virt;

        //update data
        client_update_data_virt = mm_alloc_phys_mem(pdev, mem_size_update, &pdev->client_info[i].update.data_phys, 0, LM_RESOURCE_COMMON);
        if CHK_NULL(client_update_data_virt)
        {
            DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
            return LM_STATUS_RESOURCE ;
        }

        mm_mem_zero(client_update_data_virt, mem_size_update);

        pdev->client_info[i].update.data_virt = client_update_data_virt;
    }

    return LM_STATUS_SUCCESS;
}

lm_status_t lm_setup_client_info(struct _lm_device_t *pdev)
{
    client_init_data_t  *client_init_data_virt                  = NULL;
    const u32_t mem_size_init                                   = sizeof(client_init_data_t);
    struct client_update_ramrod_data  *client_update_data_virt  = NULL;
    const u32_t mem_size_update                                 = sizeof(struct client_update_ramrod_data);
    u8_t i                                                      = 0;

    for (i = 0; i < ARRSIZE(pdev->client_info); i++)
    {
        //Init
        client_init_data_virt = pdev->client_info[i].client_init_data_virt;
        if CHK_NULL(client_init_data_virt)
        {
            DbgMessage(pdev, FATAL, "client-init-data at this point is not expected to be null... \n");
            return LM_STATUS_FAILURE ;
        }
        mm_mem_zero(client_init_data_virt, mem_size_init);

        //update
        client_update_data_virt = pdev->client_info[i].update.data_virt;
        if CHK_NULL(client_update_data_virt)
        {
            DbgMessage(pdev, FATAL, "client-update-data at this point is not expected to be null... \n");
            return LM_STATUS_FAILURE ;
        }
        mm_mem_zero(client_update_data_virt, mem_size_update);
    }

    return LM_STATUS_SUCCESS;
}

/**
 * @description
 * The next page entrys are static and wont be used by active
 * descriptor array and mask array.
 * @param pdev
 * @param chain_idx
 *
 * @return STATIC void
 */
__inline STATIC void
lm_tpa_clear_next_page( IN        lm_device_t*        pdev,
                        IN const  u32_t               chain_idx)
{
    lm_bd_chain_t*      bd_chain        = &LM_TPA_CHAIN_BD(pdev, chain_idx);
    u16_t               active_entry    = 0;
    u16_t               bd_entry        = 0;
    u16_t               i               = 0;
    u16_t               j               = 0;

    for(i = 1; i <= lm_bd_chain_page_cnt(bd_chain); i++ )
    {
        bd_entry = (lm_bd_chain_bds_per_page(bd_chain) * i) - lm_bd_chain_bds_skip_eop(bd_chain);
        /* clear page-end entries */
        for(j = 0; j < lm_bd_chain_bds_skip_eop(bd_chain); j++ )
        {
            active_entry = LM_TPA_BD_ENTRY_TO_ACTIVE_ENTRY(pdev, chain_idx, bd_entry);
            LM_TPA_MASK_CLEAR_ACTIVE_BIT(pdev, chain_idx, active_entry);
            bd_entry++;
        }
    }
}

/**
 * @description
 * Clear TPA parameters. TPA can be disabled between NDIS bind
 * unbind but the RX cahin will stay used.
 * @param pdev
 * @param cid
 */
lm_status_t
lm_tpa_chain_reset(IN lm_device_t   *pdev,
                   IN const u32_t   cid)
{

    lm_tpa_chain_t *    tpa_chain          = NULL;

    /* check arguments */
    if(CHK_NULL(pdev) ||
       ERR_IF((ARRSIZE(pdev->rx_info.rxq_chain) <= cid)))
    {
        return LM_STATUS_FAILURE;
    }

    DbgMessage(pdev, INFORMi|INFORMl2sp, "#lm_setup_tpa, cid=%d\n",cid);

    tpa_chain = &LM_TPA(pdev, cid);
    /***************** SGE chain setup *************************************/
    mm_mem_zero(tpa_chain,sizeof(lm_tpa_chain_t));

    return LM_STATUS_SUCCESS;
}
/**
 * @description
 *
 * @param pdev
 * @param cid
 *
 * @return lm_status_t
 */
lm_status_t lm_setup_tpa_chain( IN struct _lm_device_t *pdev,
                                IN u32_t const          cid)
{
    lm_bd_chain_t *     bd_chain            = NULL;
    lm_tpa_chain_t *    tpa_chain           = NULL;
    u16_t                i                  = 0;

    /* check arguments */
    if(CHK_NULL(pdev) ||
       ERR_IF((ARRSIZE(pdev->rx_info.rxq_chain) <= cid)))
    {
        return LM_STATUS_FAILURE;
    }

    DbgMessage(pdev, INFORMi|INFORMl2sp, "#lm_setup_tpa, cid=%d\n",cid);

    tpa_chain = &LM_TPA(pdev, cid);
    bd_chain = &LM_TPA_CHAIN_BD( pdev, cid );


    /***************** TPA chain setup ************************************/
    for(i = 0; i < ARRSIZE(tpa_chain->start_coales_bd) ; i++)
    {
        tpa_chain->start_coales_bd[i].is_entry_used = FALSE;
        tpa_chain->start_coales_bd[i].packet = NULL;
    }

    /***************** SGE common setup ************************************/
    tpa_chain->common.prod_bseq                 = 0;
    tpa_chain->common.bd_prod_without_next      = 0;

    /***************** SGE chain setup *************************************/
    lm_bd_chain_setup(pdev, bd_chain, bd_chain->bd_chain_virt, bd_chain->bd_chain_phy,bd_chain->page_cnt, LM_TPA_BD_ELEN_SIZE, /* is full? */0, TRUE);

    DbgMessage(pdev, INFORMi, "rxq[%d] bd_chain[%d] %p, bd_left %d\n", cid,
                                                                        bd_chain->next_bd,
                                                                        bd_chain->bd_left);

    DbgMessage(pdev, INFORMi, "   bd_chain_phy[%d] 0x%x%08x\n", bd_chain->bd_chain_phy.as_u32.high,
                                                                 bd_chain->bd_chain_phy.as_u32.low);
    tpa_chain->sge_chain.last_max_con = 0;

    for(i = 0; i < LM_TPA_ACTIVE_DESCQ_ARRAY_ELEM(pdev, cid) ; i++)
    {
        tpa_chain->sge_chain.active_descq_array[i] = NULL;
    }

    /***************** Mask entry prepare *************************************/
    ASSERT_STATIC(0 != BIT_VEC64_ELEM_SZ); //LM_TPA_MASK_LEN - divide by BIT_VEC64_ELEM_SZ
    for(i = 0; i < LM_TPA_MASK_LEN(pdev, cid) ; i++)
    {
        tpa_chain->sge_chain.mask_array[i] = BIT_VEC64_ELEM_ONE_MASK;
    }

    lm_tpa_clear_next_page(pdev,
                           cid);

    return LM_STATUS_SUCCESS;
} /* lm_setup_tpa */

lm_status_t lm_setup_sq(struct _lm_device_t *pdev)
{
    lm_sq_info_t * sq_info = &pdev->sq_info;

    mm_mem_zero(sq_info->sq_chain.sq_chain_virt, LM_PAGE_SIZE);

    pdev->sq_info.num_pending_normal = MAX_NORMAL_PRIORITY_SPE;
    pdev->sq_info.num_pending_high = MAX_HIGH_PRIORITY_SPE;

    d_list_init(&pdev->sq_info.pending_normal, 0,0,0);
    d_list_init(&pdev->sq_info.pending_high, 0,0,0);
    d_list_init(&pdev->sq_info.pending_complete, 0,0,0);


    /* The spq dont have next bd */
    pdev->sq_info.sq_chain.bd_left =  USABLE_BDS_PER_PAGE(sizeof(struct slow_path_element), TRUE); /* prod == cons means empty chain */
    pdev->sq_info.sq_chain.con_idx = 0;

    pdev->sq_info.sq_chain.prod_bd = pdev->sq_info.sq_chain.sq_chain_virt;
    pdev->sq_info.sq_chain.last_bd = pdev->sq_info.sq_chain.prod_bd + pdev->sq_info.sq_chain.bd_left ;
    pdev->sq_info.sq_chain.prod_idx = 0;

    return LM_STATUS_SUCCESS;

}

lm_status_t lm_setup_eq(struct _lm_device_t *pdev)
{
    lm_bd_chain_t * bd_chain = NULL;
    lm_eq_chain_t * eq_chain = NULL;
    volatile struct hc_sp_status_block * sp_sb = NULL;


    /* check arguments */
    if(CHK_NULL(pdev))
    {
        return LM_STATUS_FAILURE;
    }

    DbgMessage(pdev, INFORMeq, "#lm_setup_eq\n");

    eq_chain = &pdev->eq_info.eq_chain;
    bd_chain = &eq_chain->bd_chain;

    lm_bd_chain_setup(pdev, bd_chain, bd_chain->bd_chain_virt, bd_chain->bd_chain_phy, bd_chain->page_cnt, sizeof(union event_ring_elem), /* is full? */TRUE, TRUE);

    sp_sb = lm_get_default_status_block(pdev);

    sp_sb->index_values[HC_SP_INDEX_EQ_CONS] = 0;

    eq_chain->hw_con_idx_ptr = &sp_sb->index_values[HC_SP_INDEX_EQ_CONS];
    eq_chain->hc_sb_info.hc_sb = STATUS_BLOCK_NORMAL_SL_TYPE;
    eq_chain->hc_sb_info.hc_index_value = HC_SP_INDEX_EQ_CONS;
    eq_chain->iro_prod_offset = CSTORM_EVENT_RING_PROD_OFFSET(FUNC_ID(pdev));

    return LM_STATUS_SUCCESS;
}

lm_status_t lm_init_sp_objs(struct _lm_device_t *pdev)
{
    u32_t lm_cli_idx = LM_CLI_IDX_MAX;

    ecore_init_mac_credit_pool(pdev, &pdev->slowpath_info.macs_pool, FUNC_ID(pdev), CHIP_IS_E1x(pdev)? VNICS_PER_PORT(pdev) : VNICS_PER_PATH(pdev));
    ecore_init_vlan_credit_pool(pdev, &pdev->slowpath_info.vlans_pool, FUNC_ID(pdev), CHIP_IS_E1x(pdev)? VNICS_PER_PORT(pdev) : VNICS_PER_PATH(pdev));
    ecore_init_rx_mode_obj(pdev, &pdev->slowpath_info.rx_mode_obj);

    for (lm_cli_idx=0; lm_cli_idx < ARRSIZE(pdev->slowpath_info.mcast_obj); lm_cli_idx++)
    {
        ecore_init_mcast_obj(pdev,
                             &pdev->slowpath_info.mcast_obj[lm_cli_idx],
                             LM_FW_CLI_ID(pdev, pdev->params.map_client_to_cid[lm_cli_idx]),
                             pdev->params.map_client_to_cid[lm_cli_idx],
                             FUNC_ID(pdev),
                             FUNC_ID(pdev),
                             LM_SLOWPATH(pdev, mcast_rdata)[lm_cli_idx],
                             LM_SLOWPATH_PHYS(pdev, mcast_rdata)[lm_cli_idx],
                             ECORE_FILTER_MCAST_PENDING,
                             (unsigned long *)&pdev->slowpath_info.sp_mcast_state[lm_cli_idx],
                             ECORE_OBJ_TYPE_RX_TX);
    }

    ecore_init_rss_config_obj(pdev,
                              &pdev->slowpath_info.rss_conf_obj,
                              LM_FW_CLI_ID(pdev, LM_SW_LEADING_RSS_CID(pdev)),
                              LM_SW_LEADING_RSS_CID(pdev),
                              FUNC_ID(pdev),
                              FUNC_ID(pdev),
                              LM_SLOWPATH(pdev, rss_rdata),
                              LM_SLOWPATH_PHYS(pdev, rss_rdata),
                              ECORE_FILTER_RSS_CONF_PENDING,
                              (unsigned long *)&pdev->slowpath_info.sp_rss_state,
                              ECORE_OBJ_TYPE_RX);

    return LM_STATUS_SUCCESS;
}

/**
 * Description:
 *   allocate slowpath resources
 */
static lm_status_t
lm_alloc_setup_slowpath_resc(struct _lm_device_t *pdev , u8_t b_alloc)
{
    lm_slowpath_data_t *slowpath_data = &pdev->slowpath_info.slowpath_data;
    u8_t                i             = 0;

    ASSERT_STATIC(ARRSIZE(slowpath_data->mac_rdata) == ARRSIZE(slowpath_data->rx_mode_rdata));
    ASSERT_STATIC(ARRSIZE(slowpath_data->mac_rdata) == ARRSIZE(slowpath_data->mcast_rdata));

    for (i = 0; i < ARRSIZE(slowpath_data->mac_rdata); i++ )
    {
        if (b_alloc)
    {
            slowpath_data->mac_rdata[i] =
                mm_alloc_phys_mem(pdev,
                                  sizeof(*slowpath_data->mac_rdata[i]),
                                  &slowpath_data->mac_rdata_phys[i],
                                  0,
                                  LM_RESOURCE_COMMON);

            slowpath_data->rx_mode_rdata[i] =
                mm_alloc_phys_mem(pdev,
                                  sizeof(*slowpath_data->rx_mode_rdata[i]),
                                  &slowpath_data->rx_mode_rdata_phys[i],
                                  0,
                                  LM_RESOURCE_COMMON);

            slowpath_data->mcast_rdata[i] =
                mm_alloc_phys_mem(pdev,
                                  sizeof(*slowpath_data->mcast_rdata[i]),
                                  &slowpath_data->mcast_rdata_phys[i],
                                  0,
                                  LM_RESOURCE_COMMON);


    }

        if (CHK_NULL(slowpath_data->mac_rdata[i]) ||
            CHK_NULL(slowpath_data->rx_mode_rdata[i]) ||
            CHK_NULL(slowpath_data->mcast_rdata[i]))

        {
            DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
            return LM_STATUS_RESOURCE ;
        }

        mm_mem_zero(slowpath_data->mac_rdata[i], sizeof(*slowpath_data->mac_rdata[i]));
        mm_mem_zero(slowpath_data->rx_mode_rdata[i], sizeof(*slowpath_data->rx_mode_rdata[i]));
        mm_mem_zero(slowpath_data->mcast_rdata[i], sizeof(*slowpath_data->mcast_rdata[i]));
    }

    if (b_alloc)
    {
        slowpath_data->rss_rdata  = mm_alloc_phys_mem(pdev, sizeof(*slowpath_data->rss_rdata), &slowpath_data->rss_rdata_phys, 0, LM_RESOURCE_COMMON);
    }

    if CHK_NULL(slowpath_data->rss_rdata)
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return LM_STATUS_RESOURCE ;
    }

    mm_mem_zero(slowpath_data->rss_rdata, sizeof(*slowpath_data->rss_rdata));

    if (b_alloc)
    {
        slowpath_data->func_start_data  = mm_alloc_phys_mem(pdev, sizeof(*slowpath_data->func_start_data), &slowpath_data->func_start_data_phys, 0, LM_RESOURCE_COMMON);
    }

    if CHK_NULL(slowpath_data->func_start_data)
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return LM_STATUS_RESOURCE ;
    }

    mm_mem_zero(slowpath_data->func_start_data, sizeof(*slowpath_data->func_start_data));

    if (b_alloc)
    {
        slowpath_data->niv_function_update_data = mm_alloc_phys_mem(pdev, sizeof(*slowpath_data->niv_function_update_data), &slowpath_data->niv_function_update_data_phys, 0, LM_RESOURCE_COMMON);
    }
    if CHK_NULL(slowpath_data->niv_function_update_data)
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return LM_STATUS_RESOURCE ;
    }
    mm_mem_zero(slowpath_data->niv_function_update_data, sizeof(*slowpath_data->niv_function_update_data));

    if (b_alloc)
    {
        slowpath_data->l2mp_func_update_data = mm_alloc_phys_mem(pdev, sizeof(*slowpath_data->l2mp_func_update_data), &slowpath_data->l2mp_func_update_data_phys, 0, LM_RESOURCE_COMMON);
    }
    if CHK_NULL(slowpath_data->l2mp_func_update_data)
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return LM_STATUS_RESOURCE ;
    }
    mm_mem_zero(slowpath_data->l2mp_func_update_data, sizeof(*slowpath_data->l2mp_func_update_data));

    if (b_alloc)
    {
        slowpath_data->encap_function_update_data = mm_alloc_phys_mem(pdev, sizeof(*slowpath_data->encap_function_update_data), &slowpath_data->encap_function_update_data_phys, 0, LM_RESOURCE_COMMON);
    }
    if CHK_NULL(slowpath_data->encap_function_update_data)
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return LM_STATUS_RESOURCE ;
    }
    mm_mem_zero(slowpath_data->encap_function_update_data, sizeof(*slowpath_data->encap_function_update_data));

    if (b_alloc)
    {
        slowpath_data->ufp_function_update_data = mm_alloc_phys_mem(pdev, sizeof(*slowpath_data->ufp_function_update_data), &slowpath_data->ufp_function_update_data_phys, 0, LM_RESOURCE_COMMON);
    }
    if CHK_NULL(slowpath_data->ufp_function_update_data)
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return LM_STATUS_RESOURCE ;
    }
    mm_mem_zero(slowpath_data->ufp_function_update_data, sizeof(*slowpath_data->ufp_function_update_data));

    pdev->slowpath_info.niv_ramrod_state                              = NIV_RAMROD_NOT_POSTED;
    pdev->slowpath_info.l2mp_func_update_ramrod_state                 = L2MP_FUNC_UPDATE_RAMROD_NOT_POSTED;
    pdev->slowpath_info.ufp_func_ramrod_state                         = UFP_RAMROD_NOT_POSTED;

    return LM_STATUS_SUCCESS ;
}


static void * lm_setup_allocate_ilt_client_page( struct _lm_device_t *pdev,
    lm_address_t        *phys_mem,
                                                 u8_t const          cli_idx )
{
    void* ilt_client_page_virt_address = NULL;

    if (!CHIP_IS_E1(pdev))
    {
        ilt_client_page_virt_address = mm_alloc_phys_mem_align( pdev,
                                                                   pdev->params.ilt_client_page_size,
                                                                   phys_mem,
                                                                   LM_ILT_ALIGNMENT,
                                                                   0,
                                                                   cli_idx);
    }
    else
    {
        ilt_client_page_virt_address = mm_alloc_phys_mem_align(pdev,
                                                                   pdev->params.ilt_client_page_size,
                                                                   phys_mem,
                                                                   pdev->params.ilt_client_page_size,
                                                                   0,
                                                                   cli_idx);
    }

    return ilt_client_page_virt_address;
}

/* Description:
*    This routine contain common code for alloc/setup distinguish by flag
*/
lm_status_t lm_common_setup_alloc_resc(struct _lm_device_t *pdev, u8_t const b_is_alloc )
{
    lm_params_t*    params     = NULL ;
    lm_variables_t* vars       = NULL ;
//    lm_sq_info_t*   sq_info    = NULL ;
    lm_status_t     lm_status;
    u32_t           alloc_size = 0 ;
    u32_t           alloc_num  = 0 ;
    u32_t           i          = 0 ;
    u32_t           mem_size   = 0 ;
    u8_t            sb_id      = 0 ;
    u8_t            mm_cli_idx = 0 ;
    lm_address_t    sb_phy_address;

    if CHK_NULL( pdev )
    {
        return LM_STATUS_INVALID_PARAMETER ;
    }

    DbgMessage(pdev, INFORMi , "### lm_common_setup_alloc_resc b_is_alloc=%s\n", b_is_alloc ? "TRUE" : "FALSE" );

    params     = &pdev->params ;
    vars       = &(pdev->vars) ;

    //       Status blocks allocation. We allocate mem both for the default and non-default status blocks
    //       there is 1 def sb and 16 non-def sb per port.
    //       non-default sb: index 0-15, default sb: index 16.
    if (CHIP_IS_E1x(pdev))
    {
        mem_size = E1X_STATUS_BLOCK_BUFFER_SIZE;
    }
    else
    {
        mem_size = E2_STATUS_BLOCK_BUFFER_SIZE;
    }

    mm_cli_idx = LM_RESOURCE_COMMON;//!!DP mm_cli_idx_to_um_idx(LM_CLI_IDX_MAX);

    LM_FOREACH_SB_ID(pdev, sb_id)
    {
        if( b_is_alloc )
        {
            vars->status_blocks_arr[sb_id].host_hc_status_block.e1x_sb = mm_alloc_phys_mem(pdev, mem_size, &sb_phy_address, 0, mm_cli_idx);
            if (CHIP_IS_E1x(pdev))
            {
                vars->status_blocks_arr[sb_id].hc_status_block_data.e1x_sb_data.common.host_sb_addr.lo = sb_phy_address.as_u32.low;
                vars->status_blocks_arr[sb_id].hc_status_block_data.e1x_sb_data.common.host_sb_addr.hi = sb_phy_address.as_u32.high;
            }
            else
            {
                vars->status_blocks_arr[sb_id].hc_status_block_data.e2_sb_data.common.host_sb_addr.lo = sb_phy_address.as_u32.low;
                vars->status_blocks_arr[sb_id].hc_status_block_data.e2_sb_data.common.host_sb_addr.hi = sb_phy_address.as_u32.high;
            }
        }
        if CHK_NULL(vars->status_blocks_arr[sb_id].host_hc_status_block.e1x_sb)
        {
            DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
            return LM_STATUS_RESOURCE ;
        }
        mm_mem_zero((void *)(vars->status_blocks_arr[sb_id].host_hc_status_block.e1x_sb), mem_size);
    }

    mem_size = DEF_STATUS_BLOCK_BUFFER_SIZE;


    if( b_is_alloc )
    {
        vars->gen_sp_status_block.hc_sp_status_blk = mm_alloc_phys_mem(pdev,
                                                    mem_size,
                                                    &(vars->gen_sp_status_block.blk_phy_address),
                                                    0,
                                                    mm_cli_idx);
    }

    if CHK_NULL(vars->gen_sp_status_block.hc_sp_status_blk)
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return LM_STATUS_RESOURCE ;
    }

    mm_mem_zero((void *)(vars->gen_sp_status_block.hc_sp_status_blk), mem_size);

    /* Now reset the status-block ack values back to zero. */
    lm_reset_sb_ack_values(pdev);

    mm_mem_zero(pdev->debug_info.ack_dis,     sizeof(pdev->debug_info.ack_dis));
    mm_mem_zero(pdev->debug_info.ack_en,      sizeof(pdev->debug_info.ack_en));
    pdev->debug_info.ack_def_dis = pdev->debug_info.ack_def_en = 0;
    mm_mem_zero(pdev->debug_info.rx_only_int, sizeof(pdev->debug_info.rx_only_int));
    mm_mem_zero(pdev->debug_info.tx_only_int, sizeof(pdev->debug_info.tx_only_int));
    mm_mem_zero(pdev->debug_info.both_int,    sizeof(pdev->debug_info.both_int));
    mm_mem_zero(pdev->debug_info.empty_int,   sizeof(pdev->debug_info.empty_int));
    mm_mem_zero(pdev->debug_info.false_int,   sizeof(pdev->debug_info.false_int));

    /* Register common and ethernet connection types completion callback. */
    lm_sq_comp_cb_register(pdev, ETH_CONNECTION_TYPE, lm_eth_comp_cb);
    lm_sq_comp_cb_register(pdev, NONE_CONNECTION_TYPE, lm_eq_comp_cb);

    /* SlowPath Info */
    lm_status = lm_alloc_setup_slowpath_resc(pdev, b_is_alloc);
    if (lm_status != LM_STATUS_SUCCESS)
    {
        DbgMessage(pdev, FATAL, "lm_alloc_client_info failed lm-status = %d\n", lm_status);
        return lm_status;
    }


    /* Client Info */
    if( b_is_alloc )
    {
        lm_status = lm_alloc_client_info(pdev);
        if (lm_status != LM_STATUS_SUCCESS)
        {
            DbgMessage(pdev, FATAL, "lm_alloc_client_info failed lm-status = %d\n", lm_status);
            return lm_status;
        }
    }

    lm_status = lm_setup_client_info(pdev);
    if (lm_status != LM_STATUS_SUCCESS)
    {
        DbgMessage(pdev, FATAL, "lm_setup_client_info failed lm-status = %d\n", lm_status);
        return lm_status;
    }

    //  Context (roundup ( MAX_CONN / CONN_PER_PAGE) We may configure the CDU to have more than max_func_connections, specifically, we will
    // configure the CDU to have max_port_connections since it is a per-port register and not per-func, but it is OK to allocate
    // less for the cdu, and allocate only what will be used in practice - which is what is configured in max_func_connectinos.
    alloc_num = vars->context_cdu_num_pages = (params->max_func_connections / params->num_context_in_page) +
        ((params->max_func_connections % params->num_context_in_page)? 1:0);

    //TODO: optimize the roundup
    //TODO: assert that we did not go over the limit

    // allocate buffer pointers
    if( b_is_alloc )
    {
        mem_size = alloc_num * sizeof(void *) ;
        vars->context_cdu_virt_addr_table = (void **) mm_alloc_mem( pdev, mem_size, mm_cli_idx );
    }
    if CHK_NULL( vars->context_cdu_virt_addr_table )
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return LM_STATUS_RESOURCE ;
    }
    else if ( b_is_alloc )
    {
        mm_mem_zero( vars->context_cdu_virt_addr_table, mem_size ) ;
    }

    if( b_is_alloc )
    {
        mem_size = alloc_num * sizeof(lm_address_t) ;
        vars->context_cdu_phys_addr_table = mm_alloc_mem(pdev, mem_size, mm_cli_idx );
    }

    if CHK_NULL( vars->context_cdu_phys_addr_table )
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return LM_STATUS_RESOURCE ;
    }
    else if ( b_is_alloc )
    {
        mm_mem_zero(vars->context_cdu_phys_addr_table, mem_size );
    }

    /* TBD: for starters, we'll just allocate each page seperatly, to save space in the future, we may want */
    for( i = 0  ;i < alloc_num; i++)
    {
        if( b_is_alloc )
        {
            vars->context_cdu_virt_addr_table[i] = lm_setup_allocate_ilt_client_page(pdev,
                                                                                     (lm_address_t*)&vars->context_cdu_phys_addr_table[i],
                                                         mm_cli_idx);
        }
        if CHK_NULL( vars->context_cdu_virt_addr_table[i] )
        {
            DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
            return LM_STATUS_RESOURCE ;
        }
        mm_mem_zero( vars->context_cdu_virt_addr_table[i], params->ilt_client_page_size ) ;
    }


    //  Searcher T1  (roundup to log2 of 64*MAX_CONN), T2 is 1/4 of T1. The searcher has a 'per-function' register we configure
    // with the number of max connections, therefore, we use the max_func_connections. It can be different per function and independent
    // from what we configure for qm/timers/cdu.
    alloc_size = (log2_align(max(params->max_func_connections,(u32_t)1000))*64);
    alloc_num = vars->searcher_t1_num_pages = max((alloc_size / params->ilt_client_page_size),(u32_t)1);
    mem_size = alloc_num * sizeof(void *) ;

    if( b_is_alloc )
    {
        vars->searcher_t1_virt_addr_table = (void **) mm_alloc_mem(pdev, mem_size, mm_cli_idx);
    }
    if CHK_NULL(vars->searcher_t1_virt_addr_table)
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return LM_STATUS_RESOURCE ;
    }
    else if ( b_is_alloc )
    {
        mm_mem_zero( vars->searcher_t1_virt_addr_table, mem_size ) ;
    }

    mem_size = alloc_num * sizeof(lm_address_t) ;

    if( b_is_alloc )
    {
        vars->searcher_t1_phys_addr_table = mm_alloc_mem(pdev, mem_size, mm_cli_idx );
    }
    if CHK_NULL(vars->searcher_t1_phys_addr_table)
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return LM_STATUS_RESOURCE ;
    }
    else if ( b_is_alloc )
    {
        mm_mem_zero( vars->searcher_t1_phys_addr_table, mem_size ) ;
    }

    for( i = 0  ; i < alloc_num; i++ )
    {
        if( b_is_alloc )
        {
            vars->searcher_t1_virt_addr_table[i] = lm_setup_allocate_ilt_client_page(pdev,
                                                         (lm_address_t*)&(vars->searcher_t1_phys_addr_table[i]),
                                                         mm_cli_idx);
        }
        if CHK_NULL( vars->searcher_t1_virt_addr_table[i] )
        {
            DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
            return LM_STATUS_RESOURCE ;
        }
        mm_mem_zero( vars->searcher_t1_virt_addr_table[i], params->ilt_client_page_size ) ;
    }

    // allocate searcher T2 table
    // T2 does not entered into the ILT)
    alloc_size = (params->max_func_connections + 4)*64;
    alloc_num = vars->searcher_t2_num_pages = alloc_size / params->ilt_client_page_size +
        ((alloc_size % params->ilt_client_page_size)? 1:0) ;
    mem_size = alloc_num * sizeof(void *) ;

    if ( b_is_alloc )
    {
        vars->searcher_t2_virt_addr_table = (void **) mm_alloc_mem(pdev, mem_size, mm_cli_idx) ;
    }
    if CHK_NULL(vars->searcher_t2_virt_addr_table)
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return LM_STATUS_RESOURCE ;
    }
    else if (b_is_alloc)
    {
        mm_mem_zero( vars->searcher_t2_virt_addr_table, mem_size ) ;
    }

    mem_size = alloc_num * sizeof(lm_address_t) ;
    if (b_is_alloc)
    {
        vars->searcher_t2_phys_addr_table = mm_alloc_mem(pdev, mem_size, mm_cli_idx );
    }
    if CHK_NULL(vars->searcher_t2_phys_addr_table)
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return LM_STATUS_RESOURCE ;
    }

    for( i = 0  ; i < alloc_num; i++)
    {
        if (b_is_alloc )
        {
            vars->searcher_t2_virt_addr_table[i] = lm_setup_allocate_ilt_client_page(pdev,
                                                         (lm_address_t*)&(vars->searcher_t2_phys_addr_table[i]),
                                                         mm_cli_idx);
        }
        if CHK_NULL(vars->searcher_t2_virt_addr_table[i])
        {
            DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
            return LM_STATUS_RESOURCE ;
        }
        mm_mem_zero( vars->searcher_t2_virt_addr_table[i],params->ilt_client_page_size ) ;
    }

    //  Timer block array (MAX_CONN*8) phys uncached. Timer block has a per-port register that defines it's size, and the amount of
    // memory we allocate MUST match this number, therefore we have to allocate the amount of max_port_connections.
    alloc_size = ( 8 * pdev->hw_info.max_port_conns);
    alloc_num = vars->timers_linear_num_pages = alloc_size / params->ilt_client_page_size +
        ((alloc_size % params->ilt_client_page_size)? 1:0) ;
    mem_size = alloc_num * sizeof(void *) ;

    if( b_is_alloc )
    {
        vars->timers_linear_virt_addr_table = (void **) mm_alloc_mem(pdev, mem_size, mm_cli_idx );
    }
    if CHK_NULL(vars->timers_linear_virt_addr_table)
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return LM_STATUS_RESOURCE ;
    }
    else if ( b_is_alloc )
    {
        mm_mem_zero( vars->timers_linear_virt_addr_table, mem_size ) ;
    }

    mem_size = alloc_num * sizeof(lm_address_t) ;

    if ( b_is_alloc )
    {
        vars->timers_linear_phys_addr_table = mm_alloc_mem(pdev, mem_size, mm_cli_idx );
    }
    if CHK_NULL(vars->timers_linear_phys_addr_table)
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return LM_STATUS_RESOURCE ;
    }
    else if ( b_is_alloc )
    {
        mm_mem_zero( vars->timers_linear_phys_addr_table, mem_size ) ;
    }

    for( i = 0  ;i < alloc_num; i++)
    {
        if( b_is_alloc )
        {
            vars->timers_linear_virt_addr_table[i] = lm_setup_allocate_ilt_client_page(pdev,
                                                           (lm_address_t*)&(vars->timers_linear_phys_addr_table[i]),
                                                           mm_cli_idx);
        }
        if CHK_NULL(vars->timers_linear_virt_addr_table[i])
        {
            DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
            return LM_STATUS_RESOURCE ;
        }
        mm_mem_zero( vars->timers_linear_virt_addr_table[i], params->ilt_client_page_size ) ;
    }

    //  QM queues (128*MAX_CONN) QM has a per-port register that defines it's size, and the amount of
    // memory we allocate MUST match this number, therefore we have to allocate the amount of max_port_connections.
    alloc_size = ( 128 * pdev->hw_info.max_common_conns);
    alloc_num = vars->qm_queues_num_pages = alloc_size / params->ilt_client_page_size +
        ((alloc_size % params->ilt_client_page_size)? 1:0) ;
    mem_size = alloc_num * sizeof(void *) ;

    if( b_is_alloc )
    {
        vars->qm_queues_virt_addr_table = (void **) mm_alloc_mem(pdev, mem_size, mm_cli_idx );
    }
    if CHK_NULL(vars->qm_queues_virt_addr_table)
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return LM_STATUS_RESOURCE ;
    }
    else if (b_is_alloc)
    {
        mm_mem_zero( vars->qm_queues_virt_addr_table, mem_size ) ;
    }

    mem_size = alloc_num * sizeof(lm_address_t) ;

    if( b_is_alloc )
    {
        vars->qm_queues_phys_addr_table = mm_alloc_mem(pdev, mem_size, mm_cli_idx );
    }
    if CHK_NULL(vars->qm_queues_phys_addr_table)
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return LM_STATUS_RESOURCE ;
    }
    else if (b_is_alloc)
    {
        mm_mem_zero( vars->qm_queues_phys_addr_table, mem_size ) ;
    }

    for( i=0  ;i < alloc_num; i++)
    {
        if (b_is_alloc)
        {
            vars->qm_queues_virt_addr_table[i] = lm_setup_allocate_ilt_client_page(pdev,
                                                       (lm_address_t*)&(vars->qm_queues_phys_addr_table[i]),
                                                       mm_cli_idx);
        }
        if CHK_NULL( vars->qm_queues_virt_addr_table[i] )
        {
            DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
            return LM_STATUS_RESOURCE ;
        }
        mm_mem_zero( vars->qm_queues_virt_addr_table[i],params->ilt_client_page_size ) ;
    }

    // common scratchpad buffer for dmae copies of less than 4 bytes
    if( b_is_alloc )
    {
        void *virt = mm_alloc_phys_mem(pdev,
                          8,
                          &params->dmae_copy_scratchpad_phys,
                          0,
                          mm_cli_idx);
        if CHK_NULL(virt)
        {
            DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
            return LM_STATUS_RESOURCE ;
        }
    }

    return LM_STATUS_SUCCESS ;
}

lm_status_t ecore_resc_alloc(struct _lm_device_t * pdev)
{
    pdev->ecore_info.gunzip_buf = mm_alloc_phys_mem(pdev, FW_BUF_SIZE, &pdev->ecore_info.gunzip_phys, PHYS_MEM_TYPE_NONCACHED, LM_RESOURCE_COMMON);
    if CHK_NULL(pdev->ecore_info.gunzip_buf)
    {
        return LM_STATUS_RESOURCE ;
    }
    return LM_STATUS_SUCCESS;
}

/**lm_dmae_resc_alloc
 * Allocate and initialize the TOE and default DMAE contexts.
 * The statistics DMAE context is set-up in lm_stats_alloc_resc.
 *
 * @param pdev the device to use.
 *
 * @return lm_status_t LM_STATUS_SUCCESS on success, some other
 *         failure code on failure.
 */
static lm_status_t lm_dmae_alloc_resc(struct _lm_device_t * pdev)
{
    lm_status_t lm_status = LM_STATUS_FAILURE;
    lm_dmae_context_info_t* default_dmae_info = lm_dmae_get(pdev, LM_DMAE_DEFAULT);
    lm_dmae_context_info_t* toe_dmae_info = lm_dmae_get(pdev, LM_DMAE_TOE);

    //allocate and initialize the default DMAE context (used for init, WB access etc...)
    lm_status = lm_dmae_locking_policy_create(  pdev,
                                                LM_PROTECTED_RESOURCE_DMAE_DEFAULT,
                                                LM_DMAE_LOCKING_POLICY_TYPE_PER_PF,
                                                &default_dmae_info->locking_policy);
    if( LM_STATUS_SUCCESS != lm_status )
    {
        return lm_status ;
    }

    default_dmae_info->context = lm_dmae_context_create(pdev,
                                                        DMAE_WB_ACCESS_FUNCTION_CMD(FUNC_ID(pdev)),
                                                        &default_dmae_info->locking_policy,
                                                        CHANGE_ENDIANITY);
    if( NULL == default_dmae_info->context )
    {
        return LM_STATUS_FAILURE;
    }

    //allocate and initialize the TOE DMAE context
    lm_status = lm_dmae_locking_policy_create(  pdev,
                                                LM_PROTECTED_RESOURCE_DMAE_TOE,
                                                LM_DMAE_LOCKING_POLICY_TYPE_INTER_PF,
                                                &toe_dmae_info->locking_policy);
    if( LM_STATUS_SUCCESS != lm_status )
    {
        return lm_status ;
    }

    toe_dmae_info->context = lm_dmae_context_create(pdev,
                                                    DMAE_COPY_PCI_PCI_PORT_0_CMD + PORT_ID(pdev),
                                                    &toe_dmae_info->locking_policy,
                                                    TRUE);
    if( NULL == toe_dmae_info->context )
    {
        return LM_STATUS_FAILURE;
    }

    return lm_status;
}

/* Description:
*    This routine is called during driver initialization.  It is responsible
*    for allocating memory resources needed by the driver for common init.
*    This routine calls the following mm routines:
*    mm_alloc_mem, mm_alloc_phys_mem, and mm_init_packet_desc. */
lm_status_t lm_alloc_resc(struct _lm_device_t *pdev)
{
    lm_params_t*    params     = NULL ;
    lm_variables_t* vars       = NULL ;
    lm_status_t     lm_status  = LM_STATUS_SUCCESS ;
    u8_t            mm_cli_idx = 0;
    if CHK_NULL( pdev )
    {
        return LM_STATUS_INVALID_PARAMETER ;
    }
    DbgMessage(pdev, INFORMi , "### lm_alloc_resc\n");

#ifdef VF_INVOLVED
    if (IS_VFDEV(pdev)) {
        lm_status = lm_vf_init_dev_info(pdev);
        if (LM_STATUS_SUCCESS != lm_status)
            return lm_status;
    }
#endif

    params     = &pdev->params ;
    vars       = &(pdev->vars) ;

    mm_cli_idx = LM_CLI_IDX_MAX;//!!DP mm_cli_idx_to_um_idx(LM_CLI_IDX_MAX);

    // Cleaning after driver unload
    pdev->context_info = NULL;
    mm_mem_zero(&pdev->cid_recycled_callbacks, sizeof(pdev->cid_recycled_callbacks));
    mm_mem_zero(&pdev->toe_info, sizeof(pdev->toe_info));

    lm_status = lm_alloc_sq(pdev);
    if(LM_STATUS_SUCCESS != lm_status)
    {
        return lm_status;
    }

    /* alloc forward chain */
    pdev->tx_info.catchup_chain_idx = FWD_CID(pdev);
    if (IS_PFDEV(pdev))
    {
        /* Allocate Event-Queue: only the pf has an event queue */
        lm_status = lm_alloc_eq(pdev);
        if(LM_STATUS_SUCCESS != lm_status)
        {
            return lm_status;
        }

        pdev->tx_info.catchup_chain_idx = FWD_CID(pdev);

        lm_status = lm_alloc_txq(pdev, pdev->tx_info.catchup_chain_idx,
                                 (u16_t)params->l2_tx_bd_page_cnt[LM_CLI_IDX_FWD],
                                 (u16_t)params->l2_tx_coal_buf_cnt[LM_CLI_IDX_FWD]);
        if(LM_STATUS_SUCCESS != lm_status)
        {
            return lm_status;
        }
    }

    if (IS_PFDEV(pdev))
    {
        lm_status = lm_common_setup_alloc_resc(pdev, TRUE ) ;
    }
#ifdef VF_INVOLVED
    else
    {
        lm_status = lm_vf_setup_alloc_resc(pdev, TRUE);
    }
#endif

    if(LM_STATUS_SUCCESS != lm_status)
    {
        return lm_status;
    }

    if (IS_PFDEV(pdev)) {
        lm_status = lm_stats_alloc_resc( pdev ) ;
        if( LM_STATUS_SUCCESS != lm_status )
        {
            return lm_status ;
        }

        lm_status = lm_dmae_alloc_resc(pdev);
        if( LM_STATUS_SUCCESS != lm_status )
        {
            DbgBreakIf( LM_STATUS_SUCCESS != lm_status ) ;
            return lm_status ;
        }

        // Init context allocation system
        lm_status = lm_alloc_context_pool(pdev);
        if( LM_STATUS_SUCCESS != lm_status )
        {
            DbgBreakIf( LM_STATUS_SUCCESS != lm_status ) ;
            return lm_status ;
        }
        //  CAM mirror?

        /* alloc for ecore */
        lm_status = ecore_resc_alloc(pdev);
        if( LM_STATUS_SUCCESS != lm_status )
        {
            DbgBreakIf( LM_STATUS_SUCCESS != lm_status ) ;
            return lm_status ;
        }
    }
    else if (IS_CHANNEL_VFDEV(pdev))
    {
        // Init context allocation system
        lm_status = lm_alloc_context_pool(pdev);
        if( LM_STATUS_SUCCESS != lm_status )
        {
            DbgBreakIf( LM_STATUS_SUCCESS != lm_status ) ;
            return lm_status ;
        }

        lm_status = lm_stats_alloc_fw_resc(pdev);
        if( LM_STATUS_SUCCESS != lm_status )
        {
            DbgBreakIf( LM_STATUS_SUCCESS != lm_status ) ;
            return lm_status ;
    }
    }
    DbgMessage(pdev, INFORMi , "### exit lm_alloc_resc\n");

    /* FIXME: (MichalS : should be called by um, but this requires lm-um api, so should rethink...) */
    lm_status = lm_init_sp_objs(pdev);
    if( LM_STATUS_SUCCESS != lm_status )
    {
        DbgBreakIf( LM_STATUS_SUCCESS != lm_status ) ;
        return lm_status ;
    }

    return lm_setup_resc(pdev);
}

/* Description:
*    This routine is called during driver initialization.  It is responsible
*    for initilazing  memory resources needed by the driver for common init.
*    This routine calls the following mm routines:
*    mm_alloc_mem, mm_alloc_phys_mem, and mm_init_packet_desc. */
lm_status_t lm_setup_resc(struct _lm_device_t *pdev)
{
    volatile struct hc_sp_status_block * sp_sb = NULL;
    lm_params_t *    params     = NULL ;
    lm_variables_t*  vars       = NULL ;
    lm_tx_info_t *   tx_info    = NULL ;
    lm_rx_info_t *   rx_info    = NULL ;
    u32_t            i          = 0 ;
    u32_t            j          = 0 ;
    lm_status_t      lm_status  = LM_STATUS_SUCCESS ;

    if CHK_NULL( pdev )
    {
        return LM_STATUS_INVALID_PARAMETER ;
    }

    params    = &pdev->params;
    vars      = &(pdev->vars);
    tx_info   = &pdev->tx_info;
    rx_info   = &pdev->rx_info;
    sp_sb     = lm_get_default_status_block(pdev);

    mm_mem_zero(&pdev->cid_recycled_callbacks, sizeof(pdev->cid_recycled_callbacks));
    mm_mem_zero(rx_info->appr_mc.mcast_add_hash_bit_array, sizeof(rx_info->appr_mc.mcast_add_hash_bit_array));

    mm_mem_zero(&pdev->vars.nig_mirror, sizeof(lm_nig_mirror_t));

    pdev->vars.b_is_dmae_ready = FALSE ;

    if (IS_PFDEV(pdev)) {
        // adjust the FWD Tx ring consumer - default sb
        lm_status = lm_setup_txq(pdev, pdev->tx_info.catchup_chain_idx);
        if(LM_STATUS_SUCCESS != lm_status)
        {
            return lm_status;
        }
    }

    if (IS_PFDEV(pdev)) {
        /* setup mac flitering to drop all for all clients */
        // lm_status = lm_setup_tstorm_mac_filter(pdev); FIXME - necessary??
        if(LM_STATUS_SUCCESS != lm_status)
        {
            return lm_status;
        }
    }

    if (IS_PFDEV(pdev)) {
        lm_status = lm_common_setup_alloc_resc(pdev, FALSE ) ;
    }
#ifdef VF_INVOLVED
    else {
        lm_status = lm_vf_setup_alloc_resc(pdev, FALSE);
    }
#endif
    if(LM_STATUS_SUCCESS != lm_status)
    {
        return lm_status;
    }

    lm_status = lm_setup_sq(pdev);
    if(LM_STATUS_SUCCESS != lm_status)
    {
        return lm_status;
    }

    /* Only pfdev has an event-queue */
    if (IS_PFDEV(pdev))
    {
        lm_status = lm_setup_eq(pdev);
        if(LM_STATUS_SUCCESS != lm_status)
        {
            return lm_status;
        }
    }

    // Initialize T1
    if (IS_PFDEV(pdev)) {
        for( i = 0 ; i < vars->searcher_t1_num_pages ; i ++)
        {
            mm_mem_zero( vars->searcher_t1_virt_addr_table[i], params->ilt_client_page_size ) ;
        }

        // Initialize T2 first we make each next filed point to its address +1 then we fixup the edges
        for(i=0 ; i < vars->searcher_t2_num_pages ; i ++)
        {
            for (j=0; j < params->ilt_client_page_size; j+=64)
            {
                *(u64_t*)((char*)vars->searcher_t2_virt_addr_table[i]+j+56) = vars->searcher_t2_phys_addr_table[i].as_u64+j+64; //64bit pointer
            }
            // now fix up the last line in the block to point to the next block
            j = params->ilt_client_page_size - 8;

            if (i < vars->searcher_t2_num_pages -1)
            {
                // this is not the last block
                *(u64_t*)((char*)vars->searcher_t2_virt_addr_table[i]+j) = vars->searcher_t2_phys_addr_table[i+1].as_u64; //64bit pointer
            }
        }

        for( i=0  ;i < vars->timers_linear_num_pages; i++)
        {
            mm_mem_zero(vars->timers_linear_virt_addr_table[i],params->ilt_client_page_size);
        }

#if defined(EMULATION_DOORBELL_FULL_WORKAROUND)
        mm_atomic_set(&vars->doorbells_cnt, DOORBELL_CHECK_FREQUENCY);
#endif

        lm_status = lm_stats_hw_setup(pdev);
        if(lm_status != LM_STATUS_SUCCESS)
        {
            DbgMessage(pdev, WARN, "lm_stats_hw_setup failed.\n");
            return lm_status;
        }

        lm_stats_fw_setup(pdev);

        // init_context
        lm_status = lm_setup_context_pool(pdev) ;
        if(lm_status != LM_STATUS_SUCCESS)
        {
            DbgMessage(pdev, WARN, "lm_setup_context_pool failed.\n");
            return lm_status;
        }
    }
    else if (IS_CHANNEL_VFDEV(pdev))
    {
        lm_status = lm_setup_context_pool(pdev) ;
        if(lm_status != LM_STATUS_SUCCESS)
        {
            DbgMessage(pdev, WARN, "lm_setup_context_pool failed.\n");
            return lm_status;
        }
    }


    pdev->vars.mac_type = MAC_TYPE_NONE;
    pdev->vars.is_pmf = NOT_PMF;

    lm_set_int_coal_info(pdev);

    mm_mem_zero(&pdev->vars.nig_mirror, sizeof(pdev->vars.nig_mirror));

    return lm_status;
}

/**
 * @description
 * Indicate packets from the free descriptor list and the given list
 * @param pdev
 * @param rx_common         - The chain to free RSC/RX.
 * @param packet_list       - A list of packets to indicate.
 * @param idx               - Chain index.
 * @param is_stat_handle    - Is updating statistic is needed.
 */
STATIC void
lm_abort_indicate_free_list( IN OUT   lm_device_t*          pdev,
                             IN       lm_rx_chain_common_t* rx_common,
                             IN       s_list_t*             packet_list,
                             IN const u32_t                 idx,
                             IN const u8_t                  is_stat_handle)
{
    lm_packet_t*            pkt          = NULL;
    for(; ;)
    {
        // Run on all the free list
        pkt = (lm_packet_t *) s_list_pop_head(&rx_common->free_descq);
        if (pkt == NULL)
        {
            break;
        }
        pkt->status = LM_STATUS_ABORTED;
        if(is_stat_handle)
        {
            LM_COMMON_DRV_STATS_ATOMIC_INC_ETH(pdev, rx_aborted);
        }
#if (!defined(LINUX) && !defined(__SunOS) && !defined(UEFI) && !defined(DOS))
        s_list_push_tail(packet_list, (s_list_entry_t *)pkt);
#endif
    }

    if (!s_list_is_empty(packet_list))
    {
#if (!defined(LINUX) && !defined(__SunOS) && !defined(UEFI) && !defined(DOS))
        mm_indicate_rx(pdev, idx, packet_list, LM_STATUS_ABORTED);
#endif
    }
}

/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void lm_abort( lm_device_t        *pdev,
               const lm_abort_op_t abort_op,
               const u32_t         idx)
{
    lm_packet_t          *pkt          = NULL;
    lm_rx_chain_t        *rxq_chain    = NULL;
    lm_rx_chain_common_t *rx_common    = NULL;
    lm_tpa_chain_t       *tpa_chain    = NULL;
    lm_bd_chain_t        *rx_chain_bd  = NULL;
    lm_bd_chain_t        *rx_chain_sge = NULL;
    lm_tx_chain_t        *tx_chain     = NULL;
    s_list_t              packet_list  = {0};
    u16_t                 i            = 0;
    u16_t                 active_entry = 0;

    DbgMessage(pdev, INFORM, "### lm_abort   abort_op=%d idx=%d\n", abort_op, idx);
    switch(abort_op)
    {
        case ABORT_OP_RX_CHAIN:
        case ABORT_OP_INDICATE_RX_CHAIN:
        {
            rxq_chain    = &LM_RXQ(pdev, idx);
            rx_common    = &LM_RXQ_COMMON(pdev, idx);
            rx_chain_bd  = &LM_RXQ_CHAIN_BD(pdev, idx);
            rx_chain_sge = LM_RXQ_SGE_PTR_IF_VALID(pdev, idx);
            // Verify BD's consistent
            DbgBreakIfFastPath( rx_chain_sge && !lm_bd_chains_are_consistent( rx_chain_sge, rx_chain_bd ) );
            /* indicate packets from the active descriptor list */
            for(; ;)
            {
                pkt = (lm_packet_t *) s_list_pop_head(&rxq_chain->active_descq);
                if(pkt == NULL)
                {
                    break;
                }
                lm_bd_chain_bds_consumed(rx_chain_bd, 1);
                if( rx_chain_sge )
                {
                    lm_bd_chain_bds_consumed(rx_chain_sge, 1);
                }
                LM_COMMON_DRV_STATS_ATOMIC_INC_ETH(pdev, rx_aborted);
                // if in shutdown flow or not if in d3 flow ?
                if (abort_op == ABORT_OP_INDICATE_RX_CHAIN)
                {
#if (!defined(LINUX) && !defined(__SunOS) && !defined(UEFI) && !defined(DOS))
                    s_list_push_tail(&packet_list, (s_list_entry_t *)pkt);
#endif
                }
                else
                {
                    s_list_push_tail(&rx_common->free_descq, &pkt->link);
                }
            }
            if ( ABORT_OP_INDICATE_RX_CHAIN == abort_op )
            {
                /* indicate packets from the free descriptor list */
                lm_abort_indicate_free_list( pdev,
                                             rx_common,
                                             &packet_list,
                                             idx,
                                             TRUE);
            }
        } // ABORT_OP_INDICATE_RX_CHAIN
        // Fall Through
        case ABORT_OP_TPA_CHAIN:
        case ABORT_OP_INDICATE_TPA_CHAIN:
        {
            tpa_chain    = &LM_TPA(pdev, idx);
            rx_chain_bd  = &LM_TPA_CHAIN_BD(pdev, idx);
            rx_common    = &LM_TPA_COMMON(pdev, idx);

            DbgBreakIf(!(s_list_is_empty(&packet_list)));

            /* indicate packets from the active descriptor list */
            for(i = lm_bd_chain_cons_idx(rx_chain_bd); i != lm_bd_chain_prod_idx(rx_chain_bd); i++ )
            {
                // Run on all the valid active descriptor
                // Valid active descriptors can only be beteen the consumer to the producers
                active_entry = LM_TPA_BD_ENTRY_TO_ACTIVE_ENTRY(pdev,idx,i);

                LM_TPA_ACTIVE_ENTRY_BOUNDARIES_VERIFY(pdev, idx, active_entry);
                if(LM_TPA_MASK_TEST_ACTIVE_BIT(pdev, idx, active_entry))
                {
                    LM_TPA_MASK_CLEAR_ACTIVE_BIT(pdev, idx, active_entry);
                    pkt = tpa_chain->sge_chain.active_descq_array[active_entry];

                    if(NULL == pkt)
                    {
                        DbgBreakMsg(" Packet is null suppose to be null");
                        continue;
                    }
                    
                    lm_bd_chain_bds_consumed(rx_chain_bd, 1);
                    // if in shutdown flow or not if in d3 flow ?
                    if ((abort_op == ABORT_OP_INDICATE_TPA_CHAIN) ||
                        (abort_op == ABORT_OP_INDICATE_RX_CHAIN))
                    {
#if (DBG)
                        /************start TPA debbug code******************************/
                        tpa_chain->dbg_params.pck_ret_abort_active++;
                        /************end TPA debbug code********************************/
#endif //DBG
#if (!defined(LINUX) && !defined(__SunOS) && !defined(UEFI) && !defined(DOS))
                    s_list_push_tail(&packet_list, (s_list_entry_t *)pkt);
#endif
                }
                    else
                {
                        s_list_push_tail(&rx_common->free_descq, &pkt->link);
                    }
                }
                }
            if ((abort_op == ABORT_OP_INDICATE_TPA_CHAIN) ||
                (abort_op == ABORT_OP_INDICATE_RX_CHAIN))
            {
#if (DBG)
                /************start TPA debbug code******************************/
                // Total packet aborted
                tpa_chain->dbg_params.pck_ret_abort += s_list_entry_cnt(&packet_list) + s_list_entry_cnt(&rx_common->free_descq);

                if((tpa_chain->dbg_params.pck_ret_abort + tpa_chain->dbg_params.pck_ret_from_chip) !=
                   (tpa_chain->dbg_params.pck_received + tpa_chain->dbg_params.pck_received_ind) )
                {
                    DbgBreakMsg("VBD didn't return all packets this chain ");
                }
                /************end TPA debbug code******************************/
#endif //DBG
                /* indicate packets from the free descriptor list */
                lm_abort_indicate_free_list( pdev,
                                             rx_common,
                                             &packet_list,
                                             idx,
                                             FALSE);

#if (DBG)
                /************start TPA debbug code******************************/
                // make sure all packets were abort
                if(0 != (s_list_entry_cnt(&packet_list) + s_list_entry_cnt(&rx_common->free_descq)))
                {
                    DbgBreakMsg("VBD didn't return all packets this chain ");
            }
                /************end TPA debbug code******************************/
#endif //DBG
            }
        break;
        } // ABORT_OP_INDICATE_TPA_CHAIN
        case ABORT_OP_INDICATE_TX_CHAIN:
        {
            tx_chain = &LM_TXQ(pdev, idx);
            for(; ;)
            {
                pkt = (lm_packet_t *) s_list_pop_head(&tx_chain->active_descq);
                if(pkt == NULL)
                {
                    break;
                }
                pkt->status = LM_STATUS_ABORTED;
                LM_COMMON_DRV_STATS_ATOMIC_INC_ETH(pdev, tx_aborted);
                lm_bd_chain_bds_consumed(&tx_chain->bd_chain, pkt->u1.tx.bd_used);
                if (pkt->u1.tx.coalesce_buf) {
                    /* return coalesce buffer to the chain's pool */
                    lm_put_coalesce_buffer(pdev, tx_chain, pkt->u1.tx.coalesce_buf);
                    pkt->u1.tx.coalesce_buf = NULL;
                }
                s_list_push_tail(&packet_list, (s_list_entry_t *)pkt);
            }
            if (!s_list_is_empty(&packet_list))
            {
                mm_indicate_tx(pdev, idx, &packet_list);
            }

            // changed from pdev->params.l2_tx_bd_page_cnt[idx] to pdev->params.l2_tx_bd_page_cnt[0]
            DbgBreakIf(!lm_bd_chain_is_full(&tx_chain->bd_chain));
            DbgBreakIf(s_list_entry_cnt(&tx_chain->coalesce_buf_list) != tx_chain->coalesce_buf_cnt);
            break;
        } // ABORT_OP_INDICATE_TX_CHAIN
        default:
        {
            DbgBreakMsg("unknown abort operation.\n");
            break;
        }
    } //switch
} /* lm_abort */

#include "57710_int_offsets.h"
#include "57711_int_offsets.h"
#include "57712_int_offsets.h"
void ecore_init_e1_firmware(struct _lm_device_t *pdev);
void ecore_init_e1h_firmware(struct _lm_device_t *pdev);
void ecore_init_e2_firmware(struct _lm_device_t *pdev);

int lm_set_init_arrs(lm_device_t *pdev)
{
    u32_t const chip_num = CHIP_NUM(pdev);
    switch(chip_num)
    {
    case CHIP_NUM_5710:
        DbgBreakIf( !CHIP_IS_E1(pdev) );
        ecore_init_e1_firmware(pdev);
        INIT_IRO_ARRAY(pdev) = e1_iro_arr;
        break;
    case CHIP_NUM_5711:
    case CHIP_NUM_5711E:
        DbgBreakIf( !CHIP_IS_E1H(pdev) );
        ecore_init_e1h_firmware(pdev);
        INIT_IRO_ARRAY(pdev) = e1h_iro_arr;
        break;
    case CHIP_NUM_5712:
    case CHIP_NUM_5713:
    case CHIP_NUM_5712E:
    case CHIP_NUM_5713E:
        DbgBreakIf( !CHIP_IS_E2(pdev) );
    case CHIP_NUM_57800:
    case CHIP_NUM_57810:
    case CHIP_NUM_57840_4_10:
    case CHIP_NUM_57840_2_20:
    case CHIP_NUM_57840_OBSOLETE:
    case CHIP_NUM_57811:
        DbgBreakIf( !CHIP_IS_E2(pdev) && !CHIP_IS_E3(pdev) );
        ecore_init_e2_firmware(pdev);
        INIT_IRO_ARRAY(pdev) = e2_iro_arr;
        break;
    default:
        DbgMessage(pdev, FATAL, "chip-id=%x NOT SUPPORTED\n", CHIP_NUM(pdev));
        return -1; // for now not supported, can't have all three...
    }
    return 0;
}

