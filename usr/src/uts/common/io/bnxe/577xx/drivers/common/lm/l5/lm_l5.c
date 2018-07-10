#include "lm5710.h"
#include "everest_iscsi_constants.h"
#include "everest_l5cm_constants.h"
#include "577xx_int_offsets.h"
#include "bd_chain.h"
#include "command.h"
#include "lm_sp_req_mgr.h"
#include "lm_l4sp.h"
#include "lm_l4if.h"
#include "lm_l5if.h"
#include "mm_l5if.h"
#include "mm_l4if.h"
#include "mm.h"



u32_t lm_get_pbl_entries(
    IN  u32_t bufferSize
    )
{
    return CEIL_DIV(bufferSize, LM_PAGE_SIZE);
}



lm_status_t lm_alloc_pbl_mem(
    IN  struct _lm_device_t *pdev,
    IN  u32_t pbl_entries,
    OUT lm_address_t** pbl_virt,
    OUT lm_address_t *pbl_phy,
    OUT void** pbl_virt_table,
    IN  u8_t rt_mem,
    OUT u32_t *pbl_size,
    IN  u8_t mm_cli_idx
    )
{

    if (CHK_NULL(pdev) || (pbl_entries == 0) ||
        CHK_NULL(pbl_virt) || CHK_NULL(pbl_phy) ||
        CHK_NULL(pbl_size))
    {
        /* allocPblMem - illegal pblSize */
        return LM_STATUS_INVALID_PARAMETER;
    }

    *pbl_size = pbl_entries * sizeof(lm_address_t);

    if (rt_mem)
    {
        *pbl_virt = (lm_address_t *)mm_rt_alloc_phys_mem(pdev,
                                                        *pbl_size,
                                                        pbl_phy,
                                                        0,
                                                        mm_cli_idx);
        if CHK_NULL(*pbl_virt)
        {
            *pbl_size = 0;

            return LM_STATUS_RESOURCE;
        }

        *pbl_virt_table = (void *)mm_rt_alloc_mem(pdev,
                                                   pbl_entries * sizeof(void *),
                                                   mm_cli_idx);

        if CHK_NULL(*pbl_virt_table)
        {
            *pbl_size = 0;
            mm_rt_free_phys_mem(pdev, *pbl_size, *pbl_virt, *pbl_phy, mm_cli_idx);
            *pbl_virt = NULL;

            return LM_STATUS_RESOURCE;
        }
    }
    else
    {
        *pbl_virt = (lm_address_t *)mm_alloc_phys_mem_align(pdev,
                                                        *pbl_size,
                                                        pbl_phy,
                                                        LM_PAGE_SIZE,
                                                        0,
                                                        mm_cli_idx);
        if CHK_NULL(*pbl_virt)
        {
            *pbl_size = 0;

            return LM_STATUS_RESOURCE;
        }

        *pbl_virt_table = (void *)mm_alloc_mem(pdev,
                                                pbl_entries * sizeof(void *),
                                                mm_cli_idx);

        if CHK_NULL(*pbl_virt_table)
        {
            *pbl_size = 0;
            *pbl_virt = NULL;

            return LM_STATUS_RESOURCE;
        }
    }

    return LM_STATUS_SUCCESS;
}



lm_status_t lm_create_pbl(
    IN  struct _lm_device_t *pdev,
    IN  void* buf_base_virt,
    IN  lm_address_t* buf_base_phy,
    IN  u32_t buffer_size,
    OUT lm_address_t** pbl_virt,
    OUT lm_address_t* pbl_phy,
    OUT void** pbl_virt_table,
    OUT u32_t *pbl_entries,
    OUT u32_t *pbl_size,
    IN  u8_t rt_mem,
    IN  u8_t mm_cli_idx)
{
    lm_status_t lm_status;

    if (CHK_NULL(pdev) || CHK_NULL(buf_base_virt) ||
        CHK_NULL(buf_base_phy) || CHK_NULL(pbl_virt) ||
        CHK_NULL(pbl_phy) || CHK_NULL(pbl_virt_table) ||
        CHK_NULL(pbl_entries) || CHK_NULL(pbl_size))
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    *pbl_entries = lm_get_pbl_entries(buffer_size);

    lm_status = lm_alloc_pbl_mem(pdev, *pbl_entries, pbl_virt, pbl_phy, pbl_virt_table, rt_mem, pbl_size, mm_cli_idx);
    if (lm_status != LM_STATUS_SUCCESS)
    {
        *pbl_entries = 0;

        return lm_status;
    }

    lm_status = lm_bd_chain_pbl_set_ptrs(buf_base_virt, *buf_base_phy, *pbl_virt, *pbl_virt_table, *pbl_entries);
    if (lm_status != LM_STATUS_SUCCESS)
    {
        if (rt_mem)
        {
            mm_rt_free_phys_mem(pdev, *pbl_size, *pbl_virt, *pbl_phy, mm_cli_idx);
            mm_rt_free_mem(pdev, *pbl_virt_table, *pbl_entries * sizeof(void *), mm_cli_idx);
        }

        *pbl_entries = 0;
        *pbl_size = 0;

        return lm_status;
    }

    return LM_STATUS_SUCCESS;
}



lm_status_t
lm_l5_alloc_eq(
    IN      struct _lm_device_t  *pdev,
    IN      lm_eq_chain_t        *eq_chain,
    IN      lm_eq_addr_t         *eq_addr_save,
    IN      u16_t                page_cnt,
    IN      u8_t                 cli_idx)
{
    u32_t                mem_size     = 0;

    /* check arguments */
    if ((CHK_NULL(pdev) || CHK_NULL(eq_chain) || !page_cnt) ||
        (LM_CLI_IDX_FCOE != cli_idx) && (LM_CLI_IDX_ISCSI != cli_idx))
    {
        return LM_STATUS_FAILURE;
    }

    DbgMessage(pdev, INFORMi | INFORMl5sp, "#lm_alloc_eq, eq_chain=%p, page_cnt=%d\n", eq_chain, page_cnt);

    /* alloc the chain */
    mem_size = page_cnt * LM_PAGE_SIZE;

    if(!eq_addr_save->b_allocated)
    {
        eq_chain->bd_chain.bd_chain_virt = mm_alloc_phys_mem(pdev,
                                                             mem_size,
                                                             &eq_chain->bd_chain.bd_chain_phy,
                                                             0,
                                                             cli_idx);

        if (ERR_IF(!eq_chain->bd_chain.bd_chain_virt))
        {
            DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
            return LM_STATUS_RESOURCE;
        }

        eq_addr_save->bd_chain_virt = eq_chain->bd_chain.bd_chain_virt ;
        eq_addr_save->bd_chain_phy.as_u64 = eq_chain->bd_chain.bd_chain_phy.as_u64;
        eq_addr_save->b_allocated = TRUE;
        // For debugging
        eq_addr_save->prev_mem_size = mem_size;
    }
    else
    {
        DbgBreakIf(mem_size != eq_addr_save->prev_mem_size);
        eq_chain->bd_chain.bd_chain_virt = eq_addr_save->bd_chain_virt;
        eq_chain->bd_chain.bd_chain_phy.as_u64 = eq_addr_save->bd_chain_phy.as_u64;
    }
    mm_memset(eq_chain->bd_chain.bd_chain_virt, 0, mem_size);

    eq_chain->bd_chain.page_cnt = page_cnt;


    return LM_STATUS_SUCCESS;
} /* lm_alloc_eq */



lm_status_t
lm_sc_setup_eq(
    IN struct _lm_device_t *pdev,
    IN u32_t                idx,
    IN const u8_t           is_chain_mode)
{
    lm_bd_chain_t * bd_chain;
    u16_t volatile * sb_indexes;

    /* check arguments */
    if(CHK_NULL(pdev) || ERR_IF((ARRSIZE(pdev->iscsi_info.run_time.eq_chain) <= idx)))
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    DbgMessage(pdev, INFORMi|INFORMl5sp, "#lm_sc_setup_eq, idx=%d\n",idx);

    bd_chain = &LM_SC_EQ(pdev, idx).bd_chain;
    lm_bd_chain_setup(pdev, bd_chain, bd_chain->bd_chain_virt,
                      bd_chain->bd_chain_phy, (u16_t)bd_chain->page_cnt, sizeof(struct iscsi_kcqe), 1/*0*/, is_chain_mode);

    /* verify that EQ size is not too large */
    if(bd_chain->capacity > MAX_EQ_SIZE_ISCSI(is_chain_mode))
    {
        DbgBreakIf(bd_chain->capacity > MAX_EQ_SIZE_ISCSI(is_chain_mode));
        return LM_STATUS_FAILURE;
    }

    DbgMessage(pdev, INFORMi, "is eq %d, bd_chain %p, bd_left %d\n",
        idx,
        bd_chain->next_bd,
        bd_chain->bd_left);
    DbgMessage(pdev, INFORMi, "   bd_chain_phy 0x%x%08x\n",
        bd_chain->bd_chain_phy.as_u32.high,
        bd_chain->bd_chain_phy.as_u32.low);

    // Assign the EQ chain consumer pointer to the consumer index in the status block.
    if( idx >= ARRSIZE(pdev->vars.status_blocks_arr) )
    {
        DbgBreakIf( idx >= ARRSIZE(pdev->vars.status_blocks_arr) );
        return LM_STATUS_FAILURE;
    }

    sb_indexes = lm_get_sb_indexes(pdev, (u8_t)idx);
    sb_indexes[HC_INDEX_ISCSI_EQ_CONS] = 0;
    LM_SC_EQ(pdev, idx).hw_con_idx_ptr = sb_indexes + HC_INDEX_ISCSI_EQ_CONS;
/*
    if (IS_E2(pdev)) {
        pdev->vars.status_blocks_arr[idx].host_hc_status_block.e2_sb->sb.index_values[HC_INDEX_ISCSI_EQ_CONS] = 0;
        LM_SC_EQ(pdev, idx).hw_con_idx_ptr =
            &(pdev->vars.status_blocks_arr[idx].host_hc_status_block.e2_sb->sb.index_values[HC_INDEX_ISCSI_EQ_CONS]);
    } else {
        pdev->vars.status_blocks_arr[idx].host_hc_status_block.e1x_sb->sb.index_values[HC_INDEX_ISCSI_EQ_CONS] = 0;
        LM_SC_EQ(pdev, idx).hw_con_idx_ptr =
            &(pdev->vars.status_blocks_arr[idx].host_hc_status_block.e1x_sb->sb.index_values[HC_INDEX_ISCSI_EQ_CONS]);
    }
 */
    LM_SC_EQ(pdev, idx).hc_sb_info.hc_sb = STATUS_BLOCK_NORMAL_TYPE; //STATUS_BLOCK_CSTORM_TYPE;
    LM_SC_EQ(pdev, idx).hc_sb_info.hc_index_value = HC_INDEX_ISCSI_EQ_CONS;

    return LM_STATUS_SUCCESS;
} /* lm_sc_setup_eq */
/**
 *
 * @description
 * Allocate EQ PBL to pass to FW in init ramrod
 * @param pdev
 * @param eq_chain
 * @param pbl
 * @param eq_addr_save
 *
 * @return lm_status_t
 */
lm_status_t
lm_fc_alloc_eq_pbl(
    IN struct   _lm_device_t  *pdev,
    IN          lm_eq_chain_t *eq_chain,
    IN          lm_fcoe_pbl_t *pbl,
    IN          lm_eq_addr_t  *eq_addr_save)
{
    lm_status_t     lm_status = LM_STATUS_SUCCESS;

    /* check arguments */
    if(CHK_NULL(pdev))
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    DbgMessage(pdev, INFORMi|INFORMl5sp, "#lm_fc_alloc_eq_pbl\n");

    // For D3 case
    if(FALSE == pbl->allocated)
    {
        lm_status = lm_create_pbl(pdev,
                                  eq_chain->bd_chain.bd_chain_virt,
                                  &(eq_chain->bd_chain.bd_chain_phy),
                                  eq_addr_save->prev_mem_size,
                                  &pbl->pbl_phys_table_virt,
                                  &pbl->pbl_phys_table_phys,
                                  &pbl->pbl_virt_table,
                                  &pbl->pbl_entries,
                                  &pbl->pbl_size,
                                  FALSE,
                                  LM_CLI_IDX_FCOE);

        if (lm_status != LM_STATUS_SUCCESS)
        {
            mm_mem_zero(&(pbl) ,sizeof(lm_fcoe_pbl_t));
            return LM_STATUS_FAILURE;
        }
        pbl->allocated = TRUE;
    }
    return lm_status;
}

lm_status_t
lm_fc_setup_eq(
    IN struct   _lm_device_t  *pdev,
    IN          u32_t         idx,
    IN const    u8_t          is_chain_mode)
{
    lm_bd_chain_t   * bd_chain;
    lm_fcoe_pbl_t   * pbl;
    u16_t volatile  * sb_indexes;

    /* check arguments */
    if(CHK_NULL(pdev) || ERR_IF((ARRSIZE(pdev->fcoe_info.run_time.eq_chain) <= idx)))
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    DbgMessage(pdev, INFORMi|INFORMl5sp, "#lm_fc_setup_eq, idx=%d\n",idx);

    bd_chain = &LM_FC_EQ(pdev, idx).bd_chain;
    pbl = &LM_FC_PBL(pdev, idx);
    lm_bd_chain_pbl_setup(pdev, bd_chain, bd_chain->bd_chain_virt,
                      bd_chain->bd_chain_phy, pbl->pbl_virt_table, pbl->pbl_phys_table_virt,
                      (u16_t)bd_chain->page_cnt, sizeof(struct fcoe_kcqe),
                      1/*0*/); /* EQ is considered full of blank entries */

    /* verify that EQ size is not too large */
    if (bd_chain->capacity > MAX_EQ_SIZE_FCOE(is_chain_mode))
    {
        DbgBreakIf(bd_chain->capacity > MAX_EQ_SIZE_FCOE(is_chain_mode));
        return LM_STATUS_FAILURE;
    }

    DbgMessage(pdev, INFORMi, "fc eq %d, bd_chain %p, bd_left %d\n",
        idx,
        bd_chain->next_bd,
        bd_chain->bd_left);
    DbgMessage(pdev, INFORMi, "   bd_chain_phy 0x%x%08x\n",
        bd_chain->bd_chain_phy.as_u32.high,
        bd_chain->bd_chain_phy.as_u32.low);

    // Assign the EQ chain consumer pointer to the consumer index in the status block.
    if (idx >= ARRSIZE(pdev->vars.status_blocks_arr))
    {
        DbgBreakIf( idx >= ARRSIZE(pdev->vars.status_blocks_arr) );
        return LM_STATUS_FAILURE;
    }

    sb_indexes = lm_get_sb_indexes(pdev, (u8_t)idx);
    sb_indexes[HC_INDEX_FCOE_EQ_CONS] = 0;
    LM_FC_EQ(pdev, idx).hw_con_idx_ptr = sb_indexes + HC_INDEX_FCOE_EQ_CONS;
/*
    if (IS_E2(pdev)) {
        pdev->vars.status_blocks_arr[idx].host_hc_status_block.e2_sb->sb.index_values[HC_INDEX_FCOE_EQ_CONS] = 0;
        LM_FC_EQ(pdev, idx).hw_con_idx_ptr =
            &(pdev->vars.status_blocks_arr[idx].host_hc_status_block.e2_sb->sb.index_values[HC_INDEX_FCOE_EQ_CONS]);
    } else {
        pdev->vars.status_blocks_arr[idx].host_hc_status_block.e1x_sb->sb.index_values[HC_INDEX_FCOE_EQ_CONS] = 0;
        LM_FC_EQ(pdev, idx).hw_con_idx_ptr =
            &(pdev->vars.status_blocks_arr[idx].host_hc_status_block.e1x_sb->sb.index_values[HC_INDEX_FCOE_EQ_CONS]);
    }
*/
    LM_FC_EQ(pdev, idx).hc_sb_info.hc_sb = STATUS_BLOCK_NORMAL_SL_TYPE; //STATUS_BLOCK_USTORM_TYPE;
    LM_FC_EQ(pdev, idx).hc_sb_info.hc_index_value = HC_INDEX_FCOE_EQ_CONS;

    return LM_STATUS_SUCCESS;
} /* lm_fc_setup_eq */




/** Description
 *  Callback function for cids being recylced
 */
void lm_sc_recycle_cid_cb(
    struct _lm_device_t *pdev,
    void *cookie,
    s32_t cid)
{
    lm_status_t lm_status;
    lm_sp_req_common_t * sp_req = NULL;
    lm_iscsi_state_t * iscsi = (lm_iscsi_state_t *)cookie;

    if (CHK_NULL(pdev) || CHK_NULL(iscsi))
    {
        DbgBreakIf(1);
        return;
    }

    MM_ACQUIRE_TOE_LOCK(pdev);

    /* un-block the manager... */
    lm_set_cid_state(pdev, iscsi->cid, LM_CID_STATE_VALID);

    if (iscsi->hdr.status == STATE_STATUS_INIT_CONTEXT)
    {
        lm_status = lm_sc_init_iscsi_context(pdev,
                                             iscsi,
                                             &iscsi->pending_ofld1,
                                             &iscsi->pending_ofld2,
                                             &iscsi->pending_ofld3);

        mm_sc_complete_offload_request(pdev, iscsi, lm_status);
    }

    /* we can now unblock any pending slow-paths */
    lm_sp_req_manager_unblock(pdev, cid, &sp_req);

    MM_RELEASE_TOE_LOCK(pdev);
}


void lm_sc_comp_cb(struct _lm_device_t *pdev, struct sq_pending_command *pending)
{
    struct iscsi_kcqe kcqe  = {0};
    lm_iscsi_state_t *iscsi = NULL;
    u32_t            cid;
    u8_t             cmd;


    if (CHK_NULL(pdev) || CHK_NULL(pending))
    {
        return;
    }

    cmd = pending->cmd;
    cid = pending->cid;

    iscsi = lm_cid_cookie(pdev, ISCSI_CONNECTION_TYPE, cid);

    if (iscsi)
    {
        kcqe.iscsi_conn_id         = iscsi->iscsi_conn_id;
        kcqe.iscsi_conn_context_id = HW_CID(pdev, cid);
    }

    kcqe.completion_status = LM_STATUS_SUCCESS; /* TODO_ER: Fixme: do we want this?? maybe ok since l5 is aware of er... */

    kcqe.op_code = cmd; /* In iSCSI they are the same */

    kcqe.flags |= (ISCSI_KWQE_LAYER_CODE << ISCSI_KWQE_HEADER_LAYER_CODE_SHIFT);

    lm_sc_complete_slow_path_request(pdev, &kcqe);
}

lm_status_t
lm_sc_alloc_resc(
    IN struct _lm_device_t *pdev
    )
{
    u8_t        mm_cli_idx  = LM_RESOURCE_ISCSI;
    u8_t        *chk_buf    = NULL;
    u16_t       i           = 0;

    if CHK_NULL(pdev)
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    mm_mem_zero(&pdev->iscsi_info, sizeof(lm_iscsi_info_t));

    /* Allocate global buffer */
    pdev->iscsi_info.bind.global_buff_base_virt = (u8_t*)mm_alloc_phys_mem(pdev,
                                                                      ISCSI_GLOBAL_BUF_SIZE,
                                                                      &pdev->iscsi_info.bind.global_buff_base_phy,
                                                                      0,
                                                                      mm_cli_idx);
    if CHK_NULL(pdev->iscsi_info.bind.global_buff_base_virt)
    {
        return LM_STATUS_RESOURCE;
    }

    /* cid recycled cb registration  */
    lm_cid_recycled_cb_register(pdev, ISCSI_CONNECTION_TYPE, lm_sc_recycle_cid_cb);

    /* Sq-completion cb registration (sq that get completed internally in driver */
    lm_sq_comp_cb_register(pdev, ISCSI_CONNECTION_TYPE, lm_sc_comp_cb);

    chk_buf = (u8_t *)(&(pdev->iscsi_info.eq_addr_save));
    // Except global_buff and pdev->iscsi_info all other fileds should be zero
    for(i = 0 ;i < sizeof(pdev->iscsi_info.eq_addr_save) ;i++)
    {
        DbgBreakIf(0 != chk_buf[i]);
    }

    chk_buf = (u8_t *)(&(pdev->iscsi_info.run_time));
    // Except global_buff and pdev->iscsi_info all other fileds should be zero
    for(i = 0 ;i < sizeof(pdev->iscsi_info.run_time) ;i++)
    {
        DbgBreakIf(0 != chk_buf[i]);
    }
    return LM_STATUS_SUCCESS;
} /* lm_sc_alloc_resc */

/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
u16_t
lm_l5_eq_page_cnt(
    IN struct       _lm_device_t *pdev,
    const u32_t     max_func_cons,
    const u16_t     reserved_eq_elements,
    const u16_t     eqes_per_page,
    const u16_t     max_eq_pages
    )
{
    u16_t eq_page_cnt = 0;
    u16_t min_eq_size = 0;

    /* Init EQs - create page chains */
    min_eq_size = (u16_t)(max_func_cons + reserved_eq_elements);
    eq_page_cnt = CEIL_DIV(min_eq_size, (eqes_per_page));
    eq_page_cnt = min(eq_page_cnt, max_eq_pages);

    return eq_page_cnt;
}

/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t
lm_fc_free_init_resc(
    IN struct _lm_device_t *pdev
    )
{
    lm_status_t         lm_status   = LM_STATUS_SUCCESS;
    u16_t               eq_sb_idx   = 0;
    u16_t               eq_page_cnt = 0;

    if (CHK_NULL(pdev))
    {
        DbgBreakMsg("lm_fc_free_init_resc failed");
        return LM_STATUS_INVALID_PARAMETER;
    }

    mm_memset(&(pdev->fcoe_info.run_time), 0, sizeof(pdev->fcoe_info.run_time));
    return lm_status;
}


lm_status_t
lm_fc_clear_d0_resc(
    IN struct _lm_device_t *pdev,
    const u8_t cid
    )
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    u8_t eq_idx = 0;

    if CHK_NULL(pdev)
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    LM_FC_FOREACH_EQ_IDX(pdev, eq_idx)
    {
        lm_clear_chain_sb_cons_idx(pdev, eq_idx, &LM_FC_EQ(pdev, eq_idx).hc_sb_info, &LM_FC_EQ(pdev, eq_idx).hw_con_idx_ptr);
    }

    lm_status = lm_fc_free_init_resc(pdev);

    return lm_status;
} /* lm_fc_clear_d0_resc */

lm_status_t
lm_fc_clear_resc(
    IN struct _lm_device_t *pdev
    )
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    const u8_t cid  = FCOE_CID(pdev);

    if CHK_NULL(pdev)
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    lm_fc_clear_d0_resc(
        pdev,
        cid);
    s_list_init(&LM_RXQ(pdev, cid).active_descq, NULL, NULL, 0);
    s_list_init(&LM_RXQ(pdev, cid).common.free_descq, NULL, NULL, 0);

    return lm_status;
} /* lm_fc_clear_resc */


/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t
lm_sc_free_init_resc(
    IN struct _lm_device_t *pdev
    )
{
    lm_status_t         lm_status   = LM_STATUS_SUCCESS;
    u16_t               eq_sb_idx   = 0;
    u16_t               eq_page_cnt = 0;

    if (CHK_NULL(pdev))
    {
        DbgBreakMsg("lm_sc_free_init_resc failed");
        return LM_STATUS_INVALID_PARAMETER;
    }

    mm_memset(&(pdev->iscsi_info.run_time), 0, sizeof(pdev->iscsi_info.run_time));
    return lm_status;
}


lm_status_t
lm_sc_clear_d0_resc(
    IN struct _lm_device_t *pdev,
    const u8_t cid
    )
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    u8_t eq_idx = 0;

    if CHK_NULL(pdev)
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    LM_SC_FOREACH_EQ_IDX(pdev, eq_idx)
    {
        lm_clear_chain_sb_cons_idx(pdev, eq_idx, &LM_SC_EQ(pdev, eq_idx).hc_sb_info, &LM_SC_EQ(pdev, eq_idx).hw_con_idx_ptr);
    }

    lm_status = lm_sc_free_init_resc(pdev);

    return lm_status;
} /* lm_sc_clear_d0_resc */

lm_status_t
lm_sc_clear_resc(
    IN struct _lm_device_t *pdev
    )
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    const u8_t cid  = ISCSI_CID(pdev);

    if CHK_NULL(pdev)
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    lm_sc_clear_d0_resc(
        pdev,
        cid);
    s_list_init(&LM_RXQ(pdev, cid).active_descq, NULL, NULL, 0);
    s_list_init(&LM_RXQ(pdev, cid).common.free_descq, NULL, NULL, 0);

    return lm_status;
} /* lm_sc_clear_resc */



lm_status_t
lm_sc_ooo_chain_establish(
    IN struct _lm_device_t *pdev)
{
    lm_status_t             lm_status = LM_STATUS_SUCCESS;
    const u32_t             func        = FUNC_ID(pdev);

    if CHK_NULL(pdev)
    {
        lm_status = LM_STATUS_INVALID_PARAMETER;
        return lm_status;
    }
    LM_INTMEM_WRITE32(pdev,
                      TSTORM_ISCSI_L2_ISCSI_OOO_CONS_OFFSET(func),
                      0,
                      BAR_TSTRORM_INTMEM);

    LM_INTMEM_WRITE32(pdev,
                      TSTORM_ISCSI_L2_ISCSI_OOO_CID_TABLE_OFFSET(func),
                      HW_CID(pdev, OOO_CID(pdev)),
                      BAR_TSTRORM_INTMEM);

    LM_INTMEM_WRITE32(pdev,
                      TSTORM_ISCSI_L2_ISCSI_OOO_CLIENT_ID_TABLE_OFFSET(func),
                      LM_FW_CLI_ID(pdev,OOO_CID(pdev)),
                      BAR_TSTRORM_INTMEM);


    return lm_status;
}


/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t
lm_sc_init(
    IN struct _lm_device_t *pdev,
    IN struct iscsi_kwqe_init1  *req1,
    IN struct iscsi_kwqe_init2  *req2
    )
{
    lm_status_t                  lm_status;
    u16_t                        eq_page_cnt;
    u32_t                        hq_size_in_bytes;
    u32_t                        hq_pbl_entries;
    u32_t                        eq_idx;
    u16_t                        eq_sb_idx;
    u32_t                        page_size_bits;
    u8_t                         delayed_ack_en              = 0;
    const u8_t                   is_chain_mode               = TRUE;
    const u32_t                  func                        = FUNC_ID(pdev);
    struct tstorm_l5cm_tcp_flags tstorm_l5cm_tcp_flags_param = {0};

    if (CHK_NULL(req1) || CHK_NULL(req2))
    {
        return LM_STATUS_FAILURE;
    }

    DbgMessage(pdev, INFORM, "### lm_sc_init\n");

    page_size_bits = GET_FIELD(req1->flags, ISCSI_KWQE_INIT1_PAGE_SIZE);
    if (LM_PAGE_BITS - ISCSI_PAGE_BITS_SHIFT != page_size_bits)
    {
        DbgMessage(pdev, INFORM, "lm_sc_init: Illegal page size.\n");
        return LM_STATUS_FAILURE;
    }

    if(ISCSI_HSI_VERSION != req1->hsi_version)
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    delayed_ack_en = GET_FIELD(req1->flags, ISCSI_KWQE_INIT1_DELAYED_ACK_ENABLE);

    pdev->iscsi_info.run_time.num_of_tasks = req1->num_tasks_per_conn;
    pdev->iscsi_info.run_time.cq_size      = req1->cq_num_wqes;
    pdev->iscsi_info.run_time.num_of_cqs   = req1->num_cqs;

    /* the number of cqs is used to determine the number of eqs */
    if (pdev->iscsi_info.run_time.num_of_cqs > MAX_EQ_CHAIN)
    {
        DbgBreakIf(pdev->iscsi_info.run_time.num_of_cqs > MAX_EQ_CHAIN);
        pdev->iscsi_info.run_time.num_of_cqs = MAX_EQ_CHAIN;
    }
    pdev->iscsi_info.run_time.l5_eq_chain_cnt     = pdev->iscsi_info.run_time.num_of_cqs;
    pdev->iscsi_info.run_time.l5_eq_max_chain_cnt = MAX_EQ_CHAIN;
    // Only one EQ chain is supported.

    if ((pdev->iscsi_info.run_time.l5_eq_chain_cnt > 1)||
        (pdev->params.sb_cnt < pdev->iscsi_info.run_time.l5_eq_chain_cnt))
    {
        DbgMessage(pdev, INFORM, "lm_sc_init: l5_eq_chain_cnt=%d\n.\n",pdev->iscsi_info.run_time.l5_eq_chain_cnt);
        DbgBreakMsg("lm_sc_init: pdev->iscsi_info.l5_eq_chain_cnt is bigger than 1.\n");
        return LM_STATUS_FAILURE;
    }
    DbgBreakIf(pdev->iscsi_info.run_time.l5_eq_chain_cnt > 1);
    DbgBreakIf(pdev->params.sb_cnt < pdev->iscsi_info.run_time.l5_eq_chain_cnt);
    /* TOE when RSS is disabled, ISCSI and FCOE will use the same NDSB.  */
    pdev->iscsi_info.run_time.l5_eq_base_chain_idx = LM_NON_RSS_SB(pdev);

//    if (!pdev->params.l4_enable_rss) {
//        RESET_FLAGS(pdev->params.sb_cpu_affinity, 1 << LM_TOE_RSS_BASE_CHAIN_INDEX(&pdev->lmdev));
//    }


    /* round up HQ size to fill an entire page */
    hq_size_in_bytes = req1->num_ccells_per_conn * sizeof(struct iscsi_hq_bd);
    hq_pbl_entries = lm_get_pbl_entries(hq_size_in_bytes);
    pdev->iscsi_info.run_time.hq_size = (u16_t)(hq_pbl_entries * (LM_PAGE_SIZE / sizeof(struct iscsi_hq_bd)));

    /* Init EQs - create page chains */
    // The size of the EQ in iSCSI is <num iscsi connections> * 2 +slowpath.
    // I.e. for each connection there should be room for 1 fastpath completion and 1 error notification.
    eq_page_cnt = lm_l5_eq_page_cnt(pdev,
                                    (u16_t)(pdev->params.max_func_iscsi_cons * 2),
                                    RESERVED_ISCSI_EQ_ELEMENTS,
                                    (ISCSI_EQES_PER_PAGE(is_chain_mode)),
                                    MAX_EQ_PAGES);// Sub the next BD page.

    LM_SC_FOREACH_EQ_IDX(pdev, eq_sb_idx)
    {
        lm_status = lm_l5_alloc_eq(pdev, &LM_SC_EQ(pdev, eq_sb_idx), &LM_EQ_ADDR_SAVE_SC(pdev, eq_sb_idx) , eq_page_cnt, LM_CLI_IDX_ISCSI);
        if (lm_status != LM_STATUS_SUCCESS)
        {
            return lm_status;
        }

        lm_status = lm_sc_setup_eq(pdev, eq_sb_idx,is_chain_mode);
        if (lm_status != LM_STATUS_SUCCESS)
        {
            return lm_status;
        }
    }

    SET_FLAGS( tstorm_l5cm_tcp_flags_param.flags, delayed_ack_en << TSTORM_L5CM_TCP_FLAGS_DELAYED_ACK_EN_SHIFT);

    // in case size change, we need to change LM_INTMEM_WRITEXX macro etc...
    ASSERT_STATIC( sizeof(tstorm_l5cm_tcp_flags_param) == sizeof(u16_t) );

    /* Init internal RAM */
    ASSERT_STATIC(sizeof(struct regpair_t) == sizeof(lm_address_t));

    /* init Tstorm RAM */
    LM_INTMEM_WRITE16(pdev, TSTORM_ISCSI_RQ_SIZE_OFFSET(func),           req1->rq_num_wqes, BAR_TSTRORM_INTMEM);
    LM_INTMEM_WRITE16(pdev, TSTORM_ISCSI_PAGE_SIZE_OFFSET(func),         LM_PAGE_SIZE, BAR_TSTRORM_INTMEM);
    LM_INTMEM_WRITE8 (pdev, TSTORM_ISCSI_PAGE_SIZE_LOG_OFFSET(func),     LM_PAGE_BITS, BAR_TSTRORM_INTMEM);
    LM_INTMEM_WRITE32(pdev, TSTORM_ISCSI_TCP_LOCAL_ADV_WND_OFFSET(func), 0x100000, BAR_TSTRORM_INTMEM);
    LM_INTMEM_WRITE16(pdev, TSTORM_ISCSI_NUM_OF_TASKS_OFFSET(func),      req1->num_tasks_per_conn, BAR_TSTRORM_INTMEM);
    LM_INTMEM_WRITE64(pdev, TSTORM_ISCSI_ERROR_BITMAP_OFFSET(func),      *((u64_t *)&req2->error_bit_map), BAR_TSTRORM_INTMEM);
    LM_INTMEM_WRITE16(pdev, TSTORM_ISCSI_TCP_VARS_FLAGS_OFFSET(func),     tstorm_l5cm_tcp_flags_param.flags, BAR_TSTRORM_INTMEM);

    /* init Ustorm RAM */
    LM_INTMEM_WRITE16(pdev, USTORM_ISCSI_RQ_BUFFER_SIZE_OFFSET(func), req1->rq_buffer_size, BAR_USTRORM_INTMEM);
    LM_INTMEM_WRITE16(pdev, USTORM_ISCSI_PAGE_SIZE_OFFSET(func), LM_PAGE_SIZE, BAR_USTRORM_INTMEM);
    LM_INTMEM_WRITE8 (pdev, USTORM_ISCSI_PAGE_SIZE_LOG_OFFSET(func), LM_PAGE_BITS, BAR_USTRORM_INTMEM);
    LM_INTMEM_WRITE16(pdev, USTORM_ISCSI_NUM_OF_TASKS_OFFSET(func), req1->num_tasks_per_conn, BAR_USTRORM_INTMEM);
    LM_INTMEM_WRITE16(pdev, USTORM_ISCSI_RQ_SIZE_OFFSET(func), req1->rq_num_wqes, BAR_USTRORM_INTMEM);
    LM_INTMEM_WRITE16(pdev, USTORM_ISCSI_CQ_SIZE_OFFSET(func), req1->cq_num_wqes, BAR_USTRORM_INTMEM);
    LM_INTMEM_WRITE16(pdev, USTORM_ISCSI_CQ_SQN_SIZE_OFFSET(func), req2->max_cq_sqn, BAR_USTRORM_INTMEM);
    LM_INTMEM_WRITE16(pdev, USTORM_ISCSI_R2TQ_SIZE_OFFSET(func), (u16_t)pdev->iscsi_info.run_time.num_of_tasks * ISCSI_MAX_NUM_OF_PENDING_R2TS, BAR_USTRORM_INTMEM);
    LM_INTMEM_WRITE64(pdev, USTORM_ISCSI_GLOBAL_BUF_PHYS_ADDR_OFFSET(func), pdev->iscsi_info.bind.global_buff_base_phy.as_u64, BAR_USTRORM_INTMEM);
    LM_INTMEM_WRITE64(pdev, USTORM_ISCSI_ERROR_BITMAP_OFFSET(func), *((u64_t *)&req2->error_bit_map), BAR_USTRORM_INTMEM);

    /* init Xstorm RAM */
    LM_INTMEM_WRITE16(pdev, XSTORM_ISCSI_PAGE_SIZE_OFFSET(func), LM_PAGE_SIZE, BAR_XSTRORM_INTMEM);
    LM_INTMEM_WRITE8 (pdev, XSTORM_ISCSI_PAGE_SIZE_LOG_OFFSET(func), LM_PAGE_BITS, BAR_XSTRORM_INTMEM);
    LM_INTMEM_WRITE16(pdev, XSTORM_ISCSI_NUM_OF_TASKS_OFFSET(func), req1->num_tasks_per_conn, BAR_XSTRORM_INTMEM);
    LM_INTMEM_WRITE16(pdev, XSTORM_ISCSI_HQ_SIZE_OFFSET(func), pdev->iscsi_info.run_time.hq_size, BAR_XSTRORM_INTMEM);
    LM_INTMEM_WRITE16(pdev, XSTORM_ISCSI_SQ_SIZE_OFFSET(func), req1->num_tasks_per_conn, BAR_XSTRORM_INTMEM);
    LM_INTMEM_WRITE16(pdev, XSTORM_ISCSI_R2TQ_SIZE_OFFSET(func), req1->num_tasks_per_conn * ISCSI_MAX_NUM_OF_PENDING_R2TS, BAR_XSTRORM_INTMEM);

    /* init Cstorm RAM */
    LM_INTMEM_WRITE16(pdev, CSTORM_ISCSI_PAGE_SIZE_OFFSET(func), LM_PAGE_SIZE, BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8 (pdev, CSTORM_ISCSI_PAGE_SIZE_LOG_OFFSET(func), LM_PAGE_BITS, BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE16(pdev, CSTORM_ISCSI_NUM_OF_TASKS_OFFSET(func), req1->num_tasks_per_conn, BAR_CSTRORM_INTMEM);
    LM_SC_FOREACH_EQ_IDX(pdev, eq_sb_idx)
    {
        eq_idx = eq_sb_idx - pdev->iscsi_info.run_time.l5_eq_base_chain_idx;
        LM_INTMEM_WRITE16(pdev, CSTORM_ISCSI_EQ_PROD_OFFSET(func, eq_idx), lm_bd_chain_prod_idx(&LM_SC_EQ(pdev, eq_sb_idx).bd_chain), BAR_CSTRORM_INTMEM);
        LM_INTMEM_WRITE16(pdev, CSTORM_ISCSI_EQ_CONS_OFFSET(func, eq_idx), 0 , BAR_CSTRORM_INTMEM);
        LM_INTMEM_WRITE32(pdev, CSTORM_ISCSI_EQ_NEXT_PAGE_ADDR_OFFSET(func, eq_idx), lm_bd_chain_phys_addr(&LM_SC_EQ(pdev, eq_sb_idx).bd_chain, 1).as_u32.low, BAR_CSTRORM_INTMEM);
        LM_INTMEM_WRITE32(pdev, 4 + CSTORM_ISCSI_EQ_NEXT_PAGE_ADDR_OFFSET(func, eq_idx), lm_bd_chain_phys_addr(&LM_SC_EQ(pdev, eq_sb_idx).bd_chain, 1).as_u32.high, BAR_CSTRORM_INTMEM);
        LM_INTMEM_WRITE32(pdev, CSTORM_ISCSI_EQ_NEXT_EQE_ADDR_OFFSET(func, eq_idx), lm_bd_chain_phys_addr(&LM_SC_EQ(pdev, eq_sb_idx).bd_chain, 0).as_u32.low, BAR_CSTRORM_INTMEM);
        LM_INTMEM_WRITE32(pdev, 4 + CSTORM_ISCSI_EQ_NEXT_EQE_ADDR_OFFSET(func, eq_idx), lm_bd_chain_phys_addr(&LM_SC_EQ(pdev, eq_sb_idx).bd_chain, 0).as_u32.high, BAR_CSTRORM_INTMEM);
        LM_INTMEM_WRITE8 (pdev, CSTORM_ISCSI_EQ_NEXT_PAGE_ADDR_VALID_OFFSET(func, eq_idx), 1, BAR_CSTRORM_INTMEM); // maybe move to init tool
        LM_INTMEM_WRITE16(pdev, CSTORM_ISCSI_EQ_SB_NUM_OFFSET(func, eq_idx), LM_FW_SB_ID(pdev,eq_sb_idx), BAR_CSTRORM_INTMEM);
        LM_INTMEM_WRITE8 (pdev, CSTORM_ISCSI_EQ_SB_INDEX_OFFSET(func, eq_idx), HC_INDEX_ISCSI_EQ_CONS, BAR_CSTRORM_INTMEM);
    }
    LM_INTMEM_WRITE16(pdev, CSTORM_ISCSI_HQ_SIZE_OFFSET(func), pdev->iscsi_info.run_time.hq_size, BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE16(pdev, CSTORM_ISCSI_CQ_SIZE_OFFSET(func), req1->cq_num_wqes, BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE16(pdev, CSTORM_ISCSI_CQ_SQN_SIZE_OFFSET(func), req2->max_cq_sqn, BAR_CSTRORM_INTMEM);

    return LM_STATUS_SUCCESS;
} /* lm_sc_init */



/* Get dma memory for init ramrod */
STATIC lm_status_t
lm_fc_get_ramrod_phys_mem(
    IN struct _lm_device_t *pdev)
{

    if CHK_NULL(pdev->fcoe_info.bind.ramrod_mem_virt)
    {
        pdev->fcoe_info.bind.ramrod_mem_virt =
        mm_alloc_phys_mem(pdev,
                          sizeof(lm_fcoe_slow_path_phys_data_t),
                          &pdev->fcoe_info.bind.ramrod_mem_phys,
                          0,
                          LM_CLI_IDX_FCOE);

        if CHK_NULL(pdev->fcoe_info.bind.ramrod_mem_virt)
        {
            return LM_STATUS_RESOURCE;
        }
    }
    return LM_STATUS_SUCCESS;
}



lm_status_t
lm_fc_init(
    IN struct _lm_device_t          *pdev,
    IN struct fcoe_kwqe_init1       *init1,
    IN struct fcoe_kwqe_init2       *init2,
    IN struct fcoe_kwqe_init3       *init3)
{
    lm_status_t                     lm_status;
    lm_fcoe_slow_path_phys_data_t   *ramrod_params;
    u16_t                           eq_page_cnt;
    u16_t                           eq_sb_idx;
    u32_t                           func;
    u32_t                           port;
    const u8_t                      is_chain_mode = FALSE;
    if (CHK_NULL(pdev) || CHK_NULL(init1) || CHK_NULL(init2) || CHK_NULL(init3))
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    func = FUNC_ID(pdev);
    port = PORT_ID(pdev);

    DbgMessage(pdev, INFORM, "### lm_fc_init\n");

    pdev->fcoe_info.run_time.num_of_cqs = 1;                 // one EQ

    // Only one EQ chain is supported.
    if ((pdev->fcoe_info.run_time.num_of_cqs > 1)||
        (pdev->params.sb_cnt < pdev->fcoe_info.run_time.num_of_cqs))
    {
        DbgMessage(pdev, INFORM, "lm_fc_init: num_of_cqs=%d\n.\n",pdev->fcoe_info.run_time.num_of_cqs);
        DbgBreakMsg("lm_fc_init: pdev->fcoe_info.run_time.num_of_cqs is bigger than 1.\n");
        return LM_STATUS_INVALID_PARAMETER;
    }
    DbgBreakIf(pdev->fcoe_info.run_time.num_of_cqs > 1);
    DbgBreakIf(pdev->params.sb_cnt < pdev->fcoe_info.run_time.num_of_cqs);
    /* TOE when RSS is disabled, ISCSI and FCOE will use the same NDSB.  */
    pdev->fcoe_info.run_time.fc_eq_base_chain_idx = LM_NON_RSS_SB(pdev);

    if(CHK_NULL(pdev->fcoe_info.bind.ramrod_mem_virt))
    {
        return LM_STATUS_RESOURCE;
    }
    ramrod_params = (lm_fcoe_slow_path_phys_data_t*)pdev->fcoe_info.bind.ramrod_mem_virt;

    // Init EQs - create page chains
    eq_page_cnt = lm_l5_eq_page_cnt(pdev,
                                    (u16_t)pdev->params.max_func_fcoe_cons,
                                    RESERVED_FCOE_EQ_ELEMENTS,
                                    FCOE_EQES_PER_PAGE(is_chain_mode),
                                    FCOE_MAX_EQ_PAGES_PER_FUNC);


    LM_FC_FOREACH_EQ_IDX(pdev, eq_sb_idx)
    {
        lm_status = lm_l5_alloc_eq(pdev, &LM_FC_EQ(pdev, eq_sb_idx),&LM_EQ_ADDR_SAVE_FC(pdev, eq_sb_idx),eq_page_cnt, LM_CLI_IDX_FCOE);
        if (lm_status != LM_STATUS_SUCCESS)
        {
            return lm_status;
        }

        lm_status = lm_fc_alloc_eq_pbl(pdev, &LM_FC_EQ(pdev, eq_sb_idx), &LM_FC_PBL(pdev, eq_sb_idx),
                                       &LM_EQ_ADDR_SAVE_FC(pdev, eq_sb_idx));
        if (lm_status != LM_STATUS_SUCCESS)
        {
            return lm_status;
        }

        lm_status = lm_fc_setup_eq(pdev, eq_sb_idx,is_chain_mode);
        if (lm_status != LM_STATUS_SUCCESS)
        {
            return lm_status;
        }
    }

    /* Set up the ramrod params */
    mm_memset(ramrod_params, 0, sizeof(lm_fcoe_slow_path_phys_data_t));

    memcpy(&ramrod_params->fcoe_init.init_kwqe1, init1, sizeof(struct fcoe_kwqe_init1));
    memcpy(&ramrod_params->fcoe_init.init_kwqe2, init2, sizeof(struct fcoe_kwqe_init2));
    memcpy(&ramrod_params->fcoe_init.init_kwqe3, init3, sizeof(struct fcoe_kwqe_init3));


    /* waiting for new HSI */
    ramrod_params->fcoe_init.eq_pbl_base.lo = mm_cpu_to_le32(LM_FC_PBL(pdev, pdev->fcoe_info.run_time.fc_eq_base_chain_idx).pbl_phys_table_phys.as_u32.low);
    ramrod_params->fcoe_init.eq_pbl_base.hi = mm_cpu_to_le32(LM_FC_PBL(pdev, pdev->fcoe_info.run_time.fc_eq_base_chain_idx).pbl_phys_table_phys.as_u32.high);
    ramrod_params->fcoe_init.eq_pbl_size = mm_cpu_to_le32(LM_FC_PBL(pdev, pdev->fcoe_info.run_time.fc_eq_base_chain_idx).pbl_entries);
    ramrod_params->fcoe_init.eq_prod = mm_cpu_to_le16(lm_bd_chain_prod_idx(&LM_FC_EQ(pdev, pdev->fcoe_info.run_time.fc_eq_base_chain_idx).bd_chain));
    ramrod_params->fcoe_init.sb_num = mm_cpu_to_le16(LM_FW_SB_ID(pdev,pdev->fcoe_info.run_time.fc_eq_base_chain_idx));
    ramrod_params->fcoe_init.sb_id = HC_INDEX_FCOE_EQ_CONS;

    if (IS_SD_UFP_MODE(pdev))
    {
        ramrod_params->fcoe_init.init_kwqe1.flags |= FCOE_KWQE_INIT1_CLASSIFY_FAILED_ALLOWED;
    }

    lm_status = lm_command_post(pdev,
                                LM_CLI_CID(pdev, LM_CLI_IDX_FCOE),      /* cid */
                                FCOE_RAMROD_CMD_ID_INIT_FUNC,
                                CMD_PRIORITY_NORMAL,
                                FCOE_CONNECTION_TYPE,
                                pdev->fcoe_info.bind.ramrod_mem_phys.as_u64);

    if (lm_status != LM_STATUS_SUCCESS)
    {
        /* only one we know off... */
        DbgBreakIf(lm_status != LM_STATUS_REQUEST_NOT_ACCEPTED);
        /* Command wasn't posted, so we need to complete it from here. */

    }

    // completion is asynchronous

    return LM_STATUS_SUCCESS;
} /* lm_fc_init */


/** Description
 *  Callback function for cids being recylced
 */
void
lm_fc_recycle_cid_cb(
    struct _lm_device_t             *pdev,
    void                            *cookie,
    s32_t                           cid)
{
    lm_status_t         lm_status;
    lm_sp_req_common_t  *sp_req = NULL;
    lm_fcoe_state_t     *fcoe = (lm_fcoe_state_t *)cookie;

    if (CHK_NULL(pdev) || CHK_NULL(fcoe))
    {
        DbgBreakIf(1);
        return;
    }

    MM_ACQUIRE_TOE_LOCK(pdev);

    /* un-block the manager... */
    lm_set_cid_state(pdev, fcoe->cid, LM_CID_STATE_VALID);

    lm_status = lm_fc_init_fcoe_context(pdev, fcoe);

    lm_status = lm_fc_post_offload_ramrod(pdev, fcoe);

    /* we can now unblock any pending slow-paths */
    lm_sp_req_manager_unblock(pdev, cid, &sp_req);

    MM_RELEASE_TOE_LOCK(pdev);
}

void lm_fc_comp_cb(struct _lm_device_t *pdev, struct sq_pending_command *pending)
{
    struct fcoe_kcqe kcqe = {0};
    lm_fcoe_state_t *fcoe = NULL;
    u32_t            cid;
    u8_t             cmd;


    if (CHK_NULL(pdev) || CHK_NULL(pending))
    {
        return;
    }

    cmd = pending->cmd;
    cid = pending->cid;

    fcoe = lm_cid_cookie(pdev, FCOE_CONNECTION_TYPE, cid);

    if (fcoe)
    {
        kcqe.fcoe_conn_id         = fcoe->fcoe_conn_id;
        kcqe.fcoe_conn_context_id = HW_CID(pdev, cid);
    }

    kcqe.completion_status = LM_STATUS_SUCCESS; /* Fixme: do we want this?? maybe ok since l5 is aware of er... */

    switch (cmd)
    {
    case FCOE_RAMROD_CMD_ID_INIT_FUNC:
        kcqe.op_code = FCOE_KCQE_OPCODE_INIT_FUNC;
        break;

    case FCOE_RAMROD_CMD_ID_DESTROY_FUNC:
        kcqe.op_code = FCOE_KCQE_OPCODE_DESTROY_FUNC;
        break;

    case FCOE_RAMROD_CMD_ID_STAT_FUNC:
        kcqe.op_code = FCOE_KCQE_OPCODE_STAT_FUNC;
        break;

    case FCOE_RAMROD_CMD_ID_OFFLOAD_CONN:
        kcqe.op_code = FCOE_KCQE_OPCODE_OFFLOAD_CONN;
        break;

    case FCOE_RAMROD_CMD_ID_ENABLE_CONN:
        kcqe.op_code = FCOE_KCQE_OPCODE_ENABLE_CONN;
        break;

    case FCOE_RAMROD_CMD_ID_DISABLE_CONN:
        kcqe.op_code = FCOE_KCQE_OPCODE_DISABLE_CONN;
        break;

    case FCOE_RAMROD_CMD_ID_TERMINATE_CONN:
        kcqe.op_code = FCOE_RAMROD_CMD_ID_TERMINATE_CONN;
        break;
    }

    lm_fc_complete_slow_path_request(pdev, &kcqe);
}

/**
 * @description
 * Returns the max FCOE task supported.
 * In oreder to know the max task enabled refer to
 * pdev->params.max_fcoe_task
 * @param pdev
 *
 * @return u32_t
 */
u32_t
lm_fc_max_fcoe_task_sup(
    IN struct _lm_device_t          *pdev)
{
    u32_t max_fcoe_task = MAX_NUM_FCOE_TASKS_PER_ENGINE;

    /* FCOE supports a maximum of MAX_FCOE_FUNCS_PER_ENGINE per engine.
     * Incase of mf / 4-port mode it means we can have more than one fcoe function
     * on an engine - in which case we'll need to divide the number of tasks between them. 
     * However, in single function mode, on a 2-port chip (i.e. one function on the engine) 
     * the fcoe function will have all the tasks allocated to it 
     */
    if (IS_MULTI_VNIC(pdev) || (CHIP_PORT_MODE(pdev) == LM_CHIP_PORT_MODE_4))
    {
        max_fcoe_task = max_fcoe_task / MAX_FCOE_FUNCS_PER_ENGINE;
    }
    
    return max_fcoe_task;
}
/**
 *
 *
 * @description
 *
 * @param pdev
 *
 * @return STATIC void
 */
STATIC void
lm_fc_init_vars(
    IN struct _lm_device_t          *pdev)
{

    if CHK_NULL(pdev)
    {
        return ;
    }

    mm_mem_zero(&pdev->fcoe_info, sizeof(lm_fcoe_info_t));
}
/**
 *
 *
 * @description
 *
 * @param pdev
 *
 * @return lm_status_t
 */
lm_status_t
lm_fc_alloc_resc(
    IN struct _lm_device_t          *pdev)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    if CHK_NULL(pdev)
    {
        return LM_STATUS_INVALID_PARAMETER;
    }
    lm_fc_init_vars(pdev);
    /* cid recycled cb registration */
    lm_cid_recycled_cb_register(pdev, FCOE_CONNECTION_TYPE, lm_fc_recycle_cid_cb);

    /* Sq-completion cb registration (sq that get completed internally in driver */
    lm_sq_comp_cb_register(pdev, FCOE_CONNECTION_TYPE, lm_fc_comp_cb);
    /* Get physical memory for RAMROD commands */
    lm_status = lm_fc_get_ramrod_phys_mem(pdev);

    if (lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }
    return LM_STATUS_SUCCESS;
} /* lm_fc_alloc_resc */




lm_status_t lm_sc_complete_l4_ofld_request(lm_device_t *pdev, struct iscsi_kcqe *kcqe)
{
    u32_t comp_status = 0;
    lm_tcp_state_t *tcp;
    u32_t cid;

    if (CHK_NULL(pdev) || CHK_NULL(kcqe))
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    cid = SW_CID(kcqe->iscsi_conn_context_id);
    tcp = lm_cid_cookie(pdev, TOE_CONNECTION_TYPE, cid);
    DbgBreakIf(!tcp);

    if (kcqe->completion_status & ISCSI_KCQE_COMPLETION_STATUS_CTX_ALLOC_FAILURE)
    {
        /* currently there is no specific completion status handling, only success / fail */
        /* but originally the flags are those of toe_initiate_offload_ramrod_data */
        comp_status = 1;
    }

    /* toe lock is taken inside */
    lm_tcp_comp_initiate_offload_request(pdev, tcp, comp_status);

    return LM_STATUS_SUCCESS;
}

lm_status_t lm_sc_complete_l4_upload_request(lm_device_t *pdev, u8_t op_code, u32_t cid)
{
    lm_status_t      lm_status = LM_STATUS_SUCCESS;
    lm_tcp_state_t * tcp       = NULL;

    tcp = lm_cid_cookie(pdev, TOE_CONNECTION_TYPE, cid);
    if (NULL == tcp)
    {
        return LM_STATUS_FAILURE;
    }

    switch (op_code)
    {
    case L5CM_RAMROD_CMD_ID_SEARCHER_DELETE:
        if (mm_sc_is_omgr_enabled(pdev))
        {
            lm_empty_ramrod_eth(pdev, OOO_CID(pdev), cid, NULL, 0 /*d/c*/);
        }
        else
        {
            lm_tcp_searcher_ramrod_complete(pdev, tcp);
        }
        break;
    case RAMROD_CMD_ID_ETH_EMPTY:
        lm_tcp_searcher_ramrod_complete(pdev, tcp);
        break;
    case L5CM_RAMROD_CMD_ID_TERMINATE_OFFLOAD:
        lm_tcp_terminate_ramrod_complete(pdev, tcp);
        break;
    case L5CM_RAMROD_CMD_ID_QUERY:
        lm_tcp_query_ramrod_complete(pdev, tcp);
        break;
    default:
        DbgMessage(pdev, WARN, "lm_sc_complete_l4_upload_request: Invalid op_code 0x%x.\n", op_code);
        return LM_STATUS_INVALID_PARAMETER;
    }

    return LM_STATUS_SUCCESS;
}



lm_status_t lm_sc_complete_slow_path_request(lm_device_t *pdev, struct iscsi_kcqe *kcqe)
{
    lm_status_t lm_status = LM_STATUS_FAILURE;
    u8_t        op_code   = 0;

    if (CHK_NULL(pdev) || CHK_NULL(kcqe))
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    op_code = kcqe->op_code; /* Store the opcode, the function below may modify it (internal searcher), need to keep for sq_complete later on  */

    switch (kcqe->op_code)
    {
/*  case ISCSI_KCQE_OPCODE_INIT:
        lm_status = mm_sc_complete_init_request(pdev, kcqe);
        if (lm_status != LM_STATUS_SUCCESS)
        {
            DbgMessage(pdev, WARN, "lm_sc_complete_slow_path_request: lm_sc_complete_init_request failed.\n");
        }
        break;
*/    case L5CM_RAMROD_CMD_ID_ADD_NEW_CONNECTION:
        lm_status = lm_sc_complete_l4_ofld_request(pdev, kcqe);
        if (lm_status != LM_STATUS_SUCCESS)
        {
            DbgMessage(pdev, WARN, "lm_sc_complete_slow_path_request: lm_sc_complete_l4_ofld_request failed.\n");
        }
        break;
    case ISCSI_KCQE_OPCODE_UPDATE_CONN:
        lm_status = mm_sc_complete_update_request(pdev, kcqe);
        if (lm_status != LM_STATUS_SUCCESS)
        {
            DbgMessage(pdev, WARN, "lm_sc_complete_slow_path_request: lm_sc_complete_update_request failed.\n");
        }
        break;
    case L5CM_RAMROD_CMD_ID_SEARCHER_DELETE:
    case L5CM_RAMROD_CMD_ID_TERMINATE_OFFLOAD:
    case L5CM_RAMROD_CMD_ID_QUERY:
        lm_status = lm_sc_complete_l4_upload_request(pdev, kcqe->op_code, SW_CID(kcqe->iscsi_conn_context_id));
        break;
    default:
        DbgMessage(pdev, WARN, "lm_sc_complete_slow_path_request: Invalid op_code 0x%x.\n", kcqe->op_code);
    }

    lm_sq_complete(pdev, CMD_PRIORITY_NORMAL, op_code,
                   ISCSI_CONNECTION_TYPE, SW_CID(kcqe->iscsi_conn_context_id));

    return lm_status;
}


/* Handle FC related ramrod completions */
lm_status_t
lm_fc_complete_slow_path_request(
    IN struct _lm_device_t          *pdev,
    IN struct fcoe_kcqe             *kcqe)
{
    lm_status_t                     lm_status    = LM_STATUS_FAILURE;
    lm_fcoe_state_t                 *fcoe        = NULL;
    const u8_t                      priority     = CMD_PRIORITY_NORMAL;
    const enum connection_type      con_type     = FCOE_CONNECTION_TYPE;
    u32_t                           cid          = 0;
    u32_t                           sw_cid       = 0;
    u8_t                            fcoe_commnad = 0;
    u8_t                            b_valid      = TRUE;

    if (CHK_NULL(pdev) || CHK_NULL(kcqe))
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    switch (kcqe->op_code)
    {
        case FCOE_KCQE_OPCODE_INIT_FUNC:
        {
            fcoe_commnad = FCOE_RAMROD_CMD_ID_INIT_FUNC;
            lm_status    = mm_fc_complete_init_request(pdev, kcqe);
            cid          = LM_CLI_CID(pdev, LM_CLI_IDX_FCOE);
            break;
        }
        case FCOE_KCQE_OPCODE_OFFLOAD_CONN:
        {
            fcoe_commnad = FCOE_RAMROD_CMD_ID_OFFLOAD_CONN;

            DbgBreakIf(0 != mm_le32_to_cpu(kcqe->completion_status)); /* offload should never fail */

            sw_cid = SW_CID(mm_le32_to_cpu(kcqe->fcoe_conn_context_id));
            fcoe   = lm_cid_cookie(pdev, con_type, sw_cid);

            if(!fcoe)
            {
                lm_status = LM_STATUS_RESOURCE;
                DbgBreakIf(!fcoe);
                break;
            }

            cid       = fcoe->cid;
            lm_status = mm_fc_complete_ofld_request(pdev, fcoe, kcqe);
            break;
        }
        case FCOE_KCQE_OPCODE_ENABLE_CONN:
        {
            fcoe_commnad = FCOE_RAMROD_CMD_ID_ENABLE_CONN;

            DbgBreakIf(0 != mm_le32_to_cpu(kcqe->completion_status)); /* enable should never fail */

            sw_cid = SW_CID(mm_le32_to_cpu(kcqe->fcoe_conn_context_id));
            fcoe   = lm_cid_cookie(pdev, con_type, sw_cid);

            if(!fcoe)
            {
                lm_status = LM_STATUS_RESOURCE;
                DbgBreakIf(!fcoe);
                break;
            }
            cid    = fcoe->cid;

            lm_status = mm_fc_complete_enable_request(pdev, fcoe, kcqe);
            break;
        }
        case FCOE_KCQE_OPCODE_DISABLE_CONN:
        {
            fcoe_commnad = FCOE_RAMROD_CMD_ID_DISABLE_CONN;

            /* Disable is complete, now we need to send the terminate ramrod */
            DbgBreakIf(0 != mm_le32_to_cpu(kcqe->completion_status)); /* disable should never fail */

            sw_cid = SW_CID(mm_le32_to_cpu(kcqe->fcoe_conn_context_id));
            fcoe   = lm_cid_cookie(pdev, con_type, sw_cid);

            if(!fcoe)
            {
                lm_status = LM_STATUS_RESOURCE;
                DbgBreakIf(!fcoe);
                break;
            }

            cid          = fcoe->cid;
            lm_status    = mm_fc_complete_disable_request(pdev, fcoe, kcqe);
            break;
        }
        case FCOE_KCQE_OPCODE_DESTROY_FUNC:
        {
            fcoe_commnad = FCOE_RAMROD_CMD_ID_DESTROY_FUNC;
            lm_status    = mm_fc_complete_destroy_request(pdev, kcqe);
            cid          = LM_CLI_CID(pdev, LM_CLI_IDX_FCOE);
            break;
        }
        case FCOE_KCQE_OPCODE_STAT_FUNC:
        {
            fcoe_commnad = FCOE_RAMROD_CMD_ID_STAT_FUNC;
            lm_status    = mm_fc_complete_stat_request(pdev, kcqe);
            cid          = LM_CLI_CID(pdev, LM_CLI_IDX_FCOE);
            break;
        }
        case FCOE_RAMROD_CMD_ID_TERMINATE_CONN: /* Internal VBD not passed up... */
        {
            fcoe_commnad = FCOE_RAMROD_CMD_ID_TERMINATE_CONN;

            /* Terminate is complete, now we need to send the CFC delete ramrod */
            DbgBreakIf(0 != mm_le32_to_cpu(kcqe->completion_status)); /* terminate should never fail */

            sw_cid = SW_CID(mm_le32_to_cpu(kcqe->fcoe_conn_context_id));

            fcoe = lm_cid_cookie(pdev, con_type, sw_cid);

            if(!fcoe)
            {
                lm_status = LM_STATUS_RESOURCE;
                DbgBreakIf(!fcoe);
                break;
            }

            cid = fcoe->cid;

            lm_status = mm_fc_complete_terminate_request(pdev, fcoe, kcqe);
            break;
        }
        default:
        {
            DbgMessage(pdev, WARN, "lm_fc_complete_slow_path_request: Invalid op_code 0x%x.\n", kcqe->op_code);
            b_valid = FALSE;
            break;
        }
    }

    if( b_valid )
    {
        lm_sq_complete(pdev, priority, fcoe_commnad, con_type, cid);
    }

    return lm_status;
}

u8_t lm_sc_is_eq_completion(lm_device_t *pdev, u8_t sb_idx)
{
    u8_t result = FALSE;
    lm_eq_chain_t *eq = NULL;

    DbgBreakIf(!(pdev && ARRSIZE(pdev->iscsi_info.run_time.eq_chain) > sb_idx));

    eq = &LM_SC_EQ(pdev, sb_idx);

    if (eq->hw_con_idx_ptr &&
        mm_le16_to_cpu(*eq->hw_con_idx_ptr) != lm_bd_chain_cons_idx(&eq->bd_chain) )
    {
        result = TRUE;
    }
    DbgMessage(pdev, INFORMl5, "lm_sc_is_rx_completion(): result is:%s\n", result? "TRUE" : "FALSE");

    return result;
}



u8_t
lm_fc_is_eq_completion(lm_device_t *pdev, u8_t sb_idx)
{
    u8_t result = FALSE;
    lm_eq_chain_t *eq = NULL;

    DbgBreakIf(!(pdev && ARRSIZE(pdev->fcoe_info.run_time.eq_chain) > sb_idx));

    eq = &LM_FC_EQ(pdev, sb_idx);

    if (eq->hw_con_idx_ptr &&
        mm_le16_to_cpu(*eq->hw_con_idx_ptr) != lm_bd_chain_cons_idx(&eq->bd_chain))
    {
        result = TRUE;
    }

    DbgMessage(pdev, INFORMl5, "lm_fc_is_rx_completion(): result is:%s\n", result? "TRUE" : "FALSE");

    return result;
}



lm_status_t
lm_sc_handle_tcp_event(
    IN    lm_device_t *pdev,
    IN    u32_t cid,
    IN    u32_t op_code
    )
{
    lm_tcp_state_t *tcp = NULL;

    if CHK_NULL(pdev)
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    tcp = lm_cid_cookie(pdev, TOE_CONNECTION_TYPE, cid);
    if CHK_NULL(tcp)
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    switch (op_code)
    {
    case ISCSI_KCQE_OPCODE_TCP_FIN:
        tcp->tcp_state_calc.fin_reception_time = mm_get_current_time(pdev);
        break;
    case ISCSI_KCQE_OPCODE_TCP_RESET:
        tcp->tcp_state_calc.con_rst_flag = TRUE;
        break;
    default:
        DbgMessage(pdev, WARN, "lm_sc_handle_tcp_event: Invalid op_code 0x%x\n", op_code);
        return LM_STATUS_INVALID_PARAMETER;
    }

    return LM_STATUS_SUCCESS;
}

lm_status_t
lm_sc_comp_l5_request(
    IN    lm_device_t *pdev,
    IN    lm_eq_chain_t *eq_chain,
    INOUT struct iscsi_kcqe **l5_kcqe_start,
    INOUT u16_t *l5_kcqe_num)
{
    lm_status_t lm_status;

    if (CHK_NULL(pdev) || CHK_NULL(eq_chain) || CHK_NULL(l5_kcqe_start) || CHK_NULL(l5_kcqe_num))
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    lm_status = mm_sc_comp_l5_request(pdev, *l5_kcqe_start, *l5_kcqe_num);
    if (lm_status != LM_STATUS_SUCCESS)
    {
        DbgMessage(pdev, WARN, "lm_sc_service_eq_intr: mm_sc_comp_l5_request failed.\n");
    }

    lm_bd_chain_bds_produced(&eq_chain->bd_chain, *l5_kcqe_num);
    *l5_kcqe_num = 0;
    *l5_kcqe_start = NULL;

    return lm_status;
}



lm_status_t
lm_fc_comp_request(
    IN    lm_device_t       *pdev,
    IN    lm_eq_chain_t     *eq_chain,
    INOUT struct fcoe_kcqe  **fcoe_kcqe_start,
    INOUT u16_t             *fcoe_kcqe_num)
{
    lm_status_t lm_status;

    if (CHK_NULL(pdev) || CHK_NULL(eq_chain) || CHK_NULL(fcoe_kcqe_start) || CHK_NULL(fcoe_kcqe_num))
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    lm_status = mm_fc_comp_request(pdev, *fcoe_kcqe_start, *fcoe_kcqe_num);
    if (lm_status != LM_STATUS_SUCCESS)
    {
        DbgMessage(pdev, WARN, "lm_fc_service_eq_intr: lm_fc_comp_request failed.\n");
    }

    lm_bd_chain_bds_produced(&eq_chain->bd_chain, *fcoe_kcqe_num);
    *fcoe_kcqe_num = 0;
    *fcoe_kcqe_start = NULL;

    return lm_status;
}




void
lm_sc_service_eq_intr(
    IN struct _lm_device_t          *pdev,
    IN u8_t                         sb_idx)
{
    lm_status_t         lm_status;
    lm_eq_chain_t *eq_chain       = NULL;
    struct iscsi_kcqe   *kcqe           = NULL;
    struct iscsi_kcqe   *l5_kcqe_start  = NULL;
    u16_t               l5_kcqe_num     = 0;
    u16_t               eq_new_idx      = 0;
    u16_t               eq_old_idx      = 0;
    u32_t               eq_num          = 0;
    u32_t               cid             = 0;


    if (CHK_NULL(pdev) || (ARRSIZE(pdev->iscsi_info.run_time.eq_chain) <= sb_idx))
    {
        DbgBreakIf(ARRSIZE(pdev->iscsi_info.run_time.eq_chain) <= sb_idx);
        DbgBreakIf(!pdev);
        return;
    }

    eq_chain = &LM_SC_EQ(pdev, sb_idx);

    eq_new_idx = mm_le16_to_cpu(*(eq_chain->hw_con_idx_ptr));
    eq_old_idx = lm_bd_chain_cons_idx(&eq_chain->bd_chain);
    DbgBreakIf(S16_SUB(eq_new_idx, eq_old_idx) < 0);

    while (eq_old_idx != eq_new_idx)
    {
        DbgBreakIf(S16_SUB(eq_new_idx, eq_old_idx) <= 0);

        /* get next consumed kcqe */
        kcqe = (struct iscsi_kcqe *)lm_bd_chain_consume_bd_contiguous(&eq_chain->bd_chain);

        /* we got to the end of the page, if we have some kcqe that we need to indicate, */
        /* do it now, cause we can't assume that the memorey of the pages is contiguous */
        if (kcqe == NULL)
        {
            if (l5_kcqe_num != 0)
            {
                lm_status = lm_sc_comp_l5_request(pdev, eq_chain, &l5_kcqe_start, &l5_kcqe_num);
            }

            /* check cons index again */
            eq_old_idx = lm_bd_chain_cons_idx(&eq_chain->bd_chain);

            if (eq_old_idx != eq_new_idx)
            {
                /* get next consumed cqe */
                kcqe = (struct iscsi_kcqe *)lm_bd_chain_consume_bd_contiguous(&eq_chain->bd_chain);

                if (CHK_NULL(kcqe))
                {
                    /* shouldn't have happened, got second null from the bd */
                    DbgBreakIf(!kcqe);
                    break;
                }
            }
            else
            {
                /* the new kcqe was the last one we got, break */
                break;
            }
        }

        switch (kcqe->op_code)
        {
        case ISCSI_RAMROD_CMD_ID_INIT:
        case L5CM_RAMROD_CMD_ID_ADD_NEW_CONNECTION:
        case ISCSI_RAMROD_CMD_ID_UPDATE_CONN:
        case L5CM_RAMROD_CMD_ID_SEARCHER_DELETE:
        case L5CM_RAMROD_CMD_ID_TERMINATE_OFFLOAD:
        case L5CM_RAMROD_CMD_ID_QUERY:

            /* first, complete fast path and error indication, if any */
            if (l5_kcqe_num != 0)
            {
                lm_status = lm_sc_comp_l5_request(pdev, eq_chain, &l5_kcqe_start, &l5_kcqe_num);
            }

            lm_status = lm_sc_complete_slow_path_request(pdev, kcqe);
            if (lm_status != LM_STATUS_SUCCESS)
            {
                DbgMessage(pdev, WARN, "lm_sc_service_eq_intr: mm_sc_comp_l5_request failed.\n");
            }

            lm_bd_chain_bds_produced(&eq_chain->bd_chain, 1);
            break;

        case ISCSI_KCQE_OPCODE_TCP_FIN:
        case ISCSI_KCQE_OPCODE_TCP_RESET:
            cid = SW_CID(kcqe->iscsi_conn_context_id);

            lm_sc_handle_tcp_event(pdev, cid, kcqe->op_code);
            /* FALLTHROUGH */
        default:
            if (l5_kcqe_start == NULL)
            {
                l5_kcqe_start = kcqe;
            }

            l5_kcqe_num++;
            break;
        }

        eq_old_idx = lm_bd_chain_cons_idx(&eq_chain->bd_chain);
    }

    /* complete left fast path events */
    if (l5_kcqe_num != 0)
    {
        lm_status = lm_sc_comp_l5_request(pdev, eq_chain, &l5_kcqe_start, &l5_kcqe_num);
    }

    /* update EQ prod in RAM */
    eq_num = sb_idx - pdev->iscsi_info.run_time.l5_eq_base_chain_idx;
    LM_INTMEM_WRITE16(pdev, CSTORM_ISCSI_EQ_PROD_OFFSET(FUNC_ID(pdev), eq_num), lm_bd_chain_prod_idx(&eq_chain->bd_chain), BAR_CSTRORM_INTMEM);
}



void
lm_fc_service_eq_intr(lm_device_t *pdev, u8_t sb_idx)
{
    lm_status_t         lm_status;
    lm_eq_chain_t       *eq_chain       = NULL;
    struct fcoe_kcqe    *kcqe           = NULL;
    struct fcoe_kcqe    *fcoe_kcqe_start= NULL;
    u16_t               fcoe_kcqe_num   = 0;
    u16_t               eq_new_idx      = 0;
    u16_t               eq_old_idx      = 0;

    if (CHK_NULL(pdev) || (ARRSIZE(pdev->fcoe_info.run_time.eq_chain) <= sb_idx))
    {
        DbgBreakIf(ARRSIZE(pdev->fcoe_info.run_time.eq_chain) <= sb_idx);
        DbgBreakIf(!pdev);
        return;
    }

    eq_chain = &LM_FC_EQ(pdev, sb_idx);

    eq_new_idx = mm_le16_to_cpu(*(eq_chain->hw_con_idx_ptr));
    eq_old_idx = lm_bd_chain_cons_idx(&eq_chain->bd_chain);
    DbgBreakIf(S16_SUB(eq_new_idx, eq_old_idx) < 0);

    while (eq_old_idx != eq_new_idx)
    {
        DbgBreakIf(S16_SUB(eq_new_idx, eq_old_idx) <= 0);

        /* get next consumed kcqe */
        kcqe = (struct fcoe_kcqe *)lm_bd_chain_consume_bd_contiguous(&eq_chain->bd_chain);

        /* we got to the end of the page, if we have some kcqe that we need to indicate, */
        /* do it now, cause we can't assume that the memorey of the pages is contiguous */
        if (kcqe == NULL)
        {
            if (fcoe_kcqe_num != 0)
            {
                lm_status = lm_fc_comp_request(pdev,
                                               eq_chain,
                                               &fcoe_kcqe_start,
                                               &fcoe_kcqe_num);
            }

            /* check cons index again */
            eq_old_idx = lm_bd_chain_cons_idx(&eq_chain->bd_chain);

            if (eq_old_idx != eq_new_idx)
            {
                /* get next consumed cqe */
                kcqe = (struct fcoe_kcqe *)lm_bd_chain_consume_bd(&eq_chain->bd_chain);

                if (CHK_NULL(kcqe))
                {
                    /* shouldn't have happened, got second null from the bd */
                    DbgBreakIf(!kcqe);
                    break;
                }
            }
            else
            {
                /* the new kcqe was the last one we got, break */
                break;
            }
        }

        /* first, complete fast path completion notification and error indication, if any */
        if (fcoe_kcqe_num != 0)
        {
            lm_status = lm_fc_comp_request(pdev,
                                           eq_chain,
                                           &fcoe_kcqe_start,
                                           &fcoe_kcqe_num);
        }

        switch (kcqe->op_code)
        {
            case FCOE_KCQE_OPCODE_INIT_FUNC:
            case FCOE_KCQE_OPCODE_OFFLOAD_CONN:
            case FCOE_KCQE_OPCODE_ENABLE_CONN:
            case FCOE_KCQE_OPCODE_DISABLE_CONN:
            case FCOE_KCQE_OPCODE_DESTROY_FUNC:
            case FCOE_KCQE_OPCODE_STAT_FUNC:
            case FCOE_RAMROD_CMD_ID_TERMINATE_CONN:
            {
                lm_status = lm_fc_complete_slow_path_request(pdev, kcqe);
                if (lm_status != LM_STATUS_SUCCESS)
                {
                    DbgMessage(pdev, WARN, "lm_fc_service_eq_intr: lm_fc_complete_slow_path_request failed.\n");
                }

                lm_bd_chain_bds_produced(&eq_chain->bd_chain, 1);
                break;
            }

            default:
            {
                if (fcoe_kcqe_start == NULL)
                {
                    fcoe_kcqe_start = kcqe;
                }

                fcoe_kcqe_num++;
                break;
            }
        }

        eq_old_idx = lm_bd_chain_cons_idx(&eq_chain->bd_chain);
    }

    /* complete left fast path events */
    if (fcoe_kcqe_num != 0)
    {
        lm_status = lm_fc_comp_request(pdev, eq_chain, &fcoe_kcqe_start, &fcoe_kcqe_num);
    }

    /* update EQ prod in RAM */
    LM_INTMEM_WRITE16(pdev, USTORM_FCOE_EQ_PROD_OFFSET(FUNC_ID(pdev)), lm_bd_chain_prod_idx(&eq_chain->bd_chain), BAR_USTRORM_INTMEM);
}


lm_status_t
lm_sc_alloc_con_phys_mem(
    IN struct _lm_device_t          *pdev,
    IN lm_iscsi_state_t             *iscsi)
{
    lm_status_t lm_status  = LM_STATUS_SUCCESS;
    u32_t       mem_size   = sizeof(*iscsi->sp_req_data.virt_addr);
    u8_t        mm_cli_idx = LM_RESOURCE_ISCSI;


    /* Allocate slopwath request data */
    iscsi->sp_req_data.virt_addr = mm_rt_alloc_phys_mem(pdev,
                                                        mem_size,
                                                        &iscsi->sp_req_data.phys_addr,
                                                        0,
                                                        mm_cli_idx);
    if CHK_NULL(iscsi->sp_req_data.virt_addr)
    {   /* can't allocate task array */
        return LM_STATUS_RESOURCE;
    }

    mm_memset(iscsi->sp_req_data.virt_addr, 0, mem_size);

    /* Allocate task array */
    iscsi->task_array.base_size = pdev->iscsi_info.run_time.num_of_tasks * sizeof(struct iscsi_task_context_entry);
    iscsi->task_array.base_virt = mm_rt_alloc_phys_mem(pdev,
                                                iscsi->task_array.base_size,
                                                &iscsi->task_array.base_phy,
                                                0,
                                                mm_cli_idx);
    if CHK_NULL(iscsi->task_array.base_virt)
    {   /* can't allocate task array */
        return LM_STATUS_RESOURCE;
    }

    mm_memset(iscsi->task_array.base_virt, 0, iscsi->task_array.base_size);

    lm_status = lm_create_pbl(pdev,
                              iscsi->task_array.base_virt,
                              &iscsi->task_array.base_phy,
                              iscsi->task_array.base_size,
                              &iscsi->task_array.pbl_phys_table_virt,
                              &iscsi->task_array.pbl_phys_table_phys,
                              &iscsi->task_array.pbl_virt_table,
                              &iscsi->task_array.pbl_entries,
                              &iscsi->task_array.pbl_size,
                              TRUE,
                              LM_RESOURCE_ISCSI);
    if (lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    /* Allocate R2TQ */
    iscsi->r2tq.base_size = pdev->iscsi_info.run_time.num_of_tasks * ISCSI_MAX_NUM_OF_PENDING_R2TS * ISCSI_R2TQE_SIZE;
    iscsi->r2tq.base_virt = mm_rt_alloc_phys_mem(pdev,
                                                iscsi->r2tq.base_size,
                                                &iscsi->r2tq.base_phy,
                                                0,
                                                mm_cli_idx);
    if CHK_NULL(iscsi->r2tq.base_virt)
    {   /* can't allocate R2TQ */
        return LM_STATUS_RESOURCE;
    }

    mm_memset(iscsi->r2tq.base_virt, 0, iscsi->r2tq.base_size);

    lm_status = lm_create_pbl(pdev,
                              iscsi->r2tq.base_virt,
                              &iscsi->r2tq.base_phy,
                              iscsi->r2tq.base_size,
                              &iscsi->r2tq.pbl_phys_table_virt,
                              &iscsi->r2tq.pbl_phys_table_phys,
                              &iscsi->r2tq.pbl_virt_table,
                              &iscsi->r2tq.pbl_entries,
                              &iscsi->r2tq.pbl_size,
                              TRUE,
                              LM_RESOURCE_ISCSI);
    if (lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    /* Allocate HQ */
    iscsi->hq.base_size = pdev->iscsi_info.run_time.hq_size * sizeof(struct iscsi_hq_bd);
    iscsi->hq.base_virt = mm_rt_alloc_phys_mem(pdev,
                                                iscsi->hq.base_size,
                                                &iscsi->hq.base_phy,
                                                0,
                                                mm_cli_idx);
    if CHK_NULL(iscsi->hq.base_virt)
    {   /* can't allocate HQ */

        return LM_STATUS_RESOURCE;
    }

    mm_memset(iscsi->hq.base_virt, 0, iscsi->hq.base_size);

    lm_status = lm_create_pbl(pdev,
                              iscsi->hq.base_virt,
                              &iscsi->hq.base_phy,
                              iscsi->hq.base_size,
                              &iscsi->hq.pbl_phys_table_virt,
                              &iscsi->hq.pbl_phys_table_phys,
                              &iscsi->hq.pbl_virt_table,
                              &iscsi->hq.pbl_entries,
                              &iscsi->hq.pbl_size,
                              TRUE,
                              LM_RESOURCE_ISCSI);
    if (lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    return lm_status;

}
/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t
lm_sc_alloc_con_resc(
    IN struct _lm_device_t          *pdev,
    IN lm_iscsi_state_t             *iscsi,
    IN struct iscsi_kwqe_conn_offload1   *req1,
    IN struct iscsi_kwqe_conn_offload2   *req2,
    IN struct iscsi_kwqe_conn_offload3   *req3
    )
{
    lm_status_t lm_status;
    s32_t cid;

    if (CHK_NULL(pdev) || CHK_NULL(iscsi) || CHK_NULL(req1) || CHK_NULL(req2) || CHK_NULL(req3))
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    DbgMessage(pdev, INFORM, "### lm_sc_alloc_con_resc\n");

    /* save the miniport's conn id */
    iscsi->iscsi_conn_id = req1->iscsi_conn_id;

    /* Boot connections physical resources are allocated during bind, and not during offload... */
    if (!iscsi->b_resources_allocated)
    {
        lm_status = lm_sc_alloc_con_phys_mem(pdev, iscsi);
        if (lm_status != LM_STATUS_SUCCESS)
        {
            lm_sc_free_con_resc(pdev, iscsi);
            return lm_status;
        }
        iscsi->b_resources_allocated = TRUE;
    }


    /* Allocate CID */
    lm_status = lm_allocate_cid(pdev, ISCSI_CONNECTION_TYPE, (void *)iscsi, &cid);
    if (lm_status == LM_STATUS_PENDING)
    {
        lm_sp_req_manager_block(pdev, (u32_t)cid);
    }
    else if (lm_status != LM_STATUS_SUCCESS)
    {
        /* failed to allocate CID */
        lm_sc_free_con_resc(pdev, iscsi);

        return lm_status;
    }

    /* save the returned cid */
    iscsi->cid = (u32_t)cid;

    /* the allocated slow path request phys data for iscsi will be used in the tcp_state.sp_data, for the query request */
    lm_status = lm_sp_req_manager_set_sp_data(pdev, iscsi->cid, iscsi->sp_req_data.virt_addr, iscsi->sp_req_data.phys_addr);
    if (lm_status != LM_STATUS_SUCCESS)
    {
        lm_sc_free_con_resc(pdev, iscsi);

        return lm_status;
    }

    if (lm_cid_state(pdev, iscsi->cid) == LM_CID_STATE_PENDING) {
        return LM_STATUS_PENDING; /* Too soon to initialize context */
    }

    return LM_STATUS_SUCCESS;
} /* lm_sc_alloc_con_resc */


void lm_sc_free_con_phys_mem(
    IN struct _lm_device_t *pdev,
    IN lm_iscsi_state_t *iscsi
    )
{
    u8_t mm_cli_idx = LM_RESOURCE_ISCSI;

    if (iscsi->sp_req_data.virt_addr)
    {
        mm_rt_free_phys_mem(pdev, sizeof(*iscsi->sp_req_data.virt_addr), iscsi->sp_req_data.virt_addr, iscsi->sp_req_data.phys_addr, mm_cli_idx);
        iscsi->sp_req_data.virt_addr = NULL;
    }
    if (iscsi->task_array.base_virt) {
        mm_rt_free_phys_mem(pdev, iscsi->task_array.base_size, iscsi->task_array.base_virt, iscsi->task_array.base_phy, mm_cli_idx);
        iscsi->task_array.base_virt = NULL;
    }
    if (iscsi->task_array.pbl_phys_table_virt) {
        mm_rt_free_phys_mem(pdev, iscsi->task_array.pbl_size, iscsi->task_array.pbl_phys_table_virt, iscsi->task_array.pbl_phys_table_phys, mm_cli_idx);
        iscsi->task_array.pbl_phys_table_virt = NULL;
    }
    if (iscsi->task_array.pbl_virt_table) {
        mm_rt_free_mem(pdev, iscsi->task_array.pbl_virt_table, iscsi->task_array.pbl_entries * sizeof(void *), mm_cli_idx);
        iscsi->task_array.pbl_virt_table = NULL;
    }
    if (iscsi->r2tq.base_virt) {
        mm_rt_free_phys_mem(pdev, iscsi->r2tq.base_size, iscsi->r2tq.base_virt, iscsi->r2tq.base_phy, mm_cli_idx);
        iscsi->r2tq.base_virt = NULL;
    }
    if (iscsi->r2tq.pbl_phys_table_virt) {
        mm_rt_free_phys_mem(pdev, iscsi->r2tq.pbl_size, iscsi->r2tq.pbl_phys_table_virt, iscsi->r2tq.pbl_phys_table_phys, mm_cli_idx);
        iscsi->r2tq.pbl_phys_table_virt = NULL;
    }
    if (iscsi->r2tq.pbl_virt_table) {
        mm_rt_free_mem(pdev, iscsi->r2tq.pbl_virt_table, iscsi->r2tq.pbl_entries * sizeof(void *), mm_cli_idx);
        iscsi->r2tq.pbl_virt_table = NULL;
    }
    if (iscsi->hq.base_virt) {
        mm_rt_free_phys_mem(pdev, iscsi->hq.base_size, iscsi->hq.base_virt, iscsi->hq.base_phy, mm_cli_idx);
        iscsi->hq.base_virt = NULL;
    }
    if (iscsi->hq.pbl_phys_table_virt) {
        mm_rt_free_phys_mem(pdev, iscsi->hq.pbl_size, iscsi->hq.pbl_phys_table_virt, iscsi->hq.pbl_phys_table_phys, mm_cli_idx);
        iscsi->hq.pbl_phys_table_virt = NULL;
    }
    if (iscsi->hq.pbl_virt_table) {
        mm_rt_free_mem(pdev, iscsi->hq.pbl_virt_table, iscsi->hq.pbl_entries * sizeof(void *), mm_cli_idx);
        iscsi->hq.pbl_virt_table = NULL;
    }

}
/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t lm_sc_free_con_resc(
    IN struct _lm_device_t *pdev,
    IN lm_iscsi_state_t *iscsi
    )
{
    u8_t notify_fw = 1;

    if (CHK_NULL(pdev) || CHK_NULL(iscsi))
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    if (iscsi->cid != 0) {
        if (iscsi->hdr.status == STATE_STATUS_INIT_OFFLOAD_ERR) {
            notify_fw = 0;
        }
        lm_free_cid_resc(pdev, ISCSI_CONNECTION_TYPE, iscsi->cid, notify_fw);
        iscsi->cid = 0;
    }

    if (!iscsi->b_keep_resources)
    {
        lm_sc_free_con_phys_mem(pdev, iscsi);
    }

    return LM_STATUS_SUCCESS;
}


/* Free the ramrod memory and the CID */
lm_status_t
lm_fc_free_con_resc(
    IN struct _lm_device_t          *pdev,
    IN lm_fcoe_state_t              *fcoe)
{
    u8_t                            notify_fw = 1;

    if (CHK_NULL(pdev) || CHK_NULL(fcoe))
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    if (fcoe->cid != 0)
    {
        if (fcoe->hdr.status == STATE_STATUS_INIT_OFFLOAD_ERR)
        {
            notify_fw = 0;
        }

        lm_free_cid_resc(pdev, FCOE_CONNECTION_TYPE, fcoe->cid, notify_fw);

        fcoe->hdr.state_blk = NULL;
        fcoe->cid = 0;
        fcoe->ctx_virt = NULL;
        fcoe->ctx_phys.as_u64 = 0;
    }

    return LM_STATUS_SUCCESS;
}



/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
lm_status_t lm_sc_init_iscsi_context(
    IN struct _lm_device_t      *pdev,
    IN lm_iscsi_state_t         *iscsi,
    struct iscsi_kwqe_conn_offload1  *req1,
    struct iscsi_kwqe_conn_offload2  *req2,
    struct iscsi_kwqe_conn_offload3  *req3
    )
{
    struct iscsi_context *ctx;
    u32_t cid;
    u32_t cq_size_in_bytes;
    u32_t single_cq_pbl_entries;
    u32_t i;
    u16_t conn_id;
    lm_address_t pbl_base;

    if (CHK_NULL(pdev) || CHK_NULL(iscsi) || CHK_NULL(req1) || CHK_NULL(req2) || CHK_NULL(req3))
    {
        return LM_STATUS_INVALID_PARAMETER;
    }


    conn_id = req1->iscsi_conn_id;
    cid = iscsi->cid;

    DbgMessage(pdev, INFORM, "### lm_sc_init_iscsi_context\n");

    if (req2->num_additional_wqes != 1)
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    /* get context */
    iscsi->ctx_virt = (struct iscsi_context *)lm_get_context(pdev, iscsi->cid);
    DbgBreakIf(!iscsi->ctx_virt);
    iscsi->ctx_phys.as_u64 = lm_get_context_phys(pdev, iscsi->cid);
    DbgBreakIf(!iscsi->ctx_phys.as_u64);
    DbgMessage(pdev, VERBOSEl5sp,
                "iscsi->ctx_virt=%p, iscsi->ctx_phys_high=%x, iscsi->ctx_phys_low=%x\n",
                iscsi->ctx_virt, iscsi->ctx_phys.as_u32.high, iscsi->ctx_phys.as_u32.low);

    ctx = iscsi->ctx_virt;

    mm_memset(ctx, 0, sizeof(struct iscsi_context));

    // init xstorm aggregative context
    ctx->xstorm_ag_context.hq_prod = 1; //this value represents actual hq_prod + 1

    // init xstorm storm context
    //iscsi context
    ctx->xstorm_st_context.iscsi.first_burst_length = ISCSI_DEFAULT_FIRST_BURST_LENGTH;
    ctx->xstorm_st_context.iscsi.max_send_pdu_length = ISCSI_DEFAULT_MAX_PDU_LENGTH;

    /* advance the SQ pbl_base cause it's pointing the SQ_DB */
    pbl_base.as_u32.low = req1->sq_page_table_addr_lo;
    pbl_base.as_u32.high = req1->sq_page_table_addr_hi;
    LM_INC64(&pbl_base, ISCSI_SQ_DB_SIZE);
    ctx->xstorm_st_context.iscsi.sq_pbl_base.lo = pbl_base.as_u32.low;
    ctx->xstorm_st_context.iscsi.sq_pbl_base.hi = pbl_base.as_u32.high;

    //!!DP
    ctx->xstorm_st_context.iscsi.sq_curr_pbe.lo = req2->sq_first_pte.lo;
    ctx->xstorm_st_context.iscsi.sq_curr_pbe.hi = req2->sq_first_pte.hi;

    ctx->xstorm_st_context.iscsi.hq_pbl_base.lo = iscsi->hq.pbl_phys_table_phys.as_u32.low;
    ctx->xstorm_st_context.iscsi.hq_pbl_base.hi = iscsi->hq.pbl_phys_table_phys.as_u32.high;
    ctx->xstorm_st_context.iscsi.hq_curr_pbe_base.lo = iscsi->hq.pbl_phys_table_virt[0].as_u32.low;
    ctx->xstorm_st_context.iscsi.hq_curr_pbe_base.hi = iscsi->hq.pbl_phys_table_virt[0].as_u32.high;

    ctx->xstorm_st_context.iscsi.r2tq_pbl_base.lo = iscsi->r2tq.pbl_phys_table_phys.as_u32.low;
    ctx->xstorm_st_context.iscsi.r2tq_pbl_base.hi = iscsi->r2tq.pbl_phys_table_phys.as_u32.high;
    ctx->xstorm_st_context.iscsi.r2tq_curr_pbe_base.lo = iscsi->r2tq.pbl_phys_table_virt[0].as_u32.low;
    ctx->xstorm_st_context.iscsi.r2tq_curr_pbe_base.hi = iscsi->r2tq.pbl_phys_table_virt[0].as_u32.high;

    ctx->xstorm_st_context.iscsi.task_pbl_base.lo = iscsi->task_array.pbl_phys_table_phys.as_u32.low;
    ctx->xstorm_st_context.iscsi.task_pbl_base.hi = iscsi->task_array.pbl_phys_table_phys.as_u32.high;
    ctx->xstorm_st_context.iscsi.task_pbl_cache_idx = ISCSI_PBL_NOT_CACHED;
    //ctx->xstorm_st_context.iscsi.max_outstanding_r2ts = ISCSI_DEFAULT_MAX_OUTSTANDING_R2T;
    SET_FIELD(ctx->xstorm_st_context.iscsi.flags.flags, XSTORM_ISCSI_CONTEXT_FLAGS_B_IMMEDIATE_DATA, ISCSI_DEFAULT_IMMEDIATE_DATA);
    SET_FIELD(ctx->xstorm_st_context.iscsi.flags.flags, XSTORM_ISCSI_CONTEXT_FLAGS_B_INITIAL_R2T, ISCSI_DEFAULT_INITIAL_R2T);
    SET_FIELD(ctx->xstorm_st_context.iscsi.flags.flags, XSTORM_ISCSI_CONTEXT_FLAGS_B_EN_HEADER_DIGEST, ISCSI_DEFAULT_HEADER_DIGEST);
    SET_FIELD(ctx->xstorm_st_context.iscsi.flags.flags, XSTORM_ISCSI_CONTEXT_FLAGS_B_EN_DATA_DIGEST, ISCSI_DEFAULT_DATA_DIGEST);

    // init tstorm storm context
    ctx->tstorm_st_context.iscsi.hdr_bytes_2_fetch = ISCSI_HEADER_SIZE + (ISCSI_DEFAULT_HEADER_DIGEST ? ISCSI_DIGEST_SIZE : 0);
    SET_FIELD(ctx->tstorm_st_context.iscsi.flags, TSTORM_ISCSI_ST_CONTEXT_SECTION_B_HDR_DIGEST_EN, ISCSI_DEFAULT_HEADER_DIGEST);
    SET_FIELD(ctx->tstorm_st_context.iscsi.flags, TSTORM_ISCSI_ST_CONTEXT_SECTION_B_DATA_DIGEST_EN, ISCSI_DEFAULT_DATA_DIGEST);
    ctx->tstorm_st_context.iscsi.rq_db_phy_addr.lo = req2->rq_page_table_addr_lo;
    ctx->tstorm_st_context.iscsi.rq_db_phy_addr.hi = req2->rq_page_table_addr_hi;
    ctx->tstorm_st_context.iscsi.iscsi_conn_id = conn_id;

    //To enable the timer block.
    SET_FIELD(ctx->timers_context.flags, TIMERS_BLOCK_CONTEXT_CONN_VALID_FLG, 1);

    // init ustorm storm context
    cq_size_in_bytes = pdev->iscsi_info.run_time.cq_size * ISCSI_CQE_SIZE;
    single_cq_pbl_entries = lm_get_pbl_entries(cq_size_in_bytes);

    ctx->ustorm_st_context.task_pbe_cache_index = ISCSI_PBL_NOT_CACHED;
    ctx->ustorm_st_context.task_pdu_cache_index = ISCSI_PDU_HEADER_NOT_CACHED;

    /* advance the RQ pbl_base cause it's pointing the RQ_DB  */
    pbl_base.as_u32.low = req2->rq_page_table_addr_lo;
    pbl_base.as_u32.high = req2->rq_page_table_addr_hi;
    LM_INC64(&pbl_base, ISCSI_RQ_DB_SIZE);
    ctx->ustorm_st_context.ring.rq.pbl_base.lo = pbl_base.as_u32.low;
    ctx->ustorm_st_context.ring.rq.pbl_base.hi = pbl_base.as_u32.high;

    //!!DP
    /* qp_first_pte[0] will contain the first PTE of the RQ */
    ctx->ustorm_st_context.ring.rq.curr_pbe.lo = req3->qp_first_pte[0].lo;
    ctx->ustorm_st_context.ring.rq.curr_pbe.hi = req3->qp_first_pte[0].hi;

    ctx->ustorm_st_context.ring.r2tq.pbl_base.lo = iscsi->r2tq.pbl_phys_table_phys.as_u32.low;
    ctx->ustorm_st_context.ring.r2tq.pbl_base.hi = iscsi->r2tq.pbl_phys_table_phys.as_u32.high;
    ctx->ustorm_st_context.ring.r2tq.curr_pbe.lo = iscsi->r2tq.pbl_phys_table_virt[0].as_u32.low;
    ctx->ustorm_st_context.ring.r2tq.curr_pbe.hi = iscsi->r2tq.pbl_phys_table_virt[0].as_u32.high;

    /* Set up the first CQ, the first PTE info is contained in req2 */
    pbl_base.as_u32.low = req1->cq_page_table_addr_lo;
    pbl_base.as_u32.high = req1->cq_page_table_addr_hi;
    LM_INC64(&pbl_base, ISCSI_CQ_DB_SIZE);
    ctx->ustorm_st_context.ring.cq_pbl_base.lo = pbl_base.as_u32.low;
    ctx->ustorm_st_context.ring.cq_pbl_base.hi = pbl_base.as_u32.high;
    ctx->ustorm_st_context.ring.cq[0].cq_sn = ISCSI_INITIAL_SN;
    ctx->ustorm_st_context.ring.cq[0].curr_pbe.lo = req2->cq_first_pte.lo;
    ctx->ustorm_st_context.ring.cq[0].curr_pbe.hi = req2->cq_first_pte.hi;

    if (1 != pdev->iscsi_info.run_time.num_of_cqs)
    {
        /* For now we only support a single CQ */
        return LM_STATUS_INVALID_PARAMETER;

#if 0
        /* Set up additional CQs */
        for (i = 1; i < pdev->iscsi_info.run_time.num_of_cqs; i++)   // 8 x CQ curr_pbe
        {
            ctx->ustorm_st_context.ring.cq[i].cq_sn = ISCSI_INITIAL_SN;

            curr_pbl_base.as_u32.low = pbl_base.as_u32.low;
            curr_pbl_base.as_u32.high = pbl_base.as_u32.high;

            LM_INC64(&curr_pbl_base, i * single_cq_pbl_entries * sizeof(lm_address_t));
#if 0
            fix this if we ever want to use > 1 CQ

            curr_pbe = (lm_address_t *)mm_map_io_space(curr_pbl_base, sizeof(lm_address_t));
            if CHK_NULL(curr_pbe)
            {
                return LM_STATUS_INVALID_PARAMETER;
            }
            ctx->ustorm_st_context.ring.cq[i].curr_pbe.lo = curr_pbe->as_u32.low;
            ctx->ustorm_st_context.ring.cq[i].curr_pbe.hi = curr_pbe->as_u32.high;
            mm_unmap_io_space(curr_pbe, sizeof(lm_address_t));

#endif
        }
#endif
    }

    ctx->ustorm_st_context.task_pbl_base.lo = iscsi->task_array.pbl_phys_table_phys.as_u32.low;
    ctx->ustorm_st_context.task_pbl_base.hi = iscsi->task_array.pbl_phys_table_phys.as_u32.high;
    ctx->ustorm_st_context.tce_phy_addr.lo = iscsi->task_array.pbl_phys_table_virt[0].as_u32.low;
    ctx->ustorm_st_context.tce_phy_addr.hi = iscsi->task_array.pbl_phys_table_virt[0].as_u32.high;
    ctx->ustorm_st_context.iscsi_conn_id = conn_id;
    SET_FIELD(ctx->ustorm_st_context.negotiated_rx, USTORM_ISCSI_ST_CONTEXT_MAX_RECV_PDU_LENGTH, ISCSI_DEFAULT_MAX_PDU_LENGTH);
    SET_FIELD(ctx->ustorm_st_context.negotiated_rx_and_flags, USTORM_ISCSI_ST_CONTEXT_MAX_BURST_LENGTH, ISCSI_DEFAULT_MAX_BURST_LENGTH);
    SET_FIELD(ctx->ustorm_st_context.negotiated_rx, USTORM_ISCSI_ST_CONTEXT_MAX_OUTSTANDING_R2TS, ISCSI_DEFAULT_MAX_OUTSTANDING_R2T);
    SET_FIELD(ctx->ustorm_st_context.negotiated_rx_and_flags, USTORM_ISCSI_ST_CONTEXT_B_HDR_DIGEST_EN, ISCSI_DEFAULT_HEADER_DIGEST);
    SET_FIELD(ctx->ustorm_st_context.negotiated_rx_and_flags, USTORM_ISCSI_ST_CONTEXT_B_DATA_DIGEST_EN, ISCSI_DEFAULT_DATA_DIGEST);
    ctx->ustorm_st_context.num_cqs = pdev->iscsi_info.run_time.num_of_cqs;

    // init cstorm storm context
    ctx->cstorm_st_context.hq_pbl_base.lo = iscsi->hq.pbl_phys_table_phys.as_u32.low;
    ctx->cstorm_st_context.hq_pbl_base.hi = iscsi->hq.pbl_phys_table_phys.as_u32.high;
    ctx->cstorm_st_context.hq_curr_pbe.lo = iscsi->hq.pbl_phys_table_virt[0].as_u32.low;
    ctx->cstorm_st_context.hq_curr_pbe.hi = iscsi->hq.pbl_phys_table_virt[0].as_u32.high;

    ctx->cstorm_st_context.task_pbl_base.lo = iscsi->task_array.pbl_phys_table_phys.as_u32.low;
    ctx->cstorm_st_context.task_pbl_base.hi = iscsi->task_array.pbl_phys_table_phys.as_u32.high;
    ctx->cstorm_st_context.cq_db_base.lo = req1->cq_page_table_addr_lo;
    ctx->cstorm_st_context.cq_db_base.hi = req1->cq_page_table_addr_hi;
    ctx->cstorm_st_context.iscsi_conn_id = conn_id;
    ctx->cstorm_st_context.cq_proc_en_bit_map = (1 << pdev->iscsi_info.run_time.num_of_cqs) - 1;
    SET_FIELD(ctx->cstorm_st_context.flags, CSTORM_ISCSI_ST_CONTEXT_DATA_DIGEST_EN, ISCSI_DEFAULT_HEADER_DIGEST);
    SET_FIELD(ctx->cstorm_st_context.flags, CSTORM_ISCSI_ST_CONTEXT_HDR_DIGEST_EN, ISCSI_DEFAULT_DATA_DIGEST);
    for (i = 0; i < pdev->iscsi_info.run_time.num_of_cqs; i++)
    {
        ctx->cstorm_st_context.cq_c_prod_sqn_arr.sqn[i] = ISCSI_INITIAL_SN;
        ctx->cstorm_st_context.cq_c_sqn_2_notify_arr.sqn[i] = ISCSI_INITIAL_SN;
    }

    /* now we need to configure the cdu-validation data */
    lm_set_cdu_validation_data(pdev, iscsi->cid, FALSE /* don't invalidate */);

    return LM_STATUS_SUCCESS;
}


lm_status_t
lm_fc_init_fcoe_context(
    IN struct _lm_device_t          *pdev,
    IN lm_fcoe_state_t              *fcoe)
{
    struct fcoe_context *ctx;
    u32_t cid;
    u16_t conn_id;

    if (CHK_NULL(pdev) || CHK_NULL(fcoe))
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    conn_id = fcoe->ofld1.fcoe_conn_id;
    cid = fcoe->cid;

    DbgMessage(pdev, INFORM, "### lm_fc_init_fcoe_context\n");

    /* get context */
    fcoe->ctx_virt = (struct fcoe_context *)lm_get_context(pdev, fcoe->cid);
    DbgBreakIf(!fcoe->ctx_virt);
    fcoe->ctx_phys.as_u64 = lm_get_context_phys(pdev, fcoe->cid);
    DbgBreakIf(!fcoe->ctx_phys.as_u64);
    DbgMessage(pdev, VERBOSEl5sp,
                "fcoe->ctx_virt=%p, fcoe->ctx_phys_high=%x, fcoe->ctx_phys_low=%x\n",
                fcoe->ctx_virt, fcoe->ctx_phys.as_u32.high, fcoe->ctx_phys.as_u32.low);

    ctx = fcoe->ctx_virt;

    mm_memset(ctx, 0, sizeof(struct fcoe_context));

    /* now we need to configure the cdu-validation data */
    lm_set_cdu_validation_data(pdev, fcoe->cid, FALSE /* don't invalidate */);

    return LM_STATUS_SUCCESS;
}



lm_status_t
lm_fc_alloc_con_resc(
    IN struct _lm_device_t          *pdev,
    IN lm_fcoe_state_t              *fcoe)
{
    lm_status_t                     lm_status = LM_STATUS_SUCCESS;
    s32_t                           cid       = 0;

    if (CHK_NULL(pdev) || CHK_NULL(fcoe))
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    DbgMessage(pdev, INFORM, "### lm_fc_alloc_con_resc\n");

    /* save the miniport's conn id */
    fcoe->fcoe_conn_id = fcoe->ofld1.fcoe_conn_id;

    /* Allocate CID */
    lm_status = lm_allocate_cid(pdev, FCOE_CONNECTION_TYPE, (void *)fcoe, &cid);
    if (lm_status == LM_STATUS_PENDING)
    {
        lm_sp_req_manager_block(pdev, (u32_t)cid);
    }
    else if (lm_status != LM_STATUS_SUCCESS)
    {
        /* failed to allocate CID */
        lm_fc_free_con_resc(pdev, fcoe);
        return lm_status;
    }

    /* save the returned cid */
    fcoe->cid = (u32_t)cid;

    if (lm_cid_state(pdev, fcoe->cid) == LM_CID_STATE_PENDING)
    {
        return LM_STATUS_PENDING; /* Too soon to initialize context */
    }

    return LM_STATUS_SUCCESS;
} /* lm_fc_alloc_con_resc */



lm_status_t
lm_fc_post_offload_ramrod(
    struct _lm_device_t             *pdev,
    lm_fcoe_state_t                 *fcoe)
{
    lm_fcoe_slow_path_phys_data_t   *ramrod_params;
    lm_status_t                     lm_status;

    ramrod_params = (lm_fcoe_slow_path_phys_data_t*)pdev->fcoe_info.bind.ramrod_mem_virt;

    mm_memset(ramrod_params, 0, sizeof(lm_fcoe_slow_path_phys_data_t));

    memcpy(&ramrod_params->fcoe_ofld.offload_kwqe1, &fcoe->ofld1, sizeof(struct fcoe_kwqe_conn_offload1));
    memcpy(&ramrod_params->fcoe_ofld.offload_kwqe2, &fcoe->ofld2, sizeof(struct fcoe_kwqe_conn_offload2));
    memcpy(&ramrod_params->fcoe_ofld.offload_kwqe3, &fcoe->ofld3, sizeof(struct fcoe_kwqe_conn_offload3));
    memcpy(&ramrod_params->fcoe_ofld.offload_kwqe4, &fcoe->ofld4, sizeof(struct fcoe_kwqe_conn_offload4));

    lm_status = lm_command_post(pdev,
                                fcoe->cid,
                                FCOE_RAMROD_CMD_ID_OFFLOAD_CONN,
                                CMD_PRIORITY_NORMAL,
                                FCOE_CONNECTION_TYPE,
                                pdev->fcoe_info.bind.ramrod_mem_phys.as_u64);

    return lm_status;
}



lm_status_t
lm_fc_post_enable_ramrod(
    struct _lm_device_t                     *pdev,
    lm_fcoe_state_t                         *fcoe,
    struct fcoe_kwqe_conn_enable_disable    *enable)
{
    lm_fcoe_slow_path_phys_data_t   *ramrod_params;
    lm_status_t                     lm_status;

    ramrod_params = (lm_fcoe_slow_path_phys_data_t*)pdev->fcoe_info.bind.ramrod_mem_virt;

    mm_memset(ramrod_params, 0, sizeof(lm_fcoe_slow_path_phys_data_t));

    memcpy(&ramrod_params->fcoe_enable.enable_disable_kwqe, enable, sizeof(struct fcoe_kwqe_conn_enable_disable));

    lm_status = lm_command_post(pdev,
                                fcoe->cid,
                                FCOE_RAMROD_CMD_ID_ENABLE_CONN,
                                CMD_PRIORITY_NORMAL,
                                FCOE_CONNECTION_TYPE,
                                pdev->fcoe_info.bind.ramrod_mem_phys.as_u64);

    return lm_status;
}



lm_status_t
lm_fc_post_disable_ramrod(
    struct _lm_device_t                    *pdev,
    lm_fcoe_state_t                        *fcoe,
    struct fcoe_kwqe_conn_enable_disable   *disable)
{
    lm_fcoe_slow_path_phys_data_t   *ramrod_params;
    lm_status_t                     lm_status;

    ramrod_params = (lm_fcoe_slow_path_phys_data_t*)pdev->fcoe_info.bind.ramrod_mem_virt;

    mm_memset(ramrod_params, 0, sizeof(lm_fcoe_slow_path_phys_data_t));

    memcpy(&ramrod_params->fcoe_enable.enable_disable_kwqe, disable, sizeof *disable);

    lm_status = lm_command_post(pdev,
                                fcoe->cid,
                                FCOE_RAMROD_CMD_ID_DISABLE_CONN,
                                CMD_PRIORITY_NORMAL,
                                FCOE_CONNECTION_TYPE,
                                pdev->fcoe_info.bind.ramrod_mem_phys.as_u64);

    return lm_status;
}

lm_status_t
lm_fc_post_destroy_ramrod(
    struct _lm_device_t             *pdev)
{
    lm_status_t                     lm_status;

    lm_status = lm_command_post(pdev,
                                LM_CLI_CID(pdev, LM_CLI_IDX_FCOE),      /* cid */
                                FCOE_RAMROD_CMD_ID_DESTROY_FUNC,
                                CMD_PRIORITY_NORMAL,
                                FCOE_CONNECTION_TYPE,
                                0);

    return lm_status;
}


lm_status_t
lm_fc_post_stat_ramrod(
    struct _lm_device_t         *pdev,
    struct fcoe_kwqe_stat       *stat)
{
    lm_status_t                     lm_status = LM_STATUS_SUCCESS;

    lm_fcoe_slow_path_phys_data_t   *ramrod_params;

    if(CHK_NULL(pdev->fcoe_info.bind.ramrod_mem_virt))
    {
        return LM_STATUS_RESOURCE;
    }
    ramrod_params = (lm_fcoe_slow_path_phys_data_t*)pdev->fcoe_info.bind.ramrod_mem_virt;

    mm_memset(ramrod_params, 0, sizeof(lm_fcoe_slow_path_phys_data_t));

    memcpy(&ramrod_params->fcoe_stat.stat_kwqe, stat, sizeof(struct fcoe_kwqe_stat));

    lm_status = lm_command_post(pdev,
                                LM_CLI_CID(pdev, LM_CLI_IDX_FCOE),      /* cid */
                                FCOE_RAMROD_CMD_ID_STAT_FUNC,
                                CMD_PRIORITY_NORMAL,
                                FCOE_CONNECTION_TYPE,
                                pdev->fcoe_info.bind.ramrod_mem_phys.as_u64);

    return lm_status;
}

lm_status_t
lm_fc_post_terminate_ramrod(
    struct _lm_device_t             *pdev,
    lm_fcoe_state_t                 *fcoe)
{
    lm_status_t                     lm_status;

    lm_status = lm_command_post(pdev,
                                fcoe->cid,
                                FCOE_RAMROD_CMD_ID_TERMINATE_CONN,
                                CMD_PRIORITY_NORMAL,
                                FCOE_CONNECTION_TYPE,
                                0);

    return lm_status;
}
