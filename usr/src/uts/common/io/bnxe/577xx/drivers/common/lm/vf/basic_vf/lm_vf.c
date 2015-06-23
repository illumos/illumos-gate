#ifdef VF_INVOLVED

#include "lm5710.h"
#include "command.h"
#include "igu_def.h"


u8_t lm_vf_is_function_after_flr(struct _lm_device_t * pdev)
{
    u8_t res = 0;
    res = (PFDEV(pdev)->vars.connections[VF_TO_PF_CID(pdev,LM_SW_LEADING_RSS_CID(pdev))].con_state != LM_CON_STATE_CLOSE);
    if (res) {
        DbgMessage2(pdev, FATAL, "VF[%d(%d)] was FLRed\n", ABS_VFID(pdev), REL_VFID(pdev));
    }
    return res;
}


static u8_t lm_vf_get_free_sbs(struct _lm_device_t * pf_dev, u8_t num_rss)
{
    u8_t free_sb = 0xff;
    u8_t max_num = pf_dev->params.base_fw_ndsb + MAX_RSS_CHAINS / pf_dev->params.vnics_per_port;
    free_sb = lm_vf_get_free_resource(pf_dev->pf_resources.free_sbs, pf_dev->params.base_fw_ndsb, max_num, num_rss);
    if (free_sb != 0xff) {
        DbgMessage3(pf_dev,FATAL,"lm_vf_get_free_sbs(%d-%d): %d\n",pf_dev->params.base_fw_ndsb, max_num, free_sb);
    } else {
        DbgMessage2(pf_dev,FATAL,"lm_vf_get_free_sbs(%d-%d): No more free SBs\n",pf_dev->params.base_fw_ndsb, max_num);
    }
    return free_sb;
}

static u8_t lm_vf_get_free_clients(struct _lm_device_t * pf_dev, u8_t num_rss)
{
    u8_t free_cli = 0xff;
    u8_t max_num = pf_dev->params.base_fw_client_id + MAX_RSS_CHAINS / pf_dev->params.vnics_per_port;
    free_cli = lm_vf_get_free_resource(pf_dev->pf_resources.free_clients, pf_dev->params.base_fw_client_id, max_num, num_rss);
    if (free_cli != 0xff) {
        DbgMessage3(pf_dev,FATAL,"lm_vf_get_free_clients(%d-%d): %d\n",pf_dev->params.base_fw_client_id, max_num, free_cli);
    } else {
        DbgMessage2(pf_dev,FATAL,"lm_vf_get_free_clients(%d-%d): No more free clients\n",pf_dev->params.base_fw_client_id, max_num);
    }
    return free_cli;
}

static u8_t lm_vf_get_free_stats(struct _lm_device_t * pf_dev)
{
    u8_t free_st_id = 0xff;
    u8_t min_num = pf_dev->params.vnics_per_port + VNIC_ID(pf_dev) * ((MAX_NUM_OF_STATS - pf_dev->params.vnics_per_port) / pf_dev->params.vnics_per_port);
    u8_t max_num = min_num + (MAX_NUM_OF_STATS - pf_dev->params.vnics_per_port) / pf_dev->params.vnics_per_port;
    free_st_id = lm_vf_get_free_resource(pf_dev->pf_resources.free_stats, min_num, max_num, 1);
    if (free_st_id != 0xff) {
        DbgMessage1(pf_dev,FATAL,"lm_vf_get_free_stats: %d\n",free_st_id);
    } else {
        DbgMessage3(pf_dev,FATAL,"lm_vf_get_free_stats: No more free stats counters(%d,%d)\n",min_num,max_num);
        DbgMessage1(pf_dev,FATAL,"lm_vf_get_free_stats: vnic_per_port is %d)\n",pf_dev->params.vnics_per_port);
    }
    return free_st_id;
}

static u8_t lm_vf_get_free_cam_offset(struct _lm_device_t * pf_dev)
{
    u8_t free_cam_offset = 0xff;
    u8_t max_num;
    max_num = LM_CAM_SIZE(pf_dev);
    free_cam_offset = lm_vf_get_free_resource(pf_dev->pf_resources.free_cam_offsets, 0, max_num, 1);
    if (free_cam_offset != 0xff) {
        DbgMessage1(pf_dev,FATAL,"lm_vf_get_free_cam_offset: %d\n",free_cam_offset);
    } else {
        DbgMessage(pf_dev,FATAL,"lm_vf_get_free_cam_offset: No more free cam offsets\n");
    }
    return  free_cam_offset;
}

lm_status_t lm_vf_prep(struct _lm_device_t * pf_dev, struct _lm_device_t * vf_dev)
{
    vf_dev->pf_dev = pf_dev;
    /* TODO: anything else to prepare for VF? */

    lm_set_virt_mode(vf_dev, DEVICE_TYPE_VF, VT_BASIC_VF);

    return LM_STATUS_SUCCESS;
}

lm_status_t lm_vf_get_bar_offset(struct _lm_device_t *pdev, u8_t bar_num, lm_address_t * bar_addr)
{
    bar_addr->as_u64 = PFDEV(pdev)->hw_info.sriov_info.vf_bars[bar_num].as_u64 + 
        REL_VFID(pdev)*pdev->hw_info.bar_size[bar_num];
    DbgMessage3(pdev, FATAL, "VF[%d(%d)]-bar[%d]:\n", ABS_VFID(pdev),REL_VFID(pdev),bar_num);
    DbgMessage2(pdev, FATAL, "A: 0x%x, S: 0x%x\n", bar_addr->as_u32.low, pdev->hw_info.bar_size[bar_num]);

    return LM_STATUS_SUCCESS;
}

lm_status_t lm_vf_get_vf_id(struct _lm_device_t * pdev)
{
    u32_t val;

    mm_read_pci(pdev, PCICFG_ME_REGISTER, &val);

    DbgMessage1(pdev, FATAL, "vf ME-REG value: 0x%x\n", val);

    if (!(val & ME_REG_VF_VALID)) {
        DbgBreakIf(!(val & ME_REG_VF_VALID));
        return LM_STATUS_FAILURE;
    }
    pdev->params.vf_num_in_path = (val & ME_REG_VF_NUM_MASK) >> ME_REG_VF_NUM_SHIFT;
    
    if (pdev->params.vf_num_in_path < PFDEV(pdev)->hw_info.sriov_info.first_vf_in_pf) {
        DbgBreakIf(pdev->params.vf_num_in_path < PFDEV(pdev)->hw_info.sriov_info.first_vf_in_pf);
        return LM_STATUS_FAILURE;
    }
    pdev->params.vf_num_in_pf = pdev->params.vf_num_in_path - PFDEV(pdev)->hw_info.sriov_info.first_vf_in_pf;

    DbgMessage2(pdev, FATAL, "vf_num_in_path=%d vf_num_in_pf=%d\n", pdev->params.vf_num_in_path, pdev->params.vf_num_in_pf);

    return LM_STATUS_SUCCESS;
}

lm_status_t lm_vf_get_intr_blk_info(struct _lm_device_t *pdev)
{
    // TODO 
    return LM_STATUS_SUCCESS;
}

lm_status_t lm_vf_en(struct _lm_device_t * pf_dev, u16_t vf_num)
{
    u8_t rss_id;
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    /* TODO: what HW needs to be initialized at this stage */
	/* TODO: VF Database for FLR needs? */
#ifndef _VBD_CMD_
    lm_status = mm_vf_en(pf_dev, vf_num);
#endif    
    if (lm_status == LM_STATUS_SUCCESS) {
        pf_dev->pf_resources.free_cam_offsets[0] |= 0x3;
    
        LM_FOREACH_RSS_IDX(pf_dev, rss_id) {
            lm_vf_acquire_resource(pf_dev->pf_resources.free_sbs, LM_FW_SB_ID(pf_dev, RSS_ID_TO_SB_ID(rss_id)), 1);
            DbgMessage2(pf_dev, FATAL, "SB%d is allocated for PF[%d] itself\n", LM_FW_SB_ID(pf_dev, RSS_ID_TO_SB_ID(rss_id)), FUNC_ID(pf_dev));
            lm_vf_acquire_resource(pf_dev->pf_resources.free_clients, LM_FW_CLI_ID(pf_dev, RSS_ID_TO_CID(rss_id)), 1);
            DbgMessage2(pf_dev, FATAL, "Client%d is allocated for PF[%d] itself\n", LM_FW_CLI_ID(pf_dev, RSS_ID_TO_CID(rss_id)), FUNC_ID(pf_dev));
        }
    
        lm_vf_acquire_resource(pf_dev->pf_resources.free_stats, LM_STATS_CNT_ID(pf_dev), 1);
        DbgMessage2(pf_dev, FATAL, "Stats%d is allocated for PF[%d] itself\n", LM_STATS_CNT_ID(pf_dev), FUNC_ID(pf_dev));
    }
    pf_dev->vars.num_vfs_enabled = vf_num;
    return lm_status;
}

lm_status_t lm_vf_dis(struct _lm_device_t * pf_dev)
{
	/* TODO: Clean VF Database for FLR needs? */
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    u32_t base_vfid, vfid;
    u16_t pretend_val;
    u16_t ind_cids, start_cid, end_cid;

    DbgMessage(pf_dev, FATAL, "vf disable\n");
    start_cid = (((1 << LM_VF_MAX_RVFID_SIZE) | 0) <<  LM_VF_CID_WND_SIZE); //1st possible abs VF_ID
    end_cid = (((1 << LM_VF_MAX_RVFID_SIZE) | 63) <<  LM_VF_CID_WND_SIZE); //last possible abs VF_ID
    DbgMessage2(pf_dev, FATAL, "vf disable: clear VFs connections from %d till %d\n",start_cid, end_cid);
    for (ind_cids = start_cid; ind_cids <= end_cid; ind_cids++) {
        pf_dev->vars.connections[ind_cids].con_state = LM_CON_STATE_CLOSE;
    }
#ifndef _VBD_CMD_      
    mm_vf_dis(pf_dev);
#endif

    if (lm_is_function_after_flr(pf_dev)) {
        DbgMessage(pf_dev, FATAL, "vf disable called on a flred function - not much we can do here... \n");
        return LM_STATUS_SUCCESS;
    }
    /* if MCP does not exist for each vf in pf, need to pretend to it and disable igu vf_msix and internal vfid enable bit */
    if (GET_FLAGS( pf_dev->params.test_mode, TEST_MODE_NO_MCP)){
        DbgMessage(pf_dev, FATAL, "bootcode is down fix sriov disable.\n");
        base_vfid = pf_dev->hw_info.sriov_info.first_vf_in_pf;
        for (vfid = base_vfid; vfid < base_vfid + pf_dev->vars.num_vfs_enabled; vfid++ ) {
            pretend_val = ABS_FUNC_ID(pf_dev) | (1<<3) | (vfid << 4);
            lm_pretend_func(pf_dev, pretend_val);
        
            REG_WR(pf_dev, IGU_REG_PCI_VF_MSIX_EN, 0);
            REG_WR(pf_dev, IGU_REG_PCI_VF_MSIX_FUNC_MASK, 0);
            REG_WR(pf_dev, PGLUE_B_REG_INTERNAL_VFID_ENABLE, 0);
        
            lm_pretend_func(pf_dev, ABS_FUNC_ID(pf_dev) ); 
        }
    
        /* This is a clear-on-write register, therefore we actually write 1 to the bit we want to reset */
        REG_WR(pf_dev, 0x24d8, 1<<29);
    
        REG_WR(pf_dev, PGLUE_B_REG_SR_IOV_DISABLED_REQUEST_CLR ,(1<<ABS_FUNC_ID(pf_dev)));
        //REG_WR(pf_dev, PGLUE_B_REG_DISABLE_FLR_SRIOV_DISABLED, PGLUE_B_DISABLE_FLR_SRIOV_DISABLED_REG_DISABLE_SRIOV_DISABLED_REQUEST);*/
    }
    return lm_status;
}

lm_status_t lm_alloc_client_info(struct _lm_device_t *pdev);
lm_status_t lm_setup_client_info(struct _lm_device_t *pdev);

/* Description:
*    This routine contain code for VF alloc/setup distinguish by flag    
*/
lm_status_t lm_vf_setup_alloc_resc(struct _lm_device_t *pdev, u8_t b_is_alloc )
{
    lm_variables_t* vars       = NULL ;
    u32_t           mem_size   = 0 ;    
    u32_t           alloc_size = 0 ;
    u8_t            mm_cli_idx = 0 ;
    u8_t            sb_id      = 0 ;    
    lm_address_t    sb_phy_address;
    lm_status_t     lm_status  = LM_STATUS_FAILURE;

    if CHK_NULL( pdev )
    {
        return LM_STATUS_INVALID_PARAMETER ;
    }

    DbgMessage1(pdev, FATAL , "### VF lm_common_setup_alloc_resc b_is_alloc=%s\n", b_is_alloc ? "TRUE" : "FALSE" );

    vars       = &(pdev->vars) ;    
    
    //       Status blocks allocation. We allocate mem both for the default and non-default status blocks
    //       there is 1 def sb and 16 non-def sb per port.
    //       non-default sb: index 0-15, default sb: index 16.
    mem_size = E2_STATUS_BLOCK_BUFFER_SIZE;
    
    mm_cli_idx = LM_RESOURCE_COMMON;//!!DP mm_cli_idx_to_um_idx(LM_CLI_IDX_MAX);

    LM_FOREACH_SB_ID(pdev, sb_id)
    {
        if( b_is_alloc )
        {
            pdev->vars.status_blocks_arr[sb_id].host_hc_status_block.e2_sb = mm_alloc_phys_mem(pdev, mem_size, &sb_phy_address, 0, mm_cli_idx);
            pdev->vars.status_blocks_arr[sb_id].hc_status_block_data.e2_sb_data.common.host_sb_addr.lo = sb_phy_address.as_u32.low;
            pdev->vars.status_blocks_arr[sb_id].hc_status_block_data.e2_sb_data.common.host_sb_addr.hi = sb_phy_address.as_u32.high;
        }
        if CHK_NULL(pdev->vars.status_blocks_arr[sb_id].host_hc_status_block.e1x_sb)
        {
            DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
            return LM_STATUS_RESOURCE ;
        }        
        mm_mem_zero((void *)(pdev->vars.status_blocks_arr[sb_id].host_hc_status_block.e2_sb), mem_size);
    }

    /* SlowPath Info */
    lm_status = lm_alloc_setup_slowpath_resc(pdev, b_is_alloc);
    if (lm_status != LM_STATUS_SUCCESS)
    {
        DbgMessage1(pdev, FATAL, "lm_alloc_client_info failed lm-status = %d\n", lm_status);
        return lm_status;
    }


    if (b_is_alloc)
    {
        lm_status = lm_alloc_client_info(pdev);
        if (lm_status != LM_STATUS_SUCCESS)
        {
            DbgMessage1(pdev, FATAL, "lm_alloc_client_info failed lm-status = %d\n", lm_status);
            return lm_status;
        }
    }

    lm_status = lm_setup_client_info(pdev);
    if (lm_status != LM_STATUS_SUCCESS)
    {
        DbgMessage1(pdev, FATAL, "lm_setup_client_info failed lm-status = %d\n", lm_status);
        return lm_status;
    }

    return LM_STATUS_SUCCESS;
}


lm_status_t lm_vf_init_dev_info(struct _lm_device_t *pdev)
{
    u8_t    index;
    lm_status_t lm_status;
    lm_status = lm_vf_allocate_resc_in_pf(pdev);
    if (lm_status == LM_STATUS_SUCCESS) {
        pdev->vars.stats.stats_collect.stats_hw.b_collect_enabled = FALSE;
        pdev->vars.stats.stats_collect.stats_fw.b_collect_enabled = FALSE;
        DbgBreakIf(LM_SB_CNT(pdev) != 1);

        for (index = 0; index < LM_SB_CNT(pdev); index++) { //RSS? but not SBs
            PFDEV(pdev)->context_info->array[VF_TO_PF_CID(pdev,index)].cid_resc.mapped_cid_bar_addr = 
                (volatile void *)((u8_t*)pdev->vars.mapped_bar_addr[BAR_0] + index*LM_DQ_CID_SIZE + VF_BAR0_DB_OFFSET);
        }
    }
    return lm_status;
}


//static vf_info_t tmp_vf_info;

lm_status_t lm_vf_allocate_resc_in_pf(struct _lm_device_t *pdev)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;

    DbgMessage(pdev, FATAL, "lm_vf_allocate_resc_in_pf\n");

    DbgMessage2(pdev,FATAL,"lm_vf_allocate_resc_in_pf: VF %d requests resources from PF %d\n",ABS_VFID(pdev),FUNC_ID(pdev));
    MM_ACQUIRE_PF_LOCK(PFDEV(pdev));
    
    pdev->params.base_fw_client_id = lm_vf_get_free_clients(PFDEV(pdev),pdev->params.sb_cnt);
    pdev->params.base_fw_ndsb = lm_vf_get_free_sbs(PFDEV(pdev),pdev->params.sb_cnt);
    pdev->params.base_cam_offset = lm_vf_get_free_cam_offset(PFDEV(pdev));
    pdev->params.base_fw_stats_id = lm_vf_get_free_stats(PFDEV(pdev));
    
    if ((pdev->params.base_fw_client_id == 0xff) 
            || (pdev->params.base_fw_ndsb == 0xff)
            || (pdev->params.base_cam_offset == 0xff)) {
        lm_status = LM_STATUS_RESOURCE;
    } else {
        lm_vf_acquire_resource(PFDEV(pdev)->pf_resources.free_sbs, pdev->params.base_fw_ndsb, pdev->params.sb_cnt);
        lm_vf_acquire_resource(PFDEV(pdev)->pf_resources.free_clients, pdev->params.base_fw_client_id, pdev->params.sb_cnt);
        lm_vf_acquire_resource(PFDEV(pdev)->pf_resources.free_cam_offsets, pdev->params.base_cam_offset, 1);
        if (pdev->params.base_fw_stats_id != 0xff) {
            lm_vf_acquire_resource(PFDEV(pdev)->pf_resources.free_stats, pdev->params.base_fw_stats_id, 1);
        }
        /* For now, qzone_id == sb_id, but this is not a requirement */
        pdev->params.base_fw_qzone_id = pdev->params.base_fw_ndsb;
    }

    MM_RELEASE_PF_LOCK(PFDEV(pdev));

    DbgMessage4(pdev, FATAL, "vf_resc: fw_client=%d fw_ndsb=%d fw cam=%d fw stats=%d\n",
               pdev->params.base_fw_client_id, pdev->params.base_fw_ndsb, pdev->params.base_cam_offset, pdev->params.base_fw_stats_id);

    return lm_status;            
}

lm_status_t
lm_vf_chip_init(struct _lm_device_t *pdev)
{
    lm_status_t     lm_status = LM_STATUS_SUCCESS;
    u32_t           function_fw_id;
    u8_t            port = PORT_ID(pdev);
    u8_t  i;

    DbgMessage(pdev, FATAL, "lm_vf_chip_init: start\n");
    mm_memset(pdev->vars.c_hc_ack, 0, sizeof(pdev->vars.c_hc_ack));
    mm_memset(pdev->vars.u_hc_ack, 0, sizeof(pdev->vars.u_hc_ack));
    lm_init_non_def_status_block(pdev, LM_SW_LEADING_SB_ID, port);

    // Init SPQ
    /*  Driver should zero the slow path queue data before enabling the function in XSTORM.
        Until now firmware was doing this but it cannot scale for VFs, so this zeroing was removed from firmware.
        The driver should write zeros to XSTORM_SPQ_DATA_OFFSET(function).
        The size of this structure is given in XSTORM_SPQ_DATA_SIZE.
        For VFs, the XSTORM_VF_SPQ_DATA_OFFSET(vfid) should be used. To do it via GRC is preferrable */
    DbgBreakIf((XSTORM_SPQ_DATA_SIZE % 4) != 0);
    for (i = 0; i < XSTORM_SPQ_DATA_SIZE/sizeof(u32_t); i++) {
        REG_WR(PFDEV(pdev),XSEM_REG_FAST_MEMORY + XSTORM_VF_SPQ_DATA_OFFSET(ABS_VFID(pdev)) + i*sizeof(u32_t),0);
    }

    REG_WR(PFDEV(pdev),XSEM_REG_FAST_MEMORY + (XSTORM_VF_SPQ_PAGE_BASE_OFFSET(ABS_VFID(pdev))),pdev->sq_info.sq_chain.bd_chain_phy.as_u32.low);
    REG_WR(PFDEV(pdev),XSEM_REG_FAST_MEMORY + (XSTORM_VF_SPQ_PAGE_BASE_OFFSET(ABS_VFID(pdev)) + 4),pdev->sq_info.sq_chain.bd_chain_phy.as_u32.high);
    REG_WR(PFDEV(pdev),XSEM_REG_FAST_MEMORY + (XSTORM_VF_SPQ_PROD_OFFSET(ABS_VFID(pdev))),pdev->sq_info.sq_chain.prod_idx);

    lm_status = lm_set_rx_mask(pdev, LM_CLI_IDX_NDIS, LM_RX_MASK_ACCEPT_NONE, NULL); 
    if(LM_STATUS_SUCCESS != lm_status)
    {
        DbgMessage1(pdev,FATAL,"lm_set_rx_mask(LM_RX_MASK_ACCEPT_NONE) returns %d\n",lm_status);
        return lm_status;
    }
/*
Enable the function in STORMs
*/
    function_fw_id = FW_VFID(pdev);

    LM_INTMEM_WRITE8(PFDEV(pdev), XSTORM_VF_TO_PF_OFFSET(function_fw_id), FUNC_ID(pdev), BAR_XSTRORM_INTMEM);
    LM_INTMEM_WRITE8(PFDEV(pdev), CSTORM_VF_TO_PF_OFFSET(function_fw_id), FUNC_ID(pdev), BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(PFDEV(pdev), TSTORM_VF_TO_PF_OFFSET(function_fw_id), FUNC_ID(pdev), BAR_TSTRORM_INTMEM);
    LM_INTMEM_WRITE8(PFDEV(pdev), USTORM_VF_TO_PF_OFFSET(function_fw_id), FUNC_ID(pdev), BAR_USTRORM_INTMEM);

    LM_INTMEM_WRITE8(PFDEV(pdev), XSTORM_FUNC_EN_OFFSET(function_fw_id), 1, BAR_XSTRORM_INTMEM);
    LM_INTMEM_WRITE8(PFDEV(pdev), CSTORM_FUNC_EN_OFFSET(function_fw_id), 1, BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(PFDEV(pdev), TSTORM_FUNC_EN_OFFSET(function_fw_id), 1, BAR_TSTRORM_INTMEM);
    LM_INTMEM_WRITE8(PFDEV(pdev), USTORM_FUNC_EN_OFFSET(function_fw_id), 1, BAR_USTRORM_INTMEM);


    return LM_STATUS_SUCCESS;
}

lm_status_t
lm_vf_chip_reset(struct _lm_device_t *pdev, lm_reason_t reason)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    u32_t       function_fw_id;
    u8_t        port = PORT_ID(pdev);

    if (lm_reset_is_inprogress(pdev)) {
        DbgMessage1(pdev,FATAL,"lm_vf_chip_reset: VF(%d) under reset\n",ABS_VFID(pdev));
        if (!lm_vf_fl_reset_is_inprogress(pdev)) {
            lm_status = lm_vf_recycle_resc_in_pf(pdev);
            PFDEV(pdev)->vars.connections[VF_TO_PF_CID(pdev,LM_SW_LEADING_RSS_CID(pdev))].con_state = LM_CON_STATE_CLOSE;
            DbgMessage1(pdev,FATAL,"lm_vf_chip_reset: recycle resources (including connection) for VF(%d)\n",ABS_VFID(pdev));
        }
        return lm_status;
    }

/*
Disable the function in STORMs
*/
    function_fw_id = FW_VFID(pdev);

    LM_INTMEM_WRITE8(PFDEV(pdev), XSTORM_FUNC_EN_OFFSET(function_fw_id), 0, BAR_XSTRORM_INTMEM);
    LM_INTMEM_WRITE8(PFDEV(pdev), CSTORM_FUNC_EN_OFFSET(function_fw_id), 0, BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(PFDEV(pdev), TSTORM_FUNC_EN_OFFSET(function_fw_id), 0, BAR_TSTRORM_INTMEM);
    LM_INTMEM_WRITE8(PFDEV(pdev), USTORM_FUNC_EN_OFFSET(function_fw_id), 0, BAR_USTRORM_INTMEM);

    lm_clear_non_def_status_block(pdev,  LM_FW_SB_ID(pdev, LM_SW_LEADING_SB_ID)); 

    lm_status = lm_vf_recycle_resc_in_pf(pdev);
    return lm_status;
}

lm_status_t
lm_vf_recycle_resc_in_pf(struct _lm_device_t *pdev)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;

    MM_ACQUIRE_PF_LOCK(PFDEV(pdev));

    lm_vf_release_resource(PFDEV(pdev)->pf_resources.free_sbs, pdev->params.base_fw_ndsb, pdev->params.sb_cnt);
    lm_vf_release_resource(PFDEV(pdev)->pf_resources.free_clients, pdev->params.base_fw_client_id, pdev->params.sb_cnt);
    lm_vf_release_resource(PFDEV(pdev)->pf_resources.free_cam_offsets, pdev->params.base_cam_offset, 1);
    if (pdev->params.base_fw_stats_id != 0xff) {
        lm_vf_release_resource(PFDEV(pdev)->pf_resources.free_stats, pdev->params.base_fw_stats_id, 1);
    }

    MM_RELEASE_PF_LOCK(PFDEV(pdev));

    return lm_status;
}

lm_status_t
lm_vf_enable_vf(struct _lm_device_t *pdev)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    u16_t pretend_val;
    u32_t prod_idx;
    u8_t igu_sb_id;
    u32_t was_err_num;
    u32_t was_err_value;
    u32_t was_err_reg;

    /* Enable the VF in PXP - this will enable read/write from VF bar. 
     * Need to use Pretend in order to do this. Note: once we do pretend
     * all accesses to SPLIT-68 will be done as if-vf... 
     * Bits. Bits [13:10] - Reserved.  Bits [9:4] - VFID. Bits [3] - VF valid. Bits [2:0] - PFID. 
     */

    pretend_val = ABS_FUNC_ID(pdev) | (1<<3) | (ABS_VFID(pdev) << 4);
    lm_status = lm_pretend_func(PFDEV(pdev), pretend_val);
    if (lm_status == LM_STATUS_SUCCESS) {
        REG_WR(PFDEV(pdev), PBF_REG_DISABLE_VF,0);
        REG_WR(PFDEV(pdev), PGLUE_B_REG_INTERNAL_VFID_ENABLE, 1);
        lm_pretend_func(PFDEV(pdev), ABS_FUNC_ID(pdev) ); 
        DbgMessage1(pdev, FATAL, "vf[%d] is enabled\n", ABS_VFID(pdev));
    
        was_err_num = 2 * PATH_ID(pdev) + ABS_VFID(pdev) / 32;
        switch (was_err_num) {
        case 0:
            was_err_reg = PGLUE_B_REG_WAS_ERROR_VF_31_0_CLR;
            break;
        case 1:
            was_err_reg = PGLUE_B_REG_WAS_ERROR_VF_63_32_CLR;
            break;
        case 2:
            was_err_reg = PGLUE_B_REG_WAS_ERROR_VF_95_64_CLR;
            break;
        case 3:
            was_err_reg = PGLUE_B_REG_WAS_ERROR_VF_127_96_CLR;
            break;
        default:
            was_err_reg = 0;
            DbgMessage2(pdev,FATAL,"Wrong Path[%d], VF[%d]\n",PATH_ID(pdev),ABS_VFID(pdev));
            DbgBreak();
        }

        was_err_value = 1 << (ABS_VFID(pdev) % 32);
        if (was_err_reg) {
            REG_WR(PFDEV(pdev), was_err_reg, was_err_value); /* PglueB - Clear the was_error indication of the relevant function*/
        }

        /* IGU Initializations */
        for (igu_sb_id = 0; igu_sb_id < LM_IGU_SB_CNT(pdev); igu_sb_id++) {
            prod_idx = (IGU_BASE_NDSB(pdev) + igu_sb_id);
            REG_WR(PFDEV(pdev), IGU_REG_PROD_CONS_MEMORY + prod_idx*4, 0);
            DbgMessage1(pdev, FATAL, "IGU[%d] is inialized\n", prod_idx);
        }
        REG_WR(PFDEV(pdev),TSEM_REG_VFPF_ERR_NUM, ABS_VFID(pdev));
        REG_WR(PFDEV(pdev),USEM_REG_VFPF_ERR_NUM, ABS_VFID(pdev));
        REG_WR(PFDEV(pdev),CSEM_REG_VFPF_ERR_NUM, ABS_VFID(pdev));
        REG_WR(PFDEV(pdev),XSEM_REG_VFPF_ERR_NUM, ABS_VFID(pdev));
    } else {
        DbgMessage2(pdev, FATAL, "lm_pretend_func(%x) returns %d\n",pretend_val,lm_status);
        DbgMessage1(pdev, FATAL, "vf[%d] is not enabled\n", ABS_VFID(pdev));
    }

    return lm_status;
}

lm_status_t
lm_vf_enable_igu_int(struct _lm_device_t * pdev)
{
    u32_t val;
    u16_t pretend_val;
    u8_t num_segs;
    u8_t prod_idx;
    u8_t sb_id;
    u8_t i;
    lm_status_t status;

    /* Need to use pretend for VF */
    pretend_val = ABS_FUNC_ID(pdev) | (1<<3) | (ABS_VFID(pdev) << 4);
    lm_pretend_func(PFDEV(pdev), pretend_val);

    REG_WR(PFDEV(pdev), IGU_REG_SB_INT_BEFORE_MASK_LSB, 0);
    REG_WR(PFDEV(pdev), IGU_REG_SB_INT_BEFORE_MASK_MSB, 0);
    REG_WR(PFDEV(pdev), IGU_REG_SB_MASK_LSB, 0);
    REG_WR(PFDEV(pdev), IGU_REG_SB_MASK_MSB, 0);
    REG_WR(PFDEV(pdev), IGU_REG_PBA_STATUS_LSB, 0);
    REG_WR(PFDEV(pdev), IGU_REG_PBA_STATUS_MSB, 0);


    val=REG_RD(PFDEV(pdev), IGU_REG_VF_CONFIGURATION);

    SET_FLAGS(val, IGU_VF_CONF_FUNC_EN);
    SET_FLAGS(val, IGU_VF_CONF_MSI_MSIX_EN);

    if (pdev->params.interrupt_mode == LM_INT_MODE_SIMD) {
        SET_FLAGS(val,IGU_VF_CONF_SINGLE_ISR_EN);
    }

    /* set Parent PF */
    val |= ((FUNC_ID(pdev) << IGU_VF_CONF_PARENT_SHIFT) & IGU_VF_CONF_PARENT_MASK);

	REG_WR(PFDEV(pdev),  IGU_REG_VF_CONFIGURATION, val);

    status = lm_pretend_func(PFDEV(pdev), ABS_FUNC_ID(pdev)); 

    num_segs = (INTR_BLK_MODE(pdev) == INTR_BLK_MODE_BC)? IGU_BC_NDSB_NUM_SEGS : IGU_NORM_NDSB_NUM_SEGS;
    for (sb_id = 0; sb_id < LM_IGU_SB_CNT(pdev); sb_id++) {
        prod_idx = (IGU_BASE_NDSB(pdev) + sb_id)*num_segs; /* bc-assumption consecutive pfs, norm-no assumption */
        for (i = 0; i < num_segs;i++) {
            REG_WR(PFDEV(pdev), IGU_REG_PROD_CONS_MEMORY + (prod_idx + i)*4, 0);
        }
        /* Give Consumer updates with value '0' */
        lm_int_ack_sb_enable(pdev, sb_id);
    }

    return status; 

}

lm_status_t
lm_vf_disable_igu_int(struct _lm_device_t * pdev)
{
    u32_t val;
    u16_t pretend_val;

    /* Need to use pretend for VF */
    if (lm_fl_reset_is_inprogress(PFDEV(pdev))) {
        DbgMessage2(pdev, FATAL, "PF[%d] of VF[%d] is under FLR\n", FUNC_ID(pdev), ABS_VFID(pdev));
        return LM_STATUS_SUCCESS;
    }
    pretend_val = ABS_FUNC_ID(pdev) | (1<<3) | (ABS_VFID(pdev) << 4);
    lm_pretend_func(PFDEV(pdev), pretend_val);

    val = REG_RD(PFDEV(pdev), IGU_REG_VF_CONFIGURATION);

    /* disable both bits, for INTA, MSI and MSI-X. */
    RESET_FLAGS(val, (IGU_VF_CONF_MSI_MSIX_EN | IGU_VF_CONF_SINGLE_ISR_EN | IGU_VF_CONF_FUNC_EN | IGU_VF_CONF_PARENT_MASK));

    REG_WR(PFDEV(pdev),  IGU_REG_VF_CONFIGURATION, val);

    return (lm_pretend_func(PFDEV(pdev), ABS_FUNC_ID(pdev))); 
}

void lm_vf_fl_reset_set_inprogress(struct _lm_device_t * pdev)
{
    MM_ACQUIRE_PF_LOCK(PFDEV(pdev));
    lm_vf_acquire_resource(PFDEV(pdev)->pf_resources.flred_vfs, REL_VFID(pdev), 1);
    DbgMessage2(pdev, FATAL, "Set FLR flag for VF[%d(%d)]\n", ABS_VFID(pdev), REL_VFID(pdev));
    MM_RELEASE_PF_LOCK(PFDEV(pdev));
}

void lm_vf_fl_reset_clear_inprogress(struct _lm_device_t *pdev)
{
    MM_ACQUIRE_PF_LOCK(PFDEV(pdev));
    lm_vf_release_resource(PFDEV(pdev)->pf_resources.flred_vfs, REL_VFID(pdev), 1);
    DbgMessage2(pdev, FATAL, "Clear FLR flag for VF[%d(%d)]\n", ABS_VFID(pdev), REL_VFID(pdev));
    MM_RELEASE_PF_LOCK(PFDEV(pdev));
}

u8_t lm_vf_fl_reset_is_inprogress(struct _lm_device_t *pdev)
{
    u8_t vf_flr_inprogess;
    MM_ACQUIRE_PF_LOCK(PFDEV(pdev));
    vf_flr_inprogess = lm_vf_get_resource_value(PFDEV(pdev)->pf_resources.flred_vfs, REL_VFID(pdev));
    if (vf_flr_inprogess) {
        DbgMessage2(pdev, FATAL, "VF[%d(%d)] is FLRed\n", ABS_VFID(pdev), REL_VFID(pdev));
    }
    MM_RELEASE_PF_LOCK(PFDEV(pdev));
    return vf_flr_inprogess;
}

u16_t lm_vf_pf_get_sb_running_index(struct _lm_device_t *pdev, u8_t sb_id, u8_t sm_idx)
{
    DbgMessage(NULL, FATAL, "lm_vf_pf_get_sb_running_index is not used in basic VF\n");
    DbgBreak();
    return 0;
}

u16_t lm_vf_pf_get_sb_index(struct _lm_device_t *pdev, u8_t sb_id, u8_t idx)
{
    DbgMessage(NULL, FATAL, "lm_vf_pf_get_sb_running_index is not used in basic VF\n");
    DbgBreak();
    return 0;
}

u16_t lm_vf_get_doorbell_size(struct _lm_device_t *pdev)
{
    DbgMessage(NULL, FATAL, "lm_vf_get_doorbell_size is not used in basic VF\n");
    DbgBreak();
    return 0;
}

lm_status_t lm_vf_pf_set_q_filters(struct _lm_device_t * pdev, u8 vf_qid, u8_t to_indicate, q_filter_type filter_type, u8_t * pbuf, u32_t buf_len, u16_t vlan_tag, u8_t set_mac)
{
    DbgMessage(NULL, FATAL, "lm_vf_pf_set_q_filters is not used in basic VF\n");
    DbgBreak();
    return LM_STATUS_FAILURE;
}

lm_status_t lm_vf_pf_set_q_filters_list(struct _lm_device_t * pdev, u8 vf_qid, u8_t to_indicate, q_filter_type filter_type, d_list_t * pbuf, u16_t vlan_tag, u8_t set_mac)
{
    DbgMessage(NULL, FATAL, "lm_vf_pf_set_q_filters_list is not used in basic VF\n");
    DbgBreak();
    return LM_STATUS_FAILURE;
}

lm_status_t lm_vf_pf_tear_q_down(struct _lm_device_t * pdev, u8 vf_qid)
{
    DbgMessage(NULL, FATAL, "lm_vf_pf_tear_q_down is not used in basic VF\n");
    DbgBreak();
    return LM_STATUS_FAILURE;
}

lm_status_t lm_vf_queue_init(struct _lm_device_t *pdev, u8_t cid)
{
    DbgMessage(NULL, FATAL, "lm_vf_queue_init is not used in basic VF\n");
    DbgBreak();
    return LM_STATUS_FAILURE;
}

lm_status_t lm_vf_queue_close(struct _lm_device_t *pdev, u8_t cid)
{
    DbgMessage(NULL, FATAL, "lm_vf_queue_close is not used in basic VF\n");
    DbgBreak();
    return LM_STATUS_FAILURE;
}

#endif

