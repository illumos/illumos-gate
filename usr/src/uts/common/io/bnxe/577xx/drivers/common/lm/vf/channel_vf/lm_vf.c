#ifdef VF_INVOLVED

#include "lm5710.h"
#include "bd_chain.h"
#include "577xx_int_offsets.h"
#include "context.h"
#include "command.h"

extern void lm_int_igu_ack_sb(lm_device_t *pdev, u8_t rss_id, u8_t storm_id, u16_t sb_index, u8_t int_op, u8_t is_update_idx);
//#define LM_VF_PM_MESS_STATE_READY_TO_SEND       0
//#define LM_VF_PM_MESS_STATE_SENT                1

/**********************VF_PF FUNCTIONS**************************************/
/**
 * Function send a message over the pf/vf channel, first writes the message low/high addr
 * and then writes to the "addr-valid" in the trigger-zone... this causes the FW to wake
 * up and handle the message.
 *
 * @param pdev
 * @param mess
 *
 * @return lm_status_t
 */

u8_t lm_vf_is_lamac_restricted(struct _lm_device_t *pdev)
{
    return (pdev->vars.is_pf_provides_mac && (pdev->vars.is_pf_restricts_lamac || pdev->vars.is_pf_rejected_lamac));
}

static u8_t lm_vf_check_mac_restriction(struct _lm_device_t *pdev, struct pfvf_acquire_resp_tlv *pf_resp)
{
    return (!(pf_resp->pfdev_info.pf_cap | PFVF_CAP_ALLOW_MAC));
}

static lm_status_t lm_pf_get_queues_number(struct _lm_device_t *pdev, lm_vf_info_t *vf_info, u8_t *num_rxqs, u8_t * num_txqs)
{
    return mm_pf_get_queues_number(pdev, vf_info, num_rxqs, num_txqs);
}

static lm_status_t lm_pf_get_filters_number(struct _lm_device_t *pdev, lm_vf_info_t *vf_info,
                                                u8_t *num_mac_filters,
                                                u8_t *num_vlan_filters,
                                                u8_t *num_mc_filters)
{
    return mm_pf_get_filters_number(pdev, vf_info, num_mac_filters, num_vlan_filters, num_mc_filters);
}

static lm_status_t lm_pf_get_macs(struct _lm_device_t *pdev, lm_vf_info_t *vf_info, u8_t *permanent_mac_addr, u8_t *current_mac_addr)
{
    return mm_pf_get_macs(pdev, vf_info, permanent_mac_addr, current_mac_addr);
}

static u8 lm_pf_vf_check_compatibility(struct _lm_device_t *pdev,
                                                lm_vf_info_t *vf_info,
                                                struct vf_pf_msg_acquire *request)
{
    u8 status = SW_PFVF_STATUS_SUCCESS;
    if( 0 == request->vfdev_info.vf_fw_hsi_version )
    {
        // here we handle cases where HSI version of PF is not compatible with HSI version of VF
        // Until this code section was added, VF always returned 0 so we fail request for old VF's
        // Currenly (22/9/2011) we consider all VF that return ANY value (not 0) as valid
        // once HSI will change, we'll need to enter here logic that will say:
        // if( ( 0 == vf_fw_hsi_version) || ( some condition with vf_fw_hsi_version )
        status  = SW_PFVF_STATUS_MISMATCH_FW_HSI;
    }
    else
    {
        #define FW_REV_INTERFACE_SUPPORTED     0x07084b00 // 7.8.75.0 
       
        if (request->vfdev_info.vf_fw_hsi_version >= FW_REV_INTERFACE_SUPPORTED)
        {
            vf_info->fp_hsi_ver = request->vfdev_info.fp_hsi_ver;
        }
        else
        {
            vf_info->fp_hsi_ver = 0;
        }
    }
    if (vf_info->fp_hsi_ver > ETH_FP_HSI_VERSION)
    {
        /* VF FP HSI VER is newer than PF... treat as mismatch */
        status  = SW_PFVF_STATUS_MISMATCH_FW_HSI;
    }
        
    if (!(request->vfdev_info.vf_aux & SW_VFPF_VFDEF_INFO_AUX_DIRECT_DQ))
    {
        status  = SW_PFVF_STATUS_MISMATCH_FW_HSI;
    }
    
    return status; 
}

static lm_status_t lm_pf_vf_fill_acquire_response(struct _lm_device_t *pdev, lm_vf_info_t *vf_info)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    struct vf_pf_msg_acquire*      request            = NULL;
    struct pf_vf_msg_acquire_resp* response           = NULL;
    u8_t                           i                  = 0;
    u8_t                           num_mac_filters    = 0;
    u8_t                           num_vlan_filters   = 0;
    u8_t                           num_mc_filters     = 0;
    u8_t                           status;
    
    DbgBreakIf(!(pdev && vf_info && vf_info->pf_vf_response.request_virt_addr && vf_info->pf_vf_response.response_virt_addr));

    request = vf_info->pf_vf_response.request_virt_addr;
    response = vf_info->pf_vf_response.response_virt_addr;

    status = lm_pf_vf_check_compatibility(pdev, vf_info, request);
    if (status != SW_PFVF_STATUS_SUCCESS)
    {
        response->hdr.status = status;
        return lm_status;
    }
    
    response->pfdev_info.chip_num = pdev->hw_info.chip_id;//CHIP_NUM(pdev);
    response->pfdev_info.pf_cap               = PFVF_CAP_DHC | PFVF_CAP_TPA;
    if (pdev->params.debug_sriov_vfs)
    {
        response->pfdev_info.pf_cap |= PFVF_DEBUG;
    }
    response->pfdev_info.db_size              = LM_VF_DQ_CID_SIZE;
    response->pfdev_info.indices_per_sb = HC_SB_MAX_INDICES_E2;
    vf_info->num_vf_chains_requested = request->resc_request.num_sbs;
    vf_info->num_sbs = response->resc.num_sbs = min (vf_info->num_allocated_chains, request->resc_request.num_sbs);
    response->resc.igu_cnt = vf_info->num_sbs;

    for (i = 0; i < response->resc.num_sbs; i++)
    {
        response->resc.hw_sbs[i].hw_sb_id = LM_VF_IGU_SB_ID(vf_info, i);
        response->resc.hw_sbs[i].sb_qid = LM_FW_VF_DHC_QZONE_ID(vf_info, i);
        response->resc.hw_qid[i] = LM_FW_VF_QZONE_ID(vf_info, i);
    }

    if (response->resc.num_sbs < vf_info->num_allocated_chains)
    {
        for (i = response->resc.num_sbs; i < vf_info->num_allocated_chains; i++)
        {
            lm_pf_release_vf_igu_block(pdev, vf_info->vf_chains[i].igu_sb_id);
            lm_pf_release_separate_vf_chain_resources(pdev, vf_info->relative_vf_id, i);
        }
#ifdef _VBD_
        //Generate message
#endif
        vf_info->num_allocated_chains = response->resc.num_sbs;
    }

    vf_info->num_rxqs = response->resc.num_rxqs = min(vf_info->num_sbs, request->resc_request.num_rxqs);
    vf_info->num_txqs = response->resc.num_txqs = min(vf_info->num_sbs, request->resc_request.num_txqs);
    vf_info->num_rxqs = response->resc.num_rxqs = min(vf_info->num_rxqs, response->resc.num_sbs);
    vf_info->num_txqs = response->resc.num_txqs = min(vf_info->num_txqs, response->resc.num_sbs);

    lm_pf_get_filters_number(pdev,vf_info,
                             &num_mac_filters,
                             &num_vlan_filters,
                             &num_mc_filters);

    vf_info->num_mac_filters = response->resc.num_mac_filters = min(num_mac_filters, request->resc_request.num_mac_filters);
    vf_info->num_vlan_filters = response->resc.num_vlan_filters = min(num_vlan_filters, request->resc_request.num_vlan_filters);
    vf_info->num_mc_filters = response->resc.num_mc_filters = min(num_mc_filters, request->resc_request.num_mc_filters);

    lm_pf_get_macs(pdev,vf_info, response->resc.permanent_mac_addr, response->resc.current_mac_addr);
//#ifdef UPDATED_MAC
    if (pdev->params.sriov_inc_mac)
    {
        u8_t mac_addition = (u8_t)pdev->params.sriov_inc_mac;
        response->resc.current_mac_addr[5] += mac_addition;
    }
//#endif
    response->hdr.status = SW_PFVF_STATUS_SUCCESS;
    vf_info->vf_si_state = PF_SI_ACQUIRED;
    return lm_status;
}

static lm_status_t lm_pf_vf_fill_init_vf_response(struct _lm_device_t *pdev, lm_vf_info_t *vf_info)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    struct vf_pf_msg_init_vf * request = NULL;
    struct pf_vf_msg_resp * response = NULL;
    u8_t sb_idx = 0;
    u8_t q_idx = 0;
    u8_t function_fw_id;
    u32_t i;

    DbgBreakIf(!(pdev && vf_info && vf_info->pf_vf_response.request_virt_addr && vf_info->pf_vf_response.response_virt_addr));
//    DbgBreak();
    request = vf_info->pf_vf_response.request_virt_addr;
    response = vf_info->pf_vf_response.response_virt_addr;

    //lm_status = lm_pf_enable_vf(pdev, vf_info->abs_vf_id);

    MM_ACQUIRE_VFS_STATS_LOCK(pdev);
    DbgBreakIf(vf_info->vf_stats.vf_stats_state != VF_STATS_NONE);
    vf_info->vf_stats.vf_fw_stats_phys_data.as_u64 = request->stats_addr;
    vf_info->vf_stats.vf_stats_state = VF_STATS_REQ_READY;
    vf_info->vf_stats.stop_collect_stats = TRUE;
    vf_info->vf_stats.vf_stats_flag = 0;
    vf_info->vf_stats.vf_stats_cnt = 0;
    vf_info->vf_stats.vf_exracted_stats_cnt = 0;
    MM_RELEASE_VFS_STATS_LOCK(pdev);

    for (sb_idx = 0; sb_idx < vf_info->num_sbs; sb_idx++) {
        lm_pf_init_vf_non_def_sb(pdev, vf_info, sb_idx, request->sb_addr[sb_idx]);
    }

    DbgBreakIf((XSTORM_SPQ_DATA_SIZE % 4) != 0);
    for (i = 0; i < XSTORM_SPQ_DATA_SIZE/sizeof(u32_t); i++) {
        REG_WR(PFDEV(pdev),XSEM_REG_FAST_MEMORY + XSTORM_VF_SPQ_DATA_OFFSET(vf_info->abs_vf_id) + i*sizeof(u32_t),0);
    }

    REG_WR(PFDEV(pdev),XSEM_REG_FAST_MEMORY + (XSTORM_VF_SPQ_PAGE_BASE_OFFSET(vf_info->abs_vf_id)),0);
    REG_WR(PFDEV(pdev),XSEM_REG_FAST_MEMORY + (XSTORM_VF_SPQ_PAGE_BASE_OFFSET(vf_info->abs_vf_id)) + 4,0);
    REG_WR(PFDEV(pdev),XSEM_REG_FAST_MEMORY + (XSTORM_VF_SPQ_PROD_OFFSET(vf_info->abs_vf_id)),0);

    for (q_idx = 0; q_idx < vf_info->num_rxqs; q_idx++) {
        u32_t reg = PXP_REG_HST_ZONE_PERMISSION_TABLE + LM_FW_VF_QZONE_ID(vf_info,q_idx) * 4;
        u32_t val = vf_info->abs_vf_id | (1 << 6);
        REG_WR(PFDEV(pdev), reg, val);

    }
    /*lm_status = lm_set_rx_mask(pdev, LM_CLI_IDX_NDIS, LM_RX_MASK_ACCEPT_NONE);
    if(LM_STATUS_SUCCESS != lm_status)
    {
        DbgMessage(pdev, FATAL, "lm_set_rx_mask(LM_RX_MASK_ACCEPT_NONE) returns %d\n",lm_status);
        return lm_status;
    }*/
/*
Enable the function in STORMs
*/
    function_fw_id = 8 + vf_info->abs_vf_id;

    LM_INTMEM_WRITE8(PFDEV(pdev), XSTORM_VF_TO_PF_OFFSET(function_fw_id), FUNC_ID(pdev), BAR_XSTRORM_INTMEM);
    LM_INTMEM_WRITE8(PFDEV(pdev), CSTORM_VF_TO_PF_OFFSET(function_fw_id), FUNC_ID(pdev), BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(PFDEV(pdev), TSTORM_VF_TO_PF_OFFSET(function_fw_id), FUNC_ID(pdev), BAR_TSTRORM_INTMEM);
    LM_INTMEM_WRITE8(PFDEV(pdev), USTORM_VF_TO_PF_OFFSET(function_fw_id), FUNC_ID(pdev), BAR_USTRORM_INTMEM);

    LM_INTMEM_WRITE8(PFDEV(pdev), XSTORM_FUNC_EN_OFFSET(function_fw_id), 1, BAR_XSTRORM_INTMEM);
    LM_INTMEM_WRITE8(PFDEV(pdev), CSTORM_FUNC_EN_OFFSET(function_fw_id), 1, BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(PFDEV(pdev), TSTORM_FUNC_EN_OFFSET(function_fw_id), 1, BAR_TSTRORM_INTMEM);
    LM_INTMEM_WRITE8(PFDEV(pdev), USTORM_FUNC_EN_OFFSET(function_fw_id), 1, BAR_USTRORM_INTMEM);

    lm_status = lm_pf_enable_vf_igu_int(pdev, vf_info->abs_vf_id);

    if (lm_status == LM_STATUS_SUCCESS) {
        response->hdr.status = SW_PFVF_STATUS_SUCCESS;
        vf_info->vf_si_state = PF_SI_VF_INITIALIZED;
    } else {
        response->hdr.status = SW_PFVF_STATUS_FAILURE;
        DbgBreak();
    }
    return lm_status;
}


static lm_status_t lm_pf_vf_fill_setup_q_response(struct _lm_device_t *pdev, lm_vf_info_t *vf_info)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    struct vf_pf_msg_setup_q * request = NULL;
    struct pf_vf_msg_resp * response = NULL;
    struct sw_vf_pf_rxq_params * rxq_params = NULL;
    struct sw_vf_pf_txq_params * txq_params = NULL;
//    lm_rcq_chain_t * rcq_chain = NULL;
    u8_t    cmd_id        = 0;
    u8_t    type          = 0;
    u8_t    q_id          = 0;
    u8_t    valid         = 0;
    u32_t   vf_cid_of_pf  = 0;

    DbgBreakIf(!(pdev && vf_info && vf_info->pf_vf_response.request_virt_addr && vf_info->pf_vf_response.response_virt_addr));

    request = vf_info->pf_vf_response.request_virt_addr;
    response = vf_info->pf_vf_response.response_virt_addr;
    q_id = request->vf_qid;
    valid = request->param_valid;


    if (request->param_valid & VFPF_RXQ_VALID) {
        u32_t mem_size = sizeof(struct tpa_update_ramrod_data);
        rxq_params = &request->rxq;
        vf_info->vf_chains[q_id].mtu = rxq_params->mtu;
        if (rxq_params->flags & SW_VFPF_QUEUE_FLG_TPA) {
            DbgBreakIf(rxq_params->sge_addr == 0);
            vf_info->vf_chains[q_id].sge_addr = rxq_params->sge_addr;
            vf_info->vf_chains[q_id].tpa_ramrod_data_virt = mm_alloc_phys_mem(pdev, mem_size, &vf_info->vf_chains[q_id].tpa_ramrod_data_phys, 0, LM_RESOURCE_NDIS);

            if(CHK_NULL(vf_info->vf_chains[q_id].tpa_ramrod_data_virt))
            {
                DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
                response->hdr.status = SW_PFVF_STATUS_FAILURE;
                return LM_STATUS_RESOURCE ;
            }
            mm_mem_zero((void *)vf_info->vf_chains[q_id].tpa_ramrod_data_virt, mem_size);
    }
    }
    if (request->param_valid & VFPF_TXQ_VALID) {
        txq_params = &request->txq;
    }

    lm_status = lm_pf_init_vf_client_init_data(pdev, vf_info, q_id, rxq_params, txq_params);
    if (lm_status == LM_STATUS_SUCCESS) {
        vf_cid_of_pf = LM_VF_Q_ID_TO_PF_CID(pdev, vf_info, q_id);
        lm_init_connection_context(pdev, vf_cid_of_pf, 0);
        cmd_id = RAMROD_CMD_ID_ETH_CLIENT_SETUP;
        type = (ETH_CONNECTION_TYPE | ((8 + vf_info->abs_vf_id) << SPE_HDR_T_FUNCTION_ID_SHIFT));
        lm_set_con_state(pdev, vf_cid_of_pf, LM_CON_STATE_OPEN_SENT);

        lm_sq_post(pdev,
                   vf_cid_of_pf,
                   cmd_id,
                   CMD_PRIORITY_MEDIUM,
                   type,
                   pdev->client_info[LM_SW_VF_CLI_ID(vf_info,q_id)].client_init_data_phys.as_u64);

        lm_status = lm_eth_wait_state_change(pdev, LM_CON_STATE_OPEN, vf_cid_of_pf);

    }

    if (lm_status == LM_STATUS_SUCCESS) {
        response->hdr.status = SW_PFVF_STATUS_SUCCESS;
        mm_atomic_inc(&vf_info->vf_si_num_of_active_q);
        if (q_id == 0) {
            MM_ACQUIRE_VFS_STATS_LOCK(pdev);
            DbgBreakIf(vf_info->vf_stats.vf_stats_state != VF_STATS_REQ_READY)
            vf_info->vf_stats.vf_stats_state = VF_STATS_REQ_SUBMITTED;
            vf_info->vf_stats.stop_collect_stats = FALSE;
            if (!vf_info->vf_stats.do_not_collect_pf_stats) {
                vf_info->vf_stats.vf_stats_flag = VF_STATS_COLLECT_FW_STATS_FOR_PF;
            }
            if (vf_info->vf_stats.vf_fw_stats_phys_data.as_u64) {
                vf_info->vf_stats.vf_stats_flag |= VF_STATS_COLLECT_FW_STATS_FOR_VF;
            }
            MM_RELEASE_VFS_STATS_LOCK(pdev);
        }
    } else if (lm_status == LM_STATUS_PENDING) {
        response->hdr.status = SW_PFVF_STATUS_WAITING;
    } else {
        response->hdr.status = SW_PFVF_STATUS_FAILURE;
    }

    return lm_status;
}

// ASSUMPTION: CALLED IN PASSIVE LEVEL!!!

static lm_status_t lm_pf_vf_fill_set_q_filters_response(struct _lm_device_t *pdev, lm_vf_info_t *vf_info)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    struct vf_pf_msg_set_q_filters * request = NULL;
    struct pf_vf_msg_resp * response = NULL;
    lm_rx_mask_t    rx_mask = 0;

    request = vf_info->pf_vf_response.request_virt_addr;
    response = vf_info->pf_vf_response.response_virt_addr;

 //   DbgBreak();
    if (request->flags & VFPF_SET_Q_FILTERS_RX_MASK_CHANGED) {
        if (VFPF_RX_MASK_ACCEPT_NONE == request->rx_mask) {
            lm_status = lm_set_rx_mask(pdev, LM_SW_VF_CLI_ID(vf_info,request->vf_qid), LM_RX_MASK_ACCEPT_NONE, NULL);
            if (lm_status == LM_STATUS_PENDING)
            {
                lm_status = lm_wait_set_rx_mask_done(pdev, LM_SW_VF_CLI_ID(vf_info,request->vf_qid));
            }
        } else {
            if (GET_FLAGS(request->rx_mask,VFPF_RX_MASK_ACCEPT_MATCHED_UNICAST | VFPF_RX_MASK_ACCEPT_MATCHED_MULTICAST |
                           VFPF_RX_MASK_ACCEPT_ALL_MULTICAST | VFPF_RX_MASK_ACCEPT_ALL_UNICAST | VFPF_RX_MASK_ACCEPT_BROADCAST) ==
                           (VFPF_RX_MASK_ACCEPT_MATCHED_UNICAST | VFPF_RX_MASK_ACCEPT_MATCHED_MULTICAST |
                           VFPF_RX_MASK_ACCEPT_ALL_MULTICAST | VFPF_RX_MASK_ACCEPT_ALL_UNICAST | VFPF_RX_MASK_ACCEPT_BROADCAST)) {
                if (!vf_info->is_promiscuous_mode_restricted)
                {
                    rx_mask = LM_RX_MASK_PROMISCUOUS_MODE;
                lm_status = lm_set_rx_mask(pdev, LM_SW_VF_CLI_ID(vf_info,request->vf_qid), LM_RX_MASK_PROMISCUOUS_MODE, NULL);
                if (lm_status == LM_STATUS_PENDING)
                {
                    lm_status = lm_wait_set_rx_mask_done(pdev, LM_SW_VF_CLI_ID(vf_info,request->vf_qid));
                }
                }
                else
                {
                    request->rx_mask &= ~(VFPF_RX_MASK_ACCEPT_ALL_UNICAST | VFPF_RX_MASK_ACCEPT_ALL_MULTICAST);
                }
            }

            if (!rx_mask)
            {
                if (GET_FLAGS(request->rx_mask,VFPF_RX_MASK_ACCEPT_MATCHED_UNICAST)) {
                    rx_mask |= LM_RX_MASK_ACCEPT_UNICAST;
                }
                if (GET_FLAGS(request->rx_mask,VFPF_RX_MASK_ACCEPT_MATCHED_MULTICAST)) {
                    rx_mask |= LM_RX_MASK_ACCEPT_MULTICAST;
                }
                if (GET_FLAGS(request->rx_mask,VFPF_RX_MASK_ACCEPT_ALL_MULTICAST)) {
                    rx_mask |= LM_RX_MASK_ACCEPT_ALL_MULTICAST;
                }
                if (GET_FLAGS(request->rx_mask, VFPF_RX_MASK_ACCEPT_BROADCAST)) {
                    rx_mask |= LM_RX_MASK_ACCEPT_BROADCAST;
                }
                lm_status = lm_set_rx_mask(pdev, LM_SW_VF_CLI_ID(vf_info,request->vf_qid), rx_mask, NULL);
                if (lm_status == LM_STATUS_PENDING)
                {
                    lm_status = lm_wait_set_rx_mask_done(pdev, LM_SW_VF_CLI_ID(vf_info,request->vf_qid));
                }
            }
        }
    }
    if (request->flags & VFPF_SET_Q_FILTERS_MAC_VLAN_CHANGED) {
        u8_t mac_idx;
        u8_t set_mac;
        for (mac_idx = 0; mac_idx < request->n_mac_vlan_filters; mac_idx++) {
            if (request->filters[mac_idx].flags & VFPF_Q_FILTER_DEST_MAC_PRESENT) {
                if (request->filters[mac_idx].flags & VFPF_Q_FILTER_SET_MAC) {
                    set_mac = TRUE;
                } else {
                    set_mac = FALSE;
                }
                lm_status = lm_set_mac_addr(pdev, request->filters[mac_idx].dest_mac,
                                            LM_SET_CAM_NO_VLAN_FILTER, LM_SW_VF_CLI_ID(vf_info,request->vf_qid), NULL, set_mac, 0);
                if (lm_status == LM_STATUS_PENDING) {
                    lm_status = lm_wait_set_mac_done(pdev, LM_SW_VF_CLI_ID(vf_info,request->vf_qid));
                }
            } else {
                //
            }
        }
    }
    if (lm_status == LM_STATUS_SUCCESS) {
        response->hdr.status = SW_PFVF_STATUS_SUCCESS;
    } else if (lm_status == LM_STATUS_PENDING) {
        DbgBreak();
        response->hdr.status = SW_PFVF_STATUS_WAITING;
    } else {
        response->hdr.status = SW_PFVF_STATUS_FAILURE;
    }
    return lm_status;
}

static lm_status_t lm_pf_vf_fill_teardown_q_response(struct _lm_device_t *pdev, lm_vf_info_t *vf_info)
{
    lm_status_t lm_status = LM_STATUS_FAILURE;
    struct vf_pf_msg_q_op * request = NULL;
    struct pf_vf_msg_resp * response = NULL;
    u8_t    q_id          = 0;
    u32_t cid;

    //DbgBreak();
    request = vf_info->pf_vf_response.request_virt_addr;
    response = vf_info->pf_vf_response.response_virt_addr;
    q_id = request->vf_qid;

    if (q_id == 0) {
        MM_ACQUIRE_VFS_STATS_LOCK(pdev);
        if (vf_info->vf_stats.vf_stats_state != VF_STATS_REQ_IN_PROCESSING) {
            vf_info->vf_stats.vf_stats_state = VF_STATS_REQ_READY;
        }
        vf_info->vf_stats.stop_collect_stats = TRUE;
        vf_info->vf_stats.vf_stats_flag = 0;
        MM_RELEASE_VFS_STATS_LOCK(pdev);
        DbgMessage(pdev, WARN, "lm_pf_vf_fill_teardown_q_response for VF[%d]: stats_cnt: %d\n",vf_info->relative_vf_id,vf_info->vf_stats.vf_stats_cnt);

        lm_status = lm_pf_vf_wait_for_stats_ready(pdev, vf_info);
        DbgMessage(pdev, WARN, "lm_pf_vf_fill_teardown_q_response for VF[%d]: stats_cnt: %d\n",vf_info->relative_vf_id,vf_info->vf_stats.vf_stats_cnt);
        if (lm_status != LM_STATUS_SUCCESS) {
            if (lm_status != LM_STATUS_ABORTED)
            {
            DbgBreak();
        }
            response->hdr.status = SW_PFVF_STATUS_FAILURE;
            return lm_status;
    }
    }

    cid = LM_VF_Q_ID_TO_PF_CID(pdev, vf_info, q_id);


    if (vf_info->was_malicious || vf_info->was_flred)
    {
        lm_status = LM_STATUS_SUCCESS;
	lm_set_con_state(pdev, cid, LM_CON_STATE_CLOSE);
    }
    else
    {
	lm_status = lm_close_eth_con(pdev, cid, TRUE);
    }

    if (lm_status == LM_STATUS_SUCCESS) {
        response->hdr.status = SW_PFVF_STATUS_SUCCESS;
        mm_atomic_dec(&vf_info->vf_si_num_of_active_q);
    } else if (lm_status == LM_STATUS_PENDING) {
        DbgBreak();
        response->hdr.status = SW_PFVF_STATUS_WAITING;
    } else {
        response->hdr.status = SW_PFVF_STATUS_FAILURE;
    }
    return lm_status;
}

static lm_status_t lm_pf_vf_fill_close_vf_response(struct _lm_device_t *pdev, lm_vf_info_t *vf_info)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    u8_t function_fw_id;
    u8_t sb_idx;
    u8_t q_idx;
    struct vf_pf_msg_close_vf * request = NULL;
    struct pf_vf_msg_resp * response = NULL;
    u32_t cid;

    //DbgBreak();
    request = vf_info->pf_vf_response.request_virt_addr;
    response = vf_info->pf_vf_response.response_virt_addr;

    MM_ACQUIRE_VFS_STATS_LOCK(pdev);
    if (vf_info->vf_stats.vf_stats_state != VF_STATS_REQ_IN_PROCESSING) {
        vf_info->vf_stats.vf_stats_state = VF_STATS_REQ_READY;
    }
    vf_info->vf_stats.stop_collect_stats = TRUE;
    vf_info->vf_stats.vf_stats_flag = 0;
    MM_RELEASE_VFS_STATS_LOCK(pdev);

    lm_status = lm_pf_vf_wait_for_stats_ready(pdev, vf_info);
    if (lm_status != LM_STATUS_SUCCESS) {
        DbgBreak();
    } else {
        vf_info->vf_stats.vf_stats_state = VF_STATS_NONE;
    }

    for (q_idx = 0; q_idx < vf_info->vf_si_num_of_active_q; q_idx++) {
        cid = LM_VF_Q_ID_TO_PF_CID(pdev, vf_info, q_idx);
	if (vf_info->was_malicious || vf_info->was_flred)
	{
	    lm_status = LM_STATUS_SUCCESS;
	    lm_set_con_state(pdev, cid, LM_CON_STATE_CLOSE);
	}
	else
	{
	    lm_status = lm_close_eth_con(pdev, cid, TRUE);
	}
    }
    vf_info->vf_si_num_of_active_q = 0;

    lm_pf_disable_vf_igu_int(pdev, vf_info->abs_vf_id);
    /*
    Disable the function in STORMs
    */
    function_fw_id = 8 + vf_info->abs_vf_id;

    LM_INTMEM_WRITE8(PFDEV(pdev), XSTORM_FUNC_EN_OFFSET(function_fw_id), 0, BAR_XSTRORM_INTMEM);
    LM_INTMEM_WRITE8(PFDEV(pdev), CSTORM_FUNC_EN_OFFSET(function_fw_id), 0, BAR_CSTRORM_INTMEM);
    LM_INTMEM_WRITE8(PFDEV(pdev), TSTORM_FUNC_EN_OFFSET(function_fw_id), 0, BAR_TSTRORM_INTMEM);
    LM_INTMEM_WRITE8(PFDEV(pdev), USTORM_FUNC_EN_OFFSET(function_fw_id), 0, BAR_USTRORM_INTMEM);

    for (sb_idx = 0; sb_idx < vf_info->num_sbs; sb_idx++) {
        lm_clear_non_def_status_block(pdev,  LM_FW_VF_SB_ID(vf_info, sb_idx));
    }

    for (q_idx = 0; q_idx < vf_info->num_rxqs; q_idx++) {
        u32_t reg = PXP_REG_HST_ZONE_PERMISSION_TABLE + LM_FW_VF_QZONE_ID(vf_info,q_idx) * 4;
        u32_t val = 0;
        REG_WR(PFDEV(pdev), reg, val);
    }

    vf_info->vf_si_state = PF_SI_ACQUIRED;
    if (lm_status == LM_STATUS_SUCCESS) {
        response->hdr.status = SW_PFVF_STATUS_SUCCESS;
    } else if (lm_status == LM_STATUS_PENDING) {
        DbgBreak();
        response->hdr.status = SW_PFVF_STATUS_WAITING;
    } else {
        response->hdr.status = SW_PFVF_STATUS_FAILURE;
    }
    return lm_status;
}

static lm_status_t lm_pf_vf_fill_release_vf_response(struct _lm_device_t *pdev, lm_vf_info_t *vf_info)
{
    struct pf_vf_msg_resp * response = NULL;
    lm_status_t lm_status = LM_STATUS_SUCCESS;

    response = vf_info->pf_vf_response.response_virt_addr;
    response->hdr.status = SW_PFVF_STATUS_SUCCESS;
    vf_info->vf_si_state = PF_SI_WAIT_FOR_ACQUIRING_REQUEST;

    return lm_status;
}


static lm_status_t lm_pf_vf_fill_update_rss_response(struct _lm_device_t *pdev, lm_vf_info_t *vf_info)
{
    struct pf_vf_msg_resp * response = NULL;
    struct vf_pf_msg_rss * request = NULL;
    struct ecore_config_rss_params * rss_params = NULL;
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    u8_t    ind_table_size;
    u8_t    ind_table_idx;

 //   DbgBreak();
    request = vf_info->pf_vf_response.request_virt_addr;
    response = vf_info->pf_vf_response.response_virt_addr;
    rss_params = &vf_info->vf_slowpath_info.rss_params;
    mm_mem_zero(rss_params, sizeof(struct ecore_config_rss_params));
    ECORE_SET_BIT(RAMROD_COMP_WAIT, &rss_params->ramrod_flags);
    rss_params->rss_flags = request->rss_flags;
    rss_params->rss_result_mask = request->rss_result_mask;
    mm_memcpy(rss_params->rss_key, request->rss_key, sizeof(u32_t) * 10);

    ind_table_size = request->rss_result_mask + 1;
    for (ind_table_idx = 0; ind_table_idx < ind_table_size; ind_table_idx++) {
        rss_params->ind_table[ind_table_idx] = LM_FW_VF_CLI_ID(vf_info, request->ind_table[ind_table_idx]);
    }
    rss_params->rss_obj = &vf_info->vf_slowpath_info.rss_conf_obj;
    lm_status = ecore_config_rss(pdev, rss_params);
    if (lm_status == LM_STATUS_SUCCESS) {
        response->hdr.status = SW_PFVF_STATUS_SUCCESS;
    } else {
        response->hdr.status = SW_PFVF_STATUS_FAILURE;
    }

    return lm_status;
}

lm_status_t lm_pf_vf_fill_update_rsc_response(struct _lm_device_t *pdev, lm_vf_info_t *vf_info)
{
    struct pf_vf_msg_resp * response = NULL;
    struct vf_pf_msg_rsc * request = NULL;
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    u32_t   q_idx;

    //DbgBreak();
    request = vf_info->pf_vf_response.request_virt_addr;
    response = vf_info->pf_vf_response.response_virt_addr;

    vf_info->vf_tpa_info.ramrod_recv_cnt = vf_info->vf_si_num_of_active_q;
    for (q_idx = 0; q_idx < vf_info->vf_si_num_of_active_q; q_idx++) {
        lm_status = lm_pf_tpa_send_vf_ramrod(pdev, vf_info, q_idx, (u8_t)request->rsc_ipv4_state, (u8_t)request->rsc_ipv6_state);

        if(LM_STATUS_SUCCESS != lm_status)
        {
            DbgBreakMsg(" Ramrod send failed ");
            break;
        }
    }
    lm_status = lm_wait_state_change(pdev, &vf_info->vf_tpa_info.ramrod_recv_cnt, 0);
    if (lm_status == LM_STATUS_SUCCESS) {
        response->hdr.status = SW_PFVF_STATUS_SUCCESS;
    } else {
        response->hdr.status = SW_PFVF_STATUS_FAILURE;
    }
    return lm_status;
}

lm_status_t lm_pf_process_standard_request(struct _lm_device_t *pdev, lm_vf_info_t *vf_info)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    struct vf_pf_msg_hdr * requst_hdr = vf_info->pf_vf_response.request_virt_addr;
    struct pf_vf_msg_hdr * resp_hdr = vf_info->pf_vf_response.response_virt_addr;

    DbgBreakIf(!(pdev && IS_CHANNEL_VIRT_MODE_MASTER_PFDEV(pdev) && vf_info && (vf_info->pf_vf_response.req_resp_state == VF_PF_REQUEST_IN_PROCESSING)));
    DbgMessage(pdev, WARNvf, "lm_pf_process_standard_request %d for VF[%d]\n",requst_hdr->opcode,vf_info->relative_vf_id);

    resp_hdr->opcode = requst_hdr->opcode;
    resp_hdr->status = SW_PFVF_STATUS_WAITING;
    vf_info->pf_vf_response.response_size = sizeof(struct pf_vf_msg_hdr);
    vf_info->pf_vf_response.response_offset = 0;

    // Check PF/VF interface
    if ( PFVF_IF_VERSION != requst_hdr->if_ver )
    {
        resp_hdr->status                       = SW_PFVF_STATUS_MISMATCH_PF_VF_VERSION;
        vf_info->pf_vf_response.req_resp_state = VF_PF_RESPONSE_READY;
    }
    else
    {
        switch (requst_hdr->opcode)
        {
        case PFVF_OP_ACQUIRE:
            resp_hdr->opcode_ver = PFVF_ACQUIRE_VER;
            if (vf_info->vf_si_state != PF_SI_WAIT_FOR_ACQUIRING_REQUEST)
            {
                resp_hdr->status = SW_PFVF_STATUS_FAILURE;
                DbgBreakIf(!DBG_BREAK_ON(UNDER_TEST));
                break;
            }
            if (PFVF_ACQUIRE_VER != requst_hdr->opcode_ver)
            {
                resp_hdr->status = SW_PFVF_STATUS_NOT_SUPPORTED;
                vf_info->pf_vf_response.req_resp_state = VF_PF_RESPONSE_READY;
                break;
            }
            lm_status = lm_pf_vf_fill_acquire_response(pdev,vf_info);
            if (lm_status == LM_STATUS_SUCCESS)
            {
                vf_info->pf_vf_response.response_size = sizeof(struct pf_vf_msg_acquire_resp);
            }
            break;
        case PFVF_OP_INIT_VF:
            resp_hdr->opcode_ver = PFVF_INIT_VF_VER;
            if (vf_info->vf_si_state != PF_SI_ACQUIRED)
            {
                resp_hdr->status = SW_PFVF_STATUS_FAILURE;
                DbgBreakIf(!DBG_BREAK_ON(UNDER_TEST));
                break;
            }
            if (PFVF_INIT_VF_VER != requst_hdr->opcode_ver) {
                resp_hdr->status = SW_PFVF_STATUS_NOT_SUPPORTED;
                vf_info->pf_vf_response.req_resp_state = VF_PF_RESPONSE_READY;
                break;
            }
            lm_status = lm_pf_vf_fill_init_vf_response(pdev,vf_info);
            break;
        case PFVF_OP_SETUP_Q:
            resp_hdr->opcode_ver = PFVF_SETUP_Q_VER;
            if (vf_info->vf_si_state != PF_SI_VF_INITIALIZED) {
                resp_hdr->status = SW_PFVF_STATUS_FAILURE;
                DbgBreakIf(!DBG_BREAK_ON(UNDER_TEST));
                break;
            }
            if (PFVF_SETUP_Q_VER != requst_hdr->opcode_ver) {
                resp_hdr->status = SW_PFVF_STATUS_NOT_SUPPORTED;
                vf_info->pf_vf_response.req_resp_state = VF_PF_RESPONSE_READY;
                break;
            }
            lm_status = lm_pf_vf_fill_setup_q_response(pdev,vf_info);
            break;
        case PFVF_OP_SET_Q_FILTERS:
            resp_hdr->opcode_ver = PFVF_SET_Q_FILTERS_VER;
            if (PFVF_SET_Q_FILTERS_VER != requst_hdr->opcode_ver) {
                resp_hdr->status = SW_PFVF_STATUS_NOT_SUPPORTED;
                vf_info->pf_vf_response.req_resp_state = VF_PF_RESPONSE_READY;
                break;
            }
            lm_status = lm_pf_vf_fill_set_q_filters_response(pdev,vf_info);
            break;
        case PFVF_OP_ACTIVATE_Q:
            resp_hdr->opcode_ver = PFVF_ACTIVATE_Q_VER;
            if (PFVF_ACTIVATE_Q_VER != requst_hdr->opcode_ver) {
                resp_hdr->status = SW_PFVF_STATUS_NOT_SUPPORTED;
                vf_info->pf_vf_response.req_resp_state = VF_PF_RESPONSE_READY;
                break;
            }
            break;
        case PFVF_OP_DEACTIVATE_Q:
            resp_hdr->opcode_ver = PFVF_DEACTIVATE_Q_VER;
            if (PFVF_DEACTIVATE_Q_VER != requst_hdr->opcode_ver) {
                resp_hdr->status = SW_PFVF_STATUS_NOT_SUPPORTED;
                vf_info->pf_vf_response.req_resp_state = VF_PF_RESPONSE_READY;
                break;
            }
            break;
        case PFVF_OP_TEARDOWN_Q:
            resp_hdr->opcode_ver = PFVF_TEARDOWN_Q_VER;
            if (vf_info->vf_si_state != PF_SI_VF_INITIALIZED) {
                resp_hdr->status = SW_PFVF_STATUS_FAILURE;
                DbgBreakIf(!DBG_BREAK_ON(UNDER_TEST));
                break;
            }
            if (PFVF_TEARDOWN_Q_VER != requst_hdr->opcode_ver) {
                resp_hdr->status = SW_PFVF_STATUS_NOT_SUPPORTED;
                vf_info->pf_vf_response.req_resp_state = VF_PF_RESPONSE_READY;
                break;
            }
            lm_status = lm_pf_vf_fill_teardown_q_response(pdev,vf_info);
            break;
        case PFVF_OP_CLOSE_VF:
            resp_hdr->opcode_ver = PFVF_CLOSE_VF_VER;
            if (vf_info->vf_si_state != PF_SI_VF_INITIALIZED) {
                resp_hdr->status = SW_PFVF_STATUS_SUCCESS;
                DbgMessage(pdev, FATAL, "VF[%d] already closesd!\n",vf_info->relative_vf_id);
                break;
            }
            if (PFVF_CLOSE_VF_VER != requst_hdr->opcode_ver)
            {
                resp_hdr->status                       = SW_PFVF_STATUS_MISMATCH_PF_VF_VERSION;
                vf_info->pf_vf_response.req_resp_state = VF_PF_RESPONSE_READY;
                break;
            }
            lm_status = lm_pf_vf_fill_close_vf_response(pdev,vf_info);
            break;
        case PFVF_OP_RELEASE_VF:
            if (vf_info->vf_si_state != PF_SI_ACQUIRED) {
                resp_hdr->status = SW_PFVF_STATUS_FAILURE;
                DbgBreakIf(!DBG_BREAK_ON(UNDER_TEST));
                break;
            }
            resp_hdr->opcode_ver = PFVF_RELEASE_VF_VER;
            if (PFVF_RELEASE_VF_VER != requst_hdr->opcode_ver) {
                resp_hdr->status = SW_PFVF_STATUS_NOT_SUPPORTED;
                vf_info->pf_vf_response.req_resp_state = VF_PF_RESPONSE_READY;
                break;
            }
            lm_status = lm_pf_vf_fill_release_vf_response(pdev,vf_info);
            break;
        case PFVF_OP_UPDATE_RSS:
            resp_hdr->opcode_ver = PFVF_UPDATE_RSS_VER;
            if (PFVF_UPDATE_RSS_VER != requst_hdr->opcode_ver) {
                resp_hdr->status = SW_PFVF_STATUS_NOT_SUPPORTED;
                vf_info->pf_vf_response.req_resp_state = VF_PF_RESPONSE_READY;
                break;
            }
            lm_status = lm_pf_vf_fill_update_rss_response(pdev,vf_info);
            break;
        case PFVF_OP_UPDATE_RSC:
            resp_hdr->opcode_ver = PFVF_UPDATE_RSC_VER;
            if (PFVF_UPDATE_RSC_VER != requst_hdr->opcode_ver) {
                resp_hdr->status = SW_PFVF_STATUS_NOT_SUPPORTED;
                vf_info->pf_vf_response.req_resp_state = VF_PF_RESPONSE_READY;
                break;
            }
            lm_status = lm_pf_vf_fill_update_rsc_response(pdev,vf_info);
            break;
        default:
            return LM_STATUS_FAILURE;
        }
    }
    if (lm_status != LM_STATUS_PENDING)
    {
        vf_info->pf_vf_response.req_resp_state = VF_PF_RESPONSE_READY;
    }
    return lm_status;
}

lm_status_t lm_pf_notify_standard_request_ready(struct _lm_device_t *pdev, lm_vf_info_t *vf_info, u8_t * set_done)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    struct vf_pf_msg_hdr * requst_hdr = vf_info->pf_vf_response.request_virt_addr;
    struct pf_vf_msg_hdr * resp_hdr = vf_info->pf_vf_response.response_virt_addr;

    DbgBreakIf(!(pdev && IS_CHANNEL_VIRT_MODE_MASTER_PFDEV(pdev) && vf_info && (vf_info->pf_vf_response.req_resp_state != VF_PF_REQUEST_IN_PROCESSING)));
    DbgMessage(pdev, WARNvf, "lm_pf_process_standard_request\n");


    switch (requst_hdr->opcode) {
    case PFVF_OP_ACQUIRE:
        DbgBreak();
        break;
    case PFVF_OP_INIT_VF:
        DbgBreak();
        break;
    case PFVF_OP_SETUP_Q:
        resp_hdr->opcode_ver = PFVF_SETUP_Q_VER;
        if (vf_info->vf_si_state != PF_SI_VF_INITIALIZED) {
            resp_hdr->status = SW_PFVF_STATUS_FAILURE;
            DbgBreak();
            break;
        }
        break;
    case PFVF_OP_SET_Q_FILTERS:
        break;
    case PFVF_OP_ACTIVATE_Q:
        break;
    case PFVF_OP_DEACTIVATE_Q:
        break;
    case PFVF_OP_TEARDOWN_Q:
        break;
    case PFVF_OP_CLOSE_VF:
        if (vf_info->vf_si_state != PF_SI_VF_INITIALIZED) {
            resp_hdr->status = SW_PFVF_STATUS_FAILURE;
            DbgBreak();
            break;
        }
        break;
    case PFVF_OP_RELEASE_VF:
        if (vf_info->vf_si_state != PF_SI_ACQUIRED) {
            resp_hdr->status = SW_PFVF_STATUS_FAILURE;
            //return LM_STATUS_FAILURE;
            DbgBreak();
            break;
        }
        break;
    default:
        lm_status = LM_STATUS_FAILURE;
        DbgBreak();
        break;
    }


    return lm_status;
}

static lm_status_t lm_vf_pf_send_message_to_hw_channel(struct _lm_device_t * pdev, lm_vf_pf_message_t * mess)
{
    lm_address_t * message_phys_addr;

    DbgBreakIf(!(pdev && IS_CHANNEL_VFDEV(pdev)));

    DbgMessage(pdev, WARNvf, "lm_vf_pf_channel_send\n");

    if (mess != NULL) {
        message_phys_addr = &mess->message_phys_addr;
    } else {
        message_phys_addr = &pdev->vars.vf_pf_mess.message_phys_addr;
    }

    VF_REG_WR(pdev, (VF_BAR0_CSDM_GLOBAL_OFFSET +
                OFFSETOF(struct cstorm_vf_zone_data,non_trigger)
              + OFFSETOF(struct non_trigger_vf_zone,vf_pf_channel)
              + OFFSETOF(struct vf_pf_channel_zone_data, msg_addr_lo)),
                message_phys_addr->as_u32.low);

    VF_REG_WR(pdev, (VF_BAR0_CSDM_GLOBAL_OFFSET +
                OFFSETOF(struct cstorm_vf_zone_data,non_trigger)
              + OFFSETOF(struct non_trigger_vf_zone,vf_pf_channel)
              + OFFSETOF(struct vf_pf_channel_zone_data, msg_addr_hi)),
                message_phys_addr->as_u32.high);

    LM_INTMEM_WRITE8(pdev,(OFFSETOF(struct cstorm_vf_zone_data,trigger)
                        + OFFSETOF(struct trigger_vf_zone,vf_pf_channel)
                        + OFFSETOF(struct vf_pf_channel_zone_trigger, addr_valid)),
                     1,VF_BAR0_CSDM_GLOBAL_OFFSET);

/*    VF_REG_WR(pdev, VF_BAR0_CSDM_GLOBAL_OFFSET +
                OFFSETOF(struct cstorm_function_zone_data,non_trigger)
              + OFFSETOF(struct trigger_function_zone,vf_pf_channel)
              + OFFSETOF(struct vf_pf_channel_zone_trigger, addr_valid),
                message_phys_addr.as_u32.low);*/

    return LM_STATUS_SUCCESS;
}

lm_status_t lm_vf_pf_send_request_to_sw_channel(struct _lm_device_t * pdev, lm_vf_pf_message_t * mess)
{
    lm_status_t     lm_status = LM_STATUS_SUCCESS;
    struct vf_pf_msg_hdr *hdr = (struct vf_pf_msg_hdr*)pdev->vars.vf_pf_mess.message_virt_addr;
    void *  buffer = mess->message_virt_addr;
    u32_t   length = hdr->resp_msg_offset;

    lm_status = mm_vf_pf_write_block_to_sw_channel(pdev, VF_TO_PF_STANDARD_BLOCK_ID, buffer, length);
    return lm_status;
}

lm_status_t lm_vf_pf_recv_response_from_sw_channel(struct _lm_device_t * pdev, lm_vf_pf_message_t * mess)
{
    lm_status_t     lm_status = LM_STATUS_SUCCESS;
    struct vf_pf_msg_hdr *hdr = (struct vf_pf_msg_hdr*)pdev->vars.vf_pf_mess.message_virt_addr;
    void *  buffer = (u8_t*)mess->message_virt_addr + hdr->resp_msg_offset;
    u32_t   length = 0;
    u32_t   received_length;
    u32_t   received_offset = 0;

    //mess->message_size - hdr->resp_msg_offset;
    if (hdr->opcode == PFVF_OP_ACQUIRE) {
        received_length = length = sizeof(struct pf_vf_msg_acquire_resp);
    } else {
        received_length = length = sizeof(struct pf_vf_msg_resp);
    }
    while (length) {
        received_length = length;
        lm_status = mm_vf_pf_read_block_from_sw_channel(pdev, VF_TO_PF_STANDARD_BLOCK_ID, (u8_t*)buffer + received_offset, &received_length);
        if (lm_status != LM_STATUS_SUCCESS) {
            break;
        }
        if (!received_offset) {
            if (((struct pf_vf_msg_hdr*)buffer)->status != SW_PFVF_STATUS_SUCCESS) {
                break;
            }
        }
        length -= received_length;
        received_offset += received_length;
    }

    return lm_status;
}

static lm_status_t lm_vf_pf_channel_send(struct _lm_device_t * pdev, lm_vf_pf_message_t * mess)
{
    lm_status_t     lm_status = LM_STATUS_SUCCESS;

    DbgBreakIf(!(pdev && IS_CHANNEL_VFDEV(pdev)));

    DbgMessage(pdev, WARNvf, "lm_vf_pf_channel_send\n");

    if (IS_HW_CHANNEL_VIRT_MODE(pdev)) {
        lm_vf_pf_send_message_to_hw_channel(pdev, mess);
    } else if (IS_SW_CHANNEL_VIRT_MODE(pdev)) {
        lm_status = lm_vf_pf_send_request_to_sw_channel(pdev, mess);
    } else {
        DbgBreakMsg("lm_vf_pf_channel_send: UNKNOWN channel type\n");
        return LM_STATUS_FAILURE;
    }


    if (!mess->do_not_arm_trigger && (lm_status == LM_STATUS_SUCCESS)) {
        mm_vf_pf_arm_trigger(pdev, mess);
    }

    return lm_status;
}

static lm_status_t lm_vf_pf_channel_wait_response(struct _lm_device_t * pdev, lm_vf_pf_message_t * mess)
{
    u32_t             delay_us = 0;
    u32_t             sum_delay_us = 0;
    u32_t             to_cnt   = 10000 + 2360; // We'll wait 10,000 times 100us (1 second) + 2360 times 25000us (59sec) = total 60 sec
    lm_status_t       lm_status = LM_STATUS_SUCCESS;

    /* check args */
    if ERR_IF(!(pdev && IS_CHANNEL_VFDEV(pdev) && mess && pdev->vars.vf_pf_mess.message_virt_addr)) {
        DbgBreak();
        return LM_STATUS_INVALID_PARAMETER;
    }

    /* wait for message done */
    DbgMessage(pdev, WARN, "lm_vf_pf_channel_wait_response\n");
    if (mess == NULL) {
        mess = &pdev->vars.vf_pf_mess;
    }

    if ((*mess->done == FALSE) && IS_SW_CHANNEL_VIRT_MODE(pdev) && !lm_reset_is_inprogress(pdev)) {
        lm_status = lm_vf_pf_recv_response_from_sw_channel(pdev, mess);
    }

    while ((lm_status == LM_STATUS_SUCCESS) && (*mess->done == FALSE) && to_cnt--)
    {
        delay_us = (to_cnt >= 2360) ? 100 : 25000 ;
        sum_delay_us += delay_us;
        mm_wait(pdev, delay_us);

        // in case reset in progress
        // we won't get completion so no need to wait
        if( lm_reset_is_inprogress(pdev) ) {
            break;
        } else if (IS_SW_CHANNEL_VIRT_MODE(pdev)) {
            lm_status = lm_vf_pf_recv_response_from_sw_channel(pdev,mess);
        }
    }
    if (*mess->done) {
        DbgMessage(pdev, WARN, "lm_vf_pf_channel_wait_response: message done(%dus waiting)\n",sum_delay_us);
    } else {
        switch (lm_status) 
        {
        case LM_STATUS_REQUEST_NOT_ACCEPTED:
            break;
        case LM_STATUS_SUCCESS:
            lm_status = LM_STATUS_TIMEOUT;
        default:
            if (!lm_reset_is_inprogress(pdev))
            {
#if defined(_VBD_)
                DbgBreak();
#endif
            }
            break;
        }
	DbgMessage(pdev, FATAL, "lm_vf_pf_channel_wait_response returns %d\n", lm_status);
    }
    return lm_status;
}

static void lm_vf_pf_channel_release_message(struct _lm_device_t * pdev, lm_vf_pf_message_t * mess)
{
    if (mess->cookie) { //TODO don't indicate in case of error processing
        DbgMessage(pdev, WARN, "VF_PF channel: assuming REQ_SET_INFORMATION - indicating back to NDIS!\n");
        mm_set_done(pdev, LM_SW_LEADING_RSS_CID(pdev), mess->cookie);
        mess->cookie = NULL;
    }
    mm_atomic_dec(&mess->state);
}

static lm_vf_pf_message_t * lm_vf_pf_channel_get_message_to_send(struct _lm_device_t * pdev, const u32_t  opcode)
{
    u16_t resp_offset = 0;
    struct vf_pf_msg_hdr    *sw_hdr;
    struct pf_vf_msg_hdr    *sw_resp_hdr;
    struct vfpf_first_tlv   *hw_first_tlv;
    struct channel_list_end_tlv *hw_list_end_tlv;
    struct pfvf_tlv         *hw_resp_hdr;

    DbgBreakIf(!(pdev && IS_CHANNEL_VFDEV(pdev)));

#ifndef __LINUX
    if (mm_atomic_inc(&pdev->vars.vf_pf_mess.state) != 1) {
        DbgMessage(pdev, FATAL, "VF_PF Channel: pdev->vars.vf_pf_mess.state is %d\n",pdev->vars.vf_pf_mess.state);
        mm_atomic_dec(&pdev->vars.vf_pf_mess.state);

        return NULL;
    }
#else
    mm_atomic_inc(&pdev->vars.vf_pf_mess.state);
    DbgMessage(pdev, FATAL, "VF_PF Channel: pdev->vars.vf_pf_mess.state is %d\n",pdev->vars.vf_pf_mess.state);
#endif
    if (pdev->vars.vf_pf_mess.message_virt_addr == NULL) {
        if (IS_SW_CHANNEL_VIRT_MODE(pdev)) 
        {
            pdev->vars.vf_pf_mess.message_size = ((sizeof(union vf_pf_msg) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK)
                                               + ((sizeof(union pf_vf_msg) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK);
        }
        else if (IS_HW_CHANNEL_VIRT_MODE(pdev)) 
        {
            pdev->vars.vf_pf_mess.message_size = ((sizeof(union vfpf_tlvs) + sizeof(struct channel_list_end_tlv) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK)
                                               + ((sizeof(union pfvf_tlvs) + sizeof(struct channel_list_end_tlv) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK)
                                               + ((sizeof(union pf_vf_bulletin) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK);
        }
        else
        {
            DbgBreakMsg("lm_vf_pf_channel_get_message_to_send: UNKNOWN channel type\n");
            return NULL;
        }
        pdev->vars.vf_pf_mess.message_virt_addr = mm_alloc_phys_mem(pdev, pdev->vars.vf_pf_mess.message_size,
                                                                    &pdev->vars.vf_pf_mess.message_phys_addr, 0, LM_RESOURCE_COMMON);
        if CHK_NULL(pdev->vars.vf_pf_mess.message_virt_addr)
        {
            DbgMessage(pdev, FATAL, "VF_PF Channel: pdev->vvars.vf_pf_mess.message_virt_addr is NULL\n");
            DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
            mm_atomic_dec(&pdev->vars.vf_pf_mess.state);
            return NULL;
        }
        if (IS_HW_CHANNEL_VIRT_MODE(pdev))
        {
            u32_t buletin_offset;
			buletin_offset = pdev->vars.vf_pf_mess.message_size = 
                ((sizeof(union vfpf_tlvs) + sizeof(struct channel_list_end_tlv) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK)
                + ((sizeof(union pfvf_tlvs) + sizeof(struct channel_list_end_tlv) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK);
            pdev->vars.vf_pf_mess.bulletin_virt_addr = (u8_t*)pdev->vars.vf_pf_mess.message_virt_addr + buletin_offset;
            pdev->vars.vf_pf_mess.bulletin_phys_addr = pdev->vars.vf_pf_mess.message_phys_addr;
            LM_INC64(&pdev->vars.vf_pf_mess.bulletin_phys_addr, buletin_offset);
        }
    }
    mm_mem_zero(pdev->vars.vf_pf_mess.message_virt_addr, pdev->vars.vf_pf_mess.message_size);
    sw_hdr = (struct vf_pf_msg_hdr*)pdev->vars.vf_pf_mess.message_virt_addr;
    hw_first_tlv = (struct vfpf_first_tlv*)pdev->vars.vf_pf_mess.message_virt_addr;
    switch (opcode) {
    case PFVF_OP_ACQUIRE:
        if (IS_SW_CHANNEL_VIRT_MODE(pdev)) 
        {
            resp_offset = (sizeof(struct vf_pf_msg_acquire) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK;
            sw_hdr->opcode_ver = PFVF_ACQUIRE_VER;
        }
        else
        {
            resp_offset = (sizeof(struct vfpf_acquire_tlv) + sizeof(struct channel_list_end_tlv) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK;
            hw_first_tlv->tl.type = CHANNEL_TLV_ACQUIRE;
            hw_first_tlv->tl.length = sizeof(struct vfpf_acquire_tlv);
        }
        break;
    case PFVF_OP_INIT_VF:
        if (IS_SW_CHANNEL_VIRT_MODE(pdev)) 
        {
            resp_offset = (sizeof(struct vf_pf_msg_init_vf) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK;
            sw_hdr->opcode_ver = PFVF_INIT_VF_VER;
        }
        else
        {
            resp_offset = (sizeof(struct vfpf_init_tlv) + sizeof(struct channel_list_end_tlv) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK;
            hw_first_tlv->tl.type = CHANNEL_TLV_INIT;
            hw_first_tlv->tl.length = sizeof(struct vfpf_init_tlv);
        }
        break;
    case PFVF_OP_SETUP_Q:
        if (IS_SW_CHANNEL_VIRT_MODE(pdev)) 
        {    
            resp_offset = (sizeof(struct vf_pf_msg_setup_q) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK;
            sw_hdr->opcode_ver = PFVF_SETUP_Q_VER;
        }
        else
        {
            resp_offset = (sizeof(struct vfpf_setup_q_tlv) + sizeof(struct channel_list_end_tlv) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK;
            hw_first_tlv->tl.type = CHANNEL_TLV_SETUP_Q;
            hw_first_tlv->tl.length = sizeof(struct vfpf_setup_q_tlv);
        }
        break;
    case PFVF_OP_SET_Q_FILTERS:
        if (IS_SW_CHANNEL_VIRT_MODE(pdev)) 
        {    
            sw_hdr->opcode_ver = PFVF_SET_Q_FILTERS_VER;
            resp_offset = (sizeof(struct vf_pf_msg_set_q_filters) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK;
        }
        else
        {
            resp_offset = (sizeof(struct vfpf_set_q_filters_tlv) + sizeof(struct channel_list_end_tlv) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK;
            hw_first_tlv->tl.type = CHANNEL_TLV_SET_Q_FILTERS;
            hw_first_tlv->tl.length = sizeof(struct vfpf_set_q_filters_tlv);
        }
        break;
#if 0
    case PFVF_OP_ACTIVATE_Q:
        if (IS_SW_CHANNEL_VIRT_MODE(pdev)) 
        {    
            resp_offset = (sizeof(struct vf_pf_msg_q_op) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK;
            sw_hdr->opcode_ver = PFVF_ACTIVATE_Q_VER;
        }
        else
        {
            DbgBreakMsg("lm_vf_pf_channel_get_message_to_send: HW_CHANNEL is not implemented yet\n");
            return NULL;
        }
        break;
    case PFVF_OP_DEACTIVATE_Q:
        if (IS_SW_CHANNEL_VIRT_MODE(pdev)) 
        {    
            resp_offset = (sizeof(struct vf_pf_msg_q_op) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK;
            sw_hdr->opcode_ver = PFVF_DEACTIVATE_Q_VER;
        }
        else
        {
            DbgBreakMsg("lm_vf_pf_channel_get_message_to_send: HW_CHANNEL is not implemented yet\n");
            return NULL;
        }
        break;
#endif        
    case PFVF_OP_TEARDOWN_Q:
        if (IS_SW_CHANNEL_VIRT_MODE(pdev)) 
        {    
            resp_offset = (sizeof(struct vf_pf_msg_q_op) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK;
            sw_hdr->opcode_ver = PFVF_TEARDOWN_Q_VER;
        }
        else
        {
            resp_offset = (sizeof(struct vfpf_q_op_tlv) + sizeof(struct channel_list_end_tlv) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK;
            hw_first_tlv->tl.type = CHANNEL_TLV_TEARDOWN_Q;
            hw_first_tlv->tl.length = sizeof(struct vfpf_q_op_tlv);
        }
        break;
    case PFVF_OP_CLOSE_VF:
        if (IS_SW_CHANNEL_VIRT_MODE(pdev)) 
        {    
            resp_offset = (sizeof(struct vf_pf_msg_close_vf) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK;
            sw_hdr->opcode_ver = PFVF_CLOSE_VF_VER;
        }
        else
        {
            resp_offset = (sizeof(struct vfpf_close_tlv) + sizeof(struct channel_list_end_tlv) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK;
            hw_first_tlv->tl.type = CHANNEL_TLV_CLOSE;
            hw_first_tlv->tl.length = sizeof(struct vfpf_close_tlv);
        }
        break;
    case PFVF_OP_RELEASE_VF:
        if (IS_SW_CHANNEL_VIRT_MODE(pdev)) 
        {    
            resp_offset = (sizeof(struct vf_pf_msg_release_vf) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK;
            sw_hdr->opcode_ver = PFVF_RELEASE_VF_VER;
        }
        else
        {
            resp_offset = (sizeof(struct vfpf_release_tlv) + sizeof(struct channel_list_end_tlv) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK;
            hw_first_tlv->tl.type = CHANNEL_TLV_RELEASE;
            hw_first_tlv->tl.length = sizeof(struct vfpf_release_tlv);
        }
        break;
    case PFVF_OP_UPDATE_RSS:
        if (IS_SW_CHANNEL_VIRT_MODE(pdev)) 
        {    
            resp_offset = (sizeof(struct vf_pf_msg_rss) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK;
            sw_hdr->opcode_ver = PFVF_UPDATE_RSS_VER;
        }
        else
        {
            resp_offset = (sizeof(struct vfpf_rss_tlv) + sizeof(struct channel_list_end_tlv) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK;
            hw_first_tlv->tl.type = CHANNEL_TLV_UPDATE_RSS;
            hw_first_tlv->tl.length = sizeof(struct vfpf_rss_tlv);
        }
        break;
    case PFVF_OP_UPDATE_RSC:
        if (IS_SW_CHANNEL_VIRT_MODE(pdev)) 
        {    
            resp_offset = (sizeof(struct vf_pf_msg_rsc) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK;
            sw_hdr->opcode_ver = PFVF_UPDATE_RSC_VER;
        }
        else
        {
            resp_offset = (sizeof(struct vfpf_tpa_tlv) + sizeof(struct channel_list_end_tlv) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK;
            hw_first_tlv->tl.type = CHANNEL_TLV_UPDATE_TPA;
            hw_first_tlv->tl.length = sizeof(struct vfpf_tpa_tlv);
        }
        break;
    default:
        mm_atomic_dec(&pdev->vars.vf_pf_mess.state);
        DbgMessage(pdev, FATAL, "VF_PF channel: Opcode %d is not supported\n",opcode);
        DbgBreak();
        return NULL;
    }
    if (IS_SW_CHANNEL_VIRT_MODE(pdev)) 
    {    
        sw_hdr->if_ver  = PFVF_IF_VERSION;
        sw_hdr->opcode = (u16_t)opcode;
        sw_hdr->resp_msg_offset = resp_offset;
        sw_resp_hdr = (struct pf_vf_msg_hdr *)((u8_t*)sw_hdr + resp_offset);
        sw_resp_hdr->status = SW_PFVF_STATUS_WAITING;
        pdev->vars.vf_pf_mess.done = (u16_t*)((u8_t *)pdev->vars.vf_pf_mess.message_virt_addr + resp_offset);
    }
    else
    {
        hw_list_end_tlv = (struct channel_list_end_tlv *)((u8_t*)hw_first_tlv + hw_first_tlv->tl.length);
        hw_list_end_tlv->tl.type = CHANNEL_TLV_LIST_END;        
        hw_first_tlv->resp_msg_offset = resp_offset;
        hw_resp_hdr = (struct pfvf_tlv *)((u8_t*)hw_first_tlv + hw_first_tlv->resp_msg_offset);
        pdev->vars.vf_pf_mess.done = (u16_t*)(&hw_resp_hdr->status);
    }
    return &pdev->vars.vf_pf_mess;
}

u16_t lm_vf_pf_get_sb_running_index(lm_device_t *pdev, u8_t sb_id, u8_t sm_idx)
{
    u16_t running_index = 0;
    DbgBreakIf(!(pdev && IS_CHANNEL_VFDEV(pdev) && pdev->pf_vf_acquiring_resp));
    if (IS_SW_CHANNEL_VIRT_MODE(pdev)) 
    {
        struct pf_vf_msg_acquire_resp * p_sw_resp = (struct pf_vf_msg_acquire_resp *)pdev->pf_vf_acquiring_resp;
        running_index = pdev->vars.status_blocks_arr[sb_id].host_hc_status_block.vf_sb[p_sw_resp->pfdev_info.indices_per_sb + sm_idx];
    }
    else if (IS_HW_CHANNEL_VIRT_MODE(pdev)) 
    {
        struct pfvf_acquire_resp_tlv * p_hw_resp = (struct pfvf_acquire_resp_tlv *)pdev->pf_vf_acquiring_resp;;
        running_index = pdev->vars.status_blocks_arr[sb_id].host_hc_status_block.vf_sb[p_hw_resp->pfdev_info.indices_per_sb + sm_idx];
    }
    else
    {
        DbgBreak();
    }
    
    return mm_le16_to_cpu(running_index);
}


u16_t lm_vf_pf_get_sb_index(lm_device_t *pdev, u8_t sb_id, u8_t idx)
{
    DbgBreakIf(!(pdev && IS_CHANNEL_VFDEV(pdev) && pdev->pf_vf_acquiring_resp));
    if (IS_SW_CHANNEL_VIRT_MODE(pdev)) 
    {
        struct pf_vf_msg_acquire_resp * p_sw_resp = (struct pf_vf_msg_acquire_resp *)pdev->pf_vf_acquiring_resp;
        DbgBreakIf(!(p_sw_resp && (sb_id < p_sw_resp->pfdev_info.indices_per_sb)));
    }
    else if (IS_HW_CHANNEL_VIRT_MODE(pdev)) 
    {
        struct pfvf_acquire_resp_tlv * p_hw_resp = (struct pfvf_acquire_resp_tlv *)pdev->pf_vf_acquiring_resp;;
        DbgBreakIf(!(p_hw_resp && (sb_id < p_hw_resp->pfdev_info.indices_per_sb)));
    }
    else
    {
        DbgBreak();
    }
    return mm_le16_to_cpu(pdev->vars.status_blocks_arr[sb_id].host_hc_status_block.vf_sb[sb_id]);
}

u16_t lm_vf_get_doorbell_size(struct _lm_device_t *pdev)
{
    DbgBreakIf(!(pdev && IS_CHANNEL_VFDEV(pdev) && pdev->pf_vf_acquiring_resp));
    if (IS_SW_CHANNEL_VIRT_MODE(pdev)) 
    {
        struct pf_vf_msg_acquire_resp * p_sw_resp = (struct pf_vf_msg_acquire_resp *)pdev->pf_vf_acquiring_resp;
        DbgBreakIf(!p_sw_resp->pfdev_info.db_size);
        return p_sw_resp->pfdev_info.db_size;
    }
    else if (IS_HW_CHANNEL_VIRT_MODE(pdev)) 
    {
        struct pfvf_acquire_resp_tlv * p_hw_resp = (struct pfvf_acquire_resp_tlv *)pdev->pf_vf_acquiring_resp;;
        DbgBreakIf(!p_hw_resp->pfdev_info.db_size);
        return p_hw_resp->pfdev_info.db_size;
    }
    else
    {
        DbgBreak();
    }
    return 0;
}

lm_status_t lm_vf_pf_wait_no_messages_pending(struct _lm_device_t * pdev)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    lm_vf_pf_message_t * pf_mess = NULL;
    pf_mess = &pdev->vars.vf_pf_mess;
    lm_status = lm_vf_pf_channel_wait_response(pdev, pf_mess);

    DbgMessage(pdev, WARNvf, "lm_vf_pf_wait_no_messages_pending\n");

    if (lm_status == LM_STATUS_SUCCESS) {
        if (IS_SW_CHANNEL_VIRT_MODE(pdev)) 
        {    
            struct vf_pf_msg_hdr * mess_hdr = NULL;
            struct pf_vf_msg_hdr * resp_hdr = NULL;
            mess_hdr = (struct vf_pf_msg_hdr *)pf_mess->message_virt_addr;
            resp_hdr = (struct pf_vf_msg_hdr *)((u8_t*)mess_hdr + mess_hdr->resp_msg_offset);
            switch (resp_hdr->status) {
            case SW_PFVF_STATUS_SUCCESS:
                DbgMessage(pdev, WARN, "VF_PF Channel: Message %d(%d) is completed successfully\n",mess_hdr->opcode, resp_hdr->opcode);
                lm_status = LM_STATUS_SUCCESS;
                break;
            case SW_PFVF_STATUS_FAILURE:
            case SW_PFVF_STATUS_MISMATCH_PF_VF_VERSION:
            case SW_PFVF_STATUS_MISMATCH_FW_HSI:
            case SW_PFVF_STATUS_NO_RESOURCE:
                DbgMessage(pdev, FATAL, "VF_PF Channel: Status %d is not supported yet\n", resp_hdr->status);
                lm_status = LM_STATUS_FAILURE;
                pf_mess->bad_response.sw_channel_hdr = *resp_hdr;
                break;
            default:
                DbgMessage(pdev, FATAL, "VF_PF Channel: Unknown status %d\n", resp_hdr->status);
                pf_mess->bad_response.sw_channel_hdr = *resp_hdr;
                lm_status = LM_STATUS_FAILURE;
                break;
            }
        }
        else if (IS_HW_CHANNEL_VIRT_MODE(pdev)) 
        {
            struct vfpf_first_tlv * mess_hdr = NULL;
            struct pfvf_tlv * resp_hdr = NULL;
            mess_hdr = (struct vfpf_first_tlv *)pf_mess->message_virt_addr;
            resp_hdr = (struct pfvf_tlv *)((u8_t*)mess_hdr + mess_hdr->resp_msg_offset);
            switch (resp_hdr->status)
            {
            case PFVF_STATUS_SUCCESS:
                lm_status = LM_STATUS_SUCCESS;
                break;
            case PFVF_STATUS_FAILURE:
            case PFVF_STATUS_NOT_SUPPORTED:
            case PFVF_STATUS_NO_RESOURCE:
                DbgMessage(pdev, FATAL, "VF_PF Channel: Status %d is not supported yet\n", resp_hdr->status);
                pf_mess->bad_response.hw_channel_hdr = *resp_hdr;
                lm_status = LM_STATUS_FAILURE;
                break;
            default:
                DbgMessage(pdev, FATAL, "VF_PF Channel: Unknown status %d\n", resp_hdr->status);
                pf_mess->bad_response.hw_channel_hdr = *resp_hdr;
                lm_status = LM_STATUS_FAILURE;
                break;
            }
        }
        else
        {
            DbgBreak();
        }
    }
    lm_vf_pf_channel_release_message(pdev,pf_mess);
    return lm_status;
}

lm_status_t lm_vf_pf_acquire_msg(struct _lm_device_t * pdev)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    lm_vf_pf_message_t * pf_mess = NULL;
    struct  vf_pf_msg_acquire * sw_mess = NULL;
    struct  vfpf_acquire_tlv  * hw_mess = NULL;
    struct  pf_vf_msg_acquire_resp * sw_resp = NULL;
    struct  pfvf_acquire_resp_tlv  * hw_resp = NULL;
    u8_t                           max_dq    = 0;
    
    DbgBreakIf(!(pdev && IS_CHANNEL_VFDEV(pdev)));

    pf_mess = lm_vf_pf_channel_get_message_to_send(pdev, PFVF_OP_ACQUIRE);

    if (!pf_mess)
     {
        DbgMessage(pdev, FATAL, "VF_PF Channel: lm_vf_pf_channel_get_message_to_send returns NULL\n");
        lm_status = LM_STATUS_RESOURCE;
        DbgBreak();
        return lm_status;
    }
    
    if (IS_SW_CHANNEL_VIRT_MODE(pdev)) 
    {
        sw_mess = (struct vf_pf_msg_acquire*)pf_mess->message_virt_addr;

    //    mess->vfdev_info.vf_pf_msg_size = sizeof(union vf_pf_msg);
           /* the following fields are for debug purposes */
        sw_mess->vfdev_info.vf_id = ABS_VFID(pdev);       /* ME register value */
        sw_mess->vfdev_info.vf_os = 0;             /* e.g. Linux, W2K8 */
        sw_mess->vfdev_info.vf_aux             = SW_VFPF_VFDEF_INFO_AUX_DIRECT_DQ;
        sw_mess->vfdev_info.vf_fw_hsi_version  = pdev->ver_num_fw;  /* Must not be zero otherwise, VF will yellow bang */
        sw_mess->vfdev_info.fp_hsi_ver         = ETH_FP_HSI_VER_1; /* We don't want to break support for old/new VF/PF so we retrun v1 */
        DbgBreakIf( 0 == sw_mess->vfdev_info.vf_fw_hsi_version );

        sw_mess->resc_request.num_rxqs = sw_mess->resc_request.num_txqs = sw_mess->resc_request.num_sbs = LM_SB_CNT(pdev);
        sw_mess->resc_request.num_mac_filters = 1;
        sw_mess->resc_request.num_vlan_filters = 0;
        sw_mess->resc_request.num_mc_filters = 0;
        
    }
    else if (IS_HW_CHANNEL_VIRT_MODE(pdev)) 
    {
        hw_mess = (struct vfpf_acquire_tlv*)pf_mess->message_virt_addr;
        hw_mess->vfdev_info.vf_id = ABS_VFID(pdev);       /* ME register value */
        hw_mess->vfdev_info.vf_os = 0;             /* e.g. Linux, W2K8 */
        hw_mess->vfdev_info.fp_hsi_ver = ETH_FP_HSI_VER_1; /* We don't want to break support for old/new VF/PF so we retrun v1 */
        hw_mess->resc_request.num_rxqs = hw_mess->resc_request.num_txqs = hw_mess->resc_request.num_sbs = LM_SB_CNT(pdev);
        hw_mess->resc_request.num_mac_filters = 1;
        hw_mess->resc_request.num_vlan_filters = 0;
        hw_mess->resc_request.num_mc_filters = PFVF_MAX_MULTICAST_PER_VF;
        hw_mess->bulletin_addr = pf_mess->bulletin_phys_addr.as_u64;
    }
    else
    {
        DbgBreak();
        lm_vf_pf_channel_release_message(pdev,pf_mess);
        return LM_STATUS_FAILURE;
    }

    pf_mess->do_not_arm_trigger = TRUE;
    lm_status = lm_vf_pf_channel_send(pdev,pf_mess);

    if (lm_status != LM_STATUS_SUCCESS)
    {
        lm_vf_pf_channel_release_message(pdev,pf_mess);
        return lm_status;
    }
    lm_status = lm_vf_pf_channel_wait_response(pdev, pf_mess);

    // FIXME TODO
    if (lm_status == LM_STATUS_SUCCESS)
    {
        if (IS_SW_CHANNEL_VIRT_MODE(pdev)) 
        {
            sw_resp = (struct pf_vf_msg_acquire_resp *)((u8_t*)sw_mess + sw_mess->hdr.resp_msg_offset);
            if (sw_resp->hdr.opcode != PFVF_OP_ACQUIRE)
            {
                lm_status = LM_STATUS_FAILURE;
            }
            else
            {
                switch (sw_resp->hdr.status)
                {
                case SW_PFVF_STATUS_SUCCESS:
                    lm_status = LM_STATUS_SUCCESS;
                    break;
                case SW_PFVF_STATUS_FAILURE:
                case SW_PFVF_STATUS_MISMATCH_PF_VF_VERSION:
                case SW_PFVF_STATUS_MISMATCH_FW_HSI:
                case SW_PFVF_STATUS_NO_RESOURCE:
                    DbgMessage(pdev, FATAL, "VF_PF Channel: Status %d is not supported yet\n", sw_resp->hdr.status);
                    lm_status = LM_STATUS_FAILURE;
                    break;
                default:
                    DbgMessage(pdev, FATAL, "VF_PF Channel: Unknown status %d\n", sw_resp->hdr.status);
                    lm_status = LM_STATUS_FAILURE;
                    break;
                }
                // We update here the status of pf_acquire
                // in order to let the UM layer of the VF to report
                // in the event log the relevant event log message
                pdev->params.pf_acquire_status = sw_resp->hdr.status;
            }
        }
        else if (IS_HW_CHANNEL_VIRT_MODE(pdev)) 
        {
            hw_resp = (struct pfvf_acquire_resp_tlv *)((u8_t*)hw_mess + hw_mess->first_tlv.resp_msg_offset);
            if (hw_resp->hdr.tl.type != CHANNEL_TLV_ACQUIRE) 
            {
                lm_status = LM_STATUS_FAILURE;
            }
            else
            {
                switch (hw_resp->hdr.status)
                {
                case PFVF_STATUS_SUCCESS:
                    lm_status = LM_STATUS_SUCCESS;
                    break;
                case PFVF_STATUS_FAILURE:
                case PFVF_STATUS_NOT_SUPPORTED:
                case PFVF_STATUS_NO_RESOURCE:
                    DbgMessage(pdev, FATAL, "VF_PF Channel: Status %d is not supported yet\n", hw_resp->hdr.status);
                    lm_status = LM_STATUS_FAILURE;
                    break;
                default:
                    DbgMessage(pdev, FATAL, "VF_PF Channel: Unknown status %d\n", hw_resp->hdr.status);
                    lm_status = LM_STATUS_FAILURE;
                    break;
                }
                // We update here the status of pf_acquire
                // in order to let the UM layer of the VF to report
                // in the event log the relevant event log message
                pdev->params.pf_acquire_status = hw_resp->hdr.status;
            }
        }
        else
        {
            DbgBreak();
            lm_status = LM_STATUS_FAILURE;
        }
    }

    if (lm_status == LM_STATUS_SUCCESS)
    {
        if (IS_SW_CHANNEL_VIRT_MODE(pdev)) 
        {
            struct pf_vf_msg_acquire_resp * presp;

            if (pdev->pf_vf_acquiring_resp == NULL)
            {
                pdev->pf_vf_acquiring_resp = mm_alloc_mem(pdev, sizeof(struct pf_vf_msg_acquire_resp),LM_RESOURCE_COMMON);

                if CHK_NULL(pdev->pf_vf_acquiring_resp)
                {
                    lm_vf_pf_channel_release_message(pdev, pf_mess);
                    DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
                    return LM_STATUS_RESOURCE;
                }
                else
                {
                    DbgMessage(pdev, FATAL, "VF_PF Channel: pdev->pf_vf_acquiring_resp is allocated (%db)\n",sizeof(struct pf_vf_msg_acquire_resp));
                }
            }

            // FIXME TODO
            presp = (struct pf_vf_msg_acquire_resp *)pdev->pf_vf_acquiring_resp;

            // override for now to make sure we get correct answer...
            presp->pfdev_info.chip_num = CHIP_NUM_5712E;

            mm_memcpy(pdev->pf_vf_acquiring_resp, sw_resp, sizeof(struct pf_vf_msg_acquire_resp));
            if (!pdev->params.debug_sriov)
            {
                pdev->params.debug_sriov = presp->pfdev_info.pf_cap & PFVF_DEBUG;
	    }
            DbgMessage(pdev, FATALvf, "presp->pfdev_info.db_size = %d\n", presp->pfdev_info.db_size);
            DbgMessage(pdev, FATALvf, "presp->pfdev_info.indices_per_sb = %d\n", presp->pfdev_info.indices_per_sb);
            DbgMessage(pdev, FATALvf, "presp->pfdev_info.pf_cap = %d\n", presp->pfdev_info.pf_cap);
            DbgMessage(pdev, FATALvf, "presp->pfdev_info.chip_num = %d\n", presp->pfdev_info.chip_num);
            DbgMessage(pdev, FATALvf, "presp->resc.hw_qid[0] = %d\n", presp->resc.hw_qid[0]);
            DbgMessage(pdev, FATALvf, "presp->resc.hw_sbs[0].hw_sb_id = %d\n", presp->resc.hw_sbs[0].hw_sb_id);
            DbgMessage(pdev, FATALvf, "presp->resc.hw_sbs[0].sb_qid = %d\n", presp->resc.hw_sbs[0].sb_qid);
            DbgMessage(pdev, FATALvf, "presp->resc.num_sbs = %d\n", presp->resc.num_sbs);
            DbgMessage(pdev, FATALvf, "presp->resc.igu_cnt = %d\n", presp->resc.igu_cnt);
            DbgMessage(pdev, FATALvf, "presp->resc.igu_test_cnt = %d\n", presp->resc.igu_test_cnt);
            DbgMessage(pdev, FATALvf, "presp->resc.num_rxqs = %d\n", presp->resc.num_rxqs);
            DbgMessage(pdev, FATALvf, "presp->resc.num_txqs = %d\n", presp->resc.num_txqs);
            DbgMessage(pdev, FATALvf, "presp->resc.num_mac_filters = %d\n", presp->resc.num_mac_filters);
            DbgMessage(pdev, FATALvf, "presp->resc.num_mc_filters = %d\n", presp->resc.num_mc_filters);
            DbgMessage(pdev, FATALvf, "presp->resc.num_vlan_filters = %d\n", presp->resc.num_vlan_filters);

            if (presp->pfdev_info.db_size)
            {
                max_dq = VF_BAR0_DB_SIZE / presp->pfdev_info.db_size;
                if (!max_dq)
                {
                    max_dq = 1;
                }
            }
            else
            {
                lm_vf_pf_channel_release_message(pdev, pf_mess);
                DbgBreakIf(!DBG_BREAK_ON(UNDER_TEST));
                return LM_STATUS_INVALID_PARAMETER;
            }
            pdev->params.fw_base_qzone_cnt = pdev->params.sb_cnt = min(presp->resc.num_sbs, max_dq);
            pdev->params.max_rss_chains = pdev->params.rss_chain_cnt = min(presp->resc.num_rxqs, max_dq);
            pdev->params.tss_chain_cnt = min(presp->resc.num_txqs, max_dq);

            pdev->hw_info.chip_id = presp->pfdev_info.chip_num;
            pdev->hw_info.intr_blk_info.blk_type = INTR_BLK_IGU;
            pdev->hw_info.intr_blk_info.blk_mode = INTR_BLK_MODE_NORM;
            pdev->hw_info.intr_blk_info.access_type = INTR_BLK_ACCESS_IGUMEM;

            /* IGU specific data */
            pdev->hw_info.intr_blk_info.igu_info.igu_base_sb = presp->resc.hw_sbs[0].hw_sb_id;
            pdev->hw_info.intr_blk_info.igu_info.igu_sb_cnt = presp->resc.igu_cnt;
            pdev->hw_info.intr_blk_info.igu_info.igu_test_sb_cnt = presp->resc.igu_test_cnt;
            /* TODO: don't assume consecutiveness... */
            {
                u8_t idx;
                for (idx = 0; idx < pdev->params.fw_base_qzone_cnt; idx++)
                {
                    pdev->params.fw_qzone_id[idx] = presp->resc.hw_qid[idx];
                    IGU_VF_NDSB(pdev,idx) = presp->resc.hw_sbs[idx].hw_sb_id;
                }
            }


            /* TODO: get this from presp... here for purpose of rx_mask... */
            //pdev->hw_info.chip_id |= CHIP_REV_EMUL;
            if (presp->resc.num_mc_filters == 0xFF)
            {
                presp->resc.num_mc_filters = 0;
            }
            if (presp->resc.current_mac_addr[0]
                    || presp->resc.current_mac_addr[1]
                    || presp->resc.current_mac_addr[2]
                    || presp->resc.current_mac_addr[3]
                    || presp->resc.current_mac_addr[4]
                    || presp->resc.current_mac_addr[5])
            {
                DbgMessage(pdev, WARN, "VF received MAC from PF\n");
                pdev->params.mac_addr[0] = pdev->hw_info.mac_addr[0] = presp->resc.current_mac_addr[0];
                pdev->params.mac_addr[1] = pdev->hw_info.mac_addr[1] = presp->resc.current_mac_addr[1];
                pdev->params.mac_addr[2] = pdev->hw_info.mac_addr[2] = presp->resc.current_mac_addr[2];
                pdev->params.mac_addr[3] = pdev->hw_info.mac_addr[3] = presp->resc.current_mac_addr[3];
                pdev->params.mac_addr[4] = pdev->hw_info.mac_addr[4] = presp->resc.current_mac_addr[4];
                pdev->params.mac_addr[5] = pdev->hw_info.mac_addr[5] = presp->resc.current_mac_addr[5];
            }
            else
            {    
                DbgMessage(pdev, WARN, "VF uses own MAC\n");
            }
        }
        else if (IS_HW_CHANNEL_VIRT_MODE(pdev)) 
        {
            struct pfvf_acquire_resp_tlv * presp;
    
            if (pdev->pf_vf_acquiring_resp == NULL)
            {
                pdev->pf_vf_acquiring_resp = mm_alloc_mem(pdev, sizeof(struct pfvf_acquire_resp_tlv),LM_RESOURCE_COMMON);
    
                if CHK_NULL(pdev->pf_vf_acquiring_resp)
                {
                    lm_vf_pf_channel_release_message(pdev, pf_mess);
                    DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
                    return LM_STATUS_RESOURCE;
                }
                else
                {
                    DbgMessage(pdev, FATAL, "VF_PF Channel: pdev->pf_vf_acquiring_resp is allocated (%db)\n",sizeof(struct pfvf_acquire_resp_tlv));
                }
            }
    
            // FIXME TODO
            presp = (struct pfvf_acquire_resp_tlv *)pdev->pf_vf_acquiring_resp;

            presp->pfdev_info.chip_num = CHIP_NUM_5712E;

            mm_memcpy(pdev->pf_vf_acquiring_resp, hw_resp, sizeof(struct pfvf_acquire_resp_tlv));

            DbgMessage(pdev, FATALvf, "presp->pfdev_info.db_size = %d\n", presp->pfdev_info.db_size);
            DbgMessage(pdev, FATALvf, "presp->pfdev_info.indices_per_sb = %d\n", presp->pfdev_info.indices_per_sb);
            DbgMessage(pdev, FATALvf, "presp->pfdev_info.pf_cap = %d\n", presp->pfdev_info.pf_cap);
            DbgMessage(pdev, FATALvf, "presp->pfdev_info.chip_num = %d\n", presp->pfdev_info.chip_num);
            DbgMessage(pdev, FATALvf, "presp->resc.hw_qid[0] = %d\n", presp->resc.hw_qid[0]);
            DbgMessage(pdev, FATALvf, "presp->resc.hw_sbs[0].hw_sb_id = %d\n", presp->resc.hw_sbs[0].hw_sb_id);
            DbgMessage(pdev, FATALvf, "presp->resc.hw_sbs[0].sb_qid = %d\n", presp->resc.hw_sbs[0].sb_qid);
            DbgMessage(pdev, FATALvf, "presp->resc.num_sbs = %d\n", presp->resc.num_sbs);
            DbgMessage(pdev, FATALvf, "presp->resc.num_rxqs = %d\n", presp->resc.num_rxqs);
            DbgMessage(pdev, FATALvf, "presp->resc.num_txqs = %d\n", presp->resc.num_txqs);
            DbgMessage(pdev, FATALvf, "presp->resc.num_mac_filters = %d\n", presp->resc.num_mac_filters);
            DbgMessage(pdev, FATALvf, "presp->resc.num_mc_filters = %d\n", presp->resc.num_mc_filters);
            DbgMessage(pdev, FATALvf, "presp->resc.num_vlan_filters = %d\n", presp->resc.num_vlan_filters);


            if (presp->pfdev_info.db_size)
            {
                max_dq = VF_BAR0_DB_SIZE / presp->pfdev_info.db_size;
                if (!max_dq)
                {
                    max_dq = 1;
                }
            }
            else
            {
                lm_vf_pf_channel_release_message(pdev, pf_mess);
                DbgBreakIf(!DBG_BREAK_ON(UNDER_TEST));
                return LM_STATUS_INVALID_PARAMETER;
            }
            pdev->params.fw_base_qzone_cnt = pdev->params.sb_cnt = min(presp->resc.num_sbs, max_dq);
            pdev->params.max_rss_chains = pdev->params.rss_chain_cnt = min(presp->resc.num_rxqs, max_dq);
            pdev->params.tss_chain_cnt = min(presp->resc.num_txqs, max_dq);

            pdev->hw_info.chip_id = presp->pfdev_info.chip_num;
            pdev->hw_info.intr_blk_info.blk_type = INTR_BLK_IGU;
            pdev->hw_info.intr_blk_info.blk_mode = INTR_BLK_MODE_NORM;
            pdev->hw_info.intr_blk_info.access_type = INTR_BLK_ACCESS_IGUMEM;

            /* IGU specific data */
            pdev->hw_info.intr_blk_info.igu_info.igu_base_sb = presp->resc.hw_sbs[0].hw_sb_id;
            pdev->hw_info.intr_blk_info.igu_info.igu_sb_cnt = presp->resc.num_sbs;
            /* TODO: don't assume consecutiveness... */
            {
                u8_t idx;
                for (idx = 0; idx < pdev->params.fw_base_qzone_cnt; idx++)
                {
                    pdev->params.fw_qzone_id[idx] = presp->resc.hw_qid[idx];
                    IGU_VF_NDSB(pdev,idx) = presp->resc.hw_sbs[idx].hw_sb_id;
                }
            }


            /* TODO: get this from presp... here for purpose of rx_mask... */
            //pdev->hw_info.chip_id |= CHIP_REV_EMUL;
            if (presp->resc.num_mc_filters == 0xFF)
            {
                presp->resc.num_mc_filters = 0;
            }
			else if (presp->resc.num_mc_filters == 0)
			{
				presp->resc.num_mc_filters = hw_mess->resc_request.num_mc_filters;
			}
			pdev->params.mc_table_size[LM_CLI_IDX_NDIS] = presp->resc.num_mc_filters;
			pdev->vars.pf_link_speed = presp->resc.pf_link_speed;

            if (presp->resc.current_mac_addr[0]
                    || presp->resc.current_mac_addr[1]
                    || presp->resc.current_mac_addr[2]
                    || presp->resc.current_mac_addr[3]
                    || presp->resc.current_mac_addr[4]
                    || presp->resc.current_mac_addr[5])
            {

                DbgMessage(pdev, WARN, "VF received MAC from PF\n");
                pdev->params.mac_addr[0] = pdev->hw_info.mac_addr[0] = presp->resc.current_mac_addr[0];
                pdev->params.mac_addr[1] = pdev->hw_info.mac_addr[1] = presp->resc.current_mac_addr[1];
                pdev->params.mac_addr[2] = pdev->hw_info.mac_addr[2] = presp->resc.current_mac_addr[2];
                pdev->params.mac_addr[3] = pdev->hw_info.mac_addr[3] = presp->resc.current_mac_addr[3];
                pdev->params.mac_addr[4] = pdev->hw_info.mac_addr[4] = presp->resc.current_mac_addr[4];
                pdev->params.mac_addr[5] = pdev->hw_info.mac_addr[5] = presp->resc.current_mac_addr[5];
                pdev->vars.is_pf_provides_mac = TRUE;
                pdev->vars.is_pf_restricts_lamac = lm_vf_check_mac_restriction(pdev, presp);
            }
            else
            {
                DbgMessage(pdev, WARN, "VF uses own MAC\n");
                pdev->vars.is_pf_provides_mac = FALSE;
                pdev->vars.is_pf_restricts_lamac = FALSE;
            }
        }
        else
        {
            DbgBreak();
            lm_status = LM_STATUS_FAILURE;
        }
    }

    lm_vf_pf_channel_release_message(pdev, pf_mess);
    return lm_status;
}

lm_status_t lm_vf_pf_init_vf(struct _lm_device_t * pdev)
{
    lm_status_t                 lm_status = LM_STATUS_SUCCESS;
    lm_vf_pf_message_t *        pf_mess = NULL;
   lm_address_t                q_stats;
    u8_t                        sb_id;

    DbgMessage(pdev, WARNvf, "lm_vf_pf_init_vf\n");

    DbgBreakIf(!(pdev && IS_CHANNEL_VFDEV(pdev) && (LM_SB_CNT(pdev) <= PFVF_MAX_SBS_PER_VF)));
    pf_mess = lm_vf_pf_channel_get_message_to_send(pdev, PFVF_OP_INIT_VF);
    if (!pf_mess) {
        lm_status = LM_STATUS_RESOURCE;
        DbgBreak();
        return lm_status;
    }
    if (IS_SW_CHANNEL_VIRT_MODE(pdev)) 
    {
        struct vf_pf_msg_init_vf *  mess = NULL;
    mess = (struct vf_pf_msg_init_vf*)pf_mess->message_virt_addr;

    q_stats = pdev->vars.stats.stats_collect.stats_fw.fw_stats_data_mapping;
    LM_INC64(&q_stats, OFFSETOF(lm_stats_fw_stats_data_t, queue_stats));
    mess->stats_addr = q_stats.as_u64;

    LM_FOREACH_SB_ID(pdev,sb_id) {
        mess->sb_addr[sb_id] = pdev->vars.status_blocks_arr[sb_id].hc_status_block_data.vf_sb_phy_address.as_u64;
    }
    }
    else if (IS_HW_CHANNEL_VIRT_MODE(pdev)) 
    {
        struct vfpf_init_tlv *  mess = NULL;
        mess = (struct vfpf_init_tlv*)pf_mess->message_virt_addr;

        q_stats = pdev->vars.stats.stats_collect.stats_fw.fw_stats_data_mapping;
        LM_INC64(&q_stats, OFFSETOF(lm_stats_fw_stats_data_t, queue_stats));
        mess->stats_addr = q_stats.as_u64;
        mess->flags = VFPF_INIT_FLG_STATS_COALESCE;

        LM_FOREACH_SB_ID(pdev,sb_id) {
            mess->sb_addr[sb_id] = pdev->vars.status_blocks_arr[sb_id].hc_status_block_data.vf_sb_phy_address.as_u64;
        }
    }
    else
    {
        DbgBreak();
        lm_vf_pf_channel_release_message(pdev,pf_mess);
        return LM_STATUS_FAILURE;
    }
    
    lm_status = lm_vf_pf_channel_send(pdev,pf_mess);
    if (lm_status != LM_STATUS_SUCCESS) {
        lm_vf_pf_channel_release_message(pdev,pf_mess);
    }
    DbgMessage(pdev, WARNvf, "lm_vf_pf_init_vf return lm_status = %d\n", lm_status);

    return lm_status;
}

lm_status_t lm_vf_pf_setup_q(struct _lm_device_t * pdev, u8 vf_qid, u8_t validation_flag)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    lm_vf_pf_message_t * pf_mess = NULL;

    DbgMessage(pdev, WARNvf, "lm_vf_pf_setup_q\n");

    DbgBreakIf(!(pdev && IS_CHANNEL_VFDEV(pdev)
                 && (validation_flag & (RX_Q_VALIDATE | TX_Q_VALIDATE))
                 && (vf_qid < LM_SB_CNT(pdev))
                 && pdev->pf_vf_acquiring_resp));

    pf_mess = lm_vf_pf_channel_get_message_to_send(pdev, PFVF_OP_SETUP_Q);
    if (!pf_mess) {
        lm_status = LM_STATUS_RESOURCE;
        DbgBreak();
        return lm_status;
    }
    if (IS_SW_CHANNEL_VIRT_MODE(pdev)) 
    {
        struct vf_pf_msg_setup_q * mess = NULL;
        struct pf_vf_msg_acquire_resp * presp = NULL;

    mess = (struct vf_pf_msg_setup_q*)pf_mess->message_virt_addr;
    presp = (struct pf_vf_msg_acquire_resp *)pdev->pf_vf_acquiring_resp;
    mess->vf_qid = vf_qid;
    if (validation_flag & RX_Q_VALIDATE) {
        SET_FLAGS(mess->param_valid, VFPF_RXQ_VALID);
        mess->rxq.rcq_addr = lm_bd_chain_phys_addr(&(LM_RCQ(pdev,vf_qid).bd_chain), 0).as_u64;
        mess->rxq.rcq_np_addr = lm_bd_chain_phys_addr(&(LM_RCQ(pdev,vf_qid).bd_chain), 1).as_u64;
        mess->rxq.rxq_addr = lm_bd_chain_phys_addr(&(LM_RXQ_CHAIN(pdev,vf_qid,0)), 0).as_u64;
        if (presp->pfdev_info.pf_cap & PFVF_CAP_TPA) {
            mess->rxq.sge_addr = LM_TPA_CHAIN_BD(pdev, vf_qid).bd_chain_phy.as_u64;
            if (mess->rxq.sge_addr) {
                    mess->rxq.flags |= SW_VFPF_QUEUE_FLG_TPA;
                }
            } else {
                mess->rxq.sge_addr = 0;
            }
        
            /* sb + hc info */
            mess->rxq.vf_sb = vf_qid;          /* relative to vf */
            mess->rxq.flags |= SW_VFPF_QUEUE_FLG_CACHE_ALIGN;
            mess->rxq.sb_index = LM_RCQ(pdev, vf_qid).hc_sb_info.hc_index_value;
            if ((pdev->params.int_coalesing_mode == LM_INT_COAL_PERIODIC_SYNC)/* && !pdev->params.int_coalesing_mode_disabled_by_ndis*/) {
                mess->rxq.hc_rate = (u16_t)pdev->params.int_per_sec_rx[HC_PARAMS_ETH_INDEX];           /* desired interrupts per sec. *//* valid iff VFPF_QUEUE_FLG_HC */
                mess->rxq.flags |= SW_VFPF_QUEUE_FLG_HC;
                if (pdev->params.enable_dynamic_hc[HC_PARAMS_ETH_INDEX] && (presp->pfdev_info.pf_cap & PFVF_CAP_DHC)) {
                    mess->rxq.flags |= SW_VFPF_QUEUE_FLG_DHC;
                }
            }
        
            /* rx buffer info */
            mess->rxq.mtu        = (u16_t)pdev->params.l2_cli_con_params[vf_qid].mtu;
            mess->rxq.buf_sz     = MAX_L2_CLI_BUFFER_SIZE(pdev, vf_qid);
            mess->rxq.drop_flags = 0; //(u8_t)pdev->params.rx_err_filter;
        }
        
        if (validation_flag & TX_Q_VALIDATE) {
            SET_FLAGS(mess->param_valid, VFPF_TXQ_VALID);
            mess->txq.txq_addr = lm_bd_chain_phys_addr(&(LM_TXQ(pdev,vf_qid).bd_chain), 0).as_u64;
            mess->txq.vf_sb = vf_qid;
            mess->txq.sb_index = LM_TXQ(pdev, vf_qid).hc_sb_info.hc_index_value;
            if ((pdev->params.int_coalesing_mode == LM_INT_COAL_PERIODIC_SYNC)/* && pdev->params.int_coalesing_mode_disabled_by_ndis*/) {
                mess->txq.hc_rate = (u16_t)pdev->params.int_per_sec_tx[HC_PARAMS_ETH_INDEX];           /* desired interrupts per sec. *//* valid iff VFPF_QUEUE_FLG_HC */
                mess->txq.flags |= SW_VFPF_QUEUE_FLG_HC;
            }
        }
    }
    else if (IS_HW_CHANNEL_VIRT_MODE(pdev)) 
    {
        struct vfpf_setup_q_tlv * mess = NULL;
        struct pfvf_acquire_resp_tlv * presp = NULL;

        mess = (struct vfpf_setup_q_tlv*)pf_mess->message_virt_addr;
        presp = (struct pfvf_acquire_resp_tlv *)pdev->pf_vf_acquiring_resp;
        mess->vf_qid = vf_qid;
        if (validation_flag & RX_Q_VALIDATE) {
            SET_FLAGS(mess->param_valid, VFPF_RXQ_VALID);
            mess->rxq.rcq_addr = lm_bd_chain_phys_addr(&(LM_RCQ(pdev,vf_qid).bd_chain), 0).as_u64;
            mess->rxq.rcq_np_addr = lm_bd_chain_phys_addr(&(LM_RCQ(pdev,vf_qid).bd_chain), 1).as_u64;
            mess->rxq.rxq_addr = lm_bd_chain_phys_addr(&(LM_RXQ_CHAIN(pdev,vf_qid,0)), 0).as_u64;
#if 0
            if (presp->pfdev_info.pf_cap & PFVF_CAP_TPA) {
                mess->rxq.sge_addr = LM_TPA_CHAIN_BD(pdev, vf_qid).bd_chain_phy.as_u64;
                if (mess->rxq.sge_addr) {
                mess->rxq.flags |= VFPF_QUEUE_FLG_TPA;
            }
            } 
            else 
#endif            
            {
        mess->rxq.sge_addr = 0;
        }

        /* sb + hc info */
        mess->rxq.vf_sb = vf_qid;          /* relative to vf */
        mess->rxq.flags |= VFPF_QUEUE_FLG_CACHE_ALIGN;
        mess->rxq.flags |= VFPF_QUEUE_FLG_STATS;
        mess->rxq.flags |= VFPF_QUEUE_FLG_VLAN;
        mess->rxq.sb_index = LM_RCQ(pdev, vf_qid).hc_sb_info.hc_index_value;
        if ((pdev->params.int_coalesing_mode == LM_INT_COAL_PERIODIC_SYNC)/* && !pdev->params.int_coalesing_mode_disabled_by_ndis*/) {
            mess->rxq.hc_rate = (u16_t)pdev->params.int_per_sec_rx[HC_PARAMS_ETH_INDEX];           /* desired interrupts per sec. *//* valid iff VFPF_QUEUE_FLG_HC */
            mess->rxq.flags |= VFPF_QUEUE_FLG_HC;
            if (pdev->params.enable_dynamic_hc[HC_PARAMS_ETH_INDEX] && (presp->pfdev_info.pf_cap & PFVF_CAP_DHC)) {
                mess->rxq.flags |= VFPF_QUEUE_FLG_DHC;
            }
        }
        if (!vf_qid) 
        {
            mess->rxq.flags |= VFPF_QUEUE_FLG_LEADING_RSS;
        }
        /* rx buffer info */
        mess->rxq.mtu        = (u16_t)pdev->params.l2_cli_con_params[vf_qid].mtu;
        mess->rxq.buf_sz     = MAX_L2_CLI_BUFFER_SIZE(pdev, vf_qid);
        mess->rxq.drop_flags = 0; //(u8_t)pdev->params.rx_err_filter;
    }

    if (validation_flag & TX_Q_VALIDATE) {
        SET_FLAGS(mess->param_valid, VFPF_TXQ_VALID);
        mess->txq.txq_addr = lm_bd_chain_phys_addr(&(LM_TXQ(pdev,vf_qid).bd_chain), 0).as_u64;
        mess->txq.vf_sb = vf_qid;
        mess->txq.sb_index = LM_TXQ(pdev, vf_qid).hc_sb_info.hc_index_value;
        if ((pdev->params.int_coalesing_mode == LM_INT_COAL_PERIODIC_SYNC)/* && pdev->params.int_coalesing_mode_disabled_by_ndis*/) {
            mess->txq.hc_rate = (u16_t)pdev->params.int_per_sec_tx[HC_PARAMS_ETH_INDEX];           /* desired interrupts per sec. *//* valid iff VFPF_QUEUE_FLG_HC */
            mess->txq.flags |= VFPF_QUEUE_FLG_HC;
        }
    }
    }
    else
    {
        DbgBreak();
        lm_vf_pf_channel_release_message(pdev,pf_mess);
        return LM_STATUS_FAILURE;
    }
    lm_status = lm_vf_pf_channel_send(pdev,pf_mess);
    if (lm_status != LM_STATUS_SUCCESS) {
        lm_vf_pf_channel_release_message(pdev,pf_mess);
    }

    DbgMessage(pdev, WARNvf, "lm_vf_pf_setup_q lm_status = %d\n", lm_status);
    return lm_status;
}



lm_status_t lm_vf_pf_tear_q_down(struct _lm_device_t * pdev, u8 vf_qid)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    lm_vf_pf_message_t * pf_mess = NULL;

    DbgBreakIf(!(pdev && IS_CHANNEL_VFDEV(pdev)
                 && (vf_qid < LM_SB_CNT(pdev))));

    pf_mess = lm_vf_pf_channel_get_message_to_send(pdev, PFVF_OP_TEARDOWN_Q);
    if (!pf_mess) {
        lm_status = LM_STATUS_RESOURCE;
        DbgBreak();
        return lm_status;
    }
    if (IS_SW_CHANNEL_VIRT_MODE(pdev)) 
    {
        struct vf_pf_msg_q_op * mess = NULL;
    mess = (struct vf_pf_msg_q_op*)pf_mess->message_virt_addr;
    mess->vf_qid = vf_qid;
    }
    else if (IS_HW_CHANNEL_VIRT_MODE(pdev)) 
    {
        struct vfpf_q_op_tlv * mess = NULL;
        mess = (struct vfpf_q_op_tlv*)pf_mess->message_virt_addr;
        mess->vf_qid = vf_qid;
    }
    else
    {
        DbgBreak();
        lm_vf_pf_channel_release_message(pdev,pf_mess);
        return LM_STATUS_FAILURE;
    }
    lm_status = lm_vf_pf_channel_send(pdev,pf_mess);
    if (lm_status != LM_STATUS_SUCCESS) {
        lm_vf_pf_channel_release_message(pdev,pf_mess);
    }

    return lm_status;
}

lm_status_t lm_vf_pf_set_q_filters(struct _lm_device_t * pdev, u8 vf_qid, void * cookie, q_filter_type filter_type, u8_t * pbuf, u32_t buf_len,
                                   u16_t vlan_tag, u8_t set_mac)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    lm_vf_pf_message_t * pf_mess = NULL;
    u8_t    num_entries, idx_entries;
    u8_t    is_clear;
    lm_rx_mask_t * rx_mask;
    u8_t    send_it = FALSE;

    DbgMessage(pdev, WARNvf, "lm_vf_pf_set_q_filters\n");

    DbgBreakIf(!(pdev && IS_CHANNEL_VFDEV(pdev) && (vf_qid < LM_SB_CNT(pdev)) && pdev->pf_vf_acquiring_resp));

    pf_mess = lm_vf_pf_channel_get_message_to_send(pdev, PFVF_OP_SET_Q_FILTERS);
    if (!pf_mess) {
        lm_status = LM_STATUS_RESOURCE;
        DbgBreak();
        return lm_status;
    }
    if (IS_SW_CHANNEL_VIRT_MODE(pdev)) 
    {
        struct vf_pf_msg_set_q_filters * mess = NULL;
        struct pf_vf_msg_acquire_resp * resp = NULL;
    mess = (struct vf_pf_msg_set_q_filters*)pf_mess->message_virt_addr;
    resp = (struct pf_vf_msg_acquire_resp *)pdev->pf_vf_acquiring_resp;
    mess->vf_qid = vf_qid;
    pf_mess->cookie = cookie;
    is_clear = ((pbuf == NULL) || (buf_len == 0));

    switch (filter_type) {
    case Q_FILTER_MAC:
        num_entries = resp->resc.num_mac_filters;
        is_clear = !set_mac;
        if (!is_clear) {
            num_entries = min((u32_t)num_entries, buf_len/ETHERNET_ADDRESS_SIZE);
        }
        mess->n_mac_vlan_filters = num_entries;
        for (idx_entries = 0; idx_entries < num_entries; idx_entries++) {
            mess->filters[idx_entries].flags = VFPF_Q_FILTER_DEST_MAC_PRESENT;
            if (is_clear) {
                mess->filters[idx_entries].flags &= ~VFPF_Q_FILTER_SET_MAC;
            } else {
                mess->filters[idx_entries].flags |= VFPF_Q_FILTER_SET_MAC;
            }
            mm_memcpy(mess->filters[idx_entries].dest_mac, pbuf + idx_entries*ETHERNET_ADDRESS_SIZE, ETHERNET_ADDRESS_SIZE);
            if (vlan_tag != LM_SET_CAM_NO_VLAN_FILTER) {
                mess->filters[idx_entries].vlan_tag = vlan_tag;
                mess->filters[idx_entries].flags |= VFPF_Q_FILTER_VLAN_TAG_PRESENT;
            }
        }
        if (mess->n_mac_vlan_filters) {
            mess->flags = VFPF_SET_Q_FILTERS_MAC_VLAN_CHANGED;
        }
        break;
    case Q_FILTER_VLAN:
        DbgMessage(pdev, FATAL, "VLAN filter is not supported yet\n");
        DbgBreak();
        break;
    case Q_FILTER_MC:
        num_entries = resp->resc.num_mc_filters;
        if (!is_clear) {
            num_entries = min((u32_t)num_entries, buf_len/ETHERNET_ADDRESS_SIZE);
        }
        DbgMessage(pdev, FATAL, "Q_FILTER_MC: %d entries\n", num_entries);
        mess->n_multicast = num_entries;
        for (idx_entries = 0; idx_entries < num_entries; idx_entries++) {
            if (is_clear) {
                mm_mem_zero(&mess->multicast[idx_entries][0], ETHERNET_ADDRESS_SIZE);
            } else {
                mm_memcpy(&mess->multicast[idx_entries][0], pbuf + idx_entries*ETHERNET_ADDRESS_SIZE, ETHERNET_ADDRESS_SIZE);
            }
        }
        if (mess->n_multicast) {
            mess->flags = VFPF_SET_Q_FILTERS_MULTICAST_CHANGED;
        }
        break;
    case Q_FILTER_RX_MASK:
        DbgBreakIf(is_clear || (buf_len != sizeof(lm_rx_mask_t)));
        mess->rx_mask = 0;
        rx_mask = (lm_rx_mask_t*)pbuf;
        if (GET_FLAGS(*rx_mask, LM_RX_MASK_PROMISCUOUS_MODE)) {
            mess->rx_mask |= (VFPF_RX_MASK_ACCEPT_MATCHED_UNICAST | VFPF_RX_MASK_ACCEPT_MATCHED_MULTICAST |
                               VFPF_RX_MASK_ACCEPT_ALL_MULTICAST | VFPF_RX_MASK_ACCEPT_ALL_UNICAST | VFPF_RX_MASK_ACCEPT_BROADCAST);
        }
        if (GET_FLAGS(*rx_mask, LM_RX_MASK_ACCEPT_UNICAST)) {
            mess->rx_mask |= VFPF_RX_MASK_ACCEPT_MATCHED_UNICAST;
        }
        if (GET_FLAGS(*rx_mask, LM_RX_MASK_ACCEPT_MULTICAST)) {
            mess->rx_mask |= VFPF_RX_MASK_ACCEPT_MATCHED_MULTICAST;
        }
        if (GET_FLAGS(*rx_mask, LM_RX_MASK_ACCEPT_ALL_MULTICAST)) {
            mess->rx_mask |= VFPF_RX_MASK_ACCEPT_ALL_MULTICAST;
        }
        if (GET_FLAGS(*rx_mask, LM_RX_MASK_ACCEPT_BROADCAST)) {
            mess->rx_mask |= VFPF_RX_MASK_ACCEPT_BROADCAST;
        }
        mess->flags = VFPF_SET_Q_FILTERS_RX_MASK_CHANGED;

        DbgMessage(pdev, FATAL, "Q_FILTER_RX_MASK: mess->rx_mask=%x mess->flags=%x\n", mess->rx_mask, mess->flags);
        break;
    default:
        break;
    }
        if (mess->flags)
        {
            send_it = TRUE;
        }
    }
    else if (IS_HW_CHANNEL_VIRT_MODE(pdev)) 
    {
        struct vfpf_set_q_filters_tlv * mess = NULL;
        struct pfvf_acquire_resp_tlv *  resp = NULL;
        mess = (struct vfpf_set_q_filters_tlv*)pf_mess->message_virt_addr;
        resp = (struct pfvf_acquire_resp_tlv *)pdev->pf_vf_acquiring_resp;
        mess->vf_qid = vf_qid;
        pf_mess->cookie = cookie;
        is_clear = ((pbuf == NULL) || (buf_len == 0));

        switch (filter_type) {
        case Q_FILTER_MAC:
            num_entries = resp->resc.num_mac_filters;
            is_clear = !set_mac;
            if (!is_clear) {
                num_entries = min((u32_t)num_entries, buf_len/ETHERNET_ADDRESS_SIZE);
            }
            mess->n_mac_vlan_filters = num_entries;
            for (idx_entries = 0; idx_entries < num_entries; idx_entries++) {
                mess->filters[idx_entries].flags = VFPF_Q_FILTER_DEST_MAC_PRESENT;
                if (is_clear) {
                    mess->filters[idx_entries].flags &= ~VFPF_Q_FILTER_SET_MAC;
                } else {
                    mess->filters[idx_entries].flags |= VFPF_Q_FILTER_SET_MAC;
                }
                mm_memcpy(mess->filters[idx_entries].mac, pbuf + idx_entries*ETHERNET_ADDRESS_SIZE, ETHERNET_ADDRESS_SIZE);
                if (vlan_tag != LM_SET_CAM_NO_VLAN_FILTER) {
                    mess->filters[idx_entries].vlan_tag = vlan_tag;
                    mess->filters[idx_entries].flags |= VFPF_Q_FILTER_VLAN_TAG_PRESENT;
                }
            }
            if (mess->n_mac_vlan_filters) {
                mess->flags = VFPF_SET_Q_FILTERS_MAC_VLAN_CHANGED;
            }
            break;
        case Q_FILTER_VLAN:
            DbgMessage(pdev,FATAL,"VLAN filter is not supported yet\n");
            DbgBreak();
            break;
        case Q_FILTER_MC:
            num_entries = resp->resc.num_mc_filters;
            if (!is_clear) {
                num_entries = min((u32_t)num_entries, buf_len/ETHERNET_ADDRESS_SIZE);
            }
            DbgMessage(pdev, FATAL, "Q_FILTER_MC: %d entries\n", num_entries);
            mess->n_multicast = num_entries;
            for (idx_entries = 0; idx_entries < num_entries; idx_entries++) {
                if (is_clear) {
                    mm_mem_zero(&mess->multicast[idx_entries][0], ETHERNET_ADDRESS_SIZE);
                } else {
                    mm_memcpy(&mess->multicast[idx_entries][0], pbuf + idx_entries*ETHERNET_ADDRESS_SIZE, ETHERNET_ADDRESS_SIZE);
                }
            }
            if (mess->n_multicast) {
                mess->flags = VFPF_SET_Q_FILTERS_MULTICAST_CHANGED;
            }
            break;
        case Q_FILTER_RX_MASK:
            DbgBreakIf(is_clear || (buf_len != sizeof(lm_rx_mask_t)));
            mess->rx_mask = 0;
            rx_mask = (lm_rx_mask_t*)pbuf;
            if (GET_FLAGS(*rx_mask, LM_RX_MASK_PROMISCUOUS_MODE)) {
                mess->rx_mask |= (VFPF_RX_MASK_ACCEPT_MATCHED_UNICAST | VFPF_RX_MASK_ACCEPT_MATCHED_MULTICAST |
                                   VFPF_RX_MASK_ACCEPT_ALL_MULTICAST | VFPF_RX_MASK_ACCEPT_ALL_UNICAST | VFPF_RX_MASK_ACCEPT_BROADCAST);
            }
            if (GET_FLAGS(*rx_mask, LM_RX_MASK_ACCEPT_UNICAST)) {
                mess->rx_mask |= VFPF_RX_MASK_ACCEPT_MATCHED_UNICAST;
            }
            if (GET_FLAGS(*rx_mask, LM_RX_MASK_ACCEPT_MULTICAST)) {
                mess->rx_mask |= VFPF_RX_MASK_ACCEPT_MATCHED_MULTICAST;
            }
            if (GET_FLAGS(*rx_mask, LM_RX_MASK_ACCEPT_ALL_MULTICAST)) {
                mess->rx_mask |= VFPF_RX_MASK_ACCEPT_ALL_MULTICAST;
            }
            if (GET_FLAGS(*rx_mask, LM_RX_MASK_ACCEPT_BROADCAST)) {
                mess->rx_mask |= VFPF_RX_MASK_ACCEPT_BROADCAST;
            }
            mess->flags = VFPF_SET_Q_FILTERS_RX_MASK_CHANGED;

            DbgMessage(pdev, FATAL, "Q_FILTER_RX_MASK: mess->rx_mask=%x mess->flags=%x\n", mess->rx_mask, mess->flags);
            break;
        default:
            break;
        }
        if (mess->flags)
        {
            send_it = TRUE;
        }
    }
    else
    {
        DbgBreak();
        lm_vf_pf_channel_release_message(pdev,pf_mess);
        return LM_STATUS_FAILURE;
    }

    if (send_it) {
        lm_status = lm_vf_pf_channel_send(pdev,pf_mess);
        if (lm_status != LM_STATUS_SUCCESS) {
            lm_vf_pf_channel_release_message(pdev,pf_mess);
        }
    } else {
        DbgMessage(pdev, FATAL, "lm_vf_pf_set_q_filters: flag is not set. Use bypass\n");
        *pf_mess->done = SW_PFVF_STATUS_SUCCESS;
        DbgBreakIf(filter_type != Q_FILTER_MC);
    }

    return lm_status;
}

lm_status_t lm_vf_pf_set_q_filters_list(struct _lm_device_t * pdev, u8 vf_qid, void * cookie, q_filter_type filter_type, d_list_t * pbuf,
                                        u16_t vlan_tag, u8_t set_mac)

{
    DbgMessage(NULL, FATAL, "lm_vf_pf_set_q_filters_list is not used in channel VF\n");
    DbgBreak();
    return LM_STATUS_FAILURE;
}

lm_status_t lm_vf_pf_update_rss(struct _lm_device_t *pdev, void * cookie, u32_t rss_flags, u8_t rss_result_mask, u8_t * ind_table, u32_t * rss_key)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    lm_vf_pf_message_t * pf_mess = NULL;
    u8_t ind_table_idx;

    DbgMessage(pdev, WARNvf, "lm_vf_pf_update_rss\n");

    DbgBreakIf(!(pdev && IS_CHANNEL_VFDEV(pdev) && pdev->pf_vf_acquiring_resp));

    pf_mess = lm_vf_pf_channel_get_message_to_send(pdev, PFVF_OP_UPDATE_RSS);
    if (!pf_mess) {
        lm_status = LM_STATUS_RESOURCE;
        DbgBreak();
        return lm_status;
    }
    if (IS_SW_CHANNEL_VIRT_MODE(pdev)) 
    {
        struct vf_pf_msg_rss * mess = NULL;
        mess = (struct vf_pf_msg_rss*)pf_mess->message_virt_addr;
        pf_mess->cookie = cookie;
        mess->rss_flags = rss_flags;
        mess->rss_result_mask = rss_result_mask;
        mm_memcpy(mess->ind_table, ind_table, T_ETH_INDIRECTION_TABLE_SIZE);
        mess->ind_table_size = T_ETH_INDIRECTION_TABLE_SIZE;
        mm_memcpy(mess->rss_key, rss_key, sizeof(u32_t)*T_ETH_RSS_KEY);
        mess->rss_key_size = T_ETH_RSS_KEY;
    }
    else if (IS_HW_CHANNEL_VIRT_MODE(pdev)) 
    {
        struct vfpf_rss_tlv * mess = NULL;
        mess = (struct vfpf_rss_tlv*)pf_mess->message_virt_addr;
        pf_mess->cookie = cookie;
        mess->rss_flags = rss_flags;
        mess->rss_result_mask = rss_result_mask;
        for (ind_table_idx = 0; ind_table_idx < T_ETH_INDIRECTION_TABLE_SIZE; ind_table_idx++) {
            mess->ind_table[ind_table_idx] = IGU_VF_NDSB(pdev,ind_table[ind_table_idx]);
        }
        mess->ind_table_size = T_ETH_INDIRECTION_TABLE_SIZE;
        mm_memcpy(mess->rss_key, rss_key, sizeof(u32_t)*T_ETH_RSS_KEY);
        mess->rss_key_size = T_ETH_RSS_KEY;
    }
    else
    {
        DbgBreak();
        lm_vf_pf_channel_release_message(pdev,pf_mess);
        return LM_STATUS_FAILURE;
    }

    lm_status = lm_vf_pf_channel_send(pdev,pf_mess);
    if (lm_status != LM_STATUS_SUCCESS) {
        lm_vf_pf_channel_release_message(pdev,pf_mess);
    }

    return lm_status;
}

lm_status_t lm_vf_pf_update_rsc(struct _lm_device_t *pdev)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    lm_vf_pf_message_t * pf_mess = NULL;
    u8_t rss_idx = 0;

    DbgMessage(pdev, WARNvf, "lm_vf_pf_update_rsc\n");

    DbgBreakIf(!(pdev && IS_CHANNEL_VFDEV(pdev) && pdev->pf_vf_acquiring_resp));

    pf_mess = lm_vf_pf_channel_get_message_to_send(pdev, PFVF_OP_UPDATE_RSC);
    if (!pf_mess) {
        lm_status = LM_STATUS_RESOURCE;
        DbgBreak();
        return lm_status;
    }
    if (IS_SW_CHANNEL_VIRT_MODE(pdev)) 
    {
        struct vf_pf_msg_rsc * mess = (struct vf_pf_msg_rsc *)pf_mess->message_virt_addr;
        mess->rsc_ipv4_state = lm_tpa_ramrod_update_ipvx(pdev, 0, TPA_IPV4_ENABLED);
        mess->rsc_ipv6_state = lm_tpa_ramrod_update_ipvx(pdev, 0, TPA_IPV6_ENABLED);    
    }
    else if (IS_HW_CHANNEL_VIRT_MODE(pdev)) 
    {
        struct vfpf_tpa_tlv * mess = (struct vfpf_tpa_tlv*)pf_mess->message_virt_addr;

        LM_FOREACH_RSS_IDX(pdev, rss_idx)
        {
            mess->tpa_client_info.sge_addr[rss_idx] = LM_TPA_CHAIN_BD(pdev, rss_idx).bd_chain_phy.as_u64;
        }

        mess->tpa_client_info.complete_on_both_clients = 1;
        mess->tpa_client_info.max_tpa_queues = LM_TPA_MAX_AGGS;
        mess->tpa_client_info.max_sges_for_packet = DIV_ROUND_UP_BITS((u16_t)pdev->params.l2_cli_con_params[0].mtu, LM_TPA_PAGE_BITS);
        mess->tpa_client_info.sge_buff_size = LM_TPA_PAGE_SIZE;
        mess->tpa_client_info.max_agg_size = LM_TPA_MAX_AGG_SIZE * LM_TPA_PAGE_SIZE;
        mess->tpa_client_info.sge_pause_thr_low = LM_TPA_SGE_PAUSE_THR_LOW;
        mess->tpa_client_info.sge_pause_thr_high = LM_TPA_SGE_PAUSE_THR_HIGH;
        mess->tpa_client_info.complete_on_both_clients = TRUE;
        mess->tpa_client_info.dont_verify_thr = 0;
        mess->tpa_client_info.tpa_mode = TPA_LRO;
        mess->tpa_client_info.update_ipv4 = lm_tpa_ramrod_update_ipvx(pdev, 0, TPA_IPV4_ENABLED);
        mess->tpa_client_info.update_ipv6 = lm_tpa_ramrod_update_ipvx(pdev, 0, TPA_IPV6_ENABLED);

    }
    else
    {
        DbgBreak();
        lm_vf_pf_channel_release_message(pdev,pf_mess);
        return LM_STATUS_FAILURE;
    }

    lm_status = lm_vf_pf_channel_send(pdev,pf_mess);
    if (lm_status != LM_STATUS_SUCCESS) {
        lm_vf_pf_channel_release_message(pdev,pf_mess);
    }

    return lm_status;
}

lm_status_t lm_vf_pf_close_vf(struct _lm_device_t * pdev)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    lm_vf_pf_message_t * pf_mess = NULL;

    DbgBreakIf(!(pdev && IS_CHANNEL_VFDEV(pdev)));
    pf_mess = lm_vf_pf_channel_get_message_to_send(pdev, PFVF_OP_CLOSE_VF);
    if (!pf_mess) {
        lm_status = LM_STATUS_RESOURCE;
        DbgBreak();
        return lm_status;
    }
    if (IS_SW_CHANNEL_VIRT_MODE(pdev)) 
    {
        struct vf_pf_msg_close_vf * mess = NULL;
        mess = (struct vf_pf_msg_close_vf*)pf_mess->message_virt_addr;
        mess->vf_id = ABS_VFID(pdev);
    }
    else if (IS_HW_CHANNEL_VIRT_MODE(pdev)) 
    {
        struct vfpf_close_tlv * mess = NULL;
        mess = (struct vfpf_close_tlv*)pf_mess->message_virt_addr;
        mess->vf_id = ABS_VFID(pdev);
    }
    else
    {
        DbgBreak();
        lm_vf_pf_channel_release_message(pdev,pf_mess);
        return LM_STATUS_FAILURE;
    }

    lm_status = lm_vf_pf_channel_send(pdev,pf_mess);
    if (lm_status != LM_STATUS_SUCCESS) {
        lm_vf_pf_channel_release_message(pdev,pf_mess);
    }

    return lm_status;

}

lm_status_t lm_vf_pf_release_vf(struct _lm_device_t * pdev)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    lm_vf_pf_message_t * pf_mess = NULL;
    void* vresp = NULL;

    DbgBreakIf(!(pdev && IS_CHANNEL_VFDEV(pdev)));

    pf_mess = lm_vf_pf_channel_get_message_to_send(pdev, PFVF_OP_RELEASE_VF);
    if (!pf_mess) {
        lm_status = LM_STATUS_RESOURCE;
        DbgBreak();
        return lm_status;
    }
    if (IS_SW_CHANNEL_VIRT_MODE(pdev)) 
    {
        struct vf_pf_msg_release_vf * mess = NULL;
    mess = (struct vf_pf_msg_release_vf*)pf_mess->message_virt_addr;
    mess->vf_id = ABS_VFID(pdev);          /* ME register value */
        vresp = (u8_t*)mess + mess->hdr.resp_msg_offset;
    }
    else if (IS_HW_CHANNEL_VIRT_MODE(pdev)) 
    {
        struct vfpf_release_tlv * mess = NULL;
        mess = (struct vfpf_release_tlv*)pf_mess->message_virt_addr;
        mess->vf_id = ABS_VFID(pdev);
    }
    else
    {
        DbgBreak();
        lm_vf_pf_channel_release_message(pdev,pf_mess);
        return LM_STATUS_FAILURE;
    }
    pf_mess->do_not_arm_trigger = TRUE;
    lm_status = lm_vf_pf_channel_send(pdev,pf_mess);
    if (lm_status != LM_STATUS_SUCCESS) {
        lm_vf_pf_channel_release_message(pdev,pf_mess);
        return lm_status;
    }
    lm_status = lm_vf_pf_channel_wait_response(pdev, pf_mess);
    // FIXME TODO
    if (lm_status == LM_STATUS_SUCCESS) {
        if (IS_SW_CHANNEL_VIRT_MODE(pdev)) 
        {
            struct pf_vf_msg_resp * resp = NULL;
            resp = (struct pf_vf_msg_resp *)vresp;
        if (resp->hdr.opcode != PFVF_OP_RELEASE_VF) {
            lm_status = LM_STATUS_FAILURE;
        } else {
            switch (resp->hdr.status) {
                case SW_PFVF_STATUS_SUCCESS:
                lm_status = LM_STATUS_SUCCESS;
                break;
                case SW_PFVF_STATUS_FAILURE:
                case SW_PFVF_STATUS_MISMATCH_PF_VF_VERSION:
                case SW_PFVF_STATUS_MISMATCH_FW_HSI:
                case SW_PFVF_STATUS_NO_RESOURCE:
                DbgMessage(pdev, FATAL, "VF_PF Channel: Status %d is not supported yet\n", resp->hdr.status);
                lm_status = LM_STATUS_FAILURE;
                break;
            default:
                DbgMessage(pdev, FATAL, "VF_PF Channel: Unknown status %d\n", resp->hdr.status);
                lm_status = LM_STATUS_FAILURE;
                break;
            }
        }
    }
    }


    lm_vf_pf_channel_release_message(pdev, pf_mess);
    return lm_status;
}

void lm_vf_fl_reset_set_inprogress(struct _lm_device_t * pdev)
{
    DbgMessage(pdev, WARN, "Set FLR flag is not implemented yet\n");
}

void lm_vf_fl_reset_clear_inprogress(struct _lm_device_t *pdev)
{
    DbgMessage(pdev, WARN, "Clear FLR flag is not implemented yet\n");
}

u8_t lm_vf_fl_reset_is_inprogress(struct _lm_device_t *pdev)
{
    DbgMessage(pdev, WARN, "Get FLR flag is not implemented yet\n");
    return FALSE;
}

lm_status_t lm_vf_get_vf_id(struct _lm_device_t * pdev)
{
    pdev->params.debug_me_register = _vf_reg_rd(pdev,VF_BAR0_DB_OFFSET);;
    
    DbgMessage(pdev, WARN, "vf ME-REG value: 0x%x\n", pdev->params.debug_me_register);

    if (!(pdev->params.debug_me_register & ME_REG_VF_VALID)) {
        DbgBreakIf(!(pdev->params.debug_me_register & ME_REG_VF_VALID));
        return LM_STATUS_FAILURE;
    }
    pdev->params.vf_num_in_path = (pdev->params.debug_me_register & ME_REG_VF_NUM_MASK) >> ME_REG_VF_NUM_SHIFT;
    DbgMessage(pdev, WARN, "vf_num_in_path=%d\n", pdev->params.vf_num_in_path);
    return LM_STATUS_SUCCESS;
}

lm_status_t lm_vf_setup_alloc_resc(struct _lm_device_t *pdev, u8_t b_is_alloc )
{
    lm_variables_t* vars       = NULL ;
    u32_t           mem_size   = 0 ;
    //u32_t           alloc_size = 0 ;
    u8_t            mm_cli_idx = 0 ;
    u8_t            sb_id      = 0 ;
    lm_address_t    sb_phy_address;
    void * p_sb;
    DbgBreakIf(!(pdev && IS_CHANNEL_VFDEV(pdev) && pdev->pf_vf_acquiring_resp));
    //DbgBreakIf(!(presp && (sb_id < presp->pfdev_info.indices_per_sb)));

    if CHK_NULL( pdev )
    {
        return LM_STATUS_INVALID_PARAMETER ;
    }

    DbgMessage(pdev, FATAL, "### VF lm_common_setup_alloc_resc b_is_alloc=%s\n", b_is_alloc ? "TRUE" : "FALSE" );

    vars       = &(pdev->vars) ;

    //       Status blocks allocation. We allocate mem both for the default and non-default status blocks
    //       there is 1 def sb and 16 non-def sb per port.
    //       non-default sb: index 0-15, default sb: index 16.
    if (IS_CHANNEL_VFDEV(pdev)) {
        if (IS_SW_CHANNEL_VIRT_MODE(pdev)) 
        {
            struct pf_vf_msg_acquire_resp * presp;
            presp = (struct pf_vf_msg_acquire_resp *)pdev->pf_vf_acquiring_resp;
        mem_size = (sizeof(u16_t) * (presp->pfdev_info.indices_per_sb + 2) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK;
        }
        else if (IS_HW_CHANNEL_VIRT_MODE(pdev)) 
        {
            struct pfvf_acquire_resp_tlv * presp;
            presp = (struct pfvf_acquire_resp_tlv *)pdev->pf_vf_acquiring_resp;
            mem_size = (sizeof(u16_t) * (presp->pfdev_info.indices_per_sb + 2) + CACHE_LINE_SIZE_MASK) & ~CACHE_LINE_SIZE_MASK;
        }
        else
        {
            DbgBreak();
            return LM_STATUS_FAILURE;
        }
    } else {
        mem_size = E2_STATUS_BLOCK_BUFFER_SIZE;
    }

    mm_cli_idx = LM_RESOURCE_COMMON;//!!DP mm_cli_idx_to_um_idx(LM_CLI_IDX_MAX);

    LM_FOREACH_SB_ID(pdev, sb_id)
    {
        if( b_is_alloc )
        {
            if (IS_CHANNEL_VFDEV(pdev)) {
                pdev->vars.status_blocks_arr[sb_id].host_hc_status_block.vf_sb = p_sb = mm_alloc_phys_mem(pdev, mem_size, &sb_phy_address, 0, mm_cli_idx);
                pdev->vars.status_blocks_arr[sb_id].hc_status_block_data.vf_sb_phy_address.as_u32.low = sb_phy_address.as_u32.low;
                pdev->vars.status_blocks_arr[sb_id].hc_status_block_data.vf_sb_phy_address.as_u32.high = sb_phy_address.as_u32.high;
            } else {
                pdev->vars.status_blocks_arr[sb_id].host_hc_status_block.e2_sb = p_sb = mm_alloc_phys_mem(pdev, mem_size, &sb_phy_address, 0, mm_cli_idx);
                pdev->vars.status_blocks_arr[sb_id].hc_status_block_data.e2_sb_data.common.host_sb_addr.lo = sb_phy_address.as_u32.low;
                pdev->vars.status_blocks_arr[sb_id].hc_status_block_data.e2_sb_data.common.host_sb_addr.hi = sb_phy_address.as_u32.high;
            }
        }
        else
        {
            if (IS_CHANNEL_VFDEV(pdev)) {
                p_sb = (void *)pdev->vars.status_blocks_arr[sb_id].host_hc_status_block.vf_sb;
            } else {
                p_sb = (void *)pdev->vars.status_blocks_arr[sb_id].host_hc_status_block.e2_sb;
            }
        }

        if CHK_NULL(p_sb)
        {
            DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
            return LM_STATUS_RESOURCE ;
        }
        mm_mem_zero(p_sb, mem_size);
    }
    lm_reset_sb_ack_values(pdev);

    mm_mem_zero(pdev->debug_info.ack_dis,     sizeof(pdev->debug_info.ack_dis));
    mm_mem_zero(pdev->debug_info.ack_en,      sizeof(pdev->debug_info.ack_en));
    mm_mem_zero(pdev->debug_info.rx_only_int, sizeof(pdev->debug_info.rx_only_int));
    mm_mem_zero(pdev->debug_info.tx_only_int, sizeof(pdev->debug_info.tx_only_int));
    mm_mem_zero(pdev->debug_info.both_int,    sizeof(pdev->debug_info.both_int));
    mm_mem_zero(pdev->debug_info.empty_int,   sizeof(pdev->debug_info.empty_int));
    mm_mem_zero(pdev->debug_info.false_int,   sizeof(pdev->debug_info.false_int));

#if 0
    //CAM
    alloc_size = sizeof(struct mac_configuration_cmd) ;

    if( b_is_alloc )
    {
        pdev->params.mac_config[LM_CLI_IDX_NDIS] = mm_alloc_phys_mem(pdev,
                                                    alloc_size,
                                                    &pdev->params.mac_config_phy[LM_CLI_IDX_NDIS],
                                                    0,
                                                    mm_cli_idx);
    }
    if CHK_NULL( pdev->params.mac_config[LM_CLI_IDX_NDIS] )
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return LM_STATUS_RESOURCE ;
    }

    mm_mem_zero((void *) (pdev->params.mac_config[LM_CLI_IDX_NDIS]), alloc_size );

    if( b_is_alloc )
    {
        pdev->params.mcast_config = mm_alloc_phys_mem(pdev,
                                                      alloc_size,
                                                      &pdev->params.mcast_config_phy,
                                                      0,
                                                      mm_cli_idx);
    }

    if CHK_NULL( pdev->params.mcast_config )
    {
        DbgBreakIf(DBG_BREAK_ON(MEMORY_ALLOCATION_FAILURE));
        return LM_STATUS_RESOURCE ;
    }
    mm_mem_zero((void *) (pdev->params.mcast_config), alloc_size);
#endif
    return LM_STATUS_SUCCESS;
}


lm_status_t lm_vf_chip_init(struct _lm_device_t *pdev)
{
    lm_status_t lm_status;

    DbgMessage(pdev, WARNvf, "lm_vf_chip_init\n");

    lm_status = lm_vf_pf_init_vf(pdev);
    if (lm_status == LM_STATUS_SUCCESS) {
        lm_status = lm_vf_pf_wait_no_messages_pending(pdev);
#if 0
"ACK_enable" (even "ACK_disable/ACK_enable") does not help when IGU block is stuck from previous VM shutdown/reboot (not ACKed sunbitted interrupt interrupt).
Windows8 PF executes clear IGU block on VM initialization. Must be checked for Linux PF.
        if (lm_status == LM_STATUS_SUCCESS) 
        {
            u8_t sb_id;
            u8_t igu_sb_cnt;

            igu_sb_cnt = LM_IGU_SB_CNT(pdev);
            for (sb_id = 0; sb_id < igu_sb_cnt; sb_id++)
            {
                /* Give Consumer updates with value '0' */
                lm_int_igu_ack_sb(pdev, IGU_VF_NDSB(pdev,sb_id), IGU_SEG_ACCESS_NORM, 0, IGU_INT_DISABLE, 0);
                lm_int_igu_ack_sb(pdev, IGU_VF_NDSB(pdev,sb_id), IGU_SEG_ACCESS_NORM, 0, IGU_INT_ENABLE, 1);
            }
        }
#endif        
    }


    /* Temporary FIXME TODO: is this the right location??? */
    pdev->vars.cable_is_attached = TRUE;
    pdev->vars.link_status = LM_STATUS_LINK_ACTIVE;
	if (IS_HW_CHANNEL_VIRT_MODE(pdev) && pdev->vars.pf_link_speed)
	{
        switch(pdev->vars.pf_link_speed)
        {
        case 10:
            SET_MEDIUM_SPEED(pdev->vars.medium, LM_MEDIUM_SPEED_10MBPS);
            break;

        case 100:
            SET_MEDIUM_SPEED(pdev->vars.medium, LM_MEDIUM_SPEED_100MBPS);
            break;

        case 1000:
            SET_MEDIUM_SPEED(pdev->vars.medium, LM_MEDIUM_SPEED_1000MBPS);
            break;

        case 2500:
            SET_MEDIUM_SPEED(pdev->vars.medium, LM_MEDIUM_SPEED_2500MBPS);
            break;

        case 20000:
            SET_MEDIUM_SPEED(pdev->vars.medium, LM_MEDIUM_SPEED_20GBPS);
            break;

		case 10000:
        default:
            SET_MEDIUM_SPEED(pdev->vars.medium, LM_MEDIUM_SPEED_10GBPS);
        break;
        }
	}
	else
	{
        SET_MEDIUM_SPEED(pdev->vars.medium,LM_MEDIUM_SPEED_10GBPS);
	}


    DbgMessage(pdev, WARNvf, "lm_vf_chip_init lm_status = %d\n", lm_status);
    return lm_status;
}

lm_status_t lm_vf_queue_init(struct _lm_device_t *pdev, u8_t cid)
{
    lm_status_t lm_status;
    u8_t validation_flag = 0;
    u8_t q_index = LM_SW_CID_TO_SW_QID(pdev,cid);

    if (IS_SW_CHANNEL_VIRT_MODE(pdev)) 
    {
        struct pf_vf_msg_acquire_resp * presp;
    presp = (struct pf_vf_msg_acquire_resp *)pdev->pf_vf_acquiring_resp;

    if (q_index < presp->resc.num_rxqs) {
        validation_flag |= RX_Q_VALIDATE;
    }

    if (q_index < presp->resc.num_txqs) {
        validation_flag |= TX_Q_VALIDATE;
    }
    }
    else if (IS_HW_CHANNEL_VIRT_MODE(pdev)) 
    {
        struct pfvf_acquire_resp_tlv * presp;
        presp = (struct pfvf_acquire_resp_tlv *)pdev->pf_vf_acquiring_resp;
        if (q_index < presp->resc.num_rxqs) {
            validation_flag |= RX_Q_VALIDATE;
        }

        if (q_index < presp->resc.num_txqs) {
            validation_flag |= TX_Q_VALIDATE;
        }
    }
    else
    {
        DbgBreak();
        return LM_STATUS_FAILURE;
    }

    DbgMessage(pdev, WARNvf, "validation_flag = %d\n", validation_flag);

    lm_status = lm_vf_pf_setup_q(pdev, q_index, validation_flag);
    if (lm_status == LM_STATUS_SUCCESS) {
        lm_status = lm_vf_pf_wait_no_messages_pending(pdev);
    }
    if (lm_status == LM_STATUS_SUCCESS) {
        lm_set_con_state(pdev, cid, LM_CON_STATE_OPEN);
    }
    return lm_status;

}

lm_status_t lm_vf_queue_close(struct _lm_device_t *pdev, u8_t cid)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    u8_t q_index = LM_SW_CID_TO_SW_QID(pdev,cid);

    if (lm_reset_is_inprogress(pdev)) {
        lm_set_con_state(pdev, cid, LM_CON_STATE_CLOSE);
        return LM_STATUS_SUCCESS;
    }

    if (lm_get_con_state(pdev, cid) == LM_CON_STATE_OPEN) {
        lm_status = lm_vf_pf_tear_q_down(pdev, q_index);
        if (lm_status == LM_STATUS_SUCCESS) {
            lm_status = lm_vf_pf_wait_no_messages_pending(pdev);
        } else {
            if (lm_status == LM_STATUS_REQUEST_NOT_ACCEPTED) {
               lm_status = LM_STATUS_SUCCESS;
            }
        }
            if (lm_status == LM_STATUS_SUCCESS) {
                lm_set_con_state(pdev, cid, LM_CON_STATE_CLOSE);
            }
        }
    return lm_status;
}

lm_status_t lm_vf_chip_reset(struct _lm_device_t *pdev, lm_reason_t reason)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;

    if (lm_reset_is_inprogress(pdev)) {
        return LM_STATUS_SUCCESS;
    }

    lm_status = lm_vf_pf_close_vf(pdev);
    if (lm_status == LM_STATUS_SUCCESS) {
        lm_status = lm_vf_pf_wait_no_messages_pending(pdev);
    }

    return lm_status;
}

u8_t lm_vf_is_function_after_flr(struct _lm_device_t * pdev)
{
    return FALSE;
}

lm_status_t lm_vf_init_dev_info(struct _lm_device_t *pdev)
{
    DbgMessage(pdev, WARN, "lm_vf_init_dev_info>>\n");
    // Cleaning after driver unload
    pdev->context_info = NULL;
    mm_mem_zero((void *) &pdev->cid_recycled_callbacks, sizeof(pdev->cid_recycled_callbacks));
    mm_mem_zero((void *) &pdev->toe_info, sizeof(pdev->toe_info));

    return LM_STATUS_SUCCESS;
}


lm_status_t lm_vf_recycle_resc_in_pf(struct _lm_device_t *pdev)
{
    DbgMessage(NULL, WARN, "lm_vf_recycle_resc_in_pf is used only in basic VF\n");
    return LM_STATUS_SUCCESS;
}


lm_status_t lm_vf_enable_vf(struct _lm_device_t *pdev)
{
    DbgMessage(NULL, WARN, "lm_vf_enable_vf is used only in basic VF\n");
    return LM_STATUS_SUCCESS;
}

lm_status_t lm_vf_enable_igu_int(struct _lm_device_t * pdev)
{
    return LM_STATUS_SUCCESS;
}


lm_status_t lm_vf_disable_igu_int(struct _lm_device_t * pdev)
{
    /* TODO?? */
    return LM_STATUS_SUCCESS;
}

pfvf_bb_event_type lm_vf_check_hw_back_channel(struct _lm_device_t * pdev)
{
    struct pf_vf_bulletin_content volatile *bulletin = (struct pf_vf_bulletin_content *)pdev->vars.vf_pf_mess.bulletin_virt_addr;
    u32_t attempts;

    if (bulletin == NULL) 
    {
         DbgMessage(pdev, FATAL, "PF to VF channel is not active\n");
         return PFVF_BB_CHANNEL_IS_NOT_ACTIVE;
    }
    if (pdev->vars.vf_pf_mess.old_version != bulletin->version)
    {
        for (attempts = 0; attempts < BULLETIN_ATTEMPTS; attempts++) 
        {
            if ((bulletin->length >= sizeof(bulletin->crc)) && (bulletin->length <= sizeof(union pf_vf_bulletin)) 
                    && (bulletin->crc == mm_crc32((u8_t*)bulletin + sizeof(bulletin->crc), bulletin->length - sizeof(bulletin->crc), BULLETIN_CRC_SEED)))
            break;
        }
        if (attempts == BULLETIN_ATTEMPTS)
        {
            DbgMessage(pdev, FATAL, "PF to VF channel: CRC error\n");
            return PFVF_BB_CHANNEL_CRC_ERR;
        }
        pdev->vars.vf_pf_mess.old_version = bulletin->version;
        if (bulletin->valid_bitmap & (1 << VLAN_VALID)) 
        {
            DbgMessage(pdev, FATAL, "PF to VF channel: PF provides VLAN\n");
        }
        if (bulletin->valid_bitmap & (1 << MAC_ADDR_VALID)) 
        {
            if ((bulletin->mac[0] != pdev->params.mac_addr[0])
                    || (bulletin->mac[1] != pdev->params.mac_addr[1])
                    || (bulletin->mac[2] != pdev->params.mac_addr[2])
                    || (bulletin->mac[3] != pdev->params.mac_addr[3])
                    || (bulletin->mac[4] != pdev->params.mac_addr[4])
                    || (bulletin->mac[5] != pdev->params.mac_addr[5])) 
            {
                DbgMessage(pdev, FATAL, "PF to VF channel: PF provides new MAC\n");
		return PFVF_BB_VALID_MAC;
            }
        }
    }
    return PFVF_BB_NO_UPDATE;    
}
lm_status_t lm_pf_enable_vf_igu_int(struct _lm_device_t * pdev, u8_t abs_vf_id)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    u32_t val;
    u16_t pretend_val;
    u8_t num_segs;
    u8_t prod_idx;
    u8_t sb_id;
    u8_t i;
    u8_t igu_sb_cnt;

    lm_vf_info_t * vf_info = lm_pf_find_vf_info_by_abs_id(pdev, abs_vf_id);


    /* Need to use pretend for VF */
    pretend_val = ABS_FUNC_ID(pdev) | (1<<3) | (abs_vf_id << 4);
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

    igu_sb_cnt = vf_info->num_allocated_chains; // pdev->hw_info.intr_blk_info.igu_info.vf_igu_info[abs_vf_id].igu_sb_cnt;
    num_segs = IGU_NORM_NDSB_NUM_SEGS;
    for (sb_id = 0; sb_id < igu_sb_cnt; sb_id++) {
        prod_idx = LM_VF_IGU_SB_ID(vf_info,sb_id)*num_segs; /* bc-assumption consecutive pfs, norm-no assumption */
        for (i = 0; i < num_segs;i++) {
            REG_WR(PFDEV(pdev), IGU_REG_PROD_CONS_MEMORY + (prod_idx + i)*4, 0);
        }
        SB_RX_INDEX(pdev,LM_VF_IGU_SB_ID(vf_info,sb_id)) = 0;
        lm_int_ack_sb_enable(pdev, LM_VF_IGU_SB_ID(vf_info,sb_id));        
        lm_pf_int_vf_igu_sb_cleanup(pdev, vf_info, sb_id);
    }

    lm_status = lm_pretend_func(PFDEV(pdev), ABS_FUNC_ID(pdev));
    return lm_status;
}

lm_status_t lm_pf_disable_vf_igu_int(struct _lm_device_t * pdev,  u8_t abs_vf_id)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    u32_t val;
    u16_t pretend_val;

    /* Need to use pretend for VF */
    if (lm_fl_reset_is_inprogress(PFDEV(pdev))) {
        DbgMessage(pdev, FATAL, "PF[%d] of VF[%d] is under FLR\n", FUNC_ID(pdev), abs_vf_id);
        return LM_STATUS_SUCCESS;
    }
    pretend_val = ABS_FUNC_ID(pdev) | (1<<3) | (abs_vf_id << 4);
    lm_pretend_func(PFDEV(pdev), pretend_val);

    val = REG_RD(PFDEV(pdev), IGU_REG_VF_CONFIGURATION);

    /* disable both bits, for INTA, MSI and MSI-X. */
    RESET_FLAGS(val, (IGU_VF_CONF_MSI_MSIX_EN | IGU_VF_CONF_SINGLE_ISR_EN | IGU_VF_CONF_FUNC_EN | IGU_VF_CONF_PARENT_MASK));

    REG_WR(PFDEV(pdev),  IGU_REG_VF_CONFIGURATION, val);

    lm_status = lm_pretend_func(PFDEV(pdev), ABS_FUNC_ID(pdev));
    return lm_status;
}

lm_status_t
lm_pf_enable_vf(struct _lm_device_t *pdev,   u8_t abs_vf_id)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    u16_t pretend_val;
    u32_t prod_idx;
    u8_t igu_sb_id;
    u32_t was_err_num;
    u32_t was_err_value;
    u32_t was_err_reg;
    u8_t    igu_sb_cnt;

    lm_vf_info_t * vf_info = lm_pf_find_vf_info_by_abs_id(pdev, abs_vf_id);

    /* Enable the VF in PXP - this will enable read/write from VF bar.
     * Need to use Pretend in order to do this. Note: once we do pretend
     * all accesses to SPLIT-68 will be done as if-vf...
     * Bits. Bits [13:10] - Reserved.  Bits [9:4] - VFID. Bits [3] - VF valid. Bits [2:0] - PFID.
     */

    pretend_val = ABS_FUNC_ID(pdev) | (1<<3) | (abs_vf_id << 4);
    lm_status = lm_pretend_func(PFDEV(pdev), pretend_val);
    if (lm_status == LM_STATUS_SUCCESS) {
        REG_WR(PFDEV(pdev), PBF_REG_DISABLE_VF,0);
        REG_WR(PFDEV(pdev), PGLUE_B_REG_INTERNAL_VFID_ENABLE, 1);
        lm_pretend_func(PFDEV(pdev), ABS_FUNC_ID(pdev) );
        DbgMessage(pdev, FATAL, "vf[%d] is enabled\n", abs_vf_id);

        was_err_num = 2 * PATH_ID(pdev) + abs_vf_id / 32;
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
            DbgMessage(pdev, FATAL,"Wrong Path[%d], VF[%d]\n",PATH_ID(pdev),abs_vf_id);
            DbgBreak();
        }

        was_err_value = 1 << (abs_vf_id % 32);
        if (was_err_reg) {
            REG_WR(PFDEV(pdev), was_err_reg, was_err_value); /* PglueB - Clear the was_error indication of the relevant function*/
        }

        /* IGU Initializations */
        igu_sb_cnt = vf_info->num_allocated_chains;
        for (igu_sb_id = 0; igu_sb_id < igu_sb_cnt; igu_sb_id++) {
            prod_idx = LM_VF_IGU_SB_ID(vf_info, igu_sb_id);
            REG_WR(PFDEV(pdev), IGU_REG_PROD_CONS_MEMORY + prod_idx*4, 0);
            DbgMessage(pdev, FATAL, "IGU[%d] is inialized\n", prod_idx);
        }
        REG_WR(PFDEV(pdev),TSEM_REG_VFPF_ERR_NUM, abs_vf_id);
        REG_WR(PFDEV(pdev),USEM_REG_VFPF_ERR_NUM, abs_vf_id);
        REG_WR(PFDEV(pdev),CSEM_REG_VFPF_ERR_NUM, abs_vf_id);
        REG_WR(PFDEV(pdev),XSEM_REG_VFPF_ERR_NUM, abs_vf_id);
    } else {
        DbgMessage(pdev, FATAL, "lm_pretend_func(%x) returns %d\n",pretend_val,lm_status);
        DbgMessage(pdev, FATAL, "vf[%d] is not enabled\n", abs_vf_id);
        DbgBreak();
    }

    return lm_status;
}

lm_status_t
lm_pf_disable_vf(struct _lm_device_t *pdev,   u8_t abs_vf_id)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    u16_t pretend_val;

    if (lm_pf_fl_vf_reset_is_inprogress(pdev,abs_vf_id)) {
        DbgMessage(pdev, FATAL, "vf disable called on a flred function - not much we can do here... \n");
        return LM_STATUS_SUCCESS;
    }
    pretend_val = ABS_FUNC_ID(pdev) | (1<<3) | (abs_vf_id << 4);
    lm_status = lm_pretend_func(PFDEV(pdev), pretend_val);
    if (lm_status == LM_STATUS_SUCCESS) {
        REG_WR(PFDEV(pdev), PBF_REG_DISABLE_VF,1);
        REG_WR(PFDEV(pdev), PGLUE_B_REG_INTERNAL_VFID_ENABLE, 0);
        lm_pretend_func(PFDEV(pdev), ABS_FUNC_ID(pdev) );
        DbgMessage(pdev, FATAL, "vf[%d] is disbled\n", abs_vf_id);
    } else {
        DbgMessage(pdev, FATAL, "lm_pretend_func(%x) returns %d\n",pretend_val,lm_status);
        DbgMessage(pdev, FATAL, "vf[%d] is not enabled\n", abs_vf_id);
    }

    return lm_status;
}

/*Master Channel Virt*/

lm_status_t lm_pf_create_vf(struct _lm_device_t *pdev, u16_t abs_vf_id, void* ctx)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    u8_t chains_resource_acquired;
    u8_t base_fw_stat_id;
    lm_vf_info_t * vf_info;
    u32_t   num_of_vf_avaiable_chains;
    u8_t    num_rxqs,num_txqs;

    DbgMessage(pdev, WARN, "lm_pf_create_vf(%d)\n",abs_vf_id);
    vf_info = lm_pf_find_vf_info_by_abs_id(pdev, (u8_t)abs_vf_id);
    if (!vf_info) {
        DbgBreakMsg("lm_pf_create_vf: vf_info is not found\n");
        return LM_STATUS_FAILURE;
    }
    lm_status = lm_pf_set_vf_ctx(pdev, vf_info->relative_vf_id, ctx);
    DbgBreakIf(lm_status != LM_STATUS_SUCCESS);

    DbgBreakIf(!vf_info);

    lm_pf_get_queues_number(pdev, vf_info, &num_rxqs, &num_txqs);
    num_of_vf_avaiable_chains = lm_pf_allocate_vf_igu_sbs(pdev, vf_info, num_rxqs);

    if (num_of_vf_avaiable_chains == 0)
    {
        return LM_STATUS_RESOURCE;
    }

    chains_resource_acquired = lm_pf_acquire_vf_chains_resources(pdev, vf_info->relative_vf_id, num_of_vf_avaiable_chains);

    if (!chains_resource_acquired) {
        DbgBreak();
        return LM_STATUS_RESOURCE;
    }


    if (vf_info != NULL) {
        base_fw_stat_id = 8 + vf_info->abs_vf_id;
        lm_status = lm_pf_set_vf_stat_id(pdev, vf_info->relative_vf_id, base_fw_stat_id);
        lm_pf_init_vf_slow_path(pdev, vf_info);
        lm_pf_init_vf_client(pdev, vf_info, 0);
#if 0
        lm_status = lm_set_rx_mask(pdev, vf_info->vf_chains[0].sw_client_id, LM_RX_MASK_ACCEPT_NONE, NULL);

        if (lm_status == LM_STATUS_PENDING)
        {
            /* Synchrounous complete */
            lm_status = lm_wait_set_rx_mask_done(pdev, vf_info->vf_chains[0].sw_client_id);
        }
#endif
        lm_status = lm_pf_enable_vf(pdev, vf_info->abs_vf_id);
    } else {
        lm_status = LM_STATUS_FAILURE;
    }

    return lm_status;
}

lm_status_t lm_pf_remove_vf(struct _lm_device_t *pdev, u16_t abs_vf_id)
{
    lm_status_t     lm_status = LM_STATUS_SUCCESS;
    u8_t            q_idx;
    u32_t           cid,client_info_idx, con_state;
    lm_vf_info_t *  vf_info = lm_pf_find_vf_info_by_abs_id(pdev, (u8_t)abs_vf_id);

    DbgMessage(pdev, WARN, "lm_pf_remove_vf(%d)\n",abs_vf_id);
    if (!vf_info) {
        DbgBreakMsg("lm_pf_remove_vf: vf_info is not found\n");
        return LM_STATUS_FAILURE;
    }
    if (lm_pf_fl_vf_reset_is_inprogress(pdev, (u8_t)abs_vf_id)) {
        MM_ACQUIRE_VFS_STATS_LOCK(pdev);
        if (vf_info->vf_stats.vf_stats_state != VF_STATS_REQ_IN_PROCESSING) {
            vf_info->vf_stats.vf_stats_state = VF_STATS_REQ_READY;
        }
        vf_info->vf_stats.stop_collect_stats = TRUE;
        vf_info->vf_stats.vf_stats_flag = 0;
        MM_RELEASE_VFS_STATS_LOCK(pdev);
        lm_status = lm_pf_vf_wait_for_stats_ready(pdev, vf_info);
        if (lm_status != LM_STATUS_SUCCESS) {
            DbgBreak();
        } else {
            vf_info->vf_stats.vf_stats_state = VF_STATS_NONE;
        }

        for (q_idx = 0; q_idx < vf_info->vf_si_num_of_active_q; q_idx++) {
            cid = LM_VF_Q_ID_TO_PF_CID(pdev, vf_info, q_idx);
            client_info_idx = LM_SW_VF_CLI_ID(vf_info, q_idx);
            con_state = lm_get_con_state(pdev, cid);
            if (con_state != LM_CON_STATE_CLOSE)
            {
                if (con_state != LM_CON_STATE_OPEN) {
                    DbgMessage(pdev, FATAL, "State of CID %d of VF[%d(rel)] is %d)\n",cid, vf_info->relative_vf_id,
                                con_state);
                    DbgBreak();
                } else {
                    lm_set_con_state(pdev, cid, LM_CON_STATE_HALT);
                    lm_status = lm_terminate_eth_con(pdev, cid);
                    DbgMessage(pdev, WARN, "lm_pf_remove_vf(%d): terminate CID %d (0x%x)\n",abs_vf_id,cid,lm_status);
                    if (lm_status != LM_STATUS_SUCCESS)
                    {
                        DbgBreak();
                        return lm_status;
                    }
                    lm_set_con_state(pdev, cid, LM_CON_STATE_CLOSE);
                }
            }
        }
        vf_info->vf_si_num_of_active_q = 0;
        lm_status = lm_pf_cleanup_vf_after_flr(pdev, vf_info);
    } else {
        lm_status = lm_pf_disable_vf(pdev,vf_info->abs_vf_id);
    }

    lm_pf_release_vf_chains_resources(pdev, vf_info->relative_vf_id);
    lm_status = lm_pf_set_vf_ctx(pdev, vf_info->relative_vf_id, NULL);
    DbgBreakIf(lm_status != LM_STATUS_SUCCESS);


    return lm_status;
}

lm_status_t lm_pf_cleanup_vf_after_flr(struct _lm_device_t *pdev, lm_vf_info_t *vf_info)
{
    lm_status_t lm_status  = LM_STATUS_SUCCESS;
    u32_t wait_ms          = 10000;
    u16_t pretend_value    = 0;
    u32_t factor           = 0;
    u32_t cleanup_complete = 0;

    u8_t  function_for_clean_up = 0;
    u8_t  idx                   = 0;

    struct sdm_op_gen final_cleanup;

    // TODO - use here pdev->vars.clk_factor
    if (CHIP_REV_IS_EMUL(pdev))
    {
            factor = LM_EMUL_FACTOR;
    }
    else if (CHIP_REV_IS_FPGA(pdev))
    {
            factor = LM_FPGA_FACTOR;
    }
    else
    {
            factor = 1;
    }

    wait_ms *= factor;
    pdev->flr_stats.default_wait_interval_ms = DEFAULT_WAIT_INTERVAL_MICSEC;
    DbgMessage(pdev, FATAL, "lm_cleanup_after_flr VF[%d] >>>\n",vf_info->abs_vf_id);

/*
VF FLR only part
a.  Wait until there are no pending ramrods for this VFid in the PF DB. - No pending VF's pending ramrod. It's based on "FLR not during driver load/unload".
What about set MAC?

b.  Send the new "L2 connection terminate" ramrod for each L2 CID that was used by the VF,
including sending the doorbell with the "terminate" flag. - Will be implemented in FW later

c.  Send CFC delete ramrod on all L2 connections of that VF (set the CDU-validation field to "invalid"). - part of FW cleanup. VF_TO_PF_CID must initialized in
PF CID array*/

/*  3.  Poll on the DQ per-function usage-counter until it's 0. */
    pretend_value = ABS_FUNC_ID(pdev) | (1<<3) | (vf_info->abs_vf_id << 4);
    lm_status = lm_pretend_func(PFDEV(pdev), pretend_value);
    if (lm_status == LM_STATUS_SUCCESS) {
        pdev->flr_stats.dq_usage_counter = REG_WAIT_VERIFY_VAL(PFDEV(pdev), DORQ_REG_VF_USAGE_CNT, 0, wait_ms);
        lm_pretend_func(PFDEV(pdev), ABS_FUNC_ID(pdev));
        DbgMessage(pdev, FATAL, "%d*%dms waiting for DQ per vf usage counter\n", pdev->flr_stats.dq_usage_counter, DEFAULT_WAIT_INTERVAL_MICSEC);
    } else {
        DbgMessage(pdev, FATAL,"lm_pretend_func(%x) returns %d\n",pretend_value,lm_status);
        DbgMessage(pdev, FATAL, "VF[%d]: could not read DORQ_REG_VF_USAGE_CNT\n", ABS_VFID(pdev));
        return lm_status;
    }

/*  4.  Activate the FW cleanup process by activating AggInt in the FW with GRC. Set the bit of the relevant function in the AggInt bitmask,
        to indicate to the FW which function is being cleaned. Wait for the per-function completion indication in the Cstorm RAM
*/
    function_for_clean_up = 8 + vf_info->abs_vf_id;
    cleanup_complete = 0xFFFFFFFF;
    LM_INTMEM_READ32(PFDEV(pdev),CSTORM_FINAL_CLEANUP_COMPLETE_OFFSET(function_for_clean_up),&cleanup_complete, BAR_CSTRORM_INTMEM);
    if (cleanup_complete) {
        DbgMessage(pdev, FATAL, "CSTORM_FINAL_CLEANUP_COMPLETE_OFFSET is %x",cleanup_complete);
        DbgBreak();
    }

    final_cleanup.command = (XSTORM_AGG_INT_FINAL_CLEANUP_INDEX << SDM_OP_GEN_COMP_PARAM_SHIFT) & SDM_OP_GEN_COMP_PARAM;
    final_cleanup.command |= (XSTORM_AGG_INT_FINAL_CLEANUP_COMP_TYPE << SDM_OP_GEN_COMP_TYPE_SHIFT) & SDM_OP_GEN_COMP_TYPE;
    final_cleanup.command |= 1 << SDM_OP_GEN_AGG_VECT_IDX_VALID_SHIFT;
    final_cleanup.command |= (function_for_clean_up << SDM_OP_GEN_AGG_VECT_IDX_SHIFT) & SDM_OP_GEN_AGG_VECT_IDX;

    DbgMessage(pdev, FATAL, "Final cleanup\n");
    REG_WR(PFDEV(pdev),XSDM_REG_OPERATION_GEN, final_cleanup.command);
    pdev->flr_stats.final_cleanup_complete = REG_WAIT_VERIFY_VAL(PFDEV(pdev), BAR_CSTRORM_INTMEM + CSTORM_FINAL_CLEANUP_COMPLETE_OFFSET(function_for_clean_up), 1, wait_ms);
    DbgMessage(pdev, FATAL, "%d*%dms waiting for final cleanup compete\n", pdev->flr_stats.final_cleanup_complete, DEFAULT_WAIT_INTERVAL_MICSEC);
    /* Lets cleanup for next FLR final-cleanup... */
    LM_INTMEM_WRITE32(PFDEV(pdev),CSTORM_FINAL_CLEANUP_COMPLETE_OFFSET(function_for_clean_up),0, BAR_CSTRORM_INTMEM);


/*  5.  ATC cleanup. This process will include the following steps (note that ATC will not be available for phase2 of the
        integration and the following should be added only in phase3):
    a.  Optionally, wait 2 ms. This is not a must. The driver can start polling (next steps) immediately,
        but take into account that it may take time till the done indications will be set.
    b.  Wait until INVALIDATION_DONE[function] = 1
    c.  Write-clear INVALIDATION_DONE[function] */


/*  6.  Verify PBF cleanup. Do the following for all PBF queues (queues 0,1,4, that will be indicated below with N):
    a.  Make sure PBF command-queue is flushed: Read pN_tq_occupancy. Let's say that the value is X.
        This number indicates the number of occupied transmission-queue lines.
        Poll on pN_tq_occupancy and pN_tq_lines_freed_cnt until one of the following:
            i.  pN_tq_occupancy is 0 (queue is empty). OR
            ii. pN_tq_lines_freed_cnt equals has advanced (cyclically) by X (all lines that were in the queue were processed). */

    for (idx = 0; idx < 3; idx++) {
        u32_t tq_to_free;
        u32_t tq_freed_cnt_start;
        u32_t tq_occ;
        u32_t tq_freed_cnt_last;
        u32_t pbf_reg_pN_tq_occupancy = 0;
        u32_t pbf_reg_pN_tq_lines_freed_cnt = 0;

        switch (idx) {
        case 0:
            pbf_reg_pN_tq_occupancy = (CHIP_IS_E3B0(pdev))? PBF_REG_TQ_OCCUPANCY_Q0 : PBF_REG_P0_TQ_OCCUPANCY;
            pbf_reg_pN_tq_lines_freed_cnt = (CHIP_IS_E3B0(pdev)) ? PBF_REG_TQ_LINES_FREED_CNT_Q0 : PBF_REG_P0_TQ_LINES_FREED_CNT;
            break;
        case 1:
            pbf_reg_pN_tq_occupancy = (CHIP_IS_E3B0(pdev)) ? PBF_REG_TQ_OCCUPANCY_Q1 : PBF_REG_P1_TQ_OCCUPANCY;
            pbf_reg_pN_tq_lines_freed_cnt = (CHIP_IS_E3B0(pdev)) ? PBF_REG_TQ_LINES_FREED_CNT_Q1 : PBF_REG_P1_TQ_LINES_FREED_CNT;
            break;
        case 2:
            pbf_reg_pN_tq_occupancy = (CHIP_IS_E3B0(pdev)) ? PBF_REG_TQ_OCCUPANCY_LB_Q : PBF_REG_P4_TQ_OCCUPANCY;
            pbf_reg_pN_tq_lines_freed_cnt = (CHIP_IS_E3B0(pdev)) ? PBF_REG_TQ_LINES_FREED_CNT_LB_Q : PBF_REG_P4_TQ_LINES_FREED_CNT;
            break;
        }
        pdev->flr_stats.pbf_queue[idx] = 0;
        tq_freed_cnt_last = tq_freed_cnt_start = REG_RD(PFDEV(pdev), pbf_reg_pN_tq_lines_freed_cnt);
        tq_occ = tq_to_free = REG_RD(PFDEV(pdev), pbf_reg_pN_tq_occupancy);
        DbgMessage(pdev, FATAL, "TQ_OCCUPANCY[%d]      : s:%x\n", (idx == 2) ? 4 : idx, tq_to_free);
        DbgMessage(pdev, FATAL, "TQ_LINES_FREED_CNT[%d]: s:%x\n", (idx == 2) ? 4 : idx, tq_freed_cnt_start);
        while(tq_occ && ((u32_t)S32_SUB(tq_freed_cnt_last, tq_freed_cnt_start) < tq_to_free)) {
            if (pdev->flr_stats.pbf_queue[idx]++ < wait_ms/DEFAULT_WAIT_INTERVAL_MICSEC) {
                mm_wait(PFDEV(pdev), DEFAULT_WAIT_INTERVAL_MICSEC);
                tq_occ = REG_RD(PFDEV(pdev), pbf_reg_pN_tq_occupancy);
                tq_freed_cnt_last = REG_RD(PFDEV(pdev), pbf_reg_pN_tq_lines_freed_cnt);
            } else {
                DbgMessage(pdev, FATAL, "TQ_OCCUPANCY[%d]      : c:%x\n", (idx == 2) ? 4 : idx, tq_occ);
                DbgMessage(pdev, FATAL, "TQ_LINES_FREED_CNT[%d]: c:%x\n", (idx == 2) ? 4 : idx, tq_freed_cnt_last);
                DbgBreak();
                break;
            }
        }
        DbgMessage(pdev, FATAL, "%d*%dms waiting for PBF command queue[%d] is flushed\n",
                    pdev->flr_stats.pbf_queue[idx], DEFAULT_WAIT_INTERVAL_MICSEC, (idx == 2) ? 4 : idx);
    }

/*  b.  Make sure PBF transmission buffer is flushed: read pN_init_crd once and keep it in variable Y.
        Read pN_credit and keep it in X. Poll on pN_credit and pN_internal_crd_freed until one of the following:
            i.  (Y - pN_credit) is 0 (transmission buffer is empty). OR
            ii. pN_internal_crd_freed_cnt has advanced (cyclically) by Y-X (all transmission buffer lines that were occupied were freed).*/

    for (idx = 0; idx < 3; idx++) {
        u32_t init_crd;
        u32_t credit_last,credit_start;
        u32_t inernal_freed_crd_start;
        u32_t inernal_freed_crd_last = 0;
        u32_t pbf_reg_pN_init_crd = 0;
        u32_t pbf_reg_pN_credit = 0;
        u32_t pbf_reg_pN_internal_crd_freed = 0;
        switch (idx) {
        case 0:
            pbf_reg_pN_init_crd = (CHIP_IS_E3B0(pdev)) ? PBF_REG_INIT_CRD_Q0 : PBF_REG_P0_INIT_CRD;
            pbf_reg_pN_credit = (CHIP_IS_E3B0(pdev)) ? PBF_REG_CREDIT_Q0 : PBF_REG_P0_CREDIT;
            pbf_reg_pN_internal_crd_freed = (CHIP_IS_E3B0(pdev)) ? PBF_REG_INTERNAL_CRD_FREED_CNT_Q0 : PBF_REG_P0_INTERNAL_CRD_FREED_CNT;
            break;
        case 1:
            pbf_reg_pN_init_crd = (CHIP_IS_E3B0(pdev)) ? PBF_REG_INIT_CRD_Q1: PBF_REG_P1_INIT_CRD;
            pbf_reg_pN_credit = (CHIP_IS_E3B0(pdev)) ? PBF_REG_CREDIT_Q1 : PBF_REG_P1_CREDIT;
            pbf_reg_pN_internal_crd_freed = (CHIP_IS_E3B0(pdev)) ? PBF_REG_INTERNAL_CRD_FREED_CNT_Q1 : PBF_REG_P1_INTERNAL_CRD_FREED_CNT;
            break;
        case 2:
            pbf_reg_pN_init_crd = (CHIP_IS_E3B0(pdev)) ? PBF_REG_INIT_CRD_LB_Q : PBF_REG_P4_INIT_CRD;
            pbf_reg_pN_credit = (CHIP_IS_E3B0(pdev)) ? PBF_REG_CREDIT_LB_Q : PBF_REG_P4_CREDIT;
            pbf_reg_pN_internal_crd_freed = (CHIP_IS_E3B0(pdev)) ? PBF_REG_INTERNAL_CRD_FREED_CNT_LB_Q : PBF_REG_P4_INTERNAL_CRD_FREED_CNT;
            break;
        }
        pdev->flr_stats.pbf_transmit_buffer[idx] = 0;
        inernal_freed_crd_last = inernal_freed_crd_start = REG_RD(PFDEV(pdev), pbf_reg_pN_internal_crd_freed);
        credit_last = credit_start = REG_RD(PFDEV(pdev), pbf_reg_pN_credit);
        init_crd = REG_RD(PFDEV(pdev), pbf_reg_pN_init_crd);
        DbgMessage(pdev, FATAL, "INIT CREDIT[%d]       : %x\n", (idx == 2) ? 4 : idx, init_crd);
        DbgMessage(pdev, FATAL, "CREDIT[%d]            : s:%x\n", (idx == 2) ? 4 : idx, credit_start);
        DbgMessage(pdev, FATAL, "INTERNAL_CRD_FREED[%d]: s:%x\n", (idx == 2) ? 4 : idx, inernal_freed_crd_start);
        while ((credit_last != init_crd)
               && (u32_t)S32_SUB(inernal_freed_crd_last, inernal_freed_crd_start) < (init_crd - credit_start)) {
            if (pdev->flr_stats.pbf_transmit_buffer[idx]++ < wait_ms/DEFAULT_WAIT_INTERVAL_MICSEC) {
                mm_wait(PFDEV(pdev), DEFAULT_WAIT_INTERVAL_MICSEC);
                credit_last = REG_RD(PFDEV(pdev), pbf_reg_pN_credit);
                inernal_freed_crd_last = REG_RD(PFDEV(pdev), pbf_reg_pN_internal_crd_freed);
            } else {
                DbgMessage(pdev, FATAL, "CREDIT[%d]            : c:%x\n", (idx == 2) ? 4 : idx, credit_last);
                DbgMessage(pdev, FATAL, "INTERNAL_CRD_FREED[%d]: c:%x\n", (idx == 2) ? 4 : idx, inernal_freed_crd_last);
                DbgBreak();
                break;
            }
        }
        DbgMessage(pdev, FATAL, "%d*%dms waiting for PBF transmission buffer[%d] is flushed\n",
                    pdev->flr_stats.pbf_transmit_buffer[idx], DEFAULT_WAIT_INTERVAL_MICSEC, (idx == 2) ? 4 : idx);
    }

/*  7.  Wait for 100ms in order to make sure that the chip is clean, including all PCI related paths
        (in Emulation the driver can wait for 10ms*EmulationFactor, i.e.: 20s). This is especially required if FW doesn't implement
        the flows in Optional Operations (future enhancements).) */
    mm_wait(pdev, 10000*factor);

/*  9.  Initialize the function as usual this should include also re-enabling the function in all the HW blocks and Storms that
    were disabled by the MCP and cleaning relevant per-function information in the chip (internal RAM related information, IGU memory etc.).
        a.  In case of VF, PF resources that were allocated for previous VF can be re-used by the new VF. If there are resources
            that are not needed by the new VF then they should be cleared.
        b.  Note that as long as slow-path prod/cons update to Xstorm is not atomic, they must be cleared by the driver before setting
            the function to "enable" in the Xstorm.
        c.  Don't forget to enable the VF in the PXP or the DMA operation for PF in the PXP. */


    if (IS_VFDEV(pdev))
    {
#ifdef VF_INVOLVED
        lm_set_con_state(pdev, LM_VF_Q_ID_TO_PF_CID(pdev, vf_info,0), LM_CON_STATE_CLOSE);
#endif
    }

    vf_info->was_flred = FALSE;

    return lm_status;
}

void lm_pf_fl_vf_reset_set_inprogress(struct _lm_device_t * pdev, u8_t abs_vf_id)
{
    lm_vf_info_t * vf_info = lm_pf_find_vf_info_by_abs_id(pdev, (u8_t)abs_vf_id);

    DbgMessage(pdev, WARN, "lm_pf_fl_vf_reset_set_inprogress(%d)\n",abs_vf_id);
    if (!vf_info) {
        DbgBreakMsg("lm_pf_fl_vf_reset_set_inprogress: vf_info is not found\n");
        return;
    } else {
        vf_info->was_flred = TRUE;
    }
}

void lm_pf_fl_vf_reset_clear_inprogress(struct _lm_device_t *pdev, u8_t abs_vf_id)
{
    lm_vf_info_t * vf_info = lm_pf_find_vf_info_by_abs_id(pdev, (u8_t)abs_vf_id);

    DbgMessage(pdev, WARN, "lm_pf_fl_vf_reset_clear_inprogress(%d)\n",abs_vf_id);
    if (!vf_info) {
        DbgBreakMsg("lm_pf_fl_vf_reset_clear_inprogress: vf_info is not found\n");
        return;
    } else {
        vf_info->was_flred = FALSE;
    }
}

u8_t lm_pf_fl_vf_reset_is_inprogress(struct _lm_device_t *pdev, u8_t abs_vf_id)
{
    lm_vf_info_t * vf_info = lm_pf_find_vf_info_by_abs_id(pdev, (u8_t)abs_vf_id);

    DbgMessage(pdev, WARN, "lm_pf_fl_vf_reset_clear_inprogress(%d)\n",abs_vf_id);
    if (!vf_info) {
        DbgBreakMsg("lm_pf_fl_vf_reset_is_inprogress: vf_info is not found\n");
        return FALSE;
    } else {
        return vf_info->was_flred;
    }
}

lm_status_t lm_pf_finally_release_vf(struct _lm_device_t *pdev, lm_vf_info_t *vf_info)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    u8_t function_fw_id;
    u8_t sb_idx;
    u8_t q_idx;
    u32_t cid;

    DbgBreakIf(!(pdev && vf_info));
    if (vf_info->vf_si_state == PF_SI_VF_INITIALIZED) {
        DbgMessage(pdev, WARN, "VF[%d%d)] is not closed yet\n", vf_info->relative_vf_id, vf_info->abs_vf_id);
        MM_ACQUIRE_VFS_STATS_LOCK(pdev);
        if (vf_info->vf_stats.vf_stats_state != VF_STATS_REQ_IN_PROCESSING) {
            vf_info->vf_stats.vf_stats_state = VF_STATS_REQ_READY;
        }
        vf_info->vf_stats.stop_collect_stats = TRUE;
        vf_info->vf_stats.vf_stats_flag = 0;
        MM_RELEASE_VFS_STATS_LOCK(pdev);

        lm_status = lm_pf_vf_wait_for_stats_ready(pdev, vf_info);
        if (lm_status != LM_STATUS_SUCCESS) {
            DbgBreak();
        } else {
            vf_info->vf_stats.vf_stats_state = VF_STATS_NONE;
        }

        for (q_idx = 0; q_idx < vf_info->vf_si_num_of_active_q; q_idx++) {
            cid = LM_VF_Q_ID_TO_PF_CID(pdev, vf_info, q_idx);
            if (vf_info->was_malicious || vf_info->was_flred)
            {
                lm_set_con_state(pdev, cid, LM_CON_STATE_CLOSE);
            }
            else
            {
                lm_status = lm_close_eth_con(pdev, cid, TRUE);
            }
        }
        vf_info->vf_si_num_of_active_q = 0;

//        if (!(vf_info->was_malicious || vf_info->was_flred))
        {
            lm_pf_disable_vf_igu_int(pdev, vf_info->abs_vf_id);
            /*
            Disable the function in STORMs
            */
            function_fw_id = 8 + vf_info->abs_vf_id;

            LM_INTMEM_WRITE8(PFDEV(pdev), XSTORM_FUNC_EN_OFFSET(function_fw_id), 0, BAR_XSTRORM_INTMEM);
            LM_INTMEM_WRITE8(PFDEV(pdev), CSTORM_FUNC_EN_OFFSET(function_fw_id), 0, BAR_CSTRORM_INTMEM);
            LM_INTMEM_WRITE8(PFDEV(pdev), TSTORM_FUNC_EN_OFFSET(function_fw_id), 0, BAR_TSTRORM_INTMEM);
            LM_INTMEM_WRITE8(PFDEV(pdev), USTORM_FUNC_EN_OFFSET(function_fw_id), 0, BAR_USTRORM_INTMEM);

            for (sb_idx = 0; sb_idx < vf_info->num_sbs; sb_idx++) {
                lm_clear_non_def_status_block(pdev,  LM_FW_VF_SB_ID(vf_info, sb_idx));
            }

            for (q_idx = 0; q_idx < vf_info->num_rxqs; q_idx++) {
                u32_t reg = PXP_REG_HST_ZONE_PERMISSION_TABLE + LM_FW_VF_QZONE_ID(vf_info,q_idx) * 4;
                u32_t val = 0;
                REG_WR(PFDEV(pdev), reg, val);
            }
        }
        vf_info->vf_si_state = PF_SI_ACQUIRED;
    }

    if (vf_info->vf_si_state == PF_SI_ACQUIRED) {
        DbgMessage(pdev, WARN, "VF[%d%d)] is not released yet\n", vf_info->relative_vf_id, vf_info->abs_vf_id);
        vf_info->vf_si_state = PF_SI_WAIT_FOR_ACQUIRING_REQUEST;
    }
    return lm_status;
}

lm_status_t lm_pf_tpa_send_vf_ramrod(struct _lm_device_t *pdev, lm_vf_info_t *vf_info, u32_t q_idx, u8_t update_ipv4, u8_t update_ipv6)
{
    // Add ramrod send code
    lm_vf_chain_info_t*     tpa_chain = &vf_info->vf_chains[q_idx];
    lm_status_t             lm_status = LM_STATUS_SUCCESS;
    lm_address_t            q_addr;
    u32_t                   vf_cid_of_pf = 0;
    u16_t                   type = 0;

    if((CHK_NULL(tpa_chain->tpa_ramrod_data_virt)))
    {
        DbgBreakMsg("lm_tpa_send_ramrod : invalid paramters");
        return LM_STATUS_FAILURE;
    }

    tpa_chain->tpa_ramrod_data_virt->update_ipv4 = update_ipv4;
    tpa_chain->tpa_ramrod_data_virt->update_ipv6 = update_ipv6;

    tpa_chain->tpa_ramrod_data_virt->client_id     = LM_FW_VF_CLI_ID(vf_info, q_idx);
    /* maximal TPA queues allowed for this client */
    tpa_chain->tpa_ramrod_data_virt->max_tpa_queues        = LM_TPA_MAX_AGGS;
    /* The maximal number of SGEs that can be used for one packet. depends on MTU and SGE size. must be 0 if SGEs are disabled */
    tpa_chain->tpa_ramrod_data_virt->max_sges_for_packet   = DIV_ROUND_UP_BITS(tpa_chain->mtu, LM_TPA_PAGE_BITS);
    /* Size of the buffers pointed by SGEs */
    ASSERT_STATIC(LM_TPA_PAGE_SIZE < MAX_VARIABLE_VALUE(tpa_chain->tpa_ramrod_data_virt->sge_buff_size));
    tpa_chain->tpa_ramrod_data_virt->sge_buff_size         = mm_cpu_to_le16(LM_TPA_PAGE_SIZE);
    /* maximal size for the aggregated TPA packets, reprted by the host */
    ASSERT_STATIC((LM_TPA_MAX_AGG_SIZE * LM_TPA_PAGE_SIZE) < MAX_VARIABLE_VALUE(tpa_chain->tpa_ramrod_data_virt->max_agg_size));
    tpa_chain->tpa_ramrod_data_virt->max_agg_size          = mm_cpu_to_le16(LM_TPA_MAX_AGG_SIZE * LM_TPA_PAGE_SIZE);

    q_addr.as_u64 = tpa_chain->sge_addr;
    //u32_t sge_page_base_lo /* The address to fetch the next sges from (low) */;
    tpa_chain->tpa_ramrod_data_virt->sge_page_base_lo      = mm_cpu_to_le32(q_addr.as_u32.low);
    //u32_t sge_page_base_hi /* The address to fetch the next sges from (high) */;
    tpa_chain->tpa_ramrod_data_virt->sge_page_base_hi      = mm_cpu_to_le32(q_addr.as_u32.high);
    //u16_t sge_pause_thr_low /* number of remaining sges under which, we send pause message */;
    tpa_chain->tpa_ramrod_data_virt->sge_pause_thr_low     = mm_cpu_to_le16(LM_TPA_SGE_PAUSE_THR_LOW);
    //u16_t sge_pause_thr_high /* number of remaining sges above which, we send un-pause message */;
    tpa_chain->tpa_ramrod_data_virt->sge_pause_thr_high    = mm_cpu_to_le16(LM_TPA_SGE_PAUSE_THR_HIGH);

    vf_cid_of_pf = LM_VF_Q_ID_TO_PF_CID(pdev, vf_info, q_idx);
    type = (ETH_CONNECTION_TYPE | ((8 + vf_info->abs_vf_id) << SPE_HDR_T_FUNCTION_ID_SHIFT));

    tpa_chain->tpa_ramrod_data_virt->complete_on_both_clients = TRUE;

    lm_status = lm_sq_post(pdev,
                           vf_cid_of_pf,
                           RAMROD_CMD_ID_ETH_TPA_UPDATE,
                           CMD_PRIORITY_MEDIUM,
                           type,
                           *(u64_t *)&(tpa_chain->tpa_ramrod_data_phys));

    DbgBreakIf(lm_status != LM_STATUS_SUCCESS);

    return lm_status;
}

u8_t lm_is_vf_rsc_supported(struct _lm_device_t *pdev)
{
    u8_t is_rsc_supported = TRUE;
    if (IS_VFDEV(pdev)) {
        if (IS_SW_CHANNEL_VIRT_MODE(pdev)) 
        {
            struct pf_vf_msg_acquire_resp * presp = (struct pf_vf_msg_acquire_resp *)pdev->pf_vf_acquiring_resp;
            if (!(presp->pfdev_info.pf_cap & PFVF_CAP_TPA)) {
                is_rsc_supported = FALSE;
            }
        }
        else if (IS_HW_CHANNEL_VIRT_MODE(pdev)) 
        {
            struct pfvf_acquire_resp_tlv * presp;
            presp = (struct pfvf_acquire_resp_tlv *)pdev->pf_vf_acquiring_resp;
            if (!(presp->pfdev_info.pf_cap & PFVF_CAP_TPA_UPDATE)) {
                is_rsc_supported = FALSE;
            }
        }
        else
        {
            DbgBreak();
        }
    }
    return is_rsc_supported;
}

void lm_pf_init_vf_filters(struct _lm_device_t *pdev, lm_vf_info_t *vf_info)
{
    if ((vf_info == NULL) || (pdev == NULL))
    {
        DbgBreakMsg("lm_pf_init_vf_filters : invalid paramters");
    }
    else
    {
        vf_info->is_promiscuous_mode_restricted = (pdev->params.vf_promiscuous_mode_restricted != 0);
    }
    return;
}

void lm_pf_allow_vf_promiscuous_mode(lm_vf_info_t *vf_info, u8_t is_allowed)
{
    if (vf_info == NULL)
    {
        DbgBreakMsg("lm_pf_allow_vf_promiscuous_mode : invalid paramters");
    }
    else
    {
        vf_info->is_promiscuous_mode_restricted = !is_allowed;
    }
    return;
}

void lm_pf_int_vf_igu_sb_cleanup(lm_device_t *pdev, lm_vf_info_t *vf_info, u8_t vf_chain_id)
{
    struct igu_regular  cmd_data = {0};
    struct igu_ctrl_reg cmd_ctrl = {0};
    u32_t igu_addr_ack           = 0;
    u32_t sb_bit                 = 0;
    u32_t cnt                    = 100;
    u8_t  igu_sb_id              = 0;
#ifdef _VBD_CMD_
    return;
#endif

    /* Not supported in backward compatible mode! */
    if (INTR_BLK_MODE(pdev) == INTR_BLK_MODE_BC)
    {
        return;
    }

    if ((vf_info == NULL) || (pdev == NULL))
    {
        DbgBreakMsg("lm_pf_int_vf_igu_sb_cleanup : invalid paramters");
        return; 
    }
    
    if (IS_VFDEV(pdev)) 
    {
        DbgBreakMsg("lm_pf_int_vf_igu_sb_cleanup : only available on Host/PF side");
        return; 
    }

    igu_sb_id = LM_VF_IGU_SB_ID(vf_info,vf_chain_id);
    igu_addr_ack = IGU_REG_CSTORM_TYPE_0_SB_CLEANUP + (igu_sb_id/32)*4;
    sb_bit =  1 << (igu_sb_id%32);
    
    /* Cleanup can be done only via GRC access using the producer update command */
    cmd_data.sb_id_and_flags =
        ((IGU_USE_REGISTER_cstorm_type_0_sb_cleanup << IGU_REGULAR_CLEANUP_TYPE_SHIFT) |
          IGU_REGULAR_CLEANUP_SET |
          IGU_REGULAR_BCLEANUP);

    cmd_ctrl.ctrl_data =
        (((IGU_CMD_E2_PROD_UPD_BASE + igu_sb_id) << IGU_CTRL_REG_ADDRESS_SHIFT) |
         (vf_info->abs_vf_id << IGU_CTRL_REG_FID_SHIFT) |
         (IGU_CTRL_CMD_TYPE_WR << IGU_CTRL_REG_TYPE_SHIFT));

    REG_WR(pdev, IGU_REG_COMMAND_REG_32LSB_DATA, cmd_data.sb_id_and_flags);
    REG_WR(pdev, IGU_REG_COMMAND_REG_CTRL, cmd_ctrl.ctrl_data);

    /* wait for clean up to finish */
    while (!(REG_RD(pdev, igu_addr_ack) & sb_bit) && --cnt)
    {
        mm_wait(pdev, 10);
    }

    if (!(REG_RD(pdev, igu_addr_ack) & sb_bit))
    {
        DbgMessage(pdev, FATAL, "Unable to finish IGU cleanup - set: igu_sb_id %d offset %d bit %d (cnt %d)\n",
                    igu_sb_id, igu_sb_id/32, igu_sb_id%32, cnt);
    }

    /* Now we clear the cleanup-bit... same command without cleanup_set... */
    cmd_data.sb_id_and_flags =
        ((IGU_USE_REGISTER_cstorm_type_0_sb_cleanup << IGU_REGULAR_CLEANUP_TYPE_SHIFT) |
          IGU_REGULAR_BCLEANUP);


    REG_WR(pdev, IGU_REG_COMMAND_REG_32LSB_DATA, cmd_data.sb_id_and_flags);
    REG_WR(pdev, IGU_REG_COMMAND_REG_CTRL, cmd_ctrl.ctrl_data);

    /* wait for clean up to finish */
    while ((REG_RD(pdev, igu_addr_ack) & sb_bit) && --cnt)
    {
        mm_wait(pdev, 10);
    }

    if ((REG_RD(pdev, igu_addr_ack) & sb_bit))
    {
        DbgMessage(pdev, FATAL, "Unable to finish IGU cleanup - clear: igu_sb_id %d offset %d bit %d (cnt %d)\n",
                    igu_sb_id, igu_sb_id/32, igu_sb_id%32, cnt);
    }
}

#endif
/* */
