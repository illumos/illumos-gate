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
 *      This file contains the implementation of slow-path operations
 *      for L2 + Common. It uses ecore_sp_verbs in most cases.
 *
 ******************************************************************************/

#include "lm5710.h"

#if !defined(__LINUX) && !defined(__SunOS)
// disable warning C4127 (conditional expression is constant)
// for this file (relevant when compiling with W4 warning level)
#pragma warning( disable : 4127 )
#endif /* __LINUX */

#if !defined(__LINUX) && !defined(__SunOS)
#pragma warning( default : 4127 )
#endif

#include "mm.h"
#include "context.h"
#include "command.h"
#include "bd_chain.h"
#include "ecore_common.h"
#include "ecore_sp_verbs.h"
#include "debug.h"

typedef enum _ecore_status_t ecore_status_t;



lm_status_t
lm_empty_ramrod_eth(IN struct _lm_device_t *pdev,
                    IN const u32_t          cid,
                    IN u32_t                data_cid,
                    IN volatile u32_t       *curr_state,
                    IN u32_t                new_state)
{
    union eth_specific_data ramrod_data = {{0}};
    lm_status_t             lm_status   = LM_STATUS_SUCCESS;

    DbgMessage(pdev, INFORMi|INFORMl2sp, "#lm_empty_ramrod_eth_conn, curr_state=%d\n",curr_state);

    ASSERT_STATIC(sizeof(ramrod_data) == sizeof(u64_t));

    //Prepare ramrod data
    ramrod_data.update_data_addr.lo = data_cid;
    ramrod_data.update_data_addr.hi = 0 ;

    // Send Empty ramrod.
    lm_status = lm_sq_post(pdev,
                           cid,
                           RAMROD_CMD_ID_ETH_EMPTY,
                           CMD_PRIORITY_MEDIUM,
                           ETH_CONNECTION_TYPE,
                           *(u64_t *)&ramrod_data );

    if (lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    /* curr_state may be NULL incase wait isn't required */
    if (curr_state != NULL)
    {
        lm_status = lm_wait_state_change(pdev,
                                         curr_state,
                                         new_state);

        if ((lm_status != LM_STATUS_SUCCESS) && (lm_status != LM_STATUS_ABORTED))
        {
            DbgBreakMsg("lm_empty_ramrod_eth: lm_wait_state_change failed");
        }
    }



    return lm_status;
} /* lm_empty_ramrod_eth */



static lm_status_t lm_ecore_status_to_lm_status( const ecore_status_t ecore_status )
{
    lm_status_t lm_status = LM_STATUS_FAILURE;

    switch (ecore_status)
    {
    case ECORE_SUCCESS:
        lm_status = LM_STATUS_SUCCESS;
        break;

    case ECORE_TIMEOUT:
        lm_status = LM_STATUS_TIMEOUT;
        break;

    case ECORE_INVAL:
       lm_status = LM_STATUS_INVALID_PARAMETER;
       break;

    case ECORE_BUSY:
        lm_status = LM_STATUS_BUSY;
        break;

    case ECORE_NOMEM:
        lm_status = LM_STATUS_RESOURCE;
        break;

    case ECORE_PENDING:
        lm_status = LM_STATUS_PENDING;
        break;

    case ECORE_EXISTS:
        lm_status = LM_STATUS_EXISTING_OBJECT;
        break;

    case ECORE_IO:
        lm_status = LM_STATUS_FAILURE;
        break;

    default:
        DbgBreakMsg("Unknwon ecore_status_t");
        break;
    }

    return lm_status;
}

u8_t lm_is_eq_completion(lm_device_t *pdev)
{
    lm_eq_chain_t * eq_chain = NULL;
    u8_t            result   = FALSE;

    DbgBreakIf(!pdev);
    if (!pdev || IS_VFDEV(pdev))
    {
        return FALSE;
    }

    eq_chain = &pdev->eq_info.eq_chain;
    if ( eq_chain->hw_con_idx_ptr && (mm_le16_to_cpu(*eq_chain->hw_con_idx_ptr) != lm_bd_chain_cons_idx(&eq_chain->bd_chain)))
    {
        result = TRUE;
    }

    DbgMessage(pdev, INFORMeq, "lm_is_eq_completion: result is:%s\n", result? "TRUE" : "FALSE");

    return result;
}

STATIC lm_status_t
lm_eth_init_client_init_general_data(IN         lm_device_t                     *pdev,
                                     OUT        struct client_init_general_data *general,
                                     IN const   u8_t                            cid)
{
    const u8_t  stats_cnt_id  = LM_STATS_CNT_ID(pdev);
    const u8_t  is_pfdev      = IS_PFDEV(pdev);
    const u8_t  reg_cid        = (u8_t)lm_mp_get_reg_chain_from_chain(pdev,cid);
    const u8_t  cos            = lm_mp_cos_from_chain(pdev, cid);
    const u8_t  traffic_type  = LM_CHAIN_IDX_TRAFFIC_TYPE(pdev, cid);
    lm_status_t lm_status     = LM_STATUS_SUCCESS;

    if( LLFC_DRIVER_TRAFFIC_TYPE_MAX == traffic_type)
    {
        DbgBreakMsg("lm_eth_init_client_init_general_data failed ");
        return LM_STATUS_FAILURE;
    }

    /* General Structure */
    general->activate_flg          = 1;
    general->client_id             = LM_FW_CLI_ID(pdev, reg_cid);
    general->is_fcoe_flg           = (cid == FCOE_CID(pdev))? TRUE : FALSE;
    general->statistics_en_flg     = (is_pfdev || (stats_cnt_id != 0xFF))? TRUE : FALSE;
    general->statistics_counter_id = (general->statistics_en_flg)? stats_cnt_id : DISABLE_STATISTIC_COUNTER_ID_VALUE;
    general->sp_client_id          = LM_FW_CLI_ID(pdev, reg_cid);
    general->mtu                   = mm_cpu_to_le16((u16_t)pdev->params.l2_cli_con_params[cid].mtu);
    general->func_id               = FUNC_ID(pdev); /* FIXME: VFID needs to be given here for VFs... */
    // Don't care data for Non cos clients
    if(lm_chain_type_not_cos == lm_mp_get_chain_type(pdev,cid))
    {
        // FW requires a valid COS number
        general->cos                   = 0;
    }
    else
    {
        general->cos                   = cos;//The connection cos, if applicable only if STATIC_COS is set
    }
    general->traffic_type          = traffic_type;

    /* TODO: using path_has_ovlan for finding if it is UFP/BD mode or not is correct?
     * does this needs to be done even in lm_vf.c lm_vf_pf_acquire_msg
     * function? Also how do we handle the check in lm_pf_vf_check_compatibility
     */
    if(IS_MF_SD_MODE(pdev) && (IS_SD_UFP_MODE(pdev) || IS_SD_BD_MODE(pdev)) && general->is_fcoe_flg)
        general->fp_hsi_ver            = ETH_FP_HSI_VER_2;
    else
        general->fp_hsi_ver            = ETH_FP_HSI_VER_1; // default is v1 since only when conditions above are true HSI is v2

    return lm_status;
}

STATIC void
lm_eth_init_client_init_rx_data(IN          lm_device_t                 *pdev,
                                OUT         struct client_init_rx_data  *rx,
                                IN const    u8_t                        cid,
                                IN const    u8_t                        sb_id)
{
    lm_bd_chain_t * rx_chain_sge  = NULL;
    lm_bd_chain_t * rx_chain_bd   = NULL;
    u8_t            rel_cid       = 0;

    DbgBreakIf(cid == FWD_CID(pdev));

    rx_chain_sge = LM_RXQ_SGE_PTR_IF_VALID(pdev, cid);
    rx_chain_bd  = &LM_RXQ_CHAIN_BD(pdev, cid);

    rx->status_block_id               = LM_FW_SB_ID(pdev, sb_id);
    // TPA is enabled in run time.(TPA is disabled in init time)
    rx->tpa_en                        = 0;
    rx->max_agg_size                  = mm_cpu_to_le16(0); /* TPA related only  */;
    rx->max_tpa_queues                = 0;

    rx->extra_data_over_sgl_en_flg    = (cid == OOO_CID(pdev))? TRUE : FALSE;
    rx->cache_line_alignment_log_size = (u8_t)LOG2(CACHE_LINE_SIZE/* TODO mm_get_cache_line_alignment()*/);
    rx->enable_dynamic_hc             = (u8_t)pdev->params.enable_dynamic_hc[HC_INDEX_ETH_RX_CQ_CONS];

    rx->outer_vlan_removal_enable_flg = IS_MULTI_VNIC(pdev)? TRUE: FALSE;
    if(OOO_CID(pdev) == cid)
    {
        rx->inner_vlan_removal_enable_flg = 0;
    }
    else
    {
        rx->inner_vlan_removal_enable_flg = !pdev->params.keep_vlan_tag;

        if(IS_MF_AFEX_MODE(pdev))
        {
            // In NIV we must remove default VLAN.
            rx->silent_vlan_removal_flg         = 1;
            rx->silent_vlan_value               = mm_cpu_to_le16(NIV_DEFAULT_VLAN(pdev));
            rx->silent_vlan_mask                = mm_cpu_to_le16(ETHERNET_VLAN_ID_MASK);
        }

    }

    rx->bd_page_base.lo= mm_cpu_to_le32(lm_bd_chain_phys_addr(rx_chain_bd, 0).as_u32.low);
    rx->bd_page_base.hi= mm_cpu_to_le32(lm_bd_chain_phys_addr(rx_chain_bd, 0).as_u32.high);

    rx->cqe_page_base.lo = mm_cpu_to_le32(lm_bd_chain_phys_addr(&pdev->rx_info.rcq_chain[cid].bd_chain, 0).as_u32.low);
    rx->cqe_page_base.hi = mm_cpu_to_le32(lm_bd_chain_phys_addr(&pdev->rx_info.rcq_chain[cid].bd_chain, 0).as_u32.high);


    if (cid == LM_SW_LEADING_RSS_CID(pdev))
    {
        /* TODO: for now... doesn't have to be leading cid, anyone can get the approx mcast... */
        rx->is_leading_rss = TRUE;
        rx->is_approx_mcast = TRUE;
    }

    rx->approx_mcast_engine_id = FUNC_ID(pdev); /* FIMXE (MichalS) */
    rx->rss_engine_id          = FUNC_ID(pdev); /* FIMXE (MichalS) */

    if(rx_chain_sge)
    {
        /* override bd_buff_size if we are in LAH enabled mode */
        rx->max_bytes_on_bd     = mm_cpu_to_le16((u16_t)pdev->params.l2_cli_con_params[cid].lah_size);
        rx->vmqueue_mode_en_flg = TRUE;
        rx->max_sges_for_packet = LM_MAX_SGES_FOR_PACKET;
        rx->sge_buff_size       = mm_cpu_to_le16(MAX_L2_CLI_BUFFER_SIZE(pdev, cid) - (u16_t)pdev->params.l2_cli_con_params[cid].lah_size - (u16_t)pdev->params.rcv_buffer_offset - CACHE_LINE_SIZE);

        rx->sge_page_base.hi    = mm_cpu_to_le32(lm_bd_chain_phys_addr(rx_chain_sge, 0).as_u32.high);
        rx->sge_page_base.lo    = mm_cpu_to_le32(lm_bd_chain_phys_addr(rx_chain_sge, 0).as_u32.low);
    }
    else
    {
        rx->max_bytes_on_bd     = mm_cpu_to_le16(MAX_L2_CLI_BUFFER_SIZE(pdev, cid) - (u16_t)pdev->params.rcv_buffer_offset - CACHE_LINE_SIZE);
        rx->vmqueue_mode_en_flg = FALSE;
        rx->max_sges_for_packet = 0;
        rx->sge_buff_size       = 0;

        rx->sge_page_base.hi    = 0;
        rx->sge_page_base.lo    = 0;
    }

    if (cid == OOO_CID(pdev))
    {
        rel_cid = cid - LM_MAX_RSS_CHAINS(pdev);
        rx->client_qzone_id = LM_FW_AUX_QZONE_ID(pdev, rel_cid);
        rx->rx_sb_index_number = HC_SP_INDEX_ISCSI_OOO_RX_CONS;
    }
    else if (cid == ISCSI_CID(pdev))
    {
        rel_cid = cid - LM_MAX_RSS_CHAINS(pdev);
        rx->client_qzone_id = LM_FW_AUX_QZONE_ID(pdev, rel_cid);
        rx->rx_sb_index_number = HC_SP_INDEX_ETH_ISCSI_RX_CQ_CONS;
    }
    else if (cid == FCOE_CID(pdev))
    {
        rel_cid = cid - LM_MAX_RSS_CHAINS(pdev);
        rx->client_qzone_id = LM_FW_AUX_QZONE_ID(pdev, rel_cid);
        rx->rx_sb_index_number = HC_SP_INDEX_ETH_FCOE_RX_CQ_CONS;
    }
    else if (cid < MAX_RX_CHAIN(pdev))
    {
        rx->client_qzone_id = LM_FW_DHC_QZONE_ID(pdev, sb_id);
        rx->rx_sb_index_number = HC_INDEX_ETH_RX_CQ_CONS;
    }
    else
    {
        DbgMessage(NULL, FATAL, "Invalid cid 0x%x.\n", cid);
        DbgBreakIf(1);
    }

    // Avoiding rings thresholds verification is aimed for eVBD
    // which receives its buffers and SGEs only after client init
    // is completed.(eVBD receives the buffers and SGEs only after
    // client setup is completed.)
    rx->dont_verify_rings_pause_thr_flg = 1;

    /* FC */
    if (pdev->params.l2_fw_flow_ctrl)
    {
        u16_t desired_cqe_bd_low_thresh;
        u16_t desired_cqe_bd_high_thresh;
        u16_t low_thresh;
        u16_t high_thresh;
        u16_t next_page_bds;

        next_page_bds = LM_RXQ_CHAIN_BD(pdev, cid).bds_skip_eop * LM_RXQ_CHAIN_BD(pdev, cid).page_cnt;
        desired_cqe_bd_low_thresh = BRB_SIZE(pdev) + next_page_bds + FW_DROP_LEVEL(pdev);
        desired_cqe_bd_high_thresh = desired_cqe_bd_low_thresh + DROPLESS_FC_HEADROOM;

        low_thresh  = mm_cpu_to_le16(min(desired_cqe_bd_low_thresh,  (u16_t)((LM_RXQ(pdev, cid).common.desc_cnt)/4)));
        high_thresh = mm_cpu_to_le16(min(desired_cqe_bd_high_thresh, (u16_t)((LM_RXQ(pdev, cid).common.desc_cnt)/2)));

        rx->cqe_pause_thr_low  = low_thresh;
        rx->bd_pause_thr_low   = low_thresh;
        rx->sge_pause_thr_low  = 0;
        rx->rx_cos_mask        = 1;
        rx->cqe_pause_thr_high = high_thresh;
        rx->bd_pause_thr_high  = high_thresh;
        rx->sge_pause_thr_high = 0;
    }
}

STATIC void
lm_eth_init_client_init_tx_data(IN          lm_device_t                 *pdev,
                                OUT         struct client_init_tx_data  *tx,
                                IN const    u8_t                        cid,
                                IN const    u8_t                        sb_id)
{

    /* Status block index init we do for Rx + Tx together so that we ask which cid we are only once */
    if (cid == FWD_CID(pdev))
    {
        tx->tx_sb_index_number = HC_SP_INDEX_ETH_FW_TX_CQ_CONS;
    }
    else if (cid == OOO_CID(pdev))
    {
        // OOO CID doesn't really has a TX client this is don't
        // care data for FW.
        tx->tx_sb_index_number = HC_SP_INDEX_NOT_USED; /* D/C */
    }
    else if (cid == ISCSI_CID(pdev))
    {
        tx->tx_sb_index_number = HC_SP_INDEX_ETH_ISCSI_CQ_CONS;
    }
    else if (cid == FCOE_CID(pdev))
    {
        tx->tx_sb_index_number = HC_SP_INDEX_ETH_FCOE_CQ_CONS;

        if (IS_MF_AFEX_MODE(pdev))
        {
            tx->force_default_pri_flg = TRUE;
        }
    }
    else if (lm_chain_type_not_cos != lm_mp_get_chain_type(pdev, cid))
    {
        // This isn't realy cid it is the chain index
        tx->tx_sb_index_number = lm_eth_tx_hc_cq_cons_cosx_from_chain(pdev, cid);
    }
    else
    {
        DbgMessage(NULL, FATAL, "Invalid cid 0x%x.\n", cid);
        DbgBreakIf(1);
    }

    /* TX Data (remaining , sb index above...)  */
    /* ooo cid doesn't have a tx chain... */
    if (cid != OOO_CID(pdev))
    {
        tx->tx_bd_page_base.hi = mm_cpu_to_le32(lm_bd_chain_phys_addr(&pdev->tx_info.chain[cid].bd_chain, 0).as_u32.high);
        tx->tx_bd_page_base.lo = mm_cpu_to_le32(lm_bd_chain_phys_addr(&pdev->tx_info.chain[cid].bd_chain, 0).as_u32.low);
    }
    tx->tx_status_block_id = LM_FW_SB_ID(pdev, sb_id);
    tx->enforce_security_flg = FALSE; /* TBD: turn on for KVM VF? */

    /* Tx Switching... */
    if (IS_MF_SI_MODE(pdev) && pdev->params.npar_vm_switching_enable &&
        (cid != FWD_CID(pdev)) && (cid != FCOE_CID(pdev)) && (cid != ISCSI_CID(pdev)))
    {
        tx->tx_switching_flg = TRUE;
    }
    else
    {
        tx->tx_switching_flg = FALSE;
    }

    tx->tss_leading_client_id = LM_FW_CLI_ID(pdev, LM_SW_LEADING_RSS_CID(pdev));

    tx->refuse_outband_vlan_flg = 0;


    // for encapsulated packets
    // the hw ip header will be the inner ip header, the hw will incremnet the inner ip id.
    // the fw ip header will be the outer ip header, this means that if the outer ip header is ipv4, its ip id will not be incremented.
    tx->tunnel_lso_inc_ip_id = INT_HEADER;
    // In case of non-Lso encapsulated packets with L4 checksum offload, the pseudo checksum location - on BD
    tx->tunnel_non_lso_pcsum_location = CSUM_ON_BD;
    // In case of non-Lso encapsulated packets with outer L3 ip checksum offload, the pseudo checksum location - on BD
    tx->tunnel_non_lso_outer_ip_csum_location = CSUM_ON_BD;
}

u32_t lm_get_sw_client_idx_from_cid(lm_device_t * pdev,
                                    u32_t         cid)
{

    u32_t client_info_idx;

    /* If MP is enabled, we need to take care of tx-only connections, which use the
     * regular connection client-idx... the rest are split into regular eth
     * and vfs... */
    if (MM_DCB_MP_L2_IS_ENABLE(pdev))
    {
        if (lm_chain_type_cos_tx_only == lm_mp_get_chain_type(pdev, cid))
        {
            client_info_idx = lm_mp_get_reg_chain_from_chain(pdev,cid);
            return client_info_idx;
        }
    }

#ifdef VF_INVOLVED
    if (IS_CHANNEL_VIRT_MODE_MASTER_PFDEV(pdev))
    {
        client_info_idx = lm_pf_get_sw_client_idx_from_cid(pdev, cid);
    }
    else
#endif
    {
        client_info_idx = cid;
    }

    return client_info_idx;
}

u32_t lm_get_fw_client_idx_from_cid(lm_device_t * pdev,
                                    u32_t         cid)
{
    u32_t client_info_idx;
    u32_t fw_client_id;

    /* If MP is enabled, we need to take care of tx-only connections, which use the
     * regular connection client-idx... the rest are split into regular eth
     * and vfs... */
    if (MM_DCB_MP_L2_IS_ENABLE(pdev))
    {
        if (lm_chain_type_cos_tx_only == lm_mp_get_chain_type(pdev, cid))
        {
            client_info_idx = lm_mp_get_reg_chain_from_chain(pdev,cid);
            return LM_FW_CLI_ID(pdev, client_info_idx);
        }
    }

#ifdef VF_INVOLVED
    if (IS_CHANNEL_VIRT_MODE_MASTER_PFDEV(pdev))
    {
        fw_client_id = lm_pf_get_fw_client_idx_from_cid(pdev, cid);
    }
    else
#endif
    {
        fw_client_id = LM_FW_CLI_ID(pdev, cid);
    }

    return fw_client_id;
}

STATIC lm_status_t
lm_eth_init_tx_queue_data(IN       lm_device_t * pdev,
                          IN const u8_t          chain_id,
                          IN const u8_t          sb_id)
{
    struct tx_queue_init_ramrod_data * tx_queue_init_data_virt = NULL;
    u32_t                              client_info_idx         = 0;
    lm_status_t                        lm_status               = LM_STATUS_SUCCESS;
    u8_t                               cid                     = 0;

    if((lm_chain_type_cos_tx_only != lm_mp_get_chain_type(pdev,chain_id)) &&
       (chain_id != FWD_CID(pdev)))
    {
        DbgBreakMsg("lm_eth_init_tx_queue_data: the chain isn't TX only " );
        return LM_STATUS_FAILURE;
    }

    /* a bit redundant, but just so we're clear on terminology... */
    cid = chain_id;

    /* Since ramrods are sent sequentially for tx only clients, and then regular client, and
     * we won't have a case of these being sent in parallel, we can safely use the client_init_data_virt
     * of the regular eth connection for the tx only connection.
     * This way, we don't need to allocate client_info for tx only connections.
     */
    client_info_idx = lm_get_sw_client_idx_from_cid(pdev, cid);

    tx_queue_init_data_virt = &(pdev->client_info[client_info_idx].client_init_data_virt->tx_queue);

    if CHK_NULL(tx_queue_init_data_virt)
    {
        return LM_STATUS_FAILURE;
    }

    mm_mem_zero(tx_queue_init_data_virt , sizeof(struct tx_queue_init_ramrod_data));

    /* General Structure */
    lm_status = lm_eth_init_client_init_general_data(pdev,
                                                     &(tx_queue_init_data_virt->general),
                                                     chain_id);

    if(LM_STATUS_SUCCESS != lm_status)
    {
        return lm_status;
    }

    /* Tx Data */
    lm_eth_init_client_init_tx_data(pdev,
                                    &(tx_queue_init_data_virt->tx),
                                    chain_id,
                                    sb_id);

    return LM_STATUS_SUCCESS;
}

lm_status_t lm_eth_init_client_init_data(lm_device_t *pdev, u8_t cid, u8_t sb_id)
{
    struct client_init_ramrod_data * client_init_data_virt = NULL;
    lm_status_t                      lm_status             = LM_STATUS_SUCCESS;
    const u32_t                      client_info_idx       = lm_get_sw_client_idx_from_cid(pdev, cid);


    if (client_info_idx >= ARRSIZE(pdev->client_info))
    {
        DbgBreakIf(client_info_idx >= ARRSIZE(pdev->client_info));
        return LM_STATUS_FAILURE;
    }

    client_init_data_virt = &(pdev->client_info[client_info_idx].client_init_data_virt->init_data);

    if CHK_NULL(client_init_data_virt)
    {
        return LM_STATUS_FAILURE;
    }

    mm_mem_zero(client_init_data_virt , sizeof(struct client_init_ramrod_data));

    /* General Structure */
    lm_status = lm_eth_init_client_init_general_data(pdev,
                                         &(client_init_data_virt->general),
                                         cid);
    if(LM_STATUS_SUCCESS != lm_status)
    {
        return lm_status;
    }

    /* Rx Data */
    lm_eth_init_client_init_rx_data(pdev,
                                    &(client_init_data_virt->rx),
                                    cid,
                                    sb_id);

    /* Tx Data */
    lm_eth_init_client_init_tx_data(pdev,
                                    &(client_init_data_virt->tx),
                                    cid,
                                    sb_id);

    return LM_STATUS_SUCCESS;
}

/**

 * @assumptions: STRONG ASSUMPTION: This function is not
 *             called for SRIOV / MP connections...
 */
lm_status_t lm_update_eth_client(IN struct _lm_device_t    *pdev,
                                 IN const u8_t             client_idx,
                                 IN const u16_t            silent_vlan_value,
                                 IN const u16_t            silent_vlan_mask,
                                 IN const u8_t             silent_vlan_removal_flg,
                                 IN const u8_t             silent_vlan_change_flg
                                 )
{
    struct client_update_ramrod_data * client_update_data_virt = pdev->client_info[client_idx].update.data_virt;
    lm_status_t                        lm_status               = LM_STATUS_FAILURE;
    u32_t                              con_state               = 0;
    const u32_t                        cid                     = client_idx; //lm_get_cid_from_sw_client_idx(pdev);

    if CHK_NULL(client_update_data_virt)
    {
        return LM_STATUS_FAILURE;
    }

    mm_mem_zero(client_update_data_virt , sizeof(struct client_update_ramrod_data));

    MM_ACQUIRE_ETH_CON_LOCK(pdev);

    // We will send a client update ramrod in any case we can we don't optimize this flow.
    // Client setup may already took the correct NIV value but the ramrod will be sent anyway
    con_state = lm_get_con_state(pdev, cid);
    if((LM_CON_STATE_OPEN != con_state) &&
        (LM_CON_STATE_OPEN_SENT != con_state))
    {
        // Clinet is not in a state that it can recieve the ramrod
        MM_RELEASE_ETH_CON_LOCK(pdev);
        return LM_STATUS_ABORTED;
    }

    /* We don't expect this function to be called for non eth regular connections.
     * If we hit this assert it means we need support for SRIOV +  AFEX
     */
    if (cid >= MAX_RX_CHAIN(pdev))
    {
        DbgBreakIf(cid >= MAX_RX_CHAIN(pdev));
        MM_RELEASE_ETH_CON_LOCK(pdev);
        return LM_STATUS_FAILURE;
    }

    DbgBreakIf( LM_CLI_UPDATE_NOT_USED != pdev->client_info[client_idx].update.state);

    pdev->client_info[client_idx].update.state = LM_CLI_UPDATE_USED;

    client_update_data_virt->client_id  = LM_FW_CLI_ID(pdev, client_idx);
    client_update_data_virt->func_id    = FUNC_ID(pdev); /* FIXME: VFID needs to be given here for VFs... */

    client_update_data_virt->silent_vlan_value          = mm_cpu_to_le16(silent_vlan_value);
    client_update_data_virt->silent_vlan_mask           = mm_cpu_to_le16(silent_vlan_mask);
    client_update_data_virt->silent_vlan_removal_flg    = silent_vlan_removal_flg;
    client_update_data_virt->silent_vlan_change_flg     = silent_vlan_change_flg;

    client_update_data_virt->refuse_outband_vlan_flg        = 0;
    client_update_data_virt->refuse_outband_vlan_change_flg = 0;

    lm_status = lm_sq_post(pdev,
                           cid,
                           RAMROD_CMD_ID_ETH_CLIENT_UPDATE,
                           CMD_PRIORITY_MEDIUM,
                           ETH_CONNECTION_TYPE,
                           pdev->client_info[client_idx].update.data_phys.as_u64);

    MM_RELEASE_ETH_CON_LOCK(pdev);


    if (lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    lm_status = lm_wait_state_change(pdev, &pdev->client_info[client_idx].update.state, LM_CLI_UPDATE_RECV);

    pdev->client_info[client_idx].update.state = LM_CLI_UPDATE_NOT_USED;

    return lm_status;
}

lm_status_t lm_establish_eth_con(struct _lm_device_t *pdev, u8_t const chain_idx, u8_t sb_id, u8_t attributes_bitmap)
{
    lm_status_t     lm_status       = LM_STATUS_SUCCESS;
    u8_t            cmd_id          = 0;
    u8_t            type            = 0;
    lm_rcq_chain_t* rcq_chain       = NULL;
    const u8_t      cid             = chain_idx; /* redundant, but here for terminology sake... */
    u32_t           client_info_idx = 0;

    DbgMessage(pdev, INFORMi|INFORMl2sp, "#lm_establish_eth_con, cid=%d\n",cid);

    if (IS_PFDEV(pdev))
    {
        MM_ACQUIRE_ETH_CON_LOCK(pdev);
    }

    lm_set_con_state(pdev, cid, LM_CON_STATE_CLOSE);
    if (IS_PFDEV(pdev))
    {
        /* TODO: VF??? */
        if( LM_CLIENT_ATTRIBUTES_REG_CLI == GET_FLAGS(attributes_bitmap,LM_CLIENT_ATTRIBUTES_REG_CLI ))
        {
            // Regular client or OOO CID
            DbgBreakIf( LM_CLIENT_ATTRIBUTES_RX != GET_FLAGS(attributes_bitmap,LM_CLIENT_ATTRIBUTES_RX ));
            lm_status = lm_eth_init_client_init_data(pdev, cid, sb_id);
        }
        else
        {
            // TX only client or FWD
            DbgBreakIf( LM_CLIENT_ATTRIBUTES_RX == GET_FLAGS(attributes_bitmap,LM_CLIENT_ATTRIBUTES_RX ));
            lm_status = lm_eth_init_tx_queue_data(pdev, cid, sb_id);
        }

        if(LM_STATUS_SUCCESS != lm_status)
        {
            DbgBreakMsg("lm_establish_eth_con: lm_eth_init_client_init_data or lm_eth_init_tx_queue_data failed \n ");
            if (IS_PFDEV(pdev))
            {
                MM_RELEASE_ETH_CON_LOCK(pdev);
            }
            return lm_status;
        }

        lm_init_connection_context(pdev, cid, sb_id);
    }

    /* When we setup the RCQ ring we should advance the CQ cons by MAX_NUM_RAMRODS - the FWD CID is the only connection without an RCQ
     * therefore we skip this operation for forward */
    if( LM_CLIENT_ATTRIBUTES_REG_CLI == GET_FLAGS(attributes_bitmap,LM_CLIENT_ATTRIBUTES_REG_CLI ))
    {
        DbgBreakIf( LM_CLIENT_ATTRIBUTES_RX != GET_FLAGS(attributes_bitmap,LM_CLIENT_ATTRIBUTES_RX ));
        cmd_id = RAMROD_CMD_ID_ETH_CLIENT_SETUP;
        rcq_chain = &LM_RCQ(pdev, cid);
        if (IS_PFDEV(pdev))
        {
            lm_bd_chain_bds_produced(&rcq_chain->bd_chain, ETH_MIN_RX_CQES_WITH_TPA_E1H_E2);
        }
    }
    else
    {
        DbgBreakIf( LM_CLIENT_ATTRIBUTES_RX == GET_FLAGS(attributes_bitmap,LM_CLIENT_ATTRIBUTES_RX ));
        if (cid == FWD_CID(pdev))
        {
            cmd_id = RAMROD_CMD_ID_ETH_FORWARD_SETUP;
        }
        else if(lm_chain_type_cos_tx_only == lm_mp_get_chain_type(pdev,cid))
        {
            cmd_id = RAMROD_CMD_ID_ETH_TX_QUEUE_SETUP;
        }
        else
        {
            DbgBreakMsg(" lm_establish_eth_con: cmd_id not set ");
            if (IS_PFDEV(pdev))
            {
                MM_RELEASE_ETH_CON_LOCK(pdev);
            }
            return LM_STATUS_FAILURE;
        }
    }

    // Move to state ramrod sent must be done before ramrod is realy sent
    lm_set_con_state(pdev, cid, LM_CON_STATE_OPEN_SENT);

    client_info_idx = lm_get_sw_client_idx_from_cid(pdev, cid);

    if (IS_PFDEV(pdev))
    {
        lm_status = lm_sq_post(pdev,
                               cid,
                               cmd_id,
                               CMD_PRIORITY_MEDIUM,
                               type,
                               pdev->client_info[client_info_idx].client_init_data_phys.as_u64);
    }
#ifdef VF_INVOLVED
    else
    {
        lm_status = lm_vf_queue_init(pdev, cid);
    }
#endif

    if (lm_status != LM_STATUS_SUCCESS)
    {
        lm_set_con_state(pdev, cid, LM_CON_STATE_CLOSE);
        if (IS_PFDEV(pdev))
        {
            MM_RELEASE_ETH_CON_LOCK(pdev);
        }
        return lm_status;
    }

    if (IS_PFDEV(pdev))
    {
        MM_RELEASE_ETH_CON_LOCK(pdev);
    }

    lm_status = lm_eth_wait_state_change(pdev, LM_CON_STATE_OPEN, cid);


    return lm_status;
} /* lm_establish_eth_con */


/**
 * @description
 * Send all the ramrods and wait for there return.
 * @param pdev
 * @param chain_idx_base
 *
 * @return lm_status_t
 * status success is returned if all the ramrods where received.
 * Status failure is returned if not all the ramrods were
 * received.
 */
lm_status_t
lm_tpa_send_ramrods_wait(IN lm_device_t  *pdev,
                         IN const u8_t   chain_idx_base)
{
    lm_tpa_info_t   *tpa_info   = &LM_TPA_INFO(pdev);
    lm_status_t     lm_status   = LM_STATUS_SUCCESS;

    DbgBreakIf(NULL != tpa_info->update_cookie);
    DbgBreakIf(0 != tpa_info->ramrod_recv_cnt);

    lm_status = lm_tpa_send_ramrods(pdev,
                                    chain_idx_base);

    if(LM_STATUS_SUCCESS != lm_status)
    {
        DbgBreakMsg(" Ramrod send failed ");
        return lm_status;
    }

    lm_status = lm_wait_state_change(pdev, &tpa_info->state, TPA_STATE_NONE);

    return lm_status;
}

/**
 * @description
 * Update the ramrod IPVX according to the current and required
 * state.
 * @param pdev
 * @param chain_idx
 * @param vbd_rsc_ipvx_bit - The VBD TPA ipvX bit.
 *
 * @return STATIC u8_t - The HSI IPVX eth_tpa_update_command
 */
u8_t
lm_tpa_ramrod_update_ipvx(IN lm_device_t   *pdev,
                          IN const u8_t          chain_idx,
                          IN const u8_t          vbd_tpa_ipvx_bit)
{
    // Add ramrod send code
    const lm_tpa_info_t*    tpa_info    = &LM_TPA_INFO(pdev);
    u8_t                    ramrod_ipvx = 0;

    if(GET_FLAGS(tpa_info->ipvx_enabled_required, vbd_tpa_ipvx_bit) ==
       GET_FLAGS(tpa_info->ipvx_enabled_current, vbd_tpa_ipvx_bit))
    {
        ramrod_ipvx = TPA_UPDATE_NONE_COMMAND;
    }
    else if(GET_FLAGS(tpa_info->ipvx_enabled_required, vbd_tpa_ipvx_bit))
    {
        ramrod_ipvx = TPA_UPDATE_ENABLE_COMMAND;
    }
    else
    {
        ramrod_ipvx = TPA_UPDATE_DISABLE_COMMAND;
    }
    return ramrod_ipvx;
}

/**
 * @description
 * Fill and send TPA ramrod.
 * @param pdev
 * @param chain_idx
 */
STATIC lm_status_t
lm_tpa_send_ramrod(IN lm_device_t   *pdev,
                   IN const u8_t    chain_idx)
{
    // Add ramrod send code
    const lm_tpa_chain_t*   tpa_chain       = &LM_TPA( pdev, chain_idx );
    const lm_bd_chain_t*    tpa_chain_bd    = &LM_TPA_CHAIN_BD(pdev, chain_idx);
    lm_status_t             lm_status       = LM_STATUS_SUCCESS;

    if((CHK_NULL(tpa_chain->ramrod_data_virt)) ||
       (lm_tpa_state_enable != tpa_chain->state)||
       pdev->params.rss_chain_cnt <= chain_idx)
    {
        DbgBreakMsg("lm_tpa_send_ramrod : invalid paramters");
        return LM_STATUS_FAILURE;
    }

    tpa_chain->ramrod_data_virt->update_ipv4   =  lm_tpa_ramrod_update_ipvx(pdev,
                                                      chain_idx,
                                                      TPA_IPV4_ENABLED);

    tpa_chain->ramrod_data_virt->update_ipv6   =  lm_tpa_ramrod_update_ipvx(pdev,
                                                      chain_idx,
                                                      TPA_IPV6_ENABLED);

    /* TPA mode to use (LRO or GRO) */
    tpa_chain->ramrod_data_virt->tpa_mode       = TPA_LRO;

    tpa_chain->ramrod_data_virt->client_id     = LM_FW_CLI_ID(pdev, chain_idx);
    /* maximal TPA queues allowed for this client */
    tpa_chain->ramrod_data_virt->max_tpa_queues        = LM_TPA_MAX_AGGS;
    /* The maximal number of SGEs that can be used for one packet. depends on MTU and SGE size. must be 0 if SGEs are disabled */
    tpa_chain->ramrod_data_virt->max_sges_for_packet   = DIV_ROUND_UP_BITS(pdev->params.l2_cli_con_params[chain_idx].mtu, LM_TPA_PAGE_BITS);
    // Avoiding rings thresholds verification is aimed for eVBD
    // which receives its buffers and SGEs only after client init
    // is completed.(eVBD receives the buffers and SGEs only after
    // client setup is completed.)
    tpa_chain->ramrod_data_virt->dont_verify_rings_pause_thr_flg = 1;
    /* Size of the buffers pointed by SGEs */
    ASSERT_STATIC(LM_TPA_PAGE_SIZE < MAX_VARIABLE_VALUE(tpa_chain->ramrod_data_virt->sge_buff_size));
    tpa_chain->ramrod_data_virt->sge_buff_size         = mm_cpu_to_le16(LM_TPA_PAGE_SIZE);
    /* maximal size for the aggregated TPA packets, reprted by the host */
    ASSERT_STATIC((LM_TPA_MAX_AGG_SIZE * LM_TPA_PAGE_SIZE) < MAX_VARIABLE_VALUE(tpa_chain->ramrod_data_virt->max_agg_size));
    tpa_chain->ramrod_data_virt->max_agg_size          = mm_cpu_to_le16(LM_TPA_MAX_AGG_SIZE * LM_TPA_PAGE_SIZE);
    //u32_t sge_page_base_lo /* The address to fetch the next sges from (low) */;
    tpa_chain->ramrod_data_virt->sge_page_base_lo      = mm_cpu_to_le32(tpa_chain_bd->bd_chain_phy.as_u32.low);
    //u32_t sge_page_base_hi /* The address to fetch the next sges from (high) */;
    tpa_chain->ramrod_data_virt->sge_page_base_hi      = mm_cpu_to_le32(tpa_chain_bd->bd_chain_phy.as_u32.high);
    //u16_t sge_pause_thr_low /* number of remaining sges under which, we send pause message */;
    tpa_chain->ramrod_data_virt->sge_pause_thr_low     = mm_cpu_to_le16(LM_TPA_SGE_PAUSE_THR_LOW);
    //u16_t sge_pause_thr_high /* number of remaining sges above which, we send un-pause message */;
    tpa_chain->ramrod_data_virt->sge_pause_thr_high    = mm_cpu_to_le16(LM_TPA_SGE_PAUSE_THR_HIGH);

    lm_sq_post(pdev,
               chain_idx,
               RAMROD_CMD_ID_ETH_TPA_UPDATE,
               CMD_PRIORITY_MEDIUM,
               ETH_CONNECTION_TYPE,
               *(u64_t *)&(tpa_chain->ramrod_data_phys));

    DbgBreakIf(lm_status != LM_STATUS_SUCCESS);

    return lm_status;
}


/**
 * @description
 * Run on all RSS chains and send the ramrod on each one.
 * @param pdev
 * @param chain_idx_base
 */
lm_status_t
lm_tpa_send_ramrods(IN lm_device_t  *pdev,
                    IN const u8_t   chain_idx_base)
{
    lm_tpa_info_t*  tpa_info    = &LM_TPA_INFO(pdev);
    lm_status_t     lm_status   = LM_STATUS_SUCCESS;
    u8_t            chain_idx   = 0;
    u8_t            rss_idx     = 0;

    // Number of ramrods expected in receive
    tpa_info->ramrod_recv_cnt = pdev->params.rss_chain_cnt;
    tpa_info->state = TPA_STATE_RAMROD_SENT;
#ifdef VF_INVOLVED
    if (IS_VFDEV(pdev))
    {
        tpa_info->ramrod_recv_cnt++;
        lm_status = lm_vf_pf_update_rsc(pdev);
        if (lm_status == LM_STATUS_SUCCESS) {
            lm_status = lm_vf_pf_wait_no_messages_pending(pdev);
            if ((lm_status == LM_STATUS_SUCCESS) && (0 == mm_atomic_dec((u32_t*)(&tpa_info->ramrod_recv_cnt))))
            {
                tpa_info->ipvx_enabled_current = tpa_info->ipvx_enabled_required;
                if (tpa_info->update_cookie)
                {
                    void* cookie = (void *)tpa_info->update_cookie;
                    tpa_info->update_cookie = NULL;
                    mm_set_done(pdev, 0, cookie);
                }
            }
        }

    }
    else
#endif
    {
        LM_FOREACH_RSS_IDX(pdev, rss_idx)
        {
            chain_idx = chain_idx_base + RSS_ID_TO_CID(rss_idx);
            lm_status = lm_tpa_send_ramrod(pdev,
                                           chain_idx);

            if(LM_STATUS_SUCCESS != lm_status)
            {
                DbgBreakMsg(" Ramrod send failed ");
                break;
            }
        }
    }

    return lm_status;
}

/**
 * @description
 * Fill and send function_update_data ramrod.
 * @param pdev
 */
lm_status_t
lm_encap_send_ramrod(IN lm_device_t *pdev, u8_t new_encap_offload_state, void* cookie)
{
    lm_encap_info_t* encaps_info = &(pdev->encap_info);
    struct function_update_data*    data        = LM_SLOWPATH(pdev, encap_function_update_data);
    const lm_address_t              data_phys   = LM_SLOWPATH_PHYS(pdev, encap_function_update_data);
    lm_status_t                     lm_status   = LM_STATUS_SUCCESS;

    // check that we are not in the middle of handling another encapsulated packets offload set request (1 pending)
    DbgBreakIf(encaps_info->new_encap_offload_state != encaps_info->current_encap_offload_state);
    DbgBreakIf(encaps_info->update_cookie);

    encaps_info->new_encap_offload_state = new_encap_offload_state;

    if (encaps_info->new_encap_offload_state == encaps_info->current_encap_offload_state)
    {
        DbgMessage(pdev, VERBOSEencap, "no change in encapsulated packets offload state\n");
        return lm_status;
    }

    // remember this for mm_set_done call (called on completion of the ramrod)
    // mm_set_done will free memory of query_set_info
    encaps_info->update_cookie = cookie;

    // GRE config for the function will be updated according to the gre_tunnel_rss and nvgre_clss_en fields
    data->update_tunn_cfg_flg = TRUE;

    if (ENCAP_OFFLOAD_DISABLED == pdev->encap_info.new_encap_offload_state)
    {
        data->tunn_clss_en  = 0;
        data->tunnel_mode = TUNN_MODE_NONE;
    }
    else
    {
        data->tunn_clss_en  = 1;
        data->tunnel_mode = TUNN_MODE_GRE;
        data->gre_tunnel_type = NVGRE_TUNNEL;
    }

    data->echo = FUNC_UPDATE_RAMROD_SOURCE_ENCAP;

    lm_status = lm_sq_post(pdev,
                           0, //Don't care
                           RAMROD_CMD_ID_COMMON_FUNCTION_UPDATE,
                           CMD_PRIORITY_NORMAL,
                           NONE_CONNECTION_TYPE,
                           data_phys.as_u64);

    if (lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }
    return LM_STATUS_PENDING;
}
/**
 * This function is a general eq ramrod fuanction that waits
 * synchroniously for it's completion.
 *
 * @param pdev
 * cmd_id -The ramrod command ID
 * data -ramrod data
 * curr_state - what to poll on
 * curr_state Current state.
 * new_state - what we're waiting for.
 * @return lm_status_t SUCCESS / TIMEOUT on waiting for
 *         completion
 */
lm_status_t
lm_eq_ramrod_post_sync( IN struct _lm_device_t  *pdev,
                        IN u8_t                 cmd_id,
                        IN u64_t                data,
                        IN u8_t                 ramrod_priority,
                        IN volatile u32_t       *p_curr_state,
                        IN u32_t                curr_state,
                        IN u32_t                new_state)
{

    lm_status_t lm_status = LM_STATUS_SUCCESS;

    DbgMessage(pdev, INFORMeq|INFORMl2sp, "#lm_eq_ramrod\n");

    *p_curr_state = curr_state;

    lm_status = lm_sq_post(pdev,
                           0, //Don't care
                           cmd_id,
                           ramrod_priority,
                           NONE_CONNECTION_TYPE,
                           data );

    if (lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    lm_status = lm_wait_state_change(pdev,
                                     p_curr_state,
                                     new_state);

    return lm_status;
} /* lm_eq_ramrod_post_sync */

static lm_status_t
lm_halt_eth_con(struct _lm_device_t *pdev, u32_t cid,
                const u8_t send_ramrod)
{
    union eth_specific_data ramrod_data     = {{0}};
    lm_address_t            data_mapping    = {{0}};
    lm_status_t             lm_status       = LM_STATUS_SUCCESS  ;
    u32_t                   fw_client_idx   = 0xFFFFFFFF;
    u32_t                   con_state       = 0;

    fw_client_idx = lm_get_fw_client_idx_from_cid(pdev, cid);

    ASSERT_STATIC(sizeof(ramrod_data) == sizeof(u64_t));


    con_state = lm_get_con_state(pdev, cid);
    DbgMessage(pdev, WARN/*INFORMi|INFORMl2sp*/, "#lm_halt_eth_con cid=%d fw_client_idx=%d client_info=%d(%d)\n",cid, fw_client_idx,
                cid,con_state);


    if (ERR_IF(con_state != LM_CON_STATE_OPEN))
    {
        DbgBreakIf(!DBG_BREAK_ON(UNDER_TEST));
        return LM_STATUS_FAILURE;
    }
    if (IS_PFDEV(pdev))
    {
        MM_ACQUIRE_ETH_CON_LOCK(pdev);
    }

    if(FALSE == send_ramrod)
    {
        lm_set_con_state(pdev, cid, LM_CON_STATE_HALT);
        DbgMessage(pdev, WARNl2sp, "lm_close_eth_con:The HALT ramrod isn't sent \n");
        if (IS_PFDEV(pdev))
        {
            MM_RELEASE_ETH_CON_LOCK(pdev);
        }
        return LM_STATUS_SUCCESS;
    }
    // Send ramrod
    lm_set_con_state(pdev, cid, LM_CON_STATE_HALT_SENT);
    ramrod_data.halt_ramrod_data.client_id = fw_client_idx; //LM_FW_CLI_ID(pdev, client_info_idx);

    /* convert halt_ramrod_data to a big-endian friendly format */
    data_mapping.as_u32.low = ramrod_data.halt_ramrod_data.client_id;

    lm_status = lm_sq_post(pdev,
                           cid,
                           RAMROD_CMD_ID_ETH_HALT,
                           CMD_PRIORITY_MEDIUM,
                           ETH_CONNECTION_TYPE,
                           data_mapping.as_u64);

    if (IS_PFDEV(pdev))
    {
        MM_RELEASE_ETH_CON_LOCK(pdev);
    }

    if (lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    lm_status = lm_eth_wait_state_change(pdev, LM_CON_STATE_HALT, cid);

    return lm_status;
} /* lm_halt_eth_con */

lm_status_t lm_terminate_eth_con(struct _lm_device_t *pdev,
                                 u32_t const          cid)
{
    lm_status_t lm_status  = LM_STATUS_SUCCESS;

    DbgMessage(pdev, INFORMi|INFORMl2sp, "#lm_terminate_eth_con, cid=%d \n",cid);

    if (ERR_IF(lm_get_con_state(pdev, cid) != LM_CON_STATE_HALT))
    {
        DbgBreak();
        return LM_STATUS_FAILURE;
    }

    if (IS_VFDEV(pdev))
    {
        lm_set_con_state(pdev, cid, LM_CON_STATE_TERMINATE);
        return LM_STATUS_SUCCESS; /* Not supported for VFs */
    }

    lm_status = lm_sq_post(pdev,
                           cid,
                           RAMROD_CMD_ID_ETH_TERMINATE,
                           CMD_PRIORITY_MEDIUM,
                           ETH_CONNECTION_TYPE,
                           0);

    if (lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    lm_status = lm_eth_wait_state_change(pdev, LM_CON_STATE_TERMINATE, cid);

    return lm_status;
}

static lm_status_t lm_cfc_del_eth_con(struct _lm_device_t *pdev,
                                      u32_t const          cid)
{
/* VIA PF!!!!!!*/
    lm_status_t lm_status       = LM_STATUS_SUCCESS;

    DbgMessage(pdev, INFORMi|INFORMl2sp, "#lm_cfc_del_eth_con, cid=%d\n",cid);

    if (ERR_IF(lm_get_con_state(pdev, cid) != LM_CON_STATE_TERMINATE))
    {
        DbgBreak();
        return LM_STATUS_FAILURE;
    }

    lm_status = lm_sq_post(pdev,
                           cid,
                           RAMROD_CMD_ID_COMMON_CFC_DEL,
                           CMD_PRIORITY_MEDIUM,
                           NONE_CONNECTION_TYPE,
                           0);

    if (lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    lm_status = lm_eth_wait_state_change(pdev, LM_CON_STATE_CLOSE, cid);

    return lm_status;
} /* lm_cfc_del_eth_con */



lm_status_t lm_establish_forward_con(struct _lm_device_t *pdev)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    u8_t const  fwd_cid   = FWD_CID(pdev);

    DbgMessage(pdev, INFORMi | INFORMl2sp, "lm_establish_forward_con\n");
    lm_status = lm_establish_eth_con(pdev, fwd_cid, DEF_STATUS_BLOCK_INDEX , LM_CLIENT_ATTRIBUTES_TX);
    if (lm_status != LM_STATUS_SUCCESS) {
        DbgMessage(pdev, FATAL, "lm_establish_forward_con failed\n");
        return lm_status;
    }

    DbgMessage(pdev,INFORMi | INFORMl2sp, "Establish forward connection ramrod completed\n");

    return LM_STATUS_SUCCESS;
}

lm_status_t lm_close_forward_con(struct _lm_device_t *pdev)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    u8_t const  fwd_cid   = FWD_CID(pdev);

    /* halt and terminate ramrods (lm_{halt,terminate}_eth_con) are not sent for the forward channel connection.
       therefore we just change the state from OPEN to TERMINATE, and send the cfc del ramrod */
    DbgBreakIf(lm_get_con_state(pdev, fwd_cid) != LM_CON_STATE_OPEN);
    lm_set_con_state(pdev, fwd_cid, LM_CON_STATE_TERMINATE);

    lm_status = lm_cfc_del_eth_con(pdev,fwd_cid);
    if (lm_status != LM_STATUS_SUCCESS) {
        return lm_status;
    }

    DbgMessage(pdev,INFORMi | INFORMl2sp, "lm_close_forward_con completed\n");

    return LM_STATUS_SUCCESS;
}

lm_status_t lm_close_eth_con(struct _lm_device_t *pdev,
                             u32_t    const cid,
                             const  u8_t   send_halt_ramrod)
{
    lm_status_t lm_status;
    u8_t max_eth_cid;

    if (lm_fl_reset_is_inprogress(pdev)) {
        lm_set_con_state(pdev, cid, LM_CON_STATE_CLOSE);
        DbgMessage(pdev, FATAL, "lm_chip_stop: Under FLR: \"close\" cid=%d.\n", cid);
        return LM_STATUS_SUCCESS;
    }

#ifdef VF_INVOLVED
    if (IS_CHANNEL_VFDEV(pdev)) {
        lm_status = lm_vf_queue_close(pdev, (u8_t)cid);
        return lm_status;
    }
#endif


    lm_status = lm_halt_eth_con(pdev,cid, send_halt_ramrod);

    if (lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    lm_status = lm_terminate_eth_con(pdev,cid);
    if (lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    lm_status = lm_cfc_del_eth_con(pdev,cid);
    if (lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    if (MM_DCB_MP_L2_IS_ENABLE(pdev))
    {
        max_eth_cid = lm_mp_max_cos_chain_used(pdev);
    }
    else
    {
        max_eth_cid = MAX_RX_CHAIN(pdev);
    }
    if (cid < max_eth_cid) {
        lm_status = lm_clear_eth_con_resc(pdev,(u8_t)cid);
    }

    if (lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    DbgMessage(pdev,INFORMi | INFORMl2sp, "lm_close_eth_con completed for cid=%d\n", cid);

    return LM_STATUS_SUCCESS;
}
lm_status_t lm_eth_wait_state_change(struct _lm_device_t *pdev, u32_t new_state, u32_t cid)
{
    lm_cid_resc_t * cid_resc = lm_cid_resc(pdev, cid);

    if (CHK_NULL(cid_resc))
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    return lm_wait_state_change(pdev, &cid_resc->con_state, new_state);

} /* lm_eth_wait_state_change */

/**lm_func_update_post_command Post a func_update ramrod and
 * wait for its completion.
 * Must be called from a work item.
 *
 * @param pdev the device
 * @param command the ramrod cmd_id (NONE_CONNECTION_TYPE is
 *                assumed)
 * @param data the ramrod data
 *
 * @return lm_status_t LM_STATUS_SUCCESS on success, some other
 *         failure code on failure.
 */
lm_status_t
lm_l2mp_func_update_command( IN lm_device_t                         *pdev,
                             IN const struct function_update_data   *func_data)
{
    lm_status_t                     lm_status   = LM_STATUS_FAILURE;
    struct function_update_data*    data        = LM_SLOWPATH(pdev, l2mp_func_update_data);
    lm_address_t                    data_phys   = LM_SLOWPATH_PHYS(pdev, l2mp_func_update_data);

    DbgBreakIf(pdev->slowpath_info.l2mp_func_update_ramrod_state != L2MP_FUNC_UPDATE_RAMROD_NOT_POSTED);

    mm_memcpy(data, func_data, sizeof(struct function_update_data));

    data->echo = FUNC_UPDATE_RAMROD_SOURCE_L2MP;

    lm_status = lm_eq_ramrod_post_sync(pdev,RAMROD_CMD_ID_COMMON_FUNCTION_UPDATE, data_phys.as_u64,CMD_PRIORITY_NORMAL,&pdev->slowpath_info.l2mp_func_update_ramrod_state, L2MP_FUNC_UPDATE_RAMROD_POSTED, L2MP_FUNC_UPDATE_RAMROD_COMPLETED);
    if (LM_STATUS_SUCCESS != lm_status)
    {
        DbgBreakIf(LM_STATUS_SUCCESS != lm_status);
        goto _exit;
    }

_exit:
    pdev->slowpath_info.l2mp_func_update_ramrod_state = L2MP_FUNC_UPDATE_RAMROD_NOT_POSTED;
    return lm_status;
}

/*********************** NIV **************************************/

lm_status_t lm_niv_post_command(struct _lm_device_t         *pdev,
                                IN const u8_t               command,
                                IN const u64_t              data,
                                IN const u32_t              curr_state)
{
    lm_status_t              lm_status        = LM_STATUS_SUCCESS;
    const niv_ramrod_state_t niv_ramrod_state = curr_state;

    DbgBreakIf((NIV_RAMROD_COMPLETED  == curr_state)||
               (NIV_RAMROD_NOT_POSTED == curr_state));

    DbgBreakIf(pdev->slowpath_info.niv_ramrod_state != NIV_RAMROD_NOT_POSTED);

    lm_status = lm_eq_ramrod_post_sync(pdev,command,data,CMD_PRIORITY_NORMAL,&pdev->slowpath_info.niv_ramrod_state, niv_ramrod_state, NIV_RAMROD_COMPLETED);
    if (LM_STATUS_SUCCESS != lm_status)
    {
        DbgBreakIf(LM_STATUS_SUCCESS != lm_status);
        goto _exit;
    }

_exit:
    pdev->slowpath_info.niv_ramrod_state = NIV_RAMROD_NOT_POSTED;
    return lm_status;
}

lm_status_t lm_niv_vif_update(struct _lm_device_t *pdev,
                              IN const u16_t       vif_id,
                              IN const u16_t       default_vlan,
                              IN const u8_t        allowed_priorities)
{
    lm_status_t                         lm_status   = LM_STATUS_FAILURE;
    struct function_update_data*        data        = LM_SLOWPATH(pdev, niv_function_update_data);
    lm_address_t                        data_phys   = LM_SLOWPATH_PHYS(pdev, niv_function_update_data);

    data->vif_id_change_flg              = TRUE;
    data->vif_id                         = mm_cpu_to_le16(vif_id);
    data->afex_default_vlan_change_flg   = TRUE;
    data->afex_default_vlan              = mm_cpu_to_le16(default_vlan);
    data->allowed_priorities_change_flg  = TRUE;
    data->allowed_priorities             = allowed_priorities;

    data->network_cos_mode_change_flg    = FALSE;
    data->lb_mode_en                     = FALSE; //if a VIF update was received it means we're connected to a switch, so we're not in LB mode.
    data->lb_mode_en_change_flg          = 1;
    data->echo                           = FUNC_UPDATE_RAMROD_SOURCE_NIV;

    lm_status = lm_niv_post_command(pdev,RAMROD_CMD_ID_COMMON_FUNCTION_UPDATE, data_phys.as_u64, NIV_RAMROD_VIF_UPDATE_POSTED);

    return lm_status;
}

lm_status_t lm_niv_vif_list_update(struct _lm_device_t *pdev,
                                   IN const enum vif_list_rule_kind command,
                                   IN const u16_t                   list_index,
                                   IN const u8_t                    func_bit_map,
                                   IN const u8_t                    func_to_clear)
{
    struct afex_vif_list_ramrod_data data      = {0};
    lm_status_t                      lm_status = LM_STATUS_FAILURE;

    data.func_bit_map          = func_bit_map;
    data.func_to_clear         = func_to_clear;
    data.afex_vif_list_command = command;
    data.vif_list_index        = list_index;
    data.echo                  = command;

    lm_status = lm_niv_post_command(pdev,RAMROD_CMD_ID_COMMON_AFEX_VIF_LISTS, *((u64_t*)(&data)), NIV_RAMROD_VIF_LISTS_POSTED);

    return lm_status;
}



/****************** CLASSIFICATION ********************************/
/**
 * Set/Unset a mac-address or mac-vlan pair on a given chain.
 *
 * @param pdev
 * @param mac_addr  - array of size ETHERNET_ADDRESS_SIZE
 *                    containing a valid mac addresses
 * @param vlan_tag  - vlan tag to be set with mac address
 * @param chain_idx - which chain to set the mac on. Chain_idx
 *                    will be transformed to a l2 client-id
 * @param cookie    - will be returned to MM layer on completion
 * @param set       - set or remove mac address
 * @param is_encap_inner_mac_filter - set if we filter according
 *                                  to inner mac (VMQ offload of
 *                                  encapsulated packets)
 *
 * @return lm_status_t SUCCESS on syncrounous success, PENDING
 *         if completion will be called later, FAILURE o/w
 */
lm_status_t lm_set_mac_addr(struct _lm_device_t *pdev,
                            u8_t                *mac_addr,
                            u16_t               vlan_tag,
                            u8_t                chain_idx,
                            void*               cookie,
                            const u8_t          b_set,
                            u8_t                is_encap_inner_mac_filter)
{
    struct ecore_vlan_mac_ramrod_params ramrod_param  = { 0 };
    lm_status_t                         lm_status     = LM_STATUS_FAILURE;
    ecore_status_t                      ecore_status  = ECORE_SUCCESS;
    lm_cli_idx_t                        lm_cli_idx    = LM_CLI_IDX_MAX;
    u8_t                                cid           = chain_idx; // FIXME!!!

    if ERR_IF(!mac_addr)
    {
        DbgBreakMsg("lm_set_mac_addr: invalid params\n");
        return LM_STATUS_INVALID_PARAMETER;
    }

    if (lm_reset_is_inprogress(pdev))
    {
        DbgMessage(pdev, FATAL, "lm_set_mac_addr: Under FLR!!!\n");
        return  LM_STATUS_SUCCESS;
    }

#ifdef VF_INVOLVED
    if (IS_CHANNEL_VFDEV(pdev))
    {
        lm_status = lm_vf_pf_set_q_filters(pdev, LM_CLI_IDX_NDIS, cookie, Q_FILTER_MAC, mac_addr, ETHERNET_ADDRESS_SIZE,vlan_tag, b_set);
        return lm_status;
    }
#endif

    DbgMessage(pdev, WARN/*INFORMl2sp*/, "lm_set_mac_addr: b_set=%d chain_idx=%d!!!\n", b_set, chain_idx);
    DbgMessage(pdev, INFORMl2sp, "lm_set_mac_addr: [%02x]:[%02x]:[%02x]:[%02x]:[%02x]:[%02x]!!!\n",
                                   mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5]);

    /* Prepare ramrod params to be sent to ecore layer... */
    if (vlan_tag != LM_SET_CAM_NO_VLAN_FILTER)
    {
        DbgBreakIf(CHIP_IS_E1(pdev));

        ASSERT_STATIC( ETHERNET_ADDRESS_SIZE == sizeof(ramrod_param.user_req.u.vlan_mac.mac) );

        mm_memcpy( ramrod_param.user_req.u.vlan_mac.mac, mac_addr, sizeof(ramrod_param.user_req.u.vlan_mac.mac));
        ramrod_param.user_req.u.vlan_mac.vlan = vlan_tag;
        ramrod_param.user_req.u.vlan_mac.is_inner_mac = is_encap_inner_mac_filter;

        ramrod_param.vlan_mac_obj = &pdev->client_info[chain_idx].mac_vlan_obj;
    }
    else
    {
        ASSERT_STATIC( ETHERNET_ADDRESS_SIZE == sizeof(ramrod_param.user_req.u.mac.mac) );

        mm_memcpy( ramrod_param.user_req.u.mac.mac, mac_addr, sizeof(ramrod_param.user_req.u.mac.mac) );
        ramrod_param.user_req.u.mac.is_inner_mac = is_encap_inner_mac_filter;

        ramrod_param.vlan_mac_obj = &pdev->client_info[chain_idx].mac_obj;
    }
    /* Set the cookie BEFORE sending the ramrod!!!! ramrod may complete in the mean time... */
    DbgBreakIf(pdev->client_info[cid].set_mac_cookie != NULL);
    pdev->client_info[cid].set_mac_cookie = cookie;

    ramrod_param.user_req.cmd = b_set ? ECORE_VLAN_MAC_ADD : ECORE_VLAN_MAC_DEL;

    lm_cli_idx = LM_CHAIN_IDX_CLI(pdev, chain_idx);

    SET_BIT( ramrod_param.ramrod_flags, RAMROD_EXEC );

    switch (lm_cli_idx)
    {
    case LM_CLI_IDX_NDIS:
        SET_BIT (ramrod_param.user_req.vlan_mac_flags, ECORE_ETH_MAC);
        break;

    case LM_CLI_IDX_ISCSI:
        SET_BIT (ramrod_param.user_req.vlan_mac_flags, ECORE_ISCSI_ETH_MAC);
        break;

    default:
        /* Nothing... */
        break;
    }

    ecore_status = ecore_config_vlan_mac(pdev, &ramrod_param );
    lm_status    = lm_ecore_status_to_lm_status(ecore_status);

    if( LM_STATUS_PENDING != lm_status )
    {
        pdev->client_info[cid].set_mac_cookie = NULL; // rollback
    }
    return lm_status;
}

/**
 * Set/Unset a vlan on a given chain.
 *      Setting/unsetting a vlan is a bit more complex than
 *      setting a mac address and is therefore implemented in a
 *      separate function. It require deleting a previous vlan
 *      tag if one was set, and changing rx-filtering rules. The
 *      change in rx-filtering rules has to do with "any-vlan".
 *      If no vlan is set we want "any-vlan" otherwise we want
 *      to remove the any-vlan, this requires another ramrod.
 *      The way this is implemented is as follows:
 *          1. prepare vlan add/remove commands without
 *          executing them (sp-verbs feature don't send EXEC)
 *          2. If need to set rx-mask, turn on a flag that will
 *          be checked on completion of rx-mask, in
 *          lm_eq_handle_rx_filter.., we look at this flag and
 *          if it's on execute the vlan pending command
 *          (sp-verbs CONT feature).
 *
 * @param pdev
 * @param vlan_tag  - vlan tag to be set
 * @param chain_idx - which chain to set the vlan on. Chain_idx
 *                    will be transformed to a l2 client-id
 * @param cookie    - will be returned to MM layer on completion
 * @param set       - set or remove vlan
 *
 * @return lm_status_t SUCCESS on syncrounous success, PENDING
 *         if completion will be called later, FAILURE o/w
 */
lm_status_t lm_set_vlan_only(struct _lm_device_t *pdev,
                             u16_t               vlan_tag,
                             u8_t                chain_idx,
                             void*               cookie,
                             const u8_t          b_set )
{
    struct ecore_vlan_mac_ramrod_params ramrod_param       = { 0 };
    lm_status_t                         lm_status          = LM_STATUS_FAILURE;
    ecore_status_t                      ecore_status       = ECORE_SUCCESS;
    lm_cli_idx_t                        lm_cli_idx         = LM_CLI_IDX_MAX;
    u8_t                                cid                = chain_idx; // FIXME!!!
    u8_t                                b_set_rx_mask      = FALSE;

    if (lm_reset_is_inprogress(pdev))
    {
        DbgMessage(pdev, FATAL, "lm_set_mac_addr: Under FLR!!!\n");
        return  LM_STATUS_SUCCESS;
    }

#ifdef VF_INVOLVED
    if (IS_CHANNEL_VFDEV(pdev))
    {
        /* 9/22/11 Michals: should we support this for VFs??? */
        return LM_STATUS_FAILURE;
    }
#endif

    DbgMessage(pdev, INFORMl2sp, "lm_set_vlan_only: b_set=%d chain_idx=%d!!!\n", b_set, chain_idx);

    /* Prepare ramrod params to be sent to ecore layer... */
    if (CHIP_IS_E1x(pdev))
    {
        DbgMessage(pdev, WARN/*INFORMl2sp*/, "lm_set_vlan_only: not supported for E1x!!!\n");
        return LM_STATUS_FAILURE;
    }

    ramrod_param.vlan_mac_obj = &pdev->client_info[chain_idx].vlan_obj;
    if (pdev->client_info[chain_idx].current_set_vlan == vlan_tag)
    {
        return LM_STATUS_EXISTING_OBJECT;
    }

    /* Set the cookie BEFORE sending the ramrod!!!! ramrod may complete in the mean time... */
    DbgBreakIf(pdev->client_info[cid].set_mac_cookie != NULL);
    pdev->client_info[cid].set_mac_cookie = cookie;


    if (b_set)
    {
        /* If we're just setting vlan, check if we need to delete the old one first... */
        if (pdev->client_info[chain_idx].current_set_vlan != 0)
        {
            ramrod_param.user_req.u.vlan.vlan = pdev->client_info[chain_idx].current_set_vlan;
            ramrod_param.user_req.cmd = ECORE_VLAN_MAC_DEL;

            ecore_status = ecore_config_vlan_mac(pdev, &ramrod_param );
            /* don't really care about the status... */
        }

        /* Prepare for the setting... */
        ramrod_param.user_req.u.vlan.vlan = vlan_tag;
    }
    else
    {
        ramrod_param.user_req.u.vlan.vlan = pdev->client_info[chain_idx].current_set_vlan;
    }

    pdev->client_info[chain_idx].current_set_vlan = vlan_tag;

    ramrod_param.user_req.cmd = b_set ? ECORE_VLAN_MAC_ADD : ECORE_VLAN_MAC_DEL;

    lm_cli_idx = LM_CHAIN_IDX_CLI(pdev, chain_idx);

    /* Determine if rx-mask needs to be changed as a result of this update. */
    b_set_rx_mask = (( b_set &&  pdev->client_info[cid].b_any_vlan_on) ||
                     (!b_set && !pdev->client_info[cid].b_any_vlan_on) );

    /* If we don't need to change the mask we need to execute commands now, otherwise they'll
       be executed from rx filter completion */
    if (!b_set_rx_mask )
    {
        SET_BIT( ramrod_param.ramrod_flags, RAMROD_EXEC );
    }

    ecore_status = ecore_config_vlan_mac(pdev, &ramrod_param );
    lm_status    = lm_ecore_status_to_lm_status(ecore_status);

    if( (LM_STATUS_PENDING != lm_status) )
    {
        pdev->client_info[cid].set_mac_cookie = NULL; /* rollback */
        return lm_status;
    }

    /* see function description to understand this better... */
    if (b_set_rx_mask)
    {
        pdev->client_info[chain_idx].b_vlan_only_in_process = TRUE;
        lm_status = lm_set_rx_mask(pdev, cid, pdev->client_info[cid].last_set_rx_mask, NULL);
    }

    return lm_status;
}
/**
 *  Move a filter from one chain idx to another atomically
 *
 * @param pdev
 *
 * @param mac_addr       - array of size ETHERNET_ADDRESS_SIZE
 *                         containing a valid mac addresses
 * @param vlan_tag       - vlan tag to be set with mac address
 * @param src_chain_idx  - which chain to remove the mac from
 * @param dest_chain_idx - which chain to set the mac on
 * @param cookie         - will be returned to MM layer on completion
 *
 * @return lm_status_t
 */
lm_status_t lm_move_mac_addr(struct _lm_device_t *pdev, u8_t *mac_addr, u16_t vlan_tag,
                             u8_t src_chain_idx,  u8_t dest_chain_idx, void * cookie, u8_t is_encap_inner_mac_filter)
{
    struct ecore_vlan_mac_ramrod_params ramrod_param = { 0 };
    struct ecore_vlan_mac_obj          *dest_obj     = NULL;
    lm_status_t                         lm_status    = LM_STATUS_FAILURE;
    ecore_status_t                      ecore_status = ECORE_SUCCESS;
    u8_t                                sw_client_id       = src_chain_idx;

    if ERR_IF(!pdev || !mac_addr)
    {
        DbgBreakMsg("lm_move_mac_addr: invalid params\n");
        return LM_STATUS_INVALID_PARAMETER;
    }

    if (lm_reset_is_inprogress(pdev))
    {
        DbgMessage(pdev, FATAL, "lm_move_mac_addr: Under FLR!!!\n");
        return  LM_STATUS_SUCCESS;
    }

#ifdef VF_INVOLVED
    if (IS_CHANNEL_VFDEV(pdev))
    {
        DbgBreakMsg("lm_move_mac_addr: Move not expected on VF\n");
        return lm_status;
    }
#endif

    DbgMessage(pdev, INFORMl2sp, "lm_move_mac_addr: src_chain_idx=%d dest_chain_idx=%d!!!\n",
               src_chain_idx, dest_chain_idx);
    DbgMessage(pdev, INFORMl2sp, "lm_move_mac_addr: [%d]:[%d]:[%d]:[%d]:[%d]:[%d] set=%d chain_idx=%d!!!\n",
               mac_addr[0], mac_addr[1], mac_addr[2], mac_addr[3], mac_addr[4], mac_addr[5], mac_addr[6]);

    /* Prepare ramrod params to be sent to ecore layer... */
    if (vlan_tag != LM_SET_CAM_NO_VLAN_FILTER)
    {
        mm_memcpy( ramrod_param.user_req.u.vlan_mac.mac, mac_addr, sizeof(ramrod_param.user_req.u.vlan_mac.mac));
        ramrod_param.user_req.u.vlan_mac.vlan = vlan_tag;
	ramrod_param.user_req.u.vlan_mac.is_inner_mac = is_encap_inner_mac_filter;
        ramrod_param.vlan_mac_obj = &pdev->client_info[src_chain_idx].mac_vlan_obj;
        dest_obj = &pdev->client_info[dest_chain_idx].mac_vlan_obj;
    }
    else
    {
        mm_memcpy( ramrod_param.user_req.u.mac.mac, mac_addr, sizeof(ramrod_param.user_req.u.mac.mac) );
	ramrod_param.user_req.u.mac.is_inner_mac = is_encap_inner_mac_filter;

        ramrod_param.vlan_mac_obj = &pdev->client_info[src_chain_idx].mac_obj;
        dest_obj = &pdev->client_info[dest_chain_idx].mac_obj;
    }


    /* Set the cookie BEFORE sending the ramrod!!!! ramrod may complete in the mean time... */
    DbgBreakIf(pdev->client_info[sw_client_id].set_mac_cookie != NULL);
    pdev->client_info[sw_client_id].set_mac_cookie = cookie;

    ramrod_param.user_req.cmd = ECORE_VLAN_MAC_MOVE;

    ramrod_param.user_req.target_obj = dest_obj;

    SET_BIT( ramrod_param.ramrod_flags, RAMROD_EXEC );

    ecore_status = ecore_config_vlan_mac(pdev, &ramrod_param );

    lm_status    = lm_ecore_status_to_lm_status(ecore_status);

    if ( LM_STATUS_PENDING == lm_status )
    {
        /* FIXME: VF MACS in NIG stay??*/
    }
    else
    {
        pdev->client_info[sw_client_id].set_mac_cookie = NULL; // rollback
    }
    return lm_status;
}

/**
 * @Description
 *      Waits for the last set-mac called to complete, could be
 *      set-mac or set-mac-vlan...
 * @param pdev
 * @param chain_idx - the same chain-idx that the set-mac was
 *                  called on
 *
 * @return lm_status_t SUCCESS or TIMEOUT
 */
lm_status_t lm_wait_set_mac_done(struct _lm_device_t *pdev, u8_t chain_idx)
{
    struct ecore_vlan_mac_obj *mac_obj      = &pdev->client_info[chain_idx].mac_obj;
    struct ecore_vlan_mac_obj *mac_vlan_obj = &pdev->client_info[chain_idx].mac_vlan_obj;
    ecore_status_t            ecore_status  = mac_obj->wait(pdev, mac_obj);
    lm_status_t               lm_status     = lm_ecore_status_to_lm_status(ecore_status);

    if (lm_status != LM_STATUS_SUCCESS)
    {
        DbgBreakIf(lm_status != LM_STATUS_SUCCESS);
        return lm_status;
    }

    if (!CHIP_IS_E1(pdev))
    {
        ecore_status = mac_vlan_obj->wait(pdev, mac_vlan_obj);
        lm_status    = lm_ecore_status_to_lm_status(ecore_status);

        DbgBreakIf(lm_status != LM_STATUS_SUCCESS);
    }

    return lm_status;
}

/**
 * @Description
 *      Waits for the last set-vlan called to complete
 * @param pdev
 * @param chain_idx - the same chain-idx that the set-vlan was
 *                  called on
 *
 * @return lm_status_t SUCCESS or TIMEOUT
 */
lm_status_t lm_wait_set_vlan_done(struct _lm_device_t *pdev, u8_t chain_idx)
{
    struct ecore_vlan_mac_obj *vlan_obj     = &pdev->client_info[chain_idx].vlan_obj;
    lm_status_t               lm_status     = LM_STATUS_SUCCESS;
    ecore_status_t            ecore_status;

    if (!CHIP_IS_E1x(pdev))
    {
        ecore_status = vlan_obj->wait(pdev, vlan_obj);
        lm_status    = lm_ecore_status_to_lm_status(ecore_status);

        DbgBreakIf(lm_status != LM_STATUS_SUCCESS);
    }

    return lm_status;
}


/**
 * Description
 *      Clears all the mac address that are set on a certain cid...
 * @param pdev
 * @param chain_idx - which chain_idx to clear macs on...
 *
 * @assumptions: Called in PASSIVE_LEVEL!! function sleeps...
 * @return lm_status_t
 */
lm_status_t lm_clear_all_mac_addr(struct _lm_device_t *pdev, const u8_t chain_idx)
{
#define THE_REST_OF_ETH_MAC 0xffff

    struct ecore_vlan_mac_ramrod_params   ramrod_params    = {0};
    struct ecore_vlan_mac_obj           * vlan_mac_obj     = NULL;
    lm_status_t                           lm_status        = LM_STATUS_FAILURE;
    ecore_status_t                        ecore_status     = ECORE_SUCCESS;
    u32_t                                 mac_types[]      = {ECORE_ETH_MAC, ECORE_ISCSI_ETH_MAC, THE_REST_OF_ETH_MAC};
    struct ecore_vlan_mac_obj           * vlan_mac_objs[2] = {NULL, NULL};
    u8_t                                  idx              = 0;
    u8_t                                  obj_idx          = 0;

    DbgMessage(pdev, INFORMl2sp, "lm_clear_all_mac_addr chain_idx=%d\n", chain_idx);

    vlan_mac_objs[0] = &pdev->client_info[chain_idx].mac_obj;
    vlan_mac_objs[1] = &pdev->client_info[chain_idx].mac_vlan_obj;

    for (obj_idx = 0; obj_idx < ARRSIZE(vlan_mac_objs); obj_idx++)
    {
        vlan_mac_obj = vlan_mac_objs[obj_idx];
        ramrod_params.vlan_mac_obj = vlan_mac_obj;

        /* mac_vlan_obj only relevant for chips that are not E1... */
        if ((vlan_mac_obj == &pdev->client_info[chain_idx].mac_vlan_obj) &&
            CHIP_IS_E1(pdev))
        {
            break;
        }

        for (idx = 0; idx < ARRSIZE(mac_types); idx++)
        {
            SET_BIT( ramrod_params.ramrod_flags, RAMROD_COMP_WAIT);
            ramrod_params.user_req.vlan_mac_flags = 0;
            if (mac_types[idx] != THE_REST_OF_ETH_MAC)
            {
                SET_BIT( ramrod_params.user_req.vlan_mac_flags, mac_types[idx]);
            }

            ecore_status = vlan_mac_obj->delete_all( pdev, ramrod_params.vlan_mac_obj, &ramrod_params.user_req.vlan_mac_flags, &ramrod_params.ramrod_flags );
            lm_status    = lm_ecore_status_to_lm_status(ecore_status);

            if (lm_status != LM_STATUS_SUCCESS)
            {
                DbgBreakIf(lm_status != LM_STATUS_SUCCESS);
                return lm_status;
            }

        }
    }

    DbgBreakIf(lm_status != LM_STATUS_SUCCESS);
    return lm_status;
}



/**
 * Description
 *      Restores all the mac address that are set on a certain
 *      cid (after sleep / hibernate...)
 * @param pdev
 * @param chain_idx - which chain_idx to clear macs on...
 *
 * @assumptions: Called in PASSIVE_LEVEL!! function sleeps...
 * @return lm_status_t
 */
lm_status_t lm_restore_all_mac_addr(struct _lm_device_t *pdev, u8_t chain_idx)
{
    struct ecore_vlan_mac_ramrod_params       ramrod_params = {0};
    struct ecore_vlan_mac_obj *               vlan_mac_obj  = &pdev->client_info[chain_idx].mac_obj;
    lm_status_t                               lm_status     = LM_STATUS_FAILURE;
    ecore_status_t                            ecore_status  = ECORE_SUCCESS;
    struct ecore_vlan_mac_registry_elem*      pos           = NULL;

    DbgMessage(pdev, INFORMl2sp, "lm_clear_all_mac_addr chain_idx=%d\n", chain_idx);

    ramrod_params.vlan_mac_obj = vlan_mac_obj;

    ECORE_SET_BIT(RAMROD_COMP_WAIT, &ramrod_params.ramrod_flags);

    do
    {
        ecore_status = vlan_mac_obj->restore(pdev, &ramrod_params, &pos);
        lm_status    = lm_ecore_status_to_lm_status(ecore_status);
        if (lm_status != LM_STATUS_SUCCESS)
        {
            DbgBreakIf(lm_status != LM_STATUS_SUCCESS);
            return lm_status;
        }
    }
    while (pos != NULL);

    /* Take care of the pairs and vlans as well... */
    if (!CHIP_IS_E1(pdev))
    {
        vlan_mac_obj = &pdev->client_info[chain_idx].mac_vlan_obj;
        ramrod_params.vlan_mac_obj = vlan_mac_obj;
        ECORE_SET_BIT(RAMROD_COMP_WAIT, &ramrod_params.ramrod_flags);

        pos = NULL;
        do
        {
            ecore_status = vlan_mac_obj->restore(pdev, &ramrod_params, &pos);
            lm_status    = lm_ecore_status_to_lm_status(ecore_status);
            if (lm_status != LM_STATUS_SUCCESS)
            {
                DbgBreakIf(lm_status != LM_STATUS_SUCCESS);
                return lm_status;
            }
        } while (pos != NULL);
    }

    if (!CHIP_IS_E1x(pdev))
    {
        vlan_mac_obj = &pdev->client_info[chain_idx].vlan_obj;
        ramrod_params.vlan_mac_obj = vlan_mac_obj;
        ECORE_SET_BIT(RAMROD_COMP_WAIT, &ramrod_params.ramrod_flags);

        pos = NULL;
        do
        {
            ecore_status = vlan_mac_obj->restore(pdev, &ramrod_params, &pos);
            lm_status    = lm_ecore_status_to_lm_status(ecore_status);
            if (lm_status != LM_STATUS_SUCCESS)
            {
                DbgBreakIf(lm_status != LM_STATUS_SUCCESS);
                return lm_status;
    }
        } while (pos != NULL);
    }

    DbgBreakIf(lm_status != LM_STATUS_SUCCESS);
    return lm_status;
}

/************************ RX FILTERING ***************************************/

/**
 * @Description
 *  - set/unset rx filtering for a client. The setting is done
 *    for RX + TX, since tx switching is enabled FW needs to
 *    know the configuration for tx filtering as well. The
 *    configuration is almost semmetric for rx / tx except for
 *    the case of promiscuous in which case rx is in
 *    accept_unmatched and Tx is in accept_all (meaning all
 *    traffic is sent to loopback channel)
 *
 * @Assumptions
 *  - An inter client lock is taken by the caller
 * @Return
 *  - Success / Pending or Failure
 */
lm_status_t
lm_set_rx_mask(lm_device_t *pdev, u8_t chain_idx, lm_rx_mask_t rx_mask,  void * cookie)
{
    struct ecore_rx_mode_ramrod_params ramrod_param    = {0};
    lm_cli_idx_t                       lm_cli_idx      = LM_CLI_IDX_MAX;
    unsigned long                      rx_accept_flags = 0;
    unsigned long                      tx_accept_flags = 0;
    lm_status_t                        lm_status       = LM_STATUS_SUCCESS;
    ecore_status_t                     ecore_status    = ECORE_SUCCESS;

    DbgMessage(pdev, INFORMl2sp, "lm_set_rx_mask chain_idx=%d rx_mask=%d\n", chain_idx, rx_mask);

    if (lm_reset_is_inprogress(pdev))
    {
        DbgMessage(pdev, FATAL, "lm_set_rx_mask: Under FLR!!!\n");
        return  LM_STATUS_SUCCESS;
    }
    #ifdef VF_INVOLVED
    if (IS_CHANNEL_VFDEV(pdev))
    {
        return lm_vf_pf_set_q_filters(pdev, chain_idx, FALSE, Q_FILTER_RX_MASK, (u8_t*)&rx_mask, sizeof(lm_rx_mask_t), LM_SET_CAM_NO_VLAN_FILTER, FALSE);
    }
    #endif

    if (!pdev->client_info[chain_idx].b_vlan_only_in_process &&
         pdev->client_info[chain_idx].last_set_rx_mask == rx_mask)
    {
        /* No need to send a filter that has already been set...
           return immediately */
        DbgMessage(pdev, INFORMl2sp, "lm_set_rx_mask returning immediately: mask didn't change!\n");
        return LM_STATUS_SUCCESS;
    }

    /* initialize accept flags in ECORE language */
    if (pdev->client_info[chain_idx].current_set_vlan == 0)
    {
        ECORE_SET_BIT_NA(ECORE_ACCEPT_ANY_VLAN, &rx_accept_flags);
        ECORE_SET_BIT_NA(ECORE_ACCEPT_ANY_VLAN, &tx_accept_flags);
        pdev->client_info[chain_idx].b_any_vlan_on = TRUE;
    }
    else
    {
        pdev->client_info[chain_idx].b_any_vlan_on = FALSE;
    }

    /* find the desired filtering configuration */
    if GET_FLAGS(rx_mask ,LM_RX_MASK_PROMISCUOUS_MODE)
    {
        ECORE_SET_BIT_NA(ECORE_ACCEPT_UNICAST, &rx_accept_flags);
        ECORE_SET_BIT_NA(ECORE_ACCEPT_UNMATCHED, &rx_accept_flags);
        ECORE_SET_BIT_NA(ECORE_ACCEPT_ALL_MULTICAST, &rx_accept_flags);
        ECORE_SET_BIT_NA(ECORE_ACCEPT_BROADCAST, &rx_accept_flags);

        ECORE_SET_BIT_NA(ECORE_ACCEPT_UNICAST, &tx_accept_flags);
        ECORE_SET_BIT_NA(ECORE_ACCEPT_ALL_MULTICAST, &tx_accept_flags);
        ECORE_SET_BIT_NA(ECORE_ACCEPT_BROADCAST, &tx_accept_flags);

        /* In NPAR + vm_switch_enable mode, we need to turn on the ACCEPT_ALL_UNICAST for TX to make
         * sure all traffic passes on the loopback channel to enable non-enlighted vms to communicate (vms that we don't
         * have their MAC set) .
         * We turn it on once we're in promiscuous, which signals that there is probablly vms up that need
         * this feature. */
        if (IS_MF_SI_MODE(pdev) && pdev->params.npar_vm_switching_enable)
        {
            ECORE_SET_BIT_NA(ECORE_ACCEPT_ALL_UNICAST, &tx_accept_flags);
        }

    }

    if GET_FLAGS(rx_mask ,LM_RX_MASK_ACCEPT_UNICAST)
    {
        /* accept matched ucast */
        ECORE_SET_BIT_NA(ECORE_ACCEPT_UNICAST, &rx_accept_flags);
        ECORE_SET_BIT_NA(ECORE_ACCEPT_UNICAST, &tx_accept_flags);
    }

    if GET_FLAGS(rx_mask ,LM_RX_MASK_ACCEPT_MULTICAST)
    {
        /* accept matched mcast */
        ECORE_SET_BIT_NA(ECORE_ACCEPT_MULTICAST, &rx_accept_flags);
        ECORE_SET_BIT_NA(ECORE_ACCEPT_MULTICAST, &tx_accept_flags);
    }

    if GET_FLAGS(rx_mask ,LM_RX_MASK_ACCEPT_ALL_MULTICAST)
    {
        /* accept all mcast */
        ECORE_SET_BIT_NA(ECORE_ACCEPT_ALL_MULTICAST, &rx_accept_flags);
        ECORE_SET_BIT_NA(ECORE_ACCEPT_ALL_MULTICAST, &tx_accept_flags);
    }

    if GET_FLAGS(rx_mask ,LM_RX_MASK_ACCEPT_BROADCAST)
    {
        /* accept matched bcast */
        ECORE_SET_BIT_NA(ECORE_ACCEPT_BROADCAST, &rx_accept_flags);
        ECORE_SET_BIT_NA(ECORE_ACCEPT_BROADCAST, &tx_accept_flags);
    }

    if GET_FLAGS(rx_mask ,LM_RX_MASK_ACCEPT_ERROR_PACKET)
    {
        /* TBD: there is no usage in Miniport for this flag */
    }

    /* Prepare ramrod parameters */
    ramrod_param.cid         = chain_idx; // echo..
    ramrod_param.cl_id       = LM_FW_CLI_ID(pdev, chain_idx);
    ramrod_param.rx_mode_obj = &pdev->slowpath_info.rx_mode_obj;
    ramrod_param.func_id     = FUNC_ID(pdev);

    ramrod_param.pstate      = (unsigned long *)&pdev->client_info[chain_idx].sp_rxmode_state;
    ramrod_param.state       = ECORE_FILTER_RX_MODE_PENDING;

    // We set in lm_cli_idx always 0 (LM_CLI_IDX_NDIS) for E1x and lm_cli_idx for e2.
    // LM_CLI_IDX_NDIS is an occasional choice and could be any of the LM_CLI_IDX
    //
    // * rx_mode_rdata PER INDEX is problematic because:
    //      the rx filtering is same place in internal ram of e1.5/e1.0 and when we work with an array
    //      each client run over the bits of the previous client
    //
    // * rx_mode_rdata NOT PER INDEX is problematic because:
    //      in e2.0 when we send a ramrod, the rdata is same memory for all
    //      clients and therefore in case of parallel run of rx_mask of clients
    //      one of the ramrods actually won't be sent with the correct data
    //
    // * Conclusion: we have here a problem which make a conflict that both E1.0/E1.5 and E2 work without issues.
    //               This issue should be resolved in a proper way which should be discussed.
    //
    // This note is related to the following two CQ's:
    // CQ53609 - eVBD:57712: evbda!lm_sq_complete+7ca; Assert is seen while running ACPI S1 S3 sleep stress test
    // CQ53444 - OIS Certs: iSCSI Ping Test Fails

    lm_cli_idx = CHIP_IS_E1x(pdev) ? LM_CLI_IDX_NDIS : LM_CHAIN_IDX_CLI(pdev, chain_idx);

    if(LM_CLI_IDX_MAX <= lm_cli_idx)
    {
        DbgBreakMsg(" lm_cli_idx has an invalid value");
        return LM_STATUS_FAILURE;
    }

    ramrod_param.rdata = LM_SLOWPATH(pdev, rx_mode_rdata)[lm_cli_idx];
    ramrod_param.rdata_mapping = LM_SLOWPATH_PHYS(pdev, rx_mode_rdata)[lm_cli_idx];

    ECORE_SET_BIT(ECORE_FILTER_RX_MODE_PENDING, &pdev->client_info[chain_idx].sp_rxmode_state);
    ECORE_SET_BIT(RAMROD_RX, &ramrod_param.ramrod_flags);
    ECORE_SET_BIT(RAMROD_TX, &ramrod_param.ramrod_flags);

    ramrod_param.rx_mode_flags = 0; // FIXME ...
    ramrod_param.rx_accept_flags = rx_accept_flags;
    ramrod_param.tx_accept_flags = tx_accept_flags;

    /* Must be set before the ramrod... */
    DbgBreakIf(pdev->client_info[chain_idx].set_rx_mode_cookie != NULL);
    pdev->client_info[chain_idx].last_set_rx_mask = rx_mask;
    pdev->client_info[chain_idx].set_rx_mode_cookie = cookie;

    ecore_status = ecore_config_rx_mode(pdev, &ramrod_param);
    lm_status    = lm_ecore_status_to_lm_status(ecore_status);
    DbgMessage(pdev, INFORMl2sp, "Status returned from ecore_config_rx_mode: %d\n", lm_status);
    if (lm_status == LM_STATUS_SUCCESS)
    {
        pdev->client_info[chain_idx].set_rx_mode_cookie = NULL;
    }
    else if (lm_status == LM_STATUS_REQUEST_NOT_ACCEPTED)
    {
        /* Sq is blocked... meaning we're in error recovery, this is our one outstanding oid.
         * mark ecore as done, return PENDING to UM, don't clear cookie. This means miniport
         * will eventually get a completion as part of the re-initialization of the chip... */
        ECORE_CLEAR_BIT(ECORE_FILTER_RX_MODE_PENDING, &pdev->client_info[chain_idx].sp_rxmode_state);
    }

    return lm_status;
} /* lm_set_rx_mask */

/* Waits for the set=-rx-mode to complete*/
lm_status_t lm_wait_set_rx_mask_done(struct _lm_device_t *pdev, u8_t chain_idx)
{
    struct ecore_rx_mode_ramrod_params params = {0};
    lm_status_t lm_status;

    params.pstate = (unsigned long *)&pdev->client_info[chain_idx].sp_rxmode_state;
    params.state = ECORE_FILTER_RX_MODE_PENDING;

    lm_status = pdev->slowpath_info.rx_mode_obj.wait_comp(pdev, &params);
    DbgBreakIf(lm_status != LM_STATUS_SUCCESS);

    return lm_status;
}


/*************************  MULTICAST  *****************************************/
static INLINE lm_status_t _init_mcast_macs_list(lm_device_t *pdev,
                                                 u8_t*        mc_addrs,
                                                 u32_t        buf_len,
                                                 struct ecore_mcast_ramrod_params *p)
{
    u8                            mc_count = buf_len / ETHERNET_ADDRESS_SIZE;
    struct ecore_mcast_list_elem *mc_mac   = NULL;

    mc_mac = mm_rt_alloc_mem(pdev, sizeof(*mc_mac) * mc_count, 0);

    if (!mc_addrs) {
        return LM_STATUS_INVALID_PARAMETER;
    }

    d_list_clear(&p->mcast_list);

    while(buf_len && mc_addrs)
    {
        mc_mac->mac = mc_addrs;
        DbgMessage(pdev, INFORMl2sp, "mc_addrs[%d]:mc_addrs[%d]:mc_addrs[%d]:mc_addrs[%d]:mc_addrs[%d]:mc_addrs[%d]\n",
                   mc_addrs[0],mc_addrs[1],mc_addrs[2],mc_addrs[3],mc_addrs[4],mc_addrs[5]);
        d_list_push_tail(&p->mcast_list, &mc_mac->link);
        /* move on to next mc addr */
        buf_len -= ETHERNET_ADDRESS_SIZE;
        mc_addrs += ETHERNET_ADDRESS_SIZE;
        mc_mac++;
    }

    p->mcast_list_len = mc_count;

    return LM_STATUS_SUCCESS;
}

static INLINE void __free_mcast_macs_list(lm_device_t *pdev,
                                          struct ecore_mcast_ramrod_params *p)
{
    struct ecore_mcast_list_elem *mc_mac = NULL;
    mc_mac = (struct ecore_mcast_list_elem *)d_list_peek_head(&p->mcast_list);

    if (mc_mac)
    {
        /* note that p->mcast_list_len is now set to 0 after processing */
        mm_rt_free_mem(pdev, mc_mac, sizeof(*mc_mac) * d_list_entry_cnt(&p->mcast_list), 0);
    }
}

/**
 * @Description
 *      Function configures a list of multicast addresses. Or
 *      resets the list previously configured
 *
 * @param pdev
 * @param mc_addrs    - array of multicast addresses. NULL if unset is required
 * @param buf_len     - length of the buffer - 0 if unset is required
 * @param cookie      - will be returned on completion
 * @param lm_cli_idx  - which lm client to send request on
 *
 * @return lm_status_t - SUCCESS on syncrounous completion
 *                       PENDING on asyncounous completion
 *                       FAILURE o/w
 */
lm_status_t lm_set_mc(struct _lm_device_t *pdev,
                      u8_t*  mc_addrs, /* may be NULL (for unset) */
                      u32_t  buf_len,  /* may be 0 (for unset) */
                      void * cookie,  lm_cli_idx_t lm_cli_idx)
{
    struct ecore_mcast_ramrod_params rparam       = {0};
    lm_status_t                      lm_status    = LM_STATUS_SUCCESS;
    ecore_status_t                   ecore_status = ECORE_SUCCESS;

#ifdef VF_INVOLVED
    if (IS_CHANNEL_VFDEV(pdev)) {
        return lm_vf_pf_set_q_filters(pdev, lm_cli_idx, cookie, Q_FILTER_MC, mc_addrs, buf_len, LM_SET_CAM_NO_VLAN_FILTER, FALSE);
    }
#endif

    if(0 == LM_MC_TABLE_SIZE(pdev,lm_cli_idx))
    {
        DbgBreakMsg("size must be greater than zero for a valid client\n");
        return LM_STATUS_FAILURE;
    }


    /* Initialize params sent to ecore layer */
    /* Need to split to groups of 16 for E2... due to hsi restraint*/
    if (mc_addrs)
    {
        _init_mcast_macs_list(pdev, mc_addrs, buf_len, &rparam);
    }
    rparam.mcast_obj = &pdev->slowpath_info.mcast_obj[lm_cli_idx];

    /* Cookie must be set before sending the ramord, since completion could arrive before
     * we return and the cookie must be in place*/
    DbgBreakIf(pdev->slowpath_info.set_mcast_cookie[lm_cli_idx] != NULL);
    pdev->slowpath_info.set_mcast_cookie[lm_cli_idx] = cookie;

    ecore_status = ecore_config_mcast(pdev, &rparam, (mc_addrs != NULL)? ECORE_MCAST_CMD_ADD : ECORE_MCAST_CMD_DEL);
    lm_status    = lm_ecore_status_to_lm_status(ecore_status);
    if (lm_status == LM_STATUS_SUCCESS)
    {
        pdev->slowpath_info.set_mcast_cookie[lm_cli_idx] = NULL;
        }

    if (mc_addrs)
    {
        __free_mcast_macs_list(pdev, &rparam);
    }

    return lm_status;
} /* lm_set_mc */

lm_status_t lm_set_mc_list(struct _lm_device_t *pdev,
                           d_list_t * mc_addrs, /* may be NULL (for unset) */
                           void * cookie,
                           lm_cli_idx_t lm_cli_idx)
{
    struct ecore_mcast_ramrod_params rparam       = {0};
    lm_status_t                      lm_status    = LM_STATUS_SUCCESS;
    ecore_status_t                   ecore_status = ECORE_SUCCESS;

#ifdef VF_INVOLVED
    if (IS_CHANNEL_VFDEV(pdev))
    {
        return lm_vf_pf_set_q_filters_list(pdev, lm_cli_idx, cookie,
                                      Q_FILTER_MC, mc_addrs,
                                      LM_SET_CAM_NO_VLAN_FILTER, FALSE);
    }
#endif

    rparam.mcast_list = *mc_addrs;
    rparam.mcast_list_len = d_list_entry_cnt(mc_addrs);

    rparam.mcast_obj = &pdev->slowpath_info.mcast_obj[lm_cli_idx];

    /* Cookie must be set before sending the ramord, since completion could arrive before
     * we return and the cookie must be in place*/
    DbgBreakIf(pdev->slowpath_info.set_mcast_cookie[lm_cli_idx] != NULL);
    pdev->slowpath_info.set_mcast_cookie[lm_cli_idx] = cookie;

    ecore_status = ecore_config_mcast(pdev, &rparam,
                                      (mc_addrs != NULL) ? ECORE_MCAST_CMD_ADD :
                                                           ECORE_MCAST_CMD_DEL);

    lm_status = lm_ecore_status_to_lm_status(ecore_status);
    if (lm_status == LM_STATUS_SUCCESS)
    {
        pdev->slowpath_info.set_mcast_cookie[lm_cli_idx] = NULL;
    }

    return lm_status;
}

/**
 * Description
 *      This routine is called to wait for the multicast set
 *      completion. It must be called in passive level since it
 *      may sleep
 * @param pdev
 * @param lm_cli_idx the cli-idx that the multicast was sent on.
 *
 * @return lm_status SUCCESS on done, TIMEOUT o/w
 */
lm_status_t lm_wait_set_mc_done(struct _lm_device_t *pdev, lm_cli_idx_t lm_cli_idx)
{
    struct ecore_mcast_obj * mcast_obj    = &pdev->slowpath_info.mcast_obj[lm_cli_idx];
    ecore_status_t           ecore_status = mcast_obj->wait_comp(pdev, mcast_obj);
    lm_status_t              lm_status    = lm_ecore_status_to_lm_status(ecore_status);

    return lm_status;
}

/*************************  RSS ***********************************************/

/**
 * Description: update RSS key in slowpath
 * Assumptions:
 *  - given key_size is promised to be either 40 or 16 (promised by NDIS)
 * Return:
 */

/**
 * @Description: Update RSS key in driver rss_hash_key array and
 *             check if it has changed from previous key.
 *
 * @param pdev
 * @param hash_key  - hash_key received from NDIS
 * @param key_size
 *
 * @return u8_t     TRUE if changed, FALSE o/w
 */
static u8_t lm_update_rss_key(struct _lm_device_t *pdev, u8_t *hash_key,
                                     u32_t key_size)
{
    u32_t val        = 0;
    u32_t i          = 0;
    s32_t rss_reg    = 0;
    u8_t key_changed = FALSE;

    /* check params */
    if ERR_IF(!(pdev && hash_key))
    {
        DbgBreak();
        return LM_STATUS_INVALID_PARAMETER;
    }

    /* Note: MSB (that is hash_key[0]) should be placed in MSB of register KEYRSS9, regardless the key size */
    /* GilR 4/4/2007 - assert on key_size==16/40? */
    for (rss_reg = 9, i = 0; rss_reg >= 0; rss_reg--)
    {
        val = 0;
        if (i < key_size)
        {
            val = ((hash_key[i] << 24) | (hash_key[i+1] << 16) | (hash_key[i+2] << 8) | hash_key[i+3]);
            DbgMessage(pdev, INFORMl2sp,
                        "KEYRSS[%d:%d]=0x%x, written to RSS_REG=%d\n",
                        i, i+3, val, rss_reg);
            i += 4;
        }
        else
        {
            DbgMessage(pdev, INFORMl2sp,
                        "OUT OF KEY size, writing 0x%x to RSS_REG=%d\n",
                        val, rss_reg);
        }
        if (pdev->slowpath_info.rss_hash_key[rss_reg] != val)
        { /* key changed */
            pdev->slowpath_info.rss_hash_key[rss_reg] = val;
            key_changed = TRUE;
        }
    }

    if (key_changed)
    {
        DbgMessage(pdev, WARNl2, "update rss: KEY CHANGED\n");
    }

    return key_changed;
}

/**
 * @Description
 *      Enable RSS for Eth with given indirection table also updates the rss key
 *      in searcher (for previous chips...- done by sp-verbs)
 *
 * @Assumptions
 *  - given table_size is promised to be power of 2 (promised by NDIS),
 *    or 1 in case of RSS disabling
 *  - the indices in the given chain_indirection_table are chain
 *    indices converted by UM layer...
 *  - given key_size is promised to be either 40 or 16 (promised by NDIS)
 *
 * @param pdev
 * @param chain_indirection_table - array of size @table_size containing chain numbers
 * @param table_size - size of @indirection_table
 * @param hash_key - new hash_key to be configured. 0 means no key
 * @param key_size
 * @param hash_type
 * @param sync_with_toe - This field indicates that the completion to the mm layer
 *                        should take into account the fact that toe rss update will
 *                        be sent as well. A counter will be increased in lm for this purpose
 * @param cookie        - will be returned on completion
 *
 * @return lm_status_t - SUCCESS on syncrounous completion
 *                       PENDING on asyncounous completion
 *                       FAILURE o/w
 */
lm_status_t lm_enable_rss(struct _lm_device_t *pdev, u8_t *chain_indirection_table,
                          u32_t table_size, u8_t *hash_key, u32_t key_size, lm_rss_hash_t hash_type,
                          u8 sync_with_toe, void * cookie)
{
    struct ecore_config_rss_params params      = {0};
    lm_status_t                    lm_status   = LM_STATUS_SUCCESS;
    ecore_status_t                 ecore_status = ECORE_SUCCESS;
    u8_t                           value       = 0;
    u8_t                           reconfigure = FALSE;
    u8_t                           key_changed = FALSE;
    u8_t                           i           = 0;

    /* check params */
    if ERR_IF(!(pdev && chain_indirection_table))
    {
        DbgBreak();
        return LM_STATUS_INVALID_PARAMETER;
    }

    if (hash_type &
        ~(LM_RSS_HASH_IPV4 | LM_RSS_HASH_TCP_IPV4 | LM_RSS_HASH_IPV6 | LM_RSS_HASH_TCP_IPV6))
    {
        return LM_STATUS_INVALID_PARAMETER;
    }

    params.rss_obj = &pdev->slowpath_info.rss_conf_obj;

    /* RSS mode */
    /* Fixme --> anything else ?*/
    ECORE_SET_BIT(ECORE_RSS_MODE_REGULAR, &params.rss_flags);

    /* Translate the hash type to "ecore" */
    if (GET_FLAGS(hash_type, LM_RSS_HASH_IPV4))
    {
        ECORE_SET_BIT(ECORE_RSS_IPV4, &params.rss_flags);
    }
    if (GET_FLAGS(hash_type, LM_RSS_HASH_TCP_IPV4))
    {
        ECORE_SET_BIT(ECORE_RSS_IPV4_TCP, &params.rss_flags);
    }
    if (GET_FLAGS(hash_type, LM_RSS_HASH_IPV6))
    {
        ECORE_SET_BIT(ECORE_RSS_IPV6, &params.rss_flags);
    }
    if (GET_FLAGS(hash_type, LM_RSS_HASH_TCP_IPV6))
    {
        ECORE_SET_BIT(ECORE_RSS_IPV6_TCP, &params.rss_flags);
    }

    if (pdev->slowpath_info.last_set_rss_flags != params.rss_flags)
    {
        pdev->slowpath_info.last_set_rss_flags = params.rss_flags;
        reconfigure = TRUE;
    }

    /* set rss result mask according to table size
       (table_size is promised to be power of 2) */
    params.rss_result_mask = (u8_t)table_size - 1;
    if (pdev->slowpath_info.last_set_rss_result_mask != params.rss_result_mask)
    {
        /* Hash bits */
        pdev->slowpath_info.last_set_rss_result_mask = params.rss_result_mask;
        reconfigure = TRUE;
    }

    for (i = 0; i < table_size; i++)
    {

        value = LM_CHAIN_TO_FW_CLIENT(pdev,chain_indirection_table[i]);

        if (pdev->slowpath_info.last_set_indirection_table[i] != value)
        {
            DbgMessage(pdev, INFORMl2sp, "RssIndTable[%02d]=0x%x (Changed from 0x%x)\n", i, value, pdev->slowpath_info.last_set_indirection_table[i]);
            pdev->slowpath_info.last_set_indirection_table[i] = value;
            reconfigure = TRUE;
        }
    }
    mm_memcpy(params.ind_table, pdev->slowpath_info.last_set_indirection_table, sizeof(params.ind_table));

    if (hash_key)
    {
        key_changed = lm_update_rss_key(pdev, hash_key, key_size);
        if (key_changed)
        {
            reconfigure = TRUE;
        }
        mm_memcpy(params.rss_key, pdev->slowpath_info.rss_hash_key, sizeof(params.rss_key));
        ECORE_SET_BIT(ECORE_RSS_SET_SRCH, &params.rss_flags);
    }

    DbgBreakIf(!reconfigure && sync_with_toe);
    /* Not expected, that toe will update and ETH not, but just to make sure, if sync_with_toe
     * is true it means toe reconfigured... so eth must to to take care of sync... */
    if (reconfigure || sync_with_toe)
    {
        /* If we're not syncing with toe, it means that these counters have not
         * been increased by toe, and need to be increased here. */
        if (!sync_with_toe)
        {
            DbgBreakIf(pdev->params.update_comp_cnt);
            mm_atomic_inc(&pdev->params.update_comp_cnt);
            mm_atomic_inc(&pdev->params.update_suspend_cnt);
        }

        DbgBreakIf(pdev->slowpath_info.set_rss_cookie);
        pdev->slowpath_info.set_rss_cookie = cookie;
#ifdef VF_INVOLVED
        if (IS_CHANNEL_VFDEV(pdev))
        {
            lm_status = lm_vf_pf_update_rss(pdev, NULL, params.rss_flags, params.rss_result_mask, params.ind_table, params.rss_key);
            if (lm_status == LM_STATUS_SUCCESS)
            {
                lm_status = lm_vf_pf_wait_no_messages_pending(pdev);
                mm_atomic_dec(&pdev->params.update_comp_cnt);
                mm_atomic_dec(&pdev->params.update_suspend_cnt);

            }
        }
        else
#endif
        {
            ecore_status = ecore_config_rss(pdev, &params);
            lm_status    = lm_ecore_status_to_lm_status(ecore_status);
        }
        if (lm_status == LM_STATUS_SUCCESS)
        {
            lm_status = LM_STATUS_PENDING;
        }
    }

    return lm_status;
}


/**
 * @Description
 *      This routine disables rss functionality by sending a
 *      ramrod to FW.
 *
 * @param pdev
 * @param cookie - will be returned on completion
 * @param sync_with_toe - true means this call is synced with
 *                      toe, and completion will be called only
 *                      when both toe + eth complete. Eth needs
 *                      to know this (reason in code) *
 *
 * @return lm_status_t - SUCCESS on syncrounous completion
 *                       PENDING on asyncounous completion
 *                       FAILURE o/w
 */
lm_status_t lm_disable_rss(struct _lm_device_t *pdev, u8_t sync_with_toe, void * cookie)
{
    struct ecore_config_rss_params params       = {0};
    lm_status_t                    lm_status    = LM_STATUS_FAILURE;
    ecore_status_t                 ecore_status = ECORE_SUCCESS;
    u8_t                           value        = 0;
    u8_t                           i            = 0;

    DbgMessage(pdev, INFORMl2sp, "lm_disable_rss sync_with_toe = %d\n", sync_with_toe);

    DbgBreakIf(pdev->slowpath_info.set_rss_cookie);
    pdev->slowpath_info.set_rss_cookie = cookie;

    params.rss_obj = &pdev->slowpath_info.rss_conf_obj;

    /* RSS mode */
    ECORE_SET_BIT(ECORE_RSS_MODE_DISABLED, &params.rss_flags);
    pdev->slowpath_info.last_set_rss_flags = params.rss_flags;

    /* If we're not syncing with toe, it means that these counters have not
     * been increased by toe, and need to be increased here. */
    if (!sync_with_toe)
    {
        mm_atomic_inc(&pdev->params.update_comp_cnt);
        mm_atomic_inc(&pdev->params.update_suspend_cnt);
    }

    value = LM_CHAIN_TO_FW_CLIENT(pdev,LM_SW_LEADING_RSS_CID(pdev));
    for (i = 0; i < ARRSIZE(params.ind_table); i++)
    {
        pdev->slowpath_info.last_set_indirection_table[i] = value;
        params.ind_table[i] = value;
    }

#ifdef VF_INVOLVED
    if (IS_CHANNEL_VFDEV(pdev))
    {
        lm_status = lm_vf_pf_update_rss(pdev, NULL, params.rss_flags, params.rss_result_mask, params.ind_table, params.rss_key);
        if (lm_status == LM_STATUS_SUCCESS)
        {
            lm_status = lm_vf_pf_wait_no_messages_pending(pdev);
            mm_atomic_dec(&pdev->params.update_comp_cnt);
            mm_atomic_dec(&pdev->params.update_suspend_cnt);
        }
    }
    else
#endif
    {
        ecore_status = ecore_config_rss(pdev, &params);
        lm_status    = lm_ecore_status_to_lm_status(ecore_status);
    }

    if (lm_status == LM_STATUS_SUCCESS)
    {
        lm_status = LM_STATUS_PENDING;
    }
    return lm_status;

} /* lm_disable_rss */

/**
 * @Description
 *      Wait for the rss disable/enable configuration to
 *      complete
 *
 * @param pdev
 *
 * @return lm_status_t lm_status_t SUCCESS or TIMEOUT
 */
lm_status_t lm_wait_config_rss_done(struct _lm_device_t *pdev)
{
    struct ecore_raw_obj   *raw         = &pdev->slowpath_info.rss_conf_obj.raw;
    lm_status_t            lm_status    = LM_STATUS_FAILURE;
    ecore_status_t         ecore_status = raw->wait_comp(pdev, raw);

    lm_status = lm_ecore_status_to_lm_status(ecore_status);

    return lm_status;
}

#ifdef VF_INVOLVED
lm_status_t lm_wait_vf_config_rss_done(struct _lm_device_t *pdev, lm_vf_info_t *vf_info)
{
    struct ecore_raw_obj *raw = &vf_info->vf_slowpath_info.rss_conf_obj.raw;
    lm_status_t            lm_status    = LM_STATUS_FAILURE;
    ecore_status_t         ecore_status = raw->wait_comp(pdev, raw);

    lm_status = lm_ecore_status_to_lm_status(ecore_status);

    return lm_status;
}
#endif

/************************** EQ HANDLING *******************************************/

static INLINE void lm_eq_handle_function_start_eqe(struct _lm_device_t * pdev, union event_ring_elem * elem)
{
    pdev->eq_info.function_state = FUNCTION_START_COMPLETED;
    lm_sq_complete(pdev, CMD_PRIORITY_NORMAL, RAMROD_CMD_ID_COMMON_FUNCTION_START,
                   NONE_CONNECTION_TYPE, 0);
}

static INLINE void lm_eq_handle_function_stop_eqe(struct _lm_device_t * pdev, union event_ring_elem * elem)
{
    pdev->eq_info.function_state = FUNCTION_STOP_COMPLETED;
    lm_sq_complete(pdev, CMD_PRIORITY_NORMAL, RAMROD_CMD_ID_COMMON_FUNCTION_STOP,
                   NONE_CONNECTION_TYPE, 0);

}

static INLINE void lm_eq_handle_cfc_del_eqe(struct _lm_device_t * pdev, union event_ring_elem * elem)
{
    u32_t cid   = 0;
    u8_t  error = 0;

    cid = mm_le32_to_cpu(elem->message.data.cfc_del_event.cid);
    cid = SW_CID(cid);

    error = elem->message.error;

    if (cid < pdev->context_info->proto_start[TOE_CONNECTION_TYPE]) //(MAX_ETH_CONS + MAX_VF_ETH_CONS))
    {   /* cfc del completion for eth cid */
        DbgBreakIf(lm_get_con_state(pdev, cid) != LM_CON_STATE_TERMINATE);
        lm_set_con_state(pdev, cid, LM_CON_STATE_CLOSE);
        DbgMessage(pdev, WARNeq, "lm_service_eq_intr: EVENT_RING_OPCODE_CFC_DEL_WB - calling lm_extract_ramrod_req!\n");
    }
    else
    {   /* cfc del completion for toe cid */
        if (error) {

            if (lm_map_cid_to_proto(pdev, cid) != TOE_CONNECTION_TYPE)
            {
                DbgMessage(pdev, FATAL, "ERROR completion is not valid for cid=0x%x\n",cid);
                DbgBreakIfAll(1);
            }
            pdev->toe_info.stats.total_cfc_delete_error++;
            if (pdev->context_info->array[cid].cfc_delete_cnt++ < LM_MAX_VALID_CFC_DELETIONS)
            {
                DbgMessage(pdev, WARNl4sp, "lm_eth_comp_cb: RAMROD_CMD_ID_ETH_CFC_DEL(0x%x) - %d resending!\n", cid,
                            pdev->context_info->array[cid].cfc_delete_cnt);
                lm_command_post(pdev,
                                cid,
                                RAMROD_CMD_ID_COMMON_CFC_DEL,
                                CMD_PRIORITY_NORMAL,
                                NONE_CONNECTION_TYPE,
                                0 );
            }
            else
            {
                DbgMessage(pdev, FATAL, "A number of CFC deletions exceeded valid number of attempts\n");
                DbgBreakIfAll(1);
            }
        }
        else
        {
            lm_recycle_cid(pdev, cid);
        }
    }

    lm_sq_complete(pdev, CMD_PRIORITY_NORMAL,
                   (elem->message.opcode == EVENT_RING_OPCODE_CFC_DEL)? RAMROD_CMD_ID_COMMON_CFC_DEL : RAMROD_CMD_ID_COMMON_CFC_DEL_WB,
                   NONE_CONNECTION_TYPE, cid);
}

static INLINE void lm_eq_handle_fwd_setup_eqe(struct _lm_device_t * pdev, union event_ring_elem * elem)
{
    DbgBreakIf(lm_get_con_state(pdev, FWD_CID(pdev)) != LM_CON_STATE_OPEN_SENT);
    lm_set_con_state(pdev, FWD_CID(pdev), LM_CON_STATE_OPEN);

    DbgMessage(pdev, WARNl2sp, "comp of FWD SETUP -calling lm_extract_ramrod_req!\n");
    lm_sq_complete(pdev, CMD_PRIORITY_NORMAL, RAMROD_CMD_ID_ETH_FORWARD_SETUP,
                   ETH_CONNECTION_TYPE, FWD_CID(pdev));

}

static INLINE void lm_eq_handle_mcast_eqe(struct _lm_device_t * pdev, union event_ring_elem * elem)
{
    struct ecore_mcast_ramrod_params  rparam         = {0};
    void                            * cookie         = NULL;
    lm_status_t                       lm_status      = LM_STATUS_FAILURE;
    ecore_status_t                    ecore_status   = ECORE_SUCCESS;
    u32_t                             cid            = mm_le32_to_cpu(elem->message.data.eth_event.echo) & ECORE_SWCID_MASK;
    const u8_t                        lm_cli_idx     = LM_CHAIN_IDX_CLI(pdev, cid);
    struct ecore_mcast_obj          * obj            = &pdev->slowpath_info.mcast_obj[lm_cli_idx];
    u8_t                              indicate_done  = TRUE;

    if(LM_CLI_IDX_MAX <= lm_cli_idx)
    {
        DbgBreakMsg(" lm_eq_handle_mcast_eqe lm_cli_idx is invalid ");
        return;
    }

    /* Clear pending state for the last command */
    obj->raw.clear_pending(&obj->raw);

    rparam.mcast_obj = obj;

    /* If there are pending mcast commands - send them */
    if (obj->check_pending(obj))
    {
        ecore_status = ecore_config_mcast(pdev, &rparam, ECORE_MCAST_CMD_CONT);
        lm_status    = lm_ecore_status_to_lm_status(ecore_status);
        if (lm_status == LM_STATUS_PENDING)
        {
            indicate_done = FALSE;
        }
        else if (lm_status != LM_STATUS_SUCCESS)
        {
            DbgMessage(pdev, FATAL, "Failed to send pending mcast commands: %d\n", lm_status);
            DbgBreakMsg("Unexpected pending mcast command failed\n");
        }
    }

    if (indicate_done)
    {
        if (pdev->slowpath_info.set_mcast_cookie[lm_cli_idx])
        {
            cookie = (void *)pdev->slowpath_info.set_mcast_cookie[lm_cli_idx];
            pdev->slowpath_info.set_mcast_cookie[lm_cli_idx] = NULL;
            mm_set_done(pdev, cid, cookie);
        }
    }

    if (CHIP_IS_E1(pdev))
    {
        lm_sq_complete(pdev, CMD_PRIORITY_NORMAL, RAMROD_CMD_ID_ETH_SET_MAC,
                       ETH_CONNECTION_TYPE, cid);
    }
    else
    {
        lm_sq_complete(pdev, CMD_PRIORITY_NORMAL, RAMROD_CMD_ID_ETH_MULTICAST_RULES,
                       ETH_CONNECTION_TYPE, cid);
    }
}

static INLINE void lm_eq_handle_classification_eqe(struct _lm_device_t * pdev, union event_ring_elem * elem)
{
    struct ecore_raw_obj        *raw                 = NULL;
    void                        *cookie              = NULL;
    u32_t                       cid                  = GET_FLAGS( mm_le32_to_cpu(elem->message.data.eth_event.echo), ECORE_SWCID_MASK );
    u8_t                        type                 = mm_le32_to_cpu(elem->message.data.eth_event.echo) >> ECORE_SWCID_SHIFT;
    u32_t                       client_info_idx      = 0;
    struct ecore_vlan_mac_obj*  p_ecore_vlan_mac_obj = NULL;
    unsigned long               ramrod_flags         = 0;
    ecore_status_t              ecore_status         = ECORE_SUCCESS;
    int i;

    client_info_idx = lm_get_sw_client_idx_from_cid(pdev,cid);

    /* Relevant to 57710, mcast is implemented as "set-macs"*/
    if (type == ECORE_FILTER_MCAST_PENDING)
    {
        DbgBreakIf(!CHIP_IS_E1(pdev));
        lm_eq_handle_mcast_eqe(pdev, elem);
        return;
    }

    switch (type)
    {
    case ECORE_FILTER_MAC_PENDING:
        raw                  = &pdev->client_info[client_info_idx].mac_obj.raw;
        p_ecore_vlan_mac_obj = &pdev->client_info[client_info_idx].mac_obj;
        break;
    case ECORE_FILTER_VLAN_MAC_PENDING:
        raw                  = &pdev->client_info[client_info_idx].mac_vlan_obj.raw;
        p_ecore_vlan_mac_obj = &pdev->client_info[client_info_idx].mac_vlan_obj;
        break;
    case ECORE_FILTER_VLAN_PENDING:
        raw = &pdev->client_info[client_info_idx].vlan_obj.raw;
        p_ecore_vlan_mac_obj = &pdev->client_info[client_info_idx].vlan_obj;
        SET_BIT( ramrod_flags, RAMROD_CONT );
        break;
    default:
        /* unknown ER handling*/
        /* Special handling for case that type is unknown (error recovery flow)
         * check which object is pending, and clear the relevant one. */
        raw                  = &pdev->client_info[client_info_idx].mac_obj.raw;
        p_ecore_vlan_mac_obj = &pdev->client_info[client_info_idx].mac_obj;
        type                 = ECORE_FILTER_MAC_PENDING;
        if (!raw->check_pending(raw))
        {
            raw                  = &pdev->client_info[client_info_idx].mac_vlan_obj.raw;
            p_ecore_vlan_mac_obj = &pdev->client_info[client_info_idx].mac_vlan_obj;
            type                 = ECORE_FILTER_VLAN_MAC_PENDING;
        }
        if (!raw->check_pending(raw))
        {
            raw                  = &pdev->client_info[client_info_idx].vlan_obj.raw;
            p_ecore_vlan_mac_obj = &pdev->client_info[client_info_idx].vlan_obj;
            type                 = ECORE_FILTER_VLAN_PENDING;
        }
        break;
    }

    ecore_status = p_ecore_vlan_mac_obj->complete( pdev, p_ecore_vlan_mac_obj, elem, &ramrod_flags );

    // We expect here only these 2 status (CQ61418)
    DbgBreakIf ( ( ECORE_SUCCESS != ecore_status ) && ( ECORE_PENDING != ecore_status ) );

    if (( ECORE_SUCCESS != ecore_status ) && (!CHIP_IS_E1x(pdev)))
    {
        DbgMessage(pdev, WARN,
        "lm_eq_handle_classification_eqe: commands' length is above CLASSIFY_RULES_COUNT (the maximum length of commands' list for one execution), ecore_status = %d", ecore_status);
    }

    // verify that the mac_local mac_add1 & mac_add2 are continuous
    ASSERT_STATIC( OFFSETOF( eth_stats_info_t, mac_local )+ sizeof(pdev->vars.stats.stats_mirror.stats_drv.drv_info_to_mfw.eth_stats.mac_local) ==  OFFSETOF( eth_stats_info_t, mac_add1 ) );
    ASSERT_STATIC( OFFSETOF( eth_stats_info_t, mac_add1 ) + sizeof(pdev->vars.stats.stats_mirror.stats_drv.drv_info_to_mfw.eth_stats.mac_add1) ==   OFFSETOF( eth_stats_info_t, mac_add2 ) );

    if( (NDIS_CID(pdev) == client_info_idx) && (type == ECORE_FILTER_MAC_PENDING) )
    {
        if ( NULL == p_ecore_vlan_mac_obj->get_n_elements )
        {
            DbgBreakIf( !CHIP_IS_E1x(pdev) );
        }
        else
        {
            // We want to keep only eth mac this is for E3 only but we keep it anyway also for E2...
            for (i = 0; i < 3; i++)
                mm_mem_zero(pdev->vars.stats.stats_mirror.stats_drv.drv_info_to_mfw.eth_stats.mac_local + i, sizeof(u8_t));
            p_ecore_vlan_mac_obj->get_n_elements(pdev, p_ecore_vlan_mac_obj ,3, pdev->vars.stats.stats_mirror.stats_drv.drv_info_to_mfw.eth_stats.mac_local + MAC_PAD, MAC_PAD, ETH_ALEN);
        }
    }

    if (pdev->client_info[client_info_idx].set_mac_cookie)
    {
        cookie = (void *)pdev->client_info[client_info_idx].set_mac_cookie;
        pdev->client_info[client_info_idx].set_mac_cookie = NULL;
        mm_set_done(pdev, cid, cookie);
    }

    if (CHIP_IS_E1x(pdev))
    {
        lm_sq_complete(pdev, CMD_PRIORITY_NORMAL,
                       RAMROD_CMD_ID_ETH_SET_MAC, ETH_CONNECTION_TYPE, cid);
    }
    else
    {
        lm_sq_complete(pdev, CMD_PRIORITY_NORMAL,
                       RAMROD_CMD_ID_ETH_CLASSIFICATION_RULES, ETH_CONNECTION_TYPE, cid);
    }
}

static INLINE void lm_eq_handle_stats_eqe(struct _lm_device_t * pdev, union event_ring_elem * elem)
{
    /* Order is important!!!
     * stats use a predefined ramrod. We need to make sure that we first complete the ramrod, which will
     * take it out of sq-completed list, and only after that mark the ramrod as completed, so that a new
     * ramrod can be sent!.
     */
    lm_sq_complete(pdev, CMD_PRIORITY_HIGH,
                   RAMROD_CMD_ID_COMMON_STAT_QUERY, NONE_CONNECTION_TYPE, 0);

    mm_write_barrier(); /* barrier to make sure command before this line completes before executing the next line! */
    pdev->vars.stats.stats_collect.stats_fw.b_ramrod_completed = TRUE;

}

static INLINE void lm_eq_handle_filter_rules_eqe(struct _lm_device_t * pdev, union event_ring_elem * elem)
{
    struct ecore_vlan_mac_ramrod_params p;
    void  * cookie = NULL;
    u32_t   cid    = 0;

    cid = mm_le32_to_cpu(elem->message.data.eth_event.echo) & ECORE_SWCID_MASK;

    DbgMessage(pdev, INFORMeq | INFORMl2sp, "Filter rule completion: cid %d, client_info %d\n",cid);

    // FIXME: pdev->client_info[cid].mac_obj.raw.clear_pending(&pdev->client_info[cid].mac_obj.raw);
    ECORE_CLEAR_BIT(ECORE_FILTER_RX_MODE_PENDING, &pdev->client_info[cid].sp_rxmode_state);

    if (pdev->client_info[cid].set_rx_mode_cookie)
    {
        cookie = (void *)pdev->client_info[cid].set_rx_mode_cookie;
        pdev->client_info[cid].set_rx_mode_cookie = NULL;
        DbgMessage(pdev, INFORMl2sp, "Filter rule calling mm_set_done... \n");
        mm_set_done(pdev, cid, cookie);
    }

    lm_sq_complete(pdev, CMD_PRIORITY_NORMAL, RAMROD_CMD_ID_ETH_FILTER_RULES, ETH_CONNECTION_TYPE, cid);

    if (pdev->client_info[cid].b_vlan_only_in_process)
    {
        pdev->client_info[cid].b_vlan_only_in_process = FALSE;

           p.vlan_mac_obj = &pdev->client_info[cid].vlan_obj;
        p.ramrod_flags = 0;
        SET_BIT( (p.ramrod_flags), RAMROD_CONT );

        ecore_config_vlan_mac(pdev, &p);
    }
}

static INLINE void lm_eq_handle_rss_update_eqe(struct _lm_device_t * pdev, union event_ring_elem * elem)
{
    struct ecore_raw_obj  * raw    = NULL;
    void                  * cookie = NULL;
    u32_t                   cid    = LM_SW_LEADING_RSS_CID(pdev);
#ifdef VF_INVOLVED
    u8_t abs_vf_id;
    lm_vf_info_t * vf_info;
#endif

    DbgMessage(pdev, INFORMeq | INFORMl2sp, "lm_eth_comp_cb: EVENT_RING_OPCODE_RSS_UPDATE_RULES\n");


    cid = mm_le32_to_cpu(elem->message.data.eth_event.echo) & ECORE_SWCID_MASK;

#ifdef VF_INVOLVED
    if (IS_CHANNEL_VIRT_MODE_MASTER_PFDEV(pdev) && (cid >= MAX_RX_CHAIN(pdev)))
    {
        abs_vf_id = GET_ABS_VF_ID_FROM_PF_CID(cid);
        vf_info = lm_pf_find_vf_info_by_abs_id(pdev, abs_vf_id);
        DbgBreakIf(!vf_info);
        raw = &vf_info->vf_slowpath_info.rss_conf_obj.raw;
        raw->clear_pending(raw);
    }
    else
#endif
    {

        raw = &pdev->slowpath_info.rss_conf_obj.raw;
        raw->clear_pending(raw);
        mm_atomic_dec(&pdev->params.update_comp_cnt);
        if (mm_atomic_dec(&pdev->params.update_suspend_cnt) == 0)
        {
            if (pdev->slowpath_info.set_rss_cookie != NULL)
            {
                cookie = (void *)pdev->slowpath_info.set_rss_cookie;
                pdev->slowpath_info.set_rss_cookie = NULL;
                mm_set_done(pdev, cid, cookie);
            }
        }
    }
    lm_sq_complete(pdev, CMD_PRIORITY_NORMAL, RAMROD_CMD_ID_ETH_RSS_UPDATE, ETH_CONNECTION_TYPE, cid);
}

/**lm_eq_handle_niv_function_update_eqe
 * handle a NIV function update completion.
 *
 * @param pdev the device
 * @param elem the CQE
 */
static INLINE void lm_eq_handle_function_update_eqe(struct _lm_device_t * pdev, union event_ring_elem * elem)
{
    DbgBreakIf((FUNC_UPDATE_RAMROD_SOURCE_NIV != elem->message.data.function_update_event.echo) &&
               (FUNC_UPDATE_RAMROD_SOURCE_L2MP != elem->message.data.function_update_event.echo) &&
               (FUNC_UPDATE_RAMROD_SOURCE_ENCAP != elem->message.data.function_update_event.echo) &&
               (FUNC_UPDATE_RAMROD_SOURCE_UFP != elem->message.data.function_update_event.echo));

    switch(elem->message.data.function_update_event.echo)
    {
    case FUNC_UPDATE_RAMROD_SOURCE_NIV:
        DbgBreakIf((pdev->slowpath_info.niv_ramrod_state == NIV_RAMROD_COMPLETED)||
                   (pdev->slowpath_info.niv_ramrod_state == NIV_RAMROD_NOT_POSTED));

        if ( NIV_RAMROD_SET_LOOPBACK_POSTED == pdev->slowpath_info.niv_ramrod_state )
        {
            MM_ACQUIRE_PHY_LOCK(pdev);
            pdev->vars.link_status = LM_STATUS_LINK_ACTIVE;
            mm_indicate_link(pdev, pdev->vars.link_status, pdev->vars.medium);
            MM_RELEASE_PHY_LOCK(pdev);
        }
        else if (NIV_RAMROD_CLEAR_LOOPBACK_POSTED == pdev->slowpath_info.niv_ramrod_state)
        {
            MM_ACQUIRE_PHY_LOCK(pdev);
            pdev->vars.link_status = LM_STATUS_LINK_DOWN;
            mm_indicate_link(pdev, pdev->vars.link_status, pdev->vars.medium);
            MM_RELEASE_PHY_LOCK(pdev);
        }

        pdev->slowpath_info.niv_ramrod_state = NIV_RAMROD_COMPLETED;

        break;

    case FUNC_UPDATE_RAMROD_SOURCE_L2MP:
        pdev->slowpath_info.l2mp_func_update_ramrod_state = L2MP_FUNC_UPDATE_RAMROD_COMPLETED;

        break;

    case FUNC_UPDATE_RAMROD_SOURCE_ENCAP:
        pdev->encap_info.current_encap_offload_state =
            pdev->encap_info.new_encap_offload_state;
        if (pdev->encap_info.update_cookie)
        {
            void* cookie = (void*)pdev->encap_info.update_cookie;
            pdev->encap_info.update_cookie = NULL;
            mm_set_done(pdev, LM_CLI_IDX_NDIS, cookie);
        }

        break;
    case FUNC_UPDATE_RAMROD_SOURCE_UFP:
        DbgBreakIf((pdev->slowpath_info.ufp_func_ramrod_state == UFP_RAMROD_COMPLETED)||
                   (pdev->slowpath_info.ufp_func_ramrod_state == UFP_RAMROD_NOT_POSTED));

        // In case of link update, indicate the link status to miniport, else it is just
        // svid update which doesnt need anymore processing.
        if ( UFP_RAMROD_PF_LINK_UPDATE_POSTED == pdev->slowpath_info.ufp_func_ramrod_state )
        {
            MM_ACQUIRE_PHY_LOCK(pdev);
            pdev->vars.link_status = LM_STATUS_LINK_ACTIVE;
            mm_indicate_link(pdev, pdev->vars.link_status, pdev->vars.medium);
            MM_RELEASE_PHY_LOCK(pdev);
        }
        else if (UFP_RAMROD_PF_UPDATE_POSTED != pdev->slowpath_info.ufp_func_ramrod_state) 
        {
            DbgBreak();
        }
        pdev->slowpath_info.ufp_func_ramrod_state = UFP_RAMROD_COMPLETED;
        break;
    default:
        DbgBreakMsg("lm_eq_handle_function_update_eqe unknown source");
        break;
    }

    lm_sq_complete(pdev, CMD_PRIORITY_NORMAL, RAMROD_CMD_ID_COMMON_FUNCTION_UPDATE,
                   NONE_CONNECTION_TYPE, 0);
}

/**lm_eq_handle_niv_function_update_eqe
 * handle a NIV lists update completion.
 *
 * @param pdev the device
 * @param elem the CQE
 */
static INLINE void lm_eq_handle_niv_vif_lists_eqe(struct _lm_device_t * pdev, union event_ring_elem * elem)
{
    DbgBreakIf((pdev->slowpath_info.niv_ramrod_state != NIV_RAMROD_VIF_LISTS_POSTED) &&
                (!lm_reset_is_inprogress(pdev)));

    DbgBreakIf((elem->message.data.vif_list_event.echo != VIF_LIST_RULE_CLEAR_ALL) &&
               (elem->message.data.vif_list_event.echo != VIF_LIST_RULE_CLEAR_FUNC) &&
               (elem->message.data.vif_list_event.echo != VIF_LIST_RULE_GET) &&
               (elem->message.data.vif_list_event.echo != VIF_LIST_RULE_SET));

    if (elem->message.data.vif_list_event.echo == VIF_LIST_RULE_GET)
    {
        pdev->slowpath_info.last_vif_list_bitmap = (u8_t)elem->message.data.vif_list_event.func_bit_map;
    }

    if(!lm_reset_is_inprogress(pdev))
    {
        pdev->slowpath_info.niv_ramrod_state = NIV_RAMROD_COMPLETED;
    }

    lm_sq_complete(pdev, CMD_PRIORITY_NORMAL, RAMROD_CMD_ID_COMMON_AFEX_VIF_LISTS,
                   NONE_CONNECTION_TYPE, 0);
}

#ifdef VF_INVOLVED
static INLINE void lm_eq_handle_vf_flr_eqe(struct _lm_device_t * pdev, union event_ring_elem * elem)
{
    lm_vf_info_t * vf_info = NULL;
    u8_t abs_vf_id;

    abs_vf_id = elem->message.data.vf_flr_event.vf_id;

    DbgMessage(pdev, WARN, "lm_eq_handle_vf_flr_eqe(%d)\n",elem->message.data.vf_flr_event.vf_id);
    vf_info = lm_pf_find_vf_info_by_abs_id(pdev, (u8_t)abs_vf_id);
    if (!vf_info) {
        DbgBreakMsg("lm_eq_handle_vf_flr_eqe: vf_info is not found\n");
        return;
    }
    vf_info->was_flred = TRUE;
    MM_ACQUIRE_VFS_STATS_LOCK_DPC(pdev);
    if ((vf_info->vf_stats.vf_stats_state != VF_STATS_NONE) && (vf_info->vf_stats.vf_stats_state != VF_STATS_REQ_IN_PROCESSING)) {
        vf_info->vf_stats.vf_stats_state = VF_STATS_REQ_READY;
    }
    vf_info->vf_stats.stop_collect_stats = TRUE;
    vf_info->vf_stats.vf_stats_flag = 0;
    MM_RELEASE_VFS_STATS_LOCK_DPC(pdev);
}

static INLINE void lm_eq_handle_malicious_vf_eqe(struct _lm_device_t * pdev, union event_ring_elem * elem)
{
    lm_vf_info_t * vf_info = NULL;
    u8_t abs_vf_id;

    abs_vf_id = elem->message.data.malicious_vf_event.vf_id;
    vf_info = lm_pf_find_vf_info_by_abs_id(pdev, (u8_t)abs_vf_id);
    if (vf_info) {
        vf_info->was_malicious = TRUE;
        mm_report_malicious_vf(pdev, vf_info);
    }
    DbgMessage(pdev, FATAL, "lm_eq_handle_malicious_vf_eqe(%d)\n",abs_vf_id);
}

#endif
static INLINE lm_status_t lm_service_eq_elem(struct _lm_device_t * pdev, union event_ring_elem * elem)
{
    /* handle eq element */
    switch(elem->message.opcode)
    {
        case EVENT_RING_OPCODE_FUNCTION_START:
            lm_eq_handle_function_start_eqe(pdev, elem);
            break;

        case EVENT_RING_OPCODE_FUNCTION_STOP:
            lm_eq_handle_function_stop_eqe(pdev, elem);
            break;

        case EVENT_RING_OPCODE_CFC_DEL:
        case EVENT_RING_OPCODE_CFC_DEL_WB:
            lm_eq_handle_cfc_del_eqe(pdev, elem);
            break;

        case EVENT_RING_OPCODE_SET_MAC:
        case EVENT_RING_OPCODE_CLASSIFICATION_RULES:
            lm_eq_handle_classification_eqe(pdev, elem);
            break;

        case EVENT_RING_OPCODE_STAT_QUERY:
            lm_eq_handle_stats_eqe(pdev, elem);
            break;

        case EVENT_RING_OPCODE_STOP_TRAFFIC:
            pdev->dcbx_info.dcbx_ramrod_state = FUNCTION_DCBX_STOP_COMPLETED;
            lm_sq_complete(pdev, CMD_PRIORITY_MEDIUM,
                       RAMROD_CMD_ID_COMMON_STOP_TRAFFIC, NONE_CONNECTION_TYPE, 0);
            break;

        case EVENT_RING_OPCODE_START_TRAFFIC:
            pdev->dcbx_info.dcbx_ramrod_state = FUNCTION_DCBX_START_COMPLETED;
            lm_sq_complete(pdev, CMD_PRIORITY_HIGH,
                       RAMROD_CMD_ID_COMMON_START_TRAFFIC, NONE_CONNECTION_TYPE, 0);
            break;

        case EVENT_RING_OPCODE_FORWARD_SETUP:
            lm_eq_handle_fwd_setup_eqe(pdev, elem);
            break;

        case EVENT_RING_OPCODE_MULTICAST_RULES:
            lm_eq_handle_mcast_eqe(pdev, elem);
            break;

        case EVENT_RING_OPCODE_FILTERS_RULES:
            lm_eq_handle_filter_rules_eqe(pdev, elem);
            break;

        case EVENT_RING_OPCODE_RSS_UPDATE_RULES:
            lm_eq_handle_rss_update_eqe(pdev, elem);
            break;

        case EVENT_RING_OPCODE_FUNCTION_UPDATE:
            lm_eq_handle_function_update_eqe(pdev, elem);
            break;

        case EVENT_RING_OPCODE_AFEX_VIF_LISTS:
            lm_eq_handle_niv_vif_lists_eqe(pdev, elem);
            break;
#ifdef VF_INVOLVED
        case EVENT_RING_OPCODE_VF_FLR:
            lm_eq_handle_vf_flr_eqe(pdev, elem);
            break;
        case EVENT_RING_OPCODE_MALICIOUS_VF:
            lm_eq_handle_malicious_vf_eqe(pdev, elem);
            break;
#endif
        default:
            DbgBreakMsg("Unknown elem type received on eq\n");
            return LM_STATUS_FAILURE;
        }

    return LM_STATUS_SUCCESS;
}

/**
 * @Description
 *      handle cqes of the event-ring, should be called from dpc if index in status block was changed
 * @param pdev
 *
 * @return lm_status_t SUCCESS or FAILURE (if unknown completion)
 */
lm_status_t lm_service_eq_intr(struct _lm_device_t * pdev)
{
    union event_ring_elem * elem       = NULL;
    lm_eq_chain_t         * eq_chain   = &pdev->eq_info.eq_chain;
    lm_status_t             lm_status  = LM_STATUS_SUCCESS;
    u16_t                   cq_new_idx = 0;
    u16_t                   cq_old_idx = 0;

    cq_new_idx = mm_le16_to_cpu(*(eq_chain->hw_con_idx_ptr));
    if((cq_new_idx & lm_bd_chain_usable_bds_per_page(&eq_chain->bd_chain))
       == lm_bd_chain_usable_bds_per_page(&eq_chain->bd_chain))
    {
        cq_new_idx+=lm_bd_chain_bds_skip_eop(&eq_chain->bd_chain);
    }
    cq_old_idx = lm_bd_chain_cons_idx(&eq_chain->bd_chain);

    /* there is no change in the EQ consumer index so exit! */
    if (cq_old_idx == cq_new_idx)
    {
        DbgMessage(pdev, INFORMeq , "there is no change in the EQ consumer index so exit!\n");
        return LM_STATUS_SUCCESS;
    } else {
        DbgMessage(pdev, INFORMeq , "EQ consumer index: cq_old_idx=0x%x, cq_new_idx=0x%x!\n",cq_old_idx,cq_new_idx);
    }

    while(cq_old_idx != cq_new_idx)
    {
        DbgBreakIfFastPath(S16_SUB(cq_new_idx, cq_old_idx) <= 0);
        /* get hold of the cqe, and find out what it's type corresponds to */
        elem = (union event_ring_elem *)lm_bd_chain_consume_bd(&eq_chain->bd_chain);

        if (elem == NULL)
        {
            DbgBreakIfFastPath(elem == NULL);
            return LM_STATUS_FAILURE;
        }

        cq_old_idx = lm_bd_chain_cons_idx(&eq_chain->bd_chain);

        lm_status = lm_service_eq_elem(pdev, elem);
        if (lm_status != LM_STATUS_SUCCESS)
        {
            return lm_status;
        }

#ifdef __LINUX
        mm_common_ramrod_comp_cb(pdev, &elem->message);
#endif //__LINUX
        /* Recycle the cqe */
        lm_bd_chain_bd_produced(&eq_chain->bd_chain);
    } /* while */

    /* update producer */
    LM_INTMEM_WRITE16(pdev,
                      eq_chain->iro_prod_offset,
                      lm_bd_chain_prod_idx(&eq_chain->bd_chain),
                      BAR_CSTRORM_INTMEM);

    return LM_STATUS_SUCCESS;
} /* lm_service_eq_intr */

/**
 * @Description
 *     This function completes eq completions immediately
 *     (without fw completion).
 *
 * @param pdev
 * @param spe
 */
void lm_eq_comp_cb(struct _lm_device_t *pdev, struct sq_pending_command * pending)
{
    union event_ring_elem elem = {{0}};
    u32_t                 cid  = pending->cid;
    u8_t                  cmd  = pending->cmd;


    /* We need to build the "elem" based on the spe */
    if ((pending->type & SPE_HDR_T_CONN_TYPE) == ETH_CONNECTION_TYPE) /* Some Ethernets complete on Eq. */
    {
        switch (cmd)
        {
        case RAMROD_CMD_ID_ETH_SET_MAC:
            elem.message.opcode = EVENT_RING_OPCODE_SET_MAC;
            elem.message.data.eth_event.echo = (0xff << ECORE_SWCID_SHIFT | cid); /*unknown type*/

            break;

        case RAMROD_CMD_ID_ETH_CLASSIFICATION_RULES:
            elem.message.opcode = EVENT_RING_OPCODE_CLASSIFICATION_RULES;
            elem.message.data.eth_event.echo = (0xff << ECORE_SWCID_SHIFT | cid); /*unknown type*/
            break;

        case RAMROD_CMD_ID_ETH_FORWARD_SETUP:
            elem.message.opcode = EVENT_RING_OPCODE_FORWARD_SETUP;
            break;

        case RAMROD_CMD_ID_ETH_MULTICAST_RULES:
            elem.message.opcode = EVENT_RING_OPCODE_MULTICAST_RULES;
            elem.message.data.eth_event.echo = cid;
            break;

        case RAMROD_CMD_ID_ETH_FILTER_RULES:
            elem.message.opcode = EVENT_RING_OPCODE_FILTERS_RULES;
            elem.message.data.eth_event.echo = cid;
            break;

        case RAMROD_CMD_ID_ETH_RSS_UPDATE:
            elem.message.opcode = EVENT_RING_OPCODE_RSS_UPDATE_RULES;
            break;

        default:
            DbgBreakMsg("Unknown elem type received on eq\n");
        }
    }
    else if ((pending->type & SPE_HDR_T_CONN_TYPE)== NONE_CONNECTION_TYPE)
    {
        switch (cmd)
        {
        case RAMROD_CMD_ID_COMMON_FUNCTION_START:
            elem.message.opcode = EVENT_RING_OPCODE_FUNCTION_START;
            break;

        case RAMROD_CMD_ID_COMMON_FUNCTION_STOP:
            elem.message.opcode = EVENT_RING_OPCODE_FUNCTION_STOP;
            break;

        case RAMROD_CMD_ID_COMMON_CFC_DEL:
            elem.message.opcode = EVENT_RING_OPCODE_CFC_DEL;
            elem.message.data.cfc_del_event.cid = cid;
            break;

        case RAMROD_CMD_ID_COMMON_CFC_DEL_WB:
            elem.message.opcode = EVENT_RING_OPCODE_CFC_DEL_WB;
            elem.message.data.cfc_del_event.cid = cid;
            break;

        case RAMROD_CMD_ID_COMMON_STAT_QUERY:
            elem.message.opcode = EVENT_RING_OPCODE_STAT_QUERY;
            break;

        case RAMROD_CMD_ID_COMMON_STOP_TRAFFIC:
            elem.message.opcode = EVENT_RING_OPCODE_STOP_TRAFFIC;
            break;

        case RAMROD_CMD_ID_COMMON_START_TRAFFIC:
            elem.message.opcode = EVENT_RING_OPCODE_START_TRAFFIC;
            break;

        case RAMROD_CMD_ID_COMMON_FUNCTION_UPDATE:
            elem.message.opcode = EVENT_RING_OPCODE_FUNCTION_UPDATE;
            break;

        case RAMROD_CMD_ID_COMMON_AFEX_VIF_LISTS:
            elem.message.opcode = EVENT_RING_OPCODE_AFEX_VIF_LISTS;
            break;

        default:
            DbgBreakMsg("Unknown elem type received on eq\n");
        }
    }

    lm_service_eq_elem(pdev, &elem);
}

/*********************** SQ RELATED FUNCTIONS ***************************/
/* TODO: move more functions from command.h to here.                    */
void lm_cid_recycled_cb_register(struct _lm_device_t *pdev, u8_t type, lm_cid_recycled_cb_t cb)
{

    if ( CHK_NULL(pdev) ||
         CHK_NULL(cb) ||
         ERR_IF( type >= ARRSIZE( pdev->cid_recycled_callbacks ) ) ||
         ERR_IF( NULL != pdev->cid_recycled_callbacks[type] ) )
    {
        DbgBreakIf(!pdev);
        DbgBreakIf(!cb) ;
        DbgBreakIf( type >= ARRSIZE( pdev->cid_recycled_callbacks ) );
        DbgBreakIf( NULL != pdev->cid_recycled_callbacks[type] ) ;
        return;
    }
    pdev->cid_recycled_callbacks[type]= cb;
}

void lm_cid_recycled_cb_deregister(struct _lm_device_t *pdev, u8_t type)
{

    if ( CHK_NULL(pdev) ||
         ERR_IF( type >= ARRSIZE( pdev->cid_recycled_callbacks ) ) ||
         CHK_NULL(pdev->cid_recycled_callbacks[type]) )

    {
        DbgBreakIf(!pdev);
        DbgBreakIf( type >= ARRSIZE( pdev->cid_recycled_callbacks ) );
        return;
    }
    pdev->cid_recycled_callbacks[type] = (lm_cid_recycled_cb_t)NULL;
}

void lm_sq_change_state(struct _lm_device_t *pdev, lm_sq_state_t state)
{
    DbgMessage(pdev, INFORM, "Changing sq state from %d to %d\n", pdev->sq_info.sq_state, state);

    MM_ACQUIRE_SPQ_LOCK(pdev);

    pdev->sq_info.sq_state = state;

    MM_RELEASE_SPQ_LOCK(pdev);
}

/**
 * @Description
 *     function completes pending slow path requests instead of
 *     FW. Used in error recovery flow.
 *
 * @Assumptions:
 *      interrupts at this point are disabled and dpcs are
 *      flushed, thus no one else can complete these...
 *
 * @param pdev
 */
void lm_sq_complete_pending_requests(struct _lm_device_t *pdev)
{
    enum connection_type        type      = 0;
    struct sq_pending_command * pending   = NULL;

    DbgMessage(pdev, WARN, "lm_sq_complete_pending_requests\n");

    /* unexpected if not under error recovery */
    DbgBreakIf(!pdev->params.enable_error_recovery);

    do
    {
        MM_ACQUIRE_SPQ_LOCK(pdev);

        /* Find the first entry that hasn't been handled yet. */
        /* We just peek and don't pop since completion of this pending request should contain removing
         * it from the completion list. However, it may not happen immediately */
        pending = (struct sq_pending_command *)d_list_peek_head(&pdev->sq_info.pending_complete);

        /* Look for the first entry that is "pending" but not completion_called yet. */
        while (pending && GET_FLAGS(pending->flags, SQ_PEND_COMP_CALLED))
        {
            pending = (struct sq_pending_command *)d_list_next_entry(&pending->list);
        }

        /* Mark pending completion as "handled" so that we don't handle it again...  */
        if (pending)
        {
            SET_FLAGS(pending->flags, SQ_PEND_COMP_CALLED);
        }

        MM_RELEASE_SPQ_LOCK(pdev);

        if (pending)
        {
            type = pending->type & SPE_HDR_T_CONN_TYPE;

            if (pdev->sq_info.sq_comp_cb[type])
            {
                pdev->sq_info.sq_comp_cb[type](pdev, pending);
            }
            else
            {
                DbgBreakMsg("unsupported pending sq: Not implemented yet\n");
            }
        }

        /*
         * lm_sq_post_pending can only cause (via lm_sq_flush)
         * lm_sq_complete_pending_requests DPC to be scheduled if
         * pdev->sq_info.sq_comp_scheduled==FALSE. Such scheduling
         * is acompnied by sq_comp_scheduled being set to TRUE.
         *
         * If we avoid setting pdev->sq_info.sq_comp_scheduled to FALSE,
         * we are gurenteed lm_sq_complete_pending_requests will not be
         * re-scheduled here.
         */

        lm_sq_post_pending(pdev);

    } while (!d_list_is_empty(&pdev->sq_info.pending_complete));

    /*
     * We are done completing pending requests in pending_list. However, any
     * new sp requests created by callbacks, need service.
     *
     * As we are outside the SPQ lock, this DPC may be preempted,
     * lm_sq_flush may have been called somewhere before this point.
     */

    MM_ACQUIRE_SPQ_LOCK(pdev);

    pdev->sq_info.sq_comp_scheduled = FALSE;

    /*
     * check if there is more to be flushed (new SPQ that entered after
     * the "while".)
     */

    if ((pdev->sq_info.sq_state == SQ_STATE_PENDING) && !d_list_is_empty(&pdev->sq_info.pending_complete))
    {
        MM_RELEASE_SPQ_LOCK(pdev);
        lm_sq_flush(pdev);
    }
    else
    {
        MM_RELEASE_SPQ_LOCK(pdev);
    }
}


lm_status_t lm_sq_flush(struct _lm_device_t *pdev)
{
    lm_status_t lm_status   = LM_STATUS_SUCCESS;
    u8_t        schedule_wi = FALSE;

    MM_ACQUIRE_SPQ_LOCK(pdev);

    if ((pdev->sq_info.sq_comp_scheduled == FALSE) &&
        ((pdev->sq_info.num_pending_high != MAX_HIGH_PRIORITY_SPE) ||
        (pdev->sq_info.num_pending_normal != MAX_NORMAL_PRIORITY_SPE)))
    {
        schedule_wi = TRUE;
        pdev->sq_info.sq_comp_scheduled = TRUE;
    }

    MM_RELEASE_SPQ_LOCK(pdev);

    if (schedule_wi)
    {
        lm_status = MM_REGISTER_DPC(pdev, lm_sq_complete_pending_requests);
        /* Alternative: WorkItem...
        lm_status = MM_REGISTER_LPME(pdev, lm_sq_complete_pending_requests, FALSE, FALSE);
        if (lm_status == LM_STATUS_SUCCESS)
        {
            return LM_STATUS_PENDING;
        }
        */
        if (lm_status == LM_STATUS_SUCCESS)
        {
            lm_status = LM_STATUS_PENDING;
        }
    }

    return lm_status;
}

lm_status_t lm_sq_comp_cb_register(struct _lm_device_t *pdev, u8_t type, lm_sq_comp_cb_t cb)
{
    if ( CHK_NULL(pdev) ||
         CHK_NULL(cb) ||
         ERR_IF( type >= ARRSIZE( pdev->sq_info.sq_comp_cb ) ) ||
         ERR_IF( NULL != pdev->sq_info.sq_comp_cb[type] ) )
    {
        return LM_STATUS_INVALID_PARAMETER;
    }
    pdev->sq_info.sq_comp_cb[type]= cb;
    return LM_STATUS_SUCCESS;
}

lm_status_t lm_sq_comp_cb_deregister(struct _lm_device_t *pdev, u8_t type)
{

    if ( CHK_NULL(pdev) ||
         ERR_IF( type >= ARRSIZE( pdev->sq_info.sq_comp_cb ) ) ||
         CHK_NULL(pdev->sq_info.sq_comp_cb[type]) )

    {
        return LM_STATUS_INVALID_PARAMETER;
    }
    pdev->sq_info.sq_comp_cb[type] = (lm_sq_comp_cb_t)NULL;

    return LM_STATUS_SUCCESS;
}

u8_t lm_sq_is_empty(struct _lm_device_t *pdev)
{
    u8_t empty = TRUE;

    MM_ACQUIRE_SPQ_LOCK(pdev);

    if ((pdev->sq_info.num_pending_high != MAX_HIGH_PRIORITY_SPE) ||
        (pdev->sq_info.num_pending_normal != MAX_NORMAL_PRIORITY_SPE))
    {
        empty = FALSE;
    }

    MM_RELEASE_SPQ_LOCK(pdev);

    return empty;
}


/**
 * @Description
 *     Posts from the normal + high priority lists as much as it
 *     can towards the FW.
 *
 * @Assumptions
 *     called under SQ_LOCK!!!
 *
 * @param pdev
 *
 * @return lm_status_t PENDING: if indeed requests were posted,
 *         SUCCESS o/w
 */
static lm_status_t lm_sq_post_from_list(struct _lm_device_t *pdev)
{
    lm_status_t                 lm_status = LM_STATUS_SUCCESS;
    struct sq_pending_command * pending   = NULL;

    while (pdev->sq_info.num_pending_normal)
    {
        pending = (void*)d_list_pop_head(&pdev->sq_info.pending_normal);

        if(!pending)
            break;

        pdev->sq_info.num_pending_normal --;

        DbgMessage(pdev, INFORM, "lm_sq_post: priority=%d, command=%d, type=%d, cid=%d num_pending_normal=%d\n",
               CMD_PRIORITY_NORMAL, pending->cmd, pending->type, pending->cid, pdev->sq_info.num_pending_normal);

        d_list_push_tail(&pdev->sq_info.pending_complete, &pending->list);

        _lm_sq_post(pdev,pending);

        lm_status = LM_STATUS_PENDING;

    }

    /* post high priority sp */
    while (pdev->sq_info.num_pending_high)
    {
        pending = (void*)d_list_pop_head(&pdev->sq_info.pending_high);

        if(!pending)
            break;

        pdev->sq_info.num_pending_high --;
        DbgMessage(pdev, INFORM, "lm_sq_post: priority=%d, command=%d, type=%d, cid=%d num_pending_normal=%d\n",
               CMD_PRIORITY_HIGH, pending->cmd, pending->type, pending->cid, pdev->sq_info.num_pending_normal);

        d_list_push_tail(&pdev->sq_info.pending_complete, &pending->list);

        _lm_sq_post(pdev, pending);

        lm_status = LM_STATUS_PENDING;
    }

    return lm_status;
}

/**
 * Description
 *  Add the entry to the pending SP list.
 *  Try to add entry's from the list to the sq_chain if possible.(there is are less then 8 ramrod commands pending)
 *
 * @param pdev
 * @param pending  - The pending list entry.
 * @param priority - (high or low) to witch list to insert the pending list entry.
 *
 * @return lm_status_t: LM_STATUS_SUCCESS on success or
 *         LM_STATUS_REQUEST_NOT_ACCEPTED if slowpath queue is
 *         in blocked state.
 */
lm_status_t lm_sq_post_entry(struct _lm_device_t       * pdev,
                             struct sq_pending_command * pending,
                             u8_t                        priority)
{
    lm_status_t lm_status = LM_STATUS_FAILURE;
    u8_t        sq_flush  = FALSE;

    DbgBreakIf(! pdev);

    MM_ACQUIRE_SPQ_LOCK(pdev);

    if (pdev->sq_info.sq_state == SQ_STATE_BLOCKED)
    {
        // This state is valid in case hw failure such as fan failure happened.
        // so we removed assert was here before and changed only to trace CQ62337
        DbgMessage(pdev, FATAL, "lm_sq_post_entry: Unexpected slowpath command SQ_STATE_BLOCKED\n");

        MM_RELEASE_SPQ_LOCK(pdev);

        return LM_STATUS_REQUEST_NOT_ACCEPTED;
    }

    /* We shouldn't be posting any entries if the function-stop has already been posted... */
    if (((mm_le32_to_cpu(pending->command.hdr.conn_and_cmd_data) & SPE_HDR_T_CMD_ID)>>SPE_HDR_T_CMD_ID_SHIFT) != RAMROD_CMD_ID_COMMON_FUNCTION_STOP)
    {
        DbgBreakIf((pdev->eq_info.function_state == FUNCTION_STOP_POSTED) || (pdev->eq_info.function_state == FUNCTION_STOP_COMPLETED));
    }

    switch( priority )
    {
    case CMD_PRIORITY_NORMAL:
        /* add the request to the list tail*/
        d_list_push_tail(&pdev->sq_info.pending_normal, &pending->list);
        break;
    case CMD_PRIORITY_MEDIUM:
        /* add the request to the list head*/
        d_list_push_head(&pdev->sq_info.pending_normal, &pending->list);
        break;
    case CMD_PRIORITY_HIGH:
        /* add the request to the list head*/
        d_list_push_head(&pdev->sq_info.pending_high, &pending->list);
        break;
    default:
        DbgBreakIf( 1 ) ;
        // TODO_ROLLBACK - free sq_pending_command
        MM_RELEASE_SPQ_LOCK(pdev);
        return LM_STATUS_INVALID_PARAMETER ;
    }

    if(!(pdev->sq_info.num_pending_normal))
    {
        LM_COMMON_DRV_STATS_ATOMIC_INC_ETH(pdev, tx_no_sq_wqe);
    }

    lm_status = lm_sq_post_from_list(pdev);
    if (lm_status == LM_STATUS_PENDING)
    {
        /* New slowpath was posted in pending state... make sure to flush sq
         * after this... */
        if (pdev->sq_info.sq_state == SQ_STATE_PENDING)
        {
            sq_flush = TRUE;
        }

        lm_status = LM_STATUS_SUCCESS;
    }

    MM_RELEASE_SPQ_LOCK(pdev);

    if (sq_flush)
    {
        lm_sq_flush(pdev);
    }
    return lm_status ;
}


/*
    post a ramrod to the sq
    takes the sq pending list spinlock and adds the request
    will not block
    but the actuall posting to the sq might be deffered until there is room
    MUST only have one request pending per CID (this is up to the caller to enforce)
*/
lm_status_t lm_sq_post(struct _lm_device_t *pdev,
                       u32_t                cid,
                       u8_t                 command,
                       u8_t                 priority,
                       u16_t                type,
                       u64_t                data)
{
    struct sq_pending_command *pending  = NULL;
    lm_status_t               lm_status = LM_STATUS_SUCCESS;
    DbgBreakIf(! pdev);
    DbgBreakIf(! command); /* todo: make this more detailed*/

    /* allocate a new command struct and fill it */
    pending = mm_get_sq_pending_command(pdev);
    if( !pending )
    {
        DbgBreakIf(1);
        return LM_STATUS_FAILURE ;
    }

    lm_sq_post_fill_entry(pdev,pending,cid,command,type,data,TRUE);

    lm_status = lm_sq_post_entry(pdev,pending,priority);

    return lm_status ;
}

/*
    inform the sq mechanism of completed ramrods
    because the completions arrive on the fast-path rings
    the fast-path needs to inform the sq that the ramrod has been serviced
    will not block
    does not take any locks
*/
void lm_sq_complete(struct _lm_device_t *pdev, u8_t priority,
                    u8_t command, u16_t type, u32_t cid )
{

    struct sq_pending_command *pending = NULL;

    MM_ACQUIRE_SPQ_LOCK(pdev);

    DbgMessage(pdev, INFORM, "lm_sq_complete: priority=%d, command=%d, type=%d, cid=%d num_pending_normal=%d\n",
               priority, command, type, cid, pdev->sq_info.num_pending_normal);

    switch( priority )
    {
    case CMD_PRIORITY_NORMAL:
    case CMD_PRIORITY_MEDIUM:
        pdev->sq_info.num_pending_normal ++;
        DbgBreakIf(pdev->sq_info.num_pending_normal > MAX_NORMAL_PRIORITY_SPE);
        break;
    case CMD_PRIORITY_HIGH:
        pdev->sq_info.num_pending_high ++;
        DbgBreakIf(pdev->sq_info.num_pending_high > MAX_HIGH_PRIORITY_SPE);
        break;
    default:
        DbgBreakIf( 1 ) ;
        break;
    }

    /* update sq consumer */
    pdev->sq_info.sq_chain.con_idx ++;
    pdev->sq_info.sq_chain.bd_left ++;

    /* Search for the completion in the pending_complete list*/
    /* Currently only supported if error recovery is supported */
    pending = (void*)d_list_peek_head(&pdev->sq_info.pending_complete);

    if (pdev->params.validate_sq_complete)
    {
        DbgBreakIf(!pending); /* not expected, but will deal with it... just won't  */
    }

    if (pdev->params.validate_sq_complete)
    {
        while (pending)
        {
            if (((pending->type & SPE_HDR_T_CONN_TYPE) == type) &&
                (pending->cmd == command) &&
                (pending->cid == cid))
            {
                /* got it... remove from list and free it */
                d_list_remove_entry(&pdev->sq_info.pending_complete, &pending->list);
                if(GET_FLAGS(pending->flags, SQ_PEND_RELEASE_MEM))
                {
                    mm_return_sq_pending_command(pdev, pending);
                }
                break;
            }
            pending = (void*)d_list_next_entry(&pending->list);
        }
    }
    else
    {
        /* TODO_ER: on no validation, just take the head... Workaround for mc-diag */
        pending = (void*)d_list_pop_head(&pdev->sq_info.pending_complete);
        if(CHK_NULL(pending))
        {
            DbgBreakMsg("lm_sq_complete pending is NULL");
        }
        else
        {
            if((GET_FLAGS(pending->flags, SQ_PEND_RELEASE_MEM)))
            {
                mm_return_sq_pending_command(pdev, pending);
            }
        }
    }

    DbgBreakIf(!pending); /* means none were found, assert but can deal with it... */

    MM_RELEASE_SPQ_LOCK(pdev);
}

/**
 * @description
 *    do any deffered posting pending on the sq, will take the list spinlock
 *    will not block. Check sq state, if its pending (it means no hw...) call flush
 *    at the end, which will take care of completing these completions internally.
 * @param pdev
 *
 * @return lm_status_t SUCCESS: is no pending requests were sent. PENDING if a
 *                              if pending request was sent.
 */
lm_status_t lm_sq_post_pending(struct _lm_device_t *pdev)
{
    lm_status_t                 lm_status = LM_STATUS_SUCCESS;
    u8_t                        sq_flush  = FALSE;

    if ( CHK_NULL(pdev) )
    {
        DbgBreakIf(!pdev);
        return LM_STATUS_INVALID_PARAMETER;
    }

    MM_ACQUIRE_SPQ_LOCK(pdev);

    lm_status = lm_sq_post_from_list(pdev);

    if (lm_status == LM_STATUS_PENDING)
    {
        /* New slowpath was posted in pending state... make sure to flush sq
         * after this... */
        if (pdev->sq_info.sq_state == SQ_STATE_PENDING)
        {
            sq_flush = TRUE;
        }
    }

    MM_RELEASE_SPQ_LOCK(pdev);

    if (sq_flush)
    {
        lm_sq_flush(pdev);
    }
    return lm_status;
}


/*********************** ETH SLOWPATH RELATED FUNCTIONS ***************************/

void lm_eth_init_command_comp(struct _lm_device_t *pdev, struct common_ramrod_eth_rx_cqe *cqe)
{
    lm_tpa_info_t* tpa_info   = &LM_TPA_INFO(pdev);
    void *         cookie             = NULL;
    u32_t          conn_and_cmd_data   = mm_le32_to_cpu(cqe->conn_and_cmd_data);
    u32_t          cid                 = SW_CID(conn_and_cmd_data);
    enum           eth_spqe_cmd_id  command   = conn_and_cmd_data >> COMMON_RAMROD_ETH_RX_CQE_CMD_ID_SHIFT;
    u8_t           ramrod_type         = cqe->ramrod_type;
    u32_t          empty_data          = 0;
    u32_t          connection_info_idx = 0;
#ifdef VF_INVOLVED
    u32_t          max_eth_cid;
#endif

    DbgBreakIf(!pdev);

    DbgMessage(pdev, WARNl2sp,
                "lm_eth_comp_cb: completion for cid=%d, command %d(0x%x)\n", cid, command, command);

    DbgBreakIfAll(ramrod_type & COMMON_RAMROD_ETH_RX_CQE_ERROR);

    connection_info_idx = lm_get_sw_client_idx_from_cid(pdev,cid);

    switch (command)
    {
        case RAMROD_CMD_ID_ETH_CLIENT_SETUP:
            DbgBreakIf(lm_get_con_state(pdev, cid) != LM_CON_STATE_OPEN_SENT);
            lm_set_con_state(pdev, cid, LM_CON_STATE_OPEN);
            DbgMessage(pdev, WARNl2sp,
                        "lm_eth_comp_cb: RAMROD ETH SETUP completed for cid=%d, - calling lm_extract_ramrod_req!\n", cid);
            break;

        case RAMROD_CMD_ID_ETH_TX_QUEUE_SETUP:
            DbgBreakIf(lm_get_con_state(pdev, cid) != LM_CON_STATE_OPEN_SENT);
            lm_set_con_state(pdev, cid, LM_CON_STATE_OPEN);
            DbgMessage(pdev, WARNl2sp,
                        "lm_eth_comp_cb: RAMROD ETH SETUP completed for cid=%d, - calling lm_extract_ramrod_req!\n", cid);
            break;

        case RAMROD_CMD_ID_ETH_CLIENT_UPDATE:
            DbgBreakIf(PFDEV(pdev)->client_info[connection_info_idx].update.state != LM_CLI_UPDATE_USED);
            PFDEV(pdev)->client_info[connection_info_idx].update.state = LM_CLI_UPDATE_RECV;
            DbgMessage(pdev, WARNl2sp,
                        "lm_eth_comp_cb: RAMROD ETH Update completed for cid=%d, - calling lm_extract_ramrod_req!\n", cid);
            break;

        case RAMROD_CMD_ID_ETH_HALT:
            DbgBreakIf(lm_get_con_state(pdev, cid) != LM_CON_STATE_HALT_SENT);
            lm_set_con_state(pdev, cid, LM_CON_STATE_HALT);
            DbgMessage(pdev, WARNl2sp, "lm_eth_comp_cb:RAMROD_CMD_ID_ETH_HALT- calling lm_extract_ramrod_req!\n");
            break;

        case RAMROD_CMD_ID_ETH_EMPTY:
            empty_data        = mm_le32_to_cpu(cqe->protocol_data.data_lo);
            MM_EMPTY_RAMROD_RECEIVED(pdev,empty_data);
            DbgMessage(pdev, WARNl2sp, "lm_eth_comp_cb:RAMROD_CMD_ID_ETH_EMPTY- calling lm_extract_ramrod_req!\n");
            break;
        case RAMROD_CMD_ID_ETH_TPA_UPDATE:
            DbgMessage(pdev, WARNl2sp, "lm_eth_comp_cb:RAMROD_CMD_ID_ETH_TPA_UPDATE- calling lm_extract_ramrod_req!\n");
#ifdef VF_INVOLVED
            if (MM_DCB_MP_L2_IS_ENABLE(pdev))
            {
                max_eth_cid = lm_mp_max_cos_chain_used(pdev);
            }
            else
            {
                max_eth_cid = LM_SB_CNT(pdev) + MAX_NON_RSS_CHAINS;
            }
            if (IS_CHANNEL_VIRT_MODE_MASTER_PFDEV(pdev) && (cid >= max_eth_cid))
            {
                u8_t           abs_vf_id = 0xff;
                u8_t           vf_q_id   = 0xff;
                lm_vf_info_t * vf_info   = NULL;

                abs_vf_id = GET_ABS_VF_ID_FROM_PF_CID(cid);
                vf_q_id = GET_VF_Q_ID_FROM_PF_CID(cid);
                vf_info = lm_pf_find_vf_info_by_abs_id(pdev, abs_vf_id);
                DbgBreakIf(!vf_info);
                mm_atomic_dec((u32_t*)(&vf_info->vf_tpa_info.ramrod_recv_cnt));
            }
            else
#endif
            {
                if (IS_VFDEV(pdev))
                {
                    cid = GET_VF_Q_ID_FROM_PF_CID(cid);
                }
                if (0 == mm_atomic_dec((u32_t*)(&tpa_info->ramrod_recv_cnt)))
                {
                        tpa_info->ipvx_enabled_current = tpa_info->ipvx_enabled_required;
                        tpa_info->state = TPA_STATE_NONE; /* Done with ramrods... */
                        if (tpa_info->update_cookie)
                        {
                            cookie = (void *)tpa_info->update_cookie;
                            tpa_info->update_cookie = NULL;
                            mm_set_done(pdev, cid, cookie);
                        }
                        
                }
            }
            if (!IS_PFDEV(pdev))
            {
                return; /*To prevent lm_sq_completion processing for non existing (not submited) pending item*/
            }
            break;
        case RAMROD_CMD_ID_ETH_TERMINATE:
            DbgBreakIf(lm_get_con_state(pdev, cid) != LM_CON_STATE_HALT);
            lm_set_con_state(pdev, cid, LM_CON_STATE_TERMINATE);
            DbgMessage(pdev, WARNl2sp, "lm_eth_comp_cb:RAMROD_CMD_ID_ETH_TERMINATE- calling lm_extract_ramrod_req!\n");
            break;

        default:
            DbgMessage(pdev, FATAL,"lm_eth_init_command_comp_cb unhandled ramrod comp command=%d\n",command);
            DbgBreakIf(1); // unhandled ramrod!
            break;
    }
#ifdef __LINUX
    mm_eth_ramrod_comp_cb(pdev, cqe);
#endif //__LINUX
    lm_sq_complete(pdev, CMD_PRIORITY_NORMAL, command, ETH_CONNECTION_TYPE, cid);
}

/**
 * @Description
 *      Function is the callback function for completing eth
 *      completions when no chip access exists. Part of
 *      "complete-pending-sq" flow
 * @param pdev
 * @param spe
 */
void lm_eth_comp_cb(struct _lm_device_t *pdev, struct sq_pending_command * pending)
{
    struct common_ramrod_eth_rx_cqe cqe;

    /* The idea is to prepare a cqe and call: common_ramrod_eth_rx_cqe */
    cqe.conn_and_cmd_data     = pending->command.hdr.conn_and_cmd_data;
    cqe.ramrod_type           = RX_ETH_CQE_TYPE_ETH_RAMROD;
    cqe.protocol_data.data_hi = pending->command.protocol_data.hi;
    cqe.protocol_data.data_lo = pending->command.protocol_data.lo;

    switch (pending->cmd)
    {
        /* Ramrods that complete on the EQ */
    case RAMROD_CMD_ID_ETH_RSS_UPDATE:
    case RAMROD_CMD_ID_ETH_FILTER_RULES:
    case RAMROD_CMD_ID_ETH_MULTICAST_RULES:
    case RAMROD_CMD_ID_ETH_FORWARD_SETUP:
    case RAMROD_CMD_ID_ETH_CLASSIFICATION_RULES:
    case RAMROD_CMD_ID_ETH_SET_MAC:
        lm_eq_comp_cb(pdev, pending);
        break;

        /* Ramrods that complete on the RCQ */
    case RAMROD_CMD_ID_ETH_CLIENT_SETUP:
    case RAMROD_CMD_ID_ETH_TX_QUEUE_SETUP:
    case RAMROD_CMD_ID_ETH_CLIENT_UPDATE:
    case RAMROD_CMD_ID_ETH_HALT:
    case RAMROD_CMD_ID_ETH_EMPTY:
    case RAMROD_CMD_ID_ETH_TERMINATE:
        lm_eth_init_command_comp(pdev, &cqe);
        break;

    default:
        DbgBreakMsg("Unknown cmd");
    }
}

u8_t lm_check_mac_addr_exist(struct _lm_device_t *pdev, u8_t chain_idx, u8_t *mac_addr, u16_t vlan_tag, u8_t is_encap_inner_mac_filter)
{
	struct ecore_vlan_mac_obj          *dest_obj     = NULL;	
	ecore_status_t                      ecore_status = ECORE_SUCCESS;
	u8_t                                is_exist       = FALSE;
	union ecore_classification_ramrod_data 
					classification_ramrod_data = {{{0}}};

	if ERR_IF(!pdev || !mac_addr)
	{
	    DbgBreakMsg("lm_move_mac_addr: invalid params\n");
	    return LM_STATUS_INVALID_PARAMETER;
	}
#if 0
	if (lm_reset_is_inprogress(pdev))
	{
	    DbgMessage(pdev, FATAL, "lm_move_mac_addr: Under FLR!!!\n");
	    return  LM_STATUS_SUCCESS;
	}
#endif

	if (vlan_tag != LM_SET_CAM_NO_VLAN_FILTER)
	{
	    dest_obj = &pdev->client_info[chain_idx].mac_vlan_obj;
	    mm_memcpy(classification_ramrod_data.vlan_mac.mac, mac_addr, sizeof(classification_ramrod_data.vlan_mac.mac));
	    classification_ramrod_data.vlan_mac.vlan = vlan_tag;
	    classification_ramrod_data.vlan_mac.is_inner_mac = is_encap_inner_mac_filter;
	}
	else
	{
	    dest_obj = &pdev->client_info[chain_idx].mac_obj;
            mm_memcpy(classification_ramrod_data.mac.mac, mac_addr, sizeof(classification_ramrod_data.mac.mac) );
            classification_ramrod_data.mac.is_inner_mac = is_encap_inner_mac_filter;
	}

	ecore_status = dest_obj->check_add(pdev,dest_obj,&classification_ramrod_data);
	if (ecore_status == ECORE_EXISTS)
	{
            is_exist = TRUE;
	}
	else if (ecore_status == ECORE_SUCCESS)
	{
	    is_exist = FALSE;
	}
	else
	{
	    DbgBreak();
	}
	return is_exist;
}

lm_status_t lm_update_default_vlan(IN struct _lm_device_t    *pdev, IN u8_t client_idx,
                              IN const u16_t            silent_vlan_value,
                              IN const u16_t            silent_vlan_mask,
                              IN const u8_t             silent_vlan_removal_flg,
                              IN const u8_t             silent_vlan_change_flg,
                              IN const u16_t            default_vlan,
                              IN const u8_t             default_vlan_enable_flg,
                              IN const u8_t             default_vlan_change_flg)
{
    struct client_update_ramrod_data * client_update_data_virt = pdev->client_info[client_idx].update.data_virt;
    lm_status_t                        lm_status               = LM_STATUS_FAILURE;
    u32_t                              con_state               = 0;
    const u32_t                        cid                     = client_idx; //lm_get_cid_from_sw_client_idx(pdev);

    if CHK_NULL(client_update_data_virt)
    {
        return LM_STATUS_FAILURE;
    }

    mm_mem_zero(client_update_data_virt , sizeof(struct client_update_ramrod_data));

    MM_ACQUIRE_ETH_CON_LOCK(pdev);

    // We will send a client update ramrod in any case we can we don't optimize this flow.
    // Client setup may already took the correct NIV value but the ramrod will be sent anyway
    con_state = lm_get_con_state(pdev, cid);
    if((LM_CON_STATE_OPEN != con_state) &&
        (LM_CON_STATE_OPEN_SENT != con_state))
    {
        // Clinet is not in a state that it can recieve the ramrod
        MM_RELEASE_ETH_CON_LOCK(pdev);
        return LM_STATUS_ABORTED;
    }

    /* We don't expect this function to be called for non eth regular connections.
     * If we hit this assert it means we need support for SRIOV +  AFEX
     */
    if (cid >= MAX_RX_CHAIN(pdev))
    {
        DbgBreakIf(cid >= MAX_RX_CHAIN(pdev));
        MM_RELEASE_ETH_CON_LOCK(pdev);
        return LM_STATUS_FAILURE;
    }

    DbgBreakIf( LM_CLI_UPDATE_NOT_USED != pdev->client_info[client_idx].update.state);

    pdev->client_info[client_idx].update.state = LM_CLI_UPDATE_USED;

    client_update_data_virt->client_id  = LM_FW_CLI_ID(pdev, client_idx);
    client_update_data_virt->func_id    = FUNC_ID(pdev); /* FIXME: VFID needs to be given here for VFs... */

    client_update_data_virt->silent_vlan_value          = mm_cpu_to_le16(silent_vlan_value);
    client_update_data_virt->silent_vlan_mask           = mm_cpu_to_le16(silent_vlan_mask);
    client_update_data_virt->silent_vlan_removal_flg    = silent_vlan_removal_flg;
    client_update_data_virt->silent_vlan_change_flg     = silent_vlan_change_flg;

    client_update_data_virt->refuse_outband_vlan_flg        = 0;
    client_update_data_virt->refuse_outband_vlan_change_flg = 0;
    client_update_data_virt->default_vlan = default_vlan;
    client_update_data_virt->default_vlan_enable_flg    = default_vlan_enable_flg;
    client_update_data_virt->default_vlan_change_flg    = default_vlan_change_flg;

    lm_status = lm_sq_post(pdev,
                           cid,
                           RAMROD_CMD_ID_ETH_CLIENT_UPDATE,
                           CMD_PRIORITY_MEDIUM,
                           ETH_CONNECTION_TYPE,
                           pdev->client_info[client_idx].update.data_phys.as_u64);

    MM_RELEASE_ETH_CON_LOCK(pdev);


    if (lm_status != LM_STATUS_SUCCESS)
    {
        return lm_status;
    }

    lm_status = lm_wait_state_change(pdev, &pdev->client_info[client_idx].update.state, LM_CLI_UPDATE_RECV);

    pdev->client_info[client_idx].update.state = LM_CLI_UPDATE_NOT_USED;

    return lm_status;
}

