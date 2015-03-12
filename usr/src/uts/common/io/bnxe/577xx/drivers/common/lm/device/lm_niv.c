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
 *
 *
 * History:
 *    11/29/10 Alon Elhanani       Inception.
 ******************************************************************************/

#include "lm5710.h"
#include "mcp_shmem.h"
#include "mac_stats.h"

static void lm_niv_set_loopback_mode_imp(struct _lm_device_t *pdev, IN const u8_t b_enable )
{
   lm_status_t                                             lm_status     = LM_STATUS_SUCCESS;
   struct function_update_data*            data              = LM_SLOWPATH(pdev, niv_function_update_data);
   const lm_address_t                              data_phys     = LM_SLOWPATH_PHYS(pdev, niv_function_update_data);
   const niv_ramrod_state_t                        initial_state = b_enable ? NIV_RAMROD_SET_LOOPBACK_POSTED :NIV_RAMROD_CLEAR_LOOPBACK_POSTED ;

   data->vif_id_change_flg                         = FALSE;
   data->afex_default_vlan_change_flg  = TRUE;
   data->afex_default_vlan                         = mm_cpu_to_le16(NIV_DEFAULT_VLAN(pdev));
   data->allowed_priorities_change_flg = TRUE;
   data->allowed_priorities                        = NIV_ALLOWED_PRIORITIES(pdev);
   data->network_cos_mode_change_flg   = FALSE;

   data->lb_mode_en                                        = b_enable;
   data->lb_mode_en_change_flg             = 1;
   data->echo                                              = FUNC_UPDATE_RAMROD_SOURCE_NIV;

   lm_status = lm_niv_post_command(pdev,RAMROD_CMD_ID_COMMON_FUNCTION_UPDATE, data_phys.as_u64, initial_state);
}

/**lm_niv_cli_update
 * Update each client with new NIV default VLAN
 *
 * @param pdev the device to use
 *
 * @return lm_status_t LM_STATUS_SUCCESS on success, some other
 *            failure code on failure.
 */
static lm_status_t lm_niv_clients_update(IN                lm_device_t *pdev)
{
   lm_status_t lm_status             = LM_STATUS_FAILURE;
   u16_t           silent_vlan_value = NIV_DEFAULT_VLAN(pdev);
   u16_t           silent_vlan_mask  = ETHERNET_VLAN_ID_MASK;
   u8_t            cid                       = 0;
   u8_t            client_id         = 0;

   if(FUNC_MF_CFG_AFEX_VLAN_TRUNK_TAG_NATIVE_MODE == AFEX_VLAN_MODE(pdev))
   {
           // In this mode FW should remove all VLANS
           silent_vlan_value   = 0;
           silent_vlan_mask        = 0;
   }

   /* init l2 client conn param with default mtu values */
   for (cid = 0; cid < (LM_SB_CNT(pdev) + MAX_NON_RSS_CHAINS); cid++) //pdev->params.l2_cli_con_params
   {
           /* We want only Ethernet clients. For ethernet cid == client_id, we base the following check on that */
           if((OOO_CID(pdev) != cid) && //For OOO_CID we don't want to strip the VLAN
              (FWD_CID(pdev) != cid))   //The FWD_CID is TX only In T7.4 we should enable only for RX clients.
           {
                   client_id = cid; // TODO: For ethernet client_id == cid... extra parameter added for terminology clearness incase this changes in the future.
                   lm_status = lm_update_eth_client(pdev, client_id, silent_vlan_value, silent_vlan_mask, 1, 1);

                   if((LM_STATUS_ABORTED != lm_status) &&
                      (LM_STATUS_SUCCESS != lm_status))
                   {
                           return lm_status;
                   }
           }
   }

   return LM_STATUS_SUCCESS;
}

static void lm_niv_set_loopback_mode_enable(struct _lm_device_t *pdev)
{
   lm_status_t lm_status                           = LM_STATUS_FAILURE;

   lm_hardware_mf_info_t   *mf_info        = &pdev->hw_info.mf_info;

   // loopback tests will use default vlan 0x1 must be a value diffrent from zero,
   // TODO : ask Barak that DIAG test will change the value in SHMEM.
   mf_info->default_vlan = 0x1;
   mf_info->niv_allowed_priorities = 0xff;

   lm_niv_set_loopback_mode_imp(pdev, TRUE);

   lm_status = lm_niv_clients_update(pdev);

   if (LM_STATUS_SUCCESS != lm_status)
   {
      DbgBreakMsg("lm_niv_cli_update failed ");
   }
}

static void lm_niv_set_loopback_mode_disable(struct _lm_device_t *pdev)
{
   lm_hardware_mf_info_t   *mf_info         = &pdev->hw_info.mf_info;

   // loopback tests revert values (has no real effect except debugging)
   mf_info->default_vlan = 0;
   mf_info->niv_allowed_priorities = 0;

   lm_niv_set_loopback_mode_imp(pdev, FALSE);
}

lm_status_t lm_niv_set_loopback_mode(struct _lm_device_t *pdev, IN const u8_t b_enable)
{
   lm_status_t lm_status = LM_STATUS_SUCCESS;

   if (b_enable)
   {
#ifdef EDIAG
           lm_niv_set_loopback_mode_enable(pdev);
#else
           lm_status = MM_REGISTER_LPME(pdev, lm_niv_set_loopback_mode_enable, TRUE, FALSE);
#endif
   }
   else
   {
#ifdef EDIAG
           lm_niv_set_loopback_mode_disable(pdev);
#else
           lm_status = MM_REGISTER_LPME(pdev, lm_niv_set_loopback_mode_disable, TRUE, FALSE);
#endif
   }

   return lm_status;
}

/**lm_niv_vif_enable
 * enable current function or change its parameters. This
 * function must be run in PASSIVE IRQL.
 *
 * @param pdev the device to use
 *
 * @return lm_status_t LM_STATUS_SUCCESS on success, some other
 *            failure code on failure.
 */
static lm_status_t lm_niv_vif_enable(lm_device_t *pdev)
{
   lm_status_t lm_status                   = LM_STATUS_FAILURE;
   u16_t           vif_id                          = 0;
   u16_t           default_vlan            = 0;
   u8_t            allowed_priorities  = 0;
   const u32_t VLAN_PRIORITY_SHIFT = 13;

   ///Refresh MF CFG values
   lm_status = lm_get_shmem_mf_cfg_info_niv(pdev);

   if (LM_STATUS_SUCCESS != lm_status)
   {
           return lm_status;
   }

   //Reconfigure rate-limit
   MM_ACQUIRE_PHY_LOCK(pdev);
   lm_reload_link_and_cmng(pdev);
   MM_RELEASE_PHY_LOCK(pdev);

   ///Send function-update ramrod and wait for completion
   vif_id                     = VIF_ID(pdev);
   default_vlan       = NIV_DEFAULT_VLAN(pdev) | (NIV_DEFAULT_COS(pdev) << VLAN_PRIORITY_SHIFT);
   allowed_priorities = NIV_ALLOWED_PRIORITIES(pdev);


   lm_status = lm_niv_vif_update(pdev,vif_id, default_vlan, allowed_priorities);
   if (LM_STATUS_SUCCESS != lm_status)
   {
           return lm_status;
   }

   /* init l2 client conn param with default mtu values */
   lm_status = lm_niv_clients_update(pdev);
   if (LM_STATUS_SUCCESS != lm_status)
   {
           DbgBreakMsg("lm_niv_cli_update failed ");
           return lm_status;
   }

   ///notify "link-up" to miniport
   MM_ACQUIRE_PHY_LOCK(pdev);
   // cq64469 - verify that the link is up before reporting it as active to the miniport
   if (pdev->vars.link.link_up)
   {
           pdev->vars.link_status = LM_STATUS_LINK_ACTIVE;
   }
   mm_indicate_link(pdev, pdev->vars.link_status, pdev->vars.medium);
   MM_RELEASE_PHY_LOCK(pdev);

   return lm_status;
}

/** lm_niv_vif_disable
 * disable current function. This function must be run in
 * PASSIVE IRQL.
 *
 * @param pdev the device to use
 *
 * @return lm_status_t LM_STATUS_SUCCESS on success, some other
 *            failure code on failure.
 */
static lm_status_t lm_niv_vif_disable(lm_device_t *pdev)
{
   lm_status_t lm_status = LM_STATUS_FAILURE;

   ///indicate "link-down"
   MM_ACQUIRE_PHY_LOCK(pdev);

   pdev->vars.link_status = LM_STATUS_LINK_DOWN;
   mm_indicate_link(pdev, pdev->vars.link_status, pdev->vars.medium);

   MM_RELEASE_PHY_LOCK(pdev);

   ///Send function-update ramrod with vif_id=0xFFFF and wait for completion
   lm_status = lm_niv_vif_update(pdev,INVALID_VIF_ID, 0, 0);
   if (LM_STATUS_SUCCESS != lm_status)
   {
           return lm_status;
   }

   return lm_status;
}

/**lm_niv_vif_delete
 * Delete current function. . This function must be run in
 * PASSIVE IRQL.
 *
 * @param pdev the device to use
 *
 * @return lm_status_t LM_STATUS_SUCCESS on success, some other
 *            failure code on failure.
 */
static lm_status_t lm_niv_vif_delete(lm_device_t *pdev)
{
   lm_status_t lm_status = LM_STATUS_FAILURE;

   ///Send a vif-list ramrod with VIF_LIST_RULE_CLEAR_FUNC opcode and wait for completion
   lm_status = lm_niv_vif_list_update(pdev, VIF_LIST_RULE_CLEAR_FUNC, 0/*list_index*/, 0/*func_bit_map*/ ,ABS_FUNC_ID(pdev)/*func_to_clear*/);
   if (LM_STATUS_SUCCESS != lm_status)
   {
           DbgBreakMsg("Failed to clear VIF lists on VIF delete.\n");
           return lm_status;
   }

   lm_status = lm_niv_vif_disable(pdev);
   if (LM_STATUS_SUCCESS != lm_status)
   {
           DbgBreakMsg("Failed to disable VIF on VIF delete.\n");
           return lm_status;
   }

   return lm_status;
}

#define NIV_STATS_ASSIGN_HI_LO(_field, _val) _field##_hi = U64_HI((_val));\
                                                                                    _field##_lo = U64_LO((_val));
/**lm_chip_stats_to_niv_stats
 * Copy relevant fields from driver statistics to the format
 * written to the SHMEM for NIV stats.
 *
 * @param pdev the device to take the stats from
 * @param p_afex_stats the SHMEM structure
 */
static void lm_niv_chip_stats_to_niv_stats(lm_device_t* pdev, OUT struct afex_stats* p_afex_stats)
{
    b10_l2_chip_statistics_t stats           = {0};
    lm_stats_fw_t            *fw_stats       = &pdev->vars.stats.stats_mirror.stats_fw;
    fcoe_stats_info_t        *fcoe_stats_mfw = &pdev->vars.stats.stats_mirror.stats_drv.drv_info_to_mfw.fcoe_stats;
    u64_t                    sum_64          = 0;

   lm_stats_get_l2_chip_stats(pdev, &stats, L2_CHIP_STATISTICS_VER_NUM_1);

    sum_64 = stats.IfHCOutUcastPkts + fw_stats->fcoe.fcoe_tx_pkt_cnt + (HILO_U64(fcoe_stats_mfw->tx_frames_hi, fcoe_stats_mfw->tx_frames_lo ));
    NIV_STATS_ASSIGN_HI_LO(p_afex_stats->tx_unicast_frames, sum_64 );

    sum_64 = stats.IfHCOutUcastOctets + fw_stats->fcoe.fcoe_tx_byte_cnt + (HILO_U64(fcoe_stats_mfw->tx_bytes_hi, fcoe_stats_mfw->tx_bytes_lo ));
    NIV_STATS_ASSIGN_HI_LO(p_afex_stats->tx_unicast_bytes,  sum_64 );

    NIV_STATS_ASSIGN_HI_LO(p_afex_stats->tx_multicast_frames,  stats.IfHCOutMulticastPkts );
    NIV_STATS_ASSIGN_HI_LO(p_afex_stats->tx_multicast_bytes,   stats.IfHCOutMulticastOctets );

    NIV_STATS_ASSIGN_HI_LO(p_afex_stats->tx_broadcast_frames,  stats.IfHCOutBroadcastPkts );
    NIV_STATS_ASSIGN_HI_LO(p_afex_stats->tx_broadcast_bytes,   stats.IfHCOutBroadcastOctets );

    NIV_STATS_ASSIGN_HI_LO(p_afex_stats->tx_frames_discarded, 0 );

    NIV_STATS_ASSIGN_HI_LO(p_afex_stats->tx_frames_dropped,    fw_stats->eth_xstorm_common.client_statistics[LM_CLI_IDX_NDIS].error_drop_pkts);

    sum_64 = stats.IfHCInUcastPkts + fw_stats->fcoe.fcoe_rx_pkt_cnt + (HILO_U64( fcoe_stats_mfw->rx_frames_hi, fcoe_stats_mfw->rx_frames_lo ));
    NIV_STATS_ASSIGN_HI_LO(p_afex_stats->rx_unicast_frames, sum_64 );

    sum_64 = stats.IfHCInUcastOctets + fw_stats->fcoe.fcoe_rx_byte_cnt + (HILO_U64( fcoe_stats_mfw->rx_bytes_hi, fcoe_stats_mfw->rx_bytes_lo ));
    NIV_STATS_ASSIGN_HI_LO(p_afex_stats->rx_unicast_bytes,  sum_64 );

    NIV_STATS_ASSIGN_HI_LO(p_afex_stats->rx_multicast_frames,  stats.IfHCInMulticastPkts );
    NIV_STATS_ASSIGN_HI_LO(p_afex_stats->rx_multicast_bytes,   stats.IfHCInMulticastOctets );

    NIV_STATS_ASSIGN_HI_LO(p_afex_stats->rx_broadcast_frames,  stats.IfHCInBroadcastPkts );
    NIV_STATS_ASSIGN_HI_LO(p_afex_stats->rx_broadcast_bytes,   stats.IfHCInBroadcastOctets );

    NIV_STATS_ASSIGN_HI_LO(p_afex_stats->rx_frames_discarded,  stats.IfInTTL0Discards +
                                                                                                                   stats.EtherStatsOverrsizePkts +
                                                                                                                   fw_stats->eth_tstorm_common.client_statistics[LM_CLI_IDX_NDIS].checksum_discard);

    NIV_STATS_ASSIGN_HI_LO(p_afex_stats->rx_frames_dropped,    stats.IfInMBUFDiscards+
                                                                                                                   fw_stats->fcoe.fcoe_rx_drop_pkt_cnt_tstorm +
                                                                                                                   fw_stats->fcoe.fcoe_rx_drop_pkt_cnt_ustorm );
}

/**lm_niv_stats_get
 * Update NIV statistics in SHMEM. This function runs in PASSIVE
 * IRQL as an LPME.
 *
 * @param pdev the device to use
 */
static void lm_niv_stats_get(lm_device_t *pdev)
{
   u32_t            mcp_resp        = 0;
   u32_t            output_offset   = 0;
   u32_t            *field_ptr      = NULL;
   int              bytes_written   = 0;
   const u32_t      func_mailbox_id = FUNC_MAILBOX_ID(pdev);
   const u32_t      offset          = OFFSETOF(shmem2_region_t, afex_scratchpad_addr_to_write[func_mailbox_id]);
   struct afex_stats afex_stats_var = {0};

    // verify that change in struct afex_stats won't corrupt our small stack
    ASSERT_STATIC( sizeof(afex_stats_var) >= 100 );

    lm_niv_chip_stats_to_niv_stats(pdev, &afex_stats_var);

   ///Read from SHMEM2 the address where the response should be placed
   LM_SHMEM2_READ(pdev, offset, &output_offset);

   ///Write the response to the scratchpad field by field.
    field_ptr = (u32_t*)&afex_stats_var;
    for (bytes_written = 0; bytes_written  < sizeof(afex_stats_var); bytes_written += sizeof(u32_t))
   {
           REG_WR(pdev, output_offset + bytes_written, *field_ptr);
           ++field_ptr;
   }
   ///ACK the MCP message
   lm_mcp_cmd_send_recieve(pdev, lm_mcp_mb_header, DRV_MSG_CODE_AFEX_STATSGET_ACK, 0, MCP_CMD_DEFAULT_TIMEOUT, &mcp_resp);
   DbgBreakIf(mcp_resp != FW_MSG_CODE_AFEX_STATSGET_ACK);
}

/**lm_niv_vif_list_set
 * Modify local information about VIF lists. This function runs
 * in PASSIVE IRQL as an LPME. (PMF only)
 *
 * @param pdev the device to use
 */
static void lm_niv_vif_list_set(lm_device_t *pdev)
{
   lm_status_t lm_status           = LM_STATUS_FAILURE;
   u32_t           list_idx                = 0;
   u32_t           list_bitmap     = 0;
   u32_t           mcp_resp                = 0;
   const u32_t func_mailbox_id = FUNC_MAILBOX_ID(pdev);
   u32_t           offset                  = 0;

   ///Read VIF list id+bitfield from SHMEM2
   offset                  = OFFSETOF(struct shmem2_region, afex_param1_to_driver[func_mailbox_id]);
   LM_SHMEM2_READ(pdev, offset, &list_idx);
   DbgBreakIf(list_idx > 0xFFFF);

   offset                  = OFFSETOF(struct shmem2_region, afex_param2_to_driver[func_mailbox_id]);
   LM_SHMEM2_READ(pdev, offset, &list_bitmap);
   DbgBreakIf(list_bitmap > 0xFF);

   ///Send a vif-list ramrod with VIF_LIST_RULE_SET opcode and wait for completion
   lm_status = lm_niv_vif_list_update(pdev, VIF_LIST_RULE_SET,(u16_t)list_idx, (u8_t)list_bitmap,0);
   DbgBreakIf(lm_status != LM_STATUS_SUCCESS);

   ///ACK the MCP message
   lm_mcp_cmd_send_recieve(pdev, lm_mcp_mb_header, DRV_MSG_CODE_AFEX_LISTSET_ACK, 0, MCP_CMD_DEFAULT_TIMEOUT, &mcp_resp);
   DbgBreakIf(mcp_resp != FW_MSG_CODE_AFEX_LISTSET_ACK);
}

/**lm_niv_vif_list_get
 * Update NIV statistics in SHMEM. This function runs in PASSIVE
 * IRQL as an LPME.
 *
 * @param pdev the device to use
 *
 */
static void lm_niv_vif_list_get(lm_device_t *pdev)
{
   lm_status_t lm_status           = LM_STATUS_FAILURE;
   u32_t           list_idx                = 0;
   u32_t           mcp_resp                = 0;
   const u32_t func_mailbox_id = FUNC_MAILBOX_ID(pdev);
   const u32_t offset              = OFFSETOF(struct shmem2_region, afex_param1_to_driver[func_mailbox_id]);

   ///Read list ID from SHMEM2
   LM_SHMEM2_READ(pdev, offset, &list_idx);
   DbgBreakIf(list_idx > 0xFFFF);

   ///Send a vif-list ramrod with VIF_LIST_RULE_GET opcode and wait for completion
   lm_status = lm_niv_vif_list_update(pdev, VIF_LIST_RULE_GET, (u16_t)list_idx, 0, 0);
   DbgBreakIf (LM_STATUS_SUCCESS != lm_status);

   ///Write response to SHMEM and ACK the MCP message
   lm_mcp_cmd_send_recieve(pdev, lm_mcp_mb_header, DRV_MSG_CODE_AFEX_LISTGET_ACK, pdev->slowpath_info.last_vif_list_bitmap, MCP_CMD_DEFAULT_TIMEOUT, &mcp_resp);
   DbgBreakIf(mcp_resp != FW_MSG_CODE_AFEX_LISTGET_ACK);
}

/**lm_niv_vif_set
 * Handle a VIF-SET command. This function runs in PASSIVE IRQL
 * as an LPME.
 *
 * @param pdev the device to use
 */
static void lm_niv_vif_set(lm_device_t *pdev)
{
   //lm_status_t lm_status           = LM_STATUS_FAILURE;
   u32_t           func_mf_config  = 0;
   u32_t           mcp_resp                = 0;
   u32_t           val                     = 0;
   const u32_t abs_func_id         = ABS_FUNC_ID(pdev);
   const u32_t offset              = OFFSETOF(mf_cfg_t, func_mf_config[abs_func_id].config);

   ///read FUNC-DISABLED and FUNC-DELETED from func_mf_cfg
   LM_MFCFG_READ(pdev, offset, &func_mf_config);

   pdev->hw_info.mf_info.func_mf_cfg = func_mf_config ;

   ///if it's enable, call lm_niv_vif_enable
   ///if it's disable, call lm_niv_vif_disable
   ///if it's delete, call lm_niv_vif_delete
   val = GET_FLAGS(func_mf_config, FUNC_MF_CFG_FUNC_DISABLED|FUNC_MF_CFG_FUNC_DELETED);
   switch(val)
   {
   case FUNC_MF_CFG_FUNC_DISABLED:
           {
                   lm_niv_vif_disable(pdev);
           }
           break;

   case FUNC_MF_CFG_FUNC_DELETED|FUNC_MF_CFG_FUNC_DISABLED:
           {
                   lm_niv_vif_delete(pdev);
           }
           break;

   case 0: //neither=enabled
           {
                   lm_niv_vif_enable(pdev);
           }
           break;

   default:
           {
                   DbgBreakIf(1);//invalid value - FUNC_DELETED without FUNC_DISABLED
           }
           break;
   }

   ///ACK the MCP message
   lm_mcp_cmd_send_recieve(pdev, lm_mcp_mb_header, DRV_MSG_CODE_AFEX_VIFSET_ACK, 0, MCP_CMD_DEFAULT_TIMEOUT, &mcp_resp);
   DbgBreakIf(mcp_resp != FW_MSG_CODE_AFEX_VIFSET_ACK);
}

typedef struct _lm_niv_event_function_t
{
   u32_t niv_event_flag;
   void (*function)(lm_device_t*);
} lm_niv_event_function_t;

/**lm_niv_event
 * handle a NIV-related MCP general attention by scheduling the
 * appropriate work item.
 *
 * @param pdev the device to use
 * @param niv_event the DRIVER_STATUS flags that the MCP sent.
 *                                 It's assumed that only NIV-related flags are
 *                                 set.
 *
 * @return lm_status_t LM_STATUS_SUCCESS on success, some other
 *            failure code on failure.
 */
lm_status_t lm_niv_event(lm_device_t *pdev, const u32_t niv_event)
{
   lm_status_t                                              lm_status                      = LM_STATUS_FAILURE;
   u32_t                                                            event_idx                      = 0;
   u32_t                                                            handled_events                 = 0;
   u32_t                                                            cur_event                      = 0;
   static const lm_niv_event_function_t event_functions_arr[]  = { {DRV_STATUS_AFEX_VIFSET_REQ,   lm_niv_vif_set},
                                                                                                                                   {DRV_STATUS_AFEX_LISTGET_REQ,  lm_niv_vif_list_get},
                                                                                                                                   {DRV_STATUS_AFEX_LISTSET_REQ,  lm_niv_vif_list_set},
                                                                                                                                   {DRV_STATUS_AFEX_STATSGET_REQ, lm_niv_stats_get},
                                                                                                                             };

   //for every possible flag: if it's set, schedule a WI with the associated function and set the same flag in handled_events
   for (event_idx = 0; event_idx < ARRSIZE(event_functions_arr); ++event_idx)
   {
           cur_event = event_functions_arr[event_idx].niv_event_flag;

           if (GET_FLAGS(niv_event, cur_event))
           {
                   lm_status = MM_REGISTER_LPME(pdev, event_functions_arr[event_idx].function, TRUE, TRUE);
                   if (lm_status != LM_STATUS_SUCCESS)
                   {
                           DbgBreakIf(lm_status != LM_STATUS_SUCCESS);
                           return lm_status;
                   }
                   SET_FLAGS(handled_events, cur_event);
           }
   }

   //make sure there we no unknown events set.
   if (handled_events != niv_event)
   {
           DbgBreakIf(handled_events != niv_event);
           return LM_STATUS_INVALID_PARAMETER;
   }

   return lm_status;
}
