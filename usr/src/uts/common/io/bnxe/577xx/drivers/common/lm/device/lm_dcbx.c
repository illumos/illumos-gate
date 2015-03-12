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
 *    01/10/10 Shay Haroush    Inception.
 ******************************************************************************/

#include "lm5710.h"
#include "license.h"
#include "mcp_shmem.h"
#include "577xx_int_offsets.h"
#include "command.h"


#define DCBX_ILLEGAL_PG     (0xFF)
typedef struct _pg_entry_help_data_t
{
    u8_t    num_of_dif_pri;
    u8_t    pg;
    u32_t   pg_priority;
}pg_entry_help_data_t;

typedef struct _pg_help_data_t
{
    pg_entry_help_data_t    pg_entry_data[LLFC_DRIVER_TRAFFIC_TYPE_MAX];
    u8_t                    num_of_pg;
}pg_help_data_t;

// Used for IE classification debugging
typedef struct _lm_dcbx_ie_classif_dbg_t
{
    u16_t   pri;
    u8_t    num_entries;
}lm_dcbx_ie_classif_dbg_t;

#define DCBX_INVALID_COS_BW         (0xFFFFFFFF)
#define DCBX_MAX_COS_BW             (0xFF)


#define DCBX_MIB_IS_APP_ENABLED(_app_en,_mib_error_filed)                               \
                                ((TRUE == _app_en) &&                                   \
                                 (!GET_FLAGS(_mib_error_filed,(DCBX_LOCAL_APP_ERROR| DCBX_LOCAL_APP_MISMATCH))))

#define DCBX_MIB_IS_ETS_ENABLED(_app_en,_mib_error_filed,_mib_ets_en_filed)             \
                                ((TRUE == _app_en)&&                                    \
                                 (!GET_FLAGS(_mib_error_filed,DCBX_LOCAL_ETS_ERROR))&&  \
                                 _mib_ets_en_filed)

#define DCBX_MIB_IS_PFC_ENABLED(_app_en,_mib_error_filed,_mib_pfc_en_filed)             \
                                ((TRUE == _app_en)&&                                    \
                                 (!GET_FLAGS(_mib_error_filed,(DCBX_LOCAL_PFC_ERROR | DCBX_LOCAL_PFC_MISMATCH)))&&  \
                                 _mib_pfc_en_filed)


typedef struct _cos_entry_help_data_t
{
    u32_t                   pri_join_mask;
    u32_t                   cos_bw;
    u8_t    s_pri;
    u8_t                    b_pausable;
}cos_entry_help_data_t;

typedef struct _cos_help_data_t
{
    cos_entry_help_data_t   entry_data[DCBX_COS_MAX_NUM];
    u8_t                    num_of_cos;
}cos_help_data_t;

/**********************foreword declaration************************************/
/**
 * @description
 * Function is needed for PMF migration in order to synchronize
 * the new PMF that DCBX results has ended.
 * @param pdev
 *
 * @return u8_t
 * This function returns TRUE if DCBX completion received on
 * this port
 */
STATIC u8_t
lm_dcbx_check_drv_flags(
    IN struct _lm_device_t  *pdev,
    IN const  u32_t         flags_bits_to_check);

/*******************************************************************************
 * Description: Parse ets_pri_pg data and spread it from nibble to 32 bits.
 *
 * Return:
******************************************************************************/
STATIC void
lm_dcbx_get_ets_pri_pg_tbl(struct _lm_device_t      * pdev,
                           OUT u32_t                * set_configuration_ets_pg,
                           IN const u32_t           * mcp_pri_pg_tbl,
                           IN const u8_t            set_priority_app_size,
                           IN const u8_t            mcp_pri_pg_tbl_size);


void lm_dcbx_update_lpme_set_params(struct _lm_device_t *pdev);

STATIC void
lm_dcbx_ie_ets_cee_to_ieee_unparse(
    INOUT       lm_device_t         *pdev,
    IN const    dcbx_ets_feature_t  *cee_ets,
    OUT         dcb_ets_tsa_param_t *ieee_ets,
    OUT         u32_t               *flags
    );

STATIC lm_status_t
lm_dcbx_read_admin_mib( IN  lm_device_t         *pdev,
                        OUT lldp_admin_mib_t    *p_admin_mib,
                        OUT u32_t               *p_admin_mib_offset);

/**********************Start of PFC code**************************************/

/**
 * Check if DCB is configured.
 * In SF is_dcbx_neg_received is always valid.
 * DRV_FLAGS_DCB_CONFIGURED is always valid.
 * @param pdev
 *
 * @return u8_t
 */
u8_t
lm_dcbx_is_dcb_config(IN lm_device_t   *pdev)
{
    // Valid in SF
    u8_t const  dcb_config_sf   = pdev->dcbx_info.is_dcbx_neg_received;
    // Always valid.
    u8_t const  dcb_config      = lm_dcbx_check_drv_flags(pdev, DRV_FLAGS_DCB_CONFIGURED);

    if(FALSE == IS_MULTI_VNIC(pdev))
    {
        DbgBreakIf(dcb_config != dcb_config_sf);
    }

    return dcb_config;
}
/*******************************************************************************
 * Description: Fill Fw struct that will be sent in DCBX start ramrod
 *
 * Return:
 ******************************************************************************/
void
lm_dcbx_print_cos_params(
    IN OUT   lm_device_t                    *pdev,
    IN struct flow_control_configuration    *pfc_fw_cfg)
{
#if DBG
    u8_t   pri                                      = 0;
    u8_t   cos                                      = 0;

    DbgMessage(pdev, INFORM, "******************DCBX configuration******************************\n");
    DbgMessage(pdev, INFORM, "pfc_fw_cfg->dcb_version %x\n",pfc_fw_cfg->dcb_version);
    DbgMessage(pdev, INFORM, "pdev->params.dcbx_port_params.pfc.priority_non_pauseable_mask %x\n",
                pdev->params.dcbx_port_params.pfc.priority_non_pauseable_mask);

    for( cos =0 ; cos < pdev->params.dcbx_port_params.ets.num_of_cos ; cos++)
    {
        DbgMessage(pdev, INFORM, "pdev->params.dcbx_port_params.ets.cos_params[%d].pri_bitmask %x\n",cos,
                pdev->params.dcbx_port_params.ets.cos_params[cos].pri_bitmask);

        DbgMessage(pdev, INFORM, "pdev->params.dcbx_port_params.ets.cos_params[%d].bw_tbl %x\n",cos,
                pdev->params.dcbx_port_params.ets.cos_params[cos].bw_tbl);

        DbgMessage(pdev, INFORM, "pdev->params.dcbx_port_params.ets.cos_params[%d].strict %x\n",cos,
                pdev->params.dcbx_port_params.ets.cos_params[cos].s_pri);

        DbgMessage(pdev, INFORM, "pdev->params.dcbx_port_params.ets.cos_params[%d].pauseable %x\n",cos,
                pdev->params.dcbx_port_params.ets.cos_params[cos].pauseable);
    }

    for (pri = 0; pri < ARRSIZE(pdev->params.dcbx_port_params.app.traffic_type_priority); pri++)
    {
        DbgMessage(pdev, INFORM, "pfc_fw_cfg->traffic_type_to_priority_cos[%d].priority %x\n",pri,
                    pfc_fw_cfg->traffic_type_to_priority_cos[pri].priority);

        DbgMessage(pdev, INFORM, "pfc_fw_cfg->traffic_type_to_priority_cos[%d].cos %x\n",pri,
                    pfc_fw_cfg->traffic_type_to_priority_cos[pri].cos);
    }

#endif //DBG
}
/*******************************************************************************
 * Description: Fill Fw struct that will be sent in DCBX start ramrod
 *
 * Return:
 ******************************************************************************/
void
lm_dcbx_fw_struct(
    IN OUT   lm_device_t     *pdev)
{
    struct flow_control_configuration   *pfc_fw_cfg = NULL;
    u16_t  pri_bit                                  = 0;
    u8_t   cos                                      = 0;
    u8_t   pri                                      = 0;

    if(CHK_NULL(pdev->dcbx_info.pfc_fw_cfg_virt))
    {
        DbgBreakMsg("lm_pfc_fw_struct_e2:pfc_fw_cfg_virt was not allocated DCBX should have been disabled ");
        return;
    }
    pfc_fw_cfg = (struct flow_control_configuration*)pdev->dcbx_info.pfc_fw_cfg_virt;
    mm_mem_zero(pfc_fw_cfg, sizeof(struct flow_control_configuration));

    pfc_fw_cfg->dcb_version = 0; // Reserved field

    // If priority tagging (app ID) isn't enabled then DCB should be disabled.
    if(FALSE == pdev->params.dcbx_port_params.app.enabled)
    {
        // Disabled DCB at FW.
        pfc_fw_cfg->dcb_enabled = 0;
        return;
    }

    DbgBreakIf(FALSE == pdev->params.dcbx_port_params.dcbx_enabled);

    // Enable priority tagging and DCB at FW
    pfc_fw_cfg->dcb_enabled = 1;
    pfc_fw_cfg->dont_add_pri_0 = 1;

    // Default initialization
    for (pri = 0; pri < ARRSIZE(pfc_fw_cfg->traffic_type_to_priority_cos) ; pri++)
    {
        pfc_fw_cfg->traffic_type_to_priority_cos[pri].priority = LLFC_TRAFFIC_TYPE_TO_PRIORITY_UNMAPPED;
        pfc_fw_cfg->traffic_type_to_priority_cos[pri].cos      = 0;
    }

    // Fill priority parameters
    for (pri = 0; pri < ARRSIZE(pdev->params.dcbx_port_params.app.traffic_type_priority); pri++)
    {
        DbgBreakIf(pdev->params.dcbx_port_params.app.traffic_type_priority[pri] >= MAX_PFC_PRIORITIES);
        pfc_fw_cfg->traffic_type_to_priority_cos[pri].priority =
            (u8_t)pdev->params.dcbx_port_params.app.traffic_type_priority[pri];

        pri_bit = 1 << pfc_fw_cfg->traffic_type_to_priority_cos[pri].priority;
        // Fill COS parameters based on COS calculated to make it more generally for future use
        for( cos =0 ; cos < pdev->params.dcbx_port_params.ets.num_of_cos ; cos++)
        {
            if (pdev->params.dcbx_port_params.ets.cos_params[cos].pri_bitmask & pri_bit)
            {
                pfc_fw_cfg->traffic_type_to_priority_cos[pri].cos = cos;
            }
        }
    }
    lm_dcbx_print_cos_params(pdev,
                             pfc_fw_cfg);

}
/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
static void
lm_pfc_clear(lm_device_t *pdev)
{
    u8_t elink_status = ELINK_STATUS_OK;

    MM_ACQUIRE_PHY_LOCK(pdev);
    RESET_FLAGS(pdev->params.link.feature_config_flags, ELINK_FEATURE_CONFIG_PFC_ENABLED);
    elink_status = elink_update_pfc(&pdev->params.link, &pdev->vars.link, 0);
    DbgBreakIf(ELINK_STATUS_OK != elink_status);
    MM_RELEASE_PHY_LOCK(pdev);
}
/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
static void lm_pfc_set_clc(lm_device_t *pdev)
{
    struct elink_nig_brb_pfc_port_params    pfc_params = {0};
    pg_params_t                             *ets        = &pdev->params.dcbx_port_params.ets;
    u32_t                                   val         = 0;
    u32_t                                   pri_bit     = 0;
    u8_t                                    i           = 0;
    u8_t elink_status = ELINK_STATUS_OK;
    const u32_t                              class_rx_pause    = 0;
    const u32_t                              class_rx_nonpause = 1;

    DbgBreakIf(class_rx_pause == class_rx_nonpause);
    DbgBreakIf((0 != class_rx_pause) && (1 != class_rx_pause));
    DbgBreakIf((0 != class_rx_nonpause) && (1 != class_rx_nonpause));

    // Tx COS configuration
    // Here COS == pri
    pfc_params.num_of_rx_cos_priority_mask = ets->num_of_cos;

    for(i = 0 ; i < ets->num_of_cos ; i++)
    {
        // We configured in this register only the pause-able bits.(non pause-able aren't configure at all)
        // it is done to avoid false pauses from network.
        pfc_params.rx_cos_priority_mask[i] =
            ets->cos_params[i].pri_bitmask & LM_DCBX_PFC_PRI_PAUSE_MASK(pdev);
    }

    // Rx COS configuration
    // Changing PFC RX configuration . In RX COS0 will always be configured to lossless
    // and COS1 to lossy.
    // Here i == pri
    for(i = 0 ; i < MAX_PFC_PRIORITIES ; i++)
    {
        pri_bit = 1 << i;

        if(pri_bit & LM_DCBX_PFC_PRI_PAUSE_MASK(pdev))
        {
            val |= class_rx_pause << (i * 4);
        }
        else
        {
            val |= class_rx_nonpause << (i * 4);
        }
    }

    pfc_params.pkt_priority_to_cos = val;

    if(0 == class_rx_pause)
    {
        // RX Classs0: On BRB class0 trigger PFC TX. Classes are low-priority for port #. When PFC is triggered on class 0 send PFC with this priorities to stop
    pfc_params.llfc_low_priority_classes = LM_DCBX_PFC_PRI_PAUSE_MASK(pdev);
        // RX Classs1: On BRB class1 trigger PFC TX. Classes are low-priority for port #. When PFC is triggered on class 1 send PFC with this priorities to stop
    pfc_params.llfc_high_priority_classes = 0;
    }
    else
    {
        DbgBreakIf(1 != class_rx_pause);
        pfc_params.llfc_low_priority_classes    = 0;
        pfc_params.llfc_high_priority_classes   = LM_DCBX_PFC_PRI_PAUSE_MASK(pdev);
    }

    MM_ACQUIRE_PHY_LOCK(pdev);
    SET_FLAGS(pdev->params.link.feature_config_flags, ELINK_FEATURE_CONFIG_PFC_ENABLED);
    elink_status = elink_update_pfc(&pdev->params.link, &pdev->vars.link, &pfc_params);
    DbgBreakIf(ELINK_STATUS_OK != elink_status);
    MM_RELEASE_PHY_LOCK(pdev);
}
/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void
lm_pfc_set_pfc(
    lm_device_t *pdev)
{
    DbgBreakIf(CHIP_IS_E1x(pdev));
        //1.       Fills up common PFC structures if required.
        //2.       Configure BRB
        //3.       Configure NIG.
        //4.       Configure the MAC via the CLC:
        //"        CLC must first check if BMAC is not in reset and only then configures the BMAC
        //"        Or, configure EMAC.
        lm_pfc_set_clc(pdev);
    }

/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void
lm_pfc_handle_pfc(
    lm_device_t *pdev)
{
    DbgBreakIf(CHIP_IS_E1x(pdev));
    // Only for testing DCBX client the registry key won't be 0 or 1
    // Only a call from lm_chip_init can be not 0 or 1
    if(TRUE == pdev->params.dcbx_port_params.pfc.enabled)
    {// PFC enabled
        lm_pfc_set_pfc(pdev);
    }
    else
    {// PFC disabled go back to pause if needed
            lm_pfc_clear(pdev);
        }
    }

void
lm_dcbx_2cos_limit_update_ets_config(
    lm_device_t *pdev)
{

    pg_params_t *ets = &(pdev->params.dcbx_port_params.ets);
    u8_t        elink_status = ELINK_STATUS_OK;
    u32_t       bw_tbl_0 = 0;
    u32_t       bw_tbl_1 = 0;

    if ((0 == ets->num_of_cos ) ||
        (DCBX_COS_MAX_NUM_E2E3A0 < ets->num_of_cos))
    {
        DbgMessage(pdev, FATAL, " illegal num of cos= %x",ets->num_of_cos);
        DbgBreakIf(1);
        return;
    }
    //valid COS entries
    if( 1 == ets->num_of_cos)
    {// No ETS
        return;
    }
    DbgBreakIf(2 != ets->num_of_cos);

    if(((DCBX_S_PRI_INVALID == ets->cos_params[0].s_pri)&&
       (DCBX_INVALID_COS_BW == ets->cos_params[0].bw_tbl)) ||
       ((DCBX_S_PRI_INVALID == ets->cos_params[1].s_pri)&&
       (DCBX_INVALID_COS_BW == ets->cos_params[1].bw_tbl)))
    {
        DbgMessage(pdev, FATAL, "We expect all the COS to have at least bw_limit or strict"
                               "ets->cos_params[0].strict= %x"
                               "ets->cos_params[0].bw_tbl= %x"
                               "ets->cos_params[1].strict= %x"
                               "ets->cos_params[1].bw_tbl= %x"
                                ,ets->cos_params[0].s_pri, ets->cos_params[0].bw_tbl
                                ,ets->cos_params[1].s_pri, ets->cos_params[1].bw_tbl);

        // CQ47518,CQ47504 Assert in the eVBD because of illegal ETS parameters reception. When
        //switch changes configuration in runtime it sends several packets that
        //contain illegal configuration until the actual configuration is merged.
        //DbgBreakIf(1);
        return;
    }
    // If we join a group and there is bw_tbl and strict then bw rules.
    if ((DCBX_INVALID_COS_BW != ets->cos_params[0].bw_tbl) &&
        (DCBX_INVALID_COS_BW != ets->cos_params[1].bw_tbl))
    {
        DbgBreakIf(0 == (ets->cos_params[0].bw_tbl + ets->cos_params[1].bw_tbl));
        // ETS 0 100 PBF bug.
        bw_tbl_0 = ets->cos_params[0].bw_tbl;
        bw_tbl_1 = ets->cos_params[1].bw_tbl;

        if((0 == bw_tbl_0)||
           (0 == bw_tbl_1))
        {
            if(0 == bw_tbl_0)
            {
                bw_tbl_0 = 1;
                bw_tbl_1 = 99;
            }
            else
    {
                bw_tbl_0 = 99;
                bw_tbl_1 = 1;
            }

        }
        // The priority is assign as BW
        ets->cos_params[0].s_pri = DCBX_S_PRI_INVALID;
        ets->cos_params[1].s_pri = DCBX_S_PRI_INVALID;
        elink_ets_bw_limit(&pdev->params.link,
                           bw_tbl_0,
                           bw_tbl_1);
    }
    else
    {
        ets->cos_params[0].bw_tbl = DCBX_INVALID_COS_BW;
        ets->cos_params[1].bw_tbl = DCBX_INVALID_COS_BW;
        // The priority is assign as Strict
        DbgBreakIf(ets->cos_params[0].s_pri == ets->cos_params[1].s_pri);
        if(DCBX_S_PRI_COS_HIGHEST ==  ets->cos_params[0].s_pri)
        {
            ets->cos_params[1].s_pri =
                DCBX_S_PRI_COS_NEXT_LOWER_PRI(DCBX_S_PRI_COS_HIGHEST);
            elink_status = elink_ets_strict(&pdev->params.link,0);
        }
        else if(DCBX_S_PRI_COS_HIGHEST ==  ets->cos_params[1].s_pri)
        {
            ets->cos_params[0].s_pri =
                DCBX_S_PRI_COS_NEXT_LOWER_PRI(DCBX_S_PRI_COS_HIGHEST);
            elink_status = elink_ets_strict(&pdev->params.link,1);
        }

        if(ELINK_STATUS_OK != elink_status)
        {
            DbgBreakMsg("lm_dcbx_update_ets_params: elinc_ets_strict failed ");
        }
    }
}
/**
 * @description
 * Set ETS configuration in E3B0.
 * In E3B0 the configuration may have more than 2 COS.
 * @param pdev
 */
void
lm_dcbx_update_ets_config(
    IN lm_device_t *pdev)
{
    pg_params_t *ets                        = &(pdev->params.dcbx_port_params.ets);
    struct      elink_ets_params ets_params = {0};
    u8_t        elink_status                = ELINK_STATUS_OK;
    u8_t        i                           = 0;

    ets_params.num_of_cos = ets->num_of_cos;

    for(i = 0 ; i < ets->num_of_cos; i++)
    {
        if(DCBX_S_PRI_INVALID != ets->cos_params[i].s_pri)
        {// COS is SP
            if(DCBX_INVALID_COS_BW != ets->cos_params[i].bw_tbl)
            {
                DbgBreakMsg("lm_dcbx_update_ets_e3b0_params :COS can't be not BW and not SP");
                return;
            }
            ets_params.cos[i].state = elink_cos_state_strict;
            ets_params.cos[i].params.sp_params.pri = ets->cos_params[i].s_pri;
        }
        else
        {// COS is BW
            if(DCBX_INVALID_COS_BW == ets->cos_params[i].bw_tbl)
            {
                DbgBreakMsg("lm_dcbx_update_ets_e3b0_params :COS can't be not BW and not SP");
                return;
            }
            ets_params.cos[i].state                 = elink_cos_state_bw;
            ets_params.cos[i].params.bw_params.bw   = (u8_t)ets->cos_params[i].bw_tbl;
        }

    }

    // Configure the ETS in HW.
    elink_status = elink_ets_e3b0_config(&pdev->params.link,
                                         &pdev->vars.link,
                                         &ets_params);

    if(ELINK_STATUS_OK != elink_status)
    {
        DbgBreakMsg("lm_dcbx_update_ets_e3b0_params: ets_e3b0_config failed ");
        elink_status = elink_ets_disabled(&pdev->params.link,
                                          &pdev->vars.link);
    }
}
/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
void
lm_dcbx_update_ets_params(
    IN lm_device_t *pdev)
{
    pg_params_t *ets            = &(pdev->params.dcbx_port_params.ets);
    u8_t        elink_status    = ELINK_STATUS_OK;

    elink_status = elink_ets_disabled(&pdev->params.link,
                                      &pdev->vars.link);

    if(ELINK_STATUS_OK != elink_status)
    {
        DbgBreakMsg("lm_dcbx_update_ets_params the function elink_ets_disabled failed");
        return;
    }

    if(FALSE == ets->enabled)
    {
        return;
    }

    if(CHIP_IS_E3B0(pdev))
    {
        lm_dcbx_update_ets_config(pdev);
    }
    else
    {
        DbgBreakIf(FALSE == CHIP_IS_E2E3A0(pdev));
        lm_dcbx_2cos_limit_update_ets_config(pdev);
    }

}
/**********************End of PFC code**************************************/
/**********************start DCBX Common FUNCTIONS**************************************/
#define ETH_TYPE_FCOE                   (0x8906)
#define TCP_PORT_ISCSI                  (0xCBC)


/*******************************************************************************
 * Description:
 *              Runtime changes can take more than 1 second and can't be handled
 *              from DPC.
 *              When the PMF detects a DCBX update it will schedule a WI that
 *              will handle the job.
 *              Also the function lm_dcbx_stop_HW_TX/lm_dcbx_resume_HW_TX must be
 *              called in mutual exclusion.
 *              lm_mcp_cmd_send_recieve must be called from default DPC, so when the
 *              WI will finish the processing an interrupt that will be called from
 *              The WI will cause us to enter this function again and send the Ack.
 *
 * Return:
******************************************************************************/
void
lm_dcbx_event(lm_device_t *pdev,
              u32_t         drv_status)
{

    u32_t fw_resp = 0;
    lm_status_t lm_status         = LM_STATUS_SUCCESS ;

    if(IS_PMF(pdev))
    {
        if( GET_FLAGS( drv_status, DRV_STATUS_DCBX_NEGOTIATION_RESULTS))
        {
            switch(pdev->dcbx_info.dcbx_update_lpme_task_state)
            {
            case DCBX_UPDATE_TASK_STATE_FREE:
                // free: this is the first time we saw
                // this DRV_STATUS_DCBX_NEGOTIATION_RES
                if(FALSE == IS_DCB_ENABLED(pdev))
                {
                    return;
                }
                pdev->dcbx_info.dcbx_update_lpme_task_state =
                    DCBX_UPDATE_TASK_STATE_SCHEDULE;
                lm_status = MM_REGISTER_LPME(pdev,
                                             lm_dcbx_update_lpme_set_params,
                                             TRUE,
                                             FALSE);// DCBX sends ramrods

                if (LM_STATUS_SUCCESS != lm_status)
                {
                    pdev->dcbx_info.dcbx_update_lpme_task_state =
                        DCBX_UPDATE_TASK_STATE_FREE;
                    if(LM_STATUS_REQUEST_NOT_ACCEPTED == lm_status)
                    {// DCBX MM_REGISTER_LPME can fail
                        pdev->dcbx_info.lpme_failed_cnt++;
                        return;
                    }
                    pdev->dcbx_info.dcbx_error |= DCBX_ERROR_REGISTER_LPME;
                    // No rollback
                    // Problem because we won't get to DCBX_UPDATE_TASK_STATE_HANDLED (we won't schedule an interrupt)
                    DbgBreakMsg("lm_dcbx_int : The chip QM queues are stuck until an interrupt from MCP");
                    //Free the MCP
                    lm_status = lm_mcp_cmd_send_recieve( pdev,
                                                     lm_mcp_mb_header,
                                                     DRV_MSG_CODE_DCBX_PMF_DRV_OK,
                                                     0,
                                                     MCP_CMD_DEFAULT_TIMEOUT,
                                                     &fw_resp ) ;

                   DbgBreakIf( lm_status != LM_STATUS_SUCCESS );

                }
                break;

            case DCBX_UPDATE_TASK_STATE_SCHEDULE:
                // Schedule: We saw before that DRV_STATUS_DCBX_NEGOTIATION_RES
                // is set before, and didn’t handle it yet
                break;

            case DCBX_UPDATE_TASK_STATE_HANDLED:
                // handled: the WI handled was handled ,The MCP needs to updated
                pdev->dcbx_info.dcbx_update_lpme_task_state =
                    DCBX_UPDATE_TASK_STATE_FREE;

                lm_status = lm_mcp_cmd_send_recieve( pdev,
                                                     lm_mcp_mb_header,
                                                     DRV_MSG_CODE_DCBX_PMF_DRV_OK,
                                                     0,
                                                     MCP_CMD_DEFAULT_TIMEOUT,
                                                     &fw_resp ) ;

                DbgBreakIf( lm_status != LM_STATUS_SUCCESS );
                break;
            default:
                DbgBreakMsg("illegal value for dcbx_update_lpme_task_state");
                break;
            }
        }
    }
}

/*******************************************************************************
 * Description: Calculate the number of priority PG.
 * The number of priority pg should be derived from the available traffic type
 * and pg_pri_orginal_spread configured priorities
 *
 * Return:
 ******************************************************************************/
STATIC void
lm_dcbx_cee_get_num_of_pg_traf_type(
    IN  lm_device_t     *pdev,
    IN  u32_t           pg_pri_orginal_spread[DCBX_MAX_NUM_PRI_PG_ENTRIES],
    OUT pg_help_data_t  *pg_help_data)
{
    u8_t    i                                       = 0;
    u8_t    b_pg_found                              = FALSE;
    u8_t    search_traf_type                        = 0;
    u8_t    add_traf_type                           = 0;
    u8_t    add_pg                                  = 0;

    ASSERT_STATIC( DCBX_MAX_NUM_PRI_PG_ENTRIES == 8);

    // Set to invalid
    for (i = 0; i < ARRSIZE(pg_help_data->pg_entry_data); i++)
    {
        pg_help_data->pg_entry_data[i].pg = DCBX_ILLEGAL_PG;
    }

    for (add_traf_type = 0; add_traf_type < ARRSIZE(pg_help_data->pg_entry_data); add_traf_type++)
    {
        ASSERT_STATIC(ARRSIZE(pg_help_data->pg_entry_data) ==
                      ARRSIZE(pdev->params.dcbx_port_params.app.traffic_type_priority));

        b_pg_found = FALSE;
        if (pdev->params.dcbx_port_params.app.traffic_type_priority[add_traf_type] < MAX_PFC_PRIORITIES)
        {
            add_pg = (u8_t)pg_pri_orginal_spread[pdev->params.dcbx_port_params.app.traffic_type_priority[add_traf_type]];
            for (search_traf_type = 0; search_traf_type < ARRSIZE(pg_help_data->pg_entry_data); search_traf_type++)
            {
                if (pg_help_data->pg_entry_data[search_traf_type].pg == add_pg)
                {
                    if(0 == (pg_help_data->pg_entry_data[search_traf_type].pg_priority &
                             (1 << pdev->params.dcbx_port_params.app.traffic_type_priority[add_traf_type])))
                    {
                        pg_help_data->pg_entry_data[search_traf_type].num_of_dif_pri++;
                    }
                    pg_help_data->pg_entry_data[search_traf_type].pg_priority |=
                        (1 << pdev->params.dcbx_port_params.app.traffic_type_priority[add_traf_type]);

                    b_pg_found = TRUE;
                    break;
                }
            }
            if(FALSE == b_pg_found)
            {
                pg_help_data->pg_entry_data[pg_help_data->num_of_pg].pg             = add_pg;
                pg_help_data->pg_entry_data[pg_help_data->num_of_pg].pg_priority    = (1 << pdev->params.dcbx_port_params.app.traffic_type_priority[add_traf_type]);
                pg_help_data->pg_entry_data[pg_help_data->num_of_pg].num_of_dif_pri = 1;
                pg_help_data->num_of_pg++;
            }
        }
    }
    DbgBreakIf(pg_help_data->num_of_pg > LLFC_DRIVER_TRAFFIC_TYPE_MAX);
}
/*******************************************************************************
 * Description: Still
 *
 * Return:
 ******************************************************************************/
STATIC void
lm_dcbx_fill_cos_entry(
    lm_device_t         *pdev,
    dcbx_cos_params_t   *cos_params,
    const u32_t         pri_join_mask,
    const u32_t         bw,
    const u8_t          pauseable,
    const u8_t          strict)
{
    cos_params->s_pri       = strict;
    cos_params->bw_tbl      = bw;
    cos_params->pri_bitmask = pri_join_mask;


    // This filed is only for debbuging in CHIP_IS_E2E3A0(pdev)
    cos_params->pauseable   = pauseable;

    if((DCBX_INVALID_COS_BW != bw)||
       (DCBX_S_PRI_INVALID != strict))
    {
        DbgBreakIf(0 == pri_join_mask);

        if(CHIP_IS_E2E3A0(pdev))
        {
    if(pauseable)
    {
                DbgBreakIf(0 != LM_DCBX_PFC_PRI_GET_NON_PAUSE(pdev,cos_params->pri_bitmask));
    }
    else
    {
                DbgBreakIf(0 != LM_DCBX_PFC_PRI_GET_PAUSE(pdev,cos_params->pri_bitmask));
            }
        }
    }
}

/**
 * @description
 * Disable ETS.
 * @param pdev
 *
 * @return STATIC void
 */
STATIC void
lm_dcbx_ets_disable(
    INOUT       lm_device_t         *pdev)
{
    pg_params_t *ets = &pdev->params.dcbx_port_params.ets;

    ets->enabled = FALSE;
    ets->num_of_cos = 1;

    ets->cos_params[0].pri_bitmask  = 0xFF;
    ets->cos_params[0].bw_tbl       = DCBX_INVALID_COS_BW;
    ets->cos_params[0].s_pri        = DCBX_S_PRI_COS_HIGHEST;
    ets->cos_params[0].pauseable    =
        LM_DCBX_IS_PFC_PRI_SOME_PAUSE(pdev,ets->cos_params[0].pri_bitmask);
}
/**
 * @description
 * Clean up old settings of ets and initialize the COS param
 * struct.
 * @param pdev
 * @param ets
 *
 * @return STATIC void
 */
STATIC void
lm_dcbx_init_ets_internal_param(
    lm_device_t         *pdev,
    pg_params_t         *ets)
{
    u8_t i = 0;
    ets->enabled = FALSE;
    ets->num_of_cos = 0 ;

    for(i=0; i < ARRSIZE(ets->cos_params) ; i++)
    {
        lm_dcbx_fill_cos_entry(pdev,
                               &ets->cos_params[i],
                               0,
                               DCBX_INVALID_COS_BW,
                               FALSE,
                               DCBX_S_PRI_INVALID);
    }
}
/*******************************************************************************
 * Description: single priority group
 *
 * Return:
 ******************************************************************************/
STATIC void
lm_dcbx_ets_disabled_entry_data(
    IN  lm_device_t                 *pdev,
    OUT cos_help_data_t             *cos_data,
    IN  const   u32_t               pri_join_mask)
{
      // Only one priority than only one COS
    cos_data->entry_data[0].b_pausable      = LM_DCBX_IS_PFC_PRI_ONLY_PAUSE(pdev,pri_join_mask);
        cos_data->entry_data[0].pri_join_mask   = pri_join_mask;
        cos_data->entry_data[0].cos_bw          = 100;
        cos_data->num_of_cos = 1;
}

/*******************************************************************************
 * Description: Updating the cos bw.
 *
 * Return:
 ******************************************************************************/
STATIC void
lm_dcbx_add_to_cos_bw(
    IN      lm_device_t             *pdev,
    OUT     cos_entry_help_data_t   *entry_data,
    IN      u8_t                    pg_bw)
{

    if(DCBX_INVALID_COS_BW == entry_data->cos_bw )
    {

        entry_data->cos_bw =  pg_bw;
    }
    else
    {
        entry_data->cos_bw +=  pg_bw;
    }
    DbgBreakIf(entry_data->cos_bw > DCBX_MAX_COS_BW);
}
/*******************************************************************************
 * Description: single priority group
 *
 * Return:
 ******************************************************************************/
STATIC void
lm_dcbx_separate_pauseable_from_non(
    IN  lm_device_t                 *pdev,
    OUT cos_help_data_t             *cos_data,
    IN  const u32_t                 *pg_pri_orginal_spread,
    IN  const dcbx_ets_feature_t    *ets
    )
{
    u32_t       pri_tested      = 0;
    u8_t        i               = 0;
    u8_t        entry           = 0;
    u8_t        pg_entry        = 0;
    const u8_t  num_of_pri      = ARRSIZE(pdev->params.dcbx_port_params.app.traffic_type_priority);

    cos_data->entry_data[0].b_pausable = TRUE;
    cos_data->entry_data[1].b_pausable = FALSE;
    cos_data->entry_data[0].pri_join_mask = cos_data->entry_data[1].pri_join_mask = 0;

    for(i=0 ; i < num_of_pri ; i++)
    {
        DbgBreakIf(pdev->params.dcbx_port_params.app.traffic_type_priority[i] >= MAX_PFC_PRIORITIES);
        pri_tested = 1 << pdev->params.dcbx_port_params.app.traffic_type_priority[i];

        if(pri_tested & LM_DCBX_PFC_PRI_NON_PAUSE_MASK(pdev))
        {
            cos_data->entry_data[1].pri_join_mask |= pri_tested;
            entry       = 1;
        }
        else
        {
            cos_data->entry_data[0].pri_join_mask |= pri_tested;
            entry = 0;

        }
        pg_entry    = (u8_t)pg_pri_orginal_spread[pdev->params.dcbx_port_params.app.traffic_type_priority[i]];
        // There can be only one strict pg
        if( pg_entry < DCBX_MAX_NUM_PRI_PG_ENTRIES)
        {
            lm_dcbx_add_to_cos_bw(pdev,
                                  &(cos_data->entry_data[entry]),
                                  DCBX_PG_BW_GET(ets->pg_bw_tbl, pg_entry));
        }
        else
        {
            // If we join a group and one is strict than the bw rulls
            cos_data->entry_data[entry].s_pri = DCBX_S_PRI_COS_HIGHEST;
        }
    }//end of for
    // Both groups must have priorities
    DbgBreakIf(( 0 == cos_data->entry_data[0].pri_join_mask) && ( 0 == cos_data->entry_data[1].pri_join_mask));
}

/**
 * @description
 * if the number of requested PG-s in CEE is greater than
 *  expected then the results are not determined since this is a
 *  violation of the standard.
 * @param pdev
 * @param pg_help_data
 * @param required_num_of_pg
 *
 * @return STATIC lm_status_t
 * If we weren't successful in reducing the number of PGs to
 * required_num_of_pg.
 */
STATIC lm_status_t
lm_dcbx_join_pgs(
    IN          lm_device_t         *pdev,
    IN          dcbx_ets_feature_t  *ets,
    INOUT       pg_help_data_t      *pg_help_data,
    IN const    u8_t                required_num_of_pg)
{
    lm_status_t lm_status       = LM_STATUS_SUCCESS;
    u8_t        entry_joined    = pg_help_data->num_of_pg -1;
    u8_t        entry_removed   = entry_joined + 1;
    u8_t        pg_joined       = 0;

    // Algorithm below limitation (-2)
    if((required_num_of_pg < 2 )||
       (ARRSIZE(pg_help_data->pg_entry_data) <= pg_help_data->num_of_pg)||
       ( pg_help_data->num_of_pg <= required_num_of_pg))
    {
        DbgBreakMsg("lm_dcbx_join_pg_data required_num_of_pg can't be zero");
        return LM_STATUS_FAILURE;
    }

    while(required_num_of_pg < pg_help_data->num_of_pg)
    {
        entry_joined = pg_help_data->num_of_pg -2;
        entry_removed = entry_joined + 1;

        pg_help_data->pg_entry_data[entry_joined].pg_priority |=
            pg_help_data->pg_entry_data[entry_removed].pg_priority;

        pg_help_data->pg_entry_data[entry_joined].num_of_dif_pri +=
            pg_help_data->pg_entry_data[entry_removed].num_of_dif_pri;

         if((DCBX_STRICT_PRI_PG == pg_help_data->pg_entry_data[entry_joined].pg ) ||
                (DCBX_STRICT_PRI_PG == pg_help_data->pg_entry_data[entry_removed].pg))
         {
             // Entries joined strict priority rules
             pg_help_data->pg_entry_data[entry_joined].pg = DCBX_STRICT_PRI_PG;
         }
         else
         {
             // Entries can be joined join BW
             pg_joined  = DCBX_PG_BW_GET(ets->pg_bw_tbl, pg_help_data->pg_entry_data[entry_joined].pg) +
                 DCBX_PG_BW_GET(ets->pg_bw_tbl, pg_help_data->pg_entry_data[entry_removed].pg);

             DCBX_PG_BW_SET(ets->pg_bw_tbl, pg_help_data->pg_entry_data[entry_joined].pg,pg_joined);
         }
         // Joined the entries
         pg_help_data->num_of_pg--;
    }
    return lm_status;
}
/**
 * @description
 * Fill pause entries in entry_data
 * @param pdev
 * @param entry_data
 *
 * @return STATIC void
 */
STATIC void
lm_dcbx_ets_fill_cos_entry_data_as_pause(
    IN  lm_device_t             *pdev,
    OUT cos_entry_help_data_t   *entry_data,
    IN  const   u32_t           pri_join_mask
    )
{
    entry_data->b_pausable      = TRUE;
    entry_data->pri_join_mask   = LM_DCBX_PFC_PRI_GET_PAUSE(pdev,pri_join_mask);
}

/**
 * @description
 * Fill pause entries in entry_data
 * @param pdev
 * @param entry_data
 *
 * @return STATIC void
 */
STATIC void
lm_dcbx_ets_fill_cos_entry_data_as_non_pause(
    IN  lm_device_t             *pdev,
    OUT cos_entry_help_data_t   *entry_data,
    IN  const   u32_t           pri_join_mask
    )
{
    entry_data->b_pausable      = FALSE;
    entry_data->pri_join_mask   = LM_DCBX_PFC_PRI_GET_NON_PAUSE(pdev,pri_join_mask);
}
/*******************************************************************************
 * Description: single priority group
 *
 * Return:
 ******************************************************************************/
STATIC void
lm_dcbx_2cos_limit_cee_single_pg_to_cos_params(
    IN  lm_device_t                 *pdev,
    IN  pg_help_data_t              *pg_help_data,
    OUT cos_help_data_t             *cos_data,
    IN  const   u32_t               pri_join_mask,
    IN  const   u8_t                num_of_dif_pri
    )
{
    u8_t                    i                           = 0;
    u32_t                   pri_tested                  = 0;
    u32_t                   pri_mask_without_pri        = 0;

    if(1 == num_of_dif_pri)
    {
      // Only one priority than only one COS
        lm_dcbx_ets_disabled_entry_data(pdev,cos_data,pri_join_mask);
        return;
    }

    if( pg_help_data->pg_entry_data[0].pg < DCBX_MAX_NUM_PG_BW_ENTRIES)
    {// BW limited
        // If there are both pauseable and non-pauseable priorities, the pauseable priorities go to the first queue and the non-pauseable
        // priorities go to the second queue.
        if(LM_DCBX_IS_PFC_PRI_MIX_PAUSE(pdev,pri_join_mask))
        {
            DbgBreakIf( 1 == num_of_dif_pri );
            // Pause able
            lm_dcbx_ets_fill_cos_entry_data_as_pause(
                pdev,
                &cos_data->entry_data[0],
                pri_join_mask);
            // Non pause able.
            lm_dcbx_ets_fill_cos_entry_data_as_non_pause(
                pdev,
                &cos_data->entry_data[1],
                pri_join_mask);

            if(2 == num_of_dif_pri)
            {
                cos_data->entry_data[0].cos_bw = 50;
                cos_data->entry_data[1].cos_bw = 50;
            }
            if (3 == num_of_dif_pri)
            {
                // We need to find out how has only one priority and how has two priorities.
                // If the pri_bitmask is a power of 2 than there is only one priority.
                if(POWER_OF_2(LM_DCBX_PFC_PRI_GET_PAUSE(pdev,pri_join_mask)))
                {
                    DbgBreakIf(POWER_OF_2(LM_DCBX_PFC_PRI_GET_NON_PAUSE(pdev,pri_join_mask)));
                    cos_data->entry_data[0].cos_bw = 33;
                    cos_data->entry_data[1].cos_bw = 67;
                }
                else
                {
                    DbgBreakIf(FALSE == POWER_OF_2(LM_DCBX_PFC_PRI_GET_NON_PAUSE(pdev,pri_join_mask)));
                    cos_data->entry_data[0].cos_bw = 67;
                    cos_data->entry_data[1].cos_bw = 33;
                }
            }
        }
        else if(LM_DCBX_IS_PFC_PRI_ONLY_PAUSE(pdev,pri_join_mask))
        {// If there are only pauseable priorities, then one/two priorities go
         // to the first queue and one priority goes to the second queue.
            if(2 == num_of_dif_pri)
            {
                cos_data->entry_data[0].cos_bw = 50;
                cos_data->entry_data[1].cos_bw = 50;
            }
            else
            {
                DbgBreakIf(3 != num_of_dif_pri);
                cos_data->entry_data[0].cos_bw = 67;
                cos_data->entry_data[1].cos_bw = 33;
            }
            cos_data->entry_data[0].b_pausable       = cos_data->entry_data[1].b_pausable = TRUE;
            // All priorities except FCOE
            cos_data->entry_data[0].pri_join_mask    = (pri_join_mask & ((u8_t)~(1 << pdev->params.dcbx_port_params.app.traffic_type_priority[LLFC_TRAFFIC_TYPE_FCOE])));
            // Only FCOE priority.
            cos_data->entry_data[1].pri_join_mask    = (1 << pdev->params.dcbx_port_params.app.traffic_type_priority[LLFC_TRAFFIC_TYPE_FCOE]);
        }
        else
        {//If there are only non-pauseable priorities, they will all go to the same queue.
            DbgBreakIf(FALSE == LM_DCBX_IS_PFC_PRI_ONLY_NON_PAUSE(pdev,pri_join_mask));
            lm_dcbx_ets_disabled_entry_data(pdev,cos_data,pri_join_mask);
        }
    }
    else
    {
        // priority group which is not BW limited (PG#15):
        DbgBreakIf(DCBX_STRICT_PRI_PG != pg_help_data->pg_entry_data[0].pg);
        if(LM_DCBX_IS_PFC_PRI_MIX_PAUSE(pdev,pri_join_mask))
        {
            // If there are both pauseable and non-pauseable priorities, the pauseable priorities go
            // to the first queue and the non-pauseable priorities go to the second queue.
            if(LM_DCBX_PFC_PRI_GET_PAUSE(pdev,pri_join_mask) > LM_DCBX_PFC_PRI_GET_NON_PAUSE(pdev,pri_join_mask))
            {
                cos_data->entry_data[0].s_pri        = DCBX_S_PRI_COS_HIGHEST;
                cos_data->entry_data[1].s_pri        = DCBX_S_PRI_COS_NEXT_LOWER_PRI(DCBX_S_PRI_COS_HIGHEST);
            }
            else
            {
                cos_data->entry_data[1].s_pri        = DCBX_S_PRI_COS_HIGHEST;
                cos_data->entry_data[0].s_pri        = DCBX_S_PRI_COS_NEXT_LOWER_PRI(DCBX_S_PRI_COS_HIGHEST);
            }
            // Pause able
            lm_dcbx_ets_fill_cos_entry_data_as_pause(
                pdev,
                &cos_data->entry_data[0],
                pri_join_mask);
            // Non pause-able.
            lm_dcbx_ets_fill_cos_entry_data_as_non_pause(
                pdev,
                &cos_data->entry_data[1],
                pri_join_mask);
        }
        else
        {
            // If there are only pauseable priorities or only non-pauseable, the lower priorities
            // go to the first queue and the higher priorities go to the second queue.
            cos_data->entry_data[0].b_pausable = cos_data->entry_data[1].b_pausable = LM_DCBX_IS_PFC_PRI_ONLY_PAUSE(pdev,pri_join_mask);

            for(i=0 ; i < ARRSIZE(pdev->params.dcbx_port_params.app.traffic_type_priority) ; i++)
            {
                DbgBreakIf(pdev->params.dcbx_port_params.app.traffic_type_priority[i] >= MAX_PFC_PRIORITIES);
                pri_tested = 1 << pdev->params.dcbx_port_params.app.traffic_type_priority[i];
                // Remove priority tested
                pri_mask_without_pri = (pri_join_mask & ((u8_t)(~pri_tested)));
                if( pri_mask_without_pri < pri_tested )
                {
                    break;
                }
            }

            if(i == ARRSIZE(pdev->params.dcbx_port_params.app.traffic_type_priority))
            {
                DbgBreakMsg("lm_dcbx_fill_cos_params : Invalid value for pri_join_mask could not find a priority \n");
            }
            cos_data->entry_data[0].pri_join_mask = pri_mask_without_pri;
            cos_data->entry_data[1].pri_join_mask = pri_tested;
            // Both queues are strict priority, and that with the highest priority
            // gets the highest strict priority in the arbiter.
            cos_data->entry_data[1].s_pri      = DCBX_S_PRI_COS_HIGHEST;
            cos_data->entry_data[0].s_pri      = DCBX_S_PRI_COS_NEXT_LOWER_PRI(DCBX_S_PRI_COS_HIGHEST);
        }
    }

}
/*******************************************************************************
 * Description: Still
 *
 * Return:
 ******************************************************************************/
STATIC void
lm_dcbx_2cos_limit_cee_two_pg_to_cos_params(
    IN  lm_device_t                 *pdev,
    IN  pg_help_data_t              *pg_help_data,
    IN  const dcbx_ets_feature_t    *ets,
    OUT cos_help_data_t             *cos_data,
    IN  const u32_t                 *pg_pri_orginal_spread,
    IN  u32_t                       pri_join_mask,
    IN  u8_t                        num_of_dif_pri)
{
    u8_t                    i                           = 0;
    u8_t                    pg[DCBX_COS_MAX_NUM_E2E3A0]           = {0};

    // If there are both pauseable and non-pauseable priorities, the pauseable priorities
    // go to the first queue and the non-pauseable priorities go to the second queue.
    if(LM_DCBX_IS_PFC_PRI_MIX_PAUSE(pdev,pri_join_mask))
    {
        if(LM_DCBX_IS_PFC_PRI_MIX_PAUSE(pdev, pg_help_data->pg_entry_data[0].pg_priority) ||
                LM_DCBX_IS_PFC_PRI_MIX_PAUSE(pdev, pg_help_data->pg_entry_data[1].pg_priority))
        {
            // If one PG contains both pauseable and non-pauseable priorities then ETS is disabled.
            DbgMessage(pdev, WARN, "lm_dcbx_fill_cos_params : PG contains both pauseable and non-pauseable "
                        "priorities -> ETS is disabled. \n");
            lm_dcbx_separate_pauseable_from_non(pdev,cos_data,pg_pri_orginal_spread,ets);
            // ETS disabled wrong configuration
            pdev->params.dcbx_port_params.ets.enabled = FALSE;
            return;
        }

        // Pause-able
        cos_data->entry_data[0].b_pausable = TRUE;
        // Non pause-able.
        cos_data->entry_data[1].b_pausable = FALSE;
        if(LM_DCBX_IS_PFC_PRI_ONLY_PAUSE(pdev, pg_help_data->pg_entry_data[0].pg_priority))
        {// 0 is pause-able
            cos_data->entry_data[0].pri_join_mask    = pg_help_data->pg_entry_data[0].pg_priority;
            pg[0]                                   = pg_help_data->pg_entry_data[0].pg;
            cos_data->entry_data[1].pri_join_mask    = pg_help_data->pg_entry_data[1].pg_priority;
            pg[1]                                   = pg_help_data->pg_entry_data[1].pg;
        }
        else
        {// 1 is pause-able
            cos_data->entry_data[0].pri_join_mask    = pg_help_data->pg_entry_data[1].pg_priority;
            pg[0]                                   = pg_help_data->pg_entry_data[1].pg;
            cos_data->entry_data[1].pri_join_mask    = pg_help_data->pg_entry_data[0].pg_priority;
            pg[1]                                   = pg_help_data->pg_entry_data[0].pg;
        }
    }
    else
    {
        //If there are only pauseable priorities or only non-pauseable, each PG goes to a queue.
        cos_data->entry_data[0].b_pausable       = cos_data->entry_data[1].b_pausable = LM_DCBX_IS_PFC_PRI_ONLY_PAUSE(pdev,pri_join_mask);
        cos_data->entry_data[0].pri_join_mask    = pg_help_data->pg_entry_data[0].pg_priority;
        pg[0]                                   = pg_help_data->pg_entry_data[0].pg;
        cos_data->entry_data[1].pri_join_mask    = pg_help_data->pg_entry_data[1].pg_priority;
        pg[1]                                   = pg_help_data->pg_entry_data[1].pg;
    }

    // There can be only one strict pg
    for(i=0 ; i < ARRSIZE(pg) ; i++)
    {
        if( pg[i] < DCBX_MAX_NUM_PG_BW_ENTRIES)
        {
            cos_data->entry_data[i].cos_bw =  DCBX_PG_BW_GET( ets->pg_bw_tbl,pg[i]);
        }
        else
        {
            cos_data->entry_data[i].s_pri = DCBX_S_PRI_COS_HIGHEST;
        }
    }
}

/*******************************************************************************
 * Description: Still
 *
 * Return:
 ******************************************************************************/
STATIC void
lm_dcbx_2cos_limit_cee_three_pg_to_cos_params(
    IN  lm_device_t                 *pdev,
    IN  pg_help_data_t              *pg_help_data,
    IN  const dcbx_ets_feature_t    *ets,
    OUT cos_help_data_t             *cos_data,
    IN  const u32_t                 *pg_pri_orginal_spread,
    IN  u32_t                       pri_join_mask,
    IN  u8_t                        num_of_dif_pri)
{
    u8_t        i               = 0;
    u32_t       pri_tested      = 0;
    u8_t        entry           = 0;
    u8_t        pg_entry        = 0;
    u8_t        b_found_strict  = FALSE;
    u8_t        num_of_pri      = ARRSIZE(pdev->params.dcbx_port_params.app.traffic_type_priority);
    DbgBreakIf(3 != num_of_pri);
    cos_data->entry_data[0].pri_join_mask = cos_data->entry_data[1].pri_join_mask = 0;
    //- If there are both pauseable and non-pauseable priorities, the pauseable priorities go to the first
    // queue and the non-pauseable priorities go to the second queue.
    if(LM_DCBX_IS_PFC_PRI_MIX_PAUSE(pdev,pri_join_mask))
    {
        lm_dcbx_separate_pauseable_from_non(pdev,cos_data,pg_pri_orginal_spread,ets);
    }
    else
    {
        DbgBreakIf(!(LM_DCBX_IS_PFC_PRI_ONLY_NON_PAUSE(pdev,pri_join_mask) ||
            LM_DCBX_IS_PFC_PRI_ONLY_PAUSE(pdev,pri_join_mask)));

        //- If two BW-limited PG-s were combined to one queue, the BW is their sum.
        //- If there are only pauseable priorities or only non-pauseable, and there are both BW-limited and
        // non-BW-limited PG-s, the BW-limited PG/s go to one queue and the non-BW-limited PG/s go to the
        // second queue.
        //- If there are only pauseable priorities or only non-pauseable and all are BW limited, then
        // two priorities go to the first queue and one priority goes to the second queue.

        //  We will join this two cases:
        // if one is BW limited he will go to the secoend queue otherwise the last priority will get it

        cos_data->entry_data[0].b_pausable = cos_data->entry_data[1].b_pausable = LM_DCBX_IS_PFC_PRI_ONLY_PAUSE(pdev,pri_join_mask);

        for(i=0 ; i < num_of_pri; i++)
        {
            DbgBreakIf(pdev->params.dcbx_port_params.app.traffic_type_priority[i] >= MAX_PFC_PRIORITIES);
            pri_tested = 1 << pdev->params.dcbx_port_params.app.traffic_type_priority[i];
            pg_entry    = (u8_t)pg_pri_orginal_spread[pdev->params.dcbx_port_params.app.traffic_type_priority[i]];

            if(pg_entry < DCBX_MAX_NUM_PG_BW_ENTRIES)
            {
                entry = 0;

                if((i == (num_of_pri-1))&&
                   (FALSE == b_found_strict) )
                {/* last entry will be handled separately */
                    // If no priority is strict than last enty goes to last queue.
                    entry = 1;
                }
                cos_data->entry_data[entry].pri_join_mask |= pri_tested;
                lm_dcbx_add_to_cos_bw(pdev, &(cos_data->entry_data[entry]), DCBX_PG_BW_GET(ets->pg_bw_tbl, pg_entry));
            }
            else
            {
                DbgBreakIf(TRUE == b_found_strict );
                b_found_strict = TRUE;
                cos_data->entry_data[1].pri_join_mask |= pri_tested;
                // If we join a group and one is strict than the bw rulls
                cos_data->entry_data[1].s_pri = DCBX_S_PRI_COS_HIGHEST;
            }

        }//end of for
    }
}
/**
 * @description
 * Also for e3 and e2.
 * @param pdev
 * @param pg_help_data
 * @param ets
 * @param cos_data
 * @param pg_pri_orginal_spread
 * @param pri_join_mask
 * @param num_of_dif_pri
 *
 * @return STATIC void
 */
STATIC void
lm_dcbx_2cos_limit_cee_fill_cos_params(
    IN          lm_device_t         *pdev,
    IN          pg_help_data_t      *pg_help_data,
    IN          dcbx_ets_feature_t  *ets,
    OUT         cos_help_data_t     *cos_data,
    IN  const   u32_t               *pg_pri_orginal_spread,
    IN          u32_t               pri_join_mask,
    IN          u8_t                num_of_dif_pri)
{
    DbgBreakIf(FALSE == CHIP_IS_E2E3A0(pdev));

    // Default settings
    cos_data->num_of_cos = DCBX_COS_MAX_NUM_E2E3A0;

    switch(pg_help_data->num_of_pg)
    {
    case 1:
        //single priority group
        lm_dcbx_2cos_limit_cee_single_pg_to_cos_params(
            pdev,
            pg_help_data,
            cos_data,
            pri_join_mask,
            num_of_dif_pri);
    break;
    case 2:
        lm_dcbx_2cos_limit_cee_two_pg_to_cos_params(
            pdev,
            pg_help_data,
            ets,
            cos_data,
            pg_pri_orginal_spread,
            pri_join_mask,
            num_of_dif_pri);
    break;

    case 3:
        // Three pg must mean three priorities.
        lm_dcbx_2cos_limit_cee_three_pg_to_cos_params(
            pdev,
            pg_help_data,
            ets,
            cos_data,
            pg_pri_orginal_spread,
            pri_join_mask,
            num_of_dif_pri);

    break;
    default:
        DbgBreakMsg("lm_dcbx_fill_cos_params :Wrong pg_help_data->num_of_pg \n");
        lm_dcbx_ets_disabled_entry_data(pdev,cos_data,pri_join_mask);
    }
}
/**
 * @description
 * Fill cos params in E3B0 A VOQ is PFC enabled if there is one
 * or more priorities mapped to it which is PFC enabled.
 * @param pdev
 * @param entry_data
 * @param pri_join_mask
 * @param bw
 * @param sp
 *
 * @return STATIC void
 */
STATIC void
lm_dcbx_fill_cos(
    IN          lm_device_t             *pdev,
    OUT         cos_entry_help_data_t   *entry_data,
    IN  const   u32_t                   pri_join_mask,
    IN  const   u32_t                   bw,
    IN  const   u8_t                    s_pri)
{

    DbgBreakIf(FALSE == CHIP_IS_E3B0(pdev));

    entry_data->cos_bw  = bw;
    entry_data->s_pri   = s_pri;
    //Set the entry it wasn't set before
    entry_data->pri_join_mask = pri_join_mask;

    // A VOQ is PFC enabled if there is one or more priorities
    // mapped to it which is PFC enabled.
    entry_data->b_pausable =
        LM_DCBX_IS_PFC_PRI_SOME_PAUSE(pdev, entry_data->pri_join_mask);

}

/**
 * @description
 * Spread the strict priority according to
 * num_spread_of_entries.
 *
 * 2.Arbitration between the VOQ-s will be the same as the
 * arbitration requirements between the PG-s except that if
 * multiple VOQ-s are used for priorities in PG15 then there
 * will be strict priority ordering between them according to
 * the order of priorities.
 * @param pdev
 * @param cos_data
 * @param inout_entry
 * @param strict_need_num_of_entries
 * @param strict_app_pris
 *
 * @return STATIC lm_status_t
 */
STATIC lm_status_t
lm_dcbx_spread_strict_pri(
    IN      lm_device_t         *pdev,
    OUT     cos_help_data_t     *cos_data,
    IN      u8_t                entry,
    IN      u8_t                num_spread_of_entries,
    IN      u8_t                strict_app_pris)
{
    u8_t        stict_pri       = DCBX_S_PRI_COS_HIGHEST;
    u8_t        num_of_app_pri  = MAX_PFC_PRIORITIES;
    u8_t        app_pri_bit     = 0;
    lm_status_t lm_status       = LM_STATUS_SUCCESS;

    DbgBreakIf(FALSE == CHIP_IS_E3B0(pdev));

    while((num_spread_of_entries)&&
          (0 < num_of_app_pri))
    {
        app_pri_bit = 1 << (num_of_app_pri -1 );
        if(app_pri_bit & strict_app_pris)
        {
            num_spread_of_entries--;
            if(0 == num_spread_of_entries)
            {
                // last entry needed put all the entries left
                lm_dcbx_fill_cos(pdev,
                                 &(cos_data->entry_data[entry]),
                                 strict_app_pris,
                                 DCBX_INVALID_COS_BW,
                                 stict_pri);
            }
            else
            {
                strict_app_pris &= ~app_pri_bit;
                lm_dcbx_fill_cos(pdev,
                                 &(cos_data->entry_data[entry]),
                                 app_pri_bit,
                                 DCBX_INVALID_COS_BW,
                                 stict_pri);
            }

            stict_pri = DCBX_S_PRI_COS_NEXT_LOWER_PRI(stict_pri);
            entry++;
        }
        num_of_app_pri--;
    }

    if(0 != num_spread_of_entries)
    {
        DbgBreakMsg("lm_dcbx_spread_strict_pri- This is a bug ");
        lm_status = LM_STATUS_FAILURE;
    }

    return lm_status;
}
/**
 * @description
 * Try to split the strict priority to num_spread_of_entries.
 * If not possible all of the priorities will be in one entry.
 * @param pdev
 * @param cos_data
 * @param entry
 * @param num_spread_of_entries
 * @param strict_app_pris
 *
 * @return STATIC u8_t
 * Num of entries cos_data used.
 */
STATIC u8_t
lm_dcbx_cee_fill_strict_pri(
    IN      lm_device_t         *pdev,
    OUT     cos_help_data_t     *cos_data,
    INOUT   u8_t                entry,
    IN      u8_t                num_spread_of_entries,
    IN      u8_t                strict_app_pris)
{

    lm_status_t lm_status = LM_STATUS_SUCCESS;

    DbgBreakIf(FALSE == CHIP_IS_E3B0(pdev));

    lm_status = lm_dcbx_spread_strict_pri(pdev,
                                          cos_data,
                                          entry,
                                          num_spread_of_entries,
                                          strict_app_pris);
    if(LM_STATUS_SUCCESS != lm_status)
    {
        lm_dcbx_fill_cos(pdev,
                         &(cos_data->entry_data[entry]),
                         strict_app_pris,
                         DCBX_INVALID_COS_BW,
                         DCBX_S_PRI_COS_HIGHEST);
        return 1;

    }

    return num_spread_of_entries;
}
/**
 * @description
 * In E3 the allocation is based only on the PG configuration.
 * PFC will not have an effect on the mapping. The mapping is
 * done according to the following priorities:
 * 1. Allocate a single VOQ to PG15 if there is at least one
 * priority mapped to PG15.
 * 2. Allocate the rest of the VOQ-s to the other PG-s.
 * 3. If there are still VOQ-s which have no associated PG, then
 * associate these VOQ-s to PG15. These PG-s will be used for SP
 * between priorities on PG15.
 *
 * @param pdev
 * @param pg_help_data
 * @param ets
 * @param cos_data
 * @param pg_pri_orginal_spread
 * @param pri_join_mask
 * @param num_of_dif_pri
 *
 * @return STATIC void
 */
STATIC void
lm_dcbx_cee_fill_cos_params(
    IN          lm_device_t         *pdev,
    IN          pg_help_data_t      *pg_help_data,
    IN          dcbx_ets_feature_t  *ets,
    OUT         cos_help_data_t     *cos_data,
    IN  const   u32_t               pri_join_mask)
{
    lm_status_t lm_status           = LM_STATUS_SUCCESS;
    u8_t        need_num_of_entries = 0;
    u8_t        i                   = 0;
    u8_t        entry               = 0;

    DbgBreakIf(FALSE == CHIP_IS_E3B0(pdev));

    // if the number of requested PG-s in CEE is greater than 3
    // then the results are not determined since this is a violation
    // of the standard.
    if(DCBX_COS_MAX_NUM_E3B0 < pg_help_data->num_of_pg)
    {
        DbgBreakMsg("lm_dcbx_cee_e3b0_fill_cos_params :Wrong pg_help_data->num_of_pg \n");
        lm_status = lm_dcbx_join_pgs(pdev,
                                     ets,
                                     pg_help_data,
                                     DCBX_COS_MAX_NUM_E3B0);

        if(LM_STATUS_SUCCESS != lm_status)
        {
            // If we weren't successful in reducing the number of PGs we will disables ETS.
            lm_dcbx_ets_disabled_entry_data(pdev,cos_data,pri_join_mask);
            return;
        }
    }

    for(i = 0 ; i < pg_help_data->num_of_pg; i++)
    {

        if(pg_help_data->pg_entry_data[i].pg < DCBX_MAX_NUM_PG_BW_ENTRIES)
        {
            // Fill BW entry.
            lm_dcbx_fill_cos(pdev,
                             &(cos_data->entry_data[entry]),
                             pg_help_data->pg_entry_data[i].pg_priority,
                             DCBX_PG_BW_GET(ets->pg_bw_tbl, pg_help_data->pg_entry_data[i].pg),
                             DCBX_S_PRI_INVALID);
            entry++;
        }
        else
        {
            DbgBreakIf(DCBX_STRICT_PRI_PG != pg_help_data->pg_entry_data[i].pg );

            need_num_of_entries = min((u8_t)pg_help_data->pg_entry_data[i].num_of_dif_pri,
                                      (u8_t)(((u8_t)DCBX_COS_MAX_NUM_E3B0 - pg_help_data->num_of_pg) + 1/*current entry*/));

            // 3. If there are still VOQ-s which have no associated PG, then
            // associate these VOQ-s to PG15. These PG-s will be used for SP
            // between priorities on PG15.
            entry += lm_dcbx_cee_fill_strict_pri(pdev,
                                                 cos_data,
                                                 entry,
                                                 need_num_of_entries,
                                                 (u8_t)pg_help_data->pg_entry_data[i].pg_priority);

        }

    }//end of for

    // the entry will represent the number of COS used
    cos_data->num_of_cos = entry;

    DbgBreakIf(DCBX_COS_MAX_NUM_E3B0 < cos_data->num_of_cos );
}
/**
 * @description
 * Get the COS parameters according to ETS and PFC receive
 * configuration
 * @param pdev
 * @param pg_help_data
 * @param ets
 * @param pg_pri_orginal_spread
 *
 * @return STATIC void
 */
STATIC void
lm_dcbx_fill_cos_params(
    IN  lm_device_t                 *pdev,
    IN  pg_help_data_t              *pg_help_data,
    IN          dcbx_ets_feature_t  *ets,
    IN  const u32_t                 *pg_pri_orginal_spread)
{
    cos_help_data_t         cos_data                    = {{{0}}};
    u8_t                    i                           = 0;
    u8_t                    j                           = 0;
    u32_t                   pri_join_mask               = 0;
    u8_t                    num_of_dif_pri              = 0;

    // Validate the pg value
    for(i=0; i < pg_help_data->num_of_pg ; i++)
    {
        DbgBreakIf((DCBX_STRICT_PRI_PG != pg_help_data->pg_entry_data[i].pg) &&
                   (DCBX_MAX_NUM_PG_BW_ENTRIES <= pg_help_data->pg_entry_data[i].pg));
        pri_join_mask   |=  pg_help_data->pg_entry_data[i].pg_priority;
        num_of_dif_pri  += pg_help_data->pg_entry_data[i].num_of_dif_pri;
    }

    //default settings
    cos_data.num_of_cos = 1;
    for(i=0; i < ARRSIZE(cos_data.entry_data) ; i++)
    {
        cos_data.entry_data[i].pri_join_mask    = 0;
        cos_data.entry_data[i].b_pausable       = FALSE;
        cos_data.entry_data[i].s_pri               = DCBX_S_PRI_INVALID;
        cos_data.entry_data[i].cos_bw           = DCBX_INVALID_COS_BW;
    }

    DbgBreakIf((0 == num_of_dif_pri) && (3 < num_of_dif_pri));
    if(CHIP_IS_E3B0(pdev))
    {
        lm_dcbx_cee_fill_cos_params(
            pdev,
            pg_help_data,
            ets,
            &cos_data,
            pri_join_mask);
    }
    else
    {
        DbgBreakIf(FALSE == CHIP_IS_E2E3A0(pdev));
        lm_dcbx_2cos_limit_cee_fill_cos_params(
            pdev,
            pg_help_data,
            ets,
            &cos_data,
            pg_pri_orginal_spread,
            pri_join_mask,
            num_of_dif_pri);
    }

    for(i=0; i < cos_data.num_of_cos ; i++)
    {
        lm_dcbx_fill_cos_entry(pdev,
                               &pdev->params.dcbx_port_params.ets.cos_params[i],
                               cos_data.entry_data[i].pri_join_mask,
                               cos_data.entry_data[i].cos_bw,
                               cos_data.entry_data[i].b_pausable,
                               cos_data.entry_data[i].s_pri);
    }

    DbgBreakIf(0 == cos_data.num_of_cos);

    DbgBreakIf(pri_join_mask != (pdev->params.dcbx_port_params.ets.cos_params[0].pri_bitmask |
                                 pdev->params.dcbx_port_params.ets.cos_params[1].pri_bitmask |
                                 pdev->params.dcbx_port_params.ets.cos_params[2].pri_bitmask));

    // debugging make sure the same priority isn't mapped to to COS
    for(i = 0 ; i < cos_data.num_of_cos; i++)
    {
        for(j = i+1 ; j < cos_data.num_of_cos; j++)
        {
            DbgBreakIf(0 != (pdev->params.dcbx_port_params.ets.cos_params[i].pri_bitmask &
                                         pdev->params.dcbx_port_params.ets.cos_params[j].pri_bitmask));
        }
    }

    pdev->params.dcbx_port_params.ets.num_of_cos = cos_data.num_of_cos ;
}
/**
 * CQ60417 : If remote feature is not found, we disable the
 * feature unless user explicitly configured feature (copycat
 * switch behavior)
 * @param pdev
 * @param error - error flag sent from DCBX.
 * @param remote_tlv_feature_flag - Must be one of the
 *                                DCBX_REMOTE_XXX_TLV_NOT_FOUND
 *
 * @return STATIC u8_t -
 */
STATIC u8_t
lm_dcbx_is_feature_dis_remote_tlv(
    INOUT lm_device_t   *pdev,
    IN const u32_t      error,
    IN const u32_t      remote_tlv_feature_flag
    )
{
    u8_t const mfw_config       = lm_dcbx_check_drv_flags(pdev, DRV_FLAGS_DCB_MFW_CONFIGURED);
    u8_t const ret_feature_dis  = (remote_tlv_feature_flag == GET_FLAGS(error ,remote_tlv_feature_flag)) &&
                                    (FALSE == mfw_config);

    DbgBreakIf(0 == GET_FLAGS(remote_tlv_feature_flag ,
                              (DCBX_REMOTE_ETS_TLV_NOT_FOUND |
                               DCBX_REMOTE_PFC_TLV_NOT_FOUND |
                               DCBX_REMOTE_APP_TLV_NOT_FOUND)));

    return ret_feature_dis;
}

/*******************************************************************************
 * Description: Translate from ETS parameter to COS paramters
 *
 * Return:
 ******************************************************************************/
STATIC void
lm_dcbx_get_ets_cee_feature(
    INOUT       lm_device_t         *pdev,
    INOUT       dcbx_ets_feature_t  *ets,
    IN const    u32_t               error)
{
    u32_t           pg_pri_orginal_spread[DCBX_MAX_NUM_PRI_PG_ENTRIES]  = {0};
    pg_help_data_t  pg_help_data                                        = {{{0}}};
    const u8_t      is_ets_dis_remote_tlv                               = lm_dcbx_is_feature_dis_remote_tlv(
                                                                                pdev,
                                                                                error,
                                                                                DCBX_REMOTE_ETS_TLV_NOT_FOUND);
    // Clean up old settings of ets on COS
    lm_dcbx_init_ets_internal_param(pdev,
                                    &(pdev->params.dcbx_port_params.ets));

    if(DCBX_MIB_IS_ETS_ENABLED(pdev->params.dcbx_port_params.app.enabled,
       error,ets->enabled) &&
       (!is_ets_dis_remote_tlv))
    {
        DbgBreakIf(FALSE == pdev->params.dcbx_port_params.dcbx_enabled);
        pdev->params.dcbx_port_params.ets.enabled = TRUE;
    }
    else
    {

        lm_dcbx_ets_disable(pdev);
        return;
    }

    //Parse pg_pri_orginal_spread data and spread it from nibble to 32 bits
    lm_dcbx_get_ets_pri_pg_tbl(pdev,
                               pg_pri_orginal_spread,
                               ets->pri_pg_tbl,
                               ARRSIZE(pg_pri_orginal_spread),
                               DCBX_MAX_NUM_PRI_PG_ENTRIES);

    lm_dcbx_cee_get_num_of_pg_traf_type(pdev,
                                    pg_pri_orginal_spread,
                                    &pg_help_data);

    lm_dcbx_fill_cos_params(pdev,
                            &pg_help_data,
                            ets,
                            pg_pri_orginal_spread);

}

/**
 * @description
 * Mapping between TC( acording to the given parameters from
 * upper layer) which isn't zero based to COS which is zero
 * based.
 * COS configuration is used to the chip configuration.
 * @param pdev
 *
 * @return STATIC void
 */
STATIC void
lm_dcbx_ie_get_ets_ieee_feature(
    INOUT       lm_device_t         *pdev)
{
    lm_dcbx_indicate_event_t    *indicate_event     = &pdev->dcbx_info.indicate_event;
    pg_params_t                 *ets_drv_param      = &pdev->params.dcbx_port_params.ets;
    dcb_ets_tsa_param_t         *ieee_ets           = &indicate_event->ets_ieee_params_config;
    // COS should be continues and zero based
    u8_t                        cee_tc_to_continues_cos[DCBX_MAX_NUM_PRI_PG_ENTRIES] = {0};
    u8_t                        i                   = 0;
    s16_t                       pri                 = 0;
    u8_t                        strict_pri          = DCBX_S_PRI_COS_HIGHEST;
    u8_t                        tc_entry            = 0;
    u8_t                        cos_entry           = 0;
    const u8_t                  max_tc_sup          = lm_dcbx_cos_max_num(pdev) ;
    u8_t                        next_free_cos_entry = 0;
    u8_t                        tc_used_bitmap      = 0;
#if (DBG)
    u8_t                        j                   = 0;
    u8_t                        pri_used_bitmap     = 0;
#endif //DBG
    /************************************ Validate Check ***************************/
    ASSERT_STATIC(DCBX_MAX_NUM_PRI_PG_ENTRIES == DCBX_MAX_NUM_PG_BW_ENTRIES);
    ASSERT_STATIC(DCBX_MAX_NUM_PRI_PG_ENTRIES == ARRSIZE(ieee_ets->priority_assignment_table));
    ASSERT_STATIC(DCBX_MAX_NUM_PG_BW_ENTRIES == ARRSIZE(ieee_ets->tc_bw_assignment_table));
    ASSERT_STATIC(DCBX_MAX_NUM_PG_BW_ENTRIES == ARRSIZE(ieee_ets->tsa_assignment_table));

    DbgBreakIf(lm_dcbx_ets_ieee_config_not_valid == indicate_event->ets_ieee_config_state);
    /********************************** Init variables  ***************************/
    // Clean up old settings of ets on COS
    lm_dcbx_init_ets_internal_param(pdev, ets_drv_param);

    // If application priority isn't enabled then all DCB features must be disabled.
    if((FALSE == pdev->params.dcbx_port_params.app.enabled)||
        (LM_DCBX_IE_IS_ETS_DISABLE(ieee_ets->num_traffic_classes))||
        (lm_dcbx_ets_ieee_config_en != indicate_event->ets_ieee_config_state))
    {
        lm_dcbx_ets_disable(pdev);
        return;
    }

    /*** Mapping between TC which isn't zero based to COS which is zero based*****/

    // Count the number of TC entries given and fill the appropriate COS entry.
    // The for is from the higher priority down, because higher priorities should
    // receive higher strict priority.
    for (pri = (ARRSIZE(ieee_ets->priority_assignment_table) -1);
          0 <= pri;
          pri--)
    {
        tc_entry = ieee_ets->priority_assignment_table[pri];

        if(0 == (tc_used_bitmap & (1 << tc_entry)))
        {
            // We should not reenter, this will cause a bug in strict priority.
            // Validate COS entry is legal
            if(max_tc_sup <= next_free_cos_entry )
            {
                DbgBreakMsg(" Wrong ETS settings ");
                lm_dcbx_ets_disable(pdev);
                return;
            }

            tc_used_bitmap |= (1 << tc_entry);
            cee_tc_to_continues_cos[tc_entry] = next_free_cos_entry;

            if(TSA_ASSIGNMENT_DCB_TSA_STRICT == ieee_ets->tsa_assignment_table[tc_entry])
            {
                ets_drv_param->cos_params[next_free_cos_entry].bw_tbl = DCBX_INVALID_COS_BW;
                ets_drv_param->cos_params[next_free_cos_entry].s_pri = strict_pri;
                // Prepare for next strict priority
                strict_pri = DCBX_S_PRI_COS_NEXT_LOWER_PRI(strict_pri);
            }
            else if(TSA_ASSIGNMENT_DCB_TSA_ETS == ieee_ets->tsa_assignment_table[tc_entry])
            {
                ets_drv_param->cos_params[next_free_cos_entry].bw_tbl = ieee_ets->tc_bw_assignment_table[tc_entry];
                ets_drv_param->cos_params[next_free_cos_entry].s_pri = DCBX_S_PRI_INVALID;
            }
            else
            {
                DbgBreakMsg("lm_dcbx_get_ets_ieee_feature parameters are check before "
                            "this should not happen");

                lm_dcbx_ets_disable(pdev);
                return;
            }

            // Prepare for next entry and also represents after this while the number
            // of used COS entries.
            next_free_cos_entry++;
        }
    }

    // Fill priority to COS mapping
    for (pri = 0; pri < ARRSIZE(ieee_ets->priority_assignment_table); pri++)
    {
        tc_entry = ieee_ets->priority_assignment_table[pri];
        cos_entry = cee_tc_to_continues_cos[tc_entry];

        DbgBreakIf(ARRSIZE(ets_drv_param->cos_params) <= cos_entry);

        ets_drv_param->cos_params[cos_entry].pri_bitmask |= 1<< pri;

        ets_drv_param->cos_params[cos_entry].pauseable = LM_DCBX_IS_PFC_PRI_SOME_PAUSE(pdev,ets_drv_param->cos_params[cos_entry].pri_bitmask);
    }

    DbgBreakIf( ieee_ets->num_traffic_classes < next_free_cos_entry);

    ets_drv_param->num_of_cos = (u8_t)next_free_cos_entry;
    ets_drv_param->enabled = TRUE;

#if (DBG)
    pri_used_bitmap = 0;
    for(i = 0 ; i < ets_drv_param->num_of_cos; i++)
    {
        // All priorities must be present
        pri_used_bitmap |= ets_drv_param->cos_params[i].pri_bitmask;
        for(j = i+1 ; j < ets_drv_param->num_of_cos; j++)
        {
            // Make sure there are no intersection
            DbgBreakIf(0 != (ets_drv_param->cos_params[i].pri_bitmask &
                             ets_drv_param->cos_params[j].pri_bitmask));
        }
}
    DbgBreakIf(((1 << MAX_PFC_PRIORITIES) -1) != pri_used_bitmap);
#endif //DBG
}
/**
 * @description
 * Fill priority to COS mapping.
 * @param pdev
 */
void
lm_dcbx_fill_pri_to_cos_mapping(lm_device_t  *pdev)
{
    pg_params_t *ets_drv_param = &pdev->params.dcbx_port_params.ets;
    u8_t pri = 0;
    u8_t cos = 0;
    u8_t pri_bit = 0;

    ASSERT_STATIC( MAX_PFC_PRIORITIES == ARRSIZE(pdev->dcbx_info.pri_to_cos));

    // Map all priorities to COS 0 by default
    mm_mem_zero(pdev->dcbx_info.pri_to_cos, sizeof(pdev->dcbx_info.pri_to_cos));

    if(FALSE == ets_drv_param->enabled)
    {
        return;
    }

    // Fill the priority to COS
    for (cos = 0; cos < ets_drv_param->num_of_cos; cos++)
    {
        for( pri = 0; pri < ARRSIZE(pdev->dcbx_info.pri_to_cos) ; pri++)
        {
            pri_bit = 1 << pri;

            if (ets_drv_param->cos_params[cos].pri_bitmask & pri_bit)
            {
                pdev->dcbx_info.pri_to_cos[pri] = cos;
            }
        }
    }
}

static void lm_dcbx_map_nw(INOUT lm_device_t  *pdev)
{
   u8_t i;
   u32_t unmapped = (1 << MAX_PFC_PRIORITIES) - 1; // all ones
   u32_t *ttp = pdev->params.dcbx_port_params.app.traffic_type_priority;
   u32_t nw_prio = 1 << ttp[LLFC_TRAFFIC_TYPE_NW];
   dcbx_cos_params_t *cos_params =
                   pdev->params.dcbx_port_params.ets.cos_params;

   // get unmapped priorities by clearing mapped bits
   for (i = 0; i < LLFC_DRIVER_TRAFFIC_TYPE_MAX; i++)
           unmapped &= ~(1 << ttp[i]);

   // find cos for nw prio and extend it with unmapped
   for (i = 0; i < ARRSIZE(pdev->params.dcbx_port_params.ets.cos_params); i++) {
           if (cos_params[i].pri_bitmask & nw_prio) {
                   // extend the bitmask with unmapped
                   DbgMessage(pdev, INFORM,
                      "cos %d extended with 0x%08x", i, unmapped);

                   cos_params[i].pri_bitmask |= unmapped;
                   break;
           }
   }
}
/**
 * Pass on all priority_assignment_table cells and merge them to
 * the first cell of the BW until the amount of cells will be
 * less than max_tc_sup
 *
 * @param pdev
 * @param ieee_ets
 */
void
lm_dcbx_ie_merge_bw_cells(
    INOUT   lm_device_t         *pdev,
    INOUT   dcb_ets_tsa_param_t *ieee_ets
    )
{
    const u8_t  max_tc_sup      = lm_dcbx_cos_max_num(pdev);
    const u8_t  invalid_tc      = ARRSIZE(ieee_ets->priority_assignment_table);
    u8_t        tc_entry        = 0;
    u8_t        tc_entry_bit    = 0;
    u8_t        merge_tc        = invalid_tc;
    u8_t        pri             = 0;
    u8_t        pri_remap       = 0;
    u8_t        tc_used_bitmap  = 0;

    if(ieee_ets->num_traffic_classes <= max_tc_sup)
    {
        // nothing to do.
        return;
    }

    for (pri = 0;
          pri < ARRSIZE(ieee_ets->priority_assignment_table);
          pri++)
    {
        tc_entry = ieee_ets->priority_assignment_table[pri];
        tc_entry_bit = (1 << tc_entry);

        if((0 == (tc_used_bitmap & tc_entry_bit)) &&
           (TSA_ASSIGNMENT_DCB_TSA_ETS == ieee_ets->tsa_assignment_table[tc_entry]))
        {
            if(invalid_tc != merge_tc)
            {
                // We found already a cell to merge to
                DbgBreakIf(tc_entry == merge_tc);

                // point the pri to merge_tc.
                ieee_ets->priority_assignment_table[pri] = merge_tc;

                // merge the cells
                ieee_ets->tc_bw_assignment_table[merge_tc] += ieee_ets->tc_bw_assignment_table[tc_entry];
                ieee_ets->tc_bw_assignment_table[tc_entry] = 0;
                ieee_ets->tsa_assignment_table[tc_entry] = TSA_ASSIGNMENT_DCB_TSA_STRICT;// Don't care

                // remapping all tc_entry => merge_tc
                for (pri_remap = 0;
                      pri_remap < ARRSIZE(ieee_ets->priority_assignment_table);
                      pri_remap++)
                {
                    if(tc_entry == ieee_ets->priority_assignment_table[pri_remap])
                    {
                        ieee_ets->priority_assignment_table[pri_remap] = merge_tc;
                    }
                }

                ieee_ets->num_traffic_classes--;
            }
            else
            {
                // Find first BW cell
                merge_tc = tc_entry;
            }
        }

        tc_used_bitmap |= tc_entry_bit;

        if(ieee_ets->num_traffic_classes <= max_tc_sup )
        {
            break;
        }

    }

    DbgBreakIf(max_tc_sup < ieee_ets->num_traffic_classes);

}
/**
 *  if (admin.ETS == local.ETS)
 *              Use OS configuration.
 *  Else
 *              Parse the data from CEE to IEEE .
 * @param pdev
 * @param cee_ets
 *
 * @return u8_t
 */
u8_t
lm_dcbx_ie_is_ets_admin_eq_local(
    INOUT   lm_device_t         *pdev,
    IN      dcbx_ets_feature_t  *cee_ets
    )
{
    lldp_admin_mib_t    admin_mib           = {0};
    u32_t               admin_mib_offset    = 0;
    lm_status_t         lm_status           = LM_STATUS_SUCCESS;

    lm_status = lm_dcbx_read_admin_mib( pdev,
                                        &admin_mib,
                                        &admin_mib_offset);

    if(LM_STATUS_SUCCESS != lm_status)
    {
        DbgBreakMsg(" lm_dcbx_ie_admin_mib_updated_runtime lm_dcbx_read_admin_mib failed ");
        return FALSE;
    }

    return mm_memcmp(cee_ets,
                     &admin_mib.features.ets,
                     sizeof(admin_mib.features.ets));

}
/**
   In CEE all strict TC-s are map to PGID=15. This is how it
   will appear in the TLV on the wire and in local settings.
    As a result there is a problem in showing the correct
    strict TC settings of the local and remote peer side (remote
    configuration): a.     If more than one TC (e.g. TC_0 and TC_1)
    will be assigned to TSA strict, on the local or remote peer
    side they will be merged to one TC. b. The strict TC number
    will not be correct on the local and remote peer side.

    Assumption:In ETS there is no merging done by MCP we either
    take our configuration or the other side

    Suggested solution: Driver will save ETS       OS
    configuration.

    In case of an interrupt driver will :
    if (admin.ETS == local.ETS)
                Use OS configuration.
    Else
                Parse the data from CEE to IEEE .
 * @param pdev
 * @param cee_ets
 */
void
lm_dcbx_ie_get_ieee_config_param(
    INOUT   lm_device_t         *pdev,
    IN      dcbx_ets_feature_t  *cee_ets,
    IN const u32_t              error
    )
{
    lm_dcbx_indicate_event_t    *indicate_event = &pdev->dcbx_info.indicate_event;
    u32_t                       flags           = 0;

    if(FALSE == DCBX_MIB_IS_ETS_ENABLED(pdev->params.dcbx_port_params.app.enabled,
       error,cee_ets->enabled))
    {
        indicate_event->ets_ieee_config_state = lm_dcbx_ets_ieee_config_di;
        mm_mem_zero(&indicate_event->ets_ieee_params_config,
                   sizeof(indicate_event->ets_ieee_params_os));
        return;
    }

    if(lm_dcbx_ie_is_ets_admin_eq_local(pdev,cee_ets) &&
       indicate_event->is_ets_ieee_params_os_valid)
    {
        indicate_event->ets_ieee_config_state = lm_dcbx_ets_ieee_config_en;

        mm_memcpy(&indicate_event->ets_ieee_params_config,
                  &indicate_event->ets_ieee_params_os,
                  sizeof(indicate_event->ets_ieee_params_os));
    }
    else
    {
        lm_dcbx_ie_ets_cee_to_ieee_unparse(pdev,
                                           cee_ets,
                                           &indicate_event->ets_ieee_params_config,
                                           &flags);

        if(GET_FLAGS(flags,DCB_PARAMS_ETS_ENABLED))
        {
            indicate_event->ets_ieee_config_state = lm_dcbx_ets_ieee_config_en;
        }
        else
        {
            indicate_event->ets_ieee_config_state = lm_dcbx_ets_ieee_config_di;
        }

        lm_dcbx_ie_merge_bw_cells(pdev,
                                  &indicate_event->ets_ieee_params_config);
    }
}

/**
 * @description
 *
 * @param pdev
 * @param pfc
 * @param error
 *
 * @return STATIC void
 */
STATIC void
lm_dcbx_get_ets_feature(
    INOUT lm_device_t       *pdev,
    IN dcbx_ets_feature_t   *ets,
    IN const u32_t          error
    )
{
    lm_dcbx_indicate_event_t    *indicate_event     = &pdev->dcbx_info.indicate_event;

    if(lm_dcbx_ets_config_state_cee == indicate_event->ets_config_state)
    {
        indicate_event->ets_ieee_config_state = lm_dcbx_ets_ieee_config_not_valid;

        lm_dcbx_get_ets_cee_feature(
            pdev,
            ets,
            error);

        lm_dcbx_map_nw(pdev);

        DbgBreakIf(lm_dcbx_ets_ieee_config_not_valid != indicate_event->ets_ieee_config_state);
    }
    else
    {
        lm_dcbx_ie_get_ieee_config_param(pdev,
                                         ets,
                                         error);

        //If ets is given from upper layer we don't use chip ETS configuration
        lm_dcbx_ie_get_ets_ieee_feature( pdev);

        DbgBreakIf(lm_dcbx_ets_ieee_config_not_valid == indicate_event->ets_ieee_config_state);
    }

    lm_dcbx_fill_pri_to_cos_mapping( pdev);
}
/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
STATIC void
lm_dcbx_get_pfc_feature(
    INOUT lm_device_t              *pdev,
    IN const dcbx_pfc_feature_t    *pfc,
    IN const u32_t                 error
    )
{
    const u8_t  is_pfc_dis_remote_tlv = lm_dcbx_is_feature_dis_remote_tlv(
                                            pdev,
                                            error,
                                            DCBX_REMOTE_PFC_TLV_NOT_FOUND);

    if(DCBX_MIB_IS_PFC_ENABLED(pdev->params.dcbx_port_params.app.enabled,
                               error, pfc->enabled) && (!is_pfc_dis_remote_tlv))
    {
        DbgBreakIf(FALSE == pdev->params.dcbx_port_params.dcbx_enabled);
        pdev->params.dcbx_port_params.pfc.enabled = TRUE;
        pdev->params.dcbx_port_params.pfc.priority_non_pauseable_mask = (u8_t)(~(pfc->pri_en_bitmap));
    }
    else
    {
        pdev->params.dcbx_port_params.pfc.enabled = FALSE;
        pdev->params.dcbx_port_params.pfc.priority_non_pauseable_mask = 0;
    }

}

/*******************************************************************************
 * Description: Take the highest priority available.(This function don't do the
 *              initialization of priority.)
 *
 * Return:
******************************************************************************/
STATIC void
lm_dcbx_get_ap_priority(
    IN          lm_device_t     *pdev,
    INOUT       u32_t           *entry_pri,
    IN const    u8_t            pri_bitmap,
    INOUT       u8_t            *is_default_off_tt_set
    )
{
    u8_t pri      = MAX_PFC_PRIORITIES;
    u8_t index    = 0 ;
    u8_t pri_mask = 0;

    //Chose the highest priority the lower pri will get run over
    for(index = 0; index < MAX_PFC_PRIORITIES ; index++)
    {
        pri_mask = 1 <<(index);
        if(GET_FLAGS(pri_bitmap , pri_mask))
        {
            pri = index ;
        }
    }

    if(pri < MAX_PFC_PRIORITIES)
    {
        if((*entry_pri < MAX_PFC_PRIORITIES) &&
           (FALSE == *is_default_off_tt_set))
        {
            *entry_pri = max(*entry_pri, pri);
        }
        else
        {
            *entry_pri =  pri;
            *is_default_off_tt_set = FALSE;
        }

    }
}
/**
 * Check if the entry is an ISCSI classification entry.
 * @param app_id
 * @param appBitfield
 *
 * @return STATIC u8_t
 */
STATIC u8_t
lm_dcbx_cee_is_entry_iscsi_classif(IN const u8_t    appBitfield,
                                   IN const u16_t   app_id)
{
    if(GET_FLAGS(appBitfield,DCBX_APP_SF_PORT) &&
       (TCP_PORT_ISCSI == app_id))
    {
        return TRUE;
    }

    return FALSE;
}
/**
 * Check if the entry is an FCOE classification entry.
 * @param app_id
 * @param appBitfield
 *
 * @return STATIC u8_t
 */
STATIC u8_t
lm_dcbx_cee_is_entry_fcoe_classif(IN const  u8_t    appBitfield,
                                  IN const  u16_t   app_id)
{
    if(GET_FLAGS(appBitfield,DCBX_APP_SF_ETH_TYPE) &&
       (ETH_TYPE_FCOE == app_id))
    {
        return TRUE;
    }

    return FALSE;
}

/**
 * Look for offload app priorities for offload traffic
 * types:ISCSI and FCOE.
 * @param pdev
 * @param app_tbl
 * @param app_tbl_size
 *
 * @return STATIC void
 */
STATIC void
lm_dcbx_get_app_pri_off_tt(
    lm_device_t                         *pdev,
    IN const dcbx_app_priority_entry_t  *app_tbl,
    IN const u8_t                       app_tbl_size,
    INOUT   u8_t                        *is_default_off_tt_used
    )
{
    u8_t        index   = 0;

    for(index = 0 ;(index < app_tbl_size); index++)
    {
        if(DCBX_APP_ENTRY_VALID != GET_FLAGS(app_tbl[index].appBitfield,DCBX_APP_ENTRY_VALID))
        {
            continue;
        }

        if(lm_dcbx_cee_is_entry_fcoe_classif(app_tbl[index].appBitfield, app_tbl[index].app_id))
        {
            lm_dcbx_get_ap_priority(pdev,
                                    &(pdev->params.dcbx_port_params.app.traffic_type_priority[LLFC_TRAFFIC_TYPE_FCOE]),
                                    app_tbl[index].pri_bitmap,
                                    &is_default_off_tt_used[LLFC_TRAFFIC_TYPE_FCOE]);
        }

        if(lm_dcbx_cee_is_entry_iscsi_classif(app_tbl[index].appBitfield, app_tbl[index].app_id))
        {
            lm_dcbx_get_ap_priority(pdev,
                                    &(pdev->params.dcbx_port_params.app.traffic_type_priority[LLFC_TRAFFIC_TYPE_ISCSI]),
                                    app_tbl[index].pri_bitmap,
                                    &is_default_off_tt_used[LLFC_TRAFFIC_TYPE_ISCSI]);
        }
    }
}
/**
 * Update non negotiation application IDs entries.
 * @param pdev
 *
 * @return STATIC void
 */
STATIC void
lm_dcbx_get_app_pri_off_tt_non_neg(
    INOUT   lm_device_t *pdev,
    INOUT   u8_t        *is_default_off_tt_set)
{
    lm_dcbx_indicate_event_t *indicate_event    = &pdev->dcbx_info.indicate_event;
    // If indicate event is enabled and there is a OS configuration contained an entry
    // with ‘TCP port’ = 3260 use that entry.
    if((TRUE == pdev->dcbx_info.is_indicate_event_en) &&
        (LM_DCBX_ILLEGAL_PRI != indicate_event->iscsi_tcp_pri))
    {
        pdev->params.dcbx_port_params.app.traffic_type_priority[LLFC_TRAFFIC_TYPE_ISCSI] =
            indicate_event->iscsi_tcp_pri;

        is_default_off_tt_set[LLFC_TRAFFIC_TYPE_ISCSI] = FALSE;
    }
}
/*******************************************************************************
 *  Description:
 *  Traffic type (protocol) identification:
 * Networking is identified by Ether-Type = IPv4 or Ether-Type =IPv6.
 * iSCSI is  by TCP-port = iSCSI well know port (3260)
 * FCoE is identified by Ether-type = FCoE
 * Theoretically each protocol can be associated with multiple priorities (a priority bit map). In this case we choose the highest one.
 * Priority assignment for networking:
 * 1.      If IPv4 is identified, the networking priority is the IPv4 priority (highest one as mentioned above).
 * 2.      Otherwise if IPv6 is identified, the networking priority is the IPv6 priority.
 * 3.      Otherwise the networking priority is set 0. (All other protocol TLVs which are not iSCSI or FCoE are ignored).
 *
 * Priority assignment for iSCSI:
 * 1. If the operational configuration from MCP contains an entry with 'TCP or UDP port' = 3260 use that entry,
 * 2. Else if OS configuration contained an entry with 'TCP port' = 3260 use that entry,
 * 3. Else use the default configuration.
 *
 * Priority assignment for FCoE:
 * 1.      If FCoE is identified, then obviously this is the FCoE priority (again the highest one).
 * 2.      Otherwise FCoE priority is set to default configuration.
 * Return:
 ******************************************************************************/
STATIC void
lm_dcbx_get_ap_feature(
    INOUT lm_device_t                       *pdev,
    IN const dcbx_app_priority_feature_t    *app,
    IN const dcbx_app_priority_entry_t      *app_tbl_ext,
    IN const u8_t                           app_tbl_ext_size,
    IN const u32_t                          error)
{
    u8_t    index = 0;
    u8_t const  default_pri                                 = (app->default_pri < MAX_PFC_PRIORITIES)? app->default_pri: 0;
    u8_t        is_default_off_tt_used[MAX_TRAFFIC_TYPE]    = {0};
    const u8_t  is_app_dis_remote_tlv                       = lm_dcbx_is_feature_dis_remote_tlv(
                                                                    pdev,
                                                                    error,
                                                                    DCBX_REMOTE_APP_TLV_NOT_FOUND);

    if((TRUE == pdev->params.dcbx_port_params.dcbx_enabled) &&
        DCBX_MIB_IS_APP_ENABLED(app->enabled, error) && (!is_app_dis_remote_tlv))
    {
        pdev->params.dcbx_port_params.app.enabled = TRUE;

        // First initialize all the entries to default priority
        for( index=0 ; index < ARRSIZE(pdev->params.dcbx_port_params.app.traffic_type_priority) ;index++)
        {
            is_default_off_tt_used[index] = TRUE;
            pdev->params.dcbx_port_params.app.traffic_type_priority[index] = default_pri;
        }
        // The value of this entries is used only if there isn't a corresponding negotiated entry.
        lm_dcbx_get_app_pri_off_tt_non_neg(pdev, is_default_off_tt_used);

        lm_dcbx_get_app_pri_off_tt(pdev,
                                   app->app_pri_tbl,
                                   ARRSIZE(app->app_pri_tbl),
                                   is_default_off_tt_used);

        lm_dcbx_get_app_pri_off_tt(pdev,
                                   app_tbl_ext,
                                   app_tbl_ext_size,
                                   is_default_off_tt_used);
            }
    else
    {
        pdev->params.dcbx_port_params.app.enabled = FALSE;
        for( index=0 ;
             index < ARRSIZE(pdev->params.dcbx_port_params.app.traffic_type_priority) ;
             index++)
        {
            pdev->params.dcbx_port_params.app.traffic_type_priority[index] =
                INVALID_TRAFFIC_TYPE_PRIORITY;
        }
    }
}
void
lm_dcbx_get_dcbx_enabled(
    INOUT   lm_device_t         *pdev,
    IN const u32_t              error)
{
    dcbx_port_params_t  *dcbx_port_params = &(pdev->params.dcbx_port_params);
    u8_t const mfw_config = lm_dcbx_check_drv_flags(pdev, DRV_FLAGS_DCB_MFW_CONFIGURED);

    if((0 == GET_FLAGS(error, DCBX_REMOTE_MIB_ERROR)) ||
        (TRUE == mfw_config))
    {
        dcbx_port_params->dcbx_enabled = TRUE;
    }
    else
    {
        //If no configuration from OS / BACS and no DCBX received from the peer then disable DCB.
        dcbx_port_params->dcbx_enabled = FALSE;
    }
}
/*******************************************************************************
 * Description: Translate PFC/PG parameters to VBD parameters and call relevent
 * Function to set the parameters.
 *
 * Return:
******************************************************************************/
STATIC void
lm_print_dcbx_drv_param(IN struct _lm_device_t     *pdev,
                        IN const lldp_local_mib_t  *local_mib)
{
#if DBG
    u8_t i =0;
    DbgMessage(pdev, INFORM, "local_mib.error %x\n",local_mib->error);

    //Pg
    DbgMessage(pdev, INFORM, "local_mib.features.ets.enabled %x\n",local_mib->features.ets.enabled);
    for(i=0;i<DCBX_MAX_NUM_PG_BW_ENTRIES;i++)
    {
        DbgMessage(pdev, INFORM, "local_mib.features.ets.pg_bw_tbl[%x] %x\n",i,DCBX_PG_BW_GET(local_mib->features.ets.pg_bw_tbl,i));
    }
    for(i=0;i<DCBX_MAX_NUM_PRI_PG_ENTRIES;i++)
    {
        DbgMessage(pdev, INFORM,"local_mib.features.ets.pri_pg_tbl[%x] %x\n",i,DCBX_PRI_PG_GET(local_mib->features.ets.pri_pg_tbl,i));
    }

    //pfc
    DbgMessage(pdev, INFORM, "local_mib.features.pfc.pri_en_bitmap %x\n",local_mib->features.pfc.pri_en_bitmap);
    DbgMessage(pdev, INFORM, "local_mib.features.pfc.pfc_caps %x\n",local_mib->features.pfc.pfc_caps);
    DbgMessage(pdev, INFORM, "local_mib.features.pfc.enabled %x\n",local_mib->features.pfc.enabled);

    DbgMessage(pdev, INFORM, "local_mib.features.app.default_pri %x\n",local_mib->features.app.default_pri);
    DbgMessage(pdev, INFORM, "local_mib.features.app.tc_supported %x\n",local_mib->features.app.tc_supported);
    DbgMessage(pdev, INFORM, "local_mib.features.app.enabled %x\n",local_mib->features.app.enabled);
    for(i=0;i<DCBX_MAX_APP_PROTOCOL;i++)
    {

        // This has no logic this is only done for supporting old bootcodes.
        // The boot code still expexts u8 [2] instead of u16
        DbgMessage(pdev, INFORM,"local_mib.features.app.app_pri_tbl[%x].app_id %x\n",
                    i,local_mib->features.app.app_pri_tbl[i].app_id);

        DbgMessage(pdev, INFORM, "local_mib.features.app.app_pri_tbl[%x].pri_bitmap %x\n",
                    i,local_mib->features.app.app_pri_tbl[i].pri_bitmap);
        DbgMessage(pdev, INFORM, "local_mib.features.app.app_pri_tbl[%x].appBitfield %x\n",
                    i,local_mib->features.app.app_pri_tbl[i].appBitfield);
    }
#endif
}
/*******************************************************************************
 * Description: Translate PFC/PG parameters to VBD parameters and call relevent
 * Function to set the parameters.
 *
 * Return:
 ******************************************************************************/
STATIC void
lm_get_dcbx_drv_param(INOUT     lm_device_t         *pdev,
                      IN        lldp_local_mib_t        *local_mib,
                      IN const  lldp_local_mib_ext_t    *local_mib_ext)
{
    if(CHK_NULL(local_mib) || CHK_NULL(local_mib_ext))
    {
        DbgBreakMsg("lm_get_dcbx_drv_param wrong in parameters ");
        return;
    }

    lm_dcbx_get_dcbx_enabled(
        pdev,
        local_mib->error);

    lm_dcbx_get_ap_feature(
        pdev,
        &(local_mib->features.app),
        local_mib_ext->app_pri_tbl_ext,
        ARRSIZE(local_mib_ext->app_pri_tbl_ext),
        local_mib->error);

    lm_dcbx_get_pfc_feature(
        pdev,
        &(local_mib->features.pfc),
        local_mib->error);

    lm_dcbx_get_ets_feature(
        pdev,
        &(local_mib->features.ets),
        local_mib->error);
}
/*******************************************************************************
 * Description: Should be integrate with write and moved to common code
 *
 * Return:
******************************************************************************/
STATIC void
lm_dcbx_read_shmem2_mcp_fields(struct _lm_device_t * pdev,
                        u32_t                 offset,
                        u32_t               * val)
{
    u32_t shmem2_size;

    if (pdev->hw_info.shmem_base2 != 0)
    {
        LM_SHMEM2_READ(pdev, OFFSETOF(shmem2_region_t,size), &shmem2_size);
        if (shmem2_size > offset)
        {
            LM_SHMEM2_READ(pdev, offset, val);
        }
    }
}

/*******************************************************************************
 * Description:Should be integrate with read and moved to common code
 *
 * Return:
******************************************************************************/
STATIC void
lm_dcbx_write_shmem2_mcp_fields(struct _lm_device_t *pdev,
                                u32_t               offset,
                                u32_t               val)
{
    u32_t shmem2_size;

    if (pdev->hw_info.shmem_base2 != 0)
    {
        LM_SHMEM2_READ(pdev, OFFSETOF(shmem2_region_t,size), &shmem2_size);
        if (shmem2_size > offset)
        {
            LM_SHMEM2_WRITE(pdev, offset, val);
        }
    }
}
/*******************************************************************************
 * Description:
 *
 * Return:
******************************************************************************/
STATIC void
lm_dcbx_stop_hw_tx(struct _lm_device_t * pdev)
{

    // TODO DCBX change to cmd_id
    lm_eq_ramrod_post_sync(pdev,
                           RAMROD_CMD_ID_COMMON_STOP_TRAFFIC,
                           0,
                           CMD_PRIORITY_MEDIUM,/* Called from WI must be done ASAP*/
                           &(pdev->dcbx_info.dcbx_ramrod_state),
                           FUNCTION_DCBX_STOP_POSTED,
                           FUNCTION_DCBX_STOP_COMPLETED);

}
/*******************************************************************************
 * Description:
 *
 * Return:
******************************************************************************/
STATIC void
lm_dcbx_resume_hw_tx(struct _lm_device_t * pdev)
{
    lm_dcbx_fw_struct(pdev);

    lm_eq_ramrod_post_sync(pdev,
                           RAMROD_CMD_ID_COMMON_START_TRAFFIC,
                           pdev->dcbx_info.pfc_fw_cfg_phys.as_u64,
                           CMD_PRIORITY_HIGH,/* Called from WI must be done ASAP*/
                           &(pdev->dcbx_info.dcbx_ramrod_state),
                           FUNCTION_DCBX_START_POSTED,
                           FUNCTION_DCBX_START_COMPLETED);

}
/*******************************************************************************
 * Description:
 *
 * Return:
******************************************************************************/
#define DCBX_LOCAL_MIB_MAX_TRY_READ             (100)
STATIC lm_status_t
lm_dcbx_read_remote_local_mib(IN        struct _lm_device_t  *pdev,
                              OUT       u32_t                *base_mib_addr,
                              IN const  dcbx_read_mib_type   read_mib_type)
{
    static const u8_t dcbx_local_mib_max_try_read = DCBX_LOCAL_MIB_MAX_TRY_READ;
    u8_t    max_try_read            = 0 ,i =0;
    u32_t * buff                    = NULL;
    u32_t   mib_size                = 0,prefix_seq_num = 0 ,suffix_seq_num = 0;
    lldp_remote_mib_t *remote_mib   = NULL;
    lldp_local_mib_t  *local_mib    = NULL;
    const u32_t         mcp_dcbx_neg_res_offset     = OFFSETOF(shmem2_region_t,dcbx_neg_res_offset);
    const u32_t         mcp_dcbx_remote_mib_offset  = OFFSETOF(shmem2_region_t,dcbx_remote_mib_offset);
    u32_t               offset                      = 0;
    // verify no wraparound on while loop
    ASSERT_STATIC( sizeof( max_try_read ) == sizeof(u8_t) );
    ASSERT_STATIC(DCBX_LOCAL_MIB_MAX_TRY_READ < ((u8_t)-1));

    switch (read_mib_type)
    {
    case DCBX_READ_LOCAL_MIB:

        // Get negotiation results MIB data
        offset  = SHMEM_DCBX_NEG_RES_NONE;

        lm_dcbx_read_shmem2_mcp_fields(pdev,
                                       mcp_dcbx_neg_res_offset,
                                       &offset);

        if (SHMEM_DCBX_NEG_RES_NONE == offset)
        {
            DbgBreakMsg("lm_dcbx_read_remote_local_mib DCBX Negotiation result not supported");
            return LM_STATUS_FAILURE;
        }
        mib_size = sizeof(lldp_local_mib_t);
        break;
    case DCBX_READ_REMOTE_MIB:
        // Get remote MIB data
        offset  = SHMEM_DCBX_REMOTE_MIB_NONE;

        lm_dcbx_read_shmem2_mcp_fields(pdev,
                                mcp_dcbx_remote_mib_offset,
                                &offset);

        if (SHMEM_DCBX_REMOTE_MIB_NONE == offset)
        {
            DbgBreakMsg("lm_dcbx_read_remote_local_mib DCBX Negotiation result not supported");
            return LM_STATUS_FAILURE;
        }

        mib_size = sizeof(lldp_remote_mib_t);
        break;
    default:
        DbgBreakIf(1);
        return LM_STATUS_FAILURE;
    }

    offset += PORT_ID(pdev) * mib_size;

    do
    {
        buff = base_mib_addr;

        for(i=0 ;i<mib_size; i+=4,buff++)
        {
            *buff = REG_RD(pdev,
                          offset + i);
        }
        max_try_read++;

        switch (read_mib_type)
        {
        case DCBX_READ_LOCAL_MIB:
            local_mib   = (lldp_local_mib_t *) base_mib_addr;
            prefix_seq_num = local_mib->prefix_seq_num;
            suffix_seq_num = local_mib->suffix_seq_num;
            break;
        case DCBX_READ_REMOTE_MIB:
            remote_mib   = (lldp_remote_mib_t *) base_mib_addr;
            prefix_seq_num = remote_mib->prefix_seq_num;
            suffix_seq_num = remote_mib->suffix_seq_num;
            break;
        default:
            DbgBreakIf(1);
            return LM_STATUS_FAILURE;
        }
    }while((prefix_seq_num != suffix_seq_num)&&
           (max_try_read <dcbx_local_mib_max_try_read));


    if(max_try_read >= dcbx_local_mib_max_try_read)
    {
        DbgBreakMsg("prefix_seq_num doesnt equal suffix_seq_num for to much time");
        return LM_STATUS_FAILURE;
    }
    return LM_STATUS_SUCCESS;
}
/**
 *
 * @param pdev
 * @param local_mib
 * @param local_mib_ext
 *
 * @return lm_status_t
 */
lm_status_t
lm_dcbx_read_local_mib_fields(
    IN struct _lm_device_t  *pdev,
    OUT lldp_local_mib_t     *local_mib,
    OUT lldp_local_mib_ext_t *local_mib_ext)
{
    const u32_t field_res_ext_offset    = OFFSETOF(shmem2_region_t,dcbx_neg_res_ext_offset);
    u32_t       res_ext_offset          = SHMEM_DCBX_NEG_RES_EXT_NONE;
    u8_t        is_ext_sup              = FALSE;
    u8_t        max_try_read            = 0;
    lm_status_t      lm_status          = LM_STATUS_SUCCESS;

    mm_mem_zero(local_mib, sizeof(lldp_local_mib_t));
    mm_mem_zero(local_mib_ext, sizeof(lldp_local_mib_ext_t));

    if(LM_SHMEM2_HAS(pdev, dcbx_neg_res_ext_offset))
    {
    lm_dcbx_read_shmem2_mcp_fields(pdev,
                                       field_res_ext_offset,
                                       &res_ext_offset);
        //CQ62832 - T7.0  bootcode contains the field dcbx_neg_res_ext_offset
        // in shmem2 but dcbx_neg_res_ext_offse isn't implemented.
        if (SHMEM_DCBX_NEG_RES_EXT_NONE != res_ext_offset)
        {
        res_ext_offset += PORT_ID(pdev) * sizeof(lldp_local_mib_ext_t);
        is_ext_sup = TRUE;
    }
    }

    do
    {
    lm_status = lm_dcbx_read_remote_local_mib(pdev,
                                                  (u32_t *)local_mib,
                                              DCBX_READ_LOCAL_MIB);
        if (LM_STATUS_SUCCESS != lm_status)
        {
            DbgBreakMsg("lm_dcbx_read_remote_local_mib DCBX Negotiation result not supported");
            return lm_status;
        }

        if(FALSE == is_ext_sup)
        {
            break;
        }

        lm_reg_rd_blk(pdev,
                      res_ext_offset,
                      (u32_t *)local_mib_ext,
                      (sizeof(lldp_local_mib_ext_t)/sizeof(u32_t)));

        if((local_mib->prefix_seq_num == local_mib->suffix_seq_num ) &&
           (local_mib_ext->prefix_seq_num == local_mib_ext->suffix_seq_num ) &&
           (local_mib_ext->suffix_seq_num == local_mib->suffix_seq_num ))
        {
            break;
        }

        max_try_read++;

    }while(max_try_read < DCBX_LOCAL_MIB_MAX_TRY_READ);


    if(max_try_read >= DCBX_LOCAL_MIB_MAX_TRY_READ)
    {
        DbgBreakMsg("lm_dcbx_read_local_mib_fields : prefix_seq_num doesnt equal suffix_seq_num for to much time");
        return LM_STATUS_FAILURE;
    }

    return lm_status;
}
/**
 * Use parameters given for first calculate VBD settings for
 * each feature.
 * Use VBD settings to configure HW.
 * @param pdev
 * @param local_mib Not const because ETS parameters can be
 *                  changed (merge)
 * @param local_mib_ext
 * @param is_local_ets_change
 * @param b_can_update_ie - Update indiacate enent if indicate
 *                          event is valid and b_can_update_ie.
 *
 * @return lm_status_t
 */
lm_status_t
lm_dcbx_set_params(
    IN          lm_device_t              *pdev,
    IN  /*const*/ lldp_local_mib_t       *local_mib,
    IN  /*const*/   lldp_local_mib_ext_t *local_mib_ext,
    IN  const   u8_t                     is_local_ets_change,
    IN  const   u8_t                     b_can_update_ie
    )
{
    lm_status_t      lm_status          = LM_STATUS_SUCCESS;

    if(!IS_PMF(pdev))
    {
        DbgBreakMsg("lm_dcbx_update_lpme_set_params error");
        return LM_STATUS_FAILURE;
    }


    if(FALSE == pdev->dcbx_info.is_dcbx_neg_received)
    {
    pdev->dcbx_info.is_dcbx_neg_received = TRUE;
        // Setting the completion bit to TRUE can be
        // done only once but will done on each PMF
        // migration because is_dcbx_neg_received is
        // per function.
        lm_dcbx_config_drv_flags(pdev, lm_dcbx_drv_flags_set_bit, DRV_FLAGS_DCB_CONFIGURED);
    }

    lm_print_dcbx_drv_param(pdev,
                            local_mib);

    lm_get_dcbx_drv_param(pdev,
                          local_mib,
                          local_mib_ext);

    MM_ACQUIRE_PHY_LOCK(pdev);
    lm_cmng_update(pdev);
    MM_RELEASE_PHY_LOCK(pdev);

    lm_dcbx_stop_hw_tx(pdev);

    lm_pfc_handle_pfc(pdev);

    lm_dcbx_update_ets_params(pdev);

    lm_dcbx_resume_hw_tx(pdev);

    if((TRUE == pdev->dcbx_info.is_indicate_event_en) &&
       (TRUE == b_can_update_ie))
    {
        lm_status = lm_dcbx_ie_check_if_param_change(pdev,
                                                     local_mib,
                                                     local_mib_ext,
                                                     is_local_ets_change);
    }

    return lm_status;
}
/**
 * Read data from MCP and configure DCBX in HW and FW.
 * @param pdev
 * @param is_local_ets_change
 * @param b_can_update_ie Update indiacate enent if indicate
 *                          event is valid and b_can_update_ie.
 *
 * @return lm_status_t
 */
lm_status_t
lm_dcbx_set_params_and_read_mib(
    IN          lm_device_t *pdev,
    IN  const   u8_t        is_local_ets_change,
    IN  const   u8_t        b_can_update_ie
    )
{
    lldp_local_mib_t local_mib          = {0};
    lldp_local_mib_ext_t local_mib_ext  = {0};
    lm_status_t      lm_status          = LM_STATUS_SUCCESS;

    // No current flow should support this.
    DbgBreakIf(FALSE == b_can_update_ie);

    if(!IS_PMF(pdev))
    {
        DbgBreakMsg("lm_dcbx_update_lpme_set_params error");
        return LM_STATUS_FAILURE;
    }

    lm_status = lm_dcbx_read_local_mib_fields(pdev,
                                              &local_mib,
                                              &local_mib_ext);

    if(lm_status != LM_STATUS_SUCCESS)
    {

        DbgBreakMsg("lm_dcbx_set_params: couldn't read local_mib");
        return lm_status;
    }
    /******************************start Debbuging code not to submit**************************************/
    mm_memcpy(&pdev->dcbx_info.local_mib_last, &local_mib, sizeof(local_mib));
    /******************************end Debbuging code not to submit****************************************/

    lm_status =  lm_dcbx_set_params(pdev,
                                    &local_mib,
                                    &local_mib_ext,
                                    is_local_ets_change,
                                    b_can_update_ie);

    return lm_status;
}
/**
 * Disable DCBX in HW and FW.
 * @param pdev
 * @param b_can_update_ie - Update indiacate enent if indicate
 *                          event is valid and b_can_update_ie.
 *
 * @return lm_status_t
 */
lm_status_t
lm_dcbx_disable_dcb_at_fw_and_hw(
    IN          lm_device_t *pdev,
    IN  const   u8_t        b_can_update_ie
    )
{
    lldp_local_mib_t local_mib          = {0};
    lldp_local_mib_ext_t local_mib_ext  = {0};
    lm_status_t      lm_status          = LM_STATUS_SUCCESS;

    // No current flow should support this.
    DbgBreakIf(TRUE == b_can_update_ie);

    if(!IS_PMF(pdev))
    {
        DbgBreakMsg("lm_dcbx_update_lpme_set_params error");
        return LM_STATUS_FAILURE;
    }

    lm_status =  lm_dcbx_set_params(pdev,
                                    &local_mib,
                                    &local_mib_ext,
                                    FALSE,
                                    b_can_update_ie);

    return lm_status;
}
/**********************start DCBX INIT FUNCTIONS**************************************/

/*******************************************************************************
 * Description:
 *
 * Return:
******************************************************************************/
STATIC lm_status_t
lm_dcbx_init_check_params_valid(INOUT       lm_device_t     *pdev,
                                OUT         u32_t           *buff_check,
                                IN const    u32_t           buff_size)
{
    u32_t i=0;
    lm_status_t ret_val = LM_STATUS_SUCCESS;

    for (i=0 ; i < buff_size ; i++,buff_check++)
    {
        if( DCBX_CONFIG_INV_VALUE == *buff_check)
        {
            ret_val = LM_STATUS_INVALID_PARAMETER;
        }
    }
    return ret_val;
}
/*******************************************************************************
 * Description: Read lldp parameters.
 * Return:
******************************************************************************/
lm_status_t
lm_dcbx_lldp_read_params(struct _lm_device_t            * pdev,
                         b10_lldp_params_get_t          * lldp_params)
{
    lldp_params_t       mcp_lldp_params                 = {0};
    lldp_dcbx_stat_t    mcp_dcbx_stat                   = {{0}};
    u32_t               i                               = 0;
    u32_t               *buff                           = NULL ;
    u32_t               offset                          = 0;
    lm_status_t         lm_status                       = LM_STATUS_SUCCESS;
    const u32_t         mcp_dcbx_lldp_params_offset     = OFFSETOF(shmem2_region_t,dcbx_lldp_params_offset);
    const u32_t         mcp_dcbx_lldp_dcbx_stat_offset  = OFFSETOF(shmem2_region_t,dcbx_lldp_dcbx_stat_offset);

    mm_mem_zero(lldp_params, sizeof(b10_lldp_params_get_t));


    offset     = SHMEM_LLDP_DCBX_PARAMS_NONE;

    lm_dcbx_read_shmem2_mcp_fields(pdev,
                            mcp_dcbx_lldp_params_offset,
                            &offset);

    if((!IS_DCB_ENABLED(pdev)) ||
       (SHMEM_LLDP_DCBX_PARAMS_NONE == offset))
    {//DCBX isn't supported on E1
        return LM_STATUS_FAILURE;
    }

    lldp_params->config_lldp_params.overwrite_settings =
        pdev->params.lldp_config_params.overwrite_settings;

    if (SHMEM_LLDP_DCBX_PARAMS_NONE != offset)
    {
        offset += PORT_ID(pdev) * sizeof(lldp_params_t);

        //Read the data first
        buff = (u32_t *)&mcp_lldp_params;
        for(i=0 ;i<sizeof(lldp_params_t); i+=4,buff++)
        {
            *buff = REG_RD(pdev,
                          (offset + i));
        }
        lldp_params->ver_num                                     = LLDP_PARAMS_VER_NUM;
        lldp_params->config_lldp_params.msg_tx_hold              = mcp_lldp_params.msg_tx_hold;
        lldp_params->config_lldp_params.msg_fast_tx              = mcp_lldp_params.msg_fast_tx_interval;
        lldp_params->config_lldp_params.tx_credit_max            = mcp_lldp_params.tx_crd_max;
        lldp_params->config_lldp_params.msg_tx_interval          = mcp_lldp_params.msg_tx_interval;
        lldp_params->config_lldp_params.tx_fast                  = mcp_lldp_params.tx_fast;


        // Preparation for new shmem
        ASSERT_STATIC(ARRSIZE(lldp_params->remote_chassis_id) >= ARRSIZE(mcp_lldp_params.peer_chassis_id));
        ASSERT_STATIC(sizeof(lldp_params->remote_chassis_id[0]) == sizeof(mcp_lldp_params.peer_chassis_id[0]));
        for(i=0 ; i< ARRSIZE(mcp_lldp_params.peer_chassis_id) ; i++)
        {
            lldp_params->remote_chassis_id[i]    = mcp_lldp_params.peer_chassis_id[i];
        }

        ASSERT_STATIC(sizeof(lldp_params->remote_port_id[0]) == sizeof(mcp_lldp_params.peer_port_id[0]));
        ASSERT_STATIC(ARRSIZE(lldp_params->remote_port_id) > ARRSIZE(mcp_lldp_params.peer_port_id));
        for(i=0 ; i<ARRSIZE(mcp_lldp_params.peer_port_id) ; i++)
        {
            lldp_params->remote_port_id[i]    = mcp_lldp_params.peer_port_id[i];
        }

        lldp_params->admin_status                                = mcp_lldp_params.admin_status;
    }
    else
    {// DCBX not supported in MCP
        DbgBreakMsg("DCBX DCBX params supported");
        lm_status= LM_STATUS_FAILURE;
    }

    offset     = SHMEM_LLDP_DCBX_STAT_NONE;

    lm_dcbx_read_shmem2_mcp_fields(pdev,
                            mcp_dcbx_lldp_dcbx_stat_offset,
                            &offset);

    if (SHMEM_LLDP_DCBX_STAT_NONE != offset)
    {
        offset += PORT_ID(pdev) * sizeof(mcp_dcbx_stat);

        //Read the data first
        buff = (u32_t *)&mcp_dcbx_stat;
        for(i=0 ;i<sizeof(mcp_dcbx_stat); i+=4,buff++)
        {
            *buff = REG_RD(pdev,
                          (offset + i));
        }
        // Preparation for new shmem

        ASSERT_STATIC(ARRSIZE(lldp_params->local_chassis_id) >= ARRSIZE(mcp_dcbx_stat.local_chassis_id));
        ASSERT_STATIC(sizeof(lldp_params->local_chassis_id[0]) >= sizeof(mcp_dcbx_stat.local_chassis_id[0]));
        for(i=0 ; i< ARRSIZE(mcp_dcbx_stat.local_chassis_id) ; i++)
        {
            lldp_params->local_chassis_id[i]    = mcp_dcbx_stat.local_chassis_id[i];
        }

        ASSERT_STATIC(ARRSIZE(lldp_params->local_port_id) >= ARRSIZE(mcp_dcbx_stat.local_port_id));
        ASSERT_STATIC(sizeof(lldp_params->local_port_id[0]) >= sizeof(mcp_dcbx_stat.local_port_id[0]));
        for(i=0 ; i< ARRSIZE(mcp_dcbx_stat.local_port_id) ; i++)
        {
            lldp_params->local_port_id[i]    = mcp_dcbx_stat.local_port_id[i];
        }
    }
    else
    {// DCBX not supported in MCP
        DbgBreakMsg("DCBX DCBX stats supported");
        lm_status= LM_STATUS_FAILURE;
    }

    return lm_status;
}
/*******************************************************************************
 * Description:
 *              mcp_pg_bw_tbl_size: In elements.
 *              set_configuration_bw_size: In elements.
 * Return:
******************************************************************************/
STATIC void
lm_dcbx_get_bw_percentage_tbl(struct _lm_device_t   * pdev,
                              OUT u32_t             * set_configuration_bw,
                              IN u32_t              * mcp_pg_bw_tbl,
                              IN const u8_t         set_configuration_bw_size,
                              IN const u8_t         mcp_pg_bw_tbl_size)
{

    u8_t        i       = 0;
    const u8_t  mcp_pg_bw_tbl_size_in_bytes = (sizeof(*mcp_pg_bw_tbl)*(mcp_pg_bw_tbl_size));

    DbgBreakIf(set_configuration_bw_size != mcp_pg_bw_tbl_size);

    DbgBreakIf(0 != (mcp_pg_bw_tbl_size_in_bytes % sizeof(u32_t)));
    for(i=0 ;i<set_configuration_bw_size ;i++)
    {
        set_configuration_bw[i] = DCBX_PG_BW_GET(mcp_pg_bw_tbl,i);
    }
}
/*******************************************************************************
 * Description: Parse ets_pri_pg data and spread it from nibble to 32 bits.
 *
 * Return:
******************************************************************************/
STATIC void
lm_dcbx_get_ets_pri_pg_tbl(struct _lm_device_t      * pdev,
                           OUT      u32_t           * set_configuration_ets_pg,
                           IN const u32_t           * mcp_pri_pg_tbl,
                           IN const u8_t            set_priority_app_size,
                           IN const u8_t            mcp_pri_pg_tbl_size)
{
    u8_t        i       = 0;
    const u8_t  mcp_pri_pg_tbl_size_in_bytes = (sizeof(*mcp_pri_pg_tbl)*(mcp_pri_pg_tbl_size));

    DbgBreakIf(set_priority_app_size != (mcp_pri_pg_tbl_size));

    // Arrays that there cell are less than 32 bit are still
    // in big endian mode.
    DbgBreakIf(0 != (mcp_pri_pg_tbl_size_in_bytes % sizeof(u32_t)));

    // Nibble handling
    for(i=0 ; i < set_priority_app_size ; i++)
    {
            set_configuration_ets_pg[i] = DCBX_PRI_PG_GET(mcp_pri_pg_tbl,i);
    }
}
/*******************************************************************************
 * Description: Parse priority app data.
 *
 * Return:
******************************************************************************/
STATIC void
lm_dcbx_get_priority_app_table(struct _lm_device_t                      * pdev,
                              OUT struct _admin_priority_app_table_t    * set_priority_app,
                              IN dcbx_app_priority_entry_t              * mcp_array,
                              IN const u8_t                              set_priority_app_size,
                              IN const u8_t                              mcp_array_size)
{
    u8_t    i           = 0;

    if(set_priority_app_size > mcp_array_size)
    {
        DbgBreakIf(1);
        return;
    }

    for(i=0 ;i<set_priority_app_size ;i++)
    {
        if(GET_FLAGS(mcp_array[i].appBitfield,DCBX_APP_ENTRY_VALID))
        {
            set_priority_app[i].valid = TRUE;
        }

        if(GET_FLAGS(mcp_array[i].appBitfield,DCBX_APP_SF_ETH_TYPE))
        {
            set_priority_app[i].traffic_type = TRAFFIC_TYPE_ETH;
        }
        else
        {
            set_priority_app[i].traffic_type = TRAFFIC_TYPE_PORT;
        }
        set_priority_app[i].priority = mcp_array[i].pri_bitmap;


        // This has no logic this is only done for supporting old bootcodes.
        // The boot code still expexts u8 [2] instead of u16
        set_priority_app[i].app_id = mcp_array[i].app_id;
    }

}
/**
 * @description
 * Fill the operational parameters.
 * @param pdev
 * @param dcbx_params
 *
 * @return STATIC void
 */
STATIC void
lm_dcbx_read_params_fill_oper_state(struct _lm_device_t            * pdev,
                                    b10_dcbx_params_get_t          * dcbx_params)
{
    lm_dcbx_indicate_event_t *indicate_event = &pdev->dcbx_info.indicate_event;

    if(TRUE == pdev->params.dcbx_port_params.app.enabled)
    {
        SET_FLAGS(dcbx_params->dcb_current_oper_state_bitmap,PRIORITY_TAGGING_IS_CURRENTLY_OPERATIONAL);
    }

    if(TRUE == pdev->params.dcbx_port_params.pfc.enabled)
    {
        SET_FLAGS(dcbx_params->dcb_current_oper_state_bitmap,PFC_IS_CURRENTLY_OPERATIONAL);
    }

    if(TRUE == pdev->params.dcbx_port_params.ets.enabled)
    {
        SET_FLAGS(dcbx_params->dcb_current_oper_state_bitmap,ETS_IS_CURRENTLY_OPERATIONAL);
    }

    if(GET_FLAGS(indicate_event->dcb_current_oper_state_bitmap,
                 DCB_STATE_CONFIGURED_BY_OS_QOS))
    {
        SET_FLAGS(dcbx_params->dcb_current_oper_state_bitmap,
                  DRIVER_CONFIGURED_BY_OS_QOS);
    }

    if(GET_FLAGS(indicate_event->dcb_current_oper_state_bitmap,
                 DCB_STATE_CONFIGURED_BY_OS_QOS_TO_WILLING))
    {
        SET_FLAGS(dcbx_params->dcb_current_oper_state_bitmap,
                  DRIVER_CONFIGURED_BY_OS_QOS_TO_WILLING);
    }
}
/*******************************************************************************
 * Description: Read DCBX parameters from admin/local and remote MIBs.
 *
 * Return:
 *              LM_STATUS_FAILURE - All/Some of the parameters could not be read.
 *              LM_STATUS_SUCCESS - All the MIBs where read successfully.
******************************************************************************/
lm_status_t
lm_dcbx_read_params(struct _lm_device_t            * pdev,
                    b10_dcbx_params_get_t          * dcbx_params)
{
    lldp_admin_mib_t    admin_mib                       = {0};
    lldp_local_mib_t    local_mib                       = {0};
    lldp_remote_mib_t   remote_mib                      = {0};
    lldp_dcbx_stat_t    mcp_dcbx_stat                   = {{0}};
    lm_dcbx_stat        dcbx_stat                       = {0};
    u32_t               pfc_frames_sent[2]              = {0};
    u32_t               pfc_frames_received[2]          = {0};
    u32_t               i                               = 0;
    u32_t               *buff                           = NULL;
    u32_t               offset                          = SHMEM_LLDP_DCBX_PARAMS_NONE;
    lm_status_t         lm_status                       = LM_STATUS_SUCCESS;
    const u32_t         mcp_dcbx_lldp_params_offset     = OFFSETOF(shmem2_region_t,dcbx_lldp_params_offset);
    const u32_t         mcp_dcbx_lldp_dcbx_stat_offset  = OFFSETOF(shmem2_region_t,dcbx_lldp_dcbx_stat_offset);

    mm_mem_zero(dcbx_params, sizeof(b10_dcbx_params_get_t));

    lm_dcbx_read_params_fill_oper_state(pdev,dcbx_params);

    lm_dcbx_read_shmem2_mcp_fields(pdev,
                            mcp_dcbx_lldp_params_offset,
                            &offset);

    if((!IS_DCB_ENABLED(pdev)) ||
       (SHMEM_LLDP_DCBX_PARAMS_NONE == offset))
    {//DCBX isn't supported on E1
        return LM_STATUS_FAILURE;
    }

    dcbx_params->config_dcbx_params.overwrite_settings =
        pdev->params.dcbx_config_params.overwrite_settings;

    // E3.0 might be 4...not supported in current shmem
    ASSERT_STATIC( 2 == PORT_MAX );

    if (SHMEM_LLDP_DCBX_PARAMS_NONE != offset)
    {
        offset = LM_DCBX_ADMIN_MIB_OFFSET(pdev ,offset);

        //Read the data first
        buff = (u32_t *)&admin_mib;
        for(i=0 ;i<sizeof(lldp_admin_mib_t); i+=4,buff++)
        {
            *buff = REG_RD(pdev,
                          (offset + i));
        }

        dcbx_params->config_dcbx_params.dcb_enable          = IS_DCB_ENABLED(pdev) ;

        if(GET_FLAGS(admin_mib.ver_cfg_flags,DCBX_DCBX_ENABLED))
        {
            dcbx_params->config_dcbx_params.admin_dcbx_enable   = 1 ;
        }

        if(GET_FLAGS(admin_mib.ver_cfg_flags,DCBX_VERSION_CEE))
        {
            dcbx_params->config_dcbx_params.admin_dcbx_version  = ADMIN_DCBX_VERSION_CEE;
        }
        else if(GET_FLAGS(admin_mib.ver_cfg_flags,DCBX_VERSION_IEEE))
        {
            dcbx_params->config_dcbx_params.admin_dcbx_version  = ADMIN_DCBX_VERSION_IEEE;
        }
        else
        {
            dcbx_params->config_dcbx_params.admin_dcbx_version  = OVERWRITE_SETTINGS_INVALID;
            DbgMessage(pdev, WARN, " unknown DCBX version ");
        }

        dcbx_params->config_dcbx_params.admin_ets_enable    = admin_mib.features.ets.enabled;

        dcbx_params->config_dcbx_params.admin_pfc_enable    = admin_mib.features.pfc.enabled;

        //FOR IEEE pdev->params.dcbx_config_params.admin_tc_supported_tx_enable
        if(GET_FLAGS(admin_mib.ver_cfg_flags,DCBX_ETS_CONFIG_TX_ENABLED))
        {
            dcbx_params->config_dcbx_params.admin_ets_configuration_tx_enable = TRUE;
        }
        //For IEEE admin_ets_recommendation_tx_enable

        if(GET_FLAGS(admin_mib.ver_cfg_flags,DCBX_PFC_CONFIG_TX_ENABLED))
        {
            dcbx_params->config_dcbx_params.admin_pfc_tx_enable = TRUE;
        }

        if(GET_FLAGS(admin_mib.ver_cfg_flags,DCBX_APP_CONFIG_TX_ENABLED))
        {
            dcbx_params->config_dcbx_params.admin_application_priority_tx_enable = TRUE;
        }


        if(GET_FLAGS(admin_mib.ver_cfg_flags,DCBX_ETS_WILLING))
        {
            dcbx_params->config_dcbx_params.admin_ets_willing = TRUE;
        }

        //For IEEE admin_ets_reco_valid

        if(GET_FLAGS(admin_mib.ver_cfg_flags,DCBX_PFC_WILLING))
        {
            dcbx_params->config_dcbx_params.admin_pfc_willing = TRUE;
        }


        if(GET_FLAGS(admin_mib.ver_cfg_flags,DCBX_APP_WILLING))
        {
            dcbx_params->config_dcbx_params.admin_app_priority_willing = TRUE;
        }


        lm_dcbx_get_bw_percentage_tbl(pdev,
                              dcbx_params->config_dcbx_params.admin_configuration_bw_percentage,
                              admin_mib.features.ets.pg_bw_tbl,
                              ARRSIZE(dcbx_params->config_dcbx_params.admin_configuration_bw_percentage),
                              DCBX_MAX_NUM_PG_BW_ENTRIES);

        lm_dcbx_get_ets_pri_pg_tbl(pdev,
                                   dcbx_params->config_dcbx_params.admin_configuration_ets_pg,
                                   admin_mib.features.ets.pri_pg_tbl,
                                   ARRSIZE(dcbx_params->config_dcbx_params.admin_configuration_ets_pg),
                                   DCBX_MAX_NUM_PRI_PG_ENTRIES);


        //For IEEE admin_recommendation_bw_percentage
        //For IEEE admin_recommendation_ets_pg
        dcbx_params->config_dcbx_params.admin_pfc_bitmap = admin_mib.features.pfc.pri_en_bitmap;

        lm_dcbx_get_priority_app_table(pdev,
                                  dcbx_params->config_dcbx_params.admin_priority_app_table,
                                  admin_mib.features.app.app_pri_tbl,
                                  ARRSIZE(dcbx_params->config_dcbx_params.admin_priority_app_table),
                                  ARRSIZE(admin_mib.features.app.app_pri_tbl));

        dcbx_params->config_dcbx_params.admin_default_priority = admin_mib.features.app.default_pri;
    }
    else
    {// DCBX not supported in MCP
        DbgBreakMsg("DCBX DCBX params not supported");
        lm_status= LM_STATUS_FAILURE;
    }

        lm_status = lm_dcbx_read_remote_local_mib(pdev,
                                           (u32_t *)&local_mib,
                                           DCBX_READ_LOCAL_MIB);

    if (LM_STATUS_SUCCESS == lm_status)
    {

        if(0 == GET_FLAGS(local_mib.error,DCBX_REMOTE_MIB_ERROR))
        {
            SET_FLAGS(dcbx_params->dcb_current_oper_state_bitmap,DCBX_CURRENT_STATE_IS_SYNC);
        }

        dcbx_params->ver_num            = DCBX_PARAMS_VER_NUM;
        dcbx_params->local_tc_supported = local_mib.features.app.tc_supported;
        dcbx_params->local_pfc_caps     = local_mib.features.pfc.pfc_caps;
        dcbx_params->local_ets_enable   = local_mib.features.ets.enabled;
        dcbx_params->local_pfc_enable   = local_mib.features.pfc.enabled;

        lm_dcbx_get_bw_percentage_tbl(pdev,
                              dcbx_params->local_configuration_bw_percentage,
                              local_mib.features.ets.pg_bw_tbl,
                              ARRSIZE(dcbx_params->local_configuration_bw_percentage),
                              DCBX_MAX_NUM_PG_BW_ENTRIES);

        lm_dcbx_get_ets_pri_pg_tbl(pdev,
                                   dcbx_params->local_configuration_ets_pg,
                                   local_mib.features.ets.pri_pg_tbl,
                                   ARRSIZE(dcbx_params->local_configuration_ets_pg),
                                   DCBX_MAX_NUM_PRI_PG_ENTRIES);

        dcbx_params->local_pfc_bitmap = local_mib.features.pfc.pri_en_bitmap;

        lm_dcbx_get_priority_app_table(pdev,
                                  dcbx_params->local_priority_app_table,
                                  local_mib.features.app.app_pri_tbl,
                                  ARRSIZE(dcbx_params->local_priority_app_table),
                                  ARRSIZE(local_mib.features.app.app_pri_tbl));

        if(GET_FLAGS(local_mib.error,DCBX_LOCAL_PFC_MISMATCH))
        {
            dcbx_params->pfc_mismatch = TRUE;
        }

        if(GET_FLAGS(local_mib.error,DCBX_LOCAL_APP_MISMATCH))
        {
            dcbx_params->priority_app_mismatch = TRUE;
        }
    }
    else
    {// DCBX not supported in MCP
        DbgBreakMsg("DCBX Negotiation result not supported");
        lm_status= LM_STATUS_FAILURE;
    }
    // Get remote MIB data

        lm_status = lm_dcbx_read_remote_local_mib(pdev,
                                                  (u32_t *)&remote_mib,
                                                  DCBX_READ_REMOTE_MIB);
    if (LM_STATUS_SUCCESS == lm_status)
    {

        dcbx_params->remote_tc_supported = remote_mib.features.app.tc_supported;
        dcbx_params->remote_pfc_cap = remote_mib.features.pfc.pfc_caps;
        if(GET_FLAGS(remote_mib.flags,DCBX_REMOTE_ETS_RECO_VALID))
        {
            dcbx_params->remote_ets_reco_valid = TRUE;
        }

        if(GET_FLAGS(remote_mib.flags,DCBX_ETS_REM_WILLING))
        {
            dcbx_params->remote_ets_willing = TRUE;
        }

        if(GET_FLAGS(remote_mib.flags,DCBX_PFC_REM_WILLING))
        {
            dcbx_params->remote_pfc_willing = TRUE;
        }

        if(GET_FLAGS(remote_mib.flags,DCBX_APP_REM_WILLING))
        {
            dcbx_params->remote_app_priority_willing = TRUE;
        }

        lm_dcbx_get_bw_percentage_tbl(pdev,
                              dcbx_params->remote_configuration_bw_percentage,
                              remote_mib.features.ets.pg_bw_tbl,
                              ARRSIZE(dcbx_params->remote_configuration_bw_percentage),
                              DCBX_MAX_NUM_PG_BW_ENTRIES);

        lm_dcbx_get_ets_pri_pg_tbl(pdev,
                                   dcbx_params->remote_configuration_ets_pg,
                                   remote_mib.features.ets.pri_pg_tbl,
                                   ARRSIZE(dcbx_params->remote_configuration_ets_pg),
                                   DCBX_MAX_NUM_PRI_PG_ENTRIES);
        // For IEEE remote_recommendation_bw_percentage
        // For IEEE remote_recommendation_ets_pg

        dcbx_params->remote_pfc_bitmap = remote_mib.features.pfc.pri_en_bitmap;

        lm_dcbx_get_priority_app_table(pdev,
                                  dcbx_params->remote_priority_app_table,
                                  remote_mib.features.app.app_pri_tbl,
                                  ARRSIZE(dcbx_params->remote_priority_app_table),
                                  ARRSIZE(remote_mib.features.app.app_pri_tbl));
    }
    else
    {// DCBX not supported in MCP
        DbgBreakMsg("DCBX remote MIB not supported");
        lm_status= LM_STATUS_FAILURE;
    }

    // Get negotiation results MIB data
    offset  = SHMEM_LLDP_DCBX_STAT_NONE;

    lm_dcbx_read_shmem2_mcp_fields(pdev,
                            mcp_dcbx_lldp_dcbx_stat_offset,
                            &offset);

    // E3.0 might be 4...not supported in current shmem
    ASSERT_STATIC( 2 == PORT_MAX );

    if (SHMEM_LLDP_DCBX_STAT_NONE != offset)
    {
        offset += PORT_ID(pdev) * sizeof(mcp_dcbx_stat);

        //Read the data first
        buff = (u32_t *)&mcp_dcbx_stat;
        for(i=0 ;i<sizeof(mcp_dcbx_stat); i+=4,buff++)
        {
            *buff = REG_RD(pdev,
                          (offset + i));
        }

        dcbx_params->dcbx_frames_sent       = mcp_dcbx_stat.num_tx_dcbx_pkts;
        dcbx_params->dcbx_frames_received   = mcp_dcbx_stat.num_rx_dcbx_pkts;
    }
    else
    {// DCBX not supported in MCP
        DbgBreakMsg("DCBX statistic not supported");
        lm_status= LM_STATUS_FAILURE;
    }
    // TODO - Move to lm_stat


    if(pdev->vars.mac_type == MAC_TYPE_EMAC)
    {
    MM_ACQUIRE_PHY_LOCK(pdev);
        // EMAC stats are not collected through statitic code.
    elink_pfc_statistic(&pdev->params.link, &pdev->vars.link,
                        pfc_frames_sent, pfc_frames_received);

    MM_RELEASE_PHY_LOCK(pdev);

        dcbx_stat.pfc_frames_sent = ((u64_t)(pfc_frames_sent[1]) << 32) + pfc_frames_sent[0];

        dcbx_stat.pfc_frames_received = ((u64_t)(pfc_frames_received[1]) << 32) + pfc_frames_received[0];
    }
    else
    {
        lm_stats_get_dcb_stats( pdev, &dcbx_stat );

    }

    dcbx_params->pfc_frames_sent = dcbx_stat.pfc_frames_sent;

    dcbx_params->pfc_frames_received = dcbx_stat.pfc_frames_received;

    return lm_status;
}
/*******************************************************************************
 * Description:
 *
 * Return:
******************************************************************************/
void
lm_dcbx_init_lpme_set_params(struct _lm_device_t *pdev)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;

    if( TRUE == pdev->dcbx_info.is_dcbx_neg_received)
    {
        // DCBX negotiation ended normaly.
        return;
    }
    //DbgBreakMsg(" lm_dcbx_init_lpme_set_params : DCBX timer configuration \n");
    //DbgMessage(pdev, FATAL, "lm_dcbx_init_lpme_set_params : DCBX timer configuration \n");
    // DCBX negotiation didn’t ended normaly yet.
    // No lock is needed to be taken because lm_dcbx_set_params is only called from a WI
    lm_status = lm_dcbx_set_params_and_read_mib(pdev,
                                                FALSE,
                                                TRUE);

    DbgBreakIf(LM_STATUS_SUCCESS != lm_status);
}
/**
 * look for an entry that isn't iSCSI or FCoE and return it's
 * position.
 * @param pdev
 * @param app
 *
 * @return STATIC u8_t
 */
STATIC u8_t
lm_dcbx_app_find_non_off_tt_entry(
    IN          lm_device_t                 *pdev,
    INOUT       dcbx_app_priority_feature_t *app
    )
{
    dcbx_app_priority_entry_t *app_priority_entry = NULL;
    u8_t entry = 0;

    for(entry = 0; entry < ARRSIZE(app->app_pri_tbl); entry++)
    {
        app_priority_entry = &(app->app_pri_tbl[entry]);

        if(lm_dcbx_cee_is_entry_fcoe_classif(app_priority_entry->appBitfield,
                                             app_priority_entry->app_id))
        {
            DbgMessage(pdev, INFORM, "lm_dcbx_app_find_non_off_tt_entry :FCOE entry");
        }
        else if(lm_dcbx_cee_is_entry_iscsi_classif(app_priority_entry->appBitfield,
                                                   app_priority_entry->app_id))
        {
            DbgMessage(pdev, INFORM, "lm_dcbx_app_find_non_off_tt_entry :ISCSI entry");
        }
        else
        {
            // Found an entry that isn't ISCSI or FCOE
            break;
        }
    }

    return entry;
}
/**
 * @description
 *
 * @param pdev
 * @param app
 * @param other_traf_type_entry - For entries that are not
 *                              predefined
 * @param app_id
 * @param traffic_type
 * @param priority
 *
 * @return STATIC lm_status_t
 */
STATIC lm_status_t
lm_dcbx_admin_mib_update_app_pri(
    IN          lm_device_t                 *pdev,
    INOUT       dcbx_app_priority_feature_t *app,
    INOUT       u8_t                        *next_free_app_id_entry,
    IN const    u16_t                       app_id,
    IN const    u8_t                        traffic_type,
    IN const    u8_t                        priority)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    u8_t traf_type_entry = 0;
    u8_t app_bit_field = DCBX_APP_ENTRY_VALID;

    switch(traffic_type)
    {
    case TRAFFIC_TYPE_ETH:
        app_bit_field |= DCBX_APP_SF_ETH_TYPE;
        break;
    case TRAFFIC_TYPE_PORT:
        app_bit_field |= DCBX_APP_SF_PORT;
        break;
    default:
        DbgBreakMsg("lm_dcbx_admin_mib_update_app_pri illegal traffic_type entry ");
        return LM_STATUS_INVALID_PARAMETER;
    }

    if(ARRSIZE(app->app_pri_tbl) <= (*next_free_app_id_entry) )
    {
        // Reserve two entries to iSCSI and FCoE (in case they will
        // be received after the 16th application priority entry).
        if(lm_dcbx_cee_is_entry_iscsi_classif(
            app_bit_field,
            app_id ) ||
           lm_dcbx_cee_is_entry_fcoe_classif(
            app_bit_field,
            app_id))
        {
            traf_type_entry = lm_dcbx_app_find_non_off_tt_entry(pdev, app);

            if (ARRSIZE(app->app_pri_tbl) <= traf_type_entry)
            {
                DbgBreakMsg("lm_dcbx_admin_mib_update_app_pri : traf_type_entry contains an invalid value ");
                return lm_status;
            }
        }
        else
        {
            return lm_status;
        }
    }
    else
    {
        DbgBreakIf(ARRSIZE(app->app_pri_tbl) <= (*next_free_app_id_entry));
        traf_type_entry = (*next_free_app_id_entry)++;
    }

    DbgBreakIf(ARRSIZE(app->app_pri_tbl) <= traf_type_entry );

    app->app_pri_tbl[traf_type_entry].app_id = app_id;

    app->app_pri_tbl[traf_type_entry].pri_bitmap =(u8_t)(1 << priority);

    app->app_pri_tbl[traf_type_entry].appBitfield = app_bit_field;

    return lm_status;
}
/**
 * @description
 * Update admin MIB classification entries with OS DCBX
 * classification configuration.
 * @param pdev
 * @param admin_mib
 * @param dcb_params
 * @param classif_local_vars
 *
 * @return STATIC lm_status_t
 */
STATIC lm_status_t
lm_dcbx_ie_admin_mib_classif(IN         lm_device_t                 *pdev,
                             INOUT      dcbx_app_priority_feature_t *app,
                             IN const   dcb_classif_params_t        *classif_params,
                             IN const   u32_t                       flags
                             )
{
    lm_dcbx_indicate_event_t *indicate_event    = &pdev->dcbx_info.indicate_event;
    dcb_classif_elem_t  *p_classif_elem         = (dcb_classif_elem_t *)classif_params->classif_table;
    u32_t               i                       = 0;
    u8_t                traffic_type            = 0;
    u8_t                b_update_admin          = FALSE;
    // Other traffic type is defined as not ISCSI or FCOE
    u8_t                next_free_app_id_entry  = 0;

    mm_mem_zero(&(app->app_pri_tbl), sizeof(app->app_pri_tbl));
    app->default_pri = 0;
    app->tc_supported = 0;
    indicate_event->iscsi_tcp_pri = LM_DCBX_ILLEGAL_PRI;

    if(0 == GET_FLAGS(flags, DCB_PARAMS_CLASSIF_ENABLED))
    {
        return LM_STATUS_SUCCESS;
    }

    for(i = 0; i < classif_params->num_classif_elements; i++ , p_classif_elem++)
    {
        b_update_admin = FALSE;

        if(DCB_ACTION_PRIORITY != p_classif_elem->action_selector)
        {
            // VBD only supports condition_selector that is based on priority
            continue;
        }
        switch(p_classif_elem->condition_selector)
        {
        case DCB_CONDITION_DEFAULT:
            // If default entry exist it must be the first entry ISCSI and FCOE priority
            // will be update accordingly. If OS gave us an ISCSI or FCOE entry it will
            // overwrite this value.
            DbgBreakIf(0 != i);
            app->default_pri = (u8_t)p_classif_elem->action_field;
            break;

        case DCB_CONDITION_TCP_OR_UDP_PORT:
            traffic_type = TRAFFIC_TYPE_PORT;
            b_update_admin = TRUE;
            break;

        case DCB_CONDITION_ETHERTYPE:
            traffic_type = TRAFFIC_TYPE_ETH;
            b_update_admin = TRUE;
            break;
        case DCB_CONDITION_TCP_PORT:
            if(TCP_PORT_ISCSI == p_classif_elem->condition_field)
            {
                // Check if ISCSI prioriy changed from last time.
                if(LM_DCBX_ILLEGAL_PRI <= p_classif_elem->action_field )
                {
                    DbgBreakMsg("lm_dcbx_ie_admin_mib_update_runtime_classif illegal action field");
                    return LM_STATUS_FAILURE;
                }
                if(p_classif_elem->action_field !=
                   indicate_event->iscsi_tcp_pri)
                {
                    indicate_event->iscsi_tcp_pri = p_classif_elem->action_field;
                }
            }
            break;
        case DCB_CONDITION_RESERVED:
        case DCB_CONDITION_UDP_PORT://Fall through
        case DCB_CONDITION_NETDIRECT_PORT://Fall through
            //Not supported by VBD
            break;
        default:
            DbgBreakMsg("lm_dcbx_runtime_params_updated_en_classif_entries: illegal entry ");
            break;
        }
        if(TRUE == b_update_admin)
        {
            lm_dcbx_admin_mib_update_app_pri(pdev,
                                             app,
                                             &next_free_app_id_entry,
                                             p_classif_elem->condition_field,
                                             traffic_type,
                                             (u8_t)p_classif_elem->action_field);
        }
    }

    app->tc_supported = next_free_app_id_entry;

    return LM_STATUS_SUCCESS;
}
/**
 * This function is for wrapper for the function
 * lm_dcbx_ie_admin_mib_classif and it purpose is for telling if
 * DCBX configuration needs to change but MCP was not update.
 * @param pdev
 * @param app
 * @param classif_params
 * @param classif_change_mcp_not_aware
 * @param flags
 *
 * @return STATIC lm_device_t
 */
STATIC lm_status_t
lm_dcbx_ie_admin_mib_classif_wrapper(IN         lm_device_t                 *pdev,
                                     INOUT      dcbx_app_priority_feature_t *app,
                                     IN const   dcb_classif_params_t        *classif_params,
                                     OUT        u8_t                        *classif_change_mcp_not_aware,
                                     IN const   u32_t                       flags
                                     )
{
    lm_dcbx_indicate_event_t    *indicate_event     = &pdev->dcbx_info.indicate_event;
    lm_status_t                 lm_status           = LM_STATUS_SUCCESS;
    const u16_t                 iscsi_tcp_pri_prev  = indicate_event->iscsi_tcp_pri;

    lm_status = lm_dcbx_ie_admin_mib_classif(pdev,app,classif_params,flags);

    if(iscsi_tcp_pri_prev != indicate_event->iscsi_tcp_pri)
    {
        (*classif_change_mcp_not_aware) = TRUE;
    }

    return lm_status;
}

/**
 * @description
 * Update admin MIB ETS parameters.
 * @param pdev
 * @param admin_ets
 * @param bw_tbl
 * @param pri_pg
 * @param bw_tbl_size
 * @param pri_pg_size
 */
void
lm_dcbx_admin_mib_update_ets_param(
    IN lm_device_t         *pdev,
    IN dcbx_ets_feature_t  *admin_ets,
    IN const u32_t         *pg_bw_tbl,
    IN const u32_t         *pri_pg,
    IN const u8_t          bw_tbl_size,
    IN const u8_t          pri_pg_size  )
{
    u8_t    i = 0;

    DbgBreakIf(DCBX_MAX_NUM_PG_BW_ENTRIES != bw_tbl_size);

    for(i=0; i < DCBX_MAX_NUM_PG_BW_ENTRIES ;i++)
    {
        DCBX_PG_BW_SET(admin_ets->pg_bw_tbl,
                       i,
                       pg_bw_tbl[i]);
    }

    DbgBreakIf(DCBX_MAX_NUM_PRI_PG_ENTRIES != pri_pg_size);

    for(i=0; i < DCBX_MAX_NUM_PRI_PG_ENTRIES; i++)
    {
        DCBX_PRI_PG_SET(admin_ets->pri_pg_tbl,
                        i,
                        pri_pg[i]);
    }
}
/**
 * @description
 *
 * @param pdev
 * @param ets
 * @param ets_params
 *
 * @return lm_status_t
 */
lm_status_t
lm_dcbx_ie_admin_mib_update_runtime_ets(IN          lm_device_t         *pdev,
                                        OUT         dcbx_ets_feature_t  *admin_ets,
                                        IN const    dcb_ets_tsa_param_t *os_ets_params,
                                        IN const    u32_t               flags
                                        )
{
    u32_t pg_bw_tbl[DCBX_MAX_NUM_PG_BW_ENTRIES] = {0};
    u32_t pri_pg[DCBX_MAX_NUM_PRI_PG_ENTRIES] = {0};
    u8_t pri = 0;
    u8_t tc_entry = 0;

    ASSERT_STATIC(DCBX_MAX_NUM_PRI_PG_ENTRIES == DCBX_MAX_NUM_PG_BW_ENTRIES);

    ASSERT_STATIC(ARRSIZE(os_ets_params->priority_assignment_table) ==
                  DCBX_MAX_NUM_PG_BW_ENTRIES);

    ASSERT_STATIC(ARRSIZE(os_ets_params->tc_bw_assignment_table) ==
                  DCBX_MAX_NUM_PRI_PG_ENTRIES);

    ASSERT_STATIC(ARRSIZE(os_ets_params->tsa_assignment_table) ==
                  DCBX_MAX_NUM_PRI_PG_ENTRIES);

    if(0 == GET_FLAGS(flags, DCB_PARAMS_ETS_ENABLED))
    {
        // All pri_pg point to entry 0
        pg_bw_tbl[0] = 100;
    }
    else
    {
        // Prepare parameters from OS to standard config.
        for(pri = 0 ;
            pri < ARRSIZE(os_ets_params->priority_assignment_table);
            pri++)
        {
            tc_entry = os_ets_params->priority_assignment_table[pri];

            if(TSA_ASSIGNMENT_DCB_TSA_STRICT == os_ets_params->tsa_assignment_table[tc_entry])
            {
                // pg_bw_tbl isn't relevant for strict priority
                pri_pg[pri] = DCBX_STRICT_PRI_PG;
            }
            else if(TSA_ASSIGNMENT_DCB_TSA_ETS == os_ets_params->tsa_assignment_table[tc_entry])
            {
                pri_pg[pri]         = tc_entry;
                pg_bw_tbl[tc_entry] = os_ets_params->tc_bw_assignment_table[tc_entry];
            }
            else
            {
                DbgBreakMsg("lm_dcbx_get_ets_ieee_feature parameters are check before "
                            "this should not happen");
                // For retail
                return LM_STATUS_FAILURE;
            }
        }
    }

    // Update MCP.
    lm_dcbx_admin_mib_update_ets_param(
        pdev,
        admin_ets,
        pg_bw_tbl,
        pri_pg,
        ARRSIZE(pg_bw_tbl) ,
        ARRSIZE(pri_pg));

    return LM_STATUS_SUCCESS;
}
/**
 * Update PFC admin MIB
 * @param pdev
 * @param pfc
 * @param pfc_params
 * @param flags
 *
 * @return STATIC lm_status_t
 */
STATIC lm_status_t
lm_dcbx_ie_admin_mib_pfc(IN         lm_device_t         *pdev,
                         INOUT      dcbx_pfc_feature_t  *pfc,
                         IN const   dcb_pfc_param_t     *pfc_params,
                         IN const   u32_t               flags
                         )
{
    if(GET_FLAGS(flags, DCB_PARAMS_PFC_ENABLED))
    {
        pfc->pri_en_bitmap =(u8_t)pfc_params->pfc_enable;
    }
    else
    {
        pfc->pri_en_bitmap = 0;
    }

    return LM_STATUS_SUCCESS;
}
/**
 *
 * @param pdev
 * @param p_admin_mib_offset
 *
 * @return STATIC lm_status_t
 */
STATIC lm_status_t
lm_dcbx_get_admin_mib_offset( IN  lm_device_t         *pdev,
                              OUT u32_t               *p_admin_mib_offset)
{
    u32_t               dcbx_lldp_params_offset         = SHMEM_LLDP_DCBX_PARAMS_NONE;
    const u32_t         dcbx_lldp_params_field_offset   = OFFSETOF(shmem2_region_t,dcbx_lldp_params_offset);
    lm_status_t         lm_status                       = LM_STATUS_SUCCESS;

    lm_dcbx_read_shmem2_mcp_fields( pdev,
                                    dcbx_lldp_params_field_offset,
                                    &dcbx_lldp_params_offset);

    if (SHMEM_LLDP_DCBX_PARAMS_NONE == dcbx_lldp_params_offset)
    {
        DbgBreakMsg("lm_dcbx_read_admin_mib couldn't read mcp offset ");
        return LM_STATUS_FAILURE;
    }

    *p_admin_mib_offset = LM_DCBX_ADMIN_MIB_OFFSET(pdev ,dcbx_lldp_params_offset);

    return lm_status;
}
/**
 *
 * @param pdev
 * @param p_admin_mib
 * @param p_admin_mib_offset
 *
 * @return STATIC lm_status_t
 */
STATIC lm_status_t
lm_dcbx_read_admin_mib( IN  lm_device_t         *pdev,
                        OUT lldp_admin_mib_t    *p_admin_mib,
                        OUT u32_t               *p_admin_mib_offset)
{
    u32_t               i                               = 0;
    u32_t               *buff                           = NULL ;
    lm_status_t         lm_status                       = LM_STATUS_SUCCESS;

    lm_status = lm_dcbx_get_admin_mib_offset( pdev,
                                              p_admin_mib_offset);

    if(LM_STATUS_SUCCESS != lm_status)
    {
        DbgBreakMsg("lm_dcbx_read_admin_mib: lm_dcbx_get_admin_mib_offset failed ");
        return lm_status;
    }

    buff = (u32_t *)p_admin_mib;
    //Read the data first
    for(i=0 ;i < sizeof(lldp_admin_mib_t); i+=4, buff++)
    {
        *buff = REG_RD(pdev,
                      ((*p_admin_mib_offset) + i));
    }

    return lm_status;
}

/**
 * @description
 * Update admin MIN and notify MCP on the changes.
 * @param pdev
 * @param dcb_params
 * @param mf_cfg_offset_value
 *
 * @return STATIC lm_status_t
 */
STATIC lm_status_t
lm_dcbx_ie_admin_mib_updated_runtime(IN         lm_device_t                     *pdev,
                                     IN const   dcb_indicate_event_params_t     *dcb_params,
                                     OUT        u8_t                            *classif_change_mcp_not_aware,
                                     OUT        u8_t                            *is_ets_admin_updated
                                     )
{
    lldp_admin_mib_t    admin_mib           = {0};
    u32_t               i                   = 0;
    u32_t               *buff               = NULL ;
    lm_status_t         lm_status           = LM_STATUS_SUCCESS;
    u32_t               fw_resp             = 0;
    u32_t               admin_mib_offset    = 0;
    u8_t                is_mfw_cfg          = FALSE;
    const u32_t         willing_flags       = DCBX_ETS_WILLING | DCBX_PFC_WILLING | DCBX_APP_WILLING;

    // Use original admin MIB not updated by BACS
    mm_memcpy(&admin_mib, &pdev->dcbx_info.admin_mib_org, sizeof(admin_mib));

    if(GET_FLAGS(dcb_params->flags, DCB_PARAMS_WILLING))
    {
        SET_FLAGS(admin_mib.ver_cfg_flags,willing_flags);
    }
    else
    {
        RESET_FLAGS(admin_mib.ver_cfg_flags,willing_flags);
    }

    lm_status = lm_dcbx_ie_admin_mib_update_runtime_ets(pdev,
                                                        &admin_mib.features.ets,
                                                        &dcb_params->ets_params,
                                                        dcb_params->flags);

    if(LM_STATUS_SUCCESS != lm_status)
    {
        DbgBreakMsg("lm_dcbx_ie_admin_mib_update_runtime_ets function failed ");
    }
    else
    {
        *is_ets_admin_updated = TRUE;
        is_mfw_cfg = TRUE;
    }

    lm_status = lm_dcbx_ie_admin_mib_pfc(pdev,
                                         &admin_mib.features.pfc,
                                         &dcb_params->pfc_params,
                                         dcb_params->flags);

    if(LM_STATUS_SUCCESS != lm_status)
    {
        DbgBreakMsg("lm_dcbx_ie_admin_mib_update_runtime_ets function failed ");
    }
    else
    {
        is_mfw_cfg = TRUE;
    }

    lm_status = lm_dcbx_ie_admin_mib_classif_wrapper(pdev,
                                                     &admin_mib.features.app,
                                                     &dcb_params->classif_params,
                                                     classif_change_mcp_not_aware,
                                                     dcb_params->flags);

    if(LM_STATUS_SUCCESS != lm_status)
    {
        DbgBreakMsg("lm_dcbx_ie_admin_mib_update_runtime_classif function failed ");
    }
    else
    {
        is_mfw_cfg = TRUE;
    }

    if(TRUE == is_mfw_cfg)
    {
        // There is a configuration done to MCP that was done by OS.
        lm_dcbx_config_drv_flags(
            pdev,
            lm_dcbx_drv_flags_set_bit,
            DRV_FLAGS_DCB_MFW_CONFIGURED);

        lm_status = lm_dcbx_get_admin_mib_offset( pdev,
                                                  &admin_mib_offset);

        // Write the data back.
        buff = (u32_t *)&admin_mib;
        for(i=0 ; i< sizeof(lldp_admin_mib_t); i+=4,buff++)
        {
            REG_WR(pdev, (admin_mib_offset + i) , *buff);
        }

        // update MCP
        lm_status = lm_mcp_cmd_send_recieve( pdev,
                                                lm_mcp_mb_header,
                                                DRV_MSG_CODE_DCBX_ADMIN_PMF_MSG,
                                                0,
                                                MCP_CMD_DEFAULT_TIMEOUT,
                                                &fw_resp ) ;

        DbgBreakIf( lm_status != LM_STATUS_SUCCESS );
    }

    return lm_status;
}

/*******************************************************************************
 * Description: Update admin MIB that changes deafault DCBX configuration
 *              "admin_dcbx_enable" and "dcb_enable" are stand alone registry keys
 *              (if present will always be valid and not ignored), for all other
 *              DCBX registry set only if the entire DCBX registry set is present
 *              and differ from 0xFFFFFFFF (invalid value) the DCBX registry
 *              parameters are taken, otherwise the registry key set is ignored.)
 *              (Expect "admin_dcbx_enable" and "dcb_enable")
 * Return:
******************************************************************************/
STATIC void
lm_dcbx_admin_mib_updated_init(lm_device_t * pdev,
                                 u32_t                 mf_cfg_offset_value)
{
    lldp_admin_mib_t admin_mib          = {0};
    u32_t           i                   = 0;
    u8_t            next_free_app_id_entry  = 0; /*used for not predifined entries*/
    u32_t           *buff               = NULL ;
    lm_status_t     lm_status           = LM_STATUS_SUCCESS;
    u32_t           offset                  = 0;

    lm_status = lm_dcbx_read_admin_mib( pdev,
                                        &admin_mib,
                                        &offset);

    if(LM_STATUS_SUCCESS != lm_status)
    {
        DbgBreakMsg(" lm_dcbx_admin_mib_updated_init lm_dcbx_read_admin_mib failed ");
    }
    DbgBreakIf(offset != LM_DCBX_ADMIN_MIB_OFFSET(pdev, mf_cfg_offset_value));

    if(DCBX_CONFIG_INV_VALUE !=
       pdev->params.dcbx_config_params.admin_dcbx_enable)
    {
        if(pdev->params.dcbx_config_params.admin_dcbx_enable)
        {
            SET_FLAGS(admin_mib.ver_cfg_flags,DCBX_DCBX_ENABLED);
        }
        else
        {
            RESET_FLAGS(admin_mib.ver_cfg_flags,DCBX_DCBX_ENABLED);
        }
    }
    lm_status = lm_dcbx_init_check_params_valid(pdev,
                                    (u32_t *)(&(pdev->params.dcbx_config_params.overwrite_settings)),
                                    ((sizeof(pdev->params.dcbx_config_params)-
                                     OFFSETOF(config_dcbx_params_t , overwrite_settings))/sizeof(u32_t)));

    if((LM_STATUS_SUCCESS == lm_status)&&
       (OVERWRITE_SETTINGS_ENABLE == pdev->params.dcbx_config_params.overwrite_settings))
    {
        RESET_FLAGS(admin_mib.ver_cfg_flags,DCBX_CEE_VERSION_MASK);
        admin_mib.ver_cfg_flags |=
            (pdev->params.dcbx_config_params.admin_dcbx_version << DCBX_CEE_VERSION_SHIFT) & DCBX_CEE_VERSION_MASK;

        admin_mib.features.ets.enabled = (u8_t)
            pdev->params.dcbx_config_params.admin_ets_enable;


        admin_mib.features.pfc.enabled =(u8_t)
            pdev->params.dcbx_config_params.admin_pfc_enable;


        //FOR IEEE pdev->params.dcbx_config_params.admin_tc_supported_tx_enable
        if(pdev->params.dcbx_config_params.admin_ets_configuration_tx_enable)
        {
            SET_FLAGS(admin_mib.ver_cfg_flags,DCBX_ETS_CONFIG_TX_ENABLED);
        }
        else
        {
            RESET_FLAGS(admin_mib.ver_cfg_flags,DCBX_ETS_CONFIG_TX_ENABLED);
        }
        //For IEEE admin_ets_recommendation_tx_enable

        if(pdev->params.dcbx_config_params.admin_pfc_tx_enable)
        {
            SET_FLAGS(admin_mib.ver_cfg_flags,DCBX_PFC_CONFIG_TX_ENABLED);
        }
        else
        {
            RESET_FLAGS(admin_mib.ver_cfg_flags,DCBX_PFC_CONFIG_TX_ENABLED);
        }

        if(pdev->params.dcbx_config_params.admin_application_priority_tx_enable)
        {
            SET_FLAGS(admin_mib.ver_cfg_flags,DCBX_APP_CONFIG_TX_ENABLED);
        }
        else
        {
            RESET_FLAGS(admin_mib.ver_cfg_flags,DCBX_APP_CONFIG_TX_ENABLED);
        }


        if(pdev->params.dcbx_config_params.admin_ets_willing)
        {
            SET_FLAGS(admin_mib.ver_cfg_flags,DCBX_ETS_WILLING);
        }
        else
        {
            RESET_FLAGS(admin_mib.ver_cfg_flags,DCBX_ETS_WILLING);
        }
        //For IEEE admin_ets_reco_valid
        if(pdev->params.dcbx_config_params.admin_pfc_willing)
        {
            SET_FLAGS(admin_mib.ver_cfg_flags,DCBX_PFC_WILLING);
        }
        else
        {
            RESET_FLAGS(admin_mib.ver_cfg_flags,DCBX_PFC_WILLING);
        }

        if(pdev->params.dcbx_config_params.admin_app_priority_willing)
        {
            SET_FLAGS(admin_mib.ver_cfg_flags,DCBX_APP_WILLING);
        }
        else
        {
            RESET_FLAGS(admin_mib.ver_cfg_flags,DCBX_APP_WILLING);
        }

        lm_dcbx_admin_mib_update_ets_param(
            pdev,
            &admin_mib.features.ets,
            pdev->params.dcbx_config_params.admin_configuration_bw_percentage,
            pdev->params.dcbx_config_params.admin_configuration_ets_pg,
            ARRSIZE(pdev->params.dcbx_config_params.admin_configuration_bw_percentage) ,
            ARRSIZE(pdev->params.dcbx_config_params.admin_configuration_ets_pg));

        //For IEEE admin_recommendation_bw_percentage
        //For IEEE admin_recommendation_ets_pg
        admin_mib.features.pfc.pri_en_bitmap = (u8_t)pdev->params.dcbx_config_params.admin_pfc_bitmap;

        for(i = 0; i<ARRSIZE(pdev->params.dcbx_config_params.admin_priority_app_table); i++)
        {
            if(pdev->params.dcbx_config_params.admin_priority_app_table[i].valid)
            {
                lm_dcbx_admin_mib_update_app_pri(pdev,
                                                 &admin_mib.features.app,
                                                 &next_free_app_id_entry,
                                                 (u16_t)pdev->params.dcbx_config_params.admin_priority_app_table[i].app_id,
                                                 (u8_t)pdev->params.dcbx_config_params.admin_priority_app_table[i].traffic_type,
                                                 (u8_t)pdev->params.dcbx_config_params.admin_priority_app_table[i].priority);
            }
        }

        admin_mib.features.app.tc_supported = next_free_app_id_entry;
        admin_mib.features.app.default_pri = (u8_t)pdev->params.dcbx_config_params.admin_default_priority;

        // There is a configuration set by BACS.
        lm_dcbx_config_drv_flags(
                   pdev,
                   lm_dcbx_drv_flags_set_bit,
                   DRV_FLAGS_DCB_MFW_CONFIGURED);

    }
    else
    {
        if(OVERWRITE_SETTINGS_ENABLE == pdev->params.dcbx_config_params.overwrite_settings)
        {
            pdev->params.dcbx_config_params.overwrite_settings = OVERWRITE_SETTINGS_INVALID;
        }

    }

    //Write the data.
    buff = (u32_t *)&admin_mib;
    for(i=0 ; i < sizeof(lldp_admin_mib_t); i+=4,buff++)
    {
        REG_WR(pdev, (offset + i) , *buff);
    }
}
/*******************************************************************************
 * Description: Update LLDP that changes deafault LLDP configuration.
 *              Only if the entire LLDP registry set is present and differ from
 *              0xFFFFFFFF (invalid value) the LLDP registry parameters are taken,
 *              otherwise the registry keys are ignored.
 * Return:
 *              LM_STATUS_FAILURE - All/Some of the parameters could not be read.
 *              LM_STATUS_SUCCESS - All the MIBs where read successfully.
******************************************************************************/
STATIC void
lm_dcbx_init_lldp_updated_params(struct _lm_device_t * pdev,
                                 u32_t                 mf_cfg_offset_value)
{

    lldp_params_t   lldp_params = {0};
    u32_t           i           = 0;
    u32_t           *buff       = NULL ;
    lm_status_t     lm_status   = LM_STATUS_SUCCESS;
    u32_t           offest      = mf_cfg_offset_value +
        PORT_ID(pdev) * sizeof(lldp_params_t);

    lm_status = lm_dcbx_init_check_params_valid(pdev,
                                    (u32_t *)(&(pdev->params.lldp_config_params)),
                                    (sizeof(pdev->params.lldp_config_params)/sizeof(u32_t)));

    if((LM_STATUS_SUCCESS == lm_status)&&
       (OVERWRITE_SETTINGS_ENABLE == pdev->params.lldp_config_params.overwrite_settings))
    {
        //Read the data first
        buff = (u32_t *)&lldp_params;
        for(i=0 ;i<sizeof(lldp_params_t); i+=4,buff++)
        {
            *buff = REG_RD(pdev,
                          (offest+ i));
        }
        lldp_params.msg_tx_hold             = (u8_t)pdev->params.lldp_config_params.msg_tx_hold;
        lldp_params.msg_fast_tx_interval    = (u8_t)pdev->params.lldp_config_params.msg_fast_tx;
        lldp_params.tx_crd_max              = (u8_t)pdev->params.lldp_config_params.tx_credit_max;
        lldp_params.msg_tx_interval         = (u8_t)pdev->params.lldp_config_params.msg_tx_interval;
        lldp_params.tx_fast                 = (u8_t)pdev->params.lldp_config_params.tx_fast;

        //Write the data.
        buff = (u32_t *)&lldp_params;
        for(i=0 ;i<sizeof(lldp_params_t); i+=4,buff++)
        {
            REG_WR(pdev, (offest+ i) , *buff);//Change to write
        }
    }
    else
    {
        if(OVERWRITE_SETTINGS_ENABLE == pdev->params.lldp_config_params.overwrite_settings)
        {
            pdev->params.lldp_config_params.overwrite_settings = OVERWRITE_SETTINGS_INVALID;
        }

    }

}
/*******************************************************************************
 * Description:
 *              Allocate physical memory for DCBX start ramrod
 *
 * Return:
******************************************************************************/
lm_status_t
lm_dcbx_get_pfc_fw_cfg_phys_mem(
    IN struct _lm_device_t  *pdev,
    IN const u8_t           lm_cli_idx)
{
    if (CHK_NULL(pdev->dcbx_info.pfc_fw_cfg_virt))
    {
        pdev->dcbx_info.pfc_fw_cfg_virt =
            mm_alloc_phys_mem(pdev,
                              sizeof(struct flow_control_configuration),
                              &pdev->dcbx_info.pfc_fw_cfg_phys,
                              0,
                              lm_cli_idx);

        if CHK_NULL(pdev->dcbx_info.pfc_fw_cfg_virt)
        {
            return LM_STATUS_RESOURCE;
        }
    }

    return LM_STATUS_SUCCESS;
}
/**
 * @description
 *  Called to clean dcbx info after D3
 * @param pdev
 *
 * @return lm_status_t
 */
lm_status_t
lm_dcbx_init_info(
    IN lm_device_t *pdev
    )
{
    pdev->dcbx_info.is_enabled   = FALSE;

    return LM_STATUS_SUCCESS;
}
/*******************************************************************************
 * Description:
 *
 *
 * Return:
******************************************************************************/
lm_status_t
lm_dcbx_free_resc(
    IN struct _lm_device_t *pdev
    )
{
    pdev->dcbx_info.pfc_fw_cfg_virt = NULL;
    pdev->dcbx_info.is_enabled      = FALSE;
    return LM_STATUS_SUCCESS;
}
/**
 * lm_dcbx_ie_init_event_params
 * @param pdev
 * @param params
 * @param classif_table_size
 */
void
lm_dcbx_ie_init_event_params(
    IN struct _lm_device_t          *pdev,
    IN dcb_indicate_event_params_t  *params,
    IN const u32_t                  classif_table_size)
{
    params->flags = 0;

    mm_mem_zero(&params->ets_params, sizeof(params->ets_params));

    mm_mem_zero(&params->pfc_params, sizeof(params->pfc_params));

    params->classif_params.classif_version = DCB_CLASSIFI_VER_SIMPLE_ELEM;
    params->classif_params.num_classif_elements = 0;

    if((NULL != params->classif_params.classif_table) &&
       classif_table_size)
    {
        mm_mem_zero( params->classif_params.classif_table,
                     classif_table_size);
    }
}
/**
 * lm_dcbx_ie_init_params
 *
 * @param pdev
 * @param b_only_setup
 */
void
lm_dcbx_ie_init_params(
    IN struct _lm_device_t  *pdev,
    IN const u8_t           b_only_setup)
{
    lm_dcbx_indicate_event_t *indicate_event = &pdev->dcbx_info.indicate_event;

    if (TRUE == b_only_setup)
    {
        lm_dcbx_ie_init_event_params(pdev,
                                     &indicate_event->local_params,
                                     LM_DCBX_IE_CLASSIF_TABLE_ALOC_SIZE_LOCAL);

        lm_dcbx_ie_init_event_params(pdev,
                                     &indicate_event->remote_params,
                                     LM_DCBX_IE_CLASSIF_TABLE_ALOC_SIZE_REMOTE);

        lm_dcbx_ie_init_event_params(pdev,
                                     &indicate_event->dcb_params_given_dbg,
                                     LM_DCBX_IE_CLASSIF_TABLE_ALOC_SIZE_DBG);
    }
    else
    {
        mm_mem_zero(indicate_event, sizeof(lm_dcbx_indicate_event_t));
        indicate_event->lm_cli_idx = LM_CLI_IDX_MAX;
    }

    indicate_event->ets_config_state = lm_dcbx_ets_config_state_cee;

    indicate_event->is_ets_ieee_params_os_valid = FALSE;
    mm_mem_zero(&indicate_event->ets_ieee_params_os ,
                sizeof(indicate_event->ets_ieee_params_os));

    indicate_event->ets_ieee_config_state = lm_dcbx_ets_ieee_config_not_valid;
    mm_mem_zero(&indicate_event->ets_ieee_params_config ,
                sizeof(indicate_event->ets_ieee_params_config));

    indicate_event->iscsi_tcp_pri = LM_DCBX_ILLEGAL_PRI;

    indicate_event->dcb_current_oper_state_bitmap   = 0;

}
/*******************************************************************************
 * Description:
 *              Allocate physical memory for DCBX start ramrod
 *
 * Return:
******************************************************************************/
lm_status_t
lm_dcbx_init_params(
    IN struct   _lm_device_t  *pdev,
    IN const    u8_t           b_only_setup)
{
    lm_status_t lm_status                       = LM_STATUS_SUCCESS;
    u8_t        lm_cli_idx      = LM_CLI_IDX_MAX;
    u32_t       dummy_offset    = 0;

    // All priorities are mapped by default to zero
    mm_mem_zero(pdev->dcbx_info.pri_to_cos, sizeof(pdev->dcbx_info.pri_to_cos));

    mm_mem_zero(&(pdev->params.dcbx_port_params), sizeof(pdev->params.dcbx_port_params));

    pdev->dcbx_info.dcbx_update_lpme_task_state = DCBX_UPDATE_TASK_STATE_FREE;
    pdev->dcbx_info.is_dcbx_neg_received        = FALSE;

    lm_dcbx_ie_init_params(pdev, b_only_setup);

    // Should not be used in MF this is only a pach until MCP will know how to return to default
    lm_status = lm_dcbx_read_admin_mib( pdev,
                                        &pdev->dcbx_info.admin_mib_org,
                                        &dummy_offset);

    if(LM_STATUS_SUCCESS != lm_status)
    {
        DbgBreakMsg(" lm_dcbx_admin_mib_updated_init lm_dcbx_read_admin_mib failed ");
        return lm_status;
    }

    if(FALSE == b_only_setup)
    {
        lm_status = lm_dcbx_get_pfc_fw_cfg_phys_mem(pdev, lm_cli_idx);
        if(LM_STATUS_SUCCESS != lm_status )
        {
            DbgBreakMsg("lm_dcbx_init_params : resource ");
            pdev->dcbx_info.dcbx_error |= DCBX_ERROR_RESOURCE;
            return lm_status;
        }
    }


    return lm_status;
}

/**
 * @description
 * Set in a shared port memory place if DCBX completion was
 * received. Function is needed for PMF migration in order to
 * synchronize the new PMF that DCBX results has ended.
 * @param pdev
 * @param is_completion_recv
 */
void
lm_dcbx_config_drv_flags(
    IN          lm_device_t *pdev,
    IN const    lm_dcbx_drv_flags_cmd_t drv_flags_cmd,
    IN const    u32_t                   bit_drv_flags)
{
    const   u32_t drv_flags_offset = OFFSETOF(shmem2_region_t,drv_flags);
    u32_t   drv_flags = 0;
    lm_status_t     lm_status           = LM_STATUS_SUCCESS;
    const u8_t      port                = PORT_ID(pdev);
    u32_t           port_drv_flags      = DRV_FLAGS_FILED_BY_PORT(bit_drv_flags, port);

    if(!IS_PMF(pdev))
    {
        DbgBreakMsg("lm_dcbx_check_drv_flags error only PMF can access this field ");
        return;
    }

    lm_status = lm_hw_lock(pdev, HW_LOCK_RESOURCE_DRV_FLAGS, TRUE);

    if(LM_STATUS_SUCCESS != lm_status)
    {
        DbgBreakMsg("lm_dcbx_set_comp_recv_on_port_bit lm_hw_lock failed ");
        return;
    }

    lm_dcbx_read_shmem2_mcp_fields(pdev,
                                   drv_flags_offset,
                                   &drv_flags);

   switch(drv_flags_cmd)
    {
   case lm_dcbx_drv_flags_set_bit:
        SET_FLAGS(drv_flags,port_drv_flags);
        break;
    case lm_dcbx_drv_flags_reset_bit:
        RESET_FLAGS(drv_flags,port_drv_flags);
        break;
    case lm_dcbx_drv_flags_reset_flags:
        port_drv_flags = DRV_FLAGS_GET_PORT_MASK(port);

        RESET_FLAGS(drv_flags,port_drv_flags);
        break;
    default:
        DbgBreakMsg("lm_dcbx_set_comp_recv_on_port_bit : illegal drv_flags_cmd  ");
        return;
    };

    lm_dcbx_write_shmem2_mcp_fields(pdev,
                                   drv_flags_offset,
                                   drv_flags);

    lm_hw_unlock(pdev, HW_LOCK_RESOURCE_DRV_FLAGS);
}
/**
 * @description
 * Function is needed for PMF migration in order to synchronize
 * the new PMF that DCBX results has ended.
 * @param pdev
 *
 * @return u8_t
 * This function returns TRUE if DCBX completion received on
 * this port
 */
u8_t
lm_dcbx_check_drv_flags(
    IN          lm_device_t *pdev,
    IN const       u32_t       flags_bits_to_check)
{
    const   u32_t drv_flags_offset = OFFSETOF(shmem2_region_t,drv_flags);
    u32_t   drv_flags = 0;
    u8_t        is_flag_set         = FALSE;
    const u8_t  port                = PORT_ID(pdev);
    const u32_t port_flags_to_check = DRV_FLAGS_FILED_BY_PORT(flags_bits_to_check, port);

    if(!IS_PMF(pdev))
    {
        DbgBreakMsg("lm_dcbx_check_drv_flags error only PMF can access this field ");
        return FALSE;
    }

    lm_dcbx_read_shmem2_mcp_fields(pdev,
                                   drv_flags_offset,
                                   &drv_flags);

    if(GET_FLAGS(drv_flags, port_flags_to_check))
    {
        is_flag_set = TRUE;
    }

    return is_flag_set;
}
/**
 * @description
 * 1. Make sure all the DCBX init parameters for this function
 * are correct.
 * 2. Register a set DCBX params in order to let the new PMF
 * migration function to know the current DCBX settings and that
 * the pdev varibales will mach the HW configuration.
 * for example in MF when DCBX is configured to static
 * configuration ELINK_FEATURE_CONFIG_PFC_ENABLED is set in pdev
 * (we get only one interrupt)of only the original
 * function.After PMF migration the first link updated will
 * cause the PFC state to be incompatible.The function that
 * become PMF doesn't have ELINK_FEATURE_CONFIG_PFC_ENABLED set
 * @param pdev
 */
void
lm_dcbx_pmf_migration(
    IN struct _lm_device_t *pdev)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;
    const u8_t is_completion_received_on_port =
        lm_dcbx_check_drv_flags(pdev, DRV_FLAGS_DCB_CONFIGURED);

    DbgBreakIf(TRUE != IS_DCB_ENABLED(pdev));

    // We called lm_dcbx_init_params at the beginning
    // verify all the parameters are correct and that there is no error.
    DbgBreakIf(FALSE != pdev->dcbx_info.is_dcbx_neg_received);
    DbgBreakIf(DCBX_UPDATE_TASK_STATE_FREE != pdev->dcbx_info.dcbx_update_lpme_task_state);
    DbgBreakIf(CHK_NULL(pdev->dcbx_info.pfc_fw_cfg_virt));

    // for this function the only error possibole is that the pfc_fw_cfg_virt wasn't allocated.
    if((DCBX_ERROR_NO_ERROR != pdev->dcbx_info.dcbx_error) ||
        (FALSE == IS_MULTI_VNIC(pdev)))
    {
        DbgBreakMsg("lm_dcbx_init : lm_mcp_cmd_send_recieve failed ");
        return;
    }

    // If we received the DCBX parameters before on this port the new PMF
    // will read the current DCBX parameters
    if(FALSE == is_completion_received_on_port)
    {
        // DCBX parameters were not received before
        return;
    }
    // Register a set params in order to let the new PMF migration
    // function to know the current DCBX settings.
    // A side effect of this function be to set the DCBX parameters again,
    // but this is a must because in case of an error(or if we have an
    // innterrupt from MCP that eas not handled) the seetings that are
    // currently on the chip may not be equale to the local settings.
    lm_status = MM_REGISTER_LPME(pdev,
                                 lm_dcbx_init_lpme_set_params,
                                 TRUE,
                                 FALSE);// DCBX sends ramrods

    if (LM_STATUS_SUCCESS != lm_status)
    {
        pdev->dcbx_info.dcbx_error |= DCBX_ERROR_REGISTER_LPME;
        // No rollback
        // Problem because if DCBX interrupt isn't receive the chip will be
        // stuck beacuse QM queues are stopped.
        // For release version this will call DCBX start that will restart QM queues.
        DbgBreakMsg("lm_dcbx_int : The chip QM queues are stuck until an interrupt from MCP");
    }
}
/**
 * First check if DCBX is enabled on port.Old MCP that doesn't
 * support the field dcbx_en should not be used in 4 port
 * because if one port supports DCBX but the other does't,
 * driver can't tell the difference according to
 * dcbx_lldp_params_offset.(dcbx_lldp_params_offset is valid if
 * one port is enabled)
 *
 * After check that dcbx_lldp_params_offset is valid for
 * backward compatibility(until 4 port).
 * If dcbx_en isn't zero dcbx_lldp_params_offset must be vaild.
 * @param pdev
 *
 * @return u8_t
 */
u8_t
lm_dcbx_port_enable_mcp(IN lm_device_t *pdev)
{
    u32_t       lldp_params_offset      = SHMEM_LLDP_DCBX_PARAMS_NONE;
    const u32_t mcp_lldp_params_offset  = OFFSETOF(shmem2_region_t,dcbx_lldp_params_offset);
    const u8_t  port                    = PORT_ID(pdev);
    const u32_t dcbx_en_offset          = OFFSETOF(shmem2_region_t,dcbx_en[port]);
    u32_t       read_dcbx_en            = 0;

    if(LM_SHMEM2_HAS(pdev, dcbx_en[port]))
    {
        LM_SHMEM2_READ(pdev, dcbx_en_offset, &read_dcbx_en);

        if(0 == read_dcbx_en)
        {
            return FALSE;
        }
    }
    else
    {
        DbgMessage(pdev, FATAL, "lm_dcbx_port_enable_mcp: Old MCP a new driver requires"
                              "a new MFW for knowing if DCBX is enabled in 4 port mode.\n");
    }

    lm_dcbx_read_shmem2_mcp_fields( pdev,
                                    mcp_lldp_params_offset,
                                    &lldp_params_offset);

    DbgBreakIf((0 != read_dcbx_en) &&
               (SHMEM_LLDP_DCBX_PARAMS_NONE == lldp_params_offset));

    return (SHMEM_LLDP_DCBX_PARAMS_NONE != lldp_params_offset);
}
/*******************************************************************************
 * Description:
 *              The PMF function starts the DCBX negotiation after sending the
 *              MIB DRV_MSG_LLDP_PMF_MSG with new LLDP/DCBX configurations if available.
 *              The PMF will call the function dcbx_stop_Hw_TX () that will ensure
 *              that no traffic can be sent. (The driver will send a ramrod to the
 *              FW that will stop all the queues in the QM)
 *              After 1 second (a timer elapsed) if DCBX negotiation didn't end
 *              (pdev.vars.dcbx_neg_received =0) and link is up a WI lm_dcbx_resume_TX()
 *              is scheduled .
 *              In WI read the configuration from local MIB and set DCBX parameters
 *              to the value in local_MIB.
 *
 * Return:
******************************************************************************/
void
lm_dcbx_init(IN struct _lm_device_t *pdev,
             IN const u8_t          b_only_setup)
{
    u32_t       fw_resp                     = 0 ;
    lm_status_t lm_status                   = LM_STATUS_FAILURE ;
    u32_t       dcbx_lldp_params_offset     = SHMEM_LLDP_DCBX_PARAMS_NONE;
    const u32_t mcp_dcbx_lldp_params_offset = OFFSETOF(shmem2_region_t,dcbx_lldp_params_offset);
    u8_t is_mfw_config = FALSE;

    DbgBreakIf(FALSE != IS_DCB_ENABLED(pdev));

    if(IS_DCB_SUPPORTED(pdev))
    {// DCBX is supported on E1H. E2 only in 2 port mode.
        if (lm_dcbx_port_enable_mcp(pdev))
        {// DCBX supported in MCP

            lm_status = lm_dcbx_init_params(pdev, b_only_setup);
            if(LM_STATUS_SUCCESS != lm_status)
            {// If dcbx pfc_fw_cfg could not be allocated DCBX isn't supported
                return;
            }

            if(IS_PMF_ORIGINAL(pdev))
            {//Only the PMF starts and handles
                pdev->dcbx_info.is_enabled = TRUE;

                lm_dcbx_read_shmem2_mcp_fields( pdev,
                                                mcp_dcbx_lldp_params_offset,
                                                &dcbx_lldp_params_offset);

                DbgBreakIf(SHMEM_LLDP_DCBX_PARAMS_NONE == dcbx_lldp_params_offset);

                lm_dcbx_init_lldp_updated_params( pdev,
                                                     dcbx_lldp_params_offset);

                lm_dcbx_admin_mib_updated_init( pdev,
                                                     dcbx_lldp_params_offset);

                lm_status = lm_mcp_cmd_send_recieve( pdev,
                                                     lm_mcp_mb_header,
                                                     DRV_MSG_CODE_DCBX_ADMIN_PMF_MSG,
                                                     0,
                                                     MCP_CMD_DEFAULT_TIMEOUT,
                                                     &fw_resp ) ;

                if( lm_status != LM_STATUS_SUCCESS )
                {
                    pdev->dcbx_info.dcbx_error |= DCBX_ERROR_MCP_CMD_FAILED;
                    DbgBreakMsg("lm_dcbx_init : lm_mcp_cmd_send_recieve failed ");
                    return;
                }
                is_mfw_config = lm_dcbx_check_drv_flags(pdev, DRV_FLAGS_DCB_MFW_CONFIGURED);

                if(TRUE == is_mfw_config)
                {
                    lm_status = MM_REGISTER_LPME(pdev,
                             lm_dcbx_init_lpme_set_params,
                             TRUE,
                             FALSE);// DCBX sends ramrods

                    if (LM_STATUS_SUCCESS != lm_status)
                    {
                        pdev->dcbx_info.dcbx_error |= DCBX_ERROR_REGISTER_LPME;
                        // No rollback
                        // Problem because if DCBX interrupt isn't receive the chip will be
                        // stuck beacuse QM queues are stopped.
                        // For release version this will call DCBX start that will restart QM queues.
                        DbgBreakMsg("lm_dcbx_int : The chip QM queues are stuck until an interrupt from MCP");
                    }
                }
            }//PMF Original
            else
            {
                pdev->dcbx_info.is_enabled = TRUE;
                if(IS_PMF_MIGRATION(pdev))
                {
                    // Send an attention on this Function.
                    // We create an interrupt on this function to make sure we will wake up another time
                    // to send the MCP ACK.
                    LM_GENERAL_ATTN_INTERRUPT_SET(pdev,FUNC_ID(pdev));
                }
            }
        }// DCBX supported in MCP
    } //DCBX enabled.
}
/*******************************************************************************
 * Description:
 *
 * Return:
 ******************************************************************************/
static void
lm_dcbx_init_set_params_invalid(u32_t       * buff_check,
                                u32_t       buff_size)
{
    u32_t i=0;
    for (i=0 ; i < buff_size ; i++,buff_check++)
    {
        *buff_check = DCBX_CONFIG_INV_VALUE;
    }
}
/**
 * @description
 * Init dcbx init default params this function should be called
 * once before any other DCBX function is called.
 * @param pdev
 */
void
lm_dcbx_init_default_params(lm_device_t *pdev)
{
    // Init dcbx and lldp params

    lm_dcbx_init_set_params_invalid((u32_t *)(&(pdev->params.lldp_config_params)),
                                    (sizeof(pdev->params.lldp_config_params)/sizeof(u32_t)));

    lm_dcbx_init_set_params_invalid((u32_t *)(&(pdev->params.dcbx_config_params)),
                                    (sizeof(pdev->params.dcbx_config_params)/sizeof(u32_t)));

    pdev->params.dcbx_config_params.dcb_enable        = 1; //DCB by default is disabled
    pdev->params.dcbx_config_params.admin_dcbx_enable = 1; //DCBX by default is enabled

    if((!(CHIP_IS_E1x(pdev))) &&
        IS_PFDEV(pdev))
    {
        pdev->params.b_dcb_indicate_event = TRUE;
}
}

/**********************end DCBX INIT FUNCTIONS**************************************/

/**********************start DCBX UPDATE FUNCTIONS**************************************/
/*******************************************************************************
 * Description:
 *              Any DCBX update will be treated as a runtime change.
 *              Runtime changes can take more than 1 second and can't be handled
 *              from DPC.
 *              When the PMF detects a DCBX update it will schedule a WI that
 *              will handle the job.
 *              This function should be called in PASSIVE IRQL (Currently called from
 *              DPC) and in mutual exclusion any acces to lm_dcbx_stop_HW_TX
 *              /lm_dcbx_resume_HW_TX.
 *
 * Return:
******************************************************************************/
void
lm_dcbx_update_lpme_set_params(struct _lm_device_t *pdev)
{
    u32_t offset        = 0;
    u32_t drv_status    = 0;
    lm_status_t lm_status = LM_STATUS_SUCCESS;

    offset = OFFSETOF(shmem_region_t, func_mb[FUNC_MAILBOX_ID(pdev)].drv_status) ;

    // drv_status
    LM_SHMEM_READ(pdev,
                  offset,
                  &drv_status);

    if((IS_PMF(pdev))&&
       (GET_FLAGS( drv_status, DRV_STATUS_DCBX_NEGOTIATION_RESULTS))&&
       (DCBX_UPDATE_TASK_STATE_SCHEDULE == pdev->dcbx_info.dcbx_update_lpme_task_state))
    {
        // No lock is needed to be taken because lm_dcbx_set_params is only called from a WI
        lm_status = lm_dcbx_set_params_and_read_mib(pdev,
                                                    FALSE,
                                                    TRUE);

        DbgBreakIf(LM_STATUS_SUCCESS != lm_status);

        pdev->dcbx_info.dcbx_update_lpme_task_state =
            DCBX_UPDATE_TASK_STATE_HANDLED;
        // Send an attention on this Function.
        // We create an interrupt on this function to make sure we will wake up another time
        // to send the MCP ACK.
        LM_GENERAL_ATTN_INTERRUPT_SET(pdev,FUNC_ID(pdev));
    }
    else
    {
        DbgBreakMsg("lm_dcbx_update_lpme_set_params error");
    }
}
/**********************end DCBX UPDATE FUNCTIONS**************************************/

/**
 * @description
 * Enable indicate event to upper layer
 * @param pdev
 */
void lm_dcbx_ie_update_state(
    INOUT       struct _lm_device_t * pdev,
    IN const    u8_t                is_en)
{
    pdev->dcbx_info.is_indicate_event_en = is_en;
}
/**
 * @description
 *
 * @param pdev
 *
 * @return u8
 */
u8_t lm_dcbx_cos_max_num(
    INOUT   const struct _lm_device_t * pdev)
{
    u8_t cos_max_num = 0;

    if(CHIP_IS_E3B0(pdev))
    {
        cos_max_num = DCBX_COS_MAX_NUM_E3B0;
    }
    else
    {
        cos_max_num = DCBX_COS_MAX_NUM_E2E3A0;
    }

    return cos_max_num;
}
/**
 * @description
 * Validate the PFC parameters that were received can be
 * configured. The parameters will later be configured in WI.
 * @param pdev
 * @param pfc_params
 * @param dcbx_neg_res_offset - After the offset was read
 *                            correctly from Shmem.
 *
 * @return STATIC lm_status_t
 */
STATIC lm_status_t
lm_dcbx_ie_runtime_params_updated_validate_pfc(
    INOUT       lm_device_t     *pdev,
    IN const    dcb_pfc_param_t *pfc_params
    )
{
    lm_status_t         lm_status           = LM_STATUS_SUCCESS;

    if(FALSE == pdev->dcbx_info.is_indicate_event_en)
    {
        DbgBreakMsg("lm_dcbx_runtime_params_updated_validate_pfc called but is_indicate_event_en is false");
        return LM_STATUS_FAILURE;
    }

    return lm_status;
}
/**
 * @description
 * Validate the ETS parameters that were received can be
 * configured. The parameters will later be configured in WI.
 * @param pdev
 * @param ets_params
 *
 * @return STATIC lm_status_t
 */
STATIC lm_status_t
lm_dcbx_ie_params_updated_validate_ets(
    INOUT       lm_device_t         *pdev,
    IN const    dcb_ets_tsa_param_t *ets_params
    )
{
    lm_status_t lm_status   = LM_STATUS_SUCCESS;
    const u8_t  cos_max_num = lm_dcbx_cos_max_num(pdev);
    u8_t        i           = 0;
    u8_t        tc_entry    = 0;
    u8_t        tc_entry_bitmap = 0;
    u8_t        tc_used_bitmap  = 0;
    u8_t        num_of_tc_used  = 0;

    if(cos_max_num < ets_params->num_traffic_classes )
    {
        DbgBreakMsg("lm_dcbx_runtime_params_updated_validate_ets num_traffic_classes can't be larger"
                    "than cos_max_num");
        return LM_STATUS_FAILURE;
    }

    if(LM_DCBX_IE_IS_ETS_DISABLE(ets_params->num_traffic_classes))
    {
        DbgMessage(pdev, INFORM, "ETS is disabled other ETS paramters not checked \n");

        return LM_STATUS_SUCCESS;
    }

    for(i = 0; i < ARRSIZE(ets_params->priority_assignment_table); i++)
    {
        //cos_max_num
        tc_entry = ets_params->priority_assignment_table[i];
        if(tc_entry >= DCBX_MAX_NUM_PG_BW_ENTRIES)
        {
            DbgBreakMsg("lm_dcbx_runtime_params_updated_validate_ets a tc_entry can't be larger"
                        "than the number of TC supported");
            return LM_STATUS_FAILURE;
        }

        tc_entry_bitmap = (1 << tc_entry);
        // Count the number of TC entries given and fill the appropriate COS entry.
        if(0 == (tc_used_bitmap & tc_entry_bitmap))
        {
            // New TC add it to the bitmask
            tc_used_bitmap |= tc_entry_bitmap;
            num_of_tc_used++;
            DbgBreakIf(cos_max_num < num_of_tc_used);
        }


        switch(ets_params->tsa_assignment_table[tc_entry])
        {
        case TSA_ASSIGNMENT_DCB_TSA_STRICT:
        case TSA_ASSIGNMENT_DCB_TSA_ETS: //fall through
            // Entry can be handled by VBD
            break;

        case TSA_ASSIGNMENT_DCB_TSA_CBS:
            DbgBreakMsg("TSA_ASSIGNMENT_DCB_TSA_CBS value isn't supported by VBD");
            return LM_STATUS_INVALID_PARAMETER;
            break;
        default:
            DbgBreakMsg("illegal value for tsa_assignment_table");
            break;
        }
    }

    if(ets_params->num_traffic_classes < num_of_tc_used )
    {
        if(0 == pdev->params.lm_dcb_dont_break_bad_oid)
        {
            DbgBreakMsg("OS gave more TC than mentioned in num_traffic_classes");
        }
        return LM_STATUS_INVALID_PARAMETER;
    }

    return lm_status;
}
/**
 * @description
 * For classification entries that will be supported are
 * returned with the flag DCB_CLASSIF_ENFORCED_BY_VBD set.
 *
 * Set the flag in classification entries that do not conflict
 * with the remote settings and is supported by the miniport,
 * and clear the flag in classification entries that do conflict
 * with remote settings or is not supported by the miniport.
 * @param pdev
 * @param classif_params
 * @param mcp_dcbx_neg_res_offset
 *
 * @return STATIC lm_status_t
 */
STATIC lm_status_t
lm_dcbx_ie_classif_entries_validate_and_set_enforced(
    IN      struct _lm_device_t             *pdev,
    INOUT       dcb_classif_params_t    *classif_params)
{
    dcb_classif_elem_t      *p_classif_elem = classif_params->classif_table;
    lm_status_t             lm_status       = LM_STATUS_SUCCESS;
    u8_t                    i               = 0;

    if(DCB_CLASSIFI_VER_SIMPLE_ELEM != classif_params->classif_version)
    {
        DbgBreakMsg("lm_dcbx_runtime_params_updated_en_classif_entries : classif_version not supported ");
        return LM_STATUS_FAILURE;
    }

    for(i = 0; i < classif_params->num_classif_elements; i++,p_classif_elem++)
    {

        if(NULL == p_classif_elem)
        {
            DbgBreakMsg("lm_dcbx_runtime_params_updated_en_classif_entries : p_classif_elem is null ");
            return LM_STATUS_FAILURE;
        }

        if(DCB_ACTION_PRIORITY != p_classif_elem->action_selector)
        {
            // VBD only supports condition_selector that is based on priority
            continue;
        }
        switch(p_classif_elem->condition_selector)
        {
        case DCB_CONDITION_DEFAULT:
            // Must be the first entry
            DbgBreakIf(0 != i);
            break;

        case DCB_CONDITION_TCP_PORT:
        case DCB_CONDITION_TCP_OR_UDP_PORT://Fall through
            if(TCP_PORT_ISCSI == p_classif_elem->condition_field)
            {
                SET_FLAGS(p_classif_elem->flags, DCB_CLASSIF_ENFORCED_BY_VBD);
            }
            break;

        case DCB_CONDITION_ETHERTYPE:
            if(ETH_TYPE_FCOE == p_classif_elem->condition_field)
            {
                SET_FLAGS(p_classif_elem->flags, DCB_CLASSIF_ENFORCED_BY_VBD);
            }
            break;

        case DCB_CONDITION_RESERVED:
        case DCB_CONDITION_UDP_PORT://Fall through
        case DCB_CONDITION_NETDIRECT_PORT://Fall through
            //Not supported by VBD
            break;
        case DCB_CONDITION_MAX:
        default:
            DbgBreakMsg("lm_dcbx_runtime_params_updated_en_classif_entries: illegal entry ");
            break;
        }
    }
    return lm_status;
}
/**
 * @description
 * The function will allocate room for the calcification entries
 * copy the miniport buffer + local MIB.
 * The function will also copy all valid entries to the
 * beggining classif_params_copy->classif_table
 * @param pdev
 * @param classif_params
 * @param classif_params_copy
 * @param lm_cli_idx
 *
 * @return STATIC lm_status_t
 */
STATIC lm_status_t
lm_dcbx_ie_copy_alloc_classif_buffer(
    INOUT       lm_device_t                     *pdev,
    IN const    dcb_classif_params_t            *classif_params,
    OUT         dcb_classif_params_t            *classif_params_copy,
    IN const    u8_t                            lm_cli_idx
    )
{
    dcb_classif_elem_t  *p_classif_elem         = NULL;
    lm_status_t         lm_status               = LM_STATUS_SUCCESS;
    u8_t                i                       = 0;

    DbgBreakIf(lm_cli_idx != pdev->dcbx_info.indicate_event.lm_cli_idx);


    if(classif_params->num_classif_elements)
    {
        // The total size allocated
        classif_params_copy->classif_table =
            mm_rt_alloc_mem(pdev,
                            LM_DCBX_IE_CLASSIF_ENTRIES_TO_ALOC_SIZE(classif_params->num_classif_elements),
                            pdev->dcbx_info.indicate_event.lm_cli_idx);

        if(CHK_NULL(classif_params_copy->classif_table))
        {
            DbgBreakMsg(" lm_dcbx_ie_copy_alloc_classif_buffer allocation failure ");
            return LM_STATUS_RESOURCE;
        }

        classif_params_copy->num_classif_elements = classif_params->num_classif_elements;

        mm_memcpy(classif_params_copy->classif_table,
                  classif_params->classif_table,
                  LM_DCBX_IE_CLASSIF_ENTRIES_TO_ALOC_SIZE(classif_params_copy->num_classif_elements));

        p_classif_elem    = (dcb_classif_elem_t *)classif_params_copy->classif_table;
        //Clear all the DCB_CLASSIF_ENFORCED_BY_VBD from copy entries
        for(i = 0; i < classif_params_copy->num_classif_elements; i++,p_classif_elem++)
        {
            RESET_FLAGS(p_classif_elem->flags, DCB_CLASSIF_ENFORCED_BY_VBD);
        }
    }

    return lm_status;
}
/**
 * Copy dcb parameters given by OS.
 * @param pdev
 * @param dcb_params
 * @param dcb_params_copy
 * @param lm_cli_idx
 *
 * @return STATIC lm_status_t
 */
STATIC lm_status_t
lm_dcbx_ie_params_updated_copy_dcb_params(
    INOUT       lm_device_t                     *pdev,
    IN          dcb_indicate_event_params_t     *dcb_params,
    OUT         dcb_indicate_event_params_t     *dcb_params_copy,
    IN const    u8_t                            lm_cli_idx)
{
    lm_status_t lm_status = LM_STATUS_SUCCESS;

    mm_memcpy(dcb_params_copy,
              dcb_params,
              sizeof(dcb_indicate_event_params_t));

    // miniport pointers should not be used we will realloc a struct in lm_dcbx_ie_copy_alloc_classif_buffer
    dcb_params_copy->classif_params.classif_table           = NULL;
    dcb_params_copy->classif_params.num_classif_elements    = 0;

    lm_status = lm_dcbx_ie_copy_alloc_classif_buffer(pdev,
                                                     &dcb_params->classif_params,
                                                     &(dcb_params_copy->classif_params),
                                                     lm_cli_idx);

    if(LM_STATUS_SUCCESS != lm_status)
    {
        return lm_status;
    }

    return lm_status;
}
/**
 * @description
 * Validate the ETS and PFC parameters that were received can be
 * configured. The parameters will later be configured in WI.
 * For classification entries that will be supported are
 * returned with the flag DCB_CLASSIF_ENFORCED_BY_VBD set.
 * @param pdev
 * @param dcb_params
 *
 * @return lm_status_t
 */
lm_status_t
lm_dcbx_ie_params_updated_validate(
    INOUT       struct _lm_device_t             *pdev,
    OUT         dcb_indicate_event_params_t     *dcb_params,
    OUT         dcb_indicate_event_params_t     *dcb_params_copy,
    IN const    u8_t                            lm_cli_idx)
{
    lm_dcbx_indicate_event_t    *indicate_event = &pdev->dcbx_info.indicate_event;
    lm_status_t                 lm_status       = LM_STATUS_SUCCESS;

    DbgBreakIf(lm_cli_idx != indicate_event->lm_cli_idx);

    if((FALSE == pdev->dcbx_info.is_indicate_event_en) ||
       (IS_MULTI_VNIC(pdev)))
    {
        DbgBreakMsg("lm_dcbx_runtime_params_updated_validate_pfc called but is_indicate_event_en is false");
        return LM_STATUS_FAILURE;
    }

    if(GET_FLAGS(dcb_params->flags, DCB_PARAMS_PFC_ENABLED))
    {
        lm_status =
            lm_dcbx_ie_runtime_params_updated_validate_pfc(pdev,
                                                           &dcb_params->pfc_params);

        if(LM_STATUS_SUCCESS != lm_status)
        {
            return lm_status;
        }
    }

    if(GET_FLAGS(dcb_params->flags, DCB_PARAMS_ETS_ENABLED))
    {
        lm_status =
            lm_dcbx_ie_params_updated_validate_ets(pdev,
                                                   &dcb_params->ets_params);

        if(LM_STATUS_SUCCESS != lm_status)
        {
            return lm_status;
        }
    }

    if(GET_FLAGS(dcb_params->flags, DCB_PARAMS_CLASSIF_ENABLED))
    {
        lm_status =
            lm_dcbx_ie_classif_entries_validate_and_set_enforced(pdev,
                                                                 &dcb_params->classif_params);

        if(LM_STATUS_SUCCESS != lm_status)
        {
            return lm_status;
        }
    }

    lm_status = lm_dcbx_ie_params_updated_copy_dcb_params(pdev,
                                                          dcb_params,
                                                          dcb_params_copy,
                                                          indicate_event->lm_cli_idx);
    if(LM_STATUS_SUCCESS != lm_status)
    {
        return lm_status;
    }

    return lm_status;
}
/**
 * @description
 * Update the local copy of the configuration parameters free
 * the old buffer of the classification.
 * @param pdev
 * @param dcb_params
 * @param lm_cli_idx
 *
 * @return u8_t
 */
STATIC void
lm_dcbx_ie_update_local_params(
    INOUT       struct _lm_device_t             *pdev,
    INOUT       dcb_indicate_event_params_t     *dcb_params,
    OUT         u8_t                            *is_local_ets_change,
    IN const    u8_t                            lm_cli_idx,
    IN          u8_t                            is_ets_admin_updated
    )
{
    lm_dcbx_indicate_event_t    *indicate_event     = &pdev->dcbx_info.indicate_event;
    dcb_ets_tsa_param_t         ets_params_cmp      = {0};
    // I do not want to look at changed in this
    const u32_t                 interesting_flags   = DCB_PARAMS_WILLING | DCB_PARAMS_ETS_ENABLED |
        DCB_PARAMS_PFC_ENABLED | DCB_PARAMS_CLASSIF_ENABLED;

    DbgBreakIf(lm_cli_idx != indicate_event->lm_cli_idx);

    // Must be reset each OS configuration
    indicate_event->is_ets_ieee_params_os_valid = FALSE;

    // Copy before overwriting
    mm_memcpy(&(ets_params_cmp),
              &(indicate_event->ets_ieee_params_os),
              sizeof(ets_params_cmp));


    if(GET_FLAGS(dcb_params->flags, DCB_PARAMS_ETS_ENABLED))
    {
        DbgBreakIf(FALSE == is_ets_admin_updated);

        mm_memcpy(&(indicate_event->ets_ieee_params_os),
                  &(dcb_params->ets_params),
                  sizeof(indicate_event->ets_ieee_params_os));

        if(is_ets_admin_updated)
        {
            indicate_event->is_ets_ieee_params_os_valid = TRUE;
        }
    }
    else
    {
        mm_mem_zero(&(indicate_event->ets_ieee_params_os),
                    sizeof(indicate_event->ets_ieee_params_os));
    }

    if(FALSE == mm_memcmp(&(indicate_event->ets_ieee_params_os),
                  &(ets_params_cmp),
                  sizeof(ets_params_cmp)))
    {
        *is_local_ets_change = TRUE;
    }


    //A final OID_QOS_PARAMETERS with *only* the NDIS_QOS_PARAMETERS_WILLING flag set is sent to an NDIS QOS capable miniport when:
    //  1. DCB feature is uninstalled or the msdcb.sys driver is being stopped by the admin.
    //  2. The miniport is being unbound by NDIS for whatever reason.
    if(DCB_PARAMS_WILLING == GET_FLAGS(dcb_params->flags, interesting_flags))
    {
        indicate_event->ets_config_state = lm_dcbx_ets_config_state_cee;
    }
    else
    {
        indicate_event->ets_config_state = lm_dcbx_ets_config_state_ieee;
    }
}
/**
 *  For debugging purpose only.
 * @param pdev
 * @param dcb_params
 * @param is_local_ets_change
 * @param lm_cli_idx
 *
 * @return STATIC void
 */
STATIC void
lm_dcbx_ie_dbg_copy_dcb_params(
    INOUT       struct _lm_device_t             *pdev,
    INOUT       dcb_indicate_event_params_t     *dcb_params,
    IN const    u8_t                            lm_cli_idx)
{
    dcb_indicate_event_params_t *dcb_params_dbg = &pdev->dcbx_info.indicate_event.dcb_params_given_dbg;
    const u32_t table_alloc_size_dbg =
        min(LM_DCBX_IE_CLASSIF_TABLE_ALOC_SIZE_DBG,
            LM_DCBX_IE_CLASSIF_ENTRIES_TO_ALOC_SIZE(dcb_params->classif_params.num_classif_elements));

    dcb_params_dbg->flags = dcb_params->flags;

    mm_memcpy(&dcb_params_dbg->ets_params,
              &dcb_params->ets_params,
              sizeof(dcb_params_dbg->ets_params));

    mm_memcpy(&dcb_params_dbg->pfc_params,
              &dcb_params->pfc_params,
              sizeof(dcb_params_dbg->pfc_params));

    dcb_params_dbg->classif_params.classif_version =
        dcb_params->classif_params.classif_version;

    // This can be equal or more than the classification
    // entries allocated by dbg and isn't used
    dcb_params_dbg->classif_params.num_classif_elements =
        dcb_params->classif_params.num_classif_elements;

    mm_mem_zero(dcb_params_dbg->classif_params.classif_table,
                LM_DCBX_IE_CLASSIF_TABLE_ALOC_SIZE_DBG);

    if(NULL != dcb_params_dbg->classif_params.classif_table)
    {
        mm_memcpy(dcb_params_dbg->classif_params.classif_table,
                  dcb_params->classif_params.classif_table,
                  table_alloc_size_dbg);
    }
}

/**
 * @description
 * Creat the IEEE PFC settings from CEE PFC settings.
 * @param pdev
 * @param cee_pfc
 * @param ieee_pfc
 * @param flags
 *
 * @return STATIC void
 */
STATIC void
lm_dcbx_ie_pfc_cee_to_ieee_imp(
    INOUT       lm_device_t         *pdev,
    OUT         dcb_pfc_param_t     *ieee_pfc,
    OUT         u32_t               *flags,
    IN const    u8_t                is_pfc_en,
    IN const    u8_t                pri_en_bitmap
    )
{
    SET_FLAGS(*flags, DCB_PARAMS_PFC_ENABLED);

    if(0 == is_pfc_en)
    {
        return;
    }

    ieee_pfc->pfc_enable = pri_en_bitmap;
}
/**
 * @description
 * Creat the IEEE PFC settings from CEE PFC settings.
 * @param pdev
 * @param cee_pfc
 * @param ieee_pfc
 * @param flags
 *
 * @return STATIC void
 */
STATIC void
lm_dcbx_ie_pfc_cee_to_ieee(
    INOUT       lm_device_t         *pdev,
    IN const    dcbx_pfc_feature_t  *cee_pfc,
    OUT         dcb_pfc_param_t     *ieee_pfc,
    OUT         u32_t               *flags,
    IN const    lm_event_code_t     event
    )
{
    if( LM_EVENT_CODE_DCBX_OPERA_CHANGE == event)
    {
        lm_dcbx_ie_pfc_cee_to_ieee_imp(pdev,
                                       ieee_pfc,
                                       flags,
                                       (u8_t)pdev->params.dcbx_port_params.pfc.enabled,
                                       LM_DCBX_PFC_PRI_PAUSE_MASK(pdev));
    }
    else
    {
        DbgBreakIf( LM_EVENT_CODE_DCBX_REMOTE_CHANGE != event);

        lm_dcbx_ie_pfc_cee_to_ieee_imp(pdev,
                                       ieee_pfc,
                                       flags,
                                       cee_pfc->enabled,
                                       cee_pfc->pri_en_bitmap);
    }
}
/**
 * @description
 * Straight forward parsing.
 * The data given from the remote doesn't promise continues
 * entries and that for TC_x x is smaller than max TC
 * given.
 * Strict entry will always be the first TC_0.
 * Find an empty cell for strict and count the number of TC
 * entries used.
 * @param pdev
 * @param cee_ets
 * @param ieee_ets
 * @param flags
 * @param event
 *
 * @return STATIC void
 */
STATIC void
lm_dcbx_ie_ets_cee_to_ieee_unparse(
    INOUT       lm_device_t         *pdev,
    IN const    dcbx_ets_feature_t  *cee_ets,
    OUT         dcb_ets_tsa_param_t *ieee_ets,
    OUT         u32_t               *flags
    )
{
    u8_t        pri                 = 0;
    u8_t        b_found_strict      = FALSE;
    u8_t        tc_entry            = 0;
    u8_t        tc_entry_bitmap     = 0;
    u8_t        tc_used_bitmap_bw   = 0;
    u8_t        num_of_tc_used      = 0;
    u8_t        strict_tc           = 0;

    ASSERT_STATIC(DCBX_MAX_NUM_PRI_PG_ENTRIES == DCBX_MAX_NUM_PG_BW_ENTRIES);
    ASSERT_STATIC(DCBX_MAX_NUM_PRI_PG_ENTRIES == ARRSIZE(ieee_ets->priority_assignment_table));
    ASSERT_STATIC(DCBX_MAX_NUM_PG_BW_ENTRIES == ARRSIZE(ieee_ets->tc_bw_assignment_table));
    ASSERT_STATIC(DCBX_MAX_NUM_PG_BW_ENTRIES == ARRSIZE(ieee_ets->tsa_assignment_table));

    mm_mem_zero(ieee_ets, sizeof(dcb_ets_tsa_param_t));
    RESET_FLAGS(*flags, DCB_PARAMS_ETS_ENABLED);

    if(FALSE == cee_ets->enabled)
    {
        return;
    }

    /************ Find an empty cell for strict and count the number of TC entries used*******/

    // Map all BW TC to a bitfield and find if there is a strict TC
    for (pri = 0; pri < DCBX_MAX_NUM_PRI_PG_ENTRIES; pri++)
    {
        tc_entry = DCBX_PRI_PG_GET(cee_ets->pri_pg_tbl, pri);

        if(tc_entry < DCBX_MAX_NUM_PG_BW_ENTRIES)
        {
            // BW
            tc_entry_bitmap = (1 << tc_entry);
            // Count the number of TC entries given and fill the appropriate COS entry
            if (0 == (tc_used_bitmap_bw & tc_entry_bitmap))
            {
                // New TC add it to the bitmask
                tc_used_bitmap_bw |= tc_entry_bitmap;
                num_of_tc_used++;
            }
        }
        else if(DCBX_STRICT_PRI_PG == tc_entry)
        {
            // Strict
            b_found_strict = TRUE;
        }
        else
        {
            DbgBreakMsg("lm_dcbx_runtime_params_updated_validate_ets a tc_entry can't be larger"
                        "than the number of TC supported");
            return;
        }
    }

    // Find an empty cell for strict
    if(TRUE == b_found_strict)
    {
        if((DCBX_MAX_NUM_PRI_PG_ENTRIES) != num_of_tc_used )
        {
            // Find a free TC for strict priority
            for (tc_entry  = 0; tc_entry < DCBX_MAX_NUM_PRI_PG_ENTRIES; tc_entry++)
            {
                tc_entry_bitmap = (1 << tc_entry);

                // Found an unused cell that will be used for strict
                if( 0 == (tc_used_bitmap_bw & tc_entry_bitmap))
                {
                    num_of_tc_used++;
                    strict_tc = tc_entry;
                    break;
                }
            }
        }
        else
        {
            DbgBreakMsg("lm_dcbx_ie_ets_cee_to_ieee_unparse: this is a bug we cant have 9 TC");
            // In case we have 8 used TC and strict The last TC will be shared
            // between BW and streict.
            strict_tc = DCBX_MAX_NUM_PRI_PG_ENTRIES -1;
        }
    }

    for (pri = 0; pri < DCBX_MAX_NUM_PRI_PG_ENTRIES; pri++)
    {
        tc_entry = DCBX_PRI_PG_GET(cee_ets->pri_pg_tbl, pri);

        if(tc_entry < DCBX_MAX_NUM_PG_BW_ENTRIES)
        {
            // BW
            ieee_ets->priority_assignment_table[pri]    = tc_entry;
            ieee_ets->tsa_assignment_table[tc_entry]    = TSA_ASSIGNMENT_DCB_TSA_ETS;
            ieee_ets->tc_bw_assignment_table[tc_entry]  = DCBX_PG_BW_GET(cee_ets->pg_bw_tbl,tc_entry);
        }
        else if(DCBX_STRICT_PRI_PG == tc_entry)
        {
            // Strict
            ieee_ets->priority_assignment_table[pri]    = strict_tc;
            ieee_ets->tsa_assignment_table[strict_tc]   = TSA_ASSIGNMENT_DCB_TSA_STRICT;
            ieee_ets->tc_bw_assignment_table[strict_tc] = 0;
        }
        else
        {
            DbgBreakMsg("lm_dcbx_runtime_params_updated_validate_ets a tc_entry can't be larger"
                        "than the number of TC supported");
            return;
        }
    }

    ieee_ets->num_traffic_classes = num_of_tc_used;

    SET_FLAGS(*flags, DCB_PARAMS_ETS_ENABLED);
}
/**
 * @description
 * The ETS data is already parse and configured to chip. The use
 * of the parse struct is a must because there is an algorithm
 * that decide how to configure the chip, and the parsing isn't
 * straight forward.
 * @param pdev
 * @param cee_ets
 * @param ieee_ets
 * @param flags
 * @param event
 *
 * @return STATIC void
 */
STATIC void
lm_dcbx_ie_ets_cee_to_ieee_parsed_data(
    INOUT       lm_device_t         *pdev,
    OUT         dcb_ets_tsa_param_t *ieee_ets,
    OUT         u32_t               *flags
    )
{
    u8_t        i                   = 0;
    u8_t        tc_assign           = 0;
    const u8_t  max_tc_sup          = lm_dcbx_cos_max_num(pdev) ;
    pg_params_t *ets                = &(pdev->params.dcbx_port_params.ets);
    u16_t       pri_bit             = 0;

    ASSERT_STATIC(DCBX_MAX_NUM_PRI_PG_ENTRIES == DCBX_MAX_NUM_PG_BW_ENTRIES);
    ASSERT_STATIC(DCBX_MAX_NUM_PRI_PG_ENTRIES == ARRSIZE(ieee_ets->priority_assignment_table));
    ASSERT_STATIC(DCBX_MAX_NUM_PG_BW_ENTRIES == ARRSIZE(ieee_ets->tc_bw_assignment_table));
    ASSERT_STATIC(DCBX_MAX_NUM_PG_BW_ENTRIES == ARRSIZE(ieee_ets->tsa_assignment_table));

    SET_FLAGS(*flags, DCB_PARAMS_ETS_ENABLED);

    if((FALSE == ets->enabled) ||
       (max_tc_sup < ets->num_of_cos))
    {
        DbgBreakIf(max_tc_sup < ets->num_of_cos);
        return;
    }

    ieee_ets->num_traffic_classes  = ets->num_of_cos;

    for(i = 0; i < ARRSIZE(ieee_ets->priority_assignment_table) ; i++)
    {
        pri_bit = 1 << i;
        for(tc_assign = 0 ; tc_assign < ets->num_of_cos; tc_assign++)
        {
            if(0 != (pri_bit & ets->cos_params[tc_assign].pri_bitmask))
            {
                break;
            }
        }

        // If the priority doesn't belong to non of the cos_params then
        // assign this priority to zero.
        if(ets->num_of_cos == tc_assign)
        {
            tc_assign = 0;
        }

        ieee_ets->priority_assignment_table[i]        = tc_assign;
    }

    for(tc_assign = 0 ; tc_assign < ets->num_of_cos; tc_assign++)
    {
        if(DCBX_S_PRI_INVALID != ets->cos_params[tc_assign].s_pri)
        {// COS is SP
            // Strict
            DbgBreakIf(DCBX_INVALID_COS_BW != ets->cos_params[tc_assign].bw_tbl);

            ieee_ets->tsa_assignment_table[tc_assign]     = TSA_ASSIGNMENT_DCB_TSA_STRICT;
            ieee_ets->tc_bw_assignment_table[tc_assign]   = 0;
        }
        else
        {// COS is BW
            DbgBreakIf(DCBX_INVALID_COS_BW == ets->cos_params[tc_assign].bw_tbl);

            ieee_ets->tsa_assignment_table[tc_assign]     = TSA_ASSIGNMENT_DCB_TSA_ETS;
            ieee_ets->tc_bw_assignment_table[tc_assign]   = (u8_t)ets->cos_params[tc_assign].bw_tbl;
        }
    }
}
/**
 * @description
 * Creat the IEEE ETS settings from CEE ETS settings.
 * @param pdev
 * @param cee_ets
 * @param ieee_ets
 * @param flags
 *
 * @return STATIC void
 */
STATIC void
lm_dcbx_ie_ets_cee_to_ieee(
    INOUT       lm_device_t         *pdev,
    IN const    dcbx_ets_feature_t  *cee_ets,
    OUT         dcb_ets_tsa_param_t *ieee_ets,
    OUT         u32_t               *flags,
    IN const    lm_event_code_t     event
    )
{
    if( LM_EVENT_CODE_DCBX_OPERA_CHANGE == event)
    {
        lm_dcbx_ie_ets_cee_to_ieee_parsed_data(pdev, ieee_ets, flags);
    }
    else
    {
        DbgBreakIf( LM_EVENT_CODE_DCBX_REMOTE_CHANGE != event);
        lm_dcbx_ie_ets_cee_to_ieee_unparse(pdev,
                                           cee_ets,
                                           ieee_ets,
                                           flags);
    }
}
/**
 * Update the classification entry with the data given.
 *
 * @param pdev
 * @param classif_entry
 * @param condition_selector
 * @param condition_field
 * @param pri
 *
 * @return STATIC void
 */
STATIC void
lm_dcbx_ie_classif_set_entry(
    IN  lm_device_t                 *pdev,
    IN  dcb_classif_elem_t          *classif_entry,
    IN  dcb_condition_selector_t    condition_selector,
    IN  u16_t                       condition_field,
    IN  u16_t                       pri)
{
    classif_entry->flags                = 0;
    classif_entry->condition_selector   = condition_selector;
    classif_entry->condition_field      = condition_field;
    classif_entry->action_selector      = DCB_ACTION_PRIORITY;
    classif_entry->action_field         = pri;
}
/**
 * This default entry must be the first one.
 * @param pdev
 * @param cee_classif
 * @param classif_entry
 *
 * @return STATIC u8_t return the number of entries used by the
 *         function.
 */
STATIC void
lm_dcbx_ie_classif_add_default(
    INOUT       lm_device_t                 *pdev,
    IN const    dcbx_app_priority_feature_t *cee_classif,
    IN          dcb_classif_elem_t          *classif_entry)
{
    u16_t const  default_pri    = (cee_classif->default_pri < MAX_PFC_PRIORITIES)? cee_classif->default_pri: 0;

    lm_dcbx_ie_classif_set_entry( pdev,
                                  classif_entry,
                                  DCB_CONDITION_DEFAULT,
                                  0,
                                  default_pri);
}
/**
 * Parse the CEE entries to indicate event classification
 * entries.
 * @param pdev
 * @param cee_app_pri_tbl
 * @param cee_app_pri_tbl_size
 * @param classif_table
 * @param is_iscsi_cee_rec - There is an ISCSI CEE entry.
 * @param event
 *
 * @return STATIC u8_t return the number of entries used by the
 *         function.
 */
STATIC u8_t
lm_dcbx_ie_classif_parse_cee_arrray(
    INOUT       lm_device_t                 *pdev,
    IN const    dcbx_app_priority_entry_t   *cee_app_pri_tbl,
    IN const    u8_t                        cee_app_pri_tbl_size,
    INOUT       dcb_classif_elem_t          *classif_table,
    OUT         u8_t                        *is_iscsi_cee_rec
    )
{
    u8_t                        cee_index           = 0;
    u32_t                       pri                 = 0;
    dcb_condition_selector_t    condition_selector  = 0;
    u8_t                        num_entry_used      = 0;
    u8_t                        dummy_flag          = FALSE;

    if(CHK_NULL(cee_app_pri_tbl))
    {
        return 0;
    }

    for( cee_index = 0;
         (cee_index < cee_app_pri_tbl_size);
         cee_index++)
    {
        pri = MAX_PFC_PRIORITIES;

        if(0 == GET_FLAGS(cee_app_pri_tbl[cee_index].appBitfield, DCBX_APP_ENTRY_VALID))
        {
            continue;
        }

        /********************************************************************/
        /******** start parse entry to from CEE format to IEEE format********/
        if(GET_FLAGS(cee_app_pri_tbl[cee_index].appBitfield, DCBX_APP_SF_ETH_TYPE))
        {
            condition_selector = DCB_CONDITION_ETHERTYPE;
        }
        else if(GET_FLAGS(cee_app_pri_tbl[cee_index].appBitfield, DCBX_APP_SF_PORT))
        {
            condition_selector = DCB_CONDITION_TCP_OR_UDP_PORT;
        }
        else
        {
            DbgBreakMsg("lm_dcbx_classif_cee_to_ieee invalid appBitfield ");
            continue;
        }

        lm_dcbx_get_ap_priority(pdev, &pri, cee_app_pri_tbl[cee_index].pri_bitmap, &dummy_flag);

        if(MAX_PFC_PRIORITIES == pri)
        {
            if(0 == cee_app_pri_tbl[cee_index].pri_bitmap)
            {
                // This is a patch:
                // We don't assert as a request from DVT:(CQ64888 and CQ59423).
                // A quote from Darshan (DVT) mail "Brocade expects (just like Navasota) that PFC 
                // be enabled on the iSCSI traffic class (which, I agree, is inappropriate). If the PFC is not set on the iSCSI 
                // traffic class then it sends the iSCSI App TLV with PRI bit map of zero irrespective of whatever PRI you have 
                // configured for iSCSI. Once PFC is enabled, it sends the correct App TLV bit map."
                #if defined(DBG)
                DbgMessage(pdev, FATAL, "lm_dcbx_ie_classif_parse_cee_arrray invalid pri for valid entry ");
                #else
                DbgBreakMsg("lm_dcbx_ie_classif_parse_cee_arrray invalid pri for valid entry ");
                #endif 
            }
            else
            {
                DbgBreakMsg("lm_dcbx_ie_classif_parse_cee_arrray invalid pri for valid entry ");
            }
            continue;
        }

        lm_dcbx_ie_classif_set_entry( pdev,
                                      &(classif_table[num_entry_used]),
                                      condition_selector,
                                      cee_app_pri_tbl[cee_index].app_id,
                                      (u16_t)pri);

        num_entry_used++;

        // ISCSI is a special case until we will implement IEEE we can send DCB_CONDITION_TCP_PORT.
        if((DCB_CONDITION_TCP_OR_UDP_PORT == condition_selector) &&
           (TCP_PORT_ISCSI == cee_app_pri_tbl[cee_index].app_id))
        {
            (*is_iscsi_cee_rec) = TRUE;
        }
    }

    return num_entry_used;
}
/**
 * This function is only for verifying that the classification
 * Parameters sent to OS are coherent with local classification
 * parameters and that the parameters are generally coherent
 *
 * @param pdev
 * @param ieee_classif
 * @param event
 *
 * @return STATIC void
 */
STATIC void
lm_dcbx_ie_classif_cee_to_ieee_check_param_dbg(
    IN const    lm_device_t             *pdev,
    IN const    dcb_classif_params_t    *ieee_classif,
    IN const    lm_event_code_t         event
    )
{
    dcb_classif_elem_t          *p_classif_elem                 = ieee_classif->classif_table;
    u8_t                        i                               = 0;
    lm_dcbx_ie_classif_dbg_t    classif_dbg[MAX_TRAFFIC_TYPE]   = {{0}};

    for(i = 0; i < ieee_classif->num_classif_elements; i++)
    {
        if(DCB_ACTION_PRIORITY != p_classif_elem[i].action_selector)
        {
            // VBD only supports condition_selector that is based on priority
            continue;
        }

        switch(p_classif_elem[i].condition_selector)
        {
        case DCB_CONDITION_DEFAULT:
            // Must be the first entry
            DbgBreakIf(0 != i);
            break;

        case DCB_CONDITION_TCP_PORT:
        case DCB_CONDITION_TCP_OR_UDP_PORT://Fall through
            if(TCP_PORT_ISCSI == p_classif_elem[i].condition_field)
            {
                classif_dbg[LLFC_TRAFFIC_TYPE_ISCSI].pri = p_classif_elem[i].action_field;
                classif_dbg[LLFC_TRAFFIC_TYPE_ISCSI].num_entries++;
            }
            break;

        case DCB_CONDITION_ETHERTYPE:
            if(ETH_TYPE_FCOE == p_classif_elem[i].condition_field)
            {
                classif_dbg[LLFC_TRAFFIC_TYPE_FCOE].pri = p_classif_elem[i].action_field;
                classif_dbg[LLFC_TRAFFIC_TYPE_FCOE].num_entries++;
            }
            break;

        case DCB_CONDITION_RESERVED:
        case DCB_CONDITION_UDP_PORT://Fall through
        case DCB_CONDITION_NETDIRECT_PORT://Fall through
            //Not supported by VBD
            break;
        case DCB_CONDITION_MAX:
        default:
            DbgBreakMsg("lm_dcbx_runtime_params_updated_en_classif_entries: illegal entry ");
            break;
        }
    }

    // traffic_type_priority and classification DCBX_OPERA parameters are derived both from local MIB
    if( LM_EVENT_CODE_DCBX_OPERA_CHANGE == event)
    {
        for(i = 0; i < MAX_TRAFFIC_TYPE; i++)
        {
            //num_entries is more interesting if num_entries =< 1 ,otherwise this is a unusually configuration.
            if(1 == classif_dbg[i].num_entries)
            {
                DbgBreakIf(classif_dbg[i].pri !=
                           pdev->params.dcbx_port_params.app.traffic_type_priority[i]);
            }
        }
    }

}
/**
 * @description
 * Creat the IEEE settings from CEE settings.
 * If there is a given_tabel copy it to the beggining of the
 * ieee_classif.
 * After search the CEE (local /remote) entries (read from
 * chip)an add any valid CEE entry because it has a higher
 * priority than given_tabel.
 * @param pdev
 * @param cee_classif
 * @param ieee_classif
 * @param ieee_classif_alloc_size
 * @param given_tabel
 * @param given_tabel_alloc_size
 * @param flags
 *
 * @return STATIC void
 */
STATIC lm_status_t
lm_dcbx_ie_classif_cee_to_ieee(
    INOUT       lm_device_t                 *pdev,
    IN const    dcbx_app_priority_feature_t *cee_classif,
    IN const    dcbx_app_priority_entry_t   *cee_app_tbl_ext,
    IN const    u8_t                        cee_app_tbl_ext_size,
    OUT         dcb_classif_params_t        *ieee_classif,
    IN const    u32_t                       ieee_classif_alloc_size,
    OUT         u32_t                       *flags,
    IN const    lm_event_code_t             event
    )
{
    lm_dcbx_indicate_event_t    *indicate_event     = &pdev->dcbx_info.indicate_event;
    dcb_classif_elem_t          *classif_table      = ieee_classif->classif_table;
    lm_status_t                 lm_status           = LM_STATUS_SUCCESS;
    u16_t                       num_entry_used      = 0;
    u8_t                        is_iscsi_cee_rec    = FALSE;

    DbgBreakIf(0 != (ieee_classif_alloc_size % sizeof(dcb_classif_elem_t)));

    // Check enablement of classification
    if( LM_EVENT_CODE_DCBX_OPERA_CHANGE == event)
    {
        if(0 == pdev->params.dcbx_port_params.app.enabled)
        {
            return LM_STATUS_SUCCESS;
        }
        // Default must be the first entry.
        lm_dcbx_ie_classif_add_default(pdev,
                                       cee_classif,
                                       classif_table);
        num_entry_used++;
    }
    else
    {
        DbgBreakIf( LM_EVENT_CODE_DCBX_REMOTE_CHANGE != event);
        if(0 == cee_classif->enabled)
        {
            return LM_STATUS_SUCCESS;
        }
    }

    SET_FLAGS(*flags, DCB_PARAMS_CLASSIF_ENABLED);

    num_entry_used += lm_dcbx_ie_classif_parse_cee_arrray(
        pdev,
        cee_classif->app_pri_tbl,
        ARRSIZE(cee_classif->app_pri_tbl),
        &(classif_table[num_entry_used]),
        &is_iscsi_cee_rec);

    num_entry_used += lm_dcbx_ie_classif_parse_cee_arrray(
        pdev,
        cee_app_tbl_ext,
        cee_app_tbl_ext_size,
        &(classif_table[num_entry_used]),
        &is_iscsi_cee_rec);

    // If the operational configuration from MCP contains an entry with 'TCP or UDP port' = 3260 use that entry,
    //     Else if OS configuration contained an entry with 'TCP port' = 3260 use that entry,
    //     Else use the default configuration.
    if(( LM_EVENT_CODE_DCBX_OPERA_CHANGE == event) &&
        ( FALSE == is_iscsi_cee_rec) &&
        ( LM_DCBX_ILLEGAL_PRI != indicate_event->iscsi_tcp_pri))
    {
        DbgBreakIf(pdev->params.dcbx_port_params.app.traffic_type_priority[LLFC_TRAFFIC_TYPE_ISCSI] !=
                   indicate_event->iscsi_tcp_pri);

        lm_dcbx_ie_classif_set_entry( pdev,
                                      &(classif_table[num_entry_used]),
                                      DCB_CONDITION_TCP_PORT,
                                      TCP_PORT_ISCSI,
                                      indicate_event->iscsi_tcp_pri);
        num_entry_used++;
    }

    ieee_classif->num_classif_elements = num_entry_used;

    lm_dcbx_ie_classif_cee_to_ieee_check_param_dbg(pdev,
                                                   ieee_classif,
                                                   event);

    return lm_status;
}
/**
 * Check if there is a classification parameter update
 * @param pdev
 * @param params_prev
 * @param params_newest
 *
 * @return STATIC u8_t
 */
STATIC u8_t
lm_dcbx_ie_classif_check_if_params_changed(
    IN  const dcb_classif_params_t    *params_prev,
    IN  const dcb_classif_params_t    *params_newest)
{
    dcb_classif_elem_t  *p_classif_prev = params_prev->classif_table;
    dcb_classif_elem_t  *p_classif_newest = params_newest->classif_table;
    u16_t               index_prev = 0;
    u16_t               index_newest = 0;
    u8_t                is_entry_found = 0;

    if(params_prev->num_classif_elements != params_newest->num_classif_elements)
    {
        return TRUE;
    }

    for(index_prev = 0 ; index_prev < params_prev->num_classif_elements ; index_prev++)
    {
        is_entry_found = FALSE;
        for(index_newest = 0 ; index_newest < params_prev->num_classif_elements ; index_newest++)
        {
            if(mm_memcmp(&(p_classif_prev[index_prev]),
                         &(p_classif_newest[index_newest]),
                         sizeof(p_classif_prev[index_prev])))
            {
                is_entry_found = TRUE;
                break;
            }
        }

        if(FALSE == is_entry_found)
        {
            return TRUE;
        }
    }

    return FALSE;
}
/**
 * @description
 * Creat the indicate event struct based on data read from chip.
 * If the data has change call upper layer indicate event.
 * @param pdev
 * @param indicate_params
 * @param dcbx_features
 * @param event
 * @param ieee_classif_alloc_size
 * @param given_tabel
 * @param given_tabel_alloc_size
 * @param ets_given
 * @param is_ets_change
 * @param is_classif_change
 *
 * @return STATIC lm_status_t
 */
STATIC lm_status_t
lm_dcbx_ie_check_if_param_change_common(
    INOUT       lm_device_t                         *pdev,
    INOUT       dcb_indicate_event_params_t         *indicate_params,
    IN          dcbx_features_t                     *dcbx_features,
    IN const    dcbx_app_priority_entry_t           *cee_app_tbl_ext,
    IN const    u8_t                                cee_app_tbl_ext_size,
    IN const    lm_event_code_t                     event,
    IN const    u32_t                               ieee_classif_alloc_size,
    IN const    lm_dcbx_ie_ets_ieee_config_state    ets_ieee_config_state,
    IN const    dcb_ets_tsa_param_t                 *ets_ieee_config,
    IN const    u8_t                                is_ets_change)
{
    dcb_indicate_event_params_t indicate_newest_params  = {0};
    lm_status_t                 lm_status               = LM_STATUS_SUCCESS;
    u8_t                        is_changed              = 0;

    // Allocate local buffer that is enough for all entries given and read from chip
    indicate_newest_params.classif_params.classif_table =
        mm_rt_alloc_mem(pdev, ieee_classif_alloc_size, pdev->dcbx_info.indicate_event.lm_cli_idx);

    if(CHK_NULL(indicate_newest_params.classif_params.classif_table))
    {
        return LM_STATUS_RESOURCE;
    }
    mm_mem_zero(indicate_newest_params.classif_params.classif_table, ieee_classif_alloc_size);

    lm_dcbx_ie_pfc_cee_to_ieee(pdev,
                               &dcbx_features->pfc,
                               &indicate_newest_params.pfc_params,
                               &indicate_newest_params.flags,
                               event
                               );

    if(FALSE == mm_memcmp(&indicate_params->pfc_params,
                          &indicate_newest_params.pfc_params ,
                          sizeof(dcb_pfc_param_t)))
    {
        is_changed = TRUE;
        SET_FLAGS(indicate_newest_params.flags, DCB_PARAMS_PFC_CHANGED);
    }

    if(lm_dcbx_ets_ieee_config_not_valid == ets_ieee_config_state)
    {
        lm_dcbx_ie_ets_cee_to_ieee(pdev,
                                   &dcbx_features->ets,
                                   &indicate_newest_params.ets_params,
                                   &indicate_newest_params.flags,
                                   event
                                   );
    }
    else
    {
        if(lm_dcbx_ets_ieee_config_en == ets_ieee_config_state)
        {
            SET_FLAGS(indicate_newest_params.flags, DCB_PARAMS_ETS_ENABLED);
            // copy the ets_params that were before (ETS params given from upper module)
            mm_memcpy(&indicate_newest_params.ets_params,
                      ets_ieee_config,
                      sizeof(dcb_ets_tsa_param_t));
        }
        else
        {
            DbgBreakIf(lm_dcbx_ets_ieee_config_di != ets_ieee_config_state);

            RESET_FLAGS(indicate_newest_params.flags, DCB_PARAMS_ETS_ENABLED);
            mm_mem_zero(&indicate_newest_params.ets_params,
                      sizeof(dcb_ets_tsa_param_t));
        }
    }

    if((FALSE == mm_memcmp(&indicate_params->ets_params,
                          &indicate_newest_params.ets_params ,
                          sizeof(dcb_ets_tsa_param_t))) ||
       (TRUE == is_ets_change))
    {
        is_changed = TRUE;
        if(GET_FLAGS(indicate_newest_params.flags, DCB_PARAMS_ETS_ENABLED))
        {
            SET_FLAGS(indicate_newest_params.flags, DCB_PARAMS_ETS_CHANGED);
        }
    }

    lm_status = lm_dcbx_ie_classif_cee_to_ieee(pdev,
                                              &dcbx_features->app,
                                              cee_app_tbl_ext,
                                              cee_app_tbl_ext_size,
                                              &indicate_newest_params.classif_params,
                                              ieee_classif_alloc_size,
                                              &indicate_newest_params.flags,
                                              event
                                              );

    DbgBreakIf(LM_STATUS_SUCCESS != lm_status);

    if(TRUE == lm_dcbx_ie_classif_check_if_params_changed(
                        &indicate_params->classif_params,
                        &indicate_newest_params.classif_params))
    {
        is_changed = TRUE;
        SET_FLAGS(indicate_newest_params.flags, DCB_PARAMS_CLASSIF_CHANGED);
    }

    if(TRUE == is_changed)
    {

        mm_memcpy(&indicate_params->flags,
                  &indicate_newest_params.flags,
                  sizeof(indicate_newest_params.flags));

        mm_memcpy(&indicate_params->pfc_params,
                  &indicate_newest_params.pfc_params,
                  sizeof(indicate_newest_params.pfc_params));

        mm_memcpy(&indicate_params->ets_params,
                  &indicate_newest_params.ets_params,
                  sizeof(indicate_newest_params.ets_params));

        /* Start Update indicate_params with newest temp buffer params  */
        mm_memcpy(indicate_params->classif_params.classif_table,
                  indicate_newest_params.classif_params.classif_table,
                  ieee_classif_alloc_size);

        indicate_params->classif_params.num_classif_elements = indicate_newest_params.classif_params.num_classif_elements;


        /* End: Update indicate_params with newest temp buffer params  */
#ifdef _VBD_CMD_
        MM_DCB_INDICATE_EVENT(pdev,event,(u8_t*)indicate_params, sizeof(dcb_indicate_event_params_t));
#endif
#ifdef _VBD_
        MM_DCB_INDICATE_EVENT(pdev,event,(u8_t*)indicate_params, sizeof(dcb_indicate_event_params_t));
#endif
    }
    // Free the local allocated buffer
    mm_rt_free_mem(pdev,
                   indicate_newest_params.classif_params.classif_table,
                   ieee_classif_alloc_size,
                   pdev->dcbx_info.indicate_event.lm_cli_idx);
    return lm_status;
}
/**
 * @description
 *  Check if local parameter has change , if they have change
 *  indicate event to upper layer.
 * @param pdev
 * @param p_local_mib
 * @param dcbx_neg_res_offset
 * @param is_ets_change
 * @param is_classif_change
 *
 * @return lm_status_t
 */
lm_status_t
lm_dcbx_ie_check_if_param_change_local(
    INOUT       lm_device_t             *pdev,
    IN          lldp_local_mib_t        *p_in_local_mib,
    IN          lldp_local_mib_ext_t    *p_in_local_mib_ext,
    IN const    u8_t                    is_ets_change)
{
    lm_dcbx_indicate_event_t    *indicate_event     = &pdev->dcbx_info.indicate_event;
    lldp_local_mib_t            local_mib           = {0};
    lldp_local_mib_ext_t        local_mib_ext       = {0};
    lm_status_t                 lm_status           = LM_STATUS_SUCCESS;
    lldp_local_mib_t            *p_local_mib        = p_in_local_mib;
    lldp_local_mib_ext_t        *p_local_mib_ext    = p_in_local_mib_ext;

    if(NULL == p_local_mib)
    {
        // Local MIB was not received read local MIB
        lm_status = lm_dcbx_read_local_mib_fields(pdev,
                                                  &local_mib,
                                                  &local_mib_ext);

        if(LM_STATUS_SUCCESS != lm_status)
        {
            return lm_status;
        }

        p_local_mib = &local_mib;
        p_local_mib_ext = &local_mib_ext;
    }

    if(CHK_NULL(p_local_mib) || CHK_NULL(p_local_mib_ext))
    {
        DbgBreakMsg("lm_get_dcbx_drv_param wrong in parameters ");
        return lm_status;
    }

    lm_status = lm_dcbx_ie_check_if_param_change_common(
        pdev,
        &(indicate_event->local_params),
        &p_local_mib->features,
        p_local_mib_ext->app_pri_tbl_ext,
        ARRSIZE(p_local_mib_ext->app_pri_tbl_ext),
        LM_EVENT_CODE_DCBX_OPERA_CHANGE,
        LM_DCBX_IE_CLASSIF_TABLE_ALOC_SIZE_LOCAL,
        indicate_event->ets_ieee_config_state,
        &indicate_event->ets_ieee_params_config,
        is_ets_change);

    DbgBreakIf(LM_STATUS_SUCCESS != lm_status);

    return lm_status;
}
/**
 * @description
 *  Check if Remote parameter has change , if they have change
 *  indicate event to upper layer.
 * @param pdev
 * @param dcbx_neg_res_offset
 *
 * @return lm_status_t
 */
lm_status_t
lm_dcbx_ie_check_if_param_change_remote(
    INOUT   lm_device_t         *pdev)
{
    lldp_remote_mib_t   remote_mib  = {0};
    lm_status_t         lm_status   = LM_STATUS_SUCCESS;

    lm_status = lm_dcbx_read_remote_local_mib(pdev,
                                              (u32_t *)&remote_mib,
                                              DCBX_READ_REMOTE_MIB);

    if(LM_STATUS_SUCCESS != lm_status)
    {
        return lm_status;
    }


    lm_status = lm_dcbx_ie_check_if_param_change_common(
        pdev,
        &(pdev->dcbx_info.indicate_event.remote_params),
        &remote_mib.features,
        NULL,
        0,
        LM_EVENT_CODE_DCBX_REMOTE_CHANGE,
        LM_DCBX_IE_CLASSIF_TABLE_ALOC_SIZE_REMOTE,
        lm_dcbx_ets_ieee_config_not_valid,
        NULL,
        FALSE);

    DbgBreakIf(LM_STATUS_SUCCESS != lm_status);

    return lm_status;
}
/**
 * @description
 * This function will check if local or remote parameters have
 * changed if the parameters have change the function will
 * update upper layer.
 * Local parameters can be given :
 * 1. If we read local parameters to configure the chip we
 * should use the same parameter to update upper layer (although
 * if there was a change an interrupt is expected) 2.If we are
 * from update parameters flow from upper layer ETS and clasif
 * settings are not update to chip so if they change we will
 * update function.
 * @param pdev
 * @param p_local_mib
 * @param is_ets_change
 * @param is_classif_change
 *
 * @return lm_status_t
 */
lm_status_t
lm_dcbx_ie_check_if_param_change(
    INOUT   lm_device_t             *pdev,
    IN      lldp_local_mib_t        *p_local_mib,
    IN      lldp_local_mib_ext_t    *p_local_mib_ext,
    IN      u8_t                    is_local_ets_change)
{
    lm_status_t lm_status               = LM_STATUS_SUCCESS;
    if(FALSE == pdev->dcbx_info.is_indicate_event_en)
    {
        DbgBreakMsg("lm_dcbx_runtime_params_updated_validate_pfc called but is_indicate_event_en is false");
        return LM_STATUS_FAILURE;
    }


    lm_status = lm_dcbx_ie_check_if_param_change_local(pdev,
                                                       p_local_mib,
                                                       p_local_mib_ext,
                                                       is_local_ets_change);

    DbgBreakIf(LM_STATUS_SUCCESS != lm_status);

    lm_status = lm_dcbx_ie_check_if_param_change_remote(pdev);


    DbgBreakIf(LM_STATUS_SUCCESS != lm_status);

    return lm_status;
}
/**
 *
 *
 * @author shayh (10/9/2011)
 *
 * @param pdev
 */
void lm_dcbx_ie_update_bacs_state(
    INOUT   lm_device_t *pdev,
    IN const    u32_t   flags
    )
{
    lm_dcbx_indicate_event_t *indicate_event = &pdev->dcbx_info.indicate_event;

    SET_FLAGS(indicate_event->dcb_current_oper_state_bitmap, DCB_STATE_CONFIGURED_BY_OS_QOS);

    if(GET_FLAGS(flags, DCB_PARAMS_WILLING))
    {
        SET_FLAGS(indicate_event->dcb_current_oper_state_bitmap,
                  DCB_STATE_CONFIGURED_BY_OS_QOS_TO_WILLING);
    }
    else
    {
        RESET_FLAGS(indicate_event->dcb_current_oper_state_bitmap,
                    DCB_STATE_CONFIGURED_BY_OS_QOS_TO_WILLING);
    }
}
/**
 * @description
 * 1.Update the local copy of the configuration parameters
 * 2.Set data to admin parameters (PFC settings classification
 * and PFC as willing ETS as not willing ) update MCP.
 * 3. If there are ETS or clasification changes to local
 * parameters Update HW/FW because MCP is only awre of PFC
 * changes (and will give us an interrupt if there are changes).
 * @param pdev
 * @param dcb_params
 * @param lm_cli_idx
 *
 * @return lm_status_t
 */
lm_status_t
lm_dcbx_ie_runtime_params_updated(
    INOUT       struct _lm_device_t             *pdev,
    INOUT       dcb_indicate_event_params_t     *dcb_params,
    IN const    u8_t                            lm_cli_idx)
{
    lm_dcbx_indicate_event_t *indicate_event    = &pdev->dcbx_info.indicate_event;
    lm_status_t lm_status                       = LM_STATUS_SUCCESS;
    u8_t        is_local_ets_change             = FALSE;
    u8_t        classif_change_mcp_not_aware    = FALSE;
    u8_t        is_ets_admin_updated            = FALSE;

    DbgBreakIf(lm_cli_idx != indicate_event->lm_cli_idx);

    if(FALSE == pdev->dcbx_info.is_indicate_event_en)
    {
        DbgBreakMsg("lm_dcbx_runtime_params_updated_validate_pfc called but is_indicate_event_en is false");
        return LM_STATUS_FAILURE;
    }

    /* Update admin MIB*/
    lm_status = lm_dcbx_ie_admin_mib_updated_runtime(pdev,
                                                     dcb_params,
                                                     &classif_change_mcp_not_aware,
                                                     &is_ets_admin_updated);

    if(LM_STATUS_SUCCESS != lm_status)
    {
        return lm_status;
    }

    lm_dcbx_ie_update_local_params(pdev,
                                   dcb_params,
                                   &is_local_ets_change,
                                   indicate_event->lm_cli_idx,
                                   is_ets_admin_updated
                                   );

    lm_dcbx_ie_dbg_copy_dcb_params(pdev,
                                   dcb_params,
                                   indicate_event->lm_cli_idx);

    lm_dcbx_ie_update_bacs_state(pdev,
                                 dcb_params->flags);

    if((TRUE == is_local_ets_change)||
        (TRUE == classif_change_mcp_not_aware))
    {
        // Update HW/FW with new ETS classification configuration.
        lm_status = lm_dcbx_set_params_and_read_mib(pdev,
                                                    is_local_ets_change,
                                                    TRUE);

    }

    return LM_STATUS_SUCCESS;
}
/**
 * @description
 *  Allocate indicate event bind structs.
 *  The dcb_local_params->classif_params.classif_table is RT and
 *  will be changed acording to the amount of entries that are
 *  given from upper layer.
 * @param lm_cli_idx
 *
 * @return lm_status_t
 */
lm_status_t
lm_dcbx_ie_initialize(
    INOUT       struct _lm_device_t         *pdev,
    IN const    u8_t                        lm_cli_idx)
{
    lm_dcbx_indicate_event_t *indicate_event    = &pdev->dcbx_info.indicate_event;
    const u32_t classif_table_aloc_size_local   = LM_DCBX_IE_CLASSIF_TABLE_ALOC_SIZE_LOCAL;
    const u32_t classif_table_aloc_size_remote  = LM_DCBX_IE_CLASSIF_TABLE_ALOC_SIZE_REMOTE;

    DbgBreakIf(LM_CLI_IDX_MAX != indicate_event->lm_cli_idx);
    DbgBreakIf ((0 == pdev->params.b_dcb_indicate_event));

    DbgBreakIf((NULL != indicate_event->remote_params.classif_params.classif_table) ||
               (NULL != indicate_event->local_params.classif_params.classif_table)  ||
               (NULL != indicate_event->dcb_params_given_dbg.classif_params.classif_table));

    indicate_event->lm_cli_idx = lm_cli_idx;

    // Allocate dcb_remote_params
    indicate_event->remote_params.classif_params.classif_table =
        mm_alloc_mem(pdev, classif_table_aloc_size_remote, indicate_event->lm_cli_idx);

    if(CHK_NULL(indicate_event->remote_params.classif_params.classif_table))
    {
        DbgBreakMsg("lm_dcbx_ie_alloc_bind_structs allocation failed remote ");
        return LM_STATUS_RESOURCE;
    }

    // Allocate dcb_local_params
    //The only RT memory is the local table that can include upper layer classification entries
    indicate_event->local_params.classif_params.classif_table =
        mm_alloc_mem(pdev, classif_table_aloc_size_local, indicate_event->lm_cli_idx);

    if(CHK_NULL(indicate_event->local_params.classif_params.classif_table))
    {
        DbgBreakMsg("lm_dcbx_ie_alloc_bind_structs allocation failed local ");
        return LM_STATUS_RESOURCE;
    }

    indicate_event->dcb_params_given_dbg.classif_params.classif_table =
        mm_alloc_mem(pdev, LM_DCBX_IE_CLASSIF_TABLE_ALOC_SIZE_DBG, indicate_event->lm_cli_idx);

    if(CHK_NULL(indicate_event->dcb_params_given_dbg.classif_params.classif_table))
    {
        DbgBreakMsg("lm_dcbx_ie_alloc_bind_structs allocation failed given DBG");
        return LM_STATUS_RESOURCE;
    }

    return LM_STATUS_SUCCESS;
}
/**
 * @description
 * Free indicate event structs that were allocated by RT.
 * This code must be done from LPME while is_indicate_event_en
 * is still valid to avoid a race.
 * @param lm_cli_idx
 *
 * @return void
 */
void
lm_dcbx_ie_deinitialize(
    INOUT       struct _lm_device_t         *pdev,
    IN const    u8_t                        lm_cli_idx)
{
    lm_dcbx_indicate_event_t    *indicate_event     = &pdev->dcbx_info.indicate_event;

    DbgBreakIf(lm_cli_idx != indicate_event->lm_cli_idx);

    DbgBreakIf(NULL == indicate_event->local_params.classif_params.classif_table);
    DbgBreakIf(NULL == indicate_event->remote_params.classif_params.classif_table);
    DbgBreakIf(NULL == indicate_event->dcb_params_given_dbg.classif_params.classif_table);

    lm_dcbx_ie_init_params(pdev, FALSE);
}
