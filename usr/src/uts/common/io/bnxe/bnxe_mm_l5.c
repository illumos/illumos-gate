/*
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
 */

/*
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
 */

#include "bnxe.h"


lm_status_t
mm_sc_comp_l5_request(
        IN struct _lm_device_t *pdev,
        IN struct iscsi_kcqe *kcqes,
        IN u32_t num_kcqes
        )
{
    BnxeDbgBreak((um_device_t *)pdev);
    return 0;
}


lm_status_t
mm_fc_comp_request(
    IN struct _lm_device_t          *pdev,
    IN struct fcoe_kcqe             *kcqes,
    IN u32_t                        num_kcqes)
{
    return (!BnxeFcoeCompRequestCqe((um_device_t *)pdev, kcqes, num_kcqes)) ?
               LM_STATUS_FAILURE : LM_STATUS_SUCCESS;
}


lm_status_t mm_sc_complete_init_request(lm_device_t *pdev, struct iscsi_kcqe *kcqe)
{
    BnxeDbgBreak((um_device_t *)pdev);
    return 0;
}


u8_t
mm_sc_is_omgr_enabled(struct _lm_device_t *_pdev)
{
    BnxeDbgBreak((um_device_t *)_pdev);
    return 0;
}


lm_status_t
mm_sc_omgr_flush_rx(
    IN struct _lm_device_t      *_pdev,
    IN struct iscsi_kcqe        *kcqe_recv,
    IN u32_t                     cid)
{
    BnxeDbgBreak((um_device_t *)_pdev);
    return 0;
}


lm_status_t mm_sc_complete_update_request(lm_device_t *pdev, struct iscsi_kcqe *kcqe)
{
    BnxeDbgBreak((um_device_t *)pdev);
    return 0;
}


lm_status_t
mm_fc_complete_init_request(
    IN    lm_device_t               *pdev,
    IN    struct fcoe_kcqe          *kcqe)
{
    return (!BnxeFcoeInitCqe((um_device_t *)pdev, kcqe)) ?
               LM_STATUS_FAILURE : LM_STATUS_SUCCESS;
}


lm_status_t
mm_fc_complete_destroy_request(
    IN    lm_device_t               *pdev,
    IN    struct fcoe_kcqe          *kcqe)
{
    return (!BnxeFcoeDestroyCqe((um_device_t *)pdev, kcqe)) ?
               LM_STATUS_FAILURE : LM_STATUS_SUCCESS;
}


lm_status_t
mm_fc_complete_ofld_request(
    IN    lm_device_t               *pdev,
    IN    lm_fcoe_state_t           *fcoe,
    IN    struct fcoe_kcqe          *kcqe)
{
    return (!BnxeFcoeOffloadConnCqe((um_device_t *)pdev,
                                    (BnxeFcoeState *)fcoe,
                                    kcqe)) ?
               LM_STATUS_FAILURE : LM_STATUS_SUCCESS;
}


lm_status_t
mm_fc_complete_enable_request(
    IN    lm_device_t               *pdev,
    IN    lm_fcoe_state_t           *fcoe,
    IN    struct fcoe_kcqe          *kcqe)
{
    return (!BnxeFcoeEnableConnCqe((um_device_t *)pdev,
                                   (BnxeFcoeState *)fcoe,
                                   kcqe)) ?
               LM_STATUS_FAILURE : LM_STATUS_SUCCESS;
}


lm_status_t
mm_fc_complete_stat_request(
    IN    lm_device_t               *pdev,
    IN    struct fcoe_kcqe          *kcqe)
{
    return (!BnxeFcoeStatCqe((um_device_t *)pdev, kcqe)) ?
               LM_STATUS_FAILURE : LM_STATUS_SUCCESS;
}


lm_status_t
mm_fc_complete_disable_request(
    IN    lm_device_t               *pdev,
    IN    lm_fcoe_state_t           *fcoe,
    IN    struct fcoe_kcqe          *kcqe)
{
    return (!BnxeFcoeDisableConnCqe((um_device_t *)pdev,
                                    (BnxeFcoeState *)fcoe,
                                    kcqe)) ?
               LM_STATUS_FAILURE : LM_STATUS_SUCCESS;
}


lm_status_t
mm_fc_complete_terminate_request(
    IN    lm_device_t               *pdev,
    IN    lm_fcoe_state_t           *fcoe,
    IN    struct fcoe_kcqe          *kcqe)
{
    return (!BnxeFcoeDestroyConnCqe((um_device_t *)pdev,
                                    (BnxeFcoeState *)fcoe,
                                    kcqe)) ?
               LM_STATUS_FAILURE : LM_STATUS_SUCCESS;
}


lm_status_t mm_sc_complete_offload_request(
    IN    lm_device_t                *pdev,
    IN    lm_iscsi_state_t           *iscsi,
    IN    lm_status_t                 comp_status
    )
{
    BnxeDbgBreak((um_device_t *)pdev);
    return 0;
}

