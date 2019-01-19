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


#define VERIFY_FCOE_BINDING(pUM)                                  \
    if (!BNXE_FCOE(pUM))                                          \
    {                                                             \
        BnxeLogWarn((pUM), "FCoE not supported on this device!"); \
        return B_FALSE;                                           \
    }                                                             \
    if (!(CLIENT_BOUND(pUM, LM_CLI_IDX_FCOE)))                    \
    {                                                             \
        BnxeLogWarn((pUM), "FCoE client not bound!");             \
        return B_FALSE;                                           \
    }


void BnxeFcoeFreeResc(um_device_t *   pUM,
                      BnxeFcoeState * pFcoeState)
{
    BNXE_LOCK_ENTER_OFFLOAD(pUM);
    lm_fc_del_fcoe_state(&pUM->lm_dev, &pFcoeState->lm_fcoe);
    BNXE_LOCK_EXIT_OFFLOAD(pUM);

    lm_fc_free_con_resc(&pUM->lm_dev, &pFcoeState->lm_fcoe);

    kmem_free(pFcoeState, sizeof(BnxeFcoeState));
}


static boolean_t BnxeFcoeCqeIndicate(um_device_t * pUM,
                                     void *        pData,
                                     u32_t         dataLen)
{
    struct fcoe_kcqe * kcqe = (struct fcoe_kcqe *)pData;

    if (dataLen != (sizeof(*kcqe)))
    {
        BnxeLogWarn(pUM, "Invalid FCoE CQE");
        return B_FALSE;
    }

    /* XXX
     * Need to add a mutex or reference count to ensure that bnxef isn't
     * unloaded underneath this taskq dispatch routine.
     */

    ASSERT(CLIENT_BOUND(pUM, LM_CLI_IDX_FCOE));
    pUM->fcoe.bind.cliIndicateCqes(pUM->fcoe.pDev,
                                   (void **)&kcqe, 1);

    /* XXX release mutex or decrement reference count */

    return B_TRUE;
}


static void BnxeFcoeInitCqeWork(um_device_t * pUM,
                                void *        pData,
                                u32_t         dataLen)
{
    if (!BnxeFcoeCqeIndicate(pUM, pData, dataLen))
    {
        pUM->fcoe.stats.initCqeRxErr++;
    }
    else
    {
        pUM->fcoe.stats.initCqeRx++;
    }
}


boolean_t BnxeFcoeInitCqe(um_device_t *      pUM,
                          struct fcoe_kcqe * kcqe)
{
    struct fcoe_kcqe tmp_kcqe = {0};

    tmp_kcqe.op_code = FCOE_KCQE_OPCODE_INIT_FUNC;

    tmp_kcqe.flags |=
        (FCOE_KWQE_LAYER_CODE << FCOE_KWQE_HEADER_LAYER_CODE_SHIFT);

    tmp_kcqe.completion_status =
        mm_cpu_to_le32((mm_le32_to_cpu(kcqe->completion_status) == 0) ?
                           FCOE_KCQE_COMPLETION_STATUS_SUCCESS :
                           FCOE_KCQE_COMPLETION_STATUS_NIC_ERROR);

    return BnxeWorkQueueAdd(pUM, BnxeFcoeInitCqeWork,
                            &tmp_kcqe, sizeof(tmp_kcqe));
}


static void BnxeFcoeInitWqeWork(um_device_t * pUM,
                                void *        pData,
                                u32_t         dataLen)
{
    union fcoe_kwqe * kwqe = (union fcoe_kwqe *)pData;
    struct fcoe_kcqe  kcqe  = {0};

    if (dataLen != (3 * sizeof(*kwqe)))
    {
        BnxeLogWarn(pUM, "Invalid FCoE Init WQE");
        pUM->fcoe.stats.initWqeTxErr++;
        return;
    }

    if (kwqe[1].init2.hsi_major_version != FCOE_HSI_MAJOR_VERSION)
    {
        BnxeLogWarn(pUM, "ERROR: Invalid FCoE HSI major version (L5=%d vs FW=%d)",
                    kwqe[1].init2.hsi_major_version,
                    FCOE_HSI_MAJOR_VERSION);
        kcqe.completion_status = FCOE_KCQE_COMPLETION_STATUS_WRONG_HSI_VERSION;
        goto BnxeFcoeInitWqeWork_error;
    }

    if (lm_fc_init(&pUM->lm_dev,
                   &kwqe[0].init1,
                   &kwqe[1].init2,
                   &kwqe[2].init3) != LM_STATUS_SUCCESS)
    {
        BnxeLogWarn(pUM, "Failed to post FCoE Init WQE");
        kcqe.completion_status = FCOE_KCQE_COMPLETION_STATUS_ERROR;
        goto BnxeFcoeInitWqeWork_error;
    }

    pUM->fcoe.stats.initWqeTx++;

    return;

BnxeFcoeInitWqeWork_error:

    pUM->fcoe.stats.initWqeTxErr++;

    kcqe.op_code = FCOE_KCQE_OPCODE_INIT_FUNC;
    kcqe.flags |= (FCOE_KWQE_LAYER_CODE << FCOE_KWQE_HEADER_LAYER_CODE_SHIFT);
    kcqe.completion_status = mm_cpu_to_le32(kcqe.completion_status);
    kcqe.fcoe_conn_id = kwqe[1].conn_offload1.fcoe_conn_id;

    /* call here directly (for error case) */

    /* XXX
     * Need to add a mutex or reference count to ensure that bnxef isn't
     * unloaded underneath this taskq dispatch routine.
     */

    {
        struct fcoe_kcqe * pKcqe = &kcqe;
        ASSERT(CLIENT_BOUND(pUM, LM_CLI_IDX_FCOE));
        pUM->fcoe.bind.cliIndicateCqes(pUM->fcoe.pDev,
                                       (void **)&pKcqe, 1);
    }

    /* XXX release mutex or decrement reference count */
}


static boolean_t BnxeFcoeInitWqe(um_device_t *      pUM,
                                 union fcoe_kwqe ** kwqes)
{
    union fcoe_kwqe wqe[3];

    wqe[0] =*(kwqes[0]);
    wqe[1] =*(kwqes[1]);
    wqe[2] =*(kwqes[2]);

    return BnxeWorkQueueAdd(pUM, BnxeFcoeInitWqeWork, wqe, sizeof(wqe));
}


static void BnxeFcoeOffloadConnCqeWork(um_device_t * pUM,
                                       void *        pData,
                                       u32_t         dataLen)
{
    if (!BnxeFcoeCqeIndicate(pUM, pData, dataLen))
    {
        pUM->fcoe.stats.offloadConnCqeRxErr++;
    }
    else
    {
        pUM->fcoe.stats.offloadConnCqeRx++;
    }
}


boolean_t BnxeFcoeOffloadConnCqe(um_device_t *      pUM,
                                 BnxeFcoeState *    pFcoeState,
                                 struct fcoe_kcqe * kcqe)
{
    struct fcoe_kcqe tmp_kcqe = {0};

    tmp_kcqe.op_code = FCOE_KCQE_OPCODE_OFFLOAD_CONN;

    tmp_kcqe.flags |=
        (FCOE_KWQE_LAYER_CODE << FCOE_KWQE_HEADER_LAYER_CODE_SHIFT);

    tmp_kcqe.fcoe_conn_context_id = kcqe->fcoe_conn_context_id;
    tmp_kcqe.fcoe_conn_id         = kcqe->fcoe_conn_id;

    tmp_kcqe.completion_status =
        mm_cpu_to_le32((mm_le32_to_cpu(kcqe->completion_status) == 0) ?
                           FCOE_KCQE_COMPLETION_STATUS_SUCCESS :
                           FCOE_KCQE_COMPLETION_STATUS_CTX_ALLOC_FAILURE);

    if (pFcoeState != NULL)
    {
        pFcoeState->lm_fcoe.hdr.status =
            (mm_le32_to_cpu(kcqe->completion_status) == 0) ?
                STATE_STATUS_NORMAL :
                STATE_STATUS_INIT_OFFLOAD_ERR;
    }

    return BnxeWorkQueueAdd(pUM, BnxeFcoeOffloadConnCqeWork,
                            &tmp_kcqe, sizeof(tmp_kcqe));
}


static void BnxeFcoeOffloadConnWqeWork(um_device_t * pUM,
                                       void *        pData,
                                       u32_t         dataLen)
{
    union fcoe_kwqe * kwqe = (union fcoe_kwqe *)pData;
    struct fcoe_kcqe  kcqe = {0};
    BnxeFcoeState *   pFcoeState;
    lm_status_t       rc;

    if (dataLen != (4 * sizeof(*kwqe)))
    {
        BnxeLogWarn(pUM, "Invalid FCoE Offload Conn WQE");
        pUM->fcoe.stats.offloadConnWqeTxErr++;
        return;
    }

    if ((pFcoeState = kmem_zalloc(sizeof(BnxeFcoeState),
                                  KM_NOSLEEP)) == NULL)
    {
        BnxeLogWarn(pUM, "Failed to allocate memory for FCoE state");
        goto BnxeFcoeOffloadConnWqeWork_error;
    }

    BNXE_LOCK_ENTER_OFFLOAD(pUM);
    rc = lm_fc_init_fcoe_state(&pUM->lm_dev,
                               &pUM->lm_dev.fcoe_info.run_time.state_blk,
                               &pFcoeState->lm_fcoe);
    BNXE_LOCK_EXIT_OFFLOAD(pUM);

    if (rc != LM_STATUS_SUCCESS)
    {
        kmem_free(pFcoeState, sizeof(BnxeFcoeState));

        BnxeLogWarn(pUM, "Failed to initialize FCoE state");
        goto BnxeFcoeOffloadConnWqeWork_error;
    }

    pFcoeState->lm_fcoe.ofld1 = kwqe[0].conn_offload1;
    pFcoeState->lm_fcoe.ofld2 = kwqe[1].conn_offload2;
    pFcoeState->lm_fcoe.ofld3 = kwqe[2].conn_offload3;
    pFcoeState->lm_fcoe.ofld4 = kwqe[3].conn_offload4;

    rc = lm_fc_alloc_con_resc(&pUM->lm_dev, &pFcoeState->lm_fcoe);

    if (rc == LM_STATUS_SUCCESS)
    {
        lm_fc_init_fcoe_context(&pUM->lm_dev, &pFcoeState->lm_fcoe);
        lm_fc_post_offload_ramrod(&pUM->lm_dev, &pFcoeState->lm_fcoe);
    }
    else if (rc == LM_STATUS_PENDING)
    {
        /*
         * the cid is pending - its too soon to initialize the context, it will
         * be initialized from the recycle cid callback and completed as well.
         */
        BnxeLogInfo(pUM, "lm_fc_alloc_con_resc returned pending?");
    }
    else
    {
        BnxeFcoeFreeResc(pUM, pFcoeState);
        BnxeLogInfo(pUM, "lm_fc_alloc_con_resc failed (%d)", rc);
        goto BnxeFcoeOffloadConnWqeWork_error;
    }

    pUM->fcoe.stats.offloadConnWqeTx++;

    return;

BnxeFcoeOffloadConnWqeWork_error:

    pUM->fcoe.stats.offloadConnWqeTxErr++;

    kcqe.op_code = FCOE_KCQE_OPCODE_OFFLOAD_CONN;
    kcqe.flags |= (FCOE_KWQE_LAYER_CODE << FCOE_KWQE_HEADER_LAYER_CODE_SHIFT);
    kcqe.completion_status = mm_cpu_to_le32(FCOE_KCQE_COMPLETION_STATUS_CTX_ALLOC_FAILURE);
    kcqe.fcoe_conn_id = kwqe[0].conn_offload1.fcoe_conn_id;

    /* call here directly (for error case) */

    /* XXX
     * Need to add a mutex or reference count to ensure that bnxef isn't
     * unloaded underneath this taskq dispatch routine.
     */

    {
        struct fcoe_kcqe * pKcqe = &kcqe;
        ASSERT(CLIENT_BOUND(pUM, LM_CLI_IDX_FCOE));
        pUM->fcoe.bind.cliIndicateCqes(pUM->fcoe.pDev,
                                       (void **)&pKcqe, 1);
    }

    /* XXX release mutex or decrement reference count */
}


static boolean_t BnxeFcoeOffloadConnWqe(um_device_t *      pUM,
                                        union fcoe_kwqe ** kwqes)
{
    union fcoe_kwqe wqe[4];

    wqe[0] =*(kwqes[0]);
    wqe[1] =*(kwqes[1]);
    wqe[2] =*(kwqes[2]);
    wqe[3] =*(kwqes[3]);

    return BnxeWorkQueueAdd(pUM, BnxeFcoeOffloadConnWqeWork,
                            wqe, sizeof(wqe));
}


static void BnxeFcoeEnableConnCqeWork(um_device_t * pUM,
                                      void *        pData,
                                      u32_t         dataLen)
{
    if (!BnxeFcoeCqeIndicate(pUM, pData, dataLen))
    {
        pUM->fcoe.stats.enableConnCqeRxErr++;
    }
    else
    {
        pUM->fcoe.stats.enableConnCqeRx++;
    }
}


boolean_t BnxeFcoeEnableConnCqe(um_device_t *      pUM,
                                BnxeFcoeState *    pFcoeState,
                                struct fcoe_kcqe * kcqe)
{
    struct fcoe_kcqe tmp_kcqe = {0};

    tmp_kcqe.op_code = FCOE_KCQE_OPCODE_ENABLE_CONN;

    tmp_kcqe.flags |=
        (FCOE_KWQE_LAYER_CODE << FCOE_KWQE_HEADER_LAYER_CODE_SHIFT);

    tmp_kcqe.fcoe_conn_context_id = kcqe->fcoe_conn_context_id;
    tmp_kcqe.fcoe_conn_id         = kcqe->fcoe_conn_id;

    tmp_kcqe.completion_status =
        mm_cpu_to_le32((mm_le32_to_cpu(kcqe->completion_status) == 0) ?
                           FCOE_KCQE_COMPLETION_STATUS_SUCCESS :
                           FCOE_KCQE_COMPLETION_STATUS_CTX_ALLOC_FAILURE);

    if (pFcoeState != NULL)
    {
        pFcoeState->lm_fcoe.hdr.status =
            (mm_le32_to_cpu(kcqe->completion_status) == 0) ?
                STATE_STATUS_NORMAL :
                STATE_STATUS_INIT_OFFLOAD_ERR;
    }

    return BnxeWorkQueueAdd(pUM, BnxeFcoeEnableConnCqeWork,
                            &tmp_kcqe, sizeof(tmp_kcqe));
}


static void BnxeFcoeEnableConnWqeWork(um_device_t * pUM,
                                      void *        pData,
                                      u32_t         dataLen)
{
    union fcoe_kwqe * kwqe = (union fcoe_kwqe *)pData;
    struct fcoe_kcqe  kcqe = {0};
    BnxeFcoeState *   pFcoeState;

    if (dataLen != sizeof(*kwqe))
    {
        BnxeLogWarn(pUM, "Invalid FCoE Enable Conn WQE");
        pUM->fcoe.stats.enableConnWqeTxErr++;
        return;
    }

    pFcoeState =
        lm_cid_cookie(&pUM->lm_dev,
                      FCOE_CONNECTION_TYPE,
                      SW_CID(mm_le32_to_cpu(kwqe->conn_enable_disable.context_id)));

    if (pFcoeState == NULL)
    {
        goto BnxeFcoeEnableConnWqeWork_error;
    }

    if (lm_fc_post_enable_ramrod(&pUM->lm_dev,
                                 &pFcoeState->lm_fcoe,
                                 &kwqe->conn_enable_disable) !=
        LM_STATUS_SUCCESS)
    {
        goto BnxeFcoeEnableConnWqeWork_error;
    }

    pUM->fcoe.stats.enableConnWqeTx++;

    return;

BnxeFcoeEnableConnWqeWork_error:

    pUM->fcoe.stats.enableConnWqeTxErr++;

    BnxeLogWarn(pUM, "Failed to post FCoE Enable Conn WQE");

    kcqe.op_code = FCOE_KCQE_OPCODE_ENABLE_CONN;
    kcqe.flags |= (FCOE_KWQE_LAYER_CODE << FCOE_KWQE_HEADER_LAYER_CODE_SHIFT);
    kcqe.fcoe_conn_context_id = kwqe->conn_enable_disable.context_id;
    kcqe.completion_status = mm_cpu_to_le32(FCOE_KCQE_COMPLETION_STATUS_NIC_ERROR);

    /* call here directly (for error case) */

    /* XXX
     * Need to add a mutex or reference count to ensure that bnxef isn't
     * unloaded underneath this taskq dispatch routine.
     */

    {
        struct fcoe_kcqe * pKcqe = &kcqe;
        ASSERT(CLIENT_BOUND(pUM, LM_CLI_IDX_FCOE));
        pUM->fcoe.bind.cliIndicateCqes(pUM->fcoe.pDev,
                                       (void **)&pKcqe, 1);
    }

    /* XXX release mutex or decrement reference count */
}


static boolean_t BnxeFcoeEnableConnWqe(um_device_t *      pUM,
                                       union fcoe_kwqe ** kwqes)
{
    return BnxeWorkQueueAdd(pUM, BnxeFcoeEnableConnWqeWork,
                            kwqes[0], sizeof(*(kwqes[0])));
}


static void BnxeFcoeDisableConnCqeWork(um_device_t * pUM,
                                       void *        pData,
                                       u32_t         dataLen)
{
    if (!BnxeFcoeCqeIndicate(pUM, pData, dataLen))
    {
        pUM->fcoe.stats.disableConnCqeRxErr++;
    }
    else
    {
        pUM->fcoe.stats.disableConnCqeRx++;
    }
}


boolean_t BnxeFcoeDisableConnCqe(um_device_t *      pUM,
                                 BnxeFcoeState *    pFcoeState,
                                 struct fcoe_kcqe * kcqe)
{
    struct fcoe_kcqe tmp_kcqe = {0};

    tmp_kcqe.op_code = FCOE_KCQE_OPCODE_DISABLE_CONN;

    tmp_kcqe.flags |=
        (FCOE_KWQE_LAYER_CODE << FCOE_KWQE_HEADER_LAYER_CODE_SHIFT);

    tmp_kcqe.fcoe_conn_context_id = kcqe->fcoe_conn_context_id;
    tmp_kcqe.fcoe_conn_id         = kcqe->fcoe_conn_id;

    tmp_kcqe.completion_status =
        mm_cpu_to_le32((mm_le32_to_cpu(kcqe->completion_status) == 0) ?
                           FCOE_KCQE_COMPLETION_STATUS_SUCCESS :
                           FCOE_KCQE_COMPLETION_STATUS_NIC_ERROR);

    if (pFcoeState != NULL)
    {
        pFcoeState->lm_fcoe.hdr.status =
            (mm_le32_to_cpu(kcqe->completion_status) == 0) ?
                STATE_STATUS_NORMAL :
                STATE_STATUS_INIT_OFFLOAD_ERR;
    }

    return BnxeWorkQueueAdd(pUM, BnxeFcoeDisableConnCqeWork,
                            &tmp_kcqe, sizeof(tmp_kcqe));
}


static void BnxeFcoeDisableConnWqeWork(um_device_t * pUM,
                                       void *        pData,
                                       u32_t         dataLen)
{
    union fcoe_kwqe * kwqe = (union fcoe_kwqe *)pData;
    struct fcoe_kcqe  kcqe = {0};
    BnxeFcoeState *   pFcoeState;

    if (dataLen != sizeof(*kwqe))
    {
        BnxeLogWarn(pUM, "Invalid FCoE Disable Conn WQE");
        pUM->fcoe.stats.disableConnWqeTxErr++;
        return;
    }

    pFcoeState =
        lm_cid_cookie(&pUM->lm_dev,
                      FCOE_CONNECTION_TYPE,
                      SW_CID(mm_le32_to_cpu(kwqe->conn_enable_disable.context_id)));

    if (pFcoeState == NULL)
    {
        goto BnxeFcoeDisableConnWqeWork_error;
    }

    if (lm_fc_post_disable_ramrod(&pUM->lm_dev,
                                  &pFcoeState->lm_fcoe,
                                  &kwqe->conn_enable_disable) !=
        LM_STATUS_SUCCESS)
    {
        goto BnxeFcoeDisableConnWqeWork_error;
    }

    pUM->fcoe.stats.disableConnWqeTx++;

    return;

BnxeFcoeDisableConnWqeWork_error:

    pUM->fcoe.stats.disableConnWqeTxErr++;

    BnxeLogWarn(pUM, "Failed to post FCoE Disable Conn WQE");

    kcqe.op_code = FCOE_KCQE_OPCODE_DISABLE_CONN;
    kcqe.flags |= (FCOE_KWQE_LAYER_CODE << FCOE_KWQE_HEADER_LAYER_CODE_SHIFT);
    kcqe.fcoe_conn_context_id = kwqe->conn_enable_disable.context_id;
    kcqe.completion_status = mm_cpu_to_le32(FCOE_KCQE_COMPLETION_STATUS_NIC_ERROR);

    /* call here directly (for error case) */

    /* XXX
     * Need to add a mutex or reference count to ensure that bnxef isn't
     * unloaded underneath this taskq dispatch routine.
     */

    {
        struct fcoe_kcqe * pKcqe = &kcqe;
        ASSERT(CLIENT_BOUND(pUM, LM_CLI_IDX_FCOE));
        pUM->fcoe.bind.cliIndicateCqes(pUM->fcoe.pDev,
                                       (void **)&pKcqe, 1);
    }

    /* XXX release mutex or decrement reference count */
}


static boolean_t BnxeFcoeDisableConnWqe(um_device_t *      pUM,
                                       union fcoe_kwqe ** kwqes)
{
    return BnxeWorkQueueAdd(pUM, BnxeFcoeDisableConnWqeWork,
                            kwqes[0], sizeof(*(kwqes[0])));
}


static void BnxeFcoeDestroyConnCqeWork(um_device_t * pUM,
                                       void *        pData,
                                       u32_t         dataLen)
{
    struct fcoe_kcqe * kcqe = (struct fcoe_kcqe *)pData;
    BnxeFcoeState *    pFcoeState;

    if (dataLen != (sizeof(*kcqe)))
    {
        BnxeLogWarn(pUM, "Invalid FCoE Destroy Conn CQE");
        pUM->fcoe.stats.destroyConnCqeRxErr++;
        return;
    }

    pFcoeState =
        lm_cid_cookie(&pUM->lm_dev,
                      FCOE_CONNECTION_TYPE,
                      SW_CID(mm_le32_to_cpu(kcqe->fcoe_conn_context_id)));

    BnxeFcoeFreeResc(pUM, pFcoeState);

    if (!BnxeFcoeCqeIndicate(pUM, pData, dataLen))
    {
        pUM->fcoe.stats.destroyConnCqeRxErr++;
    }
    else
    {
        pUM->fcoe.stats.destroyConnCqeRx++;
    }
}


boolean_t BnxeFcoeDestroyConnCqe(um_device_t *      pUM,
                                 BnxeFcoeState *    pFcoeState,
                                 struct fcoe_kcqe * kcqe)
{
    struct fcoe_kcqe tmp_kcqe = {0};

    tmp_kcqe.op_code = FCOE_KCQE_OPCODE_DESTROY_CONN;

    tmp_kcqe.flags |=
        (FCOE_KWQE_LAYER_CODE << FCOE_KWQE_HEADER_LAYER_CODE_SHIFT);

    tmp_kcqe.fcoe_conn_context_id = kcqe->fcoe_conn_context_id;
    tmp_kcqe.fcoe_conn_id         = kcqe->fcoe_conn_id;

    tmp_kcqe.completion_status =
        mm_cpu_to_le32((mm_le32_to_cpu(kcqe->completion_status) == 0) ?
                           FCOE_KCQE_COMPLETION_STATUS_SUCCESS :
                           FCOE_KCQE_COMPLETION_STATUS_NIC_ERROR);

    if (pFcoeState != NULL)
    {
        pFcoeState->lm_fcoe.hdr.status =
            (mm_le32_to_cpu(kcqe->completion_status) == 0) ?
                STATE_STATUS_NORMAL :
                STATE_STATUS_INIT_OFFLOAD_ERR;
    }

    return BnxeWorkQueueAdd(pUM, BnxeFcoeDestroyConnCqeWork,
                            &tmp_kcqe, sizeof(tmp_kcqe));
}


static void BnxeFcoeDestroyConnWqeWork(um_device_t * pUM,
                                       void *        pData,
                                       u32_t         dataLen)
{
    union fcoe_kwqe * kwqe = (union fcoe_kwqe *)pData;
    struct fcoe_kcqe  kcqe = {0};
    BnxeFcoeState *   pFcoeState;

    if (dataLen != sizeof(*kwqe))
    {
        BnxeLogWarn(pUM, "Invalid FCoE Destroy Conn WQE");
        pUM->fcoe.stats.destroyConnWqeTxErr++;
        return;
    }

    pFcoeState =
        lm_cid_cookie(&pUM->lm_dev,
                      FCOE_CONNECTION_TYPE,
                      SW_CID(mm_le32_to_cpu(kwqe->conn_destroy.context_id)));

    if (pFcoeState == NULL)
    {
        goto BnxeFcoeDestroyConnWqeWork_error;
    }

    if (lm_fc_post_terminate_ramrod(&pUM->lm_dev,
                                    &pFcoeState->lm_fcoe) !=
        LM_STATUS_SUCCESS)
    {
        goto BnxeFcoeDestroyConnWqeWork_error;
    }

    pUM->fcoe.stats.destroyConnWqeTx++;

    return;

BnxeFcoeDestroyConnWqeWork_error:

    pUM->fcoe.stats.destroyConnWqeTxErr++;

    BnxeLogWarn(pUM, "Failed to post FCoE Destroy Conn WQE");

    kcqe.op_code = FCOE_KCQE_OPCODE_DESTROY_CONN;
    kcqe.flags |= (FCOE_KWQE_LAYER_CODE << FCOE_KWQE_HEADER_LAYER_CODE_SHIFT);
    kcqe.fcoe_conn_context_id = kwqe->conn_destroy.context_id;
    kcqe.fcoe_conn_id         = kwqe->conn_destroy.conn_id;
    kcqe.completion_status = mm_cpu_to_le32(FCOE_KCQE_COMPLETION_STATUS_NIC_ERROR);

    /* call here directly (for error case) */

    /* XXX
     * Need to add a mutex or reference count to ensure that bnxef isn't
     * unloaded underneath this taskq dispatch routine.
     */

    {
        struct fcoe_kcqe * pKcqe = &kcqe;
        ASSERT(CLIENT_BOUND(pUM, LM_CLI_IDX_FCOE));
        pUM->fcoe.bind.cliIndicateCqes(pUM->fcoe.pDev,
                                       (void **)&pKcqe, 1);
    }

    /* XXX release mutex or decrement reference count */
}


static boolean_t BnxeFcoeDestroyConnWqe(um_device_t *      pUM,
                                       union fcoe_kwqe ** kwqes)
{
    return BnxeWorkQueueAdd(pUM, BnxeFcoeDestroyConnWqeWork,
                            kwqes[0], sizeof(*(kwqes[0])));
}


static void BnxeFcoeDestroyCqeWork(um_device_t * pUM,
                                   void *        pData,
                                   u32_t         dataLen)
{
    if (!BnxeFcoeCqeIndicate(pUM, pData, dataLen))
    {
        pUM->fcoe.stats.destroyCqeRxErr++;
    }
    else
    {
        pUM->fcoe.stats.destroyCqeRx++;
    }
}


boolean_t BnxeFcoeDestroyCqe(um_device_t *      pUM,
                             struct fcoe_kcqe * kcqe)
{
    struct fcoe_kcqe tmp_kcqe = {0};

    tmp_kcqe.op_code = FCOE_KCQE_OPCODE_DESTROY_FUNC;

    tmp_kcqe.flags |=
        (FCOE_KWQE_LAYER_CODE << FCOE_KWQE_HEADER_LAYER_CODE_SHIFT);

    tmp_kcqe.completion_status =
        mm_le32_to_cpu((mm_le32_to_cpu(kcqe->completion_status) == 0) ?
                           FCOE_KCQE_COMPLETION_STATUS_SUCCESS :
                           FCOE_KCQE_COMPLETION_STATUS_NIC_ERROR);

    return BnxeWorkQueueAdd(pUM, BnxeFcoeDestroyCqeWork,
                            &tmp_kcqe, sizeof(tmp_kcqe));
}


static void BnxeFcoeDestroyWqeWork(um_device_t * pUM,
                                   void *        pData,
                                   u32_t         dataLen)
{
    union fcoe_kwqe * kwqe = (union fcoe_kwqe *)pData;
    struct fcoe_kcqe  kcqe = {0};
    BnxeFcoeState *   pFcoeState;

    if (dataLen != sizeof(*kwqe))
    {
        BnxeLogWarn(pUM, "Invalid FCoE Destroy WQE");
        pUM->fcoe.stats.destroyWqeTxErr++;
        return;
    }

    if (lm_fc_post_destroy_ramrod(&pUM->lm_dev) == LM_STATUS_SUCCESS)
    {
        pUM->fcoe.stats.destroyWqeTx++;
        return;
    }

    pUM->fcoe.stats.destroyWqeTxErr++;

    BnxeLogWarn(pUM, "Failed to post FCoE Destroy WQE");

    kcqe.op_code = FCOE_KCQE_OPCODE_DESTROY_FUNC;
    kcqe.flags |= (FCOE_KWQE_LAYER_CODE << FCOE_KWQE_HEADER_LAYER_CODE_SHIFT);
    kcqe.completion_status = mm_cpu_to_le32(FCOE_KCQE_COMPLETION_STATUS_NIC_ERROR);

    /* call here directly (for error case) */

    /* XXX
     * Need to add a mutex or reference count to ensure that bnxef isn't
     * unloaded underneath this taskq dispatch routine.
     */

    {
        struct fcoe_kcqe * pKcqe = &kcqe;
        ASSERT(CLIENT_BOUND(pUM, LM_CLI_IDX_FCOE));
        pUM->fcoe.bind.cliIndicateCqes(pUM->fcoe.pDev,
                                       (void **)&pKcqe, 1);
    }

    /* XXX release mutex or decrement reference count */
}


static boolean_t BnxeFcoeDestroyWqe(um_device_t *      pUM,
                                    union fcoe_kwqe ** kwqes)
{
    return BnxeWorkQueueAdd(pUM, BnxeFcoeDestroyWqeWork,
                            kwqes[0], sizeof(*(kwqes[0])));
}


static void BnxeFcoeStatCqeWork(um_device_t * pUM,
                                void *        pData,
                                u32_t         dataLen)
{
    if (!BnxeFcoeCqeIndicate(pUM, pData, dataLen))
    {
        pUM->fcoe.stats.statCqeRxErr++;
    }
    else
    {
        pUM->fcoe.stats.statCqeRx++;
    }
}


boolean_t BnxeFcoeStatCqe(um_device_t *      pUM,
                          struct fcoe_kcqe * kcqe)
{
    struct fcoe_kcqe tmp_kcqe = {0};

    tmp_kcqe.op_code = FCOE_KCQE_OPCODE_STAT_FUNC;

    tmp_kcqe.flags |=
        (FCOE_KWQE_LAYER_CODE << FCOE_KWQE_HEADER_LAYER_CODE_SHIFT);

    tmp_kcqe.completion_status =
        mm_cpu_to_le32((mm_le32_to_cpu(kcqe->completion_status) == 0) ?
                           FCOE_KCQE_COMPLETION_STATUS_SUCCESS :
                           FCOE_KCQE_COMPLETION_STATUS_NIC_ERROR);

    return BnxeWorkQueueAdd(pUM, BnxeFcoeStatCqeWork,
                            &tmp_kcqe, sizeof(tmp_kcqe));
}


static void BnxeFcoeStatWqeWork(um_device_t * pUM,
                                void *        pData,
                                u32_t         dataLen)
{
    union fcoe_kwqe * kwqe = (union fcoe_kwqe *)pData;
    struct fcoe_kcqe  kcqe = {0};

    if (dataLen != sizeof(*kwqe))
    {
        BnxeLogWarn(pUM, "Invalid FCoE Stat WQE");
        pUM->fcoe.stats.statWqeTxErr++;
        return;
    }

    if (lm_fc_post_stat_ramrod(&pUM->lm_dev,
                               &kwqe->statistics) == LM_STATUS_SUCCESS)
    {
        pUM->fcoe.stats.statWqeTx++;
        return;
    }

    pUM->fcoe.stats.statWqeTxErr++;

    BnxeLogWarn(pUM, "Failed to post FCoE Stat WQE");

    kcqe.op_code = FCOE_KCQE_OPCODE_STAT_FUNC;
    kcqe.flags |= (FCOE_KWQE_LAYER_CODE << FCOE_KWQE_HEADER_LAYER_CODE_SHIFT);
    kcqe.completion_status = mm_cpu_to_le32(FCOE_KCQE_COMPLETION_STATUS_NIC_ERROR);

    /* call here directly (for error case) */

    /* XXX
     * Need to add a mutex or reference count to ensure that bnxef isn't
     * unloaded underneath this taskq dispatch routine.
     */

    {
        struct fcoe_kcqe * pKcqe = &kcqe;
        ASSERT(CLIENT_BOUND(pUM, LM_CLI_IDX_FCOE));
        pUM->fcoe.bind.cliIndicateCqes(pUM->fcoe.pDev,
                                       (void **)&pKcqe, 1);
    }

    /* XXX release mutex or decrement reference count */
}


static boolean_t BnxeFcoeStatWqe(um_device_t *      pUM,
                                 union fcoe_kwqe ** kwqes)
{
    return BnxeWorkQueueAdd(pUM, BnxeFcoeStatWqeWork,
                            kwqes[0], sizeof(*(kwqes[0])));
}


#define KCQE_LIMIT 64

static void BnxeFcoeCompRequestCqeWork(um_device_t * pUM,
                                       void *        pData,
                                       u32_t         dataLen)
{
    struct fcoe_kcqe * kcqe_arr = (struct fcoe_kcqe *)pData;
    struct fcoe_kcqe * kcqes[KCQE_LIMIT];
    u32_t              num_kcqes;
    int i;

    if ((dataLen % (sizeof(*kcqe_arr))) != 0)
    {
        BnxeLogWarn(pUM, "Invalid FCoE Comp Request CQE array");
        pUM->fcoe.stats.compRequestCqeRxErr++;
        return;
    }

    num_kcqes = (dataLen / (sizeof(*kcqe_arr)));

    /* init the kcqe pointer array */

    for (i = 0; i < num_kcqes; i++)
    {
        kcqes[i] = &kcqe_arr[i];
    }

    ASSERT(CLIENT_BOUND(pUM, LM_CLI_IDX_FCOE));

    if (!pUM->fcoe.bind.cliIndicateCqes(pUM->fcoe.pDev,
                                        (void **)kcqes,
                                        num_kcqes))
    {
        pUM->fcoe.stats.compRequestCqeRxErr++;
    }
    else
    {
        pUM->fcoe.stats.compRequestCqeRx += num_kcqes;
    }
}


boolean_t BnxeFcoeCompRequestCqe(um_device_t *      pUM,
                                 struct fcoe_kcqe * kcqes,
                                 u32_t              num_kcqes)
{
    u32_t kcqesIdx = 0;
    u32_t kcqesLimit = 0;
    u32_t numUp;

    /* Send up KCQE_LIMIT kcqes at a time... */

    while (kcqesIdx < num_kcqes)
    {
        if (num_kcqes - kcqesIdx > KCQE_LIMIT)
        {
            kcqesLimit += KCQE_LIMIT;
        }
        else
        {
            kcqesLimit = num_kcqes;
        }

        numUp = (kcqesLimit % KCQE_LIMIT == 0) ? KCQE_LIMIT :
                                                 (kcqesLimit % KCQE_LIMIT);

#if 0
        if (!BnxeWorkQueueAdd(pUM, BnxeFcoeCompRequestCqeWork,
                              kcqes + kcqesIdx,
                              (sizeof(struct fcoe_kcqe) * numUp)))
        {
            return B_FALSE;
        }
#else
        BnxeFcoeCompRequestCqeWork(pUM,
                                   kcqes + kcqesIdx,
                                   (sizeof(struct fcoe_kcqe) * numUp));
#endif

        kcqesIdx += (kcqesLimit - kcqesIdx);
    }

    return B_TRUE;
}


boolean_t BnxeFcoePrvCtl(dev_info_t * pDev,
                         int          cmd,
                         void *       pData,
                         int          dataLen)
{
    um_device_t *  pUM = (um_device_t *)ddi_get_driver_private(pDev);
    BnxeFcoeInfo * pFcoeInfo;
    int rc, i;

    /* sanity check */
    if (pUM == NULL || pUM->pDev != pDev)
    {
        BnxeLogWarn(NULL, "%s: dev_info_t match failed", __func__);
        return B_FALSE;
    }

    BnxeLogDbg(pUM, "*** %s ***", __func__);

    VERIFY_FCOE_BINDING(pUM);

    switch (cmd)
    {
    case PRV_CTL_GET_MAC_ADDR:

        if (dataLen < ETHERNET_ADDRESS_SIZE)
        {
            BnxeLogWarn(pUM, "Invalid MAC Address buffer length for get (%d)",
                        dataLen);
            return B_FALSE;
        }

        if (!pData)
        {
            BnxeLogWarn(pUM, "NULL MAC Address buffer for get");
            return B_FALSE;
        }

        COPY_ETH_ADDRESS(pUM->lm_dev.hw_info.fcoe_mac_addr, pData);

        return B_TRUE;

    case PRV_CTL_SET_MAC_ADDR:

        if (dataLen < ETHERNET_ADDRESS_SIZE)
        {
            BnxeLogWarn(pUM, "Invalid MAC Address length for set (%d)",
                        dataLen);
            return B_FALSE;
        }

        if (!pData)
        {
            BnxeLogWarn(pUM, "NULL MAC Address buffer for set");
            return B_FALSE;
        }

        /* Validate MAC address */
        if (IS_ETH_MULTICAST(pData))
        {
            BnxeLogWarn(pUM, "Cannot program a mcast/bcast address as an MAC Address.");
            return B_FALSE;
        }

        BNXE_LOCK_ENTER_HWINIT(pUM);

        /* XXX wrong? (overwriting fcoe hw programmed address!) */
        COPY_ETH_ADDRESS(pData, pUM->lm_dev.hw_info.fcoe_mac_addr);

        rc = BnxeMacAddress(pUM, LM_CLI_IDX_FCOE, B_TRUE,
                            pUM->lm_dev.hw_info.fcoe_mac_addr);

        BNXE_LOCK_EXIT_HWINIT(pUM);

        return (rc < 0) ? B_FALSE : B_TRUE;

    case PRV_CTL_QUERY_PARAMS:

        if (dataLen != sizeof(BnxeFcoeInfo))
        {
            BnxeLogWarn(pUM, "Invalid query buffer for FCoE (%d)",
                        dataLen);
            return B_FALSE;
        }

        if (!pData)
        {
            BnxeLogWarn(pUM, "Invalid query buffer for FCoE");
            return B_FALSE;
        }

        pFcoeInfo = (BnxeFcoeInfo *)pData;

        pFcoeInfo->flags = 0;

        /*
         * Always set the FORCE_LOAD flags which tells bnxef to perform any
         * necessary delays needed when bringing up targets. This allows ample
         * time for bnxef to come up and finish for FCoE boot. If we don't
         * force a delay then there is a race condition and the kernel won't
         * find the root disk.
         */
        pFcoeInfo->flags |= FCOE_INFO_FLAG_FORCE_LOAD;

        switch (pUM->lm_dev.params.mf_mode)
        {
        case SINGLE_FUNCTION:
            pFcoeInfo->flags |= FCOE_INFO_FLAG_MF_MODE_SF;
            break;
        case MULTI_FUNCTION_SD:
            pFcoeInfo->flags |= FCOE_INFO_FLAG_MF_MODE_SD;
            break;
        case MULTI_FUNCTION_SI:
            pFcoeInfo->flags |= FCOE_INFO_FLAG_MF_MODE_SI;
            break;
        case MULTI_FUNCTION_AFEX:
            pFcoeInfo->flags |= FCOE_INFO_FLAG_MF_MODE_AFEX;
            break;
        default:
            break;
        }

        pFcoeInfo->max_fcoe_conn      = pUM->lm_dev.params.max_func_fcoe_cons;
        pFcoeInfo->max_fcoe_exchanges = pUM->lm_dev.params.max_fcoe_task;

        memcpy(&pFcoeInfo->wwn, &pUM->fcoe.wwn, sizeof(BnxeWwnInfo));

        return B_TRUE;

    case PRV_CTL_DISABLE_INTR:

        BnxeIntrIguSbDisable(pUM, FCOE_CID(&pUM->lm_dev), B_FALSE);
        return B_TRUE;

    case PRV_CTL_ENABLE_INTR:

        BnxeIntrIguSbEnable(pUM, FCOE_CID(&pUM->lm_dev), B_FALSE);
        return B_TRUE;

    case PRV_CTL_MBA_BOOT:

        if (dataLen != sizeof(boolean_t))
        {
            BnxeLogWarn(pUM, "Invalid MBA boot check buffer for FCoE (%d)",
                        dataLen);
            return B_FALSE;
        }

        if (!pData)
        {
            BnxeLogWarn(pUM, "Invalid MBA boot check buffer for FCoE");
            return B_FALSE;
        }

        *((boolean_t *)pData) =
            (pUM->iscsiInfo.signature != 0) ? B_TRUE : B_FALSE;

        return B_TRUE;

    case PRV_CTL_LINK_STATE:

        if (dataLen != sizeof(boolean_t))
        {
            BnxeLogWarn(pUM, "Invalid link state buffer for FCoE (%d)",
                        dataLen);
            return B_FALSE;
        }

        if (!pData)
        {
            BnxeLogWarn(pUM, "Invalid link state buffer for FCoE");
            return B_FALSE;
        }

        *((boolean_t *)pData) =
            (pUM->devParams.lastIndLink == LM_STATUS_LINK_ACTIVE) ?
                B_TRUE : B_FALSE;

        return B_TRUE;

    case PRV_CTL_BOARD_TYPE:

        if (!pData || (dataLen <= 0))
        {
            BnxeLogWarn(pUM, "Invalid board type buffer for FCoE");
            return B_FALSE;
        }

        snprintf((char *)pData, dataLen, "%s", pUM->chipName);

        return B_TRUE;

    case PRV_CTL_BOARD_SERNUM:

        if (!pData || (dataLen <= 0))
        {
            BnxeLogWarn(pUM, "Invalid board serial number buffer for FCoE");
            return B_FALSE;
        }

        snprintf((char *)pData, dataLen,
                 "%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c",
                 pUM->lm_dev.hw_info.board_num[0],
                 pUM->lm_dev.hw_info.board_num[1],
                 pUM->lm_dev.hw_info.board_num[2],
                 pUM->lm_dev.hw_info.board_num[3],
                 pUM->lm_dev.hw_info.board_num[4],
                 pUM->lm_dev.hw_info.board_num[5],
                 pUM->lm_dev.hw_info.board_num[6],
                 pUM->lm_dev.hw_info.board_num[7],
                 pUM->lm_dev.hw_info.board_num[8],
                 pUM->lm_dev.hw_info.board_num[9],
                 pUM->lm_dev.hw_info.board_num[10],
                 pUM->lm_dev.hw_info.board_num[11],
                 pUM->lm_dev.hw_info.board_num[12],
                 pUM->lm_dev.hw_info.board_num[13],
                 pUM->lm_dev.hw_info.board_num[14],
                 pUM->lm_dev.hw_info.board_num[15]);

        return B_TRUE;

    case PRV_CTL_BOOTCODE_VERSION:

        if (!pData || (dataLen <= 0))
        {
            BnxeLogWarn(pUM, "Invalid boot code version buffer for FCoE");
            return B_FALSE;
        }

        snprintf((char *)pData, dataLen, "%s", pUM->versionBC);

        return B_TRUE;

    case PRV_CTL_REPORT_FCOE_STATS:

        if (!pData ||
            (dataLen !=
             sizeof(pUM->lm_dev.vars.stats.stats_mirror.
                                     stats_drv.drv_info_to_mfw.fcoe_stats)))
        {
            BnxeLogWarn(pUM, "Invalid stats reporting buffer for FCoE");
            return B_FALSE;
        }

        memcpy(&pUM->lm_dev.vars.stats.stats_mirror.
                                stats_drv.drv_info_to_mfw.fcoe_stats,
               (fcoe_stats_info_t *)pData,
               sizeof(fcoe_stats_info_t));

        return B_TRUE;

    case PRV_CTL_SET_CAPS:

        if (!pData || (dataLen != sizeof(struct fcoe_capabilities)))
        {
            BnxeLogWarn(pUM, "Invalid capabilities buffer for FCoE");
            return B_FALSE;
        }

        memcpy(&pUM->lm_dev.vars.stats.stats_mirror.stats_drv.
                                 drv_info_to_shmem.fcoe_capabilities,
               pData,
               sizeof(pUM->lm_dev.vars.stats.stats_mirror.stats_drv.
                                       drv_info_to_shmem.fcoe_capabilities));

        lm_ncsi_fcoe_cap_to_scratchpad(&pUM->lm_dev);

        return B_TRUE;

    default:

        BnxeLogWarn(pUM, "Unknown provider command %d", cmd);
        return B_FALSE;
    }
}


mblk_t * BnxeFcoePrvTx(dev_info_t * pDev,
                       mblk_t *     pMblk,
                       u32_t        flags,
                       u16_t        vlan_tag)
{
    um_device_t * pUM = (um_device_t *)ddi_get_driver_private(pDev);
    lm_device_t * pLM = &pUM->lm_dev;
    mblk_t *      pNextMblk = NULL;
    int           txCount = 0;
    int rc;

    /* sanity check */
    if (pUM == NULL || pUM->pDev != pDev)
    {
        BnxeLogWarn(NULL, "%s: dev_info_t match failed", __func__);
        return pMblk;
    }

    VERIFY_FCOE_BINDING(pUM);

    BnxeLogDbg(pUM, "*** %s ***", __func__);

    while (pMblk)
    {
        txCount++;

        pNextMblk = pMblk->b_next;
        pMblk->b_next = NULL;

        rc = BnxeTxSendMblk(pUM, FCOE_CID(pLM), pMblk, flags, vlan_tag);

        if (rc == BNXE_TX_GOODXMIT)
        {
            pMblk = pNextMblk;
            continue;
        }
        else if (rc == BNXE_TX_DEFERPKT)
        {
            pMblk = pNextMblk;
        }
        else
        {
            pMblk->b_next = pNextMblk;
        }

        break;
    }

    return pMblk;
}


boolean_t BnxeFcoePrvPoll(dev_info_t * pDev)
{
    um_device_t * pUM  = (um_device_t *)ddi_get_driver_private(pDev);
    RxQueue *     pRxQ = &pUM->rxq[FCOE_CID(&pUM->lm_dev)];
    u32_t         idx  = pRxQ->idx;

    /* sanity check */
    if (pUM == NULL || pUM->pDev != pDev)
    {
        BnxeLogWarn(NULL, "%s: dev_info_t match failed", __func__);
        return B_FALSE;
    }

    VERIFY_FCOE_BINDING(pUM);

    BnxeLogDbg(pUM, "*** %s ***", __func__);

    if (pRxQ->inPollMode == B_FALSE)
    {
        BnxeLogWarn(pUM, "Polling on FCoE ring %d when NOT in poll mode!", idx);
        return B_FALSE;
    }

    pRxQ->pollCnt++;

    BnxePollRxRingFCOE(pUM);

    return B_TRUE;
}


boolean_t BnxeFcoePrvSendWqes(dev_info_t * pDev,
                              void *       wqes[],
                              int          wqeCnt)
{
    union fcoe_kwqe ** kwqes = (union fcoe_kwqe **)wqes;
    int                kwqeCnt = 0;

    um_device_t * pUM = (um_device_t *)ddi_get_driver_private(pDev);

    /* sanity check */
    if (pUM == NULL || pUM->pDev != pDev)
    {
        BnxeLogWarn(NULL, "%s: dev_info_t match failed", __func__);
        return B_FALSE;
    }

    VERIFY_FCOE_BINDING(pUM);

    if ((kwqes == NULL) || (kwqes[0] == NULL))
    {
        BnxeLogWarn(pUM, "Invalid WQE array");
        return B_FALSE;
    }

    BnxeLogDbg(pUM, "*** %s ***", __func__);

    while (kwqeCnt < wqeCnt)
    {
        switch (kwqes[kwqeCnt]->init1.hdr.op_code)
        {
        case FCOE_KWQE_OPCODE_INIT1:

            BnxeLogDbg(pUM, "*** %s - FCOE_KWQE_OPCODE_INIT", __func__);

            if ((wqeCnt <= kwqeCnt + 2) ||
                (kwqes[kwqeCnt + 1] == NULL) ||
                (kwqes[kwqeCnt + 2] == NULL) ||
                (kwqes[kwqeCnt + 1]->init2.hdr.op_code != FCOE_KWQE_OPCODE_INIT2) ||
                (kwqes[kwqeCnt + 2]->init3.hdr.op_code != FCOE_KWQE_OPCODE_INIT3))
            {
                BnxeLogWarn(pUM, "FCoE Init kwqes error");
                pUM->fcoe.stats.initWqeTxErr++;
                return B_FALSE;
            }

            if (!BnxeFcoeInitWqe(pUM, &kwqes[kwqeCnt]))
            {
                BnxeLogWarn(pUM, "Failed to init FCoE Init WQE work");
                return B_FALSE;
            }

            kwqeCnt += 3;

            break;

        case FCOE_KWQE_OPCODE_OFFLOAD_CONN1:

            BnxeLogDbg(pUM, "*** %s - FCOE_KWQE_OPCODE_OFFLOAD_CONN1", __func__);

            if ((wqeCnt <= kwqeCnt + 3) ||
                (kwqes[kwqeCnt + 1] == NULL) ||
                (kwqes[kwqeCnt + 2] == NULL) ||
                (kwqes[kwqeCnt + 3] == NULL) ||
                (kwqes[kwqeCnt + 1]->conn_offload2.hdr.op_code != FCOE_KWQE_OPCODE_OFFLOAD_CONN2) ||
                (kwqes[kwqeCnt + 2]->conn_offload3.hdr.op_code != FCOE_KWQE_OPCODE_OFFLOAD_CONN3) ||
                (kwqes[kwqeCnt + 3]->conn_offload4.hdr.op_code != FCOE_KWQE_OPCODE_OFFLOAD_CONN4))
            {
                BnxeLogWarn(pUM, "FCoE Offload Conn kwqes error");
                pUM->fcoe.stats.offloadConnWqeTxErr++;
                return B_FALSE;
            }

            if (!BnxeFcoeOffloadConnWqe(pUM, &kwqes[kwqeCnt]))
            {
                BnxeLogWarn(pUM, "Failed to init FCoE Offload Conn WQE work");
                return B_FALSE;
            }

            kwqeCnt += 4;

            break;

        case FCOE_KWQE_OPCODE_ENABLE_CONN:

            BnxeLogDbg(pUM, "*** %s - FCOE_KWQE_OPCODE_ENABLE_CONN", __func__);

            if (!BnxeFcoeEnableConnWqe(pUM, &kwqes[kwqeCnt]))
            {
                BnxeLogWarn(pUM, "Failed to init FCoE Enable Conn WQE work");
                return B_FALSE;
            }

            kwqeCnt += 1;

            break;

        case FCOE_KWQE_OPCODE_DISABLE_CONN:

            BnxeLogDbg(pUM, "*** %s - FCOE_KWQE_OPCODE_DISABLE_CONN", __func__);

            if (!BnxeFcoeDisableConnWqe(pUM, &kwqes[kwqeCnt]))
            {
                BnxeLogWarn(pUM, "Failed to init FCoE Disable Conn WQE work");
                return B_FALSE;
            }

            kwqeCnt += 1;

            break;

        case FCOE_KWQE_OPCODE_DESTROY_CONN:

            BnxeLogDbg(pUM, "*** %s - FCOE_KWQE_OPCODE_DESTROY_CONN", __func__);

            if (!BnxeFcoeDestroyConnWqe(pUM, &kwqes[kwqeCnt]))
            {
                BnxeLogWarn(pUM, "Failed to init FCoE Destroy Conn WQE work");
                return B_FALSE;
            }

            kwqeCnt += 1;

            break;

        case FCOE_KWQE_OPCODE_DESTROY:

            BnxeLogDbg(pUM, "*** %s - FCOE_KWQE_OPCODE_DESTROY", __func__);

            if (!BnxeFcoeDestroyWqe(pUM, &kwqes[kwqeCnt]))
            {
                BnxeLogWarn(pUM, "Failed to init FCoE Destroy WQE work");
                return B_FALSE;
            }

            kwqeCnt += 1;

            break;

        case FCOE_KWQE_OPCODE_STAT:

            BnxeLogDbg(pUM, "*** %s - FCOE_KWQE_OPCODE_STAT", __func__);

            if (!BnxeFcoeStatWqe(pUM, &kwqes[kwqeCnt]))
            {
                BnxeLogWarn(pUM, "Failed to init FCoE Stat WQE work");
                return B_FALSE;
            }

            kwqeCnt += 1;

            break;

        default:

            BnxeDbgBreakMsg(pUM, "Invalid KWQE opcode");
            return B_FALSE;
        }
    }

    return B_TRUE;
}


boolean_t BnxeFcoePrvMapMailboxq(dev_info_t *       pDev,
                                 u32_t              cid,
                                 void **            ppMap,
                                 ddi_acc_handle_t * pAccHandle)
{
    um_device_t * pUM = (um_device_t *)ddi_get_driver_private(pDev);

    /* sanity check */
    if (pUM == NULL || pUM->pDev != pDev)
    {
        BnxeLogWarn(NULL, "%s: dev_info_t match failed", __func__);
        return B_FALSE;
    }

    VERIFY_FCOE_BINDING(pUM);

    BnxeLogDbg(pUM, "*** %s ***", __func__);

    /* get the right offset from the mapped bar */

    *ppMap = (void *)((u8_t *)pUM->lm_dev.context_info->array[SW_CID(cid)].cid_resc.mapped_cid_bar_addr + DPM_TRIGER_TYPE);
    *pAccHandle = pUM->lm_dev.context_info->array[SW_CID(cid)].cid_resc.reg_handle;

    if (!(*ppMap) || !(*pAccHandle))
    {
        BnxeLogWarn(pUM, "Cannot map mailboxq base address for FCoE");
        return B_FALSE;
    }

    return B_TRUE;
}


boolean_t BnxeFcoePrvUnmapMailboxq(dev_info_t *     pDev,
                                   u32_t            cid,
                                   void *           pMap,
                                   ddi_acc_handle_t accHandle)
{
    um_device_t *    pUM = (um_device_t *)ddi_get_driver_private(pDev);
    void *           pTmp;
    ddi_acc_handle_t tmpAcc;

    /* sanity check */
    if (pUM == NULL || pUM->pDev != pDev)
    {
        BnxeLogWarn(NULL, "%s: dev_info_t match failed", __func__);
        return B_FALSE;
    }

    VERIFY_FCOE_BINDING(pUM);

    BnxeLogDbg(pUM, "*** %s ***", __func__);

    /* verify the mapped bar address */
    pTmp = (void *)((u8_t *)pUM->lm_dev.context_info->array[SW_CID(cid)].cid_resc.mapped_cid_bar_addr + DPM_TRIGER_TYPE);
    tmpAcc = pUM->lm_dev.context_info->array[SW_CID(cid)].cid_resc.reg_handle;

    if ((pMap != pTmp) || (accHandle != tmpAcc))
    {
        BnxeLogWarn(pUM, "Invalid map info for FCoE (%p)", pMap);
        return B_FALSE;
    }

    return B_TRUE;
}


int BnxeFcoeInit(um_device_t * pUM)
{
    char * pCompat[2] = { BNXEF_NAME, NULL };
    char   name[256];
    int    rc;

    BnxeLogInfo(pUM, "Starting FCoE");

    if (!BNXE_FCOE(pUM))
    {
        BnxeLogWarn(pUM, "FCoE not supported on this device");
        return ENOTSUP;
    }

    //if (CLIENT_DEVI(pUM, LM_CLI_IDX_FCOE))
    if (pUM->fcoe.pDev)
    {
        BnxeLogWarn(pUM, "FCoE child node already initialized");
        return EEXIST;
    }

    if (ndi_devi_alloc(pUM->pDev,
                       BNXEF_NAME,
                       DEVI_PSEUDO_NODEID,
                       &pUM->fcoe.pDev) != NDI_SUCCESS)
    {
        BnxeLogWarn(pUM, "Failed to allocate a child node for FCoE");
        pUM->fcoe.pDev = NULL;
        return ENOMEM;
    }

    if (ndi_prop_update_string_array(DDI_DEV_T_NONE,
                                     pUM->fcoe.pDev,
                                     "name",
                                     pCompat,
                                     1) != DDI_PROP_SUCCESS)
    {
        BnxeLogWarn(pUM, "Failed to set the name string for FCoE");
        /* XXX see other call to ndi_devi_free below */
        //ndi_devi_free(pUM->fcoe.pDev);
        pUM->fcoe.pDev = NULL;
        return ENOENT;
    }

    CLIENT_DEVI_SET(pUM, LM_CLI_IDX_FCOE);

    /*
     * XXX If/when supporting custom wwn's then prime them
     * here in so they will be passed to bnxef during BINDING.
     * Ideally custom wwn's will be set via the driver .conf
     * file and via a private driver property.
     */
    memset(&pUM->fcoe.wwn, 0, sizeof(BnxeWwnInfo));
    pUM->fcoe.wwn.fcp_pwwn_provided = B_TRUE;
    memcpy(pUM->fcoe.wwn.fcp_pwwn, pUM->lm_dev.hw_info.fcoe_wwn_port_name,
           BNXE_FCOE_WWN_SIZE);
    pUM->fcoe.wwn.fcp_nwwn_provided = B_TRUE;
    memcpy(pUM->fcoe.wwn.fcp_nwwn, pUM->lm_dev.hw_info.fcoe_wwn_node_name,
           BNXE_FCOE_WWN_SIZE);

    BnxeLogInfo(pUM, "Created the FCoE child node %s@%s",
                BNXEF_NAME, ddi_get_name_addr(pUM->pDev));

    if ((rc = ndi_devi_online(pUM->fcoe.pDev, NDI_ONLINE_ATTACH)) !=
        NDI_SUCCESS)
    {
        /* XXX
         * ndi_devi_free will cause a panic. Don't know why and we've
         * verified that Sun's FCoE driver does not free it either.
         */
        //ndi_devi_free(pUM->fcoe.pDev);
        CLIENT_DEVI_RESET(pUM, LM_CLI_IDX_FCOE);
        pUM->fcoe.pDev = NULL;
        BnxeLogInfo(pUM, "Unable to bind the QLogic FCoE driver (%d)", rc);
        return ECHILD;
    }

#if 0
    /* bring bnxef online and attach it */
    if (ndi_devi_bind_driver(pUM->fcoe.pDev, 0) != NDI_SUCCESS)
    {
        BnxeLogInfo(pUM, "Unable to bind the QLogic FCoE driver");
    }
#endif

    return 0;
}


int BnxeFcoeFini(um_device_t * pUM)
{
    int rc = 0;
    int nullDev = B_FALSE; /* false = wait for bnxef UNBIND */

    BnxeLogInfo(pUM, "Stopping FCoE");

    if (!BNXE_FCOE(pUM))
    {
        BnxeLogWarn(pUM, "FCoE not supported on this device");
        return ENOTSUP;
    }

    if (CLIENT_BOUND(pUM, LM_CLI_IDX_FCOE))
    {
        if (pUM->fcoe.pDev == NULL)
        {
            BnxeLogWarn(pUM, "FCoE Client bound and pDev is NULL, FINI failed! %s@%s",
                        BNXEF_NAME, ddi_get_name_addr(pUM->pDev));
            return ENOENT;
        }
        else if (pUM->fcoe.bind.cliCtl == NULL)
        {
            BnxeLogWarn(pUM, "FCoE Client bound and cliCtl is NULL, FINI failed! %s@%s",
                        BNXEF_NAME, ddi_get_name_addr(pUM->pDev));
            return ENOENT;
        }
        else if (pUM->fcoe.bind.cliCtl(pUM->fcoe.pDev,
                                       CLI_CTL_UNLOAD,
                                       NULL,
                                       0) == B_FALSE)
        {
            BnxeLogWarn(pUM, "FCoE Client bound and UNLOAD failed! %s@%s",
                        BNXEF_NAME, ddi_get_name_addr(pUM->pDev));
            return ENOMSG; /* no graceful unload with bnxef */
        }
    }
    else
    {
        rc = ENODEV;
        nullDev = B_TRUE;
    }

    /*
     * There are times when delete-port doesn't fully work and bnxef is unable
     * to detach and never calls UNBIND.  So here we'll just make sure that
     * the child dev node is not NULL which semi-gaurantees the UNBIND hasn't
     * been called yet.  Multiple offline calls will hopefully kick bnxef...
     */
    //if (CLIENT_DEVI(pUM, LM_CLI_IDX_FCOE))
    if (pUM->fcoe.pDev)
    {
        CLIENT_DEVI_RESET(pUM, LM_CLI_IDX_FCOE);

        BnxeLogWarn(pUM, "Bringing down QLogic FCoE driver %s@%s",
                    BNXEF_NAME, ddi_get_name_addr(pUM->pDev));

#if 1
        if (ndi_devi_offline(pUM->fcoe.pDev, NDI_DEVI_REMOVE) != NDI_SUCCESS)
        {
            BnxeLogWarn(pUM, "Failed to bring the QLogic FCoE driver offline %s@%s",
                        BNXEF_NAME, ddi_get_name_addr(pUM->pDev));
            return EBUSY;
        }
#else
        ndi_devi_offline(pUM->fcoe.pDev, NDI_DEVI_REMOVE);
        if (nullDev) pUM->fcoe.pDev = NULL;
#endif

        memset(&pUM->fcoe.wwn, 0, sizeof(BnxeWwnInfo));

        BnxeLogInfo(pUM, "Destroyed the FCoE child node %s@%s",
                    BNXEF_NAME, ddi_get_name_addr(pUM->pDev));
    }

    return rc;
}


void BnxeFcoeStartStop(um_device_t * pUM)
{
    int rc;

    if (!BNXE_FCOE(pUM))
    {
        BnxeLogWarn(pUM, "FCoE is not supported on this device");
        return;
    }

    if (pUM->devParams.fcoeEnable)
    {
        BnxeFcoeInit(pUM);
    }
    else
    {
        BnxeFcoeFini(pUM);
    }
}

