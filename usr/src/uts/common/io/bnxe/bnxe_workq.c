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


typedef struct _BnxeWorkItem
{
    s_list_entry_t link;
    void *         pWorkData;
    u32_t          workDataLen;
    u32_t          delayMs;
    void (*pWorkCbkCopy)(um_device_t *, void *, u32_t);
    void (*pWorkCbkNoCopy)(um_device_t *, void *);
    void (*pWorkCbkGeneric)(um_device_t *);
} BnxeWorkItem;


static void BnxeWorkQueueInstanceWaitAndDestroy(BnxeWorkQueueInstance * pWorkq)
{
    if (pWorkq->pTaskq)
    {
        ddi_taskq_wait(pWorkq->pTaskq);
        ddi_taskq_destroy(pWorkq->pTaskq);
        mutex_destroy(&pWorkq->workQueueMutex);
    }

    memset(pWorkq, 0, sizeof(BnxeWorkQueueInstance));
}


boolean_t BnxeWorkQueueInit(um_device_t * pUM)
{
    pUM->workqs.instq.pUM = pUM;

    strcpy(pUM->workqs.instq.taskqName, pUM->devName);
    strcat(pUM->workqs.instq.taskqName, "_inst_q");

    mutex_init(&pUM->workqs.instq.workQueueMutex, NULL,
               MUTEX_DRIVER, DDI_INTR_PRI(pUM->intrPriority));

    if ((pUM->workqs.instq.pTaskq =
         ddi_taskq_create(pUM->pDev,
                          pUM->workqs.instq.taskqName,
                          1,
                          TASKQ_DEFAULTPRI,
                          0)) == NULL)
    {
        BnxeLogWarn(pUM, "Failed to create the workqs instq");
        return B_FALSE;
    }

    pUM->workqs.instq.pUM = pUM;

    strcpy(pUM->workqs.delayq.taskqName, pUM->devName);
    strcat(pUM->workqs.delayq.taskqName, "_delay_q");

    mutex_init(&pUM->workqs.delayq.workQueueMutex, NULL,
               MUTEX_DRIVER, DDI_INTR_PRI(pUM->intrPriority));

    if ((pUM->workqs.delayq.pTaskq =
         ddi_taskq_create(pUM->pDev,
                          pUM->workqs.delayq.taskqName,
                          16, /* XXX Is this enough? */
                          TASKQ_DEFAULTPRI,
                          0)) == NULL)
    {
        BnxeLogWarn(pUM, "Failed to create the workqs delayq");
        BnxeWorkQueueInstanceWaitAndDestroy(&pUM->workqs.instq);
        return B_FALSE;
    }

    pUM->workqs.delayq.pUM = pUM;

    return B_TRUE;
}


void BnxeWorkQueueWaitAndDestroy(um_device_t * pUM)
{
    BnxeWorkQueueInstanceWaitAndDestroy(&pUM->workqs.instq);
    BnxeWorkQueueInstanceWaitAndDestroy(&pUM->workqs.delayq);
}


static void BnxeWorkQueueDispatch(void * pArg)
{
    BnxeWorkQueueInstance * pWorkq = (BnxeWorkQueueInstance *)pArg;
    um_device_t * pUM = (um_device_t *)pWorkq->pUM;
    BnxeWorkItem * pWorkItem;

    mutex_enter(&pWorkq->workQueueMutex);
    pWorkItem = (BnxeWorkItem *)s_list_pop_head(&pWorkq->workQueue);
    mutex_exit(&pWorkq->workQueueMutex);

    if (pWorkItem == NULL)
    {
        BnxeLogWarn(pUM, "Work item is NULL!");
        pWorkq->workItemError++;
        return;
    }

    if ((pWorkItem->pWorkCbkCopy == NULL) &&
        (pWorkItem->pWorkCbkNoCopy == NULL) &&
        (pWorkItem->pWorkCbkGeneric == NULL))
    {
        BnxeLogWarn(pUM, "Work item callback is NULL!");
        pWorkq->workItemError++;
        goto BnxeWorkQueueDispatch_done;
    }

    if (pWorkItem->delayMs > 0)
    {
        /* this only occurs when processing the delayq */
        drv_usecwait(pWorkItem->delayMs * 1000);
    }

    if (pWorkItem->pWorkCbkCopy)
    {
        pWorkItem->pWorkCbkCopy(pUM,
                                pWorkItem->pWorkData,
                                pWorkItem->workDataLen);
    }
    else if (pWorkItem->pWorkCbkNoCopy)
    {
        pWorkItem->pWorkCbkNoCopy(pUM,
                                  pWorkItem->pWorkData);
    }
    else /* (pWorkItem->pWorkCbkGeneric) */
    {
        pWorkItem->pWorkCbkGeneric(pUM);
    }

    pWorkq->workItemComplete++;

BnxeWorkQueueDispatch_done:

    kmem_free(pWorkItem, (sizeof(BnxeWorkItem) + pWorkItem->workDataLen));
}


static void BnxeWorkQueueTrigger(um_device_t *           pUM,
                                 BnxeWorkQueueInstance * pWorkq)
{
    if (pUM->chipStarted)
    {
        ddi_taskq_dispatch(pWorkq->pTaskq,
                           BnxeWorkQueueDispatch,
                           (void *)pWorkq,
                           DDI_NOSLEEP);
    }
    else
    {
        BnxeLogInfo(pUM, "Delaying WorkQ item since chip not yet started.");
    }
}


void BnxeWorkQueueStartPending(um_device_t * pUM)
{
    u32_t cnt;

    if (!pUM->chipStarted)
    {
        BnxeLogWarn(pUM, "Triggering WorkQs and chip not started!");
        return;
    }

    mutex_enter(&pUM->workqs.instq.workQueueMutex);
    cnt = s_list_entry_cnt(&pUM->workqs.instq.workQueue);
    mutex_exit(&pUM->workqs.instq.workQueueMutex);

    if (cnt)
    {
        BnxeWorkQueueTrigger(pUM, &pUM->workqs.instq);
    }

    mutex_enter(&pUM->workqs.delayq.workQueueMutex);
    cnt = s_list_entry_cnt(&pUM->workqs.delayq.workQueue);
    mutex_exit(&pUM->workqs.delayq.workQueueMutex);

    if (cnt)
    {
        BnxeWorkQueueTrigger(pUM, &pUM->workqs.delayq);
    }
}


boolean_t BnxeWorkQueueAdd(um_device_t * pUM,
                           void (*pWorkCbkCopy)(um_device_t *, void *, u32_t),
                           void * pWorkData,
                           u32_t  workDataLen)
{
    BnxeWorkItem * pWorkItem;

    if ((pWorkItem = kmem_zalloc((sizeof(BnxeWorkItem) + workDataLen),
                                 KM_NOSLEEP)) == NULL)
    {
        BnxeLogWarn(pUM, "Failed to allocate memory for work item!");
        return B_FALSE;
    }

    pWorkItem->pWorkData       = (pWorkItem + 1);
    pWorkItem->workDataLen     = workDataLen;
    pWorkItem->pWorkCbkCopy    = pWorkCbkCopy;
    pWorkItem->pWorkCbkNoCopy  = NULL;
    pWorkItem->pWorkCbkGeneric = NULL;
    pWorkItem->delayMs         = 0;

    memcpy(pWorkItem->pWorkData, pWorkData, workDataLen);

    mutex_enter(&pUM->workqs.instq.workQueueMutex);

    s_list_push_tail(&pUM->workqs.instq.workQueue, &pWorkItem->link);
    pUM->workqs.instq.workItemQueued++;
    if (s_list_entry_cnt(&pUM->workqs.instq.workQueue) >
        pUM->workqs.instq.highWater)
    {
        pUM->workqs.instq.highWater =
            s_list_entry_cnt(&pUM->workqs.instq.workQueue);
    }

    mutex_exit(&pUM->workqs.instq.workQueueMutex);

    BnxeWorkQueueTrigger(pUM, &pUM->workqs.instq);

    return B_TRUE;
}


boolean_t BnxeWorkQueueAddNoCopy(um_device_t * pUM,
                                 void (*pWorkCbkNoCopy)(um_device_t *, void *),
                                 void * pWorkData)
{
    BnxeWorkItem * pWorkItem;

    if ((pWorkItem = kmem_zalloc(sizeof(BnxeWorkItem), KM_NOSLEEP)) == NULL)
    {
        BnxeLogWarn(pUM, "Failed to allocate memory for work item!");
        return B_FALSE;
    }

    pWorkItem->pWorkData       = pWorkData;
    pWorkItem->workDataLen     = 0;
    pWorkItem->pWorkCbkCopy    = NULL;
    pWorkItem->pWorkCbkNoCopy  = pWorkCbkNoCopy;
    pWorkItem->pWorkCbkGeneric = NULL;
    pWorkItem->delayMs         = 0;

    mutex_enter(&pUM->workqs.instq.workQueueMutex);

    s_list_push_tail(&pUM->workqs.instq.workQueue, &pWorkItem->link);
    pUM->workqs.instq.workItemQueued++;
    if (s_list_entry_cnt(&pUM->workqs.instq.workQueue) >
        pUM->workqs.instq.highWater)
    {
        pUM->workqs.instq.highWater =
            s_list_entry_cnt(&pUM->workqs.instq.workQueue);
    }

    mutex_exit(&pUM->workqs.instq.workQueueMutex);

    BnxeWorkQueueTrigger(pUM, &pUM->workqs.instq);

    return B_TRUE;
}


boolean_t BnxeWorkQueueAddGeneric(um_device_t * pUM,
                                  void (*pWorkCbkGeneric)(um_device_t *))
{
    BnxeWorkItem * pWorkItem;

    if ((pWorkItem = kmem_zalloc(sizeof(BnxeWorkItem), KM_NOSLEEP)) == NULL)
    {
        BnxeLogWarn(pUM, "Failed to allocate memory for work item!");
        return B_FALSE;
    }

    pWorkItem->pWorkData       = NULL;
    pWorkItem->workDataLen     = 0;
    pWorkItem->pWorkCbkCopy    = NULL;
    pWorkItem->pWorkCbkNoCopy  = NULL;
    pWorkItem->pWorkCbkGeneric = pWorkCbkGeneric;
    pWorkItem->delayMs         = 0;

    mutex_enter(&pUM->workqs.instq.workQueueMutex);

    s_list_push_tail(&pUM->workqs.instq.workQueue, &pWorkItem->link);
    pUM->workqs.instq.workItemQueued++;
    if (s_list_entry_cnt(&pUM->workqs.instq.workQueue) >
        pUM->workqs.instq.highWater)
    {
        pUM->workqs.instq.highWater =
            s_list_entry_cnt(&pUM->workqs.instq.workQueue);
    }

    mutex_exit(&pUM->workqs.instq.workQueueMutex);

    BnxeWorkQueueTrigger(pUM, &pUM->workqs.instq);

    return B_TRUE;
}


boolean_t BnxeWorkQueueAddDelay(um_device_t * pUM,
                                void (*pWorkCbkCopy)(um_device_t *, void *, u32_t),
                                void * pWorkData,
                                u32_t  workDataLen,
                                u32_t  delayMs)
{
    BnxeWorkItem * pWorkItem;

    if ((pWorkItem = kmem_zalloc((sizeof(BnxeWorkItem) + workDataLen),
                                 KM_NOSLEEP)) == NULL)
    {
        BnxeLogWarn(pUM, "Failed to allocate memory for work item!");
        return B_FALSE;
    }

    pWorkItem->pWorkData       = (pWorkItem + 1);
    pWorkItem->workDataLen     = workDataLen;
    pWorkItem->pWorkCbkCopy    = pWorkCbkCopy;
    pWorkItem->pWorkCbkNoCopy  = NULL;
    pWorkItem->pWorkCbkGeneric = NULL;
    pWorkItem->delayMs         = delayMs;

    memcpy(pWorkItem->pWorkData, pWorkData, workDataLen);

    mutex_enter(&pUM->workqs.delayq.workQueueMutex);

    s_list_push_tail(&pUM->workqs.delayq.workQueue, &pWorkItem->link);
    pUM->workqs.delayq.workItemQueued++;
    if (s_list_entry_cnt(&pUM->workqs.delayq.workQueue) >
        pUM->workqs.delayq.highWater)
    {
        pUM->workqs.delayq.highWater =
            s_list_entry_cnt(&pUM->workqs.delayq.workQueue);
    }

    mutex_exit(&pUM->workqs.delayq.workQueueMutex);

    BnxeWorkQueueTrigger(pUM, &pUM->workqs.delayq);

    return B_TRUE;
}


boolean_t BnxeWorkQueueAddDelayNoCopy(um_device_t * pUM,
                                      void (*pWorkCbkNoCopy)(um_device_t *, void *),
                                      void * pWorkData,
                                      u32_t  delayMs)
{
    BnxeWorkItem * pWorkItem;

    if ((pWorkItem = kmem_zalloc(sizeof(BnxeWorkItem), KM_NOSLEEP)) == NULL)
    {
        BnxeLogWarn(pUM, "Failed to allocate memory for work item!");
        return B_FALSE;
    }

    pWorkItem->pWorkData       = pWorkData;
    pWorkItem->workDataLen     = 0;
    pWorkItem->pWorkCbkCopy    = NULL;
    pWorkItem->pWorkCbkNoCopy  = pWorkCbkNoCopy;
    pWorkItem->pWorkCbkGeneric = NULL;
    pWorkItem->delayMs         = delayMs;

    mutex_enter(&pUM->workqs.delayq.workQueueMutex);

    s_list_push_tail(&pUM->workqs.delayq.workQueue, &pWorkItem->link);
    pUM->workqs.delayq.workItemQueued++;
    if (s_list_entry_cnt(&pUM->workqs.delayq.workQueue) >
        pUM->workqs.delayq.highWater)
    {
        pUM->workqs.delayq.highWater =
            s_list_entry_cnt(&pUM->workqs.delayq.workQueue);
    }

    mutex_exit(&pUM->workqs.delayq.workQueueMutex);

    BnxeWorkQueueTrigger(pUM, &pUM->workqs.delayq);

    return B_TRUE;
}


boolean_t BnxeWorkQueueAddDelayGeneric(um_device_t * pUM,
                                       void (*pWorkCbkGeneric)(um_device_t *),
                                       u32_t delayMs)
{
    BnxeWorkItem * pWorkItem;

    if ((pWorkItem = kmem_zalloc(sizeof(BnxeWorkItem), KM_NOSLEEP)) == NULL)
    {
        BnxeLogWarn(pUM, "Failed to allocate memory for work item!");
        return B_FALSE;
    }

    pWorkItem->pWorkData       = NULL;
    pWorkItem->workDataLen     = 0;
    pWorkItem->pWorkCbkCopy    = NULL;
    pWorkItem->pWorkCbkNoCopy  = NULL;
    pWorkItem->pWorkCbkGeneric = pWorkCbkGeneric;
    pWorkItem->delayMs         = delayMs;

    mutex_enter(&pUM->workqs.delayq.workQueueMutex);

    s_list_push_tail(&pUM->workqs.delayq.workQueue, &pWorkItem->link);
    pUM->workqs.delayq.workItemQueued++;
    if (s_list_entry_cnt(&pUM->workqs.delayq.workQueue) >
        pUM->workqs.delayq.highWater)
    {
        pUM->workqs.delayq.highWater =
            s_list_entry_cnt(&pUM->workqs.delayq.workQueue);
    }

    mutex_exit(&pUM->workqs.delayq.workQueueMutex);

    BnxeWorkQueueTrigger(pUM, &pUM->workqs.delayq);

    return B_TRUE;
}

