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

/*
 * Copyright (c) 2002, 2011, Oracle and/or its affiliates. All rights reserved.
 */

#include "bnxe.h"

#define BNXE_TIMER_INTERVAL 1000000 /* usecs (once a second for stats) */


static void BnxeTimer(void * pArg)
{
    um_device_t * pUM = (um_device_t *)pArg;
    lm_device_t * pLM = &pUM->lm_dev;

    BNXE_LOCK_ENTER_TIMER(pUM);

    if (pUM->timerEnabled != B_TRUE)
    {
        BNXE_LOCK_EXIT_TIMER(pUM);
        return;
    }

    lm_stats_on_timer(pLM);

    if (pUM->fmCapabilities &&
        BnxeCheckAccHandle(pLM->vars.reg_handle[BAR_0]) != DDI_FM_OK)
    {
        ddi_fm_service_impact(pUM->pDev, DDI_SERVICE_UNAFFECTED);
    }

    if (pUM->phyInitialized)
    {
        BNXE_LOCK_ENTER_PHY(pUM);
        lm_link_on_timer(pLM);
        BNXE_LOCK_EXIT_PHY(pUM);
    }

    pUM->timerID = timeout(BnxeTimer, (void *)pUM,
                           drv_usectohz(BNXE_TIMER_INTERVAL));

    BNXE_LOCK_EXIT_TIMER(pUM);
}


void BnxeTimerStart(um_device_t * pUM)
{
    atomic_swap_32(&pUM->timerEnabled, B_TRUE);

    pUM->lm_dev.vars.stats.stats_collect.timer_wakeup = 0; /* reset */

    pUM->timerID = timeout(BnxeTimer, (void *)pUM,
                           drv_usectohz(BNXE_TIMER_INTERVAL));
}


void BnxeTimerStop(um_device_t * pUM)
{
    atomic_swap_32(&pUM->timerEnabled, B_FALSE);

    BNXE_LOCK_ENTER_TIMER(pUM);
    BNXE_LOCK_EXIT_TIMER(pUM);

    untimeout(pUM->timerID);
    pUM->timerID = 0;
}

