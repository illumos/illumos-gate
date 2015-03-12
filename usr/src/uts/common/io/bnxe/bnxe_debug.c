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

#define BNXE_LOG_LEN 256


#ifdef DBG

void DbgMessageFunc(void * pDev,
                    int    level,
                    char * pFmt,
                    ...)
{
    um_device_t * pUM = (um_device_t *)pDev;
    va_list argp;
    int ce;

    if ((pUM != NULL) &&
        (((pUM->devParams.debug_level & level & CP_ALL) != (level & CP_ALL)) ||
         ((pUM->devParams.debug_level & LV_MASK) < (level & LV_MASK))))
    {
        return;
    }

    ce = (((level & LV_VERBOSE) == LV_VERBOSE) ? CE_NOTE :
          ((level & LV_INFORM) == LV_INFORM)   ? CE_NOTE :
          ((level & LV_WARN) == LV_WARN)       ? CE_WARN :
                                                 CE_PANIC);

    va_start(argp, pFmt);
    vcmn_err(ce, pFmt, argp);
    va_end(argp);
}

#endif /* DBG */


void elink_cb_dbg(struct elink_dev * bp, char * fmt)
{
    um_device_t * pUM = (um_device_t *)bp;
    char buf[BNXE_LOG_LEN];

#ifdef DBG
    if ((pUM->devParams.debug_level & LV_MASK) < LV_WARN)
    {
        return;
    }

    snprintf(buf, sizeof(buf), fmt);
    cmn_err(CE_NOTE, "!%s: ELINK %s", BnxeDevName(pUM), buf);
#endif
}


void elink_cb_dbg1(struct elink_dev * bp, char * fmt, u32 arg1)
{
    um_device_t * pUM = (um_device_t *)bp;
    char buf[BNXE_LOG_LEN];

#ifdef DBG
    if ((pUM->devParams.debug_level & LV_MASK) < LV_WARN)
    {
        return;
    }

    snprintf(buf, sizeof(buf), fmt, arg1);
    cmn_err(CE_NOTE, "!%s: ELINK %s", BnxeDevName(pUM), buf);
#endif
}


void elink_cb_dbg2(struct elink_dev * bp, char * fmt, u32 arg1, u32 arg2)
{
    um_device_t * pUM = (um_device_t *)bp;
    char buf[BNXE_LOG_LEN];

#ifdef DBG
    if ((pUM->devParams.debug_level & LV_MASK) < LV_WARN)
    {
        return;
    }

    snprintf(buf, sizeof(buf), fmt, arg1, arg2);
    cmn_err(CE_NOTE, "!%s: ELINK %s", BnxeDevName(pUM), buf);
#endif
}


void elink_cb_dbg3(struct elink_dev * bp, char * fmt, u32 arg1, u32 arg2, u32 arg3)
{
    um_device_t * pUM = (um_device_t *)bp;
    char buf[BNXE_LOG_LEN];

#ifdef DBG
    if ((pUM->devParams.debug_level & LV_MASK) < LV_WARN)
    {
        return;
    }

    snprintf(buf, sizeof(buf), fmt, arg1, arg2, arg3);
    cmn_err(CE_NOTE, "!%s: ELINK %s", BnxeDevName(pUM), buf);
#endif
}


void BnxeLogInfo(void * pDev,
                 char * pFmt,
                 ...)
{
    um_device_t * pUM = (um_device_t *)pDev;
    char buf[BNXE_LOG_LEN];
    va_list argp;

    /*
     * Info message are logged to syslog only if logEnable is
     * turned on.  They are never logged to the console.  If
     * pUM is NULL then the log is allowed through as if logEnable
     * was turned on.
     */

    if (pUM && !pUM->devParams.logEnable)
    {
        return;
    }
    /* if !pUM then let the log through */

    va_start(argp, pFmt);
    vsnprintf(buf, sizeof(buf), pFmt, argp);
    va_end(argp);

    cmn_err(CE_NOTE, "!%s: %s", BnxeDevName(pUM), buf);
}


void BnxeLogWarn(void * pDev,
                 char * pFmt,
                 ...)
{
    um_device_t * pUM = (um_device_t *)pDev;
    char buf[BNXE_LOG_LEN];
    va_list argp;

    /*
     * Warning message are always logged to syslog.  They are
     * never logged to the console.
     */

    va_start(argp, pFmt);
    vsnprintf(buf, sizeof(buf), pFmt, argp);
    va_end(argp);

    cmn_err(CE_WARN, "!%s: %s", BnxeDevName(pUM), buf);
}


#ifdef DBG

void BnxeLogDbg(void * pDev,
                char * pFmt,
                ...)
{
    um_device_t * pUM = (um_device_t *)pDev;
    char buf[BNXE_LOG_LEN];
    va_list argp;

    /*
     * Debug message are always logged to syslog.  They are
     * never logged to the console.  Debug messages are only
     * available when the DEBUG compile time flag is turned on.
     */

    va_start(argp, pFmt);
    vsnprintf(buf, sizeof(buf), pFmt, argp);
    va_end(argp);

    cmn_err(CE_WARN, "!%s: %s", BnxeDevName(pUM), buf);
}

#endif /* DBG */


void BnxeDumpMem(um_device_t * pUM,
                 char *        pTag,
                 u8_t *        pMem,
                 u32_t         len)
{
    char buf[256];
    char c[32];
    int  xx;

    mutex_enter(&bnxeLoaderMutex);

    cmn_err(CE_WARN, "!%s ++++++++++++ %s", BnxeDevName(pUM), pTag);
    strcpy(buf, "!** 000: ");

    for (xx = 0; xx < len; xx++)
    {
        if ((xx != 0) && (xx % 16 == 0))
        {
            cmn_err(CE_WARN, buf);
            strcpy(buf, "!** ");
            snprintf(c, sizeof(c), "%03x", xx);
            strcat(buf, c);
            strcat(buf, ": ");
        }

        snprintf(c, sizeof(c), "%02x ", *pMem);
        strcat(buf, c);

        pMem++;
    }

    cmn_err(CE_WARN, buf);
    cmn_err(CE_WARN, "!%s ------------ %s", BnxeDevName(pUM), pTag);

    mutex_exit(&bnxeLoaderMutex);
}


void BnxeDumpPkt(um_device_t * pUM,
                 char *        pTag,
                 mblk_t *      pMblk,
                 boolean_t     contents)
{
    char buf[256];
    char c[32];
    u8_t * pMem;
    int  i, xx = 0;

    mutex_enter(&bnxeLoaderMutex);

    cmn_err(CE_WARN, "!%s ++++++++++++ %s", BnxeDevName(pUM), pTag);

    while (pMblk)
    {
        pMem = pMblk->b_rptr;
        strcpy(buf, "!** > ");
        snprintf(c, sizeof(c), "%03x", xx);
        strcat(buf, c);
        strcat(buf, ": ");

        if (contents)
        {
            for (i = 0; i < MBLKL(pMblk); i++)
            {
                if ((xx != 0) && (xx % 16 == 0))
                {
                    cmn_err(CE_WARN, buf);
                    strcpy(buf, "!**   ");
                    snprintf(c, sizeof(c), "%03x", xx);
                    strcat(buf, c);
                    strcat(buf, ": ");
                }

                snprintf(c, sizeof(c), "%02x ", *pMem);
                strcat(buf, c);

                pMem++;
                xx++;
            }
        }
        else
        {
            snprintf(c, sizeof(c), "%d", (int)MBLKL(pMblk));
            strcat(buf, c);
            xx += MBLKL(pMblk);
        }

        cmn_err(CE_WARN, buf);
        pMblk = pMblk->b_cont;
    }

    cmn_err(CE_WARN, "!%s ------------ %s", BnxeDevName(pUM), pTag);

    mutex_exit(&bnxeLoaderMutex);
}
