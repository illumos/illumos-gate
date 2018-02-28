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

/* This file is included by lmdev/include/debug.h */

#ifndef __BNXE_DEBUG_H__
#define __BNXE_DEBUG_H__

#include <sys/types.h>
#include <sys/cmn_err.h>
#include <sys/ddi.h>
#include <sys/sunddi.h>
#include <sys/varargs.h>
#undef u /* see bnxe.h for explanation */

extern char * BnxeDevName(void *);


#ifdef DBG

/********************************************/
/* all DbgXXX() routines are used by the LM */
/********************************************/

/*
 * Don't use the __FILE_STRIPPED macro as it will eat up too much read-only
 * data and dtrace will fail to load on SPARC. Use __BASENAME__ passed to the
 * compiler in the Makefile.
 */
#if 0
#undef __FILE_STRIPPED__
#define __FILE_STRIPPED__ (strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__)
#endif

void DbgMessageFunc(void * pDev,
                    int    level,
                    char * pFmt,
                    ...);

#define DbgMessageXX(_c, _m, _s, ...)                  \
    DbgMessageFunc(_c, _m, "!%s <0x%08x> %s(%d): " _s, \
                   BnxeDevName((void *)_c),            \
                   _m,                                 \
                   __BASENAME__,                       \
                   __LINE__,                           \
                   ##__VA_ARGS__)

#define DbgMessage DbgMessageXX

#define DbgBreak() cmn_err(CE_PANIC, "%s(%d): DbgBreak!", \
                           __BASENAME__,                  \
                           __LINE__)

#define DbgBreakMsg(_s) cmn_err(CE_PANIC, "%s(%d): " _s, \
                                __BASENAME__,            \
                                __LINE__)

#define DbgBreakIf(_cond)                                              \
    if (_cond)                                                         \
    {                                                                  \
        cmn_err(CE_PANIC, "%s(%d): Condition Failed! - if ("#_cond")", \
                __BASENAME__,                                          \
                __LINE__);                                             \
    }

#define DbgBreakFastPath()      DbgBreak()
#define DbgBreakMsgFastPath(_s) DbgBreakMsg(_s)
#define DbgBreakIfFastPath(_c)  DbgBreakIf(_c)

#define dbg_out(_c, _m, _s, _d1) DbgMessageXX(_c, _m, _s, _d1)

#endif /* DBG */


/*****************************************************************/
/* all BnxeDbgXXX() and BnxeLogXXX() routines are used by the UM */
/*****************************************************************/

#define BnxeDbgBreak(_c) cmn_err(CE_PANIC, "%s: %s(%d): DbgBreak!", \
                                 BnxeDevName(_c),                   \
                                 __BASENAME__,                      \
                                 __LINE__)

#define BnxeDbgBreakMsg(_c, _s) cmn_err(CE_PANIC, "%s: %s(%d): " _s, \
                                        BnxeDevName(_c),             \
                                        __BASENAME__,                \
                                        __LINE__)

#define BnxeDbgBreakIf(_c, _cond)                                          \
    if (_cond)                                                             \
    {                                                                      \
        cmn_err(CE_PANIC, "%s: %s(%d): Condition Failed! - if ("#_cond")", \
                BnxeDevName(_c),                                           \
                __BASENAME__,                                              \
                __LINE__);                                                 \
    }

#define BnxeDbgBreakFastPath(_c)           BnxeDbgBreak(_c)
#define BnxeDbgBreakMsgFastPath(_c, _s)    BnxeDbgBreakMsg(_c, _s)
#define BnxeDbgBreakIfFastPath(_c, _cond)  BnxeDbgBreakIf(_c, _cond)

void BnxeLogInfo(void * pDev, char * pFmt, ...);
void BnxeLogWarn(void * pDev, char * pFmt, ...);
/* for CE_PANIC use one of the BnxeDbgBreak macros above */

#ifdef DBG
void BnxeLogDbg(void * pDev, char * pFmt, ...);
#else
#define BnxeLogDbg
#endif

#endif /* __BNXE_DEBUG_H__ */

