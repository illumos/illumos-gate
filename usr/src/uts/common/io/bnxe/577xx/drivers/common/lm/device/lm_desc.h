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
 *    11/15/01 havk             Inception.
 ******************************************************************************/

#ifndef _LM_DESC_H
#define _LM_DESC_H

#include "fw_defs.h"

#ifndef StringIt
#define _StringIt(x)                    #x
#define StringIt(x)                     _StringIt(x)
#endif

#if DBG
#define LM_DEBUG_STR "\r\nDEBUG version"
#else
#define LM_DEBUG_STR ""
#endif

#define LM_DRIVER_MAJOR_VER     7
#define LM_DRIVER_MINOR_VER     10
#define LM_DRIVER_FIX_NUM       51
#define LM_DRIVER_ENG_NUM       00

/* major product release version which corresponds to T2.8, T3.0, etc. */
#define LM_PRODUCT_MAJOR_VER    18
#define LM_PRODUCT_MINOR_VER    4
#define LM_PRODUCT_FIX_NUM      0

#define LM_COMPANY_NAME_STR     "QLogic Corporation"
#define LM_COPYRIGHT_STR        "(c) COPYRIGHT 2014 QLogic Corporation"
#define LM_PRODUCT_NAME_STR     "QLogic NetXtreme II 10GigE"

#define LM_INFO_STR             "\r\nFW Ver:" StringIt(BCM_5710_FW_MAJOR_VERSION) "." StringIt(BCM_5710_FW_MINOR_VERSION) "." StringIt(BCM_5710_FW_REVISION_VERSION) "." StringIt(BCM_5710_FW_ENGINEERING_VERSION) "\r\nFW Compile:" StringIt(BCM_5710_FW_COMPILE_FLAGS) LM_DEBUG_STR

#endif /* _LM_DESC_H */
