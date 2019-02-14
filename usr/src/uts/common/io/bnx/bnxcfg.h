/*
 * Copyright 2014-2017 Cavium, Inc.
 * The contents of this file are subject to the terms of the Common Development
 * and Distribution License, v.1,  (the "License").
 *
 * You may not use this file except in compliance with the License.
 *
 * You can obtain a copy of the License at available
 * at http://opensource.org/licenses/CDDL-1.0
 *
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _BNXCFG_H
#define	_BNXCFG_H

#include "bnx.h"

#ifdef __cplusplus
extern "C" {
#endif

#define	USER_OPTION_KEYWORD_STATSTICKS	"statticks"
#define	USER_OPTION_KEYWORD_RX_DCOPY	"RxDCopy"


#define	USER_OPTION_CKSUM_NONE			0x0
#define	USER_OPTION_CKSUM_TX_ONLY		0x1
#define	USER_OPTION_CKSUM_RX_ONLY		0x2
#define	USER_OPTION_CKSUM_TX_RX			0x3
#define	USER_OPTION_CKSUM_DEFAULT		0x3

#define	USER_OPTION_STATSTICKS_MIN		0
#define	USER_OPTION_STATSTICKS_MAX		1000000
#define	USER_OPTION_STATSTICKS_DEFAULT		1000000

#define	USER_OPTION_TICKS_MIN			0
#define	USER_OPTION_TICKS_MAX			LM_HC_RX_TICKS_VAL_MAX

#define	USER_OPTION_TICKS_INT_MIN		0
#define	USER_OPTION_TICKS_INT_MAX		LM_HC_RX_TICKS_INT_MAX

#define	USER_OPTION_TXTICKS_DEFAULT		45
#define	USER_OPTION_TXTICKS_INT_DEFAULT		15
#define	USER_OPTION_RXTICKS_DEFAULT		20
#define	USER_OPTION_RXTICKS_INT_DEFAULT		15

#define	USER_OPTION_FRAMES_MIN			0
#define	USER_OPTION_FRAMES_MAX			LM_HC_RX_QUICK_CONS_TRIP_VAL_MAX

#define	USER_OPTION_TXFRAMES_DEFAULT		16
#define	USER_OPTION_TXFRAMES_INT_DEFAULT	8
#define	USER_OPTION_RXFRAMES_DEFAULT		4
#define	USER_OPTION_RXFRAMES_INT_DEFAULT	4

#define	USER_OPTION_TX_DESC_CNT_MIN		1
#define	USER_OPTION_TX_DESC_CNT_MAX		32385
#define	USER_OPTION_TX_DESC_CNT_DEFAULT		\
	(1024 - (1024 % MAX_BD_PER_PAGE))

#define	USER_OPTION_RX_DESC_CNT_MIN		1
#define	USER_OPTION_RX_DESC_CNT_MAX		32385
#define	USER_OPTION_RX_DESC_CNT_DEFAULT		(512 - (512 % MAX_BD_PER_PAGE))

#define	USER_OPTION_MTU_MIN			60
#define	USER_OPTION_MTU_MAX			9000
#define	USER_OPTION_MTU_DEFAULT		1500

#define	USER_OPTION_TX_DCOPY_THRESH_DEFAULT	512
#define	USER_OPTION_RX_DCOPY_DEFAULT		0xffffffff


extern const bnx_lnk_cfg_t bnx_copper_config;
extern const bnx_lnk_cfg_t bnx_serdes_config;

void bnx_cfg_msix(um_device_t * const umdevice);
void bnx_cfg_init(um_device_t * const umdevice);
void bnx_cfg_reset(um_device_t * const umdevice);
void bnx_cfg_map_phy(um_device_t * const umdevice);

#ifdef __cplusplus
}
#endif

#endif /* _BNXCFG_H */
