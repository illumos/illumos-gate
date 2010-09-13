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

/* Copyright 2009 QLogic Corporation */

/*
 * File Name: exioctso.h
 *
 * San/Device Management OS dependent Ioctl Header
 *
 * ***********************************************************************
 * *                                                                    **
 * *                            NOTICE                                  **
 * *            COPYRIGHT (C) 2009 QLOGIC CORPORATION                   **
 * *                    ALL RIGHTS RESERVED                             **
 * *                                                                    **
 * ***********************************************************************
 *
 */

#ifndef _EXIOCTSO_H_
#define	_EXIOCTSO_H_

#include <sys/int_types.h>

#define	INT8	int8_t
#define	INT16	int16_t
#define	INT32	int32_t
#define	INT64	int64_t

#define	UINT8	uint8_t
#define	UINT16	uint16_t
#define	UINT32	uint32_t
#define	UINT64	uint64_t

#ifdef LP64
#define	EXT_ADDR_MODE_OS	EXT_DEF_ADDR_MODE_64
#else
#define	EXT_ADDR_MODE_OS	EXT_DEF_ADDR_MODE_32
#endif

#define	EXT_DEF_MAX_HBA_OS		256	/* 0 - 0xFF */
#define	EXT_DEF_MAX_BUS_OS		1
#define	EXT_DEF_MAX_TARGET_OS  		256	/* 0 - 0xFF */
#define	EXT_DEF_MAX_LUN_OS		16384
#define	EXT_DEF_NON_SCSI3_MAX_LUN_OS	256

/* required # of entries in AEN queue */
#define	EXT_DEF_MAX_AEN_QUEUE_OS		64


#define	EXT_CC_QUERY_OS				100
#define	EXT_CC_SEND_FCCT_PASSTHRU_OS		101
#define	EXT_CC_REG_AEN_OS			102
#define	EXT_CC_GET_AEN_OS			103
#define	EXT_CC_SEND_ELS_RNID_OS			104
#define	EXT_CC_SCSI_PASSTHRU_OS			105
#define	EXT_CC_READ_HOST_PARAMS_OS		106
#define	EXT_CC_READ_RISC_PARAMS_OS		107
#define	EXT_CC_UPDATE_HOST_PARAMS_OS		108
#define	EXT_CC_UPDATE_RISC_PARAMS_OS		109
#define	EXT_CC_READ_NVRAM_OS			110
#define	EXT_CC_UPDATE_NVRAM_OS			111
#define	EXT_CC_GET_DATA_OS			112
#define	EXT_CC_SET_DATA_OS			113
#define	EXT_CC_LOOPBACK_OS			114
#define	EXT_CC_HOST_IDX_OS			115
#define	EXT_CC_READ_OPTION_ROM_OS		116
#define	EXT_CC_UPDATE_OPTION_ROM_OS		117
#define	EXT_CC_READ_OPTION_ROM_EX_OS		118
#define	EXT_CC_UPDATE_OPTION_ROM_EX_OS		119
#define	EXT_CC_WWPN_TO_SCSIADDR_OS		120 /* Temporary definition */
#define	EXT_CC_GET_VPD_OS			121
#define	EXT_CC_SET_VPD_OS			122
#define	EXT_CC_GET_FCACHE_OS			123
#define	EXT_CC_HOST_DRVNAME_OS			124
#define	EXT_CC_GET_SFP_DATA_OS			125
#define	EXT_CC_PORT_PARAM_OS			126
#define	EXT_CC_GET_FCACHE_EX_OS			127
#define	EXT_CC_GET_PCI_DATA_OS			128
#define	EXT_CC_GET_FWEXTTRACE_OS		129
#define	EXT_CC_GET_FWFCETRACE_OS		130
#define	EXT_CC_MENLO_RESET			131
#define	EXT_CC_MENLO_GET_FW_VERSION		132
#define	EXT_CC_MENLO_UPDATE_FW			133
#define	EXT_CC_MENLO_MANAGE_INFO		134
#define	EXT_CC_GET_VP_CNT_ID_OS			135
#define	EXT_CC_VPORT_CMD_OS			136
#define	EXT_CC_ACCESS_FLASH_OS			137
#define	EXT_CC_RESET_FW_OS			138

#define	EXT_CC_HBA_NODE_SBUS			0x01

#endif /* _EXIOCTSO_H_ */
