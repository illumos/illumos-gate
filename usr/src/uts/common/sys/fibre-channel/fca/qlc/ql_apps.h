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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef	_QL_APPS_H
#define	_QL_APPS_H

/*
 * ISP2xxx Solaris Fibre Channel Adapter (FCA) driver header file.
 *
 * ***********************************************************************
 * *									**
 * *				NOTICE					**
 * *		COPYRIGHT (C) 1996-2009 QLOGIC CORPORATION		**
 * *			ALL RIGHTS RESERVED				**
 * *									**
 * ***********************************************************************
 *
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/scsi/scsi_types.h>

/* f/w trace sizes */
#define	FWEXTSIZE		(0x4000 * 4)	/* bytes - 16kb multiples */
#define	FWFCESIZE		(0x4000 * 4)	/* bytes - 16kb multiples */

/*
 * ISP8100 Extended Initialization Control Block
 */
typedef struct ql_ext_icb_8100 {
	uint8_t version[2];
	/*
	 * BIT 0 = FCF VLAN ID Match
	 * BIT 1 = FCF Fabric Name Match
	 * BIT 2-7 = Reserved
	 */
	uint8_t fcf_vlan_match;
	uint8_t reserved_6[3];
	uint8_t fcf_vlan_id[2];
	uint8_t fcf_fabric_name[8];
	uint8_t reserved_7[14];
	uint8_t spma_proposed_mac_address[6];
	uint8_t reserved_8[28];
} ql_ext_icb_8100_t;

/*
 * Name:	Adapter Revsion Level Structure
 *
 * Purpose:	Supply various revision levels of h/w and driver
 *
 * Used by:
 *		qlctest utility
 *
 */
typedef struct ql_adapter_revlvl {
	uint16_t isp2200;			/* 2200 chip rev level */
	uint16_t risc;				/* risc rev level */
	uint16_t frmbfr;			/* frame buffer rev level */
	uint16_t riscrom;			/* risc rom rev level */
	char qlddv[16];				/* ql driver version string */
} ql_adapter_revlvl_t;

/*
 * Name:	Application Mailbox Interface Structure
 *
 * Purpose:	Used to pass mailbox data between app and driver.
 *
 * Used by:
 *		qlctest utility
 *
 */
typedef struct app_mbx_cmd {
	uint16_t	mb[32];
	uint8_t		reserved1[32];
} app_mbx_cmd_t;

/*
 * Name:	Diagnostic Loopback Parameter Structure
 *
 * Purpose:	Used for loopback parameter data
 *
 * Used by:
 *		qlctest utility
 *
 */
#ifndef apps_64bit
typedef struct lbp {
	uint16_t  options;
	uint32_t  transfer_count;
	uint16_t  transfer_segment_count;
	uint16_t  receive_segment_count;
	uint32_t  transfer_data_address;
	uint32_t  receive_data_address;
	uint32_t  iteration_count;
} lbp_t;
#else
typedef struct lbp {
	uint16_t  options;
	uint32_t  transfer_count;
	uint16_t  transfer_segment_count;
	uint16_t  receive_segment_count;
	uint64_t  transfer_data_address;
	uint64_t  receive_data_address;
	uint32_t  iteration_count;
} lbp_t;
#endif

/*
 * Defines used by:
 *			qlctest utility
 *
 * Prupose:
 *	diag switch clause hooks provided for requested diagnostic
 *	functionality (Check command Queue, Revision Level, Firmwware
 *	Checksum, Self Test, Loopback Mailbox, Loopback Data, Execute
 *	Firmware and send ECHO.
 */
#define	QL_DIAG_CHKCMDQUE		0
#define	QL_DIAG_FMWCHKSUM		1
#define	QL_DIAG_SLFTST			2
#define	QL_DIAG_REVLVL			3
#define	QL_DIAG_LPBMBX			4
#define	QL_DIAG_LPBDTA			5
#define	QL_DIAG_EXEFMW			6
#define	QL_GET_ADAPTER_FEATURE_BITS	7
#define	QL_SET_ADAPTER_FEATURE_BITS	8
#define	QL_SET_ADAPTER_NVRAM_DEFAULTS	9
#define	QL_DIAG_ECHO			10

/*
 * Defines used for:
 *			qladm utility
 *			qlctest utility
 *
 * Purpose:
 *	Driver IOCTL numbers for nvram dump/load, and driverop
 *	functions. NB: 300 --> 399 are reserved for qla2x00 foapi's
 */
#define	QL_UTIL_LOAD	100
#define	QL_UTIL_DUMP	101
#define	QL_FOAPI_START	300
#define	QL_FOAPI_END	399
#define	QL_ADM_OP	402

/*
 * Purpose:
 *	QLA_ADM_OP command definitions
 *
 * Used by:
 *		qladm utility
 *		qlctest utility
 */
typedef enum ql_adm_cmd  {
	QL_EXTENDED_LOGGING,
	QL_ADAPTER_INFO,
	QL_DEVICE_LIST,
	QL_LOOP_RESET,
	QL_FW_DUMP,
	QL_NVRAM_LOAD,
	QL_NVRAM_DUMP,
	QL_FLASH_LOAD,
	QL_PROP_UPDATE_INT,
	QL_UPDATE_PROPERTIES,
	QL_VPD_LOAD,
	QL_VPD_DUMP,
	QL_VPD_GETTAG,
	QL_UPD_FWMODULE
} ql_adm_cmd_t;

/*
 * Purpose:
 *	QLA_ADM_OP Parameter Interface Structure
 *
 * Used by:
 *		qladm utility
 *		qlctest utility
 */
typedef struct ql_adm_op {
	uint64_t	buffer;
	uint32_t	length;
	uint32_t	option;
	ql_adm_cmd_t	cmd;	/* driver_op command */
} ql_adm_op_t;

/*
 * Purpose:
 *	QLA_ADM_OP parameter data structure
 *
 * Used by:
 *		qladm utility
 *		qlctest utility
 */
#define	MAX_PROP_LENGTH	256
typedef struct ql_adapter_info {
	uint8_t		wwpn[8];
	uint32_t	d_id;
	uint32_t	flash_size;
	uint16_t	device_id;
	char		fw_ver[MAX_PROP_LENGTH];
	char		fcode_ver[MAX_PROP_LENGTH];
	char		driver_ver[MAX_PROP_LENGTH];
} ql_adapter_info_t;

/*
 * Purpose:
 *	QLA_ADM_OP data types (Fibre channel port types)
 *
 * Used by:
 *		qladm utility
 *		qlctest utility
 */
typedef enum ql_port_type {
	FCT_UNKNOWN,
	FCT_TAPE,
	FCT_INITIATOR,
	FCT_TARGET
} ql_port_type_t;

/*
 * Purpose:
 *	QLA_ADM_OP Device Information Structure
 *
 * Used by:
 *		qladm utility
 *		qlctest utility
 */
typedef struct ql_device_info {
	uint8_t		wwpn[8];
	uint32_t	address;
	ql_port_type_t	type;
	uint16_t	loop_id;
} ql_device_info_t;

#ifdef	__cplusplus
}
#endif

#endif /* _QL_APPS_H */
