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
 * Copyright 2010 QLogic Corporation.  All rights reserved.
 * Use is subject to license terms.
 */

/*
 * File Name: exioct.h
 *
 * San/Device Management Ioctl Header
 * File is created to adhere to Solaris requirement using 8-space tabs.
 *
 * !!!!! PLEASE DO NOT REMOVE THE TABS !!!!!
 * !!!!! PLEASE NO SINGLE LINE COMMENTS: // !!!!!
 * !!!!! PLEASE NO MORE THAN 80 CHARS PER LINE !!!!!
 *
 * ***********************************************************************
 * *                                                                    **
 * *                            NOTICE                                  **
 * *            COPYRIGHT (C) 2000-2010 QLOGIC CORPORATION              **
 * *                    ALL RIGHTS RESERVED                             **
 * *                                                                    **
 * ***********************************************************************
 */

#ifndef	_EXIOCT_H
#define	_EXIOCT_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <exioctso.h>

/*
 * NOTE: the following version defines must be updated each time the
 *	 changes made may affect the backward compatibility of the
 *	 input/output relations of the SDM IOCTL functions.
 */
#define	EXT_VERSION				5

/*
 * OS independent General definitions
 */
#define	EXT_DEF_SIGNATURE_SIZE			8
#define	EXT_DEF_WWN_NAME_SIZE			8
#define	EXT_DEF_WWP_NAME_SIZE			8
#define	EXT_DEF_SERIAL_NUM_SIZE			4
#define	EXT_DEF_PORTID_SIZE			4
#define	EXT_DEF_PORTID_SIZE_ACTUAL		3
#define	EXT_DEF_MAX_STR_SIZE			128
#define	EXT_DEF_SCSI_PASSTHRU_CDB_LENGTH	12
#define	EXT_DEF_MAC_ADDRESS_SIZE		6

#define	EXT_DEF_ADDR_MODE_32			1
#define	EXT_DEF_ADDR_MODE_64			2

/*
 * ***********************************************************************
 * OS dependent General configuration defines
 * ***********************************************************************
 */
#define	EXT_DEF_MAX_HBA			EXT_DEF_MAX_HBA_OS
#define	EXT_DEF_MAX_BUS			EXT_DEF_MAX_BUS_OS
#define	EXT_DEF_MAX_TARGET		EXT_DEF_MAX_TARGET_OS
#define	EXT_DEF_MAX_LUN			EXT_DEF_MAX_LUN_OS
#define	EXT_DEF_NON_SCSI3_MAX_LUN	EXT_DEF_NON_SCSI3_MAX_LUN_OS

/*
 * ***********************************************************************
 * Common header struct definitions for San/Device Mgmt
 * ***********************************************************************
 */
typedef struct {
	UINT64	Signature;			/* 8 chars string */
	UINT64	RequestAdr;			/* 8  */
	UINT64	ResponseAdr;			/* 8  */
	UINT64	VendorSpecificData;		/* 8 chars string */
	UINT32	Status;				/* 4  */
	UINT32	DetailStatus;			/* 4  */
	UINT32	Reserved1;			/* 4  */
	UINT32	RequestLen;			/* 4  */
	UINT32	ResponseLen;			/* 4  */
	UINT16	AddrMode;			/* 2  */
	UINT16	Version;			/* 2  */
	UINT16	SubCode;			/* 2  */
	UINT16	Instance;			/* 2  */
	UINT16	HbaSelect;			/* 2  */
	UINT16	VendorSpecificStatus[11];	/* 22 */
} EXT_IOCTL, *PEXT_IOCTL;			/* size = 84 / 0x54 */

typedef union _ext_signature {
	UINT64	Signature;
	char	bytes[EXT_DEF_SIGNATURE_SIZE];
} ext_sig_t;

/*
 * Addressing mode used by the user application
 */
#define	EXT_ADDR_MODE	EXT_ADDR_MODE_OS

/*
 * Status.  These macros are being used for setting Status field in
 * EXT_IOCTL structure.
 */
#define	EXT_STATUS_OK			0
#define	EXT_STATUS_ERR			1
#define	EXT_STATUS_BUSY			2
#define	EXT_STATUS_PENDING		3
#define	EXT_STATUS_SUSPENDED		4
#define	EXT_STATUS_RETRY_PENDING	5
#define	EXT_STATUS_INVALID_PARAM	6
#define	EXT_STATUS_DATA_OVERRUN		7
#define	EXT_STATUS_DATA_UNDERRUN	8
#define	EXT_STATUS_DEV_NOT_FOUND	9
#define	EXT_STATUS_COPY_ERR		10
#define	EXT_STATUS_MAILBOX		11
#define	EXT_STATUS_UNSUPPORTED_SUBCODE	12
#define	EXT_STATUS_UNSUPPORTED_VERSION	13
#define	EXT_STATUS_MS_NO_RESPONSE	14
#define	EXT_STATUS_SCSI_STATUS		15
#define	EXT_STATUS_BUFFER_TOO_SMALL	16
#define	EXT_STATUS_NO_MEMORY		17
#define	EXT_STATUS_UNKNOWN		18
#define	EXT_STATUS_UNKNOWN_DSTATUS	19
#define	EXT_STATUS_INVALID_REQUEST	20
#define	EXT_STATUS_DEVICE_NOT_READY	21
#define	EXT_STATUS_DEVICE_OFFLINE	22
#define	EXT_STATUS_HBA_NOT_READY	23
#define	EXT_STATUS_HBA_QUEUE_FULL	24
#define	EXT_STATUS_INVALID_VPINDEX	25

/*
 * Detail Status contains the SCSI bus status codes.
 */

#define	EXT_DSTATUS_GOOD			0x00
#define	EXT_DSTATUS_CHECK_CONDITION		0x02
#define	EXT_DSTATUS_CONDITION_MET		0x04
#define	EXT_DSTATUS_BUSY			0x08
#define	EXT_DSTATUS_INTERMEDIATE		0x10
#define	EXT_DSTATUS_INTERMEDIATE_COND_MET	0x14
#define	EXT_DSTATUS_RESERVATION_CONFLICT	0x18
#define	EXT_DSTATUS_COMMAND_TERMINATED		0x22
#define	EXT_DSTATUS_QUEUE_FULL			0x28

/*
 * Detail Status contains the needed Response buffer space(bytes)
 * when Status = EXT_STATUS_BUFFER_TOO_SMALL
 */


/*
 * Detail Status contains one of the following codes
 * when Status = EXT_STATUS_INVALID_PARAM or
 *             = EXT_STATUS_DEV_NOT_FOUND
 */
#define	EXT_DSTATUS_NOADNL_INFO			0x00
#define	EXT_DSTATUS_HBA_INST			0x01
#define	EXT_DSTATUS_TARGET			0x02
#define	EXT_DSTATUS_LUN				0x03
#define	EXT_DSTATUS_REQUEST_LEN			0x04
#define	EXT_DSTATUS_PATH_INDEX			0x05

/*
 * Currently supported DeviceControl / ioctl command codes
 */
#define	EXT_CC_QUERY			EXT_CC_QUERY_OS
#define	EXT_CC_SEND_FCCT_PASSTHRU	EXT_CC_SEND_FCCT_PASSTHRU_OS
#define	EXT_CC_REG_AEN			EXT_CC_REG_AEN_OS
#define	EXT_CC_GET_AEN			EXT_CC_GET_AEN_OS
#define	EXT_CC_SEND_ELS_RNID		EXT_CC_SEND_ELS_RNID_OS
#define	EXT_CC_SEND_SCSI_PASSTHRU	EXT_CC_SCSI_PASSTHRU_OS
#define	EXT_CC_READ_HOST_PARAMS		EXT_CC_READ_HOST_PARAMS_OS
#define	EXT_CC_READ_RISC_PARAMS		EXT_CC_READ_RISC_PARAMS_OS
#define	EXT_CC_UPDATE_HOST_PARAMS	EXT_CC_UPDATE_HOST_PARAMS_OS
#define	EXT_CC_UPDATE_RISC_PARAMS	EXT_CC_UPDATE_RISC_PARAMS_OS
#define	EXT_CC_READ_NVRAM		EXT_CC_READ_NVRAM_OS
#define	EXT_CC_UPDATE_NVRAM		EXT_CC_UPDATE_NVRAM_OS
#define	EXT_CC_HOST_IDX			EXT_CC_HOST_IDX_OS
#define	EXT_CC_LOOPBACK			EXT_CC_LOOPBACK_OS
#define	EXT_CC_READ_OPTION_ROM		EXT_CC_READ_OPTION_ROM_OS
#define	EXT_CC_READ_OPTION_ROM_EX	EXT_CC_READ_OPTION_ROM_EX_OS
#define	EXT_CC_UPDATE_OPTION_ROM	EXT_CC_UPDATE_OPTION_ROM_OS
#define	EXT_CC_UPDATE_OPTION_ROM_EX	EXT_CC_UPDATE_OPTION_ROM_EX_OS
#define	EXT_CC_GET_VPD			EXT_CC_GET_VPD_OS
#define	EXT_CC_SET_VPD			EXT_CC_SET_VPD_OS
#define	EXT_CC_GET_FCACHE		EXT_CC_GET_FCACHE_OS
#define	EXT_CC_GET_FCACHE_EX		EXT_CC_GET_FCACHE_EX_OS
#define	EXT_CC_HOST_DRVNAME		EXT_CC_HOST_DRVNAME_OS
#define	EXT_CC_GET_SFP_DATA		EXT_CC_GET_SFP_DATA_OS
#define	EXT_CC_WWPN_TO_SCSIADDR		EXT_CC_WWPN_TO_SCSIADDR_OS
#define	EXT_CC_PORT_PARAM		EXT_CC_PORT_PARAM_OS
#define	EXT_CC_GET_PCI_DATA		EXT_CC_GET_PCI_DATA_OS
#define	EXT_CC_GET_FWEXTTRACE		EXT_CC_GET_FWEXTTRACE_OS
#define	EXT_CC_GET_FWFCETRACE		EXT_CC_GET_FWFCETRACE_OS
#define	EXT_CC_GET_VP_CNT_ID		EXT_CC_GET_VP_CNT_ID_OS
#define	EXT_CC_VPORT_CMD		EXT_CC_VPORT_CMD_OS
#define	EXT_CC_ACCESS_FLASH		EXT_CC_ACCESS_FLASH_OS
#define	EXT_CC_RESET_FW			EXT_CC_RESET_FW_OS

/*
 * HBA port operations
 */
#define	EXT_CC_GET_DATA		EXT_CC_GET_DATA_OS
#define	EXT_CC_SET_DATA		EXT_CC_SET_DATA_OS

/*
 * The following DeviceControl / ioctl command codes currently are not
 * supported.
 */
#define	EXT_CC_SEND_ELS_RTIN	EXT_CC_SEND_ELS_RTIN_OS


/*
 * ***********************************************************************
 * EXT_IOCTL SubCode definition.
 * These macros are being used for setting SubCode field in EXT_IOCTL
 * structure.
 * ***********************************************************************
 */

/*
 * Query.
 * Uses with EXT_QUERY as the ioctl code.
 */
#define	EXT_SC_QUERY_HBA_NODE		1
#define	EXT_SC_QUERY_HBA_PORT		2
#define	EXT_SC_QUERY_DISC_PORT		3
#define	EXT_SC_QUERY_DISC_TGT		4
#define	EXT_SC_QUERY_DISC_LUN		5	/* Currently Not Supported */
#define	EXT_SC_QUERY_DRIVER		6
#define	EXT_SC_QUERY_FW			7
#define	EXT_SC_QUERY_CHIP		8
#define	EXT_SC_QUERY_CNA_PORT		9
#define	EXT_SC_QUERY_ADAPTER_VERSIONS	10

/*
 * Get.
 * Uses with EXT_GET_DATA as the ioctl code
 */
/* 1 - 99 Common */
#define	EXT_SC_GET_SCSI_ADDR		1	/* Currently Not Supported */
#define	EXT_SC_GET_ERR_DETECTIONS	2	/* Currently Not Supported */
#define	EXT_SC_GET_STATISTICS		3
#define	EXT_SC_GET_BUS_MODE		4	/* Currently Not Supported */
#define	EXT_SC_GET_DR_DUMP_BUF		5	/* Currently Not Supported */
#define	EXT_SC_GET_RISC_CODE		6
#define	EXT_SC_GET_FLASH_RAM		7
#define	EXT_SC_GET_BEACON_STATE		8
#define	EXT_SC_GET_DCBX_PARAM		9
#define	EXT_SC_GET_FCF_LIST		10
#define	EXT_SC_GET_RESOURCE_CNTS	11

/* 100 - 199 FC_INTF_TYPE */
#define	EXT_SC_GET_LINK_STATUS		101	/* Currently Not Supported */
#define	EXT_SC_GET_LOOP_ID		102	/* Currently Not Supported */
#define	EXT_SC_GET_LUN_BITMASK		103
#define	EXT_SC_GET_PORT_DATABASE	104	/* Currently Not Supported */
#define	EXT_SC_GET_PORT_DATABASE_MEM	105	/* Currently Not Supported */
#define	EXT_SC_GET_PORT_SUMMARY		106
#define	EXT_SC_GET_POSITION_MAP		107
#define	EXT_SC_GET_RETRY_CNT		108	/* Currently Not Supported */
#define	EXT_SC_GET_RNID			109
#define	EXT_SC_GET_RTIN			110	/* Currently Not Supported */
#define	EXT_SC_GET_FC_LUN_BITMASK	111
#define	EXT_SC_GET_FC_STATISTICS	112
#define	EXT_SC_GET_FC4_STATISTICS	113
#define	EXT_SC_GET_TARGET_ID		114


/* 200 - 299 SCSI_INTF_TYPE */
#define	EXT_SC_GET_SEL_TIMEOUT		201	/* Currently Not Supported */

#define	EXT_DEF_DCBX_PARAM_BUF_SIZE	4096	/* Bytes */

/*
 * Set.
 * Uses with EXT_SET_DATA as the ioctl code
 */
/* 1 - 99 Common */
#define	EXT_SC_RST_STATISTICS		3
#define	EXT_SC_SET_BUS_MODE		4	/* Currently Not Supported */
#define	EXT_SC_SET_DR_DUMP_BUF		5	/* Currently Not Supported */
#define	EXT_SC_SET_RISC_CODE		6
#define	EXT_SC_SET_FLASH_RAM		7
#define	EXT_SC_SET_BEACON_STATE		8

/* special types (non snia) */
#define	EXT_SC_SET_PARMS		99	/* dpb */

/* 100 - 199 FC_INTF_TYPE */
#define	EXT_SC_SET_LUN_BITMASK		103
#define	EXT_SC_SET_RETRY_CNT		108	/* Currently Not Supported */
#define	EXT_SC_SET_RNID			109
#define	EXT_SC_SET_RTIN			110	/* Currently Not Supported */
#define	EXT_SC_SET_FC_LUN_BITMASK	111
#define	EXT_SC_ADD_TARGET_DEVICE	112
#define	EXT_SC_SWAP_TARGET_DEVICE	113

/* 200 - 299 SCSI_INTF_TYPE */
#define	EXT_SC_SET_SEL_TIMEOUT		201	/* Currently Not Supported */

/* SCSI passthrough */
#define	EXT_SC_SEND_SCSI_PASSTHRU	0
#define	EXT_SC_SEND_FC_SCSI_PASSTHRU	1

/* NVRAM */
#define	EXT_SC_NVRAM_HARDWARE		0	/* Save */
#define	EXT_SC_NVRAM_DRIVER		1	/* Driver (Apply) */
#define	EXT_SC_NVRAM_ALL		2	/* NVRAM/Driver (Save+Apply) */

/*
 * Vport functions
 * Used with EXT_CC_VPORT_CMD as the ioctl code.
 */
#define	EXT_VF_SC_VPORT_GETINFO		1
#define	EXT_VF_SC_VPORT_DELETE		2
#define	EXT_VF_SC_VPORT_MODIFY		3
#define	EXT_VF_SC_VPORT_CREATE		4

/*
 * Flash access sub codes
 * Used with EXT_CC_ACCESS_FLASH as the ioctl code.
 */
#define	EXT_SC_FLASH_READ	0
#define	EXT_SC_FLASH_WRITE	1

/*
 * Reset FW subcodes for Schultz
 * Used with EXT_CC_RESET_FW as the ioctl code.
 */
#define	EXT_SC_RESET_FC_FW	1
#define	EXT_SC_RESET_MPI_FW	2

/* Read */

/* Write */

/* Reset */

/* Request struct */


/*
 * Response struct
 */
typedef struct _EXT_HBA_NODE {
	UINT32	DriverAttr;				/* 4 */
	UINT32	FWAttr;					/* 4 */
	UINT16	PortCount;				/* 2; 1 */
	UINT16	InterfaceType;				/* 2; FC/SCSI */
	UINT8	WWNN[EXT_DEF_WWN_NAME_SIZE];		/* 8 */
	UINT8	Manufacturer[EXT_DEF_MAX_STR_SIZE];	/* 128; "QLOGIC" */
	UINT8	Model[EXT_DEF_MAX_STR_SIZE];		/* 128; "QLA2200" */
	UINT8	SerialNum[EXT_DEF_SERIAL_NUM_SIZE];	/* 4;  123  */
	UINT8	DriverVersion[EXT_DEF_MAX_STR_SIZE];	/* 128; "7.4.3" */
	UINT8	FWVersion[EXT_DEF_MAX_STR_SIZE];	/* 128; "2.1.6" */
	UINT8	OptRomVersion[EXT_DEF_MAX_STR_SIZE];	/* 128; "1.44" */
	UINT8	Reserved[32];				/* 32 */
} EXT_HBA_NODE, *PEXT_HBA_NODE;				/* 696 */

/* HBA node query interface type */
#define	EXT_DEF_FC_INTF_TYPE			1
#define	EXT_DEF_SCSI_INTF_TYPE			2
#define	EXT_DEF_VIRTUAL_FC_INTF_TYPE		3

typedef struct _EXT_HBA_PORT {
	UINT64	Target;				/* 8 */
	UINT32	PortSupportedSpeed;		/* 4 */
	UINT32	PortSpeed;			/* 4 */
	UINT16	Type;				/* 2; Port Type */
	UINT16	State;				/* 2; Port State */
	UINT16	Mode;				/* 2 */
	UINT16	DiscPortCount;			/* 2 */
	UINT16	DiscPortNameType;		/* 2; USE_NODE_NAME or */
						/* USE_PORT_NAME */
	UINT16	DiscTargetCount;		/* 2 */
	UINT16	Bus;				/* 2 */
	UINT16	Lun;				/* 2 */
	UINT8	WWPN[EXT_DEF_WWN_NAME_SIZE];	/* 8 */
	UINT8	Id[EXT_DEF_PORTID_SIZE];	/* 4; 3 bytes valid Port Id. */
	UINT8	PortSupportedFC4Types;		/* 1 */
	UINT8	PortActiveFC4Types;		/* 1 */
	UINT8	FabricName[EXT_DEF_WWN_NAME_SIZE];	/* 8 */
	UINT16	LinkState2;			/* 2; sfp status */
	UINT16	LinkState3;			/* 2; reserved field */
	UINT8	Reserved[6];			/* 6 */
} EXT_HBA_PORT, *PEXT_HBA_PORT;			/* 64 */

/* FC-4 Instrumentation */
typedef struct _EXT_HBA_FC4Statistics {
	INT64	InputRequests;			/* 8  */
	INT64	OutputRequests;			/* 8  */
	INT64	ControlRequests;		/* 8  */
	INT64	InputMegabytes;			/* 8  */
	INT64	OutputMegabytes;		/* 8  */
	UINT64	Reserved[6];			/* 48 */
} EXT_HBA_FC4STATISTICS, *PEXT_HBA_FC4STATISTICS;	/* 88 */

typedef struct _EXT_LOOPBACK_REQ {
	UINT32	TransferCount;
	UINT32	IterationCount;
	UINT32	BufferAddress;
	UINT32	BufferLength;
	UINT16	Options;
	UINT8	Reserved[18];
} EXT_LOOPBACK_REQ, *PEXT_LOOPBACK_REQ;

typedef struct _EXT_LOOPBACK_RSP {
	UINT64	BufferAddress;
	UINT32	BufferLength;
	UINT32	IterationCountLastError;
	UINT16	CompletionStatus;
	UINT16	CrcErrorCount;
	UINT16	DisparityErrorCount;
	UINT16	FrameLengthErrorCount;
	UINT8	CommandSent;
	UINT8	Reserved[15];
} EXT_LOOPBACK_RSP, *PEXT_LOOPBACK_RSP;

/* used with loopback response CommandSent */
#define	INT_DEF_LB_LOOPBACK_CMD		0
#define	INT_DEF_LB_ECHO_CMD		1

/* definition for interpreting CompletionStatus values */
#define	EXT_DEF_LB_COMPLETE	0x4000
#define	EXT_DEF_LB_PARAM_ERR	0x4006
#define	EXT_DEF_LB_LOOP_DOWN	0x400b
#define	EXT_DEF_LB_CMD_ERROR	0x400c

/* port type */
#define	EXT_DEF_INITIATOR_DEV	0x1
#define	EXT_DEF_TARGET_DEV	0x2
#define	EXT_DEF_TAPE_DEV	0x4
#define	EXT_DEF_FABRIC_DEV	0x8


/* HBA port state */
#define	EXT_DEF_HBA_OK		0
#define	EXT_DEF_HBA_SUSPENDED	1
#define	EXT_DEF_HBA_LOOP_DOWN	2

/* Connection mode */
#define	EXT_DEF_UNKNOWN_MODE	0
#define	EXT_DEF_P2P_MODE	1
#define	EXT_DEF_LOOP_MODE	2
#define	EXT_DEF_FL_MODE		3
#define	EXT_DEF_N_MODE		4

/* Valid name type for Disc. port/target */
#define	EXT_DEF_USE_NODE_NAME	1
#define	EXT_DEF_USE_PORT_NAME	2

/* FC4 type values */
#define	EXT_DEF_FC4_TYPE_SCSI	0x1
#define	EXT_DEF_FC4_TYPE_IP	0x2
#define	EXT_DEF_FC4_TYPE_SCTP	0x4
#define	EXT_DEF_FC4_TYPE_VI	0x8

/* IIDMA rate values */
#define	IIDMA_RATE_1GB		0x0
#define	IIDMA_RATE_2GB		0x1
#define	IIDMA_RATE_4GB		0x3
#define	IIDMA_RATE_8GB		0x4
#define	IIDMA_RATE_10GB		0x13
#define	IIDMA_RATE_UNKNOWN	0xffff

/* IIDMA Mode values */
#define	IIDMA_MODE_0		0
#define	IIDMA_MODE_1		1
#define	IIDMA_MODE_2		2
#define	IIDMA_MODE_3		3

/* Port Speed values */
#define	EXT_DEF_PORTSPEED_UNKNOWN 	0x0
#define	EXT_DEF_PORTSPEED_1GBIT		0x1
#define	EXT_DEF_PORTSPEED_2GBIT		0x2
#define	EXT_DEF_PORTSPEED_4GBIT		0x4
#define	EXT_DEF_PORTSPEED_8GBIT		0x8
#define	EXT_DEF_PORTSPEED_10GBIT	0x10
#define	EXT_PORTSPEED_NOT_NEGOTIATED	(1<<15)	/* Speed not established */

typedef struct _EXT_DISC_PORT {
	UINT64	TargetId;		/* 8 */
	UINT16	Type;			/* 2; Port Type */
	UINT16	Status;			/* 2; Port Status */
	UINT16	Bus;			/* 2; n/a for Solaris */
	UINT16	LoopID;			/* 2; Loop ID */
	UINT8	WWNN[EXT_DEF_WWN_NAME_SIZE];	/* 8 */
	UINT8	WWPN[EXT_DEF_WWN_NAME_SIZE];	/* 8 */
	UINT8	Id[EXT_DEF_PORTID_SIZE];	/* 4; 3 bytes used big endian */
	UINT8	Local;			/* 1; Local or Remote */
	UINT8	Reserved[27];		/* 27 */
} EXT_DISC_PORT, *PEXT_DISC_PORT;	/* 64 */

typedef struct _EXT_DISC_TARGET {
	UINT64	TargetId;		/* 8 */
	UINT16	Type;			/* 2; Target Type */
	UINT16	Status;			/* 2; Target Status */
	UINT16	Bus;			/* 2; n/a for Solaris */
	UINT16	LunCount;		/* 2; n/a for nt */
	UINT16	LoopID;			/* 2; Loop ID */
	UINT8	WWNN[EXT_DEF_WWN_NAME_SIZE];	/* 8 */
	UINT8	WWPN[EXT_DEF_WWN_NAME_SIZE];	/* 8 */
	UINT8	Id[EXT_DEF_PORTID_SIZE];	/* 4; 3 bytes used big endian */
	UINT8	Local;			/* 1; Local or Remote */
	UINT8	Reserved[25];		/* 25 */
} EXT_DISC_TARGET, *PEXT_DISC_TARGET;	/* 64 */

/* The following command is not supported */
typedef struct _EXT_DISC_LUN {	/* n/a for nt */
	UINT16	Id;		/* 2 */
	UINT16	State;		/* 2 */
	UINT16	IoCount;	/* 2 */
	UINT8	Reserved[30];	/* 30 */
} EXT_DISC_LUN, *PEXT_DISC_LUN;	/* 36 */


/* SCSI address */
typedef struct _EXT_SCSI_ADDR {
	UINT64	Target;			/* 8 */
	UINT16	Bus;			/* 2 */
	UINT16	Lun;			/* 2 */
	UINT8	Padding[12];		/* 12 */
} EXT_SCSI_ADDR, *PEXT_SCSI_ADDR;	/* 24 */


/* Fibre Channel address */
typedef struct _EXT_FC_ADDR {
	UINT16	Type;					/* 2 */
	union {
		UINT8	WWNN[EXT_DEF_WWN_NAME_SIZE];	/* 8 */
		UINT8	WWPN[EXT_DEF_WWN_NAME_SIZE];	/* 8 */
		UINT8	Id[EXT_DEF_PORTID_SIZE];	/* 4 */
	} FcAddr;
	UINT8	Padding[4];				/* 4 */
} EXT_FC_ADDR, *PEXT_FC_ADDR;				/* 14 */

#define	EXT_DEF_TYPE_WWNN	1
#define	EXT_DEF_TYPE_WWPN	2
#define	EXT_DEF_TYPE_PORTID	3
#define	EXT_DEF_TYPE_FABRIC	4

/* Destination address */
typedef struct _EXT_DEST_ADDR {
	union {
		struct {
			UINT64	Target;			/* 8 */
			UINT16	Bus;			/* 2 */
			UINT8	pad[6];			/* 6 */
		} ScsiAddr;
		UINT8	WWNN[EXT_DEF_WWN_NAME_SIZE];	/* 8 */
		UINT8	WWPN[EXT_DEF_WWN_NAME_SIZE];	/* 8 */
		UINT8	Id[EXT_DEF_PORTID_SIZE];	/* 4 */
	} DestAddr;
	UINT16	DestType;				/* 2 */
	UINT16	Lun;					/* 2 */
	UINT8	Padding[4];				/* 4 */
} EXT_DEST_ADDR, *PEXT_DEST_ADDR;			/* 24 */


#define	EXT_DEF_DESTTYPE_WWNN		1
#define	EXT_DEF_DESTTYPE_WWPN		2
#define	EXT_DEF_DESTTYPE_PORTID		3
#define	EXT_DEF_DESTTYPE_FABRIC		4
#define	EXT_DEF_DESTTYPE_SCSI		5

/* Statistic */
typedef struct _EXT_HBA_PORT_STAT {
	UINT32	ControllerErrorCount;		/* 4 */
	UINT32	DeviceErrorCount;		/* 4 */
	UINT32	IoCount;			/* 4 */
	UINT32	MBytesCount;			/* 4; MB of data processed */
	UINT32	LipResetCount;			/* 4; Total no. of LIP Reset */
	UINT32	InterruptCount;			/* 4; Total no. of Interrupts */
	UINT32	LinkFailureCount;		/* 4 */
	UINT32	LossOfSyncCount;		/* 4 */
	UINT32	LossOfSignalsCount;		/* 4 */
	UINT32	PrimitiveSeqProtocolErrorCount;	/* 4 */
	UINT32	InvalidTransmissionWordCount;	/* 4 */
	UINT32	InvalidCRCCount;		/* 4 */
	UINT8	Reserved[64];			/* 64 */
} EXT_HBA_PORT_STAT, *PEXT_HBA_PORT_STAT;	/* 112 */


/* Driver property */
typedef struct _EXT_DRIVER {
	UINT32	MaxTransferLen;			/* 4 */
	UINT32	MaxDataSegments;		/* 4 */
	UINT32	Attrib;				/* 4 */
	UINT32	InternalFlags[4];		/* 16 */
	UINT16	NumOfBus;			/* 2; Port Type */
	UINT16	TargetsPerBus;			/* 2; Port Status */
	UINT16	LunsPerTarget;			/* 2 */
	UINT16	DmaBitAddresses;		/* 2 */
	UINT16	IoMapType;			/* 2 */
	UINT8	Version[EXT_DEF_MAX_STR_SIZE];	/* 128 */
	UINT8	Reserved[32];			/* 32 */
} EXT_DRIVER, *PEXT_DRIVER;			/* 198 */


/* Firmware property */
typedef struct _EXT_FW {
	UINT32	Attrib;				/* 4 */
	UINT8	Version[EXT_DEF_MAX_STR_SIZE];	/* 128 */
	UINT8	Reserved[66];			/* 66 */
} EXT_FW, *PEXT_FW;				/* 198 */

/* ISP/Chip property */
typedef struct _EXT_CHIP {
	UINT32	IoAddr;		/* 4 */
	UINT32	IoAddrLen;	/* 4 */
	UINT32	MemAddr;	/* 4 */
	UINT32	MemAddrLen;	/* 4 */
	UINT16	VendorId;	/* 2 */
	UINT16	DeviceId;	/* 2 */
	UINT16	SubVendorId;	/* 2 */
	UINT16	SubSystemId;	/* 2 */
	UINT16	PciBusNumber;	/* 2 */
	UINT16	PciSlotNumber;	/* 2 */
	UINT16	ChipType;	/* 2 */
	UINT16	InterruptLevel;	/* 2 */
	UINT16	OutMbx[8];	/* 16 */
	UINT16	FuncNo;		/* 2 */
	UINT8	Reserved[29];	/* 29 */
	UINT8	ChipRevID;	/* 1 */
} EXT_CHIP, *PEXT_CHIP;		/* 80 */

/* CNA properties */
typedef struct _EXT_CNA_PORT {
	UINT16	VLanId;						/* 2 */
	UINT8	VNPortMACAddress[EXT_DEF_MAC_ADDRESS_SIZE];	/* 6 */
	UINT16	FabricParam;					/* 2 */
	UINT16	Reserved0;					/* 2 */
	UINT32	Reserved[29];					/* 116 */
} EXT_CNA_PORT, *PEXT_CNA_PORT;					/* 128 */

/* Fabric Parameters */
#define	EXT_DEF_MAC_ADDR_MODE_FPMA	0x8000

#define	NO_OF_VERSIONS			2
#define	FLASH_VERSION			0
#define	RUNNING_VERSION			1
#define	EXT_OPT_ROM_REGION_MPI_RISC_FW	0x40
#define	EXT_OPT_ROM_REGION_EDC_PHY_FW	0x45

typedef struct _EXT_REGIONVERSION {
	UINT16	Region;
	UINT16	SubRegion;	/* If all boot codes are under region 0x7 */
	UINT16	Location;	/* 0: Flash, 1: Running */
	UINT16	VersionLength;
	UINT8	Version[8];
	UINT8	Reserved[8];
} EXT_REGIONVERSION, *PEXT_REGIONVERSION;

typedef struct _EXT_ADAPTERREGIONVERSION {
	UINT32	Length;		/* number of struct REGIONVERSION */
	UINT32	Reserved;
	EXT_REGIONVERSION RegionVersion[1];	/* variable length */
} EXT_ADAPTERREGIONVERSION, *PEXT_ADAPTERREGIONVERSION;

/* Request Buffer for RNID */
typedef struct _EXT_RNID_REQ {
	EXT_FC_ADDR	Addr;				/* 14 */
	UINT8		DataFormat;			/* 1 */
	UINT8		Pad;				/* 1 */
	UINT8		OptWWN[EXT_DEF_WWN_NAME_SIZE];	/* 8 */
	UINT8		OptPortId[EXT_DEF_PORTID_SIZE];	/* 4 */
	UINT8		Reserved[51];			/* 51 */
} EXT_RNID_REQ, *PEXT_RNID_REQ;				/* 79 */

#define	EXT_DEF_RNID_DFORMAT_NONE	0
#define	EXT_DEF_RNID_DFORMAT_TOPO_DISC	0xDF

/* Request Buffer for Set RNID */
typedef struct _EXT_SET_RNID_REQ {
	UINT8	IPVersion[2];		/*  2 */
	UINT8	UDPPortNumber[2];	/*  2 */
	UINT8	IPAddress[16];		/* 16 */
	UINT8	Reserved[64];		/* 64 */
} EXT_SET_RNID_REQ, *PEXT_SET_RNID_REQ; /* 84 */

/* RNID definition and data struct */
#define	SEND_RNID_RSP_SIZE  72

typedef struct _RNID_DATA
{
	UINT32	UnitType;		/* 4 */
	UINT32	NumOfAttachedNodes;	/* 4 */
	UINT16	TopoDiscFlags;		/* 2 */
	UINT16	Reserved;		/* 2 */
	UINT8	WWN[16];		/* 16 */
	UINT8	PortId[4];		/* 4 */
	UINT8	IPVersion[2];		/* 2 */
	UINT8	UDPPortNumber[2];	/* 2 */
	UINT8	IPAddress[16];		/* 16 */
} EXT_RNID_DATA, *PEXT_RNID_DATA;	/* 52 */


/* SCSI pass-through */
typedef struct _EXT_SCSI_PASSTHRU {
	EXT_SCSI_ADDR	TargetAddr;
	UINT8		Direction;
	UINT8		CdbLength;
	UINT8		Cdb[EXT_DEF_SCSI_PASSTHRU_CDB_LENGTH];
	UINT8		Reserved[66];
	UINT8		SenseData[256];
} EXT_SCSI_PASSTHRU, *PEXT_SCSI_PASSTHRU;

/* FC SCSI pass-through */
typedef struct _EXT_FC_SCSI_PASSTHRU {
	EXT_DEST_ADDR	FCScsiAddr;
	UINT8		Direction;
	UINT8		CdbLength;
	UINT8		Cdb[EXT_DEF_SCSI_PASSTHRU_CDB_LENGTH];
	UINT8		Reserved[64];
	UINT8		SenseData[256];
} EXT_FC_SCSI_PASSTHRU, *PEXT_FC_SCSI_PASSTHRU;

/* SCSI pass-through direction */
#define	EXT_DEF_SCSI_PASSTHRU_DATA_IN		1
#define	EXT_DEF_SCSI_PASSTHRU_DATA_OUT		2


/* EXT_REG_AEN Request struct */
typedef struct _EXT_REG_AEN {
	UINT32	Enable;		/* 4; non-0 to enable, 0 to disable. */
	UINT8	Reserved[4];	/* 4 */
} EXT_REG_AEN, *PEXT_REG_AEN;	/* 8 */

/* EXT_GET_AEN Response struct */
typedef struct _EXT_ASYNC_EVENT {
	UINT32	AsyncEventCode;		/* 4 */
	union {
		struct {
			UINT8 RSCNInfo[EXT_DEF_PORTID_SIZE_ACTUAL]; /* 3 BE */
			UINT8 AddrFormat;			/* 1 */
			UINT8 Rsvd_1[8];			/* 8 */
		} RSCN;

		UINT8	Reserved[12];	/* 12 */
	} Payload;
} EXT_ASYNC_EVENT, *PEXT_ASYNC_EVENT;	/* 16 */


/* Asynchronous Event Codes */
#define	EXT_DEF_LIP_OCCURRED	0x8010
#define	EXT_DEF_LINK_UP		0x8011
#define	EXT_DEF_LINK_DOWN	0x8012
#define	EXT_DEF_LIP_RESET	0x8013
#define	EXT_DEF_RSCN		0x8015
#define	EXT_DEF_DEVICE_UPDATE	0x8014

/* LED state information */
#define	EXT_DEF_GRN_BLINK_OFF	0x00
#define	EXT_DEF_GRN_BLINK_ON	0x01

typedef struct _EXT_BEACON_CONTROL {
	UINT32	State;				/* 4  */
	UINT8	Reserved[12];			/* 12 */
} EXT_BEACON_CONTROL, *PEXT_BEACON_CONTROL;	/* 16 */

/* Required # of entries in the queue buffer allocated. */
#define	EXT_DEF_MAX_AEN_QUEUE	EXT_DEF_MAX_AEN_QUEUE_OS

/*
 * LUN BitMask structure definition, array of 8bit bytes,
 * 1 bit per lun.  When bit == 1, the lun is masked.
 * Most significant bit of mask[0] is lun 0.
 * Least significant bit of mask[0] is lun 7.
 */
typedef struct _EXT_LUN_BIT_MASK {
#if ((EXT_DEF_NON_SCSI3_MAX_LUN & 0x7) == 0)
	UINT8	mask[EXT_DEF_NON_SCSI3_MAX_LUN >> 3];
#else
	UINT8	mask[(EXT_DEF_NON_SCSI3_MAX_LUN + 8) >> 3 ];
#endif
} EXT_LUN_BIT_MASK, *PEXT_LUN_BIT_MASK;

/* Device type to get for EXT_SC_GET_PORT_SUMMARY */
#define	EXT_DEF_GET_KNOWN_DEVICE	0x1
#define	EXT_DEF_GET_VISIBLE_DEVICE	0x2
#define	EXT_DEF_GET_HIDDEN_DEVICE	0x4
#define	EXT_DEF_GET_FABRIC_DEVICE	0x8
#define	EXT_DEF_GET_LOOP_DEVICE		0x10

/* Each entry in device database */
typedef struct _EXT_DEVICEDATAENTRY
{
	EXT_SCSI_ADDR	TargetAddress;	/* scsi address */
	UINT32		DeviceFlags;	/* Flags for device */
	UINT16		LoopID;		/* Loop ID */
	UINT16		BaseLunNumber;
	UINT8		NodeWWN[8];	/* Node World Wide Name for device */
	UINT8		PortWWN[8];	/* Port World Wide Name for device */
	UINT8		PortID[3];	/* Current PortId for device */
	UINT8		ControlFlags;	/* Control flag */
	UINT8		Reserved[132];
} EXT_DEVICEDATAENTRY, *PEXT_DEVICEDATAENTRY;

#define	EXT_DEF_EXTERNAL_LUN_COUNT		2048
#define	EXT_DEF_EXTERNAL_LUN_BITMASK_BYTES	(EXT_DEF_EXTERNAL_LUN_COUNT / 8)

/* Structure as used in the IOCTL. */

typedef struct _EXT_EXTERNAL_LUN_BITMASK_ENTRY
{
	UINT8	NodeName[EXT_DEF_WWN_NAME_SIZE];
	UINT8	PortName[EXT_DEF_WWN_NAME_SIZE];
	UINT8	Reserved1[16];		/* Pad to 32-byte header */
	UINT8	Bitmask[EXT_DEF_EXTERNAL_LUN_BITMASK_BYTES];
} EXT_EXTERNAL_LUN_BITMASK_ENTRY, *PEXT_EXTERNAL_LUN_BITMASK_ENTRY;


/* Structure as it is stored in the NT registry */

typedef struct _LUN_BITMASK_LIST
{
	UINT16	Version;	/* Should be LUN_BITMASK_REGISTRY_VERSION */
	UINT16	EntryCount;	/* Count of variable entries following */
	UINT8	Reserved[28];	/* Pad to 32-byte header */

	EXT_EXTERNAL_LUN_BITMASK_ENTRY
		BitmaskEntry[1]; /* Var-length data */
} EXT_LUN_BITMASK_LIST, *PEXT_LUN_BITMASK_LIST;


/* Device database information */
typedef struct _EXT_DEVICEDATA
{
	UINT32	TotalDevices;		/* Set to total number of device */
	UINT32	ReturnListEntryCount;	/* Set to number of device entries */
					/* returned in list. */

	EXT_DEVICEDATAENTRY  EntryList[1]; /* Variable length */
} EXT_DEVICEDATA, *PEXT_DEVICEDATA;


/* Swap Target Device Data structure */
typedef struct _EXT_SWAPTARGETDEVICE
{
	EXT_DEVICEDATAENTRY	CurrentExistDevice;
	EXT_DEVICEDATAENTRY	NewDevice;
} EXT_SWAPTARGETDEVICE, *PEXT_SWAPTARGETDEVICE;

#define	EXT_DEF_LUN_BITMASK_LIST_MIN_ENTRIES	1
#define	EXT_DEF_LUN_BITMASK_LIST_MAX_ENTRIES	256

#ifdef _WIN64
#define	EXT_DEF_LUN_BITMASK_LIST_HEADER_SIZE	32
#else
#define	EXT_DEF_LUN_BITMASK_LIST_HEADER_SIZE \
    offsetof(LUN_BITMASK_LIST_BUFFER, asBitmaskEntry)
#endif

#define	EXT_DEF_LUN_BITMASK_LIST_MIN_SIZE   \
	(EXT_DEF_LUN_BITMASK_LIST_HEADER_SIZE + \
	(sizeof (EXT_EXTERNAL_LUN_BITMASK_ENTRY) * \
	EXT_DEF_LUN_BITMASK_LIST_MIN_ENTRIES))
#define	EXT_DEF_LUN_BITMASK_LIST_MAX_SIZE   \
	(EXT_DEF_LUN_BITMASK_LIST_HEADER_SIZE + \
	(sizeof (EXT_EXTERNAL_LUN_BITMASK_ENTRY) * \
	EXT_DEF_LUN_BITMASK_LIST_MAX_ENTRIES))
/*
 * LUN mask bit manipulation macros
 *
 *   P = Pointer to an EXT_LUN_BIT_MASK union.
 *   L = LUN number.
 */
#define	EXT_IS_LUN_BIT_SET(P, L) \
	(((P)->mask[L / 8] & (0x80 >> (L % 8))) ? 1 : 0)

#define	EXT_SET_LUN_BIT(P, L) \
	((P)->mask[L / 8] |= (0x80 >> (L % 8)))

#define	EXT_CLR_LUN_BIT(P, L) \
	((P)->mask[L / 8] &= ~(0x80 >> (L % 8)))

typedef struct _EXT_PORT_PARAM {
	EXT_DEST_ADDR	FCScsiAddr;
	UINT16		Mode;
	UINT16		Speed;
} EXT_PORT_PARAM, *PEXT_PORT_PARAM;

#define	EXT_IIDMA_MODE_GET	0
#define	EXT_IIDMA_MODE_SET	1

/*
 * PCI header structure definitions.
 */

typedef struct _PCI_HEADER_T {
	UINT8	signature[2];
	UINT8	reserved[0x16];
	UINT8	dataoffset[2];
	UINT8	pad[6];
} PCI_HEADER_T, *PPCI_HEADER_T;

/*
 * PCI data structure definitions.
 */
typedef struct _PCI_DATA_T {
	UINT8	signature[4];
	UINT8	vid[2];
	UINT8	did[2];
	UINT8	reserved0[2];
	UINT8	pcidatalen[2];
	UINT8	pcidatarev;
	UINT8	classcode[3];
	UINT8	imagelength[2];   /* In sectors */
	UINT8	revisionlevel[2];
	UINT8	codetype;
	UINT8	indicator;
	UINT8	reserved1[2];
	UINT8	pad[8];
} PCI_DATA_T, *PPCI_DATA_T;

/*
 * Mercury/Menlo
 */

#define	MENLO_RESET_FLAG_ENABLE_DIAG_FW	1

typedef struct _EXT_MENLO_RESET {
	UINT16	Flags;
	UINT16	Reserved;
} EXT_MENLO_RESET, *PEXT_MENLO_RESET;

typedef struct _EXT_MENLO_GET_FW_VERSION {
	UINT32	FwVersion;
} EXT_MENLO_GET_FW_VERSION, *PEXT_MENLO_GET_FW_VERSION;

#define	MENLO_UPDATE_FW_FLAG_DIAG_FW	0x0008  /* if flag is cleared then */
						/* it must be an fw op */
typedef struct _EXT_MENLO_UPDATE_FW {
	UINT64	pFwDataBytes;
	UINT32	TotalByteCount;
	UINT16	Flags;
	UINT16	Reserved;
} EXT_MENLO_UPDATE_FW, *PEXT_MENLO_UPDATE_FW;

#define	CONFIG_PARAM_ID_RESERVED	1
#define	CONFIG_PARAM_ID_UIF		2
#define	CONFIG_PARAM_ID_FCOE_COS	3
#define	CONFIG_PARAM_ID_PAUSE_TYPE	4
#define	CONFIG_PARAM_ID_TIMEOUTS	5

#define	INFO_DATA_TYPE_CONFIG_LOG_DATA	1	/* Fetch Config Log Data */
#define	INFO_DATA_TYPE_LOG_DATA		2	/* Fetch Log Data */
#define	INFO_DATA_TYPE_PORT_STATISTICS	3	/* Fetch Port Statistics */
#define	INFO_DATA_TYPE_LIF_STATISTICS	4	/* Fetch LIF Statistics */
#define	INFO_DATA_TYPE_ASIC_STATISTICS	5	/* Fetch ASIC Statistics */
#define	INFO_DATA_TYPE_CONFIG_PARAMETERS 6	/* Fetch Config Parameters */
#define	INFO_DATA_TYPE_PANIC_LOG	7	/* Fetch Panic Log */

/*
 * InfoContext defines for INFO_DATA_TYPE_LOG_DATA
 */
#define	IC_LOG_DATA_LOG_ID_DEBUG_LOG			0
#define	IC_LOG_DATA_LOG_ID_LEARN_LOG			1
#define	IC_LOG_DATA_LOG_ID_FC_ACL_INGRESS_LOG		2
#define	IC_LOG_DATA_LOG_ID_FC_ACL_EGRESS_LOG		3
#define	IC_LOG_DATA_LOG_ID_ETHERNET_ACL_INGRESS_LOG	4
#define	IC_LOG_DATA_LOG_ID_ETHERNET_ACL_EGRESS_LOG	5
#define	IC_LOG_DATA_LOG_ID_MESSAGE_TRANSMIT_LOG		6
#define	IC_LOG_DATA_LOG_ID_MESSAGE_RECEIVE_LOG		7
#define	IC_LOG_DATA_LOG_ID_LINK_EVENT_LOG		8
#define	IC_LOG_DATA_LOG_ID_DCX_LOG			9

/*
 * InfoContext defines for INFO_DATA_TYPE_PORT_STATISTICS
 */
#define	IC_PORT_STATISTICS_PORT_NUMBER_ETHERNET_PORT0	0
#define	IC_PORT_STATISTICS_PORT_NUMBER_ETHERNET_PORT1	1
#define	IC_PORT_STATISTICS_PORT_NUMBER_NSL_PORT0	2
#define	IC_PORT_STATISTICS_PORT_NUMBER_NSL_PORT1	3
#define	IC_PORT_STATISTICS_PORT_NUMBER_FC_PORT0		4
#define	IC_PORT_STATISTICS_PORT_NUMBER_FC_PORT1		5

/*
 * InfoContext defines for INFO_DATA_TYPE_LIF_STATISTICS
 */
#define	IC_LIF_STATISTICS_LIF_NUMBER_ETHERNET_PORT0	0
#define	IC_LIF_STATISTICS_LIF_NUMBER_ETHERNET_PORT1	1
#define	IC_LIF_STATISTICS_LIF_NUMBER_FC_PORT0		2
#define	IC_LIF_STATISTICS_LIF_NUMBER_FC_PORT1		3
#define	IC_LIF_STATISTICS_LIF_NUMBER_CPU		6

typedef struct _EXT_MENLO_ACCESS_PARAMETERS {
	union {
		struct {
			UINT32 StartingAddr;
			UINT32 Reserved2;
			UINT32 Reserved3;
		} MenloMemory;		/* For Read & Write Menlo Memory */

		struct {
			UINT32 ConfigParamID;
			UINT32 ConfigParamData0;
			UINT32 ConfigParamData1;
		} MenloConfig;		/* For change Configuration */

		struct {
			UINT32 InfoDataType;
			UINT32 InfoContext;
			UINT32 Reserved;
		} MenloInfo;		/* For fetch Menlo Info */
	} ap;
} EXT_MENLO_ACCESS_PARAMETERS, *PEXT_MENLO_ACCESS_PARAMETERS;

#define	INFO_DATA_TYPE_LOG_CONFIG_TBC		((10*7)+1)*4
#define	INFO_DATA_TYPE_PORT_STAT_ETH_TBC	0x194
#define	INFO_DATA_TYPE_PORT_STAT_FC_TBC		0xC0
#define	INFO_DATA_TYPE_LIF_STAT_TBC		0x40
#define	INFO_DATA_TYPE_ASIC_STAT_TBC		0x5F8
#define	INFO_DATA_TYPE_CONFIG_TBC		0x140

#define	MENLO_OP_READ_MEM	0	/* Read Menlo Memory */
#define	MENLO_OP_WRITE_MEM	1	/* Write Menlo Memory */
#define	MENLO_OP_CHANGE_CONFIG	2	/* Change Configuration */
#define	MENLO_OP_GET_INFO	3	/* Fetch Menlo Info (Logs, & */
					/* Statistics, Configuration) */

typedef struct _EXT_MENLO_MANAGE_INFO {
	UINT64				pDataBytes;
	EXT_MENLO_ACCESS_PARAMETERS	Parameters;
	UINT32				TotalByteCount;
	UINT16				Operation;
	UINT16				Reserved;
} EXT_MENLO_MANAGE_INFO, *PEXT_MENLO_MANAGE_INFO;

#define	MENLO_FC_CHECKSUM_FAILURE	0x01
#define	MENLO_FC_INVALID_LENGTH		0x02
#define	MENLO_FC_INVALID_ADDRESS	0x04
#define	MENLO_FC_INVALID_CONFIG_ID_TYPE	0x05
#define	MENLO_FC_INVALID_CONFIG_DATA	0x06
#define	MENLO_FC_INVALID_INFO_CONTEXT	0x07

typedef struct _EXT_MENLO_MGT {
	union {
		EXT_MENLO_RESET			MenloReset;
		EXT_MENLO_GET_FW_VERSION	MenloGetFwVer;
		EXT_MENLO_UPDATE_FW		MenloUpdateFw;
		EXT_MENLO_MANAGE_INFO		MenloManageInfo;
	} sp;
} EXT_MENLO_MGT, *PEXT_MENLO_MGT;

/*
 * vport enum definations
 */
typedef enum vport_options {
	EXT_VPO_LOGIN_RETRY_ENABLE = 0,
	EXT_VPO_PERSISTENT = 1,
	EXT_VPO_QOS_BW = 2,
	EXT_VPO_VFABRIC_ENABLE = 3
} vport_options_t;

/*
 * vport struct definations
 */
#define	MAX_DEV_PATH			256
#define	MAX_VP_ID			256
#define	EXT_OLD_VPORT_ID_CNT_SIZE	260
typedef struct _EXT_VPORT_ID_CNT {
	UINT32	VpCnt;
	UINT8	VpId[MAX_VP_ID];
	UINT8	vp_path[MAX_VP_ID][MAX_DEV_PATH];
	INT32	VpDrvInst[MAX_VP_ID];
} EXT_VPORT_ID_CNT, *PEXT_VPORT_ID_CNT;

typedef struct _EXT_VPORT_PARAMS {
	UINT32		vp_id;
	vport_options_t	options;
	UINT8		wwpn[EXT_DEF_WWN_NAME_SIZE];
	UINT8		wwnn[EXT_DEF_WWN_NAME_SIZE];
} EXT_VPORT_PARAMS, *PEXT_VPORT_PARAMS;

typedef struct _EXT_VPORT_INFO {
	UINT32		free;
	UINT32		used;
	UINT32		id;
	UINT32		state;
	UINT32		bound;
	UINT8		wwnn[EXT_DEF_WWN_NAME_SIZE];
	UINT8		wwpn[EXT_DEF_WWN_NAME_SIZE];
	UINT8		reserved[220];
} EXT_VPORT_INFO, *PEXT_VPORT_INFO;

#define	EXT_DEF_FCF_LIST_SIZE	4096	/* Bytes */
#define	FCF_INFO_RETURN_ALL	0
#define	FCF_INFO_RETURN_ONE	1

typedef	struct	_EXT_FCF_INFO {
	UINT16	CntrlFlags;	/* 2 */
	UINT16	FcfId;		/* 2 */
	UINT16	VlanId;		/* 2 */
	UINT16	FcfFlags;	/* 2 */
	UINT16	FcfAdvertPri;	/* 2 */
	UINT16	FcfMacAddr1;	/* 2 */
	UINT16	FcfMacAddr2;	/* 2 */
	UINT16	FcfMacAddr3;	/* 2 */
	UINT16	FcfMapHi;	/* 2 */
	UINT16	FcfMapLow;	/* 2 */
	UINT8	SwitchName[8];	/* 8 */
	UINT8	FabricName[8];	/* 8 */
	UINT8	Reserved1[8];	/* 8 */
	UINT16	CommFeatures;	/* 2 */
	UINT16	Reserved2;	/* 2 */
	UINT32	RATovVal;	/* 4 */
	UINT32	EDTovVal;	/* 4 */
	UINT8	Reserved3[8];	/* 8 */
} EXT_FCF_INFO, *PEXT_FCF_INFO;

typedef struct _EXT_FCF_LIST {
	UINT32		Options;
	UINT32		FcfIndex;
	UINT32		BufSize;
	EXT_FCF_INFO	pFcfInfo[1];
} EXT_FCF_LIST, *PEXT_FCF_LIST;

typedef	struct	_EXT_RESOURCE_CNTS {
	UINT32	OrgTgtXchgCtrlCnt;	/* 4 */
	UINT32	CurTgtXchgCtrlCnt;	/* 4 */
	UINT32	CurXchgCtrlCnt;		/* 4 */
	UINT32	OrgXchgCtrlCnt;		/* 4 */
	UINT32	CurIocbBufCnt;		/* 4 */
	UINT32	OrgIocbBufCnt;		/* 4 */
	UINT32	NoOfSupVPs;		/* 4 */
	UINT32	NoOfSupFCFs;		/* 4 */
} EXT_RESOURCE_CNTS, *PEXT_RESOURCE_CNTS;

#ifdef	__cplusplus
}
#endif

#endif /* _EXIOCT_H */
