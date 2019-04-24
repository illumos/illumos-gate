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

/* Copyright 2010 QLogic Corporation */

/*
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_QL_MBX_H
#define	_QL_MBX_H

/*
 * ISP2xxx Solaris Fibre Channel Adapter (FCA) driver header file.
 *
 * ***********************************************************************
 * *									**
 * *				NOTICE					**
 * *		COPYRIGHT (C) 1996-2010 QLOGIC CORPORATION		**
 * *			ALL RIGHTS RESERVED				**
 * *									**
 * ***********************************************************************
 *
 */

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * ISP mailbox Self-Test status codes
 */
#define	MBS_FRM_ALIVE	0	/* Firmware Alive. */
#define	MBS_CHKSUM_ERR	1	/* Checksum Error. */
#define	MBS_BUSY	4	/* Busy. */

/*
 * ISP mailbox command complete status codes
 */
#define	MBS_COMMAND_COMPLETE		0x4000
#define	MBS_INVALID_COMMAND		0x4001
#define	MBS_HOST_INTERFACE_ERROR	0x4002
#define	MBS_TEST_FAILED			0x4003
#define	MBS_POST_ERROR			0x4004
#define	MBS_COMMAND_ERROR		0x4005
#define	MBS_COMMAND_PARAMETER_ERROR	0x4006
#define	MBS_PORT_ID_USED		0x4007
#define	MBS_LOOP_ID_USED		0x4008
#define	MBS_ALL_IDS_IN_USE		0x4009
#define	MBS_NOT_LOGGED_IN		0x400A
#define	MBS_LOOP_DOWN			0x400B
#define	MBS_LOOP_BACK_ERROR		0x400C
#define	MBS_CHECKSUM_ERROR		0x4010

/*
 * Sub-error Codes for Mailbox Command Completion Status Code 4005h
 */
#define	MBSS_NO_LINK			0x0001
#define	MBSS_IOCB_ALLOC_ERR		0x0002
#define	MBSS_ECB_ALLOC_ERR		0x0003
#define	MBSS_CMD_FAILURE		0x0004
#define	MBSS_NO_FABRIC			0x0005
#define	MBSS_FIRMWARE_NOT_RDY		0x0007
#define	MBSS_INITIATOR_DISABLED		0x0008
#define	MBSS_NOT_LOGGED_IN		0x0009
#define	MBSS_PARTIAL_DATA_XFER		0x000A
#define	MBSS_TOPOLOGY_ERR		0x0016
#define	MBSS_CHIP_RESET_NEEDED		0x0017
#define	MBSS_MULTIPLE_OPEN_EXCH		0x0018
#define	MBSS_IOCB_COUNT_ERR		0x0019
#define	MBSS_CMD_AFTER_FW_INIT_ERR	0x001A
#define	MBSS_NO_VIRTUAL_PORT_ID		0x001B
#define	MBSS_INVALID_FCF_INDEX		0x0022
#define	MBSS_MPI_PROCESSOR_ERR		0x0023
#define	MBSS_SEMAPHORE_ERR		0x0024
#define	MBSS_RANGE_ERR			0x0025
#define	MBSS_TRANSFER_SIZE_TO_LARGE	0x0026
#define	MBSS_CHECKSUM_ERR		0x0027
#define	MBSS_CONFIGURATION_ERR		0x0028

/*
 * ISP mailbox asynchronous event status codes
 */
#define	MBA_ASYNC_EVENT		0x8000  /* Asynchronous event. */
#define	MBA_RESET		0x8001  /* Reset Detected. */
#define	MBA_SYSTEM_ERR		0x8002  /* System Error. */
#define	MBA_REQ_TRANSFER_ERR	0x8003  /* Request Transfer Error. */
#define	MBA_RSP_TRANSFER_ERR	0x8004  /* Response Transfer Error. */
#define	MBA_WAKEUP_THRES	0x8005  /* Request Queue Wake-up. */
#define	MBA_MENLO_ALERT		0x800f  /* Menlo Alert Notification. */
#define	MBA_LIP_OCCURRED	0x8010  /* Loop Initialization Procedure */
					/* occurred. */
#define	MBA_LOOP_UP		0x8011  /* FC Loop UP. */
#define	MBA_LOOP_DOWN		0x8012  /* FC Loop Down. */
#define	MBA_LIP_RESET		0x8013	/* LIP reset occurred. */
#define	MBA_PORT_UPDATE		0x8014  /* Port Database update. */
#define	MBA_RSCN_UPDATE		0x8015  /* State Change Registration. */
#define	MBA_LIP_F8		0x8016	/* Received a LIP F8. */
#define	MBA_LIP_ERROR		0x8017	/* Loop initialization errors. */
#define	MBA_SECURITY_UPDATE	0x801B	/* FC-SP security update. */
#define	MBA_SCSI_COMPLETION	0x8020  /* SCSI Command Complete. */
#define	MBA_CTIO_COMPLETION	0x8021  /* CTIO Complete. */
#define	MBA_IP_COMPLETION	0x8022  /* IP Transmit Command Complete. */
#define	MBA_IP_RECEIVE		0x8023  /* IP Received. */
#define	MBA_IP_BROADCAST	0x8024  /* IP Broadcast Received. */
#define	MBA_IP_LOW_WATER_MARK   0x8025  /* IP Low Water Mark reached. */
#define	MBA_IP_RCV_BUFFER_EMPTY 0x8026  /* IP receive buffer queue empty. */
#define	MBA_IP_HDR_DATA_SPLIT   0x8027  /* IP header/data splitting feature */
					/* used. */
#define	MBA_ERROR_LOGGING_DISABLED	0x8029  /* Error Logging Disabled. */
#define	MBA_POINT_TO_POINT	0x8030  /* Point to point mode. */
#define	MBA_DCBX_COMPLETED	0x8030  /* DCBX completed. */
#define	MBA_CMPLT_1_16BIT	0x8031	/* Completion 1 16bit IOSB. */
#define	MBA_FCF_CONFIG_ERROR	0x8031	/* FCF configuration error. */
#define	MBA_CMPLT_2_16BIT	0x8032	/* Completion 2 16bit IOSB. */
#define	MBA_DCBX_PARAM_CHANGED	0x8032	/* DCBX parameters changed. */
#define	MBA_CMPLT_3_16BIT	0x8033	/* Completion 3 16bit IOSB. */
#define	MBA_CMPLT_4_16BIT	0x8034	/* Completion 4 16bit IOSB. */
#define	MBA_CMPLT_5_16BIT	0x8035	/* Completion 5 16bit IOSB. */
#define	MBA_CHG_IN_CONNECTION   0x8036  /* Change in connection mode. */
#define	MBA_ZIO_UPDATE		0x8040  /* ZIO response queue update. */
#define	MBA_CMPLT_2_32BIT	0x8042	/* Completion 2 32bit IOSB. */
#define	MBA_PORT_BYPASS_CHANGED	0x8043	/* Crystal+ port#0 bypass transition */
#define	MBA_RECEIVE_ERROR	0x8048	/* Receive Error */
#define	MBA_LS_RJT_SENT		0x8049	/* LS_RJT response sent */
#define	MBA_FW_RESTART_COMP	0x8060	/* Firmware Restart Complete. */
#define	MBA_IDC_COMPLETE	0x8100	/* Inter-driver communication */
					/* complete. */
#define	MBA_IDC_NOTIFICATION	0x8101	/* Inter-driver communication */
					/* notification. */
#define	MBA_IDC_TIME_EXTENDED	0x8102	/* Inter-driver communication */
					/* time extended. */

/* Driver defined. */
#define	MBA_CMPLT_1_32BIT	0x9000	/* Completion 1 32bit IOSB. */
/*
 * Mailbox 23 event codes
 */
#define	MBX23_MBX_OR_ASYNC_EVENT	0x0
#define	MBX23_RESPONSE_QUEUE_UPDATE	0x1
#define	MBX23_SCSI_COMPLETION		0x2

/*
 * System Error event (0x8002) defines
 */
#define	SE_MPI_RISC	BIT_2
#define	SE_NIC_1	BIT_1
#define	SE_NIC_2	BIT_0

/*
 * Menlo alert event defines
 */
#define	MLA_PANIC_RECOVERY		0x1
#define	MLA_LOGIN_OPERATIONAL_FW	0x2
#define	MLA_LOGIN_DIAGNOSTIC_FW		0x3
#define	MLA_LOGIN_GOLDEN_FW		0x4
#define	MLA_REJECT_RESPONSE		0x5

/*
 * ISP mailbox commands
 */
#define	MBC_LOAD_RAM			1	/* Load RAM. */
#define	MBC_EXECUTE_FIRMWARE		2	/* Execute firmware. */
#define	MBC_DUMP_RAM			3	/* Dump RAM. */
#define	MBC_WRITE_RAM_WORD		4	/* Write RAM word. */
#define	MBC_READ_RAM_WORD		5	/* Read RAM word. */
#define	MBC_MAILBOX_REGISTER_TEST	6	/* Wrap incoming mailboxes */
#define	MBC_VERIFY_CHECKSUM		7	/* Verify checksum. */
#define	MBC_ABOUT_FIRMWARE		8	/* About Firmware. */
#define	MBC_DUMP_RISC_RAM		0xa	/* Dump RISC RAM command. */
#define	MBC_LOAD_RAM_EXTENDED		0xb	/* Load RAM extended. */
#define	MBC_DUMP_RAM_EXTENDED		0xc	/* Dump RAM extended. */
#define	MBC_WRITE_RAM_EXTENDED		0xd	/* Write RAM word. */
#define	MBC_READ_RAM_EXTENDED		0xf	/* Read RAM extended. */
#define	MBC_SERDES_TRANSMIT_PARAMETERS	0x10	/* Serdes Xmit Parameters */
#define	MBC_TOGGLE_INTERRUPT		0x10	/* 82XX enable/disable intr */
#define	MBC_2300_EXECUTE_IOCB		0x12	/* ISP2300 Execute IOCB cmd */
#define	MBC_GET_IO_STATUS		0x12	/* ISP2422 Get I/O Status */
#define	MBC_STOP_FIRMWARE		0x14	/* Stop firmware */
#define	MBC_ABORT_COMMAND_IOCB		0x15	/* Abort IOCB command. */
#define	MBC_ABORT_DEVICE		0x16	/* Abort device (ID/LUN). */
#define	MBC_ABORT_TARGET		0x17	/* Abort target (ID). */
#define	MBC_RESET			0x18	/* Target reset. */
#define	MBC_XMIT_PARM			0x19	/* Change default xmit parms */
#define	MBC_PORT_PARAM			0x1a	/* Get/set port speed parms */
#define	MBC_GET_ID			0x20	/* Get loop id of ISP2200. */
#define	MBC_GET_TIMEOUT_PARAMETERS	0x22	/* Get Timeout Parameters. */
#define	MBC_TRACE_CONTROL		0x27	/* Trace control. */
#define	MBC_GET_FIRMWARE_OPTIONS	0x28	/* Get firmware options */
#define	MBC_READ_SFP			0x31	/* Read SFP. */
#define	MBC_SET_FIRMWARE_OPTIONS	0x38	/* set firmware options */
#define	MBC_RESET_MENLO			0x3a	/* Reset Menlo. */
#define	MBC_RESTART_MPI			0x3d	/* Restart MPI. */
#define	MBC_FLASH_ACCESS		0x3e	/* Flash Access Control */
#define	MBC_LOOP_PORT_BYPASS		0x40	/* Loop Port Bypass. */
#define	MBC_LOOP_PORT_ENABLE		0x41	/* Loop Port Enable. */
#define	MBC_GET_RESOURCE_COUNTS		0x42	/* Get Resource Counts. */
#define	MBC_NON_PARTICIPATE		0x43	/* Non-Participating Mode. */
#define	MBC_ECHO			0x44	/* ELS ECHO */
#define	MBC_DIAGNOSTIC_LOOP_BACK	0x45	/* Diagnostic loop back. */
#define	MBC_ONLINE_SELF_TEST		0x46	/* Online self-test. */
#define	MBC_ENHANCED_GET_PORT_DATABASE	0x47	/* Get Port Database + login */
#define	MBC_INITIALIZE_MULTI_ID_FW	0x48	/* Initialize multi-id fw */
#define	MBC_GET_FCF_LIST		0x50	/* Get FCF List */
#define	MBC_GET_DCBX_PARAMS		0x51	/* Get DCBX parameters */
#define	MBC_RESET_LINK_STATUS		0x52	/* Reset Link Error Status */
#define	MBC_EXECUTE_IOCB		0x54	/* 64 Bit Execute IOCB cmd. */
#define	MBC_SEND_RNID_ELS		0x57	/* Send RNID ELS request */
#define	MBC_SET_PARAMETERS		0x59	/* Set RNID parameters */
#define	MBC_GET_PARAMETERS		0x5a	/* Get RNID parameters */
#define	MBC_DATA_RATE			0x5d	/* Data Rate */
#define	MBC_INITIALIZE_FIRMWARE		0x60	/* Initialize firmware */
#define	MBC_INITIATE_LIP		0x62	/* Initiate LIP */
#define	MBC_GET_FC_AL_POSITION_MAP	0x63	/* Get FC_AL Position Map. */
#define	MBC_GET_PORT_DATABASE		0x64	/* Get Port Database. */
#define	MBC_CLEAR_ACA			0x65	/* Clear ACA. */
#define	MBC_TARGET_RESET		0x66	/* Target Reset. */
#define	MBC_CLEAR_TASK_SET		0x67	/* Clear Task Set. */
#define	MBC_ABORT_TASK_SET		0x68	/* Abort Task Set. */
#define	MBC_GET_FIRMWARE_STATE		0x69	/* Get firmware state. */
#define	MBC_GET_PORT_NAME		0x6a	/* Get port name. */
#define	MBC_GET_LINK_STATUS		0x6b	/* Get Link Status. */
#define	MBC_LIP_RESET			0x6c	/* LIP reset. */
#define	MBC_GET_STATUS_COUNTS		0x6d	/* Get Link Statistics and */
						/* Private Data Counts */
#define	MBC_SEND_SNS_COMMAND		0x6e	/* Send Simple Name Server */
#define	MBC_LOGIN_FABRIC_PORT		0x6f	/* Login fabric port. */
#define	MBC_SEND_CHANGE_REQUEST		0x70	/* Send Change Request. */
#define	MBC_LOGOUT_FABRIC_PORT		0x71	/* Logout fabric port. */
#define	MBC_LIP_FULL_LOGIN		0x72	/* Full login LIP. */
#define	MBC_LOGIN_LOOP_PORT		0x74	/* Login Loop Port. */
#define	MBC_PORT_NODE_NAME_LIST		0x75	/* Get port/node name list */
#define	MBC_INITIALIZE_IP		0x77	/* Initialize IP */
#define	MBC_SEND_FARP_REQ_COMMAND	0x78	/* FARP request. */
#define	MBC_UNLOAD_IP			0x79	/* Unload IP */
#define	MBC_GET_XGMAC_STATS		0x7a	/* Get XGMAC Statistics. */
#define	MBC_GET_ID_LIST			0x7c	/* Get port ID list. */
#define	MBC_SEND_LFA_COMMAND		0x7d	/* Send Loop Fabric Address */
#define	MBC_LUN_RESET			0x7e	/* Send Task mgmt LUN reset */
#define	MBC_IDC_REQUEST			0x100	/* IDC request */
#define	MBC_IDC_ACK			0x101	/* IDC acknowledge */
#define	MBC_IDC_TIME_EXTEND		0x102	/* IDC extend time */
#define	MBC_PORT_RESET			0x120	/* Port Reset */
#define	MBC_SET_PORT_CONFIG		0x122	/* Set port configuration */
#define	MBC_GET_PORT_CONFIG		0x123	/* Get port configuration */

/*
 * Mbc 0x100 (IDC request)
 */
/* Timeout Value */
#define	IDC_TIMEOUT_POS		8
#define	IDC_TIMEOUT_MASK	(BIT_11 | BIT_10 | BIT_9 | BIT_8)

/* Function Destination Selector */
#define	IDC_FUNC_DST_MASK	(BIT_5 | BIT_4)
#define	IDC_FUNC_DST_MBX3	0
#define	IDC_FUNC_DST_SP		0x10

/* Function Source */
#define	IDC_FUNC_SRC_MASK	(BIT_3 | BIT_2 | BIT_1 | BIT_0)

/* Information opcode */
#define	IDC_OPC_DRV_START		0x100
#define	IDC_OPC_FLASH_ACC		0x101
#define	IDC_OPC_RESTART_MPI		0x102
#define	IDC_OPC_PORT_RESET_MBC		0x120
#define	IDC_OPC_SET_PORT_CONFIG_MBC	0x122

/* Function Destination Mask */
#define	IDC_FUNC_3		BIT_3
#define	IDC_FUNC_2		BIT_2
#define	IDC_FUNC_1		BIT_1
#define	IDC_FUNC_0		BIT_0
#define	IDC_FC_FUNC		(BIT_3 | BIT_2)
#define	IDC_NIC_FUNC		(BIT_1 | BIT_0)
#define	IDC_ALL_FUNC		(IDC_FC_FUNC | IDC_NIC_FUNC)

/* Requestor Id Function Type */
#define	IDC_RIT_MASK		(BIT_6 | BIT_5 | BIT_4)
#define	IDC_RIT_NIC		0
#define	IDC_RIT_FC		0x10

/* Requestor Id Originator */
#define	IDC_RIO_MASK		(BIT_3 | BIT_2 | BIT_1 | BIT_0)
#define	IDC_RIO_DRV		0
#define	IDC_RIO_FW		1
#define	IDC_RIO_MPI		2
#define	IDC_RIO_DRV_APP		3
#define	IDC_RIO_QL_APP		4
#define	IDC_RIO_QL_MFG		5
#define	IDC_RIO_OTH_APP		6

/* Region Code */
#define	IDC_RC_POS		8
#define	IDC_RC_MASK		0xFF00

/* Region Size in 64k blocks */
#define	IDC_RS_POS		0
#define	IDC_RS_MASK		0xFF

/* Message Source */
#define	IDC_MSG_QLGC		BIT_15

/* Message Subcode */
#define	IDC_MS_MASK		(BIT_7 | BIT_6 | BIT_5 | BIT_4)
#define	IDC_MS_NONE		0x00
#define	IDC_MS_READ		0x10
#define	IDC_MS_WRITE		0x20
#define	IDC_MS_ERASE		0x30

/* Marker */
#define	IDC_MM_MASK		(BIT_3 | BIT_2 | BIT_1 | BIT_0)
#define	IDC_MM_NONE		0x0
#define	IDC_MM_BEG		0x1
#define	IDC_MM_END		0x2
#define	IDC_MM_WIP		0x3
#define	IDC_MM_ABORT		0x4

/*
 * Mbc 0x3e (Flash Access Control)
 */
#define	FAC_FORCE_SEMA_LOCK	BIT_15
#define	FAC_APPL_ID		BIT_14
#define	FAC_WRT_PROTECT		0
#define	FAC_WRT_ENABLE		1
#define	FAC_ERASE_SECTOR	2
#define	FAC_SEMA_LOCK		3
#define	FAC_SEMA_UNLOCK		4
#define	FAC_GET_SECTOR_SIZE	5
#define	FAC_ADDR_MASK		0x3fff

/*
 * MBC_DIAGNOSTIC_LOOP_BACK
 */
#define	MBC_LOOPBACK_POINT_MASK		0x07
#define	MBC_LOOPBACK_POINT_10BIT	0x00	/* 2425xx	*/
#define	MBC_LOOPBACK_POINT_1BIT		0x01	/* 2425xx	*/
#define	MBC_LOOPBACK_POINT_INTERNAL	0x01	/* 81xx		*/
#define	MBC_LOOPBACK_POINT_EXTERNAL	0x02	/* 242581xx	*/

/*
 * MBC_ECHO
 */
#define	MBC_ECHO_ELS		BIT_15	/* echo ELS */
#define	MBC_ECHO_64BIT		BIT_6	/* 64bit DMA address used */

/*
 * 81xx
 * MBC_SET_PORT_CONFIG
 * MBC_GET_PORT_CONFIG
 */
#define	LOOPBACK_MODE_FIELD_SIZE	0x03
#define	LOOPBACK_MODE_FIELD_SHIFT	0x01
#define	LOOPBACK_MODE_FIELD_MASK	((1 << LOOPBACK_MODE_FIELD_SIZE) -1)

#define	LOOPBACK_MODE(mode)		((mode & LOOPBACK_MODE_FIELD_MASK) << \
					    LOOPBACK_MODE_FIELD_SHIFT)
#define	LOOPBACK_MODE_NONE		0x00
#define	LOOPBACK_MODE_INTERNAL		0x02

/*
 * Mbc 20h (Get ID) returns the switch capabilities in mailbox7.
 * The extra bits were added with 4.00.28 MID firmware.
 */
#define	GID_TOP_NL_PORT			0
#define	GID_TOP_FL_PORT			1
#define	GID_TOP_N_PORT			2
#define	GID_TOP_F_PORT			3
#define	GID_TOP_N_PORT_NO_TGT		4

#define	GID_FP_IN_ORDER			BIT_8
#define	GID_FP_MAC_ADDR			BIT_9
#define	GID_FP_NPIV_SUPPORT		BIT_10	/* implies FDISC support */
#define	GID_FP_VF_SUPPORT		BIT_12
#define	GID_FP_SP_SUPPORT		BIT_13

/*
 * Driver Mailbox command definitions.
 */
#define	MAILBOX_TOV		30	/* Default Timeout value. */

/* Mailbox command parameter structure definition. */
typedef struct mbx_cmd {
	uint32_t out_mb;		/* Outgoing from driver */
	uint32_t in_mb;			/* Incomming from RISC */
	uint16_t mb[MAX_MBOX_COUNT];
	clock_t  timeout;		/* Timeout in seconds. */
} mbx_cmd_t;

/* Returned Mailbox registers. */
typedef struct ql_mbx_data {
	uint16_t	mb[MAX_MBOX_COUNT];
} ql_mbx_data_t;

/* Mailbox bit definitions for out_mb and in_mb */
#define	MBX_29		BIT_29
#define	MBX_28		BIT_28
#define	MBX_27		BIT_27
#define	MBX_26		BIT_26
#define	MBX_25		BIT_25
#define	MBX_24		BIT_24
#define	MBX_23		BIT_23
#define	MBX_22		BIT_22
#define	MBX_21		BIT_21
#define	MBX_20		BIT_20
#define	MBX_19		BIT_19
#define	MBX_18		BIT_18
#define	MBX_17		BIT_17
#define	MBX_16		BIT_16
#define	MBX_15		BIT_15
#define	MBX_14		BIT_14
#define	MBX_13		BIT_13
#define	MBX_12		BIT_12
#define	MBX_11		BIT_11
#define	MBX_10		BIT_10
#define	MBX_9		BIT_9
#define	MBX_8		BIT_8
#define	MBX_7		BIT_7
#define	MBX_6		BIT_6
#define	MBX_5		BIT_5
#define	MBX_4		BIT_4
#define	MBX_3		BIT_3
#define	MBX_2		BIT_2
#define	MBX_1		BIT_1
#define	MBX_0		BIT_0

#define	MBX_0_THRU_1	MBX_0|MBX_1
#define	MBX_0_THRU_2	MBX_0_THRU_1|MBX_2
#define	MBX_0_THRU_3	MBX_0_THRU_2|MBX_3
#define	MBX_0_THRU_4	MBX_0_THRU_3|MBX_4
#define	MBX_0_THRU_5	MBX_0_THRU_4|MBX_5
#define	MBX_0_THRU_6	MBX_0_THRU_5|MBX_6
#define	MBX_0_THRU_7	MBX_0_THRU_6|MBX_7
#define	MBX_0_THRU_8	MBX_0_THRU_7|MBX_8
#define	MBX_0_THRU_9	MBX_0_THRU_8|MBX_9
#define	MBX_0_THRU_10	MBX_0_THRU_9|MBX_10

/*
 * Firmware state codes from get firmware state mailbox command
 */
#define	FSTATE_CONFIG_WAIT	0
#define	FSTATE_WAIT_AL_PA	1
#define	FSTATE_WAIT_LOGIN	2
#define	FSTATE_READY		3
#define	FSTATE_LOSS_SYNC	4
#define	FSTATE_ERROR		5
#define	FSTATE_NON_PART		7

/*
 * Firmware options 1, 2, 3.
 */
#define	FO1_AE_ON_LIPF8			BIT_0
#define	FO1_AE_ALL_LIP_RESET		BIT_1
#define	FO1_CTIO_RETRY			BIT_3
#define	FO1_DISABLE_LIP_F7_SW		BIT_4
#define	FO1_DISABLE_100MS_LOS_WAIT	BIT_5
#define	FO1_DISABLE_GPIO		BIT_6
#define	FO1_AE_AUTO_BYPASS		BIT_9
#define	FO1_ENABLE_PURE_IOCB		BIT_10
#define	FO1_AE_PLOGI_RJT		BIT_11
#define	FO1_AE_IMMEDIATE_NOTIFY_IOCB	BIT_11
#define	FO1_ENABLE_ABORT_SEQUENCE	BIT_12
#define	FO1_AE_QUEUE_FULL		BIT_13
#define	FO1_POST_NOTIFY_ACK_IOCB_2_ATIO	BIT_13
#define	FO1_POST_NOTIFY_ACK_IOCB	BIT_14

#define	FO2_FCOE_512_MAX_MEM_WR_BURST	BIT_9
#define	FO2_ENABLE_SELECTIVE_CLASS_2	BIT_5
#define	FO2_REV_LOOPBACK		BIT_1
#define	FO2_ENABLE_ATIO_TYPE_3		BIT_0

#define	FO3_NO_ABORT_IO_ON_LINK_DOWN	BIT_14
#define	FO3_HOLD_STS_FOR_ABTS_RSP	BIT_12
#define	FO3_STARTUP_OPTS_VALID		BIT_5
#define	FO3_SEND_N2N_PRLI		BIT_4
#define	FO3_AE_RND_ERROR		BIT_1
#define	FO3_ENABLE_EMERG_IOCB		BIT_0

#define	FO13_LESB_NO_RESET		BIT_0

/*
 * f/w trace opcodes - mailbox 1(bits 7-0)
 */
#define	FTO_INSERT_TIME_STAMP	1
#define	FTO_RESERVED_2		2
#define	FTO_RESERVED_3		3
#define	FTO_EXT_TRACE_ENABLE	4
#define	FTO_EXT_TRACE_DISABLE	5
#define	FTO_FCE_TRACE_ENABLE	8
#define	FTO_FCE_TRACE_DISABLE	9
#define	FTO_FCEMAXTRACEBUF	0x840	/* max frame size */

/*
 * fw version 1 attributes defines from firmware version mailbox command
 */
#define	FWATTRIB_EF		0x7
#define	FWATTRIB_TP		0x17
#define	FWATTRIB_IP		0x37
#define	FWATTRIB_TPX		0x117
#define	FWATTRIB_IPX		0x137
#define	FWATTRIB_FL		0x217
#define	FWATTRIB_FPX		0x317

/*
 * fw version 2 attributes defines
 */
#define	FWATTRIB2_CLASS2	BIT_0
#define	FWATTRIB2_IP		BIT_1
#define	FWATTRIB2_MID		BIT_2
#define	FWATTRIB2_SB2		BIT_3
#define	FWATTRIB2_T10_CRC	BIT_4
#define	FWATTRIB2_VI		BIT_5
#define	FWATTRIB2_MQUE		BIT_6
#define	FWATTRIB2_FCOE		BIT_11
#define	FWATTRIB2_EX_REL	BIT_13

/*
 * Diagnostic ELS ECHO parameter structure definition.
 */
typedef struct echo {
	uint16_t		options;
	uint32_t		transfer_count;
	ddi_dma_cookie_t	transfer_data_address;
	ddi_dma_cookie_t	receive_data_address;
} echo_t;

/*
 * LFA command structure.
 */
#define	LFA_PAYLOAD_SIZE	38
typedef struct lfa_cmd {
	uint8_t	 resp_buffer_length[2];		/* length in 16bit words. */
	uint8_t	 reserved[2];
	uint8_t	 resp_buffer_address[8];
	uint8_t	 subcommand_length[2];		/* length in 16bit words. */
	uint8_t	 reserved_1[2];
	uint8_t	 addr[4];
	uint8_t  subcommand[2];
	uint8_t	 payload[LFA_PAYLOAD_SIZE];
} lfa_cmd_t;

/* Define size of Loop Position Map. */
#define	LOOP_POSITION_MAP_SIZE  128	/* bytes */

/*
 * Port Database structure definition
 * Little endian except where noted.
 */
#define	PORT_DATABASE_SIZE	128	/* bytes */
typedef struct port_database_23 {
	uint8_t  options;
	uint8_t  control;
	uint8_t  master_state;
	uint8_t  slave_state;
	uint8_t  hard_address[3];
	uint8_t  rsvd;
	uint32_t port_id;
	uint8_t  node_name[8];		/* Big endian. */
	uint8_t  port_name[8];		/* Big endian. */
	uint16_t execution_throttle;
	uint16_t execution_count;
	uint8_t  reset_count;
	uint8_t  reserved_2;
	uint16_t resource_allocation;
	uint16_t current_allocation;
	uint16_t queue_head;
	uint16_t queue_tail;
	uint16_t transmit_execution_list_next;
	uint16_t transmit_execution_list_previous;
	uint16_t common_features;
	uint16_t total_concurrent_sequences;
	uint16_t RO_by_information_category;
	uint8_t  recipient;
	uint8_t  initiator;
	uint16_t receive_data_size;
	uint16_t concurrent_sequences;
	uint16_t open_sequences_per_exchange;
	uint16_t lun_abort_flags;
	uint16_t lun_stop_flags;
	uint16_t stop_queue_head;
	uint16_t stop_queue_tail;
	uint16_t port_retry_timer;
	uint16_t next_sequence_id;
	uint16_t frame_count;
	uint16_t PRLI_payload_length;
	uint16_t PRLI_service_parameter_word_0; /* Big endian */
						/* Bits 15-0 of word 0 */
	uint16_t PRLI_service_parameter_word_3; /* Big endian */
						/* Bits 15-0 of word 3 */
	uint16_t loop_id;
	uint16_t extended_lun_info_list_pointer;
	uint16_t extended_lun_stop_list_pointer;
} port_database_23_t;

typedef struct port_database_24 {
	uint16_t flags;
	uint8_t  current_login_state;
	uint8_t  last_stable_login_state;
	uint8_t  hard_address[3];
	uint8_t  rsvd;
	uint8_t  port_id[3];
	uint8_t  sequence_id;
	uint16_t port_retry_timer;
	uint16_t n_port_handle;
	uint16_t receive_data_size;
	uint8_t	 reserved_1[2];
	uint16_t PRLI_service_parameter_word_0; /* Big endian */
						/* Bits 15-0 of word 0 */
	uint16_t PRLI_service_parameter_word_3; /* Big endian */
						/* Bits 15-0 of word 3 */
	uint8_t  port_name[8];		/* Big endian. */
	uint8_t  node_name[8];		/* Big endian. */
	uint8_t	 reserved_2[24];
} port_database_24_t;

/*
 * Port database slave/master/current_login/ast_stable_login states
 */
#define	PD_STATE_DISCOVERY			0
#define	PD_STATE_WAIT_DISCOVERY_ACK		1
#define	PD_STATE_PORT_LOGIN			2
#define	PD_STATE_WAIT_PORT_LOGIN_ACK		3
#define	PD_STATE_PLOGI_PENDING			3
#define	PD_STATE_PROCESS_LOGIN			4
#define	PD_STATE_PLOGI_COMPLETED		4
#define	PD_STATE_WAIT_PROCESS_LOGIN_ACK		5
#define	PD_STATE_PRLI_PENDING			5
#define	PD_STATE_PORT_LOGGED_IN			6
#define	PD_STATE_PLOGI_PRLI_COMPLETED		6
#define	PD_STATE_PORT_UNAVAILABLE		7
#define	PD_STATE_PROCESS_LOGOUT			8
#define	PD_STATE_WAIT_PROCESS_LOGOUT_ACK	9
#define	PD_STATE_PORT_LOGOUT			10
#define	PD_STATE_WAIT_PORT_LOGOUT_ACK		11

#define	PD_PORT_LOGIN(tq) \
	(tq->master_state == PD_STATE_PROCESS_LOGIN || \
	tq->master_state == PD_STATE_PORT_LOGGED_IN || \
	tq->slave_state == PD_STATE_PROCESS_LOGIN || \
	tq->slave_state == PD_STATE_PORT_LOGGED_IN)

/*
 * ql_login_lport() options
 */
#define	LLF_NONE	0
#define	LLF_PLOGI	BIT_0		/* unconditional PLOGI */

/*
 * ql_login_fport() options
 */
#define	LFF_NONE	0
#define	LFF_NO_PLOGI	BIT_0
#define	LFF_NO_PRLI	BIT_1

/*
 * ql_get_port_database() options
 */
#define	PDF_NONE	0
#define	PDF_PLOGI	BIT_0
#define	PDF_ADISC	BIT_1

/*
 * ql_get_adapter_id() returned connection types
 */
#define	CNX_LOOP_NO_FABRIC		0
#define	CNX_FLPORT_IN_LOOP		1
#define	CNX_NPORT_2_NPORT_P2P		2
#define	CNX_FLPORT_P2P			3
#define	CNX_NPORT_2_NPORT_NO_TGT_RSP	4

/*
 * Set/Get Port Configuration MBC
 */
#define	LINK_CONFIG_PAUSE_MASK		(BIT_6 | BIT_5)
#define	LINK_CONFIG_PAUSE_DISABLE	0x00
#define	LINK_CONFIG_PAUSE_STD_ETH	0x01
#define	LINK_CONFIG_PAUSE_PER_PRIO	0x02

#define	LINK_CONFIG_DCBX_ENA		BIT_4

#define	LINK_CONFIG_LB_MODE_MASK	(BIT_3 | BIT_2 | BIT_1)
#define	LINK_CONFIG_LB_NONE		0x00
#define	LINK_CONFIG_LB_INTERNAL		0x02

#define	LINK_CONFIG2_BP_TRAIN_ENA	BIT_15
#define	LINK_CONFIG2_BP_AUTO_NEGO_ENA	BIT_14
#define	LINK_CONFIG2_JUMBO_FRM_ENA	BIT_0

/*
 *
 */
#define	FCF_LIST_RETURN_ALL	BIT_0
#define	FCF_LIST_RETURN_ONE	BIT_1

typedef struct fcf_desc {
	uint16_t	options;
	uint16_t	fcf_index;
	uint32_t	buffer_size;
} ql_fcf_list_desc_t;

/*
 * Global Data in ql_mbx.c source file.
 */

/*
 * Global Function Prototypes in ql_mbx.c source file.
 */
int ql_initialize_ip(ql_adapter_state_t *);
int ql_shutdown_ip(ql_adapter_state_t *);
int ql_online_selftest(ql_adapter_state_t *);
int ql_loop_back(ql_adapter_state_t *, uint16_t, lbp_t *, uint32_t, uint32_t);
int ql_echo(ql_adapter_state_t *, uint16_t, echo_t *);
int ql_send_change_request(ql_adapter_state_t *, uint16_t);
int ql_send_lfa(ql_adapter_state_t *, lfa_cmd_t *);
int ql_clear_aca(ql_adapter_state_t *, ql_tgt_t *, uint16_t);
int ql_target_reset(ql_adapter_state_t *, ql_tgt_t *, uint16_t);
int ql_abort_target(ql_adapter_state_t *, ql_tgt_t *, uint16_t);
int ql_lun_reset(ql_adapter_state_t *, ql_tgt_t *, uint16_t);
int ql_clear_task_set(ql_adapter_state_t *, ql_tgt_t *, uint16_t);
int ql_abort_task_set(ql_adapter_state_t *, ql_tgt_t *, uint16_t);
int ql_loop_port_bypass(ql_adapter_state_t *, ql_tgt_t *);
int ql_loop_port_enable(ql_adapter_state_t *, ql_tgt_t *);
int ql_login_lport(ql_adapter_state_t *, ql_tgt_t *, uint16_t, uint16_t);
int ql_login_fport(ql_adapter_state_t *, ql_tgt_t *, uint16_t, uint16_t,
    ql_mbx_data_t *);
int ql_logout_fabric_port(ql_adapter_state_t *, ql_tgt_t *);
int ql_log_iocb(ql_adapter_state_t *, ql_tgt_t *, uint16_t, uint16_t,
    ql_mbx_data_t *);
int ql_get_port_database(ql_adapter_state_t *, ql_tgt_t *, uint8_t);
int ql_get_loop_position_map(ql_adapter_state_t *, size_t, caddr_t);
int ql_set_rnid_params(ql_adapter_state_t *, size_t, caddr_t);
int ql_send_rnid_els(ql_adapter_state_t *, uint16_t, uint8_t, size_t, caddr_t);
int ql_get_rnid_params(ql_adapter_state_t *, size_t, caddr_t);
int ql_get_link_status(ql_adapter_state_t *, uint16_t, size_t, caddr_t,
    uint8_t);
int ql_get_status_counts(ql_adapter_state_t *, uint16_t, size_t, caddr_t,
    uint8_t);
int ql_reset_link_status(ql_adapter_state_t *);
int ql_loop_reset(ql_adapter_state_t *);
int ql_initiate_lip(ql_adapter_state_t *);
int ql_full_login_lip(ql_adapter_state_t *);
int ql_lip_reset(ql_adapter_state_t *, uint16_t);
int ql_abort_command(ql_adapter_state_t *, ql_srb_t *);
int ql_verify_checksum(ql_adapter_state_t *);
int ql_get_id_list(ql_adapter_state_t *, caddr_t, uint32_t, ql_mbx_data_t *);
int ql_wrt_risc_ram(ql_adapter_state_t *, uint32_t, uint64_t, uint32_t);
int ql_rd_risc_ram(ql_adapter_state_t *, uint32_t, uint64_t, uint32_t);
int ql_wrt_risc_ram_word(ql_adapter_state_t *, uint32_t, uint32_t);
int ql_rd_risc_ram_word(ql_adapter_state_t *, uint32_t, uint32_t *);
int ql_issue_mbx_iocb(ql_adapter_state_t *, caddr_t, uint32_t);
int ql_mbx_wrap_test(ql_adapter_state_t *, ql_mbx_data_t *);
int ql_execute_fw(ql_adapter_state_t *);
int ql_get_firmware_option(ql_adapter_state_t *, ql_mbx_data_t *);
int ql_set_firmware_option(ql_adapter_state_t *, ql_mbx_data_t *);
int ql_init_firmware(ql_adapter_state_t *);
int ql_get_firmware_state(ql_adapter_state_t *, ql_mbx_data_t *);
int ql_get_adapter_id(ql_adapter_state_t *, ql_mbx_data_t *);
int ql_get_fw_version(ql_adapter_state_t *, ql_mbx_data_t *, uint16_t);
int ql_data_rate(ql_adapter_state_t *, ql_mbx_data_t *);
int ql_diag_loopback(ql_adapter_state_t *, uint16_t, caddr_t, uint32_t,
    uint16_t, uint32_t, ql_mbx_data_t *);
int ql_diag_echo(ql_adapter_state_t *, uint16_t, caddr_t, uint32_t, uint16_t,
    ql_mbx_data_t *);
int ql_serdes_param(ql_adapter_state_t *, ql_mbx_data_t *);
int ql_get_timeout_parameters(ql_adapter_state_t *, uint16_t *);
int ql_stop_firmware(ql_adapter_state_t *);
int ql_read_sfp(ql_adapter_state_t *, dma_mem_t *, uint16_t, uint16_t);
int ql_iidma_rate(ql_adapter_state_t *, uint16_t, uint32_t *, uint32_t);
int ql_fw_etrace(ql_adapter_state_t *, dma_mem_t *, uint16_t);
int ql_reset_menlo(ql_adapter_state_t *, ql_mbx_data_t *, uint16_t);
int ql_restart_mpi(ql_adapter_state_t *);
int ql_idc_request(ql_adapter_state_t *, ql_mbx_data_t *);
int ql_idc_ack(ql_adapter_state_t *);
int ql_idc_time_extend(ql_adapter_state_t *, ql_mbx_data_t *);
int ql_port_reset(ql_adapter_state_t *);
int ql_set_port_config(ql_adapter_state_t *, ql_mbx_data_t *);
int ql_get_port_config(ql_adapter_state_t *, ql_mbx_data_t *);
int ql_flash_access(ql_adapter_state_t *, uint16_t, uint32_t, uint32_t,
    uint32_t *);
int ql_get_xgmac_stats(ql_adapter_state_t *, size_t, caddr_t);
int ql_get_dcbx_params(ql_adapter_state_t *, uint32_t, caddr_t);
int ql_get_fcf_list_mbx(ql_adapter_state_t *, ql_fcf_list_desc_t *, caddr_t);
int ql_get_resource_cnts(ql_adapter_state_t *, ql_mbx_data_t *);
int ql_toggle_interrupt(ql_adapter_state_t *, uint16_t);
/*
 * Mailbox command table initializer
 */
#define	MBOX_CMD_TABLE()						\
{									\
	{MBC_LOAD_RAM, "MBC_LOAD_RAM"},					\
	{MBC_EXECUTE_FIRMWARE, "MBC_EXECUTE_FIRMWARE"},			\
	{MBC_DUMP_RAM, "MBC_DUMP_RAM"},					\
	{MBC_WRITE_RAM_WORD, "MBC_WRITE_RAM_WORD"},			\
	{MBC_READ_RAM_WORD, "MBC_READ_RAM_WORD"},			\
	{MBC_MAILBOX_REGISTER_TEST, "MBC_MAILBOX_REGISTER_TEST"},	\
	{MBC_VERIFY_CHECKSUM, "MBC_VERIFY_CHECKSUM"},			\
	{MBC_ABOUT_FIRMWARE, "MBC_ABOUT_FIRMWARE"},			\
	{MBC_DUMP_RISC_RAM, "MBC_DUMP_RISC_RAM"},			\
	{MBC_LOAD_RAM_EXTENDED, "MBC_LOAD_RAM_EXTENDED"},		\
	{MBC_DUMP_RAM_EXTENDED, "MBC_DUMP_RAM_EXTENDED"},		\
	{MBC_WRITE_RAM_EXTENDED, "MBC_WRITE_RAM_EXTENDED"},		\
	{MBC_READ_RAM_EXTENDED, "MBC_READ_RAM_EXTENDED"},		\
	{MBC_SERDES_TRANSMIT_PARAMETERS, \
	"MBC_SERDES_TRANSMIT_PARAMETERS or MBC_TOGGLE_INTERRUPT"},\
	{MBC_2300_EXECUTE_IOCB, "MBC_2300_EXECUTE_IOCB"},		\
	{MBC_GET_IO_STATUS, "MBC_GET_IO_STATUS"},			\
	{MBC_STOP_FIRMWARE, "MBC_STOP_FIRMWARE"},			\
	{MBC_ABORT_COMMAND_IOCB, "MBC_ABORT_COMMAND_IOCB"},		\
	{MBC_ABORT_DEVICE, "MBC_ABORT_DEVICE"},				\
	{MBC_ABORT_TARGET, "MBC_ABORT_TARGET"},				\
	{MBC_RESET, "MBC_RESET"},					\
	{MBC_XMIT_PARM, "MBC_XMIT_PARM"},				\
	{MBC_PORT_PARAM, "MBC_PORT_PARAM"},				\
	{MBC_GET_ID, "MBC_GET_ID"},					\
	{MBC_GET_TIMEOUT_PARAMETERS, "MBC_GET_TIMEOUT_PARAMETERS"},	\
	{MBC_TRACE_CONTROL, "MBC_TRACE_CONTROL"},			\
	{MBC_GET_FIRMWARE_OPTIONS, "MBC_GET_FIRMWARE_OPTIONS"},		\
	{MBC_READ_SFP, "MBC_READ_SFP"},					\
	{MBC_SET_FIRMWARE_OPTIONS, "MBC_SET_FIRMWARE_OPTIONS"},		\
	{MBC_RESET_MENLO, "MBC_RESET_MENLO"},				\
	{MBC_RESTART_MPI, "MBC_RESTART_MPI"},				\
	{MBC_FLASH_ACCESS, "MBC_FLASH_ACCESS"},				\
	{MBC_LOOP_PORT_BYPASS, "MBC_LOOP_PORT_BYPASS"},			\
	{MBC_LOOP_PORT_ENABLE, "MBC_LOOP_PORT_ENABLE"},			\
	{MBC_GET_RESOURCE_COUNTS, "MBC_GET_RESOURCE_COUNTS"},		\
	{MBC_NON_PARTICIPATE, "MBC_NON_PARTICIPATE"},			\
	{MBC_ECHO, "MBC_ECHO"},						\
	{MBC_DIAGNOSTIC_LOOP_BACK, "MBC_DIAGNOSTIC_LOOP_BACK"},		\
	{MBC_ONLINE_SELF_TEST, "MBC_ONLINE_SELF_TEST"},			\
	{MBC_ENHANCED_GET_PORT_DATABASE, "MBC_ENHANCED_GET_PORT_DATABASE"},\
	{MBC_INITIALIZE_MULTI_ID_FW, "MBC_INITIALIZE_MULTI_ID_FW"},	\
	{MBC_GET_FCF_LIST, "MBC_GET_FCF_LIST"},				\
	{MBC_GET_DCBX_PARAMS, "MBC_GET_DCBX_PARAMS"},			\
	{MBC_RESET_LINK_STATUS, "MBC_RESET_LINK_STATUS"},		\
	{MBC_EXECUTE_IOCB, "MBC_EXECUTE_IOCB"},				\
	{MBC_SEND_RNID_ELS, "MBC_SEND_RNID_ELS"},			\
	{MBC_SET_PARAMETERS, "MBC_SET_PARAMETERS"},			\
	{MBC_GET_PARAMETERS, "MBC_GET_PARAMETERS"},			\
	{MBC_DATA_RATE, "MBC_DATA_RATE"},				\
	{MBC_INITIALIZE_FIRMWARE, "MBC_INITIALIZE_FIRMWARE"},		\
	{MBC_INITIATE_LIP, "MBC_INITIATE_LIP"},				\
	{MBC_GET_FC_AL_POSITION_MAP, "MBC_GET_FC_AL_POSITION_MAP"},	\
	{MBC_GET_PORT_DATABASE, "MBC_GET_PORT_DATABASE"},		\
	{MBC_CLEAR_ACA, "MBC_CLEAR_ACA"},				\
	{MBC_TARGET_RESET, "MBC_TARGET_RESET"},				\
	{MBC_CLEAR_TASK_SET, "MBC_CLEAR_TASK_SET"},			\
	{MBC_ABORT_TASK_SET, "MBC_ABORT_TASK_SET"},			\
	{MBC_GET_FIRMWARE_STATE, "MBC_GET_FIRMWARE_STATE"},		\
	{MBC_GET_PORT_NAME, "MBC_GET_PORT_NAME"},			\
	{MBC_GET_LINK_STATUS, "MBC_GET_LINK_STATUS"},			\
	{MBC_LIP_RESET, "MBC_LIP_RESET"},				\
	{MBC_GET_STATUS_COUNTS, "MBC_GET_STATUS_COUNTS"},		\
	{MBC_SEND_SNS_COMMAND, "MBC_SEND_SNS_COMMAND"},			\
	{MBC_LOGIN_FABRIC_PORT, "MBC_LOGIN_FABRIC_PORT"},		\
	{MBC_SEND_CHANGE_REQUEST, "MBC_SEND_CHANGE_REQUEST"},		\
	{MBC_LOGOUT_FABRIC_PORT, "MBC_LOGOUT_FABRIC_PORT"},		\
	{MBC_LIP_FULL_LOGIN, "MBC_LIP_FULL_LOGIN"},			\
	{MBC_LOGIN_LOOP_PORT, "MBC_LOGIN_LOOP_PORT"},			\
	{MBC_PORT_NODE_NAME_LIST, "MBC_PORT_NODE_NAME_LIST"},		\
	{MBC_INITIALIZE_IP, "MBC_INITIALIZE_IP"},			\
	{MBC_SEND_FARP_REQ_COMMAND, "MBC_SEND_FARP_REQ_COMMAND"},	\
	{MBC_UNLOAD_IP, "MBC_UNLOAD_IP"},				\
	{MBC_GET_XGMAC_STATS, "MBC_GET_XGMAC_STATS"},			\
	{MBC_GET_ID_LIST, "MBC_GET_ID_LIST"},				\
	{MBC_SEND_LFA_COMMAND, "MBC_SEND_LFA_COMMAND"},			\
	{MBC_LUN_RESET, "MBC_LUN_RESET"},				\
	{MBC_IDC_REQUEST, "MBC_IDC_REQUEST"},				\
	{MBC_IDC_ACK, "MBC_IDC_ACK"},					\
	{MBC_IDC_TIME_EXTEND, "MBC_IDC_TIME_EXTEND"},			\
	{MBC_PORT_RESET, "MBC_PORT_RESET"},				\
	{MBC_SET_PORT_CONFIG, "MBC_SET_PORT_CONFIG"},			\
	{MBC_GET_PORT_CONFIG, "MBC_GET_PORT_CONFIG"},			\
	{0, "Unsupported"}						\
}

#ifdef	__cplusplus
}
#endif

#endif /* _QL_MBX_H */
