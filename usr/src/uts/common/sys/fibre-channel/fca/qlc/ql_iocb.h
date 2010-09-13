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

#ifndef	_QL_IOCB_H
#define	_QL_IOCB_H

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

#define	INVALID_ENTRY_TYPE	0

/*
 * ISP queue -	32-Bit DMA addressing command with extended LUN support
 *		entry structure definition.
 */
#define	IOCB_CMD_TYPE_2		0x11	/* Command entry */
#define	MAX_CMDSZ		16	/* SCSI maximum CDB size. */
#define	CMD_TYPE_2_DATA_SEGMENTS	3	/* Number of data segments. */
typedef struct cmd_entry {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  sys_define;		/* System defined. */
	uint8_t  entry_status;		/* Entry Status. */
	uint32_t handle;		/* System handle */
	uint8_t  target_l;		/* SCSI ID - LSB */
	uint8_t  target_h;		/* SCSI ID - MSB */
	uint8_t  lun_l;			/* SCSI LUN - LSB */
	uint8_t  lun_h;			/* SCSI LUN - MSB */
	uint8_t  control_flags_l;	/* Control flags - LSB. */
	uint8_t  control_flags_h;	/* Control flags - MSB. */
	uint8_t  reserved_1[2];
	uint16_t timeout;		/* Command timeout. */
	uint16_t dseg_count;		/* Data segment count - LSB. */
	uint8_t  scsi_cdb[MAX_CMDSZ];	/* SCSI command words. */
	uint32_t byte_count;		/* Total byte count. */
	uint32_t dseg_0_address;	/* Data segment 0 address. */
	uint32_t dseg_0_length;		/* Data segment 0 length. */
	uint32_t dseg_1_address;	/* Data segment 1 address. */
	uint32_t dseg_1_length;		/* Data segment 1 length. */
	uint32_t dseg_2_address;	/* Data segment 2 address. */
	uint32_t dseg_2_length;		/* Data segment 2 length. */
} cmd_entry_t, request_t;

/*
 * Command entry control flags least significant byte.
 */
#define	CF_HTAG		BIT_1
#define	CF_OTAG		BIT_2
#define	CF_STAG		BIT_3
#define	CF_DATA_IN	BIT_5
#define	CF_DATA_OUT	BIT_6

/*
 * ISP24xx queue - Command IOCB structure definition.
 */
#define	IOCB_CMD_TYPE_7		0x18
#define	CMD_TYPE_7_DATA_SEGMENTS   1	/* Number of 64 bit data segments. */
typedef struct cmd7_24xx_entry {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  sys_define;		/* System defined. */
	uint8_t  entry_status;		/* Entry Status. */
	uint32_t handle;		/* System handle */
	uint16_t n_port_hdl;
	uint16_t timeout;		/* Command timeout. */
	uint16_t dseg_count;
	uint8_t  reserved_1[2];
	uint8_t  fcp_lun[8];		/* SCSI LUN ID. */
	uint8_t  control_flags;
	uint8_t  task_mgmt;		/* Task management flags. */
	uint8_t  task;			/* Task Attributes Values. */
	uint8_t  crn;			/* Command reference number. */
	uint8_t  scsi_cdb[MAX_CMDSZ];	/* SCSI command bytes. */
	uint32_t total_byte_count;
	uint8_t  target_id[3];		/* SCSI Target ID */
	uint8_t  vp_index;
	uint32_t dseg_0_address[2];	/* Data segment 0 address. */
	uint32_t dseg_0_length;		/* Data segment 0 length. */
} cmd7_24xx_entry_t;

/*
 * ISP24xx queue - Command IOCB structure definition.
 */
#define	IOCB_CMD_TYPE_6		0x48
#define	CMD_TYPE_6_DATA_SEGMENTS   1	/* Number of 64 bit data segments. */
typedef struct cmd6_24xx_entry {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  sys_define;		/* System defined. */
	uint8_t  entry_status;		/* Entry Status. */
	uint32_t handle;		/* System handle */
	uint16_t n_port_hdl;
	uint16_t timeout;		/* Command timeout. */
	uint16_t dseg_count;
	uint16_t rsp_length;
	uint8_t  fcp_lun[8];		/* SCSI LUN ID. */
	uint16_t control_flags;
	uint16_t cmnd_length;
	uint32_t cmnd_address[2];
	uint32_t rsp_address[2];	/* Data segment 0 address. */
	uint32_t total_byte_count;
	uint8_t  target_id[3];		/* SCSI Target ID */
	uint8_t  vp_index;
	uint32_t dseg_0_address[2];	/* Data segment 0 address. */
	uint32_t dseg_0_length;		/* Data segment 0 length. */
} cmd6_24xx_entry_t;

typedef struct fcp_cmnd {
	uint8_t		fcp_lun[8];		/* SCSI LUN ID. */
	uint8_t		crn;			/* Command reference number. */
	uint8_t		task;			/* Task Attributes Values. */
	uint8_t		task_mgmt;		/* Task management flags. */
	uint8_t		control_flags;		/* Plus additional cdb length */
	uint8_t		scsi_cdb[MAX_CMDSZ];
	uint32_t	dl;
} fcp_cmnd_t;

typedef struct cmd6_2400_dma {
	fcp_cmnd_t	cmd;
	uint32_t	cookie_list[QL_DMA_SG_LIST_LENGTH + 1][3];
} cmd6_2400_dma_t;

/*
 * Task Management Flags.
 */
#define	TF_TARGET_RESET		BIT_13
#define	TF_LUN_RESET		BIT_12
#define	TF_CLEAR_TASK_SET	BIT_10
#define	TF_ABORT_TASK_SET	BIT_9

/*
 * Task Attributes Values.
 */
#define	TA_STAG		0
#define	TA_HTAG		1
#define	TA_OTAG		2
#define	TA_ACA		4
#define	TA_UNTAGGED	5

/*
 * Control Flags.
 */
#define	CF_DSD_PTR	BIT_2
#define	CF_RD		BIT_1
#define	CF_WR		BIT_0

/*
 * ISP queue -	64-Bit DMA addressing command with extended LUN support
 *		entry structure definition.
 */
#define	IOCB_CMD_TYPE_3		0x19	/* Command Type 3 entry (64 bit) */
#define	CMD_TYPE_3_DATA_SEGMENTS   2	/* Number of 64 bit data segments. */
typedef struct cmd_3_entry {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  sys_define;		/* System defined. */
	uint8_t  entry_status;		/* Entry Status. */
	uint32_t handle;		/* System handle */
	uint8_t  target_l;		/* SCSI ID - LSB */
	uint8_t  target_h;		/* SCSI ID - MSB */
	uint8_t  lun_l;			/* SCSI LUN - LSB */
	uint8_t  lun_h;			/* SCSI LUN - MSB */
	uint8_t  control_flags_l;	/* Control flags - LSB. */
	uint8_t  control_flags_h;	/* Control flags - MSB. */
	uint8_t  reserved_1[2];
	uint16_t timeout;		/* Command timeout. */
	uint16_t dseg_count;		/* Data segment count - LSB. */
	uint8_t  scsi_cdb[MAX_CMDSZ];	/* SCSI command words. */
	uint32_t byte_count;		/* Total byte count. */
	uint32_t dseg_0_address[2];	/* Data segment 0 address. */
	uint32_t dseg_0_length;		/* Data segment 0 length. */
	uint32_t dseg_1_address[2];	/* Data segment 1 address. */
	uint32_t dseg_1_length;		/* Data segment 1 length. */
} cmd_3_entry_t;

/*
 * ISP queue -	Command type 4 DSD list pointer structure definition.
 */
#define	COMMAND_CHAINING_TYPE	0x15
typedef struct cmd_chaining_entry {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  sys_define;		/* System defined. */
	uint8_t  entry_status;		/* Entry Status. */
	uint32_t handle;		/* System handle */
	uint8_t  reserved;
	uint8_t  target;		/* SCSI ID */
	uint8_t  lun_l;			/* SCSI LUN - LSB */
	uint8_t  lun_h;			/* SCSI LUN - MSB */
	uint8_t  control_flags_l;	/* Control flags - LSB. */
	uint8_t  control_flags_h;	/* Control flags - MSB. */
	uint8_t  crn;
	uint8_t  vp_index;
	uint8_t  timeout_l;		/* Command timeout - LSB. */
	uint8_t  timeout_h;		/* Command timeout - MSB. */
	uint8_t  dseg_count_l;		/* Data segment count - LSB. */
	uint8_t  dseg_count_h;		/* Data segment count - MSB. */
	uint8_t  scsi_cdb[MAX_CMDSZ];	/* SCSI command words. */
	uint32_t byte_count;		/* Total byte count. */
	uint16_t list_type;		/* 0 = 32bit, 1 = 64bit. */
	uint16_t base_address[2];
	uint16_t list_address[4];
	uint8_t reserved_2[10];
} cmd_chaining_entry_t;

/*
 * ISP queue - continuation entry structure definition.
 */
#define	CONTINUATION_TYPE_0	0x02	/* Continuation entry. */
#define	CONT_TYPE_0_DATA_SEGMENTS  7	/* Number of 32 bit data segments. */
typedef struct cont_entry {
	uint8_t entry_type;		/* Entry type. */
	uint8_t entry_count;		/* Entry count. */
	uint8_t sys_define;		/* System defined. */
	uint8_t entry_status;		/* Entry Status. */
	uint32_t reserved;
	uint32_t dseg_0_address;	/* Data segment 0 address. */
	uint32_t dseg_0_length;		/* Data segment 0 length. */
	uint32_t dseg_1_address;	/* Data segment 1 address. */
	uint32_t dseg_1_length;		/* Data segment 1 length. */
	uint32_t dseg_2_address;	/* Data segment 2 address. */
	uint32_t dseg_2_length;		/* Data segment 2 length. */
	uint32_t dseg_3_address;	/* Data segment 3 address. */
	uint32_t dseg_3_length;		/* Data segment 3 length. */
	uint32_t dseg_4_address;	/* Data segment 4 address. */
	uint32_t dseg_4_length;		/* Data segment 4 length. */
	uint32_t dseg_5_address;	/* Data segment 5 address. */
	uint32_t dseg_5_length;		/* Data segment 5 length. */
	uint32_t dseg_6_address;	/* Data segment 6 address. */
	uint32_t dseg_6_length;		/* Data segment 6 length. */
} cont_entry_t;

/*
 * ISP queue - 64-Bit addressing, continuation entry structure definition.
 */
#define	CONTINUATION_TYPE_1	0x0A	/* Continuation Type 1 entry. */
#define	CONT_TYPE_1_DATA_SEGMENTS  5	/* Number of 64 bit data segments. */
typedef struct cont_type_1_entry {
	uint8_t entry_type;		/* Entry type. */
	uint8_t entry_count;		/* Entry count. */
	uint8_t sys_define;		/* System defined. */
	uint8_t entry_status;		/* Entry Status. */
	uint32_t dseg_0_address[2];	/* Data segment 0 address. */
	uint32_t dseg_0_length;		/* Data segment 0 length. */
	uint32_t dseg_1_address[2];	/* Data segment 1 address. */
	uint32_t dseg_1_length;		/* Data segment 1 length. */
	uint32_t dseg_2_address[2];	/* Data segment 2 address. */
	uint32_t dseg_2_length;		/* Data segment 2 length. */
	uint32_t dseg_3_address[2];	/* Data segment 3 address. */
	uint32_t dseg_3_length;		/* Data segment 3 length. */
	uint32_t dseg_4_address[2];	/* Data segment 4 address. */
	uint32_t dseg_4_length;		/* Data segment 4 length. */
} cont_type_1_entry_t;

/*
 * ISP queue - status entry structure definition.
 */
#define	STATUS_TYPE	0x03		/* Status entry. */
typedef struct sts_entry {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  sys_define;		/* System defined. */
	uint8_t  entry_status;		/* Entry Status. */
	uint32_t handle;		/* System handle. */
	uint8_t  scsi_status_l;		/* SCSI status - LSB. */
	uint8_t  scsi_status_h;		/* SCSI status - MSB. */
	uint16_t comp_status;		/* Completion status. */
	uint8_t  state_flags_l;		/* State flags - LSB. */
	uint8_t  state_flags_h;		/* State flags. */
	uint8_t  status_flags_l;	/* Status flags. */
	uint8_t  status_flags_h;	/* Status flags - MSB. */
	uint16_t rsp_info_length;	/* Response Info Length. */
	uint16_t req_sense_length;	/* Request sense data length. */
	uint32_t residual_length;	/* Residual transfer length. */
	uint8_t  rsp_info[8];		/* FCP response information. */
	uint8_t  req_sense_data[32];	/* Request sense data. */
} sts_entry_t, response_t;

/*
 * Status entry entry status
 */
#define	RF_INV_E_ORDER	BIT_5		/* Invalid entry order. */
#define	RF_INV_E_COUNT  BIT_4		/* Invalid entry count. */
#define	RF_INV_E_PARAM  BIT_3		/* Invalid entry parameter. */
#define	RF_INV_E_TYPE   BIT_2		/* Invalid entry type. */
#define	RF_BUSY		BIT_1		/* Busy */

/*
 * Status entry SCSI status most significant byte.
 */
#define	FCP_CONF_REQ		BIT_4
#define	FCP_RESID_UNDER		BIT_3
#define	FCP_RESID_OVER		BIT_2
#define	FCP_SNS_LEN_VALID	BIT_1
#define	FCP_RSP_LEN_VALID	BIT_0
#define	FCP_RSP_MASK		(FCP_RESID_UNDER | FCP_RESID_OVER | \
				FCP_RSP_LEN_VALID)

/*
 * Status entry state flag most significant byte.
 * Not used in by ISP24xx
 */
#define	SF_ARQ_DONE		BIT_5
#define	SF_GOT_STATUS		BIT_4
#define	SF_XFERRED_DATA		BIT_3
#define	SF_SENT_CMD		BIT_2
#define	SF_GOT_TARGET		BIT_1
#define	SF_GOT_BUS		BIT_0

/*
 * Status entry state flag least significant byte.
 * Not used in by ISP24xx
 */
#define	SF_NO_FAST_POST		BIT_7
#define	SF_DATA_OUT		BIT_6
#define	SF_DATA_IN		BIT_5

#define	SF_SIMPLE_Q		BIT_3
#define	SF_ORDERED_Q		BIT_2
#define	SF_HEAD_OF_Q		BIT_1
#define	SF_ACA_Q		BIT_0

/*
 * Status entry completion status definitions.
 */
#define	CS_COMPLETE		0x0	/* No errors */
#define	CS_INCOMPLETE		0x1	/* Incomplete transfer of cmd. */
#define	CS_DMA_ERROR		0x2	/* A DMA direction error. */
#define	CS_PORT_ID_CHANGE	0x2	/* The port ID has changed. */
#define	CS_TRANSPORT		0x3	/* Transport error. */
#define	CS_RESET		0x4	/* SCSI bus reset occurred */
#define	CS_ABORTED		0x5	/* System aborted command. */
#define	CS_TIMEOUT		0x6	/* Timeout error. */
#define	CS_DATA_OVERRUN		0x7	/* Data overrun. */
#define	CS_INVALID_RX_ID	0x8	/* Invalid RX_ID. */
#define	CS_DATA_REASSEM_ERROR	0x11	/* Data reassembly error. */
#define	CS_ABTS_REC		0x13	/* ABTS from target. */
#define	CS_DATA_UNDERRUN	0x15	/* Data Underrun. */
#define	CS_QUEUE_FULL		0x1C	/* Queue Full. */
#define	CS_PORT_UNAVAILABLE	0x28	/* Port unavailable */
					/* (selection timeout) */
#define	CS_PORT_LOGGED_OUT	0x29	/* Port Logged Out */
#define	CS_PORT_CONFIG_CHG	0x2A	/* Port Configuration Changed */
#define	CS_PORT_BUSY		0x2B	/* Port Busy */
#define	CS_RESOUCE_UNAVAILABLE	0x2C	/* Frimware resource unavailable. */
#define	CS_TASK_MGMT_OVERRUN	0x30	/* Task management overrun. */
#define	CS_LOGIN_LOGOUT_ERROR	0x31	/* login/logout IOCB error. */
#define	CS_SEQ_COMPLETE		0x40	/* Sequence Complete. */
#define	CS_ABORTED_SEQ_REC	0x47	/* Abort sequence was received. */
#define	CS_INVALID_PARAMETER	0x102	/* IP invalid_parameter. */
#define	CS_ERROR_RESOURCE	0x103	/* IP insufficient resources. */
#define	CS_IP_NOT_INITIALIZED	0x104	/* IP not_initialized. */

#define	CS_BAD_PAYLOAD		0x180	/* Driver defined */
#define	CS_UNKNOWN		0x181	/* Driver defined */
#define	CS_CMD_FAILED		0x182	/* Driver defined */
#define	CS_LOOP_DOWN_ABORT	0x183	/* Driver defined */
#define	CS_FCP_RESPONSE_ERROR	0x184	/* Driver defined */
#define	CS_DEVICE_UNAVAILABLE	0x185	/* Driver defined */
/*
 * ISP24xx queue - Status IOCB structure definition.
 */
typedef struct sts_24xx_entry {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  sys_define;		/* System defined. */
	uint8_t  entry_status;		/* Entry Status. */
	uint32_t handle;		/* System handle. */
	uint16_t comp_status;		/* Completion status. */
	uint16_t ox_id;
	uint32_t residual_length;	/* Residual transfer length. */
	uint16_t reserved;
	uint8_t	 state_flags_l;		/* State flags. */
	uint8_t	 state_flags_h;
	uint16_t reserved_1;
	uint8_t  scsi_status_l;		/* SCSI status - LSB. */
	uint8_t  scsi_status_h;		/* SCSI status - MSB. */
	uint32_t fcp_rsp_residual_count;
	uint32_t fcp_sense_length;
	uint32_t fcp_rsp_data_length;	/* Response Info Length. */
	uint8_t  rsp_sense_data[28];	/* FCP response and/or sense data. */
} sts_24xx_entry_t;

/*
 * ISP queue - status continuation entry structure definition.
 */
#define	STATUS_CONT_TYPE	0x10	/* Status continuation entry. */
typedef struct sts_cont_entry {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  sys_define;		/* System defined. */
	uint8_t  entry_status;		/* Entry Status. */
	uint8_t  req_sense_data[60];	/* Request sense data. */
} sts_cont_entry_t;

/*
 * ISP queue -	marker with extended LUN support
 *		entry structure definition.
 */
#define	MARKER_TYPE	0x04		/* Marker entry. */
typedef struct mrk_entry {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  sys_define;		/* System defined. */
	uint8_t  entry_status;		/* Entry Status. */
	uint32_t sys_define_2;		/* System defined. */
	uint8_t  target_l;		/* SCSI ID - LSB */
	uint8_t  target_h;		/* SCSI ID - MSB */
	uint8_t  modifier;		/* Modifier (7-0). */
	uint8_t  reserved_1;
	uint8_t  sequence_number[2];	/* Sequence number of event. */
	uint8_t  lun_l;			/* SCSI LUN - LSB */
	uint8_t  lun_h;			/* SCSI LUN - MSB */
	uint8_t  reserved_2[48];
} mrk_entry_t;

/*
 * Marker modifiers
 */
#define	MK_SYNC_ID_LUN	0		/* Synchronize ID/LUN */
#define	MK_SYNC_ID	1		/* Synchronize ID */
#define	MK_SYNC_ALL	2		/* Synchronize all ID/LUN */
#define	MK_SYNC_LIP	3		/* Synchronize all ID/LUN, */
					/* clear port changed, */
					/* use sequence number. */
/*
 * ISP24xx queue - Marker IOCB structure definition.
 */
typedef struct marker_24xx_entry {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  sys_define;		/* System defined. */
	uint8_t  entry_status;		/* Entry Status. */
	uint32_t handle;		/* System handle */
	uint16_t n_port_hdl;
	uint8_t  modifier;		/* Modifier */
	uint8_t  reserved[2];
	uint8_t  vp_index;
	uint8_t  reserved_1[2];
	uint8_t  fcp_lun[8];		/* SCSI LUN ID. */
	uint8_t  reserved_2[40];
} marker_24xx_entry_t;

/*
 * ISP queue -	Management Server entry structure definition.
 */
#define	MS_TYPE			0x29
#define	MS_DATA_SEGMENTS	1	/* Number of data segments. */
typedef struct ms_entry {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  sys_define;		/* System defined. */
	uint8_t  entry_status;		/* Entry Status. */
	uint32_t handle;		/* System handle */
	uint8_t  loop_id_l;		/* device id - LSB */
	uint8_t  loop_id_h;		/* device id - MSB */
	uint16_t comp_status;		/* Completion status */
	uint8_t  control_flags_l;	/* Control flags - LSB. */
	uint8_t  control_flags_h;	/* Control flags - MSB. */
	uint8_t  reserved_1[2];
	uint16_t timeout;		/* Command timeout. */
	uint8_t  cmd_dseg_count_l;	/* CMD segment count - LSB. */
	uint8_t  cmd_dseg_count_h;	/* CMD segment count - MSB. */
	uint16_t total_dseg_count;	/* CMD + RESP segment count. */
	uint8_t	 reserved_2[10];
	uint32_t resp_byte_count;	/* Response byte count */
	uint32_t cmd_byte_count;	/* Command byte count */
	uint32_t dseg_0_address[2];	/* Data segment 0 address. */
	uint32_t dseg_0_length;		/* Data segment 0 length. */
	uint32_t dseg_1_address[2];	/* Data segment 1 address. */
	uint32_t dseg_1_length;		/* Data segment 1 length. */
} ms_entry_t;

/*
 * ISP24xx queue - CT Pass-Through IOCB structure definition.
 */
#define	CT_PASSTHRU_TYPE		0x29
#define	CT_PASSTHRU_DATA_SEGMENTS	1	/* Number of data segments. */
typedef struct ct_passthru_entry {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  sys_define;		/* System defined. */
	uint8_t  entry_status;		/* Entry Status. */
	uint32_t handle;		/* System handle */
	uint16_t status;
	uint16_t n_port_hdl;
	uint16_t cmd_dseg_count;
	uint8_t  vp_index;
	uint8_t  reserved;
	uint16_t timeout;
	uint16_t reserved_1;
	uint16_t resp_dseg_count;
	uint8_t  reserved_2[10];
	uint32_t resp_byte_count;
	uint32_t cmd_byte_count;
	uint32_t dseg_0_address[2];	/* Data segment 0 address. */
	uint32_t dseg_0_length;		/* Data segment 0 length. */
	uint32_t dseg_1_address[2];	/* Data segment 1 address. */
	uint32_t dseg_1_length;		/* Data segment 1 length. */
} ct_passthru_entry_t;

/*
 * ISP24xx queue - ELS Pass-Through IOCB structure definition.
 */
#define	ELS_PASSTHRU_TYPE		0x53
typedef struct els_passthru_entry {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  sys_define;		/* System defined. */
	uint8_t  entry_status;		/* Entry Status. */
	uint32_t handle;		/* System handle */
	uint16_t reserved_8_9;
	uint16_t n_port_hdl;
	uint16_t xmt_dseg_count;	/* Only one allowed */
	uint8_t  vp_index;
	uint8_t  sof_type;
	uint32_t rcv_exch_address;
	uint16_t rcv_dseg_count;
	uint8_t  els_cmd_opcode;
	uint8_t  reserved_17;
	uint8_t  d_id_7_0;
	uint8_t  d_id_15_8;
	uint8_t  d_id_23_16;
	uint8_t  s_id_23_16;
	uint8_t  s_id_7_0;
	uint8_t  s_id_15_8;
	uint16_t control_flags;
	uint32_t rcv_payld_data_bcnt;
	uint32_t xmt_payld_data_bcnt;
	uint32_t xmt_dseg_0_address[2];	/* Tx Data segment 0 address. */
	uint32_t xmt_dseg_0_length;	/* Tx Data segment 0 length.  */
	uint32_t rcv_dseg_0_address[2];	/* Rx Data segment 0 address. */
	uint32_t rcv_dseg_0_length;	/* Rx Data segment 0 length.  */
} els_passthru_entry_t;

/*
 * ISP24x queue - ELS Pass-Through IOCB response.
 */
typedef struct els_passthru_entry_rsp {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  sys_define;		/* System defined. */
	uint8_t  entry_status;		/* Entry Status. */
	uint32_t handle;		/* System handle */
	uint16_t comp_status;
	uint16_t n_port_hdl;
	uint16_t reserved_c_d;
	uint8_t  vp_index;
	uint8_t  sof_type;
	uint32_t rcv_exch_addr;
	uint16_t reserved_14_15;
	uint8_t  els_cmd_opcode;
	uint8_t  reserved_17;
	uint8_t  d_id_7_0;
	uint8_t  d_id_15_8;
	uint8_t  d_id_23_16;
	uint8_t  s_id_23_16;
	uint8_t  s_id_7_0;
	uint8_t  s_id_15_8;
	uint16_t control_flags;
	uint32_t total_data_bcnt;
	uint32_t error_subcode1;
	uint32_t error_subcode2;
	uint8_t  reserved_2c_3f[20];
} els_passthru_entry_rsp_t;

/*
 * ISP24xx queue - Task Management IOCB structure definition.
 */
#define	TASK_MGMT_TYPE		0x14
typedef struct task_mgmt_entry {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  sys_define;		/* System defined. */
	uint8_t  entry_status;		/* Entry Status. */
	uint32_t handle;		/* System handle */
	uint16_t n_port_hdl;
	uint16_t reserved;
	uint16_t delay;
	uint16_t timeout;
	uint8_t  fcp_lun[8];		/* SCSI LUN ID. */
	uint32_t control_flags;
	uint8_t  reserved_1[20];
	uint8_t  target_id[3];		/* SCSI Target ID */
	uint8_t  vp_index;
	uint8_t  reserved_2[12];
} task_mgmt_entry_t;

/*
 * Control Flags.
 */
#define	CF_DO_NOT_SEND		BIT_31
#define	CF_LUN_RESET		BIT_4
#define	CF_ABORT_TASK_SET	BIT_3
#define	CF_CLEAR_TASK_SET	BIT_2
#define	CF_TARGET_RESET		BIT_1
#define	CF_CLEAR_ACA		BIT_0

/*
 * ISP24xx queue - Abort I/O IOCB structure definition.
 */
#define	ABORT_CMD_TYPE		0x33
typedef struct abort_cmd_entry {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  sys_define;		/* System defined. */
	uint8_t  entry_status;		/* Entry Status. */
	uint32_t handle;		/* System handle */
	uint16_t n_port_hdl;		/* also comp_status */
	uint8_t  options;
	uint8_t  options_h;
	uint32_t cmd_handle;
	uint8_t  reserved[32];
	uint8_t  target_id[3];		/* Port ID */
	uint8_t  vp_index;
	uint8_t  reserved_1[12];
} abort_cmd_entry_t;

/*
 * Option Flags.
 */
#define	AF_NO_ABTS		BIT_0

/*
 * ISP24xx queue - Login/Logout Port IOCB structure definition.
 */
#define	LOG_TYPE		0x52
typedef struct log_entry {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  sys_define;		/* System defined. */
	uint8_t  entry_status;		/* Entry Status. */
	uint32_t handle;		/* System handle */
	uint16_t status;
	uint16_t n_port_hdl;
	uint16_t control_flags;
	uint8_t  vp_index;
	uint8_t  reserved;
	uint8_t  port_id[3];
	uint8_t  rsp_size;
	uint32_t io_param[11];
} log_entry_t;

/*
 * ISP24xx control flag commands
 */
#define	CF_CMD_PLOGI	0x00
#define	CF_CMD_PRLI	0x01
#define	CF_CMD_PDISC	0x02
#define	CF_CMD_ADISC	0x03
#define	CF_CMD_LOGO	0x08
#define	CF_CMD_PRLO	0x09
#define	CF_CMD_TPRLO	0x0A

/*
 * ISP24xx control flag command options
 */
#define	CFO_COND_PLOGI		BIT_4
#define	CFO_SKIP_PRLI		BIT_5
#define	CFO_COMMON_FEATURES	BIT_7
#define	CFO_CLASS_2		BIT_8
#define	CFO_FCP_2_OVR		BIT_9

#define	CFO_IMPLICIT_LOGO	BIT_4
#define	CFO_IMPLICIT_LOGO_ALL	BIT_5
#define	CFO_EXPLICIT_LOGO	BIT_6
#define	CFO_FREE_N_PORT_HANDLE	BIT_7

#define	CFO_IMPLICIT_PRLO	BIT_4

/*
 * ISP24xx Login/Logout Status Sub Codes in in I/O Parameter 0 field.
 */
#define	CS0_NO_LINK			0x01
#define	CS0_NO_IOCB			0x02
#define	CS0_NO_EXCH_CTRL_BLK		0x03
#define	CS0_COMMAND_FAILED		0x04
#define	CS0_NO_FABRIC_PRESENT		0x05
#define	CS0_FIRMWARE_NOT_READY		0x07
#define	CS0_PORT_NOT_LOGGED_IN		0x09
#define	CS0_NO_PCB_ALLOCATED		0x0A
#define	CS0_ELS_REJECT_RECEIVED		0x18
#define	CS0_CMD_PARAMETER_ERROR		0x19
#define	CS0_PORT_ID_USED		0x1A
#define	CS0_N_PORT_HANDLE_USED		0x1B
#define	CS0_NO_N_PORT_HANDLE_AVAILABLE	0x1C
#define	CS0_NO_FLOGI_ACC		0x1F

/*
 * ISP24xx Login/Logout Status Sub Codes in in I/O Parameter 1 field.
 */
#define	CS1_PLOGI_FAILED		0x02
#define	CS1_PLOGI_RESPONSE_FAILED	0x03
#define	CS1_PRLI_FAILED			0x04
#define	CS1_PRLI_RESPONSE_FAILED	0x05
#define	CS1_COMMAND_LOGGED_OUT		0x07

/*
 * ISP queue -	Enable LUN with extended LUN support
 *		entry structure definition.
 */
#define	ENABLE_LUN_TYPE	0xB		/* Enable LUN entry */
typedef struct enable_lun_entry {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  sys_define;		/* System defined. */
	uint8_t  entry_status;		/* Entry Status. */
	uint32_t handle;		/* System handle */
	uint8_t  reserved[8];
	uint8_t  status;
	uint8_t  reserved_1;
	uint8_t  command_count;
	uint8_t  immediate_notify_count;
	uint8_t  reserved_2[2];
	uint8_t  timeout_l;		/* Timeout - LSB. */
	uint8_t  timeout_h;		/* Timeout - MSB. */
	uint8_t  reserved_3[40];
} enable_lun_entry_t;

/*
 * ISP queue -	Modify LUN with extended LUN support
 *		entry structure definition.
 */
#define	MODIFY_LUN_TYPE	0xC		/* Modify LUN entry */
typedef struct modify_lun_entry {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  sys_define;		/* System defined. */
	uint8_t  entry_status;		/* Entry Status. */
	uint32_t handle;		/* System handle */
	uint8_t  reserved[2];
	uint8_t  operators;
	uint8_t  reserved_1[5];
	uint8_t  status;
	uint8_t  reserved_2;
	uint8_t  command_count;
	uint8_t  immediate_notify_count;
	uint8_t  reserved_3[2];
	uint8_t  timeout_l;		/* Timeout - LSB. */
	uint8_t  timeout_h;		/* Timeout - MSB. */
	uint8_t  reserved_4[40];
} modify_lun_entry_t;

/*
 * ISP queue -	Immediate Notify with extended LUN support
 *		entry structure definition.
 */
#define	IMMEDIATE_NOTIFY_TYPE	0xD	/* Immediate notify entry */
typedef struct immediate_notify_entry {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  sys_define;		/* System defined. */
	uint8_t  entry_status;		/* Entry Status. */
	uint32_t handle;		/* System handle */
	uint8_t  initiator_id_l;
	uint8_t  initiator_id_h;
	uint8_t  lun_l;
	uint8_t  lun_h;
	uint8_t  reserved_1[4];
	uint16_t status;
	uint8_t  task_flags_l;
	uint8_t  task_flags_h;
	uint16_t sequence_id;
	uint8_t  reserved_3[40];
	uint16_t ox_id;
} immediate_notify_entry_t;

/*
 * ISP24xx queue - Immediate Notify IOCB structure definition.
 */
typedef struct immd_notify_24xx_entry {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  sys_define;		/* System defined. */
	uint8_t  entry_status;		/* Entry Status. */
	uint32_t reserved;
	uint16_t n_port_hdl;
	uint16_t reserved_1;
	uint16_t flags;
	uint16_t srr_rx_id;
	uint16_t status;
	uint8_t  status_subcode;
	uint8_t  reserved_2;
	uint32_t receive_exchange_address;
	uint32_t srr_relative_offset;
	uint16_t srr_iu;
	uint16_t srr_ox_id;
	uint8_t  reserved_3[19];
	uint8_t  vp_index;
	uint8_t  reserved_4[10];
	uint16_t ox_id;
} immd_notify_24xx_entry_t;

/*
 * ISP queue -	Notify Acknowledge extended LUN support
 *		entry structure definition.
 */
#define	NOTIFY_ACKNOWLEDGE_TYPE	0xE	/* Immediate notify entry */
typedef struct notify_acknowledge_entry {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  sys_define;		/* System defined. */
	uint8_t  entry_status;		/* Entry Status. */
	uint32_t handle;		/* System handle */
	uint8_t  initiator_id_l;
	uint8_t  initiator_id_h;
	uint8_t  reserved_1[2];
	uint8_t  flags_l;
	uint8_t  flags_h;
	uint8_t  reserved_2[2];
	uint16_t status;
	uint8_t  task_flags_l;
	uint8_t  task_flags_h;
	uint16_t sequence_id;
	uint8_t  reserved_3[42];
} notify_acknowledge_entry_t;

/*
 * ISP24xx queue - Notify Acknowledge IOCB structure definition.
 */
typedef struct notify_ack_24xx_entry {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  sys_define;		/* System defined. */
	uint8_t  entry_status;		/* Entry Status. */
	uint32_t handle;
	uint16_t n_port_hdl;
	uint16_t reserved_1;
	uint16_t flags;
	uint16_t srr_rx_id;
	uint16_t status;
	uint8_t  status_subcode;
	uint8_t  reserved_2;
	uint32_t receive_exchange_address;
	uint32_t srr_relative_offset;
	uint16_t srr_iu;
	uint16_t srr_flags;
	uint8_t  reserved_3[19];
	uint8_t  vp_index;
	uint8_t  srr_reject_vendor_unique;
	uint8_t  srr_reject_code_explanation;
	uint8_t  srr_reject_code;
	uint8_t  reserved_4[7];
	uint16_t ox_id;
} notify_ack_24xx_entry_t;

/*
 * ISP queue -	Accept Target I/O with extended LUN support
 *		entry structure definition.
 */
#define	ATIO_TYPE	0x16			/* ATIO entry */
typedef struct atio_entry {
	uint8_t		entry_type;		/* Entry type. */
	uint8_t		entry_count;		/* Entry count. */
	uint8_t		sys_define;		/* System defined. */
	uint8_t		entry_status;		/* Entry Status. */
	uint32_t	handle;			/* System handle */
	uint8_t		initiator_id_l;
	uint8_t		initiator_id_h;
	uint16_t	rx_id;
	uint8_t		flags_l;
	uint8_t		flags_h;
	uint16_t	status;
	uint8_t		reserved_1;
	uint8_t		task_codes : 3,
			reserved_2 : 5;
	uint8_t		task_flags;
	uint8_t		execution_codes;
	uint8_t		cdb[MAX_CMDSZ];
	uint32_t	data_length;
	uint8_t		lun_l;
	uint8_t		lun_h;
	uint8_t		reserved_3[20];
	uint16_t	ox_id;
} atio_entry_t;

/*
 * ISP24xx queue - Accept Target I/O IOCB structure definition.
 */
#define	ATIO_24xx_TYPE		0x06
typedef struct atio_24xx_entry {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint16_t len_attr;		/* System defined. */
	uint32_t receive_exchange_address;
	uint8_t  frame_hdr[24];
	uint8_t  payload[32];
} atio_24xx_entry_t;

/*
 * ISP queue -	Continue Target I/O with extended LUN support
 *		entry structure definition.
 */
#define	CTIO_TYPE_2   0x17
#define	CTIO_TYPE_3   0x1F
typedef struct ctio_entry {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  sys_define;		/* System defined. */
	uint8_t  entry_status;		/* Entry Status. */
	uint32_t handle;		/* System handle */
	uint8_t  initiator_id_l;
	uint8_t  initiator_id_h;
	uint16_t rx_id;
	uint8_t  flags_l;
	uint8_t  flags_h;
	uint16_t status;
	uint16_t timeout;
	uint8_t  dseg_count_l;
	uint8_t  dseg_count_h;
	uint32_t relative_offset;
	uint32_t residual_transfer_length;
	uint8_t  reserved_1[4];

	union {
		struct {
			uint8_t  reserved_2[2];
			uint8_t  scsi_status_l;
			uint8_t  scsi_status_h;
			uint32_t byte_count;
			uint32_t dseg_0_address;
			uint32_t dseg_0_length;
			uint32_t dseg_1_address;
			uint32_t dseg_1_length;
			uint32_t dseg_2_address;
			uint32_t dseg_2_length;
		}s0_32bit;

		struct {
			uint8_t  reserved_3[2];
			uint8_t  scsi_status_l;
			uint8_t  scsi_status_h;
			uint32_t byte_count;
			uint32_t dseg_0_address[2];
			uint32_t dseg_0_length;
			uint32_t dseg_1_address[2];
			uint32_t dseg_1_length;
		}s0_64bit;

		struct {
			uint8_t  sense_length_l;
			uint8_t  sense_length_h;
			uint8_t  scsi_status_l;
			uint8_t  scsi_status_h;
			uint8_t  response_length_l;
			uint8_t  response_length_h;
			uint8_t  response_info[26];
		}s1;

		struct {
			uint8_t  reserved_4[2];
			uint32_t response_length;
			uint32_t response_pointer;
			uint8_t  reserved[16];
		}s2;
	}type;
} ctio_entry_t;

/*
 * ISP24xx queue -	Continue Target I/O IOCBs from the System
 *		Target Driver structure definition.
 */
#define	CTIO_24xx_TYPE		0x12
typedef struct ctio_snd_entry {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  sys_define;		/* System defined. */
	uint8_t  entry_status;		/* Entry Status. */
	uint32_t handle;
	uint16_t n_port_hdl;
	uint16_t timeout;
	uint16_t dseg_count;
	uint8_t  vp_index;
	uint8_t  flags;
	uint8_t initiator_id[3];
	uint8_t  reserved_1;
	uint32_t receive_exchange_address;

	union {
		struct {
			uint16_t reserved_2;
			uint16_t flags;
			uint32_t residual_length;
			uint16_t ox_id;
			uint16_t scsi_status;
			uint32_t relative_offset;
			uint32_t reserved_3;
			uint32_t transfer_length;
			uint32_t reserved_4;
			uint32_t dseg_0_address_l;
			uint32_t dseg_0_address_h;
			uint32_t dseg_0_length;
		}s0;

		struct {
			uint16_t sense_length;
			uint16_t flags;
			uint32_t residual_length;
			uint16_t ox_id;
			uint16_t scsi_status;
			uint16_t response_length;
			uint16_t reserved_2;
			uint8_t  rsp_sense_data[24];
		}s1;

		struct {
			uint16_t reserved_2;
			uint16_t flags;
			uint32_t residual_length;
			uint16_t ox_id;
			uint8_t  reserved_3[10];
			uint32_t transfer_length;
			uint32_t reserved_4;
			uint32_t dseg_0_address_l;
			uint32_t dseg_0_address_h;
			uint32_t dseg_0_length;
		}s2;
	}type;
} ctio_snd_entry_t;

/*
 * ISP24xx queue -	Continue Target I/O IOCBs from the ISP24xx
 *		Firmware structure definition.
 */
typedef struct ctio_rcv_entry {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  sys_define;		/* System defined. */
	uint8_t  entry_status;		/* Entry Status. */
	uint32_t handle;
	uint16_t status;
	uint16_t timeout;
	uint16_t dseg_count;
	uint8_t  reserved[6];

	uint8_t  vp_index;
	uint8_t  flags;
	uint8_t initiator_id[3];
	uint8_t  reserved_1;
	uint32_t receive_exchange_address;

	union {
		struct {
			uint16_t reserved_2;
			uint16_t flags;
			uint32_t residual_length;
			uint16_t ox_id;
			uint16_t scsi_status;
			uint32_t relative_offset;
			uint32_t reserved_3;
			uint32_t transfer_length;
			uint32_t reserved_4;
			uint32_t dseg_0_address_l;
			uint32_t dseg_0_address_h;
			uint32_t dseg_0_length;
		}s0;

		struct {
			uint16_t sense_length;
			uint16_t flags;
			uint32_t residual_length;
			uint16_t ox_id;
			uint16_t scsi_status;
			uint16_t response_length;
			uint16_t reserved_2;
			uint8_t  rsp_sense_data[24];
		}s1;

		struct {
			uint16_t reserved_2;
			uint16_t flags;
			uint32_t residual_length;
			uint16_t ox_id;
			uint8_t  reserved_3[10];
			uint32_t transfer_length;
			uint32_t reserved_4;
			uint32_t dseg_0_address_l;
			uint32_t dseg_0_address_h;
			uint32_t dseg_0_length;
		}s2;
	}type;
} ctio_rcv_entry_t;

/*
 * ISP queue -	32-Bit DMA addressing IP entry structure definition.
 */
#define	IP_TYPE			0x13
#define	IP_DATA_SEGMENTS	3	/* Number of data segments. */
typedef struct ip_entry {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  sys_define;		/* System defined. */
	uint8_t  entry_status;		/* Entry Status. */
	uint32_t handle;		/* System handle */
	uint8_t  loop_id_l;		/* device id - LSB */
	uint8_t  loop_id_h;		/* device id - MSB */
	uint16_t comp_status;		/* Completion status. */
	uint8_t  control_flags_l;	/* Control flags - LSB. */
	uint8_t  control_flags_h;	/* Control flags - MSB. */
	uint8_t  reserved_1[2];
	uint16_t timeout;		/* Command timeout. */
	uint16_t dseg_count;		/* Data segment count. */
	uint8_t  reserved_2[16];
	uint32_t byte_count;		/* Total byte count. */
	uint32_t dseg_0_address;	/* Data segment 0 address. */
	uint32_t dseg_0_length;		/* Data segment 0 length. */
	uint32_t dseg_1_address;	/* Data segment 1 address. */
	uint32_t dseg_1_length;		/* Data segment 1 length. */
	uint32_t dseg_2_address;	/* Data segment 2 address. */
	uint32_t dseg_2_length;		/* Data segment 2 length. */
} ip_entry_t;

/*
 * ISP queue -	64-Bit DMA addressing IP entry structure definition.
 */
#define	IP_A64_TYPE		0x1B
#define	IP_A64_DATA_SEGMENTS	2	/* Number of data segments. */
typedef struct ip_a64_entry {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  sys_define;		/* System defined. */
	uint8_t  entry_status;		/* Entry Status. */
	uint32_t handle;		/* System handle */
	uint8_t  reserved;
	uint8_t  loop_id;		/* Loop ID */
	uint16_t comp_status;		/* Completion status. */
	uint8_t  control_flags_l;	/* Control flags - LSB. */
	uint8_t  control_flags_h;	/* Control flags - MSB. */
	uint8_t  reserved_1[2];
	uint16_t timeout;		/* Command timeout. */
	uint16_t dseg_count;		/* Data segment count. */
	uint8_t  reserved_2[16];
	uint32_t byte_count;		/* Total byte count. */
	uint32_t dseg_0_address[2];	/* Data segment 0 address. */
	uint32_t dseg_0_length;		/* Data segment 0 length. */
	uint32_t dseg_1_address[2];	/* Data segment 1 address. */
	uint32_t dseg_1_length;		/* Data segment 1 length. */
} ip_a64_entry_t;

/*
 * ISP24xx queue - IP command entry structure definition.
 */
#define	IP_CMD_TYPE		0x3B
#define	IP_CMD_DATA_SEGMENTS	1
typedef struct ip_cmd_entry {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  sys_define;		/* System defined. */
	uint8_t  entry_status;		/* Entry Status. */
	uint32_t handle;		/* System handle. */
	uint16_t hdl_status;		/* N_port hdl or Completion status */
	uint16_t timeout_hdl;		/* N_port hdl or Command timeout */
	uint16_t dseg_count;		/* Data segment count. */
	uint8_t  reserved_1[6];
	uint32_t exch_addr;
	uint16_t control_flags;
	uint16_t frame_hdr_cntrl_flgs;
	uint8_t  reserved_2[12];
	uint32_t sys_define_2;
	uint32_t byte_count;		/* Total byte count. */
	uint8_t  reserved_3[4];
	uint32_t dseg_0_address[2];	/* Data segment 0 address. */
	uint32_t dseg_0_length;		/* Data segment 0 length. */
} ip_cmd_entry_t;

/*
 * IP command Control Flags.
 */
#define	IPCF_TERMINATE_EXCH	BIT_1
/*
 * IP command Frame Header Control Flags.
 */
#define	IPCF_FIRST_SEQ		BIT_5
#define	IPCF_LAST_SEQ		BIT_4

/*
 * ISP queue - Receive IP buffer entry structure definition.
 */
#define	IP_RCVBUF_HANDLES	24	/* Buffer handles in entry. */
#define	IP_RECEIVE_TYPE		0x23	/* IP receive entry */
typedef struct ip_rcv_entry {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  segment_count;		/* Segment count. */
	uint8_t  entry_status;		/* Entry Status. */
	uint8_t  s_id[3];		/* Source ID. */
	uint8_t  reserved[2];
	uint8_t  loop_id;		/* Loop ID */
	uint16_t comp_status;		/* Completion status. */
	uint8_t  class_of_srv_l;	/* Class of service - LSB. */
	uint8_t  class_of_srv_h;	/* Class of service - MSB. */
	uint16_t seq_length;		/* Sequence length. */
	uint16_t buffer_handle[IP_RCVBUF_HANDLES]; /* Buffer handles. */
} ip_rcv_entry_t;

/*
 * ISP queue - Receive IP buffer continuation entry structure definition.
 */
#define	IP_RCVBUF_CONT_HANDLES	30	/* Buffer handles in entry. */
#define	IP_RECEIVE_CONT_TYPE	0x2B	/* IP receive continuation entry */
typedef struct ip_rcv_cont_entry {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  reserved;
	uint8_t  entry_status;		/* Entry Status. */
	uint16_t buffer_handle[IP_RCVBUF_CONT_HANDLES]; /* Buf handles */
} ip_rcv_cont_entry_t;

/*
 * ISP24xx queue - Receive IP buffer entry structure definition.
 */
#define	IP_24XX_RCVBUF_HANDLES	4
#define	IP_24XX_RECEIVE_TYPE	0x3c
typedef struct ip_rcv_24xx_entry {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  segment_count;		/* Segment count. */
	uint8_t  entry_status;		/* Entry Status. */
	uint8_t  s_id[3];		/* Source ID. */
	uint8_t  reserved[1];
	uint16_t comp_status;		/* Completion status. */
	uint16_t n_port_hdl;		/* Loop ID */
	uint8_t  class_of_srv_l;	/* Class of service - LSB. */
	uint8_t  class_of_srv_h;	/* Class of service - MSB. */
	uint16_t seq_length;		/* Sequence length. */
	uint16_t buffer_handle[IP_24XX_RCVBUF_HANDLES]; /* Buffer handles. */
} ip_rcv_24xx_entry_t;

/*
 * ISP receive buffer container structure definition.
 */
typedef struct rcvbuf {
	uint32_t bufp[2];		/* Buffer pointer. */
	uint16_t handle;		/* Buffer handle. */
	uint16_t reserved;
} rcvbuf_t;

/*
 * ISP24xx queue - IP Load Buffer Pool entry structure definition.
 */
#define	IP_POOL_BUFFERS		4
#define	IP_BUF_POOL_TYPE	0x3d
typedef struct ip_buf_pool_entry  {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  sys_define;		/* System defined. */
	uint8_t  entry_status;		/* Entry Status. */
	uint32_t handle;		/* System handle */
	uint16_t status;
	uint16_t buffer_pool_id;
	uint16_t option;
	uint8_t  buffer_count;
	uint8_t  buffer_count_h;
	rcvbuf_t buffers[IP_POOL_BUFFERS];
} ip_buf_pool_entry_t;
/*
 * ISP2400 queue - Virtual Port Modify IOCB structure definition.
 */
#define	VP_MODIFY_TYPE		0x31
typedef struct vp_modify_entry {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  sys_define;		/* System defined. */
	uint8_t  entry_status;		/* Entry Status. */
	uint32_t handle;		/* System handle */
	uint16_t reserved;
	uint16_t status;
	uint8_t  command;
	uint8_t  vp_count;
	uint8_t  first_vp_index;
	uint8_t  second_vp_index;
	uint8_t  first_options;
	uint8_t  first_hard_prev_addr;
	uint8_t  reserved_2[2];
	uint8_t  first_port_name[8];
	uint8_t  first_node_name[8];
	uint8_t  second_options;
	uint8_t  second_hard_prev_addr;
	uint8_t  reserved_3[2];
	uint8_t  second_port_name[8];
	uint8_t  second_node_name[8];
	uint8_t  reserved_4[6];
	uint16_t fcf_index;
} vp_modify_entry_t;

/*
 * ISP2400 VP modify commands
 */
#define	VPM_MODIFY		0x0
#define	VPM_MODIFY_ENABLE	0x1

/*
 * ISP2400 queue - Virtual Port Control IOCB structure definition.
 */
#define	VP_CONTROL_TYPE		0x30
typedef struct vp_control_entry {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  sys_define;		/* System defined. */
	uint8_t  entry_status;		/* Entry Status. */
	uint32_t handle;		/* System handle */
	uint16_t vp_index_failed;
	uint16_t status;
	uint8_t  command;
	uint8_t  command_h;
	uint8_t  vp_count;
	uint8_t  vp_count_h;
	uint8_t  vp_index[16];
	uint8_t  reserved[30];
	uint16_t fcf_index;
} vp_control_entry_t;

/*
 * ISP2400 VP control commands
 */
#define	VPC_ENABLE		0x0
#define	VPC_DISABLE		0x8
#define	VPC_DISABLE_INIT	0x9	/* Only 2400 & 2500 */
#define	VPC_DISABLE_LOGOUT	0xa
#define	VPC_DISABLE_LOGOUT_ALL	0xb

/*
 * ISP2400 queue - Report ID Acquisition IOCB structure definition.
 */
#define	REPORT_ID_TYPE		0x32
typedef struct report_id_0 {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  sys_define;		/* System defined. */
	uint8_t  entry_status;		/* Entry Status. */
	uint32_t handle;		/* System handle */
	uint8_t  acq_cnt;		/* format 0 acquired, format 1 count */
	uint8_t  setup;			/* format 0 */
	uint8_t  reserved[2];
	uint8_t  port_id[3];
	uint8_t  format;
	uint8_t  vp_index[16];
	uint8_t  reserved_1[32];
} report_id_0_t;

typedef struct report_id_1 {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  sys_define;		/* System defined. */
	uint8_t  entry_status;		/* Entry Status. */
	uint32_t handle;		/* System handle */
	uint16_t vp_count;
	uint8_t  vp_index;
	uint8_t  status;
	uint8_t  port_id[3];
	uint8_t  format;
	uint8_t  reserved[48];
} report_id_1_t;

/*
 * ISP2400 queue - Verify Menlo FW entry structure definition.
 */
#define	VERIFY_MENLO_TYPE	0x1b
typedef struct vfy_menlo_entry {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  sys_define;		/* System defined. */
	uint8_t  entry_status;		/* Entry Status. */
	uint32_t handle;		/* System handle */
	uint16_t options_status;
	uint16_t failure_code;
	uint16_t dseg_count;
	uint16_t reserved_1[3];
	uint32_t fw_version;
	uint32_t exch_addr;
	uint32_t reserved_2[3];
	uint32_t fw_size;
	uint32_t fw_sequence_size;
	uint32_t relative_offset;
	uint32_t dseg_0_address[2];	/* Data segment 0 address. */
	uint32_t dseg_0_length;		/* Data segment 0 length. */
} vfy_menlo_entry_t;

/*
 * Option Flags.
 */
#define	VMO_DSD_CHAINING	BIT_15
#define	VM_END_OF_DATA		BIT_14
#define	VMF_DIAGNOSTIC_FW	BIT_3
#define	VMF_DO_NOT_RESET	BIT_2
#define	VMF_FORCE_UPDATE_FW	BIT_1
#define	VMF_DO_NOT_UPDATE_FW	BIT_0

/*
 * ISP2400 queue - Access Menlo Data entry structure definition.
 */
#define	MENLO_DATA_TYPE		0x2b
typedef struct menlo_data_entry {
	uint8_t  entry_type;		/* Entry type. */
	uint8_t  entry_count;		/* Entry count. */
	uint8_t  sys_define;		/* System defined. */
	uint8_t  entry_status;		/* Entry Status. */
	uint32_t handle;		/* System handle */
	uint16_t options_status;
	uint16_t failure_code;
	uint16_t dseg_count;
	uint16_t reserved_1[3];
	uint32_t parameter_1;
	uint32_t parameter_2;
	uint32_t parameter_3;
	uint32_t reserved_2[3];
	uint32_t total_byte_count;
	uint32_t reserved_3;
	uint32_t dseg_0_address[2];	/* Data segment 0 address. */
	uint32_t dseg_0_length;		/* Data segment 0 length. */
} menlo_data_entry_t;

/*
 * Mailbox IOCB.
 */
typedef union ql_mbx_iocb {
	cmd_entry_t		cmd;
	cmd_3_entry_t		cmd3;
	cmd7_24xx_entry_t	cmd24;
	ms_entry_t		ms;
	ct_passthru_entry_t	ms24;
	abort_cmd_entry_t	abo;
	task_mgmt_entry_t	mgmt;
	sts_entry_t		sts;
	sts_24xx_entry_t	sts24;
	log_entry_t		log;
	vp_control_entry_t	vpc;
	vp_modify_entry_t	vpm;
	vfy_menlo_entry_t	mvfy;
	menlo_data_entry_t	mdata;
} ql_mbx_iocb_t;

/*
 * Global Data in ql_iocb.c source file.
 */

/*
 * Global Function Prototypes in ql_iocb.c source file.
 */
void ql_start_iocb(ql_adapter_state_t *, ql_srb_t *);
void ql_isp_cmd(ql_adapter_state_t *);
int ql_marker(ql_adapter_state_t *, uint16_t, uint16_t, uint8_t);
void ql_isp_rcvbuf(ql_adapter_state_t *);
void ql_command_iocb(ql_adapter_state_t *, ql_srb_t *, void *);
void ql_ms_iocb(ql_adapter_state_t *, ql_srb_t *, void *);
void ql_ip_iocb(ql_adapter_state_t *, ql_srb_t *, void *);
void ql_command_24xx_iocb(ql_adapter_state_t *, ql_srb_t *, void *);
void ql_ms_24xx_iocb(ql_adapter_state_t *, ql_srb_t *, void *);
void ql_ip_24xx_iocb(ql_adapter_state_t *, ql_srb_t *, void *);
void ql_els_24xx_iocb(ql_adapter_state_t *, ql_srb_t *, void *);

#ifdef	__cplusplus
}
#endif

#endif /* _QL_IOCB_H */
