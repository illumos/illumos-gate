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
 * Copyright (c) 1990, 2010, Oracle and/or its affiliates. All rights reserved.
 *
 * Copyright 2011 Nexenta Systems, Inc.  All rights reserved.
 */

#ifndef	_SYS_SCSI_GENERIC_COMMANDS_H
#define	_SYS_SCSI_GENERIC_COMMANDS_H

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * Standard SCSI Command Definitions
 *
 * Macros to determine known command sizes
 */
#define	CDB_GROUPID(cmd)	((cmd >> 5) & 0x7)
#define	CDB_GROUPID_0	0
#define	CDB_GROUPID_1	1
#define	CDB_GROUPID_2	2
#define	CDB_GROUPID_3	3
#define	CDB_GROUPID_4	4
#define	CDB_GROUPID_5	5
#define	CDB_GROUPID_6	6
#define	CDB_GROUPID_7	7

#define	CDB_GROUP0	6	/*  6-byte cdb's */
#define	CDB_GROUP1	10	/* 10-byte cdb's */
#define	CDB_GROUP2	10	/* 10-byte cdb's */
#define	CDB_GROUP3	0	/* reserved */
#define	CDB_GROUP4	16	/* 16-byte cdb's */
#define	CDB_GROUP5	12	/* 12-byte cdb's */
#define	CDB_GROUP6	0	/* reserved */
#define	CDB_GROUP7	0	/* reserved */

/*
 * Generic Command Definitions
 * NOTE: CDROM commands are defined in cdio.h
 */

/*
 * Group 0 Commands (CDB range 0x00 - 0x1F)
 */
#define	SCMD_GROUP0		0x00

/*
 * Group 0 commands, All Devices
 */
#define	SCMD_TEST_UNIT_READY	0x00
#define	SCMD_REQUEST_SENSE	0x03
#define	SCMD_INQUIRY		0x12
#define	SCMD_COPY		0x18
#define	SCMD_GDIAG		0x1C	/* receive diagnostic results */
#define	SCMD_SDIAG		0x1D	/* send diagnostic results */

/*
 * Group 0 commands, Direct Access Devices
 */
/*	SCMD_TEST_UNIT_READY	0x00	*/
#define	SCMD_REZERO_UNIT	0x01
/*	SCMD_REQUEST_SENSE	0x03	*/
#define	SCMD_FORMAT		0x04
#define	SCMD_REASSIGN_BLOCK	0x07
#define	SCMD_READ		0x08
#define	SCMD_WRITE		0x0a
#define	SCMD_SEEK		0x0b
/*	SCMD_INQUIRY		0x12	*/
#define	SCMD_MODE_SELECT	0x15
#define	SCMD_RESERVE		0x16
#define	SCMD_RELEASE		0x17
/*	SCMD_COPY		0x18	*/
#define	SCMD_MODE_SENSE		0x1a
#define	SCMD_START_STOP		0x1b
/*	SCMD_GDIAG		0x1C	*/
/*	SCMD_SDIAG		0x1D	*/
#define	SCMD_DOORLOCK		0x1E	/* Prevent/Allow Medium Removal */

/*
 * Group 0 commands, Sequential Access Devices
 */
/*	SCMD_TEST_UNIT_READY	0x00	*/
#define	SCMD_REWIND		0x01	/* Note similarity to SCMD_REZERO */
/*	SCMD_REQUEST_SENSE	0x03	*/
#define	SCMD_READ_BLKLIM	0x05
/*	SCMD_READ		0x08	*/
/*	SCMD_WRITE		0x0a	*/
#define	SCMD_TRK_SEL		0x0b	/* Note similarity to SCMD_SEEK */
#define	SCMD_READ_REVERSE	0x0f
#define	SCMD_WRITE_FILE_MARK	0x10
#define	SCMD_SPACE		0x11
/*	SCMD_INQUIRY		0x12	*/
#define	SCMD_VERIFY_G0		0x13
#define	SCMD_RECOVER_BUF	0x14
/*	SCMD_MODE_SELECT	0x15	*/
/*	SCMD_RESERVE		0x16	*/
/*	SCMD_RELEASE		0x17	*/
/*	SCMD_COPY		0x18	*/
#define	SCMD_ERASE		0x19
/*	SCMD_MODE_SENSE		0x1a	*/
#define	SCMD_LOAD		0x1b	/* Note similarity to SCMD_START_STOP */
/*	SCMD_GDIAG		0x1c	*/
/*	SCMD_SDIAG		0x1d	*/
/*	SCMD_DOORLOCK		0x1e	*/


/*
 * Group 0 commands, Printer Devices
 */
/*	SCMD_TEST_UNIT_READY	0x00	*/
/*	SCMD_REQUEST_SENSE	0x03	*/
/*	SCMD_FORMAT		0x04	*/
#define	SCMD_PRINT		0x0a	/* Note similarity to SCMD_WRITE */
#define	SCMD_SLEW_PRINT		0x0b	/* ? similar to SCMD_SEEK ? */
#define	SCMD_FLUSH_PRINT_BUF	0x10	/* ? similar to SCMD_WRITE_FILE_MARK */
/*	SCMD_INQUIRY		0x12	*/
/*	SCMD_RECOVER_BUF	0x14	*/
/*	SCMD_MODE_SELECT	0x15	*/
/*	SCMD_RESERVE		0x16	*/
/*	SCMD_RELEASE		0x17	*/
/*	SCMD_COPY		0x18	*/
/*	SCMD_MODE_SENSE		0x1a	*/
#define	SCMD_STOP_PRINT		0x1b	/* Note similarity to SCMD_START_STOP */
/*	SCMD_GDIAG		0x1c	*/
/*	SCMD_SDIAG		0x1d	*/

/*
 * Group 0 commands, Processor Devices
 */
/*	SCMD_TEST_UNIT_READY	0x00	*/
/*	SCMD_REQUEST_SENSE	0x03	*/
#define	SCMD_RECEIVE		0x08	/* Note similarity to SCMD_READ */
#define	SCMD_SEND		0x0a	/* Note similarity to SCMD_WRITE */
/*	SCMD_INQUIRY		0x12	*/
/*	SCMD_COPY		0x18	*/
/*	SCMD_MODE_SENSE		0x1a	*/
/*	SCMD_GDIAG		0x1c	*/
/*	SCMD_SDIAG		0x1d	*/

/*
 * Group 0 commands, WORM Devices
 */
/*	SCMD_TEST_UNIT_READY	0x00	*/
/*	SCMD_REZERO_UNIT	0x01	*/
/*	SCMD_REQUEST_SENSE	0x03	*/
/*	SCMD_REASSIGN_BLOCK	0x07	*/
/*	SCMD_READ		0x08	*/
/*	SCMD_WRITE		0x0a	*/
/*	SCMD_SEEK		0x0b	*/
/*	SCMD_INQUIRY		0x12	*/
/*	SCMD_MODE_SELECT	0x15	*/
/*	SCMD_RESERVE		0x16	*/
/*	SCMD_RELEASE		0x17	*/
/*	SCMD_COPY		0x18	*/
/*	SCMD_MODE_SENSE		0x1a	*/
/*	SCMD_START_STOP		0x1b	*/
/*	SCMD_GDIAG		0x1C	*/
/*	SCMD_SDIAG		0x1D	*/
/*	SCMD_DOORLOCK		0x1E	*/

/*
 * Group 0 commands, Read Only Devices
 */
/*	SCMD_TEST_UNIT_READY	0x00	*/
/*	SCMD_REZERO_UNIT	0x01	*/
/*	SCMD_REQUEST_SENSE	0x03	*/
/*	SCMD_REASSIGN_BLOCK	0x07	*/
/*	SCMD_READ		0x08	*/
/*	SCMD_SEEK		0x0b	*/
/*	SCMD_INQUIRY		0x12	*/
/*	SCMD_MODE_SELECT	0x15	*/
/*	SCMD_RESERVE		0x16	*/
/*	SCMD_RELEASE		0x17	*/
/*	SCMD_COPY		0x18	*/
/*	SCMD_MODE_SENSE		0x1a	*/
/*	SCMD_START_STOP		0x1b	*/
/*	SCMD_GDIAG		0x1C	*/
/*	SCMD_SDIAG		0x1D	*/
/*	SCMD_DOORLOCK		0x1E	*/

/*
 * Group 1 Commands (CDB range 0x20 - 0x3F)
 */
#define	SCMD_GROUP1		0x20

/*
 * Group 1 Commands, All Devices
 */
#define	SCMD_COMPARE		0x39
#define	SCMD_COPY_VERIFY	0x3A
#define	SCMD_PERSISTENT_RESERVE_IN		0x5E
#define	SCMD_PERSISTENT_RESERVE_OUT		0x5F
#define	SCMD_PRIN		SCMD_PERSISTENT_RESERVE_IN
#define	SCMD_PROUT		SCMD_PERSISTENT_RESERVE_OUT

/*
 * Group 1 Commands, Direct Access Devices
 */
#define	SCMD_READ_FORMAT_CAP	0x23
#define	SCMD_READ_CAPACITY	0x25
#define	SCMD_READ_G1		0x28	/* Note that only the group changed */
#define	SCMD_WRITE_G1		0x2a	/* Note that only the group changed */
#define	SCMD_SEEK_G1		0x2b	/* Note that only the group changed */
#define	SCMD_WRITE_VERIFY	0x2e
#define	SCMD_VERIFY		0x2f
#define	SCMD_SEARCH_HIGH	0x30
#define	SCMD_SEARCH_EQUAL	0x31
#define	SCMD_SEARCH_LOW		0x32
#define	SCMD_SET_LIMITS		0x33
#define	SCMD_SYNCHRONIZE_CACHE	0x35
#define	SCMD_READ_DEFECT_LIST	0x37
#define	SCMD_WRITE_BUFFER	0x3B
#define	SCMD_READ_BUFFER	0x3c
#define	SCMD_READ_LONG		0x3E
#define	SCMD_WRITE_LONG		0x3F
#define	SCMD_WRITE_SAME_G1	0x41
#define	SCMD_UNMAP		0x42
#define	SCMD_GET_CONFIGURATION	0x46
#define	SCMD_LOG_SELECT_G1	0x4c
#define	SCMD_LOG_SENSE_G1	0x4d
#define	SCMD_RESERVE_G1		0x56
#define	SCMD_RELEASE_G1		0x57
#define	SCMD_MODE_SELECT_G1	0x55
#define	SCMD_MODE_SENSE_G1	0x5A


/*
 * Group 1 Commands, Sequential Access Devices
 */
#define	SCMD_LOCATE		0x2B	/* Note similarity to SCMD_SEEK_G1 */
#define	SCMD_READ_POSITION	0x34
#define	SCMD_REPORT_DENSITIES	0x44

/*
 * Group 1 Commands, Printer Devices
 */
/* (None Defined) */

/*
 * Group 1 Commands, Processor Devices
 */
/* (None Defined) */

/*
 * Group 1 Commands, WORM Devices
 */
/*	SCMD_READ_CAPACITY	0x25	*/
/*	SCMD_READ_G1		0x28	*/
/*	SCMD_WRITE_G1		0x2a	*/
/*	SCMD_SEEK_G1		0x2b	*/
/*	SCMD_WRITE_VERIFY	0x2e	*/
/*	SCMD_VERIFY		0x2f	*/
/*	SCMD_SEARCH_HIGH	0x30	*/
/*	SCMD_SEARCH_EQUAL	0x31	*/
/*	SCMD_SEARCH_LOW		0x32	*/
/*	SCMD_SET_LIMITS		0x33	*/

/*
 * Group 1 Commands, Read Only Devices
 */
/*	SCMD_READ_CAPACITY	0x25	*/
/*	SCMD_READ_G1		0x28	*/
/*	SCMD_SEEK_G1		0x2b	*/
/*	SCMD_VERIFY		0x2f	*/
/*	SCMD_SEARCH_HIGH	0x30	*/
/*	SCMD_SEARCH_EQUAL	0x31	*/
/*	SCMD_SEARCH_LOW		0x32	*/
/*	SCMD_SET_LIMITS		0x33	*/

/*
 * Group 1 Commands, MMC Devices
 */

/* GET EVENT STATUS NOTIFICATION, MMC-3 5.6 */
#define	SCMD_GET_EVENT_STATUS_NOTIFICATION	0x4a

/* event header */
#define	SD_GESN_HEADER_LEN			4
#define	SD_GESN_HEADER_NEA			0x80	/* byte 2 */
#define	SD_GESN_HEADER_CLASS			0x07	/* byte 2 */

/* media class event class and event data that follows the header */
#define	SD_GESN_MEDIA_CLASS			4

#define	SD_GESN_MEDIA_DATA_LEN			4
#define	SD_GESN_MEDIA_EVENT_CODE		0x0f	/* byte 0 */
#define	SD_GESN_MEDIA_EVENT_STATUS_PRESENT	0x02	/* byte 1 */
#define	SD_GESN_MEDIA_EVENT_STATUS_TRAY_OPEN	0x01	/* byte 1 */

/* media event code */
#define	SD_GESN_MEDIA_EVENT_NOCHG		0
#define	SD_GESN_MEDIA_EVENT_EJECTREQUEST	1
#define	SD_GESN_MEDIA_EVENT_NEWMEDIA		2
#define	SD_GESN_MEDIA_EVENT_MEDIAREMOVAL	3
#define	SD_GESN_MEDIA_EVENT_MEDIACHANGED	4
#define	SD_GESN_MEDIA_EVENT_BGFORMATCOMPLETED	5
#define	SD_GESN_MEDIA_EVENT_BGFORMATRESTARTED	6


/*
 * Group 3 Commands
 */
#define	SCMD_VAR_LEN		0x7f

/*
 * Group 4 Commands, All Devices
 */
#define	SCMD_GROUP4		0x80
#define	SCMD_EXTENDED_COPY	0x83
#define	SCMD_VERIFY_G4		0x8f

/*
 * Group 4 Commands, Direct Access Devices
 */
#define	SCMD_READ_G4		0x88
#define	SCMD_WRITE_G4		0x8a
#define	SCMD_WRITE_VERIFY_G4	0x8e
#define	SCMD_WRITE_SAME_G4	0x93
#define	SCMD_SVC_ACTION_IN_G4	0x9e
#define	SCMD_SVC_ACTION_OUT_G4	0x9f

/*
 * Group 4 Service Actions for Service Action In (16)
 */
#define	SSVC_ACTION_READ_CAPACITY_G4	0x10
#define	SSVC_ACTION_READ_LONG_G4	0x11

/*
 * Group 4 Service Actions for Service Action Out (16)
 */
#define	SSVC_ACTION_WRITE_LONG_G4	0x11

/*
 * Group 4 Commands, Sequential Access Devics
 */
#define	SCMD_WRITE_FILE_MARK_G4	0x80
#define	SCMD_READ_REVERSE_G4	0x81
#define	SCMD_READ_ATTRIBUTE	0x8c
#define	SCMD_WRITE_ATTRIBUTE	0x8d
#define	SCMD_SPACE_G4		0x91
#define	SCMD_LOCATE_G4		0x92

/*
 * Group 5 commands.
 */
#define	SCMD_GROUP5		0xA0
#define	SCMD_REPORT_LUNS	0xA0
#define	SCMD_SECURITY_PROTO_IN	0xA2
#define	SCMD_MAINTENANCE_IN	0xA3
#define	SCMD_MAINTENANCE_OUT	0xA4
#define	SCMD_READ_G5		0xA8
#define	SCMD_WRITE_G5		0xAA
#define	SCMD_SVC_ACTION_OUT_G5	0xA9
#define	SCMD_SVC_ACTION_IN_G5	0xAB
#define	SCMD_GET_PERFORMANCE	0xAC
#define	SCMD_WRITE_VERIFY_G5	0xAE
#define	SCMD_VERIFY_G5		0xAF
#define	SCMD_SECURITY_PROTO_OUT	0xB5

/*
 * Group 5 Service Actions for Maintenance In (12)
 */
#define	SSVC_ACTION_GET_TARGET_PORT_GROUPS	0x0a
#define	SSVC_ACTION_GET_SUPPORTED_OPERATIONS	0x0c
#define	SSVC_SCTION_GET_SUPPORTED_MANAGEMENT	0x0d
#define	SSVC_ACTION_GET_TIMESTAMP		0x0f

/*
 * Group 5 Service Actions for Maintenance Out (12)
 */
#define	SSVC_ACTION_SET_DEVICE_IDENTIFIER	0x06
#define	SSVC_ACTION_SET_PRIORITY		0x0e
#define	SSVC_ACTION_SET_TARGET_PORT_GROUPS	0x0a
#define	SSVC_ACTION_SET_TIMESTAMP		0x0f

/*
 * Group 5 Service Actions for Service Action In (12)
 */
#define	SSVC_ACTION_READ_MEDIA_SERIAL		0x01
/*
 * scsi_key_strings for SCMD_ definitions
 *	NOTE: see SCSI_CMDS_KEY_STRINGS_CDIO in cdio.h for additional
 *	command-to-string translations.
 */
#define	SCSI_CMDS_KEY_STRINGS						\
/* 0x00 */ SCMD_TEST_UNIT_READY,	"test_unit_ready",		\
/* 0x01 */ SCMD_REWIND |						\
		SCMD_REZERO_UNIT,	"rezero/rewind",		\
/* 0x03 */ SCMD_REQUEST_SENSE,		"request_sense",		\
/* 0x04 */ SCMD_FORMAT,			"format",			\
/* 0x05 */ SCMD_READ_BLKLIM,		"read_block_limits",		\
/* 0x07 */ SCMD_REASSIGN_BLOCK,		"reassign",			\
/* 0x08 */ SCMD_READ |							\
		SCMD_RECEIVE,		"read",				\
/* 0x0a */ SCMD_PRINT |							\
		SCMD_SEND |						\
		SCMD_WRITE,		"write",			\
/* 0x0b */ SCMD_SEEK |							\
		SCMD_SLEW_PRINT |					\
		SCMD_TRK_SEL,		"seek",				\
/* 0x0f */ SCMD_READ_REVERSE,		"read_reverse",			\
/* 0x10 */ SCMD_WRITE_FILE_MARK |					\
		SCMD_FLUSH_PRINT_BUF,	"write_file_mark",		\
/* 0x11 */ SCMD_SPACE,			"space",			\
/* 0x12 */ SCMD_INQUIRY,		"inquiry",			\
/* 0x13 */ SCMD_VERIFY_G0,		"verify",			\
/* 0x14 */ SCMD_RECOVER_BUF,		"recover_buffer_data",		\
/* 0x15 */ SCMD_MODE_SELECT,		"mode_select",			\
/* 0x16 */ SCMD_RESERVE,		"reserve",			\
/* 0x17 */ SCMD_RELEASE,		"release",			\
/* 0x18 */ SCMD_COPY,			"copy",				\
/* 0x19 */ SCMD_ERASE,			"erase_tape",			\
/* 0x1a */ SCMD_MODE_SENSE,		"mode_sense",			\
/* 0x1b */ SCMD_LOAD |							\
		SCMD_START_STOP |					\
		SCMD_STOP_PRINT,	"load/start/stop",		\
/* 0x1c */ SCMD_GDIAG,			"get_diagnostic_results",	\
/* 0x1d */ SCMD_SDIAG,			"send_diagnostic_command",	\
/* 0x1e */ SCMD_DOORLOCK,		"door_lock",			\
/* 0x23 */ SCMD_READ_FORMAT_CAP,	"read_format_capacity",		\
/* 0x25 */ SCMD_READ_CAPACITY,		"read_capacity",		\
/* 0x28 */ SCMD_READ_G1,		"read(10)",			\
/* 0x2a */ SCMD_WRITE_G1,		"write(10)",			\
/* 0x2b */ SCMD_SEEK_G1 |						\
		SCMD_LOCATE,		"seek(10)",			\
/* 0x2e */ SCMD_WRITE_VERIFY,		"write_verify",			\
/* 0x2f */ SCMD_VERIFY,			"verify(10)",			\
/* 0x30 */ SCMD_SEARCH_HIGH,		"search_data_high",		\
/* 0x31 */ SCMD_SEARCH_EQUAL,		"search_data_equal",		\
/* 0x32 */ SCMD_SEARCH_LOW,		"search_data_low",		\
/* 0x33 */ SCMD_SET_LIMITS,		"set_limits",			\
/* 0x34 */ SCMD_READ_POSITION,		"read_position",		\
/* 0x35 */ SCMD_SYNCHRONIZE_CACHE,	"synchronize_cache",		\
/* 0x37 */ SCMD_READ_DEFECT_LIST,	"read_defect_data",		\
/* 0x39 */ SCMD_COMPARE,		"compare",			\
/* 0x3a */ SCMD_COPY_VERIFY,		"copy_verify",			\
/* 0x3b */ SCMD_WRITE_BUFFER,		"write_buffer",			\
/* 0x3c */ SCMD_READ_BUFFER,		"read_buffer",			\
/* 0x3e */ SCMD_READ_LONG,		"read_long",			\
/* 0x3f */ SCMD_WRITE_LONG,		"write_long",			\
/* 0x41 */ SCMD_WRITE_SAME_G1,		"write_same(10)",		\
/* 0x42 */ SCMD_UNMAP,			"unmap",			\
/* 0x44 */ SCMD_REPORT_DENSITIES |					\
		/* SCMD_READ_HEADER (from cdio.h) | */			\
		0,			"report_densities/read_header",	\
/* 0x46 */ SCMD_GET_CONFIGURATION,	"get_configuration",		\
/* 0x4c */ SCMD_LOG_SELECT_G1,		"log_select",			\
/* 0x4d */ SCMD_LOG_SENSE_G1,		"log_sense",			\
/* 0x55 */ SCMD_MODE_SELECT_G1,		"mode_select(10)",		\
/* 0x56 */ SCMD_RESERVE_G1,		"reserve(10)",			\
/* 0x57 */ SCMD_RELEASE_G1,		"release(10)",			\
/* 0x5a */ SCMD_MODE_SENSE_G1,		"mode_sense(10)",		\
/* 0x5e */ SCMD_PERSISTENT_RESERVE_IN,	"persistent_reserve_in",	\
/* 0x5f */ SCMD_PERSISTENT_RESERVE_OUT,	"persistent_reserve_out",	\
/* 0x80 */ SCMD_WRITE_FILE_MARK_G4,	"write_file_mark(16)",		\
/* 0x81 */ SCMD_READ_REVERSE_G4,	"read_reverse(16)",		\
/* 0x83 */ SCMD_EXTENDED_COPY,		"extended_copy",		\
/* 0x88 */ SCMD_READ_G4,		"read(16)",			\
/* 0x8a */ SCMD_WRITE_G4,		"write(16)",			\
/* 0x8c */ SCMD_READ_ATTRIBUTE,		"read_attribute",		\
/* 0x8d */ SCMD_WRITE_ATTRIBUTE,	"write_attribute",		\
/* 0x8e */ SCMD_WRITE_VERIFY_G4,	"write_verify(16)",		\
/* 0x8f */ SCMD_VERIFY_G4,		"verify(16)",			\
/* 0x91 */ SCMD_SPACE_G4,		"space(16)",			\
/* 0x92 */ SCMD_LOCATE_G4,		"locate(16)",			\
/* 0x92 */ SCMD_WRITE_SAME_G4,		"write_same(16)",		\
/* 0x9e */ SCMD_SVC_ACTION_IN_G4,	"service_action_in(16)",	\
/* 0x9f */ SCMD_SVC_ACTION_OUT_G4,	"service_action_out(16)",	\
/* 0xa0 */ SCMD_REPORT_LUNS,		"report_luns",			\
/* 0xa2 */ SCMD_SECURITY_PROTO_IN,	"security_protocol_in",		\
/* 0xa3 */ SCMD_MAINTENANCE_IN,		"maintenance_in",		\
/* 0xa4 */ SCMD_MAINTENANCE_OUT,	"maintenance_out",		\
/* 0xa8 */ SCMD_READ_G5,		"read(12)",			\
/* 0xa9 */ SCMD_SVC_ACTION_OUT_G5,	"service_action_out(12)",	\
/* 0xaa */ SCMD_WRITE_G5,		"write(12)",			\
/* 0xab */ SCMD_SVC_ACTION_IN_G5,	"service_action_in(12)",	\
/* 0xac */ SCMD_GET_PERFORMANCE,	"get_performance",		\
/* 0xAE */ SCMD_WRITE_VERIFY_G5,	"write_verify(12)",		\
/* 0xAF */ SCMD_VERIFY_G5,		"verify(12)",			\
/* 0xb5 */ SCMD_SECURITY_PROTO_OUT,	"security_protocol_out"		\
	/* see cdio.h for additional command-to-string translations */

/* XXX not a command code, does not belong here */
#define	ATAPI_CAPABILITIES	0x2A

#ifdef	__cplusplus
}
#endif

/*
 * Below are inclusions of files describing various command structures
 * of interest.
 */
#include <sys/scsi/generic/inquiry.h>
#include <sys/scsi/generic/sense.h>

/*
 * Private Vendor Unique Commands - Each implementation provides this.
 */
#include <sys/scsi/impl/commands.h>

#endif	/* _SYS_SCSI_GENERIC_COMMANDS_H */
