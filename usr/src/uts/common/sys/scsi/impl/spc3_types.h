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
 * Copyright (c) 2007, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef	_SPC3_TYPES_H
#define	_SPC3_TYPES_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/types.h>
#include <sys/cdio.h>
#include <sys/sysmacros.h>
#include <sys/scsi/generic/commands.h>
#include <sys/scsi/impl/commands.h>

typedef enum spc3_cmd {
	SPC3_CMD_TEST_UNIT_READY = SCMD_TEST_UNIT_READY,
	SPC3_CMD_REZERO_UNIT = SCMD_REZERO_UNIT,
	SPC3_CMD_REWIND = SCMD_REWIND,
	SPC3_CMD_VENDOR_2 = 2,
	SPC3_CMD_REQUEST_SENSE = SCMD_REQUEST_SENSE,
	SPC3_CMD_FORMAT_UNIT = SCMD_FORMAT,
	SPC3_CMD_FORMAT_MEDIUM = SCMD_FORMAT,
	SPC3_CMD_FORMAT = SCMD_FORMAT,
	SPC3_CMD_READ_BLOCK_LIMITS = SCMD_READ_BLKLIM,
	SPC3_CMD_VENDOR_6 = 6,
	SPC3_CMD_REASSIGN_BLOCKS = SCMD_REASSIGN_BLOCK,
	SPC3_CMD_INITIALIZE_ELEMENT_STATUS = SCMD_REASSIGN_BLOCK,
	SPC3_CMD_READ = SCMD_READ,
	SPC3_CMD_READ6 = SCMD_READ,
	SPC3_CMD_RECEIVE = SCMD_RECEIVE,
	SPC3_CMD_GET_MESSAGE = SCMD_READ,
	SPC3_CMD_VENDOR_9 = 9,
	SPC3_CMD_WRITE = SCMD_WRITE,
	SPC3_CMD_WRITE6 = SCMD_WRITE,
	SPC3_CMD_SEND = SCMD_SEND,
	SPC3_CMD_SEND6 = SCMD_SEND,
	SPC3_CMD_SEND_MESSAGE = SCMD_SEND,
	SPC3_CMD_PRINT = SCMD_PRINT,
	SPC3_CMD_SEEK = SCMD_SEEK,
	SPC3_CMD_SEEK6 = SCMD_SEEK,
	SPC3_CMD_SET_CAPACITY = SCMD_SEEK,
	SPC3_CMD_SLEW_AND_PRINT = SCMD_SLEW_PRINT,
	SPC3_CMD_VENDOR_C = 0xc,
	SPC3_CMD_VENDOR_D = 0xd,
	SPC3_CMD_VENDOR_E = 0xe,
	SPC3_CMD_READ_REVERSE = SCMD_READ_REVERSE,
	SPC3_CMD_READ_REVERSE6 = SCMD_READ_REVERSE,
	SPC3_CMD_WRITE_FILEMARKS = SCMD_WRITE_FILE_MARK,
	SPC3_CMD_WRITE_FILEMARKS6 = SCMD_WRITE_FILE_MARK,
	SPC3_CMD_SYNCHRONIZE_BUFFER = SCMD_FLUSH_PRINT_BUF,
	SPC3_CMD_SPACE = SCMD_SPACE,
	SPC3_CMD_SPACE6 = SCMD_SPACE,
	SPC3_CMD_INQUIRY = SCMD_INQUIRY,
	SPC3_CMD_VERIFY = SCMD_VERIFY_G0,
	SPC3_CMD_VERIFY6 = SCMD_VERIFY_G0,
	SPC3_CMD_RECOVER_BUFFERED_DATA = SCMD_RECOVER_BUF,
	SPC3_CMD_MODE_SELECT = SCMD_MODE_SELECT,
	SPC3_CMD_MODE_SELECT6 = SCMD_MODE_SELECT,
	SPC3_CMD_RESERVE = SCMD_RESERVE,
	SPC3_CMD_RESERVE6 = SCMD_RESERVE,
	SPC3_CMD_RESERVE_ELEMENT = SCMD_RESERVE,
	SPC3_CMD_RESERVE_ELEMENT6 = SCMD_RESERVE,
	SPC3_CMD_RELEASE = SCMD_RELEASE,
	SPC3_CMD_RELEASE6 = SCMD_RELEASE,
	SPC3_CMD_RELEASE_ELEMENT = SCMD_RELEASE,
	SPC3_CMD_RELEASE_ELEMENT6 = SCMD_RELEASE,
	SPC3_CMD_COPY = SCMD_COPY,
	SPC3_CMD_ERASE = SCMD_ERASE,
	SPC3_CMD_ERASE6 = SCMD_ERASE,
	SPC3_CMD_MODE_SENSE = SCMD_MODE_SENSE,
	SPC3_CMD_MODE_SENSE6 = SCMD_MODE_SENSE,
	SPC3_CMD_START_STOP_UNIT = SCMD_START_STOP,
	SPC3_CMD_LOAD_UNLOAD = SCMD_LOAD,
	SPC3_CMD_SCAN = SCMD_START_STOP,
	SPC3_CMD_STOP_PRINT = SCMD_STOP_PRINT,
	SPC3_CMD_RECEIVE_DIAGNOSTIC_RESULTS = SCMD_GDIAG,
	SPC3_CMD_SEND_DIAGNOSTIC = SCMD_SDIAG,
	SPC3_CMD_PREVENT_ALLOW_MEDIUM_REMOVAL = SCMD_DOORLOCK,
	SPC3_CMD_VENDOR_20 = 0x20,
	SPC3_CMD_VENDOR_21 = 0x21,
	SPC3_CMD_VENDOR_22 = 0x22,
	SPC3_CMD_VENDOR_23 = 0x23,
	SPC3_CMD_SET_WINDOW = 0x24,
	SPC3_CMD_READ_CAPACITY = SCMD_READ_CAPACITY,
	SPC3_CMD_READ_CAPACITY10 = SCMD_READ_CAPACITY,
	SPC3_CMD_READ_CARD_CAPACITY = SCMD_READ_CAPACITY,
	SPC3_CMD_GET_WINDOW = SCMD_READ_CAPACITY,
	SPC3_CMD_VENDOR_26 = 0x26,
	SPC3_CMD_VENDOR_27 = 0x27,
	SPC3_CMD_READ10 = SCMD_READ_G1,
	SPC3_CMD_GET_MESSAGE10 = SCMD_READ_G1,
	SPC3_CMD_READ_GENERATION = 0x29,
	SPC3_CMD_WRITE10 = SCMD_WRITE_G1,
	SPC3_CMD_SEND10 = SCMD_WRITE_G1,
	SPC3_CMD_SEND_MESSAGE10 = SCMD_WRITE_G1,
	SPC3_CMD_SEEK10 = SCMD_SEEK_G1,
	SPC3_CMD_LOCATE = SCMD_LOCATE,
	SPC3_CMD_LOCATE10 = SCMD_LOCATE,
	SPC3_CMD_POSITION_TO_ELEMENT = SCMD_SEEK_G1,
	SPC3_CMD_ERASE10 = 0x2c,
	SPC3_CMD_READ_UPDATED_BLOCK = 0x2d,
	SPC3_CMD_WRITE_AND_VERIFY = SCMD_WRITE_VERIFY,
	SPC3_CMD_WRITE_AND_VERIFY10 = SCMD_WRITE_VERIFY,
	SPC3_CMD_VERIFY10 = SCMD_VERIFY,
	SPC3_CMD_SEARCH_DATA_HIGH = SCMD_SEARCH_HIGH,
	SPC3_CMD_SEARCH_DATA_HIGH10 = SCMD_SEARCH_HIGH,
	SPC3_CMD_SEARCH_DATA_EQUAL = SCMD_SEARCH_EQUAL,
	SPC3_CMD_SEARCH_DATA_EQUAL10 = SCMD_SEARCH_EQUAL,
	SPC3_CMD_OBJECT_POSITION = SCMD_SEARCH_EQUAL,
	SPC3_CMD_SEARCH_DATA_LOW = SCMD_SEARCH_LOW,
	SPC3_CMD_SEARCH_DATA_LOW10 = SCMD_SEARCH_LOW,
	SPC3_CMD_SET_LIMITS = SCMD_SET_LIMITS,
	SPC3_CMD_SET_LIMITS10 = SCMD_SET_LIMITS,
	SPC3_CMD_PREFETCH = SCMD_READ_POSITION,
	SPC3_CMD_PREFETCH10 = SCMD_READ_POSITION,
	SPC3_CMD_READ_POSITION = SCMD_READ_POSITION,
	SPC3_CMD_GET_DATA_BUFFER_STATUS = SCMD_READ_POSITION,
	SPC3_CMD_SYNCHRONIZE_CACHE = SCMD_SYNCHRONIZE_CACHE,
	SPC3_CMD_SYNCHRONIZE_CACHE10 = SCMD_SYNCHRONIZE_CACHE,
	SPC3_CMD_LOCK_UNLOCK_CACHE = 0x36,
	SPC3_CMD_READ_DEFECT_DATA = SCMD_READ_DEFECT_LIST,
	SPC3_CMD_READ_DEFECT_DATA10 = SCMD_READ_DEFECT_LIST,
	SPC3_CMD_INITIALIZE_ELEMENT_STATUS_WITH_RANGE = SCMD_READ_DEFECT_LIST,
	SPC3_CMD_MEDIUM_SCAN = 0x38,
	SPC3_CMD_COMPARE = SCMD_COMPARE,
	SPC3_CMD_COPY_AND_VERIFY = SCMD_COPY_VERIFY,
	SPC3_CMD_WRITE_BUFFER = SCMD_WRITE_BUFFER,
	SPC3_CMD_READ_BUFFER = SCMD_READ_BUFFER,
	SPC3_CMD_UPDATE_BLOCK = 0x3d,
	SPC3_CMD_READ_LONG = SCMD_READ_LONG,
	SPC3_CMD_READ_LONG10 = SCMD_READ_LONG,
	SPC3_CMD_WRITE_LONG = SCMD_WRITE_LONG,
	SPC3_CMD_WRITE_LONG10 = SCMD_WRITE_LONG,
	SPC3_CMD_CHANGE_DEFINITION = 0x40,
	SPC3_CMD_WRITE_SAME = 0x41,
	SPC3_CMD_WRITE_SAME10 = 0x41,
	SPC3_CMD_UNMAP = 0x42,
	SPC3_CMD_UNMAP10 = 0x42,
	SPC3_CMD_READ_SUBCHANNEL = SCMD_READ_SUBCHANNEL,
	SPC3_CMD_READ_TOC = SCMD_READ_TOC,
	SPC3_CMD_REPORT_DENSITY_SUPPORT = SCMD_REPORT_DENSITIES,
	SPC3_CMD_READ_HEADER = SCMD_READ_HEADER,
	SPC3_CMD_PLAY_AUDIO = SCMD_PLAYAUDIO10,
	SPC3_CMD_PLAY_AUDIO10 = SCMD_PLAYAUDIO10,
	SPC3_CMD_GET_CONFIGURATION = SCMD_GET_CONFIGURATION,
	SPC3_CMD_PLAY_AUDIO_MSF = SCMD_PLAYAUDIO_MSF,
	/* Not defined by SPC-3 */
	SPC3_CMD_PLAY_AUDIO_TI = SCMD_PLAYAUDIO_TI,
	SPC3_CMD_PLAY_TRACK_REL = SCMD_PLAYTRACK_REL10,
	SPC3_CMD_PLAY_TRACK_REL10 = SCMD_PLAYTRACK_REL10,
	SPC3_CMD_GET_EVENT_STATUS_NOTIFICATION = 0x4a,
	SPC3_CMD_PAUSE_RESUME = SCMD_PAUSE_RESUME,
	SPC3_CMD_LOG_SELECT = SCMD_LOG_SELECT_G1,
	SPC3_CMD_LOG_SENSE = SCMD_LOG_SENSE_G1,
	SPC3_CMD_STOP_PLAY_SCAN = 0x4e,
	SPC3_CMD_XDWRITE = 0x50,
	SPC3_CMD_XDWRITE10 = 0x50,
	SPC3_CMD_XPWRITE = 0x51,
	SPC3_CMD_XPWRITE10 = 0x51,
	SPC3_CMD_READ_DISC_INFORMATION = 0x51,
	SPC3_CMD_XDREAD = 0x52,
	SPC3_CMD_XDREAD10 = 0x52,
	SPC3_CMD_READ_TRACK_INFORMATION = 0x52,
	SPC3_CMD_RESERVE_TRACK = 0x53,
	SPC3_CMD_SEND_OPC_INFORMATION = 0x54,
	SPC3_CMD_MODE_SELECT10 = SCMD_MODE_SELECT_G1,
	SPC3_CMD_RESERVE10 = SCMD_RESERVE_G1,
	SPC3_CMD_RESERVE_ELEMENT10 = SCMD_RESERVE_G1,
	SPC3_CMD_RELEASE10 = SCMD_RELEASE_G1,
	SPC3_CMD_RELEASE_ELEMENT10 = SCMD_RELEASE_G1,
	SPC3_CMD_REPAIR_TRACK = 0x58,
	SPC3_CMD_MODE_SENSE10 = SCMD_MODE_SENSE_G1,
	SPC3_CMD_CLOSE_TRACK_SESSION = 0x5b,
	SPC3_CMD_READ_BUFFER_CAPACITY = 0x5c,
	SPC3_CMD_SEND_CUE_SHEET = 0x5d,
	SPC3_CMD_PERSISTENT_RESERVE_IN = SCMD_PERSISTENT_RESERVE_IN,
	SPC3_CMD_PERSISTENT_RESERVE_OUT = SCMD_PERSISTENT_RESERVE_OUT,
	SPC3_CMD_VARIABLE_LENGTH = SCMD_VAR_LEN,
	SPC3_CMD_XDWRITE_EXTENDED = SCMD_WRITE_FILE_MARK_G4,
	SPC3_CMD_XDWRITE_EXTENDED16 = SCMD_WRITE_FILE_MARK_G4,
	SPC3_CMD_WRITE_FILEMARKS16 = SCMD_WRITE_FILE_MARK_G4,
	SPC3_CMD_REBUILD = SCMD_READ_REVERSE_G4,
	SPC3_CMD_REBUILD16 = SCMD_READ_REVERSE_G4,
	SPC3_CMD_READ_REVERSE16 = SCMD_READ_REVERSE_G4,
	SPC3_CMD_REGENERATE = 0x82,
	SPC3_CMD_REGENERATE16 = 0x82,
	SPC3_CMD_EXTENDED_COPY = SCMD_EXTENDED_COPY,
	SPC3_CMD_RECEIVE_COPY_RESULTS = 0x84,
	SPC3_CMD_ATA_COMMAND_PASS_THROUGH = 0x85,
	SPC3_CMD_ATA_COMMAND_PASS_THROUGH16 = 0x85,
	SPC3_CMD_ACCESS_CONTROL_IN = 0x86,
	SPC3_CMD_ACCESS_CONTROL_OUT = 0x87,
	SPC3_CMD_READ16 = SCMD_READ_G4,
	SPC3_CMD_WRITE16 = SCMD_WRITE_G4,
	SPC3_CMD_READ_ATTRIBUTE = SCMD_READ_ATTRIBUTE,
	SPC3_CMD_WRITE_ATTRIBUTE = SCMD_WRITE_ATTRIBUTE,
	SPC3_CMD_WRITE_AND_VERIFY16 = 0x8e,
	SPC3_CMD_VERIFY16 = SCMD_VERIFY_G4,
	SPC3_CMD_PREFETCH16 = 0x90,
	SPC3_CMD_SYNCHRONIZE_CACHE16 = SCMD_SPACE_G4,
	SPC3_CMD_SPACE16 = SCMD_SPACE_G4,
	SPC3_CMD_LOCK_UNLOCK_CACHE16 = 0x92,
	SPC3_CMD_LOCATE16 = 0x92,
	SPC3_CMD_WRITE_SAME16 = 0x93,
	SPC3_CMD_ERASE16 = 0x93,
	SPC3_CMD_SERVICE_ACTION_IN = SCMD_SVC_ACTION_IN_G4,
	SPC3_CMD_SERVICE_ACTION_IN16 = SCMD_SVC_ACTION_IN_G4,
	SPC3_CMD_SERVICE_ACTION_OUT = SCMD_SVC_ACTION_OUT_G4,
	SPC3_CMD_SERVICE_ACTION_OUT16 = SCMD_SVC_ACTION_OUT_G4,
	SPC3_CMD_REPORT_LUNS = SCMD_REPORT_LUNS,
	SPC3_CMD_BLANK = 0xa1,
	SPC3_CMD_ATA_COMMAND_PASS_THROUGH12 = 0xa1,
	SPC3_CMD_SECURITY_PROTO_IN = SCMD_SECURITY_PROTO_IN,
	SPC3_CMD_MAINTENANCE_IN = SCMD_MAINTENANCE_IN,
	SPC3_CMD_SEND_KEY = SCMD_MAINTENANCE_IN,
	SPC3_CMD_MAINTENANCE_OUT = SCMD_MAINTENANCE_OUT,
	SPC3_CMD_REPORT_KEY = SCMD_MAINTENANCE_OUT,
	SPC3_CMD_MOVE_MEDIUM = SCMD_PLAYAUDIO12,
	SPC3_CMD_PLAY_AUDIO12 = SCMD_PLAYAUDIO12,
	SPC3_CMD_EXCHANGE_MEDIUM = 0xa6,
	SPC3_CMD_LOAD_UNLOAD_CD = 0xa6,
	SPC3_CMD_MOVE_MEDIUM_ATTACHED = 0xa7,
	SPC3_CMD_SET_READ_AHEAD = 0xa7,
	SPC3_CMD_READ12 = SCMD_READ_G5,
	SPC3_CMD_GET_MESSAGE12 = SCMD_READ_G5,
	SPC3_CMD_SERVICE_ACTION_OUT12 = SCMD_SVC_ACTION_OUT_G5,
	SPC3_CMD_PLAY_TRACK_REL12 = SCMD_PLAYTRACK_REL12,
	SPC3_CMD_WRITE12 = SCMD_WRITE_G5,
	SPC3_CMD_SEND_MESSAGE12 = SCMD_WRITE_G5,
	SPC3_CMD_SERVICE_ACTION_IN12 = SCMD_SVC_ACTION_IN_G5,
	SPC3_CMD_ERASE12 = SCMD_GET_PERFORMANCE,
	SPC3_CMD_GET_PERFORMANCE = SCMD_GET_PERFORMANCE,
	SPC3_CMD_READ_DVD_STRUCTURE = 0xad,
	SPC3_CMD_WRITE_AND_VERIFY12 = 0xae,
	SPC3_CMD_VERIFY12 = SCMD_VERIFY_G5,
	SPC3_CMD_SEARCH_DATA_HIGH12 = 0xb0,
	SPC3_CMD_SEARCH_DATA_EQUAL12 = 0xb1,
	SPC3_CMD_SEARCH_DATA_LOW12 = 0xb2,
	SPC3_CMD_SET_LIMITS12 = 0xb3,
	SPC3_CMD_READ_ELEMENT_STATUS_ATTACHED = 0xb4,
	SPC3_CMD_REQUEST_VOLUME_ELEMENT_ADDRESS = 0xb5,
	SPC3_CMD_SEND_VOLUME_TAG = 0xb6,
	SPC3_CMD_SET_STREAMING = 0xb6,
	SPC3_CMD_READ_DEFECT_DATA12 = 0xb7,
	SPC3_CMD_READ_ELEMENT_STATUS = 0xb8,
	SPC3_CMD_READ_CD_MSF = 0xb9,
	SPC3_CMD_REDUNDANCY_GROUP_IN = 0xba,
	SPC3_CMD_SCAN12 = 0xba,
	SPC3_CMD_REDUNDANCY_GROUP_OUT = SCMD_SET_CDROM_SPEED,
	SPC3_CMD_SET_CD_SPEED = SCMD_SET_CDROM_SPEED,
	SPC3_CMD_SPARE_IN = 0xbc,
	SPC3_CMD_SPARE_OUT = 0xbd,
	SPC3_CMD_MECHANISM_STATUS = 0xbd,
	SPC3_CMD_VOLUME_SET_IN = SCMD_READ_CD,
	SPC3_CMD_READ_CD = SCMD_READ_CD,
	SPC3_CMD_VOLUME_SET_OUT = 0xbf,
	SPC3_CMD_SEND_DVD_STRUCTURE = 0xbf
} spc3_cmd_t;

typedef enum spc3_dev_type {
	SPC3_DEVTYPE_DIRECT = 0x00,
	SPC3_DEVTYPE_SEQUENTIAL = 0x01,
	SPC3_DEVTYPE_PRINTER = 0x02,
	SPC3_DEVTYPE_PROCESSOR = 0x03,
	SPC3_DEVTYPE_WORM = 0x04,
	SPC3_DEVTYPE_MMC = 0x05,
	SPC3_DEVTYPE_SCANNER = 0x06,
	SPC3_DEVTYPE_OPTICAL = 0x07,
	SPC3_DEVTYPE_CHANGER = 0x08,
	SPC3_DEVTYPE_COMM = 0x09,
	SPC3_DEVTYPE_ARRAY_CONTROLLER = 0x0c,
	SPC3_DEVTYPE_SES = 0x0d,
	SPC3_DEVTYPE_RBC = 0xe,
	SPC3_DEVTYPE_OCRW = 0xf,
	SPC3_DEVTYPE_BCC = 0x10,
	SPC3_DEVTYPE_OSD = 0x11,
	SPC3_DEVTYPE_ADC = 0x12
} spc3_dev_type_t;

/*
 * SAM-4 5.3.1, Table 25
 */
typedef enum sam4_status {
	SAM4_STATUS_GOOD = 0x0,
	SAM4_STATUS_CHECK_CONDITION = 0x2,
	SAM4_STATUS_CONDITION_MET = 0x4,
	SAM4_STATUS_BUSY = 0x8,
	SAM4_STATUS_RESERVATION_CONFLICT = 0x18,
	SAM4_STATUS_TASK_SET_FULL = 0x28,
	SAM4_STATUS_ACA_ACTIVE = 0x30,
	SAM4_STATUS_TASK_ABORTED = 0x40
} sam4_status_t;

#pragma pack(1)

typedef union spc3_control {
	struct {
		DECL_BITFIELD5(
		    c_link	:1,
		    c_flag	:1,
		    c_naca	:1,
		    _reserved1	:3,
		    c_vs_6	:2);
	} c_bits;
	uint8_t c_byte;
} spc3_control_t;

/*
 * SPC-3 6.2.1 CHANGE ALIASES
 */
typedef struct spc3_change_aliases_cdb {
	uint8_t cac_opcode;
	DECL_BITFIELD2(
	    cac_service_action	:5,
	    _reserved1		:3);
	uint8_t _reserved2[4];
	uint32_t cac_parameter_list_length;
	uint8_t _reserved3;
	spc3_control_t cac_control;
} spc3_change_aliases_cdb_t;

typedef struct spc3_alias_entry {
	uint64_t ae_alias_value;
	uint8_t ae_protocol_identifier;
	uint8_t _reserved1[2];
	uint8_t ae_format_code;
	uint8_t _reserved2[2];
	uint16_t ae_designation_length;
	uint8_t ae_designation[1];	/* Flexible */
} spc3_alias_entry_t;

typedef struct spc3_change_aliases_param_list {
	uint32_t capl_parameter_data_length;
	uint8_t _reserved1[4];
	spc3_alias_entry_t capl_alias_entries[1];	/* Flexible */
} spc3_change_aliases_param_list_t;

/*
 * SPC-3 6.4.1 INQUIRY
 */
typedef struct spc3_inquiry_cdb {
	uint8_t ic_opcode;
	DECL_BITFIELD2(
	    ic_evpd	:1,
	    _reserved1	:7);
	uint8_t ic_page_code;
	uint16_t ic_allocation_length;
	spc3_control_t ic_control;
} spc3_inquiry_cdb_t;

typedef struct spc3_inquiry_data {
	DECL_BITFIELD2(
	    id_peripheral_device_type	:5,
	    id_peripheral_qualifier	:3);
	DECL_BITFIELD2(
	    _reserved1	:7,
	    id_rmb	:1);
	uint8_t id_version;
	DECL_BITFIELD4(
	    id_response_data_format	:4,
	    id_hisup			:1,
	    id_naca			:1,
	    _reserved2			:2);
	uint8_t additional_length;
	DECL_BITFIELD6(
	    id_protect	:1,
	    _reserved3	:2,
	    id_3pc	:1,
	    id_tpgs	:2,
	    id_acc	:1,
	    id_sccs	:1);
	DECL_BITFIELD7(
	    id_addr16	:1,
	    _reserved4	:2,
	    id_mchanger	:1,
	    id_multip	:1,
	    id_vs_6_5	:1,
	    id_enc_serv	:1,
	    id_b_que	:1);
	DECL_BITFIELD7(
	    id_vs_7_0	:1,
	    id_cmd_que	:1,
	    _reserved5	:1,
	    id_linked	:1,
	    id_sync	:1,
	    id_wbus16	:1,
	    _reserved6	:2);
	char id_vendor_id[8];
	char id_product_id[16];
	char id_product_revision[4];
	uint8_t id_vs_36[20];
	DECL_BITFIELD4(
	    id_ius	:1,
	    id_qas	:1,
	    id_clocking	:2,
	    _reserved7	:4);
	uint8_t _reserved8;
	uint16_t id_version_descriptors[8];
	uint8_t _reserved9[22];
	uint8_t id_vs_96[1];	/* Flexible */
} spc3_inquiry_data_t;

/*
 * SPC-3 6.5 LOG SELECT
 */
typedef enum spc3_log_page_control {
	SPC3_LOG_PC_CUR_THRESHOLD = 0,
	SPC3_LOG_PC_CUR_CUMULATIVE = 1,
	SPC3_LOG_PC_DEF_THRESHOLD = 2,
	SPC3_LOG_PC_DEF_CUMULATIVE = 3
} spc3_log_page_control_t;

typedef struct spc3_log_select_cdb {
	uint8_t lsc_opcode;
	DECL_BITFIELD3(
	    lsc_sp	:1,
	    lsc_pcr	:1,
	    _reserved1	:6);
	DECL_BITFIELD2(
	    _reserved2	:6,
	    lsc_pc	:2);
	uint8_t _reserved3[4];
	uint16_t lsc_parameter_list_length;
	spc3_control_t lsc_control;
} spc3_log_select_cdb_t;

/*
 * SPC-3 6.6 LOG SENSE
 */
typedef struct spc3_log_sense_cdb {
	uint8_t lsc_opcode;
	DECL_BITFIELD3(
	    lsc_sp	:1,
	    lsc_ppc	:1,
	    _reserved1	:6);
	DECL_BITFIELD2(
	    lsc_page_code	:6,
	    lsc_pc		:2);
	uint8_t _reserved2[2];
	uint16_t lsc_parameter_ptr;
	uint16_t lsc_allocation_length;
	spc3_control_t lsc_control;
} spc3_log_sense_cdb_t;

typedef enum spc3_mode_page_control {
	SPC3_MODE_PC_CURRENT = 0,
	SPC3_MODE_PC_CHANGEABLE = 1,
	SPC3_MODE_PC_DEFAULT = 2,
	SPC3_MODE_PC_SAVED = 3
} spc3_mode_page_control_t;

typedef struct spc3_mode_param_header6 {
	uint8_t mph_mode_data_length;
	uint8_t mph_medium_type;
	uint8_t mph_device_param;
	uint8_t mph_block_descriptor_length;
} spc3_mode_param_header6_t;

typedef spc3_mode_param_header6_t spc3_mode_param_header_t;

typedef struct spc3_mode_param_header10 {
	uint16_t mph_mode_data_length;
	uint8_t mph_medium_type;
	uint8_t mph_device_param;
	DECL_BITFIELD2(
	    mph_longlba	:1,
	    _reserved1	:7);
	uint8_t _reserved2;
	uint16_t mph_block_descriptor_length;
} spc3_mode_param_header10_t;

typedef struct spc3_mode_param_block_descriptor {
	uint8_t mpbd_density_code;
	uint8_t mpbd_nblocks[3];
	uint8_t _reserved1;
	uint8_t mpbd_block_length[3];
} spc3_mode_param_block_descriptor_t;

typedef struct spc3_mode_page_0 {
	DECL_BITFIELD3(
	    mp0_page_code	:6,
	    mp0_spf		:1,
	    mp0_ps		:1);
	uint8_t mp0_page_length;
	uint8_t mp0_mode_parameters[1];	/* Flexible */
} spc3_mode_page_0_t;

typedef struct spc3_mode_subpage {
	DECL_BITFIELD3(
	    ms_page_code	:6,
	    ms_spf		:1,
	    ms_ps		:1);
	uint8_t ms_subpage_code;
	uint16_t ms_page_length;
	uint8_t ms_mode_parameters[1];	/* Flexible */
} spc3_mode_subpage_t;

/*
 * SPC-3 7.4.6 Table 246 - TST field
 */
typedef enum spc3_mode_task_set {
	SPC3_MODE_TST_ONE = 0,
	SPC3_MODE_TST_SEPARATE = 1
} spc3_mode_task_set_t;

/*
 * SPC-3 7.4.6 Table 247 - Queue Algorithm Modifier field
 */
typedef enum spc3_mode_queue_alg_mod {
	SPC3_MODE_QAM_RESTRICTED = 0,
	SPC3_MODE_QAM_UNRESTRICTED = 1
} spc3_mode_queue_alg_mod_t;

/*
 * SPC-3 7.4.6 Table 245
 */
typedef struct spc3_mode_params_control {
	DECL_BITFIELD6(
	    mpc_rlec		:1,
	    mpc_gltsd		:1,
	    mpc_d_sense		:1,
	    _reserved1		:1,
	    mpc_tmf_only	:1,
	    mpc_tst		:3);
	DECL_BITFIELD4(
	    _reserved2		:1,
	    mpc_q_err		:1,
	    _reserved3		:1,
	    mpc_queue_alg_mod	:4);
	DECL_BITFIELD5(
	    _reserved4		:3,
	    mpc_swp		:1,
	    mpc_ua_intlck_ctrl	:2,
	    mpc_rac		:1,
	    mpc_vs_4_7		:1);
	DECL_BITFIELD4(
	    mpc_autoload_mode	:3,
	    _reserved5		:3,
	    mpc_tas		:1,
	    mpc_ato		:1);
	uint8_t _reserved6[2];
	uint16_t mpc_busy_timeout_period;
	uint16_t mpc_ext_selftest_completion_time;
} spc3_mode_page_params_control_t;

/*
 * SPC-3 7.4.7 Control Extension mode page
 */
typedef struct spc3_mode_params_control_ext {
	DECL_BITFIELD4(
	    mpce_ialuae	:1,
	    mpce_scsip	:1,
	    mpce_tcmos	:1,
	    _reserved1	:5);
	DECL_BITFIELD2(
	    mpce_initial_priority	:4,
	    _reserved2			:4);
	uint8_t _reserved3[26];
} spc3_mode_params_control_ext_t;

/*
 * SPC-3 7.4.8 Disconnect-Reconnect mode page
 */
typedef struct spc3_mode_params_dc_rc {
	uint8_t mpdr_buffer_full_ratio;
	uint8_t mpdr_buffer_empty_ratio;
	uint16_t mpdr_bus_inactivity_limit;
	uint16_t mpdr_disconnect_time_limit;
	uint16_t mpdr_connect_time_limit;
	uint16_t mpdr_max_burst_size;
	DECL_BITFIELD4(
	    mpdr_dtdc			:3,
	    mpdr_di_mm			:1,
	    mpdr_fair_arbitration	:3,
	    mpdr_emdp			:1);
	uint8_t _reserved1;
	uint16_t mpdr_first_burst_size;
} spc3_mode_params_dc_rc_t;

typedef enum spc3_mode_mrie {
	SPC3_MODE_MRIE_NONE = 0,
	SPC3_MODE_MRIE_ASYNC = 1,
	SPC3_MODE_MRIE_UNIT_ATTN = 2,
	SPC3_MODE_MRIE_COND_REC_ERR = 3,
	SPC3_MODE_MRIE_UNCOND_REC_ERR = 4,
	SPC3_MODE_MRIE_NO_SENSE = 5,
	SPC3_MODE_MRIE_REQUEST = 6
} spc3_mode_mrie_t;

/*
 * SPC-3 7.4.11 Informational Exceptions Control mode page
 */
typedef struct spc3_mode_params_iec {
	DECL_BITFIELD8(
	    mpi_log_err	:1,
	    _reserved1	:1,
	    mpi_test	:1,
	    mpi_d_excpt	:1,
	    mpi_e_wasc	:1,
	    mpi_ebf	:1,
	    _reserved2	:1,
	    mpi_perf	:1);
	DECL_BITFIELD2(
	    mpi_mrie	:4,
	    _reserved3	:4);
	uint32_t mpi_interval_timer;
	uint32_t mpi_report_count;
} spc3_mode_params_iec_t;

/*
 * SPC-3 7.4.12 Power Condition mode page
 */
typedef struct spc3_mode_params_pc {
	uint8_t _reserved1;
	DECL_BITFIELD3(
	    mpp_standby	:1,
	    mpp_idle	:1,
	    _reserved2	:6);
	uint32_t mpp_idle_condition_timer;
	uint32_t mpp_standby_condition_timer;
} spc3_mode_params_pc_t;

/*
 * SPC-3 6.7 MODE SELECT(6)
 */
typedef struct spc3_mode_select6_cdb {
	uint8_t msc_opcode;
	DECL_BITFIELD4(
	    msc_sp	:1,
	    _reserved1	:3,
	    msc_pf	:1,
	    _reserved2	:3);
	uint8_t _reserved3[2];
	uint8_t msc_parameter_list_length;
	spc3_control_t msc_control;
} spc3_mode_select6_cdb_t;

typedef spc3_mode_select6_cdb_t spc3_mode_select_cdb_t;

/*
 * SPC-3 6.8 MODE SELECT(10)
 */
typedef struct spc3_mode_select10_cdb {
	uint8_t msc_opcode;
	DECL_BITFIELD4(
	    msc_sp	:1,
	    _reserved1	:3,
	    msc_pf	:1,
	    _reserved2	:3);
	uint8_t _reserved3[5];
	uint16_t msc_parameter_list_length;
	spc3_control_t msc_control;
} spc3_mode_select10_cdb_t;

/*
 * SPC-3 6.9 MODE SENSE(6)
 */
typedef struct spc3_mode_sense6_cdb {
	uint8_t msc_opcode;
	DECL_BITFIELD3(
	    _reserved1	:3,
	    msc_dbd	:1,
	    _reserved2	:4);
	DECL_BITFIELD2(
	    msc_page_code	:6,
	    msc_pc		:2);
	uint8_t msc_subpage_code;
	uint8_t msc_allocation_length;
	spc3_control_t msc_control;
} spc3_mode_sense6_cdb_t;

typedef spc3_mode_sense6_cdb_t spc3_mode_sense_cdb_t;

/*
 * SPC-3 6.10 MODE SENSE(10)
 */
typedef struct spc3_mode_sense10_cdb {
	uint8_t msc_opcode;
	DECL_BITFIELD4(
	    _reserved1	:3,
	    msc_dbd	:1,
	    msc_llbaa	:1,
	    _reserved2	:3);
	DECL_BITFIELD2(
	    msc_page_code	:6,
	    msc_pc		:2);
	uint8_t msc_subpage_code;
	uint8_t _reserved3[3];
	uint16_t msc_allocation_length;
	spc3_control_t msc_control;
} spc3_mode_sense10_cdb_t;

/*
 * SPC-3 6.11 PERSISTENT RESERVE IN
 */
typedef enum spc3_persistent_reserve_in_sac {
	SPC3_PRI_SAC_READ_KEYS = 0,
	SPC3_PRI_SAC_READ_RESERVATION = 1,
	SPC3_PRI_SAC_REPORT_CAPABILITIES = 2,
	SPC3_PRI_SAC_READ_FULL_STATUS = 3
} spc3_persistent_reserve_in_sac_t;

typedef struct spc3_persistent_reserve_in_param_rk {
	uint32_t pripr_pr_generation;
	uint32_t pripr_additional_length;
	uint64_t pripr_keys[1];	/* Flexible */
} spc3_persistent_reserve_in_param_rk_t;

typedef enum spc3_persistent_reserve_type {
	SPC3_PR_TYPE_WREXCL = 1,
	SPC3_PR_TYPE_EXCL = 3,
	SPC3_PR_WREXCL_REG_ONLY = 5,
	SPC3_PR_EXCL_REG_ONLY = 6,
	SPC3_PR_WREXCL_ALL_REG = 7,
	SPC3_PR_EXCL_ALL_REG = 8
} spc3_persistent_reserve_type_t;

typedef struct spc3_persistent_reserve_in_param_rr {
	uint32_t pripr_pr_generation;
	uint32_t pripr_additional_length;
	uint64_t pripr_key;
	uint8_t _reserved1[4];
	uint8_t _reserved2;
	DECL_BITFIELD2(
	    pripr_type	:4,
	    pripr_scope	:4);
	uint8_t _reserved3[2];
} spc3_persistent_reserve_in_param_rr_t;

typedef struct spc3_persistent_reserve_in_param_rc {
	uint16_t pripr_length;
	DECL_BITFIELD6(
	    pripr_ptpl_c	:1,
	    _reserved1		:1,
	    pripr_atp_c		:1,
	    pripr_sip_c		:1,
	    pripr_crh		:1,
	    _reserved2		:3);
	DECL_BITFIELD3(
	    pripr_ptpl_a	:1,
	    _reserved3		:6,
	    pripr_tmv		:1);
	DECL_BITFIELD8(
	    _reserved4		:1,
	    pripr_wr_ex		:1,
	    _reserved5		:1,
	    pripr_ex_ac		:1,
	    _reserved6		:1,
	    pripr_wr_ex_ro	:1,
	    pripr_ex_ac_ro	:1,
	    pripr_wr_ex_ar	:1);
	DECL_BITFIELD2(
	    pripr_ex_ac_ar	:1,
	    _reserved7		:7);
	uint8_t _reserved8[2];
} spc3_persistent_reserve_in_param_rc_t;

typedef struct spc3_persistent_reserve_full_status {
	uint64_t prfs_key;
	uint8_t _reserved1[4];
	DECL_BITFIELD3(
	    prfs_r_holder	:1,
	    prfs_all_tg_pt	:1,
	    _reserved2		:6);
	DECL_BITFIELD2(
	    prfs_type		:4,
	    prfs_scope		:4);
	uint8_t _reserved3[4];
	uint16_t prfs_relative_target_port_identifier;
	uint32_t prfs_additional_descriptor_length;
	uint8_t prfs_transport_id[1];	/* Flexible */
} spc3_persistent_reserve_full_status_t;

typedef struct spc3_persistent_reserve_in_param_rfs {
	uint32_t pripr_pr_generation;
	uint32_t pripr_additional_length;
	uint8_t pripr_status_descriptors[1];	/* Flexible */
} spc3_persistent_reserve_in_param_rfs_t;

typedef struct spc3_persistent_reserve_in_cdb {
	uint8_t pric_opcode;
	DECL_BITFIELD2(
	    pric_service_action	:5,
	    _reserved1		:3);
	uint8_t _reserved2[5];
	uint16_t pric_allocation_length;
	spc3_control_t pric_control;
} spc3_persistent_reserve_in_cdb_t;

/*
 * SPC-3 6.16 READ MEDIA SERIAL NUMBER
 */
typedef struct spc3_read_media_serial_number_cdb {
	uint8_t rmsnc_opcode;
	DECL_BITFIELD2(
	    rmsnc_service_action	:5,
	    _reserved1			:3);
	uint8_t _reserved2[4];
	uint32_t rmsnc_allocation_length;
	uint8_t _reserved3;
	spc3_control_t rmsnc_control;
} spc3_read_media_serial_number_cdb_t;

typedef struct spc3_read_media_serial_number_data {
	uint32_t msnd_length;
	uint8_t msnd_serial_number[1];	/* Flexible */
} spc3_read_media_serial_number_data_t;

/*
 * SPC-3 6.18 RECEIVE DIAGNOSTIC RESULTS
 */
typedef struct spc3_receive_diagnostic_results_cdb {
	uint8_t rdrc_opcode;
	DECL_BITFIELD2(
	    rdrc_pcv	:1,
	    _reserved1	:7);
	uint8_t rdrc_page_code;
	uint16_t rdrc_allocation_length;
	spc3_control_t rdrc_control;
} spc3_receive_diagnostic_results_cdb_t;

/*
 * SPC-3 Diagnostic page format (Table 194, 7.1.1)
 */
typedef struct spc3_diag_page_impl {
	uint8_t sdpi_page_code;
	uint8_t sdpi_specific;
	uint16_t sdpi_page_length;
	uint8_t sdpi_data[1];
} spc3_diag_page_impl_t;

/*
 * SPC-3 Supported diagnostic pages (Table 196, 7.1.2)
 */
typedef struct spc3_supported_diag_page_impl {
	uint8_t ssdpi_page_code;
	uint8_t _reserved1;
	uint16_t ssdpi_page_length;
	uint8_t ssdpi_page_list[1];
} spc3_supported_diag_page_impl_t;

/*
 * SPC-3 6.21 REPORT LUNS
 */
typedef enum spc3_report_luns_select_report {
	SPC3_RL_SR_ADDRESSING = 0,
	SPC3_RL_SR_WELLKNOWN = 1,
	SPC3_RL_SR_ALL = 2
} spc3_report_luns_select_report_t;

typedef struct spc3_report_luns_cdb {
	uint8_t rlc_opcode;
	uint8_t _reserved1;
	uint8_t rlc_select_report;
	uint8_t _reserved2[3];
	uint32_t rlc_allocation_length;
	uint8_t _reserved3;
	spc3_control_t rlc_control;
} spc3_report_luns_cdb_t;

typedef struct spc3_report_luns_data {
	uint32_t rld_lun_list_length;
	uint8_t _reserved1[4];
	uint64_t rld_luns[1];	/* Flexible */
} spc3_report_luns_data_t;

/*
 * SPC-3 6.27 REQUEST SENSE
 */
typedef struct spc3_request_sense_cdb {
	uint8_t rsc_opcode;
	DECL_BITFIELD2(
	    rsc_desc	:1,
	    _reserved1	:7);
	uint8_t _reserved2[2];
	uint8_t rsc_allocation_length;
	spc3_control_t rsc_control;
} spc3_request_sense_cdb_t;

/*
 * SPC-3 6.28 SEND DIAGNOSTIC
 */
typedef struct spc3_send_diagnostic_cdb {
	uint8_t sdc_opcode;
	DECL_BITFIELD6(
	    sdc_unit_off_l	:1,
	    sdc_dev_off_l	:1,
	    sdc_self_test	:1,
	    _reserved1		:1,
	    sdc_pf		:1,
	    sdc_selftest_code	:3);
	uint8_t _reserved2;
	uint16_t sdc_parameter_list_length;
	spc3_control_t sdc_control;
} spc3_send_diagnostic_cdb_t;

/*
 * SPC-3 6.33 TEST UNIT READY
 */
typedef struct spc3_test_unit_ready_cdb {
	uint8_t tur_opcode;
	uint8_t _reserved1[4];
	spc3_control_t tur_control;
} spc3_test_unit_ready_cdb_t;

/*
 * SPC-3 6.36 WRITE BUFFER
 */
typedef struct spc3_write_buffer_cdb {
	uint8_t wbc_opcode;
	DECL_BITFIELD2(
	    wbc_mode		:5,
	    _reserved		:3);
	uint8_t wbc_bufferid;
	uint8_t wbc_buffer_offset[3];
	uint8_t wbc_parameter_list_len[3];
	spc3_control_t wbc_control;
} spc3_write_buffer_cdb_t;

typedef enum spc3_write_buffer_mode {
	SPC3_WB_MODE_COMB_HDR_DATA = 0x00,
	SPC3_WB_MODE_VENDOR_SPECIFIC = 0x01,
	SPC3_WB_MODE_DATA = 0x02,
	SPC3_WB_MODE_DL_UCODE = 0x04,
	SPC3_WB_MODE_DL_UCODE_SAVE = 0x05,
	SPC3_WB_MODE_DL_UCODE_OFFS = 0x06,
	SPC3_WB_MODE_DL_UCODE_OFFS_SAVE = 0x07,
	SPC3_WB_MODE_ECHO_BUF = 0x0a,
	SPC3_WB_MODE_DL_UCODE_OFFS_DEFER = 0x0e,
	SPC3_WB_MODE_ACTIVATE_DEFERRED_UCODE = 0x0f,
	SPC3_WB_MODE_ENABLE_EXPANDER_ECHO_BUF = 0x1a,
	SPC3_WB_MODE_DISABLE_EXPANDER = 0x1b,
	SPC3_WB_MODE_DL_APP_LOG = 0x1c
} spc3_write_buffer_mode_t;

typedef struct spc3_write_buffer_log {
	uint8_t wbl_vendor[8];
	uint16_t wbl_error_type;
	uint16_t _reserved1;
	uint8_t wbl_timestamp[6];
	uint16_t _reserved2;
	DECL_BITFIELD2(
	    _reserved3		:4,
	    wbl_codeset		:4);
	uint8_t wbl_error_location_fmt;
	uint16_t wbl_error_location_len;
	uint16_t wbl_client_error_history_len;
	uint32_t wbl_data[1];
} spc3_write_buffer_log_t;

typedef enum sp3_write_buffer_error_type {
	SPC3_WB_ERROR_NONE = 0x0000,
	SPC3_WB_ERROR_UNKNOWN = 0x0001,
	SPC3_WB_ERROR_DATA_CORRUPT = 0x0002,
	SPC3_WB_ERROR_PERMANENT = 0x0003,
	SPC3_WB_ERROR_SERVICETARGET_FAILURE = 0x0004
} spc3_write_buffer_error_type_t;

typedef enum spc3_write_buffer_codeset {
	SPC3_WB_CODESET_RESERVED = 0x00,
	SPC3_WB_CODESET_BIN = 0x01,
	SPC3_WB_CODESET_ASCII = 0x02,
	SPC3_WB_CODESET_UTF8 = 0x03
} spc3_write_buffer_codeset_t;

typedef enum spc_3_write_buffer_error_location {
	SPC3_WB_ERROR_LOCATION_FMT_NONE = 0x00,
	SPC3_WB_ERROR_LOCATION_FMT_LBA = 0x01
} spc3_write_buffer_error_location_t;

/*
 * SPC-4 7.5.1 Protocol values
 */
typedef enum spc4_protocol_id {
	SPC4_PROTO_FIBRE_CHANNEL = 0,
	SPC4_PROTO_PARALLEL_SCSI = 1,
	SPC4_PROTO_SSA = 2,
	SPC4_PROTO_IEEE1394 = 3,
	SPC4_PROTO_RDMA = 4,
	SPC4_PROTO_ISCSI = 5,
	SPC4_PROTO_SAS = 6,
	SPC4_PROTO_ADT = 7,
	SPC4_PROTO_ATA = 8,
	SPC4_PROTO_NONE = 0xf
} spc4_protocol_id_t;

/*
 * SPC-3 NAA identifier format (Table 305, 7.6.3.6.1)
 */
typedef struct spc3_naa_id_impl {
	DECL_BITFIELD2(
	    snii_priv_msn	:4,
	    snii_naa	:4);
	uint8_t snii_priv[1];
} spc3_naa_id_impl_t;

/*
 * SPC-3 NAA IEEE Extended Identifier field format (Table 307, 7.6.3.6.2)
 */
typedef struct spc3_naa_ieee_ext_id_impl {
	DECL_BITFIELD2(
	    snieii_vendor_id_a_msn	:4,
	    snieii_naa			:4);
	uint8_t snieii_vendor_id_a_lsb;
	uint8_t snieii_company_id[3];
	uint8_t snieii_vendor_id_b[3];
} spc3_naa_ieee_ext_id_impl_t;

#define	NAA_IEEE_EXT_VENDOR_A(idp)	\
	SCSI_MK12_4_8((idp)->snieii_vendor_id_a_msn,	\
	    (idp)->snieii_vendor_id_a_lsb)
#define	NAA_IEEE_EXT_COMPANY_ID(idp)	SCSI_READ24((idp)->snieii_company_id)
#define	NAA_IEEE_EXT_VENDOR_B(idp)	SCSI_READ24((idp)->snieii_vendor_id_b)

/*
 * Ibid, Table 308
 */
typedef struct spc3_naa_ieee_reg_id_impl {
	DECL_BITFIELD2(
	    snirii_company_id_msn	:4,
	    snirii_naa			:4);
	uint16_t snirii_company_id_mid;
	DECL_BITFIELD2(
	    snirii_vendor_id_msn	:4,
	    snirii_company_id_lsn	:4);
	uint32_t snirii_vendor_id_low;
} spc3_naa_ieee_reg_id_impl_t;

#define	NAA_IEEE_REG_COMPANY_ID(idp)	\
	SCSI_MK24_4_16_4((idp)->snirii_company_id_msn,	\
	    SCSI_READ16(&(idp)->snirii_company_id_mid),	\
	    (idp)->snirii_company_id_lsn)
#define	NAA_IEEE_REG_VENDOR_ID(idp)	\
	SCSI_MK36_4_32((idp)->snirii_vendor_id_msn,	\
	    SCSI_READ32(&(idp)->snirii_vendor_id_low))

/*
 * Ibid, Table 309
 */
typedef struct spc3_naa_ieee_reg_ext_id_impl {
	DECL_BITFIELD2(
	    snireii_company_id_msn	:4,
	    snireii_naa		:4);
	uint16_t snireii_company_id_mid;
	DECL_BITFIELD2(
	    snireii_vendor_id_msn	:4,
	    snireii_company_id_lsn	:4);
	uint32_t snireii_vendor_id_low;
	uint64_t snireii_vendor_id_ext;
} spc3_naa_ieee_reg_ext_id_impl_t;

#define	NAA_IEEE_REG_EXT_COMPANY_ID(idp)	\
	SCSI_MK20_4_16_4((idp)->snireii_company_id_msn,	\
	    SCSI_READ16(&(idp)->snireii_company_id_mid),	\
	    (idp)->snireii_company_id_lsn)
#define	NAA_IEEE_REG_EXT_VENDOR_ID(idp)	\
	SCSI_MK36_4_32((idp)->snireii_vendor_id_msn,	\
	    SCSI_READ32(&(idp)->snireii_vendor_id_low))

typedef union spc3_naa_id_8_impl {
	struct {
		DECL_BITFIELD2(
		    _reserved1	:4,
		    sni8i_naa	:4);
	} sni8i_hdr;
	spc3_naa_ieee_ext_id_impl_t sni8i_ext_id;
	spc3_naa_ieee_reg_id_impl_t sni8i_reg_id;
} spc3_naa_id_8_impl_t;

#define	sni8i_naa	sni8i_hdr.sni8i_naa

typedef enum naa_id {
	NAA_IEEE_EXT = 0x2,
	NAA_LOCAL = 0x3,
	NAA_IEEE_REG = 0x5,
	NAA_IEEE_REG_EXT = 0x6
} naa_id_t;

#pragma pack()

#ifdef	__cplusplus
}
#endif

#endif	/* _SPC3_TYPES_H */
