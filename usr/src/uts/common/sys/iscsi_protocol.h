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
 * Copyright (c) 2008, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _ISCSI_PROTOCOL_H
#define	_ISCSI_PROTOCOL_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * iSCSI connection daemon
 * Copyright (C) 2001 Cisco Systems, Inc.
 * All rights reserved.
 *
 * This file sets up definitions of messages and constants used by the
 * iSCSI protocol.
 *
 */

#include <sys/types.h>
#include <sys/isa_defs.h>

#define	ISCSI_MAX_NAME_LEN	224
#define	ISCSI_MAX_C_USER_LEN	512

/* iSCSI listen port for incoming connections */
#define	ISCSI_LISTEN_PORT 3260

/* assumes a pointer to a 3-byte array */
#define	ntoh24(p) (((p)[0] << 16) | ((p)[1] << 8) | ((p)[2]))

/* assumes a pointer to a 3 byte array, and an integer value */
#define	hton24(p, v) {\
	p[0] = (((v) >> 16) & 0xFF); \
	p[1] = (((v) >> 8) & 0xFF); \
	p[2] = ((v) & 0xFF); \
}


/* for Login min, max, active version fields */
#define	ISCSI_MIN_VERSION	0x00
#define	ISCSI_DRAFT8_VERSION    0x02
#define	ISCSI_DRAFT20_VERSION   0x00
#define	ISCSI_MAX_VERSION	0x02

/* Min. and Max. length of a PDU we can support */
#define	ISCSI_MIN_PDU_LENGTH	(8 << 9)	/* 4KB */
#define	ISCSI_MAX_PDU_LENGTH	(0xffffffff)	/* Huge */

/* Padding word length */
#define	ISCSI_PAD_WORD_LEN		4

/* Max. number of Key=Value pairs in a text message */
#define	ISCSI_MAX_KEY_VALUE_PAIRS	8192

/* text separtor between key value pairs exhanged in login */
#define	ISCSI_TEXT_SEPARATOR	'='

/* reserved text constants for Text Mode Negotiation */
#define	ISCSI_TEXT_NONE			"None"
#define	ISCSI_TEXT_REJECT		"Reject"
#define	ISCSI_TEXT_IRRELEVANT		"Irrelevant"
#define	ISCSI_TEXT_NOTUNDERSTOOD	"NotUnderstood"

/* Reserved value for initiator/target task tag */
#define	ISCSI_RSVD_TASK_TAG	0xffffffff

/* maximum length for text keys/values */
#define	KEY_MAXLEN 64
#define	VALUE_MAXLEN 255
#define	TARGET_NAME_MAXLEN    VALUE_MAXLEN

/* most PDU types have a final bit */
#define	ISCSI_FLAG_FINAL		0x80

/*
 * Strings used during SendTargets requests
 */
#define	ISCSI_TEXT_SEPARATOR	'='
#define	TARGETNAME "TargetName="
#define	TARGETADDRESS "TargetAddress="

/* iSCSI Template Message Header */
typedef struct _iscsi_hdr {
	uint8_t opcode;
	uint8_t flags;	/* Final bit */
	uint8_t rsvd2[2];
	uint8_t hlength;	/* AHSs total length */
	uint8_t dlength[3];	/* Data length */
	uint8_t lun[8];
	uint32_t itt;	/* Initiator Task Tag */
	uint8_t		rsvd3[8];
	uint32_t	expstatsn;
	uint8_t		other[16];
} iscsi_hdr_t;

typedef struct _iscsi_rsp_hdr {
	uint8_t		opcode;
	uint8_t		flags;
	uint8_t		rsvd1[3];
	uint8_t		dlength[3];
	uint8_t		rsvd2[8];
	uint32_t	itt;
	uint8_t		rsvd3[4];
	uint32_t	statsn;
	uint32_t	expcmdsn;
	uint32_t	maxcmdsn;
	uint8_t		rsvd4[12];
} iscsi_rsp_hdr_t;

/* Opcode encoding bits */
#define	ISCSI_OP_RETRY			0x80
#define	ISCSI_OP_IMMEDIATE		0x40
#define	ISCSI_OPCODE_MASK		0x3F

/* Client to Server Message Opcode values */
#define	ISCSI_OP_NOOP_OUT		0x00
#define	ISCSI_OP_SCSI_CMD		0x01
#define	ISCSI_OP_SCSI_TASK_MGT_MSG	0x02
#define	ISCSI_OP_LOGIN_CMD		0x03
#define	ISCSI_OP_TEXT_CMD		0x04
#define	ISCSI_OP_SCSI_DATA		0x05
#define	ISCSI_OP_LOGOUT_CMD		0x06
#define	ISCSI_OP_SNACK_CMD		0x10

/* Server to Client Message Opcode values */
#define	ISCSI_OP_NOOP_IN		0x20
#define	ISCSI_OP_SCSI_RSP		0x21
#define	ISCSI_OP_SCSI_TASK_MGT_RSP	0x22
#define	ISCSI_OP_LOGIN_RSP		0x23
#define	ISCSI_OP_TEXT_RSP		0x24
#define	ISCSI_OP_SCSI_DATA_RSP		0x25
#define	ISCSI_OP_LOGOUT_RSP		0x26
#define	ISCSI_OP_RTT_RSP		0x31
#define	ISCSI_OP_ASYNC_EVENT		0x32
#define	ISCSI_OP_REJECT_MSG		0x3f


/* SCSI Command Header */
typedef struct _iscsi_scsi_cmd_hdr {
	uint8_t opcode;
	uint8_t flags;
	uint8_t rsvd[2];
	uint8_t hlength;
	uint8_t dlength[3];
	uint8_t lun[8];
	uint32_t itt;	/* Initiator Task Tag */
	uint32_t data_length;
	uint32_t cmdsn;
	uint32_t expstatsn;
	uint8_t scb[16];	/* SCSI Command Block */
	/*
	 * Additional Data (Command Dependent)
	 */
} iscsi_scsi_cmd_hdr_t;

/* Command PDU flags */
#define	ISCSI_FLAG_CMD_READ		0x40
#define	ISCSI_FLAG_CMD_WRITE		0x20
#define	ISCSI_FLAG_CMD_ATTR_MASK	0x07	/* 3 bits */

/* SCSI Command Attribute values */
#define	ISCSI_ATTR_UNTAGGED		0
#define	ISCSI_ATTR_SIMPLE		1
#define	ISCSI_ATTR_ORDERED		2
#define	ISCSI_ATTR_HEAD_OF_QUEUE	3
#define	ISCSI_ATTR_ACA			4


/* SCSI Response Header */
typedef struct _iscsi_scsi_rsp_hdr {
	uint8_t opcode;
	uint8_t flags;
	uint8_t response;
	uint8_t cmd_status;
	uint8_t hlength;
	uint8_t dlength[3];
	uint8_t rsvd[8];
	uint32_t itt;	/* Initiator Task Tag */
	uint32_t rsvd1;
	uint32_t statsn;
	uint32_t expcmdsn;
	uint32_t maxcmdsn;
	uint32_t expdatasn;
	uint32_t bi_residual_count;
	uint32_t residual_count;
	/*
	 * Response or Sense Data (optional)
	 */
} iscsi_scsi_rsp_hdr_t;

/* 10.2.2.3 - Extended CDB Additional Header Segment */

typedef struct _iscsi_addl_hdr {
	iscsi_scsi_cmd_hdr_t ahs_isch;
	uint8_t ahs_hlen_hi;
	uint8_t ahs_hlen_lo;
	uint8_t ahs_key;
	uint8_t ahs_resv;
	uint8_t ahs_extscb[4];
} iscsi_addl_hdr_t;

/* Command Response PDU flags */
#define	ISCSI_FLAG_CMD_BIDI_OVERFLOW	0x10
#define	ISCSI_FLAG_CMD_BIDI_UNDERFLOW	0x08
#define	ISCSI_FLAG_CMD_OVERFLOW		0x04
#define	ISCSI_FLAG_CMD_UNDERFLOW	0x02

/* iSCSI Status values. Valid if Rsp Selector bit is not set */
#define	ISCSI_STATUS_CMD_COMPLETED	0
#define	ISCSI_STATUS_TARGET_FAILURE	1
#define	ISCSI_STATUS_SUBSYS_FAILURE	2


/* Asynchronous Event Header */
typedef struct _iscsi_async_evt_hdr {
	uint8_t opcode;
	uint8_t flags;
	uint8_t rsvd2[2];
	uint8_t rsvd3;
	uint8_t dlength[3];
	uint8_t lun[8];
	uint8_t rsvd4[8];
	uint32_t statsn;
	uint32_t expcmdsn;
	uint32_t maxcmdsn;
	uint8_t async_event;
	uint8_t async_vcode;
	uint16_t param1;
	uint16_t param2;
	uint16_t param3;
	uint8_t rsvd5[4];
} iscsi_async_evt_hdr_t;

/* iSCSI Event Indicator values */
#define	ISCSI_ASYNC_EVENT_SCSI_EVENT			0
#define	ISCSI_ASYNC_EVENT_REQUEST_LOGOUT		1
#define	ISCSI_ASYNC_EVENT_DROPPING_CONNECTION		2
#define	ISCSI_ASYNC_EVENT_DROPPING_ALL_CONNECTIONS	3
#define	ISCSI_ASYNC_EVENT_PARAM_NEGOTIATION		4
#define	ISCSI_ASYNC_EVENT_VENDOR_SPECIFIC		255


/* NOP-Out Message */
typedef struct _iscsi_nop_out_hdr {
	uint8_t opcode;
	uint8_t flags;
	uint16_t rsvd2;
	uint8_t rsvd3;
	uint8_t dlength[3];
	uint8_t lun[8];
	uint32_t itt;	/* Initiator Task Tag */
	uint32_t ttt;	/* Target Transfer Tag */
	uint32_t cmdsn;
	uint32_t expstatsn;
	uint8_t rsvd4[16];
} iscsi_nop_out_hdr_t;


/* NOP-In Message */
typedef struct _iscsi_nop_in_hdr {
	uint8_t opcode;
	uint8_t flags;
	uint16_t rsvd2;
	uint8_t rsvd3;
	uint8_t dlength[3];
	uint8_t lun[8];
	uint32_t itt;	/* Initiator Task Tag */
	uint32_t ttt;	/* Target Transfer Tag */
	uint32_t statsn;
	uint32_t expcmdsn;
	uint32_t maxcmdsn;
	uint8_t rsvd4[12];
} iscsi_nop_in_hdr_t;

/* SCSI Task Management Message Header */
typedef struct _iscsi_scsi_task_mgt_hdr {
	uint8_t opcode;
	uint8_t function;
	uint8_t rsvd1[2];
	uint8_t hlength;
	uint8_t dlength[3];
	uint8_t lun[8];
	uint32_t itt;	/* Initiator Task Tag */
	uint32_t rtt;	/* Reference Task Tag */
	uint32_t cmdsn;
	uint32_t expstatsn;
	uint32_t refcmdsn;
	uint32_t expdatasn;
	uint8_t rsvd2[8];
} iscsi_scsi_task_mgt_hdr_t;

#define	ISCSI_FLAG_TASK_MGMT_FUNCTION_MASK  0x7F

/* Function values */
#define	ISCSI_TM_FUNC_ABORT_TASK		1
#define	ISCSI_TM_FUNC_ABORT_TASK_SET		2
#define	ISCSI_TM_FUNC_CLEAR_ACA			3
#define	ISCSI_TM_FUNC_CLEAR_TASK_SET		4
#define	ISCSI_TM_FUNC_LOGICAL_UNIT_RESET	5
#define	ISCSI_TM_FUNC_TARGET_WARM_RESET		6
#define	ISCSI_TM_FUNC_TARGET_COLD_RESET		7
#define	ISCSI_TM_FUNC_TASK_REASSIGN		8


/* SCSI Task Management Response Header */
typedef struct _iscsi_scsi_task_mgt_rsp_hdr {
	uint8_t opcode;
	uint8_t flags;
	uint8_t response;	/* see Response values below */
	uint8_t qualifier;
	uint8_t hlength;
	uint8_t dlength[3];
	uint8_t rsvd2[8];
	uint32_t itt;	/* Initiator Task Tag */
	uint32_t rtt;	/* Reference Task Tag */
	uint32_t statsn;
	uint32_t expcmdsn;
	uint32_t maxcmdsn;
	uint8_t rsvd3[12];
} iscsi_scsi_task_mgt_rsp_hdr_t;


/* Response values */
#define	SCSI_TCP_TM_RESP_COMPLETE	0x00
#define	SCSI_TCP_TM_RESP_NO_TASK	0x01
#define	SCSI_TCP_TM_RESP_NO_LUN		0x02
#define	SCSI_TCP_TM_RESP_TASK_ALLEGIANT	0x03
#define	SCSI_TCP_TM_RESP_NO_ALLG_REASSN	0x04
#define	SCSI_TCP_TM_RESP_FUNC_NOT_SUPP	0x05
#define	SCSI_TCP_TM_RESP_FUNC_AUTH_FAIL	0x06
#define	SCSI_TCP_TM_RESP_REJECTED	0xff

/*
 * Maintained for backward compatibility.
 */

#define	SCSI_TCP_TM_RESP_NO_FAILOVER	SCSI_TCP_TM_RESP_NO_ALLG_REASSN
#define	SCSI_TCP_TM_RESP_IN_PRGRESS	SCSI_TCP_TM_RESP_FUNC_NOT_SUPP

/* Ready To Transfer Header */
typedef struct _iscsi_rtt_hdr {
	uint8_t opcode;
	uint8_t flags;
	uint8_t rsvd2[2];
	uint8_t rsvd3[12];
	uint32_t itt;	/* Initiator Task Tag */
	uint32_t ttt;	/* Target Transfer Tag */
	uint32_t statsn;
	uint32_t expcmdsn;
	uint32_t maxcmdsn;
	uint32_t rttsn;
	uint32_t data_offset;
	uint32_t data_length;
} iscsi_rtt_hdr_t;


/* SCSI Data Hdr */
typedef struct _iscsi_data_hdr {
	uint8_t opcode;
	uint8_t flags;
	uint8_t rsvd2[2];
	uint8_t rsvd3;
	uint8_t dlength[3];
	uint8_t lun[8];
	uint32_t itt;
	uint32_t ttt;
	uint32_t rsvd4;
	uint32_t expstatsn;
	uint32_t rsvd5;
	uint32_t datasn;
	uint32_t offset;
	uint32_t rsvd6;
	/*
	 * Payload
	 */
} iscsi_data_hdr_t;

/* SCSI Data Response Hdr */
typedef struct _iscsi_data_rsp_hdr {
	uint8_t opcode;
	uint8_t flags;
	uint8_t rsvd2;
	uint8_t cmd_status;
	uint8_t hlength;
	uint8_t dlength[3];
	uint8_t lun[8];
	uint32_t itt;
	uint32_t ttt;
	uint32_t statsn;
	uint32_t expcmdsn;
	uint32_t maxcmdsn;
	uint32_t datasn;
	uint32_t offset;
	uint32_t residual_count;
} iscsi_data_rsp_hdr_t;

/* Data Response PDU flags */
#define	ISCSI_FLAG_DATA_ACK		0x40
#define	ISCSI_FLAG_DATA_OVERFLOW	0x04
#define	ISCSI_FLAG_DATA_UNDERFLOW	0x02
#define	ISCSI_FLAG_DATA_STATUS		0x01


/* Text Header */
typedef struct _iscsi_text_hdr {
	uint8_t opcode;
	uint8_t flags;
	uint8_t rsvd2[2];
	uint8_t hlength;
	uint8_t dlength[3];
	uint8_t rsvd4[8];
	uint32_t itt;
	uint32_t ttt;
	uint32_t cmdsn;
	uint32_t expstatsn;
	uint8_t rsvd5[16];
	/*
	 * Text - key=value pairs
	 */
} iscsi_text_hdr_t;

#define	ISCSI_FLAG_TEXT_CONTINUE	0x40

/* Text Response Header */
typedef struct _iscsi_text_rsp_hdr {
	uint8_t opcode;
	uint8_t flags;
	uint8_t rsvd2[2];
	uint8_t hlength;
	uint8_t dlength[3];
	uint8_t rsvd4[8];
	uint32_t itt;
	uint32_t ttt;
	uint32_t statsn;
	uint32_t expcmdsn;
	uint32_t maxcmdsn;
	uint8_t rsvd5[12];
	/*
	 * Text Response - key:value pairs
	 */
} iscsi_text_rsp_hdr_t;

#define	ISCSI_ISID_LEN	6

/* Login Header */
typedef struct _iscsi_login_hdr {
	uint8_t opcode;
	uint8_t flags;
	uint8_t max_version;	/* Max. version supported */
	uint8_t min_version;	/* Min. version supported */
	uint8_t hlength;
	uint8_t dlength[3];
	uint8_t isid[ISCSI_ISID_LEN];	/* Initiator Session ID */
	uint16_t tsid;	/* Target Session ID */
	uint32_t itt;	/* Initiator Task Tag */
	uint16_t cid;
	uint16_t rsvd3;
	uint32_t cmdsn;
	uint32_t expstatsn;
	uint8_t rsvd5[16];
} iscsi_login_hdr_t;

/* Login PDU flags */
#define	ISCSI_FLAG_LOGIN_TRANSIT		0x80
#define	ISCSI_FLAG_LOGIN_CONTINUE		0x40
#define	ISCSI_FLAG_LOGIN_CURRENT_STAGE_MASK	0x0C	/* 2 bits */
#define	ISCSI_FLAG_LOGIN_NEXT_STAGE_MASK	0x03	/* 2 bits */

#define	ISCSI_LOGIN_CURRENT_STAGE(flags) \
	((flags & ISCSI_FLAG_LOGIN_CURRENT_STAGE_MASK) >> 2)
#define	ISCSI_LOGIN_NEXT_STAGE(flags) \
	(flags & ISCSI_FLAG_LOGIN_NEXT_STAGE_MASK)


/* Login Response Header */
typedef struct _iscsi_login_rsp_hdr {
	uint8_t opcode;
	uint8_t flags;
	uint8_t max_version;	/* Max. version supported */
	uint8_t active_version;	/* Active version */
	uint8_t hlength;
	uint8_t dlength[3];
	uint8_t isid[ISCSI_ISID_LEN];	/* Initiator Session ID */
	uint16_t tsid;	/* Target Session ID */
	uint32_t itt;	/* Initiator Task Tag */
	uint32_t rsvd3;
	uint32_t statsn;
	uint32_t expcmdsn;
	uint32_t maxcmdsn;
	uint8_t status_class;	/* see Login RSP ststus classes below */
	uint8_t status_detail;	/* see Login RSP Status details below */
	uint8_t rsvd4[10];
} iscsi_login_rsp_hdr_t;

/* Login stage (phase) codes for CSG, NSG */
#define	ISCSI_SECURITY_NEGOTIATION_STAGE	0
#define	ISCSI_OP_PARMS_NEGOTIATION_STAGE	1
#define	ISCSI_FULL_FEATURE_PHASE		3

/* Login Status response classes */
#define	ISCSI_STATUS_CLASS_SUCCESS		0x00
#define	ISCSI_STATUS_CLASS_REDIRECT		0x01
#define	ISCSI_STATUS_CLASS_INITIATOR_ERR	0x02
#define	ISCSI_STATUS_CLASS_TARGET_ERR		0x03

/* Login Status response detail codes */
/* Class-0 (Success) */
#define	ISCSI_LOGIN_STATUS_ACCEPT		0x00

/* Class-1 (Redirection) */
#define	ISCSI_LOGIN_STATUS_TGT_MOVED_TEMP	0x01
#define	ISCSI_LOGIN_STATUS_TGT_MOVED_PERM	0x02

/* Class-2 (Initiator Error) */
#define	ISCSI_LOGIN_STATUS_INIT_ERR		0x00
#define	ISCSI_LOGIN_STATUS_AUTH_FAILED		0x01
#define	ISCSI_LOGIN_STATUS_TGT_FORBIDDEN	0x02
#define	ISCSI_LOGIN_STATUS_TGT_NOT_FOUND	0x03
#define	ISCSI_LOGIN_STATUS_TGT_REMOVED		0x04
#define	ISCSI_LOGIN_STATUS_NO_VERSION		0x05
#define	ISCSI_LOGIN_STATUS_ISID_ERROR		0x06
#define	ISCSI_LOGIN_STATUS_MISSING_FIELDS	0x07
#define	ISCSI_LOGIN_STATUS_CONN_ADD_FAILED	0x08
#define	ISCSI_LOGIN_STATUS_NO_SESSION_TYPE	0x09
#define	ISCSI_LOGIN_STATUS_NO_SESSION		0x0a
#define	ISCSI_LOGIN_STATUS_INVALID_REQUEST	0x0b

/* Class-3 (Target Error) */
#define	ISCSI_LOGIN_STATUS_TARGET_ERROR		0x00
#define	ISCSI_LOGIN_STATUS_SVC_UNAVAILABLE	0x01
#define	ISCSI_LOGIN_STATUS_NO_RESOURCES		0x02

/* Logout Header */
typedef struct _iscsi_logout_hdr {
	uint8_t opcode;
	uint8_t flags;
	uint8_t rsvd1[2];
	uint8_t hlength;
	uint8_t dlength[3];
	uint8_t rsvd2[8];
	uint32_t itt;	/* Initiator Task Tag */
	uint16_t cid;
	uint8_t rsvd3[2];
	uint32_t cmdsn;
	uint32_t expstatsn;
	uint8_t rsvd4[16];
} iscsi_logout_hdr_t;

/* Logout PDU flags */
#define	ISCSI_FLAG_LOGOUT_REASON_MASK		0x7F

/* logout reason_code values */

#define	ISCSI_LOGOUT_REASON_CLOSE_SESSION	0
#define	ISCSI_LOGOUT_REASON_CLOSE_CONNECTION	1
#define	ISCSI_LOGOUT_REASON_RECOVERY		2
#define	ISCSI_LOGOUT_REASON_AEN_REQUEST		3

/* Logout Response Header */
typedef struct _iscsi_logout_rsp_hdr {
	uint8_t opcode;
	uint8_t flags;
	uint8_t response;	/* see Logout response values below */
	uint8_t rsvd2;
	uint8_t hlength;
	uint8_t dlength[3];
	uint8_t rsvd3[8];
	uint32_t itt;	/* Initiator Task Tag */
	uint32_t rsvd4;
	uint32_t statsn;
	uint32_t expcmdsn;
	uint32_t maxcmdsn;
	uint32_t rsvd5;
	uint16_t t2wait;
	uint16_t t2retain;
	uint32_t rsvd6;
} iscsi_logout_rsp_hdr_t;

/* logout response status values */

#define	ISCSI_LOGOUT_SUCCESS		  0
#define	ISCSI_LOGOUT_CID_NOT_FOUND	  1
#define	ISCSI_LOGOUT_RECOVERY_UNSUPPORTED 2
#define	ISCSI_LOGOUT_CLEANUP_FAILED	  3


/* SNACK Header */
typedef struct _iscsi_snack_hdr {
	uint8_t opcode;
	uint8_t flags;
	uint8_t rsvd2[14];
	uint32_t itt;
	uint32_t begrun;
	uint32_t runlength;
	uint32_t expstatsn;
	uint32_t rsvd3;
	uint32_t expdatasn;
	uint8_t rsvd6[8];
} iscsi_snack_hdr_t;

/* SNACK PDU flags */
#define	ISCSI_FLAG_SNACK_TYPE_MASK	0x0F	/* 4 bits */

/* Reject Message Header */
typedef struct _iscsi_reject_rsp_hdr {
	uint8_t opcode;
	uint8_t flags;
	uint8_t reason;
	uint8_t rsvd2;
	uint8_t rsvd3;
	uint8_t dlength[3];
	uint8_t rsvd4[8];
	uint8_t	must_be_ff[4];
	uint8_t	rsvd4a[4];
	uint32_t statsn;
	uint32_t expcmdsn;
	uint32_t maxcmdsn;
	uint32_t datasn;
	uint8_t rsvd5[8];
	/*
	 * Text - Rejected hdr
	 */
} iscsi_reject_rsp_hdr_t;

/* Reason for Reject */
#define	ISCSI_REJECT_CMD_BEFORE_LOGIN		1
#define	ISCSI_REJECT_DATA_DIGEST_ERROR		2
#define	ISCSI_REJECT_SNACK_REJECT		3
#define	ISCSI_REJECT_PROTOCOL_ERROR		4
#define	ISCSI_REJECT_CMD_NOT_SUPPORTED		5
#define	ISCSI_REJECT_IMM_CMD_REJECT		6
#define	ISCSI_REJECT_TASK_IN_PROGRESS		7
#define	ISCSI_REJECT_INVALID_DATA_ACK		8
#define	ISCSI_REJECT_INVALID_PDU_FIELD		9
#define	ISCSI_REJECT_LONG_OPERATION_REJECT	10
#define	ISCSI_REJECT_NEGOTIATION_RESET		11
#define	ISCSI_REJECT_WAITING_FOR_LOGOUT		12

/* Defaults as defined by the iSCSI specification */
#define	ISCSI_DEFAULT_IMMEDIATE_DATA		TRUE
#define	ISCSI_DEFAULT_INITIALR2T		TRUE
#define	ISCSI_DEFAULT_FIRST_BURST_LENGTH	(64 * 1024) /* 64kbytes */
#define	ISCSI_DEFAULT_MAX_BURST_LENGTH		(256 * 1024) /* 256kbytes */
#define	ISCSI_DEFAULT_DATA_PDU_IN_ORDER		TRUE
#define	ISCSI_DEFAULT_DATA_SEQUENCE_IN_ORDER	TRUE
#define	ISCSI_DEFAULT_TIME_TO_WAIT		2 /* 2 seconds */
#define	ISCSI_DEFAULT_TIME_TO_RETAIN		20 /* 20 seconds */
#define	ISCSI_DEFAULT_HEADER_DIGEST		ISCSI_DIGEST_NONE
#define	ISCSI_DEFAULT_DATA_DIGEST		ISCSI_DIGEST_NONE
#define	ISCSI_DEFAULT_MAX_RECV_SEG_LEN		(8 * 1024)
#define	ISCSI_DEFAULT_MAX_XMIT_SEG_LEN		(8 * 1024)
#define	ISCSI_DEFAULT_MAX_CONNECTIONS		1
#define	ISCSI_DEFAULT_MAX_OUT_R2T		1
#define	ISCSI_DEFAULT_ERROR_RECOVERY_LEVEL	0
#define	ISCSI_DEFAULT_IFMARKER			FALSE
#define	ISCSI_DEFAULT_OFMARKER			FALSE

/*
 * Minimum values from the iSCSI specification
 */

#define	ISCSI_MIN_TIME2RETAIN			0
#define	ISCSI_MIN_TIME2WAIT			0
#define	ISCSI_MIN_ERROR_RECOVERY_LEVEL		0
#define	ISCSI_MIN_RECV_DATA_SEGMENT_LENGTH	0x200
#define	ISCSI_MIN_FIRST_BURST_LENGTH		0x200
#define	ISCSI_MIN_MAX_BURST_LENGTH		0x200
#define	ISCSI_MIN_CONNECTIONS			1
#define	ISCSI_MIN_MAX_OUTSTANDING_R2T		1

/*
 * Maximum values from the iSCSI specification
 */
#define	ISCSI_MAX_HEADER_DIGEST			3
#define	ISCSI_MAX_DATA_DIGEST			3
#define	ISCSI_MAX_TIME2RETAIN			3600
#define	ISCSI_MAX_TIME2WAIT			3600
#define	ISCSI_MAX_ERROR_RECOVERY_LEVEL		2
#define	ISCSI_MAX_FIRST_BURST_LENGTH		0xffffff
#define	ISCSI_MAX_BURST_LENGTH			0xffffff
#define	ISCSI_MAX_CONNECTIONS			65535
#define	ISCSI_MAX_OUTSTANDING_R2T		65535
#define	ISCSI_MAX_RECV_DATA_SEGMENT_LENGTH	0xffffff
#define	ISCSI_MAX_TPGT_VALUE			65535 /* 16 bit numeric */

/*
 * iqn and eui name prefixes and related defines
 */
#define	ISCSI_IQN_NAME_PREFIX			"iqn"
#define	ISCSI_EUI_NAME_PREFIX			"eui"
#define	ISCSI_EUI_NAME_LEN			20 /* eui. plus 16 octets */

#ifdef __cplusplus
}
#endif

#endif /* _ISCSI_PROTOCOL_H */
