/*
 * CDDL HEADER START
 *
 * The contents of this file are subject to the terms of the
 * Common Development and Distribution License, Version 1.0 only
 * (the "License").  You may not use this file except in compliance
 * with the License.
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
 * Copyright (c) 1996-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_FC4_FCAL_LINKAPP_H
#define	_SYS_FC4_FCAL_LINKAPP_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef	__cplusplus
extern "C" {
#endif

/*
 * linkapp.h
 *
 *	This file contains the definitions for structures and macros
 *	for fiber channel link application payloads and data.
 */

/*
 * Well Known Fiber Chaneel Addresses to reach the fabric for
 * various services.
 */

#define	MAX_FCODE_SIZE		0x2000
#define	FS_GENERAL_MULTICAST	0xfffff7
#define	FS_WELL_KNOWN_MULTICAST	0xfffff8
#define	FS_HUNT_GROUP		0xfffff9
#define	FS_MANAGEMENT_SERVER	0xfffffa
#define	FS_TIME_SERVER		0xfffffb
#define	FS_NAME_SERVER		0xfffffc
#define	FS_FABRIC_CONTROLLER	0xfffffd
#define	FS_FABRIC_F_PORT	0xfffffe
#define	FS_BROADCAST		0xffffff

/*
 * Link Application Opcodes.
 */

#define	LA_ELS_RJT		0x01
#define	LA_ELS_ACC		0x02
#define	LA_ELS_PLOGI		0x03
#define	LA_ELS_FLOGI		0x04
#define	LA_ELS_LOGO		0x05
#define	LA_ELS_ABTX		0x06
#define	LA_ELS_RCS		0x07
#define	LA_ELS_RES		0x08
#define	LA_ELS_RSS		0x09
#define	LA_ELS_RSI		0x0a
#define	LA_ELS_ESTS		0x0b
#define	LA_ELS_ESTC		0x0c
#define	LA_ELS_ADVC		0x0d
#define	LA_ELS_RTV		0x0e
#define	LA_ELS_RLS		0x0f
#define	LA_ELS_ECHO		0x10
#define	LA_ELS_RRQ		0x12
#define	LA_ELS_PRLI		0x20
#define	LA_ELS_PRLO		0x21
#define	LA_ELS_SCN		0x22
#define	LA_ELS_TPLS		0x23
#define	LA_ELS_GPRLO		0x24
#define	LA_ELS_GAID		0x30
#define	LA_ELS_FACT		0x31
#define	LA_ELS_FDACT		0x32
#define	LA_ELS_NACT		0x33
#define	LA_ELS_NDACT		0x34
#define	LA_ELS_QoSR		0x40
#define	LA_ELS_RVCS		0x41
#define	LA_ELS_PDISC		0x50
#define	LA_ELS_FDISC		0x51
#define	LA_ELS_ADISC		0x52
#define	LA_ELS_NEW_IDENT	0xf0	/* SMCC specific */
#define	LA_ELS_DISPLAY		0xf1	/* SMCC specific */
#define	LA_ELS_IDENT		0x20	/* SMCC specifi, SSA compat. */

/*
 * Events supported by soc+ HBA driver
 */
#define	FCAL_INSERT_EVENT	"SUNW,sf:DEVICE-INSERTION.1"
#define	FCAL_REMOVE_EVENT	"SUNW,sf:DEVICE-REMOVAL.1"

/* Basic Accept Payload. */
typedef struct la_ba_acc {
	uchar_t		seq_id:8;
	uchar_t		org_s_id[3];
	ushort_t	ox_id;
	ushort_t	rx_id;
} la_ba_acc_t;

/* Basic Reject. */
typedef struct la_ba_rjt {
	uchar_t		reserved;
	uchar_t		reason_code;
	uchar_t		explanation;
	uchar_t		vendor;
} la_ba_rjt_t;

/*
 * Basic Reject Reason Codes.
 */
#define	RJT_INVALID_CMD		0x01
#define	RJT_LOGICAL_ERR		0x03
#define	RJT_LOGICAL_BUSY	0x05
#define	RJT_PROTOCOL_ERR	0x07
#define	RJT_UNABLE		0x09
#define	RJT_UNSUPPORTED		0x0B
#define	RJT_VENDOR		0xFF

/*
 * Basic Reject Explanation Codes
 */
#define	RJT_NOEXPLANATION	0x00
#define	RJT_INVALID_OSID	0x01
#define	RJT_INVALID_OXID_RXID	0x03
#define	RJT_INVALID_SEQID	0x05
#define	RJT_ABORT_INACTIVE_SEQ	0x07
#define	RJT_UNABLE_TO_SUPPLY	0x09

/*
 * Service parameters.
 */
typedef struct common_service {
	uint_t		fcph;
	uint_t		btob_crdt;
	uint_t		cmn_features;
	uint_t		reserved;
} common_svc_t;

typedef struct service_param {
	uchar_t		data[16];
} svc_param_t;

/* World Wide Name formats */
typedef union la_wwn {
	uchar_t		raw_wwn[8];
	struct {
	    uint_t	naa_id : 4;
	    uint_t	nport_id : 12;
	    uint_t	wwn_hi : 16;
	    uint_t	wwn_lo;
	} w;
} la_wwn_t;

#define	FC_WWN_SIZE	8

/*
 * Values for naa_id
 */
#define	NAA_ID_IEEE		1
#define	NAA_ID_IEEE_EXTENDED	2

/* Login Payload. */
typedef struct la_els_logi {
	uchar_t		ls_code;
	uchar_t		mbz[3];
	common_svc_t	common_service;

	la_wwn_t	nport_ww_name;
	la_wwn_t	node_ww_name;

	svc_param_t	class_1;
	svc_param_t	class_2;
	svc_param_t	class_3;
	uchar_t		reserved[16];
	uchar_t		vendor_version_level[16];
} la_els_logi_t;

typedef	la_els_logi_t	la_els_logi_reply_t;
#define	la_logi_t	la_els_logi_t

#define	SP_F_PORT_LOGIN	0x10

/* Read Link Error Status */
typedef struct la_els_rls {
	uchar_t		ls_code;
	uchar_t		mbz[3];
	uchar_t		reserved;
	uchar_t		nport_id[3];
} la_els_rls_t;

/* Read Link Error Status Reply */
typedef struct la_els_rls_reply {
	uchar_t		ls_code;
	uchar_t		mbz[3];
	uint_t	link_failure;
	uint_t	loss_of_sync;
	uint_t	loss_of_signal;
	uint_t	primitive;
	uint_t	invalid_transmission;
	uint_t	invalid_crc;
} la_els_rls_reply_t;

/* Logout payload. */
typedef struct la_els_logo {
	uchar_t		ls_code;
	uchar_t		mbz[3];
	uchar_t		reserved;
	uchar_t		nport_id[3];
	la_wwn_t	nport_ww_name;
} la_els_logo_t;

/* Logout reply payload. */
typedef la_els_logo_t la_els_logo_reply_t;

/* Reinstate recovery qualifier */
typedef	struct la_els_rrq {
	uchar_t		ls_code;
	uchar_t		mbz[3];
	uchar_t		reserved;
	uchar_t		source_id[3];
	ushort_t	ox_id;
	ushort_t	rx_id;
	uchar_t		assoc_header[32];
} la_els_rrq_t;

/* Reinstate recovery qualifier reply */
typedef la_els_logo_t la_els_rrq_reply_t;

/* Process login */
typedef struct la_els_prli {
	uchar_t		ls_code;
	uchar_t		page_length;
	ushort_t	payload_length;
	uchar_t		service_params[16];
} la_els_prli_t;

/* Process login reply */
typedef	la_els_prli_t la_els_prli_reply_t;

/* Process logout */
typedef la_els_prli_t la_els_prlo_t;

/* process logout reply */
typedef	la_els_prli_t la_els_prlo_reply_t;

/* Port discovery */
typedef la_els_logi_t la_els_pdisc_t;

/* Port discovery reply */
typedef la_els_logi_reply_t la_els_pdisc_reply_t;

/* Address discovery */
typedef	struct la_els_adisc {
	uchar_t	ls_code;
	uchar_t	mbz[3];
	uint_t	hard_address;
	uchar_t	port_wwn[8];
	uchar_t	node_wwn[8];
	uint_t	nport_id;
} la_els_adisc_t;

/* Address discovery reply */
typedef	la_els_adisc_t la_els_adisc_reply_t;

/* Identify */
typedef	struct la_els_identify {
	uint_t	ls_code;
	uint_t	byte_count;
} la_els_identify_t;

/* Identify reply */
typedef	struct la_els_identify_reply {
	uint_t	ls_code;
	uchar_t	fcode[MAX_FCODE_SIZE];
} la_els_identify_reply;

/* Link Application Reject */
typedef struct la_els_rjt {
	uchar_t	ls_code;
	uchar_t	mbz[3];
	uchar_t	reserved;
	uchar_t	reason_code;
	uchar_t	explanation;
	uchar_t	vendor;
} la_els_rjt_t;

/*
 * LA_RJT Reason Codes.
 */
#define	LA_RJT_INVALID			0x01
#define	LA_RJT_LOGICAL_ERR		0x03
#define	LA_RJT_LOGICAL_BUSY		0x05
#define	LA_RJT_PROTOCOL_ERR		0x07
#define	LA_RJT_UNABLE_TO_PERFORM	0x09
#define	LA_RJT_NOT_SUPPORTED		0x0b
#define	LA_RJT_VENDOR			0xff

/*
 * LA_RJT explanations
 */
#define	LA_RJT_NOEXPLANATION	0x00
#define	LA_RJT_OPTIONS		0x01
#define	LA_RJT_INITIATOR	0x03
#define	LA_RJT_RECIPIENT	0x05
#define	LA_RJT_DATA_FIELD_SIZE	0x07
#define	LA_RJT_CONCURRENT	0x09
#define	LA_RJT_CREDIT		0x0b

#define	LA_RJT_INVALID_PORT_WWNAME	0x0d
#define	LA_RJT_INVALID_NODE_WWNAME	0x0e
#define	LA_RJT_INVALID_COMMON_SVC	0x0f

#define	LA_RJT_INVALID_ASSOC_HEADER	0x11
#define	LA_RJT_ASSOC_HDR_REQD		0x13
#define	LA_RJT_INVALID_ORIG_SID		0x15
#define	LA_RJT_INVALID_FQXID		0x17
#define	LA_RJT_REQUEST_IN_PROGRESS	0x19
#define	LA_RJT_INVALID_NPORT_ID		0x1f

#define	LA_RJT_ INVALID_SEQ_ID		0x21
#define	LA_RJT_ABT_INVALID_XID		0x23
#define	LA_RJT_ABT_INACTIVE_XID		0x25
#define	LA_RJT_RRQ_REQUIRED		0x27
#define	LA_RJT_INSUFFICENT		0x29

#define	LA_RJT_REQUESTED_DATA		0x2a
#define	LA_RJT_REQUEST_NOT_SUPPORTED	0x2c

#ifdef	__cplusplus
}
#endif

#endif	/* !_SYS_FC4_FCAL_LINKAPP_H */
