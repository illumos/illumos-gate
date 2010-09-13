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
 * Copyright (c) 1995,1997-1998 by Sun Microsystems, Inc.
 * All rights reserved.
 */

#ifndef _SYS_FC4_LINKAPP_H
#define	_SYS_FC4_LINKAPP_H

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

#define	LA_RJT		0x01000000
#define	LA_ACC		0x02000000
#define	LA_LOGI		0x03000000
#define	LA_LOGO		0x04000000
#define	LA_RLS		0x0d000000
#define	LA_IDENT	0x20000000

/* Basic Accept Payload. */
typedef struct ba_acc {
	uchar_t		seq_id:8;
	uchar_t		org_s_id[3];
	ushort_t	ox_id;
	ushort_t	rx_id;
} ba_acc_t;

/* Basic Reject. */
typedef struct ba_rjt {
	uchar_t		reseved;
	uchar_t		reason_code;
	uchar_t		explanation;
	uchar_t		vendor;
} ba_rjt_t;

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

/*
 * Values for naa_id
 */
#define	NAA_ID_IEEE		1
#define	NAA_ID_IEEE_EXTENDED	2

/* Login Payload. */
typedef struct la_logi {
	unsigned	code;
	common_svc_t	common_service;

	la_wwn_t	nport_ww_name;
	la_wwn_t	node_ww_name;

	svc_param_t	class_1;
	svc_param_t	class_2;
	svc_param_t	class_3;
} la_logi_t;

#define	SP_F_PORT_LOGIN	0x10

/* Read Link Error Status */
typedef struct la_rls {
	unsigned	code;
	uchar_t		reserved;
	uchar_t		nport_id[3];
} la_rls_t;

/* Read Link Error Status Reply */
typedef struct la_rls_reply {
	unsigned	code;
	unsigned	link_failure;
	unsigned	loss_of_sync;
	unsigned	loss_of_signal;
	unsigned	primitive;
	unsigned	invalid_transmission;
	unsigned	invalid_crc;
} la_rls_reply_t;

/* Logout payload. */
typedef struct la_logo {
	unsigned	cmd;
} la_logo_t;

/* Logout reply payload. */
typedef la_logo_t la_logo_reply_t;

/* Link Application Reject */
typedef struct la_rjt {
	int	code;
	uchar_t	reserved;
	uchar_t	reason_code;
	uchar_t	explanation;
	uchar_t	vendor;
} la_rjt_t;

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

#define	LA_RJT_INSUFFICENT	0x29

#ifdef	__cplusplus
}
#endif

#endif	/* !_SYS_FC4_LINKAPP_H */
