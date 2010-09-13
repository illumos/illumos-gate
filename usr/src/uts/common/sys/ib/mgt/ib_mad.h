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
 * Copyright 2004 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_IB_MGT_IB_MAD_H
#define	_SYS_IB_MGT_IB_MAD_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/ib/ib_types.h>

#define	MAD_SIZE_IN_BYTES 256

typedef struct _ib_mad_hdr_t {
	uint8_t		BaseVersion;		/* version of MAD base format */
	uint8_t		MgmtClass;		/* class of operation */
	uint8_t		ClassVersion;		/* ver. of MAD class format */
	uint8_t		R_Method;		/* response bit & method to   */
						/* perform based on mgmtclass */
	uint16_t	Status;			/* status of operation */
	uint16_t	ClassSpecific;		/* reserved except for SMPs   */
	uint64_t	TransactionID;		/* transaction id */
	uint16_t	AttributeID;		/* defines class spec objects */
	uint16_t	Reserved;
	uint32_t	AttributeModifier;	/* further scope to attrs. */
} ib_mad_hdr_t;

#define	MAD_CLASS_BASE_VERS_1	1

/* Defines and Masks that go with MAD header */
#define	MAD_MGMT_CLASS_SUBN_LID_ROUTED		0x01
#define	MAD_MGMT_CLASS_SUBN_DIRECT_ROUTE	0x81
#define	MAD_MGMT_CLASS_SUBN_ADM			0x03
#define	MAD_MGMT_CLASS_PERF			0x04
#define	MAD_MGMT_CLASS_BM			0x05
#define	MAD_MGMT_CLASS_DEV_MGT			0x06
#define	MAD_MGMT_CLASS_COMM_MGT			0x07
#define	MAD_MGMT_CLASS_SNMP			0x08
#define	MAD_MGMT_CLASS_VENDOR_START		0x09
#define	MAD_MGMT_CLASS_VENDOR_END		0x0F
#define	MAD_MGMT_CLASS_VENDOR2_START		0x30
#define	MAD_MGMT_CLASS_VENDOR2_END		0x4F
#define	MAD_MGMT_CLASS_APPLICATION_START	0x10
#define	MAD_MGMT_CLASS_APPLICATION_END		0x2F
#define	MAD_RESPONSE_BIT			0x80
#define	MAD_RESPONSE_BIT_MASK			0x80
#define	MAD_METHOD_MASK				0x7F
#define	MAD_METHOD_GET				0x01
#define	MAD_METHOD_SET				0x02
#define	MAD_METHOD_GET_RESPONSE			0x81
#define	MAD_METHOD_SEND				0x03
#define	MAD_METHOD_TRAP				0x05
#define	MAD_METHOD_REPORT			0x06
#define	MAD_METHOD_REPORT_RESPONSE		0x86
#define	MAD_METHOD_TRAP_REPRESS			0x07
#define	MAD_STATUS_BUSY				0x01
#define	MAD_STATUS_REDIRECT_REQUIRED		0x02
#define	MAD_STATUS_NO_INVALID_FIELDS		0x00
#define	MAD_STATUS_BAD_VERSION			0x04
#define	MAD_STATUS_UNSUPP_METHOD		0x08
#define	MAD_STATUS_UNSUPP_METHOD_ATTR		0x0C
#define	MAD_STATUS_INVALID_FIELD		0x1C
#define	MAD_ATTR_ID_CLASSPORTINFO		0x01
#define	MAD_ATTR_ID_NOTICE			0x02
#define	MAD_ATTR_ID_INFORMINFO			0x03

/* ClassPortInfo: table 104 */
#if defined(_BIT_FIELDS_HTOL)
typedef struct ib_mad_classportinfo_s {
	uint8_t		BaseVersion;		/* ver. of MAD base format */
	uint8_t		ClassVersion;		/* ver. of MAD class format */
	uint16_t	CapabilityMask;		/* capabilities of this class */
	uint32_t	RespTimeValue;		/* max time btwn req and resp */
						/* (lower 5 bit field, upper */
						/* 27 bits are reserved) */
	uint64_t	RedirectGID_hi;		/* dest gid of redirect msgs */
	uint64_t	RedirectGID_lo;		/* dest gid of redirect msgs */
	uint32_t	RedirectTC	:8;	/* traffic class */
	uint32_t	RedirectSL	:4;	/* SL to access services */
	uint32_t	RedirectFL	:20;	/* flow label to use */
	ib_lid_t	RedirectLID;		/* dlid for class services */
	ib_pkey_t	RedirectP_Key;		/* p_key for class services */
	uint32_t	Reserved2	:8;
	uint32_t	RedirectQP	:24;	/* QP for class services */
	ib_qkey_t	RedirectQ_Key;		/* q_key for class services */
	uint64_t	TrapGID_hi;		/* dest gid of trap msgs */
	uint64_t	TrapGID_lo;		/* dest gid of trap msgs */
	uint32_t	TrapTC		:8;	/* traffic class for traps */
	uint32_t	TrapSL		:4;	/* SL for traps */
	uint32_t	TrapFL		:20;	/* flow label for traps */
	ib_lid_t	TrapLID;		/* dlid for traps */
	ib_pkey_t	TrapP_Key;		/* p_key for traps */
	uint32_t	TrapHL		:8;	/* hop limit for traps */
	uint32_t	TrapQP		:24;	/* QP for traps */
	ib_qkey_t	TrapQ_Key;		/* q_key for traps */
} ib_mad_classportinfo_t;

#elif defined(_BIT_FIELDS_LTOH)

typedef struct ib_mad_classportinfo_s {
	uint8_t		BaseVersion;		/* ver. of MAD base format */
	uint8_t		ClassVersion;		/* ver. of MAD class format */
	uint16_t	CapabilityMask;		/* capabilities of this class */
	uint32_t	RespTimeValue;		/* max time btwn req and resp */
						/* (lower 5 bit field, upper */
						/* 27 bits are reserved) */
	uint64_t	RedirectGID_hi;		/* dest gid of redirect msgs */
	uint64_t	RedirectGID_lo;		/* dest gid of redirect msgs */
	uint32_t	RedirectFL	:20;	/* flow label to use */
	uint32_t	RedirectSL	:4;	/* SL to access services */
	uint32_t	RedirectTC	:8;	/* traffic class */
	ib_lid_t	RedirectLID;		/* dlid for class services */
	ib_pkey_t	RedirectP_Key;		/* p_key for class services */
	uint32_t	RedirectQP	:24;	/* QP for class services */
	uint32_t	Reserved2	:8;
	ib_qkey_t	RedirectQ_Key;		/* q_key for class services */
	uint64_t	TrapGID_hi;		/* dest gid of trap msgs */
	uint64_t	TrapGID_lo;		/* dest gid of trap msgs */
	uint32_t	TrapFL		:20;	/* flow label for traps */
	uint32_t	TrapSL		:4;	/* SL for traps */
	uint32_t	TrapTC		:8;	/* traffic class for traps */
	ib_lid_t	TrapLID;		/* dlid for traps */
	ib_pkey_t	TrapP_Key;		/* p_key for traps */
	uint32_t	TrapQP		:24;	/* QP for traps */
	uint32_t	TrapHL		:8;	/* hop limit for traps */
	ib_qkey_t	TrapQ_Key;		/* q_key for traps */
} ib_mad_classportinfo_t;
#else
#error	One of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif /* _BIT_FIELDS_HTOL */

#define	MAD_CLASSPORTINFO_CAP_MASK_TRAPS	0x01
#define	MAD_CLASSPORTINFO_CAP_MASK_NOTICES	0x02

/*
 * Trap/Notice: Table 105
 */
#if defined(_BIT_FIELDS_HTOL)
typedef struct ib_mad_notice_s {
	uint32_t	IsGeneric	:1;	/* is generic or vendor spec. */
	uint32_t	Type		:7;	/* type of the trap */

	/* if generic, indicates type of event's producer, else vendor id */
	uint32_t	ProducerType_VendorID:24;

	uint16_t	TrapNumber_DeviceID;	/* trap num or device id */
	uint16_t	IssuerLID;		/* generator's LID */
	uint16_t	NoticeToggle	:1;	/* alt 0/1 between notices */
	uint16_t	NoticeCount	:15;	/* num notices queued */
	uint8_t		DataDetails[54];	/* notice/dtrap data details */
	ib_gid_t	IssuerGID;		/* GID of issuer port */
} ib_mad_notice_t;

#elif defined(_BIT_FIELDS_LTOH)

typedef struct ib_mad_notice_s {
	/* if generic, indicates type of event's producer, else vendor id */
	uint32_t	ProducerType_VendorID:24;

	uint32_t	Type		:7;	/* type of the trap */
	uint32_t	IsGeneric	:1;	/* is generic or vendor spec. */

	uint16_t	TrapNumber_DeviceID;	/* trap num or device id */
	uint16_t	IssuerLID;		/* generator's LID */
	uint16_t	NoticeCount	:15;	/* num notices queued */
	uint16_t	NoticeToggle	:1;	/* alt 0/1 between notices */
	uint8_t		DataDetails[54];	/* notice/dtrap data details */
	ib_gid_t	IssuerGID;		/* GID of issuer port */
} ib_mad_notice_t;
#else
#error	One of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif /* _BIT_FIELDS_HTOL */

#define	MAD_NOTICE_IS_GENERIC			0x1

#define	MAD_NOTICE_TYPE_FATAL			0x0
#define	MAD_NOTICE_TYPE_URGENT			0x1
#define	MAD_NOTICE_TYPE_SECURITY			0x2
#define	MAD_NOTICE_TYPE_SUBNET_MGMT		0x3
#define	MAD_NOTICE_TYPE_INFO			0x4

#define	MAD_NOTICE_NODETYPE_CA			0x1
#define	MAD_NOTICE_NODETYPE_SWITCH		0x2
#define	MAD_NOTICE_NODETYPE_ROUTER		0x3
#define	MAD_NOTICE_NODETYPE_SUBNET_MANAGEMENT	0x4

#define	MAD_NOTICE_TRAP_NUMBER_RESERVED		0xFFFF

/* InformInfo: Table 106 */
#if defined(_BIT_FIELDS_HTOL)
typedef struct ib_mad_informinfo_s {
	ib_gid_t	GID;			/* specific GID to sub. for */
	ib_lid_t	LIDRangeBegin;		/* lowest LID to sub. for */
	ib_lid_t	LIDRangeEnd;		/* highest LID to sub. for */
	uint16_t	Reserved;
	uint8_t		IsGeneric;		/* forward generic traps */
	uint8_t		Subscribe;		/* 1 subscribe, 0 unsubscribe */
	uint16_t	Type;			/* type of trap */
	uint16_t	TrapNumber_DeviceID;	/* trap num or device id */
	uint32_t	QPN		:24;	/* queue pair for results */
	uint32_t	Reserved2	:3;
	uint32_t	RespTimeValue	:5;	/* response time value */
	uint32_t	Reserved3	:8;
	uint32_t	ProducerType_VendorID:24; /* type of event's producer */
} ib_mad_informinfo_t;

#elif defined(_BIT_FIELDS_LTOH)

typedef struct ib_mad_informinfo_s {
	ib_gid_t	GID;			/* specific GID to sub. for */
	ib_lid_t	LIDRangeBegin;		/* lowest LID to sub. for */
	ib_lid_t	LIDRangeEnd;		/* highest LID to sub. for */
	uint16_t	Reserved;
	uint8_t		IsGeneric;		/* forward generic traps */
	uint8_t		Subscribe;		/* 1 subscribe, 0 unsubscribe */
	uint16_t	Type;			/* type of trap */
	uint16_t	TrapNumber_DeviceID;	/* trap num or device id */
	uint32_t	RespTimeValue	:5;	/* response time value */
	uint32_t	Reserved2	:3;
	uint32_t	QPN		:24;	/* queue pair for results */
	uint32_t	ProducerType_VendorID:24; /* type of event's producer */
	uint32_t	Reserved3	:8;
} ib_mad_informinfo_t;
#else
#error	One of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif /* _BIT_FIELDS_HTOL */

#define	MAD_INFORMINFO_ALL_ENDPORTS_RANGE		0xFFFF

#define	MAD_INFORMINFO_FORWARD_GENERIC			0x1
#define	MAD_INFORMINFO_FORWARD_VENDOR_SPECIFIC		0x0

#define	MAD_INFORMINFO_SUBSCRIBE			0x1
#define	MAD_INFORMINFO_UNSUBSCRIBE			0x0

#define	MAD_INFORMINFO_TRAP_NUMBER_FORWARD_ALL		0xFFFF

#define	MAD_INFORMINFO_TRAP_TYPE_FATAL			0x0
#define	MAD_INFORMINFO_TRAP_TYPE_URGENT			0x1
#define	MAD_INFORMINFO_TRAP_TYPE_SECURITY		0x2
#define	MAD_INFORMINFO_TRAP_TYPE_SUBNET_MGMT		0x3
#define	MAD_INFORMINFO_TRAP_TYPE_INFORM			0x4
#define	MAD_INFORMINFO_TRAP_TYPE_FORWARD_ALL		0xFFFF

#define	MAD_INFORMINFO_NODETYPE_CA			0x1
#define	MAD_INFORMINFO_NODETYPE_SWITCH			0x2
#define	MAD_INFORMINFO_NODETYPE_ROUTER			0x3
#define	MAD_INFORMINFO_NODETYPE_SUBNET_MANAGEMENT	0x4

#ifdef __cplusplus
}
#endif

#endif /* _SYS_IB_MGT_IB_MAD_H */
