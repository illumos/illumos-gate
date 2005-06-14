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

#ifndef	_SYS_IB_MGT_SA_RECS_H
#define	_SYS_IB_MGT_SA_RECS_H

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*
 * This file contains the definitions of the SA-specific records in IB spec
 * volume 1, release 1.1, chapter 15.
 */

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/ib/ib_types.h>
#include <sys/ib/mgt/sm_attr.h>

/* class header for SA MADs */
typedef struct _ib_sa_hdr_t {
	uint64_t	SM_KEY;
	uint16_t	AttributeOffset;
	uint16_t	Reserved;
	uint64_t	ComponentMask;
} ib_sa_hdr_t;

/* subnet administration methods */
#define	SA_SUBN_ADM_GET			0x01
#define	SA_SUBN_ADM_GET_RESP		0x81
#define	SA_SUBN_ADM_SET			0x02
#define	SA_SUBN_ADM_REPORT		0x06
#define	SA_SUBN_ADM_REPORT_RESP		0x86
#define	SA_SUBN_ADM_GET_TABLE		0x12
#define	SA_SUBN_ADM_GET_TABLE_RESP	0x92
#define	SA_SUBN_ADM_GET_TRACE_TABLE	0x13
#define	SA_SUBN_ADM_GET_MULTI		0x14
#define	SA_SUBN_ADM_GET_MULTI_RESP	0x94
#define	SA_SUBN_ADM_DELETE		0x15
#define	SA_SUBN_ADM_DELETE_RESP		0x95

/* sa MAD status field bit value */
#define	SA_STATUS_NO_ERROR				0x0000
#define	SA_STATUS_ERR_NO_RESOURCES			0x0100
#define	SA_STATUS_ERR_REQ_INVALID			0x0200
#define	SA_STATUS_ERR_NO_RECORDS			0x0300
#define	SA_STATUS_ERR_TOO_MANY_RECORDS			0x0400
#define	SA_STATUS_ERR_REQ_INVALID_GID			0x0500
#define	SA_STATUS_ERR_REQ_INSUFFICIENT_COMPONENTS	0x0600
#define	SA_STATUS_ERROR_MASK				0xFF00


/* SA-Specific ClassPortinfo::CapabilityMask Bits: Table 152 */
#define	SA_CAPMASK_OPT_RECORDS_SUPPORTED	0x100
#define	SA_CAPMASK_UD_MCAST_SUPPORTED		0x200
#define	SA_CAPMASK_MULTIPATH_SUPPORTED		0x400
#define	SA_CAPMASK_REINIT_SUPPORTED		0x800

/* SA attribute IDs: Table 155 */
#define	SA_CLASSPORTINFO_ATTRID		0x01
#define	SA_NOTICE_ATTRID		0x02
#define	SA_INFORMINFO_ATTRID		0x03
#define	SA_NODERECORD_ATTRID		0x11
#define	SA_PORTINFORECORD_ATTRID	0x12
#define	SA_SLTOVLRECORD_ATTRID		0x13
#define	SA_SWITCHINFORECORD_ATTRID	0x14
#define	SA_LINEARFDBRECORD_ATTRID	0x15
#define	SA_RANDOMFDBRECORD_ATTRID	0x16
#define	SA_MULTICASTFDBRECORD_ATTRID	0x17
#define	SA_SMINFORECORD_ATTRID		0x18
#define	SA_INFORMINFORECORD_ATTRID	0xF3
#define	SA_LINKRECORD_ATTRID		0x20
#define	SA_GUIDINFORECORD_ATTRID	0x30
#define	SA_SERVICERECORD_ATTRID		0x31
#define	SA_PARTITIONRECORD_ATTRID	0x33
#define	SA_PATHRECORD_ATTRID		0x35
#define	SA_VLARBRECORD_ATTRID		0x36
#define	SA_MCMEMBERRECORD_ATTRID	0x38
#define	SA_TRACERECORD_ATTRID		0x39
#define	SA_MULTIPATHRECORD_ATTRID	0x3A
#define	SA_SERVICEASSNRECORD_ATTRID	0x3B

/* Node Record: Table 157 */
typedef	struct sa_node_record_s {
	ib_lid_t	LID;			/* LID of a port of the node */
	uint16_t	Reserved;
	sm_nodeinfo_t	NodeInfo;		/* NodeInfo attr. contents */
	sm_nodedesc_t	NodeDescription;	/* NodeDesc attr. contents */
} sa_node_record_t;

#define	SA_NODEINFO_COMPMASK_NODELID		0x1
#define	SA_NODEINFO_COMPMASK_RESERVED		0x2
#define	SA_NODEINFO_COMPMASK_BASEVERSION	0x4
#define	SA_NODEINFO_COMPMASK_CLASSVERSION	0x8
#define	SA_NODEINFO_COMPMASK_NODETYPE		0x10
#define	SA_NODEINFO_COMPMASK_NUMPORTS		0x20
#define	SA_NODEINFO_COMPMASK_SYSIMAGEGUID	0x40
#define	SA_NODEINFO_COMPMASK_NODEGUID		0x80
#define	SA_NODEINFO_COMPMASK_PORTGUID		0x100
#define	SA_NODEINFO_COMPMASK_PARTITIONCAP	0x200
#define	SA_NODEINFO_COMPMASK_DEVICEID		0x400
#define	SA_NODEINFO_COMPMASK_REVISION		0x800
#define	SA_NODEINFO_COMPMASK_LOCALPORTNUM	0x1000
#define	SA_NODEINFO_COMPMASK_VENDORID		0x2000
#define	SA_NODEINFO_COMPMASK_NODEDESCRIPTION	0x4000

/* Portinfo Record: Table 158 */
typedef struct sa_portinfo_record_s {
	ib_lid_t	EndportLID;		/* LID of the port */
	uint8_t		PortNum;		/* port number (for switch) */
	uint8_t		Reserved;
	sm_portinfo_t	PortInfo;		/* PortInfo attr. contents */
} sa_portinfo_record_t;

/* first 3 components are atomic */
#define	SA_PORTINFO_COMPMASK_PORTLID		0x1
#define	SA_PORTINFO_COMPMASK_PORTNUM		0x2
#define	SA_PORTINFO_COMPMASK_RESERVED		0x4
#define	SA_PORTINFO_COMPMASK_MKEY		0x8
#define	SA_PORTINFO_COMPMASK_GIDPREFIX		0x10
#define	SA_PORTINFO_COMPMASK_LID		0x20
#define	SA_PORTINFO_COMPMASK_MASTERSMLID	0x40
#define	SA_PORTINFO_COMPMASK_CAPMASK		0x80
#define	SA_PORTINFO_COMPMASK_DIAGCODE		0x100
#define	SA_PORTINFO_COMPMASK_MKEYLEASE		0x200
#define	SA_PORTINFO_COMPMASK_LOCALPORTNUM	0x400
#define	SA_PORTINFO_COMPMASK_LINKWIDTHEN	0x800
#define	SA_PORTINFO_COMPMASK_LINKWIDTHSUPP	0x1000
#define	SA_PORTINFO_COMPMASK_LINKWIDTHACT	0x2000
#define	SA_PORTINFO_COMPMASK_LINKSPEEDSUPP	0x4000
#define	SA_PORTINFO_COMPMASK_PORTSTATE		0x8000
#define	SA_PORTINFO_COMPMASK_PORTPHYSICALSTATE	0x10000
#define	SA_PORTINFO_COMPMASK_LINKDOWNDEFSTATE	0x20000
#define	SA_PORTINFO_COMPMASK_MKEYPROTBITS	0x40000
#define	SA_PORTINFO_COMPMASK_RESERVED2		0x80000
#define	SA_PORTINFO_COMPMASK_LMC		0x100000
#define	SA_PORTINFO_COMPMASK_LINKSPEEDACT	0x200000
#define	SA_PORTINFO_COMPMASK_LINKSPEEDEN	0x400000
#define	SA_PORTINFO_COMPMASK_NEIGHBORMTU	0x800000
#define	SA_PORTINFO_COMPMASK_MASTERSMSL		0x1000000
#define	SA_PORTINFO_COMPMASK_VLCAP		0x2000000
#define	SA_PORTINFO_COMPMASK_INITTYPE		0x4000000
#define	SA_PORTINFO_COMPMASK_VLHIGHLIMIT	0x8000000
#define	SA_PORTINFO_COMPMASK_VLARBHIGHCAP	0x10000000
#define	SA_PORTINFO_COMPMASK_VLARBLOWCAP	0x20000000
#define	SA_PORTINFO_COMPMASK_INITTYPEREPLY	0x40000000
#define	SA_PORTINFO_COMPMASK_MTUCAP		0x80000000
#define	SA_PORTINFO_COMPMASK_VLSTALLCOUNT	0x100000000
#define	SA_PORTINFO_COMPMASK_HOQLIFE		0x200000000
#define	SA_PORTINFO_COMPMASK_OPERATIONALVLS	0x400000000
#define	SA_PORTINFO_COMPMASK_PARTENFINBOUND	0x800000000
#define	SA_PORTINFO_COMPMASK_PARTENFOUTBOUND	0x1000000000
#define	SA_PORTINFO_COMPMASK_FILTERRAWPKTIN	0x2000000000
#define	SA_PORTINFO_COMPMASK_FILTERRAWPKTOUT	0x4000000000
#define	SA_PORTINFO_COMPMASK_MKEYVIOLATIONS	0x8000000000
#define	SA_PORTINFO_COMPMASK_PKEYVIOLATIONS	0x10000000000
#define	SA_PORTINFO_COMPMASK_QKEYVIOLATIONS	0x20000000000
#define	SA_PORTINFO_COMPMASK_GUIDCAP		0x40000000000
#define	SA_PORTINFO_COMPMASK_RESERVED5		0x80000000000
#define	SA_PORTINFO_COMPMASK_SUBNETTIMEOUT	0x100000000000
#define	SA_PORTINFO_COMPMASK_RESERVED6		0x200000000000
#define	SA_PORTINFO_COMPMASK_RESPTIMEVALUE	0x400000000000
#define	SA_PORTINFO_COMPMASK_LOCALPHYERRORS	0x800000000000
#define	SA_PORTINFO_COMPMASK_OVERRUNERRORS	0x1000000000000

/* SLtoVL Mapping Table Record: Table 159 */
typedef struct sa_SLtoVLmapping_record_s {
	ib_lid_t			LID;
	uint8_t				InputPortNum;
	uint8_t				OutputPortNum;
	uint32_t			Reserved;
	sm_SLtoVL_mapping_table_t	SLtoVLMappingTable;
} sa_SLtoVLmapping_record_t;

#define	SA_SLTOVL_COMPMASK_PORTLID		0x1
#define	SA_SLTOVL_COMPMASK_INPUTPORTNUM		0x2
#define	SA_SLTOVL_COMPMASK_OUTPUTPORTNUM	0x4
#define	SA_SLTOVL_COMPMASK_RESERVED		0x8
#define	SA_SLTOVL_COMPMASK_SL0TOVL		0x10
#define	SA_SLTOVL_COMPMASK_SL1TOVL		0x20
#define	SA_SLTOVL_COMPMASK_SL2TOVL		0x40
#define	SA_SLTOVL_COMPMASK_SL3TOVL		0x80
#define	SA_SLTOVL_COMPMASK_SL4TOVL		0x100
#define	SA_SLTOVL_COMPMASK_SL5TOVL		0x200
#define	SA_SLTOVL_COMPMASK_SL6TOVL		0x400
#define	SA_SLTOVL_COMPMASK_SL7TOVL		0x800
#define	SA_SLTOVL_COMPMASK_SL8TOVL		0x1000
#define	SA_SLTOVL_COMPMASK_SL9TOVL		0x2000
#define	SA_SLTOVL_COMPMASK_SL10TOVL		0x4000
#define	SA_SLTOVL_COMPMASK_SL11TOVL		0x8000
#define	SA_SLTOVL_COMPMASK_SL12TOVL		0x10000
#define	SA_SLTOVL_COMPMASK_SL13TOVL		0x20000
#define	SA_SLTOVL_COMPMASK_SL14TOVL		0x40000
#define	SA_SLTOVL_COMPMASK_SL15TOVL		0x80000

/* Switchinfo Record: Table 160 */
typedef struct sa_switchinfo_record_s {
	ib_lid_t	LID;			/* LID of switch port 0 */
	uint16_t	Reserved;
	sm_switchinfo_t	SwitchInfo;		/* SwitchInfo attr. contents */
} sa_switchinfo_record_t;

#define	SA_SWITCHINFO_COMPMASK_SWITCHLID		0x1
#define	SA_SWITCHINFO_COMPMASK_RESERVED			0x2
#define	SA_SWITCHINFO_COMPMASK_LINEARFDBCAP		0x4
#define	SA_SWITCHINFO_COMPMASK_RANDOMFDBCAP		0x8
#define	SA_SWITCHINFO_COMPMASK_MCASTFDBCAP		0x10
#define	SA_SWITCHINFO_COMPMASK_LINEARFDBTOP		0x20
#define	SA_SWITCHINFO_COMPMASK_DEFAULTPORT		0x40
#define	SA_SWITCHINFO_COMPMASK_DEFAULTMCASTPPORT	0x80
#define	SA_SWITCHINFO_COMPMASK_DEFAULTMCASTNPPORT 	0x100
#define	SA_SWITCHINFO_COMPMASK_LIFETIMEVALUE		0x200
#define	SA_SWITCHINFO_COMPMASK_PORTSTATECHANGE		0x400
#define	SA_SWITCHINFO_COMPMASK_RESERVED2		0x800
#define	SA_SWITCHINFO_COMPMASK_LIDSPERPORT		0x1000
#define	SA_SWITCHINFO_COMPMASK_PARTENFCAP		0x2000
#define	SA_SWITCHINFO_COMPMASK_INBOUNDENFCAP		0x4000
#define	SA_SWITCHINFO_COMPMASK_OUTBOUNDENFCAP		0x8000
#define	SA_SWITCHINFO_COMPMASK_FILTERRAWPKTINCAP	0x10000
#define	SA_SWITCHINFO_COMPMASK_FILTERRAWPKTOUTCAP	0x20000
#define	SA_SWITCHINFO_COMPMASK_ENHANCED_PORT_0		0x40000

/* Linear Forwarding Table Record: Table 161 */
typedef struct sa_linearft_record_s {
	ib_lid_t	LID;
	uint16_t	BlockNum;
	uint32_t	Reserved;
	sm_linear_forwarding_table_t	LinearFT;
} sa_linearft_record_t;

#define	SA_LFT_COMPMASK_LFTLID			0x1
#define	SA_LFT_COMPMASK_BLOCKNUM		0x2
#define	SA_LFT_COMPMASK_RESERVED		0x4
#define	SA_LFT_COMPMASK_LINEARFORWARDINGTABLE	0x8

/* Random Forwarding Table Record: Table 162 */
typedef struct sa_randomft_record_s {
	ib_lid_t	LID;
	uint16_t	BlockNum;
	uint32_t	Reserved;
	sm_random_forwarding_table_t	RandomFT;
} sa_randomft_record_t;

#define	SA_RFT_COMPMASK_RFTLID			0x1
#define	SA_RFT_COMPMASK_BLOCKNUM		0x2
#define	SA_RFT_COMPMASK_RESERVED		0x4
#define	SA_RFT_COMPMASK_RANDOMFORWARDINGTABLE	0x8

/* Multicast Forwarding Table Record: Table 163 */

#if defined(_BIT_FIELDS_HTOL)
typedef struct sa_multicastft_record_s {
	ib_lid_t	LID;
	uint16_t	Position	:4;	/* position field of attr */
	uint16_t	Reserved	:3;
	uint16_t	BlockNum	:9;
	uint32_t	Reserved2;
	sm_multicast_forwarding_table_t	MulticastFT;
} sa_multicastft_record_t;

#elif defined(_BIT_FIELDS_LTOH)

typedef struct sa_multicastft_record_s {
	ib_lid_t	LID;
	uint16_t	BlockNum	:9;
	uint16_t	Reserved	:3;
	uint16_t	Position	:4;	/* position field of attr */
	uint32_t	Reserved2;
	sm_multicast_forwarding_table_t	MulticastFT;
} sa_multicastft_record_t;

#else
#error	One of _BIT_FIELDS_HTOL or _BIT_FIELDS_HTOL must be defined
#endif /* _BIT_FIELDS_HTOL */

#define	SA_MFT_COMPMASK_MFTLID				0x1
#define	SA_MFT_COMPMASK_POSITION			0x2
#define	SA_MFT_COMPMASK_RESERVED			0x4
#define	SA_MFT_COMPMASK_BLOCKNUM			0x8
#define	SA_MFT_COMPMASK_RESERVED2			0x10
#define	SA_MFT_COMPMASK_MULTICASTFORWARDINGTABLE	0x20

/* VLArbitration Table Record: Table 164 */
typedef struct sa_VLarb_table_record_s {
	ib_lid_t	LID;
	uint8_t		OutputPortNum;
	uint8_t		BlockNum;
	uint32_t	Reserved;
	sm_VLarb_table_t VLArbTable;
} sa_VLarb_table_record_t;

#define	SA_VLARB_COMPMASK_NODELID		0x1
#define	SA_VLARB_COMPMASK_OUTPUTPORTNUM		0x2
#define	SA_VLARB_COMPMASK_BLOCKNUM		0x4
#define	SA_VLARB_COMPMASK_RESERVED		0x8
#define	SA_VLARB_COMPMASK_VLARBTABLE		0x10

/* SMInfo Record: Table 165 */
typedef struct _sminfo_record_s {
	ib_lid_t	LID;
	uint16_t	Reserved;
	sm_sminfo_t	SMInfo;
} sa_sminfo_record_t;

#define	SA_SMINFO_COMPMASK_NODELID		0x1
#define	SA_SMINFO_COMPMASK_RESERVED		0x2
#define	SA_SMINFO_COMPMASK_GUID			0x4
#define	SA_SMINFO_COMPMASK_SMKEY		0x8
#define	SA_SMINFO_COMPMASK_ACTCOUNT		0x10
#define	SA_SMINFO_COMPMASK_PRIORITY		0x20
#define	SA_SMINFO_COMPMASK_SMSTATE		0x40

/* P_Key Table Record: Table 166 */
typedef struct sa_pkey_table_record_s {
	ib_lid_t	LID;
	uint16_t 	BlockNum;
	uint8_t		PortNum;
	uint8_t		Reserved[3];
	sm_pkey_table_t	P_KeyTable;
} sa_pkey_table_record_t;

#define	SA_PKEY_COMPMASK_PORTLID		0x1
#define	SA_PKEY_COMPMASK_BLOCKNUM		0x2
#define	SA_PKEY_COMPMASK_PORTNUM 		0x4
#define	SA_PKEY_COMPMASK_RESERVED		0x8
#define	SA_PKEY_COMPMASK_PKEYTABLE		0x10

/* InformInfo Record: Table 167 */
typedef struct sa_informinfo_record_s {
	ib_gid_t		SubscriberGID;
	uint16_t		Enum;
	uint8_t			Reserved[6];
	ib_mad_informinfo_t	InformInfo;
} sa_informinfo_record_t;

#define	SA_INFORMINFO_COMPMASK_SUBGID		0x1
#define	SA_INFORMINFO_COMPMASK_ENUM		0x2
#define	SA_INFORMINFO_COMPMASK_RESERVED		0x4
#define	SA_INFORMINFO_COMPMASK_GID		0x8
#define	SA_INFORMINFO_COMPMASK_LIDRANGEBEGIN	0x10
#define	SA_INFORMINFO_COMPMASK_LIDRANGEEND	0x20
#define	SA_INFORMINFO_COMPMASK_RESERVED2	0x40
#define	SA_INFORMINFO_COMPMASK_ISGENERIC	0x80
#define	SA_INFORMINFO_COMPMASK_SUBSCRIBE	0x100
#define	SA_INFORMINFO_COMPMASK_TYPE		0x200
#define	SA_INFORMINFO_COMPMASK_TRAPNUM_DEVID	0x400
#define	SA_INFORMINFO_COMPMASK_QPN		0x800
#define	SA_INFORMINFO_COMPMASK_RESERVED3	0x1000
#define	SA_INFORMINFO_COMPMASK_RESPTIMEVALUE	0x2000
#define	SA_INFORMINFO_COMPMASK_RESERVED4	0x4000
#define	SA_INFORMINFO_COMPMASK_PRODTYPE_VENDID	0x8000

/* Link Record: Table 168 */
typedef struct sa_link_record_s {
	ib_lid_t	FromLID;
	uint8_t		FromPort;
	uint8_t		ToPort;
	ib_lid_t	ToLID;
} sa_link_record_t;

#define	SA_LINKRECORD_COMPMASK_FROMLID		0x1
#define	SA_LINKRECORD_COMPMASK_FROMPORT		0x2
#define	SA_LINKRECORD_COMPMASK_TOPORT		0x4
#define	SA_LINKRECORD_COMPMASK_TOLID		0x8

/* Service Record: Table 169 */
typedef struct sa_service_record_s {
	uint64_t	ServiceID;		/* id of service on port */
	ib_gid_t	ServiceGID;		/* port GID for this service */
	uint16_t	ServiceP_Key;		/* p_key used to contact serv */
	uint16_t	Reserved;
	uint32_t	ServiceLease;		/* lease period remaining */
	uint64_t	ServiceKey_hi;		/* key value assoc. with serv */
	uint64_t	ServiceKey_lo;
	uint8_t		ServiceName[IB_SVC_NAME_LEN];
						/* UTF-8 encoded service name */
	uint8_t		ServiceData[IB_SVC_DATA_LEN];
						/* data for this service rec. */
} sa_service_record_t;

#define	SA_SR_INDEFINITE_SERVICE_LEASE	0xFFFFFFFF

/*
 * #defines mapping individual bits of the service record component mask
 * to components in the service record.  ServiceData uses one component mask per
 * bit.  See the IB spec for details.
 */
#define	SA_SR_COMPMASK_ID		0x1
#define	SA_SR_COMPMASK_GID		0x2
#define	SA_SR_COMPMASK_PKEY		0x4
#define	SA_SR_COMPMASK_RESERVED		0x8
#define	SA_SR_COMPMASK_LEASE		0x10
#define	SA_SR_COMPMASK_KEY		0x20
#define	SA_SR_COMPMASK_NAME		0x40

/* masks all ServiceData fields */
#define	SA_SR_COMPMASK_ALL_DATA		0x1FFFFFFF80

/* Service Association Record: Table 170 */
typedef struct sa_service_assn_record_s {
	uint64_t	ServiceKey_hi;
	uint64_t	ServiceKey_lo;
	uint8_t		ServiceName[IB_SVC_NAME_LEN];
} sa_service_assn_record_t;

#define	SA_SERVASSOC_COMPMASK_SERVICEKEY		0x1
#define	SA_SERVASSOC_COMPMASK_SERVICENAME	0x2

/* Path Record: Table 171 */

#if defined(_BIT_FIELDS_HTOL)
typedef struct sa_path_record_s {
	uint32_t	Reserved;
	uint32_t	Reserved2;
	ib_gid_t	DGID;			/* dest gid of path */
	ib_gid_t	SGID;			/* source gid of path */
	uint16_t	DLID;			/* dest lid */
	uint16_t	SLID;			/* source lid */
	uint32_t	RawTraffic	:1;	/* raw pkt path */
	uint32_t	Reserved3	:3;
	uint32_t	FlowLabel	:20;	/* flow label */
	uint32_t	HopLimit	:8;	/* hop limit */
	uint8_t		TClass;			/* TClass */
	uint8_t		Reversible	:1;	/* reversible path required */
	uint8_t		NumbPath	:7;	/* max num. of paths to ret. */
	uint16_t	P_Key;			/* partition key for path */
	uint16_t	Reserved4	:12;
	uint16_t	SL		:4;	/* service level for path */
	uint8_t		MtuSelector	:2;	/* MTU selector */
	uint8_t		Mtu		:6;	/* required MTU */
	uint8_t		RateSelector	:2;	/* rate selector */
	uint8_t		Rate		:6;	/* value of rate */
	uint8_t		PacketLifeTimeSelector:2; /* pkt life time selector */
	uint8_t		PacketLifeTime	:6;	/* total packet life time */
	uint8_t		Preference;		/* in response, order of pref */
						/* among all paths */
	uint8_t		Reserved5[6];
} sa_path_record_t;

#elif defined(_BIT_FIELDS_LTOH)

typedef struct sa_path_record_s {
	uint32_t	Reserved;
	uint32_t	Reserved2;
	ib_gid_t	DGID;			/* dest gid of path */
	ib_gid_t	SGID;			/* source gid of path */
	uint16_t	DLID;			/* dest lid */
	uint16_t	SLID;			/* source lid */
	uint32_t	HopLimit	:8;	/* hop limit */
	uint32_t	FlowLabel	:20;	/* flow label */
	uint32_t	Reserved3	:3;
	uint32_t	RawTraffic	:1;	/* raw pkt path */
	uint8_t		TClass;			/* TClass */
	uint8_t		NumbPath	:7;	/* max num. of paths to ret. */
	uint8_t		Reversible	:1;	/* reversible path required */
	uint16_t	P_Key;			/* partition key for path */
	uint16_t	SL		:4;	/* service level for path */
	uint16_t	Reserved4	:12;
	uint8_t		Mtu		:6;	/* required MTU */
	uint8_t		MtuSelector	:2;	/* MTU selector */
	uint8_t		Rate		:6;	/* value of rate */
	uint8_t		RateSelector	:2;	/* rate selector */
	uint8_t		PacketLifeTime	:6;	/* total packet life time */
	uint8_t		PacketLifeTimeSelector:2; /* pkt life time selector */
	uint8_t		Preference;		/* in response, order of pref */
						/* among all paths */
	uint8_t		Reserved5[6];
} sa_path_record_t;

#else
#error	One of _BIT_FIELDS_HTOL or _BIT_FIELDS_HTOL must be defined
#endif /* _BIT_FIELDS_HTOL */

/*
 * #defines mapping individual bits of the path record component mask
 * to components in the path record
 */
#define	SA_PR_COMPMASK_RESERVED		0x1
#define	SA_PR_COMPMASK_RESERVED2	0x2
#define	SA_PR_COMPMASK_DGID		0x4
#define	SA_PR_COMPMASK_SGID		0x8
#define	SA_PR_COMPMASK_DLID		0x10
#define	SA_PR_COMPMASK_SLID		0x20
#define	SA_PR_COMPMASK_RAWTRAFFIC	0x40
#define	SA_PR_COMPMASK_RESERVED3	0x80
#define	SA_PR_COMPMASK_FLOWLABEL	0x100
#define	SA_PR_COMPMASK_HOPLIMIT		0x200
#define	SA_PR_COMPMASK_TCLASS		0x400
#define	SA_PR_COMPMASK_REVERSIBLE	0x800
#define	SA_PR_COMPMASK_NUMBPATH		0x1000
#define	SA_PR_COMPMASK_PKEY		0x2000
#define	SA_PR_COMPMASK_RESERVED4	0x4000
#define	SA_PR_COMPMASK_SL		0x8000
#define	SA_PR_COMPMASK_MTUSELECTOR	0x10000
#define	SA_PR_COMPMASK_MTU		0x20000
#define	SA_PR_COMPMASK_RATESELECTOR	0x40000
#define	SA_PR_COMPMASK_RATE		0x80000
#define	SA_PR_COMPMASK_PKTLTSELECTOR	0x100000
#define	SA_PR_COMPMASK_PKTLT		0x200000
#define	SA_PR_COMPMASK_PREFERENCE	0x400000

#define	SA_PR_RAWTRAFFIC_PKEY		0x1
#define	SA_PR_RAWTRAFFIC_NO_PKEY 	0x0
#define	SA_PR_MTU_SEL_GREATER		0x0
#define	SA_PR_MTU_SEL_LESS		0x1
#define	SA_PR_MTU_SEL_EXACTLY		0x2
#define	SA_PR_MTU_SEL_LARGEST_AVAIL	0x3
#define	SA_PR_MTU_256			0x1
#define	SA_PR_MTU_512			0x2
#define	SA_PR_MTU_1024			0x3
#define	SA_PR_MTU_2048			0x4
#define	SA_PR_MTU_4096			0x5
#define	SA_PR_RATE_SEL_GREATER		0x0
#define	SA_PR_RATE_SEL_LESS		0x1
#define	SA_PR_RATE_SEL_EXACTLY		0x2
#define	SA_PR_RATE_SEL_LARGEST_AVAIL	0x3
#define	SA_PR_RATE_25			0x2
#define	SA_PR_RATE_10			0x3
#define	SA_PR_RATE_30			0x4
#define	SA_PR_LT_SEL_GREATER		0x0
#define	SA_PR_LT_SEL_LESS		0x1
#define	SA_PR_LT_SEL_EXACTLY		0x2
#define	SA_PR_LT_SEL_SMALLEST_AVAIL	0x3

/* MCMember Record: Table 176 */

#if defined(_BIT_FIELDS_HTOL)
typedef struct sa_mcmember_record_s {
	ib_gid_t	MGID;
	ib_gid_t	PortGID;
	uint32_t	Q_Key;
	ib_lid_t	MLID;
	uint8_t		MTUSelector		:2;
	uint8_t		MTU			:6;
	uint8_t		TClass;
	uint16_t	P_Key;
	uint8_t		RateSelector		:2;
	uint8_t		Rate			:6;
	uint8_t		PacketLifeTimeSelector	:2;
	uint8_t		PacketLifeTime		:6;
	uint32_t	SL			:4;
	uint32_t	FlowLabel		:20;
	uint32_t	HopLimit		:8;
	uint32_t	Scope			:4;
	uint32_t	JoinState		:4;
	uint32_t	ProxyJoin		:1;
	uint32_t	Reserved		:23;
} sa_mcmember_record_t;

#elif defined(_BIT_FIELDS_LTOH)

typedef struct sa_mcmember_record_s {
	ib_gid_t	MGID;
	ib_gid_t	PortGID;
	uint32_t	Q_Key;
	ib_lid_t	MLID;
	uint8_t		MTU			:6;
	uint8_t		MTUSelector		:2;
	uint8_t		TClass;
	uint16_t	P_Key;
	uint8_t		Rate			:6;
	uint8_t		RateSelector		:2;
	uint8_t		PacketLifeTime		:6;
	uint8_t		PacketLifeTimeSelector	:2;
	uint32_t	HopLimit		:8;
	uint32_t	FlowLabel		:20;
	uint32_t	SL			:4;
	uint32_t	Reserved		:23;
	uint32_t	ProxyJoin		:1;
	uint32_t	JoinState		:4;
	uint32_t	Scope			:4;
} sa_mcmember_record_t;

#else
#error	One of _BIT_FIELDS_HTOL or _BIT_FIELDS_HTOL must be defined
#endif /* _BIT_FIELDS_HTOL */

#define	SA_MC_COMPMASK_MGID		0x1
#define	SA_MC_COMPMASK_PORTGID		0x2
#define	SA_MC_COMPMASK_QKEY		0x4
#define	SA_MC_COMPMASK_MLID		0x8
#define	SA_MC_COMPMASK_MTUSELECTOR	0x10
#define	SA_MC_COMPMASK_MTU		0x20
#define	SA_MC_COMPMASK_TCLASS		0x40
#define	SA_MC_COMPMASK_PKEY		0x80
#define	SA_MC_COMPMASK_RATESELECTOR	0x100
#define	SA_MC_COMPMASK_RATE		0x200
#define	SA_MC_COMPMASK_PKTLTSELECTOR	0x400
#define	SA_MC_COMPMASK_PKTLT		0x800
#define	SA_MC_COMPMASK_SL		0x1000
#define	SA_MC_COMPMASK_FLOWLABEL	0x2000
#define	SA_MC_COMPMASK_HOPLIMIT		0x4000
#define	SA_MC_COMPMASK_SCOPE		0x8000
#define	SA_MC_COMPMASK_JOINSTATE	0x10000
#define	SA_MC_COMPMASK_PROXYJOIN	0x20000
#define	SA_MC_COMPMASK_RESERVED		0x40000

#define	SA_MC_MTU_SEL_GREATER		0x0
#define	SA_MC_MTU_SEL_LESS		0x1
#define	SA_MC_MTU_SEL_EXACTLY		0x2
#define	SA_MC_MTU_SEL_LARGEST_AVAIL	0x3
#define	SA_MC_MTU_256			0x1
#define	SA_MC_MTU_512			0x2
#define	SA_MC_MTU_1024			0x3
#define	SA_MC_MTU_2048			0x4
#define	SA_MC_MTU_4096			0x5
#define	SA_MC_RATE_SEL_GREATER		0x0
#define	SA_MC_RATE_SEL_LESS		0x1
#define	SA_MC_RATE_SEL_EXACTLY		0x2
#define	SA_MC_RATE_SEL_LARGEST_AVAIL	0x3
#define	SA_MC_RATE_25			0x2
#define	SA_MC_RATE_10			0x3
#define	SA_MC_RATE_30			0x4
#define	SA_MC_LT_SEL_GREATER		0x0
#define	SA_MC_LT_SEL_LESS		0x1
#define	SA_MC_LT_SEL_EXACTLY		0x2
#define	SA_MC_LT_SMALLEST_AVAIL		0x3

/* GUIDInfo Record: Table 177 */
typedef struct sa_guidinfo_record_s {
	ib_lid_t	LID;
	uint8_t		BlockNum;
	uint8_t		Reserved;
	uint32_t	Reserved2;
	sm_guidinfo_t	GUIDInfo;
} sa_guidinfo_record_t;

#define	SA_GUIDINFO_COMPMASK_PORTLID	0x1
#define	SA_GUIDINFO_COMPMASK_BLOCKNUM	0x2
#define	SA_GUIDINFO_COMPMASK_RESERVED	0x4
#define	SA_GUIDINFO_COMPMASK_RESERVEVD2	0x8
#define	SA_GUIDINFO_COMPMASK_GUIDINFO	0x10

/* Trace Record: Table 178 */
typedef struct sa_trace_record_s {
	ib_sn_prefix_t	GIDPrefix;
	uint16_t	IOCGeneration;
	uint8_t		Reserved;
	uint8_t		NodeType;
	uint64_t	NodeID;
	uint64_t	ChassisID;
	uint64_t	EntryPortID;
	uint64_t	ExitPortID;
	uint8_t		EntryPort;
	uint8_t		ExitPort;
} sa_trace_record_t;

#define	SA_TRACE_COMPMASK_GIDPREFIX	0x1
#define	SA_TRACE_COMPMASK_IOCGENERATION	0x2
#define	SA_TRACE_COMPMASK_RESERVED	0x4
#define	SA_TRACE_COMPMASK_NODETYPE	0x8
#define	SA_TRACE_COMPMASK_NODEID	0x10
#define	SA_TRACE_COMPMASK_CHASSISID	0x20
#define	SA_TRACE_COMPMASK_ENTRYPORTID	0x40
#define	SA_TRACE_COMPMASK_EXITPORTID	0x80
#define	SA_TRACE_COMPMASK_ENTRYPORT	0x100
#define	SA_TRACE_COMPMASK_EXITPORT	0x200

/*
 * MultiPath Record: Table 179
 * This structure only includes the constant portion of the multipath record.
 * The multipath record request will contain a variable number of SGIDs and
 * DGIDs at the end of this structure, as specified in the SGIDCount and
 * DGIDCount fields.
 */

#if defined(_BIT_FIELDS_HTOL)
typedef struct sa_mutipath_record_s {
	uint32_t	RawTraffic	:1;	/* raw pkt path */
	uint32_t	Reserved	:3;
	uint32_t	FlowLabel	:20;	/* flow label */
	uint32_t	HopLimit	:8;	/* hop limit */
	uint8_t		TClass;			/* TClass */
	uint8_t		Reversible	:1;	/* reversible path required */
	uint8_t		NumbPath	:7;	/* max num. of paths to ret. */
	uint16_t	P_Key;			/* partition key for path */
	uint16_t	Reserved2	:12;
	uint16_t	SL		:4;	/* service level for path */
	uint8_t		MtuSelector	:2;	/* MTU selector */
	uint8_t		Mtu		:6;	/* required MTU */
	uint8_t		RateSelector	:2;	/* rate selector */
	uint8_t		Rate		:6;	/* value of rate */
	uint8_t		PacketLifeTimeSelector:2; /* pkt life time selector */
	uint8_t		PacketLifeTime	:6;	/* total packet life time */
	uint8_t		Reserved3;
	uint8_t		IndependenceSelector:2;	/* fault-tolerant paths */
	uint8_t		Reserved4	:6;
	uint8_t		SGIDCount;		/* number of SGIDS */
	uint8_t		DGIDCount;		/* number of DGIDS */
	uint8_t		Reserved5[7];
} sa_multipath_record_t;

#elif defined(_BIT_FIELDS_LTOH)

typedef struct sa_mutipath_record_s {
	uint32_t	HopLimit	:8;	/* hop limit */
	uint32_t	FlowLabel	:20;	/* flow label */
	uint32_t	Reserved	:3;
	uint32_t	RawTraffic	:1;	/* raw pkt path */
	uint8_t		TClass;			/* TClass */
	uint8_t		NumbPath	:7;	/* max num. of paths to ret. */
	uint8_t		Reversible	:1;	/* reversible path required */
	uint16_t	P_Key;			/* partition key for path */
	uint16_t	SL		:4;	/* service level for path */
	uint16_t	Reserved2	:12;
	uint8_t		Mtu		:6;	/* required MTU */
	uint8_t		MtuSelector	:2;	/* MTU selector */
	uint8_t		Rate		:6;	/* value of rate */
	uint8_t		RateSelector	:2;	/* rate selector */
	uint8_t		PacketLifeTime	:6;	/* total packet life time */
	uint8_t		PacketLifeTimeSelector:2; /* pkt life time selector */
	uint8_t		Reserved3;
	uint8_t		Reserved4	:6;
	uint8_t		IndependenceSelector:2;	/* fault-tolerant paths */
	uint8_t		SGIDCount;		/* number of SGIDS */
	uint8_t		DGIDCount;		/* number of DGIDS */
	uint8_t		Reserved5[7];
} sa_multipath_record_t;

#else
#error	One of _BIT_FIELDS_HTOL or _BIT_FIELDS_HTOL must be defined
#endif /* _BIT_FIELDS_HTOL */

#define	SA_MPR_COMPMASK_RAWTRAFFIC	0x1
#define	SA_MPR_COMPMASK_RESERVED	0x2
#define	SA_MPR_COMPMASK_FLOWLABEL	0x4
#define	SA_MPR_COMPMASK_HOPLIMIT	0x8
#define	SA_MPR_COMPMASK_TCLASS		0x10
#define	SA_MPR_COMPMASK_REVERSIBLE	0x20
#define	SA_MPR_COMPMASK_NUMBPATH	0x40
#define	SA_MPR_COMPMASK_PKEY		0x80
#define	SA_MPR_COMPMASK_RESERVED2	0x100
#define	SA_MPR_COMPMASK_SL		0x200
#define	SA_MPR_COMPMASK_MTUSELECTOR	0x400
#define	SA_MPR_COMPMASK_MTU		0x800
#define	SA_MPR_COMPMASK_RATESELECTOR	0x1000
#define	SA_MPR_COMPMASK_RATE		0x2000
#define	SA_MPR_COMPMASK_PKTLTSELECTOR	0x4000
#define	SA_MPR_COMPMASK_PKTLT		0x8000
#define	SA_MPR_COMPMASK_RESERVED3	0x10000
#define	SA_MPR_COMPMASK_INDEPSEL	0x20000
#define	SA_MPR_COMPMASK_RESERVED4	0x40000
#define	SA_MPR_COMPMASK_SGIDCOUNT	0x80000
#define	SA_MPR_COMPMASK_DGIDCOUNT	0x100000
#define	SA_MPR_COMPMASK_RESERVED5	0x200000

#ifdef __cplusplus
}
#endif

#endif	/* _SYS_IB_MGT_SA_RECS_H */
