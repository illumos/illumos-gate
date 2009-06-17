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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#ifndef _SYS_IB_MGT_SM_ATTR_H
#define	_SYS_IB_MGT_SM_ATTR_H

/*
 * This file contains the definitions of the various attributes specified
 * in IB spec volume 1, release 1.1, chapter 14.
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <sys/ib/ib_types.h>
#include <sys/ib/mgt/ib_mad.h>

#define	SM_MAX_DR_PATH		64	/* max ports in a DR path */

/*
 * LID routed smp class header
 */
typedef struct sm_lid_class_hdr_s {
	uint64_t	M_Key;
	uint8_t		Reserved[32];
} sm_lid_class_hdr_t;

/*
 * Directed route smp mad header
 */
typedef struct sm_dr_mad_hdr_s {
	/* Common MAD Header1: 4 bytes, bytes 0-3 of header */
	uint8_t		BaseVersion;	/* version of MAD base format */
	uint8_t		MgmtClass;	/* class of operation */
	uint8_t		ClassVersion;	/* version of MAD class format */
	uint8_t		R_Method;	/* response bit & method to   */
					/* perform based on mgmtclass */

	uint16_t	D_Status;	/* direction, status unused */
	uint8_t		HopPointer;	/* index into Initial/Return Paths */
	uint8_t		HopCount;	/* number of directed route hops */


	/* Common MAD Header2: 16 bytes, bytes 8-23 of header */
	uint64_t	TransactionID;	/* transaction id */
	uint16_t	AttributeID;	/* defines class spec. objects */
	uint16_t	Reserved;
	uint32_t	AttributeModifier; /* further scope to attributes */
} sm_dr_mad_hdr_t;

/* Direction bit */
#define	SM_DR_SMP_D_OUT		0x0000	/* SMP is outbound from SM */
#define	SM_DR_SMP_D_IN		0x8000	/* SMP is inbound to SM */
#define	SM_DR_SMP_D_MASK	0x8000	/* direction mask */

#define	SM_DR_SMP_STATUS_MASK	0x7FFF

/*
 * Direct route smp class header:
 */
typedef struct sm_dr_class_hdr_s {
	uint64_t	M_Key;
	ib_lid_t	DrSLID;
	ib_lid_t	DrDLID;
	uint8_t		Reserved[28];
} sm_dr_class_hdr_t;

typedef struct sm_dr_data_s {
	uint8_t		Data[64];
	uint8_t		InitialPath[SM_MAX_DR_PATH];
	uint8_t		ReturnPath[SM_MAX_DR_PATH];
} sm_dr_data_t;

/* Traps: Table 118 */
#define	SM_GID_IN_SERVICE_TRAP			64
#define	SM_GID_OUT_OF_SERVICE_TRAP		65
#define	SM_MGID_CREATED_TRAP			66
#define	SM_MGID_DESTROYED_TRAP			67
#define	SM_LINK_STATE_CHANGED_TRAP		128
#define	SM_LINK_INTEGRITY_THRESHOLD_TRAP	129
#define	SM_BUFFER_OVERRUN_THRESHOLD_TRAP	130
#define	SM_WATCHDOG_TIMER_EXPIRED_TRAP		131
#define	SM_CAP_MASK_CHANGED_TRAP		144
#define	SM_SYS_IMG_GUID_CHANGED_TRAP		145
#define	SM_BAD_MKEY_TRAP			256
#define	SM_BAD_PKEY_TRAP			257
#define	SM_BAD_QKEY_TRAP			258
#define	SM_BAD_SWITCH_PKEY_TRAP			259

/*
 * Notice Data details for various sm traps
 */
/* Traps 64, 65, 66,and 67: Table 119 */
typedef struct sm_trap_64_s {
	uint8_t		Reserved[6];
	ib_gid_t	GIDADDR;		/* global identifier */
	uint8_t		Padding[32];
} sm_trap_64_t;

typedef sm_trap_64_t	sm_trap_65_t;
typedef sm_trap_64_t	sm_trap_66_t;
typedef sm_trap_64_t	sm_trap_67_t;

/* Trap 128: Table 120 */
typedef struct sm_trap_128_s {
	ib_lid_t	LIDADDR;		/* trap generator's LID */
	uint8_t		Padding[52];
} sm_trap_128_t;

/* Traps 129, 130, and 131: Table 121 */
typedef struct sm_trap_129_s {
	uint16_t	Reserved;
	ib_lid_t	LIDADDR;		/* generator's LID */
	uint8_t		PORTNO;			/* generator's port */
	uint8_t		Padding[49];
} sm_trap_129_t;

typedef sm_trap_129_t	sm_trap_130_t;
typedef sm_trap_129_t	sm_trap_131_t;

/* Trap 144: Table 122 */
typedef struct sm_trap_144_s {
	uint16_t	Reserved;
	ib_lid_t	LIDADDR;		/* generator's LID */
	uint16_t	Reserved2;
	uint32_t	CAPABILITYMASK;		/* generator's CapMask */
	uint8_t		Padding[44];
} sm_trap_144_t;

/* Trap 145: Table 123 */
typedef struct sm_trap_145_s {
	uint16_t	Reserved;
	ib_lid_t	LIDADDR;
	uint16_t	Reserved2;
	ib_guid_t	SYSTEMIMAGEGUID;	/* generator's SysImage GUID */
	uint8_t		Padding[40];
} sm_trap_145_t;

/* Trap 256: Table 124 */
#if defined(_BIT_FIELDS_HTOL)
typedef struct sm_trap_256_s {
	uint16_t	Reserved;
	ib_lid_t	LIDADDR;		/* generator's LID */
	uint16_t	Reserved1;
	uint8_t		METHOD;			/* method */
	uint8_t		Reserved2;
	uint16_t	ATTRIBUTEID;		/* attribute casuing the trap */
	uint32_t	ATTRIBUTEMODIFIER;	/* modifier for the attrib */
	uint64_t	MKEY;
	uint8_t		DRSLID;			/* SLID of SMP causing notice */
	uint8_t		DRNotice	:1;	/* notice from a dr SMP */
	uint8_t		DRPathTruncated	:1;	/* return path is truncated */
	uint8_t		DRHopCount	:6;	/* num bytes in return path */
	uint8_t		DRNoticeReturnPath[30];	/* return path from the SMP */
} sm_trap_256_t;

#elif defined(_BIT_FIELDS_LTOH)

typedef struct sm_trap_256_s {
	uint16_t	Reserved;
	ib_lid_t	LIDADDR;		/* generator's LID */
	uint16_t	Reserved1;
	uint8_t		METHOD;			/* method */
	uint8_t		Reserved2;
	uint16_t	ATTRIBUTEID;		/* attribute casuing the trap */
	uint32_t	ATTRIBUTEMODIFIER;	/* modifier for the attrib */
	uint64_t	MKEY;
	uint8_t		DRSLID;			/* SLID of SMP causing notice */
	uint8_t		DRHopCount	:6;	/* num bytes in return path */
	uint8_t		DRPathTruncated	:1;	/* return path is truncated */
	uint8_t		DRNotice	:1;	/* notice from a dr SMP */
	uint8_t		DRNoticeReturnPath[30];	/* return path from the SMP */
} sm_trap_256_t;
#else
#error	One of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif /* _BIT_FIELDS_HTOL */

/* Traps 257 and 258: Table 125 */
#if defined(_BIT_FIELDS_HTOL)
typedef struct sm_trap_257_s {
	uint16_t	Reserved;
	ib_lid_t	LIDADDR1;		/* see spec description */
	ib_lid_t	LIDADDR2;
	uint32_t	KEY;			/* qkey or pkey */
	uint32_t	SL		:4;	/* sl for the trap */
	uint32_t	Reserved2	:4;	/* reserved */
	uint32_t	QP		:24;	/* queue pair */
	uint32_t	Reserved3	:8;
	uint32_t	QP2		:24;	/* queue pair */
	ib_gid_t	GIDADDR1;		/* see spec description */
	ib_gid_t	GIDADDR2;
	uint8_t		Padding[4];
} sm_trap_257_t;

#elif defined(_BIT_FIELDS_LTOH)

typedef struct sm_trap_257_s {
	uint16_t	Reserved;
	ib_lid_t	LIDADDR1;		/* see spec description */
	ib_lid_t	LIDADDR2;
	uint32_t	KEY;			/* qkey or pkey */
	uint32_t	QP		:24;	/* queue pair */
	uint32_t	Reserved2	:4;	/* reserved */
	uint32_t	SL		:4;	/* sl for the trap */
	uint32_t	QP2		:24;	/* queue pair */
	uint32_t	Reserved3	:8;
	ib_gid_t	GIDADDR1;		/* see spec description */
	ib_gid_t	GIDADDR2;
	uint8_t		Padding[4];
} sm_trap_257_t;
#else
#error	One of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif /* _BIT_FIELDS_HTOL */

typedef	sm_trap_257_t	sm_trap_258_t;

/* Trap 259: Table 126 */
#if defined(_BIT_FIELDS_HTOL)
typedef	struct sm_trap_259_s {
	uint16_t	DataValid;		/* validity of optional data */
	ib_lid_t	LIDADDR1;		/* see spec description */
	ib_lid_t	LIDADDR2;
	uint16_t	PKEY;			/* pkey */
	uint32_t	SL		:4;	/* service level */
	uint32_t	Reserved	:4;
	uint32_t	QP1		:24;	/* queue pair */
	uint32_t	Reserved8	:8;
	uint32_t	QP2		:24;	/* queue pair */
	ib_gid_t	GIDADDR1;		/* see spec description */
	ib_gid_t	GIDADDR2;
	ib_lid_t	SWLIDADDR;		/* lid of switch */
	uint8_t		PORTNO;			/* port number */
	uint8_t		Padding[3];
} sm_trap_259_t;

#elif defined(_BIT_FIELDS_LTOH)

typedef	struct sm_trap_259_s {
	uint16_t	DataValid;		/* validity of optional data */
	ib_lid_t	LIDADDR1;		/* see spec description */
	ib_lid_t	LIDADDR2;
	uint16_t	PKEY;			/* pkey */
	uint32_t	QP1		:24;	/* queue pair */
	uint32_t	Reserved	:4;
	uint32_t	SL		:4;	/* service level */
	uint32_t	QP2		:24;	/* queue pair */
	uint32_t	Reserved8	:8;
	ib_gid_t	GIDADDR1;		/* see spec description */
	ib_gid_t	GIDADDR2;
	ib_lid_t	SWLIDADDR;		/* lid of switch */
	uint8_t		PORTNO;			/* port number */
	uint8_t		Padding[3];
} sm_trap_259_t;
#else
#error	One of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif /* _BIT_FIELDS_HTOL */

/*
 * NodeDescription: Table 127
 * NodeDescription is applicable to all ports of a node.
 */
typedef struct sm_nodedesc_s {
	uint8_t		NodeString[64];		/* description string */
} sm_nodedesc_t;

/*
 * NodeInfo: Table 128
 * The value of some NodeInfo components varies by port within a node.
 */
#if defined(_BIT_FIELDS_HTOL)
typedef struct sm_nodeinfo_s {
	uint8_t		BaseVersion;		/* supported MAD base version */
	uint8_t		ClassVersion;		/* support SMP version	*/
	uint8_t		NodeType;		/* node type(CA, switch, etc) */
	uint8_t		NumPorts;		/* # of phys ports on node    */
	ib_guid_t	SystemImageGUID;	/* GUID associating this node */
						/* with nodes controlled by   */
						/* common supervisory code    */
	ib_guid_t	NodeGUID;		/* GUID of the node itself    */
	ib_guid_t	PortGUID;		/* GUID of this port */
	uint16_t	PartitionCap;		/* # of entries in part. tbl. */
	uint16_t	DeviceID;		/* device ID info	*/
	uint32_t	Revision;		/* device revision	*/
	uint32_t	LocalPortNum	:8;	/* link port # SMP came in on */
	uint32_t	VendorID	:24;	/* device vendor, per IEEE */
} sm_nodeinfo_t;

#elif defined(_BIT_FIELDS_LTOH)

typedef struct sm_nodeinfo_s {
	uint8_t		BaseVersion;		/* supported MAD base version */
	uint8_t		ClassVersion;		/* support SMP version	*/
	uint8_t		NodeType;		/* node type(CA, switch, etc) */
	uint8_t		NumPorts;		/* # of phys ports on node    */
	ib_guid_t	SystemImageGUID;	/* GUID associating this node */
						/* with nodes controlled by   */
						/* common supervisory code    */
	ib_guid_t	NodeGUID;		/* GUID of the node itself    */
	ib_guid_t	PortGUID;		/* GUID of this port */
	uint16_t	PartitionCap;		/* # of entries in part. tbl. */
	uint16_t	DeviceID;		/* device ID info	*/
	uint32_t	Revision;		/* device revision	*/
	uint32_t	VendorID	:24;	/* device vendor, per IEEE */
	uint32_t	LocalPortNum	:8;	/* link port # SMP came in on */
} sm_nodeinfo_t;
#else
#error	One of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif /* _BIT_FIELDS_HTOL */

/* Defines and Masks that go with NodeInfo */
#define	SM_NODE_TYPE_CA				0x01
#define	SM_NODE_TYPE_SWITCH			0x02
#define	SM_NODE_TYPE_ROUTER			0x03

/* SwitchInfo: Table 129 */
#if defined(_BIT_FIELDS_HTOL)
typedef struct sm_switchinfo_s {
	uint16_t	LinearFDBCap;		/* max # of lin FDB entries */
	uint16_t	RandomFDBCap;		/* max # of ran FDB entries */
	uint16_t	MulticastFDBCap;	/* max # of mc  FDB entries */
	uint16_t	LinearFDBTop;		/* top of the linear FDB */
	uint8_t		DefaultPort;		/* port when DLID not in FDB */
	uint8_t		DefaultMulticastPrimaryPort; /* mcast port when DLID */
						/* not in FDB */
	uint8_t		DefaultMulticastNotPrimaryPort;	/* mcast port when */
						/* pkts from def port */
						/* have DLID not in FDB */
	uint8_t		LifeTimeValue	:5;	/* time pkt can live in sw */
	uint8_t		PortStateChange :1; 	/* change in port state value */
	uint8_t		Reserved	:2;
	uint16_t	LIDsPerPort;		/* max # of LID/LMCs per port */
	uint16_t	PartitionEnforcementCap; /* max entries in p. enf tbl */
	uint8_t		PartitionChecks	:4;	/* switch enforcement knobs */
	uint8_t		EnhancedPort0	:1;	/* enhanced port 0 supported */
	uint8_t		Reserved2	:3;
} sm_switchinfo_t;

#elif defined(_BIT_FIELDS_LTOH)

typedef struct sm_switchinfo_s {
	uint16_t	LinearFDBCap;		/* max # of lin FDB entries */
	uint16_t	RandomFDBCap;		/* max # of ran FDB entries */
	uint16_t	MulticastFDBCap;	/* max # of mc  FDB entries */
	uint16_t	LinearFDBTop;		/* top of the linear FDB */
	uint8_t		DefaultPort;		/* port when DLID not in FDB */
	uint8_t		DefaultMulticastPrimaryPort; /* mcast port when DLID */
						/* not in FDB */
	uint8_t		DefaultMulticastNotPrimaryPort;	/* mcast port when */
						/* pkts from def port */
						/* have DLID not in FDB */
	uint8_t		Reserved	:2;
	uint8_t		PortStateChange :1; 	/* change in port state value */
	uint8_t		LifeTimeValue	:5;	/* time pkt can live in sw */
	uint16_t	LIDsPerPort;		/* max # of LID/LMCs per port */
	uint16_t	PartitionEnforcementCap; /* max entries in p. enf tbl */
	uint8_t		Reserved2	:3;
	uint8_t		EnhancedPort0	:1;	/* enhanced port 0 supported */
	uint8_t		PartitionChecks	:4;	/* switch enforcement knobs */
} sm_switchinfo_t;
#else
#error	One of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif /* _BIT_FIELDS_HTOL */

/* Defines and Masks that go with SwitchInfo */
#define	SM_PORT_STATE_CHANGE_CLEAR		0x1
#define	SM_SWITCH_PART_ENF_IN			0x8
#define	SM_SWITCH_PART_ENF_IN_MASK		0x8
#define	SM_SWITCH_PART_ENF_OUT			0x4
#define	SM_SWITCH_PART_ENF_OUT_MASK		0x4
#define	SM_SWITCH_FILTER_RAW_IN			0x2
#define	SM_SWITCH_FILTER_RAW_IN_MASK		0x2
#define	SM_SWITCH_FILTER_RAW_OUT		0x1
#define	SM_SWITCH_FILTER_RAW_OUT_MASK		0x1

/* GUIDInfo: Table 130 */
typedef struct sm_guidinfo_s {
	ib_guid_t	GUIDBlocks[8];
} sm_guidinfo_t;

/* defines that go with guid info */
#define	SM_GUIDINFO_BLOCK_MAX			31

/*
 * PortInfo: Table 132
 * PortInfo is applicable to all ports of a node.
 */
#if defined(_BIT_FIELDS_HTOL)
typedef struct sm_portinfo_s {
	uint64_t	M_Key;			/* M_key		*/
	ib_sn_prefix_t	GidPrefix;		/* Gid prefix		*/
	ib_lid_t	LID;			/* base LID of the port	*/
	ib_lid_t	MasterSMLID;		/* LID of the master SM	*/
	uint32_t	CapabilityMask;		/* Capability Mask	*/
	uint16_t	DiagCode;		/* diag code		*/
	uint16_t	M_KeyLeasePeriod;	/* M_key lease period	*/
	uint8_t		LocalPortNum;		/* port which recvd the MAD */
	uint8_t		LinkWidthEnabled;	/* link width(s) enabled */
	uint8_t		LinkWidthSupported;	/* widths supported by port  */
	uint8_t		LinkWidthActive;	/* Currently active width    */
	uint8_t		LinkSpeedSupported:4;	/* link speed supported */
	uint8_t		PortState	:4;	/* port state */
	uint8_t		PortPhysicalState:4;	/* port physical state */
	uint8_t		LinkDownDefaultState:4;   /* see spec description */
	uint8_t		M_KeyProtectBits:2;	/* M-key protection bits */
	uint8_t		Reserved	:3;
	uint8_t		LMC		:3;	/* LID mask count */
	uint8_t		LinkSpeedActive	:4;	/* current active link speed */
	uint8_t		LinkSpeedEnabled:4;	/* enabled link speed */
	uint8_t		NeighborMTU	:4;	/* Active max MTU for port */
	uint8_t		MasterSMSL	:4;	/* admin SL of master SM */
	uint8_t		VLCap		:4;	/* virtual lanes supported */
	uint8_t		InitType	:4;	/* type of init requested */
	uint8_t		VLHighLimit;		/* VL high pri limit	*/
	uint8_t		VLArbitrationHighCap;	/* max high pri entries in  */
						/* VL arbitration table */
	uint8_t		VLArbitrationLowCap;	/* max low pri entries  */
	uint8_t		InitTypeReply	:4;	/* type of init performed */
	uint8_t		MTUCap		:4;	/* max MTU supported */
	uint8_t		VLStallCount	:3;	/* # pkts to enter stall st. */
	uint8_t		HOQLife		:5;	/* time pkt can live at HOQ */
	uint8_t		OperationalVLs	:4;	/* virtual lanes operational */
	uint8_t		PartitionChecks	:4;	/* port enforcement knbos */
	uint16_t	M_KeyViolations;	/* count of M_key violations */
	uint16_t	P_KeyViolations;	/* count of P_key violations */
	uint16_t	Q_KeyViolations;	/* count of Q_key violations */
	uint8_t		GUIDCap;		/* number of GUIDs supported */
	uint8_t		ClientRereg	:1;	/* Client ReReg supported */
	uint8_t		Reserved2	:2;
	uint8_t		SubnetTimeOut	:5;	/* defines subnet prop. dely */
	uint8_t		Reserved3	:3;
	uint8_t		RespTimeValue	:5;	/* defines resp time to SMPs */
	uint8_t		LocalPhyErrors	:4;	/* threshold for errors */
	uint8_t		OverrunErrors	:4;	/* threshold for errors */
} sm_portinfo_t;

#elif defined(_BIT_FIELDS_LTOH)

typedef struct sm_portinfo_s {
	uint64_t	M_Key;			/* M_key		*/
	ib_sn_prefix_t	GidPrefix;		/* Gid prefix		*/
	ib_lid_t	LID;			/* base LID of the port	*/
	ib_lid_t	MasterSMLID;		/* LID of the master SM	*/
	uint32_t	CapabilityMask;		/* Capability Mask	*/
	uint16_t	DiagCode;		/* diag code		*/
	uint16_t	M_KeyLeasePeriod;	/* M_key lease period	*/
	uint8_t		LocalPortNum;		/* port which recvd the MAD */
	uint8_t		LinkWidthEnabled;	/* link width(s) enabled */
	uint8_t		LinkWidthSupported;	/* widths supported by port  */
	uint8_t		LinkWidthActive;	/* Currently active width    */
	uint8_t		PortState	:4;	/* port state */
	uint8_t		LinkSpeedSupported:4;	/* link speed supported */
	uint8_t		LinkDownDefaultState:4;   /* see spec description */
	uint8_t		PortPhysicalState:4;	/* port physical state */
	uint8_t		LMC		:3;	/* LID mask count */
	uint8_t		Reserved	:3;
	uint8_t		M_KeyProtectBits:2;	/* M-key protection bits */
	uint8_t		LinkSpeedEnabled:4;	/* enabled link speed */
	uint8_t		LinkSpeedActive	:4;	/* current active link speed */
	uint8_t		MasterSMSL	:4;	/* admin SL of master SM */
	uint8_t		NeighborMTU	:4;	/* Active max MTU for port */
	uint8_t		InitType	:4;	/* type of init requested */
	uint8_t		VLCap		:4;	/* virtual lanes supported */
	uint8_t		VLHighLimit;		/* VL high pri limit	*/
	uint8_t		VLArbitrationHighCap;	/* max high pri entries in  */
						/* VL arbitration table */
	uint8_t		VLArbitrationLowCap;	/* max low pri entries  */
	uint8_t		MTUCap		:4;	/* max MTU supported */
	uint8_t		InitTypeReply	:4;	/* type of init performed */
	uint8_t		HOQLife		:5;	/* time pkt can live at HOQ */
	uint8_t		VLStallCount	:3;	/* # pkts to enter stall st. */
	uint8_t		PartitionChecks	:4;	/* port enforcement knbos */
	uint8_t		OperationalVLs	:4;	/* virtual lanes operational */
	uint16_t	M_KeyViolations;	/* count of M_key violations */
	uint16_t	P_KeyViolations;	/* count of P_key violations */
	uint16_t	Q_KeyViolations;	/* count of Q_key violations */
	uint8_t		GUIDCap;		/* number of GUIDs supported */
	uint8_t		SubnetTimeOut	:5;	/* defines subnet prop. dely */
	uint8_t		Reserved2	:2;
	uint8_t		ClientRereg	:1;	/* Client ReReg supported */
	uint8_t		RespTimeValue	:5;	/* defines resp time to SMPs */
	uint8_t		Reserved3	:3;
	uint8_t		OverrunErrors	:4;	/* threshold for errors */
	uint8_t		LocalPhyErrors	:4;	/* threshold for errors */
} sm_portinfo_t;
#else
#error	One of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif /* _BIT_FIELDS_HTOL */

/* Defines and Masks that go with PortInfo */
#define	SM_CAP_MASK_IS_SM			0x00000002
#define	SM_CAP_MASK_IS_NOTICE_SUPPD		0x00000004
#define	SM_CAP_MASK_IS_TRAP_SUPPD		0x00000008
#define	SM_CAP_MASK_IS_RESET_SUPPD		0x00000010
#define	SM_CAP_MASK_IS_APM_SUPPD		0x00000020
#define	SM_CAP_MASK_IS_SLMAPP_SUPPD		0x00000040
#define	SM_CAP_MASK_IS_NVRAM_MKEY		0x00000080
#define	SM_CAP_MASK_IS_NVRAM_PKEY		0x00000100
#define	SM_CAP_MASK_IS_LEDINFO_SUPPD		0x00000200
#define	SM_CAP_MASK_IS_SM_DISABLED		0x00000400
#define	SM_CAP_MASK_IS_SYSIMG_GUID_DISABLED	0x00000800
#define	SM_CAP_MASK_IS_PKEY_SW_TRAP_DISABLED	0x00001000
#define	SM_CAP_MASK_IS_CM_SUPPD			0x00010000
#define	SM_CAP_MASK_IS_SNMP_SUPPD		0x00020000
#define	SM_CAP_MASK_IS_DM_SUPPD			0x00080000
#define	SM_CAP_MASK_IS_VM_SUPPD			0x00100000
#define	SM_CAP_MASK_IS_DR_NOTICE_SUPPD		0x00200000
#define	SM_CAP_MASK_IS_CAP_MASK_NOTICE_SUPPD	0x00400000
#define	SM_CAP_MASK_IS_BOOT_MGMT_SUPPD		0x00800000
#define	SM_CAP_MASK_IS_CLNT_REREG_SUPPD		0x02000000

/* Standard Encoding of DiagCode Bits 3-0: Table 133 */
#define	SM_DIAG_CODE_PORT_READY			0x0
#define	SM_DIAG_CODE_PERFORMING_SELF_TEST	0x1
#define	SM_DIAG_CODE_INITIALIZING		0x2
#define	SM_DIAG_CODE_SOFT_ERROR			0x3
#define	SM_DIAG_CODE_HARD_ERROR			0x4

#define	SM_LINK_WIDTH_ENABLED_NOP		0x00
#define	SM_LINK_WIDTH_ENABLED_1X		0x01
#define	SM_LINK_WIDTH_ENABLED_4X		0x02
#define	SM_LINK_WIDTH_ENABLED_1X_4X		0x03
#define	SM_LINK_WIDTH_ENABLED_12X		0x08
#define	SM_LINK_WIDTH_ENABLED_1X_12X		0x09
#define	SM_LINK_WIDTH_ENABLED_4X_12X		0x0A
#define	SM_LINK_WIDTH_ENABLED_1X_4X_12X		0x0B
#define	SM_LINK_WIDTH_ENABLED_SUPPORTED		0xFF

#define	SM_LINK_WIDTH_SUPP_1X			0x01
#define	SM_LINK_WIDTH_SUPP_1X_4X		0x03
#define	SM_LINK_WIDTH_SUPP_1X_4X_12X		0x0B

#define	SM_LINK_WIDTH_ACTIVE_1X			0x01
#define	SM_LINK_WIDTH_ACTIVE_4X			0x02
#define	SM_LINK_WIDTH_ACTIVE_8X			0x04
#define	SM_LINK_WIDTH_ACTIVE_12X		0x08

#define	SM_LINK_SPEED_SUPP_2_5_GBPS		0x1

#define	SM_PORT_STATE_NOP			0x0
#define	SM_PORT_STATE_DOWN			0x1
#define	SM_PORT_STATE_INITIALIZE		0x2
#define	SM_PORT_STATE_ARMED			0x3
#define	SM_PORT_STATE_ACTIVE			0x4

#define	SM_PORT_PHYS_STATE_NOP			0x0
#define	SM_PORT_PHYS_STATE_SLEEP		0x1
#define	SM_PORT_PHYS_STATE_POLLING		0x2
#define	SM_PORT_PHYS_STATE_DISABLED		0x3
#define	SM_PORT_PHYS_STATE_TRAINING		0x4
#define	SM_PORT_PHYS_STATE_LINK_UP		0x5
#define	SM_PORT_PHYS_STATE_LINK_REC		0x6

#define	SM_LINK_DOWN_DEFAULT_NOP		0x0
#define	SM_LINK_DOWN_DEFAULT_SLEEP		0x1
#define	SM_LINK_DOWN_DEFAULT_POLLING		0x2

/* MKey Protection Levels: Table 115 */
#define	SM_MKEY_PROT_BITS_ALL_SUCCEED		0x0
#define	SM_MKEY_PROT_BITS_GETRESP_RESETS	0x1
#define	SM_MKEY_PROT_BITS_SET_FAIL		0x2
#define	SM_MKEY_PROT_BITS_SET_FAILX		0x3

#define	SM_LINK_SPEED_ACTIVE_2_5_GBPS		0x1
#define	SM_LINK_SPEED_ACTIVE_5_GBPS		0x2
#define	SM_LINK_SPEED_ACTIVE_10_GBPS		0x4

#define	SM_LINK_SPEED_ENABLED_NOP		0x0
#define	SM_LINK_SPEED_ENABLED_2_5_GBPS		0x1
#define	SM_LINK_SPEED_ENABLED_SUPP_VALUE	0xF

#define	SM_NEIGHBOR_MTU_256			0x1
#define	SM_NEIGHBOR_MTU_512			0x2
#define	SM_NEIGHBOR_MTU_1024			0x3
#define	SM_NEIGHBOR_MTU_2048			0x4
#define	SM_NEIGHBOR_MTU_4096			0x5

#define	SM_VL_CAP_VL0				0x1
#define	SM_VL_CAP_VL0_VL1			0x2
#define	SM_VL_CAP_VL0_VL3			0x3
#define	SM_VL_CAP_VL0_VL7			0x4
#define	SM_VL_CAP_VL0_VL14			0x5

#define	SM_INIT_TYPE_NO_LOAD			0x1
#define	SM_INIT_TYPE_PRESERVE_CONTENT		0x2
#define	SM_INIT_TYPE_PRESERVE_PRESENCE		0x4
#define	SM_INIT_TYPE_DO_NOT_RESUSCITATE		0x8

#define	SM_INIT_TYPE_REPLY_NO_LOAD_REPLY	0x1
#define	SM_INIT_TYPE_PRESERVE_CONTENT_REPLY	0x2
#define	SM_INIT_TYPE_PRESERVE_PRESENCE_REPLY	0x4

#define	SM_MTU_CAP_256				0x1
#define	SM_MTU_CAP_512				0x2
#define	SM_MTU_CAP_1024				0x3
#define	SM_MTU_CAP_2048				0x4
#define	SM_MTU_CAP_4096				0x5

#define	SM_HOQ_LIFE_INFINITY			19  /* from IB spec 18.2.5.4 */

#define	SM_OPERATIONAL_VLS_NOP			0x0
#define	SM_OPERATIONAL_VLS_VL0			0x1
#define	SM_OPERATIONAL_VLS_VL0_VL1		0x2
#define	SM_OPERATIONAL_VLS_VL0_VL3		0x3
#define	SM_OPERATIONAL_VLS_VL0_VL7		0x4
#define	SM_OPERATIONAL_VLS_VLO_VL14		0x5

#define	SM_PART_ENF_IN_BOUND			0x8
#define	SM_PART_ENF_OUT_BOUND			0x4
#define	SM_FILTER_RAW_IN_BOUND			0x2
#define	SM_FILTER_RAW_OUT_BOUND			0x1

/* P_Key Table: Table 134 */
typedef struct sm_pkey_table_s {
	uint16_t P_KeyTableBlocks[32];	/* List of 32 P_Key Block Elements */
} sm_pkey_table_t;

/* P_Key Block Element: Table 135 */
#if defined(_BIT_FIELDS_HTOL)
typedef struct sm_pkey_block_element_s {
	uint16_t MembershipType	:1;	/* 0 is limited; 1 is full type */
	uint16_t P_KeyBase	:15;	/* base value of P_Key */
} sm_pkey_block_element_t;

#elif defined(_BIT_FIELDS_LTOH)

typedef struct sm_pkey_block_element_s {
	uint16_t P_KeyBase	:15;	/* base value of P_Key */
	uint16_t MembershipType	:1;	/* 0 is limited; 1 is full type */
} sm_pkey_block_element_t;
#else
#error	One of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif /* _BIT_FIELDS_HTOL */

/*
 * SLtoVLMapping Table: Table 136
 * Each field specifies the VL onto which packets using that SL are dropped.
 */
#if defined(_BIT_FIELDS_HTOL)
typedef struct sm_SLtoVL_mapping_table_s {
	uint8_t	SL0toVL			:4;
	uint8_t	SL1toVL			:4;
	uint8_t	SL2toVL			:4;
	uint8_t	SL3toVL			:4;
	uint8_t	SL4toVL			:4;
	uint8_t	SL5toVL			:4;
	uint8_t	SL6toVL			:4;
	uint8_t	SL7toVL			:4;
	uint8_t	SL8toVL			:4;
	uint8_t	SL9toVL			:4;
	uint8_t	SL10toVL		:4;
	uint8_t	SL11toVL		:4;
	uint8_t	SL12toVL		:4;
	uint8_t	SL13toVL		:4;
	uint8_t	SL14toVL		:4;
	uint8_t	SL15toVL		:4;
} sm_SLtoVL_mapping_table_t;

#elif defined(_BIT_FIELDS_LTOH)

typedef struct sm_SLtoVL_mapping_table_s {
	uint8_t	SL1toVL			:4;
	uint8_t	SL0toVL			:4;
	uint8_t	SL3toVL			:4;
	uint8_t	SL2toVL			:4;
	uint8_t	SL5toVL			:4;
	uint8_t	SL4toVL			:4;
	uint8_t	SL7toVL			:4;
	uint8_t	SL6toVL			:4;
	uint8_t	SL9toVL			:4;
	uint8_t	SL8toVL			:4;
	uint8_t	SL11toVL		:4;
	uint8_t	SL10toVL		:4;
	uint8_t	SL13toVL		:4;
	uint8_t	SL12toVL		:4;
	uint8_t	SL15toVL		:4;
	uint8_t	SL14toVL		:4;
} sm_SLtoVL_mapping_table_t;
#else
#error	One of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif /* _BIT_FIELDS_HTOL */

/* VL/Weight Block Element: Table 138 */
typedef struct sm_VL_weight_block_s {
	uint8_t	Reserved		:4;
	uint8_t	VL			:4; /* VL assoc. with this element */
	uint8_t	Weight;			   /* weight assoc. with this element */
} sm_VL_weight_block_t;

/* VLArbitration Table: Table 137 */
typedef struct sm_VLarb_table_s {
	sm_VL_weight_block_t VLWeightPairs[32];
} sm_VLarb_table_t;

/* Defines and masks that go with VLArbitrationTable & address modifier */
#define	SM_LOW_PRI_VL_ARB_LOWER_32		0x1
#define	SM_LOW_PRI_VL_ARB_UPPER_32		0x2
#define	SM_HI_PRI_VL_ARB_LOWER_32		0x3
#define	SM_HI_PRI_VL_ARB_UPPER_32		0x4

/* Defines that go with the linear forwarding table */
#define	SM_LFT_BLOCK_MAX			767
#define	SM_LFT_PORTS_PER_BLOCK			64

/* Linear Forwarding Table: Table 139 */
typedef struct sm_linear_forwarding_table_s {
	uint8_t	PortBlocks[64];
} sm_linear_forwarding_table_t;

/* LID/Port Block Element: Table 142 */
#if defined(_BIT_FIELDS_HTOL)
typedef struct sm_lid_port_block_s {
	ib_lid_t	LID;		    /* base LID */
	uint8_t		Valid		:1; /* this LID/Port pair is valid */
	uint8_t		LMC		:3; /* the LMC of this lid */
	uint8_t		Reserved	:4;
	uint8_t		Port;		    /* port to forward entries to */
} sm_lid_port_block_t;

#elif defined(_BIT_FIELDS_LTOH)

typedef struct sm_lid_port_block_s {
	ib_lid_t	LID;		    /* base LID */
	uint8_t		Reserved	:4;
	uint8_t		LMC		:3; /* the LMC of this lid */
	uint8_t		Valid		:1; /* this LID/Port pair is valid */
	uint8_t		Port;		    /* port to forward entries to */
} sm_lid_port_block_t;
#else
#error	One of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif /* _BIT_FIELDS_HTOL */

/* Random Forwarding Table: Table 141 */
typedef struct sm_random_forwarding_table_s {
	sm_lid_port_block_t	LIDPortBlocks[16];
} sm_random_forwarding_table_t;

/* Multicast Forwarding Table: Table 143 */
typedef struct sm_multicast_forwarding_table_s {
	uint16_t	PortMaskBlocks[32];
} sm_multicast_forwarding_table_t;

/*
 * SMInfo: Table 145
 * SMInfo struct is applicable to all end ports hosting an SM
 */
#if defined(_BIT_FIELDS_HTOL)
typedef struct sm_sminfo_s {
	ib_guid_t	GUID;			/* Port GUID hosting the SM */
	uint64_t	SM_Key;			/* Key of the SM */
	uint32_t	ActCount;		/* heartbeat counter */
	uint8_t		Priority	:4;	/* priority */
	uint8_t		SMState		:4;	/* SM's state */
} sm_sminfo_t;

#elif defined(_BIT_FIELDS_LTOH)

typedef struct sm_sminfo_s {
	ib_guid_t	GUID;			/* Port GUID hosting the SM */
	uint64_t	SM_Key;			/* Key of the SM */
	uint32_t	ActCount;		/* heartbeat counter */
	uint8_t		SMState		:4;	/* SM's state */
	uint8_t		Priority	:4;	/* priority */
} sm_sminfo_t;

#else
#error	One of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif /* _BIT_FIELDS_HTOL */

/* defines that go with the sminfo structure */

/* SMState Defines */
#define	SM_SMSTATE_INACTIVE		0
#define	SM_SMSTATE_DISCOVERING		1
#define	SM_SMSTATE_STANDBY		2
#define	SM_SMSTATE_MASTER		3

/* SMInfo Control Packets: Table 148 */
#define	SM_SMINFO_AM_HANDOVER		1
#define	SM_SMINFO_AM_ACKNOWLEDGE	2
#define	SM_SMINFO_AM_DISABLE		3
#define	SM_SMINFO_AM_STANDBY		4
#define	SM_SMINFO_AM_DISCOVER		5

/* attribute ID defines */
#define	SM_NOTICE_ATTRID		0x02
#define	SM_NODEDESC_ATTRID		0x10
#define	SM_NODEINFO_ATTRID		0x11
#define	SM_SWITCHINFO_ATTRID		0x12
#define	SM_GUIDINFO_ATTRID		0x14
#define	SM_PORTINFO_ATTRID		0x15
#define	SM_PKEY_TABLE_ATTRID		0x16
#define	SM_SLTOVLTABLE_ATTRID		0x17
#define	SM_VLARBITRATION_ATTRID		0x18
#define	SM_LINEARFDB_ATTRID		0x19
#define	SM_RANDOMFDB_ATTRID		0x1A
#define	SM_MCASTFDB_ATTRID		0x1B
#define	SM_SMINFO_ATTRID		0x20
#define	SM_VENDORDIAG_ATTRID		0x30
#define	SM_LEDINFO_ATTRID		0x31

/* VendorDiag: Table 146 */
typedef struct sm_vendor_diag_s {
	uint16_t	NextIndex;	/* next attr mod to get diag info */
	uint8_t		DiagData[62];	/* vendor specific diag info */
} sm_vendor_diag_t;

/* LedInfo: Table 147 */
#if defined(_BIT_FIELDS_HTOL)
typedef struct sm_ledinfo_s {
	uint32_t	LedMask		:1;	/* 1 for LED on, 0 for off */
	uint32_t	Reserved	:31;
} sm_ledinfo_t;

#elif defined(_BIT_FIELDS_LTOH)

typedef struct sm_ledinfo_s {
	uint32_t	Reserved	:31;
	uint32_t	LedMask		:1;	/* 1 for LED on, 0 for off */
} sm_ledinfo_t;

#else
#error	One of _BIT_FIELDS_HTOL or _BIT_FIELDS_LTOH must be defined
#endif /* _BIT_FIELDS_HTOL */

/* LED Info Defines */
#define	SM_LEDINFO_ON	0x1
#define	SM_LEDINFO_OFF	0x0

#ifdef __cplusplus
}
#endif

#endif /* _SYS_IB_MGT_SM_ATTR_H */
