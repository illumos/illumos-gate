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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 */

#ifndef _SYS_SCSI_ADAPTERS_MPAPI_IMPL_H
#define	_SYS_SCSI_ADAPTERS_MPAPI_IMPL_H

#include <sys/sunmdi.h>
#include <sys/sunddi.h>
#include <sys/mdi_impldefs.h>

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(_BIT_FIELDS_LTOH) && !defined(_BIT_FIELDS_HTOL)
#error  One of _BIT_FIELDS_LTOH or _BIT_FIELDS_HTOL must be defined
#endif  /* _BIT_FIELDS_LTOH */

/*
 * All the structures (except mp_iocdata_t) are 64-bit aligned (padded,
 * where necessary) to facilitate the use of the same structure for
 * handling ioctl calls made by both 32-bit and 64-bit applications.
 * There are no pointers to other structures inside these structures
 * as copyout to user land may not produce desired result.
 * The caddr_t structure is kept at the end due to the undeterminstic
 * size it could accrue to its parent structure.
 */

/* Structure for MP_PLUGIN_PROPERTIES */

typedef struct mp_driver_prop {
	char		driverVersion[256];
	uint32_t	supportedLoadBalanceTypes;
	boolean_t	canSetTPGAccess;
	boolean_t	canOverridePaths;
	boolean_t	exposesPathDeviceFiles;
	char		deviceFileNamespace[256];
	uint32_t	onlySupportsSpecifiedProducts;
	uint32_t	maximumWeight;
	uint32_t	failbackPollingRateMax;
	uint32_t	currentFailbackPollingRate;
	uint32_t	autoFailbackSupport;
	uint32_t	autoFailbackEnabled;
	uint32_t	defaultLoadBalanceType;
	uint32_t	probingPollingRateMax;
	uint32_t	currentProbingPollingRate;
	uint32_t	autoProbingSupport;
	uint32_t	autoProbingEnabled;
	uint32_t	proprietaryPropSize;
	caddr_t		proprietaryProp;
} mp_driver_prop_t;


/* Size of "proprietaryProp" field */

#define	MP_MAX_PROP_BUF_SIZE				1024


/* Constants for autoFailbackSupport */

/*
 * Both MP_DRVR_AUTO_FAILBACK_SUPPORT and
 * MP_DRVR_AUTO_FAILBACK_SUPPORT_LU
 * can be supported at the same time.
 */

#define	MP_DRVR_AUTO_FAILBACK_SUPPORT_NONE		0
#define	MP_DRVR_AUTO_FAILBACK_SUPPORT			(1<<0)
#define	MP_DRVR_AUTO_FAILBACK_SUPPORT_LU		(1<<1)



/*
 * Declaration of the MP_LOAD_BALANCE_TYPE constants - should be
 * the same defines as in mpapi.h
 */
#define	MP_DRVR_LOAD_BALANCE_TYPE_NONE			0
#define	MP_DRVR_LOAD_BALANCE_TYPE_UNKNOWN		(1<<0)
#define	MP_DRVR_LOAD_BALANCE_TYPE_ROUNDROBIN		(1<<1)
#define	MP_DRVR_LOAD_BALANCE_TYPE_LEASTBLOCKS		(1<<2)
#define	MP_DRVR_LOAD_BALANCE_TYPE_LEASTIO		(1<<3)
#define	MP_DRVR_LOAD_BALANCE_TYPE_DEVICE_PRODUCT	(1<<4)
#define	MP_DRVR_LOAD_BALANCE_TYPE_LBA_REGION		(1<<5)
#define	MP_DRVR_LOAD_BALANCE_TYPE_FAILOVER_ONLY		(1<<6)
/*
 * Proprietary load balance type should start from 0x10000(1<<16) or greater.
 * It is exposed through API MP_GetProprietaryLoadBalanceProperties if exists.
 */
#define	MP_DRVR_LOAD_BALANCE_TYPE_PROPRIETARY1		(1<<16)
#define	MP_DRVR_LOAD_BALANCE_TYPE_PROPRIETARY2		(1<<17)

/* Constants for autoProbingSupport */

/*
 * Both MP_DRVR_AUTO_PROBING_SUPPORT and
 * MP_DRVR_AUTO_PROBING_SUPPORT_LU
 * can be supported at the same time.
 */

#define	MP_DRVR_AUTO_PROBING_SUPPORT_NONE		0
#define	MP_DRVR_AUTO_PROBING_SUPPORT			(1<<0)
#define	MP_DRVR_AUTO_PROBING_SUPPORT_LU			(1<<1)


/* Structures for MP_DEVICE_PRODUCT_PROPERTIES */

typedef struct mp_vendor_prod_info {
	char	vendor[8];
	char	product[16];
	char	revision[4];
	char	reserved[4]; /* padding for 64bit alignment */
} mp_vendor_prod_info_t;

typedef struct mp_dev_prod_prop {
	struct mp_vendor_prod_info	prodInfo;
	uint32_t			supportedLoadBalanceTypes;
	uint32_t			reserved; /* 64bit alignment padding */
	uint64_t			id;
} mp_dev_prod_prop_t;


/* Structure for MP_MULTIPATH_LOGICAL_UNIT_PROPERTIES */

typedef struct mp_logical_unit_prop {
	struct mp_vendor_prod_info	prodInfo;
	char				name[256];  /* guid */
	uint32_t			nameType;
	uint32_t			luGroupID;
	char				deviceFileName[256];
	uint64_t			id;
	boolean_t			asymmetric;
	uint32_t			currentLoadBalanceType;
	boolean_t			autoFailbackEnabled;
	uint32_t			failbackPollingRateMax;
	uint32_t			currentFailBackPollingRate;
	uint32_t			autoProbingEnabled;
	uint32_t			probingPollingRateMax;
	uint32_t			currentProbingPollingRate;
	uint64_t			overridePathID;
	boolean_t			overridePathInUse;
	uint32_t			proprietaryPropSize;
	caddr_t				proprietaryProp;
} mp_logical_unit_prop_t;


/* Constants for nameType */

#define	MP_DRVR_NAME_TYPE_UNKNOWN		0
#define	MP_DRVR_NAME_TYPE_VPD83_TYPE1		1
#define	MP_DRVR_NAME_TYPE_VPD83_TYPE2		2
#define	MP_DRVR_NAME_TYPE_VPD83_TYPE3		3
#define	MP_DRVR_NAME_TYPE_DEVICE_SPECIFIC	4


/* Structure for MP_INITIATOR_PORT_PROPERTIES */

typedef struct mp_init_port_prop {
	char		portID[256];
	char		osDeviceFile[256];
	uint32_t	portType;
	uint32_t	reserved; /* padding for 64bit alignment */
	uint64_t	id;
} mp_init_port_prop_t;


/* Constants for portType */

#define	MP_DRVR_TRANSPORT_TYPE_UNKNOWN	0
#define	MP_DRVR_TRANSPORT_TYPE_FC	2
#define	MP_DRVR_TRANSPORT_TYPE_SPI	3
#define	MP_DRVR_TRANSPORT_TYPE_ISCSI	4
#define	MP_DRVR_TRANSPORT_TYPE_IFB	5


/* Structure for MP_TARGET_PORT_PROPERTIES */

typedef struct mp_target_port_prop {
	char		portName[256];
	uint32_t	relativePortID;
	uint32_t	reserved; /* padding for 64bit alignment */
	uint64_t	id;
} mp_target_port_prop_t;


/* Structure for MP_TARGET_PORT_GROUP_PROPERTIES */

typedef struct mp_tpg_prop {
	uint32_t	accessState;
	boolean_t	explicitFailover;
	uint32_t	tpgId; /* T10 defined id in report/set TPG */
	boolean_t	preferredLuPath;
	boolean_t	supportsLuAssignment;
	uint32_t	reserved; /* padding for 64bit alignment */
	uint64_t	id;
} mp_tpg_prop_t;


/* Constants for accessState */

#define	MP_DRVR_ACCESS_STATE_ACTIVE_OPTIMIZED		0
#define	MP_DRVR_ACCESS_STATE_ACTIVE_NONOPTIMIZED	0x1
#define	MP_DRVR_ACCESS_STATE_STANDBY			0x2
#define	MP_DRVR_ACCESS_STATE_UNAVAILABLE		0x3
#define	MP_DRVR_ACCESS_STATE_TRANSITIONING		0xf
#define	MP_DRVR_ACCESS_STATE_ACTIVE			0x10


/* Structure for MP_PATH_LOGICAL_UNIT_PROPERTIES */

typedef struct mp_path_prop {
	uint32_t			weight;
	uint32_t			pathState;
	boolean_t			disabled;
	uint32_t			reserved; /* 64bit alignment padding */
	uint64_t			id;
	struct mp_init_port_prop	initPort;
	struct mp_target_port_prop	targetPort;
	struct mp_logical_unit_prop	logicalUnit;
} mp_path_prop_t;


/* Constants for pathState */

#define	MP_DRVR_PATH_STATE_ACTIVE		0
#define	MP_DRVR_PATH_STATE_PASSIVE		1
#define	MP_DRVR_PATH_STATE_PATH_ERR		2
#define	MP_DRVR_PATH_STATE_LU_ERR		3
#define	MP_DRVR_PATH_STATE_RESERVED		4
#define	MP_DRVR_PATH_STATE_REMOVED		5
#define	MP_DRVR_PATH_STATE_TRANSITIONING	6
#define	MP_DRVR_PATH_STATE_UNKNOWN		7
#define	MP_DRVR_PATH_STATE_UNINIT		8


/* Structure for MP_PROPRIETARY_LOAD_BALANCE_PROPERTIES */

typedef struct mp_proprietary_loadbalance_prop {
	char		name[256];
	char		vendorName[256];
	uint64_t	id;
	uint32_t	typeIndex;
	uint32_t	proprietaryPropSize;
	caddr_t		proprietaryProp;
} mp_proprietary_loadbalance_prop_t;


/*
 * Structure used as input to
 * MP_ASSIGN_LU_TO_TPG subcmd.
 */

typedef struct mp_lu_tpg_pair {
	uint64_t	luId;
	uint64_t	tpgId;
} mp_lu_tpg_pair_t;

/* used for uscsi commmands */
typedef struct mp_uscsi_cmd {
	struct scsi_address	*ap;		/* address of the path */
	struct uscsi_cmd	*uscmdp;	/* uscsi command */
	struct buf		*cmdbp;		/* original buffer */
	struct buf		*rqbp;		/* auto-rqsense packet */
	mdi_pathinfo_t		*pip;		/* path information */
	int			arq_enabled;	/* auto-rqsense enable flag */
}mp_uscsi_cmd_t;

/*
 * Structure used as input to
 * MP_SET_TPG_ACCESS_STATE subcmd.
 */

typedef struct mp_set_tpg_state_req {
	struct mp_lu_tpg_pair	luTpgPair;
	uint32_t		desiredState;
	uint32_t		reserved; /* padding for 64bit boundary */
} mp_set_tpg_state_req_t;


/*
 * Structure for ioctl data
 */
typedef struct mp_iocdata {
	uint16_t	mp_xfer;	/* direction */
	uint16_t	mp_cmd;		/* sub command */
	uint16_t	mp_flags;	/* flags */
	uint16_t	mp_cmd_flags;	/* command specific flags */
	size_t		mp_ilen;	/* Input buffer length */
	caddr_t		mp_ibuf;	/* Input buffer */
	size_t		mp_olen;	/* Output buffer length */
	caddr_t		mp_obuf;	/* Output buffer */
	size_t		mp_alen;	/* Auxiliary buffer length */
	caddr_t		mp_abuf;	/* Auxiliary buffer */
	int		mp_errno;	/* MPAPI driver internal error code */
} mp_iocdata_t;


#ifdef _KERNEL

#if defined(_SYSCALL32)

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack(4)
#endif

/*
 * Structure for 32-bit ioctl data
 */

typedef struct mp_iocdata32 {
	uint16_t	mp_xfer;	/* direction */
	uint16_t	mp_cmd;		/* sub command */
	uint16_t	mp_flags;	/* flags */
	uint16_t	mp_cmd_flags;	/* command specific flags */
	uint32_t	mp_ilen;	/* Input buffer length */
	caddr32_t	mp_ibuf;	/* Input buffer */
	uint32_t	mp_olen;	/* Output buffer length */
	caddr32_t	mp_obuf;	/* Output buffer */
	uint32_t	mp_alen;	/* Auxiliary buffer length */
	caddr32_t	mp_abuf;	/* Auxiliary buffer */
	int32_t		mp_errno;	/* MPAPI driver internal error code */
} mp_iocdata32_t;

#if _LONG_LONG_ALIGNMENT == 8 && _LONG_LONG_ALIGNMENT_32 == 4
#pragma pack()
#endif

#endif  /* _SYSCALL32 */

#endif /* _KERNEL */


/* Constants for MP_XFER */

#define	MP_XFER_NONE	0x00
#define	MP_XFER_READ	0x01
#define	MP_XFER_WRITE	0x02
#define	MP_XFER_RW	(MP_XFER_READ | MP_XFER_WRITE)


/* Constants for MP_OBJECT_TYPE */

#define	MP_OBJECT_TYPE_UNKNOWN			0
#define	MP_OBJECT_TYPE_PLUGIN			1
#define	MP_OBJECT_TYPE_INITIATOR_PORT		2
#define	MP_OBJECT_TYPE_TARGET_PORT		3
#define	MP_OBJECT_TYPE_MULTIPATH_LU		4
#define	MP_OBJECT_TYPE_PATH_LU			5
#define	MP_OBJECT_TYPE_DEVICE_PRODUCT		6
#define	MP_OBJECT_TYPE_TARGET_PORT_GROUP	7
#define	MP_OBJECT_TYPE_PROPRIETARY_LOAD_BALANCE	8
#define	MP_OBJECT_TYPE_LAST_ENTRY 	MP_OBJECT_TYPE_PROPRIETARY_LOAD_BALANCE
#define	MP_MAX_OBJECT_TYPE	(MP_OBJECT_TYPE_LAST_ENTRY + 1)


/* Constants for MP_CMD */

#define	MPAPI_CTL				('m'<<8)
#define	MP_CMD					(MPAPI_CTL | 2005)
#define	MP_SUB_CMD				('M'<<8)

#define	MP_API_SUBCMD_MIN			(MP_SUB_CMD + 0x01)
#define	MP_GET_DRIVER_PROP			(MP_SUB_CMD + 0x01)
#define	MP_GET_DEV_PROD_LIST			(MP_SUB_CMD + 0x02)
#define	MP_GET_DEV_PROD_PROP			(MP_SUB_CMD + 0x03)
#define	MP_GET_LU_LIST				(MP_SUB_CMD + 0x04)
#define	MP_GET_LU_LIST_FROM_TPG			(MP_SUB_CMD + 0x05)
#define	MP_GET_LU_PROP				(MP_SUB_CMD + 0x06)
#define	MP_GET_PATH_LIST_FOR_MP_LU		(MP_SUB_CMD + 0x07)
#define	MP_GET_PATH_LIST_FOR_INIT_PORT		(MP_SUB_CMD + 0x08)
#define	MP_GET_PATH_LIST_FOR_TARGET_PORT	(MP_SUB_CMD + 0x09)
#define	MP_GET_PATH_PROP			(MP_SUB_CMD + 0x0a)
#define	MP_GET_INIT_PORT_LIST			(MP_SUB_CMD + 0x0b)
#define	MP_GET_INIT_PORT_PROP			(MP_SUB_CMD + 0x0c)
#define	MP_GET_TARGET_PORT_PROP			(MP_SUB_CMD + 0x0d)
#define	MP_GET_TPG_LIST				(MP_SUB_CMD + 0x0e)
#define	MP_GET_TPG_PROP				(MP_SUB_CMD + 0x0f)
#define	MP_GET_TPG_LIST_FOR_LU			(MP_SUB_CMD + 0x10)
#define	MP_GET_TARGET_PORT_LIST_FOR_TPG		(MP_SUB_CMD + 0x11)
#define	MP_SET_TPG_ACCESS_STATE			(MP_SUB_CMD + 0x12)
#define	MP_ENABLE_AUTO_FAILBACK			(MP_SUB_CMD + 0x13)
#define	MP_DISABLE_AUTO_FAILBACK 		(MP_SUB_CMD + 0x14)
#define	MP_ENABLE_PATH				(MP_SUB_CMD + 0x15)
#define	MP_DISABLE_PATH				(MP_SUB_CMD + 0x16)
#define	MP_GET_PROPRIETARY_LOADBALANCE_LIST	(MP_SUB_CMD + 0x17)
#define	MP_GET_PROPRIETARY_LOADBALANCE_PROP	(MP_SUB_CMD + 0x18)
#define	MP_ASSIGN_LU_TO_TPG			(MP_SUB_CMD + 0x19)
#define	MP_SEND_SCSI_CMD			(MP_SUB_CMD + 0x1a)
#define	MP_API_SUBCMD_MAX			(MP_SEND_SCSI_CMD)


/*
 * Typical MP API ioctl interface specific Return Values
 */

#define	MP_IOCTL_ERROR_START			0x5533
#define	MP_MORE_DATA				(MP_IOCTL_ERROR_START + 1)
#define	MP_DRVR_INVALID_ID			(MP_IOCTL_ERROR_START + 2)
#define	MP_DRVR_ID_OBSOLETE			(MP_IOCTL_ERROR_START + 3)
#define	MP_DRVR_ACCESS_SYMMETRIC		(MP_IOCTL_ERROR_START + 4)
#define	MP_DRVR_PATH_UNAVAILABLE		(MP_IOCTL_ERROR_START + 5)
#define	MP_DRVR_IDS_NOT_ASSOCIATED		(MP_IOCTL_ERROR_START + 6)
#define	MP_DRVR_ILLEGAL_ACCESS_STATE_REQUEST	(MP_IOCTL_ERROR_START + 7)
#define	MP_DRVR_IO_ERROR			(MP_IOCTL_ERROR_START + 8)

/*
 * Macros for OID operations
 */
#define	MP_ID_SHIFT4MAJOR		32
#define	MP_GET_MAJOR_FROM_ID(id)	((id) >> MP_ID_SHIFT4MAJOR)
#define	MP_GET_INST_FROM_ID(id)		((id) & 0x00000000ffffffff)
#define	MP_STORE_INST_TO_ID(inst, id)	(((uint64_t)(inst)) | id)
#define	MP_STORE_MAJOR_TO_ID(major, id)	\
	((((uint64_t)(major)) << MP_ID_SHIFT4MAJOR) | id)

/*
 * Event Class and Sub-Class definitions
 */
#define	EC_SUN_MP			"EC_sun_mp"

#define	ESC_SUN_MP_PLUGIN_CHANGE	"ESC_sun_mp_plugin_change"

#define	ESC_SUN_MP_LU_CHANGE		"ESC_sun_mp_lu_change"
#define	ESC_SUN_MP_LU_ADD		"ESC_sun_mp_lu_add"
#define	ESC_SUN_MP_LU_REMOVE		"ESC_sun_mp_lu_remove"

#define	ESC_SUN_MP_PATH_CHANGE		"ESC_sun_mp_path_change"
#define	ESC_SUN_MP_PATH_ADD		"ESC_sun_mp_path_add"
#define	ESC_SUN_MP_PATH_REMOVE		"ESC_sun_mp_path_remove"

#define	ESC_SUN_MP_INIT_PORT_CHANGE	"ESC_sun_mp_init_port_change"

#define	ESC_SUN_MP_TPG_CHANGE		"ESC_sun_mp_tpg_change"
#define	ESC_SUN_MP_TPG_ADD		"ESC_sun_mp_tpg_add"
#define	ESC_SUN_MP_TPG_REMOVE		"ESC_sun_mp_tpg_remove"

#define	ESC_SUN_MP_TARGET_PORT_CHANGE	"ESC_sun_mp_target_port_change"
#define	ESC_SUN_MP_TARGET_PORT_ADD	"ESC_sun_mp_target_port_add"
#define	ESC_SUN_MP_TARGET_PORT_REMOVE	"ESC_sun_mp_target_port_remove"

#define	ESC_SUN_MP_DEV_PROD_CHANGE	"ESC_sun_mp_dev_prod_change"
#define	ESC_SUN_MP_DEV_PROD_ADD		"ESC_sun_mp_dev_prod_add"
#define	ESC_SUN_MP_DEV_PROD_REMOVE	"ESC_sun_mp_dev_prod_remove"

#ifdef __cplusplus
}
#endif

#endif /* _SYS_SCSI_ADAPTERS_MPAPI_IMPL_H */
