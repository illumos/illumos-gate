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

#ifndef	_ISCSIADM_H
#define	_ISCSIADM_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <sys/iscsi_protocol.h>
#include <sys/scsi/adapters/iscsi_if.h>
#include <ima.h>

#include <cmdparse.h>

#define	ADD	SUBCOMMAND(0)
#define	LIST	SUBCOMMAND(1)
#define	MODIFY	SUBCOMMAND(2)
#define	REMOVE	SUBCOMMAND(3)

#define	TARGET			OBJECT(0)
#define	NODE			OBJECT(1)
#define	INITIATOR		OBJECT(2)
#define	STATIC_CONFIG		OBJECT(3)
#define	DISCOVERY_ADDRESS	OBJECT(4)
#define	DISCOVERY		OBJECT(5)
#define	TARGET_PARAM		OBJECT(6)
#define	ISNS_SERVER_ADDRESS	OBJECT(7)

#define	DATA_SEQ_IN_ORDER	0x01
#define	DEFAULT_TIME_2_RETAIN	0x02
#define	DEFAULT_TIME_2_WAIT	0x03
#define	FIRST_BURST_LENGTH	0x04
#define	IMMEDIATE_DATA		0x05
#define	INITIAL_R2T		0x06
#define	MAX_BURST_LENGTH	0x07
#define	DATA_PDU_IN_ORDER	0x08
#define	MAX_OUTSTANDING_R2T	0x09
#define	MAX_RECV_DATA_SEG_LEN	0x0a
#define	HEADER_DIGEST		0x0b
#define	DATA_DIGEST		0x0c
#define	MAX_CONNECTIONS		0x0d
#define	ERROR_RECOVERY_LEVEL	0x0e

#define	AUTH_NAME		0x01
#define	AUTH_PASSWORD		0x02

#define	ISCSIADM_ARG_ENABLE	"enable"
#define	ISCSIADM_ARG_DISABLE	"disable"
/*
 * This object type is not defined by IMA.
 */
#define	SUN_IMA_OBJECT_TYPE_CONN  13	/* Currently not defined in IMA */
#define	SUN_IMA_NODE_ALIAS_LEN	256

#define	MAKE_IMA_ERROR(x)	((IMA_STATUS)(IMA_STATUS_ERROR | (x)))
#define	SUN_IMA_SYSTEM_ERROR(status) (((IMA_STATUS)(status) & \
	(IMA_STATUS)SUN_IMA_ERROR_SYSTEM_ERROR) == 0x8FFF0000 \
	? IMA_TRUE : IMA_FALSE)
#define	SUN_GET_SYSTEM_ERROR(x)	(((IMA_STATUS)(x) & 0x0000FFFF))
#define	SUN_IMA_ERROR_SYSTEM_ERROR MAKE_IMA_ERROR(0x0fff0000)

typedef struct _parameterTbl {
	char *name;
	int val;
} parameterTbl_t;

/*
 * The following interfaces are not defined in IMA 1.1. Some of them
 * are requirement candidates for the next IMA release.
 */

#define	SUN_IMA_MAX_DIGEST_ALGORITHMS	2	/* NONE and CRC 32 */
#define	SUN_IMA_IP_ADDRESS_PORT_LEN	256
#define	SUN_IMA_MAX_RADIUS_SECRET_LEN	128

/* Currently not defined in  IMA_TARGET_DISCOVERY_METHOD enum */
#define	IMA_TARGET_DISCOVERY_METHOD_UNKNOWN  0

typedef enum
{
    SUN_IMA_DIGEST_NONE = 0,
    SUN_IMA_DIGEST_CRC32 = 1
} SUN_IMA_DIGEST_ALGORITHM;

typedef struct _SUN_IMA_DIGEST_ALGORITHM_VALUE
{
    IMA_UINT defaultAlgorithmCount;
    SUN_IMA_DIGEST_ALGORITHM defaultAlgorithms[SUN_IMA_MAX_DIGEST_ALGORITHMS];

    IMA_BOOL currentValid;
    IMA_UINT currentAlgorithmCount;
    SUN_IMA_DIGEST_ALGORITHM currentAlgorithms[SUN_IMA_MAX_DIGEST_ALGORITHMS];

    IMA_BOOL negotiatedValid;
    IMA_UINT negotiatedAlgorithmCount;
    SUN_IMA_DIGEST_ALGORITHM
	negotiatedAlgorithms[SUN_IMA_MAX_DIGEST_ALGORITHMS];
} SUN_IMA_DIGEST_ALGORITHM_VALUE;

typedef struct _SUN_IMA_DISC_ADDR_PROP_LIST
{
    IMA_UINT discAddrCount;
    IMA_DISCOVERY_ADDRESS_PROPERTIES props[1];
} SUN_IMA_DISC_ADDR_PROP_LIST;

typedef struct _SUN_IMA_RADIUS_CONFIG
{
	char hostnameIpAddress[SUN_IMA_IP_ADDRESS_PORT_LEN];
	IMA_BOOL isIpv6;
	IMA_UINT16 port;
	IMA_BOOL sharedSecretValid;
	IMA_UINT sharedSecretLength;
	IMA_BYTE sharedSecret[SUN_IMA_MAX_RADIUS_SECRET_LEN];
} SUN_IMA_RADIUS_CONFIG;


typedef struct _SUN_IMA_DISC_ADDRESS_KEY
{
	IMA_NODE_NAME name;
	IMA_ADDRESS_KEY	address;
	IMA_UINT16 tpgt;
} SUN_IMA_DISC_ADDRESS_KEY;

typedef struct _SUN_IMA_DISC_ADDRESS_KEY_PROPERTIES
{
	IMA_UINT keyCount;
	SUN_IMA_DISC_ADDRESS_KEY keys[1];
} SUN_IMA_DISC_ADDRESS_KEY_PROPERTIES;

typedef struct _SUN_IMA_TARGET_ADDRESS
{
    IMA_TARGET_ADDRESS imaStruct;
	IMA_BOOL	defaultTpgt;	/* If true, tpgt becomes irrelvant */
	IMA_UINT16	tpgt;
} SUN_IMA_TARGET_ADDRESS;

typedef struct _SUN_IMA_STATIC_DISCOVERY_TARGET
{
	IMA_NODE_NAME	targetName;
	SUN_IMA_TARGET_ADDRESS  targetAddress;
} SUN_IMA_STATIC_DISCOVERY_TARGET;

typedef struct _SUN_IMA_STATIC_DISCOVERY_TARGET_PROPERTIES
{
	IMA_OID	associatedNodeOid;
	IMA_OID	associatedLhbaOid;
	SUN_IMA_STATIC_DISCOVERY_TARGET   staticTarget;
} SUN_IMA_STATIC_DISCOVERY_TARGET_PROPERTIES;

typedef struct _SUN_IMA_CONN_PROPERTIES {
	IMA_UINT32	connectionID;
	IMA_ADDRESS_KEY	local;
	IMA_ADDRESS_KEY	peer;

	IMA_BOOL   valuesValid;
	IMA_UINT32 defaultTime2Retain;
	IMA_UINT32 defaultTime2Wait;
	IMA_UINT32 errorRecoveryLevel;
	IMA_UINT32 firstBurstLength;
	IMA_UINT32 maxBurstLength;
	IMA_UINT32 maxConnections;
	IMA_UINT32 maxOutstandingR2T;
	IMA_UINT32 maxRecvDataSegmentLength;

	IMA_BOOL dataPduInOrder;
	IMA_BOOL dataSequenceInOrder;
	IMA_BOOL immediateData;
	IMA_BOOL initialR2T;

	IMA_UINT headerDigest;
	IMA_UINT dataDigest;

} SUN_IMA_CONN_PROPERTIES;


#define	SUN_IMA_LU_VENDOR_ID_LEN	ISCSI_INQ_VID_BUF_LEN
#define	SUN_IMA_LU_PRODUCT_ID_LEN	ISCSI_INQ_PID_BUF_LEN
typedef struct _SUN_IMA_LU_PROPERTIES
{
    IMA_LU_PROPERTIES imaProps;
    IMA_CHAR	vendorId[SUN_IMA_LU_VENDOR_ID_LEN];
    IMA_CHAR	productId[SUN_IMA_LU_PRODUCT_ID_LEN];
} SUN_IMA_LU_PROPERTIES;

typedef struct _SUN_IMA_TARGET_PROPERTIES
{
    IMA_TARGET_PROPERTIES imaProps;
    IMA_BOOL defaultTpgtConf;	/* If true, tpgtConf is irrelevant */
    IMA_UINT16 tpgtConf;
    IMA_BOOL defaultTpgtNego;	/* If true, tpgtNego is not connected */
    IMA_UINT16 tpgtNego;
    IMA_BYTE isid[ISCSI_ISID_LEN];
} SUN_IMA_TARGET_PROPERTIES;

typedef struct _SUN_IMA_CONFIG_SESSIONS {
	/* True if sessions are bound to an interface */
	IMA_BOOL	bound;	/* OUT */
	/*
	 * Memory allocated from caller.  In addition
	 * on a Set this is the number of configured
	 * sessions.
	 */
	IMA_UINT	in;	/* IN */
	/* Number of Configured sessions on Get */
	IMA_UINT	out;	/* OUT */
	IMA_ADDRESS_KEY	bindings[1];	/* IN/OUT */
} SUN_IMA_CONFIG_SESSIONS;

typedef struct _SUN_IMA_STATIC_TARGET_PROPERTIES
{
	IMA_OID	associatedNodeOid;
	IMA_OID	associatedLhbaOid;
	SUN_IMA_STATIC_DISCOVERY_TARGET   staticTarget;
} SUN_IMA_STATIC_TARGET_PROPERTIES;

#ifdef	__cplusplus
}
#endif

#endif	/* _ISCSIADM_H */
