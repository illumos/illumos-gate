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

#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <syslog.h>
#include <errno.h>
#include <wchar.h>
#include <widec.h>
#include <libsysevent.h>
#include <sys/nvpair.h>
#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <libdevinfo.h>
#include <sys/scsi/generic/commands.h>
#include <sys/scsi/generic/status.h>
#include <sys/scsi/adapters/iscsi_if.h>
#include <sys/iscsi_protocol.h>
#include <ima.h>
#include <libsun_ima.h>

#define	LIBRARY_PROPERTY_IMPLEMENTATION_VERSION	L"1.0.0"
#define	LIBRARY_PROPERTY_VENDOR			L"Sun Microsystems, Inc."
#define	OS_DEVICE_NAME				"/devices/iscsi"
#define	LIBRARY_FILE_NAME			L"libsun_ima.so"

#define	OS_DEVICE_NAME_LEN		256
#define	USCSI_TIMEOUT_IN_SEC		10
#define	MAX_AUTHMETHODS			10
#define	NUM_SUPPORTED_AUTH_METHODS	2
#define	SUN_IMA_MAX_DIGEST_ALGORITHMS	2	/* NONE and CRC 32 */
#define	SUN_IMA_IP_ADDRESS_LEN		256
#define	SUN_IMA_IP_PORT_LEN		64
#define	SUN_IMA_MAX_RADIUS_SECRET_LEN	128
#define	MAX_LONG_LONG_STRING_LEN	10
#define	MAX_INQUIRY_BUFFER_LEN		0xffff
#define	MAX_REPORT_LUNS_BUFFER_LEN	0xffffffff
#define	MAX_READ_CAPACITY16_BUFFER_LEN	0xffffffff

/* Forward declaration */
#define	BOOL_PARAM			1
#define	MIN_MAX_PARAM			2

/* OK */
#define	DISC_ADDR_OK			0
/* Incorrect IP address */
#define	DISC_ADDR_INTEGRITY_ERROR	1
/* Error converting text IP address to numeric binary form */
#define	DISC_ADDR_IP_CONV_ERROR		2

/* Currently not defined in  IMA_TARGET_DISCOVERY_METHOD enum */
#define	IMA_TARGET_DISCOVERY_METHOD_UNKNOWN  0

static IMA_OID		lhbaObjectId;
static IMA_UINT32	pluginOwnerId;
static sysevent_handle_t *shp;



/*
 * Custom struct to allow tgpt to be specified.
 */
typedef struct _SUN_IMA_DISC_ADDRESS_KEY
{
	IMA_NODE_NAME name;
	IMA_ADDRESS_KEY	address;
	IMA_UINT16 tpgt;
} SUN_IMA_DISC_ADDRESS_KEY;

/*
 * Custom struct to allow tgpt to be specified.
 */
typedef struct _SUN_IMA_DISC_ADDRESS_KEY_PROPERTIES
{
	IMA_UINT keyCount;
	SUN_IMA_DISC_ADDRESS_KEY keys[1];
} SUN_IMA_DISC_ADDRESS_KEY_PROPERTIES;

/*
 * Custom struct to allow tgpt to be specified.
 */
typedef struct _SUN_IMA_DISC_ADDR_PROP_LIST
{
	IMA_UINT discAddrCount;
	IMA_DISCOVERY_ADDRESS_PROPERTIES props[1];
} SUN_IMA_DISC_ADDR_PROP_LIST;


static IMA_OBJECT_VISIBILITY_FN pObjectVisibilityCallback = NULL;
static IMA_OBJECT_PROPERTY_FN pObjectPropertyCallback = NULL;

static IMA_STATUS getISCSINodeParameter(int paramType, IMA_OID *oid,
    void *pProps, uint32_t paramIndex);
static IMA_STATUS setISCSINodeParameter(int paramType, IMA_OID *oid,
    void *pProps, uint32_t paramIndex);
static IMA_STATUS setAuthMethods(IMA_OID oid, IMA_UINT *pMethodCount,
    const IMA_AUTHMETHOD *pMethodList);
static IMA_STATUS getAuthMethods(IMA_OID oid, IMA_UINT *pMethodCount,
    IMA_AUTHMETHOD *pMethodList);

static int prepare_discovery_entry(IMA_TARGET_ADDRESS discoveryAddress,
    entry_t *entry);
static IMA_STATUS configure_discovery_method(IMA_BOOL enable,
    iSCSIDiscoveryMethod_t method);
static IMA_STATUS get_target_oid_list(uint32_t targetListType,
    IMA_OID_LIST **ppList);
static IMA_STATUS get_target_lun_oid_list(IMA_OID * targetOid,
		iscsi_lun_list_t  **ppLunList);
static int get_lun_devlink(di_devlink_t link, void *osDeviceName);
static IMA_STATUS getDiscoveryAddressPropertiesList(
	SUN_IMA_DISC_ADDR_PROP_LIST **ppList
);
static IMA_STATUS sendTargets(IMA_TARGET_ADDRESS address,
    SUN_IMA_DISC_ADDRESS_KEY_PROPERTIES **ppList
);

static IMA_STATUS getSupportedAuthMethods(IMA_OID lhbaOid,
    IMA_BOOL getSettableMethods, IMA_UINT *pMethodCount,
    IMA_AUTHMETHOD *pMethodList);
static IMA_STATUS getLuProperties(IMA_OID luId, IMA_LU_PROPERTIES *pProps);
static IMA_STATUS getTargetProperties(IMA_OID targetId,
    IMA_TARGET_PROPERTIES *pProps);

void InitLibrary();

static void libSwprintf(wchar_t *wcs, const wchar_t *lpszFormat, ...)
{
	va_list args;
	va_start(args, lpszFormat);
	(void) vswprintf(wcs, OS_DEVICE_NAME_LEN - 1, lpszFormat, args);
	va_end(args);
}

static void
sysevent_handler(sysevent_t *ev)
{
	IMA_OID tmpOid;
	IMA_BOOL becomingVisible = IMA_FALSE;
	IMA_UINT i;

	const char *visibility_subclasses[] = {
		ESC_ISCSI_STATIC_START,
		ESC_ISCSI_STATIC_END,
		ESC_ISCSI_SEND_TARGETS_START,
		ESC_ISCSI_SEND_TARGETS_END,
		ESC_ISCSI_SLP_START,
		ESC_ISCSI_SLP_END,
		ESC_ISCSI_ISNS_START,
		ESC_ISCSI_ISNS_END,
		NULL
	};

	tmpOid.ownerId = pluginOwnerId;
	tmpOid.objectType = IMA_OBJECT_TYPE_TARGET;
	tmpOid.objectSequenceNumber = 0;

	/* Make sure our event class matches what we are looking for */
	if (strncmp(EC_ISCSI, sysevent_get_class_name(ev),
	    strlen(EC_ISCSI)) != 0) {
		return;
	}


	/* Check for object property changes */
	if ((strncmp(ESC_ISCSI_PROP_CHANGE,
	    sysevent_get_subclass_name(ev),
	    strlen(ESC_ISCSI_PROP_CHANGE)) == 0)) {
		if (pObjectPropertyCallback != NULL)
			pObjectPropertyCallback(tmpOid);
	} else {
		i = 0;
		while (visibility_subclasses[i] != NULL) {
			if ((strncmp(visibility_subclasses[i],
			    sysevent_get_subclass_name(ev),
			    strlen(visibility_subclasses[i])) == 0) &&
			    pObjectVisibilityCallback != NULL) {
				becomingVisible = IMA_TRUE;
				pObjectVisibilityCallback(becomingVisible,
				    tmpOid);
			}
			i++;
		}
	}
}

IMA_STATUS init_sysevents() {
	const char *subclass_list[] = {
		ESC_ISCSI_STATIC_START,
		ESC_ISCSI_STATIC_END,
		ESC_ISCSI_SEND_TARGETS_START,
		ESC_ISCSI_SEND_TARGETS_END,
		ESC_ISCSI_SLP_START,
		ESC_ISCSI_SLP_END,
		ESC_ISCSI_ISNS_START,
		ESC_ISCSI_ISNS_END,
		ESC_ISCSI_PROP_CHANGE,
	};

	/* Bind event handler and create subscriber handle */
	shp = sysevent_bind_handle(sysevent_handler);
	if (shp == NULL) {
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	if (sysevent_subscribe_event(shp, EC_ISCSI, subclass_list, 9) != 0) {
		sysevent_unbind_handle(shp);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}
	return (IMA_STATUS_SUCCESS);
}

IMA_STATUS Initialize(IMA_UINT32 pluginOid) {
	pluginOwnerId = pluginOid;
	return (init_sysevents());
}

void Terminate() {
	if (shp != NULL) {
		sysevent_unsubscribe_event(shp, EC_ISCSI);
	}

}

void InitLibrary() {
}

static void GetBuildTime(IMA_DATETIME* pdatetime)
{
	(void) memset(pdatetime, 0, sizeof (IMA_DATETIME));
}

/*ARGSUSED*/
IMA_API IMA_STATUS IMA_GetNodeProperties(
	IMA_OID nodeOid,
	IMA_NODE_PROPERTIES *pProps
)
{
	int fd;
	iscsi_param_get_t pg;

	pProps->runningInInitiatorMode = IMA_TRUE;
	pProps->runningInTargetMode = IMA_FALSE;
	pProps->nameAndAliasSettable = IMA_FALSE;

	if ((fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) == -1) {
		syslog(LOG_USER|LOG_DEBUG, "Cannot open %s (%d)",
		    ISCSI_DRIVER_DEVCTL, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(void) memset(&pg, 0, sizeof (iscsi_param_get_t));
	pg.g_vers = ISCSI_INTERFACE_VERSION;
	pg.g_param = ISCSI_LOGIN_PARAM_INITIATOR_NAME;

	if (ioctl(fd, ISCSI_PARAM_GET, &pg) == -1) {
		pProps->nameValid = IMA_FALSE;
	} else {
		if (strlen((char *)pg.g_value.v_name) > 0) {
			(void) mbstowcs(pProps->name,
			    (char *)pg.g_value.v_name,
			    IMA_NODE_NAME_LEN);
			pProps->nameValid = IMA_TRUE;
		} else {
			pProps->nameValid = IMA_FALSE;
		}
	}

	(void) memset(&pg, 0, sizeof (iscsi_param_get_t));
	pg.g_vers = ISCSI_INTERFACE_VERSION;
	pg.g_param = ISCSI_LOGIN_PARAM_INITIATOR_ALIAS;
	(void) memset(pProps->alias, 0,
	    sizeof (IMA_WCHAR) * IMA_NODE_ALIAS_LEN);
	if (ioctl(fd, ISCSI_PARAM_GET, &pg) == -1) {
		pProps->aliasValid = IMA_FALSE;
	} else {
		if (strlen((char *)pg.g_value.v_name) > 0) {
			(void) mbstowcs(pProps->alias,
			    (char *)pg.g_value.v_name,
			    IMA_NODE_ALIAS_LEN);
			pProps->aliasValid = IMA_TRUE;
		}
	}

	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}

IMA_API IMA_STATUS IMA_SetNodeName(
	IMA_OID nodeOid,
	const IMA_NODE_NAME newName
)
{
	int fd;
	iscsi_param_set_t ps;

	if ((fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) == -1) {
		syslog(LOG_USER|LOG_DEBUG, "Cannot open %s (%d)",
		    ISCSI_DRIVER_DEVCTL, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(void) memset(&ps, 0, sizeof (iscsi_param_set_t));
	ps.s_oid = nodeOid.objectSequenceNumber;
	ps.s_vers = ISCSI_INTERFACE_VERSION;
	ps.s_param = ISCSI_LOGIN_PARAM_INITIATOR_NAME;
	(void) wcstombs((char *)ps.s_value.v_name, newName, ISCSI_MAX_NAME_LEN);
	if (ioctl(fd, ISCSI_INIT_NODE_NAME_SET, &ps)) {
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_PARAM_SET ioctl failed, errno: %d", errno);
		(void) close(fd);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}

IMA_API IMA_STATUS IMA_SetNodeAlias(
	IMA_OID nodeOid,
	const IMA_NODE_ALIAS newAlias
)
{
	int fd;
	iscsi_param_set_t ps;

	if ((fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) == -1) {
		syslog(LOG_USER|LOG_DEBUG, "Cannot open %s (%d)",
		    ISCSI_DRIVER_DEVCTL, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(void) memset(&ps, 0, sizeof (iscsi_param_set_t));
	ps.s_oid = nodeOid.objectSequenceNumber;
	ps.s_vers = ISCSI_INTERFACE_VERSION;
	ps.s_param = ISCSI_LOGIN_PARAM_INITIATOR_ALIAS;

	/* newAlias = NULL specifies that the alias should be deleted. */
	if (newAlias != NULL)
		(void) wcstombs((char *)ps.s_value.v_name, newAlias,
		    ISCSI_MAX_NAME_LEN);
	else
		(void) wcstombs((char *)ps.s_value.v_name,
		    L"", ISCSI_MAX_NAME_LEN);

	if (ioctl(fd, ISCSI_PARAM_SET, &ps)) {
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_PARAM_SET ioctl failed, errno: %d", errno);
		(void) close(fd);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}


IMA_API IMA_STATUS IMA_GetLhbaOidList(
	IMA_OID_LIST **ppList
)
{
	/* Always return the same object ID for the lhba */
	lhbaObjectId.objectType = IMA_OBJECT_TYPE_LHBA;
	lhbaObjectId.ownerId = pluginOwnerId;
	lhbaObjectId.objectSequenceNumber = ISCSI_INITIATOR_OID;

	*ppList = (IMA_OID_LIST*)calloc(1, sizeof (IMA_OID_LIST));
	if (*ppList == NULL) {
		return (IMA_ERROR_INSUFFICIENT_MEMORY);
	}

	(*ppList)->oidCount = 1;
	(void) memcpy(&(*ppList)->oids[0],
	    &lhbaObjectId, sizeof (lhbaObjectId));
	return (IMA_STATUS_SUCCESS);
}


/*
 * Get the discovery properties of the LHBA
 */
/*ARGSUSED*/
IMA_API IMA_STATUS IMA_GetDiscoveryProperties(
	IMA_OID oid,
	IMA_DISCOVERY_PROPERTIES *pProps
)
{
	int fd;
	iSCSIDiscoveryProperties_t discoveryProps;

	if ((fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) == -1) {
		syslog(LOG_USER|LOG_DEBUG, "Cannot open %s (%d)",
		    ISCSI_DRIVER_DEVCTL, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(void) memset(&discoveryProps, 0, sizeof (discoveryProps));
	discoveryProps.vers = ISCSI_INTERFACE_VERSION;

	if (ioctl(fd, ISCSI_DISCOVERY_PROPS, &discoveryProps) != 0) {
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_DISCOVERY_PROPS ioctl failed, errno: %d", errno);
		(void) close(fd);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	pProps->iSnsDiscoverySettable = discoveryProps.iSNSDiscoverySettable;
	pProps->iSnsDiscoveryEnabled = discoveryProps.iSNSDiscoveryEnabled;
	/*
	 * Set the iSNS discovery method - The IMA specification indicates
	 * this field is valid only if iSNS discovery is enabled.
	 */
	if (pProps->iSnsDiscoveryEnabled == IMA_TRUE) {
		switch (discoveryProps.iSNSDiscoveryMethod) {
			case iSNSDiscoveryMethodStatic:
				pProps->iSnsDiscoveryMethod =
				    IMA_ISNS_DISCOVERY_METHOD_STATIC;
				break;
			case iSNSDiscoveryMethodDHCP:
				pProps->iSnsDiscoveryMethod =
				    IMA_ISNS_DISCOVERY_METHOD_DHCP;
				break;
			case iSNSDiscoveryMethodSLP:
				pProps->iSnsDiscoveryMethod =
				    IMA_ISNS_DISCOVERY_METHOD_SLP;
				break;
			default:
				(void) close(fd);
				return (IMA_ERROR_UNEXPECTED_OS_ERROR);
		}
	}
	(void) memcpy(pProps->iSnsHost.id.hostname,
	    discoveryProps.iSNSDomainName,
	    sizeof (pProps->iSnsHost.id.hostname));
	pProps->slpDiscoverySettable = discoveryProps.SLPDiscoverySettable;
	pProps->slpDiscoveryEnabled = discoveryProps.SLPDiscoveryEnabled;
	pProps->staticDiscoverySettable =
	    discoveryProps.StaticDiscoverySettable;
	pProps->staticDiscoveryEnabled = discoveryProps.StaticDiscoveryEnabled;
	pProps->sendTargetsDiscoverySettable =
	    discoveryProps.SendTargetsDiscoverySettable;
	pProps->sendTargetsDiscoveryEnabled =
	    discoveryProps.SendTargetsDiscoveryEnabled;

	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}

IMA_API IMA_STATUS IMA_FreeMemory(
	void *pMemory
)
{
	if (pMemory != NULL)
		free(pMemory);
	return (IMA_STATUS_SUCCESS);
}

IMA_API IMA_STATUS IMA_GetNonSharedNodeOidList(
		IMA_OID_LIST **ppList
)
{
	if (ppList == NULL)
		return (IMA_ERROR_INVALID_PARAMETER);

	*ppList = (IMA_OID_LIST*) calloc(1, sizeof (IMA_OID_LIST));
	if (*ppList == NULL) {
		return (IMA_ERROR_INSUFFICIENT_MEMORY);
	}
	(*ppList)->oidCount = 0;

	return (IMA_STATUS_SUCCESS);
}

IMA_API IMA_STATUS IMA_GetFirstBurstLengthProperties(
		IMA_OID Oid,
		IMA_MIN_MAX_VALUE *pProps
)
{
	return (getISCSINodeParameter(MIN_MAX_PARAM, &Oid, pProps,
	    ISCSI_LOGIN_PARAM_FIRST_BURST_LENGTH));
}

IMA_API IMA_STATUS IMA_GetMaxBurstLengthProperties(
		IMA_OID Oid,
		IMA_MIN_MAX_VALUE *pProps
)
{
	return (getISCSINodeParameter(MIN_MAX_PARAM, &Oid, pProps,
	    ISCSI_LOGIN_PARAM_MAX_BURST_LENGTH));
}

IMA_API IMA_STATUS IMA_GetMaxRecvDataSegmentLengthProperties(
		IMA_OID Oid,
		IMA_MIN_MAX_VALUE *pProps
)
{
	return (getISCSINodeParameter(MIN_MAX_PARAM, &Oid, pProps,
	    ISCSI_LOGIN_PARAM_MAX_RECV_DATA_SEGMENT_LENGTH));
}

/*ARGSUSED*/
IMA_API IMA_STATUS IMA_PluginIOCtl(
		IMA_OID pluginOid,
		IMA_UINT command,
		const void *pInputBuffer,
		IMA_UINT inputBufferLength,
		void *pOutputBuffer,
		IMA_UINT *pOutputBufferLength
)
{
	return (IMA_ERROR_NOT_SUPPORTED);
}

IMA_API	IMA_STATUS IMA_SetFirstBurstLength(
		IMA_OID lhbaId,
		IMA_UINT firstBurstLength
)
{
	IMA_MIN_MAX_VALUE mv;

	mv.currentValue = firstBurstLength;
	return (setISCSINodeParameter(MIN_MAX_PARAM, &lhbaId, &mv,
	    ISCSI_LOGIN_PARAM_FIRST_BURST_LENGTH));
}

IMA_API	IMA_STATUS IMA_SetMaxBurstLength(
		IMA_OID lhbaId,
		IMA_UINT maxBurstLength
)
{
	IMA_MIN_MAX_VALUE mv;

	mv.currentValue = maxBurstLength;
	return (setISCSINodeParameter(MIN_MAX_PARAM, &lhbaId, &mv,
	    ISCSI_LOGIN_PARAM_MAX_BURST_LENGTH));
}

IMA_API	IMA_STATUS IMA_SetMaxRecvDataSegmentLength(
		IMA_OID lhbaId,
		IMA_UINT maxRecvDataSegmentLength
)
{
	IMA_MIN_MAX_VALUE mv;

	mv.currentValue = maxRecvDataSegmentLength;
	return (setISCSINodeParameter(MIN_MAX_PARAM, &lhbaId, &mv,
	    ISCSI_LOGIN_PARAM_MAX_RECV_DATA_SEGMENT_LENGTH));
}

IMA_API	IMA_STATUS IMA_GetMaxConnectionsProperties(
		IMA_OID Oid,
		IMA_MIN_MAX_VALUE *pProps
)
{
	return (getISCSINodeParameter(MIN_MAX_PARAM, &Oid, pProps,
	    ISCSI_LOGIN_PARAM_MAX_CONNECTIONS));
}

IMA_API	IMA_STATUS IMA_SetMaxConnections(
		IMA_OID lhbaId,
		IMA_UINT maxConnections
)
{
	IMA_MIN_MAX_VALUE mv;

	mv.currentValue = maxConnections;
	return (setISCSINodeParameter(MIN_MAX_PARAM, &lhbaId, &mv,
	    ISCSI_LOGIN_PARAM_MAX_CONNECTIONS));
}

IMA_API	IMA_STATUS IMA_GetDefaultTime2RetainProperties(
		IMA_OID lhbaId,
		IMA_MIN_MAX_VALUE *pProps
)
{
	return (getISCSINodeParameter(MIN_MAX_PARAM, &lhbaId, pProps,
	    ISCSI_LOGIN_PARAM_DEFAULT_TIME_2_RETAIN));
}

IMA_API	IMA_STATUS IMA_SetDefaultTime2Retain(
		IMA_OID lhbaId,
		IMA_UINT defaultTime2Retain
)
{
	IMA_MIN_MAX_VALUE mv;

	mv.currentValue = defaultTime2Retain;
	return (setISCSINodeParameter(MIN_MAX_PARAM, &lhbaId, &mv,
	    ISCSI_LOGIN_PARAM_DEFAULT_TIME_2_RETAIN));
}

IMA_API	IMA_STATUS IMA_GetDefaultTime2WaitProperties(
		IMA_OID lhbaId,
		IMA_MIN_MAX_VALUE *pProps
)
{
	return (getISCSINodeParameter(MIN_MAX_PARAM, &lhbaId, pProps,
	    ISCSI_LOGIN_PARAM_DEFAULT_TIME_2_WAIT));
}

IMA_API	IMA_STATUS IMA_SetDefaultTime2Wait(
		IMA_OID lhbaId,
		IMA_UINT defaultTime2Wait
)
{
	IMA_MIN_MAX_VALUE mv;

	mv.currentValue = defaultTime2Wait;
	return (setISCSINodeParameter(MIN_MAX_PARAM, &lhbaId, &mv,
	    ISCSI_LOGIN_PARAM_DEFAULT_TIME_2_WAIT));
}

IMA_API	IMA_STATUS IMA_GetMaxOutstandingR2TProperties(
		IMA_OID Oid,
		IMA_MIN_MAX_VALUE *pProps
)
{
	return (getISCSINodeParameter(MIN_MAX_PARAM, &Oid, pProps,
	    ISCSI_LOGIN_PARAM_OUTSTANDING_R2T));
}

IMA_API	IMA_STATUS IMA_SetMaxOutstandingR2T(
		IMA_OID lhbaId,
		IMA_UINT maxOutstandingR2T
)
{
	IMA_MIN_MAX_VALUE mv;

	mv.currentValue = maxOutstandingR2T;
	return (setISCSINodeParameter(MIN_MAX_PARAM, &lhbaId, &mv,
	    ISCSI_LOGIN_PARAM_OUTSTANDING_R2T));
}


IMA_API	IMA_STATUS IMA_GetErrorRecoveryLevelProperties(
		IMA_OID Oid,
		IMA_MIN_MAX_VALUE *pProps
)
{
	return (getISCSINodeParameter(MIN_MAX_PARAM, &Oid, pProps,
	    ISCSI_LOGIN_PARAM_ERROR_RECOVERY_LEVEL));
}

IMA_API	IMA_STATUS IMA_SetErrorRecoveryLevel(
		IMA_OID Oid,
		IMA_UINT errorRecoveryLevel
)
{
	IMA_MIN_MAX_VALUE mv;

	mv.currentValue = errorRecoveryLevel;
	return (setISCSINodeParameter(MIN_MAX_PARAM, &Oid, &mv,
	    ISCSI_LOGIN_PARAM_ERROR_RECOVERY_LEVEL));
}

IMA_API	IMA_STATUS IMA_GetInitialR2TProperties(
		IMA_OID Oid,
		IMA_BOOL_VALUE *pProps
)
{
	return (getISCSINodeParameter(BOOL_PARAM, &Oid, pProps,
	    ISCSI_LOGIN_PARAM_INITIAL_R2T));
}

IMA_API	IMA_STATUS IMA_SetInitialR2T(
		IMA_OID Oid,
		IMA_BOOL initialR2T
)
{
	IMA_BOOL_VALUE bv;

	bv.currentValue = initialR2T;
	return (setISCSINodeParameter(BOOL_PARAM, &Oid, &bv,
	    ISCSI_LOGIN_PARAM_INITIAL_R2T));
}


IMA_API	IMA_STATUS IMA_GetImmediateDataProperties(
		IMA_OID Oid,
		IMA_BOOL_VALUE *pProps
)
{
	return (getISCSINodeParameter(BOOL_PARAM, &Oid, pProps,
	    ISCSI_LOGIN_PARAM_IMMEDIATE_DATA));
}

IMA_API	IMA_STATUS IMA_SetImmediateData(
		IMA_OID Oid,
		IMA_BOOL immediateData
)
{
	IMA_BOOL_VALUE bv;

	bv.currentValue = immediateData;
	return (setISCSINodeParameter(BOOL_PARAM, &Oid, &bv,
	    ISCSI_LOGIN_PARAM_IMMEDIATE_DATA));
}

IMA_API	IMA_STATUS IMA_GetDataPduInOrderProperties(
		IMA_OID Oid,
		IMA_BOOL_VALUE *pProps
)
{
	return (getISCSINodeParameter(BOOL_PARAM, &Oid, pProps,
	    ISCSI_LOGIN_PARAM_DATA_PDU_IN_ORDER));
}

IMA_API	IMA_STATUS IMA_SetDataPduInOrder(
		IMA_OID Oid,
		IMA_BOOL dataPduInOrder
)
{
	IMA_BOOL_VALUE bv;

	bv.currentValue = dataPduInOrder;
	return (setISCSINodeParameter(BOOL_PARAM, &Oid, &bv,
	    ISCSI_LOGIN_PARAM_DATA_PDU_IN_ORDER));
}

IMA_API	IMA_STATUS IMA_GetDataSequenceInOrderProperties(
		IMA_OID Oid,
		IMA_BOOL_VALUE *pProps
)
{
	return (getISCSINodeParameter(BOOL_PARAM, &Oid, pProps,
	    ISCSI_LOGIN_PARAM_DATA_SEQUENCE_IN_ORDER));
}

IMA_API	IMA_STATUS IMA_SetDataSequenceInOrder(
		IMA_OID Oid,
		IMA_BOOL dataSequenceInOrder
)
{
	IMA_BOOL_VALUE bv;

	bv.currentValue = dataSequenceInOrder;
	return (setISCSINodeParameter(BOOL_PARAM, &Oid, &bv,
	    ISCSI_LOGIN_PARAM_DATA_SEQUENCE_IN_ORDER));
}


/*ARGSUSED*/
IMA_API	IMA_STATUS IMA_SetStatisticsCollection(
		IMA_OID Oid,
		IMA_BOOL enableStatisticsCollection
)
{
	return (IMA_ERROR_NOT_SUPPORTED);
}


/*ARGSUSED*/
IMA_API	IMA_STATUS IMA_GetDiscoveryAddressOidList(
		IMA_OID Oid,
		IMA_OID_LIST **ppList
)
{
	int fd, i, addr_list_size;
	iscsi_addr_list_t *idlp, al_info;

	if ((fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) == -1) {
		syslog(LOG_USER|LOG_DEBUG, "Cannot open %s (%d)",
		    ISCSI_DRIVER_DEVCTL, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(void) memset(&al_info, 0, sizeof (al_info));
	al_info.al_vers = ISCSI_INTERFACE_VERSION;
	al_info.al_in_cnt = 0;

	/*
	 * Issue ioctl to obtain the number of targets.
	 */
	if (ioctl(fd, ISCSI_DISCOVERY_ADDR_LIST_GET, &al_info) != 0) {
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_DISCOVERY_ADDR_LIST_GET ioctl %d failed, errno: %d",
		    ISCSI_DISCOVERY_ADDR_LIST_GET, errno);
		(void) close(fd);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	addr_list_size = sizeof (iscsi_addr_list_t);
	if (al_info.al_out_cnt > 1) {
		addr_list_size += (sizeof (iscsi_addr_list_t) *
		    al_info.al_out_cnt - 1);
	}

	idlp = (iscsi_addr_list_t *)calloc(1, addr_list_size);
	if (idlp == NULL) {
		(void) close(fd);
		return (IMA_ERROR_INSUFFICIENT_MEMORY);
	}

	idlp->al_vers = ISCSI_INTERFACE_VERSION;
	idlp->al_in_cnt = al_info.al_out_cnt;
	/* Issue the same ioctl again to obtain the OIDs. */
	if (ioctl(fd, ISCSI_DISCOVERY_ADDR_LIST_GET, idlp) != 0) {
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_TARGET_OID_LIST_GET ioctl %d failed, errno: %d",
		    ISCSI_DISCOVERY_ADDR_LIST_GET, errno);
		free(idlp);
		(void) close(fd);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	*ppList = (IMA_OID_LIST *)calloc(1, sizeof (IMA_OID_LIST) +
	    idlp->al_out_cnt * sizeof (IMA_OID));
	if (*ppList == NULL) {
		free(idlp);
		(void) close(fd);
		return (IMA_ERROR_INSUFFICIENT_MEMORY);
	}
	(*ppList)->oidCount = idlp->al_out_cnt;

	for (i = 0; i < idlp->al_out_cnt; i++) {
		(*ppList)->oids[i].objectType =
		    IMA_OBJECT_TYPE_DISCOVERY_ADDRESS;
		(*ppList)->oids[i].ownerId = pluginOwnerId;
		(*ppList)->oids[i].objectSequenceNumber =
		    idlp->al_addrs[i].a_oid;
	}

	free(idlp);
	(void) close(fd);

	return (IMA_STATUS_SUCCESS);
}


/* ARGSUSED */
IMA_API	IMA_STATUS IMA_GetStaticDiscoveryTargetOidList(
		IMA_OID Oid,
		IMA_OID_LIST **ppList
)
{
	if (Oid.objectType == IMA_OBJECT_TYPE_PNP) {
		return (IMA_ERROR_OBJECT_NOT_FOUND);
	}

	return (get_target_oid_list(ISCSI_STATIC_TGT_OID_LIST, ppList));
}

/* ARGSUSED */
IMA_API	IMA_STATUS IMA_GetTargetOidList(
		IMA_OID Oid,
		IMA_OID_LIST **ppList
)
{
	return (get_target_oid_list(ISCSI_TGT_PARAM_OID_LIST, ppList));
}

/*ARGSUSED*/
IMA_API	IMA_STATUS IMA_SetIsnsDiscovery(
		IMA_OID phbaId,
		IMA_BOOL enableIsnsDiscovery,
		IMA_ISNS_DISCOVERY_METHOD discoveryMethod,
		const IMA_HOST_ID *iSnsHost
)
{
	/* XXX need to set discovery Method and domaineName */
	return (configure_discovery_method(enableIsnsDiscovery,
	    iSCSIDiscoveryMethodISNS));
}


/* ARGSUSED */
IMA_API	IMA_STATUS IMA_SetSlpDiscovery(
		IMA_OID phbaId,
		IMA_BOOL enableSlpDiscovery
)
{
	return (configure_discovery_method(enableSlpDiscovery,
	    iSCSIDiscoveryMethodSLP));
}


/* ARGSUSED */
IMA_API	IMA_STATUS IMA_SetStaticDiscovery(
		IMA_OID phbaId,
		IMA_BOOL enableStaticDiscovery
)
{
	return (configure_discovery_method(enableStaticDiscovery,
	    iSCSIDiscoveryMethodStatic));
}

/* ARGSUSED */
IMA_API	IMA_STATUS IMA_SetSendTargetsDiscovery(
		IMA_OID phbaId,
		IMA_BOOL enableSendTargetsDiscovery
)
{
	return (configure_discovery_method(enableSendTargetsDiscovery,
	    iSCSIDiscoveryMethodSendTargets));
}

/*ARGSUSED*/
IMA_API IMA_STATUS IMA_RemoveDiscoveryAddress(
		IMA_OID	discoveryAddressOid
)
{
	int status, fd, i, addr_list_size;
	iscsi_addr_list_t *idlp, al_info;
	iscsi_addr_t *matched_addr = NULL;
	entry_t	entry;

	if ((fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) == -1) {
		syslog(LOG_USER|LOG_DEBUG, "Cannot open %s (%d)",
		    ISCSI_DRIVER_DEVCTL, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(void) memset(&al_info, 0, sizeof (al_info));
	al_info.al_vers = ISCSI_INTERFACE_VERSION;
	al_info.al_in_cnt = 0;

	/*
	 * Issue ioctl to obtain the number of discovery address.
	 */
	if (ioctl(fd, ISCSI_DISCOVERY_ADDR_LIST_GET, &al_info) != 0) {
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_DISCOVERY_ADDR_LIST_GET ioctl %d failed, errno: %d",
		    ISCSI_DISCOVERY_ADDR_LIST_GET, errno);
		(void) close(fd);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	if (al_info.al_out_cnt == 0) {
		return (IMA_ERROR_OBJECT_NOT_FOUND);
	}

	addr_list_size = sizeof (iscsi_addr_list_t);
	if (al_info.al_out_cnt > 1) {
		addr_list_size += (sizeof (iscsi_addr_list_t) *
		    al_info.al_out_cnt - 1);
	}

	idlp = (iscsi_addr_list_t *)calloc(1, addr_list_size);
	if (idlp == NULL) {
		(void) close(fd);
		return (IMA_ERROR_INSUFFICIENT_MEMORY);
	}

	idlp->al_vers = ISCSI_INTERFACE_VERSION;
	idlp->al_in_cnt = al_info.al_out_cnt;

	/* Issue the same ioctl again to obtain the OIDs. */
	if (ioctl(fd, ISCSI_DISCOVERY_ADDR_LIST_GET, idlp) != 0) {
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_TARGET_OID_LIST_GET ioctl %d failed, errno: %d",
		    ISCSI_DISCOVERY_ADDR_LIST_GET, errno);
		free(idlp);
		(void) close(fd);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	for (i = 0; i < idlp->al_out_cnt; i++) {
		if (discoveryAddressOid.objectSequenceNumber !=
		    idlp->al_addrs[i].a_oid)
			continue;
		matched_addr = &(idlp->al_addrs[i]);
	}

	if (matched_addr == NULL) {
		return (IMA_ERROR_OBJECT_NOT_FOUND);
	}


	(void) memset(&entry, 0, sizeof (entry_t));
	entry.e_vers = ISCSI_INTERFACE_VERSION;
	entry.e_oid  = discoveryAddressOid.objectSequenceNumber;
	if (matched_addr->a_addr.i_insize == sizeof (struct in_addr)) {
		bcopy(&matched_addr->a_addr.i_addr.in4,
		    &entry.e_u.u_in4, sizeof (entry.e_u.u_in4));
		entry.e_insize = sizeof (struct in_addr);
	} else if (matched_addr->a_addr.i_insize == sizeof (struct in6_addr)) {
		bcopy(&matched_addr->a_addr.i_addr.in6,
		    &entry.e_u.u_in6, sizeof (entry.e_u.u_in6));
		entry.e_insize = sizeof (struct in6_addr);
	} else {
		/* Should not happen */
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_STATIC_GET returned bad address");
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	entry.e_port = matched_addr->a_port;
	entry.e_tpgt = 0;
	entry.e_oid = discoveryAddressOid.objectSequenceNumber;

	if (ioctl(fd, ISCSI_DISCOVERY_ADDR_CLEAR, &entry)) {
		status = errno;
		(void) close(fd);
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_DISCOVERY_ADDR_CLEAR ioctl failed, errno: %d",
		    errno);
		if (status == EBUSY) {
			return (IMA_ERROR_LU_IN_USE);
		} else {
			return (IMA_ERROR_UNEXPECTED_OS_ERROR);
		}
	}

	free(idlp);
	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}


/*ARGSUSED*/
IMA_API IMA_STATUS IMA_AddDiscoveryAddress(
		IMA_OID	oid,
		const IMA_TARGET_ADDRESS discoveryAddress,
		IMA_OID	*pDiscoveryAddressOid
)
{
	entry_t	    entry;
	int	    fd;

	if ((fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) == -1) {
		syslog(LOG_USER|LOG_DEBUG, "Cannot open %s (%d)",
		    ISCSI_DRIVER_DEVCTL, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	if (prepare_discovery_entry(discoveryAddress, &entry) !=
	    DISC_ADDR_OK) {
		(void) close(fd);
		return (IMA_ERROR_INVALID_PARAMETER);
	}

	if (ioctl(fd, ISCSI_DISCOVERY_ADDR_SET, &entry)) {
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_DISCOVERY_ADDR_SET ioctl failed, errno: %d",
		    errno);
		(void) close(fd);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	pDiscoveryAddressOid->ownerId = pluginOwnerId;
	pDiscoveryAddressOid->objectType = IMA_OBJECT_TYPE_DISCOVERY_ADDRESS;
	pDiscoveryAddressOid->objectSequenceNumber = entry.e_oid;

	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}

IMA_API IMA_STATUS IMA_GetStaticDiscoveryTargetProperties(
		IMA_OID	staticTargetOid,
		IMA_STATIC_DISCOVERY_TARGET_PROPERTIES *pProps
)
{
	char static_target_addr_str[SUN_IMA_IP_ADDRESS_LEN];
	char static_target_addr_port_str[SUN_IMA_IP_ADDRESS_LEN];
	int af, fd, status;
	iscsi_static_property_t prop;
	/* LINTED */
	IMA_HOST_ID *host;

	if ((fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) == -1) {
		syslog(LOG_USER|LOG_DEBUG, "Cannot open %s (%d)",
		    ISCSI_DRIVER_DEVCTL, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(void) memset(&prop, 0, sizeof (iscsi_static_property_t));
	prop.p_vers = ISCSI_INTERFACE_VERSION;
	prop.p_oid = (uint32_t)staticTargetOid.objectSequenceNumber;
	if (ioctl(fd, ISCSI_STATIC_GET, &prop) != 0) {
		status = errno;
		(void) close(fd);
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_STATIC_GET ioctl failed, errno: %d", status);
		if (status == ENOENT) {
			return (IMA_ERROR_OBJECT_NOT_FOUND);

		} else {
			return (IMA_ERROR_UNEXPECTED_OS_ERROR);
		}
	}
	(void) close(fd);

	(void) mbstowcs(pProps->staticTarget.targetName, (char *)prop.p_name,
	    sizeof (pProps->staticTarget.targetName)/sizeof (IMA_WCHAR));

	if (prop.p_addr_list.al_addrs[0].a_addr.i_insize ==
	    sizeof (struct in_addr)) {
		/* IPv4 */
		af = AF_INET;
	} else if (prop.p_addr_list.al_addrs[0].a_addr.i_insize ==
	    sizeof (struct in6_addr)) {
		/* IPv6 */
		af = AF_INET6;
	} else {
		/* Should not happen */
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_STATIC_GET returned bad address");
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	if (inet_ntop(af, &prop.p_addr_list.al_addrs[0].a_addr.i_addr,
	    static_target_addr_str, sizeof (static_target_addr_str)) == NULL) {
		/* Should not happen */
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_STATIC_GET returned address that cannot "
		    "be inet_ntop");
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	} else {
		if (af == AF_INET) {
			(void) snprintf(static_target_addr_port_str,
			    SUN_IMA_IP_ADDRESS_LEN,
			    "%s:%ld",
			    static_target_addr_str,
			    prop.p_addr_list.al_addrs[0].a_port);
		} else {
			(void) snprintf(static_target_addr_port_str,
			    SUN_IMA_IP_ADDRESS_LEN,
			    "[%s]:%ld",
			    static_target_addr_str,
			    prop.p_addr_list.al_addrs[0].a_port);
		}
		host = &pProps->staticTarget.targetAddress.hostnameIpAddress;
		(void) mbstowcs(pProps->staticTarget.
		    targetAddress.hostnameIpAddress.
		    id.hostname, static_target_addr_port_str,
		    sizeof (host->id.hostname) / sizeof (IMA_WCHAR));
	}

	return (IMA_STATUS_SUCCESS);
}

/*ARGSUSED*/
IMA_API IMA_STATUS IMA_GetDiscoveryAddressProperties(
		IMA_OID	discoveryAddressOid,
		IMA_DISCOVERY_ADDRESS_PROPERTIES *pProps
)
{
	int fd;
	int i;
	int addr_list_size;
	iscsi_addr_list_t *idlp, al_info;
	iscsi_addr_t *matched_addr = NULL;
	/* LINTED */
	IMA_TARGET_ADDRESS *addr;

	if ((fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) == -1) {
		syslog(LOG_USER|LOG_DEBUG, "Cannot open %s (%d)",
		    ISCSI_DRIVER_DEVCTL, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(void) memset(&al_info, 0, sizeof (al_info));
	al_info.al_vers = ISCSI_INTERFACE_VERSION;
	al_info.al_in_cnt = 0;

	/*
	 * Issue ioctl to obtain the number of discovery addresses.
	 */
	if (ioctl(fd, ISCSI_DISCOVERY_ADDR_LIST_GET, &al_info) != 0) {
		(void) close(fd);
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_DISCOVERY_ADDR_LIST_GET ioctl %d failed, errno: %d",
		    ISCSI_DISCOVERY_ADDR_LIST_GET, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	if (al_info.al_out_cnt == 0) {
		return (IMA_ERROR_OBJECT_NOT_FOUND);
	}

	addr_list_size = sizeof (iscsi_addr_list_t);
	if (al_info.al_out_cnt > 1) {
		addr_list_size += (sizeof (iscsi_addr_list_t) *
		    al_info.al_out_cnt - 1);
	}

	idlp = (iscsi_addr_list_t *)calloc(1, addr_list_size);
	if (idlp == NULL) {
		(void) close(fd);
		return (IMA_ERROR_INSUFFICIENT_MEMORY);
	}

	idlp->al_vers = ISCSI_INTERFACE_VERSION;
	idlp->al_in_cnt = al_info.al_out_cnt;

	/* Issue the same ioctl again to obtain the OIDs. */
	if (ioctl(fd, ISCSI_DISCOVERY_ADDR_LIST_GET, idlp) != 0) {
		free(idlp);
		(void) close(fd);
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_TARGET_OID_LIST_GET ioctl %d failed, errno: %d",
		    ISCSI_DISCOVERY_ADDR_LIST_GET, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	for (i = 0; i < idlp->al_out_cnt; i++) {
		if (discoveryAddressOid.objectSequenceNumber !=
		    idlp->al_addrs[i].a_oid)
			continue;
		matched_addr = &(idlp->al_addrs[i]);
	}

	if (matched_addr == NULL) {
		return (IMA_ERROR_OBJECT_NOT_FOUND);
	}

	if (matched_addr->a_addr.i_insize == sizeof (struct in_addr)) {
		pProps->discoveryAddress.hostnameIpAddress.id.
		    ipAddress.ipv4Address = IMA_TRUE;
	} else if (matched_addr->a_addr.i_insize == sizeof (struct in6_addr)) {
		pProps->discoveryAddress.hostnameIpAddress.id.
		    ipAddress.ipv4Address = IMA_FALSE;
	} else {
		/* Should not happen */
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_STATIC_GET returned bad address");
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	addr = &pProps->discoveryAddress;
	bcopy(&(matched_addr->a_addr.i_addr), pProps->discoveryAddress.
	    hostnameIpAddress.id.ipAddress.ipAddress,
	    sizeof (addr->hostnameIpAddress.id.ipAddress.ipAddress));

	pProps->discoveryAddress.portNumber = matched_addr->a_port;

	pProps->associatedLhbaOid.objectType = IMA_OBJECT_TYPE_LHBA;
	pProps->associatedLhbaOid.ownerId = pluginOwnerId;
	pProps->associatedLhbaOid.objectSequenceNumber = ISCSI_INITIATOR_OID;

	free(idlp);
	(void) close(fd);

	return (IMA_STATUS_SUCCESS);
}

IMA_API IMA_STATUS IMA_RemoveStaticDiscoveryTarget(
		IMA_OID staticTargetOid
)
{
	entry_t	entry;
	int	status, fd;

	if ((fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) == -1) {
		syslog(LOG_USER|LOG_DEBUG, "Cannot open %s (%d)",
		    ISCSI_DRIVER_DEVCTL, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(void) memset(&entry, 0, sizeof (entry_t));
	entry.e_vers = ISCSI_INTERFACE_VERSION;
	entry.e_oid = (uint32_t)staticTargetOid.objectSequenceNumber;

	if (ioctl(fd, ISCSI_STATIC_CLEAR, &entry)) {
		status = errno;
		(void) close(fd);
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_STATIC_CLEAR ioctl failed, errno: %d", errno);
		if (status == EBUSY) {
			return (IMA_ERROR_LU_IN_USE);
		} else {
			return (IMA_ERROR_UNEXPECTED_OS_ERROR);
		}
	}

	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}

/*ARGSUSED*/
IMA_API IMA_STATUS IMA_AddStaticDiscoveryTarget(
		IMA_OID lhbaOid,
		const IMA_STATIC_DISCOVERY_TARGET staticConfig,
		IMA_OID *pTargetOid
)
{
	char			tmp_target_str[SUN_IMA_IP_ADDRESS_LEN];
	char			target_addr_str[SUN_IMA_IP_ADDRESS_LEN];
	char			target_port_str[SUN_IMA_IP_PORT_LEN];
	iscsi_target_entry_t	target;
	int			fd;
	int			target_in_addr_size;
	int			target_port;
	union {
		struct in_addr	u_in4;
		struct in6_addr	u_in6;
	}			target_in;

	/*
	 * staticConfig.address may come in with port number at its trailer.
	 * Parse it to separate the IP address and port number.
	 * Also translate the hostname to IP address if needed.
	 */
	(void) wcstombs(tmp_target_str,
	    staticConfig.targetAddress.hostnameIpAddress.
	    id.hostname, sizeof (tmp_target_str));

	if (tmp_target_str[0] == '[') {
		/* IPv6 address */
		char *closeBracketPos;
		closeBracketPos = strchr(tmp_target_str, ']');
		if (!closeBracketPos) {
			return (IMA_ERROR_INVALID_PARAMETER);
		}

		*closeBracketPos = '\0';
		(void) strlcpy(target_addr_str, &tmp_target_str[1],
		    sizeof (target_addr_str));

		if (inet_pton(AF_INET6, target_addr_str,
		    &target_in.u_in6) != 1) {
			return (IMA_ERROR_INVALID_PARAMETER);
		}
		target_in_addr_size = sizeof (struct in6_addr);

		/* Extract the port number */
		closeBracketPos++;
		if (*closeBracketPos == ':') {
			closeBracketPos++;

			if (*closeBracketPos != '\0') {
				(void) strlcpy(target_port_str, closeBracketPos,
				    sizeof (target_port_str));
				target_port = atoi(target_port_str);
			} else {
				target_port = ISCSI_LISTEN_PORT;
			}
		} else {
			/* No port number specified; use default port */
			target_port = ISCSI_LISTEN_PORT;
		}
	} else {
		/* IPv4 address */
		char *colonPos;
		colonPos = strchr(tmp_target_str, ':');
		if (!colonPos) {
			/* No port number specified; use default port */
			target_port = ISCSI_LISTEN_PORT;
			(void) strlcpy(target_addr_str, tmp_target_str,
			    sizeof (target_addr_str));
		} else {
			*colonPos = '\0';
			(void) strlcpy(target_addr_str, tmp_target_str,
			    sizeof (target_addr_str));
			/* Extract the port number */
			colonPos++;
			if (*colonPos != '\0') {
				(void) strlcpy(target_port_str, colonPos,
				    sizeof (target_port_str));
				target_port = atoi(target_port_str);
			} else {
				target_port = ISCSI_LISTEN_PORT;
			}
		}

		if (inet_pton(AF_INET, target_addr_str,
		    &target_in.u_in4) != 1) {
			return (IMA_ERROR_INVALID_PARAMETER);
		}

		target_in_addr_size = sizeof (struct in_addr);
	}


	(void) memset(&target, 0, sizeof (iscsi_target_entry_t));
	target.te_entry.e_vers = ISCSI_INTERFACE_VERSION;
	target.te_entry.e_oid = ISCSI_OID_NOTSET;
	target.te_entry.e_tpgt = ISCSI_DEFAULT_TPGT;

	(void) wcstombs((char *)target.te_name, staticConfig.targetName,
	    ISCSI_MAX_NAME_LEN);

	target.te_entry.e_insize = target_in_addr_size;
	if (target.te_entry.e_insize == sizeof (struct in_addr)) {
		target.te_entry.e_u.u_in4.s_addr = target_in.u_in4.s_addr;
	} else if (target.te_entry.e_insize == sizeof (struct in6_addr)) {
		bcopy(target_in.u_in6.s6_addr,
		    target.te_entry.e_u.u_in6.s6_addr,
		    sizeof (struct in6_addr));
	} else {
		/* Should not happen */
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_STATIC_GET returned bad address");
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	target.te_entry.e_port = target_port;

	/* No target portal group specified. Default to -1. */
	target.te_entry.e_tpgt = ISCSI_DEFAULT_TPGT;

	if ((fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) == -1) {
		syslog(LOG_USER|LOG_DEBUG, "Cannot open %s (%d)",
		    ISCSI_DRIVER_DEVCTL, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	if (ioctl(fd, ISCSI_STATIC_SET, &target)) {
		/*
		 * Encountered problem setting the IP address and port for
		 * the target just added.
		 */
		(void) close(fd);
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_STATIC_SET ioctl failed, errno: %d", errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	pTargetOid->objectType = IMA_OBJECT_TYPE_TARGET;
	pTargetOid->ownerId = pluginOwnerId;
	pTargetOid->objectSequenceNumber = target.te_entry.e_oid;

	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}

IMA_API	IMA_STATUS IMA_GetTargetProperties(
		IMA_OID targetId,
		IMA_TARGET_PROPERTIES *pProps
)
{
	return (getTargetProperties(targetId, pProps));
}

static IMA_STATUS getTargetProperties(
		IMA_OID targetId,
		IMA_TARGET_PROPERTIES *pProps
)
{
	int		    fd;
	iscsi_property_t    prop;

	if ((fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) == -1) {
		syslog(LOG_USER|LOG_DEBUG, "Cannot open %s (%d)",
		    ISCSI_DRIVER_DEVCTL, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(void) memset(&prop, 0, sizeof (iscsi_property_t));
	prop.p_vers = ISCSI_INTERFACE_VERSION;
	prop.p_oid = (uint32_t)targetId.objectSequenceNumber;

	if (ioctl(fd, ISCSI_TARGET_PROPS_GET, &prop) != 0) {
		(void) close(fd);
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_TARGET_PROPS_GET ioctl failed, errno: %d", errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(void) mbstowcs(pProps->name, (char *)prop.p_name, IMA_NODE_NAME_LEN);
	(void) memset(pProps->alias, 0,
	    sizeof (IMA_WCHAR) * IMA_NODE_ALIAS_LEN);
	if (prop.p_alias_len > 0) {
		(void) mbstowcs(pProps->alias, (char *)prop.p_alias,
		    IMA_NODE_ALIAS_LEN);
	}

	/* Initialize the discovery method to unknown method. */
	pProps->discoveryMethodFlags = IMA_TARGET_DISCOVERY_METHOD_UNKNOWN;
	if (!((prop.p_discovery & iSCSIDiscoveryMethodStatic) ^
	    iSCSIDiscoveryMethodStatic)) {
		pProps->discoveryMethodFlags |=
		    IMA_TARGET_DISCOVERY_METHOD_STATIC;
	}

	if (!((prop.p_discovery & iSCSIDiscoveryMethodSLP) ^
	    iSCSIDiscoveryMethodSLP)) {
		pProps->discoveryMethodFlags |=	IMA_TARGET_DISCOVERY_METHOD_SLP;
	}

	if (!((prop.p_discovery & iSCSIDiscoveryMethodISNS) ^
	    iSCSIDiscoveryMethodISNS)) {
		pProps->discoveryMethodFlags |=	iSCSIDiscoveryMethodISNS;
	}

	if (!((prop.p_discovery & iSCSIDiscoveryMethodSendTargets) ^
	    iSCSIDiscoveryMethodSendTargets)) {
		pProps->discoveryMethodFlags |= iSCSIDiscoveryMethodSendTargets;
	}

	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}

/*ARGSUSED*/
IMA_API	IMA_STATUS IMA_GetTargetErrorStatistics(
		IMA_OID targetId,
		IMA_TARGET_ERROR_STATISTICS *pStats
)
{
	return (IMA_ERROR_NOT_SUPPORTED);
}

IMA_API	IMA_STATUS IMA_GetLuOidList(
		IMA_OID oid,
		IMA_OID_LIST **ppList
)
{
	IMA_STATUS		status;
	int			i;
	iscsi_lun_list_t	*pLunList;

	if (oid.objectType == IMA_OBJECT_TYPE_LHBA) {
		status = get_target_lun_oid_list(NULL, &pLunList);
	} else {
		status = get_target_lun_oid_list(&oid, &pLunList);
	}

	if (!IMA_SUCCESS(status)) {
		return (status);
	}

	*ppList = (IMA_OID_LIST *) calloc(1, (sizeof (IMA_OID_LIST) +
	    (pLunList->ll_out_cnt * sizeof (IMA_OID))));
	if (*ppList == NULL) {
		return (IMA_ERROR_INSUFFICIENT_MEMORY);
	}
	(*ppList)->oidCount = pLunList->ll_out_cnt;
	for (i = 0; i < pLunList->ll_out_cnt; i++) {
		(*ppList)->oids[i].objectType = IMA_OBJECT_TYPE_LU;
		(*ppList)->oids[i].ownerId = pluginOwnerId;
		(*ppList)->oids[i].objectSequenceNumber =
		    pLunList->ll_luns[i].l_oid;
	}

	free(pLunList);
	return (IMA_STATUS_SUCCESS);
}

IMA_API	IMA_STATUS IMA_GetLuOid(
		IMA_OID targetId,
		IMA_UINT64 lun,
		IMA_OID *pluId
)
{
	IMA_STATUS		status;
	int			i;
	iscsi_lun_list_t	*pLunList;

	status = get_target_lun_oid_list(&targetId, &pLunList);
	if (!IMA_SUCCESS(status)) {
		return (status);
	}

	for (i = 0; i < pLunList->ll_out_cnt; i++) {
		if (pLunList->ll_luns[i].l_num == lun) {
			pluId->objectType = IMA_OBJECT_TYPE_LU;
			pluId->ownerId = pluginOwnerId;
			pluId->objectSequenceNumber =
			    pLunList->ll_luns[i].l_oid;
			free(pLunList);
			return (IMA_STATUS_SUCCESS);
		}
	}

	free(pLunList);
	return (IMA_ERROR_OBJECT_NOT_FOUND);
}

IMA_API	IMA_STATUS IMA_GetLuProperties(
		IMA_OID luId,
		IMA_LU_PROPERTIES *pProps
)
{
	return (getLuProperties(luId, pProps));
}

static IMA_STATUS getLuProperties(
		IMA_OID luId,
		IMA_LU_PROPERTIES *pProps
)
{
	IMA_STATUS		status;
	iscsi_lun_list_t	*pLunList;
	int			j;
	IMA_BOOL		lunMatch = IMA_FALSE;
	int			fd;
	iscsi_lun_props_t	lun;
	di_devlink_handle_t	hdl;

	if (luId.objectType != IMA_OBJECT_TYPE_LU) {
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);
	}

	/*
	 * get list of lun oids for all targets
	 */
	status = get_target_lun_oid_list(NULL, &pLunList);
	if (!IMA_SUCCESS(status)) {
		return (status);
	}
	for (j = 0; j < pLunList->ll_out_cnt; j++) {
		/*
		 * for each lun, check if match is found
		 */
		if (pLunList->ll_luns[j].l_oid == luId.objectSequenceNumber) {
			/*
			 * match found, break out of lun loop
			 */
			lunMatch = IMA_TRUE;
			break;
		}
	}

	if (lunMatch == IMA_TRUE) {
		(void) memset(&lun, 0, sizeof (iscsi_lun_props_t));
		lun.lp_vers = ISCSI_INTERFACE_VERSION;
		lun.lp_tgt_oid = pLunList->ll_luns[j].l_tgt_oid;
		lun.lp_oid = pLunList->ll_luns[j].l_oid;
	}

	free(pLunList);

	if (lunMatch == IMA_FALSE) {
		return (IMA_ERROR_OBJECT_NOT_FOUND);
	}

	/*
	 * get lun properties
	 */
	if ((fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) == -1) {
		syslog(LOG_USER|LOG_DEBUG, "Cannot open %s (%d)",
		    ISCSI_DRIVER_DEVCTL, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	if (ioctl(fd, ISCSI_LUN_PROPS_GET, &lun)) {
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_LUN_PROPS_GET ioctl failed, errno: %d", errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}
	(void) close(fd);

	/*
	 * set property values
	 */
	pProps->associatedTargetOid.objectType = IMA_OBJECT_TYPE_TARGET;
	pProps->associatedTargetOid.ownerId = pluginOwnerId;
	pProps->associatedTargetOid.objectSequenceNumber = lun.lp_tgt_oid;
	pProps->targetLun = (IMA_UINT64)lun.lp_num;
	pProps->exposedToOs = IMA_TRUE;
	(void) memset(&pProps->timeExposedToOs, 0,
	    sizeof (pProps->timeExposedToOs));

	if (lun.lp_status == LunValid) {

		/* add minor device delimiter */
		(void) strcat(lun.lp_pathname, ":");

		if ((strstr(lun.lp_pathname, "sd@") != NULL) ||
		    (strstr(lun.lp_pathname, "ssd@") != NULL) ||
		    (strstr(lun.lp_pathname, "disk@") != NULL)) {
			/*
			 * modify returned pathname to obtain the 2nd slice
			 * of the raw disk
			 */
			(void) strcat(lun.lp_pathname, "c,raw");
		}

		/*
		 * Pathname returned by driver is the physical device path.
		 * This name needs to be converted to the OS device name.
		 */
		if (hdl = di_devlink_init(lun.lp_pathname, DI_MAKE_LINK)) {
			pProps->osDeviceName[0] = L'\0';
			(void) di_devlink_walk(hdl, NULL, lun.lp_pathname,
			    DI_PRIMARY_LINK, (void *)pProps->osDeviceName,
			    get_lun_devlink);
			if (pProps->osDeviceName[0] != L'\0') {
				/* OS device name synchronously made */
				pProps->osDeviceNameValid = IMA_TRUE;
			} else {
				pProps->osDeviceNameValid = IMA_FALSE;
			}

			(void) di_devlink_fini(&hdl);
		} else {
			pProps->osDeviceNameValid = IMA_FALSE;
		}

	} else {
		pProps->osDeviceNameValid = IMA_FALSE;
	}

	pProps->osParallelIdsValid = IMA_FALSE;

	return (IMA_STATUS_SUCCESS);
}

/*ARGSUSED*/
IMA_API	IMA_STATUS IMA_GetStatisticsProperties(
		IMA_OID oid,
		IMA_STATISTICS_PROPERTIES *pProps
)
{
	return (IMA_ERROR_NOT_SUPPORTED);
}

/*ARGSUSED*/
IMA_API	IMA_STATUS IMA_GetDeviceStatistics(
		IMA_OID luId,
		IMA_DEVICE_STATISTICS *pStats
)
{
	return (IMA_ERROR_NOT_SUPPORTED);
}

IMA_API	IMA_STATUS IMA_LuInquiry(
	IMA_OID deviceId,
	IMA_BOOL evpd,
	IMA_BOOL cmddt,
	IMA_BYTE pageCode,
	IMA_BYTE *pOutputBuffer,
	IMA_UINT *pOutputBufferLength,
	IMA_BYTE *pSenseBuffer,
	IMA_UINT *pSenseBufferLength
)
{
	IMA_LU_PROPERTIES luProps;
	IMA_STATUS status;
	unsigned char cmdblk[CDB_GROUP0];
	IMA_UINT buflen;
	int fd;
	iscsi_uscsi_t uscsi;

	(void) memset(&cmdblk[0], 0, CDB_GROUP0);
	cmdblk[0] = SCMD_INQUIRY;

	if (evpd == IMA_TRUE)
		cmdblk[1] |= 0x01;
	if (cmddt == IMA_TRUE)
		cmdblk[1] |= 0x02;

	cmdblk[2] = pageCode;

	if (*pOutputBufferLength > MAX_INQUIRY_BUFFER_LEN) {
		buflen = MAX_INQUIRY_BUFFER_LEN;
	} else {
		buflen = *pOutputBufferLength;
	}
	cmdblk[3] = (buflen & 0xff00) >> 8;
	cmdblk[4] = (buflen & 0x00ff);

	(void) memset(&uscsi, 0, sizeof (iscsi_uscsi_t));
	uscsi.iu_vers = ISCSI_INTERFACE_VERSION;

	/* iu_oid is a session oid in the driver */
	if (deviceId.objectType == IMA_OBJECT_TYPE_TARGET) {
		uscsi.iu_oid	= deviceId.objectSequenceNumber;
		uscsi.iu_lun	= 0;
	} else {
		/*
		 * Get LU properties and associated session oid
		 * for this lun(deviceId) and put in uscsi.iu_oid
		 */
		status = getLuProperties(deviceId, &luProps);
		if (status != IMA_STATUS_SUCCESS) {
			return (status);
		}
		uscsi.iu_oid = (uint32_t)luProps.associatedTargetOid.
		    objectSequenceNumber;
		uscsi.iu_lun = luProps.targetLun;
	}

	uscsi.iu_ucmd.uscsi_flags = USCSI_READ;
	uscsi.iu_ucmd.uscsi_timeout = USCSI_TIMEOUT_IN_SEC;
	uscsi.iu_ucmd.uscsi_bufaddr = (char *)pOutputBuffer;
	uscsi.iu_ucmd.uscsi_buflen = buflen;
	uscsi.iu_ucmd.uscsi_rqbuf = (char *)pSenseBuffer;
	uscsi.iu_ucmd.uscsi_rqlen = (pSenseBufferLength != NULL) ?
	    *pSenseBufferLength : 0;
	uscsi.iu_ucmd.uscsi_cdb = (char *)&cmdblk[0];
	uscsi.iu_ucmd.uscsi_cdblen = CDB_GROUP0;

	if ((fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) == -1) {
		syslog(LOG_USER|LOG_DEBUG, "Cannot open %s (%d)",
		    ISCSI_DRIVER_DEVCTL, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	if (ioctl(fd, ISCSI_USCSI, &uscsi) != 0) {
		(void) close(fd);
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_TARGET_PROPS_GET ioctl failed, errno: %d", errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	if (uscsi.iu_ucmd.uscsi_status == STATUS_CHECK) {
		if (pSenseBufferLength != NULL) {
			*pSenseBufferLength -= uscsi.iu_ucmd.uscsi_rqresid;
		}
		return (IMA_ERROR_SCSI_STATUS_CHECK_CONDITION);
	}

	*pOutputBufferLength = buflen - uscsi.iu_ucmd.uscsi_resid;
	return (IMA_STATUS_SUCCESS);
}

IMA_API	IMA_STATUS IMA_LuReadCapacity(
		IMA_OID deviceId,
		IMA_UINT cdbLength,
		IMA_BYTE *pOutputBuffer,
		IMA_UINT *pOutputBufferLength,

		IMA_BYTE *pSenseBuffer,
		IMA_UINT *pSenseBufferLength
)
{
	IMA_LU_PROPERTIES luProps;
	IMA_STATUS status;
	/* CDB_GROUP4 size is safe for both 10 and 16 byte CDBs */
	unsigned char cmdblk[CDB_GROUP4];
	IMA_UINT buflen;
	int fd;
	iscsi_uscsi_t uscsi;

	(void) memset(&cmdblk[0], 0, CDB_GROUP4);

	if (cdbLength == CDB_GROUP1) {
		/* Read Capacity (10) command. */
		cmdblk[0] = SCMD_READ_CAPACITY;
		buflen = *pOutputBufferLength;
	} else if (cdbLength == CDB_GROUP4) {
		/*
		 * Read Capacity (16) is a Service Action In command. One
		 * command byte (0x9E) is overloaded for multiple operations,
		 * with the second CDB byte specifying the desired operation.
		 */
		cmdblk[0] = SCMD_SVC_ACTION_IN_G4;
		cmdblk[1] = SSVC_ACTION_READ_CAPACITY_G4;

		if (*pOutputBufferLength > MAX_READ_CAPACITY16_BUFFER_LEN) {
			buflen = MAX_READ_CAPACITY16_BUFFER_LEN;
		} else {
			buflen = *pOutputBufferLength;
		}
		cmdblk[10] = (buflen & 0xff000000) >> 24;
		cmdblk[11] = (buflen & 0x00ff0000) >> 16;
		cmdblk[12] = (buflen & 0x0000ff00) >> 8;
		cmdblk[13] = (buflen & 0x000000ff);
	} else {
		/* only 10 and 16 byte CDB are supported */
		return (IMA_ERROR_NOT_SUPPORTED);
	}

	(void) memset(&uscsi, 0, sizeof (iscsi_uscsi_t));
	uscsi.iu_vers = ISCSI_INTERFACE_VERSION;

	/* iu_oid is a session oid in the driver */
	if (deviceId.objectType == IMA_OBJECT_TYPE_TARGET) {
		uscsi.iu_oid	= deviceId.objectSequenceNumber;
		uscsi.iu_lun	= 0;
	} else {
		/*
		 * Get LU properties and associated session oid
		 * for this lun(deviceId) and put in uscsi.iu_oid
		 */
		status = getLuProperties(deviceId, &luProps);
		if (status != IMA_STATUS_SUCCESS) {
			return (status);
		}
		uscsi.iu_oid = (uint32_t)luProps.associatedTargetOid.
		    objectSequenceNumber;
		uscsi.iu_lun = luProps.targetLun;
	}

	uscsi.iu_ucmd.uscsi_flags = USCSI_READ;
	uscsi.iu_ucmd.uscsi_timeout = USCSI_TIMEOUT_IN_SEC;
	uscsi.iu_ucmd.uscsi_bufaddr = (char *)pOutputBuffer;
	uscsi.iu_ucmd.uscsi_buflen = buflen;
	uscsi.iu_ucmd.uscsi_rqbuf = (char *)pSenseBuffer;
	uscsi.iu_ucmd.uscsi_rqlen = (pSenseBufferLength != NULL) ?
	    *pSenseBufferLength : 0;
	uscsi.iu_ucmd.uscsi_cdb = (char *)&cmdblk[0];
	uscsi.iu_ucmd.uscsi_cdblen = cdbLength;

	if ((fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) == -1) {
		syslog(LOG_USER|LOG_DEBUG, "Cannot open %s (%d)",
		    ISCSI_DRIVER_DEVCTL, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	if (ioctl(fd, ISCSI_USCSI, &uscsi) != 0) {
		(void) close(fd);
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_TARGET_PROPS_GET ioctl failed, errno: %d", errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	if (uscsi.iu_ucmd.uscsi_status == STATUS_CHECK) {
		if (pSenseBufferLength != NULL) {
			*pSenseBufferLength -= uscsi.iu_ucmd.uscsi_rqresid;
		}
		return (IMA_ERROR_SCSI_STATUS_CHECK_CONDITION);
	}

	*pOutputBufferLength = buflen - uscsi.iu_ucmd.uscsi_resid;
	return (IMA_STATUS_SUCCESS);
}

IMA_API	IMA_STATUS IMA_LuReportLuns(
		IMA_OID deviceId,
		IMA_BOOL sendToWellKnownLun,
		IMA_BYTE selectReport,

		IMA_BYTE *pOutputBuffer,
		IMA_UINT *pOutputBufferLength,

		IMA_BYTE *pSenseBuffer,
		IMA_UINT *pSenseBufferLength
)
{
	IMA_LU_PROPERTIES luProps;
	IMA_STATUS status;
	unsigned char cmdblk[CDB_GROUP5];
	IMA_UINT buflen;
	int fd;
	iscsi_uscsi_t uscsi;

	(void) memset(&cmdblk[0], 0, CDB_GROUP5);
	cmdblk[0] = SCMD_REPORT_LUNS;
	cmdblk[2] = selectReport;

	if (*pOutputBufferLength > MAX_REPORT_LUNS_BUFFER_LEN) {
		buflen = MAX_REPORT_LUNS_BUFFER_LEN;
	} else {
		buflen = *pOutputBufferLength;
	}
	cmdblk[6] = (buflen & 0xff000000) >> 24;
	cmdblk[7] = (buflen & 0x00ff0000) >> 16;
	cmdblk[8] = (buflen & 0x0000ff00) >> 8;
	cmdblk[9] = (buflen & 0x000000ff);

	(void) memset(&uscsi, 0, sizeof (iscsi_uscsi_t));
	uscsi.iu_vers = ISCSI_INTERFACE_VERSION;

	/* iu_oid is a session oid in the driver */
	if (deviceId.objectType == IMA_OBJECT_TYPE_TARGET) {
		if (sendToWellKnownLun == IMA_TRUE) {
			/* this optional feature is not supported now */
			return (IMA_ERROR_NOT_SUPPORTED);
		}
		uscsi.iu_oid	= deviceId.objectSequenceNumber;
		uscsi.iu_lun	= 0;
	} else {
		/*
		 * Get LU properties and associated session oid
		 * for this lun(deviceId) and put in uscsi.iu_oid
		 */
		status = getLuProperties(deviceId, &luProps);
		if (status != IMA_STATUS_SUCCESS) {
			return (status);
		}
		uscsi.iu_oid = (uint32_t)luProps.associatedTargetOid.
		    objectSequenceNumber;
		uscsi.iu_lun = luProps.targetLun;
	}

	uscsi.iu_ucmd.uscsi_flags = USCSI_READ;
	uscsi.iu_ucmd.uscsi_timeout = USCSI_TIMEOUT_IN_SEC;
	uscsi.iu_ucmd.uscsi_bufaddr = (char *)pOutputBuffer;
	uscsi.iu_ucmd.uscsi_buflen = buflen;
	uscsi.iu_ucmd.uscsi_rqbuf = (char *)pSenseBuffer;
	uscsi.iu_ucmd.uscsi_rqlen = (pSenseBufferLength != NULL) ?
	    *pSenseBufferLength : 0;
	uscsi.iu_ucmd.uscsi_cdb = (char *)&cmdblk[0];
	uscsi.iu_ucmd.uscsi_cdblen = CDB_GROUP5;

	if ((fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) == -1) {
		syslog(LOG_USER|LOG_DEBUG, "Cannot open %s (%d)",
		    ISCSI_DRIVER_DEVCTL, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	if (ioctl(fd, ISCSI_USCSI, &uscsi) != 0) {
		(void) close(fd);
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_TARGET_PROPS_GET ioctl failed, errno: %d", errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	if (uscsi.iu_ucmd.uscsi_status == STATUS_CHECK) {
		if (pSenseBufferLength != NULL) {
			*pSenseBufferLength -= uscsi.iu_ucmd.uscsi_rqresid;
		}
		return (IMA_ERROR_SCSI_STATUS_CHECK_CONDITION);
	}

	*pOutputBufferLength = buflen - uscsi.iu_ucmd.uscsi_resid;
	return (IMA_STATUS_SUCCESS);
}

/*ARGSUSED*/
IMA_API	IMA_STATUS IMA_ExposeLu(
		IMA_OID luId
)
{
	return (IMA_ERROR_NOT_SUPPORTED);
}

/*ARGSUSED*/
IMA_API	IMA_STATUS IMA_UnexposeLu(
		IMA_OID luId
)
{
	return (IMA_ERROR_NOT_SUPPORTED);
}

IMA_API	IMA_STATUS IMA_GetAddressKeys(
		IMA_OID targetOid,
		IMA_ADDRESS_KEYS **ppKeys
)
{
	IMA_STATUS status;
	IMA_TARGET_PROPERTIES targetProps;
	SUN_IMA_DISC_ADDR_PROP_LIST *discAddressList;
	SUN_IMA_DISC_ADDRESS_KEY_PROPERTIES *pList;
	int i, j, addressKeyCount = 0;
	int addressKeyIdx = 0;

	status = getTargetProperties(targetOid, &targetProps);
	if (status != IMA_STATUS_SUCCESS) {
		return (status);
	}

	status = getDiscoveryAddressPropertiesList(&discAddressList);
	if (status != IMA_STATUS_SUCCESS) {
		return (status);
	}

	/* Get the number of addresses to allocate */
	for (i = 0; i < discAddressList->discAddrCount; i++) {
		(void) sendTargets(discAddressList->props[i].discoveryAddress,
		    &pList);
		for (j = 0; j < pList->keyCount; j++) {
			if (wcsncmp(pList->keys[j].name, targetProps.name,
			    wslen(pList->keys[j].name)) == 0) {
				addressKeyCount++;
			}
		}
		(void) IMA_FreeMemory(pList);
	}

	*ppKeys = (IMA_ADDRESS_KEYS *)calloc(1, sizeof (IMA_ADDRESS_KEYS) +
	    addressKeyCount * sizeof (IMA_ADDRESS_KEY));
	if (*ppKeys == NULL) {
		return (IMA_ERROR_INSUFFICIENT_MEMORY);
	}
	(*ppKeys)->addressKeyCount = addressKeyCount;
	addressKeyIdx = 0;

	for (i = 0; i < discAddressList->discAddrCount; i++) {
		(void) sendTargets(discAddressList->props[i].discoveryAddress,
		    &pList);
		for (j = 0; j < pList->keyCount; j++) {
			if (wcsncmp(pList->keys[j].name, targetProps.name,
			    wslen(pList->keys[j].name)) != 0) {
				continue;
			}

			bcopy(&(pList->keys[j].address.ipAddress),
			    &((*ppKeys)->addressKeys[addressKeyIdx].
			    ipAddress), sizeof (IMA_IP_ADDRESS));

			(*ppKeys)->addressKeys[addressKeyIdx++].portNumber =
			    pList->keys[j].address.portNumber;

		}
		(void) IMA_FreeMemory(pList);
	}
	return (IMA_STATUS_SUCCESS);
}

IMA_BOOL isAuthMethodValid(IMA_OID oid, IMA_AUTHMETHOD method) {
	IMA_STATUS status;
	IMA_AUTHMETHOD supportedList[MAX_AUTHMETHODS];
	IMA_UINT i, supportedCount;
	IMA_BOOL supported;
	status = getSupportedAuthMethods(oid, IMA_FALSE, &supportedCount,
			supportedList);
	if (status != IMA_STATUS_SUCCESS)
		return (IMA_FALSE);

	supported = IMA_FALSE;
	for (i = 0; i < supportedCount; i++) {
		if (method == supportedList[i]) {
			supported = IMA_TRUE;
		}
	}

	return (supported);
}

IMA_BOOL isAuthMethodListValid(IMA_OID oid, const IMA_AUTHMETHOD *pMethodList,
				IMA_UINT methodCount) {
	IMA_UINT i, j;

	if (pMethodList == NULL) {
		return (IMA_FALSE);
	}
	/* Check list for duplicates */
	for (i = 0; i < methodCount; i++) {
		for (j = i + 1; j < methodCount; j++) {
			if (pMethodList[i] == pMethodList[j]) {
				return (IMA_FALSE);
			}
		}

		if (isAuthMethodValid(oid, pMethodList[i]) == IMA_FALSE) {
			return (IMA_FALSE);
		}
	}
	return (IMA_TRUE);
}

IMA_API	IMA_STATUS IMA_GetSupportedAuthMethods(
		IMA_OID lhbaOid,
		IMA_BOOL getSettableMethods,
		IMA_UINT *pMethodCount,
		IMA_AUTHMETHOD *pMethodList
)
{
	return (getSupportedAuthMethods(lhbaOid, getSettableMethods,
	    pMethodCount, pMethodList));
}


/*ARGSUSED*/
static IMA_STATUS getSupportedAuthMethods(
		IMA_OID lhbaOid,
		IMA_BOOL getSettableMethods,
		IMA_UINT *pMethodCount,
		IMA_AUTHMETHOD *pMethodList
)
{
	if (pMethodList == NULL) {
		*pMethodCount = 0;
		return (IMA_STATUS_SUCCESS);
	}

	*pMethodCount = NUM_SUPPORTED_AUTH_METHODS;
	if (*pMethodCount > 1) {
		pMethodList[0] = IMA_AUTHMETHOD_NONE;
		pMethodList[1] = IMA_AUTHMETHOD_CHAP;
	}

	return (IMA_STATUS_SUCCESS);
}

IMA_API	IMA_STATUS IMA_GetInUseInitiatorAuthMethods(
		IMA_OID		lhbaOid,
		IMA_UINT	*pMethodCount,
		IMA_AUTHMETHOD *pMethodList
)
{
	return (getAuthMethods(lhbaOid, pMethodCount, pMethodList));
}

/*ARGSUSED*/
IMA_API	IMA_STATUS IMA_GetInitiatorAuthParms(
		IMA_OID lhbaOid,
		IMA_AUTHMETHOD method,
		IMA_INITIATOR_AUTHPARMS *pParms
)
{
	int fd;
	iscsi_chap_props_t  chap_p;

	if ((fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) == -1) {
		syslog(LOG_USER|LOG_DEBUG, "Cannot open %s (%d)",
		    ISCSI_DRIVER_DEVCTL, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(void) memset(&chap_p, 0, sizeof (iscsi_chap_props_t));
	chap_p.c_vers = ISCSI_INTERFACE_VERSION;
	chap_p.c_oid = (uint32_t)lhbaOid.objectSequenceNumber;

	if (method == IMA_AUTHMETHOD_CHAP) {
		if (ioctl(fd, ISCSI_CHAP_GET, &chap_p) != 0) {
			syslog(LOG_USER|LOG_DEBUG,
			"ISCSI_CHAP_GET ioctl failed, errno: %d", errno);
			(void) close(fd);
			return (IMA_ERROR_UNEXPECTED_OS_ERROR);
		}
	} else {
		return (IMA_ERROR_INVALID_PARAMETER);
	}

	(void) memcpy(pParms->chapParms.name, chap_p.c_user,
	    chap_p.c_user_len);
	pParms->chapParms.nameLength = chap_p.c_user_len;
	(void) memcpy(pParms->chapParms.challengeSecret, chap_p.c_secret,
	    chap_p.c_secret_len);
	pParms->chapParms.challengeSecretLength = chap_p.c_secret_len;

	return (IMA_STATUS_SUCCESS);
}

IMA_API	IMA_STATUS IMA_SetInitiatorAuthMethods(
		IMA_OID lhbaOid,
		IMA_UINT methodCount,
		const IMA_AUTHMETHOD *pMethodList
)
{
	if (isAuthMethodListValid(lhbaOid, pMethodList,
	    methodCount) == IMA_FALSE)
		return (IMA_ERROR_INVALID_PARAMETER);
	return (setAuthMethods(lhbaOid, &methodCount, pMethodList));
}

/*
 * This function only sets CHAP params since we only support CHAP for now.
 */
IMA_API	IMA_STATUS IMA_SetInitiatorAuthParms(
		IMA_OID lhbaOid,
		IMA_AUTHMETHOD method,
		const IMA_INITIATOR_AUTHPARMS *pParms
)
{
	int fd;
	iscsi_chap_props_t  chap_p;

	if (method != IMA_AUTHMETHOD_CHAP)
		return (IMA_ERROR_INVALID_PARAMETER);

	if (isAuthMethodValid(lhbaOid, method) == IMA_FALSE) {
		return (IMA_ERROR_INVALID_PARAMETER);
	}

	if ((fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) == -1) {
		syslog(LOG_USER|LOG_DEBUG, "Cannot open %s (%d)",
		    ISCSI_DRIVER_DEVCTL, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(void) memset(&chap_p, 0, sizeof (iscsi_chap_props_t));
	chap_p.c_vers = ISCSI_INTERFACE_VERSION;
	chap_p.c_oid = (uint32_t)lhbaOid.objectSequenceNumber;

	chap_p.c_user_len = pParms->chapParms.nameLength;
	(void) memcpy(chap_p.c_user, pParms->chapParms.name, chap_p.c_user_len);

	chap_p.c_secret_len = pParms->chapParms.challengeSecretLength;
	(void) memcpy(chap_p.c_secret, pParms->chapParms.challengeSecret,
	    chap_p.c_secret_len);

	if (method == IMA_AUTHMETHOD_CHAP) {
		if (ioctl(fd, ISCSI_CHAP_SET, &chap_p) != 0) {
			(void) close(fd);
			syslog(LOG_USER|LOG_DEBUG,
			    "ISCSI_CHAP_SET ioctl failed, errno: %d", errno);
			return (IMA_ERROR_UNEXPECTED_OS_ERROR);
		}
	}

	return (IMA_STATUS_SUCCESS);
}

/* A helper function to obtain iSCSI node parameters. */
static IMA_STATUS
getISCSINodeParameter(int paramType, IMA_OID *oid, void *pProps,
    uint32_t paramIndex)
{
	int		    fd;
	iscsi_param_get_t   pg;

	if ((fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) == -1) {
		syslog(LOG_USER|LOG_DEBUG, "Cannot open %s (%d)",
		    ISCSI_DRIVER_DEVCTL, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(void) memset(&pg, 0, sizeof (iscsi_param_get_t));
	pg.g_vers = ISCSI_INTERFACE_VERSION;
	pg.g_oid = (uint32_t)oid->objectSequenceNumber;
	pg.g_param = paramIndex;
	pg.g_param_type = ISCSI_SESS_PARAM;

	if (ioctl(fd, ISCSI_PARAM_GET, &pg) != 0) {
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_PARAM_GET ioctl failed, errno: %d", errno);
		(void) close(fd);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	switch (paramType) {
		IMA_BOOL_VALUE *bp;
		IMA_MIN_MAX_VALUE *mp;

		case MIN_MAX_PARAM:
			mp = (IMA_MIN_MAX_VALUE *)pProps;

			mp->currentValueValid =
			    (pg.g_value.v_valid == B_TRUE) ?
			    IMA_TRUE : IMA_FALSE;
			mp->currentValue = pg.g_value.v_integer.i_current;
			mp->defaultValue = pg.g_value.v_integer.i_default;
			mp->minimumValue = pg.g_value.v_integer.i_min;
			mp->maximumValue = pg.g_value.v_integer.i_max;
			mp->incrementValue = pg.g_value.v_integer.i_incr;
			break;

		case BOOL_PARAM:
			bp = (IMA_BOOL_VALUE *)pProps;
			bp->currentValueValid =
			    (pg.g_value.v_valid == B_TRUE) ?
			    IMA_TRUE : IMA_FALSE;
			bp->currentValue = pg.g_value.v_bool.b_current;
			bp->defaultValue = pg.g_value.v_bool.b_default;
			break;

		default:
			break;
	}

	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}

/* A helper function to set iSCSI node parameters. */
static IMA_STATUS
setISCSINodeParameter(int paramType, IMA_OID *oid, void *pProp,
    uint32_t paramIndex)
{
	int		    fd;
	iscsi_param_set_t   ps;

	if ((fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) == -1) {
		syslog(LOG_USER|LOG_DEBUG, "Cannot open %s (%d)",
		    ISCSI_DRIVER_DEVCTL, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(void) memset(&ps, 0, sizeof (iscsi_param_set_t));
	ps.s_vers = ISCSI_INTERFACE_VERSION;
	ps.s_oid = (uint32_t)oid->objectSequenceNumber;
	ps.s_param = paramIndex;

	switch (paramType) {
		IMA_BOOL_VALUE *bp;
		IMA_MIN_MAX_VALUE *mp;

		case MIN_MAX_PARAM:
			mp = (IMA_MIN_MAX_VALUE *)pProp;
			ps.s_value.v_integer = mp->currentValue;
			break;
		case BOOL_PARAM:
			bp = (IMA_BOOL_VALUE *)pProp;
			ps.s_value.v_bool =
			    (bp->currentValue == IMA_TRUE) ?
			    B_TRUE : B_FALSE;
			break;

		default:
			break;
	}

	if (ioctl(fd, ISCSI_PARAM_SET, &ps)) {
		int tmpErrno = errno;
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_PARAM_SET ioctl failed, errno: %d", errno);
		(void) close(fd);
		switch (tmpErrno) {
			case ENOTSUP :
				return (IMA_ERROR_NOT_SUPPORTED);
			default :
				return (IMA_ERROR_UNEXPECTED_OS_ERROR);
		}
	}

	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}

static int
prepare_discovery_entry(IMA_TARGET_ADDRESS discoveryAddress, entry_t *entry)
{
	(void) memset(entry, 0, sizeof (entry_t));
	entry->e_vers = ISCSI_INTERFACE_VERSION;
	entry->e_oid = ISCSI_OID_NOTSET;

	if (discoveryAddress.hostnameIpAddress.id.ipAddress.ipv4Address ==
	    IMA_FALSE) {
		bcopy(discoveryAddress.hostnameIpAddress.id.ipAddress.ipAddress,
		    entry->e_u.u_in6.s6_addr,
		    sizeof (entry->e_u.u_in6.s6_addr));
		entry->e_insize = sizeof (struct in6_addr);
	} else {
		bcopy(discoveryAddress.hostnameIpAddress.id.ipAddress.ipAddress,
		    &entry->e_u.u_in4.s_addr,
		    sizeof (entry->e_u.u_in4.s_addr));
		entry->e_insize = sizeof (struct in_addr);
	}

	entry->e_port = discoveryAddress.portNumber;
	entry->e_tpgt = 0;
	return (DISC_ADDR_OK);
}

static IMA_STATUS configure_discovery_method(
    IMA_BOOL enable,
    iSCSIDiscoveryMethod_t method
)
{
	int fd, status;

	if ((fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) == -1) {
		syslog(LOG_USER|LOG_DEBUG, "Cannot open %s (%d)",
		    ISCSI_DRIVER_DEVCTL, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	if (enable == IMA_FALSE) {
		if (ioctl(fd, ISCSI_DISCOVERY_CLEAR, &method)) {
			status = errno;
			(void) close(fd);
			syslog(LOG_USER|LOG_DEBUG,
			    "ISCSI_DISCOVERY_CLEAR ioctl failed, errno: %d",
			    status);
			if (status == EBUSY) {
				return (IMA_ERROR_LU_IN_USE);
			} else {
				return (IMA_ERROR_UNEXPECTED_OS_ERROR);
			}
		}

		(void) close(fd);
		return (IMA_STATUS_SUCCESS);
	} else {
		/* Set the discovery method */
		if (ioctl(fd, ISCSI_DISCOVERY_SET, &method)) {
			(void) close(fd);
			syslog(LOG_USER|LOG_DEBUG,
			    "ISCSI_DISCOVERY_SET ioctl failed, errno: %d",
			    errno);
			return (IMA_ERROR_UNEXPECTED_OS_ERROR);
		}

		(void) close(fd);
		return (IMA_STATUS_SUCCESS);
	}
}

static IMA_STATUS get_target_oid_list(
    uint32_t targetListType,
    IMA_OID_LIST **ppList)
{
	int		    fd;
	int		    i;
	int		    target_list_size;
	iscsi_target_list_t *idlp, tl_info;

	if ((fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) == -1) {
		syslog(LOG_USER|LOG_DEBUG, "Cannot open %s (%d)",
		    ISCSI_DRIVER_DEVCTL, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(void) memset(&tl_info, 0, sizeof (tl_info));
	tl_info.tl_vers = ISCSI_INTERFACE_VERSION;
	tl_info.tl_in_cnt = 0;
	tl_info.tl_tgt_list_type = targetListType;

	/*
	 * Issue ioctl to obtain the number of targets.
	 */
	if (ioctl(fd, ISCSI_TARGET_OID_LIST_GET, &tl_info) != 0) {
		(void) close(fd);
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_TARGET_OID_LIST_GET ioctl %d failed, errno: %d",
		    targetListType, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	target_list_size = sizeof (iscsi_target_list_t);
	if (tl_info.tl_out_cnt > 1) {
		target_list_size += (sizeof (uint32_t) *
		    tl_info.tl_out_cnt - 1);
	}

	idlp = (iscsi_target_list_t *)calloc(1, target_list_size);
	if (idlp == NULL) {
		(void) close(fd);
		return (IMA_ERROR_INSUFFICIENT_MEMORY);
	}

	idlp->tl_vers = ISCSI_INTERFACE_VERSION;
	idlp->tl_in_cnt = tl_info.tl_out_cnt;
	idlp->tl_tgt_list_type = targetListType;

	/* Issue the same ioctl again to obtain the OIDs. */
	if (ioctl(fd, ISCSI_TARGET_OID_LIST_GET, idlp) != 0) {
		free(idlp);
		(void) close(fd);
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_TARGET_OID_LIST_GET ioctl %d failed, errno: %d",
		    targetListType, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	*ppList = (IMA_OID_LIST *)calloc(1, sizeof (IMA_OID_LIST) +
	    idlp->tl_out_cnt * sizeof (IMA_OID));
	if (*ppList == NULL) {
		free(idlp);
		(void) close(fd);
		return (IMA_ERROR_INSUFFICIENT_MEMORY);
	}
	(*ppList)->oidCount = idlp->tl_out_cnt;

	for (i = 0; i < idlp->tl_out_cnt; i++) {

		if (targetListType == ISCSI_STATIC_TGT_OID_LIST)
			(*ppList)->oids[i].objectType =
			    IMA_OBJECT_TYPE_STATIC_DISCOVERY_TARGET;
		else
			(*ppList)->oids[i].objectType = IMA_OBJECT_TYPE_TARGET;

		(*ppList)->oids[i].ownerId = pluginOwnerId;
		(*ppList)->oids[i].objectSequenceNumber = idlp->tl_oid_list[i];
	}

	free(idlp);
	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}

static IMA_STATUS get_target_lun_oid_list(
    IMA_OID * targetOid,
    iscsi_lun_list_t  **ppLunList)
{
	int			fd;
	iscsi_lun_list_t	*illp, ll_info;
	int			lun_list_size;

	if ((fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) == -1) {
		syslog(LOG_USER|LOG_DEBUG, "Cannot open %s (%d)",
		    ISCSI_DRIVER_DEVCTL, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(void) memset(&ll_info, 0, sizeof (ll_info));
	ll_info.ll_vers = ISCSI_INTERFACE_VERSION;
	if (targetOid == NULL) {
		/* get lun oid list for all targets */
		ll_info.ll_all_tgts = B_TRUE;
	} else {
		/* get lun oid list for single target */
		ll_info.ll_all_tgts = B_FALSE;
		ll_info.ll_tgt_oid = (uint32_t)targetOid->objectSequenceNumber;
	}
	ll_info.ll_in_cnt = 0;

	/*
	 * Issue ioctl to obtain the number of target LUNs.
	 */
	if (ioctl(fd, ISCSI_LUN_OID_LIST_GET, &ll_info) != 0) {
		(void) close(fd);
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_LUN_LIST_GET ioctl failed, errno: %d", errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	lun_list_size = sizeof (iscsi_lun_list_t);
	if (ll_info.ll_out_cnt > 1) {
		lun_list_size += (sizeof (iscsi_if_lun_t) *
		    (ll_info.ll_out_cnt - 1));
	}

	illp = (iscsi_lun_list_t *)calloc(1, lun_list_size);
	if (illp == NULL) {
		(void) close(fd);
		return (IMA_ERROR_INSUFFICIENT_MEMORY);
	}
	illp->ll_vers = ISCSI_INTERFACE_VERSION;
	illp->ll_all_tgts = ll_info.ll_all_tgts;
	illp->ll_tgt_oid = ll_info.ll_tgt_oid;
	illp->ll_in_cnt = ll_info.ll_out_cnt;

	/* Issue the same ioctl again to get the target LUN list */
	if (ioctl(fd, ISCSI_LUN_OID_LIST_GET, illp) != 0) {
		free(illp);
		(void) close(fd);
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_LUN_LIST_GET ioctl failed, errno: %d", errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	*ppLunList = illp;

	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}


/* A helper function to set authentication method. */
static IMA_STATUS
setAuthMethods(IMA_OID oid, IMA_UINT *pMethodCount,
    const IMA_AUTHMETHOD *pMethodList)
{
	int fd;
	int i;
	iscsi_auth_props_t auth;

	if ((fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) == -1) {
		syslog(LOG_USER|LOG_DEBUG, "Cannot open %s (%d)",
		    ISCSI_DRIVER_DEVCTL, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}
	(void) memset(&auth, 0, sizeof (iscsi_auth_props_t));
	auth.a_vers = ISCSI_INTERFACE_VERSION;
	auth.a_oid = (uint32_t)oid.objectSequenceNumber;
	/* First do a get because other data fields may exist */
	if (ioctl(fd, ISCSI_AUTH_GET, &auth) != 0) {
		/* EMPTY */
		/* It is fine if there is no other data fields. */
	}
	auth.a_auth_method = authMethodNone;

	for (i = 0; i < *pMethodCount; i++) {
		switch (pMethodList[i]) {
			case IMA_AUTHMETHOD_CHAP:
				auth.a_auth_method |= authMethodCHAP;
				break;
			default:
				break;
		}
	}

	if (ioctl(fd, ISCSI_AUTH_SET, &auth) != 0) {
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_AUTH_SET failed, errno: %d", errno);
		(void) close(fd);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}

/* A helper function to get authentication method. */
static IMA_STATUS
getAuthMethods(IMA_OID oid, IMA_UINT *pMethodCount, IMA_AUTHMETHOD *pMethodList)
{
	int fd, i;
	iscsi_auth_props_t auth;

	if (pMethodList == NULL) {
		*pMethodCount = 0;
		return (IMA_STATUS_SUCCESS);
	}

	if ((fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) == -1) {
		syslog(LOG_USER|LOG_DEBUG, "Cannot open %s (%d)",
		    ISCSI_DRIVER_DEVCTL, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(void) memset(&auth, 0, sizeof (iscsi_auth_props_t));
	auth.a_vers = ISCSI_INTERFACE_VERSION;
	auth.a_oid = (uint32_t)oid.objectSequenceNumber;

	if (ioctl(fd, ISCSI_AUTH_GET, &auth) != 0) {
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_AUTH_GET failed, errno: %d", errno);
		(void) close(fd);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	i = 0;
	if (auth.a_auth_method == authMethodNone) {
		pMethodList[i++] = IMA_AUTHMETHOD_NONE;
	} else if (auth.a_auth_method & authMethodCHAP) {
		pMethodList[i++] = IMA_AUTHMETHOD_CHAP;
	}
	*pMethodCount = i;

	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}

IMA_API IMA_STATUS IMA_GetPhbaOidList(
		IMA_OID_LIST **ppList
)
{
	*ppList = (IMA_OID_LIST*)calloc(1, sizeof (IMA_OID_LIST));
	if (*ppList == NULL) {
		return (IMA_ERROR_INSUFFICIENT_MEMORY);
	}
	(*ppList)->oidCount = 0;
	return (IMA_STATUS_SUCCESS);
}

/* ARGSUSED */
IMA_API IMA_STATUS IMA_GetPhbaProperties(
		IMA_OID phbaOid,
		IMA_PHBA_PROPERTIES *pProps
)
{
	return (IMA_ERROR_OBJECT_NOT_FOUND);
}

/* ARGSUSED */
IMA_API IMA_STATUS IMA_GetPhbaStatus(
		IMA_OID phbaOid,
		IMA_PHBA_STATUS *pStatus
)
{
	return (IMA_ERROR_OBJECT_NOT_FOUND);
}

/* ARGSUSED */
IMA_API IMA_STATUS IMA_GetPhbaDownloadProperties(
		IMA_OID phbaOid,
		IMA_PHBA_DOWNLOAD_PROPERTIES *pProps
)
{
	return (IMA_ERROR_OBJECT_NOT_FOUND);
}

/* ARGSUSED */
IMA_API IMA_STATUS IMA_IsPhbaDownloadFile(
		IMA_OID phbaOid,
		const IMA_WCHAR *pFileName,
		IMA_PHBA_DOWNLOAD_IMAGE_PROPERTIES *pProps
)
{
	return (IMA_ERROR_OBJECT_NOT_FOUND);
}

/* ARGSUSED */
IMA_API IMA_STATUS IMA_PhbaDownload(
		IMA_OID phbaOid,
		IMA_PHBA_DOWNLOAD_IMAGE_TYPE imageType,
		const IMA_WCHAR *pFileName
)
{
	return (IMA_ERROR_OBJECT_NOT_FOUND);
}

IMA_API IMA_STATUS IMA_GetPnpOidList(
		IMA_OID pnpOid,
		IMA_OID_LIST **ppList
)
{
	/*
	 * Always return the same object ID for the pnp as the spec
	 * states that this function will always return a list of at least
	 * one element
	 */
	pnpOid.objectType = IMA_OBJECT_TYPE_PNP;
	pnpOid.ownerId = pluginOwnerId;
	pnpOid.objectSequenceNumber = ISCSI_INITIATOR_OID;

	*ppList = (IMA_OID_LIST*)calloc(1, sizeof (IMA_OID_LIST) +
	    (1* sizeof (IMA_OID)));

	if (*ppList == NULL) {
		return (IMA_ERROR_INSUFFICIENT_MEMORY);
	}

	(*ppList)->oidCount = 1;
	(void) memcpy(&(*ppList)->oids[0], &pnpOid, sizeof (pnpOid));
	return (IMA_STATUS_SUCCESS);
}

/* ARGSUSED */
IMA_API IMA_STATUS IMA_GetPnpProperties(
		IMA_OID pnpOid,
		IMA_PNP_PROPERTIES *pProps
)
{
	return (IMA_ERROR_OBJECT_NOT_FOUND);
}

/* ARGSUSED */
IMA_API IMA_STATUS IMA_GetPnpStatistics(
		IMA_OID pnpOid,
		IMA_PNP_STATISTICS *pStats
)
{
	return (IMA_ERROR_OBJECT_NOT_FOUND);
}

/* ARGSUSED */
IMA_API IMA_STATUS IMA_GetIpProperties(
		IMA_OID oid,
		IMA_IP_PROPERTIES *pProps
)
{
	return (IMA_ERROR_OBJECT_NOT_FOUND);
}

/* ARGSUSED */
IMA_API IMA_STATUS IMA_SetDefaultGateway(
		IMA_OID oid,
		IMA_IP_ADDRESS defaultGateway
)
{
	return (IMA_ERROR_OBJECT_NOT_FOUND);
}

/* ARGSUSED */
IMA_API IMA_STATUS IMA_SetDnsServerAddress(
		IMA_OID oid,
		const IMA_IP_ADDRESS *pPrimaryDnsServerAddress,
		const IMA_IP_ADDRESS *pAlternateDnsServerAddress
)
{
	return (IMA_ERROR_OBJECT_NOT_FOUND);
}

/* ARGSUSED */
IMA_API IMA_STATUS IMA_SetSubnetMask(
		IMA_OID oid,
		IMA_IP_ADDRESS subnetMask
)
{
	return (IMA_ERROR_OBJECT_NOT_FOUND);
}

/* ARGSUSED */
IMA_API IMA_STATUS IMA_SetIpConfigMethod(
		IMA_OID oid,
		IMA_BOOL enableDhcpIpConfiguration
)
{
	return (IMA_ERROR_OBJECT_NOT_FOUND);
}

IMA_API IMA_STATUS IMA_RegisterForObjectPropertyChanges(
		IMA_OBJECT_PROPERTY_FN pClientFn
)
{
	pObjectPropertyCallback = pClientFn;
	return (IMA_STATUS_SUCCESS);
}

/* ARGSUSED */
IMA_API IMA_STATUS IMA_DeregisterForObjectPropertyChanges(
		IMA_OBJECT_PROPERTY_FN pClientFn
)
{
	return (IMA_STATUS_SUCCESS);
}

IMA_API IMA_STATUS IMA_RegisterForObjectVisibilityChanges(
		IMA_OBJECT_VISIBILITY_FN pClientFn
)
{
	pObjectVisibilityCallback = pClientFn;
	return (IMA_STATUS_SUCCESS);
}

/* ARGSUSED */
IMA_API IMA_STATUS IMA_DeregisterForObjectVisibilityChanges(
		IMA_OBJECT_VISIBILITY_FN pClientFn
)
{
	return (IMA_STATUS_SUCCESS);
}

/* ARGSUSED */
IMA_API IMA_STATUS IMA_GetNetworkPortStatus(
		IMA_OID portOid,
		IMA_NETWORK_PORT_STATUS *pStaus
)
{
	return (IMA_ERROR_OBJECT_NOT_FOUND);
}

/* ARGSUSED */
IMA_API IMA_STATUS IMA_GetNetworkPortalOidList(
		IMA_OID pnpOid,
		IMA_OID_LIST **ppList
)
{
	return (IMA_ERROR_OBJECT_NOT_FOUND);
}

/* ARGSUSED */
IMA_API IMA_STATUS IMA_GetNetworkPortalProperties(
		IMA_OID networkPortalOid,
		IMA_NETWORK_PORTAL_PROPERTIES *pProps
)
{
	return (IMA_ERROR_OBJECT_NOT_FOUND);
}

/* ARGSUSED */
IMA_API IMA_STATUS IMA_SetNetworkPortalIpAddress(
		IMA_OID networkPortalOid,
		const IMA_IP_ADDRESS NewIpAddress
)
{
	return (IMA_ERROR_OBJECT_NOT_FOUND);
}

/* ARGSUSED */
IMA_API IMA_STATUS IMA_RemoveStaleData(
		IMA_OID lhbaOid
)
{
	return (IMA_ERROR_NOT_SUPPORTED);
}

/* ARGSUSED */
IMA_API IMA_STATUS IMA_GetIpsecProperties(
		IMA_OID oid,
		IMA_IPSEC_PROPERTIES *pProps
)
{
	pProps->ipsecSupported = IMA_TRUE;
	pProps->implementedInHardware = IMA_FALSE;
	pProps->implementedInSoftware = IMA_TRUE;

	return (IMA_STATUS_SUCCESS);
}

/* ARGSUSED */
IMA_API IMA_STATUS IMA_GetLhbaProperties(
		IMA_OID lhbaOid,
		IMA_LHBA_PROPERTIES *pProps
)
{

	if (pProps == NULL) {
		return (IMA_ERROR_INVALID_PARAMETER);
	}

	if (lhbaObjectId.objectSequenceNumber != ISCSI_INITIATOR_OID) {
		return (IMA_ERROR_OBJECT_NOT_FOUND);
	}

	(void) memset(pProps, 0, sizeof (IMA_LHBA_PROPERTIES));
	(void) mbstowcs(pProps->osDeviceName, OS_DEVICE_NAME,
	    OS_DEVICE_NAME_LEN);
	pProps->luExposingSupported = IMA_FALSE;
	pProps->isDestroyable = IMA_FALSE;
	pProps->staleDataRemovable = IMA_FALSE;
	pProps->staleDataSize = 0;
	pProps->initiatorAuthMethodsSettable = IMA_TRUE;
	pProps->targetAuthMethodsSettable = IMA_FALSE;

	return (IMA_STATUS_SUCCESS);
}

IMA_API IMA_STATUS IMA_GetLnpOidList(
		IMA_OID_LIST **ppList
)
{
	*ppList = (IMA_OID_LIST *) calloc(1, (sizeof (IMA_OID_LIST)));
	if (*ppList == NULL) {
		return (IMA_ERROR_INSUFFICIENT_MEMORY);
	}
	(*ppList)->oidCount = 0;

	return (IMA_STATUS_SUCCESS);
}

/* ARGSUSED */
IMA_API IMA_STATUS IMA_GetLnpProperties(
		IMA_OID lnpOid,
		IMA_LNP_PROPERTIES *pProps
)
{
	return (IMA_ERROR_OBJECT_NOT_FOUND);
}

#define	IMA_DISK_DEVICE_NAME_PREFIX	"/dev/rdsk/"
#define	IMA_TAPE_DEVICE_NAME_PREFIX	"/dev/rmt/"
static int
get_lun_devlink(di_devlink_t link, void *osDeviceName)
{
	if ((strncmp(IMA_DISK_DEVICE_NAME_PREFIX, di_devlink_path(link),
	    strlen(IMA_DISK_DEVICE_NAME_PREFIX)) == 0) ||
	    (strncmp(IMA_TAPE_DEVICE_NAME_PREFIX, di_devlink_path(link),
	    strlen(IMA_TAPE_DEVICE_NAME_PREFIX)) == 0)) {
		(void) mbstowcs((wchar_t *)osDeviceName, di_devlink_path(link),
		    MAXPATHLEN);
		return (DI_WALK_TERMINATE);
	}

	return (DI_WALK_CONTINUE);
}

/* ARGSUSED */
IMA_API IMA_STATUS IMA_GetPluginProperties(
	IMA_OID pluginOid,
	IMA_PLUGIN_PROPERTIES *pProps
)
{
	pProps->supportedImaVersion = 1;
	libSwprintf(pProps->vendor, L"%ls", LIBRARY_PROPERTY_VENDOR);
	libSwprintf(pProps->implementationVersion, L"%ls",
	    LIBRARY_PROPERTY_IMPLEMENTATION_VERSION);
	libSwprintf(pProps->fileName, L"%ls", LIBRARY_FILE_NAME);
	GetBuildTime(&(pProps->buildTime));
	pProps->lhbasCanBeCreatedAndDestroyed = IMA_FALSE;
	return (IMA_STATUS_SUCCESS);
}

IMA_STATUS getDiscoveryAddressPropertiesList(
    SUN_IMA_DISC_ADDR_PROP_LIST **ppList
)
{
	int		    fd;
	int		    i;
	int		    discovery_addr_list_size;
	iscsi_addr_list_t   *ialp, al_info;

	if ((fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) == -1) {
		syslog(LOG_USER|LOG_DEBUG, "Cannot open %s (%d)",
		    ISCSI_DRIVER_DEVCTL, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(void) memset(&al_info, 0, sizeof (al_info));
	al_info.al_vers = ISCSI_INTERFACE_VERSION;
	al_info.al_in_cnt = 0;

	/*
	 * Issue ISCSI_DISCOVERY_ADDR_LIST_GET ioctl to obtain the number of
	 * discovery addresses.
	 */
	if (ioctl(fd, ISCSI_DISCOVERY_ADDR_LIST_GET, &al_info) != 0) {
		(void) close(fd);
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_DISCOVERY_ADDR_LIST_GET ioctl failed, errno: %d",
		    errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	discovery_addr_list_size = sizeof (iscsi_addr_list_t);
	if (al_info.al_out_cnt > 1) {
		discovery_addr_list_size += (sizeof (iscsi_addr_t) *
		    al_info.al_out_cnt - 1);
	}

	ialp = (iscsi_addr_list_t *)calloc(1, discovery_addr_list_size);
	if (ialp == NULL) {
		(void) close(fd);
		return (IMA_ERROR_INSUFFICIENT_MEMORY);
	}
	ialp->al_vers = ISCSI_INTERFACE_VERSION;
	ialp->al_in_cnt = al_info.al_out_cnt;

	/*
	 * Issue ISCSI_DISCOVERY_ADDR_LIST_GET ioctl again to obtain the
	 * discovery addresses.
	 */
	if (ioctl(fd, ISCSI_DISCOVERY_ADDR_LIST_GET, ialp) != 0) {
		free(ialp);
		(void) close(fd);
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_DISCOVERY_ADDR_LIST_GET ioctl failed, errno: %d",
		    errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	*ppList = (SUN_IMA_DISC_ADDR_PROP_LIST *)
	    calloc(1, sizeof (SUN_IMA_DISC_ADDR_PROP_LIST) +
	    ialp->al_out_cnt * sizeof (IMA_DISCOVERY_ADDRESS_PROPERTIES));

	if (*ppList == NULL) {
		free(ialp);
		(void) close(fd);
		return (IMA_ERROR_INSUFFICIENT_MEMORY);
	}
	(*ppList)->discAddrCount = ialp->al_out_cnt;

	for (i = 0; i < ialp->al_out_cnt; i++) {
		if (ialp->al_addrs[i].a_addr.i_insize ==
		    sizeof (struct in_addr)) {
			(*ppList)->props[i].discoveryAddress.hostnameIpAddress.
			id.ipAddress.ipv4Address = IMA_TRUE;
		} else if (ialp->al_addrs[i].a_addr.i_insize ==
		    sizeof (struct in6_addr)) {
			(*ppList)->props[i].discoveryAddress.
			hostnameIpAddress.id.ipAddress.ipv4Address = IMA_FALSE;
		} else {
			/* Should not happen */
			syslog(LOG_USER|LOG_DEBUG,
			"ISCSI_STATIC_GET returned bad address");
			return (IMA_ERROR_UNEXPECTED_OS_ERROR);
		}

		bcopy(&ialp->al_addrs[i].a_addr.i_addr,	(*ppList)->props[i].
		    discoveryAddress.hostnameIpAddress.id.ipAddress.ipAddress,
		    sizeof ((*ppList)->props[i].discoveryAddress.
		    hostnameIpAddress.id.ipAddress.ipAddress));

		(*ppList)->props[i].discoveryAddress.portNumber =
		    ialp->al_addrs[i].a_port;
	}

	free(ialp);
	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}


/* ARGSUSED */
IMA_STATUS sendTargets(
    IMA_TARGET_ADDRESS address,
    SUN_IMA_DISC_ADDRESS_KEY_PROPERTIES **ppList
)
{
	char	*colonPos;
	char	discAddrStr[SUN_IMA_IP_ADDRESS_LEN];
	int	fd;
	int	ctr;
	int	stl_sz;
	iscsi_sendtgts_list_t	*stl_hdr = NULL;
	IMA_BOOL		retry = IMA_TRUE;

#define	SENDTGTS_DEFAULT_NUM_TARGETS	10

	stl_sz = sizeof (*stl_hdr) + ((SENDTGTS_DEFAULT_NUM_TARGETS - 1) *
	    sizeof (iscsi_sendtgts_entry_t));
	stl_hdr = (iscsi_sendtgts_list_t *)calloc(1, stl_sz);
	if (stl_hdr == NULL) {
		return (IMA_ERROR_INSUFFICIENT_MEMORY);
	}
	stl_hdr->stl_entry.e_vers = ISCSI_INTERFACE_VERSION;
	stl_hdr->stl_in_cnt = SENDTGTS_DEFAULT_NUM_TARGETS;

	colonPos = strchr(discAddrStr, ':');
	if (colonPos == NULL) {
		/* IPv4 */
		stl_hdr->stl_entry.e_insize = sizeof (struct in_addr);
	} else {
		/* IPv6 */
		stl_hdr->stl_entry.e_insize = sizeof (struct in6_addr);
	}


	bcopy(address.hostnameIpAddress.id.ipAddress.ipAddress,
	    &stl_hdr->stl_entry.e_u,
	    sizeof (address.hostnameIpAddress.id.ipAddress.ipAddress));
	stl_hdr->stl_entry.e_port = address.portNumber;

	if ((fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) == -1) {
		syslog(LOG_USER|LOG_DEBUG, "Cannot open %s (%d)",
		    ISCSI_DRIVER_DEVCTL, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

retry_sendtgts:
	/*
	 * Issue ioctl to obtain the SendTargets list
	 */
	if (ioctl(fd, ISCSI_SENDTGTS_GET, stl_hdr) != 0) {
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_SENDTGTS_GET ioctl failed, errno: %d", errno);
		(void) close(fd);
		free(stl_hdr);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	/* check if all targets received */
	if (stl_hdr->stl_in_cnt < stl_hdr->stl_out_cnt) {
		if (retry == IMA_TRUE) {
			stl_sz = sizeof (*stl_hdr) +
			    ((stl_hdr->stl_out_cnt - 1) *
			    sizeof (iscsi_sendtgts_entry_t));
			stl_hdr = (iscsi_sendtgts_list_t *)
			    realloc(stl_hdr, stl_sz);
			if (stl_hdr == NULL) {
				(void) close(fd);
				return (IMA_ERROR_INSUFFICIENT_MEMORY);
			}
			stl_hdr->stl_in_cnt = stl_hdr->stl_out_cnt;
			retry = IMA_FALSE;
			goto retry_sendtgts;
		} else {
			/*
			 * don't retry after 2 attempts.  The target list
			 * shouldn't continue to growing. Justs continue
			 * on and display what was found.
			 */
			syslog(LOG_USER|LOG_DEBUG,
			    "ISCSI_SENDTGTS_GET overflow: "
			    "failed to obtain all targets");
			stl_hdr->stl_out_cnt = stl_hdr->stl_in_cnt;
		}
	}

	(void) close(fd);

	/* allocate for caller return buffer */
	*ppList = (SUN_IMA_DISC_ADDRESS_KEY_PROPERTIES *)calloc(1,
	    sizeof (SUN_IMA_DISC_ADDRESS_KEY_PROPERTIES) +
	    stl_hdr->stl_out_cnt * sizeof (SUN_IMA_DISC_ADDRESS_KEY));
	if (*ppList == NULL) {
		free(stl_hdr);
		return (IMA_ERROR_INSUFFICIENT_MEMORY);
	}

	(*ppList)->keyCount = stl_hdr->stl_out_cnt;

	for (ctr = 0; ctr < stl_hdr->stl_out_cnt; ctr++) {
		(void) mbstowcs((*ppList)->keys[ctr].name,
		    (char *)stl_hdr->stl_list[ctr].ste_name,
		    IMA_NODE_NAME_LEN);

		(*ppList)->keys[ctr].tpgt = stl_hdr->stl_list[ctr].ste_tpgt;

		(*ppList)->keys[ctr].address.portNumber =
		    stl_hdr->stl_list[ctr].ste_ipaddr.a_port;

		if (stl_hdr->stl_list[ctr].ste_ipaddr.a_addr.i_insize ==
		    sizeof (struct in_addr)) {
			(*ppList)->keys[ctr].address.ipAddress.ipv4Address =
			    IMA_TRUE;
		} else if (stl_hdr->stl_list[ctr].ste_ipaddr.a_addr.i_insize ==
		    sizeof (struct in6_addr)) {
			(*ppList)->keys[ctr].address.ipAddress.ipv4Address =
			    IMA_FALSE;
		} else {
			free(stl_hdr);
			syslog(LOG_USER|LOG_DEBUG,
			"ISCSI_STATIC_GET returned bad address");
			return (IMA_ERROR_UNEXPECTED_OS_ERROR);
		}


		(void) memcpy(&(*ppList)->keys[ctr].address.ipAddress.ipAddress,
		    &(stl_hdr->stl_list[ctr].ste_ipaddr.a_addr.i_addr),
		    stl_hdr->stl_list[ctr].ste_ipaddr.a_addr.i_insize);
	}
	free(stl_hdr);

	return (IMA_STATUS_SUCCESS);
}

IMA_API IMA_STATUS SUN_IMA_GetTunableProperties(
	IMA_OID oid,
	ISCSI_TUNABLE_PARAM *param)
{
	int fd;
	iscsi_tunable_object_t pg;

	if ((fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) == -1) {
		syslog(LOG_USER|LOG_DEBUG, "Cannot open %s (%d)",
		    ISCSI_DRIVER_DEVCTL, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}
	(void) memset(&pg, 0, sizeof (iscsi_tunable_object_t));
	pg.t_param = param->tunable_objectType;
	pg.t_oid = (uint32_t)oid.objectSequenceNumber;
	if (ioctl(fd, ISCSI_TUNABLE_PARAM_GET, &pg) == -1) {
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_TUNABLE_PARAM_GET ioctl failed, errno: %d", errno);
		(void) close(fd);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	} else {
		long long value;
		char tmp[MAX_LONG_LONG_STRING_LEN], *ptr = NULL;
		if (pg.t_set == B_FALSE) {
			/* default value */
			(void) close(fd);
			return (IMA_STATUS_SUCCESS);
		}
		value = (long long)pg.t_value.v_integer;
		ptr = lltostr(value, &tmp[MAX_LONG_LONG_STRING_LEN -1]);
		if ((ptr != NULL) && (ptr != tmp)) {
			tmp[MAX_LONG_LONG_STRING_LEN - 1] = '\0';
		} else {
			(void) close(fd);
			return (IMA_ERROR_UNEXPECTED_OS_ERROR);
		}
		switch (param->tunable_objectType) {
			case ISCSI_RX_TIMEOUT_VALUE:
				(void) strlcpy(param->tunable_objectValue,
				    ptr, strlen(ptr) + 1);
				break;
			case ISCSI_CONN_DEFAULT_LOGIN_MAX:
				(void) strlcpy(param->tunable_objectValue,
				    ptr, strlen(ptr) + 1);
				break;
			case ISCSI_LOGIN_POLLING_DELAY:
				(void) strlcpy(param->tunable_objectValue,
				    ptr, strlen(ptr) + 1);
				break;
			default:
				break;
		}
	}
	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}

IMA_API IMA_STATUS SUN_IMA_SetTunableProperties(
	IMA_OID oid,
	ISCSI_TUNABLE_PARAM *param)
{
	int fd;
	iscsi_tunable_object_t	ps;

	if ((fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) == -1) {
		syslog(LOG_USER|LOG_DEBUG, "Cannot open %s (%d)",
		    ISCSI_DRIVER_DEVCTL, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(void) memset(&ps, 0, sizeof (iscsi_tunable_object_t));
	ps.t_oid = oid.objectSequenceNumber;
	ps.t_param = param->tunable_objectType;
	switch (param->tunable_objectType) {
		long tmp;
		case ISCSI_RX_TIMEOUT_VALUE:
		case ISCSI_CONN_DEFAULT_LOGIN_MAX:
		case ISCSI_LOGIN_POLLING_DELAY:
			tmp = strtol(param->tunable_objectValue,
			    NULL, 10);
			if (((tmp == 0) && (errno == EINVAL)) ||
			    ((tmp == LONG_MAX) && (errno == ERANGE)) ||
			    ((tmp == LONG_MIN) && (errno == ERANGE))) {
				(void) close(fd);
				return (IMA_ERROR_INVALID_PARAMETER);
			}
			ps.t_value.v_integer = (uint32_t)tmp;
			break;
		default:
			break;
	}
	if (ioctl(fd, ISCSI_TUNABLE_PARAM_SET, &ps)) {
		int tmpErrno = errno;
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_TUNABLE_PARAM_SET ioctl failed, errno: %d", errno);
		(void) close(fd);
		switch (tmpErrno) {
			case ENOTSUP :
				return (IMA_ERROR_NOT_SUPPORTED);
			default:
				return (IMA_ERROR_UNEXPECTED_OS_ERROR);
		}
	}
	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}
