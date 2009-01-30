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

#include <fcntl.h>
#include <stdio.h>
#include <time.h>
#include <libdevinfo.h>

#include <sys/scsi/adapters/iscsi_if.h>
#include <sys/iscsi_protocol.h>
#include <ima.h>
#include "iscsiadm.h"
#include "sun_ima.h"

#define	LIBRARY_PROPERTY_SUPPORTED_IMA_VERSION	1
#define	LIBRARY_PROPERTY_IMPLEMENTATION_VERSION	L"1.0.0"
#define	LIBRARY_PROPERTY_VENDOR	L"Sun Microsystems, Inc."
#define	DEFAULT_NODE_NAME_FORMAT    "iqn.2003-13.com.ima.%s"
#define	PLUGIN_OWNER 1
#define	MAX_CHAP_SECRET_LEN	16

/* LINTED E_STATIC_UNUSED */
static IMA_INT32		number_of_plugins = -1;
/* LINTED E_STATIC_UNUSED */
static IMA_NODE_NAME		sharedNodeName;
/* LINTED E_STATIC_UNUSED */
static IMA_NODE_ALIAS		sharedNodeAlias;
/* LINTED E_STATIC_UNUSED */
static IMA_PLUGIN_PROPERTIES	PluginProperties;

/* LINTED E_STATIC_UNUSED */
static IMA_OID			pluginOid;
static IMA_OID			lhbaObjectId;
/* LINTED E_STATIC_UNUSED */
static boolean_t		pluginInit = B_FALSE;

/* Forward declaration */
#define	BOOL_PARAM		1
#define	MIN_MAX_PARAM		2
#define	PARAM_OP_OK		0
#define	PARAM_OP_FAILED		1

static int open_driver(int *fd);
static IMA_STATUS getISCSINodeParameter(int paramType,
    IMA_OID *oid,
    void *pProps,
    uint32_t paramIndex);
static IMA_STATUS setISCSINodeParameter(int paramType,
    IMA_OID *oid,
    void *pProps,
    uint32_t paramIndex);
static IMA_STATUS getDigest(IMA_OID oid, int ioctlCmd,
    SUN_IMA_DIGEST_ALGORITHM_VALUE *algorithm);
static IMA_STATUS setAuthMethods(IMA_OID oid, IMA_UINT *pMethodCount,
    const IMA_AUTHMETHOD *pMethodList);
static IMA_STATUS getAuthMethods(IMA_OID oid, IMA_UINT *pMethodCount,
    IMA_AUTHMETHOD *pMethodList);
IMA_STATUS getNegotiatedDigest(int digestType,
	SUN_IMA_DIGEST_ALGORITHM_VALUE *algorithm,
	SUN_IMA_CONN_PROPERTIES *connProps);

/* OK */
#define	DISC_ADDR_OK		    0
/* Incorrect IP address */
#define	DISC_ADDR_INTEGRITY_ERROR   1
/* Error converting text IP address to numeric binary form */
#define	DISC_ADDR_IP_CONV_ERROR	    2
static int prepare_discovery_entry(SUN_IMA_TARGET_ADDRESS discoveryAddress,
    entry_t *entry);
static int prepare_discovery_entry_IMA(IMA_TARGET_ADDRESS discoveryAddress,
    entry_t *entry);

/* LINTED E_STATIC_UNUSED */
static IMA_STATUS configure_discovery_method(IMA_BOOL enable,
    iSCSIDiscoveryMethod_t method);

static IMA_STATUS get_target_oid_list(uint32_t targetListType,
    IMA_OID_LIST **ppList);

static IMA_STATUS get_target_lun_oid_list(IMA_OID * targetOid,
					    iscsi_lun_list_t  **ppLunList);

static int get_lun_devlink(di_devlink_t link, void *arg);

static IMA_STATUS getConnOidList(
	IMA_OID			*oid,
	iscsi_conn_list_t	**ppConnList);

static IMA_STATUS getConnProps(
	iscsi_if_conn_t		*pConn,
	iscsi_conn_props_t	**ppConnProps);

/* LINTED E_STATIC_UNUSED */
static void libSwprintf(wchar_t *wcs, const wchar_t *lpszFormat, ...)
{
	va_list args;
	va_start(args, lpszFormat);
	(void) vswprintf(wcs, 255, lpszFormat, args);
	va_end(args);
}


char *
_strlwr(char *s)
{
	char *t = s;
	while (t != NULL && *t) {
		if (*t >= 'A' && *t <= 'Z')
			*t += 32;
		t++;
	}
	return (s);
}

/* LINTED E_STATIC_UNUSED */
static void GetBuildTime(IMA_DATETIME* pdatetime)
{
#if defined(BUILD_DATE)
	if (strptime(BUILD_DATE, "%Y/%m/%d %T %Z", pdatetime) == NULL) {
		(void) memset(pdatetime, 0, sizeof (IMA_DATETIME));
	}
#else
	(void) memset(pdatetime, 0, sizeof (IMA_DATETIME));
#endif
}

/*
 * Non-IMA defined function.
 */
IMA_API	IMA_STATUS SUN_IMA_GetDiscoveryAddressPropertiesList(
    SUN_IMA_DISC_ADDR_PROP_LIST	**ppList
)
{
	char		    discovery_addr_str[256];
	int		    fd;
	int		    i;
	int		    discovery_addr_list_size;
	int		    status;
	int		    out_cnt;
	iscsi_addr_list_t   *ialp;
	/* LINTED E_FUNC_SET_NOT_USED */
	IMA_IP_ADDRESS	    *ipAddr;

	if ((status = open_driver(&fd))) {
		return (SUN_IMA_ERROR_SYSTEM_ERROR | status);
	}

	ialp = (iscsi_addr_list_t *)calloc(1, sizeof (iscsi_addr_list_t));
	if (ialp == NULL) {
		(void) close(fd);
		return (IMA_ERROR_INSUFFICIENT_MEMORY);
	}

	ialp->al_vers = ISCSI_INTERFACE_VERSION;
	ialp->al_in_cnt = ialp->al_out_cnt = 1;

	/*
	 * Issue ISCSI_DISCOVERY_ADDR_LIST_GET ioctl
	 * We have allocated space for one entry, if more than one
	 * address is going to be returned, we will re-issue the ioctl
	 */
	if (ioctl(fd, ISCSI_DISCOVERY_ADDR_LIST_GET, ialp) != 0) {
		(void) close(fd);
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_DISCOVERY_ADDR_LIST_GET ioctl failed, errno: %d",
		    errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	if (ialp->al_out_cnt > 1) {
		/*
		 * we need to allocate more space, save off the out_cnt
		 * and free ialp
		 */
		out_cnt = ialp->al_out_cnt;
		free(ialp);

		discovery_addr_list_size = sizeof (iscsi_addr_list_t);
		discovery_addr_list_size += (sizeof (iscsi_addr_t) *
		    out_cnt - 1);
		ialp = (iscsi_addr_list_t *)calloc(1, discovery_addr_list_size);
		if (ialp == NULL) {
			(void) close(fd);
			return (IMA_ERROR_INSUFFICIENT_MEMORY);
		}
		ialp->al_vers = ISCSI_INTERFACE_VERSION;
		ialp->al_in_cnt = out_cnt;

		/*
		 * Issue ISCSI_DISCOVERY_ADDR_LIST_GET ioctl again to obtain all
		 * the discovery addresses.
		 */
		if (ioctl(fd, ISCSI_DISCOVERY_ADDR_LIST_GET, ialp) != 0) {
#define	ERROR_STR "ISCSI_DISCOVERY_ADDR_LIST_GET ioctl failed, errno :%d"
			free(ialp);
			(void) close(fd);
			syslog(LOG_USER|LOG_DEBUG,
			    ERROR_STR, errno);
			return (IMA_ERROR_UNEXPECTED_OS_ERROR);
#undef ERROR_STR

		}
	}

	*ppList = (SUN_IMA_DISC_ADDR_PROP_LIST *)calloc(1,
	    sizeof (SUN_IMA_DISC_ADDR_PROP_LIST) +
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

			(*ppList)->props[i].discoveryAddress.hostnameIpAddress.
			id.ipAddress.ipv4Address = IMA_FALSE;

		} else {
			(void) strlcpy(discovery_addr_str, "unknown",
			    sizeof (discovery_addr_str));
		}

		ipAddr = &(*ppList)->props[i].discoveryAddress.
		    hostnameIpAddress.id.ipAddress;

		bcopy(&ialp->al_addrs[i].a_addr.i_addr,
		    (*ppList)->props[i].discoveryAddress.hostnameIpAddress.id.
		    ipAddress.ipAddress,
		    sizeof (ipAddr->ipAddress));

		(*ppList)->props[i].discoveryAddress.portNumber =
		    ialp->al_addrs[i].a_port;
	}

	free(ialp);
	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}

IMA_API IMA_STATUS SUN_IMA_GetStaticTargetProperties(
		IMA_OID	staticTargetOid,
		SUN_IMA_STATIC_TARGET_PROPERTIES *pProps
)
{
	int fd;
	int status;
	iscsi_static_property_t prop;
	/* LINTED */
	IMA_IP_ADDRESS	    *ipAddr;

	if ((status = open_driver(&fd))) {
		return (SUN_IMA_ERROR_SYSTEM_ERROR | status);
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
		pProps->staticTarget.targetAddress.imaStruct.hostnameIpAddress.
			id.ipAddress.ipv4Address = IMA_TRUE;
	} else if (prop.p_addr_list.al_addrs[0].a_addr.i_insize ==
	    sizeof (struct in6_addr)) {
		/* IPv6 */
		pProps->staticTarget.targetAddress.imaStruct.hostnameIpAddress.
			id.ipAddress.ipv4Address = IMA_FALSE;
	} else {
		/* Should not happen */
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_STATIC_GET returned bad address");
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	ipAddr = &pProps->staticTarget.targetAddress.imaStruct.
	    hostnameIpAddress.id.ipAddress;

	bcopy(&prop.p_addr_list.al_addrs[0].a_addr.i_addr,
	    pProps->staticTarget.targetAddress.imaStruct.hostnameIpAddress.id.
	    ipAddress.ipAddress, sizeof (ipAddr->ipAddress));

	pProps->staticTarget.targetAddress.imaStruct.portNumber =
	    prop.p_addr_list.al_addrs[0].a_port;


	if (prop.p_addr_list.al_tpgt == (uint32_t)ISCSI_DEFAULT_TPGT) {
		pProps->staticTarget.targetAddress.defaultTpgt = IMA_TRUE;
		pProps->staticTarget.targetAddress.tpgt = 0;
	} else {
		pProps->staticTarget.targetAddress.defaultTpgt = IMA_FALSE;
		pProps->staticTarget.targetAddress.tpgt =
		    prop.p_addr_list.al_tpgt;
	}

	return (IMA_STATUS_SUCCESS);
}

/*ARGSUSED*/
IMA_API IMA_STATUS SUN_IMA_AddStaticTarget(
		IMA_OID lhbaOid,
		const SUN_IMA_STATIC_DISCOVERY_TARGET staticConfig,
		IMA_OID *pTargetOid
)
{
	iscsi_target_entry_t	target;
	int			fd;
	int			target_in_addr_size;
	int			status;
	union {
		struct in_addr	u_in4;
		struct in6_addr	u_in6;
	}			target_in;

	/*
	 * staticConfig.address may come in with port number at its trailer.
	 * Parse it to separate the IP address and port number.
	 * Also translate the hostname to IP address if needed.
	 */

	if (staticConfig.targetAddress.imaStruct.hostnameIpAddress.id.ipAddress.
	    ipv4Address == IMA_FALSE) {

		bcopy(staticConfig.targetAddress.imaStruct.hostnameIpAddress.
		    id.ipAddress.ipAddress, &target_in.u_in6,
		    sizeof (target_in.u_in6));

		target_in_addr_size = sizeof (struct in6_addr);
	} else {

		bcopy(staticConfig.targetAddress.imaStruct.hostnameIpAddress.
		    id.ipAddress.ipAddress, &target_in.u_in4,
		    sizeof (target_in.u_in4));

		target_in_addr_size = sizeof (struct in_addr);
	}

	(void) memset(&target, 0, sizeof (iscsi_target_entry_t));
	target.te_entry.e_vers = ISCSI_INTERFACE_VERSION;
	target.te_entry.e_oid = ISCSI_OID_NOTSET;

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
		return (IMA_ERROR_INVALID_PARAMETER);
	}

	target.te_entry.e_port =
	    staticConfig.targetAddress.imaStruct.portNumber;

	if (staticConfig.targetAddress.defaultTpgt == IMA_TRUE) {
		target.te_entry.e_tpgt = ISCSI_DEFAULT_TPGT;
	} else {
		target.te_entry.e_tpgt = staticConfig.targetAddress.tpgt;
	}

	if ((status = open_driver(&fd))) {
		return (SUN_IMA_ERROR_SYSTEM_ERROR | status);
	}

	if (ioctl(fd, ISCSI_STATIC_SET, &target)) {
		/*
		 * Encountered problem setting the IP address and port for
		 * the target just added.
		 */
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_STATIC_SET ioctl failed, errno: %d", errno);
		(void) close(fd);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	pTargetOid->objectType = IMA_OBJECT_TYPE_TARGET;
	pTargetOid->ownerId = 1;
	pTargetOid->objectSequenceNumber = target.te_entry.e_oid;

	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}

IMA_API	IMA_STATUS SUN_IMA_GetTargetProperties(
		IMA_OID targetId,
		SUN_IMA_TARGET_PROPERTIES *pProps
)
{
	int		    fd;
	int			status;
	iscsi_property_t    prop;

	if ((status = open_driver(&fd))) {
		return (SUN_IMA_ERROR_SYSTEM_ERROR | status);
	}

	(void) memset(&prop, 0, sizeof (iscsi_property_t));
	prop.p_vers = ISCSI_INTERFACE_VERSION;
	prop.p_oid = (uint32_t)targetId.objectSequenceNumber;

	if (ioctl(fd, ISCSI_TARGET_PROPS_GET, &prop) != 0) {
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_TARGET_PROPS_GET ioctl failed, errno: %d", errno);
		(void) close(fd);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(void) mbstowcs(pProps->imaProps.name,
	    (char *)prop.p_name, IMA_NODE_NAME_LEN);
	(void) memset(pProps->imaProps.alias, 0,
	    (sizeof (IMA_WCHAR) * SUN_IMA_NODE_ALIAS_LEN));
	if (prop.p_alias_len > 0) {
		(void) mbstowcs(pProps->imaProps.alias, (char *)prop.p_alias,
		    SUN_IMA_NODE_ALIAS_LEN);
	}

	/* Initialize the discovery method to unknown method. */
	pProps->imaProps.discoveryMethodFlags =
	    IMA_TARGET_DISCOVERY_METHOD_UNKNOWN;
	if (!((prop.p_discovery & iSCSIDiscoveryMethodStatic) ^
	    iSCSIDiscoveryMethodStatic)) {
		pProps->imaProps.discoveryMethodFlags |=
		    IMA_TARGET_DISCOVERY_METHOD_STATIC;
	}

	if (!((prop.p_discovery & iSCSIDiscoveryMethodSLP) ^
	    iSCSIDiscoveryMethodSLP)) {
		pProps->imaProps.discoveryMethodFlags |=
		    IMA_TARGET_DISCOVERY_METHOD_SLP;
	}

	if (!((prop.p_discovery & iSCSIDiscoveryMethodISNS) ^
	    iSCSIDiscoveryMethodISNS)) {
		pProps->imaProps.discoveryMethodFlags |=
		    iSCSIDiscoveryMethodISNS;
	}

	if (!((prop.p_discovery & iSCSIDiscoveryMethodSendTargets) ^
	    iSCSIDiscoveryMethodSendTargets)) {
		pProps->imaProps.discoveryMethodFlags |=
		    iSCSIDiscoveryMethodSendTargets;
	}

	if (prop.p_tpgt_conf == ISCSI_DEFAULT_TPGT) {
		pProps->defaultTpgtConf = IMA_TRUE;
		pProps->tpgtConf = 0;
	} else {
		pProps->defaultTpgtConf = IMA_FALSE;
		pProps->tpgtConf = prop.p_tpgt_conf;
	}

	if (prop.p_tpgt_nego == ISCSI_DEFAULT_TPGT) {
		pProps->defaultTpgtNego = IMA_TRUE;
		pProps->tpgtNego = 0;
	} else {
		pProps->defaultTpgtNego = IMA_FALSE;
		pProps->tpgtNego = prop.p_tpgt_nego;
	}

	bcopy(prop.p_isid, pProps->isid, ISCSI_ISID_LEN);

	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}

/*
 * This function only sets CHAP params since we only support CHAP for now.
 */
IMA_STATUS SUN_IMA_SetTargetAuthParams(
    IMA_OID targetOid,
    IMA_AUTHMETHOD method,
    const IMA_INITIATOR_AUTHPARMS *pParms
)
{
	int fd;
	iscsi_chap_props_t  chap_p;

	if (method != IMA_AUTHMETHOD_CHAP)
		return (IMA_ERROR_INVALID_PARAMETER);

	if ((fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) == -1) {
		syslog(LOG_USER|LOG_DEBUG, "Cannot open %s (%d)",
		    ISCSI_DRIVER_DEVCTL, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(void) memset(&chap_p, 0, sizeof (iscsi_chap_props_t));
	chap_p.c_vers = ISCSI_INTERFACE_VERSION;
	chap_p.c_oid = (uint32_t)targetOid.objectSequenceNumber;

	chap_p.c_user_len =
	    pParms->chapParms.nameLength;
	(void) memcpy(chap_p.c_user,
	    pParms->chapParms.name, chap_p.c_user_len);

	chap_p.c_secret_len =
	    pParms->chapParms.challengeSecretLength;
	(void) memcpy(chap_p.c_secret,
	    pParms->chapParms.challengeSecret,
	    chap_p.c_secret_len);

	if (ioctl(fd, ISCSI_CHAP_SET, &chap_p) != 0) {
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_CHAP_SET ioctl failed, errno: %d", errno);
		(void) close(fd);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	return (IMA_STATUS_SUCCESS);
}

IMA_STATUS SUN_IMA_GetTargetAuthMethods(
    IMA_OID		lhbaOid,
    IMA_OID		targetOid,
    IMA_UINT	*pMethodCount,
    IMA_AUTHMETHOD *pMethodList
)
{
	if (getAuthMethods(targetOid, pMethodCount, pMethodList)
	    != IMA_STATUS_SUCCESS) {
		return (getAuthMethods(lhbaOid, pMethodCount, pMethodList));
	}
	return (IMA_STATUS_SUCCESS);
}

IMA_STATUS SUN_IMA_SetInitiatorRadiusConfig(
		IMA_OID	lhbaOid,
		SUN_IMA_RADIUS_CONFIG *config
)
{
	int			af;
	int			fd;
	int			status;
	iscsi_radius_props_t	radius;
	union {
		struct in_addr	u_in4;
		struct in6_addr	u_in6;
	}	radius_in;

	if ((status = open_driver(&fd))) {
		return (SUN_IMA_ERROR_SYSTEM_ERROR | status);
	}

	(void) memset(&radius, 0, sizeof (iscsi_radius_props_t));
	radius.r_vers = ISCSI_INTERFACE_VERSION;
	radius.r_oid = (uint32_t)lhbaOid.objectSequenceNumber;
	/* Get first because other data fields may already exist */
	if (ioctl(fd, ISCSI_RADIUS_GET, &radius) != 0) {
		/* EMPTY */
		/* It's fine if other data fields are not there. */
	}

	if (config->isIpv6 == IMA_TRUE) {
		af = AF_INET6;
	} else {
		af = AF_INET;
	}

	if (inet_pton(af, config->hostnameIpAddress, &radius_in.u_in4) != 1) {
		return (IMA_ERROR_INVALID_PARAMETER);
	}

	switch (af) {
		case AF_INET:
			radius.r_addr.u_in4.s_addr = radius_in.u_in4.s_addr;
			radius.r_insize = sizeof (struct in_addr);
			break;
		case AF_INET6:
			(void) memcpy(radius.r_addr.u_in6.s6_addr,
			    radius_in.u_in6.s6_addr, 16);
			radius.r_insize = sizeof (struct in6_addr);
			break;
	}
	radius.r_port = config->port;
	radius.r_radius_config_valid = B_TRUE;
	/* Allow resetting the RADIUS shared secret to NULL */
	if (config->sharedSecretValid == IMA_TRUE) {
		radius.r_shared_secret_len = config->sharedSecretLength;
		(void) memset(&radius.r_shared_secret[0], 0,
		    MAX_RAD_SHARED_SECRET_LEN);
		(void) memcpy(&radius.r_shared_secret[0], config->sharedSecret,
		    config->sharedSecretLength);
	}

	if (ioctl(fd, ISCSI_RADIUS_SET, &radius) != 0) {
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_RADIUS_SET ioctl failed, errno: %d", errno);
		(void) close(fd);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}

IMA_STATUS SUN_IMA_GetInitiatorRadiusConfig(
		IMA_OID	lhbaOid,
		SUN_IMA_RADIUS_CONFIG *config
)
{
	int			af;
	int			fd;
	int			status;
	iscsi_radius_props_t	radius;

	if ((status = open_driver(&fd))) {
		return (SUN_IMA_ERROR_SYSTEM_ERROR | status);
	}

	(void) memset(&radius, 0, sizeof (iscsi_radius_props_t));
	radius.r_vers = ISCSI_INTERFACE_VERSION;
	radius.r_oid = (uint32_t)lhbaOid.objectSequenceNumber;

	if (ioctl(fd, ISCSI_RADIUS_GET, &radius) != 0) {
		(void) close(fd);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(void) memset(config, 0, sizeof (SUN_IMA_RADIUS_CONFIG));
	if (radius.r_insize == sizeof (struct in_addr)) {
		/* IPv4 */
		af = AF_INET;
	} else if (radius.r_insize == sizeof (struct in6_addr)) {
		/* IPv6 */
		af = AF_INET6;
	} else {
		/*
		 * It's legitimate that the existing RADIUS record does not
		 * have configuration data.
		 */
		config->hostnameIpAddress[0] = '\0';
		config->port = 0;
		(void) close(fd);
		return (IMA_STATUS_SUCCESS);
	}
	(void) inet_ntop(af, (void *)&radius.r_addr.u_in4,
	    config->hostnameIpAddress, 256);
	config->port = radius.r_port;
	(void) memcpy(config->sharedSecret, &radius.r_shared_secret[0],
	    radius.r_shared_secret_len);
	config->sharedSecretLength = radius.r_shared_secret_len;
	config->sharedSecretValid = B_TRUE;

	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}

IMA_STATUS SUN_IMA_SetInitiatorRadiusAccess(
    IMA_OID lhbaOid,
    IMA_BOOL radiusAccess
)
{
	int			fd;
	int			status;
	iscsi_radius_props_t	radius;

	if ((status = open_driver(&fd))) {
		return (SUN_IMA_ERROR_SYSTEM_ERROR | status);
	}

	(void) memset(&radius, 0, sizeof (iscsi_radius_props_t));
	radius.r_vers = ISCSI_INTERFACE_VERSION;
	radius.r_oid = (uint32_t)lhbaOid.objectSequenceNumber;
	/* Get first because other data fields may already exist */
	if (ioctl(fd, ISCSI_RADIUS_GET, &radius) != 0) {
		if (radiusAccess == IMA_TRUE) {
			/*
			 * Cannot enable RADIUS if no RADIUS configuration
			 * can be found.
			 */
			syslog(LOG_USER|LOG_DEBUG,
			    "RADIUS config data not found - "
			    "cannot enable RADIUS, errno: %d", errno);
			(void) close(fd);
			return (IMA_ERROR_UNEXPECTED_OS_ERROR);
		} else {
			/* EMPTY */
			/* Otherwise it's fine to disable RADIUS */
		}
	}

	if ((radius.r_insize != sizeof (struct in_addr)) &&
		(radius.r_insize != sizeof (struct in6_addr))) {
		/*
		 * Cannot enable RADIUS if no RADIUS configuration
		 * can be found.
		 */
		if (radiusAccess == IMA_TRUE) {
			syslog(LOG_USER|LOG_DEBUG,
				"RADIUS config data not found - "
				"cannot enable RADIUS");
			(void) close(fd);
			return (IMA_ERROR_UNEXPECTED_OS_ERROR);
		}
	}

	radius.r_radius_access = (radiusAccess == IMA_TRUE) ?
	    B_TRUE : B_FALSE;

	if (ioctl(fd, ISCSI_RADIUS_SET, &radius) != 0) {
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_RADIUS_SET ioctl failed, errno: %d", errno);
		(void) close(fd);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}

IMA_STATUS SUN_IMA_GetInitiatorRadiusAccess(
    IMA_OID lhbaOid,
    IMA_BOOL *radiusAccess
)
{
	int			fd;
	int			status;
	iscsi_radius_props_t	radius;

	if ((status = open_driver(&fd))) {
		return (SUN_IMA_ERROR_SYSTEM_ERROR | status);
	}

	(void) memset(&radius, 0, sizeof (iscsi_radius_props_t));
	radius.r_vers = ISCSI_INTERFACE_VERSION;
	radius.r_oid = (uint32_t)lhbaOid.objectSequenceNumber;

	if (ioctl(fd, ISCSI_RADIUS_GET, &radius) != 0) {
		(void) close(fd);
		if (errno == ENOENT) {
			return (IMA_ERROR_OBJECT_NOT_FOUND);
		} else {
			return (IMA_ERROR_UNEXPECTED_OS_ERROR);
		}
	}

	*radiusAccess = (radius.r_radius_access == B_TRUE) ?
	    IMA_TRUE : IMA_FALSE;

	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}

IMA_STATUS SUN_IMA_SendTargets(
    IMA_NODE_NAME nodeName,
    IMA_TARGET_ADDRESS address,
    SUN_IMA_DISC_ADDRESS_KEY_PROPERTIES **ppList
)
{
	char	*colonPos;
	char	discAddrStr[256];
	char	nodeNameStr[ISCSI_MAX_NAME_LEN];
	int	fd;
	int	ctr;
	int	stl_sz;
	int status;
	iscsi_sendtgts_list_t	*stl_hdr = NULL;
	IMA_BOOL		retry = IMA_TRUE;
	/* LINTED */
	IMA_IP_ADDRESS	    *ipAddr;

#define	SENDTGTS_DEFAULT_NUM_TARGETS	10

	stl_sz = sizeof (*stl_hdr) + ((SENDTGTS_DEFAULT_NUM_TARGETS - 1) *
	    sizeof (iscsi_sendtgts_entry_t));
	stl_hdr = (iscsi_sendtgts_list_t *)calloc(1, stl_sz);
	if (stl_hdr == NULL) {
		return (IMA_ERROR_INSUFFICIENT_MEMORY);
	}
	stl_hdr->stl_entry.e_vers = ISCSI_INTERFACE_VERSION;
	stl_hdr->stl_in_cnt = SENDTGTS_DEFAULT_NUM_TARGETS;

	(void) wcstombs(nodeNameStr, nodeName, ISCSI_MAX_NAME_LEN);

	colonPos = strchr(discAddrStr, ':');
	if (colonPos == NULL) {
		/* IPv4 */
		stl_hdr->stl_entry.e_insize = sizeof (struct in_addr);
	} else {
		/* IPv6 */
		stl_hdr->stl_entry.e_insize = sizeof (struct in6_addr);
	}

	ipAddr = &address.hostnameIpAddress.id.ipAddress;

	bcopy(address.hostnameIpAddress.id.ipAddress.ipAddress,
	    &stl_hdr->stl_entry.e_u, sizeof (ipAddr->ipAddress));

	stl_hdr->stl_entry.e_port = address.portNumber;

	if ((status = open_driver(&fd))) {
		return (SUN_IMA_ERROR_SYSTEM_ERROR | status);
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
			return (IMA_ERROR_UNEXPECTED_OS_ERROR);
		}

		(void) memcpy(&(*ppList)->keys[ctr].address.ipAddress.ipAddress,
		    &(stl_hdr->stl_list[ctr].ste_ipaddr.a_addr.i_addr),
		    stl_hdr->stl_list[ctr].ste_ipaddr.a_addr.i_insize);
	}
	free(stl_hdr);

	return (IMA_STATUS_SUCCESS);
}

IMA_STATUS SUN_IMA_SetTargetBidirAuthFlag(
    IMA_OID targetOid,
    IMA_BOOL *bidirAuthFlag
)
{
	int fd;
	int status;
	iscsi_auth_props_t auth;

	if ((status = open_driver(&fd))) {
		return (SUN_IMA_ERROR_SYSTEM_ERROR | status);
	}

	(void) memset(&auth, 0, sizeof (iscsi_auth_props_t));
	auth.a_vers = ISCSI_INTERFACE_VERSION;
	auth.a_oid = (uint32_t)targetOid.objectSequenceNumber;
	/* Get first because other data fields may already exist */
	if (ioctl(fd, ISCSI_AUTH_GET, &auth) != 0) {
		/* EMPTY */
		/* It is fine if there is no other data fields. */
	}
	auth.a_bi_auth = (*bidirAuthFlag == IMA_TRUE) ? B_TRUE : B_FALSE;
	if (ioctl(fd, ISCSI_AUTH_SET, &auth) != 0) {
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_AUTH_SET ioctl failed, errno: %d", errno);
		(void) close(fd);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}

IMA_STATUS SUN_IMA_GetTargetBidirAuthFlag(
    IMA_OID targetOid,
    IMA_BOOL *bidirAuthFlag
)
{
	int fd;
	int status;
	iscsi_auth_props_t auth;

	if ((status = open_driver(&fd))) {
		return (SUN_IMA_ERROR_SYSTEM_ERROR | status);
	}

	(void) memset(&auth, 0, sizeof (iscsi_auth_props_t));
	auth.a_vers = ISCSI_INTERFACE_VERSION;
	auth.a_oid = (uint32_t)targetOid.objectSequenceNumber;

	if (ioctl(fd, ISCSI_AUTH_GET, &auth) != 0) {
		(void) close(fd);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	*bidirAuthFlag = (auth.a_bi_auth == B_TRUE) ?
	    IMA_TRUE : IMA_FALSE;

	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}

IMA_STATUS SUN_IMA_CreateTargetOid(
    IMA_NODE_NAME targetName,
    IMA_OID *targetOid
)
{
	int	    fd;
	int		status;
	iscsi_oid_t oid;

	if ((status = open_driver(&fd))) {
		return (SUN_IMA_ERROR_SYSTEM_ERROR | status);
	}

	(void) memset(&oid, 0, sizeof (iscsi_oid_t));
	(void) wcstombs((char *)oid.o_name, targetName, ISCSI_MAX_NAME_LEN);
	oid.o_tpgt = ISCSI_DEFAULT_TPGT;
	oid.o_vers = ISCSI_INTERFACE_VERSION;
	if (ioctl(fd, ISCSI_CREATE_OID, &oid) == -1) {
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_CREATE_OID ioctl failed, errno: %d", errno);
		(void) close(fd);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	targetOid->objectType = IMA_OBJECT_TYPE_TARGET;
	targetOid->ownerId = 1;
	targetOid->objectSequenceNumber = oid.o_oid;

	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}

IMA_STATUS SUN_IMA_RemoveTargetParam(
		IMA_OID targetOid
)
{
	entry_t	entry;
	int	fd;
	int status;
	iscsi_auth_props_t auth_p;
	iscsi_chap_props_t chap_p;

	if ((status = open_driver(&fd))) {
		return (SUN_IMA_ERROR_SYSTEM_ERROR | status);
	}

	(void) memset(&entry, 0, sizeof (entry_t));
	entry.e_vers = ISCSI_INTERFACE_VERSION;
	entry.e_oid = (uint32_t)targetOid.objectSequenceNumber;
	if (ioctl(fd, ISCSI_TARGET_PARAM_CLEAR, &entry)) {
		/*
		 * It could be that the target exists but the associated
		 * target_param does not, and that is legitimate.
		 */
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_TARGET_PARAM_CLEAR ioctl failed, errno: %d", errno);
	}

	/* Issue ISCSI_CHAP_CLEAR ioctl */
	(void) memset(&chap_p, 0, sizeof (iscsi_chap_props_t));
	chap_p.c_vers = ISCSI_INTERFACE_VERSION;
	chap_p.c_oid = (uint32_t)targetOid.objectSequenceNumber;
	if (ioctl(fd, ISCSI_CHAP_CLEAR, &chap_p) != 0) {
		/*
		 * It could be that the CHAP of this target has never
		 * been set.
		 */
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_CHAP_CLEAR ioctl failed, errno: %d", errno);
	}

	/*
	 * Issue ISCSI_AUTH_CLEAR ioctl, in which the authentication information
	 * is removed and the target that is not discovered by initiator
	 * is removed from the memory. So this ioctl should be called at last
	 */
	(void) memset(&auth_p, 0, sizeof (iscsi_auth_props_t));
	auth_p.a_vers = ISCSI_INTERFACE_VERSION;
	auth_p.a_oid = (uint32_t)targetOid.objectSequenceNumber;
	if (ioctl(fd, ISCSI_AUTH_CLEAR, &auth_p) != 0) {
		/*
		 * It could be that the auth data of this target has
		 * never been set.
		 */
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_AUTH_CLEAR ioctl failed, errno: %d", errno);
	}

	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}

IMA_API IMA_STATUS SUN_IMA_SetHeaderDigest(
	IMA_OID oid,
	IMA_UINT algorithmCount,
	const SUN_IMA_DIGEST_ALGORITHM *algorithmList
)
{
	IMA_MIN_MAX_VALUE mv;
	uint32_t digest_algorithm;

	/* We only support one preference of digest algorithm. */
	if (algorithmCount > 1) {
		syslog(LOG_USER|LOG_DEBUG,
		    "More than one digest algorithm specified.");
		return (IMA_ERROR_NOT_SUPPORTED);
	}
	switch (algorithmList[0]) {
	case SUN_IMA_DIGEST_NONE:
		digest_algorithm = ISCSI_DIGEST_NONE;
		break;
	case SUN_IMA_DIGEST_CRC32:
		digest_algorithm = ISCSI_DIGEST_CRC32C;
		break;
	default:
		digest_algorithm = ISCSI_DIGEST_NONE;
		break;
	}
	mv.currentValue = digest_algorithm;
	return (setISCSINodeParameter(MIN_MAX_PARAM, &oid, &mv,
	    ISCSI_LOGIN_PARAM_HEADER_DIGEST));
}

IMA_API IMA_STATUS SUN_IMA_SetDataDigest(
	IMA_OID oid,
	IMA_UINT algorithmCount,
	const SUN_IMA_DIGEST_ALGORITHM *algorithmList
)
{
	IMA_MIN_MAX_VALUE mv;
	uint32_t digest_algorithm;

	/* We only support one preference of digest algorithm. */
	if (algorithmCount > 1) {
		syslog(LOG_USER|LOG_DEBUG,
		    "More than one digest algorithm specified.");
		return (IMA_ERROR_NOT_SUPPORTED);
	}
	switch (algorithmList[0]) {
	case SUN_IMA_DIGEST_NONE:
		digest_algorithm = ISCSI_DIGEST_NONE;
		break;
	case SUN_IMA_DIGEST_CRC32:
		digest_algorithm = ISCSI_DIGEST_CRC32C;
		break;
	default:
		digest_algorithm = ISCSI_DIGEST_NONE;
		break;
	}
	mv.currentValue = digest_algorithm;
	return (setISCSINodeParameter(MIN_MAX_PARAM, &oid, &mv,
	    ISCSI_LOGIN_PARAM_DATA_DIGEST));
}

IMA_API IMA_STATUS SUN_IMA_GetHeaderDigest(
	IMA_OID oid,
	SUN_IMA_DIGEST_ALGORITHM_VALUE *algorithm
)
{
	return (getDigest(oid, ISCSI_LOGIN_PARAM_HEADER_DIGEST, algorithm));
}

IMA_API IMA_STATUS SUN_IMA_GetDataDigest(
	IMA_OID oid,
	SUN_IMA_DIGEST_ALGORITHM_VALUE *algorithm
)
{
	return (getDigest(oid, ISCSI_LOGIN_PARAM_DATA_DIGEST, algorithm));
}

typedef struct walk_devlink {
	char *path;
	size_t len;
	char **linkpp;
} walk_devlink_t;

IMA_STATUS SUN_IMA_GetLuProperties(
		IMA_OID luId,
		SUN_IMA_LU_PROPERTIES *pProps
)
{
	IMA_STATUS		status;
	iscsi_lun_list_t	*pLunList;
	int			j;
	IMA_BOOL		lunMatch = IMA_FALSE;
	int			fd;
	int			openStatus;
	iscsi_lun_props_t	lun;
	di_devlink_handle_t	hdl;
	walk_devlink_t		warg;
	char			*minor_path, *devlinkp, lunpath[MAXPATHLEN];

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
	if ((openStatus = open_driver(&fd))) {
		return (SUN_IMA_ERROR_SYSTEM_ERROR | openStatus);
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
	pProps->imaProps.associatedTargetOid.objectType =
	    IMA_OBJECT_TYPE_TARGET;
	pProps->imaProps.associatedTargetOid.ownerId = 1;
	pProps->imaProps.associatedTargetOid.objectSequenceNumber = lun.lp_oid;
	pProps->imaProps.targetLun = (IMA_UINT64)lun.lp_num;
	(void) strncpy(pProps->vendorId, lun.lp_vid, SUN_IMA_LU_VENDOR_ID_LEN);
	(void) strncpy(pProps->productId, lun.lp_pid,
	    SUN_IMA_LU_PRODUCT_ID_LEN);
	/*
	 * lun.lp_status is defined as
	 *	LunValid = 0
	 *	LunDoesNotExist = 1
	 * IMA_LU_PROPS.exposedtoOS is defined as an IMA_BOOL
	 *	IMA_TRUE = 1
	 *	IMA_FALSE = 0
	 */
	pProps->imaProps.exposedToOs = !lun.lp_status;
	if (gmtime_r(&lun.lp_time_online, &pProps->imaProps.timeExposedToOs)
	    == NULL) {
		(void) memset(&pProps->imaProps.timeExposedToOs, 0,
		    sizeof (pProps->imaProps.timeExposedToOs));
	}

	if (lun.lp_status == LunValid) {
		if ((strlen(lun.lp_pathname) + strlen("/devices")) >
		    (MAXPATHLEN -1)) {
			/*
			 * lun.lp_pathname length too long
			 */
			pProps->imaProps.osDeviceNameValid = IMA_FALSE;
			pProps->imaProps.osParallelIdsValid = IMA_FALSE;
			return (IMA_STATUS_SUCCESS);
		}
		if ((strstr(lun.lp_pathname, "st@") != NULL) ||
		    (strstr(lun.lp_pathname, "tape@") != NULL)) {
			(void) strlcat(lun.lp_pathname, ":n", MAXPATHLEN);
		} else if ((strstr(lun.lp_pathname, "sd@") != NULL) ||
		    (strstr(lun.lp_pathname, "ssd@") != NULL) ||
		    (strstr(lun.lp_pathname, "disk@") != NULL)) {
			/*
			 * modify returned pathname to obtain the 2nd slice
			 * of the raw disk
			 */
			(void) strlcat(lun.lp_pathname, ":c,raw", MAXPATHLEN);
		} else if ((strstr(lun.lp_pathname, "ses@") != NULL) ||
		    (strstr(lun.lp_pathname, "enclosure@") != NULL)) {
			(void) strlcat(lun.lp_pathname, ":0", MAXPATHLEN);
		}

		(void) snprintf(lunpath, sizeof (lun.lp_pathname),
		    "/devices%s", lun.lp_pathname);
		if (strchr(lunpath, ':')) {
			minor_path = lunpath;
			if (strstr(minor_path, "/devices") != NULL) {
				minor_path = lunpath +
				    strlen("/devices");
			} else {
				minor_path = lunpath;
			}
			warg.path = NULL;
		} else {
			minor_path = NULL;
			warg.len = strlen(lunpath);
			warg.path = lunpath;
		}
		devlinkp = NULL;
		warg.linkpp = &devlinkp;

		/*
		 * Pathname returned by driver is the physical device path.
		 * This name needs to be converted to the OS device name.
		 */
		if (hdl = di_devlink_init(lun.lp_pathname, DI_MAKE_LINK)) {
			pProps->imaProps.osDeviceName[0] = L'\0';
			(void) di_devlink_walk(hdl, NULL, minor_path,
			    DI_PRIMARY_LINK, (void *)&warg, get_lun_devlink);
			if (devlinkp != NULL) {
				/* OS device name synchronously made */
				(void) mbstowcs(pProps->imaProps.osDeviceName,
				    devlinkp, MAXPATHLEN);
				free(devlinkp);
				pProps->imaProps.osDeviceNameValid = IMA_TRUE;
			} else {
				pProps->imaProps.osDeviceNameValid = IMA_FALSE;
			}

			(void) di_devlink_fini(&hdl);

		} else {
			pProps->imaProps.osDeviceNameValid = IMA_FALSE;
		}

	} else {
		pProps->imaProps.osDeviceNameValid = IMA_FALSE;
	}

	pProps->imaProps.osParallelIdsValid = IMA_FALSE;

	return (IMA_STATUS_SUCCESS);
}

static int
get_lun_devlink(di_devlink_t link, void *arg)
{
	walk_devlink_t *warg = (walk_devlink_t *)arg;
	if (warg->path) {
		char *content = (char *)di_devlink_content(link);
		char *start = strstr(content, "/devices");
		if (start == NULL ||
		    strncmp(start, warg->path, warg->len) != 0 ||
		    start[warg->len] != ':')
			return (DI_WALK_CONTINUE);
	}

	*(warg->linkpp) = strdup(di_devlink_path(link));
	return (DI_WALK_TERMINATE);

}

/*
 * SUN_IMA_GetConnectionOidList -
 *
 * Non-IMA defined function.
 */
IMA_API	IMA_STATUS SUN_IMA_GetConnOidList(
	IMA_OID			*oid,
	IMA_OID_LIST		**ppList
)
{
	IMA_STATUS		imaStatus;
	IMA_OID_LIST		*imaOidList;
	iscsi_conn_list_t	*iscsiConnList = NULL;
	int			i;
	size_t			allocLen;

	if ((lhbaObjectId.objectType == oid->objectType) &&
	    (lhbaObjectId.ownerId == oid->ownerId) &&
	    (lhbaObjectId.objectSequenceNumber == oid->objectSequenceNumber)) {
		imaStatus = getConnOidList(NULL, &iscsiConnList);
	} else {
		if (oid->objectType == IMA_OBJECT_TYPE_TARGET) {
			imaStatus = getConnOidList(oid, &iscsiConnList);
		} else {
			return (IMA_ERROR_INCORRECT_OBJECT_TYPE);
		}
	}
	if (imaStatus != IMA_STATUS_SUCCESS) {
		return (imaStatus);
	}

	/*
	 * Based on the results a SUN_IMA_CONN_LIST structure is allocated.
	 */
	allocLen  = iscsiConnList->cl_out_cnt * sizeof (IMA_OID);
	allocLen += sizeof (IMA_OID_LIST) - sizeof (IMA_OID);
	imaOidList = (IMA_OID_LIST *)calloc(1, allocLen);

	if (imaOidList == NULL) {
		free(iscsiConnList);
		return (IMA_ERROR_INSUFFICIENT_MEMORY);
	}

	/* The data is transfered from iscsiConnList to imaConnList. */
	imaOidList->oidCount = iscsiConnList->cl_out_cnt;
	for (i = 0; i < iscsiConnList->cl_out_cnt; i++) {
		imaOidList->oids[i].objectType = SUN_IMA_OBJECT_TYPE_CONN;
		imaOidList->oids[i].ownerId = 1;
		imaOidList->oids[i].objectSequenceNumber =
		    iscsiConnList->cl_list[i].c_oid;
	}
	/* The pointer to the SUN_IMA_CONN_LIST structure is returned. */
	*ppList = imaOidList;

	free(iscsiConnList);
	return (IMA_STATUS_SUCCESS);
}

/*
 * SUN_IMA_GetConnProperties -
 *
 * Non-IMA defined function.
 */
IMA_API	IMA_STATUS SUN_IMA_GetConnProperties(
	IMA_OID			*connOid,
	SUN_IMA_CONN_PROPERTIES	**pProps
)
{
	iscsi_conn_list_t	*pConnList;
	iscsi_conn_props_t	*pConnProps;
	/* LINTED */
	struct sockaddr_in6	*addrIn6;
	/* LINTED */
	struct sockaddr_in	*addrIn;
	SUN_IMA_CONN_PROPERTIES	*pImaConnProps;
	IMA_STATUS		imaStatus;
	int			i;

	/* If there is any error *pProps should be set to NULL */
	*pProps = NULL;

	pImaConnProps = (SUN_IMA_CONN_PROPERTIES *)calloc(1,
	    sizeof (SUN_IMA_CONN_PROPERTIES));

	if (pImaConnProps == NULL) {
		return (IMA_ERROR_INSUFFICIENT_MEMORY);
	}

	imaStatus = getConnOidList(NULL, &pConnList);

	if (imaStatus != IMA_STATUS_SUCCESS) {
		free(pImaConnProps);
		return (imaStatus);
	}

	/*
	 * Walk the list returned to find our connection.
	 */
	for (i = 0; i < pConnList->cl_out_cnt; i++) {

		if (pConnList->cl_list[i].c_oid ==
		    (uint32_t)connOid->objectSequenceNumber) {

			/* This is our connection. */
			imaStatus = getConnProps(&pConnList->cl_list[i],
			    &pConnProps);

			if (imaStatus != IMA_STATUS_SUCCESS) {
				free(pConnList);
				free(pImaConnProps);
				return (imaStatus);
			}
			pImaConnProps->connectionID = pConnProps->cp_cid;

			/*
			 * Local Propeties
			 */
			if (pConnProps->cp_local.soa4.sin_family == AF_INET) {

				pImaConnProps->local.ipAddress.ipv4Address =
				    IMA_TRUE;
				pImaConnProps->local.portNumber =
				    pConnProps->cp_local.soa4.sin_port;
				addrIn = &(pConnProps->cp_local.soa4);
				bcopy(&pConnProps->cp_local.soa4.sin_addr,
				    pImaConnProps->local.ipAddress.ipAddress,
				    sizeof (addrIn->sin_addr));

			} else {
				pImaConnProps->local.ipAddress.ipv4Address =
				    IMA_FALSE;
				pImaConnProps->local.portNumber =
				    pConnProps->cp_local.soa6.sin6_port;
				addrIn6 = &(pConnProps->cp_local.soa6);
				bcopy(&pConnProps->cp_local.soa6.sin6_addr,
				    pImaConnProps->local.ipAddress.ipAddress,
				    sizeof (addrIn6->sin6_addr));

			}

			/*
			 * Peer Propeties
			 */
			if (pConnProps->cp_peer.soa4.sin_family == AF_INET) {

				pImaConnProps->peer.ipAddress.ipv4Address =
				    IMA_TRUE;
				pImaConnProps->peer.portNumber =
				    pConnProps->cp_peer.soa4.sin_port;
				addrIn = &(pConnProps->cp_local.soa4);
				bcopy(&pConnProps->cp_peer.soa4.sin_addr,
				    pImaConnProps->peer.ipAddress.ipAddress,
				    sizeof (addrIn->sin_addr));

			} else {
				pImaConnProps->peer.ipAddress.ipv4Address =
				    IMA_FALSE;
				pImaConnProps->peer.portNumber =
				    pConnProps->cp_peer.soa6.sin6_port;

				addrIn6 = &pConnProps->cp_local.soa6;
				bcopy(&pConnProps->cp_peer.soa6.sin6_addr,
				    pImaConnProps->peer.ipAddress.ipAddress,
				    sizeof (addrIn6->sin6_addr));
			}


			pImaConnProps->valuesValid =
			    pConnProps->cp_params_valid;
			pImaConnProps->defaultTime2Retain =
			    pConnProps->cp_params.default_time_to_retain;
			pImaConnProps->defaultTime2Wait =
			    pConnProps->cp_params.default_time_to_wait;
			pImaConnProps->errorRecoveryLevel =
			    pConnProps->cp_params.error_recovery_level;
			pImaConnProps->firstBurstLength =
			    pConnProps->cp_params.first_burst_length;
			pImaConnProps->maxBurstLength =
			    pConnProps->cp_params.max_burst_length;
			pImaConnProps->maxConnections =
			    pConnProps->cp_params.max_connections;
			pImaConnProps->maxOutstandingR2T =
			    pConnProps->cp_params.max_outstanding_r2t;
			pImaConnProps->maxRecvDataSegmentLength =
			    pConnProps->cp_params.max_recv_data_seg_len;

			pImaConnProps->dataPduInOrder =
			    pConnProps->cp_params.data_pdu_in_order;
			pImaConnProps->dataSequenceInOrder =
			    pConnProps->cp_params.data_sequence_in_order;
			pImaConnProps->immediateData =
			    pConnProps->cp_params.immediate_data;
			pImaConnProps->initialR2T =
			    pConnProps->cp_params.initial_r2t;

			pImaConnProps->headerDigest =
			    pConnProps->cp_params.header_digest;
			pImaConnProps->dataDigest =
			    pConnProps->cp_params.data_digest;

			free(pConnProps);
			break;
		}
	}
	free(pConnList);
	*pProps = pImaConnProps;
	return (IMA_STATUS_SUCCESS);
}


/*
 * SUN_IMA_GetConfigSessions -
 *
 * Non-IMA defined function.
 */
IMA_API IMA_STATUS SUN_IMA_GetConfigSessions(
    IMA_OID targetOid,
    SUN_IMA_CONFIG_SESSIONS **pConfigSessions
)
{
	int			fd;
	int			status;
	iscsi_config_sess_t	*ics;
	int			size, idx;

	/* Allocate and setup initial buffer */
	size = sizeof (*ics);
	ics = (iscsi_config_sess_t *)calloc(1, size);
	if (ics == NULL) {
		return (IMA_ERROR_INSUFFICIENT_MEMORY);
	}
	ics->ics_ver = ISCSI_INTERFACE_VERSION;
	ics->ics_oid = targetOid.objectSequenceNumber;
	ics->ics_in  = 1;

	/* Open driver devctl for ioctl */
	if ((status = open_driver(&fd))) {
		return (SUN_IMA_ERROR_SYSTEM_ERROR | status);
	}

	/* Issue ioctl request */
	if (ioctl(fd, ISCSI_GET_CONFIG_SESSIONS, ics) != 0) {
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_GET_CONFIG_SESSIONS ioctl failed, errno: %d",
		    errno);
		(void) close(fd);
		free(ics);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	/* Check if we need to collect more information */
	idx = ics->ics_out;
	if (idx > 1) {

		/* Free old buffer and reallocate re-sized buffer */
		free(ics);
		size = ISCSI_SESSION_CONFIG_SIZE(idx);
		ics = (iscsi_config_sess_t *)calloc(1, size);
		if (ics == NULL) {
			return (IMA_ERROR_INSUFFICIENT_MEMORY);
		}
		ics->ics_ver = ISCSI_INTERFACE_VERSION;
		ics->ics_oid = targetOid.objectSequenceNumber;
		ics->ics_in = idx;

		/* Issue ioctl request */
		if (ioctl(fd, ISCSI_GET_CONFIG_SESSIONS, ics) != 0) {
			syslog(LOG_USER|LOG_DEBUG,
			    "ISCSI_GET_CONFIG_SESSIONS ioctl failed, errno: %d",
			    errno);
			(void) close(fd);
			free(ics);
			return (IMA_ERROR_UNEXPECTED_OS_ERROR);
		}
	}
	(void) close(fd);

	/* Allocate output buffer */
	size = sizeof (SUN_IMA_CONFIG_SESSIONS) +
	    ((ics->ics_out - 1) * sizeof (IMA_ADDRESS_KEY));
	*pConfigSessions = (SUN_IMA_CONFIG_SESSIONS *)calloc(1, size);
	if ((*pConfigSessions) == NULL) {
		return (IMA_ERROR_INSUFFICIENT_MEMORY);
	}

	/* Copy output information */
	(*pConfigSessions)->bound =
	    (ics->ics_bound == B_TRUE ?  IMA_TRUE : IMA_FALSE);
	(*pConfigSessions)->in = ics->ics_in;
	(*pConfigSessions)->out = ics->ics_out;
	for (idx = 0; idx < ics->ics_in; idx++) {
		if (ics->ics_bindings[idx].i_insize ==
		    sizeof (struct in_addr)) {
			(*pConfigSessions)->bindings[idx].ipAddress.
			    ipv4Address = IMA_TRUE;
			bcopy(&ics->ics_bindings[idx].i_addr.in4,
			    (*pConfigSessions)->bindings[idx].ipAddress.
			    ipAddress, sizeof (struct in_addr));
		} else {
			(*pConfigSessions)->bindings[idx].ipAddress.
			    ipv4Address = IMA_FALSE;
			bcopy(&ics->ics_bindings[idx].i_addr.in6,
			    (*pConfigSessions)->bindings[idx].ipAddress.
			    ipAddress, sizeof (struct in6_addr));
		}
	}

	free(ics);
	return (IMA_STATUS_SUCCESS);
}

/*
 * SUN_IMA_SetConfigSessions -
 *
 * Non-IMA defined function.
 */
IMA_API IMA_STATUS SUN_IMA_SetConfigSessions(
    IMA_OID targetOid,
    SUN_IMA_CONFIG_SESSIONS *pConfigSessions
)
{
	int		    fd;
	int		    status;
	iscsi_config_sess_t *ics;
	int		    idx, size;

	/* verify allowed range of sessions */
	if ((pConfigSessions->in < ISCSI_MIN_CONFIG_SESSIONS) ||
	    (pConfigSessions->in > ISCSI_MAX_CONFIG_SESSIONS)) {
		return (IMA_ERROR_INVALID_PARAMETER);
	}

	/* allocate record config_sess size */
	size = ISCSI_SESSION_CONFIG_SIZE(pConfigSessions->in);
	ics = (iscsi_config_sess_t *)malloc(size);

	/* setup config_sess information */
	(void) memset(ics, 0, sizeof (iscsi_config_sess_t));
	ics->ics_ver = ISCSI_INTERFACE_VERSION;
	ics->ics_oid = targetOid.objectSequenceNumber;
	ics->ics_bound =
	    (pConfigSessions->bound == IMA_TRUE ?  B_TRUE : B_FALSE);
	ics->ics_in  = pConfigSessions->in;
	for (idx = 0; idx < ics->ics_in; idx++) {
		if (pConfigSessions->bindings[idx].ipAddress.
		    ipv4Address == IMA_TRUE) {
			ics->ics_bindings[idx].i_insize =
			    sizeof (struct in_addr);
			bcopy(pConfigSessions->bindings[idx].
			    ipAddress.ipAddress,
			    &ics->ics_bindings[idx].i_addr.in4,
			    sizeof (struct in_addr));
		} else {
			ics->ics_bindings[idx].i_insize =
			    sizeof (struct in6_addr);
			bcopy(pConfigSessions->bindings[idx].
			    ipAddress.ipAddress,
			    &ics->ics_bindings[idx].i_addr.in6,
			    sizeof (struct in6_addr));
		}
	}

	/* open driver */
	if ((status = open_driver(&fd))) {
		free(ics);
		return (SUN_IMA_ERROR_SYSTEM_ERROR | status);
	}

	/* issue ioctl request */
	if (ioctl(fd, ISCSI_SET_CONFIG_SESSIONS, ics) != 0) {
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_SET_CONFIG_SESSIONS ioctl failed, errno: %d",
		    errno);
		(void) close(fd);
		free(ics);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}
	(void) close(fd);
	free(ics);
	return (IMA_STATUS_SUCCESS);
}

/* A helper function to obtain iSCSI node parameters. */
static IMA_STATUS
getISCSINodeParameter(
    int paramType,
    IMA_OID *oid,
    void *pProps,
    uint32_t paramIndex
)
{
	int		    fd;
	int 		status;
	iscsi_param_get_t   pg;

	if ((status = open_driver(&fd))) {
		return (SUN_IMA_ERROR_SYSTEM_ERROR | status);
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

	/* Issue ISCSI_PARAM_GET ioctl again to obtain connection parameters. */
	pg.g_param_type = ISCSI_CONN_PARAM;
	if (ioctl(fd, ISCSI_PARAM_GET, &pg) != 0) {
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_PARAM_GET ioctl failed, errno: %d", errno);
		(void) close(fd);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}

/* A helper function to set iSCSI node parameters. */
static IMA_STATUS
setISCSINodeParameter(
    int paramType,
    IMA_OID *oid,
    void *pProp,
    uint32_t paramIndex
)
{
	int		    fd;
	int			status;
	iscsi_param_set_t   ps;

	if ((status = open_driver(&fd))) {
		return (SUN_IMA_ERROR_SYSTEM_ERROR | status);
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
		(void) close(fd);
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_PARAM_SET ioctl failed, errno: %d", errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}

static int
prepare_discovery_entry(
    SUN_IMA_TARGET_ADDRESS discoveryAddress,
    entry_t *entry
)
{
	return (prepare_discovery_entry_IMA(discoveryAddress.imaStruct, entry));
}

static int
prepare_discovery_entry_IMA(
    IMA_TARGET_ADDRESS discoveryAddress,
    entry_t *entry
)
{
	(void) memset(entry, 0, sizeof (entry_t));
	entry->e_vers = ISCSI_INTERFACE_VERSION;
	entry->e_oid = ISCSI_OID_NOTSET;

	if (discoveryAddress.hostnameIpAddress.id.ipAddress.
	    ipv4Address == IMA_FALSE) {

		bcopy(discoveryAddress.hostnameIpAddress.id.ipAddress.
		    ipAddress, entry->e_u.u_in6.s6_addr,
		    sizeof (entry->e_u.u_in6.s6_addr));

		entry->e_insize = sizeof (struct in6_addr);
	} else {

		bcopy(discoveryAddress.hostnameIpAddress.id.ipAddress.
		    ipAddress, &entry->e_u.u_in4.s_addr,
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
	int	fd, status;

	if ((status = open_driver(&fd))) {
		return (SUN_IMA_ERROR_SYSTEM_ERROR | status);
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
			status = errno;
			(void) close(fd);
			syslog(LOG_USER|LOG_DEBUG,
			    "ISCSI_DISCOVERY_SET ioctl failed, errno: %d",
			    status);
			return (IMA_ERROR_UNEXPECTED_OS_ERROR);
		}

		(void) close(fd);
		return (IMA_STATUS_SUCCESS);
	}
}

/* LINTED E_STATIC_UNUSED */
static IMA_BOOL authMethodMatch(
    IMA_AUTHMETHOD matchingMethod,
    IMA_AUTHMETHOD *methodList,
    IMA_UINT maxEntries
)
{
	IMA_UINT i;

	for (i = 0; i < maxEntries; i++) {
		if (methodList[i] == matchingMethod) {
			return (IMA_TRUE);
		}
	}

	return (IMA_FALSE);
}

static IMA_STATUS get_target_oid_list(
    uint32_t targetListType,
    IMA_OID_LIST **ppList)
{
	int		    fd;
	int		    i;
	int		    target_list_size;
	int		    status;
	int		    out_cnt;
	iscsi_target_list_t *idlp;

	if ((status = open_driver(&fd))) {
		return (SUN_IMA_ERROR_SYSTEM_ERROR | status);
	}

	idlp = (iscsi_target_list_t *)calloc(1, sizeof (iscsi_target_list_t));
	if (idlp == NULL) {
		(void) close(fd);
		return (IMA_ERROR_INSUFFICIENT_MEMORY);
	}
	idlp->tl_vers = ISCSI_INTERFACE_VERSION;
	idlp->tl_in_cnt = idlp->tl_out_cnt = 1;
	idlp->tl_tgt_list_type = targetListType;

	/*
	 * Issue ioctl.  Space has been allocted for one entry.
	 * If more than one entry should be returned, we will re-issue the
	 * entry with the right amount of space allocted
	 */
	if (ioctl(fd, ISCSI_TARGET_OID_LIST_GET, idlp) != 0) {
		(void) close(fd);
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_TARGET_OID_LIST_GET ioctl %d failed, errno: %d",
		    targetListType, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}
	if (idlp->tl_out_cnt > 1) {
		out_cnt = idlp->tl_out_cnt;
		free(idlp);

		target_list_size = sizeof (iscsi_target_list_t);
		target_list_size += (sizeof (uint32_t) * out_cnt - 1);
		idlp = (iscsi_target_list_t *)calloc(1, target_list_size);
		if (idlp == NULL) {
			(void) close(fd);
			return (IMA_ERROR_INSUFFICIENT_MEMORY);
		}
		idlp->tl_vers = ISCSI_INTERFACE_VERSION;
		idlp->tl_in_cnt = out_cnt;
		idlp->tl_tgt_list_type = targetListType;

		/* Issue the same ioctl again to obtain all the OIDs. */
		if (ioctl(fd, ISCSI_TARGET_OID_LIST_GET, idlp) != 0) {
#define	ERROR_STR "ISCSI_DISCOVERY_ADDR_LIST_GET ioctl failed, errno :%d"
			free(idlp);
			(void) close(fd);
			syslog(LOG_USER|LOG_DEBUG,
			    ERROR_STR, targetListType, errno);
			return (IMA_ERROR_UNEXPECTED_OS_ERROR);
#undef ERROR_STR

		}
	}

	*ppList = (IMA_OID_LIST *)calloc(1, sizeof (IMA_OID_LIST) +
	    idlp->tl_out_cnt * sizeof (IMA_OID));
	(*ppList)->oidCount = idlp->tl_out_cnt;
	for (i = 0; i < idlp->tl_out_cnt; i++) {
		(*ppList)->oids[i].objectType = IMA_OBJECT_TYPE_TARGET;
		(*ppList)->oids[i].ownerId = 1;
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
	iscsi_lun_list_t	*illp, *illp_saved;
	int			lun_list_size;
	int			status;

	if ((status = open_driver(&fd))) {
		return (SUN_IMA_ERROR_SYSTEM_ERROR | status);
	}

	illp = (iscsi_lun_list_t *)calloc(1, sizeof (iscsi_lun_list_t));
	if (illp == NULL) {
		(void) close(fd);
		return (IMA_ERROR_INSUFFICIENT_MEMORY);
	}
	illp->ll_vers = ISCSI_INTERFACE_VERSION;
	if (targetOid == NULL) {
		/* get lun oid list for all targets */
		illp->ll_all_tgts = B_TRUE;
	} else {
		/* get lun oid list for single target */
		illp->ll_all_tgts = B_FALSE;
		illp->ll_tgt_oid = (uint32_t)targetOid->objectSequenceNumber;
	}
	illp->ll_in_cnt = illp->ll_out_cnt = 1;

	/*
	 * Issue ioctl to retrieve the target luns.  Space has been allocted
	 * for one entry.  If more than one entry should be returned, we
	 * will re-issue the entry with the right amount of space allocted
	 */
	if (ioctl(fd, ISCSI_LUN_OID_LIST_GET, illp) != 0) {
		(void) close(fd);
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_LUN_LIST_GET ioctl failed, errno: %d", errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	if (illp->ll_out_cnt > 1) {
		illp_saved = illp;
		lun_list_size = sizeof (iscsi_lun_list_t);
		lun_list_size += (sizeof (iscsi_if_lun_t) *
		    (illp->ll_out_cnt - 1));
		illp = (iscsi_lun_list_t *)calloc(1, lun_list_size);
		if (illp == NULL) {
			(void) close(fd);
			return (IMA_ERROR_INSUFFICIENT_MEMORY);
		}
		illp->ll_vers = ISCSI_INTERFACE_VERSION;
		illp->ll_all_tgts = illp_saved->ll_all_tgts;
		illp->ll_tgt_oid = illp_saved->ll_tgt_oid;
		illp->ll_in_cnt = illp_saved->ll_out_cnt;

		free(illp_saved);

		/* Issue the same ioctl again to get all the target LUN list */
		if (ioctl(fd, ISCSI_LUN_OID_LIST_GET, illp) != 0) {
			free(illp);
			(void) close(fd);
			syslog(LOG_USER|LOG_DEBUG,
			    "ISCSI_LUN_LIST_GET ioctl failed, errno: %d",
			    errno);
			return (IMA_ERROR_UNEXPECTED_OS_ERROR);

		}
	}
	*ppLunList = illp;


	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}

/* A helper function to obtain digest algorithms. */
static IMA_STATUS
getDigest(
    IMA_OID oid,
    int ioctlCmd,
    SUN_IMA_DIGEST_ALGORITHM_VALUE *algorithm
)
{
	IMA_MIN_MAX_VALUE pProps;
	IMA_STATUS status;

	if ((status = getISCSINodeParameter(MIN_MAX_PARAM, &oid, &pProps,
	    ioctlCmd)) != IMA_STATUS_SUCCESS) {
		return (status);
	}

	switch (pProps.defaultValue) {
		case ISCSI_DIGEST_NONE:
			algorithm->defaultAlgorithms[0] = ISCSI_DIGEST_NONE;
			algorithm->defaultAlgorithmCount = 1;
			break;
		case ISCSI_DIGEST_CRC32C:
			algorithm->defaultAlgorithms[0] = ISCSI_DIGEST_CRC32C;
			algorithm->defaultAlgorithmCount = 1;
			break;

		case ISCSI_DIGEST_CRC32C_NONE:
			algorithm->defaultAlgorithms[0] = ISCSI_DIGEST_CRC32C;
			algorithm->defaultAlgorithms[1] = ISCSI_DIGEST_NONE;
			algorithm->defaultAlgorithmCount = 2;
			break;
		case ISCSI_DIGEST_NONE_CRC32C:
			algorithm->defaultAlgorithms[0] = ISCSI_DIGEST_NONE;
			algorithm->defaultAlgorithms[1] = ISCSI_DIGEST_CRC32C;
			algorithm->defaultAlgorithmCount = 2;
			break;
		default:
			/* Error */
			syslog(LOG_USER|LOG_DEBUG,
			    "Invalid default digest: %d", pProps.defaultValue);
			return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	/* The configured value */
	if (pProps.currentValueValid == IMA_TRUE) {
		algorithm->currentValid = IMA_TRUE;

		switch (pProps.currentValue) {
			case ISCSI_DIGEST_NONE:
				algorithm->currentAlgorithms[0] =
				    ISCSI_DIGEST_NONE;
				algorithm->currentAlgorithmCount = 1;
				break;
			case ISCSI_DIGEST_CRC32C:
				algorithm->currentAlgorithms[0] =
				    ISCSI_DIGEST_CRC32C;
				algorithm->currentAlgorithmCount = 1;
				break;

			case ISCSI_DIGEST_CRC32C_NONE:
				algorithm->currentAlgorithms[0] =
				    ISCSI_DIGEST_CRC32C;
				algorithm->currentAlgorithms[1] =
				    ISCSI_DIGEST_NONE;
				algorithm->currentAlgorithmCount = 2;
				break;
			case ISCSI_DIGEST_NONE_CRC32C:
				algorithm->currentAlgorithms[0] =
				    ISCSI_DIGEST_NONE;
				algorithm->currentAlgorithms[1] =
				    ISCSI_DIGEST_CRC32C;
				algorithm->currentAlgorithmCount = 2;
				break;
			default:
				/* Error */
				syslog(LOG_USER|LOG_DEBUG,
				    "Invalid configured digest: %d",
				    pProps.defaultValue);
				return (IMA_ERROR_UNEXPECTED_OS_ERROR);
		}

	} else {
		algorithm->currentValid = IMA_FALSE;
	}

	return (IMA_STATUS_SUCCESS);
}

/*
 * getConnOidList -
 */
static IMA_STATUS getConnOidList(
	IMA_OID			*sessOid,
	iscsi_conn_list_t	**ppConnList
)
{
	iscsi_conn_list_t	*iscsiConnList = NULL;
	size_t			allocLen;
	int			fd;
	int			status;
	int			out_cnt;

	/* Preset it to NULL to prepare for the case of failure */
	*ppConnList = NULL;

	/* We try to open the driver now. */
	if ((status = open_driver(&fd))) {
		return (SUN_IMA_ERROR_SYSTEM_ERROR | status);
	}

	iscsiConnList = (iscsi_conn_list_t *)calloc(1,
	    sizeof (iscsi_conn_list_t));
	if (iscsiConnList == NULL) {
		(void) close(fd);
		return (IMA_ERROR_INSUFFICIENT_MEMORY);
	}
	iscsiConnList->cl_vers = ISCSI_INTERFACE_VERSION;
	iscsiConnList->cl_in_cnt = iscsiConnList->cl_out_cnt = 1;
	if (sessOid == NULL) {
		iscsiConnList->cl_all_sess = B_TRUE;
	} else {
		iscsiConnList->cl_all_sess = B_FALSE;
		iscsiConnList->cl_sess_oid =
		    (uint32_t)sessOid->objectSequenceNumber;
	}
	/*
	 * Issue ioctl to retrieve the connection OIDs.  Space has been
	 * allocated for one entry.  If more than one entry should be
	 * returned, we will re-issue the entry with the right amount of
	 * space allocted
	 */
	if (ioctl(fd, ISCSI_CONN_OID_LIST_GET, iscsiConnList) != 0) {
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_CONN_OID_LIST_GET ioctl failed, errno: %d", errno);
		*ppConnList = NULL;
		(void) close(fd);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}
	if (iscsiConnList->cl_out_cnt > 1) {
		out_cnt = iscsiConnList->cl_out_cnt;
		free(iscsiConnList);

		allocLen = sizeof (iscsi_conn_list_t);
		allocLen += (sizeof (iscsi_if_conn_t) * out_cnt - 1);
		iscsiConnList = (iscsi_conn_list_t *)calloc(1, allocLen);
		if (iscsiConnList == NULL) {
			*ppConnList = NULL;
			(void) close(fd);
			return (IMA_ERROR_INSUFFICIENT_MEMORY);
		}
		iscsiConnList->cl_vers = ISCSI_INTERFACE_VERSION;
		iscsiConnList->cl_in_cnt = out_cnt;
		if (sessOid == NULL) {
			iscsiConnList->cl_all_sess = B_TRUE;
		} else {
			iscsiConnList->cl_all_sess = B_FALSE;
			iscsiConnList->cl_sess_oid =
			    (uint32_t)sessOid->objectSequenceNumber;
		}
		/* Issue the same ioctl again to obtain all the OIDs */
		if (ioctl(fd, ISCSI_CONN_OID_LIST_GET, iscsiConnList) != 0) {

			syslog(LOG_USER|LOG_DEBUG,
			    "ISCSI_CONN_OID_LIST_GET ioctl failed, errno: %d",
			    errno);
			*ppConnList = NULL;
			free(iscsiConnList);
			(void) close(fd);
			return (IMA_ERROR_UNEXPECTED_OS_ERROR);

		}

		if (out_cnt < iscsiConnList->cl_out_cnt) {
			/*
			 * The connection list grew between the first and second
			 * ioctls.
			 */
			syslog(LOG_USER|LOG_DEBUG,
			    "The connection list has grown. There could be "
			    "more connections than listed.");
		}
	}


	(void) close(fd);
	*ppConnList = iscsiConnList;
	return (IMA_STATUS_SUCCESS);
}

/*
 * getConnProps -
 */
static IMA_STATUS getConnProps(
	iscsi_if_conn_t		*pConn,
	iscsi_conn_props_t	**ppConnProps
)
{
	iscsi_conn_props_t	*iscsiConnProps;
	int			fd;
	int			status;

	/* We try to open the driver. */
	if ((status = open_driver(&fd))) {
		return (SUN_IMA_ERROR_SYSTEM_ERROR | status);
	}

	iscsiConnProps = (iscsi_conn_props_t *)calloc(1,
	    sizeof (*iscsiConnProps));

	if (iscsiConnProps == NULL) {
		(void) close(fd);
		return (IMA_ERROR_INSUFFICIENT_MEMORY);
	}

	iscsiConnProps->cp_vers = ISCSI_INTERFACE_VERSION;
	iscsiConnProps->cp_oid = pConn->c_oid;
	iscsiConnProps->cp_cid = pConn->c_cid;
	iscsiConnProps->cp_sess_oid = pConn->c_sess_oid;

	/* The IOCTL is submitted. */
	if (ioctl(fd, ISCSI_CONN_PROPS_GET, iscsiConnProps) != 0) {
		/* IOCTL failed */
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_AUTH_CLEAR ioctl failed, errno: %d", errno);
		free(iscsiConnProps);
		(void) close(fd);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}
	(void) close(fd);
	*ppConnProps = iscsiConnProps;
	return (IMA_STATUS_SUCCESS);
}

/* A helper function to set authentication method. */
static IMA_STATUS
setAuthMethods(
    IMA_OID oid,
    IMA_UINT *pMethodCount,
    const IMA_AUTHMETHOD *pMethodList
)
{
	int fd;
	int i;
	int status;
	iscsi_auth_props_t auth;

	if ((status = open_driver(&fd))) {
		return (SUN_IMA_ERROR_SYSTEM_ERROR | status);
	}
	(void) memset(&auth, 0, sizeof (iscsi_auth_props_t));
	auth.a_vers = ISCSI_INTERFACE_VERSION;
	auth.a_oid = (uint32_t)oid.objectSequenceNumber;

	/*
	 * Get the current auth fields so they don't need to be reset
	 * here.
	 */
	if (ioctl(fd, ISCSI_AUTH_GET, &auth) != 0) {
	    /* EMPTY */
	    /* Initializing auth structure with current settings */
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

/* A helper function to set authentication method. */
static IMA_STATUS getAuthMethods(
    IMA_OID oid,
    IMA_UINT	*pMethodCount,
    IMA_AUTHMETHOD *pMethodList
)
{
	int fd;
	int status;
	iscsi_auth_props_t auth;

	if ((status = open_driver(&fd))) {
		return (SUN_IMA_ERROR_SYSTEM_ERROR | status);
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

	if (auth.a_auth_method == authMethodNone) {
		pMethodList[0] = IMA_AUTHMETHOD_NONE;
		*pMethodCount = 1;
	} else {
		int i = 0;
		if (!((auth.a_auth_method & authMethodCHAP)^authMethodCHAP)) {
			pMethodList[i++] = IMA_AUTHMETHOD_CHAP;
		}
		*pMethodCount = i;
	}

	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}

/* Helper function to open driver */
int open_driver(
	int *fd
)
{
	int ret = 0;
	if ((*fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) == -1) {
		ret = errno;
		syslog(LOG_USER|LOG_DEBUG, "Cannot open %s (%d)",
		    ISCSI_DRIVER_DEVCTL, ret);
	}
	return (ret);
}

/*
 * Iscsi driver does not support OID for discovery address. Create
 * a modified version of IMA_RemoveDiscoveryAddress that takes
 * discoveryAddress (instead of an OID) as input argument.
 */
IMA_API	IMA_STATUS SUN_IMA_RemoveDiscoveryAddress(
    SUN_IMA_TARGET_ADDRESS discoveryAddress
)
{
	entry_t	entry;
	int	fd;
	int status, i, addr_list_size, insize;
	iscsi_addr_list_t *idlp, al_info;
	iscsi_addr_t *matched_addr = NULL;

	if ((status = open_driver(&fd))) {
		return (SUN_IMA_ERROR_SYSTEM_ERROR | status);
	}

	if (prepare_discovery_entry(discoveryAddress, &entry) !=
	    DISC_ADDR_OK) {
		(void) close(fd);
		return (IMA_ERROR_INVALID_PARAMETER);
	}

	(void) memset(&al_info, 0, sizeof (al_info));
	al_info.al_vers = ISCSI_INTERFACE_VERSION;
	al_info.al_in_cnt = 0;
	/*
	 * Issue ioctl to get the number of discovery address.
	 */
	if (ioctl(fd, ISCSI_DISCOVERY_ADDR_LIST_GET, &al_info) != 0) {
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_DISCOVERY_ADDR_LIST_GET ioctl %d failed, errno: %d",
		    ISCSI_DISCOVERY_ADDR_LIST_GET, errno);
		(void) close(fd);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	if (al_info.al_out_cnt == 0) {
		(void) close(fd);
		return (IMA_ERROR_OBJECT_NOT_FOUND);
	}

	addr_list_size = sizeof (iscsi_addr_list_t);
	if (al_info.al_out_cnt > 1) {
		addr_list_size += (sizeof (iscsi_addr_t) *
		    (al_info.al_out_cnt - 1));
	}

	idlp = (iscsi_addr_list_t *)calloc(1, addr_list_size);
	if (idlp == NULL) {
		(void) close(fd);
		return (IMA_ERROR_INSUFFICIENT_MEMORY);
	}

	idlp->al_vers = ISCSI_INTERFACE_VERSION;
	idlp->al_in_cnt = al_info.al_out_cnt;

	/* issue the same ioctl to get all the discovery addresses */
	if (ioctl(fd, ISCSI_DISCOVERY_ADDR_LIST_GET, idlp) != 0) {
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_DISCOVERY_ADDR_LIST_GET ioctl %d failed, errno: %d",
		    ISCSI_DISCOVERY_ADDR_LIST_GET, errno);
		free(idlp);
		(void) close(fd);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	/*
	 * find the matched discovery address
	 */
	for (i = 0; i < idlp->al_out_cnt; i++) {
		insize = idlp->al_addrs[i].a_addr.i_insize;
		if (insize != entry.e_insize) {
			continue;
		}
		if (insize == sizeof (struct in_addr)) {
			if (idlp->al_addrs[i].a_addr.i_addr.in4.s_addr ==
			    entry.e_u.u_in4.s_addr) {
				matched_addr = &(idlp->al_addrs[i]);
				break;
			}
		}
		if (insize == sizeof (struct in6_addr)) {
			if (bcmp(entry.e_u.u_in6.s6_addr,
			    idlp->al_addrs[i].a_addr.i_addr.in6.s6_addr,
			    insize) == 0) {
				matched_addr = &(idlp->al_addrs[i]);
				break;
			}
		}
	}

	free(idlp);

	if (matched_addr == NULL) {
		(void) close(fd);
		return (IMA_ERROR_OBJECT_NOT_FOUND);
	}

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

	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}

IMA_STATUS SUN_IMA_SetTargetAuthMethods(
		IMA_OID targetOid,
		IMA_UINT *methodCount,
		const IMA_AUTHMETHOD *pMethodList
)
{
	return (setAuthMethods(targetOid, methodCount, pMethodList));
}

IMA_STATUS getNegotiatedDigest(
	int digestType,
	SUN_IMA_DIGEST_ALGORITHM_VALUE *algorithm,
	SUN_IMA_CONN_PROPERTIES *connProps) {

	IMA_UINT digest;

	if (connProps->valuesValid == IMA_TRUE) {
		algorithm->negotiatedValid = IMA_TRUE;

		if (digestType == ISCSI_LOGIN_PARAM_HEADER_DIGEST) {
			digest = connProps->headerDigest;
		} else {
			digest = connProps->dataDigest;
		}

		switch (digest) {
			case ISCSI_DIGEST_NONE:
				algorithm->negotiatedAlgorithms[0] =
				    ISCSI_DIGEST_NONE;
				algorithm->negotiatedAlgorithmCount = 1;
				break;
			case ISCSI_DIGEST_CRC32C:
				algorithm->negotiatedAlgorithms[0] =
				    ISCSI_DIGEST_CRC32C;
				algorithm->negotiatedAlgorithmCount = 1;
				break;

			case ISCSI_DIGEST_CRC32C_NONE:
				algorithm->negotiatedAlgorithms[0] =
				    ISCSI_DIGEST_CRC32C;
				algorithm->negotiatedAlgorithms[1] =
				    ISCSI_DIGEST_NONE;
				algorithm->negotiatedAlgorithmCount = 2;
				break;
			case ISCSI_DIGEST_NONE_CRC32C:
				algorithm->negotiatedAlgorithms[0] =
				    ISCSI_DIGEST_NONE;
				algorithm->negotiatedAlgorithms[1] =
				    ISCSI_DIGEST_CRC32C;
				algorithm->negotiatedAlgorithmCount = 2;
				break;
			default:
				syslog(LOG_USER|LOG_DEBUG,
				    "Invalid negotiated digest: %d",
				    digest);
				return (IMA_ERROR_UNEXPECTED_OS_ERROR);
		}
	} else {
		algorithm->negotiatedValid = IMA_FALSE;
	}
	return (IMA_STATUS_SUCCESS);
}

/*
 * Non-IMA defined function.
 */
IMA_API	IMA_STATUS SUN_IMA_GetISNSServerAddressPropertiesList(
    SUN_IMA_DISC_ADDR_PROP_LIST	**ppList
)
{
	char		    isns_server_addr_str[256];
	int		    fd;
	int		    i;
	int		    isns_server_addr_list_size;
	int		    status;
	int		    out_cnt;
	iscsi_addr_list_t   *ialp;
	/* LINTED */
	IMA_IP_ADDRESS	    *ipAddr;

	if ((status = open_driver(&fd))) {
		return (SUN_IMA_ERROR_SYSTEM_ERROR | status);
	}

	ialp = (iscsi_addr_list_t *)calloc(1, sizeof (iscsi_addr_list_t));
	if (ialp == NULL) {
		(void) close(fd);
		return (IMA_ERROR_INSUFFICIENT_MEMORY);
	}
	ialp->al_vers = ISCSI_INTERFACE_VERSION;
	ialp->al_in_cnt = ialp->al_out_cnt = 1;

	/*
	 * Issue ioctl to retrieve the isns server addresses.  Space has been
	 * allocted for one entry.  If more than one entry should be returned,
	 * we will re-issue the entry with the right amount of space allocted
	 */
	if (ioctl(fd, ISCSI_ISNS_SERVER_ADDR_LIST_GET, ialp) != 0) {
		(void) close(fd);
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_ISNS_SERVER_ADDR_LIST_GET ioctl failed, errno: %d",
		    errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	isns_server_addr_list_size = sizeof (iscsi_addr_list_t);
	if (ialp->al_out_cnt > 1) {
		out_cnt = ialp->al_out_cnt;
		free(ialp);

		isns_server_addr_list_size += (sizeof (iscsi_addr_t) *
		    out_cnt - 1);
		ialp = (iscsi_addr_list_t *)calloc(1,
		    isns_server_addr_list_size);
		if (ialp == NULL) {
			(void) close(fd);
			return (IMA_ERROR_INSUFFICIENT_MEMORY);
		}
		ialp->al_vers = ISCSI_INTERFACE_VERSION;
		ialp->al_in_cnt = out_cnt;

		/*
		 * Issue ISCSI_ISNS_SERVER_ADDR_LIST_GET ioctl again to obtain
		 * the list of all the iSNS server addresses
		 */
		if (ioctl(fd, ISCSI_ISNS_SERVER_ADDR_LIST_GET, ialp) != 0) {
			free(ialp);
			(void) close(fd);
			syslog(LOG_USER|LOG_DEBUG,
			    "ISCSI_ISNS_SERVER_ADDR_LIST_GET ioctl failed, "
			    "errno: %d", errno);
			return (IMA_ERROR_UNEXPECTED_OS_ERROR);

		}
	}

	*ppList = (SUN_IMA_DISC_ADDR_PROP_LIST *)calloc(1,
	    sizeof (SUN_IMA_DISC_ADDR_PROP_LIST) +
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
			(*ppList)->props[i].discoveryAddress.hostnameIpAddress.
			    id.ipAddress.ipv4Address = IMA_FALSE;
		} else {
			(void) strlcpy(isns_server_addr_str, "unknown",
			    sizeof (isns_server_addr_str));
		}

		ipAddr = &(*ppList)->props[i].discoveryAddress.
		    hostnameIpAddress.id.ipAddress;
		bcopy(&ialp->al_addrs[i].a_addr.i_addr,
		    (*ppList)->props[i].discoveryAddress.hostnameIpAddress.id.
		    ipAddress.ipAddress,
		    sizeof (ipAddr->ipAddress));
		(*ppList)->props[i].discoveryAddress.portNumber =
		    ialp->al_addrs[i].a_port;
	}

	free(ialp);
	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}

/*ARGSUSED*/
/*
 * Remove iSNS Server Address
 */
IMA_API	IMA_STATUS SUN_IMA_RemoveISNSServerAddress(
    SUN_IMA_TARGET_ADDRESS isnsServerAddress
)
{
	entry_t	entry;
	int	fd, status;

	if ((status = open_driver(&fd))) {
		return (SUN_IMA_ERROR_SYSTEM_ERROR | status);
	}

	if (prepare_discovery_entry(isnsServerAddress, &entry) !=
	    DISC_ADDR_OK) {
		(void) close(fd);
		return (IMA_ERROR_INVALID_PARAMETER);
	}

	if (ioctl(fd, ISCSI_ISNS_SERVER_ADDR_CLEAR, &entry)) {
		status = errno;
		(void) close(fd);
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_ISNS_SERVER_ADDR_CLEAR ioctl failed, errno: %d",
		    status);
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
IMA_API IMA_STATUS SUN_IMA_AddISNSServerAddress(
		const SUN_IMA_TARGET_ADDRESS isnsServerAddress
)
{
	entry_t			    entry;
	int			    fd;
	int			    status;

	if ((status = open_driver(&fd))) {
		return (SUN_IMA_ERROR_SYSTEM_ERROR | status);
	}

	if (prepare_discovery_entry(isnsServerAddress, &entry) !=
	    DISC_ADDR_OK) {
		(void) close(fd);
		return (IMA_ERROR_INVALID_PARAMETER);
	}

	if (ioctl(fd, ISCSI_ISNS_SERVER_ADDR_SET, &entry)) {
		/*
		 * Encountered problem setting the discovery address.
		 */
		(void) close(fd);
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_ISNS_SERVER_ADDR_SET ioctl failed, errno: %d",
		    errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}

IMA_STATUS SUN_IMA_RetrieveISNSServerTargets(
    IMA_TARGET_ADDRESS serverAddress,
    SUN_IMA_DISC_ADDRESS_KEY_PROPERTIES **ppList
)
{
	int				    fd;
	int				    ctr;
	int				    server_pg_list_sz;
	int				    status;
	isns_server_portal_group_list_t	    *server_pg_list = NULL;
	isns_portal_group_list_t	    *pg_list = NULL;
	IMA_BOOL			    retry = IMA_TRUE;
	entry_t				    entry;

#define	ISNS_SERVER_DEFAULT_NUM_TARGETS	50

	server_pg_list_sz = sizeof (*server_pg_list) +
	    ((ISNS_SERVER_DEFAULT_NUM_TARGETS - 1) *
	    sizeof (isns_portal_group_t));

	server_pg_list = (isns_server_portal_group_list_t *)calloc(1,
	    server_pg_list_sz);
	if (server_pg_list == NULL) {
		return (IMA_ERROR_INSUFFICIENT_MEMORY);
	}
	server_pg_list->addr_port_list.pg_in_cnt =
	    ISNS_SERVER_DEFAULT_NUM_TARGETS;

	if ((prepare_discovery_entry_IMA(serverAddress, &entry)
	    != DISC_ADDR_OK)) {
		free(server_pg_list);
		return (IMA_ERROR_INVALID_PARAMETER);
	}
	server_pg_list->addr.a_port = entry.e_port;
	server_pg_list->addr.a_addr.i_insize = entry.e_insize;
	if (entry.e_insize == sizeof (struct in_addr)) {
		server_pg_list->addr.a_addr.i_addr.in4.s_addr =
		    (entry.e_u.u_in4.s_addr);
	} else if (entry.e_insize == sizeof (struct in6_addr)) {
		bcopy(&entry.e_u.u_in6.s6_addr,
		    server_pg_list->addr.a_addr.i_addr.in6.s6_addr, 16);
	}

	if ((status = open_driver(&fd))) {
		free(server_pg_list);
		return (SUN_IMA_ERROR_SYSTEM_ERROR | status);
	}

retry_isns:
	/*
	 * Issue ioctl to obtain the ISNS Portal Group List list
	 */
	if (ioctl(fd, ISCSI_ISNS_SERVER_GET, server_pg_list) != 0) {
		int tmp_errno = errno;
		IMA_STATUS return_status;

		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_ISNS_SERVER_GET ioctl failed, errno: %d", tmp_errno);
		if (tmp_errno == EACCES) {
			return_status = IMA_ERROR_OBJECT_NOT_FOUND;
		} else {
			return_status = IMA_ERROR_UNEXPECTED_OS_ERROR;
		}
		(void) close(fd);
		free(server_pg_list);
		return (return_status);
	}
	pg_list = &server_pg_list->addr_port_list;

	/* check if all targets received */
	if (pg_list->pg_in_cnt < pg_list->pg_out_cnt) {
		if (retry == IMA_TRUE) {
			server_pg_list_sz = sizeof (*server_pg_list) +
			    ((pg_list->pg_out_cnt - 1) *
			    sizeof (isns_server_portal_group_list_t));
			server_pg_list = (isns_server_portal_group_list_t *)
			    realloc(server_pg_list, server_pg_list_sz);
			if (server_pg_list == NULL) {
				(void) close(fd);
				return (IMA_ERROR_INSUFFICIENT_MEMORY);
			}
			pg_list = &server_pg_list->addr_port_list;
			pg_list->pg_in_cnt = pg_list->pg_out_cnt;
			retry = IMA_FALSE;
			goto retry_isns;
		} else {
			/*
			 * don't retry after 2 attempts.  The target list
			 * shouldn't continue growing. Just continue
			 * on and display what was found.
			 */
			syslog(LOG_USER|LOG_DEBUG,
			    "ISCSI_SENDTGTS_GET overflow: "
			    "failed to obtain all targets");
			pg_list->pg_out_cnt = pg_list->pg_in_cnt;
		}
	}

	(void) close(fd);

	/* allocate for caller return buffer */
	*ppList = (SUN_IMA_DISC_ADDRESS_KEY_PROPERTIES *)calloc(1,
	    sizeof (SUN_IMA_DISC_ADDRESS_KEY_PROPERTIES) +
	    pg_list->pg_out_cnt * sizeof (SUN_IMA_DISC_ADDRESS_KEY));
	if (*ppList == NULL) {
		free(server_pg_list);
		return (IMA_ERROR_INSUFFICIENT_MEMORY);
	}

	(*ppList)->keyCount = pg_list->pg_out_cnt;

	for (ctr = 0; ctr < pg_list->pg_out_cnt; ctr++) {
		(void) mbstowcs((*ppList)->keys[ctr].name,
		    (char *)pg_list->pg_list[ctr].pg_iscsi_name,
		    IMA_NODE_NAME_LEN);

		(*ppList)->keys[ctr].tpgt = pg_list->pg_list[ctr].pg_tag;

		(*ppList)->keys[ctr].address.portNumber =
		    pg_list->pg_list[ctr].pg_port;

		if (pg_list->pg_list[ctr].insize == sizeof (struct in_addr)) {
			(*ppList)->keys[ctr].address.ipAddress.ipv4Address =
			    IMA_TRUE;
		} else if (pg_list->pg_list[ctr].insize ==
		    sizeof (struct in6_addr)) {
			(*ppList)->keys[ctr].address.ipAddress.ipv4Address =
			    IMA_FALSE;
		} else {
			free(pg_list);
			return (IMA_ERROR_UNEXPECTED_OS_ERROR);
		}

		(void) memcpy(&(*ppList)->keys[ctr].address.ipAddress.ipAddress,
		    &(pg_list->pg_list[ctr].pg_ip_addr),
		    pg_list->pg_list[ctr].insize);
	}
	free(server_pg_list);

	return (IMA_STATUS_SUCCESS);
}

/* ARGSUSED */
IMA_STATUS SUN_IMA_GetSessionOidList(
    IMA_OID initiatorOid,
    IMA_OID_LIST **ppList
)
{
	return (get_target_oid_list(ISCSI_TGT_OID_LIST, ppList));
}

/*ARGSUSED*/
IMA_API	IMA_STATUS SUN_IMA_GetTargetAuthParms(
	IMA_OID oid,
	IMA_AUTHMETHOD method,
	IMA_INITIATOR_AUTHPARMS *pParms
)
{
	int fd;
	iscsi_chap_props_t  chap_p;

	if (pParms == NULL) {
		return (IMA_ERROR_INVALID_PARAMETER);
	}

	if (oid.objectType != IMA_OBJECT_TYPE_TARGET) {
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);
	}

	if (method != IMA_AUTHMETHOD_CHAP) {
		return (IMA_ERROR_INVALID_PARAMETER);
	}

	if ((fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) == -1) {
		syslog(LOG_USER|LOG_DEBUG, "Cannot open %s (%d)",
		    ISCSI_DRIVER_DEVCTL, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(void) memset(&chap_p, 0, sizeof (iscsi_chap_props_t));
	chap_p.c_vers = ISCSI_INTERFACE_VERSION;
	chap_p.c_oid = (uint32_t)oid.objectSequenceNumber;

	if (ioctl(fd, ISCSI_CHAP_GET, &chap_p) != 0) {
		syslog(LOG_USER|LOG_DEBUG,

		    "ISCSI_CHAP_GET ioctl failed, errno: %d",
		    errno);
		(void) close(fd);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	(void) memcpy(pParms->chapParms.name, chap_p.c_user,
	    chap_p.c_user_len);

	pParms->chapParms.nameLength = chap_p.c_user_len;
	(void) memcpy(pParms->chapParms.challengeSecret, chap_p.c_secret,
	    chap_p.c_secret_len);

	pParms->chapParms.challengeSecretLength = chap_p.c_secret_len;

	return (IMA_STATUS_SUCCESS);
}

IMA_API IMA_STATUS SUN_IMA_GetBootTargetName(
    IMA_NODE_NAME tgtName
)
{
	int fd;
	IMA_STATUS rtn;
	iscsi_boot_property_t bootProp;

	bootProp.tgt_name.n_name[0] = '\0';
	bootProp.tgt_chap.c_user[0] = '\0';
	tgtName[0] = L'\0';
	rtn = IMA_ERROR_UNEXPECTED_OS_ERROR;
	if ((fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) == -1) {
		syslog(LOG_USER|LOG_DEBUG, "Unable to open %s (%d)",
		    ISCSI_DRIVER_DEVCTL, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	if (ioctl(fd, ISCSI_BOOTPROP_GET, &bootProp) != 0) {
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_BOOTPROP_GET ioctl failed, errno: %d",
		    errno);
		(void) close(fd);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	if ((bootProp.tgt_name.n_name[0] != '\0') && (tgtName != NULL)) {
		if (mbstowcs(tgtName, (const char *)bootProp.tgt_name.n_name,
		    IMA_NODE_NAME_LEN) == (size_t)-1) {
			syslog(LOG_USER|LOG_DEBUG,
			    "ISCSI Target name covert to WCHAR fail");
			return (IMA_ERROR_UNEXPECTED_OS_ERROR);
		} else {
			rtn = IMA_STATUS_SUCCESS;
		}
	}

	return (rtn);
}

IMA_API IMA_STATUS SUN_IMA_GetBootTargetAuthParams(
    IMA_INITIATOR_AUTHPARMS *pTgtCHAP
)
{
	int fd;
	IMA_STATUS rtn;
	iscsi_boot_property_t bootProp;

	bootProp.tgt_name.n_name[0] = '\0';
	bootProp.tgt_chap.c_user[0] = '\0';
	bootProp.tgt_chap.c_secret[0] = '\0';
	rtn = IMA_ERROR_UNEXPECTED_OS_ERROR;
	if ((fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) == -1) {
		syslog(LOG_USER|LOG_DEBUG, "Unable to open %s (%d)",
		    ISCSI_DRIVER_DEVCTL, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	if (ioctl(fd, ISCSI_BOOTPROP_GET, &bootProp) != 0) {
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_BOOTPROP_GET ioctl failed, errno: %d",
		    errno);
		(void) close(fd);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	if (pTgtCHAP != NULL) {
		if (bootProp.tgt_chap.c_user[0] != '\0') {
			(void) memcpy(pTgtCHAP->chapParms.name,
			    bootProp.tgt_chap.c_user, ISCSI_MAX_NAME_LEN);
		} else {
			pTgtCHAP->chapParms.name[0] = '\0';
		}
		if (bootProp.tgt_chap.c_secret[0] != '\0') {
			(void) memcpy(pTgtCHAP->chapParms.challengeSecret,
			    bootProp.tgt_chap.c_secret, MAX_CHAP_SECRET_LEN);
		} else {
			pTgtCHAP->chapParms.challengeSecret[0] = '\0';
		}
		rtn = IMA_STATUS_SUCCESS;
	}
	return (rtn);
}

IMA_STATUS SUN_IMA_GetBootMpxio(
    IMA_BOOL *pMpxioEnabled
)
{
	int fd;
	iscsi_boot_property_t bootProp;

	bootProp.hba_mpxio_enabled = B_FALSE;
	*pMpxioEnabled = IMA_UNKNOWN;

	if ((fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) == -1) {
		syslog(LOG_USER|LOG_DEBUG, "Unable to open %s (%d)",
		    ISCSI_DRIVER_DEVCTL, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	if (ioctl(fd, ISCSI_BOOTPROP_GET, &bootProp) != 0) {
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_BOOTPROP_GET ioctl failed, errno: %d",
		    errno);
		(void) close(fd);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	if (bootProp.hba_mpxio_enabled) {
		*pMpxioEnabled = IMA_TRUE;
	} else {
		*pMpxioEnabled = IMA_FALSE;
	}

	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}

IMA_STATUS SUN_IMA_GetBootIscsi(
    IMA_BOOL *pIscsiBoot
)
{
	int fd;
	iscsi_boot_property_t bootProp;

	bootProp.iscsiboot = 0;
	*pIscsiBoot = 0;

	if ((fd = open(ISCSI_DRIVER_DEVCTL, O_RDONLY)) == -1) {
		syslog(LOG_USER|LOG_DEBUG, "Unable to open %s (%d)",
		    ISCSI_DRIVER_DEVCTL, errno);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	if (ioctl(fd, ISCSI_BOOTPROP_GET, &bootProp) != 0) {
		syslog(LOG_USER|LOG_DEBUG,
		    "ISCSI_BOOTPROP_GET ioctl failed, errno: %d",
		    errno);
		(void) close(fd);
		return (IMA_ERROR_UNEXPECTED_OS_ERROR);
	}

	*pIscsiBoot = bootProp.iscsiboot;

	(void) close(fd);
	return (IMA_STATUS_SUCCESS);
}
