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
 * Copyright 2008 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <unistd.h>
#include <stropts.h>

#include <libdevinfo.h>

#include "mp_utils.h"


typedef struct walk_devlink {
	char *path;
	size_t len;
	char **linkpp;
} walk_devlink_t;



static int
get_devlink(di_devlink_t devlink, void *arg) {

	walk_devlink_t *warg = (walk_devlink_t *)arg;


	log(LOG_INFO, "get_devlink()", " - enter");


	*(warg->linkpp) = strdup(di_devlink_path(devlink));


	log(LOG_INFO, "get_devlink()", " - exit");

	return (DI_WALK_TERMINATE);
}


char
*getDeviceFileName(MP_UINT64 instanceNum)
{
	char *deviceFileName = NULL;

	di_node_t root_node = DI_NODE_NIL;
	di_node_t cur_node  = DI_NODE_NIL;

	MP_UINT64 nodeInstance = 0;

	char *pathName  = NULL;
	char *minorName = "c,raw";
	char *devLink   = NULL;

	char fullName[512];

	walk_devlink_t warg;
	di_devlink_handle_t dlHandle = NULL;

	int diStatus = 0;


	log(LOG_INFO, "getDeviceFileName()", " - enter");

	log(LOG_INFO, "getDeviceFileName()",
		" - instanceNum: %llx",
		instanceNum);

	root_node = di_init("/", DINFOCACHE);
	if (DI_NODE_NIL == root_node) {
		log(LOG_INFO, "MP_GetMultipathLusPlugin()",
			" - $ERROR, di_init() failed");

		return (NULL);
	}


	cur_node = di_drv_first_node("scsi_vhci", root_node);
	if (DI_NODE_NIL == cur_node) {
		log(LOG_INFO, "getDeviceFileName()",
			" - $ERROR, di_drv_first_node() failed");

		di_fini(root_node);

		return (NULL);
	}


	cur_node = di_child_node(cur_node);

	while (DI_NODE_NIL != cur_node) {

		nodeInstance =
		(MP_UINT64)di_instance(cur_node);

		if (nodeInstance == instanceNum) {

			log(LOG_INFO, "getDeviceFileName()",
				" - found node.");

			break;
		}

		cur_node = di_sibling_node(cur_node);
	}

	if (DI_NODE_NIL != cur_node) {

		dlHandle = di_devlink_init(NULL, 0);
		if (NULL == dlHandle) {
		    log(LOG_INFO, "getDeviceFileName()",
			    " - $ERROR, di_devlink_init() failed.");

		    di_fini(root_node);

		    return (NULL);
		}

		pathName = di_devfs_path(cur_node);

		(void) snprintf(fullName, 511, "%s:%s", pathName, minorName);

		log(LOG_INFO, "getDeviceFileName()",
			" - fullName: {%s]", fullName);

		(void) memset(&warg, 0, sizeof (walk_devlink_t));

		devLink  = NULL;
		warg.linkpp = &devLink;

		diStatus = di_devlink_walk(dlHandle,
				NULL,
				fullName,
				DI_PRIMARY_LINK,
				(void *)&warg,
				get_devlink);

		if (diStatus != 0) {

			log(LOG_INFO, "getDeviceFileName()",
			    "diStatus: %d", diStatus);

			if (diStatus < 0) {
				diStatus = errno;
			}

			log(LOG_INFO, "getDeviceFileName()",
			    "diStatus: %d", diStatus);

			log(LOG_INFO, "getDeviceFileName()",
			    "strerror(diStatus): %s", strerror(diStatus));
		}

		if (NULL != devLink) {

			deviceFileName =
				(char *)calloc(1, strlen(devLink) + 1);

			(void) strncpy(deviceFileName, devLink,
			    strlen(devLink));

		} else {

			log(LOG_INFO, "getDeviceFileName()",
				" - $ERROR, devLink is NULL.");

			deviceFileName =
				(char *)calloc(1, 256);

			(void) strncpy(deviceFileName, pathName, 255);
		}

		di_devfs_path_free(pathName);

		(void) di_devlink_fini(&dlHandle);

	}


	di_fini(root_node);


	log(LOG_INFO, "getDeviceFileName()", " - exit");

	return (deviceFileName);
}



MP_STATUS
MP_GetMPLogicalUnitProperties(MP_OID oid,
				MP_MULTIPATH_LOGICAL_UNIT_PROPERTIES *pProps)
{
	mp_iocdata_t		mp_ioctl;
	mp_logical_unit_prop_t	luInfo;

	MP_OID overridePathOID;

	int ioctlStatus = 0;

	int vendorLength   = 0;
	int productLength  = 0;
	int revisionLength = 0;

	char *deviceFileName = NULL;


	MP_STATUS mpStatus = MP_STATUS_SUCCESS;


	log(LOG_INFO, "MP_GetMPLogicalUnitProperties()", " - enter");


	log(LOG_INFO, "MP_GetMPLogicalUnitProperties()",
		"oid.objectSequenceNumber = %llx",
		oid.objectSequenceNumber);

	if (g_scsi_vhci_fd < 0) {
		log(LOG_INFO, "MP_GetMPLogicalUnitProperties()",
			"invalid driver file handle");
		log(LOG_INFO, "MP_GetMPLogicalUnitProperties()",
			" - error exit");
		return (MP_STATUS_FAILED);
	}

	(void) memset(&mp_ioctl, 0, sizeof (mp_iocdata_t));
	(void) memset(&luInfo,   0, sizeof (mp_logical_unit_prop_t));

	mp_ioctl.mp_cmd  = MP_GET_LU_PROP;
	mp_ioctl.mp_ibuf = (caddr_t)&oid.objectSequenceNumber;
	mp_ioctl.mp_ilen = sizeof (oid.objectSequenceNumber);
	mp_ioctl.mp_obuf = (caddr_t)&luInfo;
	mp_ioctl.mp_olen = sizeof (mp_logical_unit_prop_t);
	mp_ioctl.mp_xfer = MP_XFER_READ;

	ioctlStatus = ioctl(g_scsi_vhci_fd, MP_CMD, &mp_ioctl);

	log(LOG_INFO, "MP_GetMPLogicalUnitProperties()",
		" IOCTL call returned: %d", ioctlStatus);

	if (ioctlStatus < 0) {
		ioctlStatus = errno;
	}

	if (ioctlStatus != 0) {
		log(LOG_INFO, "MP_GetMPLogicalUnitProperties()",
			"IOCTL call failed.  IOCTL error is: %d",
			ioctlStatus);
		log(LOG_INFO, "MP_GetMPLogicalUnitProperties()",
			"IOCTL call failed.  IOCTL error is: %s",
			strerror(ioctlStatus));
		log(LOG_INFO, "MP_GetMPLogicalUnitProperties()",
			"IOCTL call failed.  mp_ioctl.mp_errno: %x",
			mp_ioctl.mp_errno);

		if (ENOTSUP == ioctlStatus) {
			mpStatus = MP_STATUS_UNSUPPORTED;
		} else if (0 == mp_ioctl.mp_errno) {
			mpStatus = MP_STATUS_FAILED;
		} else {
			mpStatus = getStatus4ErrorCode(mp_ioctl.mp_errno);
		}

		log(LOG_INFO, "MP_GetMPLogicalUnitProperties()",
			" - error exit");

		return (mpStatus);
	}

	(void) memset(pProps, 0, sizeof (MP_MULTIPATH_LOGICAL_UNIT_PROPERTIES));

	pProps->asymmetric = luInfo.asymmetric;
	pProps->autoFailbackEnabled = luInfo.autoFailbackEnabled;
	pProps->autoProbingEnabled = luInfo.autoProbingEnabled;
	pProps->currentFailbackPollingRate = luInfo.currentFailBackPollingRate;
	pProps->currentLoadBalanceType = luInfo.currentLoadBalanceType;
	pProps->currentProbingPollingRate = luInfo.currentProbingPollingRate;


	deviceFileName = getDeviceFileName(oid.objectSequenceNumber);

	if (NULL != deviceFileName) {

		log(LOG_INFO, "MP_GetMPLogicalUnitProperties()",
			"deviceFileName: %s",
			deviceFileName);

		(void) strncpy(pProps->deviceFileName,
				deviceFileName,
				sizeof (pProps->deviceFileName) - 1);

		free(deviceFileName);
	}

	pProps->failbackPollingRateMax = luInfo.failbackPollingRateMax;
	pProps->logicalUnitGroupID = luInfo.luGroupID;

	(void) strncpy(pProps->name, luInfo.name, sizeof (pProps->name) - 1);

	pProps->nameType = luInfo.nameType;

	overridePathOID.objectSequenceNumber = luInfo.overridePathID;
	overridePathOID.objectType = MP_OBJECT_TYPE_PATH_LU;
	overridePathOID.ownerId = g_pluginOwnerID;
	(void) memcpy(&pProps->overridePath, &overridePathOID, sizeof (MP_OID));

	pProps->probingPollingRateMax = luInfo.probingPollingRateMax;


	vendorLength   = sizeof (pProps->vendor);
	productLength  = sizeof (pProps->product);
	revisionLength = sizeof (pProps->revision);

	(void) strncpy(pProps->vendor,
			luInfo.prodInfo.vendor,
			vendorLength);

	(void) strncpy(pProps->product,
			luInfo.prodInfo.product,
			productLength);

	(void) strncpy(pProps->revision,
			luInfo.prodInfo.revision,
			revisionLength);

	log(LOG_INFO, "MP_GetMPLogicalUnitProperties()", " - exit");

	return (MP_STATUS_SUCCESS);
}
