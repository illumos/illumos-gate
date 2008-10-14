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

#include "mp_utils.h"

#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <unistd.h>
#include <stropts.h>



MP_STATUS
MP_GetPluginPropertiesPlugin(MP_PLUGIN_PROPERTIES *pProps)
{
	mp_iocdata_t		mp_ioctl;
	mp_driver_prop_t	driverInfo;

	int ioctlStatus = 0;
	MP_STATUS mpStatus = MP_STATUS_SUCCESS;

	log(LOG_INFO, "MP_GetPluginPropertiesPlugin()", " - enter");

	if (g_scsi_vhci_fd < 0) {
		log(LOG_INFO, "MP_GetPluginPropertiesPlugin()",
		    "invalid driver file handle");
		return (MP_STATUS_FAILED);
	}

	(void) memset(pProps, 0, sizeof (MP_PLUGIN_PROPERTIES));
	(void) memset(&mp_ioctl, 0, sizeof (mp_iocdata_t));
	(void) memset(&driverInfo, 0, sizeof (mp_driver_prop_t));

	mp_ioctl.mp_cmd  = MP_GET_DRIVER_PROP;
	mp_ioctl.mp_obuf = (caddr_t)&driverInfo;
	mp_ioctl.mp_olen = sizeof (mp_driver_prop_t);
	mp_ioctl.mp_xfer = MP_XFER_READ;

	ioctlStatus = ioctl(g_scsi_vhci_fd, MP_CMD, &mp_ioctl);

	log(LOG_INFO, "MP_GetPluginPropertiesPlugin()",
		" IOCTL call returned: %d", ioctlStatus);

	if (ioctlStatus < 0) {
		ioctlStatus = errno;
	}

	if (ioctlStatus != 0) {
		log(LOG_INFO, "MP_GetPluginPropertiesPlugin()",
		    "IOCTL call failed.  IOCTL error is: %d",
			ioctlStatus);
		log(LOG_INFO, "MP_GetPluginPropertiesPlugin()",
		    "IOCTL call failed.  IOCTL error is: %s",
			strerror(ioctlStatus));
		log(LOG_INFO, "MP_GetPluginPropertiesPlugin()",
		    "IOCTL call failed.  mp_ioctl.mp_errno: %x",
			mp_ioctl.mp_errno);

		if (ENOTSUP == ioctlStatus) {
			mpStatus = MP_STATUS_UNSUPPORTED;
		} else if (0 == mp_ioctl.mp_errno) {
			mpStatus = MP_STATUS_FAILED;
		} else {
			mpStatus = getStatus4ErrorCode(mp_ioctl.mp_errno);
		}

		log(LOG_INFO, "MP_GetPluginPropertiesPlugin()",
			" - error exit");

		return (mpStatus);
	}

	(void) wcsncpy(pProps->vendor, L"Sun Microsystems", 255);

	pProps->autoFailbackSupport = driverInfo.autoFailbackSupport;
	pProps->autoProbingSupport  = driverInfo.autoProbingSupport;

#ifdef BUILD_TIME
	(void) mbstowcs(pProps->buildTime, BUILD_TIME, 256);
#endif

	pProps->canOverridePaths = driverInfo.canOverridePaths;
	pProps->canSetTPGAccess  = driverInfo.canSetTPGAccess;
	pProps->currentFailbackPollingRate =
		driverInfo.currentFailbackPollingRate;
	pProps->currentProbingPollingRate  =
		driverInfo.currentProbingPollingRate;
	pProps->defaultloadBalanceType =
		driverInfo.defaultLoadBalanceType;

	(void) strncpy(pProps->deviceFileNamespace,
	    driverInfo.deviceFileNamespace, 255);

	(void) strncpy(pProps->driverName, "scsi_vhci", 255);

	(void) wcsncpy(pProps->driverVendor, L"Sun Microsystems", 255);

	(void) mbstowcs(pProps->driverVersion, driverInfo.driverVersion, 256);

	pProps->exposesPathDeviceFiles = driverInfo.exposesPathDeviceFiles;
	pProps->failbackPollingRateMax = driverInfo.failbackPollingRateMax;

	(void) strncpy(pProps->fileName, "libmpscsi_vhci.so", 255);

	(void) wcsncpy(pProps->implementationVersion, L"1.0.0.0", 255);

	pProps->maximumWeight = driverInfo.maximumWeight;
	pProps->onlySupportsSpecifiedProducts =
		driverInfo.onlySupportsSpecifiedProducts;

	pProps->pluginAutoFailbackEnabled = driverInfo.autoFailbackEnabled;
	pProps->pluginAutoProbingEnabled  = driverInfo.autoProbingEnabled;

	pProps->probingPollingRateMax = driverInfo.probingPollingRateMax;

	pProps->supportedLoadBalanceTypes =
		driverInfo.supportedLoadBalanceTypes;
	pProps->supportedMpVersion = MP_LIBVERSION;


	log(LOG_INFO, "MP_GetPluginPropertiesPlugin()", " - exit");

	return (MP_STATUS_SUCCESS);
}
