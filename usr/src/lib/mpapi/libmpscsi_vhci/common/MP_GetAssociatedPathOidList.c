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

#include <syslog.h>
#include <errno.h>
#include <unistd.h>
#include <stropts.h>

#include "mp_utils.h"

#include <libdevinfo.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/stat.h>


static MP_STATUS doDevInfoStuffForIntPort(MP_OID oid)
{
	di_node_t root_node	= DI_NODE_NIL;

	di_node_t vh_node	= DI_NODE_NIL;
	di_node_t ph_node	= DI_NODE_NIL;
	di_node_t sv_node	= DI_NODE_NIL;


	di_path_t path = DI_PATH_NIL;

	struct stat buffer;

	int instNum = 0;
	int majorNum = 0;

	int oidInstNum = 0;
	int oidMajorNum = 0;

	int found = 0;
	int status = -1;


	char *pathName  = NULL;
	char *minorName = "c";

	char fullName[512];




	log(LOG_INFO, "doDevInfoStuffForIntPort()", " - enter");


	oidInstNum  = (int)MP_GET_INST_FROM_ID(oid.objectSequenceNumber);
	oidMajorNum = (int)MP_GET_MAJOR_FROM_ID(oid.objectSequenceNumber);


	root_node = di_init("/", DINFOCACHE);
	if (DI_NODE_NIL == root_node) {
		log(LOG_INFO, "doDevInfoStuffForIntPort()",
			" - di_init() failed");

		return (MP_STATUS_FAILED);
	}

	vh_node = di_vhci_first_node(root_node);

	while (DI_NODE_NIL != vh_node) {
		if ((di_driver_name(vh_node) != NULL) &&
		    (strncmp(di_driver_name(vh_node), "scsi_vhci", 9) == 0)) {
			ph_node = di_phci_first_node(vh_node);
			while (DI_NODE_NIL != ph_node) {

				instNum  = di_instance(ph_node);
				majorNum = di_driver_major(ph_node);

				if ((majorNum == oidMajorNum) &&
					(instNum == oidInstNum)) {

					log(LOG_INFO,
					    "doDevInfoStuffForIntPort()",
						"got a match");

					found = 1;

					break;
				}

				ph_node = di_phci_next_node(ph_node);
			}
		}

		if (found) {

			break;
		}

		vh_node = di_vhci_next_node(vh_node);
	}


	if (!found) {

		di_fini(root_node);

		log(LOG_INFO,
			"doDevInfoStuffForIntPort()",
			" - no match found, error exit");

		return (MP_STATUS_OBJECT_NOT_FOUND);
	}


	path = di_path_next(ph_node, DI_PATH_NIL);

	if (DI_PATH_NIL == path) {

		log(LOG_INFO, "doDevInfoStuffForIntPort()",
			" - path is DI_PATH_NIL");
	}

	while (DI_PATH_NIL != path) {

		sv_node = di_path_client_node(path);
		if (DI_NODE_NIL == sv_node) {

			log(LOG_INFO, "doDevInfoStuffForIntPort()",
				" - sv_node is DI_NODE_NIL");

		} else {

			pathName = di_devfs_path(sv_node);
			(void) snprintf(fullName, 511, "/devices%s:%s",
				pathName, minorName);

			(void) di_devfs_path_free(pathName);

			status = stat(fullName, &buffer);
			if (status < 0) {

				log(LOG_INFO,
					"doDevInfoStuffForIntPort()",
					" - stat() call failed: %d", status);

				log(LOG_INFO,
				    "doDevInfoStuffForIntPort()",
					" - errno: [%d].", errno);

				log(LOG_INFO,
				    "doDevInfoStuffForIntPort()",
					" - strerror(errno): [%s].",
					strerror(errno));


				di_fini(root_node);

				log(LOG_INFO,
					"doDevInfoStuffForIntPort()",
					" - error exit.");

				return (MP_STATUS_FAILED);
			}
		}

		path = di_path_next(ph_node, path);
	}


	di_fini(root_node);

	log(LOG_INFO, "doDevInfoStuffForIntPort()", " - exit");

	return (MP_STATUS_SUCCESS);
}


static MP_STATUS doDevInfoStuffForTargetPort(MP_OID oid)
{
	di_node_t root_node	= DI_NODE_NIL;
	di_node_t sv_node	= DI_NODE_NIL;
	di_node_t child_node = DI_NODE_NIL;

	di_path_t path = DI_PATH_NIL;

	int match = 0;
	int count = 0;
	int ioctlStatus = 0;
	int status = -1;

	struct stat buffer;

	char *pathName  = NULL;
	char *minorName = "c";

	char fullName[512];

	uchar_t *targetPort = NULL;

	mp_iocdata_t mp_ioctl;

	mp_target_port_prop_t tpInfo;

	MP_STATUS mpStatus = MP_STATUS_SUCCESS;


	log(LOG_INFO, "doDevInfoStuffForTargetPort()", " - enter");


	log(LOG_INFO, "doDevInfoStuffForTargetPort()",
		"oid.objectSequenceNumber = %llx",
		oid.objectSequenceNumber);

	(void) memset(&mp_ioctl, 0, sizeof (mp_iocdata_t));
	(void) memset(&tpInfo,   0, sizeof (mp_target_port_prop_t));

	mp_ioctl.mp_cmd  = MP_GET_TARGET_PORT_PROP;
	mp_ioctl.mp_ibuf = (caddr_t)&oid.objectSequenceNumber;
	mp_ioctl.mp_ilen = sizeof (oid.objectSequenceNumber);
	mp_ioctl.mp_obuf = (caddr_t)&tpInfo;
	mp_ioctl.mp_olen = sizeof (mp_target_port_prop_t);
	mp_ioctl.mp_xfer = MP_XFER_READ;

	log(LOG_INFO, "doDevInfoStuffForTargetPort()",
		"mp_ioctl.mp_cmd (MP_GET_TARGET_PORT_PROP) : %d",
		mp_ioctl.mp_cmd);

	ioctlStatus = ioctl(g_scsi_vhci_fd, MP_CMD, &mp_ioctl);

	log(LOG_INFO, "doDevInfoStuffForTargetPort()",
		" IOCTL call returned: %d", ioctlStatus);

	if (ioctlStatus < 0) {
		ioctlStatus = errno;
	}

	if (ioctlStatus != 0) {
		log(LOG_INFO, "doDevInfoStuffForTargetPort()",
			"IOCTL call failed.  IOCTL error is: %d",
			ioctlStatus);
		log(LOG_INFO, "doDevInfoStuffForTargetPort()",
			"IOCTL call failed.  IOCTL error is: %s",
			strerror(ioctlStatus));
		log(LOG_INFO, "doDevInfoStuffForTargetPort()",
			"IOCTL call failed.  mp_ioctl.mp_errno: %x",
			mp_ioctl.mp_errno);

		if (ENOTSUP == ioctlStatus) {
			mpStatus = MP_STATUS_UNSUPPORTED;
		} else if (0 == mp_ioctl.mp_errno) {
			mpStatus = MP_STATUS_FAILED;
		} else {
			mpStatus =
				getStatus4ErrorCode(mp_ioctl.mp_errno);
		}

		log(LOG_INFO, "doDevInfoStuffForTargetPort()",
			" - error exit");

		return (mpStatus);
	}

	root_node = di_init("/", DINFOCACHE);

	if (DI_NODE_NIL == root_node) {
		log(LOG_INFO, "doDevInfoStuffForTargetPort()",
			" - di_init() failed");

		return (MP_STATUS_FAILED);
	}


	sv_node = di_drv_first_node("scsi_vhci", root_node);
	if (DI_NODE_NIL == sv_node) {
		log(LOG_INFO, "doDevInfoStuffForTargetPort()",
			" - di_drv_first_node() failed");

		di_fini(root_node);

		return (MP_STATUS_FAILED);
	}

	child_node = di_child_node(sv_node);

	while (DI_NODE_NIL != child_node) {

		path = di_path_next(child_node, path);

		match = 0;

		while (DI_PATH_NIL != path) {

			count = di_path_prop_lookup_bytes(path,
						"target-port",
						&targetPort);

			if (NULL != targetPort) {

				if (0 == memcmp(targetPort,
						tpInfo.portName,
						count)) {

					match = 1;

					break;
				}
			}

			path = di_path_next(child_node, path);
		}

		if (match) {

			log(LOG_INFO, "doDevInfoStuffForTargetPort()",
				" - got a match");

			pathName = di_devfs_path(child_node);

			(void) snprintf(fullName, 511, "/devices%s:%s",
				pathName, minorName);

			(void) di_devfs_path_free(pathName);

			status = stat(fullName, &buffer);
			if (status < 0) {

				log(LOG_INFO,
					"doDevInfoStuffForTargetPort()",
					" - stat() call failed: %d", status);

				log(LOG_INFO,
				    "doDevInfoStuffForTargetPort()",
					" - errno: [%d].", errno);

				log(LOG_INFO,
				    "doDevInfoStuffForTargetPort()",
					" - strerror(errno): [%s].",
					strerror(errno));


				di_fini(root_node);

				log(LOG_INFO,
					"doDevInfoStuffForTargetPort()",
					" - error exit.");

				return (MP_STATUS_FAILED);
			}
		}

		child_node = di_sibling_node(child_node);
	}


	di_fini(root_node);

	log(LOG_INFO, "doDevInfoStuffForTargetPort()", " - exit");

	return (MP_STATUS_SUCCESS);
}



MP_STATUS
MP_GetAssociatedPathOidList(MP_OID oid, MP_OID_LIST **ppList)
{
	mp_iocdata_t mp_ioctl;

	uint64_t *objList = NULL;

	int numOBJ = 0;
	int i = 0;
	int ioctlStatus = 0;

	MP_STATUS mpStatus = MP_STATUS_SUCCESS;

	int request = MP_GET_PATH_LIST_FOR_MP_LU;


	log(LOG_INFO, "MP_GetAssociatedPathOidList()", " - enter");


	log(LOG_INFO, "MP_GetAssociatedPathOidList()",
		" set default request to MP_GET_PATH_LIST_FOR_MP_LU");

	log(LOG_INFO, "MP_GetAssociatedPathOidList()",
		"oid.objectSequenceNumber = %llx",
		oid.objectSequenceNumber);


	if (g_scsi_vhci_fd < 0) {
		log(LOG_INFO, "MP_GetAssociatedPathOidList()",
		    "invalid driver file handle");
		log(LOG_INFO, "MP_GetAssociatedPathOidList()", " - error exit");
		return (MP_STATUS_FAILED);
	}

	if (MP_OBJECT_TYPE_INITIATOR_PORT == oid.objectType) {
		request = MP_GET_PATH_LIST_FOR_INIT_PORT;
		log(LOG_INFO, "MP_GetAssociatedPathOidList()",
			" set request to MP_GET_PATH_LIST_FOR_INIT_PORT");

		mpStatus = doDevInfoStuffForIntPort(oid);
		if (MP_STATUS_SUCCESS != mpStatus) {

			return (mpStatus);
		}
	} else if (MP_OBJECT_TYPE_TARGET_PORT == oid.objectType) {
		request = MP_GET_PATH_LIST_FOR_TARGET_PORT;
		log(LOG_INFO, "MP_GetAssociatedPathOidList()",
			" set request to MP_GET_PATH_LIST_FOR_TARGET_PORT");

		mpStatus = doDevInfoStuffForTargetPort(oid);
		if (MP_STATUS_SUCCESS != mpStatus) {

			return (mpStatus);
		}
	}

	objList = (uint64_t *)calloc(1, DEFAULT_BUFFER_SIZE_PATH_LIST);
	if (NULL == objList) {
		log(LOG_INFO, "MP_GetAssociatedPathOidList()",
			"no memory for objList(1)");
		log(LOG_INFO, "MP_GetAssociatedPathOidList()",
			" - error exit");
		return (MP_STATUS_INSUFFICIENT_MEMORY);
	}

	(void) memset(&mp_ioctl, 0, sizeof (mp_iocdata_t));

	mp_ioctl.mp_cmd  = request;
	mp_ioctl.mp_ibuf = (caddr_t)&oid.objectSequenceNumber;
	mp_ioctl.mp_ilen = sizeof (oid.objectSequenceNumber);
	mp_ioctl.mp_obuf = (caddr_t)objList;
	mp_ioctl.mp_olen = DEFAULT_BUFFER_SIZE_PATH_LIST;
	mp_ioctl.mp_xfer = MP_XFER_READ;

	log(LOG_INFO, "MP_GetAssociatedPathOidList()",
		"mp_ioctl.mp_cmd : %d", mp_ioctl.mp_cmd);
	log(LOG_INFO, "MP_GetAssociatedPathOidList()",
		"mp_ioctl.mp_obuf: %x", mp_ioctl.mp_obuf);
	log(LOG_INFO, "MP_GetAssociatedPathOidList()",
		"mp_ioctl.mp_olen: %d", mp_ioctl.mp_olen);
	log(LOG_INFO, "MP_GetAssociatedPathOidList()",
		"mp_ioctl.mp_xfer: %d (MP_XFER_READ)",
		mp_ioctl.mp_xfer);

	ioctlStatus = ioctl(g_scsi_vhci_fd, MP_CMD, &mp_ioctl);
	log(LOG_INFO, "MP_GetAssociatedPathOidList()",
		"ioctl call returned ioctlStatus: %d",
		ioctlStatus);

	if (ioctlStatus < 0) {
		ioctlStatus = errno;
	}

	if ((ioctlStatus != 0) && (MP_MORE_DATA != mp_ioctl.mp_errno)) {

		log(LOG_INFO, "MP_GetAssociatedPathOidList()",
		    "IOCTL call failed.  IOCTL error is: %d",
			ioctlStatus);
		log(LOG_INFO, "MP_GetAssociatedPathOidList()",
		    "IOCTL call failed.  IOCTL error is: %s",
			strerror(ioctlStatus));
		log(LOG_INFO, "MP_GetAssociatedPathOidList()",
		    "IOCTL call failed.  mp_ioctl.mp_errno: %x",
			mp_ioctl.mp_errno);


		free(objList);

		if (ENOTSUP == ioctlStatus) {
			mpStatus = MP_STATUS_UNSUPPORTED;
		} else if (0 == mp_ioctl.mp_errno) {
			mpStatus = MP_STATUS_FAILED;
		} else {
			mpStatus = getStatus4ErrorCode(mp_ioctl.mp_errno);
		}

		log(LOG_INFO, "MP_GetAssociatedPathOidList()",
			" - error exit");

		return (mpStatus);
	}

	log(LOG_INFO, "MP_GetAssociatedPathOidList()",
		" - mp_ioctl.mp_alen : %d",
		mp_ioctl.mp_alen);
	log(LOG_INFO, "MP_GetAssociatedPathOidList()",
		" - sizeof (uint64_t): %d",
		sizeof (uint64_t));

	numOBJ = mp_ioctl.mp_alen / sizeof (uint64_t);
	log(LOG_INFO, "MP_GetAssociatedPathOidList()",
	    "Length of list: %d", numOBJ);

	if (numOBJ < 1) {
		log(LOG_INFO, "MP_GetAssociatedPathOidList()",
			"driver returned empty list.");

		free(objList);

		*ppList = createOidList(1);
		if (NULL == *ppList) {
			log(LOG_INFO,
				"MP_GetAssociatedPathOidList()",
				"no memory for MP_OID_LIST");
			log(LOG_INFO,
				"MP_GetAssociatedPathOidList()",
				" - error exit");
			return (MP_STATUS_INSUFFICIENT_MEMORY);
		}

		return (MP_STATUS_SUCCESS);
	}

	if (mp_ioctl.mp_alen > DEFAULT_BUFFER_SIZE_PATH_LIST) {

		log(LOG_INFO, "MP_GetAssociatedPathOidList()",
			"buffer size too small, need : %d",
			mp_ioctl.mp_alen);

		free(objList);

		objList = (uint64_t *)calloc(1, numOBJ * sizeof (uint64_t));
		if (NULL == objList) {
			log(LOG_INFO, "MP_GetAssociatedPathOidList()",
				"no memory for objList(2)");
			log(LOG_INFO, "MP_GetAssociatedPathOidList()",
				" - error exit");
			return (MP_STATUS_INSUFFICIENT_MEMORY);
		}

		(void) memset(&mp_ioctl, 0, sizeof (mp_iocdata_t));

		mp_ioctl.mp_cmd  = request;
		mp_ioctl.mp_ibuf = (caddr_t)&oid.objectSequenceNumber;
		mp_ioctl.mp_ilen = sizeof (oid.objectSequenceNumber);
		mp_ioctl.mp_obuf = (caddr_t)objList;
		mp_ioctl.mp_olen = numOBJ * sizeof (uint64_t);
		mp_ioctl.mp_xfer = MP_XFER_READ;

		log(LOG_INFO, "MP_GetAssociatedPathOidList()",
			"mp_ioctl.mp_cmd : %d", mp_ioctl.mp_cmd);
		log(LOG_INFO, "MP_GetAssociatedPathOidList()",
			"mp_ioctl.mp_obuf: %x", mp_ioctl.mp_obuf);
		log(LOG_INFO, "MP_GetAssociatedPathOidList()",
			"mp_ioctl.mp_olen: %d", mp_ioctl.mp_olen);
		log(LOG_INFO, "MP_GetAssociatedPathOidList()",
			"mp_ioctl.mp_xfer: %d (MP_XFER_READ)",
			mp_ioctl.mp_xfer);


		ioctlStatus = ioctl(g_scsi_vhci_fd, MP_CMD, &mp_ioctl);
		log(LOG_INFO, "MP_GetAssociatedPathOidList()",
			"ioctl call returned ioctlStatus: %d",
			ioctlStatus);

		if (ioctlStatus < 0) {
			ioctlStatus = errno;
		}

		if (ioctlStatus != 0) {

			log(LOG_INFO, "MP_GetAssociatedPathOidList()",
				"IOCTL call failed.  IOCTL error is: %d",
				ioctlStatus);
			log(LOG_INFO, "MP_GetAssociatedPathOidList()",
				"IOCTL call failed.  IOCTL error is: %s",
				strerror(ioctlStatus));
			log(LOG_INFO, "MP_GetAssociatedPathOidList()",
				"IOCTL call failed.  mp_ioctl.mp_errno: %x",
				mp_ioctl.mp_errno);


			free(objList);

			if (ENOTSUP == ioctlStatus) {
				mpStatus = MP_STATUS_UNSUPPORTED;
			} else if (0 == mp_ioctl.mp_errno) {
				mpStatus = MP_STATUS_FAILED;
			} else {
				mpStatus =
					getStatus4ErrorCode(mp_ioctl.mp_errno);
			}

			log(LOG_INFO, "MP_GetAssociatedPathOidList()",
				" - error exit");

			return (mpStatus);
		}
	}


	*ppList = createOidList(numOBJ);
	if (NULL == *ppList) {
		log(LOG_INFO, "MP_GetAssociatedPathOidList()",
			"no memory for *ppList");
		free(objList);
		log(LOG_INFO, "MP_GetAssociatedPathOidList()",
			" - error exit");
		return (MP_STATUS_INSUFFICIENT_MEMORY);
	}

	(*ppList)->oidCount = numOBJ;

	log(LOG_INFO, "MP_GetAssociatedPathOidList()",
		"(*ppList)->oidCount = %d",
		(*ppList)->oidCount);

	for (i = 0; i < numOBJ; i++) {
		(*ppList)->oids[i].objectType = MP_OBJECT_TYPE_PATH_LU;
		(*ppList)->oids[i].ownerId = g_pluginOwnerID;
		(*ppList)->oids[i].objectSequenceNumber = objList[i];

		log(LOG_INFO, "MP_GetAssociatedPathOidList()",
			"(*ppList)->oids[%d].objectType           = %d",
			i, (*ppList)->oids[i].objectType);
		log(LOG_INFO, "MP_GetAssociatedPathOidList()",
			"(*ppList)->oids[%d].ownerId              = %d",
			i, (*ppList)->oids[i].ownerId);
		log(LOG_INFO, "MP_GetAssociatedPathOidList()",
			"(*ppList)->oids[%d].objectSequenceNumber = %llx",
			i, (*ppList)->oids[i].objectSequenceNumber);
	}

	free(objList);


	log(LOG_INFO, "MP_GetAssociatedPathOidList()", " - exit");

	return (MP_STATUS_SUCCESS);
}
