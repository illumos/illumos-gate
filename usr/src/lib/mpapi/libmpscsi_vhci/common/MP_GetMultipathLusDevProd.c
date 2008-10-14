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


static int getOidList(di_node_t root_node,
			MP_OID_LIST *pOidList,
			char *pProductID,
			char *pVendorID)
{
	int numNodes = 0;
	int pidSize = 0;
	int vidSize = 0;

	int haveList = (NULL != pOidList);

	char *pid = NULL;
	char *vid = NULL;

	di_node_t sv_node	= DI_NODE_NIL;
	di_node_t sv_child_node	= DI_NODE_NIL;

	MP_UINT64 nodeInstance	= 0;


	log(LOG_INFO, "getOidList()", " - enter");


	sv_node = di_drv_first_node("scsi_vhci", root_node);
	if (DI_NODE_NIL == sv_node) {
		log(LOG_INFO, "getOidList()",
			" - di_drv_first_node() failed");

		return (-1);
	}


	sv_child_node = di_child_node(sv_node);

	while (DI_NODE_NIL != sv_child_node) {

		(void) di_prop_lookup_strings(DDI_DEV_T_ANY,
			sv_child_node,
			"inquiry-product-id",
			&pid);

		pidSize = strlen(pid);

		(void) di_prop_lookup_strings(DDI_DEV_T_ANY,
			sv_child_node,
			"inquiry-vendor-id",
			&vid);

		vidSize = strlen(vid);

		if ((0 == strncmp(pProductID, pid, pidSize)) &&
		    (0 == strncmp(pVendorID, vid, vidSize))) {

				if (haveList) {

					nodeInstance =
						(MP_UINT64)
					    di_instance(sv_child_node);

					if (numNodes < pOidList->oidCount) {

						pOidList->oids[numNodes].
							objectType =
						MP_OBJECT_TYPE_MULTIPATH_LU;

						pOidList->oids[numNodes].
							ownerId =
							g_pluginOwnerID;

						pOidList->oids[numNodes].
							objectSequenceNumber =
							nodeInstance;
					}
				}

			++numNodes;
		}

		sv_child_node = di_sibling_node(sv_child_node);
	}


	log(LOG_INFO,
		"getOidList()",
		" - numNodes: %d",
		numNodes);


	log(LOG_INFO, "getOidList()", " - exit");

	return (numNodes);
}


MP_STATUS
MP_GetMultipathLusDevProd(MP_OID oid, MP_OID_LIST **ppList)
{
	di_node_t root_node	= DI_NODE_NIL;

	MP_STATUS mpStatus	= MP_STATUS_SUCCESS;

	int numNodes = 0;
	int ioctlStatus = 0;
	int i = 0;

	mp_iocdata_t		mp_ioctl;
	mp_dev_prod_prop_t	devProdInfo;

	char inqProductID[256];
	char inqVendorID[256];



	log(LOG_INFO, "MP_GetMultipathLusDevProd()", " - enter");



	log(LOG_INFO, "MP_GetMultipathLusDevProd()",
		"oid.objectSequenceNumber = %llx",
		oid.objectSequenceNumber);

	if (g_scsi_vhci_fd < 0) {
		log(LOG_INFO, "MP_GetMultipathLusDevProd()",
		    "invalid driver file handle");
		log(LOG_INFO, "MP_GetMultipathLusDevProd",
			" - error exit");
		return (MP_STATUS_FAILED);
	}

	(void) memset(&mp_ioctl, 0, sizeof (mp_iocdata_t));
	(void) memset(&devProdInfo, 0, sizeof (mp_dev_prod_prop_t));

	mp_ioctl.mp_cmd  = MP_GET_DEV_PROD_PROP;
	mp_ioctl.mp_ibuf = (caddr_t)&oid.objectSequenceNumber;
	mp_ioctl.mp_ilen = sizeof (oid.objectSequenceNumber);
	mp_ioctl.mp_obuf = (caddr_t)&devProdInfo;
	mp_ioctl.mp_olen = sizeof (mp_dev_prod_prop_t);
	mp_ioctl.mp_xfer = MP_XFER_READ;

	ioctlStatus = ioctl(g_scsi_vhci_fd, MP_CMD, &mp_ioctl);

	log(LOG_INFO, "MP_GetMultipathLusDevProd()",
		" IOCTL call returned: %d", ioctlStatus);

	if (ioctlStatus < 0) {
		ioctlStatus = errno;
	}

	if (ioctlStatus != 0) {
		log(LOG_INFO, "MP_GetMultipathLusDevProd()",
		    "IOCTL call failed.  IOCTL error is: %d",
			ioctlStatus);
		log(LOG_INFO, "MP_GetMultipathLusDevProd()",
		    "IOCTL call failed.  IOCTL error is: %s",
			strerror(ioctlStatus));
		log(LOG_INFO, "MP_GetMultipathLusDevProd()",
		    "IOCTL call failed.  mp_ioctl.mp_errno: %x",
			mp_ioctl.mp_errno);

		if (ENOTSUP == ioctlStatus) {
			mpStatus = MP_STATUS_UNSUPPORTED;
		} else if (0 == mp_ioctl.mp_errno) {
			mpStatus = MP_STATUS_FAILED;
		} else {
			mpStatus = getStatus4ErrorCode(mp_ioctl.mp_errno);
		}

		log(LOG_INFO, "MP_GetMultipathLusDevProd()",
			" - error exit");

		return (mpStatus);
	}

	(void) strncpy(inqProductID,
			devProdInfo.prodInfo.product,
			sizeof (devProdInfo.prodInfo.product));

	(void) strncpy(inqVendorID,
			devProdInfo.prodInfo.vendor,
			sizeof (devProdInfo.prodInfo.vendor));

	log(LOG_INFO, "MP_GetMultipathLusDevProd()",
		" - inqProductID:  [%s]", inqProductID);
	log(LOG_INFO, "MP_GetMultipathLusDevProd()",
		" - inqVendorID:   [%s]", inqVendorID);


	root_node = di_init("/", DINFOCACHE);
	if (DI_NODE_NIL == root_node) {
		log(LOG_INFO, "MP_GetMultipathLusDevProd()",
			" - di_init() failed");

		log(LOG_INFO, "MP_GetMultipathLusDevProd()",
			" - error exit");

		return (MP_STATUS_FAILED);
	}

	numNodes = getOidList(root_node,
				NULL,
				inqProductID,
				inqVendorID);

	if (numNodes < 0) {

		log(LOG_INFO,
			"MP_GetMultipathLusDevProd()",
			" - unable to get OID list.");

		log(LOG_INFO, "MP_GetMultipathLusDevProd()",
			" - error exit");

		di_fini(root_node);

		return (MP_STATUS_FAILED);
	}


	if (0 == numNodes) {

		*ppList = createOidList(1);
		if (NULL == *ppList) {

			log(LOG_INFO,
				"MP_GetMultipathLusDevProd()",
				" - unable to create OID list.");

			log(LOG_INFO, "MP_GetMultipathLusDevProd()",
				" - error exit");

			di_fini(root_node);

			return (MP_STATUS_INSUFFICIENT_MEMORY);
		}

		(*ppList)->oids[0].objectType =
			MP_OBJECT_TYPE_MULTIPATH_LU;

		(*ppList)->oids[0].ownerId =
			g_pluginOwnerID;

		log(LOG_INFO, "MP_GetMultipathLusDevProd()",
			" - returning empty list.");

		return (MP_STATUS_SUCCESS);
	}

	*ppList = createOidList(numNodes);
	if (NULL == *ppList) {
		log(LOG_INFO, "MP_GetMultipathLusDevProd()",
			"no memory for *ppList");
		log(LOG_INFO, "MP_GetMultipathLusDevProd()",
			" - error exit");
		return (MP_STATUS_INSUFFICIENT_MEMORY);
	}

	(*ppList)->oidCount = numNodes;

	numNodes = getOidList(root_node,
				*ppList,
				inqProductID,
				inqVendorID);


	for (i = 0; i < (*ppList)->oidCount; i++) {

		log(LOG_INFO, "MP_GetMultipathLusDevProd()",
			"(*ppList)->oids[%d].objectType           = %d",
			i, (*ppList)->oids[i].objectType);
		log(LOG_INFO, "MP_GetMultipathLusDevProd()",
			"(*ppList)->oids[%d].ownerId              = %d",
			i, (*ppList)->oids[i].ownerId);
		log(LOG_INFO, "MP_GetMultipathLusDevProd()",
			"(*ppList)->oids[%d].objectSequenceNumber = %llx",
			i, (*ppList)->oids[i].objectSequenceNumber);
	}


	di_fini(root_node);

	log(LOG_INFO, "MP_GetMultipathLusDevProd()", " - exit");

	return (MP_STATUS_SUCCESS);

}
