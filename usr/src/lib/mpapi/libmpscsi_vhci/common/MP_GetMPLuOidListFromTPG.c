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

#include <errno.h>
#include <unistd.h>
#include <stropts.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <libdevinfo.h>
#include <sys/stat.h>

#include "mp_utils.h"


/*
 *	The plugin library will call MP_CMD ioctl with
 *	MP_GET_TARGET_PORT_LIST_FOR_TPG subcommand.
 *	For each target port, the plugin will get the target port name property.
 *
 *	A scsi_vhci device with pathinfo containing matching target port name
 *	may potentially be associated with the given TPG.
 *	The plugin library will check the TPG list for qualifying scsi_vhci
 *	devices and find a matching TPG id.
 *
 *	An rfe was filed against MDI to
 *	refresh DINFOCACHE snapshot for pathinfo update.
 */





/*
 *	Returns MP_TRUE if the ID found in the dev info snapshot matches the ID
 *	provided by the schi_vhci driver.
 */

static int checkTPGList(MP_UINT32 tpgID, int inst_num)
{
	int tpg = 0;
	int status = MP_FALSE;

	MP_OID luOID;

	MP_OID_LIST *ppList = NULL;
	MP_STATUS mpStatus = MP_STATUS_SUCCESS;

	MP_TARGET_PORT_GROUP_PROPERTIES tpgProps;



	log(LOG_INFO, "checkTPGList()", " - enter");


	luOID.objectSequenceNumber = (MP_UINT64)inst_num;
	luOID.objectType = MP_OBJECT_TYPE_MULTIPATH_LU;
	luOID.ownerId = g_pluginOwnerID;

	mpStatus = getAssociatedTPGOidList(luOID, &ppList);
	if (MP_STATUS_SUCCESS != mpStatus) {

		log(LOG_INFO, "checkTPGList()",
			" - getAssociatedTPGOidList() failed: %d",
			mpStatus);

		return (MP_FALSE);
	}

	for (tpg = 0; tpg < ppList->oidCount; tpg++) {

		mpStatus =
			getTargetPortGroupProperties(ppList->oids[tpg],
			    &tpgProps);

		if (MP_STATUS_SUCCESS != mpStatus) {

			log(LOG_INFO, "checkTPGList()",
				" - getTargetPortGroupProperties()"
				" failed: %d",
				mpStatus);

			return (MP_FALSE);
		}

		if (tpgProps.tpgID == tpgID) {

			status = MP_TRUE;

			log(LOG_INFO,
			    "checkTPGList()",
				" - found a match");

			break;
		}
	}

	free(ppList);


	log(LOG_INFO, "checkTPGList()", " - exit");

	return (status);
}



/*
 *	Returns the number of matches found.  If pOidList is not NULL, then
 *	populate it.  A return values of -1 indicates and error, zerom menas
 *	no match is found.
 */

static int getOidList(di_node_t root_node, int tpgID,
	MP_OID_LIST *tpList, MP_OID_LIST *pOidList)
{
	di_node_t sv_node	= DI_NODE_NIL;
	di_node_t child_node	= DI_NODE_NIL;
	di_path_t path		= DI_PATH_NIL;

	int numNodes = 0;
	int tp = 0;
	int ioctlStatus = 0;
	int match = 0;
	int status = -1;
	int sv_child_inst = 0;
	int hasTpgMatch = MP_FALSE;

	struct stat buffer;

	char *pathName  = NULL;
	char *minorName = "c";

	char fullName[512];

	char *portName = NULL;

	mp_iocdata_t mp_ioctl;

	mp_target_port_prop_t tpInfo;

	MP_UINT64 tpOSN = 0;

	int haveList = (NULL != pOidList);


	log(LOG_INFO, "getOidList()", " - enter");


	/* Look through the list of target ports for a portName that matches */
	for (tp = 0; tp < tpList->oidCount; tp++) {

		tpOSN = tpList->oids[tp].objectSequenceNumber;

		log(LOG_INFO, "getOidList()",
			"tpOSN = %llx",
			tpOSN);

		(void) memset(&mp_ioctl, 0, sizeof (mp_iocdata_t));
		(void) memset(&tpInfo,   0, sizeof (mp_target_port_prop_t));

		mp_ioctl.mp_cmd  = MP_GET_TARGET_PORT_PROP;
		mp_ioctl.mp_ibuf = (caddr_t)&tpOSN;
		mp_ioctl.mp_ilen = sizeof (tpOSN);
		mp_ioctl.mp_obuf = (caddr_t)&tpInfo;
		mp_ioctl.mp_olen = sizeof (mp_target_port_prop_t);
		mp_ioctl.mp_xfer = MP_XFER_READ;

		log(LOG_INFO, "getOidList()",
			"mp_ioctl.mp_cmd (MP_GET_TARGET_PORT_PROP) : %d",
			mp_ioctl.mp_cmd);

		ioctlStatus = ioctl(g_scsi_vhci_fd, MP_CMD, &mp_ioctl);

		log(LOG_INFO, "getOidList()",
			" IOCTL call returned: %d", ioctlStatus);

		if (ioctlStatus < 0) {
			ioctlStatus = errno;
		}

		if (ioctlStatus != 0) {
			log(LOG_INFO, "getOidList()",
				"IOCTL call failed.  IOCTL error is: %d",
				ioctlStatus);
			log(LOG_INFO, "getOidList()",
				"IOCTL call failed.  IOCTL error is: %s",
				strerror(ioctlStatus));
			log(LOG_INFO, "getOidList()",
				"IOCTL call failed.  mp_ioctl.mp_errno: %x",
				mp_ioctl.mp_errno);

			log(LOG_INFO, "getOidList()",
				" - error exit");

			return (-1);
		}

		sv_node = di_drv_first_node("scsi_vhci", root_node);
		if (DI_NODE_NIL == sv_node) {
			log(LOG_INFO, "getOidList()",
				" - di_drv_first_node() failed");

			return (-1);
		}

		child_node = di_child_node(sv_node);

		while (DI_NODE_NIL != child_node) {

			path = di_path_next(child_node, path);

			match = 0;

			while (DI_PATH_NIL != path) {


				(void) di_path_prop_lookup_strings(path,
							"target-port",
							&portName);

				if (NULL != portName) {

					if (0 == strncmp(portName,
						tpInfo.portName,
						strlen(tpInfo.portName))) {

						match = 1;

						break;
					}
				}

				path = di_path_next(child_node, path);
			}

			if (match) {

				log(LOG_INFO, "getOidList()",
					" - got a match");

				pathName = di_devfs_path(child_node);

				(void) snprintf(fullName, 511, "/devices%s:%s",
				    pathName, minorName);

				di_devfs_path_free(pathName);

				status = stat(fullName, &buffer);
				if (status < 0) {

					log(LOG_INFO,
						"getOidList()",
						" - stat() call failed: %d",
						status);

					log(LOG_INFO,
					    "getOidList()",
						" - errno: [%d].", errno);

					log(LOG_INFO,
					    "getOidList()",
						" - strerror(errno): [%s].",
						strerror(errno));

					log(LOG_INFO,
					    "getOidList()",
						" - error exit.");

					return (-1);
				}

				sv_child_inst = di_instance(child_node);

				/*
				 * OK, found an portName that matches, let's
				 * to see if the IDs match.
				 */
				hasTpgMatch =
					checkTPGList(tpgID,
					    sv_child_inst);

				if (MP_TRUE != hasTpgMatch) {

					child_node =
						di_sibling_node(child_node);

					continue;
				}

				if (haveList &&
					(numNodes < pOidList->oidCount)) {

					pOidList->oids[numNodes].
						objectSequenceNumber =
						sv_child_inst;

					pOidList->oids[numNodes].objectType =
						MP_OBJECT_TYPE_MULTIPATH_LU;

					pOidList->oids[numNodes].ownerId =
						g_pluginOwnerID;
				}

				++numNodes;
			}

			child_node = di_sibling_node(child_node);
		}
	}

	log(LOG_INFO,
		"getOidList()",
		" - numNodes: %d",
		numNodes);


	log(LOG_INFO, "getOidList()", " - exit");

	return (numNodes);
}



/*
 *	Called by the common layer to request a list of multipath logical units
 *	associated with a given target port group.
 */

MP_STATUS
MP_GetMPLuOidListFromTPG(MP_OID oid, MP_OID_LIST **ppList)
{

	di_node_t root_node = DI_NODE_NIL;

	int i = 0;
	int numNodes = 0;

	MP_STATUS mpStatus = MP_STATUS_SUCCESS;

	MP_UINT32 sourceTpgID = 0;

	MP_OID_LIST *pOidList = NULL;
	MP_OID_LIST *tpList   = NULL;

	MP_TARGET_PORT_GROUP_PROPERTIES sourceTpgProps;



	log(LOG_INFO, "MP_GetMPLuOidListFromTPG()", " - enter");



	log(LOG_INFO, "MP_GetMPLuOidListFromTPG()",
		"oid.objectSequenceNumber = %llx",
		oid.objectSequenceNumber);

	mpStatus = getTargetPortGroupProperties(oid, &sourceTpgProps);
	if (MP_STATUS_SUCCESS != mpStatus) {

		log(LOG_INFO, "MP_GetMPLuOidListFromTPG()",
			" - getTargetPortGroupProperties() failed: %d",
			mpStatus);

		return (mpStatus);
	}

	/* The TPG ID we will use as a serch key */
	sourceTpgID = sourceTpgProps.tpgID;

	log(LOG_INFO, "MP_GetMPLuOidListFromTPG()",
		"sourceTpgID = %d",
		sourceTpgID);

	/* Get a list of target ports for the TPG */
	mpStatus = getTargetPortOidList(oid, &tpList);
	if (MP_STATUS_SUCCESS != mpStatus) {

		log(LOG_INFO, "getOidList()",
			" - getTargetPortOidList() failed: %d",
			mpStatus);

		return (mpStatus);
	}

	/* Take a snapshot */
	root_node = di_init("/", DINFOCACHE);
	if (DI_NODE_NIL == root_node) {
		log(LOG_INFO, "MP_GetMPLuOidListFromTPG()",
			" - di_init() failed");

		free(tpList);

		return (MP_STATUS_FAILED);
	}

	/* search for the number of multipath logical units that match */
	numNodes = getOidList(root_node, sourceTpgID, tpList, NULL);

	if (numNodes < 0) {

		log(LOG_INFO,
			"MP_GetMPLuOidListFromTPG()",
			" - unable to get OID list.");

		log(LOG_INFO, "MP_GetMPLuOidListFromTPG()",
			" - error exit");

		free(tpList);

		di_fini(root_node);

		return (MP_STATUS_FAILED);
	}

	if (0 == numNodes) {

		pOidList = createOidList(1);
		if (NULL == pOidList) {

			log(LOG_INFO,
				"MP_GetMPLuOidListFromTPG()",
				" - unable to create OID list.");

			free(tpList);

			di_fini(root_node);

			return (MP_STATUS_INSUFFICIENT_MEMORY);
		}

		pOidList->oids[0].objectType =
			MP_OBJECT_TYPE_MULTIPATH_LU;

		pOidList->oids[0].ownerId =
			g_pluginOwnerID;

		*ppList = pOidList;

		log(LOG_INFO, "MP_GetMPLuOidListFromTPG()",
			" - returning empty list.");

		free(tpList);

		return (MP_STATUS_SUCCESS);
	}

	*ppList = createOidList(numNodes);
	if (NULL == *ppList) {
		log(LOG_INFO, "MP_GetMPLuOidListFromTPG()",
			"no memory for *ppList");
		log(LOG_INFO, "MP_GetMPLuOidListFromTPG()",
			" - error exit");

		free(tpList);

		return (MP_STATUS_INSUFFICIENT_MEMORY);
	}

	/* now populate the list */

	(*ppList)->oidCount = numNodes;

	numNodes = getOidList(root_node, sourceTpgID, tpList, *ppList);

	for (i = 0; i < (*ppList)->oidCount; i++) {

		log(LOG_INFO, "MP_GetMPLuOidListFromTPG()",
			"(*ppList)->oids[%d].objectType           = %d",
			i, (*ppList)->oids[i].objectType);
		log(LOG_INFO, "MP_GetMPLuOidListFromTPG()",
			"(*ppList)->oids[%d].ownerId              = %d",
			i, (*ppList)->oids[i].ownerId);
		log(LOG_INFO, "MP_GetMPLuOidListFromTPG()",
			"(*ppList)->oids[%d].objectSequenceNumber = %llx",
			i, (*ppList)->oids[i].objectSequenceNumber);
	}

	free(tpList);

	di_fini(root_node);


	log(LOG_INFO, "MP_GetMPLuOidListFromTPG()", " - exit");

	return (MP_STATUS_SUCCESS);
}
