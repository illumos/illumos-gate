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

static int getOidList(di_node_t root_node, MP_OID_LIST *pOidList)
{
	int numNodes = 0;

	MP_UINT64 instNum = 0;

	di_node_t sv_node	= DI_NODE_NIL;
	di_node_t sv_child_node = DI_NODE_NIL;

	int haveList = (NULL != pOidList);


	log(LOG_INFO, "getOidList()", " - enter");


	sv_node = di_drv_first_node("scsi_vhci", root_node);
	if (DI_NODE_NIL == sv_node) {
		log(LOG_INFO, "getOidList()",
		    " - di_drv_first_node() failed");

		return (-1);
	}

	sv_child_node = di_child_node(sv_node);

	while (DI_NODE_NIL != sv_child_node) {

		if (haveList && (numNodes < pOidList->oidCount)) {

			instNum =
			(MP_UINT64)di_instance(sv_child_node);

			log(LOG_INFO, "getOidList()",
			    " - instance number is: %llx",
			    instNum);

			pOidList->oids[numNodes].objectType =
			MP_OBJECT_TYPE_MULTIPATH_LU;

			pOidList->oids[numNodes].ownerId =
			g_pluginOwnerID;

			pOidList->oids[numNodes].objectSequenceNumber =
			instNum;
		}

		++numNodes;

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
MP_GetMultipathLusPlugin(MP_OID_LIST **ppList)
{
	di_node_t root_node	= DI_NODE_NIL;
	MP_OID_LIST *pOidList   = NULL;

	int numNodes = 0;
	int i = 0;

	log(LOG_INFO, "MP_GetMultipathLusPlugin()", " - enter");


	root_node = di_init("/", DINFOCACHE);
	if (DI_NODE_NIL == root_node) {
		log(LOG_INFO, "MP_GetMultipathLusPlugin()",
		    " - di_init() failed");

		return (MP_STATUS_FAILED);
	}

	numNodes = getOidList(root_node, NULL);

	if (numNodes < 0) {

		log(LOG_INFO,
		    "MP_GetMultipathLusPlugin()",
		    " - unable to get OID list.");

		log(LOG_INFO, "MP_GetMultipathLusPlugin()",
		    " - error exit");

		di_fini(root_node);

		return (MP_STATUS_FAILED);
	}

	if (0 == numNodes) {

		pOidList = createOidList(1);
		if (NULL == pOidList) {

			log(LOG_INFO,
			    "MP_GetMultipathLusPlugin()",
			    " - unable to create OID list.");

			di_fini(root_node);

			return (MP_STATUS_INSUFFICIENT_MEMORY);
		}

		pOidList->oids[0].objectType =
		MP_OBJECT_TYPE_MULTIPATH_LU;

		pOidList->oids[0].ownerId =
		g_pluginOwnerID;

		*ppList = pOidList;

		log(LOG_INFO, "MP_GetMultipathLusPlugin()",
		    " - returning empty list.");

		di_fini(root_node);

		return (MP_STATUS_SUCCESS);
	}

	*ppList = createOidList(numNodes);
	if (NULL == *ppList) {
		log(LOG_INFO, "MP_GetMultipathLusPlugin()",
		    "no memory for *ppList");
		log(LOG_INFO, "MP_GetMultipathLusPlugin()",
		    " - error exit");
		return (MP_STATUS_INSUFFICIENT_MEMORY);
	}

	(*ppList)->oidCount = numNodes;

	numNodes = getOidList(root_node, *ppList);

	for (i = 0; i < (*ppList)->oidCount; i++) {

		log(LOG_INFO, "MP_GetMultipathLusPlugin()",
		    "(*ppList)->oids[%d].objectType           = %d",
		    i, (*ppList)->oids[i].objectType);
		log(LOG_INFO, "MP_GetMultipathLusPlugin()",
		    "(*ppList)->oids[%d].ownerId              = %d",
		    i, (*ppList)->oids[i].ownerId);
		log(LOG_INFO, "MP_GetMultipathLusPlugin()",
		    "(*ppList)->oids[%d].objectSequenceNumber = %llx",
		    i, (*ppList)->oids[i].objectSequenceNumber);
	}


	di_fini(root_node);

	log(LOG_INFO, "MP_GetMultipathLusPlugin()", " - exit");

	return (MP_STATUS_SUCCESS);

}
