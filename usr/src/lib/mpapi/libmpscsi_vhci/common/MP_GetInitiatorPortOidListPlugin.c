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
	int instNum = 0;
	int majorNum = 0;

	di_node_t vh_node	= DI_NODE_NIL;
	di_node_t ph_node	= DI_NODE_NIL;

	MP_UINT64 osn = 0;

	int haveList = (NULL != pOidList);


	log(LOG_INFO, "getOidList()", " - enter");

	vh_node = di_vhci_first_node(root_node);

	while (DI_NODE_NIL != vh_node) {
		if ((di_driver_name(vh_node) != NULL) &&
		    (strncmp(di_driver_name(vh_node), "scsi_vhci", 9) == 0)) {
			ph_node = di_phci_first_node(vh_node);
			while (DI_NODE_NIL != ph_node) {
				if (haveList) {

					instNum  = di_instance(ph_node);
					majorNum = di_driver_major(ph_node);

					log(LOG_INFO, "getOidList()",
						"instNum = %d",
						instNum);

					log(LOG_INFO, "getOidList()",
						"majorNum = %d",
						majorNum);

					if (numNodes < pOidList->oidCount) {

						osn = 0;

						osn =
						MP_STORE_INST_TO_ID(instNum,
								osn);

						osn =
						MP_STORE_MAJOR_TO_ID(majorNum,
								osn);

						pOidList->oids[numNodes]
							.objectSequenceNumber =
							osn;

						pOidList->oids[numNodes].
							objectType =
						MP_OBJECT_TYPE_INITIATOR_PORT;

						pOidList->oids[numNodes].
							ownerId =
							g_pluginOwnerID;
					}
				}

				++numNodes;
				ph_node = di_phci_next_node(ph_node);
			}

		}
		vh_node = di_vhci_next_node(vh_node);
	}

	log(LOG_INFO,
		"getOidList()",
		" - numNodes: %d",
		numNodes);


	log(LOG_INFO, "getOidList()", " - exit");

	return (numNodes);
}



MP_STATUS
MP_GetInitiatorPortOidListPlugin(MP_OID_LIST **ppList)
{
	di_node_t root_node	= DI_NODE_NIL;

	int i = 0;
	int numNodes = 0;



	log(LOG_INFO, "MP_GetInitiatorPortOidListPlugin()", " - enter");


	root_node = di_init("/", DINFOCACHE);
	if (DI_NODE_NIL == root_node) {
		log(LOG_INFO, "MP_GetInitiatorPortOidListPlugin()",
			" - di_init() failed");

		return (MP_STATUS_FAILED);
	}

	numNodes = getOidList(root_node, NULL);

	if (numNodes < 1) {

		*ppList = createOidList(1);

		if (NULL == *ppList) {
			log(LOG_INFO, "MP_GetInitiatorPortOidListPlugin()",
				"no memory for *ppList");
			log(LOG_INFO, "MP_GetInitiatorPortOidListPlugin()",
				" - error exit");
			return (MP_STATUS_INSUFFICIENT_MEMORY);
		}

		log(LOG_INFO, "MP_GetInitiatorPortOidListPlugin()",
			" - returning empty list.");

		return (MP_STATUS_SUCCESS);
	}

	*ppList = createOidList(numNodes);
	if (NULL == *ppList) {
		log(LOG_INFO, "MP_GetInitiatorPortOidListPlugin()",
			"no memory for *ppList");
		log(LOG_INFO, "MP_GetInitiatorPortOidListPlugin()",
			" - error exit");
		return (MP_STATUS_INSUFFICIENT_MEMORY);
	}

	(*ppList)->oidCount = numNodes;

	numNodes = getOidList(root_node, *ppList);

	for (i = 0; i < (*ppList)->oidCount; i++) {

		log(LOG_INFO, "MP_GetInitiatorPortOidListPlugin()",
			"(*ppList)->oids[%d].objectType           = %d",
			i, (*ppList)->oids[i].objectType);
		log(LOG_INFO, "MP_GetInitiatorPortOidListPlugin()",
			"(*ppList)->oids[%d].ownerId              = %d",
			i, (*ppList)->oids[i].ownerId);
		log(LOG_INFO, "MP_GetInitiatorPortOidListPlugin()",
			"(*ppList)->oids[%d].objectSequenceNumber = %llx",
			i, (*ppList)->oids[i].objectSequenceNumber);
	}


	di_fini(root_node);


	log(LOG_INFO, "MP_GetInitiatorPortOidListPlugin()", " - exit");

	return (MP_STATUS_SUCCESS);
}
