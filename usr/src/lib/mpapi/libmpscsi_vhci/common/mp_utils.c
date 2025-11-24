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
 * Copyright (c) 2006, 2010, Oracle and/or its affiliates. All rights reserved.
 * Copyright 2025 Hans Rosenfeld
 */

#include "mp_utils.h"
#include <sys/sunddi.h>

#ifndef OIDLIST
#define	OIDLIST "oid"
#endif


/* Remove these 5 when this source can compile with sunddi.h */
#ifndef EC_DDI
#define	EC_DDI				"EC_ddi"
#endif

#ifndef ESC_DDI_INITIATOR_REGISTER
#define	ESC_DDI_INITIATOR_REGISTER	"ESC_ddi_initiator_register"
#endif

#ifndef ESC_DDI_INITIATOR_UNREGISTER
#define	ESC_DDI_INITIATOR_UNREGISTER	"ESC_ddi_initiator_unregister"
#endif

#ifndef DDI_DRIVER_MAJOR
#define	DDI_DRIVER_MAJOR		"ddi.major"
#endif

#ifndef DDI_INSTANCE
#define	DDI_INSTANCE			"ddi.instance"
#endif


#define	VISA_CHANGE 1
#define	PROP_CHANGE 2



MP_STATUS
getStatus4ErrorCode(int driverError)
{
	MP_STATUS mpStatus = MP_STATUS_FAILED;

	log(LOG_INFO, "getStatus4ErrorCode()", "- enter");

	switch (driverError) {

		case MP_DRVR_INVALID_ID:
			log(LOG_INFO, "getStatus4ErrorCode()",
			    " received mp_errno=MP_DRVR_INVALID_ID"
			    " from driver call.");
			log(LOG_INFO, "getStatus4ErrorCode()",
			    " returning MP_STATUS_OBJECT_NOT_FOUND"
			    " to caller.");
			mpStatus = MP_STATUS_OBJECT_NOT_FOUND;
			break;


		case MP_DRVR_ID_OBSOLETE:
			log(LOG_INFO, "getStatus4ErrorCode()",
			    " received mp_errno=MP_DRVR_ID_OBSOLETE"
			    " from driver call.");
			log(LOG_INFO, "getStatus4ErrorCode()",
			    " returning MP_STATUS_OBJECT_NOT_FOUND"
			    " to caller.");
			mpStatus = MP_STATUS_OBJECT_NOT_FOUND;
			break;


		case MP_DRVR_ACCESS_SYMMETRIC:
			log(LOG_INFO, "getStatus4ErrorCode()",
			    " received mp_errno=MP_DRVR_ACCESS_SYMMETRIC"
			    " from driver call.");
			log(LOG_INFO, "getStatus4ErrorCode()",
			    " returning MP_STATUS_INVALID_PARAMETER"
			    " to caller.");
			mpStatus = MP_STATUS_INVALID_PARAMETER;
			break;


		case MP_DRVR_PATH_UNAVAILABLE:
			log(LOG_INFO, "getStatus4ErrorCode()",
			    " received mp_errno=MP_DRVR_PATH_UNAVAILABLE"
			    " from driver call.");
			log(LOG_INFO, "getStatus4ErrorCode()",
			    " returning MP_STATUS_PATH_NONOPERATIONAL"
			    " to caller.");
			mpStatus = MP_STATUS_PATH_NONOPERATIONAL;
			break;


		case MP_DRVR_IDS_NOT_ASSOCIATED:
			log(LOG_INFO, "getStatus4ErrorCode()",
			    " received mp_errno=MP_DRVR_IDS_NOT_ASSOCIATED"
			    " from driver call.");
			log(LOG_INFO, "getStatus4ErrorCode()",
			    " returning MP_STATUS_INVALID_PARAMETER"
			    " to caller.");
			mpStatus = MP_STATUS_INVALID_PARAMETER;
			break;


		case MP_DRVR_ILLEGAL_ACCESS_STATE_REQUEST:
			log(LOG_INFO, "getStatus4ErrorCode()",
			    " received mp_errno="
			    "MP_DRVR_ILLEGAL_ACCESS_STATE_REQUEST"
			    " from driver call.");
			log(LOG_INFO, "getStatus4ErrorCode()",
			    " returning MP_STATUS_INVALID_PARAMETER"
			    " to caller.");
			mpStatus = MP_STATUS_ACCESS_STATE_INVALID;
			break;


		case MP_DRVR_ILLEGAL_LOAD_BALANCING_TYPE:
			log(LOG_INFO, "getStatus4ErrorCode()",
			    " received mp_errno="
			    "MP_DRVR_ILLEGAL_LOAD_BALANCING_TYPE"
			    " from driver call.");
			log(LOG_INFO, "getStatus4ErrorCode()",
			    " returning MP_STATUS_INVALID_PARAMETER"
			    " to caller.");
			mpStatus = MP_STATUS_INVALID_PARAMETER;
			break;

		default:
			log(LOG_INFO, "getStatus4ErrorCode()",
			    " - received (unsupported) mp_errno=%d from"
			    " driver call.", driverError);
			log(LOG_INFO, "getStatus4ErrorCode()",
			    " - returning MP_STATUS_FAILED to caller.");
			mpStatus = MP_STATUS_FAILED;
	}

	log(LOG_INFO, "getStatus4ErrorCode()", "- exit");

	return (mpStatus);
}



MP_OID_LIST
*createOidList(int size) {

	MP_OID_LIST *pOidList = NULL;


	log(LOG_INFO, "createOidList()", "- enter");


	if (size < 1) {

		log(LOG_INFO, "createOidList()",
			"requested size is less than 1");
		log(LOG_INFO, "createOidList()",
			" - error exit");
		return (NULL);

	} else {

		pOidList = (MP_OID_LIST*)calloc(1,
			sizeof (MP_OID_LIST) +
			((size - 1) *
		    sizeof (MP_OID)));

		if (NULL == pOidList) {
			log(LOG_INFO, "createOidList()",
				"no memory for pOidList");
			log(LOG_INFO, "createOidList()",
				" - error exit");
			return (NULL);
		}

		log(LOG_INFO,
		    "createOidList()",
			"- exit(%d)",
			size);

		return (pOidList);
	}
}

/* Calls the client callback function, if one is registered */
static void
notifyClient(sysevent_t *ev)
{
	nvlist_t *attr_list = NULL;

	uint64_t *val = NULL;
	int32_t  *instance = NULL;
	int32_t  *major = NULL;

	int valAllocated = 0;

	uint_t nelem = 0;

	int i = 0;
	int eventType = 0;
	int index = -1;

	void *pCallerData = NULL;

	char subClassName[256];

	MP_BOOL becomingVisible = MP_FALSE;

	MP_OID_LIST *oidList = NULL;


	log(LOG_INFO, "notifyClient()", "- enter");


	(void) strncpy(subClassName, sysevent_get_subclass_name(ev), 256);

	if (strstr(subClassName, "change")) {

		eventType = PROP_CHANGE;

		log(LOG_INFO, "notifyClient()", "- got a change event");
		log(LOG_INFO, "notifyClient()", ": [%s]",
		    subClassName);

		if (strncmp(subClassName, ESC_SUN_MP_PLUGIN_CHANGE, 255)
		    == 0) {

			index = MP_OBJECT_TYPE_PLUGIN;

		} else if (strncmp(subClassName, ESC_SUN_MP_LU_CHANGE, 255)
		    == 0) {

			index = MP_OBJECT_TYPE_MULTIPATH_LU;

		} else if (strncmp(subClassName, ESC_SUN_MP_PATH_CHANGE, 255)
		    == 0) {

			index = MP_OBJECT_TYPE_PATH_LU;

		} else if (strncmp(subClassName, ESC_SUN_MP_INIT_PORT_CHANGE,
		    255) == 0) {

			index = MP_OBJECT_TYPE_INITIATOR_PORT;

		} else if (strncmp(subClassName, ESC_SUN_MP_TPG_CHANGE, 255)
		    == 0) {

			index = MP_OBJECT_TYPE_TARGET_PORT_GROUP;

		} else if (strncmp(subClassName, ESC_SUN_MP_TARGET_PORT_CHANGE,
		    255) == 0) {

			index = MP_OBJECT_TYPE_TARGET_PORT;

		} else if (strncmp(subClassName, ESC_SUN_MP_DEV_PROD_CHANGE,
		    255) == 0) {

			index = MP_OBJECT_TYPE_DEVICE_PRODUCT;
		}

	} else if ((strstr(subClassName, "add")) ||
	    (strstr(subClassName, "initiator_register"))) {

		eventType = VISA_CHANGE;
		becomingVisible = MP_TRUE;

		log(LOG_INFO, "notifyClient()", "- got a visibility"
		    " add event");
		log(LOG_INFO, "notifyClient()", ": [%s]",
		    subClassName);

		if (strncmp(subClassName, ESC_SUN_MP_LU_ADD, 255) == 0) {

			index = MP_OBJECT_TYPE_MULTIPATH_LU;

		} else if (strncmp(subClassName, ESC_SUN_MP_PATH_ADD, 255)
		    == 0) {

			index = MP_OBJECT_TYPE_PATH_LU;

		} else if (strncmp(subClassName, ESC_DDI_INITIATOR_REGISTER,
		    244) == 0) {

			index = MP_OBJECT_TYPE_INITIATOR_PORT;

		} else if (strncmp(subClassName, ESC_SUN_MP_TPG_ADD,
		    255) == 0) {

			index = MP_OBJECT_TYPE_TARGET_PORT_GROUP;

		} else if (strncmp(subClassName, ESC_SUN_MP_TARGET_PORT_ADD,
		    255) == 0) {

			index = MP_OBJECT_TYPE_TARGET_PORT;

		} else if (strncmp(subClassName, ESC_SUN_MP_DEV_PROD_ADD, 255)
		    == 0) {

			index = MP_OBJECT_TYPE_DEVICE_PRODUCT;
		}


	} else if ((strstr(subClassName, "remove")) ||
	    (strstr(subClassName, "initiator_unregister"))) {

		eventType = VISA_CHANGE;
		becomingVisible = MP_FALSE;

		log(LOG_INFO, "notifyClient()", "- got a visibility"
		    " remove event");
		log(LOG_INFO, "notifyClient()", ": [%s]",
		    subClassName);

		if (strncmp(subClassName, ESC_SUN_MP_LU_REMOVE, 255) == 0) {

			index = MP_OBJECT_TYPE_MULTIPATH_LU;

		} else if (strncmp(subClassName, ESC_SUN_MP_PATH_REMOVE, 255)
		    == 0) {

			index = MP_OBJECT_TYPE_PATH_LU;

		} else if (strncmp(subClassName, ESC_DDI_INITIATOR_UNREGISTER,
		    255) == 0) {

			index = MP_OBJECT_TYPE_INITIATOR_PORT;

		} else if (strncmp(subClassName, ESC_SUN_MP_TPG_REMOVE, 255)
		    == 0) {

			index = MP_OBJECT_TYPE_TARGET_PORT_GROUP;

		} else if (strncmp(subClassName, ESC_SUN_MP_TARGET_PORT_REMOVE,
		    255) == 0) {

			index = MP_OBJECT_TYPE_TARGET_PORT;

		} else if (strncmp(subClassName, ESC_SUN_MP_DEV_PROD_REMOVE,
		    255) == 0) {

			index = MP_OBJECT_TYPE_DEVICE_PRODUCT;
		}


	} else {
		log(LOG_INFO, "notifyClient()", "- got an unsupported event");
		return;
	}

	if (index < 0) {

		log(LOG_INFO, "notifyClient()", "- index is less than zero");
		return;
	}

	if (eventType == VISA_CHANGE) {

		(void) pthread_mutex_lock(&g_visa_mutex);

		if (NULL == g_Visibility_Callback_List[index].pClientFn) {

			log(LOG_INFO, "notifyClient()",
			    "- no visibility change callback to notify");

			(void) pthread_mutex_unlock(&g_visa_mutex);

			return;
		}

		(void) pthread_mutex_unlock(&g_visa_mutex);
	}

	if (eventType == PROP_CHANGE) {

		(void) pthread_mutex_lock(&g_prop_mutex);

		if (NULL == g_Property_Callback_List[index].pClientFn) {

			log(LOG_INFO, "notifyClient()",
			    "- no property change callback to notify");

			(void) pthread_mutex_unlock(&g_prop_mutex);

			return;
		}

		(void) pthread_mutex_unlock(&g_prop_mutex);
	}

	(void) sysevent_get_attr_list(ev, &attr_list);
	if (NULL != attr_list) {

		if ((VISA_CHANGE == eventType) &&
		    (MP_OBJECT_TYPE_PLUGIN == index)) {

			val = (uint64_t *)malloc(sizeof (uint64_t));
			valAllocated = 1;

			/*
			 * We have no well-defined way to determine our OSN.
			 * Currently the common library uses 0 as OSN for every
			 * plugin, so just use 0. If the OSN assigned by the
			 * common library changed, this code would have to be
			 * updated.
			 */
			*val = 0;
			nelem = 1;

		} else if ((VISA_CHANGE == eventType) &&
		    (MP_OBJECT_TYPE_INITIATOR_PORT == index)) {

			(void) nvlist_lookup_int32_array(attr_list,
			    DDI_INSTANCE, &instance, &nelem);

			log(LOG_INFO, "notifyClient()",
			    "- event (PHCI_INSTANCE) has [%d] elements",
			    nelem);

			(void) nvlist_lookup_int32_array(attr_list,
			    DDI_DRIVER_MAJOR, &major, &nelem);

			log(LOG_INFO, "notifyClient()",
			    "- event (PHCI_DRIVER_MAJOR) has [%d] elements",
			    nelem);

			if ((NULL != instance) & (NULL != major)) {

				val = (uint64_t *)malloc(sizeof (uint64_t));

				valAllocated = 1;

				*val = 0;
				*val = MP_STORE_INST_TO_ID(*instance, *val);
				*val = MP_STORE_MAJOR_TO_ID(*major, *val);

				nelem = 1;

			} else {

				nelem = 0;
			}

		} else {

			(void) nvlist_lookup_uint64_array(attr_list, OIDLIST,
			    &val, &nelem);

			log(LOG_INFO, "notifyClient()",
			    "- event has [%d] elements",
			    nelem);
		}

		if (nelem > 0) {

			for (i = 0; i < nelem; i++) {

				log(LOG_INFO, "notifyClient()",
				    "- event [%d] = %llx",
				    i, val[i]);
			}

			oidList = createOidList(nelem);
			if (NULL == oidList) {

				log(LOG_INFO, "notifyClient()",
				    "- unable to create MP_OID_LIST");

				log(LOG_INFO, "notifyClient()",
				    "- error exit");

				nvlist_free(attr_list);

				return;
			}

			oidList->oidCount = nelem;

			for (i = 0; i < nelem; i++) {

				oidList->oids[i].objectType = index;
				oidList->oids[i].ownerId = g_pluginOwnerID;
				oidList->oids[i].objectSequenceNumber = val[i];
			}

			if (valAllocated) {

				free(val);
			}

			for (i = 0; i < oidList->oidCount; i++) {

				log(LOG_INFO, "notifyClient()",
				    "oidList->oids[%d].objectType"
				    "           = %d",
				    i, oidList->oids[i].objectType);
				log(LOG_INFO, "notifyClient()",
				    "oidList->oids[%d].ownerId"
				    "              = %d",
				    i, oidList->oids[i].ownerId);
				log(LOG_INFO, "notifyClient()",
				    "oidList->oids[%d].objectSequenceNumber"
				    " = %llx",
				    i, oidList->oids[i].objectSequenceNumber);
			}

			if (eventType == PROP_CHANGE) {

				(void) pthread_mutex_lock(&g_prop_mutex);

				pCallerData = g_Property_Callback_List[index].
				    pCallerData;

				(g_Property_Callback_List[index].pClientFn)
				    (oidList, pCallerData);

				(void) pthread_mutex_unlock(&g_prop_mutex);

			} else if (eventType == VISA_CHANGE) {

				(void) pthread_mutex_lock(&g_visa_mutex);

				pCallerData = g_Visibility_Callback_List[index].
				    pCallerData;

				(g_Visibility_Callback_List[index].pClientFn)
				    (becomingVisible, oidList, pCallerData);

				(void) pthread_mutex_unlock(&g_visa_mutex);

			}
		}

		nvlist_free(attr_list);
	}


	log(LOG_INFO, "notifyClient()", "- exit");
}

/* Event handler called by system */
static void
sysevent_handler(sysevent_t *ev)
{
	log(LOG_INFO, "sysevent_handler()", "- enter");

	/* Is the event one of ours? */
	if ((strncmp(EC_SUN_MP, sysevent_get_class_name(ev), 9) != 0) &&
	    (strncmp(EC_DDI,    sysevent_get_class_name(ev), 6) != 0)) {

		return;
	}

	/* Notify client if it cares */
	notifyClient(ev);


	log(LOG_INFO, "sysevent_handler()", "- exit");
}

/* Registers the plugin to the sysevent framework */
MP_STATUS
init_sysevents(void)
{

	const char *subclass_list[] = {

		ESC_SUN_MP_PLUGIN_CHANGE,

		ESC_SUN_MP_LU_CHANGE,
		ESC_SUN_MP_LU_ADD,
		ESC_SUN_MP_LU_REMOVE,

		ESC_SUN_MP_PATH_CHANGE,
		ESC_SUN_MP_PATH_ADD,
		ESC_SUN_MP_PATH_REMOVE,

		ESC_SUN_MP_INIT_PORT_CHANGE,

		ESC_SUN_MP_TPG_CHANGE,
		ESC_SUN_MP_TPG_ADD,
		ESC_SUN_MP_TPG_REMOVE,

		ESC_SUN_MP_TARGET_PORT_CHANGE,
		ESC_SUN_MP_TARGET_PORT_ADD,
		ESC_SUN_MP_TARGET_PORT_REMOVE,

		ESC_SUN_MP_DEV_PROD_CHANGE,
		ESC_SUN_MP_DEV_PROD_ADD,
		ESC_SUN_MP_DEV_PROD_REMOVE

	};

	const char *init_port_subclass_list[] = {

		ESC_DDI_INITIATOR_REGISTER,
		ESC_DDI_INITIATOR_UNREGISTER
	};



	log(LOG_INFO, "init_sysevents()", "- enter");


	g_SysEventHandle = sysevent_bind_handle(sysevent_handler);
	if (g_SysEventHandle == NULL) {

		log(LOG_INFO, "init_sysevents()",
		    "- sysevent_bind_handle() failed");

		log(LOG_INFO, "init_sysevents()", "- error exit");

		return (MP_STATUS_FAILED);
	}

	if (sysevent_subscribe_event(g_SysEventHandle, EC_SUN_MP,
	    subclass_list, sizeof (subclass_list) / sizeof (subclass_list[0]))
	    != 0) {


		log(LOG_INFO, "init_sysevents()",
		    "- sysevent_subscribe_event() failed for subclass_list");

		log(LOG_INFO, "init_sysevents()", "- error exit");

		sysevent_unbind_handle(g_SysEventHandle);

		return (MP_STATUS_FAILED);
	}

	if (sysevent_subscribe_event(g_SysEventHandle, EC_DDI,
	    init_port_subclass_list, sizeof (init_port_subclass_list) /
	    sizeof (init_port_subclass_list[0])) != 0) {


		log(LOG_INFO, "init_sysevents()",
		    "- sysevent_subscribe_event() failed "
		    "for init_port_subclass_list");

		log(LOG_INFO, "init_sysevents()", "- error exit");

		sysevent_unbind_handle(g_SysEventHandle);

		return (MP_STATUS_FAILED);
	}


	log(LOG_INFO, "init_sysevents()", "- exit");

	return (MP_STATUS_SUCCESS);
}
