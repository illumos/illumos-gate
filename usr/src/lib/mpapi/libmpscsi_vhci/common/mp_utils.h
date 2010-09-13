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
#ifndef _MP_UTILS_H
#define	_MP_UTILS_H

#ifdef	__cplusplus
extern "C" {
#endif

#include <mpapi.h>
#include <sys/scsi/adapters/mpapi_impl.h>

#include <sys/types.h>
#include <libsysevent.h>
#include <syslog.h>
#include <pthread.h>

/* Default bytes */
#define	DEFAULT_BUFFER_SIZE_LU_LIST		4096
#define	DEFAULT_BUFFER_SIZE_INIT_PORT_LIST	1024
#define	DEFAULT_BUFFER_SIZE_PATH_LIST		1024
#define	DEFAULT_BUFFER_SIZE_DEV_PROD		1024
#define	DEFAULT_BUFFER_SIZE_TPG			1024
#define	DEFAULT_BUFFER_SIZE_LOADBALANCE		1024


/* Node to hold pointer to client callback */
typedef struct _property_node
{
	MP_OBJECT_PROPERTY_FN 	pClientFn;
	void 			*pCallerData;

} PROPERTY_CALLBACK_NODE;


/* Node to hold pointer to client callback */
typedef struct _visibility_node
{
	MP_OBJECT_VISIBILITY_FN 	pClientFn;
	void 				*pCallerData;

} VISIBILITY_CALLBACK_NODE;


/* Global array to hold client callbacks */
extern
PROPERTY_CALLBACK_NODE   g_Property_Callback_List[MP_OBJECT_TYPE_MAX + 1];

/* Global array to hold client callbacks */
extern
VISIBILITY_CALLBACK_NODE g_Visibility_Callback_List[MP_OBJECT_TYPE_MAX + 1];


/* Global variable to hold this pligin's ID */
extern MP_UINT32	g_pluginOwnerID;

/* Global variable to hold scsi_vhci file descriptor */
extern int		g_scsi_vhci_fd;

/* Global variable to hold sysevent handle */
extern sysevent_handle_t *g_SysEventHandle;

/* Mutexes to make array modify/read thread safe */
extern pthread_mutex_t g_visa_mutex;
extern pthread_mutex_t g_prop_mutex;



/* Used to add debug (log) info */
void log(int priority, const char *routine, char *msg, ...);

/* Returns an MP_STATUS code for an mp_iocdata_t.mp_errno code */
MP_STATUS getStatus4ErrorCode(int driverError);

/* Returns an MP_OID_LIST that will hold "size" MP_OID elements */
MP_OID_LIST *createOidList(int size);

/* Initializes the sysevent framework */
MP_STATUS init_sysevents();

/* Implementation function for MP_GetAssociatedTPGOidList() */
MP_STATUS getAssociatedTPGOidList(MP_OID oid, MP_OID_LIST **ppList);

/* Implementation function for MP_GetTargetPortGroupProperties() */
MP_STATUS getTargetPortGroupProperties(MP_OID oid,
	MP_TARGET_PORT_GROUP_PROPERTIES *pProps);

/* Implementation function for MP_GetTargetPortOidList() */
MP_STATUS getTargetPortOidList(MP_OID oid, MP_OID_LIST **ppList);

#ifdef	__cplusplus
}
#endif

#endif	/* _MP_UTILS_H */
