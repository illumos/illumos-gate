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


/*
 *	Called by the common layer to request the plugin to no longer call
 *	a client application's callback (pClientFn) when a property change
 *	is detected for the given object type.
 */

MP_STATUS
MP_DeregisterForObjectPropertyChangesPlugin(MP_OBJECT_PROPERTY_FN pClientFn,
		MP_OBJECT_TYPE objectType)
{
	log(LOG_INFO, "MP_DeregisterForObjectPropertyChangesPlugin()",
		" - enter");


	if (NULL == pClientFn) {

		log(LOG_INFO, "MP_DeregisterForObjectPropertyChangesPlugin()",
			" - pClientFn is NULL");

		log(LOG_INFO, "MP_DeregisterForObjectPropertyChangesPlugin()",
			" - error exit");

		return (MP_STATUS_INVALID_PARAMETER);
	}

	/* Validate the object type passes in within range */
	if (objectType > MP_OBJECT_TYPE_MAX) {

		log(LOG_INFO, "MP_DeregisterForObjectPropertyChangesPlugin()",
			" - objectType is invalid");

		log(LOG_INFO, "MP_DeregisterForObjectPropertyChangesPlugin()",
			" - error exit");

		return (MP_STATUS_INVALID_PARAMETER);
	}

	if (objectType < 1) {

		log(LOG_INFO, "MP_DeregisterForObjectPropertyChangesPlugin()",
			" - objectType is invalid");

		log(LOG_INFO, "MP_DeregisterForObjectPropertyChangesPlugin()",
			" - error exit");

		return (MP_STATUS_INVALID_PARAMETER);
	}

	/* Remove registration.  */
	(void) pthread_mutex_lock(&g_prop_mutex);
	g_Property_Callback_List[objectType].pClientFn   = NULL;
	g_Property_Callback_List[objectType].pCallerData = NULL;
	(void) pthread_mutex_unlock(&g_prop_mutex);


	log(LOG_INFO, "MP_DeregisterForObjectPropertyChangesPlugin()",
		" - exit");

	return (MP_STATUS_SUCCESS);
}
