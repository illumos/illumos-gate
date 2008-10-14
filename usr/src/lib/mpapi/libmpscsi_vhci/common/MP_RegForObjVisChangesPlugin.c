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
 *	Called by the common layer to request the plugin to call
 *	a client application's callback (pClientFn) when a visibility change
 *	is detected for the given object type.
 */

MP_STATUS
MP_RegisterForObjectVisibilityChangesPlugin(MP_OBJECT_VISIBILITY_FN pClientFn,
		MP_OBJECT_TYPE objectType,
		void *pCallerData)
{
	MP_BOOL hasFunc = MP_FALSE;


	log(LOG_INFO, "MP_RegisterForObjectVisibilityChangesPlugin()",
		" - enter");


	/* Validate the object type passes in within range */
	if (objectType > MP_OBJECT_TYPE_MAX) {

		log(LOG_INFO, "MP_RegisterForObjectVisibilityChangesPlugin()",
			" - objectType is invalid");

		log(LOG_INFO, "MP_RegisterForObjectVisibilityChangesPlugin()",
			" - error exit");

		return (MP_STATUS_INVALID_PARAMETER);
	}

	if (objectType < 1) {

		log(LOG_INFO, "MP_RegisterForObjectVisibilityChangesPlugin()",
			" - objectType is invalid");

		log(LOG_INFO, "MP_RegisterForObjectVisibilityChangesPlugin()",
			" - error exit");

		return (MP_STATUS_INVALID_PARAMETER);
	}

	/*   Check to see if we are going to be replacing */
	(void) pthread_mutex_lock(&g_visa_mutex);
	if (g_Visibility_Callback_List[objectType].pClientFn != NULL) {

		hasFunc = MP_TRUE;
	}

	g_Visibility_Callback_List[objectType].pClientFn   = pClientFn;
	g_Visibility_Callback_List[objectType].pCallerData = pCallerData;
	(void) pthread_mutex_unlock(&g_visa_mutex);

	if (hasFunc) {

		log(LOG_INFO, "MP_RegisterForObjectVisibilityChangesPlugin()",
			" - returning MP_STATUS_FN_REPLACED");

		return (MP_STATUS_FN_REPLACED);
	}


	log(LOG_INFO, "MP_RegisterForObjectVisibilityChangesPlugin()",
		" - exit");

	return (MP_STATUS_SUCCESS);
}
