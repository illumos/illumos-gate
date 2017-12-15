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
 * Copyright 2009 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

#include <dlfcn.h>
#include <pthread.h>
#include <string.h>
#include <sys/sem.h>

#include "libsun_ima.h"
#include "ima.h"
#include "ima-plugin.h"

extern int number_of_plugins;
extern int libMutex;
extern IMA_PLUGIN_INFO	 plugintable[IMA_MAX_NUM_PLUGINS];
extern void InitLibrary();

static void os_obtainmutex(int semid);
static void os_releasemutex(int semid);

IMA_API IMA_STATUS SUN_IMA_SetTunableProperties(
		IMA_OID oid,
		ISCSI_TUNABLE_PARAM *param) {
	SUN_IMA_SetTunablePropertiesFn PassFunc;
	IMA_UINT i;
	IMA_STATUS status;

	if (number_of_plugins == -1) {
		InitLibrary();
	}

	if (param == NULL) {
		return (IMA_ERROR_INVALID_PARAMETER);
	}

	if ((oid.objectType != IMA_OBJECT_TYPE_LHBA) &&
	    (oid.objectType != IMA_OBJECT_TYPE_TARGET)) {
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);
	}

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;

	for (i = 0; i < number_of_plugins; i++) {
		if (plugintable[i].ownerId == oid.ownerId) {
			status = IMA_ERROR_UNEXPECTED_OS_ERROR;
			os_obtainmutex(plugintable[i].pluginMutex);
#ifdef SOLARIS
			PassFunc = (SUN_IMA_SetTunablePropertiesFn)
			    dlsym(plugintable[i].hPlugin,
			    "SUN_IMA_SetTunableProperties");
#endif
			if (PassFunc != NULL) {
				status = PassFunc(oid, param);
			}
			os_releasemutex(plugintable[i].pluginMutex);
			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}

IMA_API IMA_STATUS SUN_IMA_GetTunableProperties(
		IMA_OID oid,
		ISCSI_TUNABLE_PARAM *param) {
	SUN_IMA_GetTunablePropertiesFn PassFunc = NULL;
	int i;
	IMA_STATUS status;

	if (number_of_plugins == -1) {
		InitLibrary();
	}

	if (param == NULL) {
		return (IMA_ERROR_INVALID_PARAMETER);
	}

	if ((oid.objectType != IMA_OBJECT_TYPE_LHBA) &&
	    (oid.objectType != IMA_OBJECT_TYPE_TARGET)) {
		return (IMA_ERROR_INCORRECT_OBJECT_TYPE);
	}

	os_obtainmutex(libMutex);
	status = IMA_ERROR_OBJECT_NOT_FOUND;
	for (i = 0; i < number_of_plugins; i++) {
		status = IMA_ERROR_UNEXPECTED_OS_ERROR;
		if (plugintable[i].ownerId == oid.ownerId) {
			os_obtainmutex(plugintable[i].pluginMutex);
#ifdef SOLARIS
			PassFunc = (SUN_IMA_GetTunablePropertiesFn)
			    dlsym(plugintable[i].hPlugin,
			    "SUN_IMA_GetTunableProperties");
#endif
			if (PassFunc != NULL) {
				status = PassFunc(oid, param);
			}
			os_releasemutex(plugintable[i].pluginMutex);
			break;
		}
	}
	os_releasemutex(libMutex);
	return (status);
}

static void
os_obtainmutex(int semid)
{
	struct sembuf sem_b;

	sem_b.sem_num = 0;
	sem_b.sem_op = -1;
	sem_b.sem_flg = SEM_UNDO;
	(void) semop(semid, &sem_b, 1);
}

static void
os_releasemutex(int semid)
{
	struct sembuf sem_b;

	sem_b.sem_num = 0;
	sem_b.sem_op = 1;
	sem_b.sem_flg = SEM_UNDO;
	(void) semop(semid, &sem_b, 1);
}
