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
 * Copyright 2006 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

/* $Id: service.c 163 2006-05-09 15:07:45Z njacobs $ */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdarg.h>
#include <uri.h>
#include <papi_impl.h>

papi_status_t
service_fill_in(service_t *svc, char *name)
{
	papi_status_t status = PAPI_OK;
	uri_t *uri = NULL;

	if (svc == NULL)
		return (PAPI_BAD_ARGUMENT);

	if (name == NULL)
		return (PAPI_OK);

	/*
	 * valid URIs are in the form:
	 *	lpd://server[:port]/.../queue[#extensions]
	 *	rfc-1179://server[:port]/.../queue[#extensions]
	 * any authentication information supplied the URI is ignored.
	 */
	if (uri_from_string((char *)name, &uri) != -1) {
		if ((strcasecmp(uri->scheme, "lpd") == 0) ||
		    (strcasecmp(uri->scheme, "rfc-1179") == 0)) {
			if (svc->uri != NULL)
				uri_free(svc->uri);
			svc->uri = uri;
		} else {
			uri_free(uri);
			status = PAPI_URI_SCHEME;
		}
	}

	return (status);
}

papi_status_t
papiServiceCreate(papi_service_t *handle, char *service_name,
		char *user_name, char *password,
		int (*authCB)(papi_service_t svc, void *app_data),
		papi_encryption_t encryption, void *app_data)
{
	papi_status_t status;
	service_t *svc = NULL;

	if (handle == NULL)
		return (PAPI_BAD_ARGUMENT);

	if ((*handle = svc = (service_t *)calloc(1, sizeof (*svc))) == NULL)
		return (PAPI_TEMPORARY_ERROR);

	if (service_name != NULL)
		papiAttributeListAddString(&svc->attributes, PAPI_ATTR_EXCL,
		"service-name", service_name);

	(void) papiServiceSetUserName(svc, user_name);
	(void) papiServiceSetPassword(svc, password);
	(void) papiServiceSetAuthCB(svc, authCB);
	(void) papiServiceSetAppData(svc, app_data);
	(void) papiServiceSetEncryption(svc, encryption);

	status = service_fill_in(svc, service_name);

	return (status);
}

void
papiServiceDestroy(papi_service_t handle)
{
	if (handle != NULL) {
		service_t *svc = handle;

#ifdef DEADBEEF
		if (svc->cache != NULL)
			cache_free(svc->cache);
#endif
		if (svc->uri != NULL)
			uri_free(svc->uri);
		if (svc->attributes != NULL)
			papiAttributeListFree(svc->attributes);
		free(svc);
	}
}

papi_status_t
papiServiceSetUserName(papi_service_t handle, char *user_name)
{
	service_t *svc = handle;

	if (svc == NULL)
		return (PAPI_BAD_ARGUMENT);

	return (papiAttributeListAddString(&svc->attributes, PAPI_ATTR_REPLACE,
			"user-name", user_name));
}

papi_status_t
papiServiceSetPassword(papi_service_t handle, char *password)
{
	service_t *svc = handle;

	if (svc == NULL)
		return (PAPI_BAD_ARGUMENT);

	return (papiAttributeListAddString(&svc->attributes,
		PAPI_ATTR_REPLACE, "password", password));
}

papi_status_t
papiServiceSetEncryption(papi_service_t handle,
			papi_encryption_t encryption)
{
	service_t *svc = handle;

	if (svc == NULL)
		return (PAPI_BAD_ARGUMENT);

	return (papiAttributeListAddInteger(&svc->attributes, PAPI_ATTR_REPLACE,
			"encryption", (int)encryption));
}

papi_status_t
papiServiceSetAuthCB(papi_service_t handle,
			int (*authCB)(papi_service_t svc, void *app_data))
{
	service_t *svc = handle;

	if (svc == NULL)
		return (PAPI_BAD_ARGUMENT);

	svc->authCB = (int (*)(papi_service_t svc, void *))authCB;

	return (PAPI_OK);
}

papi_status_t
papiServiceSetAppData(papi_service_t handle, void *app_data)
{
	service_t *svc = handle;

	if (svc == NULL)
		return (PAPI_BAD_ARGUMENT);

	svc->app_data = (void *)app_data;

	return (PAPI_OK);
}

char *
papiServiceGetServiceName(papi_service_t handle)
{
	service_t *svc = handle;
	char *result = NULL;

	if (svc != NULL)
		papiAttributeListGetString(svc->attributes, NULL,
				"service-name", &result);

	return (result);
}

char *
papiServiceGetUserName(papi_service_t handle)
{
	service_t *svc = handle;
	char *result = NULL;

	if (svc != NULL)
		papiAttributeListGetString(svc->attributes, NULL,
				"user-name", &result);

	return (result);

}

char *
papiServiceGetPassword(papi_service_t handle)
{
	service_t *svc = handle;
	char *result = NULL;

	if (svc != NULL)
		papiAttributeListGetString(svc->attributes, NULL,
				"password", &result);

	return (result);
}

papi_encryption_t
papiServiceGetEncryption(papi_service_t handle)
{
	service_t *svc = handle;
	papi_encryption_t result = PAPI_ENCRYPT_NEVER;

	if (svc != NULL)
		papiAttributeListGetInteger(svc->attributes, NULL,
				"encryption", (int *)&result);

	return (result);
}

void *
papiServiceGetAppData(papi_service_t handle)
{
	service_t *svc = handle;
	void *result = NULL;

	if (svc != NULL) {
		result = svc->app_data;
	}

	return (result);

}

papi_attribute_t **
papiServiceGetAttributeList(papi_service_t handle)
{
	service_t *svc = handle;
	papi_attribute_t **result = NULL;

	if (svc != NULL)
		result = svc->attributes;

	return (result);
}

char *
papiServiceGetStatusMessage(papi_service_t handle)
{
	service_t *svc = handle;
	char *result = NULL;

	if (svc != NULL) {
		papiAttributeListGetString(svc->attributes, NULL,
				"detailed-status-message", &result);
	}

	return (result);
}

void
detailed_error(service_t *svc, char *fmt, ...)
{
	if ((svc != NULL) && (fmt != NULL)) {
		va_list ap;
		char *message;
		int rv;

		va_start(ap, fmt);
		rv = vasprintf(&message, fmt, ap);
		va_end(ap);

		if (rv >= 0) {
			papiAttributeListAddString(&svc->attributes,
			    PAPI_ATTR_APPEND, "detailed-status-message",
			    message);
			free(message);
		}
	}
}
