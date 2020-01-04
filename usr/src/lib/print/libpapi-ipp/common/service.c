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

/* $Id: service.c 171 2006-05-20 06:00:32Z njacobs $ */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <libintl.h>
#include <papi_impl.h>

#include <config-site.h>

http_encryption_t
http_encryption_type(papi_encryption_t encryption)
{
	switch (encryption) {
	case PAPI_ENCRYPT_IF_REQUESTED:
		return (HTTP_ENCRYPT_IF_REQUESTED);
	case PAPI_ENCRYPT_REQUIRED:
		return (HTTP_ENCRYPT_REQUIRED);
	case PAPI_ENCRYPT_ALWAYS:
		return (HTTP_ENCRYPT_ALWAYS);
	case PAPI_ENCRYPT_NEVER:
		return (HTTP_ENCRYPT_NEVER);
	default:
		; /* this should log an error */
	}

	return (HTTP_ENCRYPT_NEVER);	/* should never get here */
}

papi_status_t
service_connect(service_t *svc, char *service_name)
{
	papi_status_t result = PAPI_OK;
	int port = 631;

	if (svc == NULL)
		return (PAPI_BAD_ARGUMENT);

	if (svc->connection != NULL)	/* alread connected ? */
		return (PAPI_OK);

	if (svc->uri == NULL)
		uri_from_string(service_name, &svc->uri);

	if ((service_name != NULL) && (svc->uri == NULL)) {
		/*
		 * a name was supplied and it's not in URI form, we will
		 * try to use a "default" IPP service under the assumption
		 * that this is most likely a short-form printer name from
		 * from a papiPrinter*() or papiJob*() call and not from a
		 * papiServiceCreate() call.
		 */
		if ((service_name = getenv("PAPI_SERVICE_URI")) == NULL) {
			char *cups;

			if ((cups = getenv("CUPS_SERVER")) != NULL) {
				char buf[BUFSIZ];

				snprintf(buf, sizeof (buf),
					"ipp://%s/printers/", cups);
				service_name = strdup(buf);
			}
		}
		if (service_name == NULL)
			service_name = DEFAULT_IPP_SERVICE_URI;

		uri_from_string(service_name, &svc->uri);
	}

	if (svc->uri == NULL)
		return (PAPI_NOT_POSSIBLE);

	if (svc->uri->port != NULL)
		port = strtol(svc->uri->port, NULL, 10);

	svc->connection = httpConnectEncrypt(svc->uri->host, port,
					http_encryption_type(svc->encryption));
	if (svc->connection == NULL) {
		if (svc->uri != NULL) {
			uri_free(svc->uri);
			svc->uri = NULL;
		}
		result = PAPI_SERVICE_UNAVAILABLE;
	} else if (service_name != NULL)
		svc->name = strdup(service_name);

	return (result);
}

papi_status_t
papiServiceCreate(papi_service_t *handle, char *service_name,
		char *user_name, char *password,
		int (*authCB)(papi_service_t svc, void *app_data),
		papi_encryption_t encryption, void *app_data)
{
	papi_status_t result = PAPI_NOT_POSSIBLE;
	service_t *svc = NULL;
	char *encoding = getenv("HTTP_TRANSFER_ENCODING");

	if (handle == NULL)
		return (PAPI_BAD_ARGUMENT);

	if ((*handle = svc = calloc(1, sizeof (*svc))) == NULL)
		return (PAPI_TEMPORARY_ERROR);

	if (user_name != NULL)
		svc->user = strdup(user_name);

	if (password != NULL)
		svc->password = strdup(password);

	svc->encryption = encryption;

	if (authCB != NULL)
		svc->authCB = authCB;

	if (app_data != NULL)
		svc->app_data = app_data;

	if ((encoding != NULL) && (strcasecmp(encoding, "content-length") == 0))
		svc->transfer_encoding = TRANSFER_ENCODING_LENGTH;
	else
		svc->transfer_encoding = TRANSFER_ENCODING_CHUNKED;

	if (service_name != NULL) {
		result = service_connect(svc, service_name);
	} else
		result = PAPI_OK;

	return (result);
}

void
papiServiceDestroy(papi_service_t handle)
{
	if (handle != NULL) {
		service_t *svc = handle;

		if (svc->attributes != NULL)
			papiAttributeListFree(svc->attributes);
		if (svc->name != NULL)
			free(svc->name);
		if (svc->user != NULL)
			free(svc->user);
		if (svc->password != NULL)
			free(svc->password);
		if (svc->uri != NULL)
			uri_free(svc->uri);
		if (svc->post != NULL)
			free(svc->post);
		if (svc->connection != NULL)
			httpClose(svc->connection);

		free(handle);
	}
}

papi_status_t
papiServiceSetUserName(papi_service_t handle, char *user_name)
{
	papi_status_t result = PAPI_OK;

	if (handle != NULL) {
		service_t *svc = handle;

		if (svc->user != NULL)
			free(svc->user);
		svc->user = NULL;
		if (user_name != NULL)
			svc->user = strdup(user_name);
	} else
		result = PAPI_BAD_ARGUMENT;

	return (result);
}

papi_status_t
papiServiceSetPassword(papi_service_t handle, char *password)
{
	papi_status_t result = PAPI_OK;

	if (handle != NULL) {
		service_t *svc = handle;

		if (svc->password != NULL)
			free(svc->password);
		svc->password = NULL;
		if (password != NULL)
			svc->password = strdup(password);
	} else
		result = PAPI_BAD_ARGUMENT;

	return (result);
}

papi_status_t
papiServiceSetEncryption(papi_service_t handle,
			papi_encryption_t encryption)
{
	papi_status_t result = PAPI_OK;

	if (handle != NULL) {
		service_t *svc = handle;

		svc->encryption = encryption;
		httpEncryption(svc->connection,
				(http_encryption_t)svc->encryption);
	} else
		result = PAPI_BAD_ARGUMENT;

	return (result);
}

papi_status_t
papiServiceSetAuthCB(papi_service_t handle,
			int (*authCB)(papi_service_t svc, void *app_data))
{
	papi_status_t result = PAPI_OK;

	if (handle != NULL) {
		service_t *svc = handle;

		svc->authCB = authCB;
	} else
		result = PAPI_BAD_ARGUMENT;

	return (result);
}


papi_status_t
papiServiceSetAppData(papi_service_t handle, void *app_data)
{
	papi_status_t result = PAPI_OK;

	if (handle != NULL) {
		service_t *svc = handle;

		svc->app_data = (void *)app_data;
	} else
		result = PAPI_BAD_ARGUMENT;

	return (result);
}

char *
papiServiceGetServiceName(papi_service_t handle)
{
	char *result = NULL;

	if (handle != NULL) {
		service_t *svc = handle;

		result = svc->name;
	}

	return (result);
}

char *
papiServiceGetUserName(papi_service_t handle)
{
	char *result = NULL;

	if (handle != NULL) {
		service_t *svc = handle;

		result = svc->user;
	}

	return (result);
}

char *
papiServiceGetPassword(papi_service_t handle)
{
	char *result = NULL;

	if (handle != NULL) {
		service_t *svc = handle;

		result = svc->password;
	}

	return (result);
}

papi_encryption_t
papiServiceGetEncryption(papi_service_t handle)
{
	papi_encryption_t result = PAPI_ENCRYPT_NEVER;

	if (handle != NULL) {
		service_t *svc = handle;

		result = svc->encryption;
	}

	return (result);
}

void *
papiServiceGetAppData(papi_service_t handle)
{
	void *result = NULL;

	if (handle != NULL) {
		service_t *svc = handle;

		result = svc->app_data;
	}

	return (result);
}

papi_attribute_t **
papiServiceGetAttributeList(papi_service_t handle)
{
	papi_attribute_t **result = NULL;
	service_t *svc = handle;

	if (handle != NULL)
		result = svc->attributes;

	return (result);
}

char *
papiServiceGetStatusMessage(papi_service_t handle)
{
	char *result = NULL;
	service_t *svc = handle;

	papiAttributeListGetString(svc->attributes, NULL,
					"detailed-status-message", &result);

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
