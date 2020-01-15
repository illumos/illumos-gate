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
 *
 */

/* $Id: service.c 172 2006-05-24 20:54:00Z njacobs $ */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <libintl.h>
#include <papi_impl.h>
#include <config-site.h>

static int
interposed_auth_callback(papi_service_t handle, void *app_data)
{
	int result = -1;
	service_t *svc = app_data;

	if (svc != NULL)
		result = svc->authCB(svc, svc->app_data);

	return (result);
}

static char *
default_service_uri(char *fallback)
{
	char *result = NULL;

	if (getuid() == geteuid())
		result = getenv("PAPI_SERVICE_URI");

	if (result == NULL) {
		char *cups;

		if ((cups = getenv("CUPS_SERVER")) != NULL) {
			char buf[BUFSIZ];

			snprintf(buf, sizeof (buf), "ipp://%s/printers/", cups);
			result = strdup(buf);
		}
	}

	if (result == NULL)
		result = fallback;

	return (result);
}

static char *
default_print_service()
{
	static char *result = NULL;

	if (result == NULL) {
		char *service_uri = default_service_uri(DEFAULT_SERVICE_URI);
		uri_t *uri = NULL;

		if (uri_from_string(service_uri, &uri) != -1)
			result = strdup(uri->scheme);

		if (uri != NULL)
			uri_free(uri);
	}

	return (result);
}

static papi_status_t
service_load(service_t *svc, char *name)
{
	papi_status_t result;
	char *scheme = default_print_service();

	if (svc->so_handle != NULL)	/* already loaded */
		return (PAPI_OK);

	if (name == NULL)		/* no info, can't load yet */
		return (PAPI_OK);

	/* Lookup the printer in the configuration DB */
	svc->attributes = getprinterbyname((char *)name, NULL);

	if (svc->attributes != NULL) {
		char *tmp = NULL;

		/* Printer found (or was a URI), use the attribute data */
		papiAttributeListGetString(svc->attributes, NULL,
					"printer-uri-supported", &tmp);
		if (tmp != NULL)
			svc->name = strdup(tmp);

		/* parse the URI and set the scheme(print service) */
		if (uri_from_string(svc->name, &svc->uri) != -1)
			scheme = (svc->uri)->scheme;

		/* override the scheme if it was in the attributes */
		papiAttributeListGetString(svc->attributes, NULL,
					"print-service-module", &scheme);

	} else	/* not found, assume it is the actual print service name */
		scheme = name;

	result = psm_open(svc, scheme);
	switch (result) {
	case PAPI_OK:
		break;	/* no error */
	case PAPI_URI_SCHEME:
		result = PAPI_NOT_FOUND;
#ifdef DEBUG
		detailed_error(svc, "Unable to load service for: %s", name);
#endif
		break;
	default:	/* set the detailed message */
		detailed_error(svc, "Unable to load service (%s) for: %s",
				scheme, name);
	}

	return (result);
}

static papi_status_t
service_send_peer(service_t *svc)
{
	papi_status_t result = PAPI_OK;

	if ((svc->peer_fd != -1) && (svc->so_handle != NULL) &&
	    (svc->svc_handle != NULL)) {
		papi_status_t (*f)();

		f = (papi_status_t (*)())psm_sym(svc, "papiServiceSetPeer");

		if (f != NULL)
			result = f(svc->svc_handle, svc->peer_fd);
	}

	return (result);
}

papi_status_t
service_connect(service_t *svc, char *name)
{
	papi_status_t result = PAPI_NOT_POSSIBLE;

	/* if there is no print service module loaded, try and load one. */
	if (svc->so_handle == NULL)
		result = service_load(svc, name);
	else if ((svc->name == NULL) && (name != NULL))
		svc->name = strdup(name);

	/*
	 * the print service module is loaded, but we don't have a service
	 * handle.
	 */
	if (svc->so_handle != NULL) {
		papi_status_t (*f)();

		if (svc->svc_handle != NULL)	/* already connected? */
			return (PAPI_OK);

		f = (papi_status_t (*)())psm_sym(svc, "papiServiceCreate");

		if (f != NULL) {
			char *user = svc->user;
			char *password = svc->password;

			/* if no API user, try the URI user */
			if ((user == NULL) && (svc->uri != NULL))
				user = (svc->uri)->user;
			/* if no API password, try the URI password */
			if ((password == NULL) && (svc->uri != NULL))
				password = (svc->uri)->password;

			result = f(&svc->svc_handle, svc->name, user, password,
					(svc->authCB ? interposed_auth_callback
						: NULL),
					svc->encryption, svc);
			(void) service_send_peer(svc);
		}
	}

	return (result);
}

papi_status_t
papiServiceCreate(papi_service_t *handle, char *service_name, char *user_name,
		char *password,
		int (*authCB)(papi_service_t svc, void *app_data),
		papi_encryption_t encryption, void *app_data)
{
	papi_status_t result = PAPI_NOT_POSSIBLE;
	service_t *svc = NULL;
	uri_t *u = NULL;

	if (handle == NULL)
		return (PAPI_BAD_ARGUMENT);

	if ((*handle = svc = calloc(1, sizeof (*svc))) == NULL)
		return (PAPI_TEMPORARY_ERROR);

	svc->peer_fd = -1;

	if (user_name != NULL)
		svc->user = strdup(user_name);

	if (password != NULL)
		svc->password = strdup(password);

	svc->encryption = encryption;

	if (authCB != NULL)
		svc->authCB = authCB;

	if (app_data != NULL)
		svc->app_data = app_data;

	/* If not specified, get a "default" service from the environment */
	if (service_name == NULL)
		service_name = default_service_uri(NULL);

	if (service_name != NULL) {
		result = service_load(svc, service_name);
		/* if the psm loaded and the svc contains a URI, connect */
		if ((result == PAPI_OK) && (svc->uri != NULL))
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

		if (svc->so_handle != NULL) {
			if (svc->svc_handle != NULL) {
				void (*f)();

				f = (void (*)())psm_sym(svc,
							"papiServiceDestroy");
				f(svc->svc_handle);
			}
			psm_close(svc->so_handle);
		}
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

		free(handle);
	}
}

papi_status_t
papiServiceSetPeer(papi_service_t handle, int fd)
{
	papi_status_t result = PAPI_OK;

	if (handle != NULL) {
		service_t *svc = handle;

		svc->peer_fd = fd;
		result = service_send_peer(svc);
	} else
		result = PAPI_BAD_ARGUMENT;

	return (result);
}

papi_status_t
papiServiceSetUserName(papi_service_t handle, char *user_name)
{
	papi_status_t result = PAPI_OK;

	if (handle != NULL) {
		service_t *svc = handle;
		papi_status_t (*f)();

		if (svc->user != NULL)
			free(svc->user);
		if (user_name != NULL)
			svc->user = strdup(user_name);
		f = (papi_status_t (*)())psm_sym(svc, "papiServiceSetUserName");
		if (f != NULL)
			result = f(svc->svc_handle, user_name);
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
		papi_status_t (*f)();

		if (svc->password != NULL)
			free(svc->password);
		if (password != NULL)
			svc->password = strdup(password);
		f = (papi_status_t (*)())psm_sym(svc, "papiServiceSetPassword");
		if (f != NULL)
			result = f(svc->svc_handle, password);
	} else
		result = PAPI_BAD_ARGUMENT;

	return (result);
}

papi_status_t
papiServiceSetEncryption(papi_service_t handle, papi_encryption_t encryption)
{
	papi_status_t result = PAPI_OK;

	if (handle != NULL) {
		service_t *svc = handle;
		papi_status_t (*f)();

		svc->encryption = encryption;
		f = (papi_status_t (*)())psm_sym(svc,
						"papiServiceSetEncryption");
		if (f != NULL)
			result = f(svc->svc_handle, encryption);
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
		papi_status_t (*f)();

		svc->authCB = authCB;
		f = (papi_status_t (*)())psm_sym(svc, "papiServiceSetAuthCB");
		if (f != NULL)
			result = f(svc->svc_handle, interposed_auth_callback);
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
		papi_status_t (*f)();

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
		char *(*f)();

		f = (char *(*)())psm_sym(svc, "papiServiceGetServiceName");
		if (f != NULL)
			result = f(svc->svc_handle);
		if (result == NULL)
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
		char *(*f)();

		f = (char *(*)())psm_sym(svc, "papiServiceGetUserName");
		if (f != NULL)
			result = f(svc->svc_handle);
		if (result == NULL)
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
		char *(*f)();

		f = (char *(*)())psm_sym(svc, "papiServiceGetPassword");
		if (f != NULL)
			result = f(svc->svc_handle);
		if (result == NULL)
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
		papi_encryption_t (*f)();

		f = (papi_encryption_t (*)())psm_sym(svc,
						"papiServiceGetEncryption");
		if (f != NULL)
			result = f(svc->svc_handle);
		if (result == PAPI_ENCRYPT_NEVER)
			result = svc->encryption;
	}

	return (result);
}

void *
papiServiceGetAppData(papi_service_t handle)
{
	void *result = NULL;
	service_t *svc = handle;

	if (handle != NULL)
		result = svc->app_data;

	return (result);
}

papi_attribute_t **
papiServiceGetAttributeList(papi_service_t handle)
{
	papi_attribute_t **result = NULL;
	service_t *svc = handle;

	if (handle != NULL) {
		papi_attribute_t **(*f)();

		if (svc->so_handle == NULL) {
			char *uri = default_service_uri(DEFAULT_SERVICE_URI);

			if (service_connect(svc, uri) != PAPI_OK)
				return (NULL);
		}

		f = (papi_attribute_t **(*)())psm_sym(svc,
					"papiServiceGetAttributeList");
		if (f != NULL)
			result = f(svc->svc_handle);
	} else
		result = svc->attributes;

	return (result);
}

char *
papiServiceGetStatusMessage(papi_service_t handle)
{
	char *result = NULL;
	service_t *svc = handle;

	if (handle != NULL) {
		char *(*f)();

		f = (char *(*)())psm_sym(svc, "papiServiceGetStatusMessage");
		if (f != NULL)
			result = f(svc->svc_handle);
	}
	if (result == NULL) {
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
#ifdef DEBUG
			fprintf(stderr, "detailed_error(%s)\n", message);
#endif
			free(message);
		}
	}
}
