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
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>
#include <string.h>
#include <libintl.h>
#include <papi_impl.h>

#include <tsol/label.h>

papi_status_t
papiServiceCreate(papi_service_t *handle, char *service_name,
		char *user_name, char *password,
		int (*authCB)(papi_service_t svc, void *app_data),
		papi_encryption_t encryption, void *app_data)
{
	service_t *svc = NULL;
	char *path = Lp_FIFO;

	if (handle == NULL)
		return (PAPI_BAD_ARGUMENT);

	if ((*handle = svc = calloc(1, sizeof (*svc))) == NULL)
		return (PAPI_TEMPORARY_ERROR);

	svc->md = mconnect(path, 0, 0);
	if (svc->md == NULL) {
		detailed_error(svc,
			gettext("can't connect to spooler for %s: %s"),
			(service_name ? service_name : ""), strerror(errno));
		return (PAPI_SERVICE_UNAVAILABLE);
	}

	svc->msgbuf_size = MSGMAX;
	if ((svc->msgbuf = calloc(1, svc->msgbuf_size)) == NULL)
		return (PAPI_TEMPORARY_ERROR);

	if (service_name != NULL)
		papiAttributeListAddString(&svc->attributes, PAPI_ATTR_EXCL,
				"service-name", service_name);

	(void) papiServiceSetUserName(svc, user_name);
	(void) papiServiceSetPassword(svc, password);
	(void) papiServiceSetAuthCB(svc, authCB);
	(void) papiServiceSetAppData(svc, app_data);
	(void) papiServiceSetEncryption(svc, encryption);

	return (PAPI_OK);
}

void
papiServiceDestroy(papi_service_t handle)
{
	service_t *svc = handle;

	if (svc != NULL) {
		if (svc->md != NULL)
			mdisconnect(svc->md);
		if (svc->msgbuf != NULL)
			free(svc->msgbuf);
		papiAttributeListFree(svc->attributes);
		free(svc);
	}
}

/*
 * interface for passing a peer's connection to gather sensitivity labeling
 * from for Trusted Solaris.
 */
papi_status_t
papiServiceSetPeer(papi_service_t handle, int peerfd)
{
	papi_status_t result = PAPI_OK;
	service_t *svc = handle;

	if (svc == NULL)
		return (PAPI_BAD_ARGUMENT);

	if (is_system_labeled()) {
		short status;

		if ((snd_msg(svc, S_PASS_PEER_CONNECTION) < 0) ||
		    (ioctl(svc->md->writefd, I_SENDFD, peerfd) < 0) ||
		    (rcv_msg(svc, R_PASS_PEER_CONNECTION, &status) < 0))
			status = MTRANSMITERR;

		if (status != MOK) {
			detailed_error(svc,
				gettext("failed to send peer connection: %s"),
				lpsched_status_string(status));
			result = lpsched_status_to_papi_status(status);
		}
	}

	return (result);
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

	return (papiAttributeListAddString(&svc->attributes, PAPI_ATTR_REPLACE,
				"password", password));
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

	svc->authCB = (int (*)(papi_service_t svc, void *app_data))authCB;

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

	if (svc != NULL)
		result = svc->app_data;

	return (result);
}

papi_attribute_t **
papiServiceGetAttributeList(papi_service_t handle)
{
	service_t *svc = handle;
	papi_attribute_t **result = NULL;

	if (svc != NULL) {
		lpsched_service_information(&svc->attributes);
		result = svc->attributes;
	}

	return (result);
}

char *
papiServiceGetStatusMessage(papi_service_t handle)
{
	service_t *svc = handle;
	char *result = NULL;

	if (svc != NULL)
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
