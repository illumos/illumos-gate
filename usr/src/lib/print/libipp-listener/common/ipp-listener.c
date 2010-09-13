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

/* $Id: ipp-listener.c 146 2006-03-24 00:26:54Z njacobs $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <assert.h>
#include <errno.h>
#include <syslog.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/systeminfo.h>

#include <papi.h>
#include <ipp-listener.h>
#include <uri.h>

typedef papi_status_t (ipp_handler_t)(papi_service_t svc,
					papi_attribute_t **request,
					papi_attribute_t ***response,
					ipp_reader_t iread, void *fd);

/*
 * protocol request handlers are inserted below.  The handler must be
 * declared extern immediately below this comment and then an entry
 * must be inserted in the "handlers" table a little further down.
 */
extern ipp_handler_t ipp_print_job;
extern ipp_handler_t ipp_validate_job;
extern ipp_handler_t ipp_create_job;
extern ipp_handler_t ipp_get_printer_attributes;
extern ipp_handler_t ipp_get_jobs;
extern ipp_handler_t ipp_pause_printer;
extern ipp_handler_t ipp_resume_printer;
extern ipp_handler_t ipp_disable_printer;
extern ipp_handler_t ipp_enable_printer;
extern ipp_handler_t ipp_purge_jobs;
extern ipp_handler_t ipp_send_document;
extern ipp_handler_t ipp_cancel_job;
extern ipp_handler_t ipp_get_job_attributes;
extern ipp_handler_t ipp_release_job;
extern ipp_handler_t ipp_hold_job;
extern ipp_handler_t ipp_restart_job;
extern ipp_handler_t ipp_set_job_attributes;
extern ipp_handler_t ipp_set_printer_attributes;
extern ipp_handler_t cups_get_default;
extern ipp_handler_t cups_get_printers;
extern ipp_handler_t cups_get_classes;
extern ipp_handler_t cups_accept_jobs;
extern ipp_handler_t cups_reject_jobs;
extern ipp_handler_t cups_move_job;

/* ARGSUSED0 */
static papi_status_t
default_handler(papi_service_t svc, papi_attribute_t **request,
		papi_attribute_t ***response, ipp_reader_t iread, void *fd)
{
	int result = (int)PAPI_INTERNAL_ERROR;

	if (response != NULL)
		(void) papiAttributeListGetInteger(*response, NULL,
					"status-code", &result);

	return ((papi_status_t)result);
}

static struct {
	int16_t	id;
	char *name;
	ipp_handler_t *function;
	enum { OP_REQUIRED, OP_OPTIONAL, OP_VENDOR } type;
} handlers[] = {
	/* Printer Operations */
	{ 0x0002, "print-job",			ipp_print_job,	OP_REQUIRED },
	{ 0x0003, "print-uri",			NULL,		OP_OPTIONAL },
	{ 0x0004, "validate-job",		ipp_validate_job,
								OP_REQUIRED },
	{ 0x0005, "create-job",			ipp_create_job,	OP_OPTIONAL },
	{ 0x000a, "get-jobs",			ipp_get_jobs,	OP_REQUIRED },
	{ 0x000b, "get-printer-attributes",	ipp_get_printer_attributes,
								OP_REQUIRED },
	{ 0x0010, "pause-printer",		ipp_pause_printer,
								OP_OPTIONAL },
	{ 0x0011, "resume-printer",		ipp_resume_printer,
								OP_OPTIONAL },
	{ 0x0012, "purge-jobs",			ipp_purge_jobs,	OP_OPTIONAL },
	{ 0x0013, "set-printer-attributes",	ipp_set_printer_attributes,
								OP_OPTIONAL },
	{ 0x0014, "set-job-attributes",		ipp_set_job_attributes,
								OP_OPTIONAL },
	{ 0x0022, "enable-printer",		ipp_enable_printer,
								OP_OPTIONAL },
	{ 0x0023, "disable-printer",		ipp_disable_printer,
								OP_OPTIONAL },
	/* Job Operations */
	{ 0x0006, "send-document",		ipp_send_document,
								OP_OPTIONAL },
	{ 0x0007, "send-uri",			NULL,		OP_OPTIONAL },
	{ 0x0008, "cancel-job",			ipp_cancel_job,	OP_REQUIRED },
	{ 0x0009, "get-job-attributes",		ipp_get_job_attributes,
								OP_REQUIRED },
	{ 0x000c, "hold-job",			ipp_hold_job,	OP_OPTIONAL },
	{ 0x000d, "release-job",		ipp_release_job,
								OP_OPTIONAL },
	{ 0x000e, "restart-job",		ipp_restart_job,
								OP_OPTIONAL },
	/* Other Operations */
	{ 0x4001, "cups-get-default",		cups_get_default,
								OP_VENDOR },
	{ 0x4002, "cups-get-printers",		cups_get_printers,
								OP_VENDOR },
	{ 0x4005, "cups-get-classes",		cups_get_classes,
								OP_VENDOR },
	{ 0x4008, "cups-accept-jobs",		cups_accept_jobs,
								OP_VENDOR },
	{ 0x4009, "cups-reject-jobs",		cups_reject_jobs,
								OP_VENDOR },
	{ 0x400D, "cups-move-job",		cups_move_job,	OP_VENDOR },
	{ 0, NULL, NULL, OP_VENDOR }
};

static int
ipp_operation_name_to_index(char *name)
{
	int i;

	for (i = 0; handlers[i].name != NULL; i++)
		if (strcasecmp(name, handlers[i].name) == 0)
			return (i);

	return (-1);
}

static int
ipp_operation_id_to_index(int16_t id)
{
	int i;

	for (i = 0; handlers[i].name != NULL; i++)
		if (id == handlers[i].id)
			return (i);

	return (-1);
}

static ipp_handler_t *
ipp_operation_handler(papi_attribute_t **request, papi_attribute_t ***response)
{
	int id = 0;
	int index;
	papi_attribute_t **ops = NULL;
	papi_status_t status;
	char configured = PAPI_FALSE;

	/* get the operation from the request */
	status = papiAttributeListGetInteger(request, NULL,
				"operation-id", &id);
	if (status != PAPI_OK) {
		ipp_set_status(response, PAPI_BAD_ARGUMENT,
			"no operation specified in request");
		return (default_handler);
	}

	/* find the operation in the handler table */
	index = ipp_operation_id_to_index(id);
#ifdef DEBUG
	if (index == -1)
		fprintf(stderr, "Operation: 0x%4.4x\n", id);
	else
		fprintf(stderr, "Operation: 0x%4.4x(%s)\n", id,
			handlers[index].name);
	fflush(stderr);
#endif

	if ((index == -1) || (handlers[index].function == NULL)) {
		ipp_set_status(response, PAPI_OPERATION_NOT_SUPPORTED,
			"operation (0x%4.4x) not implemented by server",
			id);
		return (default_handler);
	}

	/* find the configured operations */
	status = papiAttributeListGetCollection(request, NULL,
				"operations", &ops);
	if (status != PAPI_OK) {	/* this should not be possible */
		ipp_set_status(response, PAPI_INTERNAL_ERROR,
			"sofware error, no operations configured");
		return (default_handler);
	}

	/* check if the requested operation is configured */
	status = papiAttributeListGetBoolean(ops, NULL,
				handlers[index].name, &configured);
	if ((status != PAPI_OK) || (configured != PAPI_TRUE)) {
		ipp_set_status(response, PAPI_OPERATION_NOT_SUPPORTED,
			"operation (%s 0x%4.4x) not enabled on server",
			handlers[index].name, id);
		return (default_handler);
	}

	return (handlers[index].function);
}

static char
type_to_boolean(char *type)
{
	char result = PAPI_FALSE;

	if ((strcasecmp(type, "true") == 0) ||
	    (strcasecmp(type, "yes") == 0) ||
	    (strcasecmp(type, "on") == 0) ||
	    (strcasecmp(type, "enable") == 0))
		result = PAPI_TRUE;

	return (result);
}

static papi_status_t
ipp_configure_required_operations(papi_attribute_t ***list, char boolean)
{
	papi_status_t result = PAPI_OK;
	int i;

	for (i = 0; ((result == PAPI_OK) && (handlers[i].name != NULL)); i++)
		if (handlers[i].type == OP_REQUIRED)
			result = papiAttributeListAddBoolean(list,
					PAPI_ATTR_REPLACE, handlers[i].name,
					boolean);

	return (result);

}

static papi_status_t
ipp_configure_all_operations(papi_attribute_t ***list, char boolean)
{
	papi_status_t result = PAPI_OK;
	int i;

	for (i = 0; ((result == PAPI_OK) && (handlers[i].name != NULL)); i++)
		result = papiAttributeListAddBoolean(list, PAPI_ATTR_REPLACE,
				handlers[i].name, boolean);

	return (result);
}

papi_status_t
ipp_configure_operation(papi_attribute_t ***list, char *operation, char *type)
{
	papi_status_t result = PAPI_OPERATION_NOT_SUPPORTED;
	char boolean = PAPI_FALSE;

	if ((list == NULL) || (operation == NULL) || (type == NULL))
		return (PAPI_BAD_ARGUMENT);

	boolean = type_to_boolean(type);

	if (strcasecmp(operation, "all") == 0) {
		result = ipp_configure_all_operations(list, boolean);
	} else if (strcasecmp(operation, "required") == 0) {
		result = ipp_configure_required_operations(list, boolean);
	} else if (ipp_operation_name_to_index(operation) != -1) {
		result = papiAttributeListAddBoolean(list, PAPI_ATTR_REPLACE,
							operation, boolean);
	}

	return (result);
}

void
ipp_operations_supported(papi_attribute_t ***list, papi_attribute_t **request)
{
	papi_attribute_t **group = NULL;

	(void) papiAttributeListGetCollection(request, NULL,
				"operations", &group);
	if (group != NULL) {
		int i;

		for (i = 0; handlers[i].name != NULL; i++) {
			char boolean = PAPI_FALSE;
			(void) papiAttributeListGetBoolean(group, NULL,
					handlers[i].name, &boolean);

			if (boolean == PAPI_TRUE)
				(void) papiAttributeListAddInteger(list,
					PAPI_ATTR_APPEND,
					"operations-supported",
					handlers[i].id);
		}
	}
}

static papi_status_t
ipp_initialize_response(papi_attribute_t **request,
			papi_attribute_t ***response)
{
	papi_attribute_t **operational = NULL;
	int i;

	if ((request == NULL) || (response == NULL))
		return (PAPI_BAD_ARGUMENT);

	/* If the response was initialized, start over */
	if (*response != NULL) {
		papiAttributeListFree(*response);
		*response = NULL;
	}

	/* Add the basic ipp header information to the response */
	(void) papiAttributeListGetInteger(request, NULL, "version-major", &i);
	(void) papiAttributeListAddInteger(response, PAPI_ATTR_REPLACE,
					"version-major", i);
	(void) papiAttributeListGetInteger(request, NULL, "version-minor", &i);
	(void) papiAttributeListAddInteger(response, PAPI_ATTR_REPLACE,
					"version-minor", i);

	(void) papiAttributeListGetInteger(request, NULL, "request-id", &i);
	(void) papiAttributeListAddInteger(response, PAPI_ATTR_REPLACE,
					"request-id", i);

	/* Add a default operational attributes group to the response */
	(void) papiAttributeListAddString(&operational, PAPI_ATTR_EXCL,
			"attributes-charset", "utf-8");
	(void) papiAttributeListAddString(&operational, PAPI_ATTR_EXCL,
			"attributes-natural-language", "en-us");

	(void) papiAttributeListAddCollection(response, PAPI_ATTR_REPLACE,
				"operational-attributes-group", operational);
	papiAttributeListFree(operational);

	return (PAPI_OK);
}

/* simplistic check for cyclical service references */
static int
cyclical_service_check(char *svc_name, int port)
{
	papi_attribute_t **list;
	char buf[BUFSIZ];
	uri_t *uri = NULL;
	char *s = NULL;

	/* was there a service_uri? */
	if (svc_name == NULL)
		return (0);

	if ((list = getprinterbyname(svc_name, NULL)) == NULL)
		return (0);	/* if it doesnt' resolve, we will fail later */

	papiAttributeListGetString(list, NULL, "printer-uri-supported", &s);
	if ((s == NULL) || (strcasecmp(svc_name, s) != 0))
		return (0); 	/* they don't match */

	/* is it in uri form? */
	if (uri_from_string(s, &uri) < 0)
		return (0);

	if ((uri == NULL) || (uri->scheme == NULL) || (uri->host == NULL)) {
		uri_free(uri);
		return (0);
	}

	/* is it ipp form */
	if (strcasecmp(uri->scheme, "ipp") != 0) {
		uri_free(uri);
		return (0);
	}

	/* does the host match up */
	if (is_localhost(uri->host) != 0) {
		uri_free(uri);
		return (0);
	}

	/* does the port match our own */
	if (((uri->port == NULL) && (port != 631)) ||
	    ((uri->port != NULL) && (atoi(uri->port) != port))) {
		uri_free(uri);
		return (0);
	}

	uri_free(uri);

	return (1);
}

static papi_status_t
print_service_connect(papi_service_t *svc, papi_attribute_t **request,
		papi_attribute_t ***response)
{
	papi_status_t status;
	papi_attribute_t **operational = NULL;
	char *printer_uri = NULL;
	char *svc_name = NULL;
	char *user = NULL;
	int port = 631;

	/* Get the operational attributes group from the request */
	(void) papiAttributeListGetCollection(request, NULL,
				"operational-attributes-group", &operational);

	/* get the user name */
	(void) papiAttributeListGetString(request, NULL, "default-user", &user);
	(void) papiAttributeListGetString(operational, NULL,
				"requesting-user-name", &user);

	/* get the printer or service name */
	(void) papiAttributeListGetString(request, NULL,
				"default-service", &svc_name);
	get_printer_id(operational, &svc_name, NULL);

	/* get the port that we are listening on */
	(void) papiAttributeListGetInteger(request, NULL, "uri-port", &port);

	if (cyclical_service_check(svc_name, port) != 0) {
		status = PAPI_NOT_POSSIBLE;
		ipp_set_status(response, status, "printer-uri is cyclical");
		return (status);
	}

	status = papiServiceCreate(svc, svc_name, user, NULL, NULL,
					PAPI_ENCRYPT_NEVER, NULL);
	if (status != PAPI_OK) {
		ipp_set_status(response, status, "print service: %s",
				papiStatusString(status));
		return (status);
	}

	/*
	 * Trusted Solaris can't be trusting of intermediaries.  Pass
	 * the socket connection to the print service to retrieve the
	 * sensativity label off of a multi-level port.
	 */
	{
		int fd = -1;

		(void) papiAttributeListGetInteger(request, NULL,
					"peer-socket", &fd);
		if (fd != -1)
			papiServiceSetPeer(*svc, fd);
	}

	return (status);
}

papi_status_t
ipp_process_request(papi_attribute_t **request, papi_attribute_t ***response,
	ipp_reader_t iread, void *fd)
{
	papi_status_t result = PAPI_OK;

	ipp_initialize_response(request, response);

#ifdef DEBUG
	fprintf(stderr, "REQUEST:");
	papiAttributeListPrint(stderr, request, " %d  ", getpid());
	fprintf(stderr, "\n");
#endif

	/* verify that the request is "well-formed" */
	if ((result = ipp_validate_request(request, response)) == PAPI_OK) {
		papi_service_t svc = NULL;
		ipp_handler_t *handler;

		result = print_service_connect(&svc, request, response);
		handler = ipp_operation_handler(request, response);

		/* process the request */
		if ((result == PAPI_OK) && (handler != NULL))
			result = (handler)(svc, request, response, iread, fd);
#ifdef DEBUG
		fprintf(stderr, "RESULT: %s\n", papiStatusString(result));
#endif
		papiServiceDestroy(svc);
	}

	(void) papiAttributeListAddInteger(response, PAPI_ATTR_EXCL,
				"status-code", result);
	massage_response(request, *response);

#ifdef DEBUG
	fprintf(stderr, "RESPONSE:");
	papiAttributeListPrint(stderr, *response, " %d  ", getpid());
	fprintf(stderr, "\n");
#endif

	return (result);
}
