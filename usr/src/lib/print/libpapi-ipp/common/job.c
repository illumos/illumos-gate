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
 *
 */

/* $Id: job.c 148 2006-04-25 16:54:17Z njacobs $ */


/*LINTLIBRARY*/

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <papi_impl.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifndef OPID_CUPS_MOVE_JOB
#define	OPID_CUPS_MOVE_JOB 0x400D
#endif

void
papiJobFree(papi_job_t job)
{
	job_t *tmp = (job_t *)job;

	if (tmp != NULL) {
		if (tmp->attributes != NULL)
			papiAttributeListFree(tmp->attributes);
		free(tmp);
	}
}

void
papiJobListFree(papi_job_t *jobs)
{
	if (jobs != NULL) {
		int i;

		for (i = 0; jobs[i] != NULL; i++)
			papiJobFree(jobs[i]);
		free(jobs);
	}
}

papi_attribute_t **
papiJobGetAttributeList(papi_job_t job)
{
	papi_attribute_t **result = NULL;
	job_t *j = job;

	if (j != NULL)
		result = j->attributes;

	return (result);
}

char *
papiJobGetPrinterName(papi_job_t job)
{
	char *result = NULL;
	job_t *j = job;

	if (j != NULL)
		(void) papiAttributeListGetString(j->attributes, NULL,
		    "printer-name", &result);

	return (result);
}

int32_t
papiJobGetId(papi_job_t job)
{
	int32_t result = -1;
	job_t *j = job;

	if (j != NULL)
		(void) papiAttributeListGetInteger(j->attributes, NULL,
		    "job-id", &result);

	return (result);
}

papi_job_ticket_t *
papiJobGetJobTicket(papi_job_t job)
{
	papi_job_ticket_t *result = NULL;

	return (result);
}

static void
populate_job_request(service_t *svc, papi_attribute_t ***request,
		papi_attribute_t **attributes, char *printer, uint16_t type)
{
	papi_attribute_t **operational = NULL, **job = NULL;
	static char *operational_names[] = {
		"job-name", "ipp-attribute-fidelity", "document-name",
		"compression", "document-format", "document-natural-language",
		"job-k-octets", "job-impressions", "job-media-sheets", NULL
	};

	/* create the base IPP request */
	ipp_initialize_request(svc, request, type);

	/* create an operational attributes group */
	ipp_initialize_operational_attributes(svc, &operational, printer, -1);

	/* split up the attributes into operational and job attributes */
	split_and_copy_attributes(operational_names, attributes,
	    &operational, &job);

	/* add the operational attributes group to the request */
	papiAttributeListAddCollection(request, PAPI_ATTR_REPLACE,
	    "operational-attributes-group", operational);
	papiAttributeListFree(operational);

	/* add the job attributes group to the request */
	if (job != NULL) {
		papiAttributeListAddCollection(request, PAPI_ATTR_REPLACE,
		    "job-attributes-group", job);
		papiAttributeListFree(job);
	}
}

static papi_status_t
send_document_uri(service_t *svc, char *file, papi_attribute_t **attributes,
		char *printer, int32_t id, char last, uint16_t type)
{
	papi_status_t result = PAPI_INTERNAL_ERROR;
	papi_attribute_t **request = NULL, **op = NULL, **response = NULL;

	/* create the base IPP request */
	ipp_initialize_request(svc, &request, type);

	/* create an operational attributes group */
	ipp_initialize_operational_attributes(svc, &op, printer, id);

	papiAttributeListAddString(&op, PAPI_ATTR_REPLACE, "document-name",
	    file);
	papiAttributeListAddBoolean(&op, PAPI_ATTR_REPLACE, "last-document",
	    (last ? PAPI_TRUE : PAPI_FALSE));
	papiAttributeListAddCollection(&request, PAPI_ATTR_REPLACE,
	    "operational-attributes-group", op);
	papiAttributeListFree(op);

	/* send the IPP request to the server */
	result = ipp_send_request_with_file(svc, request, &response, file);
	papiAttributeListFree(request);
	papiAttributeListFree(response);

	return (result);
}

typedef enum {_WITH_DATA, _BY_REFERENCE, _VALIDATE} call_type_t;

papi_status_t
internal_job_submit(papi_service_t handle, char *printer,
		papi_attribute_t **job_attributes,
		papi_job_ticket_t *job_ticket,
		char **files, papi_job_t *job,
		call_type_t call_type)
{
	papi_status_t result = PAPI_INTERNAL_ERROR;
	service_t *svc = handle;
	struct stat statbuf;
	job_t *j = NULL;
	int i;
	uint16_t req_type = OPID_PRINT_JOB;
	uint16_t data_type = OPID_SEND_DOCUMENT;
	papi_attribute_t **request = NULL, **response = NULL;

	if ((svc == NULL) || (printer == NULL) || (job == NULL))
		return (PAPI_BAD_ARGUMENT);

	switch (call_type) {
	case _BY_REFERENCE:
#ifdef SOME_DAY_WE_WILL_BE_ABLE_TO_USE_URIS_FOR_JOB_DATA
		/*
		 * For the time being, this is disabled.  There are a number
		 * of issues to be dealt with before we can send a URI
		 * across the network to the server.  For example, the file
		 * name(s) passed in are most likely relative to the current
		 * hosts filesystem.  They also most likely will require some
		 * form of authentication information to be passed with the
		 * URI.
		 */
		req_type = OPID_PRINT_URI;
		req_type = OPID_SEND_URI;
#endif
		/* fall-through */
	case _WITH_DATA:
		if ((files == NULL) || (files[0] == NULL))
			return (PAPI_BAD_ARGUMENT);

		if (files[1] != NULL)	/* more than 1 file */
			req_type = OPID_CREATE_JOB;

		break;
	case _VALIDATE:
		req_type = OPID_VALIDATE_JOB;
		/* if we have files, validate access to them */
		if (files != NULL) {
			for (i = 0; files[i] != NULL; i++) {
				if (access(files[i], R_OK) < 0) {
					detailed_error(svc, "%s: %s", files[i],
					    strerror(errno));
					return (PAPI_DOCUMENT_ACCESS_ERROR);
				}

				if (strcmp("standard input", files[i]) != 0) {
					stat(files[i], &statbuf);
					if (statbuf.st_size == 0) {
						detailed_error(svc,
						    "Zero byte (empty) file: "
						    "%s",
						    files[i]);
						return (PAPI_BAD_ARGUMENT);
					}
				}
			}
			files = NULL;
		}
		break;
	}

	/* if we are already connected, use that connection. */
	if (svc->connection == NULL)
		if ((result = service_connect(svc, printer)) != PAPI_OK)
			return (result);

	if ((*job = j = calloc(1, sizeof (*j))) == NULL)
		return (PAPI_TEMPORARY_ERROR);

	/* create IPP request */
	populate_job_request(svc, &request, job_attributes, printer, req_type);

	switch (req_type) {
	case OPID_PRINT_JOB:
		result = ipp_send_request_with_file(svc, request, &response,
		    files[0]);
		break;
	case OPID_CREATE_JOB:
	case OPID_VALIDATE_JOB:
	case OPID_PRINT_URI:
		result = ipp_send_request(svc, request, &response);
		break;
	}
	papiAttributeListFree(request);

	if (result == PAPI_OK) {
		papi_attribute_t **op = NULL;

		/* retrieve the job attributes */
		papiAttributeListGetCollection(response, NULL,
		    "job-attributes-group", &op);
		copy_attributes(&j->attributes, op);

		if (req_type == OPID_CREATE_JOB) {
			int32_t id = 0;

			papiAttributeListGetInteger(j->attributes, NULL,
			    "job-id", &id);
			/* send each document */
			for (i = 0; ((result == PAPI_OK) && (files[i] != NULL));
			    i++)
				result = send_document_uri(svc, files[i],
				    job_attributes,
				    printer, id, (files[i+1]?0:1),
				    data_type);
		}
	}
	papiAttributeListFree(response);

	return (result);
}

papi_status_t
papiJobSubmit(papi_service_t handle, char *printer,
		papi_attribute_t **job_attributes,
		papi_job_ticket_t *job_ticket, char **files, papi_job_t *job)
{
	return (internal_job_submit(handle, printer, job_attributes,
	    job_ticket, files, job, _WITH_DATA));
}

papi_status_t
papiJobSubmitByReference(papi_service_t handle, char *printer,
		papi_attribute_t **job_attributes,
		papi_job_ticket_t *job_ticket, char **files, papi_job_t *job)
{
	return (internal_job_submit(handle, printer, job_attributes,
	    job_ticket, files, job, _BY_REFERENCE));
}

papi_status_t
papiJobValidate(papi_service_t handle, char *printer,
		papi_attribute_t **job_attributes,
		papi_job_ticket_t *job_ticket, char **files, papi_job_t *job)
{
	return (internal_job_submit(handle, printer, job_attributes,
	    job_ticket, files, job, _VALIDATE));
}

papi_status_t
papiJobStreamOpen(papi_service_t handle, char *printer,
		papi_attribute_t **job_attributes,
		papi_job_ticket_t *job_ticket, papi_stream_t *stream)
{
	papi_status_t result = PAPI_INTERNAL_ERROR;
	papi_attribute_t **request = NULL;
	service_t *svc = handle;

	if ((svc == NULL) || (printer == NULL) || (stream == NULL))
		return (PAPI_BAD_ARGUMENT);

	/* if we are already connected, use that connection. */
	if (svc->connection == NULL)
		if ((result = service_connect(svc, printer)) != PAPI_OK)
			return (result);

	/* create job request */
	populate_job_request(svc, &request, job_attributes, printer,
	    OPID_PRINT_JOB);

	*stream = svc->connection;

	result = ipp_send_initial_request_block(svc, request, 0);
	papiAttributeListFree(request);

	return (result);
}

papi_status_t
papiJobStreamWrite(papi_service_t handle,
		papi_stream_t stream, void *buffer, size_t buflen)
{
	papi_status_t result = PAPI_OK;
	service_t *svc = handle;
	size_t rc;

#ifdef DEBUG
	printf("papiJobStreamWrite(0x%8.8x, 0x%8.8x, 0x%8.8x, %d)\n",
	    handle, stream, buffer, buflen);
	httpDumpData(stdout, "papiJobStreamWrite:", buffer, buflen);
#endif

	if ((svc == NULL) || (stream == NULL) || (buffer == NULL) ||
	    (buflen == 0))
		return (PAPI_BAD_ARGUMENT);

	while ((result == PAPI_OK) && (buflen > 0)) {
		rc = ipp_request_write(svc, buffer, buflen);
		if (rc < 0)
			result = PAPI_TEMPORARY_ERROR;
		else {
			buffer = (char *)buffer + rc;
			buflen -= rc;
		}
	}

#ifdef DEBUG
	printf("papiJobStreamWrite(): %s\n", papiStatusString(result));
#endif

	return (result);
}

papi_status_t
papiJobStreamClose(papi_service_t handle,
		papi_stream_t stream, papi_job_t *job)
{
	papi_status_t result = PAPI_INTERNAL_ERROR;
	http_status_t status = HTTP_CONTINUE;
	service_t *svc = handle;
	papi_attribute_t **response = NULL;
	job_t *j = NULL;

	if ((svc == NULL) || (stream == NULL) || (job == NULL))
		return (PAPI_BAD_ARGUMENT);

	if ((*job = j = calloc(1, sizeof (*j))) == NULL)
		return (PAPI_TEMPORARY_ERROR);

	(void) ipp_request_write(svc, "", 0);

	/* update our connection info */
	while (status == HTTP_CONTINUE)
		status = httpUpdate(svc->connection);

	if (status != HTTP_OK)
		return (http_to_papi_status(status));
	httpWait(svc->connection, 1000);

	/* read the IPP response */
	result = ipp_read_message(&ipp_request_read, svc, &response,
	    IPP_TYPE_RESPONSE);
	if (result == PAPI_OK)
		result = ipp_status_info(svc, response);

	if (result == PAPI_OK) {
		papi_attribute_t **op = NULL;

		papiAttributeListGetCollection(response, NULL,
		    "job-attributes-group", &op);
		copy_attributes(&j->attributes, op);
	}
	papiAttributeListFree(response);

	return (result);
}

papi_status_t
papiJobQuery(papi_service_t handle, char *printer, int32_t job_id,
		char **requested_attrs,
		papi_job_t *job)
{
	papi_status_t result = PAPI_INTERNAL_ERROR;
	service_t *svc = handle;
	job_t *j = NULL;
	papi_attribute_t **request = NULL, **op = NULL, **response = NULL;

	if ((svc == NULL) || (printer == NULL))
		return (PAPI_BAD_ARGUMENT);

	/* if we are already connected, use that connection. */
	if (svc->connection == NULL)
		if ((result = service_connect(svc, printer)) != PAPI_OK)
			return (result);

	if ((*job = j = calloc(1, sizeof (*j))) == NULL)
		return (PAPI_TEMPORARY_ERROR);

	ipp_initialize_request(svc, &request, OPID_GET_JOB_ATTRIBUTES);

	ipp_initialize_operational_attributes(svc, &op, printer, job_id);

	if (requested_attrs != NULL) {
		int i;

		for (i = 0; requested_attrs[i] != NULL; i++)
			papiAttributeListAddString(&op, PAPI_ATTR_APPEND,
			    "requested-attributes", requested_attrs[i]);
	}

	papiAttributeListAddCollection(&request, PAPI_ATTR_REPLACE,
	    "operational-attributes-group", op);
	papiAttributeListFree(op);
	result = ipp_send_request(svc, request, &response);
	papiAttributeListFree(request);

	op = NULL;
	papiAttributeListGetCollection(response, NULL,
	    "job-attributes-group", &op);
	copy_attributes(&j->attributes, op);
	papiAttributeListFree(response);

	return (result);
}

/* papiJob{Cancel|Hold|Release|Restart|Promote} are all the same */
static papi_status_t
_job_cancel_hold_release_restart_promote(papi_service_t handle,
		char *printer, int32_t job_id, uint16_t type)
{
	papi_status_t result = PAPI_INTERNAL_ERROR;
	service_t *svc = handle;
	papi_attribute_t **request = NULL, **op = NULL, **response = NULL;

	if ((svc == NULL) || (printer == NULL) || (job_id < 0))
		return (PAPI_BAD_ARGUMENT);

	/* if we are already connected, use that connection. */
	if (svc->connection == NULL)
		if ((result = service_connect(svc, printer)) != PAPI_OK)
			return (result);

	ipp_initialize_request(svc, &request, type);

	ipp_initialize_operational_attributes(svc, &op, printer, job_id);

	papiAttributeListAddCollection(&request, PAPI_ATTR_REPLACE,
	    "operational-attributes-group", op);
	papiAttributeListFree(op);
	result = ipp_send_request(svc, request, &response);
	papiAttributeListFree(request);
	papiAttributeListFree(response);

	return (result);
}

papi_status_t
papiJobCancel(papi_service_t handle, char *printer, int32_t job_id)
{
	return (_job_cancel_hold_release_restart_promote(handle, printer,
	    job_id, OPID_CANCEL_JOB));
}


papi_status_t
papiJobHold(papi_service_t handle, char *printer, int32_t job_id)
{
	return (_job_cancel_hold_release_restart_promote(handle, printer,
	    job_id, OPID_HOLD_JOB));
}

papi_status_t
papiJobRelease(papi_service_t handle, char *printer, int32_t job_id)
{
	return (_job_cancel_hold_release_restart_promote(handle, printer,
	    job_id, OPID_RELEASE_JOB));
}

papi_status_t
papiJobRestart(papi_service_t handle, char *printer, int32_t job_id)
{
	return (_job_cancel_hold_release_restart_promote(handle, printer,
	    job_id, OPID_RESTART_JOB));
}

papi_status_t
papiJobPromote(papi_service_t handle, char *printer, int32_t job_id)
{
	return (_job_cancel_hold_release_restart_promote(handle, printer,
	    job_id, OPID_PROMOTE_JOB));
}

papi_status_t
papiJobMove(papi_service_t handle, char *printer, int32_t job_id,
		char *destination)
{
	papi_status_t result = PAPI_INTERNAL_ERROR;
	service_t *svc = handle;
	papi_attribute_t **request = NULL, **op = NULL, **response = NULL;

	if ((svc == NULL) || (printer == NULL) || (job_id < 0) ||
	    (destination == NULL))
		return (PAPI_BAD_ARGUMENT);

	/* if we are already connected, use that connection. */
	if (svc->connection == NULL)
		if ((result = service_connect(svc, printer)) != PAPI_OK)
			return (result);

	ipp_initialize_request(svc, &request, OPID_CUPS_MOVE_JOB);

	ipp_initialize_operational_attributes(svc, &op, printer, job_id);

	papiAttributeListAddCollection(&request, PAPI_ATTR_REPLACE,
	    "operational-attributes-group", op);
	papiAttributeListFree(op);

	op = NULL;
	papiAttributeListAddString(&op, PAPI_ATTR_EXCL,
	    "job-printer-uri", destination);
	papiAttributeListAddCollection(&request, PAPI_ATTR_REPLACE,
	    "job-attributes-group", op);
	papiAttributeListFree(op);

	result = ipp_send_request(svc, request, &response);
	papiAttributeListFree(request);
	papiAttributeListFree(response);

	return (result);
}

papi_status_t
papiJobModify(papi_service_t handle, char *printer, int32_t job_id,
		papi_attribute_t **attributes, papi_job_t *job)
{
	papi_status_t result = PAPI_INTERNAL_ERROR;
	service_t *svc = handle;
	papi_attribute_t **request = NULL, **op = NULL, **response = NULL;
	job_t *j = NULL;

	if ((svc == NULL) || (printer == NULL) || (job_id < 0) ||
	    (attributes == NULL))
		return (PAPI_BAD_ARGUMENT);

	if ((*job = j = calloc(1, sizeof (*j))) == NULL)
		return (PAPI_TEMPORARY_ERROR);

	/* if we are already connected, use that connection. */
	if (svc->connection == NULL)
		if ((result = service_connect(svc, printer)) != PAPI_OK)
			return (result);

	ipp_initialize_request(svc, &request, OPID_SET_JOB_ATTRIBUTES);

	ipp_initialize_operational_attributes(svc, &op, printer, job_id);

	papiAttributeListAddCollection(&request, PAPI_ATTR_REPLACE,
	    "operational-attributes-group", op);
	papiAttributeListFree(op);
	papiAttributeListAddCollection(&request, PAPI_ATTR_REPLACE,
	    "job-attributes-group", attributes);
	result = ipp_send_request(svc, request, &response);
	papiAttributeListFree(request);

	op = NULL;
	papiAttributeListGetCollection(response, NULL,
	    "job-attributes-group", &op);
	copy_attributes(&j->attributes, op);
	papiAttributeListFree(response);

	return (result);
}
