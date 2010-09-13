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

/* $Id: job.c 146 2006-03-24 00:26:54Z njacobs $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include <stdlib.h>
#include <papi_impl.h>

void
papiJobFree(papi_job_t job)
{
	job_t *tmp = (job_t *)job;

	if (tmp != NULL) {
		void (*f)();

		f = (void (*)())psm_sym(tmp->svc, "papiJobFree");
		if (f != NULL)
			f(tmp->job);
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

	if (job != NULL) {
		papi_attribute_t **(*f)();

		f = (papi_attribute_t **(*)())psm_sym(j->svc,
						"papiJobGetAttributeList");
		if (f != NULL)
			result = f(j->job);
	}

	return (result);
}

char *
papiJobGetPrinterName(papi_job_t job)
{
	char *result = NULL;
	job_t *j = job;

	if (job != NULL) {
		char *(*f)();

		f = (char *(*)())psm_sym(j->svc, "papiJobGetPrinterName");
		if (f != NULL)
			result = f(j->job);
	}

	return (result);
}

int32_t
papiJobGetId(papi_job_t job)
{
	int32_t result = -1;
	job_t *j = job;

	if (job != NULL) {
		int32_t (*f)();

		f = (int32_t (*)())psm_sym(j->svc, "papiJobGetId");
		if (f != NULL)
			result = f(j->job);
	}

	return (result);
}

papi_job_ticket_t *
papiJobGetJobTicket(papi_job_t job)
{
	papi_job_ticket_t *result = NULL;
	job_t *j = job;

	if (job != NULL) {
		papi_job_ticket_t *(*f)();

		f = (papi_job_ticket_t *(*)())psm_sym(j->svc,
						"papiJobGetJobTicket");
		if (f != NULL)
			result = f(j->job);
	}

	return (result);
}

/* common support for papiJob{Submit|SubmitByReference|Validate} */
static papi_status_t
_papi_job_submit_reference_or_validate(papi_service_t handle, char *printer,
		papi_attribute_t **job_attributes,
		papi_job_ticket_t *job_ticket, char **files, papi_job_t *job,
		char *function)
{
	papi_status_t result = PAPI_INTERNAL_ERROR;
	service_t *svc = handle;
	job_t *j = NULL;
	papi_status_t (*f)();

	if ((svc == NULL) || (printer == NULL) || (files == NULL) ||
	    (job == NULL))
		return (PAPI_BAD_ARGUMENT);

	if ((result = service_connect(svc, printer)) != PAPI_OK)
		return (result);

	if ((*job = j = calloc(1, sizeof (*j))) == NULL)
		return (PAPI_TEMPORARY_ERROR);

	j->svc = svc;
	f = (papi_status_t (*)())psm_sym(j->svc, function);
	if (f != NULL)
		result = f(svc->svc_handle, svc->name, job_attributes,
				job_ticket, files, &j->job);

	return (result);
}

papi_status_t
papiJobSubmit(papi_service_t handle, char *printer,
		papi_attribute_t **job_attributes,
		papi_job_ticket_t *job_ticket, char **files, papi_job_t *job)
{
	return (_papi_job_submit_reference_or_validate(handle, printer,
				job_attributes, job_ticket, files, job,
				"papiJobSubmit"));
}

papi_status_t
papiJobSubmitByReference(papi_service_t handle, char *printer,
		papi_attribute_t **job_attributes,
		papi_job_ticket_t *job_ticket, char **files, papi_job_t *job)
{
	return (_papi_job_submit_reference_or_validate(handle, printer,
				job_attributes, job_ticket, files, job,
				"papiJobSubmitByReference"));
}

papi_status_t
papiJobValidate(papi_service_t handle, char *printer,
		papi_attribute_t **job_attributes,
		papi_job_ticket_t *job_ticket, char **files, papi_job_t *job)
{
	return (_papi_job_submit_reference_or_validate(handle, printer,
				job_attributes, job_ticket, files, job,
				"papiJobValidate"));
}

papi_status_t
papiJobStreamOpen(papi_service_t handle, char *printer,
		papi_attribute_t **job_attributes,
		papi_job_ticket_t *job_ticket, papi_stream_t *stream)
{
	papi_status_t result = PAPI_INTERNAL_ERROR;
	service_t *svc = handle;
	papi_status_t (*f)();

	if ((svc == NULL) || (printer == NULL) || (stream == NULL))
		return (PAPI_BAD_ARGUMENT);

	if ((result = service_connect(svc, printer)) != PAPI_OK)
		return (result);

	f = (papi_status_t (*)())psm_sym(svc, "papiJobStreamOpen");
	if (f != NULL)
		result = f(svc->svc_handle, svc->name, job_attributes,
				job_ticket, stream);

	return (result);
}

papi_status_t
papiJobStreamWrite(papi_service_t handle,
		papi_stream_t stream, void *buffer, size_t buflen)
{
	papi_status_t result = PAPI_INTERNAL_ERROR;
	service_t *svc = handle;
	papi_status_t (*f)();

	if ((svc == NULL) || (stream == NULL) || (buffer == NULL) ||
	    (buflen == 0))
		return (PAPI_BAD_ARGUMENT);

	f = (papi_status_t (*)())psm_sym(svc, "papiJobStreamWrite");
	if (f != NULL)
		result = f(svc->svc_handle, stream, buffer, buflen);

	return (result);
}

papi_status_t
papiJobStreamClose(papi_service_t handle, papi_stream_t stream, papi_job_t *job)
{
	papi_status_t result = PAPI_INTERNAL_ERROR;
	service_t *svc = handle;
	job_t *j = NULL;
	papi_status_t (*f)();

	if ((svc == NULL) || (stream == NULL) || (job == NULL))
		return (PAPI_BAD_ARGUMENT);

	if ((*job = j = calloc(1, sizeof (*j))) == NULL)
		return (PAPI_TEMPORARY_ERROR);

	j->svc = svc;
	f = (papi_status_t (*)())psm_sym(j->svc, "papiJobStreamClose");
	if (f != NULL)
		result = f(svc->svc_handle, stream, &j->job);

	return (result);
}

papi_status_t
papiJobQuery(papi_service_t handle, char *printer, int32_t job_id,
		char **requested_attrs, papi_job_t *job)
{
	papi_status_t result = PAPI_INTERNAL_ERROR;
	service_t *svc = handle;
	job_t *j = NULL;
	papi_status_t (*f)();

	if ((svc == NULL) || (printer == NULL))
		return (PAPI_BAD_ARGUMENT);

	if ((result = service_connect(svc, printer)) != PAPI_OK)
		return (result);

	if ((*job = j = calloc(1, sizeof (*j))) == NULL)
		return (PAPI_TEMPORARY_ERROR);

	j->svc = svc;
	f = (papi_status_t (*)())psm_sym(j->svc, "papiJobQuery");
	if (f != NULL)
		result = f(svc->svc_handle, svc->name, job_id,
				requested_attrs, &j->job);

	return (result);
}

papi_status_t
papiJobMove(papi_service_t handle, char *printer, int32_t job_id,
		char *destination)
{
	papi_status_t result = PAPI_INTERNAL_ERROR;
	service_t *svc = handle;
	papi_status_t (*f)();

	if ((svc == NULL) || (printer == NULL) || (job_id < 0))
		return (PAPI_BAD_ARGUMENT);

	if ((result = service_connect(svc, printer)) != PAPI_OK)
		return (result);

	f = (papi_status_t (*)())psm_sym(svc, "papiJobMove");
	if (f != NULL) {
		papi_attribute_t **attrs = getprinterbyname(destination, NULL);

		papiAttributeListGetString(attrs, NULL,
				"printer-uri-supported", &destination);
		result = f(svc->svc_handle, svc->name, job_id, destination);
		papiAttributeListFree(attrs);
	}

	return (result);
}

/* common support for papiJob{Cancel|Release|Restart|Promote} */
static papi_status_t
_papi_job_handle_printer_id(papi_service_t handle,
		char *printer, int32_t job_id, char *function)
{
	papi_status_t result = PAPI_INTERNAL_ERROR;
	service_t *svc = handle;
	papi_status_t (*f)();

	if ((svc == NULL) || (printer == NULL) || (job_id < 0))
		return (PAPI_BAD_ARGUMENT);

	if ((result = service_connect(svc, printer)) != PAPI_OK)
		return (result);

	f = (papi_status_t (*)())psm_sym(svc, function);
	if (f != NULL)
		result = f(svc->svc_handle, svc->name, job_id);

	return (result);
}

papi_status_t
papiJobCancel(papi_service_t handle, char *printer, int32_t job_id)
{
	return (_papi_job_handle_printer_id(handle, printer, job_id,
				"papiJobCancel"));
}

papi_status_t
papiJobRelease(papi_service_t handle, char *printer, int32_t job_id)
{
	return (_papi_job_handle_printer_id(handle, printer, job_id,
				"papiJobRelease"));
}

papi_status_t
papiJobRestart(papi_service_t handle, char *printer, int32_t job_id)
{
	return (_papi_job_handle_printer_id(handle, printer, job_id,
				"papiJobRestart"));
}

papi_status_t
papiJobPromote(papi_service_t handle, char *printer, int32_t job_id)
{
	return (_papi_job_handle_printer_id(handle, printer, job_id,
				"papiJobPromote"));
}

papi_status_t
papiJobCommit(papi_service_t handle, char *printer, int32_t job_id)
{
	return (_papi_job_handle_printer_id(handle, printer, job_id,
				"papiJobCommit"));
}

papi_status_t
papiJobHold(papi_service_t handle, char *printer, int32_t job_id)
{
	return (_papi_job_handle_printer_id(handle, printer, job_id,
				"papiJobHold"));
}

papi_status_t
papiJobModify(papi_service_t handle, char *printer, int32_t job_id,
		papi_attribute_t **attributes, papi_job_t *job)
{
	papi_status_t result = PAPI_INTERNAL_ERROR;
	service_t *svc = handle;
	job_t *j = NULL;
	papi_status_t (*f)();

	if ((svc == NULL) || (printer == NULL) || (job_id < 0) ||
	    (attributes == NULL))
		return (PAPI_BAD_ARGUMENT);

	if ((result = service_connect(svc, printer)) != PAPI_OK)
		return (result);

	if ((*job = j = calloc(1, sizeof (*j))) == NULL)
		return (PAPI_TEMPORARY_ERROR);

	j->svc = svc;
	f = (papi_status_t (*)())psm_sym(j->svc, "papiJobModify");
	if (f != NULL)
		result = f(svc->svc_handle, svc->name, job_id, attributes,
				&j->job);

	return (result);
}

/*
 * The functions defined below are private to Solaris.  They are here
 * temporarily, until equivalent functionality makes it's way into the PAPI
 * spec.  This is expected in the next minor version after v1.0.
 */
papi_status_t
papiJobCreate(papi_service_t handle, char *printer,
		papi_attribute_t **job_attributes,
		papi_job_ticket_t *job_ticket, papi_job_t *job)
{
	papi_status_t result = PAPI_INTERNAL_ERROR;
	service_t *svc = handle;
	job_t *j = NULL;
	papi_status_t (*f)();

	if ((svc == NULL) || (printer == NULL) || (job == NULL))
		return (PAPI_BAD_ARGUMENT);

	if ((result = service_connect(svc, printer)) != PAPI_OK)
		return (result);

	if ((*job = j = calloc(1, sizeof (*j))) == NULL)
		return (PAPI_TEMPORARY_ERROR);

	j->svc = svc;
	f = (papi_status_t (*)())psm_sym(j->svc, "papiJobCreate");
	if (f != NULL)
		result = f(svc->svc_handle, svc->name, job_attributes,
				job_ticket, &j->job);

	return (result);
}

papi_status_t
papiJobStreamAdd(papi_service_t handle, char *printer, int32_t id,
		papi_stream_t *stream)
{
	papi_status_t result = PAPI_INTERNAL_ERROR;
	service_t *svc = handle;
	papi_status_t (*f)();

	if ((svc == NULL) || (printer == NULL))
		return (PAPI_BAD_ARGUMENT);

	if ((result = service_connect(svc, printer)) != PAPI_OK)
		return (result);

	f = (papi_status_t (*)())psm_sym(svc, "papiJobStreamAdd");
	if (f != NULL)
		result = f(svc->svc_handle, svc->name, id, stream);

	return (result);
}
