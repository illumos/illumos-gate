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
 * Copyright 2010 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 */

/* $Id: job.c 179 2006-07-17 18:24:07Z njacobs $ */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <libintl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <papi_impl.h>
#include <uri.h>

/*
 * must copy files before leaving routine
 */
papi_status_t
papiJobSubmit(papi_service_t handle, char *name, papi_attribute_t **attributes,
		papi_job_ticket_t *job_ticket, char **files, papi_job_t *job)
{
	papi_status_t status = PAPI_OK;
	service_t *svc = handle;
	job_t *j = NULL;
	char *metadata = NULL;

	if ((svc == NULL) || (name == NULL) || (files == NULL) ||
	    (job == NULL))
		return (PAPI_BAD_ARGUMENT);

	if (job_ticket != NULL) {
		detailed_error(svc,
		    gettext("papiJobSubmit: job ticket not supported"));
		return (PAPI_OPERATION_NOT_SUPPORTED);
	}

	if ((status = service_fill_in(svc, name)) != PAPI_OK)
		return (status);

	if ((*job = j = (job_t *)calloc(1, sizeof (*j))) == NULL) {
		detailed_error(svc,
		    gettext("calloc() failed"));
		return (PAPI_TEMPORARY_ERROR);
	}

	/* before creating a control file add the job-name */
	if ((files != NULL) && (files[0] != NULL))
		papiAttributeListAddString(&attributes, PAPI_ATTR_EXCL,
		    "job-name", files[0]);

	/* create a control file */
	(void) lpd_job_add_attributes(svc, attributes, &metadata,
	    &j->attributes);

	if ((status = lpd_job_add_files(svc, attributes, files, &metadata,
	    &j->attributes)) != PAPI_OK) {
		return (status);
	}

	/* send the job to the server */
	status = lpd_submit_job(svc, metadata, &j->attributes, NULL);
	free(metadata);

	return (status);

}


papi_status_t
papiJobSubmitByReference(papi_service_t handle, char *name,
		papi_attribute_t **job_attributes,
		papi_job_ticket_t *job_ticket, char **files, papi_job_t *job)
{
	return (papiJobSubmit(handle, name, job_attributes,
	    job_ticket, files, job));
}

papi_status_t
papiJobStreamOpen(papi_service_t handle, char *name,
		papi_attribute_t **attributes,
		papi_job_ticket_t *job_ticket, papi_stream_t *stream)
{
	papi_status_t status = PAPI_OK;
	service_t *svc = handle;
	char *metadata = NULL;
	stream_t *s = NULL;

	if ((svc == NULL) || (name == NULL) || (stream == NULL))
		return (PAPI_BAD_ARGUMENT);

	if (job_ticket != NULL)
		return (PAPI_OPERATION_NOT_SUPPORTED);

	if ((status = service_fill_in(svc, name)) != PAPI_OK)
		return (status);

	/* create the stream container */
	if ((*stream = s = calloc(1, sizeof (*s))) == NULL)
		return (PAPI_TEMPORARY_ERROR);

	/* create the job */
	if ((s->job = calloc(1, sizeof (*(s->job)))) == NULL)
		return (PAPI_TEMPORARY_ERROR);

	papiAttributeListAddString(&attributes, PAPI_ATTR_EXCL,
	    "job-name", "standard input");

	/* process the attribute list */
	lpd_job_add_attributes(svc, attributes, &metadata, &s->job->attributes);

	/* if we can stream, do it */
	if ((svc->uri->fragment != NULL) &&
	    (strcasecmp(svc->uri->fragment, "streaming") == 0)) {
		char *files[] = { "standard input", NULL };

		lpd_job_add_files(svc, attributes, files, &metadata,
		    &(s->job->attributes));
		status = lpd_submit_job(svc, metadata, &(s->job->attributes),
		    &s->fd);
	} else {
		char dfname[18];
		char buf[256];

		strcpy(dfname, "/tmp/stdin-XXXXX");

		if ((s->fd = mkstemp(dfname)) >= 0)
			s->dfname = strdup(dfname);
		if (s->job->attributes)
			papiAttributeListFree(s->job->attributes);
		s->job->attributes = NULL;
		papiAttributeListToString(attributes, " ", buf, sizeof (buf));
		papiAttributeListFromString(&(s->job->attributes),
		    PAPI_ATTR_APPEND, buf);
	}
	s->metadata = metadata;

	return (status);
}


papi_status_t
papiJobStreamWrite(papi_service_t handle, papi_stream_t stream,
		void *buffer, size_t buflen)
{
	service_t *svc = handle;
	stream_t *s = stream;

	if ((svc == NULL) || (stream == NULL) || (buffer == NULL) ||
	    (buflen == 0))
		return (PAPI_BAD_ARGUMENT);

	if (write(s->fd, buffer, buflen) != buflen)
		return (PAPI_DEVICE_ERROR);

	return (PAPI_OK);
}

papi_status_t
papiJobStreamClose(papi_service_t handle, papi_stream_t stream, papi_job_t *job)
{
	papi_status_t status = PAPI_INTERNAL_ERROR;
	service_t *svc = handle;
	job_t *j = NULL;
	stream_t *s = stream;
	int ret;

	if ((svc == NULL) || (stream == NULL) || (job == NULL))
		return (PAPI_BAD_ARGUMENT);

	close(s->fd);	/* close the stream */

	if (s->dfname != NULL) {	/* if it is a tmpfile, print it */
		char *files[2];

		files[0] = s->dfname;
		files[1] = NULL;

		lpd_job_add_files(svc, s->job->attributes, files, &s->metadata,
		    &(s->job->attributes));
		status = lpd_submit_job(svc, s->metadata,
		    &(s->job->attributes), NULL);
		unlink(s->dfname);
		free(s->dfname);
	} else
		status = PAPI_OK;

	if (s->metadata != NULL)
		free(s->metadata);

	*job = s->job;

	return (status);
}

papi_status_t
papiJobQuery(papi_service_t handle, char *name, int32_t job_id,
		char **job_attributes, papi_job_t *job)
{
	papi_status_t status = PAPI_OK;
	service_t *svc = handle;

	if ((svc == NULL) || (name == NULL) || job_id < 0)
		return (PAPI_BAD_ARGUMENT);

	if ((status = service_fill_in(svc, name)) == PAPI_OK)
		status = lpd_find_job_info(svc, job_id, (job_t **)job);

	return (status);
}

papi_status_t
papiJobCancel(papi_service_t handle, char *name, int32_t job_id)
{
	papi_status_t status;
	service_t *svc = handle;

	if ((svc == NULL) || (name == NULL) || (job_id < 0))
		return (PAPI_BAD_ARGUMENT);

	if ((status = service_fill_in(svc, name)) == PAPI_OK)
		status = lpd_cancel_job(svc, job_id);

	return (status);
}

papi_attribute_t **
papiJobGetAttributeList(papi_job_t job)
{
	job_t *j = (job_t *)job;

	if (j != NULL)
		return ((papi_attribute_t **)j->attributes);

	return (NULL);
}

char *
papiJobGetPrinterName(papi_job_t job)
{
	char *result = NULL;
	job_t *j = (job_t *)job;

	if (j != NULL)
		papiAttributeListGetString(j->attributes, NULL,
		    "printer-name", &result);

	return (result);
}

int
papiJobGetId(papi_job_t job)
{
	int result = -1;
	job_t *j = (job_t *)job;

	if (j != NULL)
		papiAttributeListGetInteger(j->attributes, NULL,
		    "job-id", &result);

	return (result);
}

void
papiJobFree(papi_job_t job)
{
	job_t *j = (job_t *)job;


	if (j != NULL) {
		papiAttributeListFree(j->attributes);
		free(j);
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
