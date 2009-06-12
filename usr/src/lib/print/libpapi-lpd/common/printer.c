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

/* $Id: printer.c 149 2006-04-25 16:55:01Z njacobs $ */

#include <stdlib.h>
#include <strings.h>
#include <papi_impl.h>
#include <libintl.h>

static int
contains(char *value, char **list)
{
	int i;

	if ((value == NULL) || (list == NULL))
		return (1);

	for (i = 0; list[i] != NULL; i++)
		if (strcasecmp(value, list[i]) == 0)
			return (1);

	return (0);
}

papi_status_t
papiPrinterQuery(papi_service_t handle, char *name,
		char **requested_attrs,
		papi_attribute_t **job_attributes,
		papi_printer_t *printer)
{
	papi_status_t status;
	service_t *svc = handle;
	printer_t *p = NULL;

	if ((svc == NULL) || (name == NULL) || (printer == NULL))
		return (PAPI_BAD_ARGUMENT);

	if ((status = service_fill_in(svc, name)) == PAPI_OK) {
		*printer = NULL;

		if ((contains("printer-state", requested_attrs) == 1) ||
		    (contains("printer-state-reasons", requested_attrs) == 1))
			status = lpd_find_printer_info(svc,
			    (printer_t **)printer);

		if ((status == PAPI_OK) && (*printer == NULL)) {
			char buf[BUFSIZ];

			*printer = p = calloc(1, sizeof (*p));

			papiAttributeListAddString(&(p->attributes),
			    PAPI_ATTR_APPEND, "printer-name",
			    queue_name_from_uri(svc->uri));

			if (uri_to_string(svc->uri, buf, sizeof (buf)) == 0)
				papiAttributeListAddString(&(p->attributes),
				    PAPI_ATTR_APPEND,
				    "printer-uri-supported", buf);
		}
		/* Set printer accepting: mimic prepapi behavior */
		if ((p = *printer) != NULL)
			papiAttributeListAddBoolean(&(p->attributes),
			    PAPI_ATTR_REPLACE,
			    "printer-is-accepting-jobs", PAPI_TRUE);

	}

	return (status);
}

papi_status_t
papiPrinterPurgeJobs(papi_service_t handle, char *name, papi_job_t **jobs)
{
	papi_status_t status;
	service_t *svc = handle;

	if ((svc == NULL) || (name == NULL))
		return (PAPI_BAD_ARGUMENT);

	if ((status = service_fill_in(svc, name)) == PAPI_OK)
		status = lpd_purge_jobs(svc, (job_t ***)jobs);

	return (status);
}

papi_status_t
papiPrinterListJobs(papi_service_t handle, char *name,
		char **requested_attrs, int type_mask,
		int max_num_jobs, papi_job_t **jobs)
{
	papi_status_t status;
	service_t *svc = handle;

	if ((svc == NULL) || (name == NULL) || (jobs == NULL))
		return (PAPI_BAD_ARGUMENT);

	if ((status = service_fill_in(svc, name)) == PAPI_OK)
		status = lpd_find_jobs_info(svc, (job_t ***)jobs);

	return (status);
}

papi_attribute_t **
papiPrinterGetAttributeList(papi_printer_t printer)
{
	printer_t *p = printer;

	if (p == NULL)
		return (NULL);

	return (p->attributes);
}

void
papiPrinterFree(papi_printer_t printer)
{
	printer_t *p = printer;

	if (p != NULL) {
		if (p->attributes != NULL)
			papiAttributeListFree(p->attributes);
		free(p);
	}
}

void
papiPrinterListFree(papi_printer_t *printers)
{
	if (printers != NULL) {
		int i;

		for (i = 0; printers[i] != NULL; i++)
			papiPrinterFree(printers[i]);
		free(printers);
	}
}


papi_status_t
papiPrinterDisable(papi_service_t handle, char *name, char *message)
{
	service_t *svc = handle;
	papi_status_t status;

	if ((status = service_fill_in(svc, name)) == PAPI_OK) {
		detailed_error(svc,
		    gettext("Warning: %s is remote, disable has no meaning."),
		    queue_name_from_uri(svc->uri));
	}
	return (PAPI_OPERATION_NOT_SUPPORTED);
}

papi_status_t
papiPrinterEnable(papi_service_t handle, char *name)
{
	service_t *svc = handle;
	papi_status_t status;

	if ((status = service_fill_in(svc, name)) == PAPI_OK) {
		detailed_error(svc,
		    gettext("Warning: %s is remote, enable has no meaning."),
		    queue_name_from_uri(svc->uri));
	}
	return (PAPI_OPERATION_NOT_SUPPORTED);
}


papi_status_t
papiPrinterResume(papi_service_t handle, char *name)
{
	service_t *svc = handle;
	papi_status_t status;

	if ((status = service_fill_in(svc, name)) == PAPI_OK) {
		detailed_error(svc,
		    gettext("Warning: %s is remote, accept has no meaning."),
		    queue_name_from_uri(svc->uri));
	}
	return (PAPI_OPERATION_NOT_SUPPORTED);
}


papi_status_t
papiPrinterPause(papi_service_t handle, char *name, char *message)
{
	service_t *svc = handle;
	papi_status_t status;

	if ((status = service_fill_in(svc, name)) == PAPI_OK) {
		detailed_error(svc,
		    gettext("Warning: %s is remote, reject has no meaning."),
		    queue_name_from_uri(svc->uri));
	}
	return (PAPI_OPERATION_NOT_SUPPORTED);
}
