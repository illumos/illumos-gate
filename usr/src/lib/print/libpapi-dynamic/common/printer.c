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

/* $Id: printer.c 151 2006-04-25 16:55:34Z njacobs $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include <stdlib.h>
#include <papi_impl.h>

void
papiPrinterFree(papi_printer_t printer)
{
	printer_t *tmp = printer;

	if (tmp != NULL) {
		void (*f)();

		f = (void (*)())psm_sym(tmp->svc, "papiPrinterFree");
		if (f != NULL)
			f(tmp->printer);
		if (tmp->attributes != NULL)
			papiAttributeListFree(tmp->attributes);
		if (tmp->svc_is_internal != 0)
			papiServiceDestroy(tmp->svc);
		free(tmp);
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

/* Enumerate a list of printers from the loaded print service. */
static papi_status_t
printers_from_service(service_t *svc, char **requested_attrs,
		papi_filter_t *filter, papi_printer_t **printers)
{
	papi_status_t result = PAPI_INTERNAL_ERROR;
	papi_printer_t *svc_printers = NULL;
	papi_status_t (*f)();

	if ((svc == NULL) || (printers == NULL))
		return (PAPI_BAD_ARGUMENT);

	/* connect to the service if we are not connected */
	if ((result = service_connect(svc, svc->name)) != PAPI_OK)
		return (result);

	f = (papi_status_t (*)())psm_sym(svc, "papiPrintersList");
	if (f != NULL)
		result = f(svc->svc_handle, requested_attrs, filter,
				&svc_printers);

	/*
	 * copy the resulting printer object pointers into our own
	 * representation of a printer object because we need the
	 * service context to operate against the individual printer
	 * objects.  We free the list now because we no longer need
	 * it and would have no way of freeing it later.
	 */
	if ((result == PAPI_OK) && (svc_printers != NULL)) {
		int i;

		*printers = NULL;
		for (i = 0; svc_printers[i] != NULL; i++) {
			printer_t *p = NULL;

			if ((p = calloc(1, sizeof (*p))) == NULL)
				return (PAPI_TEMPORARY_ERROR);

			p->svc = svc;
			p->printer = svc_printers[i];
			list_append(printers, p);
		}
		free(svc_printers);
	}

	return (result);
}

/* Get printer attributes from it's print service */
static papi_status_t
printer_from_service(service_t *svc, printer_t *p, char **requested_attrs)
{
	papi_status_t result;
	papi_service_t p_svc = NULL;
	papi_printer_t printer = NULL;
	char *psm = NULL;
	char *uri = NULL;

	/* get the psm and uri from the attributes */
	papiAttributeListGetString(p->attributes, NULL,
			"print-service-module", &psm);
	papiAttributeListGetString(p->attributes, NULL, "printer-name", &uri);
	papiAttributeListGetString(p->attributes, NULL, "printer-uri-supported",
			&uri);

	/* contact the service for the printer */
	result = papiServiceCreate((papi_service_t *)&p_svc, psm, svc->user,
				svc->password, svc->authCB, svc->encryption,
				svc->app_data);
	if (result != PAPI_OK)
		return (result);

	/* get the printer from the service */
	result = papiPrinterQuery(p_svc, uri, requested_attrs, NULL, &printer);
	if (result == PAPI_OK) {
		papi_attribute_t **attributes;

		attributes = papiPrinterGetAttributeList(printer);
		copy_attributes(&p->attributes, attributes);
	}
	papiPrinterFree(printer);
	papiServiceDestroy(p_svc);

	return (result);
}

/* are the requested attributes contained in the list */
static int
contained(char **requested, papi_attribute_t **list)
{
	int i;

	if (requested == NULL)	/* we want every possible attribute */
		return (0);

	for (i = 0; requested[i] != NULL; i++)
		if (papiAttributeListFind(list, requested[i]) == NULL)
			return (0);

	return (1);
}

/* Enumerate a list of printers from the Name Service */
static papi_status_t
printers_from_name_service(service_t *svc, char **requested_attrs,
		papi_filter_t *filter, papi_printer_t **printers)
{
	papi_status_t result = PAPI_INTERNAL_ERROR;
	papi_attribute_t **attrs;

	if ((svc == NULL) || (printers == NULL))
		return (PAPI_BAD_ARGUMENT);

	/* retrieve printers from the nameservice */
	setprinterentry(0, NULL);
	while ((attrs = getprinterentry(NULL)) != NULL) {
		printer_t *p = NULL;

		if ((p = calloc(1, sizeof (*p))) == NULL)
			return (PAPI_TEMPORARY_ERROR);

		p->attributes = attrs;
		list_append(printers, p);
	}

	/* if we have printers, check if our request has been satisfied */
	if ((printers != NULL) && (*printers != NULL)) {
		int i;

		/* walk through the list */
		for (i = 0; (*printers)[i] != NULL; i++) {
			printer_t *p = (*printers)[i];

			/* see if the name service satisfied the request */
			if (contained(requested_attrs, p->attributes) == 0)
				printer_from_service(svc, p, requested_attrs);
		}
	}

	return (PAPI_OK);
}

papi_status_t
papiPrintersList(papi_service_t handle, char **requested_attrs,
		papi_filter_t *filter, papi_printer_t **printers)
{
	papi_status_t result = PAPI_INTERNAL_ERROR;
	service_t *svc = handle;
	papi_printer_t *svc_printers = NULL;
	papi_status_t (*f)();

	if ((svc == NULL) || (printers == NULL))
		return (PAPI_BAD_ARGUMENT);

	if (svc->so_handle != NULL)	/* connected, use the print svc */
		result = printers_from_service(svc, requested_attrs,
					filter, printers);
	else				/* not connected, use the name svc */
		result = printers_from_name_service(svc, requested_attrs,
					filter, printers);

	return (result);
}

papi_status_t
papiPrinterQuery(papi_service_t handle, char *name, char **requested_attrs,
		papi_attribute_t **job_attributes, papi_printer_t *printer)
{
	papi_status_t result = PAPI_INTERNAL_ERROR;
	service_t *svc = handle;
	printer_t *p = NULL;
	papi_status_t (*f)();

	if ((svc == NULL) || (name == NULL) || (printer == NULL))
		return (PAPI_BAD_ARGUMENT);

	if ((result = service_connect(svc, name)) != PAPI_OK)
		return (result);

	if ((*printer = p = calloc(1, sizeof (*p))) == NULL)
		return (PAPI_TEMPORARY_ERROR);

	if ((svc->name != NULL) && (svc->svc_handle != NULL) &&
	    (svc->uri != NULL)) {
		p->svc = svc;
		f = (papi_status_t (*)())psm_sym(p->svc, "papiPrinterQuery");
		if (f != NULL)
			result = f(svc->svc_handle, svc->name, requested_attrs,
					job_attributes, &p->printer);
	} else {
		setprinterentry(0, NULL);
		p->attributes = getprinterbyname(name, NULL);
		if (p->attributes == NULL)
			result = PAPI_NOT_FOUND;
		else
			result = PAPI_OK;
	}

	return (result);
}

static papi_status_t
_papi_printer_disable_or_pause(papi_service_t handle, char *name, char *message,
		char *function)
{
	papi_status_t result = PAPI_INTERNAL_ERROR;
	service_t *svc = handle;
	papi_status_t (*f)();

	if ((svc == NULL) || (name == NULL))
		return (PAPI_BAD_ARGUMENT);

	if ((result = service_connect(svc, name)) != PAPI_OK)
		return (result);

	f = (papi_status_t (*)())psm_sym(svc, function);
	if (f != NULL)
		result = f(svc->svc_handle, svc->name, message);

	return (result);
}

static papi_status_t
_papi_printer_enable_or_resume(papi_service_t handle, char *name,
		char *function)
{
	papi_status_t result = PAPI_INTERNAL_ERROR;
	service_t *svc = handle;
	papi_status_t (*f)();

	if ((svc == NULL) || (name == NULL))
		return (PAPI_BAD_ARGUMENT);

	if ((result = service_connect(svc, name)) != PAPI_OK)
		return (result);

	f = (papi_status_t (*)())psm_sym(svc, function);
	if (f != NULL)
		result = f(svc->svc_handle, svc->name);

	return (result);
}

papi_status_t
papiPrinterDisable(papi_service_t handle, char *name, char *message)
{
	return (_papi_printer_disable_or_pause(handle, name, message,
						"papiPrinterDisable"));
}

papi_status_t
papiPrinterPause(papi_service_t handle, char *name, char *message)
{
	return (_papi_printer_disable_or_pause(handle, name, message,
						"papiPrinterPause"));
}

papi_status_t
papiPrinterEnable(papi_service_t handle, char *name)
{
	return (_papi_printer_enable_or_resume(handle, name,
						"papiPrinterEnable"));
}

papi_status_t
papiPrinterResume(papi_service_t handle, char *name)
{
	return (_papi_printer_enable_or_resume(handle, name,
						"papiPrinterResume"));
}

static papi_status_t
_papi_printer_add_or_modify(papi_service_t handle, char *name,
		papi_attribute_t **attributes, papi_printer_t *printer,
		char *function)
{
	papi_status_t result = PAPI_INTERNAL_ERROR;
	service_t *svc = handle;
	printer_t *p = NULL;
	papi_status_t (*f)();

	if ((svc == NULL) || (name == NULL) || (attributes == NULL))
		return (PAPI_BAD_ARGUMENT);

	if ((result = service_connect(svc, name)) != PAPI_OK)
		return (result);

	if ((*printer = p = calloc(1, sizeof (*p))) == NULL)
		return (PAPI_TEMPORARY_ERROR);

	p->svc = svc;
	f = (papi_status_t (*)())psm_sym(p->svc, function);
	if (f != NULL)
		result = f(svc->svc_handle, svc->name, attributes,
				&p->printer);

	return (result);
}

papi_status_t
papiPrinterAdd(papi_service_t handle, char *name,
		papi_attribute_t **attributes, papi_printer_t *printer)
{
	return (_papi_printer_add_or_modify(handle, name, attributes, printer,
						"papiPrinterAdd"));
}

papi_status_t
papiPrinterModify(papi_service_t handle, char *name,
		papi_attribute_t **attributes, papi_printer_t *printer)
{
	return (_papi_printer_add_or_modify(handle, name, attributes, printer,
						"papiPrinterModify"));
}


papi_status_t
papiPrinterRemove(papi_service_t handle, char *name)
{
	papi_status_t result = PAPI_INTERNAL_ERROR;
	service_t *svc = handle;
	papi_status_t (*f)();

	if ((svc == NULL) || (name == NULL))
		return (PAPI_BAD_ARGUMENT);

	if ((result = service_connect(svc, name)) != PAPI_OK)
		return (result);

	f = (papi_status_t (*)())psm_sym(svc, "papiPrinterRemove");
	if (f != NULL)
		result = f(svc->svc_handle, svc->name);

	return (result);
}

papi_status_t
papiPrinterPurgeJobs(papi_service_t handle, char *name, papi_job_t **jobs)
{
	papi_status_t result = PAPI_INTERNAL_ERROR;
	service_t *svc = handle;
	papi_job_t *svc_jobs = NULL;
	papi_status_t (*f)();

	if ((svc == NULL) || (name == NULL))
		return (PAPI_BAD_ARGUMENT);

	if ((result = service_connect(svc, name)) != PAPI_OK)
		return (result);

	f = (papi_status_t (*)())psm_sym(svc, "papiPrinterPurgeJobs");
	if (f != NULL)
		result = f(svc->svc_handle, svc->name, &svc_jobs);

	/*
	 * copy the resulting job object pointers into our own
	 * representation of a job object because we need the
	 * service context to operate against the individual job
	 * objects.  We free the list now because we no longer need
	 * it and would have no way of freeing it later.
	 */
	if ((result == PAPI_OK) && (svc_jobs != NULL) && (jobs != NULL)) {
		int i;

		*jobs = NULL;
		for (i = 0; svc_jobs[i] != NULL; i++) {
			job_t *j = NULL;

			if ((j = calloc(1, sizeof (*j))) == NULL)
				return (PAPI_TEMPORARY_ERROR);

			j->svc = svc;
			j->job = svc_jobs[i];
			list_append(jobs, j);
		}
		free(svc_jobs);
	}

	return (result);
}

papi_status_t
papiPrinterListJobs(papi_service_t handle, char *name, char **requested_attrs,
		int type_mask, int max_num_jobs, papi_job_t **jobs)
{
	papi_status_t result = PAPI_INTERNAL_ERROR;
	service_t *svc = handle;
	papi_job_t *svc_jobs = NULL;
	papi_status_t (*f)();

	if ((svc == NULL) || (name == NULL) || (jobs == NULL))
		return (PAPI_BAD_ARGUMENT);

	if ((result = service_connect(svc, name)) != PAPI_OK)
		return (result);

	f = (papi_status_t (*)())psm_sym(svc, "papiPrinterListJobs");
	if (f != NULL)
		result = f(svc->svc_handle, svc->name, requested_attrs,
				type_mask, max_num_jobs, &svc_jobs);

	/*
	 * copy the resulting job object pointers into our own
	 * representation of a job object because we need the
	 * service context to operate against the individual job
	 * objects.  We free the list now because we no longer need
	 * it and would have no way of freeing it later.
	 */
	if ((result == PAPI_OK) && (svc_jobs != NULL)) {
		int i;

		*jobs = NULL;
		for (i = 0; svc_jobs[i] != NULL; i++) {
			job_t *j = NULL;

			if ((j = calloc(1, sizeof (*j))) == NULL)
				return (PAPI_TEMPORARY_ERROR);

			j->svc = svc;
			j->job = svc_jobs[i];
			list_append(jobs, j);
		}
		free(svc_jobs);
	}

	return (result);
}

papi_attribute_t **
papiPrinterGetAttributeList(papi_printer_t printer)
{
	papi_attribute_t **result = NULL;
	printer_t *p = printer;

	if ((p != NULL) && (p->printer != NULL)) {
		papi_attribute_t **(*f)();

		f = (papi_attribute_t **(*)())psm_sym(p->svc,
					"papiPrinterGetAttributeList");
		if (f != NULL)
			result = f(p->printer);
	} else
		result = p->attributes;

	return (result);
}
