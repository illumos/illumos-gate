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
 * Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
 * Use is subject to license terms.
 *
 */

/* $Id: printer.c 146 2006-03-24 00:26:54Z njacobs $ */

#pragma ident	"%Z%%M%	%I%	%E% SMI"

/*LINTLIBRARY*/

#include <stdlib.h>
#include <papi_impl.h>

#include <config-site.h>

void
papiPrinterFree(papi_printer_t printer)
{
	printer_t *tmp = printer;

	if (tmp != NULL) {
		if (tmp->attributes != NULL)
			papiAttributeListFree(tmp->attributes);
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

/*
 * Enumeration of printers is not part of the IPP specification, so many
 * servers will probably not respond back with a list of printers, but
 * CUPS has implemented an extension to IPP to enumerate printers and
 * classes. the Apache/mod_ipp IPP listener module available in Solaris
 * implements this IPP extension, so CUPS and Solaris can provide this
 * to IPP clients.
 */
#ifndef	OPID_CUPS_GET_PRINTERS		/* for servers that will enumerate */
#define	OPID_CUPS_GET_PRINTERS		0x4002
#endif	/* OPID_CUPS_GET_PRINTERS */
#ifndef	OPID_CUPS_DELETE_PRINTER	/* for servers that can delete */
#define	OPID_CUPS_DELETE_PRINTER	0x4004
#endif	/* OPID_CUPS_DELETE_PRINTER */
#ifndef	OPID_CUPS_GET_CLASSES		/* for servers that will enumerate */
#define	OPID_CUPS_GET_CLASSES		0x4005
#endif	/* OPID_CUPS_GET_CLASSES */

papi_status_t
papiPrintersList(papi_service_t handle, char **requested_attrs,
		papi_filter_t *filter, papi_printer_t **printers)
{
	papi_status_t status, result = PAPI_INTERNAL_ERROR;
	service_t *svc = handle;
	papi_attribute_t **request = NULL, **op = NULL, **response = NULL;
	void *iter = NULL;

	if ((svc == NULL) || (printers == NULL))
		return (PAPI_BAD_ARGUMENT);

	/* if we are already connected, use that connection. */
	if (svc->connection == NULL)
		if ((result = service_connect(svc, DEFAULT_DEST)) != PAPI_OK)
			return (result);
	ipp_initialize_request(svc, &request, OPID_CUPS_GET_PRINTERS);

	ipp_initialize_operational_attributes(svc, &op, NULL, -1);

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
	for (status = papiAttributeListGetCollection(response, &iter,
				"printer-attributes-group", &op);
	     status == PAPI_OK;
	     status = papiAttributeListGetCollection(response, &iter,
				NULL, &op)) {
		printer_t *p = NULL;

		if ((p = calloc(1, sizeof (*p))) == NULL)
			return (PAPI_TEMPORARY_ERROR);

		copy_attributes(&p->attributes, op);
		op = NULL;
		list_append(printers, p);
	}
	papiAttributeListFree(response);

	return (result);
}

papi_status_t
papiPrinterQuery(papi_service_t handle, char *name,
		char **requested_attrs,
		papi_attribute_t **job_attributes,
		papi_printer_t *printer)
{
	papi_status_t result = PAPI_INTERNAL_ERROR;
	service_t *svc = handle;
	printer_t *p = NULL;
	papi_attribute_t **request = NULL, **op = NULL, **response = NULL;

	if ((svc == NULL) || (name == NULL) || (printer == NULL))
		return (PAPI_BAD_ARGUMENT);

	/* if we are already connected, use that connection. */
	if (svc->connection == NULL)
		if ((result = service_connect(svc, name)) != PAPI_OK)
			return (result);

	if ((*printer = p = calloc(1, sizeof (*p))) == NULL)
		return (PAPI_TEMPORARY_ERROR);

	ipp_initialize_request(svc, &request, OPID_GET_PRINTER_ATTRIBUTES);

	ipp_initialize_operational_attributes(svc, &op, name, -1);

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
			"printer-attributes-group", &op);
	copy_attributes(&p->attributes, op);
	papiAttributeListFree(response);

	return (result);
}

static papi_status_t
_printer_enable_disable_pause_resume_delete(papi_service_t handle, char *name,
		char *message, uint16_t type)
{
	papi_status_t result = PAPI_INTERNAL_ERROR;
	service_t *svc = handle;
	papi_attribute_t **request = NULL, **op = NULL, **response = NULL;

	if ((svc == NULL) || (name == NULL))
		return (PAPI_BAD_ARGUMENT);

	/* if we are already connected, use that connection. */
	if (svc->connection == NULL)
		if ((result = service_connect(svc, name)) != PAPI_OK)
			return (result);

	ipp_initialize_request(svc, &request, type);

	ipp_initialize_operational_attributes(svc, &op, name, -1);

	switch (type) {
	case OPID_DISABLE_PRINTER:
		papiAttributeListAddString(&op, PAPI_ATTR_REPLACE,
				"printer-message-from-operator", message);
		break;
	case OPID_PAUSE_PRINTER:
		papiAttributeListAddString(&op, PAPI_ATTR_REPLACE,
				"printer-state-message", message);
		break;
	default: /* a message value is of no use */
		break;
	}

	papiAttributeListAddCollection(&request, PAPI_ATTR_REPLACE,
			"operational-attributes-group", op);
	papiAttributeListFree(op);
	result = ipp_send_request(svc, request, &response);
	papiAttributeListFree(request);
	papiAttributeListFree(response);

	return (result);
}

papi_status_t
papiPrinterEnable(papi_service_t handle, char *name)
{
	return (_printer_enable_disable_pause_resume_delete(handle, name,
				NULL, OPID_ENABLE_PRINTER));
}

papi_status_t
papiPrinterResume(papi_service_t handle, char *name)
{
	return (_printer_enable_disable_pause_resume_delete(handle, name,
				NULL, OPID_RESUME_PRINTER));
}

papi_status_t
papiPrinterPause(papi_service_t handle, char *name, char *message)
{
	return (_printer_enable_disable_pause_resume_delete(handle, name,
				message, OPID_PAUSE_PRINTER));
}

papi_status_t
papiPrinterDisable(papi_service_t handle, char *name, char *message)
{
	return (_printer_enable_disable_pause_resume_delete(handle, name,
				message, OPID_PAUSE_PRINTER));
}

/*
 * there is no IPP create operation, the set-printer-attibutes operation
 * is the closest we have, so we will assume that the server will create
 * a printer and set attributes if there is none.
 */
papi_status_t
papiPrinterAdd(papi_service_t handle, char *name,
		papi_attribute_t **attributes, papi_printer_t *printer)
{
	return (papiPrinterModify(handle, name, attributes, printer));
}

papi_status_t
papiPrinterModify(papi_service_t handle, char *name,
		papi_attribute_t **attributes, papi_printer_t *printer)
{
	papi_status_t result = PAPI_INTERNAL_ERROR;
	service_t *svc = handle;
	printer_t *p = NULL;
	papi_attribute_t **request = NULL, **op = NULL, **response = NULL;

	if ((svc == NULL) || (name == NULL) || (printer == NULL))
		return (PAPI_BAD_ARGUMENT);

	/* if we are already connected, use that connection. */
	if (svc->connection == NULL)
		if ((result = service_connect(svc, name)) != PAPI_OK)
			return (result);

	if ((*printer = p = calloc(1, sizeof (*p))) == NULL)
		return (PAPI_TEMPORARY_ERROR);

	ipp_initialize_request(svc, &request, OPID_SET_PRINTER_ATTRIBUTES);

	ipp_initialize_operational_attributes(svc, &op, name, -1);

	papiAttributeListAddCollection(&request, PAPI_ATTR_REPLACE,
			"operational-attributes-group", op);
	papiAttributeListFree(op);

	papiAttributeListAddCollection(&request, PAPI_ATTR_REPLACE,
			"printer-attributes-group", attributes);
	result = ipp_send_request(svc, request, &response);
	papiAttributeListFree(request);

	op = NULL;
	papiAttributeListGetCollection(response, NULL,
			"printer-attributes-group", &op);
	copy_attributes(&p->attributes, op);
	papiAttributeListFree(response);

	return (result);
}

papi_status_t
papiPrinterRemove(papi_service_t handle, char *name)
{
	return (_printer_enable_disable_pause_resume_delete(handle, name,
				NULL, OPID_CUPS_DELETE_PRINTER));
}

papi_status_t
papiPrinterPurgeJobs(papi_service_t handle, char *name,
		papi_job_t **jobs)
{
	papi_status_t status, result = PAPI_INTERNAL_ERROR;
	service_t *svc = handle;
	papi_attribute_t **request = NULL, **op = NULL, **response = NULL;
	void *iter = NULL;


	if ((svc == NULL) || (name == NULL))
		return (PAPI_BAD_ARGUMENT);

	/* if we are already connected, use that connection. */
	if (svc->connection == NULL)
		if ((result = service_connect(svc, name)) != PAPI_OK)
			return (result);

	ipp_initialize_request(svc, &request, OPID_PURGE_JOBS);

	ipp_initialize_operational_attributes(svc, &op, name, -1);

	papiAttributeListAddCollection(&request, PAPI_ATTR_REPLACE,
			"operational-attributes-group", op);
	papiAttributeListFree(op);
	result = ipp_send_request(svc, request, &response);
	papiAttributeListFree(request);

	op = NULL;
	for (status = papiAttributeListGetCollection(response, &iter,
				"job-attributes-group", &op);
	     status == PAPI_OK;
	     status = papiAttributeListGetCollection(response, &iter,
				NULL, &op)) {
		job_t *j = NULL;

		if ((j = calloc(1, sizeof (*j))) == NULL)
			return (PAPI_TEMPORARY_ERROR);

		copy_attributes(&j->attributes, op);
		op = NULL;
		list_append(jobs, j);
	}
	papiAttributeListFree(response);

	return (result);
}

papi_status_t
papiPrinterListJobs(papi_service_t handle, char *name,
		char **requested_attrs, int type_mask,
		int max_num_jobs, papi_job_t **jobs)
{
	papi_status_t status, result = PAPI_INTERNAL_ERROR;
	service_t *svc = handle;
	papi_attribute_t **request = NULL, **op = NULL, **response = NULL;
	void *iter = NULL;

	if ((svc == NULL) || (name == NULL))
		return (PAPI_BAD_ARGUMENT);

	/* if we are already connected, use that connection. */
	if (svc->connection == NULL)
		if ((result = service_connect(svc, name)) != PAPI_OK)
			return (result);

	ipp_initialize_request(svc, &request, OPID_GET_JOBS);

	ipp_initialize_operational_attributes(svc, &op, name, -1);

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
	for (status = papiAttributeListGetCollection(response, &iter,
				"job-attributes-group", &op);
	     status == PAPI_OK;
	     status = papiAttributeListGetCollection(response, &iter,
				NULL, &op)) {
		job_t *j = NULL;

		if ((j = calloc(1, sizeof (*j))) == NULL)
			return (PAPI_TEMPORARY_ERROR);

		copy_attributes(&j->attributes, op);
		op = NULL;
		list_append(jobs, j);
	}
	papiAttributeListFree(response);

	return (result);
}

papi_attribute_t **
papiPrinterGetAttributeList(papi_printer_t printer)
{
	papi_attribute_t **result = NULL;
	printer_t *p = printer;

	if (p != NULL)
		result = p->attributes;

	return (result);
}
