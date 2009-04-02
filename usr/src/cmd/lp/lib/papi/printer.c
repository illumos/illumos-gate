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
 */


/*LINTLIBRARY*/

#include <stdlib.h>
#include <string.h>
#include <libintl.h>
#include <papi_impl.h>
#include <lp.h>

extern int isclass(char *);

void
papiPrinterFree(papi_printer_t printer)
{
	printer_t *tmp = printer;

	if (tmp != NULL) {
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

papi_status_t
papiPrintersList(papi_service_t handle, char **requested_attrs,
		papi_filter_t *filter, papi_printer_t **printers)
{
	service_t *svc = handle;
	printer_t *p = NULL;
	short status = MOK;
	char *printer = NULL,
	    *form = NULL,
	    *request_id = NULL,
	    *character_set = NULL,
	    *reject_reason = NULL,
	    *disable_reason = NULL;
	short printer_status = 0;
	long enable_date = 0, reject_date = 0;

	if ((handle == NULL) || (printers == NULL))
		return (PAPI_BAD_ARGUMENT);

	if ((filter == NULL) ||
	    ((filter->filter.bitmask.mask & PAPI_PRINTER_LOCAL) ==
	    (filter->filter.bitmask.value & PAPI_PRINTER_LOCAL))) {
		/* ask the spooler for the printer(s) and state */
		if (snd_msg(svc, S_INQUIRE_PRINTER_STATUS, NAME_ALL) < 0)
			return (PAPI_SERVICE_UNAVAILABLE);

		do {
			if (rcv_msg(svc, R_INQUIRE_PRINTER_STATUS, &status,
			    &printer, &form, &character_set,
			    &disable_reason, &reject_reason,
			    &printer_status, &request_id,
			    &enable_date, &reject_date) < 0)
				return (PAPI_SERVICE_UNAVAILABLE);

			if ((p = calloc(1, sizeof (*p))) == NULL)
				return (PAPI_TEMPORARY_ERROR);

			lpsched_printer_configuration_to_attributes(svc, p,
			    printer);

			printer_status_to_attributes(p, printer, form,
			    character_set, disable_reason,
			    reject_reason, printer_status,
			    request_id, enable_date, reject_date);

			list_append(printers, p);

		} while (status == MOKMORE);
	}

	if ((filter == NULL) ||
	    ((filter->filter.bitmask.mask & PAPI_PRINTER_CLASS) ==
	    (filter->filter.bitmask.value & PAPI_PRINTER_CLASS))) {
		/* ask the spooler for the class(es) and state */
		if (snd_msg(svc, S_INQUIRE_CLASS, NAME_ALL) < 0)
			return (PAPI_SERVICE_UNAVAILABLE);

		do {
			if (rcv_msg(svc, R_INQUIRE_CLASS, &status, &printer,
			    &printer_status, &reject_reason,
			    &reject_date) < 0)
				return (PAPI_SERVICE_UNAVAILABLE);

			if ((p = calloc(1, sizeof (*p))) == NULL)
				return (PAPI_TEMPORARY_ERROR);

			lpsched_class_configuration_to_attributes(svc, p,
			    printer);

			class_status_to_attributes(p, printer, printer_status,
			    reject_reason, reject_date);

			list_append(printers, p);

		} while (status == MOKMORE);
	}

	return (PAPI_OK);
}

papi_status_t
papiPrinterQuery(papi_service_t handle, char *name,
		char **requested_attrs,
		papi_attribute_t **job_attrs,
		papi_printer_t *printer)
{
	papi_status_t pst;
	service_t *svc = handle;
	printer_t *p = NULL;
	char *dest;
	short status = MOK;
	char *pname = NULL,
	    *form = NULL,
	    *request_id = NULL,
	    *character_set = NULL,
	    *reject_reason = NULL,
	    *disable_reason = NULL;
	short printer_status = 0;
	long enable_date = 0, reject_date = 0;

	if ((handle == NULL) || (name == NULL) || (printer == NULL))
		return (PAPI_BAD_ARGUMENT);

	if ((*printer = p = calloc(1, sizeof (*p))) == NULL)
		return (PAPI_TEMPORARY_ERROR);

	dest = printer_name_from_uri_id(name, -1);

	if (strcmp(dest, "_default") == 0) {
		static char *_default;

		if (_default == NULL) {
			int fd;
			static char buf[128];

			if ((fd = open("/etc/lp/default", O_RDONLY)) >= 0) {
				read(fd, buf, sizeof (buf));
				close(fd);
				_default = strtok(buf, " \t\n");
			}
		}
		dest = _default;
	}

	if (isprinter(dest) != 0) {
		pst = lpsched_printer_configuration_to_attributes(svc, p, dest);
		if (pst != PAPI_OK)
			return (pst);

		/* get the spooler status data now */
		if (snd_msg(svc, S_INQUIRE_PRINTER_STATUS, dest) < 0)
			return (PAPI_SERVICE_UNAVAILABLE);

		if (rcv_msg(svc, R_INQUIRE_PRINTER_STATUS, &status, &pname,
		    &form, &character_set, &disable_reason,
		    &reject_reason, &printer_status, &request_id,
		    &enable_date, &reject_date) < 0)
			return (PAPI_SERVICE_UNAVAILABLE);

		printer_status_to_attributes(p, pname, form, character_set,
		    disable_reason, reject_reason, printer_status,
		    request_id, enable_date, reject_date);
	} else if (isclass(dest) != 0) {
		pst = lpsched_class_configuration_to_attributes(svc, p, dest);
		if (pst != PAPI_OK)
			return (pst);

		/* get the spooler status data now */
		if (snd_msg(svc, S_INQUIRE_CLASS, dest) < 0)
			return (PAPI_SERVICE_UNAVAILABLE);

		if (rcv_msg(svc, R_INQUIRE_CLASS, &status, &pname,
		    &printer_status, &reject_reason,
		    &reject_date) < 0)
			return (PAPI_SERVICE_UNAVAILABLE);

		class_status_to_attributes(p, pname, printer_status,
		    reject_reason, reject_date);
	} else if (strcmp(dest, "PrintService") == 0) {
		/* fill the printer object with service information */
		lpsched_service_information(&p->attributes);
	} else
		return (PAPI_NOT_FOUND);

	free(dest);

	return (PAPI_OK);
}

papi_status_t
papiPrinterAdd(papi_service_t handle, char *name,
		papi_attribute_t **attributes, papi_printer_t *result)
{
	papi_status_t status;
	printer_t *p = NULL;
	char *dest;

	if ((handle == NULL) || (name == NULL) || (attributes == NULL))
		return (PAPI_BAD_ARGUMENT);

	dest = printer_name_from_uri_id(name, -1);

	if (isprinter(dest) != 0) {
		status = lpsched_add_modify_printer(handle, dest,
		    attributes, 0);

		if ((*result = p = calloc(1, sizeof (*p))) != NULL)
			lpsched_printer_configuration_to_attributes(handle, p,
			    dest);
		else
			status = PAPI_TEMPORARY_ERROR;

	} else if (isclass(dest) != 0) {
		status = lpsched_add_modify_class(handle, dest, attributes);

		if ((*result = p = calloc(1, sizeof (*p))) != NULL)
			lpsched_class_configuration_to_attributes(handle, p,
			    dest);
		else
			status = PAPI_TEMPORARY_ERROR;

	} else
		status = PAPI_NOT_FOUND;

	free(dest);

	return (status);
}

papi_status_t
papiPrinterModify(papi_service_t handle, char *name,
		papi_attribute_t **attributes, papi_printer_t *result)
{
	papi_status_t status;
	printer_t *p = NULL;
	char *dest;

	if ((handle == NULL) || (name == NULL) || (attributes == NULL))
		return (PAPI_BAD_ARGUMENT);

	dest = printer_name_from_uri_id(name, -1);

	if (isprinter(dest) != 0) {
		status = lpsched_add_modify_printer(handle, dest,
		    attributes, 1);

		if ((*result = p = calloc(1, sizeof (*p))) != NULL)
			lpsched_printer_configuration_to_attributes(handle, p,
			    dest);
		else
			status = PAPI_TEMPORARY_ERROR;
	} else if (isclass(dest) != 0) {
		status = lpsched_add_modify_class(handle, dest, attributes);

		if ((*result = p = calloc(1, sizeof (*p))) != NULL)
			lpsched_class_configuration_to_attributes(handle, p,
			    dest);
		else
			status = PAPI_TEMPORARY_ERROR;
	} else
		status = PAPI_NOT_FOUND;

	free(dest);

	return (status);
}

papi_status_t
papiPrinterRemove(papi_service_t handle, char *name)
{
	papi_status_t result;
	char *dest;

	if ((handle == NULL) || (name == NULL))
		return (PAPI_BAD_ARGUMENT);

	dest = printer_name_from_uri_id(name, -1);

	if (isprinter(dest) != 0) {
		result = lpsched_remove_printer(handle, dest);
	} else if (isclass(dest) != 0) {
		result = lpsched_remove_class(handle, dest);
	} else
		result = PAPI_NOT_FOUND;

	free(dest);

	return (result);
}

papi_status_t
papiPrinterDisable(papi_service_t handle, char *name, char *message)
{
	papi_status_t result;

	if ((handle == NULL) || (name == NULL))
		return (PAPI_BAD_ARGUMENT);

	result = lpsched_disable_printer(handle, name, message);

	return (result);
}

papi_status_t
papiPrinterEnable(papi_service_t handle, char *name)
{
	papi_status_t result;

	if ((handle == NULL) || (name == NULL))
		return (PAPI_BAD_ARGUMENT);

	result = lpsched_enable_printer(handle, name);

	return (result);
}

papi_status_t
papiPrinterPause(papi_service_t handle, char *name, char *message)
{
	papi_status_t result;

	if ((handle == NULL) || (name == NULL))
		return (PAPI_BAD_ARGUMENT);

	result = lpsched_reject_printer(handle, name, message);

	return (result);
}

papi_status_t
papiPrinterResume(papi_service_t handle, char *name)
{
	papi_status_t result;

	if ((handle == NULL) || (name == NULL))
		return (PAPI_BAD_ARGUMENT);

	result = lpsched_accept_printer(handle, name);

	return (result);
}

papi_status_t
papiPrinterPurgeJobs(papi_service_t handle, char *name, papi_job_t **jobs)
{
	service_t *svc = handle;
	papi_status_t result = PAPI_OK_SUBST;
	short more;
	long status;
	char *dest;
	char *req_id;

	if ((handle == NULL) || (name == NULL))
		return (PAPI_BAD_ARGUMENT);

	dest = printer_name_from_uri_id(name, -1);
	more = snd_msg(svc, S_CANCEL, dest, "", "");
	free(dest);
	if (more < 0)
		return (PAPI_SERVICE_UNAVAILABLE);

	do {
		if (rcv_msg(svc, R_CANCEL, &more, &status, &req_id) < 0)
			return (PAPI_SERVICE_UNAVAILABLE);

	switch (status) {
	case MOK:
		papiAttributeListAddString(&svc->attributes, PAPI_ATTR_APPEND,
		    "canceled-jobs", req_id);
		break;
	case M2LATE:
	case MUNKNOWN:
	case MNOINFO:
		papiAttributeListAddString(&svc->attributes, PAPI_ATTR_APPEND,
		    "cancel-failed", req_id);
		result = PAPI_DEVICE_ERROR;
		break;
	case MNOPERM:
		papiAttributeListAddString(&svc->attributes, PAPI_ATTR_APPEND,
		    "cancel-failed", req_id);
		result = PAPI_NOT_AUTHORIZED;
		break;
	default:
		detailed_error(svc, gettext("cancel failed, bad status (%d)\n"),
		    status);
		return (PAPI_DEVICE_ERROR);
	}
	} while (more == MOKMORE);

	return (result);
}

papi_status_t
papiPrinterListJobs(papi_service_t handle, char *name,
		char **requested_attrs, int type_mask,
		int max_num_jobs, papi_job_t **jobs)
{
	service_t *svc = handle;
	char *dest;
	short rc;
	int count = 1;

	if ((handle == NULL) || (name == NULL) || (jobs == NULL))
		return (PAPI_BAD_ARGUMENT);

	dest = printer_name_from_uri_id(name, -1);

	rc = snd_msg(svc, S_INQUIRE_REQUEST_RANK, 0, "", dest, "", "", "");
	free(dest);
	if (rc < 0)
		return (PAPI_SERVICE_UNAVAILABLE);

	do {
		job_t *job = NULL;
		char *dest = NULL,
		    *ptr,
		    *form = NULL,
		    *req_id = NULL,
		    *charset = NULL,
		    *owner = NULL,
		    *slabel = NULL,
		    *file = NULL;
		time_t date = 0;
		size_t size = 0;
		short  rank = 0, state = 0;

		if (rcv_msg(svc, R_INQUIRE_REQUEST_RANK, &rc, &req_id,
		    &owner, &slabel, &size, &date, &state, &dest,
		    &form, &charset, &rank, &file) < 0)
			return (PAPI_SERVICE_UNAVAILABLE);

		if ((rc != MOK) && (rc != MOKMORE))
			continue;
		/*
		 * at this point, we should check to see if the job matches the
		 * selection criterion defined in "type_mask".
		 */

		/* too many yet? */
		if ((max_num_jobs != 0) && (count++ > max_num_jobs))
			continue;

		if ((job = calloc(1, sizeof (*job))) == NULL)
			continue;

		if ((ptr = strrchr(file, '-')) != NULL) {
			*++ptr = '0';
			*++ptr = NULL;
		}

		lpsched_read_job_configuration(svc, job, file);

		job_status_to_attributes(job, req_id, owner, slabel, size,
		    date, state, dest, form, charset, rank, file);

		list_append(jobs, job);

	} while (rc == MOKMORE);

	if (rc == MNOINFO)	/* If no jobs are found, it's still ok */
		rc = MOK;

	return (lpsched_status_to_papi_status(rc));
}

papi_attribute_t **
papiPrinterGetAttributeList(papi_printer_t printer)
{
	printer_t *tmp = printer;

	if (tmp == NULL)
		return (NULL);

	return (tmp->attributes);
}
